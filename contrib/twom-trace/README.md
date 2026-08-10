# twom-trace

Census of twom access patterns inside Cyrus, via eBPF uprobes on
`libcyrus.so.0`, plus a benchmark that replays the measured shape against any
cyrusdb backend.

The tracer answers "what shapes of database calls does this server actually
make", per database type: operation mix, flags, key/value sizes, scan prefix
lengths, hit/tombstone/miss split, and shared-vs-exclusive transaction rates.
It needs no cyrus changes and no restart - it attaches to the running library.

Requires root, `bpftrace`, and an unstripped `libcyrus`.

## Running it

    ./twom-rate 15                             # how busy is this box?
    ./twom-capture [seconds] [outfile]         # default 60s

That is the whole thing. It resolves the running cyrus package itself, so
there is nothing to edit between releases. Needs root, `bpftrace`, and a
`libcyrus.so.0` with symbols (our packages ship unstripped).

    ./twom-capture 60                          # 60s, report to stdout
    MAP_KEYS_MAX=65536 ./twom-capture 30       # small box (testbed, VM)
    ./twom-report /var/tmp/twom-shape.*.txt    # re-render an old capture

Run `twom-rate` first on a server you have not traced before. It attaches two
counter-only probes, reports the twom call rate, and estimates what the full
capture would cost in cores — cheap insurance before putting fifteen probes on
a busy machine.

## Lookups: hit / tombstone / never-existed

    ./twom-hitmiss 30

Splits every lookup three ways, per database type. twom_db_fetch delegates to
twom_txn_fetch (two call sites, not inlined), so probing txn_fetch alone sees
all of them.

| at return | meaning |
|---|---|
| `TWOM_OK` | live record |
| `NOTFOUND` && `loc->offset != 0` | tombstone: record present, visible version is a DELETE |
| `NOTFOUND` && `loc->offset == 0` | never existed |

Validated against ground truth (100 keys, 30 deleted, 50 absent -> 70/30/50
exactly). Needs a uretprobe, so roughly double the census cost per call; keep
windows short. TWOM_FETCHNEXT is bucketed separately because it advances `loc`
past the key that was asked for.

## Benchmarks

Two frontends over one workload. `bench-workload.h` holds the op mix, key and
value size distributions and scan fan-out, derived from a twom-capture census
of a live IMAP server and rounded to plain ratios - so the shape came from
production rather than from guesswork. Both frontends include it, so they
cannot drift apart. Retune it against your own census if your mix differs;
that is why the tracer ships alongside the benchmark.

**twom-bench** drives the twom API directly:

    ./twom-bench-build /root/cyrus-imapd
    ./twom-bench --records 200000 --procs 8 --secs 60 --profile aggregate
    LIB=./build/libtwom.so ./twom-capture 30    # verify the shape it generates

**dbbench** goes through cyrusdb, so it runs on any backend, and reports CPU
and disk as well as throughput:

    ./dbbench-build                             # uses the running cyrus package
    ./dbbench --engine twom --records 200000 --procs 8 --secs 60
    RECORDS=200000 PROCS=8 SECS=30 ./dbbench-compare twom twoskip skiplist

`dbbench-build` defaults to the cyrus prefix the running master has mapped, so
headers and library come from the same build production is running.

Profiles: `aggregate`, `mailboxes` (fetch-heavy, 11-record scans),
`conversations`, `annotations`.

Notes on reading the results:

- Both default to NOSYNC, so the comparison measures the engines rather than
  the box's fsync latency. `--sync` for a durability-faithful run; it changes
  throughput by more than 2x.
- Disk is reported as apparent size *and* allocated blocks, before and after a
  repack. The engines differ far more in slack than in apparent size.
- skiplist has no usable standalone repack: its checkpoint assert()s unless the
  db is already WRITELOCKED, and an assert aborts the process. dbbench runs the
  repack in a child so this degrades to `n/a` instead of killing the run.
- `cursor_next` fires once more than there are records - the last call returns
  DONE. So a census ratio of 1.6 means ~0.6 records per scan. twom-bench cannot
  model sub-1 fan-out (integer, floored at 1), so its conversations profile is
  optimistic.

## How it works

Entry-only uprobes on the fifteen twom entry points, aggregated in kernel
maps. Nothing is emitted per event; the report is printed once at the end.
Attaching to the library rather than a pid covers every cyrus process on the
box, all slots, including ones that start mid-capture.

Database names come from walking the structs, all verified against DWARF:

    twom_db.fname    @ 0x0     fname = *(char **)db
    twom_txn.db      @ 0x0     db    = *(void **)txn
    twom_cursor.txn  @ 0x130   txn   = *(void **)(cur + 0x130)

`twom-offsets` re-checks these before every capture and also confirms that
resolved names really are absolute paths, because a wrong offset does not
error — it silently yields garbage. The twom flag table is read from the
library's own DWARF at capture time for the same reason: flags get added
between releases (`TWOM_ONELOCK` arrived in fm-20260730).

Per-user paths are collapsed to the db type (`conversations.db`, `dav.db`, …)
in `twom-report`, not in the kernel; the `FILES` column is how many distinct
files of that type were touched.

## Cost

**CPU is the constraint, not memory.** On a 48/96-core server with a terabyte
of RAM the maps are a rounding error, so the defaults spend memory freely to
avoid ever truncating the data.

- **`MAP_KEYS_MAX`** (default 1048576). BPF hash maps are *preallocated* and
  `count()`/`hist()` are per-CPU, allocated for `num_possible_cpus`:

  | max_keys | 4 cores | 96 cores | % of 1TB |
  |---------:|--------:|---------:|---------:|
  |    65536 | 0.05 GB |  0.32 GB |   0.03 % |
  |  1048576 | 0.77 GB |  5.08 GB |   0.50 % |
  |  4194304 | 3.06 GB | 20.31 GB |   1.98 % |

  5GB to guarantee a busy database is not silently dropped from the report is
  a good trade. Turn it *down* on a testbed or VM, not up on a real server.
  The report says so if a capture truncates anyway.

- **`STRLEN`** (auto-sized from the real paths on the box, min 104, must stay
  a multiple of 8). The db name is the *last* path component, so too small a
  value silently truncates exactly the field the report groups by. The report
  flags any key that comes back at the limit.

Per-call cost is one uprobe trap plus one string copy — order 1µs, entry-only.
At 96 cores you have ~96 core-seconds per second to spend, so even 1M twom
calls/sec is ~1% of the box; `twom-rate` does that arithmetic against the real
measured rate. There are no uretprobes: they roughly double per-call cost and
nothing here needs a return value. Adding latency measurement means adding
them — measure before leaving that on in production.

## Gotchas found the hard way

- bpftrace 0.16 has no `arg6`/`arg7` on x86_64. `fetch` flags are read at
  `*(uint32 *)(reg("sp") + 16)` and `foreach` flags at `+ 8`.
- A `[string, string]` map key hits a stack-alignment bug and the program is
  rejected by the verifier. `[string, int]` is fine.
- One map per operation multiplies the preallocation by fifteen. Everything is
  folded into six maps keyed by an opid on purpose.
- `master` only maps `libcyrus_min`, so the library is resolved from the lib
  *directory* of whatever cyrus lib it has mapped.
