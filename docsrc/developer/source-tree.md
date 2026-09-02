# The source tree

This is a map of the top level of the repository: enough to know which
directory to open, not a tour of what's in each one.

## The code that ships

- **`lib/`** — General-purpose code, independent of any particular protocol:
  string and array types (`struct buf`, `strarray`, `dynarray`), hash tables,
  the `cyrusdb` key-value interface and its backends, charset handling, config
  parsing, and the logging machinery. Also `lib/imapoptions/`, the canonical
  definition of every `imapd.conf` option — see its `README.md` for the format
  of a definition.
- **`imap/`** — The bulk of Cyrus: the mail store itself (mailboxes, the index,
  the message cache, annotations, conversations, quotas, search), the protocol
  servers (`imapd`, `pop3d`, `lmtpd`, `httpd` and the JMAP, CalDAV and CardDAV
  code it carries), and the several dozen administrative tools whose names you
  recognise from the man pages — `reconstruct`, `quota`, `ctl_mboxlist`,
  `cyr_expire` and the rest.
- **`sieve/`** — The Sieve implementation: the lexer and grammar, the bytecode
  compiler (`bc_generate.c`, `bc_emit.c`), the bytecode evaluator
  (`bc_eval.c`), and the interpreter Cyrus embeds.
- **`master/`** — The `master` process, which starts, supervises and restarts
  every other service according to `cyrus.conf`. Small, and deliberately so.
- **`timsieved/`** — The ManageSieve server.
- **`notifyd/`** — The notification daemon.
- **`ptclient/`** — `ptloader` and the protection-database backends behind it,
  for group lookups against AFS PTS or LDAP.
- **`imtest/`** — `imtest`, the protocol test client. Handy for poking a
  running server by hand.
- **`perl/`** — The Perl side of Cyrus: `perl/imap` is the `Cyrus::IMAP` XS
  binding and `cyradm`, `perl/sieve` is `managesieve` and `sieveshell`, and
  `perl/annotator` is the annotation callout support.
- **`com_err/`** — A bundled copy of the `com_err` error-table library, used to
  generate the `IMAP_*` and `SIEVE_*` error codes.

### The libraries

The C code builds into four installed libraries, and the split matters when
you're deciding where to put something new.

| Library          | Contents                                                                                            |
| ---------------- | --------------------------------------------------------------------------------------------------- |
| `libcyrus_min`   | The minimum a Cyrus process needs: config parsing, the array and buffer types, assertions, logging. |
| `libcyrus`       | Everything else in `lib/`: `cyrusdb`, charset handling, authentication, networking.                 |
| `libcyrus_imap`  | The mail store and protocol code from `imap/`.                                                      |
| `libcyrus_sieve` | The Sieve engine from `sieve/`.                                                                     |

`libcyrus_min` exists so that sensitive, long-lived processes — `master` above
all — can link the least code that will do the job. Adding a dependency to
`libcyrus_min` makes it less minimal, so don't, unless `master` needs it.

## Tests

- **`cunit/`** — The C unit tests, one `*.testc` file per suite. See
  {ref}`the CUnit page <developer-cunit>`.
- **`cassandane/`** — The Perl integration test suite, which builds and drives
  a real Cyrus. Most tests live one to a file under
  `cassandane/tiny-tests/{Suite}/`. See {ref}`the Cassandane page
  <developer-cassandane>`.
- **`bench/`** — A `cyrusdb` benchmark.

## Documentation and release engineering

- **`docsrc/`** — The source of this website. See {ref}`the documentation page
  <contribute-docs>`.
- **`doc/`** — Documentation that isn't part of the Sphinx site: most of this
  stuff is cruft in need of refiling, but there's also sample `imapd.conf` and
  `cyrus.conf` files under `doc/examples/`. The built HTML and plain-text
  output lands here too, and is generated rather than tracked.
- **`changes/`** — Release-note entries. A change that anyone outside the
  repository could notice needs a file in `changes/next/`; see {ref}`the
  development process <devprocess>`.

## Build and tooling

- **`tools/`** — Developer and administrative scripts, including the content
  lints CI runs and the generators that turn `lib/imapoptions/` and Perl Pod
  into documentation.
- **`cmulocal/`** — Local autoconf macros, used by `configure.ac`.
- **`contrib/`** — Contributed odds and ends that we ship but don't maintain.
- **`depot/`** — CMU-specific deployment configuration, of historical interest.
- **`tzdata/`**, **`languages/`** — Timezone data, and the stopword lists used
  by search.
