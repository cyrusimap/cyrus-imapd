/* zeroskip.h - append-only ordered key-value store
 *
 * Copyright (c) 2026 Fastmail Pty Ltd
 *
 * Available under any of: CC0-1.0, 0BSD, or MIT-0
 * See LICENSE-CC0, LICENSE-0BSD, or LICENSE-MIT-0 for details.
 *
 * A zeroskip database is a directory of immutable and append-only files, with
 * lock-free readers and a single writer.  Nothing is ever written except by
 * appending to a file or by creating a new one.
 *
 * The on-disk format, the database layout, the concurrency protocol and the
 * recovery rules are specified in
 * doc/specification.md, and are normative for
 * every implementation.  This header is one binding: its *semantics* are
 * normative, its spelling is not.
 *
 * THREADS.  A `struct zs_db` handle, and every transaction and cursor made from
 * it, is NOT thread-safe: two threads touching one handle concurrently is a
 * caller error, and there is no internal mutex to make it otherwise.
 *
 * A second thread with its OWN handle is supported, and is the way to run a
 * background repack or a concurrent reader in-process.  Two handles on the same
 * database exclude each other exactly as two processes would: the same `fcntl`
 * locks a peer implementation sees, plus a same-process mechanism so the
 * exclusion holds within one process too (C-1j, G-5).  A thread that opens its
 * own handle and calls zs_db_repack therefore serialises against the writer,
 * blocking or returning ZS_LOCKED rather than corrupting, and needs nothing from
 * the caller beyond not sharing the handle.  The library links no thread library
 * and contains no mutex; what makes this safe is that it keeps no unguarded
 * global mutable state -- the one global, the C-1j lock registry, is guarded by
 * an atomic, and every index, snapshot and buffer belongs to a handle.
 *
 * Two consequences worth knowing before choosing a thread over a helper process.
 * A cursor from zs_db_begin_cursor WITHOUT ZS_SHARED opens an implicit write
 * transaction and so holds the write lock for its whole life, which will now
 * block a second thread's writer: a read-only traversal wants ZS_SHARED.  And
 * locks are ordered within one database, so a caller holding locks on several
 * databases at once must impose its own consistent order (C-1h).
 */

#ifndef INCLUDED_ZEROSKIP_H
#define INCLUDED_ZEROSKIP_H

#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>

struct zs_db;
struct zs_txn;
struct zs_cursor;

enum zs_ret {
    ZS_OK          = 0,
    ZS_DONE        = 1,
    ZS_EXISTS      = -1,
    ZS_IOERROR     = -2,
    ZS_INTERNAL    = -3,
    ZS_LOCKED      = -4,
    ZS_NOTFOUND    = -5,
    ZS_READONLY    = -6,
    ZS_BADFORMAT   = -7,
    ZS_BADUSAGE    = -8,
    ZS_BADCHECKSUM = -9,
    ZS_FULL        = -10,
    ZS_AGAIN       = -11
};

/* Flags occupy one 32-bit space and are never reused for different meanings in
 * different calls, though not every flag is meaningful everywhere. */
enum zs_flagspec {
    ZS_CREATE        = 1<<0,   /* open:    create the database if absent */
    ZS_SHARED        = 1<<1,   /* open,txn: read-only */
    ZS_NOCSUM        = 1<<2,   /* open:    RETIRED in version 4 and REJECTED
                                  with ZS_BADUSAGE, not ignored (A-18).  No
                                  record carries a checksum any more (F-32), so
                                  there is nothing left to skip: span checksums
                                  are still verified at indexing (F-5e) and an
                                  in-order file's one checksum only on demand
                                  (F-26f).  A caller passing this believes it is
                                  weakening verification for speed and is
                                  entitled to be told otherwise.  The bit is
                                  reserved, not reused. */
    ZS_NOSYNC        = 1<<3,   /* open:    omit both durability gates on commit,
                                  and nothing else (C-7c).  Structure is still
                                  synced (C-6b), so a crash costs at most the
                                  active file's unconverted tail -- everything
                                  a conversion or repack has published remains
                                  durable, and zs_db_sync() is the on-demand
                                  gate for callers pacing durability
                                  themselves. */
    ZS_NONBLOCKING   = 1<<4,   /* open,txn: ZS_LOCKED rather than wait for a lock */
    ZS_NOAUTOREPACK  = 1<<5,   /* open:    do not run the repack cascade from a
                                  write transaction (D-16e, A-14).  D-16e puts
                                  an UNBOUNDED merge on the write path, paid by
                                  whichever writer starts a new generation and
                                  finds work; this is for a caller that would
                                  rather schedule it from idle time through
                                  zs_db_repack.  zs_db_should_repack still
                                  reports the work.  Setting it and then never
                                  repacking gives a read path that degrades
                                  linearly in the file count -- every read
                                  merges across every file. */

    ZS_IFNOTEXIST    = 1<<11,  /* store:   only if absent, else ZS_EXISTS */
    ZS_IFEXIST       = 1<<12,  /* store:   only if present, else ZS_NOTFOUND */
    ZS_IFCHANGED     = 1<<22,  /* store:   write nothing when the stored state
                                  already matches, returning ZS_OK either way
                                  (A-1d).  A deletion matches only an absent or
                                  deleted key, and a value only an equal value
                                  of equal length -- so storing an empty value
                                  over a deletion IS a change (A-1).
                                  Judged against this transaction's own view,
                                  so it composes with earlier writes in it.

                                  Opt-in because deciding costs a point lookup,
                                  which the write path otherwise never does.
                                  Worth it for a caller that rewrites identical
                                  values, and for deleting keys that may not
                                  exist -- without it that writes a tombstone
                                  for a key that never existed, which a repack
                                  then carries until it can prove the key is
                                  absent below it. */
    ZS_FETCHNEXT     = 1<<13,  /* fetch:   return the record with the smallest
                                  key >= the given key; with ZS_SKIPROOT,
                                  strictly > (A-12).  Exclusive with
                                  ZS_FETCHPREV. */
    ZS_SKIPROOT      = 1<<14,  /* foreach,cursor: skip an exact match on the start key */
    ZS_FETCHPREV     = 1<<15,  /* fetch:   return the record with the largest key
                                  <= the given key; with ZS_SKIPROOT, strictly <
                                  (A-12).  Exclusive with ZS_FETCHNEXT. */
    ZS_CURSOR_PREFIX = 1<<16,  /* foreach,cursor: treat the start key as a prefix
                                  and stop when a key leaves it */
    ZS_SALVAGE_UNVERIFIED = 1<<17,  /* salvage: also recover records whose
                                       COMMIT cannot be proved -- a span with
                                       no valid terminator (S-8).  The record's
                                       own checksum (F-32) proves bytes, not
                                       commitment, so it does not lift this. */
    ZS_CURSOR_LIVE   = 1<<18,  /* foreach,cursor: also observe writes committed by
                                  OTHER processes (D-14j).  Costs a re-scan per
                                  record; a cursor already sees writes made
                                  through its own handle without it. */
    ZS_INDEX_LOCAL   = 1<<19,  /* open: cache pointer tables in zeroskip.cache
                                  inside the database directory (P-2b).  Only a
                                  writable handle creates the directory; a
                                  read-only handle uses it if present.  Mutually
                                  exclusive with index_dir (A-8a). */
    ZS_REVERSE       = 1<<20,  /* cursor: iterate toward smaller keys (D-14k,
                                  A-13).  An empty start key begins at the last
                                  key; a non-empty one at the largest key <= it.
                                  ZS_CURSOR_PREFIX composes: the scan begins at
                                  the last key carrying the prefix.  Not valid
                                  on foreach or with ZS_CURSOR_LIVE. */
    ZS_EPHEMERAL     = 1<<21,  /* fetch:   the returned key and value pointers
                                  live only until the NEXT CALL on this
                                  transaction (or handle, for zs_db_fetch), not
                                  for its whole lifetime as A-4 promises
                                  (A-4b).  Copy before then.  Lets a read of a
                                  record this transaction just stored be
                                  answered out of the writer's buffer instead
                                  of forcing it to the file first, which is
                                  what read-after-write otherwise costs.
                                  A usage error on a cursor or foreach, which
                                  yield across steps. */

    ZS_CSUM_NONE     = 1<<27,  /* open: write engine 0 into files this handle creates */
    ZS_CSUM_XXHASH   = 1<<28,  /* open: engine 1, the default */
    ZS_CSUM_EXTERNAL = 1<<29   /* open: engine 2; zs_open_data.csum MUST be supplied */
};

typedef int      zs_cb(void *rock, const char *key, size_t keylen,
                       const char *val, size_t vallen);
typedef int      zs_compar(const char *a, size_t alen,
                           const char *b, size_t blen);
/* A checksum engine (F-5).  64 bits since version 4: there is one checksum over
 * a whole in-order file rather than one per record, so the field is paid once and
 * a 32-bit digest over hundreds of megabytes is the wrong width.  An engine
 * narrower than 64 bits MUST place its value in the low half and zero the rest
 * (F-5b). */
typedef uint64_t zs_csum(const char *buf, size_t len);

struct zs_open_data {
    uint32_t     flags;
    zs_compar   *compar;         /* NULL = byte order */
    const char  *compar_name;    /* stored in every file header */
    zs_csum     *csum;           /* required for engine 2 */
    size_t       rollover_size;  /* 0 = default 2MB */

    /* A-15/D-9d: also move on once the active file's replay window holds this
     * many spans, however few bytes they are.  0 = default 1024.
     * rollover_size bounds BYTES; what that is standing in for is the index
     * rebuild, which is linear in SPANS -- so many small transactions slip
     * under it and leave a rebuild that grows without limit.
     *
     * THIS, not rollover_size, is what ends a generation for a caller committing
     * one record at a time: 20 000 such commits produce about 19 generations by
     * this bound, where rollover_size would have produced one or two.  So it is
     * also what sets how often a conversion happens, which is what a caller
     * driving zs_db_seal has to pace against -- see that function.
     *
     * A handle with index_dir set is NOT exempt.  It was until P-13: a commit
     * published a pointer table, and a successful publication reset the window
     * this counts, so a cached writer never reached the bound.  A commit
     * publishes nothing now, so a cache changes nothing here. */
    size_t       rollover_txns;

    /* A-16/D-16: the size above which an in-order file stops being a candidate
     * to START a repack, so one merge rewrites about twice this rather than the
     * whole database.  0 = default 512MB, a no-op for any database that never
     * reaches it; a value above the largest file disables the cap and gives the
     * uncapped geometric policy.  Selection is not normative, so this changes
     * nothing another implementation can observe.
     *
     * It buys a shorter pause and costs read speed: a file above the cap is
     * never selected again, so the file count grows with the database and the
     * read path degrades linearly in it.  That is bounded rather than
     * unbounded -- once too many files have been skipped the cap yields for
     * that selection -- but the trade is real, and only the caller knows which
     * end it can afford. */
    size_t       repack_max_size;

    void       (*error)(const char *msg, const char *fmt, ...);

    /* Pointer table cache (spec section 8).  Names the cache ROOT: tables for
     * this database live in <index_dir>/<uuid>/, which the library creates as
     * needed (P-2a); the root itself is never created, and a missing or
     * unwritable root disables the cache rather than failing the open.  NULL
     * disables the cache unless ZS_INDEX_LOCAL asks for the in-database
     * directory instead (A-8a); with neither, no cache, which is the default:
     * the library never picks a location itself (P-2), because a planted
     * table yields wrong records and a world-writable default such as /tmp
     * would make planting one trivial.  MUST NOT name the database directory
     * -- that would let a read-only handle write into the database, which is
     * exactly what R-3 forbids. */
    const char  *index_dir;        /* A-8 */
    size_t       index_threshold;  /* A-9: 0 = the default, 32KB */
};

#define ZS_OPEN_DATA_INITIALIZER { 0, NULL, NULL, NULL, 0, 0, 0, NULL, NULL, 0 }

/* What this handle has REWRITTEN, since it was opened (A-17).
 *
 * Counts of work, not of state: a caller cannot otherwise tell how much of a
 * write's cost went on rewriting records it had already written.  A store
 * appends each record once; a conversion then rewrites its generation in key
 * order, and a repack rewrites whatever it merges, so the bytes a bulk load
 * actually writes are several times the bytes it stored -- and the two causes
 * have different remedies, which is why they are counted apart.
 *
 * Monotonic and per handle: another process's repacks are not visible here.
 * `*_ns` is zero on a platform without a monotonic clock. */
struct zs_db_stats {
    uint64_t repacks;            /* merges performed (D-16, and D-26's) */
    uint64_t repack_records;     /* records written by them */
    uint64_t repack_bytes;       /* bytes written by them, whole files */
    uint64_t repack_ns;          /* nanoseconds spent in them */
    uint64_t conversions;        /* unordered -> in-order conversions (D-12) */
    uint64_t convert_records;
    uint64_t convert_bytes;
    uint64_t convert_ns;
};

/* database operations
 *
 * Locks are ordered within one database, but the library cannot see across
 * two: a caller that holds locks on several databases while writing MUST
 * impose its own consistent order.
 */
int  zs_db_open(const char *dir, struct zs_open_data *setup, struct zs_db **dbp);
int  zs_db_close(struct zs_db **dbp);

/* non-transactional operations, each an implicit single-operation transaction */
int  zs_db_fetch(struct zs_db *db, const char *key, size_t keylen,
                 const char **keyp, size_t *keylenp,
                 const char **valp, size_t *vallenp, int flags);
int  zs_db_store(struct zs_db *db, const char *key, size_t keylen,
                 const char *val, size_t vallen, int flags);
/* start/startlen is where iteration BEGINS, not a filter.  Without
 * ZS_CURSOR_PREFIX this walks from that key to the end of the database; with it,
 * the key is also treated as a prefix and the scan stops when a key leaves it.
 * A NULL or zero-length start begins at the first key. */
int  zs_db_foreach(struct zs_db *db, const char *start, size_t startlen,
                   zs_cb *p, zs_cb *cb, void *rock, int flags);

/* transactions */
int  zs_db_begin_txn(struct zs_db *db, int shared, struct zs_txn **txnp);
int  zs_txn_commit(struct zs_txn **txnp);
int  zs_txn_abort(struct zs_txn **txnp);

int  zs_txn_fetch(struct zs_txn *txn, const char *key, size_t keylen,
                  const char **keyp, size_t *keylenp,
                  const char **valp, size_t *vallenp, int flags);
int  zs_txn_store(struct zs_txn *txn, const char *key, size_t keylen,
                  const char *val, size_t vallen, int flags);
int  zs_txn_foreach(struct zs_txn *txn, const char *start, size_t startlen,
                    zs_cb *p, zs_cb *cb, void *rock, int flags);

/* cursors, from a db (implicit transaction) or inside one.  key/keylen is the
 * seek position, and ZS_CURSOR_PREFIX additionally bounds the scan by it. */
int  zs_db_begin_cursor(struct zs_db *db, const char *key, size_t keylen,
                        struct zs_cursor **curp, int flags);
int  zs_txn_begin_cursor(struct zs_txn *txn, const char *key, size_t keylen,
                         struct zs_cursor **curp, int flags);
int  zs_cursor_next(struct zs_cursor *cur,
                    const char **keyp, size_t *keylenp,
                    const char **valp, size_t *vallenp);
int  zs_cursor_replace(struct zs_cursor *cur,
                       const char *val, size_t vallen, int flags);
int  zs_cursor_commit(struct zs_cursor **curp);
int  zs_cursor_abort(struct zs_cursor **curp);
void zs_cursor_fini(struct zs_cursor **curp);

/* Deletion is a store of a NULL value; these are macros, not functions, so
 * there is exactly one write path to implement and test.  A non-NULL
 * zero-length value stores an empty value, which is a distinct state from an
 * absent key. */
#define zs_db_delete(db, key, keylen, flags) \
        zs_db_store((db), (key), (keylen), NULL, 0, (flags))
#define zs_txn_delete(txn, key, keylen, flags) \
        zs_txn_store((txn), (key), (keylen), NULL, 0, (flags))
#define zs_cursor_delete(cur, flags) \
        zs_cursor_replace((cur), NULL, 0, (flags))

/* utility */
int  zs_db_repack(struct zs_db *db);
bool zs_db_should_repack(struct zs_db *db);

/* This handle's rewrite counters (A-17).  Takes no lock and reads no file. */
int  zs_db_stats(struct zs_db *db, struct zs_db_stats *out);

/* Convert the active generation, so every file in the database has a pointer
 * section and no reader has to replay a span chain (D-25).  Bounded by
 * rollover_size, so cheap enough to call routinely.  A no-op, not an error,
 * when there is nothing to seal.
 *
 * It is also the LATENCY LEVER for conversions, which is what ZS_NOAUTOREPACK is
 * not.  A conversion is unavoidable once per generation, and by default it lands
 * on whichever commit ends one (D-25d) -- so a caller measuring commit latency
 * sees it as a rare tall outlier that disarming the repack cascade does not
 * remove.  Calling this from an idle moment converts the generation early, and
 * the commit that would have done it then has nothing to do.  Measured
 * downstream over 20 000 single-record commits: p99.9 improved 42% against the
 * default, and NO commit did file-lifecycle work at all.
 *
 * THE CADENCE IS A FILE-COUNT KNOB FIRST AND A LATENCY KNOB SECOND, and that is
 * the trap: every seal ends a generation (D-25a), so the cadence sets the file
 * count directly and D-14d makes every read linear in it.  Measured here at
 * 200 000 one-record commits under ZS_NOAUTOREPACK: no cadence leaves 196 files,
 * sealing every 500 commits leaves 400 -- and against those two layouts a point
 * lookup runs 24% slower on a hit and 40% slower on a MISS, which is the shape a
 * probe-then-insert caller has.  Downstream on ZFS the same pairing cost 73% of
 * throughput and 245% of the median while making p99.9 36% WORSE, which is the
 * opposite of what the cadence was reached for.
 *
 * So: DO NOT PAIR A TIGHT CADENCE WITH A DISARMED CASCADE.  Each half is
 * defensible alone and together they only accumulate files.  If the cascade is
 * disarmed, a bounded zs_db_repack catch-up MUST actually run, often enough to
 * hold the file count down, or the cadence is buying latency with read
 * throughput at a rate no workload wants.
 *
 * CADENCE MUST BEAT WHICHEVER BOUND IS ENDING GENERATIONS, and for small
 * transactions that is rollover_txns, not rollover_size.  A generation ends at
 * min(rollover_size bytes, rollover_txns spans), so 20 000 one-record commits
 * end about 19 generations by the span bound while barely troubling the byte
 * one.  Sealing every 500 commits removed every merging commit; every 4000 left
 * 15 of them, because the span bound had already fired.  D-12d bounds how TALL
 * the outlier can be; this sets how often you pre-empt it.
 *
 * ALSO DO NOT SEAL FREQUENTLY WITH THE CASCADE ARMED: sealing early makes more
 * and smaller generations and the cascade then has more to merge, measured at
 * 3.2x to 4.3x of stored bytes rewritten.  Both arrangements have a cost, which
 * is why this is a BULK-IMPORT AND MAINTENANCE tool rather than a steady-state
 * mode.  For a steady-state single-record writer the plain default -- cascade
 * armed, no ZS_NOAUTOREPACK, no cadence -- is the right configuration, and the
 * p99.9 figure above was measured on a 20 000-commit fixture too small for
 * either file-count cost to appear. */
int  zs_db_seal(struct zs_db *db);

/* Merge the entire database into a single file (D-26), reclaiming the tombstones
 * a partial repack structurally cannot (D-27).  UNBOUNDED: it rewrites
 * everything in one call while writers continue.  Returns ZS_BADFORMAT if the
 * result is not a single file, having merged whatever it could first. */
int  zs_db_compact(struct zs_db *db);
int  zs_db_check_consistency(struct zs_db *db);
int  zs_db_dump(struct zs_db *db, int detail);

/* Print the pointer table (spec section 8) covering each unordered file, as
 * text, for the interop runner to compare.  ZS_OK even when the cache is off or
 * no table exists: a table is never required, so its absence is a state to
 * report rather than an error. */
int  zs_db_index_dump(struct zs_db *db);
int  zs_db_sync(struct zs_db *db);
const char *zs_strerror(int r);

/* Salvage (spec section 9).
 *
 * Rebuilds whatever is readable out of a DAMAGED directory into a new database.
 * It reads structures the ordinary path refuses -- a file set with a gap, a
 * header that does not validate, a pointer section that will not load, spans
 * after a bad one -- because those are exactly the databases worth salvaging.
 *
 * The source is never written to, never locked, and never unlinked from (S-1).
 * That is what lets salvage guess and improvise without risking the only copy
 * of the data it is trying to save, and it is why R-4's "there is no in-place
 * repair" needs no exception.
 *
 * Everything recovered is checksum-verified by default -- spans by their
 * terminator, in-order records each by their own checksum (F-32, S-8a).
 * ZS_SALVAGE_UNVERIFIED additionally recovers records whose commit cannot be
 * proved -- a span with no valid terminator -- each one reported (S-8).
 * Rolled-back spans are never recovered, with or without it (S-9).
 */
enum zs_salvage_kind {
    ZS_SALVAGE_FILE_UNREADABLE,   /* could not be opened or mapped */
    ZS_SALVAGE_HEADER_INVALID,    /* generation taken from the filename */
    ZS_SALVAGE_ENGINE_GUESSED,    /* which engine the spans validated under */
    ZS_SALVAGE_GAP,               /* a generation range absent from the set */
    ZS_SALVAGE_PTRS_IGNORED,      /* pointer section unusable; order rescanned */
    ZS_SALVAGE_SPAN_LOST,         /* a span that could not be verified */
    ZS_SALVAGE_SPAN_ROLLBACK,     /* deliberately aborted; not recovered */
    ZS_SALVAGE_RESYNC,            /* a verified span found after damage */
    ZS_SALVAGE_KEY_UNVERIFIED,    /* value came from an unverifiable span */
    ZS_SALVAGE_KEY_MAYBE_STALE,   /* a newer version may have been in lost bytes */

    /* S-13: an in-order file whose one checksum (F-26e) does not verify.
     * Reported at FILE granularity, once, with its own kind -- so a caller can
     * tell "this key came from an unverifiable span" from "every key in this
     * file is unverifiable".  Version 2's per-record checksum could name the
     * damaged record; one digest over the whole file cannot, and that is the
     * cost of the density the packed record buys. */
    ZS_SALVAGE_REGION_UNVERIFIED
};

struct zs_salvage_event {
    int          kind;        /* enum zs_salvage_kind */
    const char  *file;        /* data file name, or NULL */
    uint32_t     generation;
    size_t       offset;      /* byte offset within that file */
    size_t       length;      /* bytes affected */
    const char  *key;         /* per-key events only, else NULL */
    size_t       keylen;
};

/* Returning non-zero stops the salvage, which is then reported to the caller. */
typedef int zs_salvage_cb(void *rock, const struct zs_salvage_event *ev);

struct zs_salvage_data {
    uint32_t        flags;         /* ZS_SALVAGE_UNVERIFIED */
    zs_compar      *compar;        /* NULL = byte order */
    const char     *compar_name;
    zs_csum        *csum;          /* for a source using engine 2 */
    zs_salvage_cb  *report;        /* structured, per event (S-11) */
    void           *rock;
    void          (*error)(const char *msg, const char *fmt, ...);
};

#define ZS_SALVAGE_DATA_INITIALIZER { 0, NULL, NULL, NULL, NULL, NULL, NULL }

int  zs_db_salvage(const char *from, const char *to,
                   struct zs_salvage_data *setup);

/* Not part of the stable API.
 *
 * Behaves as zs_db_open with ZS_CREATE, except that a database being created
 * takes the given UUID instead of a generated one.  Opening an existing
 * database ignores it.  This exists so zstool can generate a reproducible
 * golden corpus; no application should call it.
 */
int  zs_db_open_with_uuid(const char *dir, struct zs_open_data *setup,
                          const char *uuid_str, struct zs_db **dbp);

#endif /* INCLUDED_ZEROSKIP_H */
