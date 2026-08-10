/* zeroskip.c - append-only ordered key-value store
 *
 * Copyright (c) 2026 Fastmail Pty Ltd
 *
 * Available under any of: CC0-1.0, 0BSD, or MIT-0
 * See LICENSE-CC0, LICENSE-0BSD, or LICENSE-MIT-0 for details.
 *
 * A directory of immutable and append-only files, with lock-free readers and a
 * single writer.  The design rests on one invariant, without exception:
 * nothing is ever written except by appending to a file or by creating a new
 * file.  No file is ever modified in place or truncated, and there is no
 * mutable object of any kind - no manifest, no shared cache.
 *
 * The format and protocol are specified in
 * doc/specification.md.  Requirement labels in
 * the comments below (F-n format, D-n database, C-n concurrency, R-n recovery,
 * A-n API, G-n guarantee) cite that document, and doc/conformance.md maps each
 * to the test that enforces it.
 *
 * Sections appear in dependency order: each may only call downwards into those
 * above it.
 */

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "zeroskip.h"

#define XXH_INLINE_ALL

/* XXH3_STREAM_USE_STACK copies the eight accumulator lanes into a local array
 * for the duration of an update, so they can live in vector registers the way
 * the one-shot path's local acc[8] does.  xxhash sets it itself for every
 * compiler EXCEPT clang ("clang doesn't need additional stack space"), which is
 * wrong here: without it clang leaves the accumulator in the heap-allocated
 * state and streaming runs at a THIRD of the one-shot rate (clang 19, aarch64:
 * 20.3 GB/s against 62.5).  With it, 63.2 against 61.0 -- parity.  Harmless on
 * gcc, which already defines it. */
#define XXH3_STREAM_USE_STACK 1

/* XXH_NO_INLINE_HINTS is deliberately NOT set here, and must not be: it turns
 * every internal xxhash function into a plain `static`, and on modern compilers
 * that costs about 3x on ALL hashing -- one-shot as well as streaming, so every
 * span checksum, conversion, repack and consistency check pays it.  Measured at
 * 21MB, aarch64: gcc 14 goes 59.0 -> 19.4 GB/s and clang 19 goes 62.5 -> 24.3.
 * End to end that is 8% of a bulk load (zsbench 400k at 1000-per-txn, best of
 * nine: gcc 1107k -> 1202k/s, clang 1122k -> 1205k/s).
 *
 * It IS still required below -O2 on gcc, which refuses always_inline for the
 * NEON helpers at -Og ("function not considered for inlining") and hits an
 * internal compiler error at -O1 on aarch64.  So the low-optimisation targets
 * in the Makefile pass -DXXH_NO_INLINE_HINTS=1 themselves; see XXH_LOWOPT_DEF
 * there.  A hand-rolled -Og build without it fails loudly at compile time,
 * which is the right way round -- the alternative was every optimised build
 * silently paying 3x.  (Downstream twom sets this flag too and does NOT need
 * it: it only ever calls one-shot XXH3_64bits, so the streaming helpers that
 * fail to inline are never instantiated.) */

#include "xxhash.h"

/* Syscall interposition for crash and sync-failure injection (T-8, T-8a).
 *
 * A test build routes the four syscalls that can leave a database in an
 * intermediate state through function pointers, so a test can count them and fail
 * or abort at call N.  Compiled out entirely otherwise -- ZS_TEST_HOOKS is defined
 * only by the crash-test target.
 *
 * Function pointers rather than LD_PRELOAD because LD_PRELOAD does not exist on
 * macOS, and rather than weak symbols because those interpose the whole process
 * including the harness's own writes.  This way only the library's calls are
 * counted, which is what makes "abort at call N" reproducible. */
#ifdef ZS_TEST_HOOKS
ssize_t (*zs_hook_write)(int, const void *, size_t) = NULL;
int     (*zs_hook_fdatasync)(int) = NULL;
int     (*zs_hook_rename)(const char *, const char *) = NULL;
int     (*zs_hook_unlink)(const char *) = NULL;

#define ZS_WRITE(fd, buf, n)  (zs_hook_write ? zs_hook_write((fd), (buf), (n)) \
                                             : write((fd), (buf), (n)))
#define ZS_FDATASYNC(fd)      (zs_hook_fdatasync ? zs_hook_fdatasync(fd) \
                                                 : fdatasync(fd))
#define ZS_RENAME(a, b)       (zs_hook_rename ? zs_hook_rename((a), (b)) \
                                              : rename((a), (b)))
#define ZS_UNLINK(p)          (zs_hook_unlink ? zs_hook_unlink(p) : unlink(p))

/* A pause point between C-4's step 2 (resolve) and step 3 (open), so a test can
 * force the interleaving C-4b is about -- a file removed after the scan saw it.
 * Racing for that window does not reliably hit it: a first attempt raced 300 times
 * and never once took the retry path, which is a test that reads as coverage
 * without providing any. */
void (*zs_hook_snapshot_gap)(const char *dir) = NULL;
#define ZS_SNAPSHOT_GAP(dir)  do { if (zs_hook_snapshot_gap) \
                                       zs_hook_snapshot_gap(dir); } while (0)
#else
#define ZS_WRITE(fd, buf, n)  write((fd), (buf), (n))
#define ZS_FDATASYNC(fd)      fdatasync(fd)
#define ZS_RENAME(a, b)       rename((a), (b))
#define ZS_UNLINK(p)          unlink(p)
#define ZS_SNAPSHOT_GAP(dir)  do { } while (0)
#endif

/********** TUNING *************/

/* A writer moves to a new file when the active file exceeds this (D-9a).
 * It bounds two other things as a side effect: how much a snapshot must replay
 * to build a private index (D-13d), and how much work one conversion does
 * (D-12d). */
#define ZSI_DEFAULT_ROLLOVER (2 * 1024 * 1024)

/* And a writer also moves on when the active file's REPLAY WINDOW holds this
 * many spans (D-9d), whatever its size.  rollover_size bounds bytes; the
 * rebuild it stands in for is linear in spans, and many small transactions put
 * many spans into few bytes -- so with no cache configured the two come apart
 * completely.  1024 sits where the replay is still cheaper than an open's other
 * fixed costs.  A sole writer never rebuilds and never notices; writers
 * alternating across processes rebuild at every begin (C-4i), so for them it is
 * a per-transaction cost.
 *
 * With a cache configured, P-13's threshold bounds the window first -- 311
 * spans replayed for a file holding 16384 -- so this condition simply never
 * fires, which is the correct outcome rather than a missed one. */
#define ZSI_DEFAULT_ROLLOVER_TXNS 1024

/* The size above which an in-order file stops being a candidate to START a
 * repack (D-16, A-16), so an ordinary merge rewrites about twice this rather
 * than the whole database.
 *
 * 512MB is chosen to be a NO-OP for essentially every database that exists
 * today, and to bound the one that grows past it without the caller having to
 * know the failure mode.  That is ZS_NOAUTOREPACK's reasoning: forgetting is
 * expensive and hard to attribute, because a database that merely accumulates
 * files just looks slow. */
#define ZSI_DEFAULT_REPACK_MAX (512 * 1024 * 1024)

/* How much of an in-order output a writer may HOLD (A-20).  A region larger than
 * this is streamed out of the inputs' mappings as it is produced, so a merge's
 * memory does not grow with the database; a smaller one is held, because holding
 * it lets the region be checksummed in one call -- about 54 GB/s against 21 GB/s
 * streamed -- and written in one write.
 *
 * 64MB rather than something larger because the point is the ceiling: the
 * buffered shape is O(output), which for a compaction (D-26) is O(database), and
 * a caller compacting a database bigger than its memory had no way to see why it
 * failed.  Rather than something smaller because every merge an ordinary database
 * performs is well under it, and those keep the one-shot checksum.  Measured on a
 * 2M-record load: 341MB peak RSS streaming everything against 684MB holding
 * everything, for about 6% of the load's time. */
#define ZSI_DEFAULT_MERGE_MEMORY (64 * 1024 * 1024)

/* How many files the cap above may skip before it yields for one selection.
 *
 * The cap costs the file-count bound the geometric policy exists to provide: a
 * skipped file is never selected again, so the count grows linearly in total
 * size and the read path degrades linearly in the count (D-14d).  So the cap is
 * itself bounded -- past this many skipped files the uncapped walk runs and
 * merges the pile, which is the same doubling-amortised work the uncapped
 * policy would have done anyway.  The steady state is therefore the uncapped
 * one, with cheaper repacks in between.
 *
 * It counts SKIPPED files, not all in-order files.  The natural ladder is
 * log(total / rollover_size) deep -- about 15 files at 100GB -- so a budget
 * over the total would hold a large database permanently in the uncapped case
 * and the cap would never act at all.
 *
 * A constant rather than a knob: it decides how much read degradation is
 * tolerated before paying for a big merge, and unlike the cap itself there is
 * no unit a caller could reason in.  8 is a guess, not a measurement -- zsbench
 * has no workload that builds a file set this deep at these sizes -- and is the
 * number here most likely to be wrong. */
#define ZSI_REPACK_MAX_FROZEN 8

/* How many pointer tables a generation publishes over its life, which is what
 * sets the default threshold (P-13, A-9): rollover_size / this.
 *
 * BOTH ends cost, and neither is the one to fix first.  A write transaction
 * refreshes its snapshot at begin (C-4), replaying from the last published
 * point, so publishing too rarely leaves that replay unbounded and a
 * one-store-per-transaction load quadratic.  Publishing too often costs an
 * O(records) rewrite of the whole table each time -- never synced (P-14), so
 * cheaper per event, but the events are what this bounds.
 *
 * PROPORTIONAL, and it took a downstream report to see why.  This was an absolute
 * 32KB, on the reasoning that the knee is set by how much data a replay walks and
 * not by how large a generation may grow.  The replay half of that is true; the
 * publish half is not, because one publication rewrites the whole table and a
 * table is proportional to its generation.  Hold the byte gap fixed and a bigger
 * generation publishes just as often while each publication costs more, so the
 * total is QUADRATIC in generation size: measured on a 2M-record load with a cache
 * configured, 1.48GB written at a 2MB rollover, 2.03GB at 16MB and 4.70GB at 64MB,
 * for about 2000 publications in every case -- and 4.69s against 1.91s for the
 * same load with no cache.  Bounding the COUNT per generation is what keeps it
 * linear, and that means a fraction.
 *
 * A fraction of THE FILE IT DESCRIBES, not of rollover_size, and not an absolute
 * count.  All three were tried and the file is the only one that gets both ends
 * right at once:
 *
 *   - absolute (32KB, what this was) bounds the replay but not the publishing, so
 *     the total is quadratic in generation size as above;
 *   - a fraction of rollover_size bounds the publishing, but a SMALL database with
 *     a large rollover configured then publishes a handful of times or never, and
 *     pays for it at every open -- measured at +63% on open-plus-first-read for a
 *     1MB database at a 16MB rollover (0.093ms to 0.152ms).  Most databases are
 *     small and Cyrus opens them from short-lived processes, so that is the wrong
 *     end to lose;
 *   - a fraction of the file scales with the thing that actually sets both costs.
 *     A 2MB generation gets the 32KB that was measured as the knee, so this is a
 *     no-op for the default; a 64MB one publishes 64 times instead of 2000; a 1MB
 *     one publishes every 16KB and its opens stay cheap whatever rollover_size
 *     says.
 *
 * The floor stops a tiny file publishing on every commit.  It can be small,
 * because the cost of publishing is O(records in the file) and that is what is
 * small here -- the bound protects against churn, not against volume. */
#define ZSI_INDEX_PUBLISHES_PER_GEN 64
#define ZSI_INDEX_MIN_THRESHOLD     (4 * 1024)

/* The streaming writer's append buffer (C-8): stores batch into it, so a
 * store is a memcpy rather than a syscall, and it flushes whenever a read
 * needs bytes it still holds and at every terminator.
 *
 * It STARTS here and doubles up to ZSI_TXN_CHUNK_MAX, because since C-7 went to
 * one gate a span that is still buffered leaves in ONE write together with its
 * terminator -- so the buffer decides how much commit traffic takes that path,
 * and a transaction that outgrows it pays a second write per overflow.  Growing
 * on demand rather than allocating the maximum is what keeps that from being a
 * memory regression: the buffer belongs to an in-flight WRITE transaction, a
 * process may hold many databases open at once, and a one-record transaction
 * must go on costing what it costs today. */
#define ZSI_TXN_CHUNK     (64 * 1024)
#define ZSI_TXN_CHUNK_MAX (4 * 1024 * 1024)

/********** LIBRARY SUPPORT *************/

static void *zsi_zmalloc(size_t bytes)
{
    void *res = malloc(bytes);
    if (!res) return NULL;
    memset(res, 0, bytes);
    return res;
}

/* Fill a buffer with random bytes from /dev/urandom (present on Linux, macOS
 * and every BSD).  Returns false if we couldn't read the whole buffer, in
 * which case the caller needs its own fallback. */
static bool zsi_random_bytes(void *buf, size_t len)
{
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return false;
    size_t off = 0;
    while (off < len) {
        ssize_t n = read(fd, (char *)buf + off, len - off);
        if (n <= 0) break;
        off += (size_t)n;
    }
    close(fd);
    return off == len;
}

/* A mix of weak entropy sources, for when /dev/urandom isn't available.  Only
 * ever used to avoid failing outright when generating a database UUID. */
static uint64_t zsi_weak_entropy(void)
{
    uint64_t a = (uint64_t)time(NULL);
    uint64_t b = (uint64_t)getpid();
    uint64_t c = (uint64_t)(uintptr_t)&a;
    return a ^ (b << 32) ^ c;
}

typedef unsigned char zsi_uuid_t[16];
#define ZSI_UUID_STR_LEN 37     /* 36 characters plus NUL */

/* Fill a 16-byte buffer with a random version-4 UUID.  Falls back to weak
 * entropy if /dev/urandom is somehow unavailable, so we always produce a
 * distinct identifier rather than failing.  The value is arbitrary and opaque;
 * only its 16-byte encoding (F-11) and its textual form (D-0) are fixed. */
static void zsi_uuid_generate(zsi_uuid_t uuid)
{
    if (!zsi_random_bytes(uuid, sizeof(zsi_uuid_t))) {
        uint64_t a = zsi_weak_entropy();
        uint64_t b = zsi_weak_entropy() * 0x2545F4914F6CDD1DULL;
        memcpy((char *)uuid + 0, &a, 8);
        memcpy((char *)uuid + 8, &b, 8);
    }
    uuid[6] = (unsigned char)((uuid[6] & 0x0f) | 0x40);  /* version 4 */
    uuid[8] = (unsigned char)((uuid[8] & 0x3f) | 0x80);  /* RFC 4122 variant */
}

/* Format as the canonical lowercase 8-4-4-4-12 string (D-0), matching
 * libuuid's uuid_unparse.  out must hold ZSI_UUID_STR_LEN bytes.
 *
 * Lowercase here, against the uppercase generations of D-1.  The contrast is
 * deliberate: it makes a malformed filename obvious on sight. */
static void zsi_uuid_unparse(const zsi_uuid_t uuid, char *out)
{
    snprintf(out, ZSI_UUID_STR_LEN,
             "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             uuid[0], uuid[1], uuid[2], uuid[3], uuid[4], uuid[5], uuid[6],
             uuid[7], uuid[8], uuid[9], uuid[10], uuid[11], uuid[12], uuid[13],
             uuid[14], uuid[15]);
}

static int zsi_hexval(unsigned char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;                          /* deliberately not 'A'-'F': see below */
}

/* Parse exactly the 36-character lowercase hyphenated form and nothing else:
 * no uppercase, no braces, no urn: prefix, no missing or extra hyphens.
 *
 * D-0 pins the spelling, and a database's file set is "the names matching
 * zeroskip-<uuid>-*" (D-4).  A lenient parser would let two implementations
 * disagree about which files belong to a database, which is a corruption bug
 * wearing a compatibility costume.  Returns 0 on success.
 *
 * in need not be NUL-terminated at 36; the caller may pass a pointer into a
 * longer filename, and we read exactly 36 bytes. */
static int zsi_uuid_parse(const char *in, zsi_uuid_t out)
{
    static const int hyphens[4] = { 8, 13, 18, 23 };
    size_t i, o = 0, h = 0;

    for (i = 0; i < 36; i++) {
        if (h < 4 && (int)i == hyphens[h]) {
            if (in[i] != '-') return -1;
            h++;
            continue;
        }
        int hi = zsi_hexval((unsigned char)in[i]);
        int lo = zsi_hexval((unsigned char)in[i + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[o++] = (unsigned char)((hi << 4) | lo);
        i++;                            /* consumed a pair */
    }

    return (o == 16 && h == 4) ? 0 : -1;
}

/* Little-endian accessors (F-1, G-0a).
 *
 * Assembled from individual bytes through an unsigned char *, which is always
 * permitted regardless of alignment or host byte order.  Nothing here casts the
 * mapped buffer to a wider integer type, so these are correct on a big-endian
 * host and on a target that faults on unaligned loads, and they compile down to
 * a single load on the platforms where that is legal. */
static uint16_t zsi_get16(const char *p)
{
    const unsigned char *u = (const unsigned char *)p;
    return (uint16_t)((uint16_t)u[0] | ((uint16_t)u[1] << 8));
}

static uint32_t zsi_get24(const char *p)
{
    const unsigned char *u = (const unsigned char *)p;
    return (uint32_t)u[0] | ((uint32_t)u[1] << 8) | ((uint32_t)u[2] << 16);
}

static uint32_t zsi_get32(const char *p)
{
    const unsigned char *u = (const unsigned char *)p;
    return (uint32_t)u[0] | ((uint32_t)u[1] << 8)
         | ((uint32_t)u[2] << 16) | ((uint32_t)u[3] << 24);
}

static uint64_t zsi_get64(const char *p)
{
    return (uint64_t)zsi_get32(p) | ((uint64_t)zsi_get32(p + 4) << 32);
}

static void zsi_put16(char *p, uint16_t v)
{
    unsigned char *u = (unsigned char *)p;
    u[0] = (unsigned char)(v & 0xFF);
    u[1] = (unsigned char)((v >> 8) & 0xFF);
}

static void zsi_put24(char *p, uint32_t v)
{
    unsigned char *u = (unsigned char *)p;
    u[0] = (unsigned char)(v & 0xFF);
    u[1] = (unsigned char)((v >> 8) & 0xFF);
    u[2] = (unsigned char)((v >> 16) & 0xFF);
}

static void zsi_put32(char *p, uint32_t v)
{
    unsigned char *u = (unsigned char *)p;
    u[0] = (unsigned char)(v & 0xFF);
    u[1] = (unsigned char)((v >> 8) & 0xFF);
    u[2] = (unsigned char)((v >> 16) & 0xFF);
    u[3] = (unsigned char)((v >> 24) & 0xFF);
}

static void zsi_put64(char *p, uint64_t v)
{
    zsi_put32(p, (uint32_t)(v & 0xFFFFFFFFu));
    zsi_put32(p + 4, (uint32_t)((v >> 32) & 0xFFFFFFFFu));
}

/* Overflow-checked arithmetic (G-0b).
 *
 * Every length, count and offset read from a file is attacker- and
 * corruption-controlled.  "keylen + vallen + 2" and "offset + record_length"
 * are exactly the expressions that turn a bounds check into a bounds-check
 * bypass when they wrap, so they go through these rather than being written
 * inline.  Each returns false on overflow and leaves *out untouched. */
static bool zsi_add_sz(size_t a, size_t b, size_t *out)
{
    if (a > SIZE_MAX - b) return false;
    *out = a + b;
    return true;
}

static bool zsi_add3_sz(size_t a, size_t b, size_t c, size_t *out)
{
    size_t t;
    if (!zsi_add_sz(a, b, &t)) return false;
    return zsi_add_sz(t, c, out);
}

/* Round up to a multiple of 8 (F-2), returning 0 when the result would not fit.
 *
 * Callers treat 0 as "not a valid length", which matters because roundup8 is
 * applied to lengths straight out of a file, where a value near SIZE_MAX is one
 * corruption away.
 *
 * The guard is documentation rather than arithmetic: unsigned overflow is
 * well-defined in C, and for n >= SIZE_MAX-6 the wrapping expression already
 * yields 0, so removing the guard changes nothing observable.  It stays because
 * the contract should be visible at the top of the function rather than deduced
 * from modular arithmetic, and because it keeps holding if the rounding width or
 * the parameter type ever changes. */
static size_t zsi_roundup8(size_t n)
{
    if (n > SIZE_MAX - 7) return 0;
    return (n + 7) & ~(size_t)7;
}

/* A monotonic nanosecond reading, for A-17's counters and nothing else.
 *
 * Zero where there is no monotonic clock, which the stats document -- a counter
 * that reads zero is better than a build that fails, since this file is vendored
 * and CLOCK_MONOTONIC is the one thing here that a very old libc may lack while
 * having everything else.  Never used for correctness: nothing in the format, the
 * protocol or a decision depends on a duration. */
static uint64_t zsi_now_ns(void)
{
#ifdef CLOCK_MONOTONIC
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
    return (uint64_t)ts.tv_sec * 1000000000u + (uint64_t)ts.tv_nsec;
#else
    return 0;
#endif
}

/* Elapsed since `t0`, or zero if either reading failed -- so a caller adds a
 * duration that is never negative and never absurd. */
static uint64_t zsi_since_ns(uint64_t t0)
{
    uint64_t now = zsi_now_ns();
    return (t0 && now > t0) ? now - t0 : 0;
}

/* Append bytes to a file descriptor, retrying a short write.  Here rather than
 * in the write path because the in-order writers emit through it too, and a
 * section may only call upwards. */
static int zsi_write_all(int fd, const char *buf, size_t len)
{
    size_t off = 0;

    while (off < len) {
        ssize_t n = ZS_WRITE(fd, buf + off, len - off);
        if (n < 0) {
            if (errno == EINTR) continue;
            return ZS_IOERROR;
        }
        if (n == 0) return ZS_IOERROR;
        off += (size_t)n;
    }

    return ZS_OK;
}

/* The same at a given offset.  lseek + ZS_WRITE rather than pwrite, so the
 * writes stay visible to the hook T-8's crash injection interposes -- a writer
 * that went around it would quietly stop being crash-tested. */
static int zsi_write_at(int fd, const char *buf, size_t len, off_t off)
{
    if (lseek(fd, off, SEEK_SET) == (off_t)-1) return ZS_IOERROR;
    return zsi_write_all(fd, buf, len);
}

/********** COMPARATORS *************/

/* The default comparator (F-11a).
 *
 * Compare min(alen, blen) bytes as UNSIGNED octets; if they differ, that
 * decides.  If they are equal, the shorter key sorts first.
 *
 * Written out rather than delegating to the C library, per F-11a.  Being precise
 * about why, because the folklore version of this warning is wrong and leads
 * people to "fix" the wrong thing:
 *
 *   - memcmp is defined to compare as unsigned char, so using it for the common
 *     prefix would in fact be correct.  What it does not do is order keys of
 *     differing length -- that is half of this function's job -- and its return
 *     magnitude is unspecified, so only its sign may be used.  A comparator that
 *     is just `return memcmp(a, b, min(alen, blen));` is broken for a key and
 *     its own prefix, which is the case T-2c leads with.
 *   - the platform hazard is comparing plain `char` directly, whose signedness
 *     varies: that orders keys above 0x7F differently on ARM than on x86 and
 *     produces pointer sections the other platform cannot read.  Hence the
 *     explicit unsigned char pointers below.
 *
 * The signedness failure is silent and survives every test that uses ASCII keys,
 * which is why T-2c's table includes 0x7F against 0x80.  A memcmp-plus-length
 * variant is not detectably different from this loop, so no test enforces the
 * loop itself -- only the ordering it produces. */
static int zsi_compar_default(const char *a, size_t alen,
                              const char *b, size_t blen)
{
    size_t n = alen < blen ? alen : blen;

    /* memcmp is DEFINED to compare as unsigned char, which is the whole of
     * F-11a's prefix rule -- and it is the one place the platform hazard bites,
     * because plain `char` is signed on x86 and unsigned on ARM, so a
     * hand-rolled loop over `char` misorders every key above 0x7F on one of
     * them and produces pointer sections the other cannot read.  Going through
     * memcmp states that requirement rather than re-implementing it, and lets
     * the compiler compare a word at a time instead of a byte.
     *
     * Only its SIGN is used: the magnitude is unspecified, so it is normalised
     * to -1/0/1 here rather than returned raw.  The length tie-break below is
     * the half memcmp says nothing about -- without it a key and its own prefix
     * compare equal, which is the bug "compar: longer key first" preserves. */
    int c = memcmp(a, b, n);
    if (c) return c < 0 ? -1 : 1;

    if (alen == blen) return 0;
    return alen < blen ? -1 : 1;
}

/* Dispatch a comparison, taking the BUILT-IN through a direct call.
 *
 * zs_compar is a function pointer, so every comparison was an indirect call:
 * the disassembly of the merge loop had no direct calls left in it at all, only
 * `blr` through db->compar and file->csum.  An indirect call cannot be inlined,
 * and the default comparator's body is small enough that the call is comparable
 * to the work it does -- a handful of byte compares and a length tiebreak.
 *
 * The test is pointer equality against a static symbol, so the branch is
 * perfectly predicted: a database's comparator is fixed at open and never
 * changes.  What it buys is not the branch but what the branch enables --
 * a direct call to a static function, which the compiler then inlines.
 *
 * A caller-supplied comparator keeps the indirect path, unchanged.  Both arms
 * run the same function they always did, so F-11a's total order is untouched
 * and this is not interoperability surface. */
static inline int zsi_cmp(zs_compar *f, const char *a, size_t alen,
                          const char *b, size_t blen)
{
    if (f == zsi_compar_default) return zsi_compar_default(a, alen, b, blen);
    return f(a, alen, b, blen);
}

/* A caller supplying its own comparator MUST supply a name; names are compared
 * byte for byte, and an empty name is invalid (F-11b). */
static bool zsi_compar_name_valid(const char *name)
{
    if (!name) return false;
    size_t n = strlen(name);
    return n >= 1 && n <= 16;
}

/********** CHECKSUMS *************/

/* Exactly three engines exist (F-5).  The id lives in the low 4 bits of each
 * file header's flags field, so every file is self-describing and files written
 * under different engines may coexist in one database (F-5a). */
#define ZSI_CSUM_NONE     0
#define ZSI_CSUM_XXHASH   1
#define ZSI_CSUM_EXTERNAL 2
#define ZSI_CSUM_MASK     0x000F

static uint64_t zsi_csum_none(const char *buf, size_t len)
{
    (void)buf;
    (void)len;
    return 0;
}

/* Engine 1: XXH3_64bits with the default seed of 0, stored little-endian like
 * every other integer (F-5b).  ALL 64 BITS since format 3 -- format 2 kept the
 * low half, so a format-3 checksum of the same bytes has the format-2 value in
 * its low half, which is a property of truncation and not a compatibility path
 * (the magic separates the formats, F-6b).  The seed is pinned because
 * otherwise two implementations produce different bytes from the same input.
 *
 * Note there is NO "if (!len) return 0;" short-circuit here, unlike twom's
 * equivalent.  F-26g requires the engine's value for empty input -- the values
 * region of a zero-record in-order file is empty and is covered by the data
 * checksum, so the engine's empty-input value has to be the one stored.  Adding
 * the short-circuit back would make such a file fail its own consistency
 * check. */
static uint64_t zsi_csum_xxhash(const char *buf, size_t len)
{
    return XXH3_64bits(buf, len);
}

/* Resolve an engine id to its function.  Returns NULL for an unknown id, and
 * for engine 2 returns the caller-supplied function, which may itself be NULL
 * -- opening a database whose files use engine 2 without supplying one is an
 * error the caller reports, not something to paper over here (A-6).
 *
 * Takes the external function directly rather than a struct zs_db *, so this
 * section has no dependency on anything defined later in the file. */
static zs_csum *zsi_csum_for_id(unsigned id, zs_csum *external)
{
    switch (id) {
    case ZSI_CSUM_NONE:     return zsi_csum_none;
    case ZSI_CSUM_XXHASH:   return zsi_csum_xxhash;
    case ZSI_CSUM_EXTERNAL: return external;
    }

    return NULL;
}

/* Which engine to write into files this handle creates (A-6).  Never overrides
 * what an existing file records. */
static unsigned zsi_csum_id_for_flags(uint32_t flags)
{
    if (flags & ZS_CSUM_EXTERNAL) return ZSI_CSUM_EXTERNAL;
    if (flags & ZS_CSUM_NONE)     return ZSI_CSUM_NONE;
    if (flags & ZS_CSUM_XXHASH)   return ZSI_CSUM_XXHASH;

    return ZSI_CSUM_XXHASH;             /* the default (F-5) */
}

/* Checksum two regions as though concatenated.
 *
 * A span terminator's checksum covers the span's data bytes followed by the
 * terminator's own bytes up to the checksum field (F-19).  The span may be
 * large, so joining them into one buffer is not an option on the hot path.
 *
 * Engine 1 uses XXH3's streaming state, which is required to agree with the
 * one-shot form over the concatenation -- asserted in test_interop_constants
 * rather than assumed.  Engine 0 ignores its input entirely.  Engine 2 is
 * caller-supplied and outside the conformance corpus (F-5d), so it falls back
 * to a temporary join and accepts the allocation. */
static uint64_t zsi_csum2(zs_csum *csum, unsigned id,
                          const char *a, size_t alen,
                          const char *b, size_t blen)
{
    if (id == ZSI_CSUM_NONE) return 0;

    if (id == ZSI_CSUM_XXHASH) {
        XXH3_state_t st;
        XXH3_64bits_reset(&st);
        if (alen) XXH3_64bits_update(&st, a, alen);
        if (blen) XXH3_64bits_update(&st, b, blen);
        return XXH3_64bits_digest(&st);
    }

    /* engine 2 */
    size_t total;
    if (!zsi_add_sz(alen, blen, &total)) return 0;
    char *join = malloc(total ? total : 1);
    if (!join) return 0;
    if (alen) memcpy(join, a, alen);
    if (blen) memcpy(join + alen, b, blen);
    uint64_t r = csum(join, total);
    free(join);
    return r;
}

/********** FILENAMES *************/

/* The directory is the file set (section 5.2).  There is no manifest: filenames
 * carry each file's generation range, so one readdir yields the set and every
 * range without opening a single file.
 *
 *   zeroskip-<uuid>.current          THE active file (unordered), no generation
 *   zeroskip-<uuid>-<start>-<end>    in-order file
 *   zeroskip.tmp.<pid>.<n>           staging for a repack or conversion output
 *   zeroskip.lock                    holds the fcntl locks
 *
 * zeroskip-* matches data files only and zeroskip.* matches metadata, so both
 * sets are prefix-globbable and staging names can never match the data-file
 * pattern (D-2).
 *
 * Two properties of this spelling are load-bearing for D-5's overlap resolution,
 * and both are asserted directly on generated names in test_filename_*:
 *
 *   - generations are UPPERCASE hex, zero-padded to exactly 8 digits (D-1).
 *     Fixed width keeps lexical and numeric order identical, and 8 digits is
 *     exactly the range of a 32-bit generation, so every representable
 *     generation has a name and the width never needs to change.
 *   - the active file is ".current", with a DOT (D-1b).  Two consequences,
 *     both deliberate: "zeroskip-<uuid>-*" matches the generation-named files
 *     and only those, so nothing has to grep the active file back out of the
 *     common pattern; and '.' (0x2E) is above '-' (0x2D), so it sorts AFTER
 *     every generation name, which is where its generation puts it and what
 *     D-5's "take the last" rule requires.
 *
 *     Its generation is NOT in its name -- it comes from the header, which is
 *     free because the active file is the one file a snapshot must open and
 *     replay anyway (D-13a).  There is one such name, so at most one unordered
 *     file can exist at all (D-12a): the invariant is structural now, not a
 *     steady state maintained by policy.
 *
 * The UUID is lowercase (D-0) against those uppercase generations.  The contrast
 * is deliberate: it makes a malformed name obvious on sight. */

#define ZSI_NAME_PREFIX     "zeroskip-"
#define ZSI_NAME_PREFIX_LEN 9
#define ZSI_LOCK_NAME       "zeroskip.lock"
#define ZSI_STAGING_PREFIX  "zeroskip.tmp."
#define ZSI_CACHE_DIR_NAME  "zeroskip.cache"   /* P-2b, in the metadata namespace (D-2) */
#define ZSI_CURRENT_SUFFIX  ".current"         /* D-1b */

/* "zeroskip-" + 36 + "-" + 8 + "-" + 8 + NUL = 64.  Rounded up for headroom. */
#define ZSI_NAME_MAX 80

enum zsi_nametype {
    ZSI_NAME_OTHER = 0,      /* not a data file of ours -- ignore (D-4) */
    ZSI_NAME_UNORDERED,      /* zeroskip-<uuid>.current  -- generation unknown */
    ZSI_NAME_INORDER         /* zeroskip-<uuid>-<start>-<end> */
};

/* The active file (D-1b).  Takes no generation because its name carries none;
 * a caller that has one and wants a name for it wants zsi_name_format. */
static void zsi_name_current(char *out, const zsi_uuid_t uuid)
{
    char ustr[ZSI_UUID_STR_LEN];
    zsi_uuid_unparse(uuid, ustr);
    snprintf(out, ZSI_NAME_MAX, "%s%s%s",
             ZSI_NAME_PREFIX, ustr, ZSI_CURRENT_SUFFIX);
}

/* An in-order file's name.  end == 0 is not a shorthand for the active file:
 * that name has no generation in it at all, so there is nothing to pass here
 * and zsi_name_current is a different function on purpose. */
static void zsi_name_format(char *out, const zsi_uuid_t uuid,
                            uint32_t start, uint32_t end)
{
    char ustr[ZSI_UUID_STR_LEN];
    zsi_uuid_unparse(uuid, ustr);

    assert(end != 0);
    snprintf(out, ZSI_NAME_MAX, "%s%s-%08X-%08X",
             ZSI_NAME_PREFIX, ustr, start, end);
}

/* Parse exactly 8 uppercase hex digits.  Returns the character count consumed,
 * or 0 on any deviation: lowercase, fewer or more digits, a 0x prefix, a sign. */
static size_t zsi_parse_gen8(const char *p, uint32_t *out)
{
    uint32_t v = 0;

    for (size_t i = 0; i < 8; i++) {
        unsigned char c = (unsigned char)p[i];
        int d;
        if (c >= '0' && c <= '9') d = c - '0';
        else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
        else return 0;                  /* lowercase deliberately excluded */
        v = (v << 4) | (uint32_t)d;
    }

    *out = v;
    return 8;
}

/* Classify a directory entry.  Fills uuid/start/end when it is a data file; for
 * the active file *end is 0, which F-9 makes unambiguous, and *start is 0 too
 * because its generation is not in its name (D-1b) -- the caller reads it from
 * the header.  F-9 makes that sentinel unambiguous as well: no real generation
 * is 0.
 *
 * Strict by design.  A lenient parser here would let two implementations
 * disagree about which files belong to a database, and D-4's "a file
 * participates if its name matches" makes that disagreement a correctness bug
 * rather than a cosmetic one. */
static enum zsi_nametype zsi_name_parse(const char *name, zsi_uuid_t uuid,
                                        uint32_t *start, uint32_t *end)
{
    /* Anything beginning "zeroskip." is metadata, not data (D-2): the lock file
     * and staging names live there and must never match. */
    if (strncmp(name, ZSI_NAME_PREFIX, ZSI_NAME_PREFIX_LEN) != 0)
        return ZSI_NAME_OTHER;

    const char *p = name + ZSI_NAME_PREFIX_LEN;

    /* 36 characters of lowercase hyphenated UUID, then a separator. */
    if (strlen(p) < 36 + 1) return ZSI_NAME_OTHER;
    if (zsi_uuid_parse(p, uuid) != 0) return ZSI_NAME_OTHER;
    p += 36;

    /* D-1b: the active file, whose generation lives in its header. */
    if (strcmp(p, ZSI_CURRENT_SUFFIX) == 0) {
        *start = 0;
        *end = 0;
        return ZSI_NAME_UNORDERED;
    }

    if (*p != '-') return ZSI_NAME_OTHER;
    p++;

    uint32_t s, e;
    if (zsi_parse_gen8(p, &s) != 8) return ZSI_NAME_OTHER;
    p += 8;

    /* F-9: generations start at 1, so 0 is never a legitimate start. */
    if (s == 0) return ZSI_NAME_OTHER;

    /* A bare generation with nothing after it was the OLD active-file name.
     * D-1b replaced it and F-7a forbids a fallback, so it is simply not a name
     * this format produces. */
    if (*p != '-') return ZSI_NAME_OTHER;
    p++;

    if (zsi_parse_gen8(p, &e) != 8) return ZSI_NAME_OTHER;
    p += 8;

    /* Nothing trailing: an in-order name ends at its second generation. */
    if (*p != '\0') return ZSI_NAME_OTHER;

    /* end == 0 would make an in-order name indistinguishable from an unordered
     * one, and a range must not run backwards. */
    if (e == 0 || e < s) return ZSI_NAME_OTHER;

    *start = s;
    *end = e;
    return ZSI_NAME_INORDER;
}

/* A staging name.  The pid is for human legibility only -- it is NOT what makes
 * the name unique, because a pid is not unique on shared storage where two hosts
 * readily have the same one.  D-20a requires O_CREAT|O_EXCL and advancing <n>
 * until it succeeds; that is what actually guarantees exclusivity, and two
 * processes writing one staging file would otherwise produce an interleaved
 * output that then gets renamed into place as though complete. */
static void zsi_staging_name(char *out, unsigned n)
{
    snprintf(out, ZSI_NAME_MAX, "%s%d.%u", ZSI_STAGING_PREFIX, (int)getpid(), n);
}

/********** FILE HEADER *************/

/* Every file begins with the same 16 bytes (section 4.2):
 *
 *     89 7A 65 72 6F 73 6B 69 70 32 0D 0A 1A 0A 00 00
 *     \x89  z  e  r  o  s  k  i  p  2 \r \n ^Z \n \0 \0
 *
 * Each part earns its place, following the reasoning behind the PNG signature:
 *
 *   89        high bit set, so no text file can be mistaken for a database and a
 *             transfer that strips the eighth bit is detected.  Also makes the
 *             sequence invalid UTF-8 (F-6a): 0x89 is in the continuation-byte
 *             range 0x80-0xBF, and a continuation byte cannot begin a sequence.
 *             Anything validating the file as text fails at byte 0 rather than
 *             part way through, and anything that sanitises invalid UTF-8 by
 *             substitution replaces it with U+FFFD, destroying the magic
 *             detectably instead of silently corrupting the body.
 *   zeroskip  human-readable in a hex dump and to file(1)
 *   2         major format version in the magic, so an incompatible format is
 *             distinguishable without parsing.  It went 1 -> 2 for format 3,
 *             which shares no structure with format 2: wider checksums, none on
 *             records, and an in-order body of three regions rather than one.
 *             So each rejects the other's files at byte 9 and there is no
 *             compatibility path in either direction (F-6b, R-6).
 *   0D 0A     CR-LF trap: newline translation in either direction alters it
 *   1A        DOS end-of-file, so accidentally type-ing a file stops early
 *   0A        bare LF, catching the inverse newline translation
 *   00 00     NUL-terminates the printable part and pads to 16
 *
 * A reader MUST validate all 16 bytes, not a prefix (F-6). */
#define ZSI_MAGIC_LEN 16

static const unsigned char zsi_magic[ZSI_MAGIC_LEN] = {
    0x89, 0x7A, 0x65, 0x72, 0x6F, 0x73, 0x6B, 0x69,
    0x70, 0x32, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00
};

/* Field offsets within the 96-byte header (section 4.3).  Spelled out rather
 * than derived by summing sizes, so a table in the spec maps to a table here.
 *
 * KEYS_LEN and VALUES_LEN are what let the pointer region come FIRST: with every
 * section's length known from the header, nothing is located by reading
 * backwards and the trailer holds only checksums (F-10a, F-26a).  Both are zero
 * in an unordered file, which has neither region. */
#define ZSI_HEADER_LEN         96
#define ZSI_HDR_OFF_MAGIC       0   /* 16 */
#define ZSI_HDR_OFF_VREAD      16   /*  1 */
#define ZSI_HDR_OFF_VWRITE     17   /*  1 */
#define ZSI_HDR_OFF_FLAGS      18   /*  2 */
#define ZSI_HDR_OFF_RESERVED1  20   /*  4 */
#define ZSI_HDR_OFF_UUID       24   /* 16 */
#define ZSI_HDR_OFF_START      40   /*  4 */
#define ZSI_HDR_OFF_END        44   /*  4 */
#define ZSI_HDR_OFF_COMPAR     48   /* 16 */
#define ZSI_HDR_OFF_KEYSLEN    64   /*  8 */
#define ZSI_HDR_OFF_VALSLEN    72   /*  8 */
#define ZSI_HDR_OFF_RESERVED2  80   /*  8 */
#define ZSI_HDR_OFF_CSUM       88   /*  8, covers [0, 88) */

/* Flags bit 4: valptr fields in this file's key entries are 8 bytes rather
 * than 4 (F-26c).  Set exactly when the values region does not end below 4GB,
 * and canonical -- a consistency check re-derives it. */
#define ZSI_HDR_FLAG_WIDEVAL   0x0010

/* The lowest library version able to read, and to write, a file we produce.
 * Version 3 is format 3's first: versions 1 and 2 belong to the previous
 * format, which the magic already separates (F-6b, F-7a). */
#define ZSI_VERSION_READ  3
#define ZSI_VERSION_WRITE 3

#define ZSI_COMPAR_NAME_LEN 16

struct zsi_header {
    uint8_t     version_read;
    uint8_t     version_write;
    uint16_t    flags;                            /* low 4 bits: csum engine */
    zsi_uuid_t  uuid;
    uint32_t    start;
    uint32_t    end;                              /* 0 == unordered (F-9) */
    char        compar_name[ZSI_COMPAR_NAME_LEN]; /* NUL-padded, not NUL-terminated */
    uint64_t    keys_len;                         /* in-order only; 0 otherwise */
    uint64_t    values_len;                       /* in-order only; 0 otherwise */
};

/* end == 0 means unordered with no pointer section; end != 0 means in-order
 * with pointers.  The two kinds are exhaustive and distinguishable from the
 * header alone, so a reader always knows, before reading anything else, whether
 * a pointer section must be present.  Generations start at 1, so end == 0 is
 * never a legitimate generation (F-9). */
static bool zsi_header_is_unordered(const struct zsi_header *h)
{
    return h->end == 0;
}

static void zsi_header_encode(char *buf, const struct zsi_header *hdr,
                              zs_csum *csum)
{
    memset(buf, 0, ZSI_HEADER_LEN);

    memcpy(buf + ZSI_HDR_OFF_MAGIC, zsi_magic, ZSI_MAGIC_LEN);
    buf[ZSI_HDR_OFF_VREAD]  = (char)hdr->version_read;
    buf[ZSI_HDR_OFF_VWRITE] = (char)hdr->version_write;
    zsi_put16(buf + ZSI_HDR_OFF_FLAGS, hdr->flags);
    /* RESERVED1 and RESERVED2 stay zero: written as zero, ignored on read
     * (F-8).  The memset above is what writes them. */
    memcpy(buf + ZSI_HDR_OFF_UUID, hdr->uuid, 16);
    zsi_put32(buf + ZSI_HDR_OFF_START, hdr->start);
    zsi_put32(buf + ZSI_HDR_OFF_END, hdr->end);
    memcpy(buf + ZSI_HDR_OFF_COMPAR, hdr->compar_name, ZSI_COMPAR_NAME_LEN);
    zsi_put64(buf + ZSI_HDR_OFF_KEYSLEN, hdr->keys_len);
    zsi_put64(buf + ZSI_HDR_OFF_VALSLEN, hdr->values_len);

    /* F-4: the checksum is the last 8 bytes and covers everything before it.
     * No field-zeroing anywhere. */
    zsi_put64(buf + ZSI_HDR_OFF_CSUM, csum(buf, ZSI_HDR_OFF_CSUM));
}

/* Decode and validate.  Returns ZS_BADFORMAT if the buffer is too short, the
 * magic is wrong, the header checksum fails, or version_read exceeds ours.
 *
 * Two things this deliberately does NOT do:
 *
 *   - it does not reject a nonzero reserved field.  F-8 says write zero and
 *     ignore on read; the checksum already covers them, and rejecting would make
 *     a future extension unreadable by this version, which is exactly what the
 *     version fields exist to decide instead.
 *   - it does not enforce version_write.  That gate belongs to the writer, so the
 *     value is recorded and the caller decides (F-7).  This is what lets a file
 *     that is readable but not writable be opened read-only rather than refused.
 *
 * csum must be the engine named by the header's own flags.  Callers get it by
 * reading those flags as plain data first -- see zsi_header_engine_id below. */
static int zsi_header_decode(const char *buf, size_t len,
                             zs_csum *csum, struct zsi_header *out)
{
    if (len < ZSI_HEADER_LEN) return ZS_BADFORMAT;

    if (memcmp(buf + ZSI_HDR_OFF_MAGIC, zsi_magic, ZSI_MAGIC_LEN) != 0)
        return ZS_BADFORMAT;

    if (zsi_get64(buf + ZSI_HDR_OFF_CSUM) != csum(buf, ZSI_HDR_OFF_CSUM))
        return ZS_BADCHECKSUM;

    uint8_t vread = (uint8_t)buf[ZSI_HDR_OFF_VREAD];
    if (vread > ZSI_VERSION_READ) return ZS_BADFORMAT;

    /* Versions 1 and 2 are the previous FORMAT, not older versions of this one
     * (F-7a).  A format-2 file never reaches here -- its magic differs, so it
     * was rejected above -- and this is the backstop for a file claiming a
     * format-3 magic with a format-2 version. */
    if (vread < 3) return ZS_BADFORMAT;

    out->version_read  = vread;
    out->version_write = (uint8_t)buf[ZSI_HDR_OFF_VWRITE];
    out->flags         = zsi_get16(buf + ZSI_HDR_OFF_FLAGS);
    memcpy(out->uuid, buf + ZSI_HDR_OFF_UUID, 16);
    out->start         = zsi_get32(buf + ZSI_HDR_OFF_START);
    out->end           = zsi_get32(buf + ZSI_HDR_OFF_END);
    memcpy(out->compar_name, buf + ZSI_HDR_OFF_COMPAR, ZSI_COMPAR_NAME_LEN);
    out->keys_len      = zsi_get64(buf + ZSI_HDR_OFF_KEYSLEN);
    out->values_len    = zsi_get64(buf + ZSI_HDR_OFF_VALSLEN);

    /* F-9: generations start at 1, so a start of 0 is never legitimate.  This is
     * checked here rather than left to the caller because every use of start --
     * resolving an omitted ancestor (F-17), ordering the file set (D-5) -- would
     * otherwise silently work with a nonsense value. */
    if (out->start == 0) return ZS_BADFORMAT;

    /* An in-order file covers start..end inclusive, so end < start is
     * incoherent.  end == 0 is the unordered marker and not a range. */
    if (out->end != 0 && out->end < out->start) return ZS_BADFORMAT;

    /* F-10a: the two region lengths belong to an in-order file and MUST be zero
     * in an unordered one.  Rejecting rather than ignoring, because a nonzero
     * value here would make a reader compute regions that do not exist -- this
     * is a structural field, not a reserved one (F-8). */
    if (out->end == 0 && (out->keys_len || out->values_len))
        return ZS_BADFORMAT;

    return ZS_OK;
}

/* The checksum engine id, read as plain data before any verification (F-5a).
 *
 * There is no bootstrapping problem only because this comes first: the checksum
 * cannot be verified until the engine is known, and the engine is recorded in
 * the very header the checksum protects.  The field is plain data, so reading it
 * unverified is safe -- a wrong value yields a failed checksum, not a wrong
 * interpretation.
 *
 * Requires len >= ZSI_HEADER_LEN; the caller checks that first. */
static unsigned zsi_header_engine_id(const char *buf)
{
    return (unsigned)(zsi_get16(buf + ZSI_HDR_OFF_FLAGS) & ZSI_CSUM_MASK);
}

/********** RECORDS *************/

/* The type byte is a bitfield of six independent properties (section 4.4).
 * Each bit is meaningful in isolation: IsBig selects the wide layout in all
 * three families, HasAncestor says whether the ancestor field is present, and
 * IsDelete means negation -- whether of a key or of a span.  A decoder reads a
 * record's shape from the bits (F-12a). */
#define ZSI_HASKEY      0x01    /* carries a key */
#define ZSI_ISDELETE    0x02    /* negation -- of a key, or of a span */
#define ZSI_ISBIG       0x04    /* wide length fields */
#define ZSI_KEYENTRY    0x08    /* a keys-region entry rather than a record */
#define ZSI_SPANTERM    0x10    /* ends a span */
#define ZSI_POINTERS    0x20    /* begins the pointer region */

/* The fourteen legal type bytes (F-12), and no others.  Bits 0x40 and 0x80 are
 * reserved and always zero.  0x08 was HasAncestor in format 2 and was left
 * reserved when that was removed; format 3 reuses it as KeyEntry, which is safe
 * because the magic separates the formats so no reader meets both meanings
 * (F-12c, F-6b).
 *
 * The two key-bearing families are disjoint BY FILE KIND, not by convention
 * (F-12d): records live in unordered files, key entries in the keys region of an
 * in-order file, and the header says which kind is in front of the decoder
 * before any body byte is read. */
#define ZSI_KEYVALUE         0x01   /* HasKey                               */
#define ZSI_DELETION         0x03   /* HasKey IsDelete                      */
#define ZSI_BIGKEYVALUE      0x05   /* HasKey IsBig                         */
#define ZSI_BIGDELETION      0x07   /* HasKey IsDelete IsBig                */
#define ZSI_KEY              0x09   /* HasKey KeyEntry                      */
#define ZSI_KEYDELETE        0x0B   /* HasKey IsDelete KeyEntry             */
#define ZSI_BIGKEY           0x0D   /* HasKey IsBig KeyEntry                */
#define ZSI_BIGKEYDELETE     0x0F   /* HasKey IsDelete IsBig KeyEntry       */
#define ZSI_COMMIT           0x10   /* SpanTerminator                       */
#define ZSI_ROLLBACK         0x12   /* SpanTerminator IsDelete              */
#define ZSI_COMMIT_LONG      0x14   /* SpanTerminator IsBig                 */
#define ZSI_ROLLBACK_LONG    0x16   /* SpanTerminator IsDelete IsBig        */
#define ZSI_PTRS32           0x20   /* Pointers                             */
#define ZSI_PTRS64           0x24   /* Pointers IsBig                       */

/* True for exactly the ten types above and nothing else, including 0x00.
 *
 * Written as an explicit switch rather than as a bit-property computation.  The
 * table in F-12 is normative, and a computed predicate would be a second
 * specification that can drift from it -- a bitfield admits far more values than
 * it defines, and the near-misses are what matter: two family bits set at once,
 * the retired 0x08 set, IsDelete with Pointers, either reserved bit set.
 * Each is a plausible result of a single flipped bit in a valid type, and each
 * must be rejected rather than half-interpreted (T-2b). */
/* `inline` for the reason zsi_cur_order gives -- it is called once per record
 * decoded, and GCC leaves it out of line otherwise.  It stays a SWITCH: F-12's
 * table is normative and a computed predicate would be a second
 * specification. */
static inline bool zsi_type_valid(uint8_t type)
{
    switch (type) {
    case ZSI_KEYVALUE:
    case ZSI_DELETION:
    case ZSI_BIGKEYVALUE:
    case ZSI_BIGDELETION:
    case ZSI_KEY:
    case ZSI_KEYDELETE:
    case ZSI_BIGKEY:
    case ZSI_BIGKEYDELETE:
    case ZSI_COMMIT:
    case ZSI_ROLLBACK:
    case ZSI_COMMIT_LONG:
    case ZSI_ROLLBACK_LONG:
    case ZSI_PTRS32:
    case ZSI_PTRS64:
        return true;
    }

    return false;
}

/* Encoding limits (F-15).  The short form is mandatory whenever the lengths fit,
 * so these are not tuning knobs -- they are part of the format. */
#define ZSI_SHORT_KEYLEN_MAX  255        /* one byte */
#define ZSI_SHORT_VALLEN_MAX  65535      /* two bytes */
#define ZSI_SHORT_SPANLEN_MAX 0xFFFFFF   /* three bytes */

/* Fixed header sizes per shape, from section 4.5's diagrams. */
#define ZSI_HDRLEN_KEYVALUE        4
#define ZSI_HDRLEN_DELETION        4
#define ZSI_HDRLEN_BIGKEYVALUE    24
#define ZSI_HDRLEN_BIGDELETION    16

/* A key entry's fixed part, BEFORE its valptr (section 4.5a).  The valptr is 4
 * or 8 bytes by the file's WideValptr flag, so an entry's header is 2 + w or
 * 16 + w.  It is PACKED rather than aligned in the short form -- F-2a's one
 * exception -- because the density of the keys region is the whole point of it:
 * a 16-byte key costs 24 bytes packed and 32 aligned, and G-0 already forbids
 * depending on alignment since every field goes through memcpy at a literal
 * offset. */
#define ZSI_HDRLEN_KEY             2   /* + valptr */
#define ZSI_HDRLEN_BIGKEY         16   /* + valptr */

/* 16 rather than format 2's 8: the checksum widened to 64 bits (F-4) and must
 * stay 8-aligned (F-2), which costs 8 bytes per span -- against which every
 * record in the span stopped carrying 4 bytes of its own (F-13a, F-19a). */
#define ZSI_TERMLEN_SHORT         16
#define ZSI_TERMLEN_LONG          24

struct zsi_rec {
    uint8_t     type;
    const char *key;    size_t keylen;
    const char *val;    size_t vallen;   /* val == NULL for a deletion */
    size_t      len;                     /* total on-disk bytes, multiple of 8 */
    const char *base;                    /* where it starts */
};

struct zsi_term {
    uint8_t     type;
    uint64_t    spanlen;
    uint64_t    csum;
    size_t      len;                     /* 16 or 24 */
};

static bool zsi_rec_is_delete(const struct zsi_rec *r)
{
    return (r->type & ZSI_ISDELETE) != 0;
}

/* Bytes a data record will occupy, or 0 if the inputs cannot be encoded.
 *
 * The big form is chosen by key or value length, and by nothing else (F-15).
 *
 * A record carries NO checksum of its own (F-13a): what protects it is the
 * checksum of its span (F-19), verified whenever that span is indexed (F-5e),
 * which covers a torn write and in-place corruption alike. */
static size_t zsi_rec_encoded_len(size_t keylen, size_t vallen, bool isdelete)
{
    size_t hdr, body;

    if (keylen < 1) return 0;           /* F-14: a key is at least 1 byte */

    bool big = keylen > ZSI_SHORT_KEYLEN_MAX
            || (!isdelete && vallen > ZSI_SHORT_VALLEN_MAX);

    if (isdelete) {
        hdr = big ? ZSI_HDRLEN_BIGDELETION : ZSI_HDRLEN_DELETION;
        /* key NUL, no value at all */
        if (!zsi_add_sz(keylen, 1, &body)) return 0;
    } else {
        hdr = big ? ZSI_HDRLEN_BIGKEYVALUE : ZSI_HDRLEN_KEYVALUE;
        /* key NUL value NUL (F-13: stored lengths exclude the terminators) */
        if (!zsi_add3_sz(keylen, vallen, 2, &body)) return 0;
    }

    size_t total;
    if (!zsi_add_sz(hdr, body, &total)) return 0;
    return zsi_roundup8(total);
}

/* Which of the four data types the given shape encodes as (F-15).  Split out so
 * the encoder and the tests agree on it by construction. */
static uint8_t zsi_rec_type_for(size_t keylen, size_t vallen, bool isdelete)
{
    bool big = keylen > ZSI_SHORT_KEYLEN_MAX
            || (!isdelete && vallen > ZSI_SHORT_VALLEN_MAX);

    if (isdelete) return big ? ZSI_BIGDELETION : ZSI_DELETION;
    return big ? ZSI_BIGKEYVALUE : ZSI_KEYVALUE;
}

/* Encode a data record into buf, which must hold zsi_rec_encoded_len bytes.
 *
 * val == NULL encodes a deletion (A-1); a non-NULL zero-length value encodes an
 * empty value, which is a distinct state.  The bytes are a function of the key
 * and value alone (F-18): nothing about the containing file, and nothing about
 * what the key held before, reaches the encoding.
 *
 * Every pad byte is zeroed, not just the tail padding.  Canonical encoding means
 * byte-for-byte reproducibility across implementations (T-12a), and an
 * uninitialised pad byte breaks that while being invisible to every test that
 * reads back through the decoder.
 *
 * There is no checksum parameter: a record carries none (F-13a), and the span
 * terminator's checksum -- computed over the whole span by the writer, which
 * does hold the containing file's engine (A-6/F-5a) -- is what covers it. */
static void zsi_rec_encode(char *buf, const char *key,
                           size_t keylen, const char *val, size_t vallen)
{
    bool isdelete = (val == NULL);
    if (isdelete) vallen = 0;

    uint8_t type = zsi_rec_type_for(keylen, vallen, isdelete);
    size_t total = zsi_rec_encoded_len(keylen, vallen, isdelete);
    size_t body;

    memset(buf, 0, total);
    buf[0] = (char)type;

    if (type & ZSI_ISBIG) {
        if (isdelete) {
            /* BIGDELETION  +0 type, +1 pad(7), +8 keylen, +16 key NUL */
            zsi_put64(buf + 8, (uint64_t)keylen);
            body = ZSI_HDRLEN_BIGDELETION;
        } else {
            /* BIGKEYVALUE  +0 type, +1 pad(7), +8 keylen, +16 vallen,
             *              +24 key NUL value NUL */
            zsi_put64(buf + 8, (uint64_t)keylen);
            zsi_put64(buf + 16, (uint64_t)vallen);
            body = ZSI_HDRLEN_BIGKEYVALUE;
        }
    } else {
        buf[1] = (char)(unsigned char)keylen;
        if (isdelete) {
            /* DELETION  +0 type, +1 keylen, +2 pad(2), +4 key NUL */
            body = ZSI_HDRLEN_DELETION;
        } else {
            /* KEYVALUE  +0 type, +1 keylen, +2 vallen, +4 key NUL value NUL */
            zsi_put16(buf + 2, (uint16_t)vallen);
            body = ZSI_HDRLEN_KEYVALUE;
        }
    }

    /* Key and value are contiguous, separated by a NUL, with a further NUL after
     * the value, then zero padding to the next multiple of 8.  Both are
     * therefore usable in place as C strings, while the stored lengths remain
     * authoritative and may themselves contain NULs (F-13). */
    memcpy(buf + body, key, keylen);
    buf[body + keylen] = '\0';
    if (!isdelete) {
        if (vallen) memcpy(buf + body + keylen + 1, val, vallen);
        buf[body + keylen + 1 + vallen] = '\0';
    }
}

/* Decode the data record at buf[0..len).
 *
 * What is checked here is structure: the type byte, every length bounded and
 * overflow-free, and the total within len.  There is no checksum to verify --
 * a record carries none (F-13a) and its span's does the work (F-19), which is
 * also why nothing here can turn one flipped byte into the loss of every
 * record after it.
 *
 * Returns ZS_BADFORMAT for anything that does not decode.  On success out->len is
 * the record's total on-disk size, which the caller uses to advance -- and which
 * F-29 requires it verify is strictly greater than zero before doing so. */
static int zsi_rec_decode(const char *buf, size_t len, struct zsi_rec *out)
{
    if (len < 1) return ZS_BADFORMAT;

    uint8_t type = (uint8_t)buf[0];
    if (!zsi_type_valid(type)) return ZS_BADFORMAT;
    if (!(type & ZSI_HASKEY)) return ZS_BADFORMAT;   /* not a data record */
    /* F-12d: a keys-region entry is a different shape and belongs to a
     * different file kind.  Rejected rather than half-interpreted -- its
     * second byte is a keylen in both families, but byte 2 onward is a valptr
     * here and a vallen there. */
    if (type & ZSI_KEYENTRY) return ZS_BADFORMAT;

    bool isdelete = (type & ZSI_ISDELETE) != 0;
    bool big      = (type & ZSI_ISBIG) != 0;

    size_t hdr, keylen = 0, vallen = 0;

    /* Read the fixed header only after confirming it is present.  Every read
     * below is inside a bound already checked. */
    if (big) {
        hdr = isdelete ? ZSI_HDRLEN_BIGDELETION : ZSI_HDRLEN_BIGKEYVALUE;
        if (len < hdr) return ZS_BADFORMAT;

        uint64_t k = zsi_get64(buf + 8);
        /* On a 32-bit host a 64-bit length may not fit in size_t at all, which
         * is a bounds failure rather than something to truncate into. */
        if (k > (uint64_t)SIZE_MAX) return ZS_BADFORMAT;
        keylen = (size_t)k;

        if (!isdelete) {
            uint64_t v = zsi_get64(buf + 16);
            if (v > (uint64_t)SIZE_MAX) return ZS_BADFORMAT;
            vallen = (size_t)v;
        }
    } else {
        hdr = isdelete ? ZSI_HDRLEN_DELETION : ZSI_HDRLEN_KEYVALUE;
        if (len < hdr) return ZS_BADFORMAT;

        keylen = (size_t)(unsigned char)buf[1];
        if (!isdelete) vallen = (size_t)zsi_get16(buf + 2);
    }

    if (keylen < 1) return ZS_BADFORMAT;             /* F-14 */

    /* Note what is NOT checked here: whether the encoding is canonical (F-15).
     *
     * A big record whose lengths would have fitted the short form is
     * non-canonical, and a conforming writer never produces one -- but decoding
     * MUST still accept it.  Rejecting would be a data-loss bug, because of how
     * two rules compose: a record that fails to validate makes an unordered file
     * complete at that point (F-24), discarding everything after it, and G-3
     * forbids corruption costing *committed* data.  A peer implementation with a
     * canonicalisation bug would therefore cost us every record it wrote after
     * the first non-canonical one, silently.
     *
     * The spec puts this in check_consistency instead, which reports the
     * divergence while still reading the data (T-6).  zsi_rec_is_canonical below
     * is what that uses. */

    /* Total size, counted exactly as zsi_rec_encoded_len counts it.
     *
     * The BIG form's lengths come off disk as 64-bit values, so every term is
     * overflow-checked (G-0b): keylen + vallen + 2 is exactly the expression
     * that turns a bounds check into a bypass when it wraps.  The SHORT form's
     * cannot wrap and the guards are dead branches -- keylen is one byte and
     * vallen sixteen bits, so hdr + keylen + vallen + 6 is at most 65 800 and
     * roundup8 cannot saturate either.
     *
     * They are separate branches rather than one guarded path because a JOIN
     * POINT erases what the compiler knows: with both forms assigning `keylen`,
     * its range at the arithmetic would be the union of a byte and a 64-bit
     * load, so every check would survive and every short-form record would pay
     * them.
     *
     * The cost of the split is that the size expression is written twice, and
     * two copies can drift -- a record sized differently by the two forms puts
     * a key or value pointer into the wrong bytes. */
    size_t total;
    if (big) {
        size_t body;
        if (isdelete) {
            if (!zsi_add_sz(keylen, 1, &body)) return ZS_BADFORMAT;
        } else {
            if (!zsi_add3_sz(keylen, vallen, 2, &body)) return ZS_BADFORMAT;
        }
        if (!zsi_add_sz(hdr, body, &total)) return ZS_BADFORMAT;
        total = zsi_roundup8(total);
        if (total == 0) return ZS_BADFORMAT;         /* roundup8 saturated */
    } else {
        total = zsi_roundup8(hdr + keylen + (isdelete ? 1 : vallen + 2));
    }
    if (total > len) return ZS_BADFORMAT;

    out->type     = type;
    out->keylen   = keylen;
    out->key      = buf + hdr;
    out->len      = total;
    out->base     = buf;

    if (isdelete) {
        out->val    = NULL;
        out->vallen = 0;
    } else {
        out->val    = buf + hdr + keylen + 1;
        out->vallen = vallen;
    }

    return ZS_OK;
}

/* Bytes a terminator will occupy: 16 while the span fits in three bytes, 24
 * beyond that (F-15). */
static size_t zsi_term_encoded_len(uint64_t spanlen)
{
    return spanlen <= ZSI_SHORT_SPANLEN_MAX ? ZSI_TERMLEN_SHORT
                                            : ZSI_TERMLEN_LONG;
}

/* Encode a terminator over a span whose data bytes are spandata[0..spanlen).
 *
 * The checksum covers the span's data followed by the terminator's own bytes up
 * to the checksum field (F-19).  Because it covers both, a terminator that
 * reaches disk without its data fails validation and reads as absent: a torn
 * tail is always detectable (F-22).  Recovery depends on that, and so does
 * reading a file a writer is still appending to (C-4f) -- the checksum supplies
 * the ordering guarantee that no memory barrier can provide between independent
 * processes sharing a mapping. */
static void zsi_term_encode(char *buf, uint64_t spanlen, bool rollback,
                            const char *spandata, zs_csum *csum, unsigned csum_id)
{
    size_t len = zsi_term_encoded_len(spanlen);

    memset(buf, 0, len);

    if (len == ZSI_TERMLEN_SHORT) {
        /* +0 type, +1 span length (3 bytes), +4 pad(4), +8 checksum */
        buf[0] = (char)(rollback ? ZSI_ROLLBACK : ZSI_COMMIT);
        zsi_put24(buf + 1, (uint32_t)spanlen);
        zsi_put64(buf + 8, zsi_csum2(csum, csum_id, spandata, (size_t)spanlen,
                                     buf, ZSI_TERMLEN_SHORT - 8));
    } else {
        /* +0 type, +1 pad(7), +8 span length, +16 checksum */
        buf[0] = (char)(rollback ? ZSI_ROLLBACK_LONG : ZSI_COMMIT_LONG);
        zsi_put64(buf + 8, spanlen);
        zsi_put64(buf + 16, zsi_csum2(csum, csum_id, spandata, (size_t)spanlen,
                                      buf, ZSI_TERMLEN_LONG - 8));
    }
}

/* Decode the terminator at buf[0..len).  Does not verify the checksum -- the
 * caller has the span's data and does that (see zsi_unordered_replay).
 *
 * Terminators are only ever found by scanning forward from the header (F-20).
 * Nothing reads them backwards, and nothing in an in-order file is located from
 * the end either (F-26a), so a long terminator needs no marker in its second
 * half. */
static int zsi_term_decode(const char *buf, size_t len, struct zsi_term *out)
{
    if (len < 1) return ZS_BADFORMAT;

    uint8_t type = (uint8_t)buf[0];
    if (!zsi_type_valid(type)) return ZS_BADFORMAT;
    if (!(type & ZSI_SPANTERM)) return ZS_BADFORMAT;

    if (type & ZSI_ISBIG) {
        if (len < ZSI_TERMLEN_LONG) return ZS_BADFORMAT;
        out->spanlen = zsi_get64(buf + 8);
        out->csum    = zsi_get64(buf + 16);
        out->len     = ZSI_TERMLEN_LONG;

        /* A long terminator over a span that would have fitted the short form is
         * non-canonical (F-15) but decodes: see zsi_term_is_canonical, and the
         * note in zsi_rec_decode about why rejecting it here would discard
         * committed data. */
    } else {
        if (len < ZSI_TERMLEN_SHORT) return ZS_BADFORMAT;
        out->spanlen = zsi_get24(buf + 1);
        out->csum    = zsi_get64(buf + 8);
        out->len     = ZSI_TERMLEN_SHORT;
    }

    out->type = type;
    return ZS_OK;
}

static bool zsi_term_is_rollback(const struct zsi_term *t)
{
    return (t->type & ZSI_ISDELETE) != 0;
}

/* Whether a decoded record uses the encoding F-15 requires for its contents.
 *
 * Reads never consult this.  Rejecting non-canonical input on read would lose
 * committed data, because a record that fails to validate makes an unordered file
 * complete at that point (F-24) and G-3 forbids that costing committed data --
 * so a peer with a canonicalisation bug would silently cost us everything it
 * wrote after its first non-canonical record.
 *
 * zs_db_check_consistency consults it instead, which reports the divergence
 * while still reading the data (T-6).
 *
 * What remains checkable is narrower than it was, and that is the point of
 * F-18: a record's bytes are a function of its own key and value, so the only
 * way to be non-canonical is to have used the wrong shape for those lengths.
 * There is no longer any per-file question to ask, which is why this no longer
 * takes the containing file's start generation. */
static bool zsi_rec_is_canonical(const struct zsi_rec *r)
{
    bool isdelete = zsi_rec_is_delete(r);

    /* the shape F-15 requires for these lengths */
    if (r->type != zsi_rec_type_for(r->keylen, r->vallen, isdelete))
        return false;

    /* and the total must be the canonical rounded length */
    if (r->len != zsi_rec_encoded_len(r->keylen, r->vallen, isdelete))
        return false;

    return true;
}

/* Whether a decoded terminator uses the width F-15 requires for its span.
 * Reported, not enforced, for the same reason as records. */
static bool zsi_term_is_canonical(const struct zsi_term *t)
{
    return t->len == zsi_term_encoded_len(t->spanlen);
}

/********** FILE OBJECT *************/

/* One open, mapped data file.
 *
 * Nothing in the format depends on mmap (G-0): an implementation may read files
 * with ordinary reads and copy data out.  This one maps, because the C binding
 * promises zero-copy pointer lifetimes (A-4), but the mapping is an optimisation
 * the format permits rather than one it requires.
 *
 * Everything a reader touches through this object is immutable for its lifetime.
 * In-order files are never modified.  A non-active unordered file is never
 * appended to again.  The active file IS appended to, but only ever appended to
 * (G-1), so every byte below the snapshot boundary is stable by construction and
 * growth beyond it is simply not looked at (C-4c). */
struct zsi_file {
    char             *fname;      /* full path, owned */
    int               fd;

    /* Who is using this object.  The lifetime that matters is the MAPPING's,
     * not the snapshot's: a snapshot is just one user, and a transaction or
     * cursor holding pointers into these bytes is another (A-4a).  Tracking it
     * on the snapshot instead makes every consumer reason about the snapshot's
     * OTHER holders rather than about the bytes it is using, which is where
     * lifetime bugs come from.
     *
     * A file is shared between snapshots when it is immutable (C-4c), so a
     * rebuild reuses it rather than re-opening, re-mapping and re-indexing it. */
    int               refcount;
    const char       *base;       /* mmap, or NULL for a zero-length file */
    size_t            maplen;     /* bytes mapped; 0 when base is NULL */
    size_t            size;       /* st_size at map time */
    struct zsi_header hdr;
    zs_csum          *csum;       /* the engine this file's own header names */
    unsigned          csum_id;
    bool              hdr_valid;  /* false for the D-10 case */
    bool              needs_external_csum;  /* engine 2, no function supplied */

    /* unordered (hdr.end == 0), filled by the UNORDERED FILE section */
    size_t            complete;   /* F-24 complete point */
    struct zsi_index *index;      /* private, built by replay */

    /* The span boundary at `complete`, and the checksum the terminator ending
     * there carries (P-10).  Recorded by the replay so publishing a pointer
     * table does not need a second walk -- terminators are only ever found by
     * scanning forward (F-20), so there is no cheap way to recover them later. */
    size_t            last_term_off;
    uint64_t          last_term_csum;

    /* The valid_upto of the pointer table this file's index was seeded from, or
     * ZSI_HEADER_LEN if none was.  P-13 measures the publishing threshold from
     * here. */
    size_t            cached_upto;

    /* D-9d: spans in the REPLAY WINDOW -- the ones a reader must walk from
     * cached_upto to rebuild this index -- not spans in the file.  That is the
     * quantity a rebuild costs, and the only one obtainable without the walk
     * this exists to avoid, since a table records no span count (P-5).  Reset
     * wherever cached_upto moves, because the window moves with it. */
    size_t            nspans;

    /* in-order (hdr.end != 0), filled by the POINTER REGION section.
     *
     * Every bound is resolved once at load: the header carries keys_len and
     * values_len (F-10a) and the pointer region is self-describing, so the four
     * region boundaries are arithmetic and nothing is located from the end of
     * the file (F-26a).  nptrs is the RECORD count; the offset array holds
     * nptrs + 1 entries, the last addressing the sentinel (F-26, F-36a). */
    size_t            ptr_off;       /* always ZSI_HEADER_LEN */
    uint64_t          nptrs;
    bool              ptr_wide;      /* PTRS64: offsets are 8 bytes */
    bool              val_wide;      /* WideValptr: valptrs are 8 bytes (F-26c) */
    size_t            keys_off;
    size_t            keys_end;      /* == values_off */
    size_t            values_off;
    size_t            values_end;
    uint64_t          data_csum;     /* F-33; verified on demand only (F-33a) */
};

/* Bounds-checked access to file data (F-30).
 *
 * This is the single choke point: no other code indexes base directly.  That is
 * deliberate, and worth preserving -- it is the difference between one audited
 * check and thirty unaudited ones, and every offset reaching it is
 * corruption-controlled.  Returns NULL unless [off, off+len) lies wholly within
 * the file.
 *
 * A zero-length request is answered with a valid pointer when the offset itself
 * is in range, because an empty records region is an ordinary case (F-26g) and
 * checksumming zero bytes at a legitimate offset must not look like a failure. */
static const char *zsi_file_at(const struct zsi_file *f, size_t off, size_t len)
{
    size_t end;

    if (!zsi_add_sz(off, len, &end)) return NULL;   /* G-0b */
    if (end > f->size) return NULL;
    if (!f->base) return NULL;                      /* zero-length file */

    return f->base + off;
}

/* "I am about to read all of this file, now."
 *
 * Called only by the merge paths, immediately before the pass that hashes a whole
 * input (a conversion's D-20b replay, a repack's records-checksum verify).  On a
 * filesystem whose page cache is not the same memory as its own cache -- ZFS,
 * where a fault runs zpl_read_folio -> zfs_fillpage -> dmu_read and COPIES out of
 * the ARC -- that pass otherwise takes one synchronous fault per page, plus a page
 * allocation and a zeroing to service each one.  Measured downstream at 14% of a
 * 2M-record load's cycles, 83% of it fault servicing rather than hashing, which is
 * the largest single item in that profile.
 *
 * POSIX_MADV_WILLNEED specifically, not MADV_SEQUENTIAL, and the reason is C-4c:
 * an immutable file's mapping is SHARED between snapshots within the process, so a
 * concurrent reader may be doing point lookups through the very same VMA.
 * WILLNEED is additive -- it starts readahead and returns -- while SEQUENTIAL
 * changes the eviction policy for the whole mapping and would evict pages that
 * reader wants.  A conversion is also the wrong shape for SEQUENTIAL in its own
 * right: it copies in KEY order, which for an unordered input is not offset order.
 *
 * Advisory and non-blocking, so a failure costs nothing but the speed; the return
 * is deliberately discarded.  posix_madvise rather than madvise because it is
 * POSIX.1-2001 and needs no feature macro -- the same papercut as _GNU_SOURCE. */
static void zsi_file_prefetch(const struct zsi_file *f)
{
    if (!f || !f->base || !f->size) return;
    (void)posix_madvise((void *)(uintptr_t)f->base, f->size, POSIX_MADV_WILLNEED);
}

/* Forward declaration, and the one place this file's strict downward layering is
 * broken.  A struct zsi_file owns its private index, so closing the file must
 * free it -- but the index is defined further down, since building one needs span
 * replay which in turn needs this struct.  The alternative, making some caller
 * remember to free the index before closing the file, is a leak waiting to
 * happen: every early-return path in the snapshot protocol would need it. */
static void zsi_index_free(struct zsi_index **ip);

static void zsi_file_ref(struct zsi_file *f)
{
    f->refcount++;
}

/* Drop one user.  The mapping, the descriptor and the index go when the LAST
 * one does -- which may be a snapshot being rebuilt, a transaction ending, or
 * a cursor closing, and which of them is last is not knowable at any of those
 * sites.  That is the whole reason this is a refcount. */
static void zsi_file_release(struct zsi_file **fp)
{
    struct zsi_file *f = *fp;
    if (!f) return;
    *fp = NULL;

    if (--f->refcount > 0) return;

    zsi_index_free(&f->index);
    if (f->base) munmap((void *)f->base, f->maplen);
    if (f->fd >= 0) close(f->fd);
    free(f->fname);
    free(f);
}

/* Open and map one data file.
 *
 * name_start is the generation parsed from the filename (D-1), used when the
 * header cannot supply one.  On a header that fails to validate, or a zero-length
 * file, this succeeds with hdr_valid == false and hdr.start taken from the name:
 * D-10 requires that state be representable, because an active file in it is
 * treated as a complete file with zero spans rather than as an error.
 *
 * The CALLER decides whether that is tolerable, and the answer differs by
 * position in the file set: for the active file, yes (D-10); for any other file,
 * it is ZS_BADFORMAT, because its records cannot be recovered and silently
 * skipping the generation would lose committed data (D-10a).  This function
 * cannot make that call, since it does not know the file set. */
static int zsi_file_open(const char *dir, const char *name,
                         uint32_t name_start, zs_csum *external_csum,
                         struct zsi_file **out)
{
    struct zsi_file *f = zsi_zmalloc(sizeof(*f));
    if (!f) return ZS_INTERNAL;

    f->fd = -1;
    f->refcount = 1;            /* the caller's, so the error paths below release */

    size_t dlen = strlen(dir), nlen = strlen(name);
    f->fname = malloc(dlen + 1 + nlen + 1);
    if (!f->fname) { zsi_file_release(&f); return ZS_INTERNAL; }
    memcpy(f->fname, dir, dlen);
    f->fname[dlen] = '/';
    memcpy(f->fname + dlen + 1, name, nlen + 1);

    /* Read-only: a struct zsi_file is a reader's view.  Writers append through a
     * separate descriptor, so nothing can write through this mapping and G-6's
     * "nothing a reader may be reading is ever rewritten beneath it" is enforced
     * by the open mode rather than by convention. */
    f->fd = open(f->fname, O_RDONLY);
    if (f->fd < 0) {
        int r = (errno == ENOENT) ? ZS_NOTFOUND : ZS_IOERROR;
        zsi_file_release(&f);
        return r;
    }

    struct stat sb;
    if (fstat(f->fd, &sb) < 0) { zsi_file_release(&f); return ZS_IOERROR; }
    if (!S_ISREG(sb.st_mode)) { zsi_file_release(&f); return ZS_BADFORMAT; }
    f->size = (size_t)sb.st_size;

    /* A zero-length file cannot be mapped, and must not be an error: D-10 makes
     * it a legal state for the active file.  base stays NULL and zsi_file_at
     * refuses every request, which is the correct behaviour for a file with no
     * content rather than a special case anyone has to remember. */
    if (f->size > 0) {
        void *m = mmap(NULL, f->size, PROT_READ, MAP_SHARED, f->fd, 0);
        if (m == MAP_FAILED) { zsi_file_release(&f); return ZS_IOERROR; }
        f->base = (const char *)m;
        f->maplen = f->size;
    }

    /* Default the generation from the filename before attempting the header, so
     * the D-10 path has it regardless of what the header turns out to hold. */
    f->hdr.start = name_start;
    f->hdr.end = 0;

    if (f->size >= ZSI_HEADER_LEN) {
        /* The engine id comes out of the flags field as plain data first (F-5a):
         * the checksum cannot be verified until the engine is known, and the
         * engine is recorded inside the header the checksum protects. */
        unsigned id = zsi_header_engine_id(f->base);
        zs_csum *cs = zsi_csum_for_id(id, external_csum);

        /* Engine 2 with no function supplied is a CONFIGURATION error, not
         * corruption, and the two must not be conflated: D-10 tolerates a corrupt
         * active file, so without this distinction an unverifiable single-file
         * database would open as empty instead of reporting A-6. */
        if (id == ZSI_CSUM_EXTERNAL && !external_csum)
            f->needs_external_csum = true;

        /* An unknown engine, or engine 2 with no function supplied, leaves the
         * header unverifiable.  Treat it as an invalid header rather than
         * guessing: the caller's position test (D-10 vs D-10a) then decides,
         * and for a non-active file that is the error A-6 wants. */
        if (cs && zsi_header_decode(f->base, f->size, cs, &f->hdr) == ZS_OK) {
            f->hdr_valid = true;
            f->csum = cs;
            f->csum_id = id;
        }
    }

    if (!f->hdr_valid) {
        /* Restore the name-derived generation: zsi_header_decode may have written
         * fields before failing, and a partially-filled header must not be
         * mistaken for a real one. */
        memset(&f->hdr, 0, sizeof(f->hdr));
        f->hdr.start = name_start;
        f->hdr.end = 0;
        f->csum = zsi_csum_none;
        f->csum_id = ZSI_CSUM_NONE;
    }

    *out = f;
    return ZS_OK;
}

/* Re-stat after appending, so bytes written through a separate descriptor
 * become visible through this object -- re-mapping only when it has to.
 *
 * Needed because a writer maintains the active file's index incrementally
 * (D-13b) and the index holds offsets that must be readable.  Only ever called
 * on a file nobody else is reading -- see the refcount guard at the call site --
 * because replacing a mapping under a live reader is exactly what G-6 forbids.
 *
 * `maplen` is deliberately allowed to EXCEED `size`.  A mapping that already
 * covers the file's new end needs no syscall at all: the page cache is shared
 * with the writing descriptor, so an append becomes visible through a mapping
 * made before it.  So the active file is mapped once with headroom and then
 * grows underneath the map for the rest of its life, instead of being unmapped
 * and remapped on every commit.
 *
 * That matters because a sole writer takes this branch at every commit (the
 * refcount is 1 whenever no one is reading).  Remapping instead would cost an
 * munmap plus an mmap each time, and since the active file grows toward
 * rollover_size, each one tears down and refaults progressively more pages --
 * enough for the kernel's mapping machinery to dominate a write profile.
 *
 * Reading past EOF in an over-sized mapping is SIGBUS, which is exactly why
 * this is safe HERE and would not be everywhere: zsi_file_at is the single
 * bounds-checked accessor and it bounds every access by `size`, never by
 * `maplen`.  Nothing else indexes `base`.  And files are append-only, so the
 * bound only ever moves up.
 *
 * `mapahead` is a hint, not a commitment: a failed over-sized mmap falls back
 * to an exact one, and a platform that would not show the growth is caught by
 * test_file_grows_under_an_oversized_map rather than by a wrong answer. */
static int zsi_file_remap(struct zsi_file *f, size_t mapahead)
{
    struct stat sb;

    if (fstat(f->fd, &sb) < 0) return ZS_IOERROR;
    if ((size_t)sb.st_size == f->size) return ZS_OK;

    /* The common case once the headroom is in place: the file grew into space
     * the mapping already covers, so only the bound moves. */
    if (f->base && (size_t)sb.st_size <= f->maplen) {
        f->size = (size_t)sb.st_size;
        return ZS_OK;
    }

    if (f->base) { munmap((void *)f->base, f->maplen); f->base = NULL; f->maplen = 0; }
    f->size = (size_t)sb.st_size;

    if (f->size) {
        size_t want = mapahead > f->size ? mapahead : f->size;
        void *m = mmap(NULL, want, PROT_READ, MAP_SHARED, f->fd, 0);
        if (m == MAP_FAILED) {
            /* Headroom is optional; the file itself is not. */
            want = f->size;
            m = mmap(NULL, want, PROT_READ, MAP_SHARED, f->fd, 0);
            if (m == MAP_FAILED) { f->size = 0; return ZS_IOERROR; }
        }
        f->base = (const char *)m;
        f->maplen = want;
    }

    return ZS_OK;
}

/* Which kind of file this is, from the header alone.
 *
 * The two kinds are exhaustive and distinguishable before reading anything else,
 * so a reader always knows whether a pointer section must be present (section 2).
 * An invalid header reads as unordered, which is what D-10 needs: an active file
 * with a corrupt header is a complete file with zero spans, and spans only exist
 * in unordered files. */
static bool zsi_file_is_unordered(const struct zsi_file *f)
{
    return !f->hdr_valid || zsi_header_is_unordered(&f->hdr);
}

/********** UNORDERED FILE *************/

/* From the end of an unordered file's header onwards, the file is a flat sequence
 * of spans (F-23).  Each span is zero or more data records followed by exactly
 * one terminator whose span length equals the span's data byte count and whose
 * checksum validates.  Every byte belongs to exactly one span or terminator: no
 * gaps, no nesting.
 *
 * Spans exist only in unordered files; an in-order file has none (section 4.9). */

/* Invoked for each committed record, in file order.  Records in rolled-back spans
 * are never presented (F-25).  Returning non-zero stops the replay. */
typedef int zsi_replay_cb(void *rock, const struct zsi_rec *rec, size_t off);

/* Walk the span chain, setting f->complete to the offset after the last valid
 * span (F-24) -- which may be short of f->size, and is the header length for a
 * file with no valid spans at all.
 *
 * A torn tail is not an error.  It is the ordinary outcome of a crash, and of
 * reading a file a writer is still appending to, so this returns ZS_OK and lets
 * f->complete carry the answer.  Content beyond the complete point is simply not
 * part of the database.
 *
 * The span checksum is verified in EVERY mode -- verification rides indexing
 * (F-5e), and this replay is where spans are indexed.  ZS_NOCSUM does not
 * reach it: skipping here would accept, on the strength of its length field
 * alone, a terminator whose data never landed.  Nothing orders data before
 * terminator on the DISK in any mode since C-7 went to a single gate, so that
 * is the state a crash really leaves -- under relaxed durability (C-7c) and,
 * inside the commit window, under the default too.  F-22 and C-4f hold for
 * every reader, and this is where they are enforced.
 *
 * Two passes per span, deliberately.  Pass one finds the terminator and validates
 * the whole span; pass two replays its records.  Records are therefore decoded
 * twice.  The alternative is buffering an unbounded span's records in memory, and
 * the second decode costs nothing measurable because the span is already in page
 * cache from the first. */
static int zsi_unordered_replay(struct zsi_file *f, size_t from,
                                zsi_replay_cb *cb, void *rock)
{
    /* D-10: an active file with a corrupt header or zero length is treated as a
     * complete file with zero spans.  Nothing in it is part of the database, so
     * the complete point is 0 -- which also makes it not clean (D-9), so a writer
     * moves to a new file rather than building a chain on an untrustworthy
     * boundary (R-4). */
    if (!f->hdr_valid) {
        f->complete = 0;
        return ZS_OK;
    }

    /* An in-order file has no spans.  Calling this on one is a programming error
     * rather than a data condition, so it reports nothing rather than inventing
     * an answer. */
    if (!zsi_header_is_unordered(&f->hdr)) {
        f->complete = 0;
        return ZS_BADUSAGE;
    }

    /* P-12: a span is self-delimiting and self-validating, so a walk may begin
     * at ANY span boundary.  A caller seeding an index from a pointer table
     * passes that table's valid_upto; everyone else passes ZSI_HEADER_LEN.
     *
     * An out-of-range or non-boundary value is not trusted and is not an error:
     * the walk simply finds no valid span there and reports the file complete at
     * that point, which is F-24's ordinary outcome rather than a special case.
     * That is what makes it safe to hand this a value read out of a file. */
    size_t pos = from < ZSI_HEADER_LEN ? ZSI_HEADER_LEN : from;
    if (pos > f->size) pos = ZSI_HEADER_LEN;

    f->complete = pos;

    /* D-9d: `pos` is the window's base, so the count starts here.  This is the
     * one place the window is established -- the other assignments to
     * cached_upto are each followed immediately by a call to this walk, which
     * recomputes the count from scratch. */
    f->nspans = 0;

    /* Recorded so a publisher has the boundary's terminator without a second
     * walk (P-10).  A caller seeding from a table overwrites these when the
     * walk finds nothing new -- see zsi_index_build_cached. */
    f->last_term_off  = pos;
    f->last_term_csum = 0;

    for (;;) {
        size_t span_start = pos;
        size_t p = pos;
        struct zsi_term term;
        bool found_term = false;

        /* Pass one: walk records until a terminator, validating as we go. */
        for (;;) {
            const char *b = zsi_file_at(f, p, 1);
            if (!b) break;                      /* ran off the end */

            uint8_t type = (uint8_t)b[0];
            if (!zsi_type_valid(type)) break;

            size_t avail = f->size - p;

            if (type & ZSI_SPANTERM) {
                if (zsi_term_decode(b, avail, &term) != ZS_OK) break;
                if (!zsi_file_at(f, p, term.len)) break;
                found_term = true;
                break;
            }

            /* A pointer section cannot appear in an unordered file (section 4.9),
             * and a valid type byte that is neither a data record nor a
             * terminator can only be one.  Ends the file here. */
            if (!(type & ZSI_HASKEY)) break;

            struct zsi_rec r;
            if (zsi_rec_decode(b, avail, &r) != ZS_OK) break;

            /* F-29's progress rule: the next offset comes from this record's own
             * length fields, and must be strictly greater and within bounds.
             * Non-termination is impossible by construction, which T-3's per-case
             * timeout is the detector for.
             *
             * These four checks are DELIBERATELY REDUNDANT, not dead code.
             * zsi_rec_decode already guarantees every one of them -- it rejects a
             * saturated roundup8, so out->len is never 0, and it rejects a total
             * exceeding the length it was given, so p + len never passes f->size.
             * Mutation testing confirms removing them changes nothing observable.
             *
             * They stay for two reasons.  F-29 requires the verification at the
             * iteration site rather than somewhere it happens to be implied.  And
             * they become load-bearing the moment the decoder's contract changes,
             * which is precisely the change nobody would think to audit this walk
             * for. */
            size_t next;
            if (r.len == 0) break;
            if (!zsi_add_sz(p, r.len, &next)) break;
            if (next <= p) break;
            if (next > f->size) break;

            p = next;
        }

        if (!found_term) break;                 /* complete at span_start */

        /* The span's data byte count is exactly the distance walked, so there is
         * nothing to accumulate and nothing to overflow. */
        size_t datalen = p - span_start;
        if (term.spanlen != (uint64_t)datalen) break;

        const char *spandata = zsi_file_at(f, span_start, datalen);
        const char *termbytes = zsi_file_at(f, p, term.len);
        if (!termbytes) break;
        if (datalen && !spandata) break;

        /* F-19: the checksum covers the span's data followed by the terminator's
         * own bytes up to the checksum field.  Because it covers BOTH, a
         * terminator that reached disk without its data fails here and the span
         * reads as absent.
         *
         * This is the load-bearing check of the whole concurrency design.  It is
         * what makes a torn tail always detectable (F-22), and it supplies the
         * ordering guarantee that no memory barrier can provide between
         * independent processes sharing a mapping -- which is what permits reading
         * a live file with no lock at all (C-4f).  It looks like an ordinary
         * checksum check and is not. */
        {
            uint64_t want = zsi_csum2(f->csum, f->csum_id,
                                      spandata ? spandata : "", datalen,
                                      termbytes, term.len - 8);
            if (want != term.csum) break;
        }

        size_t after;
        if (!zsi_add_sz(p, term.len, &after)) break;
        if (after > f->size) break;

        /* Pass two: replay, unless the span was rolled back.
         *
         * F-21: a ROLLBACK is a commit that says "ignore the records in this
         * span".  F-25: visibility is per span, not a watermark -- a rolled-back
         * span may sit between two live ones, so this must skip exactly this span
         * and carry on rather than stopping or lowering a high-water mark. */
        if (cb && !zsi_term_is_rollback(&term)) {
            size_t q = span_start;
            while (q < p) {
                const char *rb = zsi_file_at(f, q, 1);
                struct zsi_rec r;
                if (!rb) break;
                if (zsi_rec_decode(rb, f->size - q, &r) != ZS_OK)
                    break;
                if (r.len == 0) break;
                if (cb(rock, &r, q) != 0) return ZS_OK;   /* caller stopped */
                q += r.len;
            }
        }

        f->complete = after;
        f->nspans++;                            /* D-9d */
        f->last_term_off  = p;
        f->last_term_csum = term.csum;
        pos = after;
    }

    return ZS_OK;
}

/* Whether the active file may be appended to (D-9).
 *
 * "An active file is clean if it has a VALID HEADER and zero or more valid spans
 * with nothing after the last."  Both halves matter: a zero-length file has
 * complete == size == 0 and would otherwise look clean, but D-10 requires a writer
 * move to a new file rather than append to it -- so no chain is ever built on a
 * boundary that failed to validate (R-4). */
static bool zsi_unordered_is_clean(const struct zsi_file *f)
{
    return f->hdr_valid && f->complete == f->size;
}

/********** POINTER SECTION *************/

/* An in-order file is four regions and a trailer; an unordered file is a header
 * and a span chain (section 4.9).  So:
 *
 *     in-order   [header][pointer region][keys region][values region][trailer]
 *     unordered  [header](span)*
 *
 * An in-order file has no spans and no terminators.  Everything in it is live by
 * construction, and it is written whole under a temporary name and renamed only
 * once finished (D-21), so a commit record would assert nothing that is not
 * already guaranteed.
 *
 * EVERYTHING IS LOCATED FROM THE FRONT.  The header knows keys_len and
 * values_len (F-10a) and the pointer region begins immediately after it, so
 * there is no back pointer and the trailer holds nothing but checksums (F-26a).
 * Format 2 needed one because a writer streaming records could not know the
 * section's size until the last was written; a format-3 writer computes every
 * length before it emits a byte (D-20c).
 *
 *     PTRS32 (0x20)                        narrow
 *       +0    1        type
 *       +1    3        pad
 *       +4    4        count (uint32)
 *       +8    4x(N+1)  key-entry offsets (uint32)
 *             .        pad with zeroes to a multiple of 8
 *
 *     PTRS64 (0x24)                        wide
 *       +0    1        type
 *       +1    7        pad
 *       +8    8        count (uint64)
 *       +16   8x(N+1)  key-entry offsets (uint64)
 *
 * N+1 offsets for N records: the last addresses the SENTINEL entry, which is
 * what makes F-36's value-length derivation need no special case for the last
 * record (F-36a).  `count` is the record count, so a search ranges over
 * [0, count) and the extra offset is reached only by that derivation.
 *
 * The trailer is a FIXED 16 bytes at the end:
 *
 *     filesize-16   8   checksum of the keys and values regions together (F-33)
 *     filesize-8    8   checksum of the pointer region (F-34)
 */

#define ZSI_TRAILER_LEN 16

/* 96 header + 16 PTRS32 region holding one sentinel offset + 8 sentinel entry
 * + 16 trailer.  A file shorter than this cannot be a valid in-order file
 * (F-26g). */
#define ZSI_INORDER_MIN (ZSI_HEADER_LEN + 16 + 8 + ZSI_TRAILER_LEN)

/* Bytes a pointer section occupies, including F-26d's padding.  Returns 0 if the
 * count cannot be represented. */
static size_t zsi_ptrs_section_len(uint64_t count, bool wide)
{
    size_t hdr = wide ? 16 : 8;
    size_t per = wide ? 8 : 4;
    size_t body, total;

    if (count > SIZE_MAX / per) return 0;
    body = (size_t)count * per;
    if (!zsi_add_sz(hdr, body, &total)) return 0;

    /* The narrow section is padded with zeroes to a multiple of 8 so the trailer
     * begins 8-aligned (F-2).  The pad is 0 or 4 bytes and the checksum covers
     * it.  The wide section is always a multiple of 8 already. */
    return zsi_roundup8(total);
}

/* The key-entry offset at index i.  i must be <= f->nptrs -- the array holds
 * one more offset than there are records, for the sentinel (F-36a) -- and the
 * caller has already bounds-checked the array as a whole in zsi_ptrs_load.
 *
 * `inline` is load-bearing rather than decorative -- see zsi_cur_order. */
static inline uint64_t zsi_ptrs_at(const struct zsi_file *f, uint64_t i)
{
    size_t hdr = f->ptr_wide ? 16 : 8;
    size_t per = f->ptr_wide ? 8 : 4;
    const char *p = f->base + f->ptr_off + hdr + (size_t)i * per;

    return f->ptr_wide ? zsi_get64(p) : (uint64_t)zsi_get32(p);
}

/* A decoded key entry (section 4.5a).  Separate from struct zsi_rec because it
 * is only half a record: the value lives in another region and its length comes
 * from the NEXT entry (F-36), so an entry alone cannot describe one. */
struct zsi_kent {
    uint8_t     type;
    const char *key;    size_t keylen;   /* keylen 0 == the sentinel */
    uint64_t    valptr;
    size_t      len;                     /* on-disk bytes, multiple of 8 */
};

/* Bytes a key entry occupies, or 0 if it cannot be encoded.  `wide` is the
 * file's WideValptr (F-26c); the big form is chosen by key length alone. */
static size_t zsi_kent_encoded_len(size_t keylen, bool wide)
{
    size_t hdr = (keylen > ZSI_SHORT_KEYLEN_MAX ? ZSI_HDRLEN_BIGKEY
                                                : ZSI_HDRLEN_KEY)
               + (wide ? 8u : 4u);
    size_t total;

    /* +1 for the trailing NUL F-13 keeps: the stored length excludes it, and it
     * is what makes a key usable in place as a C string. */
    if (!zsi_add_sz(hdr, keylen + 1, &total)) return 0;
    return zsi_roundup8(total);
}

/* Encode one key entry.  keylen 0 encodes the sentinel, whose valptr is one past
 * the values region and which carries no key (F-36a) -- the only place a zero
 * key length is legal (F-14). */
static void zsi_kent_encode(char *buf, const char *key, size_t keylen,
                            bool isdelete, uint64_t valptr, bool wide)
{
    bool big = keylen > ZSI_SHORT_KEYLEN_MAX;
    size_t total = zsi_kent_encoded_len(keylen, wide);
    size_t hdr;

    memset(buf, 0, total);
    buf[0] = (char)(big ? (isdelete ? ZSI_BIGKEYDELETE : ZSI_BIGKEY)
                        : (isdelete ? ZSI_KEYDELETE    : ZSI_KEY));

    if (big) {
        /* +0 type, +1 pad(7), +8 keylen, +16 valptr */
        zsi_put64(buf + 8, (uint64_t)keylen);
        hdr = ZSI_HDRLEN_BIGKEY;
    } else {
        /* +0 type, +1 keylen, +2 valptr -- PACKED, F-2a's one exception */
        buf[1] = (char)(unsigned char)keylen;
        hdr = ZSI_HDRLEN_KEY;
    }

    if (wide) zsi_put64(buf + hdr, valptr);
    else      zsi_put32(buf + hdr, (uint32_t)valptr);

    if (keylen) memcpy(buf + hdr + (wide ? 8 : 4), key, keylen);
    /* the NUL and the padding are already zero from the memset */
}

/* Decode the key entry at buf[0..len).  Structure only: there is no checksum to
 * verify at this granularity (F-33 covers the whole region). */
static inline int zsi_kent_decode(const char *buf, size_t len, bool wide,
                                  struct zsi_kent *out)
{
    if (len < 1) return ZS_BADFORMAT;

    uint8_t type = (uint8_t)buf[0];
    if (!zsi_type_valid(type)) return ZS_BADFORMAT;
    /* F-12d: a data record is a different shape belonging to a different file
     * kind, and its byte 2 is a vallen where this one's is a valptr. */
    if (!(type & ZSI_KEYENTRY)) return ZS_BADFORMAT;

    size_t w = wide ? 8u : 4u;
    size_t hdr, keylen;

    if (type & ZSI_ISBIG) {
        hdr = ZSI_HDRLEN_BIGKEY + w;
        if (len < hdr) return ZS_BADFORMAT;
        uint64_t k = zsi_get64(buf + 8);
        if (k > (uint64_t)SIZE_MAX) return ZS_BADFORMAT;
        keylen = (size_t)k;
        out->valptr = wide ? zsi_get64(buf + ZSI_HDRLEN_BIGKEY)
                           : (uint64_t)zsi_get32(buf + ZSI_HDRLEN_BIGKEY);
    } else {
        hdr = ZSI_HDRLEN_KEY + w;
        if (len < hdr) return ZS_BADFORMAT;
        keylen = (size_t)(unsigned char)buf[1];
        out->valptr = wide ? zsi_get64(buf + ZSI_HDRLEN_KEY)
                           : (uint64_t)zsi_get32(buf + ZSI_HDRLEN_KEY);
    }

    size_t total;
    if (!zsi_add_sz(hdr, keylen + 1, &total)) return ZS_BADFORMAT;
    total = zsi_roundup8(total);
    if (total == 0 || total > len) return ZS_BADFORMAT;

    out->type   = type;
    out->keylen = keylen;
    out->key    = keylen ? buf + hdr : NULL;
    out->len    = total;
    return ZS_OK;
}

/* The valptr of entry i alone, without materialising the rest.  i may be
 * f->nptrs, which is the sentinel.  Returns UINT64_MAX on a decode failure,
 * which every caller treats as corruption -- it cannot be a real valptr,
 * because F-31a bounds the values region by the file size. */
static inline uint64_t zsi_kent_valptr_at(const struct zsi_file *f, uint64_t i)
{
    uint64_t off = zsi_ptrs_at(f, i);
    const char *b;
    struct zsi_kent e;

    if (off < f->keys_off || off >= f->keys_end) return UINT64_MAX;
    b = zsi_file_at(f, (size_t)off, 1);
    if (!b) return UINT64_MAX;
    if (zsi_kent_decode(b, f->keys_end - (size_t)off, f->val_wide, &e) != ZS_OK)
        return UINT64_MAX;

    return e.valptr;
}

/* Read the trailer and pointer region and resolve every region boundary.
 *
 * O(1) in the data (F-31): validate the header, read the 16-byte trailer, verify
 * the pointer region's checksum, use the pointers.  Neither the keys region nor
 * the values region is touched here -- the data checksum is verified only on
 * demand (F-33a), because opening must not be proportional to the file's size.
 *
 * Order matters, and two things make it safe:
 *
 *   - the pointer region begins immediately after the header, at a fixed
 *     offset, so nothing needs finding before it can be read (F-26a);
 *   - its count is read as PLAIN DATA before the checksum can be verified,
 *     because the checksum covers the region and the region's length is a
 *     function of the count.  That is not a circularity: a wrong count yields a
 *     bounds failure or a failed checksum, never a wrong interpretation, which
 *     is the same argument format 2 made for its back pointer.
 */
static int zsi_ptrs_load(struct zsi_file *f)
{
    if (!f->hdr_valid) return ZS_BADFORMAT;
    if (zsi_header_is_unordered(&f->hdr)) return ZS_BADUSAGE;
    if (f->size < ZSI_INORDER_MIN) return ZS_BADFORMAT;

    const char *tr = zsi_file_at(f, f->size - ZSI_TRAILER_LEN, ZSI_TRAILER_LEN);
    if (!tr) return ZS_BADFORMAT;

    uint64_t data_csum = zsi_get64(tr);
    uint64_t ptr_csum  = zsi_get64(tr + 8);

    size_t ptr_off = ZSI_HEADER_LEN;
    const char *sec = zsi_file_at(f, ptr_off, 8);
    if (!sec) return ZS_BADFORMAT;

    uint8_t type = (uint8_t)sec[0];
    bool wide;
    if (type == ZSI_PTRS32)      wide = false;
    else if (type == ZSI_PTRS64) wide = true;
    else                         return ZS_BADFORMAT;

    uint64_t count;
    if (wide) {
        const char *c = zsi_file_at(f, ptr_off, 16);
        if (!c) return ZS_BADFORMAT;
        count = zsi_get64(c + 8);
    } else {
        count = (uint64_t)zsi_get32(sec + 4);
    }

    /* N+1 offsets for N records (F-26) -- the sentinel's is always present, so
     * this cannot overflow to zero for a legitimate count. */
    if (count == UINT64_MAX) return ZS_BADFORMAT;
    size_t seclen = zsi_ptrs_section_len(count + 1, wide);
    if (seclen == 0) return ZS_BADFORMAT;

    size_t keys_off, keys_end, values_end;
    if (!zsi_add_sz(ptr_off, seclen, &keys_off)) return ZS_BADFORMAT;
    if (f->hdr.keys_len > (uint64_t)SIZE_MAX) return ZS_BADFORMAT;
    if (f->hdr.values_len > (uint64_t)SIZE_MAX) return ZS_BADFORMAT;
    if (!zsi_add_sz(keys_off, (size_t)f->hdr.keys_len, &keys_end))
        return ZS_BADFORMAT;
    if (!zsi_add_sz(keys_end, (size_t)f->hdr.values_len, &values_end))
        return ZS_BADFORMAT;

    /* F-31a: the shape has to add up exactly.  An equality rather than a bound,
     * because anything else means the header and the file size disagree, which
     * no conforming writer produces -- and it costs nothing, so a truncated or
     * overlong file is rejected before any region is read. */
    size_t want;
    if (!zsi_add_sz(values_end, ZSI_TRAILER_LEN, &want)) return ZS_BADFORMAT;
    if (want != f->size) return ZS_BADFORMAT;

    /* F-34, and before the count is used for anything but its own bounds. */
    const char *cbase = zsi_file_at(f, ptr_off, seclen);
    if (!cbase) return ZS_BADFORMAT;
    if (f->csum(cbase, seclen) != ptr_csum) return ZS_BADCHECKSUM;

    f->ptr_off    = ptr_off;
    f->nptrs      = count;
    f->ptr_wide   = wide;
    f->val_wide   = (f->hdr.flags & ZSI_HDR_FLAG_WIDEVAL) != 0;
    f->keys_off   = keys_off;
    f->keys_end   = keys_end;
    f->values_off = keys_end;
    f->values_end = values_end;
    f->data_csum  = data_csum;

    /* F-27: every offset 8-aligned and inside the keys region.  The loop runs
     * count+1 times, since the sentinel's offset is as load-bearing as any
     * other -- F-36 dereferences it for the last record's value length. */
    for (uint64_t i = 0; i <= count; i++) {
        uint64_t off = zsi_ptrs_at(f, i);
        if (off < keys_off || off >= keys_end) return ZS_BADFORMAT;
        if (off % 8 != 0) return ZS_BADFORMAT;
    }

    return ZS_OK;
}

/* Verify the data checksum: the keys and values regions as one run (F-33).
 *
 * Called on demand only -- by zs_db_check_consistency, by a merge reading this
 * file as an input (D-20b), and by salvage (S-13) -- NEVER on open, which stays
 * O(1) (F-33a), and never on a read path (F-5e).  It is the only thing that
 * detects a key entry or a value corrupted in place: an in-order file has no
 * span terminators to notice it, so without this the corruption is invisible,
 * and between calls it is served to callers.
 *
 * The two regions are checksummed together because they are adjacent and nothing
 * ever reads one without the other being part of the same integrity question. */
static int zsi_ptrs_verify_records(struct zsi_file *f)
{
    size_t len = f->values_end - f->keys_off;
    const char *p = zsi_file_at(f, f->keys_off, len);

    if (!p && len) return ZS_BADFORMAT;

    /* A zero-record file still has its sentinel entry here, so len is never 0 in
     * practice -- but the engine's value for empty input is what would be
     * required if it were (F-26g), so "" rather than NULL keeps that path
     * identical to any other zero-length checksum. */
    if (f->csum(p ? p : "", len) != f->data_csum) return ZS_BADCHECKSUM;

    return ZS_OK;
}

/* Materialise record i of an in-order file: its key entry, plus the extent of
 * its value in the values region.
 *
 * The rest of the library works in terms of struct zsi_rec, and deliberately
 * still does -- the merge, the read path, the writers and the consistency check
 * are all indifferent to whether a record came from a span or from two regions.
 * The join happens here and nowhere else.
 *
 * F-36: the length is the NEXT entry's valptr minus this one's, minus the
 * trailing NUL.  Reading the successor is what the sentinel exists to make
 * unconditional (F-36a), and it costs nothing in the case that matters -- a
 * forward scan has the next entry in cache already, and a lookup's successor is
 * adjacent to the entry the search just compared.
 *
 * A deletion never asks: it has no value, its valptr equals its successor's, and
 * the subtraction would underflow.  The type byte decides, never the pointer
 * (F-35).
 *
 * `inline` per zsi_cur_order. */
static inline int zsi_ptrs_rec(struct zsi_file *f, uint64_t i,
                               struct zsi_rec *out)
{
    struct zsi_kent e;
    uint64_t off, next;
    const char *b;

    if (i >= f->nptrs) return ZS_BADFORMAT;

    off = zsi_ptrs_at(f, i);
    if (off < f->keys_off || off >= f->keys_end) return ZS_BADFORMAT;
    b = zsi_file_at(f, (size_t)off, 1);
    if (!b) return ZS_BADFORMAT;
    if (zsi_kent_decode(b, f->keys_end - (size_t)off, f->val_wide, &e) != ZS_OK)
        return ZS_BADFORMAT;

    /* keylen 0 is the sentinel, which is not a record (F-36a).  It sits at index
     * nptrs, so reaching it here means the array or the count is wrong. */
    if (e.keylen < 1) return ZS_BADFORMAT;

    out->type   = e.type;
    out->key    = e.key;
    out->keylen = e.keylen;
    out->len    = e.len;
    out->base   = b;

    if (e.type & ZSI_ISDELETE) {
        out->val    = NULL;
        out->vallen = 0;
        return ZS_OK;
    }

    next = zsi_kent_valptr_at(f, i + 1);
    if (next == UINT64_MAX) return ZS_BADFORMAT;
    if (next < e.valptr + 1) return ZS_BADFORMAT;     /* not monotonic (F-28) */

    out->vallen = (size_t)(next - e.valptr - 1);
    out->val    = zsi_file_at(f, (size_t)e.valptr, out->vallen + 1);
    if (!out->val) return ZS_BADFORMAT;

    return ZS_OK;
}

/* An implementation MAY probe the first and last pointers before the rest, which
 * rejects an out-of-range key in two comparisons rather than the log2(n) a plain
 * binary search takes to walk to an end (D-14d).
 *
 * This is a search STRATEGY, not a way of avoiding the search: those two pointers
 * still have to be dereferenced and their keys compared, so it is the same kind
 * of work, just less of it.  It needs no cached metadata and cannot change the
 * answer -- which T-5a checks by running the same assertions with it compiled
 * out. */
#ifndef ZSI_PROBE_ENDS
#define ZSI_PROBE_ENDS 1
#endif

/* Binary search for key.  Sets *idx to the first index whose key is >= key, and
 * *exact to whether it matches.
 *
 * With nptrs == 0 this sets *idx = 0 and *exact = false: an ordinary case, not a
 * special one (F-26g, D-14b).  Because a repack emits exactly one record per key
 * (D-17), keys in an in-order file are unique and the array is a strict ordering,
 * so a plain lower bound is correct. */
static int zsi_ptrs_search(struct zsi_file *f, zs_compar *compar,
                           const char *key, size_t keylen,
                           uint64_t *idx, bool *exact)
{
    struct zsi_rec r;

    *idx = 0;
    *exact = false;
    if (f->nptrs == 0) return ZS_OK;

#if ZSI_PROBE_ENDS
    {
        if (zsi_ptrs_rec(f, 0, &r) != ZS_OK) return ZS_BADFORMAT;
        int c = zsi_cmp(compar, key, keylen, r.key, r.keylen);
        if (c <= 0) {
            *idx = 0;
            *exact = (c == 0);
            return ZS_OK;
        }

        if (zsi_ptrs_rec(f, f->nptrs - 1, &r) != ZS_OK) return ZS_BADFORMAT;
        c = zsi_cmp(compar, key, keylen, r.key, r.keylen);
        if (c > 0) {
            *idx = f->nptrs;            /* past every key */
            return ZS_OK;
        }
        if (c == 0) {
            *idx = f->nptrs - 1;
            *exact = true;
            return ZS_OK;
        }
    }
#endif

    uint64_t lo = 0, hi = f->nptrs;
    while (lo < hi) {
        uint64_t mid = lo + (hi - lo) / 2;
        if (zsi_ptrs_rec(f, mid, &r) != ZS_OK) return ZS_BADFORMAT;
        if (zsi_cmp(compar, r.key, r.keylen, key, keylen) < 0) lo = mid + 1;
        else hi = mid;
    }

    *idx = lo;
    if (lo < f->nptrs) {
        if (zsi_ptrs_rec(f, lo, &r) != ZS_OK) return ZS_BADFORMAT;
        *exact = (zsi_cmp(compar, r.key, r.keylen, key, keylen) == 0);
    }

    return ZS_OK;
}

/* Lay out an in-order file's body, holding a REFERENCE per record and no bytes.
 *
 * Both writers -- conversion and repack -- feed records in key order and this
 * builds [pointer region][keys][values][trailer].  It exists once so D-17 to
 * D-23's retention rules and this layout meet in a single place, exactly as
 * zsi_repack_run is the single merge entry point.
 *
 * D-20c requires every section's length to be known before the first byte is
 * written, because the header carries them and the pointer region precedes the
 * data.  Two things are therefore relative until the end, both depending on the
 * pointer region's size and so on a record count not known until the last record
 * has been offered:
 *
 *   - an entry's valptr is an offset into the values region;
 *   - an entry's own offset is an offset into the keys region.
 *
 * MEMORY IS O(RECORDS), NOT O(BYTES), and that is the shape of the whole file.
 * Every input is already mapped -- a repack's by the snapshot, a conversion's by
 * the writer -- so a record's key and value bytes are addressable where they
 * were written, and a 32-byte descriptor pointing at them is enough.  Nothing is
 * copied until the emit, which walks the descriptors and copies each region
 * straight from the inputs' mappings.  The DESTINATION offsets are not stored:
 * the emit walks in the same order the records arrived, so an entry's offset in
 * the keys region and its value's offset in the values region are running sums,
 * exact and free.
 *
 * The buffered shape this replaces was O(output), which for a compaction (D-26)
 * is O(database) -- so a caller could not compact a database larger than memory,
 * and nothing in the API said why.  Measured on the largest merge of a
 * 2M-record load, 1.728M records and a 212.5MB body: 55MB against 277MB.
 *
 * What it costs is the ONE-SHOT checksum.  F-33 covers the keys and values
 * regions as one run and they are no longer one run in memory, so the digest is
 * accumulated as the bytes pass by -- XXH3 streams at about 21 GB/s here against
 * 54 GB/s one-shot, which is ~6ms per 200MB of output.  A caller-supplied engine
 * (F-5d) cannot stream at all, so for ZS_CSUM_EXTERNAL the region IS held and
 * checksummed in one call; that is the same code path as emitting into memory
 * for a test (fd < 0), which is what keeps it from becoming a second
 * implementation of the layout.
 */
struct zsi_inorder_ent {
    const char *key;
    const char *val;             /* NULL is a deletion: no value bytes (F-37) */
    size_t      keylen, vallen;
};

struct zsi_inorder_out {
    struct zsi_inorder_ent *ents;
    size_t                  nents, ents_alloc;
    size_t                  vlen;        /* the values region's length so far */
    /* The keys region's length in each width, maintained per record so the fixed
     * point below is O(1) an iteration rather than a pass over every descriptor.
     * The sentinel is in neither sum: it is added at layout time, where the
     * width is settled. */
    size_t                  klen_narrow, klen_wide;
    bool                    failed;
};

static void zsi_inorder_out_fini(struct zsi_inorder_out *w)
{
    free(w->ents);
    memset(w, 0, sizeof(*w));
}

/* Size the descriptor array once, from a bound on the record count: a conversion
 * knows it exactly, a repack sums its inputs' pointer counts.  A HINT -- the
 * array still doubles if the bound was short, it just copies tens of megabytes
 * of descriptors on the way. */
static void zsi_inorder_reserve(struct zsi_inorder_out *w, size_t nents)
{
    struct zsi_inorder_ent *q;

    if (w->ents || !nents) return;
    if (nents > SIZE_MAX / sizeof(*q)) return;

    q = malloc(nents * sizeof(*q));
    if (!q) return;
    w->ents = q;
    w->ents_alloc = nents;
}

/* Offer one record.  key and val MUST stay valid until the emit -- every caller
 * holds its sources mapped for longer than that, which is the premise the
 * builder rests on.  val == NULL is a deletion, which contributes nothing at all
 * to the values region (F-37). */
static int zsi_inorder_add(struct zsi_inorder_out *w, const char *key,
                           size_t keylen, const char *val, size_t vallen)
{
    size_t nn, nw, klen_narrow, klen_wide, vlen;

    if (w->failed) return ZS_INTERNAL;
    if (keylen < 1) return ZS_BADFORMAT;            /* F-14 */

    nn = zsi_kent_encoded_len(keylen, false);
    nw = zsi_kent_encoded_len(keylen, true);
    if (!nn || !nw) { w->failed = true; return ZS_BADFORMAT; }
    if (!zsi_add_sz(w->klen_narrow, nn, &klen_narrow)
        || !zsi_add_sz(w->klen_wide, nw, &klen_wide)) {
        w->failed = true;
        return ZS_BADFORMAT;
    }

    /* the value plus the trailing NUL F-37 requires */
    vlen = w->vlen;
    if (val && !zsi_add3_sz(w->vlen, vallen, 1, &vlen)) {
        w->failed = true;
        return ZS_BADFORMAT;
    }

    if (w->nents == w->ents_alloc) {
        size_t want = w->ents_alloc ? w->ents_alloc * 2 : 256;
        struct zsi_inorder_ent *q;
        if (want > SIZE_MAX / sizeof(*q)) { w->failed = true; return ZS_INTERNAL; }
        q = realloc(w->ents, want * sizeof(*q));
        if (!q) { w->failed = true; return ZS_INTERNAL; }
        w->ents = q;
        w->ents_alloc = want;
    }

    struct zsi_inorder_ent *e = &w->ents[w->nents];
    e->key = key;
    e->keylen = keylen;
    e->val = val;
    e->vallen = val ? vallen : 0;

    w->klen_narrow = klen_narrow;
    w->klen_wide = klen_wide;
    w->vlen = vlen;
    w->nents++;
    return ZS_OK;
}

/* Every length and offset the header and the emit need.
 *
 * WIDTHS ARE A FIXED POINT, not a calculation, because each depends on offsets
 * the other moves: the pointer width on where the keys region ends, the valptr
 * width on where the values region ends, and widening either pushes both further
 * out.  Widening only ever increases an offset, so the iteration is monotone --
 * it settles in at most two rounds and the answer it settles on is canonical
 * (F-26c): if narrow did not fit before widening, it does not fit after. */
struct zsi_layout {
    bool   ptr_wide, val_wide;
    size_t seclen;                       /* the pointer region, pad included */
    size_t keys_len, values_len;
    size_t keys_off, values_off, values_end;         /* offsets in the file */
};

static int zsi_inorder_layout(const struct zsi_inorder_out *w,
                              struct zsi_layout *lay)
{
    bool ptr_wide = false, val_wide = false;

    if (w->failed) return ZS_INTERNAL;

    for (;;) {
        bool need_pw, need_vw;
        size_t keys_len, seclen, keys_off, values_off, values_end;

        /* the entries, then the sentinel: keylen 0, one past the values region
         * (F-36a) */
        keys_len = val_wide ? w->klen_wide : w->klen_narrow;
        if (!zsi_add_sz(keys_len, zsi_kent_encoded_len(0, val_wide), &keys_len))
            return ZS_BADFORMAT;

        seclen = zsi_ptrs_section_len((uint64_t)w->nents + 1, ptr_wide);
        if (!seclen) return ZS_BADFORMAT;

        if (!zsi_add_sz(ZSI_HEADER_LEN, seclen, &keys_off)) return ZS_BADFORMAT;
        if (!zsi_add_sz(keys_off, keys_len, &values_off)) return ZS_BADFORMAT;
        if (!zsi_add_sz(values_off, w->vlen, &values_end)) return ZS_BADFORMAT;

        need_pw = ptr_wide || values_off > 0xFFFFFFFFu;   /* keys region end */
        need_vw = val_wide || values_end > 0xFFFFFFFFu;
        if (need_pw == ptr_wide && need_vw == val_wide) {
            lay->ptr_wide   = ptr_wide;
            lay->val_wide   = val_wide;
            lay->seclen     = seclen;
            lay->keys_len   = keys_len;
            lay->values_len = w->vlen;
            lay->keys_off   = keys_off;
            lay->values_off = values_off;
            lay->values_end = values_end;
            return ZS_OK;
        }
        ptr_wide = need_pw;
        val_wide = need_vw;
    }
}

/* A sequential writer over one region of the output, checksumming what passes
 * through it.
 *
 * Two shapes, and the only difference is the capacity.  A STREAMING sink holds a
 * fixed window, hashes each chunk as it fills and writes it at the offset it has
 * reached, so its memory does not depend on the region's size; a JOINED sink has
 * room for the whole region and flushes once, which is what an engine that can
 * only checksum a single run needs (F-5d) and what a caller wanting the bytes
 * rather than a file gets.  Both are filled by exactly the same emit.
 *
 * Writes go through lseek + ZS_WRITE rather than pwrite deliberately: ZS_WRITE
 * is the hook T-8's crash injection interposes, and a merge that wrote around it
 * would quietly stop being crash-tested. */
#define ZSI_SINK_WINDOW  (256u * 1024u)

struct zsi_sink {
    int           fd;                    /* < 0: keep the bytes, never write */
    off_t         at;                    /* file offset of the next flush */
    char         *buf;
    size_t        len, cap;
    bool          owned;
    bool          stream;                /* flush as it fills, hashing as it goes */
    unsigned      csum_id;
    zs_csum      *csum;
    XXH3_state_t  st;                    /* engine 1 */
    uint64_t      digest;                /* engine 2, from its single flush */
    unsigned      flushes;
    int           err;
};

/* base != NULL borrows that buffer, which must have room for the whole region.
 * fd < 0 requires it: there is nowhere to flush to. */
static int zsi_sink_init(struct zsi_sink *s, int fd, off_t at, size_t region,
                         size_t budget, char *base, zs_csum *csum,
                         unsigned csum_id)
{
    memset(s, 0, sizeof(*s));
    s->fd = fd;
    s->at = at;
    s->csum = csum;
    s->csum_id = csum_id;
    s->err = ZS_OK;

    /* Stream a region that would cost more than the budget to hold (A-20), and
     * hold one that would not, because holding it buys the one-shot checksum.
     * A caller-supplied engine checksums one run in one call (F-5d), so it can
     * never stream: its region is held whatever the budget says. */
    s->stream = (fd >= 0 && csum_id != ZSI_CSUM_EXTERNAL && region > budget);

    if (base) {
        s->buf = base;
        s->cap = region ? region : 1;
    } else {
        s->cap = s->stream ? ZSI_SINK_WINDOW : (region ? region : 1);
        s->buf = malloc(s->cap);
        if (!s->buf) return ZS_INTERNAL;
        s->owned = true;
    }

    if (csum_id == ZSI_CSUM_XXHASH) XXH3_64bits_reset(&s->st);
    return ZS_OK;
}

static void zsi_sink_fini(struct zsi_sink *s)
{
    if (s->owned) free(s->buf);
    s->buf = NULL;
}

/* Hash what is buffered and write it out.  A sink with no file keeps everything:
 * its buffer IS the region, and it is the caller's answer. */
static void zsi_sink_flush(struct zsi_sink *s)
{
    if (s->err != ZS_OK) return;

    if (!s->stream) {
        /* The whole region, checksummed in ONE call -- which is the only reason
         * a small output is worth holding: XXH3 one-shots at about 54 GB/s
         * against 21 GB/s streamed.  A second flush would checksum a fragment,
         * and the capacity is the whole region precisely so there is never one.
         * F-26g's value for an empty region comes from the engine either way,
         * which is why this does not skip a zero length. */
        if (s->flushes) { s->err = ZS_INTERNAL; return; }
        s->digest = s->csum(s->buf, s->len);
        s->flushes++;
        if (s->fd >= 0 && s->len)
            s->err = zsi_write_at(s->fd, s->buf, s->len, s->at);
        return;
    }

    if (!s->len) return;
    if (s->csum_id == ZSI_CSUM_XXHASH)
        XXH3_64bits_update(&s->st, s->buf, s->len);
    s->flushes++;
    s->err = zsi_write_at(s->fd, s->buf, s->len, s->at);
    s->at += (off_t)s->len;
    s->len = 0;
}

/* Bytes straight from an input's mapping: hashed and written without being
 * copied, so a value larger than the window neither grows it nor is copied
 * twice.  Only a streaming sink can do this -- a joined one owes its caller the
 * bytes themselves. */
static void zsi_sink_through(struct zsi_sink *s, const char *p, size_t n)
{
    zsi_sink_flush(s);
    if (s->err != ZS_OK) return;

    if (s->csum_id == ZSI_CSUM_XXHASH) XXH3_64bits_update(&s->st, p, n);
    s->err = zsi_write_at(s->fd, p, n, s->at);
    s->at += (off_t)n;
}

static char *zsi_sink_claim_slow(struct zsi_sink *s, size_t n)
{
    char *at;

    if (s->err != ZS_OK) return NULL;

    zsi_sink_flush(s);
    if (s->err != ZS_OK) return NULL;

    if (n > s->cap - s->len) {
        /* One entry must be contiguous, so a key bigger than the window widens
         * it -- bounded by that key, and nothing else can cause it. */
        char *q;
        if (!s->owned) { s->err = ZS_INTERNAL; return NULL; }
        q = realloc(s->buf, n);
        if (!q) { s->err = ZS_INTERNAL; return NULL; }
        s->buf = q;
        s->cap = n;
    }

    at = s->buf + s->len;
    s->len += n;
    return at;
}

/* n contiguous bytes for the caller to fill.
 *
 * `inline` is a MEASUREMENT: everything the emit does per record comes through
 * here -- a pointer offset, a key entry, a value and its NUL -- so at millions of
 * records the call frame is the cost, not the copy.  Clang inlines it either way;
 * GCC's auto-inline budget does not, and zeroskip.c is compiled with the host
 * project's flags, so it has to be said in the source (see zsi_cur_order). */
static inline char *zsi_sink_claim(struct zsi_sink *s, size_t n)
{
    if (s->err == ZS_OK && n <= s->cap - s->len) {
        char *at = s->buf + s->len;
        s->len += n;
        return at;
    }
    return zsi_sink_claim_slow(s, n);
}

static void zsi_sink_put(struct zsi_sink *s, const char *p, size_t n)
{
    char *at;

    if (s->stream && n > s->cap) { zsi_sink_through(s, p, n); return; }

    at = zsi_sink_claim(s, n);
    if (at) memcpy(at, p, n);
}

/* One record's value: its bytes and the trailing NUL F-13 keeps, in ONE claim
 * rather than two calls, because this runs per record. */
static void zsi_sink_value(struct zsi_sink *s, const char *p, size_t n)
{
    char *at;

    if (s->stream && n + 1 > s->cap) {
        zsi_sink_through(s, p, n);               /* straight from the mapping */
        at = zsi_sink_claim(s, 1);
        if (at) *at = '\0';
        return;
    }

    at = zsi_sink_claim(s, n + 1);
    if (!at) return;
    if (n) memcpy(at, p, n);
    at[n] = '\0';
}

/* F-26d's header pad and F-2's pad to a multiple of 8. */
static void zsi_sink_zeros(struct zsi_sink *s, size_t n)
{
    char *at = zsi_sink_claim(s, n);

    if (at) memset(at, 0, n);
}

static uint64_t zsi_sink_digest(struct zsi_sink *s)
{
    if (!s->stream)                    return s->digest;   /* the one call */
    if (s->csum_id == ZSI_CSUM_XXHASH) return XXH3_64bits_digest(&s->st);
    return 0;                                        /* engine 0 (F-5b) */
}

/* Emit the body and fill the trailer.
 *
 * The pointer region goes into one sink and the keys and values regions into
 * ANOTHER, single sink -- because F-33 checksums those two as one run and a sink
 * hashes what passes through it in order, so entries first and then values gives
 * the digest F-33 defines with no second pass and nothing held.
 *
 * Two walks over the descriptors, in the same order, so every destination offset
 * is a running sum: the entries with their valptrs already absolute, then the
 * value bytes, each copied straight from the mapping the record was read from.
 *
 * fd < 0 emits into *bodyp instead, one buffer with the sections abutting exactly
 * as they do in the file; the caller frees it. */
static int zsi_inorder_emit(struct zsi_inorder_out *w,
                            const struct zsi_layout *lay,
                            zs_csum *csum, unsigned csum_id, size_t budget,
                            int fd, char **bodyp, char *trailer)
{
    struct zsi_sink ptrs, data;
    char *body = NULL;
    size_t i, koff = 0, voff = 0;
    size_t phdr = lay->ptr_wide ? 16 : 8;
    size_t pper = lay->ptr_wide ? 8 : 4;
    size_t praw = phdr + pper * (w->nents + 1);
    int r;

    if (w->failed) return ZS_INTERNAL;
    if (bodyp) *bodyp = NULL;

    if (fd < 0) {
        size_t total;
        if (!zsi_add3_sz(lay->seclen, lay->keys_len, lay->values_len, &total))
            return ZS_BADFORMAT;
        body = malloc(total ? total : 1);
        if (!body) return ZS_INTERNAL;
    }

    r = zsi_sink_init(&ptrs, fd, (off_t)ZSI_HEADER_LEN, lay->seclen, budget,
                      body, csum, csum_id);
    if (r != ZS_OK) { free(body); return r; }
    r = zsi_sink_init(&data, fd, (off_t)lay->keys_off,
                      lay->keys_len + lay->values_len, budget,
                      body ? body + lay->seclen : NULL, csum, csum_id);
    if (r != ZS_OK) { zsi_sink_fini(&ptrs); free(body); return r; }

    /* The pointer region's header (F-26): its type byte, its record count, and
     * the pad between them that F-26d requires to be zero. */
    {
        char h[16];
        memset(h, 0, sizeof(h));
        if (lay->ptr_wide) {
            h[0] = (char)ZSI_PTRS64;
            zsi_put64(h + 8, (uint64_t)w->nents);
        } else {
            h[0] = (char)ZSI_PTRS32;
            zsi_put32(h + 4, (uint32_t)w->nents);
        }
        zsi_sink_put(&ptrs, h, phdr);
    }

    /* The entries and their offsets, then the sentinel -- keylen 0, valptr one
     * past the values region, which is what makes F-36's derivation
     * unconditional for the last record (F-36a). */
    for (i = 0; i <= w->nents; i++) {
        bool sentinel = (i == w->nents);
        const struct zsi_inorder_ent *e = sentinel ? NULL : &w->ents[i];
        size_t keylen = sentinel ? 0 : e->keylen;
        size_t enclen = zsi_kent_encoded_len(keylen, lay->val_wide);
        uint64_t abs = (uint64_t)(lay->keys_off + koff);
        uint64_t valptr = (uint64_t)lay->values_off
                        + (sentinel ? lay->values_len : voff);
        char *at = zsi_sink_claim(&ptrs, pper);

        if (!at) break;
        if (lay->ptr_wide) zsi_put64(at, abs);
        else               zsi_put32(at, (uint32_t)abs);

        at = zsi_sink_claim(&data, enclen);
        if (!at) break;
        zsi_kent_encode(at, sentinel ? NULL : e->key, keylen,
                        !sentinel && e->val == NULL, valptr, lay->val_wide);

        koff += enclen;
        if (!sentinel && e->val) voff += e->vallen + 1;
    }

    zsi_sink_zeros(&ptrs, lay->seclen - praw);       /* F-2's pad */

    /* The values, in the same order, each straight from where it was read. */
    for (i = 0; i < w->nents && data.err == ZS_OK; i++) {
        const struct zsi_inorder_ent *e = &w->ents[i];
        if (!e->val) continue;                       /* a deletion (F-37) */
        zsi_sink_value(&data, e->val, e->vallen);
    }

    zsi_sink_flush(&ptrs);
    zsi_sink_flush(&data);

    r = ptrs.err != ZS_OK ? ptrs.err : data.err;
    if (r == ZS_OK) {
        /* Trailer: the data checksum over the keys and values regions as ONE run
         * (F-33), then the pointer region's (F-34).  Neither covers the other. */
        zsi_put64(trailer, zsi_sink_digest(&data));
        zsi_put64(trailer + 8, zsi_sink_digest(&ptrs));
        if (bodyp) { *bodyp = body; body = NULL; }
    }

    zsi_sink_fini(&ptrs);
    zsi_sink_fini(&data);
    free(body);
    return r;
}

/********** PRIVATE INDEX *************/

/* An unordered file has no pointer section, so key order for it must be derived
 * by replaying its spans.  There is no shared index file: every process builds
 * its own, in private memory, for each unordered file in its snapshot (section
 * 5.4).  That is what makes G-6 hold without a lock -- nothing a reader may be
 * reading is ever rewritten beneath it, because nothing is shared at all.
 *
 * Structure: a sorted array of record offsets, plus a small sorted delta array
 * for records committed since the base was built.  Lookups consult the delta
 * first; traversal merges the two, preferring the delta on equal keys.
 *
 * The full rationale, and the build and lookup paths, are in the task that
 * implements them.  Only the shape and the destructor live here, because
 * zsi_file_release must be able to free an index without the caller remembering to. */
/* The delta is merged into the base and cleared once it exceeds a bound.
 *
 * The bound is what makes insertion amortised O(1) rather than O(n): a splice
 * into an array of at most this many entries is a bounded memmove, and the merge
 * that empties it is linear in the whole index but happens once per bound's
 * worth of inserts.  A single sorted array with no delta would memmove the
 * entire index per commit, which for a 2MB active file under bulk load is
 * megabytes of copying per transaction.
 *
 * ZSI_DELTA_MAX is the FLOOR, and a fixed floor is what made the whole thing
 * quadratic in generation size.  Each merge is O(nbase) -- with a record decode
 * per comparison, since an entry is an offset and the key lives in the file
 * (zsi_index_key_at) -- and it happens every ZSI_DELTA_MAX inserts, so a
 * generation of N records costs N/ZSI_DELTA_MAX merges of O(N): measured at 2M
 * records, 8.45M entries merged at a 2MB rollover_size, 66.4M at 16MB and 251.9M
 * at 64MB.  That is the cost the downstream deployment could see from outside
 * only as "64MB is the worst setting despite the lowest write amplification".
 *
 * Making the bound proportional to the base makes the merge side LINEAR: a merge
 * every nbase/32 inserts is 32 passes over the generation however large it grows.
 * The divisor is the interesting number, and 32 rather than 8 is a measurement.
 * The other side of the trade is the D-13b fold, which merges a commit's run into
 * the delta IN PLACE and so costs O(ndelta) per commit for a run that is not
 * ascending -- so a bigger delta is paid per transaction.  At /8 the bound starts
 * moving at nbase > 8192, which a 2MB generation reaches, and it cost 11-15%
 * across every default-sized shape while winning 3-5x at 64MB.  At /32 nothing
 * moves below nbase > 32768 -- about a 4MB generation -- so the flush counts at
 * the 2MB default are *identical* to the fixed bound's, and 2M records at 64MB
 * with random keys went 7.07-7.44s to 1.91-2.19s.
 *
 * What keeps the fold side safe once the bound does move: a large generation
 * implies large transactions, because D-9d's rollover_txns bounds a generation at
 * 1024 spans, so a generation big enough to raise the bound cannot have been
 * built from one-record commits.  The fold's per-record cost is therefore bounded
 * by rollover_txns/32 whatever rollover_size is. */
#define ZSI_DELTA_MAX 1024
#define ZSI_DELTA_DIV 32

/* Record offsets are size_t rather than uint32_t.
 *
 * uint32_t would halve the footprint and rollover_size (2MB by default) keeps
 * real unordered files far below 4GB -- but rollover_size is caller-configurable
 * and a crash can leave a larger file behind, and the failure mode of guessing
 * wrong is a database that cannot be opened.  G-3 says any state a crash can
 * produce must open; paying 4 bytes an entry to keep that unconditional is the
 * right trade.  A 2MB file of minimum-size records holds 262144 of them, so the
 * index is 2MB at worst. */
struct zsi_index {
    struct zsi_file *file;
    size_t *base;   size_t nbase;
    size_t *delta;  size_t ndelta, adelta;
};

static void zsi_index_free(struct zsi_index **ip)
{
    struct zsi_index *ix = *ip;
    if (!ix) return;

    free(ix->base);
    free(ix->delta);
    free(ix);
    *ip = NULL;
}

/* Decode the record at off far enough to reach its key.
 *
 * Every offset in an index decoded successfully during the build, so this cannot
 * fail for a well-formed index -- but it is called from comparison functions
 * where returning a wrong answer is worse than returning a stable one, so a
 * failure yields an empty key rather than reading uninitialised memory. */
static bool zsi_index_key_at(struct zsi_file *f, size_t off,
                             const char **kp, size_t *klp)
{
    const char *b = zsi_file_at(f, off, 1);
    struct zsi_rec r;

    if (!b || zsi_rec_decode(b, f->size - off, &r) != ZS_OK) {
        *kp = "";
        *klp = 0;
        return false;
    }

    *kp = r.key;
    *klp = r.keylen;
    return true;
}

/* Sort context: the comparator cannot be a global, because two threads may hold
 * handles on different databases with different comparators.  That rules out
 * plain qsort, and qsort_r's signature differs between glibc and the BSDs, so
 * this file carries its own merge sort taking an explicit context. */
struct zsi_ksort {
    struct zsi_file *f;
    zs_compar       *compar;
};

/* Order by key ascending, then by offset DESCENDING.
 *
 * The offset tie-break is what makes "newest version of a key wins within a
 * file" (D-14) fall out of the sort: equal keys end up newest-first, so keeping
 * the first of each run keeps the newest.  There is no second pass and no
 * separate notion of recency. */
static int zsi_ksort_cmp(struct zsi_ksort *ks, size_t a, size_t b)
{
    const char *ka, *kb;
    size_t la, lb;

    zsi_index_key_at(ks->f, a, &ka, &la);
    zsi_index_key_at(ks->f, b, &kb, &lb);

    int c = zsi_cmp(ks->compar, ka, la, kb, lb);
    if (c) return c;

    if (a == b) return 0;
    return a > b ? -1 : 1;              /* higher offset first */
}

static void zsi_msort(size_t *arr, size_t n, size_t *tmp, struct zsi_ksort *ks)
{
    if (n < 2) return;

    size_t mid = n / 2;
    zsi_msort(arr, mid, tmp, ks);
    zsi_msort(arr + mid, n - mid, tmp + mid, ks);

    size_t i = 0, j = mid, k = 0;
    while (i < mid && j < n)
        tmp[k++] = (zsi_ksort_cmp(ks, arr[j], arr[i]) < 0) ? arr[j++] : arr[i++];
    while (i < mid) tmp[k++] = arr[i++];
    while (j < n)   tmp[k++] = arr[j++];

    memcpy(arr, tmp, n * sizeof(*arr));
}

/* The first position in arr whose key is >= (key, keylen). */
static size_t zsi_index_lb(const size_t *arr, size_t n, struct zsi_ksort *ks,
                           const char *key, size_t keylen)
{
    size_t lo = 0, hi = n;

    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        const char *k;
        size_t kl;
        zsi_index_key_at(ks->f, arr[mid], &k, &kl);
        if (zsi_cmp(ks->compar, k, kl, key, keylen) < 0) lo = mid + 1;
        else hi = mid;
    }

    return lo;
}

/* Whether the entry at arr[i] has exactly this key. */
static bool zsi_index_eq(const size_t *arr, size_t n, size_t i,
                         struct zsi_ksort *ks, const char *key, size_t keylen)
{
    const char *k;
    size_t kl;

    if (i >= n) return false;
    zsi_index_key_at(ks->f, arr[i], &k, &kl);
    return zsi_cmp(ks->compar, k, kl, key, keylen) == 0;
}

/* Collector for the build replay. */
struct zsi_index_build {
    size_t *offs;
    size_t  n, alloc;
    bool    oom;
};

static int zsi_index_build_cb(void *rock, const struct zsi_rec *rec, size_t off)
{
    struct zsi_index_build *b = rock;

    (void)rec;
    if (b->n == b->alloc) {
        size_t want = b->alloc ? b->alloc * 2 : 256;
        size_t *p = realloc(b->offs, want * sizeof(*p));
        if (!p) { b->oom = true; return 1; }
        b->offs = p;
        b->alloc = want;
    }

    b->offs[b->n++] = off;
    return 0;
}

/* Folding a run of newly known records into an index; defined below,
 * forward-declared because the seeded build path uses it and it is easier to
 * read after the lookup and traversal it shares its invariants with. */
static int zsi_index_fold_run(struct zsi_index *ix, zs_compar *compar,
                              const size_t *run, size_t n);

/* Sort a replayed run of offsets into index order and keep the newest record for
 * each key (D-13a).  n is updated to the deduplicated count.
 *
 * The offset-descending tie-break in zsi_ksort_cmp is what makes "newest wins"
 * fall out of the sort: equal keys arrive newest-first, so keeping the first of
 * each run keeps the newest, with no second pass and no separate notion of
 * recency. */
static int zsi_index_sort_dedup(struct zsi_file *f, zs_compar *compar,
                                size_t *offs, size_t *np)
{
    struct zsi_ksort ks = { f, compar };
    size_t n = *np;

    if (n < 2) return ZS_OK;

    size_t *tmp = malloc(n * sizeof(*tmp));
    if (!tmp) return ZS_INTERNAL;

    zsi_msort(offs, n, tmp, &ks);
    free(tmp);

    size_t w = 0;
    for (size_t i = 0; i < n; i++) {
        if (w) {
            const char *ka, *kb;
            size_t la, lb;
            zsi_index_key_at(f, offs[w - 1], &ka, &la);
            zsi_index_key_at(f, offs[i], &kb, &lb);
            if (zsi_cmp(compar, ka, la, kb, lb) == 0) continue;
        }
        offs[w++] = offs[i];
    }

    *np = w;
    return ZS_OK;
}

/* Build the private index for an unordered file by replaying its spans,
 * optionally SEEDED.
 *
 * It reflects COMMITTED spans only, and for each key only its newest committed
 * record (D-13a).  Building it means replaying spans and skipping rolled-back
 * ones -- never simply walking every record, which would resurrect aborted
 * writes.  That is why this goes through zsi_unordered_replay rather than
 * scanning the file directly, and why test_index_committed_only exists.
 *
 * base/nbase, when given, is an already-sorted, already-deduplicated array of
 * record offsets covering everything committed below `from` -- exactly what a
 * pointer table holds (P-9).  Ownership transfers to the index, INCLUDING on
 * every failure path, so a caller that has just loaded a table never has to
 * decide who frees it.  The replay then starts at `from` and the suffix is folded
 * in as one sorted run through zsi_index_fold_run, which is the same path a
 * writer uses at commit (D-13b): one insertion path rather than two.
 *
 * With base NULL and from ZSI_HEADER_LEN this is the plain full build.
 *
 * Sets f->complete as a side effect, since the replay establishes it. */
static int zsi_index_build_from(struct zsi_file *f, zs_compar *compar,
                                size_t *base, size_t nbase, size_t from)
{
    struct zsi_index_build b;
    struct zsi_index *ix;
    int r;

    zsi_index_free(&f->index);

    memset(&b, 0, sizeof(b));
    r = zsi_unordered_replay(f, from, zsi_index_build_cb, &b);
    if (r != ZS_OK) { free(b.offs); free(base); return r; }
    if (b.oom) { free(b.offs); free(base); return ZS_INTERNAL; }

    ix = zsi_zmalloc(sizeof(*ix));
    if (!ix) { free(b.offs); free(base); return ZS_INTERNAL; }
    ix->file = f;

    if (base) {
        ix->base = base;
        ix->nbase = nbase;
        f->index = ix;

        /* The replay collected the suffix in OFFSET order and may hold several
         * records for one key; the fold wants a sorted run with one entry per
         * key, which is what the commit site gets for free from the pending
         * skiplist and this path has to produce. */
        r = zsi_index_sort_dedup(f, compar, b.offs, &b.n);
        if (r == ZS_OK) r = zsi_index_fold_run(ix, compar, b.offs, b.n);
        free(b.offs);
        if (r != ZS_OK) zsi_index_free(&f->index);
        return r;
    }

    r = zsi_index_sort_dedup(f, compar, b.offs, &b.n);
    if (r != ZS_OK) { free(b.offs); free(ix); return r; }

    ix->base = b.offs;
    ix->nbase = b.n;
    f->index = ix;
    return ZS_OK;
}

/* The plain full build: no seed, from the top of the records region. */
static int zsi_index_build(struct zsi_file *f, zs_compar *compar)
{
    f->cached_upto = ZSI_HEADER_LEN;
    return zsi_index_build_from(f, compar, NULL, 0, ZSI_HEADER_LEN);
}

/* Point lookup.  Consults the delta first, so a key present in both yields the
 * newer record. */
static int zsi_index_find(struct zsi_index *ix, zs_compar *compar,
                          const char *key, size_t keylen, size_t *off)
{
    struct zsi_ksort ks = { ix->file, compar };
    size_t i;

    i = zsi_index_lb(ix->delta, ix->ndelta, &ks, key, keylen);
    if (zsi_index_eq(ix->delta, ix->ndelta, i, &ks, key, keylen)) {
        *off = ix->delta[i];
        return ZS_OK;
    }

    i = zsi_index_lb(ix->base, ix->nbase, &ks, key, keylen);
    if (zsi_index_eq(ix->base, ix->nbase, i, &ks, key, keylen)) {
        *off = ix->base[i];
        return ZS_OK;
    }

    return ZS_NOTFOUND;
}

/* Ordered traversal (D-13).
 *
 * A cursor over the merged base+delta ordering.  There is deliberately no random
 * access: the merged view is not an array -- a key may appear in both sides -- so
 * a count would be an upper bound and an index-addressed at() would have to
 * re-walk the merge on every call.  The only consumer advances sequentially. */
struct zsi_index_cur { size_t bi, di; };

static void zsi_index_cur_seek_first(struct zsi_index_cur *c)
{
    c->bi = 0;
    c->di = 0;
}

static void zsi_index_cur_seek(struct zsi_index *ix, zs_compar *compar,
                               const char *key, size_t keylen,
                               struct zsi_index_cur *c)
{
    struct zsi_ksort ks = { ix->file, compar };

    /* Both sides are searched independently: the merge happens on get, not here. */
    c->bi = zsi_index_lb(ix->base, ix->nbase, &ks, key, keylen);
    c->di = zsi_index_lb(ix->delta, ix->ndelta, &ks, key, keylen);
}

/* ZS_DONE when exhausted, otherwise ZS_OK with *out filled and *off set. */
static int zsi_index_cur_get(struct zsi_index *ix, zs_compar *compar,
                             struct zsi_index_cur *c,
                             struct zsi_rec *out, size_t *off)
{
    bool have_b = c->bi < ix->nbase;
    bool have_d = c->di < ix->ndelta;
    size_t chosen;

    if (!have_b && !have_d) return ZS_DONE;

    if (have_b && have_d) {
        const char *kb, *kd;
        size_t lb, ld;
        zsi_index_key_at(ix->file, ix->base[c->bi], &kb, &lb);
        zsi_index_key_at(ix->file, ix->delta[c->di], &kd, &ld);
        /* Prefer the delta when the keys are equal: it is the newer record. */
        chosen = (zsi_cmp(compar, kd, ld, kb, lb) <= 0) ? ix->delta[c->di]
                                              : ix->base[c->bi];
    } else {
        chosen = have_d ? ix->delta[c->di] : ix->base[c->bi];
    }

    const char *b = zsi_file_at(ix->file, chosen, 1);
    if (!b) return ZS_DONE;
    if (zsi_rec_decode(b, ix->file->size - chosen, out)
        != ZS_OK)
        return ZS_DONE;

    if (off) *off = chosen;
    return ZS_OK;
}

static void zsi_index_cur_next(struct zsi_index *ix, zs_compar *compar,
                               struct zsi_index_cur *c)
{
    bool have_b = c->bi < ix->nbase;
    bool have_d = c->di < ix->ndelta;

    if (!have_b && !have_d) return;

    if (have_b && have_d) {
        const char *kb, *kd;
        size_t lb, ld;
        zsi_index_key_at(ix->file, ix->base[c->bi], &kb, &lb);
        zsi_index_key_at(ix->file, ix->delta[c->di], &kd, &ld);
        int cmp = zsi_cmp(compar, kd, ld, kb, lb);

        if (cmp == 0) {
            /* Advance BOTH.  The delta's record was just yielded; leaving the
             * base's stale copy of the same key in place would surface it on the
             * following step, which breaks D-14h one level down -- a per-file
             * cursor must never yield the same key twice. */
            c->di++;
            c->bi++;
        } else if (cmp < 0) {
            c->di++;
        } else {
            c->bi++;
        }
        return;
    }

    if (have_d) c->di++;
    else        c->bi++;
}

/* Reverse twins (D-14k).  A reverse position is a COUNT: the candidate on
 * each side is [pos-1], and 0 means that side is spent -- nothing underflows.
 * The tie rules are the forward ones verbatim: equal keys prefer the delta
 * (newer), and stepping past a tie consumes BOTH sides, or the base's stale
 * copy would surface on the following step and break D-14h one level down. */
static void zsi_index_cur_seek_last(struct zsi_index *ix,
                                    struct zsi_index_cur *c)
{
    c->bi = ix->nbase;
    c->di = ix->ndelta;
}

/* Position on the largest key <= (inclusive) or < (exclusive) the given key.
 * A lower bound counts the elements strictly below the key, which IS the
 * exclusive reverse position; inclusive adds the exact match when present. */
static void zsi_index_cur_seek_rev(struct zsi_index *ix, zs_compar *compar,
                                   const char *key, size_t keylen,
                                   bool inclusive, struct zsi_index_cur *c)
{
    struct zsi_ksort ks = { ix->file, compar };

    c->bi = zsi_index_lb(ix->base, ix->nbase, &ks, key, keylen);
    if (inclusive && zsi_index_eq(ix->base, ix->nbase, c->bi, &ks, key, keylen))
        c->bi++;
    c->di = zsi_index_lb(ix->delta, ix->ndelta, &ks, key, keylen);
    if (inclusive && zsi_index_eq(ix->delta, ix->ndelta, c->di, &ks, key, keylen))
        c->di++;
}

static int zsi_index_cur_get_rev(struct zsi_index *ix, zs_compar *compar,
                                 struct zsi_index_cur *c,
                                 struct zsi_rec *out, size_t *off)
{
    bool have_b = c->bi > 0;
    bool have_d = c->di > 0;
    size_t chosen;

    if (!have_b && !have_d) return ZS_DONE;

    if (have_b && have_d) {
        const char *kb, *kd;
        size_t lb, ld;
        zsi_index_key_at(ix->file, ix->base[c->bi - 1], &kb, &lb);
        zsi_index_key_at(ix->file, ix->delta[c->di - 1], &kd, &ld);
        /* The LARGER key is next; equal keys prefer the delta, the newer. */
        chosen = (zsi_cmp(compar, kd, ld, kb, lb) >= 0) ? ix->delta[c->di - 1]
                                              : ix->base[c->bi - 1];
    } else {
        chosen = have_d ? ix->delta[c->di - 1] : ix->base[c->bi - 1];
    }

    const char *b = zsi_file_at(ix->file, chosen, 1);
    if (!b) return ZS_DONE;
    if (zsi_rec_decode(b, ix->file->size - chosen, out)
        != ZS_OK)
        return ZS_DONE;

    if (off) *off = chosen;
    return ZS_OK;
}

static void zsi_index_cur_prev(struct zsi_index *ix, zs_compar *compar,
                               struct zsi_index_cur *c)
{
    bool have_b = c->bi > 0;
    bool have_d = c->di > 0;

    if (!have_b && !have_d) return;

    if (have_b && have_d) {
        const char *kb, *kd;
        size_t lb, ld;
        zsi_index_key_at(ix->file, ix->base[c->bi - 1], &kb, &lb);
        zsi_index_key_at(ix->file, ix->delta[c->di - 1], &kd, &ld);
        int cmp = zsi_cmp(compar, kd, ld, kb, lb);

        if (cmp == 0) {
            /* Step past BOTH -- the D-14h reason zsi_index_cur_next gives. */
            c->di--;
            c->bi--;
        } else if (cmp > 0) {
            c->di--;
        } else {
            c->bi--;
        }
        return;
    }

    if (have_d) c->di--;
    else        c->bi--;
}

/* Merge the delta into the base and clear it: a linear pass, delta winning ties
 * because it is newer.
 *
 * Each side's key is decoded ONCE and held until that side advances.  Decoding
 * both every iteration is the obvious loop and doubles the work in the place
 * that does most of it: a comparison here is a random-access decode in the
 * mapped file, and this merge runs over the whole index. */
/* The bound the delta is merged at: proportional to the base, floored at
 * ZSI_DELTA_MAX.  See ZSI_DELTA_MAX for why proportional, and why the divisor
 * is what it is. */
static size_t zsi_index_delta_max(const struct zsi_index *ix)
{
    size_t prop = ix->nbase / ZSI_DELTA_DIV;
    return prop > ZSI_DELTA_MAX ? prop : ZSI_DELTA_MAX;
}

static int zsi_index_flush_delta(struct zsi_index *ix, zs_compar *compar)
{
    size_t *merged = malloc((ix->nbase + ix->ndelta) * sizeof(*merged));
    if (!merged) return ZS_OK;      /* the delta is still correct, just large */

    size_t bi = 0, di = 0, w = 0;
    const char *kb = NULL, *kd = NULL;
    size_t lb = 0, ld = 0;
    bool needb = true, needd = true;

    while (bi < ix->nbase || di < ix->ndelta) {
        if (bi >= ix->nbase) { merged[w++] = ix->delta[di++]; continue; }
        if (di >= ix->ndelta) { merged[w++] = ix->base[bi++]; continue; }

        if (needb) { zsi_index_key_at(ix->file, ix->base[bi], &kb, &lb); needb = false; }
        if (needd) { zsi_index_key_at(ix->file, ix->delta[di], &kd, &ld); needd = false; }
        int cmp = zsi_cmp(compar, kd, ld, kb, lb);

        if (cmp == 0)      { merged[w++] = ix->delta[di++]; bi++; needd = needb = true; }
        else if (cmp < 0)  { merged[w++] = ix->delta[di++]; needd = true; }
        else               { merged[w++] = ix->base[bi++]; needb = true; }
    }

    free(ix->base);
    ix->base = merged;
    ix->nbase = w;
    ix->ndelta = 0;

    return ZS_OK;
}

/* Fold a run of newly committed records into the index (D-13b).
 *
 * A writer is a reader that also maintains the active file's index
 * incrementally: it already knows every record it appends, so it folds them in
 * at commit rather than rescanning a file it is writing.
 *
 * `run` is SORTED by key ascending with one entry per key, and every entry is
 * newer than anything already in the index -- so the run wins every tie, against
 * the delta and the base alike.  That is not an extra obligation on the callers:
 * the commit site walks level 0 of the pending skiplist, which is one node per
 * key in key order, and the seeded build sorts its replayed suffix through
 * zsi_index_sort_dedup.
 *
 * The order is the whole point.  Folding record by record made each one a binary
 * search into the delta plus a memmove -- and a comparison in that search is a
 * record DECODE in the mapped file, so a bulk load paid O(n log delta) decodes
 * for order it was handed for nothing.  Measured on 200k records, 100-byte
 * values: 2.11M to 3.16M records/s at 1000 records per transaction, and 1.04M to
 * 4.18M with all 200k in ONE transaction -- because the old cost grew with the
 * transaction's size, so batching harder made a load SLOWER past about 10k
 * records and the curve is now flat.  `zsbench`'s store lines move 10% to 300%.
 *
 * What remains is this flush and the base merge under it, which is decodes and
 * nothing else -- the thing to measure a key or key-prefix cached beside each
 * offset against, since that is what would remove them.
 *
 * Nothing here re-validates a record.  Both callers have already decoded every
 * offset in the run -- the commit site wrote the records itself and refuses a
 * commit whose stream tore (C-8), and the seeded build's offsets come from a
 * replay that decoded each one -- so a decode per entry would buy nothing, and
 * skipping it is why an ascending run costs no decodes at all. */
static int zsi_index_fold_run(struct zsi_index *ix, zs_compar *compar,
                              const size_t *run, size_t n)
{
    if (n == 0) return ZS_OK;

    /* Merge into the delta first, then let it flush on its own bound.  A single
     * three-way merge of run, delta and base would save this pass over the run,
     * which is the smaller side; two two-way merges keep one statement of who
     * wins a tie, and that rule is the part nobody would notice diverging.
     *
     * IN PLACE and BACKWARDS, which is not a micro-optimisation -- it is what
     * makes a one-record transaction affordable.  Merging forwards needs somewhere
     * to write, so it allocates and copies the whole delta per commit: O(delta)
     * work and a malloc/free for a run of one, where the per-record insert this
     * replaced did a bounded memmove and no allocation.  That regressed
     * single-record commits by about 20% (144k to 121k stores/s at 20k records,
     * ZS_NOSYNC, so the two gates do not hide it), which is invisible on any
     * durable row and was reported from a NOSYNC one downstream.
     *
     * Backwards is what allows in place.  The write cursor starts above both read
     * cursors and each step consumes at least as much as it emits, so it can never
     * overtake the delta entry it has yet to read -- and when the run is exhausted
     * with the write cursor level with the read cursor, everything below is already
     * where it belongs, which is the loop's exit.  An ASCENDING run -- a bulk load,
     * or any caller with ordered keys -- takes that exit immediately after placing
     * its own entries, so the merge is O(n) rather than O(delta). */
    size_t want;
    if (!zsi_add_sz(ix->ndelta, n, &want)) return ZS_INTERNAL;
    if (want > ix->adelta) {
        size_t cap = ix->adelta ? ix->adelta : 64;
        while (cap < want) {
            if (cap > SIZE_MAX / 2) return ZS_INTERNAL;
            cap *= 2;
        }
        size_t *p = realloc(ix->delta, cap * sizeof(*p));
        if (!p) return ZS_INTERNAL;
        ix->delta = p;
        ix->adelta = cap;
    }

    size_t di = ix->ndelta, ri = n, w = want, dropped = 0;
    const char *kr = NULL, *kd = NULL;
    size_t lr = 0, ld = 0;
    bool needr = true, needd = true;

    while (di || ri) {
        if (!di) { ix->delta[--w] = run[--ri]; continue; }
        if (!ri) {
            if (w == di) break;         /* the rest is already in place */
            ix->delta[--w] = ix->delta[--di];
            continue;
        }

        if (needr) { zsi_index_key_at(ix->file, run[ri - 1], &kr, &lr); needr = false; }
        if (needd) { zsi_index_key_at(ix->file, ix->delta[di - 1], &kd, &ld); needd = false; }
        int cmp = zsi_cmp(compar, kr, lr, kd, ld);

        /* Descending, so the LARGER key is placed first.  An equal key drops the
         * delta's entry: the run is newer, and keeping one entry per key is what
         * bounds the delta at ZSI_DELTA_MAX however often a single key is
         * rewritten. */
        if (cmp == 0)      { ix->delta[--w] = run[--ri]; di--; dropped++;
                             needr = needd = true; }
        else if (cmp > 0)  { ix->delta[--w] = run[--ri]; needr = true; }
        else               { ix->delta[--w] = ix->delta[--di]; needd = true; }
    }

    /* Every tie emitted one entry for two inputs, leaving that many unused slots
     * at the BOTTOM, since the merge wrote downwards from the top.
     *
     * Counted rather than read off `w`, which is only the gap when the loop ran to
     * the end: the early exit above leaves `w` at the untouched delta's height,
     * and it can only be taken when nothing was dropped at all. */
    if (dropped)
        memmove(ix->delta, ix->delta + dropped,
                (want - dropped) * sizeof(*ix->delta));
    ix->ndelta = want - dropped;

    if (ix->ndelta > zsi_index_delta_max(ix))
        return zsi_index_flush_delta(ix, compar);
    return ZS_OK;
}

/* The merged base+delta ordering as one freshly allocated array (P-9).
 *
 * Deliberately does NOT mutate the index, even though merging in place would be
 * cheaper and would compact it as a useful side effect.  An index may be shared
 * with a live struct zsi_index_cur holding positions into BOTH arrays, and
 * rewriting them underneath it is exactly the in-place mutation of something a
 * reader is reading that G-6 forbids.  The only caller publishes a pointer
 * table, which is not worth that hazard. */
static int zsi_index_flatten(struct zsi_index *ix, zs_compar *compar,
                             size_t **out, size_t *nout)
{
    size_t total;

    if (!zsi_add_sz(ix->nbase, ix->ndelta, &total)) return ZS_INTERNAL;

    size_t *merged = malloc(total ? total * sizeof(*merged) : 1);
    if (!merged) return ZS_INTERNAL;

    size_t bi = 0, di = 0, w = 0;
    while (bi < ix->nbase || di < ix->ndelta) {
        if (bi >= ix->nbase) { merged[w++] = ix->delta[di++]; continue; }
        if (di >= ix->ndelta) { merged[w++] = ix->base[bi++]; continue; }

        const char *kb, *kd;
        size_t lb, ld;
        zsi_index_key_at(ix->file, ix->base[bi], &kb, &lb);
        zsi_index_key_at(ix->file, ix->delta[di], &kd, &ld);
        int cmp = zsi_cmp(compar, kd, ld, kb, lb);

        /* Delta wins ties: it is the newer record (D-14). */
        if (cmp == 0)      { merged[w++] = ix->delta[di++]; bi++; }
        else if (cmp < 0)  { merged[w++] = ix->delta[di++]; }
        else               { merged[w++] = ix->base[bi++]; }
    }

    *out = merged;
    *nout = w;
    return ZS_OK;
}

/********** POINTER TABLE CACHE *************/

/* Spec section 8.  An unordered file has no pointer section, so key order for it
 * is derived by replaying its spans (D-13a) -- bounded by rollover_size but paid
 * on every open.  A POINTER TABLE is that replay's result, published into a
 * cache directory the CALLER names, so another process can load it and replay
 * only the suffix beyond it.
 *
 * Three properties keep this from weakening anything:
 *
 *   - the cache directory is NOT the database (P-2), so R-3 still holds.  A
 *     reader writes nothing the database's correctness depends on, which is why
 *     a read-only handle may publish;
 *   - a table is published by rename and never modified (P-4), so G-6's "nothing
 *     a reader may be reading is ever rewritten beneath it" is unchanged;
 *   - a table is self-validating, and EVERY failure means "ignore it and replay"
 *     (P-11).  Nothing here can turn a readable database into an unreadable one.
 *
 * That last one is why nothing in this section reports corruption.  A rejected
 * table is ZS_NOTFOUND, identical to no table at all.
 *
 * Layering: this section may call upwards into PRIVATE INDEX and FILE OBJECT.
 * SNAPSHOT and WRITE PATH call into it. */

/* The same construction as the data-file magic (F-6), for the same reasons --
 * high bit set so no text file is mistaken for one and an eighth-bit-stripping
 * transfer is detected, invalid UTF-8 at byte 0, a CR-LF trap, a DOS
 * end-of-file, a bare LF, NUL padding -- and DELIBERATELY different bytes, so a
 * table and a data file are distinguishable by content as well as by name.
 * A reader validates all 16 (P-6). */
#define ZSI_IDX_MAGIC_LEN 16

static const unsigned char zsi_idx_magic[ZSI_IDX_MAGIC_LEN] = {
    0x89, 0x7A, 0x73, 0x69, 0x6E, 0x64, 0x65, 0x78,
    0x31, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00
};

/* Field offsets within the 96-byte header (P-5).  Spelled out rather than
 * derived by summing sizes, so the table in the spec maps to a table here. */
#define ZSI_IDX_HEADER_LEN       104
#define ZSI_IDX_OFF_MAGIC          0   /* 16 */
#define ZSI_IDX_OFF_VREAD         16   /*  1 */
#define ZSI_IDX_OFF_VWRITE        17   /*  1 */
#define ZSI_IDX_OFF_FLAGS         18   /*  2 */
#define ZSI_IDX_OFF_RESERVED1     20   /*  4 */
#define ZSI_IDX_OFF_UUID          24   /* 16 */
#define ZSI_IDX_OFF_START         40   /*  4 */
#define ZSI_IDX_OFF_RESERVED2     44   /*  4 */
#define ZSI_IDX_OFF_COMPAR        48   /* 16 */
#define ZSI_IDX_OFF_VALID_UPTO    64   /*  8 */
#define ZSI_IDX_OFF_TERM_OFF      72   /*  8 */
#define ZSI_IDX_OFF_NPTRS         80   /*  8 */
#define ZSI_IDX_OFF_TERM_CSUM     88   /*  8 */
#define ZSI_IDX_OFF_CSUM          96   /*  8, covers [0, 96) */

/* The header grew from 96 to 104 with the two checksums (F-4): the terminator
 * binding it records and its own. */

#define ZSI_IDX_VERSION_READ  1
#define ZSI_IDX_VERSION_WRITE 1

/* Bit 4 of flags: the index was built with checksum verification.  A table built
 * under ZS_NOCSUM may hold records a verifying reader would reject, so it must
 * not be handed to one (P-11).  The low 4 bits are the engine, exactly as in a
 * data file header. */
#define ZSI_IDX_FLAG_CSUM_VERIFIED 0x0010

/* A ceiling on a table's size, so a corrupt nptrs cannot become a huge
 * allocation before the exact-size check runs.  Deliberately generous rather
 * than tight: rollover_size is caller-configurable and a crash can leave a
 * larger file behind, and this is a sanity bound, not a policy. */
#define ZSI_IDX_MAX_BYTES ((size_t)1 << 31)

struct zsi_idxhdr {
    uint8_t     version_read;
    uint8_t     version_write;
    uint16_t    flags;
    zsi_uuid_t  uuid;
    uint32_t    start;
    char        compar_name[ZSI_COMPAR_NAME_LEN];  /* NUL-padded, as in a file */
    uint64_t    valid_upto;
    uint64_t    term_off;
    uint64_t    nptrs;
    uint64_t    term_csum;
};

static void zsi_idxhdr_encode(char *buf, const struct zsi_idxhdr *h,
                              zs_csum *csum)
{
    memset(buf, 0, ZSI_IDX_HEADER_LEN);

    memcpy(buf + ZSI_IDX_OFF_MAGIC, zsi_idx_magic, ZSI_IDX_MAGIC_LEN);
    buf[ZSI_IDX_OFF_VREAD]  = (char)h->version_read;
    buf[ZSI_IDX_OFF_VWRITE] = (char)h->version_write;
    zsi_put16(buf + ZSI_IDX_OFF_FLAGS, h->flags);
    /* RESERVED1 and RESERVED2 stay zero: written as zero, ignored on read.  The
     * memset above is what writes them. */
    memcpy(buf + ZSI_IDX_OFF_UUID, h->uuid, 16);
    zsi_put32(buf + ZSI_IDX_OFF_START, h->start);
    memcpy(buf + ZSI_IDX_OFF_COMPAR, h->compar_name, ZSI_COMPAR_NAME_LEN);
    zsi_put64(buf + ZSI_IDX_OFF_VALID_UPTO, h->valid_upto);
    zsi_put64(buf + ZSI_IDX_OFF_TERM_OFF, h->term_off);
    zsi_put64(buf + ZSI_IDX_OFF_NPTRS, h->nptrs);
    zsi_put64(buf + ZSI_IDX_OFF_TERM_CSUM, h->term_csum);

    /* Last 4 bytes, covering everything before them, exactly as F-4 has it for a
     * data file header.  No field-zeroing anywhere. */
    zsi_put64(buf + ZSI_IDX_OFF_CSUM, csum(buf, ZSI_IDX_OFF_CSUM));
}

/* Decode and validate the header ALONE.  The cross-checks against the data file
 * -- uuid, generation, comparator, offset ranges, the terminator binding --
 * belong to the loader, because they need the file. */
static int zsi_idxhdr_decode(const char *buf, size_t len, zs_csum *csum,
                             struct zsi_idxhdr *out)
{
    if (len < ZSI_IDX_HEADER_LEN) return ZS_BADFORMAT;

    if (memcmp(buf + ZSI_IDX_OFF_MAGIC, zsi_idx_magic, ZSI_IDX_MAGIC_LEN) != 0)
        return ZS_BADFORMAT;

    if (zsi_get64(buf + ZSI_IDX_OFF_CSUM) != csum(buf, ZSI_IDX_OFF_CSUM))
        return ZS_BADCHECKSUM;

    uint8_t vread = (uint8_t)buf[ZSI_IDX_OFF_VREAD];
    if (vread > ZSI_IDX_VERSION_READ) return ZS_BADFORMAT;

    out->version_read  = vread;
    out->version_write = (uint8_t)buf[ZSI_IDX_OFF_VWRITE];
    out->flags         = zsi_get16(buf + ZSI_IDX_OFF_FLAGS);
    memcpy(out->uuid, buf + ZSI_IDX_OFF_UUID, 16);
    out->start         = zsi_get32(buf + ZSI_IDX_OFF_START);
    memcpy(out->compar_name, buf + ZSI_IDX_OFF_COMPAR, ZSI_COMPAR_NAME_LEN);
    out->valid_upto    = zsi_get64(buf + ZSI_IDX_OFF_VALID_UPTO);
    out->term_off      = zsi_get64(buf + ZSI_IDX_OFF_TERM_OFF);
    out->nptrs         = zsi_get64(buf + ZSI_IDX_OFF_NPTRS);
    out->term_csum     = zsi_get64(buf + ZSI_IDX_OFF_TERM_CSUM);

    /* F-9 again: generations start at 1, so a start of 0 is never legitimate. */
    if (out->start == 0) return ZS_BADFORMAT;

    return ZS_OK;
}

/* The engine id, read as plain data before any verification -- exactly as
 * zsi_header_engine_id does, and for the same reason (F-5a): the checksum cannot
 * be verified until the engine is known, and the engine is recorded inside the
 * header the checksum protects.  A wrong value yields a failed checksum, not a
 * wrong interpretation.
 *
 * Requires len >= ZSI_IDX_HEADER_LEN; the caller checks that first. */
static unsigned zsi_idxhdr_engine_id(const char *buf)
{
    return (unsigned)(zsi_get16(buf + ZSI_IDX_OFF_FLAGS) & ZSI_CSUM_MASK);
}

/* P-3.  The `zeroskip.` prefix is the metadata namespace (D-2), so a table can
 * never be parsed as a data file even if someone points a cache directory at a
 * database.  The uuid and generation forms are D-0's and D-1's, so a table's
 * name reads naturally beside the file it describes. */
#define ZSI_IDX_NAME_PREFIX "zeroskip.index-"

static void zsi_name_format_index(char *out, const zsi_uuid_t uuid,
                                  uint32_t gen)
{
    char ustr[ZSI_UUID_STR_LEN];
    zsi_uuid_unparse(uuid, ustr);

    snprintf(out, ZSI_NAME_MAX, "%s%s-%08X", ZSI_IDX_NAME_PREFIX, ustr, gen);
}

/* Where a handle's tables live, and how far past the last one it lets the file
 * grow before publishing another (P-13).  dir NULL disables the cache.
 *
 * dir is the RESOLVED per-database directory -- <root>/<uuid> for a configured
 * root (P-2a), or <dbdir>/zeroskip.cache under ZS_INDEX_LOCAL (P-2b) --
 * resolved once at open, so publish, load, sweep and dump all take it as
 * given.  `local` marks the P-2b case, whose sweep may also remove
 * foreign-uuid tables: the directory serves exactly one database, so a table
 * carrying any other uuid there is garbage by construction. */
struct zsi_idxcfg {
    const char *dir;
    size_t      threshold;
    bool        local;
};

/* Load and fully validate the pointer table for this file (P-11).
 *
 * EVERY failure is ZS_NOTFOUND: a missing file, a short read, an allocation
 * failure, a rule violation.  That uniformity is the point, not laziness.  A
 * table is an optimisation living outside the database, and the only correct
 * response to any doubt about one is to ignore it and replay.  Returning an
 * error instead would let a corrupt file in a directory the database does not
 * depend on turn a readable database into an unreadable one, which is precisely
 * what P-11 forbids and what G-3 is about.
 *
 * On ZS_OK, *base is an owned array of *nbase offsets in key order. */
static int zsi_idx_load(struct zsi_file *f, const struct zsi_idxcfg *cfg,
                        const char *compar_name,
                        size_t **base, size_t *nbase, size_t *valid_upto,
                        size_t *term_off, uint64_t *term_csum)
{
    char name[ZSI_NAME_MAX], path[PATH_MAX];
    struct zsi_idxhdr h;
    struct stat sb;
    char *buf = NULL;
    size_t len, want, arrlen;
    size_t *offs = NULL;
    int fd = -1, rc = ZS_NOTFOUND;

    *base = NULL;
    *nbase = 0;
    *valid_upto = ZSI_HEADER_LEN;
    *term_off = ZSI_HEADER_LEN;
    *term_csum = 0;

    if (!cfg || !cfg->dir) return ZS_NOTFOUND;

    /* D-10: a file with an invalid header has no records to index and no
     * generation we would trust a table against. */
    if (!f->hdr_valid || !f->csum) return ZS_NOTFOUND;

    zsi_name_format_index(name, f->hdr.uuid, f->hdr.start);
    if ((size_t)snprintf(path, sizeof(path), "%s/%s", cfg->dir, name)
        >= sizeof(path))
        return ZS_NOTFOUND;

    fd = open(path, O_RDONLY);
    if (fd < 0) return ZS_NOTFOUND;
    if (fstat(fd, &sb) < 0 || !S_ISREG(sb.st_mode)) goto out;

    len = (size_t)sb.st_size;
    if (len < ZSI_IDX_HEADER_LEN + 8) goto out;
    if (len > ZSI_IDX_MAX_BYTES) goto out;

    buf = malloc(len);
    if (!buf) goto out;
    if (read(fd, buf, len) != (ssize_t)len) goto out;

    /* P-7: the engine is the DATA FILE's, never ours.  Resolving it from the
     * file and then REQUIRING the table to agree is what closes the hole F-5a
     * closes for data files -- otherwise a table could name an engine the file
     * does not use and still validate under it. */
    if (zsi_idxhdr_engine_id(buf) != f->csum_id) goto out;
    if (zsi_idxhdr_decode(buf, len, f->csum, &h) != ZS_OK) goto out;

    if (memcmp(h.uuid, f->hdr.uuid, 16) != 0) goto out;
    if (h.start != f->hdr.start) goto out;

    /* Both comparator names: the file's, because a table sorted under a
     * different order is meaningless against it, and OUR OWN, because a handle
     * may legitimately open a file whose recorded comparator it does not
     * implement. */
    if (memcmp(h.compar_name, f->hdr.compar_name, ZSI_COMPAR_NAME_LEN) != 0)
        goto out;
    if (memcmp(h.compar_name, compar_name, ZSI_COMPAR_NAME_LEN) != 0) goto out;

    /* A conforming builder always verifies spans at indexing (F-5e), so a
     * table without bit 4 indexed spans nobody verified, and accepting it
     * would seed OUR index with them -- for every reader, NOCSUM included,
     * since NOCSUM stops at record checksums. */
    if (!(h.flags & ZSI_IDX_FLAG_CSUM_VERIFIED)) goto out;

    /* Exact size, so a truncated or padded table is rejected rather than read
     * short.  The division guards the multiply. */
    if (h.nptrs > (ZSI_IDX_MAX_BYTES - ZSI_IDX_HEADER_LEN - 8) / 8) goto out;
    arrlen = (size_t)h.nptrs * 8;
    if (!zsi_add_sz(arrlen, ZSI_IDX_HEADER_LEN + 8, &want)) goto out;
    if (want != len) goto out;

    if (zsi_get64(buf + len - 8)
        != f->csum(buf + ZSI_IDX_HEADER_LEN, arrlen))
        goto out;

    if (h.valid_upto < ZSI_HEADER_LEN || h.valid_upto > f->size) goto out;

    /* P-10's binding, in O(1).  The table names the terminator's offset because
     * terminators are only ever found by scanning forward (F-20): a reader given
     * valid_upto alone could not locate it without the replay this whole
     * mechanism exists to avoid.
     *
     * What this catches is a data file whose covered prefix is not the one the
     * table was built over -- which the format itself cannot produce, since
     * files are append-only and generations are never reissued (D-9b), so it is
     * there for out-of-band events such as a restore from backup under a
     * surviving cache directory.  It examines one span, so P-17 states the
     * limit plainly rather than implying more. */
    if (h.valid_upto == ZSI_HEADER_LEN) {
        if (h.term_off != ZSI_HEADER_LEN || h.term_csum != 0 || h.nptrs != 0)
            goto out;
    } else {
        struct zsi_term term;
        const char *tb;
        size_t after;

        if (h.term_off < ZSI_HEADER_LEN || h.term_off >= h.valid_upto) goto out;
        tb = zsi_file_at(f, (size_t)h.term_off, 1);
        if (!tb) goto out;
        if (zsi_term_decode(tb, f->size - (size_t)h.term_off, &term) != ZS_OK)
            goto out;
        if (!zsi_add_sz((size_t)h.term_off, term.len, &after)) goto out;
        if (after != (size_t)h.valid_upto) goto out;
        if (term.csum != h.term_csum) goto out;
    }

    offs = malloc(h.nptrs ? (size_t)h.nptrs * sizeof(*offs) : 1);
    if (!offs) goto out;

    for (uint64_t i = 0; i < h.nptrs; i++) {
        uint64_t v = zsi_get64(buf + ZSI_IDX_HEADER_LEN + i * 8);

        /* Every offset must address a record inside the covered prefix.  This
         * is O(n) over the array but touches no data-file page, so it costs
         * nothing the cache is trying to save.
         *
         * It deliberately does NOT verify that the offsets are in key order:
         * that needs a record decode per entry, which is exactly the work being
         * avoided, and the array checksum already stands behind the ordering. */
        if (v < ZSI_HEADER_LEN || v >= h.valid_upto) goto out;
        if (v > (uint64_t)SIZE_MAX) goto out;
        offs[i] = (size_t)v;
    }

    *base = offs;
    *nbase = (size_t)h.nptrs;
    *valid_upto = (size_t)h.valid_upto;
    *term_off = (size_t)h.term_off;
    *term_csum = h.term_csum;
    offs = NULL;
    rc = ZS_OK;

out:
    free(offs);
    free(buf);
    if (fd >= 0) close(fd);
    return rc;
}

/* Build the private index, seeded from a table if one is usable (P-12). */
static int zsi_index_build_cached(struct zsi_file *f, zs_compar *compar,
                                  const char *compar_name,
                                  const struct zsi_idxcfg *cfg)
{
    size_t *base = NULL, nbase = 0;
    size_t vu = ZSI_HEADER_LEN, to = ZSI_HEADER_LEN;
    uint64_t tc = 0;
    int r;

    if (zsi_idx_load(f, cfg, compar_name,
                     &base, &nbase, &vu, &to, &tc) != ZS_OK)
        return zsi_index_build(f, compar);

    f->cached_upto = vu;
    r = zsi_index_build_from(f, compar, base, nbase, vu);
    if (r != ZS_OK) return r;

    /* A replay that found no new span leaves last_term_* at the values it
     * started with, so seed them from the table.  Without this, publishing after
     * a no-op catch-up would record a terminator that is not the one at the
     * complete point, and every later reader would reject the result. */
    if (f->complete == vu) {
        f->last_term_off  = to;
        f->last_term_csum = tc;
    }

    return ZS_OK;
}

/* Publish a table covering this file's complete point (P-4, P-13).
 *
 * ZS_DONE means the threshold was not reached and nothing was written, which is
 * the common case and not a failure.  Any other non-OK is a real problem with
 * the cache directory, and the caller is REQUIRED to swallow it (P-15): the data
 * is already durable, and failing an operation over a rebuildable cache would be
 * a regression rather than a safety measure.
 *
 * There is deliberately NO fsync (P-14).  A table is rebuildable, a torn or
 * zero-filled file after a crash is rejected by P-11's checksums, and syncing
 * would put a third sync on a commit path C-7 defines as exactly two -- which is
 * the cost this whole mechanism exists to reduce. */
static int zsi_idx_publish(struct zsi_file *f, const struct zsi_idxcfg *cfg,
                           zs_compar *compar)
{
    char name[ZSI_NAME_MAX], path[PATH_MAX], tmp[PATH_MAX];
    unsigned char rnd[4];
    struct zsi_idxhdr h;
    char hdr[ZSI_IDX_HEADER_LEN], csbuf[8];
    size_t *offs = NULL, n = 0, arrlen;
    char *arr = NULL;
    int fd = -1, rc = ZS_INTERNAL;

    if (!cfg || !cfg->dir) return ZS_DONE;
    if (!f->hdr_valid || !f->csum || !f->index) return ZS_DONE;
    if (!zsi_file_is_unordered(f)) return ZS_DONE;          /* P-1 */

    /* P-13.  cached_upto is the valid_upto of the table this index was seeded
     * from, or the header length if none was.  Publishing below the threshold is
     * what would make a bulk load quadratic: a table is rewritten whole, so one
     * publication per commit costs O(records in the file) of I/O per commit. */
    if (f->complete < f->cached_upto) return ZS_DONE;
    {
        /* A zero threshold means DERIVE it from this file (A-9), which is the
         * default and cannot be resolved at open: the quantity it scales with is
         * the file's own size, and that changes as the file grows. */
        size_t threshold = cfg->threshold;
        if (!threshold) {
            threshold = f->complete / ZSI_INDEX_PUBLISHES_PER_GEN;
            if (threshold < ZSI_INDEX_MIN_THRESHOLD)
                threshold = ZSI_INDEX_MIN_THRESHOLD;
        }
        if (f->complete - f->cached_upto < threshold) return ZS_DONE;
    }

    if (zsi_index_flatten(f->index, compar, &offs, &n) != ZS_OK)
        return ZS_INTERNAL;

    if (n > (ZSI_IDX_MAX_BYTES - ZSI_IDX_HEADER_LEN - 8) / 8) goto out;
    arrlen = n * 8;

    arr = malloc(arrlen ? arrlen : 1);
    if (!arr) goto out;
    for (size_t i = 0; i < n; i++)
        zsi_put64(arr + i * 8, (uint64_t)offs[i]);

    memset(&h, 0, sizeof(h));
    h.version_read  = ZSI_IDX_VERSION_READ;
    h.version_write = ZSI_IDX_VERSION_WRITE;
    /* P-7: the FILE's engine, never the handle's.  Using the handle's would
     * produce tables a conforming peer must reject -- the same silent failure
     * that using the handle's engine to append to an existing file causes
     * (A-6, F-5a). */
    h.flags = (uint16_t)(f->csum_id & ZSI_CSUM_MASK);
    /* Always: the replay that built this index verified its spans (F-5e). */
    h.flags |= ZSI_IDX_FLAG_CSUM_VERIFIED;
    memcpy(h.uuid, f->hdr.uuid, 16);
    h.start = f->hdr.start;
    memcpy(h.compar_name, f->hdr.compar_name, ZSI_COMPAR_NAME_LEN);
    h.valid_upto = (uint64_t)f->complete;
    h.term_off   = (uint64_t)f->last_term_off;
    h.nptrs      = (uint64_t)n;
    h.term_csum  = f->last_term_csum;

    zsi_idxhdr_encode(hdr, &h, f->csum);

    if (!zsi_random_bytes(rnd, sizeof(rnd))) {
        uint64_t e = zsi_weak_entropy();
        memcpy(rnd, &e, sizeof(rnd));
    }

    /* Random digits as well as the pid: two processes sharing a cache directory
     * across a network filesystem can have the same pid, and two of them writing
     * one staging name would interleave into a file that is then renamed into
     * place.  P-11 would reject the result, but at the cost of both processes'
     * work and with nothing to explain why. */
    if ((size_t)snprintf(tmp, sizeof(tmp), "%s/%s%d.%02x%02x%02x%02x",
                         cfg->dir, ZSI_STAGING_PREFIX, (int)getpid(),
                         rnd[0], rnd[1], rnd[2], rnd[3]) >= sizeof(tmp))
        goto out;

    zsi_name_format_index(name, f->hdr.uuid, f->hdr.start);
    if ((size_t)snprintf(path, sizeof(path), "%s/%s", cfg->dir, name)
        >= sizeof(path))
        goto out;

    fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) { rc = ZS_IOERROR; goto out; }

    rc = ZS_IOERROR;
    if (ZS_WRITE(fd, hdr, sizeof(hdr)) != (ssize_t)sizeof(hdr)) goto out_unlink;
    if (arrlen && ZS_WRITE(fd, arr, arrlen) != (ssize_t)arrlen) goto out_unlink;

    /* Note the empty case: f->csum(arr, 0) must be the ENGINE's value for empty
     * input, not zero.  zsi_csum_xxhash has no empty short-circuit for exactly
     * this reason (F-26g), so passing a zero length here is correct. */
    zsi_put64(csbuf, f->csum(arr, arrlen));
    if (ZS_WRITE(fd, csbuf, 8) != 8) goto out_unlink;

    if (close(fd) < 0) { fd = -1; goto out_unlink; }
    fd = -1;

    if (ZS_RENAME(tmp, path) < 0) goto out_unlink;

    /* D-9d: the window moves with its base.  A reader seeded from the table
     * just published replays nothing, so the spans it covers stop counting
     * toward the bound -- which is why a configured cache makes this condition
     * quiet rather than making it fire on a file's lifetime total. */
    f->cached_upto = f->complete;
    f->nspans = 0;
    rc = ZS_OK;
    goto out;

out_unlink:
    if (fd >= 0) { close(fd); fd = -1; }
    ZS_UNLINK(tmp);

out:
    if (fd >= 0) close(fd);
    free(arr);
    free(offs);
    return rc;
}

/* P-16.  Unlink tables for this database whose generation is no longer an
 * unordered file.
 *
 * Takes the live generations as a plain array rather than a struct zsi_fileset,
 * because FILE SET is defined below this section and the layering runs one way.
 *
 * Safe against a concurrent reader: a descriptor already open survives the
 * unlink, and a reader that misses a table replays instead.  Every error is
 * ignored, because a sweep that cannot run costs disk space, not correctness. */
static void zsi_idx_sweep(const struct zsi_idxcfg *cfg, const zsi_uuid_t uuid,
                          const uint32_t *live, size_t nlive)
{
    char want[ZSI_UUID_STR_LEN];
    size_t plen = strlen(ZSI_IDX_NAME_PREFIX);
    struct dirent *de;
    DIR *d;

    if (!cfg || !cfg->dir) return;

    zsi_uuid_unparse(uuid, want);

    d = opendir(cfg->dir);
    if (!d) return;

    while ((de = readdir(d))) {
        const char *nm = de->d_name;
        char path[PATH_MAX];
        uint32_t gen;
        bool alive = false;

        if (strncmp(nm, ZSI_IDX_NAME_PREFIX, plen) != 0) continue;
        nm += plen;

        /* Another database's tables are not ours to remove -- except inside
         * zeroskip.cache (P-2b), which serves exactly one database, where a
         * foreign uuid is garbage by construction. */
        if (!cfg->local && strncmp(nm, want, 36) != 0) continue;
        nm += 36;
        if (*nm != '-') continue;
        nm++;

        if (zsi_parse_gen8(nm, &gen) != 8) continue;
        if (nm[8] != '\0') continue;

        for (size_t i = 0; i < nlive; i++)
            if (live[i] == gen) { alive = true; break; }
        if (alive) continue;

        if ((size_t)snprintf(path, sizeof(path), "%s/%s", cfg->dir, de->d_name)
            < sizeof(path))
            ZS_UNLINK(path);
    }

    closedir(d);
}

/********** PER-FILE CURSOR *************/

/* One cursor over one source, presenting the same four operations whatever the
 * source is.  This is what lets the read path (D-14, D-14e) be written once
 * rather than per file kind -- the merge does not know or care which kind it is
 * pulling from.
 *
 * Three kinds, matching D-14's table of sources:
 *
 *   ZSI_SRC_TXN        the current write transaction's uncommitted records
 *   ZSI_SRC_UNORDERED  an unordered file, via its private index (D-13)
 *   ZSI_SRC_INORDER    an in-order file, via its pointer array
 *
 * D-14h: a per-file cursor never yields the same key twice.  An in-order file
 * holds one record per key by construction (D-17), and a private index exposes
 * only the newest committed record per key (D-13a).  Duplicates therefore arise
 * only ACROSS sources, which is exactly what the merge's step 3 handles. */

enum zsi_src_kind { ZSI_SRC_INORDER, ZSI_SRC_UNORDERED, ZSI_SRC_TXN };

/* The transaction's records sort as though they had a generation above every
 * file's, giving them highest priority for equal keys without a special case in
 * the merge comparator (D-14g). */
#define ZSI_GEN_TXN UINT32_MAX

struct zsi_fcur {
    enum zsi_src_kind kind;
    struct zsi_file  *file;      /* NULL for ZSI_SRC_TXN */
    struct zs_txn    *txn;       /* NULL otherwise */
    zs_compar        *compar;
    uint32_t          gen;       /* file->hdr.start, or ZSI_GEN_TXN */
    bool              exhausted;

    /* D-14k: travel toward smaller keys.  Fixed when the owning cursor is
     * opened.  Reverse positions are COUNTS -- the in-order candidate is
     * pi-1, the index cursor's are bi-1/di-1, and 0 is exhausted -- so no
     * unsigned position ever underflows. */
    bool              reverse;

    /* A-4b: this source may answer out of the writer's chunk buffer rather than
     * forcing it to the file first, because whoever asked accepts a pointer
     * that dies at their next call.  Only ever set on a ZSI_SRC_TXN source --
     * nothing else has a buffer -- and only by a fetch: zsi_lookup's own stack
     * cursor, or the throwaway one ZS_FETCHNEXT/ZS_FETCHPREV open and free
     * within the call.  A cursor the CALLER holds must never set it, which is
     * why ZS_EPHEMERAL is rejected at the public cursor and foreach forms
     * rather than merely ignored there. */
    bool              ephemeral;
    struct zsi_rec    cur;       /* valid iff !exhausted */

    /* The position, which is kind-specific -- and a UNION, because `kind`
     * already says which half is live and no arm has ever needed both.
     *
     * Worth the awkwardness of the extra name because struct zsi_fcur is what
     * the merge loop walks: c->cur is an array of these, and the loop touches
     * arm 0 and arm 1 for every record yielded.  Laid out flat, the file half
     * (24 bytes) and the transaction half (56) both cost every arm, and the
     * transaction half is dead weight in a file arm -- never read, but still
     * pushing the next arm further away.  Unioned they cost max() rather than
     * sum(), which is 24 bytes off every arm. */
    union {
        struct {                        /* ZSI_SRC_INORDER / ZSI_SRC_UNORDERED */
            uint64_t             pi;    /* in-order: pointer array index */
            struct zsi_index_cur ic;    /* unordered: index cursor */
        } f;

        struct {
            /* txn: the NODE reached, and nothing else.
             *
             * A skiplist node never moves and is freed only when the
             * transaction ends, so a position is a pointer: a step is
             * node->next[0], a reverse step is node->prev, and a write during
             * the traversal cannot invalidate either.
             *
             * This was six fields and a binary search per step.  With the
             * pending set as a sorted ARRAY, an index stopped referring to its
             * record the moment an insert shifted the array (D-14j-a), so the
             * position had to be the KEY, re-resolved on every load, with the
             * resolved index cached beside it behind two guards -- both of
             * which were unreachable through a cursor, since any write bumps
             * pend_seq and the resulting refresh cleared the other.  The
             * skiplist deletes the problem rather than the guards.
             *
             * What survives is at the CURSOR level, where it always belonged:
             * a refresh re-seeks this arm from the cursor's resume key
             * (D-14j-b, zsi_cursor_reseek_arm), because a write may land
             * between the last key yielded and wherever this arm is sitting --
             * the arm reads one record AHEAD of what the caller has seen. */
            size_t node;         /* an ARENA OFFSET; 0 is "exhausted" */
        } t;
    } u;
};

/* Filled in by the WRITE PATH section, which owns struct zs_txn.  Declared here
 * because the cursor must be able to present a transaction as just another
 * source; the alternative is a special case in the merge, which D-14g exists to
 * avoid. */
static int zsi_txn_cur_load(struct zsi_fcur *fc);
static bool zsi_txn_cur_cmp(struct zsi_fcur *fc, const char *key, size_t keylen,
                            int *cmp);
static void zsi_txn_cur_seek(struct zsi_fcur *fc, const char *key, size_t keylen);
static void zsi_txn_cur_step(struct zsi_fcur *fc);
static void zsi_txn_cur_seek_rev(struct zsi_fcur *fc, const char *key,
                                 size_t keylen, bool inclusive);

/* struct zs_txn belongs to WRITE PATH, below, so the cursor reaches it through
 * these rather than through its fields -- the same arrangement the two above
 * already use, and the reason the merge needs no special case for a
 * transaction (D-14g). */
struct zsi_snapshot;    /* SNAPSHOT, below */
static unsigned long zsi_txn_seq(struct zs_txn *txn);
static void zsi_txn_set_snapshot(struct zs_txn *txn, struct zsi_snapshot *snap);

/* Load the record at the cursor's current position, or mark it exhausted. */
static int zsi_fcur_load(struct zsi_fcur *fc)
{
    switch (fc->kind) {
    case ZSI_SRC_INORDER: {
        uint64_t at = fc->u.f.pi;
        if (fc->reverse) {
            if (fc->u.f.pi == 0) { fc->exhausted = true; return ZS_OK; }
            at = fc->u.f.pi - 1;
        } else if (fc->u.f.pi >= fc->file->nptrs) {
            fc->exhausted = true;
            return ZS_OK;
        }
        if (zsi_ptrs_rec(fc->file, at, &fc->cur) != ZS_OK) {
            fc->exhausted = true;
            return ZS_BADFORMAT;
        }
        fc->exhausted = false;
        return ZS_OK;
    }

    case ZSI_SRC_UNORDERED: {
        /* No index means the caller skipped building one, which is a wiring
         * error rather than a data condition.  Report an exhausted source rather
         * than dereferencing NULL: G-3 requires that no state produce a crash,
         * and a cursor over a source with nothing in it is a defined answer. */
        if (!fc->file->index) { fc->exhausted = true; return ZS_OK; }

        int r = fc->reverse
              ? zsi_index_cur_get_rev(fc->file->index, fc->compar, &fc->u.f.ic,
                                      &fc->cur, NULL)
              : zsi_index_cur_get(fc->file->index, fc->compar, &fc->u.f.ic,
                                  &fc->cur, NULL);
        fc->exhausted = (r != ZS_OK);
        return ZS_OK;
    }

    case ZSI_SRC_TXN:
        return zsi_txn_cur_load(fc);
    }

    fc->exhausted = true;
    return ZS_OK;
}

/* Position at the first record with key >= the given key, or exhaust.
 *
 * A source holding no records exhausts immediately -- an empty in-order file
 * (F-26g) or an unordered file with no committed records (F-26h) are ordinary
 * cases here, not special ones (D-14e step 1). */
static int zsi_fcur_seek(struct zsi_fcur *fc, const char *key, size_t keylen)
{
    switch (fc->kind) {
    case ZSI_SRC_INORDER: {
        uint64_t idx;
        bool exact;
        int r = zsi_ptrs_search(fc->file, fc->compar, key, keylen, &idx, &exact);
        if (r != ZS_OK) { fc->exhausted = true; return r; }
        fc->u.f.pi = idx;
        break;
    }

    case ZSI_SRC_UNORDERED:
        if (!fc->file->index) { fc->exhausted = true; return ZS_OK; }
        zsi_index_cur_seek(fc->file->index, fc->compar, key, keylen, &fc->u.f.ic);
        break;

    case ZSI_SRC_TXN:
        zsi_txn_cur_seek(fc, key, keylen);
        break;
    }

    return zsi_fcur_load(fc);
}

static int zsi_fcur_seek_first(struct zsi_fcur *fc)
{
    switch (fc->kind) {
    case ZSI_SRC_INORDER:   fc->u.f.pi = 0; break;
    case ZSI_SRC_UNORDERED: zsi_index_cur_seek_first(&fc->u.f.ic); break;
    case ZSI_SRC_TXN:
        zsi_txn_cur_seek(fc, NULL, 0);             /* the head */
        break;
    }

    return zsi_fcur_load(fc);
}

/* D-14k step 1: position on the largest key <= (inclusive) or < (exclusive)
 * the given key, or exhaust when nothing lies below the bound. */
static int zsi_fcur_seek_rev(struct zsi_fcur *fc, const char *key,
                             size_t keylen, bool inclusive)
{
    switch (fc->kind) {
    case ZSI_SRC_INORDER: {
        uint64_t idx;
        bool exact;
        int r = zsi_ptrs_search(fc->file, fc->compar, key, keylen, &idx, &exact);
        if (r != ZS_OK) { fc->exhausted = true; return r; }
        /* idx counts the pointers strictly below the key -- the exclusive
         * reverse position; inclusive keeps an exact match. */
        fc->u.f.pi = idx + ((inclusive && exact) ? 1 : 0);
        break;
    }

    case ZSI_SRC_UNORDERED:
        if (!fc->file->index) { fc->exhausted = true; return ZS_OK; }
        zsi_index_cur_seek_rev(fc->file->index, fc->compar, key, keylen,
                               inclusive, &fc->u.f.ic);
        break;

    case ZSI_SRC_TXN:
        zsi_txn_cur_seek_rev(fc, key, keylen, inclusive);
        break;
    }

    return zsi_fcur_load(fc);
}

/* D-14k's empty start: the last key each source holds. */
static int zsi_fcur_seek_last(struct zsi_fcur *fc)
{
    switch (fc->kind) {
    case ZSI_SRC_INORDER:
        fc->u.f.pi = fc->file->nptrs;
        break;
    case ZSI_SRC_UNORDERED:
        if (!fc->file->index) { fc->exhausted = true; return ZS_OK; }
        zsi_index_cur_seek_last(fc->file->index, &fc->u.f.ic);
        break;
    case ZSI_SRC_TXN:
        zsi_txn_cur_seek_rev(fc, NULL, 0, true);   /* the tail (D-14k) */
        break;
    }

    return zsi_fcur_load(fc);
}

/* Advance one step IN THE CURSOR'S DIRECTION -- the merge above never knows
 * which way an arm travels (D-14k). */
static int zsi_fcur_next(struct zsi_fcur *fc)
{
    if (fc->exhausted) return ZS_OK;

    switch (fc->kind) {
    case ZSI_SRC_INORDER:
        if (fc->reverse) fc->u.f.pi--;
        else             fc->u.f.pi++;
        break;
    case ZSI_SRC_UNORDERED:
        if (!fc->file->index) { fc->exhausted = true; return ZS_OK; }
        if (fc->reverse)
            zsi_index_cur_prev(fc->file->index, fc->compar, &fc->u.f.ic);
        else
            zsi_index_cur_next(fc->file->index, fc->compar, &fc->u.f.ic);
        break;
    case ZSI_SRC_TXN:
        /* One link.  The node cannot have moved -- see struct zsi_fcur -- so
         * there is nothing to re-resolve, and a write landing between the last
         * key yielded and this position is caught by the cursor's refresh
         * re-seeking the arm (D-14j-b), not by the arm second-guessing itself. */
        zsi_txn_cur_step(fc);
        break;
    }

    return zsi_fcur_load(fc);
}

/* Search one source for a single key, independently of any cursor state (D-14b).
 *
 * in-order   binary search the pointer array          O(log n) comparisons
 * unordered  point lookup in the private index        as that structure provides
 * txn        binary search its sorted pending array
 *
 * Both file kinds MUST report "absent" for an empty source rather than
 * misbehaving: a binary search over a zero-length array and an index for a file
 * with no committed records are both ordinary cases. */
/* Release anything a per-file cursor owns -- which, since the transaction arm's
 * position key became a borrow, is NOTHING.  Both of its pointers are into
 * storage that outlives the arm: the pending array's own key blocks, or a key
 * the caller of a seek holds.
 *
 * Kept, and kept called from all six sites, because "the arm owns nothing" is a
 * property of the arm's fields rather than of this function -- the moment one
 * of them grows an allocation again, the cleanup has somewhere to go and every
 * site already reaches it.  The history is why: the transaction arm's key copy
 * leaked out of the stack arms zsi_lookup builds until `make leaks` found it,
 * and it leaked again out of zsi_fcur_find's scratch copy right after. */
static void zsi_fcur_fini(struct zsi_fcur *fc)
{
    (void)fc;
}

static int zsi_fcur_find(struct zsi_fcur *fc, const char *key, size_t keylen,
                         struct zsi_rec *out)
{
    switch (fc->kind) {
    case ZSI_SRC_INORDER: {
        uint64_t idx;
        bool exact;
        int r = zsi_ptrs_search(fc->file, fc->compar, key, keylen, &idx, &exact);
        if (r != ZS_OK) return r;
        if (!exact) return ZS_NOTFOUND;
        return zsi_ptrs_rec(fc->file, idx, out);
    }

    case ZSI_SRC_UNORDERED: {
        size_t off;
        if (!fc->file->index) return ZS_NOTFOUND;
        int r = zsi_index_find(fc->file->index, fc->compar, key, keylen, &off);
        if (r != ZS_OK) return r;
        const char *b = zsi_file_at(fc->file, off, 1);
        if (!b) return ZS_BADFORMAT;
        return zsi_rec_decode(b, fc->file->size - off, out);
    }

    case ZSI_SRC_TXN: {
        /* Seek a scratch cursor and check for an exact hit, so the transaction's
         * lookup shares the ordering logic rather than duplicating it.
         *
         * The scratch is a COPY.  If an arm ever owns an allocation again, the
         * copy owns one too and it must be released on every exit from here.
         *
         * The match is tested against the pending set's own inlined key prefix,
         * and the record is decoded only once it is going to be returned.
         * Loading first and comparing the decoded key would make a MISS cost a
         * write(2): the seek lands on the neighbouring pending record,
         * materialising it flushes the writer's chunk (zsi_txn_at), and the
         * record is then discarded as not equal -- and a caller probing for
         * keys it is about to insert misses every time.  ZS_EPHEMERAL (A-4b)
         * covers the other half, where the read HITS and the bytes are
         * wanted. */
        struct zsi_fcur scratch = *fc;
        int cmp = 0;
        int r = ZS_NOTFOUND;

        zsi_txn_cur_seek(&scratch, key, keylen);

        if (zsi_txn_cur_cmp(&scratch, key, keylen, &cmp) && cmp == 0) {
            r = zsi_fcur_load(&scratch);
            if (r == ZS_OK) {
                if (scratch.exhausted) r = ZS_NOTFOUND;
                else *out = scratch.cur;
            }
        }

        zsi_fcur_fini(&scratch);
        return r;
    }
    }

    return ZS_NOTFOUND;
}

/* Initialise a cursor over a file.  The caller has already built the index for
 * an unordered file and loaded the pointers for an in-order one. */
static void zsi_fcur_init_file(struct zsi_fcur *fc, struct zsi_file *f,
                               zs_compar *compar)
{
    memset(fc, 0, sizeof(*fc));
    fc->kind = zsi_file_is_unordered(f) ? ZSI_SRC_UNORDERED : ZSI_SRC_INORDER;
    fc->file = f;
    fc->compar = compar;
    fc->gen = f->hdr.start;
    fc->exhausted = true;
}

/********** FILE SET *************/

/* There is no manifest.  THE DIRECTORY IS THE FILE SET (section 5.2).
 *
 * Filenames carry each file's generation range (D-1), so one readdir yields the
 * set and every range without opening a single file.  That is not a shortcut: it
 * is what makes creating a file identical to publishing it (D-8), so there is no
 * window in which a generation has been allocated but is invisible. */

struct zsi_entry {
    char     name[ZSI_NAME_MAX];
    uint32_t start, end;        /* end == 0 for unordered */
};

struct zsi_fileset {
    struct zsi_entry *all;      size_t nall;       /* every matching name */
    struct zsi_entry *resolved; size_t nresolved;  /* D-5's winners, ascending */
    zsi_uuid_t uuid;
    bool       have_uuid;
};

static void zsi_fileset_fini(struct zsi_fileset *fs)
{
    free(fs->all);
    free(fs->resolved);
    memset(fs, 0, sizeof(*fs));
}

/* readdir the directory, keeping the data files of one database (D-4).
 *
 * If want_uuid is NULL the UUID is DISCOVERED: parse it from each zeroskip-*
 * name and require they all agree (D-4a).  Disagreement is an error, never a
 * choice of majority -- silently adopting one would read half a database and
 * call it whole.  A directory with no data files leaves have_uuid false, which is
 * the empty case D-8a handles. */
/* The scan body, over an already-open directory stream.  rewinddir makes the
 * stream reflect the directory's CURRENT state -- POSIX specifies it as
 * equivalent to a fresh opendir -- which is what lets the C-4i probe hold one
 * stream open for the handle's lifetime instead of paying opendir/closedir
 * per begin: at one probe per operation, the opendir was the single largest
 * cost of a small read or write, measured at ~2/3 of a cached fetch. */
static int zsi_fileset_scan_dh(DIR *d, const zsi_uuid_t *want_uuid,
                               struct zsi_fileset *fs)
{
    struct dirent *de;
    size_t alloc = 0;

    memset(fs, 0, sizeof(*fs));
    rewinddir(d);

    if (want_uuid) {
        memcpy(fs->uuid, *want_uuid, 16);
        fs->have_uuid = true;
    }

    while ((de = readdir(d)) != NULL) {
        zsi_uuid_t u;
        uint32_t start, end;

        enum zsi_nametype t = zsi_name_parse(de->d_name, u, &start, &end);
        if (t == ZSI_NAME_OTHER) continue;      /* staging, lock, foreign, junk */

        if (!fs->have_uuid) {
            memcpy(fs->uuid, u, 16);
            fs->have_uuid = true;
        } else if (memcmp(fs->uuid, u, 16) != 0) {
            /* Two databases' files mixed into one directory.  If the caller named
             * a UUID this is simply someone else's file and we ignore it; if we
             * are discovering, it is corruption and must be reported. */
            if (want_uuid) continue;
            zsi_fileset_fini(fs);
            return ZS_BADFORMAT;
        }

        if (fs->nall == alloc) {
            size_t want = alloc ? alloc * 2 : 16;
            struct zsi_entry *p = realloc(fs->all, want * sizeof(*p));
            if (!p) { zsi_fileset_fini(fs); return ZS_INTERNAL; }
            fs->all = p;
            alloc = want;
        }

        /* The length is already bounded: zsi_name_parse returned a data-file
         * type above, which requires the name to be exactly
         * "zeroskip-" + 36 + "-" + 8 [+ "-" + 8] with nothing trailing -- 63
         * characters at most, against ZSI_NAME_MAX of 80.
         *
         * Copied with an EXPLICIT length rather than snprintf'd, because the
         * compiler cannot see that reasoning: `d_name` is NAME_MAX-sized, so
         * -Wformat-truncation flags the snprintf, and a consumer may build with
         * -Werror.  Suppressing the warning would leave the bound implicit;
         * this states it where it is relied on.  The check is unreachable for the same
         * reason it is here, in the manner of F-29's progress checks. */
        size_t nlen = strlen(de->d_name);
        if (nlen >= ZSI_NAME_MAX) continue;

        memcpy(fs->all[fs->nall].name, de->d_name, nlen + 1);
        fs->all[fs->nall].start = start;
        fs->all[fs->nall].end = end;
        fs->nall++;
    }

    /* Deliberately left in readdir order.  Every consumer that needs an order
     * imposes its own, on the entries rather than on the names -- D-5a's
     * zsi_entry_resolve_order for resolution, S-3's zsi_salvage_order for
     * salvage -- because since D-1b a name no longer determines where a file
     * belongs: the active file's carries no generation.  A lexical sort here
     * would produce an order that LOOKS meaningful and is wrong in the
     * conversion window (D-5b), which is exactly the reasoning to avoid
     * re-introducing. */
    return ZS_OK;
}

/* D-1b: the active file's generation is in its HEADER, not its name, so the
 * scan reads it.  One open and 72 bytes, and only when an active file is
 * present -- which is the trade D-1b makes: the name stops carrying the
 * generation so that C-4i's freshness probe can be a single stat.
 *
 * Inferring the generation instead -- "it must be one above the highest" --
 * is wrong in exactly the window that matters.  During a conversion the output
 * is renamed in before the input is removed (D-5), so for that moment the
 * active file is SUPERSEDED rather than new: its records have just been
 * published as an in-order file, and its real generation is the one that file
 * covers, not the next one.  Guessing puts it a generation too high, D-23a's
 * "same highest generation" check then refuses to remove it, and the writer
 * cannot create its replacement because the name is still taken.
 *
 * An invalid header means no discoverable generation and no recoverable
 * record, so the entry simply does not participate (D-10).
 *
 * ZS_OK filled it in, ZS_NOTFOUND means drop it (D-10), anything else fails
 * the scan. */
static int zsi_entry_fill_current(const char *dir, struct zsi_entry *e,
                                  zs_csum *external_csum)
{
    char path[PATH_MAX], buf[ZSI_HEADER_LEN];
    struct zsi_header h;
    ssize_t n;
    int fd;

    snprintf(path, sizeof(path), "%s/%s", dir, e->name);
    fd = open(path, O_RDONLY);
    if (fd < 0) {
        /* Vanished between readdir and here: a stale scan, not an error.  The
         * caller's retry (C-4b) rescans and converges. */
        return errno == ENOENT ? ZS_NOTFOUND : ZS_IOERROR;
    }

    n = read(fd, buf, sizeof(buf));
    close(fd);

    if (n != (ssize_t)sizeof(buf)) return ZS_NOTFOUND;             /* D-10 */

    /* Engine 2 with no function supplied is a CONFIGURATION error, not
     * corruption, and the two must not be conflated (A-6).  Dropping it as
     * unreadable would make an unverifiable database open as an empty one --
     * silently, and with the caller's mistake nowhere in sight. */
    unsigned id = zsi_header_engine_id(buf);
    if (id == ZSI_CSUM_EXTERNAL && !external_csum) return ZS_BADUSAGE;

    zs_csum *cs = zsi_csum_for_id(id, external_csum);
    if (!cs || zsi_header_decode(buf, sizeof(buf), cs, &h) != ZS_OK
            || h.start == 0)
        return ZS_NOTFOUND;                                        /* D-10 */

    e->start = h.start;
    return ZS_OK;
}

static int zsi_fileset_scan_csum(const char *dir, const zsi_uuid_t *want_uuid,
                                 zs_csum *external_csum,
                                 struct zsi_fileset *fs)
{
    DIR *d = opendir(dir);
    if (!d) {
        memset(fs, 0, sizeof(*fs));
        return (errno == ENOENT) ? ZS_NOTFOUND : ZS_IOERROR;
    }

    int r = zsi_fileset_scan_dh(d, want_uuid, fs);
    closedir(d);
    if (r != ZS_OK) return r;

    for (size_t i = 0; i < fs->nall; i++) {
        int fr;

        if (!(fs->all[i].end == 0 && fs->all[i].start == 0)) continue;

        fr = zsi_entry_fill_current(dir, &fs->all[i], external_csum);
        if (fr != ZS_OK && fr != ZS_NOTFOUND) {
            zsi_fileset_fini(fs);
            return fr;
        }
        if (fr == ZS_NOTFOUND) {
            memmove(&fs->all[i], &fs->all[i + 1],
                    (fs->nall - i - 1) * sizeof(fs->all[0]));
            fs->nall--;
        }
        break;                          /* there is only ever one (D-12a) */
    }

    return ZS_OK;
}

static int zsi_fileset_scan(const char *dir, const zsi_uuid_t *want_uuid,
                            struct zsi_fileset *fs)
{
    return zsi_fileset_scan_csum(dir, want_uuid, NULL, fs);
}

/* The scan WITHOUT D-1b's header read: the active file keeps start == 0 and is
 * kept even when its header does not validate.
 *
 * For salvage only, and for the same reason salvage does not share the read
 * path at all: §5's rules exist to refuse what cannot be trusted, and salvage
 * exists to read exactly that.  Dropping an unreadable active file (D-10) is
 * right for a database being opened and wrong for one being recovered -- it
 * would discard the file whose records salvage was called to rescue. */
static int zsi_fileset_scan_raw(const char *dir, const zsi_uuid_t *want_uuid,
                                struct zsi_fileset *fs)
{
    DIR *d = opendir(dir);
    if (!d) {
        memset(fs, 0, sizeof(*fs));
        return (errno == ENOENT) ? ZS_NOTFOUND : ZS_IOERROR;
    }

    int r = zsi_fileset_scan_dh(d, want_uuid, fs);
    closedir(d);
    return r;
}

/* D-5's single sweep over the sorted names:
 *
 *   Start at the lowest generation present.  Repeatedly take the LAST file whose
 *   start equals the current generation, then set the current generation to that
 *   file's end + 1 (or start + 1 for an unordered file).  Stop when no file starts
 *   at the current generation.
 *
 * An overlap is never an error -- it is RESOLVED, not rejected.  An output is
 * renamed into place before its inputs are removed, so a scan legitimately sees
 * a repack output alongside the files it encloses.
 *
 * Taking the LAST is the whole rule, and it is correct only because of the sort
 * below: among files sharing a start the widest reach comes last, and for a
 * shared range the in-order file comes last.  T-9 asserts that taking the FIRST
 * fails, so D-5b's requirement is tested rather than assumed.
 *
 * Returns ZS_OK when the resolved set tiles (D-6), ZS_AGAIN when it leaves a gap
 * (D-7 -- a torn readdir, retry), or ZS_BADFORMAT for a partial overlap (D-5c). */
/* D-5a's ordering, as a comparison rather than a naming accident. */
static int zsi_entry_resolve_order(const void *va, const void *vb)
{
    const struct zsi_entry *a = va, *b = vb;
    uint32_t ar = a->end ? a->end : a->start;
    uint32_t br = b->end ? b->end : b->start;

    if (a->start != b->start) return a->start < b->start ? -1 : 1;
    if (ar != br)             return ar < br ? -1 : 1;

    /* Same range: the in-order file is the published form and must win, so it
     * sorts last.  This is the conversion window (D-5). */
    if ((a->end == 0) != (b->end == 0)) return a->end == 0 ? -1 : 1;
    return 0;
}

static int zsi_fileset_resolve(struct zsi_fileset *fs)
{
    free(fs->resolved);
    fs->resolved = NULL;
    fs->nresolved = 0;

    if (fs->nall == 0) return ZS_OK;        /* the empty case D-8a handles */

    fs->resolved = malloc(fs->nall * sizeof(*fs->resolved));
    if (!fs->resolved) return ZS_INTERNAL;

    /* D-5a's order, imposed on the ENTRIES rather than inherited from the
     * names.  A name sort cannot serve: under D-1b `.current` carries no
     * generation, so where it collates says nothing about which generation it
     * holds, and a plain name sort puts it after EVERY in-order file.  In the conversion window -- output renamed
     * in, input not yet removed (D-5) -- that would make "take the last" pick
     * the superseded active file over the in-order file that just replaced it,
     * and the snapshot would carry an active file the writer is about to
     * delete.
     *
     * So sort by what the rule actually means: generation ascending, then reach
     * ascending so the widest is last, then unordered before in-order so the
     * published form wins a tie.  The scan has filled in every start by now --
     * the active file's from its header (D-1b) -- which is what makes this
     * possible at all, and is why the raw scan's entries must never reach here:
     * an unfilled start of 0 would sort the active file below everything. */
    qsort(fs->all, fs->nall, sizeof(fs->all[0]), zsi_entry_resolve_order);

    uint32_t cur = fs->all[0].start;
    for (size_t i = 1; i < fs->nall; i++)
        if (fs->all[i].start < cur) cur = fs->all[i].start;

    uint32_t highest = 0;
    for (size_t i = 0; i < fs->nall; i++) {
        uint32_t e = fs->all[i].end ? fs->all[i].end : fs->all[i].start;
        if (e > highest) highest = e;
    }

    for (;;) {
        /* The LAST file whose start equals cur.  The array is in D-5a's order,
         * and for a shared start that orders narrow-then-widest, so the last is
         * the one that encloses the others. */
        ssize_t pick = -1;
        for (size_t i = 0; i < fs->nall; i++)
            if (fs->all[i].start == cur) pick = (ssize_t)i;

        if (pick < 0) break;

        struct zsi_entry *e = &fs->all[pick];
        fs->resolved[fs->nresolved++] = *e;

        uint32_t last = e->end ? e->end : e->start;

        /* D-5c: a PARTIAL overlap, where two ranges intersect and neither
         * contains the other, cannot arise from any legal sequence.  It is
         * corruption and MUST be reported rather than resolved -- resolving it
         * would silently pick one interpretation of a directory that has no
         * correct interpretation. */
        for (size_t i = 0; i < fs->nall; i++) {
            uint32_t s2 = fs->all[i].start;
            uint32_t e2 = fs->all[i].end ? fs->all[i].end : fs->all[i].start;
            if (s2 > cur && s2 <= last && e2 > last) return ZS_BADFORMAT;
        }

        if (last == 0xFFFFFFFFu) { cur = last; break; }   /* no next generation */
        cur = last + 1;
    }

    /* D-6: the set is complete if and only if the scan consumed every generation
     * from the lowest present through the highest.  The resolved ranges therefore
     * TILE a contiguous interval.  This is the whole completeness test -- no
     * sequence number, timestamp or publication record is needed, because tiling
     * means every generation is accounted for and so nothing committed is
     * missing (C-4a). */
    if (fs->nresolved == 0) return ZS_AGAIN;

    struct zsi_entry *lastres = &fs->resolved[fs->nresolved - 1];
    uint32_t reached = lastres->end ? lastres->end : lastres->start;
    if (reached != highest) return ZS_AGAIN;

    return ZS_OK;
}

/* One above the highest generation present in ALL files, not in the resolved set
 * (D-9b).
 *
 * A superseded file still pins its generation: it is only removed once an
 * enclosing file covers it (D-23), so the highest generation present never
 * regresses and a generation can never be reissued.  Computing this from the
 * resolved set instead would let a generation be reused while a superseded file
 * bearing that name still existed.
 *
 * D-9c: allocating past 0xFFFFFFFF fails with ZS_FULL rather than wrapping. */
static int zsi_fileset_next_gen(const struct zsi_fileset *fs, uint32_t *out)
{
    uint32_t highest = 0;

    for (size_t i = 0; i < fs->nall; i++) {
        uint32_t e = fs->all[i].end ? fs->all[i].end : fs->all[i].start;
        if (e > highest) highest = e;
    }

    if (highest == 0xFFFFFFFFu) return ZS_FULL;
    *out = highest + 1;
    return ZS_OK;
}

/********** SNAPSHOT *************/

/* C-4h: a retry happens only when the file set changed during the scan, which is
 * a structural event rather than a per-operation one.  Bounded so a pathological
 * rate of structural change surfaces as ZS_AGAIN instead of a livelock. */
#define ZSI_SNAPSHOT_RETRIES 20

struct zsi_snapshot {
    struct zsi_file **files;    /* the resolved set, sorted by start ASCENDING */
    size_t            nfiles;
    int               refcount;
};

static void zsi_snapshot_release(struct zsi_snapshot **sp)
{
    struct zsi_snapshot *s = *sp;
    if (!s) return;

    if (--s->refcount > 0) { *sp = NULL; return; }

    for (size_t i = 0; i < s->nfiles; i++)
        zsi_file_release(&s->files[i]);
    free(s->files);
    free(s);
    *sp = NULL;
}

/* A handle's cache of IMMUTABLE file objects (C-4c).
 *
 * A rebuild otherwise re-opens, re-maps and re-indexes every file in the set,
 * even though only the active one can have changed -- and replaying an
 * unordered file is the expensive part (D-13d).  Here a rebuild costs only the
 * files that are actually new.
 *
 * Keyed on the FILENAME, which is sound because a name identifies its content
 * for the life of the database: generations are never reissued (D-9b, D-9c),
 * and a conversion or repack output takes a new name rather than rewriting an
 * old one.  A name that is present again therefore names the bytes we already
 * hold.
 *
 * The ACTIVE file is never cached, and that exclusion is load-bearing: it is
 * the one file that grows, and its index and `complete` boundary belong to the
 * SNAPSHOT that built them, not to the file (C-4c, G-4).  Sharing it would let
 * an older snapshot see records committed after it was taken.  A generation
 * that has stopped being active is opened fresh once -- by then its extent is
 * settled -- and cached from there on.
 */
struct zsi_fcache {
    struct zsi_file **f;
    size_t            n, a;
};

static struct zsi_file *zsi_fcache_get(struct zsi_fcache *c, const char *path)
{
    for (size_t i = 0; i < c->n; i++)
        if (strcmp(c->f[i]->fname, path) == 0) return c->f[i];
    return NULL;
}

static void zsi_fcache_put(struct zsi_fcache *c, struct zsi_file *f)
{
    if (c->n == c->a) {
        size_t want = c->a ? c->a * 2 : 8;
        struct zsi_file **p = realloc(c->f, want * sizeof(*p));
        if (!p) return;                 /* caching is only an optimisation */
        c->f = p;
        c->a = want;
    }
    zsi_file_ref(f);
    c->f[c->n++] = f;
}

/* Drop whatever the new set no longer names.  Releasing only decrements, so a
 * snapshot still using a file keeps it: this hands back the cache's own
 * reference and nothing else. */
static void zsi_fcache_sweep(struct zsi_fcache *c, struct zsi_snapshot *s)
{
    size_t keep = 0;

    for (size_t i = 0; i < c->n; i++) {
        bool present = false;

        for (size_t j = 0; j < s->nfiles && !present; j++)
            if (s->files[j] == c->f[i]) present = true;

        if (present) c->f[keep++] = c->f[i];
        else         zsi_file_release(&c->f[i]);
    }

    c->n = keep;
}

static void zsi_fcache_fini(struct zsi_fcache *c)
{
    for (size_t i = 0; i < c->n; i++)
        zsi_file_release(&c->f[i]);
    free(c->f);
    c->f = NULL;
    c->n = c->a = 0;
}

/* A-4a: what a snapshot swap must NOT throw away.
 *
 * A transaction or cursor can move to a newer snapshot while it is alive -- a
 * write transaction resolves its active file at its first store (D-9), a
 * ZS_CURSOR_LIVE cursor follows the handle's file set (D-14j) -- and the
 * snapshot it leaves behind owns the files every key and value pointer it
 * already returned points into.  Letting it go there unmaps them under the
 * caller, which is a segfault in the caller's code with nothing in the
 * backtrace to say why.
 *
 * So the borrower keeps a REFERENCE to each of those files, and the bytes live
 * until the borrower does.  Because an immutable file is shared between
 * snapshots (C-4c), a cursor that follows fifty commits ends up holding
 * references to the same few objects rather than to fifty copies -- which is
 * why this can be a plain reference and does not need the mapping-stealing
 * the descriptor cost would otherwise have forced.
 */
struct zsi_hold {
    struct zsi_file **f;
    size_t            n, a;
};

static void zsi_hold_fini(struct zsi_hold *h)
{
    for (size_t i = 0; i < h->n; i++)
        zsi_file_release(&h->f[i]);
    free(h->f);
    h->f = NULL;
    h->n = h->a = 0;
}

/* Take a reference, for the borrower `h`, to every file in `s`. */
static int zsi_hold_add_snapshot(struct zsi_hold *h, struct zsi_snapshot *s)
{
    if (!s || !s->nfiles) return ZS_OK;

    /* Reserved before anything is referenced, so a failure leaves the borrower
     * exactly as it was and the caller can propagate the error rather than
     * choosing between a leak and a dangle. */
    if (h->n + s->nfiles > h->a) {
        size_t want = h->a ? h->a : 8;
        while (want < h->n + s->nfiles) want *= 2;
        struct zsi_file **p = realloc(h->f, want * sizeof(*p));
        if (!p) return ZS_INTERNAL;
        h->f = p;
        h->a = want;
    }

    for (size_t i = 0; i < s->nfiles; i++) {
        zsi_file_ref(s->files[i]);
        h->f[h->n++] = s->files[i];
    }

    return ZS_OK;
}

/* Leave `*sp`, keeping whatever the borrower may still be reading.
 *
 * There is no "am I the last holder" case to get right anymore, and that is
 * the point: the previous version had one and got it wrong twice.  Taking a
 * reference per file is correct whoever else is looking, because the
 * reference is on the object whose lifetime is actually in question. */
static int zsi_snapshot_retire(struct zsi_snapshot **sp, struct zsi_hold *h)
{
    int r;

    if (!*sp) return ZS_OK;

    r = zsi_hold_add_snapshot(h, *sp);
    if (r != ZS_OK) return r;

    zsi_snapshot_release(sp);
    return ZS_OK;
}

/* The active file: the highest-generation UNORDERED file, or NULL if the newest
 * file is in-order.  The only file a writer appends to. */
static struct zsi_file *zsi_snapshot_active(struct zsi_snapshot *s)
{
    if (!s->nfiles) return NULL;

    struct zsi_file *last = s->files[s->nfiles - 1];
    return zsi_file_is_unordered(last) ? last : NULL;
}

/* C-4: take a snapshot.
 *
 *   1. readdir, keeping names matching zeroskip-<uuid>-* and parsing each
 *      generation range from its name;
 *   2. run D-5's scan.  If it leaves a gap the set is incomplete -- a torn
 *      readdir or corruption -- so restart from 1;
 *   3. open and map every file in the resolved set.  If any open fails with
 *      ENOENT, restart from 1;
 *   4. build a private index for each unordered file by replaying its spans,
 *      taking its snapshot boundary to be the end of its last valid span.
 *
 * NO LOCK IS TAKEN AT ANY POINT (C-2), which is the most surprising property of
 * this design.  What makes it safe:
 *
 *   - step 2's tiling check IS the completeness proof (C-4a).  Every generation
 *     in the interval is covered exactly once, so no committed data is missing,
 *     and there is nothing to compare against a published record;
 *   - a retry always converges (C-4b), because both failure modes -- a torn
 *     readdir and a file removed underneath us -- show up AS failures rather than
 *     as a set that looks complete and is not.  Removal is only ever permitted
 *     when the remaining files still tile (D-23);
 *   - everything opened is immutable from here on (C-4c).  In-order files are
 *     never modified; a non-active unordered file is never appended to again; the
 *     active file is appended to but ONLY appended to, so every byte below the
 *     boundary is stable by construction and growth beyond it is never looked at;
 *   - every index is private (C-4d), so there is no shared state to synchronise
 *     against a writer and nothing to clean up when a process dies.
 */
static int zsi_snapshot_take(const char *dir, const zsi_uuid_t *uuid,
                             zs_compar *compar, const char *compar_name,
                             zs_csum *external_csum,
                             const struct zsi_idxcfg *idxcfg,
                             void (*report)(const char *, const char *, ...),
                             struct zsi_fcache *cache,
                             struct zsi_snapshot **out)
{
    for (int attempt = 0; attempt < ZSI_SNAPSHOT_RETRIES; attempt++) {
        struct zsi_fileset fs;
        int r = zsi_fileset_scan_csum(dir, uuid, external_csum, &fs);
        if (r != ZS_OK) return r;

        r = zsi_fileset_resolve(&fs);
        if (r == ZS_AGAIN) { zsi_fileset_fini(&fs); continue; }
        if (r != ZS_OK) { zsi_fileset_fini(&fs); return r; }

        struct zsi_snapshot *s = zsi_zmalloc(sizeof(*s));
        if (!s) { zsi_fileset_fini(&fs); return ZS_INTERNAL; }
        s->refcount = 1;

        if (fs.nresolved) {
            s->files = zsi_zmalloc(fs.nresolved * sizeof(*s->files));
            if (!s->files) {
                free(s);
                zsi_fileset_fini(&fs);
                return ZS_INTERNAL;
            }
        }

        /* Between step 2 and step 3.  Nothing in a shipped build. */
        ZS_SNAPSHOT_GAP(dir);

        bool retry = false;
        for (size_t i = 0; i < fs.nresolved && !retry; i++) {
            struct zsi_file *f = NULL;
            bool is_last = (i + 1 == fs.nresolved);
            char fpath[PATH_MAX];
            bool reused = false;

            /* The active file is the last one when it is unordered, and it is
             * the only file that can still change -- so it is the only one that
             * must be opened fresh.  Everything else is immutable (C-4c) and
             * may already be in hand from the previous snapshot. */
            snprintf(fpath, sizeof(fpath), "%s/%s", dir, fs.resolved[i].name);
            if (cache) {
                /* No !is_last guard here on purpose.  The active file is kept
                 * out of the cache at the PUT below, so it can never be found
                 * at this one -- and stating the invariant twice would leave
                 * neither statement testable, since defeating either alone
                 * changes nothing. */
                f = zsi_fcache_get(cache, fpath);
                if (f) {
                    zsi_file_ref(f);
                    reused = true;
                }
            }

            if (!f) {
                r = zsi_file_open(dir, fs.resolved[i].name,
                                  fs.resolved[i].start, external_csum, &f);

                /* A file may legitimately be unlinked between steps 2 and 3, by
                 * a packer retiring an input it has already superseded.  That is
                 * not an error, it is a stale scan -- restart. */
                if (r == ZS_NOTFOUND) { retry = true; break; }
                if (r != ZS_OK) {
                    zsi_snapshot_release(&s);
                    zsi_fileset_fini(&fs);
                    return r;
                }
            }

            s->files[s->nfiles++] = f;

            /* Already indexed, header already checked, table already published
             * when it was first opened.  Skipping that IS the saving. */
            if (reused) continue;

            /* D-10a: a NON-ACTIVE file with an invalid header is REPORTED and
             * treated as holding no records.  It is deliberately NOT fatal, and
             * D-10b records why: D-10 directs a writer to move on from an unclean
             * active file, and the instant it does that file becomes non-active --
             * so a fatal rule would turn the first write after an ordinary crash
             * into a permanently unopenable database, which G-3 forbids.
             *
             * Tolerating it costs nothing that was not already lost, since an
             * invalid header means no record in that file is recoverable either
             * way, while refusing to open costs every other file too.  "Silently"
             * is the hazard, and the report addresses it. */
            if (!f->hdr_valid && !is_last && report)
                report("non-active file has an invalid header",
                       "file=<%s>", f->fname);

            if (zsi_file_is_unordered(f)) {
                /* Step 4.  The replay sets f->complete, which IS this file's
                 * snapshot boundary: growth beyond it is invisible (C-4c).
                 *
                 * Seeded from a published pointer table when one is usable
                 * (P-12), which turns the replay from "the whole file" into
                 * "whatever has been appended since somebody last published". */
                r = zsi_index_build_cached(f, compar, compar_name, idxcfg);
                if (r != ZS_OK) {
                    zsi_snapshot_release(&s);
                    zsi_fileset_fini(&fs);
                    return r;
                }

                /* P-13.  A reader publishes on exactly the same rule as a
                 * writer: whoever builds the pointers and has moved far enough
                 * past the last published table writes it out.  Safe from either
                 * side, because publication is a rename (P-4), and never fatal
                 * (P-15) -- which is why the result is discarded here rather
                 * than reported.  The write path, which has a handle to warn
                 * through, does report the first failure. */
                if (idxcfg && idxcfg->dir)
                    (void)zsi_idx_publish(f, idxcfg, compar);
            } else {
                r = zsi_ptrs_load(f);
                if (r != ZS_OK) {
                    zsi_snapshot_release(&s);
                    zsi_fileset_fini(&fs);
                    return r;
                }
            }

            /* Fully built, so it is worth keeping -- unless it is the active
             * file, whose extent is this snapshot's and nobody else's. */
            if (cache && !is_last) zsi_fcache_put(cache, f);
        }

        zsi_fileset_fini(&fs);

        if (retry) { zsi_snapshot_release(&s); continue; }

        /* P-16.  Done here rather than inside the publish, because this is the
         * one place that knows the whole file set.  A table whose generation is
         * still an unordered file is kept, so a stranded unconverted file does
         * not lose its own.  Every failure inside is ignored: a sweep that
         * cannot run costs disk space, not correctness. */
        if (idxcfg && idxcfg->dir && s->nfiles) {
            const zsi_uuid_t *u = NULL;
            uint32_t stackbuf[16];
            uint32_t *live = stackbuf;
            size_t nlive = 0;

            for (size_t i = 0; i < s->nfiles; i++)
                if (s->files[i]->hdr_valid) { u = &s->files[i]->hdr.uuid; break; }

            if (u) {
                if (s->nfiles > sizeof(stackbuf) / sizeof(stackbuf[0]))
                    live = malloc(s->nfiles * sizeof(*live));

                if (live) {
                    for (size_t i = 0; i < s->nfiles; i++)
                        if (zsi_file_is_unordered(s->files[i]))
                            live[nlive++] = s->files[i]->hdr.start;

                    zsi_idx_sweep(idxcfg, *u, live, nlive);
                    if (live != stackbuf) free(live);
                }
            }
        }

        *out = s;
        return ZS_OK;
    }

    /* C-4h: bounded rather than spinning, so a pathological rate of structural
     * change is reported instead of hanging. */
    return ZS_AGAIN;
}

/********** FILE LOCKING *************/

/* Three byte-range locks on zeroskip.lock (C-1):
 *
 *   byte 0  write   a write transaction: appending, creating a new active file,
 *                   converting an unordered file
 *   byte 1  repack  a whole repack, possibly long
 *   byte 2  remove  momentarily: verify completeness, then unlink
 *
 * The mechanism is EXACTLY fcntl record locking, and the byte offsets are
 * normative (C-1e).  This is interoperability surface, not an implementation
 * choice: implementations in different languages must exclude each other.
 *
 * NEVER flock.  On Linux flock occupies a separate lock space and does not
 * exclude fcntl, and it is a no-op over some network filesystems.  An
 * implementation using it would pass every single-implementation test and
 * silently fail to exclude a conforming peer -- which is precisely the false pass
 * T-13 exists to catch.
 *
 * There is still NO MUTEX here, and there never will be: a per-handle mutex is
 * two different objects, so it excludes only threads SHARING a handle, which is
 * not what G-5 promises.  What C-1j requires instead keys on the DATABASE --
 * F_OFD_SETLK, which the kernel scopes to an open file description, or a
 * process-global registry keyed by the lock file's inode.  That is the
 * difference between the property and the appearance of it. */

/* Byte 2 was a third lock, REMOVE, until C-1c showed it guarded nothing: every
 * removal is justified by an enclosing file the remover published first, and
 * enclosure is transitive, so removals commute.  The byte is RESERVED, not
 * reused -- a peer still taking it interoperates and contends with nobody. */
enum zsi_lock { ZSI_LOCK_WRITE = 0, ZSI_LOCK_REPACK = 1 };
#define ZSI_NLOCKS 2

/* C-1j mechanism 1: locks scoped to an open file description rather than to the
 * process, so two handles exclude each other with no extra state at all.  Linux
 * 3.15+ and macOS; absent on the BSDs, which take the registry below.
 *
 * C-1i permits this only where the two lock kinds have been verified to conflict
 * with EACH OTHER, since a peer implementation may still use F_SETLK.  Verified
 * on Darwin in both directions (an OFD holder blocks a peer's F_SETLK, and an
 * F_SETLK holder blocks a peer's OFD attempt); documented as conflicting on
 * Linux. */
#if defined(F_OFD_SETLK) && defined(F_OFD_SETLKW)
#define ZSI_HAVE_OFD_LOCKS 1
#else
#define ZSI_HAVE_OFD_LOCKS 0
#endif

/* C-1j mechanism 2, and T-14's reason for existing: on every platform anyone
 * develops on, mechanism 1 is present and this is dead code.  Dead code in a
 * concurrency path rots and is then discovered by the one platform that depends
 * on it, so the choice is a variable rather than an #if and the suite runs the
 * whole of T-14 against both settings. */
static bool zsi_lock_registry = !ZSI_HAVE_OFD_LOCKS;

/* Keyed by st_dev/st_ino, NOT by path: two paths reach one inode through a
 * symlink, a bind mount or a relative directory, and a path-keyed registry
 * would hand both handles the same lock while reporting success. */
struct zsi_lockreg {
    dev_t                dev;
    ino_t                ino;
    unsigned             held;      /* bitmask of enum zsi_lock, process-wide */
    unsigned             refs;      /* handles sharing this entry */
    struct zsi_lockreg  *next;
};

static struct zsi_lockreg *zsi_lockreg_head;

/* Guards the list and the `held` words, and NOTHING else -- never held across
 * the fcntl call, which can block for as long as another process wants.  A
 * compiler builtin rather than a pthread mutex: the library links no thread
 * library, and test_lock_no_thread_machinery keeps it that way. */
static volatile char zsi_lockreg_spin;

static void zsi_lockreg_enter(void)
{
    while (__atomic_test_and_set(&zsi_lockreg_spin, __ATOMIC_ACQUIRE))
        ;
}

static void zsi_lockreg_leave(void)
{
    __atomic_clear(&zsi_lockreg_spin, __ATOMIC_RELEASE);
}

struct zsi_locks {
    int      fd;            /* exactly one, for the handle's lifetime (C-1g) */
    unsigned held;          /* bitmask of enum zsi_lock */

    /* C-1j: this handle's entry in the process-global registry, or NULL when
     * mechanism 1 makes it unnecessary. */
    struct zsi_lockreg *reg;
};

/* Open (creating if absent) the lock file and keep ONE descriptor for the
 * handle's lifetime.
 *
 * C-1g: fcntl locks are released by closing ANY descriptor for the file in that
 * process, so a second open followed by a close would silently drop every lock
 * this handle holds.  There is exactly one, and nothing may open another.
 *
 * D-3a: created with O_CREAT if absent, so an existing database is never
 * unopenable for want of it.  Concurrent creation is harmless -- O_CREAT on one
 * path yields one inode, so every process locks the same object.
 *
 * D-3b: it is never unlinked, by this library or anything else.  Unlinking it
 * while processes hold locks is the one way to break mutual exclusion from
 * outside: holders keep locking the removed inode while a new process creates a
 * fresh one and locks that, so TWO WRITERS each believe they hold the write lock.
 * Worth stating because an empty file named *.lock is exactly what cleanup
 * scripts delete. */
static int zsi_lock_open(struct zsi_locks *lk, const char *dir)
{
    char path[PATH_MAX];

    memset(lk, 0, sizeof(*lk));
    lk->fd = -1;

    snprintf(path, sizeof(path), "%s/%s", dir, ZSI_LOCK_NAME);
    lk->fd = open(path, O_RDWR | O_CREAT, 0600);
    if (lk->fd < 0) return (errno == ENOENT) ? ZS_NOTFOUND : ZS_IOERROR;

    if (zsi_lock_registry) {
        struct stat sb;

        if (fstat(lk->fd, &sb) < 0) {
            close(lk->fd);
            lk->fd = -1;
            return ZS_IOERROR;
        }

        zsi_lockreg_enter();

        struct zsi_lockreg *e = zsi_lockreg_head;
        while (e && !(e->dev == sb.st_dev && e->ino == sb.st_ino)) e = e->next;

        if (!e) {
            e = calloc(1, sizeof(*e));
            if (!e) {
                zsi_lockreg_leave();
                close(lk->fd);
                lk->fd = -1;
                return ZS_INTERNAL;
            }
            e->dev = sb.st_dev;
            e->ino = sb.st_ino;
            e->next = zsi_lockreg_head;
            zsi_lockreg_head = e;
        }
        e->refs++;
        lk->reg = e;

        zsi_lockreg_leave();
    }

    return ZS_OK;
}

/* C-1j mechanism 2.  Claim `which` for this process, before the fcntl lock so
 * the two agree on C-1d's ordering.
 *
 * Blocking is a poll rather than a condition variable, deliberately: a condvar
 * needs the thread library this file does not link, and the wait only happens
 * when two handles in one process contend -- which C-1f called a caller error
 * until C-1j, so it is the rare path, not the hot one. */
static int zsi_lockreg_acquire(struct zsi_locks *lk, enum zsi_lock which,
                               bool block)
{
    unsigned bit = 1u << which;

    if (!lk->reg) return ZS_OK;

    for (;;) {
        zsi_lockreg_enter();
        if (!(lk->reg->held & bit)) {
            lk->reg->held |= bit;
            zsi_lockreg_leave();
            return ZS_OK;
        }
        zsi_lockreg_leave();

        if (!block) return ZS_LOCKED;

        {
            struct timespec ts;
            ts.tv_sec = 0;
            ts.tv_nsec = 1000000;               /* 1ms */
            nanosleep(&ts, NULL);
        }
    }
}

static void zsi_lockreg_drop(struct zsi_locks *lk, enum zsi_lock which)
{
    if (!lk->reg) return;

    zsi_lockreg_enter();
    lk->reg->held &= ~(1u << which);
    zsi_lockreg_leave();
}

static void zsi_lock_close(struct zsi_locks *lk)
{
    if (lk->fd < 0) return;

    /* Closing releases every fcntl lock this process holds on the inode, which is
     * what we want on the way out -- and is why C-1g forbids a second descriptor
     * being closed early.  The registry has no kernel to do that for it, so
     * whatever this handle still holds is dropped explicitly. */
    if (lk->reg) {
        zsi_lockreg_enter();
        lk->reg->held &= ~lk->held;
        if (--lk->reg->refs == 0) {
            struct zsi_lockreg **pp = &zsi_lockreg_head;
            while (*pp && *pp != lk->reg) pp = &(*pp)->next;
            if (*pp) *pp = lk->reg->next;
            free(lk->reg);
        }
        zsi_lockreg_leave();
        lk->reg = NULL;
    }

    close(lk->fd);
    lk->fd = -1;
    lk->held = 0;
}

static int zsi_lock_fcntl(int fd, enum zsi_lock which, int type, bool block)
{
    struct flock fl;

    memset(&fl, 0, sizeof(fl));
    fl.l_type = (short)type;
    fl.l_whence = SEEK_SET;
    fl.l_start = (off_t)which;
    fl.l_len = 1;

    /* C-1i/C-1j: the OFD commands where the platform has them, which makes the
     * kernel do mechanism 1 for free.  They conflict with a peer's F_SETLK, so
     * this is not visible outside the process. */
#if ZSI_HAVE_OFD_LOCKS
    int wait_cmd = F_OFD_SETLKW, try_cmd = F_OFD_SETLK;
    if (zsi_lock_registry) { wait_cmd = F_SETLKW; try_cmd = F_SETLK; }
#else
    int wait_cmd = F_SETLKW, try_cmd = F_SETLK;
#endif

    for (;;) {
        if (fcntl(fd, block ? wait_cmd : try_cmd, &fl) == 0) return ZS_OK;
        if (errno == EINTR) continue;
        if (!block && (errno == EACCES || errno == EAGAIN)) return ZS_LOCKED;
        return ZS_IOERROR;
    }
}

/* Acquire.  Blocking unless ZS_NONBLOCKING, in which case ZS_LOCKED.
 *
 * C-1f: fcntl locks are per-PROCESS, not per-thread -- two threads of one process
 * both acquire the same lock successfully, and the kernel sees a single owner, so
 * the fcntl lock alone does not deliver G-5 within a process.  C-1j closes that,
 * and both halves are taken here.  An implementation relying on fcntl alone
 * passes every single-threaded test and corrupts a database the moment a second
 * handle writes, which is why T-14 must be run per implementation.
 *
 * C-1d lock ordering: the two locks form ONE ORDER, write -> repack.  Repack may
 * be taken while holding write; write must NOT be taken while holding repack, so
 * no cycle exists.  Most operations take one lock and no order arises.  Two hold
 * both -- compaction (D-26) and C-1l's compacting seal -- which is the whole
 * reason an order has to be stated.  The byte values in enum zsi_lock happen to
 * be monotonic in it, which is a reading convenience and nothing more; the bytes
 * are interop surface (C-1e) and the order is a separate statement.
 *
 * WHY THIS DIRECTION, since it was repack -> write until C-1l landed.  A writer
 * that wants the repack lock is already inside a transaction, so it can only
 * extend forward and write-before-repack is the only order available to it at
 * all.  Compaction begins holding nothing and can acquire either way round, so
 * it is the operation that adapts.  Keeping repack -> write would have made the
 * two uses cyclic.  The ORDER is interop surface too (C-1e): two peers holding
 * both locks in opposite orders deadlock against each other while each reads
 * every byte correctly.
 *
 * The consequence to watch is D-16e's cascade at write-transaction begin, which
 * takes repack BEFORE the write lock: it is legal only because zsi_repack
 * releases repack before returning, so begin never holds both.  Under the old
 * order that sequencing did not matter.
 *
 * Asserted here, which is sound now that a handle belongs to one thread of
 * control: `held` describes the one actor using it, and a violation deadlocks in
 * production while being trivially visible in development. */
static int zsi_lock_take(struct zsi_locks *lk, enum zsi_lock which, int flags)
{
    bool block = !(flags & ZS_NONBLOCKING);

    assert(lk->fd >= 0);
    assert(!(lk->held & (1u << which)));        /* not already held */

    /* C-1d: write -> repack, so taking WRITE while holding REPACK is the one
     * illegal acquisition. */
    if (which == ZSI_LOCK_WRITE)
        assert(!(lk->held & (1u << ZSI_LOCK_REPACK)));

    /* C-1j before C-1e: the registry excludes this process's other handles, the
     * fcntl lock excludes every other process, and BOTH are always taken.  The
     * registry is invisible outside the process, so it can never substitute for
     * the lock a peer implementation sees. */
    int r = zsi_lockreg_acquire(lk, which, block);
    if (r != ZS_OK) return r;

    r = zsi_lock_fcntl(lk->fd, which, F_WRLCK, block);
    if (r != ZS_OK) { zsi_lockreg_drop(lk, which); return r; }

    lk->held |= (1u << which);
    return ZS_OK;
}

static int zsi_lock_release(struct zsi_locks *lk, enum zsi_lock which)
{
    if (!(lk->held & (1u << which))) return ZS_OK;

    /* C-1j: released AFTER the fcntl lock, the mirror of taking it before, so a
     * handle in this process never sees the lock free while another still holds
     * it against a peer process. */
    int r = zsi_lock_fcntl(lk->fd, which, F_UNLCK, true);
    lk->held &= ~(1u << which);
    zsi_lockreg_drop(lk, which);

    return r;
}

/********** DATABASE HANDLE *************/

struct zs_db {
    char        *dir;
    uint32_t     flags;
    zsi_uuid_t   uuid;
    bool         have_uuid;

    zs_compar   *compar;
    char         compar_name[ZSI_COMPAR_NAME_LEN];
    zs_csum     *external_csum;
    unsigned     create_csum_id;    /* engine for files THIS handle creates */
    size_t       rollover_size;
    size_t       rollover_txns;      /* D-9d, A-15 */
    size_t       repack_max_size;    /* D-16, A-16 */
    size_t       merge_memory;       /* D-20c, A-20 */
    void       (*error)(const char *msg, const char *fmt, ...);

    /* A-17.  Plain arithmetic, no atomics: a handle is not thread-safe anyway
     * (G-5), and these are counters rather than anything a decision reads. */
    struct zs_db_stats stats;

    /* Pointer table cache (spec section 8).  index_dir NULL disables it.
     * Resolved at open to the PER-DATABASE directory: <root>/<uuid> for a
     * configured root (P-2a), <dbdir>/zeroskip.cache under ZS_INDEX_LOCAL
     * (P-2b, index_local set). */
    char        *index_dir;          /* owned */
    size_t       index_threshold;    /* P-13 */
    bool         index_local;        /* A-8a */

    bool         readonly;          /* ZS_SHARED (A-5) */
    bool         no_auto_repack;    /* ZS_NOAUTOREPACK (A-14, D-16e) */
    bool         nosync;            /* ZS_NOSYNC (C-7c) */
    bool         nonblocking;

    struct zsi_locks     locks;
    struct zsi_snapshot *snap;

    /* C-4i: the active file's identity as of the last refresh, so the probe can
     * tell an append from a rollover (D-1b).  Kept here rather than derived
     * from the snapshot because a snapshot holds no inode. */
    dev_t                act_dev;
    ino_t                act_ino;

    /* Immutable files carried across rebuilds (C-4c).  Per HANDLE, not global:
     * it holds open descriptors and mappings, which belong to the handle's
     * lifetime and must go when it closes. */
    struct zsi_fcache    fcache;      /* current snapshot for zs_db_* calls */
    struct zs_txn       *write_txn;

    /* The active file's append descriptor, handed back by the last write
     * transaction and reused by the next while the active generation is
     * unchanged -- the open/fstat/close round trip was the largest single
     * cost of a small NOSYNC transaction.  -1 when empty.  Reuse is gated on
     * the SNAPSHOT's active file each time (zsi_writer_active): a rollover,
     * seal or conversion changes the generation, and the stale descriptor is
     * closed rather than written through.  Generations are never reissued
     * (D-9b), so gen equality on an unordered active file identifies the
     * inode. */
    int          wfd_cache;
    uint32_t     wfd_gen;

    /* Backing for pointers returned by the non-transactional calls, whose
     * implicit transaction has ended by the time the caller sees them (A-4). */
    char        *retbuf;
    size_t       retalloc;
};

static void zsi_default_error(const char *msg, const char *fmt, ...)
{
    (void)msg;
    (void)fmt;
}

/* Every mutating internal entry point starts here rather than scattering the
 * check.  R-3: a reader MUST NOT write, and opening a damaged database read-only
 * is side-effect-free -- no conversion, no repack, no new active file, no
 * removal.  There is no shared cache for it to update either (D-13c). */
static int zsi_check_writable(struct zs_db *db)
{
    return db->readonly ? ZS_READONLY : ZS_OK;
}

/* Create generation 1: a 72-byte header and no spans, which F-26h makes a legal
 * empty file (D-8a).
 *
 * C-6: after creating a DATA FILE the directory is fdatasync'd, otherwise the
 * name may be absent after a crash even though the file's contents are durable. */
static int zsi_create_active(struct zs_db *db, uint32_t gen)
{
    char name[ZSI_NAME_MAX], path[PATH_MAX], hdr[ZSI_HEADER_LEN];
    struct zsi_header h;

    memset(&h, 0, sizeof(h));
    h.version_read = ZSI_VERSION_READ;
    h.version_write = ZSI_VERSION_WRITE;
    h.flags = (uint16_t)db->create_csum_id;
    memcpy(h.uuid, db->uuid, 16);
    h.start = gen;
    h.end = 0;
    memcpy(h.compar_name, db->compar_name, ZSI_COMPAR_NAME_LEN);

    zs_csum *cs = zsi_csum_for_id(db->create_csum_id, db->external_csum);
    if (!cs) return ZS_BADUSAGE;
    zsi_header_encode(hdr, &h, cs);

    zsi_name_current(name, db->uuid);           /* D-1b */
    snprintf(path, sizeof(path), "%s/%s", db->dir, name);

    /* O_EXCL: creating a file IS publishing it (D-8), so a collision must fail
     * loudly rather than truncate.  Under D-1b the name is fixed, so what a
     * collision means has changed: not another writer allocating the same
     * generation, but a file already sitting at the one active-file name.
     *
     * If that file has no valid header it is D-10's case -- no discoverable
     * generation, no recoverable record, and invisible to the resolved set, so
     * nothing upstream had a file object to convert.  It is exactly the state a
     * crash during this function leaves behind, and removing it is what lets a
     * writer continue (G-3).  Anything with a VALID header is a different
     * matter: it holds records and a caller failed to convert it first (D-12b),
     * so it must not be silently destroyed. */
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0 && errno == EEXIST) {
        char buf[ZSI_HEADER_LEN];
        struct zsi_header probe;
        ssize_t got;
        int pfd = open(path, O_RDONLY);

        if (pfd < 0) return ZS_IOERROR;
        got = read(pfd, buf, sizeof(buf));
        close(pfd);

        if (got == (ssize_t)sizeof(buf)) {
            zs_csum *pcs = zsi_csum_for_id(zsi_header_engine_id(buf),
                                           db->external_csum);
            if (pcs && zsi_header_decode(buf, sizeof(buf), pcs, &probe) == ZS_OK)
                return ZS_BADFORMAT;    /* holds records; convert it first */
        }

        if (ZS_UNLINK(path) != 0) return ZS_IOERROR;
        fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    }
    if (fd < 0) return ZS_IOERROR;

    ssize_t n = ZS_WRITE(fd, hdr, sizeof(hdr));
    if (n != (ssize_t)sizeof(hdr)) { close(fd); return ZS_IOERROR; }
    /* C-6b: in EVERY durability mode.  ZS_NOSYNC relaxes only C-7's commit
     * gates; the structural syncs are integrity, and skipping them here and
     * below is how a crash under NOSYNC costs converted generations instead
     * of the active tail the caller agreed to risk. */
    if (ZS_FDATASYNC(fd) < 0) { close(fd); return ZS_IOERROR; }
    close(fd);

    /* C-6: fdatasync the DIRECTORY after creating a data file, or the name may be
     * absent after a crash even though the contents are durable.
     *
     * A failure here is REPORTED rather than fatal.  The file exists and its
     * contents are durable; only the name's durability is in doubt, and if it were
     * lost the result is a generation that never appeared -- which is
     * indistinguishable from the transaction not having happened, and recoverable
     * (C-6a).  Failing the create would be worse: it would leave a file the caller
     * has been told does not exist. */
    {
        int dfd = open(db->dir, O_RDONLY);
        if (dfd >= 0) {
            if (ZS_FDATASYNC(dfd) < 0)
                db->error("directory sync failed; the new file's name may not "
                          "be durable", "dir=<%s>", db->dir);
            close(dfd);
        }
    }

    return ZS_OK;
}

/* Refresh db->snap.  Used by open and by every zs_db_* call that needs a current
 * view; a transaction holds its own snapshot for its lifetime. */
static int zsi_db_refresh(struct zs_db *db)
{
    struct zsi_snapshot *s = NULL;
    struct zsi_idxcfg idxcfg = { db->index_dir, db->index_threshold,
                                 db->index_local };
    int r = zsi_snapshot_take(db->dir, db->have_uuid ? &db->uuid : NULL,
                              db->compar, db->compar_name, db->external_csum,
                              &idxcfg, db->error, &db->fcache, &s);
    if (r != ZS_OK) return r;

    zsi_snapshot_release(&db->snap);
    db->snap = s;

    /* Anything the new set no longer names is dead weight -- a repacked-away
     * input holds a descriptor and a mapping until somebody lets go. */
    zsi_fcache_sweep(&db->fcache, s);

    /* C-4i's baseline, committed only by a refresh that SUCCEEDED. */
    {
        struct zsi_file *na = zsi_snapshot_active(s);
        struct stat sb;
        db->act_dev = 0;
        db->act_ino = 0;
        if (na && stat(na->fname, &sb) == 0) {
            db->act_dev = sb.st_dev;
            db->act_ino = sb.st_ino;
        }
    }

    if (!db->have_uuid && s->nfiles) {
        memcpy(db->uuid, s->files[0]->hdr.uuid, 16);
        db->have_uuid = true;
    }

    return ZS_OK;
}

/* C-4i: refresh the handle's snapshot, unless a probe proves nothing has
 * committed since it was taken.
 *
 * This is what makes a read on an hours-old handle as current as one on a
 * handle opened for the call, at ONE syscall rather than the snapshot rebuild
 * zsi_db_refresh pays: readers take no lock (C-2), so nothing announces
 * another process's commit -- the only way to see it is to look.  Timestamps
 * play no part, so filesystem timestamp granularity cannot fake freshness. */
static int zsi_db_freshen(struct zs_db *db)
{
    struct zsi_file *act = zsi_snapshot_active(db->snap);
    char path[PATH_MAX], name[ZSI_NAME_MAX];
    struct stat sb;
    bool stale;

    /* C-4i, from ONE file.  D-1b gives the active file a fixed name, and that
     * is what makes this exact rather than a heuristic:
     *
     *   - a commit that APPENDS grows it, so the size changes;
     *   - a commit that starts a new generation converts it and creates a
     *     replacement at the same name (D-12b), so the INODE changes;
     *   - and nothing else makes committed data visible.  Publishing an
     *     in-order file by rename (C-3, D-21) only republishes records that
     *     were already readable from what it was built from, so a conversion,
     *     a repack output or a D-23 removal is invisible here -- and harmless,
     *     because no record appears or disappears.
     *
     * A superseded file vanishing therefore needs no advance detection: in-order
     * files are immutable, so a later open either finds what we expected or
     * fails with ENOENT, and C-4b's retry rescans and converges.  Detection is
     * lazy exactly where laziness is free.
     *
     * The alternative, a getdents sweep of the whole directory on every
     * operation, is equally exact and far more expensive: on a network or ZFS
     * mount it costs about what the fdatasyncs beside it do, which is enough to
     * make relaxed durability buy nothing at all. */
    zsi_name_current(name, db->uuid);
    snprintf(path, sizeof(path), "%s/%s", db->dir, name);

    if (stat(path, &sb) != 0) {
        if (errno != ENOENT) return ZS_IOERROR;
        /* No active file.  Fresh only if we did not think there was one --
         * otherwise it has been converted away and the set has moved. */
        stale = (act != NULL);
    } else if (!act) {
        stale = true;                   /* one appeared: a peer rolled over */
    } else {
        /* Identity first, then extent.  A replacement can be the same size as
         * what it replaced, so comparing size alone would miss a rollover. */
        stale = (sb.st_dev != db->act_dev)
             || (sb.st_ino != db->act_ino)
             || ((size_t)sb.st_size != act->size);
    }

    if (!stale) return ZS_OK;

    int r = zsi_db_refresh(db);
    if (r != ZS_OK) return r;

    return ZS_OK;
}

/********** READ PATH *************/

/* Every read draws on the same set of SOURCES, ordered newest to oldest (D-14):
 *
 *   highest   the current write transaction's uncommitted records
 *   then      each data file, by start generation DESCENDING
 *
 * Within a file the newest version of a key wins; across sources, the first
 * record found in that order wins.  If that record is a deletion, the key does not
 * exist.
 *
 * D-14a: point lookups, cursors and range scans ALL resolve visibility by this
 * one rule, which is what makes it impossible for them to disagree (G-7).  Both
 * live here, over the same per-file cursors, for that reason -- a second
 * resolution path would be a second set of bugs. */

/* D-14d, point lookup.  Walk the sources in priority order; in each, search for
 * the key by D-14b; stop at the first source that HAS it.  That record decides the
 * answer -- its value, or absence if it is a deletion.
 *
 * A source that does not have the key is skipped, and NO SOURCE MAY BE SKIPPED FOR
 * ANY OTHER REASON.  No bloom filter, no cached key range, nothing: the cost is
 * proportional to the number of files, which is why keeping that count low is the
 * point of the repack policy (D-16) rather than something to optimise around here.
 *
 * D-14c: ancestors are not consulted.  They exist solely for repacking, so a
 * lookup never follows a chain. */
/* `ephemeral` is A-4b: the caller accepts key and value pointers that live only
 * until its next call, which lets the transaction's own records be read where
 * they already are.  It reaches only the ZSI_SRC_TXN source below, since that
 * is the only one with anywhere else to read from. */
static int zsi_lookup(struct zs_db *db, struct zsi_snapshot *snap,
                      struct zs_txn *txn, const char *key, size_t keylen,
                      bool ephemeral, struct zsi_rec *out)
{
    struct zsi_fcur fc;

    if (keylen < 1) return ZS_BADUSAGE;         /* F-14 */

    /* The transaction first: its writes are visible to its own reads and to
     * nothing else until commit (A-1a). */
    if (txn) {
        memset(&fc, 0, sizeof(fc));
        fc.kind = ZSI_SRC_TXN;
        fc.txn = txn;
        fc.compar = db->compar;
        fc.gen = ZSI_GEN_TXN;
        fc.ephemeral = ephemeral;

        int r = zsi_fcur_find(&fc, key, keylen, out);
        zsi_fcur_fini(&fc);
        if (r == ZS_OK) return zsi_rec_is_delete(out) ? ZS_NOTFOUND : ZS_OK;
        if (r != ZS_NOTFOUND) return r;
    }

    /* Then each file, newest first.  The snapshot is sorted ascending, so this
     * walks it backwards. */
    for (size_t i = snap->nfiles; i-- > 0; ) {
        zsi_fcur_init_file(&fc, snap->files[i], db->compar);

        int r = zsi_fcur_find(&fc, key, keylen, out);
        zsi_fcur_fini(&fc);
        /* Nothing is verified here.  Records carry no checksum (F-13a); an
         * unordered source's bytes were verified by span when the index was
         * built (F-5e), and an in-order source's are covered by a region
         * checksum nothing on a read path consults (F-33a).  Between
         * consistency checks, corrupt bytes are returned -- stated in F-5e
         * rather than discovered here. */
        if (r == ZS_OK) return zsi_rec_is_delete(out) ? ZS_NOTFOUND : ZS_OK;
        if (r != ZS_NOTFOUND) return r;
    }

    return ZS_NOTFOUND;
}

/* D-14e, iteration.  A cursor holds one per-file cursor per source, each
 * traversable in comparator order, held in an array kept sorted by:
 *
 *     current key ascending, then generation descending.
 *
 * The tie-break is not decoration.  Because equal keys sort by generation
 * descending, every cursor positioned on the emitted key is CONTIGUOUS FROM THE
 * FRONT of the array and element 0 is the newest -- which is what makes step 3 a
 * complete treatment of duplicates rather than a heuristic (D-14f). */
struct zs_cursor {
    struct zs_db     *db;
    struct zs_txn    *txn;          /* owning txn, or NULL for an implicit one */
    struct zsi_snapshot *snap;

    /* A-4a: mappings from snapshots this cursor has swapped away from, kept
     * until it ends because pointers it yielded still point into them. */
    struct zsi_hold   hold;

    struct zsi_fcur  *cur;
    size_t            ncur;

    char             *prefix;
    size_t            prefixlen;

    /* ZS_SKIPROOT needs the start key kept, since the prefix buffer is only
     * populated for ZS_CURSOR_PREFIX and the two flags are independent. */
    char             *skiproot_key;
    size_t            skiproot_keylen;

    /* Every flag together: spread among the pointers they cost 29 bytes of
     * padding, and a cursor allocates this struct on every open.  No on-disk
     * layout depends on field order -- G-0 keeps that in explicit memcpy at
     * literal offsets.
     *
     * reverse is fixed at open (D-14k).  rev_succ_none means the prefix was all
     * 0xFF -- no successor, so seek from the end.  handle_live is whether this
     * cursor may observe the HANDLE's later commits (D-14j), and cannot be
     * derived from txn, since a read-only implicit transaction arrives NULL. */
    uint32_t          flags;
    bool              owns_txn;
    bool              started;
    bool              done;
    bool              have_emitted;
    bool              reverse;
    bool              rev_succ_none;
    bool              handle_live;


    /* the last record handed out, and its owning source */
    struct zsi_rec    emitted;

    /* D-14j liveness.  A cursor caches each arm's current record, so it must
     * notice when the world underneath changed:
     *
     *   - the transaction's pending array, by a counter (free);
     *   - this handle's file set, by comparing our snapshot against the
     *     handle's current one -- also free, because a commit through the same
     *     handle already replaces it.
     *
     * last_key is the key most recently yielded, BORROWED rather than copied.
     * It is what D-14j-b's "resume strictly after" is measured from, and it is
     * needed only until the next step -- a strictly shorter window than the one
     * A-4 already promises the CALLER for the very same pointer.  So a copy here
     * would be redundant with A-4a, and if it were not redundant the record the
     * caller is holding would be dangling too.  It is exactly the borrow
     * `emitted` (just above) has always taken, which zs_cursor_replace
     * dereferences arbitrarily later.
     *
     * What makes A-4a hold through a refresh: the cursor references every file
     * in its snapshot, a snapshot swap RETIRES the outgoing one into c->hold
     * instead of releasing it, and that same reference is what stops the D-13b
     * fold remapping the active file underneath a reader (G-6).
     *
     * ZS_EPHEMERAL is the one place A-4 is weakened (A-4b), and it cannot reach
     * here: the public cursor and foreach forms reject it, so the only source
     * that ever sets it belongs to the throwaway ZS_FETCHNEXT/ZS_FETCHPREV
     * cursor, which takes a single step and is freed inside the call -- it
     * never reaches a second step, which is the only thing that reads this. */
    unsigned long     txn_seq;
    const char       *last_key;
    size_t            last_keylen;

    /* The key this cursor was opened at, kept for the whole of its life.
     *
     * A refresh re-seeks every arm, and before the first record has been
     * emitted there is no last_key to resume from -- so without this it would
     * restart from the beginning and yield records BEFORE the start key.  Under
     * ZS_CURSOR_PREFIX that restart lands outside the prefix and ends the scan
     * immediately, turning a refresh into a silently empty result. */
    char             *start_key;
    size_t            start_keylen;

    /* D-14k.  Direction is fixed at open.  For a reverse prefix scan the
     * start position is the last key carrying the prefix, found by an
     * exclusive seek at the prefix's byte-successor -- computed ONCE, here,
     * so a refresh re-derives the same bound the open used rather than
     * trusting a stale arm position.  rev_succ NULL with rev_succ_none set
     * means the prefix was all 0xFF: no successor, seek from the end. */
    char             *rev_succ;
    size_t            rev_succlen;

    /* Whether this cursor may observe the HANDLE's later commits.
     *
     * True for the non-transactional forms, whose enclosing transaction is one
     * the library made for them; false inside a caller's explicit transaction,
     * where G-4 promises a fixed file set.  It cannot be derived from c->txn,
     * because a read-only implicit transaction is passed to the cursor as NULL
     * -- so the wrapper that created it says so. */
};

/* Order two per-file cursors: exhausted last, then key ascending, then generation
 * descending.  D-14g gives the transaction ZSI_GEN_TXN so its records win equal
 * keys with no special case here. */
/* `inline` is required here, not decorative.  This and zsi_ptrs_at /
 * zsi_ptrs_rec are called once per record from the merge loop and are small
 * enough that clang inlines them at -O2 while GCC, whose auto-inline budget is
 * much tighter, does not; the keyword brings them into its reach.  It has to be
 * said in the source rather than in CFLAGS, because zeroskip.c is vendored and
 * is built with the host project's flags.  Nothing depends on it for
 * correctness, so nothing reports its loss. */
static inline int zsi_cur_order(struct zs_cursor *c, const struct zsi_fcur *a,
                                const struct zsi_fcur *b)
{
    if (a->exhausted && b->exhausted) return 0;
    if (a->exhausted) return 1;
    if (b->exhausted) return -1;

    int r = zsi_cmp(c->db->compar, a->cur.key, a->cur.keylen, b->cur.key, b->cur.keylen);
    /* D-14k: reverse flips the KEY order only.  The generation tie-break is
     * direction-blind -- equal keys must stay newest-first however the walk
     * travels, or step 3 would suppress the wrong duplicate. */
    if (r) return c->reverse ? -r : r;

    if (a->gen == b->gen) return 0;
    return a->gen > b->gen ? -1 : 1;        /* higher generation first */
}

static void zsi_cur_sort(struct zs_cursor *c)
{
    /* Insertion sort: the array is small by design (D-16 keeps the file count
     * low), and it is almost always already sorted.
     *
     * The guard is D-14i-a's shortcut one level up, and for the same reason:
     * without it an element already in place is lifted into a local and put
     * back, moving a whole struct zsi_fcur to achieve nothing.  It is free when
     * the element DOES move, since that comparison is the while loop's first
     * iteration either way.  Step 3 calls this on every step of a scan whose
     * keys are duplicated across files, which is an ordinary database after
     * updates. */
    for (size_t i = 1; i < c->ncur; i++) {
        if (zsi_cur_order(c, &c->cur[i - 1], &c->cur[i]) <= 0) continue;

        struct zsi_fcur t = c->cur[i];
        size_t j = i;
        while (j > 0 && zsi_cur_order(c, &c->cur[j - 1], &t) > 0) {
            c->cur[j] = c->cur[j - 1];
            j--;
        }
        c->cur[j] = t;
    }
}

/* D-14e step 5: advance element 0, then move it down to its new position.
 *
 * Its key only ever moves in the direction of travel, so this is a single
 * insertion into an already-sorted array, and it stops as soon as it is no
 * longer greater than its neighbour under the cursor's order.  O(k) worst
 * case, and usually O(1) because the advanced cursor stays at or near the
 * front (D-14i). */
static void zsi_cur_resort_head(struct zs_cursor *c)
{
    if (c->ncur < 2) return;

    /* The overwhelmingly common case, and the one D-14i names: the advanced
     * arm is still the smallest, so nothing moves.  Answer that with ONE
     * comparison and return.
     *
     * Without this the function lifts c->cur[0] into a local and puts it back
     * whatever happens -- and struct zsi_fcur is 160 bytes, so a step that
     * moved nothing still copied 320 bytes.  Per record.  The insertion below
     * needs the local because it shifts the array down over it; the case where
     * it shifts nothing does not. */
    if (zsi_cur_order(c, &c->cur[0], &c->cur[1]) <= 0) return;

    struct zsi_fcur t = c->cur[0];
    size_t j = 0;
    while (j + 1 < c->ncur && zsi_cur_order(c, &t, &c->cur[j + 1]) > 0) {
        c->cur[j] = c->cur[j + 1];
        j++;
    }
    c->cur[j] = t;
}

static void zsi_cursor_free(struct zs_cursor *c)
{
    if (!c) return;
    for (size_t i = 0; i < c->ncur; i++) zsi_fcur_fini(&c->cur[i]);
    zsi_snapshot_release(&c->snap);

    /* A-4a: the end of the cursor is the first moment a mapping it yielded
     * pointers out of may go. */
    zsi_hold_fini(&c->hold);

    free(c->start_key);
    /* last_key is borrowed (see its declaration), so there is nothing to free --
     * and the bytes it points at only become free-able at zsi_hold_fini above. */
    free(c->rev_succ);
    free(c->cur);
    free(c->prefix);
    free(c->skiproot_key);
    free(c);
}

/* D-14e step 1: seek every per-file cursor to the start point, so its current
 * record is the first with key >= the start key -- or mark it exhausted, which is
 * immediately the case for a source holding no records.  Then sort. */
/* `flags` is uint32_t here and `int` in the public binding, which is where the
 * three casts at the call sites come from.  The binding uses int because that is
 * what C callers expect of a flags argument; internally the flag space is one
 * 32-bit set of bits and unsigned is the honest type for it.  Every public flag
 * value fits well inside 30 bits, so the conversion is value-preserving -- but it
 * is written out rather than left implicit, for consumers built with
 * -Wconversion. */
/* D-14k step 1, one arm.  Forward: lower bound of the start key, or the
 * beginning.  Reverse: the largest key <= the start key; under
 * ZS_CURSOR_PREFIX the start key IS the prefix and the scan begins at the
 * LAST key carrying it -- an exclusive seek at the prefix's byte-successor,
 * computed once at open.  Shared by open and by the pre-first-emit reseek,
 * so a refresh cannot diverge from the open (the zsi_cursor_reseek_arm
 * lesson, again). */
static int zsi_cursor_seek_arm_start(struct zs_cursor *c, struct zsi_fcur *fc)
{
    if (!c->reverse)
        return c->start_key ? zsi_fcur_seek(fc, c->start_key, c->start_keylen)
                            : zsi_fcur_seek_first(fc);

    if ((c->flags & ZS_CURSOR_PREFIX) && c->prefixlen) {
        if (c->rev_succ_none) return zsi_fcur_seek_last(fc);
        return zsi_fcur_seek_rev(fc, c->rev_succ, c->rev_succlen, false);
    }

    return c->start_key ? zsi_fcur_seek_rev(fc, c->start_key,
                                            c->start_keylen, true)
                        : zsi_fcur_seek_last(fc);
}

static int zsi_cursor_open(struct zs_db *db, struct zs_txn *txn,
                           struct zsi_snapshot *snap,
                           const char *key, size_t keylen,
                           uint32_t flags, struct zs_cursor **out)
{
    /* A-13: reverse composed with LIVE is rejected, not half-supported. */
    if ((flags & ZS_REVERSE) && (flags & ZS_CURSOR_LIVE)) return ZS_BADUSAGE;

    struct zs_cursor *c = zsi_zmalloc(sizeof(*c));
    if (!c) return ZS_INTERNAL;

    c->db = db;
    c->txn = txn;
    c->reverse = (flags & ZS_REVERSE) != 0;

    /* The cursor takes its OWN reference rather than borrowing the
     * transaction's: D-14j lets a handle-live cursor swap to a newer snapshot,
     * and releasing a borrowed reference would free one the transaction is
     * still pointing at. */
    c->snap = snap;
    c->snap->refcount++;

    /* A reference per file this cursor may read from.  Two jobs at once: it is
     * A-4a's retention for every pointer the cursor yields, and it is what
     * tells the commit-site fold that somebody is reading the active file, so
     * the fold leaves it alone and rebuilds instead (D-13b, G-6).  Without it a
     * commit through the same handle mutates the index and mapping under a
     * cursor whose view G-4 fixes at open. */
    if (zsi_hold_add_snapshot(&c->hold, c->snap) != ZS_OK) return ZS_INTERNAL;
    c->flags = flags;

    /* Take the transaction's change counter NOW.  Starting from zero makes the
     * first step see a false change whenever the transaction already holds a
     * pending write -- and a spurious refresh before anything is emitted is
     * exactly the case that loses the start key. */
    c->txn_seq = zsi_txn_seq(txn);

    if (key && keylen) {
        c->start_key = malloc(keylen);
        if (!c->start_key) { zsi_cursor_free(c); return ZS_INTERNAL; }
        memcpy(c->start_key, key, keylen);
        c->start_keylen = keylen;
    }

    size_t n = snap->nfiles + (txn ? 1 : 0);
    if (n) {
        c->cur = zsi_zmalloc(n * sizeof(*c->cur));
        if (!c->cur) { zsi_cursor_free(c); return ZS_INTERNAL; }
    }

    for (size_t i = 0; i < snap->nfiles; i++)
        zsi_fcur_init_file(&c->cur[c->ncur++], snap->files[i], db->compar);

    if (txn) {
        struct zsi_fcur *fc = &c->cur[c->ncur++];
        memset(fc, 0, sizeof(*fc));
        fc->kind = ZSI_SRC_TXN;
        fc->txn = txn;
        fc->compar = db->compar;
        fc->gen = ZSI_GEN_TXN;
        /* A-4b, and only reachable from the throwaway cursor ZS_FETCHNEXT and
         * ZS_FETCHPREV open and free inside one call (D-14l): the public
         * cursor and foreach forms reject the flag before they get here. */
        fc->ephemeral = (flags & ZS_EPHEMERAL) != 0;
    }

    if ((flags & ZS_SKIPROOT) && key && keylen) {
        c->skiproot_key = malloc(keylen);
        if (!c->skiproot_key) { zsi_cursor_free(c); return ZS_INTERNAL; }
        memcpy(c->skiproot_key, key, keylen);
        c->skiproot_keylen = keylen;
    }

    if (flags & ZS_CURSOR_PREFIX) {
        if (keylen) {
            c->prefix = malloc(keylen);
            if (!c->prefix) { zsi_cursor_free(c); return ZS_INTERNAL; }
            memcpy(c->prefix, key, keylen);
        }
        c->prefixlen = keylen;
    }

    /* D-14k: the byte-successor of the prefix -- increment the last
     * non-0xFF byte and discard everything after it.  All 0xFF has no
     * successor and means "from the end".  Seeking at the prefix ITSELF
     * would be the bug here: the largest key <= the prefix is below every
     * key carrying it (F-11a orders the bare prefix first), so the scan
     * would end before it began unless the bare prefix happened to exist. */
    if (c->reverse && (flags & ZS_CURSOR_PREFIX) && c->prefixlen) {
        size_t n = c->prefixlen;
        while (n && (unsigned char)c->prefix[n - 1] == 0xFF) n--;
        if (!n) {
            c->rev_succ_none = true;
        } else {
            c->rev_succ = malloc(n);
            if (!c->rev_succ) { zsi_cursor_free(c); return ZS_INTERNAL; }
            memcpy(c->rev_succ, c->prefix, n);
            c->rev_succ[n - 1] = (char)((unsigned char)c->rev_succ[n - 1] + 1);
            c->rev_succlen = n;
        }
    }

    for (size_t i = 0; i < c->ncur; i++) {
        c->cur[i].reverse = c->reverse;
        int r = zsi_cursor_seek_arm_start(c, &c->cur[i]);
        if (r != ZS_OK) { zsi_cursor_free(c); return r; }
    }

    zsi_cur_sort(c);

    *out = c;
    return ZS_OK;
}

/* One turn of D-14e's steps 2 through 6.  Returns ZS_OK with a record, or ZS_DONE. */
static int zsi_cursor_step(struct zs_cursor *c, struct zsi_rec *out, bool *emit)
{
    *emit = false;

    /* Step 2, take: the next record is always element 0.  O(1), with no
     * comparison needed to find it. */
    if (!c->ncur || c->cur[0].exhausted) return ZS_DONE;

    struct zsi_rec rec = c->cur[0].cur;


    /* Step 6, bound: for a prefix scan, stop when the emitted key leaves the
     * prefix.  Checked before emitting, so the first out-of-prefix key ends the
     * scan rather than being returned. */
    if ((c->flags & ZS_CURSOR_PREFIX) && c->prefixlen) {
        if (rec.keylen < c->prefixlen
            || memcmp(rec.key, c->prefix, c->prefixlen) != 0)
            return ZS_DONE;
    }

    /* Step 3, skip stale duplicates.  Every cursor positioned on this key is
     * contiguous from the front and element 0 is the newest, so advancing
     * elements 1, 2, ... while their key matches is a COMPLETE treatment.
     *
     * D-14f: advancing only element 0 would leave the same key at another
     * cursor's head, to be emitted again from an OLDER version -- the value
     * before the newest one, which is worse than a duplicate. */
    size_t nstale = 0;
    for (size_t i = 1; i < c->ncur; i++) {
        if (c->cur[i].exhausted) break;
        if (zsi_cmp(c->db->compar, c->cur[i].cur.key, c->cur[i].cur.keylen,
                          rec.key, rec.keylen) != 0)
            break;
        nstale++;
    }

    for (size_t i = 1; i <= nstale; i++) {
        int r = zsi_fcur_next(&c->cur[i]);
        if (r != ZS_OK) return r;
    }

    /* Step 5, advance element 0 and re-sort.  Done before the caller sees the
     * record, so the cursor is always positioned for the next call -- and the
     * record's key and value point into the mapping, which outlives the step. */
    int r = zsi_fcur_next(&c->cur[0]);
    if (r != ZS_OK) return r;

    if (nstale) zsi_cur_sort(c);            /* several moved: full re-sort */
    else        zsi_cur_resort_head(c);     /* just element 0 */

    /* Step 4, filter: if the record is a deletion, emit nothing.  The key is
     * consumed either way, which is what makes a tombstone hide older versions in
     * other files rather than merely being skipped. */
    if (zsi_rec_is_delete(&rec)) return ZS_OK;

    *out = rec;
    *emit = true;
    return ZS_OK;
}

/* Re-seek one arm to just after the last key yielded, against whatever its
 * source holds now.  D-14j-b: resume strictly after, never re-yielding and never
 * skipping a key that was already there.
 *
 * The resume point is the CURSOR's, never the arm's.  An arm has its own notion
 * of position -- the last key consumed from it -- and that position LAGS the
 * merge: an arm that was exhausted at open has consumed nothing at all.
 * Re-positioning an arm from its own state therefore resurfaces any key written
 * into the gap between the two, and the merge hands it out BEHIND the last key
 * yielded: a store made mid-walk at a key already passed comes out of order,
 * shifting the rest of the traversal by one. */
static int zsi_cursor_reseek_arm(struct zs_cursor *c, struct zsi_fcur *fc)
{
    int r;

    /* Before anything has been yielded, the resume point is the OPEN
     * position -- re-derived by the same helper the open used, which for a
     * reverse prefix scan means the byte-successor bound rather than any
     * stale arm state. */
    if (!c->last_key) return zsi_cursor_seek_arm_start(c, fc);

    /* Resume from the last key yielded.  A seek lands ON the key when it is
     * still present, and it has been yielded, so step once past it -- in the
     * direction of travel (D-14j-b, D-14k). */
    if (c->reverse)
        r = zsi_fcur_seek_rev(fc, c->last_key, c->last_keylen, true);
    else
        r = zsi_fcur_seek(fc, c->last_key, c->last_keylen);
    if (r != ZS_OK) return r;

    if (!fc->exhausted
        && zsi_cmp(c->db->compar, fc->cur.key, fc->cur.keylen,
                         c->last_key, c->last_keylen) == 0)
        return zsi_fcur_next(fc);

    return ZS_OK;
}

static int zsi_cursor_reseek(struct zs_cursor *c)
{
    for (size_t i = 0; i < c->ncur; i++) {
        int r = zsi_cursor_reseek_arm(c, &c->cur[i]);
        if (r != ZS_OK) return r;
    }

    zsi_cur_sort(c);
    return ZS_OK;
}

/* A pending write moved only the transaction's own records, so only that arm
 * needs re-seeking; the files cannot have moved.  An in-order file is never
 * modified, a non-active unordered file is never appended to again, and the
 * active file only ever grows by a COMMIT -- which replaces the handle's
 * snapshot and is the other refresh case entirely.
 *
 * That distinction is the difference between one binary search of the pending
 * array and a search through every file per record written mid-walk, which on a
 * large traversal is the whole cost of the liveness mechanism. */
static int zsi_cursor_reseek_txn(struct zs_cursor *c)
{
    for (size_t i = 0; i < c->ncur; i++) {
        if (c->cur[i].kind != ZSI_SRC_TXN) continue;
        int r = zsi_cursor_reseek_arm(c, &c->cur[i]);
        if (r != ZS_OK) return r;
    }

    zsi_cur_sort(c);
    return ZS_OK;
}

/* The half of D-14j's refresh that runs when something HAS changed.
 *
 * Split out so the common answer -- nothing has -- is a few loads inlined into
 * the merge loop, rather than a call into this, which GCC will not inline
 * because of the snapshot rebuild below.  See zsi_cur_order.
 *
 * BOTH conditions are decided by the fast path and passed in, and this function
 * re-derives neither.  The hazard of a split like this is the two halves
 * disagreeing about when there is work to do -- a fast path that wrongly says
 * "nothing" is a cursor that silently stops refreshing (G-4) -- so each question
 * is asked in exactly one place. */
static int zsi_cursor_refresh_slow(struct zs_cursor *c, bool txn_moved,
                                   bool look)
{
    bool files_moved = false;

    /* The transaction's own pending records, whether the transaction is ours or
     * the caller's: A-1a makes a write on it visible to a traversal already in
     * progress on it. */
    if (txn_moved) c->txn_seq = zsi_txn_seq(c->txn);

    /* The file set, but only for a cursor from a DATABASE HANDLE.  Inside an
     * explicit transaction the file set is fixed for the cursor's lifetime
     * (G-4), which is what a transactional read promises.  `look` carries that
     * decision down from the gate; it is not re-asked here. */
    if (look) {
        if (c->flags & ZS_CURSOR_LIVE) {
            /* Still the case that costs, and still a flag -- but C-4i's probe
             * makes each step a few syscalls, not the full snapshot rebuild
             * this used to pay: readers take no lock (C-2), so another
             * process's commit cannot announce itself and the only way to see
             * it is to look. */
            int r = zsi_db_freshen(c->db);
            if (r != ZS_OK) return r;
        }

        if (c->snap != c->db->snap) {
            struct zsi_snapshot *old = c->snap;

            c->db->snap->refcount++;
            c->snap = c->db->snap;
            if (c->txn) zsi_txn_set_snapshot(c->txn, c->snap);

            /* A-4a: NOT a release.  Every pointer this cursor has already
             * yielded points into `old`'s mappings, and they are promised for
             * the cursor's lifetime -- the arms below are rebuilt precisely
             * because they point there too.
             *
             * A failure here can only be the hold list's realloc, and it
             * LEAKS `old` rather than releasing it: releasing would unmap
             * bytes the caller still holds pointers to, and a dangle is worse
             * than a few hundred bytes lost on the way out of an OOM. */
            {
                int hr = zsi_snapshot_retire(&old, &c->hold);
                if (hr != ZS_OK) return hr;
                hr = zsi_hold_add_snapshot(&c->hold, c->snap);
                if (hr != ZS_OK) return hr;
            }

            /* The file arms point into the old snapshot's files, so they must be
             * rebuilt rather than re-seeked. */
            for (size_t i = 0; i < c->ncur; i++) zsi_fcur_fini(&c->cur[i]);
            free(c->cur);
            c->cur = NULL;
            c->ncur = 0;

            {
                size_t n = c->snap->nfiles + (c->txn ? 1 : 0);
                if (n) {
                    c->cur = zsi_zmalloc(n * sizeof(*c->cur));
                    if (!c->cur) return ZS_INTERNAL;
                }
                for (size_t i = 0; i < c->snap->nfiles; i++)
                    zsi_fcur_init_file(&c->cur[c->ncur++], c->snap->files[i],
                                       c->db->compar);
                if (c->txn) {
                    struct zsi_fcur *fc = &c->cur[c->ncur++];
                    memset(fc, 0, sizeof(*fc));
                    fc->kind = ZSI_SRC_TXN;
                    fc->txn = c->txn;
                    fc->compar = c->db->compar;
                    fc->gen = ZSI_GEN_TXN;
                }
                /* Rebuilt arms travel the way the cursor does (D-14k). */
                for (size_t i = 0; i < c->ncur; i++)
                    c->cur[i].reverse = c->reverse;
            }
            files_moved = true;
        }
    }

    /* A snapshot change subsumes a pending-write change: the full re-seek
     * repositions every arm, transaction included. */
    if (files_moved) return zsi_cursor_reseek(c);
    if (txn_moved)   return zsi_cursor_reseek_txn(c);

    return ZS_OK;
}

/* D-14j: has anything this cursor is allowed to observe changed since the last
 * step?  Both checks are a comparison, not a syscall -- ZS_CURSOR_LIVE is the
 * only case that costs, and it is opt-in.
 *
 * The three terms are exactly the three things the slow half acts on: a write to
 * the transaction, a ZS_CURSOR_LIVE cursor (which must go and look, since
 * readers take no lock and a peer's commit cannot announce itself), and the
 * handle having swapped snapshots underneath a handle-live cursor. */
static inline int zsi_cursor_refresh(struct zs_cursor *c)
{
    bool txn_moved = c->txn && zsi_txn_seq(c->txn) != c->txn_seq;
    bool look = c->handle_live && ((c->flags & ZS_CURSOR_LIVE)
                                   || c->snap != c->db->snap);

    if (!txn_moved && !look) return ZS_OK;

    return zsi_cursor_refresh_slow(c, txn_moved, look);
}

static int zsi_cursor_next(struct zs_cursor *c, struct zsi_rec *out)
{
    int rr = zsi_cursor_refresh(c);
    if (rr != ZS_OK) return rr;

    for (;;) {
        bool emit;
        int r = zsi_cursor_step(c, out, &emit);
        if (r != ZS_OK) return r;
        if (emit) {
            /* ZS_SKIPROOT: skip the first record if it matches the start key
             * exactly.  Only the first, and only an exact match. */
            if (!c->started && (c->flags & ZS_SKIPROOT)
                && c->skiproot_key
                && zsi_cmp(c->db->compar, out->key, out->keylen,
                                 c->skiproot_key, c->skiproot_keylen) == 0) {
                c->started = true;
                continue;
            }
            c->started = true;
            c->emitted = *out;
            c->have_emitted = true;

            /* Borrowed, not copied: A-4 already promises these bytes for the
             * whole cursor, and D-14j-b needs them only until the next step.
             * See the last_key comment on struct zs_cursor.  A copy here was
             * two allocator round-trips per record -- about a fifth of the time
             * in a scan profile -- to duplicate a guarantee we already keep. */
            c->last_key = out->keylen ? out->key : NULL;
            c->last_keylen = out->keylen;
            return ZS_OK;
        }
        c->started = true;
    }
}

/********** WRITE PATH *************/

/* Defined further down this section; the streaming store needs them first. */
static int zsi_writer_active(struct zs_db *db, int *fdp, uint32_t *genp);

/* A transaction's own uncommitted records: an ordered KEY -> OFFSET index over
 * records already streamed into the active file (C-8's shape).  The key is an
 * owned copy -- the ordering and the cursor's positions need it -- but the
 * VALUE lives in the file: transaction memory is O(keys), never O(bytes
 * written), so a terabyte transaction does not eat a terabyte of RAM.
 *
 * They are the highest-priority source in D-14's table, visible to subsequent
 * reads on the same transaction and to nothing else until commit (A-1a).
 * A same-key overwrite appends a new record and repoints `off`; the old
 * record becomes a shadowed version in the span, exactly like a shadowed
 * version across spans, and vanishes at the file's next conversion.
 *
 * A SKIPLIST, for two reasons.  A sorted array splices a new key in with a
 * memmove, so its cost depends on the order the keys arrive in: ascending keys
 * land at the end and move nothing, while a key arriving anywhere else moves
 * half the array, making a transaction O(n^2) in its distinct keys.  And a
 * node NEVER MOVES, so a cursor's position can be a pointer -- an array index
 * stops referring to its record the moment an insert shifts the array, which is
 * what D-14j-a had to work around by holding a key and re-resolving it on every
 * step.  Here `struct zsi_fcur`'s transaction half is one pointer, a step is
 * `node->next[0]`, and no write can invalidate an arm.  What remains of D-14j-a
 * is the cursor-level rule that a refresh re-seeks from the CURSOR's resume key
 * (D-14j-b).
 *
 * Level 0 is doubly linked because D-14k walks backwards and a skiplist is
 * otherwise forward-only; `prev` is what makes a reverse step O(1) rather than
 * a fresh search per record. */
#define ZSI_PEND_MAXLEVEL 16     /* 4^16 nodes at p = 1/4, far past any txn */

/* Nodes live in ONE arena and refer to each other by OFFSET.  The arena doubles
 * by realloc, which relocates every node at once and leaves every link correct:
 * a raw pointer would not survive that, an offset does, so a cursor's position
 * stays stable across any write (see struct zsi_fcur).  It also keeps a node
 * and its key to a single allocation.
 *
 * Offset 0 is the null link, so the arena's first 8 bytes are never used.
 *
 * A BOUNDED PREFIX of the key is inlined after the level array -- the whole key
 * when it fits -- so the bytes a descent compares sit beside the links it
 * followed to reach them.  The record holds the key too, but reading it through
 * zsi_txn_at costs a decode and a second cache line per comparison; inlining
 * the whole key instead would make an entry O(keylen), and since values live in
 * the file the pending set is a transaction's entire footprint.  The bound gets
 * both: an entry is at most 112 bytes, and a comparison is decided from the
 * inlined bytes unless BOTH keys are longer than the bound AND equal within it,
 * which is the only case that reads a record.
 *
 * 64 rather than something smaller because a key at or under the bound is
 * inlined WHOLE and never reads a record at all, and 64 covers the common
 * shapes: 12-byte rowid keys, 30-60 byte index keys, most mailbox names.  Keys
 * with a long structured head are the ones that fall through to the record.
 * The inline is VARIABLE-LENGTH, not a slot: a 12-byte key costs 12 bytes.
 *
 * The inlined bytes MOVE with the arena, which is safe because every borrow is
 * read inside the call that took it.  Nothing holds a pending key across a
 * store, which is the only thing that grows the arena; the cursor's D-14j-b
 * resume key is borrowed from a RECORD, not from here. */
#define ZSI_PEND_KPREFIX 64
struct zsi_pnode {
    size_t off;                       /* record offset in the active file */
    size_t len;                       /* its encoded length */
    size_t prev;                      /* arena offset, 0 = none (level 0) */
    size_t keylen;                    /* the WHOLE key's length */
    size_t nlevels;
    size_t next[];                    /* nlevels links, then min(keylen,
                                         ZSI_PEND_KPREFIX) key bytes */
};

/* One read-only mapping of the active file.  A transaction accumulates these
 * and unmaps NOTHING until it ends: that is what keeps every pointer any of
 * its reads returned valid for its whole lifetime (A-4) with no copies. */
struct zsi_txnmap {
    char  *base;
    size_t len;
};

struct zs_txn {
    struct zs_db        *db;
    struct zsi_snapshot *snap;        /* the transaction's fixed snapshot */

    /* Every flag and small counter together: scattered among the pointers they
     * cost 20 bytes of padding, and this struct's SIZE is on the read path --
     * zs_db_begin_cursor makes an implicit transaction, so every cursor
     * allocates one.  Nothing here is on-disk layout, which G-0 keeps in
     * explicit memcpy at literal offsets. */
    bool                 readonly;
    bool                 holds_write_lock;

    /* Created by a zs_db_* wrapper rather than by the caller (A-0), which is
     * what makes its cursors observe this handle's later commits (D-14j). */
    bool                 implicit;
    bool                 broken;      /* a stream failure poisoned the span:
                                         commit MUST refuse (see zsi_pend_set) */
    int                  plevel;      /* pending set: levels in use */
    int                  wfd;         /* -1 until the first store */
    uint32_t             wgen;        /* generation being appended to */
    unsigned             wcsum_id;
    unsigned             nmaps, amaps;

    /* The pending set (see struct zsi_pnode): a skiplist in one arena, and
     * every reference to a node is an OFFSET into it.
     *
     * The LEVEL HEADS live at the head of the arena rather than here: inline
     * they are 128 bytes in every transaction, and a READ transaction never
     * stores.  The arena is allocated on the first store, so a read transaction
     * has no pending set at all. */
    char                *parena;
    size_t               pused, pcap;
    size_t               ptail;       /* for a reverse walk's start (D-14k) */
    size_t               npend;
    uint64_t             prand;       /* level generator, seeded at begin */

    /* Bumped on every change to the pending set.  A cursor over this
     * transaction caches the arm's current record, so it needs to know when
     * that cache is stale -- and comparing a counter is free (D-14j). */
    unsigned long        pend_seq;

    /* Streaming state (C-8).  The active file is chosen at the FIRST store --
     * the write lock is held from begin, so D-9's rules apply identically,
     * only the moment moves -- and records are appended as they are stored,
     * through a small chunk buffer that is flushed whenever a read needs
     * bytes it still holds.
     *
     * wsize is the file's logical size including the unflushed chunk;
     * flushed is what has reached the fd.  A read maps the file on demand,
     * each new mapping at least DOUBLING the last (and mapping ahead of EOF,
     * which MAP_SHARED fills in as the file grows), so a transaction holds
     * O(log bytes) mappings -- which is why nmaps and amaps are `unsigned`
     * above and not size_t -- and unmaps none of them until it ends (A-4). */
    zs_csum             *wcs;         /* the FILE's engine (A-6, F-5a) */
    size_t               span_base;   /* where this transaction's span begins */
    size_t               wsize;
    size_t               flushed;
    char                *chunk;
    size_t               chunklen, chunkcap;
    struct zsi_txnmap   *maps;

    /* A-4a: mappings from the snapshot this transaction swapped away from at
     * its first store, kept until it ends.  The other half of the same
     * promise `maps` keeps for the transaction's own streamed records. */
    struct zsi_hold      hold;
};

/* Resolving an offset, and where a node keeps its key.  Macros rather than
 * functions so a descent's inner loop is two adds. */
#define ZSI_PN(txn, o)      ((struct zsi_pnode *)((txn)->parena + (o)))
/* The level heads, at a fixed offset in the arena.  Offset 0 stays the null
 * link, so the heads begin at 8 and the first node after them. */
#define ZSI_PHEAD_OFF       8
#define ZSI_PHEAD(txn)      ((size_t *)((txn)->parena + ZSI_PHEAD_OFF))
#define ZSI_PEND_HDRLEN     (ZSI_PHEAD_OFF + ZSI_PEND_MAXLEVEL * sizeof(size_t))
#define ZSI_PN_KEY(n)       ((const char *)((n)->next + (n)->nlevels))

/* Defined in the streaming section below: the pending set reads a record when
 * its inlined prefix cannot settle a comparison, and the streamer is what knows
 * where a record's bytes currently are (mapped, or still in the chunk). */
static const char *zsi_txn_at(struct zs_txn *txn, size_t off, size_t len,
                              bool ephemeral);

/* The full key of the record a node points at, for the cases the inlined prefix
 * cannot settle.
 *
 * Ephemeral (A-4b) deliberately: the answer is used inside the call that asks,
 * and asking any other way would flush the chunk buffer to look at a record this
 * transaction just wrote -- the 300k-write() bug the pending set exists to
 * avoid.  On a derivation failure it reports an empty key rather than an error,
 * which is what zsi_index_key_at does and for the same reason: a comparison has
 * nowhere to return one, and the only way here is an mmap failure. */
static void zsi_pend_key(struct zs_txn *txn, size_t o, const char **kp,
                         size_t *klp)
{
    struct zsi_pnode *n = ZSI_PN(txn, o);
    struct zsi_rec r;
    const char *b = zsi_txn_at(txn, n->off, n->len, true);

    if (!b || zsi_rec_decode(b, n->len, &r) != ZS_OK) {
        *kp = "";
        *klp = 0;
        return;
    }

    *kp = r.key;
    *klp = r.keylen;
}

/* Order a node against a key, from the inlined prefix where that is enough.
 *
 * F-11a is memcmp over the common prefix, then shorter-key-first, so a
 * difference inside the prefix IS the answer and needs nothing more.  Equality
 * across the compared span leaves three cases, and two of them are still
 * decidable: if the node's whole key is inlined the length rule settles it, and
 * if the SEARCH key ended inside the prefix then the node's key is longer.  Only
 * two keys that both run past the bound and agree within it need the record.
 *
 * A caller-supplied comparator may order by anything at all, so nothing can be
 * inferred from a prefix for it -- it takes the full key, every time.  Same
 * split as zsi_cmp, and the same reason. */
/* The long half, split out so the common one inlines into the descent: a
 * comparison happens ~log n times per store, and GCC will not inline a function
 * carrying the derivation below.  Same shape as zsi_cursor_refresh's gate.
 *
 * Longer than the bound, so only a prefix is on hand.  F-11a is memcmp over
     * the common prefix and then shorter-key-first, so a difference inside the
     * prefix IS the answer, and a search key that ended inside it is the
     * shorter of the two.  Only two keys that both run past the bound and agree
     * within it need the record.
     *
     * None of that follows for a CALLER's comparator, which may order by
     * anything at all -- it takes the full key, every time.  Same split as
     * zsi_cmp, and the same reason. */
static int zsi_pend_cmp_long(struct zs_txn *txn, size_t o, const char *key,
                             size_t keylen)
{
    struct zsi_pnode *n = ZSI_PN(txn, o);
    const char *nk;
    size_t nkl;

    if (txn->db->compar == zsi_compar_default) {
        size_t m = keylen < ZSI_PEND_KPREFIX ? keylen : ZSI_PEND_KPREFIX;
        int c = m ? memcmp(ZSI_PN_KEY(n), key, m) : 0;

        if (c) return c < 0 ? -1 : 1;
        if (keylen <= ZSI_PEND_KPREFIX) return 1;   /* the search key is shorter */

        /* Equal within the bound, so the record settles it -- resuming PAST the
         * bytes already known equal rather than repeating them, which would
         * make this cost strictly more than storing no prefix at all. */
        zsi_pend_key(txn, o, &nk, &nkl);
        if (nkl < ZSI_PEND_KPREFIX)                 /* derivation failed */
            return nkl < keylen ? -1 : 1;
        {
            size_t ra = nkl - ZSI_PEND_KPREFIX;
            size_t rb = keylen - ZSI_PEND_KPREFIX;
            size_t rm = ra < rb ? ra : rb;
            int rc = rm ? memcmp(nk + ZSI_PEND_KPREFIX,
                                 key + ZSI_PEND_KPREFIX, rm) : 0;
            if (rc) return rc < 0 ? -1 : 1;
            return ra < rb ? -1 : ra > rb ? 1 : 0;
        }
    }

    zsi_pend_key(txn, o, &nk, &nkl);
    return zsi_cmp(txn->db->compar, nk, nkl, key, keylen);
}

/* Order a node against a key.  The whole key is inlined at or under the bound,
 * which is the common case and the only one on the hot path: the ordinary
 * comparison, whatever the comparator, with nothing inferred and no record
 * read. */
static inline int zsi_pend_cmp(struct zs_txn *txn, size_t o, const char *key,
                               size_t keylen)
{
    struct zsi_pnode *n = ZSI_PN(txn, o);

    if (n->keylen <= ZSI_PEND_KPREFIX)
        return zsi_cmp(txn->db->compar, ZSI_PN_KEY(n), n->keylen, key, keylen);

    return zsi_pend_cmp_long(txn, o, key, keylen);
}

/* Room for `need` more bytes, 8-aligned.  Reserved BEFORE the record is
 * streamed, because a streamed record must be indexed: everything that can fail
 * has to fail first.  The bump itself cannot. */
static int zsi_pend_reserve(struct zs_txn *txn, size_t need)
{
    size_t want;

    if (!txn->pused) need += ZSI_PEND_HDRLEN;   /* the header comes first */
    if (!zsi_add_sz(txn->pused, need, &want)) return ZS_INTERNAL;
    if (want <= txn->pcap) return ZS_OK;

    size_t cap = txn->pcap ? txn->pcap : 1024;
    while (cap < want) {
        if (cap > SIZE_MAX / 2) return ZS_INTERNAL;
        cap *= 2;
    }

    char *p = realloc(txn->parena, cap);
    if (!p) return ZS_INTERNAL;

    txn->parena = p;
    txn->pcap = cap;

    /* The first growth lays down the header: the null word at offset 0, then
     * the level heads, all zero.  Nodes begin above it. */
    if (!txn->pused) {
        memset(p, 0, ZSI_PEND_HDRLEN);
        txn->pused = ZSI_PEND_HDRLEN;
    }

    return ZS_OK;
}

/* The first node with key >= the given one, or 0 past the end.
 *
 * `update`, when asked for, is the descent path: the last node strictly below
 * the key at each level, 0 meaning the head.  An insert splices into exactly
 * those links, which is why the search and the insert are one walk. */
static size_t zsi_pend_lb(struct zs_txn *txn, const char *key,
                          size_t keylen, size_t *update)
{
    size_t x = 0, n = 0;

    for (int lv = txn->plevel - 1; lv >= 0; lv--) {
        /* x was reached AT this level or above, so its next[lv] is in range. */
        n = x ? ZSI_PN(txn, x)->next[lv] : ZSI_PHEAD(txn)[lv];
        while (n) {
            /* The node is loaded ONCE and used for both the comparison and the
             * link -- the compare through zsi_pend_cmp instead re-resolved the
             * offset every iteration, which is a load of txn->parena and an add
             * per step of the descent. */
            struct zsi_pnode *p = ZSI_PN(txn, n);
            int c = p->keylen <= ZSI_PEND_KPREFIX
                  ? zsi_cmp(txn->db->compar, ZSI_PN_KEY(p), p->keylen,
                            key, keylen)
                  : zsi_pend_cmp_long(txn, n, key, keylen);
            if (c >= 0) break;
            x = n;
            n = p->next[lv];
        }
        if (update) update[lv] = x;
    }

    return n;               /* level 0's candidate, or 0 for an empty list */
}

/* The largest key <= (inclusive) or < (exclusive) the given one: a reverse
 * seek's landing point (D-14k).  The lower bound's PREDECESSOR is the strictly
 * smaller answer, and it is already linked at level 0. */
static size_t zsi_pend_lt(struct zs_txn *txn, const char *key,
                          size_t keylen, bool inclusive)
{
    size_t n = zsi_pend_lb(txn, key, keylen, NULL);

    if (!n) return txn->ptail;
    if (inclusive && zsi_pend_cmp(txn, n, key, keylen) == 0) return n;
    return ZSI_PN(txn, n)->prev;
}

/* A node's level: geometric with p = 1/4, from a per-transaction xorshift.
 *
 * Deterministic on purpose -- a level depends on nothing but the sequence, so
 * there is no input that can degrade the structure, and a reproducible shape is
 * worth more here than an unpredictable one.  No syscall either: zsi_random_bytes
 * reads /dev/urandom, which is fine once per database and not once per store. */
static int zsi_pend_level(struct zs_txn *txn)
{
    int lv = 1;

    while (lv < ZSI_PEND_MAXLEVEL) {
        txn->prand ^= txn->prand << 13;
        txn->prand ^= txn->prand >> 7;
        txn->prand ^= txn->prand << 17;
        if ((txn->prand & 3) != 0) break;
        lv++;
    }

    return lv;
}

/* Bytes a node of `lv` levels holding `keylen` key bytes occupies, rounded so
 * the next node is 8-aligned. */
static size_t zsi_pend_nodelen(int lv, size_t keylen)
{
    size_t n;
    if (keylen > ZSI_PEND_KPREFIX) keylen = ZSI_PEND_KPREFIX;
    if (!zsi_add3_sz(sizeof(struct zsi_pnode), (size_t)lv * sizeof(size_t),
                     keylen, &n))
        return 0;
    return zsi_roundup8(n);
}

/* Splice a node for a key the caller has established is absent, at the descent
 * path the caller's own lower-bound walk produced.  Cannot fail -- the arena was
 * reserved before the record was streamed.
 *
 * `update` comes from the caller because the walk that found the key ABSENT is
 * the same walk that says where to splice it, and a store used to do both: one
 * descent to look the key up and a second one here.  What makes handing the path
 * over safe is the property the arena was built for -- a link is an OFFSET, so
 * the realloc that the reservation may perform in between moves every node and
 * invalidates none of the path.
 *
 * The path must be ZSI_PEND_MAXLEVEL entries with 0 for "from the head": a walk
 * only fills levels below plevel, and this node's level may be above it. */
static size_t zsi_pend_link(struct zs_txn *txn, const char *key, size_t keylen,
                            int lv, size_t off, size_t len,
                            const size_t *update)
{
    size_t at = txn->pused;
    struct zsi_pnode *n;

    txn->pused += zsi_pend_nodelen(lv, keylen);

    n = ZSI_PN(txn, at);
    n->off = off;
    n->len = len;
    n->keylen = keylen;
    n->nlevels = (size_t)lv;
    memcpy((char *)ZSI_PN_KEY(n), key,
           keylen < ZSI_PEND_KPREFIX ? keylen : ZSI_PEND_KPREFIX);

    /* Levels above the current top are reached from the head, and update[] is
     * already 0 there. */
    if (lv > txn->plevel) txn->plevel = lv;

    for (int i = 0; i < lv; i++) {
        size_t p = update[i];
        n->next[i] = p ? ZSI_PN(txn, p)->next[i] : ZSI_PHEAD(txn)[i];
        if (p) ZSI_PN(txn, p)->next[i] = at;
        else   ZSI_PHEAD(txn)[i] = at;
    }

    n->prev = update[0];
    if (n->next[0]) ZSI_PN(txn, n->next[0])->prev = at;
    else            txn->ptail = at;

    txn->npend++;
    return at;
}

static void zsi_pend_clear(struct zs_txn *txn)
{
    free(txn->parena);
    txn->parena = NULL;
    txn->pused = txn->pcap = 0;

    txn->ptail = 0;
    txn->plevel = 0;
    txn->npend = 0;
}

/* Flush the chunk buffer to the fd.  Called before any read that needs bytes
 * the buffer still holds, and at every terminator. */
static int zsi_txn_flush(struct zs_txn *txn)
{
    if (!txn->chunklen) return ZS_OK;
    int r = zsi_write_all(txn->wfd, txn->chunk, txn->chunklen);
    if (r != ZS_OK) {
        /* A partial write leaves bytes in the file that `flushed` does not
         * count, so from here on nothing may reason from `flushed` about what
         * the file holds.  POISON the span: commit must refuse (C-8), and
         * C-8b's discard must not conclude the span never reached the file.
         *
         * Set here rather than at the call sites because there are three, and
         * the one that read a record (zsi_txn_at) used to drop this on the
         * floor -- it returns NULL on a failed flush and left the transaction
         * committable over a possibly-torn span. */
        txn->broken = true;
        return r;
    }
    txn->flushed += txn->chunklen;
    txn->chunklen = 0;
    return ZS_OK;
}

/* Append bytes to the transaction's stream, batching small records so a
 * store is not a syscall. */
static int zsi_txn_stream(struct zs_txn *txn, const char *buf, size_t len)
{
    /* Prefer GROWING to flushing, up to the cap.  A span that never leaves the
     * buffer is written once, with its terminator, at commit; flushing here is
     * what forfeits that.  Doubling keeps it amortised, and a transaction that
     * reaches the cap simply behaves as it always did.
     *
     * Reallocating is safe against A-4b, the one promise that hands out a pointer
     * INTO this buffer: an ephemeral result lives only until the next call on the
     * transaction, and this IS that next call.  Every other reader of the chunk
     * (zsi_txn_at without the flag, zsi_txn_terminate) flushes or runs with no
     * store in between.
     *
     * A failed grow is not an error -- fall through and flush, exactly as before. */
    if (txn->chunklen + len > txn->chunkcap && txn->chunkcap < ZSI_TXN_CHUNK_MAX) {
        size_t want = txn->chunkcap;
        while (want < txn->chunklen + len && want < ZSI_TXN_CHUNK_MAX)
            want *= 2;
        if (want > ZSI_TXN_CHUNK_MAX) want = ZSI_TXN_CHUNK_MAX;
        if (want > txn->chunkcap && txn->chunklen + len <= want) {
            char *grown = realloc(txn->chunk, want);
            if (grown) {
                txn->chunk = grown;
                txn->chunkcap = want;
            }
        }
    }

    if (txn->chunklen + len > txn->chunkcap) {
        int r = zsi_txn_flush(txn);
        if (r != ZS_OK) return r;
        if (len >= txn->chunkcap) {
            r = zsi_write_all(txn->wfd, buf, len);
            if (r != ZS_OK) return r;
            txn->flushed += len;
            txn->wsize += len;
            return ZS_OK;
        }
    }
    memcpy(txn->chunk + txn->chunklen, buf, len);
    txn->chunklen += len;
    txn->wsize += len;
    return ZS_OK;
}

/* Bytes [off, off+len) of the active file, valid until the TRANSACTION ends --
 * or, when `ephemeral`, only until the caller's next call (A-4b).
 *
 * This is A-4's mechanism for the transaction's own records: mappings
 * accumulate -- each new one at least doubles the last and may extend past
 * the current EOF, which MAP_SHARED fills in as the file grows -- and none
 * is unmapped until the transaction ends, so no pointer a read returned is
 * ever invalidated.  O(log bytes) mappings, total address space at most a
 * small multiple of the final size, zero copies.  Never dereferences past
 * wsize, so the beyond-EOF tail of a mapping is never touched. */
static const char *zsi_txn_at(struct zs_txn *txn, size_t off, size_t len,
                              bool ephemeral)
{
    size_t need = off + len;

    if (need < off) return NULL;                    /* overflow */
    if (need > txn->wsize) return NULL;

    /* A-4b: a caller that only needs the bytes until its next call can have
     * them where they already are, and the chunk keeps filling.  This is the
     * whole point of the flag: without it a read of a record this transaction
     * just stored costs one write(2), so read-after-write defeats the write
     * combining entirely -- 100k flushes instead of 135 over 100k records.
     *
     * Sound because a record NEVER STRADDLES the boundary: zsi_txn_append
     * flushes first and then copies the record in whole, or writes it straight
     * through when it is too big for the chunk at all.  So a range at or above
     * `flushed` is either wholly buffered or wholly beyond wsize, which the
     * check above has already rejected.  A range that is partly below
     * `flushed` therefore cannot exist, and needs no case here. */
    if (ephemeral && off >= txn->flushed
        && need <= txn->flushed + txn->chunklen)
        return txn->chunk + (off - txn->flushed);

    /* Flush BEFORE the covering-mapping early return: a record still in the
     * chunk buffer is not in the file yet, and a mapping large enough to
     * cover its offset happily shows the stale bytes there instead. */
    if (need > txn->flushed && zsi_txn_flush(txn) != ZS_OK) return NULL;

    if (txn->nmaps && need <= txn->maps[txn->nmaps - 1].len)
        return txn->maps[txn->nmaps - 1].base + off;

    size_t want = need;
    if (txn->nmaps && want < txn->maps[txn->nmaps - 1].len * 2)
        want = txn->maps[txn->nmaps - 1].len * 2;
    if (want < (size_t)1 << 20) want = (size_t)1 << 20;

    if (txn->nmaps == txn->amaps) {
        size_t grow = txn->amaps ? txn->amaps * 2 : 8;
        struct zsi_txnmap *p = realloc(txn->maps, grow * sizeof(*p));
        if (!p) return NULL;
        txn->maps = p;
        txn->amaps = grow;
    }

    void *m = mmap(NULL, want, PROT_READ, MAP_SHARED, txn->wfd, 0);
    if (m == MAP_FAILED) {
        /* Mapping ahead of EOF can be refused; the exact size cannot, short
         * of a real failure. */
        want = need;
        m = mmap(NULL, want, PROT_READ, MAP_SHARED, txn->wfd, 0);
        if (m == MAP_FAILED) return NULL;
    }

    txn->maps[txn->nmaps].base = (char *)m;
    txn->maps[txn->nmaps].len = want;
    txn->nmaps++;

    return txn->maps[txn->nmaps - 1].base + off;
}

/* First store: choose the file this transaction streams into (D-9 applied at
 * the first store rather than at commit -- the write lock is held from begin,
 * so only the moment moves), pin the snapshot the rollover may have replaced,
 * and record the FILE's checksum engine (A-6, F-5a): using the handle's
 * engine to checksum a span appended to a file recording a different one is
 * silent data loss -- the terminator validates under neither, so the next
 * reader rejects the whole span (F-22 doing its job). */
static int zsi_txn_stream_begin(struct zs_txn *txn)
{
    struct zs_db *db = txn->db;

    if (txn->wfd >= 0) return ZS_OK;

    int fd;
    uint32_t gen;
    int r = zsi_writer_active(db, &fd, &gen);
    if (r != ZS_OK) return r;

    /* The snapshot may have been replaced by a rollover, and both the
     * ancestor search and this transaction's own reads must see the file set
     * as it is now.
     *
     * A-4a: the outgoing snapshot is RETIRED, not released.  A caller that
     * read before its first write -- read-modify-write, the ordinary shape --
     * holds pointers into its mappings, and A-4 promised them for the whole
     * transaction.  Releasing here would unmap them, on every first store that
     * starts a new generation -- and after a seal there is no active file at
     * all, so the very next transaction takes that path. */
    /* Only when it actually MOVED.  zsi_writer_active refreshes just on the
     * new-generation path, so the ordinary append leaves db->snap exactly where
     * this transaction already is -- and retiring that would hand our own
     * reference to the hold list and take a fresh one, leaving the snapshot
     * with an extra reference for the rest of the transaction.  The commit-site
     * fold reads refcount == 2 as "nobody else is looking" (D-13b, G-6), so the
     * inflated count silently demotes every commit to a full rebuild. */
    if (db->snap != txn->snap) {
        int hr = zsi_snapshot_retire(&txn->snap, &txn->hold);
        if (hr != ZS_OK) { close(fd); return hr; }
        txn->snap = db->snap;
        txn->snap->refcount++;
    }

    struct zsi_file *act = zsi_snapshot_active(db->snap);
    zs_csum *cs = act && act->hdr_valid
                ? act->csum
                : zsi_csum_for_id(db->create_csum_id, db->external_csum);
    unsigned csum_id = act && act->hdr_valid ? act->csum_id
                                             : db->create_csum_id;
    if (!cs) { close(fd); return ZS_BADUSAGE; }

    struct stat sb;
    if (fstat(fd, &sb) < 0) { close(fd); return ZS_IOERROR; }

    if (!txn->chunk) {
        txn->chunk = malloc(ZSI_TXN_CHUNK);
        if (!txn->chunk) { close(fd); return ZS_INTERNAL; }
        txn->chunkcap = ZSI_TXN_CHUNK;
    }

    txn->wfd = fd;
    txn->wgen = gen;
    txn->wcs = cs;
    txn->wcsum_id = csum_id;
    txn->span_base = (size_t)sb.st_size;
    txn->wsize = (size_t)sb.st_size;
    txn->flushed = (size_t)sb.st_size;

    return ZS_OK;
}

/* Record a write.  val == NULL is a deletion; a non-NULL zero-length value is an
 * empty value, and the two are distinct states (A-1, F-14).
 *
 * The record is encoded and STREAMED here (C-8); only the key and the record's
 * offset are kept.  Encoding consults nothing outside its arguments (F-18):
 * this used to resolve the record's ancestor first, which meant a point lookup
 * across the whole file set on EVERY store -- creates included, and those miss
 * in every file so they had no early exit at all.  What that answered is now
 * derived at repack time instead (D-19). */
static int zsi_pend_set(struct zs_txn *txn, const char *key, size_t keylen,
                        const char *val, size_t vallen)
{
    /* ONE descent, whichever way it turns out: it answers "is this key already
     * pending" and, if it is not, where to splice it.  Those were a descent each
     * until 2026-08-17, and the second was invisible in every store benchmark's
     * shape -- once the D-13b fold stopped dominating a bulk load, zsi_pend_lb
     * and the memcmp under it were its largest cost that is not a syscall, at
     * about 19% of a profile between them.
     *
     * Worth 2.92M to 4.18M records/s on 200k records in one transaction, and
     * about 15% at 1000 records per transaction: the descent is O(log n) in the
     * transaction's keys, so the saving grows with the batch and is largest for
     * keys that do not arrive in order, where a descent walks furthest. */
    size_t update[ZSI_PEND_MAXLEVEL];
    size_t found;

    for (int i = 0; i < ZSI_PEND_MAXLEVEL; i++) update[i] = 0;
    found = zsi_pend_lb(txn, key, keylen, update);
    if (found && zsi_pend_cmp(txn, found, key, keylen) != 0) found = 0;

    /* Bumped up front so every early return below still counts as a change:
     * an over-count costs one wasted reload, an under-count costs a cursor that
     * misses a write, and only one of those is a bug (D-14j). */
    txn->pend_seq++;

    int r = zsi_txn_stream_begin(txn);
    if (r != ZS_OK) return r;

    size_t n = zsi_rec_encoded_len(keylen, vallen, val == NULL);
    if (!n) return ZS_BADUSAGE;

    /* One record's transient encode buffer -- the only per-store allocation
     * proportional to the VALUE, gone before this returns. */
    char *rec = malloc(n);
    if (!rec) return ZS_INTERNAL;
    zsi_rec_encode(rec, key, keylen, val, vallen);

    /* EVERYTHING fallible happens before the stream: a streamed record MUST
     * be indexed, or this handle's fold at commit would disagree with every
     * other reader's replay of the same span. */
    /* The level is drawn HERE, not at link time, because the arena reservation
     * depends on it and the reservation is what can fail. */
    int lv = 0;
    if (!found) {
        size_t need;
        lv = zsi_pend_level(txn);
        need = zsi_pend_nodelen(lv, keylen);
        if (!need) { free(rec); return ZS_INTERNAL; }
        r = zsi_pend_reserve(txn, need);
        if (r != ZS_OK) { free(rec); return r; }
    }

    size_t off = txn->wsize;
    r = zsi_txn_stream(txn, rec, n);
    free(rec);
    if (r != ZS_OK) {
        /* A short write may have left a torn record inside the span.  The
         * transaction is POISONED: commit must refuse, because a COMMIT
         * terminator over a torn record makes replay complete the file at
         * the tear (F-24) and lose the span. */
        txn->broken = true;
        /* The reservation stays -- it is capacity, not a node.  Nothing was
         * linked, so the key is absent, which is what a caller reading a
         * poisoned transaction should see. */
        return r;
    }

    if (found) {
        ZSI_PN(txn, found)->off = off;
        ZSI_PN(txn, found)->len = n;
        return ZS_OK;
    }

    zsi_pend_link(txn, key, keylen, lv, off, n, update);

    return ZS_OK;
}

/* The transaction arm of the per-file cursor (declared in PER-FILE CURSOR).
 *
 * Presenting pending records through the same interface as a file is what lets
 * D-14g work by sorting rather than by a special case in the merge. */
static unsigned long zsi_txn_seq(struct zs_txn *txn)
{
    return txn ? txn->pend_seq : 0;
}

static void zsi_txn_set_snapshot(struct zs_txn *txn, struct zsi_snapshot *snap)
{
    if (!txn) return;
    zsi_snapshot_release(&txn->snap);
    txn->snap = snap;
    txn->snap->refcount++;
}

/* The node this cursor is positioned on, without touching a byte of the record.
 * Both the load below and the exact-match test in zsi_fcur_find go through here
 * so they cannot disagree about WHERE the cursor is -- which matters more than
 * it looks, since the two would then answer for different records and a lookup
 * would return the wrong value.
 *
 * A node, not an index.  This used to resolve a KEY against the pending array on
 * every load, because an array index stops referring to its record the moment an
 * insert shifts the array (D-14j-a) -- a binary search per step, with a cached
 * index behind two guards no test could reach through a cursor.  A skiplist node
 * never moves and is freed only when the transaction ends, so the position is
 * simply the node, and a write cannot invalidate it. */
static bool zsi_txn_cur_at(struct zsi_fcur *fc, struct zsi_pnode **np)
{
    if (!fc->txn || !fc->u.t.node) return false;
    *np = ZSI_PN(fc->txn, fc->u.t.node);
    return true;
}

/* Order the record at the cursor's position against a key, without touching a
 * byte of it when the inlined prefix is enough (zsi_pend_cmp).
 *
 * The point is that a MISS costs nothing.  Materialising the record would call
 * zsi_txn_at, and a record still in the writer's chunk buffer gets flushed to
 * the file just to be looked at -- so a lookup that misses would pay a write(2)
 * for a record it then discards, and a bulk load probing for keys it is about to
 * insert misses on nearly every one. */
static bool zsi_txn_cur_cmp(struct zsi_fcur *fc, const char *key, size_t keylen,
                            int *cmp)
{
    if (!fc->txn || !fc->u.t.node) return false;
    *cmp = zsi_pend_cmp(fc->txn, fc->u.t.node, key, keylen);
    return true;
}

static int zsi_txn_cur_load(struct zsi_fcur *fc)
{
    struct zs_txn *txn = fc->txn;
    struct zsi_pnode *n;

    if (!zsi_txn_cur_at(fc, &n)) {
        fc->exhausted = true;
        return ZS_OK;
    }

    /* The record was streamed to the active file when it was stored (C-8);
     * decode it back through the transaction's accumulated mappings, whose
     * pointers live until the transaction ends (A-4) -- or straight out of the
     * chunk buffer, if whoever opened this source accepted A-4b's shorter
     * lifetime. */
    const char *b = zsi_txn_at(txn, n->off, n->len, fc->ephemeral);
    if (!b || zsi_rec_decode(b, n->len, &fc->cur) != ZS_OK) {
        fc->exhausted = true;
        return ZS_IOERROR;
    }
    fc->exhausted = false;

    return ZS_OK;
}

/* Seek to the first pending record with key >= the given key.
 *
 * Resolved to a NODE here rather than recorded as a key to resolve later.  The
 * deferral existed because the array could move between the seek and the load;
 * a node cannot, and every caller loads immediately anyway (zsi_fcur_seek ends
 * in zsi_fcur_load).  A seek lands ON the key when it is present, and it is the
 * caller -- zsi_cursor_reseek_arm, for D-14j-b -- that steps past it if that key
 * has already been yielded. */
static void zsi_txn_cur_seek(struct zsi_fcur *fc, const char *key, size_t keylen)
{
    if (!fc->txn) { fc->u.t.node = 0; return; }

    if (!key || !keylen) {         /* from the beginning */
        fc->u.t.node = fc->txn->parena ? ZSI_PHEAD(fc->txn)[0] : 0;
        return;
    }

    fc->u.t.node = zsi_pend_lb(fc->txn, key, keylen, NULL);
}

/* One step in the cursor's direction.  The whole of it: a node is stable, so
 * there is nothing to re-resolve and no search to repeat.  Lives here rather
 * than in zsi_fcur_next so struct zsi_pnode stays private to the write path,
 * exactly as struct zs_txn does. */
static void zsi_txn_cur_step(struct zsi_fcur *fc)
{
    if (!fc->u.t.node) return;
    struct zsi_pnode *n = ZSI_PN(fc->txn, fc->u.t.node);
    fc->u.t.node = fc->reverse ? n->prev : n->next[0];
}

/* Reverse seek: largest pending key <= (inclusive) or < the given key.  A NULL
 * key means "after the last" here, since a reverse walk begins at the top
 * (D-14k) -- which is the tail, kept for exactly this. */
static void zsi_txn_cur_seek_rev(struct zsi_fcur *fc, const char *key,
                                 size_t keylen, bool inclusive)
{
    if (!fc->txn) { fc->u.t.node = 0; return; }

    if (!key || !keylen) {
        fc->u.t.node = fc->txn->ptail;
        return;
    }

    fc->u.t.node = zsi_pend_lt(fc->txn, key, keylen, inclusive);
}

/* Defined in CONVERSION.  D-12 requires a writer convert any non-active unordered
 * file BEFORE IT FINISHES, so the call belongs at the end of a commit -- which
 * means this one forward declaration, since conversion needs the write path's file
 * writer in turn. */
static int zsi_convert_pending(struct zs_db *db);

/* D-16e: a write transaction runs the repack cascade before it takes the write
 * lock.  Declared here because the REPACK section is below this one. */
static bool zsi_should_repack(struct zsi_snapshot *snap, size_t cap);
static int  zsi_repack(struct zs_db *db);

/* D-12b/D-10: the writer frees the active-file name before reusing it. */
static int zsi_convert_one(struct zs_db *db, struct zsi_file *f);
static int zsi_remove_file(struct zs_db *db, const char *name);
static int zsi_convert_one(struct zs_db *db, struct zsi_file *f);

/* Choose the file a write transaction will append to (D-9).
 *
 * While holding the write lock, a writer MUST either append to a CLEAN active
 * file, or create a new unordered file whose generation is exactly one higher,
 * write a valid header, and append there.
 *
 * D-9a: it moves on when the active file is not clean, or when it exceeds
 * rollover_size.  Rollover is cheap -- a new header and nothing else, since the
 * writer never appends a pointer section to an unordered file (D-11).
 *
 * D-10 and R-4: an unclean file is not repaired.  Because it is not clean the
 * writer moves on, so no chain is ever built on an untrustworthy boundary. */
/* Whether the active file has reached the point where a writer moves on: too
 * many BYTES (D-9a), or too many spans in the replay window (D-9d).
 *
 * One predicate rather than the condition written out at each site, because
 * there are four of them -- the rollover below, the repack cascade's
 * new-generation probe, D-25d's commit-site seal, and the oversized-file
 * fallback -- and they MUST agree.  Teach one half of the condition to only
 * some of them and the writer oscillates: the seal fires on a span-bound file
 * while zsi_writer_active goes on appending to the file it just sealed. */
static bool zsi_active_full(const struct zs_db *db, const struct zsi_file *f)
{
    return f->size >= db->rollover_size || f->nspans >= db->rollover_txns;
}

static int zsi_writer_active(struct zs_db *db, int *fdp, uint32_t *genp)
{
    struct zsi_file *act = zsi_snapshot_active(db->snap);
    char name[ZSI_NAME_MAX], path[PATH_MAX];

    if (act && zsi_unordered_is_clean(act) && !zsi_active_full(db, act)) {
        /* The descriptor the last transaction handed back, if it is for THIS
         * generation.  O_APPEND means every write lands at the true EOF
         * regardless of which transaction opened the descriptor. */
        if (db->wfd_cache >= 0 && db->wfd_gen == act->hdr.start) {
            *fdp = db->wfd_cache;
            db->wfd_cache = -1;
            *genp = act->hdr.start;
            return ZS_OK;
        }
        if (db->wfd_cache >= 0) { close(db->wfd_cache); db->wfd_cache = -1; }

        snprintf(path, sizeof(path), "%s", act->fname);
        int fd = open(path, O_RDWR | O_APPEND);   /* RDWR: the streaming reads mmap this fd (A-4) */
        if (fd < 0) return ZS_IOERROR;
        *fdp = fd;
        *genp = act->hdr.start;
        return ZS_OK;
    }

    if (db->wfd_cache >= 0) { close(db->wfd_cache); db->wfd_cache = -1; }

    /* D-12b: there is one active-file name (D-1b), so the file occupying it has
     * to go before a replacement can be created.  Converting it is what makes
     * room -- and it is work that had to happen anyway (D-12), only now its
     * ordering is forced by the name rather than by policy.
     *
     * An unclean file converts like any other: the conversion reads to its
     * complete point (F-24) and the garbage beyond is simply not carried over,
     * so no chain is built on an untrustworthy boundary.  Only an invalid
     * header has nothing to convert, and D-10 says it holds no recoverable
     * record, so it is removed rather than preserved -- which is not a repair
     * (R-4), because nothing in it is being salvaged. */
    int r;
    struct zsi_file *stale = zsi_snapshot_active(db->snap);
    if (stale) {
        if (stale->hdr_valid) {
            r = zsi_convert_one(db, stale);
            if (r != ZS_OK) return r;
        } else {
            char cname[ZSI_NAME_MAX];
            zsi_name_current(cname, db->uuid);
            r = zsi_remove_file(db, cname);
            if (r != ZS_OK) return r;
        }
        r = zsi_db_refresh(db);
        if (r != ZS_OK) return r;
    }

    /* A new generation, one above the highest PRESENT (D-9b), so a superseded
     * file's generation is never reissued.  Every remaining file is in-order,
     * since the one that was not has just been dealt with. */
    struct zsi_fileset fs;
    r = zsi_fileset_scan(db->dir, &db->uuid, &fs);
    if (r != ZS_OK) return r;

    uint32_t next;
    r = zsi_fileset_next_gen(&fs, &next);
    zsi_fileset_fini(&fs);
    if (r != ZS_OK) return r;           /* ZS_FULL past 0xFFFFFFFF (D-9c) */

    r = zsi_create_active(db, next);
    if (r != ZS_OK) return r;

    r = zsi_db_refresh(db);
    if (r != ZS_OK) return r;

    zsi_name_current(name, db->uuid);           /* D-1b */
    snprintf(path, sizeof(path), "%s/%s", db->dir, name);
    int fd = open(path, O_RDWR | O_APPEND);   /* RDWR: the streaming reads mmap this fd (A-4) */
    if (fd < 0) return ZS_IOERROR;

    *fdp = fd;
    *genp = next;
    return ZS_OK;
}

/* Commit: one gate (C-7).
 *
 *   1. append the span's data records and then the terminator -- in ONE write
 *      where the span is still buffered, since nothing orders them;
 *   2. fdatasync.
 *
 * fdatasync rather than fsync because appending changes only the metadata needed
 * to read the data back, which fdatasync is required to flush.  The cost is one
 * sync per TRANSACTION, not per record, which is the reason zs_txn_* exists
 * alongside the single-operation zs_db_* calls (C-7b).
 *
 * This was TWO gates until 2026-08-18, with a sync between the records and the
 * terminator so that a valid terminator implied durable data.  F-22 already
 * implies that a different way: the terminator's checksum covers the span, so a
 * terminator that reaches disk without its data fails validation and the span
 * reads as absent.  The ordering made that impossible rather than merely
 * detectable, and cost +81% on one-record transactions.  What went with it is
 * the first gate's extra promise -- that a commit reporting an error definitely
 * did not happen -- which was never observable here anyway, since both gates
 * returned the same ZS_IOERROR (C-7a).
 *
 * C-7c: ZS_NOSYNC omits the gate.  Atomicity survives, because a torn tail is
 * still detectable (F-22); durability does not. */
static int zsi_txn_terminate(struct zs_txn *txn, bool rollback,
                             size_t *term_off_out, uint64_t *term_csum_out)
{
    struct zs_db *db = txn->db;
    size_t spanlen = txn->wsize - txn->span_base;
    int r;

    /* The terminator's checksum covers the span's BYTES plus the terminator
     * (C-4f), and the engine is one-shot -- engine 2 is the caller's, so no
     * incremental variant is possible.  The bytes come from wherever they
     * still are: a span that fits the chunk buffer entirely -- every small
     * transaction -- is checksummed there, and only a span already partially
     * flushed is re-read through a mapping (one warm pass, where the
     * buffered writer paid the same pass over RAM).  C-4f covers bytes, not
     * their residence, and the flush writes exactly these bytes.  A
     * ROLLBACK's checksum matters as much as a COMMIT's: an invalid
     * rolled-back span completes the file early (F-24) and costs everything
     * after it. */
    bool in_chunk = (txn->flushed == txn->span_base);

    /* C-8b: an abort whose span NEVER REACHED THE FILE writes nothing at all.
     *
     * F-21 needs a ROLLBACK to stop a later commit's span enclosing the aborted
     * records and making them live.  If no byte of the span left the buffer there
     * are no such records: the file is byte-identical to what it was before the
     * transaction began, and the next span starts exactly where this one would
     * have.  So there is nothing to void, and the cheapest correct ROLLBACK is
     * the one never written.
     *
     * Three things make `in_chunk` mean what it has to mean here.  The writer
     * holds the write lock for the transaction's whole life, so nobody else
     * appended.  Every byte of the span goes through the buffer, so `flushed ==
     * span_base` really does say none of it was written.  And a FAILED flush
     * poisons the transaction, so `broken` covers the one case where bytes could
     * be in the file without `flushed` counting them.
     *
     * That third check is NOT what keeps the data safe, and the mutants for it are
     * `equivalent` because of it: a file left with orphan bytes is unclean, so the
     * next write transaction's C-4i probe rebuilds, sees the last valid span below
     * them and rolls over to a new generation (D-9a, R-4) instead of appending
     * past bytes its own size no longer describes.  The check is here so the
     * discard's precondition is one the writer can actually establish rather than
     * one the backstop happens to rescue -- `test_torn_flush_then_abort` is the
     * case, and it passes either way, which is the point.
     *
     * The interop consequence is in C-8b: a rolled-back span is no longer
     * something a conforming writer can be required to produce, because whether
     * one appears depends on the writer's buffering. */
    if (rollback && in_chunk && !txn->broken) {
        txn->chunklen = 0;
        txn->wsize = txn->span_base;
        if (term_off_out) *term_off_out = txn->span_base;
        if (term_csum_out) *term_csum_out = 0;
        return ZS_OK;
    }

    const char *span;
    if (in_chunk) {
        span = txn->chunk;                  /* chunklen == spanlen here */
    } else {
        r = zsi_txn_flush(txn);
        if (r != ZS_OK) return r;
        /* Never ephemeral: the flush just emptied the chunk, so these bytes
         * are in the file and the mapping is the only place to read them. */
        span = zsi_txn_at(txn, txn->span_base, spanlen, false);
        if (!span) return ZS_IOERROR;
    }

    char term[ZSI_TERMLEN_LONG];
    size_t termlen = zsi_term_encoded_len((uint64_t)spanlen);

    /* The engine is the ACTIVE FILE'S, not this handle's (A-6, F-5a) --
     * recorded at the first store, where the file was chosen. */
    zsi_term_encode(term, (uint64_t)spanlen, rollback, span,
                    txn->wcs, txn->wcsum_id);

    /* The span and its terminator leave in ONE write whenever the span is still
     * buffered: nothing orders them in ANY durability mode since C-7 went to a
     * single gate, and the terminator checksum makes a torn interleaving read as
     * absent (F-22).  That detection is now load-bearing rather than a second
     * line of defence, which is why F-22 says so.
     *
     * The condition is about RESIDENCE, not size: a span that already flushed
     * cannot be merged with its terminator because its head is in the file
     * already.  So how much of the commit traffic takes this path is set by the
     * chunk buffer (ZSI_TXN_CHUNK), and a transaction larger than it pays a
     * second write -- never a second sync. */
    if (in_chunk && txn->chunklen + termlen <= txn->chunkcap) {
        memcpy(txn->chunk + txn->chunklen, term, termlen);
        txn->chunklen += termlen;
        txn->wsize += termlen;
        r = zsi_txn_flush(txn);
        if (r != ZS_OK) return r;
    } else {
        r = zsi_txn_flush(txn);
        if (r != ZS_OK) return r;

        /* No sync here.  The span's head is already in the file and the
         * terminator follows it; the gate below covers both, and a crash
         * between them leaves a terminator F-22 rejects. */
        r = zsi_write_all(txn->wfd, term, termlen);
        if (r != ZS_OK) return r;
        txn->flushed += termlen;
        txn->wsize += termlen;
    }

    /* The gate: everything is written, now sync it.  If this fails the
     * terminator may or may not be durable -- and either outcome is correct, so
     * the error is reported and nothing else is done.  A caller must treat a
     * failed commit as an UNKNOWN outcome and go and look (C-7a); it cannot be
     * told the transaction did not happen, because it may have.
     *
     * An implementation MUST NOT retry a failed sync and treat success as
     * evidence the data survived: a second call can succeed after the dirty
     * pages were discarded.  Retrying a failed syscall is the reflex, which
     * is why this says so at the call site rather than only in the spec. */
    if (!db->nosync && !rollback) {
        if (ZS_FDATASYNC(txn->wfd) < 0) return ZS_IOERROR;
    }

    /* Where the terminator landed and what checksum it carries (P-10).  Handed
     * back rather than recovered later because terminators are only ever found
     * by scanning FORWARD (F-20): a caller that skipped the replay -- which is
     * the whole point of the incremental index path -- has no other way to know,
     * and re-walking the span it just wrote would checksum it twice. */
    if (term_off_out) *term_off_out = txn->span_base + spanlen;
    if (term_csum_out) *term_csum_out = zsi_get64(term + termlen - 8);

    return ZS_OK;
}

static void zsi_txn_free(struct zs_txn *txn)
{
    if (!txn) return;

    zsi_pend_clear(txn);

    /* The mappings outlive every pointer this transaction's reads returned
     * (A-4), so HERE -- the end of the transaction -- is the first moment any
     * of them may go. */
    for (size_t i = 0; i < txn->nmaps; i++)
        munmap(txn->maps[i].base, txn->maps[i].len);
    free(txn->maps);
    free(txn->chunk);

    /* A-4a: and the same for what a snapshot swap left behind. */
    zsi_hold_fini(&txn->hold);

    /* Hand the append descriptor back for the next transaction rather than
     * closing it -- unless this one's stream broke, in which case nothing
     * about the descriptor is worth trusting.  A torn or rolled-back tail
     * does not disqualify it: whether the next transaction may APPEND is
     * decided by zsi_writer_active against the refreshed snapshot, and a
     * mismatched or unwanted descriptor is closed there. */
    if (txn->wfd >= 0) {
        if (!txn->broken && txn->db->wfd_cache < 0) {
            txn->db->wfd_cache = txn->wfd;
            txn->db->wfd_gen = txn->wgen;
        } else {
            close(txn->wfd);
        }
    }

    zsi_snapshot_release(&txn->snap);
    free(txn);
}

static int zsi_txn_begin(struct zs_db *db, bool shared, struct zs_txn **out)
{
    struct zs_txn *txn;
    int r;

    if (!shared) {
        r = zsi_check_writable(db);
        if (r != ZS_OK) return r;
        if (db->write_txn) return ZS_BADUSAGE;      /* one at a time */

        /* D-16e.  Here rather than at the end of the commit that created the
         * work, and NOT because a commit cannot take the repack lock -- since
         * C-1d became write -> repack it can, which is exactly what C-1l's
         * compacting seal does.  The reason is that the cascade is UNBOUNDED
         * (D-16b): taking repack from inside a commit would hold the WRITE lock
         * across an unbounded merge and block every other writer for its whole
         * duration.  This transaction holds nothing yet, so the merge runs under
         * the repack lock alone and zsi_repack releases it before the write lock
         * is taken below.
         *
         * Only when this transaction is about to START A NEW GENERATION --
         * the same condition zsi_writer_active applies (D-9a): no clean active
         * file, or one already past rollover_size.  That is the only way the
         * file count grows, so it is the only moment new repack work can
         * appear; a transaction appending to an existing active file cannot
         * have created any, and probing on every begin would pay for an
         * answer that cannot have changed.
         *
         * The cost lands on the transaction that finds the work, which is the
         * amortisation D-12 already uses for conversion.  A cascade is
         * UNBOUNDED (D-16b), so this is a latency spike on whichever writer
         * trips it; what it buys is that no caller has to remember, and
         * forgetting is expensive and invisible -- every read merges across
         * every file, so the read path degrades linearly in the file count
         * while the database merely looks slow.
         *
         * Both tests are against a possibly-stale snapshot, deliberately.
         * Neither decides anything except whether the repack lock is worth
         * taking: zsi_repack refreshes and re-selects underneath that lock and
         * returns having done nothing if the work is gone, so losing the race
         * to another process costs one lock acquisition and a rescan rather
         * than a wrong decision.
         *
         * Never fatal.  A failed or refused repack leaves a database that is
         * merely unmerged, and failing the caller's transaction over it would
         * report an error they cannot act on; the next writer tries again.
         * ZS_NONBLOCKING is honoured inside zsi_repack, so a caller who asked
         * not to wait does not wait here either. */
        if (!db->no_auto_repack) {
            struct zsi_file *act = zsi_snapshot_active(db->snap);
            bool new_gen = !(act && zsi_unordered_is_clean(act)
                             && !zsi_active_full(db, act));

            if (new_gen && zsi_should_repack(db->snap, db->repack_max_size))
                (void)zsi_repack(db);
        }
    }

    txn = zsi_zmalloc(sizeof(*txn));
    if (!txn) return ZS_INTERNAL;
    txn->db = db;
    txn->readonly = shared;
    txn->wfd = -1;              /* no stream until the first store */

    /* The pending set's level generator.  Any non-zero seed will do -- xorshift
     * is a bijection on the non-zero words and a fixed one keeps the structure
     * reproducible -- but ZERO IS A FIXED POINT, and zsi_zmalloc leaves it
     * there: every node would then draw the maximum level, which is a correct
     * skiplist with every node in every list and so a linear search. */
    txn->prand = 0x9E3779B97F4A7C15ULL;

    if (!shared) {
        /* The write lock is held for the whole transaction (C-1).  A read
         * transaction takes NO lock (C-2, G-4). */
        r = zsi_lock_take(&db->locks, ZSI_LOCK_WRITE,
                          db->nonblocking ? ZS_NONBLOCKING : 0);
        if (r != ZS_OK) { free(txn); return r; }
        txn->holds_write_lock = true;

        /* Freshen only after the lock: the set may have changed while we waited,
         * and appending to a stale view of the active file would append to a file
         * another writer has already moved past.
         *
         * The C-4i probe, NOT an unconditional rebuild.  C-4i is "shared or
         * exclusive", and the probe is exact, so a stale view is impossible;
         * what an unconditional rebuild adds is a replay of the active file
         * on every begin -- the sole writer's commit already left db->snap
         * current via the D-13b fold, so it re-derives a snapshot it already
         * holds, at O(active file) per commit -- so single-record commits decay
         * as the active file grows and snap back at every rollover. */
        r = zsi_db_freshen(db);
        if (r != ZS_OK) {
            zsi_lock_release(&db->locks, ZSI_LOCK_WRITE);
            free(txn);
            return r;
        }
    } else {
        /* C-4i: freshness is a property of BEGIN, not of open.  Without it a
         * long-lived handle reads the world as of its own last write: another
         * process's commit stays invisible for as long as the handle is held
         * open.  Snapshot isolation (G-4) starts here and holds for the
         * transaction's lifetime, never the handle's. */
        r = zsi_db_freshen(db);
        if (r != ZS_OK) { free(txn); return r; }
    }

    txn->snap = db->snap;
    txn->snap->refcount++;

    /* A READ transaction references the files it may return pointers into, for
     * the same two reasons a cursor does (A-4a, and blocking the fold from
     * mutating a view G-4 fixed here).
     *
     * A WRITE transaction deliberately does not: it is the one that will do the
     * folding, so its own reference would be indistinguishable from a reader's
     * and would disable the incremental path entirely -- which is the quadratic
     * bulk load D-13b exists to prevent.  Its borrows are safe without it,
     * because the fold happens during commit and commit is where the
     * transaction's A-4 lifetime ends. */
    if (shared && zsi_hold_add_snapshot(&txn->hold, txn->snap) != ZS_OK) {
        zsi_snapshot_release(&txn->snap);
        free(txn);
        return ZS_INTERNAL;
    }

    if (!shared) db->write_txn = txn;

    *out = txn;
    return ZS_OK;
}

static int zsi_txn_commit(struct zs_txn *txn)
{
    struct zs_db *db = txn->db;
    int r;
    uint32_t gen = 0;
    size_t *offs = NULL, noffs = 0;
    size_t term_off = 0;
    uint64_t term_csum = 0;

    if (txn->readonly) { zsi_txn_free(txn); return ZS_OK; }

    /* Nothing streamed: no span, no syncs, no trace.  An empty transaction is
     * not an error.  (An open stream with nothing appended is the same case:
     * a failed first store may have chosen the file and then written
     * nothing, and the file is exactly as it was.) */
    if (txn->wfd < 0 || txn->wsize == txn->span_base) {
        db->write_txn = NULL;
        zsi_lock_release(&db->locks, ZSI_LOCK_WRITE);
        zsi_txn_free(txn);
        return ZS_OK;
    }

    /* A stream failure left a possibly-torn record inside the span.  A
     * COMMIT terminator over it would make replay complete the file at the
     * tear (F-24) and lose the whole span -- so refuse, and void the span
     * the way an abort does (C-8). */
    if (txn->broken) {
        (void)zsi_txn_terminate(txn, true, NULL, NULL);
        r = ZS_IOERROR;
        goto out;
    }

    /* The records are already on disk (C-8): everything between the two
     * gates is the terminator's. */
    r = zsi_txn_terminate(txn, false, &term_off, &term_csum);
    if (r != ZS_OK) goto out;

    gen = txn->wgen;
    struct zsi_file *act = zsi_snapshot_active(db->snap);

    /* The D-13b fold takes its offsets from the pending index: the FINAL
     * record per key, which is exactly what D-13a wants folded -- a version
     * this transaction itself overwrote is shadowed inside the span, and
     * replay resolves it by offset order (D-17b) just as the fold does by
     * skipping it here. */
    offs = malloc(txn->npend * sizeof(*offs));
    if (offs) {
        /* Level 0 is every node, in KEY ORDER, which is exactly the sorted run
         * zsi_index_fold_run wants -- so the fold merges rather than searching
         * per record.  Reverse this walk and the run is descending, which the
         * merge accepts and mis-orders the delta with. */
        size_t i = 0;
        for (size_t o = txn->parena ? ZSI_PHEAD(txn)[0] : 0; o;
             o = ZSI_PN(txn, o)->next[0])
            offs[i++] = ZSI_PN(txn, o)->off;
        noffs = i;
    }

    /* D-13b: a writer is a reader that also maintains the active file's index
     * INCREMENTALLY.  It already knows every record it appended, so it folds them
     * in rather than rescanning a file it is writing -- which matters because a
     * rescan is O(active file) per commit, making a bulk load quadratic.
     *
     * Only when nothing else holds the snapshot.  A cursor opened from the
     * same handle shares the object, and replacing its mapping or mutating its
     * index underneath would be exactly the in-place mutation of something a
     * reader is reading that G-6 forbids.  With a sharer present the fallback
     * is a full refresh, which builds a NEW snapshot and leaves the old one
     * untouched.
     *
     * ONE reference is this commit's own -- the snapshot's.  A cursor takes a
     * reference per file it may be reading (A-4a), so a sharer shows up here
     * as a second one and the fallback engages.
     *
     * This used to ask db->snap->refcount == 2, using the SNAPSHOT's count as
     * a proxy for "is anyone reading this file".  The proxy was already subtle
     * -- two is the commit's own db->snap and txn->snap, and reading it as one
     * made the branch dead code and every bulk load quadratic -- and it broke
     * outright once A-4a's retention started perturbing snapshot references
     * for reasons that had nothing to do with the active file.  Asking about
     * the file is both simpler and the actual question. */
    if (act && offs && act->refcount == 1
        && act->hdr.start == gen && act->index) {
        r = zsi_file_remap(act, db->rollover_size);
        if (r == ZS_OK) {
            act->complete = act->size;
            /* The span just written ends the file, so its terminator is the one
             * at the complete point (P-10).  Taken from the writer rather than
             * rediscovered, since skipping the replay is the point of this
             * branch and terminators are only found by scanning forward. */
            act->last_term_off  = term_off;
            act->last_term_csum = term_csum;
            /* D-9d, and hand-carried for the same reason: this branch never
             * replays, so the count has to come from the writer that knows it
             * just added a span.  A sole writer takes this path at EVERY
             * commit, so leaving it out does not merely lose accuracy -- the
             * count sits at whatever the last rebuild left and the bound never
             * fires for the one writer shape it was written for. */
            act->nspans++;
            r = zsi_index_fold_run(act->index, db->compar, offs, noffs);
        }
        /* A failure here is not fatal to the commit -- the data is on disk and
         * durable.  Fall back to a rebuild so this handle's view is correct. */
        if (r != ZS_OK) r = zsi_db_refresh(db);

        /* P-13: a commit publishes NOTHING, and used to publish here.
         *
         * Publishing amortises a REPLAY, and this path never replays -- D-13b's
         * fold maintains the index incrementally, so a table written here is pure
         * cost to the writer with no local benefit at all.  At the default
         * rollover_size it is also waste rather than merely unbalanced: a load
         * publishes about 17 tables into each generation before D-25d seals it,
         * and a sealed generation is an in-order file with a pointer SECTION, so
         * every one of them is irrelevant before anybody opens the database.
         * Measured at 22% of a cached 2M-record load, and 38% at a 64MB rollover.
         *
         * The tables still appear.  A handle that built its index by replaying
         * publishes, at the one place that does that (zsi_snapshot_take) -- which
         * includes this same writer at its own open, and any reader.  What is gone
         * is only the speculative half: writing a table for a file this handle
         * never needed to read. */
    } else {
        r = zsi_db_refresh(db);
    }

    /* D-12: a writer that finds a non-active unordered file MUST convert it before
     * it finishes.  This is what holds the steady state at exactly one unordered
     * file (D-12a), so a snapshot normally replays only the active one.
     *
     * A conversion failure does not fail the commit: the records are already
     * durable, and an unconverted file is a performance matter that the next
     * writer retries.  Reporting it would turn a successful commit into an error
     * the caller cannot act on. */
    if (r == ZS_OK) {
        int cr = zsi_convert_pending(db);
        (void)cr;
    }

    /* D-25d: a commit that left the active file past rollover_size, or past
     * D-9d's span bound, seals it now, while the write lock is still held, so
     * the conversion cost lands on the transaction that incurred it rather
     * than on the next writer -- the one case D-12d's bound cannot cover,
     * since a span is never split across files and a bulk load writes its
     * whole transaction as one span.  After zsi_convert_pending, so D-12b's
     * oldest-first order holds.  Never fatal: the records are durable, and an
     * unsealed full file is exactly what D-9a's rollover already recovers at
     * the next commit. */
    if (r == ZS_OK) {
        struct zsi_file *full = zsi_snapshot_active(db->snap);
        if (full && full->hdr_valid
            && zsi_active_full(db, full)
            && full->complete > ZSI_HEADER_LEN) {
            int sr = zsi_convert_one(db, full);
            if (sr == ZS_OK) (void)zsi_db_refresh(db);
        }
    }

out:
    free(offs);
    db->write_txn = NULL;
    zsi_lock_release(&db->locks, ZSI_LOCK_WRITE);
    zsi_txn_free(txn);
    return r;
}

/* Abort (C-8, F-21).
 *
 * The records were streamed to the active file as they were stored, so the
 * abort MUST void them: without a ROLLBACK terminator, a later commit's span
 * would begin before the aborted records and enclose them, making them live.
 * The ROLLBACK syncs neither gate (C-8) -- the next commit's own first gate
 * orders it ahead of the next COMMIT terminator (C-8a), and a crash that
 * loses it leaves a torn span F-22 already discards, which is the same
 * outcome reached the slower way.
 *
 * A failure writing the ROLLBACK is likewise left as a torn span; it is not
 * reported, because the caller is already abandoning the transaction and
 * there is nothing they could do differently. */
static int zsi_txn_abort(struct zs_txn *txn)
{
    struct zs_db *db = txn->db;

    if (txn->readonly) { zsi_txn_free(txn); return ZS_OK; }

    if (txn->wfd >= 0 && txn->wsize > txn->span_base)
        (void)zsi_txn_terminate(txn, true, NULL, NULL);

    db->write_txn = NULL;
    zsi_lock_release(&db->locks, ZSI_LOCK_WRITE);
    zsi_txn_free(txn);
    return ZS_OK;
}

/********** CONVERSION *************/

/* D-12, immediate conversion.
 *
 * A writer that finds a NON-ACTIVE unordered file MUST convert it to its
 * single-generation in-order form -- <uuid>-N becomes <uuid>-N-N -- before it
 * finishes, oldest first, and MUST NOT go further: it does not merge in-order
 * files, which is the repacker's job (D-16).
 *
 * D-12a: this is what keeps the steady state at EXACTLY ONE unordered file, the
 * active one, so a snapshot normally replays only that file and nothing else.  A
 * non-active unordered file exists only transiently -- between a rollover and the
 * next writer's conversion, or after a crash left an unclean file behind.
 *
 * D-12d: each conversion is bounded by rollover_size, so a writer's extra cost is
 * bounded and predictable rather than proportional to the database. */

/* D-20a: a staging file MUST be created with O_CREAT|O_EXCL, advancing <n> until
 * it succeeds.
 *
 * A process identifier is NOT unique on shared storage -- two hosts readily have
 * the same pid -- and two processes writing one staging file would produce an
 * interleaved output that is then renamed into place as though complete.  O_EXCL
 * costs nothing and removes the case. */
static int zsi_staging_open(struct zs_db *db, char *name_out, int *fdp)
{
    for (unsigned n = 0; n < 10000; n++) {
        char path[PATH_MAX];

        zsi_staging_name(name_out, n);
        snprintf(path, sizeof(path), "%s/%s", db->dir, name_out);

        int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
        if (fd >= 0) { *fdp = fd; return ZS_OK; }
        if (errno != EEXIST) return ZS_IOERROR;
    }

    return ZS_IOERROR;
}

/* Remove a data file (D-23).
 *
 * MUST be done holding the REMOVE lock, and only after verifying that a complete
 * set of files exists WITHOUT it.  Verification and removal happen under one
 * unbroken hold, so the set cannot change in between.
 *
 * If verification fails the file is left alone: leaking a file costs disk space,
 * removing a needed one costs the database.  That asymmetry is the whole reason
 * this is not just an unlink.
 *
 * C-6a: no directory sync after unlink.  If a removed name reappears after a
 * crash it is a file an enclosing range already supersedes, which readers ignore
 * and a later pass removes again. */
static int zsi_remove_file(struct zs_db *db, const char *name)
{
    struct zsi_fileset fs;
    int r;

    r = zsi_fileset_scan(db->dir, &db->uuid, &fs);
    if (r != ZS_OK) return r;

    /* The interval the database currently covers.  Tiling ALONE is not a
     * sufficient precondition, which is worth spelling out because it is a
     * tempting reading of D-23: D-6 measures completeness "from the oldest
     * SURVIVING generation", so deleting the oldest file merely raises that floor
     * and the remainder tiles perfectly while the data is gone.  With files
     * {1-2, 3}, removing 1-2 leaves {3}, which tiles.
     *
     * So the real precondition is that the candidate be SUPERSEDED: the set
     * without it must tile AND still span the same interval.  That is what "a
     * complete set of files exists without it" has to mean, since a set covering
     * less is not the same set. */
    uint32_t lowest = 0, highest = 0;
    for (size_t i = 0; i < fs.nall; i++) {
        uint32_t s0 = fs.all[i].start;
        uint32_t e0 = fs.all[i].end ? fs.all[i].end : fs.all[i].start;
        if (i == 0 || s0 < lowest) lowest = s0;
        if (e0 > highest) highest = e0;
    }

    /* Drop the candidate, then ask.  Doing it in this order -- rather than
     * unlinking and re-scanning -- is what makes a failed verification harmless. */
    size_t w = 0;
    for (size_t i = 0; i < fs.nall; i++)
        if (strcmp(fs.all[i].name, name) != 0) fs.all[w++] = fs.all[i];

    if (w == fs.nall) { zsi_fileset_fini(&fs); return ZS_NOTFOUND; }
    fs.nall = w;

    r = zsi_fileset_resolve(&fs);

    if (r == ZS_OK) {
        uint32_t nlow = 0, nhigh = 0;
        for (size_t i = 0; i < fs.nall; i++) {
            uint32_t s0 = fs.all[i].start;
            uint32_t e0 = fs.all[i].end ? fs.all[i].end : fs.all[i].start;
            if (i == 0 || s0 < nlow) nlow = s0;
            if (e0 > nhigh) nhigh = e0;
        }
        if (fs.nall == 0 || nlow != lowest || nhigh != highest) r = ZS_AGAIN;
    }

    zsi_fileset_fini(&fs);

    /* Still needed.  Leave it: a leaked file is reclaimed by a later pass.  D-23b:
     * this is the only direction the check can be wrong in, since a concurrent
     * publication only ADDS a file and a torn readdir only hides one -- both make
     * the set look less complete, so a race costs a refusal, never a removal. */
    if (r != ZS_OK) return ZS_AGAIN;

    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/%s", db->dir, name);
    if (ZS_UNLINK(path) < 0 && errno != ENOENT) return ZS_IOERROR;
    return ZS_OK;
}

/* Write an in-order file holding the records at the given offsets of src, in the
 * order given, and rename it into place (D-21, C-3).
 *
 * The output has NO spans and NO terminators: every record in it is live by
 * construction, and it is written whole under a temporary name and renamed only
 * once finished, so a commit record would assert nothing not already guaranteed
 * (section 4.9, F-24a).
 *
 * Ancestors are copied through VERBATIM.  For a single-generation conversion the
 * containing file's start is unchanged (N becomes N-N), so a record whose ancestor
 * was omitted stays omitted and one that stored an ancestor keeps it -- F-17 is
 * satisfied without recomputation (F-16c, D-17a). */
static int zsi_write_inorder(struct zs_db *db, struct zsi_file *src,
                             const size_t *offs, size_t n,
                             uint32_t start, uint32_t end)
{
    char sname[ZSI_NAME_MAX], fname[ZSI_NAME_MAX];
    char spath[PATH_MAX], fpath[PATH_MAX];
    char hdr[ZSI_HEADER_LEN];
    struct zsi_header h;
    struct zsi_inorder_out body;
    int fd = -1, r;

    zs_csum *cs = zsi_csum_for_id(db->create_csum_id, db->external_csum);
    if (!cs) return ZS_BADUSAGE;

    memset(&body, 0, sizeof(body));

    /* Format 2 had a `reencode` flag here: a record carried a checksum under its
     * own file's engine (F-32c), so a byte-for-byte copy was only valid while
     * the engines matched.  Records carry no checksum now (F-13a) and an
     * in-order file stores key entries rather than records anyway, so every
     * record is re-encoded into the output's shape unconditionally and the
     * engine question does not arise. */

    /* Lay the records out contiguously, recording each one's offset in the
     * output.
     *
     * A conversion keeps EVERY record it is given, tombstones included, and
     * must: its output covers its input's range (D-5a), so there is nothing
     * below it that it is entitled to reason about.  D-19's retention test
     * belongs to repack, which merges a range and can look under it.
     *
     * The record count is exact, so the descriptor array is sized once.  Nothing
     * else is reserved: the keys and values stay where they are, in the input's
     * mapping, until the emit copies them out. */
    zsi_inorder_reserve(&body, n);

    for (size_t i = 0; i < n; i++) {
        const char *b = zsi_file_at(src, offs[i], 1);
        struct zsi_rec rec;

        if (!b) { r = ZS_BADFORMAT; goto fail; }
        if (zsi_rec_decode(b, src->size - offs[i], &rec)
            != ZS_OK) { r = ZS_BADFORMAT; goto fail; }

        r = zsi_inorder_add(&body, rec.key, rec.keylen, rec.val, rec.vallen);
        if (r != ZS_OK) goto fail;
    }

    struct zsi_layout lay;
    char trailer[ZSI_TRAILER_LEN];
    r = zsi_inorder_layout(&body, &lay);
    if (r != ZS_OK) goto fail;

    memset(&h, 0, sizeof(h));
    h.version_read = ZSI_VERSION_READ;
    h.version_write = ZSI_VERSION_WRITE;
    h.flags = (uint16_t)db->create_csum_id;
    if (lay.val_wide) h.flags |= ZSI_HDR_FLAG_WIDEVAL;
    memcpy(h.uuid, db->uuid, 16);
    h.start = start;
    h.end = end;
    memcpy(h.compar_name, db->compar_name, ZSI_COMPAR_NAME_LEN);
    h.keys_len = lay.keys_len;
    h.values_len = lay.values_len;
    zsi_header_encode(hdr, &h, cs);

    r = zsi_staging_open(db, sname, &fd);
    if (r != ZS_OK) goto fail;

    /* The header states every section's length before a body byte is written
     * (D-20c), then the emit streams the body out of the input's mapping. */
    r = zsi_write_all(fd, hdr, sizeof(hdr));
    if (r == ZS_OK)
        r = zsi_inorder_emit(&body, &lay, cs, db->create_csum_id,
                             db->merge_memory, fd, NULL, trailer);
    if (r == ZS_OK)
        r = zsi_write_at(fd, trailer, sizeof(trailer), (off_t)lay.values_end);

    /* The file's contents durable BEFORE the rename, or the name could exist
     * pointing at a partial file after a crash -- in every durability mode
     * (C-6b): the rename entitles retiring the inputs, which are these
     * records' only other copy. */
    if (r == ZS_OK && ZS_FDATASYNC(fd) < 0) r = ZS_IOERROR;
    close(fd);
    fd = -1;

    snprintf(spath, sizeof(spath), "%s/%s", db->dir, sname);
    if (r != ZS_OK) { unlink(spath); goto fail; }

    /* C-3: a file is published by writing it under a staging name, then renaming.
     * Readers see it only once complete, and the rename is the instant it joins
     * the file set.  C-1b: publishing needs NO LOCK -- rename is atomic, and a
     * conversion's output [c..c] and a repack's output [a..b] with c > b are
     * disjoint, so they cannot interfere in either order. */
    zsi_name_format(fname, db->uuid, start, end);
    snprintf(fpath, sizeof(fpath), "%s/%s", db->dir, fname);
    if (ZS_RENAME(spath, fpath) < 0) { ZS_UNLINK(spath); r = ZS_IOERROR; goto fail; }

    /* A-17, at the publish for the same reason the merge counts there.  Its only
     * caller is a conversion, which is why this lands in convert_* -- a second
     * caller would have to say which bucket it belongs in. */
    db->stats.convert_records += (uint64_t)n;
    db->stats.convert_bytes += (uint64_t)lay.values_end + ZSI_TRAILER_LEN;

    /* C-6: fdatasync the DIRECTORY after renaming an output into place, otherwise
     * the name may be absent after a crash even though the contents are durable.
     * Reported rather than fatal: a lost name leaves the inputs in place, which
     * still tile, so a later pass simply converts again (C-6a, R-5). */
    {
        int dfd = open(db->dir, O_RDONLY);
        if (dfd >= 0) {
            if (ZS_FDATASYNC(dfd) < 0)
                db->error("directory sync failed after publishing a conversion",
                          "dir=<%s>", db->dir);
            close(dfd);
        }
    }

    zsi_inorder_out_fini(&body);
    return ZS_OK;

fail:
    if (fd >= 0) close(fd);
    zsi_inorder_out_fini(&body);
    return r;
}

/* Convert one non-active unordered file to its single-generation in-order form. */
static int zsi_convert_one(struct zs_db *db, struct zsi_file *f)
{
    struct zsi_index_cur ic;
    struct zsi_rec rec;
    size_t *offs = NULL, n = 0, alloc = 0;
    uint64_t t0 = zsi_now_ns();       /* A-17 */
    int r;

    if (!f->index) return ZS_INTERNAL;

    /* D-20b: verify the span chain over everything about to be copied, with
     * checksums ON always -- verification rides indexing (F-5e)
     * (F-5e), and this is a write: the output gets a fresh records checksum
     * computed over the copy, so converting an unverified span would launder
     * corruption into a file that validates.  Replayed on a SCRATCH copy,
     * because the walk records its progress into the struct it is given
     * (complete, the last terminator) and this walk's answer must not replace
     * the one the handle's readers are using; nothing in the copy is owned or
     * released.  A verified walk stopping short of f->complete means a span
     * this handle admitted fails its checksum. */
    {
        struct zsi_file scratch = *f;
        zsi_file_prefetch(f);
        r = zsi_unordered_replay(&scratch, ZSI_HEADER_LEN, NULL, NULL);
        if (r != ZS_OK) return r;
        if (scratch.complete < f->complete) {
            db->error("unordered file fails a span checksum; not converted",
                      "file=<%s>", f->fname);
            return ZS_BADCHECKSUM;
        }
    }

    /* The index already holds exactly the live records, newest per key, in key
     * order (D-13a) -- which is precisely what the output needs (D-20: inputs are
     * iterated in key order, from the same private index any reader builds; there
     * is nothing conversion-specific about it). */
    zsi_index_cur_seek_first(&ic);
    for (;;) {
        size_t off;
        if (zsi_index_cur_get(f->index, db->compar, &ic, &rec, &off) != ZS_OK)
            break;

        if (n == alloc) {
            size_t want = alloc ? alloc * 2 : 256;
            size_t *p = realloc(offs, want * sizeof(*p));
            if (!p) { free(offs); return ZS_INTERNAL; }
            offs = p;
            alloc = want;
        }
        offs[n++] = off;

        zsi_index_cur_next(f->index, db->compar, &ic);
    }

    db->stats.conversions++;
    r = zsi_write_inorder(db, f, offs, n, f->hdr.start, f->hdr.start);
    free(offs);
    if (r != ZS_OK) { db->stats.convert_ns += zsi_since_ns(t0); return r; }

    /* Retire the input (D-23).  D-12c: conversion takes NO lock beyond the write
     * lock it already holds -- it renames its output in without one (C-1b) and
     * removal needs none either (C-1c), so a writer never waits on a repack. */
    char iname[ZSI_NAME_MAX];
    zsi_name_current(iname, db->uuid);           /* D-1b */
    r = zsi_remove_file(db, iname);

    /* ZS_AGAIN means the set still needs it, which cannot happen here -- the
     * output covers exactly its range -- but a leaked input is harmless and a
     * later pass removes it, so this is not fatal. */
    if (r == ZS_AGAIN) r = ZS_OK;

    db->stats.convert_ns += zsi_since_ns(t0);
    return r;
}

/* Convert every non-active unordered file, OLDEST FIRST (D-12b).
 *
 * Oldest first keeps the generation range split into a prefix of in-order files
 * followed by a suffix of unordered ones, the last of which is the active file.
 * Converting out of order would leave an unordered file stranded between in-order
 * ones, and since only adjacent files may be merged (D-19), that hole would block
 * the repacker's cascade until it was filled (D-12b, D-16c). */
static int zsi_convert_pending(struct zs_db *db)
{
    int r = zsi_check_writable(db);
    if (r != ZS_OK) return r;

    for (;;) {
        struct zsi_file *act = zsi_snapshot_active(db->snap);
        struct zsi_file *victim = NULL;

        /* The oldest unordered file that is not the active one. */
        for (size_t i = 0; i < db->snap->nfiles; i++) {
            struct zsi_file *f = db->snap->files[i];
            if (f == act) continue;
            if (!zsi_file_is_unordered(f)) continue;
            victim = f;
            break;
        }

        if (!victim) return ZS_OK;

        /* A file with an invalid header cannot be converted -- there is nothing
         * to read.  D-10a already makes that an error at open for a non-active
         * file, so reaching here means the active file, which we skip. */
        if (!victim->hdr_valid) return ZS_OK;

        r = zsi_convert_one(db, victim);
        if (r != ZS_OK) return r;

        r = zsi_db_refresh(db);
        if (r != ZS_OK) return r;
    }
}

/* D-25: convert the ACTIVE file, on demand, under the write lock.
 *
 * D-12 skips the active file because another writer may be appending to it.  A
 * caller holding the write lock has excluded exactly that, so the exception does
 * not apply -- which is both why this is safe and why it must never be reachable
 * without the lock.
 *
 * NO replacement active file is created (D-25a).  A conversion output covers its
 * input's range (D-5a), so afterwards the newest file is in-order,
 * zsi_snapshot_active returns NULL -- a state every reader already handles -- and
 * the next write creates a new generation (D-9b).  Rolling over first and
 * converting second reaches the same layout while consuming a generation per
 * seal, and generations are finite (D-9c); test_seal_creates_no_new_generation
 * is what holds that apart. */
/* The body, with the WRITE LOCK ALREADY HELD.  Split out for zsi_compact, which
 * under C-1d's write -> repack order must take write itself before it can take
 * repack -- so it cannot call a form that acquires the lock for it. */
static int zsi_seal_locked(struct zs_db *db)
{
    struct zsi_file *act;
    int r;

    /* Refresh under the lock: another writer may have rolled over while we
     * waited, and sealing a stale view would convert a file already superseded. */
    r = zsi_db_refresh(db);
    if (r != ZS_OK) return r;

    act = zsi_snapshot_active(db->snap);

    /* D-25b's three no-ops, none of them errors. */
    if (!act) goto out;                             /* already sealed */

    if (!act->hdr_valid) {                          /* D-10 */
        db->error("active file has an invalid header; nothing to seal",
                  "file=<%s>", act->fname);
        goto out;
    }

    if (act->complete <= ZSI_HEADER_LEN) goto out;  /* no valid spans */

    r = zsi_convert_one(db, act);
    if (r != ZS_OK) goto out;

    r = zsi_db_refresh(db);

    /* A seal is a natural moment to catch up any stranded unordered file, and
     * costs nothing when there is none (D-12).  Not fatal for the same reason it
     * is not fatal at commit: the data is already durable and an unconverted
     * file is a performance matter. */
    if (r == ZS_OK) (void)zsi_convert_pending(db);

out:
    return r;
}

/* The standalone form: takes the write lock, seals, releases.  zsi_compact takes
 * the lock itself and calls zsi_seal_locked instead (C-1d). */
static int zsi_seal(struct zs_db *db)
{
    int r = zsi_check_writable(db);
    if (r != ZS_OK) return r;

    /* One writer at a time: sealing under an open write transaction would
     * convert a file that transaction is about to append to. */
    if (db->write_txn) return ZS_BADUSAGE;

    r = zsi_lock_take(&db->locks, ZSI_LOCK_WRITE,
                      db->nonblocking ? ZS_NONBLOCKING : 0);
    if (r != ZS_OK) return r;

    r = zsi_seal_locked(db);

    zsi_lock_release(&db->locks, ZSI_LOCK_WRITE);
    return r;
}

/********** REPACK *************/

/* D-15/D-16: the repacker works ONLY on in-order files.  It never touches the
 * active file, and never touches an unordered file at all -- converting those is
 * the writer's job (D-12).
 *
 * D-16a: the two jobs divide by whether a file has an `end`, which is what makes
 * them independent (C-1a).  A writer's conversion is bounded by rollover_size and
 * runs inline; the repacker's cascade is unbounded and runs out of band.  A file
 * becomes visible to the repacker precisely when the writer has finished with it,
 * so a writer never waits on a repack. */

/* Input selection (D-16):
 *
 *   1. start from the newest in-order file;
 *   2. if the result would be larger than the next lowest in-order file, include
 *      that file too and repeat;
 *   3. stop when every file is included or the next lowest in-order file is
 *      larger.
 *
 * This yields geometrically sized in-order files and amortised O(log n) rewrites
 * per record.  D-16c: because conversion keeps in-order files as a contiguous
 * prefix, the inputs are always adjacent and the cascade is never blocked by an
 * unordered file sitting between two candidates.
 *
 * `cap` is A-16's repack_max_size, bounding what one merge rewrites.
 *
 * Returns the number selected, filling *first with the index of the lowest.  The
 * selection is always a contiguous run ending at the newest in-order file. */
static size_t zsi_repack_select(struct zsi_snapshot *snap, size_t cap,
                                size_t *first)
{
    /* The in-order prefix: files [0, nio). */
    size_t nio = 0;
    while (nio < snap->nfiles && !zsi_file_is_unordered(snap->files[nio])) nio++;

    if (nio < 2) { *first = 0; return 0; }      /* nothing to merge */

    /* A-16: skip the LEADING files above the cap, so the walk starts at the
     * oldest file still worth re-merging and one merge rewrites about twice the
     * cap rather than the whole database.
     *
     * The leading run only.  An oversized file INSIDE the range that ends up
     * selected is merged like any other, because leaving it out would make the
     * inputs non-contiguous, which D-19's tombstone rule and D-6's tiling both
     * depend on not happening (D-16).
     *
     * The cap costs the file-count bound this policy exists to provide: a
     * skipped file is never selected again, so it is frozen and the count grows
     * linearly in total size.  Past ZSI_REPACK_MAX_FROZEN skipped files the cap
     * therefore YIELDS -- base drops back to 0 and the uncapped walk merges the
     * pile, the same doubling-amortised work the uncapped policy would have
     * done anyway.  Which is why the steady state is unchanged and only the
     * repacks in between get cheaper. */
    size_t base = 0;
    while (base < nio && snap->files[base]->size > cap) base++;
    if (base > ZSI_REPACK_MAX_FROZEN) base = 0;
    if (nio - base < 2) { *first = 0; return 0; }

    /* Walk from the OLDEST candidate file and merge from the first one the files
     * above it
     * collectively outweigh.
     *
     * The invariant this leaves behind is that every file is at least as large
     * as the sum of all newer ones, so sizes fall at least geometrically and
     * the file count is bounded by log(total / smallest) directly.  Comparing
     * against the SUM is what makes that hold: a rule comparing each file with
     * its immediate neighbour stalls on an irregular tail -- sizes 100, 60, 50
     * merge nothing under it, because 50 < 60 stops it at the first step, even
     * though the two newer files together outweigh the oldest.  Deletions and
     * dropped tombstones produce exactly those irregular sizes.
     *
     * A STRICT comparison is right here, because the left side is a sum: two
     * files of equal size wait, and a third collapses all three.  A rule
     * comparing neighbours needs to merge equals or it never merges at all,
     * which is the opposite conclusion from the same-looking test.
     *
     * uint64_t rather than size_t for the accumulator: on a 32-bit host a few
     * large files would overflow the sum, and reporting a too-small tail merges
     * less rather than more, so it would fail quietly. */
    uint64_t total = 0;
    for (size_t i = base; i < nio; i++) total += snap->files[i]->size;

    uint64_t tail = total;
    for (size_t i = base; i + 1 < nio; i++) {
        uint64_t here = snap->files[i]->size;

        tail -= here;                   /* now the sum of everything above i */
        if (tail > here) { *first = i; return nio - i; }
    }

    *first = 0;
    return 0;
}

/* D-24: whether D-16 currently has work. */
static bool zsi_should_repack(struct zsi_snapshot *snap, size_t cap)
{
    size_t first;
    return zsi_repack_select(snap, cap, &first) >= 2;
}

/* One key's versions, gathered across the inputs in D-17b's total order.
 *
 * D-17b: a repack MUST consider the versions of a key oldest to newest --
 *
 *   1. across files, by increasing start generation.  The tiling invariant (D-6)
 *      means ranges never overlap, so this is total;
 *   2. within one unordered file, by increasing offset among committed spans;
 *   3. an in-order file holds one record per key, so there is nothing to order.
 *
 * V1 is the first version in that order and V3 the last; the emitted record takes
 * V3's value.  Getting the order wrong silently emits the wrong value, which is
 * why T-7 tests it directly rather than only through its consequences. */
/* The newest version of one key across the inputs, under D-17b's total order.
 * Records carry no ancestor (F-18), so the newest version is the only one a
 * merge ever needs. */
struct zsi_merge_key {
    struct zsi_rec v3;          /* newest version: its value is emitted */
    bool           have;
};

/* Merge the selected inputs into one in-order file (D-17).
 *
 * The output holds EXACTLY ONE record per key, built from the live records of all
 * inputs.  Since the repacker only ever merges in-order files, and each holds one
 * record per key, "within one file" ordering never arises -- but the code walks
 * the inputs in increasing start generation regardless, because that is what makes
 * the order total and what a future pairwise merge would still need. */
/* D-19: is the newest record for this key BELOW the output range a value?
 *
 * This is the whole of the tombstone retention test, and it replaces the
 * ancestor a record used to carry (section 4.6).  The search is the one the
 * write path used to run on every store; here it runs once per surviving
 * tombstone, which is why the trade is worth making.
 *
 * `first` indexes the lowest input in a snapshot sorted by start ascending
 * (D-6 tiles, so ranges never overlap), which makes files [0, first) exactly
 * those below the output range.  They are in-order files, because D-12b keeps
 * in-order as a contiguous prefix and the inputs to a repack are in-order --
 * so each probe is a pointer-section binary search, never a replay.  Nothing
 * requires that here, though: zsi_fcur_find handles either kind.
 *
 * Newest to oldest, stopping at the first file that holds the key, because
 * that record is the one a reader would resolve to and everything under it is
 * already hidden.  So a DELETION found here answers false: our tombstone would
 * be redundant with it, and dropping ours is safe.  That exactness is free --
 * the search has to stop there either way.
 *
 * Files ABOVE the range are deliberately not consulted, and cannot be: a newer
 * record shadows everything below it, so a newer file can only ever make a
 * retained tombstone redundant, never make a dropped one unsafe.  Looking up
 * would also cost a lookup per KEY rather than per tombstone, which is D-19a's
 * argument for writing a shadowed record rather than proving it is shadowed. */
static bool zsi_repack_value_below(struct zs_db *db, struct zsi_snapshot *snap,
                                   size_t first, const char *key, size_t keylen)
{
    for (size_t i = first; i-- > 0; ) {
        struct zsi_fcur fc;
        struct zsi_rec r;

        zsi_fcur_init_file(&fc, snap->files[i], db->compar);
        {
            bool found = (zsi_fcur_find(&fc, key, keylen, &r) == ZS_OK);
            bool isval = found && !zsi_rec_is_delete(&r);
            zsi_fcur_fini(&fc);
            if (found) return isval;
        }
    }

    /* Nothing below holds the key, so its whole lifespan is in the inputs. */
    return false;
}

static int zsi_repack_merge(struct zs_db *db, struct zsi_snapshot *snap,
                            size_t first, size_t count)
{
    struct zsi_fcur *fc = NULL;
    struct zsi_inorder_out body;
    size_t nptrs = 0;
    char sname[ZSI_NAME_MAX], fname[ZSI_NAME_MAX];
    char spath[PATH_MAX], fpath[PATH_MAX];
    char hdr[ZSI_HEADER_LEN];
    struct zsi_header h;
    int fd = -1, r = ZS_OK;

    uint32_t out_start = snap->files[first]->hdr.start;
    uint32_t out_end   = snap->files[first + count - 1]->hdr.end;
    if (out_end == 0) return ZS_INTERNAL;       /* never an unordered input */

    zs_csum *cs = zsi_csum_for_id(db->create_csum_id, db->external_csum);
    if (!cs) return ZS_BADUSAGE;

    memset(&body, 0, sizeof(body));

    /* D-20b: verify every input's data-region checksum before copying a
     * byte of it.  Always verified -- verification rides indexing (F-5e)
     * (F-5e), and this is a write: the output gets a fresh checksum computed
     * over whatever is copied, and D-23 then removes the inputs, so copying
     * an unverified body would launder corruption into a file that validates
     * while destroying the only evidence.  Failing here costs nothing: the
     * inputs stay, the database still reads, salvage still works. */
    for (size_t i = 0; i < count; i++) {
        zsi_file_prefetch(snap->files[first + i]);
        r = zsi_ptrs_verify_records(snap->files[first + i]);
        if (r != ZS_OK) {
            db->error("repack input fails its records checksum; not merged",
                      "file=<%s>", snap->files[first + i]->fname);
            return r;
        }
    }

    /* Size the descriptor array from the inputs' record counts: the output holds
     * at most one record per input record, since resolution only ever drops
     * them (D-17, D-19).  The keys and values themselves stay in the inputs'
     * mappings until the emit copies them out, which is why nothing else here
     * scales with the merge's bytes. */
    {
        size_t nrecs = 0;
        for (size_t i = 0; i < count; i++) {
            const struct zsi_file *in = snap->files[first + i];
            if (in->nptrs > SIZE_MAX - nrecs) { nrecs = 0; break; }
            nrecs += (size_t)in->nptrs;
        }
        zsi_inorder_reserve(&body, nrecs);
    }

    fc = zsi_zmalloc(count * sizeof(*fc));
    if (!fc) return ZS_INTERNAL;

    /* Inputs are iterated in key order, from the pointer section (D-20). */
    for (size_t i = 0; i < count; i++) {
        zsi_fcur_init_file(&fc[i], snap->files[first + i], db->compar);
        r = zsi_fcur_seek_first(&fc[i]);
        if (r != ZS_OK) goto out;
    }

    for (;;) {
        /* The least key still present across the inputs. */
        const char *bestk = NULL;
        size_t bestkl = 0;
        for (size_t i = 0; i < count; i++) {
            if (fc[i].exhausted) continue;
            if (!bestk || zsi_cmp(db->compar, fc[i].cur.key, fc[i].cur.keylen,
                                     bestk, bestkl) < 0) {
                bestk = fc[i].cur.key;
                bestkl = fc[i].cur.keylen;
            }
        }
        if (!bestk) break;

        /* Gather this key's versions in D-17b's order.  The inputs are indexed by
         * increasing start generation, so ascending i IS oldest to newest. */
        struct zsi_merge_key mk;
        memset(&mk, 0, sizeof(mk));

        for (size_t i = 0; i < count; i++) {
            if (fc[i].exhausted) continue;
            if (zsi_cmp(db->compar, fc[i].cur.key, fc[i].cur.keylen, bestk, bestkl) != 0)
                continue;

            mk.have = true;
            mk.v3 = fc[i].cur;      /* D-17b: last writer in the order wins */

            r = zsi_fcur_next(&fc[i]);
            if (r != ZS_OK) goto out;
        }

        if (!mk.have) break;

        /* D-18/D-19: a tombstone is kept if and only if the newest record for
         * its key below the output range is a value.  Otherwise the key goes
         * entirely -- either its whole lifespan is inside the inputs, or a
         * deletion below already hides everything under it.
         *
         * D-19a: a record is written even when a NEWER file already shadows the
         * key.  Being shadowed does not permit dropping it; only D-19 does.
         * That is a cost argument now rather than a correctness one -- proving a
         * newer file shadows a key needs a lookup per KEY, where the test below
         * needs one per surviving tombstone -- but the rule is unchanged, and
         * T-7 constructs the resurrection that follows from removing it. */
        if (zsi_rec_is_delete(&mk.v3)
            && !zsi_repack_value_below(db, snap, first,
                                       mk.v3.key, mk.v3.keylen))
            continue;                           /* drop the key */

        r = zsi_inorder_add(&body, mk.v3.key, mk.v3.keylen, mk.v3.val,
                            mk.v3.vallen);
        if (r != ZS_OK) goto out;
        nptrs++;
    }

    /* D-22: the output may legitimately contain ZERO records, in F-26g's form --
     * every key deleted, or a create and its delete repacked together.  It MUST
     * still be written, so the generation range stays tiled (D-6).  It is cheap and
     * short-lived: an empty file violates D-16's size relation maximally, so the
     * next repack absorbs it. */

    struct zsi_layout lay;
    char trailer[ZSI_TRAILER_LEN];
    r = zsi_inorder_layout(&body, &lay);
    if (r != ZS_OK) goto out;

    memset(&h, 0, sizeof(h));
    h.version_read = ZSI_VERSION_READ;
    h.version_write = ZSI_VERSION_WRITE;
    h.flags = (uint16_t)db->create_csum_id;
    if (lay.val_wide) h.flags |= ZSI_HDR_FLAG_WIDEVAL;
    memcpy(h.uuid, db->uuid, 16);
    h.start = out_start;
    h.end = out_end;
    memcpy(h.compar_name, db->compar_name, ZSI_COMPAR_NAME_LEN);
    h.keys_len = lay.keys_len;
    h.values_len = lay.values_len;
    zsi_header_encode(hdr, &h, cs);

    r = zsi_staging_open(db, sname, &fd);
    if (r != ZS_OK) goto out;

    /* The header states every section's length before a body byte is written
     * (D-20c), then the emit streams the body out of the inputs' mappings. */
    r = zsi_write_all(fd, hdr, sizeof(hdr));
    if (r == ZS_OK)
        r = zsi_inorder_emit(&body, &lay, cs, db->create_csum_id,
                             db->merge_memory, fd, NULL, trailer);
    if (r == ZS_OK)
        r = zsi_write_at(fd, trailer, sizeof(trailer), (off_t)lay.values_end);
    /* Durable before the rename, in every durability mode (C-6b). */
    if (r == ZS_OK && ZS_FDATASYNC(fd) < 0) r = ZS_IOERROR;
    close(fd);
    fd = -1;

    snprintf(spath, sizeof(spath), "%s/%s", db->dir, sname);
    if (r != ZS_OK) { unlink(spath); goto out; }

    /* D-21: renamed to a name covering the ENTIRE range of every input, only once
     * complete.  C-1b: publishing needs no lock. */
    zsi_name_format(fname, db->uuid, out_start, out_end);
    snprintf(fpath, sizeof(fpath), "%s/%s", db->dir, fname);
    if (ZS_RENAME(spath, fpath) < 0) { ZS_UNLINK(spath); r = ZS_IOERROR; goto out; }

    /* A-17, counted at the PUBLISH rather than at the write: a staged output that
     * never got renamed cost the disk the same bytes, but it is not what a caller
     * asking "how much did I rewrite" means, and counting it would make the
     * numbers move on failures that changed nothing. */
    db->stats.repack_records += (uint64_t)nptrs;
    db->stats.repack_bytes += (uint64_t)lay.values_end + ZSI_TRAILER_LEN;

    {                                           /* C-6, every mode (C-6b) */
        int dfd = open(db->dir, O_RDONLY);
        if (dfd >= 0) {
            if (ZS_FDATASYNC(dfd) < 0)
                db->error("directory sync failed after publishing a repack output",
                          "dir=<%s>", db->dir);
            close(dfd);
        }
    }

out:
    if (fd >= 0) close(fd);
    zsi_inorder_out_fini(&body);
    free(fc);
    return r;
}

/* One repack: select, merge, publish, retire the inputs.
 *
 * D-16b: a cascade writes ONE output for the whole selected set, not one per pair.
 * A single invocation is therefore unbounded in duration, which the spec records
 * as an open item -- writing continues throughout regardless, because the repack
 * lock and the write lock never contend (C-1a). */
/* Merge snap->files[first .. first+count) into one, retire the inputs, refresh.
 *
 * THE single merge entry point.  Both zsi_repack and zsi_compact reach the merge
 * through here, so D-17 to D-23 are implemented once: a second call site for
 * zsi_repack_merge is exactly how two sets of retention rules would drift apart,
 * and D-19's tombstone rule is the one nobody would notice diverging.
 *
 * The caller holds the repack lock and has refreshed under it. */
static int zsi_repack_run(struct zs_db *db, size_t first, size_t count)
{
    /* A-17's timing spans the WHOLE merge, not just the write: the refresh and
     * the input removals are part of what a caller's begin waits for, and a
     * duration that excluded them would understate exactly what the counter
     * exists to expose.  Counted here rather than in the two callers because
     * this is the single merge entry point, so D-26's compaction lands in the
     * same bucket -- deliberately, since a compaction IS a repack of everything,
     * and a caller that wants them apart brackets its own zs_db_compact call. */
    uint64_t t0 = zsi_now_ns();
    int r;

    /* Remember the input names before the merge: the snapshot is replaced by the
     * refresh below, and the names are what D-23 needs. */
    char (*names)[ZSI_NAME_MAX] = malloc(count * sizeof(*names));
    if (!names) return ZS_INTERNAL;
    db->stats.repacks++;
    for (size_t i = 0; i < count; i++)
        zsi_name_format(names[i], db->uuid,     /* in-order only (D-16) */
                        db->snap->files[first + i]->hdr.start,
                        db->snap->files[first + i]->hdr.end);

    r = zsi_repack_merge(db, db->snap, first, count);
    if (r != ZS_OK) { free(names); db->stats.repack_ns += zsi_since_ns(t0); return r; }

    r = zsi_db_refresh(db);
    if (r != ZS_OK) { free(names); db->stats.repack_ns += zsi_since_ns(t0); return r; }

    /* Retire the inputs (D-23).  Each is now superseded by the output, so each
     * verification succeeds -- but a failure is not fatal: a leaked file costs
     * disk space and a later pass removes it. */
    for (size_t i = 0; i < count; i++) {
        int rr = zsi_remove_file(db, names[i]);
        (void)rr;
    }

    free(names);
    r = zsi_db_refresh(db);
    db->stats.repack_ns += zsi_since_ns(t0);
    return r;
}

static int zsi_repack(struct zs_db *db)
{
    int r = zsi_check_writable(db);
    if (r != ZS_OK) return r;

    r = zsi_lock_take(&db->locks, ZSI_LOCK_REPACK,
                      db->nonblocking ? ZS_NONBLOCKING : 0);
    if (r != ZS_OK) return r;

    /* Refresh under the lock: another process may have repacked while we waited. */
    r = zsi_db_refresh(db);
    if (r != ZS_OK) goto out;

    size_t first, count;
    count = zsi_repack_select(db->snap, db->repack_max_size, &first);
    if (count < 2) { r = ZS_OK; goto out; }     /* nothing to do */

    r = zsi_repack_run(db, first, count);

out:
    zsi_lock_release(&db->locks, ZSI_LOCK_REPACK);
    return r;
}

/* D-26: the whole database into one file.
 *
 * Unbounded by design (D-29), holding the repack lock throughout while writers
 * continue -- the same shape zs_db_repack already has, and spec open item 1's
 * unboundedness now a deliberate API entry point rather than an emergent
 * property of D-16's cascade.
 *
 * Lock order is WRITE then REPACK (C-1d), and the write lock is released before
 * the merge, so the merge runs holding repack alone and a long compaction does
 * not block writers throughout.  C-1d had to be AMENDED twice for this: first
 * because it said nothing holds both write and repack, then to REVERSE the two,
 * because C-1l's compacting seal is already inside a write transaction when it
 * wants repack and so has no repack-first form.  Compaction is the operation
 * that adapts, since it begins holding nothing.
 *
 * Releasing write while still holding repack is out of order and is safe: a
 * cycle needs two actors each ACQUIRING what the other holds, so only
 * acquisition is ordered. */
static int zsi_compact(struct zs_db *db)
{
    size_t first, count;
    int r = zsi_check_writable(db);
    if (r != ZS_OK) return r;

    /* zsi_seal_locked does not make this check for itself, and the reason it
     * must be made is the same: sealing under an open write transaction would
     * convert a file that transaction is about to append to. */
    if (db->write_txn) return ZS_BADUSAGE;

    r = zsi_lock_take(&db->locks, ZSI_LOCK_WRITE,
                      db->nonblocking ? ZS_NONBLOCKING : 0);
    if (r != ZS_OK) return r;

    r = zsi_lock_take(&db->locks, ZSI_LOCK_REPACK,
                      db->nonblocking ? ZS_NONBLOCKING : 0);
    if (r != ZS_OK) {
        zsi_lock_release(&db->locks, ZSI_LOCK_WRITE);
        return r;
    }

    /* Steps 1 and 2: seal the active generation, and convert any straggler.  The
     * write lock is already held, so this is the inner form; it converts pending
     * files on its way out. */
    r = zsi_seal_locked(db);

    /* C-1d: drop WRITE before the merge, whatever the seal returned. */
    zsi_lock_release(&db->locks, ZSI_LOCK_WRITE);

    if (r != ZS_OK) goto out;

    r = zsi_db_refresh(db);
    if (r != ZS_OK) goto out;

    /* Step 3: merge every maximal RUN of adjacent in-order files, largest job
     * first, until none of two or more remains.
     *
     * Runs, not the in-order prefix (D-26a).  D-16's geometric selection does not
     * apply -- it exists to keep a repack amortised and compaction is explicitly
     * the unamortised case -- but adjacency still does (D-19), so a file nothing
     * can convert splits the set into runs that must each be merged separately.
     * Taking only the prefix would merge NOTHING when such a file sits second,
     * which is exactly the damaged database where D-28's "everything mergeable"
     * has to mean something.
     *
     * Terminates because each pass reduces nfiles by at least one, and
     * zsi_repack_run refreshes, so the next scan sees the new set. */
    for (;;) {
        size_t i = 0;
        bool found = false;

        while (i < db->snap->nfiles) {
            if (zsi_file_is_unordered(db->snap->files[i])) { i++; continue; }

            first = i;
            while (i < db->snap->nfiles
                   && !zsi_file_is_unordered(db->snap->files[i])) i++;
            count = i - first;

            if (count >= 2) { found = true; break; }
        }

        if (!found) break;

        r = zsi_repack_run(db, first, count);
        if (r != ZS_OK) goto out;
    }

    /* D-28: strict in reporting, having already done everything it could.  What
     * blocks a single file is a non-active file with an invalid header -- D-10a
     * tolerates it, and it can be neither converted nor merged, so it sits in
     * the middle of the range and stops the in-order prefix there. */
    if (db->snap->nfiles != 1) {
        for (size_t i = 0; i < db->snap->nfiles; i++)
            if (!db->snap->files[i]->hdr_valid)
                db->error("file cannot be merged; compaction left it in place",
                          "file=<%s>", db->snap->files[i]->fname);
        r = ZS_BADFORMAT;
    }

out:
    zsi_lock_release(&db->locks, ZSI_LOCK_REPACK);
    return r;
}

int zs_db_repack(struct zs_db *db)
{
    if (!db) return ZS_BADUSAGE;
    return zsi_repack(db);
}

int zs_db_seal(struct zs_db *db)
{
    if (!db) return ZS_BADUSAGE;
    return zsi_seal(db);
}

int zs_db_compact(struct zs_db *db)
{
    if (!db) return ZS_BADUSAGE;
    return zsi_compact(db);
}

bool zs_db_should_repack(struct zs_db *db)
{
    if (!db) return false;
    return zsi_should_repack(db->snap, db->repack_max_size);
}

/* A-17.  A copy of counters this handle has been keeping, so a caller can
 * attribute a write's cost to the rewriting that D-12 and D-16 do behind it.
 *
 * Takes no lock, opens nothing and reads no file: everything here was counted as
 * this handle did the work, which is also the limit of what it can report -- a
 * repack another process performed is invisible, and has to be, since nothing on
 * disk records who rewrote what (D-3: there is no manifest). */
int zs_db_stats(struct zs_db *db, struct zs_db_stats *out)
{
    if (!db || !out) return ZS_BADUSAGE;
    *out = db->stats;
    return ZS_OK;
}

/********** CONSISTENCY *************/

/* Checks a reader deliberately does NOT perform, gathered here.
 *
 * Two categories, and the distinction matters:
 *
 *   - things too expensive for open, which must stay O(1) (F-31): the records
 *     region checksum (F-26f), and the pointer array's key ordering;
 *   - things that are non-canonical rather than invalid (F-15, F-17): a big form
 *     whose lengths would have fitted the short one, an ancestor stored when it
 *     equals the file's own start.  A conforming writer never produces these, but
 *     REJECTING them on read would discard committed data -- a record that fails to
 *     validate makes an unordered file complete at that point (F-24), and G-3
 *     forbids that costing committed data.  So they are reported here and read
 *     normally there, which is the division T-6 sets out.
 */

static void zsi_report(struct zs_db *db, const char *what, const char *fname,
                       unsigned long long detail)
{
    db->error(what, "file=<%s> at=<%llu>", fname, detail);
}

/* Whether key entry i uses the form F-15 requires: the big form only when the
 * key does not fit the short one.  The valptr width is a FILE property (F-26c)
 * and is checked once, not per entry. */
static bool zsi_kent_is_canonical(const struct zsi_file *f, uint64_t i)
{
    uint64_t off = zsi_ptrs_at(f, i);
    struct zsi_kent e;
    const char *b;

    if (off < f->keys_off || off >= f->keys_end) return false;
    b = zsi_file_at(f, (size_t)off, 1);
    if (!b) return false;
    if (zsi_kent_decode(b, f->keys_end - (size_t)off, f->val_wide, &e) != ZS_OK)
        return false;

    return ((e.type & ZSI_ISBIG) != 0) == (e.keylen > ZSI_SHORT_KEYLEN_MAX);
}

/* F-28: an in-order file's pointer array MUST be strictly increasing by key.
 *
 * That confirms the sort AND catches a repack that emitted a key twice (D-17) --
 * two failures a binary search cannot detect, because it would simply return wrong
 * answers over a misordered array rather than noticing. */
static int zsi_check_inorder(struct zs_db *db, struct zsi_file *f)
{
    /* `prev` is read only under `i > 0`, where the previous iteration's
     * `prev = cur` has run -- but GCC 15 cannot follow that across the loop and
     * reports it -Wmaybe-uninitialized, which Cyrus's -Werror turns fatal. */
    struct zsi_rec prev = {0}, cur;
    int r = ZS_OK;

    for (uint64_t i = 0; i < f->nptrs; i++) {
        if (zsi_ptrs_rec(f, i, &cur) != ZS_OK) {
            zsi_report(db, "record does not decode", f->fname, i);
            return ZS_BADFORMAT;
        }

        if (i > 0) {
            int c = zsi_cmp(db->compar, prev.key, prev.keylen, cur.key, cur.keylen);
            if (c == 0) {
                zsi_report(db, "duplicate key in pointer array", f->fname, i);
                r = ZS_BADFORMAT;
            } else if (c > 0) {
                zsi_report(db, "pointer array not sorted by key", f->fname, i);
                r = ZS_BADFORMAT;
            }
        }

        /* F-15 non-canonical encodings, reported not rejected.  For a key entry
         * the only choice is the big form, so this is exactly "a short key
         * stored big". */
        if (!zsi_kent_is_canonical(f, i)) {
            zsi_report(db, "non-canonical key entry encoding", f->fname, i);
            r = ZS_BADFORMAT;
        }

        /* F-28: valptrs non-decreasing and inside the values region, which is
         * what makes F-36's derived lengths meaningful.  Non-DEcreasing rather
         * than increasing, because a tombstone contributes no value bytes and so
         * repeats its successor's pointer (F-35). */
        {
            uint64_t vp = zsi_kent_valptr_at(f, i);
            uint64_t nx = zsi_kent_valptr_at(f, i + 1);

            if (vp == UINT64_MAX || nx == UINT64_MAX) {
                zsi_report(db, "key entry does not decode", f->fname, i);
                r = ZS_BADFORMAT;
            } else if (vp < f->values_off || vp > f->values_end) {
                zsi_report(db, "valptr outside the values region", f->fname, i);
                r = ZS_BADFORMAT;
            } else if (nx < vp) {
                zsi_report(db, "valptr not monotonic", f->fname, i);
                r = ZS_BADFORMAT;
            }
        }

        prev = cur;
    }

    /* F-28: the sentinel's valptr is exactly one past the values region.  It is
     * what bounds the LAST record's value, so an error here is one wrong value
     * rather than a structural failure -- which is precisely why it needs
     * checking rather than trusting. */
    {
        uint64_t sent = zsi_kent_valptr_at(f, f->nptrs);
        if (sent != (uint64_t)f->values_end) {
            zsi_report(db, "sentinel valptr is not the end of the values region",
                       f->fname, f->nptrs);
            r = ZS_BADFORMAT;
        }
    }

    /* F-26c: both widths are canonical.  Re-derived rather than believed: a file
     * whose flag says wide when narrow would fit is readable and wrong, exactly
     * like a non-canonical entry, so it is reported and not rejected. */
    if (f->ptr_wide != (f->values_off > 0xFFFFFFFFu)) {
        zsi_report(db, "pointer width is not canonical", f->fname, 0);
        r = ZS_BADFORMAT;
    }
    if (f->val_wide != (f->values_end > 0xFFFFFFFFu)) {
        zsi_report(db, "valptr width is not canonical", f->fname, 0);
        r = ZS_BADFORMAT;
    }

    /* F-33: the data checksum over the keys and values regions, which is the
     * only thing that detects either corrupted in place -- and, since no read
     * path consults it (F-33a), the only thing that detects it at all. */
    if (zsi_ptrs_verify_records(f) != ZS_OK) {
        zsi_report(db, "data region checksum mismatch", f->fname, 0);
        r = ZS_BADCHECKSUM;
    }

    return r;
}

struct zsi_check_unordered {
    struct zs_db    *db;
    struct zsi_file *f;
    int              result;
};

static int zsi_check_rec_cb(void *rock, const struct zsi_rec *rec, size_t off)
{
    struct zsi_check_unordered *c = rock;

    if (!zsi_rec_is_canonical(rec)) {
        zsi_report(c->db, "non-canonical record encoding", c->f->fname, off);
        c->result = ZS_BADFORMAT;
    }

    /* There is no per-record checksum to check (F-13a).  A record inside a
     * span the replay just validated is covered by that span's checksum, which
     * is the only thing that ever protected an unordered file's body -- and
     * F-5e verifies it at indexing time in every mode, so by the time this
     * callback runs the bytes have been proved. */
    (void)off;

    return 0;
}

static int zsi_check_unordered_file(struct zs_db *db, struct zsi_file *f)
{
    struct zsi_check_unordered ctx = { db, f, ZS_OK };
    int r;

    if (!f->hdr_valid) {
        /* D-10: legal for the active file, and already an error for any other
         * (D-10a), so nothing to report here. */
        return ZS_OK;
    }

    /* The replay validates every span's checksum as it goes, so a torn or
     * corrupted span shows up as a complete point short of the file's end. */
    r = zsi_unordered_replay(f, ZSI_HEADER_LEN, zsi_check_rec_cb, &ctx);
    if (r != ZS_OK) return r;

    if (f->complete != f->size) {
        /* Not an error: F-24 makes this an ordinary state, and D-9 has the writer
         * move on rather than repair.  Reported so a tool can say so. */
        zsi_report(db, "content after the last valid span", f->fname,
                   (unsigned long long)f->complete);
    }

    /* A terminator whose width is not the canonical one for its span (F-15). */
    size_t pos = ZSI_HEADER_LEN;
    while (pos < f->complete) {
        const char *b = zsi_file_at(f, pos, 1);
        if (!b) break;

        uint8_t type = (uint8_t)b[0];
        if (type & ZSI_SPANTERM) {
            struct zsi_term t;
            if (zsi_term_decode(b, f->size - pos, &t) != ZS_OK) break;
            if (!zsi_term_is_canonical(&t)) {
                zsi_report(db, "non-canonical terminator width", f->fname, pos);
                ctx.result = ZS_BADFORMAT;
            }
            pos += t.len;
            continue;
        }

        struct zsi_rec rec;
        if (zsi_rec_decode(b, f->size - pos, &rec) != ZS_OK) break;
        if (rec.len == 0) break;
        pos += rec.len;
    }

    return ctx.result;
}

int zs_db_check_consistency(struct zs_db *db)
{
    int result = ZS_OK;

    if (!db) return ZS_BADUSAGE;

    for (size_t i = 0; i < db->snap->nfiles; i++) {
        struct zsi_file *f = db->snap->files[i];
        int r = zsi_file_is_unordered(f) ? zsi_check_unordered_file(db, f)
                                        : zsi_check_inorder(db, f);
        if (r != ZS_OK) result = r;
    }

    /* D-6: the resolved ranges must tile.  Checked last, because a per-file
     * problem is more specific and more useful to report. */
    struct zsi_fileset fs;
    int r = zsi_fileset_scan(db->dir, &db->uuid, &fs);
    if (r == ZS_OK) {
        r = zsi_fileset_resolve(&fs);
        zsi_fileset_fini(&fs);
        if (r != ZS_OK) {
            zsi_report(db, "file set does not tile", db->dir, 0);
            result = r;
        }
    }

    return result;
}

/* zs_db_dump: print structure.
 *
 * The line format is a compatibility surface, because it is what T-0a's `dump`
 * subcommand emits and what the interop runner compares as text.  Changing it
 * breaks the runner, not just a human's expectations.
 *
 *   FILE <name> kind=<unordered|inorder> start=<N> end=<N> csum=<id> size=<N>
 *   SPAN <off> len=<N> term=<COMMIT|ROLLBACK> records=<N>
 *   REC  <off> type=<0xNN> keylen=<N> vallen=<N|-> anc=<N> key=<hex>
 *   PTRS <off> width=<32|64> count=<N>
 */
static void zsi_dump_hex(const char *p, size_t n)
{
    for (size_t i = 0; i < n; i++)
        printf("%02x", (unsigned char)p[i]);
}

static void zsi_dump_rec(const struct zsi_rec *r, size_t off, int detail)
{
    printf("REC  %zu type=0x%02X keylen=%zu ", off, r->type, r->keylen);
    if (r->val) printf("vallen=%zu ", r->vallen);
    else        printf("vallen=- ");
    printf("key=");
    zsi_dump_hex(r->key, r->keylen);
    if (detail > 1 && r->val) {
        printf(" val=");
        zsi_dump_hex(r->val, r->vallen);
    }
    printf("\n");
}

struct zsi_dump_ctx { int detail; size_t nrecs; };

static int zsi_dump_cb(void *rock, const struct zsi_rec *rec, size_t off)
{
    struct zsi_dump_ctx *c = rock;
    c->nrecs++;
    if (c->detail > 0) zsi_dump_rec(rec, off, c->detail);
    return 0;
}

int zs_db_dump(struct zs_db *db, int detail)
{
    if (!db) return ZS_BADUSAGE;

    for (size_t i = 0; i < db->snap->nfiles; i++) {
        struct zsi_file *f = db->snap->files[i];
        const char *base = strrchr(f->fname, '/');
        base = base ? base + 1 : f->fname;

        printf("FILE %s kind=%s start=%u end=%u csum=%u size=%zu\n",
               base, zsi_file_is_unordered(f) ? "unordered" : "inorder",
               f->hdr.start, f->hdr.end, f->csum_id, f->size);

        if (zsi_file_is_unordered(f)) {
            /* Walk the spans directly, so a ROLLBACK is reported rather than
             * silently skipped -- the whole point of a dump is to show what is
             * there, including what a reader ignores. */
            size_t pos = ZSI_HEADER_LEN;
            while (pos < f->complete) {
                size_t span_start = pos;
                size_t nrecs = 0;

                for (;;) {
                    const char *b = zsi_file_at(f, pos, 1);
                    if (!b) break;
                    uint8_t type = (uint8_t)b[0];

                    if (type & ZSI_SPANTERM) {
                        struct zsi_term t;
                        if (zsi_term_decode(b, f->size - pos, &t) != ZS_OK) break;
                        printf("SPAN %zu len=%llu term=%s records=%zu\n",
                               span_start, (unsigned long long)t.spanlen,
                               zsi_term_is_rollback(&t) ? "ROLLBACK" : "COMMIT",
                               nrecs);
                        pos += t.len;
                        break;
                    }

                    struct zsi_rec rec;
                    if (zsi_rec_decode(b, f->size - pos, &rec)
                        != ZS_OK) break;
                    if (rec.len == 0) break;
                    if (detail > 0) zsi_dump_rec(&rec, pos, detail);
                    nrecs++;
                    pos += rec.len;
                }

                if (pos <= span_start) break;
            }
        } else {
            /* The regions, because a format-3 file's most likely damage is a
             * shape that does not add up (F-31a) and nothing else in this dump
             * would show it.  valwidth is a FILE property (F-26c), separate
             * from the pointer width, so both are named. */
            printf("PTRS %zu width=%d count=%llu\n", f->ptr_off,
                   f->ptr_wide ? 64 : 32, (unsigned long long)f->nptrs);
            printf("KEYS %zu len=%llu valwidth=%d\n", f->keys_off,
                   (unsigned long long)f->hdr.keys_len, f->val_wide ? 64 : 32);
            printf("VALS %zu len=%llu\n", f->values_off,
                   (unsigned long long)f->hdr.values_len);
            if (detail > 0) {
                for (uint64_t j = 0; j < f->nptrs; j++) {
                    struct zsi_rec rec;
                    if (zsi_ptrs_rec(f, j, &rec) != ZS_OK) break;
                    zsi_dump_rec(&rec, (size_t)zsi_ptrs_at(f, j), detail);
                }
            }
        }
    }

    (void)zsi_dump_cb;
    return ZS_OK;
}

/* T-0a: the pointer table, as text a runner can compare byte for byte.
 *
 * Validation goes through the same loader the read path uses, so what this
 * reports is the real acceptance decision (P-11) rather than a second parser
 * that could disagree with it -- which is the failure mode a separate dumper
 * would introduce, and nobody would notice until two implementations argued.
 *
 * Never an error: no cache directory, no table, and a rejected table are all
 * states to report, because a table is never required. */
int zs_db_index_dump(struct zs_db *db)
{
    struct zsi_idxcfg cfg;

    if (!db) return ZS_BADUSAGE;

    cfg.dir = db->index_dir;
    cfg.threshold = db->index_threshold;
    cfg.local = db->index_local;

    if (!db->index_dir) {
        printf("INDEXDIR none\n");
        return ZS_OK;
    }

    printf("INDEXDIR set threshold=%zu\n", db->index_threshold);

    for (size_t i = 0; i < db->snap->nfiles; i++) {
        struct zsi_file *f = db->snap->files[i];
        char name[ZSI_NAME_MAX];
        size_t *base = NULL, nbase = 0, vu = 0, to = 0;
        uint64_t tc = 0;

        /* P-1: only unordered files have tables. */
        if (!zsi_file_is_unordered(f) || !f->hdr_valid) continue;

        zsi_name_format_index(name, f->hdr.uuid, f->hdr.start);

        if (zsi_idx_load(f, &cfg, db->compar_name,
                         &base, &nbase, &vu, &to, &tc) != ZS_OK) {
            printf("TABLE %s state=absent\n", name);
            continue;
        }

        printf("TABLE %s state=usable generation=%08X valid_upto=%zu"
               " term_off=%zu term_csum=%016llX nptrs=%zu\n",
               name, f->hdr.start, vu, to, (unsigned long long)tc, nbase);
        free(base);
    }

    return ZS_OK;
}

/********** OPEN AND CLOSE *************/

/* OPENING IS RECOVERY; there is no separate pass (section 7).
 *
 * R-1: scan the directory, resolve enclosures, check the tiling, map the files,
 * then replay each unordered file's spans from its start -- building the private
 * index as it goes and stopping at the first record or terminator that fails to
 * validate, which establishes that file's end.  All of that is C-4, which the
 * snapshot already does, so open is mostly configuration plus one snapshot.
 *
 * R-4: there is no in-place repair.  A file that is not clean is simply complete
 * at its last valid span, and the writer moves to a new generation.  Nothing is
 * ever appended past a boundary that failed to validate, so a spurious terminator
 * in trailing garbage -- which a checksum can never wholly exclude -- cannot
 * become the foundation of a later chain.  Generations are cheap. */

/* Every file of a database MUST carry the same UUID and the same comparator name
 * (F-11).  The comparator determines key order and hence the meaning of the
 * pointer section, so it is recorded per file -- there is no manifest to hold it.
 * Opening a database whose files disagree, or whose comparator differs from the
 * caller's, is an error rather than something to reconcile: reading a file whose
 * pointer array was built under a different order silently returns wrong
 * answers. */
static int zsi_db_check_agreement(struct zs_db *db)
{
    for (size_t i = 0; i < db->snap->nfiles; i++) {
        struct zsi_file *f = db->snap->files[i];

        /* A-6 first, because it applies to files whose header did not validate:
         * unverifiable for want of the caller's engine is a usage error, and must
         * not be swallowed by D-10's tolerance of a corrupt ACTIVE file. */
        if (f->needs_external_csum) return ZS_BADUSAGE;

        if (!f->hdr_valid) continue;        /* the D-10 active-file case */

        if (memcmp(f->hdr.uuid, db->uuid, 16) != 0) return ZS_BADFORMAT;
        if (memcmp(f->hdr.compar_name, db->compar_name,
                   ZSI_COMPAR_NAME_LEN) != 0)
            return ZS_BADFORMAT;

        /* A-6: a file recording engine 2 is readable only by a caller supplying
         * the same function.  zsi_file_open leaves such a header invalid when it
         * cannot resolve the engine, so this catches the case where the file is
         * otherwise fine. */
        if ((f->hdr.flags & ZSI_CSUM_MASK) == ZSI_CSUM_EXTERNAL
            && !db->external_csum)
            return ZS_BADUSAGE;

        /* F-7: refuse to WRITE above our write version, while still allowing the
         * file to be read.  The read gate is in zsi_header_decode. */
        if (!db->readonly && f->hdr.version_write > ZSI_VERSION_WRITE)
            return ZS_READONLY;
    }

    return ZS_OK;
}

static int zsi_db_open(const char *dir, struct zs_open_data *setup,
                       const char *uuid_str, struct zs_db **dbp)
{
    struct zs_open_data defaults = ZS_OPEN_DATA_INITIALIZER;
    struct zs_db *db;
    int r;

    if (!dir || !dbp) return ZS_BADUSAGE;
    if (!setup) setup = &defaults;
    *dbp = NULL;

    db = zsi_zmalloc(sizeof(*db));
    if (!db) return ZS_INTERNAL;

    db->locks.fd = -1;
    db->wfd_cache = -1;
    db->flags = setup->flags;
    db->readonly = (setup->flags & ZS_SHARED) != 0;
    db->no_auto_repack = (setup->flags & ZS_NOAUTOREPACK) != 0;
    db->nosync = (setup->flags & ZS_NOSYNC) != 0;
    db->nonblocking = (setup->flags & ZS_NONBLOCKING) != 0;
    db->rollover_size = setup->rollover_size ? setup->rollover_size
                                             : ZSI_DEFAULT_ROLLOVER;
    db->rollover_txns = setup->rollover_txns ? setup->rollover_txns
                                             : ZSI_DEFAULT_ROLLOVER_TXNS;
    db->repack_max_size = setup->repack_max_size ? setup->repack_max_size
                                                 : ZSI_DEFAULT_REPACK_MAX;
    db->merge_memory = setup->merge_memory ? setup->merge_memory
                                           : ZSI_DEFAULT_MERGE_MEMORY;
    db->error = setup->error ? setup->error : zsi_default_error;
    db->external_csum = setup->csum;
    db->create_csum_id = zsi_csum_id_for_flags(setup->flags);

    /* A-6: engine 2 needs a function, or files this handle creates cannot be
     * verified by anyone including us. */
    if (db->create_csum_id == ZSI_CSUM_EXTERNAL && !db->external_csum) {
        free(db);
        return ZS_BADUSAGE;
    }

    /* F-11a/F-11b: the default comparator is named "memcmp"; a caller supplying
     * its own MUST supply a name, and names are compared byte for byte. */
    if (setup->compar) {
        if (!zsi_compar_name_valid(setup->compar_name)) {
            free(db);
            return ZS_BADUSAGE;
        }
        db->compar = setup->compar;
        snprintf(db->compar_name, sizeof(db->compar_name) + 0, "%s",
                 setup->compar_name);
        /* snprintf NUL-terminates within 16; the field is NUL-PADDED, and
         * zsi_zmalloc already zeroed it, so the padding is correct. */
    } else {
        db->compar = zsi_compar_default;
        memcpy(db->compar_name, "memcmp", 6);
    }

    db->dir = strdup(dir);
    if (!db->dir) { free(db); return ZS_INTERNAL; }

    db->index_local = (setup->flags & ZS_INDEX_LOCAL) != 0;

    /* A-8a: the two name different locations for the same tables, so setting
     * both is ambiguous, not a preference order. */
    if (db->index_local && setup->index_dir) {
        free(db->dir);
        free(db);
        return ZS_BADUSAGE;
    }

    if (setup->index_dir) {
        /* A-8/P-2, the cheap half: identical strings, caught before anything is
         * created.  The resolved-path half has to wait until the database
         * directory exists -- see below. */
        if (strcmp(dir, setup->index_dir) == 0) {
            free(db->dir);
            free(db);
            return ZS_BADUSAGE;
        }

        db->index_dir = strdup(setup->index_dir);
        if (!db->index_dir) { free(db->dir); free(db); return ZS_INTERNAL; }
    }

    if (setup->index_dir || db->index_local) {
        /* A-9.  Zero is kept as zero, and means "derive it from the file" at the
         * publish site -- see ZSI_INDEX_PUBLISHES_PER_GEN.  It cannot be resolved
         * here, because the quantity it scales with is the active file's own size
         * and that changes as the file grows. */
        db->index_threshold = setup->index_threshold;
    }

    /* Is there anything here?  A directory that does not exist, or holds no data
     * files, is the empty case D-8a handles. */
    struct zsi_fileset probe;
    /* The RAW scan: a data file whose header did not survive still proves the
     * database EXISTS, even though D-1b leaves its generation unknown and D-10
     * keeps it out of the resolved set.  The filling scan would drop it and the
     * directory would read as empty -- so a crash during the very first header
     * write would leave a database that only ZS_CREATE could open, which is
     * exactly the "any state a crash can produce reopens" that G-3 forbids.
     * The uuid is still in the name, so discovery (D-4a) works regardless. */
    r = zsi_fileset_scan_raw(dir, NULL, &probe);
    bool empty = (r == ZS_NOTFOUND) || (r == ZS_OK && probe.nall == 0);
    bool discovered = (r == ZS_OK && probe.nall > 0);

    if (discovered) {
        memcpy(db->uuid, probe.uuid, 16);
        db->have_uuid = true;
    }
    if (r == ZS_OK) zsi_fileset_fini(&probe);
    else if (r != ZS_NOTFOUND) { zs_db_close(&db); return r; }

    if (empty) {
        if (!(setup->flags & ZS_CREATE)) { zs_db_close(&db); return ZS_NOTFOUND; }
        if (db->readonly) { zs_db_close(&db); return ZS_READONLY; }

        if (mkdir(dir, 0700) && errno != EEXIST) { zs_db_close(&db); return ZS_IOERROR; }

        if (uuid_str) {
            if (zsi_uuid_parse(uuid_str, db->uuid) != 0) {
                zs_db_close(&db);
                return ZS_BADUSAGE;
            }
        } else {
            zsi_uuid_generate(db->uuid);
        }
        db->have_uuid = true;
    }

    /* A-8/P-2.  The cache directory must not be the database directory: writing
     * a table there would be a write to the database, and the R-3 amendment
     * permits a read-only handle to publish only because a cache directory is
     * somewhere else.
     *
     * Checked HERE rather than at the top of this function, because with
     * ZS_CREATE the database directory does not exist until the mkdir above and
     * realpath cannot resolve a directory that is not there yet.  Checking early
     * would let the very first open -- the one that creates the database -- slip
     * through with the two directories identical.
     *
     * This is the half that catches "." and a trailing slash.  The identical-
     * string half already ran, before the mkdir. */
    if (db->index_dir) {
        char rd[PATH_MAX], rc[PATH_MAX];

        if (realpath(dir, rd) && realpath(db->index_dir, rc)
            && strcmp(rd, rc) == 0) {
            zs_db_close(&db);
            return ZS_BADUSAGE;
        }
    }

    /* A-8/A-8a: resolve the EFFECTIVE cache directory once, here, where the
     * uuid is known and the database directory exists, so publish, load,
     * sweep and dump all take a per-database path as given and none of them
     * changes.  Every failure disables the cache for this handle rather than
     * failing the open (P-15): the cache is never load-bearing. */
    if (db->index_local) {
        char path[PATH_MAX];
        struct stat st;

        if ((size_t)snprintf(path, sizeof(path), "%s/%s",
                             dir, ZSI_CACHE_DIR_NAME) >= sizeof(path)) {
            db->index_local = false;
        } else {
            /* P-2b/R-3: ANY handle creates it, a read-only one included, and the
             * reason is that the alternative was inconsistent rather than safe.
             * A read-only handle has always been allowed to PUBLISH a table into
             * this directory -- that is what makes the cache work for readers at
             * all -- so forbidding only the mkdir permitted creating files inside
             * the database while refusing to create the directory holding them.
             *
             * What made it look principled is that R-3 is about the DATABASE, and
             * nothing here is: no name in this directory parses as a data file
             * (D-2, P-3), a table is self-validating and every failure means
             * "replay instead" (P-11), so nothing in it can turn a readable
             * database into an unreadable one.  And the caller asked: the cache is
             * opt-in (A-8a).
             *
             * What it cost was the case that matters most.  Enabling the flag on a
             * read-mostly database did nothing at all until some unrelated write
             * happened to come along, so every read-only open silently replayed
             * from the top -- bimodal open latency with no way to tell which mode
             * you were in.  A read-only MOUNT still gets no cache: the mkdir fails
             * and the handle continues without one, which is the case R-3's
             * side-effect concern was really about. */
            if (mkdir(path, 0700) != 0 && errno != EEXIST)
                db->error("could not create the cache directory; continuing "
                          "without the index cache", "dir=<%s>", path);
            if (stat(path, &st) == 0 && S_ISDIR(st.st_mode)) {
                db->index_dir = strdup(path);
                if (!db->index_dir) { zs_db_close(&db); return ZS_INTERNAL; }
            } else {
                db->index_local = false;
            }
        }
    } else if (db->index_dir) {
        char uu[ZSI_UUID_STR_LEN], path[PATH_MAX];
        struct stat st;

        zsi_uuid_unparse(db->uuid, uu);

        /* P-2a: the per-uuid level is created as needed, by ANY handle -- it
         * is outside the database, so R-3 is untouched.  The ROOT is never
         * created (A-8): a missing root fails this mkdir with ENOENT, the
         * stat below fails too, and the cache is disabled for the handle. */
        free(db->index_dir);
        db->index_dir = NULL;
        if ((size_t)snprintf(path, sizeof(path), "%s/%s",
                             setup->index_dir, uu) < sizeof(path)) {
            (void)mkdir(path, 0700);
            if (stat(path, &st) == 0 && S_ISDIR(st.st_mode)) {
                db->index_dir = strdup(path);
                if (!db->index_dir) { zs_db_close(&db); return ZS_INTERNAL; }
            }
        }
    }

    /* D-3a: the lock file is created with the database, and created on open if
     * absent, so an existing database is never unopenable for want of it.
     *
     * A read-only handle skips it entirely.  Readers take no lock (C-2), so they
     * have no use for it -- and creating it would be a write, which R-3 forbids:
     * opening a damaged database read-only must be side-effect-free, and "it only
     * creates one small file" is exactly the kind of exception that makes a
     * read-only mount fail or a forensic copy differ from its original. */
    if (!db->readonly) {
        r = zsi_lock_open(&db->locks, dir);
        if (r != ZS_OK) { zs_db_close(&db); return r; }
    }

    if (empty) {
        r = zsi_create_active(db, 1);
        if (r != ZS_OK) { zs_db_close(&db); return r; }
    }

    /* R-1: the snapshot IS the recovery pass. */
    r = zsi_db_refresh(db);
    if (r != ZS_OK) { zs_db_close(&db); return r; }

    r = zsi_db_check_agreement(db);
    if (r != ZS_OK) { zs_db_close(&db); return r; }

    *dbp = db;
    return ZS_OK;
}

int zs_db_open(const char *dir, struct zs_open_data *setup, struct zs_db **dbp)
{
    return zsi_db_open(dir, setup, NULL, dbp);
}

int zs_db_open_with_uuid(const char *dir, struct zs_open_data *setup,
                         const char *uuid_str, struct zs_db **dbp)
{
    return zsi_db_open(dir, setup, uuid_str, dbp);
}

int zs_db_close(struct zs_db **dbp)
{
    struct zs_db *db = *dbp;
    if (!db) return ZS_OK;

    zsi_snapshot_release(&db->snap);
    zsi_fcache_fini(&db->fcache);       /* the handle's own references */
    zsi_lock_close(&db->locks);
    if (db->wfd_cache >= 0) close(db->wfd_cache);
    free(db->retbuf);
    free(db->index_dir);
    free(db->dir);
    free(db);
    *dbp = NULL;

    return ZS_OK;
}

/********** PUBLIC API *************/

/* A-0: every read and write entry point exists in three forms -- on the database,
 * on a transaction, and via a cursor -- and all three take flags.  The zs_db_*
 * forms are convenience wrappers that open an implicit single-operation
 * transaction, implemented LITERALLY as wrappers so the wrapped path is the only
 * path and there is no operation reachable one way but not another.
 *
 * A-2: there is no yield call and no yield flags, because readers hold no lock and
 * so have nothing to yield.  A-3: there is no MVCC flag, because snapshot
 * isolation is the only read mode.  twom has both; porting them here would be
 * copying an answer to a question this design does not ask. */

/* A-4: pointers returned by a zs_db_* call stay valid until the next call on that
 * handle.  Records read from a mapped file are stable for the snapshot's life, so
 * those are returned directly; a record from a transaction's pending array dies
 * with the implicit transaction, so it is copied into handle-owned scratch.  This
 * is the only case that needs a buffer. */
static int zsi_db_retain(struct zs_db *db, const struct zsi_rec *r,
                         const char **keyp, size_t *keylenp,
                         const char **valp, size_t *vallenp)
{
    size_t need = r->keylen + (r->val ? r->vallen : 0) + 2;

    if (need > db->retalloc) {
        char *p = realloc(db->retbuf, need);
        if (!p) return ZS_INTERNAL;
        db->retbuf = p;
        db->retalloc = need;
    }

    memcpy(db->retbuf, r->key, r->keylen);
    db->retbuf[r->keylen] = '\0';
    if (r->val && r->vallen)
        memcpy(db->retbuf + r->keylen + 1, r->val, r->vallen);
    db->retbuf[r->keylen + 1 + (r->val ? r->vallen : 0)] = '\0';

    if (keyp) *keyp = db->retbuf;
    if (keylenp) *keylenp = r->keylen;
    if (valp) *valp = db->retbuf + r->keylen + 1;
    if (vallenp) *vallenp = r->val ? r->vallen : 0;

    return ZS_OK;
}

/* transactions */

int zs_db_begin_txn(struct zs_db *db, int shared, struct zs_txn **txnp)
{
    if (!db || !txnp) return ZS_BADUSAGE;
    *txnp = NULL;
    return zsi_txn_begin(db, shared != 0, txnp);
}

int zs_txn_commit(struct zs_txn **txnp)
{
    struct zs_txn *txn;

    if (!txnp || !*txnp) return ZS_BADUSAGE;
    txn = *txnp;
    *txnp = NULL;
    return zsi_txn_commit(txn);
}

int zs_txn_abort(struct zs_txn **txnp)
{
    struct zs_txn *txn;

    if (!txnp || !*txnp) return ZS_BADUSAGE;
    txn = *txnp;
    *txnp = NULL;
    return zsi_txn_abort(txn);
}

/* fetch */

int zs_txn_fetch(struct zs_txn *txn, const char *key, size_t keylen,
                 const char **keyp, size_t *keylenp,
                 const char **valp, size_t *vallenp, int flags)
{
    struct zsi_rec r;
    int rc;

    if (!txn || !key) return ZS_BADUSAGE;
    if (keylen < 1) return ZS_BADUSAGE;

    if ((flags & ZS_FETCHNEXT) && (flags & ZS_FETCHPREV))
        return ZS_BADUSAGE;                                 /* A-12 */

    /* ZS_FETCHNEXT: the smallest key >= (or, with ZS_SKIPROOT, >) the given
     * key -- a forward cursor's first yield from that seek, so it shares the
     * merge rather than reimplementing it.
     *
     * ZS_FETCHPREV: the largest key <= (or, with ZS_SKIPROOT, <) the given
     * key.  A REVERSE cursor seeked at the key is exactly that (D-14l), so it
     * shares the merge too -- the fetch family stays two directions by two
     * bounds, and a point lookup cannot disagree with a walk (G-7). */
    if (flags & (ZS_FETCHNEXT | ZS_FETCHPREV)) {
        struct zs_cursor *c = NULL;
        /* ZS_EPHEMERAL rides along (A-4b).  Safe here and nowhere else a
         * cursor is involved: this one is opened and freed inside this call,
         * so the single record it yields is the caller's, under exactly the
         * lifetime they asked for. */
        uint32_t cflags = ((flags & ZS_FETCHNEXT) ? 0u : (uint32_t)ZS_REVERSE)
                        | ((uint32_t)flags & (ZS_SKIPROOT | ZS_EPHEMERAL));
        rc = zsi_cursor_open(txn->db, txn->readonly ? NULL : txn, txn->snap,
                             key, keylen, cflags, &c);
        if (rc != ZS_OK) return rc;
        rc = zsi_cursor_next(c, &r);
        if (rc == ZS_OK) {
            if (keyp) *keyp = r.key;
            if (keylenp) *keylenp = r.keylen;
            if (valp) *valp = r.val;
            if (vallenp) *vallenp = r.vallen;
        } else {
            rc = ZS_NOTFOUND;
        }
        zsi_cursor_free(c);
        return rc;
    }

    rc = zsi_lookup(txn->db, txn->snap, txn->readonly ? NULL : txn,
                    key, keylen, (flags & ZS_EPHEMERAL) != 0, &r);
    if (rc != ZS_OK) return rc;

    if (keyp) *keyp = r.key;
    if (keylenp) *keylenp = r.keylen;
    if (valp) *valp = r.val;
    if (vallenp) *vallenp = r.vallen;
    return ZS_OK;
}

int zs_db_fetch(struct zs_db *db, const char *key, size_t keylen,
                const char **keyp, size_t *keylenp,
                const char **valp, size_t *vallenp, int flags)
{
    struct zs_txn *txn = NULL;
    struct zsi_rec r;
    int rc;

    if (!db || !key) return ZS_BADUSAGE;

    rc = zs_db_begin_txn(db, 1, &txn);
    if (rc != ZS_OK) return rc;
    txn->implicit = true;   /* D-14j: its cursors follow this handle */

    const char *k = NULL, *v = NULL;
    size_t kl = 0, vl = 0;
    rc = zs_txn_fetch(txn, key, keylen, &k, &kl, &v, &vl, flags);

    if (rc == ZS_OK) {
        r.key = k; r.keylen = kl;
        r.val = v; r.vallen = vl;
        r.type = ZSI_KEYVALUE;
        rc = zsi_db_retain(db, &r, keyp, keylenp, valp, vallenp);
    }

    zs_txn_abort(&txn);
    return rc;
}

/* store */

int zs_txn_store(struct zs_txn *txn, const char *key, size_t keylen,
                 const char *val, size_t vallen, int flags)
{
    struct zsi_rec r;
    int rc;

    if (!txn || !key) return ZS_BADUSAGE;
    if (keylen < 1) return ZS_BADUSAGE;             /* F-14 */
    if (txn->readonly) return ZS_READONLY;          /* A-5 */

    /* ZS_IFNOTEXIST / ZS_IFEXIST / ZS_IFCHANGED are evaluated against the
     * transaction's own view, so they compose with earlier writes in the same
     * transaction (A-1a).  All three share ONE probe. */
    if (flags & (ZS_IFNOTEXIST | ZS_IFEXIST | ZS_IFCHANGED)) {
        /* Always ephemeral (A-4b): this probe wants the ANSWER, not the bytes.
         * `r` never leaves this function, so forcing the chunk out to the file
         * to look at a record we are about to discard is pure loss -- and a
         * conditional store is otherwise read-after-write on every call, which
         * is exactly the shape the flag exists for. */
        rc = zsi_lookup(txn->db, txn->snap, txn, key, keylen, true, &r);
        if ((flags & ZS_IFNOTEXIST) && rc == ZS_OK) return ZS_EXISTS;
        if ((flags & ZS_IFEXIST) && rc == ZS_NOTFOUND) return ZS_NOTFOUND;
        if (rc != ZS_OK && rc != ZS_NOTFOUND) return rc;

        /* A-1d: nothing to write when the stored state already matches.
         *
         * Compared under A-1's distinction rather than by value bytes alone: a
         * deletion matches only an absent or deleted key, and an empty value
         * over a deletion is a CHANGE.  zsi_lookup folds a tombstone into
         * ZS_NOTFOUND, so rc alone answers both halves: NOTFOUND means absent
         * or deleted, and ZS_OK means a live value -- which is why the value
         * case needs no NULL check on r.val, and why the deletion case never
         * touches r at all.
         *
         * Returning before zsi_pend_set is what makes the skip invisible: no
         * record, and no pend_seq bump, so a cursor traversing this
         * transaction does not refresh for a write that did not happen. */
        if (flags & ZS_IFCHANGED) {
            if (val == NULL) {
                if (rc == ZS_NOTFOUND) return ZS_OK;
            } else if (rc == ZS_OK && r.vallen == vallen
                       && (vallen == 0 || memcmp(r.val, val, vallen) == 0)) {
                return ZS_OK;
            }
        }
    }

    return zsi_pend_set(txn, key, keylen, val, vallen);
}

int zs_db_store(struct zs_db *db, const char *key, size_t keylen,
                const char *val, size_t vallen, int flags)
{
    struct zs_txn *txn = NULL;
    int rc;

    if (!db || !key) return ZS_BADUSAGE;

    rc = zs_db_begin_txn(db, 0, &txn);
    if (rc != ZS_OK) return rc;
    txn->implicit = true;   /* D-14j: its cursors follow this handle */

    rc = zs_txn_store(txn, key, keylen, val, vallen, flags);
    if (rc != ZS_OK) {
        zs_txn_abort(&txn);
        return rc;
    }

    return zs_txn_commit(&txn);
}

/* foreach */

int zs_txn_foreach(struct zs_txn *txn, const char *start, size_t startlen,
                   zs_cb *p, zs_cb *cb, void *rock, int flags)
{
    struct zs_cursor *c = NULL;
    struct zsi_rec r;
    int rc;

    if (!txn || !cb) return ZS_BADUSAGE;

    /* A-13: no reverse foreach.  Nothing needs it -- a consumer walking
     * backwards drives a cursor -- and a rejected flag is cheaper than an
     * untested promise. */
    if (flags & ZS_REVERSE) return ZS_BADUSAGE;

    /* A-4b: no ephemeral traversal, for the same reason.  A callback holding
     * the record it was handed while the walk moves on is the ordinary shape
     * here, and the flag would quietly break it. */
    if (flags & ZS_EPHEMERAL) return ZS_BADUSAGE;

    rc = zsi_cursor_open(txn->db, txn->readonly ? NULL : txn, txn->snap,
                         startlen ? start : NULL, startlen,
                         (uint32_t)flags, &c);
    if (rc != ZS_OK) return rc;
    c->handle_live = txn->implicit;

    while ((rc = zsi_cursor_next(c, &r)) == ZS_OK) {
        /* p is a predicate: when supplied, cb runs only where it returns
         * non-zero.  Matches the cyrusdb convention the other backends use. */
        if (p && !p(rock, r.key, r.keylen, r.val, r.vallen)) continue;
        int cr = cb(rock, r.key, r.keylen, r.val, r.vallen);
        if (cr) { rc = cr; goto out;  }
    }

    if (rc == ZS_DONE) rc = ZS_OK;

out:
    zsi_cursor_free(c);
    return rc;
}

int zs_db_foreach(struct zs_db *db, const char *start, size_t startlen,
                  zs_cb *p, zs_cb *cb, void *rock, int flags)
{
    struct zs_txn *txn = NULL;
    int rc;

    if (!db || !cb) return ZS_BADUSAGE;

    rc = zs_db_begin_txn(db, 1, &txn);
    if (rc != ZS_OK) return rc;
    txn->implicit = true;   /* D-14j: its cursors follow this handle */

    rc = zs_txn_foreach(txn, start, startlen, p, cb, rock, flags);
    zs_txn_abort(&txn);
    return rc;
}

/* cursors */

int zs_txn_begin_cursor(struct zs_txn *txn, const char *key, size_t keylen,
                        struct zs_cursor **curp, int flags)
{
    if (!txn || !curp) return ZS_BADUSAGE;
    *curp = NULL;
    /* A-4b: a cursor yields across steps, so the caller holds what it was
     * handed while the walk moves on.  Rejected rather than ignored -- the
     * flag is only meaningful where the result dies at the next call, and
     * that is not what a cursor is. */
    if (flags & ZS_EPHEMERAL) return ZS_BADUSAGE;
    {
        int r = zsi_cursor_open(txn->db, txn->readonly ? NULL : txn, txn->snap,
                                keylen ? key : NULL, keylen,
                                (uint32_t)flags, curp);
        if (r == ZS_OK) (*curp)->handle_live = txn->implicit;
        return r;
    }
}

int zs_db_begin_cursor(struct zs_db *db, const char *key, size_t keylen,
                       struct zs_cursor **curp, int flags)
{
    struct zs_txn *txn = NULL;
    int rc;

    if (!db || !curp) return ZS_BADUSAGE;
    *curp = NULL;

    /* A-4b, before the begin below: without ZS_SHARED that begin takes the
     * WRITE LOCK, and taking it for a call already known to fail would block
     * every other handle for nothing. */
    if (flags & ZS_EPHEMERAL) return ZS_BADUSAGE;

    /* An implicit transaction, owned by the cursor: a cursor from a database
     * needs somewhere for its snapshot to live, and zs_cursor_commit/abort is
     * what ends it. */
    rc = zs_db_begin_txn(db, (flags & ZS_SHARED) ? 1 : 0, &txn);
    if (rc != ZS_OK) return rc;

    rc = zsi_cursor_open(db, txn->readonly ? NULL : txn, txn->snap,
                         keylen ? key : NULL, keylen,
                         (uint32_t)flags, curp);
    if (rc != ZS_OK) { zs_txn_abort(&txn); return rc; }

    (*curp)->txn = txn;
    (*curp)->owns_txn = true;
    (*curp)->handle_live = true;    /* D-14j: opened from a database handle */
    return ZS_OK;
}

int zs_cursor_next(struct zs_cursor *cur,
                   const char **keyp, size_t *keylenp,
                   const char **valp, size_t *vallenp)
{
    struct zsi_rec r;
    int rc;

    if (!cur) return ZS_BADUSAGE;

    rc = zsi_cursor_next(cur, &r);
    if (rc != ZS_OK) return rc;

    if (keyp) *keyp = r.key;
    if (keylenp) *keylenp = r.keylen;
    if (valp) *valp = r.val;
    if (vallenp) *vallenp = r.vallen;
    return ZS_OK;
}

int zs_cursor_replace(struct zs_cursor *cur, const char *val, size_t vallen,
                      int flags)
{
    if (!cur) return ZS_BADUSAGE;
    if (!cur->have_emitted) return ZS_BADUSAGE;     /* nothing to replace */
    if (!cur->txn || cur->txn->readonly) return ZS_READONLY;

    return zs_txn_store(cur->txn, cur->emitted.key, cur->emitted.keylen,
                        val, vallen, flags);
}

int zs_cursor_commit(struct zs_cursor **curp)
{
    struct zs_cursor *c;
    int rc = ZS_OK;

    if (!curp || !*curp) return ZS_BADUSAGE;
    c = *curp;
    *curp = NULL;

    if (c->owns_txn && c->txn) {
        struct zs_txn *txn = c->txn;
        c->txn = NULL;
        rc = zsi_txn_commit(txn);
    }

    zsi_cursor_free(c);
    return rc;
}

int zs_cursor_abort(struct zs_cursor **curp)
{
    struct zs_cursor *c;
    int rc = ZS_OK;

    if (!curp || !*curp) return ZS_BADUSAGE;
    c = *curp;
    *curp = NULL;

    if (c->owns_txn && c->txn) {
        struct zs_txn *txn = c->txn;
        c->txn = NULL;
        rc = zsi_txn_abort(txn);
    }

    zsi_cursor_free(c);
    return rc;
}

/* Release a cursor inside a caller-owned transaction, without touching it. */
void zs_cursor_fini(struct zs_cursor **curp)
{
    if (!curp || !*curp) return;

    if ((*curp)->owns_txn && (*curp)->txn) {
        struct zs_txn *txn = (*curp)->txn;
        (*curp)->txn = NULL;
        zsi_txn_abort(txn);
    }

    zsi_cursor_free(*curp);
    *curp = NULL;
}

/* utility */

int zs_db_sync(struct zs_db *db)
{
    struct zsi_file *act;

    if (!db) return ZS_BADUSAGE;

    act = zsi_snapshot_active(db->snap);
    if (!act) return ZS_OK;

    int fd = open(act->fname, O_WRONLY);
    if (fd < 0) return ZS_IOERROR;
    int r = ZS_FDATASYNC(fd) < 0 ? ZS_IOERROR : ZS_OK;
    close(fd);
    return r;
}

const char *zs_strerror(int r)
{
    switch (r) {
    case ZS_OK:           return "success";
    case ZS_DONE:         return "iteration complete";
    case ZS_EXISTS:       return "record already exists";
    case ZS_IOERROR:      return "I/O error";
    case ZS_INTERNAL:     return "internal error";
    case ZS_LOCKED:       return "database is locked";
    case ZS_NOTFOUND:     return "record not found";
    case ZS_READONLY:     return "database is read-only";
    case ZS_BADFORMAT:    return "bad file format";
    case ZS_BADUSAGE:     return "bad usage";
    case ZS_BADCHECKSUM:  return "checksum mismatch";
    case ZS_FULL:         return "generation space exhausted";
    case ZS_AGAIN:        return "file set changed, retry";
    }

    return "unknown error";
}

/********** SALVAGE *************/

/* Spec section 9.  Rebuild what is readable out of a DAMAGED directory into a
 * new database.
 *
 * This section deliberately does NOT share the read path, and must not.  Its
 * whole purpose is to read structures sections 5 and 7 refuse: a file set with a
 * gap, a header that does not validate, a pointer section that will not load,
 * spans sitting after a bad one.  Routing it through zsi_snapshot_take would
 * make it refuse exactly the databases it exists for.
 *
 * The source is never written to, never locked, and never unlinked from (S-1).
 * That is what lets this guess and improvise without risking the only copy of
 * the data it is trying to save, and it is why R-4 needs no repair exception. */

/* How far a resynchronisation scan will look before giving up on a file.  Not a
 * correctness bound -- the scan stops at end of file regardless -- but a guard
 * against spending unbounded time on a file that is mostly noise. */
#define ZSI_SALVAGE_SCAN_MAX (64u * 1024u * 1024u)

struct zsi_salvage_key { size_t off, len; };

struct zsi_salvage_ctx {
    struct zs_salvage_data *setup;
    struct zs_db           *out;        /* the destination, open for writing */
    const char             *fname;      /* the file being processed, for events */
    uint32_t                gen;

    /* S-10: the earliest point at which anything was lost, as (generation,
     * offset).  A key whose winning record is older than this MAY have been
     * superseded by something in the lost bytes. */
    bool                    any_loss;
    uint32_t                loss_gen;
    size_t                  loss_off;

    unsigned long long      nkeys, nstale, nunverified, nlost;
    int                     stopped;    /* the callback asked us to stop */

    /* Keys applied at or after the first loss (S-10).
     *
     * Files are scanned oldest first and positions ascend within a file, so the
     * first loss is DISCOVERED before any record beyond it is applied.  A key is
     * therefore stale exactly when its last application preceded that loss --
     * which makes "safe" a set that can be built as we go, with no second pass
     * and no need to know the loss point in advance.
     *
     * Keys are packed into one blob so a growable array of offsets can index
     * them without a separate allocation per key. */
    char                   *safe;       size_t safelen, safealloc;
    struct zsi_salvage_key *safekeys;   size_t nsafe, safekeysalloc;
};

static void zsi_salvage_emit(struct zsi_salvage_ctx *ctx, int kind,
                             size_t off, size_t len,
                             const char *key, size_t keylen)
{
    struct zs_salvage_event ev;

    if (!ctx->setup->report || ctx->stopped) return;

    memset(&ev, 0, sizeof(ev));
    ev.kind = kind;
    ev.file = ctx->fname;
    ev.generation = ctx->gen;
    ev.offset = off;
    ev.length = len;
    ev.key = key;
    ev.keylen = keylen;

    if (ctx->setup->report(ctx->setup->rock, &ev) != 0) ctx->stopped = 1;
}

/* Note that data was lost at this point (S-10), keeping the earliest. */
static void zsi_salvage_loss(struct zsi_salvage_ctx *ctx, size_t off, size_t len)
{
    ctx->nlost++;

    if (!ctx->any_loss || ctx->gen < ctx->loss_gen
        || (ctx->gen == ctx->loss_gen && off < ctx->loss_off)) {
        ctx->any_loss = true;
        ctx->loss_gen = ctx->gen;
        ctx->loss_off = off;
    }

    zsi_salvage_emit(ctx, ZS_SALVAGE_SPAN_LOST, off, len, NULL, 0);
}

/* S-5: determine a file's checksum engine when its header did not validate.
 *
 * Tries each engine and keeps the one under which the FIRST span validates.
 * Engine 0 is tried last and matches only where a stored checksum really is
 * zero, so it is a genuine signal rather than a catch-all that would accept
 * anything -- which is the whole risk of guessing at all.
 *
 * A file with no valid span under any engine yields ZS_NOTFOUND; the caller
 * still reports it, because "nothing recoverable here" is worth saying. */
static int zsi_salvage_engine(struct zsi_file *f, zs_csum *external,
                              zs_csum **out, unsigned *id_out)
{
    static const unsigned order[] = { ZSI_CSUM_XXHASH, ZSI_CSUM_EXTERNAL,
                                      ZSI_CSUM_NONE };

    for (size_t i = 0; i < sizeof(order) / sizeof(order[0]); i++) {
        zs_csum *cs = zsi_csum_for_id(order[i], external);
        size_t p = ZSI_HEADER_LEN;
        struct zsi_term term;

        if (!cs) continue;                      /* engine 2 with no function */

        /* Walk records to the first terminator and see whether it validates. */
        for (;;) {
            const char *b = zsi_file_at(f, p, 1);
            struct zsi_rec r;

            if (!b) break;
            if (!zsi_type_valid((uint8_t)b[0])) break;

            if ((uint8_t)b[0] & ZSI_SPANTERM) {
                const char *spandata, *termbytes;
                size_t datalen = p - ZSI_HEADER_LEN;

                if (zsi_term_decode(b, f->size - p, &term) != ZS_OK) break;
                if (!zsi_file_at(f, p, term.len)) break;
                if (term.spanlen != (uint64_t)datalen) break;

                spandata = zsi_file_at(f, ZSI_HEADER_LEN, datalen);
                termbytes = zsi_file_at(f, p, term.len);
                if (!termbytes || (datalen && !spandata)) break;

                if (zsi_csum2(cs, order[i], spandata ? spandata : "", datalen,
                              termbytes, term.len - 8) == term.csum) {
                    *out = cs;
                    *id_out = order[i];
                    return ZS_OK;
                }
                break;
            }

            if (!((uint8_t)b[0] & ZSI_HASKEY)) break;
            if (zsi_rec_decode(b, f->size - p, &r) != ZS_OK) break;
            if (r.len == 0) break;
            if (!zsi_add_sz(p, r.len, &p)) break;
            if (p > f->size) break;
        }
    }

    return ZS_NOTFOUND;
}

/* S-7: find the next VERIFIED span at or after `from`.
 *
 * This is the only place salvage guesses, and the guess is always confirmed
 * before it is believed.  A terminator carries its span's length (F-19), so a
 * candidate terminator implies exactly where its span began -- and that span can
 * then be checksummed.  A match is proof, not a heuristic.
 *
 * Steps 8 bytes at a time because every record and terminator begins on an
 * 8-multiple (F-2), so nothing valid is skipped.
 *
 * Returns ZS_OK with *span_start, *term_off and *term filled, or ZS_NOTFOUND. */
static int zsi_salvage_resync(struct zsi_file *f, zs_csum *cs, unsigned csum_id,
                              size_t from, size_t floor,
                              size_t *span_start, size_t *term_off,
                              struct zsi_term *term)
{
    size_t scanned = 0;

    for (size_t p = (from + 7u) & ~(size_t)7; p < f->size; p += 8) {
        const char *b, *spandata, *termbytes;
        struct zsi_term t;
        size_t start, after;

        if (++scanned > ZSI_SALVAGE_SCAN_MAX / 8) break;

        b = zsi_file_at(f, p, 1);
        if (!b) break;

        if (zsi_term_decode(b, f->size - p, &t) != ZS_OK) continue;
        if (!zsi_file_at(f, p, t.len)) continue;

        /* The span it claims must lie inside the region we are still willing to
         * attribute to this file: at or after the last known good boundary, and
         * ending exactly at this terminator. */
        if (t.spanlen > (uint64_t)(p - floor)) continue;
        start = p - (size_t)t.spanlen;
        if (start < floor) continue;
        if (!zsi_add_sz(p, t.len, &after)) continue;
        if (after > f->size) continue;

        spandata = zsi_file_at(f, start, (size_t)t.spanlen);
        termbytes = zsi_file_at(f, p, t.len);
        if (!termbytes) continue;
        if (t.spanlen && !spandata) continue;

        /* The proof. */
        if (zsi_csum2(cs, csum_id, spandata ? spandata : "",
                      (size_t)t.spanlen, termbytes, t.len - 8) != t.csum)
            continue;

        *span_start = start;
        *term_off = p;
        *term = t;
        return ZS_OK;
    }

    return ZS_NOTFOUND;
}

/* Apply one recovered record to the destination.
 *
 * Records arrive oldest first (S-3), so the newest surviving version of a key
 * wins simply by being applied last -- there is no recency pass, and none is
 * possible anyway once some of the ordering evidence has been lost.
 *
 * A deletion is applied as a deletion, so a recovered tombstone still removes a
 * key and a key whose newest surviving version is a deletion ends absent.  That
 * is correct rather than a loss: it is what the database said. */
static int zsi_salvage_apply(struct zsi_salvage_ctx *ctx,
                             const struct zsi_rec *rec, bool verified)
{
    int r;

    if (rec->type & ZSI_ISDELETE)
        r = zs_db_store(ctx->out, rec->key, rec->keylen, NULL, 0, 0);
    else
        r = zs_db_store(ctx->out, rec->key, rec->keylen, rec->val, rec->vallen, 0);

    if (r != ZS_OK) return r;

    ctx->nkeys++;

    /* S-10: once anything has been lost, every key applied from here on has a
     * version no older than the loss, so it cannot be stale. */
    if (ctx->any_loss) {
        if (ctx->safelen + rec->keylen > ctx->safealloc) {
            size_t want = ctx->safealloc ? ctx->safealloc * 2 : 4096;
            char *p;
            while (want < ctx->safelen + rec->keylen) want *= 2;
            p = realloc(ctx->safe, want);
            if (!p) return ZS_INTERNAL;
            ctx->safe = p;
            ctx->safealloc = want;
        }
        if (ctx->nsafe == ctx->safekeysalloc) {
            size_t want = ctx->safekeysalloc ? ctx->safekeysalloc * 2 : 256;
            struct zsi_salvage_key *p =
                realloc(ctx->safekeys, want * sizeof(*p));
            if (!p) return ZS_INTERNAL;
            ctx->safekeys = p;
            ctx->safekeysalloc = want;
        }
        memcpy(ctx->safe + ctx->safelen, rec->key, rec->keylen);
        ctx->safekeys[ctx->nsafe].off = ctx->safelen;
        ctx->safekeys[ctx->nsafe].len = rec->keylen;
        ctx->nsafe++;
        ctx->safelen += rec->keylen;
    }

    if (!verified) {
        ctx->nunverified++;
        zsi_salvage_emit(ctx, ZS_SALVAGE_KEY_UNVERIFIED, 0, 0,
                         rec->key, rec->keylen);
    }

    return ZS_OK;
}

/* Walk a span's records, applying each.
 *
 * A record's own checksum (F-32) is deliberately NOT consulted here.  It
 * proves the record's BYTES; "verified" in this walk means the span's
 * terminator proved the records were COMMITTED (S-8), and a torn tail with
 * pristine record checksums was still never acknowledged to anyone.  The
 * two proofs answer different questions, and only in-order salvage -- where
 * publication by rename already implies commitment (D-21) -- may substitute
 * one for the other. */
static int zsi_salvage_span(struct zsi_salvage_ctx *ctx, struct zsi_file *f,
                            size_t from, size_t to, bool verified)
{
    size_t q = from;

    while (q < to && !ctx->stopped) {
        const char *b = zsi_file_at(f, q, 1);
        struct zsi_rec r;
        int rc;

        if (!b) break;
        if (zsi_rec_decode(b, f->size - q, &r) != ZS_OK) break;
        if (r.len == 0) break;

        rc = zsi_salvage_apply(ctx, &r, verified);
        if (rc != ZS_OK) return rc;

        q += r.len;
    }

    return ZS_OK;
}

/* One unordered file: walk its spans, resynchronising past damage (S-7). */
static int zsi_salvage_unordered(struct zsi_salvage_ctx *ctx,
                                 struct zsi_file *f,
                                 zs_csum *cs, unsigned csum_id)
{
    bool want_unverified =
        (ctx->setup->flags & ZS_SALVAGE_UNVERIFIED) != 0;
    size_t pos = ZSI_HEADER_LEN;
    int r;

    while (pos < f->size && !ctx->stopped) {
        size_t span_start, term_off, after;
        struct zsi_term term;

        if (zsi_salvage_resync(f, cs, csum_id, pos, pos,
                               &span_start, &term_off, &term) != ZS_OK) {
            /* Nothing verifiable remains.  Whatever is left is a torn tail: it
             * was very likely never acknowledged to anyone, so it is recovered
             * only on request (S-8) and always reported. */
            if (pos < f->size) {
                zsi_salvage_loss(ctx, pos, f->size - pos);
                if (want_unverified) {
                    r = zsi_salvage_span(ctx, f, pos, f->size, false);
                    if (r != ZS_OK) return r;
                }
            }
            return ZS_OK;
        }

        /* Bytes between where we were and where the next verified span begins
         * are a span whose terminator did not survive.  Its own records cannot
         * be proved -- the terminator is what would prove them (S-8). */
        if (span_start > pos) {
            zsi_salvage_loss(ctx, pos, span_start - pos);
            if (want_unverified) {
                r = zsi_salvage_span(ctx, f, pos, span_start, false);
                if (r != ZS_OK) return r;
            }
            zsi_salvage_emit(ctx, ZS_SALVAGE_RESYNC, span_start,
                             term_off - span_start, NULL, 0);
        }

        /* S-9: a rolled-back span is deliberately aborted.  Never recovered,
         * with or without the flag -- no conforming reader has ever shown its
         * records, and producing them would resurrect a transaction that did
         * not happen. */
        if (zsi_term_is_rollback(&term)) {
            zsi_salvage_emit(ctx, ZS_SALVAGE_SPAN_ROLLBACK, span_start,
                             term_off - span_start, NULL, 0);
        } else {
            r = zsi_salvage_span(ctx, f, span_start, term_off, true);
            if (r != ZS_OK) return r;
        }

        if (!zsi_add_sz(term_off, term.len, &after)) break;
        pos = after;
    }

    return ZS_OK;
}

/* One in-order file: walk the records region directly.
 *
 * S-6: the pointer region is IGNORED entirely, whether or not it loads.  One
 * that fails makes the file unreadable under section 7 while its entries may be
 * perfect, and re-deriving order costs nothing here because the destination
 * sorts anyway.  An in-order file has no spans (F-23), so this is a flat walk of
 * the keys region -- each entry's length is a function of its own type and
 * keylen, so the region is self-describing without the pointers.
 *
 * The regions are located from the HEADER, which the header checksum covers, so
 * ignoring the pointer region costs nothing structural: keys_end is the trailer
 * minus values_len, and keys_off is that minus keys_len (F-10a). */
static int zsi_salvage_inorder(struct zsi_salvage_ctx *ctx, struct zsi_file *f,
                               zs_csum *cs, unsigned csum_id)
{
    size_t pos, keys_off, keys_end;
    bool region_ok;

    (void)cs;

    /* Without a valid header there is no way to find the regions at all -- their
     * lengths live in it (F-10a) -- so there is nothing to walk.  Reported by
     * the caller, which already handles an unreadable header. */
    if (!f->hdr_valid) return ZS_OK;
    if (f->size < ZSI_TRAILER_LEN) return ZS_OK;
    if (f->hdr.values_len > f->size - ZSI_TRAILER_LEN) return ZS_OK;

    keys_end = f->size - ZSI_TRAILER_LEN - (size_t)f->hdr.values_len;
    if (f->hdr.keys_len > keys_end) return ZS_OK;
    keys_off = keys_end - (size_t)f->hdr.keys_len;

    zsi_salvage_emit(ctx, ZS_SALVAGE_PTRS_IGNORED, 0, 0, NULL, 0);

    /* S-13.  One verdict for the whole file: engine 0 can prove nothing, and
     * otherwise the data region either checksums or it does not.  A failure is
     * reported once at FILE granularity -- never per key, which for a file
     * holding millions of them would be a flood rather than a report (A-19). */
    region_ok = false;
    if (csum_id != 0) {
        size_t dlen = f->size - ZSI_TRAILER_LEN - keys_off;
        const char *dp = zsi_file_at(f, keys_off, dlen);
        const char *tr = zsi_file_at(f, f->size - ZSI_TRAILER_LEN,
                                     ZSI_TRAILER_LEN);
        if (dp && tr) region_ok = (f->csum(dp, dlen) == zsi_get64(tr));
    }
    if (!region_ok) {
        zsi_salvage_emit(ctx, ZS_SALVAGE_REGION_UNVERIFIED, 0, 0, NULL, 0);
        if (!(ctx->setup->flags & ZS_SALVAGE_UNVERIFIED)) return ZS_OK;
    }

    pos = keys_off;
    while (pos < keys_end && !ctx->stopped) {
        struct zsi_kent e, nx;
        struct zsi_rec r;
        const char *b = zsi_file_at(f, pos, 1);
        int rc;

        if (!b) break;
        if (zsi_kent_decode(b, keys_end - pos, f->val_wide, &e) != ZS_OK) {
            zsi_salvage_loss(ctx, pos, keys_end - pos);
            break;
        }
        if (e.len == 0) break;

        /* The sentinel ends the region and is not a record (F-36a). */
        if (e.keylen == 0) break;

        memset(&r, 0, sizeof(r));
        r.type   = e.type;
        r.key    = e.key;
        r.keylen = e.keylen;
        r.len    = e.len;
        r.base   = b;

        if (e.type & ZSI_ISDELETE) {
            r.val = NULL;
            r.vallen = 0;
        } else {
            /* S-6a: the length comes from the NEXT entry (F-36), so an entry
             * whose successor did not decode has a value of unknown extent.
             * That value is LOST rather than guessed -- taking the region end
             * instead would hand back every later value as one enormous blob,
             * and the successor may be merely damaged rather than absent. */
            const char *nb = zsi_file_at(f, pos + e.len, 1);
            if (!nb
                || zsi_kent_decode(nb, keys_end - (pos + e.len), f->val_wide,
                                   &nx) != ZS_OK
                || nx.valptr < e.valptr + 1) {
                zsi_salvage_loss(ctx, pos, keys_end - pos);
                break;
            }
            r.vallen = (size_t)(nx.valptr - e.valptr - 1);
            r.val    = zsi_file_at(f, (size_t)e.valptr, r.vallen + 1);
            if (!r.val) {
                zsi_salvage_loss(ctx, pos, keys_end - pos);
                break;
            }
        }

        /* verified=true even when the region failed, because the per-key
         * KEY_UNVERIFIED report is FORBIDDEN here (A-19): the file-level event
         * above already carries the verdict, and one event per key would be a
         * flood rather than a report for a file holding millions.  What the
         * flag means at this call is "does this key need its own caveat", and
         * for an in-order file it never does -- publication by rename settles
         * commitment (S-8a) and integrity is the whole file's question. */
        rc = zsi_salvage_apply(ctx, &r, true);
        if (rc != ZS_OK) return rc;

        pos += e.len;
    }

    return ZS_OK;
}

/* Order for S-3: oldest first, by start ascending; for equal start the NARROWER
 * range first, since a wider one is a repack output derived from it and is
 * therefore newer. */
static int zsi_salvage_order(const void *va, const void *vb)
{
    const struct zsi_entry *a = va, *b = vb;

    /* D-1b: the active file's generation is not in its name, and salvage reads
     * the directory RAW (S-1) so it is not filled in either -- start == 0.
     * That must sort LAST, not first: it is the newest file, and S-10's
     * "possibly stale" report depends on scanning oldest first so that the
     * first loss is discovered before anything beyond it is applied.  Sorting
     * it first would apply the newest records before the older ones that
     * supersede nothing, and invert every version it reports. */
    if ((a->start == 0) != (b->start == 0)) return a->start == 0 ? 1 : -1;

    if (a->start != b->start) return a->start < b->start ? -1 : 1;

    {
        uint32_t ae = a->end ? a->end : a->start;
        uint32_t be = b->end ? b->end : b->start;
        if (ae != be) return ae < be ? -1 : 1;
    }

    return 0;
}

/* S-10: report every surviving key whose recovered record predates the first
 * loss, and no others.
 *
 * Deliberately conservative rather than exact: it reports what COULD have been
 * superseded by the lost bytes, because determining what actually was would need
 * the key set of those bytes, which is precisely what has been lost.  Reporting
 * only keys older than the loss is what keeps it small enough to act on -- the
 * alternative, "everything might be stale", is true and useless. */
static int zsi_salvage_report_stale(struct zsi_salvage_ctx *ctx)
{
    struct zs_cursor *c = NULL;
    zs_compar *cmp = ctx->out->compar;
    const char *k, *v;
    size_t kl, vl;
    int r;

    if (!ctx->any_loss || !ctx->setup->report) return ZS_OK;

    /* Sort the safe keys so each output key costs one binary search rather than
     * a scan; duplicates are harmless to a lower-bound search. */
    if (ctx->nsafe > 1) {
        /* Insertion into a sorted array via the merge sort already in this file
         * would need a context, so a simple qsort over a temporary of resolved
         * pointers is clearer here -- and this runs once, over recovered keys
         * only, on a path that has already read the whole database. */
        for (size_t i = 1; i < ctx->nsafe; i++) {
            struct zsi_salvage_key key = ctx->safekeys[i];
            size_t j = i;
            while (j > 0
                   && cmp(ctx->safe + ctx->safekeys[j - 1].off,
                          ctx->safekeys[j - 1].len,
                          ctx->safe + key.off, key.len) > 0) {
                ctx->safekeys[j] = ctx->safekeys[j - 1];
                j--;
            }
            ctx->safekeys[j] = key;
        }
    }

    r = zs_db_begin_cursor(ctx->out, NULL, 0, &c, 0);
    if (r != ZS_OK) return r;

    while ((r = zs_cursor_next(c, &k, &kl, &v, &vl)) == ZS_OK && !ctx->stopped) {
        size_t lo = 0, hi = ctx->nsafe;
        bool safe = false;

        while (lo < hi) {
            size_t mid = lo + (hi - lo) / 2;
            int d = cmp(ctx->safe + ctx->safekeys[mid].off,
                        ctx->safekeys[mid].len, k, kl);
            if (d == 0) { safe = true; break; }
            if (d < 0) lo = mid + 1; else hi = mid;
        }

        if (!safe) {
            ctx->nstale++;
            ctx->fname = NULL;
            ctx->gen = 0;
            zsi_salvage_emit(ctx, ZS_SALVAGE_KEY_MAYBE_STALE, 0, 0, k, kl);
        }
    }

    zs_cursor_fini(&c);
    return (r == ZS_DONE || r == ZS_OK) ? ZS_OK : r;
}

int zs_db_salvage(const char *from, const char *to,
                  struct zs_salvage_data *setup)
{
    struct zs_salvage_data defaults = ZS_SALVAGE_DATA_INITIALIZER;
    struct zs_open_data outsetup = ZS_OPEN_DATA_INITIALIZER;
    struct zsi_salvage_ctx ctx;
    struct zsi_fileset fs;
    struct zs_db *out = NULL;
    uint32_t expect_gen = 0;
    int r;

    if (!from || !to) return ZS_BADUSAGE;
    if (!setup) setup = &defaults;

    memset(&ctx, 0, sizeof(ctx));
    ctx.setup = setup;

    /* S-2: scan for names only.  zsi_fileset_scan parses D-1 names and does NOT
     * resolve overlaps or check tiling -- that is zsi_fileset_resolve, which is
     * deliberately not called here.  A gap is something to report and step over,
     * not something to fail on. */
    r = zsi_fileset_scan_raw(from, NULL, &fs);   /* keeps a bad header (S-1) */
    if (r == ZS_NOTFOUND) return ZS_NOTFOUND;
    if (r != ZS_OK) return r;

    if (fs.nall == 0) { zsi_fileset_fini(&fs); return ZS_NOTFOUND; }

    qsort(fs.all, fs.nall, sizeof(*fs.all), zsi_salvage_order);

    outsetup.flags = ZS_CREATE;
    outsetup.compar = setup->compar;
    outsetup.compar_name = setup->compar_name;
    outsetup.csum = setup->csum;
    outsetup.error = setup->error;
    r = zs_db_open(to, &outsetup, &out);
    if (r != ZS_OK) { zsi_fileset_fini(&fs); return r; }
    ctx.out = out;

    for (size_t i = 0; i < fs.nall && !ctx.stopped; i++) {
        struct zsi_file *f = NULL;
        zs_csum *cs;
        unsigned csum_id;

        ctx.fname = fs.all[i].name;
        ctx.gen = fs.all[i].start;

        /* Opened BEFORE the gap check, because D-1b puts the active file's
         * generation in its header and zsi_fileset_scan_raw deliberately does
         * not go and read it -- salvage keeps a file whose header may be the
         * damaged part.  So the generation is whatever the header turns out to
         * say, and is not known until here. */
        if (zsi_file_open(from, fs.all[i].name, fs.all[i].start,
                          setup->csum, &f) != ZS_OK) {
            ctx.gen = fs.all[i].start;
            zsi_salvage_emit(&ctx, ZS_SALVAGE_FILE_UNREADABLE, 0, 0, NULL, 0);
            continue;
        }

        {
            uint32_t gen = fs.all[i].start;
            uint32_t end;

            if (!gen && f->hdr_valid) gen = f->hdr.start;
            ctx.gen = gen;

            /* S-2 again: a generation absent from the set is reported, and the
             * walk simply carries on.  Nothing is reconstructed (S-12). */
            if (expect_gen && gen > expect_gen)
                zsi_salvage_emit(&ctx, ZS_SALVAGE_GAP, 0,
                                 gen - expect_gen, NULL, 0);

            end = fs.all[i].end ? fs.all[i].end : gen;
            if (end + 1 > expect_gen) expect_gen = end + 1;
        }


        if (f->hdr_valid) {
            cs = f->csum;
            csum_id = f->csum_id;

            /* S-4: the source's comparator does not affect the output, which is
             * ordered by the caller's -- but a mismatch means the source was
             * built under an order we are not reproducing, and that is worth
             * saying rather than discovering later. */
            if (out->compar_name[0]
                && memcmp(f->hdr.compar_name, out->compar_name,
                          ZSI_COMPAR_NAME_LEN) != 0)
                setup->error ? setup->error(
                    "source comparator differs from the one salvage was given",
                    "file=<%s>", f->fname) : (void)0;
        } else {
            /* S-5: the header did not validate.  The generation still comes
             * from the filename; only the engine is genuinely unknown. */
            zsi_salvage_emit(&ctx, ZS_SALVAGE_HEADER_INVALID, 0, 0, NULL, 0);

            if (zsi_salvage_engine(f, setup->csum, &cs, &csum_id) != ZS_OK) {
                zsi_salvage_emit(&ctx, ZS_SALVAGE_FILE_UNREADABLE, 0, 0,
                                 NULL, 0);
                zsi_file_release(&f);
                continue;
            }
            zsi_salvage_emit(&ctx, ZS_SALVAGE_ENGINE_GUESSED, csum_id, 0,
                             NULL, 0);
        }

        /* The KIND comes from the filename, not the header: a file whose header
         * is unreadable still has its range in its name (D-1), and that is what
         * says whether to expect spans or a records region. */
        if (fs.all[i].end == 0)
            r = zsi_salvage_unordered(&ctx, f, cs, csum_id);
        else
            r = zsi_salvage_inorder(&ctx, f, cs, csum_id);

        zsi_file_release(&f);
        if (r != ZS_OK) goto out;
    }

    if (r == ZS_OK) r = zsi_salvage_report_stale(&ctx);
    if (r == ZS_OK && ctx.stopped) r = ZS_DONE;

out:
    free(ctx.safe);
    free(ctx.safekeys);
    zsi_fileset_fini(&fs);
    zs_db_close(&out);
    return r;
}
