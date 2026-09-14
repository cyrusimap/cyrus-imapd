/* bench-workload.h - a measured production workload, shared by twom-bench
 * (direct twom API) and dbbench (cyrusdb API, any backend).
 *
 * The shape below was derived from a twom-capture census of a live IMAP
 * server rather than invented, then rounded to plain ratios - only the
 * proportions matter, since every table is sampled by relative weight.
 * Both frontends include this so they cannot drift apart: a twom-only number
 * and a cross-engine number describe the same workload.
 *
 * Retune these against your own census if your mix differs; that is the point
 * of shipping the tracer alongside the benchmark.
 */
#ifndef BENCH_WORKLOAD_H
#define BENCH_WORKLOAD_H

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

/* fetch key lengths: {low, high, weight-per-mille} */
static const int KEYLEN[][3] = {
    {   2,    4,     5 }, {   8,   16,    55 }, {  16,   32,   305 },
    {  32,   64,   480 }, {  64,  128,   150 }, { 128,  256,     5 },
};
/* store value lengths: {low, high, weight-per-mille} */
static const int VALLEN[][3] = {
    {   1,    2,    30 }, {   4,    8,    10 }, {   8,   16,    60 },
    {  16,   32,   225 }, {  32,   64,   500 }, {  64,  128,    50 },
    { 128,  256,    75 }, { 256,  512,    45 }, { 512, 1024,     3 },
    {1024, 4096,     1 }, {4096,16384,     1 },
};
#define NKEYLEN ((int)(sizeof(KEYLEN)/sizeof(KEYLEN[0])))
#define NVALLEN ((int)(sizeof(VALLEN)/sizeof(VALLEN[0])))

/* `scan` is cursor_next/foreach straight from the census. cursor_next fires
 * once more than there are records - the last call returns DONE - so records
 * per scan is scan-1. conversations.db at 1.6 means most of its scans return
 * nothing at all, which integer fanout cannot model; it floors at 1. */
struct profile { const char *name; int fetch, foreach, store; double scan; };
static const struct profile PROFILES[] = {
    /* fetch/foreach/store as relative weights per 10000 operations.
     * Reads dominate everywhere; writes are well under 1% on most databases. */
    { "aggregate",     8500, 1400, 100,  3.7 },
    { "mailboxes",     9250,  750,   1, 11.0 },
    { "conversations", 6550, 3250, 200,  1.6 },
    { "annotations",   9935,   65,   1,  1.7 },
    { NULL, 0, 0, 0, 0 }
};

static uint64_t rnd_state;
static inline uint64_t rnd(void)
{
    rnd_state ^= rnd_state << 13; rnd_state ^= rnd_state >> 7;
    rnd_state ^= rnd_state << 17; return rnd_state;
}

static inline double bench_now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

/* seed==0 draws from the global rng; a non-zero seed makes the draw a pure
 * function of the record id, which is what lets a fetch rebuild the exact key
 * that populate wrote. Getting this wrong just silently tanks the hit rate. */
static int pick_seeded(const int t[][3], int n, uint64_t seed)
{
    int total = 0, i;
    for (i = 0; i < n; i++) total += t[i][2];
    uint64_t h = seed;
    if (h) { h ^= h >> 33; h *= 0xff51afd7ed558ccdULL; h ^= h >> 33; }
    else   { h = rnd(); }
    int r = h % total;
    for (i = 0; i < n; i++) { r -= t[i][2]; if (r < 0) break; }
    if (i == n) i = n - 1;
    int span = t[i][1] - t[i][0];
    return t[i][0] + (int)((h >> 32) % (span ? span : 1));
}
#define pick(t, n) pick_seeded((t), (n), 0)

/* Cyrus keys are structured, not random: mailbox names, uuids, uid suffixes.
 * Shared prefixes are what a skiplist actually walks, so the structure - not
 * just the length - is part of the workload.
 *
 * Records are laid out in groups of `fanout`, and PREFIX is a strict prefix of
 * every key in a group, so a prefix scan returns exactly `fanout` records.
 * Padding is appended after the prefix, so a varying key length never breaks
 * prefix matching. */
#define PREFIX_FMT "user.u%08u.INBOX.Folder%04u.item"

static int mkprefix(char *buf, uint64_t group)
{
    return sprintf(buf, PREFIX_FMT,
                   (unsigned)(group / 1000), (unsigned)(group % 1000));
}

static int mkkey(char *buf, uint64_t group, uint64_t item)
{
    int n = mkprefix(buf, group);
    n += sprintf(buf + n, "%04u", (unsigned)item);
    int len = pick_seeded(KEYLEN, NKEYLEN, group * 1000003ULL + item + 1);
    if (len < n) len = n;
    while (n < len) { buf[n] = 'a' + (char)((group + item + n) % 26); n++; }
    buf[n] = 0;
    return n;
}

static const struct profile *find_profile(const char *name)
{
    const struct profile *pf = PROFILES;
    while (pf->name && strcmp(pf->name, name)) pf++;
    return pf->name ? pf : NULL;
}

#endif /* BENCH_WORKLOAD_H */
