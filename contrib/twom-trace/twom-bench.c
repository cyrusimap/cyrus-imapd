/* twom-bench - replay production twom access patterns against a twom database.
 *
 * The op mix and the key/value size distributions live in bench-workload.h and
 * were derived from a twom-capture census of a live server, not invented.
 * Defaults reproduce the aggregate shape; --profile picks a single database's
 * personality, and they differ a lot: mailboxes.db is fetch-dominated with
 * ~11-record scans, while conversations.db does huge numbers of tiny ones.
 *
 * Build: see twom-bench-build. Links twom.c from the cyrus tree directly, as
 * a shared library, so the twom-capture/twom-hitmiss uprobes can attach to it
 * exactly as they do to libcyrus.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <time.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <getopt.h>
#include "twom.h"

#include "bench-workload.h"

struct stats { uint64_t ops, fetch, hit, miss, fe, recs, st, ns, lat[40]; };

static int cb_count(void *rock, const char *k, size_t kl, const char *d, size_t dl)
{ (*(uint64_t *)rock)++; return 0; }

int main(int argc, char **argv)
{
    const char *dbpath = "/var/tmp/twom-bench.db";
    const char *pname  = "aggregate";
    int nrec = 200000, nproc = 8, secs = 30, missmix = 20, populate = 1;
    static struct option lo[] = {
        {"db",required_argument,0,'d'}, {"records",required_argument,0,'n'},
        {"procs",required_argument,0,'p'}, {"secs",required_argument,0,'s'},
        {"profile",required_argument,0,'P'}, {"miss",required_argument,0,'m'},
        {"no-populate",no_argument,0,'X'}, {"help",no_argument,0,'h'}, {0,0,0,0}
    };
    int c;
    while ((c = getopt_long(argc, argv, "d:n:p:s:P:m:Xh", lo, NULL)) != -1) {
        switch (c) {
        case 'd': dbpath = optarg; break;
        case 'n': nrec = atoi(optarg); break;
        case 'p': nproc = atoi(optarg); break;
        case 's': secs = atoi(optarg); break;
        case 'P': pname = optarg; break;
        case 'm': missmix = atoi(optarg); break;
        case 'X': populate = 0; break;
        default:
            fprintf(stderr,
              "usage: %s [--db PATH] [--records N] [--procs N] [--secs N]\n"
              "          [--profile aggregate|mailboxes|conversations|annotations]\n"
              "          [--miss PCT] [--no-populate]\n", argv[0]);
            return 1;
        }
    }
    const struct profile *pf = find_profile(pname);
    if (!pf) { fprintf(stderr, "unknown profile %s\n", pname); return 1; }

    /* -1 because cursor_next counts the terminating TWOM_DONE call too */
    int fanout = (int)(pf->scan - 1 + 0.5); if (fanout < 1) fanout = 1;
    int ngroups = nrec / fanout; if (ngroups < 1) ngroups = 1;
    nrec = ngroups * fanout;

    struct twom_open_data setup = TWOM_OPEN_DATA_INITIALIZER;
    struct twom_db *db = NULL;
    int r;

    if (populate) {
        fprintf(stderr, "populating %s with %d records...\n", dbpath, nrec);
        setup.flags = TWOM_CREATE | TWOM_NOSYNC;
        r = twom_db_open(dbpath, &setup, &db, NULL);
        if (r) { fprintf(stderr, "open: %s\n", twom_strerror(r)); return 1; }
        char key[512], val[16384];
        memset(val, 'v', sizeof(val));
        struct twom_txn *txn = NULL;
        twom_db_begin_txn(db, 0, &txn);
        for (int i = 0; i < nrec; i++) {
            int kl = mkkey(key, i / fanout, i % fanout);
            int vl = pick_seeded(VALLEN, NVALLEN, i + 1);
            twom_txn_store(txn, key, kl, val, vl, 0);
            if ((i % 20000) == 19999) {   /* commit periodically, like cyrus */
                twom_txn_commit(&txn); txn = NULL;
                twom_db_begin_txn(db, 0, &txn);
            }
        }
        if (txn) twom_txn_commit(&txn);
        twom_db_close(&db);
    }

    struct stats *sh = mmap(NULL, sizeof(*sh) * nproc, PROT_READ|PROT_WRITE,
                            MAP_SHARED|MAP_ANONYMOUS, -1, 0);
    memset(sh, 0, sizeof(*sh) * nproc);

    fprintf(stderr, "profile=%s procs=%d secs=%d miss=%d%% fanout=%d groups=%d -> %s\n",
            pf->name, nproc, secs, missmix, fanout, ngroups, dbpath);

    double t0 = bench_now();
    for (int w = 0; w < nproc; w++) {
        if (fork()) continue;
        /* ---- worker ---- */
        struct stats *st = &sh[w];
        rnd_state = (uint64_t)(w + 1) * 88172645463325252ULL;
        struct twom_db *wdb = NULL;
        struct twom_open_data ws = TWOM_OPEN_DATA_INITIALIZER;
        ws.flags = TWOM_NOSYNC;
        if (twom_db_open(dbpath, &ws, &wdb, NULL)) _exit(1);

        int total = pf->fetch + pf->foreach + pf->store;
        char key[512], val[16384];
        memset(val, 'v', sizeof(val));
        double deadline = bench_now() + secs;

        while (bench_now() < deadline) {
            int roll = rnd() % total;
            double s = bench_now();
            /* prod is 99.5% shared transactions: one read txn per operation */
            if (roll < pf->fetch) {
                struct twom_txn *txn = NULL;
                if (twom_db_begin_txn(wdb, TWOM_SHARED, &txn)) continue;
                uint64_t id = rnd() % nrec;
                int miss = (int)(rnd() % 100) < missmix;
                /* a miss reaches past the populated group range, so it is a
                 * genuine "never existed" rather than a malformed key */
                uint64_t g = miss ? (uint64_t)ngroups + id : id / fanout;
                int kl = mkkey(key, g, id % fanout);
                const char *vp; size_t vl;
                r = twom_txn_fetch(txn, key, kl, NULL, NULL, &vp, &vl, 0);
                if (r == 0) st->hit++; else st->miss++;
                twom_txn_abort(&txn);
                st->fetch++;
            } else if (roll < pf->fetch + pf->foreach) {
                struct twom_txn *txn = NULL;
                if (twom_db_begin_txn(wdb, TWOM_SHARED, &txn)) continue;
                uint64_t recs = 0;
                int pl = mkprefix(key, rnd() % ngroups);
                twom_txn_foreach(txn, key, pl, NULL, cb_count, &recs,
                                 TWOM_ALWAYSYIELD);
                twom_txn_abort(&txn);
                st->fe++; st->recs += recs;
            } else {
                struct twom_txn *txn = NULL;
                if (twom_db_begin_txn(wdb, 0, &txn)) continue;
                uint64_t id = rnd() % nrec;
                int kl = mkkey(key, id / fanout, id % fanout);
                int vl = pick(VALLEN, NVALLEN);
                twom_txn_store(txn, key, kl, val, vl, 0);
                twom_txn_commit(&txn);
                st->st++;
            }
            uint64_t ns = (uint64_t)((bench_now() - s) * 1e9);
            st->ns += ns; st->ops++;
            int b = 0; while ((ns >>= 1) && b < 39) b++;
            st->lat[b]++;
        }
        twom_db_close(&wdb);
        _exit(0);
    }
    for (int w = 0; w < nproc; w++) wait(NULL);
    double el = bench_now() - t0;

    struct stats t = {0};
    for (int w = 0; w < nproc; w++) {
        t.ops += sh[w].ops; t.fetch += sh[w].fetch; t.hit += sh[w].hit;
        t.miss += sh[w].miss; t.fe += sh[w].fe; t.recs += sh[w].recs;
        t.st += sh[w].st; t.ns += sh[w].ns;
        for (int b = 0; b < 40; b++) t.lat[b] += sh[w].lat[b];
    }
    printf("\nelapsed      %.1fs across %d processes\n", el, nproc);
    printf("operations   %llu  (%.0f/s)\n", (unsigned long long)t.ops, t.ops/el);
    printf("  fetch      %llu  (%.0f/s)  hit %.1f%%\n",
           (unsigned long long)t.fetch, t.fetch/el,
           t.fetch ? 100.0*t.hit/t.fetch : 0);
    printf("  foreach    %llu  (%.0f/s)  %.1f records/scan\n",
           (unsigned long long)t.fe, t.fe/el, t.fe ? (double)t.recs/t.fe : 0);
    printf("  store      %llu  (%.0f/s)\n", (unsigned long long)t.st, t.st/el);
    printf("mean latency %.1fus\n", t.ops ? t.ns/1e3/t.ops : 0);
    uint64_t cum = 0;
    printf("latency      ");
    for (int b = 0; b < 40; b++) {
        cum += t.lat[b];
        if (t.ops && cum >= t.ops/2)   { printf("p50=%lluus ", 1ULL<<b>>10); break; }
    }
    cum = 0;
    for (int b = 0; b < 40; b++) {
        cum += t.lat[b];
        if (t.ops && cum >= t.ops*99/100) { printf("p99=%lluus", 1ULL<<b>>10); break; }
    }
    printf("\n");
    return 0;
}
