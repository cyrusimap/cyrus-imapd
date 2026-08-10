/* dbbench - replay the measured production workload against ANY cyrusdb
 * backend, and report throughput, CPU, wall time and disk footprint.
 *
 * Goes through the cyrusdb abstraction rather than twom directly, so
 * --engine picks the backend by name (twom, twoskip, skiplist, flat, ...).
 * The workload itself is shared with twom-bench via bench-workload.h, so the
 * single-engine and cross-engine numbers describe the same access pattern.
 *
 * Disk is reported as both apparent size and allocated blocks, before and
 * after a repack: the engines differ far more in slack than in apparent size,
 * and the repack is where twom's compaction shows up.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <libgen.h>
#include <dirent.h>
#include <getopt.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/resource.h>

#include "cyrusdb.h"
#include "bench-workload.h"

/* cyrus expects the embedding program to supply these */
EXPORTED void fatal(const char *msg, int code)
{
    fprintf(stderr, "fatal: %s\n", msg);
    exit(code);
}

struct stats { uint64_t ops, fetch, hit, miss, fe, recs, st, ns, lat[40]; };

struct disk { uint64_t apparent, allocated; int files; };

/* every file whose name starts with the db's basename: the db plus whatever
 * index/journal/.NEW companions a backend leaves beside it */
static struct disk disk_usage(const char *path)
{
    struct disk d = {0, 0, 0};
    char tmp[4096], tmp2[4096];
    snprintf(tmp, sizeof(tmp), "%s", path);
    snprintf(tmp2, sizeof(tmp2), "%s", path);
    const char *dir = dirname(tmp);
    const char *base = basename(tmp2);
    DIR *dp = opendir(dir);
    if (!dp) return d;
    struct dirent *e;
    size_t bl = strlen(base);
    while ((e = readdir(dp))) {
        if (strncmp(e->d_name, base, bl)) continue;
        char full[8192];
        snprintf(full, sizeof(full), "%s/%s", dir, e->d_name);
        struct stat sb;
        if (stat(full, &sb)) continue;
        if (!S_ISREG(sb.st_mode)) continue;
        d.apparent += sb.st_size;
        d.allocated += (uint64_t)sb.st_blocks * 512;
        d.files++;
    }
    closedir(dp);
    return d;
}

static int cb_count(void *rock, const char *k, size_t kl, const char *v, size_t vl)
{ (*(uint64_t *)rock)++; return 0; }

static double cpu_of(const struct rusage *r)
{ return r->ru_utime.tv_sec + r->ru_utime.tv_usec/1e6
       + r->ru_stime.tv_sec + r->ru_stime.tv_usec/1e6; }

int main(int argc, char **argv)
{
    const char *dbpath = "/var/tmp/dbbench.db";
    const char *engine = "twom";
    const char *pname  = "aggregate";
    int nrec = 200000, nproc = 8, secs = 30, missmix = 20;
    int populate = 1, do_repack = 1, shared = 1, sync = 0;
    static struct option lo[] = {
        {"db",required_argument,0,'d'},      {"engine",required_argument,0,'e'},
        {"records",required_argument,0,'n'}, {"procs",required_argument,0,'p'},
        {"secs",required_argument,0,'s'},    {"profile",required_argument,0,'P'},
        {"miss",required_argument,0,'m'},    {"no-populate",no_argument,0,'X'},
        {"no-repack",no_argument,0,'R'},     {"no-shared",no_argument,0,'S'},
        {"list-engines",no_argument,0,'L'},  {"sync",no_argument,0,'Y'},
        {"help",no_argument,0,'h'}, {0,0,0,0}
    };
    int c;
    while ((c = getopt_long(argc, argv, "d:e:n:p:s:P:m:XRSLYh", lo, NULL)) != -1) {
        switch (c) {
        case 'd': dbpath = optarg; break;
        case 'e': engine = optarg; break;
        case 'n': nrec = atoi(optarg); break;
        case 'p': nproc = atoi(optarg); break;
        case 's': secs = atoi(optarg); break;
        case 'P': pname = optarg; break;
        case 'm': missmix = atoi(optarg); break;
        case 'X': populate = 0; break;
        case 'R': do_repack = 0; break;
        case 'S': shared = 0; break;
        case 'Y': sync = 1; break;
        case 'L': {
            cyrusdb_init();
            strarray_t *b = cyrusdb_backends();
            for (int i = 0; i < b->count; i++) printf("%s\n", b->data[i]);
            cyrusdb_done();
            return 0;
        }
        default:
            fprintf(stderr,
              "usage: %s [--engine NAME] [--db PATH] [--records N] [--procs N]\n"
              "          [--secs N] [--profile aggregate|mailboxes|conversations|annotations]\n"
              "          [--miss PCT] [--no-populate] [--no-repack] [--no-shared]\n"
              "          [--sync] [--list-engines]\n", argv[0]);
            return 1;
        }
    }
    const struct profile *pf = find_profile(pname);
    if (!pf) { fprintf(stderr, "unknown profile %s\n", pname); return 1; }

    /* -1 because cursor_next counts the terminating DONE call too */
    int fanout = (int)(pf->scan - 1 + 0.5); if (fanout < 1) fanout = 1;
    int ngroups = nrec / fanout; if (ngroups < 1) ngroups = 1;
    nrec = ngroups * fanout;

    /* default to NOSYNC so the comparison measures the engines rather than
     * this box's fsync latency; --sync for a durability-faithful run */
    int openflags = sync ? 0 : CYRUSDB_NOSYNC;

    cyrusdb_init();

    struct db *db = NULL;
    struct txn *tid = NULL;
    int r;
    char key[512];
    static char val[16384];
    memset(val, 'v', sizeof(val));

    if (populate) {
        fprintf(stderr, "populating %s (%s) with %d records...\n",
                dbpath, engine, nrec);
        unlink(dbpath);
        r = cyrusdb_open(engine, dbpath, CYRUSDB_CREATE | openflags, &db);
        if (r) { fprintf(stderr, "open: %s\n", cyrusdb_strerror(r)); return 1; }
        for (int i = 0; i < nrec; i++) {
            int kl = mkkey(key, i / fanout, i % fanout);
            int vl = pick_seeded(VALLEN, NVALLEN, i + 1);
            r = cyrusdb_store(db, key, kl, val, vl, &tid);
            if (r) { fprintf(stderr, "store: %s\n", cyrusdb_strerror(r)); return 1; }
            if ((i % 20000) == 19999) { cyrusdb_commit(db, tid); tid = NULL; }
        }
        if (tid) { cyrusdb_commit(db, tid); tid = NULL; }
        cyrusdb_close(db);
    }

    struct disk d_pop = disk_usage(dbpath);

    struct stats *sh = mmap(NULL, sizeof(*sh) * nproc, PROT_READ|PROT_WRITE,
                            MAP_SHARED|MAP_ANONYMOUS, -1, 0);
    memset(sh, 0, sizeof(*sh) * nproc);

    fprintf(stderr, "engine=%s profile=%s procs=%d secs=%d miss=%d%% "
                    "fanout=%d groups=%d sync=%s\n",
            engine, pf->name, nproc, secs, missmix, fanout, ngroups,
            sync ? "yes" : "no");

    double t0 = bench_now();
    for (int w = 0; w < nproc; w++) {
        if (fork()) continue;
        /* ---- worker ---- */
        struct stats *st = &sh[w];
        rnd_state = (uint64_t)(w + 1) * 88172645463325252ULL;
        struct db *wdb = NULL;
        if (cyrusdb_open(engine, dbpath, openflags, &wdb)) _exit(1);
        int total = pf->fetch + pf->foreach + pf->store;
        char wkey[512];
        double deadline = bench_now() + secs;

        while (bench_now() < deadline) {
            int roll = rnd() % total;
            double s = bench_now();
            struct txn *t = NULL;
            if (roll < pf->fetch) {
                /* prod is 99.5% shared transactions: one read txn per op */
                if (shared) cyrusdb_lock(wdb, &t, CYRUSDB_SHARED);
                uint64_t id = rnd() % nrec;
                int miss = (int)(rnd() % 100) < missmix;
                uint64_t g = miss ? (uint64_t)ngroups + id : id / fanout;
                int kl = mkkey(wkey, g, id % fanout);
                const char *vp; size_t vl;
                r = cyrusdb_fetch(wdb, wkey, kl, &vp, &vl, &t);
                if (r == 0) st->hit++; else st->miss++;
                if (t) cyrusdb_abort(wdb, t);
                st->fetch++;
            } else if (roll < pf->fetch + pf->foreach) {
                if (shared) cyrusdb_lock(wdb, &t, CYRUSDB_SHARED);
                uint64_t recs = 0;
                int pl = mkprefix(wkey, rnd() % ngroups);
                cyrusdb_foreach(wdb, wkey, pl, NULL, cb_count, &recs, &t);
                if (t) cyrusdb_abort(wdb, t);
                st->fe++; st->recs += recs;
            } else {
                uint64_t id = rnd() % nrec;
                int kl = mkkey(wkey, id / fanout, id % fanout);
                int vl = pick(VALLEN, NVALLEN);
                if (cyrusdb_store(wdb, wkey, kl, val, vl, &t) == 0 && t)
                    cyrusdb_commit(wdb, t);
                else if (t) cyrusdb_abort(wdb, t);
                st->st++;
            }
            uint64_t ns = (uint64_t)((bench_now() - s) * 1e9);
            st->ns += ns; st->ops++;
            int b = 0; while ((ns >>= 1) && b < 39) b++;
            st->lat[b]++;
        }
        cyrusdb_close(wdb);
        _exit(0);
    }
    for (int w = 0; w < nproc; w++) wait(NULL);
    double el = bench_now() - t0;

    struct rusage ru;
    getrusage(RUSAGE_CHILDREN, &ru);
    double cpu = cpu_of(&ru);

    struct disk d_run = disk_usage(dbpath);
    struct disk d_pack = d_run;
    double packsec = 0;
    int packed = 0;
    if (do_repack) {
        /* skiplist's checkpoint assert()s unless the db is already WRITELOCKED,
         * and an assert aborts the process - so do it in a child and treat a
         * dead child as "this backend has no standalone repack". */
        double p0 = bench_now();
        pid_t pid = fork();
        if (pid == 0) {
            struct db *pdb = NULL;
            if (cyrusdb_open(engine, dbpath, openflags, &pdb)) _exit(2);
            int rr = cyrusdb_repack(pdb);
            cyrusdb_close(pdb);
            _exit(rr == CYRUSDB_OK ? 0 : 3);
        }
        int wst = 0;
        waitpid(pid, &wst, 0);
        packed = WIFEXITED(wst) && WEXITSTATUS(wst) == 0;
        packsec = bench_now() - p0;
        if (packed) d_pack = disk_usage(dbpath);
        else fprintf(stderr, "note: no usable standalone repack for %s\n", engine);
    }
    cyrusdb_done();

    struct stats t = {0};
    for (int w = 0; w < nproc; w++) {
        t.ops += sh[w].ops; t.fetch += sh[w].fetch; t.hit += sh[w].hit;
        t.miss += sh[w].miss; t.fe += sh[w].fe; t.recs += sh[w].recs;
        t.st += sh[w].st; t.ns += sh[w].ns;
        for (int b = 0; b < 40; b++) t.lat[b] += sh[w].lat[b];
    }
#define MB(x) ((double)(x) / (1024.0*1024.0))
    printf("\nengine       %s   profile=%s   records=%d   procs=%d\n",
           engine, pf->name, nrec, nproc);
    printf("walltime     %.1fs\n", el);
    printf("cpu          %.1fs  (%.2f cores, %.2f us/op)\n",
           cpu, el > 0 ? cpu/el : 0, t.ops ? cpu*1e6/t.ops : 0);
    printf("operations   %llu  (%.0f/s)\n", (unsigned long long)t.ops, t.ops/el);
    printf("  fetch      %llu  (%.0f/s)  hit %.1f%%\n",
           (unsigned long long)t.fetch, t.fetch/el,
           t.fetch ? 100.0*t.hit/t.fetch : 0);
    printf("  foreach    %llu  (%.0f/s)  %.1f records/scan\n",
           (unsigned long long)t.fe, t.fe/el, t.fe ? (double)t.recs/t.fe : 0);
    printf("  store      %llu  (%.0f/s)\n", (unsigned long long)t.st, t.st/el);
    printf("mean latency %.1fus\n", t.ops ? t.ns/1e3/t.ops : 0);
    uint64_t cum = 0;
    for (int b = 0; b < 40; b++) {
        cum += t.lat[b];
        if (t.ops && cum >= t.ops/2) { printf("latency      p50=%lluus ", 1ULL<<b>>10); break; }
    }
    cum = 0;
    for (int b = 0; b < 40; b++) {
        cum += t.lat[b];
        if (t.ops && cum >= t.ops*99/100) { printf("p99=%lluus\n", 1ULL<<b>>10); break; }
    }
    printf("disk         %-10s %10s %10s %6s\n", "", "apparent", "on-disk", "files");
    printf("  populated  %-10s %9.1fM %9.1fM %6d\n", "",
           MB(d_pop.apparent), MB(d_pop.allocated), d_pop.files);
    printf("  after run  %-10s %9.1fM %9.1fM %6d\n", "",
           MB(d_run.apparent), MB(d_run.allocated), d_run.files);
    if (do_repack && packed)
        printf("  repacked   %-10s %9.1fM %9.1fM %6d  (%.1fs)\n", "",
               MB(d_pack.apparent), MB(d_pack.allocated), d_pack.files, packsec);
    else if (do_repack)
        printf("  repacked   %-10s %9s\n", "", "n/a");
    printf("bytes/record %.1f apparent, %.1f on-disk%s\n",
           nrec ? (double)d_pack.apparent/nrec : 0,
           nrec ? (double)d_pack.allocated/nrec : 0,
           packed ? " (after repack)" : "");

    /* machine-readable: dbbench-compare parses this rather than the prose */
    uint64_t p50 = 0, p99 = 0, cum2 = 0;
    for (int b = 0; b < 40; b++) {
        cum2 += t.lat[b];
        if (!p50 && t.ops && cum2 >= t.ops/2) p50 = 1ULL<<b>>10;
        if (!p99 && t.ops && cum2 >= t.ops*99/100) { p99 = 1ULL<<b>>10; break; }
    }
    printf("RESULT engine=%s profile=%s records=%d procs=%d wall=%.2f cpu=%.2f"
           " ops=%llu opsps=%.0f cores=%.2f usop=%.2f hit=%.1f"
           " p50=%llu p99=%llu recscan=%.2f"
           " app_pop=%llu alloc_pop=%llu app_run=%llu alloc_run=%llu"
           " app_pack=%llu alloc_pack=%llu brec=%.1f packsec=%.2f repack=%s\n",
           engine, pf->name, nrec, nproc, el, cpu,
           (unsigned long long)t.ops, t.ops/el, el > 0 ? cpu/el : 0,
           t.ops ? cpu*1e6/t.ops : 0, t.fetch ? 100.0*t.hit/t.fetch : 0,
           (unsigned long long)p50, (unsigned long long)p99,
           t.fe ? (double)t.recs/t.fe : 0,
           (unsigned long long)d_pop.apparent, (unsigned long long)d_pop.allocated,
           (unsigned long long)d_run.apparent, (unsigned long long)d_run.allocated,
           (unsigned long long)d_pack.apparent, (unsigned long long)d_pack.allocated,
           nrec ? (double)d_pack.allocated/nrec : 0, packsec,
           packed ? "yes" : "no");
    return 0;
}
