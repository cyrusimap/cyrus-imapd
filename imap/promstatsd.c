/* promstatsd.c - daemon for collating statistics for Prometheus
 *
 * Copyright (c) 1994-2017 Carnegie Mellon University.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The name "Carnegie Mellon University" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For permission or any legal
 *    details, please contact
 *      Carnegie Mellon University
 *      Center for Technology Transfer and Enterprise Creation
 *      4615 Forbes Avenue
 *      Suite 302
 *      Pittsburgh, PA  15213
 *      (412) 268-7393, fax: (412) 268-7395
 *      innovation@andrew.cmu.edu
 *
 * 4. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Computing Services
 *     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <config.h>

#include <sys/types.h>

#include <dirent.h>
#include <errno.h>
#include <inttypes.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <sysexits.h>
#include <syslog.h>
#include <unistd.h>

#include "lib/bsearch.h"
#include "lib/cyr_lock.h"
#include "lib/hash.h"
#include "lib/retry.h"
#include "lib/strarray.h"
#include "lib/util.h"

#include "imap/global.h"
#include "imap/mboxlist.h"
#include "imap/mboxname.h"
#include "imap/prometheus.h"
#include "imap/quota.h"

/* globals so that shut_down() can clean up */
static struct buf report_buf = BUF_INITIALIZER;
static struct mappedfile *report_file = NULL;

static void shut_down(int ec) __attribute__((noreturn));
static void shut_down(int ec)
{
    mappedfile_close(&report_file);
    buf_free(&report_buf);
    cyrus_done();
    exit(ec);
}

EXPORTED void fatal(const char *msg, int err)
{
    syslog(LOG_CRIT, "%s", msg);
    syslog(LOG_NOTICE, "exiting");

    shut_down(err);
}

static const char *argv0 = NULL;
static void usage(void)
{
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "    %s [-C alt_config] [-v] [-f frequency] [-d]\n", argv0);
    fprintf(stderr, "    %s [-C alt_config] [-v] -c\n", argv0);
    exit(EX_USAGE);
}

static void save_argv0(const char *s)
{
    const char *slash = strrchr(s, '/');
    if (slash)
        argv0 = slash + 1;
    else
        argv0 = s;
}

static int do_cleanup(void)
{
    const char *basedir = prometheus_stats_dir();
    DIR *dh;
    struct dirent *dirent;

    dh = opendir(basedir);
    if (!dh) {
        if (errno == ENOENT) return 0; /* nothing to do */
        syslog(LOG_ERR, "IOERROR: opendir(%s): %m", basedir);
        return EX_IOERR;
    }

    while ((dirent = readdir(dh))) {
        char path[PATH_MAX];
        int r;

        if (dirent->d_name[0] == '.') continue;

        r = snprintf(path, sizeof(path), "%s%s", basedir, dirent->d_name);
        if (r < 0 || (size_t) r >= sizeof(path)) {
            syslog(LOG_ERR, "IOERROR: path too long: %s%s", basedir, dirent->d_name);
            continue;
        }

        unlink(path);
    }

    closedir(dh);
    return 0;
}

enum promdir_foreach_mode {
    PROMDIR_FOREACH_PIDS,
    PROMDIR_FOREACH_DONEPROCS,
};
typedef int promdir_foreach_cb(const struct prom_stats *stats, void *rock);
static int promdir_foreach(promdir_foreach_cb *proc, enum promdir_foreach_mode mode, void *rock)
{
    const char *basedir;
    DIR *dh;
    struct dirent *dirent;
    int r = 0;

    basedir = prometheus_stats_dir();

    dh = opendir(basedir);
    if (!dh) {
        syslog(LOG_ERR, "IOERROR: prometheus_foreach opendir(%s): %m", basedir);
        return -1;
    }

    while ((dirent = readdir(dh))) {
        char fname[PATH_MAX];
        struct prom_stats stats;
        struct mappedfile *mf = NULL;

        /* skip filenames we don't care about */
        if (dirent->d_name[0] == '.') continue;
        if (mode == PROMDIR_FOREACH_PIDS && !cyrus_isdigit(dirent->d_name[0])) continue;
        if (mode == PROMDIR_FOREACH_DONEPROCS && dirent->d_name[0] != 'd') continue;

        r = snprintf(fname, sizeof(fname), "%s%s", basedir, dirent->d_name);
        if (r < 0 || (size_t) r >= sizeof(fname)) {
            syslog(LOG_ERR, "IOERROR: path too long: %s%s", basedir, dirent->d_name);
            continue;
        }

        r = mappedfile_open(&mf, fname, 0);
        if (r) continue;
        r = mappedfile_readlock(mf);
        if (!r) {
            memcpy(&stats, mappedfile_base(mf), mappedfile_size(mf));
            mappedfile_unlock(mf);
        }
        mappedfile_close(&mf);

        r = proc(&stats, rock);
        if (r) break;
    }

    closedir(dh);

    return r;
}

static int accum_stats(const struct prom_stats *stats, void *rock)
{
    struct prom_stats *stats_copy;
    hash_table *h = (hash_table *) rock;
    int i;

    stats_copy = hash_lookup(stats->ident, h);
    if (!stats_copy) {
        stats_copy = xzmalloc(sizeof *stats_copy);
        strcpy(stats_copy->ident, stats->ident);
        hash_insert(stats->ident, stats_copy, h);
    }

    for (i = 0; i < PROM_NUM_METRICS; i++) {
        stats_copy->metrics[i].value += stats->metrics[i].value;
        stats_copy->metrics[i].last_updated = MAX(stats_copy->metrics[i].last_updated,
                                                  stats->metrics[i].last_updated);
    }

    return 0;
}

struct format_metric_rock {
    struct buf *buf;
    enum prom_metric_id metric;
};

static void format_metric(const char *key __attribute__((unused)),
                          void *data, void *rock)
{
    struct prom_stats *stats = (struct prom_stats *) data;
    struct format_metric_rock *fmrock = (struct format_metric_rock *) rock;

    /* don't report service/metric combinations that have never been seen */
    if (!stats->metrics[fmrock->metric].last_updated)
        return;

    buf_appendcstr(fmrock->buf, prom_metric_descs[fmrock->metric].name);
    buf_printf(fmrock->buf, "{service=\"%s\"", stats->ident);
    if (prom_metric_descs[fmrock->metric].label)
        buf_printf(fmrock->buf, ",%s", prom_metric_descs[fmrock->metric].label);
    buf_printf(fmrock->buf, "} %0.f %" PRId64 "\n",
                            stats->metrics[fmrock->metric].value,
                            stats->metrics[fmrock->metric].last_updated);
}

static void do_collate_report(struct buf *buf)
{
    hash_table all_stats = HASH_TABLE_INITIALIZER;
    char *doneprocs_lock_fname;
    int doneprocs_lock_fd;
    int i;

    buf_reset(buf);
    construct_hash_table(&all_stats, 128, 0);

    /* hold a lock on .doneprocs.lock while reading stats files - this ensures
     * process cleanups won't lead to double counts while we're collating */
    doneprocs_lock_fname = strconcat(prometheus_stats_dir(), ".",
                                     FNAME_PROM_DONEPROCS, ".lock", NULL);

    doneprocs_lock_fd = open(doneprocs_lock_fname, O_CREAT|O_TRUNC|O_RDWR, 0644);
    if (doneprocs_lock_fd == -1) {
        syslog(LOG_ERR, "can't open doneprocs lock: %s (%m)", doneprocs_lock_fname);
        free_hash_table(&all_stats, NULL);
        return;
    }
    if (lock_setlock(doneprocs_lock_fd, /*ex*/1, /*nb*/0, doneprocs_lock_fname)) {
        syslog(LOG_ERR, "can't get exclusive lock on %s", doneprocs_lock_fname);
        close(doneprocs_lock_fd);
        doneprocs_lock_fd = -1;
        free(doneprocs_lock_fname);
        free_hash_table(&all_stats, NULL);
        return;
    }

    /* slurp up and accumulate doneprocs stats */
    promdir_foreach(&accum_stats, PROMDIR_FOREACH_DONEPROCS, &all_stats);

    /* slurp up and accumulate current stats */
    promdir_foreach(&accum_stats, PROMDIR_FOREACH_PIDS, &all_stats);

    syslog(LOG_DEBUG, "updating prometheus report for %d services",
                      hash_numrecords(&all_stats));

    /* release .doneprocs.lock */
    unlink(doneprocs_lock_fname);
    lock_unlock(doneprocs_lock_fd, doneprocs_lock_fname);
    close(doneprocs_lock_fd);
    free(doneprocs_lock_fname);

    /* format it into buf */
    for (i = 0; i < PROM_NUM_METRICS; i++) {
        if (prom_metric_descs[i].help) {
            buf_printf(buf, "# HELP %s %s\n", prom_metric_descs[i].name,
                            prom_metric_descs[i].help);
        }
        if (prom_metric_descs[i].type != PROM_METRIC_CONTINUED) {
            buf_printf(buf, "# TYPE %s %s\n", prom_metric_descs[i].name,
                            prom_metric_type_names[prom_metric_descs[i].type]);
        }

	/*  */ {
		
        struct format_metric_rock fmrock = { buf, i };
        hash_enumerate(&all_stats, &format_metric, &fmrock);
	
	}
    }

    /* clean up the copy */
    free_hash_table(&all_stats, free);
}

struct partition_data {
    int64_t n_users;
    int64_t n_mailboxes;
    int64_t n_deleted;
    hash_table shared;

    double quota_commitment[QUOTA_NUMRESOURCES];

    int64_t timestamp;
};

static void free_partition_data(void *ptr)
{
    struct partition_data *pdata = (struct partition_data *) ptr;

    free_hash_table(&pdata->shared, free);
    memset(pdata, 0, sizeof *pdata);
    free(pdata);
}

/* Tricky optimisation to avoid excess unlocking in twoskip:
 * instead of using the cb hook, we use the p hook and ALWAYS return 0.
 * We wouldn't need this if cyrusdb had a real readonly foreach API
 */
static int count_users_mailboxes(struct findall_data *data, void *rock)
{
    hash_table *h = (hash_table *) rock;
    struct partition_data *pdata;

    /* don't want partial matches */
    if (!data || !data->is_exactmatch) return 0;

    /* don't want intermediates XXX unless we do? in which case count them! */
    if (!data->mbentry->partition) return 0;

    pdata = hash_lookup(data->mbentry->partition, h);
    if (!pdata) {
        pdata = malloc(sizeof *pdata);
        memset(pdata, 0, sizeof *pdata);
        construct_hash_table(&pdata->shared, 10, 0); /* 10 shared namespaces probably enough */
        hash_insert(data->mbentry->partition, pdata, h);
    }

    if (mbname_isdeleted(data->mbname)) {
        pdata->n_deleted ++;
        pdata->timestamp = now_ms();
    }
    else if (mbname_category(data->mbname, mboxname_get_adminnamespace(), NULL)
             == MBNAME_SHARED) {
        const char *namespace = strarray_nth(mbname_boxes(data->mbname), 0);
        int64_t *n_shared = hash_lookup(namespace, &pdata->shared);
        if (!n_shared) {
            n_shared = malloc(sizeof *n_shared);
            *n_shared = 0;
            hash_insert(namespace, n_shared, &pdata->shared);
        }

        (*n_shared)++;
        pdata->timestamp = now_ms();
    }
    else if (mbname_userid(data->mbname) &&
        !strarray_size(mbname_boxes(data->mbname))) {
        pdata->n_users ++;
        pdata->n_mailboxes ++; /* an inbox is also a mailbox */
        pdata->timestamp = now_ms();
    }
    else {
        pdata->n_mailboxes ++;
        pdata->timestamp = now_ms();
    }

    return 0;
}

struct quota_rock {
    struct quota *quota;
    hash_table *data;
    hash_table *seen;
};

static int quota_cb(const mbentry_t *mbentry, void *rock)
{
    struct quota_rock *qrock = (struct quota_rock *) rock;
    struct partition_data *pdata;
    const char *partition;
    char qroot[MAX_MAILBOX_NAME];
    int res;

    /* don't count if it belongs to a different quotaroot */
    if (quota_findroot(qroot, sizeof(qroot), mbentry->name)
        && strcmp(qroot, qrock->quota->root) != 0) {
        return 0;
    }

    /* no partition? nothing to count */
    if (!mbentry->partition) {
        return 0;
    }

    partition = mbentry->partition;
    if (hash_lookup(partition, qrock->seen)) {
        /* seen this partition for this quotaroot already, don't double count it */
        return 0;
    }

    pdata = hash_lookup(partition, qrock->data);

    for (res = 0; res < QUOTA_NUMRESOURCES; res++) {
        struct quota *q = qrock->quota;
        double dv = q->limits[res] < 0 ? INFINITY : q->limits[res];

        pdata->quota_commitment[res] += dv;
    }
    pdata->timestamp = now_ms();

    hash_insert(partition, (void *) 1, qrock->seen);
    return 0;
}

static int count_quota_commitments(struct quota *quota, void *rock)
{
    struct quota_rock *qrock = (struct quota_rock *) rock;
    hash_table seen = HASH_TABLE_INITIALIZER;
    int r;

    construct_hash_table(&seen, 10, 0); /* XXX */
    qrock->seen = &seen;
    qrock->quota = quota;

    r = mboxlist_mboxtree(quota->root, quota_cb, qrock, 0);

    qrock->quota = NULL;
    free_hash_table(&seen, NULL);
    qrock->seen = NULL;

    return r;
}

static void pname_cb(const char *key,
                     void *data __attribute__((unused)),
                     void *rock)
{
    strarray_append((strarray_t *) rock, key);
}

static strarray_t *get_partition_names(hash_table *h)
{
    strarray_t *names = strarray_new();
    hash_enumerate(h, pname_cb, names);
    strarray_sort(names, cmpstringp_raw);
    return names;
}

#define FORMAT_USAGE_INT64(metric, type, help, member, buf, pnames, h) \
do {                                                                         \
    const char *___metric = (metric);                                        \
    const char *___type = (type);                                            \
    const char *___help = (help);                                            \
    struct buf *___buf = (buf);                                              \
    const strarray_t *___pnames = (pnames);                                  \
    hash_table *___h = (h);                                                  \
    int i;                                                                   \
                                                                             \
    buf_printf(___buf, "# HELP %s %s\n", ___metric, ___help);                \
    buf_printf(___buf, "# TYPE %s %s\n", ___metric, ___type);                \
                                                                             \
    for (i = 0; i < strarray_size(___pnames); i++) {                         \
        struct partition_data *pdata =                                       \
            hash_lookup(strarray_nth(___pnames, i), ___h);                   \
                                                                             \
        buf_printf(___buf, "%s{partition=\"%s\"} %" PRId64 " %" PRId64 "\n", \
                        ___metric,                                           \
                        strarray_nth(___pnames, i),                          \
                        pdata->member,                                       \
                        pdata->timestamp);                                   \
    }                                                                        \
} while(0)

struct shared_mailbox_rock {
    struct buf *buf;
    char *partition;
    int64_t timestamp;
};

static void format_usage_shared_mailbox(const char *key, void *data, void *rock)
{
    struct shared_mailbox_rock *smrock = (struct shared_mailbox_rock *) rock;
    int64_t n_shared = *(int64_t *) data;

    buf_printf(smrock->buf, "%s{partition=\"%s\",namespace=\"%s\"}",
                            "cyrus_usage_shared_mailboxes",
                            smrock->partition,
                            key);
    buf_printf(smrock->buf, " %" PRId64 " %" PRId64 "\n",
                            n_shared,
                            smrock->timestamp);
}

static void format_usage_shared_mailboxes(struct buf *buf,
                                          const strarray_t *pnames,
                                          hash_table *h)
{
    int i;

    buf_printf(buf, "# HELP %s %s\n",
                    "cyrus_usage_shared_mailboxes",
                    "The number of shared Cyrus mailboxes");
    buf_appendcstr(buf, "# TYPE cyrus_usage_shared_mailboxes gauge\n");

    for (i = 0; i < strarray_size(pnames); i++) {
        struct shared_mailbox_rock smrock;
        struct partition_data *pdata;

        smrock.buf = buf;
        smrock.partition = (char *) strarray_nth(pnames, i); /* n.b. casting away const */

        pdata = hash_lookup(smrock.partition, h);
        smrock.timestamp = pdata->timestamp;

        hash_enumerate(&pdata->shared, format_usage_shared_mailbox, &smrock);
    }
}

static void format_usage_quota_commitment(struct buf *buf,
                                          const strarray_t *pnames,
                                          hash_table *h)
{
    int i, res;
    buf_printf(buf, "# HELP %s %s\n",
                    "cyrus_usage_quota_commitment",
                    "The amount of quota committed");
    buf_appendcstr(buf, "# TYPE cyrus_usage_quota_commitment gauge\n");

    for (i = 0; i < strarray_size(pnames); i++) {
        struct partition_data *pdata = hash_lookup(strarray_nth(pnames, i), h);

        for (res = 0; res < QUOTA_NUMRESOURCES; res++) {
            buf_printf(buf, "%s{partition=\"%s\",resource=\"%s\"}",
                            "cyrus_usage_quota_commitment",
                            strarray_nth(pnames, i),
                            quota_names[res]);
            buf_printf(buf, " %.0f %" PRId64 "\n",
                            pdata->quota_commitment[res],
                            pdata->timestamp);
        }
    }
}

static void do_collate_usage(struct buf *buf)
{
    hash_table h = HASH_TABLE_INITIALIZER;
    strarray_t *partition_names = NULL;
    int r;
    int64_t starttime;

    construct_hash_table(&h, 10, 0); /* 10 partitions is probably enough right */

    starttime = now_ms();
    r = mboxlist_findall_withp(NULL /* admin namespace */,
                               "*", 1,
                               NULL, NULL,
                               count_users_mailboxes, NULL, &h);
    syslog(LOG_DEBUG, "counted users and mailboxes in %f seconds",
                      (now_ms() - starttime) / 1000.0);

    if (!r) {
        struct quota_rock rock = { NULL, &h, NULL };

        starttime = now_ms();
        r = quota_foreach(NULL, count_quota_commitments, &rock, NULL);
        syslog(LOG_DEBUG, "counted quota commitments in %f seconds",
                          (now_ms() - starttime) / 1000.0);

    }

    /* need to invert the hash table on output, so build a list of its keys */
    partition_names = get_partition_names(&h);

    FORMAT_USAGE_INT64("cyrus_usage_deleted_mailboxes", "gauge",
                       "The number of deleted Cyrus mailboxes",
                       n_deleted,
                       buf, partition_names, &h);

    FORMAT_USAGE_INT64("cyrus_usage_users", "gauge",
                       "The number of Cyrus user Inboxes",
                       n_users,
                       buf, partition_names, &h);

    FORMAT_USAGE_INT64("cyrus_usage_mailboxes", "gauge",
                       "The number of Cyrus mailboxes",
                       n_mailboxes,
                       buf, partition_names, &h);

    format_usage_shared_mailboxes(buf, partition_names, &h);

    format_usage_quota_commitment(buf, partition_names, &h);

    strarray_free(partition_names);
    free_hash_table(&h, free_partition_data);
}

static void do_write_report(struct mappedfile *mf, const struct buf *report)
{
    int r;

    r = mappedfile_writelock(mf);
    if (r) fatal("couldn't write lock report file", EX_IOERR);

    r = mappedfile_pwritebuf(mf, report, 0);
    if (r < 0) fatal("error writing report file", EX_IOERR);

    mappedfile_truncate(mf, buf_len(report));

    r = mappedfile_commit(mf);
    if (r) fatal("error committing report file", EX_IOERR);

    mappedfile_unlock(mf);
}

int main(int argc, char **argv)
{
    const char *alt_config = NULL;
    int call_debugger = 0;
    char *report_fname = NULL;
    struct mappedfile *report_f = NULL;
    const char *p;
    int cleanup = 0;
    int debugmode = 0;
    int verbose = 0;
    int frequency = 0;
    int oneshot = 0;
    int opt;
    int r;

    save_argv0(argv[0]);

    p = getenv("CYRUS_VERBOSE");
    if (p) verbose = atoi(p) + 1;

    while ((opt = getopt(argc, argv, "C:D1cdf:v")) != -1) {
        switch (opt) {
        case 'C': /* alt config file */
            alt_config = optarg;
            break;

        case 'D': /* run gdb */
            call_debugger = 1;
            break;

        case '1': /* produce report once and exit */
            oneshot = 1;
            break;

        case 'c': /* cleanup stats directory and exit */
            cleanup = 1;
            break;

        case 'd': /* debug mode (no fork) */
            debugmode = 1;
            break;

        case 'f': /* set frequency */
            frequency = atoi(optarg);
            if (frequency <= 0) usage();
            break;

        case 'v': /* verbose */
            verbose ++;
            break;

        default:
            usage();
            break;
        }
    }

    cyrus_init(alt_config, "promstatsd", 0, 0);
    signals_set_shutdown(shut_down);
    signals_add_handlers(0);

    if (cleanup) {
        shut_down(do_cleanup());
    }

    if (!config_getswitch(IMAPOPT_PROMETHEUS_ENABLED)) {
        fatal("Prometheus metrics are not being tracked."
              "  Set prometheus_enable in imapd.conf",
              EX_CONFIG);
    }

    /* fork unless we were given the -d option or we're running as a daemon */
    if (oneshot == 0 && debugmode == 0 && !getenv("CYRUS_ISDAEMON")) {
        pid_t pid = fork();

        if (pid == -1) {
            fatal("fork failed", EX_OSERR);
        }

        if (pid != 0) { /* parent */
            exit(0);
        }
    }

    if (call_debugger) {
        char debugbuf[1024];
        int ret;
        const char *debugger = config_getstring(IMAPOPT_DEBUG_COMMAND);
        if (debugger) {
            snprintf(debugbuf, sizeof(debugbuf), debugger,
                     argv[0], getpid(), "promstatsd");
            syslog(LOG_DEBUG, "running external debugger: %s", debugbuf);
            ret = system(debugbuf); /* run debugger */
            syslog(LOG_DEBUG, "debugger returned exit status: %d", ret);
        }
    }

    if (frequency <= 0)
        frequency = config_getduration(IMAPOPT_PROMETHEUS_UPDATE_FREQ, 's');
    if (frequency <= 0)
        frequency = 10;

    report_fname = strconcat(prometheus_stats_dir(), FNAME_PROM_REPORT, NULL);
    syslog(LOG_DEBUG, "updating %s every %d seconds", report_fname, frequency);

    unlink(report_fname);
    r = mappedfile_open(&report_f, report_fname, MAPPEDFILE_CREATE | MAPPEDFILE_RW);
    free(report_fname);
    if (r) fatal("couldn't open report file", EX_IOERR);

    for (;;) {
        int sig;
        int64_t starttime;

        sig = signals_poll();
        if (sig == SIGHUP && getenv("CYRUS_ISDAEMON")) {
            syslog(LOG_DEBUG, "received SIGHUP, shutting down gracefully\n");
            shut_down(0);
        }

        /* check for shutdown file */
        if (shutdown_file(NULL, 0)) {
            if (verbose || debugmode)
                syslog(LOG_DEBUG, "Detected shutdown file\n");
            shut_down(0);
        }

        starttime = now_ms();
        do_collate_report(&report_buf);
        syslog(LOG_DEBUG, "collated service report in %f seconds",
                (now_ms() - starttime) / 1000.0);

        starttime = now_ms();
        do_collate_usage(&report_buf);
        syslog(LOG_DEBUG, "collated usage report in %f seconds",
                (now_ms() - starttime) / 1000.0);

        do_write_report(report_f, &report_buf);

        if (oneshot) {
            shut_down(0);
        }

        /* then wait around a bit */
        sleep(frequency); /* XXX substract elapsed time? */
    }

    /* NOTREACHED */
    shut_down(EX_SOFTWARE);
}
