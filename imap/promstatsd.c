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
#include <stdint.h>
#include <stdio.h>
#include <syslog.h>
#include <unistd.h>

#include "lib/cyr_lock.h"
#include "lib/exitcodes.h"
#include "lib/retry.h"
#include "lib/util.h"

#include "imap/global.h"
#include "imap/mboxlist.h"
#include "imap/mboxname.h"
#include "imap/prometheus.h"

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
    exit(EC_USAGE);
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
        return EC_IOERR;
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
    int r;

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

        struct format_metric_rock fmrock = { buf, i };
        hash_enumerate(&all_stats, &format_metric, &fmrock);
    }

    /* clean up the copy */
    free_hash_table(&all_stats, free);
}

struct users_mailboxes_counts {
    int64_t users;
    int64_t mailboxes;
    /* XXX deleted? shared? */
};

static int count_users_mailboxes(struct findall_data *data, void *rock)
{
    struct users_mailboxes_counts *umcounts = (struct users_mailboxes_counts *) rock;

    /* don't want partial matches */
    if (!data || !data->mbname) return 0;

    if (mbname_userid(data->mbname) &&
        !strarray_size(mbname_boxes(data->mbname))) {
        syslog(LOG_DEBUG, "counting user: %s", mbname_intname(data->mbname));
        umcounts->users ++;
    }

    syslog(LOG_DEBUG, "counting mailbox: %s", mbname_intname(data->mbname));
    umcounts->mailboxes ++;

    return 0;
}

static void do_collate_usage(struct buf *buf)
{
    struct users_mailboxes_counts umcounts = { 0, 0 };
    int64_t now;
    int r;

    r = mboxlist_findall(NULL /* admin namespace */, "*", 1, NULL, NULL,
                         count_users_mailboxes, &umcounts);
    if (!r) {
        now = now_ms();

        buf_printf(buf, "# HELP %s %s\n",
                        "cyrus_usage_users",
                        "The number of Cyrus user accounts");
        buf_appendcstr(buf, "# TYPE cyrus_usage_users gauge\n");
        buf_printf(buf, "cyrus_usage_users %" PRId64 " %" PRId64 "\n",
                        umcounts.users, now);

        buf_printf(buf, "# HELP %s %s\n",
                        "cyrus_usage_mailboxes",
                        "The number of Cyrus mailboxes");
        buf_appendcstr(buf, "# TYPE cyrus_usage_mailboxes gauge\n");
        buf_printf(buf, "cyrus_usage_mailboxes %" PRId64 " %" PRId64 "\n",
                        umcounts.mailboxes, now);
    }
}

static void do_write_report(struct mappedfile *mf, const struct buf *report)
{
    int r;

    r = mappedfile_writelock(mf);
    if (r) fatal("couldn't write lock report file", EC_IOERR);

    r = mappedfile_pwritebuf(mf, report, 0);
    if (r < 0) fatal("error writing report file", EC_IOERR);

    mappedfile_truncate(mf, buf_len(report));

    r = mappedfile_commit(mf);
    if (r) fatal("error committing report file", EC_IOERR);

    mappedfile_unlock(mf);
}

int main(int argc, char **argv)
{
    save_argv0(argv[0]);

    const char *alt_config = NULL;
    char *report_fname = NULL;
    struct mappedfile *report_file = NULL;
    const char *p;
    int cleanup = 0;
    int debugmode = 0;
    int verbose = 0;
    int frequency = 0;
    int opt;
    int r;

    p = getenv("CYRUS_VERBOSE");
    if (p) verbose = atoi(p) + 1;

    while ((opt = getopt(argc, argv, "C:cdf:v")) != -1) {
        switch (opt) {
        case 'C': /* alt config file */
            alt_config = optarg;
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

    if (!config_getswitch(IMAPOPT_PROMETHEUS_ENABLED)) {
        fatal("Prometheus metrics are not being tracked."
              "  Set prometheus_enable in imapd.conf",
              EC_CONFIG);
    }

    if (cleanup) {
        shut_down(do_cleanup());
    }

    /* fork unless we were given the -d option or we're running as a daemon */
    if (debugmode == 0 && !getenv("CYRUS_ISDAEMON")) {
        pid_t pid = fork();

        if (pid == -1) {
            fatal("fork failed", EC_OSERR);
        }

        if (pid != 0) { /* parent */
            exit(0);
        }
    }

    if (frequency <= 0) frequency = config_getint(IMAPOPT_PROMETHEUS_UPDATE_FREQ);
    if (frequency <= 0) frequency = 10;

    report_fname = strconcat(prometheus_stats_dir(), FNAME_PROM_REPORT, NULL);
    syslog(LOG_DEBUG, "updating %s every %d seconds", report_fname, frequency);

    unlink(report_fname);
    r = mappedfile_open(&report_file, report_fname, MAPPEDFILE_CREATE | MAPPEDFILE_RW);
    free(report_fname);
    if (r) fatal("couldn't open report file", EC_IOERR);

    for (;;) {
        signals_poll();

        /* check for shutdown file */
        if (shutdown_file(NULL, 0)) {
            if (verbose || debugmode)
                syslog(LOG_DEBUG, "Detected shutdown file\n");
            shut_down(0);
        }

        do_collate_report(&report_buf);
        do_collate_usage(&report_buf);
        do_write_report(report_file, &report_buf);

        /* then wait around a bit */
        sleep(frequency); /* XXX substract elapsed time? */
    }

    /* NOTREACHED */
    shut_down(EC_SOFTWARE);
}
