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

#include "lib/exitcodes.h"
#include "lib/retry.h"
#include "lib/util.h"

#include "imap/global.h"
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

typedef int promdir_foreach_cb(const struct prom_stats *stats, void *rock);
static int promdir_foreach(promdir_foreach_cb *proc, void *rock)
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

        /* skip filenames that aren't pids */
        if (!cyrus_isdigit(dirent->d_name[0])) continue;

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

static int read_into_array(const struct prom_stats *stats, void *rock)
{
    ptrarray_t *p = (ptrarray_t *) rock;

    struct prom_stats *stats_copy = xmalloc(sizeof *stats_copy);
    memcpy(stats_copy, stats, sizeof(*stats_copy));
    ptrarray_append(p, stats_copy);

    return 0;
}

static void do_collate_report(struct buf *buf)
{
    ptrarray_t proc_stats = PTRARRAY_INITIALIZER;
    struct prom_stats doneprocs_stats = PROM_STATS_INITIALIZER;
    char *doneprocs_fname;
    struct mappedfile *doneprocs_mf = NULL;
    int i, j;

    buf_reset(buf);

    /* load up accumulated stats of former processes.  hold this lock until
     * we've read all the stats files, so we don't double count if a process
     * exits while we're counting */
    doneprocs_fname = strconcat(prometheus_stats_dir(), FNAME_PROM_DONEPROCS, NULL);
    mappedfile_open(&doneprocs_mf, doneprocs_fname, MAPPEDFILE_CREATE);
    free(doneprocs_fname);
    if (doneprocs_mf && 0 == mappedfile_readlock(doneprocs_mf)) {
        memcpy(&doneprocs_stats, mappedfile_base(doneprocs_mf), mappedfile_size(doneprocs_mf));
        read_into_array(&doneprocs_stats, &proc_stats);
    }

    /* slurp up current stats */
    promdir_foreach(&read_into_array, &proc_stats);
    syslog(LOG_DEBUG, "updating prometheus report for %d processes", proc_stats.count);

    /* release the doneprocs lock */
    if (doneprocs_mf) {
        mappedfile_unlock(doneprocs_mf);
        mappedfile_close(&doneprocs_mf);
    }

    /* format it into buf */
    for (j = 0; j < PROM_NUM_METRICS; j++) {
        double sum = 0.0;
        int64_t last_updated = 0;

        if (prom_metric_descs[j].help) {
            buf_printf(buf, "# HELP %s %s\n", prom_metric_descs[j].name,
                            prom_metric_descs[j].help);
        }
        if (prom_metric_descs[j].type != PROM_METRIC_CONTINUED) {
            buf_printf(buf, "# TYPE %s %s\n", prom_metric_descs[j].name,
                            prom_metric_type_names[prom_metric_descs[j].type]);
        }

        /* prevent zero timestamp when we don't have any real stats yet */
        if (proc_stats.count == 0) last_updated = now_ms();

        for (i = 0; i < proc_stats.count; i++) {
            const struct prom_stats *p = ptrarray_nth(&proc_stats, i);
            sum += p->metrics[j].value;
            last_updated = MAX(last_updated, p->metrics[j].last_updated);
        }

        buf_appendcstr(buf, prom_metric_descs[j].name);
        if (prom_metric_descs[j].label)
            buf_printf(buf, "{%s}", prom_metric_descs[j].label);
        buf_printf(buf, " %.0f %" PRId64 "\n", sum, last_updated);
    }

    /* clean up the copy */
    void *p;
    while ((p = ptrarray_shift(&proc_stats))) {
        free(p);
    }
    ptrarray_fini(&proc_stats);
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
        do_write_report(report_file, &report_buf);

        /* then wait around a bit */
        sleep(frequency); /* XXX substract elapsed time? */
    }

    /* NOTREACHED */
    shut_down(EC_SOFTWARE);
}
