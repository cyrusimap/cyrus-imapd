/* prometheus.c -- Aggregate statistics for prometheus
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
#include <string.h>
#include <sysexits.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "lib/assert.h"
#include "lib/cyr_lock.h"
#include "lib/libconfig.h"
#include "lib/map.h"
#include "lib/ptrarray.h"
#include "lib/util.h"
#include "lib/xunlink.h"

#include "imap/global.h"
#include "imap/imap_err.h"
#include "imap/prometheus.h"

struct prometheus_handle {
    struct mappedfile *mf;
};

static struct prometheus_handle *promhandle = NULL;
static int prometheus_enabled = -1;

static void prometheus_init(void);
static void prometheus_done(void *rock __attribute__((unused)));

EXPORTED const char *prometheus_stats_dir(void)
{
    static struct buf statsdir = BUF_INITIALIZER;
    const char *tmp;

    if (buf_len(&statsdir) > 0) return buf_cstring(&statsdir);

    if ((tmp = config_getstring(IMAPOPT_PROMETHEUS_STATS_DIR))) {
        if (tmp[0] != '/')
            fatal("prometheus_stats_dir must be fully qualified", EX_CONFIG);

        if (strlen(tmp) < 2)
            fatal("prometheus_stats_dir must not be '/'", EX_CONFIG);

        buf_setcstr(&statsdir, tmp);

        if (statsdir.s[statsdir.len-1] != '/')
            buf_putc(&statsdir, '/');
    }
    else {
        buf_setcstr(&statsdir, config_dir);
        buf_appendcstr(&statsdir, FNAME_PROM_STATS_DIR);
        buf_putc(&statsdir, '/');
    }

    return buf_cstring(&statsdir);
}

static void prometheus_init(void)
{
    char fname[PATH_MAX];
    struct prometheus_handle *handle = NULL;
    struct prom_stats stats = PROM_STATS_INITIALIZER;
    int r;

    if (promhandle != NULL) return;

    prometheus_enabled = config_getswitch(IMAPOPT_PROMETHEUS_ENABLED);
    if (!prometheus_enabled) return;

    r = snprintf(stats.ident, sizeof(stats.ident), "%s", config_ident);
    if (r < 0 || (size_t) r >= sizeof(stats.ident))
        syslog(LOG_WARNING, "service name '%s' is longer than " SIZE_T_FMT
                            " characters - prometheus label will be truncated",
                            config_ident,
                            sizeof(stats.ident) - 1);

    r = snprintf(fname, sizeof(fname), "%s%jd",
                 prometheus_stats_dir(), (intmax_t) getpid());
    if (r < 0 || (size_t) r >= sizeof(fname))
        fatal("unable to register stats for prometheus", EX_CONFIG);

    r = cyrus_mkdir(fname, 0755);
    if (r) goto error;;

    handle = xzmalloc(sizeof(*handle));
    r = mappedfile_open(&handle->mf, fname, MAPPEDFILE_CREATE | MAPPEDFILE_RW);
    if (r) goto error;

    r = mappedfile_writelock(handle->mf);
    if (r) goto error;

    r = mappedfile_pwrite(handle->mf, &stats, sizeof(stats), 0);
    if (r != sizeof(stats)) {
        syslog(LOG_ERR, "IOERROR: mappedfile_pwrite: expected to write " SIZE_T_FMT "bytes, "
                        "actually wrote %d",
                        sizeof(stats), r);
        goto error;
    }

    r = mappedfile_commit(handle->mf);
    if (r) goto error;

    r = mappedfile_unlock(handle->mf);
    if (r) goto error;

    promhandle = handle;
    cyrus_modules_add(&prometheus_done, NULL);
    return;

error:
    if (handle) {
        if (handle->mf) {
            mappedfile_unlock(handle->mf);
            mappedfile_close(&handle->mf);
        }
        free(handle);
    }
    promhandle = NULL;
    prometheus_enabled = 0;
}

static void prometheus_done(void *rock __attribute__((unused)))
{
    struct prom_stats accum = PROM_STATS_INITIALIZER;
    struct prom_stats thisproc = PROM_STATS_INITIALIZER;
    struct mappedfile *doneprocs = NULL;
    char *doneprocs_fname = NULL;
    char *doneprocs_lock_fname;
    int doneprocs_lock_fd;
    int i, r = 0;
    int unlinked = 0;

    if (!promhandle) return; /* make double-call safe */

    /* hold a lock on .doneprocs.lock - this keeps promstatsd from double
     * counting while we're juggling files */
    doneprocs_lock_fname = strconcat(prometheus_stats_dir(), ".",
                                     FNAME_PROM_DONEPROCS, ".lock", NULL);

    doneprocs_lock_fd = open(doneprocs_lock_fname, O_CREAT|O_TRUNC|O_RDWR, 0644);
    if (doneprocs_lock_fd == -1) {
        syslog(LOG_ERR, "can't open doneprocs lock: %s (%m)", doneprocs_lock_fname);
        goto done;
    }
    if (lock_setlock(doneprocs_lock_fd, /*ex*/1, /*nb*/0, doneprocs_lock_fname)) {
        syslog(LOG_ERR, "can't get exclusive lock on %s", doneprocs_lock_fname);
        close(doneprocs_lock_fd);
        doneprocs_lock_fd = -1;
        goto done;
    }

    /* load existing doneprocs stats */
    doneprocs_fname = strconcat(prometheus_stats_dir(), FNAME_PROM_DONEPROCS,
                                ".", config_ident, NULL);
    r = mappedfile_open(&doneprocs, doneprocs_fname, MAPPEDFILE_CREATE | MAPPEDFILE_RW);
    if (r) {
        syslog(LOG_ERR, "IOERROR: mappedfile_open(%s): %s",
                        doneprocs_fname, error_message(r));
        goto done;
    }

    r = mappedfile_writelock(doneprocs);
    if (r) goto done;

    if (mappedfile_size(doneprocs)) {
        memcpy(&accum, mappedfile_base(doneprocs), mappedfile_size(doneprocs));
    }
    if (accum.ident[0] == '\0') {
        snprintf(accum.ident, sizeof(accum.ident), "%s", config_ident);
    }

    /* read stats from this process */
    r = mappedfile_readlock(promhandle->mf);
    if (r) {
        syslog(LOG_ERR, "IOERROR: mappedfile_open(%s): %s",
                        doneprocs_fname, error_message(r));
        goto done;
    }
    memcpy(&thisproc, mappedfile_base(promhandle->mf), mappedfile_size(promhandle->mf));
    mappedfile_unlock(promhandle->mf);

    /* unlink per-process stats file, we don't need it anymore */
    if (xunlink(mappedfile_fname(promhandle->mf)) == -1)
        goto done;
    unlinked = 1;

    /* accumulate the statistics */
    for (i = 0; i < PROM_NUM_METRICS; i++) {
        accum.metrics[i].value += thisproc.metrics[i].value;
        accum.metrics[i].last_updated = MAX(accum.metrics[i].last_updated,
                                            thisproc.metrics[i].last_updated);
    }

    /* and write it out */
    r = mappedfile_pwrite(doneprocs, &accum, sizeof(accum), 0);
    if (r != sizeof(accum)) {
        syslog(LOG_ERR, "IOERROR: mappedfile_pwrite: expected to write " SIZE_T_FMT "bytes, "
                        "actually wrote %d",
                        sizeof(accum), r);
        goto done;
    }

    mappedfile_commit(doneprocs);

done:
    free(doneprocs_fname);

    if (!unlinked) {
        syslog(LOG_NOTICE, "per-process prometheus statistics file not removed");
    }
    mappedfile_close(&promhandle->mf);

    free(promhandle);
    promhandle = NULL;

    mappedfile_unlock(doneprocs);
    mappedfile_close(&doneprocs);

    /* release .doneprocs.lock */
    if (doneprocs_lock_fd != -1) {
        xunlink(doneprocs_lock_fname);
        lock_unlock(doneprocs_lock_fd, doneprocs_lock_fname);
        close(doneprocs_lock_fd);
    }
    free(doneprocs_lock_fname);
}

/* use the prometheus_increment() and prometheus_decrement() wrapper macros
 * for readability if that's all you're doing.
 */
EXPORTED void prometheus_apply_delta(enum prom_metric_id metric_id,
                                     double delta)
{
    struct prom_metric metric;
    size_t offset;
    int r;

    if (!prometheus_enabled) return;

    if (!promhandle) prometheus_init();

    if (!prometheus_enabled) return;

    assert(metric_id >= 0 && metric_id < PROM_NUM_METRICS);

    r = mappedfile_writelock(promhandle->mf);
    if (r) {
        syslog(LOG_ERR, "IOERROR: mappedfile_writelock unable to obtain lock on %s",
                        mappedfile_fname(promhandle->mf));
        return;
    }

    offset = offsetof(struct prom_stats, metrics) + metric_id * sizeof(metric);
    memcpy(&metric, mappedfile_base(promhandle->mf) + offset, sizeof(metric));
    if (delta < 0) {
        /* counters must not be decremented */
        assert(prom_metric_descs[metric_id].type != PROM_METRIC_COUNTER);
    }
    metric.value = metric.value + delta;
    metric.last_updated = now_ms();

    r = mappedfile_pwrite(promhandle->mf, &metric, sizeof(metric), offset);
    if (r != sizeof(metric)) {
        syslog(LOG_ERR, "IOERROR: mappedfile_pwrite: expected to write "
                        SIZE_T_FMT " bytes, actually wrote %d",
                        sizeof(metric), r);
    }
    else {
        mappedfile_commit(promhandle->mf);
    }

    mappedfile_unlock(promhandle->mf);
}

EXPORTED int prometheus_text_report(struct buf *buf, const char **mimetype)
{
    const struct {
        int required;
        const char *fname;
    } reports[] = {
        { 1, FNAME_PROM_SERVICE_REPORT },
        { 0, FNAME_PROM_USAGE_REPORT   },
        { 0, FNAME_PROM_MASTER_REPORT  },
    };
    const size_t n_reports = sizeof(reports) / sizeof(reports[0]);
    unsigned i;
    int r = 0;

    if (!prometheus_enabled) return IMAP_INTERNAL;

    buf_reset(buf);

    for (i = 0; i < n_reports; i++) {
        char *report_fname = NULL;
        struct mappedfile *mf = NULL;

        report_fname = strconcat(prometheus_stats_dir(),
                                 reports[i].fname,
                                 NULL);

        r = mappedfile_open(&mf, report_fname, 0);
        if (r && reports[i].required) {
            free(report_fname);
            return r;
        }

        r = mappedfile_readlock(mf);
        if (!r) {
            buf_appendmap(buf, mappedfile_base(mf), mappedfile_size(mf));
        }

        mappedfile_unlock(mf);
        mappedfile_close(&mf);
        free(report_fname);
    }

    if (!r && mimetype)
        *mimetype = "text/plain; version=0.0.4";

    return r;
}

EXPORTED enum prom_metric_id prometheus_lookup_label(enum prom_labelled_metric metric,
                                                     const char *value)
{
    size_t i;

    assert(metric >= 0 && metric < PROM_NUM_LABELLED_METRICS);

    for (i = 0; prom_label_lookup_table[metric][i].value != NULL; i++) {
        const struct prom_label_lookup_value *v = &prom_label_lookup_table[metric][i];

        int cmp = strcmp(v->value, value);
        if (cmp == 0) /* found it */
            return v->id;
        if (cmp > 0) /* gone too far, not found */
            break;
    }

    fatal("invalid metric value -- compile time bug", EX_SOFTWARE);
}
