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
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "lib/assert.h"
#include "lib/cyr_lock.h"
#include "lib/exitcodes.h"
#include "lib/libconfig.h"
#include "lib/map.h"
#include "lib/ptrarray.h"
#include "lib/util.h"

#include "imap/global.h"
#include "imap/prometheus.h"

struct prometheus_handle {
    struct mappedfile *mf;
};

static struct prometheus_handle *promhandle = NULL;

static void prometheus_init(void);
static void prometheus_done(void *rock __attribute__((unused)));

EXPORTED const char *prometheus_stats_dir(void)
{
    static struct buf statsdir = BUF_INITIALIZER;
    const char *tmp;

    if (buf_len(&statsdir) > 0) return buf_cstring(&statsdir);

    if ((tmp = config_getstring(IMAPOPT_PROMETHEUS_STATS_DIR))) {
        if (tmp[0] != '/')
            fatal("prometheus_stats_dir must be fully qualified", EC_CONFIG);

        if (strlen(tmp) < 2)
            fatal("prometheus_stats_dir must not be '/'", EC_CONFIG);

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

static int64_t now_ms(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_REALTIME, &ts) == 0) {
        return (ts.tv_sec * 1000) + (ts.tv_nsec / 1000000);
    }
    else {
        syslog(LOG_WARNING, "clock_gettime(): %m");
        return time(NULL) * 1000;
    }
}

static void prometheus_init(void)
{
    char fname[PATH_MAX];
    struct prometheus_handle *handle = NULL;
    struct prom_stats stats = PROM_STATS_INITIALIZER;
    int i;
    int r;

    if (promhandle != NULL) return;

    stats.pid = getpid();
    for (i = 0; i < PROM_NUM_METRICS; i++) {
        stats.metrics[i].last_updated = now_ms();
    }

    r = snprintf(fname, sizeof(fname), "%s%jd",
                 prometheus_stats_dir(), (intmax_t) stats.pid);
    if (r < 0 || (size_t) r >= sizeof(fname))
        fatal("unable to register stats for prometheus", EC_CONFIG);

    r = cyrus_mkdir(fname, 0755);
    if (r) return;

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
}

static void prometheus_done(void *rock __attribute__((unused)))
{
    if (!promhandle) return; /* make double-call safe */

    /* n.b. we do not unlink the file on unregister, as we still want
     * to be able to keep track of the terminated process's stats while
     * this session is active.
     */
    mappedfile_close(&promhandle->mf);

    free(promhandle);
    promhandle = NULL;
}

/* do not call this directly! use the prometheus_increment() and
 * prometheus_decrement() wrapper macros.
 */
EXPORTED void prometheus_change(enum prom_metric_id metric_id,
                                int delta)
{
    struct prom_metric metric;
    size_t offset;
    int r;

    if (!promhandle) prometheus_init();

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
    char *report_fname = NULL;
    struct mappedfile *mf = NULL;
    int r;

    report_fname = strconcat(prometheus_stats_dir(), FNAME_PROM_REPORT, NULL);

    r = mappedfile_open(&mf, report_fname, 0);
    if (r) {
        free(report_fname);
        return r;
    }

    r = mappedfile_readlock(mf);
    if (!r) {
        buf_setmap(buf, mappedfile_base(mf), mappedfile_size(mf));
        if (mimetype)
            *mimetype = "text/plain; version=0.0.4";
    }

    mappedfile_unlock(mf);
    mappedfile_close(&mf);
    free(report_fname);
    return r;
}
