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
#include <unistd.h>

#include "lib/assert.h"
#include "lib/cyr_lock.h"
#include "lib/exitcodes.h"
#include "lib/libconfig.h"
#include "lib/map.h"
#include "lib/ptrarray.h"
#include "lib/util.h"

#include "imap/prometheus.h"

#define FNAME_PROM_STATS_DIR "/stats"

static const char *prometheus_stats_dir(void)
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

EXPORTED struct prometheus_handle *prometheus_register(void)
{
    char fname[PATH_MAX];
    struct prometheus_handle *handle = NULL;
    struct prom_stats buf = PROM_STATS_INITIALIZER;
    int r;

    buf.pid = getpid();

    r = snprintf(fname, sizeof(fname), "%s%jd",
                 prometheus_stats_dir(), (intmax_t) buf.pid);
    if (r < 0 || (size_t) r >= sizeof(fname))
        fatal("unable to register stats for prometheus", EC_CONFIG);

    r = cyrus_mkdir(fname, 0755);
    if (r) return NULL;

    handle = xzmalloc(sizeof(*handle));
    r = mappedfile_open(&handle->mf, fname, MAPPEDFILE_CREATE | MAPPEDFILE_RW);
    if (r) goto error;

    r = mappedfile_writelock(handle->mf);
    if (r) goto error;

    r = mappedfile_pwrite(handle->mf, &buf, sizeof(buf), 0);
    if (r != sizeof(buf)) {
        syslog(LOG_ERR, "IOERROR: mappedfile_pwrite: expected to write " SIZE_T_FMT "bytes, "
                        "actually wrote %d",
                        sizeof(buf), r);
        goto error;
    }

    r = mappedfile_commit(handle->mf);
    if (r) goto error;

    r = mappedfile_unlock(handle->mf);
    if (r) goto error;

    return handle;

error:
    if (handle) {
        if (handle->mf) {
            mappedfile_unlock(handle->mf);
            mappedfile_close(&handle->mf);
        }
        free(handle);
    }
    return NULL;
}

EXPORTED void prometheus_unregister(struct prometheus_handle **handlep)
{
    struct prometheus_handle *handle = *handlep;

    *handlep = NULL;

    if (!handle) return; /* make double-call safe */

    mappedfile_writelock(handle->mf);
//    unlink(mappedfile_fname(handle->mf)); /* XXX ? */
    mappedfile_unlock(handle->mf);
    mappedfile_close(&handle->mf);

    free(handle);
}

/* do not call this directly! use the prometheus_increment() and
 * prometheus_decrement() wrapper macros.
 */
EXPORTED void prometheus_adjust_at_offset(struct prometheus_handle *handle,
                                          size_t offset, double delta)
{
    int r;

    if (!handle) return;

    assert(offset < sizeof(struct prom_stats));

    r = mappedfile_writelock(handle->mf);
    if (r) {
        syslog(LOG_ERR, "IOERROR: mappedfile_writelock unable to obtain lock on %s",
                        mappedfile_fname(handle->mf));
        return;
    }

    double v = *(double *)(mappedfile_base(handle->mf) + offset);
    v += delta;

    r = mappedfile_pwrite(handle->mf, &v, sizeof(v), offset);
    if (r != sizeof(v)) {
        syslog(LOG_ERR, "IOERROR: mappedfile_pwrite: expected to write "
                        SIZE_T_FMT " bytes, actually wrote %d",
                        sizeof(v), r);
    }
    else {
        mappedfile_commit(handle->mf);
    }

    mappedfile_unlock(handle->mf);
}


/* n.b. This function -CANNOT- use mappedfile because doing so would clash
 * with the caller's own statistics collection.
 */
typedef int prometheus_foreach_cb(const struct prom_stats *stats, void *rock);
static int prometheus_foreach(prometheus_foreach_cb *proc, void *rock)
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
        char path[PATH_MAX];
        struct prom_stats stats;
        const char *base = NULL;
        size_t len = 0;
        int fd;

        /* skip filenames that aren't pids */
        if (!cyrus_isdigit(dirent->d_name[0])) continue;

        r = snprintf(path, sizeof(path), "%s%s", basedir, dirent->d_name);
        if (r < 0 || (size_t) r >= sizeof(path))
            fatal("cannot iterate prometheus stats directory", EC_CONFIG);

        fd = open(path, O_RDONLY);
        if (fd < 0) continue;

        r = lock_shared(fd, path);
        if (r) continue;

        /* grab a copy so we can unlock/close the file */
        map_refresh(fd, /*onceonly*/ 1,
                    &base, &len, sizeof(stats),
                    path, NULL);
        assert(len == sizeof(stats));
        memcpy(&stats, base, sizeof(stats));
        map_free(&base, &len);

        lock_unlock(fd, path);
        close(fd);

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

EXPORTED int prometheus_text_report(struct buf *buf, const char **mimetype)
{
    ptrarray_t proc_stats = PTRARRAY_INITIALIZER;
    double accumulator;
    int i;

    if (mimetype)
        *mimetype = "text/plain; version=0.0.4";

    buf_reset(buf);

    /* slurp up current stats */
    prometheus_foreach(&read_into_array, &proc_stats);

    /* format it into buf */
    buf_appendcstr(buf, "# HELP imap_connections_total The total number of IMAP connections.\n");
    buf_appendcstr(buf, "# TYPE imap_connections_total counter\n");
    for (i = 0, accumulator = 0.0; i < proc_stats.count; i++) {
        struct prom_stats *p = ptrarray_nth(&proc_stats, i);
        buf_printf(buf, "imap_connections_total{pid=\"%jd\"} %.0f\n",
                   (intmax_t) p->pid, p->total_connections);
        accumulator += p->total_connections;
    }
    buf_printf(buf, "imap_connections_total %.0f\n", accumulator);

    buf_appendcstr(buf, "# HELP imap_connections_active The number of active IMAP connections.\n");
    buf_appendcstr(buf, "# TYPE imap_connections_active gauge\n");
    for (i = 0, accumulator = 0.0; i < proc_stats.count; i++) {
        struct prom_stats *p = ptrarray_nth(&proc_stats, i);
        buf_printf(buf, "imap_connections_active{pid=\"%jd\"} %.0f\n",
                   (intmax_t) p->pid, p->active_connections);
        accumulator += p->active_connections;
    }
    buf_printf(buf, "imap_connections_active %.0f\n", accumulator);

    void *p;
    while ((p = ptrarray_shift(&proc_stats))) {
        free(p);
    }
    ptrarray_fini(&proc_stats);
    return 0;
}
