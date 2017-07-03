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

#include <unistd.h>

#include "lib/assert.h"
#include "lib/exitcodes.h"
#include "lib/libconfig.h"
#include "lib/util.h"

#include "imap/prometheus.h"

EXPORTED struct prometheus_handle *prometheus_register(void)
{
    char fname[PATH_MAX];
    struct prometheus_handle *handle = NULL;
    struct prom_stats buf = PROM_STATS_INITIALIZER;
    int r;

    buf.pid = getpid();

    r = snprintf(fname, sizeof(fname), "%s/stats/%jd", config_dir, (intmax_t) buf.pid);
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
    if (r) goto error;

    r = mappedfile_commit(handle->mf);
    if (r) goto error;

    r = mappedfile_unlock(handle->mf);
    if (r) goto error;

    return handle;

error:
    if (handle) free(handle);
    return NULL;
}

EXPORTED void prometheus_unregister(struct prometheus_handle **handlep)
{
    struct prometheus_handle *handle = *handlep;

    *handlep = NULL;

    if (!handle) return; /* make double-call safe */

    mappedfile_writelock(handle->mf);
    unlink(mappedfile_fname(handle->mf));
    mappedfile_unlock(handle->mf);
    mappedfile_close(&handle->mf);

    free(handle);
}

/* do not call this directly! use the prometheus_increment() and
 * prometheus_decrement() wrapper macros.
 */
EXPORTED int prometheus_adjust_at_offset(struct prometheus_handle *handle,
                                         size_t offset, double delta)
{
    int r;

    if (!handle) return 0;

    assert(offset < sizeof(struct prom_stats));

    r = mappedfile_writelock(handle->mf);
    if (r) return r;

    double v = *(double *)(mappedfile_base(handle->mf) + offset);
    v += delta;

    r = mappedfile_pwrite(handle->mf, &v, sizeof(v), offset);
    if (r) return r;

    r = mappedfile_commit(handle->mf);
    if (r) return r;

    r = mappedfile_unlock(handle->mf);
    if (r) return r;

    return 0;
}

EXPORTED int prometheus_text_report(struct buf *buf, const char **mimetype)
{
    if (mimetype)
        *mimetype = "text/plain; version=0.0.4";

    /* FIXME produce the report into buf */
    buf_reset(buf);

    return 0;
}
