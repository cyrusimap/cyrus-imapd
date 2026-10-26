/* core_seterror.c - sasl_seterror implementation */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>

#include "libsasl_min/core_saslint.h"

#include "libsasl_min/sasl.h"
#include "libsasl_min/saslutil.h"
#include "libsasl_min/saslplug.h"

#include "lib/buf.h"

#include <errno.h>
#include <stdarg.h>

EXPORTED void sasl_seterror(sasl_conn_t *conn,
                            unsigned flags,
                            const char *fmt,
                            ...)
{
    sasl_log_t *log_cb = NULL;
    void *log_ctx = NULL;
    struct buf err = BUF_INITIALIZER;
    va_list args;
    const int saved_errno = errno;

    if (!(flags & SASL_NOLOG)) {
        /* look up logging callback. conn may be NULL here */
        _sasl_getcallback(conn,
                          SASL_CB_LOG,
                          (sasl_callback_ft *) &log_cb,
                          &log_ctx);
    }

    if (!conn) {
        /* cyrus-sasl logs this situation, so we will too */
        if (log_cb) {
            log_cb(log_ctx, SASL_LOG_FAIL,
                   "No sasl_conn_t passed to sasl_seterror");
        }
        return;
    }

    if (!fmt) {
        return;
    }

    va_start(args, fmt);
    errno = saved_errno; /* make sure %m is caller's errno, not one of ours! */
    buf_vprintf(&err, fmt, args);
    va_end(args);

    conn->error_buf_len = buf_len(&err);
    conn->error_buf = buf_release(&err);

    if (log_cb) {
        log_cb(log_ctx, SASL_LOG_FAIL, conn->error_buf);
    }
}
