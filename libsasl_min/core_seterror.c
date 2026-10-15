/* core_seterror.c - sasl_seterror implementation */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>

#include "libsasl_min/core_saslint.h"

#include "libsasl_min/sasl.h"
#include "libsasl_min/saslutil.h"
#include "libsasl_min/saslplug.h"

#include <stdio.h>
#include <string.h>

/* this is apparently no longer a user function */
static int _sasl_seterror_usererr(int saslerr)
{
    /* Hide the difference in a username failure and a password failure */
    if (saslerr == SASL_NOUSER) {
        return SASL_BADAUTH;
    }

    /* otherwise return the error given; no transform necessary */
    return saslerr;
}

/* set the error string which will be returned by sasl_errdetail() using
 *  syslog()-style formatting (e.g. printf-style with %m as the string form
 *  of an errno error)
 *
 *  primarily for use by server callbacks such as the sasl_authorize_t
 *  callback and internally to plug-ins
 *
 * This will also trigger a call to the SASL logging callback (if any)
 * with a level of SASL_LOG_FAIL unless the SASL_NOLOG flag is set.
 *
 * Messages should be sensitive to the current language setting.  If there
 * is no SASL_CB_LANGUAGE callback messages MUST be US-ASCII otherwise UTF-8
 * is used and use of RFC 2482 for mixed-language text is encouraged.
 *
 * if conn is NULL, function does nothing
 */
EXPORTED void sasl_seterror(sasl_conn_t *conn,
                            unsigned flags,
                            const char *fmt,
                            ...)
{
    size_t outlen = 0; /* current length of output buffer */
    size_t pos = 0;    /* current position in format string */
    size_t formatlen;
    int result;
    sasl_log_t *log_cb = NULL;
    void *log_ctx;
    int ival;
    char *cval;
    va_list ap; /* varargs thing */
    char **error_buf;
    size_t *error_buf_len;

    if (!conn) {
#ifndef SASL_OSX_CFMGLUE
        if (!(flags & SASL_NOLOG)) {
            /* See if we have a logging callback... */
            result = _sasl_getcallback(NULL,
                                       SASL_CB_LOG,
                                       (sasl_callback_ft *) &log_cb,
                                       &log_ctx);
            if (result == SASL_OK && !log_cb) {
                result = SASL_FAIL;
            }
            if (result != SASL_OK) {
                return;
            }

            log_cb(log_ctx,
                   SASL_LOG_FAIL,
                   "No sasl_conn_t passed to sasl_seterror");
        }
#endif /* SASL_OSX_CFMGLUE */
        return;
    }
    else if (!fmt) {
        return;
    }

    /* we need to use a back end function to get the buffer because the
       cfm glue can't be rooting around in the internal structs */
    _sasl_get_errorbuf(conn, &error_buf, &error_buf_len);

    formatlen = strlen(fmt);

    va_start(ap, fmt); /* start varargs */

    while (pos < formatlen) {
        if (fmt[pos] != '%') /* regular character */ {
            result = _buf_alloc(error_buf, error_buf_len, outlen + 1);
            if (result != SASL_OK) {
                goto done;
            }
            (*error_buf)[outlen] = fmt[pos];
            outlen++;
            pos++;
        }
        else { /* formating thing */
            int done = 0;
            char frmt[10];
            int frmtpos = 1;
            char tempbuf[21];
            frmt[0] = '%';
            pos++;

            while (done == 0) {
                switch (fmt[pos]) {
                case 's':                      /* need to handle this */
                    cval = va_arg(ap, char *); /* get the next arg */
                    result = _sasl_add_string(error_buf,
                                              error_buf_len,
                                              &outlen,
                                              cval);

                    if (result != SASL_OK) /* add the string */ {
                        goto done;
                    }

                    done = 1;
                    break;

                case '%': /* double % output the '%' character */
                    result = _buf_alloc(error_buf, error_buf_len, outlen + 1);
                    if (result != SASL_OK) {
                        goto done;
                    }
                    (*error_buf)[outlen] = '%';
                    outlen++;
                    done = 1;
                    break;

                case 'm': /* insert the errno string */
                    result = _sasl_add_string(error_buf,
                                              error_buf_len,
                                              &outlen,
                                              strerror(va_arg(ap, int)));
                    if (result != SASL_OK) {
                        goto done;
                    }
                    done = 1;
                    break;

                case 'z': /* insert the sasl error string */
                    result = _sasl_add_string(
                        error_buf,
                        error_buf_len,
                        &outlen,
                        (char *) sasl_errstring(
                            _sasl_seterror_usererr(va_arg(ap, int)),
                            NULL,
                            NULL));
                    if (result != SASL_OK) {
                        goto done;
                    }
                    done = 1;
                    break;

                case 'c':
                    frmt[frmtpos++] = fmt[pos];
                    frmt[frmtpos] = 0;
                    tempbuf[0] = (char) va_arg(ap, int); /* get the next arg */
                    tempbuf[1] = '\0';

                    /* now add the character */
                    result = _sasl_add_string(error_buf,
                                              error_buf_len,
                                              &outlen,
                                              tempbuf);
                    if (result != SASL_OK) {
                        goto done;
                    }
                    done = 1;
                    break;

                case 'd':
                case 'i':
                    frmt[frmtpos++] = fmt[pos];
                    frmt[frmtpos] = 0;
                    ival = va_arg(ap, int); /* get the next arg */

                    snprintf(tempbuf,
                             20,
                             frmt,
                             ival); /* have snprintf do the work */
                    /* now add the string */
                    result = _sasl_add_string(error_buf,
                                              error_buf_len,
                                              &outlen,
                                              tempbuf);
                    if (result != SASL_OK) {
                        goto done;
                    }
                    done = 1;

                    break;
                default:
                    frmt[frmtpos++] = fmt[pos]; /* add to the formating */
                    frmt[frmtpos] = 0;
                    if (frmtpos > 9) {
                        done = 1;
                    }
                }
                pos++;
                if (pos > formatlen) {
                    done = 1;
                }
            }
        }
    }

    (*error_buf)[outlen] = '\0'; /* put 0 at end */

#ifndef SASL_OSX_CFMGLUE
    if (!(flags & SASL_NOLOG)) {
        /* See if we have a logging callback... */
        result = _sasl_getcallback(conn,
                                   SASL_CB_LOG,
                                   (sasl_callback_ft *) &log_cb,
                                   &log_ctx);
        if (result == SASL_OK && !log_cb) {
            result = SASL_FAIL;
        }
        if (result != SASL_OK) {
            goto done;
        }

        result = log_cb(log_ctx, SASL_LOG_FAIL, conn->error_buf);
    }
#endif /* SASL_OSX_CFMGLUE */
done:
    va_end(ap);
}
