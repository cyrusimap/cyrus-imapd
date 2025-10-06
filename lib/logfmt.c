/* logfmt - formatted logging API
 *
 * Copyright (c) 1994-2025 Carnegie Mellon University.  All rights reserved.
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

#include "lib/assert.h"
#include "lib/logfmt.h"
#include "lib/sessionid.h"

#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

/* visible for testing; probably don't call this directly */
EXPORTED void logfmt_escape(struct buf *buf, const char *val)
{
    bool need_dquotes = false;
    const unsigned char *p;

    if (val == NULL) {
        buf_setcstr(buf, "~null~");
        return;
    }

    if (!val[0]) {
        buf_setcstr(buf, "\"\"");
        return;
    }

    /* event = pair *(WSP pair)
     * pair  = key "=" value
     * okchr = %x21 / %x23-3c / %x3e-5b / %x5d-7e ; graphic ASCII, less: \ " = DEL
     * key   = 1*(okchr)
     * value = key / quoted
     *
     * quoted = DQUOTE *( escaped / quoted-ok / okchr / eightbit ) DQUOTE
     * escaped         = escaped-special / escaped-hex
     * escaped-special = "\\" / "\n" / "\r" / "\t" / ("\" DQUOTE)
     * escaped-hex     = "\x{" 2HEXDIG "}" ; lowercase forms okay also
     * quoted-ok       = SP / "="
     * eightbit        = %x80-ff
     */

    /* partial first pass to see whether we'll need to quote */
    for (p = (const unsigned char *) val; *p && !need_dquotes; p++) {
        switch (*p) {
        case 0x21:
        case 0x23 ... 0x3C:
        case 0x3E ... 0x5B:
        case 0X5D ... 0x7E:
            /* okchr doesn't need quotes */
            break;
        default:
            /* but anything else does */
            need_dquotes = true;
            break;
        }
    }

    /* build escaped string forward */
    buf_reset(buf);
    buf_ensure(buf, strlen(val) + 2 * need_dquotes);
    if (need_dquotes) buf_putc(buf, '\"');

    for (p = (const unsigned char *) val; *p; p++) {
        switch (*p) {
        /* okchr and quoted-ok */
        case ' ': /* 0x20 */
        case 0x21:
        case 0x23 ... 0x3C:
        case '=': /* 0x3D */
        case 0x3E ... 0x5B:
        case 0X5D ... 0x7E:
            buf_putc(buf, *p);
            break;

        /* escaped-special */
        case '\t': /* 0x09 */
            buf_appendmap(buf, "\\t", 2);
            break;
        case '\n': /* 0x0A */
            buf_appendmap(buf, "\\n", 2);
            break;
        case '\r': /* 0x0D */
            buf_appendmap(buf, "\\r", 2);
            break;
        case '\"': /* 0x22 */
            buf_appendmap(buf, "\\\"", 2);
            break;
        case '\\': /* 0x5C */
            buf_appendmap(buf, "\\\\", 2);
            break;

        /* escaped-hex */
        case 0x00 ... 0x08:
        case 0x0B ... 0x0C:
        case 0x0E ... 0x1F:
        case 0x7F:
            buf_printf(buf, "\\x{%2.2x}", *p);
            break;

        /* eightbit */
        case 0x80 ... 0xFF:
            /* XXX unicode will require different behaviour here... */
            buf_printf(buf, "\\x{%2.2x}", *p);
            break;

        default:
            /* every case should be covered above! if we've missed any,
             * test_logfmt_escape2 in logfmt.testc will trip this
             */
            abort();
        }
    }

    if (need_dquotes) buf_putc(buf, '\"');
}

EXPORTED void logfmt_init(struct logfmt *lf, const char *event)
{
    buf_reset(&lf->msg);
    buf_reset(&lf->scratch);
    logfmt_push(lf, "event", event);
}

EXPORTED void logfmt_fini(struct logfmt *lf)
{
    buf_free(&lf->msg);
    buf_free(&lf->scratch);
}

EXPORTED const char *logfmt_cstring(const struct logfmt *lf)
{
    return buf_cstring(&lf->msg);
}

EXPORTED void logfmt_push(struct logfmt *lf,
                          const char *key,
                          const char *value)
{
    assert(key && *key);

    if (buf_len(&lf->msg))
        buf_putc(&lf->msg, ' ');

    logfmt_escape(&lf->scratch, value);
    buf_printf(&lf->msg, "%s=%s", key, buf_cstring(&lf->scratch));
    buf_reset(&lf->scratch);
}

EXPORTED void logfmt_pushf(struct logfmt *lf, const char *key,
                           const char *valuefmt, ...)
{
    struct buf formatted = BUF_INITIALIZER;
    va_list args;

    va_start(args, valuefmt);
    buf_vprintf(&formatted, valuefmt, args);
    va_end(args);

    logfmt_push(lf, key, buf_cstring(&formatted));

    buf_free(&formatted);
}

EXPORTED void logfmt_push_session(struct logfmt *lf)
{
    const char *traceid = trace_id();

    if (session_have_id()) {
        logfmt_push(lf, "sessionid", session_id());
    }

    if (traceid) {
        logfmt_push(lf, "r.tid", traceid);
    }
}
