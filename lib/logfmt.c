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

#include "unicode/uchar.h"
#include "unicode/utext.h"
#include "unicode/utf8.h"
#include "unicode/utypes.h"

#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

static bool val_needs_dquotes(const char *val)
{
    const unsigned char *p;

    for (p = (const unsigned char *) val; *p; p++) {
        switch (*p) {
        case 0x21:
        case 0x23 ... 0x3C:
        case 0x3E ... 0x5B:
        case 0X5D ... 0x7E:
            /* okchr doesn't need quotes */
            break;
        default:
            /* but anything else does */
            return true;
        }
    }

    return false;
}

/* visible for testing; probably don't call this directly */
EXPORTED void logfmt_escape_bytestring(struct buf *buf, const char *val)
{
    const unsigned char *p;
    bool need_dquotes;

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
    need_dquotes = val_needs_dquotes(val);

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

        /* escaped-hex, eightbit */
        case 0x00 ... 0x08:
        case 0x0B ... 0x0C:
        case 0x0E ... 0x1F:
        case 0x7F:
        case 0x80 ... 0xFF:
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

static inline bool is_utf8_escaped_hex(uint32_t cp)
{
    switch (cp) {
    case 0x000b: /* LINE TABULATION */
    case 0x000c: /* FORM FEED */
    case 0x0085: /* NEXT LINE */
    case 0x2028: /* LINE SEPARATOR */
    case 0x2029: /* PARAGRAPH SEPARATOR */
        return true;
    default:
        return u_iscntrl(cp);
    }
}

/* visible for testing; probably don't call this directly */
EXPORTED void logfmt_escape_utf8(struct buf *buf, const char *utf8val)
{
    UText ut = UTEXT_INITIALIZER; /* XXX cache between calls? */
    UErrorCode status = U_ZERO_ERROR;
    bool need_dquotes;
    uint32_t cp;

    if (utf8val == NULL) {
        buf_setcstr(buf, "~null~");
        return;
    }

    if (!utf8val[0]) {
        buf_setcstr(buf, "\"\"");
        return;
    }

    /* utext_openUTF8:
     * > Any invalid UTF-8 in the input will be handled in this way: a sequence
     * > of bytes that has the form of a truncated, but otherwise valid, UTF-8
     * > sequence will be replaced by a single unicode replacement character,
     * > \uFFFD. Any other illegal bytes will each be replaced by a \uFFFD.
     *
     * The "replacement character" \uFFFD is �.  This character doesn't need to
     * be escaped for logfmt, so we don't need (and can't have) explicit error
     * handling for invalid utf8.
     */
    utext_openUTF8(&ut, utf8val, -1, &status);
    if (U_FAILURE(status)) {
        /* it's not clear what circumstances this might error in, but fall back
         * to a bytestring escape anyway
         */
        syslog(LOG_DEBUG, "%s: utext_openUTF8() failed with status %s",
                          __func__, u_errorName(status));
        logfmt_escape_bytestring(buf, utf8val);
        return;
    }

    need_dquotes = val_needs_dquotes(utf8val);

    buf_reset(buf);
    buf_ensure(buf, strlen(utf8val) + 2 * need_dquotes);
    if (need_dquotes) buf_putc(buf, '"');

    while ((uint32_t) U_SENTINEL != (cp = utext_next32(&ut))) {
        uint8_t scratch[8] = {0};
        int32_t i, len = 0;
        UBool is_error = false;

        /* escaped-special */
        switch (cp) {
        case '\\':
            buf_appendmap(buf, "\\\\", 2);
            continue;
        case '"':
            buf_appendmap(buf, "\\\"", 2);
            continue;
        case '\n':
            buf_appendmap(buf, "\\n", 2);
            continue;
        case '\r':
            buf_appendmap(buf, "\\r", 2);
            continue;
        case '\t':
            buf_appendmap(buf, "\\t", 2);
            continue;
        }

        /* rebuild the utf8 bytes into scratch */
        U8_APPEND(scratch, len, (int32_t) sizeof(scratch), cp, is_error);
        if (is_error) {
            /* only errors if scratch is too small? should never happen */
            syslog(LOG_DEBUG, "%s: U8_APPEND reported an error", __func__);
            logfmt_escape_bytestring(buf, utf8val);
            return;
        }

        if (is_utf8_escaped_hex(cp)) {
            /* escaped-hex */
            for (i = 0; i < len; i++)
                buf_printf(buf, "\\x{%2.2x}", scratch[i]);
        }
        else {
            /* eightbit */
            buf_appendmap(buf, (char *) scratch, len);
        }
    }
    utext_close(&ut);

    if (need_dquotes) buf_putc(buf, '"');
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

    logfmt_escape_bytestring(&lf->scratch, value);
    buf_printf(&lf->msg, "%s=%s", key, buf_cstring(&lf->scratch));
    buf_reset(&lf->scratch);
}

EXPORTED void logfmt_push_utf8(struct logfmt *lf,
                               const char *key,
                               const char *value)
{
    assert(key && *key);

    if (buf_len(&lf->msg))
        buf_putc(&lf->msg, ' ');

    logfmt_escape_utf8(&lf->scratch, value);
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

EXPORTED void logfmt_push_caller(struct logfmt *lf,
                                 const char *file,
                                 int line,
                                 const char *func)
{
    logfmt_push(lf, "caller.file", file);
    logfmt_pushf(lf, "caller.line", "%d", line);
    logfmt_push(lf, "caller.func", func);
}
