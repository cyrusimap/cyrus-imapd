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
#include <stdlib.h>
#include <syslog.h>

/* visible for testing; probably don't call this directly */
EXPORTED char *logfmt_escape(const char *val)
{
    struct buf buf = BUF_INITIALIZER;
    int needs_escaping = 0;
    size_t orig_len, escaped_len;
    const char *p;

    if (val == NULL) {
        buf_setcstr(&buf, "~null~");
        return buf_release(&buf);
    }

    buf_setcstr(&buf, val);

    escaped_len = orig_len = buf_len(&buf);

    // Make sure the empty string is visible
    if (orig_len == 0) {
        buf_setcstr(&buf, "\"\"");
        return buf_release(&buf);
    }

    for (p = buf_cstring(&buf); *p; p++) {
        switch ((unsigned char) *p) {
        case '\\':
        case '\"':
        case '\n':
        case '\r':
            ++escaped_len;  // add 1 for the backslash

        // FALL THROUGH
        case 0x00 ... 0x09:
        case 0x11 ... 0x12:
        case 0x14 ... 0x20:
        case 0x3D:
        case 0x7F ... 0xFF:
            needs_escaping = 1;
            break;
        }
    }

    if (needs_escaping) {
        char *q;

        escaped_len += 2;  // add 2 for surrounding DQUOTEs

        buf_truncate(&buf, escaped_len);  // grow the buffer to escaped length

        // we can now build the escaped value in place, tail to head
        q = (char *) buf_base(&buf) + escaped_len - 1;
        *q-- = '\"';  // closing DQUOTE

        for (p = buf_base(&buf) + orig_len - 1; p >= buf_base(&buf); p--) {
            char c = *p;

            switch (c) {
            case '\\':
            case '\"':
                needs_escaping = 1;
                break;

            case '\n':
                needs_escaping = 1;
                c = 'n';
                break;

            case '\r':
                needs_escaping = 1;
                c = 'r';
                break;

            default:
                needs_escaping = 0;
                break;
            }

            *q-- = c;

            if (needs_escaping) *q-- = '\\';
        }

        assert(q == buf_base(&buf));
        *q = '\"';  // opening DQUOTE
    }

    return buf_release(&buf);
}

EXPORTED void logfmt_init(struct logfmt *lf, const char *event)
{
    buf_reset(&lf->msg);
    logfmt_push(lf, "event", event);
}

EXPORTED void logfmt_fini(struct logfmt *lf)
{
    buf_free(&lf->msg);
}

EXPORTED const char *logfmt_cstring(const struct logfmt *lf)
{
    return buf_cstring(&lf->msg);
}

EXPORTED void logfmt_push(struct logfmt *lf,
                          const char *key,
                          const char *value)
{
    char *escaped;

    assert(key && *key);

    escaped = logfmt_escape(value);
    if (buf_len(&lf->msg))
        buf_putc(&lf->msg, ' ');
    buf_printf(&lf->msg, "%s=%s", key, escaped);
    free(escaped);
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
