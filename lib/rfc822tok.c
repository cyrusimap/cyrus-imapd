/* rfc822tok.c -- RFC 822/RFC 2822 tokenizer
 *
 * Copyright (c) 2012 Carnegie Mellon University.  All rights reserved.
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
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include "rfc822tok.h"

EXPORTED void rfc822tok_init(rfc822tok_t *t,
                             const char *base,
                             unsigned int len,
                             unsigned int flags)
{
    buf_init_ro(&t->buf, base, len);
    t->ptr = base;
    t->flags = flags;
}

EXPORTED void rfc822tok_init_buf(rfc822tok_t *t,
                                 const struct buf *b,
                                 unsigned int flags)
{
    rfc822tok_init(t, (b ? b->s : NULL), (b ? b->len : 0), flags);
}

EXPORTED void rfc822tok_fini(rfc822tok_t *t)
{
    buf_free(&t->buf);
}

static inline int is_special(rfc822tok_t *t, int c)
{
    /* These specials are defined by RFC2822 */
    if (strchr("()<>[]:;@\\,", c)) {
        return 1;
    }
    /* ...except '.' sometimes is and sometimes isn't special */
    if (c == '.' && (t->flags & RFC822_SPECIAL_DOT)) {
        return 1;
    }
    /* ...and '=' sometimes is and sometimes isn't */
    if (c == '=' && (t->flags & RFC822_SPECIAL_EQUAL)) {
        return 1;
    }
    return 0;
}

EXPORTED int rfc822tok_next(rfc822tok_t *t, char **textp)
{
    const char *p;
    const char *end;
    int comment_depth = 0;
    static struct buf text = BUF_INITIALIZER;
    int r;

    buf_reset(&text);
    if (textp) {
        *textp = NULL;
    }
    if (!t->buf.len) {
        return EOF;
    }

    end = t->buf.s + t->buf.len;
    p = t->ptr;
    if (p >= end) {
        return EOF;
    }

    /* skip any leading whitespace and comments */
    for (; p < end; p++) {
        if (comment_depth) {
            if (*p == '\\') {
                p++;
            }
            else if (*p == ')') {
                comment_depth--;
            }
            else if (*p == '(') {
                comment_depth++;
            }
        }
        else if (*p == '(') {
            comment_depth++;
        }
        else if (!isspace(*p)) {
            break;
        }
    }
    if (comment_depth) {
        r = -EINVAL;
        goto out;
    }
    if (p >= end) {
        r = EOF;
        goto out;
    }

    /* RFC2822 specials are single-char tokens */
    if (is_special(t, *p)) {
        r = *p++;
        goto out;
    }

    if (*p == '"') {
        /* parse quoted-string per RFC2822 section 3.2.5 */
        int in_quoted_pair = 0;
        int in_quoted_string = 1;

        for (p++; p < end; p++) {
            if (*p == '\r' && p + 1 < end && p[1] == '\n') {
                /* elide CRLF inside a quoted string */
                p++;
                /* a close reading of RFC2822 shows that \ is only
                 * semantically invisible when part of a quoted-pair,
                 * and CRLF is not part of a quoted-pair; so if we see a
                 * dangling \ just before CRLF we need to include it in
                 * the string */
                if (in_quoted_pair) {
                    buf_putc(&text, '\\');
                    in_quoted_pair = 0;
                }
                continue;
            }
            else if (in_quoted_pair) {
                in_quoted_pair = 0;
                buf_putc(&text, *p);
            }
            else if (*p == '\\') {
                in_quoted_pair = 1;
                continue;
            }
            else if (*p == '"') {
                in_quoted_string = 0;
                p++;
                break;
            }
            else {
                buf_putc(&text, *p);
            }
        }
        r = RFC822_QSTRING;
        if (in_quoted_string || in_quoted_pair) {
            r = -EINVAL;
        }
        goto out;
    }

    /* anything else is an atom */
    for (; p < end; p++) {
        if (isspace(*p) || *p == '(' || *p == '"' || is_special(t, *p)) {
            break;
        }
        buf_putc(&text, *p);
    }
    r = RFC822_ATOM;

out:
    t->ptr = p;
    if (textp) {
        *textp = text.len ? (char *) buf_cstring(&text) : NULL;
    }
    return r;
}
