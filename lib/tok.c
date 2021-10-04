/* tok.c -- utility for string tokenisation
 *
 * Copyright (c) 2011 Carnegie Mellon University.  All rights reserved.
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
#include "tok.h"
#include "xmalloc.h"

EXPORTED void tok_init(tok_t *t, const char *str, const char *sep, int flags)
{
    tok_initm(t, str ? xstrdup(str) : NULL, sep, flags|TOK_FREEBUFFER);
}

EXPORTED void tok_initm(tok_t *t, char *str, const char *sep, int flags)
{
    memset(t, 0, sizeof(*t));
    t->buf = str;
    t->sep = sep;
    t->flags = flags | _TOK_FIRST;
}

EXPORTED void tok_fini(tok_t *t)
{
    if ((t->flags & TOK_FREEBUFFER))
        free(t->buf);
    memset(t, 0, sizeof(*t));
}

EXPORTED const char *tok_next(tok_t *t)
{
    const char *sep;
    char *token;

    /* initialising us with a NULL buffer is harmless */
    if (!t->buf)
        return NULL;

    /* use the given separator or the default separator string */
    sep = (t->sep ? t->sep : " \t\n\r");

    if ((t->flags & TOK_EMPTY)) {
        if ((t->flags & _TOK_FIRST)) {
            t->flags &= ~_TOK_FIRST;
            t->state = t->buf;
        }
        token = strsep(&t->state, sep);
    }
    else {
        char *buf = NULL;

        if ((t->flags & _TOK_FIRST)) {
            /* strtok_r() wants the buffer only the first time */
            t->flags &= ~_TOK_FIRST;
            buf = t->buf;
        }

        token = strtok_r(buf, sep, &t->state);
    }

    if (!token) {
        /* end of tokens; clean up the tok_t to ensure we don't
         * leak any memory even if the caller doesn't call tok_fini() */
        tok_fini(t);
        return NULL;
    }

    /* we have a token, perform any additional munging */

    if ((t->flags & TOK_TRIMLEFT)) {
        while (*token && isspace(*token))
            token++;
    }

    if ((t->flags & TOK_TRIMRIGHT)) {
        char *p = token + strlen(token) - 1;
        while (p >= token && isspace(*p))
            *p-- = '\0';
    }

    t->curr = token;
    return token;
}

EXPORTED unsigned int tok_offset(const tok_t *t)
{
    if (!t->buf || !t->curr)
        return 0;
    return (t->curr - t->buf);
}
