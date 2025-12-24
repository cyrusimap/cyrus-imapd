/* tok.c -- utility for string tokenisation */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

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

EXPORTED char *tok_next(tok_t *t)
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
