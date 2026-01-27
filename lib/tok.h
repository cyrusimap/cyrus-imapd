/* tok.h - utility for string tokenisation */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef __CYRUS_TOK_H__
#define __CYRUS_TOK_H__

#include <sys/types.h>
#include "xmalloc.h"

typedef struct
{
    char *buf;
    char *state;
    const char *sep;
    char *curr;
#define _TOK_FIRST      (1<<0)
#define TOK_TRIMLEFT    (1<<1)  /* trim whitespace from start of tokens */
#define TOK_TRIMRIGHT   (1<<2)  /* trim whitespace from end of tokens */
#define TOK_EMPTY       (1<<3)  /* return empty "" tokens if adjacent
                                 * delimiter characters are present */
#define TOK_FREEBUFFER  (1<<4)  /* tok_t should free() the buffer when done */
    unsigned int flags;
} tok_t;

#define TOK_INITIALIZER(str, sep, flags) \
    { xstrdup((str)), NULL, (sep), NULL, (flags)|_TOK_FIRST|TOK_FREEBUFFER }

void tok_init(tok_t *, const char *buf, const char *sep, int flags);
void tok_initm(tok_t *, char *buf, const char *sep, int flags);
void tok_fini(tok_t *);

/* advance to the next token and return it */
char *tok_next(tok_t *);
/* return offset into the buffer of the current token, for error messages */
unsigned int tok_offset(const tok_t *);

#endif /* __CYRUS_TOK_H__ */
