/* tok.h -- utility for string tokenisation
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
 *
 * Author: Greg Banks
 * Based on his tok_t class from ggcov.sf.net
 */

#ifndef __CYRUS_TOK_H__
#define __CYRUS_TOK_H__

#include <config.h>
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
const char *tok_next(tok_t *);
/* return offset into the buffer of the current token, for error messages */
unsigned int tok_offset(const tok_t *);

#endif /* __CYRUS_TOK_H__ */
