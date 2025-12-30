/* rfc822tok.h -- RFC822/RFC2822 tokenizer */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef __CYRUS__RFC822TOK_H__
#define __CYRUS__RFC822TOK_H__

#include "buf.h"

/* definitions for tokens returned */
#define RFC822_ATOM             256
#define RFC822_QSTRING          257

typedef struct
{
    struct buf buf;
    const char *ptr;
#define RFC822_SPECIAL_DOT      (1<<0)
#define RFC822_SPECIAL_EQUAL    (1<<1)
    unsigned int flags;
} rfc822tok_t;

#define RFC822TOK_INITIALIZER \
    { BUF_INITIALIZER, NULL, 0 }

void rfc822tok_init(rfc822tok_t *, const char *base,
                    unsigned int len, unsigned int flags);
void rfc822tok_init_buf(rfc822tok_t *, const struct buf *,
                        unsigned int flags);
void rfc822tok_fini(rfc822tok_t *);

/* Advance to the next token and return it.  Tokens may be several ASCII
 * characters or the tokens defined above.  EOF is returned on end of
 * the input text, other negative numbers indicate errors.  Some tokens
 * have associated text; if @textp is non-NULL, fill it in with a
 * pointer to the text in an internal buffer which is valid until the
 * next call and can be written e.g. for further parsing. */
int rfc822tok_next(rfc822tok_t *, char **textp);

#endif /* __CYRUS__RFC822TOK_H__ */
