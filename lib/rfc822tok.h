/* rfc822tok.h -- RFC822/RFC2822 tokenizer
 *
 * Copyright (c) 1994-2012 Carnegie Mellon University.  All rights reserved.
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

#ifndef __CYRUS__RFC822TOK_H__
#define __CYRUS__RFC822TOK_H__

#include "util.h"

/* definitions for tokens returned */
#define RFC822_ATOM		256
#define RFC822_QSTRING		257

typedef struct
{
    struct buf buf;
    const char *ptr;
#define RFC822_SPECIAL_DOT	(1<<0)
#define RFC822_SPECIAL_EQUAL	(1<<1)
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
