/* parseaddr.h -- RFC 822 address parser
 *
 * Copyright (c) 1994-2008 Carnegie Mellon University.  All rights reserved.
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

#ifndef INCLUDED_PARSEADDR_H
#define INCLUDED_PARSEADDR_H

struct address
{
    const char *name;
    const char *route;
    const char *mailbox;
    const char *domain;
    struct address *next;
    char *freeme; /* If non-nil, free */
    int invalid;  /* If non-zero, this mail address is known to
                     be invalid. */
};

struct address_itr
{
    struct address *addrlist;
    struct address *anext;
};

extern void parseaddr_list(const char *s, struct address **addrp);
extern void parseaddr_free(struct address *addr);

extern char *address_get_all(const struct address *, int canon_domain);
extern char *address_get_localpart(const struct address *);
extern char *address_get_domain(const struct address *, int canon_domain);
extern char *address_get_user(const struct address *);
extern char *address_get_detail(const struct address *);

extern void address_itr_init(struct address_itr *ai,
                             const char *str,
                             int reverse_path);
extern const struct address *address_itr_next(struct address_itr *ai);
extern void address_itr_fini(struct address_itr *ai);

extern char *address_canonicalise(const char *str);

#endif /* INCLUDED_PARSEADDR_H */
