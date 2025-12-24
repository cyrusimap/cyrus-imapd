/* parseaddr.h -- RFC 822 address parser */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef INCLUDED_PARSEADDR_H
#define INCLUDED_PARSEADDR_H

struct address {
    const char *name;
    const char *route;
    const char *mailbox;
    const char *domain;
    struct address *next;
    char *freeme;               /* If non-nil, free */
    int invalid;                /* If non-zero, this mail address is known to
                                   be invalid. */
};

struct address_itr {
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

extern void address_itr_init(struct address_itr *ai, const char *str,
                             int reverse_path);
extern const struct address *address_itr_next(struct address_itr *ai);
extern void address_itr_fini(struct address_itr *ai);

extern char *address_canonicalise(const char *str);

#endif /* INCLUDED_PARSEADDR_H */
