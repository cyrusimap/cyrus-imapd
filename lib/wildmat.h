/* wildmat.h - NNTP wildmat processing functions */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef INCLUDED_WILDMAT_H
#define INCLUDED_WILDMAT_H

struct wildmat {
    char *pat;
    int not;
};

extern int wildmat(const char *text, const char *p);
extern struct wildmat *split_wildmats(char *str, const char *prefix);
extern void free_wildmats(struct wildmat *wild);

#endif /* INCLUDED_WILDMAT_H */
