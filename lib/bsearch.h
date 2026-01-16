/* bsearch.h - binary search */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef INCLUDED_BSEARCH_H
#define INCLUDED_BSEARCH_H

extern int bsearch_mem_mbox(const char *word,
                            const char *base, unsigned long len,
                            unsigned long hint,
                            unsigned long *linelenp);

extern int bsearch_ncompare_mbox(const char *s1, size_t l1, const char *s2, size_t l2);
extern int bsearch_memtree_mbox(const unsigned char *s1, size_t l1,
                                const unsigned char *s2, size_t l2);

extern int bsearch_ncompare_raw(const char *s1, size_t l1, const char *s2, size_t l2);

extern int cmpstringp_raw(const void *p1, const void *p2);
extern int cmpstringp_mbox(const void *p1, const void *p2);

#endif /* INCLUDED_BSEARCH_H */
