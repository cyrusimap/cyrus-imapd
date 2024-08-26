/* bsearch.c -- binary search newline-separated fields in memory
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

#include <config.h>
#include <string.h>

#include "bsearch.h"
#include "util.h"

/* Case-dependent comparison converter.
 * Treats \r and \t as end-of-string and treats '.' lower than
 * everything else.
 */
#define TOCOMPARE(c) (convert_to_compare[(unsigned char)(c)])
static unsigned char convert_to_compare[256] = {
    0x00, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
    0x0a, 0x01, 0x01, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x02, 0x2f,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
    0x40, 'A', 'B', 'C', 'D', 'E', 'F', 'G',
    'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O',
    'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W',
    'X', 'Y', 'Z', 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
    0x60, 'a', 'b', 'c', 'd', 'e', 'f', 'g',
    'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o',
    'p', 'q', 'r', 's', 't', 'u', 'v', 'w',
    'x', 'y', 'z', 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
    0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
    0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
    0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
    0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
    0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
    0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
    0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
    0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7,
    0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
    0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7,
    0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
    0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
};

/*
 * Search for a line starting with 'word'.  The search respects case.
 * The search is performed in 'base', which is of length 'len'.
 * 'hint' gives an idea of where to start looking.
 *
 * On success, the offset in 'base' of the found line is returned and
 * the length of the found line is put in the unsigned long pointed to
 * by 'linelenp'.  On failure, the offset in 'base' of where a new line should
 * be inserted is returned and zero is put in the unsigned long pointed to
 * by 'linelenp'.
 */
HIDDEN int bsearch_mem_mbox(const char *word,
                     const char *base,
                     unsigned long len,
                     unsigned long hint,
                     unsigned long *linelenp)
{
    int firstsearch = 1;
    unsigned long start = 0, end = len - 1, mid, offset;
    unsigned long linelen;
    long n;
    int cmp = 0;
    const char *wordp, *p;

    while (start < end + 1) {
        if (firstsearch) {
            /* Use hint supplied by caller */
            firstsearch = 0;
            mid = offset = hint;
            if (mid <= start || mid > end) mid = offset = start;
        }
        else {
            /* Calculate position of middle of this range */
            offset = mid = (start + end)/2;
        }

        if (mid) {
            p = memchr(base+mid, '\n', (end + 1) - mid);
            if (!p) {
                end = mid - 1;
                continue;
            }
            offset = p - base + 1;
        }

        p = memchr(base+offset, '\n', len-offset);
        if (p) {
            linelen = p - (base+offset) + 1;
        }
        else {
            end = mid - 1;
            continue;
        }

        n = linelen;
        wordp = word;
        p = base+offset;

        while (n-- > 0 && (cmp = TOCOMPARE(*wordp) - TOCOMPARE(*p)) == 0) {
            wordp++;
            p++;
        }
        if (n >= 0 && !*wordp) {
            cmp = TOCOMPARE('\t') - TOCOMPARE(*p);
        }
        else if (!cmp) {
            cmp = 1;
        }

        if (!cmp) {
            if (linelenp) *linelenp = linelen;
            return offset;
        }

        if (cmp < 0) {
            if (mid == 0) break;
            end = mid - 1;
        }
        else {
            start = offset + 1;
        }
    }

    /* Word was not found.  Return offset where word should be inserted */
    if (linelenp) *linelenp = 0;
    if (start > len) return len;
    if (!start) return 0;
    p = memchr(base+start, '\n', len-start);
    return p - base + 1;
}

EXPORTED int bsearch_compare_mbox(const char *s1, const char *s2)
{
    int cmp;
    char c2;

    for (;;) {
        if ((c2 = *s2) == 0) {
            return (unsigned char)*s1;
        }
        cmp = TOCOMPARE(*s1) - TOCOMPARE(c2);
        if (cmp) return cmp;
        if (TOCOMPARE(c2) == TOCOMPARE('\t')) {
            return 0;
        }
        s1++;
        s2++;
    }
}

HIDDEN int bsearch_ncompare_mbox(const char *s1, int l1, const char *s2, int l2)
{
    int min = l1 < l2 ? l1 : l2;
    int cmp = 0;

    while (min-- > 0 && (cmp = TOCOMPARE(*s1) - TOCOMPARE(*s2)) == 0) {
        s1++;
        s2++;
    }
    if (min >= 0) {
        return cmp;
    } else {
        if (l2 > l1) return -1;
        else if (l1 > l2) return 1;
        else return 0;
    }
}

HIDDEN int bsearch_uncompare_mbox(const unsigned char *s1, size_t l1,
                                  const unsigned char *s2, size_t l2)
{
    ssize_t min = l1 < l2 ? l1 : l2;
    int cmp = 0;

    while (min-- > 0 && (cmp = TOCOMPARE(*s1) - TOCOMPARE(*s2)) == 0) {
        s1++;
        s2++;
    }
    if (min >= 0) {
        return cmp;
    } else {
        if (l2 > l1) return -1;
        else if (l1 > l2) return 1;
        else return 0;
    }
}

HIDDEN int bsearch_memtree_mbox(const unsigned char *s1, size_t l1,
                                const unsigned char *s2, size_t l2)
{
    size_t min = l1 < l2 ? l1 : l2;
    int cmp = 0;

    while ((min-- >0) &&
           (cmp = (TOCOMPARE(*s1) - TOCOMPARE(*s2))) == 0) {
        s1++;
        s2++;
    }

    /* found a mismatch */
    if (cmp) return cmp;

    /* Walked off the end of one (or both strings), in which case one
     * (or both) of these will be zero, and the string with bytes remaining
     * is the greater.
     * XXX Arguably we don't need to TOCOMPARE() them here cause it's
     * always a comparison against zero, but if this turns into a perf
     * problem we can always optimise it then!
     */
    return TOCOMPARE(*s1) - TOCOMPARE(*s2);
}

/* direct from the qsort manpage */
EXPORTED int cmpstringp_raw(const void *p1, const void *p2)
{
    /* The actual arguments to this function are "pointers to
    pointers to char", but strcmp(3) arguments are "pointers
   to char", hence the following cast plus dereference */

   return strcmpsafe(* (char * const *) p1, * (char * const *) p2);
}

EXPORTED int cmpstringp_mbox(const void *p1, const void *p2)
{
    const char *s1 = *((const char **)p1);
    const char *s2 = *((const char **)p2);
    int cmp = 0;

    while (*s1 && *s2 && (cmp = TOCOMPARE(*s1) - TOCOMPARE(*s2)) == 0) {
        s1++;
        s2++;
    }

    /* found a mismatch */
    if (cmp) return cmp;

    /* Walked off the end of one (or both strings), in which case one
     * (or both) of these will be zero, and the string with bytes remaining
     * is the greater.
     * XXX Arguably we don't need to TOCOMPARE() them here cause it's
     * always a comparison against zero, but if this turns into a perf
     * problem we can always optimise it then!
     */
    return TOCOMPARE(*s1) - TOCOMPARE(*s2);
}

HIDDEN int bsearch_ncompare_raw(const char *s1, int l1, const char *s2, int l2)
{
    int min = l1 < l2 ? l1 : l2;
    int r = memcmp(s1, s2, min);

    if (!r) {
        if (l1 > l2)
            r = 1;
        else if (l2 > l1)
            r = -1;
    }

    return r;
}

