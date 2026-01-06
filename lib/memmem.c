/* memmem.c -- replacement memmem() routine */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>
#ifdef HAVE_STRING_H
#include <string.h>
#endif

/*
 * Search for a needle 'vm' of length 'mlen' in
 * haystack 'vb' of length 'len' and return the
 * pointer to the first occurrence or NULL.
 * Does not handle mlen=0.
 */
void *memmem(const void *vb, size_t len,
             const void *vm, size_t mlen)
{
    /* use unsigned char* not void* so ptr arithmetic works portably */
    const unsigned char *b = vb;
    const unsigned char *end = b+len;
    const unsigned char *m = vm;
    const unsigned char *p;

    while (b < end) {
        p = memchr(b, *m, end-b);
        if (!p) return NULL;
        if (p + mlen > end) return NULL;
        if (!memcmp(p, m, mlen)) return (void *)p;
        b = p+1;
    }
    return NULL;
}

