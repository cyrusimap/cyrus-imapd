/* memrchr.c -- replacement memrchr() routine */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>
#ifdef HAVE_STRING_H
#include <string.h>
#endif

/*
 * Reverse memchr()
 * memrchr() is a GNU extension and not available on all platforms
 */
void *
memrchr(const void *s, int c1, size_t n)
{
    if (n != 0) {
        const unsigned char *sp = (unsigned char *)s + n;
        unsigned char c = (unsigned char)c1;

        do {
            if (*(--sp) == c)
                return((void *)sp);
        } while (--n != 0);
    }
    return NULL;
}

