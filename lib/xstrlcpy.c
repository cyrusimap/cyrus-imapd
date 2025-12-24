/* xmalloc.c -- Allocation package that calls fatal() when out of memory */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include "xstrlcpy.h"

#ifndef HAVE_STRLCPY
/* strlcpy -- copy string smartly.
 *
 * i believe/hope this is compatible with the BSD strlcpy().
 */
EXPORTED size_t strlcpy(char *dst, const char *src, size_t len)
{
    size_t n;

    if (len <= 0) {
        /* we can't do anything ! */
        return strlen(src);
    }

    /* assert(len >= 1); */
    for (n = 0; n < len-1; n++) {
        if ((dst[n] = src[n]) == '\0') break;
    }
    if (n >= len-1) {
        /* ran out of space */
        dst[n] = '\0';
        while(src[n]) n++;
    }
    return n;
}
#endif
