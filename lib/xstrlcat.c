/* xmalloc.c -- Allocation package that calls fatal() when out of memory */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include "xstrlcat.h"

#ifndef HAVE_STRLCAT
EXPORTED size_t strlcat(char *dst, const char *src, size_t len)
{
    size_t i, j, o;

    o = strlen(dst);
    if (len < o + 1)
        return o + strlen(src);
    len -= o + 1;
    for (i = 0, j = o; i < len; i++, j++) {
        if ((dst[j] = src[i]) == '\0') break;
    }
    dst[j] = '\0';
    if (src[i] == '\0') {
        return j;
    } else {
        return j + strlen(src + i);
    }
}
#endif
