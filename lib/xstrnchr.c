/* xstrnchr.c - Implementation of strnchr() */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include "xstrnchr.h"

#ifndef HAVE_STRNCHR
EXPORTED char *strnchr(const char *s, int c, size_t n)
{
    if (!s) return NULL;

    for (; n; n--, s++) if (*s == c) return ((char *) s);

    return NULL;
}
#endif
