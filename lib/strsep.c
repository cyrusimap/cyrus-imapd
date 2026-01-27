/* strsep.c - replacement strsep() routine */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif

char *strsep(char **stringp, const char *delim)
{
    char *p;
    char *start;

    if (!stringp) return NULL;
    start = *stringp;
    if (!start) return NULL;

    p = strpbrk(start, delim);
    if (!p) return NULL;

    *p++ = '\0';
    *stringp = p;

    return start;
}

