/* xmalloc.c - Allocation package that calls fatal() when out of memory */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include "xmalloc.h"


EXPORTED void *xmalloc(size_t size)
{
    void *ret;

    ret = malloc(size);
    if (ret != NULL) return ret;

    fatal("Virtual memory exhausted", EX_TEMPFAIL);
    return 0; /*NOTREACHED*/
}

EXPORTED void *xzmalloc(size_t size)
{
    void *ret = xmalloc(size);
    memset(ret, 0, size);
    return ret;
}

EXPORTED void *xcalloc(size_t nmemb, size_t size)
{
    return xzmalloc(nmemb * size);
}

EXPORTED void *xrealloc(void *ptr, size_t size)
{
    void *ret;

    ret = realloc(ptr, size);
    if (ret != NULL) return ret;

    fatal("Virtual memory exhausted", EX_TEMPFAIL);
    return 0; /*NOTREACHED*/
}

EXPORTED void *xzrealloc(void *ptr, size_t orig_size, size_t new_size)
{
    void *ret = xrealloc(ptr, new_size);

    if (orig_size < new_size)
        memset(ret + orig_size, 0, new_size - orig_size);

    return ret;
}

EXPORTED char *xstrdup(const char* str)
{
    char *p = xmalloc(strlen(str)+1);
    strcpy(p, str);
    return p;
}

/* return a malloced "" if NULL is passed */
EXPORTED char *xstrdupsafe(const char *str)
{
    return str ? xstrdup(str) : xstrdup("");
}

/* return NULL if NULL is passed */
EXPORTED char *xstrdupnull(const char *str)
{
    return str ? xstrdup(str) : NULL;
}

EXPORTED char *xstrndup(const char* str, size_t len)
{
    char *p = xmalloc(len+1);
    if (len) strncpy(p, str, len);
    p[len] = '\0';
    return p;
}

EXPORTED void *xmemdup(const void *ptr, size_t size)
{
    void *p = xmalloc(size);
    memcpy(p, ptr, size);
    return p;
}
