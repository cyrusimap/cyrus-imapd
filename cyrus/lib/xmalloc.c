/* xmalloc.c -- Allocation package that calls fatal() when out of memory
 *
 *        Copyright 1998 by Carnegie Mellon University
 *
 *                      All Rights Reserved
 *
 * Permission to use, copy, modify, and distribute this software and its
 * documentation for any purpose and without fee is hereby granted,
 * provided that the above copyright notice appear in all copies and that
 * both that copyright notice and this permission notice appear in
 * supporting documentation, and that the name of CMU not be
 * used in advertising or publicity pertaining to distribution of the
 * software without specific, written prior permission.
 *
 * CMU DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
 * ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL
 * CMU BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR
 * ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
 * WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
 * ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 */
/*
 * $Id: xmalloc.c,v 1.19 2000/02/10 21:25:42 leg Exp $
 */
#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "xmalloc.h"

#include "exitcodes.h"

void* xmalloc(unsigned size)
{
    void *ret;

    ret = malloc(size);
    if (ret != NULL) return ret;

    fatal("Virtual memory exhausted", EC_TEMPFAIL);
    return 0; /*NOTREACHED*/
}

void *xrealloc (void* ptr, unsigned size)
{
    void *ret;

    /* xrealloc (NULL, size) behaves like xmalloc (size), as in ANSI C */
    ret = (!ptr ? malloc (size) : realloc (ptr, size));
    if (ret != NULL) return ret;

    fatal("Virtual memory exhausted", EC_TEMPFAIL);
    return 0; /*NOTREACHED*/
}

char *xstrdup(const char* str)
{
    char *p = xmalloc(strlen(str)+1);
    strcpy(p, str);
    return p;
}

char *xstrndup(const char* str, unsigned len)
{
    char *p = xmalloc(len+1);
    strncpy(p, str, len);
    p[len] = '\0';
    return p;
}

/* Same as xmalloc() */
void *fs_get(unsigned size)
{
    void *ret;

    if ((ret = malloc(size)) != NULL)
      return (void *)ret;

    fatal("Virtual memory exhausted", EC_TEMPFAIL);
}

void fs_give(void** ptr)
{
    free((void *)*ptr);
    *ptr = 0;
}
