/* xmalloc.c -- Allocation package that calls fatal() when out of memory
 *
 * Copyright (c) 1998-2000 Carnegie Mellon University.  All rights reserved.
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
 *    prior written permission. For permission or any other legal
 *    details, please contact  
 *      Office of Technology Transfer
 *      Carnegie Mellon University
 *      5000 Forbes Avenue
 *      Pittsburgh, PA  15213-3890
 *      (412) 268-4387, fax: (412) 268-7395
 *      tech-transfer@andrew.cmu.edu
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
/*
 * $Id: xmalloc.c,v 1.23 2000/11/17 02:10:48 leg Exp $
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

void* xzmalloc(unsigned size)
{
    void *ret;

    ret = malloc(size);
    if (ret != NULL) {
	memset(ret, 0, size);
	return ret;
    }

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

#ifndef HAVE_STRLCPY
/* strlcpy -- copy string smartly.
 *
 * i believe/hope this is compatible with the BSD strlcpy(). 
 */
size_t strlcpy(char *dst, const char *src, size_t len)
{
    size_t n;

    if (len <= 0) return strlen(src);
    for (n = 0; n < len; n++) {
	if ((dst[n] = src[n]) == '\0') break;
    }
    if (src[n] == '\0') {
	/* copied entire string */
	return n;
    } else {
	dst[n] = '\0';
	/* ran out of space */
	return n + strlen(src + n);
    }
}
#endif

#ifndef HAVE_STRLCAT
size_t strlcat(char *dst, const char *src, size_t len)
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
