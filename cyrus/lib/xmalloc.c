/* xmalloc.c -- Allocation package that calls fatal() when out of memory
 *
 *	(C) Copyright 1994 by Carnegie Mellon University
 *
 *                      All Rights Reserved
 *
 * Permission to use, copy, modify, distribute, and sell this software
 * and its documentation for any purpose is hereby granted without
 * fee, provided that the above copyright notice appear in all copies
 * and that both that copyright notice and this permission notice
 * appear in supporting documentation, and that the name of Carnegie
 * Mellon University not be used in advertising or publicity
 * pertaining to distribution of the software without specific,
 * written prior permission.  Carnegie Mellon University makes no
 * representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied
 * warranty.
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 *
 */
#include <stdio.h>

#include "sysexits.h"

extern char *malloc(), *realloc();

char *xmalloc (size)
unsigned size;
{
    char *ret;

    if (ret = malloc(size))
      return ret;

    fatal("Virtual memory exhausted", EX_TEMPFAIL);
}


char *xrealloc (ptr, size)
char *ptr;
unsigned size;
{
    char *ret;

    /* xrealloc (NULL, size) behaves like xmalloc (size), as in ANSI C */
    if (ret = !ptr ? malloc (size) : realloc (ptr, size))
      return ret;

    fatal("Virtual memory exhausted", EX_TEMPFAIL);
}

char *xstrdup(str)
const char *str;
{
    char *p = xmalloc(strlen(str)+1);
    strcpy(p, str);
    return p;
}

/* Same as xmalloc() */
void *fs_get(size)
unsigned size;
{
    char *ret;

    if (ret = malloc(size))
      return (void *)ret;

    fatal("Virtual memory exhausted", EX_TEMPFAIL);
}

void fs_give(ptr)
void **ptr;
{
    free((char *)*ptr);
    *ptr = 0;
}
