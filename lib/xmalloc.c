/* xmalloc.c -- Allocation package that calls fatal() when out of memory
 *
 *	(C) Copyright 1993 by Carnegie Mellon University
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
 *
 */
#include <stdio.h>
#include <sysexits.h>

extern char *malloc(), *realloc();

char *xmalloc (size)
int size;
{
    char *ret;

    if (ret = malloc((unsigned) size))
      return ret;

    fatal("Virtual memory exhausted", EX_TEMPFAIL);
}


char *xrealloc (ptr, size)
char *ptr;
int size;
{
    char *ret;

    /* xrealloc (NULL, size) behaves like xmalloc (size), as in ANSI C */
    if (ret = !ptr ? malloc ((unsigned) size) : realloc (ptr, (unsigned) size))
      return ret;

    fatal("Virtual memory exhausted", EX_TEMPFAIL);
}

char *strsave(str)
char *str;
{
    char *p = xmalloc(strlen(str)+1);
    strcpy(p, str);
    return p;
}
