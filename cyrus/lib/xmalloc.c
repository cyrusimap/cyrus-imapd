/* xmalloc.c -- Allocation package that calls fatal() when out of memory
 *
 * Copyright 1996, Carnegie Mellon University.  All Rights Reserved.
 * 
 * This software is made available for academic and research
 * purposes only.  No commercial license is hereby granted.
 * Copying and other reproduction is authorized only for research,
 * education, and other non-commercial purposes.  No warranties,
 * either expressed or implied, are made regarding the operation,
 * use, or results of the software.  Such a release does not permit
 * use of the code for commercial purposes or benefits by anyone
 * without specific, additional permission by the owner of the code.
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

char *xstrndup(str, len)
const char *str;
unsigned len;
{
    char *p = xmalloc(len+1);
    strncpy(p, str, len);
    p[len] = '\0';
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
