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
