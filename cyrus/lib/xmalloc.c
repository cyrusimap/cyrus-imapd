#include <stdio.h>
extern char *malloc(), *realloc();

char *xmalloc (size)
int size;
{
    char *ret;

    if (ret = malloc((unsigned) size))
      return ret;

    fprintf(stderr, "Virtual memory exhausted\n");
    exit(1);
}


char *xrealloc (ptr, size)
char *ptr;
int size;
{
    char *ret;

    /* xrealloc (NULL, size) behaves like xmalloc (size), as in ANSI C */
    if (ret = !ptr ? malloc ((unsigned) size) : realloc (ptr, (unsigned) size))
      return ret;

    fprintf(stderr, "Virtual memory exhausted\n");
    exit(1);
}

char *strsave(str)
char *str;
{
    char *p = xmalloc(strlen(str)+1);
    strcpy(p, str);
    return p;
}
