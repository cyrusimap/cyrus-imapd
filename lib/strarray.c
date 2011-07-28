/* strarray.c -- an expanding array of strings
 *
 * Copyright (c) 1994-2011 Carnegie Mellon University.  All rights reserved.
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
 *    prior written permission. For permission or any legal
 *    details, please contact
 *      Carnegie Mellon University
 *      Center for Technology Transfer and Enterprise Creation
 *      4615 Forbes Avenue
 *      Suite 302
 *      Pittsburgh, PA  15213
 *      (412) 268-7393, fax: (412) 268-7395
 *      innovation@andrew.cmu.edu
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
 *
 * Author: Greg Banks
 * Start Date: 2011/01/11
 */

#include "strarray.h"
#include <memory.h>
#include "xmalloc.h"

strarray_t *strarray_new(void)
{
    return xzmalloc(sizeof(strarray_t));
}

void strarray_fini(strarray_t *sa)
{
    int i;

    if (!sa)
	return;
    for (i = 0 ; i < sa->count ; i++) {
	free(sa->data[i]);
	sa->data[i] = NULL;
    }
    free(sa->data);
    sa->data = NULL;
    sa->count = 0;
    sa->alloc = 0;
}

void strarray_free(strarray_t *sa)
{
    if (!sa)
	return;
    strarray_fini(sa);
    free(sa);
}

/*
 * Ensure the index @idx exists in the array, if necessary expanding the
 * array, and if necessary NULL-filling all the intervening elements.
 * Note that we always ensure an empty slot past the last reported
 * index, so that we can pass data[] to execve() or other routines that
 * assume a NULL terminator.
 */
#define QUANTUM	    16
static void ensure_alloc(strarray_t *sa, int newalloc)
{
    if (newalloc)
	newalloc++;
    if (newalloc <= sa->alloc)
	return;
    newalloc = ((newalloc + QUANTUM-1) / QUANTUM) * QUANTUM;
    sa->data = xrealloc(sa->data, sizeof(char *) * newalloc);
    memset(sa->data+sa->alloc, 0, sizeof(char *) * (newalloc-sa->alloc));
    sa->alloc = newalloc;
}

static inline int adjust_index_ro(const strarray_t *sa, int idx)
{
    if (idx >= sa->count)
	return -1;
    else if (idx < 0)
	idx += sa->count;
    return idx;
}

static inline int adjust_index_rw(strarray_t *sa, int idx, int len)
{
    if (idx >= sa->count) {
	ensure_alloc(sa, idx+len);
    } else if (idx < 0) {
	idx += sa->count;
	if (idx >= 0 && len)
	    ensure_alloc(sa, sa->count+len);
    } else if (len) {
	ensure_alloc(sa, sa->count+len);
    }
    return idx;
}

strarray_t *strarray_dup(const strarray_t *sa)
{
    strarray_t *new = strarray_new();
    int i;

    strarray_truncate(new, sa->count);
    for (i = 0 ; i < sa->count ; i++)
	new->data[i] = xstrdup(sa->data[i]);
    return new;
}

void strarray_append(strarray_t *sa, const char *s)
{
    strarray_appendm(sa, xstrdup(s));
}

void strarray_add(strarray_t *sa, const char *s)
{
    if (strarray_find(sa, s, 0) < 0)
	strarray_append(sa, s);
}

void strarray_appendm(strarray_t *sa, char *s)
{
    ensure_alloc(sa, sa->count+1);
    sa->data[sa->count++] = s;
}

void strarray_set(strarray_t *sa, int idx, const char *s)
{
    if ((idx = adjust_index_rw(sa, idx, 0)) < 0)
	return;
    free(sa->data[idx]);
    sa->data[idx] = xstrdup(s);
}

void strarray_setm(strarray_t *sa, int idx, char *s)
{
    if ((idx = adjust_index_rw(sa, idx, 0)) < 0)
	return;
    free(sa->data[idx]);
    sa->data[idx] = s;
}

static inline void _strarray_insert(strarray_t *sa, int idx, char *s)
{
    if (idx < sa->count)
	memmove(sa->data+idx+1, sa->data+idx,
		sizeof(char *) * (sa->count-idx));
    sa->data[idx] = s;
    sa->count++;
}

void strarray_insert(strarray_t *sa, int idx, const char *s)
{
    if ((idx = adjust_index_rw(sa, idx, 1)) < 0)
	return;
    _strarray_insert(sa, idx, xstrdup(s));
}

void strarray_insertm(strarray_t *sa, int idx, char *s)
{
    if ((idx = adjust_index_rw(sa, idx, 1)) < 0)
	return;
    _strarray_insert(sa, idx, s);
}

char *strarray_remove(strarray_t *sa, int idx)
{
    char *s;
    if ((idx = adjust_index_ro(sa, idx)) < 0)
	return NULL;
    s = sa->data[idx];
    sa->count--;
    if (idx < sa->count)
	memmove(sa->data+idx, sa->data+idx+1,
		sizeof(char *) * (sa->count-idx));
    return s;
}

void strarray_remove_all(strarray_t *sa, const char *s)
{
    int i = 0;

    for (;;) {
	i = strarray_find(sa, s, i);
	if (i < 0)
	    break;
	free(strarray_remove(sa, i));
    }
}

void strarray_truncate(strarray_t *sa, int newlen)
{
    int i;

    if (newlen == sa->count)
	return;

    if (newlen > sa->count) {
	ensure_alloc(sa, newlen);
    } else {
	for (i = newlen ; i < sa->count ; i++) {
	    free(sa->data[i]);
	    sa->data[i] = NULL;
	}
    }
    sa->count = newlen;
}

const char *strarray_nth(const strarray_t *sa, int idx)
{
    if ((idx = adjust_index_ro(sa, idx)) < 0)
	return NULL;
    return sa->data[idx];
}

char *strarray_join(const strarray_t *sa, const char *sep)
{
    int seplen = (sep ? strlen(sep) : 0);
    int len = 0;
    int i;
    int first;
    char *buf, *p;

    for (i = 0, first = 1 ; i < sa->count ; i++, first = 0) {
	if (sa->data[i])
	    len += strlen(sa->data[i]) + (first ? 0 : seplen);
    }

    if (!len)
	return NULL;
    len++;	/* room for NUL terminator */
    p = buf = xmalloc(len);

    for (i = 0, first = 1 ; i < sa->count ; i++, first = 0) {
	if (sa->data[i]) {
	    if (!first && sep) {
		strcpy(p, sep);
		p += strlen(p);
	    }
	    strcpy(p, sa->data[i]);
	    p += strlen(p);
	}
    }

    return buf;
}

strarray_t *strarray_splitm(char *buf, const char *sep)
{
    strarray_t *sa = strarray_new();
    char *p;

    if (!sep)
	sep = " \t\r\n";

    for (p = strtok(buf, sep) ; p ; p = strtok(NULL, sep))
	strarray_append(sa, p);

    free(buf);
    return sa;
}

strarray_t *strarray_split(const char *line, const char *sep)
{
    return strarray_splitm(xstrdup(line), sep);
}

strarray_t *strarray_nsplit(const char *buf, size_t len, const char *sep)
{
    return strarray_splitm(xstrndup(buf, len), sep);
}

char **strarray_takevf(strarray_t *sa)
{
    char **d = sa->data;
    sa->data = NULL;
    sa->count = sa->alloc = 0;
    strarray_free(sa);
    return d;
}

/* direct from the qsort manpage */
static int cmpstringp(const void *p1, const void *p2) 
{
    /* The actual arguments to this function are "pointers to
    pointers to char", but strcmp(3) arguments are "pointers
   to char", hence the following cast plus dereference */

   return strcmp(* (char * const *) p1, * (char * const *) p2);
}

void strarray_sort(strarray_t *sa)
{
    qsort(sa->data, sa->count, sizeof(char *), cmpstringp);
}

int strarray_find(const strarray_t *sa, const char *match, int starting)
{
    int i;

    for (i = starting ; i < sa->count ; i++)
	if (!strcmp(match, sa->data[i]))
	    return i;
    return -1;
}
