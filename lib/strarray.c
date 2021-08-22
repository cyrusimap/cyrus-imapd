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
#include "util.h"
#include "xmalloc.h"

EXPORTED strarray_t *strarray_new(void)
{
    return xzmalloc(sizeof(strarray_t));
}

EXPORTED void strarray_fini(strarray_t *sa)
{
    int i;

    if (!sa)
        return;
    for (i = 0 ; i < sa->count ; i++) {
        xzfree(sa->data[i]);
    }
    xzfree(sa->data);
    sa->count = 0;
    sa->alloc = 0;
}

EXPORTED void strarray_free(strarray_t *sa)
{
    if (!sa)
        return;
    strarray_fini(sa);
    free(sa);
}

#define QUANTUM     16
static inline int grow(int have, int want)
{
    int x = MAX(QUANTUM, have);
    while (x < want)
        x *= 2;
    return x;
}

/*
 * Ensure the index @newalloc exists in the array, if necessary expanding the
 * array, and if necessary NULL-filling all the intervening elements.
 * Note that we always ensure an empty slot past the last reported
 * index, so that we can pass data[] to execve() or other routines that
 * assume a NULL terminator.
 */
static void ensure_alloc(strarray_t *sa, int newalloc)
{
    if (newalloc < sa->alloc)
        return;
    newalloc = grow(sa->alloc, newalloc + 1);
    sa->data = xrealloc(sa->data, sizeof(char *) * newalloc);
    memset(sa->data + sa->alloc, 0, sizeof(char *) * (newalloc - sa->alloc));
    sa->alloc = newalloc;
}

/*
 * Normalise the index passed by a caller, to a value in the range
 * 0..count-1, or < 0 for invalid, assuming the function we're
 * performing does not have the side effect of expanding the array.
 * Note that doesn't necessarily mean the array is read-only, e.g.
 * strarray_remove() modifies the array but does not expand the array if
 * given an index outside the array's current bounds.  In Perl style,
 * negative indexes whose absolute value is less than the length of the
 * array are treated as counting back from the end, e.g.  idx=-1 means
 * the final element.
 */
static inline int adjust_index_ro(const strarray_t *sa, int idx)
{
    if (idx >= sa->count)
        return -1;
    else if (idx < 0)
        idx += sa->count;
    return idx;
}

/*
 * Like adjust_index_ro(), with extra complication that the function
 * we're performing will expand the array if either the adjusted index
 * points outside the current bounds of the array, or @grow tells us
 * that we're about to need more space in the array.
 */
static inline int adjust_index_rw(strarray_t *sa, int idx, int grow)
{
    if (idx >= sa->count) {
        /* expanding the array as a side effect @idx pointing
         * outside the current bounds, plus perhaps @grow */
        ensure_alloc(sa, idx+grow);
    } else if (idx < 0) {
        /* adjust Perl-style negative indices */
        idx += sa->count;
        if (idx >= 0 && grow)
            ensure_alloc(sa, sa->count+grow);
    } else if (grow) {
        /* expanding the array due to an insert or append */
        ensure_alloc(sa, sa->count+grow);
    }
    return idx;
}

EXPORTED strarray_t *strarray_dup(const strarray_t *sa)
{
    strarray_t *new = strarray_new();
    int i;

    if (!sa) return new;

    strarray_truncate(new, sa->count);
    for (i = 0 ; i < sa->count ; i++)
        new->data[i] = xstrdupnull(sa->data[i]);
    return new;
}

EXPORTED int strarray_append(strarray_t *sa, const char *s)
{
    return strarray_appendm(sa, xstrdupnull(s));
}

EXPORTED void strarray_cat(strarray_t *dest, const strarray_t *src)
{
    int i;
    for (i = 0 ; i < src->count ; i++)
        strarray_append(dest, strarray_nth(src, i));
}

EXPORTED int strarray_add(strarray_t *sa, const char *s)
{
    int pos = strarray_find(sa, s, 0);
    if (pos < 0) pos = strarray_append(sa, s);
    return pos;
}

EXPORTED int strarray_add_case(strarray_t *sa, const char *s)
{
    int pos = strarray_find_case(sa, s, 0);
    if (pos < 0) pos = strarray_append(sa, s);
    return pos;
}

EXPORTED int strarray_appendm(strarray_t *sa, char *s)
{
    int pos = sa->count++;
    ensure_alloc(sa, sa->count);
    /* coverity[var_deref_op] */
    sa->data[pos] = s;
    return pos;
}

static void _strarray_set(strarray_t *sa, int idx, char *s)
{
    free(sa->data[idx]);
    sa->data[idx] = s;
    /* adjust the count if we just sparsely expanded the array */
    if (s && idx >= sa->count)
        sa->count = idx+1;
}

EXPORTED void strarray_set(strarray_t *sa, int idx, const char *s)
{
    if ((idx = adjust_index_rw(sa, idx, 0)) < 0)
        return;
    _strarray_set(sa, idx, xstrdupnull(s));
}

EXPORTED void strarray_setm(strarray_t *sa, int idx, char *s)
{
    if ((idx = adjust_index_rw(sa, idx, 0)) < 0)
        return;
    _strarray_set(sa, idx, s);
}

static inline void _strarray_insert(strarray_t *sa, int idx, char *s)
{
    if (idx < sa->count)
        memmove(sa->data+idx+1, sa->data+idx,
                sizeof(char *) * (sa->count-idx));
    sa->data[idx] = s;
    sa->count++;
}

EXPORTED void strarray_insert(strarray_t *sa, int idx, const char *s)
{
    if ((idx = adjust_index_rw(sa, idx, 1)) < 0)
        return;
    _strarray_insert(sa, idx, xstrdupnull(s));
}

EXPORTED void strarray_insertm(strarray_t *sa, int idx, char *s)
{
    if ((idx = adjust_index_rw(sa, idx, 1)) < 0)
        return;
    _strarray_insert(sa, idx, s);
}

EXPORTED char *strarray_remove(strarray_t *sa, int idx)
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

EXPORTED void strarray_remove_all(strarray_t *sa, const char *s)
{
    int i = 0;

    for (;;) {
        i = strarray_find(sa, s, i);
        if (i < 0)
            break;
        free(strarray_remove(sa, i));
    }
}

EXPORTED void strarray_subtract_complement(strarray_t *sa, const strarray_t *sb)
{
    int i;
    for (i = 0; i < sb->count; i++)
        strarray_remove_all(sa, strarray_nth(sb, i));
}


EXPORTED void strarray_remove_all_case(strarray_t *sa, const char *s)
{
    int i = 0;

    for (;;) {
        i = strarray_find_case(sa, s, i);
        if (i < 0)
            break;
        free(strarray_remove(sa, i));
    }
}

EXPORTED void strarray_truncate(strarray_t *sa, int newlen)
{
    int i;

    if (newlen == sa->count)
        return;

    if (newlen > sa->count) {
        ensure_alloc(sa, newlen);
    } else {
        for (i = newlen ; i < sa->count ; i++) {
            xzfree(sa->data[i]);
        }
    }
    sa->count = newlen;
}

EXPORTED void strarray_swap(strarray_t *sa, int idxa, int idxb)
{
    if (idxa < 0 || idxa >= sa->count)
        return;
    if (idxb < 0 || idxb >= sa->count)
        return;

    char *tmp = sa->data[idxa];
    sa->data[idxa] = sa->data[idxb];
    sa->data[idxb] = tmp;
}

EXPORTED const char *strarray_nth(const strarray_t *sa, int idx)
{
    if ((idx = adjust_index_ro(sa, idx)) < 0)
        return NULL;
    return sa->data[idx];
}

EXPORTED const char *strarray_safenth(const strarray_t *sa, int idx)
{
    const char *v = strarray_nth(sa, idx);
    return v ? v : "";
}

EXPORTED char *strarray_join(const strarray_t *sa, const char *sep)
{
    int seplen = (sep ? strlen(sep) : 0);
    int len = 0;
    int i;  /* array index */
    int j;  /* index into non-sparse logical subset of the array
             * i.e. doesn't count NULLs */
    char *buf, *p;

    for (i = 0, j = 0 ; i < sa->count ; i++) {
        if (sa->data[i])
            len += strlen(sa->data[i]) + (j++ ? seplen : 0);
    }

    if (!len)
        return NULL;
    len++;      /* room for NUL terminator */
    p = buf = xmalloc(len);

    for (i = 0, j = 0 ; i < sa->count ; i++) {
        if (sa->data[i]) {
            if (j++ && sep) {
                strcpy(p, sep);
                p += strlen(p);
            }
            strcpy(p, sa->data[i]);
            p += strlen(p);
        }
    }

    return buf;
}

EXPORTED strarray_t *strarray_splitm(char *buf, const char *sep, int flags)
{
    strarray_t *sa = strarray_new();
    char *p, *q;

    if (!buf) return sa;

    if (!sep)
        sep = " \t\r\n";

    if (flags & STRARRAY_LCASE) lcase(buf);

    for (p = strtok(buf, sep) ; p ; p = strtok(NULL, sep)) {
        if (flags & STRARRAY_TRIM) {
            while (Uisspace(*p)) p++;
            q = p + strlen(p);
            while (q > p && Uisspace(q[-1])) q--;
            *q = '\0';
        }
        if (*p) strarray_append(sa, p);
    }

    free(buf);
    return sa;
}

EXPORTED strarray_t *strarray_split(const char *line, const char *sep, int flags)
{
    if (!line)
        return strarray_new();
    return strarray_splitm(xstrdup(line), sep, flags);
}

EXPORTED strarray_t *strarray_nsplit(const char *buf, size_t len, const char *sep, int flags)
{
    if (!len)
        return strarray_new();
    return strarray_splitm(xstrndup(buf, len), sep, flags);
}

EXPORTED char **strarray_takevf(strarray_t *sa)
{
    char **d = sa->data;
    sa->data = NULL;
    sa->count = sa->alloc = 0;
    strarray_free(sa);
    return d;
}

EXPORTED char **strarray_safetakevf(strarray_t *sa)
{
    ensure_alloc(sa, 1); // never return NULL
    return strarray_takevf(sa);
}

EXPORTED void strarray_sort(strarray_t *sa, strarray_cmp_fn_t *cmp)
{
    qsort(sa->data, sa->count, sizeof(char *), cmp);
}


EXPORTED void strarray_uniq(strarray_t *sa)
{
    int i;

    for (i = 1; i < sa->count; i++) {
        if (!strcmpsafe(sa->data[i-1], sa->data[i]))
            free(strarray_remove(sa, i--));
    }
}

/* common generic routine for the _find family */
static int strarray_findg(const strarray_t *sa, const char *match, int starting,
                          int (*compare)(const char *, const char *))
{
    int i;

    for (i = starting ; i < sa->count ; i++)
        if (!compare(match, sa->data[i]))
            return i;
    return -1;
}

EXPORTED int strarray_find(const strarray_t *sa, const char *match, int starting)
{
    return strarray_findg(sa, match, starting, strcmpsafe);
}

EXPORTED int strarray_find_case(const strarray_t *sa, const char *match, int starting)
{
    return strarray_findg(sa, match, starting, strcasecmpsafe);
}

EXPORTED int strarray_intersect(const strarray_t *sa, const strarray_t *sb)
{
    /* XXX O(n^2)... but we don't have a proper set type */
    int i;
    for (i = 0; i < sa->count; i++)
        if (strarray_find(sb, strarray_nth(sa, i), 0) >= 0)
            return 1;
    return 0;
}

EXPORTED int strarray_intersect_case(const strarray_t *sa, const strarray_t *sb)
{
    /* XXX O(n^2)... but we don't have a proper set type */
    int i;
    for (i = 0; i < sa->count; i++)
        if (strarray_find_case(sb, strarray_nth(sa, i), 0) >= 0)
            return 1;
    return 0;
}

EXPORTED int strarray_size(const strarray_t *sa)
{
    if (!sa) return 0;
    return sa->count;
}

EXPORTED int strarray_cmp(const strarray_t *a, const strarray_t *b)
{
    int as = strarray_size(a);
    int bs = strarray_size(b);
    int i;

    /* test size first */
    if (as != bs) return as - bs;

    for (i = 0; i < as; i++) {
        int res = strcmpsafe(strarray_nth(a, i), strarray_nth(b, i));
        if (res) return res;
    }

    return 0;
}

EXPORTED void strarray_addfirst(strarray_t *sa, const char *s)
{
    strarray_remove_all(sa, s);
    strarray_unshift(sa, s);

}

EXPORTED void strarray_addfirst_case(strarray_t *sa, const char *s)
{
    strarray_remove_all_case(sa, s);
    strarray_unshift(sa, s);
}
