/* ptrarray.c -- an expanding array of pointers
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

#include "ptrarray.h"
#include <memory.h>
#include "util.h"
#include "xmalloc.h"

EXPORTED ptrarray_t *ptrarray_new(void)
{
    return xzmalloc(sizeof(ptrarray_t));
}

EXPORTED void ptrarray_fini(ptrarray_t *pa)
{
    if (!pa)
        return;
    memset(pa->data, 0, sizeof(void *) * pa->count);
    free(pa->data);
    pa->data = NULL;
    pa->count = 0;
    pa->alloc = 0;
}

EXPORTED void ptrarray_free(ptrarray_t *pa)
{
    if (!pa)
        return;
    ptrarray_fini(pa);
    free(pa);
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
static void ensure_alloc(ptrarray_t *pa, int newalloc)
{
    if (newalloc < pa->alloc)
        return;
    newalloc = grow(pa->alloc, newalloc + 1);
    pa->data = xrealloc(pa->data, sizeof(void *) * newalloc);
    memset(pa->data+pa->alloc, 0, sizeof(void *) * (newalloc-pa->alloc));
    pa->alloc = newalloc;
}

static inline int adjust_index_ro(const ptrarray_t *pa, int idx)
{
    if (idx >= pa->count)
        return -1;
    else if (idx < 0)
        idx += pa->count;
    return idx;
}

static inline int adjust_index_rw(ptrarray_t *pa, int idx, int len)
{
    if (idx >= pa->count) {
        ensure_alloc(pa, idx+len);
    } else if (idx < 0) {
        idx += pa->count;
        if (idx >= 0 && len)
            ensure_alloc(pa, pa->count+len);
    } else if (len) {
        ensure_alloc(pa, pa->count+len);
    }
    return idx;
}

EXPORTED void ptrarray_add(ptrarray_t *pa, void *p)
{
    if (ptrarray_find(pa, p, 0) < 0)
        ptrarray_append(pa, p);
}

EXPORTED void ptrarray_append(ptrarray_t *pa, void *p)
{
    ensure_alloc(pa, pa->count+1);
    pa->data[pa->count++] = p;
}

EXPORTED void ptrarray_set(ptrarray_t *pa, int idx, void *p)
{
    if ((idx = adjust_index_rw(pa, idx, 0)) < 0)
        return;
    pa->data[idx] = p;
}

static inline void _ptrarray_insert(ptrarray_t *pa, int idx, void *p)
{
    if (idx < pa->count)
        memmove(pa->data+idx+1, pa->data+idx,
                sizeof(void *) * (pa->count-idx));
    pa->data[idx] = p;
    pa->count++;
}

EXPORTED void ptrarray_insert(ptrarray_t *pa, int idx, void *p)
{
    if ((idx = adjust_index_rw(pa, idx, 1)) < 0)
        return;
    _ptrarray_insert(pa, idx, p);
}

EXPORTED void *ptrarray_remove(ptrarray_t *pa, int idx)
{
    void *p;
    if ((idx = adjust_index_ro(pa, idx)) < 0)
        return NULL;
    p = pa->data[idx];
    pa->count--;
    if (idx < pa->count)
        memmove(pa->data+idx, pa->data+idx+1,
                sizeof(void *) * (pa->count-idx));
    return p;
}

EXPORTED void ptrarray_truncate(ptrarray_t *pa, int newlen)
{
    int i;

    if (newlen == pa->count)
        return;

    if (newlen > pa->count) {
        ensure_alloc(pa, newlen);
    } else {
        for (i = newlen ; i < pa->count ; i++) {
            pa->data[i] = NULL;
        }
    }
    pa->count = newlen;
}

EXPORTED void *ptrarray_nth(const ptrarray_t *pa, int idx)
{
    if ((idx = adjust_index_ro(pa, idx)) < 0)
        return NULL;
    return pa->data[idx];
}

EXPORTED int ptrarray_find(const ptrarray_t *pa, void *match, int starting)
{
    if (!pa) return -1;
    int i;

    for (i = starting ; i < pa->count ; i++)
        if (match == pa->data[i])
            return i;
    return -1;
}

EXPORTED void ptrarray_sort(ptrarray_t *pa,
                            int (*compare)(const void **, const void **))
{
    if (!pa) return;
    qsort(pa->data, pa->count, sizeof(void*),
            (int (*)(const void *, const void *))compare);
}

EXPORTED int ptrarray_size(const ptrarray_t *pa)
{
    if (!pa) return 0;
    return pa->count;
}
