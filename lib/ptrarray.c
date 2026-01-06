/* ptrarray.c -- an expanding array of pointers */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

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

    xzfree(pa->data);
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
    pa->data = xzrealloc(pa->data,
                         sizeof(void *) * pa->alloc,
                         sizeof(void *) * newalloc);
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

EXPORTED void **ptrarray_takevf(ptrarray_t *pa)
{
    void **d = pa->data;
    pa->data = NULL;
    pa->count = pa->alloc = 0;
    ptrarray_free(pa);
    return d;
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
    if (!pa->count) return;
    qsort(pa->data, pa->count, sizeof(void*),
            (int (*)(const void *, const void *))compare);
}

EXPORTED int ptrarray_size(const ptrarray_t *pa)
{
    if (!pa) return 0;
    return pa->count;
}
