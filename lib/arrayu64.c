/* arrayu64.c - expanding array of 64 bit unsigned numbers
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
 * Author: Bron Gondwana
 * Start Date: 2013/02/12
 */

#include <config.h>

#include <string.h>

#include "arrayu64.h"
#include "util.h"
#include "xmalloc.h"

EXPORTED arrayu64_t *arrayu64_new(void)
{
    return xzmalloc(sizeof(arrayu64_t));
}

EXPORTED void arrayu64_fini(arrayu64_t *au)
{
    if (!au)
        return;
    free(au->data);
    au->data = NULL;
    au->count = 0;
    au->alloc = 0;
}

EXPORTED void arrayu64_free(arrayu64_t *au)
{
    if (!au)
        return;
    arrayu64_fini(au);
    free(au);
}

#define QUANTUM     16
static inline size_t grow(size_t have, size_t want)
{
    size_t x = MAX(QUANTUM, have);
    while (x < want)
        x *= 2;
    return x;
}

/* XXX n.b. unlike some other ensure_allocs, this one doesn't always
 * XXX leave an extra NULL at the end.
 */
static void ensure_alloc(arrayu64_t *au, size_t newalloc)
{
    if (newalloc <= au->alloc)
        return;
    newalloc = grow(au->alloc, newalloc);
    au->data = xrealloc(au->data, sizeof(uint64_t) * newalloc);
    memset(au->data + au->alloc, 0, sizeof(uint64_t) * (newalloc - au->alloc));
    au->alloc = newalloc;
}

/*
 * Normalise the index passed by a caller, to a value in the range
 * 0..count-1, or < 0 for invalid, assuming the function we're
 * performing does not have the side effect of expanding the array.
 * Note that doesn't necessarily mean the array is read-only, e.g.
 * arrayu64_remove() modifies the array but does not expand the array if
 * given an index outside the array's current bounds.  In Perl style,
 * negative indexes whose absolute value is less than the length of the
 * array are treated as counting back from the end, e.g.  idx=-1 means
 * the final element.
 */
static inline int adjust_index_ro(const arrayu64_t *au, int idx)
{
    if (idx >= 0 && (unsigned) idx >= au->count)
        return -1;
    else if (idx < 0)
        idx += au->count;
    return idx;
}

/*
 * Like adjust_index_ro(), with extra complication that the function
 * we're performing will expand the array if either the adjusted index
 * points outside the current bounds of the array, or @grow tells us
 * that we're about to need more space in the array.
 */
static inline int adjust_index_rw(arrayu64_t *au, int idx, int grow)
{
    if (idx >= 0 && (unsigned) idx >= au->count) {
        /* expanding the array as a side effect @idx pointing
         * outside the current bounds, plus perhaps @grow */
        ensure_alloc(au, idx+grow);
    } else if (idx < 0) {
        /* adjust Perl-style negative indices */
        idx += au->count;
        if (idx >= 0 && grow)
            ensure_alloc(au, au->count+grow);
    } else if (grow) {
        /* expanding the array due to an insert or append */
        ensure_alloc(au, au->count+grow);
    }
    return idx;
}

EXPORTED arrayu64_t *arrayu64_dup(const arrayu64_t *au)
{
    arrayu64_t *new = arrayu64_new();
    size_t i;

    arrayu64_truncate(new, au->count);

    for (i = 0 ; i < au->count ; i++)
        new->data[i] = au->data[i];

    return new;
}

EXPORTED int arrayu64_append(arrayu64_t *au, uint64_t val)
{
    int pos = au->count++;
    ensure_alloc(au, au->count);
    au->data[pos] = val;
    return pos;
}

EXPORTED int arrayu64_add(arrayu64_t *au, uint64_t val)
{
    int pos = arrayu64_find(au, val, 0);
    if (pos < 0) pos = arrayu64_append(au, val);
    return pos;
}

EXPORTED void arrayu64_set(arrayu64_t *au, int idx, uint64_t val)
{
    if ((idx = adjust_index_rw(au, idx, 0)) < 0)
        return;
    au->data[idx] = val;
    /* adjust the count if we just sparsely expanded the array */
    if ((unsigned) idx >= au->count)
        au->count = idx+1;
}


EXPORTED void arrayu64_insert(arrayu64_t *au, int idx, uint64_t val)
{
    if ((idx = adjust_index_rw(au, idx, 1)) < 0)
        return;
    if ((unsigned) idx < au->count)
        memmove(au->data+idx+1, au->data+idx,
                sizeof(uint64_t) * (au->count-idx));
    au->data[idx] = val;
    au->count++;
}

EXPORTED uint64_t arrayu64_remove(arrayu64_t *au, int idx)
{
    uint64_t val;
    if ((idx = adjust_index_ro(au, idx)) < 0)
        return 0;
    val = au->data[idx];
    au->count--;
    if ((unsigned) idx < au->count)
        memmove(au->data+idx, au->data+idx+1,
                sizeof(uint64_t) * (au->count-idx));
    au->data[au->count] = 0;
    return val;
}

EXPORTED int arrayu64_remove_all(arrayu64_t *au, uint64_t val)
{
    int i = 0;
    int count = 0;

    for (;;) {
        i = arrayu64_find(au, val, i);
        if (i < 0)
            break;
        count++;
        arrayu64_remove(au, i);
    }

    return count;
}

EXPORTED void arrayu64_truncate(arrayu64_t *au, size_t newlen)
{
    if (newlen == au->count)
        return;

    if (newlen > au->count) {
        ensure_alloc(au, newlen);
    }
    else {
        memset(au->data+newlen, 0, sizeof(uint64_t) * (au->count - newlen));
    }

    au->count = newlen;
}

/* note: values outside the range are all zero */
EXPORTED uint64_t arrayu64_nth(const arrayu64_t *au, int idx)
{
    if ((idx = adjust_index_ro(au, idx)) < 0)
        return 0;
    return au->data[idx];
}

EXPORTED uint64_t arrayu64_max(const arrayu64_t *au)
{
    uint64_t max = 0;
    size_t i;

    for (i = 0; i < au->count; i++) {
        if (au->data[i] > max)
            max = au->data[i];
    }

    return max;
}

static int _numeric_sort(const void *a, const void *b)
{
    uint64_t av = *((uint64_t *)a);
    uint64_t bv = *((uint64_t *)b);

    if (av == bv)
        return 0;
    if (av < bv)
        return -1;
    return 1;
}

EXPORTED void arrayu64_sort(arrayu64_t *au, arrayu64_cmp_fn_t *cmp)
{
    if (!cmp) cmp = _numeric_sort;
    qsort(au->data, au->count, sizeof(uint64_t), cmp);
}

EXPORTED void arrayu64_uniq(arrayu64_t *au)
{
    size_t i;

    for (i = 1; i < au->count; i++) {
        if (au->data[i-1] == au->data[i])
            arrayu64_remove(au, i--);
    }
}

EXPORTED off_t arrayu64_find(const arrayu64_t *au, uint64_t val, off_t idx)
{
    size_t i;

    if ((idx = adjust_index_ro(au, idx)) < 0)
        return -1;

    for (i = idx; i < au->count; i++) {
        if (au->data[i] == val)
            return i;
    }

    return -1;
}

// needs a sorted array
EXPORTED off_t arrayu64_bsearch(const arrayu64_t *au, uint64_t val)
{
    if (!au->count) return -1;

    size_t low = 0;
    size_t high = au->count - 1;

    while (low <= high) {
        off_t mid = (high - low)/2 + low;
        uint64_t this = arrayu64_nth(au, mid);
        if (this == val)
            return mid;
        if (this > val)
            high = mid - 1;
        else
            low = mid + 1;
    }
    return -1;
}

EXPORTED size_t arrayu64_size(const arrayu64_t *au)
{
    return au->count;
}
