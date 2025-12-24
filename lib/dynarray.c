/* dynarray.c -- an expanding array of same-size members */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <assert.h>
#include <memory.h>

#include "dynarray.h"
#include "util.h"
#include "xmalloc.h"

EXPORTED void dynarray_init(struct dynarray *da, size_t membsize)
{
    assert(membsize);
    memset(da, 0, sizeof(struct dynarray));
    da->membsize = membsize;
}

EXPORTED void dynarray_fini(struct dynarray *da)
{
    size_t membsize = da->membsize;
    free(da->data);
    memset(da, 0, sizeof(struct dynarray));
    da->membsize = membsize;
}

EXPORTED struct dynarray *dynarray_new(size_t membsize)
{
    struct dynarray *da = xmalloc(sizeof(struct dynarray));
    dynarray_init(da, membsize);
    return da;
}

EXPORTED void dynarray_free(struct dynarray **dap)
{
    if (!dap || *dap == NULL) return;
    free((*dap)->data);
    free(*dap);
    *dap = NULL;
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
static void ensure_alloc(struct dynarray *da, int newalloc)
{
    assert(newalloc >= 0);
    assert(da->membsize > 0);
    if (newalloc < da->alloc)
        return;
    newalloc = grow(da->alloc, newalloc + 1);
    da->data = xzrealloc(da->data,
                         da->membsize * da->alloc,
                         da->membsize * newalloc);
    da->alloc = newalloc;
}


static inline int adjust_index_ro(const struct dynarray *da, int idx)
{
    if (idx >= da->count)
        return -1;
    else if (idx < 0)
        idx += da->count;
    return idx;
}

static inline int adjust_index_rw(struct dynarray *da, int idx, int len)
{
    if (idx >= da->count) {
        ensure_alloc(da, idx+len);
    } else if (idx < 0) {
        idx += da->count;
        if (idx >= 0 && len)
            ensure_alloc(da, da->count+len);
    } else if (len) {
        ensure_alloc(da, da->count+len);
    }
    return idx;
}

EXPORTED int dynarray_size(struct dynarray *da)
{
    return da->count;
}

__attribute__((unused))
static char *dump(struct dynarray *da)
{
    struct buf buf = BUF_INITIALIZER;
    buf_printf(&buf, "{membsize=%zu count=%d alloc=%d data=%p: ", da->membsize, da->count, da->alloc, da->data);
    int i;
    for (i = 0; i < da->alloc; i++) {
        void *memb = da->data + i * da->membsize;
        buf_putc(&buf, '[');
        size_t j;
        for (j = 0; j < da->membsize; j++) {
            buf_printf(&buf, "%02x", *((unsigned char*) memb + j) & 0xff);
            if (j < da->membsize - 1) buf_putc(&buf, ' ');
        }
        buf_putc(&buf, ']');
    }
    buf_cstring(&buf);
    return buf_release(&buf);
}

EXPORTED int dynarray_append(struct dynarray *da, void *memb)
{
    ensure_alloc(da, da->count+1);
    memcpy(da->data + da->count * da->membsize, memb, da->membsize);
    return da->count++;
}

EXPORTED int dynarray_append_empty(struct dynarray *da, void **out_memb)
{
    void *memb;

    ensure_alloc(da, da->count+1);
    memb = da->data + da->count * da->membsize;
    memset(memb, 0, da->membsize);
    if (out_memb) *out_memb = memb;
    return da->count++;
}

EXPORTED void dynarray_set(struct dynarray *da, int idx, void *memb)
{
    if ((idx = adjust_index_rw(da, idx, 0)) < 0)
        return;
    memcpy(da->data + idx * da->membsize, memb, da->membsize);
    if (idx >= da->count)
        da->count = idx + 1;
}

EXPORTED void *dynarray_nth(const struct dynarray *da, int idx)
{
    if ((idx = adjust_index_ro(da, idx)) < 0)
        return NULL;
    return da->data + idx * da->membsize;
}

EXPORTED void dynarray_truncate(struct dynarray *da, int newlen)
{
    if (newlen == da->count)
        return;

    if (newlen > da->count) {
        ensure_alloc(da, newlen);
    } else {
        int i;
        for (i = newlen ; i < da->count ; i++) {
            memset(da->data + i * da->membsize, 0, da->membsize);
        }
    }
    da->count = newlen;
}

EXPORTED void dynarray_sort(struct dynarray *da,
                            int (*compare)(const void *, const void *))
{
    if (!da || !da->count) return;

    qsort(da->data, da->count, da->membsize,
            (int (*)(const void *, const void *))compare);
}
