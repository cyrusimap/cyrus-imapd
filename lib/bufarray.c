/* buf.c -- buffer library */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include "bufarray.h"
#include <memory.h>
#include "util.h"
#include "xmalloc.h"

EXPORTED bufarray_t *bufarray_new(void)
{
    return xzmalloc(sizeof(bufarray_t));
}

EXPORTED void bufarray_fini(bufarray_t *ba)
{
    size_t i;

    if (!ba)
        return;
    for (i = 0 ; i < ba->count ; i++) {
        buf_free(ba->items[i]);
        free(ba->items[i]);
        ba->items[i] = NULL;
    }
    free(ba->items);
    ba->items = NULL;
    ba->count = 0;
    ba->alloc = 0;
}

EXPORTED void bufarray_free(bufarray_t **ba)
{
    if (!ba || !*ba)
        return;
    bufarray_fini(*ba);
    free(*ba);
    *ba = NULL;
}

#define QUANTUM     16
static inline size_t grow(size_t have, size_t want)
{
    size_t x = MAX(QUANTUM, have);
    while (x < want)
        x *= 2;
    return x;
}

/*
 * Ensure the index @newalloc exists in the array, if necessary expanding the
 * array, and if necessary NULL-filling all the intervening elements.
 */
static void ba_ensure_alloc(bufarray_t *ba, size_t newalloc)
{
    if (newalloc < ba->alloc)
        return;
    newalloc = grow(ba->alloc, newalloc + 1);
    ba->items = xzrealloc(ba->items,
                          sizeof(struct buf) * ba->alloc,
                          sizeof(struct buf) * newalloc);
    ba->alloc = newalloc;
}

EXPORTED bufarray_t *bufarray_dup(const bufarray_t *ba)
{
    bufarray_t *new = bufarray_new();
    size_t i;

    bufarray_truncate(new, ba->count);
    for (i = 0 ; i < ba->count ; i++) {
        new->items[i] = buf_new();
        buf_setmap(new->items[i], ba->items[i]->s, ba->items[i]->len);
    }

    return new;
}

EXPORTED size_t bufarray_append(bufarray_t *ba, const struct buf *buf)
{
    struct buf *new = xzmalloc(sizeof(struct buf));
    buf_copy(new, buf);
    return bufarray_appendm(ba, new);
}

EXPORTED size_t bufarray_appendm(bufarray_t *ba, struct buf *buf)
{
    int pos = ba->count++;
    ba_ensure_alloc(ba, ba->count);
    ba->items[pos] = buf;
    return pos;
}

EXPORTED void bufarray_truncate(bufarray_t *ba, size_t newlen)
{
    size_t i;

    if (newlen == ba->count)
        return;

    if (newlen > ba->count) {
        ba_ensure_alloc(ba, newlen);
    } else {
        for (i = newlen ; i < ba->count ; i++) {
            buf_free(ba->items[i]);
            free(ba->items[i]);
            ba->items[i] = 0;
        }
    }
    ba->count = newlen;
}

EXPORTED const struct buf *bufarray_nth(const bufarray_t *ba, size_t idx)
{
    return ba->items[idx];
}

EXPORTED size_t bufarray_size(const bufarray_t *ba)
{
    return ba->count;
}
