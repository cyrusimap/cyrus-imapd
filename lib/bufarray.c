/* buf.c -- buffer library
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
    ba->items = xrealloc(ba->items, sizeof(struct buf) * newalloc);
    memset(ba->items + ba->alloc, 0, sizeof(struct buf) * (newalloc - ba->alloc));
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
