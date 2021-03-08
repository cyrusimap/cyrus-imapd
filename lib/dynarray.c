/* dynarray.c -- an expanding array of same-size members
 *
 * Copyright (c) 1994-2020 Carnegie Mellon University.  All rights reserved.
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
 */

#include <assert.h>
#include <memory.h>

#include "dynarray.h"
#include "util.h"
#include "xmalloc.h"

EXPORTED struct dynarray *dynarray_new(size_t membsize)
{
    assert(membsize);
    struct dynarray *da = xzmalloc(sizeof(struct dynarray));
    da->membsize = membsize;
    return da;
}

EXPORTED void dynarray_free(struct dynarray **dap)
{
    if (!dap || *dap == NULL) return;
    free((*dap)->data);
    free(*dap);
    *dap = NULL;
}

/*
 * Ensure the index @newalloc exists in the array, if necessary expanding the
 * array, and if necessary NULL-filling all the intervening elements.
 * Note that we always ensure an empty slot past the last reported
 * index, so that we can pass data[] to execve() or other routines that
 * assume a NULL terminator.
 */
#define QUANTUM     16
static void ensure_alloc(struct dynarray *da, int newalloc)
{
    assert(newalloc >= 0);
    if (newalloc)
        newalloc++;
    if (newalloc <= da->alloc)
        return;
    newalloc = ((newalloc + QUANTUM-1) / QUANTUM) * QUANTUM;
    da->data = xrealloc(da->data, da->membsize * newalloc);
    memset(da->data + da->alloc * da->membsize, 0, da->membsize * (newalloc-da->alloc));
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

EXPORTED void dynarray_append(struct dynarray *da, void *memb)
{
    ensure_alloc(da, da->count+1);
    memcpy(da->data + da->count * da->membsize, memb, da->membsize);
    da->count++;
}

EXPORTED void dynarray_set(struct dynarray *da, int idx, void *memb)
{
    if ((idx = adjust_index_rw(da, idx, 0)) < 0)
        return;
    memcpy(da->data + idx * da->membsize, memb, da->membsize);
}

EXPORTED void *dynarray_nth(const struct dynarray *da, int idx)
{
    if ((idx = adjust_index_ro(da, idx)) < 0)
        return NULL;
    return da->data + idx * da->membsize;
}
