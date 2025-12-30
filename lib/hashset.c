/* hashset.c -- library for building a set of hashed keys (evenly distributed) */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <string.h>

#include "assert.h"
#include "hashset.h"
#include "xmalloc.h"
#include "util.h"

EXPORTED struct hashset *hashset_new(size_t bytesize)
{
    assert(bytesize > 2);
    assert(bytesize <= 128);
    struct hashset *hs = xzmalloc(sizeof(struct hashset));
    hs->recsize = bytesize + 4;
    hs->bytesize = bytesize;
    return hs;
}

// returns 1 if added, 0 if already there
EXPORTED int hashset_add(struct hashset *hs, const void *value)
{
    assert(hs);
    uint32_t *pos = &hs->starts[*((uint16_t *)value)];
    uint32_t *base = pos;
    size_t offset = 0;
    while (*pos) {
        offset = hs->recsize * (*pos - 1);
        if (!memcmp(hs->data+offset, value, hs->bytesize))
            return 0; // found it
        pos = hs->data + offset + hs->bytesize;
    }

    // make space
    if (hs->alloc <= hs->count) {
        if (!hs->alloc) {
            hs->alloc = 1024;
            hs->data = xmalloc(hs->alloc * hs->recsize);
        }
        else {
            hs->alloc *= 2;  // double the allocation each time
            hs->data = xrealloc(hs->data, hs->alloc * hs->recsize);

            // relocate after realloc if necessary
            if (pos != base)
                pos = hs->data + offset + hs->bytesize;
        }

    }

    offset = hs->recsize * hs->count;
    memcpy(hs->data + offset, value, hs->bytesize);
    memset(hs->data + offset + hs->bytesize, 0, 4);

    // make pointers start at 1 so the value is never zero
    hs->count++;
    *pos = hs->count;

    return 1; // added it
}

// returns 1 if present, 0 if not
EXPORTED int hashset_exists(struct hashset *hs, const void *data)
{
    if (!hs) return 0;

    uint32_t pos = hs->starts[*((uint16_t *)data)];
    while (pos) {
        size_t offset = hs->recsize * (pos - 1);
        if (!memcmp(hs->data+offset, data, hs->bytesize))
            return 1; // found it
        pos = *(uint32_t *) (hs->data + offset + hs->bytesize);
    }

    return 0; // not found
}

EXPORTED void hashset_free(struct hashset **hsp)
{
    free((*hsp)->data);
    xzfree(*hsp);
}
