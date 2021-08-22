/* hashset.c -- library for building a set of hashed keys (evenly distributed)
 *
 * Copyright (c) 2018 Carnegie Mellon University.  All rights reserved.
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
 */

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
