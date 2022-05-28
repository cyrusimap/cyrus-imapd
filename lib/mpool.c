/* mpool.c memory pool management
 *
 * Copyright (c) 1994-2008 Carnegie Mellon University.  All rights reserved.
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

#include <config.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <sysexits.h>

#include "mpool.h"
#include "xmalloc.h"

struct mpool
{
    struct mpool_blob *blob;
};

struct mpool_blob
{
    size_t size;
    unsigned char *base; /* Base of allocated section */
    unsigned char *ptr; /* End of allocated section */
    struct mpool_blob *next; /* Next Pool */
};

static struct mpool_blob *new_mpool_blob(size_t size)
{
    struct mpool_blob *blob = xmalloc(sizeof(struct mpool_blob));

    if(!size) size = DEFAULT_MPOOL_SIZE;

    blob->base = blob->ptr = xmalloc(size);
    blob->size = size;
    blob->next = NULL;

    return blob;
}

/* Create a new pool */
EXPORTED struct mpool *new_mpool(size_t size)
{
    struct mpool *ret = xmalloc(sizeof(struct mpool));

    ret->blob = new_mpool_blob(size);

    return ret;
}

/* Free a pool */
EXPORTED void free_mpool(struct mpool *pool)
{
    struct mpool_blob *p, *p_next;

    if (!pool) return;
    if (!pool->blob) {
        fatal("memory pool without a blob", EX_TEMPFAIL);
    }

    p = pool->blob;

    while(p) {
        p_next = p->next;
        free(p->base);
        free(p);
        p = p_next;
    }

    free(pool);
}

#ifdef ROUNDUP
#undef ROUNDUP
#endif

/* round up to the next multiple of 16 bytes if necessary */
/* 0xFF...FFF0 = ~0 ^ 0xF */
#define ROUNDUP(num) (((num) + 15) & (~((unsigned long) 0x0) ^ 0xF))

/* Allocate from a pool */
EXPORTED void *mpool_malloc(struct mpool *pool, size_t size)
{
    void *ret = NULL;
    struct mpool_blob *p;
    size_t remain;

    if(!pool || !pool->blob) {
        fatal("mpool_malloc called without a valid pool", EX_TEMPFAIL);
    }
    if(!size) {
        /* This is legal under ANSI C, so we should allow it too */
        size = 1;
    }

    p = pool->blob;

    /* This is a bit tricky, not only do we have to make sure that the current
     * pool has enough room, we need to be sure that we haven't rounded p->ptr
     * outside of the current pool anyway */

    remain = p->size - ((char *)p->ptr - (char *)p->base);

    if (remain < size ||
        (char *) p->ptr > (p->size + (char *) p->base)) {
        /* Need a new pool */
        struct mpool_blob *new_pool;
        size_t new_pool_size = 2 * ((size > p->size) ? size : p->size);

        new_pool = new_mpool_blob(new_pool_size);
        new_pool->next = p;
        p = pool->blob = new_pool;
    }

    ret = p->ptr;

    /* make sure that the next thing we allocate is align on
       a ROUNDUP boundary */
    p->ptr = p->base + ROUNDUP(p->ptr - p->base + size);

    return ret;
}

EXPORTED char *mpool_strndup(struct mpool *pool, const char *str, size_t n)
{
    char *ret;

    if(!str) return NULL;

    ret = mpool_malloc(pool, n+1);
    strncpy(ret, str, n);
    ret[n] = '\0';

    return ret;
}


EXPORTED char *mpool_strdup(struct mpool *pool, const char *str)
{
    size_t len;

    if(!str) return NULL;

    len = strlen(str);

    return mpool_strndup(pool, str, len);
}
