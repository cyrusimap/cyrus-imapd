/* mpool.c memory pool management
 *
 * $Id: mpool.c,v 1.9 2002/11/04 19:55:52 rjs3 Exp $
 * Copyright (c) 2001 Carnegie Mellon University.  All rights reserved.
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
 *    prior written permission. For permission or any other legal
 *    details, please contact  
 *      Office of Technology Transfer
 *      Carnegie Mellon University
 *      5000 Forbes Avenue
 *      Pittsburgh, PA  15213-3890
 *      (412) 268-4387, fax: (412) 268-7395
 *      tech-transfer@andrew.cmu.edu
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

#include <sys/time.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <signal.h>
#include <time.h>
#include <stdlib.h>
#include <assert.h>
#include <syslog.h>
#include <errno.h>

#include "mpool.h"
#include "xmalloc.h"
#include "exitcodes.h"

struct mpool 
{
    struct mpool_blob *blob;
};

struct mpool_blob
{
    size_t size;
    void *base; /* Base of allocated section */
    void *ptr; /* End of allocated section */
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
struct mpool *new_mpool(size_t size) 
{
    struct mpool *ret = xmalloc(sizeof(struct mpool));

    ret->blob = new_mpool_blob(size);
    
    return ret;
}

/* Free a pool */
void free_mpool(struct mpool *pool) 
{
    struct mpool_blob *p, *p_next;

    if(!pool) return;
    if(!pool->blob) {
	fatal("memory pool without a blob",EC_TEMPFAIL);
	return;
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

/* bump to the next multiple of 8 bytes */
#define ROUNDUP(num) (((num) + 15) & 0xFFFFFFF0)

/* Allocate from a pool */
void *mpool_malloc(struct mpool *pool, size_t size) 
{
    void *ret = NULL;
    struct mpool_blob *p;
    size_t remain;
    
    if(!pool || !pool->blob) {
	fatal("mpool_malloc called without a valid pool", EC_TEMPFAIL);
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

    if(remain < size ||
       (unsigned int)p->ptr > (p->size + (unsigned int)p->base)) {
      	/* Need a new pool */
	struct mpool_blob *new_pool;
       	size_t new_pool_size = 2 * ((size > p->size) ? size : p->size);
	
	new_pool = new_mpool_blob(new_pool_size);
	new_pool->next = p;
	p = pool->blob = new_pool;
    }

    ret = p->ptr;
    p->ptr = (void *)ROUNDUP((unsigned int)p->ptr + size);

    return ret;
}

char *mpool_strdup(struct mpool *pool, const char *str) 
{
    char *ret;
    size_t len;
    
    if(!str) return NULL;
    
    len = strlen(str);
    
    ret = mpool_malloc(pool, len+1);
    strcpy(ret, str);

    return ret;
}

