/* mpool.c memory pool management
 *
 * $Id: mpool.c,v 1.1 2002/02/07 19:45:42 rjs3 Exp $
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

/* Create a new pool */
struct mpool *new_mpool(size_t size) 
{
    struct mpool *ret = xmalloc(sizeof(struct mpool));

    ret->base = ret->ptr = xzmalloc(size);
    ret->size = size;
    ret->next = NULL;
    
    return ret;
}

/* Free a pool */
void free_mpool(struct mpool *pool) 
{
    struct mpool *p_next;
    
    if(!pool) return;

    while(pool) {
	p_next = pool->next;
	free(pool);
	pool = p_next;
    }
}

/* Allocate from a pool */
void *mpool_malloc(struct mpool **pool, size_t size) 
{
    void *ret = NULL;
    struct mpool *p;
    size_t remain;
    
    if(!pool || !(*pool)) {
	fatal("mpool_malloc called without a pool", EC_TEMPFAIL);
    }
    if(!size) {
	fatal("mpool_malloc called with size = 0", EC_TEMPFAIL);
    }

    p = *pool;
    
    remain = p->size - (p->ptr - p->base);
    if(remain < size) {
      	/* Need a new pool */
	struct mpool *new_pool;
       	size_t new_pool_size = 2 * ((size > p->size) ? size : p->size);
	
	new_pool = new_mpool(new_pool_size);
	new_pool->next = p;
	p = *pool = new_pool;
    }

    ret = p->ptr;
    p->ptr += size;

    return ret;
}

