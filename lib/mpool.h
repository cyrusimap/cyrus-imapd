/* mpool.h memory pool management
 *
 * $Id: mpool.h,v 1.6 2002/02/20 19:30:26 leg Exp $
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

#ifndef _MPOOL_H_

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

/* xxx is there a reason struct mpool isn't opaque ? */
struct mpool_blob;

struct mpool 
{
    struct mpool_blob *blob;
};

#define DEFAULT_MPOOL_SIZE 32768

/* Create a new pool -- pass zero for default */
/* xxx 'size' is an estimate; maximum size for allocated object ? */
struct mpool *new_mpool(size_t size);

/* Free a pool */
void free_mpool(struct mpool *pool);

/* Allocate from a pool */
void *mpool_malloc(struct mpool *pool, size_t size);
char *mpool_strdup(struct mpool *pool, const char *str);

#endif /* _MPOOL_H_ */
