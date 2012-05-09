/* bitvector.h -- bit vector functions
 *
 * Copyright (c) 1994-2012 Carnegie Mellon University.  All rights reserved.
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

#ifndef __CYRUS_LIB_BITVECTOR_H__
#define __CYRUS_LIB_BITVECTOR_H__

#include <config.h>
#include <sys/types.h>
#include <limits.h>

typedef struct bitvector bitvector_t;

struct bitvector
{
    unsigned int length;
    unsigned int alloc;
    unsigned char *bits;
};

#define BV_INITIALIZER	{ 0, 0, NULL }

extern void bv_init(bitvector_t *);
extern void bv_setsize(bitvector_t *, unsigned int i);
extern void bv_prealloc(bitvector_t *, unsigned int);
extern void bv_copy(bitvector_t *to, const bitvector_t *from);
extern void bv_clearall(bitvector_t *);
extern void bv_setall(bitvector_t *);
extern int bv_isset(const bitvector_t *, unsigned int);
extern void bv_set(bitvector_t *, unsigned int);
extern void bv_clear(bitvector_t *, unsigned int);
extern void bv_andeq(bitvector_t *a, const bitvector_t *b);
extern void bv_oreq(bitvector_t *a, const bitvector_t *b);
extern char *bv_cstring(const bitvector_t *);
extern void bv_free(bitvector_t *);

#endif /* __CYRUS_LIB_BITVECTOR_H__ */
