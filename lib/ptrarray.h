/* ptrarray.h -- an expanding array of pointers
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

#ifndef __CYRUS_PTRARRAY_H__
#define __CYRUS_PTRARRAY_H__

#include <config.h>
#include <sys/types.h>

typedef struct
{
    int count;
    int alloc;
    void **data;
} ptrarray_t;

#define PTRARRAY_INITIALIZER    { 0, 0, NULL }
#define ptrarray_init(pa)   (memset((pa), 0, sizeof(ptrarray_t)))
void ptrarray_fini(ptrarray_t *);

ptrarray_t *ptrarray_new(void);
void ptrarray_free(ptrarray_t *);

void ptrarray_append(ptrarray_t *, void *);
void ptrarray_add(ptrarray_t *, void *);
void ptrarray_set(ptrarray_t *, int idx, void *);
void ptrarray_insert(ptrarray_t *, int idx, void *);
void *ptrarray_remove(ptrarray_t *, int idx);
void *ptrarray_nth(const ptrarray_t *pa, int idx);
void ptrarray_truncate(ptrarray_t *pa, int newlen);

#define ptrarray_shift(pa)          ptrarray_remove((pa), 0)
#define ptrarray_unshift(pa, s)     ptrarray_insert((pa), 0, (s))

#define ptrarray_pop(pa)            ptrarray_remove((pa), -1)
#define ptrarray_push(pa, s)        ptrarray_append((pa), (s))

#define ptrarray_tail(pa)           ptrarray_nth((pa), -1)
#define ptrarray_head(pa)           ptrarray_nth((pa), 0)

int ptrarray_find(const ptrarray_t *pa, void *match,
                  int starting);

void ptrarray_sort(ptrarray_t *pa, int (*compare)(const void **, const void **));

int ptrarray_size(const ptrarray_t *pa);

#endif /* __CYRUS_PTRARRAY_H__ */
