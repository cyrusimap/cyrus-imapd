/* ptrarray.h -- an expanding array of pointers */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

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

void **ptrarray_takevf(ptrarray_t *pa);

int ptrarray_find(const ptrarray_t *pa, void *match,
                  int starting);

void ptrarray_sort(ptrarray_t *pa, int (*compare)(const void **, const void **));

int ptrarray_size(const ptrarray_t *pa);

#endif /* __CYRUS_PTRARRAY_H__ */
