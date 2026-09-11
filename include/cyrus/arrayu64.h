/* arrayu64.h - an expanding array of 64 bit unsigned integers */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef __CYRUS_ARRAYU64_H__
#define __CYRUS_ARRAYU64_H__

#include <sys/types.h>

#include <stdint.h>

typedef struct
{
    size_t count;
    size_t alloc;
    uint64_t *data;
} arrayu64_t;

#define ARRAYU64_INITIALIZER    { 0, 0, NULL }
#define arrayu64_init(sa)   (memset((sa), 0, sizeof(arrayu64_t)))
void arrayu64_fini(arrayu64_t *);

arrayu64_t *arrayu64_new(void);
void arrayu64_free(arrayu64_t *);

int arrayu64_append(arrayu64_t *, uint64_t);
int arrayu64_add(arrayu64_t *, uint64_t);
void arrayu64_set(arrayu64_t *, int idx, uint64_t);
void arrayu64_insert(arrayu64_t *, int idx, uint64_t);
uint64_t arrayu64_remove(arrayu64_t *, int idx);
/* returns number removed */
int arrayu64_remove_all(arrayu64_t *, uint64_t);
uint64_t arrayu64_nth(const arrayu64_t *, int idx);
void arrayu64_truncate(arrayu64_t *, size_t newlen);
arrayu64_t *arrayu64_dup(const arrayu64_t *);

uint64_t arrayu64_max(const arrayu64_t *);

#define arrayu64_shift(sa)          arrayu64_remove((sa), 0)
#define arrayu64_unshift(sa, s)     arrayu64_insert((sa), 0, (s))

#define arrayu64_pop(sa)            arrayu64_remove((sa), -1)
#define arrayu64_push(sa, s)        arrayu64_append((sa), (s))

/* arrayu64_cmp_fn_t is same sig as qsort's compar argument */
typedef int arrayu64_cmp_fn_t(const void *, const void *);
void arrayu64_sort(arrayu64_t *, arrayu64_cmp_fn_t *);

void arrayu64_uniq(arrayu64_t *);

size_t arrayu64_size(const arrayu64_t *);

off_t arrayu64_find(const arrayu64_t *au, uint64_t val, off_t start);
off_t arrayu64_bsearch(const arrayu64_t *au, uint64_t val);

#endif /* __CYRUS_ARRAYU64_H__ */
