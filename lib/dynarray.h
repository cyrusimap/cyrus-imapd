/* dynarray.h - an expanding array of same-size members */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef __CYRUS_DYNARRAY_H__
#define __CYRUS_DYNARRAY_H__

typedef struct dynarray {
    size_t membsize;
    int count;
    int alloc;
    void *data;
} dynarray_t;

#define DYNARRAY_INITIALIZER(membsize) { (membsize), 0, 0, NULL }

extern void dynarray_init(struct dynarray *da, size_t membsize);
extern void dynarray_fini(struct dynarray *da);

extern struct dynarray *dynarray_new(size_t membsize);
extern void dynarray_free(struct dynarray **dap);

extern int dynarray_append(struct dynarray *da, void *memb);
extern int dynarray_append_empty(struct dynarray *da, void **out_memb);
extern void dynarray_set(struct dynarray *, int idx, void *memb);
extern void *dynarray_nth(const struct dynarray *da, int idx);
extern int dynarray_size(struct dynarray *da);
extern void dynarray_truncate(struct dynarray *da, int newlen);
extern void dynarray_sort(struct dynarray *da,
                          int (*compare)(const void *, const void *));

#endif /* __CYRUS_DYNARRAY_H__ */
