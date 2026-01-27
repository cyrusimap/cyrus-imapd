/* bitvector.h - bit vector functions */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef __CYRUS_LIB_BITVECTOR_H__
#define __CYRUS_LIB_BITVECTOR_H__

typedef struct bitvector bitvector_t;

#define BV_NOALLOCSIZE 8

struct bitvector
{
    unsigned int length;
    unsigned int alloc;
    /* TODO: should use natural word size, uint32_t or uint64_t,
     * for faster searching in bv_next_set() */
    union {
        unsigned char *alloced;
        unsigned char _noalloc[BV_NOALLOCSIZE];
    } bits;
};

#define BV_INITIALIZER  { 0, 0, {0} }

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
extern int bv_next_set(const bitvector_t *, int start);
extern int bv_prev_set(const bitvector_t *, int start);
extern int bv_first_set(const bitvector_t *);
extern int bv_last_set(const bitvector_t *);
extern unsigned bv_count(const bitvector_t *);
extern char *bv_cstring(const bitvector_t *);
extern void bv_fini(bitvector_t *);

#endif /* __CYRUS_LIB_BITVECTOR_H__ */
