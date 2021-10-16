/* bitvector.c -- bit vector functions
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

#include <config.h>

#include <sys/types.h>
#include <stdlib.h>
#include <string.h>

#include "xmalloc.h"
#include "bitvector.h"
#include "util.h"

#ifndef MAX
#define MAX(a,b)    ((a)>(b)?(a):(b))
#endif

#define BITS_PER_UNIT   8
#define vidx(x)         ((x) >> 3)
#define visaligned(x)   (!((x) & 0x7))
#define vmask(x)        (1 << ((x) & 0x7))
#define vtailmask(x)    ((unsigned char)(0xff << ((x) & 0x7)))
#define vlen(x)         vidx((x)+7)
#define QUANTUM         (256)
#define bv_bits(bv)     (bv->alloc ? bv->bits.alloced : bv->bits._noalloc)


EXPORTED void bv_init(bitvector_t *bv)
{
    memset(bv, 0, sizeof(*bv));
}

/* Ensure that the array contains enough memory for @len
 * bits, expanding the bitvector if necessary */
static void bv_ensure(bitvector_t *bv, unsigned int len)
{
    len = vlen(len);        /* now number of bytes */

    if ((!bv->alloc && len > BV_NOALLOCSIZE) || (bv->alloc && len > bv->alloc)) {
        unsigned int newalloc = ((len + QUANTUM-1) / QUANTUM) * QUANTUM;
        if (!bv->alloc) {
            unsigned char *alloced = xzmalloc(newalloc);
            memcpy(alloced, bv->bits._noalloc, BV_NOALLOCSIZE);
            bv->bits.alloced = alloced;
        }
        else {
            bv->bits.alloced = xrealloc(bv->bits.alloced, newalloc);
            memset(bv->bits.alloced + bv->alloc, 0, newalloc - bv->alloc);
        }
        bv->alloc = newalloc;
    }
}

EXPORTED void bv_setsize(bitvector_t *bv, unsigned int len)
{
    bv_ensure(bv, len);
    if (len < bv->length) {
        /* shrinking - need to clear old bits */
        memset(bv_bits(bv)+vlen(len), 0, vlen(bv->length) - vlen(len));
        bv_bits(bv)[vidx(len)] &= ~vtailmask(len);
    }
    bv->length = len;
}

EXPORTED void bv_prealloc(bitvector_t *bv, unsigned int len)
{
    bv_ensure(bv, len);
}

EXPORTED void bv_copy(bitvector_t *to, const bitvector_t *from)
{
    bv_setsize(to, from->length);
    memcpy(bv_bits(to), bv_bits(from), vlen(from->length));
}

EXPORTED void bv_clearall(bitvector_t *bv)
{
    if (bv->length)
        memset(bv_bits(bv), 0, vlen(bv->length));
}

EXPORTED void bv_setall(bitvector_t *bv)
{
    if (bv->length)
        memset(bv_bits(bv), 0xff, vlen(bv->length));
}

EXPORTED int bv_isset(const bitvector_t *bv, unsigned int i)
{
    if (i >= bv->length)
        return 0;
    return !!(bv_bits(bv)[vidx(i)] & vmask(i));
}

EXPORTED void bv_set(bitvector_t *bv, unsigned int i)
{
    bv_ensure(bv, i+1);
    bv_bits(bv)[vidx(i)] |= vmask(i);
    if (i >= bv->length)
        bv->length = i+1;
}

EXPORTED void bv_clear(bitvector_t *bv, unsigned int i)
{
    if (i < bv->length) {
        bv_ensure(bv, i+1);
        bv_bits(bv)[vidx(i)] &= ~vmask(i);
    }
}

EXPORTED void bv_andeq(bitvector_t *a, const bitvector_t *b)
{
    unsigned int n;
    unsigned int i;
    unsigned char *abits;
    const unsigned char *bbits;

    bv_ensure(a, b->length);
    if (!a->length)
        return;

    abits = bv_bits(a);
    bbits = bv_bits(b);

    n = vlen(b->length);
    for (i = 0; i < n; i++)
        abits[i] &= bbits[i];
    n = vlen(a->length);
    for ( ; i < n ; i++)
        abits[i] = 0;
    a->length = MAX(a->length, b->length);
}

EXPORTED void bv_oreq(bitvector_t *a, const bitvector_t *b)
{
    unsigned int n;
    unsigned int i;
    unsigned char *abits;
    const unsigned char *bbits;

    bv_ensure(a, b->length);

    abits = bv_bits(a);
    bbits = bv_bits(b);

    n = vlen(b->length);
    for (i = 0 ; i < n ; i++)
        abits[i] |= bbits[i];
    a->length = MAX(a->length, b->length);
}

/*
 * Returns the bit position of the next set bit which is after or equal
 * to position 'start'.  Passing start = 0 returns the first set bit.
 * Returns a bit position or -1 if there are no more set bits.
 */
EXPORTED int bv_next_set(const bitvector_t *bv, int start)
{
    int i;
    const unsigned char *bits;

    if (start < 0 || start >= (int)bv->length) return -1;

    bits = bv_bits(bv);

    for (i = start ; i < (int)bv->length && !visaligned(i) ; i++)
        if (bits[vidx(i)] & vmask(i))
            return i;

    while (i < (int)bv->length) {
        if (!bits[vidx(i)]) {
            i += BITS_PER_UNIT;
        }
        else {
            if (bits[vidx(i)] & vmask(i))
                return i;
            i++;
        }
    }

    return -1;
}

/*
 * Returns the bit position of the previous set bit which is before or
 * equal to position 'start'.  Passing start = bv->vector-1 returns the
 * last set bit.  Returns a bit position or -1 if there are no more set
 * bits.
 */
EXPORTED int bv_prev_set(const bitvector_t *bv, int start)
{
    int i;
    const unsigned char *bits;

    if (start < 0 || start >= (int)bv->length) return -1;

    bits = bv_bits(bv);

    for (i = start ; i < (int)bv->length && !visaligned(i) ; i--)
        if (bits[vidx(i)] & vmask(i))
            return i;

    while (i >= 0) {
        if (!bits[vidx(i)]) {
            i -= BITS_PER_UNIT;
        }
        else {
            if (bits[vidx(i)] & vmask(i))
                return i;
            i--;
        }
    }

    return -1;
}

EXPORTED int bv_first_set(const bitvector_t *bv)
{
    return bv_next_set(bv, 0);
}

EXPORTED int bv_last_set(const bitvector_t *bv)
{
    return bv_prev_set(bv, bv->length-1);
}

static unsigned int bitcount(unsigned int i)
{
    /* http://stackoverflow.com/questions/109023/how-to-count-the-number-of-set-bits-in-a-32-bit-integer */
    i = i - ((i >> 1) & 0x55555555);
    i = (i & 0x33333333) + ((i >> 2) & 0x33333333);
    return (((i + (i >> 4)) & 0x0F0F0F0F) * 0x01010101) >> 24;
}

EXPORTED unsigned bv_count(const bitvector_t *bv)
{
    unsigned i;
    unsigned int n = 0;

    for (i = 0 ; i < bv->length ; i += BITS_PER_UNIT)
        n += bitcount(bv_bits(bv)[vidx(i)]);
    return n;
}

/* Returns a string which describes the state of the bitvector,
 * useful for debugging.  Returns a new string which must be free'd
 * by the caller */
EXPORTED char *bv_cstring(const bitvector_t *bv)
{
    struct buf buf = BUF_INITIALIZER;
    unsigned int i;
    unsigned int first = ~0U;
    unsigned int last;
    const char *sep = "";

    if (bv->length) {
        buf_truncate(&buf, vlen(bv->length)*2);
        bin_to_hex(bv_bits(bv), vlen(bv->length), buf.s, 0);
    }

    buf_putc(&buf, '[');

    for (i = 0 ; i < bv->length ; i++) {
        if (bv_bits(bv)[vidx(i)] & vmask(i)) {
            if (first == ~0U)
                first = i;
        }
        else if (first != ~0U) {
            last = i-1;
            if (first == last)
                buf_printf(&buf, "%s%u", sep, first);
            else
                buf_printf(&buf, "%s%u-%u", sep, first, last);
            sep = ",";
            first = ~0U;
        }
    }

    if (first != ~0U) {
        last = bv->length-1;
        if (first == last)
            buf_printf(&buf, "%s%u", sep, first);
        else
            buf_printf(&buf, "%s%u-%u", sep, first, last);
    }

    buf_putc(&buf, ']');
    return buf_release(&buf);
}

EXPORTED void bv_fini(bitvector_t *bv)
{
    if (bv->alloc)
        free(bv->bits.alloced);
    bv->length = 0;
    bv->alloc = 0;
    memset(bv->bits._noalloc, 0, BV_NOALLOCSIZE);
}


