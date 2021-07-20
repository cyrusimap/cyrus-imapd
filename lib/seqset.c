/* sequence.c -- Routines for dealing with sequences
 *
 * Copyright (c) 1994-2008 Carnegie Mellon University.  All rights reserved.
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
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <sysexits.h>
#include "seqset.h"
#include "string.h"
#include "util.h"
#include "xmalloc.h"

#define SETGROWSIZE 30

struct seq_range {
    unsigned low;
    unsigned high;
};

struct seqset {
    struct seq_range *set;
    size_t len;
    size_t alloc;
    unsigned current;
    unsigned prev;
    unsigned maxval;
    int flags;
};

/*
 * Allocate and return a new seqset object.
 *
 * `maxval' is the maximum insertable value, currently used only to
 * expand the `*' syntax when parsing sequences from a string.
 *
 * `flags' is either
 *
 *   SEQ_SPARSE - the behaviour you expected
 *
 *   SEQ_MERGE - assumes that seqset_add() is going to be called
 *               with monotonically increasing numbers, and treats
 *               interior ranges of numbers which were not explicitly
 *               excluded (with ismember=0) as if they had been
 *               included.  Used to reduce fragmentation in SEEN lists.
 */
EXPORTED seqset_t *seqset_init(unsigned maxval, int flags)
{
    seqset_t *seq = xzmalloc(sizeof(seqset_t));

    /* make sure flags are sane - be explicit about what
     * sort of list we're building */
    if (flags != SEQ_SPARSE && flags != SEQ_MERGE)
        fatal("invalid flags", EX_SOFTWARE);

    seq->maxval = maxval;
    seq->flags = flags;
    return seq;
}

/*
 * Add a number `num' to the sequence set `seq'.  The `ismember'
 * argument is normally 1, but affects the result for SEQ_MERGE
 * sequences.  Currently assumes that it will be called in
 * monotonically increasing order of `num's.
 */
EXPORTED void seqset_add(seqset_t *seq, unsigned num, int ismember)
{
    if (!seq) return;

    /* there are some cases where we want to make sure something is added
     * as an initial value and then re-add it again later, so if we get
     * the same number multiple times, that's OK */
    if (ismember && num == seq->prev && seq->len && seq->set[seq->len-1].high == num)
        return;

    if (num > seq->prev) {
        if (!ismember) {
            seq->prev = num;
            return;
        }

        /* as if the previous number was given to us */
        if (seq->flags & SEQ_SPARSE)
            seq->prev = num - 1;
    }

    /* do we need to add a new set? */
    if (!seq->set || seq->set[seq->len-1].high < seq->prev || num <= seq->prev) {
        if (seq->len == seq->alloc) {
            seq->alloc += SETGROWSIZE;
            seq->set =
                xrealloc(seq->set, seq->alloc * sizeof(struct seq_range));
        }
        seq->set[seq->len].low = num;
        seq->len++;
    }
    /* update the final high value */
    seq->set[seq->len-1].high = num;
    seq->prev = num;
}


/* read the final number from a sequence string and return it */
EXPORTED unsigned seq_lastnum(const char *list)
{
    const char *tail;
    uint32_t retval = 0;

    /* empty */
    if (!list) return 0;
    if (!list[0]) return 0;

    /* find the end of the string */
    tail = list + strlen(list);

    /* work back until first non-digit */
    while (tail > list && cyrus_isdigit(tail[-1]))
        tail--;

    /* read the number */
    if (parseuint32(tail, NULL, &retval))
        retval = 0;

    return retval;
}

/***************** SEQSET STUFF ******************/




/* Comparator function that sorts ranges by the low value,
   and coalesces intersecting ranges to have the same high value */
static int comp_rangesort(const void *v1, const void *v2)
{
    struct seq_range *r1 = (struct seq_range *) v1;
    struct seq_range *r2 = (struct seq_range *) v2;

    int ret = r1->low - r2->low;
    if (ret) return ret;
    return r1->high - r2->high;
}

static void seqset_simplify(seqset_t *seq)
{
    unsigned out = 0;
    unsigned i;

    /* nothing to simplify */
    if (!seq->len)
        return;

    /* Sort the ranges using our special comparator */
    qsort(seq->set, seq->len, sizeof(struct seq_range), comp_rangesort);

    /* Merge intersecting/adjacent ranges */
    for (i = 1; i < seq->len; i++) {
        if (seq->set[out].high + 1 < seq->set[i].low) {
            /* these are disjoint */
            out++;
            if (out != i)
                seq->set[out] = seq->set[i];
        }
        else if (seq->set[out].high < seq->set[i].high) {
            seq->set[out].high = seq->set[i].high;
        }
    }

    /* final length */
    seq->len = out+1;
}

static int read_num(const char **input, unsigned maxval, unsigned *res)
{
    const char *ptr = *input;

    if (*ptr == '*') {
        *res = maxval ? maxval : UINT_MAX;
        ptr++;
        *input = ptr;
        return 0;
    }
    else if (cyrus_isdigit((int) *ptr)) {
        *res = 0;
        while (cyrus_isdigit((int) *ptr)) {
            *res = (*res)*10 + *ptr - '0';
            ptr++;
        }
        *input = ptr;
        return 0;
    }

    /* not expected */
    return -1;
}

/*
 * Parse a sequence into an array of sorted & merged ranges.
 */
EXPORTED seqset_t *seqset_parse(const char *sequence,
                                     seqset_t *set,
                                     unsigned maxval)
{
    unsigned start = 0, end = 0;

    /* short circuit no sequence */
    if (!sequence) return NULL;

    if (!set) set = seqset_init(maxval, SEQ_SPARSE);

    while (*sequence) {
        if (read_num(&sequence, maxval, &start))
            fatal("invalid sequence", EX_SOFTWARE);
        if (*sequence == ':') {
            sequence++;
            if (read_num(&sequence, maxval, &end))
                fatal("invalid sequence", EX_SOFTWARE);
        }
        else
            end = start;
        if (start > end) {
            unsigned i = end;
            end = start;
            start = i;
        }

        if (set->len == set->alloc) {
            set->alloc += SETGROWSIZE;
            set->set = xrealloc(set->set, set->alloc * sizeof(struct seq_range));
        }
        set->set[set->len].low = start;
        set->set[set->len].high = end;
        set->len++;

        if (*sequence == ',')
            sequence++;
        /* could test for invalid chars here, but the number parser next
         * time through will grab them, so no need */
    }

    seqset_simplify(set);
    return set;
}

/* Comparator function that checks if r1 is a subset of r2 */
static int comp_subset(const void *v1, const void *v2)
{
    struct seq_range *r1 = (struct seq_range *) v1;
    struct seq_range *r2 = (struct seq_range *) v2;

    if (r1->low < r2->low) return -1;
    if (r1->high > r2->high) return 1;
    return 0;
}

/*
 * Return nonzero iff 'num' is included in 'sequence'
 */
EXPORTED int seqset_ismember(const seqset_t *seq, unsigned num)
{
    struct seq_range key = {num, num};
    struct seq_range *found;

    /* Short circuit no list! */
    if (!seq) return 0;
    if (!seq->len) return 0;

    /* Short circuit if we're outside all ranges */
    if ((num < seq->set[0].low) || (num > seq->set[seq->len-1].high)) {
        return 0;
    }

    seqset_t *backdoor = (seqset_t *)seq;

    /* Move one set ahead if necessary (avoids bsearch in the common case of
       incrementing through the list) */
    if (num > backdoor->set[backdoor->current].high) {
        if (backdoor->current + 1 >= backdoor->len)
            return 0; /* no more sequences! */
        if (num < backdoor->set[backdoor->current+1].low)
            return 0; /* in the gap still */
        backdoor->current++; /* move ahead */
    }

    /* maybe we're in this range */
    if (num >= backdoor->set[backdoor->current].low &&
        num <= backdoor->set[backdoor->current].high)
        return 1;

    /* Fall back to full search */
    found = bsearch(&key, backdoor->set, backdoor->len,
                    sizeof(struct seq_range), comp_subset);
    if (found) {
        /* track the range we found ourselves in */
        backdoor->current = found - backdoor->set;
        return 1;
    }

    return 0;
}

/*
 * Return the first number in the sequence, or 0
 * if the sequence is empty.
 */
EXPORTED unsigned seqset_first(const seqset_t *seq)
{
    if (!seq) return 0;
    return (seq->len ? seq->set[0].low : 0);
}

/*
 * Return the last number in the sequence, or 0
 * if the sequence is empty.
 */
EXPORTED unsigned seqset_last(const seqset_t *seq)
{
    if (!seq) return 0;
    return (seq->len ? seq->set[seq->len-1].high : 0);
}

/* NOTE: this assumes normalised, and also assumes that '1' is
 * the first element */
EXPORTED unsigned seqset_firstnonmember(const seqset_t *seq)
{
    if (!seq) return 1;
    if (!seq->len) return 1;
    if (seq->set[0].low != 1) return 1;
    return seq->set[0].high + 1;
}

/*
 * Iteration interface for sequences.  Returns the next number
 * in the sequence, or 0 if the end of the sequence has been
 * reached.
 * Interferes with the state used for seqset_add() so don't mix
 * adding and iterating.
 */
EXPORTED unsigned seqset_getnext(const seqset_t *seq)
{
    unsigned num;
    unsigned i;

    /* no sequence, there's no next value */
    if (!seq) return 0;

    /* finished? */
    if (seq->prev == UINT_MAX) return 0;

    seqset_t *backdoor = (seqset_t *)seq;

    num = backdoor->prev + 1;

    for (i = backdoor->current; i < backdoor->len; i++) {
        if (num < backdoor->set[i].low)
            num = backdoor->set[i].low;
        if (num <= backdoor->set[i].high) {
            backdoor->current = i;
            backdoor->prev = num;
            return num;
        }
    }

    backdoor->prev = UINT_MAX;
    return 0;
}

EXPORTED void seqset_reset(const seqset_t *seq)
{
    if (!seq) return;
    seqset_t *backdoor = (seqset_t *)seq;
    backdoor->prev = 0;
    backdoor->current = 0;
}

/*
 * Merge the numbers in seqset `src' into seqset `dst'.
 */
/* NOTE - not sort safe! */
EXPORTED void seqset_join(seqset_t *dst, const seqset_t *src)
{
    if (!src) return;

    if (dst->len + src->len > dst->alloc) {
        dst->alloc = dst->len + src->len;
        dst->set =
            xrealloc(dst->set, dst->alloc * sizeof(struct seq_range));
    }
    /* call them char * so the maths works out right */
    memcpy((char *)dst->set + dst->len * sizeof(struct seq_range),
           (char *)src->set, src->len * sizeof(struct seq_range));
    dst->len += src->len;

    seqset_simplify(dst);
}

static void format_num(struct buf *buf, unsigned i)
{
    if (i == UINT_MAX)
        buf_putc(buf, '*');
    else
        buf_printf(buf, "%u", i);
}

/*
 * Format the seqset `seq' as a string.  Returns a newly allocated
 * string which must be free()d by the caller.
 */
EXPORTED char *seqset_cstring(const seqset_t *seq)
{
    struct buf buf = BUF_INITIALIZER;
    unsigned i;

    if (!seq) return NULL;
    if (!seq->len) return NULL;

    for (i = 0; i < seq->len; i++) {
        /* join with comma if not the first item */
        if (i) buf_putc(&buf, ',');

        /* single value only */
        if (seq->set[i].low == seq->set[i].high)
            format_num(&buf, seq->set[i].low);

        /* value range */
        else {
            format_num(&buf, seq->set[i].low);
            buf_putc(&buf, ':');
            format_num(&buf, seq->set[i].high);
        }
    }

    return buf_release(&buf);
}

/*
 * Duplicate the given seqset.
 */
EXPORTED seqset_t *seqset_dup(const seqset_t *src)
{
    if (!src) return NULL;

    seqset_t *dst = (seqset_t *)xmemdup(src, sizeof(struct seqset));

    dst->set = (struct seq_range *)xmemdup(src->set,
                    src->alloc * sizeof(struct seq_range));

    return dst;
}

/*
 * Free the given seqset (and any others chained to it)
 */
EXPORTED void seqset_free(seqset_t **l)
{
    if (!*l) return;

    free((*l)->set);
    free(*l);
    *l = NULL;
}
