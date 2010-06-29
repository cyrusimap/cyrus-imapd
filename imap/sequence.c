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
 *
 * $Id: sequence.c,v 1.1 2010/06/28 12:05:04 brong Exp $
 */

#include <config.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include "exitcodes.h"
#include "sequence.h"
#include "string.h"
#include "util.h"
#include "xmalloc.h"

#define SETGROWSIZE 30

struct seqset *seqset_init(unsigned maxval, int flags)
{
    struct seqset *seq = xzmalloc(sizeof(struct seqset));

    /* make sure flags are sane - be explicit about what
     * sort of list we're building */
    if (flags != SEQ_SPARSE && flags != SEQ_MERGE)
	fatal("invalid flags", EC_SOFTWARE);

    seq->maxval = maxval;
    seq->flags = flags;
    return seq;
}

void seqset_add(struct seqset *seq, unsigned num, int ismember)
{
    if (!seq) return;

    if (num <= seq->prev)
	fatal("numbers out of order", EC_SOFTWARE);

    if (!ismember) {
	seq->prev = num;
	return;
    }

    /* as if the previous number was given to us */
    if (seq->flags & SEQ_SPARSE)
	seq->prev = num - 1;

    /* do we need to add a new set? */
    if (!seq->set || seq->set[seq->len-1].high < seq->prev) {
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


/* read the final number from a sequence string and return it.
 * if given "numstart", return a pointer to the start of
 * that number in the string */
unsigned int seq_lastnum(const char *list, const char **numstart)
{
    const char *tail;
    uint32_t retval = 0;

    if (numstart)
	*numstart = list;

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

    if (numstart)
	*numstart = tail;

    return retval;
}

/***************** SEQSET STUFF ******************/



#define MAX(x, y) (x > y ? x : y)

/* Comparator function that sorts ranges by the low value,
   and coalesces intersecting ranges to have the same high value */
static int comp_coalesce(const void *v1, const void *v2)
{
    struct seq_range *r1 = (struct seq_range *) v1;
    struct seq_range *r2 = (struct seq_range *) v2;

    /* If ranges don't intersect, we're done */
    if (r1->high < r2->low) return -1;
    if (r1->low > r2->high) return 1;

    /* Ranges intersect, coalesce them */
    r1->high = r2->high = MAX(r1->high, r2->high);

    return r1->low - r2->low;;
}

/*
 * Parse a sequence into an array of sorted & merged ranges.
 */
struct seqset *seqset_parse(const char *sequence,
			    struct seqset *set,
			    unsigned maxval)
{
    unsigned i, j, start, end, *num;

    /* short circuit no sequence */
    if (!sequence) return NULL;

    if (!set) set = seqset_init(maxval, SEQ_SPARSE);

    start = end = 0;
    num = &start;
    for (;;) {
	if (cyrus_isdigit((int) *sequence)) {
	    *num = (*num)*10 + *sequence - '0';
	}
	else if (*sequence == '*') {
	    *num = maxval ? maxval : UINT_MAX;
	}
	else if (*sequence == ':') {
	    num = &end;
	}
	else {
	    if (!end) end = start;
	    else if (start > end) {
		i = end;
		end = start;
		start = i;
	    }

	    if (set->len == set->alloc) {
		set->alloc += SETGROWSIZE;
		set->set =
		    xrealloc(set->set, set->alloc * sizeof(struct seq_range));
	    }
	    set->set[set->len].low = start;
	    set->set[set->len].high = end;
	    set->len++;

	    start = end = 0;
	    num = &start;

	    if (!*sequence) break;
	}
	sequence++;
    }

    /* Sort the ranges using our special comparator */
    qsort(set->set, set->len, sizeof(struct seq_range), comp_coalesce);

    /* Merge intersecting/adjacent ranges */
    for (i = 0, j = 1; j < set->len; j++) {
	if ((int)(set->set[j].low - set->set[i].high) <= 1) {
	    set->set[i].high = set->set[j].high;
	} else {
	    i++;
	    set->set[i].low = set->set[j].low;
	    set->set[i].high = set->set[j].high;
	}
    }
    set->len = i+1;

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
int seqset_ismember(struct seqset *seq, unsigned num)
{
    struct seq_range key = {num, num};
    struct seq_range *found;

    /* Short circuit no list! */
    if (!seq) return 0;

    /* Short circuit if we're outside all ranges */
    if ((num < seq->set[0].low) || (num > seq->set[seq->len-1].high)) {
	return 0;
    }

    /* Move one set ahead if necessary (avoids bsearch in the common case of
       incrementing through the list) */
    if (num > seq->set[seq->current].high) {
	if (seq->current + 1 >= seq->len)
	    return 0; /* no more sequences! */
	if (num < seq->set[seq->current+1].low)
	    return 0; /* in the gap still */
	seq->current++; /* move ahead */
    }

    /* maybe we're in this range */
    if (num >= seq->set[seq->current].low && num <= seq->set[seq->current].high)
	return 1;

    /* Fall back to full search */
    found = bsearch(&key, seq->set, seq->len,
		    sizeof(struct seq_range), comp_subset);
    if (found) {
	/* track the range we found ourselves in */
	seq->current = found - seq->set;
	return 1;
    }

    return 0;
}

unsigned seqset_getnext(struct seqset *seq)
{
    unsigned long num;
    int i;

    /* no sequence, there's no next value */
    if (!seq) return 0;

    /* finished? */
    if (seq->prev == UINT_MAX) return 0;

    num = seq->prev + 1;

    for (i = seq->current; i < seq->len; i++) {
	if (num < seq->set[i].low)
	    num = seq->set[i].low;
	if (num <= seq->set[i].high) {
	    seq->current = i;
	    seq->prev = num;
	    return num;
	}
    }

    seq->prev = UINT_MAX;
    return 0;
}

void seqset_append(struct seqset **l, char *sequence, unsigned maxval)
{
    struct seqset **tail = l;

    while (*tail) {
	if (!maxval) maxval = (*tail)->maxval;
	tail = &(*tail)->nextseq;
    }

    *tail = seqset_parse(sequence, NULL, maxval);
}

#define SEQGROW 300

char *seqset_cstring(struct seqset *seq) 
{
    int alloc = 0;
    int offset = 0;
    char *base = NULL;
    int i;

    if (!seq) return NULL;

    for (i = 0; i < seq->len; i++) {
	/* ensure we have space */
	if (alloc < offset + 30) {
	    alloc += SEQGROW;
	    base = xrealloc(base, alloc);
	}

	/* join with comma if not the first item */
	if (i) base[offset++] = ',';

	/* single value only */
	if (seq->set[i].low == seq->set[i].high)
	    sprintf(base+offset, "%u", seq->set[i].low);

	/* special case - end of the list */
	else if (seq->set[i].high == UINT_MAX)
	    sprintf(base+offset, "%u:*", seq->set[i].low);

	/* value range */
	else
	    sprintf(base+offset, "%u:%u", seq->set[i].low,
					  seq->set[i].high);

	/* find the end */
	while (base[offset]) offset++;
    }

    return base;
}

void seqset_free(struct seqset *l)
{
    struct seqset *n;

    while(l) {
	n = l->nextseq;
	free(l->set);
	free(l);
	l = n;
    }
}
