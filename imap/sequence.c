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

#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include "sequence.h"
#include "string.h"
#include "util.h"
#include "xmalloc.h"

#define SEQGROW 200

void seq_readinit(struct seq_listreader *seq, const char *list) 
{
    seq->base = seq->ptr = list;
    seq->next = 0;
    seq->prev = 0;
    seq->state = seq_noseq;
    if (!list) return; /* NULL => empty */
    while (cyrus_isdigit((int) *(seq->ptr))) 
	seq->next = seq->next * 10 + *(seq->ptr)++ - '0';
}

int seq_ismember(struct seq_listreader *seq, unsigned long num)
{
    /* if we're being asked out of order, restart the reader */
    if (num < seq->prev) {
	seq->ptr = seq->base;
	seq->next = 0;
	while (cyrus_isdigit((int) *(seq->ptr))) 
	    seq->next = seq->next * 10 + *(seq->ptr)++ - '0';
    }

    /* list is finished - can't be any more members */
    if (!seq->next)
	return 0;

    /* track the last request */
    seq->prev = num;

    while (num > seq->next) {
	if (*(seq->ptr) == ':') {
	    seq->state = seq_inseq;
	} 
	else if (*(seq->ptr) == ',') {
	    seq->state = seq_noseq;
	} 
	else {
	    /* invalid or end */
	    seq->next = 0;
	    return 0;
	}
	seq->ptr++;
	/* <n>:* - true until the end! */
	if (*(seq->ptr) == '*') {
	    seq->next = ULONG_MAX;
	    return 1;
	} 
	seq->next = 0;
	while (cyrus_isdigit((int) *(seq->ptr))) 
	    seq->next = seq->next * 10 + *(seq->ptr)++ - '0';
    }

    /* in the current range - is it an on or off? */
    if (num < seq->next)
	return (seq->state == seq_inseq);

    return 1; /* exact match */
}

void seq_listinit(struct seq_listbuilder *seq, int flags)
{
    seq->flags = flags;

    seq->base = NULL;
    seq->alloc = 0;
    seq->offset = 0;
    seq->prev = 0;
    seq->state = seq_empty;
}

/* caller to free when done! */
char *seq_listdone(struct seq_listbuilder *seq)
{
    char *res;

    /* should always be space, because we alloc 30 chars slop, and inseq
     * implies we didn't write anything last add */
    if (seq->state == seq_inseq)
	sprintf(seq->base + seq->offset, ":%lu", seq->prev);
    seq->state = seq_done;

    return (seq->base);
}

int seq_isempty(struct seq_listbuilder *seq)
{
    return seq->state == seq_empty;
}

void seq_listadd(struct seq_listbuilder *seq, unsigned long num, int inseq)
{
    /* short circuit so we don't allocate unless there's 
     * SOMETHING to add */
    if (inseq == 0 && seq->state == seq_empty)
	return;

    if (seq->alloc + 30 > seq->offset) {
	seq->alloc += SEQGROW;
	seq->base = xrealloc(seq->base, seq->alloc);
    }

    /* insert a spurious blank record in between if sparse */
    if ((seq->flags & SEQ_SPARSE) && inseq && (num > seq->prev+1))
	seq_listadd(seq, num - 1, 0);

    if (inseq) {
	switch (seq->state) {
	case seq_noseq:
	    seq->base[seq->offset++] = ',';
	    /* fall through */
	case seq_empty:
	    sprintf(seq->base + seq->offset, "%lu", num);
	    while (seq->base[seq->offset]) seq->offset++;
	    seq->state = seq_seen1;
	    break;
	case seq_seen1:
	    seq->state = seq_inseq;
	    break;
	}
	/* remember the last number that was in the sequence */
	seq->prev = num;
    } else { /* not seen */
	switch (seq->state) {
	case seq_inseq:
	    sprintf(seq->base + seq->offset, ":%lu", seq->prev);
	    while (seq->base[seq->offset]) seq->offset++;
	    /* fall through */
	case seq_seen1:
	    seq->state = seq_noseq;
	    break;
	}
    }
}

/* read the final number from a sequence string and return it.
 * if given "numstart", return a pointer to the start of
 * that number in the string */
int seq_lastnum(const char *list, const char **numstart)
{
    const char *tail, *p;
    int retval = 0;

    /* empty */
    if (!list) return 0;
    if (!list[0]) return 0;

    /* find the end of the string */
    tail = list + strlen(list);
    
    /* work back until first non-digit */
    while (tail > list && cyrus_isdigit(tail[-1]))
	tail--;

    /* read the number */
    for (p = tail; *p; p++)
	retval = retval * 10 + *p - '0';

    if (numstart)
	*numstart = tail;

    return retval;
}
