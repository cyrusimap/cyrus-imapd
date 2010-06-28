/* sequence.h -- Routines for dealing with message sequences
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
 * $Id: sequence.h,v 1.1 2010/06/28 12:05:04 brong Exp $
 */

/* Header for internal usage of index.c + programs that make raw access
 * to index files */

#ifndef SEQUENCE_H
#define SEQUENCE_H

/* old-style seq stuff */

struct seq_range {
    unsigned low;
    unsigned high;
};

struct seq_set {
    struct seq_range *set;
    unsigned len;
    unsigned alloc;
    unsigned mark;
    struct seq_set *next;
};

/* new seq stuff */

enum seq_enum { seq_empty, seq_noseq, seq_seen1, seq_inseq, seq_done };

#define SEQ_SPARSE (1<<0)

struct seq_listbuilder {
    char *base;
    unsigned long prev;
    int alloc;
    int offset;
    int flags;
    enum seq_enum state;
};

struct seq_listreader {
    const char *base;
    const char *ptr;
    unsigned long next;
    unsigned long prev;
    enum seq_enum state;
};

extern void seq_readinit(struct seq_listreader *seq, const char *list);
extern int seq_ismember(struct seq_listreader *seq, unsigned long num);
extern void seq_listinit(struct seq_listbuilder *seq, int flags);
extern void seq_listadd(struct seq_listbuilder *seq, 
			unsigned long num, int inseq);
extern int seq_isempty(struct seq_listbuilder *seq);
extern char *seq_listdone(struct seq_listbuilder *seq);
int seq_lastnum(const char *list, const char **numstart);

#endif /* SEQUENCE_H */
