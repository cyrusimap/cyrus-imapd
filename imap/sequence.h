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
 */

/* Header for internal usage of index.c + programs that make raw access
 * to index files */

#ifndef SEQUENCE_H
#define SEQUENCE_H

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

#define SEQ_SPARSE 1
#define SEQ_MERGE 2

extern unsigned seq_lastnum(const char *list);

/* for writing */
extern struct seqset *seqset_init(unsigned maxval, int flags);
void seqset_add(struct seqset *seq, unsigned num, int ismember);

extern struct seqset *seqset_parse(const char *sequence,
                                   struct seqset *set,
                                   unsigned maxval);
extern void seqset_join(struct seqset *a, const struct seqset *b);
extern int seqset_ismember(struct seqset *set, unsigned num);
extern unsigned seqset_getnext(struct seqset *set);
extern unsigned seqset_first(const struct seqset *set);
extern unsigned seqset_firstnonmember(const struct seqset *set);
extern unsigned seqset_last(const struct seqset *set);
extern char *seqset_cstring(const struct seqset *set);
extern void seqset_free(struct seqset *set);
extern struct seqset *seqset_dup(const struct seqset *);

#endif /* SEQUENCE_H */
