/* seqset.h -- Routines for dealing with message sequences
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

#ifndef SEQSET_H
#define SEQSET_H

struct seqset;
typedef struct seqset seqset_t;

#define SEQ_SPARSE 1
#define SEQ_MERGE 2

extern unsigned seq_lastnum(const char *list);

/* for writing */
extern seqset_t *seqset_init(unsigned maxval, int flags);
void seqset_add(seqset_t *seq, unsigned num, int ismember);

extern seqset_t *seqset_parse(const char *sequence,
                              seqset_t *set,
                              unsigned maxval);
extern void seqset_join(seqset_t *dst, const seqset_t *src);
extern int seqset_ismember(const seqset_t *set, unsigned num);
extern void seqset_reset(const seqset_t *set);
extern unsigned seqset_getnext(const seqset_t *set);
extern unsigned seqset_first(const seqset_t *set);
extern unsigned seqset_firstnonmember(const seqset_t *set);
extern unsigned seqset_last(const seqset_t *set);
extern char *seqset_cstring(const seqset_t *set);
extern void seqset_free(seqset_t **setp);
extern seqset_t *seqset_dup(const seqset_t *src);

#endif /* SEQSET_H */
