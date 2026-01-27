/* seqset.h - Routines for dealing with message sequences */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

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
void seqset_remove(seqset_t *seq, unsigned num);

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
