/* search_expr.h --  search query tree handling for SEARCH
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

#ifndef __CYRUS_SEARCH_EXPR_H__
#define __CYRUS_SEARCH_EXPR_H__

#include "mailbox.h"
#include "message.h"
#include "util.h"

struct protstream;
struct index_state;

enum search_op {
    SEOP_UNKNOWN,
    SEOP_TRUE,
    SEOP_FALSE,

    /* operators for ordinal types: dates, sizes */
    SEOP_LT,
    SEOP_LE,
    SEOP_GT,
    SEOP_GE,

    /* operators for nonordinal types: strings, uid sequences */
    SEOP_MATCH,
    SEOP_FUZZYMATCH,

    SEOP_AND,
    SEOP_OR,
    SEOP_NOT,
};

union search_value {
    time_t t;
    uint64_t u;
    char *s;
    struct searchannot *annot;
    strarray_t *list;
    void *v;
};

/* search_attr.flags */
enum {
    SEA_MUTABLE =       (1<<0),
    SEA_FUZZABLE =      (1<<1),
    SEA_ISLIST =        (1<<2),
};

typedef struct search_attr search_attr_t;
struct search_attr {
    const char *name;
    int flags;
    int part;
    int cost;
    void (*internalise)(struct index_state *, const union search_value *,
                        void *data1, void **internalisedp);
    int (*cmp)(message_t *, const union search_value *, void *internalised, void *data1);
    int (*match)(message_t *, const union search_value *, void *internalised, void *data1);
    void (*serialise)(struct buf *, const union search_value *);
    int (*unserialise)(struct protstream*, union search_value *);
    unsigned int (*get_countability)(const union search_value *);
    void (*duplicate)(union search_value *, const union search_value *);
    void (*free)(union search_value *, struct search_attr **);
    void (*freeattr)(struct search_attr **);
    struct search_attr* (*dupattr)(struct search_attr *);
    void *data1;        /* extra data for the functions above */
};

typedef struct search_expr search_expr_t;
struct search_expr {
    enum search_op op;
    search_expr_t *parent;
    search_expr_t *next;
    search_expr_t *children;
    const search_attr_t *attr;
    union search_value value;
    void *internalised;
};

/* flags for search_expr_get_countability */
enum {
    SEC_EXISTS =            (1<<0),
    SEC_RECENT =            (1<<1),
    SEC_SEEN =              (1<<2),
    SEC_CONVSEEN =          (1<<3),
    SEC_NOT =               (1<<29),
    SEC_UNCOUNTED =         (1<<30),
};

extern search_expr_t *search_expr_new(search_expr_t *parent,
                                      enum search_op);
extern void search_expr_append(search_expr_t *parent, search_expr_t *child);
extern void search_expr_detach(search_expr_t *parent, search_expr_t *child);
extern void search_expr_free(search_expr_t *);
extern search_expr_t *search_expr_duplicate(const search_expr_t *e);
extern int search_expr_apply(search_expr_t *e,
                             int (*cb)(search_expr_t *e, void *rock),
                             void *rock);
extern char *search_expr_serialise(const search_expr_t *);
extern search_expr_t *search_expr_unserialise(const char *s);
extern int search_expr_normalise(search_expr_t **);
extern void search_expr_internalise(struct index_state *, search_expr_t *);
extern int search_expr_always_same(const search_expr_t *);
extern int search_expr_evaluate(message_t *m, const search_expr_t *);
extern int search_expr_uses_attr(const search_expr_t *, const char *);
extern int search_expr_is_mutable(const search_expr_t *);
extern unsigned int search_expr_get_countability(const search_expr_t *);
extern void search_expr_neutralise(search_expr_t *);
extern void search_expr_split_by_folder_and_index(search_expr_t *e,
                                        void (*cb)(const char *mboxname,
                                                   search_expr_t *indexed,
                                                   search_expr_t *scan,
                                                   void *rock),
                                        void *rock);
extern char *search_expr_firstmailbox(const search_expr_t *);
extern void search_expr_detrivialise(search_expr_t **ep);

enum search_cost {
    SEARCH_COST_NONE = 0,
    SEARCH_COST_INDEX,
    SEARCH_COST_CONV,
    SEARCH_COST_ANNOT,
    SEARCH_COST_CACHE,
    SEARCH_COST_BODY
};

extern void search_attr_init(void);
extern const search_attr_t *search_attr_find(const char *);
extern const search_attr_t *search_attr_find_field(const char *field);
extern int search_attr_is_fuzzable(const search_attr_t *);
extern enum search_cost search_attr_cost(const search_attr_t *);

extern int search_getseword(struct protstream *prot, char *buf, int maxlen);

#endif
