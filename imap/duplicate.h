/* duplicate.h */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef DUPLICATE_H
#define DUPLICATE_H

#include "hash.h"

/* name of the duplicate delivery database */
#define FNAME_DELIVERDB "/deliver.db"

typedef struct duplicate_key {
    const char *id;
    const char *to;
    const char *date;
} duplicate_key_t;

#define DUPLICATE_INITIALIZER { NULL, NULL, NULL }

int duplicate_init(const char *fname);

time_t duplicate_check(const duplicate_key_t *dkey);
void duplicate_log(const duplicate_key_t *dkey, const char *action);
void duplicate_mark(const duplicate_key_t *dkey, time_t mark, unsigned long uid);
typedef int (*duplicate_find_proc_t)(const duplicate_key_t *, time_t,
                                     unsigned long, void *);
int duplicate_find(const char *msgid, duplicate_find_proc_t, void *rock);

int duplicate_prune(int seconds, struct hash_table *expire_table);
int duplicate_dump(FILE *f);

int duplicate_done(void);

#endif /* DUPLICATE_H */
