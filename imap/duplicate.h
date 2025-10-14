/*
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

#ifndef DUPLICATE_H
#define DUPLICATE_H

#include "hash.h"

/* name of the duplicate delivery database */
#define FNAME_DELIVERDB "/deliver.db"

typedef struct duplicate_key
{
    const char *id;
    const char *to;
    const char *date;
} duplicate_key_t;

#define DUPLICATE_INITIALIZER { NULL, NULL, NULL }

int duplicate_init(const char *fname);

time_t duplicate_check(const duplicate_key_t *dkey);
void duplicate_log(const duplicate_key_t *dkey, const char *action);
void duplicate_mark(const duplicate_key_t *dkey,
                    time_t mark,
                    unsigned long uid);
typedef int (*duplicate_find_proc_t)(const duplicate_key_t *,
                                     time_t,
                                     unsigned long,
                                     void *);
int duplicate_find(const char *msgid, duplicate_find_proc_t, void *rock);

int duplicate_prune(int seconds, struct hash_table *expire_table);
int duplicate_dump(FILE *f);

int duplicate_done(void);

#endif /* DUPLICATE_H */
