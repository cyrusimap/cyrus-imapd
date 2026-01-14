/* jmap_push.h - Routines for handling JMAP Push API requests */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef JMAP_PUSH_H
#define JMAP_PUSH_H

#include <jansson.h>

#include "httpd.h"
#include "mboxname.h"
#include "prot.h"
#include "util.h"

extern int jmap_push_poll;

typedef struct jmap_push_ctx {
    char *accountid;
    char *inboxname;
    int ping;
    time_t next_ping;
    time_t next_poll;
    unsigned closeafter : 1;
    struct prot_waitevent *wait;
    struct mboxname_counters counters;
    struct buf buf;
} jmap_push_ctx_t;

extern jmap_push_ctx_t *jmap_push_init(struct transaction_t *txn,
                                       const char *accountid,
                                       strarray_t *types, modseq_t lastmodseq,
                                       prot_waiteventcallback_t *ev);

extern void jmap_push_done(struct transaction_t *txn);

extern json_t *jmap_push_get_state(jmap_push_ctx_t *jpush);

#endif /* JMAP_PUSH_H */
