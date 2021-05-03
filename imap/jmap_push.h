/* jmap_push.h -- Routines for handling JMAP Push API requests
 *
 * Copyright (c) 1994-2021 Carnegie Mellon University.  All rights reserved.
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
 */

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
