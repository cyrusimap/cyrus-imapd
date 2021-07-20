/* proxy.h - proxy support functions
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

#ifndef _PROXY_H
#define _PROXY_H

#include "backend.h"
#include "protocol.h"
#include "prot.h"

#define IDLE_TIMEOUT (5 * 60)

/* a final destination for a message */
struct rcpt {
    char rcpt[MAX_MAILBOX_BUFFER]; /* where? */
    int rcpt_num;                   /* credit this to who? */
    struct rcpt *next;
};

struct dest {
    char server[MAX_MAILBOX_BUFFER];  /* where? */
    char authas[MAX_MAILBOX_BUFFER];  /* as who? */
    int rnum;                         /* number of rcpts */
    struct rcpt *to;
    struct dest *next;
};

void proxy_adddest(struct dest **dlist, const char *rcpt, int rcpt_num,
                   const char *server, const char *authas);

struct backend *
proxy_findserver(const char *server, struct protocol_t *prot,
                 const char *userid, ptrarray_t *cache,
                 struct backend **current, struct backend **inbox,
                 struct protstream *clientin);

void proxy_downserver(struct backend *s);

int proxy_check_input(struct protgroup *protin,
                      struct protstream *clientin,
                      struct protstream *clientout,
                      struct protstream *serverin,
                      struct protstream *serverout,
                      unsigned long timeout_sec);

struct mbox_refer {
    int (*proc)(mbentry_t *mbentry, void *rock);
    void *rock;
};

extern int proxy_mlookup(const char *name, mbentry_t **mbentryp,
                         void *tid, struct mbox_refer *refer);

#endif /* _PROXY_H */
