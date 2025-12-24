/* proxy.h - proxy support functions */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

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
                      int extra_read_fd,
                      int *extra_read_flag,
                      unsigned long timeout_sec);

struct mbox_refer {
    int (*proc)(mbentry_t *mbentry, void *rock);
    void *rock;
};

extern int proxy_mlookup(const char *name, mbentry_t **mbentryp,
                         void *tid, struct mbox_refer *refer);

#endif /* _PROXY_H */
