/* lmtpengine.h: lmtp protocol engine interface
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

#ifndef LMTPENGINE_H
#define LMTPENGINE_H

/***************** server-side LMTP *******************/

#include "xmalloc.h"
#include "spool.h"
#include "mboxname.h"
#include "quota.h"

typedef struct message_data message_data_t;
typedef struct address_data address_data_t;

struct message_data {
    struct protstream *data;    /* message in temp file */
    FILE *f;                    /* FILE * corresponding */
    long body_offset;           /* offset of msg body in file */

    char *id;                   /* message id */
    int size;                   /* size of message */

    /* msg envelope */
    char *return_path;          /* where to return message */
    const struct namespace *ns; /* namespace for recipients */
    address_data_t **rcpt;      /* to recipients of this message */
    int rcpt_num;               /* number of recipients */
    char *date;                 /* date field of header */

    /* auth state */
    char *authuser;
    struct auth_state *authstate;

    void *rock;

    hdrcache_t hdrcache;
};

/* return the corresponding header */
const char **msg_getheader(message_data_t *m, const char *phead);

/* return message size */
int msg_getsize(message_data_t *m);

/* return # of recipients */
int msg_getnumrcpt(message_data_t *m);

/* return delivery destination of recipient 'rcpt_num' */
const mbname_t *msg_getrcpt(message_data_t *m, int rcpt_num);

/* return entire recipient of 'rcpt_num' */
const char *msg_getrcptall(message_data_t *m, int rcpt_num);

/* return ignorequota flag of 'rcpt_num' */
int msg_getrcpt_ignorequota(message_data_t *m, int rcpt_num);

/* set a recipient status; 'r' should be an IMAP error code that will be
   translated into an LMTP status code */
void msg_setrcpt_status(message_data_t *m, int rcpt_num, int r, strarray_t *resp);

void *msg_getrock(message_data_t *m);
void msg_setrock(message_data_t *m, void *rock);

struct addheader {
    const char *name;
    const char *body;
};

struct lmtp_func {
    int (*deliver)(message_data_t *m,
                   char *authuser, const struct auth_state *authstate, const struct namespace *ns);
    int (*verify_user)(const mbname_t *mbname,
                       quota_t quotastorage_check, /* user must have this much storage quota left
                                           (-1 means don't care about quota) */
                       quota_t quotamessage_check, /* user must have this much message quota left
                                           (-1 means don't care about quota) */
                       struct auth_state *authstate);
    void (*shutdown)(int code);
    FILE *(*spoolfile)(message_data_t *m);
    void (*removespool)(message_data_t *m);
    struct namespace *namespace; /* mailbox namespace that we're working in */
    struct addheader *addheaders; /* add these headers to all messages */
    int addretpath;             /* should i add a return-path header? */
    int preauth;                /* preauth connection? */
};

/* run LMTP on 'pin' and 'pout', doing callbacks to 'func' where appropriate
 *
 * will call signals_poll() on occasion.
 * will return when connection closes.
 */
void lmtpmode(struct lmtp_func *func,
              struct protstream *pin,
              struct protstream *pout,
              int fd);

/************** client-side LMTP ****************/

#include "backend.h"

enum {
    /* LMTP capabilities */
    CAPA_PIPELINING     = (1 << 3),
    CAPA_IGNOREQUOTA    = (1 << 4)
};

struct lmtp_txn {
    const char *from;
    const char *auth;
    int isdotstuffed;           /* 1 if 'data' is a dotstuffed stream
                                   (including end-of-file \r\n.\r\n) */
    int tempfail_unknown_mailbox; /* 1 if '550 5.1.1 unknown mailbox'
                                   * should be masked as a temporary failure */
    struct protstream *data;
    int rcpt_num;
    struct lmtp_rcpt {
        char *addr;
        int ignorequota;
        enum {
            RCPT_GOOD,
            RCPT_TEMPFAIL,
            RCPT_PERMFAIL
        } result;
        int r;                  /* if non-zero,
                                   a more descriptive error code */
        strarray_t *resp;
    } rcpt[1];
};

#define LMTP_TXN_ALLOC(n) (xzmalloc(sizeof(struct lmtp_txn) + \
                                   ((n) * (sizeof(struct lmtp_rcpt)))))

int lmtp_runtxn(struct backend *conn, struct lmtp_txn *txn);

#endif /* LMTPENGINE_H */
