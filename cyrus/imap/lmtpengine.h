/* lmtpengine.h: lmtp protocol engine interface
 * $Id: lmtpengine.h,v 1.18.2.4 2004/03/24 19:53:06 ken3 Exp $
 *
 * Copyright (c) 1998-2003 Carnegie Mellon University.  All rights reserved.
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
 *    prior written permission. For permission or any other legal
 *    details, please contact  
 *      Office of Technology Transfer
 *      Carnegie Mellon University
 *      5000 Forbes Avenue
 *      Pittsburgh, PA  15213-3890
 *      (412) 268-4387, fax: (412) 268-7395
 *      tech-transfer@andrew.cmu.edu
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

#include "spool.h"
#include "mboxname.h"

typedef struct message_data message_data_t;
typedef struct address_data address_data_t;

struct message_data {
    struct protstream *data;	/* message in temp file */
    FILE *f;			/* FILE * corresponding */

    char *id;			/* message id */
    int size;			/* size of message */

    /* msg envelope */
    char *return_path;		/* where to return message */
    address_data_t **rcpt;	/* to recipients of this message */
    int rcpt_num;		/* number of recipients */

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
void msg_getrcpt(message_data_t *m, int rcpt_num,
		 const char **user, const char **domain, const char **mailbox);

/* return entire recipient of 'rcpt_num' */
const char *msg_getrcptall(message_data_t *m, int rcpt_num);

/* return ignorequota flag of 'rcpt_num' */
int msg_getrcpt_ignorequota(message_data_t *m, int rcpt_num);

/* set a recipient status; 'r' should be an IMAP error code that will be
   translated into an LMTP status code */
void msg_setrcpt_status(message_data_t *m, int rcpt_num, int r);

void *msg_getrock(message_data_t *m);
void msg_setrock(message_data_t *m, void *rock);

struct addheader {
    const char *name;
    const char *body;
};

struct lmtp_func {
    int (*deliver)(message_data_t *m, 
		   char *authuser, struct auth_state *authstate);
    int (*verify_user)(const char *user, const char *domain, const char *mailbox,
		       long quotacheck, /* user must have this much quota left
					   (-1 means don't care about quota) */
		       struct auth_state *authstate);
    void (*shutdown)(int code);
    FILE *(*spoolfile)(message_data_t *m);
    void (*removespool)(message_data_t *m);
    struct namespace *namespace; /* mailbox namespace that we're working in */
    struct addheader *addheaders; /* add these headers to all messages */
    int addretpath;		/* should i add a return-path header? */
    int preauth;		/* preauth connection? */
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

struct lmtp_txn {
    const char *from;
    const char *auth;
    int isdotstuffed;		/* 1 if 'data' is a dotstuffed stream
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
	int r;			/* if non-zero, 
				   a more descriptive error code */
    } rcpt[1];
};

#define LMTP_TXN_ALLOC(n) (xmalloc(sizeof(struct lmtp_txn) + \
				   ((n) * (sizeof(struct lmtp_rcpt)))))

int lmtp_runtxn(struct backend *conn, struct lmtp_txn *txn);

#endif /* LMTPENGINE_H */
