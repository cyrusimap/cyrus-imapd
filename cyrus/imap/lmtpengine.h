/* lmtpengine.h: lmtp protocol engine interface
 * $Id: lmtpengine.h,v 1.12 2002/03/13 21:39:17 ken3 Exp $
 *
 * Copyright (c) 2000 Carnegie Mellon University.  All rights reserved.
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

/* configuration parameters */
#define DEFAULT_SENDMAIL ("/usr/lib/sendmail")
#define DEFAULT_POSTMASTER ("postmaster")

#define SENDMAIL (config_getstring("sendmail", DEFAULT_SENDMAIL))
#define POSTMASTER (config_getstring("postmaster", DEFAULT_POSTMASTER))

/***************** server-side LMTP *******************/

#define HEADERCACHESIZE 4009

typedef struct message_data message_data_t;
typedef struct Header header_t;
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

    header_t *cache[HEADERCACHESIZE];
};

/* return the corresponding header */
const char **msg_getheader(message_data_t *m, const char *phead);

/* return message size */
int msg_getsize(message_data_t *m);

/* return # of recipients */
int msg_getnumrcpt(message_data_t *m);

/* return delivery destination of recipient 'rcpt_num' */
const char *msg_getrcpt(message_data_t *m, int rcpt_num);

/* return entire recipient of 'rcpt_num' */
const char *msg_getrcptall(message_data_t *m, int rcpt_num);

/* return ignorequota flag of 'rcpt_num' */
int msg_getrcpt_ignorequota(message_data_t *m, int rcpt_num);

/* set a recipient status; 'r' should be an IMAP error code that will be
   translated into an LMTP status code */
void msg_setrcpt_status(message_data_t *m, int rcpt_num, int r);

void *msg_getrock(message_data_t *m);
void msg_setrock(message_data_t *m, void *rock);

struct lmtp_func {
    int (*deliver)(message_data_t *m, 
		   char *authuser, struct auth_state *authstate);
    int (*verify_user)(const char *user,
		       long quotacheck, /* user must have this much quota left
					   (-1 means don't care about quota) */
		       struct auth_state *authstate);
    void (*shutdown)(int code);
    FILE *(*spoolfile)(message_data_t *m);
    char *addheaders;		/* add these headers to all messages */
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

struct lmtp_conn;

struct lmtp_txn {
    const char *from;
    const char *auth;
    int ignorequota;
    int isdotstuffed;		/* 1 if 'data' is a dotstuffed stream
                                   (including end-of-file \r\n.\r\n) */
    struct protstream *data;
    int rcpt_num;
    struct lmtp_rcpt {
	char *addr;
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


int lmtp_connect(const char *host,
		 sasl_callback_t *cb,
		 struct lmtp_conn **conn);

/* lmtp_runtxn() attempts delivery of the message in 'txn' on the
   connection 'conn'.  regardless of the return code (which indicates
   something about the protocol/connection state) 'rcpt[n].result' is
   guaranteed to be filled in. */
int lmtp_runtxn(struct lmtp_conn *conn, struct lmtp_txn *txn);

/* send a NOOP to the conn to verify it's still ok */
int lmtp_verify_conn(struct lmtp_conn *conn);

/* disconnect from lmtp server */
int lmtp_disconnect(struct lmtp_conn *conn);

#endif /* LMTPENGINE_H */
