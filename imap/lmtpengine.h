/* lmtpengine.h: lmtp protocol engine interface
 * $Id: lmtpengine.h,v 1.1 2000/05/28 23:19:40 leg Exp $
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

#ifndef LMTP_PARSE_H
#define LMTP_PARSE_H

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
    header_t *cache[HEADERCACHESIZE];
};

/*
 * to do: 
 *
 * figure out how to ask the delivery system to deliver the message multiple
 * times, and allow the delivery system to return status.
 * perhaps a register_deliver() function, and that function gets called on
 * every rcpt w/ the message, and the message 
 */

/* return the corresponding header */
const char **msg_getheader(message_data_t *m, const char *phead);

/* return message size */
int msg_getsize(message_data_t *m);

/* return # of recipients */
int msg_getnumrcpt(message_data_t *m);

/* return delivery destination of recipient 'rcpt_num' */
const char *msg_getrcpt(message_data_t *m, int rcpt_num);

/* return entire receipient of 'rcpt_num' */
const char *msg_getrcptall(message_data_t *m, int rcpt_num);

/* set a recipient status; 'r' should be an IMAP error code that will be
   translated into an LMTP status code */
void msg_setrcpt_status(message_data_t *m, int rcpt_num, int r);

struct lmtp_func {
    int (*deliver)(message_data_t *m, 
		   char *authuser, struct auth_state *authstate);
    int (*verify_user)(const char *user);
    char *addheaders;
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

#endif /* LMTP_PARSE_H */
