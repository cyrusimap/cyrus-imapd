/* mupdate-client.c -- cyrus murder database clients
 *
 * $Id: mupdate-client.c,v 1.2 2002/01/16 17:56:37 rjs3 Exp $
 * Copyright (c) 2001 Carnegie Mellon University.  All rights reserved.
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

#include <config.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <sasl/sasl.h>
#ifdef __STDC__
#include <stdarg.h>
#else
#include <varargs.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <sys/types.h>
#include <sys/time.h>
#include <netinet/in.h>
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif

#include "prot.h"
#include "xmalloc.h"
#include "assert.h"
#include "mupdate_err.h"

typedef struct mupdate_handle_s {
    int sock;

    struct protstream *pin;
    struct protstream *pout;

    int tag;

    sasl_conn_t *saslconn;
    int saslcompleted;
} mupdate_handle;

static const sasl_callback_t callbacks[] = {
  { SASL_CB_USER, NULL, NULL }, 
  { SASL_CB_GETREALM, NULL, NULL }, 
  { SASL_CB_AUTHNAME, NULL, NULL }, 
  { SASL_CB_PASS, NULL, NULL },
  { SASL_CB_LIST_END, NULL, NULL }
};

int mupdate_connect(const char *server, const char *port, mupdate_handle **handle)
{
    mupdate_handle *h;
    struct hostent *hp;
    struct servent *sp;
    struct sockaddr_in addr;
    int s, saslresult;
    
    if(!server || !handle)
	return MUPDATE_BADPARAM;

    /* open connection to 'server' */
    hp = gethostbyname(server);
    if(!hp) return -2;
    
    s = socket(AF_INET, SOCK_STREAM, 0);
    if(s == -1) return errno;
    
    addr.sin_family = AF_INET;
    memcpy(&addr.sin_addr, hp->h_addr, sizeof(addr.sin_addr));

    if (port && imparse_isnumber(port)) {
	addr.sin_port = htons(atoi(port));
    } else if (port) {
	sp = getservbyname(port, "tcp");
	if (!sp) return -2;
	addr.sin_port = sp->s_port;
    } else {
	addr.sin_port = htons(1234); /* FIXME: how about a real port number?! */
    }

    if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
	return errno;
    }

    h = xzmalloc(sizeof(mupdate_handle));
    h->sock = s;

    saslresult = sasl_client_new("imap", /* FIXME: real service name? */
				 server,
				 NULL, NULL,
				 callbacks,
				 0,
				 &(h->saslconn));

    /* create protstream */
    h->pin=prot_new(h->sock, 0);
    h->pout=prot_new(h->sock, 1);

    *handle = h;
    return 0; /* SUCCESS */
}


int mupdate_authenticate(mupdate_handle *handle)
{
    /* create 'saslconn'? how to enable client to set sasl stuff? */

}

int mupdate_activate(mupdate_handle *handle, 
		     const char *mailbox, const char *server,
		     const char *acl)
{
    if (!handle) return MUPDATE_BADPARAM;
    if (!mailbox || !server || !acl) return MUPDATE_BADPARAM;
    if (!handle->saslcompleted) return MUPDATE_NOAUTH;


}

int mupdate_reserve(mupdate_handle *handle,
		    const char *mailbox, const char *server)
{
    if (!handle) return MUPDATE_BADPARAM;
    if (!mailbox || !server) return MUPDATE_BADPARAM;
    if (!handle->saslcompleted) return MUPDATE_NOAUTH;


}

int mupdate_delete(mupdate_handle *handle,
		   const char *mailbox)
{
    if (!handle) return MUPDATE_BADPARAM;
    if (!mailbox) return MUPDATE_BADPARAM;
    if (!handle->saslcompleted) return MUPDATE_NOAUTH;


}

struct mupdate_mailboxdata {
    const char *mailbox;
    const char *server;
    const char *acl;
};
typedef int (*mupdate_callback)(struct mupdate_mailboxdata *mdata, 
				const char *rock);
int mupdate_listen(mupdate_handle *handle,
		   mupdate_callback *create,
		   mupdate_callback *reserve,
		   mupdate_callback *delete,
		   mupdate_callback *noop,
		   int pinginterval, int pingtimeout)
{
    int gotdata = 0;

    if (!handle) return MUPDATE_BADPARAM;
    if (pinginterval < 0 || pingtimeout < 0) return MUPDATE_BADPARAM;
    if (!handle->saslcompleted) return MUPDATE_NOAUTH;

    /* ask for updates */

    /* set protstream nonblocking */


    for (;;) {
	/* select for 'pinginterval' */

	if (gotdata) {
	    /* make the callbacks, if requested */
	    
	    /* if any callbacks fail, return */

	    continue;
	} else {
	    prot_printf(handle->pout, "X%d NOOP\r\n", handle->tag++);
	    /* timed out, send a NOOP */

	    /* wait 'pingtimeout' seconds for response */

	    
	}

    }


}

