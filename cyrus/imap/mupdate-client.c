/* mupdate-client.c -- cyrus murder database clients
 *
 * $Id: mupdate-client.c,v 1.1 2001/10/23 20:17:21 leg Exp $
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

#include "xmalloc.h"

struct mupdate_handle_s {
    int sock;
    int authed;
    struct protstream *pin;
    struct protstream *pout;
    sasl_conn_t *saslconn;
};

int mupdate_connect(const char *server, mupdate_handle **handle)
{
    mupdate_handle *h = xzmalloc(sizeof(mupdate_handle));

    /* open connection to 'server' */

    /* create protstream */
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
    if (!handle->authed) return MUPDATE_NOAUTH;


}

int mupdate_reserve(mupdate_handle *handle,
		    const char *mailbox, const char *server)
{
    if (!handle) return MUPDATE_BADPARAM;
    if (!mailbox || !server) return MUPDATE_BADPARAM;
    if (!handle->authed) return MUPDATE_NOAUTH;


}

int mupdate_delete(mupdate_handle *handle,
		   const char *mailbox)
{
    if (!handle) return MUPDATE_BADPARAM;
    if (!mailbox) return MUPDATE_BADPARAM;
    if (!handle->authed) return MUPDATE_NOAUTH;


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
    if (!handle) return MUPDATE_BADPARAM;
    if (pinginterval < 0 || pingtimeout < 0) return MUPDATE_BADPARAM;
    if (!handle->authed) return MUPDATE_NOAUTH;

    /* ask for updates */

    /* set protstream nonblocking */


    for (;;) {
	/* select for 'pinginterval' */

	if (gotdata) {
	    /* make the callbacks, if requested */
	    
	    /* if any callbacks fail, return */

	    continue;
	} else {
	    /* timed out, send a NOOP */

	    /* wait 'pingtimeout' seconds for response */

	    
	}

    }


}

