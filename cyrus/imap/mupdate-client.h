/* mupdate-client.h -- cyrus murder database clients
 *
 * $Id: mupdate-client.h,v 1.5 2002/01/25 19:51:55 rjs3 Exp $
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

#ifndef INCLUDED_MUPDATE_CLIENT_H
#define INCLUDED_MUPDATE_CLIENT_H

#include <sasl/sasl.h>
#include "mupdate_err.h"

typedef struct mupdate_handle_s mupdate_handle;

/* connect & authenticate to an mupdate server */
int mupdate_connect(const char *server, const char *port,
		    mupdate_handle **handle, sasl_callback_t *cbs);

/* disconnect from mupdate server */
void mupdate_disconnect(mupdate_handle **h);

/* activate a mailbox */
int mupdate_activate(mupdate_handle *handle, 
		     const char *mailbox, const char *server,
		     const char *acl);

/* reserve a piece of namespace */
int mupdate_reserve(mupdate_handle *handle,
		    const char *mailbox, const char *server);

/* delete a mailbox */
int mupdate_delete(mupdate_handle *handle,
		   const char *mailbox);

/* mailbox data structure */
struct mupdate_mailboxdata {
    const char *mailbox;
    const char *server;
    const char *acl;
};

/* does a given mailbox exist?  1 if false, 0 if true, -1 if error,
 * if target is non-null, it fills in the caller-provided buffer 
 */
int mupdate_find(mupdate_handle *handle, const char *mailbox,
		 struct mupdate_mailboxdata **target);

#endif
