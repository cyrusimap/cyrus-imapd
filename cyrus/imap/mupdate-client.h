/* mupdate-client.h -- cyrus murder database clients
 *
 * $Id: mupdate-client.h,v 1.10 2002/01/31 17:46:48 rjs3 Exp $
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

#define FNAME_MUPDATE_TARGET_SOCK "/socket/mupdate.target"

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

enum mbtype {
    ACTIVE, RESERVE 
};

/* mailbox data structure */
struct mupdate_mailboxdata {
    const char *mailbox;
    const char *server;
    const char *acl;
    enum mbtype t;
};

/* does a given mailbox exist?  1 if false, 0 if true, -1 if error,
 * "target" gets pointed at a struct mudate_mailboxdata that is only valid
 * until the next mupdate_* call on this mupdate_handle.
 */
int mupdate_find(mupdate_handle *handle, const char *mailbox,
		 struct mupdate_mailboxdata **target);

/* Callbacks for mupdate_scarf and mupdate_list */
/* cmd is one of DELETE, MAILBOX, RESERVE */
/* context is as provided to mupdate_scarf */
/* FIXME/xxx: "cmd" can probabally go away and instead
 * we just use the t in mdata */
typedef int (*mupdate_callback)(struct mupdate_mailboxdata *mdata,
                                const char *cmd, void *context);

/* perform an MUPDATE LIST operation (callback is called for
 * each remote mailbox) */
int mupdate_list(mupdate_handle *handle, mupdate_callback callback,
		 const char *prefix, void *context);

#endif
