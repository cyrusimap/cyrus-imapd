/* mupdate.h - private mupdate header file
 *
 * $Id: mupdate.h,v 1.2 2002/01/24 21:03:22 rjs3 Exp $
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

#ifndef MUPDATE_H
#define MUPDATE_H

#include "mailbox.h"
#include "mupdate-client.h"
#include "mupdate_err.h"

struct mupdate_handle_s {
    int sock;

    struct protstream *pin;
    struct protstream *pout;

    unsigned int tag;

    sasl_conn_t *saslconn;
    int saslcompleted;
};

enum settype {
    SET_ACTIVE,
    SET_RESERVE,
    SET_DELETE
};

/* mailbox name MUST be first, since it is the key */
/* acl MUST be last, since it is what causes the variable size */
struct mbent {
    char mailbox[MAX_MAILBOX_NAME];
    char server[MAX_MAILBOX_NAME];
    enum settype t;
    struct mbent *next; /* used for queue */
    char acl[1];
};

struct mbent_queue 
{
    struct mbent *head;
    struct mbent **tail;
};

/* Callbacks for mupdate_scarf */
/* cmd is one of DELETE, MAILBOX, RESERVE */
/* context is as provided to mupdate_scarf */
typedef int (*mupdate_callback)(struct mupdate_mailboxdata *mdata,
                                const char *cmd, void *context);

/* Scarf up the incoming data and perform the requested operations */
/* Returns 0 on no error (or success, if wait_for_ok set) */
/* Returns 1 on fatal error */
/* Returns -1 on command-related error (if wait_for_ok set) */
int mupdate_scarf(mupdate_handle *handle,
		  mupdate_callback callback,
		  void *context,
		  int wait_for_ok);

/* Used by the slave listener thread to update the local database */
int cmd_change(struct mupdate_mailboxdata *mdata,
	       const char *cmd, void *context);

/* Given an mbent_queue, will synchronize the local database to it */
int mupdate_synchronize(mupdate_handle *handle);

#endif /* MUPDATE_H */
