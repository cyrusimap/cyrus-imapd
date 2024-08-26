/* mupdate.h - private mupdate header file
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

#ifndef INCLUDED_MUPDATE_H
#define INCLUDED_MUPDATE_H

/* Quick reference to the mupdate files:
 *
 * mupdate.h: Internal header for mupdate modules.
 * mupdate-client.h: Public header for mupdate clients.
 * mupdate-client.c: Implementation of client functions
 * mupdate.c: Implementation of server functions
 * mupdate-slave.c: Slave listener thread functions.
 */

#include "backend.h"
#include "mailbox.h"
#include "mpool.h"
#include "mupdate-client.h"
#include "global.h"

/* generated headers are not necessarily in current directory */
#include "imap/mupdate_err.h"

struct mupdate_handle_s {
    sasl_callback_t *sasl_cb;
    struct backend *conn;

    /* For keeping track of what tag # is next */
    unsigned int tagn;

    /* For mupdate_scarf and mupdate_authenticate */
    struct buf tag, cmd, arg1, arg2, arg3;

    /* For client side mupdate_find calls */
    char mailbox_buf[MAX_MAILBOX_BUFFER];
    char location_buf[MAX_MAILBOX_BUFFER];
    char *acl;
    struct mupdate_mailboxdata mailboxdata_buf;

    int saslcompleted;
};

enum settype {
    SET_ACTIVE,
    SET_RESERVE,
    SET_DELETE,
    SET_DEACTIVATE
};

/* mailbox name MUST be first, since it is the key */
/* acl MUST be last, since it is what causes the variable size */
struct mbent {
    char *mailbox;
    char *location;
    enum settype t;
    struct mbent *next; /* used for queue */
    char acl[1];
};

struct mbent_queue
{
    struct mbent *head;
    struct mbent **tail;
};

/* Used to free malloc'd mbent's */
void free_mbent(struct mbent *p);

/* Used by the slave listener thread to update the local database */
int cmd_change(struct mupdate_mailboxdata *mdata,
               const char *cmd, void *context);

int mupdate_synchronize_remote(mupdate_handle *handle,
                               struct mbent_queue *remote_boxes,
                               struct mpool *pool);
/* Given an mbent_queue, will synchronize the local database to it */
int mupdate_synchronize(struct mbent_queue *remote_boxes, struct mpool *pool);

/* Signal that we are ready to accept connections */
void mupdate_ready(void);
void mupdate_unready(void);
void mupdate_signal_db_synced(void);

/* --- internal client functions (mupdate-client.c) --- */
/* these are used by the slave thread and by the client API */

enum mupdate_cmd_response {
    MUPDATE_NONE = 1,
    MUPDATE_OK = 0,
    MUPDATE_NO = -1,
    MUPDATE_BAD = -2,
    MUPDATE_BYE = -3
};

/* Scarf up the incoming data and perform the requested operations */
/* Returns 0 on no error
   otherwise MUPDATE_error. */
/* if 'wait_for_ok' is set and 'response' != NULL, *response is filled in */
int mupdate_scarf(mupdate_handle *handle,
                  mupdate_callback callback,
                  void *context,
                  int wait_for_ok,
                  enum mupdate_cmd_response *response);

#endif /* INCLUDED_MUPDATE_H */
