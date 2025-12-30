/* pushsub_db.h -- abstract interface for per-user PushSubcription database
 *
 * Copyright (c) 1994-2022 Carnegie Mellon University.  All rights reserved.
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
 *
 */

#ifndef PUSHSUB_DB_H
#define PUSHSUB_DB_H

#include <config.h>

#include "mailbox.h"
#include "sqldb.h"

struct pushsub_db;

#define PUSHSUB_CREATE 0x01
#define PUSHSUB_TRUNC  0x02

struct pushsub_data {
    unsigned rowid;
    const char *mailbox;
    uint32_t imap_uid;
    const char *id;
    const char *subscription;
    time_t expires;
    unsigned isverified;
    int alive;
};

typedef int pushsub_cb_t(void *rock, struct pushsub_data *psdata);

/* prepare for pushsub operations in this process */
int pushsubdb_init(void);

/* done with all pushsub operations for this process */
int pushsubdb_done(void);

/* get a database handle corresponding to userid */
struct pushsub_db *pushsubdb_open_userid(const char *userid);

/* get a database handle corresponding to mailbox */
struct pushsub_db *pushsubdb_open_mailbox(struct mailbox *mailbox);

/* close this handle */
int pushsubdb_close(struct pushsub_db *pushsubdb);

/* lookup an entry from 'pushsubdb' by id
   (optionally inside a transaction for updates) */
int pushsubdb_lookup_id(struct pushsub_db *pushsubdb, const char *id,
                      struct pushsub_data **result, int tombstones);

/* lookup an entry from 'pushsubdb' by IMAP uid
   (optionally inside a transaction for updates) */
int pushsubdb_lookup_imapuid(struct pushsub_db *pushsubdb, int uid,
                           struct pushsub_data **result, int tombstones);

/* process each entry in 'pushsubdb' with cb() */
int pushsubdb_foreach(struct pushsub_db *pushsubdb,
                    int (*cb)(void *rock, struct pushsub_data *data),
                    void *rock);

/* write an entry to 'pushsubdb' */
int pushsubdb_write(struct pushsub_db *pushsubdb, struct pushsub_data *psdata);

/* delete an entry from 'pushsubdb' */
int pushsubdb_delete(struct pushsub_db *pushsubdb, unsigned rowid);

/* begin transaction */
int pushsubdb_begin(struct pushsub_db *pushsubdb);

/* commit transaction */
int pushsubdb_commit(struct pushsub_db *pushsubdb);

/* abort transaction */
int pushsubdb_abort(struct pushsub_db *pushsubdb);

int pushsub_ensure_folder(const char *userid, struct mailbox **mailboxptr);

/* calculate a mailbox name */
char *pushsub_mboxname(const char *userid);

#endif /* PUSHSUB_DB_H */
