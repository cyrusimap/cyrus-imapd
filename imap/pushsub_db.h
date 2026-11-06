/* pushsub_db.h -- abstract interface for per-user PushSubcription database */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

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
