/* sieve_db.h - abstract interface for per-user Sieve database */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef SIEVE_DB_H
#define SIEVE_DB_H

#include <config.h>

#include <stdbool.h>

#include "mailbox.h"
#include "sqldb.h"
#include "user.h"

struct sieve_db;

#define SIEVE_CREATE 0x01
#define SIEVE_TRUNC  0x02

#define SIEVE_EXTENSION ".sieve"

struct sieve_data {
    unsigned rowid;
    time_t creationdate;
    time_t lastupdated;
    const char *mailbox;
    uint32_t imap_uid;
    modseq_t modseq;
    modseq_t createdmodseq;
    const char *id;
    const char *name;
    const char *contentid;
    unsigned isactive;
    int alive;
};

typedef int sieve_cb_t(void *rock, struct sieve_data *sdata);

/* prepare for sieve operations in this process */
int sievedb_init(void);

/* done with all sieve operations for this process */
int sievedb_done(void);

/* get a database handle corresponding to userid */
struct sieve_db *sievedb_open_userid(const char *userid);

/* get a database handle corresponding to mailbox */
struct sieve_db *sievedb_open_mailbox(struct mailbox *mailbox);

/* close this handle */
int sievedb_close(struct sieve_db *sievedb);

/* lookup an entry from 'sievedb' by script name
   (optionally inside a transaction for updates) */
int sievedb_lookup_name(struct sieve_db *sievedb, const char *name,
                        struct sieve_data **result, int tombstones);

/* lookup an entry from 'sievedb' by id
   (optionally inside a transaction for updates) */
int sievedb_lookup_id(struct sieve_db *sievedb, const char *id,
                      struct sieve_data **result, int tombstones);

/* lookup an entry from 'sievedb' by IMAP uid
   (optionally inside a transaction for updates) */
int sievedb_lookup_imapuid(struct sieve_db *sievedb, int uid,
                           struct sieve_data **result, int tombstones);

int sievedb_lookup_active(struct sieve_db *sievedb,
                          struct sieve_data **result);

/* process each entry in 'sievedb' with cb() */
int sievedb_foreach(struct sieve_db *sievedb,
                    int (*cb)(void *rock, struct sieve_data *data),
                    void *rock);

/* write an entry to 'sievedb' */
int sievedb_write(struct sieve_db *sievedb, struct sieve_data *sdata);

/* delete an entry from 'sievedb' */
int sievedb_delete(struct sieve_db *sievedb, unsigned rowid);

/* delete all entries for 'mailbox' from 'sievedb' */
int sievedb_delmbox(struct sieve_db *sievedb);

/* begin transaction */
int sievedb_begin(struct sieve_db *sievedb);

/* commit transaction */
int sievedb_commit(struct sieve_db *sievedb);

/* abort transaction */
int sievedb_abort(struct sieve_db *sievedb);

/* Process each entry for 'sievedb' with a modseq higher than oldmodseq,
 * in ascending order of modseq.
 * If max_records is positive, only call cb for at most this entries. */
int sievedb_get_updates(struct sieve_db *sievedb, modseq_t oldmodseq,
                        int max_records, sieve_cb_t *cb, void *rock);

/* count number of scripts */
int sievedb_count(struct sieve_db *sievedb, int *count);

int sieve_script_store(struct mailbox *mailbox, struct sieve_data *sdata,
                       const struct buf *content);

int sieve_script_activate(struct mailbox *mailbox, struct sieve_data *sdata);

int sieve_script_remove(struct mailbox *mailbox, struct sieve_data *sdata);

int sieve_script_rename(struct mailbox *mailbox,
                        struct sieve_data *sdata, const char *newname);

int sieve_script_fetch(struct mailbox *mailbox,
                       const struct sieve_data *sdata, struct buf *content);

/**
 * Whether a userid names the global Sieve scripts rather than a user's.
 *
 * A userid with no localpart, "" or "@domain", names the global scripts of
 * the server or of that domain.  They are kept in a shared mailbox, which
 * only admins may access, rather than in a user's.
 *
 * @param userid  a userid, or "" or "@domain"
 * @return        true if @p userid names global scripts
 */
bool sieve_userid_isglobal(const char *userid);

/**
 * Make sure the Sieve mailbox of a user, or the global one, exists.
 *
 * Creates the mailbox if need be, and moves into it any scripts still kept
 * in the corresponding Sieve directory.
 *
 * @param userid      the owner, or "" or "@domain" for global scripts
 * @param mailboxptr  if not NULL, set to the opened (write-locked) mailbox;
 *                    if NULL and the Sieve directory doesn't exist, nothing
 *                    is created
 * @param silent      don't record the changes for replication
 * @return            0 on success, or an IMAP error code
 */
int sieve_ensure_folder(const char *userid, struct mailbox **mailboxptr,
                        int silent);

/**
 * Bring a script's bytecode in a Sieve directory up to date.
 *
 * The script is read from the Sieve mailbox of @p userid if it is stored
 * there, else from the script file in @p sievedir.
 *
 * @param userid    the owner, or "" or "@domain" for global scripts
 * @param sievedir  the Sieve directory holding the bytecode
 * @param script    the script's name
 * @return          0 on success, or an IMAP error code
 */
int sieve_script_rebuild(const char *userid,
                         const char *sievedir, const char *script);

/**
 * Lock the namespace that protects a user's, or the global, Sieve mailbox.
 *
 * @param userid  the owner, or "" or "@domain" for global scripts
 * @return        the lock, to release with user_nslock_release()
 */
user_nslock_t *sieve_nslock_lock_w(const char *userid);

/**
 * Name the Sieve mailbox of a user, or of the global scripts.
 *
 * @param userid  the owner, or "" or "@domain" for global scripts
 * @return        the internal mailbox name, which the caller must free
 */
char *sieve_mboxname(const char *userid);

#endif /* SIEVE_DB_H */
