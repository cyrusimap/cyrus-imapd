/* dav_db.h - abstract interface for per-user DAV database */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef DAV_DB_H
#define DAV_DB_H

#include "sqldb.h"
#include "mailbox.h"
#include "mboxlist.h"
#include "util.h"

#define FNAME_DAVSUFFIX "dav" /* per-user DAV DB extension */

#define DB_MBOXID_VERSION 11     /* first version with records by mboxid */

struct dav_data {
    unsigned rowid;
    time_t creationdate;
    const char *mailbox;
    const char *resource;
    uint32_t imap_uid;          /* zero (0) until URL is mapped */
    modseq_t modseq;
    modseq_t createdmodseq;
    const char *lock_token;
    const char *lock_owner;
    const char *lock_ownerid;
    time_t lock_expire;
    int alive;
    int mailbox_byname;         /* NOT stored in record - derived from db ver */
};

/* Create filename corresponding to DAV DB for mailbox */
void dav_getpath(struct buf *fname, struct mailbox *mailbox);

/* Create filename corresponding to DAV DB for userid */
void dav_getpath_byuserid(struct buf *fname, const char *userid);

/* get a database handle corresponding to mailbox */
sqldb_t *dav_open_userid(const char *userid);
sqldb_t *dav_open_mailbox(struct mailbox *mailbox);
int dav_close(sqldb_t **dbp);

/* delete database corresponding to mailbox */
int dav_delete(struct mailbox *mailbox);

int dav_reconstruct_user(const char *userid, const char *audit_tool);

int dav_attach_userid(sqldb_t *db, const char *userid);
int dav_attach_mailbox(sqldb_t *db, struct mailbox *mailbox);

/**
 * Call a function for each locked resource of a mailbox.
 *
 * Only live resources holding a write lock that has not expired at @p now
 * are visited.
 *
 * @param db       the DAV DB holding the resources of the mailbox
 * @param mbentry  the mailbox whose resources are visited; its type selects
 *                 the table (calendar, address book or generic DAV)
 * @param now      the time against which lock expiry is checked
 * @param cb       called with @p rock, the resource name, its lock token and
 *                 the userid of the lock owner; a non-zero return stops the
 *                 walk
 * @param rock     passed through to @p cb
 *
 * @return 0 if every call to @p cb returned 0, otherwise the first non-zero
 *         value returned by @p cb, or an error from the database
 */
int dav_foreach_lock(sqldb_t *db,
                     const mbentry_t *mbentry,
                     time_t now,
                     int (*cb)(void *rock,
                               const char *resource,
                               const char *token,
                               const char *ownerid),
                     void *rock);

#endif /* DAV_DB_H */
