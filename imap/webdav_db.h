/* webdav_db.h - abstract interface for per-user WebDAV database */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef WEBDAV_DB_H
#define WEBDAV_DB_H

#include <config.h>

/* prepare for webdav operations in this process */
int webdav_init(void);

/* done with all webdav operations for this process */
int webdav_done(void);

#ifdef WITH_DAV

#include "dav_db.h"
#include "mboxlist.h"

struct webdav_db;

#define WEBDAV_CREATE 0x01
#define WEBDAV_TRUNC  0x02

struct webdav_data {
    struct dav_data dav;  /* MUST be first so we can typecast */
    const char *filename;
    const char *type;
    const char *subtype;
    const char *res_uid;
    unsigned ref_count;
};

typedef int webdav_cb_t(void *rock, struct webdav_data *wdata);

/* get a database handle corresponding to userid */
struct webdav_db *webdav_open_userid(const char *userid);

/* get a database handle corresponding to mailbox */
struct webdav_db *webdav_open_mailbox(struct mailbox *mailbox);

/* close this handle */
int webdav_close(struct webdav_db *webdavdb);

/* lookup an entry from 'webdavdb' by resource
   (optionally inside a transaction for updates) */
int webdav_lookup_resource(struct webdav_db *webdavdb,
                           const mbentry_t *mbentry, const char *resource,
                           struct webdav_data **result,
                           int tombstones);

/* lookup an entry from 'webdavdb' by mailbox and IMAP uid
   (optionally inside a transaction for updates) */
int webdav_lookup_imapuid(struct webdav_db *webdavdb,
                          const mbentry_t *mbentry, int uid,
                          struct webdav_data **result,
                          int tombstones);

/* lookup an entry from 'webdavdb' by resource UID
   (optionally inside a transaction for updates) */
int webdav_lookup_uid(struct webdav_db *webdavdb, const char *res_uid,
                      struct webdav_data **result);

/* process each entry for 'mailbox' in 'webdavdb' with cb() */
int webdav_foreach(struct webdav_db *webdavdb, const mbentry_t *mbentry,
                   int (*cb)(void *rock, struct webdav_data *data),
                   void *rock);

/* write an entry to 'webdavdb' */
int webdav_write(struct webdav_db *webdavdb, struct webdav_data *cdata);

/* delete an entry from 'webdavdb' */
int webdav_delete(struct webdav_db *webdavdb, unsigned rowid);

/* delete all entries for 'mailbox' from 'webdavdb' */
int webdav_delmbox(struct webdav_db *webdavdb, const mbentry_t *mbentry);

/* begin transaction */
int webdav_begin(struct webdav_db *webdavdb);

/* commit transaction */
int webdav_commit(struct webdav_db *webdavdb);

/* abort transaction */
int webdav_abort(struct webdav_db *webdavdb);

/* Process each entry for 'webdavdb' with a modseq higher than oldmodseq,
 * in ascending order of modseq.
 * If mailbox is not NULL, only process entries of this mailbox.
 * If kind is non-negative, only process entries of this kind.
 * If max_records is positive, only call cb for at most this entries. */
int webdav_get_updates(struct webdav_db *webdavdb,
                       modseq_t oldmodseq, const mbentry_t *mbentry, int kind,
                       int max_records, webdav_cb_t *cb, void *rock);

#endif /* WITH_DAV */

#endif /* WEBDAV_DB_H */
