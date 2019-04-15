/* webdav_db.h -- abstract interface for per-user WebDAV database
 *
 * Copyright (c) 1994-2015 Carnegie Mellon University.  All rights reserved.
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
                       modseq_t oldmodseq, const char *mboxname, int kind,
                       int max_records, webdav_cb_t *cb, void *rock);

#endif /* WITH_DAV */

#endif /* WEBDAV_DB_H */
