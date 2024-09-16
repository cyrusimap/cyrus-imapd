/* dav_db.h -- abstract interface for per-user DAV database
 *
 * Copyright (c) 1994-2012 Carnegie Mellon University.  All rights reserved.
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

#ifndef DAV_DB_H
#define DAV_DB_H

#include "sqldb.h"
#include "mailbox.h"
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

#endif /* DAV_DB_H */
