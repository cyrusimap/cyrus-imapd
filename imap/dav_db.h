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

#include <config.h>

#ifdef WITH_DAV

#include <sqlite3.h>
#include "dav_util.h"

struct dav_data {
    unsigned rowid;
    time_t creationdate;
    const char *mailbox;
    const char *resource;
    uint32_t imap_uid;		/* zero (0) until URL is mapped */
    const char *lock_token;
    const char *lock_owner;
    const char *lock_ownerid;
    time_t lock_expire;
};

struct bind_val {
    const char *name;
    int type;
    union {
	int i;
	const char *s;
    } val;
};

/* prepare for DAV operations in this process */
int dav_init(void);

/* done with all DAV operations for this process */
int dav_done(void);

/* get a database handle corresponding to mailbox */
sqlite3 *dav_open(struct mailbox *mailbox, const char *cmds);

/* close this handle */
int dav_close(sqlite3 *davdb);

/* execute 'cmd' and process results with 'cb'
   'cmd' is prepared as 'stmt' with 'bval' as bound values */
int dav_exec(sqlite3 *davdb, const char *cmd, struct bind_val bval[],
	     int (*cb)(sqlite3_stmt *stmt, void *rock), void *rock,
	     sqlite3_stmt **stmt);

/* delete database corresponding to mailbox */
int dav_delete(struct mailbox *mailbox);

#endif /* WITH_DAV */

#endif /* DAV_DB_H */
