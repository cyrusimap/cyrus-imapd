/* carddav_db.h -- abstract interface for per-user CardDAV database
 *
 * Copyright (c) 1994-2013 Carnegie Mellon University.  All rights reserved.
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

#ifndef CARDDAV_DB_H
#define CARDDAV_DB_H

#include <config.h>

/* prepare for carddav operations in this process */
int carddav_init(void);

/* done with all carddav operations for this process */
int carddav_done(void);

#ifdef WITH_DAV

#include <libical/vcc.h>

#include "dav_db.h"

struct carddav_db;

#define CARDDAV_CREATE 0x01
#define CARDDAV_TRUNC  0x02

struct carddav_data {
    struct dav_data dav;  /* MUST be first so we can typecast */
    unsigned version;
    const char *vcard_uid;
    unsigned kind;
    const char *fullname;
    const char *name;
    const char *nickname;
    const char *email;
};

/* get a database handle corresponding to mailbox */
struct carddav_db *carddav_open(struct mailbox *mailbox, int flags);

/* close this handle */
int carddav_close(struct carddav_db *carddavdb);

/* lookup an entry from 'carddavdb' by resource
   (optionally inside a transaction for updates) */
int carddav_lookup_resource(struct carddav_db *carddavdb,
			   const char *mailbox, const char *resource,
			   int lock, struct carddav_data **result);

/* lookup an entry from 'carddavdb' by iCal UID
   (optionally inside a transaction for updates) */
int carddav_lookup_uid(struct carddav_db *carddavdb, const char *ical_uid,
		      int lock, struct carddav_data **result);

/* process each entry for 'mailbox' in 'carddavdb' with cb() */
int carddav_foreach(struct carddav_db *carddavdb, const char *mailbox,
		   int (*cb)(void *rock, void *data),
		   void *rock);

/* write an entry to 'carddavdb' */
int carddav_write(struct carddav_db *carddavdb, struct carddav_data *cdata,
		 int commit);

/* delete an entry from 'carddavdb' */
int carddav_delete(struct carddav_db *carddavdb, unsigned rowid, int commit);

/* delete all entries for 'mailbox' from 'carddavdb' */
int carddav_delmbox(struct carddav_db *carddavdb, const char *mailbox, int commit);

/* begin transaction */
int carddav_begin(struct carddav_db *carddavdb);

/* commit transaction */
int carddav_commit(struct carddav_db *carddavdb);

/* abort transaction */
int carddav_abort(struct carddav_db *carddavdb);

#endif /* WITH_DAV */

#endif /* CARDDAV_DB_H */
