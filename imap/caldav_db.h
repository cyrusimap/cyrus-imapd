/* caldav_db.h -- abstract interface for per-user CalDAV database
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

#ifndef CALDAV_DB_H
#define CALDAV_DB_H

#include "dav_db.h"

struct caldav_db;

#define CALDAV_CREATE 0x01
#define CALDAV_TRUNC  0x02

struct caldav_data {
    unsigned rowid;
    const char *mailbox;
    const char *resource;
    uint32_t imap_uid;
    const char *ical_uid;
    unsigned comp_type;
    const char *organizer;
    const char *sched_tag;
    const char *dtstart;
    const char *dtend;
    unsigned recurring;
    unsigned transp;
};

/* prepare for caldav operations in this process */
int caldav_init(void);

/* done with all caldav operations for this process */
int caldav_done(void);

/* get a database handle corresponding to userid */
struct caldav_db *caldav_open(const char *userid, int flags);

/* close this handle */
int caldav_close(struct caldav_db *caldavdb);

/* read an entry from 'caldavdb' */
int caldav_read(struct caldav_db *caldavdb, struct caldav_data *cdata);

/* read an entry from 'caldavdb' and begin a transaction for updates */
int caldav_lockread(struct caldav_db *caldavdb, struct caldav_data *cdata);

/* process each entry for 'mailbox' in 'caldavdb' with cb() */
int caldav_foreach(struct caldav_db *caldavdb, const char *mailbox,
		   int (*cb)(void *rock,
			     const char *resource, uint32_t imap_uid),
		   void *rock);

/* write an entry to 'caldavdb' */
int caldav_write(struct caldav_db *caldavdb, struct caldav_data *cdata);

/* delete an entry from 'caldavdb' */
int caldav_delete(struct caldav_db *caldavdb, struct caldav_data *cdata);

/* delete all entries for 'mailbox' from 'caldavdb' */
int caldav_delmbox(struct caldav_db *caldavdb, const char *mailbox);

/* commit transaction */
int caldav_commit(struct caldav_db *caldavdb);

/* abort transaction */
int caldav_abort(struct caldav_db *caldavdb);

/* create caldav_data from icalcomponent */
void caldav_make_entry(icalcomponent *ical, struct caldav_data *cdata);

#endif /* CALDAV_DB_H */
