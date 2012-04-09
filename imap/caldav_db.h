/* caldav_db.h -- abstract interface for per-mailbox CalDAV database
 *
 * Copyright (c) 1994-2011 Carnegie Mellon University.  All rights reserved.
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

struct caldav_db;

#define CALDAV_CREATE 0x01

/* get a database handle corresponding to mailbox */
int caldav_open(struct mailbox *mailbox, int flags,
		struct caldav_db **caldavdb);

/* read an entry from 'caldavdb' */
int caldav_read(struct caldav_db *caldavdb, const char *resource,
		uint32_t *uid);

/* read an entry from 'caldavdb' and leave that record (or some superset
   of it) locked for update */
int caldav_lockread(struct caldav_db *caldavdb, const char *resource,
		    uint32_t *uid);

/* write an entry to 'caldavdb' */
int caldav_write(struct caldav_db *caldavdb, const char *resource,
		 uint32_t uid);

/* delete an entry from 'caldavdb' */
int caldav_delete(struct caldav_db *caldavdb, const char *resource);

/* process each entry in 'caldavdb' with cb() */
int caldav_foreach(struct caldav_db *caldavdb,
		   int (*cb)(void *rock, const char *resource, uint32_t uid),
		   void *rock);

/* close this handle */
int caldav_close(struct caldav_db *caldavdb);

/* discard lock on handle */
int caldav_unlock(struct caldav_db *caldavdb);

/* done with all caldav operations for this process */
int caldav_done(void);

#endif /* CALDAV_DB_H */
