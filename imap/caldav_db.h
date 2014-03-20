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

#include <config.h>

/* prepare for caldav operations in this process */
int caldav_init(void);

/* done with all caldav operations for this process */
int caldav_done(void);

#ifdef WITH_DAV

#include <libical/ical.h>

#include "dav_db.h"

#ifndef HAVE_VAVAILABILITY
/* Allow us to compile without #ifdef HAVE_VAVAILABILITY everywhere */
#define ICAL_VAVAILABILITY_COMPONENT  ICAL_NO_COMPONENT
#endif

#ifndef HAVE_VPOLL
/* Allow us to compile without #ifdef HAVE_VPOLL everywhere */
#define ICAL_VPOLL_COMPONENT   	      ICAL_NO_COMPONENT
#define ICAL_METHOD_POLLSTATUS	      ICAL_METHOD_NONE
#define ICAL_VOTER_PROPERTY	      ICAL_NO_PROPERTY
#define icalproperty_get_voter	      icalproperty_get_attendee
#endif

/* Bitmask of calendar components */
enum {
    /* "Real" components - MUST remain in this order (values used in DAV DB) */
    CAL_COMP_VEVENT =		(1<<0),
    CAL_COMP_VTODO =		(1<<1),
    CAL_COMP_VJOURNAL =		(1<<2),
    CAL_COMP_VFREEBUSY =	(1<<3),
    CAL_COMP_VAVAILABILITY =	(1<<4),
    CAL_COMP_VPOLL =	   	(1<<5),
    /* Append additional "real" components here */

    /* Other components - values don't matter - prepend here */
    CAL_COMP_VALARM =		(1<<13),
    CAL_COMP_VTIMEZONE =	(1<<14),
    CAL_COMP_VCALENDAR =	(1<<15)
};

struct caldav_db;

#define CALDAV_CREATE 0x01
#define CALDAV_TRUNC  0x02

struct caldav_data {
    struct dav_data dav;  /* MUST be first so we can typecast */
    unsigned comp_type;
    const char *ical_uid;
    const char *organizer;
    const char *dtstart;
    const char *dtend;
    unsigned recurring;
    unsigned transp;
    const char *sched_tag;
};

/* get a database handle corresponding to mailbox */
struct caldav_db *caldav_open(struct mailbox *mailbox, int flags);

/* close this handle */
int caldav_close(struct caldav_db *caldavdb);

/* lookup an entry from 'caldavdb' by resource
   (optionally inside a transaction for updates) */
int caldav_lookup_resource(struct caldav_db *caldavdb,
			   const char *mailbox, const char *resource,
			   int lock, struct caldav_data **result);

/* lookup an entry from 'caldavdb' by iCal UID
   (optionally inside a transaction for updates) */
int caldav_lookup_uid(struct caldav_db *caldavdb, const char *ical_uid,
		      int lock, struct caldav_data **result);

/* process each entry for 'mailbox' in 'caldavdb' with cb() */
int caldav_foreach(struct caldav_db *caldavdb, const char *mailbox,
		   int (*cb)(void *rock, void *data),
		   void *rock);

/* write an entry to 'caldavdb' */
int caldav_write(struct caldav_db *caldavdb, struct caldav_data *cdata,
		 int commit);

/* delete an entry from 'caldavdb' */
int caldav_delete(struct caldav_db *caldavdb, unsigned rowid, int commit);

/* delete all entries for 'mailbox' from 'caldavdb' */
int caldav_delmbox(struct caldav_db *caldavdb, const char *mailbox, int commit);

/* begin transaction */
int caldav_begin(struct caldav_db *caldavdb);

/* commit transaction */
int caldav_commit(struct caldav_db *caldavdb);

/* abort transaction */
int caldav_abort(struct caldav_db *caldavdb);

/* create caldav_data from icalcomponent */
void caldav_make_entry(icalcomponent *ical, struct caldav_data *cdata);

int caldav_mboxname(const char *name, const char *userid, char *result);

#endif /* WITH_DAV */

#endif /* CALDAV_DB_H */
