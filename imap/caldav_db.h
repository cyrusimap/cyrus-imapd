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

extern time_t caldav_epoch;
extern time_t caldav_eternity;

#include <libical/ical.h>

#include "dav_db.h"
#include "ical_support.h"
#include "mboxlist.h"

/* Bitmask of calendar components */
enum {
    /* "Real" components - MUST remain in this order (values used in DAV DB) */
    CAL_COMP_VEVENT =           (1<<0),
    CAL_COMP_VTODO =            (1<<1),
    CAL_COMP_VJOURNAL =         (1<<2),
    CAL_COMP_VFREEBUSY =        (1<<3),
    CAL_COMP_VAVAILABILITY =    (1<<4),
    CAL_COMP_VPOLL =            (1<<5),
    /* Append additional "real" components here */

    /* Other components - values don't matter - prepend here */
    CAL_COMP_VALARM =           (1<<13),
    CAL_COMP_VTIMEZONE =        (1<<14),
    CAL_COMP_VCALENDAR =        (1<<15)
};

/* Returns NULL for unknown type */
extern const char *caldav_comp_type_as_string(unsigned comp_type);

#define CAL_COMP_REAL            0xff   /* All "real" components */

struct caldav_db;

struct comp_flags {
    unsigned recurring    : 1;          /* Has RRULE property */
    unsigned transp       : 1;          /* Is TRANSParent */
    unsigned status       : 2;          /* STATUS property value (see below) */
    unsigned tzbyref      : 1;          /* VTIMEZONEs by reference */
    unsigned mattach      : 1;          /* Has managed ATTACHment(s) */
    unsigned shared       : 1;          /* Is shared (per-user-data stripped) */
    unsigned defaultalerts : 1;         /* Has default alerts property set */
    unsigned mayinviteself : 1;         /* Users may invite themselves */
    unsigned mayinviteothers : 1;       /* Attending users may invite others */
};

/* Status values */
enum {
    CAL_STATUS_BUSY = 0,
    CAL_STATUS_CANCELED,
    CAL_STATUS_TENTATIVE,
    CAL_STATUS_UNAVAILABLE
};

struct caldav_data {
    struct dav_data dav;  /* MUST be first so we can typecast */
    unsigned comp_type;
    const char *ical_uid;
    const char *organizer;
    const char *dtstart;
    const char *dtend;
    struct comp_flags comp_flags;
    const char *sched_tag;
};

typedef int caldav_cb_t(void *rock, struct caldav_data *cdata);

/* prepare for caldav operations in this process */
int caldav_init(void);

/* done with all caldav operations for this process */
int caldav_done(void);

/* get a database handle corresponding to mailbox */
struct caldav_db *caldav_open_mailbox(struct mailbox *mailbox);
struct caldav_db *caldav_open_userid(const char *userid);

/* close this handle */
int caldav_close(struct caldav_db *caldavdb);

/* lookup an entry from 'caldavdb' by resource
   (optionally inside a transaction for updates) */
int caldav_lookup_resource(struct caldav_db *caldavdb,
                           const mbentry_t *mbentry, const char *resource,
                           struct caldav_data **result,
                           int tombstones);

/* lookup an entry from 'caldavdb' by mailbox and IMAP uid
   (optionally inside a transaction for updates) */
int caldav_lookup_imapuid(struct caldav_db *caldavdb,
                          const mbentry_t *mbentry, int uid,
                          struct caldav_data **result,
                          int tombstones);

/* lookup an entry from 'caldavdb' by iCal UID
   (optionally inside a transaction for updates) */
int caldav_lookup_uid(struct caldav_db *caldavdb, const char *ical_uid,
                      struct caldav_data **result);

/* process each entry for 'mailbox' in 'caldavdb' with cb() */
int caldav_foreach(struct caldav_db *caldavdb, const mbentry_t *mbentry,
                   caldav_cb_t *cb, void *rock);

enum caldav_sort {
    CAL_SORT_NONE = 0,
    CAL_SORT_ICAL_UID,
    CAL_SORT_START,
    CAL_SORT_MAILBOX,
    CAL_SORT_IMAP_UID,
    CAL_SORT_MODSEQ,
    CAL_SORT_DESC  = 0x80 /* bit-flag for descending sort */
};

/* write an entry to 'caldavdb' */
int caldav_write(struct caldav_db *caldavdb, struct caldav_data *cdata);
int caldav_writeical(struct caldav_db *caldavdb, struct caldav_data *cdata,
                     icalcomponent *ical);

/* delete an entry from 'caldavdb' */
int caldav_delete(struct caldav_db *caldavdb, unsigned rowid);

/* delete all entries for 'mailbox' from 'caldavdb' */
int caldav_delmbox(struct caldav_db *caldavdb, const mbentry_t *mbentry);

/* begin transaction */
int caldav_begin(struct caldav_db *caldavdb);

/* commit transaction */
int caldav_commit(struct caldav_db *caldavdb);

/* abort transaction */
int caldav_abort(struct caldav_db *caldavdb);

char *caldav_mboxname(const char *userid, const char *name);

/* Process each entry for 'caldavdb' with a modseq higher than oldmodseq,
 * in ascending order of modseq.
 * If mailbox is not NULL, only process entries of this mailbox.
 * If kind is non-negative, only process entries of this kind.
 * If max_records is positive, only call cb for at most this entries. */
int caldav_get_updates(struct caldav_db *caldavdb,
                       modseq_t oldmodseq, const mbentry_t *mbentry, int kind,
                       int max_records, caldav_cb_t *cb, void *rock);

/* Update all the share ACLs */
int caldav_update_shareacls(const char *userid);

/* JSCalendar object API */

struct caldav_jscal {
    struct caldav_data cdata;
    const char *ical_recurid; // main events have empty string
    const char *dtstart;
    const char *dtend;
    int alive;
    modseq_t modseq;
    modseq_t createdmodseq;
    const char *ical_guid;
    int cacheversion;
    const char *cachedata;
};

struct caldav_jscal_filter {
    const mbentry_t *mbentry;
    const char *ical_uid;
    const char *ical_recurid;
    uint32_t imap_uid;
    const time_t *after;
    const time_t *before;
    modseq_t aftermodseq;
    int tombstones;
    size_t maxcount;
};

typedef int caldav_jscal_cb_t(void *rock, struct caldav_jscal *jscal);

int caldav_foreach_jscal(struct caldav_db *caldavdb,
                         const char *cache_userid,
                         struct caldav_jscal_filter *filter,
                         enum caldav_sort* sort, size_t nsort,
                         caldav_jscal_cb_t *cb, void *rock);

int caldav_write_jscalcache(struct caldav_db *caldavdb, int rowid,
                            const char *recurid, const char *userid,
                            int version, const char *data);

#endif /* CALDAV_DB_H */
