/* caldav_util.h - utility functions for dealing with CALDAV database */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef CALDAV_UTIL_H
#define CALDAV_UTIL_H

#include <libical/ical.h>

#include "caldav_db.h"
#include "hash.h"
#include "mailbox.h"
#include "strarray.h"


#define NEW_STAG (1<<8)           /* Make sure we skip over PREFER bits */
#define TZ_STRIP (1<<9)
#define PERMS_NOKEEP (1<<10)      /* Do not keep JMAP permissions during event updates  */

#define SHARED_MODSEQ \
    DAV_ANNOT_NS "<" XML_NS_CYRUS ">shared-modseq"


extern void replace_tzid_aliases(icalcomponent *ical,
                                 struct hash_table *tzid_table);

extern void strip_vtimezones(icalcomponent *ical);

extern int caldav_is_personalized(struct mailbox *mailbox,
                                  const struct caldav_data *cdata,
                                  const char *userid,
                                  struct buf *userdata);

extern icalcomponent *caldav_record_to_ical(struct mailbox *mailbox,
                                            const struct caldav_data *cdata,
                                            const char *userid,
                                            strarray_t *schedule_addresses);

extern int caldav_get_validators(struct mailbox *mailbox, void *data,
                                 const char *userid, struct index_record *record,
                                 const char **etag, time_t *lastmod);

typedef struct transaction_t txn_t; // defined in httpd.h
extern int caldav_store_resource(struct transaction_t *txn, icalcomponent *ical,
                                 struct mailbox *mailbox, const char *resource,
                                 modseq_t createdmodseq, struct caldav_db *caldavdb,
                                 unsigned flags, const char *userid,
                                 const strarray_t *add_imapflags,
                                 const strarray_t *del_imapflags,
                                 const strarray_t *schedule_addresses);

/* Create the calendar home, default calendars and scheduling
 * boxes for userid, if they don't already exist. */
extern unsigned long config_types_to_caldav_types(void);
extern int caldav_create_defaultcalendars(const char *userid,
                                          const struct namespace *namespace,
                                          const struct auth_state *authstate,
                                          mbentry_t **mbentryp);

extern int caldav_is_secretarymode(const char *mboxname);

extern void caldav_attachment_url(struct buf *buf, const char *userid,
                                  const char *baseurl, const char *managedid);

/* Update refcounts for managed attachments owned by userid.
 * For updated events, both ical and oldical must be non-null.
 * for deleted events, ical must be null.
 * Returns HTTP_NOT_FOUND for any invalid managed id, or some
 * other HTTP error on internal error. */
extern int caldav_manage_attachments(const char *userid,
                                     icalcomponent *ical,
                                     icalcomponent *oldical);

enum caldav_rewrite_attachments_mode {
    caldav_attachments_to_binary,
    caldav_attachments_to_url
};

// implemented in http_caldav_sched.c
extern void caldav_rewrite_attachments(const char *userid,
                                       enum caldav_rewrite_attachments_mode mode,
                                       icalcomponent *oldical,
                                       icalcomponent *newical,
                                       icalcomponent **myoldicalp,
                                       icalcomponent **mynewicalp);

#define CALDAV_REWRITE_ATTACHPROP_TO_URL_NBUFS 2
extern void caldav_rewrite_attachprop_to_url(struct webdav_db *webdavdb,
                                             icalproperty *prop,
                                             struct buf *baseurl,
                                             struct buf *bufs);

/* Bump the modseq of all records in mailbox that contain iCalendar
 * components with enabled default alarms. Also forces calalarmd to
 * recalculate the alarms for these records.
 *
 * Side-effect warning: if the mailbox has an open annotation state
 * that isn't scoped to SCOPE_MESSAGE, then the state is committed
 * and rescoped to messages. */
extern int caldav_bump_defaultalarms(struct mailbox *mailbox);

extern int caldav_get_usedefaultalerts(struct dlist *dl,
                                       struct mailbox *mailbox,
                                       const struct index_record *record,
                                       icalcomponent **icalp);


extern int caldav_is_secretarymode(const char *mboxname);

#ifdef WITH_JMAP
extern int caldav_init_jmapcalendar(const char *userid, struct mailbox *mailbox);
#endif

extern icaltimetype caldav_get_historical_cutoff();

#endif /* HTTP_CALDAV_H */
