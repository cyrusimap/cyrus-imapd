/* http_caldav.h -- Routines for dealing with CALDAV in httpd
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

#ifndef HTTP_CALDAV_H
#define HTTP_CALDAV_H

/* Create the calendar home, default calendars and scheduling
 * boxes for userid, if they don't already exist. */
extern unsigned long config_types_to_caldav_types(void);
extern int caldav_create_defaultcalendars(const char *userid);

extern int caldav_store_resource(struct transaction_t *txn, icalcomponent *ical,
                                 struct mailbox *mailbox, const char *resource,
                                 modseq_t createdmodseq,
                                 struct caldav_db *caldavdb, unsigned flags,
                                 const strarray_t *add_imapflags,
                                 const strarray_t *del_imapflags,
                                 const char *userid, const strarray_t *schedule_addresses);

extern icalcomponent *caldav_record_to_ical(struct mailbox *mailbox,
                                            const struct caldav_data *cdata,
                                            const char *userid,
                                            strarray_t *schedule_addresses);

extern int caldav_is_personalized(struct mailbox *mailbox,
                                  const struct caldav_data *cdata,
                                  const char *userid,
                                  struct buf *userdata);

extern char *caldav_scheddefault(const char *userid);

extern void caldav_attachment_url(struct buf *buf, const char *userid,
                                  const char *proto, const char *host,
                                  const char *managedid);

/* Update refcounts for managed attachments owned by userid.
 * For updated events, both ical and oldical must be non-null.
 * for deleted events, ical must be null.
 * Returns HTTP_NOT_FOUND for any invalid managed id, or some
 * other HTTP error on internal error. */
extern int caldav_manage_attachments(const char *userid,
                                     icalcomponent *ical,
                                     icalcomponent *oldical);

#define CALDAV_DEFAULTALARMS_ANNOT_WITHTIME \
    DAV_ANNOT_NS "<" XML_NS_CALDAV ">default-alarm-vevent-datetime"

#define CALDAV_DEFAULTALARMS_ANNOT_WITHDATE \
    DAV_ANNOT_NS "<" XML_NS_CALDAV ">default-alarm-vevent-date"

/* Read the default alarms for mailbox mboxname and userid as
 * icalcomponent. The VALARMs are wrapped inside a libical
 * XROOT component */
extern icalcomponent *caldav_read_calendar_icalalarms(const char *mboxname,
                                                      const char *userid,
                                                      const char *annot);

/* Write the default alarms in ical to annot, or delete if ical is NULL.
 * The alarms MUST be wrapped in either a XROOT or VCALENDAR component. */
extern int caldav_write_defaultalarms(struct mailbox *mailbox,
                                      const char *userid,
                                      const char *annot,
                                      icalcomponent *ical);

/* Bump the modseq of all records in mailbox that contain iCalendar
 * components with enabled default alarms. Also forces calalarmd to
 * recalculate the alarms for these records.
 *
 * Side-effect warning: if the mailbox has an open annotation state
 * that isn't scoped to SCOPE_MESSAGE, then the state is committed
 * and rescoped to messages. */
extern int caldav_bump_defaultalarms(struct mailbox *mailbox);

#endif /* HTTP_CALDAV_H */
