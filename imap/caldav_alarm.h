/* caldav_alarm.h -- interface to global CalDAV alarm database
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

#ifndef CALDAV_ALARM_DB_H
#define CALDAV_ALARM_DB_H

#include <config.h>

#include "sqldb.h"
#include "mailbox.h"
#include <libical/ical.h>

enum alarm_type {
    ALARM_CALENDAR = 1,
    ALARM_SNOOZE,
    ALARM_SEND,
    ALARM_UNSCHEDULED,
};

/* prepare for caldav alarm operations in this process */
int caldav_alarm_init(void);

/* done with all caldav operations for this process */
int caldav_alarm_done(void);

/* reconstruct support */
int caldav_alarm_set_reconstruct(sqldb_t *db);
int caldav_alarm_commit_reconstruct(const char *userid);
void caldav_alarm_rollback_reconstruct();

/* add a calendar alarm */
int caldav_alarm_add_record(struct mailbox *mailbox,
                            const struct index_record *record,
                            void *data);

/* make sure that the alarms match the annotation. If forced,
 * the event is not checked if it contains alarms */
int caldav_alarm_touch_record(struct mailbox *mailbox,
                              const struct index_record *record,
                              int force);

/* set the caldav_alarm db nextcheck field for the record (from sync_support) */
int caldav_alarm_sync_nextcheck(struct mailbox *mailbox,
                                const struct index_record *record);

/* delete all alarms matching the event */
int caldav_alarm_delete_record(const char *mboxname, uint32_t uid);

/* delete entire mailbox's alarms */
int caldav_alarm_delete_mailbox(const char *mboxname);

/* delete all alarms for a user */
int caldav_alarm_delete_user(const char *userid);

/* distribute alarms with triggers in the next minute */
int caldav_alarm_process(time_t runtime, time_t *next, int dryrun);

/* upgrade old databases */
int caldav_alarm_upgrade();

#endif /* CALDAV_ALARM_H */
