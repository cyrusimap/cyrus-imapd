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

#include <libical/ical.h>

#include "lib/sqldb.h"

#include "imap/mailbox.h"
#include "imap/mboxname.h"
#include "imap/json_support.h"

enum alarm_type {
    ALARM_CALENDAR = 1,
    ALARM_SNOOZE,
    ALARM_SEND,
    ALARM_UNSCHEDULED,
};

#define CALDAV_ALARM_LOOKAHEAD (10)

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

/* process alarms with triggers before a given time */
int caldav_alarm_process(time_t runtime, time_t *next, int dryrun);

/* list alarms (via callbacks) before a given time */
typedef void (*list_calendar_proc)(const mbname_t *mbname,
                                   uint32_t imap_uid,
                                   time_t nextcheck,
                                   uint32_t num_rcpts,
                                   uint32_t num_retries,
                                   time_t last_run,
                                   const char *last_err,
                                   void *rock);
typedef void (*list_snooze_proc)(const mbname_t *mbname,
                                 time_t nextcheck,
                                 uint32_t num_retries,
                                 time_t last_run,
                                 const char *last_err,
                                 json_t *snoozed,
                                 void *rock);
typedef void (*list_send_proc)(const mbname_t *mbname,
                               time_t nextcheck,
                               uint32_t num_retries,
                               time_t last_run,
                               const char *last_err,
                               json_t *submission,
                               void *rock);
typedef void (*list_unscheduled_proc)(const mbname_t *mbname,
                                      uint32_t imap_uid,
                                      time_t nextcheck,
                                      uint32_t num_rcpts,
                                      uint32_t num_retries,
                                      time_t last_run,
                                      const char *last_err,
                                      void *rock);
int caldav_alarm_list(time_t runtime,
                      int lookahead,
                      list_calendar_proc calendar_proc,
                      list_snooze_proc snooze_proc,
                      list_send_proc send_proc,
                      list_unscheduled_proc unscheduled_proc,
                      void *rock);

/* upgrade old databases */
int caldav_alarm_upgrade();

/* update nextcheck for floating events */
int caldav_alarm_update_floating(struct mailbox *mailbox, const char *userid);

#endif /* CALDAV_ALARM_H */
