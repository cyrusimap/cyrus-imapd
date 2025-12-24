/* caldav_alarm.h -- interface to global CalDAV alarm database */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

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

/* update nextcheck for floating events */
int caldav_alarm_update_floating(struct mailbox *mailbox, const char *userid);

#endif /* CALDAV_ALARM_H */
