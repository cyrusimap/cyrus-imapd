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

#include <sqlite3.h>
#include "strarray.h"

struct caldav_alarm_db;

enum caldav_alarm_action {
    CALDAV_ALARM_ACTION_NONE	= 0,
    CALDAV_ALARM_ACTION_DISPLAY	= 1,
    CALDAV_ALARM_ACTION_EMAIL	= 2,

    CALDAV_ALARM_ACTION_FIRST	= CALDAV_ALARM_ACTION_DISPLAY,
    CALDAV_ALARM_ACTION_LAST	= CALDAV_ALARM_ACTION_EMAIL
};

struct caldav_alarm_data {
    sqlite3_int64		rowid;
    const char			*mailbox;
    const char			*resource;
    enum caldav_alarm_action	action;
    icaltimetype		nextalarm;
    const char			*tzid;
    icaltimetype		start;
    icaltimetype		end;
    strarray_t			recipients;
};

/* prepare for caldav alarm operations in this process */
int caldav_alarm_init(void);

/* done with all caldav operations for this process */
int caldav_alarm_done(void);

/* get a database handle to the alarm db */
struct caldav_alarm_db *caldav_alarm_open(void);

/* close this handle */
int caldav_alarm_close(struct caldav_alarm_db *alarmdb);

/* transactions */
int caldav_alarm_begin(struct caldav_alarm_db *alarmdb);
int caldav_alarm_commit(struct caldav_alarm_db *alarmdb);
int caldav_alarm_rollback(struct caldav_alarm_db *alarmdb);

/* add a calendar alarm */
int caldav_alarm_add(struct caldav_alarm_db *alarmdb, struct caldav_alarm_data *alarmdata);

/* delete a single alarm */
int caldav_alarm_delete(struct caldav_alarm_db *alarmdb, struct caldav_alarm_data *alarmdata);

/* delete all alarms matching the event */
int caldav_alarm_delete_all(struct caldav_alarm_db *alarmdb, struct caldav_alarm_data *alarmdata);

/* delete all alarms for a user */
int caldav_alarm_delete_user(struct caldav_alarm_db *alarmdb, const char *userid);

/* fill alarmdata with data for next alarm of given type for given entry */
int caldav_alarm_prepare(icalcomponent *ical, struct caldav_alarm_data *alarmdata, enum caldav_alarm_action action, icaltimetype after);

/* clean up alarmdata after prepare */
void caldav_alarm_fini(struct caldav_alarm_data *alarmdata);

/* distribute alarms with triggers in the next minute */
int caldav_alarm_process();

#endif /* CALDAV_ALARM_H */
