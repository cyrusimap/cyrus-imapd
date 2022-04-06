/* caldav_alarm.c -- implementation of global CalDAV alarm database
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

#include <config.h>

#include <sysexits.h>
#include <syslog.h>
#include <string.h>

#include <libical/ical.h>

#include "append.h"
#include "caldav_alarm.h"
#include "caldav_db.h"
#include "cyrusdb.h"
#include "httpd.h"
#include "http_dav.h"
#include "ical_support.h"
#include "jmap_util.h"
#include "libconfig.h"
#include "mboxevent.h"
#include "mboxlist.h"
#include "mboxname.h"
#include "msgrecord.h"
#include "times.h"
#include "user.h"
#include "util.h"
#include "xstrlcat.h"
#include "xmalloc.h"

/* generated headers are not necessarily in current directory */
#include "imap/http_err.h"
#include "imap/imap_err.h"

struct caldav_alarm_data {
    char *mboxname;
    uint32_t imap_uid;
    time_t nextcheck;
    uint32_t type;
    uint32_t num_rcpts;
    uint32_t num_retries;
    time_t last_run;
    char *last_err;
};

static void caldav_alarm_fini(struct caldav_alarm_data *alarmdata)
{
    xzfree(alarmdata->mboxname);
    xzfree(alarmdata->last_err);
}

struct get_alarm_rock {
    const char *userid;
    const char *mboxname;
    uint32_t imap_uid;  // for logging
    icaltimezone *floatingtz;
    time_t last;
    time_t now;
    time_t nextcheck;
    int dryrun;
};

static struct namespace caldav_alarm_namespace;

EXPORTED int caldav_alarm_init(void)
{
    int r;

    /* Set namespace -- force standard (internal) */
    if ((r = mboxname_init_namespace(&caldav_alarm_namespace, 1))) {
        syslog(LOG_ERR, "%s", error_message(r));
        fatal(error_message(r), EX_CONFIG);
    }

    return sqldb_init();
}


EXPORTED int caldav_alarm_done(void)
{
    return sqldb_done();
}


#define CMD_CREATE_INDEXES                                        \
    "CREATE INDEX IF NOT EXISTS checktime ON events (nextcheck);" \
    "CREATE INDEX IF NOT EXISTS idx_type ON events (type);"

#define CMD_CREATE(name)                                \
    "CREATE TABLE IF NOT EXISTS " name " ("             \
    " mboxname TEXT NOT NULL,"                          \
    " imap_uid INTEGER NOT NULL,"                       \
    " nextcheck INTEGER NOT NULL,"                      \
    " type INTEGER NOT NULL,"                           \
    " num_rcpts INTEGER NOT NULL,"                      \
    " num_retries INTEGER NOT NULL,"                    \
    " last_run INTEGER NOT NULL,"                       \
    " last_err TEXT,"                                   \
    " PRIMARY KEY (mboxname, imap_uid)"                 \
    ");"                                                \
    CMD_CREATE_INDEXES


#define DBVERSION 4

#define CMD_UPGRADEv4                                      \
    CMD_CREATE("new_events")                               \
    "INSERT INTO new_events"                               \
    " SELECT *, 1, 0, 0, 0, NULL FROM events;"             \
    "DROP TABLE events;"                                   \
    "ALTER TABLE new_events RENAME TO events;"             \
    CMD_CREATE_INDEXES

static struct sqldb_upgrade upgrade[] = {
    /* Don't upgrade to version 2. */
    /* Don't upgrade to version 3.  This was an intermediate DB version */
    { 4, CMD_UPGRADEv4, NULL },
    /* always finish with an empty row */
    { 0, NULL, NULL }
};

#define CMD_REPLACE                                            \
    "REPLACE INTO events"                                      \
    " ( mboxname, imap_uid, nextcheck, type, num_rcpts,"       \
    "   num_retries, last_run, last_err)"                      \
    " VALUES"                                                  \
    " ( :mboxname, :imap_uid, :nextcheck, :type, :num_rcpts,"  \
    "   :num_retries, :last_run, :last_err)"                   \
    ";"

#define CMD_DELETE                               \
    "DELETE FROM events"                         \
    " WHERE mboxname = :mboxname"                \
    "   AND imap_uid = :imap_uid"                \
    ";"

#define CMD_DELETEMAILBOX       \
    "DELETE FROM events WHERE"  \
    " mboxname = :mboxname"     \
    ";"

#define CMD_DELETEUSER          \
    "DELETE FROM events WHERE"  \
    " mboxname LIKE :prefix"     \
    ";"

#define CMD_SELECTUSER                                      \
    "SELECT mboxname, imap_uid, nextcheck, type, num_rcpts,"\
    "  num_retries, last_run, last_err"                     \
    " FROM events WHERE"                                    \
    " mboxname LIKE :prefix"                                \
    ";"

#define CMD_SELECT_ALARMS                                   \
    "SELECT mboxname, imap_uid, nextcheck, type, num_rcpts,"\
    "  num_retries, last_run, last_err"                     \
    " FROM events WHERE"                                    \
    " nextcheck < :before"                                  \
    " ORDER BY mboxname, imap_uid, nextcheck"               \
    ";"

static sqldb_t *my_alarmdb;
static int refcount;
static struct mboxlock *my_alarmdb_lock;

/* get a database handle to the alarm db */
static sqldb_t *caldav_alarm_open()
{
    /* already running?  Bonus */
    if (refcount) {
        refcount++;
        return my_alarmdb;
    }

    /* we need exclusivity! */
    int r = mboxname_lock("$CALDAVALARMDB", &my_alarmdb_lock, LOCK_EXCLUSIVE);
    if (r) {
        syslog(LOG_ERR, "DBERROR: failed to lock $CALDAVALARMDB");
        return NULL;
    }

    // XXX - config option?
    char *dbfilename = strconcat(config_dir, "/caldav_alarm.sqlite3", NULL);
    my_alarmdb = sqldb_open(dbfilename, CMD_CREATE("events"), DBVERSION, upgrade,
                            config_getduration(IMAPOPT_DAV_LOCK_TIMEOUT, 's') * 1000);

    if (!my_alarmdb) {
        syslog(LOG_ERR, "DBERROR: failed to open %s", dbfilename);
        mboxname_release(&my_alarmdb_lock);
    }

    free(dbfilename);
    refcount = 1;
    return my_alarmdb;
}

/* close this handle */
static int caldav_alarm_close(sqldb_t *alarmdb)
{
    assert(my_alarmdb == alarmdb);

    if (--refcount) return 0;

    sqldb_close(&my_alarmdb);
    mboxname_release(&my_alarmdb_lock);

    return 0;
}

/* set up a reconstruct database to override regular open/close */
EXPORTED int caldav_alarm_set_reconstruct(sqldb_t *db)
{
    // make sure we're not already open
    assert(!my_alarmdb);
    assert(!refcount);

    // create the events table
    int rc = sqldb_exec(db, CMD_CREATE("events"), NULL, NULL, NULL);
    if (rc != SQLITE_OK) return IMAP_IOERROR;

    // preload the DB into our refcounter
    my_alarmdb = db;
    refcount = 1;

    return 0;
}

static int copydb(sqlite3_stmt *stmt, void *rock)
{
    sqldb_t *destdb = (sqldb_t *)rock;
    struct sqldb_bindval bval[] = {
        { ":mboxname",  SQLITE_TEXT,    { .s = (const char *)sqlite3_column_text(stmt, 0) } },
        { ":imap_uid",  SQLITE_INTEGER, { .i = sqlite3_column_int(stmt, 1)  } },
        { ":nextcheck", SQLITE_INTEGER, { .i = sqlite3_column_int(stmt, 2)  } },
        { ":type",      SQLITE_INTEGER, { .i = sqlite3_column_int(stmt, 3)  } },
        { ":num_rcpts", SQLITE_INTEGER, { .i = sqlite3_column_int(stmt, 4)  } },
        { ":num_retries", SQLITE_INTEGER, { .i = sqlite3_column_int(stmt, 5)  } },
        { ":last_run",  SQLITE_INTEGER, { .i = sqlite3_column_int(stmt, 6)  } },
        { ":last_err",  SQLITE_TEXT,    { .s = (const char *)sqlite3_column_text(stmt, 7) } },
        { NULL,         SQLITE_NULL,    { .s = NULL      } }
    };
    return sqldb_exec(destdb, CMD_REPLACE, bval, NULL, NULL);
}

/* remove all existing alarms for this user and copy all alarms from the
   reconstructed database into place instead */
EXPORTED int caldav_alarm_commit_reconstruct(const char *userid)
{
    sqldb_t *db = my_alarmdb;

    // zero out the override so we can open the correct database
    assert(refcount == 1);
    refcount = 0;
    my_alarmdb = NULL;

    mbname_t *mbname = mbname_from_userid(userid);
    const char *mboxname = mbname_intname(mbname);
    char *prefix = strconcat(mboxname, ".%", (char *)NULL);
    mbname_free(&mbname);

    struct sqldb_bindval bval[] = {
        { ":prefix",    SQLITE_TEXT, { .s = prefix  } },
        { NULL,         SQLITE_NULL, { .s = NULL    } }
    };

    sqldb_t *alarmdb = caldav_alarm_open();
    int r = sqldb_begin(alarmdb, "replace_alarms");
    if (!r) r = sqldb_exec(alarmdb, CMD_DELETEUSER, bval, NULL, NULL);
    if (!r) r = sqldb_exec(db, CMD_SELECTUSER, bval, &copydb, alarmdb);
    if (!r) r = sqldb_commit(alarmdb, "replace_alarms");
    else sqldb_rollback(alarmdb, "replace_alarms");
    caldav_alarm_close(alarmdb);

    // if we succeeded, drop the copy of events in this DB
    if (!r) r = sqldb_exec(db, "DROP TABLE events;", NULL, NULL, NULL);

    free(prefix);

    return r;
}

/* release the reconstruction database without copying or removing any
 * existing alarms */
EXPORTED void caldav_alarm_rollback_reconstruct()
{
    assert(refcount == 1);
    refcount = 0;
    my_alarmdb = NULL;

    // we keep the events database in this copy for later examination
}

/*
 * Extract data from the given ical object
 */
static int send_alarm(struct get_alarm_rock *rock,
                      icalcomponent *comp, icalcomponent *alarm,
                      icaltimetype start, icaltimetype end,
                      icaltimetype recurid,
                      int is_standalone,
                      icaltimetype alarmtime)
{
    const char *userid = rock->userid;
    struct buf calname = BUF_INITIALIZER;
    struct buf calcolor = BUF_INITIALIZER;
    struct buf buf = BUF_INITIALIZER;

    /* get the calendar id */
    mbname_t *mbname = mbname_from_intname(rock->mboxname);
    const char *calid = strarray_nth(mbname_boxes(mbname), -1);

    /* get the display name annotation */
    const char *displayname_annot = DAV_ANNOT_NS "<" XML_NS_DAV ">displayname";
    annotatemore_lookupmask(rock->mboxname, displayname_annot, userid, &calname);
    if (!calname.len) buf_setcstr(&calname, calid);

    /* get the calendar color annotation */
    const char *color_annot = DAV_ANNOT_NS "<" XML_NS_APPLE ">calendar-color";
    annotatemore_lookupmask(rock->mboxname, color_annot, userid, &calcolor);

    struct mboxevent *event = mboxevent_new(EVENT_CALENDAR_ALARM);
    icalproperty *prop;
    icalvalue *val;

    FILL_STRING_PARAM(event, EVENT_CALENDAR_ALARM_TIME,
                      xstrdup(icaltime_as_ical_string(alarmtime)));

    prop = icalcomponent_get_first_property(alarm, ICAL_ACTION_PROPERTY);
    val = icalproperty_get_value(prop);
    enum icalproperty_action action = icalvalue_get_action(val);
    if (action == ICAL_ACTION_DISPLAY) {
        FILL_STRING_PARAM(event, EVENT_CALENDAR_ACTION, xstrdup("display"));
    }
    else {
        FILL_STRING_PARAM(event, EVENT_CALENDAR_ACTION, xstrdup("email"));
    }

    FILL_STRING_PARAM(event, EVENT_CALENDAR_USER_ID, xstrdup(userid));
    FILL_STRING_PARAM(event, EVENT_CALENDAR_CALENDAR_ID, xstrdup(calid));
    FILL_STRING_PARAM(event, EVENT_CALENDAR_CALENDAR_NAME, buf_release(&calname));
    FILL_STRING_PARAM(event, EVENT_CALENDAR_CALENDAR_COLOR, buf_release(&calcolor));

    struct jmap_caleventid eid = { 0 };

    prop = icalcomponent_get_first_property(comp, ICAL_UID_PROPERTY);
    if (prop) eid.ical_uid = icalproperty_get_value_as_string(prop);
    FILL_STRING_PARAM(event, EVENT_CALENDAR_UID,
                      xstrdup(prop ? icalproperty_get_value_as_string(prop) : ""));

    if (!icaltime_is_null_time(recurid) && is_standalone) {
        // if the event is a standalone recurrence instance, encode
        // the recurrence id in the event id. otherwise use the
        // main event id for the alert notification
        eid.ical_recurid = icaltime_as_ical_string(recurid);
    }

    // set calendarEventId
    if (eid.ical_uid) jmap_caleventid_encode(&eid, &buf);
    FILL_STRING_PARAM(event, EVENT_CALENDAR_EVENTID, buf_release(&buf));

    // set recurrenceId
    if (!icaltime_is_null_time(recurid)) {
        buf_printf(&buf, "%d-%02d-%02dT%02d:%02d:%02d",
                recurid.year, recurid.month, recurid.day,
                recurid.hour, recurid.minute, recurid.second);
    }
    FILL_STRING_PARAM(event, EVENT_CALENDAR_RECURID, buf_release(&buf));

    prop = icalcomponent_get_first_property(comp, ICAL_SUMMARY_PROPERTY);
    FILL_STRING_PARAM(event, EVENT_CALENDAR_SUMMARY,
                      xstrdup(prop ? icalproperty_get_value_as_string(prop) : ""));

    prop = icalcomponent_get_first_property(comp, ICAL_DESCRIPTION_PROPERTY);
    FILL_STRING_PARAM(event, EVENT_CALENDAR_DESCRIPTION,
                      xstrdup(prop ? icalproperty_get_value_as_string(prop) : ""));

    prop = icalcomponent_get_first_property(comp, ICAL_LOCATION_PROPERTY);
    FILL_STRING_PARAM(event, EVENT_CALENDAR_LOCATION,
                      xstrdup(prop ? icalproperty_get_value_as_string(prop) : ""));

    prop = icalcomponent_get_first_property(comp, ICAL_ORGANIZER_PROPERTY);
    FILL_STRING_PARAM(event, EVENT_CALENDAR_ORGANIZER,
                      xstrdup(prop ? icalproperty_get_value_as_string(prop) : ""));

    const char *timezone = NULL;
    if (!icaltime_is_date(start) && icaltime_is_utc(start))
        timezone = "UTC";
    else if (icaltime_get_timezone(start))
        timezone = icaltime_get_location_tzid(start);
    else if (rock->floatingtz)
        timezone = icaltimezone_get_location_tzid(rock->floatingtz);
    else
        timezone = "[floating]";
    FILL_STRING_PARAM(event, EVENT_CALENDAR_TIMEZONE,
                      xstrdupsafe(timezone));
    FILL_STRING_PARAM(event, EVENT_CALENDAR_START,
                      xstrdup(icaltime_as_ical_string(start)));
    FILL_STRING_PARAM(event, EVENT_CALENDAR_END,
                      xstrdup(icaltime_as_ical_string(end)));
    FILL_UNSIGNED_PARAM(event, EVENT_CALENDAR_ALLDAY,
                        icaltime_is_date(start) ? 1 : 0);

    strarray_t *recipients = strarray_new();
    for (prop = icalcomponent_get_first_property(alarm, ICAL_ATTENDEE_PROPERTY);
         prop;
         prop = icalcomponent_get_next_property(alarm, ICAL_ATTENDEE_PROPERTY)) {
        const char *email = icalproperty_get_value_as_string(prop);
        if (!email)
            continue;
        strarray_append(recipients, email);
    }
    FILL_ARRAY_PARAM(event, EVENT_CALENDAR_ALARM_RECIPIENTS, recipients);

    jmap_alertid_encode(alarm, &buf);
    FILL_STRING_PARAM(event, EVENT_CALENDAR_ALERTID, buf_release(&buf));

    strarray_t *attendee_names = strarray_new();
    strarray_t *attendee_emails = strarray_new();
    strarray_t *attendee_status = strarray_new();
    for (prop = icalcomponent_get_first_property(comp, ICAL_ATTENDEE_PROPERTY);
         prop;
         prop = icalcomponent_get_next_property(comp, ICAL_ATTENDEE_PROPERTY)) {
        const char *email = icalproperty_get_value_as_string(prop);
        if (!email)
            continue;
        strarray_append(attendee_emails, email);

        const char *name = icalproperty_get_parameter_as_string(prop, "CN");
        strarray_append(attendee_names, name ? name : "");

        const char *partstat =
            icalproperty_get_parameter_as_string(prop, "PARTSTAT");
        strarray_append(attendee_status, partstat ? partstat : "");
    }
    FILL_ARRAY_PARAM(event, EVENT_CALENDAR_ATTENDEE_NAMES, attendee_names);
    FILL_ARRAY_PARAM(event, EVENT_CALENDAR_ATTENDEE_EMAILS, attendee_emails);
    FILL_ARRAY_PARAM(event, EVENT_CALENDAR_ATTENDEE_STATUS, attendee_status);

    mboxevent_notify(&event);
    mboxevent_free(&event);

    strarray_free(recipients);
    strarray_free(attendee_names);
    strarray_free(attendee_emails);
    strarray_free(attendee_status);

    buf_free(&calname);
    buf_free(&calcolor);
    buf_free(&buf);
    mbname_free(&mbname);

    return 0;
}

static int process_alarm_cb(icalcomponent *comp,
                            icaltimetype start, icaltimetype end,
                            icaltimetype recurid,
                            int is_standalone,
                            void *rock)
{
    struct get_alarm_rock *data = (struct get_alarm_rock *)rock;

    icalcomponent *alarm;
    icalproperty *prop;
    icalvalue *val;

    int alarmno = 0;

    for (alarm = icalcomponent_get_first_component(comp, ICAL_VALARM_COMPONENT);
         alarm;
         alarm = icalcomponent_get_next_component(comp, ICAL_VALARM_COMPONENT)) {

        alarmno++;

        prop = icalcomponent_get_first_property(alarm, ICAL_ACTION_PROPERTY);
        if (!prop) {
            /* no action, invalid alarm, skip */
            continue;
        }

        val = icalproperty_get_value(prop);
        enum icalproperty_action action = icalvalue_get_action(val);
        if (!(action == ICAL_ACTION_DISPLAY || action == ICAL_ACTION_EMAIL)) {
            /* we only want DISPLAY and EMAIL, skip */
            continue;
        }

        prop = icalcomponent_get_first_property(alarm, ICAL_TRIGGER_PROPERTY);
        if (!prop) {
            /* no trigger, invalid alarm, skip */
            continue;
        }

        val = icalproperty_get_value(prop);

        struct icaltriggertype trigger = icalvalue_get_trigger(val);
        /* XXX validate trigger */

        icaltimetype alarmtime = icaltime_null_time();
        unsigned is_duration = (icalvalue_isa(val) == ICAL_DURATION_VALUE);
        if (is_duration) {
            icalparameter *param =
                icalproperty_get_first_parameter(prop, ICAL_RELATED_PARAMETER);
            icaltimetype base = start;
            if (param && icalparameter_get_related(param) == ICAL_RELATED_END) {
                base = end;
            }
            base.is_date = 0; /* need an actual time for triggers */
            alarmtime = icaltime_add(base, trigger.duration);
        }
        else {
            /* absolute */
            alarmtime = trigger.time;
        }
        alarmtime.is_date = 0;

        time_t check = icaltime_to_timet(alarmtime, data->floatingtz);

        /* skip already sent alarms */
        if (check <= data->last) {
            continue;
        }

        if (check <= data->now && !data->dryrun) {
            prop = icalcomponent_get_first_property(comp, ICAL_SUMMARY_PROPERTY);
            const char *summary =
                prop ? icalproperty_get_value_as_string(prop) : "[no summary]";
            int age = data->now - check;
            if (age > 7200) { // more than 2 hours stale?  Just log it
                syslog(LOG_ERR, "suppressing alarm aged %d seconds "
                       "at %s for %s %u - %s(%d) %s",
                       age,
                       icaltime_as_ical_string(alarmtime),
                       data->mboxname, data->imap_uid,
                       icaltime_as_ical_string(start), alarmno,
                       summary);
            }
            else {
                syslog(LOG_NOTICE, "sending alarm at %s for %s %u - %s(%d) %s",
                       icaltime_as_ical_string(alarmtime),
                       data->mboxname, data->imap_uid,
                       icaltime_as_ical_string(start), alarmno,
                       summary);
                send_alarm(data, comp, alarm, start, end, recurid, is_standalone, alarmtime);
            }
        }

        else if (!data->nextcheck || check < data->nextcheck) {
            data->nextcheck = check;
        }

        /* alarms can't be more than a week either side of the event start,
         * so if we're past 2 months, then just check again in a month */
        if (check > data->now + 86400*60) {
            syslog(LOG_DEBUG, "XXX  pushing off nextcheck");
            time_t next = data->now + 86400*30;
            if (!data->nextcheck || next < data->nextcheck)
                data->nextcheck = next;
            return 0;
        }
        else if (!is_duration) {
            /* alarms with absolute triggers can only fire once,
               so stop recurrence expansion */
            syslog(LOG_DEBUG, "XXX  absolute trigger - stop recurrence expansion");
            return 0;
        }
    }

    return 1; /* keep going */
}

static int update_alarmdb(const char *mboxname,
                          uint32_t imap_uid, time_t nextcheck,
                          uint32_t type, uint32_t num_rcpts,
                          uint32_t num_retries, time_t last_run,
                          const char *last_err)
{
    struct sqldb_bindval bval[] = {
        { ":mboxname",     SQLITE_TEXT,    { .s = mboxname     } },
        { ":imap_uid",     SQLITE_INTEGER, { .i = imap_uid     } },
        { ":nextcheck",    SQLITE_INTEGER, { .i = nextcheck    } },
        { ":type",         SQLITE_INTEGER, { .i = type         } },
        { ":num_rcpts",    SQLITE_INTEGER, { .i = num_rcpts    } },
        { ":num_retries",  SQLITE_INTEGER, { .i = num_retries  } },
        { ":last_run",     SQLITE_INTEGER, { .i = last_run     } },
        { ":last_err",     SQLITE_TEXT,    { .s = last_err     } },
        { NULL,            SQLITE_NULL,    { .s = NULL         } }
    };

    sqldb_t *alarmdb = caldav_alarm_open();
    if (!alarmdb) return -1;
    int rc = SQLITE_OK;

    syslog(LOG_DEBUG,
           "update_alarmdb(%s:%u, " TIME_T_FMT ", %u, %u, %u, " TIME_T_FMT ", %s)",
           mboxname, imap_uid, nextcheck, type, num_rcpts,
           num_retries, last_run, last_err ? last_err : "NULL");

    if (nextcheck)
        rc = sqldb_exec(alarmdb, CMD_REPLACE, bval, NULL, NULL);
    else
        rc = sqldb_exec(alarmdb, CMD_DELETE, bval, NULL, NULL);

    caldav_alarm_close(alarmdb);

    if (rc == SQLITE_OK) return 0;

    /* failed? */
    return -1;
}

static icaltimezone *get_floatingtz(const char *mailbox, const char *userid)
{
    icaltimezone *floatingtz = NULL;

    struct buf buf = BUF_INITIALIZER;
    const char *annotname = DAV_ANNOT_NS "<" XML_NS_CALDAV ">calendar-timezone";
    if (!annotatemore_lookupmask(mailbox, annotname, userid, &buf)) {
        icalcomponent *comp = NULL;
        comp = icalparser_parse_string(buf_cstring(&buf));
        icalcomponent *subcomp =
            icalcomponent_get_first_component(comp, ICAL_VTIMEZONE_COMPONENT);
        if (subcomp) {
            floatingtz = icaltimezone_new();
            icalcomponent_remove_component(comp, subcomp);
            icaltimezone_set_component(floatingtz, subcomp);
        }
        icalcomponent_free(comp);
    }
    buf_free(&buf);

    return floatingtz;
}

static icalcomponent *vpatch_from_peruserdata(struct dlist *dl)
{
    const char *icalstr;
    icalcomponent *vpatch;

    /* Parse the value and fetch the patch */
    dlist_getatom(dl, "VPATCH", &icalstr);
    vpatch = icalparser_parse_string(icalstr);

    return vpatch;
}

struct has_alarms_rock {
    uint32_t mbox_options;
    int *has_alarms;
};

static int has_usedefaultalarms(icalcomponent *comp)
{
    icalproperty *prop;
    for (prop = icalcomponent_get_first_property(comp, ICAL_X_PROPERTY);
         prop;
         prop = icalcomponent_get_next_property(comp, ICAL_X_PROPERTY)) {
        /* Check patch for default alerts properties */
        const char *xname = icalproperty_get_x_name(prop);
        if (!strcasecmp(xname, "X-APPLE-DEFAULT-ALARM")) {
            const char *strval = icalproperty_get_value_as_string(prop);
            if (!strcasecmpsafe(strval, "TRUE")) {
                return 1;
            }
        }
    }
    return 0;
}

static int has_peruser_alarms_cb(const char *mailbox,
                                 uint32_t uid __attribute__((unused)),
                                 const char *entry __attribute__((unused)),
                                 const char *userid, const struct buf *value,
                                 const struct annotate_metadata *mdata __attribute__((unused)),
                                 void *rock)
{
    struct has_alarms_rock *hrock = (struct has_alarms_rock *) rock;
    icalcomponent *vpatch = NULL, *comp;
    struct dlist *dl = NULL;

    if (!mboxname_userownsmailbox(userid, mailbox) &&
        ((hrock->mbox_options & OPT_IMAP_SHAREDSEEN) ||
         mboxlist_checksub(mailbox, userid) != 0)) {
        /* No per-user-data, or sharee has unsubscribed from this calendar */
        return 0;
    }

    dlist_parsemap(&dl, 1, 0, buf_base(value), buf_len(value));
    const char *strval = NULL;
    if (dlist_getatom(dl, "USEDEFAULTALERTS", &strval)) {
        if (!strcasecmp(strval, "YES")) {
            *(hrock->has_alarms) = 1;
            goto done;
        }
    }

    /* Extract VPATCH from per-user-cal-data annotation */
    vpatch = vpatch_from_peruserdata(dl);

    /* Check PATCHes for any VALARMs */
    for (comp = icalcomponent_get_first_component(vpatch, ICAL_XPATCH_COMPONENT);
         comp && !*(hrock->has_alarms);
         comp = icalcomponent_get_next_component(vpatch, ICAL_XPATCH_COMPONENT)) {
        if (icalcomponent_get_first_component(comp, ICAL_VALARM_COMPONENT)) {
            *(hrock->has_alarms) = 1;
            break;
        }
        else if (has_usedefaultalarms(comp)) {
            *(hrock->has_alarms) = 1;
            break;
        }
    }

done:
    if (vpatch) icalcomponent_free(vpatch);
    if (dl) dlist_free(&dl);
    return 0;
}

static int has_alarms(void *data, struct mailbox *mailbox,
                      uint32_t uid, unsigned *num_rcpts)
{
    int has_alarms = 0;

    syslog(LOG_DEBUG, "checking for alarms in mailbox %s uid %u",
           mailbox_name(mailbox), uid);

    if (mailbox->i.options & OPT_IMAP_HAS_ALARMS) {
        if (data && num_rcpts &&
            mbtype_isa(mailbox_mbtype(mailbox)) == MBTYPE_JMAPSUBMIT) {
            json_t *submission = (json_t *) data;
            json_t *envelope = json_object_get(submission, "envelope");
            if (envelope) {
                *num_rcpts = json_array_size(json_object_get(envelope, "rcptTo"));
            }
        }
        return 1;
    }

    icalcomponent *ical = (icalcomponent *) data;
    if (ical) {
        /* Check iCalendar resource for VALARMs */
        icalcomponent *comp = icalcomponent_get_first_real_component(ical);
        icalcomponent_kind kind = icalcomponent_isa(comp);

        syslog(LOG_DEBUG, "checking resource");
        for (; comp; comp = icalcomponent_get_next_component(ical, kind)) {
            if (icalcomponent_get_first_component(comp, ICAL_VALARM_COMPONENT))
                return 1;
            else if (has_usedefaultalarms(comp))
                return 1;
        }
    }

    /* Check all per-user-cal-data for VALARMs */
    struct has_alarms_rock hrock = { mailbox->i.options, &has_alarms };

    syslog(LOG_DEBUG, "checking per-user-data");
    mailbox_get_annotate_state(mailbox, uid, NULL);
    annotatemore_findall_mailbox(mailbox, uid, PER_USER_CAL_DATA, /* modseq */ 0,
                         &has_peruser_alarms_cb, &hrock, /* flags */ 0);

    return has_alarms;
}

static icalcomponent *read_calendar_icalalarms(const char *mboxname,
                                               const char *userid,
                                               const char *annot)
{
    icalcomponent *ical = NULL;
    struct buf buf = BUF_INITIALIZER;

    annotatemore_lookupmask(mboxname, annot, userid, &buf);

    if (buf_len(&buf)) {
        struct dlist *dl = NULL;
        if (dlist_parsemap(&dl, 1, 0, buf_base(&buf), buf_len(&buf)) == 0) {
            const char *content = NULL;
            if (dlist_getatom(dl, "CONTENT", &content)) {
                buf_setcstr(&buf, content);
            }
        }
        dlist_free(&dl);
    }
    if (buf_len(&buf)) {
        ical = icalparser_parse_string(buf_cstring(&buf));
        if (ical) {
            if (icalcomponent_isa(ical) == ICAL_VALARM_COMPONENT) {
                /* libical wraps multiple VALARMs in a XROOT component,
                 * so also wrap a single VALARM for consistency */
                icalcomponent *root = icalcomponent_new(ICAL_XROOT_COMPONENT);
                icalcomponent_add_component(root, ical);
                ical = root;
            }
        }
    }

    buf_free(&buf);
    return ical;
}

static time_t process_alarms(const char *mboxname, uint32_t imap_uid,
                             const char *userid, icaltimezone *floatingtz,
                             icalcomponent *ical, time_t lastrun,
                             time_t runtime, int dryrun)
{
    icalcomponent *myical = NULL;

    /* Add default alarms */
    if (icalcomponent_read_usedefaultalerts(ical) > 0) {
        static const char *withtime_annot =
            DAV_ANNOT_NS "<" XML_NS_CALDAV ">default-alarm-vevent-datetime";
        static const char *withdate_annot =
            DAV_ANNOT_NS "<" XML_NS_CALDAV ">default-alarm-vevent-date";

        icalcomponent *withtime =
            read_calendar_icalalarms(mboxname, userid, withtime_annot);;
        icalcomponent *withdate =
            read_calendar_icalalarms(mboxname, userid, withdate_annot);

        if (withtime || withdate) {
            myical = icalcomponent_clone(ical);
            icalcomponent_add_defaultalerts(myical, withtime, withdate, 0);
            ical = myical;
        }

        if (withtime) icalcomponent_free(withtime);
        if (withdate) icalcomponent_free(withdate);
    }

    /* Process alarms */
    struct get_alarm_rock rock =
        { userid, mboxname, imap_uid, floatingtz, lastrun, runtime, 0, dryrun };
    struct icalperiodtype range = icalperiodtype_null_period();
    icalcomponent_myforeach(ical, range, floatingtz, process_alarm_cb, &rock);

    if (myical) icalcomponent_free(myical);
    return rock.nextcheck;
}

struct lastalarm_data {
    time_t lastrun;
    time_t nextcheck;
};

static int write_lastalarm(struct mailbox *mailbox,
                           const struct index_record *record,
                           struct lastalarm_data *data)
{
    struct buf annot_buf = BUF_INITIALIZER;

    syslog(LOG_DEBUG, "writing last alarm for mailbox %s uid %u",
           mailbox_name(mailbox), record->uid);

    if (data) {
        buf_printf(&annot_buf, TIME_T_FMT " " TIME_T_FMT, data->lastrun, data->nextcheck);
    }
    syslog(LOG_DEBUG, "data: %s", buf_cstring(&annot_buf));

    const char *annotname = DAV_ANNOT_NS "lastalarm";
    int r = mailbox_annotation_write(mailbox, record->uid,
                                     annotname, "", &annot_buf);
    buf_free(&annot_buf);

    return r;
}

static int read_lastalarm(struct mailbox *mailbox,
                          const struct index_record *record,
                          struct lastalarm_data *data)
{
    int r = IMAP_NOTFOUND;
    memset(data, 0, sizeof(struct lastalarm_data));

    syslog(LOG_DEBUG, "reading last alarm for mailbox %s uid %u",
           mailbox_name(mailbox), record->uid);

    const char *annotname = DAV_ANNOT_NS "lastalarm";
    struct buf annot_buf = BUF_INITIALIZER;
    mailbox_get_annotate_state(mailbox, record->uid, NULL);
    annotatemore_msg_lookup(mailbox, record->uid,
                            annotname, "", &annot_buf);

    if (annot_buf.len &&
        sscanf(buf_cstring(&annot_buf), TIME_T_FMT " " TIME_T_FMT,
               &data->lastrun, &data->nextcheck) == 2) {
        r = 0;
    }

    buf_free(&annot_buf);
    return r;
}

static enum alarm_type mbtype_to_alarm_type(uint32_t mbtype)
{
    enum alarm_type atype = 0;

    switch (mbtype_isa(mbtype)) {
    case MBTYPE_CALENDAR:
        atype = ALARM_CALENDAR;
        break;
    case MBTYPE_EMAIL:
        atype = ALARM_SNOOZE;
        break;
    case MBTYPE_JMAPSUBMIT:
        atype = ALARM_SEND;
        break;
    default:
        fatal("unknown alarm type", EX_SOFTWARE);
    }

    return atype;
}

/* add a calendar alarm */
HIDDEN int caldav_alarm_add_record(struct mailbox *mailbox,
                                   const struct index_record *record,
                                   void *data)
{
    unsigned num_rcpts = 0;

    if (has_alarms(data, mailbox, record->uid, &num_rcpts)) {
        enum alarm_type atype = mbtype_to_alarm_type(mailbox_mbtype(mailbox));
        update_alarmdb(mailbox_name(mailbox), record->uid, record->internaldate,
                       atype, num_rcpts, 0, 0, NULL);
    }

    return 0;
}

EXPORTED int caldav_alarm_touch_record(struct mailbox *mailbox,
                                       const struct index_record *record,
                                       int force)
{
    unsigned num_rcpts = 0;

    /* if there are alarms in the annotations,
     * the next alarm may have become earlier, so get calalarmd to check again */
    if (force || has_alarms(NULL, mailbox, record->uid, &num_rcpts)) {
        enum alarm_type atype = mbtype_to_alarm_type(mailbox_mbtype(mailbox));
        return update_alarmdb(mailbox_name(mailbox), record->uid,
                              record->last_updated, atype, num_rcpts, 0, 0, NULL);
    }

    return 0;
}

/* called by sync_support from sync_server -
 * set nextcheck in the calalarmdb based on the full state,
 * record + annotations, after the annotations have been updated too */
EXPORTED int caldav_alarm_sync_nextcheck(struct mailbox *mailbox,
                                         const struct index_record *record)
{
    struct lastalarm_data data;
    if (!read_lastalarm(mailbox, record, &data)) {
        enum alarm_type atype = mbtype_to_alarm_type(mailbox_mbtype(mailbox));
        return update_alarmdb(mailbox_name(mailbox), record->uid,
                              data.nextcheck, atype, 0, 0, 0, NULL);
    }

    /* if there's no lastalarm on the record, nuke any existing alarmdb entry */
    return caldav_alarm_delete_record(mailbox_name(mailbox), record->uid);
}

/* delete all alarms matching the event */
HIDDEN int caldav_alarm_delete_record(const char *mboxname, uint32_t imap_uid)
{
    return update_alarmdb(mboxname, imap_uid, 0, 0, 0, 0, 0, NULL);
}

static int caldav_alarm_bump_nextcheck(struct caldav_alarm_data *data,
                                       time_t nextcheck,
                                       time_t last_run, const char *last_err)
{
    uint32_t num_retries = data->num_retries;

    if (last_err) num_retries++;
    else last_err = data->last_err;

    if (!last_run) last_run = data->last_run;

    return update_alarmdb(data->mboxname, data->imap_uid, nextcheck, data->type,
                          data->num_rcpts, num_retries, last_run, last_err);
}

/* delete all alarms matching the event */
HIDDEN int caldav_alarm_delete_mailbox(const char *mboxname)
{
    struct sqldb_bindval bval[] = {
        { ":mboxname",  SQLITE_TEXT, { .s = mboxname  } },
        { NULL,         SQLITE_NULL, { .s = NULL      } }
    };

    sqldb_t *alarmdb = caldav_alarm_open();
    int rc = sqldb_exec(alarmdb, CMD_DELETEMAILBOX, bval, NULL, NULL);
    caldav_alarm_close(alarmdb);

    return rc;
}

/* delete all alarms matching the event */
HIDDEN int caldav_alarm_delete_user(const char *userid)
{
    mbname_t *mbname = mbname_from_userid(userid);
    const char *mboxname = mbname_intname(mbname);
    char *prefix = strconcat(mboxname, ".%", (char *)NULL);
    mbname_free(&mbname);

    struct sqldb_bindval bval[] = {
        { ":prefix",    SQLITE_TEXT, { .s = prefix  } },
        { NULL,         SQLITE_NULL, { .s = NULL    } }
    };

    sqldb_t *alarmdb = caldav_alarm_open();
    int rc = sqldb_exec(alarmdb, CMD_DELETEUSER, bval, NULL, NULL);
    caldav_alarm_close(alarmdb);

    free(prefix);

    return rc;
}

struct alarm_read_rock {
    ptrarray_t list;
    time_t runtime;
    time_t next;
};

static int alarm_read_cb(sqlite3_stmt *stmt, void *rock)
{
    struct alarm_read_rock *alarm = rock;

    time_t nextcheck = sqlite3_column_int(stmt, 2);

    if (nextcheck <= alarm->runtime) {
        struct caldav_alarm_data *data = xzmalloc(sizeof(struct caldav_alarm_data));
        data->mboxname     = xstrdup((const char *) sqlite3_column_text(stmt, 0));
        data->imap_uid     = sqlite3_column_int(stmt, 1);
        data->nextcheck    = nextcheck; // column 2
        data->type         = sqlite3_column_int(stmt, 3);
        data->num_rcpts    = sqlite3_column_int(stmt, 4);
        data->num_retries  = sqlite3_column_int(stmt, 5);
        data->last_run     = sqlite3_column_int(stmt, 6);
        data->last_err     = xstrdupnull((const char *) sqlite3_column_text(stmt, 7));
        ptrarray_append(&alarm->list, data);
    }
    else if (nextcheck < alarm->next) {
        alarm->next = nextcheck;
    }

    return 0;
}

struct process_alarms_rock {
    uint32_t mbox_options;
    icalcomponent *ical;
    struct lastalarm_data *alarm;
    time_t runtime;
    int dryrun;
    int is_secretarymode;
};

static int process_peruser_alarms_cb(const char *mailbox, uint32_t uid,
                                     const char *entry __attribute__((unused)),
                                     const char *userid, const struct buf *value,
                                     const struct annotate_metadata *mdata __attribute__((unused)),
                                     void *rock)
{
    struct process_alarms_rock *prock = (struct process_alarms_rock *) rock;
    icalcomponent *vpatch, *myical;
    icaltimezone *floatingtz = NULL;
    struct dlist *dl = NULL;

    time_t check;

    if (!mboxname_userownsmailbox(userid, mailbox) &&
        ((prock->mbox_options & OPT_IMAP_SHAREDSEEN) ||
         mboxlist_checksub(mailbox, userid) != 0 ||
         prock->is_secretarymode)) {
        /* No per-user-data, or sharee has unsubscribed from this calendar,
         * or calendar is in secretary mode */
        return 0;
    }

    /* Extract VPATCH from per-user-cal-data annotation */
    dlist_parsemap(&dl, 1, 0, buf_base(value), buf_len(value));
    vpatch = vpatch_from_peruserdata(dl);

    /* Apply VPATCH to a clone of the iCalendar resource */
    myical = icalcomponent_clone(prock->ical);
    icalcomponent_apply_vpatch(myical, vpatch, NULL, NULL);
    icalcomponent_free(vpatch);

    /* Fetch per-user timezone for floating events */
    floatingtz = get_floatingtz(mailbox, userid);

    /* Process any VALARMs in the patched iCalendar resource */
    check = process_alarms(mailbox, uid, userid, floatingtz, myical,
                           prock->alarm->lastrun, prock->runtime, prock->dryrun);
    if (!prock->alarm->nextcheck || check < prock->alarm->nextcheck) {
        prock->alarm->nextcheck = check;
    }

    if (floatingtz) icaltimezone_free(floatingtz, 1);
    icalcomponent_free(myical);
    dlist_free(&dl);

    return 0;
}

static int process_valarms(struct mailbox *mailbox,
                            struct index_record *record,
                            icaltimezone *floatingtz, time_t runtime,
                            int dryrun)
{
    icalcomponent *ical = ical = record_to_ical(mailbox, record, NULL);
    const char *mboxname = mailbox_name(mailbox);

    if (!ical) {
        syslog(LOG_ERR, "error parsing ical string mailbox %s uid %u",
               mboxname, record->uid);
        caldav_alarm_delete_record(mboxname, record->uid);
        return 0;
    }

    /* ensure this record corresponds to the current version of the event */
    struct caldav_db *db = caldav_open_mailbox(mailbox);
    struct caldav_data *cdata;
    if (!db ||
        caldav_lookup_uid(db, icalcomponent_get_uid(ical), &cdata) ||
        record->uid != cdata->dav.imap_uid ||
        strcmp(cdata->dav.mailbox_byname ? mboxname : mailbox_uniqueid(mailbox),
               cdata->dav.mailbox)) {
        syslog(LOG_NOTICE, "removing bogus lastalarm check "
               "for mailbox %s uid %u which is not current event",
               mboxname, record->uid);
        caldav_alarm_delete_record(mboxname, record->uid);
        goto done_item;
    }

    /* check for bogus lastalarm data on record
       which actually shouldn't have it */
    if (!has_alarms(ical, mailbox, record->uid, NULL)) {
        syslog(LOG_NOTICE, "removing bogus lastalarm check "
               "for mailbox %s uid %u which has no alarms",
               mboxname, record->uid);
        caldav_alarm_delete_record(mboxname, record->uid);
        goto done_item;
    }

    /* don't process alarms in draft messages */
    if (record->system_flags & FLAG_DRAFT) {
        syslog(LOG_NOTICE, "ignoring draft message in mailbox %s uid %u",
               mailbox_name(mailbox), record->uid);
        goto done_item;
    }

    struct lastalarm_data data;
    if (read_lastalarm(mailbox, record, &data))
        data.lastrun = record->internaldate;

    /* Process VALARMs in iCalendar resource */
    char *userid = mboxname_to_userid(mboxname);

    syslog(LOG_DEBUG, "processing alarms in resource");

    data.nextcheck = process_alarms(mboxname, record->uid, userid,
                                    floatingtz, ical, data.lastrun, runtime, dryrun);
    free(userid);


    /* Determine JMAP secretary mode for this account */
    int is_secretarymode = 0;
    mbname_t *mbname = mbname_from_intname(mailbox_name(mailbox));
    const strarray_t *boxes = mbname_boxes(mbname);
    const char *prefix = config_getstring(IMAPOPT_CALENDARPREFIX);
    if (strarray_size(boxes) && !strcmpsafe(prefix, strarray_nth(boxes, 0))) {
        mbname_truncate_boxes(mbname, 1);
        static const char *annot =
            DAV_ANNOT_NS "<" XML_NS_JMAPCAL ">sharees-act-as";
        struct buf val = BUF_INITIALIZER;
        annotatemore_lookup(mbname_intname(mbname), annot, "", &val);
        is_secretarymode = !strcmp(buf_cstring(&val), "secretary");
        buf_free(&val);
    }
    mbname_free(&mbname);

    /* Process VALARMs in per-user-cal-data */
    struct process_alarms_rock prock =
        { mailbox->i.options, ical, &data, runtime, dryrun, is_secretarymode };

    syslog(LOG_DEBUG, "processing per-user alarms");

    mailbox_get_annotate_state(mailbox, record->uid, NULL);
    annotatemore_findall_mailbox(mailbox, record->uid, PER_USER_CAL_DATA,
                         /* modseq */ 0, &process_peruser_alarms_cb,
                         &prock, /* flags */ 0);

    data.lastrun = runtime;
    if (!dryrun) write_lastalarm(mailbox, record, &data);

    update_alarmdb(mboxname, record->uid, data.nextcheck,
                   ALARM_CALENDAR, 0, 0, 0, NULL);

done_item:
    if (ical) icalcomponent_free(ical);
    caldav_close(db);
    return 0;
}

#ifdef WITH_JMAP
static int move_to_mailboxid(struct mailbox *srcmbox,
                             struct index_record *record,
                             const char *destmboxid, time_t savedate,
                             json_t *setkeywords, int is_snoozed)
                           
{
    struct buf buf = BUF_INITIALIZER;
    msgrecord_t *mr = NULL;
    mbname_t *mbname = NULL;
    struct appendstate as;
    struct mailbox *destmbox = NULL;
    struct auth_state *authstate = NULL;
    const char *userid;
    char *destname = NULL;
    struct stagemsg *stage = NULL;
    struct entryattlist *annots = NULL;
    strarray_t *flags = NULL;
    struct body *body = NULL;
    FILE *f = NULL;
    int r = 0;

    syslog(LOG_DEBUG, "moving message %s:%u to mailboxid %s",
           mailbox_name(srcmbox), record->uid, destmboxid);

    mr = msgrecord_from_index_record(srcmbox, record);
    if (!mr) goto done;

    /* Fetch message */
    r = msgrecord_get_body(mr, &buf);
    if (r) goto done;

    /* Fetch annotations */
    r = msgrecord_extract_annots(mr, &annots);
    if (r) goto done;

    mbname = mbname_from_intname(mailbox_name(srcmbox));
    mbname_set_boxes(mbname, NULL);
    userid = mbname_userid(mbname);
    authstate = auth_newstate(userid);

    /* Fetch flags */
    r = msgrecord_extract_flags(mr, userid, &flags);
    if (r) goto done;

    if (is_snoozed) {
        /* Add \snoozed pseudo-flag */
        strarray_add(flags, "\\snoozed");
    }

    /* (Un)set any client-supplied flags */
    if (setkeywords) {
        const char *key;
        json_t *val;

        json_object_foreach(setkeywords, key, val) {
            const char *flag = jmap_keyword_to_imap(key);
            if (flag) {
                if (json_is_true(val)) strarray_add_case(flags, flag);
                else strarray_remove_all_case(flags, flag);
            }
        }
    }

    /* Determine destination mailbox of moved email */
    if (destmboxid) {
        mbentry_t *mbentry = NULL;
        r = mboxlist_lookup_by_uniqueid(destmboxid, &mbentry, NULL);
        if (!r && mbentry &&
            // MUST be an email mailbox
            (mbtype_isa(mbentry->mbtype) == MBTYPE_EMAIL) &&
            // MUST NOT be deleted
            !(mbentry->mbtype & MBTYPE_DELETED) &&
            // MUST be able to append messages
            (cyrus_acl_myrights(authstate, mbentry->acl) & ACL_INSERT) &&
            // MUST NOT be DELETED mailbox
            !mboxname_isdeletedmailbox(mbentry->name, NULL) &&
            // MUST NOT be our source mailbox
            strcmp(mbentry->name, mailbox_name(srcmbox))) {
            destname = xstrdup(mbentry->name);
        }
        mboxlist_entry_free(&mbentry);

        if (!destname && !is_snoozed) {
            /* Fallback to \Sent mailbox */
            destname = mboxlist_find_specialuse("\\Sent", userid);
        }
    }
    else if (!is_snoozed) {
        /* onSend with no destination, just remove from \Scheduled */
        goto expunge;
    }
    if (!destname) {
        /* Fallback to INBOX */
        destname = xstrdup(mbname_intname(mbname));
    }

    /* Fetch message filename */
    const char *fname;
    r = msgrecord_get_fname(mr, &fname);
    if (r) goto done;

    /* Prepare to stage the message */
    if (!(f = append_newstage_full(destname, time(0), 0, &stage, fname))) {
        syslog(LOG_ERR, "append_newstage(%s) failed", destname);
        r = IMAP_IOERROR;
        goto done;
    }
    fclose(f);

    r = mailbox_open_iwl(destname, &destmbox);
    if (r) goto done;

    /* XXX: should we look for an existing record with that GUID in the target folder
     * first and just remove this copy if so?  Otherwise we could duplicate if the
     * update fails between the append to the new mailbox and the expunge from Snoozed
     */

    r = append_setup_mbox(&as, destmbox, userid, authstate,
                          ACL_INSERT, NULL, NULL, 0,
                          is_snoozed ? EVENT_MESSAGE_NEW : EVENT_MESSAGE_APPEND);
    if (r) goto done;

    /* Append the message to the mailbox */
    r = append_fromstage_full(&as, &body, stage, record->internaldate,
                              savedate, 0, flags, 0, &annots);
    if (r) {
        append_abort(&as);
        goto done;
    }

    r = append_commit(&as);
    if (r) goto done;

  expunge:
    /* Expunge the resource from the source mailbox (also unset \snoozed) */
    record->internal_flags |= FLAG_INTERNAL_EXPUNGED;
    if (is_snoozed) record->internal_flags &= ~FLAG_INTERNAL_SNOOZED;
    r = mailbox_rewrite_index_record(srcmbox, record);
    if (r) {
        syslog(LOG_ERR, "expunging record (%s:%u) failed: %s",
               mailbox_name(srcmbox), record->uid, error_message(r));
    }

  done:
    if (body) {
        message_free_body(body);
        free(body);
    }
    strarray_free(flags);
    freeentryatts(annots);
    append_removestage(stage);

    mailbox_close(&destmbox);
    if (authstate) auth_freestate(authstate);
    if (mbname) mbname_free(&mbname);
    if (mr) msgrecord_unref(&mr);
    buf_free(&buf);
    free(destname);

    return r;
}

struct find_sched_rock {
    char *userid;
    char *mboxname;
    uint32_t uid;
};

static int find_sched_cb(const conv_guidrec_t *rec, void *rock)
{
    struct find_sched_rock *frock = (struct find_sched_rock *) rock;
    mbentry_t *mbentry = NULL;
    int res = 0;

    /* We're looking for whole, non-expunged messages */
    if (rec->part ||
        (rec->system_flags & FLAG_DELETED) ||
        (rec->internal_flags & FLAG_INTERNAL_EXPUNGED)) {
        return 0;
    }

    /* Lookup mailbox and make sure it is \Scheduled */
    conv_guidrec_mbentry(rec, &mbentry);

    if (!mbentry) return 0;

    if (mboxname_isscheduledmailbox(mbentry->name, mbentry->mbtype)) {
        frock->mboxname = xstrdup(mbentry->name);
        frock->uid = rec->uid;
        res = IMAP_OK_COMPLETED;
    }

    mboxlist_entry_free(&mbentry);

    return res;
}

static int find_scheduled_email(const char *emailid,
                                struct find_sched_rock *frock)
{
    struct conversations_state *cstate = NULL;
    int r;

    if (emailid[0] != 'M' || strlen(emailid) != 25) {
        return IMAP_NOTFOUND;
    }

    r = conversations_open_user(frock->userid, 1/*shared*/, &cstate);
    if (r) {
        syslog(LOG_ERR, "IOERROR: failed to open conversations for user %s",
               frock->userid);
        return r;
    }

    const char *guid = emailid + 1;
    r = conversations_guid_foreach(cstate, guid, find_sched_cb, frock);
    conversations_commit(&cstate);

    if (r == IMAP_OK_COMPLETED) r = 0;
    else if (!frock->mboxname) r = IMAP_NOTFOUND;

    return r;
}

static int count_cb(sqlite3_stmt *stmt, void *rock)
{
    unsigned *count = (unsigned *) rock;

    *count = sqlite3_column_int(stmt, 0);

    return 0;
}

#define CMD_GET_UNSCHEDULED_COUNT \
    "SELECT num_retries"          \
    " FROM events WHERE"          \
    "  mboxname = :mboxname AND"  \
    "  imap_uid = :imap_uid AND"  \
    "  type     = :type"          \
    ";"

static int update_unscheduled(const char *mboxname, time_t nextcheck)
{
    struct sqldb_bindval bval[] = {
        { ":mboxname",     SQLITE_TEXT,    { .s = mboxname          } },
        { ":imap_uid",     SQLITE_INTEGER, { .i = 0                 } },
        { ":nextcheck",    SQLITE_INTEGER, { .i = nextcheck         } },
        { ":type",         SQLITE_INTEGER, { .i = ALARM_UNSCHEDULED } },
        { ":num_rcpts",    SQLITE_INTEGER, { .i = 0                 } },
        { ":num_retries",  SQLITE_INTEGER, { .i = 0                 } },
        { ":last_run",     SQLITE_INTEGER, { .i = 0                 } },
        { ":last_err",     SQLITE_TEXT,    { .s = NULL              } },
        { NULL,            SQLITE_NULL,    { .s = NULL              } }
    };

    sqldb_t *alarmdb = caldav_alarm_open();
    if (!alarmdb) return -1;

    syslog(LOG_DEBUG, "update_unscheduled(%s, " TIME_T_FMT ")",
           mboxname, nextcheck);

    unsigned count = 0;
    int rc = sqldb_exec(alarmdb, CMD_GET_UNSCHEDULED_COUNT,
                        bval, &count_cb, &count);

    if (rc == SQLITE_OK) {
        bval[5].val.i = ++count; // num_retries used as unscheduled count
        rc = sqldb_exec(alarmdb, CMD_REPLACE, bval, NULL, NULL);
    }

    caldav_alarm_close(alarmdb);

    if (rc == SQLITE_OK) return 0;

    /* failed? */
    return -1;
}

static int process_futurerelease(struct caldav_alarm_data *data,
                                 struct mailbox *mailbox,
                                 struct index_record *record,
                                 time_t runtime)

{
    message_t *m = message_new_from_record(mailbox, record);
    struct buf buf = BUF_INITIALIZER;
    json_t *submission = NULL, *identity, *envelope, *onSend;
    smtpclient_t *sm = NULL;
    int r = 0;

    syslog(LOG_DEBUG, "processing future release for mailbox %s uid %u",
           mailbox_name(mailbox), record->uid);

    if (record->system_flags & FLAG_ANSWERED) {
        syslog(LOG_NOTICE, "email already sent for mailbox %s uid %u",
               mailbox_name(mailbox), record->uid);
        r = IMAP_NO_NOSUCHMSG;
        goto done;
    }

    if (record->system_flags & FLAG_FLAGGED) {
        syslog(LOG_NOTICE, "submission canceled for mailbox %s uid %u",
               mailbox_name(mailbox), record->uid);
        r = IMAP_NO_NOSUCHMSG;
        goto done;
    }

    /* Parse the submission object from the header field */
    r = message_get_field(m, JMAP_SUBMISSION_HDR, MESSAGE_RAW, &buf);
    if (!r) {
        json_error_t jerr;
        submission = json_loadb(buf_base(&buf), buf_len(&buf),
                                JSON_DISABLE_EOF_CHECK, &jerr);
    }
    if (!submission) {
        syslog(LOG_ERR,
               "process_futurerelease: failed to parse submission obj");
        goto done;
    }
    envelope = json_object_get(submission, "envelope");
    identity = json_object_get(submission, "identityId");
    onSend = json_object_get(submission, "onSend");

    /* Load message */
    r = message_get_field(m, "rawbody", MESSAGE_RAW, &buf);
    if (r) {
        syslog(LOG_ERR, "process_futurerelease: can't get body for %s:%u",
               mailbox_name(mailbox), record->uid);
        goto done;
    }

    /* Open the SMTP connection */
    unsigned code = 0, cancel = 0;
    const char *err = NULL;
    r = smtpclient_open(&sm);
    if (r) {
        err = error_message(r);
        syslog(LOG_ERR, "smtpclient_open failed: %s", err);
    }
    else {
        smtpclient_set_auth(sm, json_string_value(identity));

        /* Prepare envelope */
        smtp_envelope_t smtpenv = SMTP_ENVELOPE_INITIALIZER;
        jmap_emailsubmission_envelope_to_smtp(&smtpenv, envelope);

        /* Send message */
        r = smtpclient_send(sm, &smtpenv, &buf);
        smtp_envelope_fini(&smtpenv);
        if (r) {
            /* Get the response code and error text.
               We treat anything other than 5xx as a temp failure */
            code = smtpclient_get_resp_code(sm);
            if (code) {
                err = smtpclient_get_resp_text(sm);
                if (code >= 500) {
                    /* Permanent failure */
                    cancel = 1;
                }
            }
            else {
                err = error_message(r);
            }
            syslog(LOG_ERR, "smtpclient_send failed: %s", err);
        }
    }

    const char *destmboxid = NULL;
    json_t *setkeywords = NULL;
    char *userid = NULL;

    if (r) {
        /* Determine if we should retry (again) or cancel the submission.
           We try at 5m, 15m, 30m, 60m after original scheduled time. */
        unsigned duration;
        switch (data->num_retries) {
        case 0: duration =  300; break;
        case 1: duration =  600; break;
        case 2: duration =  900; break;
        case 3: duration = 1800; break;
        default: cancel = 1; break;
        }

        if (!cancel) {
            /* Retry */
            caldav_alarm_bump_nextcheck(data, runtime + duration, runtime, err);
            if (sm) smtpclient_close(&sm);
            goto done;
        }
        else if (onSend) {
            /* Move the scheduled message back into Drafts mailbox.
               Use INBOX as a fallback. */
            userid = mboxname_to_userid(data->mboxname);

            char *destname = mboxlist_find_specialuse("\\Drafts", userid);
            mbentry_t *mbentry = NULL;

            if (!destname) {
                destname = mboxname_user_mbox(userid, NULL);
            }

            mboxlist_lookup(destname, &mbentry, NULL);
            if (mbentry) {
                buf_setcstr(&buf, mbentry->uniqueid);

                destmboxid = buf_cstring(&buf);
                setkeywords = json_pack("{ s:b }", "$draft", 1);

                mboxlist_entry_free(&mbentry);
            }
            free(destname);
        }
    }
    else {
        /* Mark the email as sent */
        record->system_flags |= FLAG_ANSWERED;

        /* Get any onSend instructions */
        if (onSend) {
            destmboxid =
                json_string_value(json_object_get(onSend, "moveToMailboxId"));
            setkeywords = json_deep_copy(json_object_get(onSend, "setKeywords"));
        }
    }
    if (sm) smtpclient_close(&sm);

    if (cancel || config_getswitch(IMAPOPT_JMAPSUBMISSION_DELETEONSEND)) {
        /* Delete the EmailSubmission object immediately */
        record->system_flags |= FLAG_DELETED;
        record->internal_flags |= FLAG_INTERNAL_EXPUNGED;
    }

    r = mailbox_rewrite_index_record(mailbox, record);
    if (r) {
        syslog(LOG_ERR, "IOERROR: marking emailsubmission as %s (%s:%u) failed: %s",
               cancel ? "cancelled" : "sent",
               mailbox_name(mailbox), record->uid, error_message(r));
        // email is already sent, so we don't want to try to send it again!
        // go ahead and delete the record still...
    }

    caldav_alarm_delete_record(mailbox_name(mailbox), record->uid);

    if (destmboxid) {
        /* Move the scheduled message into the specified mailbox */
        if (!userid) userid = mboxname_to_userid(data->mboxname);

        const char *emailid =
            json_string_value(json_object_get(submission, "emailId"));
        struct find_sched_rock frock = { userid, NULL, 0 };
        struct mailbox *sched_mbox = NULL;
        struct index_record sched_rec;

        /* Locate email in \Scheduled mailbox */
        r = find_scheduled_email(emailid, &frock);

        if (r || !frock.mboxname) {
            syslog(LOG_ERR,
                   "IOERROR: failed to find \\Scheduled mailbox for user %s (%s)",
                   frock.userid, error_message(r));
        }
        else if ((r = mailbox_open_iwl(frock.mboxname, &sched_mbox))) {
            syslog(LOG_ERR, "IOERROR: failed to open %s: %s",
                   frock.mboxname, error_message(r));
        }
        else if ((r = mailbox_find_index_record(sched_mbox,
                                                frock.uid, &sched_rec))) {
            syslog(LOG_ERR, "IOERROR: failed find message %u in %s: %s",
                   frock.uid, frock.mboxname, error_message(r));
        }
        else {
            r = move_to_mailboxid(sched_mbox, &sched_rec, destmboxid,
                                  time(0), setkeywords, 0/*is_snoozed*/);

            if (r) {
                syslog(LOG_ERR, "IOERROR: failed to move %s:%u (%s)",
                       frock.mboxname, frock.uid, error_message(r));

            }
            else if (cancel) {
                update_unscheduled(data->mboxname, runtime + 300);
            }
        }

        if (setkeywords) json_decref(setkeywords);
        mailbox_close(&sched_mbox);
        free(frock.mboxname);
    }
    free(userid);

  done:
    if (submission) json_decref(submission);
    if (m) message_unref(&m);
    buf_free(&buf);

    return r;
}

static int process_snoozed(struct caldav_alarm_data *data,
                           struct mailbox *mailbox,
                           struct index_record *record,
                           time_t runtime,
                           int dryrun)
{
    json_t *snoozed, *destmboxid, *setkeywords;
    time_t wakeup;
    int r = 0;

    syslog(LOG_DEBUG, "processing snoozed email for mailbox %s uid %u",
           mailbox_name(mailbox), record->uid);

    /* Get the snoozed annotation */
    snoozed = jmap_fetch_snoozed(mailbox_name(mailbox), record->uid);
    if (!snoozed) {
        // no worries, let's not try again
        caldav_alarm_delete_record(mailbox_name(mailbox), record->uid);
        goto done;
    }

    /* Extract until (wakeup) */
    time_from_iso8601(json_string_value(json_object_get(snoozed, "until")),
                      &wakeup);

    /* Check runtime against wakeup and adjust as necessary */
    if (dryrun || wakeup > runtime) {
        caldav_alarm_bump_nextcheck(data, wakeup, 0, NULL);
        goto done;
    }

    destmboxid = json_object_get(snoozed, "moveToMailboxId");
    setkeywords = json_object_get(snoozed, "setKeywords");

    r = move_to_mailboxid(mailbox, record, json_string_value(destmboxid),
                          wakeup, setkeywords, 1/*is_snoozed*/);

    if (r) {
        syslog(LOG_ERR, "IOERROR: failed to unsnooze %s:%u (%s)",
               mailbox_name(mailbox), record->uid, error_message(r));
        /* try again in 5 minutes */
        caldav_alarm_bump_nextcheck(data, runtime + 300, runtime, error_message(r));
    }

 done:
    if (snoozed) json_decref(snoozed);

    return r;
}
#endif /* WITH_JMAP */

static void process_unscheduled(struct caldav_alarm_data *data)
{
    struct mboxevent *event = mboxevent_new(EVENT_MESSAGES_UNSCHEDULED);
    char *userid = mboxname_to_userid(data->mboxname);

    FILL_STRING_PARAM(event, EVENT_MESSAGES_UNSCHEDULED_USERID, userid);
    FILL_UNSIGNED_PARAM(event, EVENT_MESSAGES_UNSCHEDULED_COUNT, data->num_retries);

    mboxevent_notify(&event);
    mboxevent_free(&event);

    caldav_alarm_delete_record(data->mboxname, data->imap_uid);
}

static void process_one_record(struct caldav_alarm_data *data, time_t runtime, int dryrun)
{
    int r;
    struct mailbox *mailbox = NULL;

    syslog(LOG_DEBUG,
           "processing alarms for mailbox %s uid %u type %u retries %u",
           data->mboxname, data->imap_uid, data->type, data->num_retries);

    if (data->type == ALARM_UNSCHEDULED) {
        process_unscheduled(data);
        return;
    }

    r = dryrun ? mailbox_open_irl(data->mboxname, &mailbox) : mailbox_open_iwl(data->mboxname, &mailbox);
    if (r == IMAP_MAILBOX_NONEXISTENT) {
        syslog(LOG_ERR, "not found mailbox %s", data->mboxname);
        /* no record, no worries */
        caldav_alarm_delete_record(data->mboxname, data->imap_uid);
        return;
    }
    else if (r) {
        /* Temporary error - skip over this message for now and try again in 5 minutes */
        syslog(LOG_ERR, "IOERROR: failed to open mailbox %s for uid %u (%s)",
               data->mboxname, data->imap_uid, error_message(r));
        caldav_alarm_bump_nextcheck(data, runtime + 300, runtime, error_message(r));
        return;
    }

    struct index_record record;
    memset(&record, 0, sizeof(struct index_record));
    r = mailbox_find_index_record(mailbox, data->imap_uid, &record);
    if (r == IMAP_NOTFOUND) {
        syslog(LOG_NOTICE, "not found mailbox %s uid %u",
               data->mboxname, data->imap_uid);
        /* no record, no worries */
        caldav_alarm_delete_record(data->mboxname, data->imap_uid);
        goto done;
    }
    if (r) {
        syslog(LOG_ERR, "IOERROR: error reading mailbox %s uid %u (%s)",
               data->mboxname, data->imap_uid, error_message(r));
        /* XXX no index record? item deleted or transient error? */
        caldav_alarm_bump_nextcheck(data, runtime + 300, runtime, error_message(r));
        goto done;
    }

    if (record.internal_flags & FLAG_INTERNAL_EXPUNGED) {
        syslog(LOG_NOTICE, "already expunged mailbox %s uid %u",
               data->mboxname, data->imap_uid);
        /* no longer exists?  nothing to do */
        caldav_alarm_delete_record(data->mboxname, data->imap_uid);
        goto done;
    }

    switch (data->type) {
    case ALARM_CALENDAR: {
        icaltimezone *floatingtz = get_floatingtz(mailbox_name(mailbox), "");
        r = process_valarms(mailbox, &record, floatingtz, runtime, dryrun);
        if (floatingtz) icaltimezone_free(floatingtz, 1);
        break;
    }
#ifdef WITH_JMAP
    case ALARM_SEND:
        if (record.internaldate > runtime || dryrun) {
            caldav_alarm_bump_nextcheck(data, record.internaldate, 0, NULL);
            goto done;
        }
        r = process_futurerelease(data, mailbox, &record, runtime);
        break;

    case ALARM_SNOOZE:
        /* XXX  Check special-use flag on mailbox */
        r = process_snoozed(data, mailbox, &record, runtime, dryrun);
        break;
#endif
    default:
        /* XXX  Should never get here */
        syslog(LOG_ERR, "Unknown/unsupported alarm triggered for"
               " mailbox %s uid %u of type %d with options 0x%02x",
               data->mboxname, data->imap_uid,
               mailbox_mbtype(mailbox), mailbox->i.options);
        caldav_alarm_delete_record(data->mboxname, data->imap_uid);
        break;
    }

done:
    if (r) mailbox_abort(mailbox);
    mailbox_close(&mailbox);
}

#define MAX_CONSECUTIVE_ALARMS_PER_USER 50

/* process alarms with triggers before a given time */
EXPORTED int caldav_alarm_process(time_t runtime, time_t *intervalp, int dryrun)
{
    int i;

    syslog(LOG_DEBUG, "processing alarms");

    if (!runtime) {
        runtime = time(NULL);
    }

    struct alarm_read_rock rock = { PTRARRAY_INITIALIZER, runtime, runtime + 10 };

    // check 10 seconds into the future - if there's something in there,
    // we'll run again - otherwise we'll wait the 10 seconds before checking again
    struct sqldb_bindval bval[] = {
        { ":before",    SQLITE_INTEGER, { .i = rock.next } },
        { NULL,         SQLITE_NULL,    { .s = NULL      } }
    };

    sqldb_t *alarmdb = caldav_alarm_open();
    if (!alarmdb)
        return HTTP_SERVER_ERROR;

    int rc = sqldb_exec(alarmdb, CMD_SELECT_ALARMS, bval, &alarm_read_cb, &rock);

    caldav_alarm_close(alarmdb);

    if (intervalp) {
        // we want to restrict the number of records processed per user per run,
        // and also take a non-blocking lock so we're never waiting while other
        // things process
        int skipped_some = 0;
        int did_some = 0;
        int num_user_records = 0;
        char *userid = NULL;
        struct mboxlock *nslock = NULL;
        for (i = 0; i < rock.list.count; i++) {
            struct caldav_alarm_data *data = ptrarray_nth(&rock.list, i);

            // only alarms for mailboxes with userids
            mbname_t *mbname = mbname_from_intname(data->mboxname);
            if (!mbname_userid(mbname)) {
                mbname_free(&mbname);
                continue;
            }

            // we are sorted by mboxname, so all the mailboxes for the same
            // userid will be next to each other
            if (strcmpsafe(userid, mbname_userid(mbname))) {
                num_user_records = 0;
                free(userid);
                mboxname_release(&nslock);
                userid = xstrdup(mbname_userid(mbname));
                nslock = user_namespacelock_full(userid, LOCK_NONBLOCKING);
            }
            mbname_free(&mbname);

            // if we failed to lock the user, or have done too many for this user, skip
            if (!nslock || ++num_user_records > MAX_CONSECUTIVE_ALARMS_PER_USER) {
                skipped_some++;
                caldav_alarm_fini(data);
                free(data);
                continue;
            }

            did_some++;
            process_one_record(data, runtime, dryrun);
            caldav_alarm_fini(data);
            free(data);
        }

        free(userid);
        mboxname_release(&nslock);

        // if we both made some progress AND skipped some, then retry again immediately
        if (did_some && skipped_some) rock.next = runtime;
    }
    else {
        // we're testing or reconstructing, run everything!
        for (i = 0; i < rock.list.count; i++) {
            struct caldav_alarm_data *data = ptrarray_nth(&rock.list, i);
            process_one_record(data, runtime, dryrun);
            caldav_alarm_fini(data);
            free(data);
        }
    }

    ptrarray_fini(&rock.list);

    syslog(LOG_DEBUG, "done");

    if (intervalp) *intervalp = rock.next - runtime;

    return rc;
}

static int upgrade_read_cb(sqlite3_stmt *stmt, void *rock)
{
    strarray_t *target = (strarray_t *)rock;

    strarray_append(target, (const char *) sqlite3_column_text(stmt, 0));

    return 0;
}

#define CMD_READ_OLDALARMS "SELECT DISTINCT mailbox FROM alarms;"

EXPORTED int caldav_alarm_upgrade()
{
    syslog(LOG_DEBUG, "checking if alarm database needs upgrading");

    struct mailbox *mailbox = NULL;

    strarray_t mailboxes = STRARRAY_INITIALIZER;

    sqldb_t *alarmdb = caldav_alarm_open();
    if (!alarmdb) return HTTP_SERVER_ERROR;
    int rc = sqldb_exec(alarmdb, "SELECT DISTINCT mailbox FROM alarms;",
                        NULL, &upgrade_read_cb, &mailboxes);
    caldav_alarm_close(alarmdb);

    time_t runtime = time(NULL);

    int i;
    for (i = 0; i < strarray_size(&mailboxes); i++) {
        const char *mboxname = strarray_nth(&mailboxes, i);
        syslog(LOG_DEBUG, "UPDATING calalarm database for %s", mboxname);
        rc = mailbox_open_iwl(mboxname, &mailbox);
        if (rc) continue;

        sqldb_t *alarmdb = caldav_alarm_open();
        /* clean up any existing alarms for this mailbox */
        struct sqldb_bindval bval[] = {
            { ":mboxname",  SQLITE_TEXT, { .s = mboxname  } },
            { NULL,         SQLITE_NULL, { .s = NULL      } }
        };
        rc = sqldb_exec(alarmdb, CMD_DELETEMAILBOX, bval, NULL, NULL);
        caldav_alarm_close(alarmdb);
        if (rc) continue;

        icaltimezone *floatingtz = get_floatingtz(mailbox_name(mailbox), "");

        /* add alarms for all records */
        struct mailbox_iter *iter =
            mailbox_iter_init(mailbox, 0, ITER_SKIP_EXPUNGED);
        const message_t *msg;
        while ((msg = mailbox_iter_step(iter))) {
            const struct index_record *record = msg_record(msg);
            icalcomponent *ical = record_to_ical(mailbox, record, NULL);

            if (ical) {
                if (has_alarms(ical, mailbox, record->uid, NULL)) {
                    char *userid = mboxname_to_userid(mailbox_name(mailbox));
                    time_t nextcheck = process_alarms(mailbox_name(mailbox), record->uid,
                                                      userid, floatingtz, ical,
                                                      runtime, runtime, /*dryrun*/1);
                    free(userid);

                    update_alarmdb(mailbox_name(mailbox), record->uid, nextcheck,
                                   ALARM_CALENDAR, 0, 0, 0, NULL);
                }
                icalcomponent_free(ical);
            }
        }
        mailbox_iter_done(&iter);
        mailbox_close(&mailbox);

        if (floatingtz) icaltimezone_free(floatingtz, 1);
    }

    strarray_fini(&mailboxes);

    alarmdb = caldav_alarm_open();
    if (!alarmdb) return HTTP_SERVER_ERROR;
    sqldb_exec(alarmdb, "DROP TABLE alarm_recipients;", NULL, NULL, NULL);
    sqldb_exec(alarmdb, "DROP TABLE alarms;", NULL, NULL, NULL);
    caldav_alarm_close(alarmdb);

    return rc;
}
