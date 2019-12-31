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
};

void caldav_alarm_fini(struct caldav_alarm_data *alarmdata)
{
    free(alarmdata->mboxname);
    alarmdata->mboxname = NULL;
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


#define CMD_CREATE                                      \
    "CREATE TABLE IF NOT EXISTS events ("               \
    " mboxname TEXT NOT NULL,"                          \
    " imap_uid INTEGER NOT NULL,"                       \
    " nextcheck INTEGER NOT NULL,"                      \
    " PRIMARY KEY (mboxname, imap_uid)"                 \
    ");"                                                \
    "CREATE INDEX IF NOT EXISTS checktime ON events (nextcheck);"


#define DBVERSION 2

/* the command loop will do the upgrade and then drop the old tables.
 * Sadly there's no other way to do it without creating a lock inversion! */
#define CMD_UPGRADEv2 CMD_CREATE

static struct sqldb_upgrade upgrade[] = {
    { 2, CMD_UPGRADEv2, NULL },
    /* always finish with an empty row */
    { 0, NULL, NULL }
};

#define CMD_REPLACE                              \
    "REPLACE INTO events"                        \
    " ( mboxname, imap_uid, nextcheck )"         \
    " VALUES"                                    \
    " ( :mboxname, :imap_uid, :nextcheck )"      \
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

#define CMD_SELECTUSER           \
    "SELECT mboxname, imap_uid, nextcheck" \
    " FROM events WHERE"                   \
    " mboxname LIKE :prefix"               \
    ";"

#define CMD_SELECT_ALARMS                                                \
    "SELECT mboxname, imap_uid, nextcheck"                               \
    " FROM events WHERE"                                                 \
    " nextcheck < :before"                                               \
    " ORDER BY mboxname, imap_uid, nextcheck"                            \
    ";"

static sqldb_t *my_alarmdb;
int refcount;
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
    my_alarmdb = sqldb_open(dbfilename, CMD_CREATE, DBVERSION, upgrade,
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
    int rc = sqldb_exec(db, CMD_CREATE, NULL, NULL, NULL);
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
                      icaltimetype alarmtime)
{
    const char *userid = rock->userid;
    struct buf calname = BUF_INITIALIZER;
    struct buf calcolor = BUF_INITIALIZER;

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

    prop = icalcomponent_get_first_property(comp, ICAL_UID_PROPERTY);
    FILL_STRING_PARAM(event, EVENT_CALENDAR_UID,
                      xstrdup(prop ? icalproperty_get_value_as_string(prop) : ""));

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
    mbname_free(&mbname);

    return 0;
}

static int process_alarm_cb(icalcomponent *comp, icaltimetype start,
                            icaltimetype end, void *rock)
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
        if (icalvalue_isa(val) == ICAL_DURATION_VALUE) {
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
                send_alarm(data, comp, alarm, start, end, alarmtime);
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
    }

    return 1; /* keep going */
}

static int update_alarmdb(const char *mboxname,
                          uint32_t imap_uid, time_t nextcheck)
{
    struct sqldb_bindval bval[] = {
        { ":mboxname",  SQLITE_TEXT,    { .s = mboxname  } },
        { ":imap_uid",  SQLITE_INTEGER, { .i = imap_uid  } },
        { ":nextcheck", SQLITE_INTEGER, { .i = nextcheck } },
        { NULL,         SQLITE_NULL,    { .s = NULL      } }
    };

    sqldb_t *alarmdb = caldav_alarm_open();
    if (!alarmdb) return -1;
    int rc = SQLITE_OK;

    syslog(LOG_DEBUG, "update_alarmdb(%s:%u, " TIME_T_FMT ")",
           mboxname, imap_uid, nextcheck);

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

static icalcomponent *vpatch_from_peruserdata(const struct buf *userdata)
{
    struct dlist *dl;
    const char *icalstr;
    icalcomponent *vpatch;

    /* Parse the value and fetch the patch */
    dlist_parsemap(&dl, 1, 0, buf_base(userdata), buf_len(userdata));
    dlist_getatom(dl, "VPATCH", &icalstr);
    vpatch = icalparser_parse_string(icalstr);
    dlist_free(&dl);

    return vpatch;
}

struct has_alarms_rock {
    uint32_t mbox_options;
    int *has_alarms;
};

static int has_peruser_alarms_cb(const char *mailbox,
                                 uint32_t uid __attribute__((unused)),
                                 const char *entry __attribute__((unused)),
                                 const char *userid, const struct buf *value,
                                 const struct annotate_metadata *mdata __attribute__((unused)),
                                 void *rock)
{
    struct has_alarms_rock *hrock = (struct has_alarms_rock *) rock;
    icalcomponent *vpatch, *comp;

    if (!mboxname_userownsmailbox(userid, mailbox) &&
        ((hrock->mbox_options & OPT_IMAP_SHAREDSEEN) ||
         mboxlist_checksub(mailbox, userid) != 0)) {
        /* No per-user-data, or sharee has unsubscribed from this calendar */
        return 0;
    }
        
    /* Extract VPATCH from per-user-cal-data annotation */
    vpatch = vpatch_from_peruserdata(value);

    /* Check PATCHes for any VALARMs */
    for (comp = icalcomponent_get_first_component(vpatch, ICAL_XPATCH_COMPONENT);
         comp;
         comp = icalcomponent_get_next_component(vpatch, ICAL_XPATCH_COMPONENT)) {
        if (icalcomponent_get_first_component(comp, ICAL_VALARM_COMPONENT)) {
            *(hrock->has_alarms) = 1;
            break;
        }
    }

    icalcomponent_free(vpatch);

    return 0;
}

static int has_alarms(icalcomponent *ical, struct mailbox *mailbox, uint32_t uid)
{
    int has_alarms = 0;

    syslog(LOG_DEBUG, "checking for alarms in mailbox %s uid %u",
           mailbox_name(mailbox), uid);

    if (mailbox->i.options & OPT_IMAP_HAS_ALARMS) return 1;

    if (ical) {
        /* Check iCalendar resource for VALARMs */
        icalcomponent *comp = icalcomponent_get_first_real_component(ical);
        icalcomponent_kind kind = icalcomponent_isa(comp);

        syslog(LOG_DEBUG, "checking resource");
        for (; comp; comp = icalcomponent_get_next_component(ical, kind)) {
            if (icalcomponent_get_first_component(comp, ICAL_VALARM_COMPONENT))
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

static time_t process_alarms(const char *mboxname, uint32_t imap_uid,
                             const char *userid, icaltimezone *floatingtz,
                             icalcomponent *ical, time_t lastrun,
                             time_t runtime, int dryrun)
{
    struct get_alarm_rock rock =
        { userid, mboxname, imap_uid, floatingtz, lastrun, runtime, 0, dryrun };
    struct icalperiodtype range = icalperiodtype_null_period();
    icalcomponent_myforeach(ical, range, floatingtz, process_alarm_cb, &rock);
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

/* add a calendar alarm */
HIDDEN int caldav_alarm_add_record(struct mailbox *mailbox,
                                     const struct index_record *record,
                                     icalcomponent *ical)
{
    if (has_alarms(ical, mailbox, record->uid))
        update_alarmdb(mailbox_name(mailbox), record->uid, record->internaldate);

    return 0;
}

EXPORTED int caldav_alarm_touch_record(struct mailbox *mailbox,
                                       const struct index_record *record)
{
    /* if there are alarms in the annotations,
     * the next alarm may have become earlier, so get calalarmd to check again */
    if (has_alarms(NULL, mailbox, record->uid))
        return update_alarmdb(mailbox_name(mailbox), record->uid, record->last_updated);

    return 0;
}

/* called by sync_support from sync_server -
 * set nextcheck in the calalarmdb based on the full state,
 * record + annotations, after the annotations have been updated too */
EXPORTED int caldav_alarm_sync_nextcheck(struct mailbox *mailbox, const struct index_record *record)
{
    struct lastalarm_data data;
    if (!read_lastalarm(mailbox, record, &data))
        return update_alarmdb(mailbox_name(mailbox), record->uid, data.nextcheck);

    /* if there's no lastalarm on the record, nuke any existing alarmdb entry */
    return caldav_alarm_delete_record(mailbox_name(mailbox), record->uid);
}

/* delete all alarms matching the event */
HIDDEN int caldav_alarm_delete_record(const char *mboxname, uint32_t imap_uid)
{
    return update_alarmdb(mboxname, imap_uid, 0);
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
        data->mboxname    = xstrdup((const char *) sqlite3_column_text(stmt, 0));
        data->imap_uid    = sqlite3_column_int(stmt, 1);
        data->nextcheck   = nextcheck;
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
    time_t check;

    if (!mboxname_userownsmailbox(userid, mailbox) &&
        ((prock->mbox_options & OPT_IMAP_SHAREDSEEN) ||
         mboxlist_checksub(mailbox, userid) != 0)) {
        /* No per-user-data, or sharee has unsubscribed from this calendar */
        return 0;
    }

    /* Extract VPATCH from per-user-cal-data annotation */
    vpatch = vpatch_from_peruserdata(value);

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
    if (!has_alarms(ical, mailbox, record->uid)) {
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

    /* Process VALARMs in per-user-cal-data */
    struct process_alarms_rock prock =
        { mailbox->i.options, ical, &data, runtime, dryrun };

    syslog(LOG_DEBUG, "processing per-user alarms");

    mailbox_get_annotate_state(mailbox, record->uid, NULL);
    annotatemore_findall_mailbox(mailbox, record->uid, PER_USER_CAL_DATA,
                         /* modseq */ 0, &process_peruser_alarms_cb,
                         &prock, /* flags */ 0);

    data.lastrun = runtime;
    if (!dryrun) write_lastalarm(mailbox, record, &data);

    update_alarmdb(mboxname, record->uid, data.nextcheck);

done_item:
    if (ical) icalcomponent_free(ical);
    caldav_close(db);
    return 0;
}

#ifdef WITH_JMAP
static int process_futurerelease(struct mailbox *mailbox,
                                 struct index_record *record)
{
    message_t *m = message_new_from_record(mailbox, record);
    struct buf buf = BUF_INITIALIZER;
    json_t *submission = NULL, *identity, *envelope;
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

    /* Load message */
    r = message_get_field(m, "rawbody", MESSAGE_RAW, &buf);
    if (r) {
        syslog(LOG_ERR, "process_futurerelease: can't get body for %s:%u",
               mailbox_name(mailbox), record->uid);
        goto done;
    }

    /* Open the SMTP connection */
    smtpclient_t *sm = NULL;
    r = smtpclient_open(&sm);
    if (r) {
        syslog(LOG_ERR, "smtpclient_open failed: %s", error_message(r));
        goto done;
    }
    smtpclient_set_auth(sm, json_string_value(identity));

    /* Prepare envelope */
    smtp_envelope_t smtpenv = SMTP_ENVELOPE_INITIALIZER;
    jmap_emailsubmission_envelope_to_smtp(&smtpenv, envelope);

    /* Send message */
    r = smtpclient_send(sm, &smtpenv, &buf);
    smtp_envelope_fini(&smtpenv);
    smtpclient_close(&sm);

    if (r) {
        syslog(LOG_ERR, "smtpclient_send failed: %s", error_message(r));
        goto done;
    }

    /* Mark the email as sent */
    record->system_flags |= FLAG_ANSWERED;
    if (config_getswitch(IMAPOPT_JMAPSUBMISSION_DELETEONSEND)) {
        /* delete the EmailSubmission object immediately */
        record->system_flags |= FLAG_DELETED;
        record->internal_flags |= FLAG_INTERNAL_EXPUNGED;
    }
    r = mailbox_rewrite_index_record(mailbox, record);
    if (r) {
        syslog(LOG_ERR, "IOERROR: marking emailsubmission as sent (%s:%u) failed: %s",
               mailbox_name(mailbox), record->uid, error_message(r));
        // email is already sent, so we don't want to try to send it again!
        // go ahead and delete the record still...
    }

    caldav_alarm_delete_record(mailbox_name(mailbox), record->uid);

  done:
    if (submission) json_decref(submission);
    if (m) message_unref(&m);
    buf_free(&buf);

    return r;
}

static int process_snoozed(struct mailbox *mailbox,
                           struct index_record *record,
                           time_t runtime,
                           int dryrun)
{
    struct buf buf = BUF_INITIALIZER;
    msgrecord_t *mr = NULL;
    mbname_t *mbname = NULL;
    struct appendstate as;
    struct mailbox *destmbox = NULL;
    struct auth_state *authstate = NULL;
    const char *userid;
    char *destname = NULL;
    time_t wakeup;
    struct stagemsg *stage = NULL;
    struct entryattlist *annots = NULL;
    strarray_t *flags = NULL;
    struct body *body = NULL;
    FILE *f = NULL;
    json_t *snoozed, *destmboxid, *keywords;
    int r = 0;

    syslog(LOG_DEBUG, "processing snoozed email for mailbox %s uid %u",
           mailbox_name(mailbox), record->uid);

    /* Get the snoozed annotation */
    snoozed = jmap_fetch_snoozed(mailbox_name(mailbox), record->uid);
    if (!snoozed) {
        // no worries, let's not try again
        update_alarmdb(mailbox_name(mailbox), record->uid, 0);
        goto done;
    }

    time_from_iso8601(json_string_value(json_object_get(snoozed, "until")),
                      &wakeup);

    /* Check runtime against wakeup and adjust as necessary */
    if (dryrun || wakeup > runtime) {
        update_alarmdb(mailbox_name(mailbox), record->uid, wakeup);
        goto done;
    }

    mr = msgrecord_from_index_record(mailbox, record);
    if (!mr) goto done;

    /* Fetch message */
    r = msgrecord_get_body(mr, &buf);
    if (r) goto done;

    /* Fetch annotations */
    r = msgrecord_extract_annots(mr, &annots);
    if (r) goto done;

    mbname = mbname_from_intname(mailbox_name(mailbox));
    mbname_set_boxes(mbname, NULL);
    userid = mbname_userid(mbname);
    authstate = auth_newstate(userid);

    /* Fetch flags */
    r = msgrecord_extract_flags(mr, userid, &flags);
    if (r) goto done;

    /* Add \snoozed pseudo-flag */
    strarray_add(flags, "\\snoozed");

    /* (Un)set any client-supplied flags */
    keywords = json_object_get(snoozed, "setKeywords");
    if (keywords) {
        const char *key;
        json_t *val;

        json_object_foreach(keywords, key, val) {
            const char *flag = jmap_keyword_to_imap(key);
            if (flag) {
                if (json_is_true(val)) strarray_add_case(flags, flag);
                else strarray_remove_all_case(flags, flag);
            }
        }
    }

    /* Determine destination mailbox of awakened email */
    destmboxid = json_object_get(snoozed, "moveToMailboxId");
    if (destmboxid) {
        destname = mboxlist_find_uniqueid(json_string_value(destmboxid),
                                          userid, authstate);
    }
    if (!destname) {
        destname = xstrdup(mbname_intname(mbname));
    }

    /* Fetch message filename */
    const char *fname;
    r = msgrecord_get_fname(mr, &fname);
    if (r) goto done;

    /* Prepare to stage the message */
    if (!(f = append_newstage_full(destname, runtime, 0, &stage, fname))) {
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
                          ACL_INSERT, NULL, NULL, 0, EVENT_MESSAGE_NEW);
    if (r) goto done;

    /* Extract until and use it as savedate */
    time_t savedate;
    time_from_iso8601(json_string_value(json_object_get(snoozed, "until")),
                      &savedate);

    /* Append the message to the mailbox */
    r = append_fromstage_full(&as, &body, stage, record->internaldate,
                              savedate, 0, flags, 0, &annots);
    if (r) {
        append_abort(&as);
        goto done;
    }

    r = append_commit(&as);
    if (r) goto done;

    /* Expunge the resource from the \Snoozed mailbox (also unset \snoozed) */
    record->internal_flags |= FLAG_INTERNAL_EXPUNGED;
    record->internal_flags &= ~FLAG_INTERNAL_SNOOZED;
    r = mailbox_rewrite_index_record(mailbox, record);
    if (r) {
        syslog(LOG_ERR, "expunging record (%s:%u) failed: %s",
               mailbox_name(mailbox), record->uid, error_message(r));
    }

  done:
    if (r) {
        syslog(LOG_ERR, "IOERROR: failed to unsnooze %s:%u (%s)",
               mailbox_name(mailbox), record->uid, error_message(r));
        update_alarmdb(mailbox_name(mailbox), record->uid, runtime + 300); // try again in 5 minutes
    }

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
    if (snoozed) json_decref(snoozed);
    buf_free(&buf);
    free(destname);

    return r;
}
#endif /* WITH_JMAP */

static void process_one_record(struct caldav_alarm_data *data, time_t runtime, int dryrun)
{
    int r;
    struct mailbox *mailbox = NULL;

    syslog(LOG_DEBUG, "processing alarms for mailbox %s uid %u",
           data->mboxname, data->imap_uid);

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
        update_alarmdb(data->mboxname, data->imap_uid, runtime + 300);
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
        update_alarmdb(data->mboxname, data->imap_uid, runtime + 300);
        goto done;
    }

    if (record.internal_flags & FLAG_INTERNAL_EXPUNGED) {
        syslog(LOG_NOTICE, "already expunged mailbox %s uid %u",
               data->mboxname, data->imap_uid);
        /* no longer exists?  nothing to do */
        caldav_alarm_delete_record(data->mboxname, data->imap_uid);
        goto done;
    }

    if (mbtype_isa(mailbox_mbtype(mailbox)) == MBTYPE_CALENDAR) {
        icaltimezone *floatingtz = get_floatingtz(mailbox_name(mailbox), "");
        r = process_valarms(mailbox, &record, floatingtz, runtime, dryrun);
        if (floatingtz) icaltimezone_free(floatingtz, 1);
    }
#ifdef WITH_JMAP
    else if (mbtype_isa(mailbox_mbtype(mailbox)) == MBTYPE_JMAPSUBMIT) {
        if (record.internaldate > runtime || dryrun) {
            update_alarmdb(data->mboxname, data->imap_uid, record.internaldate);
            goto done;
        }
        r = process_futurerelease(mailbox, &record);
    }
    else if (mailbox->i.options & OPT_IMAP_HAS_ALARMS) {
        /* XXX  Check special-use flag on mailbox */
        r = process_snoozed(mailbox, &record, runtime, dryrun);
    }
#endif
    else {
        /* XXX  Should never get here */
        syslog(LOG_ERR, "Unknown/unsupported alarm triggered for"
               " mailbox %s uid %u of type %d with options 0x%02x",
               data->mboxname, data->imap_uid,
               mailbox_mbtype(mailbox), mailbox->i.options);
        caldav_alarm_delete_record(data->mboxname, data->imap_uid);
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
                if (has_alarms(ical, mailbox, record->uid)) {
                    char *userid = mboxname_to_userid(mailbox_name(mailbox));
                    time_t nextcheck = process_alarms(mailbox_name(mailbox), record->uid,
                                                      userid, floatingtz, ical,
                                                      runtime, runtime, /*dryrun*/1);
                    free(userid);

                    update_alarmdb(mailbox_name(mailbox), record->uid, nextcheck);
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
