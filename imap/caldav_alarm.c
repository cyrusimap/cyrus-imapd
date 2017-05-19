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

#include <syslog.h>
#include <string.h>

#include <libical/ical.h>

#include "caldav_alarm.h"
#include "cyrusdb.h"
#include "exitcodes.h"
#include "httpd.h"
#include "http_dav.h"
#include "ical_support.h"
#include "libconfig.h"
#include "mboxevent.h"
#include "mboxname.h"
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
    const char *mboxname;
    uint32_t imap_uid;  // for logging
    icaltimezone *floatingtz;
    time_t last;
    time_t now;
    time_t nextcheck;
};

static struct namespace caldav_alarm_namespace;

EXPORTED int caldav_alarm_init(void)
{
    int r;

    /* Set namespace -- force standard (internal) */
    if ((r = mboxname_init_namespace(&caldav_alarm_namespace, 1))) {
        syslog(LOG_ERR, "%s", error_message(r));
        fatal(error_message(r), EC_CONFIG);
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
    my_alarmdb = sqldb_open(dbfilename, CMD_CREATE, DBVERSION, upgrade);

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

/*
 * Extract data from the given ical object
 */
static int send_alarm(struct get_alarm_rock *rock,
                      icalcomponent *comp, icalcomponent *alarm,
                      icaltimetype start, icaltimetype end, icaltimetype alarmtime)
{
    char *userid = mboxname_to_userid(rock->mboxname);
    struct buf calname = BUF_INITIALIZER;

    /* get the display name annotation */
    const char *displayname_annot = DAV_ANNOT_NS "<" XML_NS_DAV ">displayname";
    annotatemore_lookupmask(rock->mboxname, displayname_annot, userid, &calname);
    if (!calname.len) buf_setcstr(&calname, strrchr(rock->mboxname, '.') + 1);

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
    FILL_STRING_PARAM(event, EVENT_CALENDAR_CALENDAR_NAME, buf_release(&calname));

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
        timezone = icaltime_get_tzid(start);
    else if (rock->floatingtz)
        timezone = icaltimezone_get_tzid(rock->floatingtz);
    else
        timezone = "[floating]";
    FILL_STRING_PARAM(event, EVENT_CALENDAR_TIMEZONE,
                      xstrdup(timezone));
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

        const char *partstat = icalproperty_get_parameter_as_string(prop, "PARTSTAT");
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
    free(userid);

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
            icalparameter *param = icalproperty_get_first_parameter(prop, ICAL_RELATED_PARAMETER);
            icaltimetype base = icaltime_null_time();
            if (param && icalparameter_get_related(param) == ICAL_RELATED_END) {
                base = end;
            }
            else {
                base = start;
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

        if (check <= data->now) {
            prop = icalcomponent_get_first_property(comp, ICAL_SUMMARY_PROPERTY);
            const char *summary = prop ? icalproperty_get_value_as_string(prop) : "[no summary]";
            int age = data->now - check;
            if (age > 7200) { // more than 2 hours stale?  Just log it
                syslog(LOG_ERR, "suppressing alarm aged %d seconds at %s for %s %u - %s(%d) %s",
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

        /* alarms can't be more than a week either side of the event start, so if we're
         * past 2 months, then just check again in a month */
        if (check > data->now + 86400*60) {
            time_t next = data->now + 86400*30;
            if (!data->nextcheck || next < data->nextcheck)
                data->nextcheck = next;
            return 0;
        }
    }

    return 1; /* keep going */
}

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

static int update_alarmdb(const char *mboxname, uint32_t imap_uid, time_t nextcheck)
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

    if (nextcheck)
        rc = sqldb_exec(alarmdb, CMD_REPLACE, bval, NULL, NULL);
    else
        rc = sqldb_exec(alarmdb, CMD_DELETE, bval, NULL, NULL);

    caldav_alarm_close(alarmdb);

    if (rc == SQLITE_OK) return 0;

    /* failed? */
    return -1;
}

static icaltimezone *get_floatingtz(struct mailbox *mailbox)
{
    icaltimezone *floatingtz = NULL;

    struct buf buf = BUF_INITIALIZER;
    const char *annotname = DAV_ANNOT_NS "<" XML_NS_CALDAV ">calendar-timezone";
    if (!annotatemore_lookup(mailbox->name, annotname, /*userid*/"", &buf)) {
        icalcomponent *comp = NULL;
        comp = icalparser_parse_string(buf_cstring(&buf));
        icalcomponent *subcomp = icalcomponent_get_first_component(comp, ICAL_VTIMEZONE_COMPONENT);
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

static int has_alarms(icalcomponent *ical)
{
    icalcomponent *comp = icalcomponent_get_first_real_component(ical);
    icalcomponent_kind kind = icalcomponent_isa(comp);
    for (; comp; comp = icalcomponent_get_next_component(ical, kind)) {
        if (icalcomponent_get_first_component(comp, ICAL_VALARM_COMPONENT))
            return 1;
    }
    return 0;
}

static time_t process_alarms(const char *mboxname, uint32_t imap_uid, icaltimezone *floatingtz,
                             icalcomponent *ical, time_t lastrun, time_t runtime)
{
    /* we don't send alarms for anything except VEVENTS */
    icalcomponent *comp = icalcomponent_get_first_real_component(ical);
    icalcomponent_kind kind = icalcomponent_isa(comp);
    if (kind != ICAL_VEVENT_COMPONENT)
        return 0;

    struct get_alarm_rock rock = { mboxname, imap_uid, floatingtz, lastrun, runtime, 0 };
    struct icalperiodtype range = icalperiodtype_null_period();
    icalcomponent_myforeach(ical, range, floatingtz, process_alarm_cb, &rock);
    return rock.nextcheck;
}

struct lastalarm_data {
    time_t lastrun;
    time_t nextcheck;
};

static int read_lastalarm(struct mailbox *mailbox, const struct index_record *record,
                          struct lastalarm_data *data)
{
    int r = IMAP_NOTFOUND;
    memset(data, 0, sizeof(struct lastalarm_data));

    const char *annotname = DAV_ANNOT_NS "lastalarm";
    struct buf annot_buf = BUF_INITIALIZER;
    annotatemore_msg_lookup(mailbox->name, record->uid, annotname, "", &annot_buf);

    if (annot_buf.len) {
        char *base = (char *)buf_cstring(&annot_buf);
        data->lastrun = strtoul(base, &base, 10);
        if (*base == ' ') base++;
        data->nextcheck = strtoul(base, &base, 10);
        r = 0;
    }

    buf_free(&annot_buf);
    return r;
}

/* add a calendar alarm */
EXPORTED int caldav_alarm_add_record(struct mailbox *mailbox, const struct index_record *record,
                                     icalcomponent *ical)
{
    if (!has_alarms(ical)) return 0;
    // we need to skip silent records (replication) because the lastalarm annotation won't be
    // set yet, so it will all break :(  Instead, we have an explicit touch on the record which
    // is done after the annotations are written, and processes the alarms if needed then, and
    // regardless will always update the alarmdb
    if (record->silent) return 0;
    int rc = 0;

    /* XXX - we COULD cache this in the mailbox object so it doesn't get read multiple times,
     * but this is really rare - only dav_reconstruct maybe */
    icaltimezone *floatingtz = get_floatingtz(mailbox);

    struct lastalarm_data data;
    if (read_lastalarm(mailbox, record, &data))
        data.lastrun = record->internaldate;
    data.nextcheck = process_alarms(mailbox->name, record->uid, floatingtz,
                                    ical, data.lastrun, data.lastrun);
    rc = update_alarmdb(mailbox->name, record->uid, data.nextcheck);

    if (floatingtz) icaltimezone_free(floatingtz, 1);

    return rc;
}

EXPORTED int caldav_alarm_touch_record(struct mailbox *mailbox, const struct index_record *record)
{
    struct lastalarm_data data;
    if (!read_lastalarm(mailbox, record, &data))
        return update_alarmdb(mailbox->name, record->uid, data.nextcheck);
    return 0;
}

/* delete all alarms matching the event */
EXPORTED int caldav_alarm_delete_record(const char *mboxname, uint32_t imap_uid)
{
    return update_alarmdb(mboxname, imap_uid, 0);
}

#define CMD_DELETEMAILBOX       \
    "DELETE FROM events WHERE"  \
    " mboxname = :mboxname"     \
    ";"

/* delete all alarms matching the event */
EXPORTED int caldav_alarm_delete_mailbox(const char *mboxname)
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

#define CMD_DELETEUSER          \
    "DELETE FROM events WHERE"  \
    " mboxname LIKE :prefix"     \
    ";"

/* delete all alarms matching the event */
EXPORTED int caldav_alarm_delete_user(const char *userid)
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

#define CMD_SELECT_ALARMS                                                \
    "SELECT mboxname, imap_uid, nextcheck"                               \
    " FROM events WHERE"                                                 \
    " nextcheck < :before"                                               \
    " ORDER BY mboxname, imap_uid"                                       \
    ";"

static int alarm_read_cb(sqlite3_stmt *stmt, void *rock)
{
    ptrarray_t *target = (ptrarray_t *)rock;

    struct caldav_alarm_data *data = xzmalloc(sizeof(struct caldav_alarm_data));

    data->mboxname    = xstrdup((const char *) sqlite3_column_text(stmt, 0));
    data->imap_uid    = sqlite3_column_int(stmt, 1);
    data->nextcheck   = sqlite3_column_int(stmt, 2);

    ptrarray_append(target, data);

    return 0;
}

static void process_one_record(struct mailbox *mailbox, uint32_t imap_uid,
                               icaltimezone *floatingtz, time_t runtime)
{
    int rc;
    icalcomponent *ical = NULL;
    struct buf msg_buf = BUF_INITIALIZER;

    syslog(LOG_DEBUG, "processing alarms for mailbox %s uid %u",
           mailbox->name, imap_uid);

    struct index_record record;
    memset(&record, 0, sizeof(struct index_record));
    rc = mailbox_find_index_record(mailbox, imap_uid, &record);
    if (rc == IMAP_NOTFOUND) {
        /* no record, no worries */
        goto done_item;
    }
    if (rc) {
        /* XXX no index record? item deleted or transient error? */
        goto done_item;
    }
    if (record.system_flags & FLAG_EXPUNGED) {
        /* no longer exists?  nothing to do */
        goto done_item;
    }

    rc = mailbox_map_record(mailbox, &record, &msg_buf);
    if (rc) {
        /* XXX no message? index is wrong? yikes */
        goto done_item;
    }

    ical = icalparser_parse_string(buf_cstring(&msg_buf) + record.header_size);

    if (!ical) {
        /* XXX log error */
        goto done_item;
    }

    struct lastalarm_data data;
    if (read_lastalarm(mailbox, &record, &data))
        data.lastrun = record.internaldate;

    if (runtime > data.nextcheck)
        data.nextcheck = process_alarms(mailbox->name, record.uid, floatingtz, ical, data.lastrun, runtime);

    struct buf annot_buf = BUF_INITIALIZER;
    buf_printf(&annot_buf, "%ld %ld", runtime, data.nextcheck);
    const char *annotname = DAV_ANNOT_NS "lastalarm";
    mailbox_annotation_write(mailbox, record.uid, annotname, "", &annot_buf);
    buf_free(&annot_buf);

done_item:
    buf_free(&msg_buf);
    if (ical) icalcomponent_free(ical);
}

static void process_records(ptrarray_t *list, time_t runtime)
{
    struct mailbox *mailbox = NULL;
    int rc;
    int i;
    icaltimezone *floatingtz = NULL;

    for (i = 0; i < list->count; i++) {
        struct caldav_alarm_data *data = ptrarray_nth(list, i);

        if (mailbox && !strcmp(mailbox->name, data->mboxname)) {
            /* woot, reuse mailbox */
        }
        else {
            if (floatingtz) icaltimezone_free(floatingtz, 1);
            floatingtz = NULL;
            mailbox_close(&mailbox);
            rc = mailbox_open_iwl(data->mboxname, &mailbox);
            if (rc == IMAP_MAILBOX_NONEXISTENT) {
                /* mailbox was deleted or something, nothing we can do */
                data->nextcheck = 0;
                continue;
            }
            if (rc) {
                /* transient open error, don't delete this alarm */
                continue;
            }
            floatingtz = get_floatingtz(mailbox);
        }
        process_one_record(mailbox, data->imap_uid, floatingtz, runtime);
    }

    if (floatingtz) icaltimezone_free(floatingtz, 1);
    mailbox_close(&mailbox);
}

/* process alarms with triggers before a given time */
EXPORTED int caldav_alarm_process(time_t runtime)
{
    syslog(LOG_DEBUG, "processing alarms");

    if (!runtime) {
        /* check 10s into the future - we run every 10, so that guarantees we will
         * deliver on or before the target time */
        runtime = time(NULL) + 10;
    }

    struct sqldb_bindval bval[] = {
        { ":before",    SQLITE_INTEGER, { .i = runtime  } },
        { NULL,         SQLITE_NULL,    { .s = NULL     } }
    };

    sqldb_t *alarmdb = caldav_alarm_open();
    if (!alarmdb)
        return HTTP_SERVER_ERROR;

    ptrarray_t list = PTRARRAY_INITIALIZER;

    int rc = sqldb_exec(alarmdb, CMD_SELECT_ALARMS, bval, &alarm_read_cb, &list);

    caldav_alarm_close(alarmdb);

    process_records(&list, runtime);

    int i;
    for (i = 0; i < list.count; i++) {
        struct caldav_alarm_data *data = ptrarray_nth(&list, i);
        caldav_alarm_fini(data);
        free(data);
    }
    ptrarray_fini(&list);

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
    const char *annotname = DAV_ANNOT_NS "lastalarm";
    struct buf annot_buf = BUF_INITIALIZER;

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

        icaltimezone *floatingtz = get_floatingtz(mailbox);

        /* add alarms for all records */
        struct mailbox_iter *iter = mailbox_iter_init(mailbox, 0, ITER_SKIP_EXPUNGED);
        const message_t *msg;
        while ((msg = mailbox_iter_step(iter))) {
            const struct index_record *record = msg_record(msg);
            struct buf msg_buf = BUF_INITIALIZER;
            rc = mailbox_map_record(mailbox, record, &msg_buf);
            if (rc) continue;
            icalcomponent *ical = icalparser_parse_string(buf_cstring(&msg_buf) + record->header_size);
            if (ical) {
                if (has_alarms(ical)) {
                    time_t nextcheck = process_alarms(mailbox->name, record->uid, floatingtz, ical, runtime, runtime);
                    buf_reset(&annot_buf);
                    buf_printf(&annot_buf, "%ld %ld", runtime, nextcheck);
                    mailbox_annotation_write(mailbox, record->uid, annotname, "", &annot_buf);
                }
                icalcomponent_free(ical);
            }
            buf_free(&msg_buf);
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

    buf_free(&annot_buf);

    return rc;
}
