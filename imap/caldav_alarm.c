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
#include "imap_err.h"
#include "http_err.h"
#include "libconfig.h"
#include "mboxname.h"
#include "util.h"
#include "xstrlcat.h"
#include "xmalloc.h"

enum {
    STMT_BEGIN,
    STMT_COMMIT,
    STMT_ROLLBACK,
    STMT_INSERT_ALARM,
    STMT_INSERT_RECIPIENT,
    STMT_DELETE,
    STMT_DELETEALL,
    STMT_DELETEMAILBOX,
    STMT_DELETEUSER,
    STMT_SELECT_ALARM,
    STMT_SELECT_RECIPIENT
};

#define NUM_STMT 11

struct caldav_alarm_db {
    sqlite3	    *db;
    int		    refcount;
    sqlite3_stmt    *stmt[NUM_STMT];
    int		    in_transaction;
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

    /* XXX initializes sqlite, but we're not really supposed to know that */
    return dav_init();
}


EXPORTED int caldav_alarm_done(void)
{
    /* XXX shuts down sqlite, but we're not really supposed to know that */
    return dav_done();
}


#define CMD_DROP "DROP TABLE IF EXISTS alarms;"

#define CMD_CREATE					\
    "CREATE TABLE IF NOT EXISTS alarms ("		\
    " rowid INTEGER PRIMARY KEY AUTOINCREMENT,"		\
    " mailbox TEXT NOT NULL,"				\
    " resource TEXT NOT NULL,"				\
    " action INTEGER NOT NULL,"				\
    " nextalarm TEXT NOT NULL,"				\
    " tzid TEXT NOT NULL,"				\
    " start TEXT NOT NULL,"				\
    " end TEXT NOT NULL"				\
    ");"						\
    "CREATE TABLE IF NOT EXISTS alarm_recipients ("	\
    " rowid INTEGER PRIMARY KEY AUTOINCREMENT,"		\
    " alarmid INTEGER NOT NULL,"			\
    " email TEXT NOT NULL,"				\
    " FOREIGN KEY (alarmid) REFERENCES alarms (rowid) ON DELETE CASCADE" \
    ");"						\
    "CREATE INDEX IF NOT EXISTS idx_alarm_id ON alarm_recipients ( alarmid );"

static struct caldav_alarm_db *my_alarmdb = NULL;

/* get a database handle to the alarm db */
EXPORTED struct caldav_alarm_db *caldav_alarm_open()
{
    if (my_alarmdb) {
	my_alarmdb->refcount++;
	return my_alarmdb;
    }

    sqlite3 *db;
    const char *cmds = CMD_CREATE;

    char *dbfilename = strconcat(config_dir, "/caldav_alarm.sqlite3", NULL);

    int rc = sqlite3_open(dbfilename, &db);
    if (rc != SQLITE_OK) {
	syslog(LOG_ERR, "IOERROR: caldav_alarm_open (open): %s", db ? sqlite3_errmsg(db) : "failed");
	sqlite3_close(db);
	free(dbfilename);
	return NULL;
    }

    free(dbfilename);

    rc = sqlite3_exec(db, "PRAGMA foreign_keys = ON;", NULL, NULL, NULL);
    if (rc) goto fail;

    if (cmds) {
	rc = sqlite3_exec(db, cmds, NULL, NULL, NULL);
	if (rc) goto fail;
    }

    my_alarmdb = xzmalloc(sizeof(struct caldav_alarm_db));
    my_alarmdb->db = db;
    my_alarmdb->refcount = 1;
    my_alarmdb->in_transaction = 0;

    return my_alarmdb;

fail:
    syslog(LOG_ERR, "IOERROR: caldav_alarm_open (exec): %s", sqlite3_errmsg(db));
    sqlite3_close(db);
    return NULL;
}

/* close this handle */
EXPORTED int caldav_alarm_close(struct caldav_alarm_db *alarmdb)
{
    assert(my_alarmdb == alarmdb);

    if (--(my_alarmdb->refcount)) return 0;

    int i;
    for (i = 0; i < NUM_STMT; i++) {
	sqlite3_stmt *stmt = my_alarmdb->stmt[i];
	if (stmt) sqlite3_finalize(stmt);
    }

    sqlite3_close(my_alarmdb->db);

    free(my_alarmdb);
    my_alarmdb = NULL;

    return 0;
}

#define CMD_BEGIN "BEGIN TRANSACTION;"

EXPORTED int caldav_alarm_begin(struct caldav_alarm_db *alarmdb)
{
    int rc = dav_exec(alarmdb->db, CMD_BEGIN, NULL, NULL, NULL,
		      &alarmdb->stmt[STMT_BEGIN]);
    if (rc) return rc;
    alarmdb->in_transaction = 1;
    return 0;
}


#define CMD_COMMIT "COMMIT TRANSACTION;"

EXPORTED int caldav_alarm_commit(struct caldav_alarm_db *alarmdb)
{
    int rc = dav_exec(alarmdb->db, CMD_COMMIT, NULL, NULL, NULL,
		      &alarmdb->stmt[STMT_COMMIT]);
    if (rc) return rc;
    alarmdb->in_transaction = 0;
    return 0;
}


#define CMD_ROLLBACK "ROLLBACK TRANSACTION;"

EXPORTED int caldav_alarm_rollback(struct caldav_alarm_db *alarmdb)
{
    int rc = dav_exec(alarmdb->db, CMD_ROLLBACK, NULL, NULL, NULL,
		      &alarmdb->stmt[STMT_ROLLBACK]);
    if (rc) return rc;
    alarmdb->in_transaction = 0;
    return 0;
}

#define CMD_INSERT_ALARM							\
    "INSERT INTO alarms"							\
    " ( mailbox, resource, action, nextalarm, tzid, start, end )"		\
    " VALUES"									\
    " ( :mailbox, :resource, :action, :nextalarm, :tzid, :start, :end )"	\
    ";"

#define CMD_INSERT_RECIPIENT		\
    "INSERT INTO alarm_recipients"	\
    " ( alarmid, email )"		\
    " VALUES"				\
    " ( :alarmid, :email )"		\
    ";"

/* add a calendar alarm */
EXPORTED int caldav_alarm_add(struct caldav_alarm_db *alarmdb, struct caldav_alarm_data *alarmdata)
{
    assert(alarmdb);
    assert(alarmdata);

    struct bind_val bval[] = {
	{ ":mailbox",	SQLITE_TEXT,	{ .s = alarmdata->mailbox				} },
	{ ":resource",	SQLITE_TEXT,	{ .s = alarmdata->resource				} },
	{ ":action",	SQLITE_INTEGER,	{ .i = alarmdata->action				} },
	{ ":nextalarm",	SQLITE_TEXT,	{ .s = icaltime_as_ical_string(alarmdata->nextalarm)	} },
	{ ":tzid",	SQLITE_TEXT,	{ .s = alarmdata->tzid					} },
	{ ":start",	SQLITE_TEXT,	{ .s = icaltime_as_ical_string(alarmdata->start)	} },
	{ ":end",	SQLITE_TEXT,	{ .s = icaltime_as_ical_string(alarmdata->end)		} },
	{ NULL,		SQLITE_NULL,	{ .s = NULL						} }
    };

    int in_transaction = 0;
    int rc = 0;

    if (!alarmdb->in_transaction) {
	rc = caldav_alarm_begin(alarmdb);
	if (rc)
	    return rc;
	in_transaction = 1;
    }

    /* XXX deal with SQLITE_FULL */
    rc = dav_exec(alarmdb->db, CMD_INSERT_ALARM, bval, NULL, NULL, &alarmdb->stmt[STMT_INSERT_ALARM]);
    if (rc) {
	if (in_transaction)
	    caldav_alarm_rollback(alarmdb);
	return rc;
    }

    alarmdata->rowid = sqlite3_last_insert_rowid(alarmdb->db);

    int i;
    for (i = 0; i < strarray_size(&alarmdata->recipients); i++) {
	const char *email = strarray_nth(&alarmdata->recipients, i);

	struct bind_val rbval[] = {
	    { ":alarmid",   SQLITE_INTEGER, { .i = alarmdata->rowid	} },
	    { ":email",	    SQLITE_TEXT,    { .s = email		} },
	    { NULL,	    SQLITE_NULL,    { .s = NULL			} }
	};

	rc = dav_exec(alarmdb->db, CMD_INSERT_RECIPIENT, rbval, NULL, NULL, &alarmdb->stmt[STMT_INSERT_RECIPIENT]);
	if (rc) {
	    if (in_transaction)
		caldav_alarm_rollback(alarmdb);
	    return rc;
	}
    }

    if (in_transaction)
	return caldav_alarm_commit(alarmdb);

    return 0;
}

#define CMD_DELETE		\
    "DELETE FROM alarms WHERE"	\
    " rowid = :rowid"		\
    ";"

/* delete a single alarm */
static int caldav_alarm_delete_row(struct caldav_alarm_db *alarmdb, struct caldav_alarm_data *alarmdata)
{
    assert(alarmdb);
    assert(alarmdata);

    struct bind_val bval[] = {
	{ ":rowid", SQLITE_INTEGER, { .i = alarmdata->rowid } },
	{ NULL,	    SQLITE_NULL,    { .s = NULL		    } }
    };

    return dav_exec(alarmdb->db, CMD_DELETE, bval, NULL, NULL, &alarmdb->stmt[STMT_DELETE]);
}

#define CMD_DELETEALL		\
    "DELETE FROM alarms WHERE"	\
    " mailbox = :mailbox AND"	\
    " resource = :resource"	\
    ";"

/* delete all alarms matching the event */
EXPORTED int caldav_alarm_delete_all(struct caldav_alarm_db *alarmdb, struct caldav_alarm_data *alarmdata)
{
    assert(alarmdb);
    assert(alarmdata);

    struct bind_val bval[] = {
	{ ":mailbox",	SQLITE_TEXT, { .s = alarmdata->mailbox  } },
	{ ":resource",	SQLITE_TEXT, { .s = alarmdata->resource } },
	{ NULL,		SQLITE_NULL, { .s = NULL		} }
    };

    return dav_exec(alarmdb->db, CMD_DELETEALL, bval, NULL, NULL, &alarmdb->stmt[STMT_DELETEALL]);
}

#define CMD_DELETEMAILBOX		\
    "DELETE FROM alarms WHERE"	\
    " mailbox = :mailbox"	\
    ";"

/* delete all alarms matching the event */
EXPORTED int caldav_alarm_delmbox(struct caldav_alarm_db *alarmdb, const char *mboxname)
{
    assert(alarmdb);

    struct bind_val bval[] = {
	{ ":mailbox",	SQLITE_TEXT, { .s = mboxname  } },
	{ NULL,		SQLITE_NULL, { .s = NULL	} }
    };

    return dav_exec(alarmdb->db, CMD_DELETEMAILBOX, bval, NULL, NULL, &alarmdb->stmt[STMT_DELETEMAILBOX]);
}

#define CMD_DELETEUSER		\
    "DELETE FROM alarms WHERE"	\
    " mailbox LIKE :prefix"	\
    ";"

/* delete all alarms matching the event */
EXPORTED int caldav_alarm_delete_user(struct caldav_alarm_db *alarmdb, const char *userid)
{
    assert(alarmdb);
    char mailboxname[MAX_MAILBOX_NAME];
    struct mboxname_parts parts;

    mboxname_userid_to_parts(userid, &parts);

    mboxname_parts_to_internal(&parts, mailboxname);
    size_t len = strlen(mailboxname);
    if (len + 3 > MAX_MAILBOX_NAME) return IMAP_INTERNAL;
    mailboxname[len] = '.';
    mailboxname[len+1] = '%';
    mailboxname[len+2] = '\0';

    struct bind_val bval[] = {
	{ ":prefix",	SQLITE_TEXT, { .s = mailboxname  } },
	{ NULL,		SQLITE_NULL, { .s = NULL		} }
    };

    return dav_exec(alarmdb->db, CMD_DELETEUSER, bval, NULL, NULL, &alarmdb->stmt[STMT_DELETEUSER]);
}

enum trigger_type {
    TRIGGER_RELATIVE_START,
    TRIGGER_RELATIVE_END,
    TRIGGER_ABSOLUTE
};
struct trigger_data {
    icalcomponent		*alarm;
    struct icaltriggertype	trigger;
    enum trigger_type		type;
    enum caldav_alarm_action	action;
};

struct recur_cb_data {
    struct trigger_data		*triggerdata;
    int				ntriggers;
    struct icaltimetype		now;
    icalcomponent		*nextalarm;
    enum caldav_alarm_action	nextaction;
    struct icaltimetype		nextalarmtime;
    struct icaltimetype		eventstart;
    struct icaltimetype		eventend;
};

/* icalcomponent_foreach_recurrence() callback to find closest future event */
static void recur_cb(icalcomponent *comp, struct icaltime_span *span, void *rock)
{
    struct recur_cb_data *rdata = (struct recur_cb_data *) rock;
    int is_date = icaltime_is_date(icalcomponent_get_dtstart(comp));
    icaltimezone *utc = icaltimezone_get_utc_timezone();
    struct icaltimetype start =
	icaltime_from_timet_with_zone(span->start, is_date, utc);
    struct icaltimetype end =
	icaltime_from_timet_with_zone(span->end, is_date, utc);

    int i;
    for (i = 0; i < rdata->ntriggers; i++) {
	struct trigger_data *tdata = &(rdata->triggerdata[i]);

	struct icaltimetype alarmtime;
	switch (tdata->type) {
	    case TRIGGER_RELATIVE_START:
		alarmtime = icaltime_add(start, tdata->trigger.duration);
		break;
	    case TRIGGER_RELATIVE_END:
		alarmtime = icaltime_add(end, tdata->trigger.duration);
		break;
	    case TRIGGER_ABSOLUTE:
		alarmtime = tdata->trigger.time;
		break;
	    default:
		/* doesn't happen */
		continue;
	}

	if (icaltime_compare(alarmtime, rdata->now) > 0 &&
	    (!rdata->nextalarm ||
	     icaltime_compare(alarmtime, rdata->nextalarmtime) < 0)) {

	    rdata->nextalarm = tdata->alarm;

	    rdata->nextaction = tdata->action;

	    memcpy(&(rdata->nextalarmtime), &alarmtime, sizeof(struct icaltimetype));

	    memcpy(&(rdata->eventstart), &start, sizeof(struct icaltimetype));
	    memcpy(&(rdata->eventend), &end, sizeof(struct icaltimetype));
	}
    }
}

/* fill alarmdata with data for next alarm for given entry */
EXPORTED int caldav_alarm_prepare(
	icalcomponent *ical, struct caldav_alarm_data *alarmdata,
	enum caldav_alarm_action wantaction, icaltimetype after)
{
    assert(ical);
    assert(alarmdata);

    icalcomponent *comp = icalcomponent_get_first_real_component(ical);

    /* if there's no VALARM on this item then we have nothing to do */
    int nalarms = icalcomponent_count_components(comp, ICAL_VALARM_COMPONENT);
    if (nalarms == 0)
	return 1;

    int ntriggers = 0;
    struct trigger_data *triggerdata =
	(struct trigger_data *) xmalloc(sizeof(struct trigger_data) * nalarms);

    icalcomponent *alarm;
    for ( alarm = icalcomponent_get_first_component(comp, ICAL_VALARM_COMPONENT);
	  alarm;
	  alarm = icalcomponent_get_next_component(comp, ICAL_VALARM_COMPONENT)) {

	icalproperty *prop;
	icalvalue *val;

	prop = icalcomponent_get_first_property(alarm, ICAL_ACTION_PROPERTY);
	if (!prop)
	    /* no action, invalid alarm, skip */
	    continue;

	val = icalproperty_get_value(prop);
	enum icalproperty_action action = icalvalue_get_action(val);
	if (!(action == ICAL_ACTION_DISPLAY || action == ICAL_ACTION_EMAIL))
	    /* we only want DISPLAY and EMAIL, skip */
	    continue;

	if (
	    (wantaction == CALDAV_ALARM_ACTION_DISPLAY && action != ICAL_ACTION_DISPLAY) ||
	    (wantaction == CALDAV_ALARM_ACTION_EMAIL   && action != ICAL_ACTION_EMAIL)
	)
	    /* specific action was requested and this doesn't match, skip */
	    continue;

	prop = icalcomponent_get_first_property(alarm, ICAL_TRIGGER_PROPERTY);
	if (!prop)
	    /* no trigger, invalid alarm, skip */
	    continue;

	val = icalproperty_get_value(prop);

	struct trigger_data *tdata = &(triggerdata[ntriggers]);

	tdata->alarm = alarm;
	tdata->action =
	    action ==
		ICAL_ACTION_DISPLAY	? CALDAV_ALARM_ACTION_DISPLAY	:
		ICAL_ACTION_EMAIL	? CALDAV_ALARM_ACTION_EMAIL	:
					  CALDAV_ALARM_ACTION_NONE;

	struct icaltriggertype trigger = icalvalue_get_trigger(val);
	/* XXX validate trigger */
	memcpy(&(tdata->trigger), &trigger, sizeof(struct icaltriggertype));

	if (icalvalue_isa(val) == ICAL_DURATION_VALUE) {
	    icalparameter *param = icalproperty_get_first_parameter(prop, ICAL_RELATED_PARAMETER);
	    if (param && icalparameter_get_related(param) == ICAL_RELATED_END)
		tdata->type = TRIGGER_RELATIVE_END;
	    else
		tdata->type = TRIGGER_RELATIVE_START;
	}
	else
	    tdata->type = TRIGGER_ABSOLUTE;

	ntriggers++;
	assert(ntriggers <= nalarms);
    }

    icaltimezone *utc = icaltimezone_get_utc_timezone();

    struct recur_cb_data rdata = {
	.triggerdata	= triggerdata,
	.ntriggers	= ntriggers,
	.now		= after,
	.nextalarm	= NULL,
	.nextalarmtime	= icaltime_null_time(),
	.eventstart	= icaltime_null_time(),
	.eventend	= icaltime_null_time()
    };

    /* See if its a recurring event */
    if (icalcomponent_get_first_property(comp, ICAL_RRULE_PROPERTY) ||
	icalcomponent_get_first_property(comp, ICAL_RDATE_PROPERTY) ||
	icalcomponent_get_first_property(comp, ICAL_EXDATE_PROPERTY)) {

	icalcomponent_foreach_recurrence(
	    comp,
	    rdata.now,
	    icaltime_from_timet_with_zone(INT_MAX, 0, utc),
	    recur_cb,
	    &rdata);

	/* Handle overridden recurrences */
	while ((comp = icalcomponent_get_next_component(comp, ICAL_VEVENT_COMPONENT))) {
	    struct icalperiodtype period;
	    caldav_get_period(comp, ICAL_VEVENT_COMPONENT, &period);
	    icaltime_span span = icaltime_span_new(period.start, period.end, 0);
	    recur_cb(comp, &span, &rdata);
	}
    }

    else {
	/* not recurring, use dtstart/dtend instead */
	struct icalperiodtype period;
	caldav_get_period(comp, ICAL_VEVENT_COMPONENT, &period);
	icaltime_span span = icaltime_span_new(period.start, period.end, 0);
	recur_cb(comp, &span, &rdata);
    }

    /* no next alarm, nothing more to do! */
    if (!rdata.nextalarm)
	return 1;

    /* now fill out alarmdata with all the stuff from event/ocurrence/alarm */
    alarmdata->action = rdata.nextaction;

    alarmdata->nextalarm = rdata.nextalarmtime;

    /* dtstart timezone is good enough for alarm purposes */
    icalproperty *prop = NULL;
    icalparameter *param = NULL;
    const char *tzid = NULL;

    prop = icalcomponent_get_first_property(comp, ICAL_DTSTART_PROPERTY);
    if (prop) param = icalproperty_get_first_parameter(prop, ICAL_TZID_PARAMETER);
    if (param) tzid = icalparameter_get_tzid(param);
    alarmdata->tzid = xstrdup(tzid ? tzid : "[floating]");

    memcpy(&(alarmdata->start), &(rdata.eventstart), sizeof(struct icaltimetype));
    memcpy(&(alarmdata->end), &(rdata.eventend), sizeof(struct icaltimetype));

    icalproperty *attendee = icalcomponent_get_first_property(rdata.nextalarm, ICAL_ATTENDEE_PROPERTY);
    while (attendee) {
	const char *email = icalproperty_get_value_as_string(attendee);
	if (email)
	    strarray_append(&alarmdata->recipients, email);
	attendee = icalcomponent_get_next_property(rdata.nextalarm, ICAL_ATTENDEE_PROPERTY);
    }

    return 0;
}

/* clean up alarmdata after prepare */
void caldav_alarm_fini(struct caldav_alarm_data *alarmdata)
{
    free((void *) alarmdata->tzid);
    alarmdata->tzid = NULL;
    strarray_fini(&alarmdata->recipients);
}

#define CMD_SELECT_ALARM							\
    "SELECT rowid, mailbox, resource, action, nextalarm, tzid, start, end"	\
    " FROM alarms WHERE"							\
    " nextalarm <= :before"							\
    ";"

#define CMD_SELECT_RECIPIENT		\
    "SELECT email"			\
    " FROM alarm_recipients WHERE"	\
    " alarmid = :alarmid"		\
    ";"

struct alarmdata_list {
    struct alarmdata_list	*next;
    struct caldav_alarm_data	data;
    int				do_delete;
};

static int alarm_read_cb(sqlite3_stmt *stmt, void *rock)
{
    struct alarmdata_list **list = (struct alarmdata_list **) rock;

    struct alarmdata_list *n = xzmalloc(sizeof(struct alarmdata_list));

    n->data.rowid	= sqlite3_column_int(stmt, 0);
    n->data.mailbox	= xstrdup((const char *) sqlite3_column_text(stmt, 1));
    n->data.resource	= xstrdup((const char *) sqlite3_column_text(stmt, 2));
    n->data.action	= sqlite3_column_int(stmt, 3);
    n->data.nextalarm	= icaltime_from_string((const char *) sqlite3_column_text(stmt, 4));
    n->data.tzid	= xstrdup((const char *) sqlite3_column_text(stmt, 5));
    n->data.start	= icaltime_from_string((const char *) sqlite3_column_text(stmt, 6));
    n->data.end		= icaltime_from_string((const char *) sqlite3_column_text(stmt, 7));

    n->do_delete = 1; // unless something goes wrong, we will delete this alarm

    n->next = *list;
    *list = n;

    return 0;
}

static int recipient_read_cb(sqlite3_stmt *stmt, void *rock)
{
    strarray_t *recipients = (strarray_t *) rock;

    strarray_append(recipients, (const char *) sqlite3_column_text(stmt, 0));

    return 0;
}

/* process alarms with triggers within before a given time */
EXPORTED int caldav_alarm_process()
{
    syslog(LOG_DEBUG, "processing alarms");

    // all alarms in the past and within the next 60 seconds
    icaltimetype before = icaltime_current_time_with_zone(icaltimezone_get_utc_timezone());
    icaltime_adjust(&before, 0, 0, 0, 60);

    struct bind_val bval[] = {
	{ ":before",	SQLITE_TEXT,	{ .s = icaltime_as_ical_string(before)	} },
	{ NULL,		SQLITE_NULL,	{ .s = NULL				} }
    };

    struct alarmdata_list *list = NULL, *scan;

    struct caldav_alarm_db *alarmdb = caldav_alarm_open();
    if (!alarmdb)
	return HTTP_SERVER_ERROR;

    int rc = dav_exec(alarmdb->db, CMD_SELECT_ALARM, bval, &alarm_read_cb, &list,
		  &alarmdb->stmt[STMT_SELECT_ALARM]);
    if (rc)
	goto done;

    for (scan = list; scan; scan = scan->next) {
	struct mailbox *mailbox = NULL;
	char *userid = NULL;
	struct caldav_db *caldavdb = NULL;
	icalcomponent *ical = NULL;
	struct buf msg_buf = BUF_INITIALIZER;
	struct buf calname_buf = BUF_INITIALIZER;
	static const char *displayname_annot = ANNOT_NS "<" XML_NS_DAV ">displayname";

	syslog(LOG_DEBUG,
	       "processing alarm rowid %llu mailbox %s resource %s action %d nextalarm %s tzid %s start %s end %s",
	       scan->data.rowid, scan->data.mailbox,
	       scan->data.resource, scan->data.action,
	       icaltime_as_ical_string(scan->data.nextalarm),
	       scan->data.tzid,
	       icaltime_as_ical_string(scan->data.start),
	       icaltime_as_ical_string(scan->data.end)
	);

	rc = mailbox_open_irl(scan->data.mailbox, &mailbox);
	if (rc == IMAP_MAILBOX_NONEXISTENT)
	    /* mailbox was deleted or something, nothing we can do */
	    continue;
	if (rc) {
	    /* transient open error, don't delete this alarm */
	    scan->do_delete = 0;
	    continue;
	}

	userid = xstrdup(mboxname_to_userid(mailbox->name));

	caldavdb = caldav_open_mailbox(mailbox, 0);
	if (!caldavdb) {
	    /* XXX mailbox exists but caldav structure doesn't? delete event? */
	    scan->do_delete = 0;
	    goto done_item;
	}

	struct caldav_data *cdata = NULL;
	caldav_lookup_resource(caldavdb, mailbox->name, scan->data.resource, 0, &cdata);
	if (!cdata || !cdata->ical_uid)
	    /* resource not found, nothing we can do */
	    goto done_item;

	struct index_record record;
	memset(&record, 0, sizeof(struct index_record));
	rc = mailbox_find_index_record(mailbox, cdata->dav.imap_uid, &record, NULL);
	if (rc) {
	    /* XXX no index record? item deleted or transient error? */
	    scan->do_delete = 0;
	    goto done_item;
	}

	rc = mailbox_map_record(mailbox, &record, &msg_buf);
	if (rc) {
	    /* XXX no message? index is wrong? yikes */
	    scan->do_delete = 0;
	    goto done_item;
	}

	ical = icalparser_parse_string(buf_base(&msg_buf) + record.header_size);
	buf_free(&msg_buf);

	rc = annotatemore_lookup(mailbox->name, displayname_annot, NULL, &calname_buf);
	if (rc || !calname_buf.len) buf_setcstr(&calname_buf, strrchr(mailbox->name, '.') + 1);
	buf_cstring(&calname_buf);

	mailbox_close(&mailbox);
	mailbox = NULL;

	caldav_close(caldavdb);
	caldavdb = NULL;

	if (!ical)
	    /* XXX log error */
	    goto done_item;

	/* fill out recipients */
	struct bind_val rbval[] = {
	    { ":alarmid",	SQLITE_INTEGER,	{ .i = scan->data.rowid	} },
	    { NULL,		SQLITE_NULL,	{ .s = NULL		} }
	};

	rc = dav_exec(alarmdb->db, CMD_SELECT_RECIPIENT, rbval, recipient_read_cb,
		      &scan->data.recipients,
		      &alarmdb->stmt[STMT_SELECT_RECIPIENT]);

	struct mboxevent *event = mboxevent_new(EVENT_CALENDAR_ALARM);
	mboxevent_extract_icalcomponent(event, ical, userid, buf_base(&calname_buf),
					scan->data.action, scan->data.nextalarm,
					scan->data.tzid,
					scan->data.start, scan->data.end,
					&scan->data.recipients);
	mboxevent_notify(event);
	mboxevent_free(&event);

	/* set up for next alarm */
	struct caldav_alarm_data alarmdata = {
	    .mailbox  = scan->data.mailbox,
	    .resource = scan->data.resource,
	};

	if (!caldav_alarm_prepare(ical, &alarmdata, scan->data.action, before)) {
	    rc = caldav_alarm_add(alarmdb, &alarmdata);
	    caldav_alarm_fini(&alarmdata);
	    /* report error, but don't do anything */
	}

done_item:
	buf_free(&calname_buf);
	buf_free(&msg_buf);
	if (ical) icalcomponent_free(ical);
	if (caldavdb) caldav_close(caldavdb);
	if (userid) free(userid);
	if (mailbox) mailbox_close(&mailbox);
    }

    for (scan = list; scan; scan = scan->next)
	if (scan->do_delete)
	    caldav_alarm_delete_row(alarmdb, &scan->data);

done:
    caldav_alarm_close(alarmdb);

    scan = list;
    while (scan) {
	struct alarmdata_list *next = scan->next;

	free((void*) scan->data.mailbox);
	free((void*) scan->data.resource);
	free((void*) scan->data.tzid);
	free(scan);

	scan = next;
    }

    return rc;
}
