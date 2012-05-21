/* caldav_db.c -- implementation of per-user CalDAV database
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

#include "caldav_db.h"
#include "cyrusdb.h"
#include "dav_prop.h"
#include "httpd.h"
#include "libconfig.h"
#include "mboxname.h"
#include "xstrlcat.h"
#include "xmalloc.h"


enum {
    STMT_SELECT,
    STMT_SELMBOX,
    STMT_INSERT,
    STMT_UPDATE,
    STMT_DELETE,
    STMT_DELMBOX,
    STMT_BEGIN,
    STMT_COMMIT,
    STMT_ROLLBACK
};

#define NUM_STMT 9

struct caldav_db {
    sqlite3 *db;			/* DB handle */
    char sched_inbox[MAX_MAILBOX_BUFFER];/* DB owner's scheduling Inbox */
    sqlite3_stmt *stmt[NUM_STMT];	/* prepared statements */
};


static struct namespace caldav_namespace;

int caldav_init(void)
{
    int r;

    /* Set namespace -- force standard (internal) */
    if ((r = mboxname_init_namespace(&caldav_namespace, 1))) {
	syslog(LOG_ERR, "%s", error_message(r));
	fatal(error_message(r), EC_CONFIG);
    }

    return dav_init();
}


int caldav_done(void)
{
    return dav_done();
}


#define CMD_DROP "DROP TABLE IF EXISTS ical_objs;"

#define CMD_CREATE							\
    "CREATE TABLE IF NOT EXISTS ical_objs ("				\
    " rowid INTEGER PRIMARY KEY,"					\
    " mailbox TEXT NOT NULL,"						\
    " resource TEXT NOT NULL,"						\
    " imap_uid INTEGER,"						\
    " ical_uid TEXT,"							\
    " comp_type INTEGER,"						\
    " organizer TEXT,"							\
    " sched_tag TEXT,"							\
    " dtstart TEXT,"							\
    " dtend TEXT,"							\
    " recurring INTEGER,"						\
    " transp INTEGER,"							\
    " UNIQUE( mailbox, resource ) );"					\
    "CREATE INDEX IF NOT EXISTS idx_ical_uid ON ical_objs ( ical_uid );"

/* Open DAV DB corresponding to userid */
struct caldav_db *caldav_open(const char *userid, int flags)
{
    sqlite3 *db;
    struct caldav_db *caldavdb = NULL;
    const char *cmds = CMD_CREATE;

    if (flags & CALDAV_TRUNC) cmds = CMD_DROP CMD_CREATE;

    db = dav_open(userid, cmds);

    if (db) {
	caldavdb = xzmalloc(sizeof(struct caldav_db));
	caldavdb->db = db;

	/* Construct mailbox name corresponding to userid's scheduling Inbox */
	caldav_mboxname(SCHED_INBOX, userid, caldavdb->sched_inbox);
    }

    return caldavdb;
}


/* Close DAV DB */
int caldav_close(struct caldav_db *caldavdb)
{
    int i, r = 0;

    if (!caldavdb) return 0;

    for (i = 0; i < NUM_STMT; i++) {
	sqlite3_stmt *stmt = caldavdb->stmt[i];
	if (stmt) sqlite3_finalize(stmt);
    }

    r = dav_close(caldavdb->db);

    free(caldavdb);

    return r;
}


struct read_rock {
    struct caldav_data *cdata;
    int (*cb)(void *rock, struct caldav_data *cdata);
    void *rock;
};

static int read_cb(sqlite3_stmt *stmt, void *rock)
{
    struct read_rock *rrock = (struct read_rock *) rock;
    struct caldav_data *cdata = rrock->cdata;
    int r = 0;

    memset(cdata, 0, sizeof(struct caldav_data));
    cdata->rowid = sqlite3_column_int(stmt, 0);
    cdata->mailbox = (const char *) sqlite3_column_text(stmt, 1);
    cdata->resource = (const char *) sqlite3_column_text(stmt, 2);
    cdata->imap_uid = sqlite3_column_int(stmt, 3);
    cdata->ical_uid = (const char *) sqlite3_column_text(stmt, 4);
    cdata->comp_type = sqlite3_column_int(stmt, 5);
    cdata->organizer = (const char *) sqlite3_column_text(stmt, 6);
    cdata->sched_tag = (const char *) sqlite3_column_text(stmt, 7);
    cdata->dtstart = (const char *) sqlite3_column_text(stmt, 8);
    cdata->dtend = (const char *) sqlite3_column_text(stmt, 9);
    cdata->recurring = sqlite3_column_int(stmt, 10);
    cdata->transp = sqlite3_column_int(stmt, 11);

    if (rrock->cb) r = rrock->cb(rrock->rock, cdata);
    else r = CYRUSDB_DONE;

    return r;
}


#define CMD_SELECT							\
    "SELECT rowid, mailbox, resource, imap_uid, ical_uid, comp_type,"	\
    "  organizer, sched_tag, dtstart, dtend, recurring, transp"		\
    " FROM ical_objs"							\
    " WHERE ( mailbox = :mailbox AND resource = :resource )"		\
    "  OR ( ical_uid = :ical_uid AND mailbox != :inbox);"

int caldav_read(struct caldav_db *caldavdb, struct caldav_data *cdata)
{
    struct bind_val bval[] = {
	{ ":mailbox",  SQLITE_TEXT, { .s = cdata->mailbox	 } },
	{ ":resource", SQLITE_TEXT, { .s = cdata->resource	 } },
	{ ":ical_uid", SQLITE_TEXT, { .s = cdata->ical_uid	 } },
	{ ":inbox",    SQLITE_TEXT, { .s = caldavdb->sched_inbox } },
	{ NULL,	       SQLITE_NULL, { .s = NULL			 } } };
    struct read_rock rrock = { cdata, NULL, NULL };
    int r;

    cdata->rowid = 0;
    r = dav_exec(caldavdb->db, CMD_SELECT, bval, &read_cb, &rrock,
		 &caldavdb->stmt[STMT_SELECT]);
    if (!r && !cdata->rowid) r = CYRUSDB_NOTFOUND;

    return r;
}


#define CMD_BEGIN "BEGIN TRANSACTION;"

int caldav_lockread(struct caldav_db *caldavdb, struct caldav_data *cdata)
{
    int r;

    /* begin a transaction */
    r = dav_exec(caldavdb->db, CMD_BEGIN, NULL, NULL, NULL,
		 &caldavdb->stmt[STMT_BEGIN]);
    if (r) return r;

    /* do the actual read */
    return caldav_read(caldavdb, cdata);
}


#define CMD_SELMBOX							\
    "SELECT rowid, mailbox, resource, imap_uid, ical_uid, comp_type,"	\
    "  organizer, sched_tag, dtstart, dtend, recurring, transp"		\
    " FROM ical_objs WHERE mailbox = :mailbox;"

int caldav_foreach(struct caldav_db *caldavdb, const char *mailbox,
		   int (*cb)(void *rock, struct caldav_data *cdata),
		   void *rock)
{
    struct bind_val bval[] = {
	{ ":mailbox", SQLITE_TEXT, { .s = mailbox } },
	{ NULL,	      SQLITE_NULL, { .s = NULL    } } };
    struct caldav_data cdata;
    struct read_rock rrock = { &cdata, cb, rock };

    return dav_exec(caldavdb->db, CMD_SELMBOX, bval, &read_cb, &rrock,
		    &caldavdb->stmt[STMT_SELMBOX]);
}


#define CMD_INSERT							\
    "INSERT INTO ical_objs ("						\
    "  mailbox, resource, imap_uid, ical_uid, comp_type,"		\
    "  organizer, sched_tag, dtstart, dtend, recurring, transp )"	\
    " VALUES ("								\
    "  :mailbox, :resource, :imap_uid, :ical_uid, :comp_type,"		\
    "  :organizer, :sched_tag, :dtstart, :dtend, :recurring, :transp );"

#define CMD_UPDATE		\
    "UPDATE ical_objs SET"	\
    "  imap_uid  = :imap_uid,"	\
    "  ical_uid  = :ical_uid,"	\
    "  comp_type = :comp_type," \
    "  organizer = :organizer," \
    "  sched_tag = :sched_tag," \
    "  dtstart   = :dtstart,"	\
    "  dtend     = :dtend,"	\
    "  recurring = :recurring," \
    "  transp    = :transp"	\
    " WHERE rowid = :rowid;"

int caldav_write(struct caldav_db *caldavdb, struct caldav_data *cdata)
{
    struct bind_val bval[] = {
	{ ":imap_uid",	 SQLITE_INTEGER, { .i = cdata->imap_uid  } },
	{ ":ical_uid",	 SQLITE_TEXT,	 { .s = cdata->ical_uid  } },
	{ ":comp_type",	 SQLITE_INTEGER, { .i = cdata->comp_type } },
	{ ":organizer",	 SQLITE_TEXT,	 { .s = cdata->organizer } },
	{ ":sched_tag",	 SQLITE_TEXT,	 { .s = cdata->sched_tag } },
	{ ":dtstart",	 SQLITE_TEXT,	 { .s = cdata->dtstart   } },
	{ ":dtend",	 SQLITE_TEXT,	 { .s = cdata->dtend     } },
	{ ":recurring",	 SQLITE_INTEGER, { .i = cdata->recurring } },
	{ ":transp",	 SQLITE_INTEGER, { .i = cdata->transp    } },
	{ NULL,		 SQLITE_NULL,	 { .s = NULL		 } },
	{ NULL,		 SQLITE_NULL,	 { .s = NULL		 } },
	{ NULL,		 SQLITE_NULL,	 { .s = NULL		 } } };
    const char *cmd;
    sqlite3_stmt **stmt;

    if (cdata->rowid) {
	cmd = CMD_UPDATE;
	stmt = &caldavdb->stmt[STMT_UPDATE];

	bval[9].name = ":rowid";
	bval[9].type = SQLITE_INTEGER;
	bval[9].val.i = cdata->rowid;
    }
    else {
	cmd = CMD_INSERT;
	stmt = &caldavdb->stmt[STMT_INSERT];

	bval[9].name = ":mailbox";
	bval[9].type = SQLITE_TEXT;
	bval[9].val.s = cdata->mailbox;
	bval[10].name = ":resource";
	bval[10].type = SQLITE_TEXT;
	bval[10].val.s = cdata->resource;
    }

    return dav_exec(caldavdb->db, cmd, bval, NULL, NULL, stmt);
}


#define CMD_DELETE "DELETE FROM ical_objs WHERE rowid = :rowid;"

int caldav_delete(struct caldav_db *caldavdb, struct caldav_data *cdata)
{
    struct bind_val bval[] = {
	{ ":rowid", SQLITE_INTEGER, { .i = cdata->rowid } },
	{ NULL,	    SQLITE_NULL,    { .s = NULL         } } };

    return dav_exec(caldavdb->db, CMD_DELETE, bval, NULL, NULL,
		    &caldavdb->stmt[STMT_DELETE]);
}


#define CMD_DELMBOX "DELETE FROM ical_objs WHERE mailbox = :mailbox;"

int caldav_delmbox(struct caldav_db *caldavdb, const char *mailbox)
{
    struct bind_val bval[] = {
	{ ":mailbox", SQLITE_TEXT, { .s = mailbox } },
	{ NULL,	      SQLITE_NULL, { .s = NULL    } } };

    return dav_exec(caldavdb->db, CMD_DELMBOX, bval, NULL, NULL,
		    &caldavdb->stmt[STMT_DELMBOX]);
}


#define CMD_COMMIT "COMMIT TRANSACTION;"

int caldav_commit(struct caldav_db *caldavdb)
{
    return dav_exec(caldavdb->db, CMD_COMMIT, NULL, NULL, NULL,
		    &caldavdb->stmt[STMT_COMMIT]);
}


#define CMD_ROLLBACK "ROLLBACK TRANSACTION;"

int caldav_abort(struct caldav_db *caldavdb)
{
    return dav_exec(caldavdb->db, CMD_ROLLBACK, NULL, NULL, NULL,
		    &caldavdb->stmt[STMT_ROLLBACK]);
}


/* icalcomponent_foreach_recurrence() callback to find ealiest/latest time */
static void get_times(icalcomponent *comp, struct icaltime_span *span,
		      void *rock)
{
    struct icalperiodtype *period = (struct icalperiodtype *) rock;
    int is_date = icaltime_is_date(icalcomponent_get_dtstart(comp));
    icaltimezone *utc = icaltimezone_get_utc_timezone();
    struct icaltimetype start =
	icaltime_from_timet_with_zone(span->start, is_date, utc);
    struct icaltimetype end =
	icaltime_from_timet_with_zone(span->end, is_date, utc);

    if (icaltime_compare(start, period->start) < 0)
	memcpy(&period->start, &start, sizeof(struct icaltimetype));

    if (icaltime_compare(end, period->end) > 0)
	memcpy(&period->end, &end, sizeof(struct icaltimetype));
}


void caldav_make_entry(icalcomponent *ical, struct caldav_data *cdata)
{
    icalcomponent *comp = icalcomponent_get_first_real_component(ical);
    icaltimezone *utc = icaltimezone_get_utc_timezone();
    icalcomponent_kind kind;
    icalproperty *prop;
    unsigned mykind = 0, recurring = 0, transp = 0;
    struct icalperiodtype period;

    /* Get iCalendar UID */
    cdata->ical_uid = icalcomponent_get_uid(comp);

    /* Get component type */
    kind = icalcomponent_isa(comp);
    switch (kind) {
    case ICAL_VEVENT_COMPONENT: mykind = CAL_COMP_VEVENT; break;
    case ICAL_VTODO_COMPONENT: mykind = CAL_COMP_VTODO; break;
    case ICAL_VJOURNAL_COMPONENT: mykind = CAL_COMP_VJOURNAL; break;
    case ICAL_VFREEBUSY_COMPONENT: mykind = CAL_COMP_VFREEBUSY; break;
    default: break;
    }
    cdata->comp_type = mykind;

    /* Get organizer */
    prop = icalcomponent_get_first_property(comp, ICAL_ORGANIZER_PROPERTY);
    if (prop) cdata->organizer = icalproperty_get_organizer(prop)+7;

    /* Get transparency */
    prop = icalcomponent_get_first_property(comp, ICAL_TRANSP_PROPERTY);
    if (prop) {
	icalvalue *transp_val = icalproperty_get_value(prop);

	switch (icalvalue_get_transp(transp_val)) {
	case ICAL_TRANSP_TRANSPARENT:
	case ICAL_TRANSP_TRANSPARENTNOCONFLICT:
	    transp = 1;
	    break;

	default:
	    transp = 0;
	    break;
	}
    }
    cdata->transp = transp;

    /* Get base dtstart and dtend */
    period.start =
	icaltime_convert_to_zone(icalcomponent_get_dtstart(comp), utc);
    period.end =
	icaltime_convert_to_zone(icalcomponent_get_dtend(comp), utc);

    /* See if its a recurring event */
    if (icalcomponent_get_first_property(comp,ICAL_RRULE_PROPERTY) ||
	icalcomponent_get_first_property(comp,ICAL_RDATE_PROPERTY) ||
	icalcomponent_get_first_property(comp,ICAL_EXDATE_PROPERTY)) {
	/* Recurring - find widest time range that includes events */
	recurring = 1;

	icalcomponent_foreach_recurrence(
	    comp,
	    icaltime_from_timet_with_zone(INT_MIN, 0, NULL),
	    icaltime_from_timet_with_zone(INT_MAX, 0, NULL),
	    get_times,
	    &period);

	/* Handle overridden recurrences */
	while ((comp = icalcomponent_get_next_component(ical, kind))) {
	    struct icaltimetype start =
		icaltime_convert_to_zone(icalcomponent_get_dtstart(comp), utc);
	    struct icaltimetype end =
		icaltime_convert_to_zone(icalcomponent_get_dtend(comp), utc);

	    if (icaltime_compare(start, period.start) < 0)
		memcpy(&period.start, &start, sizeof(struct icaltimetype));

	    if (icaltime_compare(end, period.end) > 0)
		memcpy(&period.end, &end, sizeof(struct icaltimetype));
	}
    }

    cdata->dtstart = icaltime_as_ical_string(period.start);
    cdata->dtend = icaltime_as_ical_string(period.end);
    cdata->recurring = recurring;
}


int caldav_mboxname(const char *name, const char *userid, char *result)
{
    size_t len;

    /* Construct mailbox name corresponding to userid's calendar mailbox */
    (*caldav_namespace.mboxname_tointernal)(&caldav_namespace, "INBOX",
					    userid, result);
    len = strlen(result);
    len += snprintf(result+len, MAX_MAILBOX_BUFFER - len,
		    ".%s", config_getstring(IMAPOPT_CALENDARPREFIX));
    if (name && *name) {
	len += snprintf(result+len, MAX_MAILBOX_BUFFER - len,
			".%s", name);
    }

    if (result[len-1] == '/') result[len-1] = '\0';

    return 0;
}
