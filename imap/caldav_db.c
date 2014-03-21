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

#ifdef WITH_DAV

#include <syslog.h>
#include <string.h>

#include <libical/ical.h>

#include "caldav_db.h"
#include "cyrusdb.h"
#include "httpd.h"
#include "http_dav.h"
#include "libconfig.h"
#include "mboxname.h"
#include "util.h"
#include "xstrlcat.h"
#include "xmalloc.h"


enum {
    STMT_SELRSRC,
    STMT_SELUID,
    STMT_SELMBOX,
    STMT_INSERT,
    STMT_UPDATE,
    STMT_DELETE,
    STMT_DELMBOX,
    STMT_BEGIN,
    STMT_COMMIT,
    STMT_ROLLBACK
};

#define NUM_STMT 10

struct caldav_db {
    sqlite3 *db;			/* DB handle */
    char sched_inbox[MAX_MAILBOX_BUFFER];/* DB owner's scheduling Inbox */
    sqlite3_stmt *stmt[NUM_STMT];	/* prepared statements */
    struct buf mailbox;			/* buffers for copies of column text */
    struct buf resource;
    struct buf lock_token;
    struct buf lock_owner;
    struct buf lock_ownerid;
    struct buf ical_uid;
    struct buf organizer;
    struct buf dtstart;
    struct buf dtend;
    struct buf sched_tag;
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
    " creationdate INTEGER,"						\
    " mailbox TEXT NOT NULL,"						\
    " resource TEXT NOT NULL,"						\
    " imap_uid INTEGER,"						\
    " lock_token TEXT,"							\
    " lock_owner TEXT,"							\
    " lock_ownerid TEXT,"						\
    " lock_expire INTEGER,"						\
    " comp_type INTEGER,"						\
    " ical_uid TEXT,"							\
    " organizer TEXT,"							\
    " dtstart TEXT,"							\
    " dtend TEXT,"							\
    " recurring INTEGER,"						\
    " transp INTEGER,"							\
    " sched_tag TEXT,"							\
    " UNIQUE( mailbox, resource ) );"					\
    "CREATE INDEX IF NOT EXISTS idx_ical_uid ON ical_objs ( ical_uid );"

/* Open DAV DB corresponding to mailbox */
struct caldav_db *caldav_open(struct mailbox *mailbox, int flags)
{
    sqlite3 *db;
    struct caldav_db *caldavdb = NULL;
    const char *cmds = CMD_CREATE;

    if (flags & CALDAV_TRUNC) cmds = CMD_DROP CMD_CREATE;

    db = dav_open(mailbox, cmds);

    if (db) {
	const char *userid;

	caldavdb = xzmalloc(sizeof(struct caldav_db));
	caldavdb->db = db;

	userid = mboxname_to_userid(mailbox->name);
	if (userid) {
	    /* Construct mbox name corresponding to userid's scheduling Inbox */
	    caldav_mboxname(SCHED_INBOX, userid, caldavdb->sched_inbox);
	}
    }

    return caldavdb;
}


/* Close DAV DB */
int caldav_close(struct caldav_db *caldavdb)
{
    int i, r = 0;

    if (!caldavdb) return 0;

    buf_free(&caldavdb->mailbox);
    buf_free(&caldavdb->resource);
    buf_free(&caldavdb->lock_token);
    buf_free(&caldavdb->lock_owner);
    buf_free(&caldavdb->lock_ownerid);
    buf_free(&caldavdb->ical_uid);
    buf_free(&caldavdb->organizer);
    buf_free(&caldavdb->dtstart);
    buf_free(&caldavdb->dtend);
    buf_free(&caldavdb->sched_tag);

    for (i = 0; i < NUM_STMT; i++) {
	sqlite3_stmt *stmt = caldavdb->stmt[i];
	if (stmt) sqlite3_finalize(stmt);
    }

    r = dav_close(caldavdb->db);

    free(caldavdb);

    return r;
}


#define CMD_BEGIN "BEGIN TRANSACTION;"

int caldav_begin(struct caldav_db *caldavdb)
{
    return dav_exec(caldavdb->db, CMD_BEGIN, NULL, NULL, NULL,
		    &caldavdb->stmt[STMT_BEGIN]);
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


struct read_rock {
    struct caldav_db *db;
    struct caldav_data *cdata;
    int (*cb)(void *rock, void *data);
    void *rock;
};

static const char *column_text_to_buf(const char *text, struct buf *buf)
{
    if (text) {
	buf_setcstr(buf, text);
	text = buf_cstring(buf);
    }

    return text;
}

static int read_cb(sqlite3_stmt *stmt, void *rock)
{
    struct read_rock *rrock = (struct read_rock *) rock;
    struct caldav_db *db = rrock->db;
    struct caldav_data *cdata = rrock->cdata;
    int r = 0;

    memset(cdata, 0, sizeof(struct caldav_data));

    cdata->dav.rowid = sqlite3_column_int(stmt, 0);
    cdata->dav.creationdate = sqlite3_column_int(stmt, 1);
    cdata->dav.imap_uid = sqlite3_column_int(stmt, 4);
    cdata->dav.lock_expire = sqlite3_column_int(stmt, 8);
    cdata->comp_type = sqlite3_column_int(stmt, 9);
    cdata->recurring = sqlite3_column_int(stmt, 14);
    cdata->transp = sqlite3_column_int(stmt, 15);

    if (rrock->cb) {
	/* We can use the column data directly for the callback */
	cdata->dav.mailbox = (const char *) sqlite3_column_text(stmt, 2);
	cdata->dav.resource = (const char *) sqlite3_column_text(stmt, 3);
	cdata->dav.lock_token = (const char *) sqlite3_column_text(stmt, 5);
	cdata->dav.lock_owner = (const char *) sqlite3_column_text(stmt, 6);
	cdata->dav.lock_ownerid = (const char *) sqlite3_column_text(stmt, 7);
	cdata->ical_uid = (const char *) sqlite3_column_text(stmt, 10);
	cdata->organizer = (const char *) sqlite3_column_text(stmt, 11);
	cdata->dtstart = (const char *) sqlite3_column_text(stmt, 12);
	cdata->dtend = (const char *) sqlite3_column_text(stmt, 13);
	cdata->sched_tag = (const char *) sqlite3_column_text(stmt, 16);
	r = rrock->cb(rrock->rock, cdata);
    }
    else {
	/* For single row SELECTs like caldav_read(),
	 * we need to make a copy of the column data before
	 * it gets flushed by sqlite3_step() or sqlite3_reset() */
	cdata->dav.mailbox =
	    column_text_to_buf((const char *) sqlite3_column_text(stmt, 2),
			       &db->mailbox);
	cdata->dav.resource =
	    column_text_to_buf((const char *) sqlite3_column_text(stmt, 3),
			       &db->resource);
	cdata->dav.lock_token =
	    column_text_to_buf((const char *) sqlite3_column_text(stmt, 5),
			       &db->lock_token);
	cdata->dav.lock_owner =
	    column_text_to_buf((const char *) sqlite3_column_text(stmt, 6),
			       &db->lock_owner);
	cdata->dav.lock_ownerid =
	    column_text_to_buf((const char *) sqlite3_column_text(stmt, 7),
			       &db->lock_ownerid);
	cdata->ical_uid =
	    column_text_to_buf((const char *) sqlite3_column_text(stmt, 10),
			       &db->ical_uid);
	cdata->organizer =
	    column_text_to_buf((const char *) sqlite3_column_text(stmt, 11),
			       &db->organizer);
	cdata->dtstart =
	    column_text_to_buf((const char *) sqlite3_column_text(stmt, 12),
			       &db->dtstart);
	cdata->dtend =
	    column_text_to_buf((const char *) sqlite3_column_text(stmt, 13),
			       &db->dtend);
	cdata->sched_tag =
	    column_text_to_buf((const char *) sqlite3_column_text(stmt, 16),
			       &db->sched_tag);
    }

    return r;
}


#define CMD_SELRSRC							\
    "SELECT rowid, creationdate, mailbox, resource, imap_uid,"		\
    "  lock_token, lock_owner, lock_ownerid, lock_expire,"		\
    "  comp_type, ical_uid, organizer, dtstart, dtend,"			\
    "  recurring, transp, sched_tag"					\
    " FROM ical_objs"							\
    " WHERE ( mailbox = :mailbox AND resource = :resource );"

int caldav_lookup_resource(struct caldav_db *caldavdb,
			   const char *mailbox, const char *resource,
			   int lock, struct caldav_data **result)
{
    struct bind_val bval[] = {
	{ ":mailbox",  SQLITE_TEXT, { .s = mailbox	 } },
	{ ":resource", SQLITE_TEXT, { .s = resource	 } },
	{ NULL,	       SQLITE_NULL, { .s = NULL		 } } };
    static struct caldav_data cdata;
    struct read_rock rrock = { caldavdb, &cdata, NULL, NULL };
    int r;

    *result = memset(&cdata, 0, sizeof(struct caldav_data));

    if (lock) {
	/* begin a transaction */
	r = dav_exec(caldavdb->db, CMD_BEGIN, NULL, NULL, NULL,
		     &caldavdb->stmt[STMT_BEGIN]);
	if (r) return r;
    }

    r = dav_exec(caldavdb->db, CMD_SELRSRC, bval, &read_cb, &rrock,
		 &caldavdb->stmt[STMT_SELRSRC]);
    if (!r && !cdata.dav.rowid) r = CYRUSDB_NOTFOUND;

    return r;
}


#define CMD_SELUID							\
    "SELECT rowid, creationdate, mailbox, resource, imap_uid,"		\
    "  lock_token, lock_owner, lock_ownerid, lock_expire,"		\
    "  comp_type, ical_uid, organizer, dtstart, dtend,"			\
    "  recurring, transp, sched_tag"					\
    " FROM ical_objs"							\
    " WHERE ( ical_uid = :ical_uid AND mailbox != :inbox);"

int caldav_lookup_uid(struct caldav_db *caldavdb, const char *ical_uid,
		      int lock, struct caldav_data **result)
{
    struct bind_val bval[] = {
	{ ":ical_uid", SQLITE_TEXT, { .s = ical_uid		 } },
	{ ":inbox",    SQLITE_TEXT, { .s = caldavdb->sched_inbox } },
	{ NULL,	       SQLITE_NULL, { .s = NULL			 } } };
    static struct caldav_data cdata;
    struct read_rock rrock = { caldavdb, &cdata, NULL, NULL };
    int r;

    *result = memset(&cdata, 0, sizeof(struct caldav_data));

    if (lock) {
	/* begin a transaction */
	r = dav_exec(caldavdb->db, CMD_BEGIN, NULL, NULL, NULL,
		     &caldavdb->stmt[STMT_BEGIN]);
	if (r) return r;
    }

    r = dav_exec(caldavdb->db, CMD_SELUID, bval, &read_cb, &rrock,
		 &caldavdb->stmt[STMT_SELUID]);
    if (!r && !cdata.dav.rowid) r = CYRUSDB_NOTFOUND;

    return r;
}


#define CMD_SELMBOX							\
    "SELECT rowid, creationdate, mailbox, resource, imap_uid,"		\
    "  lock_token, lock_owner, lock_ownerid, lock_expire,"		\
    "  comp_type, ical_uid, organizer, dtstart, dtend,"			\
    "  recurring, transp, sched_tag"					\
    " FROM ical_objs WHERE mailbox = :mailbox;"

int caldav_foreach(struct caldav_db *caldavdb, const char *mailbox,
		   int (*cb)(void *rock, void *data),
		   void *rock)
{
    struct bind_val bval[] = {
	{ ":mailbox", SQLITE_TEXT, { .s = mailbox } },
	{ NULL,	      SQLITE_NULL, { .s = NULL    } } };
    struct caldav_data cdata;
    struct read_rock rrock = { caldavdb, &cdata, cb, rock };

    return dav_exec(caldavdb->db, CMD_SELMBOX, bval, &read_cb, &rrock,
		    &caldavdb->stmt[STMT_SELMBOX]);
}


#define CMD_INSERT							\
    "INSERT INTO ical_objs ("						\
    "  creationdate, mailbox, resource, imap_uid,"			\
    "  lock_token, lock_owner, lock_ownerid, lock_expire,"		\
    "  comp_type, ical_uid, organizer, dtstart, dtend,"			\
    "  recurring, transp, sched_tag )" 	       		  	   	\
    " VALUES ("								\
    "  :creationdate, :mailbox, :resource, :imap_uid,"			\
    "  :lock_token, :lock_owner, :lock_ownerid, :lock_expire,"		\
    "  :comp_type, :ical_uid, :organizer, :dtstart, :dtend,"		\
    "  :recurring, :transp, :sched_tag );"

#define CMD_UPDATE		   	\
    "UPDATE ical_objs SET"		\
    "  imap_uid     = :imap_uid,"	\
    "  lock_token   = :lock_token,"	\
    "  lock_owner   = :lock_owner,"	\
    "  lock_ownerid = :lock_ownerid,"	\
    "  lock_expire = :lock_expire,"	\
    "  comp_type    = :comp_type,"	\
    "  ical_uid     = :ical_uid,"	\
    "  organizer    = :organizer,"	\
    "  dtstart      = :dtstart,"	\
    "  dtend        = :dtend,"		\
    "  recurring    = :recurring,"	\
    "  transp       = :transp,"		\
    "  sched_tag    = :sched_tag"	\
    " WHERE rowid = :rowid;"

int caldav_write(struct caldav_db *caldavdb, struct caldav_data *cdata,
		 int commit)
{
    struct bind_val bval[] = {
	{ ":imap_uid",	   SQLITE_INTEGER, { .i = cdata->dav.imap_uid	  } },
	{ ":lock_token",   SQLITE_TEXT,	   { .s = cdata->dav.lock_token	  } },
	{ ":lock_owner",   SQLITE_TEXT,	   { .s = cdata->dav.lock_owner	  } },
	{ ":lock_ownerid", SQLITE_TEXT,	   { .s = cdata->dav.lock_ownerid } },
	{ ":lock_expire",  SQLITE_INTEGER, { .i = cdata->dav.lock_expire  } },
	{ ":comp_type",	   SQLITE_INTEGER, { .i = cdata->comp_type	  } },
	{ ":ical_uid",	   SQLITE_TEXT,	   { .s = cdata->ical_uid	  } },
	{ ":organizer",	   SQLITE_TEXT,	   { .s = cdata->organizer	  } },
	{ ":dtstart",	   SQLITE_TEXT,	   { .s = cdata->dtstart	  } },
	{ ":dtend",	   SQLITE_TEXT,	   { .s = cdata->dtend		  } },
	{ ":recurring",	   SQLITE_INTEGER, { .i = cdata->recurring	  } },
	{ ":transp",	   SQLITE_INTEGER, { .i = cdata->transp		  } },
	{ ":sched_tag",	   SQLITE_TEXT,	   { .s = cdata->sched_tag	  } },
	{ NULL,		   SQLITE_NULL,	   { .s = NULL			  } },
	{ NULL,		   SQLITE_NULL,	   { .s = NULL			  } },
	{ NULL,		   SQLITE_NULL,	   { .s = NULL			  } },
	{ NULL,		   SQLITE_NULL,	   { .s = NULL			  } } };
    const char *cmd;
    sqlite3_stmt **stmt;
    int r;

    if (cdata->dav.rowid) {
	cmd = CMD_UPDATE;
	stmt = &caldavdb->stmt[STMT_UPDATE];

	bval[13].name = ":rowid";
	bval[13].type = SQLITE_INTEGER;
	bval[13].val.i = cdata->dav.rowid;
    }
    else {
	cmd = CMD_INSERT;
	stmt = &caldavdb->stmt[STMT_INSERT];

	bval[13].name = ":creationdate";
	bval[13].type = SQLITE_INTEGER;
	bval[13].val.i = cdata->dav.creationdate;
	bval[14].name = ":mailbox";
	bval[14].type = SQLITE_TEXT;
	bval[14].val.s = cdata->dav.mailbox;
	bval[15].name = ":resource";
	bval[15].type = SQLITE_TEXT;
	bval[15].val.s = cdata->dav.resource;
    }

    r = dav_exec(caldavdb->db, cmd, bval, NULL, NULL, stmt);

    if (!r && commit) {
	/* commit transaction */
	return dav_exec(caldavdb->db, CMD_COMMIT, NULL, NULL, NULL,
			&caldavdb->stmt[STMT_COMMIT]);
    }

    return r;
}


#define CMD_DELETE "DELETE FROM ical_objs WHERE rowid = :rowid;"

int caldav_delete(struct caldav_db *caldavdb, unsigned rowid, int commit)
{
    struct bind_val bval[] = {
	{ ":rowid", SQLITE_INTEGER, { .i = rowid } },
	{ NULL,	    SQLITE_NULL,    { .s = NULL  } } };
    int r;

    r = dav_exec(caldavdb->db, CMD_DELETE, bval, NULL, NULL,
		 &caldavdb->stmt[STMT_DELETE]);

    if (!r && commit) {
	/* commit transaction */
	return dav_exec(caldavdb->db, CMD_COMMIT, NULL, NULL, NULL,
			&caldavdb->stmt[STMT_COMMIT]);
    }	

    return r;
}


#define CMD_DELMBOX "DELETE FROM ical_objs WHERE mailbox = :mailbox;"

int caldav_delmbox(struct caldav_db *caldavdb, const char *mailbox, int commit)
{
    struct bind_val bval[] = {
	{ ":mailbox", SQLITE_TEXT, { .s = mailbox } },
	{ NULL,	      SQLITE_NULL, { .s = NULL    } } };
    int r;

    r = dav_exec(caldavdb->db, CMD_DELMBOX, bval, NULL, NULL,
		 &caldavdb->stmt[STMT_DELMBOX]);

    if (!r && commit) {
	/* commit transaction */
	return dav_exec(caldavdb->db, CMD_COMMIT, NULL, NULL, NULL,
			&caldavdb->stmt[STMT_COMMIT]);
    }	

    return r;
}


/* Get time period (start/end) of a component based in RFC 4791 Sec 9.9 */
static void get_period(icalcomponent *comp, icalcomponent_kind kind,
		       struct icalperiodtype *period)
{
    icaltimezone *utc = icaltimezone_get_utc_timezone();

    period->start =
	icaltime_convert_to_zone(icalcomponent_get_dtstart(comp), utc);
    period->end =
	icaltime_convert_to_zone(icalcomponent_get_dtend(comp), utc);

    switch (kind) {
    case ICAL_VEVENT_COMPONENT:
	if (icaltime_is_null_time(period->end)) {
	    /* No DTEND or DURATION */
	    memcpy(&period->end, &period->start,
		   sizeof(struct icaltimetype));

	    if (icaltime_is_date(period->start)) {
		/* DTSTART is not DATE-TIME */
		struct icaldurationtype dur;

		dur = icaldurationtype_from_int(60*60*24 - 1);  /* P1D */
		icaltime_add(period->end, dur);
	    }
	}
	break;

#ifdef HAVE_VPOLL
    case ICAL_VPOLL_COMPONENT:
#endif
    case ICAL_VTODO_COMPONENT: {
	struct icaltimetype due = (kind == ICAL_VPOLL_COMPONENT) ?
	    icalcomponent_get_dtend(comp) : icalcomponent_get_due(comp);

	if (!icaltime_is_null_time(period->start)) {
	    /* Has DTSTART */
	    if (icaltime_is_null_time(period->end)) {
		/* No DURATION */
		memcpy(&period->end, &period->start,
		       sizeof(struct icaltimetype));

		if (!icaltime_is_null_time(due)) {
		    /* Has DUE (DTEND for VPOLL) */
		    if (icaltime_compare(due, period->start) < 0)
			memcpy(&period->start, &due, sizeof(struct icaltimetype));
		    if (icaltime_compare(due, period->end) > 0)
			memcpy(&period->end, &due, sizeof(struct icaltimetype));
		}
	    }
	}
	else {
	    icalproperty *prop;

	    /* No DTSTART */
	    if (!icaltime_is_null_time(due)) {
		/* Has DUE (DTEND for VPOLL) */
		memcpy(&period->start, &due, sizeof(struct icaltimetype));
		memcpy(&period->end, &due, sizeof(struct icaltimetype));
	    }
	    else if ((prop =
		      icalcomponent_get_first_property(comp,
						       ICAL_COMPLETED_PROPERTY))) {
		/* Has COMPLETED */
		period->start =
		    icaltime_convert_to_zone(icalproperty_get_completed(prop),
					     utc);
		memcpy(&period->end, &period->start, sizeof(struct icaltimetype));

		if ((prop =
		     icalcomponent_get_first_property(comp,
						      ICAL_CREATED_PROPERTY))) {
		    /* Has CREATED */
		    struct icaltimetype created =
			icaltime_convert_to_zone(icalproperty_get_created(prop),
						 utc);
		    if (icaltime_compare(created, period->start) < 0)
			memcpy(&period->start, &created, sizeof(struct icaltimetype));
		    if (icaltime_compare(created, period->end) > 0)
			memcpy(&period->end, &created, sizeof(struct icaltimetype));
		}
	    }
	    else if ((prop =
		      icalcomponent_get_first_property(comp,
						       ICAL_CREATED_PROPERTY))) {
		/* Has CREATED */
		period->start =
		    icaltime_convert_to_zone(icalproperty_get_created(prop),
					     utc);
		memcpy(&period->end, &period->start, sizeof(struct icaltimetype));
	    }
	    else {
		/* Always */
		period->start =
		    icaltime_from_timet_with_zone(INT_MIN, 0, NULL);
		period->end =
		    icaltime_from_timet_with_zone(INT_MAX, 0, NULL);
	    }
	}
	break;
    }

    case ICAL_VJOURNAL_COMPONENT:
	if (!icaltime_is_null_time(period->start)) {
	    /* Has DTSTART */
	    memcpy(&period->end, &period->start,
		   sizeof(struct icaltimetype));

	    if (icaltime_is_date(period->start)) {
		/* DTSTART is not DATE-TIME */
		struct icaldurationtype dur;

		dur = icaldurationtype_from_int(60*60*24 - 1);  /* P1D */
		icaltime_add(period->end, dur);
	    }
	}
	else {
	    /* Never */
	    period->start =
		icaltime_from_timet_with_zone(INT_MAX, 0, NULL);
	    period->end =
		icaltime_from_timet_with_zone(INT_MIN, 0, NULL);
	}
	break;

    case ICAL_VAVAILABILITY_COMPONENT:
	/* XXX  Probably need to do something different here */
    case ICAL_VFREEBUSY_COMPONENT:
	if (icaltime_is_null_time(period->start) ||
	    icaltime_is_null_time(period->end)) {
	    /* No DTSTART or DTEND */
	    icalproperty *fb =
		icalcomponent_get_first_property(comp,
						 ICAL_FREEBUSY_PROPERTY);


	    if (fb) {
		/* Has FREEBUSY */
		/* XXX  Convert FB period into our period */
	    }
	    else {
		/* Never */
		period->start =
		    icaltime_from_timet_with_zone(INT_MAX, 0, NULL);
		period->end =
		    icaltime_from_timet_with_zone(INT_MIN, 0, NULL);
	    }
	}
	break;

    default:
	break;
    }
}


/* icalcomponent_foreach_recurrence() callback to find earliest/latest time */
static void recur_cb(icalcomponent *comp, struct icaltime_span *span,
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
    icalcomponent_kind kind;
    icalproperty *prop;
    unsigned mykind = 0, recurring = 0, transp = 0;
    struct icalperiodtype span;

    /* Get iCalendar UID */
    cdata->ical_uid = icalcomponent_get_uid(comp);

    /* Get component type */
    kind = icalcomponent_isa(comp);
    switch (kind) {
    case ICAL_VEVENT_COMPONENT: mykind = CAL_COMP_VEVENT; break;
    case ICAL_VTODO_COMPONENT: mykind = CAL_COMP_VTODO; break;
    case ICAL_VJOURNAL_COMPONENT: mykind = CAL_COMP_VJOURNAL; break;
    case ICAL_VFREEBUSY_COMPONENT: mykind = CAL_COMP_VFREEBUSY; break;
    case ICAL_VAVAILABILITY_COMPONENT: mykind = CAL_COMP_VAVAILABILITY; break;
#ifdef HAVE_VPOLL
    case ICAL_VPOLL_COMPONENT: mykind = CAL_COMP_VPOLL; break;
#endif
    default: break;
    }
    cdata->comp_type = mykind;

    /* Get organizer */
    prop = icalcomponent_get_first_property(comp, ICAL_ORGANIZER_PROPERTY);
    if (prop) cdata->organizer = icalproperty_get_organizer(prop)+7;
    else cdata->organizer = NULL;

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
    get_period(comp, kind, &span);

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
	    recur_cb,
	    &span);

	/* Handle overridden recurrences */
	while ((comp = icalcomponent_get_next_component(ical, kind))) {
	    struct icalperiodtype period;

	    get_period(comp, kind, &period);

	    if (icaltime_compare(period.start, span.start) < 0)
		memcpy(&span.start, &period.start, sizeof(struct icaltimetype));

	    if (icaltime_compare(period.end, span.end) > 0)
		memcpy(&span.end, &period.end, sizeof(struct icaltimetype));
	}
    }

    cdata->dtstart = icaltime_as_ical_string(span.start);
    cdata->dtend = icaltime_as_ical_string(span.end);
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

#else

int caldav_init(void)
{
    return 0;
}


int caldav_done(void)
{
    return 0;
}


#endif /* WITH_DAV */
