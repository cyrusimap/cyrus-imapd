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

#include "caldav_db.h"
#include "cyrusdb.h"
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
    char *userid;			/* DB owner's userid */
    sqlite3_stmt *stmt[NUM_STMT];	/* prepared statements */
};


int caldav_init(void)
{
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
	caldavdb->userid = xstrdup(userid);
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

    free(caldavdb->userid);
    free(caldavdb);

    return r;
}


static int read_cb(sqlite3_stmt *stmt, void *rock)
{
    struct caldav_data *cdata = (struct caldav_data *) rock;

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

    return 0;
}


#define CMD_SELECT							\
    "SELECT rowid, mailbox, resource, imap_uid, ical_uid, comp_type,"	\
    "  organizer, sched_tag, dtstart, dtend, recurring, transp"		\
    " FROM ical_objs"							\
    " WHERE ( mailbox = :mailbox AND resource = :resource )"		\
    "  OR ical_uid = :ical_uid;"

int caldav_read(struct caldav_db *caldavdb, struct caldav_data *cdata)
{
    struct bind_val bval[] = {
	{ ":mailbox", SQLITE_TEXT, { .s = cdata->mailbox } },
	{ ":resource", SQLITE_TEXT, { .s = cdata->resource } },
	{ ":ical_uid", SQLITE_TEXT, { .s = cdata->ical_uid } },
	{ NULL, SQLITE_NULL, { .s = NULL } } };
    int r;

    cdata->rowid = 0;
    r = dav_exec(caldavdb->db, CMD_SELECT, bval, &read_cb, cdata,
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


struct for_rock {
    int (*cb)(void *rock, const char *resource, uint32_t imap_uid);
    void *rock;
};


static int for_cb(sqlite3_stmt *stmt, void *rock)
{
    struct for_rock *frock = (struct for_rock *) rock;
    const char *resource;
    uint32_t imap_uid;

    resource = (const char *) sqlite3_column_text(stmt, 2);
    imap_uid = sqlite3_column_int(stmt, 3);

    return frock->cb(frock->rock, resource, imap_uid);
}


#define CMD_SELMBOX							\
    "SELECT rowid, mailbox, resource, imap_uid, ical_uid, comp_type,"	\
    "  organizer, sched_tag, dtstart, dtend, recurring, transp"		\
    " FROM ical_objs WHERE mailbox = :mailbox;"

int caldav_foreach(struct caldav_db *caldavdb, const char *mailbox,
		   int (*cb)(void *rock,
			     const char *resource, uint32_t imap_uid),
		   void *rock)
{
    struct bind_val bval[] = {
	{ ":mailbox", SQLITE_TEXT, { .s = mailbox } },
	{ NULL, SQLITE_NULL, { .s = NULL } } };
    struct for_rock frock = { cb, rock };

    return dav_exec(caldavdb->db, CMD_SELMBOX, bval, &for_cb, &frock,
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
	{ ":imap_uid", SQLITE_INTEGER, { .i = cdata->imap_uid } },
	{ ":ical_uid", SQLITE_TEXT, { .s = cdata->ical_uid } },
	{ ":comp_type", SQLITE_INTEGER, { .i = cdata->comp_type } },
	{ ":organizer", SQLITE_TEXT, { .s = cdata->organizer } },
	{ ":sched_tag", SQLITE_TEXT, { .s = cdata->sched_tag } },
	{ ":dtstart", SQLITE_TEXT, { .s = cdata->dtstart } },
	{ ":dtend", SQLITE_TEXT, { .s = cdata->dtend } },
	{ ":recurring:", SQLITE_INTEGER, { .i = cdata->recurring } },
	{ ":transp", SQLITE_INTEGER, { .i = cdata->transp } },
	{ NULL, SQLITE_NULL, { .s = NULL } },
	{ NULL, SQLITE_NULL, { .s = NULL } },
	{ NULL, SQLITE_NULL, { .s = NULL } } };
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
	{ NULL, SQLITE_NULL, { .s = NULL } } };

    return dav_exec(caldavdb->db, CMD_DELETE, bval, NULL, NULL,
		    &caldavdb->stmt[STMT_DELETE]);
}


#define CMD_DELMBOX "DELETE FROM ical_objs WHERE mailbox = :mailbox;"

int caldav_delmbox(struct caldav_db *caldavdb, const char *mailbox)
{
    struct bind_val bval[] = {
	{ ":mailbox", SQLITE_TEXT, { .s = mailbox } },
	{ NULL, SQLITE_NULL, { .s = NULL } } };

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
