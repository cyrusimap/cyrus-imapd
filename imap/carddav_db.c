/* carddav_db.c -- implementation of per-user CardDAV database
 *
 * Copyright (c) 1994-2013 Carnegie Mellon University.  All rights reserved.
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

#include "carddav_db.h"
#include "cyrusdb.h"
#include "httpd.h"
#include "http_dav.h"
#include "libconfig.h"
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

struct carddav_db {
    sqlite3 *db;			/* DB handle */
    sqlite3_stmt *stmt[NUM_STMT];	/* prepared statements */
    struct buf mailbox;			/* buffers for copies of column text */
    struct buf resource;
    struct buf lock_token;
    struct buf lock_owner;
    struct buf lock_ownerid;
    struct buf vcard_uid;
    struct buf fullname;
    struct buf name;
    struct buf nickname;
    struct buf email;
};


int carddav_init(void)
{
    return dav_init();
}


int carddav_done(void)
{
    return dav_done();
}


#define CMD_DROP "DROP TABLE IF EXISTS vcard_objs;"

#define CMD_CREATE							\
    "CREATE TABLE IF NOT EXISTS vcard_objs ("				\
    " rowid INTEGER PRIMARY KEY,"					\
    " creationdate INTEGER,"						\
    " mailbox TEXT NOT NULL,"						\
    " resource TEXT NOT NULL,"						\
    " imap_uid INTEGER,"						\
    " lock_token TEXT,"							\
    " lock_owner TEXT,"							\
    " lock_ownerid TEXT,"						\
    " lock_expire INTEGER,"						\
    " version INTEGER,"							\
    " vcard_uid TEXT,"							\
    " kind INTEGER,"							\
    " fullname TEXT,"							\
    " name TEXT,"							\
    " nickname TEXT,"							\
    " email TEXT,"							\
    " UNIQUE( mailbox, resource ) );"					\
    "CREATE INDEX IF NOT EXISTS idx_vcard_uid ON vcard_objs ( vcard_uid );"

/* Open DAV DB corresponding to mailbox */
struct carddav_db *carddav_open(struct mailbox *mailbox, int flags)
{
    sqlite3 *db;
    struct carddav_db *carddavdb = NULL;
    const char *cmds = CMD_CREATE;

    if (flags & CARDDAV_TRUNC) cmds = CMD_DROP CMD_CREATE;

    db = dav_open(mailbox, cmds);

    if (db) {
	carddavdb = xzmalloc(sizeof(struct carddav_db));
	carddavdb->db = db;
    }

    return carddavdb;
}


/* Close DAV DB */
int carddav_close(struct carddav_db *carddavdb)
{
    int i, r = 0;

    if (!carddavdb) return 0;

    buf_free(&carddavdb->mailbox);
    buf_free(&carddavdb->resource);
    buf_free(&carddavdb->lock_token);
    buf_free(&carddavdb->lock_owner);
    buf_free(&carddavdb->lock_ownerid);
    buf_free(&carddavdb->vcard_uid);
    buf_free(&carddavdb->fullname);
    buf_free(&carddavdb->name);
    buf_free(&carddavdb->nickname);
    buf_free(&carddavdb->email);

    for (i = 0; i < NUM_STMT; i++) {
	sqlite3_stmt *stmt = carddavdb->stmt[i];
	if (stmt) sqlite3_finalize(stmt);
    }

    r = dav_close(carddavdb->db);

    free(carddavdb);

    return r;
}


#define CMD_BEGIN "BEGIN TRANSACTION;"

int carddav_begin(struct carddav_db *carddavdb)
{
    return dav_exec(carddavdb->db, CMD_BEGIN, NULL, NULL, NULL,
		    &carddavdb->stmt[STMT_BEGIN]);
}


#define CMD_COMMIT "COMMIT TRANSACTION;"

int carddav_commit(struct carddav_db *carddavdb)
{
    return dav_exec(carddavdb->db, CMD_COMMIT, NULL, NULL, NULL,
		    &carddavdb->stmt[STMT_COMMIT]);
}


#define CMD_ROLLBACK "ROLLBACK TRANSACTION;"

int carddav_abort(struct carddav_db *carddavdb)
{
    return dav_exec(carddavdb->db, CMD_ROLLBACK, NULL, NULL, NULL,
		    &carddavdb->stmt[STMT_ROLLBACK]);
}


struct read_rock {
    struct carddav_db *db;
    struct carddav_data *cdata;
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
    struct carddav_db *db = rrock->db;
    struct carddav_data *cdata = rrock->cdata;
    int r = 0;

    memset(cdata, 0, sizeof(struct carddav_data));

    cdata->dav.rowid = sqlite3_column_int(stmt, 0);
    cdata->dav.creationdate = sqlite3_column_int(stmt, 1);
    cdata->dav.imap_uid = sqlite3_column_int(stmt, 4);
    cdata->dav.lock_expire = sqlite3_column_int(stmt, 8);
    cdata->version = sqlite3_column_int(stmt, 9);
    cdata->kind = sqlite3_column_int(stmt, 11);

    if (rrock->cb) {
	/* We can use the column data directly for the callback */
	cdata->dav.mailbox = (const char *) sqlite3_column_text(stmt, 2);
	cdata->dav.resource = (const char *) sqlite3_column_text(stmt, 3);
	cdata->dav.lock_token = (const char *) sqlite3_column_text(stmt, 5);
	cdata->dav.lock_owner = (const char *) sqlite3_column_text(stmt, 6);
	cdata->dav.lock_ownerid = (const char *) sqlite3_column_text(stmt, 7);
	cdata->vcard_uid = (const char *) sqlite3_column_text(stmt, 10);
	cdata->fullname = (const char *) sqlite3_column_text(stmt, 12);
	cdata->name = (const char *) sqlite3_column_text(stmt, 13);
	cdata->nickname = (const char *) sqlite3_column_text(stmt, 14);
	cdata->email = (const char *) sqlite3_column_text(stmt, 15);
	r = rrock->cb(rrock->rock, cdata);
    }
    else {
	/* For single row SELECTs like carddav_read(),
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
	cdata->vcard_uid =
	    column_text_to_buf((const char *) sqlite3_column_text(stmt, 10),
			       &db->vcard_uid);
	cdata->fullname =
	    column_text_to_buf((const char *) sqlite3_column_text(stmt, 12),
			       &db->fullname);
	cdata->name =
	    column_text_to_buf((const char *) sqlite3_column_text(stmt, 13),
			       &db->name);
	cdata->nickname =
	    column_text_to_buf((const char *) sqlite3_column_text(stmt, 14),
			       &db->nickname);
	cdata->email =
	    column_text_to_buf((const char *) sqlite3_column_text(stmt, 15),
			       &db->email);
    }

    return r;
}


#define CMD_SELRSRC							\
    "SELECT rowid, creationdate, mailbox, resource, imap_uid,"		\
    "  lock_token, lock_owner, lock_ownerid, lock_expire,"		\
    "  version, vcard_uid, kind, fullname, name, nickname, email"	\
    " FROM vcard_objs"							\
    " WHERE ( mailbox = :mailbox AND resource = :resource );"

int carddav_lookup_resource(struct carddav_db *carddavdb,
			   const char *mailbox, const char *resource,
			   int lock, struct carddav_data **result)
{
    struct bind_val bval[] = {
	{ ":mailbox",  SQLITE_TEXT, { .s = mailbox	 } },
	{ ":resource", SQLITE_TEXT, { .s = resource	 } },
	{ NULL,	       SQLITE_NULL, { .s = NULL		 } } };
    static struct carddav_data cdata;
    struct read_rock rrock = { carddavdb, &cdata, NULL, NULL };
    int r;

    *result = memset(&cdata, 0, sizeof(struct carddav_data));

    if (lock) {
	/* begin a transaction */
	r = dav_exec(carddavdb->db, CMD_BEGIN, NULL, NULL, NULL,
		     &carddavdb->stmt[STMT_BEGIN]);
	if (r) return r;
    }

    r = dav_exec(carddavdb->db, CMD_SELRSRC, bval, &read_cb, &rrock,
		 &carddavdb->stmt[STMT_SELRSRC]);
    if (!r && !cdata.dav.rowid) r = CYRUSDB_NOTFOUND;

    return r;
}


#define CMD_SELUID							\
    "SELECT rowid, creationdate, mailbox, resource, imap_uid,"		\
    "  lock_token, lock_owner, lock_ownerid, lock_expire,"		\
    "  version, vcard_uid, kind, fullname, name, nickname, email"	\
    " FROM vcard_objs"							\
    " WHERE ( vcard_uid = :vcard_uid );"

int carddav_lookup_uid(struct carddav_db *carddavdb, const char *vcard_uid,
		      int lock, struct carddav_data **result)
{
    struct bind_val bval[] = {
	{ ":vcard_uid", SQLITE_TEXT, { .s = vcard_uid		 } },
	{ NULL,	        SQLITE_NULL, { .s = NULL		 } } };
    static struct carddav_data cdata;
    struct read_rock rrock = { carddavdb, &cdata, NULL, NULL };
    int r;

    *result = memset(&cdata, 0, sizeof(struct carddav_data));

    if (lock) {
	/* begin a transaction */
	r = dav_exec(carddavdb->db, CMD_BEGIN, NULL, NULL, NULL,
		     &carddavdb->stmt[STMT_BEGIN]);
	if (r) return r;
    }

    r = dav_exec(carddavdb->db, CMD_SELUID, bval, &read_cb, &rrock,
		 &carddavdb->stmt[STMT_SELUID]);
    if (!r && !cdata.dav.rowid) r = CYRUSDB_NOTFOUND;

    return r;
}


#define CMD_SELMBOX							\
    "SELECT rowid, creationdate, mailbox, resource, imap_uid,"		\
    "  lock_token, lock_owner, lock_ownerid, lock_expire,"		\
    "  version, vcard_uid, kind, fullname, name, nickname, email"	\
    " FROM vcard_objs WHERE mailbox = :mailbox;"

int carddav_foreach(struct carddav_db *carddavdb, const char *mailbox,
		   int (*cb)(void *rock, void *data),
		   void *rock)
{
    struct bind_val bval[] = {
	{ ":mailbox", SQLITE_TEXT, { .s = mailbox } },
	{ NULL,	      SQLITE_NULL, { .s = NULL    } } };
    struct carddav_data cdata;
    struct read_rock rrock = { carddavdb, &cdata, cb, rock };

    return dav_exec(carddavdb->db, CMD_SELMBOX, bval, &read_cb, &rrock,
		    &carddavdb->stmt[STMT_SELMBOX]);
}


#define CMD_INSERT							\
    "INSERT INTO vcard_objs ("						\
    "  creationdate, mailbox, resource, imap_uid,"			\
    "  lock_token, lock_owner, lock_ownerid, lock_expire,"		\
    "  version, vcard_uid, kind, fullname, name, nickname, email )" 	\
    " VALUES ("								\
    "  :creationdate, :mailbox, :resource, :imap_uid,"			\
    "  :lock_token, :lock_owner, :lock_ownerid, :lock_expire,"		\
    "  :version, :vcard_uid, :kind, :fullname, :name, :nickname, :email );"

#define CMD_UPDATE		   	\
    "UPDATE vcard_objs SET"		\
    "  imap_uid     = :imap_uid,"	\
    "  lock_token   = :lock_token,"	\
    "  lock_owner   = :lock_owner,"	\
    "  lock_ownerid = :lock_ownerid,"	\
    "  lock_expire  = :lock_expire,"	\
    "  version      = :comp_type,"	\
    "  vcard_uid    = :vcard_uid,"	\
    "  kind         = :kind,"		\
    "  fullname     = :fullname,"	\
    "  name         = :name,"		\
    "  nickname     = :nickname,"	\
    "  email        = :email"		\
    " WHERE rowid = :rowid;"

int carddav_write(struct carddav_db *carddavdb, struct carddav_data *cdata,
		 int commit)
{
    struct bind_val bval[] = {
	{ ":imap_uid",	   SQLITE_INTEGER, { .i = cdata->dav.imap_uid	  } },
	{ ":lock_token",   SQLITE_TEXT,	   { .s = cdata->dav.lock_token	  } },
	{ ":lock_owner",   SQLITE_TEXT,	   { .s = cdata->dav.lock_owner	  } },
	{ ":lock_ownerid", SQLITE_TEXT,	   { .s = cdata->dav.lock_ownerid } },
	{ ":lock_expire",  SQLITE_INTEGER, { .i = cdata->dav.lock_expire  } },
	{ ":version",	   SQLITE_INTEGER, { .i = cdata->version	  } },
	{ ":vcard_uid",	   SQLITE_TEXT,	   { .s = cdata->vcard_uid	  } },
	{ ":kind",	   SQLITE_INTEGER, { .i = cdata->kind		  } },
	{ ":fullname",	   SQLITE_TEXT,	   { .s = cdata->fullname	  } },
	{ ":name",	   SQLITE_TEXT,	   { .s = cdata->name		  } },
	{ ":nickname",	   SQLITE_TEXT,	   { .s = cdata->nickname	  } },
	{ ":email",	   SQLITE_TEXT,	   { .s = cdata->email		  } },
	{ NULL,		   SQLITE_NULL,	   { .s = NULL			  } },
	{ NULL,		   SQLITE_NULL,	   { .s = NULL			  } },
	{ NULL,		   SQLITE_NULL,	   { .s = NULL			  } },
	{ NULL,		   SQLITE_NULL,	   { .s = NULL			  } } };
    const char *cmd;
    sqlite3_stmt **stmt;
    int r;

    if (cdata->dav.rowid) {
	cmd = CMD_UPDATE;
	stmt = &carddavdb->stmt[STMT_UPDATE];

	bval[12].name = ":rowid";
	bval[12].type = SQLITE_INTEGER;
	bval[12].val.i = cdata->dav.rowid;
    }
    else {
	cmd = CMD_INSERT;
	stmt = &carddavdb->stmt[STMT_INSERT];

	bval[12].name = ":creationdate";
	bval[12].type = SQLITE_INTEGER;
	bval[12].val.i = cdata->dav.creationdate;
	bval[13].name = ":mailbox";
	bval[13].type = SQLITE_TEXT;
	bval[13].val.s = cdata->dav.mailbox;
	bval[14].name = ":resource";
	bval[14].type = SQLITE_TEXT;
	bval[14].val.s = cdata->dav.resource;
    }

    r = dav_exec(carddavdb->db, cmd, bval, NULL, NULL, stmt);

    if (!r && commit) {
	/* commit transaction */
	return dav_exec(carddavdb->db, CMD_COMMIT, NULL, NULL, NULL,
			&carddavdb->stmt[STMT_COMMIT]);
    }

    return r;
}


#define CMD_DELETE "DELETE FROM vcard_objs WHERE rowid = :rowid;"

int carddav_delete(struct carddav_db *carddavdb, unsigned rowid, int commit)
{
    struct bind_val bval[] = {
	{ ":rowid", SQLITE_INTEGER, { .i = rowid } },
	{ NULL,	    SQLITE_NULL,    { .s = NULL  } } };
    int r;

    r = dav_exec(carddavdb->db, CMD_DELETE, bval, NULL, NULL,
		 &carddavdb->stmt[STMT_DELETE]);

    if (!r && commit) {
	/* commit transaction */
	return dav_exec(carddavdb->db, CMD_COMMIT, NULL, NULL, NULL,
			&carddavdb->stmt[STMT_COMMIT]);
    }	

    return r;
}


#define CMD_DELMBOX "DELETE FROM vcard_objs WHERE mailbox = :mailbox;"

int carddav_delmbox(struct carddav_db *carddavdb, const char *mailbox, int commit)
{
    struct bind_val bval[] = {
	{ ":mailbox", SQLITE_TEXT, { .s = mailbox } },
	{ NULL,	      SQLITE_NULL, { .s = NULL    } } };
    int r;

    r = dav_exec(carddavdb->db, CMD_DELMBOX, bval, NULL, NULL,
		 &carddavdb->stmt[STMT_DELMBOX]);

    if (!r && commit) {
	/* commit transaction */
	return dav_exec(carddavdb->db, CMD_COMMIT, NULL, NULL, NULL,
			&carddavdb->stmt[STMT_COMMIT]);
    }	

    return r;
}

#else

int carddav_init(void)
{
    return 0;
}


int carddav_done(void)
{
    return 0;
}

#endif /* WITH_DAV */
