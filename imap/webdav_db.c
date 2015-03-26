/* webdav_db.c -- implementation of per-user WebDAV database
 *
 * Copyright (c) 1994-2015 Carnegie Mellon University.  All rights reserved.
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

#include "webdav_db.h"
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

struct webdav_db {
    sqlite3 *db;			/* DB handle */
    char *userid;
    sqlite3_stmt *stmt[NUM_STMT];	/* prepared statements */
    struct buf mailbox;			/* buffers for copies of column text */
    struct buf resource;
    struct buf lock_token;
    struct buf lock_owner;
    struct buf lock_ownerid;
    struct buf filename;
    struct buf type;
    struct buf subtype;
    struct buf res_uid;
    unsigned ref_count;
};


EXPORTED int webdav_init(void)
{
    return dav_init();
}


EXPORTED int webdav_done(void)
{
    return dav_done();
}

/* Open DAV DB corresponding to userid */
EXPORTED struct webdav_db *webdav_open_userid(const char *userid)
{
    struct webdav_db *webdavdb = NULL;

    sqlite3 *db = dav_open_userid(userid);
    if (!db) return NULL;

    webdavdb = xzmalloc(sizeof(struct webdav_db));
    webdavdb->userid = xstrdup(userid);
    webdavdb->db = db;

    return webdavdb;
}

/* Open DAV DB corresponding to mailbox */
EXPORTED struct webdav_db *webdav_open_mailbox(struct mailbox *mailbox)
{
    struct webdav_db *webdavdb = NULL;
    const char *userid = mboxname_to_userid(mailbox->name);

    if (userid)
	return webdav_open_userid(userid);

    sqlite3 *db = dav_open_mailbox(mailbox);
    if (!db) return NULL;

    webdavdb = xzmalloc(sizeof(struct webdav_db));
    webdavdb->userid = xstrdup(userid);
    webdavdb->db = db;

    return webdavdb;
}

/* Close DAV DB */
EXPORTED int webdav_close(struct webdav_db *webdavdb)
{
    int i, r = 0;

    if (!webdavdb) return 0;

    buf_free(&webdavdb->mailbox);
    buf_free(&webdavdb->resource);
    buf_free(&webdavdb->lock_token);
    buf_free(&webdavdb->lock_owner);
    buf_free(&webdavdb->lock_ownerid);
    buf_free(&webdavdb->filename);
    buf_free(&webdavdb->type);
    buf_free(&webdavdb->subtype);
    buf_free(&webdavdb->res_uid);

    for (i = 0; i < NUM_STMT; i++) {
	sqlite3_stmt *stmt = webdavdb->stmt[i];
	if (stmt) sqlite3_finalize(stmt);
    }

    r = dav_close(webdavdb->db);

    free(webdavdb->userid);
    free(webdavdb);

    return r;
}


#define CMD_BEGIN "BEGIN TRANSACTION;"

EXPORTED int webdav_begin(struct webdav_db *webdavdb)
{
    return dav_exec(webdavdb->db, CMD_BEGIN, NULL, NULL, NULL,
		    &webdavdb->stmt[STMT_BEGIN]);
}


#define CMD_COMMIT "COMMIT TRANSACTION;"

EXPORTED int webdav_commit(struct webdav_db *webdavdb)
{
    return dav_exec(webdavdb->db, CMD_COMMIT, NULL, NULL, NULL,
		    &webdavdb->stmt[STMT_COMMIT]);
}


#define CMD_ROLLBACK "ROLLBACK TRANSACTION;"

EXPORTED int webdav_abort(struct webdav_db *webdavdb)
{
    return dav_exec(webdavdb->db, CMD_ROLLBACK, NULL, NULL, NULL,
		    &webdavdb->stmt[STMT_ROLLBACK]);
}


struct read_rock {
    struct webdav_db *db;
    struct webdav_data *wdata;
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
    struct webdav_db *db = rrock->db;
    struct webdav_data *wdata = rrock->wdata;
    int r = 0;

    memset(wdata, 0, sizeof(struct webdav_data));

    wdata->dav.rowid = sqlite3_column_int(stmt, 0);
    wdata->dav.creationdate = sqlite3_column_int(stmt, 1);
    wdata->dav.imap_uid = sqlite3_column_int(stmt, 4);
    wdata->dav.lock_expire = sqlite3_column_int(stmt, 8);
    wdata->ref_count = sqlite3_column_int(stmt, 13);

    if (rrock->cb) {
	/* We can use the column data directly for the callback */
	wdata->dav.mailbox = (const char *) sqlite3_column_text(stmt, 2);
	wdata->dav.resource = (const char *) sqlite3_column_text(stmt, 3);
	wdata->dav.lock_token = (const char *) sqlite3_column_text(stmt, 5);
	wdata->dav.lock_owner = (const char *) sqlite3_column_text(stmt, 6);
	wdata->dav.lock_ownerid = (const char *) sqlite3_column_text(stmt, 7);
	wdata->filename = (const char *) sqlite3_column_text(stmt, 9);
	wdata->type = (const char *) sqlite3_column_text(stmt, 10);
	wdata->subtype = (const char *) sqlite3_column_text(stmt, 11);
	wdata->res_uid = (const char *) sqlite3_column_text(stmt, 12);
	r = rrock->cb(rrock->rock, wdata);
    }
    else {
	/* For single row SELECTs like webdav_read(),
	 * we need to make a copy of the column data before
	 * it gets flushed by sqlite3_step() or sqlite3_reset() */
	wdata->dav.mailbox =
	    column_text_to_buf((const char *) sqlite3_column_text(stmt, 2),
			       &db->mailbox);
	wdata->dav.resource =
	    column_text_to_buf((const char *) sqlite3_column_text(stmt, 3),
			       &db->resource);
	wdata->dav.lock_token =
	    column_text_to_buf((const char *) sqlite3_column_text(stmt, 5),
			       &db->lock_token);
	wdata->dav.lock_owner =
	    column_text_to_buf((const char *) sqlite3_column_text(stmt, 6),
			       &db->lock_owner);
	wdata->dav.lock_ownerid =
	    column_text_to_buf((const char *) sqlite3_column_text(stmt, 7),
			       &db->lock_ownerid);
	wdata->filename =
	    column_text_to_buf((const char *) sqlite3_column_text(stmt, 9),
			       &db->filename);
	wdata->type =
	    column_text_to_buf((const char *) sqlite3_column_text(stmt, 10),
			       &db->type);
	wdata->subtype =
	    column_text_to_buf((const char *) sqlite3_column_text(stmt, 11),
			       &db->subtype);
	wdata->res_uid =
	    column_text_to_buf((const char *) sqlite3_column_text(stmt, 12),
			       &db->res_uid);
    }

    return r;
}


#define CMD_SELRSRC							\
    "SELECT rowid, creationdate, mailbox, resource, imap_uid,"		\
    "  lock_token, lock_owner, lock_ownerid, lock_expire,"		\
    "  filename, type, subtype, res_uid, ref_count"			\
    " FROM dav_objs"							\
    " WHERE ( mailbox = :mailbox AND resource = :resource );"

EXPORTED int webdav_lookup_resource(struct webdav_db *webdavdb,
				    const char *mailbox, const char *resource,
				    int lock, struct webdav_data **result)
{
    struct bind_val bval[] = {
	{ ":mailbox",  SQLITE_TEXT, { .s = mailbox	 } },
	{ ":resource", SQLITE_TEXT, { .s = resource	 } },
	{ NULL,	       SQLITE_NULL, { .s = NULL		 } } };
    static struct webdav_data wdata;
    struct read_rock rrock = { webdavdb, &wdata, NULL, NULL };
    int r;

    *result = memset(&wdata, 0, sizeof(struct webdav_data));

    if (lock) {
	/* begin a transaction */
	r = dav_exec(webdavdb->db, CMD_BEGIN, NULL, NULL, NULL,
		     &webdavdb->stmt[STMT_BEGIN]);
	if (r) return r;
    }

    r = dav_exec(webdavdb->db, CMD_SELRSRC, bval, &read_cb, &rrock,
		 &webdavdb->stmt[STMT_SELRSRC]);
    if (!r && !wdata.dav.rowid) r = CYRUSDB_NOTFOUND;

    return r;
}


#define CMD_SELUID							\
    "SELECT rowid, creationdate, mailbox, resource, imap_uid,"		\
    "  lock_token, lock_owner, lock_ownerid, lock_expire,"		\
    "  filename, type, subtype, res_uid, ref_count"			\
    " FROM dav_objs"							\
    " WHERE ( res_uid = :res_uid );"

EXPORTED int webdav_lookup_uid(struct webdav_db *webdavdb, const char *res_uid,
			       int lock, struct webdav_data **result)
{
    struct bind_val bval[] = {
	{ ":res_uid",    SQLITE_TEXT, { .s = res_uid		 } },
	{ NULL,	         SQLITE_NULL, { .s = NULL		 } } };
    static struct webdav_data wdata;
    struct read_rock rrock = { webdavdb, &wdata, NULL, NULL };
    int r;

    *result = memset(&wdata, 0, sizeof(struct webdav_data));

    if (lock) {
	/* begin a transaction */
	r = dav_exec(webdavdb->db, CMD_BEGIN, NULL, NULL, NULL,
		     &webdavdb->stmt[STMT_BEGIN]);
	if (r) return r;
    }

    r = dav_exec(webdavdb->db, CMD_SELUID, bval, &read_cb, &rrock,
		 &webdavdb->stmt[STMT_SELUID]);
    if (!r && !wdata.dav.rowid) r = CYRUSDB_NOTFOUND;

    return r;
}


#define CMD_SELMBOX							\
    "SELECT rowid, creationdate, mailbox, resource, imap_uid,"		\
    "  lock_token, lock_owner, lock_ownerid, lock_expire,"		\
    "  filename, type, subtype, res_uid, ref_count"			\
    " FROM dav_objs WHERE mailbox = :mailbox;"

EXPORTED int webdav_foreach(struct webdav_db *webdavdb, const char *mailbox,
			    int (*cb)(void *rock, void *data),
			    void *rock)
{
    struct bind_val bval[] = {
	{ ":mailbox", SQLITE_TEXT, { .s = mailbox } },
	{ NULL,	      SQLITE_NULL, { .s = NULL    } } };
    struct webdav_data wdata;
    struct read_rock rrock = { webdavdb, &wdata, cb, rock };

    return dav_exec(webdavdb->db, CMD_SELMBOX, bval, &read_cb, &rrock,
		    &webdavdb->stmt[STMT_SELMBOX]);
}


#define CMD_INSERT							\
    "INSERT INTO dav_objs ("						\
    "  creationdate, mailbox, resource, imap_uid,"			\
    "  lock_token, lock_owner, lock_ownerid, lock_expire,"		\
    "  filename, type, subtype, res_uid, ref_count )"			\
    " VALUES ("								\
    "  :creationdate, :mailbox, :resource, :imap_uid,"			\
    "  :lock_token, :lock_owner, :lock_ownerid, :lock_expire,"		\
    "  :filename, :type, :subtype, :res_uid, :ref_count );"

#define CMD_UPDATE		   	\
    "UPDATE dav_objs SET"		\
    "  imap_uid     = :imap_uid,"	\
    "  lock_token   = :lock_token,"	\
    "  lock_owner   = :lock_owner,"	\
    "  lock_ownerid = :lock_ownerid,"	\
    "  lock_expire  = :lock_expire,"	\
    "  filename     = :filename,"	\
    "  type         = :type,"		\
    "  subtype      = :subtype,"	\
    "  res_uid      = :res_uid,"	\
    "  ref_count    = :ref_count"	\
    " WHERE rowid = :rowid;"

EXPORTED int webdav_write(struct webdav_db *webdavdb, struct webdav_data *wdata,
			  int commit)
{
    struct bind_val bval[] = {
	{ ":imap_uid",	   SQLITE_INTEGER, { .i = wdata->dav.imap_uid	  } },
	{ ":lock_token",   SQLITE_TEXT,	   { .s = wdata->dav.lock_token	  } },
	{ ":lock_owner",   SQLITE_TEXT,	   { .s = wdata->dav.lock_owner	  } },
	{ ":lock_ownerid", SQLITE_TEXT,	   { .s = wdata->dav.lock_ownerid } },
	{ ":lock_expire",  SQLITE_INTEGER, { .i = wdata->dav.lock_expire  } },
	{ ":filename",	   SQLITE_TEXT,	   { .s = wdata->filename	  } },
	{ ":type",	   SQLITE_TEXT,	   { .s = wdata->type		  } },
	{ ":subtype",	   SQLITE_TEXT,	   { .s = wdata->subtype	  } },
	{ ":res_uid",	   SQLITE_TEXT,	   { .s = wdata->res_uid	  } },
	{ ":ref_count",	   SQLITE_INTEGER, { .i = wdata->ref_count	  } },
	{ NULL,		   SQLITE_NULL,	   { .s = NULL			  } },
	{ NULL,		   SQLITE_NULL,	   { .s = NULL			  } },
	{ NULL,		   SQLITE_NULL,	   { .s = NULL			  } },
	{ NULL,		   SQLITE_NULL,	   { .s = NULL			  } } };
    const char *cmd;
    sqlite3_stmt **stmt;
    int r;

    if (wdata->dav.rowid) {
	cmd = CMD_UPDATE;
	stmt = &webdavdb->stmt[STMT_UPDATE];

	bval[10].name = ":rowid";
	bval[10].type = SQLITE_INTEGER;
	bval[10].val.i = wdata->dav.rowid;
    }
    else {
	cmd = CMD_INSERT;
	stmt = &webdavdb->stmt[STMT_INSERT];

	bval[10].name = ":creationdate";
	bval[10].type = SQLITE_INTEGER;
	bval[10].val.i = wdata->dav.creationdate;
	bval[11].name = ":mailbox";
	bval[11].type = SQLITE_TEXT;
	bval[11].val.s = wdata->dav.mailbox;
	bval[12].name = ":resource";
	bval[12].type = SQLITE_TEXT;
	bval[12].val.s = wdata->dav.resource;
    }

    r = dav_exec(webdavdb->db, cmd, bval, NULL, NULL, stmt);

    if (!r && commit) {
	/* commit transaction */
	return dav_exec(webdavdb->db, CMD_COMMIT, NULL, NULL, NULL,
			&webdavdb->stmt[STMT_COMMIT]);
    }

    return r;
}


#define CMD_DELETE "DELETE FROM dav_objs WHERE rowid = :rowid;"

EXPORTED int webdav_delete(struct webdav_db *webdavdb, unsigned rowid,
			   int commit)
{
    struct bind_val bval[] = {
	{ ":rowid", SQLITE_INTEGER, { .i = rowid } },
	{ NULL,	    SQLITE_NULL,    { .s = NULL  } } };
    int r;

    r = dav_exec(webdavdb->db, CMD_DELETE, bval, NULL, NULL,
		 &webdavdb->stmt[STMT_DELETE]);

    if (!r && commit) {
	/* commit transaction */
	return dav_exec(webdavdb->db, CMD_COMMIT, NULL, NULL, NULL,
			&webdavdb->stmt[STMT_COMMIT]);
    }	

    return r;
}


#define CMD_DELMBOX "DELETE FROM dav_objs WHERE mailbox = :mailbox;"

EXPORTED int webdav_delmbox(struct webdav_db *webdavdb, const char *mailbox,
			    int commit)
{
    struct bind_val bval[] = {
	{ ":mailbox", SQLITE_TEXT, { .s = mailbox } },
	{ NULL,	      SQLITE_NULL, { .s = NULL    } } };
    int r;

    r = dav_exec(webdavdb->db, CMD_DELMBOX, bval, NULL, NULL,
		 &webdavdb->stmt[STMT_DELMBOX]);

    if (!r && commit) {
	/* commit transaction */
	return dav_exec(webdavdb->db, CMD_COMMIT, NULL, NULL, NULL,
			&webdavdb->stmt[STMT_COMMIT]);
    }	

    return r;
}

#else

EXPORTED int webdav_init(void)
{
    return 0;
}


EXPORTED int webdav_done(void)
{
    return 0;
}

#endif /* WITH_DAV */
