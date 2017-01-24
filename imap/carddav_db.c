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
    STMT_DELETE,
    STMT_DELMBOX,
    STMT_BEGIN,
    STMT_COMMIT,
    STMT_ROLLBACK,
    STMT_INSERT_EMAIL,
    STMT_INSERT_GROUP,
    STMT_GETEMAIL,
    STMT_GETGROUP,
    NUM_STMT
};

#define NUM_BUFS 10

struct carddav_db {
    sqlite3 *db;			/* DB handle */
    sqlite3_stmt *stmt[NUM_STMT];	/* prepared statements */
    struct buf bufs[NUM_BUFS];		/* buffers for copies of column text */
};


EXPORTED int carddav_init(void)
{
    return dav_init();
}


EXPORTED int carddav_done(void)
{
    return dav_done();
}


#define CMD_DROP_OBJ "DROP TABLE IF EXISTS vcard_objs;"

#define CMD_CREATE_OBJ							\
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
    " UNIQUE( mailbox, resource ) );"					\
    "CREATE INDEX IF NOT EXISTS idx_vcard_fn ON vcard_objs ( fullname );" \
    "CREATE INDEX IF NOT EXISTS idx_vcard_uid ON vcard_objs ( vcard_uid );"

#define CMD_DROP_EM "DROP TABLE IF EXISTS vcard_emails;"

#define CMD_CREATE_EM							\
    "CREATE TABLE IF NOT EXISTS vcard_emails ("				\
    " rowid INTEGER PRIMARY KEY,"					\
    " objid INTEGER,"							\
    " pos INTEGER NOT NULL," /* for sorting */				\
    " email TEXT NOT NULL,"						\
    " FOREIGN KEY (objid) REFERENCES vcard_objs (rowid) ON DELETE CASCADE );" \
    "CREATE INDEX IF NOT EXISTS idx_vcard_email ON vcard_emails ( email );"

#define CMD_DROP_GR "DROP TABLE IF EXISTS vcard_groups;"

#define CMD_CREATE_GR							\
    "CREATE TABLE IF NOT EXISTS vcard_groups ("				\
    " rowid INTEGER PRIMARY KEY,"					\
    " objid INTEGER,"							\
    " pos INTEGER NOT NULL," /* for sorting */				\
    " member_uid TEXT NOT NULL,"					\
    " FOREIGN KEY (objid) REFERENCES vcard_objs (rowid) ON DELETE CASCADE );"

#define CMD_DROP CMD_DROP_OBJ CMD_DROP_EM CMD_DROP_GR
#define CMD_CREATE CMD_CREATE_OBJ CMD_CREATE_EM CMD_CREATE_GR

/* Open DAV DB corresponding to mailbox */
static struct carddav_db *carddav_open_fname(const char *fname, int flags)
{
    sqlite3 *db;
    struct carddav_db *carddavdb = NULL;
    const char *cmds = CMD_CREATE;

    if (flags & CARDDAV_TRUNC) cmds = CMD_DROP CMD_CREATE;

    db = dav_open(fname, cmds);

    if (db) {
	carddavdb = xzmalloc(sizeof(struct carddav_db));
	carddavdb->db = db;
    }

    return carddavdb;
}

EXPORTED struct carddav_db *carddav_open_userid(const char *userid, int flags)
{
    struct buf fname = BUF_INITIALIZER;
    struct carddav_db *carddavdb = NULL;

    dav_getpath_byuserid(&fname, userid);
    carddavdb = carddav_open_fname(buf_cstring(&fname), flags);
    buf_free(&fname);

    return carddavdb;
}

EXPORTED struct carddav_db *carddav_open_mailbox(struct mailbox *mailbox, int flags)
{
    struct buf fname = BUF_INITIALIZER;
    struct carddav_db *carddavdb = NULL;

    dav_getpath(&fname, mailbox);
    carddavdb = carddav_open_fname(buf_cstring(&fname), flags);
    buf_free(&fname);

    return carddavdb;
}


/* Close DAV DB */
EXPORTED int carddav_close(struct carddav_db *carddavdb)
{
    int i, r = 0;

    if (!carddavdb) return 0;

    for (i = 0; i < NUM_BUFS; i++) {
	buf_free(&carddavdb->bufs[i]);
    }

    for (i = 0; i < NUM_STMT; i++) {
	sqlite3_stmt *stmt = carddavdb->stmt[i];
	if (stmt) sqlite3_finalize(stmt);
    }

    r = dav_close(carddavdb->db);

    free(carddavdb);

    return r;
}


#define CMD_BEGIN "BEGIN TRANSACTION;"

EXPORTED int carddav_begin(struct carddav_db *carddavdb)
{
    return dav_exec(carddavdb->db, CMD_BEGIN, NULL, NULL, NULL,
		    &carddavdb->stmt[STMT_BEGIN]);
}


#define CMD_COMMIT "COMMIT TRANSACTION;"

EXPORTED int carddav_commit(struct carddav_db *carddavdb)
{
    return dav_exec(carddavdb->db, CMD_COMMIT, NULL, NULL, NULL,
		    &carddavdb->stmt[STMT_COMMIT]);
}


#define CMD_ROLLBACK "ROLLBACK TRANSACTION;"

EXPORTED int carddav_abort(struct carddav_db *carddavdb)
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
	r = rrock->cb(rrock->rock, cdata);
    }
    else {
	/* For single row SELECTs like carddav_read(),
	 * we need to make a copy of the column data before
	 * it gets flushed by sqlite3_step() or sqlite3_reset() */
	cdata->dav.mailbox =
	    column_text_to_buf((const char *) sqlite3_column_text(stmt, 2),
			       &db->bufs[0]);
	cdata->dav.resource =
	    column_text_to_buf((const char *) sqlite3_column_text(stmt, 3),
			       &db->bufs[1]);
	cdata->dav.lock_token =
	    column_text_to_buf((const char *) sqlite3_column_text(stmt, 5),
			       &db->bufs[2]);
	cdata->dav.lock_owner =
	    column_text_to_buf((const char *) sqlite3_column_text(stmt, 6),
			       &db->bufs[3]);
	cdata->dav.lock_ownerid =
	    column_text_to_buf((const char *) sqlite3_column_text(stmt, 7),
			       &db->bufs[4]);
	cdata->vcard_uid =
	    column_text_to_buf((const char *) sqlite3_column_text(stmt, 10),
			       &db->bufs[5]);
	cdata->fullname =
	    column_text_to_buf((const char *) sqlite3_column_text(stmt, 12),
			       &db->bufs[6]);
	cdata->name =
	    column_text_to_buf((const char *) sqlite3_column_text(stmt, 13),
			       &db->bufs[7]);
	cdata->nickname =
	    column_text_to_buf((const char *) sqlite3_column_text(stmt, 14),
			       &db->bufs[8]);
    }

    return r;
}


#define CMD_SELRSRC							\
    "SELECT rowid, creationdate, mailbox, resource, imap_uid,"		\
    "  lock_token, lock_owner, lock_ownerid, lock_expire,"		\
    "  version, vcard_uid, kind, fullname, name, nickname"		\
    " FROM vcard_objs"							\
    " WHERE ( mailbox = :mailbox AND resource = :resource );"

EXPORTED int carddav_lookup_resource(struct carddav_db *carddavdb,
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

    /* always mailbox and resource so error paths don't fail */
    cdata.dav.mailbox = mailbox;
    cdata.dav.resource = resource;

    return r;
}


#define CMD_SELUID							\
    "SELECT rowid, creationdate, mailbox, resource, imap_uid,"		\
    "  lock_token, lock_owner, lock_ownerid, lock_expire,"		\
    "  version, vcard_uid, kind, fullname, name, nickname"		\
    " FROM vcard_objs"							\
    " WHERE ( vcard_uid = :vcard_uid );"

EXPORTED int carddav_lookup_uid(struct carddav_db *carddavdb, const char *vcard_uid,
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
    "  version, vcard_uid, kind, fullname, name, nickname"		\
    " FROM vcard_objs WHERE mailbox = :mailbox;"

EXPORTED int carddav_foreach(struct carddav_db *carddavdb, const char *mailbox,
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

#define CMD_GETEMAIL							\
    "SELECT rowid"							\
    " FROM vcard_emails"						\
    " WHERE ( email = :email );"

static int foundemail_cb(sqlite3_stmt *stmt, void *rock)
{
    int *foundp = (int *)rock;
    if (sqlite3_column_int(stmt, 0))
	*foundp = 1;
    return 0;
}

EXPORTED int carddav_getemail(struct carddav_db *carddavdb, const char *email)
{
    struct bind_val bval[] = {
	{ ":email", SQLITE_TEXT, { .s = email } },
	{ NULL,     SQLITE_NULL, { .s = NULL  } }
    };
    int found = 0;
    int r;

    r = dav_exec(carddavdb->db, CMD_GETEMAIL, bval, &foundemail_cb, &found,
		 &carddavdb->stmt[STMT_GETEMAIL]);
    if (r) {
	/* XXX syslog */
    }

    return found;
}

#define CMD_GETGROUP \
    "SELECT E.email FROM vcard_emails E" \
    " JOIN vcard_objs CO JOIN vcard_groups G JOIN vcard_objs GO" \
    " WHERE E.objid = CO.rowid AND CO.vcard_uid = G.member_uid AND G.objid = GO.rowid" \
    " AND E.pos = 0 AND GO.fullname = :group"

static int foundgroup_cb(sqlite3_stmt *stmt, void *rock)
{
    strarray_t *array = (strarray_t *)rock;
    strarray_add(array, (const char *)sqlite3_column_text(stmt, 0));
    return 0;
}

EXPORTED strarray_t *carddav_getgroup(struct carddav_db *carddavdb, const char *group)
{
    struct bind_val bval[] = {
	{ ":group", SQLITE_TEXT, { .s = group } },
	{ NULL,     SQLITE_NULL, { .s = NULL  } }
    };
    strarray_t *found = strarray_new();
    int r;

    r = dav_exec(carddavdb->db, CMD_GETGROUP, bval, &foundgroup_cb, found,
		 &carddavdb->stmt[STMT_GETGROUP]);
    if (r) {
	/* XXX syslog */
    }

    if (!strarray_size(found)) {
	strarray_free(found);
	return NULL;
    }

    return found;
}


#define CMD_INSERT_EMAIL						\
    "INSERT INTO vcard_emails ( objid, pos, email )"			\
    " VALUES ( :objid, :pos, :email );"

/* no commit */
static int carddav_write_emails(struct carddav_db *carddavdb, struct carddav_data *cdata)
{
    struct bind_val bval[] = {
	{ ":objid",	   SQLITE_INTEGER, { .i = cdata->dav.rowid	  } },
	{ ":pos",	   SQLITE_INTEGER, { .i = 0			  } },
	{ ":email",	   SQLITE_TEXT,	   { .s = NULL			  } },
	{ NULL,		   SQLITE_NULL,	   { .s = NULL			  } } };
    int r;
    int i;

    for (i = 0; i < strarray_size(&cdata->emails); i++) {
	bval[1].val.i = i;
	bval[2].val.s = strarray_nth(&cdata->emails, i);
	r = dav_exec(carddavdb->db, CMD_INSERT_EMAIL, bval, NULL, NULL,
		    &carddavdb->stmt[STMT_INSERT_EMAIL]);
	if (r) return r;
    }

    return 0;
}

#define CMD_INSERT_GROUP						\
    "INSERT INTO vcard_groups ( objid, pos, member_uid )"		\
    " VALUES ( :objid, :pos, :member_uid );"

/* no commit */
static int carddav_write_groups(struct carddav_db *carddavdb, struct carddav_data *cdata)
{
    struct bind_val bval[] = {
	{ ":objid",	   SQLITE_INTEGER, { .i = cdata->dav.rowid	  } },
	{ ":pos",	   SQLITE_INTEGER, { .i = 0			  } },
	{ ":member_uid",   SQLITE_TEXT,	   { .s = NULL			  } },
	{ NULL,		   SQLITE_NULL,	   { .s = NULL			  } } };
    int r;
    int i;

    for (i = 0; i < strarray_size(&cdata->member_uids); i++) {
	bval[1].val.i = i;
	bval[2].val.s = strarray_nth(&cdata->member_uids, i);
	r = dav_exec(carddavdb->db, CMD_INSERT_GROUP, bval, NULL, NULL,
		    &carddavdb->stmt[STMT_INSERT_GROUP]);
	if (r) return r;
    }

    return 0;
}

#define CMD_INSERT							\
    "INSERT INTO vcard_objs ("						\
    "  creationdate, mailbox, resource, imap_uid,"			\
    "  lock_token, lock_owner, lock_ownerid, lock_expire,"		\
    "  version, vcard_uid, kind, fullname, name, nickname)"		\
    " VALUES ("								\
    "  :creationdate, :mailbox, :resource, :imap_uid,"			\
    "  :lock_token, :lock_owner, :lock_ownerid, :lock_expire,"		\
    "  :version, :vcard_uid, :kind, :fullname, :name, :nickname );"

EXPORTED int carddav_write(struct carddav_db *carddavdb, struct carddav_data *cdata,
		 int commit)
{
    struct bind_val bval[] = {
	{ ":creationdate", SQLITE_INTEGER, { .i = cdata->dav.creationdate } },
	{ ":mailbox",	   SQLITE_TEXT,	   { .s = cdata->dav.mailbox	  } },
	{ ":resource",	   SQLITE_TEXT,	   { .s = cdata->dav.resource	  } },
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
	{ NULL,		   SQLITE_NULL,	   { .s = NULL			  } } };
    int r;

    if (cdata->dav.rowid) {
	r = carddav_delete(carddavdb, cdata->dav.rowid, /*commit*/0);
	if (r) return r;
    }

    r = dav_exec(carddavdb->db, CMD_INSERT, bval, NULL, NULL,
		 &carddavdb->stmt[STMT_INSERT]);
    if (r) return r;

    cdata->dav.rowid = sqlite3_last_insert_rowid(carddavdb->db);

    r = carddav_write_emails(carddavdb, cdata);
    if (r) return r;

    r = carddav_write_groups(carddavdb, cdata);
    if (r) return r;

    /* commit transaction */
    if (commit) {
	r = carddav_commit(carddavdb);
	if (r) return r;
    }

    return 0;
}


#define CMD_DELETE "DELETE FROM vcard_objs WHERE rowid = :rowid;"

EXPORTED int carddav_delete(struct carddav_db *carddavdb, unsigned rowid, int commit)
{
    struct bind_val bval[] = {
	{ ":rowid", SQLITE_INTEGER, { .i = rowid } },
	{ NULL,	    SQLITE_NULL,    { .s = NULL  } } };
    int r;

    r = dav_exec(carddavdb->db, CMD_DELETE, bval, NULL, NULL,
		 &carddavdb->stmt[STMT_DELETE]);
    if (r) return r;

    /* commit transaction */
    if (commit) {
	r = carddav_commit(carddavdb);
	if (r) return r;
    }

    return 0;
}


#define CMD_DELMBOX "DELETE FROM vcard_objs WHERE mailbox = :mailbox;"

EXPORTED int carddav_delmbox(struct carddav_db *carddavdb, const char *mailbox, int commit)
{
    struct bind_val bval[] = {
	{ ":mailbox", SQLITE_TEXT, { .s = mailbox } },
	{ NULL,	      SQLITE_NULL, { .s = NULL    } } };
    int r;

    r = dav_exec(carddavdb->db, CMD_DELMBOX, bval, NULL, NULL,
		 &carddavdb->stmt[STMT_DELMBOX]);
    if (r) return r;

    /* commit transaction */
    if (commit) {
	r = carddav_commit(carddavdb);
	if (r) return r;
    }

    return 0;
}

EXPORTED void carddav_make_entry(struct vparse_card *vcard, struct carddav_data *cdata)
{
    struct vparse_entry *ventry;

    for (ventry = vcard->properties; ventry; ventry = ventry->next) {
	const char *name = ventry->name;
	const char *propval = ventry->v.value;

	if (!name) continue;
	if (!propval) continue;

	if (!strcmp(name, "uid")) {
	    cdata->vcard_uid = propval;
	}
	else if (!strcmp(name, "n")) {
	    cdata->name = propval;
	}
	else if (!strcmp(name, "fn")) {
	    cdata->fullname = propval;
	}
	else if (!strcmp(name, "nickname")) {
	    cdata->nickname = propval;
	}
	else if (!strcmp(name, "email")) {
	    /* XXX - insert if primary */
	    strarray_append(&cdata->emails, propval);
	}
	else if (!strcmp(name, "x-addressbookserver-member")) {
	    const char *item = propval;
	    if (!strncmp(item, "urn:uuid:", 9))
		strarray_append(&cdata->member_uids, item+9);
	}
    }
}

EXPORTED void carddav_data_fini(struct carddav_data *cdata)
{
    if (!cdata) return;
    strarray_fini(&cdata->emails);
    strarray_fini(&cdata->member_uids);
    memset(cdata, 0, sizeof *cdata);
}
