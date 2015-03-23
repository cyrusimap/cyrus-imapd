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

#include "append.h"
#include "carddav_db.h"
#include "cyrusdb.h"
#include "httpd.h"
#include "http_dav.h"
#include "libconfig.h"
#include "times.h"
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
    STMT_GETUID_GROUPS,
    STMT_GETEMAIL_EXISTS,
    STMT_GETEMAIL_GROUPS,
    STMT_GETGROUP_EXISTS,
    STMT_GETGROUP_MEMBERS,
    STMT_GETGROUPS,
    STMT_GETCONTACTS,
    STMT_GETUPDATES,
    NUM_STMT
};

#define NUM_BUFS 10

struct carddav_db {
    sqlite3 *db;			/* DB handle */
    sqlite3_stmt *stmt[NUM_STMT];	/* prepared statements */
    struct buf bufs[NUM_BUFS];		/* buffers for copies of column text */
    char *userid;
};


EXPORTED int carddav_init(void)
{
    return dav_init();
}


EXPORTED int carddav_done(void)
{
    return dav_done();
}

EXPORTED struct carddav_db *carddav_open_userid(const char *userid)
{
    struct carddav_db *carddavdb = NULL;

    sqlite3 *db = dav_open_userid(userid);
    if (!db) return NULL;

    carddavdb = xzmalloc(sizeof(struct carddav_db));
    carddavdb->userid = xstrdup(userid);
    carddavdb->db = db;

    return carddavdb;
}

EXPORTED struct carddav_db *carddav_open_mailbox(struct mailbox *mailbox)
{
    struct carddav_db *carddavdb = NULL;
    const char *userid = mboxname_to_userid(mailbox->name);

    if (userid)
	return carddav_open_userid(userid);

    sqlite3 *db = dav_open_mailbox(mailbox);
    if (!db) return NULL;

    carddavdb = xzmalloc(sizeof(struct carddav_db));
    carddavdb->userid = xstrdup(userid);
    carddavdb->db = db;

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

    free(carddavdb->userid);
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
    int tombstones;
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

#define CMD_GETFIELDS							\
    "SELECT rowid, creationdate, mailbox, resource, imap_uid,"		\
    "  lock_token, lock_owner, lock_ownerid, lock_expire,"		\
    "  version, vcard_uid, kind, fullname, name, nickname, alive"	\
    " FROM vcard_objs"

static int read_cb(sqlite3_stmt *stmt, void *rock)
{
    struct read_rock *rrock = (struct read_rock *) rock;
    struct carddav_db *db = rrock->db;
    struct carddav_data *cdata = rrock->cdata;
    int r = 0;

    memset(cdata, 0, sizeof(struct carddav_data));

    cdata->dav.alive = sqlite3_column_int(stmt, 15);
    if (!rrock->tombstones && !cdata->dav.alive)
	return 0;

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

#define CMD_SELRSRC CMD_GETFIELDS \
    " WHERE mailbox = :mailbox AND resource = :resource;"

EXPORTED int carddav_lookup_resource(struct carddav_db *carddavdb,
			   const char *mailbox, const char *resource,
			   int lock, struct carddav_data **result,
			   int tombstones)
{
    struct bind_val bval[] = {
	{ ":mailbox",  SQLITE_TEXT, { .s = mailbox	 } },
	{ ":resource", SQLITE_TEXT, { .s = resource	 } },
	{ NULL,	       SQLITE_NULL, { .s = NULL		 } } };
    static struct carddav_data cdata;
    struct read_rock rrock = { carddavdb, &cdata, tombstones, NULL, NULL };
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


#define CMD_SELUID CMD_GETFIELDS \
    " WHERE vcard_uid = :vcard_uid;"

EXPORTED int carddav_lookup_uid(struct carddav_db *carddavdb, const char *vcard_uid,
		      int lock, struct carddav_data **result)
{
    struct bind_val bval[] = {
	{ ":vcard_uid", SQLITE_TEXT, { .s = vcard_uid		 } },
	{ NULL,	        SQLITE_NULL, { .s = NULL		 } } };
    static struct carddav_data cdata;
    struct read_rock rrock = { carddavdb, &cdata, 0, NULL, NULL };
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


#define CMD_SELMBOX CMD_GETFIELDS \
    " WHERE mailbox = :mailbox;"

EXPORTED int carddav_foreach(struct carddav_db *carddavdb, const char *mailbox,
		   int (*cb)(void *rock, void *data),
		   void *rock)
{
    struct bind_val bval[] = {
	{ ":mailbox", SQLITE_TEXT, { .s = mailbox } },
	{ NULL,	      SQLITE_NULL, { .s = NULL    } } };
    struct carddav_data cdata;
    struct read_rock rrock = { carddavdb, &cdata, 0, cb, rock };

    return dav_exec(carddavdb->db, CMD_SELMBOX, bval, &read_cb, &rrock,
		    &carddavdb->stmt[STMT_SELMBOX]);
}

#define CMD_GETUID_GROUPS \
    "SELECT GO.vcard_uid FROM vcard_objs GO" \
    " JOIN vcard_groups G" \
    " WHERE G.objid = GO.rowid" \
    " AND G.member_uid = :uid AND GO.alive = 1;"

static int uidgroups_cb(sqlite3_stmt *stmt, void *rock)
{
    strarray_t *array = (strarray_t *)rock;
    strarray_add(array, (const char *)sqlite3_column_text(stmt, 0));
    return 0;
}

EXPORTED strarray_t *carddav_getuid_groups(struct carddav_db *carddavdb, const char *uid)
{
    struct bind_val bval[] = {
	{ ":uid", SQLITE_TEXT, { .s = uid } },
	{ NULL,   SQLITE_NULL, { .s = NULL  } }
    };

    strarray_t *groups;
    int r;

    groups = strarray_new();

    r = dav_exec(carddavdb->db, CMD_GETUID_GROUPS, bval, &uidgroups_cb, groups,
		 &carddavdb->stmt[STMT_GETUID_GROUPS]);
    if (r) {
	/* XXX syslog */
    }

    return groups;
}

#define CMD_GETEMAIL_EXISTS \
    "SELECT E.rowid " \
    " FROM vcard_emails E JOIN vcard_objs CO" \
    " WHERE E.objid = CO.rowid AND E.email = :email AND CO.alive = 1" \
    " LIMIT 1"

#define CMD_GETEMAIL_GROUPS \
    "SELECT GO.vcard_uid FROM vcard_objs GO" \
    " JOIN vcard_groups G JOIN vcard_objs CO JOIN vcard_emails E" \
    " WHERE E.objid = CO.rowid AND CO.vcard_uid = G.member_uid" \
    " AND G.objid = GO.rowid AND E.email = :email" \
    " AND GO.alive = 1 AND CO.alive = 1;"

static int emailexists_cb(sqlite3_stmt *stmt, void *rock)
{
    int *exists = (int *)rock;
    if (sqlite3_column_int(stmt, 0))
	*exists = 1;
    return 0;
}

static int emailgroups_cb(sqlite3_stmt *stmt, void *rock)
{
    strarray_t *array = (strarray_t *)rock;
    strarray_add(array, (const char *)sqlite3_column_text(stmt, 0));
    return 0;
}

EXPORTED strarray_t *carddav_getemail(struct carddav_db *carddavdb, const char *email)
{
    struct bind_val bval[] = {
	{ ":email", SQLITE_TEXT, { .s = email } },
	{ NULL,     SQLITE_NULL, { .s = NULL  } }
    };

    int exists = 0;
    strarray_t *groups;
    int r;

    r = dav_exec(carddavdb->db, CMD_GETEMAIL_EXISTS, bval, &emailexists_cb, &exists,
		 &carddavdb->stmt[STMT_GETEMAIL_EXISTS]);
    if (r) {
	/* XXX syslog */
	return NULL;
    }

    if (!exists)
	return NULL;

    groups = strarray_new();

    r = dav_exec(carddavdb->db, CMD_GETEMAIL_GROUPS, bval, &emailgroups_cb, groups,
		 &carddavdb->stmt[STMT_GETEMAIL_GROUPS]);
    if (r) {
	/* XXX syslog */
    }

    return groups;
}

#define CMD_GETGROUP_EXISTS \
    "SELECT rowid " \
    " FROM vcard_objs" \
    " WHERE mailbox = :mailbox AND kind = :kind AND vcard_uid = :group AND alive = 1;"

#define CMD_GETGROUP_MEMBERS \
    "SELECT E.email FROM vcard_emails E" \
    " JOIN vcard_objs CO JOIN vcard_groups G JOIN vcard_objs GO" \
    " WHERE E.objid = CO.rowid AND CO.vcard_uid = G.member_uid AND G.objid = GO.rowid" \
    " AND E.pos = 0 AND GO.mailbox = :mailbox AND GO.vcard_uid = :group" \
    " AND GO.alive = 1 AND CO.alive = 1;"

static int groupexists_cb(sqlite3_stmt *stmt, void *rock)
{
    int *exists = (int *)rock;
    if (sqlite3_column_int(stmt, 0))
	*exists = 1;
    return 0;
}

static int groupmembers_cb(sqlite3_stmt *stmt, void *rock)
{
    strarray_t *array = (strarray_t *)rock;
    strarray_add(array, (const char *)sqlite3_column_text(stmt, 0));
    return 0;
}

EXPORTED strarray_t *carddav_getgroup(struct carddav_db *carddavdb, const char *mailbox, const char *group)
{
    struct bind_val bval[] = {
	{ ":mailbox", SQLITE_TEXT,    { .s = mailbox } },
	{ ":group",   SQLITE_TEXT,    { .s = group   } },
	{ ":kind",    SQLITE_INTEGER, { .i = CARDDAV_KIND_GROUP } },
	{ NULL,       SQLITE_NULL,    { .s = NULL    } }
    };

    int exists = 0;
    strarray_t *members;
    int r;

    r = dav_exec(carddavdb->db, CMD_GETGROUP_EXISTS, bval, &groupexists_cb, &exists,
		 &carddavdb->stmt[STMT_GETGROUP_EXISTS]);
    if (r) {
	/* XXX syslog */
	return NULL;
    }

    if (!exists)
	return NULL;

    members = strarray_new();

    r = dav_exec(carddavdb->db, CMD_GETGROUP_MEMBERS, bval, &groupmembers_cb, members,
		 &carddavdb->stmt[STMT_GETGROUP_MEMBERS]);
    if (r) {
	/* XXX syslog */
    }

    return members;
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
    "  alive, creationdate, mailbox, resource, imap_uid, modseq,"	\
    "  lock_token, lock_owner, lock_ownerid, lock_expire,"		\
    "  version, vcard_uid, kind, fullname, name, nickname)"		\
    " VALUES ("								\
    "  :alive, :creationdate, :mailbox, :resource, :imap_uid, :modseq,"	\
    "  :lock_token, :lock_owner, :lock_ownerid, :lock_expire,"		\
    "  :version, :vcard_uid, :kind, :fullname, :name, :nickname );"

EXPORTED int carddav_write(struct carddav_db *carddavdb, struct carddav_data *cdata,
		 int commit)
{
    struct bind_val bval[] = {
	{ ":alive",	   SQLITE_INTEGER, { .i = cdata->dav.alive	  } },
	{ ":creationdate", SQLITE_INTEGER, { .i = cdata->dav.creationdate } },
	{ ":mailbox",	   SQLITE_TEXT,	   { .s = cdata->dav.mailbox	  } },
	{ ":resource",	   SQLITE_TEXT,	   { .s = cdata->dav.resource	  } },
	{ ":imap_uid",	   SQLITE_INTEGER, { .i = cdata->dav.imap_uid	  } },
	{ ":modseq",	   SQLITE_INTEGER, { .i = cdata->dav.modseq	  } },
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

#define CMD_GETGROUPS \
  "SELECT GO.vcard_uid, GO.fullname, F.vcard_uid " \
  "FROM vcard_objs GO LEFT JOIN (" \
    "SELECT G.objid AS rowid, CO.vcard_uid FROM vcard_groups G " \
    "JOIN vcard_objs CO ON (G.member_uid = CO.vcard_uid) " \
    "WHERE CO.alive = 1 ORDER BY G.objid, G.pos" \
  ") AS F USING (rowid)" \
  "WHERE GO.kind = 1 AND GO.alive = 1;"

struct groups_rock {
    struct jmap_req *req;
    json_t *array;
    struct hash_table *hash;
    struct hash_table *need;
};

static int getgroups_cb(sqlite3_stmt *stmt, void *rock)
{
    struct groups_rock *grock = (struct groups_rock *)rock;
    const char *group_uid = (const char *)sqlite3_column_text(stmt, 0);
    const char *group_name = (const char *)sqlite3_column_text(stmt, 1);
    const char *card_uid = (const char *)sqlite3_column_text(stmt, 2);

    if (grock->need) {
	/* skip records not in hash */
	if (!hash_lookup(group_uid, grock->need))
	    return 0;
	/* mark 2 == seen */
	hash_insert(group_uid, (void *)2, grock->need);
    }

    json_t *members = hash_lookup(group_uid, grock->hash);
    if (!members) {
	json_t *obj;
	members = json_pack("[]");
	obj = json_pack("{s:s, s:s, s:o}",
	    "id", group_uid,
	    "name", group_name,
	    "contactIds", members
	);
	json_array_append(grock->array, obj);
	hash_insert(group_uid, members, grock->hash);
    }
    if (card_uid) json_array_append(members, json_string(card_uid));

    return 0;
}

static void _add_notfound(const char *key, void *data, void *rock)
{
    json_t *list = (json_t *)rock;
    /* magic "pointer" of 1 equals wanted but not found */
    if (data == (void *)1)
	json_array_append_new(list, json_string(key));
}

/* jmap contact APIs */
EXPORTED int carddav_getContactGroups(struct carddav_db *carddavdb, struct jmap_req *req)
{
    struct bind_val bval[] = {
	{ NULL,     SQLITE_NULL, { .s = NULL  } }
    };
    struct groups_rock rock;
    int r;

    rock.array = json_pack("[]");
    rock.need = NULL;  /* XXX - support getting a list of IDs */
    rock.hash = xzmalloc(sizeof(struct hash_table));
    construct_hash_table(rock.hash, 1024, 0);

    json_t *want = json_object_get(req->args, "ids");
    if (want) {
	rock.need = xzmalloc(sizeof(struct hash_table));
	construct_hash_table(rock.need, 1024, 0);
	int i;
	int size = json_array_size(want);
	for (i = 0; i < size; i++) {
	    const char *id = json_string_value(json_array_get(want, i));
	    /* 1 == want */
	    hash_insert(id, (void *)1, rock.need);
	}
    }

    r = dav_exec(carddavdb->db, CMD_GETGROUPS, bval, &getgroups_cb, &rock,
		 &carddavdb->stmt[STMT_GETGROUPS]);
    if (r) {
	syslog(LOG_ERR, "caldav error %s", error_message(r));
	/* XXX - free memory */
	return r;
    }

    free_hash_table(rock.hash, NULL);
    free(rock.hash);

    json_t *contactGroups = json_pack("{}");
    json_object_set_new(contactGroups, "accountId", json_string(req->userid));
    json_object_set_new(contactGroups, "state", json_string(req->state));
    json_object_set_new(contactGroups, "list", rock.array);
    if (rock.need) {
	json_t *notfound = json_array();
	hash_enumerate(rock.need, _add_notfound, notfound);
	free_hash_table(rock.need, NULL);
	free(rock.need);
	if (json_array_size(notfound)) {
	    json_object_set_new(contactGroups, "notFound", notfound);
	}
	else {
	    json_decref(notfound);
	    json_object_set_new(contactGroups, "notFound", json_null());
	}
    }
    else {
	json_object_set_new(contactGroups, "notFound", json_null());
    }

    json_t *item = json_pack("[]");
    json_array_append_new(item, json_string("contactGroups"));
    json_array_append_new(item, contactGroups);
    json_array_append_new(item, json_string(req->tag));

    json_array_append_new(req->response, item);

    return 0;
}

#define CMD_GETUPDATES \
  "SELECT vcard_uid, alive " \
  "FROM vcard_objs "\
  "WHERE kind = :kind AND modseq > :modseq;"

struct updates_rock {
    struct jmap_req *req;
    json_t *changed;
    json_t *removed;
};

static int getupdates_cb(sqlite3_stmt *stmt, void *rock)
{
    struct updates_rock *grock = (struct updates_rock *)rock;
    const char *group_uid = (const char *)sqlite3_column_text(stmt, 0);
    int group_alive = sqlite3_column_int(stmt, 1);

    if (group_alive) {
	json_array_append_new(grock->changed, json_string(group_uid));
    }
    else {
	json_array_append_new(grock->removed, json_string(group_uid));
    }

    return 0;
}

EXPORTED int carddav_getContactGroupUpdates(struct carddav_db *carddavdb, struct jmap_req *req)
{
    struct updates_rock rock;
    int r;
    json_t *since = json_object_get(req->args, "sinceState");
    if (!since) return -1;
    const char *since_str = json_string_value(since);
    if (!since_str) return -1;
    modseq_t oldmodseq = str2uint64(since_str);
    rock.changed = json_array();
    rock.removed = json_array();
    struct bind_val bval[] = {
	{ ":modseq", SQLITE_INTEGER, { .i = oldmodseq } },
	{ ":kind",   SQLITE_INTEGER, { .i = CARDDAV_KIND_GROUP } },
	{ NULL,      SQLITE_NULL,    { .s = NULL  } }
    };

    r = dav_exec(carddavdb->db, CMD_GETUPDATES, bval, &getupdates_cb, &rock,
		 &carddavdb->stmt[STMT_GETUPDATES]);
    if (r) {
	syslog(LOG_ERR, "caldav error %s", error_message(r));
	/* XXX - free memory */
	return r;
    }

    json_t *contactGroupUpdates = json_pack("{}");
    json_object_set_new(contactGroupUpdates, "accountId", json_string(req->userid));
    json_object_set_new(contactGroupUpdates, "oldState", json_string(since_str)); // XXX - just use refcounted
    json_object_set_new(contactGroupUpdates, "newState", json_string(req->state));
    json_object_set(contactGroupUpdates, "changed", rock.changed);
    json_object_set(contactGroupUpdates, "removed", rock.removed);

    json_t *item = json_pack("[]");
    json_array_append_new(item, json_string("contactGroupUpdates"));
    json_array_append_new(item, contactGroupUpdates);
    json_array_append_new(item, json_string(req->tag));

    json_array_append_new(req->response, item);

    json_t *dofetch = json_object_get(req->args, "fetchContactGroups");
    if (dofetch && json_is_true(dofetch) && json_array_size(rock.changed)) {
	struct jmap_req subreq = *req; // struct copy, woot
	subreq.args = json_pack("{}");
	json_object_set(subreq.args, "ids", rock.changed);
	r = carddav_getContactGroups(carddavdb, &subreq);
	json_decref(subreq.args);
    }

    json_decref(rock.changed);
    json_decref(rock.removed);

    return r;
}

struct contacts_rock {
    struct jmap_req *req;
    json_t *array;
    struct hash_table *need;
    struct hash_table *props;
    struct mailbox *mailbox;
};

static int _wantprop(hash_table *props, const char *name)
{
    if (!props) return 1;
    if (hash_lookup(name, props)) return 1;
    return 0;
}

#define CMD_GETCONTACTS \
  "SELECT vcard_uid, mailbox, imap_uid" \
  " FROM vcard_objs" \
  " WHERE kind = 0 AND alive = 1" \
  " ORDER BY mailbox, imap_uid;"

static json_t *_optstring(const char *str)
{
    return json_string(str ? str : "");
}

static void _date_to_jmap(const char *date, struct buf *buf)
{
    if (date)
	buf_setcstr(buf, date);
    else
	buf_setcstr(buf, "0000-00-00");
}

static const char *_servicetype(const char *type)
{
    /* add new services here */
    if (!strcasecmp(type, "aim")) return "AIM";
    if (!strcasecmp(type, "facebook")) return "Facebook";
    if (!strcasecmp(type, "flickr")) return "Flickr";
    if (!strcasecmp(type, "gadugadu")) return "GaduGadu";
    if (!strcasecmp(type, "github")) return "GitHub";
    if (!strcasecmp(type, "googletalk")) return "GoogleTalk";
    if (!strcasecmp(type, "icq")) return "ICQ";
    if (!strcasecmp(type, "jabber")) return "Jabber";
    if (!strcasecmp(type, "linkedin")) return "LinkedIn";
    if (!strcasecmp(type, "msn")) return "MSN";
    if (!strcasecmp(type, "myspace")) return "MySpace";
    if (!strcasecmp(type, "qq")) return "QQ";
    if (!strcasecmp(type, "skype")) return "Skype";
    if (!strcasecmp(type, "twitter")) return "Twitter";
    if (!strcasecmp(type, "yahoo")) return "Yahoo";

    syslog(LOG_NOTICE, "unknown service type %s", type);
    return type;
}

static int _is_im(const char *type)
{
    /* add new services here */
    if (!strcasecmp(type, "aim")) return 1;
    if (!strcasecmp(type, "facebook")) return 1;
    if (!strcasecmp(type, "gadugadu")) return 1;
    if (!strcasecmp(type, "googletalk")) return 1;
    if (!strcasecmp(type, "icq")) return 1;
    if (!strcasecmp(type, "jabber")) return 1;
    if (!strcasecmp(type, "msn")) return 1;
    if (!strcasecmp(type, "qq")) return 1;
    if (!strcasecmp(type, "skype")) return 1;
    if (!strcasecmp(type, "twitter")) return 1;
    if (!strcasecmp(type, "yahoo")) return 1;

    return 0;
}

static int getcontacts_cb(sqlite3_stmt *stmt, void *rock)
{
    struct contacts_rock *grock = (struct contacts_rock *)rock;
    const char *card_uid = (const char *)sqlite3_column_text(stmt, 0);
    const char *mboxname = (const char *)sqlite3_column_text(stmt, 1);
    uint32_t uid = sqlite3_column_int(stmt, 2);
    struct index_record record;
    strarray_t *empty = NULL;
    int r = 0;

    if (grock->need) {
	/* skip records not in hash */
	if (!hash_lookup(card_uid, grock->need))
	    return 0;
	/* mark 2 == seen */
	hash_insert(card_uid, (void *)2, grock->need);
    }

    if (!grock->mailbox || strcmp(grock->mailbox->name, mboxname)) {
	mailbox_close(&grock->mailbox);
	r = mailbox_open_irl(mboxname, &grock->mailbox);
	if (r) return r;
    }

    r = mailbox_find_index_record(grock->mailbox, uid, &record, NULL);
    if (r) return r;

    /* XXX - this could definitely be refactored from here and mailbox.c */
    struct buf msg_buf = BUF_INITIALIZER;
    struct vparse_state vparser;
    struct buf tmp_buf = BUF_INITIALIZER;

    /* Load message containing the resource and parse vcard data */
    r = mailbox_map_record(grock->mailbox, &record, &msg_buf);
    if (r) return r;

    memset(&vparser, 0, sizeof(struct vparse_state));
    vparser.base = buf_cstring(&msg_buf) + record.header_size;
    vparse_set_multival(&vparser, "adr");
    vparse_set_multival(&vparser, "org");
    vparse_set_multival(&vparser, "n");
    r = vparse_parse(&vparser, 0);
    buf_free(&msg_buf);
    if (r) return r;
    if (!vparser.card || !vparser.card->objects) {
        vparse_free(&vparser);
        return r;
    }
    struct vparse_card *card = vparser.card->objects;

    json_t *obj = json_pack("{}");

    json_object_set_new(obj, "id", json_string(card_uid));

    if (_wantprop(grock->props, "isFlagged")) {
	json_object_set_new(obj, "isFlagged", record.system_flags & FLAG_FLAGGED ? json_true() : json_false());
    }

    if (_wantprop(grock->props, "x-importance")) {
	double val = 0;
	struct buf buf = BUF_INITIALIZER;
	const char *ns = ANNOT_NS "<" XML_NS_CYRUS ">importance";

	annotatemore_msg_lookup(grock->mailbox->name, record.uid,
				ns, "", &buf);
	if (buf.len)
	    val = strtod(buf_cstring(&buf), NULL);
	buf_free(&buf);

	json_object_set_new(obj, "x-importance", json_real(val));
    }

    const strarray_t *n = vparse_multival(card, "n");
    const strarray_t *org = vparse_multival(card, "org");
    if (!n) n = empty ? empty : (empty = strarray_new());
    if (!org) org = empty ? empty : (empty = strarray_new());

    /* name fields */
    if (_wantprop(grock->props, "lastName"))
	json_object_set_new(obj, "lastName", _optstring(strarray_nth(n, 0)));
    if (_wantprop(grock->props, "firstName"))
	json_object_set_new(obj, "firstName", _optstring(strarray_nth(n, 1)));
    if (_wantprop(grock->props, "prefix"))
	json_object_set_new(obj, "prefix", _optstring(strarray_nth(n, 3)));

    /* org fields */
    if (_wantprop(grock->props, "company"))
	json_object_set_new(obj, "company", _optstring(strarray_nth(org, 0)));
    if (_wantprop(grock->props, "department"))
	json_object_set_new(obj, "department", _optstring(strarray_nth(org, 1)));
    /* XXX - position? */

    /* address - we need to open code this, because it's repeated */
    if (_wantprop(grock->props, "addresses")) {
	json_t *adr = json_array();

	struct vparse_entry *entry;
	for (entry = card->properties; entry; entry = entry->next) {
	    if (strcasecmp(entry->name, "adr")) continue;
	    json_t *item = json_pack("{}");

	    /* XXX - type and label */
	    const strarray_t *a = entry->v.values;

	    const struct vparse_param *param;
	    const char *type = "other";
	    const char *label = NULL;
	    for (param = entry->params; param; param = param->next) {
		if (!strcasecmp(param->name, "type")) {
		    if (!strcasecmp(param->value, "home")) {
			type = "home";
		    }
		    else if (!strcasecmp(param->value, "work")) {
			type = "work";
		    }
		    else if (!strcasecmp(param->value, "billing")) {
			type = "billing";
		    }
		    else if (!strcasecmp(param->value, "postal")) {
			type = "postal";
		    }
		}
		else if (!strcasecmp(param->name, "label")) {
		    label = param->value;
		}
	    }
	    json_object_set_new(item, "type", json_string(type));
	    if (label) json_object_set_new(item, "label", json_string(label));

	    json_object_set_new(item, "street", _optstring(strarray_nth(a, 2)));
	    json_object_set_new(item, "locality", _optstring(strarray_nth(a, 3)));
	    json_object_set_new(item, "region", _optstring(strarray_nth(a, 4)));
	    json_object_set_new(item, "postcode", _optstring(strarray_nth(a, 5)));
	    json_object_set_new(item, "country", _optstring(strarray_nth(a, 6)));

	    json_array_append_new(adr, item);
	}

	json_object_set_new(obj, "addresses", adr);
    }

    /* address - we need to open code this, because it's repeated */
    if (_wantprop(grock->props, "emails")) {
	json_t *emails = json_array();

	struct vparse_entry *entry;
	int defaultIndex = -1;
	int i = 0;
	for (entry = card->properties; entry; entry = entry->next) {
	    if (strcasecmp(entry->name, "email")) continue;
	    json_t *item = json_pack("{}");
	    const struct vparse_param *param;
	    const char *type = "other";
	    const char *label = NULL;
	    for (param = entry->params; param; param = param->next) {
		if (!strcasecmp(param->name, "type")) {
		    if (!strcasecmp(param->value, "personal")) {
			type = "personal";
		    }
		    else if (!strcasecmp(param->value, "work")) {
			type = "work";
		    }
		    else if (!strcasecmp(param->value, "pref")) {
			if (defaultIndex < 0)
			    defaultIndex = i;
		    }
		}
		else if (!strcasecmp(param->name, "label")) {
		    label = param->value;
		}
	    }
	    json_object_set_new(item, "type", json_string(type));
	    if (label) json_object_set_new(item, "label", json_string(label));

	    json_object_set_new(item, "value", json_string(entry->v.value));

	    json_array_append_new(emails, item);
	    i++;
	}

	if (defaultIndex < 0)
	    defaultIndex = 0;
	int size = json_array_size(emails);
	for (i = 0; i < size; i++) {
	    json_t *item = json_array_get(emails, i);
	    json_object_set_new(item, "isDefault", i == defaultIndex ? json_true() : json_false());
	}

	json_object_set_new(obj, "emails", emails);
    }

    /* address - we need to open code this, because it's repeated */
    if (_wantprop(grock->props, "phones")) {
	json_t *phones = json_array();

	struct vparse_entry *entry;
	for (entry = card->properties; entry; entry = entry->next) {
	    if (strcasecmp(entry->name, "tel")) continue;
	    json_t *item = json_pack("{}");
	    const struct vparse_param *param;
	    const char *type = "other";
	    const char *label = NULL;
	    for (param = entry->params; param; param = param->next) {
		if (!strcasecmp(param->name, "type")) {
		    if (!strcasecmp(param->value, "home")) {
			type = "home";
		    }
		    else if (!strcasecmp(param->value, "work")) {
			type = "work";
		    }
		    else if (!strcasecmp(param->value, "cell")) {
			type = "mobile";
		    }
		    else if (!strcasecmp(param->value, "mobile")) {
			type = "mobile";
		    }
		    else if (!strcasecmp(param->value, "fax")) {
			type = "fax";
		    }
		    else if (!strcasecmp(param->value, "pager")) {
			type = "pager";
		    }
		}
		else if (!strcasecmp(param->name, "label")) {
		    label = param->value;
		}
	    }
	    json_object_set_new(item, "type", json_string(type));
	    if (label) json_object_set_new(item, "label", json_string(label));

	    json_object_set_new(item, "value", json_string(entry->v.value));

	    json_array_append_new(phones, item);
	}

	json_object_set_new(obj, "phones", phones);
    }

    /* address - we need to open code this, because it's repeated */
    if (_wantprop(grock->props, "online")) {
	json_t *online = json_array();

	struct vparse_entry *entry;
	for (entry = card->properties; entry; entry = entry->next) {
	    if (!strcasecmp(entry->name, "url")) {
		json_t *item = json_pack("{}");
		const struct vparse_param *param;
		const char *label = NULL;
		for (param = entry->params; param; param = param->next) {
		    if (!strcasecmp(param->name, "label")) {
			label = param->value;
		    }
		}
		json_object_set_new(item, "type", json_string("uri"));
		if (label) json_object_set_new(item, "label", json_string(label));
		json_object_set_new(item, "value", json_string(entry->v.value));
	        json_array_append_new(online, item);
	    }
	    if (!strcasecmp(entry->name, "impp")) {
		json_t *item = json_pack("{}");
		const struct vparse_param *param;
		const char *label = NULL;
		for (param = entry->params; param; param = param->next) {
		    if (!strcasecmp(param->name, "x-service-type")) {
			label = _servicetype(param->value);
		    }
		}
		json_object_set_new(item, "type", json_string("username"));
		if (label) json_object_set_new(item, "label", json_string(label));
		json_object_set_new(item, "value", json_string(entry->v.value));
	        json_array_append_new(online, item);
	    }
	    if (!strcasecmp(entry->name, "x-social-profile")) {
		json_t *item = json_pack("{}");
		const struct vparse_param *param;
		const char *label = NULL;
		const char *value = NULL;
		for (param = entry->params; param; param = param->next) {
		    if (!strcasecmp(param->name, "type")) {
			label = _servicetype(param->value);
		    }
		    if (!strcasecmp(param->name, "x-user")) {
			value = param->value;
		    }
		}
		json_object_set_new(item, "type", json_string("username"));
		if (label) json_object_set_new(item, "label", json_string(label));
		json_object_set_new(item, "value", json_string(value ? value : entry->v.value));
	        json_array_append_new(online, item);
	    }
	}

	json_object_set_new(obj, "online", online);
    }

    if (_wantprop(grock->props, "nickname")) {
	const char *item = vparse_stringval(card, "nickname");
	json_object_set_new(obj, "nickname", json_string(item ? item : ""));
    }

    if (_wantprop(grock->props, "birthday")) {
	const char *item = vparse_stringval(card, "bday");
	_date_to_jmap(item, &tmp_buf);
	json_object_set_new(obj, "birthday", json_string(buf_cstring(&tmp_buf)));
    }

    /* XXX - other fields */

    json_array_append_new(grock->array, obj);

    if (empty) strarray_free(empty);

    buf_free(&tmp_buf);

    return 0;
}

static const char *_resolveid(struct jmap_req *req, const char *id)
{
    const char *newid = hash_lookup(id, req->idmap);
    if (newid) return newid;
    return id;
}

static int _add_group_entries(struct carddav_db *carddavdb, struct jmap_req *req,
			      struct vparse_card *card, json_t *members)
{
    vparse_delete_entries(card, NULL, "X-ADDRESSBOOKSERVER-MEMBER");
    int r = 0;
    size_t index;
    struct buf buf = BUF_INITIALIZER;
    for (index = 0; index < json_array_size(members); index++) {
	json_t *item = json_array_get(members, index);
	const char *uid = _resolveid(req, json_string_value(item));
	struct carddav_data *cdata = NULL;
	r = carddav_lookup_uid(carddavdb, uid, 0, &cdata);
	if (r) goto done;
	if (!cdata || !cdata->dav.imap_uid || !cdata->dav.alive
	    || cdata->kind != CARDDAV_KIND_CONTACT) {
	    r = -1;
	    goto done;
	}
	buf_setcstr(&buf, "urn:uuid:");
	buf_appendcstr(&buf, json_string_value(item));
	vparse_add_entry(card, NULL, "X-ADDRESSBOOKSERVER-MEMBER", buf_cstring(&buf));
    }
done:
    buf_free(&buf);
    return r;
}

EXPORTED int carddav_setContactGroups(struct carddav_db *carddavdb, struct jmap_req *req)
{
    int r = 0;
    json_t *checkState = json_object_get(req->args, "ifInState");
    if (checkState && strcmp(req->state, json_string_value(checkState))) {
	json_t *item = json_pack("[s, {s:s}, s]", "error", "type", "stateMismatch", req->tag);
	json_array_append_new(req->response, item);
	return 0;
    }
    json_t *set = json_pack("{s:s,s:s}",
			    "oldState", req->state,
			    "accountId", req->userid);

    struct mailbox *mailbox = NULL;

    json_t *create = json_object_get(req->args, "create");
    if (create) {
	json_t *created = json_pack("{}");
	json_t *notCreated = json_pack("{}");
	json_t *record;
	/* XXX - default name finding */
	const char *mboxname = mboxname_user_mbox(req->userid, "#addressbooks.Default");

	const char *key;
	json_t *arg;
	json_object_foreach(create, key, arg) {
	    char *uid = makeuuid();
	    json_t *name = json_object_get(arg, "name");
	    if (!name) {
		json_t *err = json_pack("{s:s}", "type", "missingParameters");
		json_object_set_new(notCreated, key, err);
		free(uid);
		continue;
	    }
	    // XXX - no name => notCreated
	    struct vparse_card *card = vparse_new_card("VCARD");
	    vparse_add_entry(card, NULL, "VERSION", "3.0");
	    vparse_add_entry(card, NULL, "FN", json_string_value(name));
	    vparse_add_entry(card, NULL, "UID", uid);
	    vparse_add_entry(card, NULL, "X-ADDRESSBOOKSERVER-KIND", "group");

	    /* it's legal to create an empty group */
	    json_t *members = json_object_get(arg, "contactIds");
	    if (members) {
		r = _add_group_entries(carddavdb, req, card, members);
		if (r) {
		    /* this one is legit - it just means we'll be adding an error instead */
		    r = 0;
		    json_t *err = json_pack("{s:s}", "type", "invalidContactId");
		    json_object_set_new(notCreated, key, err);
		    free(uid);
		    vparse_free_card(card);
		    continue;
		}
	    }

	    /* we need to create and append a record */
	    if (!mailbox || strcmp(mailbox->name, mboxname)) {
		mailbox_close(&mailbox);
		r = mailbox_open_iwl(mboxname, &mailbox);
	    }

	    if (!r) r = carddav_store(mailbox, 0, card, NULL, NULL, NULL, req->userid, req->authstate);

	    vparse_free_card(card);

	    if (r) {
		/* these are real "should never happen" errors */
		free(uid);
		goto done;
	    }

	    record = json_pack("{s:s}", "id", uid);
	    json_object_set_new(created, key, record);

	    /* hash_insert takes ownership of uid here, skanky I know */
	    hash_insert(key, uid, req->idmap);
	}

	if (json_object_size(created))
	    json_object_set(set, "created", created);
	json_decref(created);
	if (json_object_size(notCreated))
	    json_object_set(set, "notCreated", notCreated);
	json_decref(notCreated);
    }

    json_t *update = json_object_get(req->args, "update");
    if (update) {
	json_t *updated = json_pack("[]");
	json_t *notUpdated = json_pack("{}");

	const char *uid;
	json_t *arg;
	json_object_foreach(update, uid, arg) {
	    struct carddav_data *cdata = NULL;
	    r = carddav_lookup_uid(carddavdb, uid, 0, &cdata);
	    uint32_t olduid;
	    char *resource = NULL;

	    /* is it a valid group? */
	    if (r || !cdata || !cdata->dav.imap_uid || !cdata->dav.resource
		  || cdata->kind != CARDDAV_KIND_GROUP) {
		r = 0;
		json_t *err = json_pack("{s:s}", "type", "notFound");
		json_object_set_new(notUpdated, uid, err);
		continue;
	    }
	    olduid = cdata->dav.imap_uid;
	    resource = xstrdup(cdata->dav.resource);

	    if (!mailbox || strcmp(mailbox->name, cdata->dav.mailbox)) {
		mailbox_close(&mailbox);
		r = mailbox_open_iwl(cdata->dav.mailbox, &mailbox);
		if (r) {
		    syslog(LOG_ERR, "IOERROR: failed to open %s", cdata->dav.mailbox);
		    goto done;
		}
	    }

	    /* XXX - this could definitely be refactored from here and mailbox.c */
	    struct buf msg_buf = BUF_INITIALIZER;
	    struct vparse_state vparser;
	    struct index_record record;

	    r = mailbox_find_index_record(mailbox, cdata->dav.imap_uid, &record, NULL);
	    if (r) goto done;

	    /* Load message containing the resource and parse vcard data */
	    r = mailbox_map_record(mailbox, &record, &msg_buf);
	    if (r) goto done;

	    memset(&vparser, 0, sizeof(struct vparse_state));
	    vparser.base = buf_cstring(&msg_buf) + record.header_size;
	    vparse_set_multival(&vparser, "adr");
	    vparse_set_multival(&vparser, "org");
	    vparse_set_multival(&vparser, "n");
	    r = vparse_parse(&vparser, 0);
	    buf_free(&msg_buf);
	    if (r || !vparser.card || !vparser.card->objects) {
		json_t *err = json_pack("{s:s}", "type", "parseError");
		json_object_set_new(notUpdated, uid, err);
		vparse_free(&vparser);
		continue;
	    }
	    struct vparse_card *card = vparser.card->objects;

	    json_t *namep = json_object_get(arg, "name");
	    if (namep) {
		const char *name = json_string_value(namep);
		struct vparse_entry *entry = vparse_get_entry(card, NULL, "FN");
		if (entry) {
		    free(entry->v.value);
		    entry->v.value = xstrdup(name);
		}
		else {
		    vparse_add_entry(card, NULL, "FN", name);
		}
	    }

	    json_t *members = json_object_get(arg, "contactIds");
	    if (members) {
		r = _add_group_entries(carddavdb, req, card, members);
		if (r) {
		    /* this one is legit - it just means we'll be adding an error instead */
		    r = 0;
		    json_t *err = json_pack("{s:s}", "type", "invalidContactId");
		    json_object_set_new(notUpdated, uid, err);
		    vparse_free(&vparser);
		    continue;
		}
	    }

	    r = carddav_store(mailbox, olduid, card, resource, NULL, NULL, req->userid, req->authstate);

	    vparse_free(&vparser);
	    free(resource);
	    if (r) goto done;

	    json_array_append_new(updated, json_string(uid));
	}

	if (json_array_size(updated))
	    json_object_set(set, "updated", updated);
	json_decref(updated);
	if (json_object_size(notUpdated))
	    json_object_set(set, "notUpdated", notUpdated);
	json_decref(notUpdated);
    }

    json_t *destroy = json_object_get(req->args, "destroy");
    if (destroy) {
	json_t *destroyed = json_pack("[]");
	json_t *notDestroyed = json_pack("{}");

	size_t index;
	for (index = 0; index < json_array_size(destroy); index++) {
	    const char *uid = json_string_value(json_array_get(destroy, index));
	    struct carddav_data *cdata = NULL;
	    uint32_t olduid;
	    r = carddav_lookup_uid(carddavdb, uid, 0, &cdata);

	    /* is it a valid group? */
	    if (r || !cdata || !cdata->dav.imap_uid || cdata->kind != CARDDAV_KIND_GROUP) {
		r = 0;
		json_t *err = json_pack("{s:s}", "type", "notFound");
		json_object_set_new(notDestroyed, uid, err);
		continue;
	    }
	    olduid = cdata->dav.imap_uid;

	    if (!mailbox || strcmp(mailbox->name, cdata->dav.mailbox)) {
		mailbox_close(&mailbox);
		r = mailbox_open_iwl(cdata->dav.mailbox, &mailbox);
		if (r) goto done;
	    }

	    /* XXX - alive check */

	    r = carddav_remove(mailbox, olduid);
	    if (r) {
		syslog(LOG_ERR, "IOERROR: setContactGroups remove failed for %s %u", mailbox->name, cdata->dav.imap_uid);
		goto done;
	    }

	    json_array_append_new(destroyed, json_string(uid));
	}

	if (json_array_size(destroyed))
	    json_object_set(set, "destroyed", destroyed);
	json_decref(destroyed);
	if (json_object_size(notDestroyed))
	    json_object_set(set, "notDestroyed", notDestroyed);
	json_decref(notDestroyed);
    }

    /* force modseq to stable */
    if (mailbox) mailbox_unlock_index(mailbox, NULL);

    /* read the modseq again every time, just in case something changed it
     * in our actions */
    struct buf buf = BUF_INITIALIZER;
    const char *inboxname = mboxname_user_mbox(req->userid, NULL);
    modseq_t modseq = mboxname_readmodseq(inboxname);
    buf_printf(&buf, "%llu", modseq);
    json_object_set_new(set, "newState", json_string(buf_cstring(&buf)));
    buf_free(&buf);

    json_t *item = json_pack("[]");
    json_array_append_new(item, json_string("contactGroupsSet"));
    json_array_append_new(item, set);
    json_array_append_new(item, json_string(req->tag));

    json_array_append_new(req->response, item);

done:
    mailbox_close(&mailbox);

    return r;
}

EXPORTED int carddav_getContacts(struct carddav_db *carddavdb, struct jmap_req *req)
{
    struct bind_val bval[] = {
	{ NULL,     SQLITE_NULL, { .s = NULL  } }
    };
    struct contacts_rock rock;
    int r;

    rock.array = json_pack("[]");
    rock.need = NULL;
    rock.props = NULL;
    rock.mailbox = NULL;

    json_t *want = json_object_get(req->args, "ids");
    if (want) {
	rock.need = xzmalloc(sizeof(struct hash_table));
	construct_hash_table(rock.need, 1024, 0);
	int i;
	int size = json_array_size(want);
	for (i = 0; i < size; i++) {
	    const char *id = json_string_value(json_array_get(want, i));
	    if (id == NULL) {
		free_hash_table(rock.need, NULL);
		free(rock.need);
		return -1; /* XXX - need codes */
	    }
	    /* 1 == want */
	    hash_insert(id, (void *)1, rock.need);
	}
    }

    json_t *properties = json_object_get(req->args, "properties");
    if (properties) {
	rock.props = xzmalloc(sizeof(struct hash_table));
	construct_hash_table(rock.props, 1024, 0);
	int i;
	int size = json_array_size(properties);
	for (i = 0; i < size; i++) {
	    const char *id = json_string_value(json_array_get(properties, i));
	    if (id == NULL) {
		free_hash_table(rock.need, NULL);
		free(rock.need);
		return -1; /* XXX - need codes */
	    }
	    /* 1 == properties */
	    hash_insert(id, (void *)1, rock.props);
	}
    }

    r = dav_exec(carddavdb->db, CMD_GETCONTACTS, bval, &getcontacts_cb, &rock,
		 &carddavdb->stmt[STMT_GETCONTACTS]);
    if (r) {
	syslog(LOG_ERR, "caldav error %s", error_message(r));
	/* XXX - free memory */
	return r;
    }

    mailbox_close(&rock.mailbox);

    json_t *contacts = json_pack("{}");
    json_object_set_new(contacts, "accountId", json_string(req->userid));
    json_object_set_new(contacts, "state", json_string(req->state));
    json_object_set_new(contacts, "list", rock.array);
    if (rock.need) {
	json_t *notfound = json_array();
	hash_enumerate(rock.need, _add_notfound, notfound);
	free_hash_table(rock.need, NULL);
	free(rock.need);
	if (json_array_size(notfound)) {
	    json_object_set_new(contacts, "notFound", notfound);
	}
	else {
	    json_decref(notfound);
	    json_object_set_new(contacts, "notFound", json_null());
	}
    }
    else {
	json_object_set_new(contacts, "notFound", json_null());
    }

    json_t *item = json_pack("[]");
    json_array_append_new(item, json_string("contacts"));
    json_array_append_new(item, contacts);
    json_array_append_new(item, json_string(req->tag));

    json_array_append_new(req->response, item);

    return 0;
}

EXPORTED int carddav_getContactUpdates(struct carddav_db *carddavdb, struct jmap_req *req)
{
    struct updates_rock rock;
    int r;
    json_t *since = json_object_get(req->args, "sinceState");
    if (!since) return -1;
    const char *since_str = json_string_value(since);
    if (!since_str) return -1;
    modseq_t oldmodseq = str2uint64(since_str);
    rock.changed = json_array();
    rock.removed = json_array();
    struct bind_val bval[] = {
	{ ":modseq", SQLITE_INTEGER, { .i = oldmodseq } },
	{ ":kind",   SQLITE_INTEGER, { .i = 0 } },
	{ NULL,      SQLITE_NULL,    { .s = NULL  } }
    };

    r = dav_exec(carddavdb->db, CMD_GETUPDATES, bval, &getupdates_cb, &rock,
		 &carddavdb->stmt[STMT_GETUPDATES]);
    if (r) {
	syslog(LOG_ERR, "caldav error %s", error_message(r));
	/* XXX - free memory */
	return r;
    }

    json_t *contactUpdates = json_pack("{}");
    json_object_set_new(contactUpdates, "accountId", json_string(req->userid));
    json_object_set_new(contactUpdates, "oldState", json_string(since_str));
    json_object_set_new(contactUpdates, "newState", json_string(req->state));
    json_object_set(contactUpdates, "changed", rock.changed);
    json_object_set(contactUpdates, "removed", rock.removed);

    json_t *item = json_pack("[]");
    json_array_append_new(item, json_string("contactUpdates"));
    json_array_append_new(item, contactUpdates);
    json_array_append_new(item, json_string(req->tag));

    json_array_append_new(req->response, item);

    json_t *dofetch = json_object_get(req->args, "fetchContacts");
    json_t *doprops = json_object_get(req->args, "fetchContactProperties");
    if (dofetch && json_is_true(dofetch) && json_array_size(rock.changed)) {
	struct jmap_req subreq = *req;
	subreq.args = json_pack("{}");
	json_object_set(subreq.args, "ids", rock.changed);
	if (doprops) json_object_set(subreq.args, "properties", doprops);
	r = carddav_getContacts(carddavdb, &subreq);
	json_decref(subreq.args);
    }

    json_decref(rock.changed);
    json_decref(rock.removed);

    return r;
}

static void _card_val(struct vparse_card *card, const char *name, const char *value)
{
    struct vparse_entry *res = vparse_get_entry(card, NULL, name);
    if (!res) res = vparse_add_entry(card, NULL, name, NULL);
    free(res->v.value);
    res->v.value = xstrdupnull(value);
}

static struct vparse_entry *_card_multi(struct vparse_card *card, const char *name)
{
    struct vparse_entry *res = vparse_get_entry(card, NULL, name);
    if (!res) {
	res = vparse_add_entry(card, NULL, name, NULL);
	res->multivalue = 1;
	res->v.values = strarray_new();
    }
    return res;
}

static int _emails_to_card(struct vparse_card *card, json_t *arg)
{
    vparse_delete_entries(card, NULL, "email");

    int i;
    int size = json_array_size(arg);
    for (i = 0; i < size; i++) {
	json_t *item = json_array_get(arg, i);
	json_t *jvalue = json_object_get(item, "value");
	if (!jvalue) return -1;
	json_t *jtype = json_object_get(item, "type");
	if (!jtype) return -1;
	struct vparse_entry *entry = vparse_add_entry(card, NULL, "email", json_string_value(jvalue));
	const char *type = json_string_value(jtype);
	if (!strcmp(type, "personal"))
	    vparse_add_param(entry, "type", type);
	else if (!strcmp(type, "work"))
	    vparse_add_param(entry, "type", type);
	else if (!strcmp(type, "other"))
	    {} // no param
	else
	    return -1;  // all other types
	json_t *jlabel = json_object_get(item, "label");
	if (jlabel)
	    vparse_add_param(entry, "label", json_string_value(jlabel));
    }
    return 0;
}

static int _phones_to_card(struct vparse_card *card, json_t *arg)
{
    vparse_delete_entries(card, NULL, "tel");

    int i;
    int size = json_array_size(arg);
    for (i = 0; i < size; i++) {
	json_t *item = json_array_get(arg, i);
	json_t *jvalue = json_object_get(item, "value");
	if (!jvalue) return -1;
	json_t *jtype = json_object_get(item, "type");
	if (!jtype) return -1;
	struct vparse_entry *entry = vparse_add_entry(card, NULL, "tel", json_string_value(jvalue));
	const char *type = json_string_value(jtype);
	if (!strcmp(type, "home"))
	    vparse_add_param(entry, "type", type);
	else if (!strcmp(type, "work"))
	    vparse_add_param(entry, "type", type);
	else if (!strcmp(type, "mobile"))
	    vparse_add_param(entry, "type", "cell");
	else if (!strcmp(type, "fax"))
	    vparse_add_param(entry, "type", type);
	else if (!strcmp(type, "pager"))
	    vparse_add_param(entry, "type", type);
	else if (!strcmp(type, "other"))
	    {} // no param
	else
	    return -1;  // all other types
	json_t *jlabel = json_object_get(item, "label");
	if (jlabel)
	    vparse_add_param(entry, "label", json_string_value(jlabel));
    }
    return 0;
}

static int _online_to_card(struct vparse_card *card, json_t *arg)
{
    vparse_delete_entries(card, NULL, "url");
    vparse_delete_entries(card, NULL, "impp");
    vparse_delete_entries(card, NULL, "x-social-profile");

    int i;
    int size = json_array_size(arg);
    for (i = 0; i < size; i++) {
	json_t *item = json_array_get(arg, i);
	json_t *jvalue = json_object_get(item, "value");
	if (!jvalue) return -1;
	json_t *jtype = json_object_get(item, "type");
	if (!jtype) return -1;
	json_t *jlabel = json_object_get(item, "label");

	const char *type = json_string_value(jtype);
	if (!strcmp(type, "uri")) {
	    struct vparse_entry *entry = vparse_add_entry(card, NULL, "url", json_string_value(jvalue));
	    if (jlabel)
		vparse_add_param(entry, "label", json_string_value(jlabel));
	}
	else if (!strcmp(type, "username")) {
	    const char *label = json_string_value(jlabel);
	    if (!label) return -1;
	    if (_is_im(label)) {
		struct vparse_entry *entry = vparse_add_entry(card, NULL, "impp", json_string_value(jvalue));
		vparse_add_param(entry, "x-type", label);
	    }
	    else {
		struct vparse_entry *entry = vparse_add_entry(card, NULL, "x-social-profile", ""); // XXX - URL calculated, ick
		vparse_add_param(entry, "type", label);
		vparse_add_param(entry, "x-user", json_string_value(jvalue));
	    }
	}
	/* XXX other? */
    }
    return 0;
}

static int _addresses_to_card(struct vparse_card *card, json_t *arg)
{
    if (card && arg)
	return 0;
    return 1;
}

static void _make_fn(struct vparse_card *card)
{
    struct vparse_entry *n = vparse_get_entry(card, NULL, "n");
    strarray_t *name = strarray_new();
    const char *v;

    if (n) {
	v = strarray_nth(n->v.values, 3); // prefix
	if (v && v[0]) strarray_append(name, v);

	v = strarray_nth(n->v.values, 1); // first
	if (v && v[0]) strarray_append(name, v);

	v = strarray_nth(n->v.values, 2); // middle
	if (v && v[0]) strarray_append(name, v);

	v = strarray_nth(n->v.values, 0); // last
	if (v && v[0]) strarray_append(name, v);

	v = strarray_nth(n->v.values, 4); // suffix
	if (v && v[0]) strarray_append(name, v);
    }

    if (!strarray_size(name)) {
	v = vparse_stringval(card, "nickname");
	if (v && v[0]) strarray_append(name, v);
    }

    if (!strarray_size(name)) {
	/* XXX - grep type=pref?  Meh */
	v = vparse_stringval(card, "email");
	if (v && v[0]) strarray_append(name, v);
    }

    if (!strarray_size(name)) {
	strarray_append(name, "No Name");
    }

    char *fn = strarray_join(name, " ");

     _card_val(card, "fn", fn);
}

static int _json_to_card(struct vparse_card *card, json_t *arg, strarray_t *flags,
			 struct entryattlist **annotsp)
{
    const char *key;
    json_t *val;
    struct vparse_entry *fn = vparse_get_entry(card, NULL, "fn");
    int name_is_dirty = 0;
    /* we'll be updating you later anyway... create early so that it's
     * at the top of the card */
    if (!fn) {
	fn = vparse_add_entry(card, NULL, "fn", "No Name");
	name_is_dirty = 1;
    }

    json_object_foreach(arg, key, val) {
	if (!strcmp(key, "isFlagged")) {
	    if (json_is_true(val)) {
		strarray_add_case(flags, "\\Flagged");
	    }
	    else {
		strarray_remove_all_case(flags, "\\Flagged");
	    }
	}
	else if (!strcmp(key, "x-importance")) {
	    double dval = json_number_value(val);
	    const char *ns = ANNOT_NS "<" XML_NS_CYRUS ">importance";
	    const char *attrib = "value.shared";
	    if (dval) {
		struct buf buf = BUF_INITIALIZER;
		buf_printf(&buf, "%e", dval);
		setentryatt(annotsp, ns, attrib, &buf);
		buf_free(&buf);
	    }
	    else {
		clearentryatt(annotsp, ns, attrib);
	    }
	}
	else if (!strcmp(key, "avatar")) {
	    /* XXX - file handling */
	}
	else if (!strcmp(key, "prefix")) {
	    name_is_dirty = 1;
	    struct vparse_entry *n = _card_multi(card, "n");
	    strarray_set(n->v.values, 3, json_string_value(val));
	}
	else if (!strcmp(key, "firstName")) {
	    name_is_dirty = 1;
	    struct vparse_entry *n = _card_multi(card, "n");
	    strarray_set(n->v.values, 1, json_string_value(val));
	}
	else if (!strcmp(key, "lastName")) {
	    name_is_dirty = 1;
	    struct vparse_entry *n = _card_multi(card, "n");
	    strarray_set(n->v.values, 0, json_string_value(val));
	}
	else if (!strcmp(key, "suffix")) {
	    name_is_dirty = 1;
	    struct vparse_entry *n = _card_multi(card, "n");
	    strarray_set(n->v.values, 4, json_string_value(val));
	}
	else if (!strcmp(key, "nickname")) {
	    _card_val(card, "nickname", json_string_value(val));
	}
	else if (!strcmp(key, "birthday")) {
	    _card_val(card, "bday", json_string_value(val));
	}
	else if (!strcmp(key, "anniversary")) {
	    _card_val(card, "anniversary", json_string_value(val));
	}
	else if (!strcmp(key, "company")) {
	    struct vparse_entry *org = _card_multi(card, "org");
	    strarray_set(org->v.values, 0, json_string_value(val));
	}
	else if (!strcmp(key, "department")) {
	    struct vparse_entry *org = _card_multi(card, "org");
	    strarray_set(org->v.values, 1, json_string_value(val));
	}
	else if (!strcmp(key, "jobTitle")) {
	    struct vparse_entry *org = _card_multi(card, "org");
	    strarray_set(org->v.values, 2, json_string_value(val));
	}
	else if (!strcmp(key, "emails")) {
	    int r = _emails_to_card(card, val);
	    if (r) return r;
	}
	else if (!strcmp(key, "phones")) {
	    int r = _phones_to_card(card, val);
	    if (r) return r;
	}
	else if (!strcmp(key, "online")) {
	    int r = _online_to_card(card, val);
	    if (r) return r;
	}
	else if (!strcmp(key, "addresses")) {
	    int r = _addresses_to_card(card, val);
	    if (r) return r;
	}
	else if (!strcmp(key, "notes")) {
	    _card_val(card, "note", json_string_value(val));
	}

	else {
	    /* INVALID PARAM */
	    return -1; /* XXX - need codes */
	}
    }

    if (name_is_dirty)
	_make_fn(card);

    return 0;
}

EXPORTED int carddav_setContacts(struct carddav_db *carddavdb, struct jmap_req *req)
{
    int r = 0;
    json_t *checkState = json_object_get(req->args, "ifInState");
    if (checkState && strcmp(req->state, json_string_value(checkState))) {
	json_t *item = json_pack("[s, {s:s}, s]", "error", "type", "stateMismatch", req->tag);
	json_array_append_new(req->response, item);
	return 0;
    }
    json_t *set = json_pack("{s:s,s:s}",
			    "oldState", req->state,
			    "accountId", req->userid);

    struct mailbox *mailbox = NULL;

    json_t *create = json_object_get(req->args, "create");
    if (create) {
	json_t *created = json_pack("{}");
	json_t *notCreated = json_pack("{}");
	json_t *record;
	/* XXX - default name finding */
	const char *mboxname = mboxname_user_mbox(req->userid, "#addressbooks.Default");

	const char *key;
	json_t *arg;
	json_object_foreach(create, key, arg) {
	    char *uid = makeuuid();
	    strarray_t *flags = strarray_new();
	    struct entryattlist *annots = NULL;

	    struct vparse_card *card = vparse_new_card("VCARD");
	    vparse_add_entry(card, NULL, "VERSION", "3.0");
	    vparse_add_entry(card, NULL, "UID", uid);

	    /* we need to create and append a record */
	    if (!mailbox || strcmp(mailbox->name, mboxname)) {
		mailbox_close(&mailbox);
		r = mailbox_open_iwl(mboxname, &mailbox);
		if (r) {
		    free(uid);
		    vparse_free_card(card);
		    goto done;
		}
	    }

	    r = _json_to_card(card, arg, flags, &annots);
	    if (r) {
		/* this is just a failure */
		r = 0;
		json_t *err = json_pack("{s:s}", "type", "invalidParameters");
		json_object_set_new(notCreated, key, err);
		strarray_free(flags);
		freeentryatts(annots);
		free(uid);
		vparse_free_card(card);
		continue;
	    }

	    r = carddav_store(mailbox, 0, card, NULL, flags, annots, req->userid, req->authstate);
	    vparse_free_card(card);
	    strarray_free(flags);
	    freeentryatts(annots);

	    if (r) {
		free(uid);
		goto done;
	    }

	    record = json_pack("{s:s}", "id", uid);
	    json_object_set_new(created, key, record);

	    /* hash_insert takes ownership of uid here, skanky I know */
	    hash_insert(key, uid, req->idmap);
	}

	if (json_object_size(created))
	    json_object_set(set, "created", created);
	json_decref(created);
	if (json_object_size(notCreated))
	    json_object_set(set, "notCreated", notCreated);
	json_decref(notCreated);
    }

    json_t *update = json_object_get(req->args, "update");
    if (update) {
	json_t *updated = json_pack("[]");
	json_t *notUpdated = json_pack("{}");

	const char *uid;
	json_t *arg;
	json_object_foreach(update, uid, arg) {
	    struct carddav_data *cdata = NULL;
	    r = carddav_lookup_uid(carddavdb, uid, 0, &cdata);
	    uint32_t olduid;
	    char *resource = NULL;

	    if (r || !cdata || !cdata->dav.imap_uid
		  || cdata->kind != CARDDAV_KIND_CONTACT) {
		r = 0;
		json_t *err = json_pack("{s:s}", "type", "notFound");
		json_object_set_new(notUpdated, uid, err);
		continue;
	    }
	    olduid = cdata->dav.imap_uid;
	    resource = xstrdup(cdata->dav.resource);

	    if (!mailbox || strcmp(mailbox->name, cdata->dav.mailbox)) {
		mailbox_close(&mailbox);
		r = mailbox_open_iwl(cdata->dav.mailbox, &mailbox);
		if (r) {
		    syslog(LOG_ERR, "IOERROR: failed to open %s", cdata->dav.mailbox);
		    goto done;
		}
	    }

	    /* XXX - this could definitely be refactored from here and mailbox.c */
	    struct buf msg_buf = BUF_INITIALIZER;
	    struct vparse_state vparser;
	    struct index_record record;

	    r = mailbox_find_index_record(mailbox, cdata->dav.imap_uid, &record, NULL);
	    if (r) goto done;

	    /* Load message containing the resource and parse vcard data */
	    r = mailbox_map_record(mailbox, &record, &msg_buf);
	    if (r) goto done;

	    strarray_t *flags = mailbox_extract_flags(mailbox, &record, req->userid);
	    struct entryattlist *annots = mailbox_extract_annots(mailbox, &record);

	    memset(&vparser, 0, sizeof(struct vparse_state));
	    vparser.base = buf_cstring(&msg_buf) + record.header_size;
	    vparse_set_multival(&vparser, "adr");
	    vparse_set_multival(&vparser, "org");
	    vparse_set_multival(&vparser, "n");
	    r = vparse_parse(&vparser, 0);
	    buf_free(&msg_buf);
	    if (r || !vparser.card || !vparser.card->objects) {
		r = 0;
		json_t *err = json_pack("{s:s}", "type", "parseError");
		json_object_set_new(notUpdated, uid, err);
		vparse_free(&vparser);
		strarray_free(flags);
		freeentryatts(annots);
		continue;
	    }
	    struct vparse_card *card = vparser.card->objects;

	    r = _json_to_card(card, arg, flags, &annots);
	    if (r) {
		/* this is just a failure to create the JSON, not an error */
		r = 0;
		json_t *err = json_pack("{s:s}", "type", "invalidParameters");
		json_object_set_new(notUpdated, uid, err);
		vparse_free(&vparser);
		strarray_free(flags);
		freeentryatts(annots);
		continue;
	    }
	    r = carddav_store(mailbox, olduid, card, resource, flags, annots, req->userid, req->authstate);
	    strarray_free(flags);
	    freeentryatts(annots);

	    vparse_free(&vparser);
	    free(resource);

	    if (r) goto done;

	    json_array_append_new(updated, json_string(uid));
	}

	if (json_array_size(updated))
	    json_object_set(set, "updated", updated);
	json_decref(updated);
	if (json_object_size(notUpdated))
	    json_object_set(set, "notUpdated", notUpdated);
	json_decref(notUpdated);
    }

    json_t *destroy = json_object_get(req->args, "destroy");
    if (destroy) {
	json_t *destroyed = json_pack("[]");
	json_t *notDestroyed = json_pack("{}");

	size_t index;
	for (index = 0; index < json_array_size(destroy); index++) {
	    const char *uid = json_string_value(json_array_get(destroy, index));
	    struct carddav_data *cdata = NULL;
	    uint32_t olduid;
	    r = carddav_lookup_uid(carddavdb, uid, 0, &cdata);

	    if (r || !cdata || !cdata->dav.imap_uid
		  || cdata->kind != CARDDAV_KIND_CONTACT) {
		r = 0;
		json_t *err = json_pack("{s:s}", "type", "notFound");
		json_object_set_new(notDestroyed, uid, err);
		continue;
	    }
	    olduid = cdata->dav.imap_uid;

	    if (!mailbox || strcmp(mailbox->name, cdata->dav.mailbox)) {
		mailbox_close(&mailbox);
		r = mailbox_open_iwl(cdata->dav.mailbox, &mailbox);
		if (r) goto done;
	    }

	    /* XXX - fricking mboxevent */

	    r = carddav_remove(mailbox, olduid);
	    if (r) {
		syslog(LOG_ERR, "IOERROR: setContacts remove failed for %s %u", mailbox->name, olduid);
		goto done;
	    }

	    json_array_append_new(destroyed, json_string(uid));
	}

	if (json_array_size(destroyed))
	    json_object_set(set, "destroyed", destroyed);
	json_decref(destroyed);
	if (json_object_size(notDestroyed))
	    json_object_set(set, "notDestroyed", notDestroyed);
	json_decref(notDestroyed);
    }

    /* force modseq to stable */
    if (mailbox) mailbox_unlock_index(mailbox, NULL);

    /* read the modseq again every time, just in case something changed it
     * in our actions */
    struct buf buf = BUF_INITIALIZER;
    const char *inboxname = mboxname_user_mbox(req->userid, NULL);
    modseq_t modseq = mboxname_readmodseq(inboxname);
    buf_printf(&buf, "%llu", modseq);
    json_object_set_new(set, "newState", json_string(buf_cstring(&buf)));
    buf_free(&buf);

    json_t *item = json_pack("[]");
    json_array_append_new(item, json_string("contactsSet"));
    json_array_append_new(item, set);
    json_array_append_new(item, json_string(req->tag));

    json_array_append_new(req->response, item);

done:
    mailbox_close(&mailbox);

    return r;
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

EXPORTED int carddav_store(struct mailbox *mailbox, uint32_t olduid,
			   struct vparse_card *vcard, const char *resource,
			   strarray_t *flags, struct entryattlist *annots,
			   const char *userid, struct auth_state *authstate)
{
    int r = 0;
    FILE *f = NULL;
    struct stagemsg *stage;
    char *header;
    quota_t qdiffs[QUOTA_NUMRESOURCES] = QUOTA_DIFFS_DONTCARE_INITIALIZER;
    struct appendstate as;
    time_t now = time(0);
    char *freeme = NULL;

    /* Prepare to stage the message */
    if (!(f = append_newstage(mailbox->name, now, 0, &stage))) {
	syslog(LOG_ERR, "append_newstage(%s) failed", mailbox->name);
	return -1;
    }

    /* Create header for resource */
    const char *uid = vparse_stringval(vcard, "uid");
    const char *fullname = vparse_stringval(vcard, "fn");
    if (!resource) resource = freeme = strconcat(uid, ".vcf", (char *)NULL);
    char datestr[80];
    time_to_rfc822(now, datestr, sizeof(datestr));
    struct buf buf = BUF_INITIALIZER;
    vparse_tobuf(vcard, &buf);
    const char *mbuserid = mboxname_to_userid(mailbox->name);

    /* XXX  This needs to be done via an LDAP/DB lookup */
    header = charset_encode_mimeheader(mbuserid, 0);
    fprintf(f, "From: %s <>\r\n", header);
    free(header);

    header = charset_encode_mimeheader(fullname, 0);
    fprintf(f, "Subject: %s\r\n", header);
    free(header);

    fprintf(f, "Date: %s\r\n", datestr);

    if (strchr(uid, '@'))
	fprintf(f, "Message-ID: <%s>\r\n", uid);
    else
	fprintf(f, "Message-ID: <%s@%s>\r\n", uid, config_servername);

    fprintf(f, "Content-Type: text/vcard; charset=utf-8\r\n");

    fprintf(f, "Content-Length: %u\r\n", (unsigned)buf_len(&buf));
    fprintf(f, "Content-Disposition: inline; filename=\"%s\"\r\n", resource);

    /* XXX  Check domain of data and use appropriate CTE */

    fprintf(f, "MIME-Version: 1.0\r\n");
    fprintf(f, "\r\n");

    /* Write the vCard data to the file */
    fprintf(f, "%s", buf_cstring(&buf));
    buf_free(&buf);

    qdiffs[QUOTA_STORAGE] = ftell(f);
    qdiffs[QUOTA_MESSAGE] = 1;

    fclose(f);

    if ((r = append_setup_mbox(&as, mailbox, userid, authstate, 0, qdiffs, 0, 0, EVENT_MESSAGE_NEW|EVENT_CALENDAR))) {
	syslog(LOG_ERR, "append_setup(%s) failed: %s",
	       mailbox->name, error_message(r));
	goto done;
    }

    struct body *body = NULL;

    r = append_fromstage(&as, &body, stage, now, flags, 0, annots);
    if (body) {
	message_free_body(body);
	free(body);
    }

    if (r) {
	syslog(LOG_ERR, "append_fromstage() failed");
	append_abort(&as);
        goto done;
    }

    /* Commit the append to the calendar mailbox */
    r = append_commit(&as);
    if (r) {
	syslog(LOG_ERR, "append_commit() failed");
	goto done;
    }

    if (olduid) {
	/* Now that we have the replacement message in place
	   and the mailbox locked, re-read the old record
	   and see if we should overwrite it.  Either way,
	   one of our records will have to be expunged.
	*/
	struct index_record oldrecord;
	int userflag;
	r = mailbox_user_flag(mailbox, DFLAG_UNBIND, &userflag, 1);
	if (!r) r = mailbox_find_index_record(mailbox, olduid, &oldrecord, NULL);
	if (!r) {
	    oldrecord.user_flags[userflag/32] |= 1<<(userflag&31);
	    oldrecord.system_flags |= FLAG_EXPUNGED;
	    r = mailbox_rewrite_index_record(mailbox, &oldrecord);
	}
	if (r) {
	    syslog(LOG_ERR, "expunging record (%s) failed: %s",
		   mailbox->name, error_message(r));
	    goto done;
	}
    }

done:
    append_removestage(stage);
    free(freeme);
    return r;
}

EXPORTED int carddav_remove(struct mailbox *mailbox, uint32_t olduid)
{

    int userflag;
    int r = mailbox_user_flag(mailbox, DFLAG_UNBIND, &userflag, 1);
    struct index_record oldrecord;
    if (!r) r = mailbox_find_index_record(mailbox, olduid, &oldrecord, NULL);
    if (!r && !(oldrecord.system_flags & FLAG_EXPUNGED)) {
	oldrecord.user_flags[userflag/32] |= 1<<(userflag&31);
	oldrecord.system_flags |= FLAG_EXPUNGED;
	r = mailbox_rewrite_index_record(mailbox, &oldrecord);
    }
    if (r) {
	syslog(LOG_ERR, "expunging record (%s) failed: %s",
	       mailbox->name, error_message(r));
    }
    return r;
}



