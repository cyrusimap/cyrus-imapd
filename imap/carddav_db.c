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
    modseq_t oldmodseq = str2uint64(json_string_value(since));
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
    json_object_set_new(contactGroupUpdates, "oldState", json_string(json_string_value(since))); // XXX - just use refcounted
    json_object_set_new(contactGroupUpdates, "newState", json_string(req->state));
    json_object_set(contactGroupUpdates, "changed", rock.changed);
    json_object_set(contactGroupUpdates, "removed", rock.removed);

    json_t *item = json_pack("[]");
    json_array_append_new(item, json_string("contactGroupUpdates"));
    json_array_append_new(item, contactGroupUpdates);
    json_array_append_new(item, json_string(req->tag));

    json_array_append_new(req->response, item);

    json_t *dofetch = json_object_get(req->args, "fetchContactGroups");
    if (dofetch && json_is_true(dofetch)) {
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

static int getcontacts_cb(sqlite3_stmt *stmt, void *rock)
{
    struct contacts_rock *grock = (struct contacts_rock *)rock;
    const char *card_uid = (const char *)sqlite3_column_text(stmt, 0);
    const char *mboxname = (const char *)sqlite3_column_text(stmt, 1);
    uint32_t uid = sqlite3_column_int(stmt, 2);
    struct index_record record;
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

    const strarray_t *n = vparse_multival(card, "n");
    const strarray_t *org = vparse_multival(card, "org");

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
		}
		else if (!strcasecmp(param->name, "label")) {
		    label = param->value;
		}
	    }
	    json_object_set_new(item, "type", json_string(type));
	    if (label) json_object_set_new(item, "label", json_string(label));

	    json_object_set_new(item, "value", json_string(entry->v.value));

	    json_array_append_new(emails, item);
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

    if (_wantprop(grock->props, "nickname")) {
	const char *item = vparse_stringval(card, "nickname");
	json_object_set_new(obj, "nickname", json_string(item ? item : ""));
    }

    if (_wantprop(grock->props, "nickname")) {
	const char *item = vparse_stringval(card, "nickname");
	json_object_set_new(obj, "nickname", json_string(item ? item : ""));
    }

    /* XXX - other fields */

    json_array_append_new(grock->array, obj);

    return 0;
}

static void _add_group_entries(struct vparse_card *card, json_t *members)
{
    if (card && members)
	return;
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
	/* XXX - default name finding */
	const char *mboxname = mboxname_user_mbox(req->userid, "#addressbooks.Default");

	const char *key;
	json_t *arg;
	json_object_foreach(create, key, arg) {
	    char *uid = makeuuid();
	    json_t *namep = json_object_get(arg, "name");
	    const char *name = namep ? json_string_value(namep) : NULL;
	    struct vparse_card *card = vparse_new_card("VCARD");
	    vparse_add_entry(card, NULL, "VERSION", "3.0");
	    vparse_add_entry(card, NULL, "FN", name ? name : key); // why not ;)
	    vparse_add_entry(card, NULL, "UID", uid);
	    json_t *members = json_object_get(arg, "contactIds");
	    _add_group_entries(card, members);

	    /* we need to create and append a record */
	    if (!mailbox || strcmp(mailbox->name, mboxname)) {
		mailbox_close(&mailbox);
		r = mailbox_open_iwl(mboxname, &mailbox);
		if (r) goto done;
	    }

// XXX - write the card

	    vparse_free_card(card);
	    free(uid);
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
	json_t *updated = json_pack("{}");
	json_t *notUpdated = json_pack("{}");

	const char *uid;
	json_t *arg;
	json_object_foreach(update, uid, arg) {
	    struct carddav_data *cdata = NULL;
	    r = carddav_lookup_uid(carddavdb, uid, 0, &cdata);
	    if (r) goto done;

	    if (!mailbox || strcmp(mailbox->name, cdata->dav.mailbox)) {
		mailbox_close(&mailbox);
		r = mailbox_open_iwl(cdata->dav.mailbox, &mailbox);
		if (r) goto done;
	    }

	    /* XXX - this could definitely be refactored from here and mailbox.c */
	    struct buf msg_buf = BUF_INITIALIZER;
	    struct vparse_state vparser;
	    struct index_record record;

	    r = mailbox_read_index_record(mailbox, cdata->dav.imap_uid, &record);
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
	    if (r) goto done;
	    if (!vparser.card || !vparser.card->objects) {
		vparse_free(&vparser);
		goto done;
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
		vparse_delete_entries(card, NULL, "X-ADDRESSBOOKSERVER-MEMBER");
		_add_group_entries(card, members);
	    }

/* XXX store card */

	    vparse_free(&vparser);
	}

	if (json_object_size(updated))
	    json_object_set(set, "updated", updated);
	json_decref(updated);
	if (json_object_size(notUpdated))
	    json_object_set(set, "notUpdated", notUpdated);
	json_decref(notUpdated);
    }

    json_t *delete = json_object_get(req->args, "delete");
    if (delete) {
	json_t *deleted = json_pack("{}");
	json_t *notDeleted = json_pack("{}");

	size_t index;
	for (index = 0; index < json_array_size(delete); index++) {
	    const char *uid = json_string_value(json_array_get(delete, index));
	    struct carddav_data *cdata = NULL;
	    r = carddav_lookup_uid(carddavdb, uid, 0, &cdata);
	    if (r) goto done;

	    if (!mailbox || strcmp(mailbox->name, cdata->dav.mailbox)) {
		mailbox_close(&mailbox);
		r = mailbox_open_iwl(cdata->dav.mailbox, &mailbox);
		if (r) goto done;
	    }

	    /* XXX - fricking mboxevent */

	    struct index_record record;
	    r = mailbox_read_index_record(mailbox, cdata->dav.imap_uid, &record);
	    if (r) goto done;

	    record.system_flags |= FLAG_EXPUNGED;
	    r = mailbox_rewrite_index_record(mailbox, &record);
	    if (r) goto done;
	}

	if (json_object_size(deleted))
	    json_object_set(set, "deleted", deleted);
	json_decref(deleted);
	if (json_object_size(notDeleted))
	    json_object_set(set, "notDeleted", notDeleted);
	json_decref(notDeleted);
    }

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
    modseq_t oldmodseq = str2uint64(json_string_value(since));
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
    json_object_set_new(contactUpdates, "oldState", json_string(json_string_value(since)));
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
    if (dofetch && json_is_true(dofetch)) {
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

EXPORTED int carddav_setContacts(struct carddav_db *carddavdb, struct jmap_req *req)
{
    struct carddav_data *cdata = NULL;
    /* XXX - should we lock?... it's tricky because we're going to need to lock the DB anyway */
    // maybe a foreach would be better
    int r = carddav_lookup_uid(carddavdb, req->tag, 0, &cdata);

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

EXPORTED int carddav_store(struct mailbox *mailbox, struct vparse_card *vcard,
			   struct index_record *oldrecord, struct carddav_data *cdata)
{
    int r = 0;
    FILE *f = NULL;
    struct stagemsg *stage;
    char *header;
    quota_t qdiffs[QUOTA_NUMRESOURCES] = QUOTA_DIFFS_DONTCARE_INITIALIZER;   
    struct appendstate as;
    time_t now = time(0);

    /* Prepare to stage the message */
    if (!(f = append_newstage(mailbox->name, now, 0, &stage))) {
	syslog(LOG_ERR, "append_newstage(%s) failed", mailbox->name);
	return -1;
    }

    /* Create header for resource */
    const char *uid = vparse_stringval(vcard, "uid");
    const char *fullname = vparse_stringval(vcard, "fn");
    char *resource = cdata ? xstrdup(cdata->dav.resource) : strconcat(uid, ".vcf", (char *)NULL);
    char datestr[80];
    time_to_rfc822(now, datestr, sizeof(datestr));
    struct buf buf = BUF_INITIALIZER;
    vparse_tobuf(vcard, &buf);
    const char *userid = mboxname_to_userid(mailbox->name);

    /* XXX  This needs to be done via an LDAP/DB lookup */
    header = charset_encode_mimeheader(userid, 0);
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

    if ((r = append_setup_mbox(&as, mailbox, NULL, NULL, 0, qdiffs, 0, 0, EVENT_MESSAGE_NEW|EVENT_CALENDAR))) {
	syslog(LOG_ERR, "append_setup(%s) failed: %s",
	       mailbox->name, error_message(r));
	goto done;
    }

    struct body *body = NULL;

    r = append_fromstage(&as, &body, stage, now, NULL, 0, 0);
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

    if (oldrecord) {
	/* Now that we have the replacement message in place
	   and the mailbox locked, re-read the old record
	   and see if we should overwrite it.  Either way,
	   one of our records will have to be expunged.
	*/
	int userflag;
	r = mailbox_user_flag(mailbox, DFLAG_UNBIND, &userflag, 1);
	if (!r) {
	    oldrecord->user_flags[userflag/32] |= 1<<(userflag&31);
	    oldrecord->system_flags |= FLAG_EXPUNGED;
	    r = mailbox_rewrite_index_record(mailbox, oldrecord);
	}
	if (r) {
	    syslog(LOG_ERR, "expunging record (%s) failed: %s",
		   mailbox->name, error_message(r));
	    goto done;
	}
    }

done:
    append_removestage(stage);
    free(resource);
    return r;
}

EXPORTED int carddav_remove(struct mailbox *mailbox,
			    struct index_record *oldrecord)
{

    int userflag;
    int r = mailbox_user_flag(mailbox, DFLAG_UNBIND, &userflag, 1);
    if (!r) {
	oldrecord->user_flags[userflag/32] |= 1<<(userflag&31);
	oldrecord->system_flags |= FLAG_EXPUNGED;
	r = mailbox_rewrite_index_record(mailbox, oldrecord);
    }
    if (r) {
	syslog(LOG_ERR, "expunging record (%s) failed: %s",
	       mailbox->name, error_message(r));
    }
    return r;
}



