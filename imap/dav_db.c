/* dav_db.c -- implementation of per-user DAV database
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

#include <stdlib.h>
#include <syslog.h>
#include <string.h>
#include <errno.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <sys/stat.h>
#include <sys/types.h>

#include "assert.h"
#include "cyrusdb.h"
#include "dav_db.h"
#include "global.h"
#include "util.h"
#include "xmalloc.h"

#define FNAME_DAVSUFFIX ".dav" /* per-user DAV DB extension */

#define CMD_CREATE_CAL							\
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
    " comp_flags INTEGER,"						\
    " sched_tag TEXT,"							\
    " UNIQUE( mailbox, resource ) );"					\
    "CREATE INDEX IF NOT EXISTS idx_ical_uid ON ical_objs ( ical_uid );"

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

#define CMD_CREATE_EM							\
    "CREATE TABLE IF NOT EXISTS vcard_emails ("				\
    " rowid INTEGER PRIMARY KEY,"					\
    " objid INTEGER,"							\
    " pos INTEGER NOT NULL," /* for sorting */				\
    " email TEXT NOT NULL,"						\
    " FOREIGN KEY (objid) REFERENCES vcard_objs (rowid) ON DELETE CASCADE );" \
    "CREATE INDEX IF NOT EXISTS idx_vcard_email ON vcard_emails ( email );"

#define CMD_CREATE_GR							\
    "CREATE TABLE IF NOT EXISTS vcard_groups ("				\
    " rowid INTEGER PRIMARY KEY,"					\
    " objid INTEGER,"							\
    " pos INTEGER NOT NULL," /* for sorting */				\
    " member_uid TEXT NOT NULL,"					\
    " FOREIGN KEY (objid) REFERENCES vcard_objs (rowid) ON DELETE CASCADE );"

#define CMD_CREATE CMD_CREATE_CAL CMD_CREATE_OBJ CMD_CREATE_EM CMD_CREATE_GR

/* leaves these unused columns around, but that's life.  A dav_reconstruct
 * will fix them */
#define CMD_DBUPDGRADEv2						\
    "ALTER TABLE ical_objs ADD COLUMN comp_flags INTEGER;"		\
    "UPDATE ical_objs SET comp_flags = recurring + 2 * transp;"

#define DB_VERSION 2

struct open_davdb {
    sqlite3 *db;
    char *path;
    unsigned refcount;
    struct open_davdb *next;
};

static struct open_davdb *open_davdbs;

static int dbinit = 0;

EXPORTED int dav_init(void)
{
    if (!dbinit++) {
#if SQLITE_VERSION_NUMBER >= 3006000
	sqlite3_initialize();
#endif
    }

    assert(!open_davdbs);

    return 0;
}


EXPORTED int dav_done(void)
{
    if (--dbinit) {
#if SQLITE_VERSION_NUMBER >= 3006000
	sqlite3_shutdown();
#endif
    }

    /* XXX - report the problems? */
    assert(!open_davdbs);

    return 0;
}


static void dav_debug(void *fname, const char *sql)
{
    syslog(LOG_DEBUG, "dav_exec(%s): %s", (const char *) fname, sql);
}

static void free_dav_open(struct open_davdb *open)
{
    free(open->path);
    free(open);
}

static int version_cb(void *rock, int ncol, char **vals, char **names __attribute__((unused)))
{
    int *vptr = (int *)rock;
    if (ncol == 1 && vals[0])
	*vptr = atoi(vals[0]);
    else
	abort();
    return 0;
}

/* this is only called if there's some schema with the old-style value */
static int synthetic_cb(void *rock, int ncol, char **vals, char **names __attribute__((unused)))
{
    int *vptr = (int *)rock;
    if (ncol == 2 && vals[0])
	*vptr = 1;
    else
	abort();
    return 0;
}

/* Open DAV DB corresponding in file */
static sqlite3 *dav_open(const char *fname)
{
    int rc = SQLITE_OK;
    struct stat sbuf;
    struct open_davdb *open;

    for (open = open_davdbs; open; open = open->next) {
	if (!strcmp(open->path, fname)) {
	    /* already open! */
	    open->refcount++;
	    return open->db;
	}
    }

    open = xzmalloc(sizeof(struct open_davdb));
    open->path = xstrdup(fname);

    rc = stat(open->path, &sbuf);
    if (rc == -1 && errno == ENOENT) {
	rc = cyrus_mkdir(open->path, 0755);
    }

#if SQLITE_VERSION_NUMBER >= 3006000
    rc = sqlite3_open_v2(open->path, &open->db,
			 SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL);
#else
    rc = sqlite3_open(open->path, &open->db);
#endif
    if (rc != SQLITE_OK) {
	syslog(LOG_ERR, "dav_open(%s) open: %s",
	       open->path, open->db ? sqlite3_errmsg(open->db) : "failed");
	sqlite3_close(open->db);
	free_dav_open(open);
	return NULL;
    }
    else {
#if SQLITE_VERSION_NUMBER >= 3006000
	sqlite3_extended_result_codes(open->db, 1);
#endif
	sqlite3_trace(open->db, dav_debug, open->path);
    }

    rc = sqlite3_exec(open->db, "PRAGMA foreign_keys = ON;", NULL, NULL, NULL);
    if (rc != SQLITE_OK) {
	syslog(LOG_ERR, "dav_open(%s) enabled foreign_keys: %s",
	    open->path, sqlite3_errmsg(open->db));
	sqlite3_close(open->db);
	free_dav_open(open);
	return NULL;
    }

    int current_version = 0;
    sqlite3_exec(open->db, "PRAGMA user_version;", version_cb, &current_version, NULL);
    /* check for synthetic v1 - exists but not the right format */
    if (!current_version) {
	sqlite3_exec(open->db, "SELECT COUNT(*),transp FROM ical_objs;", synthetic_cb, &current_version, NULL);
    }

    if (current_version != DB_VERSION) {
	struct buf buf = BUF_INITIALIZER;

	switch (current_version) {
	case 0:
	    syslog(LOG_NOTICE, "creating dav_db %s", open->path);
	    rc = sqlite3_exec(open->db, CMD_CREATE, NULL, NULL, NULL);
	    if (rc != SQLITE_OK) {
		syslog(LOG_ERR, "dav_open(%s) create: %s",
		    open->path, sqlite3_errmsg(open->db));
		sqlite3_close(open->db);
		free_dav_open(open);
		return NULL;
	    }
	    break;

	case 1:
	    syslog(LOG_NOTICE, "upgrading dav_db %s", open->path);
	    rc = sqlite3_exec(open->db, CMD_DBUPDGRADEv2, NULL, NULL, NULL);
	    if (rc != SQLITE_OK) {
		syslog(LOG_ERR, "dav_open(%s) upgrade v2: %s",
		    open->path, sqlite3_errmsg(open->db));
		sqlite3_close(open->db);
		free_dav_open(open);
		return NULL;
	    }
	    break;

	default:
	    abort();  /* unknown version */
	}

	buf_printf(&buf, "PRAGMA user_version = %d;", DB_VERSION);
	rc = sqlite3_exec(open->db, buf_cstring(&buf), NULL, NULL, NULL);
	buf_free(&buf);
	if (rc != SQLITE_OK) {
	    /* XXX - fatal? */
	    syslog(LOG_ERR, "dav_open(%s) user_version: %s",
		  open->path, sqlite3_errmsg(open->db));
	    sqlite3_close(open->db);
	    free_dav_open(open);
	    return NULL;
	}
    }

    /* stitch on up */
    open->refcount = 1;
    open->next = open_davdbs;
    open_davdbs = open;

    return open->db;
}

EXPORTED sqlite3 *dav_open_userid(const char *userid)
{
    sqlite3 *db = NULL;
    struct buf fname = BUF_INITIALIZER;
    dav_getpath_byuserid(&fname, userid);
    db = dav_open(buf_cstring(&fname));
    buf_free(&fname);
    return db;
}

EXPORTED sqlite3 *dav_open_mailbox(struct mailbox *mailbox)
{
    sqlite3 *db = NULL;
    struct buf fname = BUF_INITIALIZER;
    dav_getpath(&fname, mailbox);
    db = dav_open(buf_cstring(&fname));
    buf_free(&fname);
    return db;
}

/* Close DAV DB */
EXPORTED int dav_close(sqlite3 *davdb)
{
    int rc, r = 0;
    struct open_davdb *open, *prev = NULL;

    if (!davdb) return 0;

    for (open = open_davdbs; open; open = open->next) {
	if (davdb == open->db) {
	    if (--open->refcount) return 0; /* still in use */
	    if (prev)
		prev->next = open->next;
	    else
		open_davdbs = open->next;
	    break;
	}
	prev = open;
    }

    assert(open);

    rc = sqlite3_close(open->db);
    if (rc != SQLITE_OK) {
	syslog(LOG_ERR, "dav_close(%s): %s", open->path, sqlite3_errmsg(open->db));
	r = CYRUSDB_INTERNAL;
    }

    free_dav_open(open);

    return r;
}


EXPORTED int dav_exec(sqlite3 *davdb, const char *cmd, struct bind_val bval[],
	     int (*cb)(sqlite3_stmt *stmt, void *rock), void *rock,
	     sqlite3_stmt **stmt)
{
    int rc, r = 0;

    if (!*stmt) {
	/* prepare new statement */
#if SQLITE_VERSION_NUMBER >= 3006000
	rc = sqlite3_prepare_v2(davdb, cmd, -1, stmt, NULL);
#else
	rc = sqlite3_prepare(davdb, cmd, -1, stmt, NULL);
#endif
	if (rc != SQLITE_OK) {
	    syslog(LOG_ERR, "dav_exec() prepare: %s", sqlite3_errmsg(davdb));
	    return CYRUSDB_INTERNAL;
	}
    }

    /* bind values */
    for (; bval && bval->name; bval++) {
	int cidx = sqlite3_bind_parameter_index(*stmt, bval->name);

	switch (bval->type) {
	case SQLITE_INTEGER:
	    sqlite3_bind_int(*stmt, cidx, bval->val.i);
	    break;

	case SQLITE_TEXT:
	    sqlite3_bind_text(*stmt, cidx, bval->val.s, -1, NULL);
	    break;
	}
    }

    /* execute and process the results */
    while ((rc = sqlite3_step(*stmt)) == SQLITE_ROW) {
	if (cb && (r = cb(*stmt, rock))) break;
    }

    /* reset statement and clear all bindings */
    sqlite3_reset(*stmt);
#if SQLITE_VERSION_NUMBER >= 3006000
    sqlite3_clear_bindings(*stmt);
#endif

    if (!r && rc != SQLITE_DONE) {
	syslog(LOG_ERR, "dav_exec() step: %s", sqlite3_errmsg(davdb));
	r = CYRUSDB_INTERNAL;
    }

    return r;
}


EXPORTED int dav_delete(struct mailbox *mailbox)
{
    struct buf fname = BUF_INITIALIZER;
    int r = 0;

    dav_getpath(&fname, mailbox);
    if (unlink(buf_cstring(&fname)) && errno != ENOENT) {
	syslog(LOG_ERR, "dav_db: error unlinking %s: %m", buf_cstring(&fname));
	r = CYRUSDB_INTERNAL;
    }

    buf_free(&fname);

    return r;
}

/*
 * mboxlist_findall() callback function to create DAV DB entries for a mailbox
 */
static int _dav_reconstruct_mb(void *rock __attribute__((unused)),
			       const char *key,
			       size_t keylen,
			       const char *data __attribute__((unused)),
			       size_t datalen __attribute__((unused)))
{
    int r = 0;
    char *name = xstrndup(key, keylen);
    mbentry_t *mbentry = NULL;

    signals_poll();

    r = mboxlist_lookup(name, &mbentry, NULL);
    if (r) goto done;

#ifdef WITH_DAV
    if (mbentry->mbtype & MBTYPES_DAV) {
	struct mailbox *mailbox = NULL;
	/* Open/lock header */
	r = mailbox_open_irl(mbentry->name, &mailbox);
	if (!r) r = mailbox_add_dav(mailbox);
	mailbox_close(&mailbox);
    }
#endif

done:
    mboxlist_entry_free(&mbentry);
    return r;
}

EXPORTED int dav_reconstruct_user(const char *userid)
{
    struct buf fnamebuf = BUF_INITIALIZER;

    syslog(LOG_NOTICE, "dav_reconstruct_user: %s", userid);

    /* remove existing database entirely */
    /* XXX - build a new file and rename into place? */
    dav_getpath_byuserid(&fnamebuf, userid);
    if (buf_len(&fnamebuf))
	unlink(buf_cstring(&fnamebuf));
    buf_free(&fnamebuf);

    struct caldav_alarm_db *alarmdb = caldav_alarm_open();

    caldav_alarm_delete_user(alarmdb, userid);

    mboxlist_allusermbox(userid, _dav_reconstruct_mb, NULL, 0);

    caldav_alarm_close(alarmdb);

    return 0;
}
