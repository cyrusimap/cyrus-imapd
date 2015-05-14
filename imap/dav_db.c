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
#include <sys/wait.h>

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
    " modseq INTEGER,"							\
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
    " alive INTEGER,"							\
    " UNIQUE( mailbox, resource ) );"					\
    "CREATE INDEX IF NOT EXISTS idx_ical_uid ON ical_objs ( ical_uid );"

#define CMD_CREATE_CARD							\
    "CREATE TABLE IF NOT EXISTS vcard_objs ("				\
    " rowid INTEGER PRIMARY KEY,"					\
    " creationdate INTEGER,"						\
    " mailbox TEXT NOT NULL,"						\
    " resource TEXT NOT NULL,"						\
    " imap_uid INTEGER,"						\
    " modseq INTEGER,"							\
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
    " alive INTEGER,"							\
    " UNIQUE( mailbox, resource ) );"					\
    "CREATE INDEX IF NOT EXISTS idx_vcard_fn ON vcard_objs ( fullname );" \
    "CREATE INDEX IF NOT EXISTS idx_vcard_uid ON vcard_objs ( vcard_uid );"

#define CMD_CREATE_EM							\
    "CREATE TABLE IF NOT EXISTS vcard_emails ("				\
    " rowid INTEGER PRIMARY KEY,"					\
    " objid INTEGER,"							\
    " pos INTEGER NOT NULL," /* for sorting */				\
    " email TEXT NOT NULL COLLATE NOCASE,"				\
    " ispref INTEGER NOT NULL DEFAULT 0,"				\
    " FOREIGN KEY (objid) REFERENCES vcard_objs (rowid) ON DELETE CASCADE );" \
    "CREATE INDEX IF NOT EXISTS idx_vcard_email ON vcard_emails ( email COLLATE NOCASE );"

#define CMD_CREATE_GR							\
    "CREATE TABLE IF NOT EXISTS vcard_groups ("				\
    " rowid INTEGER PRIMARY KEY,"					\
    " objid INTEGER,"							\
    " pos INTEGER NOT NULL," /* for sorting */				\
    " member_uid TEXT NOT NULL,"					\
    " otheruser TEXT NOT NULL DEFAULT \"\","				\
    " FOREIGN KEY (objid) REFERENCES vcard_objs (rowid) ON DELETE CASCADE );"

#define CMD_CREATE_OBJS							\
    "CREATE TABLE IF NOT EXISTS dav_objs ("				\
    " rowid INTEGER PRIMARY KEY,"					\
    " creationdate INTEGER,"						\
    " mailbox TEXT NOT NULL,"						\
    " resource TEXT NOT NULL,"						\
    " imap_uid INTEGER,"						\
    " modseq INTEGER,"							\
    " lock_token TEXT,"							\
    " lock_owner TEXT,"							\
    " lock_ownerid TEXT,"						\
    " lock_expire INTEGER,"						\
    " filename TEXT,"							\
    " type TEXT,"							\
    " subtype TEXT,"							\
    " res_uid TEXT,"							\
    " ref_count INTEGER,"						\
    " alive INTEGER,"							\
    " UNIQUE( mailbox, resource ) );"					\
    "CREATE INDEX IF NOT EXISTS idx_res_uid ON dav_objs ( res_uid );"


#define CMD_CREATE CMD_CREATE_CAL CMD_CREATE_CARD CMD_CREATE_EM CMD_CREATE_GR \
		   CMD_CREATE_OBJS

/* leaves these unused columns around, but that's life.  A dav_reconstruct
 * will fix them */
#define CMD_DBUPGRADEv2						\
    "ALTER TABLE ical_objs ADD COLUMN comp_flags INTEGER;"	\
    "UPDATE ical_objs SET comp_flags = recurring + 2 * transp;"

#define CMD_DBUPGRADEv3						\
    "ALTER TABLE ical_objs ADD COLUMN modseq INTEGER;"		\
    "UPDATE ical_objs SET modseq = 1;"				\
    "ALTER TABLE vcard_objs ADD COLUMN modseq INTEGER;"		\
    "UPDATE vcard_objs SET modseq = 1;"

#define CMD_DBUPGRADEv4						\
    "ALTER TABLE ical_objs ADD COLUMN alive INTEGER;"		\
    "UPDATE ical_objs SET alive = 1;"				\
    "ALTER TABLE vcard_objs ADD COLUMN alive INTEGER;"		\
    "UPDATE vcard_objs SET alive = 1;"

#define CMD_DBUPGRADEv5						\
    "ALTER TABLE vcard_emails ADD COLUMN ispref INTEGER NOT NULL DEFAULT 0;"	\
    "ALTER TABLE vcard_groups ADD COLUMN otheruser TEXT NOT NULL DEFAULT \"\";"

#define CMD_DBUPGRADEv6 CMD_CREATE_OBJS

#define DB_VERSION 6

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
#define DAV_OPEN_REBUILD (1<<0)
#define DAV_OPEN_FORCE   (1<<1) /* skip refcount check */
static sqlite3 *dav_open(const char *fname, int flags)
{
    int rc = SQLITE_OK;
    struct stat sbuf;
    struct open_davdb *open;
    char *path = NULL;

    if (!(flags & DAV_OPEN_FORCE)) {
	for (open = open_davdbs; open; open = open->next) {
	    if (!strcmp(open->path, fname)) {
		/* already open! */
		open->refcount++;
		return open->db;
	    }
	}
    }

    open = xzmalloc(sizeof(struct open_davdb));
    open->path = xstrdup(fname);
    path = flags & DAV_OPEN_REBUILD
	 ? strconcat(fname, ".NEW", NULL)
	 : xstrdup(fname);

    rc = stat(path, &sbuf);
    if (rc == -1 && errno == ENOENT) {
	rc = cyrus_mkdir(path, 0755);
    }

#if SQLITE_VERSION_NUMBER >= 3006000
    rc = sqlite3_open_v2(path, &open->db,
			 SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL);
#else
    rc = sqlite3_open(path, &open->db);
#endif
    if (rc != SQLITE_OK) {
	syslog(LOG_ERR, "dav_open(%s) open: %s",
	       path, open->db ? sqlite3_errmsg(open->db) : "failed");
	sqlite3_close(open->db);
	free_dav_open(open);
	free(path);
	return NULL;
    }
    else {
#if SQLITE_VERSION_NUMBER >= 3006000
	sqlite3_extended_result_codes(open->db, 1);
#endif
	sqlite3_trace(open->db, dav_debug, path);
    }

    sqlite3_busy_timeout(open->db, 20*1000); /* 20 seconds is an eternity */

    rc = sqlite3_exec(open->db, "PRAGMA foreign_keys = ON;", NULL, NULL, NULL);
    if (rc != SQLITE_OK) {
	syslog(LOG_ERR, "dav_open(%s) enable foreign_keys: %s",
	    path, sqlite3_errmsg(open->db));
	sqlite3_close(open->db);
	free_dav_open(open);
	free(path);
	return NULL;
    }

    int current_version = 0;
    int i;
    for (i = 0; i < 10; i++) {
	rc = sqlite3_exec(open->db, "PRAGMA user_version;", version_cb, &current_version, NULL);
	if (rc == SQLITE_OK) break;
    }
    if (rc != SQLITE_OK) {
	syslog(LOG_ERR, "dav_open(%s) get user_version: %s (%d)",
	    path, sqlite3_errmsg(open->db), rc);
	sqlite3_close(open->db);
	free_dav_open(open);
	free(path);
	return NULL;
    }
    if (current_version == DB_VERSION) goto out;

    rc = sqlite3_exec(open->db, "BEGIN IMMEDIATE;", NULL, NULL, NULL);
    if (rc != SQLITE_OK) {
	syslog(LOG_ERR, "dav_open(%s) begin: %s",
	    path, sqlite3_errmsg(open->db));
	sqlite3_close(open->db);
	free_dav_open(open);
	free(path);
	return NULL;
    }

    rc = sqlite3_exec(open->db, "PRAGMA user_version;", version_cb, &current_version, NULL);
    if (rc != SQLITE_OK) {
	syslog(LOG_ERR, "dav_open(%s) get user_version locked: %s",
	    path, sqlite3_errmsg(open->db));
	sqlite3_close(open->db);
	free_dav_open(open);
	free(path);
	return NULL;
    }
    if (current_version == DB_VERSION) goto out;
    /* check for synthetic v1 - exists but not the right format */
    if (!current_version) {
	sqlite3_exec(open->db, "SELECT COUNT(*),transp FROM ical_objs;", synthetic_cb, &current_version, NULL);
    }

    if (current_version != DB_VERSION) {
	struct buf buf = BUF_INITIALIZER;

	switch (current_version) {
	case 0:
	    syslog(LOG_NOTICE, "creating dav_db %s", path);
	    rc = sqlite3_exec(open->db, CMD_CREATE, NULL, NULL, NULL);
	    if (rc != SQLITE_OK) {
		syslog(LOG_ERR, "dav_open(%s) create: %s",
		    path, sqlite3_errmsg(open->db));
		sqlite3_close(open->db);
		free_dav_open(open);
		free(path);
		return NULL;
	    }
	    break;

	case 1:
	    syslog(LOG_NOTICE, "upgrading dav_db to v2 %s", path);
	    rc = sqlite3_exec(open->db, CMD_DBUPGRADEv2, NULL, NULL, NULL);
	    if (rc != SQLITE_OK) {
		syslog(LOG_ERR, "dav_open(%s) upgrade v2: %s",
		    path, sqlite3_errmsg(open->db));
		sqlite3_close(open->db);
		free_dav_open(open);
		free(path);
		return NULL;
	    }
	    /* fall through */

	case 2:
	    syslog(LOG_NOTICE, "upgrading dav_db to v3 %s", path);
	    rc = sqlite3_exec(open->db, CMD_DBUPGRADEv3, NULL, NULL, NULL);
	    if (rc != SQLITE_OK) {
		syslog(LOG_ERR, "dav_open(%s) upgrade v3: %s",
		    path, sqlite3_errmsg(open->db));
		sqlite3_close(open->db);
		free_dav_open(open);
		free(path);
		return NULL;
	    }
	    /* fall through */

	case 3:
	    syslog(LOG_NOTICE, "upgrading dav_db to v4 %s", path);
	    rc = sqlite3_exec(open->db, CMD_DBUPGRADEv4, NULL, NULL, NULL);
	    if (rc != SQLITE_OK) {
		syslog(LOG_ERR, "dav_open(%s) upgrade v4: %s",
		    path, sqlite3_errmsg(open->db));
		sqlite3_close(open->db);
		free_dav_open(open);
		free(path);
		return NULL;
	    }
	    /* fall through */

	case 4:
	    syslog(LOG_NOTICE, "upgrading dav_db to v5 %s", path);
	    rc = sqlite3_exec(open->db, CMD_DBUPGRADEv5, NULL, NULL, NULL);
	    if (rc != SQLITE_OK) {
		syslog(LOG_ERR, "dav_open(%s) upgrade v5: %s",
		    path, sqlite3_errmsg(open->db));
		sqlite3_close(open->db);
		free_dav_open(open);
		free(path);
		return NULL;
	    }
	    /* fall through */

	case 5:
	    syslog(LOG_NOTICE, "upgrading dav_db to v6 %s", path);
	    rc = sqlite3_exec(open->db, CMD_DBUPGRADEv6, NULL, NULL, NULL);
	    if (rc != SQLITE_OK) {
		syslog(LOG_ERR, "dav_open(%s) upgrade v6: %s",
		    path, sqlite3_errmsg(open->db));
		sqlite3_close(open->db);
		free_dav_open(open);
		free(path);
		return NULL;
	    }
	    /* fall through */

	    /* AND NOW... (to avoid copy-paste of previous leaving two breaks */
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
		  path, sqlite3_errmsg(open->db));
	    sqlite3_close(open->db);
	    free_dav_open(open);
	    free(path);
	    return NULL;
	}
    }

    rc = sqlite3_exec(open->db, "COMMIT;", NULL, NULL, NULL);
    if (rc != SQLITE_OK) {
	syslog(LOG_ERR, "dav_open(%s) commit: %s",
	    path, sqlite3_errmsg(open->db));
	sqlite3_close(open->db);
	free_dav_open(open);
	free(path);
	return NULL;
    }

out:
    /* stitch on up */
    open->refcount = 1;
    open->next = open_davdbs;
    open_davdbs = open;
    free(path);

    return open->db;
}

EXPORTED sqlite3 *dav_open_userid(const char *userid)
{
    sqlite3 *db = NULL;
    struct buf fname = BUF_INITIALIZER;
    dav_getpath_byuserid(&fname, userid);
    db = dav_open(buf_cstring(&fname), 0);
    buf_free(&fname);
    return db;
}

EXPORTED sqlite3 *dav_open_mailbox(struct mailbox *mailbox)
{
    sqlite3 *db = NULL;
    struct buf fname = BUF_INITIALIZER;
    dav_getpath(&fname, mailbox);
    db = dav_open(buf_cstring(&fname), 0);
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

static void run_audit_tool(const char *tool, const char *srcdb, const char *dstdb)
{
    pid_t pid = fork();
    if (pid < 0)
	return;

    if (pid == 0) {
	/* child */
	execl(tool, tool, srcdb, dstdb, (void *)NULL);
	exit(-1);
    }

    int status;
    while (waitpid(pid, &status, 0) < 0);
}

EXPORTED int dav_reconstruct_user(const char *userid, const char *audit_tool)
{
    syslog(LOG_NOTICE, "dav_reconstruct_user: %s", userid);

    /* XXX - this still means that alarms can go missing if this
     * task is interrupted, but we can't afford to keep the
     * alarm database locked for the entire time, it's a single
     * blocking database over the entire server */
    sqldb_t *alarmdb = caldav_alarm_open();
    caldav_alarm_delete_user(alarmdb, userid);
    caldav_alarm_close(alarmdb);

    struct buf fname = BUF_INITIALIZER;
    dav_getpath_byuserid(&fname, userid);
    char *dstname = xstrdup(buf_cstring(&fname));

    sqlite3 *userdb = dav_open(dstname, DAV_OPEN_REBUILD);
    int r = mboxlist_allusermbox(userid, _dav_reconstruct_mb, NULL, 0);
    dav_close(userdb);

    buf_appendcstr(&fname, ".NEW");

    /* this actually works before close according to the internets */
    if (r) {
	syslog(LOG_ERR, "dav_reconstruct_user: %s FAILED %s", userid, error_message(r));
	if (audit_tool) {
	    printf("Not auditing %s, reconstruct failed %s\n", userid, error_message(r));
	}
	unlink(buf_cstring(&fname));
    }
    else {
	syslog(LOG_NOTICE, "dav_reconstruct_user: %s SUCCEEDED", userid);
	if (audit_tool) {
	    run_audit_tool(audit_tool, dstname, buf_cstring(&fname));
	    unlink(buf_cstring(&fname));
	}
	else {
	    rename(buf_cstring(&fname), dstname);
	}
    }

    buf_free(&fname);

    return 0;
}
