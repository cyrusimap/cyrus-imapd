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

#ifdef WITH_DAV

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

struct open_davdb {
    sqlite3 *db;
    char *path;
    unsigned refcount;
    struct open_davdb *next;
};

static struct open_davdb *open_davdbs = NULL;


static int dbinit = 0;

int dav_init(void)
{
    if (!dbinit++) {
#if SQLITE_VERSION_NUMBER >= 3006000
	sqlite3_initialize();
#endif
    }

    assert(!open_davdbs);

    return 0;
}


int dav_done(void)
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


/* Open DAV DB corresponding to mailbox */
sqlite3 *dav_open(struct mailbox *mailbox, const char *cmds)
{
    int rc = SQLITE_OK;
    struct buf fname = BUF_INITIALIZER;
    struct stat sbuf;
    struct open_davdb *open;

    dav_getpath(&fname, mailbox);

    for (open = open_davdbs; open; open = open->next) {
	if (!strcmp(open->path, buf_cstring(&fname))) {
	    /* already open! */
	    open->refcount++;
	    goto docmds;
	}
    }

    open = xzmalloc(sizeof(struct open_davdb));
    open->path = buf_release(&fname);

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
	sqlite3_trace(open->db, dav_debug, (void *) open->path);
    }

    /* stitch on up */
    open->refcount = 1;
    open->next = open_davdbs;
    open_davdbs = open;

  docmds:
    if (cmds) {
	rc = sqlite3_exec(open->db, cmds, NULL, NULL, NULL);
	if (rc != SQLITE_OK) {
	    /* XXX - fatal? */
	    syslog(LOG_ERR, "dav_open(%s) cmds: %s",
		   open->path, sqlite3_errmsg(open->db));
	}
    }

    buf_free(&fname);

    return open->db;
}


/* Close DAV DB */
int dav_close(sqlite3 *davdb)
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


int dav_exec(sqlite3 *davdb, const char *cmd, struct bind_val bval[],
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


int dav_delete(struct mailbox *mailbox)
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

#endif /* WITH_DAV */
