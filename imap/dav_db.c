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

#include "cyrusdb.h"
#include "dav_db.h"
#include "global.h"
#include "util.h"
#include "xmalloc.h"

#define FNAME_DAVSUFFIX ".dav" /* per-user DAV DB extension */

static struct buf fname = BUF_INITIALIZER;

static int dbinit = 0;

int dav_init(void)
{
    if (!dbinit++) {
#if SQLITE_VERSION_NUMBER >= 3006000
	sqlite3_initialize();
#endif
    }

    return 0;
}


int dav_done(void)
{
    if (--dbinit) {
#if SQLITE_VERSION_NUMBER >= 3006000
	sqlite3_shutdown();
#endif

	buf_free(&fname);
    }

    return 0;
}


/* Create filename corresponding to userid's DAV DB */
static const char *dav_getpath(const char *userid)
{
    char c, *domain;

    buf_reset(&fname);
    if (config_virtdomains && (domain = strchr(userid, '@'))) {
	char d = (char) dir_hash_c(domain+1, config_fulldirhash);
	*domain = '\0';  /* split user@domain */
	c = (char) dir_hash_c(userid, config_fulldirhash);
	buf_printf(&fname, "%s%s%c/%s%s%c/%s%s", config_dir, FNAME_DOMAINDIR, d,
		   domain+1, FNAME_USERDIR, c, userid, FNAME_DAVSUFFIX);
	*domain = '@';  /* reassemble user@domain */
    }
    else {
	c = (char) dir_hash_c(userid, config_fulldirhash);
	buf_printf(&fname, "%s%s%c/%s%s", config_dir, FNAME_USERDIR, c, userid,
		   FNAME_DAVSUFFIX);
    }

    return buf_cstring(&fname);
}


/* Open DAV DB corresponding to userid */
sqlite3 *dav_open(const char *userid, const char *cmds)
{
    int rc;
    const char *fname = dav_getpath(userid);
    sqlite3 *db = NULL;

    rc = sqlite3_open(fname, &db);
    if (rc != SQLITE_OK) {
	syslog(LOG_ERR, "dav_open(%s) open: %s",
	       userid, db ? sqlite3_errmsg(db) : "failed");
    }
    else if (cmds) {
	rc = sqlite3_exec(db, cmds, NULL, NULL, NULL);
	if (rc != SQLITE_OK) {
	    syslog(LOG_ERR, "dav_open(%s) cmds: %s",
		   userid, sqlite3_errmsg(db));
	}
    }

    if (rc != SQLITE_OK) {
	sqlite3_close(db);
	db = NULL;
    }

    return db;
}


/* Close DAV DB */
int dav_close(sqlite3 *davdb)
{
    int rc, r = 0;;

    if (!davdb) return 0;

    rc = sqlite3_close(davdb);
    if (rc != SQLITE_OK) {
	syslog(LOG_ERR, "dav_close(): %s", sqlite3_errmsg(davdb));
	r = CYRUSDB_INTERNAL;
    }

    return r;
}


int dav_exec(sqlite3 *davdb, const char *cmd, struct bind_val bval[],
	     int (*cb)(sqlite3_stmt *stmt, void *rock), void *rock,
	     sqlite3_stmt **stmt)
{
    int rc, r = 0;

    if (!*stmt) {
	/* prepare new statement */
	rc = sqlite3_prepare(davdb, cmd, -1, stmt, NULL);
	if (rc != SQLITE_OK) {
	    syslog(LOG_ERR, "dav_exec() prepare: %s", sqlite3_errmsg(davdb));
	    return CYRUSDB_INTERNAL;
	}
    }

    /* reset statement */
    sqlite3_reset(*stmt);

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
	if (!r && cb) r = cb(*stmt, rock);
    }

    if (rc != SQLITE_DONE) {
	syslog(LOG_ERR, "dav_exec() step: %s", sqlite3_errmsg(davdb));
	r = CYRUSDB_INTERNAL;
    }

    return r;
}
