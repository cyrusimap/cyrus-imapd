/* caldav_db.c -- implementation of per-mailbox CalDAV database
 *
 * Copyright (c) 1994-2011 Carnegie Mellon University.  All rights reserved.
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
#include <ctype.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <errno.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/uio.h>

#include "assert.h"
#include "cyrusdb.h"
#include "map.h"
#include "util.h"

#include "global.h"
#include "xmalloc.h"
#include "mailbox.h"
#include "imap_err.h"
#include "xstrlcpy.h"
#include "caldav_db.h"

enum {
    CALDAV_VERSION = 1,
    CALDAV_DEBUG = 0
};

struct caldav_db {
    char *fname;		/* filename (full path) of db */
    struct db *db;
    struct txn *tid;		/* outstanding txn, if any */
};

static struct caldav_db *lastcaldav = NULL;

#define DB (&cyrusdb_flat) /*(config_caldav_db)*/

static void abortcurrent(struct caldav_db *s)
{
    if (s && s->tid) {
	int r = DB->abort(s->db, s->tid);
	if (r) {
	    syslog(LOG_ERR, "DBERROR: error aborting txn: %s", 
		   cyrusdb_strerror(r));
	}
	s->tid = NULL;
    }
}

int caldav_open(struct mailbox *mailbox, int flags,
		struct caldav_db **caldavdbptr)
{
    struct caldav_db *caldavdb = NULL;
    char *fname = NULL;
    int r;
#if 0
    struct stat sbuf;

    /* try to reuse the last db handle */
    caldavdb = lastcaldav;
    lastcaldav = NULL;
    if (CALDAV_DEBUG) {
	syslog(LOG_DEBUG, "caldav_db: caldav_open(%s)", user);
    }

    /* if this is the db we've already opened, return it */
    if (caldavdb && !strcmp(caldavdb->user, user) &&
	!stat(caldavdb->fname, &sbuf)) {
	abortcurrent(caldavdb);
	*caldavdbptr = caldavdb;
	return 0;
    }
#endif
    *caldavdbptr = NULL;
    /* otherwise, close the existing database */
    if (caldavdb) {
	abortcurrent(caldavdb);
	r = (DB->close)(caldavdb->db);
	if (r) {
	    syslog(LOG_ERR, "DBERROR: error closing caldavdb: %s", 
		   cyrusdb_strerror(r));
	}
	free(caldavdb->fname);
    } else {
	/* create caldavdb */
	caldavdb = (struct caldav_db *) xmalloc(sizeof(struct caldav_db));
    }

    /* open the caldavdb corresponding to mailbox */
    fname = mailbox_meta_fname(mailbox, META_CALDAV);
    r = (DB->open)(fname, (flags & CALDAV_CREATE) ? CYRUSDB_CREATE : 0,
		 &caldavdb->db);
    if (r != 0) {
	int level = (flags & CALDAV_CREATE) ? LOG_ERR : LOG_DEBUG;
	syslog(level, "DBERROR: opening %s: %s", fname, 
	       cyrusdb_strerror(r));
	r = IMAP_IOERROR;
	free(caldavdb);
	return r;
    }
    syslog(LOG_DEBUG, "caldav_db: opened %s", fname);

    caldavdb->tid = NULL;
    caldavdb->fname = xstrdup(fname);

    *caldavdbptr = caldavdb;
    return r;
}

static int parse_data(const char *data, int datalen, uint32_t *uid) {
    char *p;
    unsigned short version;

    /* 'data' is <version> SP <UID> */
    version = strtol(data, &p, 10);
    assert(version == CALDAV_VERSION);

    *uid = strtoul(p, &p, 10);
    /* XXX  may not work for berkeley, skiplist */
    if (p > (data + datalen)) return IMAP_IOERROR;

    return 0;
}

static int caldav_readit(struct caldav_db *caldavdb, const char *resource,
			 uint32_t *uid, int rw)
{
    int r;
    const char *data;
    int datalen;

    assert(caldavdb && resource);

    if (rw || caldavdb->tid) {
	r = DB->fetchlock(caldavdb->db, resource, strlen(resource),
			  &data, &datalen, &caldavdb->tid);
    } else {
	r = DB->fetch(caldavdb->db, resource, strlen(resource),
		      &data, &datalen, NULL);
    }
    switch (r) {
    case 0:
	break;
    case CYRUSDB_AGAIN:
	syslog(LOG_DEBUG, "deadlock in caldav database for '%s'", resource);
	return IMAP_AGAIN;
	break;
    case CYRUSDB_IOERROR:
	syslog(LOG_ERR, "DBERROR: error fetching txn %s",
	       cyrusdb_strerror(r));
	return IMAP_IOERROR;
	break;
    case CYRUSDB_NOTFOUND:
	*uid = 0;

	return 0;
	break;
    }

    return parse_data(data, datalen, uid);
}

int caldav_read(struct caldav_db *caldavdb, const char *resource, uint32_t *uid)
{
    if (CALDAV_DEBUG) {
	syslog(LOG_DEBUG, "caldav_db: caldav_read(%s)", resource);
    }

    return caldav_readit(caldavdb, resource, uid, 0);
}

int caldav_lockread(struct caldav_db *caldavdb, const char *resource,
		    uint32_t *uid)
{
    if (CALDAV_DEBUG) {
	syslog(LOG_DEBUG, "caldav_db: caldav_lockread(%s)", resource);
    }

    return caldav_readit(caldavdb, resource, uid, 1);
}

int caldav_write(struct caldav_db *caldavdb, const char *resource, uint32_t uid)
{
    int r;
	char data[20];

    assert(caldavdb && resource);
/*    assert(caldavdb->tid);*/

    if (CALDAV_DEBUG) {
	syslog(LOG_DEBUG, "caldav_db: caldav_write(%s, %u)", resource, uid);
    }

    snprintf(data, sizeof(data), "%u %u", CALDAV_VERSION, uid);

    r = DB->store(caldavdb->db, resource, strlen(resource),
		  data, strlen(data), &caldavdb->tid);

    switch (r) {
    case CYRUSDB_OK:
	break;
    case CYRUSDB_IOERROR:
	r = IMAP_AGAIN;
	break;
    default:
	syslog(LOG_ERR, "DBERROR: error updating database: %s", 
	       cyrusdb_strerror(r));
	r = IMAP_IOERROR;
	break;
    }

    return r;
}

int caldav_delete(struct caldav_db *caldavdb, const char *resource)
{
    int r;

    assert(caldavdb && resource);
/*    assert(caldavdb->tid);*/

    if (CALDAV_DEBUG) {
	syslog(LOG_DEBUG, "caldav_db: caldav_delete(%s)", resource);
    }

    r = DB->delete(caldavdb->db, resource, strlen(resource),
		   &caldavdb->tid, 1);

    switch (r) {
    case CYRUSDB_OK:
	break;
    case CYRUSDB_IOERROR:
	r = IMAP_AGAIN;
	break;
    default:
	syslog(LOG_ERR, "DBERROR: error updating database: %s", 
	       cyrusdb_strerror(r));
	r = IMAP_IOERROR;
	break;
    }

    return r;
}

struct forrock {
    int (*cb)(void *rock, const char *resource, uint32_t uid);
    void *rock;
};

static int for_cb(void *rock,
		  const char *key, int keylen,
		  const char *data, int datalen)
{
    struct forrock *frock = (struct forrock *) rock;
    char resource[MAX_MAILBOX_PATH+1];
    uint32_t uid;
    int r;

    strlcpy(resource, key, keylen+1);
    resource[keylen] = '\0';

    if ((r = parse_data(data, datalen, &uid))) return r;

    frock->cb(frock->rock, resource, uid);

    return 0;
}

int caldav_foreach(struct caldav_db *caldavdb,
		   int (*cb)(void *rock, const char *resource, uint32_t uid),
		   void *rock)
{
    struct forrock frock;

    frock.cb = cb;
    frock.rock = rock;

    return DB->foreach(caldavdb->db, "", 0, NULL, &for_cb, &frock, NULL);
}

int caldav_close(struct caldav_db *caldavdb)
{
    int r;

    if (CALDAV_DEBUG) {
	syslog(LOG_DEBUG, "caldav_db: caldav_close(%s)", caldavdb->fname);
    }

    if (caldavdb->tid) {
	r = DB->commit(caldavdb->db, caldavdb->tid);
	if (r != CYRUSDB_OK) {
	    syslog(LOG_ERR, "DBERROR: error committing caldav txn; "
		   "caldav state lost: %s", cyrusdb_strerror(r));
	}
	caldavdb->tid = NULL;
    }
#if 0
    r = (DB->close)(caldavdb->db);
    if (r) {
	syslog(LOG_ERR, "DBERROR: error closing: %s",
	       cyrusdb_strerror(r));
	r = IMAP_IOERROR;
    }
	free(caldavdb->fname);
	free(caldavdb);
#else
    if (lastcaldav) {
	int r;

	/* free the old database hanging around */
	abortcurrent(lastcaldav);
	r = (DB->close)(lastcaldav->db);
	if (r != CYRUSDB_OK) {
	    syslog(LOG_ERR, "DBERROR: error closing lastcaldav: %s",
		   cyrusdb_strerror(r));
	    r = IMAP_IOERROR;
	}
	if(!r) lastcaldav->db = NULL;
	free(lastcaldav->fname);
	free(lastcaldav);
	lastcaldav = NULL;
    }

    /* this database can now be reused */
    lastcaldav = caldavdb;
#endif
    return 0;
}

/* database better have been locked before this ! */
int caldav_unlock(struct caldav_db *caldavdb)
{
    int r;

    assert(caldavdb);
    if (!caldavdb->tid) return 0;

    if (CALDAV_DEBUG) {
	syslog(LOG_DEBUG, "caldav_db: caldav_unlock(%s)", caldavdb->fname);
    }

    r = DB->commit(caldavdb->db, caldavdb->tid);
    if (r != CYRUSDB_OK) {
	syslog(LOG_ERR, "DBERROR: error committing caldav txn; "
	       "caldav state lost: %s", cyrusdb_strerror(r));
    }
    caldavdb->tid = NULL;

    return 0;
}

int caldav_done(void)
{
    int r = 0;

    if (CALDAV_DEBUG) {
	syslog(LOG_DEBUG, "caldav_db: caldav_done()");
    }
#if 0
    if (lastcaldav) {
	abortcurrent(lastcaldav);
	r = (DB->close)(lastcaldav->db);
	if (r) {
	    syslog(LOG_ERR, "DBERROR: error closing lastcaldav: %s",
		   cyrusdb_strerror(r));
	    r = IMAP_IOERROR;
	}
	free(lastcaldav->user);
	free(lastcaldav->fname);
	free(lastcaldav);
    }
#endif
    return r;
}
