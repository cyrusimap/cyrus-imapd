/* seen_db.c -- implementation of seen database using per-user berkeley db
 *
 * Copyright (c) 1994-2008 Carnegie Mellon University.  All rights reserved.
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
 * $Id: seen_db.c,v 1.62 2010/01/06 17:01:40 murch Exp $
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
#include "cyrusdb.h"
#include "map.h"
#include "bsearch.h"
#include "util.h"

#include "assert.h"
#include "global.h"
#include "xmalloc.h"
#include "xstrlcpy.h"
#include "xstrlcat.h"
#include "mailbox.h"
#include "imap_err.h"
#include "statuscache.h"
#include "seen.h"
#include "sync_log.h"

#define FNAME_SEENSUFFIX ".seen" /* per user seen state extension */
#define FNAME_SEEN "/cyrus.seen" /* for legacy seen state */

enum {
    SEEN_VERSION = 1,
    SEEN_DEBUG = 0
};

struct seen {
    char *user;			/* what user is this for? */
    struct db *db;
    struct txn *tid;		/* outstanding txn, if any */
};

static struct seen *lastseen = NULL;

#define DB (config_seenstate_db)

static void abortcurrent(struct seen *s)
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

char *seen_getpath(const char *userid)
{
    char *fname = xmalloc(strlen(config_dir) + sizeof(FNAME_DOMAINDIR) +
			  sizeof(FNAME_USERDIR) + strlen(userid) +
			  sizeof(FNAME_SEENSUFFIX) + 10);
    char c, *domain;

    if (config_virtdomains && (domain = strchr(userid, '@'))) {
	char d = (char) dir_hash_c(domain+1, config_fulldirhash);
	*domain = '\0';  /* split user@domain */
	c = (char) dir_hash_c(userid, config_fulldirhash);
	sprintf(fname, "%s%s%c/%s%s%c/%s%s", config_dir, FNAME_DOMAINDIR, d,
		domain+1, FNAME_USERDIR, c, userid, FNAME_SEENSUFFIX);
	*domain = '@';  /* reassemble user@domain */
    }
    else {
	c = (char) dir_hash_c(userid, config_fulldirhash);
	sprintf(fname, "%s%s%c/%s%s", config_dir, FNAME_USERDIR, c, userid,
		FNAME_SEENSUFFIX);
    }

    return fname;
}

int seen_open(const char *user, 
	      int flags,
	      struct seen **seendbptr)
{
    struct seen *seendb;
    char *fname = NULL;
    int dbflags = (flags & SEEN_CREATE) ? CYRUSDB_CREATE : 0;
    int r;

    /* try to reuse the last db handle */
    seendb = lastseen;
    lastseen = NULL;
    if (SEEN_DEBUG) {
	syslog(LOG_DEBUG, "seen_db: seen_open(%s)", user);
    }

    /* if this is the db we've already opened, return it */
    if (seendb && !strcmp(seendb->user, user)) {
	abortcurrent(seendb);
	*seendbptr = seendb;
	return 0;
    }

    *seendbptr = NULL;
    /* otherwise, close the existing database */
    if (seendb) {
	abortcurrent(seendb);
	r = (DB->close)(seendb->db);
	if (r) {
	    syslog(LOG_ERR, "DBERROR: error closing seendb: %s", 
		   cyrusdb_strerror(r));
	}
	free(seendb->user);
    } else {
	/* create seendb */
	seendb = (struct seen *) xmalloc(sizeof(struct seen));
    }

    /* open the seendb corresponding to user */
    fname = seen_getpath(user);
    if (flags & SEEN_CREATE) cyrus_mkdir(fname, 0755);
    r = (DB->open)(fname, dbflags, &seendb->db);
    if (r) {
	if (!(flags & SEEN_SILENT)) {
	    int level = (flags & SEEN_CREATE) ? LOG_ERR : LOG_DEBUG;
	    syslog(level, "DBERROR: opening %s: %s", fname, 
		   cyrusdb_strerror(r));
	}
	r = IMAP_IOERROR;
	free(seendb);
	free(fname);
	return r;
    }
    syslog(LOG_DEBUG, "seen_db: user %s opened %s", user, fname);
    free(fname);

    seendb->tid = NULL;
    seendb->user = xstrdup(user);

    *seendbptr = seendb;
    return r;
}

struct seendata_rock {
    seenproc_t *f;
    void *rock;
};

void seen_freedata(struct seendata *sd)
{
    free (sd->seenuids);
}

static void parse_data(const char *data, int datalen, struct seendata *sd)
{
    /* remember that 'data' may not be null terminated ! */
    const char *dend = data + datalen;
    char *p;
    int uidlen;
    int version;

    memset(sd, 0, sizeof(struct seendata));

    version = strtol(data, &p, 10); data = p;
    assert(version == SEEN_VERSION);

    sd->lastread = strtol(data, &p, 10); data = p;
    sd->lastuid = strtoll(data, &p, 10); data = p;
    sd->lastchange = strtol(data, &p, 10); data = p;
    while (p < dend && Uisspace(*p)) p++; data = p;
    uidlen = dend - data;
    sd->seenuids = xmalloc(uidlen + 1);
    memcpy(sd->seenuids, data, uidlen);
    sd->seenuids[uidlen] = '\0';
}

int foreach_proc(void *rock,
		 const char *key,
		 int keylen,
		 const char *data,
		 int datalen)
{
    struct seendata sd;
    struct seendata_rock *sr = (struct seendata_rock *)rock;
    char *name = xstrndup(key, keylen);
    int r;

    parse_data(data, datalen, &sd);

    r = (sr->f)(name, &sd, sr->rock);

    seen_freedata(&sd);
    free(name);

    return r;
}

int seen_foreach(struct seen *seendb, seenproc_t *f, void *rock)
{
    struct seendata_rock sdrock;
    sdrock.f = f;
    sdrock.rock = rock;
    return DB->foreach(seendb->db, "", 0, NULL, foreach_proc, &sdrock, NULL);
}

static int seen_readit(struct seen *seendb, const char *uniqueid,
		       struct seendata *sd, int rw)
{
    int r;
    const char *data;
    int datalen;

    assert(seendb && uniqueid);
    if (rw || seendb->tid) {
	r = DB->fetchlock(seendb->db, uniqueid, strlen(uniqueid),
			  &data, &datalen, &seendb->tid);
    } else {
	r = DB->fetch(seendb->db, uniqueid, strlen(uniqueid),
		      &data, &datalen, NULL);
    }
    switch (r) {
    case 0:
	break;
    case CYRUSDB_AGAIN:
	syslog(LOG_DEBUG, "deadlock in seen database for '%s/%s'",
	       seendb->user, uniqueid);
	return IMAP_AGAIN;
	break;
    case CYRUSDB_NOTFOUND:
	memset(sd, 0, sizeof(struct seendata));
	sd->seenuids = xstrdup("");
	return 0;
	break;
    default:
	syslog(LOG_ERR, "DBERROR: error fetching txn %s",
	       cyrusdb_strerror(r));
	return IMAP_IOERROR;
	break;
    }

    parse_data(data, datalen, sd);

    return 0;
}

int seen_read(struct seen *seendb, const char *uniqueid, struct seendata *sd)
{
    if (SEEN_DEBUG) {
	syslog(LOG_DEBUG, "seen_db: seen_read %s (%s)", 
	       seendb->user, uniqueid);
    }

    return seen_readit(seendb, uniqueid, sd, 0);
}

int seen_lockread(struct seen *seendb, const char *uniqueid, struct seendata *sd)
{
    if (SEEN_DEBUG) {
	syslog(LOG_DEBUG, "seen_db: seen_lockread %s (%s)", 
	       seendb->user, uniqueid);
    }

    return seen_readit(seendb, uniqueid, sd, 1);
}

int seen_write(struct seen *seendb, const char *uniqueid, struct seendata *sd)
{
    int sz = strlen(sd->seenuids) + 50;
    char *data = xmalloc(sz);
    int datalen;
    int r;

    assert(seendb && uniqueid);

    if (SEEN_DEBUG) {
	syslog(LOG_DEBUG, "seen_db: seen_write %s (%s)", 
	       seendb->user, uniqueid);
    }

    snprintf(data, sz, "%d %u %lu %u %s", SEEN_VERSION, 
	    (unsigned)sd->lastread, sd->lastuid, 
	    (unsigned)sd->lastchange, sd->seenuids);
    datalen = strlen(data);

    r = DB->store(seendb->db, uniqueid, strlen(uniqueid),
		  data, datalen, &seendb->tid);
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

    free(data);

    sync_log_seen(seendb->user, uniqueid);

    return r;
}

int seen_close(struct seen *seendb)
{
    int r;

    if (SEEN_DEBUG) {
	syslog(LOG_DEBUG, "seen_db: seen_close(%s)", seendb->user);
    }

    if (seendb->tid) {
	r = DB->commit(seendb->db, seendb->tid);
	if (r != CYRUSDB_OK) {
	    syslog(LOG_ERR, "DBERROR: error committing seen txn; "
		   "seen state lost: %s", cyrusdb_strerror(r));
	}
	seendb->tid = NULL;
    }

    if (lastseen) {
	int r;

	/* free the old database hanging around */
	abortcurrent(lastseen);
	r = (DB->close)(lastseen->db);
	if (r != CYRUSDB_OK) {
	    syslog(LOG_ERR, "DBERROR: error closing lastseen: %s",
		   cyrusdb_strerror(r));
	    r = IMAP_IOERROR;
	}
	if(!r) lastseen->db = NULL;
	free(lastseen->user);
	free(lastseen);
	lastseen = NULL;
    }

    /* this database can now be reused */
    lastseen = seendb;
    return 0;
}

int seen_create_mailbox(struct mailbox *mailbox)
{
    if (SEEN_DEBUG) {
	syslog(LOG_DEBUG, "seen_db: seen_create_mailbox(%s)", 
	       mailbox->uniqueid);
    }

    /* noop */
    return 0;
}

int seen_delete_mailbox(struct mailbox *mailbox)
{
    if (SEEN_DEBUG) {
	syslog(LOG_DEBUG, "seen_db: seen_delete_mailbox(%s)", 
	       mailbox->uniqueid);
    }

    /* noop */
    return 0;
}

int seen_create_user(const char *user)
{
    if (SEEN_DEBUG) {
	syslog(LOG_DEBUG, "seen_db: seen_create_user(%s)", 
	       user);
    }

    /* we'll be lazy here and create this when needed */
    return 0;
}

int seen_delete_user(const char *user)
{
    char *fname = seen_getpath(user);
    int r = 0;

    if (SEEN_DEBUG) {
	syslog(LOG_DEBUG, "seen_db: seen_delete_user(%s)", 
	       user);
    }

    if (unlink(fname) && errno != ENOENT) {
	syslog(LOG_ERR, "error unlinking %s: %m", fname);
	r = IMAP_IOERROR;
    }

    free(fname);
    
    return r;
}

int seen_rename_user(const char *olduser, const char *newuser)
{
    char *oldfname = seen_getpath(olduser);
    char *newfname = seen_getpath(newuser);
    int r = 0;

    if (SEEN_DEBUG) {
	syslog(LOG_DEBUG, "seen_db: seen_rename_user(%s, %s)", 
	       olduser, newuser);
    }

    cyrus_mkdir(newfname, 0755);
    if (rename(oldfname, newfname) && errno != ENOENT) {
	syslog(LOG_ERR, "error renaming %s to %s: %m", oldfname, newfname);
	r = IMAP_IOERROR;
    }

    free(oldfname);
    free(newfname);
    
    return r;
}

int seen_copy(const char *userid, struct mailbox *oldmailbox,
	      struct mailbox *newmailbox)
{
    if (SEEN_DEBUG) {
	syslog(LOG_DEBUG, "seen_db: seen_copy %s (%s => %s)",
	       userid ? userid : "", oldmailbox->uniqueid, newmailbox->uniqueid);
    }

    if (userid && strcmp(oldmailbox->uniqueid, newmailbox->uniqueid)) {
	int r;
	struct seen *seendb;
	struct seendata sd;

	r = seen_open(userid, 0, &seendb);
	if (r) return r;
    
	r = seen_lockread(seendb, oldmailbox->uniqueid, &sd);
	if (!r) r = seen_write(seendb, newmailbox->uniqueid, &sd);

	seen_freedata(&sd);
	seen_close(seendb);
	return r;
    }

    /* noop */
    return 0;
}

/* database better have been locked before this ! */
int seen_unlock(struct seen *seendb)
{
    int r;

    assert(seendb);
    if (!seendb->tid) return 0;

    if (SEEN_DEBUG) {
	syslog(LOG_DEBUG, "seen_db: seen_unlock %s",
	       seendb->user);
    }

    r = DB->commit(seendb->db, seendb->tid);
    if (r != CYRUSDB_OK) {
	syslog(LOG_ERR, "DBERROR: error committing seen txn; "
	       "seen state lost: %s", cyrusdb_strerror(r));
    }
    seendb->tid = NULL;

    return 0;
}

int seen_done(void)
{
    int r = 0;

    if (SEEN_DEBUG) {
	syslog(LOG_DEBUG, "seen_db: seen_done()");
    }

    if (lastseen) {
	abortcurrent(lastseen);
	r = (DB->close)(lastseen->db);
	if (r) {
	    syslog(LOG_ERR, "DBERROR: error closing lastseen: %s",
		   cyrusdb_strerror(r));
	    r = IMAP_IOERROR;
	}
	free(lastseen->user);
	free(lastseen);
    }

    return r;
}

int seen_compare(struct seendata *a, struct seendata *b)
{
    if (a->lastuid == b->lastuid &&
	a->lastread == b->lastread &&
	a->lastchange == b->lastchange &&
	!strcmp(a->seenuids, b->seenuids))
	return 1;

    return 0;
}
