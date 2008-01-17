/* mboxkey.c -- implementation of URLAUTH mailbox keys
 * $Id: mboxkey.c,v 1.5 2008/01/17 13:25:30 murch Exp $
 * 
 * Copyright (c) 1998-2005 Carnegie Mellon University.  All rights reserved.
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
 *    prior written permission. For permission or any other legal
 *    details, please contact  
 *      Office of Technology Transfer
 *      Carnegie Mellon University
 *      5000 Forbes Avenue
 *      Pittsburgh, PA  15213-3890
 *      (412) 268-4387, fax: (412) 268-7395
 *      tech-transfer@andrew.cmu.edu
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
#include "mboxkey.h"

#define FNAME_MBOXKEYSUFFIX ".mboxkey" /* per user mailbox key extension */

enum {
    MBOXKEY_VERSION = 1,
    MBOXKEY_DEBUG = 0
};

struct mboxkey {
    char *user;			/* what user is this for? */
    char *fname;		/* filename (full path) of db */
    struct db *db;
    struct txn *tid;		/* outstanding txn, if any */
};

static struct mboxkey *lastmboxkey = NULL;

#define DB (config_mboxkey_db)

static void abortcurrent(struct mboxkey *s)
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

char *mboxkey_getpath(const char *userid)
{
    char *fname = xmalloc(strlen(config_dir) + sizeof(FNAME_DOMAINDIR) +
			  sizeof(FNAME_USERDIR) + strlen(userid) +
			  sizeof(FNAME_MBOXKEYSUFFIX) + 10);
    char c, *domain;

    if (config_virtdomains && (domain = strchr(userid, '@'))) {
	char d = (char) dir_hash_c(domain+1, config_fulldirhash);
	*domain = '\0';  /* split user@domain */
	c = (char) dir_hash_c(userid, config_fulldirhash);
	sprintf(fname, "%s%s%c/%s%s%c/%s%s", config_dir, FNAME_DOMAINDIR, d,
		domain+1, FNAME_USERDIR, c, userid, FNAME_MBOXKEYSUFFIX);
	*domain = '@';  /* reassemble user@domain */
    }
    else {
	c = (char) dir_hash_c(userid, config_fulldirhash);
	sprintf(fname, "%s%s%c/%s%s", config_dir, FNAME_USERDIR, c, userid,
		FNAME_MBOXKEYSUFFIX);
    }

    return fname;
}

int mboxkey_open(const char *user,
		 int flags,
		 struct mboxkey **mboxkeydbptr)
{
    struct mboxkey *mboxkeydb;
    struct stat sbuf;
    char *fname = NULL;
    int r;

    /* try to reuse the last db handle */
    mboxkeydb = lastmboxkey;
    lastmboxkey = NULL;
    if (MBOXKEY_DEBUG) {
	syslog(LOG_DEBUG, "mboxkey_db: mboxkey_open(%s)", user);
    }

    /* if this is the db we've already opened, return it */
    if (mboxkeydb && !strcmp(mboxkeydb->user, user) &&
	!stat(mboxkeydb->fname, &sbuf)) {
	abortcurrent(mboxkeydb);
	*mboxkeydbptr = mboxkeydb;
	return 0;
    }

    *mboxkeydbptr = NULL;
    /* otherwise, close the existing database */
    if (mboxkeydb) {
	abortcurrent(mboxkeydb);
	r = (DB->close)(mboxkeydb->db);
	if (r) {
	    syslog(LOG_ERR, "DBERROR: error closing mboxkeydb: %s", 
		   cyrusdb_strerror(r));
	}
	free(mboxkeydb->user);
	free(mboxkeydb->fname);
    } else {
	/* create mboxkeydb */
	mboxkeydb = (struct mboxkey *) xmalloc(sizeof(struct mboxkey));
    }

    /* open the mboxkeydb corresponding to user */
    fname = mboxkey_getpath(user);
    r = (DB->open)(fname, (flags & MBOXKEY_CREATE) ? CYRUSDB_CREATE : 0,
		 &mboxkeydb->db);
    if (r != 0) {
	int level = (flags & MBOXKEY_CREATE) ? LOG_ERR : LOG_DEBUG;
	syslog(level, "DBERROR: opening %s: %s", fname, 
	       cyrusdb_strerror(r));
	r = IMAP_IOERROR;
	free(mboxkeydb);
	free(fname);
	return r;
    }
    syslog(LOG_DEBUG, "mboxkey_db: user %s opened %s", user, fname);

    mboxkeydb->tid = NULL;
    mboxkeydb->user = xstrdup(user);
    mboxkeydb->fname = fname;

    *mboxkeydbptr = mboxkeydb;
    return r;
}

static int mboxkey_readit(struct mboxkey *mboxkeydb, const char *mailbox,
			  const char **mboxkey, size_t *mboxkeylen,
			  int rw)
{
    int r;
    const char *data;
    int datalen;
    unsigned short version, s;

    assert(mboxkeydb && mailbox);
    if (rw || mboxkeydb->tid) {
	r = DB->fetchlock(mboxkeydb->db, mailbox, strlen(mailbox),
			  &data, &datalen, &mboxkeydb->tid);
    } else {
	r = DB->fetch(mboxkeydb->db, mailbox, strlen(mailbox),
		      &data, &datalen, NULL);
    }
    switch (r) {
    case 0:
	break;
    case CYRUSDB_AGAIN:
	syslog(LOG_DEBUG, "deadlock in mboxkey database for '%s/%s'",
	       mboxkeydb->user, mailbox);
	return IMAP_AGAIN;
	break;
    case CYRUSDB_IOERROR:
	syslog(LOG_ERR, "DBERROR: error fetching txn %s",
	       cyrusdb_strerror(r));
	return IMAP_IOERROR;
	break;
    case CYRUSDB_NOTFOUND:
	*mboxkey = NULL;
	*mboxkeylen = 0;

	return 0;
	break;
    }

    /* 'data' is <version><mboxkey> */
    memcpy(&s, data, sizeof(s));
    version = ntohs(s);
    assert(version == MBOXKEY_VERSION);
    *mboxkey = data + sizeof(s);
    *mboxkeylen = datalen - sizeof(s);

    return 0;
}

int mboxkey_read(struct mboxkey *mboxkeydb, const char *mailbox,
		 const char **mboxkey, size_t *mboxkeylen)
{
    if (MBOXKEY_DEBUG) {
	syslog(LOG_DEBUG, "mboxkey_db: mboxkey_read(%s, %s)", 
	       mboxkeydb->user, mailbox);
    }

    return mboxkey_readit(mboxkeydb, mailbox, mboxkey, mboxkeylen, 0);
}

int mboxkey_lockread(struct mboxkey *mboxkeydb, const char *mailbox,
		     const char **mboxkey, size_t *mboxkeylen)
{
    if (MBOXKEY_DEBUG) {
	syslog(LOG_DEBUG, "mboxkey_db: mboxkey_lockread(%s, %s)", 
	       mboxkeydb->user, mailbox);
    }

    return mboxkey_readit(mboxkeydb, mailbox, mboxkey, mboxkeylen, 1);
}

int mboxkey_write(struct mboxkey *mboxkeydb, const char *mailbox,
		  const char *mboxkey, size_t mboxkeylen)
{
    int r;

    assert(mboxkeydb && mailbox);
/*    assert(mboxkeydb->tid);*/

    if (MBOXKEY_DEBUG) {
	syslog(LOG_DEBUG, "mboxkey_db: mboxkey_write(%s, %s, %s)", 
	       mboxkeydb->user, mailbox, mboxkey ? "KEY" : "NIL");
    }

    if (!mboxkey) {
	r = DB->delete(mboxkeydb->db, mailbox, strlen(mailbox),
		       &mboxkeydb->tid, 1);
    }
    else {
	unsigned short version = MBOXKEY_VERSION, s;
	int datalen = sizeof(s) + mboxkeylen;
	char *data = xmalloc(datalen);

	s = htons(version);
	memcpy(data, &s, sizeof(s));
	memcpy(data+sizeof(s), mboxkey, mboxkeylen);

	r = DB->store(mboxkeydb->db, mailbox, strlen(mailbox),
		      data, datalen, &mboxkeydb->tid);
	free(data);
    }

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

int mboxkey_close(struct mboxkey *mboxkeydb)
{
    int r;

    if (MBOXKEY_DEBUG) {
	syslog(LOG_DEBUG, "mboxkey_db: mboxkey_close(%s)", 
	       mboxkeydb->user);
    }

    if (mboxkeydb->tid) {
	r = DB->commit(mboxkeydb->db, mboxkeydb->tid);
	if (r != CYRUSDB_OK) {
	    syslog(LOG_ERR, "DBERROR: error committing mboxkey txn; "
		   "mboxkey state lost: %s", cyrusdb_strerror(r));
	}
	mboxkeydb->tid = NULL;
    }

    if (lastmboxkey) {
	int r;

	/* free the old database hanging around */
	abortcurrent(lastmboxkey);
	r = (DB->close)(lastmboxkey->db);
	if (r != CYRUSDB_OK) {
	    syslog(LOG_ERR, "DBERROR: error closing lastmboxkey: %s",
		   cyrusdb_strerror(r));
	    r = IMAP_IOERROR;
	}
	if(!r) lastmboxkey->db = NULL;
	free(lastmboxkey->user);
	free(lastmboxkey->fname);
	free(lastmboxkey);
	lastmboxkey = NULL;
    }

    /* this database can now be reused */
    lastmboxkey = mboxkeydb;
    return 0;
}

int mboxkey_delete_user(const char *user)
{
    char *fname = mboxkey_getpath(user);
    int r = 0;

    if (MBOXKEY_DEBUG) {
	syslog(LOG_DEBUG, "mboxkey_db: mboxkey_delete_user(%s)", 
	       user);
    }

    /* erp! */
    r = unlink(fname);
    if (r < 0 && errno == ENOENT) {
	syslog(LOG_DEBUG, "can not unlink %s: %m", fname);
	/* but maybe the user just never read anything? */
	r = 0;
    }
    else if (r < 0) {
	syslog(LOG_ERR, "error unlinking %s: %m", fname);
	r = IMAP_IOERROR;
    }
    free(fname);

    if (lastmboxkey) {
	free(lastmboxkey->user);
	free(lastmboxkey->fname);
	free(lastmboxkey);
	lastmboxkey = NULL;
    }

    return r;
}

/* database better have been locked before this ! */
int mboxkey_unlock(struct mboxkey *mboxkeydb)
{
    int r;

    assert(mboxkeydb);
    if (!mboxkeydb->tid) return 0;

    if (MBOXKEY_DEBUG) {
	syslog(LOG_DEBUG, "mboxkey_db: mboxkey_unlock(%s)",
	       mboxkeydb->user);
    }

    r = DB->commit(mboxkeydb->db, mboxkeydb->tid);
    if (r != CYRUSDB_OK) {
	syslog(LOG_ERR, "DBERROR: error committing mboxkey txn; "
	       "mboxkey state lost: %s", cyrusdb_strerror(r));
    }
    mboxkeydb->tid = NULL;

    return 0;
}

int mboxkey_done(void)
{
    int r = 0;

    if (MBOXKEY_DEBUG) {
	syslog(LOG_DEBUG, "mboxkey_db: mboxkey_done()");
    }

    if (lastmboxkey) {
	abortcurrent(lastmboxkey);
	r = (DB->close)(lastmboxkey->db);
	if (r) {
	    syslog(LOG_ERR, "DBERROR: error closing lastmboxkey: %s",
		   cyrusdb_strerror(r));
	    r = IMAP_IOERROR;
	}
	free(lastmboxkey->user);
	free(lastmboxkey->fname);
	free(lastmboxkey);
    }

    return r;
}

struct mboxkey_merge_rock 
{
    struct db *db;
    struct txn *tid;
};

/* Copy keys from tmp file to tgt file.
 *
 * XXX  We currently have nothing to compare against.
 */
static int mboxkey_merge_cb(void *rockp,
			 const char *key, int keylen,
			 const char *tmpdata, int tmpdatalen) 
{
    int r;
    struct mboxkey_merge_rock *rockdata = (struct mboxkey_merge_rock *)rockp;
    struct db *tgtdb = rockdata->db;
    const char *tgtdata;
    int tgtdatalen, dirty = 0;

    if(!tgtdb) return IMAP_INTERNAL;

    r = DB->fetchlock(tgtdb, key, keylen, &tgtdata, &tgtdatalen,
		      &(rockdata->tid));
    if(!r && tgtdata) {
	unsigned short version, s;
	const char *tmp = tmpdata, *tgt = tgtdata;
	
	/* get version */
	memcpy(&s, tgt, sizeof(s));
	version = ntohs(s);
	assert(version == MBOXKEY_VERSION);

	/* get version */
	memcpy(&s, tmp, sizeof(s));
	version = ntohs(s);
	assert(version == MBOXKEY_VERSION);

	dirty = 1;
    } else {
	dirty = 1;
    }
    
    if(dirty) {
	/* write back data from new entry */
	return DB->store(tgtdb, key, keylen, tmpdata, tmpdatalen,
			 &(rockdata->tid));
    } else {
	return 0;
    }
}

int mboxkey_merge(const char *tmpfile, const char *tgtfile) 
{
    int r = 0;
    struct db *tmp = NULL, *tgt = NULL;
    struct mboxkey_merge_rock rock;

    /* xxx does this need to be CYRUSDB_CREATE? */
    r = (DB->open)(tmpfile, CYRUSDB_CREATE, &tmp);
    if(r) goto done;
	    
    r = (DB->open)(tgtfile, CYRUSDB_CREATE, &tgt);
    if(r) goto done;

    rock.db = tgt;
    rock.tid = NULL;
    
    r = DB->foreach(tmp, "", 0, NULL, mboxkey_merge_cb, &rock, &rock.tid);

    if(r) DB->abort(rock.db, rock.tid);
    else DB->commit(rock.db, rock.tid);

 done:

    if(tgt) (DB->close)(tgt);
    if(tmp) (DB->close)(tmp);
    
    return r;
}
