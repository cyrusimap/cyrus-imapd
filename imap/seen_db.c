/* seen_db.c -- implementation of seen database using per-user berkeley db
   $Id: seen_db.c,v 1.31 2002/05/14 20:55:06 rjs3 Exp $
 
 * Copyright (c) 2000 Carnegie Mellon University.  All rights reserved.
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
#include <assert.h>
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

#include "imapconf.h"
#include "xmalloc.h"
#include "mailbox.h"
#include "imap_err.h"
#include "seen.h"

#define FNAME_SEENSUFFIX ".seen" /* per user seen state extension */
#define FNAME_SEEN "/cyrus.seen" /* for legacy seen state */

enum {
    SEEN_VERSION = 1,
    SEEN_DEBUG = 0
};

struct seen {
    char *user;			/* what user is this for? */
    const char *uniqueid;	/* what mailbox? */
    const char *path;		/* where is this mailbox? */
    struct db *db;
    struct txn *tid;		/* outstanding txn, if any */
    int converting;
};

static struct seen *lastseen = NULL;

/* choose "flat" or "db3" here */
#define DB (CONFIG_DB_SEEN)

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
    char *fname = xmalloc(strlen(config_dir) + sizeof(FNAME_USERDIR) +
		    strlen(userid) + sizeof(FNAME_SEENSUFFIX) + 10);
    char c;

    c = (char) dir_hash_c(userid);
    sprintf(fname, "%s%s%c/%s%s", config_dir, FNAME_USERDIR, c, userid,
	    FNAME_SEENSUFFIX);

    return fname;
}

int seen_open(struct mailbox *mailbox, 
	      const char *user, 
	      struct seen **seendbptr)
{
    struct seen *seendb;
    char *fname = NULL;
    int r;

    /* try to reuse the last db handle */
    seendb = lastseen;
    lastseen = NULL;
    if (SEEN_DEBUG) {
	syslog(LOG_DEBUG, "seen_db: seen_open(%s, %s)", 
	       mailbox->uniqueid, user);
    }

    /* if this is the db we've already opened, return it */
    if (seendb && !strcmp(seendb->user, user)) {
	abortcurrent(seendb);
	seendb->uniqueid = mailbox->uniqueid;
	seendb->path = mailbox->path;
	*seendbptr = seendb;
	return 0;
    }

    *seendbptr = NULL;
    /* otherwise, close the existing database */
    if (seendb) {
	abortcurrent(seendb);
	r = DB->close(seendb->db);
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
    r = DB->open(fname, &seendb->db);
    if (r != 0) {
	syslog(LOG_ERR, "DBERROR: opening %s: %s", fname, 
	       cyrusdb_strerror(r));
	r = IMAP_IOERROR;
	free(seendb);
	free(fname);
	return r;
    }
    syslog(LOG_DEBUG, "seen_db: user %s opened %s", user, fname);
    free(fname);

    seendb->tid = NULL;
    seendb->uniqueid = mailbox->uniqueid;
    seendb->path = mailbox->path;
    seendb->user = xstrdup(user);

    *seendbptr = seendb;
    return r;
}

static int seen_readold(struct seen *seendb, 
			time_t *lastreadptr, unsigned int *lastuidptr, 
			time_t *lastchangeptr, char **seenuidsptr)
{
    char fnamebuf[MAX_MAILBOX_PATH];
    struct stat sbuf;
    int fd;
    const char *base;
    const char *buf = 0, *p;
    unsigned long len = 0, linelen;
    unsigned long offset = 0;

    if (SEEN_DEBUG) {
	syslog(LOG_DEBUG, "seen_db: seen_readold(%s, %s)", 
	       seendb->path, seendb->user);
    }

    strcpy(fnamebuf, seendb->path);
    strcat(fnamebuf, FNAME_SEEN);

    fd = open(fnamebuf, O_RDWR, 0);

    *lastreadptr = 0;
    *lastuidptr = 0;
    *lastchangeptr = 0;

    if (fd == -1 && errno == ENOENT) {
	/* no old-style seen file for this database */
	*seenuidsptr = xstrdup("");
	return 0;
    } else if (fd == -1) {
	syslog(LOG_ERR, "error opening '%s': %m", fnamebuf);
	return IMAP_IOERROR;
    }

    if (fstat(fd, &sbuf) == -1) {
	close(fd);
	return IMAP_IOERROR;
    }
    map_refresh(fd, 1, &base, &len, sbuf.st_size, fnamebuf, 0);
    
    /* Find record for user */
    offset = bsearch_mem(seendb->user, 1, base, len, 0, &linelen);

    if (!linelen) {
	*seenuidsptr = xstrdup("");
	close(fd);
	return 0;
    }

    /* Skip over username we know is there */
    buf = base + offset + strlen(seendb->user)+1;
    *lastreadptr = strtol(buf, (char **) &p, 10); buf = p;
    *lastuidptr = strtol(buf, (char **) &p, 10); buf = p;
    *lastchangeptr = strtol(buf, (char **) &p, 10); buf = p;
    while (isspace((int) *p)) p++;
    buf = p;
    /* Scan for end of uids */
    while (p < base + offset + linelen && !isspace((int) *p)) p++;

    *seenuidsptr = xmalloc(p - buf + 1);
    strlcpy(*seenuidsptr, buf, p - buf);
    (*seenuidsptr)[p - buf] = '\0';

    map_free(&base, &len);
    close(fd);

    return 0;
}

static int seen_readit(struct seen *seendb, 
		       time_t *lastreadptr, unsigned int *lastuidptr, 
		       time_t *lastchangeptr, char **seenuidsptr,
		       int rw)
{
    int r;
    const char *data, *dstart, *dend;
    char *p;
    int datalen;
    int version;
    int uidlen;

    assert(seendb && seendb->uniqueid);
    if (rw || seendb->tid) {
	r = DB->fetchlock(seendb->db, 
			  seendb->uniqueid, strlen(seendb->uniqueid),
			  &data, &datalen, &seendb->tid);
    } else {
	r = DB->fetch(seendb->db, 
		      seendb->uniqueid, strlen(seendb->uniqueid),
		      &data, &datalen, NULL);
    }
    switch (r) {
    case 0:
	break;
    case CYRUSDB_AGAIN:
	syslog(LOG_DEBUG, "deadlock in seen database for '%s/%s'",
	       seendb->user, seendb->uniqueid);
	return IMAP_AGAIN;
	break;
    case CYRUSDB_IOERROR:
	syslog(LOG_ERR, "DBERROR: error fetching txn %s",
	       cyrusdb_strerror(r));
	return IMAP_IOERROR;
	break;
    }
    if (data == NULL) {
	r = seen_readold(seendb, lastreadptr, lastuidptr,
			 lastchangeptr, seenuidsptr);
	if (r) {
	    abortcurrent(seendb);
	}
	return r;
    }

    /* remember that 'data' may not be null terminated ! */
    dstart = data;
    dend = data + datalen;

    version = strtol(data, &p, 10); data = p;
    assert(version == SEEN_VERSION);
    *lastreadptr = strtol(data, &p, 10); data = p;
    *lastuidptr = strtol(data, &p, 10); data = p;
    *lastchangeptr = strtol(data, &p, 10); data = p;
    while (isspace((int) *p) && p < dend) p++; data = p;
    uidlen = dend - data;
    *seenuidsptr = xmalloc(uidlen + 1);
    memcpy(*seenuidsptr, data, uidlen);
    (*seenuidsptr)[uidlen] = '\0';

    return 0;
}

int seen_read(struct seen *seendb, 
	      time_t *lastreadptr, unsigned int *lastuidptr, 
	      time_t *lastchangeptr, char **seenuidsptr)
{
    if (SEEN_DEBUG) {
	syslog(LOG_DEBUG, "seen_db: seen_read(%s, %s)", 
	       seendb->uniqueid, seendb->user);
    }

    return seen_readit(seendb, lastreadptr, lastuidptr, lastchangeptr,
		       seenuidsptr, 0);
}

int seen_lockread(struct seen *seendb, 
		  time_t *lastreadptr, unsigned int *lastuidptr, 
		  time_t *lastchangeptr, char **seenuidsptr)
{
    if (SEEN_DEBUG) {
	syslog(LOG_DEBUG, "seen_db: seen_lockread(%s, %s)", 
	       seendb->uniqueid, seendb->user);
    }

    return seen_readit(seendb, lastreadptr, lastuidptr, lastchangeptr,
		       seenuidsptr, 1);
}

int seen_write(struct seen *seendb, time_t lastread, unsigned int lastuid, 
	       time_t lastchange, char *seenuids)
{
    int sz = strlen(seenuids) + 50;
    char *data = xmalloc(sz);
    int datalen;
    int r;

    assert(seendb && seendb->uniqueid);
    assert(seendb->tid);

    if (SEEN_DEBUG) {
	syslog(LOG_DEBUG, "seen_db: seen_write(%s, %s)", 
	       seendb->uniqueid, seendb->user);
    }

    sprintf(data, "%d %d %d %d %s", SEEN_VERSION, 
	    (int) lastread, lastuid, (int) lastchange, seenuids);
    datalen = strlen(data);

    r = DB->store(seendb->db, seendb->uniqueid, strlen(seendb->uniqueid),
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
    return r;
}

int seen_close(struct seen *seendb)
{
    int r;

    if (SEEN_DEBUG) {
	syslog(LOG_DEBUG, "seen_db: seen_close(%s, %s)", 
	       seendb->uniqueid, seendb->user);
    }

    if (seendb->tid) {
	r = DB->commit(seendb->db, seendb->tid);
	if (r != CYRUSDB_OK) {
	    syslog(LOG_ERR, "DBERROR: error committing seen txn; "
		   "seen state lost: %s", cyrusdb_strerror(r));
	    DB->abort(seendb->db, seendb->tid);
	}
	seendb->tid = NULL;
    }

    seendb->uniqueid = NULL;
    seendb->path = NULL;

    if (lastseen) {
	int r;

	/* free the old database hanging around */
	abortcurrent(lastseen);
	r = DB->close(lastseen->db);
	if (r != CYRUSDB_OK) {
	    syslog(LOG_ERR, "DBERROR: error closing lastseen: %s",
		   cyrusdb_strerror(r));
	    r = IMAP_IOERROR;
	}
	free(lastseen->user);
	free(lastseen);
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

    /* erp! */
    r = unlink(fname);
    if (r < 0) {
	syslog(LOG_ERR, "error unlinking %s: %m", fname);
	r = IMAP_IOERROR;
    }
    free(fname);
    
    return r;
}

int seen_copy(struct mailbox *oldmailbox, struct mailbox *newmailbox)
{
    if (SEEN_DEBUG) {
	syslog(LOG_DEBUG, "seen_db: seen_copy(%s, %s)",
	       oldmailbox->uniqueid, newmailbox->uniqueid);
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
	syslog(LOG_DEBUG, "seen_db: seen_unlock(%s, %s)",
	       seendb->uniqueid, seendb->user);
    }

    r = DB->commit(seendb->db, seendb->tid);
    if (r != CYRUSDB_OK) {
	syslog(LOG_ERR, "DBERROR: error committing seen txn; "
	       "seen state lost: %s", cyrusdb_strerror(r));
	DB->abort(seendb->db, seendb->tid);
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
	r = DB->close(lastseen->db);
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

int seen_reconstruct(struct mailbox *mailbox,
		     time_t report_time,
		     time_t prune_time,
		     int (*report_proc)(),
		     void *report_rock)
{
    if (SEEN_DEBUG) {
	syslog(LOG_DEBUG, "seen_db: seen_reconstruct()");
    }

    /* not supported */
    return 0;
}

struct seen_merge_rock 
{
    struct db *db;
    struct txn *tid;
};

/* Look up the unique id in the tgt file, if it is there, compare the
 * last change times, and ensure that the tgt database uses the newer of
 * the two */
static int seen_merge_cb(void *rockp,
			 const char *key, int keylen,
			 const char *tmpdata, int tmpdatalen) 
{
    int r;
    struct seen_merge_rock *rockdata = (struct seen_merge_rock *)rockp;
    struct db *tgtdb = rockdata->db;
    const char *tgtdata;
    int tgtdatalen, dirty = 0;

    if(!tgtdb) return IMAP_INTERNAL;

    r = DB->fetchlock(tgtdb, key, keylen, &tgtdata, &tgtdatalen,
		      &(rockdata->tid));
    if(!r && tgtdata) {
	/* compare timestamps */
	int version, tmplast, tgtlast;
	char *p;
	const char *tmp = tmpdata, *tgt = tgtdata;
	
	/* get version */
	version = strtol(tgt, &p, 10); tgt = p;
	assert(version == SEEN_VERSION);
       	/* skip lastread */
	strtol(tgt, &p, 10); tgt = p;
	/* skip lastuid */
	strtol(tgt, &p, 10); tgt = p;
	/* get lastchange */
	tgtlast = strtol(tgt, &p, 10);

	/* get version */
	version = strtol(tmp, &p, 10); tmp = p;
	assert(version == SEEN_VERSION);
       	/* skip lastread */
	strtol(tmp, &p, 10); tmp = p;
	/* skip lastuid */
	strtol(tmp, &p, 10); tmp = p;
	/* get lastchange */
	tmplast = strtol(tmp, &p, 10);

	if(tmplast > tgtlast) dirty = 1;
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

static int seen_merge_p(void *rockp __attribute__((unused)),
			const char *key __attribute__((unused)),
			int keylen __attribute__((unused)),
			const char *data __attribute__((unused)),
			int datalen __attribute__((unused)))
{
    return 1;
}

int seen_merge(const char *tmpfile, const char *tgtfile) 
{
    int r = 0;
    struct db *tmp = NULL, *tgt = NULL;
    struct seen_merge_rock rock;

    r = DB->open(tmpfile, &tmp);
    if(r) goto done;
	    
    r = DB->open(tgtfile, &tgt);
    if(r) goto done;

    rock.db = tgt;
    rock.tid = NULL;

    r = DB->foreach(tmp, "", 0, seen_merge_p, seen_merge_cb, &rock, NULL);

    if(r) DB->abort(rock.db, rock.tid);
    else DB->commit(rock.db, rock.tid);

 done:

    if(tgt) DB->close(tgt);
    if(tmp) DB->close(tmp);
    
    return r;
}
