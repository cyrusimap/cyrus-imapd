/* seen_db.c -- implementation of seen database using per-user berkeley db
   $Id: seen_db.c,v 1.13 2000/07/30 15:37:26 leg Exp $
 
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

#include "imapconf.h"
#include "xmalloc.h"
#include "mailbox.h"
#include "imap_err.h"

#define FNAME_SEENSUFFIX ".seen" /* per user seen state extension */
#define FNAME_SEEN "/cyrus.seen" /* for legacy seen state */

#define SEEN_VERSION (1)

struct seen {
    const char *user;		/* what user is this for? */
    const char *uniqueid;	/* what mailbox? */
    const char *path;		/* where is this mailbox? */
    struct db *db;
    struct txn *tid;		/* outstanding txn, if any */
};

static struct seen *lastseen = NULL;

#define DB (&cyrusdb_flat)

static void abortcurrent(struct seen *s)
{
    if (s && s->tid) {
	int r = DB->abort(s->db, s->tid);
	if (r) {
	    syslog(LOG_ERR, "DBERROR: error aborting txn: %s", 
		   strerror(r));
	}
	s->tid = NULL;
    }
}

static char *getpath(const char *userid)
{
    char *fname = xmalloc(strlen(config_dir) + sizeof(FNAME_USERDIR) +
		    strlen(userid) + sizeof(FNAME_SEENSUFFIX) + 10);
    char c;

    c = (char) tolower((int) *userid);
    if (!islower((int) c)) { c = 'q'; }
    sprintf(fname, "%s%s%c/%s%s", config_dir, FNAME_USERDIR, c, userid,
	    FNAME_SEENSUFFIX);

    return fname;
}

int seen_open(struct mailbox *mailbox, 
	      const char *user, 
	      struct seen **seendbptr)
{
    struct seen *seendb = lastseen;
    char *fname = NULL;
    int r;

    /* if this is the db we've already opened, return it */
    if (seendb && !strcmp(seendb->user, user)) {
	seendb->uniqueid = mailbox->uniqueid;
	*seendbptr = seendb;
	return 0;
    }

    /* otherwise, close the existing database */
    if (seendb) {
	abortcurrent(seendb);
	r = DB->close(seendb->db);
	if (r) {
	    syslog(LOG_ERR, "DBERROR: error closing seendb: %s", strerror(r));
	}
    } else {
	/* create seendb */
	seendb = (struct seen *) xmalloc(sizeof(struct seen));
    }

    /* open the seendb corresponding to user */
    fname = getpath(user);
    r = DB->open(fname, &seendb->db);
    if (r != 0) {
	syslog(LOG_ERR, "DBERROR: opening %s: %s", fname, strerror(r));
	r = IMAP_IOERROR;
    }
    syslog(LOG_DEBUG, "seen_db: user %s opened %s", user, fname);
    free(fname);

    seendb->tid = NULL;
    seendb->uniqueid = mailbox->uniqueid;
    seendb->path = mailbox->path;
    seendb->user = user;

    *seendbptr = seendb;
    lastseen = seendb;
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

    strcpy(fnamebuf, seendb->path);
    strcat(fnamebuf, FNAME_SEEN);

    fd = open(fnamebuf, O_RDWR, 0);
    if (fd == -1 && errno == ENOENT) {
	/* no old-style seen file for this database */
	linelen = 0;
    } else if (fd == -1) {
	syslog(LOG_ERR, "error opening '%s': %m", fnamebuf);
	return IMAP_IOERROR;
    } else {
	if (fstat(fd, &sbuf) == -1) {
	    close(fd);
	    return IMAP_IOERROR;
	}
	map_refresh(fd, 1, &base, &len, sbuf.st_size, fnamebuf, 0);
	
	/* Find record for user */
	offset = bsearch_mem(seendb->user, 1, base, len, 0, &linelen);
    }

    *lastreadptr = 0;
    *lastuidptr = 0;
    *lastchangeptr = 0;
    if (!linelen) {
	*seenuidsptr = xstrdup("");
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
    strncpy(*seenuidsptr, buf, p - buf);
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
    const char *data, *dstart;
    char *p;
    int datalen;
    int version;
    int uidlen;

    assert(seendb && seendb->uniqueid);

    if (rw) {
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
	syslog(LOG_ERR, "DBERROR: error fetching txn", strerror(r));
	return IMAP_IOERROR;
	break;
    }
    if (data == NULL) {
	return seen_readold(seendb, lastreadptr, lastuidptr,
			    lastchangeptr, seenuidsptr);
    }

    dstart = data;

    version = strtol(data, &p, 10); data = p;
    assert(version == SEEN_VERSION);
    *lastreadptr = strtol(data, &p, 10); data = p;
    *lastuidptr = strtol(data, &p, 10); data = p;
    *lastchangeptr = strtol(data, &p, 10); data = p;
    while (isspace((int) *p)) p++; data = p;
    uidlen = datalen - (data - dstart);
    *seenuidsptr = xmalloc(uidlen + 1);
    memcpy(*seenuidsptr, data, uidlen);
    (*seenuidsptr)[uidlen] = '\0';

    return 0;
}

int seen_read(struct seen *seendb, 
	      time_t *lastreadptr, unsigned int *lastuidptr, 
	      time_t *lastchangeptr, char **seenuidsptr)
{
    return seen_readit(seendb, lastreadptr, lastuidptr, lastchangeptr,
		       seenuidsptr, 0);
}

int seen_lockread(struct seen *seendb, 
		  time_t *lastreadptr, unsigned int *lastuidptr, 
		  time_t *lastchangeptr, char **seenuidsptr)
{
    assert(seendb && seendb->uniqueid);

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

    sprintf(data, "%d %d %d %d %s", SEEN_VERSION, 
	    (int) lastread, lastuid, (int) lastchange, seenuids);
    datalen = strlen(data);

    r = DB->store(seendb->db, seendb->uniqueid, strlen(seendb->uniqueid),
		  data, datalen, NULL);
    switch (r) {
    case CYRUSDB_OK:
	break;
    case CYRUSDB_IOERROR:
	r = IMAP_AGAIN;
	break;
    default:
	syslog(LOG_ERR, "DBERROR: error updating database: %s", strerror(r));
	r = IMAP_IOERROR;
	break;
    }

    free(data);
    return r;
}

int seen_close(struct seen *seendb)
{
    abortcurrent(seendb);

    return 0;
}

int seen_create_mailbox(struct mailbox *mailbox)
{
    /* noop */
    return 0;
}

int seen_delete_mailbox(struct mailbox *mailbox)
{
    /* noop */
    return 0;
}

int seen_create_user(const char *user)
{
    /* we'll be lazy here and create this when needed */
    return 0;
}

int seen_delete_user(const char *user)
{
    char *fname = getpath(user);
    int r = 0;

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
    /* noop */
    return 0;
}

int seen_unlock(struct seen *seendb)
{
    assert(seendb);

    abortcurrent(seendb);
    /* we lazily close the database */
    return 0;
}

int seen_done(void)
{
    struct seen *seendb = lastseen;
    int r = 0;

    if (seendb) {
	abortcurrent(seendb);
	r = DB->close(seendb->db);
	if (r) {
	    syslog(LOG_ERR, "DBERROR: error closing seendb: %s",
		   strerror(r));
	    r = IMAP_IOERROR;
	}
    }

    return r;
}

int seen_reconstruct(struct mailbox *mailbox,
		     time_t report_time,
		     time_t prune_time,
		     int (*report_proc)(),
		     void *report_rock)
{
    /* not supported */
    return 0;
}

