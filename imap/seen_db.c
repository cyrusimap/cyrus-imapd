/* seen_db.c -- implementation of seen database using per-user berkeley db
   $Id: seen_db.c,v 1.7 2000/04/18 01:00:20 leg Exp $
 
 # Copyright 2000 Carnegie Mellon University
 # 
 # No warranties, either expressed or implied, are made regarding the
 # operation, use, or results of the software.
 #
 # Permission to use, copy, modify and distribute this software and its
 # documentation is hereby granted for non-commercial purposes only
 # provided that this copyright notice appears in all copies and in
 # supporting documentation.
 #
 # Permission is also granted to Internet Service Providers and others
 # entities to use the software for internal purposes.
 #
 # The distribution, modification or sale of a product which uses or is
 # based on the software, in whole or in part, for commercial purposes or
 # benefits requires specific, additional permission from:
 #
 #  Office of Technology Transfer
 #  Carnegie Mellon University
 #  5000 Forbes Avenue
 #  Pittsburgh, PA  15213-3890
 #  (412) 268-4387, fax: (412) 268-7395
 #  tech-transfer@andrew.cmu.edu
 *
 */

#include <config.h>

#include <stdlib.h>
#include <assert.h>
#include <syslog.h>
#include <ctype.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <db.h>

#include "imapconf.h"
#include "xmalloc.h"
#include "mailbox.h"
#include "imap_err.h"

#define FNAME_SEENSUFFIX ".seen"

extern DB_ENV *dbenv;

struct seen {
    const char *user;		/* what user is this for? */
    const char *uniqueid;	/* what mailbox? */
    DB *db;
    DB_TXN *tid;		/* outstanding txn, if any */
};

/* indexed by unique id */
struct seenentry {
    time_t lastread;
    unsigned long lastuid;
    time_t lastchange;
    char seenuids[1];
};

static struct seen *lastseen = NULL;

static void abortcurrent(struct seen *s)
{
    if (s && s->tid) {
	int r = txn_abort(s->tid);
	if (r) {
	    syslog(LOG_ERR, "DBERROR: error aborting txn: %s", 
		   db_strerror(r));
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
	r = seendb->db->close(seendb->db, 0);
	if (r) {
	    syslog(LOG_ERR, "DBERROR: error closing seendb: %s",
		   db_strerror(r));
	}
    } else {
	/* create seendb */
	seendb = (struct seen *) xmalloc(sizeof(struct seen));
	r = db_create(&seendb->db, dbenv, 0);
	if (r) {
	    syslog(LOG_ERR, "db_create() failed: %s", db_strerror(r));
	    return IMAP_IOERROR;
	}
    }

    /* open the seendb corresponding to user */
    fname = getpath(user);
    r = seendb->db->open(seendb->db, fname, NULL, DB_BTREE, DB_CREATE, 0664);
    if (r != 0) {
	syslog(LOG_ERR, "DBERROR: opening %s: %s", fname, db_strerror(r));
	r = IMAP_IOERROR;
    }
    syslog(LOG_DEBUG, "seen_db: user %s opened %s", user, fname);
    free(fname);

    seendb->tid = NULL;
    seendb->uniqueid = mailbox->uniqueid;
    seendb->user = user;

    *seendbptr = seendb;
    lastseen = seendb;
    return r;
}

static int seen_readit(struct seen *seendb, 
		       time_t *lastreadptr, unsigned int *lastuidptr, 
		       time_t *lastchangeptr, char **seenuidsptr,
		       int flags)
{
    int r;
    DBT key, data;
    struct seenentry *e;

    assert(seendb && seendb->uniqueid);

    memset(&key, 0, sizeof(key));
    memset(&data, 0, sizeof(data));

    key.data = (char *) seendb->uniqueid;
    key.size = strlen(seendb->uniqueid);
    r = seendb->db->get(seendb->db, seendb->tid, &key, &data, flags);
    switch (r) {
    case 0:
	break;
    case DB_NOTFOUND:
	*seenuidsptr = xstrdup("");
	return 0;
	break;
    case DB_LOCK_DEADLOCK:
	syslog(LOG_DEBUG, "deadlock in seen database for '%s/%s'",
	       seendb->user, seendb->uniqueid);
	return IMAP_AGAIN;
	break;
    default:
	syslog(LOG_ERR, "DBERROR: error fetching txn: %s", db_strerror(r));
	return IMAP_IOERROR;
	break;
    }

    e = (struct seenentry *) data.data;
    *lastreadptr = ntohl(e->lastread);
    *lastuidptr = ntohl(e->lastuid);
    *lastchangeptr = ntohl(e->lastchange);
    *seenuidsptr = xstrdup(e->seenuids);

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
    int r;

    assert(seendb && seendb->uniqueid);

    if (!seendb->tid) {
	r = txn_begin(dbenv, NULL, &seendb->tid, DB_TXN_NOSYNC);
	if (r) {
	    syslog(LOG_ERR, "DBERROR: error beginning txn: %s", 
		   db_strerror(r));
	    return IMAP_IOERROR;
	}
    }

    return seen_readit(seendb, lastreadptr, lastuidptr, lastchangeptr,
		       seenuidsptr, DB_RMW);
}

int seen_write(struct seen *seendb, time_t lastread, unsigned int lastuid, 
	       time_t lastchange, char *seenuids)
{
    int sz = sizeof(struct seenentry) + strlen(seenuids);
    struct seenentry *e = xmalloc(sz);
    DBT key, data;
    int r;

    assert(seendb && seendb->uniqueid);
    assert(seendb->tid);

    memset(&key, 0, sizeof(key));
    memset(&data, 0, sizeof(data));

    key.data = (void *) seendb->uniqueid;
    key.size = strlen(seendb->uniqueid);

    e->lastread = htonl(lastread);
    e->lastuid = htonl(lastuid);
    e->lastchange = htonl(lastchange);
    strcpy(e->seenuids, seenuids);

    data.data = e;
    data.size = sz;

    r = seendb->db->put(seendb->db, seendb->tid, &key, &data, 0);
    switch (r) {
    case 0:
	break;
    case DB_LOCK_DEADLOCK:
	r = IMAP_AGAIN;
	break;
    default:
	syslog(LOG_ERR, "DBERROR: error updating database: %s",
	       db_strerror(r));
	r = IMAP_IOERROR;
	break;
    }
    if (!r) {
	switch (r = txn_commit(seendb->tid, 0)) {
	case 0:
	    break;
	default:
	    syslog(LOG_ERR, "DBERROR: failed on commit: %s", db_strerror(r));
	    r = IMAP_IOERROR;
	}
	seendb->tid = NULL;
    }

    free(e);
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
    DB *db = NULL;
    char *fname = getpath(user);
    int r;

    /* erp! */
    r = db->open(db, fname, NULL, DB_HASH, 0, 0664);
    free(fname);
    if (!r) {
	r = db->remove(db, fname, NULL, 0);
	if (r) {
	    syslog(LOG_ERR, "DBERROR: removing %s: %s", fname,
		   db_strerror(r));
	    r = 0;
	}
    } else {
	syslog(LOG_ERR, "DBERROR: opening %s: %s", fname, db_strerror(r));
	r = IMAP_IOERROR;
    }
    if (!r) {
	r = db->close(db, 0);
	if (r) {
	    syslog(LOG_ERR, "DBERROR: error closing %s: %s", fname,
		   db_strerror(r));
	    r = IMAP_IOERROR;
	}
    }
    
    return r;
}

int seen_copy(struct mailbox *oldmailbox,struct mailbox *newmailbox)
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
	r = seendb->db->close(seendb->db, 0);
	if (r) {
	    syslog(LOG_ERR, "DBERROR: error closing seendb: %s",
		   db_strerror(r));
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

