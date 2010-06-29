/* statuscache_db.c -- Status caching routines
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
 * $Id: statuscache_db.c,v 1.8 2010/01/06 17:01:41 murch Exp $
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <ctype.h>
#include <syslog.h>

#include "assert.h"
#include "cyrusdb.h"
#include "exitcodes.h"
#include "imapd.h"
#include "global.h"
#include "imap_err.h"
#include "mboxlist.h"
#include "mailbox.h"
#include "seen.h"
#include "util.h"
#include "xmalloc.h"
#include "xstrlcpy.h"

#include "statuscache.h"

#define DB config_statuscache_db

struct db *statuscachedb;
static int statuscache_dbopen = 0;

void statuscache_open(char *fname)
{
    int ret;
    char *tofree = NULL;

    /* create db file name */
    if (!fname) {
	fname = xmalloc(strlen(config_dir)+sizeof(FNAME_STATUSCACHEDB));
	tofree = fname;
	strcpy(fname, config_dir);
	strcat(fname, FNAME_STATUSCACHEDB);
    }

    ret = DB->open(fname, CYRUSDB_CREATE, &statuscachedb);
    if (ret != 0) {
	syslog(LOG_ERR, "DBERROR: opening %s: %s", fname,
	       cyrusdb_strerror(ret));
	syslog(LOG_ERR, "statuscache in degraded mode");
	return;
    }    

    if (tofree) free(tofree);

    statuscache_dbopen = 1;
}

void statuscache_close(void)
{
    int r;

    if (statuscache_dbopen) {
	r = DB->close(statuscachedb);
	if (r) {
	    syslog(LOG_ERR, "DBERROR: error closing statuscache: %s",
		   cyrusdb_strerror(r));
	}
	statuscache_dbopen = 0;
    }
}

void statuscache_fill(struct statusdata *sdata, const char *userid,
		      struct mailbox *mailbox, unsigned statusitems,
		      unsigned numrecent, unsigned numunseen)
{
    assert(sdata);
    assert(mailbox);

    sdata->userid = userid;
    sdata->statusitems = statusitems;

    sdata->messages = mailbox->i.exists;
    sdata->recent = numrecent;
    sdata->uidnext = mailbox->i.last_uid+1;
    sdata->uidvalidity = mailbox->i.uidvalidity;
    sdata->unseen = numunseen;
    sdata->highestmodseq = mailbox->i.highestmodseq;
}

void statuscache_done(void)
{
    /* DB->done() handled by cyrus_done() */
}

static char *statuscache_buildkey(const char *mailboxname, const char *userid,
				  int *keylen)
{
    static char key[MAX_MAILBOX_BUFFER];
    int len;

    /* Build statuscache key */
    len = strlcpy(key, mailboxname, sizeof(key));
    key[len++] = '%';
    key[len++] = '%';
    len += strlcpy(key + len, userid, sizeof(key) - len);

    *keylen = len;

    return key;
}

/*
 * Performs a STATUS command - note: state MAY be NULL here.
 */
int status_lookup(const char *mboxname, const char *userid,
		  unsigned statusitems, struct statusdata *sdata)
{
    struct mailbox *mailbox;
    unsigned numrecent = 0;
    unsigned numunseen = 0;
    unsigned c_statusitems;
    int r;

    /* Check status cache if possible */
    if (config_getswitch(IMAPOPT_STATUSCACHE)) {
	/* Do actual lookup of cache item. */
	r = statuscache_lookup(mboxname, userid, statusitems, sdata);

	/* Seen/recent status uses "push" invalidation events from
	 * seen_db.c.   This avoids needing to open cyrus.header to get
	 * the mailbox uniqueid to open the seen db and get the
	 * unseen_mtime and recentuid.
	 */

	if (!r) {
	    syslog(LOG_DEBUG, "statuscache, '%s', '%s', '0x%02x', 'yes'",
		   mboxname, userid, statusitems);
	    return 0;
	}

	syslog(LOG_DEBUG, "statuscache, '%s', '%s', '0x%02x', 'no'",
	       mboxname, userid, statusitems);
    }

    /* Missing or invalid cache entry */
    r = mailbox_open_irl(mboxname, &mailbox);
    if (r) return r;

    /* We always have message count, uidnext,
       uidvalidity, and highestmodseq for cache */
     c_statusitems = STATUS_MESSAGES | STATUS_UIDNEXT |
		     STATUS_UIDVALIDITY | STATUS_HIGHESTMODSEQ;

    if (!mailbox->i.exists) {
	/* no messages, so these two must also be zero */
	c_statusitems |= STATUS_RECENT | STATUS_UNSEEN;
    }
    else if (statusitems & (STATUS_RECENT | STATUS_UNSEEN)) {
	/* Read \Seen state */
	struct seqset *seq;
	unsigned recno;
	struct index_record record;
	int internalseen = mailbox_internal_seen(mailbox, userid);
	unsigned recentuid;

	if (internalseen) {
	    recentuid = mailbox->i.recentuid;
	} else {
	    struct seen *seendb;
	    struct seendata sd;

	    r = seen_open(userid, SEEN_CREATE, &seendb);
	    if (r) goto done;

	    r = seen_read(seendb, mailbox->uniqueid, &sd);
	    seen_close(seendb);
	    if (r) goto done;

	    recentuid = sd.lastuid;
	    seq = seqset_parse(sd.seenuids, NULL, recentuid);
	    free(sd.seenuids);
	}

	for (recno = 1; recno <= mailbox->i.num_records; recno++) {
	    if (mailbox_read_index_record(mailbox, recno, &record))
		continue;
	    if (record.system_flags & FLAG_EXPUNGED)
		continue;
	    if (record.uid > recentuid)
		numrecent++;
	    if (internalseen) {
		if (!(record.system_flags & FLAG_SEEN))
		    numunseen++;
	    }
	    else {
		if (!seqset_ismember(seq, record.uid))
		    numunseen++;
	    }
	}

	/* we've calculated the correct values for both */
	c_statusitems |= STATUS_RECENT | STATUS_UNSEEN;
    }

    statuscache_fill(sdata, userid, mailbox, c_statusitems,
		     numrecent, numunseen);

    /* cache the new value while unlocking */
    mailbox_unlock_index(mailbox, sdata);

  done:
    mailbox_close(&mailbox);
    return r;
}

int statuscache_lookup(const char *mboxname, const char *userid,
		       unsigned statusitems, struct statusdata *sdata)
{
    int keylen, datalen, r = 0;
    const char *data = NULL, *dend;
    char *p, *key = statuscache_buildkey(mboxname, userid, &keylen);
    unsigned version;

    /* Don't access DB if it hasn't been opened */
    if (!statuscache_dbopen)
	return IMAP_NO_NOSUCHMSG;

    memset(sdata, 0, sizeof(struct statusdata));

    /* Check if there is an entry in the database */
    do {
	r = DB->fetch(statuscachedb, key, keylen, &data, &datalen, NULL);
    } while (r == CYRUSDB_AGAIN);

    if (r || !data || ((size_t) datalen < sizeof(unsigned))) {
	return IMAP_NO_NOSUCHMSG;
    }

    dend = data + datalen;

    version = (unsigned) strtoul(data, &p, 10);
    if (version != (unsigned) STATUSCACHE_VERSION) {
	/* Wrong version */
	return IMAP_NO_NOSUCHMSG;
    }

    if (p < dend) sdata->statusitems = strtoul(p, &p, 10);
    if (p < dend) sdata->messages = strtoul(p, &p, 10);
    if (p < dend) sdata->recent = strtoul(p, &p, 10);
    if (p < dend) sdata->uidnext = strtoul(p, &p, 10);
    if (p < dend) sdata->uidvalidity = strtoul(p, &p, 10);
    if (p < dend) sdata->unseen = strtoul(p, &p, 10);
#ifdef HAVE_LONG_LONG_INT
    if (p < dend) sdata->highestmodseq = strtoull(p, &p, 10);
#else
    if (p < dend) sdata->highestmodseq = strtoul(p, &p, 10);
#endif

    /* Sanity check the data */
    if (!sdata->statusitems || !sdata->uidnext || !sdata->uidvalidity) {
	return IMAP_NO_NOSUCHMSG;
    }

    if ((sdata->statusitems & statusitems) != statusitems) {
	/* Don't have all of the requested information */
	return IMAP_NO_NOSUCHMSG;
    }

    return 0;
}

static int statuscache_update_txn(const char *mboxname,
				  struct statusdata *sdata,
				  struct txn **tidptr)
{
    char data[250];  /* enough room for 11*(UULONG + SP) */
    int keylen, datalen;
    char *key = statuscache_buildkey(mboxname, sdata->userid, &keylen);
    int r;

    /* Don't access DB if it hasn't been opened */
    if (!statuscache_dbopen)
	return 0;

    /* The trailing whitespace is necessary because we
     * use non-length-based functions to parse the values.
     * Any non-digit char would be fine, but whitespace 
     * looks less ugly in dbtool output */
    datalen = snprintf(data, sizeof(data),
		       "%u %u %u %u %u %u %u " MODSEQ_FMT " ",
		       STATUSCACHE_VERSION,
		       sdata->statusitems, sdata->messages,
		       sdata->recent, sdata->uidnext,
		       sdata->uidvalidity, sdata->unseen,
		       sdata->highestmodseq);

    r = DB->store(statuscachedb, key, keylen, data, datalen, tidptr);

    if (r != CYRUSDB_OK) {
	syslog(LOG_ERR, "DBERROR: error updating database: %s (%s)",
	       mboxname, cyrusdb_strerror(r));
    }

    return r;
}

int statuscache_update(const char *mboxname, struct statusdata *sdata)
{
    statuscache_update_txn(mboxname, sdata, NULL);
    return 0; 
}

struct statuscache_deleterock {
    struct db *db;
    struct txn *tid;
};

static int delete_cb(void *rockp,
                     const char *key, int keylen,
                     const char *data __attribute__((unused)),
                     int datalen __attribute__((unused))) 
{
    int r;
    char buf[4096];
    struct statuscache_deleterock *rp = (struct statuscache_deleterock *)rockp;

    /* error if it's too big */
    if (keylen > 4096)
	return 1;

    /* we need to cache a copy, because the delete might re-map
     * the mmap space */
    memcpy(buf, key, keylen);

    /* Delete db entry */
    r = DB->delete(rp->db, buf, keylen, &rp->tid, 1);
    if (r != CYRUSDB_OK) {
	syslog(LOG_ERR, "DBERROR: error deleting from database: %s", 
	       cyrusdb_strerror(r));
    }

    return 0;
}

int statuscache_invalidate(const char *mboxname, struct statusdata *sdata)
{
    int keylen, r;
    char *key = statuscache_buildkey(mboxname, "", &keylen);
    int doclose = 0;
    struct statuscache_deleterock drock;

    /* Open DB if it hasn't been opened */
    if (!statuscache_dbopen) {
	statuscache_open(NULL);
	doclose = 1;
    }

    drock.db = statuscachedb;
    drock.tid = NULL;

    /* strip off the second NULL that buildkey added, so we match 
     * the entires for all users */
    r = DB->foreach(drock.db, key, keylen - 1, NULL, delete_cb,
		    &drock, &drock.tid);
    if (r != CYRUSDB_OK) {
	syslog(LOG_ERR, "DBERROR: error invalidating: %s (%s)",
	       mboxname, cyrusdb_strerror(r));
    }

    if (!r && sdata) {
	r = statuscache_update_txn(mboxname, sdata, &drock.tid);
    }

    if (r != CYRUSDB_OK)
	DB->abort(drock.db, drock.tid);
    else
	DB->commit(drock.db, drock.tid);

    if (doclose)
	statuscache_close();

    return 0; 
}

