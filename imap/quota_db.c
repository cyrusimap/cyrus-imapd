/* quota_db.c -- quota manipulation routines
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
 * $Id: quota_db.c,v 1.11 2010/01/06 17:01:39 murch Exp $
 */

#include <config.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>

#include "assert.h"
#include "cyrusdb.h"
#include "exitcodes.h"
#include "global.h"
#include "imap_err.h"
#include "mailbox.h"
#include "quota.h"
#include "util.h"
#include "xmalloc.h"
#include "xstrlcpy.h"
#include "xstrlcat.h"
#include "strarray.h"

#define QDB config_quota_db

struct db *qdb;

static int quota_dbopen = 0;

/* keywords used when storing fields in the new quota db format */
static const char * const quota_db_names[QUOTA_NUMRESOURCES] = {
    NULL,	/* QUOTA_STORAGE */
    "AS"	/* QUOTA_ANNOTSTORAGE */
};

/* IMAP atoms for various quota resources */
const char * const quota_names[QUOTA_NUMRESOURCES] = {
    "STORAGE",			/* QUOTA_STORAGE -- RFC2087 */
    "X-ANNOTATION-STORAGE"	/* QUOTA_ANNOTSTORAGE */
};

const int quota_units[QUOTA_NUMRESOURCES] = {
    1024,		/* QUOTA_STORAGE -- RFC2087 */
    1024		/* QUOTA_ANNOTSTORAGE */
};

int quota_name_to_resource(const char *str)
{
    int res;

    for (res = 0 ; res < QUOTA_NUMRESOURCES ; res++) {
	if (!strcasecmp(str, quota_names[res]))
	    return res;
    }
    return -1;
}

/*
 * Initialise a struct quota, except that we preserve the original value
 * of the .root field which is presumed to have been passed in by the
 * caller.
 */
static void quota_init(struct quota *q)
{
    const char *root = q->root;	    /* save this, it was passed in */
    int res;

    memset(q, 0, sizeof(*q));
    for (res = 0 ; res < QUOTA_NUMRESOURCES ; res++)
	q->limits[res] = QUOTA_UNLIMITED;
    q->root = root;
}

/*
 * Parse a quota database entry, which is formatted as a string
 * containing multiple space-separated fields, into a struct quota.
 * Returns: 0 on success or an IMAP error code.
 */
static int quota_parseval(const char *data, struct quota *quota)
{
    strarray_t *fields = strarray_split(data, NULL);
    int r = 0;
    int i = 0;
    int res = QUOTA_STORAGE;

    quota_init(quota);

    for (;;) {
	r = IMAP_MAILBOX_BADFORMAT;
	if (i+2 > fields->count)
	    goto out;	/* need at least 2 more fields */
	if (sscanf(fields->data[i++], UQUOTA_T_FMT, &quota->useds[res]) != 1)
	    goto out;
	if (sscanf(fields->data[i++], "%d", &quota->limits[res]) != 1)
	    goto out;
	if (i == fields->count)
	    break;	/* successfully parsed whole line */

	for (res = 0 ; res < QUOTA_NUMRESOURCES ; res++) {
	    if (quota_db_names[res] && !strcasecmp(fields->data[i], quota_db_names[res]))
		break;
	}
	if (res == QUOTA_NUMRESOURCES)
	    goto out;

	i++;
    }

    r = 0;
out:
    strarray_free(fields);
    return r;
}

/*
 * Read the quota entry 'quota'
 */
int quota_read(struct quota *quota, struct txn **tid, int wrlock)
{
    int r;
    int qrlen;
    const char *data;
    int datalen;

    if (!quota->root || !(qrlen = strlen(quota->root)))
	return IMAP_QUOTAROOT_NONEXISTENT;

    if (wrlock)
	r = QDB->fetchlock(qdb, quota->root, qrlen, &data, &datalen, tid);
    else
	r = QDB->fetch(qdb, quota->root, qrlen, &data, &datalen, tid);

    if (!datalen) /* zero byte file can cause no data to be mapped */
	return IMAP_QUOTAROOT_NONEXISTENT;

    switch (r) {
    case CYRUSDB_OK:
	if (!*data) return IMAP_QUOTAROOT_NONEXISTENT;
	r = quota_parseval(data, quota);
	if (r) {
	    syslog(LOG_ERR, "DBERROR: error fetching quota "
			    "root=<%s> value=<%s>",
		   quota->root, data);
	    return r;
	}
	break;

    case CYRUSDB_AGAIN:
	return IMAP_AGAIN;

    case CYRUSDB_NOTFOUND:
	return IMAP_QUOTAROOT_NONEXISTENT;
    }

    if (r) {
	syslog(LOG_ERR, "DBERROR: error fetching quota %s: %s",
	       quota->root, cyrusdb_strerror(r));
	return IMAP_IOERROR;
    }

    return 0;
}

int quota_check(const struct quota *q,
		enum quota_resource res, quota_t delta)
{
    uquota_t lim;

    if (q->limits[res] < 0)
	return 0;	    /* unlimited */

    /*
     * We are always allowed to *reduce* usage even if it doesn't get us
     * below the quota.  As a side effect this allows our caller to pass
     * delta = -1 meaning "don't care about quota checks".
     */
    if (delta < 0)
	return 0;

    lim = (uquota_t)(q->limits[res] * quota_units[res]);
    if (q->useds[res] + delta > lim)
	return IMAP_QUOTA_EXCEEDED;
    return 0;
}

void quota_use(struct quota *q,
	       enum quota_resource res, quota_t delta)
{
    q->useds[res] += delta;
}

struct quota_foreach_t {
    quotaproc_t *proc;
    void *rock;
};

static int do_onequota(void *rock,
		       const char *key, int keylen,
		       const char *data, int datalen)
{
    int r = 0;
    struct quota quota;
    struct quota_foreach_t *fd = (struct quota_foreach_t *)rock;
    char *root = xstrndup(key, keylen);

    quota.root = root;

    /* XXX - error if not parsable? */
    if (datalen && !quota_parseval(data, &quota)) {
	r = fd->proc(&quota, fd->rock);
    }

    free(root);

    return r;
}

int quota_foreach(const char *prefix, quotaproc_t *proc, void *rock)
{
    int r;
    char *search = prefix ? (char *)prefix : "";
    struct quota_foreach_t foreach_d;

    foreach_d.proc = proc;
    foreach_d.rock = rock;

    r = QDB->foreach(qdb, search, strlen(search), NULL,
		     do_onequota, &foreach_d, NULL);

    return r;
}

/*
 * Commit the outstanding quota transaction
 */
void quota_commit(struct txn **tid)
{
    if (tid && *tid) {
	if (QDB->commit(qdb, *tid)) {
	    syslog(LOG_ERR, "IOERROR: committing quota: %m");
	}
	*tid = NULL;
    }
}

/*
 * Abort the outstanding quota transaction
 */
void quota_abort(struct txn **tid)
{
    if (tid && *tid) {
	if (QDB->abort(qdb, *tid)) {
	    syslog(LOG_ERR, "IOERROR: aborting quota: %m");
	}
	*tid = NULL;
    }
}

/*
 * Write out the quota entry 'quota'
 */
int quota_write(struct quota *quota, struct txn **tid)
{
    int r;
    int qrlen;
    int res;
    struct buf buf = BUF_INITIALIZER;

    if (!quota->root) return 0;

    qrlen = strlen(quota->root);
    if (!qrlen) return IMAP_QUOTAROOT_NONEXISTENT;

    for (res = 0 ; res < QUOTA_NUMRESOURCES ; res++)
    {
	if (quota_db_names[res])
	    buf_printf(&buf, " %s ", quota_db_names[res]);
	buf_printf(&buf, UQUOTA_T_FMT " %d",
		   quota->useds[res], quota->limits[res]);
    }

    r = QDB->store(qdb, quota->root, qrlen, buf_cstring(&buf), buf.len, tid);

    switch (r) {
    case CYRUSDB_OK:
	r = 0;
	break;

    case CYRUSDB_AGAIN:
	r = IMAP_AGAIN;
	break;

    default:
	syslog(LOG_ERR, "DBERROR: error storing %s: %s",
	       quota->root, cyrusdb_strerror(r));
	r = IMAP_IOERROR;
	break;
    }

    buf_free(&buf);
    return r;
}

int quota_update_used(const char *quotaroot, enum quota_resource res, quota_t diff)
{
    struct quota q;
    struct txn *tid = NULL;
    int r = 0;

    if (!*quotaroot)
	return IMAP_QUOTAROOT_NONEXISTENT;

    q.root = quotaroot;
    r = quota_read(&q, &tid, 1);

    if (!r) {
	quota_t used = (quota_t)q.useds[res] + diff;
	if (used < 0)
	    used = 0;	    /* prevent underflow */
	q.useds[res] = used;
	r = quota_write(&q, &tid);
    }

    if (r) {
	quota_abort(&tid);
	return r;
    }
    quota_commit(&tid);
    return 0;
}

/*
 * Remove the quota root 'quota'
 */
int quota_deleteroot(const char *quotaroot)
{
    int r;

    if (!quotaroot || !*quotaroot)
	return IMAP_QUOTAROOT_NONEXISTENT;

    r = QDB->delete(qdb, quotaroot, strlen(quotaroot), NULL, 0);

    switch (r) {
    case CYRUSDB_OK:
    case CYRUSDB_NOTFOUND:  /* shouldn't happen anyway */
	return 0;

    case CYRUSDB_AGAIN:
	return IMAP_AGAIN;

    default:
	syslog(LOG_ERR, "DBERROR: error deleting quotaroot %s: %s",
	       quotaroot, cyrusdb_strerror(r));
	return IMAP_IOERROR;
    }
}

/*
 * Find the mailbox 'name' 's quotaroot, and return it in 'ret'.
 * 'ret' must be at least MAX_MAILBOX_NAME.
 *
 * returns true if a quotaroot is found, 0 otherwise. 
*/
int quota_findroot(char *ret, size_t retlen, const char *name)
{
    char *tail, *p, *mbox;

    strlcpy(ret, name, retlen);

    /* find the start of the unqualified mailbox name */
    mbox = (config_virtdomains && (p = strchr(ret, '!'))) ? p+1 : ret;
    tail = mbox + strlen(mbox);

    while (QDB->fetch(qdb, ret, strlen(ret), NULL, NULL, NULL)) {
	tail = strrchr(mbox, '.');
	if (!tail) break;
	*tail = '\0';
    }
    if (tail) return 1;
    if (mbox == ret) return 0;

    /* check for a domain quota */
    *mbox = '\0';
    return (QDB->fetch(qdb, ret, strlen(ret), NULL, NULL, NULL) == 0);
}

/* must be called after cyrus_init */
void quotadb_init(int myflags)
{
    if (myflags & QUOTADB_SYNC) {
	QDB->sync();
    }
}

void quotadb_open(const char *fname)
{
    int ret;
    char *tofree = NULL;
    int flags = CYRUSDB_CREATE;

    if (!fname)
	fname = config_getstring(IMAPOPT_QUOTA_DB_PATH);

    /* create db file name */
    if (!fname) {
	tofree = strconcat(config_dir, FNAME_QUOTADB, (char *)NULL);
	fname = tofree;
    }

    if (config_getswitch(IMAPOPT_IMPROVED_MBOXLIST_SORT))
	flags |= CYRUSDB_MBOXSORT;

    ret = (QDB->open)(fname, flags, &qdb);
    if (ret != 0) {
	syslog(LOG_ERR, "DBERROR: opening %s: %s", fname,
	       cyrusdb_strerror(ret));
	    /* Exiting TEMPFAIL because Sendmail thinks this
	       EC_OSFILE == permanent failure. */
	fatal("can't read quotas file", EC_TEMPFAIL);
    }

    free(tofree);

    quota_dbopen = 1;
}

void quotadb_close(void)
{
    int r;

    if (quota_dbopen) {
	r = (QDB->close)(qdb);
	if (r) {
	    syslog(LOG_ERR, "DBERROR: error closing quotas: %s",
		   cyrusdb_strerror(r));
	}
	quota_dbopen = 0;
    }
}

void quotadb_done(void)
{
    /* DB->done() handled by cyrus_done() */
}
