/* mboxlist.c -- Mailbox list manipulation routines
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
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <syslog.h>

#include <sys/ipc.h>
#include <sys/msg.h>

#include "acl.h"
#include "annotate.h"
#include "glob.h"
#include "assert.h"
#include "global.h"
#include "cyrusdb.h"
#include "util.h"
#include "mailbox.h"
#include "mboxevent.h"
#include "exitcodes.h"
#include "imap/imap_err.h"
#include "xmalloc.h"
#include "xstrlcpy.h"
#include "partlist.h"
#include "xstrlcat.h"
#include "user.h"

#include "mboxname.h"
#include "mupdate-client.h"

#include "mboxlist.h"
#include "quota.h"
#include "sync_log.h"

#define DB config_mboxlist_db
#define SUBDB config_subscription_db

cyrus_acl_canonproc_t mboxlist_ensureOwnerRights;

EXPORTED struct db *mbdb;

static int mboxlist_dbopen = 0;

static int mboxlist_opensubs(const char *userid, struct db **ret);
static void mboxlist_closesubs(struct db *sub);

static int mboxlist_rmquota(const char *name, int matchlen, int maycreate,
			    void *rock);
static int mboxlist_changequota(const char *name, int matchlen, int maycreate,
				void *rock);

EXPORTED mbentry_t *mboxlist_entry_create(void)
{
    mbentry_t *ret = xzmalloc(sizeof(mbentry_t));
    /* xxx - initialiser functions here? */
    return ret;
}

EXPORTED void mboxlist_entry_free(mbentry_t **mbentryptr)
{
    mbentry_t *mbentry = *mbentryptr;

    /* idempotent */
    if (!mbentry) return;

    free(mbentry->name);
    free(mbentry->ext_name);

    free(mbentry->partition);
    free(mbentry->server);
    free(mbentry->acl);
    free(mbentry->uniqueid);

    free(mbentry->legacy_specialuse);

    free(mbentry);

    *mbentryptr = NULL;
}

static void _write_acl(struct dlist *dl, const char *aclstr)
{
    const char *p, *q;
    struct dlist *al = dlist_newkvlist(dl, "A");

    p = aclstr;

    while (p && *p) {
	char *name,*val;

	q = strchr(p, '\t');
	if (!q) break;

	name = xstrndup(p, q-p);
	q++;

	p = strchr(q, '\t');
	if (p) {
	    val = xstrndup(q, p-q);
	    p++;
	}
	else
	    val = xstrdup(q);

	dlist_setatom(al, name, val);

	free(name);
	free(val);
    }
}

EXPORTED const char *mboxlist_mbtype_to_string(uint32_t mbtype)
{
    static struct buf buf = BUF_INITIALIZER;

    buf_reset(&buf);

    if (mbtype & MBTYPE_DELETED)
	buf_putc(&buf, 'd');
    if (mbtype & MBTYPE_MOVING)
	buf_putc(&buf, 'm');
    if (mbtype & MBTYPE_NETNEWS)
	buf_putc(&buf, 'n');
    if (mbtype & MBTYPE_REMOTE)
	buf_putc(&buf, 'r');
    if (mbtype & MBTYPE_RESERVE)
	buf_putc(&buf, 'z');
    if (mbtype & MBTYPE_CALENDAR)
	buf_putc(&buf, 'c');
    if (mbtype & MBTYPE_ADDRESSBOOK)
	buf_putc(&buf, 'a');

    return buf_cstring(&buf);
}

EXPORTED char *mboxlist_entry_cstring(mbentry_t *mbentry)
{
    struct buf buf = BUF_INITIALIZER;
    struct dlist *dl = dlist_newkvlist(NULL, mbentry->name);

    if (mbentry->acl)
	_write_acl(dl, mbentry->acl);

    if (mbentry->uniqueid)
	dlist_setatom(dl, "I", mbentry->uniqueid);

    if (mbentry->partition)
	dlist_setatom(dl, "P", mbentry->partition);

    if (mbentry->server)
	dlist_setatom(dl, "S", mbentry->server);

    if (mbentry->mbtype)
	dlist_setatom(dl, "T", mboxlist_mbtype_to_string(mbentry->mbtype));

    if (mbentry->uidvalidity)
	dlist_setnum32(dl, "V", mbentry->uidvalidity);

    dlist_setdate(dl, "M", time(NULL));

    dlist_printbuf(dl, 0, &buf);

    dlist_free(&dl);

    return buf_release(&buf);
}

/*
 * read a single record from the mailboxes.db and return a pointer to it
 */
static int mboxlist_read(const char *name, const char **dataptr, size_t *datalenptr,
			 struct txn **tid, int wrlock)
{
    int namelen = strlen(name);
    int r;

    if (!namelen)
	return IMAP_MAILBOX_NONEXISTENT;

    if (wrlock) {
	r = cyrusdb_fetchlock(mbdb, name, namelen, dataptr, datalenptr, tid);
    } else {
	r = cyrusdb_fetch(mbdb, name, namelen, dataptr, datalenptr, tid);
    }

    switch (r) {
    case CYRUSDB_OK:
	/* no entry required, just checking if it exists */
	return 0;
	break;

    case CYRUSDB_AGAIN:
	return IMAP_AGAIN;
	break;

    case CYRUSDB_NOTFOUND:
	return IMAP_MAILBOX_NONEXISTENT;
	break;

    default:
	syslog(LOG_ERR, "DBERROR: error fetching mboxlist %s: %s",
	       name, cyrusdb_strerror(r));
	return IMAP_IOERROR;
	break;
    }

    /* never get here */
}

EXPORTED uint32_t mboxlist_string_to_mbtype(const char *string)
{
    uint32_t mbtype = 0;

    if (!string) return 0; /* null just means default */

    for (; *string; string++) {
	switch (*string) {
	case 'a':
	    mbtype |= MBTYPE_ADDRESSBOOK;
	    break;
	case 'c':
	    mbtype |= MBTYPE_CALENDAR;
	    break;
	case 'd':
	    mbtype |= MBTYPE_DELETED;
	    break;
	case 'm':
	    mbtype |= MBTYPE_MOVING;
	    break;
	case 'n':
	    mbtype |= MBTYPE_NETNEWS;
	    break;
	case 'r':
	    mbtype |= MBTYPE_REMOTE;
	    break;
	case 'z':
	    mbtype |= MBTYPE_RESERVE;
	    break;
	}
    }

    return mbtype;
}

struct parseentry_rock {
    struct mboxlist_entry *mbentry;
    struct buf *aclbuf;
    int doingacl;
};

int parseentry_cb(int type, struct dlistsax_data *d)
{
    struct parseentry_rock *rock = (struct parseentry_rock *)d->rock;

    switch(type) {
    case DLISTSAX_KVLISTSTART:
	if (!strcmp(buf_cstring(&d->kbuf), "A")) {
	    rock->doingacl = 1;
	}
	break;
    case DLISTSAX_KVLISTEND:
	rock->doingacl = 0;
	break;
    case DLISTSAX_STRING:
	if (rock->doingacl) {
	    buf_append(rock->aclbuf, &d->kbuf);
	    buf_putc(rock->aclbuf, '\t');
	    buf_append(rock->aclbuf, &d->buf);
	    buf_putc(rock->aclbuf, '\t');
	}
	else {
	    const char *key = buf_cstring(&d->kbuf);
	    if (!strcmp(key, "I")) {
		rock->mbentry->uniqueid = buf_newcstring(&d->buf);
	    }
	    else if (!strcmp(key, "M")) {
		rock->mbentry->mtime = atoi(buf_cstring(&d->buf));
	    }
	    else if (!strcmp(key, "P")) {
		rock->mbentry->partition = buf_newcstring(&d->buf);
	    }
	    else if (!strcmp(key, "S")) {
		rock->mbentry->server = buf_newcstring(&d->buf);
	    }
	    else if (!strcmp(key, "T")) {
		rock->mbentry->mbtype = mboxlist_string_to_mbtype(buf_cstring(&d->buf));
	    }
	    else if (!strcmp(key, "V")) {
		rock->mbentry->uidvalidity = atoi(buf_cstring(&d->buf));
	    }
	}
    }

    return 0;
}

/*
 * parse a record read from the mailboxes.db into its parts.
 *
 * full dlist format is:
 *  A: _a_cl
 *  I: unique_i_d
 *  M: _m_time
 *  P: _p_artition
 *  S: _s_erver
 *  T: _t_ype
 *  V: uid_v_alidity
 */
EXPORTED int mboxlist_parse_entry(mbentry_t **mbentryptr,
				  const char *name, size_t namelen,
				  const char *data, size_t datalen)
{
    static struct buf aclbuf;
    int r = IMAP_MAILBOX_BADFORMAT;
    char *freeme = NULL;
    char **target;
    char *p, *q;
    mbentry_t *mbentry = mboxlist_entry_create();

    if (!datalen)
	goto done;

    /* copy name */
    if (namelen)
	mbentry->name = xstrndup(name, namelen);
    else
	mbentry->name = xstrdup(name);

    /* check for DLIST mboxlist */
    if (*data == '%') {
	struct parseentry_rock rock;
	memset(&rock, 0, sizeof(struct parseentry_rock));
	rock.mbentry = mbentry;
	rock.aclbuf = &aclbuf;
	aclbuf.len = 0;
	r = dlist_parsesax(data, datalen, 0, parseentry_cb, &rock);
	if (!r) mbentry->acl = buf_newcstring(&aclbuf);
	goto done;
    }

    /* copy data */
    freeme = p = xstrndup(data, datalen);

    /* check for extended mboxlist entry */
    if (*p == '(') {
	int last = 0;
	p++; /* past leading '(' */
	while (!last) {
	    target = NULL;
	    q = p;
	    while (*q && *q != ' ' && *q != ')') q++;
	    if (*q != ' ') break;
	    *q++ = '\0';
	    if (!strcmp(p, "uniqueid")) target = &mbentry->uniqueid;
	    if (!strcmp(p, "specialuse")) target = &mbentry->legacy_specialuse;
	    p = q;
	    while (*q && *q != ' ' && *q != ')') q++;
	    if (*q != ' ') last = 1;
	    if (*q) *q++ = '\0';
	    if (target) *target = xstrdup(p);
	    p = q;
	}
	if (*p == ' ') p++; /* past trailing ' ' */
    }

    /* copy out interesting parts */
    mbentry->mbtype = strtol(p, &p, 10);
    if (*p == ' ') p++;

    q = p;
    while (*q && *q != ' ' && *q != '!') q++;
    if (*q == '!') {
	*q++ = '\0';
	mbentry->server = xstrdup(p);
	p = q;
	while (*q && *q != ' ') q++;
    }
    if (*q) *q++ = '\0';
    mbentry->partition = xstrdup(p);

    mbentry->acl = xstrdup(q);

    r = 0;

done:
    if (!r && mbentryptr)
	*mbentryptr = mbentry;
    else mboxlist_entry_free(&mbentry);
    free(freeme);
    return r;
}

/* read a record and parse into parts */
static int mboxlist_mylookup(const char *name,
			     mbentry_t **mbentryptr,
			     struct txn **tid, int wrlock)
{
    int r;
    const char *data;
    size_t datalen;

    r = mboxlist_read(name, &data, &datalen, tid, wrlock);
    if (r) return r;

    return mboxlist_parse_entry(mbentryptr, name, 0, data, datalen);
}

EXPORTED int mboxlist_delete(const char *name, int force)
{
    return cyrusdb_delete(mbdb, name, strlen(name), NULL, force);
}

/*
 * Lookup 'name' in the mailbox list, ignoring reserved records
 */
EXPORTED int mboxlist_lookup(const char *name, mbentry_t **entryptr,
			     struct txn **tid)
{
    mbentry_t *entry = NULL;
    int r;

    r = mboxlist_mylookup(name, &entry, tid, 0);

    if (r) return r;

    /* Ignore "reserved" entries, like they aren't there */
    if (entry->mbtype & MBTYPE_RESERVE) {
	mboxlist_entry_free(&entry);
	return IMAP_MAILBOX_RESERVED;
    }

    /* Ignore "deleted" entries, like they aren't there */
    if (entry->mbtype & MBTYPE_DELETED) {
	mboxlist_entry_free(&entry);
	return IMAP_MAILBOX_NONEXISTENT;
    }

    if (entryptr) *entryptr = entry;
    else mboxlist_entry_free(&entry);

    return 0;
}

EXPORTED int mboxlist_lookup_allow_all(const char *name,
				   mbentry_t **entryptr,
				   struct txn **tid)
{
    return mboxlist_mylookup(name, entryptr, tid, 0);
}

/* given a mailbox name, find the staging directory.  XXX - this should
 * require more locking, and staging directories should be by pid */
HIDDEN int mboxlist_findstage(const char *name, char *stagedir, size_t sd_len)
{
    const char *root;
    mbentry_t *mbentry = NULL;
    int r;

    assert(stagedir != NULL);

    /* Find mailbox */
    r = mboxlist_lookup(name, &mbentry, NULL);
    if (r) return r;

    root = config_partitiondir(mbentry->partition);
    mboxlist_entry_free(&mbentry);

    if (!root) return IMAP_PARTITION_UNKNOWN;

    snprintf(stagedir, sd_len, "%s/stage./", root);

    return 0;
}

EXPORTED int mboxlist_update(mbentry_t *mbentry, int localonly)
{
    int r = 0, r2 = 0;
    char *mboxent = NULL;
    struct txn *tid = NULL;

    mboxent = mboxlist_entry_cstring(mbentry);
    r = cyrusdb_store(mbdb, mbentry->name, strlen(mbentry->name),
		      mboxent, strlen(mboxent), &tid);
    free(mboxent);
    mboxent = NULL;

    /* commit the change to mupdate */
    if (!r && !localonly && config_mupdate_server) {
        mupdate_handle *mupdate_h = NULL;

	r = mupdate_connect(config_mupdate_server, NULL, &mupdate_h, NULL);
	if (r) {
	    syslog(LOG_ERR,
		   "cannot connect to mupdate server for update of '%s'",
		   mbentry->name);
	} else {
	    char *location = strconcat(config_servername, "!",
				       mbentry->partition, (char *)NULL);
	    r = mupdate_activate(mupdate_h, mbentry->name,
				 location, mbentry->acl);
	    free(location);
	    if (r) {
		syslog(LOG_ERR,
		       "MUPDATE: can't update mailbox entry for '%s'",
		       mbentry->name);
	    }
	}
	mupdate_disconnect(&mupdate_h);
    }

    if (tid) {
	if (r) {
	    r2 = cyrusdb_abort(mbdb, tid);
	} else {
	    r2 = cyrusdb_commit(mbdb, tid);
	}
    }

    if (r2) {
	syslog(LOG_ERR, "DBERROR: error %s txn in mboxlist_update: %s",
	       r ? "aborting" : "commiting", cyrusdb_strerror(r2));
    }

    return r;
}

EXPORTED int mboxlist_findparent(const char *mboxname,
			       mbentry_t **mbentryp)
{
    mbentry_t *mbentry = NULL;
    char *parent = xstrdup(mboxname);
    int parentlen = 0;
    char *p;
    int r = IMAP_MAILBOX_NONEXISTENT;

    while ((parentlen==0) && (p = strrchr(parent, '.')) && !strchr(p, '!')) {
	*p = '\0';

	mboxlist_entry_free(&mbentry);
	r = mboxlist_lookup(parent, &mbentry, NULL);
	if (r != IMAP_MAILBOX_NONEXISTENT)
	    break;
    }

    free(parent);

    if (r)
	mboxlist_entry_free(&mbentry);
    else
	*mbentryp = mbentry;

    return r;
}

static int mboxlist_create_partition(const char *mboxname,
				     const char *part,
				     char **out)
{
    mbentry_t *parent = NULL;

    if (!part) {
	int r = mboxlist_findparent(mboxname, &parent);
	if (!r) part = parent->partition;
    }

    /* use defaultpartition if specified */
    if (!part && config_defpartition)
	part = config_defpartition;

    /* look for most fitting partition */
    if (!part)
	part = partlist_local_select();

    /* Configuration error */
    if (!part || (strlen(part) > MAX_PARTITION_LEN))
	goto err;

    if (!config_partitiondir(part))
	goto err;

    *out = xstrdupnull(part);

    mboxlist_entry_free(&parent);
    return 0;

err:
    mboxlist_entry_free(&parent);
    return IMAP_PARTITION_UNKNOWN;
}

/*
 * Check if a mailbox can be created.  There is no other setup at this
 * stage, just the check!
 */
static int mboxlist_create_namecheck(const char *mboxname,
				     const char *userid,
				     struct auth_state *auth_state,
				     int isadmin, int force_subdirs)
{
    mbentry_t *mbentry = NULL;
    const char *p;
    int r = 0;

    /* policy first */
    r = mboxname_policycheck(mboxname);
    if (r) goto done;

    /* is this the user's INBOX namespace? */
    if (!isadmin && mboxname_userownsmailbox(userid, mboxname)) {
	/* User has admin rights over their own mailbox namespace */
	if (config_implicitrights & ACL_ADMIN)
	    isadmin = 1;
    }

    /* Check to see if mailbox already exists */
    r = mboxlist_lookup(mboxname, &mbentry, NULL);
    if (r != IMAP_MAILBOX_NONEXISTENT) {
	if (!r) {
	    r = IMAP_MAILBOX_EXISTS;

	    /* Lie about error if privacy demands */
	    if (!isadmin &&
		!(cyrus_acl_myrights(auth_state, mbentry->acl) & ACL_LOOKUP)) {
		r = IMAP_PERMISSION_DENIED;
	    }
	}

	goto done;
    }
    mboxlist_entry_free(&mbentry);

    /* look for a parent mailbox */
    r = mboxlist_findparent(mboxname, &mbentry);
    if (r == 0) {
	/* found a parent */
	char root[MAX_MAILBOX_NAME+1];

	/* check acl */
	if (!isadmin &&
	    !(cyrus_acl_myrights(auth_state, mbentry->acl) & ACL_CREATE)) {
	    r = IMAP_PERMISSION_DENIED;
	    goto done;
	}

	/* check quota */
	if (quota_findroot(root, sizeof(root), mboxname)) {
	    quota_t qdiffs[QUOTA_NUMRESOURCES] = QUOTA_DIFFS_DONTCARE_INITIALIZER;
	    qdiffs[QUOTA_NUMFOLDERS] = 1;
	    r = quota_check_useds(root, qdiffs);
	    if (r) goto done;
	}
    }
    else if (r == IMAP_MAILBOX_NONEXISTENT) {
	/* no parent mailbox */
	if (!isadmin) {
	    r = IMAP_PERMISSION_DENIED;
	    goto done;
	}

	p = mboxname_isusermailbox(mboxname, 0);
	if (p) {
	    char *firstdot = strchr(p, '.');
	    if (!force_subdirs && firstdot) {
		/* Disallow creating user.X.* when no user.X */
		r = IMAP_PERMISSION_DENIED;
		goto done;
	    }
	}

	/* otherwise no parent is OK */
	r = 0;
    }

done:
    mboxlist_entry_free(&mbentry);

    return r;
}

static int mboxlist_create_acl(const char *mboxname, char **out)
{
    mbentry_t *mbentry = NULL;
    const char *owner;
    int r;
    int mask;

    char *defaultacl;
    char *identifier;
    char *rights;
    char *p;

    r = mboxlist_findparent(mboxname, &mbentry);
    if (!r) {
	*out = xstrdup(mbentry->acl);
	mboxlist_entry_free(&mbentry);
	return 0;
    }

    *out = xstrdup("");
    owner = mboxname_to_userid(mboxname);
    if (owner) {
	/* owner gets full permission on own mailbox by default */
	if (config_getswitch(IMAPOPT_UNIXHIERARCHYSEP)) {
	    /*
	     * The mailboxname is now in the internal format,
	     * so we we need to change DOTCHARs back to '.'
	     * in the identifier in order to have the correct ACL.
	     */
	    for (p = (char *)owner; *p; p++) {
		if (*p == DOTCHAR) *p = '.';
	    }
	}
	cyrus_acl_set(out, owner, ACL_MODE_SET, ACL_ALL,
		      (cyrus_acl_canonproc_t *)0, (void *)0);
	return 0;
    }

    defaultacl = identifier = xstrdup(config_getstring(IMAPOPT_DEFAULTACL));
    for (;;) {
	while (*identifier && Uisspace(*identifier)) identifier++;
	rights = identifier;
	while (*rights && !Uisspace(*rights)) rights++;
	if (!*rights) break;
	*rights++ = '\0';
	while (*rights && Uisspace(*rights)) rights++;
	if (!*rights) break;
	p = rights;
	while (*p && !Uisspace(*p)) p++;
	if (*p) *p++ = '\0';
	cyrus_acl_strtomask(rights, &mask);
	/* XXX and if strtomask fails? */
	cyrus_acl_set(out, identifier, ACL_MODE_SET, mask,
		      (cyrus_acl_canonproc_t *)0, (void *)0);
	identifier = p;
    }
    free(defaultacl);

    return 0;
}

/* and this API just plain sucks */
EXPORTED int mboxlist_createmailboxcheck(const char *name, int mbtype __attribute__((unused)),
				const char *partition, 
				int isadmin, const char *userid, 
				struct auth_state *auth_state, 
				char **newacl, char **newpartition,
				int forceuser)
{
    char *part = NULL;
    char *acl = NULL;
    int r = 0;

    r = mboxlist_create_namecheck(name, userid, auth_state,
				  isadmin, forceuser);
    if (r) goto done;

    if (newacl) {
	r = mboxlist_create_acl(name, &acl);
	if (r) goto done;
    }

    if (newpartition) {
	r = mboxlist_create_partition(name, partition, &part);
	if (r) goto done;
    }

    r = 0;

 done:
    if (r || !newacl) free(acl);
    else *newacl = acl;

    if (r || !newpartition) free(part);
    else *newpartition = part;

    return r;
}

/*
 * Create a mailbox
 *
 * 1. verify ACL's to best of ability (CRASH: abort)
 * 2. verify parent ACL's if need to
 * 3. create the local mailbox locally (exclusive lock) and keep it locked
 * 4. open mupdate connection if necessary
 * 5. create mupdate entry (CRASH: mupdate inconsistant)
 *
 */

static int mboxlist_createmailbox_full(const char *mboxname, int mbtype,
				const char *partition,
				int isadmin, const char *userid,
				struct auth_state *auth_state,
				int options, unsigned uidvalidity,
				const char *copyacl, const char *uniqueid,
				int localonly, int forceuser, int dbonly,
				struct mailbox **mboxptr)
{
    int r;
    char *newpartition = NULL;
    char *mboxent = NULL;
    char *acl = NULL;
    struct mailbox *newmailbox = NULL;
    int isremote = mbtype & MBTYPE_REMOTE;
    mbentry_t *newmbentry = NULL;
    mbentry_t *mbentry = NULL;

    r = mboxlist_create_namecheck(mboxname, userid, auth_state,
				  isadmin, forceuser);
    if (r) goto done;

    /* check if a previous deleted mailbox existed */
    r = mboxlist_mylookup(mboxname, &mbentry, NULL, 0);
    if (!r && mbentry->mbtype == MBTYPE_DELETED) {
	/* changing the unique id since last time? */
	if (strcmpsafe(uniqueid, mbentry->uniqueid)) {
	    /* then the UIDVALIDITY must be higher than before */
	    if (uidvalidity <= mbentry->uidvalidity)
		uidvalidity = mbentry->uidvalidity+1;
	}
    }

    if (copyacl) {
	acl = xstrdup(copyacl);
    }
    else {
	r = mboxlist_create_acl(mboxname, &acl);
	if (r) goto done;
    }

    r = mboxlist_create_partition(mboxname, partition, &newpartition);
    if (r) goto done;

    if (!dbonly && !isremote) {

	/* Filesystem Operations */
	r = mailbox_create(mboxname, mbtype, newpartition, acl, uniqueid,
			   options, uidvalidity, &newmailbox);
	if (r) goto done; /* CREATE failed */ 
    }

    /* all is well - activate the mailbox */
    newmbentry = mboxlist_entry_create();
    newmbentry->acl = xstrdupnull(acl);
    newmbentry->mbtype = mbtype;
    newmbentry->partition = xstrdupnull(newpartition);
    if (newmailbox) {
	newmbentry->uniqueid = xstrdupnull(newmailbox->uniqueid);
	newmbentry->uidvalidity = newmailbox->i.uidvalidity;
    }
    mboxent = mboxlist_entry_cstring(newmbentry);
    r = cyrusdb_store(mbdb, mboxname, strlen(mboxname),
		      mboxent, strlen(mboxent), NULL);

    if (r) {
	syslog(LOG_ERR, "DBERROR: failed to insert to mailboxes list %s: %s", 
	       mboxname, cyrusdb_strerror(r));
	r = IMAP_IOERROR;
    }

    /* 9. set MUPDATE entry as commited (CRASH: commited) */
    if (!r && config_mupdate_server && !localonly) {
	mupdate_handle *mupdate_h = NULL;
	char *loc = strconcat(config_servername, "!", newpartition, (char *)NULL);

	r = mupdate_connect(config_mupdate_server, NULL, &mupdate_h, NULL);
	if (!r) r = mupdate_reserve(mupdate_h, mboxname, loc);
	if (!r) r = mupdate_activate(mupdate_h, mboxname, loc, acl);
	if (r) {
	    syslog(LOG_ERR, "MUPDATE: can't commit mailbox entry for '%s'",
		   mboxname);
	    cyrusdb_delete(mbdb, mboxname, strlen(mboxname), NULL, 0);
	}
	if (mupdate_h) mupdate_disconnect(&mupdate_h);
	free(loc);
    }

done:
    if (newmailbox) {
	if (r) mailbox_delete(&newmailbox);
	else if (mboxptr) *mboxptr = newmailbox;
	else mailbox_close(&newmailbox);
    }

    free(acl);
    free(newpartition);
    free(mboxent);
    mboxlist_entry_free(&mbentry);
    mboxlist_entry_free(&newmbentry);

    return r;
}

EXPORTED int mboxlist_createmailbox(const char *name, int mbtype,
			   const char *partition, 
			   int isadmin, const char *userid, 
			   struct auth_state *auth_state,
			   int localonly, int forceuser, int dbonly,
			   int notify, struct mailbox **mailboxptr)
{
    int options = config_getint(IMAPOPT_MAILBOX_DEFAULT_OPTIONS)
		  | OPT_POP3_NEW_UIDL;
    int r;
    struct mailbox *mailbox = NULL;

    r = mboxlist_createmailbox_full(name, mbtype, partition,
				    isadmin, userid, auth_state,
				    options, 0, NULL, NULL, localonly,
				    forceuser, dbonly, &mailbox);

    if (notify && !r) {
	/* send a MailboxCreate event notification */
	struct mboxevent *mboxevent = mboxevent_new(EVENT_MAILBOX_CREATE);
	mboxevent_extract_mailbox(mboxevent, mailbox);
	mboxevent_set_access(mboxevent, NULL, NULL, userid, mailbox->name, 1);

	mboxevent_notify(mboxevent);
	mboxevent_free(&mboxevent);
    }

    if (mailboxptr && !r) *mailboxptr = mailbox;
    else mailbox_close(&mailbox);

    return r;
}

EXPORTED int mboxlist_createsync(const char *name, int mbtype,
			const char *partition,
			const char *userid, struct auth_state *auth_state,
			int options, unsigned uidvalidity,
			const char *acl, const char *uniqueid,
			struct mailbox **mboxptr)
{
    return mboxlist_createmailbox_full(name, mbtype, partition,
				       1, userid, auth_state,
				       options, uidvalidity, acl, uniqueid,
				       0, 1, 0, mboxptr);
}

/* insert an entry for the proxy */
EXPORTED int mboxlist_insertremote(mbentry_t *mbentry,
			  struct txn **tid)
{
    char *mboxent;
    int r = 0;

    if (mbentry->server) {
	/* remote mailbox */
	if (config_mupdate_config == IMAP_ENUM_MUPDATE_CONFIG_UNIFIED &&
	    !strcasecmp(mbentry->server, config_servername)) {
	    /* its on our server, make it a local mailbox */
	    mbentry->mbtype &= ~MBTYPE_REMOTE;
	    mbentry->server = NULL;
	}
	else {
	    /* make sure it's a remote mailbox */
	    mbentry->mbtype |= MBTYPE_REMOTE;
	}
    }

    mboxent = mboxlist_entry_cstring(mbentry);

    /* database put */
    r = cyrusdb_store(mbdb, mbentry->name, strlen(mbentry->name),
		      mboxent, strlen(mboxent), tid);
    switch (r) {
    case CYRUSDB_OK:
	break;
    case CYRUSDB_AGAIN:
	abort(); /* shouldn't happen ! */
	break;
    default:
	syslog(LOG_ERR, "DBERROR: error updating database %s: %s",
	       mbentry->name, cyrusdb_strerror(r));
	r = IMAP_IOERROR;
	break;
    }

    free(mboxent);

    return r;
}

/* Special function to delete a remote mailbox.
 * Only affects mboxlist.
 * Assumes admin powers. */
EXPORTED int mboxlist_deleteremote(const char *name, struct txn **in_tid)
{
    int r;
    struct txn **tid;
    struct txn *lcl_tid = NULL;
    mbentry_t *mbentry = NULL;

    if(in_tid) {
	tid = in_tid;
    } else {
	tid = &lcl_tid;
    }

 retry:
    r = mboxlist_mylookup(name, &mbentry, tid, 1);
    switch (r) {
    case 0:
	break;

    case IMAP_AGAIN:
	goto retry;
	break;

    default:
	goto done;
    }

    if ((mbentry->mbtype & MBTYPE_REMOTE) && !mbentry->server) {
	syslog(LOG_ERR,
	       "mboxlist_deleteremote called on non-remote mailbox: %s",
	       name);
	goto done;
    }

 retry_del:
    /* delete entry */
    r = cyrusdb_delete(mbdb, name, strlen(name), tid, 0);
    switch (r) {
    case CYRUSDB_OK: /* success */
	break;
    case CYRUSDB_AGAIN:
	goto retry_del;
    default:
	syslog(LOG_ERR, "DBERROR: error deleting %s: %s",
	       name, cyrusdb_strerror(r));
	r = IMAP_IOERROR;
    }

    /* commit db operations, but only if we weren't passed a transaction */
    if (!in_tid) {
	r = cyrusdb_commit(mbdb, *tid);
	if (r) {
	    syslog(LOG_ERR, "DBERROR: failed on commit: %s",
		   cyrusdb_strerror(r));
	    r = IMAP_IOERROR;
	}
	tid = NULL;
    }

 done:
    if (r && !in_tid && tid) {
	/* Abort the transaction if it is still in progress */
	cyrusdb_abort(mbdb, *tid);
    }

    return r;
}

/*
 * Delayed Delete a mailbox: translate delete into rename
 */
EXPORTED int
mboxlist_delayed_deletemailbox(const char *name, int isadmin,
			       const char *userid,
			       struct auth_state *auth_state,
			       struct mboxevent *mboxevent,
			       int checkacl,
			       int localonly,
			       int force)
{
    mbentry_t *mbentry = NULL;
    char newname[MAX_MAILBOX_BUFFER];
    int r;
    long myrights;
    char *p;

    if (!isadmin && force) return IMAP_PERMISSION_DENIED;

    /* Check for request to delete a user:
       user.<x> with no dots after it */
    if ((p = mboxname_isusermailbox(name, 1))) {
	/* Can't DELETE INBOX (your own inbox) */
	if (userid) {
	    size_t len = config_virtdomains ?
                strcspn(userid, "@") : strlen(userid);
	    if ((len == strlen(p)) && !strncmp(p, userid, len)) {
		return(IMAP_MAILBOX_NOTSUPPORTED);
	    }
	}

	/* Only admins may delete user */
	if (!isadmin) return(IMAP_PERMISSION_DENIED);
    }

    r = mboxlist_lookup(name, &mbentry, NULL);
    if (r) return r;

    /* check if user has Delete right (we've already excluded non-admins
     * from deleting a user mailbox) */
    if (checkacl) {
	myrights = cyrus_acl_myrights(auth_state, mbentry->acl);
	if (!(myrights & ACL_DELETEMBOX)) {
	    /* User has admin rights over their own mailbox namespace */
	    if (mboxname_userownsmailbox(userid, name) &&
		(config_implicitrights & ACL_ADMIN)) {
		isadmin = 1;
	    }

	    /* Lie about error if privacy demands */
	    r = (isadmin || (myrights & ACL_LOOKUP)) ?
		IMAP_PERMISSION_DENIED : IMAP_MAILBOX_NONEXISTENT;

	    mboxlist_entry_free(&mbentry);

	    return r;
	}
    }

    /* get the deleted name */
    mboxname_todeleted(name, newname, 1);

    /* Get mboxlist_renamemailbox to do the hard work. No ACL checks needed */
    r = mboxlist_renamemailbox((char *)name, newname, mbentry->partition,
			       0 /* uidvalidity */,
                               1 /* isadmin */, userid,
                               auth_state,
			       mboxevent,
			       localonly /* local_only */,
                               force, 1);

    mboxlist_entry_free(&mbentry);

    return r;
}

/*
 * Delete a mailbox.
 * Deleting the mailbox user.FOO may only be performed by an admin.
 *
 * 1. Begin transaction
 * 2. Verify ACL's
 * 3. remove from database
 * 4. remove from disk
 * 5. commit transaction
 * 6. Open mupdate connection if necessary
 * 7. delete from mupdate
 *
 */
EXPORTED int mboxlist_deletemailbox(const char *name, int isadmin,
				    const char *userid,
				    struct auth_state *auth_state,
				    struct mboxevent *mboxevent,
				    int checkacl,
				    int local_only, int force)
{
    mbentry_t *mbentry = NULL;
    int r;
    long myrights;
    struct mailbox *mailbox = NULL;
    int isremote = 0;
    const char *p;
    mupdate_handle *mupdate_h = NULL;

    if (!isadmin && force) return IMAP_PERMISSION_DENIED;

    /* Check for request to delete a user:
       user.<x> with no dots after it */
    if ((p = mboxname_isusermailbox(name, 1))) {
	/* Can't DELETE INBOX (your own inbox) */
	if (userid) {
	    size_t len = config_virtdomains ? strcspn(userid, "@") : strlen(userid);
	    if ((len == strlen(p)) && !strncmp(p, userid, len)) {
		r = IMAP_MAILBOX_NOTSUPPORTED;
		goto done;
	    }
	}

	/* Only admins may delete user */
	if (!isadmin) { r = IMAP_PERMISSION_DENIED; goto done; }
    }

    r = mboxlist_lookup_allow_all(name, &mbentry, NULL);
    if (r) goto done;

    isremote = mbentry->mbtype & MBTYPE_REMOTE;

    /* check if user has Delete right (we've already excluded non-admins
     * from deleting a user mailbox) */
    if (checkacl) {
	myrights = cyrus_acl_myrights(auth_state, mbentry->acl);
	if(!(myrights & ACL_DELETEMBOX)) {
	    /* User has admin rights over their own mailbox namespace */
	    if (mboxname_userownsmailbox(userid, name) &&
		(config_implicitrights & ACL_ADMIN)) {
		isadmin = 1;
	    }

	    /* Lie about error if privacy demands */
	    r = (isadmin || (myrights & ACL_LOOKUP)) ?
		IMAP_PERMISSION_DENIED : IMAP_MAILBOX_NONEXISTENT;
	    goto done;
	}
    }

    /* Lock the mailbox if it isn't a remote mailbox */
    if (!isremote) {
	r = mailbox_open_iwl(name, &mailbox);
    }
    if (r && !force) goto done;

    /* remove from mupdate */
    if (!isremote && !local_only && config_mupdate_server) {
	/* delete the mailbox in MUPDATE */
	r = mupdate_connect(config_mupdate_server, NULL, &mupdate_h, NULL);
	if (r) {
	    syslog(LOG_ERR,
		   "cannot connect to mupdate server for delete of '%s'",
		   name);
	    goto done;
	}
	r = mupdate_delete(mupdate_h, name);
	if(r) {
	    syslog(LOG_ERR,
		   "MUPDATE: can't delete mailbox entry '%s'", name);
	}
	if (mupdate_h) mupdate_disconnect(&mupdate_h);
    }
    if (r && !force) goto done;

    if (!isremote && !mboxname_isdeletedmailbox(name, NULL)) {
	/* store a DELETED marker */
	mbentry_t *newmbentry = mboxlist_entry_create();
	newmbentry->name = xstrdupnull(name);
	newmbentry->mbtype = MBTYPE_DELETED;
	if (mailbox) {
	    newmbentry->uidvalidity = mailbox->i.uidvalidity;
	    newmbentry->uniqueid = xstrdupnull(mailbox->uniqueid);
	}
	r = mboxlist_update(newmbentry, /*localonly*/1);
	mboxlist_entry_free(&newmbentry);
    }
    else {
	/* delete entry (including DELETED.* mailboxes, no need
	 * to keep that rubbish around) */
	r = cyrusdb_delete(mbdb, name, strlen(name), NULL, 0);
	if (r) {
	    syslog(LOG_ERR, "DBERROR: error deleting %s: %s",
		   name, cyrusdb_strerror(r));
	    r = IMAP_IOERROR;
	    if (!force) goto done;
	}
	if (r && !force) goto done;
    }

    /* delete underlying mailbox */
    if (!isremote && mailbox) {
	/* only on a real delete do we delete from the remote end as well */
	sync_log_unmailbox(mailbox->name);
	mboxevent_extract_mailbox(mboxevent, mailbox);
	mboxevent_set_access(mboxevent, NULL, NULL, userid, mailbox->name, 1);

	r = mailbox_delete(&mailbox);
	/* abort event notification */
	if (r && mboxevent)
	    mboxevent_free(&mboxevent);
    }

 done:
    mailbox_close(&mailbox);
    mboxlist_entry_free(&mbentry);

    return r;
}

/*
 * Rename/move a single mailbox (recursive renames are handled at a
 * higher level).  This only supports local mailboxes.  Remote
 * mailboxes are handled up in imapd.c
 */
EXPORTED int mboxlist_renamemailbox(const char *oldname, const char *newname,
			   const char *partition, unsigned uidvalidity,
			   int isadmin, const char *userid,
			   struct auth_state *auth_state,
			   struct mboxevent *mboxevent,
			   int local_only, int forceuser, int ignorequota)
{
    int r;
    int mupdatecommiterror = 0;
    long myrights;
    int isusermbox = 0; /* Are we renaming someone's inbox */
    int partitionmove = 0;
    struct mailbox *oldmailbox = NULL;
    struct mailbox *newmailbox = NULL;
    struct txn *tid = NULL;
    const char *root = NULL;
    char *newpartition = NULL;
    char *mboxent = NULL;
    mupdate_handle *mupdate_h = NULL;
    mbentry_t *newmbentry = NULL;

    /* 1. open mailbox */
    r = mailbox_open_iwl(oldname, &oldmailbox);
    if (r) return r;

    myrights = cyrus_acl_myrights(auth_state, oldmailbox->acl);

    /* check the ACLs up-front */
    if (!isadmin) {
	if (!(myrights & ACL_DELETEMBOX)) {
	    r = (myrights & ACL_LOOKUP) ?
		IMAP_PERMISSION_DENIED : IMAP_MAILBOX_NONEXISTENT;
	    goto done;
	}
    }

    /* 2. verify valid move */
    /* XXX - handle remote mailbox */

    /* special case: same mailbox, must be a partition move */
    if (!strcmp(oldname, newname)) {
	char *oldpath = mailbox_datapath(oldmailbox);

	/* Only admin can move mailboxes between partitions */
	if (!isadmin) {
	    r = IMAP_PERMISSION_DENIED;
	    goto done;
	}

	/* No partition, we're definitely not moving anywhere */
	if (!partition) {
	    r = IMAP_MAILBOX_EXISTS;
	    goto done;
	}

	/* let mupdate code below know it was a partition move */
	partitionmove = 1;

	/* this is OK because it uses a different static buffer */
	root = config_partitiondir(partition);
	if (!root) {
	    r = IMAP_PARTITION_UNKNOWN;
	    goto done;
	}
	if (!strncmp(root, oldpath, strlen(root)) &&
	    oldpath[strlen(root)] == '/') {
	    /* partitions are the same or share common prefix */
	    r = IMAP_MAILBOX_EXISTS;
	    goto done;
	}

	/* NOTE: this is a rename to the same mailbox name on a
	 * different partition.  This is a pretty filthy hack,
	 * which should be handled by having four totally different
	 * codepaths: INBOX -> INBOX.foo, user rename, regular rename
	 * and of course this one, partition move */
	newpartition = xstrdup(partition);
	r = mailbox_copy_files(oldmailbox, newpartition, newname);
	if (r) goto done;
	newmbentry = mboxlist_entry_create();
	newmbentry->mbtype = oldmailbox->mbtype;
	newmbentry->partition = xstrdupnull(newpartition);
	newmbentry->acl = xstrdupnull(oldmailbox->acl);
	newmbentry->uidvalidity = oldmailbox->i.uidvalidity;
	mboxent = mboxlist_entry_cstring(newmbentry);
	r = cyrusdb_store(mbdb, newname, strlen(newname), 
		          mboxent, strlen(mboxent), &tid);
	if (r) goto done;

	/* skip ahead to the commit */
	goto dbdone;
    }

    /* RENAME of some user's INBOX */
    if (mboxname_isusermailbox(oldname, 1)) {
	if (mboxname_isdeletedmailbox(newname, NULL)) {
	    /* delete user is OK */
	}
	else if (mboxname_isusermailbox(newname, 1)) {
	    /* user rename is depends on config */
	    if (!config_getswitch(IMAPOPT_ALLOWUSERMOVES)) {
		r = IMAP_MAILBOX_NOTSUPPORTED;
		goto done;
	    }
	}
	else if (mboxname_userownsmailbox(userid, oldname) &&
		 mboxname_userownsmailbox(userid, newname)) {
	    /* Special case of renaming inbox */
	    isusermbox = 1;
	}
	else {
	    /* Everything else is bogus */
	    r = IMAP_MAILBOX_NOTSUPPORTED;
	    goto done;
	}
    }

    r = mboxlist_create_namecheck(newname, userid, auth_state,
				  isadmin, forceuser);
    if (r) goto done;

    r = mboxlist_create_partition(newname, partition, &newpartition);
    if (r) goto done;

    if (!newpartition) newpartition = xstrdup(config_defpartition);

    /* Rename the actual mailbox */
    r = mailbox_rename_copy(oldmailbox, newname, newpartition, uidvalidity,
			    isusermbox ? userid : NULL, ignorequota,
			    &newmailbox);
    if (r) goto done;

    syslog(LOG_INFO, "Rename: %s -> %s", oldname, newname);

    /* create new entry */
    newmbentry = mboxlist_entry_create();
    newmbentry->name = xstrdupnull(newmailbox->name);
    newmbentry->mbtype = newmailbox->mbtype;
    newmbentry->partition = xstrdupnull(newmailbox->part);
    newmbentry->acl = xstrdupnull(newmailbox->acl);
    newmbentry->uidvalidity = newmailbox->i.uidvalidity;
    newmbentry->uniqueid = xstrdupnull(newmailbox->uniqueid);
    mboxent = mboxlist_entry_cstring(newmbentry);

    do {
	r = 0;

	/* delete the old entry */
	if (!isusermbox) {
	    /* store a DELETED marker */
	    char *oldmboxent = NULL;
	    mbentry_t *oldmbentry = mboxlist_entry_create();
	    oldmbentry->name = xstrdupnull(oldmailbox->name);
	    oldmbentry->mbtype = MBTYPE_DELETED;
	    oldmbentry->uidvalidity = oldmailbox->i.uidvalidity;
	    oldmbentry->uniqueid = xstrdupnull(oldmailbox->uniqueid);
	    oldmboxent = mboxlist_entry_cstring(oldmbentry);

	    r = cyrusdb_store(mbdb, oldname, strlen(oldname),
			      oldmboxent, strlen(oldmboxent), &tid);

	    mboxlist_entry_free(&oldmbentry);
	    free(oldmboxent);
	}

	/* create a new entry */
	if (!r)
	    r = cyrusdb_store(mbdb, newname, strlen(newname),
			      mboxent, strlen(mboxent), &tid);

	switch (r) {
	case 0: /* success */
	    break;
	case CYRUSDB_AGAIN:
	    tid = NULL;
	    break;
	default:
	    syslog(LOG_ERR, "DBERROR: rename failed on store %s %s: %s",
		   oldname, newname, cyrusdb_strerror(r));
	    r = IMAP_IOERROR;
	    goto done;
	    break;
	}
    } while (r == CYRUSDB_AGAIN);

 dbdone:

    /* 3. Commit transaction */
    r = cyrusdb_commit(mbdb, tid);
    tid = NULL;
    if (r) {
	syslog(LOG_ERR, "DBERROR: rename failed on commit %s %s: %s",
	       oldname, newname, cyrusdb_strerror(r));
	r = IMAP_IOERROR;
	goto done;
    }

    if (!local_only && config_mupdate_server) {
	/* commit the mailbox in MUPDATE */
	char *loc = strconcat(config_servername, "!", newpartition, (char *)NULL);

	r = mupdate_connect(config_mupdate_server, NULL, &mupdate_h, NULL);
	if (!partitionmove) {
	    if (!r && !isusermbox)
		r = mupdate_delete(mupdate_h, oldname);
	    if (!r) r = mupdate_reserve(mupdate_h, newname, loc);
	}
	if (!r) r = mupdate_activate(mupdate_h, newname, loc, newmbentry->acl);
	if (r) {
	    syslog(LOG_ERR,
		   "MUPDATE: can't commit mailbox entry for '%s'",
		   newname);
            mupdatecommiterror = r;
	}
	if (mupdate_h) mupdate_disconnect(&mupdate_h);
	free(loc);
    }

 done: /* Commit or cleanup */
    if (!r && newmailbox)
	r = mailbox_commit(newmailbox);

    if (r) {
	/* rollback DB changes if it was an mupdate failure */
        if (mupdatecommiterror) {
            r = 0;

            /* delete the new entry */
            if (!isusermbox)
                r = cyrusdb_delete(mbdb, newname, strlen(newname), &tid, 0);

            /* recreate an old entry */
            if (!r)
                r = cyrusdb_store(mbdb, oldname, strlen(oldname),
				  mboxent, strlen(mboxent), &tid);

            /* Commit transaction */
            if (!r)
                r = cyrusdb_commit(mbdb, tid);

            tid = NULL;
            if (r) {
                /* XXX HOWTO repair this mess! */
                syslog(LOG_ERR, "DBERROR: failed DB rollback on mailboxrename %s %s: %s",
                       oldname, newname, cyrusdb_strerror(r));
                syslog(LOG_ERR, "DBERROR: mailboxdb on mupdate and backend ARE NOT CONSISTENT");
                syslog(LOG_ERR, "DBERROR: mailboxdb on mupdate has entry for %s, mailboxdb on backend has entry for %s and files are on the old position", oldname, newname);
                r = IMAP_IOERROR;
            } else {
                r = mupdatecommiterror;
            }

        }

	if (newmailbox) mailbox_delete(&newmailbox);
	if (partitionmove && newpartition)
	    mailbox_delete_cleanup(newpartition, newname);
	mailbox_close(&oldmailbox);
    } else {
	if (newmailbox) {
	    /* prepare the event notification */
	    if (mboxevent) {

		/* case of delayed delete */
		if (mboxevent->type == EVENT_MAILBOX_DELETE)
		    mboxevent_extract_mailbox(mboxevent, oldmailbox);
		else {
		    mboxevent_extract_mailbox(mboxevent, newmailbox);
		    mboxevent_extract_old_mailbox(mboxevent, oldmailbox);
		}

		mboxevent_set_access(mboxevent, NULL, NULL, userid, newmailbox->name, 1);
	    }

	    mailbox_rename_cleanup(&oldmailbox, isusermbox);
	    mailbox_close(&newmailbox);
	}
	else if (partitionmove) {
	    char *oldpartition = xstrdup(oldmailbox->part);
	    if (config_auditlog)
		syslog(LOG_NOTICE, "auditlog: partitionmove sessionid=<%s> "
		       "mailbox=<%s> uniqueid=<%s> oldpart=<%s> newpart=<%s>",
		       session_id(),
		       oldmailbox->name, oldmailbox->uniqueid,
		       oldpartition, partition);
	    mailbox_close(&oldmailbox);
	    mailbox_delete_cleanup(oldpartition, oldname);
	    free(oldpartition);

	}
	else
	    abort(); /* impossible, in theory */

	/* log the rename */
	sync_log_mailbox_double(oldname, newname);
    }

    /* free memory */
    free(newpartition);
    free(mboxent);
    mboxlist_entry_free(&newmbentry);

    return r;
}

/*
 * Verify if the 'user' is the mailbox 'name' owner.
 */
static int mboxlist_is_owner(struct namespace *namespace,
			     const char *name, int domainlen,
			     const char *user, int userlen)
{
    struct buf extname = BUF_INITIALIZER;
    const char *username = NULL;
    const char *dot_position = NULL;

    /* is_user_mbox */
    if (strncmp(name+domainlen, "user.", 5))
	return 0;

    /* get external representation of owner to check against given user */
    username = name + domainlen + 5;
    dot_position = strchr(username, '.');
    buf_setmap(&extname, username, dot_position ?
	dot_position - username : (int)strlen(username));
    mboxname_hiersep_toexternal(namespace,
	(char *)buf_cstring(&extname), buf_len(&extname));

    /* starts_with_user */
    if (strncmp(buf_cstring(&extname), user, userlen)) {
	buf_free(&extname);
	return 0;
    }
    buf_free(&extname);

    /* is_exactly_user */
    if (!(username[userlen] == '\0' || username[userlen] == '.'))
	return 0;

    return 1;
}

/*
 * Check if the admin rights are present in the 'rights'
 */
static int mboxlist_have_admin_rights(const char* rights) {
    int access, have_admin_access;

    cyrus_acl_strtomask(rights, &access);
    have_admin_access = access & ACL_ADMIN;

    return have_admin_access;
}

/*
 * Change the ACL for mailbox 'name' so that 'identifier' has the
 * rights enumerated in the string 'rights'.  If 'rights' is the null
 * pointer, removes the ACL entry for 'identifier'.   'isadmin' is
 * nonzero if user is a mailbox admin.  'userid' is the user's login id.
 *
 * 1. Start transaction
 * 2. Check rights
 * 3. Set db entry
 * 4. Change backup copy (cyrus.header)
 * 5. Commit transaction
 * 6. Change mupdate entry 
 *
 */
EXPORTED int mboxlist_setacl(struct namespace *namespace, const char *name,
		    const char *identifier, const char *rights,
		    int isadmin, const char *userid, 
		    struct auth_state *auth_state)
{
    mbentry_t *mbentry = NULL;
    int useridlen = strlen(userid);
    int domainlen = 0;
    int identifierlen = strlen(identifier);
    char *cp, ident[256];
    const char *domain = NULL;
    int r;
    int myrights;
    int mode = ACL_MODE_SET;
    int isusermbox = 0;
    int isidentifiermbox = 0;
    int anyoneuseracl = 1;
    int ensure_owner_rights = 0;
    int mask;
    const char *mailbox_owner = NULL;
    struct mailbox *mailbox = NULL;
    char *newacl = NULL;
    char *mboxent = NULL;
    struct txn *tid = NULL;

    if (config_virtdomains) {
	if ((cp = strchr(userid, '@'))) {
	    useridlen = cp - userid;
	}
	if ((cp = strchr(name, '!'))) {
	    domain = name;
	    domainlen = cp - name + 1;
	}

	/* canonify identifier so it is fully qualified,
	   except for "anonymous", "anyone", the global admin
	   and users in the default domain */
	if ((cp = strchr(identifier, '@'))) {
	    identifierlen = cp - identifier;
	    if (rights &&
		((domain && strncasecmp(cp+1, domain, strlen(cp+1))) ||
		 (!domain && (!config_defdomain ||
			      strcasecmp(config_defdomain, cp+1))))) {
		/* can't set cross-domain ACLs */
		return IMAP_INVALID_IDENTIFIER;
	    }
	    if ((config_defdomain && !strcasecmp(config_defdomain, cp+1)) ||
		!strcmp(identifier, "anonymous") ||
		!strcmp(identifier, "anyone")) {
		snprintf(ident, sizeof(ident),
			 "%.*s", (int) (cp - identifier), identifier);
	    } else {
		strlcpy(ident, identifier, sizeof(ident));
	    }
	} else {
	    strlcpy(ident, identifier, sizeof(ident));
	    if (domain && !isadmin &&
		strcmp(ident, "anonymous") && strcmp(ident, "anyone")) {
		snprintf(ident+strlen(ident), sizeof(ident)-strlen(ident),
			 "@%.*s",
			 domainlen ? domainlen-1 : (int) strlen(domain), domain);
	    }
	}

	identifier = ident;
    }

    /* checks if the mailbox belongs to the user who is trying to change the
       access rights */
    if (mboxlist_is_owner(namespace, name, domainlen, userid, useridlen)) {
	isusermbox = 1;
    }
    anyoneuseracl = config_getswitch(IMAPOPT_ANYONEUSERACL);

    /* checks if the identifier is the mailbox owner */
    if (mboxlist_is_owner(namespace, name, domainlen,
	identifier, identifierlen))
    {
	isidentifiermbox = 1;
    }

    /* who is the mailbox owner? */
    if (isusermbox) {
	mailbox_owner = userid;
    }
    else if (isidentifiermbox) {
	mailbox_owner = identifier;
    }

    /* ensure the access rights if the folder owner is the current user or
       the identifier */
    ensure_owner_rights = isusermbox || isidentifiermbox;

    /* 1. Start Transaction */
    /* lookup the mailbox to make sure it exists and get its acl */
    do {
	r = mboxlist_mylookup(name, &mbentry, &tid, 1);
    } while(r == IMAP_AGAIN);

    /* Can't do this to an in-transit or reserved mailbox */
    if (!r && mbentry->mbtype & (MBTYPE_MOVING | MBTYPE_RESERVE | MBTYPE_DELETED)) {
	r = IMAP_MAILBOX_NOTSUPPORTED;
    }

    /* if it is not a remote mailbox, we need to unlock the mailbox list,
     * lock the mailbox, and re-lock the mailboxes list */
    /* we must do this to obey our locking rules */
    if (!r && !(mbentry->mbtype & MBTYPE_REMOTE)) {
	cyrusdb_abort(mbdb, tid);
	tid = NULL;
	mboxlist_entry_free(&mbentry);

	/* open & lock mailbox header */
        r = mailbox_open_iwl(name, &mailbox);

	if (!r) {
	    do {
		/* lookup the mailbox to make sure it exists and get its acl */
		r = mboxlist_mylookup(name, &mbentry, &tid, 1);
	    } while (r == IMAP_AGAIN);
	}

	if(r) goto done;
    }

    /* 2. Check Rights */
    if (!r && !isadmin) {
	myrights = cyrus_acl_myrights(auth_state, mbentry->acl);
	if (!(myrights & ACL_ADMIN)) {
	    r = (myrights & ACL_LOOKUP) ?
		IMAP_PERMISSION_DENIED : IMAP_MAILBOX_NONEXISTENT;
	    goto done;
	}
    }

    /* 2.1 Only admin user can set 'anyone' rights if config says so */
    if (!r && !isadmin && !anyoneuseracl && !strncmp(identifier, "anyone", 6)) {
      r = IMAP_PERMISSION_DENIED;
      goto done;
    }

    /* 3. Set DB Entry */
    if(!r) {
	/* Make change to ACL */
	newacl = xstrdup(mbentry->acl);
	if (rights && *rights) {
	    /* rights are present and non-empty */
	    mode = ACL_MODE_SET;
	    if (*rights == '+') {
		rights++;
		mode = ACL_MODE_ADD;
	    }
	    else if (*rights == '-') {
		rights++;
		mode = ACL_MODE_REMOVE;
	    }
	    /* do not allow non-admin user to remove the admin rights from mailbox owner */
	    if (!isadmin && isidentifiermbox && mode != ACL_MODE_ADD) {
		int has_admin_rights = mboxlist_have_admin_rights(rights);
		if ((has_admin_rights && mode == ACL_MODE_REMOVE) ||
		   (!has_admin_rights && mode != ACL_MODE_REMOVE)) {
		    syslog(LOG_ERR, "Denied removal of admin rights on "
			   "folder \"%s\" (owner: %s) by user \"%s\"", name,
			   mailbox_owner, userid);
		    r = IMAP_PERMISSION_DENIED;
		    goto done;
		}
	    }

	    r = cyrus_acl_strtomask(rights, &mask);

	    if (!r && cyrus_acl_set(&newacl, identifier, mode, mask,
				    ensure_owner_rights ? mboxlist_ensureOwnerRights : 0,
				    (void *)mailbox_owner)) {
		r = IMAP_INVALID_IDENTIFIER;
	    }
	} else {
	    /* do not allow to remove the admin rights from mailbox owner */
	    if (!isadmin && isidentifiermbox) {
		syslog(LOG_ERR, "Denied removal of admin rights on "
		       "folder \"%s\" (owner: %s) by user \"%s\"", name,
		       mailbox_owner, userid);
		r = IMAP_PERMISSION_DENIED;
		goto done;
	    }

	    if (cyrus_acl_remove(&newacl, identifier,
				 ensure_owner_rights ? mboxlist_ensureOwnerRights : 0,
				 (void *)mailbox_owner)) {
		r = IMAP_INVALID_IDENTIFIER;
	    }
	}
    }

    if(!r) {
	/* ok, change the database */
	free(mbentry->acl);
	mbentry->acl = xstrdupnull(newacl);
	mboxent = mboxlist_entry_cstring(mbentry);

	do {
	    r = cyrusdb_store(mbdb, name, strlen(name),
			      mboxent, strlen(mboxent), &tid);
	} while(r == CYRUSDB_AGAIN);

	if(r) {
	    syslog(LOG_ERR, "DBERROR: error updating acl %s: %s",
		   name, cyrusdb_strerror(r));
	    r = IMAP_IOERROR;
	}

	/* send a AclChange event notification */
	struct mboxevent *mboxevent = mboxevent_new(EVENT_ACL_CHANGE);
	mboxevent_extract_mailbox(mboxevent, mailbox);
	mboxevent_set_acl(mboxevent, identifier, rights);
	mboxevent_set_access(mboxevent, NULL, NULL, userid, mailbox->name, 0);

	mboxevent_notify(mboxevent);
	mboxevent_free(&mboxevent);

    }

    /* 4. Change backup copy (cyrus.header) */
    /* we already have it locked from above */
    if (!r && !(mbentry->mbtype & MBTYPE_REMOTE)) {
	mailbox_set_acl(mailbox, newacl, 1);
	/* want to commit immediately to ensure ordering */
	r = mailbox_commit(mailbox);
    }

    /* 5. Commit transaction */
    if (!r) {
	if((r = cyrusdb_commit(mbdb, tid)) != 0) {
	    syslog(LOG_ERR, "DBERROR: failed on commit: %s",
		   cyrusdb_strerror(r));
	    r = IMAP_IOERROR;
	}
	tid = NULL;
    }

    /* 6. Change mupdate entry  */
    if (!r && config_mupdate_server) {
        mupdate_handle *mupdate_h = NULL;
	/* commit the update to MUPDATE */
	char buf[MAX_PARTITION_LEN + HOSTNAME_SIZE + 2];

	snprintf(buf, sizeof(buf), "%s!%s", config_servername, mbentry->partition);

	r = mupdate_connect(config_mupdate_server, NULL, &mupdate_h, NULL);
	if(r) {
	    syslog(LOG_ERR,
		   "cannot connect to mupdate server for setacl on '%s'",
		   name);
	} else {
	    r = mupdate_activate(mupdate_h, name, buf, newacl);
	    if(r) {
		syslog(LOG_ERR,
		       "MUPDATE: can't update mailbox entry for '%s'",
		       name);
	    }
	}
	mupdate_disconnect(&mupdate_h);
    }

  done:
    if (r && tid) {
	/* if we are mid-transaction, abort it! */
	int r2 = cyrusdb_abort(mbdb, tid);
	if (r2) {
	    syslog(LOG_ERR,
		   "DBERROR: error aborting txn in mboxlist_setacl: %s",
		   cyrusdb_strerror(r2));
	}
    }
    mailbox_close(&mailbox);
    free(mboxent);
    free(newacl);
    mboxlist_entry_free(&mbentry);

    return r;
}

/*
 * Change the ACL for mailbox 'name'.  We already have it locked
 * and have written the backup copy to the header, so there's
 * nothing left but to write the mailboxes.db.
 *
 * 1. Start transaction
 * 2. Set db entry
 * 3. Commit transaction
 * 4. Change mupdate entry 
 *
 */
EXPORTED int
mboxlist_sync_setacls(const char *name, const char *newacl)
{
    mbentry_t *mbentry = NULL;
    int r;
    struct txn *tid = NULL;

    /* 1. Start Transaction */
    /* lookup the mailbox to make sure it exists and get its acl */
    do {
	r = mboxlist_mylookup(name, &mbentry, &tid, 1);
    } while(r == IMAP_AGAIN);

    /* Can't do this to an in-transit or reserved mailbox */
    if (!r && mbentry->mbtype & (MBTYPE_MOVING | MBTYPE_RESERVE | MBTYPE_DELETED)) {
	r = IMAP_MAILBOX_NOTSUPPORTED;
    }

    /* 2. Set DB Entry */
    if (!r) {
	/* ok, change the database */
	free(mbentry->acl);
	mbentry->acl = xstrdupnull(newacl);
	char *mboxent = mboxlist_entry_cstring(mbentry);

	do {
	    r = cyrusdb_store(mbdb, name, strlen(name),
			      mboxent, strlen(mboxent), &tid);
	} while (r == CYRUSDB_AGAIN);

	if (r) {
	    syslog(LOG_ERR, "DBERROR: error updating acl %s: %s",
		   name, cyrusdb_strerror(r));
	    r = IMAP_IOERROR;
	}

	free(mboxent);
    }

    /* 3. Commit transaction */
    if (!r) {
	r = cyrusdb_commit(mbdb, tid);
	if (r) {
	    syslog(LOG_ERR, "DBERROR: failed on commit %s: %s",
		   name, cyrusdb_strerror(r));
	    r = IMAP_IOERROR;
	}
	tid = NULL;
    }

    /* 4. Change mupdate entry  */
    if (!r && config_mupdate_server) {
        mupdate_handle *mupdate_h = NULL;
	/* commit the update to MUPDATE */
	char buf[MAX_PARTITION_LEN + HOSTNAME_SIZE + 2];
	sprintf(buf, "%s!%s", config_servername, mbentry->partition);

	r = mupdate_connect(config_mupdate_server, NULL, &mupdate_h, NULL);
	if (r) {
	    syslog(LOG_ERR,
		   "cannot connect to mupdate server for syncacl on '%s'",
		   name);
	} else {
	    r = mupdate_activate(mupdate_h, name, buf, newacl);
	    if(r) {
		syslog(LOG_ERR,
		       "MUPDATE: can't update mailbox entry for '%s'",
		       name);
	    }
	}
	mupdate_disconnect(&mupdate_h);
    }

    if (r && tid) {
	/* if we are mid-transaction, abort it! */
	int r2 = cyrusdb_abort(mbdb, tid);
	if (r2) {
	    syslog(LOG_ERR,
		   "DBERROR: error aborting txn in sync_setacls %s: %s",
		   name, cyrusdb_strerror(r2));
	}
    }

    mboxlist_entry_free(&mbentry);

    return r;
}

struct find_rock {
    struct glob *g;
    struct namespace *namespace;
    int find_namespace;
    int domainlen;
    int inboxoffset;
    const char *inboxcase;
    const char *usermboxname;
    size_t usermboxnamelen;
    int checkmboxlist;
    int issubs;
    int checkshared;
    struct db *db;
    int isadmin;
    struct auth_state *auth_state;
    char *prev;
    int prevlen;
    int (*proc)(char *, int, int, void *rock);
    void *procrock;
};

/* return non-zero if we like this one */
static int find_p(void *rockp,
		  const char *key, size_t keylen,
		  const char *data, size_t datalen)
{
    struct find_rock *rock = (struct find_rock *) rockp;
    long minmatch;
    struct glob *g = rock->g;
    long matchlen;
    mbentry_t *mbentry = NULL;
    int ret = 0;

    /* don't list mailboxes outside of the default domain */
    if (!rock->domainlen && !rock->isadmin && memchr(key, '!', keylen)) return 0;

    minmatch = 0;
    if (rock->inboxoffset) {
	char namebuf[MAX_MAILBOX_BUFFER];

	if (keylen >= (int) sizeof(namebuf)) {
	    syslog(LOG_ERR, "oversize keylen in mboxlist.c:find_p()");
	    return 0;
	}
	memcpy(namebuf, key, keylen);
	namebuf[keylen] = '\0';

	if (rock->inboxoffset) {
	    namebuf[rock->inboxoffset] = rock->inboxcase[0];
	    namebuf[rock->inboxoffset+1] = rock->inboxcase[1];
	    namebuf[rock->inboxoffset+2] = rock->inboxcase[2];
	    namebuf[rock->inboxoffset+3] = rock->inboxcase[3];
	    namebuf[rock->inboxoffset+4] = rock->inboxcase[4];
	}

	matchlen = glob_test(g, namebuf+rock->inboxoffset,
			     keylen-rock->inboxoffset, &minmatch);
    } else {
	matchlen = glob_test(g, key, keylen, &minmatch);
    }

    /* If its not a match, skip it -- partial matches are ok. */
    if(matchlen == -1) return 0;

    if (rock->find_namespace != NAMESPACE_INBOX &&
	rock->usermboxname &&
	keylen >= rock->usermboxnamelen &&
	(keylen == rock->usermboxnamelen || 
	 key[rock->usermboxnamelen] == '.') &&
	!strncmp(key, rock->usermboxname, rock->usermboxnamelen)) {
	/* this would've been output with the inbox stuff, so skip it */
	return 0;
    }

    if (rock->find_namespace == NAMESPACE_SHARED &&
	rock->namespace && rock->namespace->isalt &&
	!strncmp(key+rock->domainlen, "user", 4) &&
	(key[rock->domainlen+4] == '\0' || key[rock->domainlen+4] == '.')) {
	/* this would've been output with the user stuff, so skip it */
	return 0;
    }

    /* subs DB has empty keys */
    if (rock->issubs)
	return 1;

    /* ignore entirely deleted records */
    if (mboxlist_parse_entry(&mbentry, key, keylen, data, datalen))
	return 0;

    /* nobody sees tombstones */
    if (mbentry->mbtype & MBTYPE_DELETED)
	goto done;

    /* check acl */
    if (!rock->isadmin) {
	/* always suppress deleted for non-admin */
	if (mboxname_isdeletedmailbox(mbentry->name, NULL)) goto done;

	/* also suppress calendar */
	if (mboxname_iscalendarmailbox(mbentry->name, mbentry->mbtype)) goto done;

	/* and addressbook */
	if (mboxname_isaddressbookmailbox(mbentry->name, mbentry->mbtype)) goto done;

	/* check the acls */
	if (!(cyrus_acl_myrights(rock->auth_state, mbentry->acl) & ACL_LOOKUP)) goto done;
    }

    /* if we get here, close enough for us to spend the time
       acting interested */
    ret = 1;

done:
    mboxlist_entry_free(&mbentry);
    return ret;
}

static int check_name(struct find_rock *rock,
		      const char *base, int len)
{
    if (rock->prev) {
	if (cyrusdb_compar(rock->db, base, len, rock->prev, rock->prevlen) < 0)
	    return 0; /* previous name, skip it */
	free(rock->prev);
    }

    rock->prev = xstrndup(base, len);
    rock->prevlen = len;

    return 1;
}

static int find_cb(void *rockp, 
		   const char *key, size_t keylen,
		   const char *data __attribute__((unused)),
		   size_t datalen __attribute__((unused)))
{
    char namebuf[MAX_MAILBOX_BUFFER];
    struct find_rock *rock = (struct find_rock *) rockp;
    int r = 0;
    long minmatch;
    struct glob *g = rock->g;

    /* foreach match, do this test */
    minmatch = 0;
    while (minmatch >= 0) {
	long matchlen;

	if(keylen >= (int) sizeof(namebuf)) {
	    syslog(LOG_ERR, "oversize keylen in mboxlist.c:find_cb()");
	    return 0;
	}
	memcpy(namebuf, key, keylen);
	namebuf[keylen] = '\0';

	if (rock->find_namespace != NAMESPACE_INBOX &&
	    rock->usermboxname &&
	    !strncmp(namebuf, rock->usermboxname, rock->usermboxnamelen)
	    && (keylen == rock->usermboxnamelen || 
		namebuf[rock->usermboxnamelen] == '.')) {
	    /* this would've been output with the inbox stuff, so skip it */
	    return 0;
	}

	/* make sure it's in the mailboxes db */
	if (rock->checkmboxlist) {
	    r = mboxlist_lookup(namebuf, NULL, NULL);
	} else {
	    r = 0;		/* don't bother checking */
	}

	if (!r && rock->inboxoffset) {
	    namebuf[rock->inboxoffset] = rock->inboxcase[0];
	    namebuf[rock->inboxoffset+1] = rock->inboxcase[1];
	    namebuf[rock->inboxoffset+2] = rock->inboxcase[2];
	    namebuf[rock->inboxoffset+3] = rock->inboxcase[3];
	    namebuf[rock->inboxoffset+4] = rock->inboxcase[4];
	}

	matchlen = glob_test(g, namebuf+rock->inboxoffset,
			     keylen-rock->inboxoffset, &minmatch);

	if (matchlen == -1) {
	    r = 0;
	    break;
	}

	switch (r) {
	case 0:
	    /* found the entry; output it */
	    if (rock->find_namespace == NAMESPACE_SHARED &&
		rock->checkshared && rock->namespace) {
		/* special case:  LIST "" *% -- output prefix */
		r = (*rock->proc)(rock->namespace->prefix[NAMESPACE_SHARED],
				  strlen(rock->namespace->prefix[NAMESPACE_SHARED])-1,
				  1, rock->procrock);

		if (rock->checkshared > 1) {
		    /* special case:  LIST "" % -- output prefix only */
		    /* short-circuit the foreach - one mailbox is sufficient */
		    return CYRUSDB_DONE;
		}
	    }

	    rock->checkshared = 0;

	    if (check_name(rock, namebuf+rock->inboxoffset, matchlen))
		r = (*rock->proc)(namebuf+rock->inboxoffset, matchlen,
				  1, rock->procrock);

	    break;

	case IMAP_MAILBOX_NONEXISTENT:
	    /* didn't find the entry */
	    r = 0;
	    break;

	default:
	    break;
	}

	if (r) break;
    }

    return r;
}

static int skipdel_cb(void *rock __attribute__((unused)),
		      const char *key,
		      size_t keylen,
		      const char *data,
		      size_t datalen)
{
    mbentry_t *mbentry = NULL;
    int r;
    int res = 1;

    r = mboxlist_parse_entry(&mbentry, key, keylen, data, datalen);
    if (r) return 0;

    if (mbentry->mbtype & MBTYPE_DELETED)
	res = 0;

    mboxlist_entry_free(&mbentry);

    return res;
}

EXPORTED int mboxlist_allmbox(const char *prefix, foreach_cb *proc, void *rock,
			      int incdel)
{
    char *search = prefix ? (char *)prefix : "";

    return cyrusdb_foreach(mbdb, search, strlen(search),
			   incdel ? NULL : skipdel_cb,
			   proc, rock, 0);
}

struct alluser_rock {
    char *prev;
    user_cb *proc;
    void *rock;
};

static int alluser_cb(void *rock,
		      const char *key, size_t keylen,
		      const char *val __attribute__((unused)),
		      size_t vallen __attribute__((unused)))
{
    struct alluser_rock *urock = (struct alluser_rock *)rock;
    char *mboxname = xstrndup(key, keylen);
    const char *userid = mboxname_to_userid(mboxname);
    int r = 0;

    if (userid) {
	if (strcmpsafe(urock->prev, userid)) {
	    r = urock->proc(userid, urock->rock);
	    free(urock->prev);
	    urock->prev = xstrdup(userid);
	}
    }

    free(mboxname);
    return r;
}

EXPORTED int mboxlist_alluser(user_cb *proc, void *rock)
{
    struct alluser_rock urock;
    int r = 0;
    urock.prev = NULL;
    urock.proc = proc;
    urock.rock = rock;
    r = cyrusdb_foreach(mbdb, "", 0, skipdel_cb, alluser_cb, &urock, NULL);
    free(urock.prev);
    return r;
}

EXPORTED int mboxlist_allusermbox(const char *userid, foreach_cb *proc,
				  void *rock, int incdel)
{
    char *inbox = mboxname_user_mbox(userid, 0);
    if (!inbox) return CYRUSDB_NOTFOUND;
    size_t inboxlen = strlen(inbox);
    char *search = strconcat(inbox, ".", (char *)NULL);
    const char *data = NULL;
    size_t datalen = 0;
    int r;

    r = cyrusdb_fetch(mbdb, inbox, inboxlen, &data, &datalen, NULL);
    if (!r) {
	/* process inbox first */
	if (incdel || skipdel_cb(rock, inbox, inboxlen, data, datalen))
	    r = proc(rock, inbox, inboxlen, data, datalen);
    }
    else if (r == CYRUSDB_NOTFOUND) {
	/* don't process inbox! */
	r = 0;
    }
    if (r) goto done;

    /* process all the sub folders */
    r = cyrusdb_foreach(mbdb, search, strlen(search),
			incdel ? NULL : skipdel_cb,
			proc, rock, 0);
    if (r) goto done;

    /* don't check if delayed delete is enabled, maybe the caller wants to
     * clean up deleted stuff after it's been turned off */
    if (incdel) {
	const char *prefix = config_getstring(IMAPOPT_DELETEDPREFIX);
	char *name = strconcat(prefix, ".", inbox, ".", (char *)NULL);
	r = cyrusdb_foreach(mbdb, name, strlen(name),
			    incdel ? NULL : skipdel_cb,
			    proc, rock, 0);
	free(name);
    }

done:
    free(search);
    free(inbox);
    return r;
}

/*
 * Find all mailboxes that match 'pattern'.
 * 'isadmin' is nonzero if user is a mailbox admin.  'userid'
 * is the user's login id.  For each matching mailbox, calls
 * 'proc' with the name of the mailbox.  If 'proc' ever returns
 * a nonzero value, mboxlist_findall immediately stops searching
 * and returns that value.  'rock' is passed along as an argument to proc in
 * case it wants some persistant storage or extra data.
 */
/* Find all mailboxes that match 'pattern'. */
EXPORTED int mboxlist_findall(struct namespace *namespace,
		     const char *pattern, int isadmin, const char *userid, 
		     struct auth_state *auth_state, int (*proc)(), void *rock)
{
    struct find_rock cbrock;
    char usermboxname[MAX_MAILBOX_BUFFER];
    size_t usermboxnamelen = 0;
    const char *data;
    size_t datalen;
    int r = 0;
    char *p;
    size_t prefixlen;
    int userlen = userid ? strlen(userid) : 0, domainlen = 0;
    char domainpat[MAX_MAILBOX_BUFFER] = ""; /* do intra-domain fetches only */
    char *pat = NULL;

    if (!namespace) namespace = mboxname_get_adminnamespace();

    if (config_virtdomains) {
	char *domain;

	if (userid && (domain = strrchr(userid, '@'))) {
	    userlen = domain - userid;
	    domainlen = strlen(domain); /* includes separator */

	    if ((p = strchr(pattern , '!'))) {
		if ((p-pattern != domainlen-1) ||
		    strncmp(pattern, domain+1, domainlen-1)) {
		    /* don't allow cross-domain access */
		    return IMAP_MAILBOX_BADNAME;
		}

		pattern = p+1;
	    }

	    snprintf(domainpat, sizeof(domainpat), "%s!%s", domain+1, pattern);
	}
	if ((p = strrchr(pattern, '@'))) {
	    /* global admin specified mbox@domain */
	    if (domainlen) {
		/* can't do both user@domain and mbox@domain */
		return IMAP_MAILBOX_BADNAME;
	    }

	    /* don't prepend default domain */
	    if (!(config_defdomain && !strcasecmp(config_defdomain, p+1))) {
		snprintf(domainpat, sizeof(domainpat), "%s!", p+1);
		domainlen = strlen(p);
	    }
	    snprintf(domainpat+domainlen, sizeof(domainpat)-domainlen,
		     "%.*s", (int) (p - pattern), pattern);
	}
    }

    if (domainpat[0] == '\0')
	strlcpy(domainpat, pattern, sizeof(domainpat));

    cbrock.g = glob_init(pattern, GLOB_HIERARCHY|GLOB_INBOXCASE);
    cbrock.namespace = NULL;
    cbrock.domainlen = domainlen;
    cbrock.inboxcase = glob_inboxcase(cbrock.g);
    cbrock.isadmin = isadmin;
    cbrock.auth_state = auth_state;
    cbrock.checkmboxlist = 0;	/* don't duplicate work */
    cbrock.issubs = 0;
    cbrock.checkshared = 0;
    cbrock.proc = proc;
    cbrock.procrock = rock;
    cbrock.prev = NULL;
    cbrock.prevlen = 0;
    cbrock.db = mbdb;

    /* Build usermboxname */
    if (userid && (!(p = strchr(userid, '.')) || ((p - userid) > userlen)) &&
	strlen(userid)+5 < MAX_MAILBOX_BUFFER) {
	if (domainlen)
	    snprintf(usermboxname, sizeof(usermboxname),
		     "%s!", userid+userlen+1);
	snprintf(usermboxname+domainlen, sizeof(usermboxname)-domainlen,
		 "user.%.*s", userlen, userid);
	usermboxnamelen = strlen(usermboxname);
    }
    else {
	userid = NULL;
    }

    /* Check for INBOX first of all */
    if (userid) {
	if (GLOB_TEST(cbrock.g, "INBOX") != -1) {
	    r = cyrusdb_fetch(mbdb, usermboxname, usermboxnamelen,
			      &data, &datalen, NULL);
	    if (r == CYRUSDB_NOTFOUND) r = 0;
	    else if (!r)
		r = (*proc)(cbrock.inboxcase, 5, 1, rock);
	}
	else if (!strncmp(pattern,
			  usermboxname+domainlen, usermboxnamelen-domainlen) &&
		 GLOB_TEST(cbrock.g, usermboxname+domainlen) != -1) {
	    r = cyrusdb_fetch(mbdb, usermboxname, usermboxnamelen,
			      &data, &datalen, NULL);
	    if (r == CYRUSDB_NOTFOUND) r = 0;
	    else if (!r)
		r = (*proc)(usermboxname, usermboxnamelen, 1, rock);
	}
	strlcat(usermboxname, ".", sizeof(usermboxname));
	usermboxnamelen++;

	cbrock.usermboxname = usermboxname;
	cbrock.usermboxnamelen = usermboxnamelen;
    } else {
	cbrock.usermboxname = NULL;
	cbrock.usermboxnamelen = 0;
    }

    if (r) goto done;

    /* Make a working copy of pattern */
    pattern = pat = xstrdup(pattern);

    /* Find fixed-string pattern prefix */
    for (p = pat; *p; p++) {
	if (*p == '*' || *p == '%' || *p == '?' || *p == '@') break;
    }
    prefixlen = p - pattern;
    *p = '\0';

    /*
     * If user.X.* or INBOX.* can match pattern,
     * search for those mailboxes next
     */
    if (userid &&
	(!strncmp(usermboxname+domainlen, pattern, usermboxnamelen-domainlen-1) ||
	 !strncasecmp("inbox.", pattern, prefixlen < 6 ? prefixlen : 6))) {

	if (!strncmp(usermboxname+domainlen, pattern, usermboxnamelen-domainlen-1)) {
	    /* switch to pattern with domain prepended */
	    glob_free(&cbrock.g);
	    cbrock.g = glob_init(domainpat, GLOB_HIERARCHY);
	    cbrock.inboxoffset = 0;
	}
	else {
	    cbrock.inboxoffset = domainlen + userlen;
	}

	cbrock.find_namespace = NAMESPACE_INBOX;
	/* iterate through prefixes matching usermboxname */
	r = cyrusdb_foreach(mbdb,
			    usermboxname, usermboxnamelen,
			    &find_p, &find_cb, &cbrock,
			    NULL);

	free(cbrock.prev);
	cbrock.prev = NULL;
	cbrock.prevlen = 0;
    }

    if (!r && (isadmin || namespace->accessible[NAMESPACE_USER])) {
	cbrock.find_namespace = NAMESPACE_USER;
	/* switch to pattern with domain prepended */
	glob_free(&cbrock.g);
	cbrock.g = glob_init(domainpat, GLOB_HIERARCHY);
	cbrock.inboxoffset = 0;
	if (usermboxnamelen) {
	    usermboxname[--usermboxnamelen] = '\0';
	    cbrock.usermboxname = usermboxname;
	    cbrock.usermboxnamelen = usermboxnamelen;
	}
	/* search for all remaining mailboxes.
	   just bother looking at the ones that have the same pattern
	   prefix. */
	r = cyrusdb_foreach(mbdb,
			    domainpat, domainlen + prefixlen,
			    &find_p, &find_cb, &cbrock,
			    NULL);

	free(cbrock.prev);
	cbrock.prev = NULL;
	cbrock.prevlen = 0;
    }

  done:
    glob_free(&cbrock.g);
    if (pat) free(pat);

    return r;
}

HIDDEN int mboxlist_findall_alt(struct namespace *namespace,
			 const char *pattern, int isadmin, const char *userid,
			 struct auth_state *auth_state, int (*proc)(),
			 void *rock)
{
    struct find_rock cbrock;
    char usermboxname[MAX_MAILBOX_BUFFER], patbuf[MAX_MAILBOX_BUFFER];
    size_t usermboxnamelen = 0;
    const char *data;
    size_t datalen;
    int r = 0;
    char *p;
    size_t prefixlen, len;
    size_t userlen = userid ? strlen(userid) : 0, domainlen = 0;
    char domainpat[MAX_MAILBOX_BUFFER]; /* do intra-domain fetches only */
    char *pat = NULL;

    if (!namespace) namespace = mboxname_get_adminnamespace();

    if (config_virtdomains && userid && (p = strchr(userid, '@'))) {
	userlen = p - userid;
	domainlen = strlen(p); /* includes separator */
	snprintf(domainpat, sizeof(domainpat), "%s!", p+1);
    }
    else
	domainpat[0] = '\0';

    cbrock.g = glob_init(pattern, GLOB_HIERARCHY|GLOB_INBOXCASE);
    cbrock.namespace = namespace;
    cbrock.domainlen = domainlen;
    cbrock.inboxcase = glob_inboxcase(cbrock.g);
    cbrock.isadmin = isadmin;
    cbrock.auth_state = auth_state;
    cbrock.checkmboxlist = 0;	/* don't duplicate work */
    cbrock.issubs = 0;
    cbrock.checkshared = 0;
    cbrock.proc = proc;
    cbrock.procrock = rock;
    cbrock.prev = NULL;
    cbrock.prevlen = 0;
    cbrock.db = mbdb;

    /* Build usermboxname */
    if (userid && (!(p = strchr(userid, '.')) || ((p - userid) > (int)userlen)) &&
	strlen(userid)+5 < MAX_MAILBOX_BUFFER) {
	if (domainlen)
	    snprintf(usermboxname, sizeof(usermboxname),
		     "%s!", userid+userlen+1);
	snprintf(usermboxname+domainlen, sizeof(usermboxname)-domainlen,
		 "user.%.*s", (int)userlen, userid);
	usermboxnamelen = strlen(usermboxname);
    }
    else {
	userid = 0;
    }

    /* Check for INBOX first of all */
    if (userid) {
	if (GLOB_TEST(cbrock.g, "INBOX") != -1) {
	    r = cyrusdb_fetch(mbdb, usermboxname, usermboxnamelen,
			      &data, &datalen, NULL);
	    if (r == CYRUSDB_NOTFOUND) r = 0;
	    else if (!r)
		r = (*proc)(cbrock.inboxcase, 5, 0, rock);
	}

	strlcat(usermboxname, ".", sizeof(usermboxname));
	usermboxnamelen++;

	cbrock.usermboxname = usermboxname;
	cbrock.usermboxnamelen = usermboxnamelen;
    } else {
	cbrock.usermboxname = NULL;
	cbrock.usermboxnamelen = 0;
    }

    if (r) goto done;

    glob_free(&cbrock.g);

    /* Make a working copy of pattern */
    pattern = pat = xstrdup(pattern);

    /* Find fixed-string pattern prefix */
    for (p = pat; *p; p++) {
	if (*p == '*' || *p == '%' || *p == '?' || *p == '@') break;
    }
    prefixlen = p - pattern;

    /*
     * Personal (INBOX) namespace
     *
     * Append pattern to "INBOX.", search for those mailboxes next
     */
    if (userid) {
	strlcpy(patbuf, usermboxname, sizeof(patbuf));
	strlcat(patbuf, pattern, sizeof(patbuf));
	cbrock.g = glob_init(patbuf, GLOB_HIERARCHY);
	cbrock.inboxoffset = 0;
	cbrock.find_namespace = NAMESPACE_INBOX;

	/* iterate through prefixes matching usermboxname */
	cyrusdb_foreach(mbdb,
			usermboxname, usermboxnamelen,
			&find_p, &find_cb, &cbrock,
			NULL);

	free(cbrock.prev);
	cbrock.prev = NULL;
	cbrock.prevlen = 0;
	glob_free(&cbrock.g);
    }

    if (usermboxnamelen) {
	usermboxname[--usermboxnamelen] = '\0';
	cbrock.usermboxname = usermboxname;
	cbrock.usermboxnamelen = usermboxnamelen;
    }

    /*
     * Other Users namespace
     *
     * If "Other Users*" can match pattern, search for those mailboxes next
     */
    if (isadmin || namespace->accessible[NAMESPACE_USER]) {
        len = strlen(namespace->prefix[NAMESPACE_USER]);
        if(len>0) len--;

	if (!strncmp(namespace->prefix[NAMESPACE_USER], pattern,
		 prefixlen < len ? prefixlen : len)) {

	    if (prefixlen < len) {
	        strlcpy(domainpat+domainlen, pattern+prefixlen,
		    sizeof(domainpat)-domainlen);
	        cbrock.g = glob_init(domainpat, GLOB_HIERARCHY);
	    }
	    else {
	        strlcpy(domainpat+domainlen, "user", sizeof(domainpat)-domainlen);
	        strlcat(domainpat, pattern+len, sizeof(domainpat));
	        cbrock.g = glob_init(domainpat, GLOB_HIERARCHY);
	    }
	    cbrock.find_namespace = NAMESPACE_USER;
	    cbrock.inboxoffset = 0;

	    /* iterate through prefixes matching usermboxname */
	    strlcpy(domainpat+domainlen, "user", sizeof(domainpat)-domainlen);
	    cyrusdb_foreach(mbdb,
			    domainpat, strlen(domainpat),
			    &find_p, &find_cb, &cbrock,
			    NULL);

	    glob_free(&cbrock.g);
	    free(cbrock.prev);
	    cbrock.prev = NULL;
	    cbrock.prevlen = 0;
        }
    }

    /*
     * Shared namespace
     *
     * search for all remaining mailboxes.
     * just bother looking at the ones that have the same pattern prefix.
     */
    if (isadmin || namespace->accessible[NAMESPACE_SHARED]) {
	len = strlen(namespace->prefix[NAMESPACE_SHARED]);
	if(len>0) len--;
	if (!strncmp(namespace->prefix[NAMESPACE_SHARED], pattern,
		prefixlen < len ? prefixlen : len)) {

	    cbrock.find_namespace = NAMESPACE_SHARED;
	    cbrock.inboxoffset = 0;

	    if (prefixlen <= len) {
		/* Skip pattern which matches shared namespace prefix */
		for (p = pat+prefixlen; *p; p++) {
		    if (*p == '%') continue;
		    else if (*p == '.') p++;
		    break;
		}

		if (*pattern && !strchr(pattern, '.') &&
		    pattern[strlen(pattern)-1] == '%')
		/* special case:  LIST "" *% -- output prefix */
		    cbrock.checkshared = 1;

		if ((cbrock.checkshared || prefixlen == len) && !*p) {
		    /* special case:  LIST "" % -- output prefix
		       (if we have a shared mbox) and quit */
		    strlcpy(domainpat+domainlen, "*", sizeof(domainpat)-domainlen);
		    cbrock.g = glob_init(domainpat, GLOB_HIERARCHY);
		    cbrock.checkshared = 2;
		}
		else {
		    strlcpy(domainpat+domainlen, p, sizeof(domainpat)-domainlen);
		    cbrock.g = glob_init(domainpat, GLOB_HIERARCHY);
		}

		domainpat[domainlen] = '\0';
		cyrusdb_foreach(mbdb,
				domainpat, domainlen,
				&find_p, &find_cb, &cbrock,
				NULL);
	    }
	    else if (pattern[len] == '.') {
		strlcpy(domainpat+domainlen, pattern+len+1,
			sizeof(domainpat)-domainlen);
		cbrock.g = glob_init(domainpat, GLOB_HIERARCHY);

		cyrusdb_foreach(mbdb,
				domainpat, domainlen+prefixlen-(len+1),
				&find_p, &find_cb, &cbrock,
				NULL);
	    }
	    free(cbrock.prev);
	    cbrock.prev = NULL;
	    cbrock.prevlen = 0;
	}
    }

  done:
    glob_free(&cbrock.g);
    if (pat) free(pat);

    return r;
}

static int child_cb(char *name,
		    int matchlen __attribute__((unused)),
		    int maycreate __attribute__((unused)),
		    void *rock)
{
    if (!name) return 0;
    return (*((int *) rock) = 1);
}

/*
 * Set all the resource quotas on, or create a quota root.
 */
EXPORTED int mboxlist_setquotas(const char *root,
		       quota_t newquotas[QUOTA_NUMRESOURCES], int force)
{
    char pattern[MAX_MAILBOX_PATH+1];
    struct quota q;
    int have_mailbox = 1;
    int r;
    int res;
    struct txn *tid = NULL;
    struct mboxevent *mboxevents = NULL;
    struct mboxevent *quotachange_event = NULL;
    struct mboxevent *quotawithin_event = NULL;

    if (!root[0] || root[0] == '.' || strchr(root, '/')
	|| strchr(root, '*') || strchr(root, '%') || strchr(root, '?')) {
	return IMAP_MAILBOX_BADNAME;
    }
    
    quota_init(&q, root);
    r = quota_read(&q, &tid, 1);

    if (!r) {
	int changed = 0;
	int underquota;

	/* has it changed? */
	for (res = 0 ; res < QUOTA_NUMRESOURCES ; res++) {
	    if (q.limits[res] != newquotas[res]) {
		underquota = 0;

		/* Prepare a QuotaChange event notification *now*.
		 * 
		 * This is to ensure the QuotaChange is emitted before the
		 * subsequent QuotaWithin (if the latter becomes applicable).
		 */
		if (quotachange_event == NULL) {
		    quotachange_event = mboxevent_enqueue(EVENT_QUOTA_CHANGE,
		                                          &mboxevents);
		}

		/* prepare a QuotaWithin event notification if now under quota */
		if (quota_is_overquota(&q, res, NULL) &&
		    (!quota_is_overquota(&q, res, newquotas) || newquotas[res] == -1)) {
		    if (quotawithin_event == NULL)
			quotawithin_event = mboxevent_enqueue(EVENT_QUOTA_WITHIN,
			                                      &mboxevents);
		    underquota++;
		}

		q.limits[res] = newquotas[res];
		changed++;

		mboxevent_extract_quota(quotachange_event, &q, res);
		if (underquota)
		    mboxevent_extract_quota(quotawithin_event, &q, res);
	    }
	}
	if (changed) {
	    r = quota_write(&q, &tid);

	    if (quotachange_event == NULL) {
		quotachange_event = mboxevent_enqueue(EVENT_QUOTA_CHANGE, &mboxevents);
	    }

	    for (res = 0; res < QUOTA_NUMRESOURCES; res++) {
		mboxevent_extract_quota(quotachange_event, &q, res);
	    }
	}

	if (!r)
	    quota_commit(&tid);

	goto done;
    }

    if (r != IMAP_QUOTAROOT_NONEXISTENT)
	goto done;

    /*
     * Have to create a new quota root
     */
    strlcpy(pattern, root, sizeof(pattern));

    if (config_virtdomains && root[strlen(root)-1] == '!') {
	/* domain quota */
	have_mailbox = 0;
	strlcat(pattern, "*", sizeof(pattern));
    }
    else {
	mbentry_t *mbentry = NULL;
	strlcat(pattern, ".*", sizeof(pattern));

	/* look for a top-level mailbox in the proposed quotaroot */
	r = mboxlist_lookup(root, &mbentry, NULL);
	if (r) {
	    if (!force && r == IMAP_MAILBOX_NONEXISTENT) {
		/* look for a child mailbox in the proposed quotaroot */
		 mboxlist_findall(NULL, pattern, 1, NULL, NULL,
				 child_cb, (void *) &force);
	    }
	    /* are we going to force the create anyway? */
	    if (force) {
		have_mailbox = 0;
		r = 0;
	    }
	}
	else if (mbentry->mbtype & (MBTYPE_REMOTE | MBTYPE_MOVING)) {
	    /* Can't set quota on a remote mailbox */
	    r = IMAP_MAILBOX_NOTSUPPORTED;
	}
	mboxlist_entry_free(&mbentry);
	if (r) goto done;
    }

    /* safe against quota -f and other root change races */
    r = quota_changelock();
    if (r) goto done;

    /* initialise the quota */
    memcpy(q.limits, newquotas, sizeof(q.limits));
    r = quota_write(&q, &tid);
    if (r) goto done;

    /* prepare a QuotaChange event notification */
    if (quotachange_event == NULL)
	quotachange_event = mboxevent_enqueue(EVENT_QUOTA_CHANGE, &mboxevents);

    for (res = 0; res < QUOTA_NUMRESOURCES; res++) {
	mboxevent_extract_quota(quotachange_event, &q, res);
    }

    quota_commit(&tid);

    /* recurse through mailboxes, setting the quota and finding
     * out the usage */
    /* top level mailbox */
    if (have_mailbox)
	mboxlist_changequota(root, 0, 0, (void *)root);

    /* submailboxes - we're using internal names here */
    mboxlist_findall(NULL, pattern, 1, 0, 0, mboxlist_changequota, (void *)root);

    quota_changelockrelease();

done:
    quota_free(&q);
    if (r && tid) quota_abort(&tid);
    if (!r) {
	sync_log_quota(root);

	/* send QuotaChange and QuotaWithin event notifications */
	mboxevent_notify(mboxevents);
    }
    mboxevent_freequeue(&mboxevents);

    return r;
}

/*
 *  Remove a quota root
 */
EXPORTED int mboxlist_unsetquota(const char *root)
{
    char pattern[MAX_MAILBOX_PATH+1];
    struct quota q;
    int r=0;

    if (!root[0] || root[0] == '.' || strchr(root, '/')
	|| strchr(root, '*') || strchr(root, '%') || strchr(root, '?')) {
	return IMAP_MAILBOX_BADNAME;
    }
    
    quota_init(&q, root);
    r = quota_read(&q, NULL, 0);
    /* already unset */
    if (r == IMAP_QUOTAROOT_NONEXISTENT) {
	r = 0;
	goto done;
    }
    if (r) goto done;

    r = quota_changelock();

    /*
     * Have to remove it from all affected mailboxes
     */
    strlcpy(pattern, root, sizeof(pattern));
    if (config_virtdomains && root[strlen(root)-1] == '!') {
	/* domain quota */
	strlcat(pattern, "*", sizeof(pattern));
    }
    else
	strlcat(pattern, ".*", sizeof(pattern));
    
    /* top level mailbox */
    mboxlist_rmquota(root, 0, 0, (void *)root);
    /* submailboxes - we're using internal names here */
    mboxlist_findall(NULL, pattern, 1, 0, 0, mboxlist_rmquota, (void *)root);

    r = quota_deleteroot(root);
    quota_changelockrelease();

    if (!r) sync_log_quota(root);

 done:
    quota_free(&q);
    return r;
}

/*
 * ACL access canonicalization routine which ensures that 'owner'
 * retains lookup, administer, and create rights over a mailbox.
 */
EXPORTED int mboxlist_ensureOwnerRights(void *rock, const char *identifier,
			       int myrights)
{
    char *owner = (char *)rock;
    if (strcmp(identifier, owner) != 0) return myrights;
    return myrights|config_implicitrights;
}

/*
 * Helper function to remove the quota root for 'name'
 */
static int mboxlist_rmquota(const char *name,
			    int matchlen __attribute__((unused)),
			    int maycreate __attribute__((unused)),
			    void *rock)
{
    int r = 0;
    struct mailbox *mailbox = NULL;
    const char *oldroot = (const char *) rock;

    assert(oldroot != NULL);

    r = mailbox_open_iwl(name, &mailbox);
    if (r) goto done;

    if (mailbox->quotaroot) {
	if (strcmp(mailbox->quotaroot, oldroot)) {
	    /* Part of a different quota root */
	    goto done;
	}

	r = mailbox_set_quotaroot(mailbox, NULL);
    }

 done:
    mailbox_close(&mailbox);

    if (r) {
	syslog(LOG_ERR, "LOSTQUOTA: unable to remove quota root %s for %s: %s",
	       oldroot, name, error_message(r));
    }

    /* not a huge tragedy if we failed, so always return success */
    return 0;
}

/*
 * Helper function to change the quota root for 'name' to that pointed
 * to by the static global struct pointer 'mboxlist_newquota'.
 */
static int mboxlist_changequota(const char *name,
				int matchlen __attribute__((unused)),
				int maycreate __attribute__((unused)),
				void *rock)
{
    int r = 0;
    struct mailbox *mailbox = NULL;
    const char *root = (const char *) rock;
    int res;
    quota_t quota_usage[QUOTA_NUMRESOURCES];

    assert(root);

    r = mailbox_open_iwl(name, &mailbox);
    if (r) goto done;

    mailbox_get_usage(mailbox, quota_usage);

    if (mailbox->quotaroot) {
	quota_t quota_diff[QUOTA_NUMRESOURCES];

	if (strlen(mailbox->quotaroot) >= strlen(root)) {
	    /* Part of a child quota root - skip */
	    goto done;
	}

	/* remove usage from the old quotaroot */
	for (res = 0; res < QUOTA_NUMRESOURCES ; res++) {
	    quota_diff[res] = -quota_usage[res];
	}
	r = quota_update_useds(mailbox->quotaroot, quota_diff,
			       mailbox->name);
    }

    /* update (or set) the quotaroot */
    r = mailbox_set_quotaroot(mailbox, root);
    if (r) goto done;

    /* update the new quota root */
    r = quota_update_useds(root, quota_usage, mailbox->name);

 done:
    mailbox_close(&mailbox);

    if (r) {
	syslog(LOG_ERR, "LOSTQUOTA: unable to change quota root for %s to %s: %s",
	       name, root, error_message(r));
    }

    /* Note, we're a callback, and it's not a huge tragedy if we
     * fail, so we don't ever return a failure */
    return 0;
}

/* must be called after cyrus_init */
EXPORTED void mboxlist_init(int myflags)
{
    if (myflags & MBOXLIST_SYNC) {
	cyrusdb_sync(DB);
    }
}

EXPORTED void mboxlist_open(const char *fname)
{
    int ret, flags;
    char *tofree = NULL;

    if (!fname)
	fname = config_getstring(IMAPOPT_MBOXLIST_DB_PATH);

    /* create db file name */
    if (!fname) {
	tofree = strconcat(config_dir, FNAME_MBOXLIST, (char *)NULL);
	fname = tofree;
    }

    flags = CYRUSDB_CREATE;
    if (config_getswitch(IMAPOPT_IMPROVED_MBOXLIST_SORT)) {
	flags |= CYRUSDB_MBOXSORT;
    }

    ret = cyrusdb_open(DB, fname, flags, &mbdb);
    if (ret != 0) {
	syslog(LOG_ERR, "DBERROR: opening %s: %s", fname,
	       cyrusdb_strerror(ret));
	    /* Exiting TEMPFAIL because Sendmail thinks this
	       EC_OSFILE == permanent failure. */
	fatal("can't read mailboxes file", EC_TEMPFAIL);
    }    

    free(tofree);

    mboxlist_dbopen = 1;
}

EXPORTED void mboxlist_close(void)
{
    int r;

    if (mboxlist_dbopen) {
	r = cyrusdb_close(mbdb);
	if (r) {
	    syslog(LOG_ERR, "DBERROR: error closing mailboxes: %s",
		   cyrusdb_strerror(r));
	}
	mboxlist_dbopen = 0;
    }
}

EXPORTED void mboxlist_done(void)
{
    /* DB->done() handled by cyrus_done() */
}

/*
 * Open the subscription list for 'userid'.
 * 
 * On success, returns zero.
 * On failure, returns an error code.
 */
static int
mboxlist_opensubs(const char *userid,
		  struct db **ret)
{
    int r = 0, flags;
    char *subsfname;

    /* Build subscription list filename */
    subsfname = user_hash_subs(userid);

    flags = CYRUSDB_CREATE;
    if (config_getswitch(IMAPOPT_IMPROVED_MBOXLIST_SORT)) {
	flags |= CYRUSDB_MBOXSORT;
    }

    r = cyrusdb_open(SUBDB, subsfname, flags, ret);
    if (r != CYRUSDB_OK) {
	r = IMAP_IOERROR;
    }
    free(subsfname);

    return r;
}

/*
 * Close a subscription file
 */
static void mboxlist_closesubs(struct db *sub)
{
    cyrusdb_close(sub);
}

/*
 * Find subscribed mailboxes that match 'pattern'.
 * 'isadmin' is nonzero if user is a mailbox admin.  'userid'
 * is the user's login id.  For each matching mailbox, calls
 * 'proc' with the name of the mailbox.
 */
EXPORTED int mboxlist_findsub(struct namespace *namespace,
		     const char *pattern, int isadmin __attribute__((unused)),
		     const char *userid, struct auth_state *auth_state, 
		     int (*proc)(), void *rock, int force)
{
    struct db *subs = NULL;
    struct find_rock cbrock;
    char usermboxname[MAX_MAILBOX_BUFFER];
    size_t usermboxnamelen = 0;
    const char *data;
    size_t datalen;
    int r = 0;
    char *p;
    size_t prefixlen;
    size_t userlen = userid ? strlen(userid) : 0, domainlen = 0;
    char domainpat[MAX_MAILBOX_BUFFER]; /* do intra-domain fetches only */
    char *pat = NULL;

    if (!namespace) namespace = mboxname_get_adminnamespace();

    if (config_virtdomains && userid && (p = strchr(userid, '@'))) {
	userlen = p - userid;
	domainlen = strlen(p); /* includes separator */
	snprintf(domainpat, sizeof(domainpat), "%s!%s", p+1, pattern);
    }
    else
	xstrncpy(domainpat, pattern, sizeof(domainpat));

    cbrock.g = glob_init(pattern, GLOB_HIERARCHY|GLOB_INBOXCASE);
    cbrock.namespace = NULL;
    cbrock.domainlen = domainlen;
    cbrock.inboxcase = glob_inboxcase(cbrock.g);
    cbrock.isadmin = 1;		/* user can always see their subs */
    cbrock.auth_state = auth_state;
    cbrock.checkmboxlist = !force;
    cbrock.issubs = 1;
    cbrock.checkshared = 0;
    cbrock.proc = proc;
    cbrock.procrock = rock;
    cbrock.prev = NULL;
    cbrock.prevlen = 0;

    /* open the subscription file that contains the mailboxes the 
       user is subscribed to */
    if ((r = mboxlist_opensubs(userid, &subs)) != 0) {
	goto done;
    }

    cbrock.db = subs;

    /* Build usermboxname */
    if (userid && (!(p = strchr(userid, '.')) || ((p - userid) > (int)userlen)) &&
	strlen(userid)+5 < MAX_MAILBOX_BUFFER) {
	if (domainlen)
	    snprintf(usermboxname, sizeof(usermboxname),
		     "%s!", userid+userlen+1);
	snprintf(usermboxname+domainlen, sizeof(usermboxname)-domainlen,
		 "user.%.*s", (int)userlen, userid);
	usermboxnamelen = strlen(usermboxname);
    }
    else {
	userid = 0;
    }

    /* Check for INBOX first of all */
    if (userid) {
	if (GLOB_TEST(cbrock.g, "INBOX") != -1) {
	    r = cyrusdb_fetch(subs, usermboxname, usermboxnamelen,
			     &data, &datalen, NULL);
	    if (r == CYRUSDB_NOTFOUND) r = 0;
	    else if (!r)
		r = (*proc)(cbrock.inboxcase, 5, 1, rock);
	}
	else if (!strncmp(pattern,
			  usermboxname+domainlen, usermboxnamelen-domainlen) &&
		 GLOB_TEST(cbrock.g, usermboxname+domainlen) != -1) {
	    r = cyrusdb_fetch(subs, usermboxname, usermboxnamelen,
			     &data, &datalen, NULL);
	    if (r == CYRUSDB_NOTFOUND) r = 0;
	    else if (!r)
		r = (*proc)(usermboxname, usermboxnamelen, 1, rock);
	}
	strlcat(usermboxname, ".", sizeof(usermboxname));
	usermboxnamelen++;

	cbrock.usermboxname = usermboxname;
	cbrock.usermboxnamelen = usermboxnamelen;
    }

    if (r) goto done;

    /* Make a working copy of pattern */
    pattern = pat = xstrdup(pattern);

    /* Find fixed-string pattern prefix */
    for (p = pat; *p; p++) {
	if (*p == '*' || *p == '%' || *p == '?' || *p == '@') break;
    }
    prefixlen = p - pattern;
    *p = '\0';

    /*
     * If user.X.* or INBOX.* can match pattern,
     * search for those mailboxes next
     */
    if (userid &&
	(!strncmp(usermboxname+domainlen, pattern, usermboxnamelen-domainlen-1) ||
	 !strncasecmp("inbox.", pattern, prefixlen < 6 ? prefixlen : 6))) {

	if (!strncmp(usermboxname+domainlen, pattern, usermboxnamelen-domainlen-1)) {
	    /* switch to pattern with domain prepended */
	    glob_free(&cbrock.g);
	    cbrock.g = glob_init(domainpat, GLOB_HIERARCHY);
	    cbrock.inboxoffset = 0;
	}
	else {
	    cbrock.inboxoffset = strlen(userid);
	}

	cbrock.find_namespace = NAMESPACE_INBOX;
	/* iterate through prefixes matching usermboxname */
	cyrusdb_foreach(subs,
			usermboxname, usermboxnamelen,
			&find_p, &find_cb, &cbrock,
			NULL);
	free(cbrock.prev);
	cbrock.prev = NULL;
	cbrock.prevlen = 0;

	cbrock.usermboxname = usermboxname;
	cbrock.usermboxnamelen = usermboxnamelen;
    } else {
	cbrock.usermboxname = NULL;
	cbrock.usermboxnamelen = 0;
    }

    if (isadmin || namespace->accessible[NAMESPACE_USER]) {
	cbrock.find_namespace = NAMESPACE_USER;
	/* switch to pattern with domain prepended */
	glob_free(&cbrock.g);
	cbrock.g = glob_init(domainpat, GLOB_HIERARCHY);
	cbrock.inboxoffset = 0;
	if (usermboxnamelen) {
	    usermboxname[--usermboxnamelen] = '\0';
	    cbrock.usermboxname = usermboxname;
	    cbrock.usermboxnamelen = usermboxnamelen;
	}
	/* search for all remaining mailboxes.
	   just bother looking at the ones that have the same pattern prefix. */
	cyrusdb_foreach(subs, domainpat, domainlen + prefixlen,
			&find_p, &find_cb, &cbrock, NULL);
	free(cbrock.prev);
	cbrock.prev = NULL;
	cbrock.prevlen = 0;
   }

  done:
    if (subs) mboxlist_closesubs(subs);
    glob_free(&cbrock.g);
    if (pat) free(pat);

    return r;
}

EXPORTED int mboxlist_allsubs(const char *userid, foreach_cb *proc, void *rock)
{
    struct db *subs = NULL;
    int r;

    /* open subs DB */
    r = mboxlist_opensubs(userid, &subs);
    if (r) return r;

    r = cyrusdb_foreach(subs, "", 0, NULL, proc, rock, 0);

    mboxlist_closesubs(subs);

    return r;
}

HIDDEN int mboxlist_findsub_alt(struct namespace *namespace,
			 const char *pattern, int isadmin __attribute__((unused)),
			 const char *userid, struct auth_state *auth_state, 
			 int (*proc)(), void *rock, int force)
{
    struct db *subs = NULL;
    struct find_rock cbrock;
    char usermboxname[MAX_MAILBOX_BUFFER], patbuf[MAX_MAILBOX_BUFFER];
    size_t usermboxnamelen = 0;
    const char *data;
    size_t datalen;
    int r = 0;
    char *p;
    size_t prefixlen, len;
    size_t userlen = userid ? strlen(userid) : 0, domainlen = 0;
    char domainpat[MAX_MAILBOX_BUFFER]; /* do intra-domain fetches only */
    char *pat = NULL;

    if (!namespace) namespace = mboxname_get_adminnamespace();

    if (config_virtdomains && userid && (p = strchr(userid, '@'))) {
	userlen = p - userid;
	domainlen = strlen(p); /* includes separator */
	snprintf(domainpat, sizeof(domainpat), "%s!", p+1);
    }
    else
	domainpat[0] = '\0';

    cbrock.g = glob_init(pattern, GLOB_HIERARCHY|GLOB_INBOXCASE);
    cbrock.namespace = namespace;
    cbrock.domainlen = domainlen;
    cbrock.inboxcase = glob_inboxcase(cbrock.g);
    cbrock.isadmin = 1;		/* user can always see their subs */
    cbrock.auth_state = auth_state;
    cbrock.checkmboxlist = !force;
    cbrock.issubs = 1;
    cbrock.checkshared = 0;
    cbrock.proc = proc;
    cbrock.procrock = rock;
    cbrock.prev = NULL;
    cbrock.prevlen = 0;

    /* open the subscription file that contains the mailboxes the 
       user is subscribed to */
    if ((r = mboxlist_opensubs(userid, &subs)) != 0) {
	goto done;
    }

    cbrock.db = subs;

    /* Build usermboxname */
    if (userid && (!(p = strchr(userid, '.')) || ((p - userid) > (int)userlen)) &&
	strlen(userid)+5 < MAX_MAILBOX_BUFFER) {
	if (domainlen)
	    snprintf(usermboxname, sizeof(usermboxname),
		     "%s!", userid+userlen+1);
	snprintf(usermboxname+domainlen, sizeof(usermboxname)-domainlen,
		 "user.%.*s", (int)userlen, userid);
	usermboxnamelen = strlen(usermboxname);
    }
    else {
	userid = 0;
    }

    /* Check for INBOX first of all */
    if (userid) {
	if (GLOB_TEST(cbrock.g, "INBOX") != -1) {
	    r = cyrusdb_fetch(subs, usermboxname, usermboxnamelen,
			      &data, &datalen, NULL);
	    if (r == CYRUSDB_NOTFOUND) r = 0;
	    else if (!r)
		r = (*proc)(cbrock.inboxcase, 5, 0, rock);
	}
	strlcat(usermboxname, ".", sizeof(usermboxname));
	usermboxnamelen++;

	cbrock.usermboxname = usermboxname;
	cbrock.usermboxnamelen = usermboxnamelen;
    }

    if (r) goto done;

    glob_free(&cbrock.g);

    /* Make a working copy of pattern */
    pattern = pat = xstrdup(pattern);

    /* Find fixed-string pattern prefix */
    for (p = pat; *p; p++) {
	if (*p == '*' || *p == '%' || *p == '?' || *p == '@') break;
    }
    prefixlen = p - pattern;

    /*
     * Personal (INBOX) namespace
     *
     * Append pattern to "INBOX.", search for those subscriptions next
     */
    if (userid) {
	strlcpy(patbuf, usermboxname, sizeof(patbuf));
	strlcat(patbuf, pattern, sizeof(patbuf));
	cbrock.g = glob_init(patbuf, GLOB_HIERARCHY);
	cbrock.inboxoffset = 0;
	cbrock.find_namespace = NAMESPACE_INBOX;

	/* iterate through prefixes matching usermboxname */
	cyrusdb_foreach(subs,
			usermboxname, usermboxnamelen,
			&find_p, &find_cb, &cbrock,
			NULL);
	free(cbrock.prev);
	cbrock.prev = NULL;
	cbrock.prevlen = 0;

	glob_free(&cbrock.g);

	cbrock.usermboxname = usermboxname;
	cbrock.usermboxnamelen = usermboxnamelen;
    } else {
	cbrock.usermboxname = NULL;
	cbrock.usermboxnamelen = 0;
    }

    if (usermboxnamelen) {
	usermboxname[--usermboxnamelen] = '\0';
	cbrock.usermboxname = usermboxname;
	cbrock.usermboxnamelen = usermboxnamelen;
    }

    /*
     * Other Users namespace
     *
     * If "Other Users*" can match pattern, search for those subscriptions next
     */

    if (isadmin || namespace->accessible[NAMESPACE_USER]) {
	len = strlen(namespace->prefix[NAMESPACE_USER]);
	if(len>0) len--; /* Remove Separator */
	if (!strncmp(namespace->prefix[NAMESPACE_USER], pattern,
		     prefixlen < len ? prefixlen : len)) {

	    if (prefixlen < len) {
		strlcpy(domainpat+domainlen, pattern+prefixlen,
			sizeof(domainpat)-domainlen);
		cbrock.g = glob_init(domainpat, GLOB_HIERARCHY);
	    }
	    else {
		strlcpy(domainpat+domainlen, "user",
			sizeof(domainpat)-domainlen);
		strlcat(domainpat, pattern+len, sizeof(domainpat));
		cbrock.g = glob_init(domainpat, GLOB_HIERARCHY);
	    }
	    cbrock.find_namespace = NAMESPACE_USER;
	    cbrock.inboxoffset = 0;
	
	    /* iterate through prefixes matching usermboxname */
	    strlcpy(domainpat+domainlen, "user", sizeof(domainpat)-domainlen);
	    cyrusdb_foreach(subs,
			    domainpat, strlen(domainpat),
			    &find_p, &find_cb, &cbrock,
			    NULL);
	    free(cbrock.prev);
	    cbrock.prev = NULL;
	    cbrock.prevlen = 0;

	    glob_free(&cbrock.g);
	}
    }

    /*
     * Shared namespace
     *
     * search for all remaining subscriptions.
     * just bother looking at the ones that have the same pattern prefix.
     */
    if (isadmin || namespace->accessible[NAMESPACE_SHARED]) {
	len = strlen(namespace->prefix[NAMESPACE_SHARED]);
	if(len>0) len--; /* Remove Separator */
	if (!strncmp(namespace->prefix[NAMESPACE_SHARED], pattern,
		     prefixlen < len ? prefixlen : len)) {

	    cbrock.find_namespace = NAMESPACE_SHARED;
	    cbrock.inboxoffset = 0;

	    if (prefixlen <= len) {
		/* Skip pattern which matches shared namespace prefix */
		for (p = pat+prefixlen; *p; p++) {
		    if (*p == '%') continue;
		    else if (*p == '.') p++;
		    break;
		}

		if (*pattern && !strchr(pattern, '.') &&
		    pattern[strlen(pattern)-1] == '%') {
		    /* special case:  LSUB "" *% -- output prefix */
		    cbrock.checkshared = 1;
		}

		if ((cbrock.checkshared || prefixlen == len) && !*p) {
		    /* special case:  LSUB "" % -- output prefix
		       (if we have a shared mbox) and quit */
		    strlcpy(domainpat+domainlen, "*", sizeof(domainpat)-domainlen);
		    cbrock.g = glob_init(domainpat, GLOB_HIERARCHY);
		    cbrock.checkshared = 2;
		}
		else {
		    strlcpy(domainpat+domainlen, p, sizeof(domainpat)-domainlen);
		    cbrock.g = glob_init(domainpat, GLOB_HIERARCHY);
		}

		domainpat[domainlen] = '\0';
		cyrusdb_foreach(subs,
				domainpat, domainlen,
				&find_p, &find_cb, &cbrock,
				NULL);
		free(cbrock.prev);
		cbrock.prev = NULL;
		cbrock.prevlen = 0;
	    }
	    else if (pattern[len] == '.') {
		strlcpy(domainpat+domainlen, pattern+len+1,
		        sizeof(domainpat)-domainlen);
		cbrock.g = glob_init(domainpat, GLOB_HIERARCHY);

		cyrusdb_foreach(subs,
				domainpat, domainlen+prefixlen-(len+1),
				&find_p, &find_cb, &cbrock,
				NULL);
		free(cbrock.prev);
		cbrock.prev = NULL;
		cbrock.prevlen = 0;
	    }
	}
    }

  done:
    if (subs) mboxlist_closesubs(subs);
    glob_free(&cbrock.g);
    if (pat) free(pat);

    return r;
}

/* returns CYRUSDB_NOTFOUND if the folder doesn't exist, and 0 if it does! */
EXPORTED int mboxlist_checksub(const char *name, const char *userid)
{
    int r;
    struct db *subs;
    const char *val;
    size_t vallen;

    r = mboxlist_opensubs(userid, &subs);

    if (!r) r = cyrusdb_fetch(subs, name, strlen(name), &val, &vallen, NULL);

    mboxlist_closesubs(subs);
    return r;
}

/*
 * Change 'user's subscription status for mailbox 'name'.
 * Subscribes if 'add' is nonzero, unsubscribes otherwise.
 * if 'force' is set, force the subscription through even if
 * we don't know about 'name'.
 */
EXPORTED int mboxlist_changesub(const char *name, const char *userid,
				struct auth_state *auth_state, 
				int add, int force, int notify)
{
    mbentry_t *mbentry = NULL;
    int r;
    struct db *subs;
    struct mboxevent *mboxevent;

    if ((r = mboxlist_opensubs(userid, &subs)) != 0) {
	return r;
    }

    if (add && !force) {
	/* Ensure mailbox exists and can be seen by user */
	if ((r = mboxlist_lookup(name, &mbentry, NULL))!=0) {
	    mboxlist_closesubs(subs);
	    return r;
	}
	if ((cyrus_acl_myrights(auth_state, mbentry->acl) & ACL_LOOKUP) == 0) {
	    mboxlist_closesubs(subs);
	    mboxlist_entry_free(&mbentry);
	    return IMAP_MAILBOX_NONEXISTENT;
	}
    }

    if (add) {
	r = cyrusdb_store(subs, name, strlen(name), "", 0, NULL);
    } else {
	r = cyrusdb_delete(subs, name, strlen(name), NULL, 0);
	/* if it didn't exist, that's ok */
	if (r == CYRUSDB_EXISTS) r = CYRUSDB_OK;
    }

    switch (r) {
    case CYRUSDB_OK:
	r = 0;
	break;

    default:
	r = IMAP_IOERROR;
	break;
    }

    sync_log_subscribe(userid, name);
    mboxlist_closesubs(subs);
    mboxlist_entry_free(&mbentry);

    /* prepare a MailboxSubscribe or MailboxUnSubscribe event notification */
    if (notify && r == 0) {
	mboxevent = mboxevent_new(add ? EVENT_MAILBOX_SUBSCRIBE :
					EVENT_MAILBOX_UNSUBSCRIBE);

	mboxevent_set_access(mboxevent, NULL, NULL, userid, name, 1);
	mboxevent_notify(mboxevent);
	mboxevent_free(&mboxevent);
    }

    return r;
}

/* Transaction Handlers */
EXPORTED int mboxlist_commit(struct txn *tid)
{
    assert(tid);
    
    return cyrusdb_commit(mbdb, tid);
}

int mboxlist_abort(struct txn *tid)
{
    assert(tid);

    return cyrusdb_abort(mbdb, tid);
}

EXPORTED int mboxlist_delayed_delete_isenabled(void)
{
    enum enum_value config_delete_mode = config_getenum(IMAPOPT_DELETE_MODE);

    return(config_delete_mode == IMAP_ENUM_DELETE_MODE_DELAYED);
}
