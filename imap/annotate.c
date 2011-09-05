/* annotate.c -- Annotation manipulation routines
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
 * $Id: annotate.c,v 1.47 2010/01/06 17:01:30 murch Exp $
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

#include "acl.h"
#include "assert.h"
#include "cyrusdb.h"
#include "exitcodes.h"
#include "glob.h"
#include "hash.h"
#include "imapd.h"
#include "global.h"
#include "times.h"
#include "imap_err.h"
#include "mboxlist.h"
#include "util.h"
#include "xmalloc.h"
#include "ptrarray.h"
#include "xstrlcpy.h"
#include "xstrlcat.h"
#include "tok.h"
#include "quota.h"

#include "annotate.h"
#include "sync_log.h"

#define DEBUG 0

enum {
  ANNOTATION_SCOPE_SERVER = 1,
  ANNOTATION_SCOPE_MAILBOX = 2,
  ANNOTATION_SCOPE_MESSAGE = 3
};

typedef struct annotate_entrydesc annotate_entrydesc_t;

struct annotate_entry_list
{
    struct annotate_entry_list *next;
    const annotate_entrydesc_t *desc;
    char *name;
    /* used for storing */
    struct buf shared;
    struct buf priv;
    int have_shared;
    int have_priv;
};

/* Encapsulates all the state involved in providing the scope
 * for setting or getting a single annotation */
struct annotate_state
{
    /*
     * Common between storing and fetching
     */
    int which;			/* ANNOTATION_SCOPE_* */
    const char *mboxpat;	/* for _MAILBOX */
    const char *int_mboxname;	/* for _MAILBOX, _MESSAGE */
    const char *ext_mboxname;	/* for _MAILBOX */
    struct mboxlist_entry *mbentry; /* for _MAILBOX */
    unsigned int uid;		/* for _MESSAGE */
    const char *acl;		/* for _MESSAGE */

    /* authentication state */
    struct namespace *namespace;
    const char *userid;
    int isadmin;
    struct auth_state *auth_state;

    struct annotate_entry_list *entry_list;
    /* for proxies */
    struct hash_table entry_table;
    struct hash_table server_table;

    /*
     * Fetching.
     */
    unsigned attribs;
    struct entryattlist **entryatts;
    unsigned found;

    /* For proxies (a null entry_list indicates that we ONLY proxy) */
    /* if these are NULL, we have had a local exact match, and we
       DO NOT proxy */
    const char *orig_mailbox;
    const strarray_t *orig_entry;
    const strarray_t *orig_attribute;
    int maxsize;
    int *sizeptr;

    /* state for output_entryatt */
    struct attvaluelist *attvalues;
    char lastname[MAX_MAILBOX_BUFFER];
    char lastentry[MAX_MAILBOX_BUFFER];
    uint32_t lastuid;
    annotate_fetch_cb_t callback;
    void *callback_rock;

    /*
     * Storing.
     */
    struct quota quota;
    struct quota oldquota;

    /* number of mailboxes matching the pattern */
    unsigned count;
};

enum {
    ATTRIB_VALUE_SHARED =		(1<<0),
    ATTRIB_VALUE_PRIV =			(1<<1),
    ATTRIB_SIZE_SHARED =		(1<<2),
    ATTRIB_SIZE_PRIV =			(1<<3),
    ATTRIB_DEPRECATED =			(1<<4)
};

typedef enum {
    ANNOTATION_PROXY_T_INVALID = 0,

    PROXY_ONLY = 1,
    BACKEND_ONLY = 2,
    PROXY_AND_BACKEND = 3
} annotation_proxy_t;

enum {
    ATTRIB_TYPE_STRING,
    ATTRIB_TYPE_BOOLEAN,
    ATTRIB_TYPE_UINT,
    ATTRIB_TYPE_INT
};
#define ATTRIB_NO_FETCH_ACL_CHECK   (1<<30)

struct annotate_entrydesc
{
    const char *name;		/* entry name */
    int type;			/* entry type */
    annotation_proxy_t proxytype; /* mask of allowed server types */
    int attribs;		/* mask of allowed attributes */
    int extra_rights;		/* for set of shared mailbox annotations */
		/* function to get the entry */
    void (*get)(annotate_state_t *state,
	        struct annotate_entry_list *entry);
	       /* function to set the entry */
    int (*set)(annotate_state_t *state,
	       struct annotate_entry_list *entry);
    void *rock;			/* rock passed to get() function */
};

#define DB config_annotation_db

static annotate_db_t *all_dbs_head = NULL;
static annotate_db_t *all_dbs_tail = NULL;
static int in_txn = 0;
static struct txn *quota_txn = NULL;
#define tid(d)	(in_txn ? &(d)->txn : NULL)
int (*proxy_fetch_func)(const char *server, const char *mbox_pat,
			const strarray_t *entry_pat,
			const strarray_t *attribute_pat) = NULL;
int (*proxy_store_func)(const char *server, const char *mbox_pat,
			struct entryattlist *entryatts) = NULL;
static ptrarray_t message_entries = PTRARRAY_INITIALIZER;
static ptrarray_t mailbox_entries = PTRARRAY_INITIALIZER;
static ptrarray_t server_entries = PTRARRAY_INITIALIZER;

static void init_annotation_definitions(void);
static int annotation_set_tofile(annotate_state_t *state,
			         struct annotate_entry_list *entry);
static int annotation_set_todb(annotate_state_t *state,
			       struct annotate_entry_list *entry);
static int annotation_set_mailboxopt(annotate_state_t *state,
			             struct annotate_entry_list *entry);
static int annotation_set_pop3showafter(annotate_state_t *state,
			                struct annotate_entry_list *entry);
static int annotation_set_specialuse(annotate_state_t *state,
				     struct annotate_entry_list *entry);
static int _annotate_rewrite(const char *oldmboxname, uint32_t olduid,
			     const char *olduserid, const char *newmboxname,
			     uint32_t newuid, const char *newuserid,
			     int copy);
static int _annotate_may_store(annotate_state_t *state,
			       int is_shared,
			       const annotate_entrydesc_t *desc);

/* String List Management */
/*
 * Append 's' to the strlist 'l'.
 */
void appendstrlist(struct strlist **l, char *s)
{
    struct strlist **tail = l;

    while (*tail) tail = &(*tail)->next;

    *tail = (struct strlist *)xmalloc(sizeof(struct strlist));
    (*tail)->s = xstrdup(s);
    (*tail)->p = 0;
    (*tail)->next = 0;
}

/*
 * Append 's' to the strlist 'l', compiling it as a pattern.
 * Caller must pass in memory that is freed when the strlist is freed.
 */
void appendstrlistpat(struct strlist **l, char *s)
{
    struct strlist **tail = l;

    while (*tail) tail = &(*tail)->next;

    *tail = (struct strlist *)xmalloc(sizeof(struct strlist));
    (*tail)->s = s;
    (*tail)->p = charset_compilepat(s);
    (*tail)->next = 0;
}

/*
 * Free the strlist 'l'
 */
void freestrlist(struct strlist *l)
{
    struct strlist *n;

    while (l) {
	n = l->next;
	free(l->s);
	if (l->p) charset_freepat(l->p);
	free((char *)l);
	l = n;
    }
}

/* Attribute Management (also used by the ID command) */

/*
 * Append the 'attrib'/'value' pair to the attvaluelist 'l'.
 */
void appendattvalue(struct attvaluelist **l,
		    const char *attrib,
		    const struct buf *value)
{
    struct attvaluelist **tail = l;

    while (*tail) tail = &(*tail)->next;

    *tail = xzmalloc(sizeof(struct attvaluelist));
    (*tail)->attrib = xstrdup(attrib);
    buf_copy(&(*tail)->value, value);
}

/*
 * Duplicate the attvaluelist @src to @dst.
 */
void dupattvalues(struct attvaluelist **dst,
		  const struct attvaluelist *src)
{
    for ( ; src ; src = src->next)
	appendattvalue(dst, src->attrib, &src->value);
}

/*
 * Free the attvaluelist 'l'
 */
void freeattvalues(struct attvaluelist *l)
{
    struct attvaluelist *n;

    while (l) {
	n = l->next;
	free(l->attrib);
	buf_free(&l->value);
	free(l);
	l = n;
    }
}

/*
 * Append the 'entry'/'attvalues' pair to the entryattlist 'l'.
 */
void appendentryatt(struct entryattlist **l, const char *entry,
		    struct attvaluelist *attvalues)
{
    struct entryattlist **tail = l;

    while (*tail) tail = &(*tail)->next;

    *tail = (struct entryattlist *)xmalloc(sizeof(struct entryattlist));
    (*tail)->entry = xstrdup(entry);
    (*tail)->attvalues = attvalues;
    (*tail)->next = NULL;
}

void setentryatt(struct entryattlist **l, const char *entry,
		 const char *attrib, const struct buf *value)
{
    struct entryattlist *ee;

    for (ee = *l ; ee ; ee = ee->next) {
	if (!strcmp(ee->entry, entry))
	    break;
    }

    if (!ee) {
	struct attvaluelist *atts = NULL;
	appendattvalue(&atts, attrib, value);
	appendentryatt(l, entry, atts);
    }
    else {
	struct attvaluelist *av;
	for (av = ee->attvalues ; av ; av = av->next) {
	    if (!strcmp(av->attrib, attrib))
		break;
	}
	if (av)
	    buf_copy(&av->value, value);
	else
	    appendattvalue(&ee->attvalues, attrib, value);
    }
}

void clearentryatt(struct entryattlist **l, const char *entry,
		   const char *attrib)
{
    struct entryattlist *ea, **pea;
    struct attvaluelist *av, **pav;

    for (pea = l ; *pea ; pea = &(*pea)->next) {
	if (!strcmp((*pea)->entry, entry))
	    break;
    }
    ea = *pea;
    if (!ea)
	return;	/* entry not found */

    for (pav = &(*pea)->attvalues ; *pav ; pav = &(*pav)->next) {
	if (!strcmp((*pav)->attrib, attrib))
	    break;
    }
    av = *pav;
    if (!av)
	return;	/* attrib not found */

    /* detach and free attvaluelist */
    *pav = av->next;
    free(av->attrib);
    buf_free(&av->value);
    free(av);

    if (!ea->attvalues) {
	/* ->attvalues is now empty, so we can detach and free *pea too */
	*pea = ea->next;
	free(ea->entry);
	free(ea);
    }
}

/*
 * Duplicate the entryattlist @src to @dst.
 */
void dupentryatt(struct entryattlist **dst,
		 const struct entryattlist *src)
{
    for ( ; src ; src = src->next) {
	struct attvaluelist *attvalues = NULL;
	dupattvalues(&attvalues, src->attvalues);
	appendentryatt(dst, src->entry, attvalues);
    }
}

/*
 * Free the entryattlist 'l'
 */
void freeentryatts(struct entryattlist *l)
{
    struct entryattlist *n;

    while (l) {
	n = l->next;
	free(l->entry);
	freeattvalues(l->attvalues);
	free(l);
	l = n;
    }
}

/* must be called after cyrus_init */
void annotatemore_init(int (*fetch_func)(const char *, const char *,
					 const strarray_t *, const strarray_t *),
		       int (*store_func)(const char *, const char *,
					 struct entryattlist *))
{
    if (fetch_func) {
	proxy_fetch_func = fetch_func;
    }
    if (store_func) {
	proxy_store_func = store_func;
    }

    init_annotation_definitions();
}

/* detach the db_t from the global list */
static void detach_db(annotate_db_t *prev, annotate_db_t *d)
{
    if (prev)
	prev->next = d->next;
    else
	all_dbs_head = d->next;
    if (all_dbs_tail == d)
	all_dbs_tail = prev;
}

/* append the db_t to the global list */
static void append_db(annotate_db_t *d)
{
    if (all_dbs_tail)
	all_dbs_tail->next = d;
    else
	all_dbs_head = d;
    all_dbs_tail = d;
    d->next = NULL;
}

/*
 * Generate a new string containing the db filename
 * for the given @mboxname, (or the global db if
 * @mboxname is NULL).  Returns the new string in
 * *@fnamep.  Returns an error code.
 */
static int annotate_dbname_mbentry(const struct mboxlist_entry *mbentry,
				   char **fnamep)
{
    const char *conf_fname;

    if (mbentry) {
	/* per-mbox database */
	conf_fname = mboxname_metapath(mbentry->partition, mbentry->name,
				       META_ANNOTATIONS, /*isnew*/0);
	if (!conf_fname)
	    return IMAP_MAILBOX_BADNAME;
	*fnamep = xstrdup(conf_fname);
    }
    else {
	/* global database */
	conf_fname = config_getstring(IMAPOPT_ANNOTATION_DB_PATH);

	if (conf_fname)
	    *fnamep = xstrdup(conf_fname);
	else
	    *fnamep = strconcat(config_dir, FNAME_GLOBALANNOTATIONS, (char *)NULL);
    }

    return 0;
}

static int annotate_dbname(const char *mboxname, char **fnamep)
{
    int r = 0;
    struct mboxlist_entry *mbentry = NULL;

    if (mboxname) {
	r = mboxlist_lookup(mboxname, &mbentry, NULL);
	if (r) goto out;
    }

    r = annotate_dbname_mbentry(mbentry, fnamep);

out:
    mboxlist_entry_free(&mbentry);
    return r;
}

static int annotate_getdb(const char *mboxname,
			  unsigned int uid,
			  int dbflags,
			  annotate_db_t **dbp)
{
    annotate_db_t *d, *prev = NULL;
    char *fname = NULL;
    struct db *db;
    int r;

    *dbp = NULL;

    /*
     * The incoming (mboxname,uid) tuple tells us which scope we
     * need a database for.  Translate into the mboxname used to
     * key annotate_db_t's, which is slightly different: message
     * scope goes into a per-mailbox db, others in the global db.
     */
    if (!strcmpsafe(mboxname, NULL) /*server scope*/ ||
        !uid /* mailbox scope*/)
	mboxname = NULL;

    /* try to find an existing db for the mbox */
    for (d = all_dbs_head ; d ; prev = d, d = d->next) {
	if (!strcmpsafe(mboxname, d->mboxname)) {
	    /* found it, bump the refcount */
	    d->refcount++;
	    *dbp = d;
	    /*
	     * Splay the db_t to the end of the global list.
	     * This ensures the list remains in getdb() call
	     * order, and in particular that the dbs are
	     * committed in getdb() call order.  This is
	     * necessary to ensure safety should a commit fail
	     * while moving annotations between per-mailbox dbs
	     */
	    detach_db(prev, d);
	    append_db(d);
	    return 0;
	}
    }
    /* not found, open/create a new one */

    r = annotate_dbname(mboxname, &fname);
    if (r)
	goto error;
#if DEBUG
    syslog(LOG_ERR, "Opening annotations db %s\n", fname);
#endif

    r = DB->open(fname, dbflags, &db);
    if (r != 0) {
	if (!(dbflags & CYRUSDB_CREATE) && r == CYRUSDB_NOTFOUND)
	    goto error;
	syslog(LOG_ERR, "DBERROR: opening %s: %s",
			fname, cyrusdb_strerror(r));
	goto error;
    }

    /* record all the above */
    d = xzmalloc(sizeof(*d));
    d->refcount = 1;
    d->mboxname = (mboxname ? xstrdup(mboxname) : NULL);
    d->filename = fname;
    d->db = db;

    append_db(d);

    *dbp = d;
    return 0;

error:
    free(fname);
    *dbp = NULL;
    return r;
}

int annotate_getmailboxdb(const char *mboxname,
			  int dbflags,
			  annotate_db_t **dbp)
{
    /* synthetic UID '1' forces per-mailbox mode */
    return annotate_getdb(mboxname, 1, dbflags, dbp);
}

static void annotate_closedb(annotate_db_t *d)
{
    annotate_db_t *dx, *prev = NULL;
    int r;

    /* detach from the global list */
    for (dx = all_dbs_head ; dx && dx != d ; prev = dx, dx = dx->next)
	;
    assert(dx);
    assert(d == dx);
    detach_db(prev, d);

#if DEBUG
    syslog(LOG_ERR, "Closing annotations db %s\n", d->filename);
#endif

    r = DB->close(d->db);
    if (r)
	syslog(LOG_ERR, "DBERROR: error closing annotations %s: %s",
	       d->filename, cyrusdb_strerror(r));

    free(d->filename);
    free(d->mboxname);
    memset(d, 0, sizeof(*d));	/* JIC */
    free(d);
}

void annotate_putdb(annotate_db_t **dbp)
{
    annotate_db_t *d;

    if (!dbp || !(d = *dbp))
	return;
    assert(d->refcount > 0);
    if (--d->refcount == 0 && !in_txn)
	annotate_closedb(d);
    *dbp = NULL;
}

void annotatemore_open(void)
{
    int r;
    annotate_db_t *d = NULL;

    /* force opening the global annotations db */
    r = annotate_getdb(NULL, 0, CYRUSDB_CREATE, &d);
    if (r)
	fatal("can't open global annotations database", EC_TEMPFAIL);
}

void annotatemore_close(void)
{
    /* close all the open databases */
    while (all_dbs_head)
	annotate_closedb(all_dbs_head);
}

int annotatemore_begin(void)
{
    if (!all_dbs_head)
	return IMAP_INTERNAL;
    /* abort any dangling db-transactions */
    annotatemore_abort();
    in_txn = 1;			/* beginning of ann-transaction */
    return 0;
}

static void annotatemore_end(void)
{
    annotate_db_t *d, *next;

    /* perform delayed close of any db_t's kept
     * alive during an ann-transaction */
    for (d = all_dbs_head ; d ; d = next) {
	next = d->next;
	if (!d->refcount)
	    annotate_closedb(d);
    }
    in_txn = 0;			/* end of ann-transaction */
}

void annotatemore_abort(void)
{
    annotate_db_t *d;

    /* abort all open db-transactions */
    for (d = all_dbs_head ; d ; d = d->next) {
	if (d->txn) {
#if DEBUG
	    syslog(LOG_ERR, "Aborting annotations db %s\n", d->filename);
#endif
	    DB->abort(d->db, d->txn);
	}
	d->txn = NULL;
    }

    if (quota_txn)
	quota_abort(&quota_txn);

    annotatemore_end();
}

int annotatemore_commit(void)
{
    annotate_db_t *d;
    int r = 0;

    if (!all_dbs_head)
	return IMAP_INTERNAL;	/* no open dbs */
    if (!in_txn)
	return IMAP_INTERNAL;	/* not in an ann-transaction */

    /* commit any open db-transactions */
    for (d = all_dbs_head ; d ; d = d->next) {
	if (!d->txn)
	    continue;	/* no changes */

#if DEBUG
	syslog(LOG_ERR, "Committing annotations db %s\n", d->filename);
#endif

	r = DB->commit(d->db, d->txn);
	d->txn = NULL;
	if (r) {
	    annotatemore_abort();
	    return r;
	}
    }

    if (quota_txn)
	quota_commit(&quota_txn);

    annotatemore_end();
    return r;
}

void annotatemore_done(void)
{
    /* DB->done() handled by cyrus_done() */
}

static int make_key(const char *mboxname,
		    unsigned int uid,
		    const char *entry,
		    const char *userid,
		    char *key, size_t keysize)
{
    int keylen = 0;

    if (!uid) {
	strlcpy(key+keylen, mboxname, keysize-keylen);
	keylen += strlen(mboxname) + 1;
    }
    else {
	snprintf(key+keylen, keysize-keylen, "%u", uid);
	keylen += strlen(key+keylen) + 1;
    }
    strlcpy(key+keylen, entry, keysize-keylen);
    keylen += strlen(entry);
    /* if we don't have a userid, we're doing a foreach() */
    if (userid) {
	keylen++;
	strlcpy(key+keylen, userid, keysize-keylen);
	keylen += strlen(userid) + 1;
    }

    return keylen;
}

static int split_key(const annotate_db_t *d,
		     const char *key, int keysize,
		     const char **mboxnamep,
		     unsigned int *uidp,
		     const char **entryp,
		     const char **useridp)
{
#define NFIELDS 3
    const char *fields[NFIELDS];
    int nfields = 0;
    const char *p;
    unsigned int uid = 0;
    const char *mboxname = "";

    /* paranoia: ensure the last character in the key is
     * a NUL, which it should be because of the way we
     * always build keys */
    if (key[keysize-1])
	return IMAP_ANNOTATION_BADENTRY;
    keysize--;
    /*
     * paranoia: split the key into fields on NUL characters.
     * We would use strarray_nsplit() for this, except that
     * by design that function cannot split on NULs and does
     * not handle embedded NULs.
     */
    fields[nfields++] = key;
    for (p = key ; (p-key) < keysize ; p++) {
	if (!*p) {
	    if (nfields == NFIELDS)
		return IMAP_ANNOTATION_BADENTRY;
	    fields[nfields++] = p+1;
	}
    }
    if (nfields != NFIELDS)
	return IMAP_ANNOTATION_BADENTRY;

    if (d->mboxname) {
	/* per-folder db for message scope annotations */
	char *end = NULL;
	uid = strtoul(fields[0], &end, 10);
	if (uid == 0 || end == NULL || *end)
	    return IMAP_ANNOTATION_BADENTRY;
	mboxname = d->mboxname;
    }
    else {
	/* global db for mailnbox & server scope annotations */
	uid = 0;
	mboxname = fields[0];
    }

    if (mboxnamep) *mboxnamep = mboxname;
    if (uidp) *uidp = uid;
    if (entryp) *entryp = fields[1];
    if (useridp) *useridp = fields[2];
    return 0;
#undef NFIELDS
}

#if DEBUG
static const char *key_as_string(const annotate_db_t *d,
			         const char *key, int keylen)
{
    const char *mboxname, *entry, *userid;
    unsigned int uid;
    int r;
    static struct buf buf = BUF_INITIALIZER;

    buf_reset(&buf);
    r = split_key(d, key, keylen, &mboxname, &uid, &entry, &userid);
    if (r)
	buf_appendcstr(&buf, "invalid");
    else
	buf_printf(&buf, "{ mboxname=\"%s\" uid=%u entry=\"%s\" userid=\"%s\" }",
		   mboxname, uid, entry, userid);
    return buf_cstring(&buf);
}
#endif

static int split_attribs(const char *data, int datalen __attribute__((unused)),
			 struct buf *value)
{
    unsigned long tmp; /* for alignment */

    /* xxx use datalen? */
    /* xxx sanity check the data? */
    /*
     * Sigh...this is dumb.  We take care to be machine independent by
     * storing the length in network byte order...but the size of the
     * length field depends on whether we're running on a 32b or 64b
     * platform.
     */
    memcpy(&tmp, data, sizeof(unsigned long));
    data += sizeof(unsigned long); /* skip to value */

    buf_init_ro(value, data, ntohl(tmp));

    /*
     * In records written by older versions of Cyrus, there will be
     * binary encoded content-type and modifiedsince values after the
     * data.  We don't care about those anymore, so we just ignore them.
     */
    return 0;
}

struct find_rock {
    struct glob *mglob;
    struct glob *eglob;
    unsigned int uid;
    annotate_db_t *d;
    annotatemore_find_proc_t proc;
    void *rock;
};

static int find_p(void *rock, const char *key, int keylen,
		const char *data __attribute__((unused)),
		int datalen __attribute__((unused)))
{
    struct find_rock *frock = (struct find_rock *) rock;
    const char *mboxname, *entry, *userid;
    unsigned int uid;
    int r;

    r = split_key(frock->d, key, keylen, &mboxname,
		  &uid, &entry, &userid);
    if (r < 0)
	return 0;

    if (frock->uid && frock->uid != uid)
	return 0;
    if (GLOB_TEST(frock->mglob, mboxname) == -1)
	return 0;
    if (GLOB_TEST(frock->eglob, entry) == -1)
	return 0;
    return 1;
}

static int find_cb(void *rock, const char *key, int keylen,
		   const char *data, int datalen)
{
    struct find_rock *frock = (struct find_rock *) rock;
    const char *mboxname, *entry, *userid;
    unsigned int uid;
    struct buf value = BUF_INITIALIZER;
    int r;

#if DEBUG
    syslog(LOG_ERR, "find_cb: found key %s in %s",
	    key_as_string(frock->d, key, keylen), frock->d->filename);
#endif

    r = split_key(frock->d, key, keylen, &mboxname,
		  &uid, &entry, &userid);
    if (r)
	return r;

    r = split_attribs(data, datalen, &value);

    if (!r) r = frock->proc(mboxname, uid, entry, userid, &value, frock->rock);

    return r;
}

int annotatemore_findall(const char *mboxname,	/* internal */
			 unsigned int uid,
			 const char *entry,
			 annotatemore_find_proc_t proc,
			 void *rock)
{
    char key[MAX_MAILBOX_PATH+1], *p;
    int keylen, r;
    struct find_rock frock;

    assert(mboxname);
    assert(entry);
    frock.mglob = glob_init(mboxname, GLOB_HIERARCHY);
    frock.eglob = glob_init(entry, GLOB_HIERARCHY);
    GLOB_SET_SEPARATOR(frock.eglob, '/');
    frock.uid = uid;
    frock.proc = proc;
    frock.rock = rock;
    r = annotate_getdb(mboxname, uid, 0, &frock.d);
    if (r) {
	if (r == CYRUSDB_NOTFOUND)
	    r = 0;
	goto out;
    }

    /* Find fixed-string pattern prefix */
    keylen = make_key(mboxname, uid,
		      entry, NULL, key, sizeof(key));

    for (p = key; keylen; p++, keylen--) {
	if (*p == '*' || *p == '%') break;
    }
    keylen = p - key;

    r = DB->foreach(frock.d->db, key, keylen, &find_p, &find_cb,
		    &frock, tid(frock.d));

out:
    glob_free(&frock.mglob);
    glob_free(&frock.eglob);
    annotate_putdb(&frock.d);

    return r;
}

/***************************  Annotate State Management  ***************************/

annotate_state_t *annotate_state_new(void)
{
    annotate_state_t *state;

    state = xzmalloc(sizeof(*state));
    state->which = -1;	/* invalid scope */

    return state;
}

static void annotate_state_start(annotate_state_t *state)
{
    /* xxx better way to determine a size for this table? */
    construct_hash_table(&state->entry_table, 100, 1);
    construct_hash_table(&state->server_table, 10, 1);
}

static void annotate_state_finish(annotate_state_t *state)
{
    /* Free the entry list */
    while (state->entry_list) {
	struct annotate_entry_list *ee = state->entry_list;
	state->entry_list = ee->next;
	buf_free(&ee->shared);
	buf_free(&ee->priv);
	free(ee->name);
	free(ee);
    }

    free_hash_table(&state->entry_table, NULL);
    free_hash_table(&state->server_table, NULL);
}

int annotate_state_write_start(annotate_state_t *state)
{
    int r;

    r = quota_read(&state->quota, &quota_txn, 1);
    if (r == IMAP_QUOTAROOT_NONEXISTENT) {
	/* ensure we don't try to update it */
	state->quota.root = NULL;
	return 0;
    }
    if (r)
	return r;

    state->oldquota = state->quota;
    return 0;
}

int annotate_state_write_finish(annotate_state_t *state)
{
    if (!state->quota.root)
	return 0;   /* no quota applies */

    if (state->quota.useds[QUOTA_ANNOTSTORAGE] ==
        state->oldquota.useds[QUOTA_ANNOTSTORAGE])
	return 0;   /* no change */

    return quota_write(&state->quota, &quota_txn);
}

void annotate_state_free(annotate_state_t **statep)
{
    annotate_state_t *state = *statep;

    if (!state)
	return;

    annotate_state_finish(state);
    free(state);
    *statep = NULL;
}

static struct annotate_entry_list *
_annotate_state_add_entry(annotate_state_t *state,
		          const annotate_entrydesc_t *desc,
		          const char *name)
{
    struct annotate_entry_list *ee;

    ee = xzmalloc(sizeof(*ee));
    ee->name = xstrdup(name);
    ee->desc = desc;

    ee->next = state->entry_list;
    state->entry_list = ee;

    return ee;
}

void annotate_state_set_auth(annotate_state_t *state,
			     struct namespace *namespace,
		             int isadmin, const char *userid,
		             struct auth_state *auth_state)
{
    state->namespace = namespace;
    state->userid = userid;
    state->isadmin = isadmin;
    state->auth_state = auth_state;
}

void annotate_state_set_server(annotate_state_t *state)
{
    annotate_state_set_mailbox(state, NULL);
}

void annotate_state_set_mailbox(annotate_state_t *state,
				const char *mboxpat)
{
    if (!mboxpat || !mboxpat[0]) {
	state->which = ANNOTATION_SCOPE_SERVER;
	state->mboxpat = "";
	state->int_mboxname = "";
	state->quota.root = NULL;	/* no quota for server annots */
    }
    else {
	state->which = ANNOTATION_SCOPE_MAILBOX;
	state->mboxpat = mboxpat;
	state->int_mboxname = NULL;
	state->quota.root = NULL;	/* will be set later */
    }
    state->uid = 0;
    state->mbentry = NULL;
    state->acl = NULL;
}

void annotate_state_set_message(annotate_state_t *state,
				struct mailbox *mailbox,
				unsigned int uid)
{
    if (!uid) {
	if (!mailbox) {
	    annotate_state_set_server(state);
	    return;
	}
	state->which = ANNOTATION_SCOPE_MAILBOX;
    }
    else {
	state->which = ANNOTATION_SCOPE_MESSAGE;
    }

    state->mboxpat = mailbox->name;
    state->int_mboxname = mailbox->name;
    state->quota.root = mailbox->quotaroot;
    state->uid = uid;
    state->mbentry = NULL;
    state->acl = mailbox->acl;
}

/*
 * Common code used to apply a function to every mailbox which matches
 * a mailbox pattern, with an annotate_state_t* set up to point to the
 * mailbox (specifically, the .mbentry, .int_mboxname and .ext_mboxname
 * fields will all be set correctly).
 */

struct apply_rock {
    annotate_state_t *state;
    int (*proc)(annotate_state_t *);
    char lastname[MAX_MAILBOX_PATH+1];
    int sawuser;
};

static int apply_cb(char *name, int matchlen,
		    int maycreate __attribute__((unused)), void* rock)
{
    struct apply_rock *arock = (struct apply_rock *)rock;
    annotate_state_t *state = arock->state;
    int c;
    char int_mboxname[MAX_MAILBOX_BUFFER];
    char ext_mboxname[MAX_MAILBOX_BUFFER];
    int r;

    /* Suppress any output of a partial match */
    if (name[matchlen] && strncmp(arock->lastname, name, matchlen) == 0)
	return 0;

    /*
     * We can get a partial match for "user" multiple times with
     * other matches inbetween.  Handle it as a special case
     */
    if (matchlen == 4 && strncasecmp(name, "user", 4) == 0) {
	if (arock->sawuser)
	    return 0;
	arock->sawuser = 1;
    }

    strlcpy(arock->lastname, name, sizeof(arock->lastname));
    arock->lastname[matchlen] = '\0';

    if (!strncasecmp(arock->lastname, "INBOX", 5)) {
	state->namespace->mboxname_tointernal(state->namespace, "INBOX",
					      state->userid, int_mboxname);
	strlcat(int_mboxname, arock->lastname+5, sizeof(int_mboxname));
    }
    else
	strlcpy(int_mboxname, arock->lastname, sizeof(int_mboxname));

    c = name[matchlen];
    if (c) name[matchlen] = '\0';
    state->namespace->mboxname_toexternal(state->namespace, name,
					  state->userid, ext_mboxname);
    if (c) name[matchlen] = c;

    state->int_mboxname = int_mboxname;
    state->ext_mboxname = ext_mboxname;
    state->mbentry = NULL;

    r = 0;
    if (mboxlist_lookup(int_mboxname, &state->mbentry, NULL))
	goto out;

    r = arock->proc(state);

out:
    state->int_mboxname = NULL;
    state->ext_mboxname = NULL;
    state->quota.root = NULL;
    mboxlist_entry_free(&state->mbentry);

    return r;
}

static int annotate_apply_mailboxes(annotate_state_t *state,
				    int (*proc)(annotate_state_t *))
{
    struct apply_rock arock;
    char mboxpat[MAX_MAILBOX_BUFFER];
    int r = 0;

    memset(&arock, 0, sizeof(arock));
    arock.state = state;
    arock.proc = proc;

    /* copy the pattern so we can change hiersep */
    strlcpy(mboxpat, state->mboxpat, sizeof(mboxpat));
    mboxname_hiersep_tointernal(state->namespace, mboxpat,
				config_virtdomains ?
				strcspn(mboxpat, "@") : 0);

    r = state->namespace->mboxlist_findall(state->namespace, mboxpat,
					   state->isadmin, state->userid,
					   state->auth_state,
					   apply_cb, &arock);

    return r;
}

/***************************  Annotation Fetching  ***************************/

static void flush_entryatt(annotate_state_t *state)
{
    if (!state->attvalues)
	return;	    /* nothing to flush */

    state->callback(state->lastname,
		    state->lastuid,
		    state->lastentry,
		    state->attvalues,
		    state->callback_rock);
    freeattvalues(state->attvalues);
    state->attvalues = NULL;
}

/* Output a single entry and attributes for a single mailbox.
 * Shared and private annotations are output together by caching
 * the attributes until the mailbox and/or entry changes.
 *
 * The cache is reset by calling with a NULL mboxname or entry.
 * The last entry is flushed by calling with a NULL attrib.
 */
static void output_entryatt(annotate_state_t *state, const char *entry,
			    const char *userid, const struct buf *value)
{
    const char *mboxname;
    char key[MAX_MAILBOX_BUFFER]; /* XXX MAX_MAILBOX_NAME + entry + userid */
    struct buf buf = BUF_INITIALIZER;
    int vallen;
    char ext_mboxname[MAX_MAILBOX_BUFFER];

    /* We don't put any funny interpretations on NULL values for
     * some of these anymore, now that the dirty hacks are gone. */
    assert(state);
    assert(entry);
    assert(userid);
    assert(value);

    if (state->ext_mboxname)
	mboxname = state->ext_mboxname;
    else if (state->int_mboxname) {
	state->namespace->mboxname_toexternal(state->namespace,
					      state->int_mboxname,
					      state->userid,
					      ext_mboxname);
	mboxname = ext_mboxname;
    }
    else
	mboxname = "";
    /* @mboxname is now an external mailbox name */

    /* Check if this is a new entry.
     * If so, flush our current entry.
     */
    if (state->uid != state->lastuid ||
	strcmp(mboxname, state->lastname) ||
	strcmp(entry, state->lastentry))
	flush_entryatt(state);

    strlcpy(state->lastname, mboxname, sizeof(state->lastname));
    strlcpy(state->lastentry, entry, sizeof(state->lastentry));
    state->lastuid = state->uid;

    /* check if we already returned this entry */
    strlcpy(key, mboxname, sizeof(key));
    if (state->uid) {
	char uidbuf[32];
	snprintf(uidbuf, sizeof(uidbuf), "/UID%u/", state->uid);
	strlcat(key, uidbuf, sizeof(key));
    }
    strlcat(key, entry, sizeof(key));
    strlcat(key, userid, sizeof(key));
    if (hash_lookup(key, &state->entry_table)) return;
    hash_insert(key, (void *)0xDEADBEEF, &state->entry_table);

    vallen = value->len;
    if (state->sizeptr && state->maxsize < vallen) {
	/* too big - track the size of the largest */
	int *sp = state->sizeptr;
	if (*sp < vallen) *sp = vallen;
	return;
    }

    if (!userid[0]) { /* shared annotation */
	if ((state->attribs & ATTRIB_VALUE_SHARED)) {
	    appendattvalue(&state->attvalues, "value.shared", value);
	    state->found |= ATTRIB_VALUE_SHARED;
	}

	if ((state->attribs & ATTRIB_SIZE_SHARED)) {
	    buf_reset(&buf);
	    buf_printf(&buf, "%u", value->len);
	    appendattvalue(&state->attvalues, "size.shared", &buf);
	    state->found |= ATTRIB_SIZE_SHARED;
	}
    }
    else { /* private annotation */
	if ((state->attribs & ATTRIB_VALUE_PRIV)) {
	    appendattvalue(&state->attvalues, "value.priv", value);
	    state->found |= ATTRIB_VALUE_PRIV;
	}

	if ((state->attribs & ATTRIB_SIZE_PRIV)) {
	    buf_reset(&buf);
	    buf_printf(&buf, "%u", value->len);
	    appendattvalue(&state->attvalues, "size.priv", &buf);
	    state->found |= ATTRIB_SIZE_PRIV;
	}
    }
    buf_free(&buf);
}

/* Note that unlike store access control, fetch access control
 * is identical between shared and private annotations */
static int _annotate_may_fetch(annotate_state_t *state,
			       const annotate_entrydesc_t *desc)
{
    unsigned int my_rights;
    unsigned int needed = 0;
    const char *acl = NULL;

    /* If we got here without calling _set_auth() we're *NOT*
     * authorised! */
    if (!state->auth_state)
	return 0;

    /* Admins can do anything */
    if (state->isadmin)
	return 1;

    /* Some entries need to do their own access control */
    if ((desc->type & ATTRIB_NO_FETCH_ACL_CHECK))
	return 1;

    if (state->which == ANNOTATION_SCOPE_SERVER) {
	/* RFC5464 doesn't mention access control for server
	 * annotations, but this seems a sensible practice and is
	 * consistent with past Cyrus behaviour */
	return 1;
    }
    else if (state->which == ANNOTATION_SCOPE_MAILBOX) {
	assert(state->int_mboxname[0]);
	assert(state->mbentry);

	/* Make sure its a local mailbox annotation */
	if (state->mbentry->server)
	    return 0;

	acl = state->mbentry->acl;
	/* RFC5464 is a trifle vague about access control for mailbox
	 * annotations but this seems to be compliant */
	needed = ACL_LOOKUP|ACL_READ;
	/* fall through to ACL check */
    }
    else if (state->which == ANNOTATION_SCOPE_MESSAGE) {
	acl = state->acl;
	/* RFC5257: reading from a private annotation needs 'r'.
	 * Reading from a shared annotation needs 'r' */
	needed = ACL_READ;
	/* fall through to ACL check */
    }

    if (!acl)
	return 0;

    my_rights = cyrus_acl_myrights(state->auth_state, acl);

    return ((my_rights & needed) == needed);
}

static void annotation_get_fromfile(annotate_state_t *state,
				    struct annotate_entry_list *entry)
{
    const char *filename = (const char *) entry->desc->rock;
    char path[MAX_MAILBOX_PATH+1];
    struct buf value = BUF_INITIALIZER;
    FILE *f;

    snprintf(path, sizeof(path), "%s/msg/%s", config_dir, filename);
    if ((f = fopen(path, "r")) && buf_getline(&value, f)) {

	/* TODO: we need a buf_chomp() */
	if (value.s[value.len-1] == '\r')
	    buf_truncate(&value, value.len-1);
    }
    if (f) fclose(f);
    output_entryatt(state, entry->name, "", &value);
    buf_free(&value);
}

static void annotation_get_freespace(annotate_state_t *state,
				     struct annotate_entry_list *entry)
{
    unsigned long tavail;
    struct buf value = BUF_INITIALIZER;

    (void) find_free_partition(&tavail);
    buf_printf(&value, "%lu", tavail);
    output_entryatt(state, entry->name, "", &value);
    buf_free(&value);
}

static void annotation_get_server(annotate_state_t *state,
				  struct annotate_entry_list *entry)
{
    struct buf value = BUF_INITIALIZER;

    assert(state);
    assert(state->which == ANNOTATION_SCOPE_MAILBOX);
    assert(state->mbentry);

    /* Check ACL */
    /* Note that we use a weaker form of access control than
     * normal - we only check for ACL_LOOKUP and we don't refuse
     * access if the mailbox is not local */
    if (!state->mbentry->acl ||
        !(cyrus_acl_myrights(state->auth_state, state->mbentry->acl) & ACL_LOOKUP))
	goto out;

    if (state->mbentry->server)
	buf_appendcstr(&value, state->mbentry->server);

    output_entryatt(state, entry->name, "", &value);
out:
    buf_free(&value);
}

static void annotation_get_partition(annotate_state_t *state,
				     struct annotate_entry_list *entry)
{
    struct buf value = BUF_INITIALIZER;

    assert(state);
    assert(state->which == ANNOTATION_SCOPE_MAILBOX);
    assert(state->mbentry);

    /* Check ACL */
    if (!state->mbentry->acl ||
        !(cyrus_acl_myrights(state->auth_state, state->mbentry->acl) & ACL_LOOKUP))
	goto out;

    if (!state->mbentry->server)
	buf_appendcstr(&value, state->mbentry->partition);

    output_entryatt(state, entry->name, "", &value);
out:
    buf_free(&value);
}

static void annotation_get_size(annotate_state_t *state,
			        struct annotate_entry_list *entry)
{
    struct mailbox *mailbox = NULL;
    struct buf value = BUF_INITIALIZER;

    assert(state);
    assert(state->mbentry);

    if (mailbox_open_irl(state->int_mboxname, &mailbox))
	goto out;

    buf_printf(&value, QUOTA_T_FMT, mailbox->i.quota_mailbox_used);

    mailbox_close(&mailbox);

    output_entryatt(state, entry->name, "", &value);
out:
    buf_free(&value);
}

static void annotation_get_lastupdate(annotate_state_t *state,
				      struct annotate_entry_list *entry)
{
    struct stat sbuf;
    char valuebuf[RFC3501_DATETIME_MAX+1];
    struct buf value = BUF_INITIALIZER;
    char *fname;

    assert(state);
    assert(state->mbentry);

    fname = mboxname_metapath(state->mbentry->partition,
			      state->int_mboxname, META_INDEX, 0);
    if (!fname)
	goto out;
    if (stat(fname, &sbuf) == -1)
	goto out;

    time_to_rfc3501(sbuf.st_mtime, valuebuf, sizeof(valuebuf));
    buf_appendcstr(&value, valuebuf);

    output_entryatt(state, entry->name, "", &value);
out:
    buf_free(&value);
}

static void annotation_get_lastpop(annotate_state_t *state,
				   struct annotate_entry_list *entry)
{
    struct mailbox *mailbox = NULL;
    char valuebuf[RFC3501_DATETIME_MAX+1];
    struct buf value = BUF_INITIALIZER;

    assert(state);
    assert(state->mbentry);

    if (mailbox_open_irl(state->int_mboxname, &mailbox) != 0)
	goto out;

    if (mailbox->i.pop3_last_login) {
	time_to_rfc3501(mailbox->i.pop3_last_login, valuebuf,
			sizeof(valuebuf));
	buf_appendcstr(&value, valuebuf);
    }

    mailbox_close(&mailbox);

    output_entryatt(state, entry->name, "", &value);
out:
    buf_free(&value);
}

static void annotation_get_mailboxopt(annotate_state_t *state,
				      struct annotate_entry_list *entry)
{
    struct mailbox *mailbox = NULL;
    uint32_t flag = (unsigned long)entry->desc->rock;
    struct buf value = BUF_INITIALIZER;

    assert(state);
    assert(state->mbentry);
    assert(entry);
    assert(state->int_mboxname);

    if (mailbox_open_irl(state->int_mboxname, &mailbox) != 0)
	goto out;

    buf_appendcstr(&value,
		   (mailbox->i.options & flag ? "true" : "false"));

    mailbox_close(&mailbox);

    output_entryatt(state, entry->name, "", &value);
out:
    buf_free(&value);
}

static void annotation_get_pop3showafter(annotate_state_t *state,
				         struct annotate_entry_list *entry)
{
    struct mailbox *mailbox = NULL;
    char valuebuf[RFC3501_DATETIME_MAX+1];
    struct buf value = BUF_INITIALIZER;

    assert(state);
    assert(state->mbentry);
    assert(entry);
    assert(state->int_mboxname);

    if (mailbox_open_irl(state->int_mboxname, &mailbox) != 0)
	goto out;

    if (mailbox->i.pop3_show_after)
    {
	time_to_rfc3501(mailbox->i.pop3_show_after, valuebuf, sizeof(valuebuf));
	buf_appendcstr(&value, valuebuf);
    }

    mailbox_close(&mailbox);

    output_entryatt(state, entry->name, "", &value);
out:
    buf_free(&value);
}

static void annotation_get_specialuse(annotate_state_t *state,
				      struct annotate_entry_list *entry)
{
    struct buf value = BUF_INITIALIZER;

    assert(state);
    assert(state->mbentry);
    assert(state->int_mboxname);

    if (state->mbentry->specialuse)
	buf_appendcstr(&value, state->mbentry->specialuse);

    output_entryatt(state, entry->name, state->userid, &value);
    buf_free(&value);
}

static int rw_cb(const char *mailbox __attribute__((unused)),
		 uint32_t uid __attribute__((unused)),
		 const char *entry, const char *userid,
		 const struct buf *value, void *rock)
{
    annotate_state_t *state = (annotate_state_t *)rock;

    if (!userid[0] || !strcmp(userid, state->userid)) {
	output_entryatt(state, entry, userid, value);
    }

    return 0;
}

static void annotation_get_fromdb(annotate_state_t *state,
				  struct annotate_entry_list *entry)
{
    state->found = 0;

    annotatemore_findall(state->int_mboxname, state->uid, entry->name, &rw_cb, state);

    if (state->found != state->attribs &&
	(!strchr(entry->name, '%') && !strchr(entry->name, '*'))) {
	/* some results not found for an explicitly specified entry,
	 * make sure we emit explicit NILs */
	struct buf empty = BUF_INITIALIZER;
	if (!(state->found & (ATTRIB_VALUE_PRIV|ATTRIB_SIZE_PRIV)) &&
	    (state->attribs & (ATTRIB_VALUE_PRIV|ATTRIB_SIZE_PRIV))) {
	    /* store up value.priv and/or size.priv */
	    output_entryatt(state, entry->name, state->userid, &empty);
	}
	if (!(state->found & (ATTRIB_VALUE_SHARED|ATTRIB_SIZE_SHARED)) &&
	    (state->attribs & (ATTRIB_VALUE_SHARED|ATTRIB_SIZE_SHARED))) {
	    /* store up value.shared and/or size.shared */
	    output_entryatt(state, entry->name, "", &empty);
	}
	/* flush any stored attribute-value pairs */
	flush_entryatt(state);
    }
}

/* TODO: need to handle /<section-part>/ somehow */
static const annotate_entrydesc_t message_builtin_entries[] =
{
    {
	/* RFC5257 defines /altsubject with both .shared & .priv */
	"/altsubject",
	ATTRIB_TYPE_STRING,
	BACKEND_ONLY,
	ATTRIB_VALUE_SHARED | ATTRIB_VALUE_PRIV,
	0,
	annotation_get_fromdb,
	annotation_set_todb,
	NULL
    },{
	/* RFC5257 defines /comment with both .shared & .priv */
	"/comment",
	ATTRIB_TYPE_STRING,
	BACKEND_ONLY,
	ATTRIB_VALUE_SHARED | ATTRIB_VALUE_PRIV,
	0,
	annotation_get_fromdb,
	annotation_set_todb,
	NULL
    },{ NULL, 0, ANNOTATION_PROXY_T_INVALID, 0, 0, NULL, NULL, NULL }
};

static const annotate_entrydesc_t message_db_entry =
    {
	NULL,
	ATTRIB_TYPE_STRING,
	BACKEND_ONLY,
	ATTRIB_VALUE_SHARED | ATTRIB_VALUE_PRIV,
	0,
	annotation_get_fromdb,
	annotation_set_todb,
	NULL
    };

static const annotate_entrydesc_t mailbox_builtin_entries[] =
{
    {
	/*
	 * This entry was defined in the early ANNOTATMORE drafts but
	 * disappeared as of draft 13 and didn't make it into the final
	 * RFC.  We keep it around because it's not too hard to
	 * implement.
	 */
	"/check",
	ATTRIB_TYPE_BOOLEAN,
	BACKEND_ONLY,
	ATTRIB_VALUE_SHARED | ATTRIB_VALUE_PRIV,
	0,
	annotation_get_fromdb,
	annotation_set_todb,
	NULL
    },{
	/*
	 * This entry was defined in the early ANNOTATMORE drafts but
	 * disappeared as of draft 13 and didn't make it into the final
	 * RFC.  We keep it around because it's not too hard to
	 * implement.
	 */
	"/checkperiod",
	ATTRIB_TYPE_UINT,
	BACKEND_ONLY,
	ATTRIB_VALUE_SHARED | ATTRIB_VALUE_PRIV,
	0,
	annotation_get_fromdb,
	annotation_set_todb,
	NULL
    },{
	/* RFC5464 defines /shared/comment and /private/comment */
	"/comment",
	ATTRIB_TYPE_STRING,
	BACKEND_ONLY,
	ATTRIB_VALUE_SHARED | ATTRIB_VALUE_PRIV,
	0,
	annotation_get_fromdb,
	annotation_set_todb,
	NULL
    },{
	/*
	 * This entry was defined in the early ANNOTATMORE drafts but
	 * disappeared as of draft 13 and didn't make it into the final
	 * RFC.  We keep it around because it's not too hard to
	 * implement, even though we don't check the format.
	 */
	"/sort",
	ATTRIB_TYPE_STRING,
	BACKEND_ONLY,
	ATTRIB_VALUE_SHARED | ATTRIB_VALUE_PRIV,
	0,
	annotation_get_fromdb,
	annotation_set_todb,
	NULL
    },{
	/*
	 * RFC6154 defines /private/specialuse.  We incorrectly
	 * implement /shared semantics, as defined in the drafts but not
	 * the final RFC, by historical accident.
	 */
	"/specialuse",
	ATTRIB_TYPE_STRING,
	BACKEND_ONLY,
	ATTRIB_VALUE_PRIV,
	0,
	annotation_get_specialuse,
	annotation_set_specialuse,
	NULL
    },{
	/*
	 * This entry was defined in the early ANNOTATMORE drafts but
	 * disappeared as of draft 13 and didn't make it into the final
	 * RFC.  We keep it around because it's not too hard to
	 * implement, even though we don't check the format.
	 */
	"/thread",
	ATTRIB_TYPE_STRING,
	BACKEND_ONLY,
	ATTRIB_VALUE_SHARED | ATTRIB_VALUE_PRIV,
	0,
	annotation_get_fromdb,
	annotation_set_todb,
	NULL
    },{
	"/vendor/cmu/cyrus-imapd/duplicatedeliver",
	ATTRIB_TYPE_BOOLEAN,
	BACKEND_ONLY,
	ATTRIB_VALUE_SHARED,
	ACL_ADMIN,
	annotation_get_mailboxopt,
	annotation_set_mailboxopt,
	(void *)OPT_IMAP_DUPDELIVER
    },{
	"/vendor/cmu/cyrus-imapd/expire",
	ATTRIB_TYPE_UINT,
	BACKEND_ONLY,
	ATTRIB_VALUE_SHARED,
	ACL_ADMIN,
	annotation_get_fromdb,
	annotation_set_todb,
	NULL
    },{
	"/vendor/cmu/cyrus-imapd/lastpop",
	ATTRIB_TYPE_STRING,
	BACKEND_ONLY,
	ATTRIB_VALUE_SHARED,
	0,
	annotation_get_lastpop,
	/*set*/NULL,
	NULL
    },{
	"/vendor/cmu/cyrus-imapd/lastupdate",
	ATTRIB_TYPE_STRING,
	BACKEND_ONLY,
	ATTRIB_VALUE_SHARED,
	0,
	annotation_get_lastupdate,
	/*set*/NULL,
	NULL
    },{
	"/vendor/cmu/cyrus-imapd/news2mail",
	ATTRIB_TYPE_STRING,
	BACKEND_ONLY,
	ATTRIB_VALUE_SHARED,
	ACL_ADMIN,
	annotation_get_fromdb,
	annotation_set_todb,
	NULL
    },{
	"/vendor/cmu/cyrus-imapd/partition",
	/* _get_partition does its own access control check */
	ATTRIB_TYPE_STRING | ATTRIB_NO_FETCH_ACL_CHECK,
        BACKEND_ONLY,
	ATTRIB_VALUE_SHARED,
	0,
        annotation_get_partition,
	/*set*/NULL,
        NULL
    },{
	"/vendor/cmu/cyrus-imapd/pop3newuidl",
	ATTRIB_TYPE_BOOLEAN,
	BACKEND_ONLY,
	ATTRIB_VALUE_SHARED,
	ACL_ADMIN,
	annotation_get_mailboxopt,
	annotation_set_mailboxopt,
	(void *)OPT_POP3_NEW_UIDL
    },{
	"/vendor/cmu/cyrus-imapd/pop3showafter",
	ATTRIB_TYPE_STRING,
	BACKEND_ONLY,
	ATTRIB_VALUE_SHARED,
	ACL_ADMIN,
	annotation_get_pop3showafter,
	annotation_set_pop3showafter,
	NULL
    },{
	"/vendor/cmu/cyrus-imapd/server",
	/* _get_server does its own access control check */
	ATTRIB_TYPE_STRING | ATTRIB_NO_FETCH_ACL_CHECK,
	PROXY_ONLY,
	ATTRIB_VALUE_SHARED,
	0,
	annotation_get_server,
	/*set*/NULL,
	NULL
    },{
	"/vendor/cmu/cyrus-imapd/sharedseen",
	ATTRIB_TYPE_BOOLEAN,
	BACKEND_ONLY,
	ATTRIB_VALUE_SHARED,
	ACL_ADMIN,
	annotation_get_mailboxopt,
	annotation_set_mailboxopt,
        (void *)OPT_IMAP_SHAREDSEEN
    },{
	"/vendor/cmu/cyrus-imapd/sieve",
	ATTRIB_TYPE_STRING,
	BACKEND_ONLY,
	ATTRIB_VALUE_SHARED,
	ACL_ADMIN,
	annotation_get_fromdb,
	annotation_set_todb,
	NULL
    },{
	"/vendor/cmu/cyrus-imapd/size",
	ATTRIB_TYPE_STRING,
	BACKEND_ONLY,
	ATTRIB_VALUE_SHARED,
	0,
        annotation_get_size,
	/*set*/NULL,
	NULL
    },{
	"/vendor/cmu/cyrus-imapd/squat",
	ATTRIB_TYPE_BOOLEAN,
	BACKEND_ONLY,
	ATTRIB_VALUE_SHARED,
	ACL_ADMIN,
	annotation_get_fromdb,
	annotation_set_todb,
	NULL
    },{ NULL, 0, ANNOTATION_PROXY_T_INVALID, 0, 0, NULL, NULL, NULL }
};

static const annotate_entrydesc_t mailbox_db_entry =
    {
	NULL,
	ATTRIB_TYPE_STRING,
	BACKEND_ONLY,
	ATTRIB_VALUE_SHARED | ATTRIB_VALUE_PRIV,
	0,
	annotation_get_fromdb,
	annotation_set_todb,
	NULL
    };

static const annotate_entrydesc_t server_builtin_entries[] =
{
    {
	/* RFC5464 defines /shared/admin. */
	"/admin",
	ATTRIB_TYPE_STRING,
	PROXY_AND_BACKEND,
	ATTRIB_VALUE_SHARED,
	ACL_ADMIN,
	annotation_get_fromdb,
	annotation_set_todb,
	NULL
    },{
	/* RFC5464 defines /shared/comment. */
	"/comment",
	ATTRIB_TYPE_STRING,
	PROXY_AND_BACKEND,
	ATTRIB_VALUE_SHARED | ATTRIB_VALUE_PRIV,
	ACL_ADMIN,
	annotation_get_fromdb,
	annotation_set_todb,
	NULL
    },{
	/*
	 * This entry was defined in the early ANNOTATMORE drafts but
	 * disappeared as of draft 13 and didn't make it into the final
	 * RFC.  We keep it around because it's not too hard to
	 * implement.
	 */
	"/motd",
	ATTRIB_TYPE_STRING,
	PROXY_AND_BACKEND,
	ATTRIB_VALUE_SHARED,
	ACL_ADMIN,
	annotation_get_fromfile,
	annotation_set_tofile,
	(void *)"motd"
    },{
	"/vendor/cmu/cyrus-imapd/expire",
	ATTRIB_TYPE_UINT,
	PROXY_AND_BACKEND,
	ATTRIB_VALUE_SHARED,
	ACL_ADMIN,
	annotation_get_fromdb,
	annotation_set_todb,
	NULL
    },{
	"/vendor/cmu/cyrus-imapd/freespace",
	ATTRIB_TYPE_STRING,
	BACKEND_ONLY,
	ATTRIB_VALUE_SHARED,
	0,
	annotation_get_freespace,
	/*set*/NULL,
	NULL
    },{
	"/vendor/cmu/cyrus-imapd/shutdown",
	ATTRIB_TYPE_STRING,
	PROXY_AND_BACKEND,
	ATTRIB_VALUE_SHARED,
	ACL_ADMIN,
	annotation_get_fromfile,
	annotation_set_tofile,
	(void *)"shutdown"
    },{
	"/vendor/cmu/cyrus-imapd/squat",
	ATTRIB_TYPE_BOOLEAN,
	PROXY_AND_BACKEND,
	ATTRIB_VALUE_SHARED,
	ACL_ADMIN,
	annotation_get_fromdb,
	annotation_set_todb,
	NULL
    },{ NULL, 0, ANNOTATION_PROXY_T_INVALID,
	0, 0, NULL, NULL, NULL }
};

static const annotate_entrydesc_t server_db_entry =
    {
	NULL,
	ATTRIB_TYPE_STRING,
	PROXY_AND_BACKEND,
	ATTRIB_VALUE_SHARED | ATTRIB_VALUE_PRIV,
	0,
	annotation_get_fromdb,
	annotation_set_todb,
	NULL
    };

/* Annotation attributes and their flags */
struct annotate_attrib
{
    const char *name;
    int entry;
};

const struct annotate_attrib annotation_attributes[] =
{
    { "value", ATTRIB_VALUE_SHARED | ATTRIB_VALUE_PRIV },
    { "value.shared", ATTRIB_VALUE_SHARED },
    { "value.priv", ATTRIB_VALUE_PRIV },
    { "size", ATTRIB_SIZE_SHARED | ATTRIB_SIZE_PRIV },
    { "size.shared", ATTRIB_SIZE_SHARED },
    { "size.priv", ATTRIB_SIZE_PRIV },
    /*
     * The following attribute names appeared in the first drafts of the
     * ANNOTATEMORE extension but did not make it to the final RFC, or
     * even to draft 11 which we also officially support.  They might
     * appear in old annotation definition files, so we map them to
     * ATTRIB_DEPRECATED and issue a warning rather then remove them
     * entirely.
     */
    { "modifiedsince", ATTRIB_DEPRECATED },
    { "modifiedsince.shared", ATTRIB_DEPRECATED },
    { "modifiedsince.priv", ATTRIB_DEPRECATED },
    { "content-type", ATTRIB_DEPRECATED },
    { "content-type.shared", ATTRIB_DEPRECATED },
    { "content-type.priv", ATTRIB_DEPRECATED },
    { NULL, 0 }
};

static void _annotate_fetch_entries(annotate_state_t *state,
				    int proxy_check)
{
    struct annotate_entry_list *ee;

    /* Loop through the list of provided entries to get */
    for (ee = state->entry_list; ee; ee = ee->next) {

	if (proxy_check) {
	    if (ee->desc->proxytype == BACKEND_ONLY &&
	        proxy_fetch_func &&
		!config_getstring(IMAPOPT_PROXYSERVERS))
		continue;
	}

	if (!_annotate_may_fetch(state, ee->desc))
	    continue;

	ee->desc->get(state, ee);
    }
}

static int fetch_cb(annotate_state_t *state)
{
    struct mboxlist_entry *mbentry = state->mbentry;

    _annotate_fetch_entries(state, /*proxy_check*/0);

    if (proxy_fetch_func && state->orig_entry && mbentry->server &&
	!hash_lookup(mbentry->server, &state->server_table)) {
	/* xxx ignoring result */
	proxy_fetch_func(mbentry->server, state->orig_mailbox,
			 state->orig_entry, state->orig_attribute);
	hash_insert(mbentry->server, (void *)0xDEADBEEF, &state->server_table);
    }

    return 0;
}

int annotate_state_fetch(annotate_state_t *state,
		         const strarray_t *entries, const strarray_t *attribs,
		         annotate_fetch_cb_t callback, void *rock,
		         int *maxsizeptr)
{
    int i;
    struct glob *g;
    const ptrarray_t *non_db_entries;
    const annotate_entrydesc_t *db_entry;
    int r = 0;

    annotate_state_start(state);
    state->callback = callback;
    state->callback_rock = rock;
    if (maxsizeptr) {
	state->maxsize = *maxsizeptr; /* copy to check against */
        state->sizeptr = maxsizeptr; /* pointer to push largest back */
    }

    /* Build list of attributes to fetch */
    for (i = 0 ; i < attribs->count ; i++)
    {
	const char *s = attribs->data[i];
	int attribcount;

	/*
	 * TODO: this is bogus.  The * and % wildcard characters applied
	 * to attributes in the early drafts of the ANNOTATEMORE
	 * extension, but not in later drafts where those characters are
	 * actually illegal in attribute names.
	 */
	g = glob_init(s, GLOB_HIERARCHY);
	
	for (attribcount = 0;
	     annotation_attributes[attribcount].name;
	     attribcount++) {
	    if (GLOB_TEST(g, annotation_attributes[attribcount].name) != -1) {
		if (annotation_attributes[attribcount].entry & ATTRIB_DEPRECATED) {
		    if (strcmp(s, "*"))
			syslog(LOG_WARNING, "annotatemore_fetch: client used "
					    "deprecated attribute \"%s\", ignoring",
					    annotation_attributes[attribcount].name);
		}
		else
		    state->attribs |= annotation_attributes[attribcount].entry;
	    }
	}
	
	glob_free(&g);
    }

    if (!state->attribs)
	goto out;

    if (state->which == ANNOTATION_SCOPE_SERVER) {
	non_db_entries = &server_entries;
	db_entry = &server_db_entry;
    }
    else if (state->which == ANNOTATION_SCOPE_MAILBOX) {
	non_db_entries = &mailbox_entries;
	db_entry = &mailbox_db_entry;
    }
    else if (state->which == ANNOTATION_SCOPE_MESSAGE) {
	non_db_entries = &message_entries;
	db_entry = &message_db_entry;
    }
    else {
	r = IMAP_INTERNAL;
	goto out;
    }

    /* Build a list of callbacks for fetching the annotations */
    for (i = 0 ; i < entries->count ; i++)
    {
	const char *s = entries->data[i];
	int j;
	int check_db = 0; /* should we check the db for this entry? */

	g = glob_init(s, GLOB_HIERARCHY);
	GLOB_SET_SEPARATOR(g, '/');

	for (j = 0 ; j < non_db_entries->count ; j++) {
	    const annotate_entrydesc_t *desc = non_db_entries->data[j];

	    if (!desc->get)
		continue;

	    if (GLOB_TEST(g, desc->name) != -1) {
		/* Add this entry to our list only if it
		   applies to our particular server type */
		if ((desc->proxytype != PROXY_ONLY)
		    || proxy_fetch_func)
		    _annotate_state_add_entry(state, desc, desc->name);
	    }

	    if (!strcmp(s, desc->name)) {
		/* exact match */
		if (desc->proxytype != PROXY_ONLY) {
		    state->orig_entry = entries;  /* proxy it */
		}
		break;
	    }
	}

	if (j == non_db_entries->count) {
	    /* no [exact] match */
	    state->orig_entry = entries;  /* proxy it */
	    check_db = 1;
	}

	/* Add the db entry to our list if only if it
	   applies to our particular server type */
	if (check_db &&
	    ((db_entry->proxytype != PROXY_ONLY) || proxy_fetch_func)) {
	    /* Add the db entry to our list */
	    _annotate_state_add_entry(state, db_entry, s);
	}
	    
	glob_free(&g);
    }

    if (state->which == ANNOTATION_SCOPE_SERVER) {
	_annotate_fetch_entries(state, /*proxy_check*/1);
    }
    else if (state->which == ANNOTATION_SCOPE_MAILBOX) {

	if (state->entry_list || proxy_fetch_func) {

	    if (proxy_fetch_func && state->orig_entry) {
		state->orig_mailbox = state->mboxpat;
		state->orig_attribute = attribs;
	    }

	    annotate_apply_mailboxes(state, fetch_cb);
	}
    }
    else if (state->which == ANNOTATION_SCOPE_MESSAGE) {
	_annotate_fetch_entries(state, /*proxy_check*/0);
    }

    /* Flush last cached entry in output_entryatt() */
    flush_entryatt(state);

out:
    annotate_state_finish(state);
    return r;
}

/**************************  Annotation Storing  *****************************/

int annotatemore_lookup(const char *mboxname, const char *entry,
			const char *userid, struct buf *value)
{
    return annotatemore_msg_lookup(mboxname, /*uid*/0, entry, userid, value);
}

int annotatemore_msg_lookup(const char *mboxname, uint32_t uid, const char *entry,
			    const char *userid, struct buf *value)
{
    char key[MAX_MAILBOX_PATH+1];
    int keylen, datalen, r;
    const char *data;
    annotate_db_t *d = NULL;

    r = annotate_getdb(mboxname, uid, 0, &d);
    if (r)
	return (r == CYRUSDB_NOTFOUND ? 0 : r);

    keylen = make_key(mboxname, uid, entry, userid, key, sizeof(key));

    do {
	r = DB->fetch(d->db, key, keylen, &data, &datalen, tid(d));
    } while (r == CYRUSDB_AGAIN);

    if (!r && data) {
	r = split_attribs(data, datalen, value);
	if (!r) {
	    /* Force a copy, in case the putdb() call destroys
	     * the per-db data area that @data points to.  */
	    buf_cstring(value);
	}
    }
    else if (r == CYRUSDB_NOTFOUND) r = 0;

    annotate_putdb(&d);
    return r;
}

static int count_old_storage(annotate_db_t *d,
			     const char *key, int keylen,
			     quota_t *oldlenp)
{
    int r;
    int datalen;
    const char *data;
    struct buf val = BUF_INITIALIZER;

    *oldlenp = 0;
    do {
	r = DB->fetch(d->db, key, keylen, &data, &datalen, tid(d));
    } while (r == CYRUSDB_AGAIN);

    if (r == CYRUSDB_NOTFOUND) {
	r = 0;
	goto out;
    }
    if (r || !data)
	goto out;

    r = split_attribs(data, datalen, &val);
    if (r)
	goto out;
    *oldlenp = val.len;

out:
    buf_free(&val);
    return r;
}

static int write_entry(const char *mboxname,
		       unsigned int uid,
		       const char *entry,
		       const char *userid,
		       const struct buf *value,
		       struct quota *quota)
{
    char key[MAX_MAILBOX_PATH+1];
    int keylen, r;
    annotate_db_t *d = NULL;
    quota_t oldlen = 0;

    /* must be in a transaction to modify the db */
    if (!in_txn)
	return IMAP_INTERNAL;

    r = annotate_getdb(mboxname, uid, CYRUSDB_CREATE, &d);
    if (r)
	return r;

    keylen = make_key(mboxname, uid, entry, userid, key, sizeof(key));

    if (quota && quota->root) {
	r = count_old_storage(d, key, keylen, &oldlen);
	if (r)
	    goto out;
	r = quota_check(quota, QUOTA_ANNOTSTORAGE, value->len - oldlen);
	if (r)
	    goto out;
    }

    if (value->s == NULL) {

#if DEBUG
	syslog(LOG_ERR, "write_entry: deleting key %s from %s",
		key_as_string(d, key, keylen), d->filename);
#endif

	do {
	    r = DB->delete(d->db, key, keylen, tid(d), 0);
	} while (r == CYRUSDB_AGAIN);
    }
    else {
	struct buf data = BUF_INITIALIZER;
	unsigned long l;
	static const char contenttype[] = "text/plain"; /* fake */

	l = htonl(value->len);
	buf_appendmap(&data, (const char *)&l, sizeof(l));

	buf_appendmap(&data, value->s, value->len);
	buf_putc(&data, '\0');

	/*
	 * Older versions of Cyrus expected content-type and
	 * modifiedsince fields after the value.  We don't support those
	 * but we write out default values just in case the database
	 * needs to be read by older versions of Cyrus
	 */
	buf_appendcstr(&data, contenttype);
	buf_putc(&data, '\0');

	l = 0;	/* fake modifiedsince */
	buf_appendmap(&data, (const char *)&l, sizeof(l));

#if DEBUG
	syslog(LOG_ERR, "write_entry: storing key %s to %s",
		key_as_string(d, key, keylen), d->filename);
#endif

	do {
	    r = DB->store(d->db, key, keylen, data.s, data.len, tid(d));
	} while (r == CYRUSDB_AGAIN);
	buf_free(&data);
    }

    if (*mboxname)
	sync_log_mailbox(mboxname);
    else
	sync_log_annotation(mboxname);

    if (quota && quota->root)
	quota_use(quota, QUOTA_ANNOTSTORAGE, value->len - oldlen);

out:
    annotate_putdb(&d);

    return r;
}

int annotate_state_write(annotate_state_t *state,
			 const char *entry,
			 const char *userid,
			 const struct buf *value)
{
    return write_entry(state->int_mboxname, state->uid,
		       entry, userid, value, &state->quota);
}

static int annotate_canon_value(struct buf *value, int type)
{
    char *p = NULL;

    /* check for NIL */
    if (value->s == NULL)
	return 0;

    switch (type) {
    case ATTRIB_TYPE_STRING:
	/* free form */
	break;

    case ATTRIB_TYPE_BOOLEAN:
	/* make sure its "true" or "false" */
	if (value->len == 4 && !strncasecmp(value->s, "true", 4)) {
	    buf_reset(value);
	    buf_appendcstr(value, "true");
	    buf_cstring(value);
	}
	else if (value->len == 5 && !strncasecmp(value->s, "false", 5)) {
	    buf_reset(value);
	    buf_appendcstr(value, "false");
	    buf_cstring(value);
	}
	else return IMAP_ANNOTATION_BADVALUE;
	break;

    case ATTRIB_TYPE_UINT:
	/* make sure its a valid ulong ( >= 0 ) */
	errno = 0;
	strtoul(value->s, &p, 10);
	if ((p == value->s)		/* no value */
	    || (*p != '\0')		/* illegal char */
	    || (unsigned)(p - value->s) != value->len
					/* embedded NUL */
	    || errno			/* overflow */
	    || strchr(value->s, '-')) {	/* negative number */
	    return IMAP_ANNOTATION_BADVALUE;
	}
	break;

    case ATTRIB_TYPE_INT:
	/* make sure its a valid long */
	errno = 0;
	strtol(value->s, &p, 10);
	if ((p == value->s)		/* no value */
	    || (*p != '\0')		/* illegal char */
	    || (unsigned)(p - value->s) != value->len
					/* embedded NUL */
	    || errno) {			/* underflow/overflow */
	    return IMAP_ANNOTATION_BADVALUE;
	}
	break;

    default:
	/* unknown type */
	return IMAP_ANNOTATION_BADVALUE;
    }

    return 0;
}

static int _annotate_store_entries(annotate_state_t *state)
{
    struct annotate_entry_list *ee;
    int r;

    /* Loop through the list of provided entries to get */
    for (ee = state->entry_list ; ee ; ee = ee->next) {

	if (ee->have_shared &&
	    !_annotate_may_store(state, /*shared*/1, ee->desc))
	    return IMAP_PERMISSION_DENIED;

	if (ee->have_priv &&
	    !_annotate_may_store(state, /*shared*/0, ee->desc))
	    return IMAP_PERMISSION_DENIED;

	r = ee->desc->set(state, ee);
	if (r)
	    return r;
    }
    return 0;
}

static int store_cb(annotate_state_t *state)
{
    struct mboxlist_entry *mbentry = state->mbentry;
    char *quotaroot = NULL;
    int r = 0;

    state->quota.root = NULL;
    if (!mbentry->server) {
	/* local mailbox, so lookup the quotaroot */
	struct mailbox *mailbox = NULL;

	r = mailbox_open_irl(state->int_mboxname, &mailbox);
	if (r)
	    goto cleanup;
	if (mailbox->quotaroot)
	    quotaroot = xstrdup(mailbox->quotaroot);
	mailbox_close(&mailbox);

	state->quota.root = quotaroot;
	r = annotate_state_write_start(state);
	if (r)
	    goto cleanup;
    }

    r = _annotate_store_entries(state);
    if (r)
	goto cleanup;

    state->count++;

    if (proxy_store_func && mbentry->server &&
	!hash_lookup(mbentry->server, &state->server_table)) {
	hash_insert(mbentry->server, (void *)0xDEADBEEF, &state->server_table);
    }

    r = annotate_state_write_finish(state);

 cleanup:
    free(quotaroot);
    return r;
}

struct proxy_rock {
    const char *mbox_pat;
    struct entryattlist *entryatts;
};

static void store_proxy(const char *server, void *data __attribute__((unused)),
			void *rock)
{
    struct proxy_rock *prock = (struct proxy_rock *) rock;

    proxy_store_func(server, prock->mbox_pat, prock->entryatts);
}

static int _annotate_may_store(annotate_state_t *state,
			       int is_shared,
			       const annotate_entrydesc_t *desc)
{
    unsigned int my_rights;
    unsigned int needed = 0;
    const char *acl = NULL;

    /* If we got here without calling _set_auth() we're *NOT*
     * authorised! */
    if (!state->auth_state)
	return 0;

    /* Admins can do anything */
    if (state->isadmin)
	return 1;

    if (state->which == ANNOTATION_SCOPE_SERVER) {
	/* RFC5464 doesn't mention access control for server
	 * annotations, but this seems a sensible practice and is
	 * consistent with past Cyrus behaviour */
	return !is_shared;
    }
    else if (state->which == ANNOTATION_SCOPE_MAILBOX) {
	assert(state->int_mboxname[0]);
	assert(state->mbentry);

	/* Make sure its a local mailbox annotation */
	if (state->mbentry->server)
	    return 0;

	acl = state->mbentry->acl;
	/* RFC5464 is a trifle vague about access control for mailbox
	 * annotations but this seems to be compliant */
	needed = ACL_LOOKUP;
	if (is_shared)
	    needed |= ACL_READ|ACL_WRITE|desc->extra_rights;
	/* fall through to ACL check */
    }
    else if (state->which == ANNOTATION_SCOPE_MESSAGE) {
	acl = state->acl;
	/* RFC5257: writing to a private annotation needs 'r'.
	 * Writing to a shared annotation needs 'n' */
	needed = (is_shared ? ACL_ANNOTATEMSG : ACL_READ);
	/* fall through to ACL check */
    }

    if (!acl)
	return 0;

    my_rights = cyrus_acl_myrights(state->auth_state, acl);

    return ((my_rights & needed) == needed);
}

static int annotation_set_tofile(annotate_state_t *state
				    __attribute__((unused)),
				 struct annotate_entry_list *entry)
{
    const char *filename = (const char *)entry->desc->rock;
    char path[MAX_MAILBOX_PATH+1];
    int r;
    FILE *f;

    snprintf(path, sizeof(path), "%s/msg/%s", config_dir, filename);

    /* XXX how do we do this atomically with other annotations? */
    if (entry->shared.s == NULL)
	return unlink(path);
    else {
	r = cyrus_mkdir(path, 0755);
	if (r)
	    return r;
	f = fopen(path, "w");
	if (!f) {
	    syslog(LOG_ERR, "cannot open %s for writing: %m", path);
	    return IMAP_IOERROR;
	}
	fwrite(entry->shared.s, 1, entry->shared.len, f);
	fputc('\n', f);
	return fclose(f);
    }

    return IMAP_IOERROR;
}

static int annotation_set_todb(annotate_state_t *state,
			       struct annotate_entry_list *entry)
{
    int r = 0;

    if (entry->have_shared)
	r = write_entry(state->int_mboxname, state->uid,
			entry->name, "",
			&entry->shared,
			&state->quota);
    if (!r && entry->have_priv)
	r = write_entry(state->int_mboxname, state->uid,
			entry->name, state->userid,
			&entry->priv,
			&state->quota);

    return r;
}

static int annotation_set_mailboxopt(annotate_state_t *state,
			             struct annotate_entry_list *entry)
{
    struct mailbox *mailbox = NULL;
    uint32_t flag = (unsigned long)entry->desc->rock;
    int r = 0;
    unsigned long newopts;

    r = mailbox_open_iwl(state->int_mboxname, &mailbox);
    if (r) return r;

    newopts = mailbox->i.options;

    if (entry->shared.s &&
	!strcmp(entry->shared.s, "true")) {
	newopts |= flag;
    } else {
	newopts &= ~flag;
    }

    /* only commit if there's been a change */
    if (mailbox->i.options != newopts) {
	mailbox_index_dirty(mailbox);
	mailbox->i.options = newopts;
    }

    mailbox_close(&mailbox);

    return 0;
}

static int annotation_set_pop3showafter(annotate_state_t *state,
				        struct annotate_entry_list *entry)
{
    struct mailbox *mailbox = NULL;
    int r = 0;
    time_t date;

    if (entry->shared.s == NULL) {
	/* Effectively removes the annotation */
	date = 0;
    }
    else {
	r = time_from_rfc3501(buf_cstring(&entry->shared), &date);
	if (r < 0)
	    return IMAP_PROTOCOL_BAD_PARAMETERS;
    }

    r = mailbox_open_iwl(state->int_mboxname, &mailbox);
    if (r) return r;

    if (date != mailbox->i.pop3_show_after) {
	mailbox->i.pop3_show_after = date;
	mailbox_index_dirty(mailbox);
    }

    mailbox_close(&mailbox);

    return 0;
}

static int annotation_set_specialuse(annotate_state_t *state,
				     struct annotate_entry_list *entry)
{
    int r = 0;
    const char *val;
    int i;
    strarray_t * specialuse_extra = 0;
    static const char * const valid_specialuse[] = {
    /*   "\\All",  -- we don't support virtual folders right now */
      "\\Archive",
      "\\Drafts",
    /*  "\\Flagged",  -- we don't support virtual folders right now */
      "\\Junk",
      "\\Sent",
      "\\Trash",
      NULL
    };

    /* can only set specialuse on your own mailboxes */
    if (!mboxname_userownsmailbox(state->userid, state->int_mboxname))
	return IMAP_PERMISSION_DENIED;

    if (entry->priv.s == NULL) {
	/* Effectively removes the annotation */
	val = NULL;
    }
    else {
	for (i = 0; valid_specialuse[i]; i++) {
	    if (!strcasecmp(valid_specialuse[i], buf_cstring(&entry->priv)))
		break;
	    /* or without the leading '\' */
	    if (!strcasecmp(valid_specialuse[i]+1, buf_cstring(&entry->priv)))
		break;
	}
	val = valid_specialuse[i];

	/* If not a built in one, check specialuse_extra option */
	if (!val) {
	    const char * specialuse_extra_opt = config_getstring(IMAPOPT_SPECIALUSE_EXTRA);
	    if (specialuse_extra_opt) {
		specialuse_extra = strarray_split(specialuse_extra_opt, NULL);

		for (i = 0; i < specialuse_extra->count; i++) {
		    const char * extra_val = strarray_nth(specialuse_extra, i);
		    if (!strcasecmp(extra_val, buf_cstring(&entry->priv))) {
			/* strarray owns string, keep specialuse_extra until after set call */
			val = extra_val;
			break;
		    }
		}
	    }
	}

	if (!val) {
	    r = IMAP_ANNOTATION_BADVALUE;
	    goto done;
	}
    }

    r = mboxlist_setspecialuse(state->int_mboxname, val);

done:
    strarray_free(specialuse_extra);

    return r;
}

static int find_desc_store(int scope,
			   const char *name,
			   const annotate_entrydesc_t **descp)
{
    const ptrarray_t *descs;
    const annotate_entrydesc_t *db_entry;
    annotate_entrydesc_t *desc;
    int i;

    if (scope == ANNOTATION_SCOPE_SERVER) {
	descs = &server_entries;
	db_entry = &server_db_entry;
    }
    else if (scope == ANNOTATION_SCOPE_MAILBOX) {
	descs = &mailbox_entries;
	db_entry = &mailbox_db_entry;
    }
    else if (scope == ANNOTATION_SCOPE_MESSAGE) {
	descs = &message_entries;
	db_entry = &message_db_entry;
    }
    else
	return IMAP_INTERNAL;

    for (i = 0 ; i < descs->count ; i++) {
	desc = descs->data[i];
	if (strcmp(name, desc->name))
	    continue;
	if (!desc->set) {
	    /* read-only annotation */
	    return IMAP_PERMISSION_DENIED;
	}
	*descp = desc;
	return 0;
    }

    /* unknown annotation */
    if (!config_getswitch(IMAPOPT_ANNOTATION_ALLOW_UNDEFINED))
	return IMAP_PERMISSION_DENIED;

    /* check for /flags and /vendor/cyrus */
    if (scope == ANNOTATION_SCOPE_MESSAGE &&
	!strncmp(name, "/flags/", 7))
	return IMAP_PERMISSION_DENIED;

    if (!strncmp(name, "/vendor/cmu/cyrus-imapd/", 24))
	return IMAP_PERMISSION_DENIED;

    *descp = db_entry;
    return 0;
}

int annotate_state_store(annotate_state_t *state, struct entryattlist *l)
{
    int r = 0;
    struct entryattlist *e = l;
    struct attvaluelist *av;

    annotate_state_start(state);

    /* Build a list of callbacks for storing the annotations */
    while (e) {
	int attribs;
	const annotate_entrydesc_t *desc = NULL;
	struct annotate_entry_list *nentry = NULL;

	/* See if we support this entry */
	r = find_desc_store(state->which, e->entry, &desc);
	if (r)
	    goto cleanup;

	/* Add this entry to our list only if it
	   applies to our particular server type */
	if ((desc->proxytype != PROXY_ONLY)
	    || proxy_store_func)
	    nentry = _annotate_state_add_entry(state, desc, e->entry);

	/* See if we are allowed to set the given attributes. */
	attribs = desc->attribs;
	av = e->attvalues;
	while (av) {
	    if (!strcmp(av->attrib, "value.shared")) {
		if (!(attribs & ATTRIB_VALUE_SHARED)) {
		    r = IMAP_PERMISSION_DENIED;
		    goto cleanup;
		}
		r = annotate_canon_value(&av->value,
					 desc->type);
		if (r)
		    goto cleanup;
		if (nentry) {
		    buf_init_ro(&nentry->shared, av->value.s, av->value.len);
		    nentry->have_shared = 1;
		}
	    }
	    else if (!strcmp(av->attrib, "content-type.shared") ||
	             !strcmp(av->attrib, "content-type.priv")) {
		syslog(LOG_WARNING, "annotatemore_store: client used "
				    "deprecated attribute \"%s\", ignoring",
				    av->attrib);
	    }
	    else if (!strcmp(av->attrib, "value.priv")) {
		if (!(attribs & ATTRIB_VALUE_PRIV)) {
		    r = IMAP_PERMISSION_DENIED;
		    goto cleanup;
		}
		r = annotate_canon_value(&av->value,
					 desc->type);
		if (r)
		    goto cleanup;
		if (nentry) {
		    buf_init_ro(&nentry->priv, av->value.s, av->value.len);
		    nentry->have_priv = 1;
		}
	    }
	    else {
		r = IMAP_PERMISSION_DENIED;
		goto cleanup;
	    }

	    av = av->next;
	}

	e = e->next;
    }

    if (state->which == ANNOTATION_SCOPE_SERVER) {
	r = _annotate_store_entries(state);
    }

    else if (state->which == ANNOTATION_SCOPE_MAILBOX) {

	r = annotate_apply_mailboxes(state, store_cb);

	if (!r && !state->count) r = IMAP_MAILBOX_NONEXISTENT;

	if (proxy_store_func) {
	    if (!r) {
		/* proxy command to backends */
		struct proxy_rock prock = { NULL, NULL };
		prock.mbox_pat = state->mboxpat;
		prock.entryatts = l;
		hash_enumerate(&state->server_table, store_proxy, &prock);
	    }
	}
    }
    else if (state->which == ANNOTATION_SCOPE_MESSAGE) {

	r = annotate_state_write_start(state);
	if (r)
	    goto cleanup;

	r = _annotate_store_entries(state);
	if (r)
	    goto cleanup;

	r = annotate_state_write_finish(state);
	if (r)
	    goto cleanup;
    }

    if (r)
	annotatemore_abort();

cleanup:
    annotate_state_finish(state);
    return r;
}

struct rename_rock {
    const char *oldmboxname;
    const char *newmboxname;
    const char *olduserid;
    const char *newuserid;
    uint32_t olduid;
    uint32_t newuid;
    int copy;
};

static int rename_cb(const char *mailbox,
		     uint32_t uid __attribute__((unused)),
		     const char *entry,
		     const char *userid, const struct buf *value,
		     void *rock)
{
    struct rename_rock *rrock = (struct rename_rock *) rock;
    int r = 0;

    if (rrock->newmboxname) {
	/* create newly renamed entry */
	const char *newuserid = userid;

	if (rrock->olduserid && rrock->newuserid &&
	    !strcmp(rrock->olduserid, userid)) {
	    /* renaming a user, so change the userid for priv annots */
	    newuserid = rrock->newuserid;
	}
	r = write_entry(rrock->newmboxname, rrock->newuid, entry, newuserid, value, NULL);
    }

    if (!rrock->copy && !r) {
	/* delete existing entry */
	struct buf dattrib = BUF_INITIALIZER;
	r = write_entry(mailbox, uid, entry, userid, &dattrib, NULL);
    }

    return r;
}

int annotatemore_rename(const char *oldmboxname, const char *newmboxname,
			const char *olduserid, const char *newuserid)
{
    int r;

    /* rewrite any per-folder annotations from the global db */
    r = annotatemore_begin();
    if (r)
	return r;

    r = _annotate_rewrite(oldmboxname, 0, olduserid,
			  newmboxname, 0, newuserid,
			  /*copy*/0);

    /*
     * The per-folder database got moved or linked by mailbox_copy_files().
     */

    if (r)
	annotatemore_abort();
    else
	r = annotatemore_commit();

    return r;
}

static int _annotate_rewrite(const char *oldmboxname,
			     uint32_t olduid,
			     const char *olduserid,
			     const char *newmboxname,
			     uint32_t newuid,
			     const char *newuserid,
			     int copy)
{
    struct rename_rock rrock;
    int r;

    rrock.oldmboxname = oldmboxname;
    rrock.newmboxname = newmboxname;
    rrock.olduserid = olduserid;
    rrock.newuserid = newuserid;
    rrock.olduid = olduid;
    rrock.newuid = newuid;
    rrock.copy = copy;

    r = annotatemore_findall(oldmboxname, olduid, "*", &rename_cb, &rrock);

    if (r)
	annotatemore_abort();

    return r;
}

int annotatemore_delete(const struct mboxlist_entry *mbentry)
{
    int r;
    char *fname = NULL;

    assert(mbentry);

    /* remove any per-folder annotations from the global db */
    r = annotatemore_begin();
    if (r)
	goto out;

    r = _annotate_rewrite(mbentry->name, /*olduid*/0, /*olduserid*/NULL,
			 /*newmboxname*/NULL, /*newuid*/0, /*newuserid*/NULL,
			 /*copy*/0);
    if (r)
	goto out;

    /* remove the entire per-folder database */
    r = annotate_dbname_mbentry(mbentry, &fname);
    if (r)
	goto out;

    if (unlink(fname) < 0 && errno != ENOENT) {
	syslog(LOG_ERR, "cannot unlink %s: %m", fname);
    }

    r = annotatemore_commit();

out:
    free(fname);
    if (r)
	annotatemore_abort();
    return r;
}

int annotate_msg_copy(const char *oldmboxname, uint32_t olduid,
		      const char *newmboxname, uint32_t newuid,
		      const char *userid)
{
    return _annotate_rewrite(oldmboxname, olduid, userid,
			     newmboxname, newuid, userid,
			     /*copy*/1);
}

/*************************  Annotation Initialization  ************************/

/* The following code is courtesy of Thomas Viehmann <tv@beamnet.de> */


const struct annotate_attrib annotation_scope_names[] =
{
    { "server", ANNOTATION_SCOPE_SERVER },
    { "mailbox", ANNOTATION_SCOPE_MAILBOX },
    { "message", ANNOTATION_SCOPE_MESSAGE },
    { NULL, 0 }
};

const struct annotate_attrib annotation_proxy_type_names[] =
{
    { "proxy", PROXY_ONLY },
    { "backend", BACKEND_ONLY },
    { "proxy_and_backend", PROXY_AND_BACKEND },
    { NULL, 0 }
};

const struct annotate_attrib attribute_type_names[] = 
{
    /*
     * The "content-type" type was only used for protocol features which
     * were dropped before the RFCs became final.  We accept it in
     * annotation definition files only for backwards compatibility with
     * earlier Cyrus versions.
     */
    { "content-type", ATTRIB_TYPE_STRING },
    { "string", ATTRIB_TYPE_STRING },
    { "boolean", ATTRIB_TYPE_BOOLEAN },
    { "uint", ATTRIB_TYPE_UINT },
    { "int", ATTRIB_TYPE_INT },
    { NULL, 0 }
};

#define ANNOT_DEF_MAXLINELEN 1024
#define ANNOT_MAX_ERRORS    64

struct parse_state
{
    const char *filename;
    const char *context;
    unsigned int lineno;
    unsigned int nerrors;
    tok_t tok;
};

static void parse_error(struct parse_state *state, const char *err)
{
    if (++state->nerrors < ANNOT_MAX_ERRORS)
    {
	struct buf msg = BUF_INITIALIZER;

	buf_printf(&msg, "%s:%u:%u:error: %s",
		   state->filename, state->lineno,
		   tok_offset(&state->tok), err);
	if (state->context && *state->context)
	    buf_printf(&msg, ", at or near '%s'", state->context);
	syslog(LOG_ERR, "%s", buf_cstring(&msg));
	buf_free(&msg);
    }

    state->context = NULL;
}

/* Search in table for the value given by @name and return
 * the corresponding enum value, or -1 on error.
 * @state and @errmsg is used to hint the user where we failed.
 */
static int table_lookup(const struct annotate_attrib *table,
		        const char *name)
{
    for ( ; table->name ; table++) {
	 if (!strcasecmp(table->name, name))
	    return table->entry;
    }
    return -1;
}


/*
 * Parse and return the next token from the line buffer.  Tokens are
 * separated by comma ',' characters but leading and trailing whitespace
 * is trimmed.  Tokens are made up of alphanumeric characters (as
 * defined by libc's isalnum()) plus additional allowable characters
 * defined by @extra.
 *
 * At start *@state points into the buffer, and will be adjusted to
 * point further along in the buffer.  Returns the beginning of the
 * token or NULL (and whines to syslog) if an error was encountered.
 */
static char *get_token(struct parse_state *state, const char *extra)
{
    char *token;
    char *p;

    token = tok_next(&state->tok);
    if (!token) {
	parse_error(state, "short line");
	return NULL;
    }

    /* check the token */
    if (extra == NULL)
	extra = "";
    for (p = token ; *p && (isalnum(*p) || strchr(extra, *p)) ; p++)
	;
    if (*p) {
	state->context = p;
	parse_error(state, "invalid character");
	return NULL;
    }

    state->context = token;
    return token;
}

/* Parses strings of the form value1 [ value2 [ ... ]].
 * value1 is mapped via table to ints and the result or'ed.
 * Whitespace is allowed between value names and punctuation.
 * The field must end in '\0' or ','.
 * s is advanced to '\0' or ','.
 * On error errmsg is used to identify item to be parsed.
 */
static int parse_table_lookup_bitmask(const struct annotate_attrib *table,
                                      struct parse_state *state)
{
    char *token = get_token(state, ".-_/ ");
    char *p;
    int i;
    int result = 0;
    tok_t tok;

    if (!token)
	return -1;
    tok_initm(&tok, token, NULL, 0);

    while ((p = tok_next(&tok))) {
	state->context = p;
	i = table_lookup(table, p);
	if (i < 0)
	    return i;
	result |= i;
    }

    return result;
}

static int normalise_attribs(struct parse_state *state, int attribs)
{
    int nattribs = 0;
    static int deprecated_warnings = 0;

    /* always provide size.shared if value.shared specified */
    if ((attribs & ATTRIB_VALUE_SHARED))
	nattribs |= ATTRIB_VALUE_SHARED|ATTRIB_SIZE_SHARED;

    /* likewise size.priv */
    if ((attribs & ATTRIB_VALUE_PRIV))
	nattribs |= ATTRIB_VALUE_PRIV|ATTRIB_SIZE_PRIV;

    /* ignore any other specified attributes */

    if ((attribs & ATTRIB_DEPRECATED)) {
	if (!deprecated_warnings++)
	    parse_error(state, "deprecated attribute names such as "
				"content-type or modified-since (ignoring)");
    }

    return nattribs;
}

/* Create array of allowed annotations, both internally & externally defined */
static void init_annotation_definitions(void)
{
    char *p;
    char aline[ANNOT_DEF_MAXLINELEN];
    annotate_entrydesc_t *ae;
    int i;
    FILE* f;
    struct parse_state state;
    ptrarray_t *entries;

    /* copy static entries into list */
    for (i = 0 ; server_builtin_entries[i].name ; i++)
	ptrarray_append(&server_entries, (void *)&server_builtin_entries[i]);

    /* copy static entries into list */
    for (i = 0 ; mailbox_builtin_entries[i].name ; i++)
	ptrarray_append(&mailbox_entries, (void *)&mailbox_builtin_entries[i]);

    /* copy static entries into list */
    for (i = 0 ; message_builtin_entries[i].name ; i++)
	ptrarray_append(&message_entries, (void *)&message_builtin_entries[i]);

    memset(&state, 0, sizeof(state));

    /* parse config file */
    state.filename = config_getstring(IMAPOPT_ANNOTATION_DEFINITIONS);

    if (!state.filename)
	return;

    f = fopen(state.filename,"r");
    if (!f) {
	syslog(LOG_ERR, "%s: could not open annotation definition file: %m",
	       state.filename);
	return;
    }

    while (fgets(aline, sizeof(aline), f)) {
	/* remove leading space, skip blank lines and comments */
	state.lineno++;
	for (p = aline; *p && isspace(*p); p++);
	if (!*p || *p == '#') continue;
	tok_initm(&state.tok, aline, ",", TOK_TRIMLEFT|TOK_TRIMRIGHT|TOK_EMPTY);

	/* note, we only do the most basic validity checking and may
	   be more restrictive than neccessary */

	ae = xzmalloc(sizeof(*ae));

	if (!(p = get_token(&state, ".-_/:"))) goto bad;
	/* TV-TODO: should test for empty */

	if (!strncmp(p, "/vendor/cmu/cyrus-imapd/", 24)) {
	    parse_error(&state, "annotation under /vendor/cmu/cyrus-imapd/");
	    goto bad;
	}
	ae->name = xstrdup(p);

	if (!(p = get_token(&state, ".-_/"))) goto bad;
	switch (table_lookup(annotation_scope_names, p)) {
	case ANNOTATION_SCOPE_SERVER:
	    entries = &server_entries;
	    break;
	case ANNOTATION_SCOPE_MAILBOX:
	    entries = &mailbox_entries;
	    break;
	case ANNOTATION_SCOPE_MESSAGE:
	    if (!strncmp(ae->name, "/flags/", 7)) {
		/* RFC5257 reserves the /flags/ hierarchy for future use */
		state.context = ae->name;
		parse_error(&state, "message entry under /flags/");
		goto bad;
	    }
	    entries = &message_entries;
	    break;
	case -1:
	    parse_error(&state, "invalid annotation scope");
	    goto bad;
	}

	if (!(p = get_token(&state, NULL))) goto bad;
	i = table_lookup(attribute_type_names, p);
	if (i < 0) {
	    parse_error(&state, "invalid annotation type");
	    goto bad;
	}
	ae->type = i;

	i = parse_table_lookup_bitmask(annotation_proxy_type_names, &state);
	if (i < 0) {
	    parse_error(&state, "invalid annotation proxy type");
	    goto bad;
	}
	ae->proxytype = i;

	i = parse_table_lookup_bitmask(annotation_attributes, &state);
	if (i < 0) {
	    parse_error(&state, "invalid annotation attributes");
	    goto bad;
	}
	ae->attribs = normalise_attribs(&state, i);

	if (!(p = get_token(&state, NULL))) goto bad;
	ae->extra_rights = cyrus_acl_strtomask(p);

	p = tok_next(&state.tok);
	if (p) {
	    parse_error(&state, "junk at end of line");
	    goto bad;
	}

	ae->get = annotation_get_fromdb;
	ae->set = annotation_set_todb;
	ae->rock = NULL;
	ptrarray_append(entries, ae);
	continue;

bad:
	free((char *)ae->name);
	free(ae);
	tok_fini(&state.tok);
	continue;
    }

    if (state.nerrors)
	syslog(LOG_ERR, "%s: encountered %u errors.  Struggling on, but "
			"some of your annotation definitions may be "
			"ignored.  Please fix this file!",
			state.filename, state.nerrors);

    fclose(f);
}
