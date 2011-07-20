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

#include "annotate.h"
#include "sync_log.h"

#define DEBUG 1

/* Encapsulates all the state involved in providing the scope
 * for setting or getting a single annotation */
typedef struct annotate_cursor annotate_cursor_t;
struct annotate_cursor
{
    int which;			/* ANNOTATION_SCOPE_* */
    const char *int_mboxname;	/* for _MAILBOX, _MESSAGE */
    const char *ext_mboxname;	/* for _MAILBOX */
    struct mboxlist_entry *mbentry; /* for _MAILBOX */
    unsigned int uid;		/* for _MESSAGE */
    const char *acl;		/* for _MESSAGE */
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

struct fetchdata;
struct storedata;
struct annotate_st_entry_list;

typedef struct annotate_entrydesc annotate_entrydesc_t;
struct annotate_entrydesc
{
    const char *name;		/* entry name */
    int type;			/* entry type */
    annotation_proxy_t proxytype; /* mask of allowed server types */
    int attribs;		/* mask of allowed attributes */
    int extra_rights;		/* for set of shared mailbox annotations */
    void (*get)(const annotate_cursor_t *cursor,
		const char *name, struct fetchdata *fdata,
		void *rock);	/* function to get the entry */
    int (*set)(const annotate_cursor_t *cursor, struct annotate_st_entry_list *entry,
	       struct storedata *sdata,
	       void *rock);	/* function to set the entry */
    void *rock;			/* rock passed to get() function */
};

typedef struct annotate_db annotate_db_t;
struct annotate_db
{
    annotate_db_t *next;
    int refcount;
    char *mboxname;
    char *filename;
    struct db *db;
    struct txn *txn;
};

#define DB config_annotation_db

static annotate_db_t *all_dbs_head = NULL;
static annotate_db_t *all_dbs_tail = NULL;
static int in_txn = 0;
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
static int _annotate_find(const annotate_cursor_t *cursor, const char *entry,
			  annotatemore_find_proc_t proc, void *rock);
static int annotation_set_tofile(const annotate_cursor_t *cursor
				    __attribute__((unused)),
				 struct annotate_st_entry_list *entry,
				 struct storedata *sdata,
				 void *rock);
static int annotation_set_todb(const annotate_cursor_t *cursor,
			       struct annotate_st_entry_list *entry,
			       struct storedata *sdata,
			       void *rock __attribute__((unused)));
static int annotation_set_mailboxopt(const annotate_cursor_t *cursor,
				     struct annotate_st_entry_list *entry,
				     struct storedata *sdata,
				     void *rock __attribute__((unused)));
static int annotation_set_pop3showafter(const annotate_cursor_t *cursor,
				     struct annotate_st_entry_list *entry,
				     struct storedata *sdata,
				     void *rock __attribute__((unused)));
static int annotation_set_specialuse(const annotate_cursor_t *cursor,
				     struct annotate_st_entry_list *entry,
				     struct storedata *sdata,
				     void *rock __attribute__((unused)));
static int _annotate_rewrite(const char *oldmboxname, uint32_t olduid,
			     const char *olduserid, const char *newmboxname,
			     uint32_t newuid, const char *newuserid,
			     int copy);
static int _annotate_may_store(const struct storedata *sdata,
			       const annotate_cursor_t *cursor,
			       int is_shared,
			       const annotate_entrydesc_t *desc);

/* String List Management */
/*
 * Append 's' to the strlist 'l'.  Possibly include metadata.
 */
void appendstrlist_withdata(struct strlist **l, char *s, void *d, size_t size)
{
    struct strlist **tail = l;

    while (*tail) tail = &(*tail)->next;

    *tail = (struct strlist *)xmalloc(sizeof(struct strlist));
    (*tail)->s = xstrdup(s);
    (*tail)->p = 0;
    if(d && size) {
	(*tail)->rock = xmalloc(size);
	memcpy((*tail)->rock, d, size);
    } else {
	(*tail)->rock = NULL;
    }
    (*tail)->next = 0;
}

/*
 * Append 's' to the strlist 'l'.
 */
void appendstrlist(struct strlist **l, char *s) 
{
    appendstrlist_withdata(l, s, NULL, 0);
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
    (*tail)->rock = NULL;
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
	if (l->rock) free(l->rock);
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
static int annotate_dbname(const char *mboxname, char **fnamep)
{
    char *fname;
    int r = 0;

    if (mboxname) {
	/* per-mbox database */
	struct mboxlist_entry *mbentry = NULL;

	r = mboxlist_lookup(mboxname, &mbentry, NULL);
	if (r)
	    return r;
	fname = mboxname_metapath(mbentry->partition, mboxname,
			          META_ANNOTATIONS, /*isnew*/0);
	mboxlist_entry_free(&mbentry);
	if (!fname)
	    return IMAP_MAILBOX_BADNAME;
	fname = xstrdup(fname);
    }
    else {
	/* global database */
	const char *conf_fname = config_getstring(IMAPOPT_ANNOTATION_DB_PATH);

	if (conf_fname)
	    fname = xstrdup(conf_fname);
	else
	    fname = strconcat(config_dir, FNAME_ANNOTATIONS, (char *)NULL);
    }

    *fnamep = fname;
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

static void annotate_putdb(annotate_db_t **dbp)
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

static void annotate_cursor_setup(annotate_cursor_t *cursor,
				  const char *mailbox, uint32_t uid)
{
    memset(cursor, 0, sizeof(*cursor));
    cursor->int_mboxname = mailbox;
    if (!*mailbox) {
	cursor->which = ANNOTATION_SCOPE_SERVER;
    }
    else if (!uid) {
	cursor->which = ANNOTATION_SCOPE_MAILBOX;
    }
    else {
	cursor->which = ANNOTATION_SCOPE_MESSAGE;
	cursor->uid = uid;
    }
}

int annotatemore_findall(const char *mailbox, uint32_t uid, const char *entry,
			 annotatemore_find_proc_t proc, void *rock)
{
    annotate_cursor_t cursor;
    annotate_cursor_setup(&cursor, mailbox, uid);
    return _annotate_find(&cursor, entry, proc, rock);
}

static int _annotate_find(const annotate_cursor_t *cursor,
			  const char *entry,
			  annotatemore_find_proc_t proc,
			  void *rock)
{
    char key[MAX_MAILBOX_PATH+1], *p;
    int keylen, r;
    struct find_rock frock;

    frock.mglob = glob_init(cursor->int_mboxname, GLOB_HIERARCHY);
    frock.eglob = glob_init(entry, GLOB_HIERARCHY);
    GLOB_SET_SEPARATOR(frock.eglob, '/');
    frock.uid = cursor->uid;
    frock.proc = proc;
    frock.rock = rock;
    r = annotate_getdb(cursor->int_mboxname, cursor->uid, 0, &frock.d);
    if (r) {
	if (r == CYRUSDB_NOTFOUND)
	    r = 0;
	goto out;
    }

    /* Find fixed-string pattern prefix */
    keylen = make_key(cursor->int_mboxname, cursor->uid,
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

/***************************  Annotation Fetching  ***************************/

struct fetchdata {
    struct namespace *namespace;
    const char *userid;
    int isadmin;
    struct auth_state *auth_state;
    struct annotate_f_entry_list *entry_list;
    unsigned attribs;
    struct entryattlist **entryatts;
    struct hash_table entry_table;
    unsigned found;

    /* For proxies (a null entry_list indicates that we ONLY proxy) */
    /* if these are NULL, we have had a local exact match, and we
       DO NOT proxy */
    struct hash_table server_table;
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
};

static void flush_entryatt(struct fetchdata *fdata)
{
    if (!fdata->attvalues)
	return;	    /* nothing to flush */

    fdata->callback(fdata->lastname,
		    fdata->lastuid,
		    fdata->lastentry,
		    fdata->attvalues,
		    fdata->callback_rock);
    freeattvalues(fdata->attvalues);
    fdata->attvalues = NULL;
}

/* Output a single entry and attributes for a single mailbox.
 * Shared and private annotations are output together by caching
 * the attributes until the mailbox and/or entry changes.
 *
 * The cache is reset by calling with a NULL mboxname or entry.
 * The last entry is flushed by calling with a NULL attrib.
 */
static void output_entryatt(const annotate_cursor_t *cursor, const char *entry,
			    const char *userid, const struct buf *value,
			    struct fetchdata *fdata)
{
    const char *mboxname;
    char key[MAX_MAILBOX_BUFFER]; /* XXX MAX_MAILBOX_NAME + entry + userid */
    struct buf buf = BUF_INITIALIZER;
    int vallen;
    char ext_mboxname[MAX_MAILBOX_BUFFER];

    /* We don't put any funny interpretations on NULL values for
     * some of these anymore, now that the dirty hacks are gone. */
    assert(cursor);
    assert(entry);
    assert(userid);
    assert(value);
    assert(fdata);

    if (cursor->ext_mboxname)
	mboxname = cursor->ext_mboxname;
    else if (cursor->int_mboxname) {
	fdata->namespace->mboxname_toexternal(fdata->namespace,
					      cursor->int_mboxname,
					      fdata->userid,
					      ext_mboxname);
	mboxname = ext_mboxname;
    }
    else
	mboxname = "";
    /* @mboxname is now an external mailbox name */

    /* Check if this is a new entry.
     * If so, flush our current entry.
     */
    if (cursor->uid != fdata->lastuid ||
	strcmp(mboxname, fdata->lastname) ||
	strcmp(entry, fdata->lastentry))
	flush_entryatt(fdata);

    strlcpy(fdata->lastname, mboxname, sizeof(fdata->lastname));
    strlcpy(fdata->lastentry, entry, sizeof(fdata->lastentry));
    fdata->lastuid = cursor->uid;

    /* check if we already returned this entry */
    strlcpy(key, mboxname, sizeof(key));
    if (cursor->uid) {
	char uidbuf[32];
	snprintf(uidbuf, sizeof(uidbuf), "/UID%u/", cursor->uid);
	strlcat(key, uidbuf, sizeof(key));
    }
    strlcat(key, entry, sizeof(key));
    strlcat(key, userid, sizeof(key));
    if (hash_lookup(key, &(fdata->entry_table))) return;
    hash_insert(key, (void *)0xDEADBEEF, &(fdata->entry_table));

    vallen = value->len;
    if (fdata->sizeptr && fdata->maxsize < vallen) {
	/* too big - track the size of the largest */
	int *sp = fdata->sizeptr;
	if (*sp < vallen) *sp = vallen;
	return;
    }

    if (!userid[0]) { /* shared annotation */
	if ((fdata->attribs & ATTRIB_VALUE_SHARED)) {
	    appendattvalue(&fdata->attvalues, "value.shared", value);
	    fdata->found |= ATTRIB_VALUE_SHARED;
	}

	if ((fdata->attribs & ATTRIB_SIZE_SHARED)) {
	    buf_reset(&buf);
	    buf_printf(&buf, "%u", value->len);
	    appendattvalue(&fdata->attvalues, "size.shared", &buf);
	    fdata->found |= ATTRIB_SIZE_SHARED;
	}
    }
    else { /* private annotation */
	if ((fdata->attribs & ATTRIB_VALUE_PRIV)) {
	    appendattvalue(&fdata->attvalues, "value.priv", value);
	    fdata->found |= ATTRIB_VALUE_PRIV;
	}

	if ((fdata->attribs & ATTRIB_SIZE_PRIV)) {
	    buf_reset(&buf);
	    buf_printf(&buf, "%u", value->len);
	    appendattvalue(&fdata->attvalues, "size.priv", &buf);
	    fdata->found |= ATTRIB_SIZE_PRIV;
	}
    }
    buf_free(&buf);
}

/* Note that unlike store access control, fetch access control
 * is identical between shared and private annotations */
static int _annotate_may_fetch(const struct fetchdata *fdata,
			       const annotate_cursor_t *cursor,
			       const annotate_entrydesc_t *desc)
{
    unsigned int my_rights;
    unsigned int needed = 0;
    const char *acl = NULL;

    /* Admins can do anything */
    if (fdata->isadmin)
	return 1;

    /* Some entries need to do their own access control */
    if ((desc->type & ATTRIB_NO_FETCH_ACL_CHECK))
	return 1;

    if (cursor->which == ANNOTATION_SCOPE_SERVER) {
	/* RFC5464 doesn't mention access control for server
	 * annotations, but this seems a sensible practice and is
	 * consistent with past Cyrus behaviour */
	return 1;
    }
    else if (cursor->which == ANNOTATION_SCOPE_MAILBOX) {
	assert(cursor->int_mboxname[0]);
	assert(cursor->mbentry);

	/* Make sure its a local mailbox annotation */
	if (cursor->mbentry->server)
	    return 0;

	acl = cursor->mbentry->acl;
	/* RFC5464 is a trifle vague about access control for mailbox
	 * annotations but this seems to be compliant */
	needed = ACL_LOOKUP|ACL_READ;
	/* fall through to ACL check */
    }
    else if (cursor->which == ANNOTATION_SCOPE_MESSAGE) {
	acl = cursor->acl;
	/* RFC5257: reading from a private annotation needs 'r'.
	 * Reading from a shared annotation needs 'r' */
	needed = ACL_READ;
	/* fall through to ACL check */
    }

    if (!acl)
	return 0;

    my_rights = cyrus_acl_myrights(fdata->auth_state, acl);

    return ((my_rights & needed) == needed);
}

static void annotation_get_fromfile(const annotate_cursor_t *cursor,
				    const char *entry,
				    struct fetchdata *fdata,
				    void *rock)
{
    const char *filename = (const char *) rock;
    char path[MAX_MAILBOX_PATH+1];
    struct buf value = BUF_INITIALIZER;
    FILE *f;

    snprintf(path, sizeof(path), "%s/msg/%s", config_dir, filename);
    if ((f = fopen(path, "r")) && buf_getline(&value, f)) {

	/* TODO: we need a buf_chomp() */
	if (value.s[value.len-1] == '\r')
	    buf_truncate(&value, value.len-1);

	output_entryatt(cursor, entry, "", &value, fdata);
    }
    if (f) fclose(f);
    buf_free(&value);
}

static void annotation_get_freespace(const annotate_cursor_t *cursor,
				     const char *entry,
				     struct fetchdata *fdata,
				     void *rock __attribute__((unused)))
{
    unsigned long tavail;
    struct buf value = BUF_INITIALIZER;

    (void) find_free_partition(&tavail);
    buf_printf(&value, "%lu", tavail);
    output_entryatt(cursor, entry, "", &value, fdata);
    buf_free(&value);
}

static void annotation_get_server(const annotate_cursor_t *cursor,
				  const char *entry,
				  struct fetchdata *fdata,
				  void *rock __attribute__((unused))) 
{
    struct buf value = BUF_INITIALIZER;

    assert(fdata);
    assert(cursor->which == ANNOTATION_SCOPE_MAILBOX);
    assert(cursor->mbentry);

    /* Check ACL */
    /* Note that we use a weaker form of access control than
     * normal - we only check for ACL_LOOKUP and we don't refuse
     * access if the mailbox is not local */
    if (!cursor->mbentry->acl ||
        !(cyrus_acl_myrights(fdata->auth_state, cursor->mbentry->acl) & ACL_LOOKUP))
	goto out;

    if (cursor->mbentry->server)
	buf_appendcstr(&value, cursor->mbentry->server);

    output_entryatt(cursor, entry, "", &value, fdata);
out:
    buf_free(&value);
}

static void annotation_get_partition(const annotate_cursor_t *cursor,
				     const char *entry,
				     struct fetchdata *fdata,
				     void *rock __attribute__((unused))) 
{
    struct buf value = BUF_INITIALIZER;

    assert(fdata);
    assert(cursor->which == ANNOTATION_SCOPE_MAILBOX);
    assert(cursor->mbentry);

    /* Check ACL */
    if (!cursor->mbentry->acl ||
        !(cyrus_acl_myrights(fdata->auth_state, cursor->mbentry->acl) & ACL_LOOKUP))
	goto out;

    if (!cursor->mbentry->server)
	buf_appendcstr(&value, cursor->mbentry->partition);

    output_entryatt(cursor, entry, "", &value, fdata);
out:
    buf_free(&value);
}

static void annotation_get_size(const annotate_cursor_t *cursor,
				const char *entry,
				struct fetchdata *fdata,
				void *rock __attribute__((unused))) 
{
    struct mailbox *mailbox = NULL;
    struct buf value = BUF_INITIALIZER;

    if (!fdata || !cursor->mbentry)
	fatal("annotation_get_size called with bad parameters",
	      EC_TEMPFAIL);

    if (mailbox_open_irl(cursor->int_mboxname, &mailbox))
	goto out;

    buf_printf(&value, QUOTA_T_FMT, mailbox->i.quota_mailbox_used);

    mailbox_close(&mailbox);

    output_entryatt(cursor, entry, "", &value, fdata);
out:
    buf_free(&value);
}

static void annotation_get_lastupdate(const annotate_cursor_t *cursor,
				      const char *entry,
				      struct fetchdata *fdata,
				      void *rock __attribute__((unused))) 
{
    struct stat sbuf;
    char valuebuf[RFC3501_DATETIME_MAX+1];
    struct buf value = BUF_INITIALIZER;
    char *fname;

    if(!fdata || !cursor->mbentry)
	fatal("annotation_get_lastupdate called with bad parameters",
	      EC_TEMPFAIL);

    fname = mboxname_metapath(cursor->mbentry->partition,
			      cursor->int_mboxname, META_INDEX, 0);
    if (!fname)
	goto out;
    if (stat(fname, &sbuf) == -1)
	goto out;

    time_to_rfc3501(sbuf.st_mtime, valuebuf, sizeof(valuebuf));
    buf_appendcstr(&value, valuebuf);

    output_entryatt(cursor, entry, "", &value, fdata);
out:
    buf_free(&value);
}

static void annotation_get_lastpop(const annotate_cursor_t *cursor,
				   const char *entry,
				   struct fetchdata *fdata,
				   void *rock __attribute__((unused)))
{
    struct mailbox *mailbox = NULL;
    char valuebuf[RFC3501_DATETIME_MAX+1];
    struct buf value = BUF_INITIALIZER;

    if(!fdata || !cursor->mbentry)
      fatal("annotation_get_lastpop called with bad parameters",
              EC_TEMPFAIL);

    if (mailbox_open_irl(cursor->int_mboxname, &mailbox) != 0)
	goto out;

    if (mailbox->i.pop3_last_login) {
	time_to_rfc3501(mailbox->i.pop3_last_login, valuebuf,
			sizeof(valuebuf));
	buf_appendcstr(&value, valuebuf);
    }

    mailbox_close(&mailbox);

    output_entryatt(cursor, entry, "", &value, fdata);
out:
    buf_free(&value);
}

static void annotation_get_mailboxopt(const annotate_cursor_t *cursor,
				      const char *entry,
				      struct fetchdata *fdata,
				      void *rock)
{
    struct mailbox *mailbox = NULL;
    uint32_t flag = (unsigned long)rock;
    struct buf value = BUF_INITIALIZER;

    if (!cursor->int_mboxname || !entry || !fdata || !cursor->mbentry)
	fatal("annotation_get_mailboxopt called with bad parameters",
	      EC_TEMPFAIL);

    if (mailbox_open_irl(cursor->int_mboxname, &mailbox) != 0)
	goto out;

    buf_appendcstr(&value,
		   (mailbox->i.options & flag ? "true" : "false"));

    mailbox_close(&mailbox);

    output_entryatt(cursor, entry, "", &value, fdata);
out:
    buf_free(&value);
}

static void annotation_get_pop3showafter(const annotate_cursor_t *cursor,
				        const char *entry,
				        struct fetchdata *fdata,
				        void *rock __attribute__((unused)))
{
    struct mailbox *mailbox = NULL;
    char valuebuf[RFC3501_DATETIME_MAX+1];
    struct buf value = BUF_INITIALIZER;

    if(!cursor->int_mboxname || !entry || !fdata || !cursor->mbentry)
      fatal("annotation_get_pop3showafter called with bad parameters",
              EC_TEMPFAIL);

    if (mailbox_open_irl(cursor->int_mboxname, &mailbox) != 0)
	goto out;

    if (mailbox->i.pop3_show_after)
    {
	time_to_rfc3501(mailbox->i.pop3_show_after, valuebuf, sizeof(valuebuf));
	buf_appendcstr(&value, valuebuf);
    }

    mailbox_close(&mailbox);

    output_entryatt(cursor, entry, "", &value, fdata);
out:
    buf_free(&value);
}

static void annotation_get_specialuse(const annotate_cursor_t *cursor,
				      const char *entry,
				      struct fetchdata *fdata,
				      void *rock __attribute__((unused)))
{
    struct buf value = BUF_INITIALIZER;

    if (!cursor->int_mboxname || !fdata || !cursor->mbentry)
	fatal("annotation_get_lastupdate called with bad parameters",
	      EC_TEMPFAIL);

    if (cursor->mbentry->specialuse)
	buf_appendcstr(&value, cursor->mbentry->specialuse);

    output_entryatt(cursor, entry, "", &value, fdata);
    buf_free(&value);
}

struct rw_rock {
    const annotate_cursor_t *cursor;
    struct fetchdata *fdata;
};

static int rw_cb(const char *mailbox __attribute__((unused)),
		 uint32_t uid __attribute__((unused)),
		 const char *entry, const char *userid,
		 const struct buf *value, void *rock)
{
    struct rw_rock *rw_rock = (struct rw_rock *) rock;

    if (!userid[0] || !strcmp(userid, rw_rock->fdata->userid)) {
	output_entryatt(rw_rock->cursor, entry, userid, value,
			rw_rock->fdata);
    }

    return 0;
}

static void annotation_get_fromdb(const annotate_cursor_t *cursor,
				  const char *entry  __attribute__((unused)),
				  struct fetchdata *fdata,
				  void *rock)
{
    struct rw_rock rw_rock;
    const char *entrypat = (const char *) rock;

    rw_rock.cursor = cursor;
    rw_rock.fdata = fdata;
    fdata->found = 0;

    _annotate_find(cursor, entrypat, &rw_cb, &rw_rock);

    if (fdata->found != fdata->attribs &&
	(!strchr(entrypat, '%') && !strchr(entrypat, '*'))) {
	/* some results not found for an explicitly specified entry,
	 * make sure we emit explicit NILs */
	struct buf empty = BUF_INITIALIZER;
	if (!(fdata->found & (ATTRIB_VALUE_PRIV|ATTRIB_SIZE_PRIV)) &&
	    (fdata->attribs & (ATTRIB_VALUE_PRIV|ATTRIB_SIZE_PRIV))) {
	    /* store up value.priv and/or size.priv */
	    output_entryatt(cursor, entrypat, fdata->userid, &empty, fdata);
	}
	if (!(fdata->found & (ATTRIB_VALUE_SHARED|ATTRIB_SIZE_SHARED)) &&
	    (fdata->attribs & (ATTRIB_VALUE_SHARED|ATTRIB_SIZE_SHARED))) {
	    /* store up value.shared and/or size.shared */
	    output_entryatt(cursor, entrypat, "", &empty, fdata);
	}
	/* flush any stored attribute-value pairs */
	flush_entryatt(fdata);
    }
}

struct annotate_f_entry_list
{
    const annotate_entrydesc_t *entry;
    const char *entrypat;
    struct annotate_f_entry_list *next;
};

/* TODO: need to handle /<section-part>/ somehow */
static const annotate_entrydesc_t message_builtin_entries[] =
{
    {
	"/altsubject",
	ATTRIB_TYPE_STRING,
	BACKEND_ONLY,
	ATTRIB_VALUE_SHARED | ATTRIB_VALUE_PRIV,
	0,
	annotation_get_fromdb,
	annotation_set_todb,
	NULL
    },{
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
	/*set*/NULL,		    /* ??? */
	NULL
    };

static const annotate_entrydesc_t mailbox_builtin_entries[] =
{
    {
	"/check",
	ATTRIB_TYPE_BOOLEAN,
	BACKEND_ONLY,
	ATTRIB_VALUE_SHARED | ATTRIB_VALUE_PRIV,
	0,
	annotation_get_fromdb,
	annotation_set_todb,
	NULL
    },{
	"/checkperiod",
	ATTRIB_TYPE_UINT,
	BACKEND_ONLY,
	ATTRIB_VALUE_SHARED | ATTRIB_VALUE_PRIV,
	0,
	annotation_get_fromdb,
	annotation_set_todb,
	NULL
    },{
	"/comment",
	ATTRIB_TYPE_STRING,
	BACKEND_ONLY,
	ATTRIB_VALUE_SHARED | ATTRIB_VALUE_PRIV,
	0,
	annotation_get_fromdb,
	annotation_set_todb,
	NULL
    },{
	"/sort",
	ATTRIB_TYPE_STRING,
	BACKEND_ONLY,
	ATTRIB_VALUE_SHARED | ATTRIB_VALUE_PRIV,
	0,
	annotation_get_fromdb,
	annotation_set_todb,
	NULL
    },{
	"/specialuse",
	ATTRIB_TYPE_STRING,
	BACKEND_ONLY,
	ATTRIB_VALUE_SHARED,
	0,
	annotation_get_specialuse,
	annotation_set_specialuse,
	NULL
    },{
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
	/*set*/NULL,		    /* ??? */
	NULL
    };

static const annotate_entrydesc_t server_builtin_entries[] =
{
    {
	"/admin",
	ATTRIB_TYPE_STRING,
	PROXY_AND_BACKEND,
	ATTRIB_VALUE_SHARED,
	ACL_ADMIN,
	annotation_get_fromdb,
	annotation_set_todb,
	NULL
    },{
	"/comment",
	ATTRIB_TYPE_STRING,
	PROXY_AND_BACKEND,
	ATTRIB_VALUE_SHARED | ATTRIB_VALUE_PRIV,
	ACL_ADMIN,
	annotation_get_fromdb,
	annotation_set_todb,
	NULL
    },{
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
	/*set*/NULL,
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

static void _annotate_fetch_entries(struct fetchdata *fdata,
				    const annotate_cursor_t *cursor,
				    int proxy_check)
{
    struct annotate_f_entry_list *ee;

    /* Loop through the list of provided entries to get */
    for (ee = fdata->entry_list; ee; ee = ee->next) {

	if (proxy_check) {
	    if (ee->entry->proxytype == BACKEND_ONLY &&
	        proxy_fetch_func &&
		!config_getstring(IMAPOPT_PROXYSERVERS))
		continue;
	}

	if (!_annotate_may_fetch(fdata, cursor, ee->entry))
	    continue;

	ee->entry->get(cursor, ee->entry->name, fdata,
		       (ee->entry->rock ? ee->entry->rock : (void*) ee->entrypat));
    }
}

static int fetch_cb(char *name, int matchlen,
		    int maycreate __attribute__((unused)), void* rock)
{
    struct fetchdata *fdata = (struct fetchdata *) rock;
    static char lastname[MAX_MAILBOX_BUFFER];
    static int sawuser = 0;
    int c;
    char int_mboxname[MAX_MAILBOX_BUFFER], ext_mboxname[MAX_MAILBOX_BUFFER];
    struct mboxlist_entry *mbentry = NULL;
    annotate_cursor_t cursor;

    /* We have to reset the sawuser flag before each fetch command.
     * Handle it as a dirty hack.
     */
    if (name == NULL) {
	sawuser = 0;
	lastname[0] = '\0';
	return 0;
    }
    /* Suppress any output of a partial match */
    if (name[matchlen] && strncmp(lastname, name, matchlen) == 0) {
	return 0;
    }

    /*
     * We can get a partial match for "user" multiple times with
     * other matches inbetween.  Handle it as a special case
     */
    if (matchlen == 4 && strncasecmp(name, "user", 4) == 0) {
	if (sawuser) return 0;
	sawuser = 1;
    }

    strlcpy(lastname, name, sizeof(lastname));
    lastname[matchlen] = '\0';

    if (!strncasecmp(lastname, "INBOX", 5)) {
	(*fdata->namespace->mboxname_tointernal)(fdata->namespace, "INBOX",
						 fdata->userid, int_mboxname);
	strlcat(int_mboxname, lastname+5, sizeof(int_mboxname));
    }
    else
	strlcpy(int_mboxname, lastname, sizeof(int_mboxname));

    c = name[matchlen];
    if (c) name[matchlen] = '\0';
    (*fdata->namespace->mboxname_toexternal)(fdata->namespace, name,
					     fdata->userid, ext_mboxname);
    if (c) name[matchlen] = c;

    if (mboxlist_lookup(int_mboxname, &mbentry, NULL))
	return 0;

    annotate_cursor_setup(&cursor, int_mboxname, 0);
    cursor.ext_mboxname = ext_mboxname;
    cursor.mbentry = mbentry;

    _annotate_fetch_entries(fdata, &cursor, /*proxy_check*/0);

    if (proxy_fetch_func && fdata->orig_entry && mbentry->server &&
	!hash_lookup(mbentry->server, &(fdata->server_table))) {
	/* xxx ignoring result */
	proxy_fetch_func(mbentry->server, fdata->orig_mailbox,
			 fdata->orig_entry, fdata->orig_attribute);
	hash_insert(mbentry->server, (void *)0xDEADBEEF, &(fdata->server_table));
    }

    mboxlist_entry_free(&mbentry);

    return 0;
}

int annotatemore_fetch(const annotate_scope_t *scope,
		       const strarray_t *entries, const strarray_t *attribs,
		       struct namespace *namespace, int isadmin, const char *userid,
		       struct auth_state *auth_state,
		       annotate_fetch_cb_t callback, void *rock,
		       int *maxsizeptr)
{
    int i;
    struct fetchdata fdata;
    struct glob *g;
    const ptrarray_t *non_db_entries;
    const annotate_entrydesc_t *db_entry;

    memset(&fdata, 0, sizeof(struct fetchdata));
    fdata.namespace = namespace;
    fdata.userid = userid;
    fdata.isadmin = isadmin;
    fdata.auth_state = auth_state;
    fdata.callback = callback;
    fdata.callback_rock = rock;
    if (maxsizeptr) {
	fdata.maxsize = *maxsizeptr; /* copy to check against */
        fdata.sizeptr = maxsizeptr; /* pointer to push largest back */
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
		    fdata.attribs |= annotation_attributes[attribcount].entry;
	    }
	}
	
	glob_free(&g);
    }

    if (!fdata.attribs) return 0;

    if (scope->which == ANNOTATION_SCOPE_SERVER) {
	non_db_entries = &server_entries;
	db_entry = &server_db_entry;
    }
    else if (scope->which == ANNOTATION_SCOPE_MAILBOX) {
	non_db_entries = &mailbox_entries;
	db_entry = &mailbox_db_entry;
    }
    else if (scope->which == ANNOTATION_SCOPE_MESSAGE) {
	non_db_entries = &message_entries;
	db_entry = &message_db_entry;
    }
    else
	return IMAP_INTERNAL;

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
		    || proxy_fetch_func) {
		    struct annotate_f_entry_list *nentry =
			xzmalloc(sizeof(struct annotate_f_entry_list));

		    nentry->next = fdata.entry_list;
		    nentry->entry = desc;
		    nentry->entrypat = s;
		    fdata.entry_list = nentry;
		}
	    }

	    if (!strcmp(s, desc->name)) {
		/* exact match */
		if (desc->proxytype != PROXY_ONLY) {
		    fdata.orig_entry = entries;  /* proxy it */
		}
		break;
	    }
	}

	if (j == non_db_entries->count) {
	    /* no [exact] match */
	    fdata.orig_entry = entries;  /* proxy it */
	    check_db = 1;
	}

	/* Add the db entry to our list if only if it
	   applies to our particular server type */
	if (check_db &&
	    ((db_entry->proxytype != PROXY_ONLY) || proxy_fetch_func)) {
	    /* Add the db entry to our list */
	    struct annotate_f_entry_list *nentry =
		xzmalloc(sizeof(struct annotate_f_entry_list));

	    nentry->next = fdata.entry_list;
	    nentry->entry = db_entry;
	    nentry->entrypat = s;
	    fdata.entry_list = nentry;
	}
	    
	glob_free(&g);
    }

    if (scope->which == ANNOTATION_SCOPE_SERVER) {

	if (fdata.entry_list) {
	    annotate_cursor_t cursor;

	    annotate_cursor_setup(&cursor, "", 0);

	    /* xxx better way to determine a size for this table? */
	    construct_hash_table(&fdata.entry_table, 100, 1);

	    _annotate_fetch_entries(&fdata, &cursor, /*proxy_check*/1);

	    free_hash_table(&fdata.entry_table, NULL);
	}
    }
    else if (scope->which == ANNOTATION_SCOPE_MAILBOX) {

	if (fdata.entry_list || proxy_fetch_func) {
	    char mboxpat[MAX_MAILBOX_BUFFER];

	    /* Reset state in fetch_cb */
	    fetch_cb(NULL, 0, 0, 0);

	    /* xxx better way to determine a size for this table? */
	    construct_hash_table(&fdata.entry_table, 100, 1);

	    if(proxy_fetch_func && fdata.orig_entry) {
		fdata.orig_mailbox = scope->mailbox;
		fdata.orig_attribute = attribs;
		/* xxx better way to determine a size for this table? */
		construct_hash_table(&fdata.server_table, 10, 1);
	    }

	    /* copy the pattern so we can change hiersep */
	    strlcpy(mboxpat, scope->mailbox, sizeof(mboxpat));
	    mboxname_hiersep_tointernal(namespace, mboxpat,
					config_virtdomains ?
					strcspn(mboxpat, "@") : 0);

	    (*namespace->mboxlist_findall)(namespace, mboxpat,
					   isadmin, userid,
					   auth_state, fetch_cb,
					   &fdata);
	    free_hash_table(&fdata.entry_table, NULL);

	    if(proxy_fetch_func && fdata.orig_entry) {
		free_hash_table(&fdata.server_table, NULL);
	    }
	}
    }
    else if (scope->which == ANNOTATION_SCOPE_MESSAGE) {

	if (fdata.entry_list || proxy_fetch_func) {
	    annotate_cursor_t cursor;

	    annotate_cursor_setup(&cursor, scope->mailbox, scope->uid);
	    cursor.acl = scope->acl;

	    /* xxx better way to determine a size for this table? */
	    construct_hash_table(&fdata.entry_table, 100, 1);

// 	    if(proxy_fetch_func && fdata.orig_entry) {
// 		fdata.orig_mailbox = scope->mailbox;
// 		fdata.orig_attribute = attribs;
// 		/* xxx better way to determine a size for this table? */
// 		construct_hash_table(&fdata.server_table, 10, 1);
// 	    }

	    _annotate_fetch_entries(&fdata, &cursor, /*proxy_check*/0);

	    free_hash_table(&fdata.entry_table, NULL);

// 	    if(proxy_fetch_func && fdata.orig_entry) {
// 		free_hash_table(&fdata.server_table, NULL);
// 	    }
	}
    }

    /* Flush last cached entry in output_entryatt() */
    flush_entryatt(&fdata);

    /* Free the entry list, if needed */
    while(fdata.entry_list) {
	struct annotate_f_entry_list *freeme = fdata.entry_list;
	fdata.entry_list = fdata.entry_list->next;
	free(freeme);
    }

    return 0;
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

static int write_entry(const char *mboxname,
		       unsigned int uid,
		       const char *entry,
		       const char *userid,
		       const struct buf *value)
{
    char key[MAX_MAILBOX_PATH+1];
    int keylen, r;
    annotate_db_t *d = NULL;

    /* must be in a transaction to modify the db */
    if (!in_txn)
	return IMAP_INTERNAL;

    r = annotate_getdb(mboxname, uid, CYRUSDB_CREATE, &d);
    if (r)
	return r;

    keylen = make_key(mboxname, uid, entry, userid, key, sizeof(key));

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
	sync_log_annotation(mboxname);
	buf_free(&data);
    }

    annotate_putdb(&d);

    return r;
}

int annotatemore_write_entry(const char *mboxname,
			     uint32_t uid,
			     const char *entry,
			     const char *userid,
			     const struct buf *value)
{
    return write_entry(mboxname, uid, entry, userid, value);
}

struct storedata {
    struct namespace *namespace;
    const char *userid;
    int isadmin;
    struct auth_state *auth_state;
    struct annotate_st_entry_list *entry_list;

    /* number of mailboxes matching the pattern */
    unsigned count;

    /* for proxies only */
    struct hash_table server_table;
};

struct annotate_st_entry_list
{
    const annotate_entrydesc_t *entry;
    struct buf shared;
    struct buf priv;
    int have_shared;
    int have_priv;

    struct annotate_st_entry_list *next;
};

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

static int _annotate_store_entries(struct storedata *sdata,
				   const annotate_cursor_t *cursor)
{
    struct annotate_st_entry_list *ee;
    int r;

    /* Loop through the list of provided entries to get */
    for (ee = sdata->entry_list ; ee ; ee = ee->next) {

	if (ee->have_shared &&
	    !_annotate_may_store(sdata, cursor, /*shared*/1, ee->entry))
	    return IMAP_PERMISSION_DENIED;

	if (ee->have_priv &&
	    !_annotate_may_store(sdata, cursor, /*shared*/0, ee->entry))
	    return IMAP_PERMISSION_DENIED;

	r = ee->entry->set(cursor, ee, sdata, ee->entry->rock);
	if (r)
	    return r;
    }
    return 0;
}

static int store_cb(const char *name, int matchlen,
		    int maycreate __attribute__((unused)), void *rock)
{
    struct storedata *sdata = (struct storedata *) rock;
    static char lastname[MAX_MAILBOX_PATH+1];
    static int sawuser = 0;
    char int_mboxname[MAX_MAILBOX_BUFFER];
    struct mboxlist_entry *mbentry = NULL;
    int r = 0;
    annotate_cursor_t cursor;

    /* We have to reset the sawuser flag before each fetch command.
     * Handle it as a dirty hack.
     */
    if (name == NULL) {
	sawuser = 0;
	lastname[0] = '\0';
	return 0;
    }
    /* Suppress any output of a partial match */
    if (name[matchlen] && strncmp(lastname, name, matchlen) == 0) {
	return 0;
    }

    /*
     * We can get a partial match for "user" multiple times with
     * other matches inbetween.  Handle it as a special case
     */
    if (matchlen == 4 && strncasecmp(name, "user", 4) == 0) {
	if (sawuser) return 0;
	sawuser = 1;
    }

    strlcpy(lastname, name, sizeof(lastname));
    lastname[matchlen] = '\0';

    if (!strncasecmp(lastname, "INBOX", 5)) {
	(*sdata->namespace->mboxname_tointernal)(sdata->namespace, "INBOX",
						 sdata->userid, int_mboxname);
	strlcat(int_mboxname, lastname+5, sizeof(int_mboxname));
    }
    else
	strlcpy(int_mboxname, lastname, sizeof(int_mboxname));

    if (mboxlist_lookup(int_mboxname, &mbentry, NULL))
	return 0;

    annotate_cursor_setup(&cursor, int_mboxname, 0);
    cursor.ext_mboxname = name;
    cursor.mbentry = mbentry;

    r = _annotate_store_entries(sdata, &cursor);
    if (r)
	goto cleanup;

    sync_log_annotation(int_mboxname);

    sdata->count++;

    if (proxy_store_func && mbentry->server &&
	!hash_lookup(mbentry->server, &(sdata->server_table))) {
	hash_insert(mbentry->server, (void *)0xDEADBEEF, &(sdata->server_table));
    }

 cleanup:
    mboxlist_entry_free(&mbentry);

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

static int _annotate_may_store(const struct storedata *sdata,
			       const annotate_cursor_t *cursor,
			       int is_shared,
			       const annotate_entrydesc_t *desc)
{
    unsigned int my_rights;
    unsigned int needed = 0;
    const char *acl = NULL;

    /* Admins can do anything */
    if (sdata->isadmin)
	return 1;

    if (cursor->which == ANNOTATION_SCOPE_SERVER) {
	/* RFC5464 doesn't mention access control for server
	 * annotations, but this seems a sensible practice and is
	 * consistent with past Cyrus behaviour */
	return !is_shared;
    }
    else if (cursor->which == ANNOTATION_SCOPE_MAILBOX) {
	assert(cursor->int_mboxname[0]);
	assert(cursor->mbentry);

	/* Make sure its a local mailbox annotation */
	if (cursor->mbentry->server)
	    return 0;

	acl = cursor->mbentry->acl;
	/* RFC5464 is a trifle vague about access control for mailbox
	 * annotations but this seems to be compliant */
	needed = ACL_LOOKUP;
	if (is_shared)
	    needed |= ACL_READ|ACL_WRITE|desc->extra_rights;
	/* fall through to ACL check */
    }
    else if (cursor->which == ANNOTATION_SCOPE_MESSAGE) {
	acl = cursor->acl;
	/* RFC5257: writing to a private annotation needs 'r'.
	 * Writing to a shared annotation needs 'n' */
	needed = (is_shared ? ACL_ANNOTATEMSG : ACL_READ);
	/* fall through to ACL check */
    }

    if (!acl)
	return 0;

    my_rights = cyrus_acl_myrights(sdata->auth_state, acl);

    return ((my_rights & needed) == needed);
}

static int annotation_set_tofile(const annotate_cursor_t *cursor
				    __attribute__((unused)),
				 struct annotate_st_entry_list *entry,
				 struct storedata *sdata
				    __attribute__((unused)),
				 void *rock)
{
    const char *filename = (const char *) rock;
    char path[MAX_MAILBOX_PATH+1];
    FILE *f;

    snprintf(path, sizeof(path), "%s/msg/%s", config_dir, filename);

    /* XXX how do we do this atomically with other annotations? */
    if (entry->shared.s == NULL)
	return unlink(path);
    else if ((f = fopen(path, "w"))) {
	fwrite(entry->shared.s, 1, entry->shared.len, f);
	fputc('\n', f);
	return fclose(f);
    }

    return IMAP_IOERROR;
}

static int annotation_set_todb(const annotate_cursor_t *cursor,
			       struct annotate_st_entry_list *entry,
			       struct storedata *sdata,
			       void *rock __attribute__((unused)))
{
    int r = 0;

    if (entry->have_shared)
	r = write_entry(cursor->int_mboxname, cursor->uid,
			entry->entry->name, "",
			&entry->shared);
    if (!r && entry->have_priv)
	r = write_entry(cursor->int_mboxname, cursor->uid,
			entry->entry->name, sdata->userid,
			&entry->priv);

    return r;
}

static int annotation_set_mailboxopt(const annotate_cursor_t *cursor,
				     struct annotate_st_entry_list *entry,
				     struct storedata *sdata
					__attribute__((unused)),
				     void *rock)
{
    struct mailbox *mailbox = NULL;
    uint32_t flag = (unsigned long)rock;
    int r = 0;
    unsigned long newopts;

    r = mailbox_open_iwl(cursor->int_mboxname, &mailbox);
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

static int annotation_set_pop3showafter(const annotate_cursor_t *cursor,
				     struct annotate_st_entry_list *entry,
				     struct storedata *sdata
					__attribute__((unused)),
				     void *rock __attribute__((unused)))
{
    struct mailbox *mailbox = NULL;
    int r = 0;
    time_t date;

    if (entry->shared.s == NULL) {
	/* Effectively removes the annotation */
	date = 0;
    }
    else {
	r = time_from_rfc3501(entry->shared.s, &date);
	if (r < 0)
	    return IMAP_PROTOCOL_BAD_PARAMETERS;
    }

    r = mailbox_open_iwl(cursor->int_mboxname, &mailbox);
    if (r) return r;

    if (date != mailbox->i.pop3_show_after) {
	mailbox->i.pop3_show_after = date;
	mailbox_index_dirty(mailbox);
    }

    mailbox_close(&mailbox);

    return 0;
}

static int annotation_set_specialuse(const annotate_cursor_t *cursor,
				     struct annotate_st_entry_list *entry,
				     struct storedata *sdata
					 __attribute__((unused)),
				     void *rock __attribute__((unused)))
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

    if (entry->shared.s == NULL) {
	/* Effectively removes the annotation */
	val = NULL;
    }
    else {
	for (i = 0; valid_specialuse[i]; i++) {
	    if (!strcasecmp(valid_specialuse[i], entry->shared.s))
		break;
	    /* or without the leading '\' */
	    if (!strcasecmp(valid_specialuse[i]+1, entry->shared.s))
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
		    if (!strcasecmp(extra_val, entry->shared.s)) {
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

    r = mboxlist_setspecialuse(cursor->int_mboxname, val);

done:
    strarray_free(specialuse_extra);

    return r;
}

static int find_desc_store(const annotate_scope_t *scope,
			   const char *name,
			   const annotate_entrydesc_t **descp)
{
    const ptrarray_t *descs;
    const annotate_entrydesc_t *desc;
    int i;

    if (scope->which == ANNOTATION_SCOPE_SERVER)
	descs = &server_entries;
    else if (scope->which == ANNOTATION_SCOPE_MAILBOX)
	descs = &mailbox_entries;
    else if (scope->which == ANNOTATION_SCOPE_MESSAGE)
	descs = &message_entries;
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
    return IMAP_PERMISSION_DENIED;
}

int annotatemore_store(const annotate_scope_t *scope,
		       struct entryattlist *l,
		       struct namespace *namespace,
		       int isadmin,
		       const char *userid,
		       struct auth_state *auth_state)
{
    int r = 0;
    struct entryattlist *e = l;
    struct attvaluelist *av;
    struct storedata sdata;

    memset(&sdata, 0, sizeof(struct storedata));
    sdata.namespace = namespace;
    sdata.userid = userid;
    sdata.isadmin = isadmin;
    sdata.auth_state = auth_state;

    /* Build a list of callbacks for storing the annotations */
    while (e) {
	int attribs;
	const annotate_entrydesc_t *desc = NULL;
	struct annotate_st_entry_list *nentry = NULL;

	/* See if we support this entry */
	r = find_desc_store(scope, e->entry, &desc);
	if (r)
	    return r;

	/* Add this entry to our list only if it
	   applies to our particular server type */
	if ((desc->proxytype != PROXY_ONLY)
	    || proxy_store_func) {
	    nentry = xzmalloc(sizeof(struct annotate_st_entry_list));
	    nentry->next = sdata.entry_list;
	    nentry->entry = desc;
	    sdata.entry_list = nentry;
	}

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

    if (scope->which == ANNOTATION_SCOPE_SERVER) {

	if (sdata.entry_list) {
	    annotate_cursor_t cursor;

	    annotate_cursor_setup(&cursor, "", 0);

	    r = _annotate_store_entries(&sdata, &cursor);

	    if (!r) sync_log_annotation("");
	}
    }

    else if (scope->which == ANNOTATION_SCOPE_MAILBOX) {

	char mboxpat[MAX_MAILBOX_BUFFER];

	/* Reset state in store_cb */
	store_cb(NULL, 0, 0, 0);

	if (proxy_store_func) {
	    /* xxx better way to determine a size for this table? */
	    construct_hash_table(&sdata.server_table, 10, 1);
	}

	/* copy the pattern so we can change hiersep */
	strlcpy(mboxpat, scope->mailbox, sizeof(mboxpat));
	mboxname_hiersep_tointernal(namespace, mboxpat,
				    config_virtdomains ?
				    strcspn(mboxpat, "@") : 0);

	r = (*namespace->mboxlist_findall)(namespace, mboxpat,
					   isadmin, userid,
					   auth_state, store_cb,
					   &sdata);

	if (!r && !sdata.count) r = IMAP_MAILBOX_NONEXISTENT;

	if (proxy_store_func) {
	    if (!r) {
		/* proxy command to backends */
		struct proxy_rock prock = { NULL, NULL };
		prock.mbox_pat = scope->mailbox;
		prock.entryatts = l;
		hash_enumerate(&sdata.server_table, store_proxy, &prock);
	    }
	    free_hash_table(&sdata.server_table, NULL);
	}
    }
    else if (scope->which == ANNOTATION_SCOPE_MESSAGE) {

	annotate_cursor_t cursor;

	annotate_cursor_setup(&cursor, scope->mailbox, scope->uid);
	cursor.acl = scope->acl;

// 	if (proxy_store_func) {
// 	    /* xxx better way to determine a size for this table? */
// 	    construct_hash_table(&sdata.server_table, 10, 1);
// 	}
	r = _annotate_store_entries(&sdata, &cursor);

	if (!r) sync_log_annotation("");

// 	if (proxy_store_func) {
// 	    if (!r) {
// 		/* proxy command to backends */
// 		struct proxy_rock prock = { NULL, NULL };
// 		prock.mbox_pat = scope->mailbox;
// 		prock.entryatts = l;
// 		hash_enumerate(&sdata.server_table, store_proxy, &prock);
// 	    }
// 	    free_hash_table(&sdata.server_table, NULL);
// 	}

    }

    if (r)
	annotatemore_abort();

  cleanup:
    /* Free the entry list */
    while (sdata.entry_list) {
	struct annotate_st_entry_list *freeme = sdata.entry_list;
	sdata.entry_list = sdata.entry_list->next;
	free(freeme);
    }

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
	r = write_entry(rrock->newmboxname, rrock->newuid, entry, newuserid, value);
    }

    if (!rrock->copy && !r) {
	/* delete existing entry */
	struct buf dattrib = BUF_INITIALIZER;
	r = write_entry(mailbox, uid, entry, userid, &dattrib);
    }

    return r;
}

int annotatemore_rename(const char *oldmboxname, const char *newmboxname,
			const char *olduserid, const char *newuserid)
{
    int r;
    char *oldfname = NULL, *newfname = NULL;

    /* rewrite any per-folder annotations from the global db */
    r = annotatemore_begin();
    if (r)
	goto out;

    r = _annotate_rewrite(oldmboxname, 0, olduserid,
			  newmboxname, 0, newuserid,
			  /*copy*/0);
    if (r)
	goto out;

    /* rename the per-folder database */
    r = annotate_dbname(oldmboxname, &oldfname);
    if (r)
	goto out;
    r = annotate_dbname(newmboxname, &newfname);
    if (r)
	goto out;

    r = rename(oldfname, newfname);
    if (r < 0) {
	syslog(LOG_ERR, "DBERROR: error renaming %s to %s: %m",
	       oldfname, newfname);
	r = IMAP_IOERROR;
	goto out;
    }

    r = annotatemore_commit();

out:
    free(oldfname);
    free(newfname);
    if (r)
	annotatemore_abort();
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
    annotate_cursor_t cursor;

    annotate_cursor_setup(&cursor, oldmboxname, olduid);

    rrock.oldmboxname = oldmboxname;
    rrock.newmboxname = newmboxname;
    rrock.olduserid = olduserid;
    rrock.newuserid = newuserid;
    rrock.olduid = olduid;
    rrock.newuid = newuid;
    rrock.copy = copy;

    r = _annotate_find(&cursor, "*", &rename_cb, &rrock);

    if (r)
	annotatemore_abort();

    return r;
}

int annotatemore_delete(const char *mboxname)
{
    int r;
    char *fname = NULL;

    assert(mboxname);

    /* remove any per-folder annotations from the global db */
    r = annotatemore_begin();
    if (r)
	goto out;

    r = _annotate_rewrite(mboxname, /*olduid*/0, /*olduserid*/NULL,
			 /*newmboxname*/NULL, /*newuid*/0, /*newuserid*/NULL,
			 /*copy*/0);
    if (r)
	goto out;

    /* remove the entire per-folder database */
    r = annotate_dbname(mboxname, &fname);
    if (r)
	goto out;

    r = unlink(fname);
    if (r < 0) {
	syslog(LOG_ERR, "cannot unlink %s: %m", fname);
	r = IMAP_IOERROR;
	goto out;
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

/* Search in table for the value given by name and namelen
 * (name is null-terminated, but possibly more than just the key).
 * errmsg is used to hint the user where we failed
 */
int table_lookup(const struct annotate_attrib *table,
		 const char *name, size_t namelen, const char *errmsg)
{
    char errbuf[ANNOT_DEF_MAXLINELEN*2];
    int entry;

    for (entry = 0; table[entry].name &&
	     (strncasecmp(table[entry].name, name, namelen)
	      || table[entry].name[namelen] != '\0'); entry++);

    if (! table[entry].name) {
	sprintf(errbuf, "invalid %s at '%s'", errmsg, name);
	fatal(errbuf, EC_CONFIG);
    }
    return table[entry].entry;
}

/* Advance beyond the next ',', skipping whitespace,
 * fail if next non-space is no comma.
 */
char *consume_comma(char* p)
{
    char errbuf[ANNOT_DEF_MAXLINELEN*2];

    for (; *p && isspace(*p); p++);  
    if (*p != ',') {
	sprintf(errbuf,
		"',' expected, '%s' found parsing annotation definition", p);
	fatal(errbuf, EC_CONFIG);
    }
    p++;
    for (; *p && isspace(*p); p++);  

    return p;
}

/* Parses strings of the form value1 [ value2 [ ... ]].
 * value1 is mapped via table to ints and the result or'ed.
 * Whitespace is allowed between value names and punctuation.
 * The field must end in '\0' or ','.
 * s is advanced to '\0' or ','.
 * On error errmsg is used to identify item to be parsed.
 */
int parse_table_lookup_bitmask(const struct annotate_attrib *table,
                               char** s, const char* errmsg) 
{
    int result = 0;
    char *p, *p2;

    p = *s;
    do {
	p2 = p;
	for (; *p && (isalnum(*p) || *p=='.' || *p=='-' || *p=='_' || *p=='/');
	     p++);
	result |= table_lookup(table, p2, p-p2, errmsg);
	for (; *p && isspace(*p); p++);
    } while (*p && *p != ',');

    *s = p;
    return result;
}

static int normalise_attribs(int attribs)
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
	    syslog(LOG_WARNING, "annotation definitions file contains "
				"deprecated attribute names such as "
				"content-type or modified-since, ignoring");
    }

    return nattribs;
}

/* Create array of allowed annotations, both internally & externally defined */
static void init_annotation_definitions(void)
{
    char *p, *p2, *tmp;
    const char *filename;
    char aline[ANNOT_DEF_MAXLINELEN];
    char errbuf[ANNOT_DEF_MAXLINELEN*2];
    annotate_entrydesc_t *ae;
    int i;
    FILE* f;

    /* copy static entries into list */
    for (i = 0 ; server_builtin_entries[i].name ; i++)
	ptrarray_append(&server_entries, (void *)&server_builtin_entries[i]);

    /* copy static entries into list */
    for (i = 0 ; mailbox_builtin_entries[i].name ; i++)
	ptrarray_append(&mailbox_entries, (void *)&mailbox_builtin_entries[i]);

    /* copy static entries into list */
    for (i = 0 ; message_builtin_entries[i].name ; i++)
	ptrarray_append(&message_entries, (void *)&message_builtin_entries[i]);

    /* parse config file */
    filename = config_getstring(IMAPOPT_ANNOTATION_DEFINITIONS);

    if (!filename)
	return;
  
    f = fopen(filename,"r");
    if (! f) {
	sprintf(errbuf, "could not open annotation definition %s", filename);
	fatal(errbuf, EC_CONFIG);
    }
  
    while (fgets(aline, sizeof(aline), f)) {
	/* remove leading space, skip blank lines and comments */
	for (p = aline; *p && isspace(*p); p++);
	if (!*p || *p == '#') continue;

	/* note, we only do the most basic validity checking and may
	   be more restrictive than neccessary */

	ae = xzmalloc(sizeof(*ae));

	p2 = p;
	for (; *p && (isalnum(*p) ||
		      *p=='.' || *p=='-' || *p=='_' || *p=='/' || *p==':');
	     p++);
	/* TV-TODO: should test for empty */
	ae->name = xstrndup(p2, p-p2);

	if (!strncmp(ae->name, "/vendor/cmu/cyrus-imapd/", 24)) {
	    syslog(LOG_WARNING, "annotation definitions file contains an "
				"annotation in /vendor/cmu/cyrus-imapd/, ignoring");
	    free((char *)ae->name);
	    free(ae);
	    continue;
	}

	p = consume_comma(p);
  
	p2 = p;
	for (; *p && (isalnum(*p) || *p=='.' || *p=='-' || *p=='_' || *p=='/');
	     p++);

	switch (table_lookup(annotation_scope_names, p2, p-p2,
			 "annotation scope")) {
	case ANNOTATION_SCOPE_SERVER:
	    ptrarray_append(&server_entries, ae);
	    break;
	case ANNOTATION_SCOPE_MAILBOX:
	    ptrarray_append(&mailbox_entries, ae);
	    break;
	case ANNOTATION_SCOPE_MESSAGE:
	    if (!strncmp(ae->name, "/flags/", 7)) {
		/* RFC5257 reserves the /flags/ hierarchy for future use */
		syslog(LOG_WARNING, "annotation definitions file contains "
				    "a message annotation in /flags/, ignoring");
		free((char *)ae->name);
		free(ae);
		continue;
	    }
	    ptrarray_append(&message_entries, ae);
	    break;
	}

	p = consume_comma(p);
	p2 = p;
	for (; *p && (isalnum(*p) || *p=='.' || *p=='-' || *p=='_' || *p=='/');
	     p++);
	ae->type = table_lookup(attribute_type_names, p2, p-p2,
				"attribute type");

	p = consume_comma(p);
	ae->proxytype = parse_table_lookup_bitmask(annotation_proxy_type_names,
						   &p,
						   "annotation proxy type");

	p = consume_comma(p);
	ae->attribs = parse_table_lookup_bitmask(annotation_attributes,
						 &p,
						 "annotation attributes");
	ae->attribs = normalise_attribs(ae->attribs);

	p = consume_comma(p);
	p2 = p;
	for (; *p && (isalnum(*p) || *p=='.' || *p=='-' || *p=='_' || *p=='/');
	     p++);
	tmp = xstrndup(p2, p-p2);
	ae->extra_rights = cyrus_acl_strtomask(tmp);
	free(tmp);

	for (; *p && isspace(*p); p++);
	if (*p) {
	    sprintf(errbuf, "junk at end of line: '%s'", p);
	    fatal(errbuf, EC_CONFIG);
	}

	ae->get = annotation_get_fromdb;
	ae->set = annotation_set_todb;
	ae->rock = NULL;
    }

    fclose(f);
}
