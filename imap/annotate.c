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
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <errno.h>
#ifdef HAVE_INTTYPES_H
# include <inttypes.h>
#elif defined(HAVE_STDINT_H)
# include <stdint.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <ctype.h>
#include <sysexits.h>
#include <syslog.h>

#include "acl.h"
#include "assert.h"
#include "cyrusdb.h"
#include "glob.h"
#include "hash.h"
#include "imapd.h"
#include "global.h"
#include "times.h"
#include "mboxlist.h"
#include "partlist.h"
#include "util.h"
#include "xmalloc.h"
#include "ptrarray.h"
#include "xstrlcpy.h"
#include "xstrlcat.h"
#include "tok.h"
#include "quota.h"

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"

#include "annotate.h"
#include "sync_log.h"

#define DEBUG 0

#define ANNOTATION_SCOPE_UNKNOWN    (-1)
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
    int which;                  /* ANNOTATION_SCOPE_* */
    const mbentry_t *mbentry; /* for _MAILBOX */
    mbentry_t *ourmbentry;
    struct mailbox *mailbox;    /* for _MAILBOX, _MESSAGE */
    struct mailbox *ourmailbox;
    unsigned int uid;           /* for _MESSAGE */
    const char *acl;            /* for _MESSAGE */
    annotate_db_t *d;

    /* authentication state */
    const char *userid;
    int isadmin;
    const struct auth_state *auth_state;

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

    /* state for output_entryatt */
    struct attvaluelist *attvalues;
    char lastname[MAX_MAILBOX_PATH+1];  /* internal */
    char lastentry[MAX_MAILBOX_PATH+1];
    uint32_t lastuid;
    annotate_fetch_cb_t callback;
    void *callback_rock;

    /*
     * Storing.
     */
    /* number of mailboxes matching the pattern */
    unsigned count;

    /*
     * Silent. If set, mailboxes aren't dirtied for mailbox and
     * message annotation writes.
     */
    unsigned silent;
};

enum {
    ATTRIB_VALUE_SHARED =               (1<<0),
    ATTRIB_VALUE_PRIV =                 (1<<1),
    ATTRIB_SIZE_SHARED =                (1<<2),
    ATTRIB_SIZE_PRIV =                  (1<<3),
    ATTRIB_DEPRECATED =                 (1<<4)
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
    const char *name;           /* entry name */
    int type;                   /* entry type */
    annotation_proxy_t proxytype; /* mask of allowed server types */
    int attribs;                /* mask of allowed attributes */
    int extra_rights;           /* for set of shared mailbox annotations */
                /* function to get the entry */
    void (*get)(annotate_state_t *state,
                struct annotate_entry_list *entry);
               /* function to set the entry */
    int (*set)(annotate_state_t *state,
               struct annotate_entry_list *entry,
               int maywrite);
    void *rock;                 /* rock passed to get() function */
};

struct annotate_db
{
    annotate_db_t *next;
    int refcount;
    char *mboxname;
    char *filename;
    struct db *db;
    struct txn *txn;
    int in_txn;
};

#define DB config_annotation_db

static annotate_db_t *all_dbs_head = NULL;
static annotate_db_t *all_dbs_tail = NULL;
#define tid(d)  ((d)->in_txn ? &(d)->txn : NULL)
static int (*proxy_fetch_func)(const char *server, const char *mbox_pat,
                        const strarray_t *entry_pat,
                        const strarray_t *attribute_pat) = NULL;
static int (*proxy_store_func)(const char *server, const char *mbox_pat,
                        struct entryattlist *entryatts) = NULL;
static ptrarray_t message_entries = PTRARRAY_INITIALIZER;
static ptrarray_t mailbox_entries = PTRARRAY_INITIALIZER;
static ptrarray_t server_entries = PTRARRAY_INITIALIZER;

static void annotate_state_unset_scope(annotate_state_t *state);
static int annotate_state_set_scope(annotate_state_t *state,
                                    const mbentry_t *mbentry,
                                    struct mailbox *mailbox,
                                    unsigned int uid);
static void init_annotation_definitions(void);
static int annotation_set_tofile(annotate_state_t *state,
                                 struct annotate_entry_list *entry,
                                 int maywrite);
static int annotation_set_todb(annotate_state_t *state,
                               struct annotate_entry_list *entry,
                               int maywrite);
static int annotation_set_mailboxopt(annotate_state_t *state,
                                     struct annotate_entry_list *entry,
                                     int maywrite);
static int annotation_set_pop3showafter(annotate_state_t *state,
                                        struct annotate_entry_list *entry,
                                        int maywrite);
static int annotation_set_specialuse(annotate_state_t *state,
                                     struct annotate_entry_list *entry,
                                     int maywrite);
static int _annotate_rewrite(struct mailbox *oldmailbox,
                             uint32_t olduid,
                             const char *olduserid,
                             struct mailbox *newmailbox,
                             uint32_t newuid,
                             const char *newuserid,
                             int copy);
static int _annotate_may_store(annotate_state_t *state,
                               int is_shared,
                               const annotate_entrydesc_t *desc);
static void annotate_begin(annotate_db_t *d);
static void annotate_abort(annotate_db_t *d);
static int annotate_commit(annotate_db_t *d);

static void init_internal();

static int annotate_initialized = 0;
static int annotatemore_dbopen = 0;

/* String List Management */
/*
 * Append 's' to the strlist 'l'.
 */
EXPORTED void appendstrlist(struct strlist **l, char *s)
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
EXPORTED void appendstrlistpat(struct strlist **l, char *s)
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
EXPORTED void freestrlist(struct strlist *l)
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
EXPORTED void appendattvalue(struct attvaluelist **l,
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
EXPORTED void freeattvalues(struct attvaluelist *l)
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
EXPORTED void appendentryatt(struct entryattlist **l, const char *entry,
                    struct attvaluelist *attvalues)
{
    struct entryattlist **tail = l;

    while (*tail) tail = &(*tail)->next;

    *tail = (struct entryattlist *)xmalloc(sizeof(struct entryattlist));
    (*tail)->entry = xstrdup(entry);
    (*tail)->attvalues = attvalues;
    (*tail)->next = NULL;
}

EXPORTED void setentryatt(struct entryattlist **l, const char *entry,
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

EXPORTED char *dumpentryatt(const struct entryattlist *l)
{
    struct buf buf = BUF_INITIALIZER;

    const struct entryattlist *ee;
    buf_printf(&buf, "(");
    const char *sp = "";
    const struct attvaluelist *av;
    for (ee = l ; ee ; ee = ee->next) {
        buf_printf(&buf, "%s%s (", sp, ee->entry);
        const char *insp = "";
        for (av = ee->attvalues ; av ; av = av->next) {
            buf_printf(&buf, "%s%s %s", insp, av->attrib, buf_cstring(&av->value));
            insp = " ";
        }
        buf_printf(&buf, ")");
        sp = " ";
    }
    buf_printf(&buf, ")");

    char *res = buf_release(&buf);
    buf_free(&buf);

    return res;
}

EXPORTED void clearentryatt(struct entryattlist **l, const char *entry,
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
        return; /* entry not found */

    for (pav = &(*pea)->attvalues ; *pav ; pav = &(*pav)->next) {
        if (!strcmp((*pav)->attrib, attrib))
            break;
    }
    av = *pav;
    if (!av)
        return; /* attrib not found */

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
 * Count the storage used by entryattlist 'l'
 */
EXPORTED size_t sizeentryatts(const struct entryattlist *l)
{
    size_t sz = 0;
    struct attvaluelist *av;

    for ( ; l ; l = l->next)
        for (av = l->attvalues ; av ; av = av->next)
            sz += av->value.len;
    return sz;
}

/*
 * Free the entryattlist 'l'
 */
EXPORTED void freeentryatts(struct entryattlist *l)
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

static void done_cb(void*rock __attribute__((unused)))
{
    if (annotatemore_dbopen) {
        annotatemore_close();
    }
    annotate_done();
}

static void init_internal()
{
    if (!annotate_initialized) {
        annotate_init(NULL, NULL);
        cyrus_modules_add(done_cb, NULL);
    }
    if (!annotatemore_dbopen) {
        annotatemore_open();
    }
}

/* must be called after cyrus_init */
EXPORTED void annotate_init(int (*fetch_func)(const char *, const char *,
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
    annotate_initialized = 1;
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
static int annotate_dbname_mbentry(const mbentry_t *mbentry,
                                   char **fnamep)
{
    const char *conf_fname;

    if (mbentry) {
        /* per-mbox database */
        conf_fname = mbentry_metapath(mbentry, META_ANNOTATIONS, /*isnew*/0);
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

static int annotate_dbname_mailbox(struct mailbox *mailbox, char **fnamep)
{
    const char *conf_fname;

    if (!mailbox) return annotate_dbname_mbentry(NULL, fnamep);

    conf_fname = mailbox_meta_fname(mailbox, META_ANNOTATIONS);
    if (!conf_fname) return IMAP_MAILBOX_BADNAME;
    *fnamep = xstrdup(conf_fname);

    return 0;
}


static int annotate_dbname(const char *mboxname, char **fnamep)
{
    int r = 0;
    mbentry_t *mbentry = NULL;

    if (mboxname) {
        r = mboxlist_lookup(mboxname, &mbentry, NULL);
        if (r) goto out;
    }

    r = annotate_dbname_mbentry(mbentry, fnamep);

out:
    mboxlist_entry_free(&mbentry);
    return r;
}

static int _annotate_getdb(const char *mboxname,
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

    r = cyrusdb_open(DB, fname, dbflags | CYRUSDB_CONVERT, &db);
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
    d->mboxname = xstrdupnull(mboxname);
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

HIDDEN int annotate_getdb(const char *mboxname, annotate_db_t **dbp)
{
    if (!mboxname || !*mboxname) {
        syslog(LOG_ERR, "IOERROR: annotate_getdb called with no mboxname");
        return IMAP_INTERNAL;   /* we don't return the global db */
    }
    /* synthetic UID '1' forces per-mailbox mode */
    return _annotate_getdb(mboxname, 1, CYRUSDB_CREATE, dbp);
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

    r = cyrusdb_close(d->db);
    if (r)
        syslog(LOG_ERR, "DBERROR: error closing annotations %s: %s",
               d->filename, cyrusdb_strerror(r));

    free(d->filename);
    free(d->mboxname);
    memset(d, 0, sizeof(*d));   /* JIC */
    free(d);
}

HIDDEN void annotate_putdb(annotate_db_t **dbp)
{
    annotate_db_t *d;

    if (!dbp || !(d = *dbp))
        return;
    assert(d->refcount > 0);
    if (--d->refcount == 0) {
        if (d->in_txn && d->txn) {
            syslog(LOG_ERR, "IOERROR: dropped last reference on "
                            "database %s with uncommitted updates, "
                            "aborting - DATA LOST!",
                            d->filename);
            annotate_abort(d);
        }
        assert(!d->in_txn);
        annotate_closedb(d);
    }
    *dbp = NULL;
}

EXPORTED void annotatemore_open(void)
{
    int r;
    annotate_db_t *d = NULL;

    /* force opening the global annotations db */
    r = _annotate_getdb(NULL, 0, CYRUSDB_CREATE, &d);
    if (r)
        fatal("can't open global annotations database", EX_TEMPFAIL);

    annotatemore_dbopen = 1;
}

EXPORTED void annotatemore_close(void)
{
    /* close all the open databases */
    while (all_dbs_head)
        annotate_closedb(all_dbs_head);

    annotatemore_dbopen = 0;
}

/* Begin a txn if one is not already started.  Can be called multiple
 * times */
static void annotate_begin(annotate_db_t *d)
{
    if (d)
        d->in_txn = 1;
}

static void annotate_abort(annotate_db_t *d)
{
    /* don't double-abort */
    if (!d || !d->in_txn) return;

    if (d->txn) {
#if DEBUG
        syslog(LOG_ERR, "Aborting annotations db %s\n", d->filename);
#endif
        cyrusdb_abort(d->db, d->txn);
    }
    d->txn = NULL;
    d->in_txn = 0;
}

static int annotate_commit(annotate_db_t *d)
{
    int r = 0;

    /* silently succeed if not in a txn */
    if (!d || !d->in_txn) return 0;

    if (d->txn) {
#if DEBUG
        syslog(LOG_ERR, "Committing annotations db %s\n", d->filename);
#endif
        r = cyrusdb_commit(d->db, d->txn);
        if (r)
            r = IMAP_IOERROR;
        d->txn = NULL;
    }
    d->in_txn = 0;

    return r;
}

EXPORTED void annotate_done(void)
{
    /* DB->done() handled by cyrus_done() */
    if (annotatemore_dbopen) {
        annotatemore_close();
    }
    annotate_initialized = 0;
}

static int make_key(const char *mboxname,
                    unsigned int uid,
                    const char *entry,
                    const char *userid,
                    char *key, size_t keysize)
{
    int keylen;

    if (!uid) {
        strlcpy(key, mboxname, keysize);
    }
    else if (uid == ANNOTATE_ANY_UID) {
        strlcpy(key, "*", keysize);
    }
    else {
        snprintf(key, keysize, "%u", uid);
    }
    keylen = strlen(key) + 1;
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
    static struct buf keybuf;
    const char *p;
    const char *end;

    buf_setmap(&keybuf, key, keysize);
    buf_putc(&keybuf, '\0'); /* safety tricks due to broken FM code */
    p = buf_cstring(&keybuf);
    end = p + keysize;

    /*
     * paranoia: split the key into fields on NUL characters.
     * We would use strarray_nsplit() for this, except that
     * by design that function cannot split on NULs and does
     * not handle embedded NULs.
     */

    if (d->mboxname) {
        *mboxnamep = d->mboxname;
        *uidp = 0;
        while (*p && p < end) *uidp = (10 * (*uidp)) + (*p++ - '0');
        if (p < end) p++;
        else return IMAP_ANNOTATION_BADENTRY;
    }
    else {
        /* global db for mailnbox & server scope annotations */
        *uidp = 0;
        *mboxnamep = p;
        while (*p && p < end) p++;
        if (p < end) p++;
        else return IMAP_ANNOTATION_BADENTRY;
    }

    *entryp = p; /* XXX: trailing NULLs on non-userid keys?  Bogus just at FM */
    while (*p && p < end) p++;
    if (p < end && !*p)
        *useridp = p+1;
    else
        *useridp = NULL;
    return 0;
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

static int split_attribs(const char *data, int datalen,
                         struct buf *value, struct annotate_metadata *mdata)
{
    unsigned long tmp; /* for alignment */
    const char *tmps;
    const char *end = data + datalen;

    /* initialize metadata */
    memset(mdata, 0, sizeof(struct annotate_metadata));

    /* xxx sanity check the data? */
    if (datalen <= 0)
            return 1;
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
     * data. We don't care about those anymore, so we just ignore them
     * and skip to the entry's metadata.
     */
    tmps = data + ntohl(tmp) + 1;  /* Skip zero-terminated value */
    if (tmps < end) {
        tmps += strlen(tmps) + 1;      /* Skip zero-terminated content-type */
        tmps += sizeof(unsigned long); /* Skip modifiedsince value */
    }

    if (tmps < end) {
        /* make sure ntohll's input is correctly aligned */
        modseq_t modseq;
        memcpy(&modseq, tmps, sizeof(modseq));
        mdata->modseq = ntohll(modseq);
        tmps += sizeof(modseq_t);
    }

    if (tmps < end) {
        mdata->flags = *tmps;
        tmps++;
    }

    /* normalise deleted entries */
    if (mdata->flags & ANNOTATE_FLAG_DELETED) {
        buf_reset(value);
    }

    return 0;
}

struct find_rock {
    struct glob *mglob;
    struct glob *eglob;
    unsigned int uid;
    modseq_t since_modseq;
    annotate_db_t *d;
    annotatemore_find_proc_t proc;
    void *rock;
    int flags;
};

static int find_p(void *rock, const char *key, size_t keylen,
                const char *data __attribute__((unused)),
                size_t datalen __attribute__((unused)))
{
    struct find_rock *frock = (struct find_rock *) rock;
    const char *mboxname, *entry, *userid;
    unsigned int uid;
    int r;

    r = split_key(frock->d, key, keylen, &mboxname,
                  &uid, &entry, &userid);
    if (r < 0)
        return 0;

    if (!userid)
        return 0;

    if (frock->uid &&
        frock->uid != ANNOTATE_ANY_UID &&
        frock->uid != uid)
        return 0;
    if (!GLOB_MATCH(frock->mglob, mboxname))
        return 0;
    if (!GLOB_MATCH(frock->eglob, entry))
        return 0;
    return 1;
}

static int find_cb(void *rock, const char *key, size_t keylen,
                   const char *data, size_t datalen)
{
    struct find_rock *frock = (struct find_rock *) rock;
    const char *mboxname, *entry, *userid;
    unsigned int uid;
    char newkey[MAX_MAILBOX_PATH+1];
    size_t newkeylen;
    struct buf value = BUF_INITIALIZER;
    struct annotate_metadata mdata;
    int r;

    assert(keylen < MAX_MAILBOX_PATH);

    r = split_key(frock->d, key, keylen, &mboxname,
                  &uid, &entry, &userid);
    if (r) {
        syslog(LOG_ERR, "find_cb: can't split bogus key %*.s", (int)keylen, key);
        return r;
    }

    newkeylen = make_key(mboxname, uid, entry, userid, newkey, sizeof(newkey));
    if (keylen != newkeylen || strncmp(newkey, key, keylen)) {
        syslog(LOG_ERR, "find_cb: bogus key %s %d %s %s (%d %d)", mboxname, uid, entry, userid, (int)keylen, (int)newkeylen);
    }

    r = split_attribs(data, datalen, &value, &mdata);
    if (r) {
        buf_free(&value);
        return r;
    }
#if DEBUG
    syslog(LOG_ERR, "find_cb: found key %s in %s with modseq " MODSEQ_FMT,
            key_as_string(frock->d, key, keylen), frock->d->filename, mdata.modseq);
#endif

    if (frock->since_modseq && frock->since_modseq >= mdata.modseq) {
#if DEBUG
        syslog(LOG_ERR,"find_cb: ignoring key %s: " " modseq " MODSEQ_FMT " is <= " MODSEQ_FMT,
                key_as_string(frock->d, key, keylen), mdata.modseq, frock->since_modseq);
#endif
        buf_free(&value);
        return 0;
    }

    if (((mdata.flags & ANNOTATE_FLAG_DELETED) || !buf_len(&value)) &&
        !(frock->flags & ANNOTATE_TOMBSTONES)) {
#if DEBUG
    syslog(LOG_ERR, "find_cb: ignoring key %s, tombstones are ignored",
            key_as_string(frock->d, key, keylen));
#endif
        buf_free(&value);
        return 0;
    }

    if (!r) r = frock->proc(mboxname, uid, entry, userid, &value, &mdata,
                            frock->rock);
    buf_free(&value);
    return r;
}

EXPORTED int annotatemore_findall(const char *mboxname, /* internal */
                         unsigned int uid,
                         const char *entry,
                         modseq_t since_modseq,
                         annotatemore_find_proc_t proc,
                         void *rock,
                         int flags)
{
    char key[MAX_MAILBOX_PATH+1], *p;
    size_t keylen;
    int r;
    struct find_rock frock;

    init_internal();

    assert(mboxname);
    assert(entry);
    frock.mglob = glob_init(mboxname, '.');
    frock.eglob = glob_init(entry, '/');
    frock.uid = uid;
    frock.proc = proc;
    frock.rock = rock;
    frock.since_modseq = since_modseq;
    frock.flags = flags;
    r = _annotate_getdb(mboxname, uid, 0, &frock.d);
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

    r = cyrusdb_foreach(frock.d->db, key, keylen, &find_p, &find_cb,
                        &frock, tid(frock.d));

out:
    glob_free(&frock.mglob);
    glob_free(&frock.eglob);
    annotate_putdb(&frock.d);

    return r;
}
/***************************  Annotate State Management  ***************************/

EXPORTED annotate_state_t *annotate_state_new(void)
{
    annotate_state_t *state;

    state = xzmalloc(sizeof(*state));
    state->which = ANNOTATION_SCOPE_UNKNOWN;

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


static void annotate_state_free(annotate_state_t **statep)
{
    annotate_state_t *state = *statep;

    if (!state)
        return;

    annotate_state_finish(state);
    annotate_state_unset_scope(state);
    free(state);
    *statep = NULL;
}

EXPORTED void annotate_state_begin(annotate_state_t *state)
{
    init_internal();

    annotate_begin(state->d);
}

EXPORTED void annotate_state_abort(annotate_state_t **statep)
{
    if (*statep)
        annotate_abort((*statep)->d);

    annotate_state_free(statep);
}

EXPORTED int annotate_state_commit(annotate_state_t **statep)
{
    int r = 0;
    if (*statep)
        r = annotate_commit((*statep)->d);

    annotate_state_free(statep);
    return r;
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

EXPORTED void annotate_state_set_auth(annotate_state_t *state,
                             int isadmin, const char *userid,
                             const struct auth_state *auth_state)
{
    /* Note: lmtpd sometimes calls through the append code with
     * auth_state=NULL, so we cannot rely on it being non-NULL */
    state->userid = userid;
    state->isadmin = isadmin;
    state->auth_state = auth_state;
}

EXPORTED int annotate_state_set_server(annotate_state_t *state)
{
    return annotate_state_set_scope(state, NULL, NULL, 0);
}

EXPORTED int annotate_state_set_mailbox(annotate_state_t *state,
                                struct mailbox *mailbox)
{
    return annotate_state_set_scope(state, NULL, mailbox, 0);
}

EXPORTED int annotate_state_set_mailbox_mbe(annotate_state_t *state,
                                   const mbentry_t *mbentry)
{
    return annotate_state_set_scope(state, mbentry, NULL, 0);
}

HIDDEN int annotate_state_set_message(annotate_state_t *state,
                               struct mailbox *mailbox,
                               unsigned int uid)
{
    return annotate_state_set_scope(state, NULL, mailbox, uid);
}

/* unset any state from a previous scope */
static void annotate_state_unset_scope(annotate_state_t *state)
{
    init_internal();

    if (state->ourmailbox)
        mailbox_close(&state->ourmailbox);
    state->mailbox = NULL;

    if (state->ourmbentry)
        mboxlist_entry_free(&state->ourmbentry);
    state->mbentry = NULL;

    state->uid = 0;
    state->which = ANNOTATION_SCOPE_UNKNOWN;
    annotate_putdb(&state->d);
}

static int annotate_state_set_scope(annotate_state_t *state,
                                    const mbentry_t *mbentry,
                                    struct mailbox *mailbox,
                                    unsigned int uid)
{
    int r = 0;
    annotate_db_t *oldd = NULL;
    int oldwhich = state->which;

    init_internal();

    /* Carefully preserve the reference on the old DB just in case it
     * turns out to be the same as the new DB, so we avoid the overhead
     * of an unnecessary cyrusdb_open/close pair. */
    oldd = state->d;
    state->d = NULL;

    annotate_state_unset_scope(state);

    if (mbentry) {
        assert(!mailbox);
        assert(!uid);
        if (!mbentry->server) {
            /* local mailbox */
            r = mailbox_open_iwl(mbentry->name, &mailbox);
            if (r)
                goto out;
            state->ourmailbox = mailbox;
        }
        state->mbentry = mbentry;
        state->which = ANNOTATION_SCOPE_MAILBOX;
    }

    else if (uid) {
        assert(mailbox);
        state->which = ANNOTATION_SCOPE_MESSAGE;
    }
    else if (mailbox) {
        assert(!uid);
        state->which = ANNOTATION_SCOPE_MAILBOX;
    }
    else {
        assert(!mailbox);
        assert(!uid);
        state->which = ANNOTATION_SCOPE_SERVER;
    }
    assert(oldwhich == ANNOTATION_SCOPE_UNKNOWN ||
           oldwhich == state->which);
    state->mailbox = mailbox;
    state->uid = uid;

    r = _annotate_getdb(mailbox ? mailbox->name : NULL, uid,
                        CYRUSDB_CREATE, &state->d);

out:
    annotate_putdb(&oldd);
    return r;
}

static int annotate_state_need_mbentry(annotate_state_t *state)
{
    int r = 0;

    if (!state->mbentry && state->mailbox) {
        r = mboxlist_lookup(state->mailbox->name, &state->ourmbentry, NULL);
        if (r) {
            syslog(LOG_ERR, "Failed to lookup mbentry for %s: %s",
                    state->mailbox->name, error_message(r));
            goto out;
        }
        state->mbentry = state->ourmbentry;
    }

out:
    return r;
}

/***************************  Annotation Fetching  ***************************/

static void flush_entryatt(annotate_state_t *state)
{
    if (!state->attvalues)
        return;     /* nothing to flush */

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
    char key[MAX_MAILBOX_PATH+1]; /* XXX MAX_MAILBOX_NAME + entry + userid */
    struct buf buf = BUF_INITIALIZER;

    /* We don't put any funny interpretations on NULL values for
     * some of these anymore, now that the dirty hacks are gone. */
    assert(state);
    assert(entry);
    assert(userid);
    assert(value);

    if (state->mailbox)
        mboxname = state->mailbox->name;
    else if (state->mbentry)
        mboxname = state->mbentry->name;
    else
        mboxname = "";
    /* @mboxname is now an internal mailbox name */

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

    if (!userid[0]) { /* shared annotation */
        if ((state->attribs & ATTRIB_VALUE_SHARED)) {
            appendattvalue(&state->attvalues, "value.shared", value);
            state->found |= ATTRIB_VALUE_SHARED;
        }

        if ((state->attribs & ATTRIB_SIZE_SHARED)) {
            buf_reset(&buf);
            buf_printf(&buf, SIZE_T_FMT, value->len);
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
            buf_printf(&buf, SIZE_T_FMT, value->len);
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
        assert(state->mailbox || state->mbentry);

        /* Make sure its a local mailbox annotation */
        if (state->mbentry && state->mbentry->server)
            return 0;

        if (state->mailbox) acl = state->mailbox->acl;
        else if (state->mbentry) acl = state->mbentry->acl;
        /* RFC5464 is a trifle vague about access control for mailbox
         * annotations but this seems to be compliant */
        needed = ACL_LOOKUP|ACL_READ;
        /* fall through to ACL check */
    }
    else if (state->which == ANNOTATION_SCOPE_MESSAGE) {
        assert(state->mailbox);
        acl = state->mailbox->acl;
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
    uint64_t tavail = 0;
    struct buf value = BUF_INITIALIZER;

    (void) partlist_local_find_freespace_most(0, NULL, NULL, &tavail, NULL);
    buf_printf(&value, "%" PRIuMAX, (uintmax_t)tavail);
    output_entryatt(state, entry->name, "", &value);
    buf_free(&value);
}

static void annotation_get_freespace_total(annotate_state_t *state,
                     struct annotate_entry_list *entry)
{
    uint64_t tavail = 0;
    uint64_t ttotal = 0;
    struct buf value = BUF_INITIALIZER;

    (void) partlist_local_find_freespace_most(0, NULL, NULL, &tavail, &ttotal);
    buf_printf(&value, "%" PRIuMAX ";%" PRIuMAX, (uintmax_t)tavail, (uintmax_t)ttotal);
    output_entryatt(state, entry->name, "", &value);
    buf_free(&value);
}

static void annotation_get_freespace_percent_most(annotate_state_t *state,
                     struct annotate_entry_list *entry)
{
    uint64_t avail = 0;
    uint64_t total = 0;
    struct buf value = BUF_INITIALIZER;

    (void) partlist_local_find_freespace_most(1, &avail, &total, NULL, NULL);
    buf_printf(&value, "%" PRIuMAX ";%" PRIuMAX, (uintmax_t)avail, (uintmax_t)total);
    output_entryatt(state, entry->name, "", &value);
    buf_free(&value);
}

static void annotation_get_server(annotate_state_t *state,
                                  struct annotate_entry_list *entry)
{
    struct buf value = BUF_INITIALIZER;
    int r;

    assert(state);
    assert(state->which == ANNOTATION_SCOPE_MAILBOX);
    r = annotate_state_need_mbentry(state);
    assert(r == 0);

    /* Make sure its a remote mailbox */
    if (!state->mbentry->server) goto out;

    /* Check ACL */
    /* Note that we use a weaker form of access control than
     * normal - we only check for ACL_LOOKUP and we don't refuse
     * access if the mailbox is not local */
    if (!state->isadmin &&
        (!state->mbentry->acl ||
         !(cyrus_acl_myrights(state->auth_state, state->mbentry->acl) & ACL_LOOKUP)))
        goto out;

    buf_appendcstr(&value, state->mbentry->server);

    output_entryatt(state, entry->name, "", &value);
out:
    buf_free(&value);
}

static void annotation_get_partition(annotate_state_t *state,
                                     struct annotate_entry_list *entry)
{
    struct buf value = BUF_INITIALIZER;
    int r;

    assert(state);
    assert(state->which == ANNOTATION_SCOPE_MAILBOX);
    r = annotate_state_need_mbentry(state);
    assert(r == 0);

    /* Make sure its a local mailbox */
    if (state->mbentry->server) goto out;

    /* Check ACL */
    if (!state->isadmin &&
        (!state->mbentry->acl ||
         !(cyrus_acl_myrights(state->auth_state, state->mbentry->acl) & ACL_LOOKUP)))
        goto out;

    buf_appendcstr(&value, state->mbentry->partition);

    output_entryatt(state, entry->name, "", &value);
out:
    buf_free(&value);
}

static void annotation_get_annotsize(annotate_state_t *state,
                                struct annotate_entry_list *entry)
{
    struct mailbox *mailbox = state->mailbox;
    struct buf value = BUF_INITIALIZER;

    assert(mailbox);

    buf_printf(&value, QUOTA_T_FMT, mailbox->i.quota_annot_used);
    output_entryatt(state, entry->name, "", &value);
    buf_free(&value);
}

static void annotation_get_size(annotate_state_t *state,
                                struct annotate_entry_list *entry)
{
    struct mailbox *mailbox = state->mailbox;
    struct buf value = BUF_INITIALIZER;

    assert(mailbox);

    buf_printf(&value, QUOTA_T_FMT, mailbox->i.quota_mailbox_used);
    output_entryatt(state, entry->name, "", &value);
    buf_free(&value);
}

static void annotation_get_lastupdate(annotate_state_t *state,
                                      struct annotate_entry_list *entry)
{
    struct stat sbuf;
    char valuebuf[RFC3501_DATETIME_MAX+1];
    struct buf value = BUF_INITIALIZER;
    char *fname;
    int r;

    r = annotate_state_need_mbentry(state);
    if (r)
        goto out;

    fname = mbentry_metapath(state->mbentry, META_INDEX, 0);
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
    struct mailbox *mailbox = state->mailbox;
    char valuebuf[RFC3501_DATETIME_MAX+1];
    struct buf value = BUF_INITIALIZER;

    assert(mailbox);

    if (mailbox->i.pop3_last_login) {
        time_to_rfc3501(mailbox->i.pop3_last_login, valuebuf,
                        sizeof(valuebuf));
        buf_appendcstr(&value, valuebuf);
    }

    output_entryatt(state, entry->name, "", &value);
    buf_free(&value);
}

static void annotation_get_mailboxopt(annotate_state_t *state,
                                      struct annotate_entry_list *entry)
{
    struct mailbox *mailbox = state->mailbox;
    uint32_t flag = (unsigned long)entry->desc->rock;
    struct buf value = BUF_INITIALIZER;

    assert(mailbox);

    buf_appendcstr(&value,
                   (mailbox->i.options & flag ? "true" : "false"));
    output_entryatt(state, entry->name, "", &value);
    buf_free(&value);
}

static void annotation_get_pop3showafter(annotate_state_t *state,
                                         struct annotate_entry_list *entry)
{
    struct mailbox *mailbox = state->mailbox;
    char valuebuf[RFC3501_DATETIME_MAX+1];
    struct buf value = BUF_INITIALIZER;

    assert(mailbox);

    if (mailbox->i.pop3_show_after)
    {
        time_to_rfc3501(mailbox->i.pop3_show_after, valuebuf, sizeof(valuebuf));
        buf_appendcstr(&value, valuebuf);
    }

    output_entryatt(state, entry->name, "", &value);
    buf_free(&value);
}

static void annotation_get_synccrcs(annotate_state_t *state,
                                    struct annotate_entry_list *entry)
{
    struct mailbox *mailbox = state->mailbox;
    struct buf value = BUF_INITIALIZER;

    assert(mailbox);

    buf_printf(&value, "%u %u", mailbox->i.synccrcs.basic,
                                mailbox->i.synccrcs.annot);

    output_entryatt(state, entry->name, "", &value);
    buf_free(&value);
}

static void annotation_get_foldermodseq(annotate_state_t *state,
                                        struct annotate_entry_list *entry)
{
    struct buf value = BUF_INITIALIZER;

    assert(state);
    annotate_state_need_mbentry(state);
    assert(state->mbentry);

    buf_printf(&value, "%llu", state->mbentry->foldermodseq);
    output_entryatt(state, entry->name, "", &value);

    buf_free(&value);
}

static void annotation_get_usermodseq(annotate_state_t *state,
                                      struct annotate_entry_list *entry)
{
    struct buf value = BUF_INITIALIZER;
    struct mboxname_counters counters;
    char *mboxname = NULL;

    memset(&counters, 0, sizeof(struct mboxname_counters));

    assert(state);
    assert(state->userid);

    mboxname = mboxname_user_mbox(state->userid, NULL);
    mboxname_read_counters(mboxname, &counters);

    buf_printf(&value, "%llu", counters.highestmodseq);

    output_entryatt(state, entry->name, state->userid, &value);
    free(mboxname);
    buf_free(&value);
}

static void annotation_get_usercounters(annotate_state_t *state,
                                        struct annotate_entry_list *entry)
{
    struct buf value = BUF_INITIALIZER;
    struct mboxname_counters counters;
    char *mboxname = NULL;

    assert(state);
    assert(state->userid);

    mboxname = mboxname_user_mbox(state->userid, NULL);
    int r = mboxname_read_counters(mboxname, &counters);

    if (!r) buf_printf(&value, "%u %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %u",
                       counters.version, counters.highestmodseq,
                       counters.mailmodseq, counters.caldavmodseq,
                       counters.carddavmodseq, counters.notesmodseq,
                       counters.mailfoldersmodseq, counters.caldavfoldersmodseq,
                       counters.carddavfoldersmodseq, counters.notesfoldersmodseq,
                       counters.quotamodseq, counters.raclmodseq,
                       counters.uidvalidity);

    output_entryatt(state, entry->name, state->userid, &value);
    free(mboxname);
    buf_free(&value);
}

static void annotation_get_uniqueid(annotate_state_t *state,
                                    struct annotate_entry_list *entry)
{
    struct buf value = BUF_INITIALIZER;

    assert(state->mailbox);

    if (state->mailbox->uniqueid)
        buf_appendcstr(&value, state->mailbox->uniqueid);

    output_entryatt(state, entry->name, "", &value);
    buf_free(&value);
}

static int rw_cb(const char *mailbox __attribute__((unused)),
                 uint32_t uid __attribute__((unused)),
                 const char *entry, const char *userid,
                 const struct buf *value,
                 const struct annotate_metadata *mdata __attribute__((unused)),
                 void *rock)
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
    const char *mboxname = (state->mailbox ? state->mailbox->name : "");
    state->found = 0;

    annotatemore_findall(mboxname, state->uid, entry->name, 0, &rw_cb, state, 0);

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
    },
    {
        /* RFC5257 defines /comment with both .shared & .priv */
        "/comment",
        ATTRIB_TYPE_STRING,
        BACKEND_ONLY,
        ATTRIB_VALUE_SHARED | ATTRIB_VALUE_PRIV,
        0,
        annotation_get_fromdb,
        annotation_set_todb,
        NULL
    },
    {
        /* we use 'basethrid' to support split threads */
        IMAP_ANNOT_NS "basethrid",
        ATTRIB_TYPE_STRING,
        BACKEND_ONLY,
        ATTRIB_VALUE_SHARED | ATTRIB_VALUE_PRIV,
        0,
        annotation_get_fromdb,
        annotation_set_todb,
        NULL
    },
    {
        /* prior to version 12, there was no storage for thrid, so it became an annotation */
        IMAP_ANNOT_NS "thrid",
        ATTRIB_TYPE_STRING,
        BACKEND_ONLY,
        ATTRIB_VALUE_SHARED | ATTRIB_VALUE_PRIV,
        0,
        annotation_get_fromdb,
        annotation_set_todb,
        NULL
    },
    {
        /* prior to version 15, there was no storage for savedate, so it became an annotation */
        IMAP_ANNOT_NS "savedate",
        ATTRIB_TYPE_STRING,
        BACKEND_ONLY,
        ATTRIB_VALUE_SHARED | ATTRIB_VALUE_PRIV,
        0,
        annotation_get_fromdb,
        annotation_set_todb,
        NULL
    },
    {
        /* prior to version 16, there was no storage for createdmodseq, so it became an annotation */
        IMAP_ANNOT_NS "createdmodseq",
        ATTRIB_TYPE_STRING,
        BACKEND_ONLY,
        ATTRIB_VALUE_SHARED | ATTRIB_VALUE_PRIV,
        0,
        annotation_get_fromdb,
        annotation_set_todb,
        NULL
    },
    {
        /* Deprecated in favor of "snoozed" */
        IMAP_ANNOT_NS "snoozed-until",
        ATTRIB_TYPE_STRING,
        BACKEND_ONLY,
        ATTRIB_VALUE_SHARED,
        0,
        annotation_get_fromdb,
        NULL,
        NULL
    },
    {
        IMAP_ANNOT_NS "snoozed",
        ATTRIB_TYPE_STRING,
        BACKEND_ONLY,
        ATTRIB_VALUE_SHARED,
        0,
        annotation_get_fromdb,
        annotation_set_todb,
        NULL
    },
    { NULL, 0, ANNOTATION_PROXY_T_INVALID, 0, 0, NULL, NULL, NULL }
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
         * RFC6154 defines /private/specialuse.
         */
        "/specialuse",
        ATTRIB_TYPE_STRING,
        BACKEND_ONLY,
        ATTRIB_VALUE_PRIV,
        0,
        annotation_get_fromdb,
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
        IMAP_ANNOT_NS "annotsize",
        ATTRIB_TYPE_STRING,
        BACKEND_ONLY,
        ATTRIB_VALUE_SHARED,
        0,
        annotation_get_annotsize,
        /*set*/NULL,
        NULL
    },{
        IMAP_ANNOT_NS "archive",
        ATTRIB_TYPE_UINT,
        BACKEND_ONLY,
        ATTRIB_VALUE_SHARED,
        ACL_ADMIN,
        annotation_get_fromdb,
        annotation_set_todb,
        NULL
    },{
        IMAP_ANNOT_NS "delete",
        ATTRIB_TYPE_UINT,
        BACKEND_ONLY,
        ATTRIB_VALUE_SHARED,
        ACL_ADMIN,
        annotation_get_fromdb,
        annotation_set_todb,
        NULL
    },{
        IMAP_ANNOT_NS "duplicatedeliver",
        ATTRIB_TYPE_BOOLEAN,
        BACKEND_ONLY,
        ATTRIB_VALUE_SHARED,
        0,
        annotation_get_mailboxopt,
        annotation_set_mailboxopt,
        (void *)OPT_IMAP_DUPDELIVER
    },{
        IMAP_ANNOT_NS "expire",
        ATTRIB_TYPE_UINT,
        BACKEND_ONLY,
        ATTRIB_VALUE_SHARED,
        ACL_ADMIN,
        annotation_get_fromdb,
        annotation_set_todb,
        NULL
    },{
        IMAP_ANNOT_NS "lastpop",
        ATTRIB_TYPE_STRING,
        BACKEND_ONLY,
        ATTRIB_VALUE_SHARED,
        0,
        annotation_get_lastpop,
        /*set*/NULL,
        NULL
    },{
        IMAP_ANNOT_NS "hasalarms",
        ATTRIB_TYPE_BOOLEAN,
        BACKEND_ONLY,
        ATTRIB_VALUE_SHARED,
        0,
        annotation_get_mailboxopt,
        /*set*/NULL,
        (void *)OPT_IMAP_HAS_ALARMS
    },{
        IMAP_ANNOT_NS "foldermodseq",
        ATTRIB_TYPE_UINT,
        BACKEND_ONLY,
        ATTRIB_VALUE_SHARED,
        0,
        annotation_get_foldermodseq,
        /*set*/NULL,
        NULL
    },{
        IMAP_ANNOT_NS "lastupdate",
        ATTRIB_TYPE_STRING,
        BACKEND_ONLY,
        ATTRIB_VALUE_SHARED,
        0,
        annotation_get_lastupdate,
        /*set*/NULL,
        NULL
    },{
        IMAP_ANNOT_NS "news2mail",
        ATTRIB_TYPE_STRING,
        BACKEND_ONLY,
        ATTRIB_VALUE_SHARED,
        ACL_ADMIN,
        annotation_get_fromdb,
        annotation_set_todb,
        NULL
    },{
        IMAP_ANNOT_NS "partition",
        /* _get_partition does its own access control check */
        ATTRIB_TYPE_STRING | ATTRIB_NO_FETCH_ACL_CHECK,
        BACKEND_ONLY,
        ATTRIB_VALUE_SHARED,
        0,
        annotation_get_partition,
        /*set*/NULL,
        NULL
    },{
        IMAP_ANNOT_NS "pop3newuidl",
        ATTRIB_TYPE_BOOLEAN,
        BACKEND_ONLY,
        ATTRIB_VALUE_SHARED,
        0,
        annotation_get_mailboxopt,
        annotation_set_mailboxopt,
        (void *)OPT_POP3_NEW_UIDL
    },{
        IMAP_ANNOT_NS "pop3showafter",
        ATTRIB_TYPE_STRING,
        BACKEND_ONLY,
        ATTRIB_VALUE_SHARED,
        0,
        annotation_get_pop3showafter,
        annotation_set_pop3showafter,
        NULL
    },{
        IMAP_ANNOT_NS "server",
        /* _get_server does its own access control check */
        ATTRIB_TYPE_STRING | ATTRIB_NO_FETCH_ACL_CHECK,
        PROXY_ONLY,
        ATTRIB_VALUE_SHARED,
        0,
        annotation_get_server,
        /*set*/NULL,
        NULL
    },{
        IMAP_ANNOT_NS "sharedseen",
        ATTRIB_TYPE_BOOLEAN,
        BACKEND_ONLY,
        ATTRIB_VALUE_SHARED,
        0,
        annotation_get_mailboxopt,
        annotation_set_mailboxopt,
        (void *)OPT_IMAP_SHAREDSEEN
    },{
        IMAP_ANNOT_NS "sieve",
        ATTRIB_TYPE_STRING,
        BACKEND_ONLY,
        ATTRIB_VALUE_SHARED,
        ACL_ADMIN,
        annotation_get_fromdb,
        annotation_set_todb,
        NULL
    },{
        IMAP_ANNOT_NS "size",
        ATTRIB_TYPE_STRING,
        BACKEND_ONLY,
        ATTRIB_VALUE_SHARED,
        0,
        annotation_get_size,
        /*set*/NULL,
        NULL
    },{
        IMAP_ANNOT_NS "sortorder",
        ATTRIB_TYPE_UINT,
        BACKEND_ONLY,
        ATTRIB_VALUE_PRIV,
        0,
        annotation_get_fromdb,
        annotation_set_todb,
        NULL
    },{
        IMAP_ANNOT_NS "squat",
        ATTRIB_TYPE_BOOLEAN,
        BACKEND_ONLY,
        ATTRIB_VALUE_SHARED,
        ACL_ADMIN,
        annotation_get_fromdb,
        annotation_set_todb,
        NULL
    },{
        IMAP_ANNOT_NS "synccrcs",
        ATTRIB_TYPE_STRING,
        BACKEND_ONLY,
        ATTRIB_VALUE_SHARED,
        0,
        annotation_get_synccrcs,
        NULL,
        NULL,
    },{
        IMAP_ANNOT_NS "uniqueid",
        ATTRIB_TYPE_STRING,
        BACKEND_ONLY,
        ATTRIB_VALUE_SHARED,
        0,
        annotation_get_uniqueid,
        NULL,
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
        0,
        annotation_get_fromfile,
        annotation_set_tofile,
        (void *)"motd"
    },{
        /* The "usemodseq" was added with conversations support, to allow
         * a single value to show any changes to anything about a user */
        IMAP_ANNOT_NS "usermodseq",
        ATTRIB_TYPE_UINT,
        BACKEND_ONLY,
        ATTRIB_VALUE_PRIV,
        0,
        annotation_get_usermodseq,
        /*set*/NULL,
        NULL
    },{
        /* The "usemodseq" was added with conversations support, to allow
         * a single value to show any changes to anything about a user */
        IMAP_ANNOT_NS "usercounters",
        ATTRIB_TYPE_STRING,
        BACKEND_ONLY,
        ATTRIB_VALUE_PRIV,
        0,
        annotation_get_usercounters,
        /*set*/NULL,
        NULL
    },{
        IMAP_ANNOT_NS "expire",
        ATTRIB_TYPE_UINT,
        PROXY_AND_BACKEND,
        ATTRIB_VALUE_SHARED,
        ACL_ADMIN,
        annotation_get_fromdb,
        annotation_set_todb,
        NULL
    },{
        IMAP_ANNOT_NS "freespace",
        ATTRIB_TYPE_STRING,
        BACKEND_ONLY,
        ATTRIB_VALUE_SHARED,
        0,
        annotation_get_freespace,
        /*set*/NULL,
        NULL
    },{
        IMAP_ANNOT_NS "freespace/total",
        ATTRIB_TYPE_STRING,
        BACKEND_ONLY,
        ATTRIB_VALUE_SHARED,
        0,
        annotation_get_freespace_total,
        /*set*/NULL,
        NULL
    },{
        IMAP_ANNOT_NS "freespace/percent/most",
        ATTRIB_TYPE_STRING,
        BACKEND_ONLY,
        ATTRIB_VALUE_SHARED,
        0,
        annotation_get_freespace_percent_most,
        /*set*/NULL,
    NULL
    },{
        IMAP_ANNOT_NS "shutdown",
        ATTRIB_TYPE_STRING,
        PROXY_AND_BACKEND,
        ATTRIB_VALUE_SHARED,
        0,
        annotation_get_fromfile,
        annotation_set_tofile,
        (void *)"shutdown"
    },{
        IMAP_ANNOT_NS "squat",
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

static const struct annotate_attrib annotation_attributes[] =
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

EXPORTED int annotate_state_fetch(annotate_state_t *state,
                         const strarray_t *entries, const strarray_t *attribs,
                         annotate_fetch_cb_t callback, void *rock)
{
    int i;
    struct glob *g;
    const ptrarray_t *non_db_entries;
    const annotate_entrydesc_t *db_entry;
    int r = 0;

    init_internal();

    annotate_state_start(state);
    state->callback = callback;
    state->callback_rock = rock;

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
        g = glob_init(s, '.');

        for (attribcount = 0;
             annotation_attributes[attribcount].name;
             attribcount++) {
            if (GLOB_MATCH(g, annotation_attributes[attribcount].name)) {
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
        syslog(LOG_ERR, "IOERROR: unknown annotation scope %d", state->which);
        r = IMAP_INTERNAL;
        goto out;
    }

    /* Build a list of callbacks for fetching the annotations */
    for (i = 0 ; i < entries->count ; i++)
    {
        const char *s = entries->data[i];
        int j;
        int check_db = 0; /* should we check the db for this entry? */

        g = glob_init(s, '/');

        for (j = 0 ; j < non_db_entries->count ; j++) {
            const annotate_entrydesc_t *desc = non_db_entries->data[j];

            if (!desc->get)
                continue;

            if (GLOB_MATCH(g, desc->name)) {
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
            if (proxy_fetch_func) {
                r = annotate_state_need_mbentry(state);
                if (r)
                    goto out;
                assert(state->mbentry);
            }

            if (proxy_fetch_func && state->orig_entry) {
                state->orig_mailbox = state->mbentry->name;
                state->orig_attribute = attribs;
            }

            _annotate_fetch_entries(state, /*proxy_check*/1);

            if (proxy_fetch_func && state->orig_entry && state->mbentry->server &&
                !hash_lookup(state->mbentry->server, &state->server_table)) {
                /* xxx ignoring result */
                proxy_fetch_func(state->mbentry->server, state->mbentry->ext_name,
                                 state->orig_entry, state->orig_attribute);
                hash_insert(state->mbentry->server, (void *)0xDEADBEEF, &state->server_table);
            }
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

EXPORTED int annotatemore_lookup(const char *mboxname, const char *entry,
                                 const char *userid, struct buf *value)
{
    return annotatemore_msg_lookup(mboxname, /*uid*/0, entry, userid, value);
}

EXPORTED int annotatemore_lookupmask(const char *mboxname, const char *entry,
                                     const char *userid, struct buf *value)
{
    return annotatemore_msg_lookupmask(mboxname, /*uid*/0, entry, userid, value);
}

EXPORTED int annotatemore_msg_lookup(const char *mboxname, uint32_t uid, const char *entry,
                                     const char *userid, struct buf *value)
{
    char key[MAX_MAILBOX_PATH+1];
    size_t keylen, datalen;
    int r;
    const char *data;
    annotate_db_t *d = NULL;
    struct annotate_metadata mdata;

    init_internal();

    r = _annotate_getdb(mboxname, uid, 0, &d);
    if (r)
        return (r == CYRUSDB_NOTFOUND ? 0 : r);

    keylen = make_key(mboxname, uid, entry, userid, key, sizeof(key));

    do {
        r = cyrusdb_fetch(d->db, key, keylen, &data, &datalen, tid(d));
    } while (r == CYRUSDB_AGAIN);

    if (!r && data) {
        r = split_attribs(data, datalen, value, &mdata);
        if (!r) {
            /* Force a copy, in case the putdb() call destroys
             * the per-db data area that @data points to.  */
            buf_cstring(value);
        }
        if (mdata.flags & ANNOTATE_FLAG_DELETED) {
            buf_free(value);
            r = CYRUSDB_NOTFOUND;
        }
    }
    if (r == CYRUSDB_NOTFOUND) r = 0;

    annotate_putdb(&d);
    return r;
}

EXPORTED int annotatemore_msg_lookupmask(const char *mboxname, uint32_t uid, const char *entry,
                                         const char *userid, struct buf *value)
{
    int r = 0;
    value->len = 0; /* just in case! */

    init_internal();

    /* only if the user isn't the owner, we look for a masking value */
    if (!mboxname_userownsmailbox(userid, mboxname))
        r = annotatemore_msg_lookup(mboxname, uid, entry, userid, value);
    /* and if there isn't one, we fall through to the shared value */
    if (value->len == 0)
        r = annotatemore_msg_lookup(mboxname, uid, entry, "", value);
    /* and because of Bron's use of NULL rather than "" at FastMail... */
    if (value->len == 0)
        r = annotatemore_msg_lookup(mboxname, uid, entry, NULL, value);
    return r;
}

static int read_old_value(annotate_db_t *d,
                          const char *key, int keylen,
                          struct buf *valp,
                          struct annotate_metadata *mdata)
{
    int r;
    size_t datalen;
    const char *data;

    do {
        r = cyrusdb_fetch(d->db, key, keylen, &data, &datalen, tid(d));
    } while (r == CYRUSDB_AGAIN);

    if (r == CYRUSDB_NOTFOUND) {
        r = 0;
        goto out;
    }
    if (r || !data)
        goto out;

    r = split_attribs(data, datalen, valp, mdata);

out:
    return r;
}

static int make_entry(struct buf *data,
                      const struct buf *value,
                      modseq_t modseq,
                      unsigned char flags)
{
    unsigned long l;
    static const char contenttype[] = "text/plain"; /* fake */
    unsigned long long nmodseq;

    /* Make sure that native types are wide enough */
    assert(sizeof(modseq_t) <= sizeof(unsigned long long));
    nmodseq = htonll((unsigned long long) modseq);

    l = htonl(value->len);
    buf_appendmap(data, (const char *)&l, sizeof(l));

    buf_appendmap(data, value->s ? value->s : "", value->len);
    buf_putc(data, '\0');

    /*
     * Older versions of Cyrus expected content-type and
     * modifiedsince fields after the value.  We don't support those
     * but we write out default values just in case the database
     * needs to be read by older versions of Cyrus
     */
    buf_appendcstr(data, contenttype);
    buf_putc(data, '\0');

    l = 0;  /* fake modifiedsince */
    buf_appendmap(data, (const char *)&l, sizeof(l));

    /* Append modseq at the end */
    buf_appendmap(data, (const char *)&nmodseq, sizeof(nmodseq));

    /* Append flags */
    buf_putc(data, flags);

    return 0;
}

static int write_entry(struct mailbox *mailbox,
                       unsigned int uid,
                       const char *entry,
                       const char *userid,
                       const struct buf *value,
                       int ignorequota,
                       int silent,
                       const struct annotate_metadata *mdata,
                       int maywrite)

{
    char key[MAX_MAILBOX_PATH+1];
    int keylen, r;
    annotate_db_t *d = NULL;
    struct buf oldval = BUF_INITIALIZER;
    const char *mboxname = mailbox ? mailbox->name : "";
    modseq_t modseq = mdata ? mdata->modseq : 0;

    r = _annotate_getdb(mboxname, uid, CYRUSDB_CREATE, &d);
    if (r)
        return r;

    /* must be in a transaction to modify the db */
    annotate_begin(d);

    keylen = make_key(mboxname, uid, entry, userid, key, sizeof(key));

    struct annotate_metadata oldmdata;
    r = read_old_value(d, key, keylen, &oldval, &oldmdata);
    if (r) goto out;

    /* if the value is identical, don't touch the mailbox */
    if (oldval.len == value->len && (!value->len || !memcmp(oldval.s, value->s, value->len)))
        goto out;

    if (!maywrite) {
        r = IMAP_PERMISSION_DENIED;
        if (r) goto out;
    }

    if (mailbox) {
        if (!ignorequota) {
            quota_t qdiffs[QUOTA_NUMRESOURCES] = QUOTA_DIFFS_DONTCARE_INITIALIZER;
            qdiffs[QUOTA_ANNOTSTORAGE] = value->len - (quota_t)oldval.len;
            r = mailbox_quota_check(mailbox, qdiffs);
            if (r) goto out;
        }

        /* do the annot-changed here before altering the DB */
        mailbox_annot_changed(mailbox, uid, entry, userid, &oldval, value, silent);

        /* grab the message annotation modseq, if not overridden */
        if (uid && !mdata) {
            modseq = mailbox->i.highestmodseq;
        }
    }

    /* zero length annotation is deletion.
     * keep tombstones for message annotations */
    if (!value->len && !uid) {

#if DEBUG
        syslog(LOG_ERR, "write_entry: deleting key %s from %s",
                key_as_string(d, key, keylen), d->filename);
#endif

        do {
            r = cyrusdb_delete(d->db, key, keylen, tid(d), /*force*/1);
        } while (r == CYRUSDB_AGAIN);
    }
    else {
        struct buf data = BUF_INITIALIZER;
        unsigned char flags = 0;
        if (!value->len || value->s == NULL) {
            flags |= ANNOTATE_FLAG_DELETED;
        }
        else {
            // this is only here to allow cleanup of invalid values in the past...
            // the calling of this API with a NULL "userid" is bogus, because that's
            // supposed to be reserved for the make_key of prefixes - but there has
            // been API abuse in the past, so some of these are in the wild.  *sigh*.
            // Don't allow new ones to be written
            if (!userid) goto out;
        }
        make_entry(&data, value, modseq, flags);

#if DEBUG
        syslog(LOG_ERR, "write_entry: storing key %s (value: %s) to %s (modseq=" MODSEQ_FMT ")",
                key_as_string(d, key, keylen), value->s, d->filename, modseq);
#endif

        do {
            r = cyrusdb_store(d->db, key, keylen, data.s, data.len, tid(d));
        } while (r == CYRUSDB_AGAIN);
        buf_free(&data);
    }

    if (!mailbox)
        sync_log_annotation("");

out:
    annotate_putdb(&d);
    buf_free(&oldval);

    return r;
}

EXPORTED int annotatemore_rawwrite(const char *mboxname, const char *entry,
                                   const char *userid, const struct buf *value)
{
    char key[MAX_MAILBOX_PATH+1];
    int keylen, r;
    annotate_db_t *d = NULL;
    uint32_t uid = 0;

    init_internal();

    r = _annotate_getdb(mboxname, uid, CYRUSDB_CREATE, &d);
    if (r) goto done;

    /* must be in a transaction to modify the db */
    annotate_begin(d);

    keylen = make_key(mboxname, uid, entry, userid, key, sizeof(key));

    if (value->s == NULL) {
        do {
            r = cyrusdb_delete(d->db, key, keylen, tid(d), /*force*/1);
        } while (r == CYRUSDB_AGAIN);
    }
    else {
        struct buf data = BUF_INITIALIZER;

        make_entry(&data, value, uid, /*flags*/0);

        do {
            r = cyrusdb_store(d->db, key, keylen, data.s, data.len, tid(d));
        } while (r == CYRUSDB_AGAIN);
        buf_free(&data);
    }

    if (r) goto done;
    r = annotate_commit(d);

done:
    annotate_putdb(&d);

    return r;
}

EXPORTED int annotatemore_write(const char *mboxname, const char *entry,
                                const char *userid, const struct buf *value)
{
    struct mailbox *mailbox = NULL;
    int r = 0;
    annotate_db_t *d = NULL;

    init_internal();

    r = _annotate_getdb(mboxname, /*uid*/0, CYRUSDB_CREATE, &d);
    if (r) goto done;

    if (mboxname) {
        r = mailbox_open_iwl(mboxname, &mailbox);
        if (r) goto done;
    }

    r = write_entry(mailbox, /*uid*/0, entry, userid, value,
                    /*ignorequota*/1, /*silent*/0, NULL, /*maywrite*/1);
    if (r) goto done;

    r = annotate_commit(d);

done:
    annotate_putdb(&d);
    mailbox_close(&mailbox);

    return r;
}

EXPORTED int annotatemore_writemask(const char *mboxname, const char *entry,
                                    const char *userid, const struct buf *value)
{
    if (mboxname_userownsmailbox(userid, mboxname))
        return annotatemore_write(mboxname, entry, "", value);
    else
        return annotatemore_write(mboxname, entry, userid, value);
}

EXPORTED int annotate_state_write(annotate_state_t *state,
                                  const char *entry,
                                  const char *userid,
                                  const struct buf *value)
{
    return write_entry(state->mailbox, state->uid,
                       entry, userid, value, /*ignorequota*/1,
                       state->silent, NULL, /*maywrite*/1);
}

EXPORTED int annotate_state_writesilent(annotate_state_t *state,
                                        const char *entry,
                                        const char *userid,
                                        const struct buf *value)
{
    return write_entry(state->mailbox, state->uid,
                       entry, userid, value, /*ignorequota*/1,
                       /*silent*/1, NULL, /*maywrite*/1);
}

EXPORTED int annotate_state_writemdata(annotate_state_t *state,
                                       const char *entry,
                                       const char *userid,
                                       const struct buf *value,
                                       const struct annotate_metadata *mdata)
{
    return write_entry(state->mailbox, state->uid, entry, userid, value,
                       /*ignorequota*/1, 0, mdata, /*maywrite*/1);
}

EXPORTED int annotate_state_writemask(annotate_state_t *state,
                                      const char *entry,
                                      const char *userid,
                                      const struct buf *value)
{
    /* if the user is the owner, then write to the shared namespace */
    if (mboxname_userownsmailbox(userid, state->mailbox->name))
        return annotate_state_write(state, entry, "", value);
    else
        return annotate_state_write(state, entry, userid, value);
}

static int annotate_canon_value(struct buf *value, int type)
{
    char *p = NULL;
    unsigned long uwhatever = 0;
    long whatever = 0;

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
        buf_cstring(value);
        uwhatever = strtoul(value->s, &p, 10);
        if ((p == value->s)             /* no value */
            || (*p != '\0')             /* illegal char */
            || (unsigned)(p - value->s) != value->len
                                        /* embedded NUL */
            || errno                    /* overflow */
            || strchr(value->s, '-')) { /* negative number */
            return IMAP_ANNOTATION_BADVALUE;
        }
        break;

    case ATTRIB_TYPE_INT:
        /* make sure its a valid long */
        errno = 0;
        buf_cstring(value);
        whatever = strtol(value->s, &p, 10);
        if ((p == value->s)             /* no value */
            || (*p != '\0')             /* illegal char */
            || (unsigned)(p - value->s) != value->len
                                        /* embedded NUL */
            || errno) {                 /* underflow/overflow */
            return IMAP_ANNOTATION_BADVALUE;
        }
        break;

    default:
        /* unknown type */
        return IMAP_ANNOTATION_BADVALUE;
    }

    if (whatever || uwhatever) /* filthy compiler magic */
        return 0;

    return 0;
}

static int _annotate_store_entries(annotate_state_t *state)
{
    struct annotate_entry_list *ee;
    int r = 0;
    unsigned oldsilent = state->silent;

    /* Loop through the list of provided entries to set */
    for (ee = state->entry_list ; ee ; ee = ee->next) {
        int maystore = 1;

        /* Skip annotations that can't be stored on frontend */
        if ((ee->desc->proxytype == BACKEND_ONLY) &&
            (state->mbentry && state->mbentry->server))
            continue;

        if (ee->have_shared &&
            !_annotate_may_store(state, /*shared*/1, ee->desc)) {
            maystore = 0;
        }

        if (ee->have_priv &&
            !_annotate_may_store(state, /*shared*/0, ee->desc)) {
            maystore = 0;
        }

        r = ee->desc->set(state, ee, maystore);
        if (r)
            goto done;

        /* only the first write for message annotations isn't silent! */
        if (state->which == ANNOTATION_SCOPE_MESSAGE)
            state->silent = 1;
    }

done:
    state->silent = oldsilent;
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
        assert(state->mailbox);

        /* Make sure its a local mailbox annotation */
        if (state->mbentry && state->mbentry->server)
            return 0;

        acl = state->mailbox->acl;
        /* RFC5464 is a trifle vague about access control for mailbox
         * annotations but this seems to be compliant */
        needed = ACL_LOOKUP;
        if (is_shared)
            needed |= ACL_READ|ACL_WRITE|desc->extra_rights;
        /* fall through to ACL check */
    }
    else if (state->which == ANNOTATION_SCOPE_MESSAGE) {
        assert(state->mailbox);
        acl = state->mailbox->acl;
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
                                 struct annotate_entry_list *entry,
                                 int maywrite)
{
    const char *filename = (const char *)entry->desc->rock;
    char path[MAX_MAILBOX_PATH+1];
    int r;
    FILE *f;

    if (!maywrite) return IMAP_PERMISSION_DENIED;

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
                               struct annotate_entry_list *entry,
                               int maywrite)
{
    int r = 0;

    if (entry->have_shared)
        r = write_entry(state->mailbox, state->uid,
                        entry->name, "",
                        &entry->shared, 0, state->silent, NULL, maywrite);
    if (!r && entry->have_priv)
        r = write_entry(state->mailbox, state->uid,
                        entry->name, state->userid,
                        &entry->priv, 0, state->silent, NULL, maywrite);

    return r;
}

static int annotation_set_mailboxopt(annotate_state_t *state,
                                     struct annotate_entry_list *entry,
                                     int maywrite)
{
    struct mailbox *mailbox = state->mailbox;
    uint32_t flag = (unsigned long)entry->desc->rock;
    unsigned long newopts;

    assert(mailbox);

    newopts = mailbox->i.options;

    if (entry->shared.s &&
        !strcmp(entry->shared.s, "true")) {
        newopts |= flag;
    } else {
        newopts &= ~flag;
    }

    /* only mark dirty if there's been a change */
    if (mailbox->i.options != newopts) {
        if (!maywrite) return IMAP_PERMISSION_DENIED;
        mailbox_index_dirty(mailbox);
        mailbox_modseq_dirty(mailbox);
        mailbox->i.options = newopts;
        mboxlist_update_foldermodseq(mailbox->name, mailbox->i.highestmodseq);
    }

    return 0;
}

static int annotation_set_pop3showafter(annotate_state_t *state,
                                        struct annotate_entry_list *entry,
                                        int maywrite)
{
    struct mailbox *mailbox = state->mailbox;
    int r = 0;
    time_t date;

    assert(mailbox);

    if (entry->shared.s == NULL) {
        /* Effectively removes the annotation */
        date = 0;
    }
    else {
        r = time_from_rfc5322(buf_cstring(&entry->shared), &date, DATETIME_FULL);
        if (r < 0)
            return IMAP_PROTOCOL_BAD_PARAMETERS;
    }

    if (date != mailbox->i.pop3_show_after) {
        if (!maywrite) return IMAP_PERMISSION_DENIED;
        mailbox_index_dirty(mailbox);
        mailbox_modseq_dirty(mailbox);
        mailbox->i.pop3_show_after = date;
        mboxlist_update_foldermodseq(mailbox->name, mailbox->i.highestmodseq);
    }

    return 0;
}

EXPORTED int specialuse_validate(const char *mboxname, const char *userid,
                                 const char *src, struct buf *dest)
{
    const char *specialuse_extra_opt = config_getstring(IMAPOPT_SPECIALUSE_EXTRA);
    char *strval = NULL;
    strarray_t *valid = NULL;
    strarray_t *new_attribs = NULL;
    strarray_t *cur_attribs = NULL;
    struct buf mbattribs = BUF_INITIALIZER;
    int i, j;
    int r = 0;

    if (!src) {
        buf_reset(dest);
        return 0;
    }

    /* If there is a valid mboxname, we get the current specialuse annotations.
     */
    if (mboxname) {
        annotatemore_lookup(mboxname, "/specialuse", userid, &mbattribs);
        if (mbattribs.len) {
            cur_attribs = strarray_split(buf_cstring(&mbattribs), NULL, 0);
        }
    }

    /* check specialuse_extra option if set */
    if (specialuse_extra_opt)
        valid = strarray_split(specialuse_extra_opt, NULL, 0);
    else
        valid = strarray_new();

    /* strarray_add(valid, "\\All"); -- we don't support virtual folders right now */
    strarray_add(valid, "\\Archive");
    strarray_add(valid, "\\Drafts");
    /* strarray_add(valid, "\\Flagged"); -- we don't support virtual folders right now */
    strarray_add(valid, "\\Important"); // draft-ietf-specialuse-important
    strarray_add(valid, "\\Junk");
    strarray_add(valid, "\\Sent");
    strarray_add(valid, "\\Trash");
    strarray_add(valid, "\\Snoozed"); // JMAP

    new_attribs = strarray_split(src, NULL, 0);

    for (i = 0; i < new_attribs->count; i++) {
        int skip_mbcheck = 0;
        const char *item = strarray_nth(new_attribs, i);

        for (j = 0; j < valid->count; j++) { /* can't use find here */
            if (!strcasecmp(strarray_nth(valid, j), item))
                break;
            /* or without the leading '\' */
            if (!strcasecmp(strarray_nth(valid, j) + 1, item))
                break;
        }

        if (j >= valid->count) {
            r = IMAP_ANNOTATION_BADENTRY;
            goto done;
        }

        if (cur_attribs &&
            (strarray_find_case(cur_attribs, strarray_nth(valid, j), 0) >= 0)) {
            /* The mailbox has this specialuse attribute set already */
            skip_mbcheck = 1;
        }

        /* don't allow names that are already in use */
        if (!skip_mbcheck) {
            char *mbname = mboxlist_find_specialuse(strarray_nth(valid, j),
                                                    userid);
            if (mbname) {
                free(mbname);
                r = IMAP_MAILBOX_SPECIALUSE;
                goto done;
            }
        }

        /* normalise the value */
        strarray_set(new_attribs, i, strarray_nth(valid, j));
    }

    strval = strarray_join(new_attribs, " ");
    buf_setcstr(dest, strval);

done:
    free(strval);
    strarray_free(valid);
    strarray_free(new_attribs);
    strarray_free(cur_attribs);
    buf_free(&mbattribs);
    return r;
}

static int annotation_set_specialuse(annotate_state_t *state,
                                     struct annotate_entry_list *entry,
                                     int maywrite)
{
    struct buf res = BUF_INITIALIZER;
    int r = IMAP_PERMISSION_DENIED;

    assert(state->mailbox);

    /* Effectively removes the annotation */
    if (entry->priv.s == NULL) {
        r = write_entry(state->mailbox, state->uid, entry->name, state->userid,
                        &entry->priv, /*ignorequota*/0, /*silent*/0, NULL, maywrite);
        goto done;
    }

    r = specialuse_validate(state->mailbox->name, state->userid,
                            buf_cstring(&entry->priv), &res);
    if (r) goto done;

    r = write_entry(state->mailbox, state->uid, entry->name, state->userid,
                    &res, /*ignorequota*/0, state->silent, NULL, maywrite);

done:
    buf_free(&res);

    return r;
}

static int find_desc_store(annotate_state_t *state,
                           const char *name,
                           const annotate_entrydesc_t **descp)
{
    int scope = state->which;
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
    else {
        syslog(LOG_ERR, "IOERROR: unknown scope in find_desc_store %d", scope);
        return IMAP_INTERNAL;
    }

    /* check for DAV annotations */
    if (state->mailbox && (state->mailbox->mbtype & MBTYPES_DAV) &&
        !strncmp(name, DAV_ANNOT_NS, strlen(DAV_ANNOT_NS))) {
        *descp = db_entry;
        return 0;
    }

    /* check known IMAP annotations */
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

    /* check for /flags and /vendor/cmu */
    if (scope == ANNOTATION_SCOPE_MESSAGE &&
        !strncmp(name, "/flags/", 7))
        return IMAP_PERMISSION_DENIED;

    if (!strncmp(name, IMAP_ANNOT_NS, strlen(IMAP_ANNOT_NS)))
        return IMAP_PERMISSION_DENIED;

    *descp = db_entry;
    return 0;
}

EXPORTED int annotate_state_store(annotate_state_t *state, struct entryattlist *l)
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
        r = find_desc_store(state, e->entry, &desc);
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
        if (proxy_store_func) {
            r = annotate_state_need_mbentry(state);
            if (r)
                goto cleanup;
            assert(state->mbentry);
        }
        else assert(state->mailbox);

        r = _annotate_store_entries(state);
        if (r)
            goto cleanup;

        state->count++;

        if (proxy_store_func && state->mbentry->server &&
            !hash_lookup(state->mbentry->server, &state->server_table)) {
            hash_insert(state->mbentry->server, (void *)0xDEADBEEF, &state->server_table);
        }

        if (!r && !state->count) r = IMAP_MAILBOX_NONEXISTENT;

        if (proxy_store_func) {
            if (!r) {
                /* proxy command to backends */
                struct proxy_rock prock = { NULL, NULL };
                prock.mbox_pat = state->mbentry->ext_name;
                prock.entryatts = l;
                hash_enumerate(&state->server_table, store_proxy, &prock);
            }
        }
    }
    else if (state->which == ANNOTATION_SCOPE_MESSAGE) {
        r = _annotate_store_entries(state);
        if (r)
            goto cleanup;
    }

cleanup:
    annotate_state_finish(state);
    return r;
}

struct rename_rock {
    struct mailbox *oldmailbox;
    struct mailbox *newmailbox;
    const char *olduserid;
    const char *newuserid;
    uint32_t olduid;
    uint32_t newuid;
    int copy;
};

static int rename_cb(const char *mboxname __attribute__((unused)),
                     uint32_t uid,
                     const char *entry,
                     const char *userid, const struct buf *value,
                     const struct annotate_metadata *mdata __attribute__((unused)),
                     void *rock)
{
    struct rename_rock *rrock = (struct rename_rock *) rock;
    int r = 0;

    if (rrock->newmailbox &&
            /* snoozed MUST only appear on one copy of a message */
            strcmp(entry, IMAP_ANNOT_NS "snoozed") &&
            /* displayname stores the UTF-8 encoded JMAP name of a mailbox */
            strcmp(entry, IMAP_ANNOT_NS "displayname")) {
        /* create newly renamed entry */
        const char *newuserid = userid;

        if (rrock->olduserid && rrock->newuserid &&
            !strcmpsafe(rrock->olduserid, userid)) {
            /* renaming a user, so change the userid for priv annots */
            newuserid = rrock->newuserid;
        }
        r = write_entry(rrock->newmailbox, rrock->newuid, entry, newuserid,
                        value, /*ignorequota*/0, /*silent*/0, NULL, /*maywrite*/1);
    }

    if (!rrock->copy && !r) {
        /* delete existing entry */
        struct buf dattrib = BUF_INITIALIZER;
        r = write_entry(rrock->oldmailbox, uid, entry, userid, &dattrib,
                        /*ignorequota*/0, /*silent*/0, NULL, /*maywrite*/1);
    }

    return r;
}

EXPORTED int annotate_rename_mailbox(struct mailbox *oldmailbox,
                            struct mailbox *newmailbox)
{
    /* rename one mailbox */
    char *olduserid = mboxname_to_userid(oldmailbox->name);
    char *newuserid = mboxname_to_userid(newmailbox->name);
    annotate_db_t *d = NULL;
    int r = 0;

    init_internal();

    /* rewrite any per-folder annotations from the global db */
    r = _annotate_getdb(NULL, 0, /*don't create*/0, &d);
    if (r == CYRUSDB_NOTFOUND) {
        /* no global database, must not be anything to rename */
        r = 0;
        goto done;
    }
    if (r) goto done;

    annotate_begin(d);

    /* copy here - delete will dispose of old records later */
    r = _annotate_rewrite(oldmailbox, 0, olduserid,
                          newmailbox, 0, newuserid,
                         /*copy*/1);
    if (r) goto done;

    r = annotate_commit(d);
    if (r) goto done;

    /*
     * The per-folder database got moved or linked by mailbox_copy_files().
     */

 done:
    annotate_putdb(&d);
    free(olduserid);
    free(newuserid);

    return r;
}

/*
 * Perform a scan-and-rewrite through the database(s) for
 * a given set of criteria; common code for several higher
 * level operations.
 */
static int _annotate_rewrite(struct mailbox *oldmailbox,
                             uint32_t olduid,
                             const char *olduserid,
                             struct mailbox *newmailbox,
                             uint32_t newuid,
                             const char *newuserid,
                             int copy)
{
    struct rename_rock rrock;

    rrock.oldmailbox = oldmailbox;
    rrock.newmailbox = newmailbox;
    rrock.olduserid = olduserid;
    rrock.newuserid = newuserid;
    rrock.olduid = olduid;
    rrock.newuid = newuid;
    rrock.copy = copy;

    return annotatemore_findall(oldmailbox->name, olduid, "*", /*modseq*/0,
                                &rename_cb, &rrock, /*flags*/0);
}

EXPORTED int annotate_delete_mailbox(struct mailbox *mailbox)
{
    int r = 0;
    char *fname = NULL;
    annotate_db_t *d = NULL;

    init_internal();

    assert(mailbox);

    /* remove any per-folder annotations from the global db */
    r = _annotate_getdb(NULL, 0, /*don't create*/0, &d);
    if (r == CYRUSDB_NOTFOUND) {
        /* no global database, must not be anything to rename */
        r = 0;
        goto out;
    }
    if (r) goto out;

    annotate_begin(d);

    r = _annotate_rewrite(mailbox,
                          /*olduid*/0, /*olduserid*/NULL,
                          /*newmailbox*/NULL,
                          /*newuid*/0, /*newuserid*/NULL,
                          /*copy*/0);
    if (r) goto out;

    /* remove the entire per-folder database */
    r = annotate_dbname_mailbox(mailbox, &fname);
    if (r) goto out;

    /* (gnb)TODO: do we even need to do this?? */
    if (unlink(fname) < 0 && errno != ENOENT) {
        syslog(LOG_ERR, "cannot unlink %s: %m", fname);
    }

    r = annotate_commit(d);

out:
    annotate_putdb(&d);
    free(fname);
    return r;
}

EXPORTED int annotate_msg_copy(struct mailbox *oldmailbox, uint32_t olduid,
                      struct mailbox *newmailbox, uint32_t newuid,
                      const char *userid)
{
    annotate_db_t *d = NULL;
    int r;

    init_internal();

    r = _annotate_getdb(newmailbox->name, newuid, CYRUSDB_CREATE, &d);
    if (r) return r;

    annotate_begin(d);

    /* If these are not true, nobody will ever commit the data we're
     * about to copy, and that would be sad */
    assert(newmailbox->annot_state != NULL);
    assert(newmailbox->annot_state->d == d);

    r = _annotate_rewrite(oldmailbox, olduid, userid,
                          newmailbox, newuid, userid,
                          /*copy*/1);

    annotate_putdb(&d);
    return r;
}

static int cleanup_cb(void *rock,
                      const char *key, size_t keylen,
                      const char *data __attribute__((unused)),
                      size_t datalen __attribute__((unused)))
{
    annotate_db_t *d = (annotate_db_t *)rock;

    return cyrusdb_delete(d->db, key, keylen, tid(d), /*force*/1);
}

/* clean up WITHOUT counting usage again, we already removed that when
 * we expunged the record */
HIDDEN int annotate_msg_cleanup(struct mailbox *mailbox, unsigned int uid)
{
    char key[MAX_MAILBOX_PATH+1];
    size_t keylen;
    int r = 0;
    annotate_db_t *d = NULL;

    assert(uid);

    r = _annotate_getdb(mailbox->name, uid, 0, &d);
    if (r) return r;

    /* must be in a transaction to modify the db */
    annotate_begin(d);

    /* If these are not true, nobody will ever commit the data we're
     * about to copy, and that would be sad */
    assert(mailbox->annot_state != NULL);
    assert(mailbox->annot_state->d == d);

    keylen = make_key(mailbox->name, uid, "", NULL, key, sizeof(key));

    r = cyrusdb_foreach(d->db, key, keylen, NULL, &cleanup_cb, d, tid(d));

    annotate_putdb(&d);
    return r;
}

/*************************  Annotation Initialization  ************************/

/* The following code is courtesy of Thomas Viehmann <tv@beamnet.de> */


static const struct annotate_attrib annotation_scope_names[] =
{
    { "server", ANNOTATION_SCOPE_SERVER },
    { "mailbox", ANNOTATION_SCOPE_MAILBOX },
    { "message", ANNOTATION_SCOPE_MESSAGE },
    { NULL, 0 }
};

static const struct annotate_attrib annotation_proxy_type_names[] =
{
    { "proxy", PROXY_ONLY },
    { "backend", BACKEND_ONLY },
    { "proxy_and_backend", PROXY_AND_BACKEND },
    { NULL, 0 }
};

static const struct annotate_attrib attribute_type_names[] =
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
        parse_error(state, "invalid annotation attributes");
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
    ptrarray_t *entries = NULL;

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
           be more restrictive than necessary */

        ae = xzmalloc(sizeof(*ae));

        if (!(p = get_token(&state, ".-_/:"))) goto bad;
        /* TV-TODO: should test for empty */

        if (!strncmp(p, IMAP_ANNOT_NS, strlen(IMAP_ANNOT_NS))) {
            parse_error(&state, "annotation under " IMAP_ANNOT_NS);
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
        cyrus_acl_strtomask(p, &ae->extra_rights);
        /* XXX and if strtomask fails? */

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


#if 0
/* Suppress the syslog message to fix the unit tests, but have the
 * syslog message to aid the admin ...
 */
    if (state.nerrors)
        syslog(LOG_ERR, "%s: encountered %u errors.  Struggling on, but "
                        "some of your annotation definitions may be "
                        "ignored.  Please fix this file!",
                        state.filename, state.nerrors);
#endif

    fclose(f);
}
