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

/* Encapsulates all the state involved in providing the scope
 * for setting or getting a single annotation */
typedef struct annotate_cursor annotate_cursor_t;
struct annotate_cursor
{
    int which;		    /* ANNOTATION_SCOPE_* */
    /* for _MAILBOX */
    const char *int_mboxname;
    const char *ext_mboxname;
    struct mboxlist_entry *mbentry;
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
    int acl;			/* add'l required ACL for .shared */
    void (*get)(const annotate_cursor_t *cursor,
		const char *name, struct fetchdata *fdata,
		void *rock);	/* function to get the entry */
    int (*set)(const annotate_cursor_t *cursor, struct annotate_st_entry_list *entry,
	       struct storedata *sdata,
	       void *rock);	/* function to set the entry */
    void *rock;			/* rock passed to get() function */
};


#define DB config_annotation_db

struct db *anndb;
static int annotate_dbopen = 0;
int (*proxy_fetch_func)(const char *server, const char *mbox_pat,
			const strarray_t *entry_pat,
			const strarray_t *attribute_pat) = NULL;
int (*proxy_store_func)(const char *server, const char *mbox_pat,
			struct entryattlist *entryatts) = NULL;
static ptrarray_t mailbox_entries = PTRARRAY_INITIALIZER;
static ptrarray_t server_entries = PTRARRAY_INITIALIZER;

static void init_annotation_definitions(void);
static int annotatemore_findall2(const annotate_cursor_t *cursor,
				 const char *entry,
				 annotatemore_find_proc_t proc,
				 void *rock,
				 struct txn **tid);
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
void appendattvalue(struct attvaluelist **l, const char *attrib, const char *value)
{
    struct attvaluelist **tail = l;

    while (*tail) tail = &(*tail)->next;

    *tail = (struct attvaluelist *)xmalloc(sizeof(struct attvaluelist));
    (*tail)->attrib = xstrdup(attrib);
    (*tail)->value = value ? xstrdup(value) : NULL;
    (*tail)->next = 0;
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
	free(l->value);
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

/*
 * Free the entryattlist 'l'
 */
void freeentryatts(struct entryattlist *l)
{
    struct entryattlist *n;

    while (l) {
	n = l->next;
	free(l->entry);
	if (l->attvalues) freeattvalues(l->attvalues);
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

void annotatemore_open(void)
{
    int ret;
    char *tofree = NULL;
    const char *fname;

    fname = config_getstring(IMAPOPT_ANNOTATION_DB_PATH);

    /* create db file name */
    if (!fname) {
	tofree = strconcat(config_dir, FNAME_ANNOTATIONS, (char *)NULL);
	fname = tofree;
    }

    ret = (DB->open)(fname, CYRUSDB_CREATE, &anndb);
    if (ret != 0) {
	syslog(LOG_ERR, "DBERROR: opening %s: %s", fname,
	       cyrusdb_strerror(ret));
	fatal("can't read annotations file", EC_TEMPFAIL);
    }    

    free(tofree);

    annotate_dbopen = 1;
}

void annotatemore_close(void)
{
    int r;

    if (annotate_dbopen) {
	r = (DB->close)(anndb);
	if (r) {
	    syslog(LOG_ERR, "DBERROR: error closing annotations: %s",
		   cyrusdb_strerror(r));
	}
	annotate_dbopen = 0;
    }
}

void annotatemore_done(void)
{
    /* DB->done() handled by cyrus_done() */
}

static int make_key(const char *mboxname, const char *entry,
		    const char *userid, char *key, size_t keysize)
{
    int keylen = 0;

    strlcpy(key+keylen, mboxname, keysize-keylen);
    keylen += strlen(mboxname) + 1;
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

static int split_key(const char *key, int keysize,
		     const char **mboxnamep,
		     const char **entryp,
		     const char **useridp)
{
#define NFIELDS 3
    const char *fields[NFIELDS];
    int nfields = 0;
    const char *p;

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

    if (mboxnamep) *mboxnamep = fields[0];
    if (entryp) *entryp = fields[1];
    if (useridp) *useridp = fields[2];
    return 0;
#undef NFIELDS
}

static int split_attribs(const char *data, int datalen __attribute__((unused)),
			 struct annotation_data *attrib)
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
    attrib->size = (size_t) ntohl(tmp);
    data += sizeof(unsigned long); /* skip to value */

    attrib->value = data;

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
    annotatemore_find_proc_t proc;
    void *rock;
};

static int find_p(void *rock, const char *key, int keylen,
		const char *data __attribute__((unused)),
		int datalen __attribute__((unused)))
{
    struct find_rock *frock = (struct find_rock *) rock;
    const char *mboxname, *entry, *userid;
    int r;

    r = split_key(key, keylen, &mboxname,
		  &entry, &userid);
    if (r < 0)
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
    struct annotation_data attrib;
    int r;

    r = split_key(key, keylen, &mboxname,
		  &entry, &userid);
    if (r)
	return r;

    r = split_attribs(data, datalen, &attrib);

    if (!r) r = frock->proc(mboxname, entry, userid, &attrib, frock->rock);

    return r;
}

static void annotate_cursor_setup(annotate_cursor_t *cursor,
				  const char *mailbox)
{
    memset(cursor, 0, sizeof(*cursor));
    cursor->int_mboxname = mailbox;
    if (!*mailbox) {
	cursor->which = ANNOTATION_SCOPE_SERVER;
    }
    else {
	cursor->which = ANNOTATION_SCOPE_MAILBOX;
    }
}

int annotatemore_findall(const char *mailbox, const char *entry,
			 annotatemore_find_proc_t proc, void *rock,
			 struct txn **tid)
{
    annotate_cursor_t cursor;
    annotate_cursor_setup(&cursor, mailbox);
    return annotatemore_findall2(&cursor, entry, proc, rock, tid);
}

static int annotatemore_findall2(const annotate_cursor_t *cursor,
				 const char *entry,
				 annotatemore_find_proc_t proc,
				 void *rock,
				 struct txn **tid)
{
    char key[MAX_MAILBOX_PATH+1], *p;
    int keylen, r;
    struct find_rock frock;

    frock.mglob = glob_init(cursor->int_mboxname, GLOB_HIERARCHY);
    frock.eglob = glob_init(entry, GLOB_HIERARCHY);
    GLOB_SET_SEPARATOR(frock.eglob, '/');
    frock.proc = proc;
    frock.rock = rock;

    /* Find fixed-string pattern prefix */
    keylen = make_key(cursor->int_mboxname, entry, NULL, key, sizeof(key));

    for (p = key; keylen; p++, keylen--) {
	if (*p == '*' || *p == '%') break;
    }
    keylen = p - key;

    r = DB->foreach(anndb, key, keylen, &find_p, &find_cb, &frock, tid);

    glob_free(&frock.mglob);
    glob_free(&frock.eglob);

    return r;
}

/***************************  Annotation Fetching  ***************************/

struct fetchdata {
    struct namespace *namespace;
    struct protstream *pout;
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
    int ismetadata;
    int maxsize;
    int *sizeptr;
};

static void output_attlist(struct protstream *pout, struct attvaluelist *l) 
{
    int flag = 0;
    
    assert(l);
    
    prot_putc('(',pout);
    
    while(l) {
	if (flag) prot_putc(' ', pout);
	else flag = 1;

	prot_printstring(pout, l->attrib);
	prot_putc(' ', pout);
	prot_printstring(pout, l->value);

	l = l->next;
    }

    prot_putc(')',pout);
}

static void output_metalist(struct protstream *pout, struct attvaluelist *l,
			    const char *entry)
{
    int flag = 0;
    const char *prefix;

    assert(l);

    prot_putc('(', pout);

    while (l) {
	prefix = NULL;

	/* check if it's a value we print... */
	if (!strcmp(l->attrib, "value.shared"))
	    prefix = "/shared";
	else if (!strcmp(l->attrib, "value.priv"))
	    prefix = "/private";

	if (prefix) {
	    if (flag) prot_putc(' ', pout);
	    else flag = 1;

	    /* a little dodgy, but legit here because of limitations on
	     * valid entry names ... */
	    prot_printf(pout, "%s%s ", prefix, entry);
	    prot_printstring(pout, l->value);
	}

	l = l->next;
    }

    prot_putc(')', pout);
}

/* Output a single entry and attributes for a single mailbox.
 * Shared and private annotations are output together by caching
 * the attributes until the mailbox and/or entry changes.
 *
 * The cache is reset by calling with a NULL mboxname or entry.
 * The last entry is flushed by calling with a NULL attrib.
 */
static void output_entryatt(const annotate_cursor_t *cursor, const char *entry,
			    const char *userid, struct annotation_data *attrib,
			    struct fetchdata *fdata)
{
    static struct attvaluelist *attvalues = NULL;
    static int lastwhich;
    static char lastname[MAX_MAILBOX_BUFFER];
    static char lastentry[MAX_MAILBOX_BUFFER];
    char key[MAX_MAILBOX_BUFFER]; /* XXX MAX_MAILBOX_NAME + entry + userid */
    char buf[100];
    int vallen;

    /* We have to reset before each GETANNOTATION command.
     * Handle it as a dirty hack.
     */
    if (!entry) {
	attvalues = NULL;
	lastwhich = 0;
	lastname[0] = '\0';
	lastentry[0] = '\0';
	return;
    }

    /* Check if this is a new entry.
     * If so, flush our current entry.  Otherwise append the entry.
     *
     * We also need a way to flush the last cached entry when we're done.
     * Handle it as a dirty hack.
     */
    if ((!attrib || !cursor || cursor->which != lastwhich ||
	strcmp(cursor->int_mboxname, lastname) || strcmp(entry, lastentry))
	&& attvalues) {
	if (fdata->ismetadata) {
	    prot_printf(fdata->pout, "* METADATA \"%s\" ",
			lastname);
	    output_metalist(fdata->pout, attvalues, lastentry);
	    prot_printf(fdata->pout, "\r\n");
	}
	else {
	    prot_printf(fdata->pout, "* ANNOTATION \"%s\" \"%s\" ",
			lastname, lastentry);
	    output_attlist(fdata->pout, attvalues);
	    prot_printf(fdata->pout, "\r\n");
	}
	
	freeattvalues(attvalues);
	attvalues = NULL;
    }
    if (!cursor) return;
    if (!attrib) return;

    lastwhich = cursor->which;
    if (cursor->which == ANNOTATION_SCOPE_MAILBOX)
	strlcpy(lastname, cursor->int_mboxname, sizeof(lastname));
    else
	lastname[0] = '\0';
    strlcpy(lastentry, entry, sizeof(lastentry));

    /* check if we already returned this entry */
    strlcpy(key, lastname, sizeof(key));
    strlcat(key, entry, sizeof(key));
    strlcat(key, userid, sizeof(key));
    if (hash_lookup(key, &(fdata->entry_table))) return;
    hash_insert(key, (void *)0xDEADBEEF, &(fdata->entry_table));

    vallen = attrib->size;
    if (fdata->sizeptr && fdata->maxsize < vallen) {
	/* too big - track the size of the largest */
	int *sp = fdata->sizeptr;
	if (*sp < vallen) *sp = vallen;
	return;
    }

    if (!userid[0]) { /* shared annotation */
	if ((fdata->attribs & ATTRIB_VALUE_SHARED)) {
	    appendattvalue(&attvalues, "value.shared", attrib->value);
	    fdata->found |= ATTRIB_VALUE_SHARED;
	}

	if ((fdata->attribs & ATTRIB_SIZE_SHARED)) {
	    snprintf(buf, sizeof(buf), SIZE_T_FMT, attrib->size);
	    appendattvalue(&attvalues, "size.shared", buf);
	    fdata->found |= ATTRIB_SIZE_SHARED;
	}
    }
    else { /* private annotation */
	if ((fdata->attribs & ATTRIB_VALUE_PRIV)) {
	    appendattvalue(&attvalues, "value.priv", attrib->value);
	    fdata->found |= ATTRIB_VALUE_PRIV;
	}

	if ((fdata->attribs & ATTRIB_SIZE_PRIV)) {
	    snprintf(buf, sizeof(buf), SIZE_T_FMT, attrib->size);
	    appendattvalue(&attvalues, "size.priv", buf);
	    fdata->found |= ATTRIB_SIZE_PRIV;
	}
    }
}

static int annotation_may_fetch(const struct fetchdata *fdata,
				const struct mboxlist_entry *mbentry,
				unsigned needed)
{
    unsigned my_rights;

    if (fdata->isadmin)
	return 1;

    if (!mbentry->acl)
	return 0;

    my_rights = cyrus_acl_myrights(fdata->auth_state, mbentry->acl);

    return ((my_rights & needed) == needed);
}

static void annotation_get_fromfile(const annotate_cursor_t *cursor,
				    const char *entry,
				    struct fetchdata *fdata,
				    void *rock)
{
    const char *filename = (const char *) rock;
    char path[MAX_MAILBOX_PATH+1], buf[MAX_MAILBOX_PATH+1], *p;
    FILE *f;
    struct annotation_data attrib;

    snprintf(path, sizeof(path), "%s/msg/%s", config_dir, filename);
    if ((f = fopen(path, "r")) && fgets(buf, sizeof(buf), f)) {
	if ((p = strchr(buf, '\r'))!=NULL) *p = 0;
	if ((p = strchr(buf, '\n'))!=NULL) *p = 0;

	memset(&attrib, 0, sizeof(attrib));

	attrib.value = buf;
	attrib.size = strlen(buf);
	output_entryatt(cursor, entry, "", &attrib, fdata);
    }
    if (f) fclose(f);
}

static void annotation_get_freespace(const annotate_cursor_t *cursor,
				     const char *entry,
				     struct fetchdata *fdata,
				     void *rock __attribute__((unused)))
{
    unsigned long tavail;
    char value[21];
    struct annotation_data attrib;

    (void) find_free_partition(&tavail);

    if (snprintf(value, sizeof(value), "%lu", tavail) == -1) return;

    memset(&attrib, 0, sizeof(attrib));

    attrib.value = value;
    attrib.size = strlen(value);

    output_entryatt(cursor, entry, "", &attrib, fdata);
}

static void annotation_get_server(const annotate_cursor_t *cursor,
				  const char *entry,
				  struct fetchdata *fdata,
				  void *rock __attribute__((unused))) 
{
    struct annotation_data attrib;

    if(!fdata || !cursor->mbentry)
	fatal("annotation_get_server called with bad parameters", EC_TEMPFAIL);
    
    /* Make sure its a remote mailbox */
    if (!cursor->mbentry->server) return;

    /* Check ACL */
    if (!annotation_may_fetch(fdata, cursor->mbentry, ACL_LOOKUP))
	return;

    memset(&attrib, 0, sizeof(attrib));

    attrib.value = cursor->mbentry->server;
    if (attrib.value)
	attrib.size = strlen(attrib.value);

    output_entryatt(cursor, entry, "", &attrib, fdata);
}

static void annotation_get_partition(const annotate_cursor_t *cursor,
				     const char *entry,
				     struct fetchdata *fdata,
				     void *rock __attribute__((unused))) 
{
    struct annotation_data attrib;

    if(!fdata || !cursor->mbentry)
	fatal("annotation_get_partition called with bad parameters",
	      EC_TEMPFAIL);
    
    /* Make sure its a local mailbox */
    if (cursor->mbentry->server) return;

    /* Check ACL */
    if (!annotation_may_fetch(fdata, cursor->mbentry, ACL_LOOKUP))
	return;

    memset(&attrib, 0, sizeof(attrib));

    attrib.value = cursor->mbentry->partition;
    if (attrib.value)
	attrib.size = strlen(attrib.value);

    output_entryatt(cursor, entry, "", &attrib, fdata);
}

static void annotation_get_size(const annotate_cursor_t *cursor,
				const char *entry,
				struct fetchdata *fdata,
				void *rock __attribute__((unused))) 
{
    struct mailbox *mailbox = NULL;
    char value[21];
    struct annotation_data attrib;

    if (!fdata || !cursor->mbentry)
	fatal("annotation_get_size called with bad parameters",
	      EC_TEMPFAIL);
    
    /* Make sure its a local mailbox */
    if (cursor->mbentry->server) return;

    /* Check ACL */
    if (!annotation_may_fetch(fdata, cursor->mbentry, ACL_LOOKUP|ACL_READ))
	return;

    if (mailbox_open_irl(cursor->int_mboxname, &mailbox))
	return;

    if (snprintf(value, sizeof(value), QUOTA_T_FMT, mailbox->i.quota_mailbox_used) == -1)
	return;

    mailbox_close(&mailbox);

    memset(&attrib, 0, sizeof(attrib));

    attrib.value = value;
    attrib.size = strlen(value);

    output_entryatt(cursor, entry, "", &attrib, fdata);
}

static void annotation_get_lastupdate(const annotate_cursor_t *cursor,
				      const char *entry,
				      struct fetchdata *fdata,
				      void *rock __attribute__((unused))) 
{
    struct stat sbuf;
    char valuebuf[RFC3501_DATETIME_MAX+1];
    struct annotation_data attrib;
    char *fname;

    if(!fdata || !cursor->mbentry)
	fatal("annotation_get_lastupdate called with bad parameters",
	      EC_TEMPFAIL);
    
    /* Make sure its a local mailbox */
    if (cursor->mbentry->server) return;

    /* Check ACL */
    if (!annotation_may_fetch(fdata, cursor->mbentry, ACL_LOOKUP|ACL_READ))
	return;

    fname = mboxname_metapath(cursor->mbentry->partition,
			      cursor->int_mboxname, META_INDEX, 0);
    if (!fname) return;
    if (stat(fname, &sbuf) == -1) return;
    
    time_to_rfc3501(sbuf.st_mtime, valuebuf, sizeof(valuebuf));
    
    memset(&attrib, 0, sizeof(attrib));

    attrib.value = valuebuf;
    attrib.size = strlen(valuebuf);

    output_entryatt(cursor, entry, "", &attrib, fdata);
}

static void annotation_get_lastpop(const annotate_cursor_t *cursor,
				   const char *entry,
				   struct fetchdata *fdata,
				   void *rock __attribute__((unused)))
{ 
    time_t date;
    struct mailbox *mailbox = NULL;
    char value[RFC3501_DATETIME_MAX+1];
    struct annotation_data attrib;
  
    if(!fdata || !cursor->mbentry)
      fatal("annotation_get_lastpop called with bad parameters",
              EC_TEMPFAIL);

    /* Make sure its a local mailbox */
    if (cursor->mbentry->server) return;

    /* Check ACL */
    if (!annotation_may_fetch(fdata, cursor->mbentry, ACL_LOOKUP|ACL_READ))
	return;

    if (mailbox_open_irl(cursor->int_mboxname, &mailbox) != 0)
	return;

    date = mailbox->i.pop3_last_login;

    mailbox_close(&mailbox);

    if (date != 0)
    {
	time_to_rfc3501(date, value, sizeof(value));
	attrib.value = value;
	attrib.size = strlen(value);
    }

    output_entryatt(cursor, entry, "", &attrib, fdata);
}

static void annotation_get_mailboxopt(const annotate_cursor_t *cursor,
				      const char *entry,
				      struct fetchdata *fdata,
				      void *rock)
{ 
    struct mailbox *mailbox = NULL;
    uint32_t flag = (unsigned long)rock;
    char value[40];
    struct annotation_data attrib;
  
    if (!cursor->int_mboxname || !entry || !fdata || !cursor->mbentry)
	fatal("annotation_get_mailboxopt called with bad parameters",
	      EC_TEMPFAIL);

    /* Make sure its a local mailbox */
    if (cursor->mbentry->server) return;

    /* Check ACL */
    if (!annotation_may_fetch(fdata, cursor->mbentry, ACL_LOOKUP|ACL_READ))
	return;

    if (mailbox_open_irl(cursor->int_mboxname, &mailbox) != 0)
	return;

    if (mailbox->i.options & flag) {
	strcpy(value, "true");
    } else {
	strcpy(value, "false");
    }

    mailbox_close(&mailbox);

    memset(&attrib, 0, sizeof(attrib));

    attrib.value = value;
    attrib.size = strlen(value);

    output_entryatt(cursor, entry, "", &attrib, fdata);
}

static void annotation_get_pop3showafter(const annotate_cursor_t *cursor,
				        const char *entry,
				        struct fetchdata *fdata,
				        void *rock __attribute__((unused)))
{
    struct mailbox *mailbox = NULL;
    time_t date;
    char value[RFC3501_DATETIME_MAX+1];
    struct annotation_data attrib;

    if(!cursor->int_mboxname || !entry || !fdata || !cursor->mbentry)
      fatal("annotation_get_pop3showafter called with bad parameters",
              EC_TEMPFAIL);

    /* Make sure its a local mailbox */
    if (cursor->mbentry->server) return;

    /* Check ACL */
    if (!annotation_may_fetch(fdata, cursor->mbentry, ACL_LOOKUP|ACL_READ))
	return;

    if (mailbox_open_irl(cursor->int_mboxname, &mailbox) != 0)
      return;

    date = mailbox->i.pop3_show_after;

    mailbox_close(&mailbox);

    memset(&attrib, 0, sizeof(attrib));

    if (date != 0)
    {
	time_to_rfc3501(date, value, sizeof(value));
	attrib.value = value;
	attrib.size = strlen(value);
    }

    output_entryatt(cursor, entry, "", &attrib, fdata);
}

static void annotation_get_specialuse(const annotate_cursor_t *cursor,
				      const char *entry,
				      struct fetchdata *fdata,
				      void *rock __attribute__((unused)))
{
    struct annotation_data attrib;

    if (!cursor->int_mboxname || !fdata || !cursor->mbentry)
	fatal("annotation_get_lastupdate called with bad parameters",
	      EC_TEMPFAIL);

    /* Make sure its a local mailbox */
    if (cursor->mbentry->server) return;

    /* Check ACL */
    if (!annotation_may_fetch(fdata, cursor->mbentry, ACL_LOOKUP|ACL_READ))
	return;

    if (!cursor->mbentry->specialuse)
	return;

    memset(&attrib, 0, sizeof(attrib));

    attrib.value = cursor->mbentry->specialuse;
    attrib.size = strlen(cursor->mbentry->specialuse);

    output_entryatt(cursor, entry, "", &attrib, fdata);
}

struct rw_rock {
    const annotate_cursor_t *cursor;
    struct fetchdata *fdata;
};

static int rw_cb(const char *mailbox __attribute__((unused)),
		 const char *entry, const char *userid,
		 struct annotation_data *attrib, void *rock)
{
    struct rw_rock *rw_rock = (struct rw_rock *) rock;

    if (!userid[0] || !strcmp(userid, rw_rock->fdata->userid)) {
	output_entryatt(rw_rock->cursor, entry, userid, attrib,
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

    if (cursor->which == ANNOTATION_SCOPE_SERVER) {
	if(cursor->int_mboxname || !entrypat || !fdata)
	    fatal("annotation_get_fromdb called with bad parameters", EC_TEMPFAIL);

	/* XXX any kind of access controls for reading? */

    } else if (cursor->which == ANNOTATION_SCOPE_MAILBOX) {
	if(!cursor->int_mboxname || !entrypat || !fdata || !cursor->mbentry)
	    fatal("annotation_get_fromdb called with bad parameters", EC_TEMPFAIL);

	/* Make sure its a local mailbox */
	if (cursor->mbentry->server) return;

	/* Check ACL */
	if (!annotation_may_fetch(fdata, cursor->mbentry, ACL_LOOKUP|ACL_READ))
	    return;
    }

    rw_rock.cursor = cursor;
    rw_rock.fdata = fdata;
    fdata->found = 0;

    annotatemore_findall2(cursor, entrypat, &rw_cb, &rw_rock, NULL);

    if (fdata->found != fdata->attribs &&
	(!strchr(entrypat, '%') && !strchr(entrypat, '*'))) {
	/* some results not found for an explicitly specified entry,
	 * make sure we emit explicit NILs */
	struct annotation_data empty = { NULL, 0 };
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
	output_entryatt(NULL, "", "", NULL, fdata);
    }
}

struct annotate_f_entry_list
{
    const annotate_entrydesc_t *entry;
    const char *entrypat;
    struct annotate_f_entry_list *next;
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
	ATTRIB_TYPE_STRING,
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
	ATTRIB_TYPE_STRING,
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

static int fetch_cb(char *name, int matchlen,
		    int maycreate __attribute__((unused)), void* rock)
{
    struct fetchdata *fdata = (struct fetchdata *) rock;
    struct annotate_f_entry_list *entries_ptr;
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

    annotate_cursor_setup(&cursor, int_mboxname);
    cursor.ext_mboxname = ext_mboxname;
    cursor.mbentry = mbentry;

    /* Loop through the list of provided entries to get */
    for (entries_ptr = fdata->entry_list;
	 entries_ptr;
	 entries_ptr = entries_ptr->next) {

	entries_ptr->entry->get(&cursor,
				entries_ptr->entry->name, fdata,
				(entries_ptr->entry->rock ?
				entries_ptr->entry->rock :
				(void*) entries_ptr->entrypat));
    }

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
		       struct auth_state *auth_state, struct protstream *pout,
		       int ismetadata, int *maxsizeptr)
{
    int i;
    struct fetchdata fdata;
    struct glob *g;
    const ptrarray_t *non_db_entries;
    const annotate_entrydesc_t *db_entry;

    memset(&fdata, 0, sizeof(struct fetchdata));
    fdata.pout = pout;
    fdata.namespace = namespace;
    fdata.userid = userid;
    fdata.isadmin = isadmin;
    fdata.auth_state = auth_state;
    fdata.ismetadata = ismetadata;
    if (maxsizeptr) {
	fdata.maxsize = *maxsizeptr; /* copy to check against */
        fdata.sizeptr = maxsizeptr; /* pointer to push largest back */
    }

    /* Reset state in output_entryatt() */
    output_entryatt(NULL, NULL, NULL, NULL, NULL);

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
			xmalloc(sizeof(struct annotate_f_entry_list));

		    nentry->next = fdata.entry_list;
		    nentry->entry = desc;
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
		xmalloc(sizeof(struct annotate_f_entry_list));

	    nentry->next = fdata.entry_list;
	    nentry->entry = db_entry;
	    nentry->entrypat = s;
	    fdata.entry_list = nentry;
	}
	    
	glob_free(&g);
    }

    if (scope->which == ANNOTATION_SCOPE_SERVER) {

	if (fdata.entry_list) {
	    struct annotate_f_entry_list *entries_ptr;
	    annotate_cursor_t cursor;

	    annotate_cursor_setup(&cursor, "");

	    /* xxx better way to determine a size for this table? */
	    construct_hash_table(&fdata.entry_table, 100, 1);

	    /* Loop through the list of provided entries to get */
	    for (entries_ptr = fdata.entry_list;
		 entries_ptr;
		 entries_ptr = entries_ptr->next) {
	
		if (!(entries_ptr->entry->proxytype == BACKEND_ONLY &&
		      proxy_fetch_func && !config_getstring(IMAPOPT_PROXYSERVERS))) {
		entries_ptr->entry->get(&cursor, entries_ptr->entry->name,
					&fdata,
					(entries_ptr->entry->rock ?
					 entries_ptr->entry->rock :
					 (void*) entries_ptr->entrypat));
		}
	    }

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

    /* Flush last cached entry in output_entryatt() */
    output_entryatt(NULL, "", "", NULL, &fdata);

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
			const char *userid, struct annotation_data *attrib)
{
    char key[MAX_MAILBOX_PATH+1];
    int keylen, datalen, r;
    const char *data;

    memset(attrib, 0, sizeof(struct annotation_data));

    keylen = make_key(mboxname, entry, userid, key, sizeof(key));

    do {
	r = DB->fetch(anndb, key, keylen, &data, &datalen, NULL);
    } while (r == CYRUSDB_AGAIN);

    if (!r && data) {
	r = split_attribs(data, datalen, attrib);
    }
    else if (r == CYRUSDB_NOTFOUND) r = 0;

    return r;
}

static int write_entry(const char *mboxname, const char *entry,
		       const char *userid,
		       const struct annotation_data *attrib,
		       struct txn **tid)
{
    char key[MAX_MAILBOX_PATH+1];
    int keylen, r;

    keylen = make_key(mboxname, entry, userid, key, sizeof(key));

    if (attrib->value == NULL) {
	do {
	    r = DB->delete(anndb, key, keylen, tid, 0);
	} while (r == CYRUSDB_AGAIN);
    }
    else {
	struct buf data = BUF_INITIALIZER;
	unsigned long l;
	static const char contenttype[] = "text/plain"; /* fake */

	l = htonl(attrib->size);
	buf_appendmap(&data, (const char *)&l, sizeof(l));

	buf_appendmap(&data, attrib->value, attrib->size);
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

	do {
	    r = DB->store(anndb, key, keylen, data.s, data.len, tid);
	} while (r == CYRUSDB_AGAIN);
	sync_log_annotation(mboxname);
	buf_free(&data);
    }

    return r;
}

int annotatemore_write_entry(const char *mboxname, const char *entry,
			     const char *userid,
			     const char *value,
			     size_t size,
			     struct txn **tid)
{
    struct annotation_data theentry;

    theentry.size = (value ? size : 0);
    theentry.value = value;

    return write_entry(mboxname, entry, userid, &theentry, tid);
}

int annotatemore_commit(struct txn *tid) {
    return tid ? DB->commit(anndb, tid) : 0;
}

int annotatemore_abort(struct txn *tid) {
    return tid ? DB->abort(anndb, tid) : 0;
}

struct storedata {
    struct namespace *namespace;
    const char *userid;
    int isadmin;
    struct auth_state *auth_state;
    struct annotate_st_entry_list *entry_list;

    /* number of mailboxes matching the pattern */
    unsigned count;

    /* for backends only */
    struct txn *tid;

    /* for proxies only */
    struct hash_table server_table;
};

struct annotate_st_entry_list
{
    const annotate_entrydesc_t *entry;
    struct annotation_data shared;
    struct annotation_data priv;
    int have_shared;
    int have_priv;

    struct annotate_st_entry_list *next;
};

static int annotate_canon_value(const char *value, int type,
				const char **canon)
{
    char *p = NULL;

    *canon = value;

    /* check for NIL */
    if (value == NULL)
	return 0;

    switch (type) {
    case ATTRIB_TYPE_STRING:
	/* free form */
	break;

    case ATTRIB_TYPE_BOOLEAN:
	/* make sure its "true" or "false" */
	if (!strcasecmp(value, "true")) *canon = "true";
	else if (!strcasecmp(value, "false")) *canon = "false";
	else return IMAP_ANNOTATION_BADVALUE;
	break;

    case ATTRIB_TYPE_UINT:
	/* make sure its a valid ulong ( >= 0 ) */
	errno = 0;
	strtoul(value, &p, 10);
	if ((p == value)		/* no value */
	    || (*p != '\0')		/* illegal char */
	    || errno			/* overflow */
	    || strchr(value, '-')) {	/* negative number */
	    return IMAP_ANNOTATION_BADVALUE;
	}
	break;

    case ATTRIB_TYPE_INT:
	/* make sure its a valid long */
	errno = 0;
	strtol(value, &p, 10);
	if ((p == value)		/* no value */
	    || (*p != '\0')		/* illegal char */
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

static int store_cb(const char *name, int matchlen,
		    int maycreate __attribute__((unused)), void *rock)
{
    struct storedata *sdata = (struct storedata *) rock;
    struct annotate_st_entry_list *entries_ptr;
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

    annotate_cursor_setup(&cursor, int_mboxname);
    cursor.ext_mboxname = name;
    cursor.mbentry = mbentry;

    for (entries_ptr = sdata->entry_list;
	 entries_ptr;
	 entries_ptr = entries_ptr->next) {

	r = entries_ptr->entry->set(&cursor, entries_ptr, sdata,
				    entries_ptr->entry->rock);
	if (r) goto cleanup;
    }

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

static int annotation_may_store(const struct storedata *sdata,
				const struct mboxlist_entry *mbentry,
				unsigned needed)
{
    unsigned my_rights;

    if (sdata->isadmin)
	return 1;

    if (!mbentry->acl)
	return 0;

    my_rights = cyrus_acl_myrights(sdata->auth_state, mbentry->acl);

    return ((my_rights & needed) == needed);
}

static int annotation_set_tofile(const annotate_cursor_t *cursor
				    __attribute__((unused)),
				 struct annotate_st_entry_list *entry,
				 struct storedata *sdata,
				 void *rock)
{
    const char *filename = (const char *) rock;
    char path[MAX_MAILBOX_PATH+1];
    FILE *f;

    /* Check ACL */
    if (!sdata->isadmin) return IMAP_PERMISSION_DENIED;

    snprintf(path, sizeof(path), "%s/msg/%s", config_dir, filename);

    /* XXX how do we do this atomically with other annotations? */
    if (entry->shared.value == NULL)
	return unlink(path);
    else if ((f = fopen(path, "w"))) {
	fprintf(f, "%s\n", entry->shared.value);
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

    if (entry->have_shared) {
	/* Check ACL
	 *
	 * Must be an admin to set shared server annotations and
	 * must have the required rights for shared mailbox annotations.
	 */
	int acl = ACL_READ | ACL_WRITE | entry->entry->acl;

	if (!sdata->isadmin &&
	    (!cursor->int_mboxname[0] || !cursor->mbentry->acl ||
	     ((cyrus_acl_myrights(sdata->auth_state,
				  cursor->mbentry->acl) & acl) != acl))) {
	    return IMAP_PERMISSION_DENIED;
	}

	/* Make sure its a server or local mailbox annotation */
	if (!cursor->int_mboxname[0] || !cursor->mbentry->server) {
	    r = write_entry(cursor->int_mboxname, entry->entry->name, "",
			    &(entry->shared), &(sdata->tid));
	}
    }
    if (entry->have_priv) {
	/* Check ACL
	 *
	 * XXX We don't actually need to check anything here,
	 * since we don't have any access control for server annotations
	 * and all we need for private mailbox annotations is ACL_LOOKUP,
	 * and we wouldn't be in this callback without it.
	 */

	/* Make sure its a server or local mailbox annotation */
	if (!cursor->int_mboxname[0] || !cursor->mbentry->server) {
	    r = write_entry(cursor->int_mboxname, entry->entry->name, sdata->userid,
			    &(entry->priv), &(sdata->tid));
	}
    }

    return r;
}

static int annotation_set_mailboxopt(const annotate_cursor_t *cursor,
				     struct annotate_st_entry_list *entry,
				     struct storedata *sdata,
				     void *rock)
{
    struct mailbox *mailbox = NULL;
    uint32_t flag = (unsigned long)rock;
    int r = 0;
    unsigned long newopts;

    /* Check ACL */
    if (!annotation_may_store(sdata, cursor->mbentry, ACL_LOOKUP|ACL_WRITE))
	return IMAP_PERMISSION_DENIED;

    r = mailbox_open_iwl(cursor->int_mboxname, &mailbox);
    if (r) return r;

    newopts = mailbox->i.options;

    if (entry->shared.value &&
	!strcmp(entry->shared.value, "true")) {
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
				     struct storedata *sdata,
				     void *rock __attribute__((unused)))
{
    struct mailbox *mailbox = NULL;
    int r = 0;
    time_t date;

    /* Check ACL */
    if (!annotation_may_store(sdata, cursor->mbentry, ACL_LOOKUP|ACL_WRITE))
	return IMAP_PERMISSION_DENIED;

    if (entry->shared.value == NULL) {
	/* Effectively removes the annotation */
	date = 0;
    }
    else {
	r = time_from_rfc3501(entry->shared.value, &date);
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
				     struct storedata *sdata,
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

    /* Check ACL */
    if (!annotation_may_store(sdata, cursor->mbentry, ACL_LOOKUP|ACL_WRITE))
	return IMAP_PERMISSION_DENIED;

    if (entry->shared.value == NULL) {
	/* Effectively removes the annotation */
	val = NULL;
    }
    else {
	for (i = 0; valid_specialuse[i]; i++) {
	    if (!strcasecmp(valid_specialuse[i], entry->shared.value))
		break;
	    /* or without the leading '\' */
	    if (!strcasecmp(valid_specialuse[i]+1, entry->shared.value))
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
		    if (!strcasecmp(extra_val, entry->shared.value)) {
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
	    const char *value;
	    if (!strcmp(av->attrib, "value.shared")) {
		if (!(attribs & ATTRIB_VALUE_SHARED)) {
		    r = IMAP_PERMISSION_DENIED;
		    goto cleanup;
		}
		r = annotate_canon_value(av->value,
					 desc->type,
					 &value);
		if (r)
		    goto cleanup;
		if (nentry) {
		    nentry->shared.value = value;
		    nentry->shared.size = value ? strlen(value) : 0;
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
		r = annotate_canon_value(av->value,
					 desc->type,
					 &value);
		if (r)
		    goto cleanup;
		if (nentry) {
		    nentry->priv.value = value;
		    nentry->priv.size = value ? strlen(value) : 0;
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
	    struct annotate_st_entry_list *entries_ptr;
	    annotate_cursor_t cursor;

	    annotate_cursor_setup(&cursor, "");

	    /* Loop through the list of provided entries to get */
	    for (entries_ptr = sdata.entry_list;
		 entries_ptr;
		 entries_ptr = entries_ptr->next) {

		r = entries_ptr->entry->set(&cursor, entries_ptr, &sdata,
					    entries_ptr->entry->rock);
		if (r) break;
	    }

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

    if (sdata.tid) {
	if (!r) {
	    /* commit txn */
	    DB->commit(anndb, sdata.tid);
	}
	else {
	    /* abort txn */
	    DB->abort(anndb, sdata.tid);
	}
    }

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
    const char *newmboxname;
    const char *olduserid;
    const char *newuserid;
    struct txn *tid;
};

static int rename_cb(const char *mailbox, const char *entry,
		     const char *userid, struct annotation_data *attrib,
		     void *rock)
{
    struct rename_rock *rrock = (struct rename_rock *) rock;
    int r = 0;

    if (rrock->newmboxname) {
	/* create newly renamed entry */

	if (rrock->olduserid  && rrock->newuserid &&
	    !strcmp(rrock->olduserid, userid)) {
	    /* renaming a user, so change the userid for priv annots */
	    r = write_entry(rrock->newmboxname, entry, rrock->newuserid,
			    attrib, &rrock->tid);
	}
	else {
	    r = write_entry(rrock->newmboxname, entry, userid,
			    attrib, &rrock->tid);
	}
    }

    if (!r) {
	/* delete existing entry */
	struct annotation_data dattrib = { NULL, 0 };
	r = write_entry(mailbox, entry, userid, &dattrib, &rrock->tid);
    }

    return r;
}

int annotatemore_rename(const char *oldmboxname, const char *newmboxname,
			const char *olduserid, const char *newuserid)
{
    struct rename_rock rrock;
    int r;

    rrock.newmboxname = newmboxname;
    rrock.olduserid = olduserid;
    rrock.newuserid = newuserid;
    rrock.tid = NULL;

    r = annotatemore_findall(oldmboxname, "*", &rename_cb, &rrock, &rrock.tid);

    if (rrock.tid) {
	if (!r) {
	    /* commit txn */
	    DB->commit(anndb, rrock.tid);
	}
	else {
	    /* abort txn */
	    DB->abort(anndb, rrock.tid);
	}
    }

    return r;
}

int annotatemore_delete(const char *mboxname)
{
    /* we treat a deleteion as a rename without a new name */

    return annotatemore_rename(mboxname, NULL, NULL, NULL);
}

/*************************  Annotation Initialization  ************************/

/* The following code is courtesy of Thomas Viehmann <tv@beamnet.de> */


const struct annotate_attrib annotation_scope_names[] =
{
    { "server", ANNOTATION_SCOPE_SERVER },
    { "mailbox", ANNOTATION_SCOPE_MAILBOX },
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
    int deprecated_warnings = 0;

    /* copy static entries into list */
    for (i = 0 ; server_builtin_entries[i].name ; i++)
	ptrarray_append(&server_entries, (void *)&server_builtin_entries[i]);

    /* copy static entries into list */
    for (i = 0 ; mailbox_builtin_entries[i].name ; i++)
	ptrarray_append(&mailbox_entries, (void *)&mailbox_builtin_entries[i]);

    /* parse config file */
    filename = config_getstring(IMAPOPT_ANNOTATION_DEFINITIONS);

    if (!filename)
	return;
  
    f = fopen(filename,"r");
    if (! f) {
	sprintf(errbuf, "could not open annotation definiton %s", filename);
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

	p = consume_comma(p);
  
	p2 = p;
	for (; *p && (isalnum(*p) || *p=='.' || *p=='-' || *p=='_' || *p=='/');
	     p++);

	if (table_lookup(annotation_scope_names, p2, p-p2,
			 "annotation scope")==ANNOTATION_SCOPE_SERVER) {
	    ptrarray_append(&server_entries, ae);
	}
	else {
	    ptrarray_append(&mailbox_entries, ae);
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
	if (ae->attribs & ATTRIB_DEPRECATED) {
	    if (!deprecated_warnings++)
		syslog(LOG_WARNING, "annotation definitions file contains "
				    "deprecated attribute names such as "
				    "content-type or modified-since, ignoring");
	    ae->attribs &= ~ATTRIB_DEPRECATED;
	}


	p = consume_comma(p);
	p2 = p;
	for (; *p && (isalnum(*p) || *p=='.' || *p=='-' || *p=='_' || *p=='/');
	     p++);
	tmp = xstrndup(p2, p-p2);
	ae->acl = cyrus_acl_strtomask(tmp);
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
