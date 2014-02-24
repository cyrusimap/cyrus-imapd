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
#include "imap_err.h"
#include "mboxlist.h"
#include "util.h"
#include "xmalloc.h"
#include "xstrlcpy.h"
#include "xstrlcat.h"

#include "annotate.h"
#include "sync_log.h"

#define DB config_annotation_db

struct db *anndb;
static int annotate_dbopen = 0;
int (*proxy_fetch_func)(const char *server, const char *mbox_pat,
			struct strlist *entry_pat,
			struct strlist *attribute_pat) = NULL;
int (*proxy_store_func)(const char *server, const char *mbox_pat,
			struct entryattlist *entryatts) = NULL;

void init_annotation_definitions();

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
    (*tail)->value = xstrdup(value);
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
void annotatemore_init(int myflags,
		       int (*fetch_func)(const char *, const char *,
					 struct strlist *, struct strlist *),
		       int (*store_func)(const char *, const char *,
					 struct entryattlist *))
{
    int r;

    if (myflags & ANNOTATE_SYNC) {
	r = DB->sync();
    }

    if (fetch_func) {
	proxy_fetch_func = fetch_func;
    }
    if (store_func) {
	proxy_store_func = store_func;
    }
    
    init_annotation_definitions();
}

void annotatemore_open(const char *fname)
{
    int ret;
    char *tofree = NULL;

    if (!fname)
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

static int split_attribs(const char *data, int datalen __attribute__((unused)),
			 struct annotation_data *attrib)
{
    unsigned long tmp; /* for alignment */

    /* xxx use datalen? */
    /* xxx sanity check the data? */
    memcpy(&tmp, data, sizeof(unsigned long));
    attrib->size = (size_t) ntohl(tmp);
    data += sizeof(unsigned long); /* skip to value */

    attrib->value = data;
    data += strlen(data) + 1; /* skip to contenttype */

    attrib->contenttype = data;
    data += strlen(data) + 1; /* skip to modifiedsince */

    memcpy(&tmp, data, sizeof(unsigned long));
    attrib->modifiedsince = (size_t) ntohl(tmp);
    data += sizeof(unsigned long); /* skip to optional attribs */

    return 0;
}

struct find_rock {
    struct glob *mglob;
    struct glob *eglob;
    int (*proc)();
    void *rock;
};

static int find_p(void *rock, const char *key,
		int keylen __attribute__((unused)),
		const char *data __attribute__((unused)),
		int datalen __attribute__((unused)))
{
    struct find_rock *frock = (struct find_rock *) rock;
    const char *mboxname, *entry, *userid;

    mboxname = key;
    entry = mboxname + strlen(mboxname) + 1;
    userid = entry + strlen(entry) + 1;

    return ((GLOB_TEST(frock->mglob, mboxname) != -1) &&
	    (GLOB_TEST(frock->eglob, entry) != -1));
}

static int find_cb(void *rock, const char *key,
		   int keylen __attribute__((unused)),
		   const char *data, int datalen)
{
    struct find_rock *frock = (struct find_rock *) rock;
    const char *mboxname, *entry, *userid;
    struct annotation_data attrib;
    int r;

    mboxname = key;
    entry = mboxname + strlen(mboxname) + 1;
    userid = entry + strlen(entry) + 1;

    r = split_attribs(data, datalen, &attrib);

    if (!r) r = frock->proc(mboxname, entry, userid, &attrib, frock->rock);

    return r;
}

int annotatemore_findall(const char *mailbox, const char *entry,
			 int (*proc)(), void *rock, struct txn **tid)
{
    char key[MAX_MAILBOX_PATH+1], *p;
    int keylen, r;
    struct find_rock frock;

    frock.mglob = glob_init(mailbox, GLOB_HIERARCHY);
    frock.eglob = glob_init(entry, GLOB_HIERARCHY);
    GLOB_SET_SEPARATOR(frock.eglob, '/');
    frock.proc = proc;
    frock.rock = rock;

    /* Find fixed-string pattern prefix */
    keylen = make_key(mailbox, entry, NULL, key, sizeof(key));

    for (p = key; keylen; p++, keylen--) {
	if (*p == '*' || *p == '%') break;
    }
    keylen = p - key;

    r = DB->foreach(anndb, key, keylen, &find_p, &find_cb, &frock, tid);

    glob_free(&frock.mglob);
    glob_free(&frock.eglob);

    return r;
}

enum {
    ATTRIB_VALUE_SHARED =		(1<<0),
    ATTRIB_VALUE_PRIV =			(1<<1),
    ATTRIB_SIZE_SHARED =		(1<<2),
    ATTRIB_SIZE_PRIV =			(1<<3),
    ATTRIB_MODIFIEDSINCE_SHARED =	(1<<4),
    ATTRIB_MODIFIEDSINCE_PRIV =		(1<<5),
    ATTRIB_CONTENTTYPE_SHARED = 	(1<<6),
    ATTRIB_CONTENTTYPE_PRIV = 		(1<<7)
};

typedef enum {
    ANNOTATION_PROXY_T_INVALID = 0,

    PROXY_ONLY = 1,
    BACKEND_ONLY = 2,
    PROXY_AND_BACKEND = 3
} annotation_proxy_t;

struct mailbox_annotation_rock
{
    char *server, *partition, *acl, *path, *mpath;
};

const struct annotate_info_t annotate_mailbox_flags[] =
{
    { "/vendor/cmu/cyrus-imapd/pop3newuidl",
      OPT_POP3_NEW_UIDL },
    { "/vendor/cmu/cyrus-imapd/duplicatedeliver",
      OPT_IMAP_DUPDELIVER },
    { "/vendor/cmu/cyrus-imapd/sharedseen",
      OPT_IMAP_SHAREDSEEN },
    { NULL, 0 }
};

/* To free values in the mailbox_annotation_rock as needed */
static void cleanup_mbrock(struct mailbox_annotation_rock *mbrock __attribute__((unused))) 
{
    /* Don't free server and partition, since they're straight from the
     * output of mboxlist_lookup() */
    return;
}

static void get_mb_data(const char *mboxname,
			struct mailbox_annotation_rock *mbrock) 
{
    if(!mbrock->server && !mbrock->partition) {
	struct mboxlist_entry mbentry;
	int r = mboxlist_lookup(mboxname, &mbentry, NULL);
	if (r) return;
	mbrock->server = mbentry.partition;
	mbrock->acl = mbentry.acl;

	mbrock->partition = strchr(mbrock->server, '!');
	if (mbrock->partition) {
	    *(mbrock->partition)++ = '\0';
	} else {
	    mbrock->partition = mbrock->server;
	    mbrock->server = NULL;
	}
    }
}

/***************************  Annotation Fetching  ***************************/

struct fetchdata {
    struct namespace *namespace;
    struct protstream *pout;
    char *userid;
    int isadmin;
    struct auth_state *auth_state;
     struct annotate_f_entry_list *entry_list;
    unsigned attribs;
    struct entryattlist **entryatts;
    struct hash_table entry_table;

    /* For proxies (a null entry_list indicates that we ONLY proxy) */
    /* if these are NULL, we have had a local exact match, and we
       DO NOT proxy */
    struct hash_table server_table;
    const char *orig_mailbox;
    struct strlist *orig_entry;
    struct strlist *orig_attribute;
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

/* Output a single entry and attributes for a single mailbox.
 * Shared and private annotations are output together by caching
 * the attributes until the mailbox and/or entry changes.
 *
 * The cache is reset by calling with a NULL mboxname or entry.
 * The last entry is flushed by calling with a NULL attrib.
 */
static void output_entryatt(const char *mboxname, const char *entry,
			    const char *userid, struct annotation_data *attrib,
			    struct fetchdata *fdata)
{
    static struct attvaluelist *attvalues = NULL;
    static char lastname[MAX_MAILBOX_BUFFER];
    static char lastentry[MAX_MAILBOX_BUFFER];
    char key[MAX_MAILBOX_BUFFER]; /* XXX MAX_MAILBOX_NAME + entry + userid */
    char buf[100];

    /* We have to reset before each GETANNOTATION command.
     * Handle it as a dirty hack.
     */
    if (!mboxname || !entry) {
	attvalues = NULL;
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
    if ((!attrib || strcmp(mboxname, lastname) || strcmp(entry, lastentry))
	&& attvalues) {
	prot_printf(fdata->pout, "* ANNOTATION \"%s\" \"%s\" ",
		    lastname, lastentry);
	output_attlist(fdata->pout, attvalues);
	prot_printf(fdata->pout, "\r\n");
	
	freeattvalues(attvalues);
	attvalues = NULL;
    }
    if (!attrib) return;

    strlcpy(lastname, mboxname, sizeof(lastname));
    strlcpy(lastentry, entry, sizeof(lastentry));

    /* check if we already returned this entry */
    strlcpy(key, mboxname, sizeof(key));
    strlcat(key, entry, sizeof(key));
    strlcat(key, userid, sizeof(key));
    if (hash_lookup(key, &(fdata->entry_table))) return;
    hash_insert(key, (void *)0xDEADBEEF, &(fdata->entry_table));

    if (!userid[0]) { /* shared annotation */
	if ((fdata->attribs & ATTRIB_VALUE_SHARED) && attrib->value) {
	    appendattvalue(&attvalues, "value.shared", attrib->value);
	}

	if ((fdata->attribs & ATTRIB_CONTENTTYPE_SHARED)
	    && attrib->value && attrib->contenttype) {
	    appendattvalue(&attvalues, "content-type.shared",
			   attrib->contenttype);
	}

	/* Base the return of the size attribute on whether or not there is
	 * an attribute, not whether size is nonzero. */
	if ((fdata->attribs & ATTRIB_SIZE_SHARED) && attrib->value) {
	    snprintf(buf, sizeof(buf), SIZE_T_FMT, attrib->size);
	    appendattvalue(&attvalues, "size.shared", buf);
	}

	/* For this one we need both a value for the entry *and* a nonzero
	 * modifiedsince time */
	if ((fdata->attribs & ATTRIB_MODIFIEDSINCE_SHARED)
	    && attrib->value && attrib->modifiedsince) {
	    snprintf(buf, sizeof(buf), "%ld", attrib->modifiedsince);
	    appendattvalue(&attvalues, "modifiedsince.shared", buf);
	}
    }
    else { /* private annotation */
	if ((fdata->attribs & ATTRIB_VALUE_PRIV) && attrib->value) {
	    appendattvalue(&attvalues, "value.priv", attrib->value);
	}

	if ((fdata->attribs & ATTRIB_CONTENTTYPE_PRIV)
	    && attrib->value && attrib->contenttype) {
	    appendattvalue(&attvalues, "content-type.priv",
			   attrib->contenttype);
	}

	/* Base the return of the size attribute on whether or not there is
	 * an attribute, not whether size is nonzero. */
	if ((fdata->attribs & ATTRIB_SIZE_PRIV) && attrib->value) {
	    snprintf(buf, sizeof(buf), SIZE_T_FMT, attrib->size);
	    appendattvalue(&attvalues, "size.priv", buf);
	}

	/* For this one we need both a value for the entry *and* a nonzero
	 * modifiedsince time */
	if ((fdata->attribs & ATTRIB_MODIFIEDSINCE_PRIV)
	    && attrib->value && attrib->modifiedsince) {
	    snprintf(buf, sizeof(buf), "%ld", attrib->modifiedsince);
	    appendattvalue(&attvalues, "modifiedsince.priv", buf);
	}
    }
}

static void annotation_get_fromfile(const char *int_mboxname __attribute__((unused)),
				    const char *ext_mboxname,
				    const char *entry,
				    struct fetchdata *fdata,
				    struct mailbox_annotation_rock *mbrock __attribute__((unused)),
				    void *rock)
{
    const char *filename = (const char *) rock;
    char path[MAX_MAILBOX_PATH+1], buf[MAX_MAILBOX_PATH+1], *p;
    FILE *f;
    struct stat statbuf;
    struct annotation_data attrib;

    snprintf(path, sizeof(path), "%s/msg/%s", config_dir, filename);
    if ((f = fopen(path, "r")) && fgets(buf, sizeof(buf), f)) {
	if ((p = strchr(buf, '\r'))!=NULL) *p = 0;
	if ((p = strchr(buf, '\n'))!=NULL) *p = 0;

	memset(&attrib, 0, sizeof(attrib));

	attrib.value = buf;
	attrib.size = strlen(buf);
	attrib.contenttype = "text/plain";
	if (!fstat(fileno(f), &statbuf))
	    attrib.modifiedsince = statbuf.st_mtime;

	output_entryatt(ext_mboxname, entry, "", &attrib, fdata);
    }
    if (f) fclose(f);
}

static void annotation_get_freespace(const char *int_mboxname __attribute__((unused)),
				     const char *ext_mboxname,
				     const char *entry,
				     struct fetchdata *fdata,
				     struct mailbox_annotation_rock *mbrock __attribute__((unused)),
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
    attrib.contenttype = "text/plain";

    output_entryatt(ext_mboxname, entry, "", &attrib, fdata);
}

static void annotation_get_server(const char *int_mboxname,
				  const char *ext_mboxname,
				  const char *entry,
				  struct fetchdata *fdata,
				  struct mailbox_annotation_rock *mbrock,
				  void *rock __attribute__((unused))) 
{
    struct annotation_data attrib;

    if(!int_mboxname || !ext_mboxname || !fdata || !mbrock)
	fatal("annotation_get_server called with bad parameters", EC_TEMPFAIL);
    
    get_mb_data(int_mboxname, mbrock);

    /* Make sure its a remote mailbox */
    if (!mbrock->server) return;

    /* Check ACL */
    if(!fdata->isadmin &&
       (!mbrock->acl ||
        !(cyrus_acl_myrights(fdata->auth_state, mbrock->acl) & ACL_LOOKUP)))
	return;

    memset(&attrib, 0, sizeof(attrib));

    attrib.value = mbrock->server;
    if(mbrock->server) {
	attrib.size = strlen(mbrock->server);
	attrib.contenttype = "text/plain";
    }

    output_entryatt(ext_mboxname, entry, "", &attrib, fdata);
}

static void annotation_get_partition(const char *int_mboxname,
				     const char *ext_mboxname,
				     const char *entry,
				     struct fetchdata *fdata,
				     struct mailbox_annotation_rock *mbrock,
				     void *rock __attribute__((unused))) 
{
    struct annotation_data attrib;

    if(!int_mboxname || !ext_mboxname || !fdata || !mbrock)
	fatal("annotation_get_partition called with bad parameters",
	      EC_TEMPFAIL);
    
    get_mb_data(int_mboxname, mbrock);

    /* Make sure its a local mailbox */
    if (mbrock->server) return;

    /* Check ACL */
    if(!fdata->isadmin &&
       (!mbrock->acl ||
        !(cyrus_acl_myrights(fdata->auth_state, mbrock->acl) & ACL_LOOKUP)))
	return;

    memset(&attrib, 0, sizeof(attrib));

    attrib.value = mbrock->partition;
    if(mbrock->partition) {
	attrib.size = strlen(mbrock->partition);
	attrib.contenttype = "text/plain";
    }

    output_entryatt(ext_mboxname, entry, "", &attrib, fdata);
}

static void annotation_get_size(const char *int_mboxname,
				const char *ext_mboxname,
				const char *entry,
				struct fetchdata *fdata,
				struct mailbox_annotation_rock *mbrock,
				void *rock __attribute__((unused))) 
{
    struct mailbox *mailbox = NULL;
    char value[21];
    struct annotation_data attrib;

    if (!int_mboxname || !ext_mboxname || !fdata || !mbrock)
	fatal("annotation_get_size called with bad parameters",
	      EC_TEMPFAIL);
    
    get_mb_data(int_mboxname, mbrock);

    /* Make sure its a local mailbox */
    if (mbrock->server) return;

    /* Check ACL */
    if(!fdata->isadmin &&
       (!mbrock->acl ||
        !(cyrus_acl_myrights(fdata->auth_state, mbrock->acl) & ACL_LOOKUP) ||
        !(cyrus_acl_myrights(fdata->auth_state, mbrock->acl) & ACL_READ)))
	return;

    if (mailbox_open_irl(int_mboxname, &mailbox))
	return;

    if (snprintf(value, sizeof(value), QUOTA_T_FMT, mailbox->i.quota_mailbox_used) == -1)
	return;

    mailbox_close(&mailbox);

    memset(&attrib, 0, sizeof(attrib));

    attrib.value = value;
    attrib.size = strlen(value);
    attrib.contenttype = "text/plain";

    output_entryatt(ext_mboxname, entry, "", &attrib, fdata);
}

static void annotation_get_lastupdate(const char *int_mboxname,
				      const char *ext_mboxname,
				      const char *entry,
				      struct fetchdata *fdata,
				      struct mailbox_annotation_rock *mbrock,
				      void *rock __attribute__((unused))) 
{
    struct stat sbuf;
    char valuebuf[128];
    struct annotation_data attrib;
    char *fname;

    if(!int_mboxname || !ext_mboxname || !fdata || !mbrock)
	fatal("annotation_get_lastupdate called with bad parameters",
	      EC_TEMPFAIL);
    
    get_mb_data(int_mboxname, mbrock);

    /* Make sure its a local mailbox */
    if (mbrock->server) return;

    /* Check ACL */
    if(!fdata->isadmin &&
       (!mbrock->acl ||
        !(cyrus_acl_myrights(fdata->auth_state, mbrock->acl) & ACL_LOOKUP) ||
        !(cyrus_acl_myrights(fdata->auth_state, mbrock->acl) & ACL_READ)))
	return;

    fname = mboxname_metapath(mbrock->partition, int_mboxname, META_INDEX, 0);
    if (!fname) return;
    if (stat(fname, &sbuf) == -1) return;
    
    cyrus_ctime(sbuf.st_mtime, valuebuf);
    
    memset(&attrib, 0, sizeof(attrib));

    attrib.value = valuebuf;
    attrib.size = strlen(valuebuf);
    attrib.contenttype = "text/plain";

    output_entryatt(ext_mboxname, entry, "", &attrib, fdata);
}

static void annotation_get_lastpop(const char *int_mboxname,
                                 const char *ext_mboxname,
                                 const char *entry,
                                 struct fetchdata *fdata,
                                 struct mailbox_annotation_rock *mbrock,
                                 void *rock __attribute__((unused)))
{ 
    struct mailbox *mailbox = NULL;
    char value[40];
    struct annotation_data attrib;
  
    if(!int_mboxname || !ext_mboxname || !fdata || !mbrock)
      fatal("annotation_get_lastpop called with bad parameters",
              EC_TEMPFAIL);

    get_mb_data(int_mboxname, mbrock);

    /* Make sure its a local mailbox */
    if (mbrock->server) return;

    /* Check ACL */
    if(!fdata->isadmin &&
       (!mbrock->acl ||
      !(cyrus_acl_myrights(fdata->auth_state, mbrock->acl) & ACL_LOOKUP) ||
      !(cyrus_acl_myrights(fdata->auth_state, mbrock->acl) & ACL_READ)))
      return;


    if (mailbox_open_irl(int_mboxname, &mailbox) != 0)
      return;

    if (mailbox->i.pop3_last_login == 0) {
	strcpy (value, " ");
    } else {
	cyrus_ctime(mailbox->i.pop3_last_login, value);
    }

    mailbox_close(&mailbox);

    memset(&attrib, 0, sizeof(attrib));

    attrib.value = value;
    attrib.size = strlen(value);
    attrib.contenttype = "text/plain";

    output_entryatt(ext_mboxname, entry, "", &attrib, fdata);
}

static void annotation_get_mailboxopt(const char *int_mboxname,
				      const char *ext_mboxname,
				      const char *entry,
				      struct fetchdata *fdata,
				      struct mailbox_annotation_rock *mbrock,
				      void *rock __attribute__((unused)))
{ 
    struct mailbox *mailbox = NULL;
    int flag = 0, i;
    char value[40];
    struct annotation_data attrib;
  
    if(!int_mboxname || !ext_mboxname || !entry || !fdata || !mbrock)
      fatal("annotation_get_mailboxopt called with bad parameters",
              EC_TEMPFAIL);

    get_mb_data(int_mboxname, mbrock);

    /* Make sure its a local mailbox */
    if (mbrock->server) return;

    /* check that this is a mailboxopt annotation */
    for (i = 0; annotate_mailbox_flags[i].name; i++) {
	if (!strcmp(entry, annotate_mailbox_flags[i].name)) {
	    flag = annotate_mailbox_flags[i].flag;
	    break;
	}
    }
    if (!flag) return;
  
    /* Check ACL */
    if(!fdata->isadmin &&
       (!mbrock->acl ||
      !(cyrus_acl_myrights(fdata->auth_state, mbrock->acl) & ACL_LOOKUP) ||
      !(cyrus_acl_myrights(fdata->auth_state, mbrock->acl) & ACL_READ)))
      return;


    if (mailbox_open_irl(int_mboxname, &mailbox) != 0)
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
    attrib.contenttype = "text/plain";

    output_entryatt(ext_mboxname, entry, "", &attrib, fdata);
}

struct rw_rock {
    const char *ext_mboxname;
    struct fetchdata *fdata;
};

static int rw_cb(const char *mailbox __attribute__((unused)),
		 const char *entry, const char *userid,
		 struct annotation_data *attrib, void *rock)
{
    struct rw_rock *rw_rock = (struct rw_rock *) rock;

    if (!userid[0] || !strcmp(userid, rw_rock->fdata->userid)) {
	output_entryatt(rw_rock->ext_mboxname, entry, userid, attrib,
			rw_rock->fdata);
    }

    return 0;
}

static void annotation_get_fromdb(const char *int_mboxname,
				  const char *ext_mboxname,
				  const char *entry  __attribute__((unused)),
				  struct fetchdata *fdata,
				  struct mailbox_annotation_rock *mbrock,
				  void *rock)
{
    struct rw_rock rw_rock;
    const char *entrypat = (const char *) rock;

    if(!int_mboxname || !ext_mboxname || !entrypat || !fdata ||
       (int_mboxname[0] && !mbrock)) {
	fatal("annotation_get_fromdb called with bad parameters", EC_TEMPFAIL);
    }

    if (!int_mboxname[0]) {
	/* server annotation */

	/* XXX any kind of access controls for reading? */
    }
    else {
	/* mailbox annotation */
	get_mb_data(int_mboxname, mbrock);

	/* Make sure its a local mailbox */
	if (mbrock->server) return;

	/* Check ACL */
	if(!fdata->isadmin &&
	   (!mbrock->acl ||
	    !(cyrus_acl_myrights(fdata->auth_state, mbrock->acl) & ACL_LOOKUP) ||
	    !(cyrus_acl_myrights(fdata->auth_state, mbrock->acl) & ACL_READ)))
	    return;
    }

    rw_rock.ext_mboxname = ext_mboxname;
    rw_rock.fdata = fdata;

    annotatemore_findall(int_mboxname, entrypat, &rw_cb, &rw_rock, NULL);
}

struct annotate_f_entry
{
    const char *name;		/* entry name */
    annotation_proxy_t proxytype; /* mask of allowed server types */
    void (*get)(const char *int_mboxname, const char *ext_mboxname,
		const char *name, struct fetchdata *fdata,
		struct mailbox_annotation_rock *mbrock,
		void *rock);	/* function to get the entry */
    void *rock;			/* rock passed to get() function */
};

struct annotate_f_entry_list
{
    const struct annotate_f_entry *entry;
    const char *entrypat;
    struct annotate_f_entry_list *next;
};

const struct annotate_f_entry mailbox_ro_entries[] =
{
    { "/vendor/cmu/cyrus-imapd/partition", BACKEND_ONLY,
      annotation_get_partition, NULL },
    { "/vendor/cmu/cyrus-imapd/server", PROXY_ONLY,
      annotation_get_server, NULL },
    { "/vendor/cmu/cyrus-imapd/size", BACKEND_ONLY,
      annotation_get_size, NULL },
    { "/vendor/cmu/cyrus-imapd/lastupdate", BACKEND_ONLY,
      annotation_get_lastupdate, NULL },
    { "/vendor/cmu/cyrus-imapd/lastpop", BACKEND_ONLY,
      annotation_get_lastpop, NULL },
    { "/vendor/cmu/cyrus-imapd/pop3newuidl", BACKEND_ONLY,
      annotation_get_mailboxopt, NULL },
    { "/vendor/cmu/cyrus-imapd/sharedseen", BACKEND_ONLY,
      annotation_get_mailboxopt, NULL },
    { "/vendor/cmu/cyrus-imapd/duplicatedeliver", BACKEND_ONLY,
      annotation_get_mailboxopt, NULL },
    { NULL, ANNOTATION_PROXY_T_INVALID, NULL, NULL }
};

const struct annotate_f_entry mailbox_rw_entry =
    { NULL, BACKEND_ONLY, annotation_get_fromdb, NULL };

const struct annotate_f_entry server_legacy_entries[] =
{
    { "/motd", PROXY_AND_BACKEND, annotation_get_fromfile, "motd" },
    { "/vendor/cmu/cyrus-imapd/shutdown", PROXY_AND_BACKEND,
      annotation_get_fromfile, "shutdown" },
    { "/vendor/cmu/cyrus-imapd/freespace", BACKEND_ONLY,
      annotation_get_freespace, NULL },
    { NULL, ANNOTATION_PROXY_T_INVALID, NULL, NULL }
};

const struct annotate_f_entry server_entry =
    { NULL, PROXY_AND_BACKEND, annotation_get_fromdb, NULL };

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
    { "modifiedsince", ATTRIB_MODIFIEDSINCE_SHARED | ATTRIB_MODIFIEDSINCE_PRIV },
    { "modifiedsince.shared", ATTRIB_MODIFIEDSINCE_SHARED },
    { "modifiedsince.priv", ATTRIB_MODIFIEDSINCE_PRIV },
    { "content-type", ATTRIB_CONTENTTYPE_SHARED | ATTRIB_CONTENTTYPE_PRIV },
    { "content-type.shared", ATTRIB_CONTENTTYPE_SHARED },
    { "content-type.priv", ATTRIB_CONTENTTYPE_PRIV },
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
    struct mailbox_annotation_rock mbrock;

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

    memset(&mbrock, 0, sizeof(struct mailbox_annotation_rock));

    if (proxy_fetch_func && fdata->orig_entry) {
	get_mb_data(int_mboxname, &mbrock);
    }

    /* Loop through the list of provided entries to get */
    for (entries_ptr = fdata->entry_list;
	 entries_ptr;
	 entries_ptr = entries_ptr->next) {
	
	entries_ptr->entry->get(int_mboxname, ext_mboxname,
				entries_ptr->entry->name, fdata,
				&mbrock, (entries_ptr->entry->rock ?
					  entries_ptr->entry->rock :
					  (void*) entries_ptr->entrypat));
    }

    if (proxy_fetch_func && fdata->orig_entry && mbrock.server &&
	!hash_lookup(mbrock.server, &(fdata->server_table))) {
	/* xxx ignoring result */
	proxy_fetch_func(mbrock.server, fdata->orig_mailbox,
			 fdata->orig_entry, fdata->orig_attribute);
	hash_insert(mbrock.server, (void *)0xDEADBEEF, &(fdata->server_table));
    }

    cleanup_mbrock(&mbrock);

    return 0;
}

int annotatemore_fetch(char *mailbox,
		       struct strlist *entries, struct strlist *attribs,
		       struct namespace *namespace, int isadmin, char *userid,
		       struct auth_state *auth_state, struct protstream *pout)
{
    struct strlist *e = entries;
    struct strlist *a = attribs;
    struct fetchdata fdata;
    struct glob *g;
    const struct annotate_f_entry *non_db_entries;
    const struct annotate_f_entry *db_entry;

    memset(&fdata, 0, sizeof(struct fetchdata));
    fdata.pout = pout;
    fdata.namespace = namespace;
    fdata.userid = userid;
    fdata.isadmin = isadmin;
    fdata.auth_state = auth_state;

    /* Reset state in output_entryatt() */
    output_entryatt(NULL, NULL, NULL, NULL, NULL);

    /* Build list of attributes to fetch */
    while (a) {
	int attribcount;

	g = glob_init(a->s, GLOB_HIERARCHY);
	
	for (attribcount = 0;
	     annotation_attributes[attribcount].name;
	     attribcount++) {
	    if (GLOB_TEST(g, annotation_attributes[attribcount].name) != -1) {
		fdata.attribs |= annotation_attributes[attribcount].entry;
	    }
	}
	
	glob_free(&g);

	a = a->next;
    }

    if (!fdata.attribs) return 0;

    if (!mailbox[0]) {
	/* server annotation(s) */
	non_db_entries = server_legacy_entries;
	db_entry = &server_entry;
    }
    else {
	/* mailbox annotation(s) */
	non_db_entries = mailbox_ro_entries;
	db_entry = &mailbox_rw_entry;
    }

    /* Build a list of callbacks for fetching the annotations */
    while (e) {
	int entrycount;
	int check_db = 0; /* should we check the db for this entry? */

	g = glob_init(e->s, GLOB_HIERARCHY);
	GLOB_SET_SEPARATOR(g, '/');

	for (entrycount = 0;
	     non_db_entries[entrycount].name;
	     entrycount++) {

	    if (GLOB_TEST(g, non_db_entries[entrycount].name) != -1) {
		/* Add this entry to our list only if it
		   applies to our particular server type */
		if ((non_db_entries[entrycount].proxytype != PROXY_ONLY)
		    || proxy_fetch_func) {
		    struct annotate_f_entry_list *nentry =
			xmalloc(sizeof(struct annotate_f_entry_list));

		    nentry->next = fdata.entry_list;
		    nentry->entry = &(non_db_entries[entrycount]);
		    fdata.entry_list = nentry;
		}
	    }

	    if (!strcmp(e->s, non_db_entries[entrycount].name)) {
		/* exact match */
		if (non_db_entries[entrycount].proxytype != PROXY_ONLY) {
		    fdata.orig_entry = entries;  /* proxy it */
		}
		break;
	    }
	}
		
	if (!non_db_entries[entrycount].name) {
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
	    nentry->entrypat = e->s;
	    fdata.entry_list = nentry;
	}
	    
	glob_free(&g);

	e = e->next;
    }

    if (!mailbox[0]) {
	/* server annotation(s) */

	if (fdata.entry_list) {
	    struct annotate_f_entry_list *entries_ptr;

	    /* xxx better way to determine a size for this table? */
	    construct_hash_table(&fdata.entry_table, 100, 1);

	    /* Loop through the list of provided entries to get */
	    for (entries_ptr = fdata.entry_list;
		 entries_ptr;
		 entries_ptr = entries_ptr->next) {
	
		if (!(entries_ptr->entry->proxytype == BACKEND_ONLY &&
		      proxy_fetch_func && !config_getstring(IMAPOPT_PROXYSERVERS))) {
		entries_ptr->entry->get("", "", entries_ptr->entry->name,
					&fdata, NULL,
					(entries_ptr->entry->rock ?
					 entries_ptr->entry->rock :
					 (void*) entries_ptr->entrypat));
		}
	    }

	    free_hash_table(&fdata.entry_table, NULL);
	}
    }
    else {
	/* mailbox annotation(s) */

	if (fdata.entry_list || proxy_fetch_func) {
	    char mboxpat[MAX_MAILBOX_BUFFER];

	    /* Reset state in fetch_cb */
	    fetch_cb(NULL, 0, 0, 0);

	    /* xxx better way to determine a size for this table? */
	    construct_hash_table(&fdata.entry_table, 100, 1);

	    if(proxy_fetch_func && fdata.orig_entry) {
		fdata.orig_mailbox = mailbox;
		fdata.orig_attribute = attribs;
		/* xxx better way to determine a size for this table? */
		construct_hash_table(&fdata.server_table, 10, 1);
	    }

	    /* copy the pattern so we can change hiersep */
	    strlcpy(mboxpat, mailbox, sizeof(mboxpat));
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
    output_entryatt("", "", "", NULL, &fdata);

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
		       const char *userid, struct annotation_data *attrib,
		       struct txn **tid)
{
    char key[MAX_MAILBOX_PATH+1];
    int keylen, r;

    keylen = make_key(mboxname, entry, userid, key, sizeof(key));

    if (!strcmp(attrib->value, "NIL")) {
	do {
	    r = DB->delete(anndb, key, keylen, tid, 0);
	} while (r == CYRUSDB_AGAIN);
    }
    else {
	struct buf data = BUF_INITIALIZER;
	unsigned long l;

	l = htonl(strlen(attrib->value));
	buf_appendmap(&data, (const char *) &l, sizeof(l));

	buf_appendcstr(&data, attrib->value);
	buf_putc(&data, '\0');

	if (!attrib->contenttype || !strcmp(attrib->contenttype, "NIL")) {
	    attrib->contenttype = "text/plain";
	}
	buf_appendcstr(&data, attrib->contenttype);
	buf_putc(&data, '\0');

	l = htonl(attrib->modifiedsince);
	buf_appendmap(&data, (const char *) &l, sizeof(l));

	do {
	    r = DB->store(anndb, key, keylen, data.s, data.len, tid);
	} while (r == CYRUSDB_AGAIN);
	buf_free(&data);

	sync_log_annotation(mboxname);
    }

    return r;
}

int annotatemore_write_entry(const char *mboxname, const char *entry,
			     const char *userid,
			     const char *value, const char *contenttype,
			     size_t size, time_t modifiedsince,
			     struct txn **tid) 
{
    struct annotation_data theentry;
    
    theentry.size = size;
    theentry.modifiedsince = modifiedsince ? modifiedsince : time(NULL);
    theentry.contenttype = contenttype ? contenttype : "text/plain";
    theentry.value = value ? value : "NIL";

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

enum {
    ATTRIB_TYPE_CONTENTTYPE,
    ATTRIB_TYPE_STRING,
    ATTRIB_TYPE_BOOLEAN,
    ATTRIB_TYPE_UINT,
    ATTRIB_TYPE_INT
};

struct annotate_st_entry {
    const char *name;		/* entry name */
    int type;			/* entry type */
    annotation_proxy_t proxytype; /* mask of allowed server types */
    int attribs;		/* mask of allowed attributes */
    int acl;			/* add'l required ACL for .shared */
    int (*set)(const char *int_mboxname, struct annotate_st_entry_list *entry,
	       struct storedata *sdata, struct mailbox_annotation_rock *mbrock,
	       void *rock);	/* function to set the entry */
    void *rock;			/* rock passed to set() function */
};

struct annotate_st_entry_list
{
    const struct annotate_st_entry *entry;
    struct annotation_data shared;
    struct annotation_data priv;

    struct annotate_st_entry_list *next;
};

static const char *annotate_canon_value(const char *value, int type)
{
    char *p = NULL;
    unsigned long n;

    /* check for "NIL" */
    if (!strcasecmp(value, "NIL")) return "NIL";

    switch (type) {
    case ATTRIB_TYPE_CONTENTTYPE:
	/* XXX how do we check this? */
	break;

    case ATTRIB_TYPE_STRING:
	/* free form */
	break;

    case ATTRIB_TYPE_BOOLEAN:
	/* make sure its "true" or "false" */
	if (!strcasecmp(value, "true")) return "true";
	else if (!strcasecmp(value, "false")) return "false";
	else return NULL;
	break;

    case ATTRIB_TYPE_UINT:
	/* make sure its a valid ulong ( >= 0 ) */
	errno = 0;
	n = strtoul(value, &p, 10);
	if ((p == value)		/* no value */
	    || (*p != '\0')		/* illegal char */
	    || errno			/* overflow */
	    || strchr(value, '-')) {	/* negative number */
	    return NULL;
	}
	break;

    case ATTRIB_TYPE_INT:
	/* make sure its a valid long */
	errno = 0;
	n = strtol(value, &p, 10);
	if ((p == value)		/* no value */
	    || (*p != '\0')		/* illegal char */
	    || errno) {			/* underflow/overflow */
	    return NULL;
	}
	break;

    default:
	/* unknown type */
	return NULL;
	break;
    }

    return value;
}

static int store_cb(const char *name, int matchlen,
		    int maycreate __attribute__((unused)), void *rock)
{
    struct storedata *sdata = (struct storedata *) rock;
    struct annotate_st_entry_list *entries_ptr;
    static char lastname[MAX_MAILBOX_PATH+1];
    static int sawuser = 0;
    char int_mboxname[MAX_MAILBOX_BUFFER];
    struct mailbox_annotation_rock mbrock;
    int r = 0;

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

    memset(&mbrock, 0, sizeof(struct mailbox_annotation_rock));
    get_mb_data(int_mboxname, &mbrock);

    for (entries_ptr = sdata->entry_list;
	 entries_ptr;
	 entries_ptr = entries_ptr->next) {

	r = entries_ptr->entry->set(int_mboxname, entries_ptr, sdata, &mbrock,
				    entries_ptr->entry->rock);
	if (r) goto cleanup;
    }

    sync_log_annotation(int_mboxname);

    sdata->count++;

    if (proxy_store_func && mbrock.server &&
	!hash_lookup(mbrock.server, &(sdata->server_table))) {
	hash_insert(mbrock.server, (void *)0xDEADBEEF, &(sdata->server_table));
    }

  cleanup:
    cleanup_mbrock(&mbrock);

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

static int annotation_set_tofile(const char *int_mboxname __attribute__((unused)),
				 struct annotate_st_entry_list *entry,
				 struct storedata *sdata,
				 struct mailbox_annotation_rock *mbrock __attribute__((unused)),
				 void *rock)
{
    const char *filename = (const char *) rock;
    char path[MAX_MAILBOX_PATH+1];
    FILE *f;

    /* Check ACL */
    if (!sdata->isadmin) return IMAP_PERMISSION_DENIED;

    snprintf(path, sizeof(path), "%s/msg/%s", config_dir, filename);

    /* XXX how do we do this atomically with other annotations? */
    if (!strcmp(entry->shared.value, "NIL"))
	return unlink(path);
    else if ((f = fopen(path, "w"))) {
	fprintf(f, "%s\n", entry->shared.value);
	return fclose(f);
    }

    return IMAP_IOERROR;
}

static int annotation_set_todb(const char *int_mboxname,
			       struct annotate_st_entry_list *entry,
			       struct storedata *sdata,
			       struct mailbox_annotation_rock *mbrock,
			       void *rock __attribute__((unused)))
{
    int r = 0;

    if (entry->shared.value || entry->shared.contenttype) {
	/* Check ACL
	 *
	 * Must be an admin to set shared server annotations and
	 * must have the required rights for shared mailbox annotations.
	 */
	int acl = ACL_READ | ACL_WRITE | entry->entry->acl;

	if (!sdata->isadmin &&
	    (!int_mboxname[0] || !mbrock->acl ||
	     ((cyrus_acl_myrights(sdata->auth_state,
				  mbrock->acl) & acl) != acl))) {
	    return IMAP_PERMISSION_DENIED;
	}

	/* Make sure its a server or local mailbox annotation */
	if (!int_mboxname[0] || !mbrock->server) {
	    /* if we don't have a value, retrieve the existing entry */
	    if (!entry->shared.value) {
		struct annotation_data shared;

		r = annotatemore_lookup(int_mboxname, entry->entry->name,
					"", &shared);
		if (r) return r;

		entry->shared.value = shared.value;
	    }

	    r = write_entry(int_mboxname, entry->entry->name, "",
			    &(entry->shared), &(sdata->tid));
	}
    }
    if (entry->priv.value || entry->priv.contenttype) {
	/* Check ACL
	 *
	 * XXX We don't actually need to check anything here,
	 * since we don't have any access control for server annotations
	 * and all we need for private mailbox annotations is ACL_LOOKUP,
	 * and we wouldn't be in this callback without it.
	 */

	/* Make sure its a server or local mailbox annotation */
	if (!int_mboxname[0] || !mbrock->server) {
	    /* if we don't have a value, retrieve the existing entry */
	    if (!entry->priv.value) {
		struct annotation_data priv;

		r = annotatemore_lookup(int_mboxname, entry->entry->name,
					sdata->userid, &priv);
		if (r) return r;

		entry->priv.value = priv.value;
	    }

	    r = write_entry(int_mboxname, entry->entry->name, sdata->userid,
			    &(entry->priv), &(sdata->tid));
	}
    }

    return r;
}

static int annotation_set_mailboxopt(const char *int_mboxname,
				     struct annotate_st_entry_list *entry,
				     struct storedata *sdata,
				     struct mailbox_annotation_rock *mbrock,
				     void *rock __attribute__((unused)))
{
    struct mailbox *mailbox = NULL;
    int flag = 0, r = 0, i;
    unsigned long newopts;

    /* Check entry */
    for (i = 0; annotate_mailbox_flags[i].name; i++) {
	if (!strcmp(entry->entry->name, annotate_mailbox_flags[i].name)) {
	    flag = annotate_mailbox_flags[i].flag;
	    break;
	}
    }
    if (!flag) return IMAP_PERMISSION_DENIED;
  
    /* Check ACL */
    if(!sdata->isadmin &&
       (!mbrock->acl ||
	!(cyrus_acl_myrights(sdata->auth_state, mbrock->acl) & ACL_LOOKUP) ||
	!(cyrus_acl_myrights(sdata->auth_state, mbrock->acl) & ACL_WRITE))) {
	return IMAP_PERMISSION_DENIED;
    }

    r = mailbox_open_iwl(int_mboxname, &mailbox);
    if (r) return r;

    newopts = mailbox->i.options;

    if (!strcmp(entry->shared.value, "true")) {
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

const struct annotate_st_entry server_entries[] =
{
    { "/comment", ATTRIB_TYPE_STRING, PROXY_AND_BACKEND,
      ATTRIB_VALUE_SHARED | ATTRIB_VALUE_PRIV
      | ATTRIB_CONTENTTYPE_SHARED | ATTRIB_CONTENTTYPE_PRIV,
      ACL_ADMIN, annotation_set_todb, NULL },
    { "/motd", ATTRIB_TYPE_STRING, PROXY_AND_BACKEND,
      ATTRIB_VALUE_SHARED | ATTRIB_CONTENTTYPE_SHARED,
      ACL_ADMIN, annotation_set_tofile, "motd" },
    { "/admin", ATTRIB_TYPE_STRING, PROXY_AND_BACKEND,
      ATTRIB_VALUE_SHARED | ATTRIB_CONTENTTYPE_SHARED,
      ACL_ADMIN, annotation_set_todb, NULL },
    { "/vendor/cmu/cyrus-imapd/shutdown", ATTRIB_TYPE_STRING, PROXY_AND_BACKEND,
      ATTRIB_VALUE_SHARED | ATTRIB_CONTENTTYPE_SHARED,
      ACL_ADMIN, annotation_set_tofile, "shutdown" },
    { "/vendor/cmu/cyrus-imapd/squat", ATTRIB_TYPE_BOOLEAN, PROXY_AND_BACKEND,
      ATTRIB_VALUE_SHARED | ATTRIB_CONTENTTYPE_SHARED,
      ACL_ADMIN, annotation_set_todb, NULL },
    { "/vendor/cmu/cyrus-imapd/expire", ATTRIB_TYPE_UINT, PROXY_AND_BACKEND,
      ATTRIB_VALUE_SHARED | ATTRIB_CONTENTTYPE_SHARED,
      ACL_ADMIN, annotation_set_todb, NULL },
    { NULL, 0, ANNOTATION_PROXY_T_INVALID, 0, 0, NULL, NULL }
};

const struct annotate_st_entry mailbox_rw_entries[] =
{
    { "/comment", ATTRIB_TYPE_STRING, BACKEND_ONLY,
      ATTRIB_VALUE_SHARED | ATTRIB_VALUE_PRIV
      | ATTRIB_CONTENTTYPE_SHARED | ATTRIB_CONTENTTYPE_PRIV,
      0, annotation_set_todb, NULL },
    { "/sort", ATTRIB_TYPE_STRING, BACKEND_ONLY,
      ATTRIB_VALUE_SHARED | ATTRIB_VALUE_PRIV
      | ATTRIB_CONTENTTYPE_SHARED | ATTRIB_CONTENTTYPE_PRIV,
      0, annotation_set_todb, NULL },
    { "/thread", ATTRIB_TYPE_STRING, BACKEND_ONLY,
      ATTRIB_VALUE_SHARED | ATTRIB_VALUE_PRIV
      | ATTRIB_CONTENTTYPE_SHARED | ATTRIB_CONTENTTYPE_PRIV,
      0, annotation_set_todb, NULL },
    { "/check", ATTRIB_TYPE_BOOLEAN, BACKEND_ONLY,
      ATTRIB_VALUE_SHARED | ATTRIB_VALUE_PRIV
      | ATTRIB_CONTENTTYPE_SHARED | ATTRIB_CONTENTTYPE_PRIV,
      0, annotation_set_todb, NULL },
    { "/checkperiod", ATTRIB_TYPE_UINT, BACKEND_ONLY,
      ATTRIB_VALUE_SHARED | ATTRIB_VALUE_PRIV
      | ATTRIB_CONTENTTYPE_SHARED | ATTRIB_CONTENTTYPE_PRIV,
      0, annotation_set_todb, NULL },
    { "/vendor/cmu/cyrus-imapd/squat", ATTRIB_TYPE_BOOLEAN, BACKEND_ONLY,
      ATTRIB_VALUE_SHARED | ATTRIB_CONTENTTYPE_SHARED,
      ACL_ADMIN, annotation_set_todb, NULL },
    { "/vendor/cmu/cyrus-imapd/expire", ATTRIB_TYPE_UINT, BACKEND_ONLY,
      ATTRIB_VALUE_SHARED | ATTRIB_CONTENTTYPE_SHARED,
      ACL_ADMIN, annotation_set_todb, NULL },
    { "/vendor/cmu/cyrus-imapd/news2mail", ATTRIB_TYPE_STRING, BACKEND_ONLY,
      ATTRIB_VALUE_SHARED | ATTRIB_CONTENTTYPE_SHARED,
      ACL_ADMIN, annotation_set_todb, NULL },
    { "/vendor/cmu/cyrus-imapd/sieve", ATTRIB_TYPE_STRING, BACKEND_ONLY,
      ATTRIB_VALUE_SHARED | ATTRIB_CONTENTTYPE_SHARED,
      ACL_ADMIN, annotation_set_todb, NULL },
    { "/vendor/cmu/cyrus-imapd/pop3newuidl", ATTRIB_TYPE_BOOLEAN, BACKEND_ONLY,
      ATTRIB_VALUE_SHARED | ATTRIB_CONTENTTYPE_SHARED,
      ACL_ADMIN, annotation_set_mailboxopt, NULL },
    { "/vendor/cmu/cyrus-imapd/sharedseen", ATTRIB_TYPE_BOOLEAN, BACKEND_ONLY,
      ATTRIB_VALUE_SHARED | ATTRIB_CONTENTTYPE_SHARED,
      ACL_ADMIN, annotation_set_mailboxopt, NULL },
    { "/vendor/cmu/cyrus-imapd/duplicatedeliver", ATTRIB_TYPE_BOOLEAN, BACKEND_ONLY,
      ATTRIB_VALUE_SHARED | ATTRIB_CONTENTTYPE_SHARED,
      ACL_ADMIN, annotation_set_mailboxopt, NULL },
    { NULL, 0, ANNOTATION_PROXY_T_INVALID, 0, 0, NULL, NULL }
};

const struct annotate_st_entry dav_mailbox_rw_entry =
    { "/vendor/cmu/cyrus-httpd/", ATTRIB_TYPE_STRING, BACKEND_ONLY,
      ATTRIB_VALUE_SHARED | ATTRIB_VALUE_PRIV
      | ATTRIB_CONTENTTYPE_SHARED | ATTRIB_CONTENTTYPE_PRIV,
      0, annotation_set_todb, NULL };

struct annotate_st_entry_list *server_entries_list = NULL;
struct annotate_st_entry_list *mailbox_rw_entries_list = NULL;

int annotatemore_store(const char *mboxname,
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
    const struct annotate_st_entry_list *entries, *currententry;
    time_t now = time(0);

    memset(&sdata, 0, sizeof(struct storedata));
    sdata.namespace = namespace;
    sdata.userid = userid;
    sdata.isadmin = isadmin;
    sdata.auth_state = auth_state;

    if (!mboxname[0]) {
	/* server annotations */
	entries = server_entries_list;
    }
    else {
	/* mailbox annotation(s) */
	entries = mailbox_rw_entries_list;
    }

    /* Build a list of callbacks for storing the annotations */
    while (e) {
	int attribs;
	struct annotate_st_entry_list *nentry = NULL;

	/* See if we support this entry */
	for (currententry = entries;
	     currententry;
	     currententry = currententry->next) {
	    if (!strcmp(e->entry, currententry->entry->name)) {
		break;
	    }
	}
	if (!currententry) {
	    if ((mboxname_iscalendarmailbox(mboxname, 0) ||
		 mboxname_isaddressbookmailbox(mboxname, 0)) &&
		!strncmp(e->entry, dav_mailbox_rw_entry.name,
			 strlen(dav_mailbox_rw_entry.name))) {
		static struct annotate_st_entry_list dav_entries_list;

		memset(&dav_entries_list, 0,
		       sizeof(struct annotate_st_entry_list));
		dav_entries_list.entry = &dav_mailbox_rw_entry;
		currententry = &dav_entries_list;
	    }
	    else {
		/* unknown annotation */
		return IMAP_PERMISSION_DENIED;
	    }
	}

	/* Add this entry to our list only if it
	   applies to our particular server type */
	if ((currententry->entry->proxytype != PROXY_ONLY)
	    || proxy_store_func) {
	    nentry = xzmalloc(sizeof(struct annotate_st_entry_list));
	    nentry->next = sdata.entry_list;
	    nentry->entry = currententry->entry;
	    nentry->shared.modifiedsince = now;
	    nentry->priv.modifiedsince = now;
	    sdata.entry_list = nentry;
	}

	/* See if we are allowed to set the given attributes. */
	attribs = currententry->entry->attribs;
	av = e->attvalues;
	while (av) {
	    const char *value;
	    if (!strcmp(av->attrib, "value.shared")) {
		if (!(attribs & ATTRIB_VALUE_SHARED)) {
		    r = IMAP_PERMISSION_DENIED;
		    goto cleanup;
		}
		value = annotate_canon_value(av->value,
					     currententry->entry->type);
		if (!value) {
		    r = IMAP_ANNOTATION_BADVALUE;
		    goto cleanup;
		}
		if (nentry) nentry->shared.value = value;
	    }
	    else if (!strcmp(av->attrib, "content-type.shared")) {
		if (!(attribs & ATTRIB_CONTENTTYPE_SHARED)) {
		    r = IMAP_PERMISSION_DENIED;
		    goto cleanup;
		}
		value = annotate_canon_value(av->value,
					     ATTRIB_TYPE_CONTENTTYPE);
		if (!value) {
		    r = IMAP_ANNOTATION_BADVALUE;
		    goto cleanup;
		}
		if (nentry) nentry->shared.contenttype = value;
	    }
	    else if (!strcmp(av->attrib, "value.priv")) {
		if (!(attribs & ATTRIB_VALUE_PRIV)) {
		    r = IMAP_PERMISSION_DENIED;
		    goto cleanup;
		}
		value = annotate_canon_value(av->value,
					     currententry->entry->type);
		if (!value) {
		    r = IMAP_ANNOTATION_BADVALUE;
		    goto cleanup;
		}
		if (nentry) nentry->priv.value = value;
	    }
	    else if (!strcmp(av->attrib, "content-type.priv")) {
		if (!(attribs & ATTRIB_CONTENTTYPE_PRIV)) {
		    r = IMAP_PERMISSION_DENIED;
		    goto cleanup;
		}
		value = annotate_canon_value(av->value,
					     ATTRIB_TYPE_CONTENTTYPE);
		if (!value) {
		    r = IMAP_ANNOTATION_BADVALUE;
		    goto cleanup;
		}
		if (nentry) nentry->priv.contenttype = value;
	    }
	    else {
		r = IMAP_PERMISSION_DENIED;
		goto cleanup;
	    }

	    av = av->next;
	}

	e = e->next;
    }

    if (!mboxname[0]) {
	/* server annotations */

	if (sdata.entry_list) {
	    struct annotate_st_entry_list *entries_ptr;

	    /* Loop through the list of provided entries to get */
	    for (entries_ptr = sdata.entry_list;
		 entries_ptr;
		 entries_ptr = entries_ptr->next) {
	
		r = entries_ptr->entry->set("", entries_ptr, &sdata, NULL,
					    entries_ptr->entry->rock);
		if (r) break;
	    }

	    if (!r) sync_log_annotation("");
	}
    }

    else {
	/* mailbox annotations */

	char mboxpat[MAX_MAILBOX_BUFFER];

	/* Reset state in store_cb */
	store_cb(NULL, 0, 0, 0);

	if (proxy_store_func) {
	    /* xxx better way to determine a size for this table? */
	    construct_hash_table(&sdata.server_table, 10, 1);
	}

	/* copy the pattern so we can change hiersep */
	strlcpy(mboxpat, mboxname, sizeof(mboxpat));
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
		prock.mbox_pat = mboxname;
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
	attrib->value = "NIL";
	r = write_entry(mailbox, entry, userid, attrib, &rrock->tid);
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

enum {
  ANNOTATION_SCOPE_SERVER = 1,
  ANNOTATION_SCOPE_MAILBOX = 2
};

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
    { "content-type", ATTRIB_TYPE_CONTENTTYPE },
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
		 char *name, size_t namelen, char *errmsg) 
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
                               char** s, char* errmsg) 
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
void init_annotation_definitions()
{
    char *p, *p2, *tmp;
    const char *filename;
    char aline[ANNOT_DEF_MAXLINELEN];
    char errbuf[ANNOT_DEF_MAXLINELEN*2];
    struct annotate_st_entry_list *se, *me;
    struct annotate_st_entry *ae;
    int i;
    FILE* f;

    /* NOTE: we assume # static entries > 0 */
    server_entries_list = xmalloc(sizeof(struct annotate_st_entry_list));
    mailbox_rw_entries_list = xmalloc(sizeof(struct annotate_st_entry_list));
    se = server_entries_list;
    me = mailbox_rw_entries_list;

    /* copy static entries into list */
    for (i = 0; server_entries[i].name;i++) {
	se->entry = &server_entries[i];
	if (server_entries[i+1].name) {
	    se->next = xmalloc(sizeof(struct annotate_st_entry_list));
	    se = se->next;
	}
    }

    /* copy static entries into list */
    for (i = 0; mailbox_rw_entries[i].name;i++) {
	me->entry = &mailbox_rw_entries[i];
	if (mailbox_rw_entries[i+1].name) {
	    me->next = xmalloc(sizeof(struct annotate_st_entry_list));
	    me = me->next;
	}
    }

    /* parse config file */
    filename = config_getstring(IMAPOPT_ANNOTATION_DEFINITIONS);

    if (! filename) {
	se->next = NULL;
	me->next = NULL;
	return;
    }
  
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

	ae = xmalloc(sizeof(struct annotate_st_entry));

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
	    se->next = xmalloc(sizeof(struct annotate_st_entry_list));
	    se = se->next;
	    se->entry = ae;
	}
	else {
	    me->next = xmalloc(sizeof(struct annotate_st_entry_list));
	    me = me->next;      
	    me->entry = ae;
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

	ae->set = annotation_set_todb;
	ae->rock = NULL;
    }

    fclose(f);
    se->next = NULL;
    me->next = NULL;
}
