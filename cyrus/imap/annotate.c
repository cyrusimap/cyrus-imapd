/* annotate.c -- Annotation manipulation routines
 * 
 * Copyright (c) 1998-2000 Carnegie Mellon University.  All rights reserved.
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
/*
 * $Id: annotate.c,v 1.8.6.20 2002/11/17 05:06:28 ken3 Exp $
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
#include <com_err.h>

#include "acl.h"
#include "assert.h"
#include "cyrusdb.h"
#include "exitcodes.h"
#include "glob.h"
#include "hash.h"
#include "imapd.h"
#include "imapconf.h"
#include "imap_err.h"
#include "mboxlist.h"
#include "util.h"
#include "xmalloc.h"

#include "annotate.h"

#ifdef ENABLE_ANNOTATEMORE

#define DB (&cyrusdb_skiplist) /* CONFIG_DB_ANNOTATION */

extern void printstring(const char *s);
extern void appendattvalue(struct attvaluelist **l, char *attrib,
			   const char *value);
extern void freeattvalues(struct attvaluelist *l);
static void output_attlist(struct protstream *pout, struct attvaluelist *l);

struct db *anndb;
static int annotate_dbopen = 0;
int (*proxy_func)(const char *server, const char *entry_pat,
		  struct strlist *attribute_pat) = NULL;
#endif

/* String List Management */
/*
 * Append 's' to the strlist 'l'.
 */
void
appendstrlist(l, s)
struct strlist **l;
char *s;
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
void
appendstrlistpat(l, s)
struct strlist **l;
char *s;
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
void
freestrlist(l)
struct strlist *l;
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
void appendattvalue(struct attvaluelist **l, char *attrib, const char *value)
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

#ifdef ENABLE_ANNOTATEMORE

/*
 * Append the 'entry'/'attvalues' pair to the entryattlist 'l'.
 */
void appendentryatt(struct entryattlist **l, char *entry,
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

/* must be called after config_init */
void annotatemore_init(int myflags,int (*func)(const char *, const char *,
					       struct strlist *))
{
    int r;

    if (myflags & ANNOTATE_SYNC) {
	r = DB->sync();
    }

    if (func) {
	proxy_func = func;
    }
}

void annotatemore_open(char *fname)
{
    int ret;
    char *tofree = NULL;

    /* create db file name */
    if (!fname) {
	fname = xmalloc(strlen(config_dir)+sizeof(FNAME_ANNOTATIONS));
	tofree = fname;
	strcpy(fname, config_dir);
	strcat(fname, FNAME_ANNOTATIONS);
    }

    ret = DB->open(fname, &anndb);
    if (ret != 0) {
	syslog(LOG_ERR, "DBERROR: opening %s: %s", fname,
	       cyrusdb_strerror(ret));
	fatal("can't read annotations file", EC_TEMPFAIL);
    }    

    if (tofree) free(tofree);

    annotate_dbopen = 1;
}

enum {
    ENTRY_PARTITION =		(1<<0),
    ENTRY_SERVER =		(1<<1),
    ENTRY_SIZE =                (1<<2)
};

enum {
    SRVENTRY_MOTD =             (1<<0),
    SRVENTRY_COMMENT =          (1<<1),
};

enum {
    ATTRIB_VALUE_SHARED =		(1<<0),
    ATTRIB_SIZE_SHARED =		(1<<1),
    ATTRIB_MODIFIEDSINCE_SHARED =	(1<<2),
    ATTRIB_CONTENTTYPE_SHARED = 	(1<<3)
};

typedef enum {
    ANNOTATION_PROXY_T_INVALID = 0,

    PROXY_ONLY = 1,
    BACKEND_ONLY = 2,
    PROXY_AND_BACKEND = 3
} annotation_proxy_t;

struct mailbox_annotation_rock 
{
    char *server, *partition, *acl, *path;
};

struct annotation_result 
{
    const char *value;
    size_t size;
    time_t modifiedsince;
    const char *contenttype;
};

/* To free values in the mailbox_annotation_rock as needed */
static void cleanup_mbrock(struct mailbox_annotation_rock *mbrock __attribute__((unused))) 
{
    /* Don't free server and partition, since they're straight from the
     * output of mboxlist_detail() */
    return;
}

static void get_mb_data(const char *mboxname,
			struct mailbox_annotation_rock *mbrock) 
{
    if(!mbrock->server && !mbrock->partition) {
	int r = mboxlist_detail(mboxname, NULL, &(mbrock->path),
				&(mbrock->server), &(mbrock->acl), NULL);
	if (r) return;

	mbrock->partition = strchr(mbrock->server, '!');
	if (mbrock->partition) {
	    *(mbrock->partition)++ = '\0';
	    mbrock->path = NULL;
	} else {
	    mbrock->partition = mbrock->server;
	    mbrock->server = NULL;
	}
    }
}

static void annotation_get_server(const char *mboxname,
				  int isadmin,
				  struct auth_state *auth_state,
				  struct annotation_result *result,
				  struct mailbox_annotation_rock *mbrock,
				  void *rock __attribute__((unused))) 
{
    if(!mboxname || !result || !mbrock)
	fatal("annotation_get_server called with bad parameters", EC_TEMPFAIL);
    
    get_mb_data(mboxname, mbrock);

    /* Check ACL */
    if(!isadmin &&
       (!mbrock->acl ||
        !(cyrus_acl_myrights(auth_state, mbrock->acl) & ACL_LOOKUP)))
	return;

    result->value = mbrock->server;
    if(mbrock->server) {
	result->size = strlen(mbrock->server);
    }
}

static void annotation_get_partition(const char *mboxname,
				     int isadmin,
				     struct auth_state *auth_state,
				     struct annotation_result *result,
				     struct mailbox_annotation_rock *mbrock,
				     void *rock __attribute__((unused))) 
{
    if(!mboxname || !result || !mbrock)
	fatal("annotation_get_partition called with bad parameters",
	      EC_TEMPFAIL);
    
    get_mb_data(mboxname, mbrock);

    /* Check ACL */
    if(!isadmin &&
       (!mbrock->acl ||
        !(cyrus_acl_myrights(auth_state, mbrock->acl) & ACL_LOOKUP)))
	return;

    result->value = mbrock->partition;
    if(mbrock->partition) {
	result->size = strlen(mbrock->partition);
    }
}

static void annotation_get_size(const char *mboxname,
				int isadmin,
				struct auth_state *auth_state,
				struct annotation_result *result,
				struct mailbox_annotation_rock *mbrock,
				void *rock __attribute__((unused))) 
{
    struct mailbox mailbox;
    struct index_record record;
    int r = 0, msg;
    unsigned long totsize = 0;
    static char value[21];

    if(!mboxname || !result || !mbrock)
	fatal("annotation_get_size called with bad parameters",
	      EC_TEMPFAIL);
    
    get_mb_data(mboxname, mbrock);

    /* Check ACL */
    if(!isadmin &&
       (!mbrock->acl ||
        !(cyrus_acl_myrights(auth_state, mbrock->acl) & ACL_LOOKUP) ||
        !(cyrus_acl_myrights(auth_state, mbrock->acl) & ACL_READ)))
	return;

    if (mailbox_open_header(mboxname, 0, &mailbox) != 0)
	return;

    if (!r) r = mailbox_open_index(&mailbox);

    if (!r) {
	for (msg = 1; msg <= mailbox.exists; msg++) {
	    if ((r = mailbox_read_index_record(&mailbox, msg, &record))!=0)
		break;
	    totsize += record.size;
	}
    }

    mailbox_close(&mailbox);

    if (r || snprintf(value, sizeof(value), "%lu", totsize) == -1)
	return;

    result->value = value;
    result->size = strlen(value);
}

static void annotation_get_lastupdate(const char *mboxname,
				      int isadmin,
				      struct auth_state *auth_state,
				      struct annotation_result *result,
				      struct mailbox_annotation_rock *mbrock,
				      void *rock __attribute__((unused))) 
{
    time_t modtime = 0;
    struct stat header, index;
    static char valuebuf[128];
    
    if(!mboxname || !result || !mbrock)
	fatal("annotation_get_lastupdate called with bad parameters",
	      EC_TEMPFAIL);
    
    get_mb_data(mboxname, mbrock);

    /* Check ACL */
    if(!isadmin &&
       (!mbrock->acl ||
        !(cyrus_acl_myrights(auth_state, mbrock->acl) & ACL_LOOKUP) ||
        !(cyrus_acl_myrights(auth_state, mbrock->acl) & ACL_READ)))
	return;

    if (!mbrock->path) return;
    if (mailbox_stat(mbrock->path, &header, &index, NULL)) return;

    modtime = (header.st_mtime > index.st_mtime) ?
	header.st_mtime : index.st_mtime;

    cyrus_ctime(modtime, valuebuf);
    
    result->value = valuebuf;
    result->size = strlen(valuebuf);
}

struct annotate_entry
{
    const char *name;
    void (*get)(const char *mboxname,
		int isadmin,
		struct auth_state *auth_state,
		struct annotation_result *result,
		struct mailbox_annotation_rock *mbrock,
		void *rock);
    void *rock;
    int entry;
    annotation_proxy_t proxytype;
};

struct annotate_entry_list
{
    const struct annotate_entry *entry;
    struct annotate_entry_list *next;
};

const struct annotate_entry mailbox_ro_entries[] =
{
    { "/vendor/cmu/cyrus-imapd/partition", annotation_get_partition,
	  NULL, ENTRY_PARTITION, BACKEND_ONLY },
    { "/vendor/cmu/cyrus-imapd/server", annotation_get_server,
	  NULL, ENTRY_SERVER, PROXY_ONLY },
    { "/vendor/cmu/cyrus-imapd/size", annotation_get_size,
	  NULL, ENTRY_SIZE, BACKEND_ONLY },
    { "/vendor/cmu/cyrus-imapd/lastupdate", annotation_get_lastupdate,
	  NULL, ENTRY_SIZE, BACKEND_ONLY },
    { NULL, NULL, NULL, 0, ANNOTATION_PROXY_T_INVALID }
};

const struct annotate_entry server_entries[] =
{
    { "motd", NULL, NULL, SRVENTRY_MOTD, PROXY_AND_BACKEND },
    { "comment", NULL, NULL, SRVENTRY_COMMENT, PROXY_AND_BACKEND },
    { NULL, NULL, NULL, 0, ANNOTATION_PROXY_T_INVALID }
};

/* Annotation attributes and their flags */
struct annotate_attrib
{
    const char *name;
    int entry;
};

const struct annotate_attrib annotation_attributes[] = 
{
    { "value", ATTRIB_VALUE_SHARED },
    { "value.shared", ATTRIB_VALUE_SHARED },
    { "size", ATTRIB_SIZE_SHARED },
    { "size.shared", ATTRIB_SIZE_SHARED },
    { "modifiedsince", ATTRIB_MODIFIEDSINCE_SHARED },
    { "modifiedsince.shared", ATTRIB_MODIFIEDSINCE_SHARED },
    { "content-type", ATTRIB_CONTENTTYPE_SHARED },
    { "content-type.shared", ATTRIB_CONTENTTYPE_SHARED },
    { NULL, 0 }
};

/* Mailbox Annotation Fetching */
struct fetchdata {
    struct namespace *namespace;
    struct protstream *pout;
    char *userid;
    int isadmin;
    struct auth_state *auth_state;
    struct annotate_entry_list *entry_list;
    unsigned entries; /* xxx used for server annotations, shouldn't be */
    unsigned attribs;
    struct entryattlist **entryatts;

    /* For proxies (a null entry_list indicates that we ONLY proxy) */
    /* if these are NULL, we have had a local exact match, and we
       DO NOT proxy */
    struct hash_table server_table;
    const char *orig_entry;
    struct strlist *orig_attribute;
};

static int fetch_cb(char *name, int matchlen,
		    int maycreate __attribute__((unused)), void* rock)
{
    struct fetchdata *fdata = (struct fetchdata *) rock;
    struct annotate_entry_list *entries_ptr;
    static char lastname[MAX_MAILBOX_PATH];
    static int sawuser = 0;
    int c;
    char int_mboxname[MAX_MAILBOX_PATH+1], ext_mboxname[MAX_MAILBOX_PATH+1];

    char entry[MAX_MAILBOX_PATH+25];
    char size[100], modifiedsince[100];
    struct attvaluelist *attvalues = NULL;

    struct annotation_result result;
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

    strcpy(lastname, name);
    lastname[matchlen] = '\0';

    if (!strncasecmp(lastname, "INBOX", 5)) {
	(*fdata->namespace->mboxname_tointernal)(fdata->namespace, "INBOX",
						 fdata->userid, int_mboxname);
	strcat(int_mboxname, lastname+5);
    }
    else
	strcpy(int_mboxname, lastname);

    c = name[matchlen];
    if (c) name[matchlen] = '\0';
    (*fdata->namespace->mboxname_toexternal)(fdata->namespace, name,
					     fdata->userid, ext_mboxname);
    if (c) name[matchlen] = c;

    memset(&mbrock, 0, sizeof(struct mailbox_annotation_rock));

    if(proxy_func && fdata->orig_entry) {
	get_mb_data(int_mboxname, &mbrock);
    }

    /* Loop through the list of provided entries to get */
    for(entries_ptr = fdata->entry_list;
	entries_ptr;
	entries_ptr = entries_ptr->next) {
	int appended_one = 0;
	
	snprintf(entry, sizeof(entry), "/mailbox/{%s}%s",
		ext_mboxname, entries_ptr->entry->name);

	attvalues = NULL;
	memset(&result,0,sizeof(struct annotation_result));

	entries_ptr->entry->get(int_mboxname, fdata->isadmin,
				fdata->auth_state,
				&result, &mbrock, NULL);

	if ((fdata->attribs & ATTRIB_VALUE_SHARED) && result.value) {
	    appended_one = 1;
	    appendattvalue(&attvalues, "value.shared", result.value);
	}

	if ((fdata->attribs & ATTRIB_CONTENTTYPE_SHARED)
	    && result.value && result.contenttype) {
	    appended_one = 1;
	    appendattvalue(&attvalues, "contenttype.shared",
			   result.contenttype);
	}

	/* Base the return of the size attribute on whether or not there is
	 * an attribute, not wether size is nonzero. */
	if ((fdata->attribs & ATTRIB_SIZE_SHARED) && result.value) {
	    appended_one = 1;
	    snprintf(size, sizeof(size), "%u", result.size);
	    appendattvalue(&attvalues, "size.shared", size);
	}

	/* For this one we need both a value for the entry *and* a nonzero
	 * modifiedsince time */
	if ((fdata->attribs & ATTRIB_MODIFIEDSINCE_SHARED)
	    && result.value && result.modifiedsince) {
	    appended_one = 1;
	    snprintf(modifiedsince, sizeof(modifiedsince),
		     "%d", (int)result.modifiedsince);
	    appendattvalue(&attvalues, "modifiedsince.shared", modifiedsince);
	}

	if(appended_one) {
	    prot_printf(fdata->pout, "* ANNOTATION \"%s\" ", entry);
	    output_attlist(fdata->pout, attvalues);
	    prot_printf(fdata->pout, "\r\n");
	    
	    freeattvalues(attvalues);
	    attvalues = NULL;
	}
    }

    if(proxy_func && fdata->orig_entry
       && !hash_lookup(mbrock.server, &(fdata->server_table))) {
	/* xxx ignoring result */
	proxy_func(mbrock.server, fdata->orig_entry, fdata->orig_attribute);
	hash_insert(mbrock.server, (void *)0xDEADBEEF, &(fdata->server_table));
    }

    cleanup_mbrock(&mbrock);

    return 0;
}

static void output_attlist(struct protstream *pout, struct attvaluelist *l) 
{
    int flag = 0;
    
    assert(l);
    
    prot_putc('(',pout);
    
    while(l) {
	if(flag) prot_putc(' ',pout);
	else flag = 1;
	
	printstring(l->attrib);
	prot_putc(' ',pout);
	printstring(l->value);

	l = l->next;
    }

    prot_putc(')',pout);
}

int annotatemore_fetch(struct strlist *entries, struct strlist *attribs,
		       struct namespace *namespace, int isadmin, char *userid,
		       struct auth_state *auth_state, struct protstream *pout)
{
    struct strlist *e = entries;
    struct strlist *a = attribs;
    char *tmp_entry = NULL;
    char *mailbox, *cp;
    struct fetchdata fdata;

    memset(&fdata, 0, sizeof(struct fetchdata));

    /* we only do shared annotations right now */
    while (a) {
	int attribcount;
	struct glob *g;

	g = glob_init(a->s, GLOB_HIERARCHY);
	
	for(attribcount = 0;
	    annotation_attributes[attribcount].name;
	    attribcount++) {
	    if(GLOB_TEST(g, annotation_attributes[attribcount].name) != -1) {
		fdata.attribs |= annotation_attributes[attribcount].entry;
	    }
	}
	
	glob_free(&g);

	a = a->next;
    }

    if (!fdata.attribs) return 0;

    while (e) {
	int exact_match = 0;
	
	if(tmp_entry) free(tmp_entry);
	tmp_entry = xstrdup(e->s);
	
	if (!strncmp(tmp_entry, "/mailbox/{", 10) &&
	    ((cp = strchr(tmp_entry + 10, '}')) != NULL)) {
	    int entrycount;
	    struct glob *g;

	    mailbox = tmp_entry + 10;
	    *cp++ = '\0'; /* just after mailbox w/leading slash */

	    g = glob_init(cp, GLOB_HIERARCHY);
	    GLOB_SET_SEPARATOR(g, '/');

	    for(entrycount = 0;
		mailbox_ro_entries[entrycount].name;
		entrycount++) {

		/* Skip this entry if it doesn't apply to our particular
		   server type */
		if(mailbox_ro_entries[entrycount].proxytype !=
		   PROXY_AND_BACKEND) {
		    if((proxy_func &&
			mailbox_ro_entries[entrycount].proxytype != PROXY_ONLY)
		       ||(!proxy_func &&
			  mailbox_ro_entries[entrycount].proxytype !=
			  BACKEND_ONLY))
			continue;
		}
		
		if(GLOB_TEST(g, mailbox_ro_entries[entrycount].name) != -1) {
		    struct annotate_entry_list *nentry =
			xmalloc(sizeof(struct annotate_entry_list));

		    nentry->next = fdata.entry_list;
		    nentry->entry = &(mailbox_ro_entries[entrycount]);
		    fdata.entry_list = nentry;
		    if(!strcmp(cp, mailbox_ro_entries[entrycount].name)) {
			exact_match = 1;
			break;
		    }
		}
	    }
		
	    glob_free(&g);
	    
	    if (fdata.entry_list || proxy_func) {
		/* Reset state in fetch_cb */
		fetch_cb(NULL, 0, 0, 0);

		if(proxy_func && !exact_match) {
		    fdata.orig_entry = e->s;
		    fdata.orig_attribute = attribs;
		    /* xxx better way to determine a size for this table? */
		    construct_hash_table(&fdata.server_table, 10, 1);
		} else if (proxy_func) {
		    fdata.orig_entry = NULL;
		    fdata.orig_attribute = NULL;
		}

		mboxname_hiersep_tointernal(namespace, mailbox,
				    config_virtdomains ?
				    strcspn(mailbox, "@") : 0);
		fdata.pout = pout;
		fdata.namespace = namespace;
		fdata.userid = userid;
		fdata.isadmin = isadmin;
		fdata.auth_state = auth_state;
		(*namespace->mboxlist_findall)(namespace, mailbox,
					       isadmin, userid,
					       auth_state, fetch_cb,
					       &fdata);

		if(proxy_func && !exact_match) {
		    free_hash_table(&fdata.server_table, NULL);
		}
	    }
	}

	/* Free the entry list, if needed */
	while(fdata.entry_list) {
	    struct annotate_entry_list *freeme = fdata.entry_list;
	    fdata.entry_list = fdata.entry_list->next;
	    free(freeme);
	}

	if (!strncmp(e->s, "/server/", 8)) {
	    FILE *f;
	    char filename[1024], buf[1024], size[100], *p;
	    struct attvaluelist *attvalues;
	    int entrycount;
	    struct glob *g;

	    cp = e->s + 8;

	    g = glob_init(cp, GLOB_HIERARCHY);
	    GLOB_SET_SEPARATOR(g, '/');
	    for(entrycount = 0;
		server_entries[entrycount].name;
		entrycount++) {
		if(GLOB_TEST(g, server_entries[entrycount].name) != -1) {
		    fdata.entries |= server_entries[entrycount].entry;
		}
	    }

	    glob_free(&g);

	    if (fdata.entries & SRVENTRY_MOTD) {
		snprintf(filename, sizeof(filename), "%s/msg/motd", config_dir);
		if ((f = fopen(filename, "r")) != NULL) {
		    fgets(buf, sizeof(buf), f);
		    fclose(f);

		    if ((p = strchr(buf, '\r'))!=NULL) *p = 0;
		    if ((p = strchr(buf, '\n'))!=NULL) *p = 0;

		    attvalues = NULL;
		    if (fdata.attribs & ATTRIB_VALUE_SHARED)
			appendattvalue(&attvalues, "value.shared", buf);
		    if (fdata.attribs & ATTRIB_SIZE_SHARED) {
			snprintf(size, sizeof(size), "%u", strlen(buf));
			appendattvalue(&attvalues, "size.shared", size);
		    }

		    prot_printf(pout, "* ANNOTATION \"/server/motd\" ");
		    output_attlist(pout, attvalues);
		    prot_printf(pout, "\r\n");

		    freeattvalues(attvalues);
		    attvalues = NULL;
		}
	    }
	    if (fdata.entries & SRVENTRY_COMMENT) {
		snprintf(filename, sizeof(filename), 
			 "%s/msg/comment", config_dir);
		if ((f = fopen(filename, "r")) != NULL) {
		    fgets(buf, sizeof(buf), f);
		    fclose(f);

		    if ((p = strchr(buf, '\r'))!=NULL) *p = 0;
		    if ((p = strchr(buf, '\n'))!=NULL) *p = 0;

		    attvalues = NULL;
		    if (fdata.attribs & ATTRIB_VALUE_SHARED)
			appendattvalue(&attvalues, "value.shared", buf);
		    if (fdata.attribs & ATTRIB_SIZE_SHARED) {
			snprintf(size, sizeof(size), "%u", strlen(buf));
			appendattvalue(&attvalues, "size.shared", size);
		    }

		    prot_printf(pout, "* ANNOTATION \"/server/comment\" ");
		    output_attlist(pout, attvalues);
		    prot_printf(pout, "\r\n");

		    freeattvalues(attvalues);
		    attvalues = NULL;
		}
	    }
	}

	e = e->next;
    }
    if(tmp_entry) free(tmp_entry);

    return 0;
}

static int server_store(char *filename, char *value)
{
    FILE *f;

    /* XXX check for failures */
    if (!strcmp(value, "NIL"))
	unlink(filename);
    else {
	f = fopen(filename, "w");
	fprintf(f, "%s\n", value);
	fclose(f);
    }

    return 0;
}

int annotatemore_store(struct entryattlist *l,
		       struct namespace *namespace __attribute__((unused)),
		       int isadmin __attribute__((unused)),
		       char *userid __attribute__((unused)),
		       struct auth_state *auth_state __attribute__((unused)))
{
    struct entryattlist *e = l;
    struct attvaluelist *av;
    char *value = NULL, *motd = NULL, *comment = NULL;
    char filename[1024];

    syslog(LOG_INFO, "annotatemore_store");

    while (e) {
	if (strncmp(e->entry, "/server/", 8) &&
	    strncmp(e->entry, "/mailbox/", 9)) {
	    return IMAP_ANNOTATION_BADENTRY;
	}

	av = e->attvalues;
	while (av) {
	    if (!strcmp(av->attrib, "value.shared")) {
		value = av->value;
		break;
	    }
	    else
		return IMAP_PERMISSION_DENIED;

	    av = av->next;
	}

	if (value && !strcmp(e->entry, "/server/motd"))
	    motd = value;
	else if (value && !strcmp(e->entry, "/server/comment"))
	    comment = value;
	else
	    return IMAP_PERMISSION_DENIED;

	e = e->next;
    }

    /* XXX check for failures -- how to do this atomic? */
    if (motd) {
	snprintf(filename, sizeof(filename), "%s/msg/motd", config_dir);
	server_store(filename, value);
    }
    if (comment) {
	snprintf(filename, sizeof(filename), "%s/msg/comment", config_dir);
	server_store(filename, value);
    }

    return 0;
}

void annotatemore_close(void)
{
    int r;

    if (annotate_dbopen) {
	r = DB->close(anndb);
	if (r) {
	    syslog(LOG_ERR, "DBERROR: error closing annotations: %s",
		   cyrusdb_strerror(r));
	}
	annotate_dbopen = 0;
    }
}

void annotatemore_done(void)
{
    int r;

    r = DB->done();
    if (r) {
	syslog(LOG_ERR, "DBERROR: error exiting application: %s",
	       cyrusdb_strerror(r));
    }
}

#endif /* ENABLE_ANNOTATEMORE */
