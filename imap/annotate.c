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
 * $Id: annotate.c,v 1.12 2002/11/06 20:43:20 rjs3 Exp $
 */

#include <config.h>

#ifdef ENABLE_ANNOTATEMORE

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
#include "imapd.h"
#include "imapconf.h"
#include "cyrusdb.h"
#include "util.h"
#include "exitcodes.h"
#include "imap_err.h"
#include "xmalloc.h"
#include "mboxlist.h"

#include "annotate.h"

#define DB (&cyrusdb_skiplist) /* CONFIG_DB_ANNOTATION */

struct db *anndb;

static int annotate_dbopen = 0;

extern void appendattvalue(struct attvaluelist **l, char *attrib, char *value);
extern void freeattvalues(struct attvaluelist *l);

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

void annotatemore_init(int myflags)
{
    int r;
    char dbdir[1024];
    int flags = 0;

    /* create the name of the db file */
    strcpy(dbdir, config_dir);
    strcat(dbdir, FNAME_DBDIR);
    if (myflags & ANNOTATE_RECOVER) flags |= CYRUSDB_RECOVER;
    r = DB->init(dbdir, flags);
    if (r != CYRUSDB_OK) {
	fatal("can't initialize annotate environment", EC_TEMPFAIL);
    }

    if (myflags & ANNOTATE_SYNC) {
	r = DB->sync();
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

struct fetchdata {
    struct namespace *namespace;
    char *userid;
    unsigned entries;
    unsigned attribs;
    int isadmin;
    struct auth_state *auth_state;
    struct entryattlist **entryatts;
};

enum {
    ENTRY_SERVER =		(1<<0),
    ENTRY_PARTITION =		(1<<1)
};

enum {
    ATTRIB_VALUE =		(1<<0),
    ATTRIB_SIZE =		(1<<1),
    ATTRIB_MODIFIEDSINCE =	(1<<2),
    ATTRIB_CONTENTTYPE = 	(1<<3)
};

static int fetch_cb(char *name, int matchlen, int maycreate, void* rock)
{
    struct fetchdata *fdata = (struct fetchdata *) rock;
    static char lastname[MAX_MAILBOX_PATH];
    static int sawuser = 0;
    int c, r;
    char mboxname[MAX_MAILBOX_PATH+1];
    char *path, *server, *partition, *acl;
    char entry[MAX_MAILBOX_PATH+25];
    char size[100];
    struct attvaluelist *attvalues = NULL;

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

    if (!strncasecmp(lastname, "INBOX", 5))
	snprintf(mboxname, sizeof(mboxname), "user.%s%s", 
		 fdata->userid, lastname+5);
    else
	strcpy(mboxname, name);

    /* Suppress any output of a partial match */
    if (name[matchlen] && strncmp(mboxname, name, matchlen) == 0) {
	return 0;
    }

    /* lookup the partition info */
    r = mboxlist_detail(mboxname, NULL, &path, &server, &acl, NULL);
    if (r) return r;

    /* Check ACL - silently skip if we can't lookup this mailbox */
    if(!fdata->isadmin &&
       (!acl ||
        !(cyrus_acl_myrights(fdata->auth_state, acl) & ACL_LOOKUP)))
	return 0;

    partition = strchr(server, '!');
    if (partition) {
	*partition++ = '\0';
    }
    else {
	partition = server;
	server = NULL;
    }

    c = name[matchlen];
    if (c) name[matchlen] = '\0';
    (*fdata->namespace->mboxname_toexternal)(fdata->namespace, name,
					     fdata->userid, mboxname);
    if (c) name[matchlen] = c;

    if (server && (fdata->entries & ENTRY_SERVER)) {
	snprintf(entry, sizeof(entry), 
		"/mailbox/{%s}/vendor/cmu/cyrus-imapd/server",
		mboxname);

	attvalues = NULL;
	if (fdata->attribs & ATTRIB_VALUE)
	    appendattvalue(&attvalues, "value.shared", server);
	if (fdata->attribs & ATTRIB_SIZE) {
	    snprintf(size, sizeof(size), "%u", strlen(server));
	    appendattvalue(&attvalues, "size.shared", size);
	}

	appendentryatt(fdata->entryatts, entry, attvalues);
    }

    if (fdata->entries & ENTRY_PARTITION) {
	snprintf(entry, sizeof(entry),
		"/mailbox/{%s}/vendor/cmu/cyrus-imapd/partition",
		mboxname);

	attvalues = NULL;
	if (fdata->attribs & ATTRIB_VALUE)
	    appendattvalue(&attvalues, "value.shared", partition);
	if (fdata->attribs & ATTRIB_SIZE) {
	    snprintf(size, sizeof(size), "%u", strlen(partition));
	    appendattvalue(&attvalues, "size.shared", size);
	}

	appendentryatt(fdata->entryatts, entry, attvalues);
    }

    return 0;
}

int annotatemore_fetch(struct strlist *entries, struct strlist *attribs,
		       struct namespace *namespace, int isadmin, char *userid,
		       struct auth_state *auth_state, struct entryattlist **l)
{
    struct strlist *e = entries;
    struct strlist *a = attribs;
    char *mailbox, *cp, *wildcard;
    struct fetchdata fdata;

    *l = NULL;

    /* we only do shared annotations right now */
    fdata.attribs = 0;
    while (a) {
	if (!strcmp(a->s, "*") || !strcmp(a->s, "%"))
	    fdata.attribs |= ATTRIB_VALUE | ATTRIB_SIZE;
	else if (!strcmp(a->s, "value.*") || !strcmp(a->s, "value.%") ||
		 !strcmp(a->s, "value") || !strcmp(a->s, "value.shared"))
	    fdata.attribs |= ATTRIB_VALUE;
	else if (!strcmp(a->s, "size.*") || !strcmp(a->s, "size.%") ||
		 !strcmp(a->s, "size") || !strcmp(a->s, "size.shared"))
	    fdata.attribs |= ATTRIB_SIZE;

	a = a->next;
    }

    if (!fdata.attribs) return 0;

    while (e) {
	fdata.entries = 0;

	/* XXX fix this cheesy matching stuff so we support wildcards */
	if (!strncmp(e->s, "/mailbox/{", 10) &&
	    ((cp = strchr(e->s + 10, '}')) != NULL)) {
	    mailbox = e->s + 10;
	    *cp++ = '\0';

	    /* we only support "/mailbox/{mbox}/vendor/cmu/cyrus-imapd/server"
	       and ".../vendor/cmu/cyrus-imapd/partition" right now */
	    if (!strncmp(cp, "/vendor/cmu/cyrus-imapd/server",
			 (wildcard = strchr(cp, '*')) ? wildcard - cp : 20)) {
		fdata.entries |= ENTRY_SERVER;
	    }
	    if (!strncmp(cp, "/vendor/cmu/cyrus-imapd/partition",
			 (wildcard = strchr(cp, '*')) ? wildcard - cp : 23)) {
		fdata.entries |= ENTRY_PARTITION;
	    }
	    if (!strcmp(cp, "/vendor/cmu/cyrus-imapd/%")) {
		fdata.entries |= (ENTRY_SERVER | ENTRY_PARTITION);
	    }
		
	    if (fdata.entries) {
		/* Reset state in fetch_cb */
		fetch_cb(NULL, 0, 0, 0);

		mboxname_hiersep_tointernal(namespace, mailbox);
		fdata.namespace = namespace;
		fdata.userid = userid;
		fdata.isadmin = isadmin;
		fdata.auth_state = auth_state;
		fdata.entryatts = l;
		(*namespace->mboxlist_findall)(namespace, mailbox,
					       isadmin, userid,
					       auth_state, fetch_cb,
					       &fdata);
	    }
	}

	if (!strncmp(e->s, "/server/", 8)) {
	    FILE *f;
	    char filename[1024], buf[1024], size[100], *p;
	    struct attvaluelist *attvalues;

	    cp = e->s + 8;

	    if (!strncmp(cp, "motd", strcspn(cp, "*%"))) {
		snprintf(filename, sizeof(filename), "%s/msg/motd", config_dir);
		if ((f = fopen(filename, "r")) != NULL) {
		    fgets(buf, sizeof(buf), f);
		    fclose(f);

		    if ((p = strchr(buf, '\r'))!=NULL) *p = 0;
		    if ((p = strchr(buf, '\n'))!=NULL) *p = 0;
		    /* can't have [ be first char, sigh */
		    for(p = buf; *p == '['; p++);

		    attvalues = NULL;
		    if (fdata.attribs & ATTRIB_VALUE)
			appendattvalue(&attvalues, "value.shared", buf);
		    if (fdata.attribs & ATTRIB_SIZE) {
			snprintf(size, sizeof(size), "%u", strlen(buf));
			appendattvalue(&attvalues, "size.shared", size);
		    }

		    appendentryatt(l, "/server/motd", attvalues);
		}
	    }
	    if (!strncmp(cp, "comment", strcspn(cp, "*%"))) {
		snprintf(filename, sizeof(filename), 
			 "%s/msg/comment", config_dir);
		if ((f = fopen(filename, "r")) != NULL) {
		    fgets(buf, sizeof(buf), f);
		    fclose(f);

		    if ((p = strchr(buf, '\r'))!=NULL) *p = 0;
		    if ((p = strchr(buf, '\n'))!=NULL) *p = 0;

		    attvalues = NULL;
		    if (fdata.attribs & ATTRIB_VALUE)
			appendattvalue(&attvalues, "value.shared", buf);
		    if (fdata.attribs & ATTRIB_SIZE) {
			snprintf(size, sizeof(size), "%u", strlen(buf));
			appendattvalue(&attvalues, "size.shared", size);
		    }

		    appendentryatt(l, "/server/comment", attvalues);
		}
	    }
	}

	e = e->next;
    }

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

int annotatemore_store(struct entryattlist *l, struct namespace *namespace,
		       int isadmin, char *userid,
		       struct auth_state *auth_state)
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
