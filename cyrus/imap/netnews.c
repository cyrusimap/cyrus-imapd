/*
 * Copyright (c) 1998-2003 Carnegie Mellon University.  All rights reserved.
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

/* $Id: netnews.c,v 1.1.2.11 2003/05/09 02:11:38 ken3 Exp $ */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <assert.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_DIRENT_H
# include <dirent.h>
#else
# define dirent direct
# if HAVE_SYS_NDIR_H
#  include <sys/ndir.h>
# endif
# if HAVE_SYS_DIR_H
#  include <sys/dir.h>
# endif
# if HAVE_NDIR_H
#  include <ndir.h>
# endif
#endif
#include <errno.h>

#include <db.h>

#include "cyrusdb.h"
#include "exitcodes.h"
#include "imap_err.h"
#include "global.h"
#include "mailbox.h"
#include "netnews.h"
#include "util.h"
#include "xmalloc.h"


#define DB (CONFIG_DB_NETNEWS)

static struct db *newsdb = NULL;
static int news_dbopen = 0;

/* must be called after cyrus_init */
int netnews_init(char *fname, int myflags)
{
    char buf[1024];
    int r = 0;

    if (r != 0)
	syslog(LOG_ERR, "DBERROR: init %s: %s", buf,
	       cyrusdb_strerror(r));
    else {
	char *tofree = NULL;

	/* create db file name */
	if (!fname) {
	    fname = xmalloc(strlen(config_dir)+sizeof(FNAME_NETNEWSDB));
	    tofree = fname;
	    strcpy(fname, config_dir);
	    strcat(fname, FNAME_NETNEWSDB);
	}

	r = DB->open(fname, &newsdb);
	if (r != 0)
	    syslog(LOG_ERR, "DBERROR: opening %s: %s", fname,
		   cyrusdb_strerror(r));
	else
	    news_dbopen = 1;

	if (tofree) free(tofree);
    }

    return r;
}

struct netnews_entry {
    char *mailbox;
    unsigned long uid;
    unsigned long lines; /* deprecated */
    time_t tstamp;
};

static void parse_entry(const char *data, struct netnews_entry *entry)
{
    char *p = (char *) data;

    entry->mailbox = p;
    p += strlen(p);

    entry->uid = strtoul(++p, &p, 10);
    entry->lines = strtoul(++p, &p, 10);
    entry->tstamp = (time_t) strtoul(++p, &p, 10);
}

int netnews_lookup(char *msgid, char **mailbox, unsigned long *uid,
		   time_t *tstamp)
{
    int r;
    const char *data = NULL;
    int len = 0;

    if (!news_dbopen) return 0;

    do {
	r = DB->fetch(newsdb, msgid, strlen(msgid), &data, &len, NULL);
    } while (r == CYRUSDB_AGAIN);

    if (data) {
	/* found the record */
	struct netnews_entry entry;

	parse_entry(data, &entry);

	if (mailbox) *mailbox = entry.mailbox;
	if (uid) *uid = entry.uid;
	if (tstamp) *tstamp = entry.tstamp;

	return 1;
    } else if (r != CYRUSDB_OK) {
	syslog(LOG_ERR, "netnews_lookup: error looking up %s: %s",
	       msgid, cyrusdb_strerror(r));
    }

    return 0;
}

void netnews_store(char *msgid, char *mailbox, unsigned long uid,
		   time_t tstamp)
{
    char buf[1024];
    int n, r;

    if (!news_dbopen) return;

    strcpy(buf, mailbox);
    n = strlen(mailbox) + 1;
    n += sprintf(buf+n, "%lu", uid) + 1;
    n += sprintf(buf+n, "%lu", 0L) + 1;
    n += sprintf(buf+n, "%ld", tstamp) + 1;

    do {
	r = DB->store(newsdb, msgid, strlen(msgid), buf, n, NULL);
    } while (r == CYRUSDB_AGAIN);

    syslog(LOG_DEBUG, "netnews_store: %s %s %lu %ld",
	   msgid, mailbox, uid, tstamp);

    return;
}

void netnews_delete(char *msgid)
{
    int r;

    if (!news_dbopen) return;

    do {
	r = DB->delete(newsdb, msgid, strlen(msgid), NULL, 0);
    } while (r == CYRUSDB_AGAIN);

    return;
}

struct findrock {
    struct wildmat *wild;
    time_t mark;
    int later;
    int count;
    int (*proc)();
    void *rock;
};

static int find_p(void *rock, const char *id, int idlen,
		  const char *data, int datalen)
{
    struct findrock *frock = (struct findrock *) rock;
    struct wildmat *wild = frock->wild;
    struct netnews_entry entry;

    frock->count++;

    parse_entry(data, &entry);

    /* see if the mailbox matches one of our wildmats */
    while (wild->pat && wildmat(entry.mailbox, wild->pat) != 1) wild++;

    /* if we don't have a match, or its a negative match, skip it */
    if (!wild->pat || wild->not) return 0;

    /* check timestamp against mark */
    if (frock->later)
	return (entry.tstamp >= frock->mark);
    else
	return (entry.tstamp < frock->mark);
}

static int find_cb(void *rock, const char *id, int idlen,
		   const char *data, int datalen)
{
    struct findrock *frock = (struct findrock *) rock;
    static char *msgid = NULL;
    static int size = 0;
    struct netnews_entry entry;
    int r;

    if (idlen+1 > size) {
	size = idlen + 1;
	msgid = xrealloc(msgid, size);
    }
    memcpy(msgid, id, idlen);
    msgid[idlen] = '\0';

    parse_entry(data, &entry);

    r = (*frock->proc)(msgid, entry.mailbox, entry.uid,
		       entry.tstamp, frock->rock);

    return r;
}

int netnews_findall(struct wildmat *wild, time_t mark, int later,
		    int (*proc)(), void *rock)
{
    struct findrock frock;

    frock.wild = wild;
    frock.mark = mark;
    frock.later = later;
    frock.count = 0;
    frock.proc = proc;
    frock.rock = rock;

    /* check each entry in our database */
    DB->foreach(newsdb, "", 0, &find_p, &find_cb, &frock, NULL);

    return frock.count;
}

int netnews_done(void)
{
    int r;

    if (news_dbopen) {
	r = DB->close(newsdb);
	if (r) {
	    syslog(LOG_ERR, "DBERROR: error closing deliverdb: %s",
		   cyrusdb_strerror(r));
	}
	news_dbopen = 0;
    }
    r = DB->done();

    return r;
}

struct wildmat *split_wildmats(char *str)
{
    const char *prefix;
    char pattern[MAX_MAILBOX_NAME+1] = "", *p, *c;
    struct wildmat *wild = NULL;
    int n = 0;

    if ((prefix = config_getstring(IMAPOPT_NEWSPREFIX)))
	snprintf(pattern, sizeof(pattern), "%s.", prefix);
    p = pattern + strlen(pattern);

    /*
     * split the list of wildmats
     *
     * we split them right to left because this is the order in which
     * we want to test them (per draft-ietf-nntpext-base 5.2)
     */
    do {
	if ((c = strrchr(str, ',')))
	    *c++ = '\0';
	else
	    c = str;

	if (!(n % 10)) /* alloc some more */
	    wild = xrealloc(wild, (n + 11) * sizeof(struct wildmat));

	if (*c == '!') wild[n].not = 1;		/* not */
	else if (*c == '@') wild[n].not = -1;	/* absolute not (feeding) */
	else wild[n].not = 0;

	strcpy(p, wild[n].not ? c + 1 : c);
	wild[n++].pat = xstrdup(pattern);
    } while (c != str);
    wild[n].pat = NULL;

    return wild;
}

void free_wildmats(struct wildmat *wild)
{
    struct wildmat *w = wild;

    while (w->pat) {
	free(w->pat);
	w++;
    }
    free(wild);
}

