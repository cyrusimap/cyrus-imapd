/*
 * Copyright (c) 2000 Carnegie Mellon University.  All rights reserved.
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

#include <config.h>

#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <assert.h>
#include <ctype.h>
#include <time.h>
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

#include "imap_err.h"
#include "imapconf.h"
#include "exitcodes.h"
#include "xmalloc.h"
#include "util.h"
#include "cyrusdb.h"

#include "duplicate.h"

#define DB CONFIG_DB_DELIVER


int duplicate_init(int myflags)
{
    char buf[1024];
    int r = 0;
    int flags = 0;

    /* create the name of the db file */
    strcpy(buf, config_dir);
    strcat(buf, FNAME_DBDIR);
    if (myflags & DUPLICATE_RECOVER) flags |= CYRUSDB_RECOVER;
    r = DB->init(buf, flags);

    return r;
}

time_t duplicate_check(char *id, int idlen, char *to, int tolen)
{
    char buf[1024];
    char fname[1024];
    struct db *db;
    int r;
    const char *data = NULL;
    int len = 0;
    time_t mark = 0;

    if (idlen + tolen > sizeof(buf) - 30) return 0;
    memcpy(buf, id, idlen);
    buf[idlen] = '\0';
    memcpy(buf + idlen + 1, to, tolen);
    buf[idlen + tolen + 1] = '\0';

    /* create the name of the db file */
    strcpy(fname, config_dir);
    strcat(fname, FNAME_DELIVERDB);

    /* fetch the entry from our database */
    r = DB->open(fname, &db);
    if (r != CYRUSDB_OK) {
	syslog(LOG_ERR, "DBERROR: opening %s: %s",
	       fname, cyrusdb_strerror(r));
    }
    else {
	do {
	    r = DB->fetch(db, buf,
			  idlen + tolen + 2, /* +2 b/c 1 for the center null;
						+1 for the terminating null */
			  &data, &len, NULL);
	} while (r == CYRUSDB_AGAIN);
	DB->close(db);
    }

    if (data) {
	/* found the record */
	memcpy(&mark, data, sizeof(time_t));
    } else if (r != CYRUSDB_OK) {
	syslog(LOG_ERR, "duplicate_check: error looking up %s/%d: %s", id, to,
	       cyrusdb_strerror(r));
	mark = 0;
    }

    syslog(LOG_DEBUG, "duplicate_check: %-40s %-20s %d",
	   buf, buf+idlen+1, mark);

    return mark;
}

void duplicate_mark(char *id, int idlen, char *to, int tolen, time_t mark)
{
    char buf[1024];
    char fname[1024];
    struct db *db;
    int r;

    if (idlen + tolen > sizeof(buf) - 30) return;
    memcpy(buf, id, idlen);
    buf[idlen] = '\0';
    memcpy(buf + idlen + 1, to, tolen);
    buf[idlen + tolen + 1] = '\0';

    /* create the name of the db file */
    strcpy(fname, config_dir);
    strcat(fname, FNAME_DELIVERDB);

    r = DB->open(fname, &db);
    if (r != CYRUSDB_OK) {
	syslog(LOG_ERR, "DBERROR: opening %s: %s",
	       fname, cyrusdb_strerror(r));
    }
    else {
	do {
	    r = DB->store(db, buf,
			  idlen + tolen + 2, /* +2 b/c 1 for the center null;
						+1 for the terminating null */
			  (char *) &mark, sizeof(mark), NULL);
	} while (r == CYRUSDB_AGAIN);
	DB->close(db);
    }

    syslog(LOG_DEBUG, "duplicate_mark: %-40s %-20s %d",
	   buf, buf+idlen+1, mark);

    return;
}

struct prunerock {
    struct db *db;
    time_t expmark;
    int count;
    int deletions;
};

static int find_p(void *rock, const char *id, int idlen,
		  const char *data, int datalen)
{
    time_t mark;
    struct prunerock *prock = (struct prunerock *) rock;

    prock->count++;

    /* grab the mark */
    memcpy(&mark, data, sizeof(time_t));

    /* check if we should prune this entry */
    return (mark < prock->expmark);
}

static int find_cb(void *rock, const char *id, int idlen,
		   const char *data, int datalen)
{
    struct prunerock *prock = (struct prunerock *) rock;
    int r;

    prock->deletions++;

    do {
	r = DB->delete(prock->db, id, idlen, NULL);
    } while (r == CYRUSDB_AGAIN);


    return 0;
}

int duplicate_prune(int days)
{
    char fname[1024];
    int r;
    struct db *db;
    struct prunerock prock;

    if (days < 0) fatal("must specify positive number of days", EC_USAGE);

    prock.count = prock.deletions = 0;
    prock.expmark = time(NULL) - (days * 60 * 60 * 24);
    syslog(LOG_NOTICE, "duplicate_prune: pruning back %d days", days);
    
   /* create the name of the db file */
    strcpy(fname, config_dir);
    strcat(fname, FNAME_DELIVERDB);

    r = DB->open(fname, &db);
    if (r != CYRUSDB_OK) {
	syslog(LOG_ERR, "DBERROR: opening %s: %s",
	       fname, cyrusdb_strerror(r));
	return 1;
    }
    else {
	/* check each entry in our database */
	prock.db = db;
	DB->foreach(db, "", 0, &find_p, &find_cb, &prock, NULL);
	DB->close(db);
    }

    syslog(LOG_NOTICE, "duplicate_prune: purged %d out of %d entries",
	   prock.deletions, prock.count);

    return 0;
}

int duplicate_done(void)
{
    int r;

    r = DB->done();

    return r;
}
