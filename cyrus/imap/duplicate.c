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
#include <stdlib.h>
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

#include "xmalloc.h"
#include "imap_err.h"
#include "imapconf.h"
#include "exitcodes.h"
#include "util.h"
#include "cyrusdb.h"

#include "duplicate.h"

#define DB (CONFIG_DB_DUPLICATE)

static struct db *dupdb = NULL;
static int duplicate_dbopen = 0;


int duplicate_init(char *fname, int myflags)
{
    char buf[1024];
    int r = 0;
    int flags = 0;

    /* create the name of the db file */
    strcpy(buf, config_dir);
    strcat(buf, FNAME_DBDIR);
    if (myflags & DUPLICATE_RECOVER) flags |= CYRUSDB_RECOVER;
    r = DB->init(buf, flags);

    if (r != 0)
	syslog(LOG_ERR, "DBERROR: init %s: %s", buf,
	       cyrusdb_strerror(r));
    else {
	char *tofree = NULL;

	/* create db file name */
	if (!fname) {
	    fname = xmalloc(strlen(config_dir)+sizeof(FNAME_DELIVERDB));
	    tofree = fname;
	    strcpy(fname, config_dir);
	    strcat(fname, FNAME_DELIVERDB);
	}

	r = DB->open(fname, &dupdb);
	if (r != 0)
	    syslog(LOG_ERR, "DBERROR: opening %s: %s", fname,
		   cyrusdb_strerror(r));
	else
	    duplicate_dbopen = 1;

	if (tofree) free(tofree);
    }

    return r;
}

time_t duplicate_check(char *id, int idlen, char *to, int tolen)
{
    char buf[1024];
    int r;
    const char *data = NULL;
    int len = 0;
    time_t mark = 0;

    if (!duplicate_dbopen) return 0;

    if (idlen + tolen > sizeof(buf) - 30) return 0;
    memcpy(buf, id, idlen);
    buf[idlen] = '\0';
    memcpy(buf + idlen + 1, to, tolen);
    buf[idlen + tolen + 1] = '\0';

    do {
	r = DB->fetch(dupdb, buf,
		      idlen + tolen + 2, /* +2 b/c 1 for the center null;
					    +1 for the terminating null */
		      &data, &len, NULL);
    } while (r == CYRUSDB_AGAIN);

    if (data) {
	assert(len == sizeof(time_t));

	/* found the record */
	memcpy(&mark, data, sizeof(time_t));
    } else if (r != CYRUSDB_OK) {
	syslog(LOG_ERR, "duplicate_check: error looking up %s/%s: %s",
	       id, to,
	       cyrusdb_strerror(r));
	mark = 0;
    }

    syslog(LOG_DEBUG, "duplicate_check: %-40s %-20s %ld",
	   buf, buf+idlen+1, mark);

    return mark;
}

void duplicate_mark(char *id, int idlen, char *to, int tolen, time_t mark)
{
    char buf[1024];
    int r;

    if (!duplicate_dbopen) return;

    if (idlen + tolen > sizeof(buf) - 30) return;
    memcpy(buf, id, idlen);
    buf[idlen] = '\0';
    memcpy(buf + idlen + 1, to, tolen);
    buf[idlen + tolen + 1] = '\0';

    do {
	r = DB->store(dupdb, buf,
		      idlen + tolen + 2, /* +2 b/c 1 for the center null;
					    +1 for the terminating null */
		      (char *) &mark, sizeof(mark), NULL);
    } while (r == CYRUSDB_AGAIN);

    syslog(LOG_DEBUG, "duplicate_mark: %-40s %-20s %ld",
	   buf, buf+idlen+1, mark);

    return;
}

struct prunerock {
    struct db *db;
    time_t expmark;
    int count;
    int deletions;
};

static int prune_p(void *rock, const char *id, int idlen,
		  const char *data, int datalen)
{
    struct prunerock *prock = (struct prunerock *) rock;
    time_t mark;

    prock->count++;

    /* grab the mark */
    memcpy(&mark, data, sizeof(time_t));

    /* check if we should prune this entry */
    return (mark < prock->expmark);
}

static int prune_cb(void *rock, const char *id, int idlen,
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
    struct prunerock prock;

    if (days < 0) fatal("must specify positive number of days", EC_USAGE);

    prock.count = prock.deletions = 0;
    prock.expmark = time(NULL) - (days * 60 * 60 * 24);
    syslog(LOG_NOTICE, "duplicate_prune: pruning back %d days", days);

    /* check each entry in our database */
    prock.db = dupdb;
    DB->foreach(dupdb, "", 0, &prune_p, &prune_cb, &prock, NULL);

    syslog(LOG_NOTICE, "duplicate_prune: purged %d out of %d entries",
	   prock.deletions, prock.count);

    return 0;
}

struct dumprock {
    FILE *f;
    int count;
};

static int dump_p(void *rock,
		  const char *key, int keylen,
		  const char *data, int datalen)
{
    struct dumprock *drock = (struct dumprock *) rock;

    drock->count++;

    return 1;
}

static const char hexcodes[] = "0123456789ABCDEF";

static int dump_cb(void *rock,
		   const char *key, int keylen,
		   const char *data, int datalen)
{
    struct dumprock *drock = (struct dumprock *) rock;
    time_t mark;
    char *id, *to, *freeme;
    int idlen, i;

    assert(datalen == sizeof(time_t));

    memcpy(&mark, data, sizeof(time_t));
    to = (char*) key + strlen(key) + 1;
    id = (char *) key;
    idlen = strlen(id);

    for (i = 0; i < idlen; i++) {
	if (!isprint((unsigned char) id[i])) break;
    }

    if (i != idlen) {
	/* change to hexadecimal */
	freeme = (char *) xmalloc(sizeof(char) * idlen * 2 + 1);
	for (i = 0; i < idlen; i++) {
	    freeme[2 * i] = hexcodes[(id[i] >> 4) & 0xf];
	    freeme[2 * i + 1] = hexcodes[id[i] & 0xf];
	}
	freeme[2 * idlen] = '\0';
	id = freeme;
    } else {
	freeme = NULL;
    }

    fprintf(drock->f, "id: %-40s\tto: %-20s\tat: %ld\n", id, to, (long) mark);

    if (freeme) free(freeme);

    return 0;
}

int duplicate_dump(FILE *f)
{
    struct dumprock drock;

    drock.f = f;
    drock.count = 0;

    /* check each entry in our database */
    DB->foreach(dupdb, "", 0, &dump_p, &dump_cb, &drock, NULL);

    return drock.count;
}

int duplicate_done(void)
{
    int r;

    if (duplicate_dbopen) {
	r = DB->close(dupdb);
	if (r) {
	    syslog(LOG_ERR, "DBERROR: error closing deliverdb: %s",
		   cyrusdb_strerror(r));
	}
	duplicate_dbopen = 0;
    }
    r = DB->done();

    return r;
}
