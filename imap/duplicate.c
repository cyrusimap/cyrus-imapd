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

#include "duplicate.h"

/* it would be nice to cache some DBs so that we're not constantly
   opening and closing them; something to be evaluated */

static int duplicate_dbinit = 0;
DB_ENV *duplicate_dbenv;

static void db_err(const char *db_prfx, char *buffer)
{
    syslog(LOG_ERR, "DBERROR %s: %s", db_prfx, buffer);
}

static int nuke_dir(char *dir)
{
    DIR *dirp;
    struct dirent *dirent;

    if (chdir(dir) == -1) {
	if (!mkdir(dir, 0755)) return 0;
	else return IMAP_IOERROR;
    }
    dirp = opendir(".");
    if (!dirp) return IMAP_IOERROR;

    while ((dirent = readdir(dirp)) != NULL) {
	unlink(dirent->d_name);
    }
    closedir(dirp);
    
    return 0;
}

int duplicate_init(int myflags)
{
    char buf[1024];
    int r = 0;
    int flags = 0;

    assert(!duplicate_dbinit);

    sprintf(buf, "%s/deliverdb/db", config_dir);
    if (myflags & DUPLICATE_RECOVER) {
	/* remove the database environment; it'll be recreated */
	r = nuke_dir(buf);
	if (r) return r;
    }
    if ((r = db_env_create(&duplicate_dbenv, 0)) != 0) {
	syslog(LOG_ERR, "DBERROR: db_appinit failed: %s", strerror(r));
	return IMAP_IOERROR;
    }
    
    flags |= DB_INIT_CDB | DB_INIT_MPOOL | DB_CREATE;
    /* create the name of the db file */
#if (DB_VERSION_MINOR > 0)
    r = duplicate_dbenv->open(duplicate_dbenv, buf, flags, 0644);
#else
    r = duplicate_dbenv->open(duplicate_dbenv, buf, NULL, flags, 0644);
#endif
    if (r) {
	syslog(LOG_ERR, "DBERROR: dbenv->open failed: %s", strerror(r));
	return IMAP_IOERROR;
    }

    duplicate_dbenv->set_errpfx(duplicate_dbenv, "dup");
    duplicate_dbenv->set_errcall(duplicate_dbenv, db_err);

    duplicate_dbinit = 1;

    return 0;
}

/* too many processes are contending for single locks on delivered.db 
 * so we use this function to generate a specific delivered.db for a mailbox
 * First pass will be to just have 26 db files based on the first letter of 
 * the mailbox name. As distribution goes, this really blows but, hey, what do 
 * you expect from something quick and dirty?
 * 'buf' should be at least 1024
 */
static char *get_db_name (char *mbox, char *buf)
{
    char *idx;
    char c;
  
    idx = strchr(mbox,'.');   /* skip past user. */
    if (idx == NULL) {         /* no '.' so just use mbox */
	idx = mbox;
    } else {
	idx++;                   /* skip past '.' */
    }
    c = (char) tolower((int) *idx);
    if (!islower((int) c)) {
	c = 'q';
    }

    snprintf(buf, 1024, "%s/deliverdb/deliver-%c.db", config_dir, c);

    return buf;
}


time_t duplicate_check(char *id, int idlen, char *to, int tolen)
{
    char buf[1024];
    char fname[1024];
    DB *d;
    DBT date, delivery;
    int r;
    time_t mark;

    assert(duplicate_dbinit);
    (void)memset(&date, 0, sizeof(date));
    (void)memset(&delivery, 0, sizeof(delivery));

    if (idlen + tolen > sizeof(buf) - 30) return 0;
    memcpy(buf, id, idlen);
    buf[idlen] = '\0';
    memcpy(buf + idlen + 1, to, tolen);
    buf[idlen + tolen + 1] = '\0';
    delivery.data = buf;
    delivery.size = idlen + tolen + 2;
          /* +2 b/c 1 for the center null; +1 for the terminating null */

    get_db_name(to, fname);

    r = db_create(&d, duplicate_dbenv, 0);
    if (r != 0) {
	syslog(LOG_ERR, "duplicate_check: db_create %s: %s", fname,
	       db_strerror(r));
	return 0;
    }
    r = d->open(d, fname, NULL, DB_HASH, DB_CREATE, 0664);
    if (r != 0) {
	syslog(LOG_ERR, "duplicate_check: opening %s: %s", fname,
	       db_strerror(r));
	return 0;
    }

    r = d->get(d, NULL, &delivery, &date, 0);
    if (r == 0) {
	/* found the record */
	memcpy(&mark, date.data, sizeof(time_t));
    } else if (r == DB_NOTFOUND) {
	mark = 0;
    } else {
	syslog(LOG_ERR, "duplicate_check: error looking up %s/%d: %s", id, to,
	       db_strerror(r));
	mark = 0;
    }

    r = d->close(d, 0);
    if (r != 0) {
	syslog(LOG_ERR, "duplicate_check: closing %s: %s", fname, 
	       db_strerror(r));
	return 0;
    }

    return mark;
}

void duplicate_mark(char *id, int idlen, char *to, int tolen, time_t mark)
{
    char buf[1024];
    char fname[1024];
    DB *d;
    DBT date, delivery;
    int r;

    assert(duplicate_dbinit);
    (void)memset(&date, 0, sizeof(date));
    (void)memset(&delivery, 0, sizeof(delivery));

    if (idlen + tolen > sizeof(buf) - 30) return;
    memcpy(buf, id, idlen);
    buf[idlen] = '\0';
    memcpy(buf + idlen + 1, to, tolen);
    buf[idlen + tolen + 1] = '\0';
    delivery.data = buf;
    delivery.size = idlen + tolen + 2;
          /* +2 b/c 1 for the center null; +1 for the terminating null */

    date.data = &mark;
    date.size = sizeof(mark);

    get_db_name(to, fname);

    r = db_create(&d, duplicate_dbenv, 0);
    if (r != 0) {
	syslog(LOG_ERR, "duplicate_mark: db_create %s: %s", fname,
	       db_strerror(r));
	return;
    }
    r = d->open(d, fname, NULL, DB_HASH, DB_CREATE, 0664);
    if (r != 0) {
	syslog(LOG_ERR, "duplicate_mark: opening %s: %s", fname,
	       db_strerror(r));
	return;
    }

    r = d->put(d, NULL, &delivery, &date, 0);
    if (r != 0) {
	syslog(LOG_ERR, "duplicate_mark: error setting %s/%d: %s", id, to,
	       db_strerror(r));
	mark = 0;
    }

    r = d->close(d, 0);
    if (r != 0) {
	syslog(LOG_ERR, "duplicate_mark: closing %s: %s", fname,
	       db_strerror(r));
	return;
    }

    return;
}


int duplicate_prune(int days)
{
    int r;
    DB *d;
    DBC *cursor = NULL;
    DBT delivery, date;
    time_t mark, expmark;
    char c[2];

    if (days < 0) fatal("must specify positive number of days", EC_USAGE);

    memset(&delivery, 0, sizeof(delivery));
    memset(&date, 0, sizeof(date));

    expmark = time(NULL) - (days * 60 * 60 * 24);
    syslog(LOG_NOTICE, "duplicate_prune: pruning back %d days", days);
    
    c[1] = '\0';
    for (c[0] = 'a'; c[0] <= 'z'; c[0]++) {
	char fname[1024];
	int count = 0, deletions = 0;

	get_db_name(c, fname);
	r = db_create(&d, duplicate_dbenv, 0);
	if (r != 0) {
	    syslog(LOG_ERR, "duplicate_prune: db_create: %s", db_strerror(r));
	    return 1;
	}
	
	r = d->open(d, fname, NULL, DB_HASH, 0, 0664);
	if (r == ENOENT) {
	    syslog(LOG_NOTICE, "creating %s", fname);
	    r = d->open(d, fname, NULL, DB_HASH, DB_CREATE, 0664);
	}
	if (r != 0) {
	    /* might just not exist */
	    syslog(LOG_NOTICE, "duplicate_prune: opening %s: %s", fname,
		   db_strerror(r));
	    continue;
	}
	
	r = d->cursor(d, NULL, &cursor, DB_WRITECURSOR);
	if (r != 0) { 
	    syslog(LOG_ERR, "duplicate_prune: unable to create cursor: %s",
		    db_strerror(r));
	    goto closedb;
	}

	r = cursor->c_get(cursor, &delivery, &date, DB_FIRST);
	while (r != DB_NOTFOUND) {
	    if (r != 0) {
		syslog(LOG_ERR, "duplicate_prune: error advancing: %s", 
		       db_strerror(r));
		break;
	    }

	    count++;
	    memcpy(&mark, date.data, sizeof(time_t));
	    if (mark < expmark) {
		deletions++;
		r = cursor->c_del(cursor, 0);
		if (r != 0) {
		    syslog(LOG_ERR, "duplicate_prune: error deleting: %s",
			   db_strerror(r));
		}
	    }

	    r = cursor->c_get(cursor, &delivery, &date, DB_NEXT);
	}
	r = cursor->c_close(cursor);
	if (r != 0) {
	    syslog(LOG_ERR, "duplicate_prune: error closing cursor: %s",
		   db_strerror(r));
	}

    closedb:
	r = d->close(d, 0);
	if (r != 0) {
	    syslog(LOG_ERR, "duplicate_prune: closing %s: %s", fname,
		   db_strerror);
	}

	syslog(LOG_NOTICE, "duplicate_prune: %s: purged %d out of %d entries",
	       fname, deletions, count);
    }

    return 0;
}

int duplicate_done(void)
{
    int r;

    assert(duplicate_dbinit);

    r = duplicate_dbenv->close(duplicate_dbenv, 0);
    if (r) {
	syslog(LOG_ERR, "DBERROR: error exiting application: %s",
	       strerror(r));
    }

    duplicate_dbinit = 0;

    return 0;
}
