/*  cyrusdb_db3: berkeley db backend
 *
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
 */

#include <config.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <fcntl.h>

#include "assert.h"
#include "cyrusdb.h"
#include "exitcodes.h"
#include "map.h"
#include "bsearch.h"
#include "lock.h"
#include "retry.h"
#include "xmalloc.h"

/* we have the file locked iff we have an outstanding transaction */

struct db {
    char *fname;

    int fd;			/* current file open */
    long ino;

    const char *base;		/* contents of file */
    unsigned long size;
};

struct txn {
    char *fnamenew;
    int fd;
};

/* other routines call this one when they fail */
static int abort_txn(struct db *db, struct txn *tid)
{
    int r = CYRUSDB_OK;
    int rw = 0;
    struct stat sbuf;

    assert(db && tid);

    /* cleanup done while lock is held */
    if (tid->fnamenew) {
	unlink(tid->fnamenew);
	free(tid->fnamenew);
	rw = 1;
    }

    /* release lock */
    r = lock_unlock(db->fd);
    if (r == -1) {
	syslog(LOG_ERR, "IOERROR: unlocking db %s: %m", db->fname);
	r = CYRUSDB_IOERROR;
    }

    if (rw) {
	/* return to our normally scheduled fd */
	if (!r && fstat(db->fd, &sbuf) == -1) {
	    syslog(LOG_ERR, "IOERROR: fstat on %s: %m", db->fname);
	    r = CYRUSDB_IOERROR;
	}
	if (!r) {
	    map_free(&db->base, &db->size);
	    map_refresh(db->fd, 1, &db->base, &db->size, sbuf.st_size,
			db->fname, 0);
	}
    }

    free(tid);
    
    return 0;
}

static int init(const char *dbdir, int myflags)
{
    return 0;
}

static int done(void)
{
    return 0;
}

static int mysync(void)
{
    return 0;
}

static int myopen(const char *fname, struct db **ret)
{
    struct db *db = (struct db *) xmalloc(sizeof(struct db));
    struct stat sbuf;

    assert(fname && ret);

    db->fd = open(fname, O_RDWR | O_CREAT, 0666);
    if (db->fd == -1) {
	syslog(LOG_ERR, "IOERROR: opening %s: %m", fname);
	free(db);
	return CYRUSDB_IOERROR;
    }

    if (fstat(db->fd, &sbuf) == -1) {
	syslog(LOG_ERR, "IOERROR: fstat on %s: %m", fname);
	close(db->fd);
	free(db);
	return CYRUSDB_IOERROR;
    }
    db->ino = sbuf.st_ino;

    db->base = 0;
    db->size = 0;
    map_refresh(db->fd, 1, &db->base, &db->size, sbuf.st_size,
		fname, 0);

    db->fname = xstrdup(fname);

    *ret = db;
    return 0;
}

static int myclose(struct db *db)
{
    assert(db);

    map_free(&db->base, &db->size);
    close(db->fd);
    free(db);

    return 0;
}

static int starttxn_or_refetch(struct db *db, struct txn **mytid)
{
    int r = 0;
    struct stat sbuf;

    assert(db);

    if (mytid && !*mytid) {
	const char *lockfailaction;

	/* start txn; grab lock */

	r = lock_reopen(db->fd, db->fname, &sbuf, &lockfailaction);
	if (r < 0) {
	    syslog(LOG_ERR, "IOERROR: %s %s: %m", lockfailaction, db->fname);
	    return CYRUSDB_IOERROR;
	}
	*mytid = (struct txn *) xmalloc(sizeof(struct txn));
	(*mytid)->fnamenew = NULL;

	if (db->ino != sbuf.st_ino) {
	    map_free(&db->base, &db->size);
	}
	map_refresh(db->fd, 1, &db->base, &db->size, sbuf.st_size,
		    db->fname, 0);
    }

    if (!mytid) {
	/* no txn, but let's try to be reasonably up-to-date */

	if (stat(db->fname, &sbuf) == -1) {
	    syslog(LOG_ERR, "IOERROR: stating %s: %m", db->fname);
	    return CYRUSDB_IOERROR;
	}

	if (sbuf.st_ino != db->ino) {
	    /* reopen */
	    int newfd = open(db->fname, O_RDWR);

	    if (newfd == -1) {
		/* fail! */
		syslog(LOG_ERR, "couldn't reopen %s: %m", db->fname);
		return CYRUSDB_IOERROR;
	    }
	    dup2(newfd, db->fd);
	    close(newfd);
	    if (stat(db->fname, &sbuf) == -1) {
		syslog(LOG_ERR, "IOERROR: stating %s: %m", db->fname);
		return CYRUSDB_IOERROR;
	    }
	    
	    db->ino = sbuf.st_ino;
	    map_free(&db->base, &db->size);
	    map_refresh(db->fd, 1, &db->base, &db->size,
			sbuf.st_size, db->fname, 0);
	}
    }

    return 0;
}

static int myfetch(struct db *db, 
		   const char *key, int keylen,
		   const char **data, int *datalen,
		   struct txn **mytid)
{
    int r = 0;
    int offset;
    unsigned long len;

    assert(db);

    r = starttxn_or_refetch(db, mytid);
    if (r) return r;

    offset = bsearch_mem(key, 1, db->base, db->size, 0, &len);
    if (len) {
	*data = db->base + offset + keylen + 1;
	/* subtract one for \t, and one for the \n */
	*datalen = len - keylen - 2;
    } else {
	*data = NULL;
	*datalen = 0;
    }

    return r;
}

static int fetch(struct db *mydb, 
		 const char *key, int keylen,
		 const char **data, int *datalen,
		 struct txn **mytid)
{
    return myfetch(mydb, key, keylen, data, datalen, mytid);
}

static int fetchlock(struct db *db, 
		     const char *key, int keylen,
		     const char **data, int *datalen,
		     struct txn **mytid)
{
    return myfetch(db, key, keylen, data, datalen, mytid);
}


static int foreach(struct db *db,
		   char *prefix, int prefixlen,
		   foreach_cb *cb, void *rock, 
		   struct txn **mytid)
{
    int r = CYRUSDB_OK;
    int offset;
    unsigned long len;
    const char *p, *pend;

    r = starttxn_or_refetch(db, mytid);
    if (r) return r;

    offset = bsearch_mem(prefix, 1, db->base, db->size, 0, &len);
    p = db->base + offset;
    pend = db->base + db->size;
    while (p < pend) {
	const char *key = p;
	int keylen;
	const char *data = strchr(key, '\t'), *dataend;
	int datalen;

	if (!data) {
	    /* huh, might be corrupted? */
	    r = CYRUSDB_IOERROR;
	    break;
	}
	keylen = data - key;
	data++; /* skip of the \t */
       
	dataend = strchr(data, '\n');
	if (!dataend) {
	    /* huh, might be corrupted? */
	    r = CYRUSDB_IOERROR;
	    break;
	}
	datalen = dataend - data;

	/* does it still match prefix? */
	if (keylen < prefixlen) break;
	if (prefixlen && memcmp(key, prefix, prefixlen)) break;

	/* make callback */
	r = cb(rock, key, keylen, data, datalen);
	if (r) break;

	p = dataend + 1;
    }

    return r;
}

static int mystore(struct db *db, 
		   const char *key, int keylen,
		   const char *data, int datalen,
		   struct txn **mytid, int overwrite)
{
    int r = 0;
    char fnamebuf[1024];
    int offset;
    unsigned long len;
    const char *lockfailaction;
    int writefd;
    struct iovec iov[10];
    int niov;
    struct stat sbuf;

    /* lock file, if needed */
    if (!mytid || !*mytid) {
	r = lock_reopen(db->fd, db->fname, &sbuf, &lockfailaction);
	if (r < 0) {
	    syslog(LOG_ERR, "IOERROR: %s %s: %m", lockfailaction, db->fname);
	    return CYRUSDB_IOERROR;
	}

	if (sbuf.st_ino != db->ino) {
	    db->ino = sbuf.st_ino;
	    map_free(&db->base, &db->size);
	    map_refresh(db->fd, 1, &db->base, &db->size,
			sbuf.st_size, db->fname, 0);
	}

	if (mytid) {
	    *mytid = (struct txn *) xmalloc(sizeof(struct txn));
	    (*mytid)->fnamenew = NULL;
	}
    }

    /* find entry, if it exists */
    offset = bsearch_mem(key, 1, db->base, db->size, 0, &len);

    /* overwrite? */
    if (len && !overwrite) {
	if (mytid) abort_txn(db, *mytid);
	return CYRUSDB_EXISTS;
    }

    /* write new file */
    if (mytid && (*mytid)->fnamenew) {
	strcpy(fnamebuf, (*mytid)->fnamenew);
    } else {
	strcpy(fnamebuf, db->fname);
	strcat(fnamebuf, ".NEW");
    }
    unlink(fnamebuf);
    writefd = open(fnamebuf, O_RDWR | O_CREAT, 0666);
    niov = 0;
    iov[niov].iov_base = (char *) db->base;
    iov[niov++].iov_len = offset;

    if (data) {
	/* new entry */
	iov[niov].iov_base = (char *) key;
	iov[niov++].iov_len = keylen;
	
	iov[niov].iov_base = "\t";
	iov[niov++].iov_len = 1;
	
	iov[niov].iov_base = (char *) data;
	iov[niov++].iov_len = datalen;
	
	iov[niov].iov_base = "\n";
	iov[niov++].iov_len = 1;
    }

    iov[niov].iov_base = (char *) db->base + offset + len;
    iov[niov++].iov_len = db->size - (offset + len);

    /* do the write */
    r = retry_writev(writefd, iov, niov);
    if (r == -1) {
	syslog(LOG_ERR, "IOERROR: writing %s: %m", fnamebuf);
	close(writefd);
	if (mytid) abort_txn(db, *mytid);
    }
    r = 0;

    if (mytid) {
	/* setup so further accesses will be against fname.NEW */
	if (fstat(writefd, &sbuf) == -1) {

	}

	(*mytid)->fnamenew = xstrdup(fnamebuf);
	(*mytid)->fd = writefd;
	map_free(&db->base, &db->size);
	map_refresh(writefd, 1, &db->base, &db->size, sbuf.st_size,
		    fnamebuf, 0);
    } else {
	/* commit immediately */
	if (fsync(writefd) ||
	    fstat(writefd, &sbuf) == -1 ||
	    rename(fnamebuf, db->fname) == -1) {
	    syslog(LOG_ERR, "IOERROR: writing %s: %m", fnamebuf);
	    close(writefd);
	    return CYRUSDB_IOERROR;
	}

	/* release lock */
	r = lock_unlock(db->fd);
	if (r == -1) {
	    syslog(LOG_ERR, "IOERROR: unlocking db %s: %m", db->fname);
	    r = CYRUSDB_IOERROR;
	}

	close(db->fd);
	db->fd = writefd;

	db->ino = sbuf.st_ino;
	map_free(&db->base, &db->size);
	map_refresh(writefd, 1, &db->base, &db->size, sbuf.st_size,
	    db->fname, 0);
    }

    return r;
}

static int create(struct db *db, 
		  const char *key, int keylen,
		  const char *data, int datalen,
		  struct txn **tid)
{
    return mystore(db, key, keylen, data, datalen, tid, 0);
}

static int store(struct db *db, 
		 const char *key, int keylen,
		 const char *data, int datalen,
		 struct txn **tid)
{
    return mystore(db, key, keylen, data, datalen, tid, 1);
}

static int delete(struct db *db, 
		  const char *key, int keylen,
		  struct txn **mytid)
{
    return mystore(db, key, keylen, NULL, 0, mytid, 1);
}

static int commit_txn(struct db *db, struct txn *tid)
{
    int writefd;
    int r = 0;
    struct stat sbuf;

    assert(db && tid);

    if (tid->fnamenew) {
	/* we wrote something */

	writefd = tid->fd;
	if (fsync(writefd) ||
	    fstat(writefd, &sbuf) == -1 ||
	    rename(tid->fnamenew, db->fname) == -1) {
	    syslog(LOG_ERR, "IOERROR: writing %s: %m", tid->fnamenew);
	    close(writefd);
	    r = CYRUSDB_IOERROR;
	} else {
	    /* successful */
	    /* we now deal exclusively with our new fd */
	    close(db->fd);
	    db->fd = writefd;
	    db->ino = sbuf.st_ino;
	}
	free(tid->fnamenew);
    } else {
	/* read-only txn */
    }

    free(tid);
    return r;
}

struct cyrusdb_backend cyrusdb_flat = 
{
    "flat",			/* name */

    &init,
    &done,
    &mysync,

    &myopen,
    &myclose,

    &fetch,
    &fetchlock,
    &foreach,
    &create,
    &store,
    &delete,

    &commit_txn,
    &abort_txn
};
