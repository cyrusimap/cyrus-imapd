/*  cyrusdb_flat: a sorted flat textfile backend
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

/* $Id: cyrusdb_flat.c,v 1.19.4.8 2003/02/11 15:45:06 ken3 Exp $ */

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
    ino_t ino;

    const char *base;		/* contents of file */
    unsigned long size;		/* actual size */
    unsigned long len;		/* mapped size */
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
	    map_free(&db->base, &db->len);
	    map_refresh(db->fd, 0, &db->base, &db->len, sbuf.st_size,
			db->fname, 0);
	    db->size = sbuf.st_size;
	}
    }

    free(tid);
    
    return 0;
}

static void free_db(struct db *db)
{
    if (db) {
	if (db->fname) free(db->fname);
	free(db);
    }
}

static struct txn *new_txn(void)
{
    struct txn *ret = (struct txn *) xmalloc(sizeof(struct txn));
    ret->fnamenew = NULL;
    ret->fd = 0;
    return ret;
}

static int init(const char *dbdir __attribute__((unused)),
		int myflags __attribute__((unused)))
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

static int myarchive(const char **fnames, const char *dirname)
{
    int r;
    const char **fname;
    char dstname[1024], *dp;

    strcpy(dstname, dirname);
    dp = dstname + strlen(dstname);

    /* archive those files specified by the app */
    for (fname = fnames; *fname != NULL; ++fname) {
	syslog(LOG_DEBUG, "archiving database file: %s", *fname);
	strcpy(dp, strrchr(*fname, '/'));
	r = cyrusdb_copyfile(*fname, dstname);
	if (r) {
	    syslog(LOG_ERR,
		   "DBERROR: error archiving database file: %s", *fname);
	    return CYRUSDB_IOERROR;
	}
    }

    return 0;
}

static int myopen(const char *fname, struct db **ret)
{
    struct db *db = (struct db *) xzmalloc(sizeof(struct db));
    struct stat sbuf;

    assert(fname && ret);

    db->fd = open(fname, O_RDWR | O_CREAT, 0666);
    if (db->fd == -1) {
	syslog(LOG_ERR, "IOERROR: opening %s: %m", fname);
	free_db(db);
	return CYRUSDB_IOERROR;
    }

    if (fstat(db->fd, &sbuf) == -1) {
	syslog(LOG_ERR, "IOERROR: fstat on %s: %m", fname);
	close(db->fd);
	free_db(db);
	return CYRUSDB_IOERROR;
    }
    db->ino = sbuf.st_ino;

    map_refresh(db->fd, 0, &db->base, &db->len, sbuf.st_size,
		fname, 0);
    db->size = sbuf.st_size;

    db->fname = xstrdup(fname);

    *ret = db;
    return 0;
}

static int myclose(struct db *db)
{
    assert(db);

    map_free(&db->base, &db->len);
    close(db->fd);
    free_db(db);

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
	*mytid = new_txn();

	if (db->ino != sbuf.st_ino) {
	    map_free(&db->base, &db->len);
	}
	map_refresh(db->fd, 0, &db->base, &db->len, sbuf.st_size,
		    db->fname, 0);

        /* we now have the latest & greatest open */
	db->size = sbuf.st_size;
        db->ino = sbuf.st_ino;
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
	    map_free(&db->base, &db->len);
	}
	map_refresh(db->fd, 0, &db->base, &db->len,
		    sbuf.st_size, db->fname, 0);
	db->size = sbuf.st_size;
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

#define GETENTRY(p)			\
     key = p;				\
     data = strchr(key, '\t');		\
 					\
     if (!data) {			\
 	/* huh, might be corrupted? */	\
 	r = CYRUSDB_IOERROR;		\
 	break;				\
     }					\
     keylen = data - key;		\
     data++; /* skip of the \t */	\
 					\
     dataend = strchr(data, '\n');	\
     if (!dataend) {			\
 	/* huh, might be corrupted? */	\
 	r = CYRUSDB_IOERROR;		\
 	break;				\
     }					\
     datalen = dataend - data;

static int foreach(struct db *db,
		   char *prefix, int prefixlen,
		   foreach_p *goodp,
		   foreach_cb *cb, void *rock, 
		   struct txn **mytid)
{
    int r = CYRUSDB_OK;
    int offset;
    unsigned long len;
    const char *p, *pend;

    /* for use inside the loop, but we need the values to be retained
     * from loop to loop */
    const char *key = NULL;
    size_t keylen = 0;
    const char *data = NULL, *dataend = NULL;
    size_t datalen = 0;
    int dontmove = 0;

    /* For when we have a transaction running */
    char *savebuf = NULL;
    size_t savebuflen = 0;
    size_t savebufsize = 0;

    /* for the local iteration so that the db can change out from under us */
    const char *dbbase = NULL;
    unsigned long dblen = 0;
    int dbfd = -1;

    r = starttxn_or_refetch(db, mytid);
    if (r) return r;

    if(!mytid) {
	/* No transaction, use the fast method to avoid stomping on our
	 * memory map if changes happen */
	dbfd = dup(db->fd);
	if(dbfd == -1) return CYRUSDB_IOERROR;
	
	map_refresh(dbfd, 1, &dbbase, &dblen, db->size, db->fname, 0);

	/* drop our read lock on the file, since we don't really care
	 * if it gets replaced out from under us, our mmap stays on the
	 * old version */
	lock_unlock(db->fd);
    } else {
	/* use the same variables as in the no transaction case, just to
	 * get things set up */
	dbbase = db->base;
	dblen = db->len;
    }

    if (prefix) {
	offset = bsearch_mem(prefix, 1, dbbase, db->size, 0, &len);
    } else {
	offset = 0;
    }
    
    p = dbbase + offset;
    pend = dbbase + db->size;

    while (p < pend) {
	if(!dontmove) {
	    GETENTRY(p)
	}
	else dontmove = 0;
	
	/* does it still match prefix? */
	if (keylen < prefixlen) break;
	if (prefixlen && memcmp(key, prefix, prefixlen)) break;

	if (goodp(rock, key, keylen, data, datalen)) {
	    unsigned long ino = db->ino;
 	    unsigned long sz = db->size;

	    if(mytid) {
		/* transaction present, this means we do the slow way */
		if (keylen > savebuflen) {
		    int dblsize = 2 * savebuflen;
		    int addsize = keylen + 32;
		    
		    savebuflen = (dblsize > addsize) ? dblsize : addsize;
		    savebuf = xrealloc(savebuf, savebuflen);
		}
		memcpy(savebuf, key, keylen);
		savebufsize = keylen;
	    }
	    
	    /* make callback */
	    r = cb(rock, key, keylen, data, datalen);
	    if (r) break;

	    if(mytid) {
		/* reposition? (we made a change) */
		if (!(ino == db->ino && sz == db->size)) {
		    /* something changed in the file; reseek */
		    offset = bsearch_mem(savebuf, 1, db->base, db->size,
					 0, &len);
		    p = db->base + offset;
		    
		    GETENTRY(p);
		    
		    /* 'key' might not equal 'savebuf'.  if it's different,
		       we want to stay where we are.  if it's the same, we
		       should move on to the next one */
		    if (savebufsize == keylen &&
			!memcmp(savebuf, key, savebufsize)) {
			p = dataend + 1;
		    } else {
			/* 'savebuf' got deleted, so we're now pointing at the
			   right thing */
			dontmove = 1;
		    }
		}	
	    }
	}

	p = dataend + 1;
    }

    if(!mytid) {
	/* cleanup the fast method */
	map_free(&dbbase, &dblen);
	close(dbfd);
    } else if(savebuf) {
	free(savebuf);
    }

    return r;
}

#undef GETENTRY

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
    char *tmpkey = NULL;

    /* lock file, if needed */
    if (!mytid || !*mytid) {
	r = lock_reopen(db->fd, db->fname, &sbuf, &lockfailaction);
	if (r < 0) {
	    syslog(LOG_ERR, "IOERROR: %s %s: %m", lockfailaction, db->fname);
	    return CYRUSDB_IOERROR;
	}

	if (sbuf.st_ino != db->ino) {
	    db->ino = sbuf.st_ino;
	    map_free(&db->base, &db->len);
	    map_refresh(db->fd, 0, &db->base, &db->len,
			sbuf.st_size, db->fname, 0);
	    db->size = sbuf.st_size;
	}

	if (mytid) {
	    *mytid = new_txn();
	}
    }

    /* if we need to truncate the key, do so */
    if(key[keylen] != '\0') {
	tmpkey = xmalloc(keylen + 1);
	memcpy(tmpkey, key, keylen);
	tmpkey[keylen] = '\0';
	key = tmpkey;
    }

    /* find entry, if it exists */
    offset = bsearch_mem(key, 1, db->base, db->size, 0, &len);

    /* overwrite? */
    if (len && !overwrite) {
	if (mytid) abort_txn(db, *mytid);
	if (tmpkey) free(tmpkey);
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
    r = writefd = open(fnamebuf, O_RDWR | O_CREAT, 0666);
    if (r < 0) {
        syslog(LOG_ERR, "opening %s for writing failed: %m", fnamebuf);
	if (mytid) abort_txn(db, *mytid);
	if (tmpkey) free(tmpkey);
	return CYRUSDB_IOERROR;
    }

    niov = 0;
    if (offset) {
	WRITEV_ADD_TO_IOVEC(iov, niov, (char *) db->base, offset);
    }

    if (data) {
	/* new entry */
	WRITEV_ADD_TO_IOVEC(iov, niov, (char *) key, keylen);
	WRITEV_ADD_TO_IOVEC(iov, niov, "\t", 1);
	WRITEV_ADD_TO_IOVEC(iov, niov, (char *) data, datalen);
	WRITEV_ADD_TO_IOVEC(iov, niov, "\n", 1);
    }

    if (db->size - (offset + len) > 0) {
	WRITEV_ADD_TO_IOVEC(iov, niov, (char *) db->base + offset + len,
			    db->size - (offset + len));
    }

    /* do the write */
    r = retry_writev(writefd, iov, niov);
    if (r == -1) {
	syslog(LOG_ERR, "IOERROR: writing %s: %m", fnamebuf);
	close(writefd);
	if (mytid) abort_txn(db, *mytid);
        /* xxx return error ? */
    }
    r = 0;

    if (mytid) {
	/* setup so further accesses will be against fname.NEW */
	if (fstat(writefd, &sbuf) == -1) {
            /* xxx ? */
	}

	if (!(*mytid)->fnamenew) (*mytid)->fnamenew = xstrdup(fnamebuf);
	if ((*mytid)->fd) close((*mytid)->fd);
	(*mytid)->fd = writefd;
	map_free(&db->base, &db->len);
	map_refresh(writefd, 0, &db->base, &db->len, sbuf.st_size,
		    fnamebuf, 0);
	db->size = sbuf.st_size;
    } else {
	/* commit immediately */
	if (fsync(writefd) ||
	    fstat(writefd, &sbuf) == -1 ||
	    rename(fnamebuf, db->fname) == -1) {
	    syslog(LOG_ERR, "IOERROR: writing %s: %m", fnamebuf);
	    close(writefd);
	    if (tmpkey) free(tmpkey);
	    return CYRUSDB_IOERROR;
	}

	close(db->fd);
	db->fd = writefd;

	/* release lock */
	r = lock_unlock(db->fd);
	if (r == -1) {
	    syslog(LOG_ERR, "IOERROR: unlocking db %s: %m", db->fname);
	    r = CYRUSDB_IOERROR;
	}

	db->ino = sbuf.st_ino;
	map_free(&db->base, &db->len);
	map_refresh(writefd, 0, &db->base, &db->len, sbuf.st_size,
	    db->fname, 0);
	db->size = sbuf.st_size;
    }

    if(tmpkey) free(tmpkey);
    
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
		  struct txn **mytid, int force __attribute__((unused)))
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
	/* release lock */
	r = lock_unlock(db->fd);
	if (r == -1) {
	    syslog(LOG_ERR, "IOERROR: unlocking db %s: %m", db->fname);
	    r = CYRUSDB_IOERROR;
	}
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
    &myarchive,

    &myopen,
    &myclose,

    &fetch,
    &fetchlock,
    &foreach,
    &create,
    &store,
    &delete,

    &commit_txn,
    &abort_txn,

    NULL,
    NULL
};
