/*  cyrusdb_flat: a sorted flat textfile backend
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
 * $Id: cyrusdb_flat.c,v 1.40 2010/01/06 17:01:45 murch Exp $
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
#include "cyr_lock.h"
#include "retry.h"
#include "util.h"
#include "xmalloc.h"
#include "xstrlcpy.h"
#include "xstrlcat.h"

/* we have the file locked iff we have an outstanding transaction */

struct db {
    char *fname;
    struct db *next;
    int refcount;

    int fd;			/* current file open */
    ino_t ino;

    const char *base;		/* contents of file */
    unsigned long size;		/* actual size */
    unsigned long len;		/* mapped size */

    struct buf data;		/* returned storage for fetch */
};
#define DATA(db)	((db)->data.s ? (db)->data.s : "")
#define DATALEN(db)	((db)->data.len)

struct txn {
    char *fnamenew;
    int fd;
};

static struct db *alldbs;

/*
 * We choose an escape character which is an invalid UTF-8 encoding and
 * thus unlikely to appear in the key or data unless they are completely
 * non-textual.
 */
#define ESCAPE	    0xff

static void encode(const char *ps, int len, struct buf *buf)
{
    const unsigned char *p = (const unsigned char *)ps;

    buf_reset(buf);
    /* allocate enough space plus a little slop to cover
     * escaping a few characters */
    buf_ensure(buf, len+10);

    for ( ; len > 0 ; len--, p++) {
	switch (*p) {
	case '\0':
	case '\t':
	case '\r':
	case '\n':
	    buf_putc(buf, ESCAPE);
	    buf_putc(buf, 0x80|(*p));
	    break;
	case ESCAPE:
	    buf_putc(buf, ESCAPE);
	    buf_putc(buf, ESCAPE);
	    break;
	default:
	    buf_putc(buf, *p);
	    break;
	}
    }

    /* ensure the buf is NUL-terminated; we pass the buf's data to
     * bsearch_mem(), which expects a C string, several times */
    buf_cstring(buf);
}

static void decode(const char *ps, int len, struct buf *buf)
{
    const unsigned char *p = (const unsigned char *)ps;

    buf_reset(buf);
    /* allocate enough space; we don't need slop because
     * decoding can only shrink the result */
    buf_ensure(buf, len);

    for ( ; len > 0 ; len--, p++) {
	if (*p == ESCAPE) {
	    if (len < 2) {
		/* invalid encoding, silently ignore */
		continue;
	    }
	    len--;
	    p++;
	    if (*p == ESCAPE)
		buf_putc(buf, ESCAPE);
	    else
		buf_putc(buf, (*p) & ~0x80);
	}
	else
	    buf_putc(buf, *p);
    }
    /* Note: buf is not NUL-terminated.  It happens that neither
     * skiplist nor berkeley backends guarantee any such thing,
     * and so code that depends on it is quite broken anyway */
}

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
	free(db->fname);
	buf_free(&db->data);
	free(db);
    }
}

static struct db *find_db(const char *fname)
{
    struct db *db;

    for (db = alldbs ; db ; db = db->next) {
	if (!strcmp(fname, db->fname)) {
	    db->refcount++;
	    return db;
	}
    }
    return NULL;
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
    int r, d_length, d_remain;
    const char **fname;
    char dstname[1024], *dp;

    strlcpy(dstname, dirname, sizeof(dstname));
    d_length = strlen(dstname);
    dp = dstname + d_length;
    d_remain = sizeof(dstname)-d_length;

    /* archive those files specified by the app */
    for (fname = fnames; *fname != NULL; ++fname) {
	syslog(LOG_DEBUG, "archiving database file: %s", *fname);
	strlcpy(dp, strrchr(*fname, '/'), d_remain);
	r = cyrusdb_copyfile(*fname, dstname);
	if (r) {
	    syslog(LOG_ERR,
		   "DBERROR: error archiving database file: %s", *fname);
	    return CYRUSDB_IOERROR;
	}
    }

    return 0;
}

static int myopen(const char *fname, int flags, struct db **ret)
{
    struct db *db;
    struct stat sbuf;

    assert(fname && ret);

    db = find_db(fname);
    if (db)
	goto out;   /* new reference to existing db */

    db = (struct db *) xzmalloc(sizeof(struct db));

    db->fd = open(fname, O_RDWR, 0644);
    if (db->fd == -1 && errno == ENOENT && (flags & CYRUSDB_CREATE)) {
	if (cyrus_mkdir(fname, 0755) == -1) return CYRUSDB_IOERROR;

	db->fd = open(fname, O_RDWR | O_CREAT, 0644);
    }

    if (db->fd == -1) {
	int level = (flags & CYRUSDB_CREATE) ? LOG_ERR : LOG_DEBUG;
	syslog(level, "IOERROR: opening %s: %m", fname);
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
    db->refcount = 1;

    /* prepend to the list */
    db->next = alldbs;
    alldbs = db;

out:
    *ret = db;
    return 0;
}

static int myclose(struct db *db)
{
    struct db **prevp;

    assert(db);
    if (--db->refcount > 0)
	return 0;
    /* now we are dropping the last reference */

    /* detach from the list of all dbs */
    for (prevp = &alldbs ;
	 *prevp && *prevp != db ;
	 prevp = &(*prevp)->next)
	;
    assert(*prevp == db); /* this struct must be in the list */
    *prevp = db->next;

    /* clean up the internals */
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
	    syslog(LOG_ERR, "IOERROR: stating flat %s: %m", db->fname);
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
		syslog(LOG_ERR, "IOERROR: stating flat %s: %m", db->fname);
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
		   const char *key, size_t keylen,
		   const char **data, size_t *datalen,
		   struct txn **mytid)
{
    int r = 0;
    int offset;
    unsigned long len;
    struct buf keybuf = BUF_INITIALIZER;

    assert(db);

    if (data) *data = NULL;
    if (datalen) *datalen = 0;

    r = starttxn_or_refetch(db, mytid);
    if (r) return r;

    encode(key, keylen, &keybuf);

    offset = bsearch_mem(keybuf.s, db->base, db->size, 0, &len);
    if (len) {
	if (data) {
	    decode(db->base + offset + keybuf.len + 1,
		   /* subtract one for \t, and one for the \n */
		   len - keybuf.len - 2,
		   &db->data);
	    if (data) *data = DATA(db);
	    if (datalen) *datalen = DATALEN(db);
	}
    } else {
	r = CYRUSDB_NOTFOUND;
    }

    buf_free(&keybuf);
    return r;
}

static int fetch(struct db *mydb, 
		 const char *key, size_t keylen,
		 const char **data, size_t *datalen,
		 struct txn **mytid)
{
    return myfetch(mydb, key, keylen, data, datalen, mytid);
}

static int fetchlock(struct db *db, 
		     const char *key, size_t keylen,
		     const char **data, size_t *datalen,
		     struct txn **mytid)
{
    return myfetch(db, key, keylen, data, datalen, mytid);
}

static int getentry(struct db *db, const char *p,
		    struct buf *keybuf, const char **dataendp)
{
    const char *key;
    int keylen;
    const char *data;
    const char *dataend;
    int datalen;

    key = p;
    data = strchr(p, '\t');
    if (!data) {
	/* huh, might be corrupted? */
	return CYRUSDB_IOERROR;
    }
    keylen = data - key;
    data++; /* skip the \t */
    dataend = strchr(data, '\n');
    if (!dataend) {
	/* huh, might be corrupted? */
	return CYRUSDB_IOERROR;
    }
    datalen = dataend - data;

    decode(data, datalen, &db->data);
    decode(key, keylen, keybuf);
    *dataendp = dataend;

    return 0;
}

#define GETENTRY(p)				\
    r = getentry(db, p, &keybuf, &dataend);	\
    if (r) break;

static int foreach(struct db *db,
		   const char *prefix, size_t prefixlen,
		   foreach_p *goodp,
		   foreach_cb *cb, void *rock, 
		   struct txn **mytid)
{
    int r = CYRUSDB_OK;
    int offset;
    unsigned long len;
    const char *p, *pend;
    const char *dataend;

    /* for use inside the loop, but we need the values to be retained
     * from loop to loop */
    struct buf keybuf = BUF_INITIALIZER;
    int dontmove = 0;

    /* For when we have a transaction running */
    struct buf savebuf = BUF_INITIALIZER;

    /* for the local iteration so that the db can change out from under us */
    const char *dbbase = NULL;
    unsigned long dblen = 0;
    int dbfd = -1;

    struct buf prefixbuf = BUF_INITIALIZER;

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
	encode(prefix, prefixlen, &prefixbuf);
	offset = bsearch_mem(prefixbuf.s, dbbase, db->size, 0, &len);
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
	if (keybuf.len < (size_t) prefixbuf.len) break;
	if (prefixbuf.len && memcmp(keybuf.s, prefixbuf.s, prefixbuf.len)) break;

	if (!goodp || goodp(rock, keybuf.s, keybuf.len, DATA(db), DATALEN(db))) {
	    unsigned long ino = db->ino;
 	    unsigned long sz = db->size;

	    if(mytid) {
		/* transaction present, this means we do the slow way */
		buf_copy(&savebuf, &keybuf);
	    }

	    /* make callback */
	    r = cb(rock, keybuf.s, keybuf.len, DATA(db), DATALEN(db));
	    if (r) break;

	    if(mytid) {
		/* reposition? (we made a change) */
		if (!(ino == db->ino && sz == db->size)) {
		    /* something changed in the file; reseek */
		    buf_cstring(&savebuf);
		    offset = bsearch_mem(savebuf.s, db->base, db->size,
					 0, &len);
		    p = db->base + offset;
		    
		    GETENTRY(p);
		    
		    /* 'key' might not equal 'savebuf'.  if it's different,
		       we want to stay where we are.  if it's the same, we
		       should move on to the next one */
		    if (!buf_cmp(&savebuf, &keybuf)) {
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
    }

    buf_free(&savebuf);
    buf_free(&keybuf);
    buf_free(&prefixbuf);
    return r;
}

#undef GETENTRY

static int mystore(struct db *db, 
		   const char *key, size_t keylen,
		   const char *data, size_t datalen,
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
    struct buf keybuf = BUF_INITIALIZER;
    struct buf databuf = BUF_INITIALIZER;

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

    encode(key, keylen, &keybuf);

    /* find entry, if it exists */
    offset = bsearch_mem(keybuf.s, db->base, db->size, 0, &len);

    /* overwrite? */
    if (len && !overwrite) {
	if (mytid) abort_txn(db, *mytid);
	buf_free(&keybuf);
	buf_free(&databuf);
	return CYRUSDB_EXISTS;
    }

    /* write new file */
    if (mytid && (*mytid)->fnamenew) {
	strlcpy(fnamebuf, (*mytid)->fnamenew, sizeof(fnamebuf));
    } else {
	strlcpy(fnamebuf, db->fname, sizeof(fnamebuf));
	strlcat(fnamebuf, ".NEW", sizeof(fnamebuf));
    }

    unlink(fnamebuf);
    r = writefd = open(fnamebuf, O_RDWR | O_CREAT, 0666);
    if (r < 0) {
        syslog(LOG_ERR, "opening %s for writing failed: %m", fnamebuf);
	if (mytid) abort_txn(db, *mytid);
	buf_free(&keybuf);
	buf_free(&databuf);
	return CYRUSDB_IOERROR;
    }

    niov = 0;
    if (offset) {
	WRITEV_ADD_TO_IOVEC(iov, niov, (char *) db->base, offset);
    }

    if (data) {
	/* new entry */
	encode(data, datalen, &databuf);
	WRITEV_ADD_TO_IOVEC(iov, niov, keybuf.s, keybuf.len);
	WRITEV_ADD_TO_IOVEC(iov, niov, "\t", 1);
	WRITEV_ADD_TO_IOVEC(iov, niov, databuf.s, databuf.len);
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
	buf_free(&keybuf);
	buf_free(&databuf);
        return CYRUSDB_IOERROR;
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
	    buf_free(&keybuf);
	    buf_free(&databuf);
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

    buf_free(&keybuf);
    buf_free(&databuf);

    return r;
}

static int create(struct db *db, 
		  const char *key, size_t keylen,
		  const char *data, size_t datalen,
		  struct txn **tid)
{
    if (!data) {
	data = "";
	datalen = 0;
    }
    return mystore(db, key, keylen, data, datalen, tid, 0);
}

static int store(struct db *db, 
		 const char *key, size_t keylen,
		 const char *data, size_t datalen,
		 struct txn **tid)
{
    if (!data) {
	data = "";
	datalen = 0;
    }
    return mystore(db, key, keylen, data, datalen, tid, 1);
}

static int delete(struct db *db, 
		  const char *key, size_t keylen,
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
