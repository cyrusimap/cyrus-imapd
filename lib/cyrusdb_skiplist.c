/* skip-list.c -- generic skip list routines
 * $Id: cyrusdb_skiplist.c,v 1.6 2002/01/24 18:17:12 leg Exp $
 *
 * Copyright (c) 1998, 2000, 2002 Carnegie Mellon University.
 * All rights reserved.
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
 *	Office of Technology Transfer
 *	Carnegie Mellon University
 *	5000 Forbes Avenue
 *	Pittsburgh, PA  15213-3890
 *	(412) 268-4387, fax: (412) 268-7395
 *	tech-transfer@andrew.cmu.edu
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

/* xxx check retry_xxx for failure */

#include <config.h>

#include <stdlib.h>
#include <limits.h>
#include <assert.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "cyrusdb.h"
#include "xmalloc.h"
#include "map.h"
#include "lock.h"
#include "retry.h"

#define PROB (0.5)

/* 
 *
 * disk format; all numbers in network byte order
 *
 * there's the data file, consisting of the
 * multiple records of "key", "data", and "skip pointers", where skip
 * pointers are the record number of the data pointer.
 *
 * on startup, recovery is performed.  the last known good data file
 * is taken and the intent log is replayed on it.  the index file is
 * regenerated from scratch.
 *
 * during operation ckecpoints will compress the data.  the data file
 * is locked.  then a checkpoint rewrites the data file in order,
 * removing any unused records.  this is written and fsync'd to
 * dfile.NEW and stored for use during recovery.
 */

/* 
   header "skiplist file\0\0\0"
   version (4 bytes)
   maxlevel (4 bytes)
   curlevel (4 bytes)
   listsize (4 bytes)
     in active items
   log start (4 bytes)
     offset where log records start, used mainly to tell when to compress
   last recovery (4 bytes)
     seconds since unix epoch
   
   1 or more skipnodes, one of:

     record type (4 bytes) [DUMMY, INORDER, ADD]
     key size (4 bytes)
     key string (bit string, rounded to up to 4 byte multiples w/ 0s)
     data size (4 bytes)
     data string (bit string, rounded to up to 4 byte multiples w/ 0s)
     skip pointers (4 bytes each)
       least to most
     padding (4 bytes, must be -1)

     record type (4 bytes) [DELETE]
     record ptr (4 bytes; record to be deleted)

     record type (4 bytes) [COMMIT]
     

   record type is either
     DUMMY (first node is of this type)
     INORDER
     ADD
     DELETE
     COMMIT (commit the previous records)
*/

enum {
    INORDER = 1,
    ADD = 2,
    DELETE = 4,
    COMMIT = 255,
    DUMMY = 257
};

struct db {
    /* file data */
    char *fname;
    int fd;

    const char *map_base;
    unsigned long map_len;	/* mapped size */
    unsigned long map_size;	/* actual size */
    long map_ino;

    /* header info */
    int version;
    int version_minor;
    int maxlevel;
    int curlevel;
    int listsize;
    int logstart;		/* where the log starts from last chkpnt */
    time_t last_recovery;

};

struct txn {
    int ismalloc;

    int oldcurlevel;		/* any updates to curlevel necessary? */

    /* logstart is where we start changes from on commit, where we truncate
       to on abort */
    int logstart;
    int logend;			/* where to write to continue this txn */
};

static time_t global_recovery = 0;

static int myinit(const char *dbdir, int myflags)
{
    if (myflags & CYRUSDB_RECOVER) {
	/* xxx set the recovery timestamp; all databases earlier than this
	   time need recovery run when opened */

    } else {
	/* xxx read the global recovery timestamp */

    }
    
    return 0;
}

static int mydone(void)
{
    return 0;
}

static int mysync(void)
{
    return 0;
}

enum {
    SKIPLIST_VERSION = 1,
    SKIPLIST_VERSION_MINOR = 2,
    SKIPLIST_MAXLEVEL = 20,
    SKIPLIST_MINREWRITE = 16834 /* don't rewrite logs smaller than this */
};

#define BIT32_MAX 4294967295U

#if UINT_MAX == BIT32_MAX
typedef unsigned int bit32;
#elif ULONG_MAX == BIT32_MAX
typedef unsigned long bit32;
#elif USHRT_MAX == BIT32_MAX
typedef unsigned short bit32;
#else
#error dont know what to use for bit32
#endif

#define HEADER_MAGIC ("\241\002\213\015skiplist file\0\0\0")
#define HEADER_MAGIC_SIZE (20)

/* offsets of header files */
enum {
    OFFSET_HEADER = 0,
    OFFSET_VERSION = 20,
    OFFSET_VERSION_MINOR = 24,
    OFFSET_MAXLEVEL = 28,
    OFFSET_CURLEVEL = 32,
    OFFSET_LISTSIZE = 36,
    OFFSET_LOGSTART = 40,
    OFFSET_LASTRECOVERY = 44
};

enum {
    HEADER_SIZE = OFFSET_LASTRECOVERY + 4
};

static int mycommit(struct db *db, struct txn *tid);
static int myabort(struct db *db, struct txn *tid);
static int mycheckpoint(struct db *db, int locked);
static int recovery(struct db *db);

/* file looks like:
   struct header {
       ...
   }
   struct dummy {
       bit32 t = htonl(DUMMY);
       bit32 ks = 0;
       bit32 ds = 0;
       bit32 forward[db->maxlevel];
       bit32 pad = -1;
   } */
#define DUMMY_OFFSET(db) (HEADER_SIZE)
#define DUMMY_PTR(db) ((db)->map_base + HEADER_SIZE)
#define DUMMY_SIZE(db) (4 * (3 + db->maxlevel + 1))

/* bump to the next multiple of 4 bytes */
#define ROUNDUP(num) (((num) + 3) & 0xFFFFFFFC)

#define TYPE(ptr) (ntohl(*((bit32 *)(ptr))))
#define KEY(ptr) ((ptr) + 8)
#define KEYLEN(ptr) (ntohl(*((bit32 *)((ptr) + 4))))
#define DATA(ptr) ((ptr) + 8 + ROUNDUP(KEYLEN(ptr)) + 4)
#define DATALEN(ptr) (ntohl(*((bit32 *)((ptr) + 8 + ROUNDUP(KEYLEN(ptr))))))
#define FIRSTPTR(ptr) ((ptr) + 8 + ROUNDUP(KEYLEN(ptr)) + 4 + ROUNDUP(DATALEN(ptr)))

/* return a pointer to the pointer */
#define PTR(ptr, x) (FIRSTPTR(ptr) + 4 * (x))

/* FORWARD(ptr, x)
 * given a pointer to the start of the record, return the offset
 * corresponding to the xth pointer
 */
#define FORWARD(ptr, x) (ntohl(*((bit32 *)(FIRSTPTR(ptr) + 4 * (x)))))

/* how many levels does this record have? */
static int LEVEL(const char *ptr)
{
    const bit32 *p, *q;
    p = q = (bit32 *) FIRSTPTR(ptr);
    while (*p != -1) p++;
    return (p - q);
}

/* how big is this record? */
static int RECSIZE(const char *ptr)
{
    int ret = 0;
    switch (TYPE(ptr)) {
    case DUMMY:
    case INORDER:
    case ADD:
	ret += 4;			/* tag */
	ret += 4;			/* keylen */
	ret += ROUNDUP(KEYLEN(ptr));    /* key */
	ret += 4;			/* datalen */
	ret += ROUNDUP(DATALEN(ptr));   /* data */
	ret += 4 * LEVEL(ptr);	        /* pointers */
	ret += 4;			/* padding */
	break;

    case DELETE:
	ret += 8;
	break;

    case COMMIT:
	ret += 4;
	break;
    }

    return ret;
}

#define PADDING(ptr) (ntohl(*((bit32 *)((ptr) + RECSIZE(ptr) - 4))))

/* given an open, mapped db, read in the header information */
static int read_header(struct db *db)
{
    const char *dptr;
    int r;
    
    assert(db && db->map_len && db->fname);
    if (db->map_len < HEADER_SIZE) {
	syslog(LOG_ERR, 
	       "skiplist: file not large enough for header: %s", db->fname);
    }

    if (memcmp(db->map_base, HEADER_MAGIC, HEADER_MAGIC_SIZE)) {
	syslog(LOG_ERR, "skiplist: invalid magic header: %s", db->fname);
	return CYRUSDB_IOERROR;
    }

    db->version = ntohl(*((bit32 *)(db->map_base + OFFSET_VERSION)));
    db->version_minor = 
	ntohl(*((bit32 *)(db->map_base + OFFSET_VERSION_MINOR)));
    if (db->version != SKIPLIST_VERSION) {
	syslog(LOG_ERR, "skiplist: version mismatch: %s has version %d.%d",
	       db->fname, db->version, db->version_minor);
	return CYRUSDB_IOERROR;
    }

    db->maxlevel = ntohl(*((bit32 *)(db->map_base + OFFSET_MAXLEVEL)));
    db->curlevel = ntohl(*((bit32 *)(db->map_base + OFFSET_CURLEVEL)));
    db->listsize = ntohl(*((bit32 *)(db->map_base + OFFSET_LISTSIZE)));
    db->logstart = ntohl(*((bit32 *)(db->map_base + OFFSET_LOGSTART)));
    db->last_recovery = 
	ntohl(*((bit32 *)(db->map_base + OFFSET_LASTRECOVERY)));

    /* verify dummy node */
    dptr = DUMMY_PTR(db);
    r = 0;

    if (!r && TYPE(dptr) != DUMMY) {
	syslog(LOG_ERR, "DBERROR: %s: first node not type DUMMY",
	       db->fname);
	r = CYRUSDB_IOERROR;
    }
    if (!r && KEYLEN(dptr) != 0) {
	syslog(LOG_ERR, "DBERROR: %s: DUMMY has non-zero KEYLEN",
	       db->fname);
	r = CYRUSDB_IOERROR;
    }
    if (!r && DATALEN(dptr) != 0) {
	syslog(LOG_ERR, "DBERROR: %s: DUMMY has non-zero DATALEN",
	       db->fname);
	r = CYRUSDB_IOERROR;
    }
    if (!r && LEVEL(dptr) != db->maxlevel) {
	syslog(LOG_ERR, "DBERROR: %s: DUMMY level(%d) != db->maxlevel(%d)",
	       db->fname, LEVEL(dptr), db->maxlevel);
	r = CYRUSDB_IOERROR;
    }

    return r;
}

/* given an open, mapped db, locked db,
   write the header information */
static int write_header(struct db *db)
{
    char buf[HEADER_SIZE];
    int n;

    memcpy(buf + 0, HEADER_MAGIC, HEADER_MAGIC_SIZE);
    *((bit32 *)(buf + OFFSET_VERSION)) = htonl(db->version);
    *((bit32 *)(buf + OFFSET_VERSION_MINOR)) = htonl(db->version_minor);
    *((bit32 *)(buf + OFFSET_MAXLEVEL)) = htonl(db->maxlevel);
    *((bit32 *)(buf + OFFSET_CURLEVEL)) = htonl(db->curlevel);
    *((bit32 *)(buf + OFFSET_LISTSIZE)) = htonl(db->listsize);
    *((bit32 *)(buf + OFFSET_LOGSTART)) = htonl(db->logstart);
    *((bit32 *)(buf + OFFSET_LASTRECOVERY)) = htonl(db->last_recovery);

    /* write it out */
    lseek(db->fd, 0, SEEK_SET);
    n = retry_write(db->fd, buf, HEADER_SIZE);
    if (n != HEADER_SIZE) {
	syslog(LOG_ERR, "DBERROR: writing skiplist header for %s: %m",
	       db->fname);
	return CYRUSDB_IOERROR;
    }

    return 0;
}

static int dispose_db(struct db *db)
{
    if (!db) return 0;
    if (db->fname) { 
	free(db->fname);
    }
    if (db->map_base) {
	map_free(&db->map_base, &db->map_len);
    }
    if (db->fd != -1) {
	close(db->fd);
    }

    free(db);

    return 0;
}

static int write_lock(struct db *db)
{
    struct stat sbuf;
    const char *lockfailaction;

    if (lock_reopen(db->fd, db->fname, &sbuf, &lockfailaction) < 0) {
	syslog(LOG_ERR, "IOERROR: %s %s: %m", lockfailaction, db->fname);
	return CYRUSDB_IOERROR;
    }
    db->map_size = sbuf.st_size;
    if (db->map_ino != sbuf.st_ino) {
	map_free(&db->map_base, &db->map_len);
    }
    map_refresh(db->fd, 0, &db->map_base, &db->map_len, sbuf.st_size,
		db->fname, 0);
    
    return 0;
}

static int read_lock(struct db *db)
{
    struct stat sbuf;

    if (lock_shared(db->fd) < 0) {
	syslog(LOG_ERR, "IOERROR: lock_shared %s: %m", db->fname);
	return CYRUSDB_IOERROR;
    }

    if (fstat(db->fd, &sbuf) == -1) {
	syslog(LOG_ERR, "IOERROR: fstat %s: %m", db->fname);
	return CYRUSDB_IOERROR;
    }

    db->map_size = sbuf.st_size;
    if (db->map_ino != sbuf.st_ino) {
	map_free(&db->map_base, &db->map_len);
    }
    
    map_refresh(db->fd, 0, &db->map_base, &db->map_len, sbuf.st_size,
		db->fname, 0);

    return 0;
}

static int unlock(struct db *db)
{
    if (lock_unlock(db->fd) < 0) {
	syslog(LOG_ERR, "IOERROR: lock_unlock %s: %m", db->fname);
	return CYRUSDB_IOERROR;
    }

    return 0;
}

static int myopen(const char *fname, struct db **ret)
{
    struct db *db = (struct db *) xzmalloc(sizeof(struct db));
    int r;
    int new = 0;
    struct stat sbuf;

    db->fd = -1;
    db->fname = xstrdup(fname);

    db->fd = open(fname, O_RDWR, 0666);
    if (db->fd == -1) {
	db->fd = open(fname, O_RDWR | O_CREAT, 0666);
	new = 1;
    }
    if (db->fd == -1) {
	syslog(LOG_ERR, "IOERROR: opening %s: %m", fname);
	dispose_db(db);
	return CYRUSDB_IOERROR;
    }

    if (new) {
	/* lock the db */
	if (write_lock(db) < 0) {
	    dispose_db(db);
	    return CYRUSDB_IOERROR;
	}

	/* initialize in memory structure */
	db->version = SKIPLIST_VERSION;
	db->version_minor = SKIPLIST_VERSION_MINOR;
	db->maxlevel = SKIPLIST_MAXLEVEL;
	db->curlevel = 0;
	db->listsize = 0;
	/* where do we start writing new entries? */
	db->logstart = HEADER_SIZE + DUMMY_SIZE(db);
	db->last_recovery = time(NULL);

	/* create the header */
	r = write_header(db);

	if (!r) {
	    int n;
	    int dsize = DUMMY_SIZE(db);
	    bit32 *buf = (bit32 *) xzmalloc(dsize);

	    buf[0] = htonl(DUMMY);
	    buf[(dsize / 4) - 1] = htonl(-1);

	    lseek(db->fd, HEADER_SIZE, SEEK_SET);
	    n = retry_write(db->fd, (char *) buf, dsize);
	    if (n != dsize) {
		syslog(LOG_ERR, "DBERROR: writing dummy node for %s: %m",
		       db->fname);
		r = CYRUSDB_IOERROR;
	    }
	    free(buf);
	}
	
	/* sync the db */
	if (!r && (fsync(db->fd) < 0)) {
	    syslog(LOG_ERR, "DBERROR: fsync(%s): %m", db->fname);
	    r = CYRUSDB_IOERROR;
	}

	/* unlock the db */
	unlock(db);
    }

    if (fstat(db->fd, &sbuf) == -1) {
	syslog(LOG_ERR, "IOERROR: fstat %s: %m", fname);
	dispose_db(db);
	return CYRUSDB_IOERROR;
    }
    db->map_ino = sbuf.st_ino;
    db->map_size = sbuf.st_size;

    db->map_base = 0;
    db->map_size = 0;
    map_refresh(db->fd, 0, &db->map_base, &db->map_len, sbuf.st_size, 
		fname, 0);

    r = read_header(db);
    if (r) {
	dispose_db(db);
	return r;
    }

    if (db->last_recovery < global_recovery) {
	/* run recovery; we rebooted since the last time recovery
	   was run */
	r = recovery(db);
	if (r) {
	    dispose_db(db);
	    return r;
	}
    }

    *ret = db;
    return 0;
}

int myclose(struct db *db)
{
    return dispose_db(db);
}

static int compare(const char *s1, int l1, const char *s2, int l2)
{
    int min = l1 < l2 ? l1 : l2;
    int cmp = 0;

    while (min-- > 0 && (cmp = *s1 - *s2) == 0) {
	s1++;
	s2++;
    }
    if (min >= 0) {
	return cmp;
    } else {
	if (l1 > l2) return 1;
	else if (l2 > l1) return -1;
	else return 0;
    }
}

/* returns the offset to the node asked for, or the node after it
   if it doesn't exist.
   if previous is set, finds the last node < key */
static const char *find_node(struct db *db, 
			     const char *key, int keylen,
			     int *updateoffsets)
{
    const char *ptr = db->map_base + HEADER_SIZE;
    int i;
    int offset;

    if (updateoffsets) {
	for (i = 0; i < db->maxlevel; i++) {
	    updateoffsets[i] = DUMMY_OFFSET(db);
	}
    }

    for (i = db->curlevel - 1; i >= 0; i--) {
	while ((offset = FORWARD(ptr, i)) && 
	       compare(KEY(db->map_base + offset), KEYLEN(db->map_base + offset), 
		       key, keylen) < 0) {
	    /* move forward at level 'i' */
	    ptr = db->map_base + offset;
	}
	if (updateoffsets) updateoffsets[i] = ptr - db->map_base;
    }

    ptr = db->map_base + FORWARD(ptr, 0);
    
    return ptr;
}

int myfetch(struct db *db,
	    const char *key, int keylen,
	    const char **data, int *datalen,
	    struct txn **mytid)
{
    const char *ptr;
    struct txn t, *tp;
    int r;

    if (!mytid) {
	/* grab a r lock */
	if ((r = read_lock(db)) < 0) {
	    return r;
	}

	tp = NULL;
    } else if (!*mytid) {
	/* grab a r/w lock */
	if ((r = write_lock(db)) < 0) {
	    return r;
	}

	/* fill in t */
	t.ismalloc = 0;
	t.oldcurlevel = db->curlevel;
	t.logstart = lseek(db->fd, 0, SEEK_END);
	assert(t.logstart != -1);
	t.logend = t.logstart;

	tp = &t;
    } else {
	tp = *mytid;
    }

    ptr = find_node(db, key, keylen, 0);

    if (ptr == db->map_base || compare(KEY(ptr), KEYLEN(ptr), key, keylen)) {
	/* failed to find key/keylen */
	*data = NULL;
	*datalen = 0;
    } else {
	*datalen = DATALEN(ptr);
	*data = DATA(ptr);
    }

    if (mytid) {
	if (!*mytid) {
	    /* return the txn structure */

	    *mytid = xmalloc(sizeof(struct txn));
	    memcpy(*mytid, tp, sizeof(struct txn));
	    (*mytid)->ismalloc = 1;
	}
    } else {
	/* release read lock */
	if ((r = unlock(db)) < 0) {
	    return r;
	}
    }

    return 0;
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

int myforeach(struct db *db,
	      char *prefix, int prefixlen,
	      foreach_p *goodp,
	      foreach_cb *cb, void *rock, 
	      struct txn **tid)
{
    const char *ptr;
    struct txn t, *tp;
    int r;

    if (!tid) {
	/* grab a r lock */
	if ((r = read_lock(db)) < 0) {
	    return r;
	}

	tp = NULL;
    } else if (!*tid) {
	/* grab a r/w lock */
	if ((r = write_lock(db)) < 0) {
	    return r;
	}

	/* fill in t */
	t.ismalloc = 0;
	t.oldcurlevel = db->curlevel;
	t.logstart = lseek(db->fd, 0, SEEK_END);
	assert(t.logstart != -1);
	t.logend = t.logstart;

	tp = &t;
    } else {
	tp = *tid;
    }

    ptr = find_node(db, prefix, prefixlen, 0);

    while (ptr != db->map_base) {
	int r;

	/* does it match prefix? */
	if (KEYLEN(ptr) < prefixlen) break;
	if (prefixlen && compare(KEY(ptr), prefixlen, prefix, prefixlen)) break;

	if (goodp(rock, KEY(ptr), KEYLEN(ptr), DATA(ptr), DATALEN(ptr))) {
	    /* xxx need to unlock */

	    /* make callback */
	    r = cb(rock, KEY(ptr), KEYLEN(ptr), DATA(ptr), DATALEN(ptr));
	    if (r) break;

	    /* xxx relock, reposition */
	}
	
	ptr = db->map_base + FORWARD(ptr, 0);
    }

    if (tid) {
	if (!*tid) {
	    /* return the txn structure */

	    *tid = xmalloc(sizeof(struct txn));
	    memcpy(*tid, tp, sizeof(struct txn));
	    (*tid)->ismalloc = 1;
	}
    } else {
	/* release read lock */
	if ((r = unlock(db)) < 0) {
	    return r;
	}
    }

    return 0;
}

int randlvl(struct db *db)
{
    int lvl = 1;
    
    while ((((float) rand() / (float) (RAND_MAX)) < PROB) 
	   && (lvl < db->maxlevel)) {
	lvl++;
    }
    syslog(LOG_DEBUG, "picked level %d", lvl);

    return lvl;
}

int mystore(struct db *db, 
	    const char *key, int keylen,
	    const char *data, int datalen,
	    struct txn **tid, int overwrite)
{
    const char *ptr;
    bit32 klen, dlen;
    struct iovec iov[50];
    int lvl;
    int num_iov;
    struct txn t, *tp;
    bit32 endpadding = htonl(-1);
    bit32 zeropadding[4] = { 0, 0, 0, 0 };
    int updateoffsets[SKIPLIST_MAXLEVEL];
    int newoffsets[SKIPLIST_MAXLEVEL];
    int addrectype = htonl(ADD);
    int delrectype = htonl(DELETE);
    bit32 todelete;
    bit32 newoffset;
    int r, i;

    assert(db != NULL);
    assert(key && keylen);

    if (!tid || !*tid) {
	/* grab a r/w lock */
	if ((r = write_lock(db)) < 0) {
	    return r;
	}

	/* fill in t */
	t.ismalloc = 0;
	t.oldcurlevel = db->curlevel;
	t.logstart = lseek(db->fd, 0, SEEK_END);
	assert(t.logstart != -1);
	t.logend = t.logstart;

	tp = &t;
    } else {
	tp = *tid;
    }

    num_iov = 0;
    
    newoffset = tp->logend;
    ptr = find_node(db, key, keylen, updateoffsets);
    if (ptr != db->map_base && 
	!compare(KEY(ptr), KEYLEN(ptr), key, keylen)) {
	    
	if (!overwrite) {
	    myabort(db, tp);	/* releases lock */
	    return CYRUSDB_EXISTS;
	} else {
	    /* replace with an equal height node */
	    lvl = LEVEL(ptr);

	    /* log a removal */
	    WRITEV_ADD_TO_IOVEC(iov, num_iov, (char *) &delrectype, 4);
	    todelete = htonl(ptr - db->map_base);
	    WRITEV_ADD_TO_IOVEC(iov, num_iov, (char *) &todelete, 4);
	    
	    /* now we write at newoffset */
	    newoffset += 8;

	    /* our pointers are whatever the old node pointed to */
	    for (i = 0; i < lvl; i++) {
		newoffsets[i] = htonl(FORWARD(ptr, i));
	    }
	}
    } else {
	/* pick a size for the new node */
	lvl = randlvl(db);

	/* do we need to update the header ? */
	if (lvl > tp->oldcurlevel) {
	    for (i = db->curlevel; i < lvl; i++) {
		updateoffsets[i] = DUMMY_OFFSET(db);
	    }
	    db->curlevel = lvl;
	    
	    /* write out that change */
	    write_header(db); /* xxx errors? */
	}

	/* we point to what we're updating used to point to */
	/* newoffsets is written in the iovec later */
	for (i = 0; i < lvl; i++) {
	    /* written in the iovec */
	    newoffsets[i] = 
		htonl(FORWARD(db->map_base + updateoffsets[i], i));
	}
    }

    klen = htonl(keylen);
    dlen = htonl(datalen);
    
    newoffset = htonl(newoffset);

    /* set pointers appropriately */
    for (i = 0; i < lvl; i++) {
	/* write pointer updates */
	/* FORWARD(updates[i], i) = newoffset; */
	lseek(db->fd, 
	      PTR(db->map_base + updateoffsets[i], i) - db->map_base,
	      SEEK_SET);
	retry_write(db->fd, (char *) &newoffset, 4);
    }

    WRITEV_ADD_TO_IOVEC(iov, num_iov, (char *) &addrectype, 4);
    WRITEV_ADD_TO_IOVEC(iov, num_iov, (char *) &klen, 4);
    WRITEV_ADD_TO_IOVEC(iov, num_iov, (char *) key, keylen);
    if (ROUNDUP(keylen) - keylen > 0) {
	WRITEV_ADD_TO_IOVEC(iov, num_iov, (char *) zeropadding,
			    ROUNDUP(keylen) - keylen);
    }
    WRITEV_ADD_TO_IOVEC(iov, num_iov, (char *) &dlen, 4);
    WRITEV_ADD_TO_IOVEC(iov, num_iov, (char *) data, datalen);
    if (ROUNDUP(datalen) - datalen > 0) {
	WRITEV_ADD_TO_IOVEC(iov, num_iov, (char *) zeropadding,
			    ROUNDUP(datalen) - datalen);
    }
    WRITEV_ADD_TO_IOVEC(iov, num_iov, (char *) newoffsets, 4 * lvl);
    WRITEV_ADD_TO_IOVEC(iov, num_iov, (char *) &endpadding, 4);

    lseek(db->fd, tp->logend, SEEK_SET);
    r = retry_writev(db->fd, iov, num_iov);
    if (r < 0) {
	syslog(LOG_ERR, "DBERROR: retry_writev(): %m");
	myabort(db, tp);
	return CYRUSDB_IOERROR;
    }
    tp->logend += r;		/* update where to write next */

    if (tid) {
	if (!*tid) {
	    /* return the txn structure */

	    *tid = xmalloc(sizeof(struct txn));
	    memcpy(*tid, tp, sizeof(struct txn));
	    (*tid)->ismalloc = 1;
	}
    } else {
	/* commit the store, which releases the write lock */
	mycommit(db, tp);
    }
    
    return 0;
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

int mydelete(struct db *db, 
	     const char *key, int keylen,
	     struct txn **tid)
{
    const char *ptr;
    int delrectype = htonl(DELETE);
    int updateoffsets[SKIPLIST_MAXLEVEL];
    int offset;
    bit32 writebuf[2];
    struct txn t, *tp;
    int i;
    int r;

    if (!tid || !*tid) {
	/* grab a r/w lock */
	if ((r = write_lock(db)) < 0) {
	    return r;
	}

	/* fill in t */
	t.ismalloc = 0;
	t.oldcurlevel = db->curlevel;
	t.logstart = lseek(db->fd, 0, SEEK_END);
	assert(t.logstart != -1);
	t.logend = t.logstart;

	tp = &t;
    } else {
	tp = *tid;
    }

    ptr = find_node(db, key, keylen, updateoffsets);
    if (ptr == db->map_base ||
	!compare(KEY(ptr), KEYLEN(ptr), key, keylen)) {
	/* gotcha */
	offset = ptr - db->map_base;

	/* update pointers */
	for (i = 0; i < db->curlevel; i++) {
	    int newoffset;

	    if (FORWARD(db->map_base + updateoffsets[i], i) != offset) {
		break;
	    }
	    newoffset = htonl(FORWARD(ptr, i));
	    lseek(db->fd, 
		  PTR(db->map_base + updateoffsets[i], i) - db->map_base, 
		  SEEK_SET);
	    retry_write(db->fd, (char *) &newoffset, 4);
	}

	/* log the deletion */
	lseek(db->fd, tp->logend, SEEK_SET);
	writebuf[0] = delrectype;
	writebuf[1] = htonl(offset);

	/* update end-of-log */
	tp->logend += retry_write(db->fd, (char *) writebuf, 8);
    }

    if (tid) {
	if (!*tid) {
	    /* return the txn structure */

	    *tid = xmalloc(sizeof(struct txn));
	    memcpy(*tid, tp, sizeof(struct txn));
	    (*tid)->ismalloc = 1;
	}
    } else {
	/* commit the store, which releases the write lock */
	mycommit(db, tp);
    }

    return 0;
}

int mycommit(struct db *db, struct txn *tid)
{
    bit32 commitrectype = htonl(COMMIT);
    int r;

    assert(db && tid);

    /* fsync */
    if (fsync(db->fd) < 0) {
	syslog(LOG_ERR, "IOERROR: writing %s: %m", db->fname);
	return CYRUSDB_IOERROR;
    }

    /* write a commit record */
    lseek(db->fd, tid->logend, SEEK_SET);
    retry_write(db->fd, (char *) &commitrectype, 4);

    /* fsync */
    if (fsync(db->fd) < 0) {
	syslog(LOG_ERR, "IOERROR: writing %s: %m", db->fname);
	return CYRUSDB_IOERROR;
    }

    /* consider checkpointing */
    if (tid->logend > (2 * db->logstart + SKIPLIST_MINREWRITE)) {
	r = mycheckpoint(db, 1);
    }

    /* release the write lock */
    if ((r = unlock(db)) < 0) {
	return r;
    }
    
    /* free tid if needed */
    if (tid->ismalloc) {
	free(tid);
    }

    return 0;
}

int myabort(struct db *db, struct txn *tid) /* xxx */
{
    assert(db && tid);
    
    /* look at the log entries we've written, and undo their effects */

    /* truncate the file to remove log entries */

    /* release the write lock */

    /* free the tid */

    return 0;
}

/* compress 'db'. if 'locked != 0', the database is already R/W locked and
   will be returned as such. */
static int mycheckpoint(struct db *db, int locked)
{
    char fname[1024];
    int oldfd;
    struct iovec iov[50];
    int num_iov;
    int updateoffsets[SKIPLIST_MAXLEVEL];
    const char *ptr;
    int offset;
    int r = 0;
    int iorectype = htonl(INORDER);
    int i;
    time_t start = time(NULL);

    /* grab write lock (could be read but this prevents multiple checkpoints
     simultaneously) */
    if (!locked && (r = write_lock(db)) < 0) {
	return r;
    }

    /* open fname.NEW */
    snprintf(fname, sizeof(fname), "%s.NEW", db->fname);
    oldfd = db->fd;
    db->fd = open(fname, O_RDWR | O_CREAT, 0666);
    if (db->fd < 0) {
	syslog(LOG_ERR, "DBERROR: skiplist checkpoint: open(%s): %m", fname);
	if (!locked) unlock(db);
	db->fd = oldfd;
	return CYRUSDB_IOERROR;
    }

    /* write dummy record */
    if (!r) {
	int dsize = DUMMY_SIZE(db);
	bit32 *buf = (bit32 *) xzmalloc(dsize);

	buf[0] = htonl(DUMMY);
	buf[(dsize / 4) - 1] = htonl(-1);

	lseek(db->fd, HEADER_SIZE, SEEK_SET);
	r = retry_write(db->fd, (char *) buf, dsize);
	if (r != dsize) {
	    r = CYRUSDB_IOERROR;
	} else {
	    r = 0;
	}
	free(buf);
	
	/* initialize the updateoffsets array so when we append records
	   we know where to set the pointers */
	for (i = 0; i < db->maxlevel; i++) {
	    /* header_size + 4 (rectype) + 4 (ksize) + 4 (dsize)
	       + 4 * i */
	    updateoffsets[i] = HEADER_SIZE + 12 + 4 * i;
	}
    }

    /* write records to new file */
    offset = FORWARD(db->map_base + DUMMY_OFFSET(db), 0);
    db->listsize = 0;
    while (!r && offset != 0) {
	int lvl;
	bit32 newoffset, newoffsetnet;

	ptr = db->map_base + offset;
	lvl = LEVEL(ptr);
	db->listsize++;

	num_iov = 0;
	WRITEV_ADD_TO_IOVEC(iov, num_iov, (char *) &iorectype, 4);
	/* copy all but the rectype from the record */
	WRITEV_ADD_TO_IOVEC(iov, num_iov, (char *) ptr + 4, RECSIZE(ptr) - 4);

	newoffset = lseek(db->fd, 0, SEEK_END);
	newoffsetnet = htonl(newoffset);
	r = retry_writev(db->fd, iov, num_iov);
	if (r < 0) {
	    r = CYRUSDB_IOERROR;
	} else {
	    r = 0;
	}
	for (i = 0; !r && i < lvl; i++) {
	    /* update pointers */
	    r = lseek(db->fd, updateoffsets[i], SEEK_SET);
	    if (r < 0) {
		r = CYRUSDB_IOERROR;
		break;
	    } else {
		r = 0;
	    }
		    
	    r = retry_write(db->fd, (char *) &newoffsetnet, 4);
	    if (r < 0) {
		r = CYRUSDB_IOERROR;
		break;
	    } else {
		r = 0;
	    }

	    /* PTR(ptr, i) - ptr is the offset relative to me
	       to my ith pointer */
	    updateoffsets[i] = newoffset + (PTR(ptr, i) - ptr);
	}

	offset = FORWARD(ptr, 0);
    }

    /* set any dangling pointers to zero */
    for (i = 0; !r && i < db->maxlevel; i++) {
	bit32 newoffset = htonl(0);

	r = lseek(db->fd, updateoffsets[i], SEEK_SET);
	if (r < 0) {
	    r = CYRUSDB_IOERROR;
	    break;
	} else {
	    r = 0;
	}

	r = retry_write(db->fd, (char *) &newoffset, 4);
	if (r < 0) {
	    r = CYRUSDB_IOERROR;
	    break;
	} else {
	    r = 0;
	}
    }

    /* create the header */
    db->logstart = lseek(db->fd, 0, SEEK_END);
    r = write_header(db);

    /* sync new file */
    if (!r && (fsync(db->fd) < 0)) {
	syslog(LOG_ERR, "DBERROR: skiplist checkpoint: fsync(%s): %m", fname);
	r = CYRUSDB_IOERROR;
    }
    
    if (!r) {
	/* get new lock */
	r = write_lock(db);
    }

    /* move new file to original file name */
    if (!r && (rename(fname, db->fname) < 0)) {
	syslog(LOG_ERR, "DBERROR: skiplist checkpoint: rename(%s, %s): %m", 
	       fname, db->fname);
	r = CYRUSDB_IOERROR;
    }

    if (r) {
	/* clean up */
	close(db->fd);
	db->fd = oldfd;
	unlink(fname);
    }

    /* release old write lock */
    close(oldfd);

    if (!locked) {
	/* unlock the new db files */
	unlock(db);
    }

    {
	int diff = time(NULL) - start;
	syslog(LOG_INFO, 
	       "skiplist: checkpointed %s (%d records, %d bytes) in %d second%s",
	       db->fname, db->listsize, db->logstart, 
	       diff, diff == 1 ? "" : "s"); 
    }

    return r;
}

/* dump the database.
   if detail == 1, dump all records.
   if detail == 2, also dump pointers for active records.
   if detail == 3, dump all records/all pointers.
*/
static int mydbdump(struct db *db, int detail) /* xxx */
{

    return 0;
}

/* perform some basic consistency checks */
static int consistent(struct db *db) /* xxx */
{

    return 0;
}

/* run recovery on this file */
static int recovery(struct db *db)
{
    const char *ptr, *keyptr;
    int updateoffsets[SKIPLIST_MAXLEVEL];
    int offset, offsetnet, myoff = 0;
    int r = 0;
    time_t start = time(NULL);
    int i;

    if ((r = write_lock(db)) < 0) {
	return r;
    }

    if (db->last_recovery >= global_recovery) {
	/* someone beat us to it */
	unlock(db);
	return 0;
    }
    db->listsize = 0;

    ptr = DUMMY_PTR(db);
    r = 0;

    /* verify this is DUMMY */
    if (!r && TYPE(ptr) != DUMMY) {
	r = CYRUSDB_IOERROR;
	syslog(LOG_ERR, "DBERROR: skiplist recovery %s: no dummy node?",
	       db->fname);
    }

    /* zero key */
    if (!r && KEYLEN(ptr) != 0) {
	r = CYRUSDB_IOERROR;
	syslog(LOG_ERR, 
	       "DBERROR: skiplist recovery %s: dummy node KEYLEN != 0",
	       db->fname);
    }

    /* zero data */
    if (!r && DATALEN(ptr) != 0) {
	r = CYRUSDB_IOERROR;
	syslog(LOG_ERR, 
	       "DBERROR: skiplist recovery %s: dummy node DATALEN != 0",
	       db->fname);
    }

    /* pointers for db->maxlevel */
    if (!r && LEVEL(ptr) != db->maxlevel) {
	r = CYRUSDB_IOERROR;
	syslog(LOG_ERR, 
	       "DBERROR: skiplist recovery %s: dummy node level: %d != %d",
	       db->fname, LEVEL(ptr), db->maxlevel);
    }
    
    for (i = 0; i < db->maxlevel; i++) {
	/* header_size + 4 (rectype) + 4 (ksize) + 4 (dsize)
	   + 4 * i */
	updateoffsets[i] = HEADER_SIZE + 12 + 4 * i;
    }
    
    if (!r) ptr += RECSIZE(ptr);

    /* reset the data that was written INORDER by the last checkpoint */
    offset = db->logstart;
    while (!r && (offset < db->logstart)) {
	ptr = db->map_base + offset;
	offsetnet = htonl(offset);

	db->listsize++;

	/* make sure this is INORDER */
	if (TYPE(ptr) != INORDER) {
	    syslog(LOG_ERR, "DBERROR: skiplist recovery: %d should be INORDER",
		   offset);
	    r = CYRUSDB_IOERROR;
	    continue;
	}
	    
	/* xxx check \0 fill on key */

	/* xxx check \0 fill on data */
	    
	/* update previous pointers, record these for updating */
	for (i = 0; !r && i < LEVEL(ptr); i++) {
	    r = lseek(db->fd, updateoffsets[i], SEEK_SET);
	    if (r < 0) {
		syslog(LOG_ERR, "DBERROR: lseek %s: %m", db->fname);
		r = CYRUSDB_IOERROR;
		break;
	    } else {
		r = 0;
	    }

	    r = retry_write(db->fd, (char *) &offsetnet, 4);
	    if (r < 0) {
		r = CYRUSDB_IOERROR;
		break;
	    } else {
		r = 0;
	    }

	    /* PTR(ptr, i) - ptr is the offset relative to me
	       to my ith pointer */
	    updateoffsets[i] = offset + (PTR(ptr, i) - ptr);
	}

	/* check padding */
	if (!r && PADDING(ptr) != -1) {
	    syslog(LOG_ERR, "DBERROR: %s: offset %d padding not -1",
		   db->fname, offset);
	    r = CYRUSDB_IOERROR;
	}

	if (!r) {
	    offset += RECSIZE(ptr);
	}
    }

    /* zero out the remaining pointers */
    if (!r) {
	for (i = 0; !r && i < db->maxlevel; i++) {
	    int zerooffset = 0;

	    r = lseek(db->fd, updateoffsets[i], SEEK_SET);
	    if (r < 0) {
		syslog(LOG_ERR, "DBERROR: lseek %s: %m", db->fname);
		r = CYRUSDB_IOERROR;
		break;
	    } else {
		r = 0;
	    }

	    r = retry_write(db->fd, (char *) &zerooffset, 4);
	    if (r < 0) {
		r = CYRUSDB_IOERROR;
		break;
	    } else {
		r = 0;
	    }
	}
    }

    /* replay the log */
    while (!r && offset < db->map_size) {
	const char *p, *q;

	/* refresh map, so we see the writes we've just done */
	map_refresh(db->fd, 0, &db->map_base, &db->map_len, db->map_size,
		    db->fname, 0);

	ptr = db->map_base + offset;
	offsetnet = htonl(offset);

	/* if this is a commit, we've processed everything in this txn */
	if (TYPE(ptr) == COMMIT) {
	    offset += RECSIZE(ptr);
	    continue;
	}

	/* make sure this is ADD or DELETE */
	if (TYPE(ptr) != ADD && TYPE(ptr) != DELETE) {
	    syslog(LOG_ERR, 
		   "DBERROR: skiplist recovery: %d should be ADD or DELETE",
		   offset);
	    r = CYRUSDB_IOERROR;
	    break;
	}

	/* look ahead for a commit */
	q = db->map_base + db->map_size;
	p = ptr;
	for (;;) {
	    p += RECSIZE(p);
	    if (p >= q) break;
	    if (TYPE(ptr) == COMMIT) break;
	}
	if (p >= q) {
	    /* no commit, we should truncate */
	    if (ftruncate(db->fd, offset) < 0) {
		syslog(LOG_ERR, 
		       "DBERROR: skiplist recovery %s: ftruncate: %m",
		       db->fname);
		r = CYRUSDB_IOERROR;
	    }
	    break;
	}

	keyptr = NULL;
	/* look for the key */
	if (TYPE(ptr) == ADD) {
	    keyptr = find_node(db, KEY(ptr), KEYLEN(ptr), updateoffsets);
	    if (!compare(KEY(ptr), KEYLEN(ptr), KEY(keyptr), KEYLEN(keyptr))) {
		keyptr = NULL;
	    }
	} else {
	    const char *p;

	    myoff = ntohl(*((bit32 *)(ptr + 4)));
	    p = db->map_base + myoff;
	    keyptr = find_node(db, KEY(p), KEYLEN(p), updateoffsets);
	}

	/* if DELETE & found key, skip over it */
	if (TYPE(ptr) == DELETE && keyptr) {
	    db->listsize--;

	    for (i = 0; i < db->curlevel; i++) {
		int newoffset;

		if (FORWARD(db->map_base + updateoffsets[i], i) != myoff) {
		    break;
		}
		newoffset = htonl(FORWARD(db->map_base + myoff, i));
		lseek(db->fd,
		      PTR(db->map_base + updateoffsets[i], i) - db->map_base,
		      SEEK_SET);
		retry_write(db->fd, (char *) &newoffset, 4);
	    }

	/* otherwise if DELETE, throw an error */
	} else if (TYPE(ptr)) {
	    syslog(LOG_ERR, 
		   "DBERROR: skiplist recovery %s: DELETE at %d doesn't exist",
		   db->fname, offset);
	    r = CYRUSDB_IOERROR;

	/* otherwise if ADD & found key, throw an error */
	} else if (TYPE(ptr) && keyptr) {
	    syslog(LOG_ERR, 
		   "DBERROR: skiplist recovery %s: ADD at %d exists", 
		   db->fname, offset);
	    r = CYRUSDB_IOERROR;

	/* otherwise insert it */
	} else {
	    int lvl;
	    bit32 newoffsets[SKIPLIST_MAXLEVEL];

	    db->listsize++;
	    offsetnet = htonl(offset);

	    lvl = LEVEL(ptr);
	    for (i = 0; i < lvl; i++) {
		/* set our next pointers */
		newoffsets[i] = 
		    htonl(FORWARD(db->map_base + updateoffsets[i], i));

		/* replace 'updateptrs' to point to me */
		lseek(db->fd, updateoffsets[i], SEEK_SET);
		retry_write(db->fd, (char *) &offsetnet, 4);
	    }
	    /* write out newoffsets */
	    lseek(db->fd, FIRSTPTR(ptr) - db->map_base, SEEK_SET);
	    retry_write(db->fd, (char *) newoffsets, 4 * lvl);
	}
    }

    /* fsync the recovered database */
    if (!r && fsync(db->fd) < 0) {
	
	r = CYRUSDB_IOERROR;
    }

    /* set the last recovery timestamp */
    if (!r) {
	db->last_recovery = time(NULL);
	write_header(db);
    }

    /* fsync the new header */
    if (!r && fsync(db->fd) < 0) {
	
	r = CYRUSDB_IOERROR;
    }

    if (!r) {
	int diff = time(NULL) - start;

	syslog(LOG_INFO, 
	       "skiplist: recovered %s (%d records, %d bytes) in %d second%s",
	       db->fname, db->listsize, db->map_size, 
	       diff, diff == 1 ? "" : "s"); 
    }

    unlock(db);
    
    return r;
}

struct cyrusdb_backend cyrusdb_skiplist = 
{
    "skiplist",			/* name */

    &myinit,
    &mydone,
    &mysync,

    &myopen,
    &myclose,

    &fetch,
    &fetchlock,
    &myforeach,
    &create,
    &store,
    &mydelete,

    &mycommit,
    &myabort
};
