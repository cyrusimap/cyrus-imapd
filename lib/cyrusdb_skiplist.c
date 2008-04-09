/* cyrusdb_skiplist.c -- cyrusdb skiplist implementation
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
 * $Id: cyrusdb_skiplist.c,v 1.61 2008/04/09 17:56:57 murch Exp $
 */

/* xxx check retry_xxx for failure */

/* xxx all offsets should be bit32s i think */

#include <config.h>

#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <netinet/in.h>

#include "assert.h"
#include "bsearch.h"
#include "cyrusdb.h"
#include "libcyr_cfg.h"
#include "lock.h"
#include "map.h"
#include "retry.h"
#include "util.h"
#include "xmalloc.h"
#include "xstrlcpy.h"
#include "xstrlcat.h"

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
   version_minor (4 bytes)
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

enum {
    UNLOCKED = 0,
    READLOCKED = 1,
    WRITELOCKED = 2,
};

struct txn {
    int ismalloc;
    int syncfd;

    /* logstart is where we start changes from on commit, where we truncate
       to on abort */
    unsigned logstart;
    unsigned logend;			/* where to write to continue this txn */
};

struct db {
    /* file data */
    char *fname;
    int fd;

    const char *map_base;
    unsigned long map_len;	/* mapped size */
    unsigned long map_size;	/* actual size */
    ino_t map_ino;

    /* header info */
    unsigned version;
    unsigned version_minor;
    unsigned maxlevel;
    unsigned curlevel;
    unsigned listsize;
    unsigned logstart;		/* where the log starts from last chkpnt */
    time_t last_recovery;

    /* tracking info */
    int lock_status;
    int is_open;
    struct txn *current_txn;

    /* comparator function to use for sorting */
    int (*compar) (const char *s1, int l1, const char *s2, int l2);
};

struct db_list {
    struct db *db;
    struct db_list *next;
    int refcount;
};

static time_t global_recovery = 0;
static struct db_list *open_db = NULL;

/* Perform an FSYNC/FDATASYNC if we are *not* operating in UNSAFE mode */
#define DO_FSYNC (!libcyrus_config_getswitch(CYRUSOPT_SKIPLIST_UNSAFE))

enum {
    be_paranoid = 0,
    use_osync = 0
};

static int compare(const char *s1, int l1, const char *s2, int l2);

static void getsyncfd(struct db *db, struct txn *t)
{
    if (!use_osync) {
	t->syncfd = db->fd;
    } else if (t->syncfd == -1) {
	t->syncfd = open(db->fname, O_RDWR | O_DSYNC, 0666);
	assert(t->syncfd != -1); /* xxx do better error recovery */
    }
}

static void closesyncfd(struct db *db __attribute__((unused)),
			struct txn *t)
{
    /* if we're using fsync, then we don't want to close the file */
    if (use_osync && (t->syncfd != -1)) {
	close(t->syncfd);
    }
    t->syncfd = -1;
}

static int myinit(const char *dbdir, int myflags)
{
    char sfile[1024];
    int fd, r = 0;
    time_t a;
    
    snprintf(sfile, sizeof(sfile), "%s/skipstamp", dbdir);

    if (myflags & CYRUSDB_RECOVER) {
	/* set the recovery timestamp; all databases earlier than this
	   time need recovery run when opened */

	global_recovery = time(NULL);
	fd = open(sfile, O_RDWR | O_CREAT, 0644);
	if (fd == -1) r = -1;

	if (r != -1) r = ftruncate(fd, 0);
	a = htonl(global_recovery);
	if (r != -1) r = write(fd, &a, 4);
	if (r != -1) r = close(fd);

	if (r == -1) {
	    syslog(LOG_ERR, "DBERROR: writing %s: %m", sfile);
	    if (fd != -1) close(fd);
	    return CYRUSDB_IOERROR;
	}
    } else {
	/* read the global recovery timestamp */

	fd = open(sfile, O_RDONLY, 0644);
	if (fd == -1) r = -1;
	if (r != -1) r = read(fd, &a, 4);
	if (r != -1) r = close(fd);

	if (r == -1) {
	    syslog(LOG_ERR, "DBERROR: reading %s, assuming the worst: %m", 
		   sfile);
	    global_recovery = 0;
	} else {
	    global_recovery = ntohl(a);
	}
    }

    srand(time(NULL) * getpid());

    open_db = NULL;

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

static int myarchive(const char **fnames, const char *dirname)
{
    int r;
    const char **fname;
    char dstname[1024], *dp;
    int length, rest;
    
    strlcpy(dstname, dirname, sizeof(dstname));
    length = strlen(dstname);
    dp = dstname + length;
    rest = sizeof(dstname) - length;
    
    /* archive those files specified by the app */
    for (fname = fnames; *fname != NULL; ++fname) {
	syslog(LOG_DEBUG, "archiving database file: %s", *fname);
	strlcpy(dp, strrchr(*fname, '/'), rest);
	r = cyrusdb_copyfile(*fname, dstname);
	if (r) {
	    syslog(LOG_ERR,
		   "DBERROR: error archiving database file: %s", *fname);
	    return CYRUSDB_IOERROR;
	}
    }

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
static int myconsistent(struct db *db, struct txn *tid, int locked);
static int recovery(struct db *db, int flags);

enum {
    /* Force recovery regardless of timestamp on database */
    RECOVERY_FORCE = 1,
    /* Caller already has a write lock on the database.  In the case
     * of successful recovery, the database will still be locked on return.
     *
     * If the recovery fails, then the database will be unlocked an an
     * error will be returned */
    RECOVERY_CALLER_LOCKED = 2    
};

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
static unsigned LEVEL(const char *ptr)
{
    const bit32 *p, *q;

    assert(TYPE(ptr) == DUMMY || TYPE(ptr) == INORDER || TYPE(ptr) == ADD);
    p = q = (bit32 *) FIRSTPTR(ptr);
    while (*p != (bit32)-1) p++;
    return (p - q);
}

/* how big is this record? */
static unsigned RECSIZE(const char *ptr)
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

/* Determine if it is safe to append to this skiplist database.
 *  e.g. does it end in 4 bytes of -1 followed by a commit record? 
 * *or* does it end with 'DELETE' + 4 bytes + a commit record?
 * *or* is this the beginning of the log, in which case we only need
 * the padding from the last INORDER (or DUMMY) record
 */
static int SAFE_TO_APPEND(struct db *db)
{
    /* check it's a multiple of 4 */
    if (db->map_size % 4) return 1;

    /* is it the beginning of the log? */
    if (db->map_size == db->logstart) {
	if (*((bit32 *)(db->map_base + db->map_size - 4)) != htonl(-1)) {
	    return 1;
	}
    }

    /* in the middle of the log somewhere */
    else {
	if (*((bit32 *)(db->map_base + db->map_size - 4)) != htonl(COMMIT)) {
	    return 1;
	}

	/* if it's not an end of a record or a delete */
	if (!((*((bit32 *)(db->map_base + db->map_size - 8)) == htonl(-1)) ||
	      (*((bit32 *)(db->map_base + db->map_size -12)) == htonl(DELETE)))) {
	    return 1;
	}
    }

    return 0;
}

static int newtxn(struct db *db, struct txn *t)
{
    /* is this file safe to append to?
     * 
     * If it isn't, we need to run recovery. */
    if (SAFE_TO_APPEND(db)) {
	int r = recovery(db, RECOVERY_FORCE | RECOVERY_CALLER_LOCKED);
	if (r) return r;
    }

    /* fill in t */
    t->ismalloc = 0;
    t->syncfd = -1;
    t->logstart = db->map_size;
/*    assert(t->logstart != -1);*/
    t->logend = t->logstart;
    return 0;
}


#define PADDING(ptr) (ntohl(*((bit32 *)((ptr) + RECSIZE(ptr) - 4))))

/* given an open, mapped db, read in the header information */
static int read_header(struct db *db)
{
    const char *dptr;
    int r;
    
    assert(db && db->map_len && db->fname && db->map_base 
              && db->is_open && db->lock_status);
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

    if(db->maxlevel > SKIPLIST_MAXLEVEL) {
	syslog(LOG_ERR,
	       "skiplist %s: MAXLEVEL %d in database beyond maximum %d\n",
	       db->fname, db->maxlevel, SKIPLIST_MAXLEVEL);
	return CYRUSDB_IOERROR;
    }

    db->curlevel = ntohl(*((bit32 *)(db->map_base + OFFSET_CURLEVEL)));

    if(db->curlevel > db->maxlevel) {
	syslog(LOG_ERR,
	       "skiplist %s: CURLEVEL %d in database beyond maximum %d\n",
	       db->fname, db->curlevel, db->maxlevel);
	return CYRUSDB_IOERROR;
    }

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

    assert (db->lock_status == WRITELOCKED);
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

/* make sure our mmap() is big enough */
static int update_lock(struct db *db, struct txn *txn) 
{
    /* txn->logend is the current size of the file */
    assert (db->is_open && db->lock_status == WRITELOCKED);
    map_refresh(db->fd, 0, &db->map_base, &db->map_len, txn->logend,
		db->fname, 0);
    db->map_size = txn->logend;

    return 0;
}

static int write_lock(struct db *db, const char *altname)
{
    struct stat sbuf;
    const char *lockfailaction;
    const char *fname = altname ? altname : db->fname;

    assert(db->lock_status == UNLOCKED);
    if (lock_reopen(db->fd, fname, &sbuf, &lockfailaction) < 0) {
	syslog(LOG_ERR, "IOERROR: %s %s: %m", lockfailaction, fname);
	return CYRUSDB_IOERROR;
    }
    if (db->map_ino != sbuf.st_ino) {
	map_free(&db->map_base, &db->map_len);
    }
    db->map_size = sbuf.st_size;
    db->map_ino = sbuf.st_ino;
    db->lock_status = WRITELOCKED;
    
    map_refresh(db->fd, 0, &db->map_base, &db->map_len, sbuf.st_size,
		fname, 0);

    if (db->is_open) {
	/* reread header */
	read_header(db);
    }
    
    /* printf("%d: write lock: %d\n", getpid(), db->map_ino); */

    return 0;
}

static int read_lock(struct db *db)
{
    struct stat sbuf, sbuffile;
    int newfd = -1;

    assert(db->lock_status == UNLOCKED);
    for (;;) {
	if (lock_shared(db->fd) < 0) {
	    syslog(LOG_ERR, "IOERROR: lock_shared %s: %m", db->fname);
	    return CYRUSDB_IOERROR;
	}

	if (fstat(db->fd, &sbuf) == -1) {
	    syslog(LOG_ERR, "IOERROR: fstat %s: %m", db->fname);
	    lock_unlock(db->fd);
	    return CYRUSDB_IOERROR;
	}
	
	if (stat(db->fname, &sbuffile) == -1) {
	    syslog(LOG_ERR, "IOERROR: stat %s: %m", db->fname);
	    lock_unlock(db->fd);
	    return CYRUSDB_IOERROR;
	}
	if (sbuf.st_ino == sbuffile.st_ino) break;

	newfd = open(db->fname, O_RDWR, 0644);
	if (newfd == -1) {
	    syslog(LOG_ERR, "IOERROR: open %s: %m", db->fname);
	    lock_unlock(db->fd);
	    return CYRUSDB_IOERROR;
	}
	
	dup2(newfd, db->fd);
	close(newfd);
    }

    if (db->map_ino != sbuf.st_ino) {
	map_free(&db->map_base, &db->map_len);
    }
    db->map_size = sbuf.st_size;
    db->map_ino = sbuf.st_ino;
    db->lock_status = READLOCKED;
    
    /* printf("%d: read lock: %d\n", getpid(), db->map_ino); */

    map_refresh(db->fd, 0, &db->map_base, &db->map_len, sbuf.st_size,
		db->fname, 0);

    if (db->is_open) {
	/* reread header */
	read_header(db);
    }
    
    return 0;
}

static int unlock(struct db *db)
{
    if (db->lock_status == UNLOCKED) {
	syslog(LOG_NOTICE, "skiplist: unlock while not locked");
    }
    if (lock_unlock(db->fd) < 0) {
	syslog(LOG_ERR, "IOERROR: lock_unlock %s: %m", db->fname);
	return CYRUSDB_IOERROR;
    }
    db->lock_status = UNLOCKED;

    /* printf("%d: unlock: %d\n", getpid(), db->map_ino); */

    return 0;
}

static int dispose_db(struct db *db)
{
    if (!db) return 0;
    assert(db->is_open);
    if (db->lock_status) {
	syslog(LOG_ERR, "skiplist: closed while still locked");
	unlock(db);
    }
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

static int myopen(const char *fname, int flags, struct db **ret)
{
    struct db *db;
    struct db_list *list_ent = open_db;
    int r;
    int new = 0;

    while (list_ent && strcmp(list_ent->db->fname, fname)) {
	list_ent = list_ent->next;
    }
    if (list_ent) {
	/* we already have this DB open! */
	syslog(LOG_NOTICE, "skiplist: %s is already open %d time%s, returning object", 
	fname, list_ent->refcount, list_ent->refcount == 1 ? "" : "s");
	*ret = list_ent->db;
	++list_ent->refcount;
	return 0;
    }

    db = (struct db *) xzmalloc(sizeof(struct db));
    db->fd = -1;
    db->fname = xstrdup(fname);
    db->compar = (flags & CYRUSDB_MBOXSORT) ? bsearch_ncompare : compare;

    db->fd = open(fname, O_RDWR, 0644);
    if (db->fd == -1 && errno == ENOENT && (flags & CYRUSDB_CREATE)) {
	if (cyrus_mkdir(fname, 0755) == -1) return CYRUSDB_IOERROR;

	db->fd = open(fname, O_RDWR | O_CREAT, 0644);
	new = 1;
    }

    if (db->fd == -1) {
	int level = (flags & CYRUSDB_CREATE) ? LOG_ERR : LOG_DEBUG;
	syslog(level, "IOERROR: opening %s: %m", fname);
	dispose_db(db);
	return CYRUSDB_IOERROR;
    }

    db->curlevel = 0;
    db->is_open = 0;
    db->lock_status = UNLOCKED;

    /* grab a read lock, only reading the header */
    r = read_lock(db);
    if (r < 0) {
        dispose_db(db);
	return r;
    }

    /* if the file is empty, then the header needs to be created first */
    if (db->map_size == 0) {
        unlock(db);
	r = write_lock(db, NULL);
	if (r < 0) {
	    dispose_db(db);
	    return r;
	}
    }

    /* race condition.  Another process may have already got the write
     * lock and created the header. Only go ahead if the map_size is 
     * still zero (read/write_lock updates map_size). */
    if (db->map_size == 0) {
	/* initialize in memory structure */
	db->version = SKIPLIST_VERSION;
	db->version_minor = SKIPLIST_VERSION_MINOR;
	db->maxlevel = SKIPLIST_MAXLEVEL;
	db->curlevel = 1;
	db->listsize = 0;
	/* where do we start writing new entries? */
	db->logstart = DUMMY_OFFSET(db) + DUMMY_SIZE(db);
	db->last_recovery = time(NULL);

	/* create the header */
	r = write_header(db);

	if (!r) {
	    int n;
	    int dsize = DUMMY_SIZE(db);
	    bit32 *buf = (bit32 *) xzmalloc(dsize);

	    buf[0] = htonl(DUMMY);
	    buf[(dsize / 4) - 1] = htonl(-1);

	    lseek(db->fd, DUMMY_OFFSET(db), SEEK_SET);
	    n = retry_write(db->fd, (char *) buf, dsize);
	    if (n != dsize) {
		syslog(LOG_ERR, "DBERROR: writing dummy node for %s: %m",
		       db->fname);
		r = CYRUSDB_IOERROR;
	    }
	    free(buf);
	}
	
	/* sync the db */
	if (!r && DO_FSYNC && (fsync(db->fd) < 0)) {
	    syslog(LOG_ERR, "DBERROR: fsync(%s): %m", db->fname);
	    r = CYRUSDB_IOERROR;
	}

	/* map the new file */
	db->map_size = db->logstart;
	map_refresh(db->fd, 0, &db->map_base, &db->map_len, db->logstart,
		    db->fname, 0);
    }

    db->is_open = 1;

    r = read_header(db);
    if (r) {
	dispose_db(db);
	return r;
    }

    /* unlock the db */
    unlock(db);

    if (!global_recovery || db->last_recovery < global_recovery) {
	/* run recovery; we rebooted since the last time recovery
	   was run */
	r = recovery(db, 0);
	if (r) {
	    dispose_db(db);
	    return r;
	}
    }

    *ret = db;

    /* track this database in the open list */
    list_ent = (struct db_list *) xzmalloc(sizeof(struct db_list));
    list_ent->db = db;
    list_ent->next = open_db;
    list_ent->refcount = 1;
    open_db = list_ent;

    return 0;
}

int myclose(struct db *db)
{
    struct db_list *list_ent = open_db;
    struct db_list *prev = NULL;

    /* remove this DB from the open list */
    while (list_ent && list_ent->db != db) {
	prev = list_ent;
	list_ent = list_ent->next;
    }
    assert(list_ent);
    if (--list_ent->refcount <= 0) {
	if (prev) prev->next = list_ent->next;
	else open_db = list_ent->next;
	free(list_ent);
	return dispose_db(db);
    }

    return 0;
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
    const char *ptr = db->map_base + DUMMY_OFFSET(db);
    int i;
    unsigned offset;

    if (updateoffsets) {
	for (i = 0; (unsigned) i < db->maxlevel; i++) {
	    updateoffsets[i] = DUMMY_OFFSET(db);
	}
    }

    for (i = db->curlevel - 1; i >= 0; i--) {
	while ((offset = FORWARD(ptr, i)) && 
	       db->compar(KEY(db->map_base + offset), KEYLEN(db->map_base + offset), 
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
    int r = 0;

    assert(db != NULL && key != NULL);

    if (data) *data = NULL;
    if (datalen) *datalen = 0;

    if (!mytid) {
	if (db->current_txn == NULL) {
	    /* grab a r lock */
	    if ((r = read_lock(db)) < 0) {
		return r;
	    }
	    tp = NULL;
	} else {
	    tp = db->current_txn;
	    update_lock(db, tp);
	}
    } else if (!*mytid) {
	assert(db->current_txn == NULL);
	/* grab a r/w lock */
	if ((r = write_lock(db, NULL)) < 0) {
	    return r;
	}

	/* fill in t */
	if ((r = newtxn(db, &t))) return r;

	tp = &t;
    } else {
	assert(db->current_txn == *mytid);
	tp = *mytid;
	update_lock(db, tp);
    }

    ptr = find_node(db, key, keylen, 0);

    if (ptr == db->map_base || db->compar(KEY(ptr), KEYLEN(ptr), key, keylen)) {
	/* failed to find key/keylen */
	r = CYRUSDB_NOTFOUND;
    } else {
	if (datalen) *datalen = DATALEN(ptr);
	if (data) *data = DATA(ptr);
    }

    if (mytid) {
	if (!*mytid) {
	    /* return the txn structure */

	    *mytid = xmalloc(sizeof(struct txn));
	    memcpy(*mytid, tp, sizeof(struct txn));
	    (*mytid)->ismalloc = 1;

	    db->current_txn = *mytid;
	}
    } else if (!tp) {
	/* release read lock */
	int r1;
	if ((r1 = unlock(db)) < 0) {
	    return r1;
	}
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

/* foreach allows for subsidary mailbox operations in 'cb'.
   if there is a txn, 'cb' must make use of it.
*/
int myforeach(struct db *db,
	      char *prefix, int prefixlen,
	      foreach_p *goodp,
	      foreach_cb *cb, void *rock, 
	      struct txn **tid)
{
    const char *ptr;
    char *savebuf = NULL;
    size_t savebuflen = 0;
    size_t savebufsize;
    struct txn t, *tp;
    int r = 0, cb_r = 0;

    assert(db != NULL);
    assert(prefixlen >= 0);

    if (!tid) {
	if (db->current_txn == NULL) {
	    /* grab a r lock */
	    if ((r = read_lock(db)) < 0) {
		return r;
	    }
	    tp = NULL;
	} else {
	    tp = db->current_txn;
	    update_lock(db, tp);
	}
    } else if (!*tid) {
	assert(db->current_txn == NULL);
	/* grab a r/w lock */
	if ((r = write_lock(db, NULL)) < 0) {
	    return r;
	}

	/* fill in t */
	if ((r = newtxn(db, &t))) return r;

	tp = &t;
    } else {
	assert(db->current_txn == *tid);
	tp = *tid;
	update_lock(db, tp);
    }

    ptr = find_node(db, prefix, prefixlen, 0);

    while (ptr != db->map_base) {
	/* does it match prefix? */
	if (KEYLEN(ptr) < (bit32) prefixlen) break;
	if (prefixlen && db->compar(KEY(ptr), prefixlen, prefix, prefixlen)) break;

	if (!goodp ||
	    goodp(rock, KEY(ptr), KEYLEN(ptr), DATA(ptr), DATALEN(ptr))) {
	    ino_t ino = db->map_ino;
	    unsigned long sz = db->map_size;

	    if (!tp) {
		/* release read lock */
		if ((r = unlock(db)) < 0) {
		    return r;
		}
	    }

	    /* save KEY, KEYLEN */
	    if (KEYLEN(ptr) > savebuflen) {
		savebuflen = KEYLEN(ptr) + 1024;
		savebuf = xrealloc(savebuf, savebuflen);
	    }
	    memcpy(savebuf, KEY(ptr), KEYLEN(ptr));
	    savebufsize = KEYLEN(ptr);

	    /* make callback */
	    cb_r = cb(rock, KEY(ptr), KEYLEN(ptr), DATA(ptr), DATALEN(ptr));
	    if (cb_r) break;

	    if (!tp) {
		/* grab a r lock */
		if ((r = read_lock(db)) < 0) {
		    return r;
		}
	    } else {
		/* make sure we're up to date */
		update_lock(db, tp);
	    }

	    /* reposition */
	    if (!(ino == db->map_ino && sz == db->map_size)) {
		/* something changed in the file; reseek */
		ptr = find_node(db, savebuf, savebufsize, 0);

		/* 'ptr' might not equal 'savebuf'.  if it's different,
		   we want to stay where we are.  if it's the same, we
		   should move on to the next one */
		if (savebufsize == KEYLEN(ptr) &&
		    !memcmp(savebuf, KEY(ptr), savebufsize)) {
		    ptr = db->map_base + FORWARD(ptr, 0);
		} else {
		    /* 'savebuf' got deleted, so we're now pointing at the
		       right thing */
		}
	    } else {
		/* move to the next one */
		ptr = db->map_base + FORWARD(ptr, 0);
	    }
	} else {
	    /* we didn't make the callback; keep going */
	    ptr = db->map_base + FORWARD(ptr, 0);
	}
    }

    if (tid) {
	if (!*tid) {
	    /* return the txn structure */

	    *tid = xmalloc(sizeof(struct txn));
	    memcpy(*tid, tp, sizeof(struct txn));
	    (*tid)->ismalloc = 1;

	    db->current_txn = *tid;
	}
    } else if (!tp) {
	/* release read lock */
	if ((r = unlock(db)) < 0) {
	    return r;
	}
    }

    if (savebuf) {
	free(savebuf);
    }

    return r ? r : cb_r;
}

unsigned int randlvl(struct db *db)
{
    unsigned int lvl = 1;
    
    while ((((float) rand() / (float) (RAND_MAX)) < PROB) 
	   && (lvl < db->maxlevel)) {
	lvl++;
    }
    /* syslog(LOG_DEBUG, "picked level %d", lvl); */

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
    unsigned int lvl, i;
    int num_iov;
    struct txn t, *tp;
    bit32 endpadding = (bit32) htonl(-1);
    bit32 zeropadding[4] = { 0, 0, 0, 0 };
    int updateoffsets[SKIPLIST_MAXLEVEL];
    int newoffsets[SKIPLIST_MAXLEVEL];
    int addrectype = htonl(ADD);
    int delrectype = htonl(DELETE);
    bit32 todelete;
    bit32 newoffset, netnewoffset;
    int r;

    assert(db != NULL);
    assert(key && keylen);

    if (!tid || !*tid) {
	assert(db->current_txn == NULL);
	/* grab a r/w lock */
	if ((r = write_lock(db, NULL)) < 0) {
	    return r;
	}

	/* fill in t */
	if ((r = newtxn(db, &t))) return r;

	tp = &t;

	db->current_txn = tp;
    } else {
	assert(db->current_txn == *tid);
	tp = *tid;
	update_lock(db, tp);
    }

    if (be_paranoid) {
	assert(myconsistent(db, tp, 1) == 0);
    }

    num_iov = 0;
    
    newoffset = tp->logend;
    ptr = find_node(db, key, keylen, updateoffsets);
    if (ptr != db->map_base && 
	!db->compar(KEY(ptr), KEYLEN(ptr), key, keylen)) {
	    
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
	if (lvl > db->curlevel) {
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
    
    netnewoffset = htonl(newoffset);

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

    getsyncfd(db, tp);
    lseek(tp->syncfd, tp->logend, SEEK_SET);
    r = retry_writev(tp->syncfd, iov, num_iov);
    if (r < 0) {
	syslog(LOG_ERR, "DBERROR: retry_writev(): %m");
	myabort(db, tp);
	return CYRUSDB_IOERROR;
    }
    tp->logend += r;		/* update where to write next */

    /* update pointers after writing record so abort is guaranteed to
     * see which records need reverting */
    for (i = 0; i < lvl; i++) {
	/* write pointer updates */
	/* FORWARD(updates[i], i) = newoffset; */
	lseek(db->fd,
	      PTR(db->map_base + updateoffsets[i], i) - db->map_base,
	      SEEK_SET);
	retry_write(db->fd, (char *) &netnewoffset, 4);
    }

    if (tid) {
	if (!*tid) {
	    /* return the txn structure */

	    *tid = xmalloc(sizeof(struct txn));
	    memcpy(*tid, tp, sizeof(struct txn));
	    (*tid)->ismalloc = 1;

	    db->current_txn = *tid;
	}

	if (be_paranoid) {
	    assert(myconsistent(db, *tid, 1) == 0);
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
	     struct txn **tid, int force __attribute__((unused)))
{
    const char *ptr;
    int delrectype = htonl(DELETE);
    int updateoffsets[SKIPLIST_MAXLEVEL];
    bit32 offset;
    bit32 writebuf[2];
    struct txn t, *tp;
    unsigned i;
    int r;

    if (!tid || !*tid) {
	assert(db->current_txn == NULL);
	/* grab a r/w lock */
	if ((r = write_lock(db, NULL)) < 0) {
	    return r;
	}

	/* fill in t */
	if ((r = newtxn(db, &t))) return r;

	tp = &t;

	db->current_txn = tp;
    } else {
	assert(db->current_txn == *tid);
	tp = *tid;
	update_lock(db, tp);
    }

    if (be_paranoid) {
	assert(myconsistent(db, tp, 1) == 0);
    }

    ptr = find_node(db, key, keylen, updateoffsets);
    if (ptr != db->map_base &&
	!db->compar(KEY(ptr), KEYLEN(ptr), key, keylen)) {
	/* gotcha */
	offset = ptr - db->map_base;

	/* log the deletion */
	getsyncfd(db, tp);
	lseek(tp->syncfd, tp->logend, SEEK_SET);
	writebuf[0] = delrectype;
	writebuf[1] = htonl(offset);

	/* update end-of-log */
	r = retry_write(tp->syncfd, (char *) writebuf, 8);
	if (r < 0) {
	    syslog(LOG_ERR, "DBERROR: retry_write(): %m");
	    myabort(db, tp);
	    return CYRUSDB_IOERROR;
	}
	tp->logend += r;

	/* update pointers after writing record so abort is guaranteed to
	 * see which records need reverting */
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
    }

    if (tid) {
	if (!*tid) {
	    /* return the txn structure */

	    *tid = xmalloc(sizeof(struct txn));
	    memcpy(*tid, tp, sizeof(struct txn));
	    (*tid)->ismalloc = 1;

	    db->current_txn = *tid;
	}

	if (be_paranoid) {
	    assert(myconsistent(db, *tid, 1) == 0);
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
    int r = 0;

    assert(db && tid);

    assert(db->current_txn == tid);

    update_lock(db, tid);

    if (be_paranoid) {
	assert(myconsistent(db, tid, 1) == 0);
    }

    /* verify that we did something this txn */
    if (tid->logstart == tid->logend) {
	/* empty txn, done */
        r = 0;
	goto done;
    }

    /* fsync if we're not using O_SYNC writes */
    if (!use_osync && DO_FSYNC && (fdatasync(db->fd) < 0)) {
	syslog(LOG_ERR, "IOERROR: writing %s: %m", db->fname);
	r = CYRUSDB_IOERROR;
        goto done;
    }

    /* xxx consider unlocking the database here: the transaction isn't
       yet durable but the file is in a form that is consistent for
       other transactions to use. releasing the lock here would give
       ACI properties. */
    
    /* write a commit record */
    assert(tid->syncfd != -1);
    lseek(tid->syncfd, tid->logend, SEEK_SET);
    retry_write(tid->syncfd, (char *) &commitrectype, 4);

    /* fsync if we're not using O_SYNC writes */
    if (!use_osync && DO_FSYNC && (fdatasync(db->fd) < 0)) {
	syslog(LOG_ERR, "IOERROR: writing %s: %m", db->fname);
	r = CYRUSDB_IOERROR;
        goto done;
    }

 done:
    if (!r)
	db->current_txn = NULL;

    /* consider checkpointing */
    if (!r && tid->logend > (2 * db->logstart + SKIPLIST_MINREWRITE)) {
	r = mycheckpoint(db, 1);
    }
    
    if (be_paranoid) {
	assert(myconsistent(db, db->current_txn, 1) == 0);
    }

    if (r) {
        int r2;

        /* error during commit; we must abort */
        r2 = myabort(db, tid);
        if (r2) {
            syslog(LOG_ERR, "DBERROR: skiplist %s: commit AND abort failed",
		   db->fname);
        }
    } else {
        /* release the write lock */
        if ((r = unlock(db)) < 0) {
            return r;
        }
        
        /* must close this after releasing the lock */
        closesyncfd(db, tid);

        /* free tid if needed */
        if (tid->ismalloc) {
            free(tid);
        }
    }

    return r;
}

int myabort(struct db *db, struct txn *tid)
{
    const char *ptr;
    int updateoffsets[SKIPLIST_MAXLEVEL];
    bit32 offset;
    unsigned i;
    int r = 0;

    assert(db && tid);

    assert(db->current_txn == tid);

    /* update the mmap so we can see the log entries we need to remove */
    update_lock(db, tid);
    
    /* look at the log entries we've written, and undo their effects */
    while (tid->logstart != tid->logend) {
	/* find the last log entry */
	for (offset = tid->logstart, ptr = db->map_base + offset; 
	     offset + RECSIZE(ptr) != (bit32) tid->logend;
	     offset += RECSIZE(ptr), ptr = db->map_base + offset) ;
	
	offset = ptr - db->map_base;

	assert(TYPE(ptr) == ADD || TYPE(ptr) == DELETE);
	switch (TYPE(ptr)) {
	case DUMMY:
	case INORDER:
	case COMMIT:
	    abort();

	case ADD:
	    /* remove this record */
	    (void) find_node(db, KEY(ptr), KEYLEN(ptr), updateoffsets);
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
	    break;
	case DELETE:
	{
	    unsigned int lvl;
	    int newoffset;
	    const char *q;
	    
	    /* re-add this record.  it can't exist right now. */
	    newoffset = *((bit32 *)(ptr + 4));
	    q = db->map_base + ntohl(newoffset);
	    lvl = LEVEL(q);
	    (void) find_node(db, KEY(q), KEYLEN(q), updateoffsets);
	    for (i = 0; i < lvl; i++) {
		/* the current pointers FROM this node are correct,
		   so we just have to update 'updateoffsets' */
		lseek(db->fd, 
		      PTR(db->map_base + updateoffsets[i], i) - db->map_base,
		      SEEK_SET);
		retry_write(db->fd, (char *) &newoffset, 4);
	    }
	    break;
	}
	}

	/* remove looking at this */
	tid->logend -= RECSIZE(ptr);
    }

    /* truncate the file to remove log entries */
    if (ftruncate(db->fd, tid->logstart) < 0) {
	syslog(LOG_ERR, 
	       "DBERROR: skiplist abort %s: ftruncate: %m",
	       db->fname);
	r = CYRUSDB_IOERROR;
	unlock(db);
	return r;
    }

    db->map_size = tid->logstart;

    /* release the write lock */
    if ((r = unlock(db)) < 0) {
	return r;
    }

    /* must close this after releasing the lock */
    closesyncfd(db, tid);

    /* free the tid */
    if (tid->ismalloc) {
	free(tid);
    }

    db->current_txn = NULL;

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
    bit32 offset;
    int r = 0;
    int iorectype = htonl(INORDER);
    unsigned i;
    time_t start = time(NULL);

    /* grab write lock (could be read but this prevents multiple checkpoints
     simultaneously) */
    if (!locked) {
	r = write_lock(db, NULL);
	if (r < 0) return r;
    } else {
	/* we need the latest and greatest data */
        assert(db->is_open && db->lock_status == WRITELOCKED);
	map_refresh(db->fd, 0, &db->map_base, &db->map_len, MAP_UNKNOWN_LEN,
		    db->fname, 0);
    }

    /* can't be in a transaction */
    assert(db->current_txn == NULL);

    if ((r = myconsistent(db, NULL, 1)) < 0) {
	syslog(LOG_ERR, "db %s, inconsistent pre-checkpoint, bailing out",
	       db->fname);
	return r;
    }

    /* open fname.NEW */
    snprintf(fname, sizeof(fname), "%s.NEW", db->fname);
    oldfd = db->fd;
    db->fd = open(fname, O_RDWR | O_CREAT, 0644);
    if (db->fd < 0) {
	syslog(LOG_ERR, "DBERROR: skiplist checkpoint: open(%s): %m", fname);
	if (!locked) unlock(db);
	db->fd = oldfd;
	return CYRUSDB_IOERROR;
    }

    /* truncate it just in case! */
    r = ftruncate(db->fd, 0);
    if (r < 0) {
	syslog(LOG_ERR, "DBERROR: skiplist checkpoint %s: ftruncate %m", fname);
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

	lseek(db->fd, DUMMY_OFFSET(db), SEEK_SET);
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
	    updateoffsets[i] = DUMMY_OFFSET(db) + 12 + 4 * i;
	}
    }

    /* write records to new file */
    offset = FORWARD(db->map_base + DUMMY_OFFSET(db), 0);
    db->listsize = 0;
    while (!r && offset != 0) {
	unsigned int lvl;
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
    db->last_recovery = time(NULL);
    r = write_header(db);

    /* sync new file */
    if (!r && DO_FSYNC && (fdatasync(db->fd) < 0)) {
	syslog(LOG_ERR, "DBERROR: skiplist checkpoint: fdatasync(%s): %m", fname);
	r = CYRUSDB_IOERROR;
    }
    
    if (!r) {
	/* get new lock */
	db->lock_status = UNLOCKED; /* well, the new file is... */
	r = write_lock(db, fname);
    }

    /* move new file to original file name */
    if (!r && (rename(fname, db->fname) < 0)) {
	syslog(LOG_ERR, "DBERROR: skiplist checkpoint: rename(%s, %s): %m", 
	       fname, db->fname);
	r = CYRUSDB_IOERROR;
    }

    /* force the new file name to disk */
    if (!r && DO_FSYNC && (fsync(db->fd) < 0)) {
	syslog(LOG_ERR, "DBERROR: skiplist checkpoint: fsync(%s): %m", fname);
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

    {
	struct stat sbuf;

	/* let's make sure we're up to date */
	map_free(&db->map_base, &db->map_len);
	if (fstat(db->fd, &sbuf) == -1) {
	    syslog(LOG_ERR, "IOERROR: fstat %s: %m", db->fname);
	    return CYRUSDB_IOERROR;
	}
	db->map_size = sbuf.st_size;
	db->map_ino = sbuf.st_ino;
	map_refresh(db->fd, 0, &db->map_base, &db->map_len, sbuf.st_size,
		    db->fname, 0);
    }

    if ((r = myconsistent(db, NULL, 1)) < 0) {
	syslog(LOG_ERR, "db %s, inconsistent post-checkpoint, bailing out",
	       db->fname);
	return r;
    }

    if (!locked) {
	/* unlock the new db files */
	unlock(db);
    }

    {
	int diff = time(NULL) - start;
	syslog(LOG_INFO, 
	       "skiplist: checkpointed %s (%d record%s, %d bytes) in %d second%s",
	       db->fname, db->listsize, db->listsize == 1 ? "" : "s", 
	       db->logstart, diff, diff == 1 ? "" : "s"); 
    }

    return r;
}

/* dump the database.
   if detail == 1, dump all records.
   if detail == 2, also dump pointers for active records.
   if detail == 3, dump all records/all pointers.
*/
static int dump(struct db *db, int detail __attribute__((unused)))
{
    const char *ptr, *end;
    unsigned i;

    read_lock(db);

    ptr = db->map_base + DUMMY_OFFSET(db);
    end = db->map_base + db->map_size;
    while (ptr < end) {
	printf("%04X: ", ptr - db->map_base);
	switch (TYPE(ptr)) {
	case DUMMY:
	    printf("DUMMY ");
	    break;
	case INORDER:
	    printf("INORDER ");
	    break;
	case ADD:
	    printf("ADD ");
	    break;
	case DELETE:
	    printf("DELETE ");
	    break;
	case COMMIT:
	    printf("COMMIT ");
	    break;
	}

	switch (TYPE(ptr)) {
	case DUMMY:
	case INORDER:
	case ADD:
	    printf("kl=%d dl=%d lvl=%d\n",
		   KEYLEN(ptr), DATALEN(ptr), LEVEL(ptr));
	    printf("\t");
	    for (i = 0; i < LEVEL(ptr); i++) {
		printf("%04X ", FORWARD(ptr, i));
	    }
	    printf("\n");
	    break;

	case DELETE:
	    printf("offset=%04X\n", ntohl(*((bit32 *)(ptr + 4))));
	    break;

	case COMMIT:
	    printf("\n");
	    break;
	}

	ptr += RECSIZE(ptr);
    }

    unlock(db);
    return 0;
}

static int consistent(struct db *db)
{
    return myconsistent(db, NULL, 0);
}

/* perform some basic consistency checks */
static int myconsistent(struct db *db, struct txn *tid, int locked)
{
    const char *ptr;
    bit32 offset;

    assert(db->current_txn == tid); /* could both be null */

    if (!locked) read_lock(db);
    else if (tid) update_lock(db, tid);

    offset = FORWARD(db->map_base + DUMMY_OFFSET(db), 0);
    while (offset != 0) {
	unsigned i;

	ptr = db->map_base + offset;

	for (i = 0; i < LEVEL(ptr); i++) {
	    offset = FORWARD(ptr, i);

	    if (offset > db->map_size) {
		fprintf(stdout, 
			"skiplist inconsistent: %04X: ptr %d is %04X; "
			"eof is %04X\n", 
			ptr - db->map_base,
			i, offset, (unsigned int) db->map_size);
		return CYRUSDB_INTERNAL;
	    }

	    if (offset != 0) {
		/* check to see that ptr < ptr -> next */
		const char *q = db->map_base + offset;
		int cmp;

		cmp = db->compar(KEY(ptr), KEYLEN(ptr), KEY(q), KEYLEN(q));
		if (cmp >= 0) {
		    fprintf(stdout, 
			    "skiplist inconsistent: %04X: ptr %d is %04X; "
			    "db->compar() = %d\n", 
			    ptr - db->map_base,
			    i,
			    offset, cmp);
		    return CYRUSDB_INTERNAL;
		}
	    }
	}

	offset = FORWARD(ptr, 0);
    }

    if (!locked) unlock(db);

    return 0;
}

/* run recovery on this file */
static int recovery(struct db *db, int flags)
{
    const char *ptr, *keyptr;
    int updateoffsets[SKIPLIST_MAXLEVEL];
    bit32 offset, offsetnet, myoff = 0;
    int r = 0, need_checkpoint = 0;
    time_t start = time(NULL);
    unsigned i;

    if (!(flags & RECOVERY_CALLER_LOCKED) && (r = write_lock(db, NULL)) < 0) {
	return r;
    }
    assert(db->is_open && db->lock_status == WRITELOCKED);

    if ((r = read_header(db)) < 0) {
	unlock(db);
	return r;
    }

    if (!(flags & RECOVERY_FORCE)
	&& global_recovery
	&& db->last_recovery >= global_recovery) {
	/* someone beat us to it */
	unlock(db);
	return 0;
    }

    /* can't run recovery inside a txn */
    assert(db->current_txn == NULL);

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
	updateoffsets[i] = DUMMY_OFFSET(db) + 12 + 4 * i;
    }
    
    /* reset the data that was written INORDER by the last checkpoint */
    offset = DUMMY_OFFSET(db) + DUMMY_SIZE(db);
    while (!r && (offset < db->map_size)
	      && TYPE(db->map_base + offset) == INORDER) {
	ptr = db->map_base + offset;
	offsetnet = htonl(offset);

	db->listsize++;

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
	if (!r && PADDING(ptr) != (bit32) -1) {
	    syslog(LOG_ERR, "DBERROR: %s: offset %04X padding not -1",
		   db->fname, offset);
	    r = CYRUSDB_IOERROR;
	}

	if (!r) {
	    offset += RECSIZE(ptr);
	}
    }

    if (offset != db->logstart) {
	syslog(LOG_NOTICE, "skiplist recovery %s: incorrect logstart %04X changed to %04X", 
	       db->fname, db->logstart, offset);
	db->logstart = offset; /* header will be committed later */
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

	/* bugs in recovery truncates could have left some bogus zeros here */
	if (TYPE(ptr) == 0) {
	    int orig = offset;
	    while (TYPE(ptr) == 0 && offset < db->map_size) {
		offset += 4;
		ptr = db->map_base + offset;
	    }
	    syslog(LOG_ERR, "skiplist recovery %s: skipped %d bytes of zeros at %04X",
			    db->fname, offset - orig, orig);
	    need_checkpoint = 1;
	}

	offsetnet = htonl(offset);

	/* if this is a commit, we've processed everything in this txn */
	if (TYPE(ptr) == COMMIT) {
	    offset += RECSIZE(ptr);
	    continue;
	}

	/* make sure this is ADD or DELETE */
	if (TYPE(ptr) != ADD && TYPE(ptr) != DELETE) {
	    syslog(LOG_ERR, 
		   "DBERROR: skiplist recovery %s: %04X should be ADD or DELETE",
		   db->fname, offset);
	    r = CYRUSDB_IOERROR;
	    break;
	}

	/* look ahead for a commit */
	q = db->map_base + db->map_size;
	p = ptr;
	for (;;) {
            if (RECSIZE(p) <= 0) {
                /* hmm, we can't trust this transaction */
		syslog(LOG_ERR,
		       "DBERROR: skiplist recovery %s: found a RECSIZE of 0, "
		       "truncating corrupted file instead of looping forever...",
		       db->fname);
                p = q;
                break;
            }
	    p += RECSIZE(p);
	    if (p >= q) break;
	    if (TYPE(p) == COMMIT) break;
	}
	if (p >= q) {
	    syslog(LOG_NOTICE, 
		   "skiplist recovery %s: found partial txn, not replaying",
		   db->fname);

	    /* no commit, we should truncate */
	    if (ftruncate(db->fd, offset) < 0) {
		syslog(LOG_ERR, 
		       "DBERROR: skiplist recovery %s: ftruncate: %m",
		       db->fname);
		r = CYRUSDB_IOERROR;
	    }

	    /* set the map size back as well */
	    db->map_size = offset;

	    break;
	}

	keyptr = NULL;
	/* look for the key */
	if (TYPE(ptr) == ADD) {
	    keyptr = find_node(db, KEY(ptr), KEYLEN(ptr), updateoffsets);
	    if (keyptr == db->map_base ||
		db->compar(KEY(ptr), KEYLEN(ptr), KEY(keyptr), KEYLEN(keyptr))) {
		/* didn't find exactly this node */
		keyptr = NULL;
	    }
	} else { /* type == DELETE */
	    const char *p;

	    myoff = ntohl(*((bit32 *)(ptr + 4)));
	    p = db->map_base + myoff;
	    keyptr = find_node(db, KEY(p), KEYLEN(p), updateoffsets);
	    if (keyptr == db->map_base ||
		db->compar(KEY(p), KEYLEN(p), KEY(keyptr), KEYLEN(keyptr))) {
		/* didn't find exactly this node */
		keyptr = NULL;
	    }
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
	} else if (TYPE(ptr) == DELETE) {
	    syslog(LOG_ERR, 
		   "DBERROR: skiplist recovery %s: DELETE at %04X doesn't exist, skipping",
		   db->fname, offset);
	    need_checkpoint = 1;

	/* otherwise insert it */
	} else if (TYPE(ptr) == ADD) {
	    unsigned int lvl;
	    bit32 newoffsets[SKIPLIST_MAXLEVEL];

	    if (keyptr) {
		syslog(LOG_ERR, 
		       "DBERROR: skiplist recovery %s: ADD at %04X exists, replacing", 
		       db->fname, offset);
		need_checkpoint = 1;
	    } else {
		db->listsize++;
	    }
	    offsetnet = htonl(offset);

	    lvl = LEVEL(ptr);
	    if(lvl > SKIPLIST_MAXLEVEL) {
		syslog(LOG_ERR,
		       "DBERROR: skiplist recovery %s: node claims level %d (greater than max %d)",
		       db->fname, lvl, SKIPLIST_MAXLEVEL);
		r = CYRUSDB_IOERROR;
	    } else {
		/* NOTE - in the bogus case where a record with the same key already
		 * exists, there are three possible cases:
		 * lvl == LEVEL(keyptr)
		 *    * trivial: all to me, all mine to keyptr's FORWARD
		 * lvl > LEVEL(keyptr)	 -
		 *    * all updateoffsets values should point to me
		 *    * up until LEVEL(keyptr) set to keyptr's next values
		 *      (updateoffsets[i] should be keyptr in these cases)
		 *      then point all my higher pointers are updateoffsets[i]'s
		 *      FORWARD instead.
		 * lvl < LEVEL(keyptr)
		 *    * updateoffsets values up to lvl should point to me
		 *    * all mine should point to keyptr's next values
		 *    * from lvl up, all updateoffsets[i] should point to
		 *      FORWARD(keyptr, i) instead.
		 *
		 * All of this fully unstitches keyptr from the chain and stitches
		 * the current node in, regardless of height difference.  Man what
		 * a pain!
		 */
		for (i = 0; i < lvl; i++) {
		    /* set our next pointers */
		    if (keyptr && i < LEVEL(keyptr)) {
                        /* need to replace the matching record key */
			newoffsets[i] = 
			    htonl(FORWARD(keyptr, i));
		    } else {
			newoffsets[i] = 
			    htonl(FORWARD(db->map_base + updateoffsets[i], i));
		    }
		    
		    /* replace 'updateoffsets' to point to me */
		    lseek(db->fd, 
			  PTR(db->map_base + updateoffsets[i], i) - db->map_base,
			  SEEK_SET);
		    retry_write(db->fd, (char *) &offsetnet, 4);
		}
		/* write out newoffsets */
		lseek(db->fd, FIRSTPTR(ptr) - db->map_base, SEEK_SET);
		retry_write(db->fd, (char *) newoffsets, 4 * lvl);
                
		if (keyptr && lvl < LEVEL(keyptr)) {
		    bit32 newoffsetnet;
		    for (i = lvl; i < LEVEL(keyptr); i++) {
			newoffsetnet = htonl(FORWARD(keyptr, i));
			/* replace 'updateoffsets' to point onwards */
			lseek(db->fd, 
			      PTR(db->map_base + updateoffsets[i], i) - db->map_base,
			      SEEK_SET);
			retry_write(db->fd, (char *) &newoffsetnet, 4);
		    }
		}
	    }
	/* can't happen */
	} else {
	    abort();
	}

	/* move to next record */
	offset += RECSIZE(ptr);
    }

    /* fsync the recovered database */
    if (!r && DO_FSYNC && (fdatasync(db->fd) < 0)) {
	syslog(LOG_ERR, 
	       "DBERROR: skiplist recovery %s: fdatasync: %m", db->fname); 
	r = CYRUSDB_IOERROR;
    }

    /* set the last recovery timestamp */
    if (!r) {
	db->last_recovery = time(NULL);
	write_header(db);
    }

    /* fsync the new header */
    if (!r && DO_FSYNC && (fdatasync(db->fd) < 0)) {
	syslog(LOG_ERR,
	       "DBERROR: skiplist recovery %s: fdatasync: %m", db->fname); 
	r = CYRUSDB_IOERROR;
    }

    if (!r) {
	int diff = time(NULL) - start;

	syslog(LOG_NOTICE, 
	       "skiplist: recovered %s (%d record%s, %ld bytes) in %d second%s",
	       db->fname, db->listsize, db->listsize == 1 ? "" : "s", 
	       db->map_size, diff, diff == 1 ? "" : "s"); 
    }

    if (!r && need_checkpoint) {
	r = mycheckpoint(db, 1);
    }

    if(r || !(flags & RECOVERY_CALLER_LOCKED)) {
	unlock(db);
    }
    
    return r;
}

struct cyrusdb_backend cyrusdb_skiplist = 
{
    "skiplist",			/* name */

    &myinit,
    &mydone,
    &mysync,
    &myarchive,

    &myopen,
    &myclose,

    &fetch,
    &fetchlock,
    &myforeach,
    &create,
    &store,
    &mydelete,

    &mycommit,
    &myabort,

    &dump,
    &consistent
};
