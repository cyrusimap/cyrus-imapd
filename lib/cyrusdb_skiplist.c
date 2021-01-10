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
 */

/* xxx check retry_xxx for failure */

/* xxx all offsets should be uint32_ts i think */

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
#include "cyr_lock.h"
#include "map.h"
#include "retry.h"
#include "util.h"
#include "xmalloc.h"

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
 * during operation checkpoints will compress the data.  the data file
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
    int syncfd;

    /* logstart is where we start changes from on commit, where we truncate
       to on abort */
    unsigned logstart;
    unsigned logend;                    /* where to write to continue this txn */
};

struct dbengine {
    /* file data */
    char *fname;
    int fd;

    const char *map_base;
    size_t map_len;     /* mapped size */
    size_t map_size;    /* actual size */
    ino_t map_ino;

    /* header info */
    uint32_t version;
    uint32_t version_minor;
    uint32_t maxlevel;
    uint32_t curlevel;
    uint32_t listsize;
    uint32_t logstart;          /* where the log starts from last chkpnt */
    time_t last_recovery;

    /* tracking info */
    int lock_status;
    int is_open;
    int open_flags;
    struct txn *current_txn;
    struct timeval starttime;

    /* comparator function to use for sorting */
    int (*compar) (const char *s1, int l1, const char *s2, int l2);
};

struct db_list {
    struct dbengine *db;
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

static void getsyncfd(struct dbengine *db, struct txn *t)
{
    if (!use_osync) {
        t->syncfd = db->fd;
    } else if (t->syncfd == -1) {
        t->syncfd = open(db->fname, O_RDWR | O_DSYNC, 0666);
        assert(t->syncfd != -1); /* xxx do better error recovery */
    }
}

static void closesyncfd(struct dbengine *db __attribute__((unused)),
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
    int fd = -1, r = 0;
    uint32_t net32_time;

    snprintf(sfile, sizeof(sfile), "%s/skipstamp", dbdir);

    if (myflags & CYRUSDB_RECOVER) {
        struct stat sbuf;
        char cleanfile[1024];

        snprintf(cleanfile, sizeof(cleanfile), "%s/skipcleanshutdown", dbdir);

        /* if we had a clean shutdown, we don't need to run recovery on
         * everything */
        if (stat(cleanfile, &sbuf) == 0) {
            syslog(LOG_NOTICE, "skiplist: clean shutdown detected, starting normally");
            unlink(cleanfile);
            goto normal;
        }

        syslog(LOG_NOTICE, "skiplist: clean shutdown file missing, updating recovery stamp");

        /* set the recovery timestamp; all databases earlier than this
           time need recovery run when opened */
        global_recovery = time(NULL);
        fd = open(sfile, O_RDWR | O_CREAT, 0644);
        if (fd == -1) r = -1;

        if (r != -1) r = ftruncate(fd, 0);
        net32_time = htonl(global_recovery);
        if (r != -1) r = write(fd, &net32_time, 4);
        xclose(fd);

        if (r == -1) {
            syslog(LOG_ERR, "DBERROR: writing %s: %m", sfile);
            xclose(fd);
            return CYRUSDB_IOERROR;
        }
    } else {
normal:
        /* read the global recovery timestamp */

        fd = open(sfile, O_RDONLY, 0644);
        if (fd == -1) r = -1;
        if (r != -1) r = read(fd, &net32_time, 4);
        xclose(fd);

        if (r == -1) {
            syslog(LOG_ERR, "DBERROR: reading %s, assuming the worst: %m",
                   sfile);
            global_recovery = 0;
        } else {
            global_recovery = ntohl(net32_time);
        }
    }

    srand(time(NULL) * getpid());

    open_db = NULL;

    return 0;
}

enum {
    SKIPLIST_VERSION = 1,
    SKIPLIST_VERSION_MINOR = 2,
    SKIPLIST_MAXLEVEL = 20,
    SKIPLIST_MINREWRITE = 16834 /* don't rewrite logs smaller than this */
};

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

static int mycommit(struct dbengine *db, struct txn *tid);
static int myabort(struct dbengine *db, struct txn *tid);
static int mycheckpoint(struct dbengine *db);
static int myconsistent(struct dbengine *db, struct txn *tid, int locked);
static int recovery(struct dbengine *db, int flags);

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
       uint32_t t = htonl(DUMMY);
       uint32_t ks = 0;
       uint32_t ds = 0;
       uint32_t forward[db->maxlevel];
       uint32_t pad = -1;
   } */
#define DUMMY_OFFSET(db) (HEADER_SIZE)
#define DUMMY_PTR(db) ((db)->map_base + HEADER_SIZE)
#define DUMMY_SIZE(db) (4 * (3 + db->maxlevel + 1))

/* bump to the next multiple of 4 bytes */
#define ROUNDUP(num) (((num) + 3) & 0xFFFFFFFC)

#define TYPE(ptr) (ntohl(*((uint32_t *)(ptr))))
#define KEY(ptr) ((ptr) + 8)
#define KEYLEN(ptr) (ntohl(*((uint32_t *)((ptr) + 4))))
#define DATA(ptr) ((ptr) + 8 + ROUNDUP(KEYLEN(ptr)) + 4)
#define DATALEN(ptr) (ntohl(*((uint32_t *)((ptr) + 8 + ROUNDUP(KEYLEN(ptr))))))
#define FIRSTPTR(ptr) ((ptr) + 8 + ROUNDUP(KEYLEN(ptr)) + 4 + ROUNDUP(DATALEN(ptr)))

/* return a pointer to the pointer */
#define PTR(ptr, x) (FIRSTPTR(ptr) + 4 * (x))

/* FORWARD(ptr, x)
 * given a pointer to the start of the record, return the offset
 * corresponding to the xth pointer
 */
#define FORWARD(ptr, x) (ntohl(*((uint32_t *)(FIRSTPTR(ptr) + 4 * (x)))))

static int is_safe(struct dbengine *db, const char *ptr)
{
    if (ptr < db->map_base)
        return 0;
    if (ptr > db->map_base + db->map_size)
        return 0;

    return 1;
}

static unsigned LEVEL_safe(struct dbengine *db, const char *ptr)
{
    const uint32_t *p, *q;

    assert(TYPE(ptr) == DUMMY || TYPE(ptr) == INORDER || TYPE(ptr) == ADD);
    if (!is_safe(db, ptr + 12))
        return 0;
    if (!is_safe(db, ptr + 12 + KEYLEN(ptr)))
        return 0;
    p = q = (uint32_t *) FIRSTPTR(ptr);
    if (!is_safe(db, (const char *)p))
        return 0;
    while (*p != (uint32_t)-1) {
        p++;
        if (!is_safe(db, (const char *)p))
            return 0;
    }
    return p - q;
}

/* how big is this record? */
static unsigned RECSIZE_safe(struct dbengine *db, const char *ptr)
{
    int ret = 0;
    int level;
    switch (TYPE(ptr)) {
    case DUMMY:
    case INORDER:
    case ADD:
        level = LEVEL_safe(db, ptr);
        if (!level) {
            syslog(LOG_ERR, "IOERROR: skiplist RECSIZE not safe %s, offset %u",
                   db->fname, (unsigned)(ptr - db->map_base));
            return 0;
        }
        ret += 4;                       /* tag */
        ret += 4;                       /* keylen */
        ret += ROUNDUP(KEYLEN(ptr));    /* key */
        ret += 4;                       /* datalen */
        ret += ROUNDUP(DATALEN(ptr));   /* data */
        ret += 4 * level;               /* pointers */
        ret += 4;                       /* padding */
        break;

    case DELETE:
        if (!is_safe(db, ptr+8)) {
            syslog(LOG_ERR, "IOERROR: skiplist RECSIZE not safe %s, offset %u",
                   db->fname, (unsigned)(ptr - db->map_base));
            return 0;
        }
        ret += 8;
        break;

    case COMMIT:
        if (!is_safe(db, ptr+4)) {
            syslog(LOG_ERR, "IOERROR: skiplist RECSIZE not safe %s, offset %u",
                   db->fname, (unsigned)(ptr - db->map_base));
            return 0;
        }
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
static int SAFE_TO_APPEND(struct dbengine *db)
{
    /* check it's a multiple of 4 */
    if (db->map_size % 4) return 1;

    /* is it the beginning of the log? */
    if (db->map_size == db->logstart) {
        if (*((uint32_t *)(db->map_base + db->map_size - 4)) != htonl(-1)) {
            return 1;
        }
    }

    /* in the middle of the log somewhere */
    else {
        if (*((uint32_t *)(db->map_base + db->map_size - 4)) != htonl(COMMIT)) {
            return 1;
        }

        /* if it's not an end of a record or a delete */
        if (!((*((uint32_t *)(db->map_base + db->map_size - 8)) == htonl(-1)) ||
              (*((uint32_t *)(db->map_base + db->map_size -12)) == htonl(DELETE)))) {
            return 1;
        }
    }

    return 0;
}

static int newtxn(struct dbengine *db, struct txn **tidptr)
{
    struct txn *tid;
    /* is this file safe to append to?
     *
     * If it isn't, we need to run recovery. */
    if (SAFE_TO_APPEND(db)) {
        int r = recovery(db, RECOVERY_FORCE | RECOVERY_CALLER_LOCKED);
        if (r) return r;
    }

    /* create the transaction */
    tid = xmalloc(sizeof(struct txn));
    tid->syncfd = -1;
    tid->logstart = db->map_size;
/*    assert(t->logstart != -1);*/
    tid->logend = tid->logstart;
    db->current_txn = tid;

    /* pass it back out */
    *tidptr = tid;

    return 0;
}


static unsigned PADDING_safe(struct dbengine *db, const char *ptr)
{
    unsigned size = RECSIZE_safe(db, ptr);
    if (!size) return 0;
    return ntohl(*((uint32_t *)((ptr) + size - 4)));
}

/* given an open, mapped db, read in the header information */
static int read_header(struct dbengine *db)
{
    const char *dptr;

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

    db->version = ntohl(*((uint32_t *)(db->map_base + OFFSET_VERSION)));
    db->version_minor =
        ntohl(*((uint32_t *)(db->map_base + OFFSET_VERSION_MINOR)));
    if (db->version != SKIPLIST_VERSION) {
        syslog(LOG_ERR, "skiplist: version mismatch: %s has version %d.%d",
               db->fname, db->version, db->version_minor);
        return CYRUSDB_IOERROR;
    }

    db->maxlevel = ntohl(*((uint32_t *)(db->map_base + OFFSET_MAXLEVEL)));

    if (db->maxlevel > SKIPLIST_MAXLEVEL) {
        syslog(LOG_ERR,
               "skiplist %s: MAXLEVEL %d in database beyond maximum %d\n",
               db->fname, db->maxlevel, SKIPLIST_MAXLEVEL);
        return CYRUSDB_IOERROR;
    }

    db->curlevel = ntohl(*((uint32_t *)(db->map_base + OFFSET_CURLEVEL)));

    if (db->curlevel > db->maxlevel) {
        syslog(LOG_ERR,
               "skiplist %s: CURLEVEL %d in database beyond maximum %d\n",
               db->fname, db->curlevel, db->maxlevel);
        return CYRUSDB_IOERROR;
    }

    db->listsize = ntohl(*((uint32_t *)(db->map_base + OFFSET_LISTSIZE)));
    db->logstart = ntohl(*((uint32_t *)(db->map_base + OFFSET_LOGSTART)));
    db->last_recovery =
        ntohl(*((uint32_t *)(db->map_base + OFFSET_LASTRECOVERY)));

    /* verify dummy node */
    dptr = DUMMY_PTR(db);

    if (TYPE(dptr) != DUMMY) {
        syslog(LOG_ERR, "DBERROR: %s: first node not type DUMMY",
               db->fname);
        return CYRUSDB_IOERROR;
    }
    if (KEYLEN(dptr) != 0) {
        syslog(LOG_ERR, "DBERROR: %s: DUMMY has non-zero KEYLEN",
               db->fname);
        return CYRUSDB_IOERROR;
    }
    if (DATALEN(dptr) != 0) {
        syslog(LOG_ERR, "DBERROR: %s: DUMMY has non-zero DATALEN",
               db->fname);
        return CYRUSDB_IOERROR;
    }
    if (LEVEL_safe(db, dptr) != db->maxlevel) {
        syslog(LOG_ERR, "DBERROR: %s: DUMMY level(%d) != db->maxlevel(%d)",
               db->fname, LEVEL_safe(db, dptr), db->maxlevel);
        return CYRUSDB_IOERROR;
    }

    return 0;
}

/* given an open, mapped db, locked db,
   write the header information */
static int write_header(struct dbengine *db)
{
    char buf[HEADER_SIZE];

    assert (db->lock_status == WRITELOCKED);
    memcpy(buf + 0, HEADER_MAGIC, HEADER_MAGIC_SIZE);
    *((uint32_t *)(buf + OFFSET_VERSION)) = htonl(db->version);
    *((uint32_t *)(buf + OFFSET_VERSION_MINOR)) = htonl(db->version_minor);
    *((uint32_t *)(buf + OFFSET_MAXLEVEL)) = htonl(db->maxlevel);
    *((uint32_t *)(buf + OFFSET_CURLEVEL)) = htonl(db->curlevel);
    *((uint32_t *)(buf + OFFSET_LISTSIZE)) = htonl(db->listsize);
    *((uint32_t *)(buf + OFFSET_LOGSTART)) = htonl(db->logstart);
    *((uint32_t *)(buf + OFFSET_LASTRECOVERY)) = htonl(db->last_recovery);

    /* write it out */
    lseek(db->fd, 0, SEEK_SET);
    if (retry_write(db->fd, buf, HEADER_SIZE) != HEADER_SIZE) {
        syslog(LOG_ERR, "DBERROR: writing skiplist header for %s: %m",
               db->fname);
        return CYRUSDB_IOERROR;
    }

    return 0;
}

/* make sure our mmap() is big enough */
static int update_lock(struct dbengine *db, struct txn *txn)
{
    /* txn->logend is the current size of the file */
    assert (db->is_open && db->lock_status == WRITELOCKED);
    map_refresh(db->fd, 0, &db->map_base, &db->map_len, txn->logend,
                db->fname, 0);
    db->map_size = txn->logend;

    return 0;
}

static int write_lock(struct dbengine *db, const char *altname)
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
    gettimeofday(&db->starttime, 0);

    map_refresh(db->fd, 0, &db->map_base, &db->map_len, sbuf.st_size,
                fname, 0);

    if (db->is_open) {
        /* reread header */
        read_header(db);
    }

    /* printf("%d: write lock: %d\n", getpid(), db->map_ino); */

    return 0;
}

static int read_lock(struct dbengine *db)
{
    struct stat sbuf, sbuffile;
    int newfd = -1;

    assert(db->lock_status == UNLOCKED);
    for (;;) {
        if (lock_shared(db->fd, db->fname) < 0) {
            syslog(LOG_ERR, "IOERROR: lock_shared %s: %m", db->fname);
            return CYRUSDB_IOERROR;
        }

        if (fstat(db->fd, &sbuf) == -1) {
            syslog(LOG_ERR, "IOERROR: fstat %s: %m", db->fname);
            lock_unlock(db->fd, db->fname);
            return CYRUSDB_IOERROR;
        }

        if (stat(db->fname, &sbuffile) == -1) {
            syslog(LOG_ERR, "IOERROR: stat %s: %m", db->fname);
            lock_unlock(db->fd, db->fname);
            return CYRUSDB_IOERROR;
        }
        if (sbuf.st_ino == sbuffile.st_ino) break;

        newfd = open(db->fname, O_RDWR, 0644);
        if (newfd == -1) {
            syslog(LOG_ERR, "IOERROR: open %s: %m", db->fname);
            lock_unlock(db->fd, db->fname);
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
    gettimeofday(&db->starttime, 0);

    /* printf("%d: read lock: %d\n", getpid(), db->map_ino); */

    map_refresh(db->fd, 0, &db->map_base, &db->map_len, sbuf.st_size,
                db->fname, 0);

    if (db->is_open) {
        /* reread header */
        read_header(db);
    }

    return 0;
}

static int unlock(struct dbengine *db)
{
    struct timeval endtime;
    double timediff;

    if (db->lock_status == UNLOCKED) {
        syslog(LOG_NOTICE, "skiplist: unlock while not locked");
    }
    if (lock_unlock(db->fd, db->fname) < 0) {
        syslog(LOG_ERR, "IOERROR: lock_unlock %s: %m", db->fname);
        return CYRUSDB_IOERROR;
    }
    db->lock_status = UNLOCKED;

    gettimeofday(&endtime, 0);
    timediff = timesub(&db->starttime, &endtime);
    if (timediff > 1.0) {
        syslog(LOG_NOTICE, "skiplist: longlock %s for %0.1f seconds",
               db->fname, timediff);
    }

    /* printf("%d: unlock: %d\n", getpid(), db->map_ino); */

    return 0;
}

static int lock_or_refresh(struct dbengine *db, struct txn **tidptr)
{
    int r;

    assert(db);

    if (!tidptr) {
        /* just grab a readlock */
        r = read_lock(db);
        if (r) return r;

        /* start tracking the lock time */
        gettimeofday(&db->starttime, 0);

        return 0;
    }

    if (*tidptr) {
        /* check that the DB agrees that we're in this transaction */
        assert(db->current_txn == *tidptr);

        /* just update the active transaction */
        return update_lock(db, *tidptr);
    }

    /* check that the DB isn't in a transaction */
    assert(db->current_txn == NULL);

    /* grab a r/w lock */
    r = write_lock(db, NULL);
    if (r) return r;

    /* start the transaction */
    r = newtxn(db, tidptr);
    if (r) return r;

    /* start tracking the lock time */
    gettimeofday(&db->starttime, 0);

    return 0;
}

static int dispose_db(struct dbengine *db)
{
    if (!db) return 0;

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

/* NOTE: this function compares with the SIGNED CHAR value of
 * the individual characters.  This is a pretty bogus sort order,
 * but for backwards compatibility reasons we're stuck with it
 * for skiplist files at least */
static int compare_signed(const char *s1, int l1, const char *s2, int l2)
{
    int min = l1 < l2 ? l1 : l2;
    int cmp = 0;

    while (min-- > 0 && (cmp = *s1 - *s2) == 0) {
        s1++;
        s2++;
    }
    if (min >= 0) return cmp;
    if (l1 > l2) return 1;
    if (l2 > l1) return -1;
    return 0;
}

static int myopen(const char *fname, int flags, struct dbengine **ret, struct txn **mytid)
{
    struct dbengine *db;
    struct db_list *list_ent = open_db;
    int r;

    while (list_ent && strcmp(list_ent->db->fname, fname)) {
        list_ent = list_ent->next;
    }
    if (list_ent) {
        /* we already have this DB open! */
        syslog(LOG_NOTICE, "skiplist: %s is already open %d time%s, returning object",
               fname, list_ent->refcount, list_ent->refcount == 1 ? "" : "s");
        if (list_ent->db->current_txn)
            return CYRUSDB_LOCKED;
        if (mytid) {
            r = lock_or_refresh(list_ent->db, mytid);
            if (r) return r;
        }
        ++list_ent->refcount;
        *ret = list_ent->db;
        return 0;
    }

    db = (struct dbengine *) xzmalloc(sizeof(struct dbengine));
    db->fd = -1;
    db->fname = xstrdup(fname);
    db->compar = (flags & CYRUSDB_MBOXSORT) ? bsearch_ncompare_mbox : compare_signed;
    db->open_flags = (flags & ~CYRUSDB_CREATE);

    db->fd = open(fname, O_RDWR, 0644);
    if (db->fd == -1 && errno == ENOENT) {
        if (!(flags & CYRUSDB_CREATE)) {
            dispose_db(db);
            return CYRUSDB_NOTFOUND;
        }
        if (cyrus_mkdir(fname, 0755) == -1) {
            dispose_db(db);
            return CYRUSDB_IOERROR;
        }
        db->fd = open(fname, O_RDWR | O_CREAT, 0644);
    }

    if (db->fd == -1) {
        syslog(LOG_ERR, "IOERROR: opening %s: %m", fname);
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
            uint32_t *buf = (uint32_t *) xzmalloc(dsize);

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
        if (r) {
            dispose_db(db);
            return r;
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

    return mytid ? lock_or_refresh(db, mytid) : 0;
}

static int myclose(struct dbengine *db)
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

/* returns the offset to the node asked for, or the node after it
   if it doesn't exist.
   if previous is set, finds the last node < key */
static const char *find_node(struct dbengine *db,
                             const char *key, size_t keylen,
                             unsigned *updateoffsets)
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

static int myfetch(struct dbengine *db,
                   const char *key, size_t keylen,
                   const char **data, size_t *datalen,
                   struct txn **tidptr)
{
    const char *ptr;
    int r = 0;

    assert(db != NULL && key != NULL);

    if (data) *data = NULL;
    if (datalen) *datalen = 0;

    /* Hacky workaround:
     *
     * If no transaction was passed, but we're in a transaction,
     * then just do the read within that transaction.
     */
    if (!tidptr && db->current_txn != NULL) {
        tidptr = &(db->current_txn);
    }

    if (tidptr) {
        /* make sure we're write locked and up to date */
        if ((r = lock_or_refresh(db, tidptr)) < 0) {
            return r;
        }
    } else {
        /* grab a r lock */
        if ((r = read_lock(db)) < 0) {
            return r;
        }
    }

    ptr = find_node(db, key, keylen, 0);

    if (ptr == db->map_base || db->compar(KEY(ptr), KEYLEN(ptr), key, keylen)) {
        /* failed to find key/keylen */
        r = CYRUSDB_NOTFOUND;
    } else {
        if (datalen) *datalen = DATALEN(ptr);
        if (data) *data = DATA(ptr);
    }

    if (!tidptr) {
        /* release read lock */
        int r1;
        if ((r1 = unlock(db)) < 0) {
            return r1;
        }
    }

    return r;
}

/* foreach allows for subsidiary mailbox operations in 'cb'.
   if there is a txn, 'cb' must make use of it.
*/
static int myforeach(struct dbengine *db,
                     const char *prefix, size_t prefixlen,
                     foreach_p *goodp,
                     foreach_cb *cb, void *rock,
                     struct txn **tidptr)
{
    const char *ptr;
    char *savebuf = NULL;
    size_t savebuflen = 0;
    size_t savebufsize;
    int r = 0, cb_r = 0;
    int need_unlock = 0;

    assert(db != NULL);
    assert(cb);

    /* Hacky workaround:
     *
     * If no transaction was passed, but we're in a transaction,
     * then just do the read within that transaction.
     */
    if (!tidptr && db->current_txn != NULL) {
        tidptr = &(db->current_txn);
    }

    if (tidptr) {
        /* make sure we're write locked and up to date */
        if ((r = lock_or_refresh(db, tidptr)) < 0) {
            return r;
        }
    } else {
        /* grab a r lock */
        if ((r = read_lock(db)) < 0) {
            return r;
        }
        need_unlock = 1;
    }

    ptr = find_node(db, prefix, prefixlen, 0);

    while (ptr != db->map_base) {
        /* does it match prefix? */
        if (KEYLEN(ptr) < (uint32_t) prefixlen) break;
        if (prefixlen && db->compar(KEY(ptr), prefixlen, prefix, prefixlen)) break;

        if (!goodp ||
            goodp(rock, KEY(ptr), KEYLEN(ptr), DATA(ptr), DATALEN(ptr))) {
            ino_t ino = db->map_ino;
            unsigned long sz = db->map_size;

            if (!tidptr) {
                /* release read lock */
                if ((r = unlock(db)) < 0) {
                    return r;
                }
                need_unlock = 0;
            }

            /* save KEY, KEYLEN */
            if (!savebuf || KEYLEN(ptr) > savebuflen) {
                savebuflen = KEYLEN(ptr) + 1024;
                savebuf = xrealloc(savebuf, savebuflen);
            }
            memcpy(savebuf, KEY(ptr), KEYLEN(ptr));
            savebufsize = KEYLEN(ptr);

            /* make callback */
            cb_r = cb(rock, KEY(ptr), KEYLEN(ptr), DATA(ptr), DATALEN(ptr));
            if (cb_r) break;

            if (!tidptr) {
                /* grab a r lock */
                if ((r = read_lock(db)) < 0) {
                    free(savebuf);
                    return r;
                }
                need_unlock = 1;
            } else {
                /* make sure we're up to date */
                update_lock(db, *tidptr);
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

    free(savebuf);

    if (need_unlock) {
        /* release read lock */
        if ((r = unlock(db)) < 0) {
            return r;
        }
    }

    return r ? r : cb_r;
}

static unsigned int randlvl(struct dbengine *db)
{
    unsigned int lvl = 1;

    while ((((float) rand() / (float) (RAND_MAX)) < PROB)
           && (lvl < db->maxlevel)) {
        lvl++;
    }
    /* syslog(LOG_DEBUG, "picked level %d", lvl); */

    return lvl;
}

static int mystore(struct dbengine *db,
                   const char *key, size_t keylen,
                   const char *data, size_t datalen,
                   struct txn **tidptr, int overwrite)
{
    const char *ptr;
    uint32_t klen;
    uint32_t dlen;
    struct iovec iov[50];
    unsigned lvl;
    unsigned i;
    unsigned num_iov;
    struct txn *tid;
    struct txn *localtid = NULL;
    uint32_t endpadding = htonl(-1);
    uint32_t zeropadding[4] = { 0, 0, 0, 0 };
    unsigned updateoffsets[SKIPLIST_MAXLEVEL+1];
    unsigned newoffsets[SKIPLIST_MAXLEVEL+1];
    uint32_t addrectype = htonl(ADD);
    uint32_t delrectype = htonl(DELETE);
    uint32_t todelete;
    unsigned newoffset;
    uint32_t netnewoffset;
    int r;

    assert(db != NULL);
    assert(key && keylen);
    if (!data)
        datalen = 0;

    /* not keeping the transaction, just create one local to
     * this function */
    if (!tidptr) {
        tidptr = &localtid;
    }

    /* make sure we're write locked and up to date */
    if ((r = lock_or_refresh(db, tidptr)) < 0) {
        return r;
    }

    tid = *tidptr; /* consistent naming is nice */

    if (be_paranoid) {
        assert(myconsistent(db, tid, 1) == 0);
    }

    num_iov = 0;

    newoffset = tid->logend;
    ptr = find_node(db, key, keylen, updateoffsets);
    if (ptr != db->map_base &&
        !db->compar(KEY(ptr), KEYLEN(ptr), key, keylen)) {

        if (!overwrite) {
            myabort(db, tid);   /* releases lock */
            return CYRUSDB_EXISTS;
        }
        /* replace with an equal height node */
        lvl = LEVEL_safe(db, ptr);

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
    if (datalen) {
        WRITEV_ADD_TO_IOVEC(iov, num_iov, (char *) data, datalen);
    }
    if (ROUNDUP(datalen) - datalen > 0) {
        WRITEV_ADD_TO_IOVEC(iov, num_iov, (char *) zeropadding,
                            ROUNDUP(datalen) - datalen);
    }
    WRITEV_ADD_TO_IOVEC(iov, num_iov, (char *) newoffsets, 4 * lvl);
    WRITEV_ADD_TO_IOVEC(iov, num_iov, (char *) &endpadding, 4);

    getsyncfd(db, tid);
    lseek(tid->syncfd, tid->logend, SEEK_SET);
    r = retry_writev(tid->syncfd, iov, num_iov);
    if (r < 0) {
        syslog(LOG_ERR, "DBERROR: retry_writev(): %m");
        myabort(db, tid);
        return CYRUSDB_IOERROR;
    }
    tid->logend += r;           /* update where to write next */

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

    if (be_paranoid) {
        assert(myconsistent(db, tid, 1) == 0);
    }

    if (localtid) {
        /* commit the store, which releases the write lock */
        r = mycommit(db, tid);
        if (r) return r;
    }

    return 0;
}

static int create(struct dbengine *db,
                  const char *key, size_t keylen,
                  const char *data, size_t datalen,
                  struct txn **tid)
{
    return mystore(db, key, keylen, data, datalen, tid, 0);
}

static int store(struct dbengine *db,
                 const char *key, size_t keylen,
                 const char *data, size_t datalen,
                 struct txn **tid)
{
    return mystore(db, key, keylen, data, datalen, tid, 1);
}

static int mydelete(struct dbengine *db,
                    const char *key, size_t keylen,
                    struct txn **tidptr, int force __attribute__((unused)))
{
    const char *ptr;
    uint32_t delrectype = htonl(DELETE);
    unsigned updateoffsets[SKIPLIST_MAXLEVEL+1];
    uint32_t offset;
    uint32_t writebuf[2];
    struct txn *tid, *localtid = NULL;
    unsigned i;
    int r;

    /* not keeping the transaction, just create one local to
     * this function */
    if (!tidptr) {
        tidptr = &localtid;
    }

    /* make sure we're write locked and up to date */
    if ((r = lock_or_refresh(db, tidptr)) < 0) {
        return r;
    }

    tid = *tidptr; /* consistent naming is nice */

    if (be_paranoid) {
        assert(myconsistent(db, tid, 1) == 0);
    }

    ptr = find_node(db, key, keylen, updateoffsets);
    if (ptr != db->map_base &&
        !db->compar(KEY(ptr), KEYLEN(ptr), key, keylen)) {
        /* gotcha */
        offset = ptr - db->map_base;

        /* log the deletion */
        getsyncfd(db, tid);
        lseek(tid->syncfd, tid->logend, SEEK_SET);
        writebuf[0] = delrectype;
        writebuf[1] = htonl(offset);

        /* update end-of-log */
        r = retry_write(tid->syncfd, (char *) writebuf, 8);
        if (r < 0) {
            syslog(LOG_ERR, "DBERROR: retry_write(): %m");
            myabort(db, tid);
            return CYRUSDB_IOERROR;
        }
        tid->logend += r;

        /* update pointers after writing record so abort is guaranteed to
         * see which records need reverting */
        for (i = 0; i < db->curlevel; i++) {
            uint32_t netnewoffset;

            if (FORWARD(db->map_base + updateoffsets[i], i) != offset) {
                break;
            }
            netnewoffset = htonl(FORWARD(ptr, i));
            lseek(db->fd,
                  PTR(db->map_base + updateoffsets[i], i) - db->map_base,
                  SEEK_SET);
            retry_write(db->fd, (char *) &netnewoffset, 4);
        }
    }

    if (be_paranoid) {
        assert(myconsistent(db, tid, 1) == 0);
    }

    if (localtid) {
        /* commit the store, which releases the write lock */
        mycommit(db, tid);
    }

    return 0;
}

static int mycommit(struct dbengine *db, struct txn *tid)
{
    uint32_t commitrectype = htonl(COMMIT);
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
    if (!r && !(db->open_flags & CYRUSDB_NOCOMPACT) &&
        tid->logend > (2 * db->logstart + SKIPLIST_MINREWRITE)) {
        r = mycheckpoint(db);
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

        /* free tid */
        free(tid);
    }

    return r;
}

static int myabort(struct dbengine *db, struct txn *tid)
{
    const char *ptr;
    unsigned updateoffsets[SKIPLIST_MAXLEVEL+1];
    unsigned offset;
    unsigned i;
    int r = 0;

    assert(db && tid);

    assert(db->current_txn == tid);

    /* look at the log entries we've written, and undo their effects */
    while (tid->logstart != tid->logend) {
        /* update the mmap so we can see the log entries we need to remove */
        update_lock(db, tid);

        /* find the last log entry */
        for (offset = tid->logstart, ptr = db->map_base + offset;
             offset + RECSIZE_safe(db, ptr) != (uint32_t) tid->logend;
             offset += RECSIZE_safe(db, ptr), ptr = db->map_base + offset) ;

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
                uint32_t netnewoffset;

                if (FORWARD(db->map_base + updateoffsets[i], i) != offset) {
                    break;
                }

                netnewoffset = htonl(FORWARD(ptr, i));
                lseek(db->fd,
                      PTR(db->map_base + updateoffsets[i], i) - db->map_base,
                      SEEK_SET);
                retry_write(db->fd, (char *) &netnewoffset, 4);
            }
            break;
        case DELETE:
        {
            unsigned lvl;
            uint32_t netnewoffset;
            const char *q;

            /* re-add this record.  it can't exist right now. */
            netnewoffset = *((uint32_t *)(ptr + 4));
            q = db->map_base + ntohl(netnewoffset);
            lvl = LEVEL_safe(db, q);
            (void) find_node(db, KEY(q), KEYLEN(q), updateoffsets);
            for (i = 0; i < lvl; i++) {
                /* the current pointers FROM this node are correct,
                   so we just have to update 'updateoffsets' */
                lseek(db->fd,
                      PTR(db->map_base + updateoffsets[i], i) - db->map_base,
                      SEEK_SET);
                retry_write(db->fd, (char *) &netnewoffset, 4);
            }
            break;
        }
        }

        /* remove looking at this */
        tid->logend -= RECSIZE_safe(db, ptr);
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
    free(tid);

    db->current_txn = NULL;

    return 0;
}

/* compress 'db'. if 'locked != 0', the database is already R/W locked and
   will be returned as such. */
static int mycheckpoint(struct dbengine *db)
{
    char fname[1024];
    int oldfd;
    struct iovec iov[50];
    unsigned num_iov;
    unsigned updateoffsets[SKIPLIST_MAXLEVEL+1];
    const char *ptr;
    unsigned offset;
    int r = 0;
    uint32_t iorectype = htonl(INORDER);
    unsigned i;
    clock_t start = sclock();

    /* we need the latest and greatest data */
    assert(db->is_open && db->lock_status == WRITELOCKED);
    map_refresh(db->fd, 0, &db->map_base, &db->map_len, MAP_UNKNOWN_LEN,
                db->fname, 0);

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
        db->fd = oldfd;
        return CYRUSDB_IOERROR;
    }

    /* truncate it just in case! */
    r = ftruncate(db->fd, 0);
    if (r < 0) {
        syslog(LOG_ERR, "DBERROR: skiplist checkpoint %s: ftruncate %m", fname);
        db->fd = oldfd;
        return CYRUSDB_IOERROR;
    }

    /* write dummy record */
    if (!r) {
        int dsize = DUMMY_SIZE(db);
        uint32_t *buf = (uint32_t *) xzmalloc(dsize);

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
        unsigned newoffset;
        uint32_t netnewoffset;

        ptr = db->map_base + offset;
        lvl = LEVEL_safe(db, ptr);
        db->listsize++;

        num_iov = 0;
        WRITEV_ADD_TO_IOVEC(iov, num_iov, (char *) &iorectype, 4);
        /* copy all but the rectype from the record */
        WRITEV_ADD_TO_IOVEC(iov, num_iov, (char *) ptr + 4, RECSIZE_safe(db, ptr) - 4);

        newoffset = lseek(db->fd, 0, SEEK_END);
        netnewoffset = htonl(newoffset);
        r = retry_writev(db->fd, iov, num_iov);
        if (r < 0) {
            r = CYRUSDB_IOERROR;
        } else {
            r = 0;
        }
        for (i = 0; !r && i < lvl; i++) {
            /* update pointers */
            off_t p = lseek(db->fd, updateoffsets[i], SEEK_SET);
            if (p < 0) {
                r = CYRUSDB_IOERROR;
                break;
            } else {
                r = 0;
            }

            r = retry_write(db->fd, (char *) &netnewoffset, 4);
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
        uint32_t netnewoffset = htonl(0);

        off_t p = lseek(db->fd, updateoffsets[i], SEEK_SET);
        if (p < 0) {
            r = CYRUSDB_IOERROR;
            break;
        } else {
            r = 0;
        }

        r = retry_write(db->fd, (char *) &netnewoffset, 4);
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
    else {
        struct stat sbuf;

        /* remove content of old file so it doesn't sit around using disk */
        r = ftruncate(oldfd, 0);

        /* release old write lock */
        close(oldfd);

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

    syslog(LOG_INFO,
           "skiplist: checkpointed %s (%d record%s, %d bytes) in %2.3f sec",
           db->fname, db->listsize, db->listsize == 1 ? "" : "s",
           db->logstart, (sclock() - start) / (double) CLOCKS_PER_SEC);

    return r;
}

/* dump the database.
   if detail == 1, dump all records.
   if detail == 2, also dump pointers for active records.
   if detail == 3, dump all records/all pointers.
*/
static int dump(struct dbengine *db, int detail __attribute__((unused)))
{
    const char *ptr, *end;
    unsigned i;

    read_lock(db);

    ptr = db->map_base + DUMMY_OFFSET(db);
    end = db->map_base + db->map_size;
    while (ptr < end) {
        printf("%04lX: ", (unsigned long) (ptr - db->map_base));
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
                   KEYLEN(ptr), DATALEN(ptr), LEVEL_safe(db, ptr));
            printf("\t");
            for (i = 0; i < LEVEL_safe(db, ptr); i++) {
                printf("%04X ", FORWARD(ptr, i));
            }
            printf("\n");
            break;

        case DELETE:
            printf("offset=%04X\n", ntohl(*((uint32_t *)(ptr + 4))));
            break;

        case COMMIT:
            printf("\n");
            break;
        }

        ptr += RECSIZE_safe(db, ptr);
    }

    unlock(db);
    return 0;
}

static int consistent(struct dbengine *db)
{
    return myconsistent(db, NULL, 0);
}

/* perform some basic consistency checks */
static int myconsistent(struct dbengine *db, struct txn *tid, int locked)
{
    const char *ptr;
    uint32_t offset;

    assert(db->current_txn == tid); /* could both be null */

    if (!locked) read_lock(db);
    else if (tid) update_lock(db, tid);

    offset = FORWARD(db->map_base + DUMMY_OFFSET(db), 0);
    while (offset != 0) {
        unsigned i;

        ptr = db->map_base + offset;

        for (i = 0; i < LEVEL_safe(db, ptr); i++) {
            offset = FORWARD(ptr, i);

            if (offset > db->map_size) {
                syslog(LOG_ERR,
                        "skiplist inconsistent: %04X: ptr %d is %04X; "
                        "eof is %04X\n",
                        (unsigned int) (ptr - db->map_base),
                        i, offset, (unsigned int) db->map_size);
                if (!locked) unlock(db);
                return CYRUSDB_INTERNAL;
            }

            if (offset != 0) {
                /* check to see that ptr < ptr -> next */
                const char *q = db->map_base + offset;
                int cmp;

                cmp = db->compar(KEY(ptr), KEYLEN(ptr), KEY(q), KEYLEN(q));
                if (cmp >= 0) {
                    syslog(LOG_ERR,
                            "skiplist inconsistent: %04X: ptr %d is %04X; "
                            "db->compar() = %d\n",
                            (unsigned int) (ptr - db->map_base),
                            i,
                            offset, cmp);
                    if (!locked) unlock(db);
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
static int recovery(struct dbengine *db, int flags)
{
    const char *ptr, *keyptr;
    unsigned filesize = db->map_size;
    unsigned updateoffsets[SKIPLIST_MAXLEVEL+1];
    uint32_t offset, offsetnet, myoff = 0;
    int r = 0;
    int need_checkpoint = libcyrus_config_getswitch(CYRUSOPT_SKIPLIST_ALWAYS_CHECKPOINT);
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
    if (!r && LEVEL_safe(db, ptr) != db->maxlevel) {
        r = CYRUSDB_IOERROR;
        syslog(LOG_ERR,
               "DBERROR: skiplist recovery %s: dummy node level: %d != %d",
               db->fname, LEVEL_safe(db, ptr), db->maxlevel);
    }

    for (i = 0; i < db->maxlevel; i++) {
        /* header_size + 4 (rectype) + 4 (ksize) + 4 (dsize)
           + 4 * i */
        updateoffsets[i] = DUMMY_OFFSET(db) + 12 + 4 * i;
    }

    /* reset the data that was written INORDER by the last checkpoint */
    offset = DUMMY_OFFSET(db) + DUMMY_SIZE(db);
    while (!r && (offset < filesize)
              && TYPE(db->map_base + offset) == INORDER) {
        ptr = db->map_base + offset;
        offsetnet = htonl(offset);

        db->listsize++;

        /* xxx check \0 fill on key */

        /* xxx check \0 fill on data */

        /* update previous pointers, record these for updating */
        for (i = 0; !r && i < LEVEL_safe(db, ptr); i++) {
            off_t p = lseek(db->fd, updateoffsets[i], SEEK_SET);
            if (p < 0) {
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

        if (!r) {
            unsigned size = RECSIZE_safe(db, ptr);
            if (!size) {
                syslog(LOG_ERR, "skiplist recovery %s: damaged record at %u, truncating here",
                       db->fname, offset);
                filesize = offset;
                break;
            }

            if (PADDING_safe(db, ptr) != (uint32_t) -1) {
                syslog(LOG_ERR, "DBERROR: %s: offset %04X padding not -1",
                       db->fname, offset);
                filesize = offset;
                break;
            }

            offset += size;
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

            off_t p = lseek(db->fd, updateoffsets[i], SEEK_SET);
            if (p < 0) {
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
    while (!r && offset < filesize) {
        const char *p, *q;

        /* refresh map, so we see the writes we've just done */
        map_refresh(db->fd, 0, &db->map_base, &db->map_len, db->map_size,
                    db->fname, 0);

        ptr = db->map_base + offset;

        /* bugs in recovery truncates could have left some bogus zeros here */
        if (TYPE(ptr) == 0) {
            int orig = offset;
            while (TYPE(ptr) == 0 && offset < filesize) {
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
            unsigned size = RECSIZE_safe(db, ptr);
            if (!size) break;
            offset += size;
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
        q = db->map_base + filesize;
        p = ptr;
        for (;;) {
            unsigned size = RECSIZE_safe(db, p);
            if (!size) {
                /* hmm, we can't trust this transaction */
                syslog(LOG_ERR,
                       "DBERROR: skiplist recovery %s: found a RECSIZE of 0, "
                       "truncating corrupted file instead of looping forever...",
                       db->fname);
                p = q;
                break;
            }
            p += size;
            if (p >= q) break;
            if (TYPE(p) == COMMIT) break;
        }
        if (p >= q) {
            syslog(LOG_NOTICE,
                   "skiplist recovery %s: found partial txn, not replaying",
                   db->fname);

            filesize = offset;

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

            myoff = ntohl(*((uint32_t *)(ptr + 4)));
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
            uint32_t newoffsets[SKIPLIST_MAXLEVEL+1];

            if (keyptr) {
                syslog(LOG_ERR,
                       "DBERROR: skiplist recovery %s: ADD at %04X exists, replacing",
                       db->fname, offset);
                need_checkpoint = 1;
            } else {
                db->listsize++;
            }
            offsetnet = htonl(offset);

            lvl = LEVEL_safe(db, ptr);
            if (lvl > SKIPLIST_MAXLEVEL) {
                syslog(LOG_ERR,
                       "DBERROR: skiplist recovery %s: node claims level %d (greater than max %d)",
                       db->fname, lvl, SKIPLIST_MAXLEVEL);
                r = CYRUSDB_IOERROR;
            } else {
                /* NOTE - in the bogus case where a record with the same key already
                 * exists, there are three possible cases:
                 * lvl == LEVEL_safe(db, keyptr)
                 *    * trivial: all to me, all mine to keyptr's FORWARD
                 * lvl > LEVEL_safe(db, keyptr)  -
                 *    * all updateoffsets values should point to me
                 *    * up until LEVEL_safe(db, keyptr) set to keyptr's next values
                 *      (updateoffsets[i] should be keyptr in these cases)
                 *      then point all my higher pointers are updateoffsets[i]'s
                 *      FORWARD instead.
                 * lvl < LEVEL_safe(db, keyptr)
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
                    if (keyptr && i < LEVEL_safe(db, keyptr)) {
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

                if (keyptr && lvl < LEVEL_safe(db, keyptr)) {
                    uint32_t newoffsetnet;
                    for (i = lvl; i < LEVEL_safe(db, keyptr); i++) {
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
        unsigned size = RECSIZE_safe(db, ptr);
        if (!size) break;
        offset += size;
    }

    /* didn't read the exact end?  We should truncate */
    if (offset < db->map_size) {
        if (ftruncate(db->fd, offset) < 0) {
            syslog(LOG_ERR,
                   "DBERROR: skiplist recovery %s: ftruncate: %m",
                   db->fname);
            r = CYRUSDB_IOERROR;
        }

        /* set the map size back as well */
        db->map_size = offset;
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
               (long unsigned)db->map_size, diff, diff == 1 ? "" : "s");
    }

    if (!r && need_checkpoint) {
        /* refresh map, so we see the writes we've just done */
        map_refresh(db->fd, 0, &db->map_base, &db->map_len, db->map_size,
                    db->fname, 0);
        r = mycheckpoint(db);
    }

    if (r || !(flags & RECOVERY_CALLER_LOCKED)) {
        unlock(db);
    }

    return r;
}

/* skiplist compar function is set at open */
static int mycompar(struct dbengine *db, const char *a, int alen,
                    const char *b, int blen)
{
    return db->compar(a, alen, b, blen);
}


EXPORTED struct cyrusdb_backend cyrusdb_skiplist =
{
    "skiplist",                 /* name */

    &myinit,
    &cyrusdb_generic_done,
    &cyrusdb_generic_sync,
    &cyrusdb_generic_archive,
    &cyrusdb_generic_unlink,

    &myopen,
    &myclose,

    &myfetch,
    &myfetch,
    NULL,

    &myforeach,
    &create,
    &store,
    &mydelete,

    &mycommit,
    &myabort,

    &dump,
    &consistent,
    &mycheckpoint,
    &mycompar
};
