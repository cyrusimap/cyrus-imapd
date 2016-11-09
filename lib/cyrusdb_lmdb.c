/*  cyrusdb_lmdb: a backend built on Lightning Memory-Mapped Database (LMDB)
 *
 * Copyright (c) 2016 Carnegie Mellon University.  All rights reserved.
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

/*
 * This backend implements the Cyrus DB API on top of the Lightning
 * Memory-Mapped Database (LMDB).
 *
 * These two APIs work together nicely most of the time, but there are
 * a few caveats:
 *
 * - LMDB requires database environments to be set to a (user-configurable)
 *   maximum size. This backend sets a reasonable high default size (see
 *   maxdbsize). Cyrus installations may override this by setting the
 *   environment variable CYRUSDB_LMDB_MAXSIZE. The value of this variable
 *   must be an integer, optionally followed (without space) by "mb" or "gb"
 *   to define the maximum size in bytes, megabytes or gigabytes. The size
 *   should be a multiple of the OS page size.
 *
 * - Callbacks within foreach might call a database engine without a
 *   transaction, although the foreach operates within an existing or
 *   newly created transaction. But LMDB only allows one unnested
 *   transaction per thread.
 *   As a consequence, the database engine has to keep track of the
 *   current transaction and reuses that one if no transaction has been
 *   supplied by caller. This is similar to the inner workings of the
 *   skiplist and twoskip backends.
 *
 * - Callbacks within foreach might update the currently seeked data
 *   item. To protect the database from corruption, the cursor is
 *   invalidated and reseeked after the operation, causing foreach()
 *   performance degrade to O(m*log n), where m denotes the iteration
 *   count and n the number of items in the database.
 *
 * - LMDB transactions operate on database environments and database
 *   environments may contain multiple databases. A single writer
 *   locks all other operations within this environment. To avoid
 *   (already observed) deadlocks between multiple open databases
 *   of Cyrus DB callers, this backend creates an unique environment
 *   for each database.
 *
 */

/* TODO:
 * - support optional resize in myopen: e.g. resize if DB is >80% full
 */

#include <config.h>

#include <assert.h>
#include <errno.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "bsearch.h"
#include "cyrusdb.h"
#include "hash.h"
#include "xstrlcpy.h"

#include "lmdb.h"

struct txn {
    MDB_dbi dbi;
    MDB_txn *mtxn;
};

struct dbengine {
    MDB_env *env;     /* mdb environment, one per database */
    char *fname;      /* external filename of the database */
    int flags;        /* create flags */
    void *data;       /* allocated buffer for fetched data */
    size_t datalen;   /* bytes allocated in data */
    struct txn *tid;  /* master transaction, if any. See begin_txn. */
    MDB_cursor *mcur; /* current cursor of foreach(), if any */
};

struct dblist {
    struct dbengine *db;
    struct dblist *next;
};

/* Default environment size is 512MB */
static size_t maxdbsize = 1 << 29;

#define DEBUG 0

#if DEBUG
#    define PDEBUG(fmt, args...) syslog(LOG_DEBUG, fmt, ## args)
#else
#    define PDEBUG(fmt, args...) /* do nothing */
#endif

/* Global list of open dbs for internal bookkeeping */
static struct dblist *dbs = NULL;

static void register_db(struct dbengine *db)
{
    struct dblist *l = xzmalloc(sizeof(struct dblist));
    assert(db);
    l->db = db;
    l->next = dbs;
    dbs = l;
}

static void unregister_db(struct dbengine *db)
{
    /* Caller must make sure that memory pointed to by db is freed */
    struct dblist *l = dbs;
    assert(db && dbs);

    if (dbs->db == db) {
        /* Reset head of list */
        dbs = l->next;
        free(l);
        return;
    }
    while (l->next) {
        /* Purge db from list */
        if (l->next->db == db) {
            struct dblist *tmp = l->next;
            l->next = l->next->next;
            free(tmp);
            return;
        }
        l = l->next;
    }
    /* Should never be reached */
    assert(0);
}

static int my_mdberror(int mr) {
    switch (mr) {
        case MDB_MAP_FULL:
            return CYRUSDB_FULL;
        case MDB_NOTFOUND:
            return CYRUSDB_NOTFOUND;
        case MDB_MAP_RESIZED:
            /* Should be CYRUSDB_AGAIN, but resize requires to reopen env */
            return CYRUSDB_IOERROR;
        case MDB_SUCCESS:
            return CYRUSDB_OK;
        default:
            return CYRUSDB_INTERNAL;
    }
}

static int mboxcmp(const MDB_val *a, const MDB_val *b);

static int bufferval(struct dbengine *db, MDB_val val, const char **dst, size_t *dstlen)
{
    assert(db && val.mv_data);

    /* Allocate at least 1 byte so data never points to NULL */
    db->data = xrealloc(db->data, val.mv_size + 1);
    memcpy(db->data, val.mv_data, val.mv_size);
    *dst = db->data;
    *dstlen = val.mv_size;
    db->datalen = val.mv_size;

    return CYRUSDB_OK;
}

static int commit_txn(struct dbengine *db, struct txn *tid)
{
    int mr;

    assert(db && tid);

    mr = mdb_txn_commit(tid->mtxn);
    free(tid);
    if (tid == db->tid) db->tid = NULL;

    if (mr) syslog(LOG_ERR, "lmdb: %s", mdb_strerror(mr));
    return mr ? my_mdberror(mr) : CYRUSDB_OK;
}

static int abort_txn(struct dbengine *db, struct txn *tid)
{
    assert(db && tid);

    mdb_txn_abort(tid->mtxn);
    free(tid);
    if (tid == db->tid) db->tid = NULL;

    return CYRUSDB_OK;
}

static int begin_txn(struct dbengine *db, struct txn **tidptr, int readonly)
{
    struct txn *tid = xzmalloc(sizeof(struct txn));
    int mflags, mr, r;
    struct MDB_txn *parent = NULL;

    assert(db && tidptr);

    /* Read-only transactions may only be master transactions and do
     * not allow nested transactions. */
    readonly = !db->tid ? readonly : 0;

    /*
     * Hacky workaround, similar to skiplist
     *
     * If no transaction was passed, but we're in a transaction,
     * then create a nested exception within the current main
     * transaction.
     *
     * Note that transactions are always either the main transaction,
     * or a direct descendant of it. There are no deeper transaction
     * levels supported (although LMDB supports them).
     */
    if (db->tid) {
        parent = db->tid->mtxn;
    }

    /* Begin a new LMDB transaction */
    mr = mdb_txn_begin(db->env, parent, readonly ? MDB_RDONLY : 0, &tid->mtxn);
    if (mr) goto fail;

    /* Open the database */
    mflags = db->flags & CYRUSDB_CREATE ? MDB_CREATE : 0;
    mr = mdb_dbi_open(tid->mtxn, NULL /*name*/, mflags, &tid->dbi);
    if (mr) goto fail;

    if (db->flags & CYRUSDB_MBOXSORT) {
        /* Set mboxsort order */
        mr = mdb_set_compare(tid->mtxn, tid->dbi, mboxcmp);
        if (mr) goto fail;
    }

    if (!db->tid) {
        /* Set the master transaction */
        db->tid = tid;
    }
    *tidptr = tid;
    return CYRUSDB_OK;

fail:
    r = my_mdberror(mr);
    if (tid->mtxn) abort_txn(db, tid);
    syslog(LOG_ERR, "cryusdb_lmdb(%s): %s", db->fname, mdb_strerror(mr));
    return r;
}

/*
 * Get or create an existing transaction from tidptr, and store it in _tidptr.
 */
static int getorset_txn(struct dbengine *db,
                        struct txn **tidptr,
                        struct txn **_tidptr,
                        int readonly)
{
    struct txn *tid;
    int r;

    assert(_tidptr);
    tid = *_tidptr;

    if (!tidptr || !*tidptr) {
        /* Create a new transaction */
        if ((r = begin_txn(db, &tid, readonly))) {
            *_tidptr = NULL;
            return r;
        }
    } else {
        /* Reuse the existing transaction */
        tid = *tidptr;
    }
    if (tidptr) {
        /* Refresh tidptr */
        *tidptr = tid;
    }
    /* Return the transaction */
    *_tidptr = tid;
    return CYRUSDB_OK;
}

static int mboxcmp(const MDB_val *a, const MDB_val *b)
{
    return bsearch_ncompare_mbox((const char *) a->mv_data, a->mv_size,
                                 (const char *) b->mv_data, b->mv_size);
}

static int my_mkparentdir(const char *fname)
{
    struct buf buf = BUF_INITIALIZER;
    int r;

    buf_setcstr(&buf, fname);
    r = cyrus_mkdir(buf_cstring(&buf), 0755);
    buf_free(&buf);
    return r;
}

static int my_stat(const char *fname)
{
    struct stat sb;
    int r;

    r = stat(fname, &sb);
    if (r < 0)
        r = -errno;
    return r;
}

static int myopen(const char *fname, int flags, struct dbengine **ret,
                  struct txn **tidptr)
{
    struct dbengine *db;
    struct txn *tid = NULL;
    int r, mr = 0;

    PDEBUG("cyrusdb_lmdb(%s): open (create=%d)", fname, flags & CYRUSDB_CREATE);
    assert(fname && ret);

    /* Create a new database engine */
    db = (struct dbengine *) xzmalloc(sizeof(struct dbengine));
    db->fname = xstrdup(fname);
    db->flags = flags;

    /* Assert that either the parent directory or the database exists */
    r = flags & CYRUSDB_CREATE ? my_mkparentdir(fname) : my_stat(fname);
    if (r) {
        /* Both my_stat and my_mkparentdir preserve errno */
        r = errno == ENOENT ? CYRUSDB_NOTFOUND : CYRUSDB_IOERROR;
        goto fail;
    }

    /* Create the environment for this database */
    mr = mdb_env_create(&db->env);
    if (mr) {
        r = CYRUSDB_INTERNAL;
        goto fail;
    }

    /* Size (or resize) the environment */
    mr = mdb_env_set_mapsize(db->env, maxdbsize);
    if (mr) {
        r = CYRUSDB_INTERNAL;
        goto fail;
    }

    /* Open the environment */
    mr = mdb_env_open(db->env, fname, MDB_NOSUBDIR, 0600);
    if (mr) {
        r = CYRUSDB_IOERROR;
        goto fail;
    }

    /* Touch the unnamend database in the environment */
    r = begin_txn(db, &tid, 0);
    if (r) goto fail;

    /* Commit or export the transaction */
    if (!tidptr) {
        r = commit_txn(db, tid);
        if (r) goto fail;
    } else {
        *tidptr = tid;
    }

    /* Keep database for internal bookkeeping */
    register_db(db);

    /* Return the database handle */
    *ret = db;
    return CYRUSDB_OK;

fail:
    if (mr)
        syslog(LOG_ERR, "cryusdb_lmdb(%s): %s", db->fname, mdb_strerror(mr));
    if (db->env)
        mdb_env_close(db->env);
    free(db);
    return r;
}

static void close_db(struct dbengine *db)
{
    assert(db);

    if (db->tid) {
        syslog(LOG_ERR, "cyrusdb_lmdb(%s): stray transaction %p",
                db->fname, db->tid);
        abort_txn(db, db->tid);
    }
    if (db->env) {
        mdb_env_close(db->env);
    }
    if (db->data) {
        free(db->data);
    }
    free(db->fname);
    free(db);
}

static int myclose(struct dbengine *db)
{
    assert(db);

    if (db->mcur) {
        syslog(LOG_ERR, "cyrusdb_lmdb(%s): close within foreach", db->fname);
        return CYRUSDB_INTERNAL;
    }

    PDEBUG("cyrusdb_lmdb(%s): close", db->fname);
    close_db(db);
    unregister_db(db);
    return CYRUSDB_OK;
}

static int fetch(struct dbengine *db, const char *key, size_t keylen,
                 const char **data, size_t *datalen, struct txn **tidptr)
{
    MDB_val mkey, mval;
    struct txn *tid;
    int r, r2 = 0, mr;

    PDEBUG("cyrusdb_lmdb(%s): fetch %.*s", db->fname, (int) keylen, key);
    assert(db && key);

    mkey.mv_data = (void*) key;
    mkey.mv_size = keylen;

    /* Open or reuse transaction */
    r = getorset_txn(db, tidptr, &tid, !tidptr /*readonly*/);
    if (r) goto fail;

    mr = mdb_get(tid->mtxn, tid->dbi, &mkey, &mval);
    if (mr == MDB_NOTFOUND) {
        /* That's not an error */
        r = CYRUSDB_NOTFOUND;
        if (datalen) *datalen = 0;
        if (data) *data = NULL;
    } else if (mr) {
        /* That's an error */
        syslog(LOG_ERR, "cryusdb_lmdb(%s): %s", db->fname, mdb_strerror(mr));
        r = CYRUSDB_INTERNAL;
        goto fail;
    } else if (data && datalen) {
        /* Cache the fetched data from LMDB memory in own buffer */
        r = bufferval(db, mval, data, datalen);
        if (r) goto fail;
    }

    /* Commit or export the transaction */
    if (!tidptr) {
        r2 = commit_txn(db, tid);
        if (r2) goto fail;
    } else {
        *tidptr = tid;
        r2 = CYRUSDB_OK;
    }

    return r ? r : r2;

fail:
    if (tid && (!tidptr || !*tidptr)) abort_txn(db, tid);
    return r ? r : r2;
}

static int foreach(struct dbengine *db, const char *prefix, size_t prefixlen,
                   foreach_p *p, foreach_cb *cb, void *rock, struct txn **tidptr)
{
    int r, r2, mr = 0;
    struct txn *tid = NULL;
    MDB_val mkey, mval;
    enum MDB_cursor_op op;
    struct buf cur = BUF_INITIALIZER;

    PDEBUG("cyrusdb_lmdb(%s): foreach %.*s", db->fname, (int) prefixlen, prefix);
    assert(db);

    /* Open or reuse transaction */
    r = getorset_txn(db, tidptr, &tid, 0);
    if (r) goto fail;

    mr = mdb_cursor_open(tid->mtxn, tid->dbi, &db->mcur);
    if (mr) goto fail;

    /* Normalize and set prefix for search */
    if (prefix && !prefixlen) {
        prefix = NULL;
    }

    /* Initialize cursor */
    mkey.mv_data = (void*) prefix;
    mkey.mv_size = prefix ? prefixlen : 0;
    op = prefix ? MDB_SET_RANGE : MDB_FIRST;
    mr = mdb_cursor_get(db->mcur, &mkey, &mval, op);

    /* Iterate cursor until no records or out of range */
    while (!mr) {
        if (prefixlen && (mkey.mv_size < prefixlen))
            break;

        if (prefix && memcmp(mkey.mv_data, prefix, prefixlen))
            break;

        if (!p || p(rock, cur.s, cur.len, mval.mv_data, mval.mv_size)) {
            /* Cache the current position in local memory */
            buf_setmap(&cur, mkey.mv_data, mkey.mv_size);

            r = cb(rock, cur.s, cur.len, mval.mv_data, mval.mv_size);
            if (r) break;

            if (db->mcur == NULL) {
                /* An update has invalidated the cursor. Reseek cursor. */
                mr = mdb_cursor_open(tid->mtxn, tid->dbi, &db->mcur);
                if (mr) break;

                mkey.mv_data = cur.s;
                mkey.mv_size = cur.len;
                mr = mdb_cursor_get(db->mcur, &mkey, &mval, MDB_SET_RANGE);
                if (mr) break;

                if (mkey.mv_size != cur.len || memcmp(mkey.mv_data, cur.s, cur.len)) {
                    /* The current position has been deleted. */
                    continue;
                }
            }
        }

        /* Advance cursor */
        mr = mdb_cursor_get(db->mcur, &mkey, &mval, MDB_NEXT);
    }

    if (mr && mr != MDB_NOTFOUND)
        goto fail;

    if (db->mcur) {
        mdb_cursor_close(db->mcur);
        db->mcur = NULL;
    }
    buf_free(&cur);

    /* Export or commit transaction */
    r2 = tidptr ? CYRUSDB_OK : commit_txn(db, tid);

    return r ? r : r2;

fail:
    if (db->mcur) {
        mdb_cursor_close(db->mcur);
        db->mcur = NULL;
    }
    buf_free(&cur);

    if (tid && (!tidptr || !*tidptr))
        abort_txn(db, tid);
    if (mr) {
        syslog(LOG_ERR, "cryusdb_lmdb(%s): %s", db->fname, mdb_strerror(mr));
        r = my_mdberror(mr);
    }
    return r;
}

static int put(struct dbengine *db, const char *key, size_t keylen,
               const char *data, size_t datalen, struct txn **tidptr, int mflags)
{
    MDB_val mkey, mval;
    struct txn *tid;
    int r, mr;

    mkey.mv_data = (void*) key;
    mkey.mv_size = keylen;
    mval.mv_data = (void*) data;
    mval.mv_size = datalen;

    /* Invalidate cursor */
    if (db->mcur) {
        mdb_cursor_close(db->mcur);
        db->mcur = NULL;
    }

    /* Open or reuse transaction */
    r = getorset_txn(db, tidptr, &tid, 0);
    if (r) goto fail;

    mr = mdb_put(tid->mtxn, tid->dbi, &mkey, &mval, mflags);
    if (mr) {
        /* Return the appropriate error code for existing key overwrites */
        syslog(LOG_ERR, "cryusdb_lmdb(%s): %s", db->fname, mdb_strerror(mr));
        r = (mr == MDB_KEYEXIST && (mflags & MDB_NOOVERWRITE)) ? \
            CYRUSDB_EXISTS : CYRUSDB_INTERNAL;
        goto fail;
    }

    /* Commit or export the transaction */
    if (!tidptr) {
        r = commit_txn(db, tid);
        if (r) goto fail;
    } else {
        *tidptr = tid;
    }

    return CYRUSDB_OK;

fail:
    if (tid && (!tidptr || !*tidptr)) abort_txn(db, tid);
    return r;
}

static int create(struct dbengine *db, const char *key, size_t keylen,
                  const char *data, size_t datalen, struct txn **tidptr)
{
    PDEBUG("cyrusdb_lmdb(%s): create %.*s => %.*s", db->fname,
            (int) keylen, key, (int) datalen, data);
    return put(db, key, keylen, data, datalen, tidptr, MDB_NOOVERWRITE);
}

static int store(struct dbengine *db, const char *key, size_t keylen,
                  const char *data, size_t datalen, struct txn **tidptr)
{
    PDEBUG("cyrusdb_lmdb(%s): store %.*s => %.*s", db->fname,
            (int) keylen, key, (int) datalen, data);
    return put(db, key, keylen, data, datalen, tidptr, 0);
}

static int delete(struct dbengine *db, const char *key, size_t keylen,
                  struct txn **tidptr, int force)
{
    MDB_val mkey;
    struct txn *tid;
    int r, mr;

    PDEBUG("cyrusdb_lmdb(%s): delete %.*s", db->fname, (int) keylen, key);

    mkey.mv_data = (void*) key;
    mkey.mv_size = keylen;

    /* Invalidate cursor */
    if (db->mcur) {
        mdb_cursor_close(db->mcur);
        db->mcur = NULL;
    }

    /* Open or reuse transaction */
    r = getorset_txn(db, tidptr, &tid, 0);
    if (r) goto fail;

    mr = mdb_del(tid->mtxn, tid->dbi, &mkey, NULL);
    if (mr == MDB_NOTFOUND) {
        /* Force deleting an inexistent key is not an error */
        r = force ? CYRUSDB_OK : CYRUSDB_NOTFOUND;
        if (r) goto fail;
    } else if (mr) {
        syslog(LOG_ERR, "cryusdb_lmdb(%s): %s", db->fname, mdb_strerror(mr));
        r = CYRUSDB_INTERNAL;
        goto fail;
    }

    /* Commit or export the transaction */
    if (!tidptr) {
        r = commit_txn(db, tid);
        if (r) goto fail;
    } else {
        *tidptr = tid;
    }

    return CYRUSDB_OK;

fail:
    if (tid && (!tidptr || !*tidptr)) abort_txn(db, tid);
    return r;
}

static int mycompar(struct dbengine *db, const char *a, int alen,
                    const char *b, int blen)
{
    int cmp;
    struct txn *tid = NULL;
    MDB_val ma, mb;
    int use_mboxcmp = db->flags & CYRUSDB_MBOXSORT;

    assert(db && a && b);

    /* LMDB internal order requires a transaction to operate on */
    if (!use_mboxcmp && begin_txn(db, &tid, 1 /*readonly*/)) {
        syslog(LOG_ERR, "lmdb_compar(%s): internal error", db->fname);
        return -1;
    }

    ma.mv_data = (void *) a;
    ma.mv_size = alen;
    mb.mv_data = (void *) b;
    mb.mv_size = blen;

    /* Compare values using appropriate comparator */
    cmp = use_mboxcmp ? mboxcmp(&ma, &mb) : mdb_cmp(tid->mtxn, tid->dbi, &ma, &mb);

    /* Discard LMDB-owned transaction, if any */
    if (!use_mboxcmp && abort_txn(db, tid)) {
        syslog(LOG_ERR, "lmdb_compar(%s): internal error", db->fname);
        return -1;
    }

    return cmp;
}

static int init(const char *dbdir __attribute__((unused)),
                int myflags __attribute__((unused)))
{
    PDEBUG("cyrusdb_lmdb(%s): init", dbdir);
    char *val = getenv("CYRUSDB_LMDB_MAXSIZE");
    int pagesize;

    if (val) {
        /* Parse user-defined maximum database size */
        char *endptr = NULL;
        long size;
        int myerrno;
        size_t guard, factor = 1;

        /* Convert and keep conversion error */
        size = strtol(val, &endptr, 10);
        myerrno = errno;
        if (endptr) {
            /* Be nice to humans: parse 1gb, 3mb or byte size */
            if (!strcasecmp(endptr, "mb")) {
                factor = 1024 * 1024;
            } else if (!strcasecmp(endptr, "gb")) {
                factor = 1024 * 1024 * 1024;
            } else if (*endptr) {
                factor = 0;
            }
        }
        /* Check for overflows */
        guard = (size_t) size * factor;
        if (factor != 0 && guard/factor != (size_t) size) myerrno = ERANGE;

        /* Validate input */
        if (factor == 0 || myerrno == ERANGE || size < 0) {
            syslog(LOG_ERR, "cyrusdb_lmdb: invalid CYRUSDB_LMDB_MAXSIZE: %s", val);
            return CYRUSDB_INTERNAL;
        }
        /* Use user-defined value */
        maxdbsize = guard;
        PDEBUG("cyrusdb_lmdb: set maximum db size to %zu bytes", maxdbsize);
    }
    /* Warn about sub-par configuration */
    pagesize = getpagesize();
    if ((maxdbsize % pagesize) != 0) {
        syslog(LOG_ERR,
                "cyrusdb_lmdb: db size %zu isn't a multiple of pagesize %d",
                maxdbsize, pagesize);
    }
    return CYRUSDB_OK;
}

static int done(void)
{
    struct dblist *l;

    PDEBUG("cyrusdb_lmdb: done");
    l = dbs;
    while (l) {
        struct dblist *tmp;
        syslog(LOG_ERR, "cyrusdb_lmdb: closing stray database %s", l->db->fname);
        close_db(l->db);
        tmp = l;
        l = l->next;
        free(tmp);
    }
    dbs = NULL;
    return CYRUSDB_OK;
}

static int mysync(void)
{
    int r, mr;
    struct dblist *l;

    r = CYRUSDB_OK;
    for (l = dbs; l; l = l->next) {
        PDEBUG("cyrusdb_lmdb(%s): sync", l->db->fname);
        mr = mdb_env_sync(l->db->env, 1 /*force*/);
        if (mr) {
            syslog(LOG_ERR, "cyrusdb_lmdb(%s): sync: %s", l->db->fname, mdb_strerror(mr));
            r = CYRUSDB_INTERNAL;
            break;
        }
    }
    return r;
}

static int archive(const strarray_t *fnames, const char *dirname)
{
    struct hash_table want = HASH_TABLE_INITIALIZER;
    struct dblist *l = dbs;
    char dstname[1024], *dp;
    size_t length, rest, n;
    int i, r, init = 1;

    if (!strarray_size(fnames))
        return 0;

    construct_hash_table(&want, strarray_size(fnames), 0);
    for (i = 0; i < fnames->count; i++) {
        hash_insert(strarray_nth(fnames, i), (void*) 1, &want);
    }

    /* Prepare filename buffer */
    n = strlcpy(dstname, dirname, sizeof(dstname));
    if (n == sizeof(dstname)) {
        syslog(LOG_ERR, "cyrusdb_lmdb: archive: long dirname %s", dirname);
        r = CYRUSDB_IOERROR;
        goto fail;
    }
    length = strlen(dstname);
    dp = dstname + length;
    rest = sizeof(dstname) - length;

    r = CYRUSDB_OK;
    for(l = dbs; l; l = l->next) {
        char *base;
        int mr;

        /* Skip unwanted databases */
        if (!hash_lookup(l->db->fname, &want)) {
            continue;
        }

        /* Append the basename of the source database file to dirname.
         * This flattens all fnames into the same target directory, which
         * isn't entirely safe but replicates the generic archiver */
        base = strrchr(l->db->fname, '/');
        base = base ? base : l->db->fname;
        if (strlen(base) + length > sizeof(dstname)) {
            syslog(LOG_ERR, "cyrusdb_lmdb: archive: long filename %s/%s", dirname, base);
            r = CYRUSDB_IOERROR;
            break;
        }
        strlcpy(dp, base, rest);

        /* If this is the first archival, make sure that dirname exists */
        if (init) {
            r = my_mkparentdir(dstname);
            if (r) {
                syslog(LOG_ERR, "cyrusdb_lmdb(%s): archive: %s", dirname, strerror(errno));
                r = CYRUSDB_IOERROR;
                break;
            }
            init = 0;
        }

        /* Archive the current database */
        PDEBUG("cyrusdb_lmdb(%s): archiving to %s", l->db->fname, dstname);
        if ((mr = mdb_env_copy(l->db->env, dstname))) {
            syslog(LOG_ERR, "cryusdb_lmdb(%s): archive: %s", dstname, mdb_strerror(mr));
            r = mr == EEXIST ? CYRUSDB_EXISTS : CYRUSDB_INTERNAL;
            break;
        }
    }

fail:
    free_hash_table(&want, NULL);
    return r;
}

static int myunlink(const char *fname, int flags __attribute__((unused)))
{
    /* XXX: smart lock checks? */
    char *lockname = strconcat(fname, "-lock", (char *)NULL);
    unlink(fname);
    unlink(lockname);
    free(lockname);
    return 0;
}

EXPORTED struct cyrusdb_backend cyrusdb_lmdb =
{
    "lmdb",                     /* name */

    &init,
    &done,
    &mysync,
    &archive,
    &myunlink,

    &myopen,
    &myclose,

    &fetch,
    &fetch, /* fetchlock */
    NULL,   /* fetchnext */

    &foreach,
    &create,
    &store,
    &delete,

    &commit_txn,
    &abort_txn,

    NULL, /* dump */
    NULL, /* consistent */
    NULL, /* repack */
    &mycompar
};
