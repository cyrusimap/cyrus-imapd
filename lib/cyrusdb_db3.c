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

#include <db.h>
#include <syslog.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>

#include "cyrusdb.h"
#include "exitcodes.h"
#include "xmalloc.h"

/* --- cut here --- */
/*
 * what berkeley db algorithm should we use for deadlock detection?
 * 
 * DB_LOCK_DEFAULT
 *    Use the default policy as specified by db_deadlock. 
 * DB_LOCK_OLDEST
 *    Abort the oldest transaction. 
 * DB_LOCK_RANDOM
 *    Abort a random transaction involved in the deadlock. 
 * DB_LOCK_YOUNGEST
 *    Abort the youngest transaction. 
 */

#define CONFIG_DEADLOCK_DETECTION DB_LOCK_YOUNGEST
#define FNAME_DBDIR "/db"

/* --- cut here --- */

static int dbinit = 0;
static DB_ENV *dbenv;

/* other routines call this one when they fail */
static int commit_txn(struct db *db, struct txn *tid);
static int abort_txn(struct db *db, struct txn *tid);

static void db_panic(DB_ENV *dbenv, int errno)
{
    syslog(LOG_CRIT, "DBERROR: critical database situation");
    /* but don't bounce mail */
    exit(EC_TEMPFAIL);
}

static void db_err(const char *db_prfx, char *buffer)
{
    syslog(LOG_ERR, "DBERROR %s: %s", db_prfx, buffer);
}

static int init(const char *dbdir, int myflags)
{
    int r, do_retry = 1;
    int flags = 0;

    if (dbinit++) return 0;

    if (myflags & CYRUSDB_RECOVER) {
      flags |= DB_RECOVER | DB_CREATE;
    }

    if ((r = db_env_create(&dbenv, 0)) != 0) {
	syslog(LOG_ERR, "DBERROR: db_appinit failed: %s", db_strerror(r));
	return CYRUSDB_IOERROR;
    }
    dbenv->set_paniccall(dbenv, (void (*)(DB_ENV *, int)) &db_panic);
    if (CONFIG_DB_VERBOSE) {
	dbenv->set_verbose(dbenv, DB_VERB_DEADLOCK, 1);
	dbenv->set_verbose(dbenv, DB_VERB_WAITSFOR, 1);
    }
    if (CONFIG_DB_VERBOSE > 1) {
	dbenv->set_verbose(dbenv, DB_VERB_CHKPOINT, 1);
    }
    dbenv->set_lk_detect(dbenv, CONFIG_DEADLOCK_DETECTION);

    /* XXX should make this value runtime configurable */
    r = dbenv->set_lk_max(dbenv, 50000);
    if (r) {
	syslog(LOG_ERR, "DBERROR: set_lk_max(): %s", db_strerror(r));
	abort();
    }

    /* XXX should make this value runtime configurable */
    r = dbenv->set_tx_max(dbenv, 100);
    if (r) {
	syslog(LOG_ERR, "DBERROR: set_tx_max(): %s", db_strerror(r));
	abort();
    }

    dbenv->set_errcall(dbenv, db_err);
    dbenv->set_errpfx(dbenv, "db3");

#if 0
    if ((r = dbenv->set_cachesize(dbenv, 0, 64 * 1024, 0)) != 0) {
	dbenv->err(dbenv, r, "set_cachesize");
	dbenv->close(dbenv, 0);
	syslog(LOG_ERR, "DBERROR: set_cachesize(): %s", db_strerror(r));
	return CYRUSDB_IOERROR;
    }
#endif

    /* what directory are we in? */
 retry:
    flags |= DB_INIT_LOCK | DB_INIT_MPOOL | 
	     DB_INIT_LOG | DB_INIT_TXN;
#if DB_VERSION_MINOR > 0
    r = dbenv->open(dbenv, dbdir, flags, 0644); 
#else
    r = dbenv->open(dbenv, dbdir, NULL, flags, 0644); 
#endif
    if (r) {
        if (do_retry && (r == ENOENT)) {
	  /* Per sleepycat Support Request #3838 reporting a performance problem: 

	        Berkeley DB only transactionally protects the open if you're
	        doing a DB_CREATE.  Even if the Cyrus application is opening
  	        the file read/write, we don't need a transaction.  I see
	        from their source that they are always specifying DB_CREATE.
	        I bet if they changed it to not specifying CREATE and only
	        creating if necessary, the problem would probably go away.

	     Given that in general the file should exist, we optimize the most 
	     often case: the file exists.  So, we add DB_CREATE only if we fail 
	     to open the file and thereby avoid doing a stat(2) needlessly. Sure, it 
	     should be cached by why waste the cycles anyway?
	  */
	  flags |= DB_CREATE;
	  do_retry = 0;
	  goto retry;
        }
	
	syslog(LOG_ERR, "DBERROR: dbenv->open '%s' failed: %s", dbdir,
	       db_strerror(r));
	return CYRUSDB_IOERROR;
    }

    dbinit = 1;

    return 0;
}

static int done(void)
{
    int r;

    if (--dbinit) return 0;

    r = dbenv->close(dbenv, 0);
    dbinit = 0;
    if (r) {
	syslog(LOG_ERR, "DBERROR: error exiting application: %s",
	       db_strerror(r));
	return CYRUSDB_IOERROR;
    }

    return 0;
}

static int sync(void)
{
    int r;

    assert(dbinit);

    do {
#if DB_VERSION_MINOR > 0
	r = txn_checkpoint(dbenv, 0, 0, 0);
#else
	r = txn_checkpoint(dbenv, 0, 0);
#endif
    } while (r == DB_INCOMPLETE);
    if (r) {
	syslog(LOG_ERR, "DBERROR: couldn't checkpoint: %s",
	       db_strerror(r));
	return CYRUSDB_IOERROR;
    }

    return 0;
}

static int open(const char *fname, struct db **ret)
{
    DB *db;
    int r;

    assert(dbinit && fname && ret);

    *ret = NULL;

    r = db_create(&db, dbenv, 0);
    if (r != 0) {
	syslog(LOG_ERR, "DBERROR: opening %s: %s", fname, db_strerror(r));
	return CYRUSDB_IOERROR;
    }
    /* xxx set comparator! */

    r = db->open(db, fname, NULL, DB_BTREE, DB_CREATE, 0664);
    if (r != 0) {
	syslog(LOG_ERR, "DBERROR: opening %s: %s", fname, db_strerror(r));
	return CYRUSDB_IOERROR;
    }

    *ret = (struct db *) db;

    return r;
}

static int close(struct db *db)
{
    int r;
    DB *a = (DB *) db;

    assert(dbinit && db);

    r = a->close(a, 0);
    if (r != 0) {
	syslog(LOG_ERR, "DBERROR: error closing: %s", db_strerror(r));
	r = CYRUSDB_IOERROR;
    }

    return r;
}

static int gettid(struct txn **mytid, DB_TXN **tid, char *where)
{
    int r;

    if (mytid) {
	if (*mytid) {
  	    assert((txn_id((DB_TXN *)*mytid) != 0));
	    *tid = (DB_TXN *) *mytid;
	    if (CONFIG_DB_VERBOSE)
		syslog(LOG_DEBUG, "%s: reusing txn %lu", where, txn_id(*tid));
	} else {
	    r = txn_begin(dbenv, NULL, tid, 0);
	    if (r != 0) {
		syslog(LOG_ERR, "DBERROR: error beginning txn (%s): %s", where,
		       db_strerror(r));
		return CYRUSDB_IOERROR;
	    }
	    if (CONFIG_DB_VERBOSE)
		syslog(LOG_DEBUG, "%s: starting txn %lu", where, txn_id(*tid));
	}
	*mytid = (struct txn *) *tid;
    }

    return 0;
}

static int myfetch(struct db *mydb, 
		   const char *key, int keylen,
		   const char **data, int *datalen,
		   struct txn **mytid, int flags)
{
    int r = 0;
    DBT k, d;
    DB *db = (DB *) mydb;
    DB_TXN *tid = NULL;
	
    assert(dbinit && db);

    r = gettid(mytid, &tid, "myfetch");
    if (r) return r;

    memset(&k, 0, sizeof(k));
    memset(&d, 0, sizeof(d));

    k.data = (char *) key;
    k.size = keylen;

    r = db->get(db, tid, &k, &d, flags);
    switch (r) {
    case 0:
	if (data) *data = d.data;
	if (datalen) *datalen = d.size;
	break;
    case DB_NOTFOUND:
	*data = NULL;
	*datalen = 0;
	r = 0;
	break;
    case DB_LOCK_DEADLOCK:
	if (mytid) {
	    abort_txn(mydb, *mytid);
	    *mytid = NULL;
	}
	r = CYRUSDB_AGAIN;
	break;
    default:
	syslog(LOG_ERR, "DBERROR: error fetching %s: %s", key,
	       db_strerror(r));
	r = CYRUSDB_IOERROR;
	break;
    }

    return r;
}

static int fetch(struct db *mydb, 
		 const char *key, int keylen,
		 const char **data, int *datalen,
		 struct txn **mytid)
{
    return myfetch(mydb, key, keylen, data, datalen, mytid, 0);
}

static int fetchlock(struct db *mydb, 
		     const char *key, int keylen,
		     const char **data, int *datalen,
		     struct txn **mytid)
{
    return myfetch(mydb, key, keylen, data, datalen, mytid, DB_RMW);
}

#define OPENCURSOR() do { \
    r = db->cursor(db, tid, &cursor, 0); \
    if (r != 0) { \
	syslog(LOG_ERR, "DBERROR: unable to create cursor: %s", \
	       db_strerror(r)); \
	cursor = NULL; \
	goto done; \
    } \
 } while (0)

#define CLOSECURSOR() do { \
    int r = cursor->c_close(cursor); \
    if (r) { \
	syslog(LOG_ERR, "DBERROR: error closing cursor: %s", \
	       db_strerror(r)); \
	cursor = NULL; \
	goto done; \
    } \
 } while (0)


/* instead of "DB_DBT_REALLOC", we might want DB_DBT_USERMEM and allocate
   this to the maximum length at the beginning. */
static int foreach(struct db *mydb,
		   char *prefix, int prefixlen,
		   foreach_p *goodp,
		   foreach_cb *cb, void *rock, 
		   struct txn **mytid)
{
    int r = 0;
    DBT k, d;
    DBC *cursor = NULL;
    DB *db = (DB *) mydb;
    DB_TXN *tid = NULL;

    assert(dbinit && db);
    assert(cb);

    memset(&k, 0, sizeof(k));
    memset(&d, 0, sizeof(d));

    /* k.flags |= DB_DBT_REALLOC;
       d.flags |= DB_DBT_REALLOC;*/

    r = gettid(mytid, &tid, "foreach");
    if (r) return r;

    if (0) {
    restart:
	CLOSECURSOR();
    }

    /* create cursor */
    OPENCURSOR();

    /* find first record */
    if (prefix && *prefix) {
	/* if (k.data) free(k.data); */
	k.data = prefix;
	k.size = prefixlen;

	r = cursor->c_get(cursor, &k, &d, DB_SET_RANGE);
    } else {
	r = cursor->c_get(cursor, &k, &d, DB_FIRST);
    }
    if (!tid && r == DB_LOCK_DEADLOCK) goto restart;
	
    /* iterate over all mailboxes matching prefix */
    while (!r) {
	/* does this match our prefix? */
	if (prefixlen && memcmp(k.data, prefix, prefixlen)) break;

	if (goodp(rock, k.data, k.size, d.data, d.size)) {
	    /* we have a winner! */

	    /* close the cursor, so we're not holding locks 
	       during a callback */
	    CLOSECURSOR(); cursor = NULL;

	    r = cb(rock, k.data, k.size, d.data, d.size);
            if (r != 0) {
                if (r < 0) {
                    syslog(LOG_ERR, "DBERROR: foreach cb() failed");
                }
                /* don't mistake this for a db error */
                r = 0;

                break;
            }

	    /* restore the current location & advance */
	    OPENCURSOR();
	    
	    r = cursor->c_get(cursor, &k, &d, DB_SET);
	    switch (r) {
	    case 0:
		r = cursor->c_get(cursor, &k, &d, DB_NEXT);
		break;

	    case DB_NOTFOUND:
		/* deleted during callback? */
		r = cursor->c_get(cursor, &k, &d, DB_SET_RANGE);
		break;

	    default:
		/* handle other cases below */
		break;
	    }
	} else {
	    /* advance the cursor */
	    r = cursor->c_get(cursor, &k, &d, DB_NEXT);
	}

	while (r == DB_LOCK_DEADLOCK) {
	    if (tid) {
		break;		/* don't autoretry txn-protected */
	    }

	    /* if we deadlock, close and reopen the cursor, and
	       reposition it */
	    CLOSECURSOR();
	    OPENCURSOR();

	    r = cursor->c_get(cursor, &k, &d, DB_SET);
	    switch (r) {
	    case 0:
		r = cursor->c_get(cursor, &k, &d, DB_NEXT);
		break;
	    case DB_LOCK_DEADLOCK:
		continue;
	    case DB_NOTFOUND: /* deleted? */
		r = cursor->c_get(cursor, &k, &d, DB_SET_RANGE);
		break;
	    }
	}
    }

 done:
    if (cursor) {
	CLOSECURSOR();
    }

    switch (r) {
    case 0:			/* ok */
	break;
    case DB_NOTFOUND:		/* also ok */
	r = 0;
	break;
    case DB_LOCK_DEADLOCK:	/* erg, we're in a txn! */
	if (mytid) {
	    abort_txn(mydb, *mytid);
	    *mytid = NULL;
	}
	r = CYRUSDB_AGAIN;
	break;
    default:
	if (mytid) {
	    abort_txn(mydb, *mytid); 
	    *mytid = NULL;
	}
	syslog(LOG_ERR, "DBERROR: error advancing: %s",  db_strerror(r));
	r = CYRUSDB_IOERROR;
	break;
    }

/*     if (k.data) free(k.data);
       if (d.data) free(d.data);*/

    return r;
}

static int mystore(struct db *mydb, 
		   const char *key, int keylen,
		   const char *data, int datalen,
		   struct txn **mytid, int putflags, int txnflags)
{
    int r = 0;
    DBT k, d;
    DB_TXN *tid;
    DB *db = (DB *) mydb;

    assert(dbinit && db);
    assert(key && keylen);

    r = gettid(mytid, &tid, "mystore");
    if (r) return r;

    memset(&k, 0, sizeof(k));
    memset(&d, 0, sizeof(d));

    k.data = (char *) key;
    k.size = keylen;
    d.data = (char *) data;
    d.size = datalen;

    if (!mytid) {
	/* start a transaction for the write */
    restart:
	r = txn_begin(dbenv, NULL, &tid, 0);
	if (r != 0) {
	    syslog(LOG_ERR, "DBERROR: mystore: error beginning txn: %s", 
		   db_strerror(r));
	    return CYRUSDB_IOERROR;
	}
	if (CONFIG_DB_VERBOSE)
	    syslog(LOG_DEBUG, "mystore: starting txn %lu", txn_id(tid));
    }
    r = db->put(db, tid, &k, &d, putflags);
    if (!mytid) {
	/* finish once-off txn */
	if (r) {
	    int r2;

	    if (CONFIG_DB_VERBOSE)
		syslog(LOG_DEBUG, "mystore: aborting txn %lu", txn_id(tid));
	    r2 = txn_abort(tid);
	    if (r2) {
		syslog(LOG_ERR, "DBERROR: mystore: error aborting txn: %s", 
		       db_strerror(r));
		return CYRUSDB_IOERROR;
	    }

	    if (r == DB_LOCK_DEADLOCK) {
		goto restart;
	    }
	} else {
	    if (CONFIG_DB_VERBOSE)
		syslog(LOG_DEBUG, "mystore: committing txn %lu", txn_id(tid));
	    r = txn_commit(tid, txnflags);
	}
    }

    if ( r != 0) {
	if (mytid) {
	    abort_txn(mydb, *mytid);
	    *mytid = NULL;
	}
	if (r == DB_LOCK_DEADLOCK) {
	    r = CYRUSDB_AGAIN;
	} else {
	    syslog(LOG_ERR, "DBERROR: mystore: error storing %s: %s",
		   key, db_strerror(r));
	    r = CYRUSDB_IOERROR;
	}
    }

    return r;
}

static int create(struct db *db, 
		  const char *key, int keylen,
		  const char *data, int datalen,
		  struct txn **tid)
{
    return mystore(db, key, keylen, data, datalen, tid, DB_NOOVERWRITE, 0);
}

static int store(struct db *db, 
		 const char *key, int keylen,
		 const char *data, int datalen,
		 struct txn **tid)
{
    return mystore(db, key, keylen, data, datalen, tid, 0, 0);
}

static int create_nosync(struct db *db, 
			 const char *key, int keylen,
			 const char *data, int datalen,
			 struct txn **tid)
{
    return mystore(db, key, keylen, data, datalen, tid, DB_NOOVERWRITE,
		   DB_TXN_NOSYNC);
}

static int store_nosync(struct db *db, 
			const char *key, int keylen,
			const char *data, int datalen,
			struct txn **tid)
{
    return mystore(db, key, keylen, data, datalen, tid, 0, DB_TXN_NOSYNC);
}

static int mydelete(struct db *mydb, 
		    const char *key, int keylen,
		    struct txn **mytid, int txnflags)
{
    int r = 0;
    DBT k;
    DB_TXN *tid;
    DB *db = (DB *) mydb;

    assert(dbinit && db);
    assert(key && keylen);

    r = gettid(mytid, &tid, "delete");
    if (r) return r;

    memset(&k, 0, sizeof(k));

    k.data = (char *) key;
    k.size = keylen;

    if (!mytid) {
    restart:
	/* start txn for the write */
	r = txn_begin(dbenv, NULL, &tid, 0);
	if (r != 0) {
	    syslog(LOG_ERR, "DBERROR: delete: error beginning txn: %s", 
		   db_strerror(r));
	    return CYRUSDB_IOERROR;
	}
	if (CONFIG_DB_VERBOSE)
	    syslog(LOG_DEBUG, "delete: starting txn %lu", txn_id(tid));
    }
    r = db->del(db, tid, &k, 0);
    if (!mytid) {
	/* finish txn for the write */
	if (r) {
	    int r2;
	    if (CONFIG_DB_VERBOSE)
		syslog(LOG_DEBUG, "delete: aborting txn %lu", txn_id(tid));
	    r2 = txn_abort(tid);
	    if (r2) {
		syslog(LOG_ERR, "DBERROR: delete: error aborting txn: %s", 
		       db_strerror(r));
		return CYRUSDB_IOERROR;
	    }

	    if (r == DB_LOCK_DEADLOCK) {
		goto restart;
	    }
	} else {
	    if (CONFIG_DB_VERBOSE)
		syslog(LOG_DEBUG, "delete: committing txn %lu", txn_id(tid));
	    r = txn_commit(tid, txnflags);
	}
    }

    if (r != 0) {
	if (mytid) {
	    abort_txn(mydb, *mytid);
	    *mytid = NULL;
	}
	if (r == DB_LOCK_DEADLOCK) {
	    r = CYRUSDB_AGAIN;
	} else {
	    syslog(LOG_ERR, "DBERROR: delete: error deleting %s: %s",
		   key, db_strerror(r));
	    r = CYRUSDB_IOERROR;
	}
    }

    return r;
}

static int delete(struct db *db, 
		  const char *key, int keylen,
		  struct txn **tid)
{
    return mydelete(db, key, keylen, tid, 0);
}

static int delete_nosync(struct db *db, 
			 const char *key, int keylen,
			 struct txn **tid)
{
    return mydelete(db, key, keylen, tid, DB_TXN_NOSYNC);
}

static int mycommit(struct db *db, struct txn *tid, int txnflags)
{
    int r;
    DB_TXN *t = (DB_TXN *) tid;

    assert(dbinit && tid);

    if (CONFIG_DB_VERBOSE)
	syslog(LOG_DEBUG, "commit_txn: committing txn %lu", txn_id(t));
    r = txn_commit(t, txnflags);
    switch (r) {
    case 0:
	break;
    case EINVAL:
	syslog(LOG_WARNING, "commit_txn: tried to commit an already aborted transaction");
	r = CYRUSDB_IOERROR;
	break;
    default:
	syslog(LOG_ERR, "DBERROR: commit_txn  failed on commit: %s",
	       db_strerror(r));
	r = CYRUSDB_IOERROR;
	break;
    }

    return r;
}

static int commit_txn(struct db *db, struct txn *tid)
{
    return mycommit(db, tid, 0);
}

static int commit_nosync(struct db *db, struct txn *tid)
{
    return mycommit(db, tid, DB_TXN_NOSYNC);
}

static int abort_txn(struct db *db, struct txn *tid)
{
    int r;
    DB_TXN *t = (DB_TXN *) tid;

    assert(dbinit && tid);

    if (CONFIG_DB_VERBOSE)
	syslog(LOG_DEBUG, "abort_txn: aborting txn %lu", txn_id(t));
    r = txn_abort(t);
    if (r != 0) {
	syslog(LOG_ERR, "DBERROR: abort_txn: error aborting txn: %s", db_strerror(r));
	return CYRUSDB_IOERROR;
    }

    return 0;
}

struct cyrusdb_backend cyrusdb_db3 = 
{
    "db3",			/* name */

    &init,
    &done,
    &sync,

    &open,
    &close,

    &fetch,
    &fetchlock,
    &foreach,
    &create,
    &store,
    &delete,

    &commit_txn,
    &abort_txn
};

struct cyrusdb_backend cyrusdb_db3_nosync = 
{
    "db3-nosync",		/* name */

    &init,
    &done,
    &sync,

    &open,
    &close,

    &fetch,
    &fetchlock,
    &foreach,
    &create_nosync,
    &store_nosync,
    &delete_nosync,

    &commit_nosync,
    &abort_txn
};
