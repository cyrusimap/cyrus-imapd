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

#include <db.h>
#include <syslog.h>
#include <assert.h>
#include <string.h>
#include <errno.h>

#include "cyrusdb.h"
#include "exitcodes.h"

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
#define CONFIG_DB_VERBOSE 1
#define FNAME_DBDIR "/db"

/* --- cut here --- */

static int dbinit = 0;
static DB_ENV *dbenv;

/* other routines call this one when they fail */
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
    int r;
    int flags = 0;

    assert(!dbinit);

    if (myflags & CYRUSDB_RECOVER) flags |= DB_RECOVER;

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
    dbenv->set_lk_max(dbenv, 10000);
    dbenv->set_errcall(dbenv, db_err);
    dbenv->set_errpfx(dbenv, "db3");

    if ((r = dbenv->set_cachesize(dbenv, 0, 64 * 1024, 0)) != 0) {
	dbenv->err(dbenv, r, "set_cachesize");
	dbenv->close(dbenv, 0);
	syslog(LOG_ERR, "DBERROR: set_cachesize(): %s", db_strerror(r));
	return CYRUSDB_IOERROR;
    }

    /* what directory are we in? */
    flags |= DB_CREATE | DB_INIT_LOCK | DB_INIT_MPOOL | 
	     DB_INIT_LOG | DB_INIT_TXN;
#if DB_VERSION_MINOR > 0
    r = dbenv->open(dbenv, dbdir, flags, 0644); 
#else
    r = dbenv->open(dbenv, dbdir, NULL, flags, 0644); 
#endif
    if (r) {
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

    assert(dbinit);

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

static int gettid(struct txn **mytid, DB_TXN **tid)
{
    int r;

    if (mytid) {
	if (*mytid) {
	    *tid = (DB_TXN *) *mytid;
	} else {
	    r = txn_begin(dbenv, NULL, tid, 0);
	    if (r != 0) {
		syslog(LOG_ERR, "DBERROR: error beginning txn: %s", 
		       db_strerror(r));
		return CYRUSDB_IOERROR;
	    }
	    syslog(LOG_DEBUG, "starting txn %d", txn_id(*tid));
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

    r = gettid(mytid, &tid);
    if (r) return r;

    memset(&k, 0, sizeof(k));
    memset(&d, 0, sizeof(d));

    k.data = (char *) key;
    k.size = keylen;

    r = db->get(db, tid, &k, &d, 0);
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
	if (mytid) abort_txn(mydb, *mytid);
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


static int foreach(struct db *mydb,
		   char *prefix, int prefixlen,
		   foreach_cb *cb, void *rock, 
		   struct txn **mytid)
{
    int r = 0, r2;
    DBT k, d;
    DBC *cursor = NULL;
    DB *db = (DB *) mydb;
    DB_TXN *tid = NULL;

    assert(dbinit && db);
    assert(cb);

    memset(&k, 0, sizeof(k));
    memset(&d, 0, sizeof(d));

    r = gettid(mytid, &tid);
    if (r) return r;

    if (0) {
    restart:
	r = cursor->c_close(cursor);
	if (r) {
	    syslog(LOG_ERR, "DBERROR: error closing cursor: %s",
		   db_strerror(r));
	}
	return r;
    }

    /* create cursor */
    r = db->cursor(db, tid, &cursor, 0);
    if (r != 0) { 
	syslog(LOG_ERR, "DBERROR: unable to create cursor: %s",db_strerror(r));
	return r;
    }

    /* find first record */
    if (prefix && *prefix) {
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

	r = cb(rock, k.data, k.size, d.data, d.size);
	if (r != 0) break;

	r = cursor->c_get(cursor, &k, &d, DB_NEXT);
	if (r == DB_LOCK_DEADLOCK && tid) {
	    break;		/* don't autoretry txn-protected */
	}

	while (r == DB_LOCK_DEADLOCK) {
	    /* if we deadlock, close and reopen the cursor, and
	       reposition it */
	    switch (r = cursor->c_close(cursor)) {
	    case 0:
		break;
	    default:
		syslog(LOG_ERR, "DBERROR: couldn't close cursor: %s",
		       db_strerror(r));
		goto done;
	    }
	    switch (r = db->cursor(db, NULL, &cursor, 0)) {
	    case 0:
		break;
	    default:
		syslog(LOG_ERR, "DBERROR: couldn't recreate cursor: %s",
		       db_strerror(r));
		goto done;
	    }
	    r = cursor->c_get(cursor, &k, &d, DB_SET);
	    switch (r) {
	    case 0:
		break;
	    case DB_LOCK_DEADLOCK:
		continue;
	    case DB_NOTFOUND:
		r = cursor->c_get(cursor, &k, &d, DB_SET_RANGE);
		if (r == DB_LOCK_DEADLOCK) continue;
		break;
	    }
	    r = cursor->c_get(cursor, &k, &d, DB_NEXT);
	}
    }

 done:
    r2 = cursor->c_close(cursor);
    if (r2 != 0) {
	syslog(LOG_ERR, "DBERROR: error closing cursor: %s", db_strerror(r2));
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
	}
	r = CYRUSDB_AGAIN;
	break;
    default:
	if (mytid) {
	    abort_txn(mydb, *mytid);
	}
	syslog(LOG_ERR, "DBERROR: error advancing: %s",  db_strerror(r));
	r = CYRUSDB_IOERROR;
	break;
    }

    return r;
}

static int mystore(struct db *mydb, 
		   const char *key, int keylen,
		   const char *data, int datalen,
		   struct txn **mytid, int flag)
{
    int r = 0;
    DBT k, d;
    DB_TXN *tid;
    DB *db = (DB *) mydb;

    assert(dbinit && db);
    assert(key && keylen);

    r = gettid(mytid, &tid);
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
	    syslog(LOG_ERR, "DBERROR: error beginning txn: %s", 
		   db_strerror(r));
	    return CYRUSDB_IOERROR;
	}
	syslog(LOG_DEBUG, "starting txn %d", txn_id(tid));
    }
    r = db->put(db, tid, &k, &d, 0);
    if (!mytid) {
	/* finish once-off txn */
	if (r) {
	    int r2 = txn_abort(tid);
	    if (r2) {
		syslog(LOG_ERR, "DBERROR: error aborting txn: %s", 
		       db_strerror(r));
		return CYRUSDB_IOERROR;
	    }

	    if (r == DB_LOCK_DEADLOCK) {
		goto restart;
	    }
	} else {
	    r = txn_commit(tid, 0);
	}
    }

    if (r != 0) {
	if (mytid) abort_txn(mydb, *mytid);
	if (r == DB_LOCK_DEADLOCK) {
	    r = CYRUSDB_AGAIN;
	} else {
	    syslog(LOG_ERR, "DBERROR: error storing %s: %s",
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
    return mystore(db, key, keylen, data, datalen, tid, DB_NOOVERWRITE);
}

static int store(struct db *db, 
		 const char *key, int keylen,
		 const char *data, int datalen,
		 struct txn **tid)
{
    return mystore(db, key, keylen, data, datalen, tid, 0);
}

static int delete(struct db *mydb, 
		  const char *key, int keylen,
		  struct txn **mytid)
{
    int r = 0;
    DBT k;
    DB_TXN *tid;
    DB *db = (DB *) mydb;

    assert(dbinit && db);
    assert(key && keylen);

    r = gettid(mytid, &tid);
    if (r) return r;

    memset(&k, 0, sizeof(k));

    k.data = (char *) key;
    k.size = keylen;

    if (!mytid) {
    restart:
	/* start txn for the write */
	r = txn_begin(dbenv, NULL, &tid, 0);
	if (r != 0) {
	    syslog(LOG_ERR, "DBERROR: error beginning txn: %s", 
		   db_strerror(r));
	    return CYRUSDB_IOERROR;
	}
	syslog(LOG_DEBUG, "starting txn %d", txn_id(tid));
    }
    r = db->del(db, tid, &k, 0);
    if (!mytid) {
	/* finish txn for the write */
	if (r) {
	    int r2 = txn_abort(tid);
	    if (r2) {
		syslog(LOG_ERR, "DBERROR: error aborting txn: %s", 
		       db_strerror(r));
		return CYRUSDB_IOERROR;
	    }

	    if (r == DB_LOCK_DEADLOCK) {
		goto restart;
	    }
	} else {
	    r = txn_commit(tid, 0);
	}
    }

    if (r != 0) {
	if (mytid) abort_txn(mydb, *mytid);
	if (r == DB_LOCK_DEADLOCK) {
	    r = CYRUSDB_AGAIN;
	} else {
	    syslog(LOG_ERR, "DBERROR: error deleting %s: %s",
		   key, db_strerror(r));
	    r = CYRUSDB_IOERROR;
	}
    }

    return r;
}

static int commit_txn(struct db *db, struct txn *tid)
{
    int r;
    DB_TXN *t = (DB_TXN *) tid;

    assert(dbinit && tid);

    r = txn_commit(t, 0);
    switch (r) {
    case 0:
	break;
    case EINVAL:
	syslog(LOG_WARNING, "tried to commit an already aborted transaction");
	r = CYRUSDB_IOERROR;
	break;
    default:
	syslog(LOG_ERR, "DBERROR: failed on commit: %s",
	       db_strerror(r));
	r = CYRUSDB_IOERROR;
	break;
    }

    return r;
}

static int abort_txn(struct db *db, struct txn *tid)
{
    int r;
    DB_TXN *t = (DB_TXN *) tid;

    assert(dbinit && tid);

    r = txn_abort(t);
    if (r != 0) {
	syslog(LOG_ERR, "DBERROR: error aborting txn: %s", db_strerror(r));
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
