/*
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
 * $Id: cyrusdb.h,v 1.34 2010/01/06 17:01:44 murch Exp $
 */

#ifndef INCLUDED_CYRUSDB_H
#define INCLUDED_CYRUSDB_H

#include <stdio.h>

struct db;
struct txn;

enum cyrusdb_ret {
    CYRUSDB_OK = 0,
    CYRUSDB_DONE = 1,
    CYRUSDB_IOERROR = -1,
    CYRUSDB_AGAIN = -2,
    CYRUSDB_EXISTS = -3,
    CYRUSDB_INTERNAL = -4,
    CYRUSDB_NOTFOUND = -5
};

#define cyrusdb_strerror(c) ("cyrusdb error")

enum cyrusdb_initflags {
    CYRUSDB_RECOVER = 0x01
};

enum cyrusdb_dbflags {
    CYRUSDB_NOSYNC = 0x01	/* durability not a concern */
};

enum cyrusdb_openflags {
    CYRUSDB_CREATE   = 0x01,	/* Create the database if not existant */
    CYRUSDB_MBOXSORT = 0x02	/* Use mailbox sort order ('.' sorts 1st) */
};

typedef int foreach_p(void *rock,
		      const char *key, size_t keylen,
		      const char *data, size_t datalen);

typedef int foreach_cb(void *rock,
		       const char *key, size_t keylen,
		       const char *data, size_t datalen);

struct cyrusdb_backend {
    const char *name;

    /* init() should be called once per process; no calls are legal
     * until init() returns */
    int (*init)(const char *dbdir, int myflags);

    /* done() should be called once per process; no calls are legal
     * once done() starts.  it is legal to call init() after done() returns
     * to reset state */
    int (*done)(void);

    /* checkpoints this database environment */
    int (*sync)(void);

    /* archives this database environment, and specified databases
     * into the specified directory */
    int (*archive)(const char **fnames, const char *dirname);

    /* open the specified database in the global environment */
    int (*open)(const char *fname, int flags, struct db **ret);

    /* close the specified database */
    int (*close)(struct db *db);

    /* what are the overall specifications? */
    /* 'mydb': the database to act on
       'key': the key to fetch.
       'keylen': length of the key
       'data': where to put the data
       'datalen': how big is the data?
       'mytid': may be NULL, in which case the fetch is not txn protected.
                if mytid != NULL && *mytid == NULL, begins a new txn
		if mytid != NULL && *mytid != NULL, continues an old txn

		transactions may lock the entire database on some backends.
		beware
		
       fetchlock() is identical to fetch() except gives a hint to the
       underlying database that the key/data being fetched will be modified
       soon. it is useless to use fetchlock() without a non-NULL mytid

       If fetch returns successfully, 'data' will be filled in with a
       non-NULL pointer to an internal buffer.  The buffer is not in
       general terminated with a \0, so you cannot use C string
       operations on it without first making a copy (xstrndup(), or
       buf_init_ro() plus buf_cstring(), are easy ways to do this).
       For a zero length record 'data' will point to a zero length
       buffer, and will *not* be NULL.

       Both keys and data are binary-safe.  In particular the characters
       \0 \t \r and \n may be used in either keys or data.  For flat
       files this is achieved with an escaping mechanism.  The
       "quotalegacy" backend is designed for special legacy use only
       and breaks this rule.
    */
    int (*fetch)(struct db *mydb, 
		 const char *key, size_t keylen,
		 const char **data, size_t *datalen,
		 struct txn **mytid);
    int (*fetchlock)(struct db *mydb, 
		     const char *key, size_t keylen,
 		     const char **data, size_t *datalen,
		     struct txn **mytid);

    /* foreach: iterate through entries that start with 'prefix'
       if 'p' is NULL (always true) or returns true, call 'cb'

       if 'cb' changes the database, these changes will only be visible
       if they are after the current database cursor.  If other processes
       change the database (i.e. outside of a transaction) these changes
       may or may not be visible to the foreach()

       'p' should be fast and should avoid blocking it should be safe
       to call other db routines inside of 'cb'.  however, the "flat"
       backend is currently are not reentrant in this way
       unless you're using transactions and pass the same transaction
       to all db calls during the life of foreach()

	The callbacks will never be called with data=NULL.  For a zero
	length record, data will point to a zero length buffer.  */
    int (*foreach)(struct db *mydb,
		   const char *prefix, size_t prefixlen,
		   foreach_p *p,
		   foreach_cb *cb, void *rock, 
		   struct txn **tid);

    /* Place entries in database.  create will not overwrite existing
     * entries.
     * Passing data=NULL or datalen=0 places a zero-length record in
     * the database, which can be fetched back again.  */
    int (*create)(struct db *db, 
		  const char *key, size_t keylen,
		  const char *data, size_t datalen,
		  struct txn **tid);
    int (*store)(struct db *db, 
		 const char *key, size_t keylen,
		 const char *data, size_t datalen,
		 struct txn **tid);

    /* Remove entrys from the database */
    int (*delete)(struct db *db, 
		  const char *key, size_t keylen,
		  struct txn **tid,
		  int force); /* 1 = ignore not found errors */
    
    /* Commit the transaction.  When commit() returns, the tid will no longer
     * be valid, regardless of if the commit succeeded or failed */
    int (*commit)(struct db *db, struct txn *tid);

    /* Abort the transaction and invalidate the tid */
    int (*abort)(struct db *db, struct txn *tid);

    int (*dump)(struct db *db, int detail);
    int (*consistent)(struct db *db);
};

extern struct cyrusdb_backend *cyrusdb_backends[];

/* Note that some of these may be undefined symbols
 * if libcyrus was not built with support for them */
extern struct cyrusdb_backend cyrusdb_berkeley;
extern struct cyrusdb_backend cyrusdb_berkeley_nosync;
extern struct cyrusdb_backend cyrusdb_berkeley_hash;
extern struct cyrusdb_backend cyrusdb_berkeley_hash_nosync;
extern struct cyrusdb_backend cyrusdb_flat;
extern struct cyrusdb_backend cyrusdb_skiplist;
extern struct cyrusdb_backend cyrusdb_quotalegacy;
extern struct cyrusdb_backend cyrusdb_sql;

extern int cyrusdb_copyfile(const char *srcname, const char *dstname);

extern void cyrusdb_convert(const char *fromfname, const char *tofname,
			    struct cyrusdb_backend *frombackend,
			    struct cyrusdb_backend *tobackend);

int cyrusdb_dump(struct cyrusdb_backend *backend,
		 struct db *db,
		 const char *prefix, size_t prefixlen,
		 FILE *f,
		 struct txn **tid);
int cyrusdb_truncate(struct cyrusdb_backend *backend,
		     struct db *db,
		     struct txn **tid);
int cyrusdb_undump(struct cyrusdb_backend *backend,
		   struct db *db,
		   FILE *f,
		   struct txn **tid);


extern const char *cyrusdb_detect(const char *fname);

/* Start/Stop the backends */
void cyrusdb_init(void);
void cyrusdb_done(void);

/* Configuration */
struct cyrusdb_backend *cyrusdb_fromname(const char *name);

#endif /* INCLUDED_CYRUSDB_H */
