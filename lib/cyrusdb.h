/* 
 * Copyright (c) 1998-2003 Carnegie Mellon University.  All rights reserved.
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

/* $Id: cyrusdb.h,v 1.22 2003/02/13 20:15:39 rjs3 Exp $ */

#ifndef INCLUDED_CYRUSDB_H
#define INCLUDED_CYRUSDB_H

struct db;
struct txn;

enum cyrusdb_ret {
    CYRUSDB_OK = 0,
    CYRUSDB_DONE = 1,
    CYRUSDB_IOERROR = -1,
    CYRUSDB_AGAIN = -2,
    CYRUSDB_EXISTS = -3,
    CYRUSDB_INTERNAL = -4
};

#define cyrusdb_strerror(c) ("cyrusdb error")

enum cyrusdb_initflags {
    CYRUSDB_RECOVER = 0x01
};

enum cyrusdb_dbflags {
    CYRUSDB_NOSYNC = 0x01	/* durability not a concern */
};

typedef int foreach_p(void *rock,
		      const char *key, int keylen,
		      const char *data, int datalen);

typedef int foreach_cb(void *rock,
		       const char *key, int keylen,
		       const char *data, int datalen);

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
    int (*open)(const char *fname, struct db **ret);

    /* close the specified database */
    int (*close)(struct db *db);

    /* what are the overall specifications? */
    /* 'mydb': the database to act on
       'key': the key to fetch.  cyrusdb currently requires this to not have
              any of [\t\n\0] in keys
       'keylen': length of the key
       'data': where to put the data (generally won't have [\n\0])
       'datalen': how big is the data?
       'mytid': may be NULL, in which case the fetch is not txn protected.
                if mytid != NULL && *mytid == NULL, begins a new txn
		if mytid != NULL && *mytid != NULL, continues an old txn

		transactions may lock the entire database on some backends.
		beware
		
       fetchlock() is identical to fetch() except gives a hint to the
       underlying database that the key/data being fetched will be modified
       soon. it is useless to use fetchlock() without a non-NULL mytid
    */
    int (*fetch)(struct db *mydb, 
		 const char *key, int keylen,
		 const char **data, int *datalen,
		 struct txn **mytid);
    int (*fetchlock)(struct db *mydb, 
		     const char *key, int keylen,
 		     const char **data, int *datalen,
		     struct txn **mytid);

    /* foreach: iterate through entries that start with 'prefix'
       if 'p' returns true, call 'cb'

       'p' should be fast and should avoid blocking it should be safe
       to call other db routines inside of 'cb'.  however, the "flat"
       backend is currently are not reentrant in this way
       unless you're using transactions and pass the same transaction
       to all db calls during the life of foreach() */
    int (*foreach)(struct db *mydb,
		   char *prefix, int prefixlen,
		   foreach_p *p,
		   foreach_cb *cb, void *rock, 
		   struct txn **tid);
    int (*create)(struct db *db, 
		  const char *key, int keylen,
		  const char *data, int datalen,
		  struct txn **tid);
    int (*store)(struct db *db, 
		 const char *key, int keylen,
		 const char *data, int datalen,
		 struct txn **tid);
    int (*delete)(struct db *db, 
		  const char *key, int keylen,
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

extern struct cyrusdb_backend cyrusdb_db3;
extern struct cyrusdb_backend cyrusdb_db3_nosync;
extern struct cyrusdb_backend cyrusdb_flat;
extern struct cyrusdb_backend cyrusdb_skiplist;

extern int cyrusdb_copyfile(const char *srcname, const char *dstname);

#endif /* INCLUDED_CYRUSDB_H */
