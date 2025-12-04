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
 */

#ifndef INCLUDED_CYRUSDB_H
#define INCLUDED_CYRUSDB_H

#include <stdio.h>
#include "strarray.h"

struct db;
struct txn;

enum cyrusdb_ret {
    CYRUSDB_OK = 0,
    CYRUSDB_DONE = 1,
    CYRUSDB_IOERROR = -1,
    CYRUSDB_AGAIN = -2,
    CYRUSDB_EXISTS = -3,
    CYRUSDB_INTERNAL = -4,
    CYRUSDB_NOTFOUND = -5,
    CYRUSDB_LOCKED = -6,
    CYRUSDB_NOTIMPLEMENTED = -7,
    CYRUSDB_FULL = -8,
    CYRUSDB_READONLY = -9,
    CYRUSDB_BADFORMAT = -10,
};

enum cyrusdb_initflags {
    CYRUSDB_RECOVER = 0x01
};

enum cyrusdb_openflags {
    CYRUSDB_CREATE    = 0x01,    /* Create the database if not existant */
    CYRUSDB_NOSYNC    = 0x02,    /* durability not a concern */
    CYRUSDB_CONVERT   = 0x04,    /* Convert to the named format if not already */
    CYRUSDB_NOCOMPACT = 0x08,    /* Don't run any database compaction routines */
    CYRUSDB_SHARED    = 0x10,    /* Open in shared lock mode */
    CYRUSDB_NOCRC     = 0x20     /* Don't check CRC32 on read */
};

typedef int foreach_p(void *rock,
                      const char *key, size_t keylen,
                      const char *data, size_t datalen);

typedef int foreach_cb(void *rock,
                       const char *key, size_t keylen,
                       const char *data, size_t datalen);

typedef int cyrusdb_archiver(const strarray_t *fnames,
                             const char *dirname);

struct dbengine;


struct cyrusdb_backend {
    const char *name;

    /* init() should be called once per process; no calls are legal
     * until init() returns */
    int (*init)(const char *dbdir, int myflags);

    /* done() should be called once per process; no calls are legal
     * once done() starts.  it is legal to call init() after done() returns
     * to reset state */
    int (*done)(void);

    /* archives this database environment, and specified databases
     * into the specified directory */
    int (*archive)(const strarray_t *fnames, const char *dirname);

    /* unlinks this specific database, including cleaning up any environment */
    int (*unlink)(const char *fname, int flags);

    /* yield any transactions on the current database */
    int (*yield)(struct dbengine *db);

    /* open the specified database in the global environment */
    int (*open)(const char *fname, int flags, struct dbengine **ret, struct txn **tid);

    /* close the specified database */
    int (*close)(struct dbengine *db);

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
    int (*fetch)(struct dbengine *mydb,
                 const char *key, size_t keylen,
                 const char **data, size_t *datalen,
                 struct txn **mytid);
    int (*fetchlock)(struct dbengine *mydb,
                     const char *key, size_t keylen,
                     const char **data, size_t *datalen,
                     struct txn **mytid);
    int (*fetchnext)(struct dbengine *mydb,
                 const char *key, size_t keylen,
                 const char **foundkey, size_t *foundkeylen,
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
        length record, data will point to a zero length buffer.
        Calling store, create or delete within a callback may invalidate
        the memory pointed to by the data parameter. */
    int (*foreach)(struct dbengine *mydb,
                   const char *prefix, size_t prefixlen,
                   foreach_p *p,
                   foreach_cb *cb, void *rock,
                   struct txn **tid);

    /* Place entries in database.  create will not overwrite existing
     * entries.
     * Passing data=NULL or datalen=0 places a zero-length record in
     * the database, which can be fetched back again.  */
    int (*create)(struct dbengine *db,
                  const char *key, size_t keylen,
                  const char *data, size_t datalen,
                  struct txn **tid);
    int (*store)(struct dbengine *db,
                 const char *key, size_t keylen,
                 const char *data, size_t datalen,
                 struct txn **tid);

    /* Remove entries from the database
     * n.b. trailing underscore so that C++ apps can also use this API
     */
    int (*delete_)(struct dbengine *db,
                   const char *key, size_t keylen,
                   struct txn **tid,
                   int force); /* 1 = ignore not found errors */

    /* start a transaction (shared if flags & CYRUSDB_SHARED) */
    int (*lock)(struct dbengine *db, struct txn **tid, int flags);

    /* Commit the transaction.  When commit() returns, the tid will no longer
     * be valid, regardless of if the commit succeeded or failed */
    int (*commit)(struct dbengine *db, struct txn *tid);

    /* Abort the transaction and invalidate the tid */
    int (*abort)(struct dbengine *db, struct txn *tid);

    int (*dump)(struct dbengine *db, int detail);
    int (*consistent)(struct dbengine *db);
    int (*repack)(struct dbengine *db);
    int (*compar)(const char *s1, size_t l1, const char *s2, size_t l2);
};

extern int cyrusdb_copyfile(const char *srcname, const char *dstname);

extern int cyrusdb_convert(const char *fromfname, const char *tofname,
                           const char *frombackend, const char *tobackend);

extern int cyrusdb_unlink(const char *backend, const char *fname, int flags);

extern int cyrusdb_dumpfile(struct db *db,
                            const char *prefix, size_t prefixlen,
                            FILE *f,
                            struct txn **tid);
extern int cyrusdb_truncate(struct db *db,
                            struct txn **tid);
extern int cyrusdb_undumpfile(struct db *db,
                              FILE *f,
                              struct txn **tid);


extern const char *cyrusdb_detect(const char *fname);

/* Start/Stop the backends */
void cyrusdb_init(void);
void cyrusdb_done(void);

/* direct DB interface */
extern int cyrusdb_open(const char *backend, const char *fname,
                        int flags, struct db **ret);
extern int cyrusdb_lockopen(const char *backend, const char *fname,
                           int flags, struct db **ret, struct txn **tid);
extern int cyrusdb_close(struct db *db);
extern int cyrusdb_fetch(struct db *db,
                         const char *key, size_t keylen,
                         const char **data, size_t *datalen,
                         struct txn **mytid);
extern int cyrusdb_fetchlock(struct db *db,
                             const char *key, size_t keylen,
                             const char **data, size_t *datalen,
                             struct txn **mytid);
extern int cyrusdb_fetchnext(struct db *db,
                             const char *key, size_t keylen,
                             const char **found, size_t *foundlen,
                             const char **data, size_t *datalen,
                             struct txn **mytid);
extern int cyrusdb_foreach(struct db *db,
                           const char *prefix, size_t prefixlen,
                           foreach_p *p,
                           foreach_cb *cb, void *rock,
                           struct txn **tid);
extern int cyrusdb_forone(struct db *db,
                           const char *key, size_t keylen,
                           foreach_p *p,
                           foreach_cb *cb, void *rock,
                           struct txn **tid);
int cyrusdb_create(struct db *db,
                          const char *key, size_t keylen,
                          const char *data, size_t datalen,
                          struct txn **tid);
extern int cyrusdb_store(struct db *db,
                         const char *key, size_t keylen,
                         const char *data, size_t datalen,
                         struct txn **tid);
extern int cyrusdb_delete(struct db *db,
                          const char *key, size_t keylen,
                          struct txn **tid, int force);
extern int cyrusdb_lock(struct db *db, struct txn **tid, int flags);
extern int cyrusdb_commit(struct db *db, struct txn *tid);
extern int cyrusdb_abort(struct db *db, struct txn *tid);
extern int cyrusdb_dump(struct db *db, int detail);
extern int cyrusdb_consistent(struct db *db);
extern int cyrusdb_repack(struct db *db);
extern int cyrusdb_yield(struct db *db);
extern int cyrusdb_compar(struct db *db,
                          const char *a, size_t alen,
                          const char *b, size_t blen);

/* somewhat special case, because they don't take a DB */

extern cyrusdb_archiver *cyrusdb_getarchiver(const char *backend);

extern int cyrusdb_canfetchnext(const char *backend);

extern strarray_t *cyrusdb_backends(void);

/* generic implementations */
int cyrusdb_generic_init(const char *dbdir, int myflags);
int cyrusdb_generic_done(void);
int cyrusdb_generic_archive(const strarray_t *fnames, const char *dirname);
int cyrusdb_generic_noarchive(const strarray_t *fnames, const char *dirname);
int cyrusdb_generic_unlink(const char *fname, int flags);

extern const char *cyrusdb_strerror(int r);

#endif /* INCLUDED_CYRUSDB_H */
