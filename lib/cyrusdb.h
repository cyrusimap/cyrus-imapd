/* cyrusdb.h */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

/**
 * @file cyrusdb.h
 * @brief The key-value store interface and its backends
 *
 * cyrusdb is the one API through which Cyrus reads and writes its sorted
 * key-value databases: mailboxes.db, annotations.db, the per-user seen,
 * subscription and conversations databases, and the rest.  A database is
 * opened by backend name and path, and from then on every operation goes
 * through the cyrusdb_* functions here, which dispatch to the backend's
 * struct cyrusdb_backend.  It's part of libcyrus, not libcyrus_min.
 *
 * **Backends**
 *
 * Each is a lib/cyrusdb_NAME.c, registered in lib/cyrusdb.c, and named as
 * imapd.conf names it:
 *
 * - `twoskip`: the default; one file
 * - `twom`: one file; the newest format
 * - `zeroskip`: a directory of files
 * - `skiplist`: the old single-file format; still read, and convertible
 * - `flat`: a text file, one record per line; not binary-safe
 * - `quotalegacy`: the one-file-per-quota-root layout of old Cyrus, as a
 *   database
 * - `sql`: only when built with a SQL library; the path is a connection
 *   descriptor, not a file
 *
 * imapd.conf picks a backend per database with the `*_db` options
 * (`annotation_db`, `mboxlist_db`, ...) and a location with the matching
 * `*_db_path`; imap/global.c reads the former into the `config_*_db`
 * strings, which name a backend, not a file.
 *
 * **Lifecycle**
 *
 * cyrusdb_init() and cyrusdb_done() run once per process, from
 * libcyrus_init() and libcyrus_done(), which cyrus_init() and cyrus_done()
 * call.  Nothing else calls them.  cyrusdb_init() creates the `db`
 * directory under the config directory and runs each backend's init() with
 * the `db_init_flags` libcyrus option; `ctl_cyrusdb -r` sets CYRUSDB_RECOVER
 * there, and only skiplist looks at it.
 *
 * **Opening**
 *
 * cyrusdb_open() takes a backend name, a path and cyrusdb_openflags, and
 * returns a `struct db` that every other call takes.  Opening a path a
 * second time in one process gets the same underlying engine, refcounted,
 * so locking it "again" through the second handle is an assertion failure,
 * not a nested lock.
 *
 * When the backend can't read the file as its own format
 * (CYRUSDB_BADFORMAT, or a file where the backend wants a directory or the
 * reverse), cyrusdb_open() runs cyrusdb_detect() on it under a global lock,
 * `<configdirectory>/lock/cyrusdb_convert.lock`.  With CYRUSDB_CONVERT, or
 * the `cyrusdb_autoconvert` option, the file is then converted in place to
 * the requested backend; otherwise it's opened with the backend detection
 * found.  Detection knows skiplist, twoskip and twom by their magic and
 * zeroskip by its directory contents, and can't tell flat or sql.
 *
 * cyrusdb_lockopen() opens and starts a transaction in one step, so a
 * single-operation caller needn't unlock and relock, and it's the only way
 * to open with CYRUSDB_SHARED.
 *
 * **Transactions and the tid argument**
 *
 * Every data operation ends with a `struct txn **`, and its value picks the
 * mode:
 *
 * - NULL: non-transactional.  The backend takes whatever lock the one
 *   operation needs and releases it before returning.
 * - a pointer to a NULL `struct txn *`: start a transaction, exclusive, and
 *   store its opaque handle there.
 * - a pointer to that handle: continue the transaction.
 *
 * A transaction ends with cyrusdb_commit() or cyrusdb_abort(), and the
 * handle is invalid after either, whether or not it succeeded; a commit
 * that fails aborts.  While a transaction is open, every operation on that
 * database must pass it.  Transactions don't nest, and starting a second
 * one is an assertion failure.  twoskip and skiplist quietly use the open
 * transaction when a read passes NULL instead; don't rely on that.
 *
 * cyrusdb_lock() starts a transaction without doing anything else.  With
 * CYRUSDB_SHARED it's a shared one: readers don't exclude each other, and a
 * write in it is an error.  flat, quotalegacy and sql have no lock()
 * method, so they can only start a transaction through a read or write.
 *
 * **Reading**
 *
 * cyrusdb_fetch() reads one exact key.  cyrusdb_fetchnext() reads the first
 * key after the one given, whether or not that key exists, so given "f" and
 * "g", fetchnext of either "f" or "foo" finds "g"; only twoskip, twom and
 * zeroskip implement it, and cyrusdb_canfetchnext() says which.
 * cyrusdb_foreach() visits every key with a prefix, in key order, and
 * cyrusdb_forone() runs foreach's callbacks on one exact key.  Key order is
 * the backend's comparator, exposed as cyrusdb_compar(): flat orders keys
 * as mailbox names, skiplist compares bytes as signed chars, and the rest
 * compare unsigned bytes.
 *
 * forone and foreach together visit "folder" and everything under
 * "folder." without the "folder2" siblings that share the shorter prefix:
 *
 * @code
 * r = cyrusdb_forone(db, "folder", 6, p, cb, rock, &tid);
 * if (!r) r = cyrusdb_foreach(db, "folder.", 7, p, cb, rock, &tid);
 * @endcode
 *
 * The data a fetch returns, and the key and data a foreach callback
 * receives, point into the backend's map of the file.  They aren't
 * NUL-terminated, so copy them (xstrndup(), or buf_init_ro() and
 * buf_cstring()) before using them as C strings.  They're valid only until
 * the next operation on that database, including another read: an unlocked
 * read may find a newer file and remap.  Use or copy the data first, then
 * touch the database.
 *
 * **Iteration**
 *
 * foreach takes two callbacks with the same signature and different return
 * conventions.  The filter `p`, which may be NULL, runs with the database
 * locked and returns true to process the record or false to skip it; keep
 * it quick, and don't touch the database from it.  The callback `cb`
 * returns a CYRUSDB_* code: 0 to continue, anything else to stop, and
 * foreach returns that value.  CYRUSDB_DONE is the conventional
 * "stop, and that's not an error".
 *
 * Without a transaction, the lock is released before `cb` and retaken after
 * it, so `cb` may read and write the same database.  The iterator then
 * finds its place again by key, so a record `cb` inserts after the current
 * one is visited and one it inserts before it isn't.  A write from `cb` may
 * also invalidate the key and data pointers it was given.  With a
 * transaction, the lock is held throughout, and `cb` must use that same
 * transaction, which means passing it and the db in `rock`.
 *
 * **Writing**
 *
 * cyrusdb_store() creates or replaces; cyrusdb_create() fails with
 * CYRUSDB_EXISTS on an existing key; cyrusdb_delete() removes, and with
 * `force` succeeds on a missing key too.  Without a transaction, each is
 * its own write-locked transaction.  A failed write aborts the transaction
 * it was in.
 *
 * **Keys and values**
 *
 * Both are binary-safe, NUL included, in every backend but flat and
 * quotalegacy.  A key is at least one byte.  A value may be empty: store
 * NULL or "" with a datalen of 0, and fetch returns a non-NULL pointer to
 * zero bytes.
 *
 * **Return codes**
 *
 * Every function returns 0 (CYRUSDB_OK) or another cyrusdb_ret, never an
 * IMAP_* code; cyrusdb_strerror() names them.  A wrapper whose backend
 * lacks the method returns CYRUSDB_NOTIMPLEMENTED, except cyrusdb_dump(),
 * cyrusdb_consistent() and cyrusdb_repack(), which return 0.
 *
 * **Tools**
 *
 * `ctl_cyrusdb -r` runs at every startup.  It converts each configured
 * database that cyrusdb_detect() finds in another format, and sets
 * CYRUSDB_RECOVER for the backends' init().  `ctl_cyrusdb -c` runs
 * periodically and copies the databases into rotating backup directories
 * with each backend's archiver.  cvt_cyrusdb converts one database between
 * backends, and cyr_dbtool reads, writes and iterates any database from the
 * command line.
 */

#ifndef INCLUDED_CYRUSDB_H
#define INCLUDED_CYRUSDB_H

#include <stdio.h>
#include "strarray.h"

/** @brief An open database: a backend plus its engine state */
struct db;

/** @brief An open transaction; opaque, and owned by the backend */
struct txn;

/**
 * @brief Return codes.  Not IMAP_* codes; see cyrusdb_strerror().
 */
enum cyrusdb_ret {
    /** @brief Success */
    CYRUSDB_OK = 0,
    /** @brief A foreach callback's "stop iterating, and all is well" */
    CYRUSDB_DONE = 1,
    /** @brief Any error reading or writing the file, including corruption */
    CYRUSDB_IOERROR = -1,
    /** @brief A deadlock aborted the transaction; a retry may succeed */
    CYRUSDB_AGAIN = -2,
    /** @brief create() on a key that exists */
    CYRUSDB_EXISTS = -3,
    /** @brief A misuse the API caught, e.g. CYRUSDB_SHARED with CONVERT */
    CYRUSDB_INTERNAL = -4,
    /** @brief fetch() or an unforced delete() on a key that doesn't exist */
    CYRUSDB_NOTFOUND = -5,
    /** @brief The transaction passed doesn't match the one the db holds */
    CYRUSDB_LOCKED = -6,
    /** @brief The backend has no such method */
    CYRUSDB_NOTIMPLEMENTED = -7,
    /** @brief No space left for the write */
    CYRUSDB_FULL = -8,
    /** @brief A write in a shared transaction, or to a read-only database */
    CYRUSDB_READONLY = -9,
    /** @brief The file isn't in the backend's format; triggers detection */
    CYRUSDB_BADFORMAT = -10,
};

/** @brief Flags for a backend's init(), from the db_init_flags option */
enum cyrusdb_initflags {
    /** @brief Set by ctl_cyrusdb -r.  skiplist stamps a recovery time, and
     *  recovers each database older than it on open. */
    CYRUSDB_RECOVER = 0x01
};

/** @brief Flags for cyrusdb_open(), cyrusdb_lockopen() and cyrusdb_lock() */
enum cyrusdb_openflags {
    /** @brief Create the database if it doesn't exist */
    CYRUSDB_CREATE    = 0x01,
    /** @brief Don't fsync; for data that can be lost (twom, zeroskip) */
    CYRUSDB_NOSYNC    = 0x02,
    /** @brief Convert a file in another format to this backend, in place */
    CYRUSDB_CONVERT   = 0x04,
    /** @brief Skip automatic compaction; e.g. on a read-only filesystem */
    CYRUSDB_NOCOMPACT = 0x08,
    /** @brief Open or lock with a shared transaction; excludes CONVERT */
    CYRUSDB_SHARED    = 0x10,
    /** @brief Don't check CRC32s on read (twoskip, twom, zeroskip) */
    CYRUSDB_NOCRC     = 0x20
};

/** @brief Properties a backend declares in cyrusdb_backend::flags */
enum cyrusdb_backendflags {
    /* the database is a directory rather than a single file.  cyrusdb_open()
       stats fname and compares S_ISDIR() against this flag to spot a shape
       mismatch and route it to conversion.

       quotalegacy sets it too, but the check never fires there: quotalegacy is
       opened with a sentinel fname that nothing creates, it stats
       dirname(fname) itself, so cyrusdb_open()'s stat fails first.  Don't rely
       on that if quotalegacy ever gets a real path. */
    /** @brief The database is a directory rather than a single file */
    CYRUSDB_BACKEND_ISDIR = 0x01
};

/**
 * @brief The foreach filter: true to process the record, false to skip it
 *
 * Runs with the database locked, so keep it quick and don't touch the
 * database.  NULL means "process every record".
 */
typedef int foreach_p(void *rock,
                      const char *key, size_t keylen,
                      const char *data, size_t datalen);

/**
 * @brief The foreach callback: 0 to continue, any other CYRUSDB_* to stop
 *
 * Without a transaction, runs with the database unlocked and may read or
 * write it.  With one, must use that transaction, passed through rock.
 * data is never NULL; an empty value is a zero-length buffer.
 */
typedef int foreach_cb(void *rock,
                       const char *key, size_t keylen,
                       const char *data, size_t datalen);

/** @brief A backend's archiver: copy the named databases into dirname */
typedef int cyrusdb_archiver(const strarray_t *fnames,
                             const char *dirname);

/** @brief A backend's per-database state; opaque outside the backend */
struct dbengine;

/**
 * @brief The method table a backend implements
 *
 * Every method returns a cyrusdb_ret.  Except where noted, a NULL method
 * makes the matching cyrusdb_* wrapper return CYRUSDB_NOTIMPLEMENTED.
 * Transaction arguments follow the rules in the file comment.
 */
struct cyrusdb_backend {
    /** @brief The name imapd.conf uses */
    const char *name;

    /** @brief Once per process, from cyrusdb_init(); nothing else is legal
     *  until it returns */
    int (*init)(const char *dbdir, int myflags);

    /** @brief Once per process, from cyrusdb_done(); nothing is legal once
     *  it starts, but init() may be called again afterwards */
    int (*done)(void);

    /** @brief Copy the named databases into the directory */
    int (*archive)(const strarray_t *fnames, const char *dirname);

    /** @brief Remove the database, including any environment it has */
    int (*unlink)(const char *fname, int flags);

    /** @brief Open the database; with a non-NULL tid, start a transaction
     *  too.  CYRUSDB_BADFORMAT sends cyrusdb_open() to detection. */
    int (*open)(const char *fname, int flags, struct dbengine **ret, struct txn **tid);

    /** @brief Close the database, releasing any lock still held */
    int (*close)(struct dbengine *db);

    /**
     * @brief Fetch the value of one exact key
     *
     * On success data points to a non-NULL internal buffer, not
     * NUL-terminated, and datalen is its length; an empty value is a
     * zero-length buffer, not NULL.  data may be NULL if only the length is
     * wanted.  Keys and values are binary-safe except in flat and
     * quotalegacy.  Returns CYRUSDB_NOTFOUND for a missing key.
     */
    int (*fetch)(struct dbengine *mydb,
                 const char *key, size_t keylen,
                 const char **data, size_t *datalen,
                 struct txn **mytid);

    /** @brief fetch(), plus a hint that the record will soon be modified.
     *  Useless without a transaction.  Every current backend aliases fetch. */
    int (*fetchlock)(struct dbengine *mydb,
                     const char *key, size_t keylen,
                     const char **data, size_t *datalen,
                     struct txn **mytid);

    /** @brief Fetch the first record whose key sorts after key, whether or
     *  not key itself exists.  NULL in flat, skiplist, quotalegacy and sql. */
    int (*fetchnext)(struct dbengine *mydb,
                 const char *key, size_t keylen,
                 const char **foundkey, size_t *foundkeylen,
                 const char **data, size_t *datalen,
                 struct txn **mytid);

    /**
     * @brief Call cb on every record with the prefix that p accepts
     *
     * Without a transaction, the lock is dropped around each cb, so cb may
     * change the database; a record it adds after the cursor is visited, one
     * it adds before it isn't, and other processes' changes may or may not
     * be seen.  With a transaction, cb must use it for any database call.
     * flat isn't reentrant from cb without a transaction.
     */
    int (*foreach)(struct dbengine *mydb,
                   const char *prefix, size_t prefixlen,
                   foreach_p *p,
                   foreach_cb *cb, void *rock,
                   struct txn **tid);

    /** @brief Add a record; CYRUSDB_EXISTS if the key exists.  NULL data or
     *  a datalen of 0 stores an empty value, which fetch gives back. */
    int (*create)(struct dbengine *db,
                  const char *key, size_t keylen,
                  const char *data, size_t datalen,
                  struct txn **tid);

    /** @brief Add or replace a record; otherwise as create() */
    int (*store)(struct dbengine *db,
                 const char *key, size_t keylen,
                 const char *data, size_t datalen,
                 struct txn **tid);

    /** @brief Remove a record.  force=1 ignores a missing key; otherwise
     *  that's CYRUSDB_NOTFOUND.  The trailing underscore keeps the name legal
     *  in C++. */
    int (*delete_)(struct dbengine *db,
                   const char *key, size_t keylen,
                   struct txn **tid,
                   int force);

    /** @brief Start a transaction, shared if flags has CYRUSDB_SHARED.
     *  NULL in flat, quotalegacy and sql. */
    int (*lock)(struct dbengine *db, struct txn **tid, int flags);

    /** @brief Commit; tid is invalid afterwards whether or not it worked */
    int (*commit)(struct dbengine *db, struct txn *tid);

    /** @brief Roll back; tid is invalid afterwards */
    int (*abort)(struct dbengine *db, struct txn *tid);

    /** @brief Print the internal structure to stdout; NULL returns 0 */
    int (*dump)(struct dbengine *db, int detail);
    /** @brief Check internal consistency; NULL returns 0 */
    int (*consistent)(struct dbengine *db);
    /** @brief Rewrite the file compactly; NULL returns 0 */
    int (*repack)(struct dbengine *db);
    /** @brief The key ordering: a bsearch_ncompare_* function */
    int (*compar)(const char *s1, size_t l1, const char *s2, size_t l2);

    /** @brief A bitmask of cyrusdb_backendflags */
    unsigned flags;
};

/** @brief Copy a database file, or a directory-shaped database wholesale,
 *  skipping its lock files.  Returns -1 on failure. */
extern int cyrusdb_copyfile(const char *srcname, const char *dstname);

/**
 * @brief Copy every record from one database into a new one
 *
 * tofname may equal fromfname, in which case the copy is written beside it
 * and renamed into place, moving the original aside first if the two
 * backends differ in shape (file or directory).  A failure leaves the
 * original untouched.
 */
extern int cyrusdb_convert(const char *fromfname, const char *tofname,
                           const char *frombackend, const char *tobackend);

/** @brief Remove a database through its backend, which knows its shape */
extern int cyrusdb_unlink(const char *backend, const char *fname, int flags);

/**
 * @brief Write every record with the prefix to f, one per line
 *
 * Each line is the key, a tab, and the value, or the value's bytes as
 * space-separated hex when any byte isn't printable.  The hex form isn't
 * read back by cyrusdb_undumpfile().
 */
extern int cyrusdb_dumpfile(struct db *db,
                            const char *prefix, size_t prefixlen,
                            FILE *f,
                            struct txn **tid);

/** @brief Delete every record */
extern int cyrusdb_truncate(struct db *db,
                            struct txn **tid);

/**
 * @brief Store records from f, in cyrusdb_dumpfile()'s format
 *
 * A line without a tab deletes its key; blank lines and lines starting with
 * `#` are skipped.
 */
extern int cyrusdb_undumpfile(struct db *db,
                              FILE *f,
                              struct txn **tid);

/** @brief Name the backend that wrote fname, or NULL if it can't tell.
 *  Knows skiplist, twoskip, twom and zeroskip; not flat or sql. */
extern const char *cyrusdb_detect(const char *fname);

/** @brief Create the db directory and init() every backend.  Only
 *  libcyrus_init() calls this. */
void cyrusdb_init(void);

/** @brief done() every backend.  Only libcyrus_done() calls this. */
void cyrusdb_done(void);

/** @brief Open a database; see the file comment for detection and
 *  conversion.  backend NULL means the default, twoskip. */
extern int cyrusdb_open(const char *backend, const char *fname,
                        int flags, struct db **ret);

/** @brief cyrusdb_open(), and start a transaction in tid.  Required for
 *  CYRUSDB_SHARED, which must not be combined with CYRUSDB_CONVERT. */
extern int cyrusdb_lockopen(const char *backend, const char *fname,
                           int flags, struct db **ret, struct txn **tid);

/** @brief Close and free the handle.  Commit or abort first; closing with
 *  a transaction open is an error the backend logs. */
extern int cyrusdb_close(struct db *db);

/** @brief Fetch one exact key; see cyrusdb_backend::fetch */
extern int cyrusdb_fetch(struct db *db,
                         const char *key, size_t keylen,
                         const char **data, size_t *datalen,
                         struct txn **mytid);

/** @brief Fetch with a hint that the record will be modified */
extern int cyrusdb_fetchlock(struct db *db,
                             const char *key, size_t keylen,
                             const char **data, size_t *datalen,
                             struct txn **mytid);

/** @brief Fetch the first record after key; see cyrusdb_backend::fetchnext */
extern int cyrusdb_fetchnext(struct db *db,
                             const char *key, size_t keylen,
                             const char **found, size_t *foundlen,
                             const char **data, size_t *datalen,
                             struct txn **mytid);

/** @brief Iterate the records with a prefix; a NULL prefix with prefixlen 0
 *  is every record.  See cyrusdb_backend::foreach. */
extern int cyrusdb_foreach(struct db *db,
                           const char *prefix, size_t prefixlen,
                           foreach_p *p,
                           foreach_cb *cb, void *rock,
                           struct txn **tid);

/** @brief Run foreach's callbacks on one exact key.  A missing key is
 *  success, with no callback. */
extern int cyrusdb_forone(struct db *db,
                           const char *key, size_t keylen,
                           foreach_p *p,
                           foreach_cb *cb, void *rock,
                           struct txn **tid);

/** @brief Add a record; CYRUSDB_EXISTS if the key exists */
int cyrusdb_create(struct db *db,
                          const char *key, size_t keylen,
                          const char *data, size_t datalen,
                          struct txn **tid);

/** @brief Add or replace a record */
extern int cyrusdb_store(struct db *db,
                         const char *key, size_t keylen,
                         const char *data, size_t datalen,
                         struct txn **tid);

/** @brief Remove a record; with force, a missing key is success.  The
 *  only call with an argument after tid. */
extern int cyrusdb_delete(struct db *db,
                          const char *key, size_t keylen,
                          struct txn **tid, int force);

/** @brief Start a transaction, shared with CYRUSDB_SHARED in flags */
extern int cyrusdb_lock(struct db *db, struct txn **tid, int flags);

/** @brief Commit tid, which is invalid afterwards.  A failed commit
 *  aborts. */
extern int cyrusdb_commit(struct db *db, struct txn *tid);

/** @brief Roll back tid, which is invalid afterwards */
extern int cyrusdb_abort(struct db *db, struct txn *tid);

/** @brief Print the internal structure to stdout, for debugging */
extern int cyrusdb_dump(struct db *db, int detail);

/** @brief Check internal consistency */
extern int cyrusdb_consistent(struct db *db);

/** @brief Rewrite the file compactly */
extern int cyrusdb_repack(struct db *db);

/** @brief Compare two keys in the database's order */
extern int cyrusdb_compar(struct db *db,
                          const char *a, size_t alen,
                          const char *b, size_t blen);

/* somewhat special case, because they don't take a DB */

/** @brief The backend's archiver, for ctl_cyrusdb -c */
extern cyrusdb_archiver *cyrusdb_getarchiver(const char *backend);

/** @brief Whether the backend implements fetchnext */
extern int cyrusdb_canfetchnext(const char *backend);

/** @brief The names of the backends built in; the caller frees it */
extern strarray_t *cyrusdb_backends(void);

/* generic implementations, for backends with nothing special to do */

/** @brief An init() that does nothing */
int cyrusdb_generic_init(const char *dbdir, int myflags);
/** @brief A done() that does nothing */
int cyrusdb_generic_done(void);
/** @brief An archive() that copies each named file into dirname with
 *  cyrusdb_copyfile() */
int cyrusdb_generic_archive(const strarray_t *fnames, const char *dirname);
/** @brief An archive() that copies nothing, for a backend with no files
 *  worth saving */
int cyrusdb_generic_noarchive(const strarray_t *fnames, const char *dirname);
/** @brief An unlink() that removes the one file */
int cyrusdb_generic_unlink(const char *fname, int flags);

/** @brief A short description of a cyrusdb_ret */
extern const char *cyrusdb_strerror(int r);

#endif /* INCLUDED_CYRUSDB_H */
