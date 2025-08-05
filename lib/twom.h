/* twom.h - twoskip implementation with MVCC capability
 *
 * Copyright (c) 2025 Fastmail Pty Ltd
 *
 * https://creativecommons.org/publicdomain/zero/1.0/
 *
 *   The person who associated a work with this deed has dedicated the work to the
 *   public domain by waiving all of his or her rights to the work worldwide under
 *   copyright law, including all related and neighboring rights, to the extent
 *   allowed by law.
 *
 *   You can copy, modify, distribute and perform the work, even for commercial
 *   purposes, all without asking permission.
 */

#ifndef INCLUDED_TWOM_H
#define INCLUDED_TWOM_H

#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>

struct twom_db;
struct twom_txn;
struct twom_cursor;

enum twom_ret {
    TWOM_OK = 0,
    TWOM_DONE = 1,
    TWOM_EXISTS = -1,
    TWOM_IOERROR = -2,
    TWOM_INTERNAL = -3,
    TWOM_LOCKED = -4,
    TWOM_NOTFOUND = -5,
    TWOM_READONLY = -6,
    TWOM_BADFORMAT = -7,
    TWOM_BADUSAGE = -8,
    TWOM_BADCHECKSUM = -9,
};

// we don't reuse flags for different operations (e.g. open, fetch, foreach), as
// there's 32 bits of space available - though not all flags have meaning in all contexts.
enum twom_flagspec {
    TWOM_CREATE          = 1<<0,    /* Create the database if not existant */
    TWOM_SHARED          = 1<<1,    /* Open in shared lock mode */
    TWOM_NOCSUM          = 1<<2,    /* Don't check checksums on read */
    TWOM_NOSYNC          = 1<<3,    /* Don't msync/fsync on write */
    TWOM_NONBLOCKING     = 1<<4,    /* When taking a lock, return immediately if the file is already locked */

    TWOM_ALWAYSYIELD     = 1<<9,    /* Yield foreach before every callback */
    TWOM_NOYIELD         = 1<<10,   /* Never yield a read transaction lock */
    TWOM_IFNOTEXIST      = 1<<11,   /* Only store if the record doesn't exist */
    TWOM_IFEXIST         = 1<<12,   /* Only store if the record already exists (e.g. when deleting) */
    TWOM_FETCHNEXT       = 1<<13,   /* Return the record AFTER the given key */
    TWOM_SKIPROOT        = 1<<14,   /* For foreach or cursor, skip the first record if it matches exactly */
    TWOM_MVCC            = 1<<15,   /* For cursor or transaction, operate in serializable isolation (MVCC) mode */
    TWOM_CURSOR_PREFIX   = 1<<16,   /* For cursor or transaction, only iterate inside the prefix */

    TWOM_CSUM_NULL       = 1<<27,   /* use the NULL checksum when creating or repacking database */
    TWOM_CSUM_XXH64      = 1<<28,   /* use the XXH64 checksum algorithm when creating or repacking */
    TWOM_CSUM_EXTERNAL   = 1<<29,   /* use an external checksum algorithm (must be passed in init) */
    TWOM_COMPAR_EXTERNAL = 1<<30    /* use an external comparison function (must be passed in init) */
};

typedef int twom_cb(void *rock,
                    const char *key, size_t keylen,
                    const char *data, size_t datalen);
typedef int twom_compar(const char *s1, size_t l1, const char *s2, size_t l2);
typedef uint32_t twom_csum(const char *s, size_t l);

struct twom_open_data {
    uint32_t flags;
    twom_compar *compar;
    twom_csum *csum;
    void (*error)(const char *msg, const char *fmt, ...);
};

#define TWOM_OPEN_DATA_INITIALIZER { 0, NULL, NULL, NULL }

// database operations
int twom_db_open(const char *fname, struct twom_open_data *setup,
                 struct twom_db **dbptr,
                 struct twom_txn **tidptr);
int twom_db_close(struct twom_db **dbptr);

// non-transactional operations
int twom_db_fetch(struct twom_db *db,
                  const char *key, size_t keylen,
                  const char **keyp, size_t *keylenp,
                  const char **valp, size_t *vallenp,
                  int flags);
int twom_db_foreach(struct twom_db *db,
                    const char *prefix, size_t prefixlen,
                    twom_cb *p, twom_cb *cb, void *rock,
                    int flags);
int twom_db_store(struct twom_db *db,
                  const char *key, size_t keylen,
                  const char *val, size_t vallen,
                  int flags);

// utility
int twom_db_dump(struct twom_db *, int detail);
int twom_db_check_consistency(struct twom_db *db);
int twom_db_repack(struct twom_db *db);
bool twom_db_should_repack(struct twom_db *db); // returns 1 for true

// release any read lock if doing something else for a while
int twom_db_yield(struct twom_db *db);

// cursor operations
int twom_db_begin_cursor(struct twom_db *db,
                         const char *key, size_t keylen,
                         struct twom_cursor **curp, int flags);
int twom_cursor_next(struct twom_cursor *cur,
                     const char **keyp, size_t *keylenp,
                     const char **valp, size_t *vallenp);

int twom_cursor_replace(struct twom_cursor *cur,
                        const char *val, size_t vallen,
                        int flags);
int twom_cursor_commit(struct twom_cursor **curp);
int twom_cursor_abort(struct twom_cursor **curp);

// cursors within a transaction
int twom_txn_begin_cursor(struct twom_txn *txn,
                          const char *key, size_t keylen,
                          struct twom_cursor **curp, int flags);
void twom_cursor_fini(struct twom_cursor **curp);

// transactional operations
int twom_db_begin_txn(struct twom_db *db, int shared, struct twom_txn **tidptr);
int twom_txn_abort(struct twom_txn **txnp);
int twom_txn_commit(struct twom_txn **txnp);
int twom_txn_yield(struct twom_txn *txn);
int twom_txn_fetch(struct twom_txn *txn,
                   const char *key, size_t keylen,
                   const char **keyp, size_t *keylenp,
                   const char **valp, size_t *vallenp,
                   int flags);
int twom_txn_foreach(struct twom_txn *txn,
                     const char *prefix, size_t prefixlen,
                     twom_cb *p, twom_cb *cb, void *rock,
                     int flags);
int twom_txn_store(struct twom_txn *txn,
                   const char *key, size_t keylen,
                   const char *val, size_t vallen,
                   int flags);

// header info
size_t twom_db_generation(struct twom_db *db);
size_t twom_db_num_records(struct twom_db *db);
size_t twom_db_size(struct twom_db *db);
const char *twom_db_fname(struct twom_db *db);
const char *twom_db_uuid(struct twom_db *db);
int twom_db_sync(struct twom_db *db);
const char *twom_strerror(int r);

#endif /* INCLUDED_TWOM_H */
