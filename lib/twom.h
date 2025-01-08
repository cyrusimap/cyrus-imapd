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

#include <stdlib.h>
#include <stdint.h>

struct twom_db;
struct twom_txn;
struct twom_cursor;

enum twom_ret {
    TWOM_OK = 0,
    TWOM_DONE = 1,
    TWOM_IOERROR = -1,
    TWOM_AGAIN = -2,
    TWOM_EXISTS = -3,
    TWOM_INTERNAL = -4,
    TWOM_NOTFOUND = -5,
    TWOM_LOCKED = -6,
    TWOM_READONLY = -9,
};

// we don't reuse flags, there's 32 bits of space, and we spread through them
enum twom_flagspec {
    TWOM_CREATE          = 1<<0,    /* Create the database if not existant */
    TWOM_SHARED          = 1<<1,    /* Open in shared lock mode */
    TWOM_NOCSUM          = 1<<2,    /* Don't check checksums on read */
    TWOM_NOSYNC          = 1<<3,    /* Don't msync/fsync on write */

    TWOM_ALWAYSYIELD     = 1<<9,
    TWOM_NOYIELD         = 1<<10,
    TWOM_IFNOTEXIST      = 1<<11,
    TWOM_IFEXIST         = 1<<12,
    TWOM_FETCHNEXT       = 1<<13,
    TWOM_SKIPROOT        = 1<<14,
    TWOM_MVCC            = 1<<15,
    TWOM_NONBLOCKING     = 1<<16,

    TWOM_CSUM_NULL       = 1<<27,
    TWOM_CSUM_XXH64      = 1<<28,
    TWOM_CSUM_EXTERNAL   = 1<<29,
    TWOM_COMPAR_EXTERNAL = 1<<30
};

#define TWOM_VERSION 1

typedef int twom_cb(void *rock,
                    const char *key, size_t keylen,
                    const char *data, size_t datalen);
typedef int twom_compar(const char *s1, size_t l1, const char *s2, size_t l2);
typedef uint32_t twom_csum(const char *s, size_t l);

struct twom_open_data {
    uint32_t flags;
    int (*compar)(const char *s1, size_t l1, const char *s2, size_t l2);
    uint32_t (*csum)(const char *s, size_t l);
    void (*error)(const char *msg, const char *fmt, ...);
};

typedef struct twom_open_data twom_init;
#define TWOM_INIT { 0, NULL, NULL, NULL }

// database operations
extern int twom_fname_open_db(const char *fname, struct twom_open_data *setup,
                              struct twom_db **dbptr,
                              struct twom_txn **tidptr);
extern int twom_db_close(struct twom_db **dbptr);

// non-transactional operations
extern int twom_db_fetch(struct twom_db *db,
                         const char *key, size_t keylen,
                         const char **keyp, size_t *keylenp,
                         const char **valp, size_t *vallenp,
                         int flags);
extern int twom_db_foreach(struct twom_db *db,
                           const char *prefix, size_t prefixlen,
                           twom_cb *p, twom_cb *cb, void *rock,
                           int flags);
extern int twom_db_store(struct twom_db *db,
                         const char *key, size_t keylen,
                         const char *val, size_t vallen,
                         int flags);

// utility
extern int twom_db_consistent(struct twom_db *db);
extern int twom_db_dump(struct twom_db *, int detail);
extern int twom_db_repack(struct twom_db *db);
extern int twom_db_should_repack(struct twom_db *db); // returns 1 for true

// release any read lock if doing something else for a while

extern int twom_db_yield(struct twom_db *db);

// cursor operations

extern int twom_db_begin_cursor(struct twom_db *db,
                                const char *key, size_t keylen,
                                struct twom_cursor **curp, int flags);
extern int twom_cursor_next(struct twom_cursor *cur,
                            const char **keyp, size_t *keylenp,
                            const char **valp, size_t *vallenp);

extern int twom_cursor_replace(struct twom_cursor *cur,
                               const char *val, size_t vallen,
                               int flags);
extern int twom_cursor_commit(struct twom_cursor **curp);
extern int twom_cursor_abort(struct twom_cursor **curp);

// cursors within a transaction

extern int twom_txn_begin_cursor(struct twom_txn *txn,
                                 const char *key, size_t keylen,
                                 struct twom_cursor **curp, int flags);
extern int twom_cursor_fini(struct twom_cursor **curp);

// transactional operations

extern int twom_db_begin_txn(struct twom_db *db, int shared, struct twom_txn **tidptr);
extern int twom_txn_abort(struct twom_txn **txnp);
extern int twom_txn_commit(struct twom_txn **txnp);
extern int twom_txn_yield(struct twom_txn *txn);
extern int twom_txn_fetch(struct twom_txn *txn,
                          const char *key, size_t keylen,
                          const char **keyp, size_t *keylenp,
                          const char **valp, size_t *vallenp,
                          int flags);
extern int twom_txn_foreach(struct twom_txn *txn,
                            const char *prefix, size_t prefixlen,
                            twom_cb *p, twom_cb *cb, void *rock,
                            int flags);
extern int twom_txn_store(struct twom_txn *txn,
                          const char *key, size_t keylen,
                          const char *val, size_t vallen,
                          int flags);

// header info
extern size_t twom_db_generation(struct twom_db *db);
extern size_t twom_db_num_records(struct twom_db *db);
extern size_t twom_db_size(struct twom_db *db);
extern const char *twom_db_fname(struct twom_db *db);
extern const char *twom_db_uuid(struct twom_db *db);

extern int twom_db_sync(struct twom_db *db);

extern const char *twom_strerror(int r);

#endif /* INCLUDED_TWOM_H */
