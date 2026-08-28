/* sqldb.h - abstract interface for sqlite databases */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef SQLDB_H
#define SQLDB_H

#include <cyrus/strarray.h>

#include <sys/types.h>

#include <sqlite3.h>
#include "ptrarray.h"
#include "util.h"

struct sqldb_bindval {
    const char *name;
    int type;
    union sqldb_sqlval {
        sqlite3_int64 i;
        const char *s;
        struct buf b;
    } val;
};

#define SQL_MAXVAL 256

/* track the scope of data that each database contains, allowing us to
   ensure the correct locks are taken, and ensure we don't try to use
   a database that has been deleted */
enum sqldb_scope {
    SQLDB_SCOPE_NONE = 0,   /* process-local, no owner */
    SQLDB_SCOPE_USER,       /* user namespace lock, owner is the userid */
    SQLDB_SCOPE_MAILBOX,    /* mailbox name lock, owner is the mboxname */
    SQLDB_SCOPE_GLOBAL,     /* its own lock, no owner */
};

struct sqldb {
    sqlite3 *db;
    char *fname;
    int version;
    int refcount;
    int writelock;
    int attached;
    dev_t dev;      /* identify the file we opened, to detect it being */
    ino_t ino;      /* unlinked or replaced */
    int stale;      /* it has been */
    int scope;      /* enum sqldb_scope */
    char *owner;    /* userid or mboxname, per the scope */
    strarray_t trans;
    ptrarray_t stmts;
    struct sqldb *next;
};

typedef struct sqldb sqldb_t;

struct sqldb_upgrade {
    int to;
    const char *sql;
    int (*cb)(sqldb_t *db);
};

/* prepare for SQL operations in this process */
int sqldb_init(void);

/* done with all SQL operations for this process */
int sqldb_done(void);

#define SQLDB_DEFAULT_TIMEOUT  20000 /* 20 seconds is an eternity */

#define SQLDB_DONE         1
#define SQLDB_OK           0
#define SQLDB_ERR_UNKNOWN -1
#define SQLDB_ERR_LIMIT   -2
#define SQLDB_ERR_DBMOVED -3

sqldb_t *sqldb_open(const char *fname, const char *initsql,
                   int version, const struct sqldb_upgrade *upgradesql,
                   int timeout_ms);

/* as sqldb_open, tagged with the scope of data it contains */
sqldb_t *sqldb_open_full(const char *fname, const char *initsql,
                   int version, const struct sqldb_upgrade *upgradesql,
                   int timeout_ms, int scope, const char *owner);

/* report whether any live handle remains for this scope */
int sqldb_isopen_forscope(int scope, const char *owner);

int sqldb_attach(sqldb_t *open, const char *fname);
int sqldb_detach(sqldb_t *open);

/* execute 'cmd' and process results with 'cb'
   'cmd' is prepared as 'stmt' with 'bval' as bound values */
int sqldb_exec(sqldb_t *open, const char *cmd, struct sqldb_bindval bval[],
               int (*cb)(sqlite3_stmt *stmt, void *rock), void *rock);

int sqldb_begin(sqldb_t *open, const char *name);
int sqldb_commit(sqldb_t *open, const char *name);
int sqldb_rollback(sqldb_t *open, const char *name);

int sqldb_writelock(sqldb_t *open);
int sqldb_writecommit(sqldb_t *open);
int sqldb_writeabort(sqldb_t *open);

int sqldb_lastid(sqldb_t *open);
int sqldb_changes(sqldb_t *open);

int sqldb_close(sqldb_t **openp);

#endif /* SQLDB_H */
