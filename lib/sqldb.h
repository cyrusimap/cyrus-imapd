/* sqldb.h - abstract interface for sqlite databases */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef SQLDB_H
#define SQLDB_H

#include <sqlite3.h>
#include "ptrarray.h"
#include "strarray.h"
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

struct sqldb {
    sqlite3 *db;
    char *fname;
    int version;
    int refcount;
    int writelock;
    int attached;
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

sqldb_t *sqldb_open(const char *fname, const char *initsql,
                   int version, const struct sqldb_upgrade *upgradesql,
                   int timeout_ms);

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
