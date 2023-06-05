/* sqldb.h -- abstract interface for sqlite databases
 *
 * Copyright (c) 1994-2012 Carnegie Mellon University.  All rights reserved.
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
 */

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
