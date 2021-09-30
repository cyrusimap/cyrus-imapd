/* sqldb.c -- implementation of sqlite abstraction layer
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

#include <config.h>

#include <stdlib.h>
#include <syslog.h>
#include <string.h>
#include <errno.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "assert.h"
#include "sqldb.h"
#include "util.h"
#include "xmalloc.h"

static int sqldb_active = 0;

static sqldb_t *open_sqldbs;

EXPORTED int sqldb_init(void)
{
    if (!sqldb_active++) {
        sqlite3_initialize();
        assert(!open_sqldbs);
    }

    return 0;
}

EXPORTED int sqldb_done(void)
{
    if (!--sqldb_active) {
        sqlite3_shutdown();
        /* XXX - report the problems? */
        assert(!open_sqldbs);
    }

    return 0;
}

static void _debug(void *fname, const char *sql)
{
    syslog(LOG_DEBUG, "sqldb_exec(%s): %s", (const char *) fname, sql);
}

static int _free_open(sqldb_t *open)
{
    int rc = sqlite3_close(open->db);
    int r = (rc == SQLITE_OK ? 0 : -1);
    free(open->fname);
    free(open);
    return r;
}

static int _version_cb(void *rock, int ncol, char **vals, char **names __attribute__((unused)))
{
    int *vptr = (int *)rock;
    if (ncol == 1 && vals[0])
        *vptr = atoi(vals[0]);
    else
        abort();
    return 0;
}

/* Open DAV DB corresponding in file */
EXPORTED sqldb_t *sqldb_open(const char *fname, const char *initsql,
                             int version, const struct sqldb_upgrade *upgrade,
                             int timeout_ms)
{
    int rc = SQLITE_OK;
    struct stat sbuf;
    sqldb_t *open;
    int i;

    for (open = open_sqldbs; open; open = open->next) {
        if (!strcmp(open->fname, fname)) {
            /* already open! */
            open->refcount++;
            return open;
        }
    }

    open = xzmalloc(sizeof(sqldb_t));
    open->fname = xstrdup(fname);

    rc = stat(open->fname, &sbuf);
    if (rc == -1 && errno == ENOENT) {
        rc = cyrus_mkdir(open->fname, 0755);
    }

    rc = sqlite3_open_v2(open->fname, &open->db,
                         SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL);
    if (rc != SQLITE_OK) {
        syslog(LOG_ERR, "DBERROR: sqldb_open(%s) open: %s",
               open->fname, open->db ? sqlite3_errmsg(open->db) : "failed");
        _free_open(open);
        return NULL;
    }

    sqlite3_extended_result_codes(open->db, 1);
    sqlite3_trace(open->db, _debug, open->fname);

    sqlite3_busy_timeout(open->db, timeout_ms);

    rc = sqlite3_exec(open->db, "PRAGMA foreign_keys = ON;", NULL, NULL, NULL);
    if (rc != SQLITE_OK) {
        syslog(LOG_ERR, "DBERROR: sqldb_open(%s) enable foreign_keys: %s",
               open->fname, sqlite3_errmsg(open->db));
        _free_open(open);
        return NULL;
    }

    /* <http://stackoverflow.com/questions/19530419/
     *  sqlite-efficient-way-to-drop-lots-of-rows/19536232#19536232>
     * it's expensive and not needed here
     */
    rc = sqlite3_exec(open->db, "PRAGMA secure_delete = OFF;", NULL, NULL, NULL);
    if (rc != SQLITE_OK) {
        syslog(LOG_ERR, "DBERROR: sqldb_open(%s) disable secure_delete: %s",
               open->fname, sqlite3_errmsg(open->db));
        _free_open(open);
        return NULL;
    }

    /* https://sqlite.org/pragma.html#pragma_temp_store
     * When temp_store is MEMORY (2) temporary tables and indices are
     * kept in as if they were pure in-memory databases memory.
     */
    rc = sqlite3_exec(open->db, "PRAGMA temp_store = 2;", NULL, NULL, NULL);
    if (rc != SQLITE_OK) {
        syslog(LOG_ERR, "DBERROR: sqldb_open(%s) enable foreign_keys: %s",
               open->fname, sqlite3_errmsg(open->db));
        _free_open(open);
        return NULL;
    }

    rc = sqlite3_exec(open->db, "PRAGMA user_version;", _version_cb, &open->version, NULL);
    if (rc != SQLITE_OK) {
        syslog(LOG_ERR, "DBERROR: sqldb_open(%s) get user_version: %s",
            open->fname, sqlite3_errmsg(open->db));
        _free_open(open);
        return NULL;
    }
    if (open->version == version) goto out;

    /* if no initsql was passed, then we have no way to create a DB */
    if (!initsql) {
        /* just keep the version we already have */
        if (open->version) goto out;
        syslog(LOG_ERR, "DBERROR: sqldb_open(%s) no initsql and no DB",
            open->fname);
        _free_open(open);
        return NULL;
    }

    rc = sqlite3_exec(open->db, "BEGIN EXCLUSIVE;", NULL, NULL, NULL);
    if (rc != SQLITE_OK) {
        syslog(LOG_ERR, "DBERROR: sqldb_open(%s) begin: %s",
               open->fname, sqlite3_errmsg(open->db));
        _free_open(open);
        return NULL;
    }

    rc = sqlite3_exec(open->db, "PRAGMA user_version;", _version_cb, &open->version, NULL);
    if (rc != SQLITE_OK) {
        syslog(LOG_ERR, "DBERROR: sqldb_open(%s) get user_version locked: %s",
            open->fname, sqlite3_errmsg(open->db));
        _free_open(open);
        return NULL;
    }

    if (open->version == version) goto transout;

    if (open->version == 0) {
        syslog(LOG_NOTICE, "creating sql_db %s", open->fname);
        rc = sqlite3_exec(open->db, initsql, NULL, NULL, NULL);
        if (rc != SQLITE_OK) {
            syslog(LOG_ERR, "DBERROR: sqldb_open(%s) create: %s",
                   open->fname, sqlite3_errmsg(open->db));
            _free_open(open);
            return NULL;
        }
    }
    else {
        if (!upgrade) {
            syslog(LOG_ERR, "DBERROR: sqldb_open(%s) need upgrade from %d to %d: %s",
                   open->fname, open->version, version, sqlite3_errmsg(open->db));
            _free_open(open);
            return NULL;
        }
        for (i = 0; upgrade[i].to; i++) {
            if (upgrade[i].to <= open->version) continue;

            syslog(LOG_NOTICE, "sqldb_open(%s) upgrade to v%d", open->fname, upgrade[i].to);
            if (upgrade[i].sql) {
                rc = sqlite3_exec(open->db, upgrade[i].sql, NULL, NULL, NULL);
                if (rc != SQLITE_OK) {
                    syslog(LOG_ERR, "DBERROR: sqldb_open(%s) upgrade v%d: %s",
                        open->fname, upgrade[i].to, sqlite3_errmsg(open->db));
                    _free_open(open);
                    return NULL;
                }
            }
            if (upgrade[i].cb) {
                rc = upgrade[i].cb(open);
                if (rc != SQLITE_OK) {
                    syslog(LOG_ERR, "DBERROR: sqldb_open(%s) upgrade v%d: %s",
                        open->fname, upgrade[i].to, sqlite3_errmsg(open->db));
                    _free_open(open);
                    return NULL;
                }
            }
        }
    }

    /*  */ {
	    
    struct buf buf = BUF_INITIALIZER;

    buf_printf(&buf, "PRAGMA user_version = %d;", version);
    rc = sqlite3_exec(open->db, buf_cstring(&buf), NULL, NULL, NULL);
    buf_free(&buf);
    
    }

    if (rc != SQLITE_OK) {
        syslog(LOG_ERR, "DBERROR: sqldb_open(%s) user_version: %s",
               open->fname, sqlite3_errmsg(open->db));
        _free_open(open);
        return NULL;
    }

    open->version = version;

transout:
    rc = sqlite3_exec(open->db, "COMMIT;", NULL, NULL, NULL);
    if (rc != SQLITE_OK) {
        syslog(LOG_ERR, "DBERROR: sqldb_open(%s) commit: %s",
               open->fname, sqlite3_errmsg(open->db));
        _free_open(open);
        return NULL;
    }

out:
    /* stitch on up */
    open->refcount = 1;
    open->next = open_sqldbs;
    open_sqldbs = open;

    return open;
}

static sqlite3_stmt *_prepare_stmt(sqldb_t *open, const char *cmd)
{
    int i;
    sqlite3_stmt *stmt;
    int rc;

    for (i = 0; i < open->stmts.count; i++) {
        stmt = ptrarray_nth(&open->stmts, i);
        if (!strcmp(cmd, sqlite3_sql(stmt)))
            return stmt;
    }
    /* prepare new statement */
    rc = sqlite3_prepare_v2(open->db, cmd, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        syslog(LOG_ERR, "DBERROR: sqldb_exec(%s) prepare <%s>: %s",
               open->fname, cmd, sqlite3_errmsg(open->db));
        return NULL;
    }
    ptrarray_append(&open->stmts, stmt);
    return stmt;
}

static void _finish_stmt(sqldb_t *open)
{
    int i;
    sqlite3_stmt *stmt;
    for (i = 0; i < open->stmts.count; i++) {
        stmt = ptrarray_nth(&open->stmts, i);
        sqlite3_finalize(stmt);
    }
    ptrarray_fini(&open->stmts);
}

EXPORTED int sqldb_exec(sqldb_t *open, const char *cmd, struct sqldb_bindval bval[],
                        int (*cb)(sqlite3_stmt *stmt, void *rock), void *rock)
{
    int rc, r = 0;
    sqlite3_stmt *stmt = _prepare_stmt(open, cmd);
    if (!stmt) return -1;

    /* bind values */
    for (; bval && bval->name; bval++) {
        int cidx = sqlite3_bind_parameter_index(stmt, bval->name);

        switch (bval->type) {
        case SQLITE_INTEGER:
            sqlite3_bind_int64(stmt, cidx, bval->val.i);
            break;

        case SQLITE_TEXT:
            sqlite3_bind_text(stmt, cidx, bval->val.s, -1, NULL);
            break;
        }
    }

    /* execute and process the results */
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        if (cb && (r = cb(stmt, rock))) break;
    }

    /* reset statement and clear all bindings */
    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);

    if (!r && rc != SQLITE_DONE) {
        syslog(LOG_ERR, "DBERROR: sqldb_exec() step: %s for (%s: %s)",
               sqlite3_errmsg(open->db), open->fname, cmd);
        r = -1;
    }

    return r;
}

static int _onecmd(sqldb_t *open, const char *cmd, const char *name)
{
    static struct buf buf = BUF_INITIALIZER;
    buf_reset(&buf);
    buf_printf(&buf, "%s %s;", cmd, name);
    return sqldb_exec(open, buf_cstring(&buf), NULL, NULL, NULL);
}

EXPORTED int sqldb_begin(sqldb_t *open, const char *name)
{
    int r = 0;

    if (!name) name = "DUMMY";
    if (!open->writelock) r = sqldb_writelock(open);
    if (!r) r = _onecmd(open, "SAVEPOINT", name);
    if (!r) strarray_push(&open->trans, name);
    return r;
}

EXPORTED int sqldb_commit(sqldb_t *open, const char *name)
{
    char *prev;
    int r;

    assert(open->trans.count);
    prev = strarray_pop(&open->trans);
    if (name) assert(!strcmp(prev, name));
    r = _onecmd(open, "RELEASE SAVEPOINT", prev);
    if (r) strarray_push(&open->trans, prev);
    free(prev);
    if (!r && !open->trans.count) r = sqldb_writecommit(open);
    return r;
}

EXPORTED int sqldb_rollback(sqldb_t *open, const char *name)
{
    char *prev;
    int r;

    assert(open->trans.count);

    prev = strarray_pop(&open->trans);
    if (name) assert(!strcmp(prev, name));
    r = _onecmd(open, "ROLLBACK TO SAVEPOINT", prev);
    if (r) strarray_push(&open->trans, prev);
    // it's still commit here even if we rolled back THIS savepoint,
    // because other savepoints may have committed, so we want to
    // commit the wrapping transaction
    if (!r && !open->trans.count) r = sqldb_writecommit(open);
    free(prev);
    return r;
}

EXPORTED int sqldb_writelock(sqldb_t *open)
{
    int r = sqldb_exec(open, "BEGIN IMMEDIATE;", NULL, NULL, NULL);

    assert (!open->writelock);
    assert (!open->trans.count);

    if (!r) open->writelock = 1;
    return r;
}

EXPORTED int sqldb_writecommit(sqldb_t *open)
{
    int r;

    if (!open->writelock) return 0;
    strarray_truncate(&open->trans, 0);
    r = sqldb_exec(open, "COMMIT;", NULL, NULL, NULL);
    if (!r) open->writelock = 0;
    return r;
}

EXPORTED int sqldb_writeabort(sqldb_t *open)
{
    int r;

    if (!open->writelock) return 0;
    strarray_truncate(&open->trans, 0);
    r = sqldb_exec(open, "ROLLBACK;", NULL, NULL, NULL);
    if (!r) open->writelock = 0;
    return r;
}


EXPORTED int sqldb_lastid(sqldb_t *open)
{
    return sqlite3_last_insert_rowid(open->db);
}

EXPORTED int sqldb_changes(sqldb_t *open)
{
    return sqlite3_changes(open->db);
}

EXPORTED int sqldb_close(sqldb_t **dbp)
{
    sqldb_t *open, *prev = NULL;

    if (!*dbp) return 0;

    for (open = open_sqldbs; open; open = open->next) {
        if (*dbp == open) {
            if (--open->refcount) return 0; /* still in use */
            if (prev)
                prev->next = open->next;
            else
                open_sqldbs = open->next;
            break;
        }
        prev = open;
    }

    assert(open);
    assert(!open->trans.count);

    strarray_fini(&open->trans);
    _finish_stmt(open);

    *dbp = NULL;

    return _free_open(open);
}

EXPORTED int sqldb_attach(sqldb_t *open, const char *fname)
{
    struct sqldb_bindval bval[] = {
        { ":fname",  SQLITE_TEXT, { .s = fname         } },
        { NULL,      SQLITE_NULL, { .s = NULL          } } };
    struct stat sbuf;
    int r;

    if (open->attached) return SQLITE_MISUSE;
    if (stat(fname, &sbuf)) return SQLITE_NOTFOUND;

    r = sqldb_exec(open, "ATTACH DATABASE :fname AS other;", bval, NULL, NULL);
    if (r) return r;
    open->attached = 1;
    return 0;
}

EXPORTED int sqldb_detach(sqldb_t *open)
{
    int r;

    if (!open->attached) return SQLITE_MISUSE;
    r = sqldb_exec(open, "DETACH DATABASE other;", NULL, NULL, NULL);
    if (r) return r;
    open->attached = 0;
    return 0;
}
