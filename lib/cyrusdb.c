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

#include <config.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sysexits.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#include "assert.h"
#include "bsearch.h"
#include "cyrusdb.h"
#include "util.h"
#include "libcyr_cfg.h"
#include "xmalloc.h"
#include "xstrlcpy.h"

//#define DEBUGDB 1

/* Note that some of these may be undefined symbols
 * if libcyrus was not built with support for them */
extern struct cyrusdb_backend cyrusdb_flat;
extern struct cyrusdb_backend cyrusdb_skiplist;
extern struct cyrusdb_backend cyrusdb_quotalegacy;
extern struct cyrusdb_backend cyrusdb_sql;
extern struct cyrusdb_backend cyrusdb_twoskip;
extern struct cyrusdb_backend cyrusdb_zeroskip;

static struct cyrusdb_backend *_backends[] = {
    &cyrusdb_flat,
    &cyrusdb_skiplist,
    &cyrusdb_quotalegacy,
#if defined USE_CYRUSDB_SQL
    &cyrusdb_sql,
#endif
    &cyrusdb_twoskip,
#if defined HAVE_ZEROSKIP
    &cyrusdb_zeroskip,
#endif
    NULL };

#define DEFAULT_BACKEND "twoskip"

struct db {
    struct dbengine *engine;
    struct cyrusdb_backend *backend;
};

static struct cyrusdb_backend *cyrusdb_fromname(const char *name)
{
    int i;
    struct cyrusdb_backend *db = NULL;

    for (i = 0; _backends[i]; i++) {
        if (!strcmp(_backends[i]->name, name)) {
            db = _backends[i]; break;
        }
    }
    if (!db) {
        char errbuf[1024];
        snprintf(errbuf, sizeof(errbuf),
                 "cyrusdb backend %s not supported", name);
        fatal(errbuf, EX_CONFIG);
    }

    return db;
}

static int _myopen(const char *backend, const char *fname,
                 int flags, struct db **ret, struct txn **tid)
{
    const char *realname;
    struct db *db = xzmalloc(sizeof(struct db));
    int r;

    if (!backend) backend = DEFAULT_BACKEND; /* not used yet, later */
    db->backend = cyrusdb_fromname(backend);

    /* Check if shared lock is requested */
    if (flags & CYRUSDB_SHARED) {
        assert(tid && *tid == NULL);
        if (flags & CYRUSDB_CONVERT) {
            xsyslog(LOG_ERR,
                    "DBERROR: CONVERT and SHARED are mutually exclusive,"
                        " won't open db",
                    "fname=<%s> backend=<%s>",
                    fname, backend);
            r = CYRUSDB_INTERNAL;
            goto done;
        }
    }

    /* This whole thing is a fricking critical section.  We don't have the API
     * in place for a safe rename of a locked database, so the choices are
     * basically:
     * a) convert each DB layer to support locked database renames while still
     *    in the transaction.  Best, but lots of work.
     * b) rename and hope... unreliable
     * c) global lock around this block of code.  Safest and least efficient.
     */

    /* check if it opens normally.  Horray */
    r = db->backend->open(fname, flags, &db->engine, tid);
    if (r == CYRUSDB_NOTFOUND) goto done; /* no open flags */
    if (!r) goto done;

    /* magic time - we need to work out if the file was created by a different
     * backend and convert if possible */

    realname = cyrusdb_detect(fname);
    if (!realname) {
        xsyslog(LOG_ERR, "DBERROR: failed to detect DB type",
                         "fname=<%s> backend=<%s> r=<%d>",
                         fname, backend, r);
        /* r is still set */
        goto done;
    }

    /* different type */
    if (strcmp(realname, backend)) {
        if (flags & CYRUSDB_CONVERT) {
            r = cyrusdb_convert(fname, fname, realname, backend);
            if (r) {
                xsyslog(LOG_ERR, "DBERROR: failed to convert, maybe someone beat us",
                                 "fname=<%s> from=<%s> to=<%s>",
                                 fname, realname, backend);
            }
            else {
                syslog(LOG_NOTICE, "cyrusdb: converted %s from %s to %s",
                       fname, realname, backend);
            }
        }
        else {
            syslog(LOG_NOTICE, "cyrusdb: opening %s with backend %s (requested %s)",
                   fname, realname, backend);
            db->backend = cyrusdb_fromname(realname);
        }
    }

    r = db->backend->open(fname, flags, &db->engine, tid);

#ifdef DEBUGDB
    syslog(LOG_NOTICE, "DEBUGDB open(%s, %d) => %llx\n", fname, flags, (long long unsigned)db->engine);
#endif

done:

    if (r) free(db);
    else *ret = db;

    return r;
}

EXPORTED int cyrusdb_open(const char *backend, const char *fname,
                          int flags, struct db **ret)
{
    return _myopen(backend, fname, flags, ret, NULL);
}

EXPORTED int cyrusdb_lockopen(const char *backend, const char *fname,
                              int flags, struct db **ret, struct txn **tid)
{
    return _myopen(backend, fname, flags, ret, tid);
}

EXPORTED int cyrusdb_close(struct db *db)
{
#ifdef DEBUGDB
    syslog(LOG_NOTICE, "DEBUGDB close(%llx)\n", (long long unsigned)db->engine);
#endif

    int r = db->backend->close(db->engine);

    free(db);

    return r;
}

EXPORTED int cyrusdb_fetch(struct db *db,
             const char *key, size_t keylen,
             const char **data, size_t *datalen,
             struct txn **mytid)
{
    if (!db->backend->fetch)
        return CYRUSDB_NOTIMPLEMENTED;
#ifdef DEBUGDB
    syslog(LOG_NOTICE, "DEBUGDB fetch(%llx, %.*s)\n", (long long unsigned)db->engine, (int)keylen, key);
#endif
    return db->backend->fetch(db->engine, key, keylen,
                              data, datalen, mytid);
}

EXPORTED int cyrusdb_fetchlock(struct db *db,
                 const char *key, size_t keylen,
                 const char **data, size_t *datalen,
                 struct txn **mytid)
{
    if (!db->backend->fetchlock)
        return CYRUSDB_NOTIMPLEMENTED;
#ifdef DEBUGDB
    syslog(LOG_NOTICE, "DEBUGDB fetchlock(%llx, %.*s)\n", (long long unsigned)db->engine, (int)keylen, key);
#endif
    return db->backend->fetchlock(db->engine, key, keylen,
                                  data, datalen, mytid);
}

EXPORTED int cyrusdb_fetchnext(struct db *db,
                 const char *key, size_t keylen,
                 const char **found, size_t *foundlen,
                 const char **data, size_t *datalen,
                 struct txn **mytid)
{
    if (!db->backend->fetchnext)
        return CYRUSDB_NOTIMPLEMENTED;
#ifdef DEBUGDB
    syslog(LOG_NOTICE, "DEBUGDB fetchnext(%llx, %.*s)\n", (long long unsigned)db->engine, (int)keylen, key);
#endif
    return db->backend->fetchnext(db->engine, key, keylen,
                                  found, foundlen,
                                  data, datalen, mytid);
}

EXPORTED int cyrusdb_foreach(struct db *db,
               const char *prefix, size_t prefixlen,
               foreach_p *p,
               foreach_cb *cb, void *rock,
               struct txn **tid)
{
    if (!db->backend->foreach)
        return CYRUSDB_NOTIMPLEMENTED;
#ifdef DEBUGDB
    syslog(LOG_NOTICE, "DEBUGDB foreach(%llx, %.*s)\n", (long long unsigned)db->engine, (int)prefixlen, prefix);
#endif
    return db->backend->foreach(db->engine, prefix, prefixlen,
                                p, cb, rock, tid);
}

EXPORTED int cyrusdb_forone(struct db *db,
               const char *key, size_t keylen,
               foreach_p *p,
               foreach_cb *cb, void *rock,
               struct txn **tid)
{
    const char *data;
    size_t datalen;
#ifdef DEBUGDB
    syslog(LOG_NOTICE, "DEBUGDB forone(%llx, %.*s)\n", (long long unsigned)db->engine, (int)keylen, key);
#endif
    int r = cyrusdb_fetch(db, key, keylen, &data, &datalen, tid);
    if (r == CYRUSDB_NOTFOUND) return 0;
    if (r) return r;

    if (!p || p(rock, key, keylen, data, datalen))
        r = cb(rock, key, keylen, data, datalen);
    return r;
}

EXPORTED int cyrusdb_create(struct db *db,
              const char *key, size_t keylen,
              const char *data, size_t datalen,
              struct txn **tid)
{
    if (!db->backend->create)
        return CYRUSDB_NOTIMPLEMENTED;
#ifdef DEBUGDB
    syslog(LOG_NOTICE, "DEBUGDB create(%llx, %.*s)\n", (long long unsigned)db->engine, (int)keylen, key);
#endif
    return db->backend->create(db->engine, key, keylen, data, datalen, tid);
}

EXPORTED int cyrusdb_store(struct db *db,
             const char *key, size_t keylen,
             const char *data, size_t datalen,
             struct txn **tid)
{
    if (!db->backend->store)
        return CYRUSDB_NOTIMPLEMENTED;
#ifdef DEBUGDB
    syslog(LOG_NOTICE, "DEBUGDB store(%llx, %.*s)\n", (long long unsigned)db->engine, (int)keylen, key);
#endif
    return db->backend->store(db->engine, key, keylen, data, datalen, tid);
}

EXPORTED int cyrusdb_delete(struct db *db,
              const char *key, size_t keylen,
              struct txn **tid, int force)
{
    if (!db->backend->delete_)
        return CYRUSDB_NOTIMPLEMENTED;
#ifdef DEBUGDB
    syslog(LOG_NOTICE, "DEBUGDB delete(%llx, %.*s)\n", (long long unsigned)db->engine, (int)keylen, key);
#endif
    return db->backend->delete_(db->engine, key, keylen, tid, force);
}

EXPORTED int cyrusdb_commit(struct db *db, struct txn *tid)
{
    if (!db->backend->commit)
        return CYRUSDB_NOTIMPLEMENTED;
#ifdef DEBUGDB
    syslog(LOG_NOTICE, "DEBUGDB commit(%llx)\n", (long long unsigned)db->engine);
#endif
    return db->backend->commit(db->engine, tid);
}

EXPORTED int cyrusdb_abort(struct db *db, struct txn *tid)
{
    if (!db->backend->abort)
        return CYRUSDB_NOTIMPLEMENTED;
#ifdef DEBUGDB
    syslog(LOG_NOTICE, "DEBUGDB abort(%llx)\n", (long long unsigned)db->engine);
#endif
    return db->backend->abort(db->engine, tid);
}

EXPORTED int cyrusdb_dump(struct db *db, int detail)
{
    if (!db->backend->dump) return 0;
    return db->backend->dump(db->engine, detail);
}

EXPORTED int cyrusdb_consistent(struct db *db)
{
    if (!db->backend->consistent) return 0;
    return db->backend->consistent(db->engine);
}

EXPORTED int cyrusdb_repack(struct db *db)
{
    if (!db->backend->repack) return 0;
    return db->backend->repack(db->engine);
}

EXPORTED int cyrusdb_compar(struct db *db,
                   const char *a, int alen,
                   const char *b, int blen)
{
    if (!db->backend->compar)
        return bsearch_ncompare_raw(a, alen, b, blen);
    return db->backend->compar(db->engine, a, alen, b, blen);
}

/**********************************************/

EXPORTED void cyrusdb_init(void)
{
    int i, r;
    char dbdir[1024];
    const char *confdir = libcyrus_config_getstring(CYRUSOPT_CONFIG_DIR);
    int initflags = libcyrus_config_getint(CYRUSOPT_DB_INIT_FLAGS);

    strcpy(dbdir, confdir);
    strcat(dbdir, FNAME_DBDIR);

    for (i=0; _backends[i]; i++) {
        r = (_backends[i])->init(dbdir, initflags);
        if (r) {
            xsyslog(LOG_ERR, "DBERROR: backend init failed",
                             "backend=<%s>",
                             _backends[i]->name);
        }
    }
}

EXPORTED void cyrusdb_done(void)
{
    int i;

    for(i=0; _backends[i]; i++) {
        (_backends[i])->done();
    }
}

EXPORTED int cyrusdb_copyfile(const char *srcname, const char *dstname)
{
    return cyrus_copyfile(srcname, dstname, COPYFILE_NOLINK);
}

struct db_rock {
    struct db *db;
    struct txn **tid;
};

static int delete_cb(void *rock,
                     const char *key, size_t keylen,
                     const char *data __attribute__((unused)),
                     size_t datalen __attribute__((unused)))
{
    struct db_rock *cr = (struct db_rock *)rock;
    return cyrusdb_delete(cr->db, key, keylen, cr->tid, 1);
}

static int print_cb(void *rock,
                    const char *key, size_t keylen,
                    const char *data, size_t datalen)
{
    FILE *f = (FILE *)rock;

    /* XXX: improve binary safety */
    fprintf(f, "%.*s\t%.*s\n", (int)keylen, key, (int)datalen, data);

    return 0;
}


EXPORTED int cyrusdb_dumpfile(struct db *db,
                              const char *prefix, size_t prefixlen,
                              FILE *f,
                              struct txn **tid)
{
    return cyrusdb_foreach(db, prefix, prefixlen, NULL, print_cb, f, tid);
}

EXPORTED int cyrusdb_truncate(struct db *db,
                              struct txn **tid)
{
    struct db_rock tr;

    tr.db = db;
    tr.tid = tid;

    return cyrusdb_foreach(db, "", 0, NULL, delete_cb, &tr, tid);
}

EXPORTED int cyrusdb_undumpfile(struct db *db,
                                FILE *f,
                                struct txn **tid)
{
    struct buf line = BUF_INITIALIZER;
    const char *tab;
    const char *str;
    int r = 0;

    while (buf_getline(&line, f)) {
        /* skip blank lines */
        if (!line.len) continue;
        str = buf_cstring(&line);
        /* skip comments */
        if (str[0] == '#') continue;

        tab = strchr(str, '\t');

        /* deletion (no value) */
        if (!tab) {
            r = cyrusdb_delete(db, str, line.len, tid, 1);
            if (r) goto out;
        }

        /* store */
        else {
            unsigned klen = (tab - str);
            unsigned vlen = line.len - klen - 1; /* TAB */
            r = cyrusdb_store(db, str, klen, tab + 1, vlen, tid);
            if (r) goto out;
        }
    }

  out:
    buf_free(&line);
    return r;
}

static int converter_cb(void *rock,
                        const char *key, size_t keylen,
                        const char *data, size_t datalen)
{
    struct db_rock *cr = (struct db_rock *)rock;
    return cyrusdb_store(cr->db, key, keylen, data, datalen, cr->tid);
}

/* convert (just copy every record) from one database to another in possibly
   a different format.  It's up to the surrounding code to copy the
   new database over the original if it wants to */
EXPORTED int cyrusdb_convert(const char *fromfname, const char *tofname,
                    const char *frombackend, const char *tobackend)
{
    char *newfname = NULL;
    struct db *fromdb = NULL;
    struct db *todb = NULL;
    struct db_rock cr;
    struct txn *fromtid = NULL;
    struct txn *totid = NULL;
    int r;

    /* open source database */
    r = cyrusdb_open(frombackend, fromfname, 0, &fromdb);
    if (r) goto err;

    /* use a bogus fetch to lock source DB before touching the destination */
    r = cyrusdb_fetch(fromdb, "_", 1, NULL, NULL, &fromtid);
    if (r == CYRUSDB_NOTFOUND) r = 0;
    if (r) goto err;

    /* same file?  Create with a new name */
    if (!strcmp(tofname, fromfname))
        tofname = newfname = strconcat(fromfname, ".NEW", NULL);

    /* remove any rubbish lying around */
    unlink(tofname);

    r = cyrusdb_open(tobackend, tofname, CYRUSDB_CREATE, &todb);
    if (r) goto err;

    /* set up the copy rock */
    cr.db = todb;
    cr.tid = &totid;

    /* copy each record to the destination DB */
    cyrusdb_foreach(fromdb, "", 0, NULL, converter_cb, &cr, &fromtid);

    /* commit destination transaction */
    if (totid) cyrusdb_commit(todb, totid);
    r = cyrusdb_close(todb);
    totid = NULL;
    todb = NULL;
    if (r) goto err;

    /* created a new filename - so it's a replace-in-place */
    if (newfname) {
        r = rename(newfname, fromfname);
        if (r) goto err;
    }

    /* and close the source database - nothing should have
     * written here, so an abort is fine */
    if (fromtid) cyrusdb_abort(fromdb, fromtid);
    cyrusdb_close(fromdb);

    free(newfname);

    return 0;

err:
    if (totid) cyrusdb_abort(todb, totid);
    if (todb) cyrusdb_close(todb);
    if (fromtid) cyrusdb_abort(fromdb, fromtid);
    if (fromdb) cyrusdb_close(fromdb);

    unlink(tofname);
    free(newfname);

    return r;
}

EXPORTED const char *cyrusdb_detect(const char *fname)
{
    FILE *f;
    char buf[32];
    int n;

    f = fopen(fname, "r");
    if (!f) return NULL;

    /* empty file? */
    n = fread(buf, 32, 1, f);
    fclose(f);

    if (n != 1) return NULL;

    /* only compare first 16 bytes, that's OK */
    if (!strncmp(buf, "\241\002\213\015skiplist file\0\0\0", 16))
        return "skiplist";

    if (!strncmp(buf, "\241\002\213\015twoskip file\0\0\0\0", 16))
        return "twoskip";

    /* unable to detect SQLite databases or flat files explicitly here */
    return NULL;
}

EXPORTED int cyrusdb_sync(const char *backend)
{
    struct cyrusdb_backend *db = cyrusdb_fromname(backend);
    return db->sync();
}

EXPORTED int cyrusdb_unlink(const char *backend, const char *fname, int flags)
{
    struct cyrusdb_backend *db = cyrusdb_fromname(backend);
    if (!db->unlink) return 0;
    return db->unlink(fname, flags);
}

EXPORTED cyrusdb_archiver *cyrusdb_getarchiver(const char *backend)
{
    struct cyrusdb_backend *db = cyrusdb_fromname(backend);
    return db->archive; /* the function used for archiving */
}

EXPORTED int cyrusdb_canfetchnext(const char *backend)
{
    struct cyrusdb_backend *db = cyrusdb_fromname(backend);
    return db->fetchnext ? 1 : 0;
}

/* caller is responsible for calling strarray_free() */
EXPORTED strarray_t *cyrusdb_backends(void)
{
    strarray_t *ret = strarray_new();
    int i;

    for (i = 0; _backends[i]; i++) {
        strarray_add(ret, _backends[i]->name);
    }

    return ret;
}


/* generic backend implementations */

HIDDEN int cyrusdb_generic_init(const char *dbdir __attribute__((unused)),
                         int myflags __attribute__((unused)))
{
    return 0;
}

HIDDEN int cyrusdb_generic_done(void)
{
    return 0;
}

HIDDEN int cyrusdb_generic_sync(void)
{
    return 0;
}

HIDDEN int cyrusdb_generic_archive(const strarray_t *fnames,
                            const char *dirname)
{
    char dstname[1024], *dp;
    int length, rest;
    int i;
    int r;

    strlcpy(dstname, dirname, sizeof(dstname));
    length = strlen(dstname);
    dp = dstname + length;
    rest = sizeof(dstname) - length;

    /* archive those files specified by the app */
    for (i = 0; i < fnames->count; i++) {
        const char *fname = strarray_nth(fnames, i);
        struct stat sbuf;
        if (stat(fname, &sbuf) < 0) {
            syslog(LOG_DEBUG, "not archiving database file: %s: %m", fname);
            continue;
        }
        syslog(LOG_DEBUG, "archiving database file: %s", fname);
        strlcpy(dp, strrchr(fname, '/'), rest);
        r = cyrusdb_copyfile(fname, dstname);
        if (r) {
            syslog(LOG_ERR,
                   "DBERROR: error archiving database file: %s", fname);
            return CYRUSDB_IOERROR;
        }
    }

    return 0;
}

HIDDEN int cyrusdb_generic_noarchive(const strarray_t *fnames __attribute__((unused)),
                              const char *dirname __attribute__((unused)))
{
    return 0;
}

HIDDEN int cyrusdb_generic_unlink(const char *fname, int flags __attribute__((unused)))
{
    if (fname)
        unlink(fname);
    /* XXX - check that it exists unless FORCE flag? */
    return 0;
}

EXPORTED const char *cyrusdb_strerror(int r)
{
    const char *err = "unknown error";

    switch (r) {
    case CYRUSDB_OK:
        err = "not an error";
        break;

    case CYRUSDB_DONE:
        err = "done";
        break;

    case CYRUSDB_IOERROR:
        err = "IO error";
        break;

    case CYRUSDB_AGAIN:
        err = "again";
        break;

    case CYRUSDB_EXISTS:
        err = "item exists";
        break;

    case CYRUSDB_INTERNAL:
        err = "internal error";
        break;

    case CYRUSDB_NOTFOUND:
        err = "item not found";
        break;

    case CYRUSDB_LOCKED:
        err = "locked";
        break;

    case CYRUSDB_NOTIMPLEMENTED:
        err = "action not implemented";
        break;

    case CYRUSDB_FULL:
        err = "no space available";
        break;

    case CYRUSDB_READONLY:
        err = "database is readonly";
        break;

    default:
        err = "not a cyrusdb error";
        break;
    }

    return err;
}

