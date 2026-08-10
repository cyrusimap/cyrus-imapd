/* cyrusdb_zeroskip.c - wrapper around the zeroskip library */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>

#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <syslog.h>
#include <sys/stat.h>

#include "bsearch.h"
#include "cyrusdb.h"
#include "libcyr_cfg.h"
#include "util.h"
#include "xmalloc.h"
#include "zeroskip.h"

/* Data files are named "zeroskip-<uuid>-<generation>[-<generation>]", plus the
 * active file "zeroskip-<uuid>.current".  Everything else in the directory is
 * metadata under the "zeroskip." prefix - the lock file, repack staging, the
 * pointer-table cache - and deliberately does not match: none of it carries
 * state worth archiving, and all of it is recreated on demand. */
#define ZEROSKIP_DATA_PREFIX "zeroskip-"

/* zeroskip exposes no filename accessor, so unlike the twom wrapper this one
 * cannot cast a struct dbengine * straight to the library handle: it has to
 * carry the filename itself for logging and for reopening during a delayed
 * checkpoint. */
struct dbengine {
    struct zs_db *db;
    char *fname;
};

static void _zeroskip_error_callback(const char *msg, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));
static void _zeroskip_error_callback(const char *msg, const char *fmt, ...)
{
    int saved_errno = errno;

    struct buf buf = BUF_INITIALIZER;
    buf_printf(&buf, "DBERROR: zeroskip %s:", msg);

    if (fmt) {
        va_list args;
        va_start(args, fmt);
        buf_putc(&buf, ' ');
        buf_vprintf(&buf, fmt, args);
        va_end(args);
    }

    if (saved_errno)
        buf_printf(&buf, " syserror=<%s>", strerror(saved_errno));

    syslog(LOG_ERR, "%s", buf_cstring(&buf));
    buf_free(&buf);

    errno = saved_errno;
}

static int _errormap(int r)
{
    switch (r) {
    case ZS_OK: return CYRUSDB_OK;
    case ZS_DONE: return CYRUSDB_DONE;
    case ZS_EXISTS: return CYRUSDB_EXISTS;
    case ZS_IOERROR: return CYRUSDB_IOERROR;
    case ZS_INTERNAL: return CYRUSDB_INTERNAL;
    case ZS_LOCKED: return CYRUSDB_LOCKED;
    case ZS_NOTFOUND: return CYRUSDB_NOTFOUND;
    case ZS_READONLY: return CYRUSDB_READONLY;
    case ZS_BADFORMAT: return CYRUSDB_BADFORMAT;
    case ZS_BADUSAGE: return CYRUSDB_INTERNAL;
    case ZS_BADCHECKSUM: return CYRUSDB_IOERROR;
    case ZS_FULL: return CYRUSDB_FULL;
    case ZS_AGAIN: return CYRUSDB_AGAIN;
    // must be a foreach result
    default: return r;
    }
}

static void _setup_init(struct zs_open_data *setup, int flags)
{
    setup->error = _zeroskip_error_callback;
    setup->index_dir = libcyrus_config_getstring(CYRUSOPT_ZEROSKIP_INDEX_PATH);
    /* by default the writer runs the repack cascade itself (D-16e), which is an
     * unbounded merge landing on whichever write transaction starts a new
     * generation and finds work.  cyrus already schedules that reclaim from the
     * delayed-action queue, where the user isn't waiting, so take the deferral
     * we can already deliver rather than the latency spike. */
    setup->flags = ZS_NOAUTOREPACK;
    /* the library never picks a cache location itself, but the database
     * directory is already ours and access-controlled, so default the
     * pointer-table cache there rather than running uncached */
    if (!setup->index_dir) setup->flags |= ZS_INDEX_LOCAL;
    if (flags & CYRUSDB_CREATE) setup->flags |= ZS_CREATE;
    if (flags & CYRUSDB_NOSYNC) setup->flags |= ZS_NOSYNC;
    if (flags & CYRUSDB_SHARED) setup->flags |= ZS_SHARED;
    /* NOCRC only picks the checksum engine files get written with: nothing in
     * format 3 verifies on a read path anyway (F-33a), so there is no
     * verification left to skip - the old ZS_NOCSUM is reserved and rejected. */
    if (flags & CYRUSDB_NOCRC) setup->flags |= ZS_CSUM_NONE;
}

struct dcrock {
    char *fname;
    int flags;
};

static void _delayed_checkpoint_free(void *rock)
{
    struct dcrock *drock = rock;
    free(drock->fname);
    free(drock);
}

/* zeroskip offers two reclaim operations, and the two cyrus entry points want
 * different ones.  The cyrusdb repack slot is an explicit maintenance pass
 * (ctl_cyrusdb -c), where reclaiming everything is the whole point and being
 * unbounded is acceptable; only a full compaction reclaims tombstones (D-27),
 * which a partial repack structurally cannot.  The post-commit path is the
 * opposite case -- routine and latency-sensitive -- so it takes the bounded
 * zs_db_repack. */
static int checkpoint(struct dbengine *db, int full)
{
    /* zs_db_stats counts from open rather than reporting file sizes, and a
     * compact seals before it merges, so take a delta over both causes to get
     * the twom-shaped "this is what the checkpoint rewrote" line. */
    struct zs_db_stats before = { 0 }, after = { 0 };
    clock_t start = sclock();

    zs_db_stats(db->db, &before);
    int zsr = full ? zs_db_compact(db->db) : zs_db_repack(db->db);

    /* zs_db_compact reports ZS_BADFORMAT when it could not reduce the database
     * to a single file, having merged whatever it could first.  That is partial
     * success rather than corruption, so it must not fail the checkpoint. */
    if (full && zsr == ZS_BADFORMAT) {
        xsyslog(LOG_INFO, "zeroskip: compact did not reach a single file",
                "filename=<%s>", db->fname);
        zsr = ZS_OK;
    }

    int r = _errormap(zsr);
    if (r == CYRUSDB_LOCKED) {
        xsyslog(LOG_INFO, "zeroskip: repack already locked",
                "filename=<%s>", db->fname);
    }
    else if (r) {
        xsyslog(LOG_ERR, "zeroskip: failed to checkpoint",
                "filename=<%s> error=<%s>", db->fname, cyrusdb_strerror(r));
    }
    else {
        zs_db_stats(db->db, &after);
        unsigned long long records =
            (after.repack_records - before.repack_records)
            + (after.convert_records - before.convert_records);
        unsigned long long bytes =
            (after.repack_bytes - before.repack_bytes)
            + (after.convert_bytes - before.convert_bytes);

        syslog(LOG_INFO,
               "zeroskip: %s %s (%llu record%s, %llu bytes) in %2.3f seconds",
               full ? "compacted" : "repacked", db->fname,
               records, records == 1 ? "" : "s", bytes,
               (sclock() - start) / (double) CLOCKS_PER_SEC);
    }
    return r;
}

static int myopen(const char *fname, int flags,
                  struct dbengine **ret, struct txn **tidptr);
static int myclose(struct dbengine *db);

static void _delayed_checkpoint(void *rock)
{
    struct dcrock *drock = rock;
    struct dbengine *db = NULL;

    int r = myopen(drock->fname, drock->flags, &db, NULL);
    if (r == CYRUSDB_NOTFOUND) {
        // the database is gone - it's fine to lose this race, nothing to do
        return;
    }
    else if (r) {
        syslog(LOG_ERR, "DBERROR: opening %s for checkpoint: %s",
               drock->fname, cyrusdb_strerror(r));
        return;
    }

    if (zs_db_should_repack(db->db)) {
        checkpoint(db, 0);
    }
    else {
        syslog(LOG_INFO, "zeroskip: delayed checkpoint already done %s",
               drock->fname);
    }
    myclose(db);
}

/*************** EXTERNAL APIS ***********************/

static int myopen(const char *fname, int flags,
                  struct dbengine **ret, struct txn **tidptr)
{
    struct zs_db *zsdb = NULL;
    struct zs_open_data setup = ZS_OPEN_DATA_INITIALIZER;

    _setup_init(&setup, flags);

    int zsr = zs_db_open(fname, &setup, &zsdb);

    /* zs_db_open mkdirs only the leaf, and a missing parent surfaces from that
     * mkdir as ZS_IOERROR rather than ZS_NOTFOUND, because an absent directory
     * is zeroskip's "empty database" case. */
    if (zsr == ZS_IOERROR && (flags & CYRUSDB_CREATE)) {
        int r = cyrus_mkdir(fname, 0755);
        if (r < 0) {
            xsyslog(LOG_ERR, "IOERROR: zeroskip cyrus_mkdir failed",
                    "filename=<%s>", fname);
            return CYRUSDB_IOERROR;
        }
        zsr = zs_db_open(fname, &setup, &zsdb);
    }
    if (zsr) return _errormap(zsr);

    struct dbengine *db = xzmalloc(sizeof(struct dbengine));
    db->db = zsdb;
    db->fname = xstrdup(fname);

    if (tidptr) {
        struct zs_txn *zstxn = NULL;
        zsr = zs_db_begin_txn(zsdb, (flags & CYRUSDB_SHARED) ? 1 : 0, &zstxn);
        if (zsr) {
            zs_db_close(&db->db);
            free(db->fname);
            free(db);
            return _errormap(zsr);
        }
        *tidptr = (struct txn *)zstxn;
    }

    *ret = db;
    return CYRUSDB_OK;
}

static int myclose(struct dbengine *db)
{
    int zsr = zs_db_close(&db->db);
    free(db->fname);
    free(db);
    return _errormap(zsr);
}

/* A zeroskip database is a directory, so the generic unlink's xunlink cannot
 * remove it. */
static int myunlink(const char *fname, int flags __attribute__((unused)))
{
    if (fname) removedir(fname);
    return 0;
}

/* Likewise the generic archiver, which copies each named file into the backup
 * directory: here each name is a directory whose data files must be copied.
 * zeroskip.lock is deliberately not copied - it is recreated on open, and
 * carries no state. */
static int myarchive(const strarray_t *fnames, const char *dirname)
{
    char dstpath[PATH_MAX];
    int i;
    int r = 0;

    for (i = 0; i < fnames->count; i++) {
        const char *fname = strarray_nth(fnames, i);
        if (!fname) continue;

        struct stat sbuf;
        if (stat(fname, &sbuf) < 0) {
            syslog(LOG_DEBUG, "not archiving database file: %s: %m", fname);
            continue;
        }

        const char *base = strrchr(fname, '/');
        base = base ? base + 1 : fname;

        snprintf(dstpath, sizeof(dstpath), "%s/%s/dummy", dirname, base);
        if (cyrus_mkdir(dstpath, 0755) < 0) {
            syslog(LOG_ERR, "DBERROR: error creating archive dir for %s", fname);
            return CYRUSDB_IOERROR;
        }

        DIR *d = opendir(fname);
        if (!d) {
            syslog(LOG_ERR, "DBERROR: error opening %s: %m", fname);
            return CYRUSDB_IOERROR;
        }

        struct dirent *de;
        while ((de = readdir(d)) != NULL) {
            if (strncmp(de->d_name, ZEROSKIP_DATA_PREFIX,
                        strlen(ZEROSKIP_DATA_PREFIX)))
                continue;

            char srcpath[PATH_MAX];
            snprintf(srcpath, sizeof(srcpath), "%s/%s", fname, de->d_name);
            snprintf(dstpath, sizeof(dstpath), "%s/%s/%s",
                     dirname, base, de->d_name);

            syslog(LOG_DEBUG, "archiving database file: %s", srcpath);
            if (cyrusdb_copyfile(srcpath, dstpath)) {
                syslog(LOG_ERR,
                       "DBERROR: error archiving database file: %s", srcpath);
                r = CYRUSDB_IOERROR;
                break;
            }
        }
        closedir(d);
        if (r) return r;
    }

    return 0;
}

static int mybegin(struct dbengine *db, struct txn **tidptr)
{
    if (*tidptr) return 0;

    struct zs_txn *zstxn = NULL;
    int zsr = zs_db_begin_txn(db->db, 0, &zstxn);
    if (zsr) return _errormap(zsr);

    *tidptr = (struct txn *)zstxn;
    return 0;
}

static int mylock(struct dbengine *db, struct txn **tidptr, int flags)
{
    struct zs_txn *zstxn = (struct zs_txn *)*tidptr;
    int zsr = zs_db_begin_txn(db->db, flags & CYRUSDB_SHARED, &zstxn);
    *tidptr = (struct txn *)zstxn;
    return _errormap(zsr);
}

static int myabort(struct dbengine *db __attribute__((unused)), struct txn *tid)
{
    if (!tid) return 0;
    struct zs_txn *zstid = (struct zs_txn *)tid;
    int zsr = zs_txn_abort(&zstid);
    return _errormap(zsr);
}

static int mycommit(struct dbengine *db, struct txn *tid)
{
    if (!tid) return 0;
    struct zs_txn *zstid = (struct zs_txn *)tid;

    if (zs_db_should_repack(db->db)) {
        // delay the checkpoint until the user isn't waiting
        struct dcrock *drock = xzmalloc(sizeof(struct dcrock));
        drock->fname = xstrdup(db->fname);
        drock->flags = 0;
        libcyrus_delayed_action(drock->fname, _delayed_checkpoint,
                                _delayed_checkpoint_free, drock);
    }

    int zsr = zs_txn_commit(&zstid);
    return _errormap(zsr);
}

/* foreach allows for subsidiary mailbox operations in 'cb'.
   if there is a txn, 'cb' must make use of it.

   ZS_CURSOR_PREFIX is mandatory: without it zeroskip treats the prefix purely
   as a seek position and iterates to the end of the database, which is not
   what cyrusdb foreach means.  Readers take no lock, so there is no equivalent
   of twom's ALWAYSYIELD to add here.

   A cursor observes writes made through its own handle as it goes (D-14j), so
   a store() from inside 'cb' at a key after the current position is seen by
   the rest of the traversal, as cyrusdb.h requires.  ZS_CURSOR_LIVE, which
   additionally observes commits by OTHER processes, is deliberately not passed:
   it costs a re-scan per record, and cyrusdb explicitly leaves those changes
   "may or may not be visible".
*/
static int myforeach(struct dbengine *db,
                     const char *prefix, size_t prefixlen,
                     foreach_p *goodp,
                     foreach_cb *cb, void *rock,
                     struct txn **tidptr)
{
    int zsflags = ZS_CURSOR_PREFIX;

    if (!tidptr) {
        return _errormap(zs_db_foreach(db->db, prefix, prefixlen,
                                       goodp, cb, rock, zsflags));
    }

    int r = mybegin(db, tidptr);
    if (r) return r;

    struct zs_txn *zstxn = (struct zs_txn *)*tidptr;
    return _errormap(zs_txn_foreach(zstxn, prefix, prefixlen,
                                    goodp, cb, rock, zsflags));
}

static int mycheckpoint(struct dbengine *db)
{
    return checkpoint(db, 1);
}

static int mydump(struct dbengine *db, int detail)
{
    return _errormap(zs_db_dump(db->db, detail));
}

static int myconsistent(struct dbengine *db)
{
    return _errormap(zs_db_check_consistency(db->db));
}

/* zs_db_fetch()/zs_txn_fetch() reject any keylen < 1 unconditionally,
 * including for ZS_FETCHNEXT -- where cyrusdb's (NULL, 0) spells "start of
 * the database", not an actual zero-length key.  The cursor API has no such
 * restriction, so route that one case through it instead. */
static int myfetchnext_start(struct dbengine *db,
                             const char **foundkey, size_t *fklen,
                             const char **data, size_t *datalen,
                             struct txn **tidptr)
{
    struct zs_cursor *cur = NULL;
    int r;

    if (!tidptr) {
        r = zs_db_begin_cursor(db->db, NULL, 0, &cur, ZS_SHARED);
        if (r) return _errormap(r);

        r = zs_cursor_next(cur, foundkey, fklen, data, datalen);
        zs_cursor_abort(&cur);
    }
    else {
        int br = mybegin(db, tidptr);
        if (br) return br;

        struct zs_txn *zstxn = (struct zs_txn *)*tidptr;
        r = zs_txn_begin_cursor(zstxn, NULL, 0, &cur, 0);
        if (r) return _errormap(r);

        r = zs_cursor_next(cur, foundkey, fklen, data, datalen);
        zs_cursor_fini(&cur);
    }

    /* zs_cursor_next() signals exhaustion with ZS_DONE; zs_txn_fetch()'s own
     * ZS_FETCHNEXT path translates that to ZS_NOTFOUND, so match it here. */
    if (r == ZS_DONE) r = ZS_NOTFOUND;
    return _errormap(r);
}

static int myread(struct dbengine *db,
                  const char *key, size_t keylen,
                  const char **foundkey, size_t *fklen,
                  const char **data, size_t *datalen,
                  struct txn **tidptr, int zsflags)
{
    if (keylen) assert(key);
    /* zeroskip rejects a NULL key outright, where cyrusdb allows the empty
     * key to be spelled (NULL, 0). */
    if (!key) key = "";

    /* zs_db_fetch()/zs_txn_fetch() only write their out-params on success,
     * leaving them untouched otherwise.  cyrusdb callers rely on NOTFOUND
     * (and other failures) leaving data/datalen at NULL/0, so clear them
     * up front rather than passing through whatever the caller preset. */
    if (foundkey) *foundkey = NULL;
    if (fklen) *fklen = 0;
    if (data) *data = NULL;
    if (datalen) *datalen = 0;

    if ((zsflags & ZS_FETCHNEXT) && !keylen)
        return myfetchnext_start(db, foundkey, fklen, data, datalen, tidptr);

    if (!tidptr)
        return _errormap(zs_db_fetch(db->db, key, keylen, foundkey, fklen,
                                     data, datalen, zsflags));

    int r = mybegin(db, tidptr);
    if (r) return r;

    struct zs_txn *zstxn = (struct zs_txn *)*tidptr;
    return _errormap(zs_txn_fetch(zstxn, key, keylen, foundkey, fklen,
                                  data, datalen, zsflags));
}

static int fetch(struct dbengine *db,
                 const char *key, size_t keylen,
                 const char **data, size_t *datalen,
                 struct txn **tidptr)
{
    return myread(db, key, keylen, NULL, NULL, data, datalen, tidptr, 0);
}

/* cyrusdb's fetchnext is the strict successor, which zeroskip spells
 * ZS_FETCHNEXT|ZS_SKIPROOT -- bare ZS_FETCHNEXT is the inclusive bound. */
static int fetchnext(struct dbengine *db,
                     const char *key, size_t keylen,
                     const char **foundkey, size_t *fklen,
                     const char **data, size_t *datalen,
                     struct txn **tidptr)
{
    return myread(db, key, keylen, foundkey, fklen, data, datalen, tidptr,
                  ZS_FETCHNEXT | ZS_SKIPROOT);
}

static int mywrite(struct dbengine *db,
                   const char *key, size_t keylen,
                   const char *data, size_t datalen,
                   struct txn **tidptr, int zsflags)
{
    if (!tidptr)
        return _errormap(zs_db_store(db->db, key, keylen, data, datalen,
                                     zsflags));

    int r = mybegin(db, tidptr);
    if (r) return r;

    struct zs_txn *zstxn = (struct zs_txn *)*tidptr;
    return _errormap(zs_txn_store(zstxn, key, keylen, data, datalen, zsflags));
}

static int create(struct dbengine *db,
                  const char *key, size_t keylen,
                  const char *data, size_t datalen,
                  struct txn **tidptr)
{
    if (!data) data = "";
    return mywrite(db, key, keylen, data, datalen, tidptr, ZS_IFNOTEXIST);
}

static int store(struct dbengine *db,
                 const char *key, size_t keylen,
                 const char *data, size_t datalen,
                 struct txn **tidptr)
{
    if (!data) data = "";
    return mywrite(db, key, keylen, data, datalen, tidptr, 0);
}

/* A forced delete is cyrusdb's "remove it, it might not be there" case, so pay
 * ZS_IFCHANGED's point lookup to keep it from writing a tombstone for a key
 * that was never there: nothing else drops such a tombstone, a repack carries
 * it until it can prove the key absent everywhere below, and the callers that
 * force are the ones deleting speculatively.  An unforced delete already knows
 * the key exists, or wants the ZS_IFEXIST error if it doesn't. */
static int delete(struct dbengine *db,
                  const char *key, size_t keylen,
                  struct txn **tidptr, int force)
{
    int zsflags = force ? ZS_IFCHANGED : ZS_IFEXIST;
    return mywrite(db, key, keylen, NULL, 0, tidptr, zsflags);
}

HIDDEN struct cyrusdb_backend cyrusdb_zeroskip =
{
    "zeroskip",              /* name */

    &cyrusdb_generic_init,
    &cyrusdb_generic_done,
    &myarchive,
    &myunlink,

    &myopen,
    &myclose,

    &fetch,
    &fetch,
    &fetchnext,

    &myforeach,
    &create,
    &store,
    &delete,

    &mylock,
    &mycommit,
    &myabort,

    &mydump,
    &myconsistent,
    &mycheckpoint,
    &bsearch_ncompare_raw,
    CYRUSDB_BACKEND_ISDIR,
};
