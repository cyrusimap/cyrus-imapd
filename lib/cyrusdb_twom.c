/* cyrusdb_twom.c - wrapper around the twom library
 *
 * Copyright (c) 1994-2025 Carnegie Mellon University.  All rights reserved.
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

#include <errno.h>
#include <libgen.h>
#include <syslog.h>
#include <sys/mman.h>

#include "bsearch.h"
#include "cyrusdb.h"
#include "libcyr_cfg.h"
#include "twom.h"
#include "util.h"
#include "xmalloc.h"

/* type aliases */
#define LLU long long unsigned int

static void _twom_error_callback(const char *msg, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));
static void _twom_error_callback(const char *msg, const char *fmt, ...)
{
    int saved_errno = errno;

    struct buf buf = BUF_INITIALIZER;
    buf_printf(&buf, "DBERROR: twom %s:", msg);

    if (fmt) {
        va_list args;
        va_start(args, fmt);
        buf_putc(&buf, ' ');
        buf_vprintf(&buf, fmt, args);
        va_end(args);
    }

    if (saved_errno)
        buf_printf(&buf, " syserror=<%s>",  strerror(saved_errno));

    syslog(LOG_ERR, "%s", buf_cstring(&buf));
    buf_free(&buf);

    errno = saved_errno;
}

static int _errormap(int r) {
    switch(r) {
    case TWOM_OK: return CYRUSDB_OK;
    case TWOM_DONE: return CYRUSDB_DONE;
    case TWOM_EXISTS: return CYRUSDB_EXISTS;
    case TWOM_IOERROR: return CYRUSDB_IOERROR;
    case TWOM_INTERNAL: return CYRUSDB_INTERNAL;
    case TWOM_LOCKED: return CYRUSDB_LOCKED;
    case TWOM_NOTFOUND: return CYRUSDB_NOTFOUND;
    case TWOM_READONLY: return CYRUSDB_READONLY;
    case TWOM_BADFORMAT: return CYRUSDB_BADFORMAT;
    case TWOM_BADUSAGE: return CYRUSDB_INTERNAL;
    case TWOM_BADCHECKSUM: return CYRUSDB_IOERROR;
    // must be a foreach result
    default: return r;
    }
}

struct dcrock {
    char *fname;
    int flags;
    uint64_t generation;
};

static void _delayed_checkpoint_free(void *rock)
{
    struct dcrock *drock = rock;
    free(drock->fname);
    free(drock);
}

static int checkpoint(struct twom_db *db)
{
    size_t presize = twom_db_size(db);
    clock_t start = sclock();
    int r = _errormap(twom_db_repack(db));
    size_t postsize = twom_db_size(db);
    size_t num = twom_db_num_records(db);
    if (r == CYRUSDB_LOCKED) {
        xsyslog(LOG_INFO, "twom: repack already locked",
               "filename=<%s>", twom_db_fname(db));
    }
    else if (r) {
        xsyslog(LOG_ERR, "twom: failed to checkpoint",
               "filename=<%s> error=<%s>", twom_db_fname(db), cyrusdb_strerror(r));
    }
    else {
        syslog(LOG_INFO,
               "twom: repacked %s (%llu record%s, %llu => %llu bytes) in %2.3f seconds",
               twom_db_fname(db), (LLU)num, num == 1 ? "" : "s", (LLU)presize, (LLU)(postsize),
               (sclock() - start) / (double) CLOCKS_PER_SEC);
    }
    return r;
}

static void _delayed_checkpoint(void *rock)
{
    struct dcrock *drock = rock;
    struct twom_db *db = NULL;
    struct twom_open_data init = TWOM_OPEN_DATA_INITIALIZER;
    init.error = _twom_error_callback;
    init.flags = drock->flags;
    int r = _errormap(twom_db_open(drock->fname, &init, &db, NULL));
    if (r == CYRUSDB_NOTFOUND) {
        syslog(LOG_INFO, "twom: no file to delayed checkpoint for %s",
               drock->fname);
        return;
    }
    else if (r) {
        syslog(LOG_ERR, "DBERROR: opening %s for checkpoint: %s",
               drock->fname, cyrusdb_strerror(r));
        return;
    }
    if (twom_db_should_repack(db)) {
        checkpoint(db);
    }
    else {
        syslog(LOG_INFO, "twom: delayed checkpoint already done %s",
               drock->fname);
    }
    twom_db_close(&db);
}

/*************** EXTERNAL APIS ***********************/

static int mylock(struct dbengine *db, struct txn **tidptr, int flags)
{
    struct twom_db *tmdb = (struct twom_db *)db;
    struct twom_txn *tmtxn = (struct twom_txn *)*tidptr;
    int tmr = twom_db_begin_txn(tmdb, flags & CYRUSDB_SHARED, &tmtxn);
    *tidptr = (struct txn *)tmtxn;
    return _errormap(tmr);
}

static int myopen(const char *fname, int flags, struct dbengine **ret, struct txn **tidptr)
{
    struct twom_db *tmdb = NULL;
    struct twom_txn *tmtxn = NULL;
    struct twom_open_data init = TWOM_OPEN_DATA_INITIALIZER;
    init.error = _twom_error_callback;
    init.flags = 0;
    if (flags & CYRUSDB_NOSYNC)
        init.flags |= TWOM_NOSYNC;
    if (flags & CYRUSDB_NOCRC) {
        init.flags |= TWOM_CSUM_NULL;
        init.flags |= TWOM_NOCSUM;
    }
    if (flags & CYRUSDB_CREATE)
        init.flags |= TWOM_CREATE;
    if (flags & CYRUSDB_SHARED)
        init.flags |= TWOM_SHARED;
    int tmr = twom_db_open(fname, &init, &tmdb, tidptr ? &tmtxn : NULL);
    if (tmr == TWOM_NOTFOUND && (flags & CYRUSDB_CREATE)) {
        int r = cyrus_mkdir(fname, 0755);
        if (r < 0) {
            xsyslog(LOG_ERR, "IOERROR: twom cyrus_mkdir failed",
                             "filename=<%s>", fname);
            return r;
        }
        tmr = twom_db_open(fname, &init, &tmdb, tidptr ? &tmtxn : NULL);
    }
    if (!tmr) {
        *ret = (struct dbengine *)tmdb;
        if (tidptr) *tidptr = (struct txn *)tmtxn;
    }
    return _errormap(tmr);
}

static int myclose(struct dbengine *db)
{
    struct twom_db *tmdb = (struct twom_db *)db;
    int tmr = twom_db_close(&tmdb);
    return _errormap(tmr);
}

static int myabort(struct dbengine *db __attribute__((unused)), struct txn *tid)
{
    if (!tid) return 0;
    struct twom_txn *tmtid = (struct twom_txn *)tid;
    int tmr = twom_txn_abort(&tmtid);
    return _errormap(tmr);
}

static int mycommit(struct dbengine *db, struct txn *tid)
{
    if (!tid) return 0;
    struct twom_db *tmdb = (struct twom_db *)db;
    struct twom_txn *tmtid = (struct twom_txn *)tid;
    if (twom_db_should_repack(tmdb)) {
        // delay the checkpoint until the user isn't waiting
        struct dcrock *drock = xzmalloc(sizeof(struct dcrock));
        drock->fname = xstrdup(twom_db_fname(tmdb));
        drock->flags = 0;
        libcyrus_delayed_action(drock->fname, _delayed_checkpoint,
                                _delayed_checkpoint_free, drock);
    }
    int tmr = twom_txn_commit(&tmtid);
    return _errormap(tmr);
}

static int mybegin(struct dbengine *db, struct txn **tidptr)
{
    if (*tidptr) return 0;

    struct twom_db *tmdb = (struct twom_db *)db;
    struct twom_txn *tmtxn = NULL;

    int tmr = twom_db_begin_txn(tmdb, 0, &tmtxn);
    if (tmr) return _errormap(tmr);

    *tidptr = (struct txn *)tmtxn;
    return 0;
}

/* foreach allows for subsidiary mailbox operations in 'cb'.
   if there is a txn, 'cb' must make use of it.
*/
static int myforeach(struct dbengine *db,
                     const char *prefix, size_t prefixlen,
                     foreach_p *goodp,
                     foreach_cb *cb, void *rock,
                     struct txn **tidptr)
{
    int tmflags = 0;

    if (!tidptr) {
        // we call out to the mupdate server within mailbox findall,
        // which tries to lock the mailboxes.db!  This breaks unless
        // we release the lock every time sadly, so add ALWAYSYIELD
        // to match twoskip/skiplist et al behaviour
        tmflags |= TWOM_ALWAYSYIELD;
        struct twom_db *tmdb = (struct twom_db *)db;
        return _errormap(twom_db_foreach(tmdb, prefix, prefixlen,
                                         goodp, cb, rock, tmflags));
    }

    int r = mybegin(db, tidptr);
    if (r) return r;

    struct twom_txn *tmtxn = (struct twom_txn *)*tidptr;
    return _errormap(twom_txn_foreach(tmtxn, prefix, prefixlen,
                                      goodp, cb, rock, tmflags));
}

static int mycheckpoint(struct dbengine *db)
{
    struct twom_db *tmdb = (struct twom_db *)db;
    int tmr = checkpoint(tmdb);
    return _errormap(tmr);
}

static int mydump(struct dbengine *db, int detail)
{
    struct twom_db *tmdb = (struct twom_db *)db;
    int tmr = twom_db_dump(tmdb, detail);
    return _errormap(tmr);
}

static int myconsistent(struct dbengine *db)
{
    struct twom_db *tmdb = (struct twom_db *)db;
    int tmr = twom_db_check_consistency(tmdb);
    return _errormap(tmr);
}

static int myread(struct dbengine *db,
                  const char *key, size_t keylen,
                  const char **foundkey, size_t *fklen,
                  const char **data, size_t *datalen,
                  struct txn **tidptr, int tmflags)
{
    if (keylen) assert(key);
    struct twom_db *tmdb = (struct twom_db *)db;

    if (!tidptr)
        return _errormap(twom_db_fetch(tmdb, key, keylen, foundkey, fklen,
                                       data, datalen, tmflags));

    int r = mybegin(db, tidptr);
    if (r) return r;

    struct twom_txn *tmtxn = (struct twom_txn *)*tidptr;
    return _errormap(twom_txn_fetch(tmtxn, key, keylen, foundkey, fklen,
                                    data, datalen, tmflags));
}

static int fetch(struct dbengine *db,
                 const char *key, size_t keylen,
                 const char **data, size_t *datalen,
                 struct txn **tidptr)
{
    return myread(db, key, keylen, NULL, NULL, data, datalen, tidptr, 0);
}

static int fetchnext(struct dbengine *db,
                     const char *key, size_t keylen,
                     const char **foundkey, size_t *fklen,
                     const char **data, size_t *datalen,
                     struct txn **tidptr)
{
    return myread(db, key, keylen, foundkey, fklen, data, datalen, tidptr, TWOM_FETCHNEXT);
}

static int mywrite(struct dbengine *db,
                   const char *key, size_t keylen,
                   const char *data, size_t datalen,
                   struct txn **tidptr, int tmflags)
{
    struct twom_db *tmdb = (struct twom_db *)db;

    if (!tidptr)
        return _errormap(twom_db_store(tmdb, key, keylen, data, datalen, tmflags));

    int r = mybegin(db, tidptr);
    if (r) return r;

    struct twom_txn *tmtxn = (struct twom_txn *)*tidptr;
    return _errormap(twom_txn_store(tmtxn, key, keylen, data, datalen, tmflags));
}

static int create(struct dbengine *db,
                  const char *key, size_t keylen,
                  const char *data, size_t datalen,
                  struct txn **tidptr)
{
    if (!data) data = "";
    return mywrite(db, key, keylen, data, datalen, tidptr, TWOM_IFNOTEXIST);
}

static int store(struct dbengine *db,
                 const char *key, size_t keylen,
                 const char *data, size_t datalen,
                 struct txn **tidptr)
{
    if (!data) data = "";
    return mywrite(db, key, keylen, data, datalen, tidptr, 0);
}

static int delete(struct dbengine *db,
                 const char *key, size_t keylen,
                 struct txn **tidptr, int force)
{
    int tmflags = force ? 0 : TWOM_IFEXIST;
    return mywrite(db, key, keylen, NULL, 0, tidptr, tmflags);
}

HIDDEN struct cyrusdb_backend cyrusdb_twom =
{
    "twom",                  /* name */

    &cyrusdb_generic_init,
    &cyrusdb_generic_done,
    &cyrusdb_generic_archive,
    &cyrusdb_generic_unlink,

    NULL, /*yield*/

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
};
