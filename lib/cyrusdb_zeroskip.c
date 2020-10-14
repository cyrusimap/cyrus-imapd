/* cyrusdb_zeroskip.c - Support for Zeroskip
 *
 * Copyright (c) 1994-2018 Carnegie Mellon University.  All rights reserved.
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
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/types.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "assert.h"
#include "bsearch.h"
#include "cyrusdb.h"
#include "util.h"
#include "xmalloc.h"

#include <libzeroskip/zeroskip.h>
#include <libzeroskip/memtree.h>

struct txn {
    struct zsdb_txn *t;
};


struct dbengine {
    struct zsdb *db;
    struct zsdb_txn **curent_txn;
};


struct dblist {
    struct dbengine *db;
    struct dblist *next;
};

/****** INTERNAL FUNCTIONS ******/
static int create_or_reuse_txn(struct dbengine *db,
                               struct txn **curtidptr,
                               struct txn **newtidptr)
{
    struct txn *tid = NULL;

    assert(newtidptr);
    tid = *newtidptr;

    if (!curtidptr || !*curtidptr) {
        /* New transaction */
        int r;

        tid = xcalloc(1, sizeof(struct txn));
        r = zsdb_transaction_begin(db->db, &tid->t);
        if (r != ZS_OK) {
            free(tid);
            tid = NULL;
            *newtidptr = NULL;
            return CYRUSDB_INTERNAL;
        }
    } else {
        /* Existing transaction */
        tid = *curtidptr;
    }

    if (curtidptr)
        *curtidptr = tid;

    *newtidptr = tid;

    return CYRUSDB_OK;
}

memtree_memcmp_fn(
  mbox,
  ,
  bsearch_memtree_mbox(k, keylen, b, blen)
)
/****** CYRUS DB API ******/

HIDDEN int cyrusdb_zeroskip_init(const char *dbdir __attribute__((unused)),
                                 int myflags __attribute__((unused)))
{
    return CYRUSDB_OK;
}

HIDDEN int cyrusdb_zeroskip_done(void)
{
    return CYRUSDB_OK;
}

HIDDEN int cyrusdb_zeroskip_sync(void)
{
    return CYRUSDB_OK;
}

HIDDEN int cyrusdb_zeroskip_archive(const strarray_t *fnames __attribute__((unused)),
                                    const char *dirname __attribute__((unused)))
{
    return CYRUSDB_OK;
}


HIDDEN int cyrusdb_zeroskip_unlink(const char *fname __attribute__((unused)),
                                   int flags __attribute__((unused)))
{
    return CYRUSDB_OK;
}

static int cyrusdb_zeroskip_open(const char *fname,
                                 int flags,
                                 struct dbengine **ret,
                                 struct txn **mytid)
{
    struct dbengine *dbe;
    int r = CYRUSDB_OK;
    int zsdbflags = MODE_RDWR;
    zsdb_cmp_fn dbcmpfn = NULL;
    memtree_search_cb_t btcmpfn = NULL;

    dbe = (struct dbengine *) xzmalloc(sizeof(struct dbengine));

    if (flags & CYRUSDB_CREATE)
        zsdbflags = MODE_CREATE;

    if (flags & CYRUSDB_MBOXSORT) {
        zsdbflags |= MODE_CUSTOMSEARCH;
        dbcmpfn = bsearch_uncompare_mbox;
        btcmpfn = memtree_memcmp_mbox;
    }

    if (zsdb_init(&dbe->db, dbcmpfn, btcmpfn) != ZS_OK) {
        r = CYRUSDB_IOERROR;
        goto done;
    }

    r = zsdb_open(dbe->db, fname, zsdbflags);
    if (r) {
        if (r == ZS_NOTFOUND) r = CYRUSDB_NOTFOUND;
        else r = CYRUSDB_IOERROR;
        goto finalise_db;
    }

    *ret = dbe;

    if (mytid) {
        *mytid = xmalloc(sizeof(struct txn));
        r = zsdb_transaction_begin(dbe->db, &(*mytid)->t);
        if (r != ZS_OK) {
            r = CYRUSDB_INTERNAL;
            goto close_db;
        }
    }

    r = CYRUSDB_OK;
    goto done;

 close_db:
    zsdb_close(dbe->db);
 finalise_db:
    zsdb_final(&dbe->db);
    free(dbe);

 done:
    return r;
}

static int cyrusdb_zeroskip_close(struct dbengine *dbe)
{
    int r = CYRUSDB_OK;

    assert(dbe);
    assert(dbe->db);

    r = zsdb_close(dbe->db);
    if (r) {
        r = CYRUSDB_INTERNAL;
        goto done;
    }

    zsdb_final(&dbe->db);

    free(dbe);
    dbe = NULL;

 done:
    return r;
}

static int cyrusdb_zeroskip_fetch(struct dbengine *db,
                                  const char *key, size_t keylen,
                                  const char **data, size_t *datalen,
                                  struct txn **tidptr)
{
    int r = CYRUSDB_OK;
    struct txn *tid = NULL;

    assert(db);
    assert(key);
    assert(keylen);

    if (datalen) assert(data);

    if (data) *data = NULL;
    if (datalen) *datalen = 0;

    r = create_or_reuse_txn(db, tidptr, &tid);
    if (r)
        goto done;

    r = zsdb_fetch(db->db, (const unsigned char *)key, keylen,
                   (const unsigned char **)data, datalen,
                   tidptr ? &tid->t : NULL);
    if (r == ZS_NOTFOUND){
        r = CYRUSDB_NOTFOUND;
        if (data) *data = NULL;
        if (datalen) *datalen = 0;

        goto done;

    } else if (r) {
        r = CYRUSDB_IOERROR;
        goto done;
    }

    if (tidptr) {
        *tidptr = tid;
    }

    r = CYRUSDB_OK;

 done:
    if (tid && (!tidptr || !*tidptr)) {
        zsdb_transaction_end(&tid->t);
        free(tid);
        tid = NULL;
    }

    return r;
}

static int cyrusdb_zeroskip_fetchlock(struct dbengine *db,
                                      const char *key, size_t keylen,
                                      const char **data, size_t *datalen,
                                      struct txn **tidptr)
{
    assert(key);
    assert(keylen);

    /* TODO: LOCK??? */
    return cyrusdb_zeroskip_fetch(db, key, keylen,
                                  data, datalen,
                                  tidptr);
}

static int cyrusdb_zeroskip_fetchnext(struct dbengine *db,
                                      const char *key, size_t keylen,
                                      const char **foundkey, size_t *fklen,
                                      const char **data, size_t *datalen,
                                      struct txn **tidptr __attribute__((unused)))
{
    int r = CYRUSDB_OK;
    struct txn *tid = NULL;

    assert(db);

    r = zsdb_fetchnext(db->db, (const unsigned char *)key, keylen,
                       (const unsigned char **)foundkey, fklen,
                       (const unsigned char **)data, datalen,
                       &tid->t);
    if (r != ZS_OK) {
        if (r == ZS_NOTFOUND) r = CYRUSDB_NOTFOUND;
        else                  r = CYRUSDB_IOERROR;
        goto done;
    }

 done:
    return r;
}

static int cyrusdb_zeroskip_foreach(struct dbengine *db,
                                    const char *prefix, size_t prefixlen,
                                    foreach_p *goodp,
                                    foreach_cb *cb, void *rock,
                                    struct txn **tidptr)
{
    int r = CYRUSDB_OK;
    struct txn *tid = NULL;

    assert(db);
    assert(cb);

    if (prefixlen) assert(prefix);

    r = create_or_reuse_txn(db, tidptr, &tid);
    if (r)
        goto done;

    /* FIXME: The *ugly* typecasts  be removed as soon as we * update the
     * CyrusDB interfaces to support `unsigned char *` instead of * `char *`.
     */
    r = zsdb_foreach(db->db, (unsigned char *)prefix, prefixlen,
                     (int (*)(void*, const unsigned char *, size_t , const unsigned char *, size_t))goodp,
                     (int (*)(void*, const unsigned char *, size_t , const unsigned char *, size_t))cb,
                     rock, tidptr ? &tid->t : NULL);
    if (r != ZS_OK) {
        r = CYRUSDB_IOERROR;
        goto done;
    }

    if (tidptr) {
        *tidptr = tid;
    }

    r = CYRUSDB_OK;

 done:
    if (tid && (!tidptr || !*tidptr)) {
        zsdb_transaction_end(&tid->t);
        free(tid);
        tid = NULL;
    }

    return r;
}

static int cyrusdb_zeroskip_create(struct dbengine *db __attribute__((unused)),
                                   const char *key __attribute__((unused)),
                                   size_t keylen __attribute__((unused)),
                                   const char *data, size_t datalen,
                                   struct txn **tidptr __attribute__((unused)))
{
    if (datalen) assert(data);

    return 0;
}

static int cyrusdb_zeroskip_store(struct dbengine *db,
                                  const char *key, size_t keylen,
                                  const char *data, size_t datalen,
                                  struct txn **tidptr)
{
    struct txn *tid = NULL;
    int r = 0;

    if (datalen) assert(data);

    assert(db);
    assert(key && keylen);

    r = create_or_reuse_txn(db, tidptr, &tid);
    if (r)
        goto done;

    /* Acquire write lock */
    zsdb_write_lock_acquire(db->db, 0);

    r = zsdb_add(db->db, (const unsigned char *)key, keylen,
                 (const unsigned char *)data, datalen,
                 tidptr ? &tid->t : NULL);
    if (r == ZS_NOTFOUND) {
        r = CYRUSDB_NOTFOUND;
        goto done;
    } else if (r) {
        zsdb_abort(db->db, &tid->t);
        r = CYRUSDB_IOERROR;
        goto done;
    }

    if (tidptr) {
        *tidptr = tid;
    }

    if (r) r = CYRUSDB_IOERROR;
    else   r = CYRUSDB_OK;

 done:
    /* Release write lock */
    zsdb_write_lock_release(db->db);

    if (tid && (!tidptr || !*tidptr)) {
        zsdb_transaction_end(&tid->t);
        free(tid);
        tid = NULL;
    }

    return r;
}

static int cyrusdb_zeroskip_delete(struct dbengine *db,
                                   const char *key, size_t keylen,
                                   struct txn **tidptr,
                                   int force __attribute__((unused)))
{
    struct txn *tid = NULL;
    int r = 0;

    if (keylen) assert(key);

    assert(db);

    r = create_or_reuse_txn(db, tidptr, &tid);
    if (r)
        goto done;

    /* Acquire write lock */
    zsdb_write_lock_acquire(db->db, 0);

    r = zsdb_remove(db->db, (const unsigned char *)key, keylen, &tid->t);
    if (r == ZS_NOTFOUND) {
        r = CYRUSDB_NOTFOUND;
        goto done;
    } else if (r) {
        r = CYRUSDB_INTERNAL;
        goto done;
    }

    if (tidptr) {
        *tidptr = tid;
    }

    if (r) r = CYRUSDB_IOERROR;
    else   r = CYRUSDB_OK;

 done:
    /* Release write lock */
    zsdb_write_lock_release(db->db);

    if (tid && (!tidptr || !*tidptr)) {
        zsdb_transaction_end(&tid->t);
        free(tid);
        tid = NULL;
    }

    return r;
}


static int cyrusdb_zeroskip_commit(struct dbengine *db, struct txn *tid)
{
    int r = 0;
    struct zsdb_txn *t;

    assert(db);

    t = tid ? tid->t : NULL;

    r = zsdb_commit(db->db, &t);
    if (r)
        r = CYRUSDB_IOERROR;
    else
        r = CYRUSDB_OK;

    if (tid)
        free(tid);

    return r;
}

static int cyrusdb_zeroskip_abort(struct dbengine *db, struct txn *tid)
{
    assert(db);
    assert(tid);

    zsdb_abort(db->db, &tid->t);
    free(tid);
    tid = NULL;

    return CYRUSDB_OK;
}

/* cyrusdb_zeroskip_dump:
   if detail == 1, dump all records.
   if detail == 2, dump active records only
*/
static int cyrusdb_zeroskip_dump(struct dbengine *db,
                                 int detail)
{
    int r = 0;

    assert(db);

    r = zsdb_dump(db->db, (detail == 1) ? DB_DUMP_ALL : DB_DUMP_ACTIVE);
    if (r)
        r = CYRUSDB_IOERROR;
    else
        r = CYRUSDB_OK;

    return r;
}

static int cyrusdb_zeroskip_consistent(struct dbengine *db __attribute__((unused)))
{
    return 0;
}

static int cyrusdb_zeroskip_checkpoint(struct dbengine *db)
{
    int r = 0;

    assert(db);

    if (zsdb_pack_lock_acquire(db->db, 0) != ZS_OK) {
        r = CYRUSDB_IOERROR;
        goto done;
    }

    r = zsdb_repack(db->db);
    if (r)
        r = CYRUSDB_IOERROR;
    else
        r = CYRUSDB_OK;

    if (zsdb_pack_lock_release(db->db) != ZS_OK) {
        r = CYRUSDB_IOERROR;
    }

done:
    return r;
}

static int cyrusdb_zeroskip_compar(struct dbengine *db __attribute__((unused)),
                                   const char *a __attribute__((unused)),
                                   int alen __attribute__((unused)),
                                   const char *b __attribute__((unused)),
                                   int blen __attribute__((unused)))
{
    /* return db->compar(a, alen, b, blen); */
    return 0;
}


HIDDEN struct cyrusdb_backend cyrusdb_zeroskip =
{
    "zeroskip",                  /* name */

    &cyrusdb_zeroskip_init,
    &cyrusdb_zeroskip_done,
    &cyrusdb_zeroskip_sync,
    &cyrusdb_zeroskip_archive,
    &cyrusdb_zeroskip_unlink,

    &cyrusdb_zeroskip_open,
    &cyrusdb_zeroskip_close,

    &cyrusdb_zeroskip_fetch,
    &cyrusdb_zeroskip_fetchlock,
    &cyrusdb_zeroskip_fetchnext,

    &cyrusdb_zeroskip_foreach,
    &cyrusdb_zeroskip_create,
    &cyrusdb_zeroskip_store,
    &cyrusdb_zeroskip_delete,

    NULL, /* lock */
    &cyrusdb_zeroskip_commit,
    &cyrusdb_zeroskip_abort,

    &cyrusdb_zeroskip_dump,
    &cyrusdb_zeroskip_consistent,
    &cyrusdb_zeroskip_checkpoint,
    &cyrusdb_zeroskip_compar
};

