/* search_xapian.c -- glue code for searching with Xapian
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
 */

#include <config.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <syslog.h>
#include <string.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <dirent.h>

#include "assert.h"
#include "bitvector.h"
#include "bloom.h"
#include "global.h"
#include "ptrarray.h"
#include "user.h"
#include "xmalloc.h"
#include "xstrlcpy.h"
#include "xstrlcat.h"
#include "mappedfile.h"
#include "mboxlist.h"
#include "mboxname.h"
#include "xstats.h"
#include "search_engines.h"
#include "sequence.h"
#include "cyr_lock.h"
#include "xapian_wrap.h"
#include "command.h"

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"

#define INDEXEDDB_VERSION       2
#define INDEXEDDB_FNAME         "/cyrus.indexed.db"
#define XAPIAN_DIRNAME          "/xapian"
#define ACTIVEFILE_METANAME     "xapianactive"
#define XAPIAN_NAME_LOCK_PREFIX "$XAPIAN$"

/* Name of columns */
#define COL_CYRUSID     "cyrusid"

struct segment
{
    int part;
    int sequence;       /* forces stable sort order JIC */
    int is_finished;
    struct buf text;
};

static const char *xapian_rootdir(const char *tier, const char *partition);
static int xapian_basedir(const char *tier, const char *mboxname, const char *part,
                          const char *root, char **basedir);

/* ====================================================================== */
static int check_config(void)
{
    int r = 0;
    const char *s;

    if (!config_getswitch(IMAPOPT_CONVERSATIONS)) {
        syslog(LOG_ERR, "ERROR: conversations required but not enabled");
        return IMAP_NOTFOUND;
    }
    s = config_getstring(IMAPOPT_DEFAULTSEARCHTIER);
    if (!s || !strlen(s)) {
        syslog(LOG_ERR, "ERROR: no default search tier configured");
        r = IMAP_PARTITION_UNKNOWN;
    }

    return r;
}

/* ====================================================================== */

/* the "activefile" file lists the tiers and generations of all the
 * currently active search databases.  The format is space separated
 * records tiername:generation, i.e. "meta:0".  If there is no file present,
 * it is created by finding all the existing search directories (from
 * filesystem inspection) and prepending default:nextgen where default
 * is the searchdefaulttier value and nextgen is one higher than the
 * largest generation found.  In the simplest configuration this is
 * just ":0" */

struct activeitem {
    char *tier;
    int generation;
};

enum LockType {
    AF_LOCK_READ = 0,
    AF_LOCK_WRITE = 1,
};

static struct activeitem *activeitem_parse(const char *input)
{
    struct activeitem *res = NULL;
    char *num = strrchr(input, ':');

    if (!num) return NULL;

    res = xzmalloc(sizeof(struct activeitem));
    res->tier = xstrndup(input, num-input);
    res->generation = atoi(num+1);

    return res;
}

static void activeitem_free(struct activeitem *item)
{
    if (!item) return;
    free(item->tier);
    free(item);
}

char *activeitem_generate(const char *tier, int generation)
{
    struct buf buf = BUF_INITIALIZER;
    char *ret;
    buf_printf(&buf, "%s:%d", tier, generation);
    ret = buf_release(&buf);
    buf_free(&buf);

    return ret;
}

/* calculate the next name for this tier, by incrementing the generation
 * to one higher than any existing active record */
static char *activefile_nextname(const strarray_t *active, const char *tier)
{
    int max = -1;
    int i;

    for (i = 0; i < active->count; i++) {
        struct activeitem *item = activeitem_parse(strarray_nth(active, i));
        if (item && !strcmp(item->tier, tier)) {
            if (item->generation > max)
                max = item->generation;
        }
        activeitem_free(item);
    }

    return activeitem_generate(tier, max+1);
}

/* filter a list of active records to only those in certain tiers.
 * Used to calculate which databases to use as sources for compression */
static strarray_t *activefile_filter(const strarray_t *active, const strarray_t *tiers, const char *partition)
{
    strarray_t *res = strarray_new();
    int i;

    for (i = 0; i < active->count; i++) {
        const char *name = strarray_nth(active, i);
        struct activeitem *item = activeitem_parse(name);
        /* we want to compress anything which can't possibly exist as well
         * as anything which matches the filter tiers */
        if (!item || strarray_find(tiers, item->tier, 0) >= 0
                  || strarray_find(tiers, name, 0) >= 0
                  || !xapian_rootdir(item->tier, partition))
            strarray_append(res, name);
        activeitem_free(item);
    }

    return res;
}

/* the activefile file is a per-user meta file */
static char *activefile_fname(const char *mboxname)
{
    char *userid = mboxname_to_userid(mboxname);
    if (!userid) return NULL;
    char *res = user_hash_meta(userid, ACTIVEFILE_METANAME);
    free(userid);
    return res;
}

/* file format is very simple */
static strarray_t *activefile_read(struct mappedfile *activefile)
{
    return strarray_nsplit(mappedfile_base(activefile), mappedfile_size(activefile), NULL, 1);
}

/* to write a activefile file safely, we need to do the create .NEW,
 * write, fsync, rename dance.  This unlocks the original file, so
 * callers will need to lock again if they need a locked file.
 * The 'mappedfile' API isn't a perfect match for what we need here,
 * but it's close enough, and avoids open coding the lock dance. */
static int activefile_write(struct mappedfile *mf, const strarray_t *new)
{
    char *newname = strconcat(mappedfile_fname(mf), ".NEW", (char *)NULL);
    struct mappedfile *newfile = NULL;
    int r;
    ssize_t nwritten;
    char *towrite = NULL;

    r = mappedfile_open(&newfile, newname, MAPPEDFILE_CREATE|MAPPEDFILE_RW);
    if (r) goto done;
    r = mappedfile_writelock(newfile);
    if (r) goto done;

    towrite = strarray_join(new, " ");
    nwritten = mappedfile_pwrite(newfile, towrite, strlen(towrite), 0);
    free(towrite);
    if (nwritten < 0) {
        /* commit anyway so mappedfile doesn't have kittens
         * about the map being closed dirty */
        r = IMAP_IOERROR;
        mappedfile_commit(newfile);
        goto done;
    }

    r = mappedfile_commit(newfile);
    if (r) goto done;

    r = mappedfile_rename(newfile, mappedfile_fname(mf));
    if (r) unlink(newname);

    /* we lose control over the lock here, so we have to release */
    mappedfile_unlock(mf);

done:
    if (newfile) {
        mappedfile_unlock(newfile);
        mappedfile_close(&newfile);
    }
    free(newname);

    return r;
}

/* if the mappedfile has no content, it needs to be initialised
 * with some dummy data.  Strictly it doesn't, but it makes
 * reasoning about everything else easier if there's always a
 * file */

static void inspect_filesystem(const char *mboxname, const char *partition,
                               strarray_t *found, strarray_t *bogus);

static void _activefile_init(const char *mboxname, const char *partition,
                             struct mappedfile *activefile)
{
    int r = mappedfile_writelock(activefile);
    const char *tier = config_getstring(IMAPOPT_DEFAULTSEARCHTIER);
    strarray_t *list = NULL;

    /* failed to lock, doh */
    if (r) return;

    /* did someone beat us to it? */
    if (mappedfile_size(activefile)) {
        mappedfile_unlock(activefile);
        return;
    }

    list = strarray_new();
    inspect_filesystem(mboxname, partition, list, NULL);
    /* always put the next item on the front so we don't write to any
     * existing databases */
    strarray_unshiftm(list, activefile_nextname(list, tier));

    activefile_write(activefile, list);

    strarray_free(list);
}

static strarray_t *activefile_open(const char *mboxname, const char *partition,
                                   struct mappedfile **activefile, enum LockType type)
{
    char *fname = activefile_fname(mboxname);
    int r;

    if (!fname) return NULL;

    /* try to open the file, and populate with initial values if it's empty */
    r = mappedfile_open(activefile, fname, MAPPEDFILE_CREATE|MAPPEDFILE_RW);
    if (!r && !mappedfile_size(*activefile))
        _activefile_init(mboxname, partition, *activefile);
    free(fname);

    if (r) return NULL;

    /* take the requested lock (a better helper API would allow this to be
     * specified as part of the open call, but here's where we are */
    if (type == AF_LOCK_WRITE) r = mappedfile_writelock(*activefile);
    else r = mappedfile_readlock(*activefile);
    if (r) return NULL;

    /* finally, read the contents */
    return activefile_read(*activefile);
}

static int xapstat(const char *path)
{
    struct stat sbuf;
    int r;

    /* is there a glass file? */
    char *glass = strconcat(path, "/iamglass", (char *)NULL);
    r = stat(glass, &sbuf);
    free(glass);

    /* zero byte file is the same as no database */
    if (!r && !sbuf.st_size) {
         r = -1;
         errno = ENOENT;
    }
    if (!r) return 0;

    /* check for old chert file */
    char *chert = strconcat(path, "/iamchert", (char *)NULL);
    r = stat(chert, &sbuf);
    free(chert);

    /* zero byte file is the same as no database */
    if (!r && !sbuf.st_size) {
         r = -1;
         errno = ENOENT;
    }

    return r;
}

/* given an item from the activefile file, and the mboxname and partition
 * to calculate the user, find the path.  If dostat is true, also stat the
 * path and return NULL if it doesn't exist (used for filtering databases
 * to actually search in */
static char *activefile_path(const char *mboxname, const char *part, const char *item, int dostat)
{
    char *basedir = NULL;
    struct buf buf = BUF_INITIALIZER;
    char *dest = NULL;
    struct activeitem *ai = activeitem_parse(item);

    xapian_basedir(ai->tier, mboxname, part, NULL, &basedir);
    if (!basedir) goto out;
    buf_printf(&buf, "%s%s", basedir, XAPIAN_DIRNAME);
    free(basedir);

    if (ai->generation)
        buf_printf(&buf, ".%d", ai->generation);

    dest = buf_release(&buf);

    if (dostat) {
        if (xapstat(dest)) {
            if (errno != ENOENT)
                syslog(LOG_ERR, "IOERROR: can't read %s for search, check permissions: %m", dest);
            free(dest);
            dest = NULL;
        }
    }

out:
    buf_free(&buf);
    activeitem_free(ai);
    return dest;
}

/* convert an array of activefile items to an array of database paths,
 * optionally stripping records where the path doesn't exist. If itemsptr
 * is not NULL, it stores the unparsed items for which database paths
 * exist in order and cardinality of the returned string array value.
 */
static strarray_t *activefile_resolve(const char *mboxname, const char *part,
                                      const strarray_t *items, int dostat,
                                      strarray_t **itemsptr)

{
    strarray_t *result = strarray_new();
    int i;

    if (itemsptr) {
        *itemsptr = strarray_new();
    }

    for (i = 0; i < items->count; i++) {
        int statthis = (dostat == 1 || (dostat == 2 && i));
        const char *item = strarray_nth(items, i);
        char *dir = activefile_path(mboxname, part, item, statthis);
        if (dir) {
            strarray_appendm(result, dir);
            if (itemsptr) {
                strarray_append(*itemsptr, item);
            }
        }
    }

    return result;
}

/* ====================================================================== */

/* the filesystem layout is inspectable - this is useful for a couple of
 * purposes - both rebuilding the activefile if it's lost, and also finding
 * stale "missing" directories after a successful rebuild */

struct inspectrock {
    const char *mboxname;
    const char *partition;
    strarray_t *found;
    strarray_t *bogus;
};

static void inspect_check(const char *key, const char *val __attribute__((unused)), void *rock)
{
    struct inspectrock *ir = (struct inspectrock *)rock;
    const char *match = strstr(key, "searchpartition-");
    char *basedir = NULL;
    char *tier = NULL;
    char *fname = NULL;
    DIR *dirh = NULL;
    struct dirent *de;
    bit64 generation;
    const char *rest;

    if (!match) goto out;
    tier = xstrndup(key, match - key);

    if (xapian_basedir(tier, ir->mboxname, ir->partition, NULL, &basedir))
        goto out;

    dirh = opendir(basedir);
    if (!dirh) goto out;

    while ((de = readdir(dirh))) {
        generation = 0;
        if (de->d_name[0] == '.') continue;
        free(fname);
        fname = strconcat(basedir, "/", de->d_name, (char *)NULL);
        /* only 'xapian' directories allowed */
        if (strncmp(de->d_name, "xapian", 6)) goto bogus;

        /* xapian by itself is tier zero */
        if (de->d_name[6]) {
            /* otherwise it's xapian.generation */
            if (de->d_name[6] != '.') goto bogus;

            /* unless it exactly matches digits, it's either got .NEW on the end or is
             * likewise bogus, track it */
            if (parsenum(de->d_name + 7, &rest, strlen(de->d_name)-7, &generation) || rest[0])
                goto bogus;
        }

        /* found one! */
        strarray_appendm(ir->found, activeitem_generate(tier, (int)generation));
        continue;

bogus:
        if (ir->bogus) {
            strarray_appendm(ir->bogus, fname);
            fname = NULL;
        }
    }

out:
    if (dirh) closedir(dirh);
    free(fname);
    free(basedir);
    free(tier);
}

static void inspect_filesystem(const char *mboxname, const char *partition,
                               strarray_t *found, strarray_t *bogus)
{
    struct inspectrock rock;

    rock.mboxname = mboxname;
    rock.partition = partition;
    rock.found = found;
    rock.bogus = bogus;

    config_foreachoverflowstring(inspect_check, &rock);
}

/* ====================================================================== */

/* The "indexed database" contains information about which cyrus messages
 * are indexed in this sphinx directory.  The keys are mailbox.uidvalidity
 * and the values are "version sequence", where sequence is an IMAP-style
 * sequence of UIDs.  This allows squatter to quickly determine which
 * messages are not yet indexed in any active database. */

/* parse both the old version 1 (just max UID rather than range) and
 * current version sequence from a mapped database value */
static struct seqset *parse_indexed(const char *data, size_t datalen)
{
    struct seqset *seq = NULL;
    const char *rest;
    bit64 version;
    char *val;

    if (parsenum(data, &rest, datalen, &version))
        return NULL;

    if (*rest++ != ' ')
        return NULL;

    switch(version) {
    case 1:
        {
            char buf[20];
            snprintf(buf, 20, "1:%.*s", (int)(datalen - (rest - data)), rest);
            return seqset_parse(buf, NULL, 0);
        }
    case 2:
        val = xstrndup(rest, datalen - (rest - data));
        seq = seqset_parse(val, NULL, 0);
        free(val);
        return seq;
    }

    return NULL;
}

static int tierexists_cb(void *rock, const char *key, size_t keylen,
                         const char *data __attribute__((unused)),
                         size_t datalen __attribute__((unused)))
{
    const int *verbose = rock;
    if (*verbose > 1) {
        syslog(LOG_INFO, "tierexists_cb: found tier key %.*s", (int) keylen, key);
    }
    return CYRUSDB_DONE;
}

struct cachetier_rock {
    struct buf *buf;
    struct db *dst_db;
    struct txn *txn;
};

static int cachetier_cb(void *rock, const char *key, size_t keylen,
                        const char *data, size_t datalen)
{
    if (*key == '#') {
        /* Ignore cache entries */
        return 0;
    }

    struct cachetier_rock *mr = rock;
    size_t prefix_len = buf_len(mr->buf);
    int r = 0;

    buf_appendmap(mr->buf, key, keylen);
    r = cyrusdb_store(mr->dst_db, buf_base(mr->buf), buf_len(mr->buf),
                      data, datalen, &mr->txn);
    buf_truncate(mr->buf, prefix_len);
    if (r) {
        syslog(LOG_ERR, "cachetier_cb: could not save key %.*s for tier %s: %s",
                (int) keylen, key, buf_cstring(mr->buf), cyrusdb_strerror(r));
    }
    return r;
}

/*
 * Merge the indexed.db of all search tiers activetiers[1..n] into the
 * indexed.db of the top tier.
 *
 * Any entries in indexed.dbs located at activedirs[1..n] are cached into
 * the indexed.db located at activedirs[0] (created if not exists), using
 * a special prefix:
 *
 * The keys from merged entries are formatted as
 *
 *     '#c'.<tiername:tiergen>'#'<key>
 *
 * and any keys starting with '#' are ignored during the merge.
 *
 * Returns 0 on success or a cyrusdb error code.
 */
static int cache_indexed(const strarray_t *activedirs,
                         const strarray_t *activetiers,
                         int verbose)
{
    struct db *src_db = NULL;
    struct db *dst_db = NULL;
    struct buf path = BUF_INITIALIZER;
    struct buf key = BUF_INITIALIZER;
    int r = 0;
    int i;

    assert(activedirs->count == activetiers->count);

    if (!activedirs->count) {
        return 0;
    }

    /* Open destination database */
    buf_printf(&path, "%s%s", strarray_nth(activedirs, 0), INDEXEDDB_FNAME);
    r = cyrusdb_open(config_getstring(IMAPOPT_SEARCH_INDEXED_DB),
                     buf_cstring(&path), CYRUSDB_CREATE, &dst_db);
    if (r) {
        syslog(LOG_ERR, "cache_indexed: can't open destination db %s: %s",
                buf_cstring(&path), cyrusdb_strerror(r));
        goto out;
    }

    for (i = 1; i < activedirs->count; i++) {
        /* Reset state */
        if (src_db) {
            cyrusdb_close(src_db);
        }
        src_db = NULL;
        buf_reset(&path);
        buf_reset(&key);

        /* Check if the tier is already merged. We assume a tier is merged
         * if at least one entry with its tier prefix exists. */
        buf_printf(&key, "#c.%s#", strarray_nth(activetiers, i));
        r = cyrusdb_foreach(dst_db, buf_base(&key), buf_len(&key),
                            NULL, tierexists_cb, &verbose, NULL);
        if (r == CYRUSDB_DONE) {
            if (verbose) {
                syslog(LOG_INFO, "cache_indexed: tier %s is already merged",
                       strarray_nth(activetiers, i));
            }
            r = 0;
            continue;
        }
        else if (r) goto out;

        /* Open source database */
        buf_printf(&path, "%s%s", strarray_nth(activedirs, i), INDEXEDDB_FNAME);
        r = cyrusdb_open(config_getstring(IMAPOPT_SEARCH_INDEXED_DB),
                         buf_cstring(&path), 0, &src_db);
        if (r == CYRUSDB_NOTFOUND) {
            if (verbose) {
                syslog(LOG_INFO, "cache_indexed: no db found at %s",
                       buf_cstring(&path));
            }
            r = 0;
            continue;
        }
        else if (r) goto out;

        /* Merge the entries from source into destination. The first
         * store in the callback will create a write transaction. */
        struct cachetier_rock rock = { &key, dst_db, NULL };
        r = cyrusdb_foreach(src_db, NULL, 0, NULL, cachetier_cb, &rock, NULL);
        cyrusdb_close(src_db);
        src_db = NULL;
        if (r) {
            cyrusdb_abort(dst_db, rock.txn);
            goto out;
        }
        cyrusdb_commit(dst_db, rock.txn);
    }

out:
    if (dst_db) {
        cyrusdb_close(dst_db);
    }
    if (src_db) {
        cyrusdb_close(src_db);
    }
    buf_free(&key);
    buf_free(&path);

    return r;
}

/*
 * Read the indexed UIDs sequence for mailbox mboxname
 * from the activetiers located at activedirs and join
 * them into a single result res.
 *
 * If do_cache is true, any activetiers[1..n] that are not
 * already cached in the top tier (activetiers[0]) are
 * cached before looking up their sequence sets in the
 * cache. Caller must guarantee an exlusive write lock on
 * activetier[0].
 *
 * If do_cache is zero, the sequence sets are constructed
 * by looking up first any already cached indexes in the
 * top tier, followed by looking up entries in any non-
 * cached activetiers[1..n]. Since no writes are done,
 * this operation is safe without exclusively locking
 * the top tier.
 *
 * Returns 0 on success or a cyrusdb error code.
 */
static int read_indexed(const strarray_t *activedirs,
                       const strarray_t *activetiers,
                       const char *mboxname,
                       uint32_t uidvalidity,
                       struct seqset *res,
                       int do_cache,
                       int verbose)
{
    struct db *db = NULL;
    struct db *srcdb = NULL;
    struct buf path = BUF_INITIALIZER;
    struct buf key = BUF_INITIALIZER;
    const char *data = NULL;
    size_t datalen = 0;
    int r = 0;
    int i;

    assert(activedirs->count == activetiers->count);

    if (!activedirs->count) {
        return 0;
    }

    if (do_cache) {
        /* Merge search tiers first */
        r = cache_indexed(activedirs, activetiers, verbose);
        if (r) return r;
    }

    /* Open database */
    buf_printf(&path, "%s%s", strarray_nth(activedirs, 0), INDEXEDDB_FNAME);
    r = cyrusdb_open(config_getstring(IMAPOPT_SEARCH_INDEXED_DB),
                     buf_cstring(&path), CYRUSDB_CREATE, &db);
    if (r) {
        syslog(LOG_ERR, "read_indexed: can't open db %s: %s",
                buf_cstring(&path), cyrusdb_strerror(r));
        goto out;
    }

    /* Lookup entry in top tier */
    buf_printf(&key, "%s.%u", mboxname, uidvalidity);
    r = cyrusdb_fetch(db, key.s, key.len, &data, &datalen, (struct txn **)NULL);
    if (r && r != CYRUSDB_NOTFOUND) {
        goto out;
    }
    else if (!r) {
        struct seqset *seq = parse_indexed(data, datalen);
        if (seq) {
            seqset_join(res, seq);
            seqset_free(seq);
            if (verbose > 1) {
                syslog(LOG_INFO, "read_indexed: top tier seq=%.*s", (int)datalen, data);
            }
        }
    }
    r = 0;

    /* Lookup entries from lower tiers */
    for (i = 1; i < activedirs->count; i++) {
        buf_reset(&key);
        if (srcdb) {
            cyrusdb_close(srcdb);
            srcdb = NULL;
        }

        /* First look in the cached tiers in the top tier database. */
        buf_printf(&key, "#c.%s#%s.%u", strarray_nth(activetiers, i), mboxname, uidvalidity);
        r = cyrusdb_fetch(db, key.s, key.len, &data, &datalen, (struct txn **)NULL);

        /* Fall back to the lower tiers if we haven't merged all tiers. */
        if (r == CYRUSDB_NOTFOUND && !do_cache) {
            buf_reset(&path);
            buf_printf(&path, "%s%s", strarray_nth(activedirs, i), INDEXEDDB_FNAME);
            r = cyrusdb_open(config_getstring(IMAPOPT_SEARCH_INDEXED_DB),
                             buf_cstring(&path), 0, &srcdb);
            if (r) {
                syslog(LOG_ERR, "read_indexed: can't open db %s: %s",
                        buf_cstring(&path), cyrusdb_strerror(r));
                goto out;
            }
            buf_reset(&key);
            buf_printf(&key, "%s.%u", mboxname, uidvalidity);
            r = cyrusdb_fetch(srcdb, key.s, key.len, &data, &datalen, (struct txn **)NULL);
        }
        if (r && r != CYRUSDB_NOTFOUND) {
            goto out;
        }

        /* No entry found */
        if (r == CYRUSDB_NOTFOUND) {
            r = 0;
            continue;
        }

        /* Parse and join the sequence sets */
        struct seqset *seq = parse_indexed(data, datalen);
        if (seq) {
            seqset_join(res, seq);
            seqset_free(seq);
            if (verbose > 1) {
                syslog(LOG_INFO, "read_indexed: tier %s seq=%.*s",
                        strarray_nth(activetiers, i), (int)datalen, data);
            }
        }
    }

out:
    if (db) {
        cyrusdb_close(db);
    }
    if (srcdb) {
        cyrusdb_close(srcdb);
    }
    buf_free(&key);
    buf_free(&path);

    return r;
}

/* store the given sequence into the already opened cyrus db
 * with the given key.  If there is an existing sequence in
 * the DB, then join this sequence to it, so incremental
 * indexing does what you would expect. */
static int store_indexed(struct db *db, struct txn **tid,
                         const char *key, size_t keylen,
                         const struct seqset *val)
{
    struct buf data = BUF_INITIALIZER;
    char *str = NULL;
    int r;
    const char *olddata = NULL;
    size_t oldlen = 0;

    r = cyrusdb_fetch(db, key, keylen, &olddata, &oldlen, tid);
    if (r == CYRUSDB_NOTFOUND) {
        str = seqset_cstring(val);
    }
    else if (r) return r;
    else {
        struct seqset *seq = parse_indexed(olddata, oldlen);
        if (seq) {
            seqset_join(seq, val);
            str = seqset_cstring(seq);
            seqset_free(seq);
        }
        else {
            str = seqset_cstring(val);
        }
    }

    if (!str) return 0;

    buf_printf(&data, "%u %s", INDEXEDDB_VERSION, str);
    r = cyrusdb_store(db, key, keylen, data.s, data.len, tid);
    buf_free(&data);
    free(str);

    return r;
}

/* Given the directory of a xapian database which has just had
 * messages indexed into it, add the sequence of UIDs to the
 * record for the given mailbox and uidvalidity */
static int write_indexed(const char *dir,
                         const char *mboxname,
                         uint32_t uidvalidity,
                         struct seqset *seq,
                         int verbose)
{
    struct buf path = BUF_INITIALIZER;
    struct buf key = BUF_INITIALIZER;
    struct db *db = NULL;
    struct txn *txn = NULL;
    int r = 0;

    buf_reset(&path);
    buf_printf(&path, "%s%s", dir, INDEXEDDB_FNAME);

    if (verbose) {
        char *str = seqset_cstring(seq);
        syslog(LOG_INFO, "write_indexed db=%s mailbox=%s uidvalidity=%u uids=%s",
               buf_cstring(&path), mboxname, uidvalidity, str);
        free(str);
    }

    buf_printf(&key, "%s.%u", mboxname, uidvalidity);

    r = cyrusdb_open(config_getstring(IMAPOPT_SEARCH_INDEXED_DB),
                     buf_cstring(&path), CYRUSDB_CREATE, &db);
    if (r) goto out;

    r = store_indexed(db, &txn, key.s, key.len, seq);
    if (!r)
        r = cyrusdb_commit(db, txn);
    else
        cyrusdb_abort(db, txn);

out:
    if (db) cyrusdb_close(db);
    buf_free(&path);
    buf_free(&key);
    return r;
}

/* ====================================================================== */

/* FIXME remove when legacy cyrusid are deprecated */
static int parse_legacy_cyrusid(const char *cyrusid,
                                const char **mboxnamep,
                                unsigned int *uidvalidityp,
                                unsigned int *uidp)
{
    // user.cassandane.1320711192.196715
    static struct buf buf = BUF_INITIALIZER;
    char *p;

    buf_reset(&buf);
    buf_appendcstr(&buf, cyrusid);

    p = strrchr(buf_cstring(&buf), '.');
    if (!p)
        return 0;
    *p++ = '\0';
    *uidp = strtoul(p, NULL, 10);

    p = strrchr(buf.s, '.');
    if (!p)
        return 0;
    *p++ = '\0';
    *uidvalidityp = strtoul(p, NULL, 10);

    *mboxnamep = buf.s;

    return 1;
}

static const char *make_cyrusid(const struct message_guid *guid)
{
    static struct buf buf = BUF_INITIALIZER;
    // *G*<encoded message guid>
    buf_setcstr(&buf, "*G*");
    buf_appendcstr(&buf, message_guid_encode(guid));
    return buf_cstring(&buf);
}

/* XXX - replace with cyrus_mkdir and cyrus_copyfile */
static void remove_dir(const char *dir)
{
    run_command("/bin/rm", "-rf", dir, (char *)NULL);
}

static int copy_files(const char *fromdir, const char *todir)
{
    char *fromdir2 = strconcat(fromdir, "/", (char *)NULL);
    int r = run_command("/usr/bin/rsync", "-a", fromdir2, todir, (char *)NULL);

    free(fromdir2);
    return r;
}

/* ====================================================================== */

struct opnode
{
    int op;     /* SEARCH_OP_* or SEARCH_PART_* constant */
    char *arg;
    struct opnode *next;
    struct opnode *children;
};

typedef struct xapian_builder xapian_builder_t;
struct xapian_builder {
    search_builder_t super;
    struct mappedfile *activefile;
    struct mboxlock *xapiandb_namelock;
    struct seqset *indexed;
    struct mailbox *mailbox;
    xapian_db_t *db;
    int opts;
    struct opnode *root;
    ptrarray_t stack;       /* points to opnode* */
    int (*proc)(const char *, uint32_t, uint32_t, void *);
    void *rock;
};

static struct opnode *opnode_new(int op, const char *arg)
{
    struct opnode *on = xzmalloc(sizeof(struct opnode));
    on->op = op;
    on->arg = xstrdupnull(arg);
    return on;
}

static void opnode_delete(struct opnode *on)
{
    struct opnode *child;
    struct opnode *next;

    for (child = on->children ; child ; child = next) {
        next = child->next;
        opnode_delete(child);
    }
    free(on->arg);
    free(on);
}

static void opnode_detach_child(struct opnode *parent, struct opnode *child)
{
    struct opnode **prevp;

    for (prevp = &parent->children ; *prevp ; prevp = &((*prevp)->next)) {
        if (*prevp == child) {
            *prevp = child->next;
            child->next = NULL;
            return;
        }
    }
}

static void opnode_append_child(struct opnode *parent, struct opnode *child)
{
    struct opnode **tailp;

    for (tailp = &parent->children ; *tailp ; tailp = &((*tailp)->next))
        ;
    *tailp = child;
    child->next = NULL;
}

static void opnode_insert_child(struct opnode *parent __attribute__((unused)),
                                struct opnode *after,
                                struct opnode *child)
{
    child->next = after->next;
    after->next = child;
}

static void optimise_nodes(struct opnode *parent, struct opnode *on)
{
    struct opnode *child;
    struct opnode *next;

    switch (on->op) {
    case SEARCH_OP_NOT:
    case SEARCH_OP_OR:
    case SEARCH_OP_AND:
        for (child = on->children ; child ; child = next) {
            next = child->next;
            optimise_nodes(on, child);
        }
        if (parent) {
            if (!on->children) {
                /* empty node - remove it */
                opnode_detach_child(parent, on);
                opnode_delete(on);
            }
            else if (on->op != SEARCH_OP_NOT && !on->children->next) {
                /* logical AND or OR with only one child - replace
                 * the node with its child */
                struct opnode *child = on->children;
                opnode_detach_child(on, child);
                opnode_insert_child(parent, on, child);
                opnode_detach_child(parent, on);
                opnode_delete(on);
            }
        }
        break;
    }
}

static xapian_query_t *opnode_to_query(const xapian_db_t *db, struct opnode *on)
{
    struct opnode *child;
    xapian_query_t *qq = NULL;
    int i;
    ptrarray_t childqueries = PTRARRAY_INITIALIZER;

    switch (on->op) {
    case SEARCH_OP_NOT:
        if (on->children)
            qq = xapian_query_new_not(db, opnode_to_query(db, on->children));
        break;
    case SEARCH_OP_OR:
    case SEARCH_OP_AND:
        for (child = on->children ; child ; child = child->next) {
            qq = opnode_to_query(db, child);
            if (qq) ptrarray_push(&childqueries, qq);
        }
        qq = NULL;
        if (childqueries.count)
            qq = xapian_query_new_compound(db, (on->op == SEARCH_OP_OR),
                                           (xapian_query_t **)childqueries.data,
                                           childqueries.count);
        break;
    case SEARCH_PART_ANY:
        /* Xapian does not have a convenient way of search for "any
         * field"; instead we fake it by explicitly searching for
         * all of the available prefixes */
        for (i = 0 ; i < SEARCH_NUM_PARTS ; i++) {
            void *q = xapian_query_new_match(db, i, on->arg);
            if (q) ptrarray_push(&childqueries, q);
        }
        qq = xapian_query_new_compound(db, /*is_or*/1,
                                       (xapian_query_t **)childqueries.data,
                                       childqueries.count);
        break;
    default:
        assert(on->arg != NULL);
        assert(on->children == NULL);
        qq = xapian_query_new_match(db, on->op, on->arg);
        break;
    }
    ptrarray_fini(&childqueries);
    return qq;
}

static int xapian_run_guid_cb(const conv_guidrec_t *rec, void *rock)
{
    xapian_builder_t *bb = (xapian_builder_t *)rock;

    /* we only want full message matches here */
    if (rec->part) return 0;

    if (!(bb->opts & SEARCH_MULTIPLE)) {
        if (strcmp(rec->mboxname, bb->mailbox->name))
            return 0;
    }

    return bb->proc(rec->mboxname, /*uidvalidity*/0, rec->uid, bb->rock);
}

static int xapian_run_cb(const char *cyrusid, void *rock)
{
    xapian_builder_t *bb = (xapian_builder_t *)rock;

    int r = cmd_cancelled();
    if (r) return r;

    if (!strncmp(cyrusid, "*G*", 3)) {
        /* Current cyrus ids: *G*<encoded message guid> */
        struct conversations_state *cstate;
        const char *guid = cyrusid + 3;

        cstate = mailbox_get_cstate(bb->mailbox);
        if (!cstate) {
            syslog(LOG_INFO, "search_xapian: can't open conversations for %s",
                    bb->mailbox->name);
            return IMAP_NOTFOUND;
        }

        r = conversations_guid_foreach(cstate, guid, xapian_run_guid_cb, bb);
        return r;

    } else {
        /* FIXME remove block when legacy cyrusid are deprecated */
        /* Legacy cyrus ids: user.cassandane.1320711192.196715 */
        const char *mboxname;
        unsigned int uidvalidity;
        unsigned int uid;

        r = parse_legacy_cyrusid(cyrusid, &mboxname, &uidvalidity, &uid);
        if (!r) {
            syslog(LOG_ERR, "IOERROR: Cannot parse \"%s\" as cyrusid", cyrusid);
            return IMAP_IOERROR;
        }

        if (!(bb->opts & SEARCH_MULTIPLE)) {
            if (strcmp(mboxname, bb->mailbox->name))
                return 0;
            if (uidvalidity != bb->mailbox->i.uidvalidity)
                return 0;
        }

        r = bb->proc(mboxname, uidvalidity, uid, bb->rock);
        return r;
    }
}

static int run(search_builder_t *bx, search_hit_cb_t proc, void *rock)
{
    xapian_builder_t *bb = (xapian_builder_t *)bx;
    xapian_query_t *qq = NULL;
    int r = 0;

    if (bb->db == NULL) {
        syslog(LOG_ERR, "search_xapian: can't find index for mailbox: %s",
                bb->mailbox ?  bb->mailbox->name : "<unknown>");
        return IMAP_NOTFOUND;       /* there's no index for this user */
    }

    /* Validate config */
    r = check_config();
    if (r) return r;

    optimise_nodes(NULL, bb->root);
    qq = opnode_to_query(bb->db, bb->root);
    if (!qq) goto out;

    bb->proc = proc;
    bb->rock = rock;

    r = xapian_query_run(bb->db, qq, xapian_run_cb, bb);
    if (r) goto out;

    /* add in the unindexed uids as false positives */
    if ((bb->opts & SEARCH_UNINDEXED)) {
        uint32_t uid;
        for (uid = seqset_firstnonmember(bb->indexed);
             uid <= bb->mailbox->i.last_uid ; uid++) {
            r = proc(bb->mailbox->name, bb->mailbox->i.uidvalidity, uid, rock);
            if (r) goto out;
        }
    }

out:
    if (qq) xapian_query_free(qq);
    return r;
}

static void begin_boolean(search_builder_t *bx, int op)
{
    xapian_builder_t *bb = (xapian_builder_t *)bx;
    struct opnode *top = ptrarray_tail(&bb->stack);
    struct opnode *on = opnode_new(op, NULL);
    if (top)
        opnode_append_child(top, on);
    else
        bb->root = on;
    ptrarray_push(&bb->stack, on);
    if (SEARCH_VERBOSE(bb->opts))
        syslog(LOG_INFO, "begin_boolean(op=%s)", search_op_as_string(op));
}

static void end_boolean(search_builder_t *bx, int op __attribute__((unused)))
{
    xapian_builder_t *bb = (xapian_builder_t *)bx;
    if (SEARCH_VERBOSE(bb->opts))
        syslog(LOG_INFO, "end_boolean");
    ptrarray_pop(&bb->stack);
}

static void match(search_builder_t *bx, int part, const char *str)
{
    xapian_builder_t *bb = (xapian_builder_t *)bx;
    struct opnode *top = ptrarray_tail(&bb->stack);
    struct opnode *on;

    if (!str) return;
    if (SEARCH_VERBOSE(bb->opts))
        syslog(LOG_INFO, "match(part=%s, str=\"%s\")",
               search_part_as_string(part), str);

    on = opnode_new(part, str);
    if (top)
        opnode_append_child(top, on);
    else
        bb->root = on;
}

static void *get_internalised(search_builder_t *bx)
{
    xapian_builder_t *bb = (xapian_builder_t *)bx;
    struct opnode *on = bb->root;
    bb->root = NULL;
    optimise_nodes(NULL, on);
    return on;
}

static char *describe_internalised(void *internalised __attribute__((unused)))
{
    return xstrdup("--xapian query--");
}

static void free_internalised(void *internalised)
{
    struct opnode *on = (struct opnode *)internalised;
    if (on) opnode_delete(on);
}

/*
 * This function builds a lockfilename of the format:
 *  $XAPIAN$<userid>
 * example:
 *  If the userid is `foo@bar.com` then the lockfilename is
 *  $XAPIAN$foo@bar^com
 *
 * It replaces '.' in a string with a '^' into a struct buf
 */
static char *xapiandb_namelock_fname_from_userid(const char *userid)
{
    const char *p;
    struct buf buf = BUF_INITIALIZER;

    buf_setcstr(&buf, XAPIAN_NAME_LOCK_PREFIX);

    for (p = userid; *p; p++) {
        switch(*p) {
        case '.':
            buf_putc(&buf, '^');
            break;
        default:
            buf_putc(&buf, *p);
            break;
        }
    }

    char *ret = buf_release(&buf);

    buf_free(&buf);

    return ret;
}

static search_builder_t *begin_search(struct mailbox *mailbox, int opts)
{
    int r = check_config();
    if (r) return NULL;

    xapian_builder_t *bb;
    strarray_t *dirs = NULL;
    strarray_t *tiers = NULL;
    strarray_t *active = NULL;
    char *namelock_fname = NULL;
    char *userid = NULL;

    bb = xzmalloc(sizeof(xapian_builder_t));
    bb->super.begin_boolean = begin_boolean;
    bb->super.end_boolean = end_boolean;
    bb->super.match = match;
    bb->super.get_internalised = get_internalised;
    bb->super.run = run;

    bb->mailbox = mailbox;
    bb->opts = opts;

    /* Do nothing if there is no userid */
    userid = mboxname_to_userid(mailbox->name);
    if (!userid) goto out;

    namelock_fname = xapiandb_namelock_fname_from_userid(userid);

    /* Get a shared lock */
    r = mboxname_lock(namelock_fname, &bb->xapiandb_namelock, LOCK_SHARED);
    if (r) {
        syslog(LOG_ERR, "Could not acquire shared namelock on %s\n",
               namelock_fname);
        goto out;
    }

    /* need to hold a read-only lock on the activefile file until the search
     * has completed to ensure no databases are deleted out from under us */
    active = activefile_open(mailbox->name, mailbox->part, &bb->activefile, AF_LOCK_READ);
    if (!active) goto out;

    /* only try to open directories with databases in them */
    dirs = activefile_resolve(mailbox->name, mailbox->part, active, /*dostat*/1, &tiers);
    if (!dirs || !dirs->count) goto out;

    /* if there are directories, open the databases */
    r = xapian_db_open((const char **)dirs->data, &bb->db);
    if (r) goto out;

    /* read the list of all indexed messages to allow (optional) false positives
     * for unindexed messages */
    bb->indexed = seqset_init(0, SEQ_MERGE);
    r = read_indexed(dirs, tiers, mailbox->name, mailbox->i.uidvalidity, bb->indexed,
                    /*do_cache*/0, /*verbose*/0);
    if (r) goto out;

out:
    strarray_free(dirs);
    strarray_free(tiers);
    strarray_free(active);
    free(namelock_fname);
    free(userid);
    /* XXX - error return? */
    return &bb->super;
}

static void end_search(search_builder_t *bx)
{
    xapian_builder_t *bb = (xapian_builder_t *)bx;

    seqset_free(bb->indexed);
    ptrarray_fini(&bb->stack);
    if (bb->root) opnode_delete(bb->root);

    if (bb->db) xapian_db_close(bb->db);

    /* now that the databases are closed, it's safe to unlock
     * the active file */
    if (bb->activefile) {
        mappedfile_unlock(bb->activefile);
        mappedfile_close(&bb->activefile);
    }

    if (bb->xapiandb_namelock) {
        mboxname_release(&bb->xapiandb_namelock);
        bb->xapiandb_namelock = NULL;
    }

    free(bx);
}

/* ====================================================================== */

/* base class for both update and snippet receivers */
typedef struct xapian_receiver xapian_receiver_t;
struct xapian_receiver
{
    search_text_receiver_t super;
    int verbose;
    struct mailbox *mailbox;
    struct message_guid guid;
    uint32_t uid;
    int part;
    unsigned int parts_total;
    int truncate_warning;
    ptrarray_t segs;
};

/* receiver used for updating the index */
typedef struct xapian_update_receiver xapian_update_receiver_t;
struct xapian_update_receiver
{
    xapian_receiver_t super;
    xapian_dbw_t *dbw;
    struct mappedfile *activefile;
    struct mboxlock *xapiandb_namelock;
    unsigned int uncommitted;
    unsigned int commits;
    struct seqset *oldindexed;
    struct seqset *indexed;
    strarray_t *activedirs;
    strarray_t *activetiers;
    hash_table cached_seqs;
    int mode;
};

/* receiver used for extracting snippets after a search */
typedef struct xapian_snippet_receiver xapian_snippet_receiver_t;
struct xapian_snippet_receiver
{
    xapian_receiver_t super;
    xapian_snipgen_t *snipgen;
    struct opnode *root;
    search_snippet_cb_t proc;
    void *rock;
};

/* Maximum size of a query, determined empirically, is a little bit
 * under 8MB.  That seems like more than enough, so let's limit the
 * total amount of parts text to 4 MB. */
#define MAX_PARTS_SIZE      (4*1024*1024)

static const char *xapian_rootdir(const char *tier, const char *partition)
{
    char *confkey;
    const char *root;

    if (!partition) {
        partition = config_getstring(IMAPOPT_DEFAULTPARTITION);
        if (!partition) {
            syslog(LOG_ERR, "no default partition configured");
            return NULL;
        }
    }
    confkey = strconcat(tier, "searchpartition-", partition, NULL);
    root = config_getoverflowstring(confkey, NULL);
    if (!root) {
        syslog(LOG_ERR, "undefined search partition: %s", confkey);
    }
    free(confkey);
    return root;
}

/* Returns in *basedirp a new string which must be free()d */
static int xapian_basedir(const char *tier,
                          const char *mboxname, const char *partition,
                          const char *root, char **basedirp)
{
    char *basedir = NULL;
    mbname_t *mbname = NULL;
    char c[2], d[2];
    int r;

    if (!root)
        root = xapian_rootdir(tier, partition);
    if (!root) {
        r = IMAP_PARTITION_UNKNOWN;
        goto out;
    }

    mbname = mbname_from_intname(mboxname);
    if (!mbname_userid(mbname)) {
        r = IMAP_PARTITION_UNKNOWN;
        goto out;
    }

    const char *domain = mbname_domain(mbname);
    const char *localpart = mbname_localpart(mbname);

    if (domain)
        basedir = strconcat(root,
                            FNAME_DOMAINDIR,
                            dir_hash_b(domain, config_fulldirhash, d),
                            "/", domain,
                            "/", dir_hash_b(localpart, config_fulldirhash, c),
                            FNAME_USERDIR,
                            localpart,
                            (char *)NULL);
    else
        basedir = strconcat(root,
                            "/", dir_hash_b(localpart, config_fulldirhash, c),
                            FNAME_USERDIR,
                            localpart,
                            (char *)NULL);

    r = 0;

out:
    if (!r && basedirp)
        *basedirp = basedir;
    else
        free(basedir);
    mbname_free(&mbname);
    return r;
}

static int check_directory(const char *dir, int verbose, int create)
{
    int r;
    char *dummyfile = NULL;
    struct stat sb;

    r = stat(dir, &sb);
    if (r < 0) {
        if (errno != ENOENT) {
            /* something went wrong - permissions problem most likely */
            syslog(LOG_ERR, "IOERROR: unable to stat %s: %m", dir);
            r = IMAP_IOERROR;
            goto out;
        }
        /* the directory is just missing */
        if (!create) {
            /* caller doesn't care that much */
            r = IMAP_NOTFOUND;
            goto out;
        }
        if (verbose)
            syslog(LOG_INFO, "Building directory %s", dir);
        dummyfile = strconcat(dir, "/dummy", (char *)NULL);
        cyrus_mkdir(dummyfile, 0700);
        r = stat(dir, &sb);
        if (r < 0) {
            /* something went wrong - permissions problem most likely */
            syslog(LOG_ERR, "IOERROR: unable to stat %s: %m", dir);
            r = IMAP_IOERROR;
            goto out;
        }
    }

out:
    free(dummyfile);
    return r;
}

static int flush(search_text_receiver_t *rx)
{
    xapian_update_receiver_t *tr = (xapian_update_receiver_t *)rx;
    int r = 0;
    struct timeval start, end;

    if (tr->uncommitted) {
        assert(tr->dbw);

        gettimeofday(&start, NULL);
        r = xapian_dbw_commit_txn(tr->dbw);
        if (r) goto out;
        gettimeofday(&end, NULL);

        syslog(LOG_INFO, "Xapian committed %u updates in %.6f sec",
                    tr->uncommitted, timesub(&start, &end));

        tr->uncommitted = 0;
        tr->commits++;
    }

    /* We write out the indexed list for the mailbox only after successfully
     * updating the index, to avoid a future instance not realising that
     * there are unindexed messages should we fail to index */
    if (tr->indexed) {
        r = write_indexed(strarray_nth(tr->activedirs, 0),
                          tr->super.mailbox->name, tr->super.mailbox->i.uidvalidity,
                          tr->indexed, tr->super.verbose);
        if (r) goto out;
    }

out:
    return r;
}

static void free_segments(xapian_receiver_t *tr)
{
    int i;
    struct segment *seg;

    for (i = 0 ; i < tr->segs.count ; i++) {
        seg = (struct segment *)ptrarray_nth(&tr->segs, i);
        buf_free(&seg->text);
        free(seg);
    }
    ptrarray_truncate(&tr->segs, 0);
}

static int begin_message(search_text_receiver_t *rx, message_t *msg)
{
    xapian_update_receiver_t *tr = (xapian_update_receiver_t *)rx;

    uint32_t uid = 0;
    const struct message_guid *guid = NULL;
    message_get_uid(msg, &uid);
    message_get_guid(msg, &guid);

    tr->super.uid = uid;
    message_guid_copy(&tr->super.guid, guid);
    free_segments((xapian_receiver_t *)tr);
    tr->super.parts_total = 0;
    tr->super.truncate_warning = 0;
    return 0;
}

static void begin_part(search_text_receiver_t *rx, int part)
{
    xapian_receiver_t *tr = (xapian_receiver_t *)rx;

    tr->part = part;
}

static void append_text(search_text_receiver_t *rx,
                        const struct buf *text)
{
    xapian_receiver_t *tr = (xapian_receiver_t *)rx;
    struct segment *seg;

    if (tr->part) {
        unsigned len = text->len;
        if (tr->parts_total + len > MAX_PARTS_SIZE) {
            if (!tr->truncate_warning++)
                syslog(LOG_ERR, "Xapian: truncating text from "
                                "message mailbox %s uid %u",
                                tr->mailbox->name, tr->uid);
            len = MAX_PARTS_SIZE - tr->parts_total;
        }
        if (len) {
            tr->parts_total += len;

            seg = (struct segment *)ptrarray_tail(&tr->segs);
            if (!seg || seg->is_finished || seg->part != tr->part) {
                seg = (struct segment *)xzmalloc(sizeof(*seg));
                seg->sequence = tr->segs.count;
                seg->part = tr->part;
                ptrarray_append(&tr->segs, seg);
            }
            buf_appendmap(&seg->text, text->s, len);
        }
    }
}

static void end_part(search_text_receiver_t *rx,
                     int part __attribute__((unused)))
{
    xapian_receiver_t *tr = (xapian_receiver_t *)rx;
    struct segment *seg;

    seg = (struct segment *)ptrarray_tail(&tr->segs);
    if (seg)
        seg->is_finished = 1;

    if (tr->verbose > 1)
        syslog(LOG_NOTICE, "Xapian: %llu bytes in part %s",
               (seg ? (unsigned long long)seg->text.len : 0),
               search_part_as_string(tr->part));

    tr->part = 0;
}

static int compare_segs(const void **v1, const void **v2)
{
    const struct segment *s1 = *(const struct segment **)v1;
    const struct segment *s2 = *(const struct segment **)v2;
    int r;

    r = s1->part - s2->part;
    if (!r)
        r = s1->sequence - s2->sequence;
    return r;
}

static int end_message_update(search_text_receiver_t *rx)
{
    xapian_update_receiver_t *tr = (xapian_update_receiver_t *)rx;
    int i;
    struct segment *seg;
    int r = 0;

    if (!tr->dbw) {
        r = xapian_dbw_open((const char **)tr->activedirs->data, &tr->dbw, tr->mode);
        if (r) goto out;
    }

    r = xapian_dbw_begin_doc(tr->dbw, make_cyrusid(&tr->super.guid));
    if (r) goto out;

    ptrarray_sort(&tr->super.segs, compare_segs);

    for (i = 0 ; i < tr->super.segs.count ; i++) {
        seg = (struct segment *)ptrarray_nth(&tr->super.segs, i);
        r = xapian_dbw_doc_part(tr->dbw, &seg->text, seg->part);
        if (r) goto out;
    }

    if (!tr->uncommitted) {
        r = xapian_dbw_begin_txn(tr->dbw);
        if (r) goto out;
    }
    r = xapian_dbw_end_doc(tr->dbw);
    if (r) goto out;

    ++tr->uncommitted;

out:
    tr->super.uid = 0;
    message_guid_set_null(&tr->super.guid);
    return r;
}

static int begin_mailbox_update(search_text_receiver_t *rx,
                                struct mailbox *mailbox,
                                int flags)
{
    xapian_update_receiver_t *tr = (xapian_update_receiver_t *)rx;
    char *fname = activefile_fname(mailbox->name);
    strarray_t *active = NULL;
    int r = IMAP_IOERROR;
    char *namelock_fname = NULL;
    char *userid = NULL;

    /* not an indexable mailbox, fine - return a code to avoid
     * trying to index each message as well */
    if (!fname) {
        r = IMAP_MAILBOX_NONEXISTENT;
        goto out;
    }

    /* Do nothing if there is no userid */
    userid = mboxname_to_userid(mailbox->name);
    if (!userid) goto out;

    /* Get a shared namelock */
    namelock_fname = xapiandb_namelock_fname_from_userid(userid);

    r = mboxname_lock(namelock_fname, &tr->xapiandb_namelock, LOCK_SHARED);
    if (r) {
        syslog(LOG_ERR, "Could not acquire shared namelock on %s\n",
               namelock_fname);
        goto out;
    }

    /* we're using "not incremental" to mean "check that the GUID of every message
     * in the mailbox is present in an index rather than trusting the UID ranges */

    /* we grab an activefile writelock to index.  Strictly we don't need it, but
     * doing this guarantees we never write under a client which is reading, which
     * avoids this:
     *
     *     IOERROR: Xapian: caught exception: : DatabaseModifiedError: The revision
     *     being read has been discarded - you should call Xapian::Database::reopen()
     *     and retry the operation
     *
     * in theory, this will go away eventually, and we can switch back to write: 0
     * in this code.
     *
     * http://grokbase.com/t/xapian/xapian-discuss/0667ppbks8/#20060608j8x5aeept49dv5fm8d02xkczgr
     *
     * "This is almost invariably caused by updating a database while reading
     *  from it. If two updates are committed before the read completes, you
     *  get this error (it's DatabaseModifiedError). It's a bit of a pain
     *  and will be going away in the future, but it's not too hard to design
     *  to avoid it happening at least."
     */
    active = activefile_open(mailbox->name, mailbox->part, &tr->activefile, AF_LOCK_WRITE);
    if (!active || !active->count) {
        goto out;
    }

    tr->mode = (flags & SEARCH_UPDATE_XAPINDEXED) ? XAPIAN_DBW_XAPINDEXED
                                                  : XAPIAN_DBW_CONVINDEXED;

    /* doesn't matter if the first one doesn't exist yet, we'll create it. Only stat the others if we're going
     * to be opening them */
    int dostat = tr->mode == XAPIAN_DBW_XAPINDEXED ? 2 : 0;
    tr->activedirs = activefile_resolve(mailbox->name, mailbox->part, active, dostat, &tr->activetiers);
    if (!tr->activedirs || !tr->activedirs->count) {
        goto out;
    }

    /* create the directory if needed */
    r = check_directory(strarray_nth(tr->activedirs, 0), tr->super.verbose, /*create*/1);
    if (r) goto out;

    if (tr->mode == XAPIAN_DBW_XAPINDEXED) {
        /* open the DB now, we need it to check if messages are indexed */
        r = xapian_dbw_open((const char **)tr->activedirs->data, &tr->dbw, tr->mode);
        if (r) goto out;
    }

    /* read the indexed data from every directory so know what still needs indexing */
    tr->oldindexed = seqset_init(0, SEQ_MERGE);

    if ((flags & SEARCH_UPDATE_INCREMENTAL)) {
        r = read_indexed(tr->activedirs, tr->activetiers, mailbox->name, mailbox->i.uidvalidity,
                        tr->oldindexed, /*do_cache*/1, tr->super.verbose);
        if (r) goto out;
    }

    /* purge any stale cache for this mailbox index sequences */
    struct seqset *seq = hash_del(mailbox->name, &tr->cached_seqs);
    if (seq) seqset_free(seq);

    tr->super.mailbox = mailbox;

out:
    free(fname);
    free(userid);
    free(namelock_fname);
    strarray_free(active);
    return r;
}

static uint32_t first_unindexed_uid(search_text_receiver_t *rx)
{
    xapian_update_receiver_t *tr = (xapian_update_receiver_t *)rx;

   return seqset_firstnonmember(tr->oldindexed);
}

static int is_indexed_cb(const conv_guidrec_t *rec, void *rock)
{
    xapian_update_receiver_t *tr = rock;

    /* Is this GUID record in the mailbox we are currently indexing? */
    if (!strcmp(tr->super.mailbox->name, rec->mboxname)) {
        if (seqset_ismember(tr->indexed, rec->uid) ||
            seqset_ismember(tr->oldindexed, rec->uid)) {
            return CYRUSDB_DONE;
        }
        return 0;
    }

    /* Is this GUID record in an already cached sequence set? */
    struct seqset *seq = hash_lookup(rec->mboxname, &tr->cached_seqs);
    if (seq) {
        return seqset_ismember(seq, rec->uid) ? CYRUSDB_DONE : 0;
    }

    /* Read the index cache for this mailbox */
    mbentry_t *mb = NULL;
    seq = seqset_init(0, SEQ_MERGE);
    int r = 0;

    r = mboxlist_lookup(rec->mboxname, &mb, NULL);
    if (r) {
        syslog(LOG_ERR, "is_indexed_cb: mboxlist_lookup %s failed: %s",
                rec->mboxname, error_message(r));
        goto out;
    }
    r = read_indexed(tr->activedirs, tr->activetiers, mb->name, mb->uidvalidity,
                    seq, /*do_cache*/1, tr->super.verbose);
    if (r) {
        syslog(LOG_ERR, "is_indexed_cb: read_indexed %s failed: %s",
                rec->mboxname, error_message(r));
        goto out;
    }
    hash_insert(rec->mboxname, seq, &tr->cached_seqs);

out:
    mboxlist_entry_free(&mb);
    if (r) {
        seqset_free(seq);
        return 0;
    }
    return seqset_ismember(seq, rec->uid) ? CYRUSDB_DONE : 0;
}

static int is_indexed(search_text_receiver_t *rx, message_t *msg)
{
    /* XXX caveat: this function returns non-zero if msg already
     * has been indexed _and marks msg as indexed in any case_.
     * The current squatter implementation relies on this and
     * we should probably change this. */
    xapian_update_receiver_t *tr = (xapian_update_receiver_t *)rx;

    uint32_t uid = 0;
    message_get_uid(msg, &uid);

    /* bail early if we've already indexed this message in THIS run */
    if (seqset_ismember(tr->indexed, uid))
        return 1;

    int ret = 0;

    const struct message_guid *guid = NULL;
    message_get_guid(msg, &guid);

    if (tr->mode == XAPIAN_DBW_CONVINDEXED) {
        /* Determine if msg is already indexed */
        struct conversations_state *cstate = mailbox_get_cstate(tr->super.mailbox);
        if (!cstate) {
            syslog(LOG_INFO, "search_xapian: can't open conversations for %s",
                    tr->super.mailbox->name);
            return 0;
        }

        char *guidrep = xstrdup(message_guid_encode(guid));
        int r = conversations_guid_foreach(cstate, guidrep, is_indexed_cb, tr);
        if (r == CYRUSDB_DONE) ret = 1;
        else if (r) {
            syslog(LOG_ERR, "is_indexed %s:%d: unexpected return code: %d (%s)",
                   tr->super.mailbox->name, uid, r, cyrusdb_strerror(r));
        }
        free(guidrep);
    }
    else if (tr->mode == XAPIAN_DBW_XAPINDEXED) {
        if (xapian_dbw_is_indexed(tr->dbw, make_cyrusid(guid)))
            ret = 1;
    }

    /* start the range back at the first unindexed if necessary */
    if (!tr->indexed) {
        tr->indexed = seqset_init(0, SEQ_MERGE);
        /* we want to say that we indexed the entire gap from last time
         * up until this first message as well, so our indexed range
         * isn't gappy */
        seqset_add(tr->indexed, seqset_firstnonmember(tr->oldindexed), 1);
    }
    seqset_add(tr->indexed, uid, 1);

    return ret;
}

static int end_mailbox_update(search_text_receiver_t *rx,
                              struct mailbox *mailbox
                            __attribute__((unused)))
{
    xapian_update_receiver_t *tr = (xapian_update_receiver_t *)rx;
    int r = 0;

    r = flush(rx);

    /* flush before cleaning up, since indexed data is written by flush */
    if (tr->indexed) {
        seqset_free(tr->indexed);
        tr->indexed = NULL;
    }
    if (tr->oldindexed) {
        seqset_free(tr->oldindexed);
        tr->oldindexed = NULL;
    }

    tr->super.mailbox = NULL;

    if (tr->dbw) {
        xapian_dbw_close(tr->dbw);
        tr->dbw = NULL;
    }

    /* don't unlock until DB is committed */
    if (tr->activefile) {
        mappedfile_unlock(tr->activefile);
        mappedfile_close(&tr->activefile);
        tr->activefile = NULL;
    }

    /* Release xapian db named lock */
    if (tr->xapiandb_namelock) {
        mboxname_release(&tr->xapiandb_namelock);
        tr->xapiandb_namelock = NULL;
    }

    if (tr->activedirs) {
        strarray_free(tr->activedirs);
        tr->activedirs = NULL;
    }
    if (tr->activetiers) {
        strarray_free(tr->activetiers);
        tr->activetiers = NULL;
    }

    return r;
}

static search_text_receiver_t *begin_update(int verbose)
{
    xapian_update_receiver_t *tr;

    if (check_config()) return NULL;

    tr = xzmalloc(sizeof(xapian_update_receiver_t));
    tr->super.super.begin_mailbox = begin_mailbox_update;
    tr->super.super.first_unindexed_uid = first_unindexed_uid;
    tr->super.super.is_indexed = is_indexed;
    tr->super.super.begin_message = begin_message;
    tr->super.super.begin_part = begin_part;
    tr->super.super.append_text = append_text;
    tr->super.super.end_part = end_part;
    tr->super.super.end_message = end_message_update;
    tr->super.super.end_mailbox = end_mailbox_update;
    tr->super.super.flush = flush;

    tr->super.verbose = verbose;

    construct_hash_table(&tr->cached_seqs, 128, 0);

    return &tr->super.super;
}

static void free_receiver(xapian_receiver_t *tr)
{
    free_segments(tr);
    ptrarray_fini(&tr->segs);
    free(tr);
}

static int end_update(search_text_receiver_t *rx)
{
    xapian_update_receiver_t *tr = (xapian_update_receiver_t *)rx;
    free_hash_table(&tr->cached_seqs, (void(*)(void*))seqset_free);

    free_receiver(&tr->super);

    return 0;
}

static int begin_mailbox_snippets(search_text_receiver_t *rx,
                                  struct mailbox *mailbox,
                                  int incremental __attribute__((unused)))
{
    xapian_snippet_receiver_t *tr = (xapian_snippet_receiver_t *)rx;

    tr->super.mailbox = mailbox;

    return 0;
}

/* Find match terms for the given part and add them to the Xapian
 * snippet generator.  */
static void generate_snippet_terms(xapian_snipgen_t *snipgen,
                                   int part,
                                   struct opnode *on)
{
    struct opnode *child;

    switch (on->op) {

    case SEARCH_OP_NOT:
    case SEARCH_OP_OR:
    case SEARCH_OP_AND:
        for (child = on->children ; child ; child = child->next)
            generate_snippet_terms(snipgen, part, child);
        break;

    case SEARCH_PART_ANY:
        assert(on->children == NULL);
        if (part != SEARCH_PART_HEADERS) {
            xapian_snipgen_add_match(snipgen, on->arg);
        }
        break;

    default:
        /* other SEARCH_PART_* constants */
        assert(on->op >= 0 && on->op < SEARCH_NUM_PARTS);
        assert(on->children == NULL);
        if (part == on->op) {
            xapian_snipgen_add_match(snipgen, on->arg);
        }
        break;
    }
}

static int end_message_snippets(search_text_receiver_t *rx)
{
    xapian_snippet_receiver_t *tr = (xapian_snippet_receiver_t *)rx;
    struct buf snippets = BUF_INITIALIZER;
    unsigned int context_length;
    int i;
    struct segment *seg;
    int last_part = -1;
    int r = 0;

    if (!tr->root) {
        goto out;
    }

    if (!tr->snipgen) {
        r = IMAP_INTERNAL;          /* need to call begin_mailbox() */
        goto out;
    }

    ptrarray_sort(&tr->super.segs, compare_segs);

    for (i = 0 ; i < tr->super.segs.count ; i++) {
        seg = (struct segment *)ptrarray_nth(&tr->super.segs, i);

        if (seg->part != last_part) {

            if (last_part != -1) {
                r = xapian_snipgen_end_doc(tr->snipgen, &snippets);
                if (!r && snippets.len)
                    r = tr->proc(tr->super.mailbox, tr->super.uid, last_part, snippets.s, tr->rock);
                if (r) break;
            }

            /* TODO: UINT_MAX doesn't behave as expected, which is probably
             * a bug, but really any value larger than a reasonable Subject
             * length will do */
            context_length = (seg->part == SEARCH_PART_HEADERS || seg->part == SEARCH_PART_BODY ? 5 : 1000000);
            r = xapian_snipgen_begin_doc(tr->snipgen, context_length);
            if (r) break;

            generate_snippet_terms(tr->snipgen, seg->part, tr->root);
        }

        r = xapian_snipgen_doc_part(tr->snipgen, &seg->text, seg->part);
        if (r) break;

        last_part = seg->part;
    }

    if (last_part != -1) {
        r = xapian_snipgen_end_doc(tr->snipgen, &snippets);
        if (!r && snippets.len)
            r = tr->proc(tr->super.mailbox, tr->super.uid, last_part, snippets.s, tr->rock);
    }

out:
    buf_free(&snippets);
    return r;
}

static int end_mailbox_snippets(search_text_receiver_t *rx,
                                struct mailbox *mailbox
                                    __attribute__((unused)))
{
    xapian_snippet_receiver_t *tr = (xapian_snippet_receiver_t *)rx;

    tr->super.mailbox = NULL;

    return 0;
}

static search_text_receiver_t *begin_snippets(void *internalised,
                                              int verbose,
                                              search_snippet_markup_t *m,
                                              search_snippet_cb_t proc,
                                              void *rock)
{
    xapian_snippet_receiver_t *tr;

    if (check_config()) return NULL;

    tr = xzmalloc(sizeof(xapian_snippet_receiver_t));
    tr->super.super.begin_mailbox = begin_mailbox_snippets;
    tr->super.super.begin_message = begin_message;
    tr->super.super.begin_part = begin_part;
    tr->super.super.append_text = append_text;
    tr->super.super.end_part = end_part;
    tr->super.super.end_message = end_message_snippets;
    tr->super.super.end_mailbox = end_mailbox_snippets;

    tr->super.verbose = verbose;
    tr->root = (struct opnode *)internalised;
    tr->snipgen = xapian_snipgen_new(m->hi_start, m->hi_end, m->omit);
    tr->proc = proc;
    tr->rock = rock;

    return &tr->super.super;
}

static int end_snippets(search_text_receiver_t *rx)
{
    xapian_snippet_receiver_t *tr = (xapian_snippet_receiver_t *)rx;

    if (tr->snipgen) xapian_snipgen_free(tr->snipgen);

    free_receiver(&tr->super);

    return 0;
}

static int list_files(const char *userid, strarray_t *files)
{
    char *mboxname = mboxname_user_mbox(userid, NULL);
    struct mboxlist_entry *mbentry = NULL;
    char *fname = NULL;
    DIR *dirh = NULL;
    struct dirent *de;
    struct stat sb;
    strarray_t *active = NULL;
    strarray_t *dirs = NULL;
    struct mappedfile *activefile = NULL;
    struct mboxlock *xapiandb_namelock = NULL;
    char *namelock_fname = NULL;
    int r;
    int i;

    r = mboxlist_lookup(mboxname, &mbentry, NULL);
    if (r == IMAP_MAILBOX_NONEXISTENT) {
        /* no user, no worries */
        r = 0;
        goto out;
    }
    if (r) {
        syslog(LOG_ERR, "IOERROR: failed to lookup %s", mboxname);
        goto out;
    }

    /* Get a shared namelock */
    namelock_fname = xapiandb_namelock_fname_from_userid(userid);

    r = mboxname_lock(namelock_fname, &xapiandb_namelock, LOCK_SHARED);
    if (r) {
        syslog(LOG_ERR, "Could not acquire shared namelock on %s\n",
               namelock_fname);
        goto out;
    }

    /* Get a readlock on the activefile */
    active = activefile_open(mboxname, mbentry->partition, &activefile, AF_LOCK_READ);
    if (!active) goto out;
    dirs = activefile_resolve(mboxname, mbentry->partition, active, /*dostat*/1, NULL/*resultitems*/);

    for (i = 0; i < dirs->count; i++) {
        const char *basedir = strarray_nth(dirs, i);

        dirh = opendir(basedir);
        if (!dirh) continue;

        while ((de = readdir(dirh))) {
            if (de->d_name[0] == '.') continue;
            free(fname);
            fname = strconcat(basedir, "/", de->d_name, (char *)NULL);
            r = stat(fname, &sb);
            if (!r && S_ISREG(sb.st_mode)) {
                strarray_appendm(files, fname);
                fname = NULL;
            }
        }

        closedir(dirh);
        dirh = NULL;
    }

out:
    if (activefile) {
        mappedfile_unlock(activefile);
        mappedfile_close(&activefile);
    }

    if (xapiandb_namelock) {
        mboxname_release(&xapiandb_namelock);
        xapiandb_namelock = NULL;
    }

    strarray_free(active);
    strarray_free(dirs);
    free(fname);
    free(namelock_fname);
    mboxlist_entry_free(&mbentry);
    free(mboxname);

    return 0;
}

struct mbfilter {
    const char *userid;
    struct bloom bloom;
    struct db *indexeddb;
    struct txn **tid;
    const strarray_t *destpaths;
    const strarray_t *desttiers;
    int flags;
};

static void free_mbfilter(struct mbfilter *filter)
{
    if (filter->tid) cyrusdb_abort(filter->indexeddb, *filter->tid);
    cyrusdb_close(filter->indexeddb);
    bloom_free(&filter->bloom);
}

static int copyindexed_cb(void *rock,
                         const char *key, size_t keylen,
                         const char *data, size_t datalen)
{
    /* Ignore cached index entries */
    if (*key == '#') {
        return 0;
    }

    /* Copy the record */
    struct mbfilter *filter = (struct mbfilter *)rock;
    struct seqset *seq = parse_indexed(data, datalen);
    int r = 0;
    if (seq) {
        r = store_indexed(filter->indexeddb, filter->tid, key, keylen, seq);
        seqset_free(seq);
    }
    return r;
}

static int mbdata_exists_cb(const char *cyrusid, void *rock)
{
    struct mbfilter *filter = (struct mbfilter *)rock;

    /* we can't get here without GUID keys */
    assert(!strncmp(cyrusid, "*G*", 3));

    return bloom_check(&filter->bloom, cyrusid+3, strlen(cyrusid+3));
}

static int bloomadd_cb(void *rock,
                       const char *key, size_t keylen,
                       const char *data __attribute__((unused)),
                       size_t datalen __attribute__((unused)))
{
    struct bloom *bloom = (struct bloom *)rock;
    if (keylen > 41 && !memchr(key+41, '[', keylen-41))
        bloom_add(bloom, key+1, 40);
    return 0;
}

static int create_filter(const strarray_t *srcpaths, const strarray_t *destpaths,
                         const strarray_t *desttiers,
                         const char *userid, int flags, struct mbfilter *filter,
                         int bloom, int newindexdb)
{
    struct buf buf = BUF_INITIALIZER;
    int r = 0;
    int i;
    struct conversations_state *cstate = NULL;

    memset(filter, 0, sizeof(struct mbfilter));
    filter->destpaths = destpaths;
    filter->desttiers = desttiers;
    filter->userid = userid;
    filter->flags = flags;

    /* build the cyrus.indexed.db from the contents of the source dirs */

    buf_reset(&buf);
    buf_printf(&buf, "%s%s", strarray_nth(destpaths, 0), INDEXEDDB_FNAME);
    if (newindexdb)
        buf_appendcstr(&buf, ".NEW");

    r = cyrusdb_open(config_getstring(IMAPOPT_SEARCH_INDEXED_DB),
                     buf_cstring(&buf), CYRUSDB_CREATE, &filter->indexeddb);
    if (r) {
        printf("ERROR: failed to open indexed %s\n", buf_cstring(&buf));
        goto done;
    }
    for (i = 0; i < srcpaths->count; i++) {
        struct db *db = NULL;
        buf_reset(&buf);
        buf_printf(&buf, "%s%s", strarray_nth(srcpaths, i), INDEXEDDB_FNAME);
        r = cyrusdb_open(config_getstring(IMAPOPT_SEARCH_INDEXED_DB),
                         buf_cstring(&buf), 0, &db);
        if (r) {
            r = 0;
            continue;
        }
        r = cyrusdb_foreach(db, "", 0, NULL, copyindexed_cb, filter, NULL);
        cyrusdb_close(db);
        if (r) {
            printf("ERROR: failed to process indexed db %s\n", strarray_nth(srcpaths, i));
            goto done;
        }
    }
    if (filter->tid) r = cyrusdb_commit(filter->indexeddb, *filter->tid);
    if (r) {
        printf("ERROR: failed to commit indexed %s\n", strarray_nth(destpaths, 0));
        goto done;
    }

    if (bloom) {
        /* assume a 4 million maximum records */
        bloom_init(&filter->bloom, 4000000, 0.01);

        r = conversations_open_user(userid, &cstate);
        if (r) {
            printf("ERROR: failed to open conversations for %s\n", userid);
            goto done;
        }

        r = cyrusdb_foreach(cstate->db, "G", 1, NULL, bloomadd_cb, &filter->bloom, NULL);
    }

done:
    conversations_commit(&cstate);
    buf_free(&buf);

    return r;
}

static int search_filter(const char *userid, const strarray_t *srcpaths,
                         const strarray_t *destpaths, const strarray_t *desttiers, int flags)
{
    struct mbfilter filter;
    int verbose = SEARCH_VERBOSE(flags);
    int r;

    r = create_filter(srcpaths, destpaths, desttiers, userid, flags, &filter, 1, 0);
    if (r) goto done;

    if (verbose)
        printf("Filtering database %s\n", strarray_nth(destpaths, 0));

    r = xapian_filter(strarray_nth(destpaths, 0), (const char **)srcpaths->data,
                      mbdata_exists_cb, &filter);
    if (r) goto done;

    if (verbose)
        printf("done %s\n", strarray_nth(destpaths, 0));

done:
    free_mbfilter(&filter);
    return r;
}

static int reindex_mb(void *rock,
                      const char *key, size_t keylen,
                      const char *data, size_t datalen)
{
    struct mbfilter *filter = (struct mbfilter *)rock;
    char *mboxname = xstrndup(key, keylen);
    struct seqset *seq = parse_indexed(data, datalen);
    xapian_update_receiver_t *tr = NULL;
    struct mailbox *mailbox = NULL;
    ptrarray_t batch = PTRARRAY_INITIALIZER;
    int verbose = SEARCH_VERBOSE(filter->flags);
    int r = 0;
    int i;
    char *dot;
    uint32_t uidvalidity;

    dot = strrchr(mboxname, '.');
    *dot++ = '\0';
    uidvalidity = atol(dot);

    if (!seq) goto done;

    r = mailbox_open_irl(mboxname, &mailbox);
    if (r == IMAP_MAILBOX_NONEXISTENT) {
        r = 0;  /* it's not an error to have a no-longer-exiting mailbox to index */
        goto done;
    }
    if (r) goto done;

    if (mailbox->i.uidvalidity != uidvalidity) goto done; /* returns 0, nothing to index */

    /* open the DB */
    tr = (xapian_update_receiver_t *)begin_update(verbose);
    tr->mode = (filter->flags & SEARCH_COMPACT_XAPINDEXED) ? XAPIAN_DBW_XAPINDEXED
                                                           : XAPIAN_DBW_CONVINDEXED;
    r = xapian_dbw_open((const char **)filter->destpaths->data, &tr->dbw, tr->mode);
    if (r) goto done;
    tr->super.mailbox = mailbox;

    tr->activedirs = strarray_dup(filter->destpaths);
    tr->activetiers = strarray_dup(filter->desttiers);

    struct mailbox_iter *iter = mailbox_iter_init(mailbox, 0, ITER_SKIP_UNLINKED);
    mailbox_iter_startuid(iter, seqset_first(seq));

    /* initialise here so it doesn't add firstunindexed
     * from oldindexed in is_indexed */
    tr->indexed = seqset_init(0, SEQ_MERGE);

    const message_t *msg;
    while ((msg = mailbox_iter_step(iter))) {
        const struct index_record *record = msg_record(msg);
        /* it wasn't in the previous index, skip it */
        if (!seqset_ismember(seq, record->uid))
            continue;

        message_t *msg = message_new_from_record(mailbox, record);

        /* add the record to the list */
        if (!is_indexed((search_text_receiver_t *)tr, msg))
            ptrarray_append(&batch, msg);
        else
            message_unref(&msg);

        if (record->uid > seqset_last(seq))
            break;
    }

    mailbox_iter_done(&iter);

    mailbox_unlock_index(mailbox, NULL);

    if (batch.count) {
        /* XXX - errors here could leak... */
        /* game on */

        /* preload */
        for (i = 0 ; i < batch.count ; i++) {
            message_t *msg = ptrarray_nth(&batch, i);

            const char *fname;
            r = message_get_fname(msg, &fname);
            if (r) goto done;
            r = warmup_file(fname, 0, 0);
            if (r) goto done; /* means we failed to open a file,
                                so we'll fail later anyway */
        }

        /* index the messages */
        for (i = 0 ; i < batch.count ; i++) {
            message_t *msg = ptrarray_nth(&batch, i);
            r = index_getsearchtext(msg, &tr->super.super, 0);
            if (r) goto done;
            message_unref(&msg);
        }
        if (tr->uncommitted) {
            r = xapian_dbw_commit_txn(tr->dbw);
            if (r) goto done;
        }
    }

done:
    if (tr) {
        strarray_free(tr->activedirs);
        strarray_free(tr->activetiers);
        if (tr->indexed) seqset_free(tr->indexed);
        if (tr->dbw) xapian_dbw_close(tr->dbw);
        free_receiver(&tr->super);
    }
    mailbox_close(&mailbox);
    ptrarray_fini(&batch);
    free(mboxname);
    seqset_free(seq);
    return r;
}

static int search_reindex(const char *userid, const strarray_t *srcpaths,
                          const strarray_t *destpaths, const strarray_t *desttiers, int flags)
{
    struct buf buf = BUF_INITIALIZER;
    struct mbfilter filter;
    int verbose = SEARCH_VERBOSE(flags);
    int r;

    r = create_filter(srcpaths, destpaths, desttiers, userid, flags, &filter, 0, 1);
    if (r) goto done;

    if (verbose)
        printf("Reindexing messages for %s\n", userid);

    r = cyrusdb_foreach(filter.indexeddb, "", 0, NULL, reindex_mb, &filter, NULL);
    if (r) {
        printf("ERROR: failed to reindex to %s\n", strarray_nth(destpaths, 0));
        goto done;
    }

    if (verbose)
        printf("done %s\n", strarray_nth(destpaths, 0));

done:
    free_mbfilter(&filter);
    buf_free(&buf);
    return r;
}

static int search_compress(const char *userid, const strarray_t *srcpaths,
                           const strarray_t *destpaths, const strarray_t *desttiers, int flags)
{
    struct buf buf = BUF_INITIALIZER;
    struct mbfilter filter;
    int verbose = SEARCH_VERBOSE(flags);
    int r;

    r = create_filter(srcpaths, destpaths, desttiers, userid, flags, &filter, 0, 0);
    if (r) goto done;

    if (verbose)
        printf("Compressing messages for %s\n", userid);

    r = xapian_compact_dbs(strarray_nth(destpaths, 0), (const char **)srcpaths->data);
    if (r) {
        printf("ERROR: failed to compress to %s\n", strarray_nth(destpaths, 0));
        goto done;
    }

    if (verbose)
        printf("done %s\n", strarray_nth(destpaths, 0));

done:
    free_mbfilter(&filter);
    buf_free(&buf);
    return r;
}

static int compact_dbs(const char *userid, const char *tempdir,
                       const strarray_t *srctiers, const char *desttier,
                       int flags)
{
    char *mboxname = mboxname_user_mbox(userid, NULL);
    struct mboxlist_entry *mbentry = NULL;
    struct mappedfile *activefile = NULL;
    struct mboxlock *xapiandb_namelock = NULL;
    strarray_t *srcdirs = NULL;
    strarray_t *newdirs = NULL;
    strarray_t *active = NULL;
    strarray_t *tochange = NULL;
    strarray_t *orig = NULL;
    strarray_t *toreindex = NULL;
    strarray_t *tocompact = NULL;
    char *newdest = NULL;
    char *destdir = NULL;
    char *tempdestdir = NULL;
    char *tempreindexdir = NULL;
    strarray_t *newtiers = NULL;
    struct buf mytempdir = BUF_INITIALIZER;
    char *namelock_fname = NULL;
    int verbose = SEARCH_VERBOSE(flags);
    int r = 0;
    int i;

    r = mboxlist_lookup(mboxname, &mbentry, NULL);
    if (r == IMAP_MAILBOX_NONEXISTENT) {
        /* no user, no worries */
        r = 0;
        goto out;
    }
    if (r) {
        syslog(LOG_ERR, "IOERROR: failed to lookup %s", mboxname);
        goto out;
    }

    r = check_config();
    if (r) goto out;

    /* Generated the namelock filename */
    namelock_fname = xapiandb_namelock_fname_from_userid(userid);

    /* Get an exclusive namelock */
    r = mboxname_lock(namelock_fname, &xapiandb_namelock, LOCK_EXCLUSIVE);
    if (r) {
        syslog(LOG_ERR, "Could not acquire shared namelock on %s\n",
               namelock_fname);
        goto out;
    }

    /* take an exclusive lock on the activefile file */
    active = activefile_open(mboxname, mbentry->partition, &activefile, AF_LOCK_WRITE);
    if (!active || !active->count) goto out;

    orig = strarray_dup(active);

    /* read the activefile file, taking down the names of all paths with a
     * level less than or equal to that requested */
    tochange = activefile_filter(active, srctiers, mbentry->partition);
    if (!tochange || !tochange->count) goto out;

    if (tochange->count == 1 && srctiers->count == 1 &&
        (flags & SEARCH_COMPACT_COPYONE) && !strcmp(desttier, strarray_nth(srctiers, 0))) {
        if (verbose) {
            printf("Skipping %s for %s, only one\n", strarray_nth(tochange, 0), mboxname);
        }
        goto out;
    }

    /* find out which items actually exist from the set to be compressed - first pass */
    srcdirs = activefile_resolve(mboxname, mbentry->partition, tochange, /*dostat*/1, NULL/*resultitems*/);
    if (!srcdirs || !srcdirs->count) goto out;
    /* NOTE: it's safe to keep this list even over the unlock/relock because we
     * always write out a new first item if necessary, so these will never be
     * written to after we release the lock - if they don't have content now,
     * they never will */

    /* register the target name first, and put it at the end of the file */
    newdest = activefile_nextname(active, desttier);
    strarray_push(active, newdest);

    if (verbose) {
        char *target = strarray_join(tochange, ",");
        char *activestr = strarray_join(orig, ",");
        printf("compressing %s to %s for %s (active %s)\n", target, newdest, mboxname, activestr);
        free(activestr);
        free(target);
    }

    /* are we going to change the first active?  We need to start indexing to
     * a new location! */
    if (strarray_find(tochange, strarray_nth(active, 0), 0) >= 0) {
        /* always recalculate the first name once the destination is chosen,
        * because we may be compressing to the default tier for some reason */
        char *newstart = activefile_nextname(active, config_getstring(IMAPOPT_DEFAULTSEARCHTIER));
        if (verbose) {
            printf("adding new initial search location %s\n", newstart);
        }
        strarray_unshiftm(active, newstart);
    }

    destdir = activefile_path(mboxname, mbentry->partition, newdest, /*dostat*/0);
    tempdestdir = strconcat(destdir, ".NEW", (char *)NULL);

    /* write the new file and release the exclusive lock */
    activefile_write(activefile, active);
    mappedfile_unlock(activefile);

    /* Release the exclusive named lock */
    if (xapiandb_namelock) {
        mboxname_release(&xapiandb_namelock);
        xapiandb_namelock = NULL;
    }

    /* Get a shared name lock */
    r = mboxname_lock(namelock_fname, &xapiandb_namelock, LOCK_SHARED);
    if (r) {
        syslog(LOG_ERR, "Could not acquire shared namelock on %s\n",
               namelock_fname);
        goto out;
    }

    /* take a shared lock */
    mappedfile_readlock(activefile);

    /* reread and ensure our 'directory zero' is still directory zero,
     * otherwise abort now */
    {
        strarray_t *newactive = activefile_read(activefile);
        if (strarray_cmp(active, newactive)) {
            if (verbose) {
                printf("aborting compact of %s, lost the race early\n", mboxname);
            }
            strarray_free(newactive);
            goto out;
        }
        strarray_free(newactive);
    }

    /* release the sharedlock on the active file, compcating is safe
     * without locking activefile.
     */
    mappedfile_unlock(activefile);

    if (tempdir) {
        /* run the compress to tmpfs */
        buf_printf(&mytempdir, "%s/xapian.%d", tempdir, getpid());
    }
    else {
        /* or just directly in place */
        buf_printf(&mytempdir, "%s", tempdestdir);
    }

    /* make sure the destination path exists */
    r = cyrus_mkdir(buf_cstring(&mytempdir), 0755);
    if (r) goto out;
    /* and doesn't contain any junk */
    remove_dir(buf_cstring(&mytempdir));
    r = mkdir(buf_cstring(&mytempdir), 0755);
    if (r) goto out;

    if (srcdirs->count == 1 && (flags & SEARCH_COMPACT_COPYONE)) {
        if (verbose) {
            printf("only one source, copying directly to %s\n", tempdestdir);
        }
        cyrus_mkdir(tempdestdir, 0755);
        remove_dir(tempdestdir);
        r = copy_files(srcdirs->data[0], tempdestdir);
    }
    else if (srcdirs->count) {
        if (verbose) {
            printf("compacting databases\n");
        }

        /* calculate the existing databases that we also need to check for duplicates */
        strarray_t *existing = strarray_dup(orig);
        for (i = 0; i < tochange->count; i++)
            strarray_remove_all(existing, strarray_nth(tochange, i));
        newdirs = activefile_resolve(mboxname, mbentry->partition, existing, /*dostat*/1, &newtiers);
        strarray_free(existing);
        /* we'll be prepending the final target directory to newdirs before compacting,
         * so also add the new tier so the indexes match up */
        strarray_unshift(newtiers, newdest);

        toreindex = strarray_new();
        tocompact = strarray_new();
        if ((flags & SEARCH_COMPACT_REINDEX)) {
            /* all databases to be reindexed */
            strarray_cat(toreindex, srcdirs);
        }
        else {
            xapian_check_if_needs_reindex(srcdirs, toreindex);
            for (i = 0; i < srcdirs->count; i++) {
                const char *thisdir = strarray_nth(srcdirs, i);
                if (strarray_find(toreindex, thisdir, 0) < 0)
                    strarray_append(tocompact, thisdir);
            }
        }

        if (toreindex->count) {
            tempreindexdir = strconcat(buf_cstring(&mytempdir), ".REINDEX", (char *)NULL);
            // add this directory to the repack target as the first entry point
            strarray_unshift(newdirs, tempreindexdir);
            r = search_reindex(userid, toreindex, newdirs, newtiers, flags);
            if (r) {
                printf("ERROR: failed to reindex to %s", buf_cstring(&mytempdir));
                goto out;
            }
            // remove tempreindexdir from newdirs again, it's going to be compacted instead
            free(strarray_shift(newdirs));

            // add it to the to-compact list if there's something there to reindex
            if (!xapstat(tempreindexdir))
                strarray_unshift(tocompact, tempreindexdir);
        }
        else if ((flags & SEARCH_COMPACT_ONLYUPGRADE)) {
            /* nothing to reindex, so bail now.  Since we don't set 'r', we will just
             * abort with no change other than a new tmp location which compresses down
             * soon enough */
            goto out;
        }

        // nothing left to compress
        if (!tocompact->count)
            goto out;

        // and now we're ready to compact to the real tempdir
        strarray_unshift(newdirs, buf_cstring(&mytempdir));

        if (flags & SEARCH_COMPACT_FILTER) {
            r = search_filter(userid, tocompact, newdirs, newtiers, flags);
            if (r) {
                printf("ERROR: failed to filter to %s", buf_cstring(&mytempdir));
                goto out;
            }
        }
        else {
            r = search_compress(userid, tocompact, newdirs, newtiers, flags);
            if (r) {
                printf("ERROR: failed to compact to %s", buf_cstring(&mytempdir));
                goto out;
            }
        }

        /* move the tmpfs files to a temporary name in our target directory */
        if (tempdir) {
            if (verbose) {
                printf("copying from tempdir to destination\n");
            }
            cyrus_mkdir(tempdestdir, 0755);
            remove_dir(tempdestdir);
            r = copy_files(buf_cstring(&mytempdir), tempdestdir);
            if (r) {
                printf("Failed to rsync from %s to %s", buf_cstring(&mytempdir), tempdestdir);
                goto out;
            }
        }
    }

    /* Release the shared named lock */
    if (xapiandb_namelock) {
        mboxname_release(&xapiandb_namelock);
        xapiandb_namelock = NULL;
    }

    /* Get an exclusive namelock */
    r = mboxname_lock(namelock_fname, &xapiandb_namelock, LOCK_EXCLUSIVE);
    if (r) {
        syslog(LOG_ERR, "Could not acquire shared namelock on %s\n",
               namelock_fname);
        goto out;
    }

    /* check that we still have 'directory zero'.  If not, delete all
     * temporary files and abort */
    {
        strarray_t *newactive = activefile_read(activefile);
        if (strarray_cmp(active, newactive)) {
            if (verbose) {
                printf("aborting compact of %s, lost the race late\n", mboxname);
            }
            strarray_free(newactive);
            goto out;
        }
        strarray_free(newactive);
    }

    if (srcdirs->count) {
        /* create a new target name one greater than the highest in the
         * activefile file for our target directory.  Rename our DB to
         * that path, then rewrite activefile removing all the source
         * items */
        if (verbose) {
            printf("renaming tempdir into place\n");
        }
        remove_dir(destdir);
        r = rename(tempdestdir, destdir);
        if (r) {
            printf("ERROR: failed to rename into place %s to %s\n", tempdestdir, destdir);
            goto out;
        }
    }
    else {
        if (verbose) {
            printf("nothing compacted, cleaning up %s\n", newdest);
        }
        strarray_append(tochange, newdest);
    }

    for (i = 0; i < tochange->count; i++)
        strarray_remove_all(active, strarray_nth(tochange, i));

    /* Get an exclusive lock on the activefile */
    mappedfile_writelock(activefile);

    activefile_write(activefile, active);

    /* release the lock */
    mappedfile_unlock(activefile);

    /* Release the exclusive named lock */
    if (xapiandb_namelock) {
        mboxname_release(&xapiandb_namelock);
        xapiandb_namelock = NULL;
    }

    if (verbose) {
        char *alist = strarray_join(active, ",");
        printf("finished compact of %s (active %s)\n", mboxname, alist);
        free(alist);
    }

    /* Get a shared name lock */
    r = mboxname_lock(namelock_fname, &xapiandb_namelock, LOCK_SHARED);
    if (r) {
        syslog(LOG_ERR, "Could not acquire shared namelock on %s\n",
               namelock_fname);
        goto out;
    }

    /* And finally remove all directories on disk of the source dbs */
    for (i = 0; i < srcdirs->count; i++)
        remove_dir(strarray_nth(srcdirs, i));

    /* XXX - readdir and remove other directories as well */

    /* Release the shared named lock */
    if (xapiandb_namelock) {
        mboxname_release(&xapiandb_namelock);
        xapiandb_namelock = NULL;
    }

out:
    // cleanup all our work locations
    if (tempdestdir)
        remove_dir(tempdestdir);
    if (tempreindexdir)
        remove_dir(tempreindexdir);
    if (mytempdir.len)
        remove_dir(buf_cstring(&mytempdir));

    strarray_free(orig);
    strarray_free(active);
    strarray_free(srcdirs);
    strarray_free(newdirs);
    strarray_free(toreindex);
    strarray_free(tochange);
    strarray_free(tocompact);
    buf_free(&mytempdir);
    free(namelock_fname);
    free(newdest);
    free(destdir);
    free(tempdestdir);
    free(tempreindexdir);
    mappedfile_unlock(activefile);
    mappedfile_close(&activefile);

    if (xapiandb_namelock) {
        mboxname_release(&xapiandb_namelock);
        xapiandb_namelock = NULL;
    }

    mboxlist_entry_free(&mbentry);
    free(mboxname);

    return r;
}

/* cleanup */
static void delete_one(const char *key, const char *val __attribute__((unused)), void *rock)
{
    const char *mboxname = (const char *)rock;
    const char *partition = NULL;
    char *tier = NULL;
    char *basedir = NULL;

    partition = strstr(key, "searchpartition-");
    if (!partition) return;
    tier = xstrndup(key, partition - key);
    partition += 16; /* skip over name */

    xapian_basedir(tier, mboxname, partition, NULL, &basedir);
    if (basedir)
        remove_dir(basedir);

    free(basedir);
    free(tier);
}

static int delete_user(const char *userid)
{
    char *mboxname = mboxname_user_mbox(userid, /*subfolder*/NULL);
    char *activename = activefile_fname(mboxname);
    struct mappedfile *activefile = NULL;
    struct mboxlock *xapiandb_namelock = NULL;
    char *namelock_fname = NULL;
    int r = 0;


    /* Get an exclusive namelock */
    namelock_fname = xapiandb_namelock_fname_from_userid(userid);
    r = mboxname_lock(namelock_fname, &xapiandb_namelock, LOCK_EXCLUSIVE);
    if (r) {
        syslog(LOG_ERR, "Could not acquire shared namelock on %s\n",
               namelock_fname);
        goto out;
    }

    /* grab an exclusive lock on activefile: that way we won't delete
     * it out from under something else (such as squatter)
     */
    r = mappedfile_open(&activefile, activename, MAPPEDFILE_RW);
    if (r) goto out;
    r = mappedfile_writelock(activefile);
    if (r) goto out;

    config_foreachoverflowstring(delete_one, mboxname);
    unlink(activename);

out:
    if (activefile) {
        mappedfile_unlock(activefile);
        mappedfile_close(&activefile);
    }

    if (xapiandb_namelock) {
        mboxname_release(&xapiandb_namelock);
        xapiandb_namelock = NULL;
    }

    free(namelock_fname);
    free(activename);
    free(mboxname);

    return r;
}


const struct search_engine xapian_search_engine = {
    "Xapian",
    SEARCH_FLAG_CAN_BATCH,
    begin_search,
    end_search,
    begin_update,
    end_update,
    begin_snippets,
    end_snippets,
    describe_internalised,
    free_internalised,
    /*start_daemon*/NULL,
    /*stop_daemon*/NULL,
    list_files,
    compact_dbs,
    delete_user  /* XXX: fixme */
};

