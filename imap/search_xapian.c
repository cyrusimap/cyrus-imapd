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

#define INDEXEDDB_VERSION           2 /* version string for entry value */
#define INDEXEDDB_KEY_VERSION       2 /* version string for entry keys */
#define INDEXEDDB_FNAME         "/cyrus.indexed.db"
#define XAPIAN_DIRNAME          "/xapian"
#define ACTIVEFILE_METANAME     "xapianactive"
#define XAPIAN_NAME_LOCK_PREFIX "$XAPIAN$"

// this seems to translate for 4Gb-ish  - units are 10 bytes?
#define XAPIAN_REINDEX_TEMPDIR_SIZE 419430400
#define XAPIAN_REINDEX_TEMPDIR_COUNT 64000

/* Name of columns */
#define COL_CYRUSID     "cyrusid"

struct segment
{
    int part;
    struct message_guid guid;
    char doctype;
    int sequence;       /* forces stable sort order JIC */
    int is_finished;
    char *partid;
    struct buf text;
};

static const char *xapian_rootdir(const char *tier, const char *partition);

/* ====================================================================== */
static int check_config(char **errstr)
{
    const char *s;

    if (!config_getswitch(IMAPOPT_CONVERSATIONS)) {
        syslog(LOG_ERR, "ERROR: conversations required but not enabled");
        if (errstr)
            *errstr = xstrdup("xapian: conversations required but not enabled");
        return IMAP_NOTFOUND;
    }
    s = config_getstring(IMAPOPT_DEFAULTSEARCHTIER);
    if (!s || !strlen(s)) {
        syslog(LOG_ERR, "ERROR: no default search tier configured");
        if (errstr)
            *errstr = xstrdup("xapian: no default search tier configured");
        return IMAP_PARTITION_UNKNOWN;
    }

    return 0;
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
    buf_printf(&buf, "%s:%d", tier, generation);

    return buf_release(&buf);
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

static int activefile_open(const char *mboxname, const char *partition,
                           struct mappedfile **activefile, enum LockType type,
                           strarray_t **ret)
{
    char *fname = activefile_fname(mboxname);
    int r;

    if (!fname) return IMAP_MAILBOX_NONEXISTENT;

    /* try to open the file, and populate with initial values if it's empty */
    r = mappedfile_open(activefile, fname, MAPPEDFILE_CREATE|MAPPEDFILE_RW);
    if (!r && !mappedfile_size(*activefile))
        _activefile_init(mboxname, partition, *activefile);
    free(fname);
    if (r) {
        xsyslog(LOG_ERR, "mappedfile_open failed",
                         "fname=<%s> error=<%s>",
                         fname, error_message(r));
        return r;
    }

    /* take the requested lock (a better helper API would allow this to be
     * specified as part of the open call, but here's where we are */
    if (type == AF_LOCK_WRITE) r = mappedfile_writelock(*activefile);
    else r = mappedfile_readlock(*activefile);
    if (r) {
        xsyslog(LOG_ERR, "mappedfile_readlock failed",
                         "fname=<%s> error=<%s>",
                         fname, error_message(r));
        return IMAP_MAILBOX_LOCKED;
    }

    /* finally, read the contents */
    *ret = activefile_read(*activefile);
    return 0;
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
    /* Ignore all but mailbox entries */
    if (keylen < 3 || strncmp(key, "*M*", 3)) return 0;

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

struct migrate_indexed_rock {
    struct db *db;
    struct txn **txnptr;
    uint32_t key_version;
};

static int migrate_indexed_cb(void *vrock,
                              const char *key, size_t keylen,
                              const char *data, size_t datalen)
{
    struct migrate_indexed_rock *rock = vrock;

    /* Don't touch entries with current keys */
    if (*key == '*') {
        return 0;
    }

    /* Remove legacy cachetier entries */
    if (*key == '#' && rock->key_version == 0) {
        return cyrusdb_delete(rock->db, key, keylen, rock->txnptr, /*force*/1);
    }

    struct buf buf = BUF_INITIALIZER;
    char *mboxname = NULL;
    uint32_t uidvalidity = 0;
    mbentry_t *mbentry = NULL;
    int r = 0;

    /* Keep a local copy of data */
    buf_setmap(&buf, data, datalen);
    char *mydata = buf_release(&buf);

    /* Parse key formatted as <mboxname>.<uidvalidity> */
    buf_setmap(&buf, key, keylen);
    const char *dot = strrchr(buf_cstring(&buf), '.');
    if (dot > buf_base(&buf) && dot < buf_base(&buf) + buf_len(&buf)) {
        const char *p = NULL;
        if (parseuint32(dot + 1, &p, &uidvalidity) == 0 && *p == '\0') {
            buf_truncate(&buf, dot - buf_base(&buf));
            buf_cstring(&buf);
            mboxname = buf_release(&buf);
        }
    }
    if (!mboxname) {
        syslog(LOG_ERR, "migrate_indexed_cb: can't parse entry: %.*s",
                (int) keylen, key);
        r = CYRUSDB_INTERNAL;
        goto done;
    }

    /* Remove legacy entry */
    r = cyrusdb_delete(rock->db, key, keylen, rock->txnptr, /*force*/1);
    if (r) {
        syslog(LOG_DEBUG, "migrate_indexed_cb: can't delete %.*s",
                (int) keylen, key);
        goto done;
    }

    /* Now key and data buffers are invalid, so don't use them! */

    /* Lookup mailbox entry */
    r = mboxlist_lookup(mboxname, &mbentry, NULL);
    if (r && r != IMAP_MAILBOX_NONEXISTENT) {
        syslog(LOG_ERR, "migrate_indexed_cb: can't lookup mailbox %s: %s",
                mboxname, error_message(r));
        r = CYRUSDB_INTERNAL;
        goto done;
    } else if (r == IMAP_MAILBOX_NONEXISTENT) {
        mbentry = NULL;
        r = 0;
    }

    /* Only migrate current mailbox entries */
    if (mbentry && uidvalidity == mbentry->uidvalidity) {
        buf_printf(&buf, "*M*%s*", mbentry->uniqueid);
        r = cyrusdb_store(rock->db, buf_base(&buf), buf_len(&buf),
                          mydata, datalen, rock->txnptr);
        if (r) {
            syslog(LOG_ERR, "migrate_indexed_cb: can't store %s: %s",
                    buf_cstring(&buf), error_message(r));
            goto done;
        }
    }

done:
    mboxlist_entry_free(&mbentry);
    buf_free(&buf);
    free(mboxname);
    free(mydata);
    return r;
}

static int read_indexversion(struct db *db, int *versionptr, struct txn **txnptr)
{
    const char *data = NULL;
    size_t datalen = 0;
    *versionptr = 0;

    int r = cyrusdb_fetch(db, "*V*", 3, &data, &datalen, txnptr);
    if (r && r != CYRUSDB_NOTFOUND) return r;

    if (!r) {
        bit64 num;
        if (parsenum(data, NULL, datalen, &num) || num > INDEXEDDB_KEY_VERSION) {
            syslog(LOG_ERR, "search_xapian: bogus version entry: %.*s",
                    (int) datalen, data);
            return CYRUSDB_INTERNAL;
        }
        *versionptr = (int) num;
    }
    return 0;
}

/* Open the cyrus.indexed.db located at fname, passing flags to cyrusdb.
 *
 * Any entries with legacy keys are migrated to the latest key version.
 * The returned database is write-locked, and flags must not contain
 * the CYRUSDB_SHARED flag. */
/* XXX this API should allow shared locks if the db backend supports them */
static int open_indexed(const char *fname, int flags, struct db **dbptr)
{

    struct db *db = NULL;
    struct txn *txn = NULL;
    int key_version = 0;
    int r = 0;

    assert(!(flags & CYRUSDB_SHARED));

    r = cyrusdb_open(config_getstring(IMAPOPT_SEARCH_INDEXED_DB),
            fname, flags, &db);
    if (r) return r;

    /* Read the index version */
    r = read_indexversion(db, &key_version, NULL);
    if (!r && key_version != INDEXEDDB_KEY_VERSION) {
        /* Start a write transaction */
        r = read_indexversion(db, &key_version, &txn);
    }
    if (r) return r;

    /* Migrate legacy keys, if any */
    if (key_version != INDEXEDDB_KEY_VERSION) {
        struct migrate_indexed_rock rock = { db, &txn, key_version };
        r = cyrusdb_foreach(db, NULL, 0, NULL, migrate_indexed_cb, &rock, &txn);
        if (r) goto done;

        /* Store the current key version */
        struct buf buf = BUF_INITIALIZER;
        buf_printf(&buf, "%d", INDEXEDDB_KEY_VERSION);
        r = cyrusdb_store(db, "*V*", 3, buf_base(&buf), buf_len(&buf), &txn);
        buf_free(&buf);
        if (r) goto done;
    }

    r = cyrusdb_commit(db, txn);
    txn = NULL;

done:
    if (r && txn) {
        cyrusdb_abort(db, txn);
        txn = NULL;
    }
    if (r && db) {
        cyrusdb_close(db);
        db = NULL;
    }
    *dbptr = db;
    return r;
}

/*
 * Merge the indexed.db of all search tiers activetiers[1..n] into the
 * indexed.db of the top tier.
 *
 * Any entries in indexed.dbs located at activedirs[1..n] are cached into
 * the indexed.db located at activedirs[0] (created if not exists), using
 * the cachetier prefix. Cached tier entries are ignored.
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
    r = open_indexed(buf_cstring(&path), CYRUSDB_CREATE, &dst_db);
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
        buf_printf(&key, "*T*%s*", strarray_nth(activetiers, i));
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
        r = open_indexed(buf_cstring(&path), 0, &src_db);
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
 * Read the indexed UIDs sequence for mailbox identified
 * by uniqueid from the activetiers located at activedirs
 * and join them into a single result res.
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
                       const char *uniqueid,
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
    r = open_indexed(buf_cstring(&path), CYRUSDB_CREATE, &db);
    if (r) {
        syslog(LOG_ERR, "read_indexed: can't open db %s: %s",
                buf_cstring(&path), cyrusdb_strerror(r));
        goto out;
    }

    /* Lookup entry in top tier */
    buf_printf(&key, "*M*%s*", uniqueid);
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
        if (srcdb) {
            cyrusdb_close(srcdb);
            srcdb = NULL;
        }

        /* First look in the cached tiers in the top tier database. */
        buf_reset(&key);
        buf_printf(&key, "*T*%s*", strarray_nth(activetiers, i));
        buf_printf(&key, "*M*%s*", uniqueid);
        r = cyrusdb_fetch(db, key.s, key.len, &data, &datalen, (struct txn **)NULL);

        /* Fall back to the lower tiers if we haven't merged all tiers. */
        if (r == CYRUSDB_NOTFOUND && !do_cache) {
            buf_reset(&path);
            buf_printf(&path, "%s%s", strarray_nth(activedirs, i), INDEXEDDB_FNAME);
            r = open_indexed(buf_cstring(&path), 0, &srcdb);
            if (r) {
                syslog(LOG_ERR, "read_indexed: can't open db %s: %s",
                        buf_cstring(&path), cyrusdb_strerror(r));
                goto out;
            }
            buf_reset(&key);
            buf_printf(&key, "*M*%s*", uniqueid);
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
                         const char *uniqueid,
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
        syslog(LOG_INFO, "write_indexed db=%s uniqueid=%s uids=%s",
               buf_cstring(&path), uniqueid, str);
        free(str);
    }

    buf_printf(&key, "*M*%s*", uniqueid);

    r = open_indexed(buf_cstring(&path), CYRUSDB_CREATE, &db);
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

static int copy_files(const char *fromdir, const char *todir)
{
    char *fromdir2 = strconcat(fromdir, "/", (char *)NULL);
    int r = run_command(RSYNC_BIN, "-a", fromdir2, todir, (char *)NULL);

    free(fromdir2);
    return r;
}

/* ====================================================================== */

/* shared lock for xapian dbs */
struct xapiandb_lock {
    struct mappedfile *activefile;
    struct mboxlock *namelock;
    strarray_t *activedirs;
    strarray_t *activetiers;
    xapian_db_t *db;
};

#define XAPIANDB_LOCK_INITIALIZER { NULL, NULL, NULL, NULL, NULL }

static void xapiandb_lock_release(struct xapiandb_lock *lock)
{
    if (lock->db) xapian_db_close(lock->db);

    /* now that the databases are closed, it's safe to unlock
     * the active file */
    if (lock->activefile) {
        mappedfile_unlock(lock->activefile);
        mappedfile_close(&lock->activefile);
    }
    if (lock->namelock) {
        mboxname_release(&lock->namelock);
    }

    strarray_free(lock->activedirs);
    strarray_free(lock->activetiers);

    memset(lock, 0, sizeof(struct xapiandb_lock));
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

    return buf_release(&buf);
}


static int xapiandb_lock_open(struct mailbox *mailbox, struct xapiandb_lock *lock)
{
    strarray_t *active = NULL;
    char *namelock_fname = NULL;
    char *userid = NULL;
    int r = 0;

    assert(lock->namelock == NULL);
    assert(lock->activefile == NULL);
    assert(lock->activedirs == NULL);
    assert(lock->activetiers == NULL);

    /* Do nothing if there is no userid */
    userid = mboxname_to_userid(mailbox->name);
    if (!userid) goto out;

    namelock_fname = xapiandb_namelock_fname_from_userid(userid);

    /* Get a shared lock */
    r = mboxname_lock(namelock_fname, &lock->namelock, LOCK_SHARED);
    if (r) {
        syslog(LOG_ERR, "Could not acquire shared namelock on %s",
                namelock_fname);
        goto out;
    }

    /* need to hold a read-only lock on the activefile file
     * to ensure no databases are deleted out from under us */
    r = activefile_open(mailbox->name, mailbox->part, &lock->activefile, AF_LOCK_READ, &active);
    if (r) goto out;

    /* only try to open directories with databases in them */
    lock->activedirs = activefile_resolve(mailbox->name, mailbox->part, active,
            /*dostat*/1, &lock->activetiers);

    /* open the databases */
    if (lock->activedirs->count) {
        const char **paths = (const char **) lock->activedirs->data;
        r = xapian_db_open(paths, &lock->db);
        if (r) goto out;
    }

out:
    if (r) xapiandb_lock_release(lock);
    strarray_free(active);
    free(namelock_fname);
    free(userid);
    return r;
}

/* ====================================================================== */

#define XAPIAN_SEARCH_OP_DOCTYPE 1025

struct opnode
{
    int op;     /* SEARCH_OP_* or SEARCH_PART_* or XAPIAN_SEARCH_OP_* */
    strarray_t *items;
    struct opnode *next;
    struct opnode *children;
};

typedef struct xapian_builder xapian_builder_t;
struct xapian_builder {
    search_builder_t super;
    struct xapiandb_lock lock;
    struct seqset *indexed;
    struct mailbox *mailbox;
    int opts;
    struct opnode *root;
    ptrarray_t stack;       /* points to opnode* */
    int (*proc)(const char *, uint32_t, uint32_t, const char *, void *);
    int (*proc_guidsearch)(const conv_guidrec_t*,size_t,void*);
    void *rock;
};

static struct opnode *opnode_new(int op, const strarray_t *arg)
{
    struct opnode *on = xzmalloc(sizeof(struct opnode));
    on->op = op;
    on->items = strarray_dup(arg);
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
    strarray_free(on->items);
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
static struct opnode *opnode_deep_copy(const struct opnode *on)
{
    if (!on) return NULL;

    struct opnode *clone = opnode_new(on->op, on->items);
    const struct opnode *child;
    for (child = on->children; child; child = child->next) {
        opnode_append_child(clone, opnode_deep_copy(child));
    }
    return clone;
}

static const char *opnode_serialise(struct buf *buf, const struct opnode *on)
{
    if (!on) return "";

    buf_putc(buf, '(');

    if (on->op < SEARCH_NUM_PARTS) {
        buf_appendcstr(buf, "MATCH");
        buf_putc(buf, ' ');
        const char *part = search_part_as_string(on->op);
        buf_appendcstr(buf, part ? part : "ANY");
    }
    else if (on->op == SEARCH_OP_AND)
        buf_appendcstr(buf, "AND");
    else if (on->op == SEARCH_OP_OR)
        buf_appendcstr(buf, "OR");
    else if (on->op == SEARCH_OP_NOT)
        buf_appendcstr(buf, "NOT");
    else if (on->op == SEARCH_OP_TRUE)
        buf_appendcstr(buf, "TRUE");
    else if (on->op == SEARCH_OP_FALSE)
        buf_appendcstr(buf, "FALSE");
    else if (on->op == XAPIAN_SEARCH_OP_DOCTYPE)
        buf_appendcstr(buf, "DOCTYPE");
    else
        buf_appendcstr(buf, "UNKNOWN");

    if (on->items) {
        buf_putc(buf, ' ');
        buf_putc(buf, '(');
        int i = 0;
        for (i = 0; i < strarray_size(on->items); i++) {
            if (i) buf_putc(buf, ' ');
            buf_putc(buf, '"');
            buf_appendcstr(buf, strarray_nth(on->items, i));
            buf_putc(buf, '"');
        }
        buf_putc(buf, ')');
    }

    if (on->children) {
        buf_putc(buf, ' ');
        const struct opnode *child;
        for (child = on->children ; child ; child = child->next) {
            opnode_serialise(buf, child);
        }
    }

    buf_putc(buf, ')');

    return buf_cstring(buf);
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

static xapian_query_t *opnode_to_query(const xapian_db_t *db, struct opnode *on, int opts)
{
    struct opnode *child;
    xapian_query_t *qq = NULL;
    int i, j;
    ptrarray_t childqueries = PTRARRAY_INITIALIZER;

    if (!on) return xapian_query_new_matchall(db);

    switch (on->op) {
    case SEARCH_OP_TRUE:
        qq = xapian_query_new_matchall(db);
        break;
    case SEARCH_OP_FALSE:
        qq = xapian_query_new_not(db, xapian_query_new_matchall(db));
        break;
    case SEARCH_OP_NOT:
        if (on->children)
            qq = xapian_query_new_not(db, opnode_to_query(db, on->children, opts));
        break;
    case SEARCH_OP_OR:
    case SEARCH_OP_AND:
        for (child = on->children ; child ; child = child->next) {
            qq = opnode_to_query(db, child, opts);
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
            switch (i) {
                case SEARCH_PART_LISTID:
                case SEARCH_PART_TYPE:
                case SEARCH_PART_LANGUAGE:
                case SEARCH_PART_PRIORITY:
                    continue;
                case SEARCH_PART_ATTACHMENTBODY:
                    if (!(opts & SEARCH_ATTACHMENTS_IN_ANY)) {
                        continue;
                    }
                    // fallthrough
            }
            for (j = 0; j < strarray_size(on->items); j++) {
                void *q = xapian_query_new_match(db, i, strarray_nth(on->items, j));
                if (q) ptrarray_push(&childqueries, q);
            }
        }
        qq = xapian_query_new_compound(db, /*is_or*/1,
                                       (xapian_query_t **)childqueries.data,
                                       childqueries.count);
        break;
    case XAPIAN_SEARCH_OP_DOCTYPE:
        assert(on->items != NULL && strarray_size(on->items));
        const char *val = strarray_nth(on->items, 0);
        qq = xapian_query_new_has_doctype(db, val[0], NULL);
        break;
    default:
        assert(on->items != NULL);
        assert(on->children == NULL);
        if (strarray_size(on->items) > 1) {
            for (j = 0; j < strarray_size(on->items); j++) {
                void *q = xapian_query_new_match(db, on->op, strarray_nth(on->items, j));
                if (q) ptrarray_push(&childqueries, q);
            }
            qq = xapian_query_new_compound(db, /*is_or*/1,
                                           (xapian_query_t **)childqueries.data,
                                           childqueries.count);
        }
        else {
            qq = xapian_query_new_match(db, on->op, strarray_nth(on->items, 0));
        }
        break;
    }
    ptrarray_fini(&childqueries);
    return qq;
}

static int is_dnfclause(const struct opnode *on)
{
    if (on->op < SEARCH_NUM_PARTS) {
        return 1;
    }

    if (on->op == SEARCH_OP_TRUE || on->op == SEARCH_OP_FALSE) {
        return 1;
    }

    if (on->op == SEARCH_OP_NOT) {
        const struct opnode *child;
        for (child = on->children; child; child = child->next) {
            if (child->op >= SEARCH_NUM_PARTS)
                return 0;
        }
        return 1;
    }

    if (on->op == SEARCH_OP_AND) {
        const struct opnode *child;
        for (child = on->children; child; child = child->next) {
            if (child->op < SEARCH_NUM_PARTS ||
                child->op == SEARCH_OP_TRUE ||
                child->op == SEARCH_OP_FALSE) {
                continue;
            }
            else if (child->op == SEARCH_OP_NOT) {
                const struct opnode *gchild;
                for (gchild = child->children; gchild; gchild = gchild->next) {
                    if (gchild->op >= SEARCH_NUM_PARTS &&
                        gchild->op < XAPIAN_SEARCH_OP_DOCTYPE) {
                        return 0;
                    }
                }
                continue;
            }
            else return 0;
        }
        return 1;
    }

    return 0;
}

static int is_orclause(const struct opnode *on)
{
    if (on->op != SEARCH_OP_OR) {
        return 0;
    }

    const struct opnode *child;
    for (child = on->children; child; child = child->next) {
        if (child->op < SEARCH_NUM_PARTS ||
                child->op >= XAPIAN_SEARCH_OP_DOCTYPE) {
            // A MATCH or our own extensions are OK.
            continue;
        }
        else if (child->op != SEARCH_OP_OR) {
            // Not an OR operator.
            return 0;
        }
        else if (!is_orclause(child)) {
            // Not a pure OR subclause.
            return 0;
        }
    }

    return 1;
}

static int normalise_dnfclause(const struct opnode *expr, struct opnode **normalised)
{
    /* Normalise DNF clause expr to an AND clause, with each child
     * expression being a part MATCH or single-valued NOT. */

    struct opnode *root = opnode_deep_copy(expr);

    if (root->op == SEARCH_OP_NOT) {
        /* Convert NOT(x,y) to AND(NOT(x),NOT(y)) */
        struct opnode *newroot = opnode_new(SEARCH_OP_AND, NULL);
        while (root->children) {
            struct opnode *child = root->children;
            opnode_detach_child(root, child);
            struct opnode *notchild = opnode_new(SEARCH_OP_NOT, NULL);
            opnode_append_child(notchild, child);
            opnode_append_child(newroot, notchild);
        }
        opnode_delete(root);
        root = newroot;
    }
    else if (root->op < SEARCH_NUM_PARTS) {
        /* Convert MATCH to AND(MATCH) */
        struct opnode *newroot = opnode_new(SEARCH_OP_AND, NULL);
        opnode_append_child(newroot, root);
        root = newroot;
    }

    struct opnode *child = root->children;
    while (child) {
        /* Convert AND(NOT(x,y)) to AND(NOT(x),NOT(y)) */
        if (child->op != SEARCH_OP_NOT) {
            child = child->next;
            continue;
        }
        if (!child->children || !child->children->next) {
            child = child->next;
            continue;
        }
        while (child->children) {
            struct opnode *grandchild = child->children;
            opnode_detach_child(child, grandchild);
            struct opnode *notgrandchild = opnode_new(SEARCH_OP_NOT, NULL);
            opnode_append_child(notgrandchild, grandchild);
            opnode_append_child(root, notgrandchild);
        }
        struct opnode *next = child->next;
        opnode_detach_child(root, child);
        opnode_delete(child);
        child = next;
    }

    *normalised = root;
    return 0;
}

static int xapian_run_guid_cb(const conv_guidrec_t *rec, void *rock)
{
    xapian_builder_t *bb = rock;

    if (!(bb->opts & SEARCH_MULTIPLE)) {
        if (conversations_guid_mbox_cmp(rec, bb->mailbox))
            return 0;
    }

    mbentry_t *mbentry = NULL;
    int r = mboxlist_lookup_by_guidrec(rec, &mbentry, NULL);

    r = bb->proc(mbentry->name, 0, rec->uid, rec->part, bb->rock);

    mboxlist_entry_free(&mbentry);

    return r;
}


static int memcmp40(const void *a, const void *b)
{
    return memcmp(a, b, 40);
}

static int xapian_run_cb(void *data, size_t nmemb, void *rock)
{
    xapian_builder_t *bb = rock;

    int r = cmd_cancelled(/*insearch*/1);
    if (r) return r;

    struct conversations_state *cstate = mailbox_get_cstate(bb->mailbox);
    if (!cstate) {
        syslog(LOG_INFO, "search_xapian: can't open conversations for %s",
               bb->mailbox->name);
        return IMAP_NOTFOUND;
    }

    qsort(data, nmemb, 41, memcmp40); // byte 41 is always zero

    return conversations_iterate_searchset(cstate, data, nmemb, xapian_run_guid_cb, bb);
}

struct xapian_run_guidsearch_rock {
    xapian_builder_t *bb;
    size_t total;
};

static int xapian_run_guidsearch_guid_cb(const conv_guidrec_t *rec, void *rock)
{
    struct xapian_run_guidsearch_rock *xrock = rock;
    xapian_builder_t *bb = xrock->bb;
    return bb->proc_guidsearch(rec, xrock->total, bb->rock);
}

static int xapian_run_guidsearch_cb(void *data, size_t nmemb, void *rock)
{
    xapian_builder_t *bb = rock;

    int r = cmd_cancelled(/*insearch*/1);
    if (r) return r;

    struct conversations_state *cstate = mailbox_get_cstate(bb->mailbox);
    if (!cstate) return IMAP_NOTFOUND;

    qsort(data, nmemb, 41, memcmp40); // byte 41 is always zero

    struct xapian_run_guidsearch_rock xrock = { bb, nmemb };
    return conversations_iterate_searchset(cstate, data, nmemb,
                                    xapian_run_guidsearch_guid_cb, &xrock);
}

static int validate_query(xapian_db_t *db, struct opnode *on)
{
    if (!on) return 0;
    struct opnode *child;
    for (child = on->children ; child ; child = child->next) {
        int r = validate_query(db, child);
        if (r) return r;
    }

    return 0;
}

static int run_query(xapian_builder_t *bb)
{
    struct opnode *root = NULL;
    xapian_query_t *xq = NULL;
    int r = 0;

    /* Validate query for this db */
    r = validate_query(bb->lock.db, bb->root);
    if (r) return r;

    if (bb->proc_guidsearch) {
        xq = opnode_to_query(bb->lock.db, bb->root, bb->opts);
        if (!xq) goto out;

        r = xapian_query_run(bb->lock.db, xq, xapian_run_guidsearch_cb, bb);
        goto out;
    }

    /* Fallback to UID search */

    if (bb->root && is_dnfclause(bb->root)) {
        struct opnode *norm = NULL;
        r = normalise_dnfclause(bb->root, &norm);
        if (r) return r;

        assert(norm->op == SEARCH_OP_AND);

        /* Exclude P doctypes from matches for headers or ANY */
        root = opnode_new(SEARCH_OP_AND, NULL);
        while (norm->children) {
            struct opnode *child = norm->children;
            opnode_detach_child(norm, child);
            if (child->op != SEARCH_OP_NOT) {
                opnode_append_child(root, child);
                continue;
            }
            struct opnode *expr = child->children;
            if (expr->op >= SEARCH_NUM_PARTS) {
                opnode_append_child(root, child);
                continue;
            }
            if (!search_part_is_body(expr->op) || expr->op == SEARCH_PART_ANY) {
                /* Transform NOT(MATCH) to AND(NOT(MATCH),NOT(DOCTYPE==P)) */
                struct opnode *notdp = opnode_new(SEARCH_OP_NOT, NULL);
                strarray_t ar = STRARRAY_INITIALIZER;
                strarray_append(&ar, "P");
                opnode_append_child(notdp, opnode_new(XAPIAN_SEARCH_OP_DOCTYPE, &ar));
                strarray_fini(&ar);
                struct opnode *node = opnode_new(SEARCH_OP_AND, NULL);
                opnode_append_child(node, child);
                opnode_append_child(node, notdp);
                opnode_append_child(root, node);
            }
        }
        opnode_delete(norm);
    }
    else if (bb->root && is_orclause(bb->root)) {
        root = bb->root;
    }
    else if (bb->root) {
        struct buf buf = BUF_INITIALIZER;
        opnode_serialise(&buf, bb->root);
        syslog(LOG_ERR, "search_xapian: expected DNF or OR clause, got %s",
                buf_cstring(&buf));
        buf_free(&buf);
        r = IMAP_INTERNAL;
        goto out;
    }

    xq = opnode_to_query(bb->lock.db, root, bb->opts);
    if (!xq) goto out;

    struct conversations_state *cstate = mailbox_get_cstate(bb->mailbox);
    if (!cstate) {
        syslog(LOG_INFO, "search_xapian: can't open conversations for %s",
                bb->mailbox->name);
        r = IMAP_NOTFOUND;
        goto out;
    }
    // sort the response by GUID for more efficient later handling
    r = xapian_query_run(bb->lock.db, xq, xapian_run_cb, bb);

out:
    if (root && root != bb->root) opnode_delete(root);
    xapian_query_free(xq);
    return r;
}

static void add_stemmers(xapian_db_t *db, struct opnode *on)
{
    if (!on) return;

    if (on->op == SEARCH_PART_LANGUAGE) {
        int i;
        for (i = 0; i < strarray_size(on->items); i++) {
            xapian_query_add_stemmer(db, strarray_nth(on->items, i));
        }
    }
    struct opnode *child;
    for (child = on->children ; child ; child = child->next) {
        add_stemmers(db, child);
    }
}

static int run_internal(xapian_builder_t *bb)
{
    int r = 0;

    /* Sanity check builder */
    assert((bb->proc == NULL) != (bb->proc_guidsearch == NULL));

    if (!bb->lock.db) return 0; // no index for this user

    /* Validate config */
    r = check_config(NULL);
    if (r) return r;

    if (bb->root) optimise_nodes(NULL, bb->root);

    /* Stem using any languages explicitly requested by the user. */
    add_stemmers(bb->lock.db, bb->root);

    return run_query(bb);
}

static int run(search_builder_t *bx, search_hit_cb_t proc, void *rock)
{
    xapian_builder_t *bb = (xapian_builder_t *)bx;
    bb->proc = proc;
    bb->rock = rock;
    return run_internal(bb);
}

static int run_guidsearch(search_builder_t *bx, search_hitguid_cb_t proc, void *rock)
{
    xapian_builder_t *bb = (xapian_builder_t *)bx;
    bb->proc_guidsearch = proc;
    bb->rock = rock;
    if (!bb->lock.db) return IMAP_SEARCH_NOT_SUPPORTED;
    return run_internal(bb);
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

static void matchlist(search_builder_t *bx, int part, const strarray_t *vals)
{
    xapian_builder_t *bb = (xapian_builder_t *)bx;
    struct opnode *top = ptrarray_tail(&bb->stack);
    struct opnode *on;

    if (!vals) return;
    if (SEARCH_VERBOSE(bb->opts)) {
        char *item = strarray_join(vals, ",");
        syslog(LOG_INFO, "match(part=%s, str=\"%s\")",
               search_part_as_string(part), item);
        free(item);
    }

    on = opnode_new(part, vals);
    if (top)
        opnode_append_child(top, on);
    else
        bb->root = on;
}

static void match(search_builder_t *bx, int part, const char *val)
{
    strarray_t items = STRARRAY_INITIALIZER;
    strarray_append(&items, val);
    matchlist(bx, part, &items);
    strarray_fini(&items);
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

static search_builder_t *begin_search(struct mailbox *mailbox, int opts)
{
    int r = check_config(NULL);
    if (r) return NULL;

    xapian_builder_t *bb = xzmalloc(sizeof(xapian_builder_t));
    bb->super.begin_boolean = begin_boolean;
    bb->super.end_boolean = end_boolean;
    bb->super.match = match;
    bb->super.matchlist = matchlist;
    bb->super.get_internalised = get_internalised;
    bb->super.run = run;
    bb->super.run_guidsearch = run_guidsearch;

    bb->mailbox = mailbox;
    bb->opts = opts;

    r = xapiandb_lock_open(mailbox, &bb->lock);
    if (r) goto out;
    if (!bb->lock.activedirs || !bb->lock.activedirs->count) goto out;

    /* read the list of all indexed messages to allow (optional) false positives
     * for unindexed messages */
    // TODO also handle for guidsearch
    bb->indexed = seqset_init(0, SEQ_MERGE);
    r = read_indexed(bb->lock.activedirs, bb->lock.activetiers, mailbox->uniqueid,
                     bb->indexed, /*do_cache*/0, /*verbose*/0);
    if (r) goto out;

out:
    /* XXX - error return? */
    return &bb->super;
}

static void end_search(search_builder_t *bx)
{
    xapian_builder_t *bb = (xapian_builder_t *)bx;

    if (bb->indexed) seqset_free(bb->indexed);
    ptrarray_fini(&bb->stack);
    if (bb->root) opnode_delete(bb->root);

    xapiandb_lock_release(&bb->lock);

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
    time_t internaldate;
    int part;
    const struct message_guid *part_guid;
    const char *partid;
    unsigned int part_total;
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
    int flags;
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
    struct xapiandb_lock lock;
    const search_snippet_markup_t *markup;
};

struct is_indexed_rock {
    xapian_update_receiver_t *tr;
    char doctype;
};

static int is_indexed_cb(const conv_guidrec_t *rec, void *rock);

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
EXPORTED int xapian_basedir(const char *tier,
                          const char *mboxname, const char *partition,
                          const char *root, char **basedirp)
{
    char *basedir = NULL;
    mbname_t *mbname = NULL;
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

    char *inboxname = mboxname_user_mbox(mbname_userid(mbname), NULL);
    mbentry_t *mbentry = NULL;

    r = mboxlist_lookup(inboxname, &mbentry, NULL);
    free(inboxname);
    if (r) goto out;

    if (mbentry->mbtype & MBTYPE_LEGACY_DIRS) {
        const char *domain = mbname_domain(mbname);
        const char *localpart = mbname_localpart(mbname);
        char c[2], d[2];

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
    }
    else {
        char path[MAX_MAILBOX_PATH+1];
        mboxname_id_hash(path, MAX_MAILBOX_PATH, "", mbentry->uniqueid);

        basedir = strconcat(root,
                            FNAME_USERDIR,
                            path,
                            (char *)NULL);
    }
    mboxlist_entry_free(&mbentry);

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
                          tr->super.mailbox->uniqueid, tr->indexed,
                          tr->super.verbose);
        if (r) goto out;
    }

out:
    return r;
}

static int audit_mailbox(search_text_receiver_t *rx, bitvector_t *unindexed)
{
    xapian_update_receiver_t *tr = (xapian_update_receiver_t *)rx;
    struct mailbox_iter *iter = NULL;
    const message_t *msg = NULL;
    int r = 0;

    if (tr->mode != XAPIAN_DBW_XAPINDEXED) {
        syslog(LOG_ERR, "search_xapian: require XAPIAN_DBW_XAPINDEXED mode");
        r = IMAP_INTERNAL;
        goto done;
    }

    iter = mailbox_iter_init(tr->super.mailbox, 0, ITER_SKIP_UNLINKED);

    while ((msg = mailbox_iter_step(iter))) {
        uint32_t uid;
        r = message_get_uid((message_t*) msg, &uid);
        if (r) goto done;

        if (!seqset_ismember(tr->oldindexed, uid)) {
            if (tr->super.verbose)
                syslog(LOG_INFO, "search_xapian: ignoring %s:%d during audit",
                        tr->super.mailbox->name, uid);
            continue;
        }

        const struct message_guid *guid;
        r = message_get_guid((message_t*) msg, &guid);
        if (r) goto done;

        uint8_t indexlevel = xapian_dbw_is_indexed(tr->dbw, guid, XAPIAN_WRAP_DOCTYPE_MSG);
        if (indexlevel == 0 || (indexlevel & SEARCH_INDEXLEVEL_PARTIAL)) {
            bv_set(unindexed, uid);
        }
    }

done:
    mailbox_iter_done(&iter);
    return r;
}

static void free_segments(xapian_receiver_t *tr)
{
    int i;
    struct segment *seg;

    for (i = 0 ; i < tr->segs.count ; i++) {
        seg = (struct segment *)ptrarray_nth(&tr->segs, i);
        buf_free(&seg->text);
        free(seg->partid);
        free(seg);
    }
    ptrarray_truncate(&tr->segs, 0);
}

static int begin_message(search_text_receiver_t *rx, message_t *msg)
{
    xapian_update_receiver_t *tr = (xapian_update_receiver_t *)rx;
    const struct message_guid *guid = NULL;

    int r = message_get_uid(msg, &tr->super.uid);
    if (!r) r = message_get_guid(msg, &guid);
    if (!r) r = message_get_internaldate(msg, &tr->super.internaldate);
    if (r) return r;

    message_guid_copy(&tr->super.guid, guid);
    free_segments((xapian_receiver_t *)tr);
    return 0;
}

static int begin_bodypart(search_text_receiver_t *rx,
                          const char *partid,
                          const struct message_guid *content_guid,
                          const char *type __attribute__((unused)),
                          const char *subtype __attribute__((unused)))
{
    xapian_receiver_t *tr = (xapian_receiver_t *)rx;
    tr->partid = partid;
    tr->part_guid = content_guid;
    return 0;
}

static void begin_part(search_text_receiver_t *rx, int part)
{
    xapian_receiver_t *tr = (xapian_receiver_t *)rx;

    tr->part = part;
    tr->part_total = 0;
}

static int append_text(search_text_receiver_t *rx,
                       const struct buf *text)
{
    xapian_receiver_t *tr = (xapian_receiver_t *)rx;
    struct segment *seg;

    if (tr->part) {
        unsigned len = text->len;
        if (tr->part_total + len > config_search_maxsize) {
            syslog(LOG_ERR, "Xapian: truncating text from "
                    "message mailbox %s uid %u part %s",
                    tr->mailbox->name, tr->uid,
                    search_part_as_string(tr->part));
            len = config_search_maxsize - tr->part_total;
        }

        if (len) {
            tr->part_total += len;

            seg = (struct segment *)ptrarray_tail(&tr->segs);
            if (!seg || seg->is_finished || seg->part != tr->part) {
                seg = (struct segment *)xzmalloc(sizeof(*seg));
                seg->sequence = tr->segs.count;
                seg->part = tr->part;
                seg->partid = xstrdupnull(tr->partid);
                if (tr->part_guid && search_part_is_body(tr->part)) {
                    message_guid_copy(&seg->guid, tr->part_guid);
                    seg->doctype = XAPIAN_WRAP_DOCTYPE_PART;
                } else {
                    message_guid_copy(&seg->guid, &tr->guid);
                    seg->doctype = XAPIAN_WRAP_DOCTYPE_MSG;
                }
                ptrarray_append(&tr->segs, seg);
            }
            buf_appendmap(&seg->text, text->s, len);
        }
    }

    if (tr->part_total >= config_search_maxsize) {
        return IMAP_MESSAGE_TOO_LARGE;
    }

    return 0;
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

static void end_bodypart(search_text_receiver_t *rx __attribute__((unused)))
{
    xapian_receiver_t *tr = (xapian_receiver_t *)rx;
    tr->partid = NULL;
    tr->part_guid = NULL;
}

static int doctype_cmp(char doctype1, char doctype2)
{
    if (doctype1 == XAPIAN_WRAP_DOCTYPE_MSG &&
        doctype2 != XAPIAN_WRAP_DOCTYPE_MSG) return -1;

    if (doctype1 != XAPIAN_WRAP_DOCTYPE_MSG &&
        doctype2 == XAPIAN_WRAP_DOCTYPE_MSG) return 1;

    return doctype1 - doctype2;
}

static int compare_segs(const void **v1, const void **v2)
{
    const struct segment *s1 = *(const struct segment **)v1;
    const struct segment *s2 = *(const struct segment **)v2;
    int r;

    r = doctype_cmp(s1->doctype, s2->doctype);
    if (!r)
        r = message_guid_cmp(&s1->guid, &s2->guid);
    if (!r)
        r = strcmpsafe(s1->partid, s2->partid);
    if (!r)
        r = s1->part - s2->part;
    if (!r)
        r = s1->sequence - s2->sequence;
    return r;
}

static int is_indexed_part(xapian_update_receiver_t *tr, const struct message_guid *guid)
{
    if (tr->mode == XAPIAN_DBW_XAPINDEXED) {
        return xapian_dbw_is_indexed(tr->dbw, guid, XAPIAN_WRAP_DOCTYPE_PART);
    }

    struct conversations_state *cstate = mailbox_get_cstate(tr->super.mailbox);
    if (!cstate) {
        xsyslog(LOG_INFO, "can't open conversations", "mailbox=<%s>",
                tr->super.mailbox->name);
        return 0;
    }

    int ret = 0;
    char *guidrep = xstrdup(message_guid_encode(guid));
    struct is_indexed_rock rock = { tr, XAPIAN_WRAP_DOCTYPE_PART };
    int r = conversations_guid_foreach(cstate, guidrep, is_indexed_cb, &rock);
    if (r == CYRUSDB_DONE) ret = SEARCH_INDEXLEVEL_BASIC;
    else if (r) {
        xsyslog(LOG_ERR, "unexpected return code", "guid=<%s> r=<%d> err=<%s>",
                message_guid_encode(guid), r, cyrusdb_strerror(r));
    }
    free(guidrep);

    return ret;
}

static int end_message_update(search_text_receiver_t *rx, uint8_t indexlevel)
{
    xapian_update_receiver_t *tr = (xapian_update_receiver_t *)rx;
    int i;
    struct segment *seg;
    int r = 0;

    if (!tr->dbw) {
        r = xapian_dbw_open((const char **)tr->activedirs->data, &tr->dbw, tr->mode, /*nosync*/0);
        if (r) goto out;
    }

    ptrarray_sort(&tr->super.segs, compare_segs);

    // index headers and body parts with message guid
    if (!tr->uncommitted) {
        r = xapian_dbw_begin_txn(tr->dbw);
        if (r) goto out;
    }
    r = xapian_dbw_begin_doc(tr->dbw, &tr->super.guid, XAPIAN_WRAP_DOCTYPE_MSG);
    if (r) goto out;
    for (i = 0 ; i < tr->super.segs.count ; i++) {
        seg = (struct segment *)ptrarray_nth(&tr->super.segs, i);
        r = xapian_dbw_doc_part(tr->dbw, &seg->text, seg->part);
        if (r) goto out;
    }
    r = xapian_dbw_end_doc(tr->dbw, indexlevel);
    if (r) goto out;
    ++tr->uncommitted;

    // index body parts with content guid
    const struct message_guid *last_guid = NULL;
    for (i = 0 ; i < tr->super.segs.count ; i++) {
        seg = (struct segment *)ptrarray_nth(&tr->super.segs, i);
        if (seg->doctype == XAPIAN_WRAP_DOCTYPE_MSG) continue;

        if (!last_guid || message_guid_cmp(last_guid, &seg->guid)) {
            if (last_guid) {
                // finalize indexing of previous part
                r = xapian_dbw_end_doc(tr->dbw, SEARCH_INDEXLEVEL_BASIC);
                if (r) goto out;
                ++tr->uncommitted;
                last_guid = NULL;
            }

            if (!(tr->flags & SEARCH_UPDATE_ALLOW_DUPPARTS) &&
                    is_indexed_part(tr, &seg->guid)) {
                continue;
            }

            last_guid = &seg->guid;
            // TODO which internaldate, if any?
            r = xapian_dbw_begin_doc(tr->dbw, &seg->guid, seg->doctype);
            if (r) goto out;
        }
        r = xapian_dbw_doc_part(tr->dbw, &seg->text, seg->part);
        if (r) goto out;
    }
    if (last_guid) {
        // body parts have no index level
        r = xapian_dbw_end_doc(tr->dbw, SEARCH_INDEXLEVEL_BASIC);
        if (r) goto out;
        ++tr->uncommitted;
    }

    /* start the range back at the first unindexed if necessary */
    if (!tr->indexed) {
        tr->indexed = seqset_init(0, SEQ_MERGE);
        /* we want to say that we indexed the entire gap from last time
         * up until this first message as well, so our indexed range
         * isn't gappy */
        seqset_add(tr->indexed, seqset_firstnonmember(tr->oldindexed), 1);
    }
    seqset_add(tr->indexed, tr->super.uid, 1);

out:
    tr->super.uid = 0;
    message_guid_set_null(&tr->super.guid);
    tr->super.internaldate = 0;
    return r;
}

static int _starts_with_tier(const strarray_t *active, const char *tier)
{
    if (!active) return 0;
    if (!active->count) return 0;
    const char *candidate = strarray_nth(active, 0);
    struct activeitem *item = activeitem_parse(candidate);
    int res = !strcmp(item->tier, tier);
    activeitem_free(item);
    return res;
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

    tr->flags = flags;

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
        syslog(LOG_ERR, "Could not acquire shared namelock on %s",
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
    const char *deftier = config_getstring(IMAPOPT_DEFAULTSEARCHTIER);
    r = activefile_open(mailbox->name, mailbox->part, &tr->activefile, AF_LOCK_WRITE, &active);
    if (r) {
        syslog(LOG_ERR, "Failed to lock activefile for %s", mailbox->name);
        goto out;
    }

    if (!active) active = strarray_new();

    // make sure we're indexing to the default tier
    while (!_starts_with_tier(active, deftier)) {
        char *newstart = activefile_nextname(active, config_getstring(IMAPOPT_DEFAULTSEARCHTIER));
        syslog(LOG_NOTICE, "create new search tier %s for %s", newstart, mailbox->name);
        strarray_unshiftm(active, newstart);
        r = activefile_write(tr->activefile, active);
        mappedfile_close(&tr->activefile);
        strarray_free(active);
        active = NULL;
        r = activefile_open(mailbox->name, mailbox->part, &tr->activefile, AF_LOCK_WRITE, &active);
        if (r) {
            syslog(LOG_ERR, "Failed to lock activefile for %s", mailbox->name);
            goto out;
        }
    }

    assert(active->count);

    tr->mode = (flags & (SEARCH_UPDATE_XAPINDEXED|SEARCH_UPDATE_AUDIT)) ?
        XAPIAN_DBW_XAPINDEXED : XAPIAN_DBW_CONVINDEXED;

    /* doesn't matter if the first one doesn't exist yet, we'll create it. Only stat the others if we're going
     * to be opening them */
    int dostat = tr->mode == XAPIAN_DBW_XAPINDEXED ? 2 : 0;
    tr->activedirs = activefile_resolve(mailbox->name, mailbox->part, active, dostat, &tr->activetiers);
    // this should never be able to fail here, because the first item will always exist!
    assert(tr->activedirs && tr->activedirs->count);

    /* create the directory if needed */
    r = check_directory(strarray_nth(tr->activedirs, 0), tr->super.verbose, /*create*/1);
    if (r) goto out;

    if (tr->mode == XAPIAN_DBW_XAPINDEXED) {
        /* open the DB now, we need it to check if messages are indexed */
        r = xapian_dbw_open((const char **)tr->activedirs->data, &tr->dbw, tr->mode, /*nosync*/0);
        if (r) goto out;
    }

    /* read the indexed data from every directory so know what still needs indexing */
    tr->oldindexed = seqset_init(0, SEQ_MERGE);

    if ((flags & (SEARCH_UPDATE_INCREMENTAL|SEARCH_UPDATE_AUDIT))) {
        r = read_indexed(tr->activedirs, tr->activetiers, mailbox->uniqueid,
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
    xapian_update_receiver_t *tr = ((struct is_indexed_rock*)rock)->tr;
    char doctype = ((struct is_indexed_rock*)rock)->doctype;

    if (doctype == XAPIAN_WRAP_DOCTYPE_MSG && rec->part) return 0;

    /* Is this a part in the message we are just indexing? */
    if (doctype == XAPIAN_WRAP_DOCTYPE_PART && rec->uid == tr->super.uid &&
         !strcmp(rec->mailbox, (rec->version > CONV_GUIDREC_BYNAME_VERSION) ?
                 tr->super.mailbox->uniqueid : tr->super.mailbox->name)) {
        return 0;
    }

    /* Is this GUID record in the mailbox we are currently indexing? */
    if (!conversations_guid_mbox_cmp(rec, tr->super.mailbox)) {
        if (seqset_ismember(tr->indexed, rec->uid) ||
            seqset_ismember(tr->oldindexed, rec->uid)) {
            return CYRUSDB_DONE;
        }
        return 0;
    }

    /* Is this GUID record in an already cached sequence set? */
    struct seqset *seq = hash_lookup(rec->mailbox, &tr->cached_seqs);
    if (seq) {
        return seqset_ismember(seq, rec->uid) ? CYRUSDB_DONE : 0;
    }

    /* Read the index cache for this mailbox */
    seq = seqset_init(0, SEQ_MERGE);
    int r = 0;

    const char *mboxuniqueid;
    mbentry_t *mbentry = NULL;
    if (rec->version > CONV_GUIDREC_BYNAME_VERSION) {
        mboxuniqueid = rec->mailbox;
    }
    else {
        r = mboxlist_lookup(rec->mailbox, &mbentry, NULL);
        if (r) {
            syslog(LOG_ERR, "is_indexed_cb: mboxlist_lookup %s failed: %s",
                    rec->mailbox, error_message(r));
            goto out;
        }
        mboxuniqueid = mbentry->uniqueid;
    }

    r = read_indexed(tr->activedirs, tr->activetiers, mboxuniqueid,
                     seq, /*do_cache*/1, tr->super.verbose);
    if (mbentry) mboxlist_entry_free(&mbentry);
    if (r) {
        syslog(LOG_ERR, "is_indexed_cb: read_indexed %s failed: %s",
                rec->mailbox, error_message(r));
        goto out;
    }
    hash_insert(rec->mailbox, seq, &tr->cached_seqs);

out:
    if (r) {
        seqset_free(seq);
        return 0;
    }
    return seqset_ismember(seq, rec->uid) ? CYRUSDB_DONE : 0;
}

static uint8_t is_indexed(search_text_receiver_t *rx, message_t *msg)
{
    xapian_update_receiver_t *tr = (xapian_update_receiver_t *)rx;

    uint32_t uid = 0;
    message_get_uid(msg, &uid);

    /* bail early if we've already indexed this message in THIS run */
    if (seqset_ismember(tr->indexed, uid))
        return 1;

    uint8_t ret = 0;

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
        struct is_indexed_rock rock = { tr, XAPIAN_WRAP_DOCTYPE_MSG };
        int r = conversations_guid_foreach(cstate, guidrep, is_indexed_cb, &rock);
        if (r == CYRUSDB_DONE) ret = SEARCH_INDEXLEVEL_BASIC;
        else if (r) {
            syslog(LOG_ERR, "is_indexed %s:%d: unexpected return code: %d (%s)",
                   tr->super.mailbox->name, uid, r, cyrusdb_strerror(r));
        }
        free(guidrep);
    }
    else if (tr->mode == XAPIAN_DBW_XAPINDEXED) {
        // XXX check for all parts of that message?
        ret = xapian_dbw_is_indexed(tr->dbw, guid, XAPIAN_WRAP_DOCTYPE_MSG);
    }

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

    tr->flags = 0;

    return r;
}

static int xapian_charset_flags(int flags)
{
    return (flags|CHARSET_KEEPCASE|CHARSET_MIME_UTF8) & ~CHARSET_SKIPDIACRIT;
}

static int xapian_message_format(int format __attribute__((unused)),
                                 int is_snippet __attribute__((unused)))
{
    return MESSAGE_SNIPPET;
}

static search_text_receiver_t *begin_update(int verbose)
{
    xapian_update_receiver_t *tr;

    if (check_config(NULL)) return NULL;

    tr = xzmalloc(sizeof(xapian_update_receiver_t));
    tr->super.super.begin_mailbox = begin_mailbox_update;
    tr->super.super.first_unindexed_uid = first_unindexed_uid;
    tr->super.super.is_indexed = is_indexed;
    tr->super.super.begin_message = begin_message;
    tr->super.super.begin_bodypart = begin_bodypart;
    tr->super.super.begin_part = begin_part;
    tr->super.super.append_text = append_text;
    tr->super.super.end_part = end_part;
    tr->super.super.end_bodypart = end_bodypart;
    tr->super.super.end_message = end_message_update;
    tr->super.super.end_mailbox = end_mailbox_update;
    tr->super.super.flush = flush;
    tr->super.super.audit_mailbox = audit_mailbox;
    tr->super.super.index_charset_flags = xapian_charset_flags;
    tr->super.super.index_message_format = xapian_message_format;

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

    int r = xapiandb_lock_open(mailbox, &tr->lock);
    if (r) goto out;
    if (!tr->lock.activedirs || !tr->lock.activedirs->count) goto out;

    tr->snipgen = xapian_snipgen_new(tr->lock.db, tr->markup->hi_start,
                                     tr->markup->hi_end, tr->markup->omit);

out:
    return r;
}

/* Find match terms for the given part and add them to the Xapian
 * snippet generator.  */
static void generate_snippet_terms(xapian_snipgen_t *snipgen,
                                   int part,
                                   struct opnode *on)
{
    struct opnode *child;
    int i;

    switch (on->op) {

    case SEARCH_OP_TRUE:
    case SEARCH_OP_FALSE:
        // ignore
        break;

    case SEARCH_OP_NOT:
    case SEARCH_OP_OR:
    case SEARCH_OP_AND:
        for (child = on->children ; child ; child = child->next)
            generate_snippet_terms(snipgen, part, child);
        break;

    case SEARCH_PART_ANY:
        assert(on->children == NULL);
        if (part != SEARCH_PART_HEADERS) {
            for (i = 0; i < strarray_size(on->items); i++)
                xapian_snipgen_add_match(snipgen, strarray_nth(on->items, i));
        }
        break;
    default:
        /* other SEARCH_PART_* constants */
        if (on->op >= 0 && on->op < SEARCH_NUM_PARTS) {
            assert(on->children == NULL);
            if (part == on->op) {
                for (i = 0; i < strarray_size(on->items); i++)
                    xapian_snipgen_add_match(snipgen, strarray_nth(on->items, i));
            }
        }
        break;
    }
}

static int flush_snippets(search_text_receiver_t *rx)
{
    xapian_snippet_receiver_t *tr = (xapian_snippet_receiver_t *)rx;
    struct buf snippets = BUF_INITIALIZER;
    int i;
    struct segment *seg;
    int last_part = -1;
    int r = 0;

    if (!tr->root) {
        goto out;
    }

    if (!tr->lock.activedirs || !tr->lock.activedirs->count) {
        goto out;
    }

    if (!tr->snipgen) {
        r = IMAP_INTERNAL;          /* need to call begin_mailbox() */
        goto out;
    }

    ptrarray_sort(&tr->super.segs, compare_segs);

    const struct message_guid *last_guid = NULL;
    const char *last_partid = NULL;

    for (i = 0 ; i < tr->super.segs.count ; i++) {
        seg = (struct segment *)ptrarray_nth(&tr->super.segs, i);

        if (!last_guid || message_guid_cmp(last_guid, &seg->guid) ||
                strcmpsafe(seg->partid, last_partid) || seg->part != last_part) {
            if (i) {
                /* In contrast to the update code, we start and end a document
                 * for each search part of the same message. This is due to
                 * the way the snippet callbacks are implemented. */
                r = xapian_snipgen_end_doc(tr->snipgen, &snippets);
                if (!r && snippets.len) {
                    r = tr->proc(tr->super.mailbox, tr->super.uid, last_part,
                                 last_partid, snippets.s, tr->rock);
                }
                if (r) goto out;
            }

            if (search_part_is_body(seg->part)) {
                r = xapian_snipgen_begin_doc(tr->snipgen, &seg->guid,
                        XAPIAN_WRAP_DOCTYPE_PART);
            }
            else {
                r = xapian_snipgen_begin_doc(tr->snipgen, &tr->super.guid,
                        XAPIAN_WRAP_DOCTYPE_MSG);
            }
            if (r) break;
            generate_snippet_terms(tr->snipgen, seg->part, tr->root);

            last_guid = &seg->guid;
            last_part = -1;
        }

        r = xapian_snipgen_doc_part(tr->snipgen, &seg->text, seg->part);
        last_partid = seg->partid;
        last_part = seg->part;
        if (r) break;
    }

    if (last_part != -1) {
        r = xapian_snipgen_end_doc(tr->snipgen, &snippets);
        if (!r && snippets.len)
            r = tr->proc(tr->super.mailbox, tr->super.uid, last_part,
                    last_partid, snippets.s, tr->rock);
    }

    free_segments(&tr->super);

out:
    buf_free(&snippets);
    return r;
}

static int end_message_snippets(search_text_receiver_t *rx,
                                uint8_t indexlevel __attribute__((unused)))
{
    return flush_snippets(rx);
}

static int end_mailbox_snippets(search_text_receiver_t *rx,
                                struct mailbox *mailbox
                                    __attribute__((unused)))
{
    xapian_snippet_receiver_t *tr = (xapian_snippet_receiver_t *)rx;

    xapiandb_lock_release(&tr->lock);
    tr->super.mailbox = NULL;
    xapian_snipgen_free(tr->snipgen);
    tr->snipgen = NULL;

    return 0;
}

static search_text_receiver_t *begin_snippets(void *internalised,
                                              int verbose,
                                              search_snippet_markup_t *m,
                                              search_snippet_cb_t proc,
                                              void *rock)
{
    xapian_snippet_receiver_t *tr;

    if (check_config(NULL)) return NULL;

    tr = xzmalloc(sizeof(xapian_snippet_receiver_t));
    tr->super.super.begin_mailbox = begin_mailbox_snippets;
    tr->super.super.begin_message = begin_message;
    tr->super.super.begin_bodypart = begin_bodypart;
    tr->super.super.begin_part = begin_part;
    tr->super.super.append_text = append_text;
    tr->super.super.end_part = end_part;
    tr->super.super.end_bodypart = end_bodypart;
    tr->super.super.end_message = end_message_snippets;
    tr->super.super.end_mailbox = end_mailbox_snippets;
    tr->super.super.flush = flush_snippets;
    tr->super.super.index_charset_flags = xapian_charset_flags;

    tr->super.verbose = verbose;
    tr->root = (struct opnode *)internalised;
    tr->proc = proc;
    tr->rock = rock;
    tr->markup = m;

    return &tr->super.super;
}

static int end_snippets(search_text_receiver_t *rx)
{
    xapian_snippet_receiver_t *tr = (xapian_snippet_receiver_t *)rx;

    xapian_snipgen_free(tr->snipgen);

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
        syslog(LOG_ERR, "Could not acquire shared namelock on %s",
               namelock_fname);
        goto out;
    }

    /* Get a readlock on the activefile */
    r = activefile_open(mboxname, mbentry->partition, &activefile, AF_LOCK_READ, &active);
    if (r) {
        syslog(LOG_ERR, "Couldn't open active file: %s", mboxname);
        goto out;
    }
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
    char *temp_path;
    strarray_t temptargets;
    int numindexed;
    int flags;
};

static void free_mbfilter(struct mbfilter *filter)
{
    int i;

    if (filter->tid) cyrusdb_abort(filter->indexeddb, *filter->tid);
    cyrusdb_close(filter->indexeddb);
    bloom_free(&filter->bloom);

    for (i = 0; i < strarray_size(&filter->temptargets); i++) {
        removedir(strarray_nth(&filter->temptargets, i));
    }
    strarray_fini(&filter->temptargets);

    if (filter->temp_path) {
        removedir(filter->temp_path);
        free(filter->temp_path);
    }
}

static int copyindexed_cb(void *rock,
                         const char *key, size_t keylen,
                         const char *data, size_t datalen)
{
    /* Ignore all but mailbox entries */
    if (keylen < 3 || strncmp(key, "*M*", 3)) return 0;

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

    if (strncmp(cyrusid, "*G*", 3) && strncmp(cyrusid, "*P*", 3)) return 0;

    return bloom_check(&filter->bloom, cyrusid+3, 40);
}

static int bloomadd_cb(void *rock,
                       const char *key,
                       size_t keylen __attribute__((unused)),
                       const char *data __attribute__((unused)),
                       size_t datalen __attribute__((unused)))
{
    struct bloom *bloom = (struct bloom *)rock;
    bloom_add(bloom, key+1, 40);
    return 0;
}

static int create_filter(const strarray_t *srcpaths, const strarray_t *destpaths,
                         const strarray_t *desttiers,
                         const char *userid, int flags, struct mbfilter *filter,
                         int bloom)
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

    r = open_indexed(buf_cstring(&buf), CYRUSDB_CREATE, &filter->indexeddb);
    if (r) {
        printf("ERROR: failed to open indexed %s\n", buf_cstring(&buf));
        goto done;
    }
    for (i = 0; i < srcpaths->count; i++) {
        struct db *db = NULL;
        buf_reset(&buf);
        buf_printf(&buf, "%s%s", strarray_nth(srcpaths, i), INDEXEDDB_FNAME);
        r = open_indexed(buf_cstring(&buf), 0, &db);
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

        r = conversations_open_user(userid, 1/*shared*/, &cstate);
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

    r = create_filter(srcpaths, destpaths, desttiers, userid, flags, &filter, 1);
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
    struct buf buf = BUF_INITIALIZER;
    ptrarray_t batch = PTRARRAY_INITIALIZER;
    int verbose = SEARCH_VERBOSE(filter->flags);
    strarray_t alldirs = STRARRAY_INITIALIZER;
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

    struct mailbox_iter *iter = mailbox_iter_init(mailbox, 0, ITER_SKIP_UNLINKED);
    mailbox_iter_startuid(iter, seqset_first(seq));

    const message_t *msg;
    while ((msg = mailbox_iter_step(iter))) {
        const struct index_record *record = msg_record(msg);
        /* it wasn't in the previous index, skip it */
        if (!seqset_ismember(seq, record->uid))
            continue;

        /* we need to create a new message, because the iterator reuses its one */
        ptrarray_append(&batch, (void *)message_new_from_record(mailbox, record));

        if (record->uid > seqset_last(seq))
            break;
    }

    mailbox_iter_done(&iter);

    mailbox_unlock_index(mailbox, NULL);

    // nothing to do?  Bonus!
    if (!ptrarray_size(&batch)) goto done;

    /* open the DB */
    tr = (xapian_update_receiver_t *)begin_update(verbose);
    tr->mode = XAPIAN_DBW_XAPINDEXED; // always use XAPINDEXED for reindex, so we reindex the same emails
    tr->super.mailbox = mailbox;
    tr->activedirs = strarray_dup(filter->destpaths);
    tr->activetiers = strarray_dup(filter->desttiers);
    // include all the new databases too
    strarray_cat(&alldirs, &filter->temptargets);
    // skip the first one, there's no data in there!
    for (i = 1; i < strarray_size(filter->destpaths); i++)
        strarray_append(&alldirs, strarray_nth(filter->destpaths, i));

    r = xapian_dbw_open((const char **)alldirs.data, &tr->dbw, tr->mode, /*nosync*/1);
    if (r) goto done;

    /* initialise here so it doesn't add firstunindexed
     * from oldindexed in is_indexed */
    tr->indexed = seqset_init(0, SEQ_MERGE);

    int allow_partials = 0;
    int getsearchtext_flags = 0;
    if (filter->flags & SEARCH_COMPACT_ALLOW_PARTIALS) {
        allow_partials = 1;
        getsearchtext_flags |= INDEX_GETSEARCHTEXT_PARTIALS;
    }

    int base = 0;
    int batchend = 0;
    for (base = 0; base < batch.count; base = batchend) {
        /* XXX - errors here could leak... */
        /* game on */
        batchend = base + 1024;
        if (batchend > batch.count) batchend = batch.count;

        /* preload */
        for (i = base ; i < batchend ; i++) {
            message_t *msg = ptrarray_nth(&batch, i);

            /* add the record to the list */
            uint8_t indexlevel = is_indexed((search_text_receiver_t *)tr, msg);
            if (indexlevel == 0 || ((indexlevel & SEARCH_INDEXLEVEL_PARTIAL) && !allow_partials)) {
                const char *fname;
                r = message_get_fname(msg, &fname);
                if (r) goto done;
                r = warmup_file(fname, 0, 0);
                if (r) goto done; /* means we failed to open a file,
                                     so we'll fail later anyway */
            }
            else {
                // remove it from the list now so we don't try to index it later
                message_unref(&msg);
                ptrarray_set(&batch, i, NULL);
            }
        }

        /* index the messages */
        for (i = base ; i < batchend ; i++) {
            message_t *msg = ptrarray_nth(&batch, i);
            if (!msg) continue;

            r = index_getsearchtext(msg, NULL, &tr->super.super, getsearchtext_flags);
            // we must unref the message and then zero out the entry in the ptrarray
            // now, because index_getsearchtext will have mapped the file in, and even
            // if we decided not to index it, we won't need it again
            message_unref(&msg);
            ptrarray_set(&batch, i, NULL);
            if (r) goto done;

            filter->numindexed++;
        }

        // the next write will start a new transaction if uncommitted == 0
        if (tr->uncommitted) {
            r = xapian_dbw_commit_txn(tr->dbw);
            if (r) goto done;
            tr->uncommitted = 0;
            tr->commits++;

            // we don't want to blow out the temporary space, so let's split every so often!
            if (filter->numindexed > XAPIAN_REINDEX_TEMPDIR_COUNT ||
                xapian_dbw_total_length(tr->dbw) > XAPIAN_REINDEX_TEMPDIR_SIZE) {
                // close the database, move the data, open a new database with a new target!  Yikes
                xapian_dbw_close(tr->dbw);
                // we move the existing temp database to the same partition as the target, then
                // start up a brand new temp database at the same path!
                // e.g. temp == /tmpfs/cyrus-tempXXX-reindex/xapian
                //      buf  == /mnt/searchdrive/path/to/user/xapian.23.REINDEX.NEW.<num>
                buf_reset(&buf);
                buf_printf(&buf, "%s.%d", strarray_nth(filter->destpaths, 0), (int)strarray_size(&filter->temptargets));
                const char *temp = strarray_nth(&filter->temptargets, 0);
                syslog(LOG_DEBUG, "REINDEX: chunking %s to %s", temp, buf_cstring(&buf));
                r = copy_files(temp, buf_cstring(&buf));
                removedir(temp);
                // insert the new path directly after the temporary directory
                strarray_insert(&filter->temptargets, 1, buf_cstring(&buf));
                // and also open it for the next writes
                strarray_insert(&alldirs, 1, buf_cstring(&buf));

                // finally, re-open the database on the new empty directory with the extra path added
                if (!r) r = xapian_dbw_open((const char **)alldirs.data, &tr->dbw, tr->mode, /*nosync*/1);
                if (r) goto done;
                filter->numindexed = 0;
            }
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
    for (i = 0; i < batch.count; i++) {
        message_t *msg = ptrarray_nth(&batch, i);
        message_unref(&msg);
    }
    ptrarray_fini(&batch);
    free(mboxname);
    seqset_free(seq);
    strarray_fini(&alldirs);
    buf_free(&buf);
    return r;
}

static int search_reindex(const char *userid, const strarray_t *srcpaths,
                          const strarray_t *destpaths, const strarray_t *desttiers, int flags)
{
    struct buf buf = BUF_INITIALIZER;
    struct mbfilter filter;
    int verbose = SEARCH_VERBOSE(flags);
    int r;

    r = create_filter(srcpaths, destpaths, desttiers, userid, flags, &filter, 0);
    if (r) goto done;

    if (verbose)
        printf("Reindexing messages for %s\n", userid);

    // set up temporary target
    filter.temp_path = create_tempdir(config_getstring(IMAPOPT_TEMP_PATH), "reindex");
    buf_printf(&buf, "%s/xapian", filter.temp_path);
    strarray_append(&filter.temptargets, buf_cstring(&buf));

    // do the indexing
    r = cyrusdb_foreach(filter.indexeddb, "", 0, NULL, reindex_mb, &filter, NULL);
    if (r) {
        printf("ERROR: failed to reindex to %s\n", strarray_nth(destpaths, 0));
        goto done;
    }

    // we exactly managed to split at the end, or there was nothing to process!
    if (!filter.numindexed)
        free(strarray_shift(&filter.temptargets)); // removes temp_path

    // put all the indexes into the destination path
    if (strarray_size(&filter.temptargets) == 0) {
        // nothing to copy!
    }
    else if (strarray_size(&filter.temptargets) == 1) {
        // copy into place.  Strictly this is a waste, we could just compact directly from here
        r = copy_files(strarray_nth(&filter.temptargets, 0), strarray_nth(destpaths, 0));
    }
    else {
        // we're going to double-compact, but that's OK
        r = xapian_compact_dbs(strarray_nth(destpaths, 0), (const char **)filter.temptargets.data);
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

    r = create_filter(srcpaths, destpaths, desttiers, userid, flags, &filter, 0);
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

static void cleanup_xapiandirs(const char *mboxname, const char *partition, strarray_t *active, int verbose)
{
    int i;
    strarray_t found = STRARRAY_INITIALIZER;
    strarray_t bogus = STRARRAY_INITIALIZER;

    inspect_filesystem(mboxname, partition, &found, &bogus);

    for (i = 0; i < strarray_size(active); i++) {
        const char *item = strarray_nth(active, i);
        strarray_remove_all(&found, item);
    }

    for (i = 0; i < strarray_size(&found); i++) {
        const char *item = strarray_nth(&found, i);
        char *path = activefile_path(mboxname, partition, item, /*dostat*/0);
        if (verbose)
            printf("Removing unreferenced item %s (%s)\n", item, path);
        removedir(path);
        free(path);
    }

    for (i = 0; i < strarray_size(&bogus); i++) {
        const char *path = strarray_nth(&bogus, i);
        if (verbose)
            printf("Removing bogus path %s\n", path);
        removedir(path);
    }

    strarray_fini(&found);
    strarray_fini(&bogus);
}

static int compact_dbs(const char *userid, const strarray_t *reindextiers,
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
    strarray_t *reindexitems = NULL;
    strarray_t *orig = NULL;
    strarray_t *toreindex = NULL;
    strarray_t *tocompact = NULL;
    char *newdest = NULL;
    char *destdir = NULL;
    char *tempdestdir = NULL;
    char *tempreindexdir = NULL;
    strarray_t *newtiers = NULL;
    char *namelock_fname = NULL;
    int verbose = SEARCH_VERBOSE(flags);
    int created_something = 0;
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

    r = check_config(NULL);
    if (r) goto out;

    if (!xapian_rootdir(desttier, mbentry->partition)) {
        if (verbose)
            printf("INVALID: unknown tier %s\n", desttier);
        goto out;
    }

    /* Generated the namelock filename */
    namelock_fname = xapiandb_namelock_fname_from_userid(userid);

    /* Get an exclusive namelock */
    int lockflags = LOCK_EXCLUSIVE;
    if (flags & SEARCH_COMPACT_NONBLOCKING) lockflags |= LOCK_NONBLOCK;
    r = mboxname_lock(namelock_fname, &xapiandb_namelock, lockflags);
    if (r == IMAP_MAILBOX_LOCKED) {
        // that's OK, we asked for it!
        r = 0;
        goto out;
    }
    if (r) {
        syslog(LOG_ERR, "Could not acquire shared namelock on %s",
               namelock_fname);
        goto out;
    }

    /* take an exclusive lock on the activefile file */
    r = activefile_open(mboxname, mbentry->partition, &activefile, AF_LOCK_WRITE, &active);
    if (r) {
        syslog(LOG_ERR, "Failed to lock activefile for %s", mboxname);
        goto out;
    }
    if (!active || !active->count) goto out;

    orig = strarray_dup(active);

    /* read the activefile file, taking down the names of all paths with a
     * level less than or equal to that requested */
    tochange = activefile_filter(active, srctiers, mbentry->partition);
    if (!tochange || !tochange->count) goto out;

    /* also, track which ones to reindex */
    if (reindextiers) {
        reindexitems = activefile_filter(tochange, reindextiers, mbentry->partition);
    }
    else {
        reindexitems = strarray_new();
    }

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
        char *reindexstr = strarray_join(reindexitems, ",");
        const char *reindex = (flags & SEARCH_COMPACT_REINDEX)
                            ? "ALL" : reindexstr ? reindexstr : "NONE";
        printf("compressing %s to %s for %s (active %s) (reindex %s)\n",
               target, newdest, mboxname, activestr, reindex);
        free(reindexstr);
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
        syslog(LOG_ERR, "Could not acquire shared namelock on %s",
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

    /* make sure the destination path exists */
    r = cyrus_mkdir(tempdestdir, 0755);
    if (r) goto out;
    /* and doesn't contain any junk */
    removedir(tempdestdir);
    r = mkdir(tempdestdir, 0755);
    if (r) goto out;

    if (srcdirs->count == 1 && (flags & SEARCH_COMPACT_COPYONE)) {
        if (verbose) {
            printf("only one source, copying directly to %s\n", tempdestdir);
        }
        cyrus_mkdir(tempdestdir, 0755);
        removedir(tempdestdir);
        r = copy_files(strarray_nth(srcdirs, 0), tempdestdir);
        if (r) goto out;
        created_something = 1;
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

        tocompact = strarray_new();
        if ((flags & SEARCH_COMPACT_REINDEX)) {
            /* all databases to be reindexed */
            toreindex = strarray_dup(srcdirs);
        }
        else {
            toreindex = activefile_resolve(mboxname, mbentry->partition, reindexitems, 0, NULL);
            xapian_check_if_needs_reindex(srcdirs, toreindex, flags & SEARCH_COMPACT_ONLYUPGRADE);
            for (i = 0; i < srcdirs->count; i++) {
                const char *thisdir = strarray_nth(srcdirs, i);
                if (strarray_find(toreindex, thisdir, 0) < 0)
                    strarray_append(tocompact, thisdir);
            }
        }

        if (!toreindex->count && (flags & SEARCH_COMPACT_ONLYUPGRADE)) {
            /* nothing to reindex, so bail now.  Since we don't set 'r', we will just
             * abort with no change other than a new tmp location which compresses down
             * soon enough */
            goto out;
        }

        // first, we'll reindex anything that needs reindexing to a temporary directory
        if (toreindex->count) {
            tempreindexdir = strconcat(tempdestdir, ".REINDEX", (char *)NULL);
            // add this directory to the repack target as the first entry point
            strarray_unshift(newdirs, tempreindexdir);
            r = search_reindex(userid, toreindex, newdirs, newtiers, flags);
            if (r) {
                printf("ERROR: failed to reindex to %s", tempreindexdir);
                removedir(tempreindexdir);
                goto out;
            }
            // remove tempreindexdir from newdirs again, it's going to be compacted instead
            free(strarray_shift(newdirs));

            // and then add the temporary directory to the to-compact list if anything was indexed into it
            if (!xapstat(tempreindexdir))
                strarray_unshift(tocompact, tempreindexdir);
        }

        // then we'll compact together all the source databases
        if (tocompact->count) {
            // and now we're ready to compact to the real tempdir
            strarray_unshift(newdirs, tempdestdir);

            if (flags & SEARCH_COMPACT_FILTER) {
                r = search_filter(userid, tocompact, newdirs, newtiers, flags);
                if (r) {
                    printf("ERROR: failed to filter to %s", tempdestdir);
                    goto out;
                }
            }
            else {
                r = search_compress(userid, tocompact, newdirs, newtiers, flags);
                if (r) {
                    printf("ERROR: failed to compact to %s", tempdestdir);
                    goto out;
                }
            }

            if (!xapstat(tempdestdir)) {
                created_something = 1;
            }
        }

        if (tempreindexdir) {
            removedir(tempreindexdir);
            free(tempreindexdir);
            tempreindexdir = NULL;
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
        syslog(LOG_ERR, "Could not acquire shared namelock on %s",
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

    if (created_something) {
        /* rename the destination data into place */
        if (verbose) {
            printf("renaming tempdir into place\n");
        }
        removedir(destdir);
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

    /* And finally remove all directories on disk of the source dbs */
    for (i = 0; i < srcdirs->count; i++)
        removedir(strarray_nth(srcdirs, i));

    /* remove any other files that are still lying around! */
    cleanup_xapiandirs(mboxname, mbentry->partition, active, verbose);

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

out:
    strarray_free(orig);
    strarray_free(active);
    strarray_free(srcdirs);
    strarray_free(newdirs);
    strarray_free(newtiers);
    strarray_free(toreindex);
    strarray_free(tochange);
    strarray_free(tocompact);
    strarray_free(reindexitems);
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
        removedir(basedir);

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
        syslog(LOG_ERR, "Could not acquire shared namelock on %s",
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

static int langstats(const char *userid, ptrarray_t *lstats, size_t *total_docs)
{
    struct mailbox *mailbox = NULL;
    char *inboxname = mboxname_user_mbox(userid, NULL);
    struct xapiandb_lock lock = XAPIANDB_LOCK_INITIALIZER;

    int r = mailbox_open_irl(inboxname, &mailbox);
    if (r) goto out;

    r = xapiandb_lock_open(mailbox, &lock);
    if (r || lock.db == NULL) goto out;

    r = xapian_db_langstats(lock.db, lstats, total_docs);

out:
    xapiandb_lock_release(&lock);
    mailbox_close(&mailbox);
    free(inboxname);
    return r;
}

static int can_match(enum search_op matchop, int partnum)
{
    return matchop == SEOP_FUZZYMATCH && partnum != SEARCH_PART_NONE;
}

const struct search_engine xapian_search_engine = {
    "Xapian",
    SEARCH_FLAG_CAN_BATCH | SEARCH_FLAG_CAN_GUIDSEARCH,
    begin_search,
    end_search,
    begin_update,
    end_update,
    begin_snippets,
    end_snippets,
    describe_internalised,
    free_internalised,
    list_files,
    compact_dbs,
    delete_user,  /* XXX: fixme */
    check_config,
    langstats,
    can_match
};

