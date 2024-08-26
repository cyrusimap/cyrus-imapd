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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <syslog.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_DIRENT_H
# include <dirent.h>
#else
# define dirent direct
# if HAVE_SYS_NDIR_H
#  include <sys/ndir.h>
# endif
# if HAVE_SYS_DIR_H
#  include <sys/dir.h>
# endif
# if HAVE_NDIR_H
#  include <ndir.h>
# endif
#endif

#include "assert.h"
#include "xmalloc.h"
#include "global.h"
#include "util.h"
#include "cyrusdb.h"

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"

#include "duplicate.h"

#define DEBUG 0

#define DB (config_duplicate_db)

static struct db *dupdb = NULL;
static int duplicate_dbopen = 0;

/* must be called after cyrus_init */
EXPORTED int duplicate_init(const char *fname)
{
    int r = 0;
    char *tofree = NULL;

    if (!fname)
        fname = config_getstring(IMAPOPT_DUPLICATE_DB_PATH);

    /* create db file name */
    if (!fname) {
        tofree = strconcat(config_dir, FNAME_DELIVERDB, (char *)NULL);
        fname = tofree;
    }

    r = cyrusdb_open(DB, fname, CYRUSDB_CREATE, &dupdb);
    if (r != 0) {
        syslog(LOG_ERR, "DBERROR: opening %s: %s", fname,
               cyrusdb_strerror(r));
        goto out;
    }
    duplicate_dbopen = 1;

out:
    free(tofree);

    return r;
}

static int make_key(struct buf *key, const duplicate_key_t *dkey)
{
    if (!dkey ||
        !dkey->id ||
        !dkey->to ||
        !dkey->date)
        return IMAP_INTERNAL;

    buf_reset(key);
    buf_appendmap(key, dkey->id, strlen(dkey->id)+1);
    buf_appendmap(key, dkey->to, strlen(dkey->to)+1);
    buf_appendmap(key, dkey->date, strlen(dkey->date)+1);
    /* We have three concatenated values now, all parts ending with '\0' */

    return 0;
}

static int split_key(const char *key, int keylen, duplicate_key_t *dkey)
{
#define MAXFIELDS 3
    const char *fields[MAXFIELDS];
    int n = 0;
    const char *p;

    /* check the key as a whole is nul-terminated */
    if (key[keylen-1] != '\0')
        return IMAP_INTERNAL;

    /* find the \0 field boundaries */
    for (p = key ; p < (key+keylen) ; p += strlen(p)+1) {
        if (n == MAXFIELDS)
            return IMAP_INTERNAL;
        fields[n++] = p;
    }

    if (n != 3)
        return IMAP_INTERNAL;
    dkey->id = fields[0];
    dkey->to = fields[1];
    dkey->date = fields[2];

    return 0;
#undef MAXFIELDS
}

EXPORTED time_t duplicate_check(const duplicate_key_t *dkey)
{
    struct buf key = BUF_INITIALIZER;
    int r;
    const char *data = NULL;
    size_t len = 0;
    time_t mark = 0;

    if (!duplicate_dbopen) return 0;

    r = make_key(&key, dkey);
    if (r) return 0;

    do {
        r = cyrusdb_fetch(dupdb, key.s, key.len,
                      &data, &len, NULL);
    } while (r == CYRUSDB_AGAIN);

    if (!r && data) {
        assert((len == sizeof(time_t)) ||
               (len == sizeof(time_t) + sizeof(unsigned long)));

        /* found the record */
        memcpy(&mark, data, sizeof(time_t));
    } else if (r != CYRUSDB_OK) {
        if (r != CYRUSDB_NOTFOUND) {
            syslog(LOG_ERR, "duplicate_check: error looking up %s/%s/%s: %s",
                   dkey->id, dkey->to, dkey->date,
                   cyrusdb_strerror(r));
        }
        mark = 0;
    }

#if DEBUG
    syslog(LOG_DEBUG, "duplicate_check: %-40s %-20s %-40s %ld",
           dkey->id, dkey->to, dkey->date, mark);
#endif

    buf_free(&key);
    return mark;
}

EXPORTED void duplicate_log(const duplicate_key_t *dkey, const char *action)
{
    assert(dkey->date != NULL);
    syslog(LOG_INFO, "dupelim: eliminated duplicate message to %s id %s date %s (%s)",
      dkey->to, dkey->id, dkey->date, action);
    if (config_auditlog)
        syslog(LOG_NOTICE, "auditlog: duplicate sessionid=<%s> action=<%s> message-id=%s user=<%s> date=<%s>",
               session_id(), action, dkey->id, dkey->to, dkey->date);
}

EXPORTED void duplicate_mark(const duplicate_key_t *dkey, time_t mark, unsigned long uid)
{
    struct buf key = BUF_INITIALIZER;
    char data[100];
    int r;

    if (!duplicate_dbopen) return;

    r = make_key(&key, dkey);
    if (r) return;

    memcpy(data, &mark, sizeof(mark));
    memcpy(data + sizeof(mark), &uid, sizeof(uid));

    do {
        r = cyrusdb_store(dupdb, key.s, key.len,
                      data, sizeof(mark)+sizeof(uid), NULL);
    } while (r == CYRUSDB_AGAIN);

#if DEBUG
    syslog(LOG_DEBUG, "duplicate_mark: %-40s %-20s %-40s %ld %lu",
           dkey->id, dkey->to, dkey->date, mark, uid);
#endif
    buf_free(&key);
}

struct findrock {
    duplicate_find_proc_t proc;
    void *rock;
};

static int find_cb(void *rock, const char *key, size_t keylen,
                   const char *data, size_t datalen)
{
    struct findrock *frock = (struct findrock *) rock;
    duplicate_key_t dkey = DUPLICATE_INITIALIZER;
    time_t mark;
    unsigned long uid = 0;
    int r;

    r = split_key(key, keylen, &dkey);
    if (r) return 0;    /* ignore broken records */

    /* make sure it is a mailbox */
    if (dkey.to[0] == '.') return 0;

    /* grab the mark and uid */
    memcpy(&mark, data, sizeof(time_t));
    if (datalen > (int) sizeof(mark))
        memcpy(&uid, data + sizeof(mark), sizeof(unsigned long));

    r = (*frock->proc)(&dkey, mark, uid, frock->rock);

    return r;
}

EXPORTED int duplicate_find(const char *msgid,
                   duplicate_find_proc_t proc,
                   void *rock)
{
    struct findrock frock;

    if (!msgid) msgid = "";

    frock.proc = proc;
    frock.rock = rock;

    /* check each entry in our database */
    cyrusdb_foreach(dupdb, msgid, strlen(msgid), NULL, find_cb, &frock, NULL);

    return 0;
}

struct prunerock {
    struct db *db;
    time_t expmark; /* default expmark, if not overridden by table entry */
    struct hash_table *expire_table;
    int count;
    int deletions;
};

static int prune_p(void *rock,
                   const char *key, size_t keylen,
                   const char *data, size_t datalen __attribute__((unused)))
{
    struct prunerock *prock = (struct prunerock *) rock;
    time_t mark, *expmark = NULL;
    duplicate_key_t dkey = DUPLICATE_INITIALIZER;
    int r;

    prock->count++;

    r = split_key(key, keylen, &dkey);
    if (r) return 1;    /* broken record, want to prune it */

    /* grab the rcpt, make sure it is a mailbox and lookup its expire time */
    if (prock->expire_table && dkey.to[0] && dkey.to[0] != '.') {
        expmark = (time_t *) hash_lookup(dkey.to, prock->expire_table);
    }

    /* grab the mark */
    memcpy(&mark, data, sizeof(time_t));

    /* check if we should prune this entry */
    return (mark < (expmark ? *expmark : prock->expmark));
}

static int prune_cb(void *rock, const char *id, size_t idlen,
                    const char *data __attribute__((unused)),
                    size_t datalen __attribute__((unused)))
{
    struct prunerock *prock = (struct prunerock *) rock;
    int r;

    prock->deletions++;

    do {
        r = cyrusdb_delete(prock->db, id, idlen, NULL, 0);
    } while (r == CYRUSDB_AGAIN);


    return 0;
}

EXPORTED int duplicate_prune(int seconds, struct hash_table *expire_table)
{
    struct prunerock prock;

    if (seconds < 0) fatal("must specify positive number of seconds", EX_USAGE);

    prock.count = prock.deletions = 0;
    prock.expmark = time(NULL) - seconds;
    prock.expire_table = expire_table;
    syslog(LOG_NOTICE, "duplicate_prune: pruning back %0.2f days",
           ((double)seconds/86400));

    /* check each entry in our database */
    prock.db = dupdb;
    cyrusdb_foreach(dupdb, "", 0, &prune_p, &prune_cb, &prock, NULL);

    syslog(LOG_NOTICE, "duplicate_prune: purged %d out of %d entries",
           prock.deletions, prock.count);

    return 0;
}

struct dumprock {
    FILE *f;
    int count;
};

static int dump_cb(void *rock,
                   const char *key, size_t keylen,
                   const char *data, size_t datalen)
{
    struct dumprock *drock = (struct dumprock *) rock;
    time_t mark;
    duplicate_key_t dkey = DUPLICATE_INITIALIZER;
    char *freeme = NULL;
    int r;
    int idlen, i;
    unsigned long uid = 0;

    assert((datalen == sizeof(time_t)) ||
           (datalen == sizeof(time_t) + sizeof(unsigned long)));

    drock->count++;

    memcpy(&mark, data, sizeof(time_t));
    if (datalen > (int) sizeof(mark))
        memcpy(&uid, data + sizeof(mark), sizeof(unsigned long));

    r = split_key(key, keylen, &dkey);
    if (r) goto out;
    idlen = strlen(dkey.id);

    for (i = 0; i < idlen; i++) {
        if (!isprint((unsigned char) dkey.id[i])) break;
    }

    if (i != idlen) {
        /* change to hexadecimal */
        freeme = xmalloc(idlen * 2 + 1);
        bin_to_hex(dkey.id, idlen, freeme, BH_UPPER);
        dkey.id = freeme;
    }

    fprintf(drock->f, "id: %-40s\tto: %-20s\tat: %ld\tuid: %lu\n",
            dkey.id, dkey.to, (long) mark, uid);

out:
    if (freeme) free(freeme);

    return 0;
}

EXPORTED int duplicate_dump(FILE *f)
{
    struct dumprock drock;

    drock.f = f;
    drock.count = 0;

    /* check each entry in our database */
    cyrusdb_foreach(dupdb, "", 0, NULL, &dump_cb, &drock, NULL);

    return drock.count;
}

EXPORTED int duplicate_done(void)
{
    int r = 0;

    if (duplicate_dbopen) {
        r = cyrusdb_close(dupdb);
        if (r) {
            syslog(LOG_ERR, "DBERROR: error closing deliverdb: %s",
                   cyrusdb_strerror(r));
        }
        duplicate_dbopen = 0;
    }

    return r;
}
