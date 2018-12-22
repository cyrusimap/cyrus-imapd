/* mboxkey.c -- implementation of URLAUTH mailbox keys
 *
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
#include <syslog.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <errno.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/uio.h>

#include "assert.h"
#include "cyrusdb.h"
#include "map.h"
#include "util.h"

#include "global.h"
#include "xmalloc.h"
#include "mailbox.h"
#include "mboxkey.h"

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"

#define FNAME_MBOXKEYSUFFIX "mboxkey" /* per user mailbox key extension */

enum {
    MBOXKEY_VERSION = 1,
    MBOXKEY_DEBUG = 0
};

struct mboxkey {
    char *user;                 /* what user is this for? */
    char *fname;                /* filename (full path) of db */
    struct db *db;
    struct txn *tid;            /* outstanding txn, if any */
};

static struct mboxkey *lastmboxkey = NULL;

#define DB (config_mboxkey_db)

static void abortcurrent(struct mboxkey *s)
{
    if (s && s->tid) {
        int r = cyrusdb_abort(s->db, s->tid);
        if (r) {
            syslog(LOG_ERR, "DBERROR: error aborting txn: %s",
                   cyrusdb_strerror(r));
        }
        s->tid = NULL;
    }
}

HIDDEN char *mboxkey_getpath(const char *userid)
{
    mbname_t *mbname = mbname_from_userid(userid);
    char *fname = mboxname_conf_getpath(mbname, FNAME_MBOXKEYSUFFIX);

    mbname_free(&mbname);

    return fname;
}

EXPORTED int mboxkey_open(const char *user,
                 int flags,
                 struct mboxkey **mboxkeydbptr)
{
    struct mboxkey *mboxkeydb;
    struct stat sbuf;
    char *fname = NULL;
    int r;

    /* try to reuse the last db handle */
    mboxkeydb = lastmboxkey;
    lastmboxkey = NULL;
    if (MBOXKEY_DEBUG) {
        syslog(LOG_DEBUG, "mboxkey_db: mboxkey_open(%s)", user);
    }

    /* if this is the db we've already opened, return it */
    if (mboxkeydb && !strcmp(mboxkeydb->user, user) &&
        !stat(mboxkeydb->fname, &sbuf)) {
        abortcurrent(mboxkeydb);
        *mboxkeydbptr = mboxkeydb;
        return 0;
    }

    *mboxkeydbptr = NULL;
    /* otherwise, close the existing database */
    if (mboxkeydb) {
        abortcurrent(mboxkeydb);
        r = cyrusdb_close(mboxkeydb->db);
        if (r) {
            syslog(LOG_ERR, "DBERROR: error closing mboxkeydb: %s",
                   cyrusdb_strerror(r));
        }
        free(mboxkeydb->user);
        free(mboxkeydb->fname);
    } else {
        /* create mboxkeydb */
        mboxkeydb = (struct mboxkey *) xmalloc(sizeof(struct mboxkey));
    }

    /* open the mboxkeydb corresponding to user */
    fname = mboxkey_getpath(user);
    r = cyrusdb_open(DB, fname, (flags & MBOXKEY_CREATE) ? CYRUSDB_CREATE : 0,
                 &mboxkeydb->db);
    if (r != 0) {
        int level = (flags & MBOXKEY_CREATE) ? LOG_ERR : LOG_DEBUG;
        syslog(level, "DBERROR: opening %s: %s", fname,
               cyrusdb_strerror(r));
        r = IMAP_IOERROR;
        free(mboxkeydb);
        free(fname);
        return r;
    }
    syslog(LOG_DEBUG, "mboxkey_db: user %s opened %s", user, fname);

    mboxkeydb->tid = NULL;
    mboxkeydb->user = xstrdup(user);
    mboxkeydb->fname = fname;

    *mboxkeydbptr = mboxkeydb;
    return r;
}

static int mboxkey_readit(struct mboxkey *mboxkeydb, const char *mailbox,
                          const char **mboxkey, size_t *mboxkeylen,
                          int rw)
{
    int r;
    const char *data;
    size_t datalen;
    unsigned short version, s;

    assert(mboxkeydb && mailbox);
    if (rw || mboxkeydb->tid) {
        r = cyrusdb_fetchlock(mboxkeydb->db, mailbox, strlen(mailbox),
                          &data, &datalen, &mboxkeydb->tid);
    } else {
        r = cyrusdb_fetch(mboxkeydb->db, mailbox, strlen(mailbox),
                      &data, &datalen, NULL);
    }
    switch (r) {
    case 0:
        break;
    case CYRUSDB_AGAIN:
        syslog(LOG_DEBUG, "deadlock in mboxkey database for '%s/%s'",
               mboxkeydb->user, mailbox);
        return IMAP_AGAIN;
        break;
    case CYRUSDB_IOERROR:
        syslog(LOG_ERR, "DBERROR: error fetching txn %s",
               cyrusdb_strerror(r));
        return IMAP_IOERROR;
        break;
    case CYRUSDB_NOTFOUND:
        *mboxkey = NULL;
        *mboxkeylen = 0;

        return 0;
        break;
    }

    /* 'data' is <version><mboxkey> */
    memcpy(&s, data, sizeof(s));
    version = ntohs(s);
    assert(version == MBOXKEY_VERSION);
    *mboxkey = data + sizeof(s);
    *mboxkeylen = datalen - sizeof(s);

    return 0;
}

EXPORTED int mboxkey_read(struct mboxkey *mboxkeydb, const char *mailbox,
                 const char **mboxkey, size_t *mboxkeylen)
{
    if (MBOXKEY_DEBUG) {
        syslog(LOG_DEBUG, "mboxkey_db: mboxkey_read(%s, %s)",
               mboxkeydb->user, mailbox);
    }

    return mboxkey_readit(mboxkeydb, mailbox, mboxkey, mboxkeylen, 0);
}

int mboxkey_lockread(struct mboxkey *mboxkeydb, const char *mailbox,
                     const char **mboxkey, size_t *mboxkeylen)
{
    if (MBOXKEY_DEBUG) {
        syslog(LOG_DEBUG, "mboxkey_db: mboxkey_lockread(%s, %s)",
               mboxkeydb->user, mailbox);
    }

    return mboxkey_readit(mboxkeydb, mailbox, mboxkey, mboxkeylen, 1);
}

EXPORTED int mboxkey_write(struct mboxkey *mboxkeydb, const char *mailbox,
                  const char *mboxkey, size_t mboxkeylen)
{
    int r;

    assert(mboxkeydb && mailbox);
/*    assert(mboxkeydb->tid);*/

    if (MBOXKEY_DEBUG) {
        syslog(LOG_DEBUG, "mboxkey_db: mboxkey_write(%s, %s, %s)",
               mboxkeydb->user, mailbox, mboxkey ? "KEY" : "NIL");
    }

    if (!mboxkey) {
        r = cyrusdb_delete(mboxkeydb->db, mailbox, strlen(mailbox),
                       &mboxkeydb->tid, 1);
    }
    else {
        unsigned short version = MBOXKEY_VERSION, s;
        int datalen = sizeof(s) + mboxkeylen;
        char *data = xmalloc(datalen);

        s = htons(version);
        memcpy(data, &s, sizeof(s));
        memcpy(data+sizeof(s), mboxkey, mboxkeylen);

        r = cyrusdb_store(mboxkeydb->db, mailbox, strlen(mailbox),
                      data, datalen, &mboxkeydb->tid);
        free(data);
    }

    switch (r) {
    case CYRUSDB_OK:
        break;
    case CYRUSDB_IOERROR:
        r = IMAP_AGAIN;
        break;
    default:
        syslog(LOG_ERR, "DBERROR: error updating database: %s",
               cyrusdb_strerror(r));
        r = IMAP_IOERROR;
        break;
    }

    return r;
}

EXPORTED int mboxkey_close(struct mboxkey *mboxkeydb)
{
    int r;

    if (MBOXKEY_DEBUG) {
        syslog(LOG_DEBUG, "mboxkey_db: mboxkey_close(%s)",
               mboxkeydb->user);
    }

    if (mboxkeydb->tid) {
        r = cyrusdb_commit(mboxkeydb->db, mboxkeydb->tid);
        if (r != CYRUSDB_OK) {
            syslog(LOG_ERR, "DBERROR: error committing mboxkey txn; "
                   "mboxkey state lost: %s", cyrusdb_strerror(r));
        }
        mboxkeydb->tid = NULL;
    }

    if (lastmboxkey) {
        int r;

        /* free the old database hanging around */
        abortcurrent(lastmboxkey);
        r = cyrusdb_close(lastmboxkey->db);
        if (r != CYRUSDB_OK) {
            syslog(LOG_ERR, "DBERROR: error closing lastmboxkey: %s",
                   cyrusdb_strerror(r));
            r = IMAP_IOERROR;
        }
        if(!r) lastmboxkey->db = NULL;
        free(lastmboxkey->user);
        free(lastmboxkey->fname);
        free(lastmboxkey);
        lastmboxkey = NULL;
    }

    /* this database can now be reused */
    lastmboxkey = mboxkeydb;
    return 0;
}

EXPORTED int mboxkey_delete_user(const char *user)
{
    char *fname = mboxkey_getpath(user);
    int r = 0;

    if (MBOXKEY_DEBUG) {
        syslog(LOG_DEBUG, "mboxkey_db: mboxkey_delete_user(%s)",
               user);
    }

    /* erp! */
    r = unlink(fname);
    if (r < 0 && errno == ENOENT) {
        syslog(LOG_DEBUG, "cannot unlink %s: %m", fname);
        /* but maybe the user just never read anything? */
        r = 0;
    }
    else if (r < 0) {
        syslog(LOG_ERR, "error unlinking %s: %m", fname);
        r = IMAP_IOERROR;
    }
    free(fname);

    if (lastmboxkey) {
        free(lastmboxkey->user);
        free(lastmboxkey->fname);
        free(lastmboxkey);
        lastmboxkey = NULL;
    }

    return r;
}

/* database better have been locked before this ! */
int mboxkey_unlock(struct mboxkey *mboxkeydb)
{
    int r;

    assert(mboxkeydb);
    if (!mboxkeydb->tid) return 0;

    if (MBOXKEY_DEBUG) {
        syslog(LOG_DEBUG, "mboxkey_db: mboxkey_unlock(%s)",
               mboxkeydb->user);
    }

    r = cyrusdb_commit(mboxkeydb->db, mboxkeydb->tid);
    if (r != CYRUSDB_OK) {
        syslog(LOG_ERR, "DBERROR: error committing mboxkey txn; "
               "mboxkey state lost: %s", cyrusdb_strerror(r));
    }
    mboxkeydb->tid = NULL;

    return 0;
}

EXPORTED int mboxkey_done(void)
{
    int r = 0;

    if (MBOXKEY_DEBUG) {
        syslog(LOG_DEBUG, "mboxkey_db: mboxkey_done()");
    }

    if (lastmboxkey) {
        abortcurrent(lastmboxkey);
        r = cyrusdb_close(lastmboxkey->db);
        if (r) {
            syslog(LOG_ERR, "DBERROR: error closing lastmboxkey: %s",
                   cyrusdb_strerror(r));
            r = IMAP_IOERROR;
        }
        free(lastmboxkey->user);
        free(lastmboxkey->fname);
        free(lastmboxkey);
    }

    return r;
}

struct mboxkey_merge_rock
{
    struct db *db;
    struct txn *tid;
};

/* Copy keys from tmp file to tgt file.
 *
 * XXX  We currently have nothing to compare against.
 */
static int mboxkey_merge_cb(void *rockp,
                         const char *key, size_t keylen,
                         const char *tmpdata, size_t tmpdatalen)
{
    int r;
    struct mboxkey_merge_rock *rockdata = (struct mboxkey_merge_rock *)rockp;
    struct db *tgtdb = rockdata->db;
    const char *tgtdata;
    size_t tgtdatalen;

    if (!tgtdb) return IMAP_INTERNAL;

    r = cyrusdb_fetchlock(tgtdb, key, keylen, &tgtdata, &tgtdatalen,
                      &(rockdata->tid));
    if(!r && tgtdata) {
        unsigned short version, s;
        const char *tmp = tmpdata, *tgt = tgtdata;

        /* get version */
        memcpy(&s, tgt, sizeof(s));
        version = ntohs(s);
        assert(version == MBOXKEY_VERSION);

        /* get version */
        memcpy(&s, tmp, sizeof(s));
        version = ntohs(s);
        assert(version == MBOXKEY_VERSION);
    }

    return cyrusdb_store(tgtdb, key, keylen, tmpdata, tmpdatalen,
                     &(rockdata->tid));
}

HIDDEN int mboxkey_merge(const char *tmpfile, const char *tgtfile)
{
    int r = 0;
    struct db *tmp = NULL, *tgt = NULL;
    struct mboxkey_merge_rock rock;

    /* xxx does this need to be CYRUSDB_CREATE? */
    r = cyrusdb_open(DB, tmpfile, CYRUSDB_CREATE, &tmp);
    if(r) goto done;

    r = cyrusdb_open(DB, tgtfile, CYRUSDB_CREATE, &tgt);
    if(r) goto done;

    rock.db = tgt;
    rock.tid = NULL;

    r = cyrusdb_foreach(tmp, "", 0, NULL, mboxkey_merge_cb, &rock, &rock.tid);

    if(r) cyrusdb_abort(rock.db, rock.tid);
    else cyrusdb_commit(rock.db, rock.tid);

 done:

    if(tgt) cyrusdb_close(tgt);
    if(tmp) cyrusdb_close(tmp);

    return r;
}
