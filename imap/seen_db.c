/* seen_db.c -- implementation of seen database using per-user db
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
#include "cyrusdb.h"
#include "map.h"
#include "util.h"

#include "assert.h"
#include "global.h"
#include "xmalloc.h"
#include "mailbox.h"
#include "seen.h"
#include "sync_log.h"
#include "imparse.h"

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"

#define FNAME_SEEN "/cyrus.seen" /* for legacy seen state */

enum {
    SEEN_VERSION = 1,
    SEEN_DEBUG = 0
};

struct seen {
    char *user;                 /* what user is this for? */
    struct db *db;
    struct txn *tid;            /* outstanding txn, if any */
};

#define DB (config_seenstate_db)

EXPORTED char *seen_getpath(const char *userid)
{
    mbname_t *mbname = mbname_from_userid(userid);
    char *fname = mboxname_conf_getpath(mbname, FNAME_SEENSUFFIX);

    mbname_free(&mbname);

    return fname;
}

EXPORTED int seen_open(const char *user,
              int flags,
              struct seen **seendbptr)
{
    struct seen *seendb = NULL;
    char *fname = NULL;
    int dbflags = (flags & SEEN_CREATE) ? CYRUSDB_CREATE : 0;
    int r;

    assert(user);
    assert(*seendbptr == NULL);

    /* create seendb */
    seendb = (struct seen *) xmalloc(sizeof(struct seen));

    if (SEEN_DEBUG) {
        syslog(LOG_DEBUG, "seen_db: seen_open(%s)", user);
    }

    /* open the seendb corresponding to user */
    fname = seen_getpath(user);
    if (flags & SEEN_CREATE) cyrus_mkdir(fname, 0755);
    r = cyrusdb_open(DB, fname, dbflags | CYRUSDB_CONVERT, &seendb->db);
    if (r) {
        if (!(flags & SEEN_SILENT)) {
            int level = (flags & SEEN_CREATE) ? LOG_ERR : LOG_DEBUG;
            syslog(level, "DBERROR: opening %s: %s", fname,
                   cyrusdb_strerror(r));
        }
        r = r == CYRUSDB_NOTFOUND ? IMAP_NOTFOUND : IMAP_IOERROR;
        free(seendb);
        free(fname);
        return r;
    }
    syslog(LOG_DEBUG, "seen_db: user %s opened %s", user, fname);
    free(fname);

    seendb->tid = NULL;
    seendb->user = xstrdup(user);

    *seendbptr = seendb;
    return r;
}

struct seendata_rock {
    seenproc_t *f;
    void *rock;
};

EXPORTED void seen_freedata(struct seendata *sd)
{
    free (sd->seenuids);
}

static void parse_data(const char *data, int datalen, struct seendata *sd)
{
    /* remember that 'data' may not be null terminated ! */
    const char *dend = data + datalen;
    char *p;
    int uidlen;
    int version;

    memset(sd, 0, sizeof(struct seendata));

    version = strtol(data, &p, 10); data = p;
    assert(version == SEEN_VERSION);

    sd->lastread = strtol(data, &p, 10); data = p;
    sd->lastuid = strtoll(data, &p, 10); data = p;
    sd->lastchange = strtol(data, &p, 10); data = p;
    while (p < dend && Uisspace(*p)) { p++; } data = p;
    uidlen = dend - data;
    sd->seenuids = xmalloc(uidlen + 1);
    memcpy(sd->seenuids, data, uidlen);
    sd->seenuids[uidlen] = '\0';
}

static int foreach_proc(void *rock,
                 const char *key,
                 size_t keylen,
                 const char *data,
                 size_t datalen)
{
    struct seendata sd = SEENDATA_INITIALIZER;
    struct seendata_rock *sr = (struct seendata_rock *)rock;
    char *name = xstrndup(key, keylen);
    int r;

    parse_data(data, datalen, &sd);

    r = (sr->f)(name, &sd, sr->rock);

    seen_freedata(&sd);
    free(name);

    return r;
}

EXPORTED int seen_foreach(struct seen *seendb, seenproc_t *f, void *rock)
{
    struct seendata_rock sdrock;
    sdrock.f = f;
    sdrock.rock = rock;
    return cyrusdb_foreach(seendb->db, "", 0, NULL, foreach_proc, &sdrock, NULL);
}

static int seen_readit(struct seen *seendb, const char *uniqueid,
                       struct seendata *sd, int rw)
{
    int r;
    const char *data;
    size_t datalen;

    assert(seendb && uniqueid);
    if (rw || seendb->tid) {
        r = cyrusdb_fetchlock(seendb->db, uniqueid, strlen(uniqueid),
                          &data, &datalen, &seendb->tid);
    } else {
        r = cyrusdb_fetch(seendb->db, uniqueid, strlen(uniqueid),
                      &data, &datalen, NULL);
    }
    switch (r) {
    case 0:
        break;
    case CYRUSDB_AGAIN:
        syslog(LOG_DEBUG, "deadlock in seen database for '%s/%s'",
               seendb->user, uniqueid);
        return IMAP_AGAIN;
        break;
    case CYRUSDB_NOTFOUND:
        memset(sd, 0, sizeof(struct seendata));
        sd->seenuids = xstrdup("");
        return 0;
        break;
    default:
        syslog(LOG_ERR, "DBERROR: error fetching txn %s",
               cyrusdb_strerror(r));
        return IMAP_IOERROR;
        break;
    }

    parse_data(data, datalen, sd);
    if (sd->seenuids[0] && !imparse_issequence(sd->seenuids)) {
        syslog(LOG_ERR, "DBERROR: invalid sequence <%s> for %s %s - nuking",
               sd->seenuids, seendb->user, uniqueid);
        free(sd->seenuids);
        sd->seenuids = xstrdup("");
    }

    return 0;
}

EXPORTED int seen_read(struct seen *seendb, const char *uniqueid, struct seendata *sd)
{
    if (SEEN_DEBUG) {
        syslog(LOG_DEBUG, "seen_db: seen_read %s (%s)",
               seendb->user, uniqueid);
    }

    return seen_readit(seendb, uniqueid, sd, 0);
}

EXPORTED int seen_lockread(struct seen *seendb, const char *uniqueid, struct seendata *sd)
{
    if (SEEN_DEBUG) {
        syslog(LOG_DEBUG, "seen_db: seen_lockread %s (%s)",
               seendb->user, uniqueid);
    }

    return seen_readit(seendb, uniqueid, sd, 1);
}

EXPORTED int seen_write(struct seen *seendb, const char *uniqueid, struct seendata *sd)
{
    int sz = strlen(sd->seenuids) + 50;
    char *data = xmalloc(sz);
    int datalen;
    int r;

    assert(seendb && uniqueid);

    if (SEEN_DEBUG) {
        syslog(LOG_DEBUG, "seen_db: seen_write %s (%s)",
               seendb->user, uniqueid);
    }

    snprintf(data, sz, "%d " TIME_T_FMT " %u " TIME_T_FMT " %s", SEEN_VERSION,
            sd->lastread, sd->lastuid,
            sd->lastchange, sd->seenuids);
    datalen = strlen(data);

    r = cyrusdb_store(seendb->db, uniqueid, strlen(uniqueid),
                  data, datalen, &seendb->tid);
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

    free(data);

    sync_log_seen(seendb->user, uniqueid);

    return r;
}

EXPORTED int seen_close(struct seen **seendbptr)
{
    struct seen *seendb = *seendbptr;
    int r;

    if (!seendb) return 0;

    if (SEEN_DEBUG) {
        syslog(LOG_DEBUG, "seen_db: seen_close(%s)", seendb->user);
    }

    if (seendb->tid) {
        if (SEEN_DEBUG) {
            syslog(LOG_DEBUG, "seen_db: committing changes for %s", seendb->user);
        }
        r = cyrusdb_commit(seendb->db, seendb->tid);
        if (r != CYRUSDB_OK) {
            syslog(LOG_ERR, "DBERROR: error committing seen txn; "
                   "seen state lost: %s", cyrusdb_strerror(r));
        }
        seendb->tid = NULL;
    }

    r = cyrusdb_close(seendb->db);
    if (r) {
        syslog(LOG_ERR, "DBERROR: error closing: %s",
               cyrusdb_strerror(r));
        r = IMAP_IOERROR;
    }
    free(seendb->user);
    free(seendb);

    *seendbptr = NULL;

    return 0;
}

HIDDEN int seen_create_mailbox(const char *userid, struct mailbox *mailbox)
{
    if (SEEN_DEBUG) {
        syslog(LOG_DEBUG, "seen_db: seen_create_mailbox(%s, %s)",
               userid, mailbox_uniqueid(mailbox));
    }

    /* noop */
    return 0;
}

EXPORTED int seen_delete_mailbox(const char *userid, struct mailbox *mailbox)
{
    int r;
    struct seen *seendb = NULL;
    const char *uniqueid = mailbox_uniqueid(mailbox);

    if (SEEN_DEBUG) {
        syslog(LOG_DEBUG, "seen_db: seen_delete_mailbox(%s, %s)",
               userid, uniqueid);
    }

    /* noop */
    if (!userid)
        return 0;

    r = seen_open(userid, SEEN_SILENT, &seendb);
    if (!r) r = cyrusdb_delete(seendb->db, uniqueid, strlen(uniqueid),
                           &seendb->tid, 1);
    seen_close(&seendb);

    return r;
}

int seen_create_user(const char *user)
{
    if (SEEN_DEBUG) {
        syslog(LOG_DEBUG, "seen_db: seen_create_user(%s)",
               user);
    }

    /* we'll be lazy here and create this when needed */
    return 0;
}

HIDDEN int seen_delete_user(const char *user)
{
    char *fname = seen_getpath(user);
    int r = 0;

    if (SEEN_DEBUG) {
        syslog(LOG_DEBUG, "seen_db: seen_delete_user(%s)",
               user);
    }

    if (unlink(fname) && errno != ENOENT) {
        syslog(LOG_ERR, "error unlinking %s: %m", fname);
        r = IMAP_IOERROR;
    }

    free(fname);
    return r;
}

HIDDEN int seen_rename_user(const char *olduser, const char *newuser)
{
    char *oldfname = seen_getpath(olduser);
    char *newfname = seen_getpath(newuser);
    int r = 0;

    if (SEEN_DEBUG) {
        syslog(LOG_DEBUG, "seen_db: seen_rename_user(%s, %s)",
               olduser, newuser);
    }

    cyrus_mkdir(newfname, 0755);
    if (rename(oldfname, newfname) && errno != ENOENT) {
        syslog(LOG_ERR, "error renaming %s to %s: %m", oldfname, newfname);
        r = IMAP_IOERROR;
    }

    free(oldfname);
    free(newfname);

    return r;
}

HIDDEN int seen_copy(const char *userid, struct mailbox *oldmailbox,
              struct mailbox *newmailbox)
{
    if (SEEN_DEBUG) {
        syslog(LOG_DEBUG, "seen_db: seen_copy %s (%s => %s)",
               userid ? userid : "", mailbox_uniqueid(oldmailbox), mailbox_uniqueid(newmailbox));
    }

    if (userid && strcmp(mailbox_uniqueid(oldmailbox), mailbox_uniqueid(newmailbox))) {
        int r;
        struct seen *seendb = NULL;
        struct seendata sd = SEENDATA_INITIALIZER;

        r = seen_open(userid, SEEN_SILENT, &seendb);

        /* just be silent if it's missing */
        if (!r) r = seen_lockread(seendb, mailbox_uniqueid(oldmailbox), &sd);
        if (!r) r = seen_write(seendb, mailbox_uniqueid(newmailbox), &sd);

        seen_close(&seendb);
        seen_freedata(&sd);
    }

    /* noop */
    return 0;
}

EXPORTED int seen_done(void)
{
    if (SEEN_DEBUG) {
        syslog(LOG_DEBUG, "seen_db: seen_done()");
    }

    return 0;
}

EXPORTED int seen_compare(struct seendata *a, struct seendata *b)
{
    if (a->lastuid == b->lastuid &&
        a->lastread == b->lastread &&
        a->lastchange == b->lastchange &&
        !strcmp(a->seenuids, b->seenuids))
        return 1;

    return 0;
}

/* Look up the unique id in the new file, if it is there, compare the
 * last change times, and ensure that the database uses the newer of
 * the two */
static int seen_merge_cb(void *rockp,
                         const char *key, size_t keylen,
                         const char *newdata, size_t newlen)
{
    int r = 0;
    struct seen *seendb = (struct seen *)rockp;
    struct seendata oldsd, newsd;
    char *uniqueid = xstrndup(key, keylen);
    int dirty = 0;

    parse_data(newdata, newlen, &newsd);

    if (seen_lockread(seendb, uniqueid, &oldsd)) {
        dirty = 1; /* no record */
    }
    else {
        if (newsd.lastuid > oldsd.lastuid) dirty = 1;
        if (newsd.lastread > oldsd.lastread) dirty = 1;
    }

    if (dirty) {
        /* write back data from new entry */
        r = seen_write(seendb, uniqueid, &newsd);
    }

    free(uniqueid);

    return r;
}

/* we want to merge records from "newfile" into
 * the already existing "currentfile", but only
 * if the record in newfile is actually newer
 * (or doesn't exist in currentfile yet)  */
HIDDEN int seen_merge(struct seen *seendb, const char *newfile)
{
    int r = 0;
    struct db *newdb = NULL;

    r = cyrusdb_open(DB, newfile, 0, &newdb);
    /* if it doesn't exist, there's nothing
     * to do, so abort without an error */
    if (r == CYRUSDB_NOTFOUND) return 0;

    if (!r) r = cyrusdb_foreach(newdb, "", 0, NULL, seen_merge_cb, seendb, NULL);

    if (newdb) cyrusdb_close(newdb);

    return r;
}
