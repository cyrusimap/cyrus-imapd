/* pushsub_db.c -- implementation of per-user PushSubscription database
 *
 * Copyright (c) 1994-2022 Carnegie Mellon University.  All rights reserved.
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

#include <syslog.h>
#include <string.h>

#include "append.h"
#include "cyrusdb.h"
#include "dav_db.h"
#include <errno.h>
#include "global.h"
#include "jmap_api.h"
#include "libconfig.h"
#include "mboxlist.h"
#include "pushsub_db.h"
#include "times.h"
#include "user.h"
#include "util.h"
#include "xmalloc.h"

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"


enum {
    STMT_SELRSRC,
    STMT_SELUID,
    STMT_SELMBOX,
    STMT_INSERT,
    STMT_UPDATE,
    STMT_DELETE,
    STMT_BEGIN,
    STMT_COMMIT,
    STMT_ROLLBACK
};

#define NUM_STMT 10

struct pushsub_db {
    sqldb_t *db;                        /* DB handle */
    struct buf mailbox;                 /* buffers for copies of column text */
    struct buf id;
    struct buf subscription;
};

static int pushsub_initialized = 0;

static void done_cb(void *rock __attribute__((unused))) {
    pushsubdb_done();
}

static void init_internal() {
    if (!pushsub_initialized) {
        pushsubdb_init();
        cyrus_modules_add(done_cb, NULL);
    }
}

EXPORTED int pushsubdb_init(void)
{
    int r = sqldb_init();
    if (!r) pushsub_initialized = 1;
    return r;
}


EXPORTED int pushsubdb_done(void)
{
    int r = sqldb_done();
    if (!r) pushsub_initialized = 0;
    return r;
}

/* Open PushSubscription DB corresponding to userid */
EXPORTED struct pushsub_db *pushsubdb_open_userid(const char *userid)
{
    struct pushsub_db *pushsubdb = NULL;

    init_internal();

    sqldb_t *db = dav_open_userid(userid);
    if (!db) return NULL;

    pushsubdb = xzmalloc(sizeof(struct pushsub_db));
    pushsubdb->db = db;

    return pushsubdb;
}

/* Open PushSubscription DB corresponding to mailbox */
EXPORTED struct pushsub_db *pushsubdb_open_mailbox(struct mailbox *mailbox)
{
    struct pushsub_db *pushsubdb = NULL;
    char *userid = mboxname_to_userid(mailbox_name(mailbox));

    init_internal();

    if (userid) {
        pushsubdb = pushsubdb_open_userid(userid);
        free(userid);
        return pushsubdb;
    }

    sqldb_t *db = dav_open_mailbox(mailbox);
    if (!db) return NULL;

    pushsubdb = xzmalloc(sizeof(struct pushsub_db));
    pushsubdb->db = db;

    return pushsubdb;
}

/* Close PushSubscription DB */
EXPORTED int pushsubdb_close(struct pushsub_db *pushsubdb)
{
    int r = 0;

    if (!pushsubdb) return 0;

    buf_free(&pushsubdb->mailbox);
    buf_free(&pushsubdb->id);
    buf_free(&pushsubdb->subscription);

    r = dav_close(&pushsubdb->db);

    free(pushsubdb);

    return r;
}

EXPORTED int pushsubdb_begin(struct pushsub_db *pushsubdb)
{
    return sqldb_begin(pushsubdb->db, "pushsub");
}

EXPORTED int pushsubdb_commit(struct pushsub_db *pushsubdb)
{
    return sqldb_commit(pushsubdb->db, "pushsub");
}

EXPORTED int pushsubdb_abort(struct pushsub_db *pushsubdb)
{
    return sqldb_rollback(pushsubdb->db, "pushsub");
}


struct read_rock {
    struct pushsub_db *db;
    struct pushsub_data *psdata;
    int tombstones;
    pushsub_cb_t *cb;
    void *rock;
};

static const char *column_text_to_buf(const char *text, struct buf *buf)
{
    if (text) {
        buf_setcstr(buf, text);
        text = buf_cstring(buf);
    }

    return text;
}

static int read_cb(sqlite3_stmt *stmt, void *rock)
{
    struct read_rock *rrock = (struct read_rock *) rock;
    struct pushsub_db *db = rrock->db;
    struct pushsub_data *psdata = rrock->psdata;
    int r = 0;

    memset(psdata, 0, sizeof(struct pushsub_data));

    psdata->alive = sqlite3_column_int(stmt, 7);
    if (!rrock->tombstones && !psdata->alive)
        return 0;

    psdata->rowid = sqlite3_column_int(stmt, 0);
    psdata->imap_uid = sqlite3_column_int(stmt, 2);
    psdata->expires = sqlite3_column_int(stmt, 5);
    psdata->isverified = sqlite3_column_int(stmt, 6);

    if (rrock->cb) {
        /* We can use the column data directly for the callback */
        psdata->mailbox = (const char *) sqlite3_column_text(stmt, 1);
        psdata->id = (const char *) sqlite3_column_text(stmt, 3);
        psdata->subscription = (const char *) sqlite3_column_text(stmt, 4);
        r = rrock->cb(rrock->rock, psdata);
    }
    else {
        /* For single row SELECTs like pushsub_read(),
         * we need to make a copy of the column data before
         * it gets flushed by sqlite3_step() or sqlite3_reset() */
        psdata->mailbox =
            column_text_to_buf((const char *) sqlite3_column_text(stmt, 1),
                               &db->mailbox);
        psdata->id =
            column_text_to_buf((const char *) sqlite3_column_text(stmt, 3),
                               &db->id);
        psdata->subscription =
            column_text_to_buf((const char *) sqlite3_column_text(stmt, 4),
                               &db->subscription);
    }

    return r;
}

#define CMD_GETFIELDS                                                       \
    "SELECT rowid, mailbox, imap_uid,"                                      \
    "  id, subscription, expires, isverified, alive"                        \
    " FROM push_subscriptions"


#define CMD_SELID CMD_GETFIELDS                                             \
    " WHERE id = :id;"

EXPORTED int pushsubdb_lookup_id(struct pushsub_db *pushsubdb, const char *id,
                               struct pushsub_data **result, int tombstones)
{
    struct sqldb_bindval bval[] = {
        { ":id", SQLITE_TEXT, { .s = id                  } },
        { NULL,  SQLITE_NULL, { .s = NULL                } } };
    static struct pushsub_data psdata;
    struct read_rock rrock = { pushsubdb, &psdata, tombstones, NULL, NULL };
    int r;

    *result = memset(&psdata, 0, sizeof(struct pushsub_data));

    r = sqldb_exec(pushsubdb->db, CMD_SELID, bval, &read_cb, &rrock);
    if (!r && !psdata.rowid) r = CYRUSDB_NOTFOUND;

    return r;
}


#define CMD_SELIMAPUID CMD_GETFIELDS                                        \
    " WHERE imap_uid = :imap_uid;"

EXPORTED int pushsubdb_lookup_imapuid(struct pushsub_db *pushsubdb, int imap_uid,
                                    struct pushsub_data **result, int tombstones)
{
    struct sqldb_bindval bval[] = {
        { ":imap_uid", SQLITE_INTEGER, { .i = imap_uid      } },
        { NULL,        SQLITE_NULL,    { .s = NULL          } } };
    static struct pushsub_data psdata;
    struct read_rock rrock = { pushsubdb, &psdata, tombstones, NULL, NULL };
    int r;

    *result = memset(&psdata, 0, sizeof(struct pushsub_data));

    r = sqldb_exec(pushsubdb->db, CMD_SELIMAPUID, bval, &read_cb, &rrock);
    if (!r && !psdata.rowid) r = CYRUSDB_NOTFOUND;

    psdata.imap_uid = imap_uid;

    return r;
}


#define CMD_SELMBOX CMD_GETFIELDS                                       \
    " WHERE alive = 1;"

EXPORTED int pushsubdb_foreach(struct pushsub_db *pushsubdb,
                             int (*cb)(void *rock, struct pushsub_data *data),
                             void *rock)
{
    struct pushsub_data psdata;
    struct read_rock rrock = { pushsubdb, &psdata, 0, cb, rock };

    return sqldb_exec(pushsubdb->db, CMD_SELMBOX, NULL, &read_cb, &rrock);
}


#define CMD_INSERT                                                      \
    "INSERT INTO push_subscriptions ("                                  \
    "  mailbox, imap_uid,"                                              \
    "  id, subscription, expires, isverified, alive )"                  \
    " VALUES ("                                                         \
    "  :mailbox, :imap_uid,"                                            \
    "  :id, :subscription, :expires, :isverified, :alive );"

#define CMD_UPDATE                       \
    "UPDATE push_subscriptions SET"      \
    "  subscription  = :subscription,"   \
    "  expires       = :expires,"        \
    "  isverified    = :isverified,"     \
    "  alive         = :alive"           \
    " WHERE rowid = :rowid;"

EXPORTED int pushsubdb_write(struct pushsub_db *pushsubdb, struct pushsub_data *psdata)
{
    struct sqldb_bindval bval[] = {
        { ":subscription",  SQLITE_TEXT,    { .s = psdata->subscription } },
        { ":expires",       SQLITE_INTEGER, { .i = psdata->expires      } },
        { ":isverified",    SQLITE_INTEGER, { .i = psdata->isverified   } },
        { ":alive",         SQLITE_INTEGER, { .i = psdata->alive        } },
        { NULL,             SQLITE_NULL,    { .s = NULL                 } },
        { NULL,             SQLITE_NULL,    { .s = NULL                 } },
        { NULL,             SQLITE_NULL,    { .s = NULL                 } },
        { NULL,             SQLITE_NULL,    { .s = NULL                 } } };
    const char *cmd;
    int r;

    if (psdata->rowid) {
        cmd = CMD_UPDATE;

        bval[4].name = ":rowid";
        bval[4].type = SQLITE_INTEGER;
        bval[4].val.i = psdata->rowid;
    }
    else {
        cmd = CMD_INSERT;

        bval[4].name = ":mailbox";
        bval[4].type = SQLITE_TEXT;
        bval[4].val.s = psdata->mailbox;
        bval[5].name = ":imap_uid";
        bval[5].type = SQLITE_INTEGER;
        bval[5].val.i = psdata->imap_uid;
        bval[6].name = ":id";
        bval[6].type = SQLITE_TEXT;
        bval[6].val.s = psdata->id;
    }

    r = sqldb_exec(pushsubdb->db, cmd, bval, NULL, NULL);

    return r;
}


#define CMD_DELETE "DELETE FROM push_subscriptions WHERE rowid = :rowid;"

EXPORTED int pushsubdb_delete(struct pushsub_db *pushsubdb, unsigned rowid)
{
    struct sqldb_bindval bval[] = {
        { ":rowid", SQLITE_INTEGER, { .i = rowid } },
        { NULL,     SQLITE_NULL,    { .s = NULL  } } };
    int r;

    r = sqldb_exec(pushsubdb->db, CMD_DELETE, bval, NULL, NULL);

    return r;
}

EXPORTED int pushsub_ensure_folder(const char *userid, struct mailbox **mailboxptr)
{
    struct mboxlock *namespacelock = NULL;
    char *mboxname = pushsub_mboxname(userid);
    int r = mboxlist_lookup(mboxname, NULL, NULL);

    if (r == IMAP_MAILBOX_NONEXISTENT) {
        namespacelock = user_namespacelock(userid);

        if (!namespacelock) {
            r = IMAP_MAILBOX_LOCKED;
            goto done;
        }

        /* maybe we lost the race on this one */
        r = mboxlist_lookup(mboxname, NULL, NULL);
    }

    if (!r && mailboxptr) {
        r = mailbox_open_iwl(mboxname, mailboxptr);
        if (r) {
            syslog(LOG_ERR, "IOERROR: failed to open %s (%s)",
                   mboxname, error_message(r));
            goto done;
        }
    }

    else if (r == IMAP_MAILBOX_NONEXISTENT) {
        /* Create locally */
        struct mailbox *mailbox = NULL;
        mbentry_t mbentry = MBENTRY_INITIALIZER;
        mbentry.name = (char *) mboxname;
        mbentry.mbtype = MBTYPE_JMAPPUSHSUB;

        r = mboxlist_createmailbox(&mbentry, 0/*options*/, 0/*highestmodseq*/,
                                   1/*isadmin*/, userid, NULL/*auth_state*/,
                                   0/*flags*/, &mailbox);
        if (r) {
            syslog(LOG_ERR, "IOERROR: failed to create %s (%s)",
                   mboxname, error_message(r));
            goto done;
        }

        if (mailboxptr) *mailboxptr = mailbox;
        else mailbox_close(&mailbox);
    }

  done:
    mboxname_release(&namespacelock);
    free(mboxname);
    return r;
}

EXPORTED char *pushsub_mboxname(const char *userid)
{
    struct buf boxbuf = BUF_INITIALIZER;
    char *res = NULL;

    init_internal();

    buf_setcstr(&boxbuf, config_getstring(IMAPOPT_JMAPPUSHSUBSCRIPTIONFOLDER));

    res = mboxname_user_mbox(userid, buf_cstring(&boxbuf));

    buf_free(&boxbuf);

    return res;
}
