/* pushsub_db.c -- implementation of per-user PushSubscription database */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

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

#define NUM_STMT 9

struct pushsub_db {
    sqldb_t *db;                        /* DB handle */
    struct buf mailbox;                 /* buffers for copies of column text */
    struct buf id;
    struct buf subscription;
};

static int pushsub_initialized = 0;

/* prepare for pushsub operations in this process */
static void pushsubdb_init(void)
{
    if (!sqldb_init()) pushsub_initialized = 1;
}

/* done with all pushsub operations for this process */
static void pushsubdb_done(void *rock __attribute__((unused)))
{
    if (!sqldb_done()) pushsub_initialized = 0;
}

static void init_internal() {
    if (!pushsub_initialized) {
        pushsubdb_init();
        cyrus_modules_add(pushsubdb_done, NULL);
    }
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
HIDDEN struct pushsub_db *pushsubdb_open_mailbox(struct mailbox *mailbox)
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

HIDDEN int pushsubdb_begin(struct pushsub_db *pushsubdb)
{
    return sqldb_begin(pushsubdb->db, "pushsub");
}

HIDDEN int pushsubdb_commit(struct pushsub_db *pushsubdb)
{
    return sqldb_commit(pushsubdb->db, "pushsub");
}

HIDDEN int pushsubdb_abort(struct pushsub_db *pushsubdb)
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
    "  imap_uid      = :imap_uid,"       \
    "  subscription  = :subscription,"   \
    "  expires       = :expires,"        \
    "  isverified    = :isverified,"     \
    "  alive         = :alive"           \
    " WHERE rowid = :rowid;"

HIDDEN int pushsubdb_write(struct pushsub_db *pushsubdb, struct pushsub_data *psdata)
{
    struct sqldb_bindval bval[] = {
        { ":imap_uid",      SQLITE_INTEGER, { .i = psdata->imap_uid     } },
        { ":subscription",  SQLITE_TEXT,    { .s = psdata->subscription } },
        { ":expires",       SQLITE_INTEGER, { .i = psdata->expires      } },
        { ":isverified",    SQLITE_INTEGER, { .i = psdata->isverified   } },
        { ":alive",         SQLITE_INTEGER, { .i = psdata->alive        } },
        { NULL,             SQLITE_NULL,    { .s = NULL                 } },
        { NULL,             SQLITE_NULL,    { .s = NULL                 } },
        { NULL,             SQLITE_NULL,    { .s = NULL                 } } };
    const char *cmd;

    if (psdata->rowid) {
        cmd = CMD_UPDATE;

        bval[5].name = ":rowid";
        bval[5].type = SQLITE_INTEGER;
        bval[5].val.i = psdata->rowid;
    }
    else {
        cmd = CMD_INSERT;

        bval[5].name = ":mailbox";
        bval[5].type = SQLITE_TEXT;
        bval[5].val.s = psdata->mailbox;
        bval[6].name = ":id";
        bval[6].type = SQLITE_TEXT;
        bval[6].val.s = psdata->id;
    }

    return sqldb_exec(pushsubdb->db, cmd, bval, NULL, NULL);
}


#define CMD_DELETE "DELETE FROM push_subscriptions WHERE rowid = :rowid;"

EXPORTED int pushsubdb_delete(struct pushsub_db *pushsubdb, unsigned rowid)
{
    struct sqldb_bindval bval[] = {
        { ":rowid", SQLITE_INTEGER, { .i = rowid } },
        { NULL,     SQLITE_NULL,    { .s = NULL  } } };

    return sqldb_exec(pushsubdb->db, CMD_DELETE, bval, NULL, NULL);
}

EXPORTED int pushsub_ensure_folder(const char *userid, struct mailbox **mailboxptr)
{
    char *mboxname = pushsub_mboxname(userid);
    int r = mboxlist_lookup(mboxname, NULL, NULL);

    user_nslock_t *user_nslock = NULL;
    if (r == IMAP_MAILBOX_NONEXISTENT) {
        user_nslock = user_nslock_lock_w(userid);

        /* maybe we lost the race on this one */
        r = mboxlist_lookup(mboxname, NULL, NULL);
    }

    if (r == IMAP_MAILBOX_NONEXISTENT) {
        /* Create locally */
        struct mailbox *mailbox = NULL;
        mbentry_t mbentry = MBENTRY_INITIALIZER;
        mbentry.name = (char *) mboxname;
        mbentry.mbtype = MBTYPE_JMAPPUSHSUB;

        r = mboxlist_createmailbox(&mbentry, 0/*options*/, 0/*highestmodseq*/,
                                   1/*isadmin*/, userid, NULL/*auth_state*/,
                                   0/*flags*/, &mailbox);
        if (r) {
            xsyslog(LOG_ERR, "IOERROR: failed to create",
                    "mailbox=<%s> error=<%s>",
                    mboxname, error_message(r));
            goto done;
        }

        // close the mailbox here, we'll re-open once we've released the namespace lock
        mailbox_close(&mailbox);
    }

    // release before opening mailbox so mailbox takes and holds a lock
    user_nslock_release(&user_nslock);

    if (!r && mailboxptr) {
        r = mailbox_open_iwl(mboxname, mailboxptr);
        if (r) {
            xsyslog(LOG_ERR, "IOERROR: failed to open",
                    "mailbox=<%s> error=<%s>",
                    mboxname, error_message(r));
            goto done;
        }
    }

  done:
    user_nslock_release(&user_nslock);
    free(mboxname);
    return r;
}

EXPORTED char *pushsub_mboxname(const char *userid)
{
    init_internal();

    const char *folder = config_getstring(IMAPOPT_JMAPPUSHSUBSCRIPTIONFOLDER);

    return mboxname_user_mbox(userid, folder);
}
