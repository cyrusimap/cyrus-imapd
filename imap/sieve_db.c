/* sieve_db.c -- implementation of per-user Sieve database
 *
 * Copyright (c) 1994-2020 Carnegie Mellon University.  All rights reserved.
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
#include "sieve_db.h"
#include "sievedir.h"
#include "times.h"
#include "user.h"
#include "util.h"
#include "xmalloc.h"

#include "sieve/bytecode.h"
#include "sieve/bc_parse.h"
#include "sieve/script.h"
#include "sieve/sieve_interface.h"

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"


enum {
    STMT_SELRSRC,
    STMT_SELUID,
    STMT_SELMBOX,
    STMT_INSERT,
    STMT_UPDATE,
    STMT_DELETE,
    STMT_DELMBOX,
    STMT_BEGIN,
    STMT_COMMIT,
    STMT_ROLLBACK
};

#define NUM_STMT 10

struct sieve_db {
    sqldb_t *db;                        /* DB handle */
    struct buf mailbox;                 /* buffers for copies of column text */
    struct buf id;
    struct buf name;
    struct buf contentid;
};

static int sieve_initialized = 0;

static void done_cb(void *rock __attribute__((unused))) {
    sievedb_done();
}

static void init_internal() {
    if (!sieve_initialized) {
        sievedb_init();
        cyrus_modules_add(done_cb, NULL);
    }
}

EXPORTED int sievedb_init(void)
{
    int r = sqldb_init();
    if (!r) sieve_initialized = 1;
    return r;
}


EXPORTED int sievedb_done(void)
{
    int r = sqldb_done();
    if (!r) sieve_initialized = 0;
    return r;
}

/* Open Sieve DB corresponding to userid */
EXPORTED struct sieve_db *sievedb_open_userid(const char *userid)
{
    struct sieve_db *sievedb = NULL;

    init_internal();

    sqldb_t *db = dav_open_userid(userid);
    if (!db) return NULL;

    sievedb = xzmalloc(sizeof(struct sieve_db));
    sievedb->db = db;

    return sievedb;
}

/* Open Sieve DB corresponding to mailbox */
EXPORTED struct sieve_db *sievedb_open_mailbox(struct mailbox *mailbox)
{
    struct sieve_db *sievedb = NULL;
    char *userid = mboxname_to_userid(mailbox_name(mailbox));

    init_internal();

    if (userid) {
        sievedb = sievedb_open_userid(userid);
        free(userid);
        return sievedb;
    }

    sqldb_t *db = dav_open_mailbox(mailbox);
    if (!db) return NULL;

    sievedb = xzmalloc(sizeof(struct sieve_db));
    sievedb->db = db;

    return sievedb;
}

/* Close Sieve DB */
EXPORTED int sievedb_close(struct sieve_db *sievedb)
{
    int r = 0;

    if (!sievedb) return 0;

    buf_free(&sievedb->mailbox);
    buf_free(&sievedb->id);
    buf_free(&sievedb->name);
    buf_free(&sievedb->contentid);

    r = dav_close(&sievedb->db);

    free(sievedb);

    return r;
}

EXPORTED int sievedb_begin(struct sieve_db *sievedb)
{
    return sqldb_begin(sievedb->db, "sieve");
}

EXPORTED int sievedb_commit(struct sieve_db *sievedb)
{
    return sqldb_commit(sievedb->db, "sieve");
}

EXPORTED int sievedb_abort(struct sieve_db *sievedb)
{
    return sqldb_rollback(sievedb->db, "sieve");
}


struct read_rock {
    struct sieve_db *db;
    struct sieve_data *sdata;
    int tombstones;
    sieve_cb_t *cb;
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
    struct sieve_db *db = rrock->db;
    struct sieve_data *sdata = rrock->sdata;
    int r = 0;

    memset(sdata, 0, sizeof(struct sieve_data));

    sdata->modseq = sqlite3_column_int64(stmt, 5);
    sdata->createdmodseq = sqlite3_column_int64(stmt, 6);
    sdata->alive = sqlite3_column_int(stmt, 11);
    if (!rrock->tombstones && !sdata->alive)
        return 0;

    sdata->rowid = sqlite3_column_int(stmt, 0);
    sdata->creationdate = sqlite3_column_int(stmt, 1);
    sdata->lastupdated = sqlite3_column_int(stmt, 2);
    sdata->imap_uid = sqlite3_column_int(stmt, 4);
    sdata->isactive = sqlite3_column_int(stmt, 10);

    if (rrock->cb) {
        /* We can use the column data directly for the callback */
        sdata->mailbox = (const char *) sqlite3_column_text(stmt, 3);
        sdata->id = (const char *) sqlite3_column_text(stmt, 7);
        sdata->name = (const char *) sqlite3_column_text(stmt, 8);
        sdata->contentid = (const char *) sqlite3_column_text(stmt, 9);
        r = rrock->cb(rrock->rock, sdata);
    }
    else {
        /* For single row SELECTs like sieve_read(),
         * we need to make a copy of the column data before
         * it gets flushed by sqlite3_step() or sqlite3_reset() */
        sdata->mailbox =
            column_text_to_buf((const char *) sqlite3_column_text(stmt, 3),
                               &db->mailbox);
        sdata->id =
            column_text_to_buf((const char *) sqlite3_column_text(stmt, 7),
                               &db->id);
        sdata->name =
            column_text_to_buf((const char *) sqlite3_column_text(stmt, 8),
                               &db->name);
        sdata->contentid =
            column_text_to_buf((const char *) sqlite3_column_text(stmt, 9),
                               &db->contentid);
    }

    return r;
}

#define CMD_GETFIELDS                                                       \
    "SELECT rowid, creationdate, lastupdated, mailbox, imap_uid,"           \
    "  modseq, createdmodseq, id, name, contentid, isactive, alive"         \
    " FROM sieve_scripts"


#define CMD_SELNAME CMD_GETFIELDS                                           \
    " WHERE name = :name;"

EXPORTED int sievedb_lookup_name(struct sieve_db *sievedb, const char *name,
                                 struct sieve_data **result, int tombstones)
{
    struct sqldb_bindval bval[] = {
        { ":name",    SQLITE_TEXT, { .s = name          } },
        { NULL,       SQLITE_NULL, { .s = NULL          } } };
    static struct sieve_data sdata;
    struct read_rock rrock = { sievedb, &sdata, tombstones, NULL, NULL };
    int r;

    *result = memset(&sdata, 0, sizeof(struct sieve_data));

    r = sqldb_exec(sievedb->db, CMD_SELNAME, bval, &read_cb, &rrock);
    if (!r && !sdata.rowid) r = CYRUSDB_NOTFOUND;

    return r;
}


#define CMD_SELID CMD_GETFIELDS                                             \
    " WHERE id = :id;"

EXPORTED int sievedb_lookup_id(struct sieve_db *sievedb, const char *id,
                               struct sieve_data **result, int tombstones)
{
    struct sqldb_bindval bval[] = {
        { ":id", SQLITE_TEXT, { .s = id                  } },
        { NULL,  SQLITE_NULL, { .s = NULL                } } };
    static struct sieve_data sdata;
    struct read_rock rrock = { sievedb, &sdata, tombstones, NULL, NULL };
    int r;

    *result = memset(&sdata, 0, sizeof(struct sieve_data));

    r = sqldb_exec(sievedb->db, CMD_SELID, bval, &read_cb, &rrock);
    if (!r && !sdata.rowid) r = CYRUSDB_NOTFOUND;

    return r;
}


#define CMD_SELIMAPUID CMD_GETFIELDS                                        \
    " WHERE imap_uid = :imap_uid;"

EXPORTED int sievedb_lookup_imapuid(struct sieve_db *sievedb, int imap_uid,
                                    struct sieve_data **result, int tombstones)
{
    struct sqldb_bindval bval[] = {
        { ":imap_uid", SQLITE_INTEGER, { .i = imap_uid      } },
        { NULL,        SQLITE_NULL,    { .s = NULL          } } };
    static struct sieve_data sdata;
    struct read_rock rrock = { sievedb, &sdata, tombstones, NULL, NULL };
    int r;

    *result = memset(&sdata, 0, sizeof(struct sieve_data));

    r = sqldb_exec(sievedb->db, CMD_SELIMAPUID, bval, &read_cb, &rrock);
    if (!r && !sdata.rowid) r = CYRUSDB_NOTFOUND;

    sdata.imap_uid = imap_uid;

    return r;
}


#define CMD_SELACTIVE CMD_GETFIELDS " WHERE isactive = 1 AND alive = 1;"

EXPORTED int sievedb_lookup_active(struct sieve_db *sievedb,
                                   struct sieve_data **result)
{
    static struct sieve_data sdata;
    struct read_rock rrock = { sievedb, &sdata, 0, NULL, NULL };
    int r;

    *result = memset(&sdata, 0, sizeof(struct sieve_data));

    r = sqldb_exec(sievedb->db, CMD_SELACTIVE, NULL, &read_cb, &rrock);
    if (!r && !sdata.rowid) r = CYRUSDB_NOTFOUND;

    return r;
}


#define CMD_SELMBOX CMD_GETFIELDS                                       \
    " WHERE alive = 1;"

EXPORTED int sievedb_foreach(struct sieve_db *sievedb,
                             int (*cb)(void *rock, struct sieve_data *data),
                             void *rock)
{
    struct sieve_data sdata;
    struct read_rock rrock = { sievedb, &sdata, 0, cb, rock };

    return sqldb_exec(sievedb->db, CMD_SELMBOX, NULL, &read_cb, &rrock);
}


#define CMD_INSERT                                                      \
    "INSERT INTO sieve_scripts ("                                       \
    "  creationdate, lastupdated, mailbox, imap_uid,"                   \
    "  modseq, createdmodseq,  id, name, contentid, isactive, alive )"  \
    " VALUES ("                                                         \
    "  :creationdate, :lastupdated, :mailbox, :imap_uid,"               \
    "  :modseq, :createdmodseq,  :id, :name, :contentid, :isactive, :alive );"

#define CMD_UPDATE                       \
    "UPDATE sieve_scripts SET"           \
    "  lastupdated   = :lastupdated,"    \
    "  imap_uid      = :imap_uid,"       \
    "  modseq        = :modseq,"         \
    "  name          = :name,"           \
    "  contentid     = :contentid,"      \
    "  isactive      = :isactive,"       \
    "  alive         = :alive"           \
    " WHERE rowid = :rowid;"

EXPORTED int sievedb_write(struct sieve_db *sievedb, struct sieve_data *sdata)
{
    struct sqldb_bindval bval[] = {
        { ":lastupdated",   SQLITE_INTEGER, { .i = sdata->lastupdated   } },
        { ":imap_uid",      SQLITE_INTEGER, { .i = sdata->imap_uid      } },
        { ":modseq",        SQLITE_INTEGER, { .i = sdata->modseq        } },
        { ":name",          SQLITE_TEXT,    { .s = sdata->name          } },
        { ":contentid",     SQLITE_TEXT,    { .s = sdata->contentid     } },
        { ":isactive",      SQLITE_INTEGER, { .i = sdata->isactive      } },
        { ":alive",         SQLITE_INTEGER, { .i = sdata->alive         } },
        { NULL,             SQLITE_NULL,    { .s = NULL                 } },
        { NULL,             SQLITE_NULL,    { .s = NULL                 } },
        { NULL,             SQLITE_NULL,    { .s = NULL                 } },
        { NULL,             SQLITE_NULL,    { .s = NULL                 } },
        { NULL,             SQLITE_NULL,    { .s = NULL                 } } };
    const char *cmd;
    int r;

    if (sdata->rowid) {
        cmd = CMD_UPDATE;

        bval[7].name = ":rowid";
        bval[7].type = SQLITE_INTEGER;
        bval[7].val.i = sdata->rowid;
    }
    else {
        cmd = CMD_INSERT;

        bval[7].name = ":creationdate";
        bval[7].type = SQLITE_INTEGER;
        bval[7].val.i = sdata->creationdate;
        bval[8].name = ":createdmodseq";
        bval[8].type = SQLITE_INTEGER;
        bval[8].val.i = sdata->createdmodseq;
        bval[9].name = ":id";
        bval[9].type = SQLITE_TEXT;
        bval[9].val.s = sdata->id;
        bval[10].name = ":mailbox";
        bval[10].type = SQLITE_TEXT;
        bval[10].val.s = sdata->mailbox;
    }

    r = sqldb_exec(sievedb->db, cmd, bval, NULL, NULL);

    return r;
}


#define CMD_DELETE "DELETE FROM sieve_scripts WHERE rowid = :rowid;"

EXPORTED int sievedb_delete(struct sieve_db *sievedb, unsigned rowid)
{
    struct sqldb_bindval bval[] = {
        { ":rowid", SQLITE_INTEGER, { .i = rowid } },
        { NULL,     SQLITE_NULL,    { .s = NULL  } } };
    int r;

    r = sqldb_exec(sievedb->db, CMD_DELETE, bval, NULL, NULL);

    return r;
}


#define CMD_DELMBOX "DELETE FROM sieve_scripts;"

HIDDEN int sievedb_delmbox(struct sieve_db *sievedb)
{
    int r;

    r = sqldb_exec(sievedb->db, CMD_DELMBOX, NULL, NULL, NULL);

    return r;
}

EXPORTED int sievedb_get_updates(struct sieve_db *sievedb,
                                 modseq_t oldmodseq, int limit,
                                 int (*cb)(void *rock, struct sieve_data *sdata),
                                 void *rock)
{
    struct sqldb_bindval bval[] = {
        { ":modseq",       SQLITE_INTEGER, { .i = oldmodseq } },
        /* SQLite interprets a negative limit as unbounded. */
        { ":limit",        SQLITE_INTEGER, { .i = limit > 0 ? limit : -1 } },
        { NULL,            SQLITE_NULL,    { .s = NULL      } }
    };
    static struct sieve_data sdata;
    struct read_rock rrock = { sievedb, &sdata, 1 /* tombstones */, cb, rock };
    struct buf sqlbuf = BUF_INITIALIZER;
    int r;

    buf_setcstr(&sqlbuf, CMD_GETFIELDS " WHERE");
    if (!oldmodseq) buf_appendcstr(&sqlbuf, " alive = 1 AND");
    buf_appendcstr(&sqlbuf, " modseq > :modseq ORDER BY modseq LIMIT :limit;");

    r = sqldb_exec(sievedb->db, buf_cstring(&sqlbuf), bval, &read_cb, &rrock);
    buf_free(&sqlbuf);

    return r;
}

static int count_cb(sqlite3_stmt *stmt, void *rock)
{
    int *count = (int *) rock;

    *count = sqlite3_column_int(stmt, 0);

    return 0;
}

#define CMD_COUNTREC "SELECT COUNT(name) FROM sieve_scripts WHERE alive = 1;"

EXPORTED int sievedb_count(struct sieve_db *sievedb, int *count)
{
    int r;

    *count = 0;

    r = sqldb_exec(sievedb->db, CMD_COUNTREC, NULL, &count_cb, count);

    return r;
}

static int lock_and_execute(struct mailbox *mailbox,
                            struct sieve_data *sdata,
                            void *rock,
                            int (*proc)(struct mailbox *mailbox,
                                        struct sieve_data *sdata,
                                        void *rock))
{
    int r, unlock = 0;

    if (!mailbox_index_islocked(mailbox, 1/*write*/)) {
        r = mailbox_lock_index(mailbox, LOCK_EXCLUSIVE);

        if (r) {
            syslog(LOG_ERR, "locking mailbox %s failed: %s",
                   mailbox_name(mailbox), error_message(r));
            return r;
        }

        unlock = 1;
    }

    r = proc(mailbox, sdata, rock);

    if (unlock) mailbox_unlock_index(mailbox, NULL);

    return r;
}

static int remove_uid(struct mailbox *mailbox, uint32_t uid)
{
    struct index_record record;
    int r;

    r = mailbox_find_index_record(mailbox, uid, &record);
    if (!r) {
        record.internal_flags |= FLAG_INTERNAL_EXPUNGED;

        r = mailbox_rewrite_index_record(mailbox, &record);
    }

    if (r) {
        syslog(LOG_ERR, "expunging record (%s:%u) failed: %s",
               mailbox_name(mailbox), uid, error_message(r));
    }

    return r;
}

static int store_script(struct mailbox *mailbox, struct sieve_data *sdata,
                        void *rock)
{
    const struct buf *databuf = (const struct buf *) rock;
    strarray_t flags = STRARRAY_INITIALIZER;
    struct auth_state *authstate = NULL;
    struct buf buf = BUF_INITIALIZER;
    uint32_t old_uid = sdata->imap_uid;
    const char *data = buf_base(databuf);
    size_t datalen = buf_len(databuf);
    struct stagemsg *stage;
    struct appendstate as;
    time_t now = time(0);
    FILE *f = NULL;
    char *mimehdr;
    int r = 0;

    init_internal();

    /* Prepare to stage the message */
    if (!(f = append_newstage(mailbox_name(mailbox), now, 0, &stage))) {
        syslog(LOG_ERR, "append_newstage(%s) failed", mailbox_name(mailbox));
        return CYRUSDB_IOERROR;
    }

    /* Create RFC 5322 header for script */
    char *userid = mboxname_to_userid(mailbox_name(mailbox));
    if (strchr(userid, '@')) {
        buf_printf(&buf, "<%s>", userid);
    }
    else {
        buf_printf(&buf, "<%s@%s>", userid, config_servername);
    }
    mimehdr = charset_encode_mimeheader(buf_cstring(&buf), buf_len(&buf), 0);
    fprintf(f, "From: %s\r\n", mimehdr);
    free(mimehdr);

    mimehdr = charset_encode_mimeheader(sdata->name, 0, 0);
    fprintf(f, "Subject: %s\r\n", mimehdr);
    free(mimehdr);

    char datestr[80];
    time_to_rfc5322(now, datestr, sizeof(datestr));
    fprintf(f, "Date: %s\r\n", datestr);

    /* Use SHA1(script) as contentid */
    struct message_guid uuid;
    message_guid_generate(&uuid, data, datalen);
    sdata->contentid = message_guid_encode(&uuid);

    /* Use scriptid@servername as Message-ID */
    fprintf(f, "Message-ID: <%s@%s>\r\n", sdata->contentid, config_servername);

    fprintf(f, "Content-Type: application/sieve; charset=utf-8\r\n");
    fprintf(f, "Content-Length: %lu\r\n", datalen);
    fprintf(f, "Content-Disposition: attachment;\r\n\tfilename=\"%s%s\"\r\n",
            sdata->id ? sdata->id : makeuuid(), SIEVE_EXTENSION);
    fputs("MIME-Version: 1.0\r\n", f);
    fputs("\r\n", f);

    /* Write the script data to the file */
    fwrite(data, datalen, 1, f);

    fclose(f);

    if (sdata->isactive) {
        /* Flag script as active */
        strarray_append(&flags, "\\Flagged");

        /* Need authstate in order to set flags */
        authstate = auth_newstate(userid);
    }

    if ((r = append_setup_mbox(&as, mailbox, userid, authstate,
                               0, NULL, NULL, 0, 0))) {
        syslog(LOG_ERR, "append_setup(%s) failed: %s",
               mailbox_name(mailbox), error_message(r));
    }
    else {
        struct body *body = NULL;

        r = append_fromstage(&as, &body, stage, now,
                             sdata->createdmodseq, &flags, 0, NULL);
        if (body) {
            message_free_body(body);
            free(body);
        }

        if (r) {
            syslog(LOG_ERR, "append_fromstage() failed: %s", error_message(r));
            append_abort(&as);
        }
        else {
            /* Commit the append to the sieve mailbox */
            r = append_commit(&as);
            if (r) {
                syslog(LOG_ERR, "append_commit() failed: %s", error_message(r));
            }
            else if (old_uid) {
                /* Now that we have the replacement script in place
                   expunge the old one. */
                r = remove_uid(mailbox, old_uid);
            }
        }
    }

    append_removestage(stage);
    auth_freestate(authstate);
    strarray_fini(&flags);
    buf_free(&buf);
    free(userid);

    return r;
}

EXPORTED int sieve_script_store(struct mailbox *mailbox,
                                struct sieve_data *sdata,
                                const struct buf *content)
{
    return lock_and_execute(mailbox, sdata, (void *) content, &store_script);
}

static int activate_script(struct mailbox *mailbox, struct sieve_data *sdata,
                           void *rock __attribute__((unused)))
{
    struct index_record record;
    int activate = (sdata != NULL);
    int r;

    init_internal();

    if (activate) {
        if (sdata->isactive) return 0;

        r = mailbox_find_index_record(mailbox, sdata->imap_uid, &record);
        if (r) {
            syslog(LOG_ERR, "fetching record (%s:%u) failed: %s",
                   mailbox_name(mailbox), sdata->imap_uid, error_message(r));
            return r;
        }
    }

    struct sieve_db *sievedb = sievedb_open_mailbox(mailbox);

    if (!sievedb) {
        syslog(LOG_ERR, "opening sieve_db for %s failed", mailbox_name(mailbox));
        return CYRUSDB_IOERROR;
    }
        
    struct sieve_data *mydata = NULL;
    r = sievedb_lookup_active(sievedb, &mydata);

    if (r == CYRUSDB_NOTFOUND) {
        /* No active script to deactivate */
        r = 0;
    }
    else if (!r) {
        struct index_record oldactive;

        r = mailbox_find_index_record(mailbox, mydata->imap_uid, &oldactive);
        if (r) {
            syslog(LOG_ERR, "fetching record (%s:%u) failed: %s",
                   mailbox_name(mailbox), mydata->imap_uid, error_message(r));
        }
        else {
            oldactive.system_flags &= ~FLAG_FLAGGED;
            r = mailbox_rewrite_index_record(mailbox, &oldactive);

            if (r) {
                syslog(LOG_ERR, "unflagging record (%s:%u) failed: %s",
                       mailbox_name(mailbox), oldactive.uid, error_message(r));
            }
        }
    }
    sievedb_close(sievedb);

    if (!r && activate) {
        record.system_flags |= FLAG_FLAGGED;
        r = mailbox_rewrite_index_record(mailbox, &record);

        if (r) {
            syslog(LOG_ERR, "flagging record (%s:%u) failed: %s",
                   mailbox_name(mailbox), record.uid, error_message(r));
        }
    }

    return r;
}

EXPORTED int sieve_script_activate(struct mailbox *mailbox,
                                   struct sieve_data *sdata)
{
    return lock_and_execute(mailbox, sdata, NULL, &activate_script);
}

static int remove_script(struct mailbox *mailbox, struct sieve_data *sdata,
                         void *rock __attribute__((unused)))
{
    init_internal();

    return remove_uid(mailbox, sdata->imap_uid);
}

EXPORTED int sieve_script_remove(struct mailbox *mailbox,
                                 struct sieve_data *sdata)
{
    return lock_and_execute(mailbox, sdata, NULL, &remove_script);
}

EXPORTED int sieve_script_rename(struct mailbox *mailbox,
                                 struct sieve_data *sdata,
                                 const char *newname)
{
    struct buf content = BUF_INITIALIZER;
    int r;

    r = sieve_script_fetch(mailbox, sdata, &content);
    if (!r) {
        sdata->name = newname;

        r = sieve_script_store(mailbox, sdata, &content);
    }

    buf_free(&content);

    return r;
}

EXPORTED int sieve_script_fetch(struct mailbox *mailbox,
                                const struct sieve_data *sdata,
                                struct buf *content)
{
    struct index_record record;
    int r;

    r = mailbox_find_index_record(mailbox, sdata->imap_uid, &record);
    if (!r) {
        /* Load message containing the resource */
        message_t *m = message_new_from_record(mailbox, &record);

        r = message_get_field(m, "rawbody", MESSAGE_RAW, content);

        message_unref(&m);
    }

    if (r) {
        syslog(LOG_ERR, "fetching message (%s:%u) failed: %s",
               mailbox_name(mailbox), sdata->imap_uid, error_message(r));
    }

    return r;
}

struct migrate_rock {
    struct mailbox *mailbox;
    char *active;
};

static int migrate_cb(const char *sievedir,
                      const char *fname, struct stat *sbuf,
                      const char *link_target __attribute__((unused)),
                      void *rock)
{
    struct migrate_rock *mrock = (struct migrate_rock *) rock;
    struct buf *content = sievedir_get_script(sievedir, fname);

    if (content) {
        struct sieve_data sdata;
        char *myname = xstrndup(fname, strlen(fname) - SCRIPT_SUFFIX_LEN);
        int deletebc = 0;

        memset(&sdata, 0, sizeof(sdata));

        if (!strcmp(myname, "jmap_vacation")) {
            sdata.id = sdata.name = JMAP_URN_VACATION;
            deletebc = 1;
        }
        else {
            sdata.name = myname;
        }
        sdata.lastupdated = sbuf->st_mtime;
        sdata.isactive = !strcmpnull(myname, mrock->active);

        if (!store_script(mrock->mailbox, &sdata, content)) {
            char path[PATH_MAX];

            /* delete script */
            snprintf(path, sizeof(path), "%s/%s", sievedir, fname);
            unlink(path);

            if (deletebc) {
                sievedir_delete_script(sievedir, myname);
            }
        }

        buf_destroy(content);
        free(myname);
    }

    return SIEVEDIR_OK;
}

EXPORTED int sieve_ensure_folder(const char *userid, struct mailbox **mailboxptr)
{
    const char *sievedir = user_sieve_path(userid);
    struct stat sbuf;
    int r;

    r = stat(sievedir, &sbuf);
    if (r && errno == ENOENT) {
        if (!mailboxptr) {
            /* Don't bother continuing if sievedir doesn't currently exist */
            return 0;
        }

        r = cyrus_mkdir(sievedir, 0755);
        if (!r) {
            r = mkdir(sievedir, 0755);
        }
    }
    if (r) return IMAP_IOERROR;


    struct mboxlock *namespacelock = NULL;
    char *mboxname = sieve_mboxname(userid);
    r = mboxlist_lookup(mboxname, NULL, NULL);

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
        mbentry.mbtype = MBTYPE_SIEVE;

        r = mboxlist_createmailbox(&mbentry, 0/*options*/, 0/*highestmodseq*/,
                                   1/*isadmin*/, userid, NULL/*auth_state*/,
                                   0/*flags*/, &mailbox);
        if (r) {
            syslog(LOG_ERR, "IOERROR: failed to create %s (%s)",
                   mboxname, error_message(r));
            goto done;
        }

        /* Migrate scripts from sievedir into mailbox */
        struct migrate_rock mrock =
            { mailbox, xstrdupnull(sievedir_get_active(sievedir)) };

        sievedir_foreach(sievedir, SIEVEDIR_SCRIPTS_ONLY, &migrate_cb, &mrock);

        free(mrock.active);

        if (mailboxptr) *mailboxptr = mailbox;
        else mailbox_close(&mailbox);
    }

  done:
    mboxname_release(&namespacelock);
    free(mboxname);
    return r;
}

EXPORTED int sieve_script_rebuild(const char *userid,
                                  const char *sievedir, const char *script)
{
    struct buf namebuf = BUF_INITIALIZER, *content_buf = NULL;
    struct sieve_data *sdata = NULL;
    struct sieve_db *db = NULL;
    const char *content = NULL;
    time_t lastupdated = 0;
    struct stat bc_stat;
    int r;

    db = sievedb_open_userid(userid);
    if (!db) {
        r = IMAP_INTERNAL;
        goto done;
    }

    /* Lookup script in Sieve DB */
    r = sievedb_lookup_name(db, script, &sdata, 0);
    if (!r) {
        char *mboxname = sieve_mboxname(userid);
        struct mailbox *mailbox = NULL;

        lastupdated = sdata->lastupdated;

        content_buf = buf_new();

        r = mailbox_open_irl(mboxname, &mailbox);
        if (r) {
            syslog(LOG_ERR, "IOERROR: failed to open %s (%s)",
                   mboxname, error_message(r));
        }
        else {
            r = sieve_script_fetch(mailbox, sdata, content_buf);

            if (!r) {
                content = buf_cstring(content_buf);
            }
        }
        mailbox_close(&mailbox);
        free(mboxname);

        if (r) goto done;
    }
    else if (r == CYRUSDB_NOTFOUND) {
        /* Get mtime of script file */
        struct stat sbuf;

        buf_printf(&namebuf, "%s/%s%s", sievedir, script, SCRIPT_SUFFIX);
        r = stat(buf_cstring(&namebuf), &sbuf);
        if (!r) {
            lastupdated = sbuf.st_mtime;
        }
        else {
            syslog(LOG_ERR, "IOERROR: stat %s: %m", buf_cstring(&namebuf));
        }
    }

    if (r) {
        r = IMAP_IOERROR;
        goto done;
    }

    /* Get mtime of bytecode file */
    buf_reset(&namebuf);
    buf_printf(&namebuf, "%s/%s%s", sievedir, script, BYTECODE_SUFFIX);
    r = stat(buf_cstring(&namebuf), &bc_stat);
    if (r && errno != ENOENT) {
        syslog(LOG_ERR, "IOERROR: stat %s: %m", buf_cstring(&namebuf));
        r = IMAP_IOERROR;
        goto done;
    }

    if (!r && bc_stat.st_mtime >= lastupdated) {
        /* Check version of bytecode file */
        sieve_execute_t *exe = NULL;
        int version = -1;

        r = sieve_script_load(buf_cstring(&namebuf), &exe);

        if (!r) {
            bc_header_parse((bytecode_input_t *) exe->bc_cur->data,
                            &version, NULL);
        }

        sieve_script_unload(&exe);

        if (version == BYTECODE_VERSION) {
            syslog(LOG_DEBUG,
                   "%s: %s is up to date\n", __func__, buf_cstring(&namebuf));
            goto done;
        }
    }

    if (!content) {
        /* Fetch content from script file */
        buf_reset(&namebuf);
        buf_printf(&namebuf, "%s%s", script, SCRIPT_SUFFIX);

        content_buf = sievedir_get_script(sievedir, buf_cstring(&namebuf));
                                          
        if (!content_buf) {
            r = IMAP_IOERROR;
            goto done;
        }

        content = buf_cstring(content_buf);
    }

    /* Update bytecode */
    char *errors = NULL;
    r = sievedir_put_script(sievedir, script, content, &errors);
    free(errors);

  done:
    buf_destroy(content_buf);
    buf_free(&namebuf);
    sievedb_close(db);

    return r;
}

#define CMD_ALTER_v12_TABLE              \
    "ALTER TABLE sieve_scripts RENAME COLUMN content TO contentid;"

#define CMD_UPDATE_v12_ROW               \
    "UPDATE sieve_scripts SET"           \
    "  contentid     = :contentid"       \
    " WHERE rowid = :rowid;"

#define CMD_UPDATE_v13_TABLE             \
    "UPDATE sieve_scripts SET mailbox = :mailbox;"


static int upgrade_cb(void *rock, struct sieve_data *sdata)
{
    strarray_t *sha1 = (strarray_t *) rock;
    struct message_guid uuid;

    /* v12 stored script content in the column that is now named 'contentid' */
    const char *content = sdata->contentid;

    /* Generate SHA1 from content */
    message_guid_generate(&uuid, content, strlen(content));

    /* Add SHA1 to our array using rowid as the index */
    strarray_set(sha1, sdata->rowid, message_guid_encode(&uuid));

    return 0;
}

EXPORTED int sievedb_upgrade(sqldb_t *db)
{
    strarray_t sha1 = STRARRAY_INITIALIZER;
    struct sieve_data sdata;
    struct sieve_db sievedb = { .db = db };
    struct read_rock rrock =
        { &sievedb, &sdata, 1 /*tombstones*/, upgrade_cb, &sha1 };
    struct sqldb_bindval bval[] = {
        { ":rowid",     SQLITE_INTEGER, { .i = 0    } },
        { ":contentid", SQLITE_TEXT,    { .s = NULL } },
        { ":mailbox",   SQLITE_TEXT,    { .s = NULL } },
        { NULL,         SQLITE_NULL,    { .s = NULL } } };
    mbentry_t *mbentry = NULL;
    int rowid, r;

    if (db->version < 12) return 0;
    if (db->version > 13) return 0;

    if (db->version == 12) {
        /* Rename 'content' -> 'contentid' */
        r = sqldb_exec(db, CMD_ALTER_v12_TABLE, NULL, NULL, NULL);
        if (r) return r;

        /* Create an array of SHA1 for the content in each record */
        r = sqldb_exec(db, CMD_GETFIELDS, NULL, &read_cb, &rrock);

        /* Rewrite 'contentid' columns with actual ids (SHA1) */
        for (rowid = 1; !r && rowid < strarray_size(&sha1); rowid++) {
            bval[0].val.i = rowid;
            bval[1].val.s = strarray_nth(&sha1, rowid);

            r = sqldb_exec(db, CMD_UPDATE_v12_ROW, bval, NULL, NULL);
            if (r) goto done;
        }
    }
    else if (db->version == 13) {
        rrock.cb = NULL;
        sdata.mailbox = NULL;
        r = sqldb_exec(db, CMD_GETFIELDS " WHERE rowid = 1;",
                       NULL, &read_cb, &rrock);
        if (r || !sdata.mailbox) goto done;
    }

    r = mboxlist_lookup_allow_all(sdata.mailbox, &mbentry, NULL);
    if (r) goto done;

    bval[2].val.s = mbentry->uniqueid;
    r = sqldb_exec(db, CMD_UPDATE_v13_TABLE, bval, NULL, NULL);

  done:
    mboxlist_entry_free(&mbentry);
    strarray_fini(&sha1);

    return r;
}

EXPORTED char *sieve_mboxname(const char *userid)
{
    struct buf boxbuf = BUF_INITIALIZER;
    char *res = NULL;

    init_internal();

    buf_setcstr(&boxbuf, config_getstring(IMAPOPT_SIEVE_FOLDER));

    res = mboxname_user_mbox(userid, buf_cstring(&boxbuf));

    buf_free(&boxbuf);

    return res;
}
