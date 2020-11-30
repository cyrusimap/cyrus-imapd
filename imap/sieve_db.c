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
#include "libconfig.h"
#include "mboxlist.h"
#include "sieve_db.h"
#include "sievedir.h"
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
    struct buf content;
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
    char *userid = mboxname_to_userid(mailbox->name);

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
    buf_free(&sievedb->content);

    r = sqldb_close(&sievedb->db);

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

    sdata->modseq = sqlite3_column_int64(stmt, 4);
    sdata->createdmodseq = sqlite3_column_int64(stmt, 5);
    sdata->alive = sqlite3_column_int(stmt, 10);
    if (!rrock->tombstones && !sdata->alive)
        return 0;

    sdata->rowid = sqlite3_column_int(stmt, 0);
    sdata->creationdate = sqlite3_column_int(stmt, 1);
    sdata->imap_uid = sqlite3_column_int(stmt, 3);
    sdata->isactive = sqlite3_column_int(stmt, 9);

    if (rrock->cb) {
        /* We can use the column data directly for the callback */
        sdata->mailbox = (const char *) sqlite3_column_text(stmt, 2);
        sdata->id = (const char *) sqlite3_column_text(stmt, 6);
        sdata->name = (const char *) sqlite3_column_text(stmt, 7);
        sdata->content = (const char *) sqlite3_column_text(stmt, 8);
        r = rrock->cb(rrock->rock, sdata);
    }
    else {
        /* For single row SELECTs like sieve_read(),
         * we need to make a copy of the column data before
         * it gets flushed by sqlite3_step() or sqlite3_reset() */
        sdata->mailbox =
            column_text_to_buf((const char *) sqlite3_column_text(stmt, 2),
                               &db->mailbox);
        sdata->id =
            column_text_to_buf((const char *) sqlite3_column_text(stmt, 6),
                               &db->id);
        sdata->name =
            column_text_to_buf((const char *) sqlite3_column_text(stmt, 7),
                               &db->name);
        sdata->content =
            column_text_to_buf((const char *) sqlite3_column_text(stmt, 8),
                               &db->content);
    }

    return r;
}

#define CMD_GETFIELDS                                                       \
    "SELECT rowid, creationdate, mailbox, imap_uid, modseq, createdmodseq," \
    "  id, name, content, isactive, alive"                                  \
    " FROM sieve_scripts"


#define CMD_SELNAME CMD_GETFIELDS                                           \
    " WHERE mailbox = :mailbox AND name = :name;"

EXPORTED int sievedb_lookup_name(struct sieve_db *sievedb,
                                 const char *mailbox, const char *name,
                                 struct sieve_data **result,
                                 int tombstones)
{
    struct sqldb_bindval bval[] = {
        { ":mailbox", SQLITE_TEXT, { .s = mailbox       } },
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
    " WHERE mailbox = :mailbox AND imap_uid = :imap_uid;"

EXPORTED int sievedb_lookup_imapuid(struct sieve_db *sievedb,
                                    const char *mailbox, int imap_uid,
                                    struct sieve_data **result,
                                    int tombstones)
{
    struct sqldb_bindval bval[] = {
        { ":mailbox",  SQLITE_TEXT,    { .s = mailbox       } },
        { ":imap_uid", SQLITE_INTEGER, { .i = imap_uid      } },
        { NULL,        SQLITE_NULL,    { .s = NULL          } } };
    static struct sieve_data sdata;
    struct read_rock rrock = { sievedb, &sdata, tombstones, NULL, NULL };
    int r;

    *result = memset(&sdata, 0, sizeof(struct sieve_data));

    r = sqldb_exec(sievedb->db, CMD_SELIMAPUID, bval, &read_cb, &rrock);
    if (!r && !sdata.rowid) r = CYRUSDB_NOTFOUND;

    sdata.mailbox = mailbox;
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
    "  creationdate, mailbox, imap_uid, modseq, createdmodseq,"         \
    "  id, name, content, isactive, alive )"                           \
    " VALUES ("                                                         \
    "  :creationdate, :mailbox, :imap_uid, :modseq, :createdmodseq,"    \
    "  :id, :name, :content, :isactive, :alive );"

#define CMD_UPDATE                       \
    "UPDATE sieve_scripts SET"           \
    "  imap_uid      = :imap_uid,"       \
    "  modseq        = :modseq,"         \
    "  name          = :name,"           \
    "  content       = :content,"        \
    "  isactive      = :isactive,"       \
    "  alive         = :alive"           \
    " WHERE rowid = :rowid;"

EXPORTED int sievedb_write(struct sieve_db *sievedb, struct sieve_data *sdata)
{
    struct sqldb_bindval bval[] = {
        { ":imap_uid",      SQLITE_INTEGER, { .i = sdata->imap_uid      } },
        { ":modseq",        SQLITE_INTEGER, { .i = sdata->modseq        } },
        { ":name",          SQLITE_TEXT,    { .s = sdata->name          } },
        { ":content",       SQLITE_TEXT,    { .s = sdata->content       } },
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

        bval[6].name = ":rowid";
        bval[6].type = SQLITE_INTEGER;
        bval[6].val.i = sdata->rowid;
    }
    else {
        cmd = CMD_INSERT;

        bval[6].name = ":creationdate";
        bval[6].type = SQLITE_INTEGER;
        bval[6].val.i = sdata->creationdate;
        bval[7].name = ":createdmodseq";
        bval[7].type = SQLITE_INTEGER;
        bval[7].val.i = sdata->createdmodseq;
        bval[8].name = ":id";
        bval[8].type = SQLITE_TEXT;
        bval[8].val.s = sdata->id;
        bval[9].name = ":mailbox";
        bval[9].type = SQLITE_TEXT;
        bval[9].val.s = sdata->mailbox;
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


#define CMD_DELMBOX "DELETE FROM sieve_scripts WHERE mailbox = :mailbox;"

HIDDEN int sievedb_delmbox(struct sieve_db *sievedb, const char *mailbox)
{
    struct sqldb_bindval bval[] = {
        { ":mailbox", SQLITE_TEXT, { .s = mailbox } },
        { NULL,       SQLITE_NULL, { .s = NULL    } } };
    int r;

    r = sqldb_exec(sievedb->db, CMD_DELMBOX, bval, NULL, NULL);

    return r;
}

EXPORTED int sievedb_get_updates(struct sieve_db *sievedb,
                                 modseq_t oldmodseq, const char *mboxname, int limit,
                                 int (*cb)(void *rock, struct sieve_data *sdata),
                                 void *rock)
{
    struct sqldb_bindval bval[] = {
        { ":mailbox",      SQLITE_TEXT,    { .s = mboxname  } },
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
    if (mboxname) buf_appendcstr(&sqlbuf, " mailbox = :mailbox AND");
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
                            int (*proc)(struct mailbox *mailbox,
                                        struct sieve_data *sdata))
{
    int r, unlock = 0;

    if (!mailbox_index_islocked(mailbox, 1/*write*/)) {
        r = mailbox_lock_index(mailbox, LOCK_EXCLUSIVE);

        if (r) {
            syslog(LOG_ERR, "locking mailbox %s failed: %s",
                   mailbox->name, error_message(r));
            return r;
        }

        unlock = 1;
    }

    r = proc(mailbox, sdata);

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
               mailbox->name, uid, error_message(r));
    }

    return r;
}

static int store_script(struct mailbox *mailbox, struct sieve_data *sdata)
{
    strarray_t flags = STRARRAY_INITIALIZER;
    struct auth_state *authstate = NULL;
    struct buf buf = BUF_INITIALIZER;
    uint32_t old_uid = sdata->imap_uid;
    const char *data = sdata->content;
    size_t datalen = strlen(data);
    struct stagemsg *stage;
    struct appendstate as;
    time_t now = time(0);
    FILE *f = NULL;
    char *mimehdr;
    int r = 0;

    init_internal();

    /* Prepare to stage the message */
    if (!(f = append_newstage(mailbox->name, now, 0, &stage))) {
        syslog(LOG_ERR, "append_newstage(%s) failed", mailbox->name);
        return CYRUSDB_IOERROR;
    }

    /* Create RFC 5322 header for script */
    char *userid = mboxname_to_userid(mailbox->name);
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

    /* Use SHA1(script)@servername as Message-ID */
    struct message_guid uuid;
    message_guid_generate(&uuid, data, datalen);
    fprintf(f, "Message-ID: <%s@%s>\r\n",
            message_guid_encode(&uuid), config_servername);

    fprintf(f, "Content-Type: application/sieve; charset=utf-8\r\n");
    fprintf(f, "Content-Length: %lu\r\n", datalen);
    fprintf(f, "Content-Disposition: attachment;\r\n\tfilename=\"%s\"\r\n",
            sdata->id ? sdata->id : makeuuid());
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
               mailbox->name, error_message(r));
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
            syslog(LOG_ERR, "append_fromstage() failed");
            append_abort(&as);
        }
        else {
            /* Commit the append to the sieve mailbox */
            r = append_commit(&as);
            if (r) {
                syslog(LOG_ERR, "append_commit() failed");
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
                                struct sieve_data *sdata)
{
    return lock_and_execute(mailbox, sdata, &store_script);
}

static int activate_script(struct mailbox *mailbox, struct sieve_data *sdata)
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
                   mailbox->name, sdata->imap_uid, error_message(r));
            return r;
        }
    }

    struct sieve_db *sievedb = sievedb_open_mailbox(mailbox);

    if (!sievedb) {
        syslog(LOG_ERR, "opening sieve_db for %s failed", mailbox->name);
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
                   mailbox->name, mydata->imap_uid, error_message(r));
        }
        else {
            oldactive.system_flags &= ~FLAG_FLAGGED;
            r = mailbox_rewrite_index_record(mailbox, &oldactive);

            if (r) {
                syslog(LOG_ERR, "unflagging record (%s:%u) failed: %s",
                       mailbox->name, oldactive.uid, error_message(r));
            }
        }
    }
    sievedb_close(sievedb);

    if (!r && activate) {
        record.system_flags |= FLAG_FLAGGED;
        r = mailbox_rewrite_index_record(mailbox, &record);

        if (r) {
            syslog(LOG_ERR, "flagging record (%s:%u) failed: %s",
                   mailbox->name, record.uid, error_message(r));
        }
    }

    return r;
}

EXPORTED int sieve_script_activate(struct mailbox *mailbox,
                                   struct sieve_data *sdata)
{
    return lock_and_execute(mailbox, sdata, &activate_script);
}

static int remove_script(struct mailbox *mailbox, struct sieve_data *sdata)
{
    init_internal();

    return remove_uid(mailbox, sdata->imap_uid);
}

EXPORTED int sieve_script_remove(struct mailbox *mailbox,
                                 struct sieve_data *sdata)
{
    return lock_and_execute(mailbox, sdata, &remove_script);
}

EXPORTED int sieve_script_rename(struct mailbox *mailbox,
                                 struct sieve_data *sdata,
                                 const char *newname)
{
    sdata->name = newname;

    return sieve_script_store(mailbox, sdata);
}

EXPORTED struct buf *sieve_script_fetch(struct mailbox *mailbox,
                                        const struct sieve_data *sdata)
{
    struct index_record record;
    struct buf *data = NULL;
    int r;

    r = mailbox_find_index_record(mailbox, sdata->imap_uid, &record);
    if (!r) {
        /* Load message containing the resource */
        data = buf_new();

        r = mailbox_map_record(mailbox, &record, data);
        if (r) {
            buf_destroy(data);
            data = NULL;
        }
        else {
            buf_remove(data, 0, record.header_size);
        }
    }

    if (r) {
        syslog(LOG_ERR, "fetching message (%s:%u) failed: %s",
               mailbox->name, sdata->imap_uid, error_message(r));
    }

    return data;
}

struct migrate_rock {
    struct mailbox *mailbox;
    char *active;
};

static int migrate_cb(const char *sievedir,
                      const char *fname,
                      struct stat *sbuf __attribute__((unused)),
                      const char *link_target __attribute__((unused)),
                      void *rock)
{
    struct migrate_rock *mrock = (struct migrate_rock *) rock;
    struct buf *content = sievedir_get_script(sievedir, fname);

    if (content) {
        struct sieve_data sdata;
        char *myname = xstrndup(fname, strlen(fname) - SCRIPT_SUFFIX_LEN);

        memset(&sdata, 0, sizeof(sdata));
        sdata.name = myname;
        sdata.content = buf_cstring(content);
        sdata.isactive = !strcmpnull(myname, mrock->active);

        store_script(mrock->mailbox, &sdata);

        buf_destroy(content);
        free(myname);
    }

    return SIEVEDIR_OK;
}

EXPORTED int sieve_open_folder(const char *userid, int write,
                               struct mailbox **mailboxptr)
{
    struct mboxlock *namespacelock = NULL;
    const char *sievedir = user_sieve_path(userid);
    mbname_t *mbname = mbname_from_userid(userid);
    struct stat sbuf;
    int r;

    r = stat(sievedir, &sbuf);
    if (r && errno == ENOENT) {
        if (!mailboxptr) return 0;

        r = cyrus_mkdir(sievedir, 0755);
        if (!r) {
            r = mkdir(sievedir, 0755);
        }
    }

    mbname_push_boxes(mbname, config_getstring(IMAPOPT_SIEVE_FOLDER));

    const char *mboxname = mbname_intname(mbname);
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
        if (write) r = mailbox_open_iwl(mboxname, mailboxptr);
        else r = mailbox_open_irl(mboxname, mailboxptr);
        if (r) {
            syslog(LOG_ERR, "IOERROR: failed to open %s (%s)",
                   mboxname, error_message(r));
            goto done;
        }
    }

    else if (r == IMAP_MAILBOX_NONEXISTENT) {
        /* Create locally */
        struct mailbox *mailbox = NULL;

        r = mboxlist_createmailbox(mboxname, MBTYPE_SIEVE, NULL, 0,
                                   userid, NULL, 0, 0, 0, 0, &mailbox);
        if (r) {
            syslog(LOG_ERR, "IOERROR: failed to create %s (%s)",
                   mboxname, error_message(r));
            goto done;
        }

        /* Migrate scripts from sievedir into mailbox */
        const char *sievedir = user_sieve_path(userid);
        struct migrate_rock mrock =
            { mailbox, xstrdupnull(sievedir_get_active(sievedir)) };

        sievedir_foreach(sievedir, SIEVEDIR_SCRIPTS_ONLY, &migrate_cb, &mrock);

        free(mrock.active);

        if (mailboxptr) *mailboxptr = mailbox;
        else mailbox_close(&mailbox);
    }

  done:
    if (mailboxptr && *mailboxptr && !write) {
        mailbox_unlock_index(*mailboxptr, NULL);
    }
    mboxname_release(&namespacelock);
    mbname_free(&mbname);
    return r;
}
