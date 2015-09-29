/* api.c -- replication-based backup api
 *
 * Copyright (c) 1994-2015 Carnegie Mellon University.  All rights reserved.
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

#include <assert.h>
#include <errno.h>
#include <syslog.h>
#include <zlib.h>

#include "lib/cyrusdb.h"
#include "lib/cyr_lock.h"
#include "lib/sqldb.h"
#include "lib/xmalloc.h"
#include "lib/xstrlcat.h"
#include "lib/xstrlcpy.h"

#include "imap/dlist.h"
#include "imap/global.h"
#include "imap/imap_err.h"
#include "imap/imapparse.h"

#include "backup/api.h"
#include "backup/gzuncat.h"
#include "backup/sqlconsts.h"

struct backup {
    int fd;
    char *gzname;
    char *idxname;
    char *oldidxname;
    sqldb_t *db;
    gzFile gzfile;
    int index_id;
};

/*
 * use cases:
 *  - backupd needs to be able to append to gz and update index (exclusive)
 *  - backupd maybe needs to create a new backup from scratch (exclusive)
 *  - reindex needs to gzuc gz and rewrite index (exclusive)
 *  - compress needs to rewrite gz and index (exclusive)
 *  - restore needs to read gz and index (shared)
 *
 * with only one shared case, might as well always lock exclusively...
 */
enum backup_open_mode {
    BACKUP_OPEN_NORMAL = 0,
    BACKUP_OPEN_REINDEX,
};

static struct backup *backup_open_internal(const char *gzname,
                                           const char *idxname,
                                           enum backup_open_mode mode)
{
    int locked = 0;
    struct backup *backup = xzmalloc(sizeof *backup);
    if (!backup) return NULL;

    backup->fd = -1;
    backup->index_id = -1;

    backup->gzname = xstrdup(gzname);
    backup->idxname = xstrdup(idxname);

    backup->fd = open(backup->gzname, O_RDWR | O_CREAT | O_APPEND, S_IRUSR | S_IWUSR);
    if (backup->fd < 0) goto error;

    int r = lock_setlock(backup->fd, /* exclusive */ 1, /*nb*/ 0, backup->gzname);
    if (r) goto error;
    locked = 1;

    if (mode == BACKUP_OPEN_REINDEX) {
        // when reindexing, we want to move the old index out of the way
        // and create a new, empty one -- while holding the lock
        char *oldidxname = strconcat(backup->idxname, ".old", NULL);

        r = rename(backup->idxname, oldidxname);
        if (r && errno != ENOENT) {
            free(oldidxname);
            goto error;
        }

        backup->oldidxname = oldidxname;
    }

    backup->db = sqldb_open(backup->idxname, backup_index_initsql,
                            backup_index_version, backup_index_upgrade);
    if (!backup->db) goto error;

    return backup;

error:
    // unwind creation in reverse order
    // FIXME could this just call out to backup_close...?
    if (backup->db) sqldb_close(&backup->db);

    if (backup->oldidxname) {
        rename(backup->oldidxname, backup->idxname);
        free(backup->oldidxname);
    }

    if (locked) lock_unlock(backup->fd, backup->gzname);
    if (backup->fd >= 0) close(backup->fd);

    if (backup->idxname) free(backup->idxname);
    if (backup->gzname) free(backup->gzname);

    free(backup);
    return NULL;
}

EXPORTED struct backup *backup_open(const mbname_t *mbname)
{
    struct buf gzpath = BUF_INITIALIZER;
    struct buf idxpath = BUF_INITIALIZER;
    struct backup *backup = NULL;

    int r = backup_get_paths(mbname, &gzpath, &idxpath);
    if (r) goto done;

    backup = backup_open_internal(buf_cstring(&gzpath),
                                  buf_cstring(&idxpath),
                                  BACKUP_OPEN_NORMAL);

done:
    buf_free(&gzpath);
    buf_free(&idxpath);

    return backup;
}

/*
 * If idxpath is NULL, it will be automatically derived from gzpath
 */
EXPORTED struct backup *backup_open_paths(const char *gzpath, const char *idxpath)
{
    if (idxpath)
        return backup_open_internal(gzpath, idxpath, BACKUP_OPEN_NORMAL);

    char tmp[PATH_MAX] = {0};
    strlcpy(tmp, gzpath, sizeof(tmp));

    char *dot = strrchr(tmp, '.');
    if (!dot || strcmp(dot, ".gz") != 0)
        return NULL;

    *dot = '\0';
    strlcat(tmp, ".index", sizeof(tmp));
    return backup_open_internal(gzpath, tmp, BACKUP_OPEN_NORMAL);
}

/* Uses mkstemp() to create a new, unique, backup path for the given user.
 *
 * On success, the file is not unlinked, presuming that it will shortly be
 * used for storing backup data.  This also ensures its uniqueness remains:
 * this function won't generate the same value again as long as the previous
 * file is intact, so there's no user-rename race.
 *
 * On error, returns NULL and logs to syslog.
 */
static const char *backup_make_path(const mbname_t *mbname)
{
    char pathresult[PATH_MAX];

    const char *userid = mbname_userid(mbname);
    const char *backup_data_path = config_getstring(IMAPOPT_BACKUP_DATA_PATH);
    const char *ret = NULL;

    if (!backup_data_path) {
        syslog(LOG_ERR,
               "unable to make backup path for %s: no backup_data_path defined in imapd.conf",
               userid);
        return NULL;
    }

    char hash_buf[2];
    char *template = strconcat(backup_data_path,
                               "/", dir_hash_b(userid, 1, hash_buf),
                               "/", userid, "_XXXXXX",
                               NULL);

    int fd = mkstemp(template);
    if (fd >= 0) {
        if (strlcpy(pathresult, template, sizeof(pathresult)) < sizeof(pathresult)) {
            ret = pathresult;
        }
        else {
            syslog(LOG_ERR, "unable to make backup path for %s: path too long", userid);
            unlink(template);
        }
        close(fd);
    }
    else {
        syslog(LOG_ERR, "unable to make backup path for %s: %m", userid);
    }

    free(template);
    return ret;
}

EXPORTED int backup_get_paths(const mbname_t *mbname,
                              struct buf *gzpath, struct buf *idxpath)
{
    char *backups_db_fname = xstrdup(config_getstring(IMAPOPT_BACKUPS_DB_PATH));
    if (!backups_db_fname)
        backups_db_fname = strconcat(config_dir, "/backups.db", NULL);

    struct db *backups_db = NULL;
    struct txn *tid = NULL;

    int r = cyrusdb_open(config_backups_db, backups_db_fname, CYRUSDB_CREATE, &backups_db);
    if (r) goto done;

    const char *userid = mbname_userid(mbname);
    const char *backup_path = NULL;
    size_t path_len = 0;

    r = cyrusdb_fetch(backups_db,
                      userid, strlen(userid),
                      &backup_path, &path_len,
                      &tid);

    if (r == CYRUSDB_NOTFOUND) {
        backup_path = backup_make_path(mbname);
        if (!backup_path) {
            r = IMAP_INTERNAL; /* FIXME ?? */
            goto done;
        }
        path_len = strlen(backup_path);

        r = cyrusdb_create(backups_db,
                           userid, strlen(userid),
                           backup_path, path_len,
                           &tid);

        /* if we didn't store it in the database successfully, trash the file, it won't be used */
        if (r) unlink(backup_path);
    }

    if (r) goto done;

    if (path_len == 0) {
        syslog(LOG_DEBUG, "unexpectedly got zero length backup path for user %s", userid);
        r = IMAP_INTERNAL; /* FIXME ?? */
        goto done;
    }

    buf_setmap(gzpath, backup_path, path_len);

    buf_setmap(idxpath, backup_path, path_len);
    buf_appendcstr(idxpath, ".index");

done:
    if (tid)
        cyrusdb_commit(backups_db, tid);
    if (backups_db)
        cyrusdb_close(backups_db);
    free(backups_db_fname);
    return r;
}

EXPORTED int backup_close(struct backup **backupp)
{
    (void) backupp;
    return -1;
}

EXPORTED int backup_write_dlist(struct backup *backup, time_t ts, struct dlist *dl)
{
    (void) backup;
    (void) ts;
    (void) dl;
    return -1;
}

static int _column_int(sqlite3_stmt *stmt, int column)
{
    assert(sqlite3_column_type(stmt, column) == SQLITE_INTEGER);
    return sqlite3_column_int(stmt, column);
}

static sqlite3_int64 _column_int64(sqlite3_stmt *stmt, int column)
{
    assert(sqlite3_column_type(stmt, column) == SQLITE_INTEGER);
    return sqlite3_column_int64(stmt, column);
}

static char * _column_text(sqlite3_stmt *stmt, int column)
{
    assert(sqlite3_column_type(stmt, column) == SQLITE_TEXT);
    return xstrdup((const char *) sqlite3_column_text(stmt, column));
}

static int _get_mailbox_id_cb(sqlite3_stmt *stmt, void *rock) {
    int *idp = (int *) rock;

    *idp = _column_int(stmt, 0);

    return 0;
}

EXPORTED int backup_get_mailbox_id(struct backup *backup, const char *uniqueid)
{
    struct sqldb_bindval bval[] = {
        { ":uniqueid",  SQLITE_TEXT,    { .s = uniqueid } },
        { NULL,         SQLITE_NULL,    { .s = NULL } },
    };

    int id = -1;

    int r = sqldb_exec(backup->db, backup_index_mailbox_select_uniqueid_sql, bval,
                       _get_mailbox_id_cb, &id);
    if (r)
        fprintf(stderr, "%s: something went wrong: %i %s\n", __func__, r, uniqueid);

    return id;
}

struct _mailbox_row_rock {
    sqldb_t *db;
    backup_mailbox_foreach_cb proc;
    void *rock;
    struct backup_mailbox **save;
    int want_records;
};

static int _mailbox_message_row_cb(sqlite3_stmt *stmt, void *rock)
{
    struct dlist *parent = (struct dlist *) rock;

    struct dlist *record = dlist_newkvlist(parent, NULL);
    const char *flag_str = NULL;
    const char *annot_str = NULL;
    int r = 0;

    int column = 4;  // skip unused columns
    dlist_setnum32(record, "UID", _column_int(stmt, column++));
    dlist_setnum64(record, "MODSEQ", _column_int64(stmt, column++));
    dlist_setdate(record, "LAST_UPDATE", _column_int64(stmt, column++));
    flag_str = _column_text(stmt, column++);
    dlist_setdate(record, "INTERNALDATE", _column_int64(stmt, column++));
    dlist_setatom(record, "GUID", _column_text(stmt, column++)); // FIXME dlist_setguid?
    dlist_setnum32(record, "SIZE", _column_int(stmt, column++));
    annot_str = _column_text(stmt, column++);

    if (flag_str && flag_str[0]) {
        struct dlist *flags = NULL;
        r = dlist_parsemap(&flags, 0, flag_str, strlen(flag_str));
        if (r) return r; // FIXME handle this sanely
        if (flags) {
            flags->name = xstrdup("FLAGS");
            dlist_stitch(record, flags);
        }
    }

    if (annot_str && annot_str[0]) {
        struct dlist *annots = NULL;
        r = dlist_parsemap(&annots, 0, annot_str, strlen(annot_str));
        if (r) return r; // FIXME handle this sanely
        if (annots) {
            annots->name = xstrdup("ANNOTATIONS");
            dlist_stitch(record, annots);
        }
    }

    return r;
}

static int _mailbox_row_cb(sqlite3_stmt *stmt, void *rock)
{
    struct _mailbox_row_rock *mbrock = (struct _mailbox_row_rock *) rock;

    struct backup_mailbox *mailbox = xzmalloc(sizeof *mailbox);
    struct dlist *dl = dlist_newkvlist(NULL, "MAILBOX");
    int r = 0;
    const char *annot_str = NULL;

    int column = 0;
    mailbox->id = _column_int(stmt, column++);
    mailbox->last_backup_id = _column_int(stmt, column++);
    dlist_setatom(dl, "UNIQUEID", _column_text(stmt, column++));
    dlist_setatom(dl, "MBOXNAME", _column_text(stmt, column++));
    dlist_setatom(dl, "MBOXTYPE", _column_text(stmt, column++));
    dlist_setnum32(dl, "LAST_UID", _column_int(stmt, column++));
    dlist_setnum64(dl, "HIGHESTMODSEQ", _column_int64(stmt, column++));
    dlist_setnum32(dl, "RECENTUID", _column_int(stmt, column++));
    dlist_setdate(dl, "RECENTTIME", _column_int64(stmt, column++));
    dlist_setdate(dl, "LAST_APPENDDATE", _column_int64(stmt, column++));
    dlist_setdate(dl, "POP3_LAST_LOGIN", _column_int64(stmt, column++));
    dlist_setdate(dl, "POP3_SHOW_AFTER", _column_int64(stmt, column++));
    dlist_setnum32(dl, "UIDVALIDITY", _column_int(stmt, column++));
    dlist_setatom(dl, "PARTITION", _column_text(stmt, column++));
    dlist_setatom(dl, "ACL", _column_text(stmt, column++));
    dlist_setatom(dl, "OPTIONS", _column_text(stmt, column++));
    dlist_setnum32(dl, "SYNC_CRC", _column_int(stmt, column++));
    dlist_setnum32(dl, "SYNC_CRC_ANNOT", _column_int(stmt, column++));
    dlist_setatom(dl, "QUOTAROOT", _column_text(stmt, column++));
    dlist_setnum64(dl, "XCONVMODSEQ", _column_int64(stmt, column++));
    annot_str = _column_text(stmt, column++);
    mailbox->deleted = _column_int(stmt, column++);

    if (annot_str && annot_str[0]) {
        struct dlist *annots = NULL;
        r = dlist_parsemap(&annots, 0, annot_str, strlen(annot_str));
        if (r) return r; // FIXME handle this sanely
        if (annots) {
            annots->name = xstrdup("ANNOTATIONS");
            dlist_stitch(dl, annots);
        }
    }

    if (mbrock->want_records) {
        struct dlist *records = dlist_newlist(NULL, "RECORD");

        struct sqldb_bindval bval[] = {
            { ":mailbox_id",    SQLITE_INTEGER, { .i = mailbox->id } },
            { NULL,             SQLITE_NULL,    { .s = NULL } },
        };

        r = sqldb_exec(mbrock->db,
                       backup_index_mailbox_message_select_mailbox_sql,
                       bval,
                       _mailbox_message_row_cb, records);

        if (!r)
            dlist_stitch(dl, records);

        // FIXME sensible error handling
    }

    mailbox->dlist = dl;

    if (mbrock->proc)
        r = mbrock->proc(mailbox, mbrock->rock);

    if (mbrock->save)
        *mbrock->save = mailbox;
    else
    backup_mailbox_free(&mailbox);

    return r;
}

EXPORTED int backup_mailbox_foreach(struct backup *backup,
                                    int want_records,
                                    backup_mailbox_foreach_cb cb,
                                    void *rock)
{
    struct _mailbox_row_rock mbrock = { backup->db, cb, rock, NULL, want_records};

    int r = sqldb_exec(backup->db, backup_index_mailbox_select_all_sql, NULL,
                       _mailbox_row_cb, &mbrock);

    return r;
}

EXPORTED struct backup_mailbox *backup_get_mailbox_by_name(struct backup *backup,
                                                  const mbname_t *mbname,
                                                  int want_records)
{
    struct backup_mailbox *mailbox = NULL;

    struct _mailbox_row_rock mbrock = { backup->db, NULL, NULL, &mailbox, want_records };

    struct sqldb_bindval bval[] = {
        { ":mboxname",  SQLITE_TEXT,    { .s = mbname_intname(mbname) } },
        { NULL,         SQLITE_NULL,    { .s = NULL } },
    };

    int r = sqldb_exec(backup->db, backup_index_mailbox_select_mboxname_sql,
                       bval, _mailbox_row_cb, &mbrock);

    if (r) {
        if (mailbox) backup_mailbox_free(&mailbox);
        return NULL;
    }

    return mailbox;
}

EXPORTED void backup_mailbox_free(struct backup_mailbox **mailboxp)
{
    struct backup_mailbox *mailbox = *mailboxp;
    *mailboxp = NULL;

    if (mailbox->dlist) dlist_free(&mailbox->dlist);

    free(mailbox);
}

static int _get_message_id_cb(sqlite3_stmt *stmt, void *rock) {
    int *idp = (int *) rock;

    *idp = _column_int(stmt, 0);

    return 0;
}

EXPORTED int backup_get_message_id(struct backup *backup, const char *guid)
{
    struct sqldb_bindval bval[] = {
        { ":guid",  SQLITE_TEXT,    { .s = guid } },
        { NULL,     SQLITE_NULL,    { .s = NULL } },
    };

    // FIXME distinguish between error and not found
    int id = -1;

    int r = sqldb_exec(backup->db, backup_index_message_select_guid_sql, bval,
                       _get_message_id_cb, &id);
    if (r)
        fprintf(stderr, "%s: something went wrong: %i %s\n", __func__, r, guid);

    return id;
}

static int _get_message_cb(sqlite3_stmt *stmt, void *rock) {
    struct backup_message *message = (struct backup_message *) rock;
    int column = 0;

    message->id = _column_int(stmt, column++);
    char *guid_str = _column_text(stmt, column++);
    message->partition = _column_text(stmt, column++);
    message->backup_id = _column_int(stmt, column++);
    message->offset = _column_int64(stmt, column++);
    message->length = _column_int64(stmt, column++);

    struct message_guid *guid = xzmalloc(sizeof *guid);
    if (!message_guid_decode(guid, guid_str)) goto error;
    message->guid = guid;
    free(guid_str);

    return 0;

error:
    if (guid && !message->guid) free(guid);
    if (guid_str) free(guid_str);
    return -1;
}

EXPORTED struct backup_message *backup_get_message(struct backup *backup,
                                                   const struct message_guid *guid)
{
    struct sqldb_bindval bval[] = {
        { ":guid",  SQLITE_TEXT,    { .s = message_guid_encode(guid) } },
        { NULL,     SQLITE_NULL,    { .s = NULL } },
    };

    struct backup_message *bm = xzmalloc(sizeof *bm);

    int r = sqldb_exec(backup->db, backup_index_message_select_guid_sql, bval,
                       _get_message_cb, bm);
    if (r) goto error;

    return bm;

error:
    fprintf(stderr, "%s: something went wrong: %i %s\n", __func__, r, message_guid_encode(guid));
    if (bm) backup_message_free(&bm);
    return NULL;
}

EXPORTED void backup_message_free(struct backup_message **messagep)
{
    struct backup_message *message = *messagep;
    *messagep = NULL;

    if (message->guid) free(message->guid);
    if (message->partition) free(message->partition);

    free(message);
}


// FIXME rename this
int backup_index_apply_mailbox(struct backup *backup, struct dlist *dl, off_t dl_offset) {
    fprintf(stderr, "indexing MAILBOX at " OFF_T_FMT "...\n", dl_offset);

    const char *uniqueid = NULL;
    const char *mboxname = NULL;
    const char *mboxtype = NULL;
    uint32_t last_uid = 0;
    modseq_t highestmodseq = 0;
    uint32_t recentuid = 0;
    time_t recenttime = 0;
    time_t last_appenddate = 0;
    time_t pop3_last_login = 0;
    time_t pop3_show_after = 0;
    uint32_t uidvalidity = 0;
    const char *partition = NULL;
    const char *acl = NULL;
    const char *options = NULL;
    struct synccrcs synccrcs = { 0, 0 };
    const char *quotaroot = NULL;
    modseq_t xconvmodseq = 0;
    struct dlist *annotations = NULL;
    struct buf annotations_buf = BUF_INITIALIZER;
    struct dlist *record = NULL;

    if (!dlist_getatom(dl, "UNIQUEID", &uniqueid))
        return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getatom(dl, "MBOXNAME", &mboxname))
        return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getnum32(dl, "LAST_UID", &last_uid))
        return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getnum64(dl, "HIGHESTMODSEQ", &highestmodseq))
        return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getnum32(dl, "RECENTUID", &recentuid))
        return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getdate(dl, "RECENTTIME", &recenttime))
        return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getdate(dl, "LAST_APPENDDATE", &last_appenddate))
        return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getdate(dl, "POP3_LAST_LOGIN", &pop3_last_login))
        return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getnum32(dl, "UIDVALIDITY", &uidvalidity))
        return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getatom(dl, "PARTITION", &partition))
        return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getatom(dl, "ACL", &acl))
        return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getatom(dl, "OPTIONS", &options))
        return IMAP_PROTOCOL_BAD_PARAMETERS;
    if (!dlist_getlist(dl, "RECORD", &record))
        return IMAP_PROTOCOL_BAD_PARAMETERS;

    /* optional */
    dlist_getlist(dl, "ANNOTATIONS", &annotations);
    dlist_getdate(dl, "POP3_SHOW_AFTER", &pop3_show_after);
    dlist_getatom(dl, "MBOXTYPE", &mboxtype);
    dlist_getnum64(dl, "XCONVMODSEQ", &xconvmodseq);

    /* CRCs */
    dlist_getnum32(dl, "SYNC_CRC", &synccrcs.basic);
    dlist_getnum32(dl, "SYNC_CRC_ANNOT", &synccrcs.annot);

    if (annotations) {
        dlist_printbuf(annotations, 0, &annotations_buf);
    }

    struct sqldb_bindval mbox_bval[] = {
        { ":last_backup_id",    SQLITE_INTEGER, { .i = backup->index_id } },
        { ":uniqueid",          SQLITE_TEXT,    { .s = uniqueid } },
        { ":mboxname",          SQLITE_TEXT,    { .s = mboxname } },
        { ":mboxtype",          SQLITE_TEXT,    { .s = mboxtype } },
        { ":last_uid",          SQLITE_INTEGER, { .i = last_uid } },
        { ":highestmodseq",     SQLITE_INTEGER, { .i = highestmodseq } },
        { ":recentuid",         SQLITE_INTEGER, { .i = recentuid } },
        { ":recenttime",        SQLITE_INTEGER, { .i = recenttime } },
        { ":last_appenddate",   SQLITE_INTEGER, { .i = last_appenddate } },
        { ":pop3_last_login",   SQLITE_INTEGER, { .i = pop3_last_login } },
        { ":pop3_show_after",   SQLITE_INTEGER, { .i = pop3_show_after } },
        { ":uidvalidity",       SQLITE_INTEGER, { .i = uidvalidity } },
        { ":partition",         SQLITE_TEXT,    { .s = partition } },
        { ":acl",               SQLITE_TEXT,    { .s = acl } },
        { ":options",           SQLITE_TEXT,    { .s = options } },
        { ":sync_crc",          SQLITE_INTEGER, { .i = synccrcs.basic } },
        { ":sync_crc_annot",    SQLITE_INTEGER, { .i = synccrcs.annot } },
        { ":quotaroot",         SQLITE_TEXT,    { .s = quotaroot } },
        { ":xconvmodseq",       SQLITE_INTEGER, { .i = xconvmodseq } },
        { ":annotations",       SQLITE_TEXT,    { .s = buf_cstring(&annotations_buf) } },
        { ":deleted",           SQLITE_INTEGER, { .i = 0 } },
        { NULL,                 SQLITE_NULL,    { .s = NULL      } },
    };

    buf_free(&annotations_buf);

    sqldb_begin(backup->db, __func__); // FIXME what if this fails

    int r = sqldb_exec(backup->db, backup_index_mailbox_update_sql, mbox_bval, NULL, NULL);
    if (r) {
        // FIXME handle this sensibly
        fprintf(stderr, "%s: something went wrong: %i update %s\n", __func__, r, mboxname);
        goto error;
    }
    if (sqldb_changes(backup->db) == 0) {
        r = sqldb_exec(backup->db, backup_index_mailbox_insert_sql, mbox_bval, NULL, NULL);
        if (r) {
            // FIXME handle this sensibly
            fprintf(stderr, "%s: something went wrong: %i insert %s\n", __func__, r, mboxname);
            goto error;
        }
    }

    int mailbox_id = backup_get_mailbox_id(backup, uniqueid);

    struct dlist *ki = NULL;

    for (ki = record->head; ki; ki = ki->next) {
        uint32_t uid = 0;
        modseq_t modseq = 0;
        uint32_t last_updated = 0;
        struct dlist *flags = NULL;
        struct buf flags_buf = BUF_INITIALIZER;
        uint32_t internaldate;
        uint32_t size;
        const char *guid;
        struct dlist *annotations = NULL;
        struct buf annotations_buf = BUF_INITIALIZER;
        int message_id = -1;

        if (!dlist_getnum32(ki, "UID", &uid))
            goto error;
        if (!dlist_getnum64(ki, "MODSEQ", &modseq))
            goto error;
        if (!dlist_getnum32(ki, "LAST_UPDATED", &last_updated))
            goto error;
        if (!dlist_getnum32(ki, "INTERNALDATE", &internaldate))
            goto error;
        if (!dlist_getnum32(ki, "SIZE", &size))
            goto error;
        if (!dlist_getatom(ki, "GUID", &guid))
            goto error;

        dlist_getlist(ki, "FLAGS", &flags);
        if (flags) {
            dlist_printbuf(flags, 0, &flags_buf);
        }

        dlist_getlist(ki, "ANNOTATIONS", &annotations);
        if (annotations) {
            dlist_printbuf(annotations, 0, &annotations_buf);
        }

        message_id = backup_get_message_id(backup, guid);
        if (message_id == -1) {
            // FIXME handle this sensibly
            fprintf(stderr, "%s: something went wrong: %i %s %s\n", __func__, r, mboxname, guid);
            goto error;
        }

        struct sqldb_bindval record_bval[] = {
            { ":mailbox_id",        SQLITE_INTEGER, { .i = mailbox_id } },
            { ":message_id",        SQLITE_INTEGER, { .i = message_id } },
            { ":last_backup_id",    SQLITE_INTEGER, { .i = backup->index_id } },
            { ":uid",               SQLITE_INTEGER, { .i = uid } },
            { ":modseq",            SQLITE_INTEGER, { .i = modseq } },
            { ":last_updated",      SQLITE_INTEGER, { .i = last_updated } },
            { ":flags",             SQLITE_TEXT,    { .s = buf_cstring(&flags_buf) } },
            { ":internaldate",      SQLITE_INTEGER, { .i = internaldate } },
            { ":annotations",       SQLITE_TEXT,    { .s = buf_cstring(&annotations_buf) } },
            { ":expunged",          SQLITE_INTEGER, { .i = 0 /* FIXME */ } },
            { NULL,                 SQLITE_NULL,    { .s = NULL      } },
        };

        buf_free(&annotations_buf);
        buf_free(&flags_buf);

        r = sqldb_exec(backup->db, backup_index_mailbox_message_update_sql, record_bval, NULL, NULL);
        if (r) {
            // FIXME handle this sensibly
            fprintf(stderr, "%s: something went wrong: %i update %s %s\n", __func__, r, mboxname, guid);
            goto error;
        }
        if (sqldb_changes(backup->db) == 0) {
            r = sqldb_exec(backup->db, backup_index_mailbox_message_insert_sql, record_bval, NULL, NULL);
            if (r) {
                // FIXME handle this sensibly
                fprintf(stderr, "%s: something went wrong: %i insert %s %s\n", __func__, r, mboxname, guid);
                goto error;
            }
        }
    }

    fprintf(stderr, "%s: committing index change: %s\n", __func__, mboxname);
    sqldb_commit(backup->db, __func__);
    return 0;

error:
    fprintf(stderr, "%s: rolling back index change: %s\n", __func__, mboxname);
    sqldb_rollback(backup->db, __func__);

    return -1;
}

// FIXME this isn't really an apply, it's just the index part of an apply
// backupd will have its own work to do (e.g. at v least reply "OK" or "NO")
int backup_index_apply_message(sqldb_t *db, int backup_id, struct dlist *dl, off_t dl_offset, size_t dl_len) {
    fprintf(stderr, "indexing MESSAGE at " OFF_T_FMT " (" SIZE_T_FMT " bytes)...\n", dl_offset, dl_len);

    struct dlist *ki;

    /* n.b. APPLY MESSAGE contains a list of messages, not just one */
    for (ki = dl->head; ki; ki = ki->next) {
        if (ki->type != DL_SFILE)
            continue;

        // FIXME DL_SFILEs have the offset and size already recorded
        // so we could use that...
        // but, it's the offset in the input stream which is fine
        // for reindex (input stream = gz data), but useless for
        // backupd (input stream = remote sync_client).

        char *guid = xstrdup(message_guid_encode(ki->gval));
        char *partition = ki->part;

        struct sqldb_bindval bval[] = {
            { ":guid",      SQLITE_TEXT,    { .s = guid      } },
            { ":partition", SQLITE_TEXT,    { .s = partition } },
            { ":backup_id", SQLITE_INTEGER, { .i = backup_id } },
            { ":offset",    SQLITE_INTEGER, { .i = dl_offset } },
            { ":length",    SQLITE_INTEGER, { .i = dl_len    } },
            { NULL,         SQLITE_NULL,    { .s = NULL      } },
        };

        int r = sqldb_exec(db, backup_index_message_insert_sql, bval, NULL, NULL);
        if (r) {
            // FIXME handle this sensibly
            fprintf(stderr, "%s: something went wrong: %i %s\n", __func__, r, guid);
        }

        free(guid);
    }

    return 0;
}

static int backup_index_start3(struct backup *backup, time_t ts, off_t offset) {
    if (backup->index_id != -1) fatal("already started", -1);

    struct sqldb_bindval bval[] = {
        { ":timestamp", SQLITE_INTEGER, { .i = ts     } },
        { ":offset",    SQLITE_INTEGER, { .i = offset } },
        { NULL,         SQLITE_NULL,    { .s = NULL   } },
    };

    sqldb_begin(backup->db, "backup_index"); // FIXME what if this fails

    int r = sqldb_exec(backup->db, backup_index_start_sql, bval, NULL, NULL);
    if (r) {
        // FIXME handle this sensibly
        fprintf(stderr, "%s: something went wrong: %i\n", __func__, r);
        sqldb_rollback(backup->db, "backup_index");
        return -1;
    }

    backup->index_id = sqldb_lastid(backup->db);
    return 0;
}

int backup_index_start(struct backup *backup) {
    off_t offset = lseek(backup->fd, 0, SEEK_END);

    return backup_index_start3(backup, time(0), offset);
}

int backup_index_end(struct backup *backup, size_t length) {
    if (backup->index_id == -1) fatal("not started", -1);

    struct sqldb_bindval bval[] = {
        { ":id",        SQLITE_INTEGER, { .i = backup->index_id } },
        { ":length",    SQLITE_INTEGER, { .i = length           } },
        { NULL,         SQLITE_NULL,    { .s = NULL             } },
    };

    int r = sqldb_exec(backup->db, backup_index_end_sql, bval, NULL, NULL);
    if (r) {
        // FIXME handle this sensibly
        fprintf(stderr, "%s: something went wrong: %i\n", __func__, r);
        sqldb_rollback(backup->db, "backup_index");
        backup->index_id = -1;
        return -1;
    }

    sqldb_commit(backup->db, "backup_index");

    backup->index_id = -1;

    return 0;
}

int backup_index_abort(struct backup *backup) {
    if (backup->index_id == -1) fatal("not started", -1);

    sqldb_rollback(backup->db, "backup_index");
    backup->index_id = -1;

    return 0;
}

EXPORTED int backup_index_dlist(struct backup *backup, struct dlist *dl, off_t dl_offset, size_t dl_len)
{
    if (backup->index_id == -1) fatal("not started", -1);

    int r = 0;

    if (0) { }

    else if (strcmp(dl->name, "MAILBOX") == 0)
        r = backup_index_apply_mailbox(backup, dl, dl_offset);
    else if (strcmp(dl->name, "MESSAGE") == 0)
        r = backup_index_apply_message(backup->db, backup->index_id, dl, dl_offset, dl_len);

    else {
        fprintf(stderr, "ignoring unrecognised dlist name: %s\n", dl->name);
        r = -1; // FIXME
    }

    return r;
}

EXPORTED int backup_append_start(struct backup *backup)
{
    if (backup->gzfile != NULL) fatal("already started", -1);

    int dup_fd = dup(backup->fd);
    backup->gzfile = gzdopen(dup_fd, "ab");
    if (backup->gzfile) return 0;

    fprintf(stderr, "%s: gzdopen fd %i failed: %s\n", __func__, dup_fd, strerror(errno));
    close(dup_fd);
    return -1;
}


EXPORTED int backup_append(struct backup *backup, struct dlist *dlist, time_t ts)
{
    if (!backup->gzfile) fatal("not started", -1);

    gzprintf(backup->gzfile, "%ld ", (int64_t) ts);

    /* gzprintf's internal buffer is limited to about 8K, which
     * dlist will exceed if there's a message in it, so don't use
     * gzprintf for writing the dlist contents.
     */
    struct buf buf = BUF_INITIALIZER;
    dlist_printbuf(dlist, 1, &buf);
    gzwrite(backup->gzfile, buf_cstring(&buf), buf_len(&buf));
    // FIXME check return value is long enough
    buf_free(&buf);

    return 0;
}

EXPORTED int backup_append_done(struct backup *backup)
{
    if (!backup->gzfile) fatal("not started", -1);

    int r = gzclose_w(backup->gzfile);
    backup->gzfile = NULL;
    if (r == Z_OK) return 0;

    fprintf(stderr, "%s: gzclose_w failed: %i\n", __func__, r);
    return -1;
}

static int _parse_line(struct protstream *in, time_t *ts,
                       struct buf *cmd, struct dlist **kin)
{
    struct dlist *dl = NULL;
    struct buf buf = BUF_INITIALIZER;
    int64_t t;
    int c;

    c = prot_getc(in);
    if (c == '#')
        eatline(in, c);
    else
        prot_ungetc(c, in);

    c = getint64(in, &t);
    if (c == EOF)
        goto fail;

    c = getword(in, &buf);
    if (c == EOF)
        goto fail;

    c = dlist_parse(&dl, DLIST_SFILE | DLIST_PARSEKEY, in);

    if (!dl) {
        fprintf(stderr, "\ndidn't parse dlist, error %i\n", c);
        goto fail;
    }

    if (c == '\r') c = prot_getc(in);
    if (c != '\n') {
        fprintf(stderr, "expected newline, got '%c'\n", c);
        eatline(in, c);
        goto fail;
    }

    if (kin) *kin = dl;
    if (cmd) buf_copy(cmd, &buf);
    if (ts) *ts = (time_t) t;
    buf_free(&buf);
    return c;

fail:
    if (dl) dlist_free(&dl);
    buf_free(&buf);
    return c;
}

static ssize_t _prot_fill_cb(unsigned char *buf, size_t len, void *rock) {
    struct gzuncat *gzuc = (struct gzuncat *) rock;
    return gzuc_read(gzuc, buf, len);
}

EXPORTED int backup_reindex(const char *name)
{
    struct buf gzname = BUF_INITIALIZER;
    struct buf idxname = BUF_INITIALIZER;
    int r;

    buf_printf(&gzname, "%s.gz", name);
    buf_printf(&idxname, "%s.index", name);

    struct backup *backup = backup_open_internal(buf_cstring(&gzname),
                                                 buf_cstring(&idxname),
                                                 BACKUP_OPEN_REINDEX);
    buf_free(&idxname);
    buf_free(&gzname);
    if (!backup) return -1;

    struct gzuncat *gzuc = gzuc_open(backup->fd);

    time_t prev_member_ts = -1;

    while (gzuc && !gzuc_eof(gzuc)) {
        gzuc_member_start(gzuc);
        off_t member_offset = gzuc_member_offset(gzuc);

        fprintf(stderr, "\nfound chunk at offset %jd\n\n", member_offset);

        struct protstream *member = prot_readcb(_prot_fill_cb, gzuc);
        prot_setisclient(member, 1); /* don't sync literals */

        // FIXME stricter timestamp sequence checks
        time_t member_ts = -1;

        while (1) {
            struct buf cmd = BUF_INITIALIZER;
            time_t ts;
            struct dlist *dl = NULL;
            off_t dl_offset = prot_bytes_in(member);

            int c = _parse_line(member, &ts, &cmd, &dl);
            if (c == EOF) break;
            size_t dl_len = prot_bytes_in(member) - dl_offset;

            if (member_ts == -1) {
                if (prev_member_ts != -1 && prev_member_ts > ts) {
                    fatal("member timestamp older than previous", -1);
                }
                member_ts = ts;
                backup_index_start3(backup, member_ts, member_offset);
            }
            else if (member_ts > ts)
                fatal("line timestamp older than previous", -1);

            if (strcmp(buf_cstring(&cmd), "APPLY") != 0)
                continue;

            ucase(dl->name);

            r = backup_index_dlist(backup, dl, dl_offset, dl_len);
            if (r) {
                // FIXME do something
            }
        }

        backup_index_end(backup, prot_bytes_in(member));
        prot_free(member);
        gzuc_member_end(gzuc, NULL);

        prev_member_ts = member_ts;
    }

    fprintf(stderr, "reached end of file\n");

    gzuc_close(&gzuc);
    backup_close(&backup);

    return r;
}
