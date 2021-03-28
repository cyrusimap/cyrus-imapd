/* lcb_indexr.c -- replication-based backup api - index reading functions
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
#include <syslog.h>

#include "lib/xmalloc.h"

#include "backup/backup.h"

#define LIBCYRUS_BACKUP_SOURCE /* this file is part of libcyrus_backup */
#include "backup/lcb_internal.h"
#include "backup/lcb_sqlconsts.h"

static int _column_int(sqlite3_stmt *stmt, int column)
{
    assert(sqlite3_column_type(stmt, column) == SQLITE_INTEGER ||
           sqlite3_column_type(stmt, column) == SQLITE_NULL);
    return sqlite3_column_int(stmt, column);
}

static sqlite3_int64 _column_int64(sqlite3_stmt *stmt, int column)
{
    assert(sqlite3_column_type(stmt, column) == SQLITE_INTEGER ||
           sqlite3_column_type(stmt, column) == SQLITE_NULL);
    return sqlite3_column_int64(stmt, column);
}

static const char * _column_text(sqlite3_stmt *stmt, int column)
{
    assert(sqlite3_column_type(stmt, column) == SQLITE_TEXT ||
           sqlite3_column_type(stmt, column) == SQLITE_NULL);
    return (const char *) sqlite3_column_text(stmt, column);
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

    int r = sqldb_exec(backup->db, backup_index_mailbox_select_uniqueid_sql,
                       bval, _get_mailbox_id_cb, &id);
    if (r) {
        syslog(LOG_ERR, "%s: something went wrong: %i %s",
                        __func__, r, uniqueid);
    }

    return id;
}

static void backup_mailbox_message_list_add(
    struct backup_mailbox_message_list *list,
    struct backup_mailbox_message *mailbox_message)
{
    mailbox_message->next = NULL;

    if (!list->head)
        list->head = mailbox_message;

    if (list->tail)
        list->tail->next = mailbox_message;

    list->tail = mailbox_message;

    list->count++;
}

EXPORTED struct backup_mailbox_message *backup_mailbox_message_list_remove(
    struct backup_mailbox_message_list *list,
    struct backup_mailbox_message *mailbox_message)
{
    struct backup_mailbox_message *node, *prev;

    assert(list != NULL);
    assert(mailbox_message != NULL);

    prev = NULL;
    node = list->head;
    while (node && node != mailbox_message) {
        prev = node;
        node = node->next;
    }

    if (!node) return NULL;
    assert(node == mailbox_message);

    if (prev) {
        prev->next = node->next;
    }
    else {
        assert(node == list->head);
        list->head = node->next;
    }

    if (!node->next) {
        assert(node == list->tail);
        list->tail = prev;
    }

    node->next = NULL;
    list->count--;
    return node;
}

EXPORTED void backup_mailbox_message_list_empty(
    struct backup_mailbox_message_list *list)
{
    struct backup_mailbox_message *mailbox_message, *next;

    mailbox_message = list->head;
    while (mailbox_message) {
        next = mailbox_message->next;
        backup_mailbox_message_free(&mailbox_message);
        mailbox_message = next;
    }

    memset(list, 0, sizeof(*list));
}

EXPORTED void backup_mailbox_list_add(struct backup_mailbox_list *list,
                                      struct backup_mailbox *mailbox)
{
    mailbox->next = NULL;

    if (!list->head)
        list->head = mailbox;

    if (list->tail)
        list->tail->next = mailbox;

    list->tail = mailbox;

    list->count++;
}

EXPORTED struct backup_mailbox *backup_mailbox_list_remove(
    struct backup_mailbox_list *list,
    struct backup_mailbox *mailbox)
{
    struct backup_mailbox *node, *prev;

    assert(list != NULL);
    assert(mailbox != NULL);

    prev = NULL;
    node = list->head;
    while (node && node != mailbox) {
        prev = node;
        node = node->next;
    }

    if (!node) return NULL;
    assert(node == mailbox);

    if (prev) {
        prev->next = node->next;
    }
    else {
        assert(node == list->head);
        list->head = node->next;
    }

    if (!node->next) {
        assert(node == list->tail);
        list->tail = prev;
    }

    node->next = NULL;
    list->count--;
    return node;
}

EXPORTED void backup_mailbox_list_empty(struct backup_mailbox_list *list)
{
    struct backup_mailbox *mailbox, *next;

    mailbox = list->head;
    while (mailbox) {
        next = mailbox->next;
        backup_mailbox_free(&mailbox);
        mailbox = next;
    }

    memset(list, 0, sizeof(*list));
}

struct _mailbox_message_row_rock {
    struct message_guid *match_guid;
    struct backup_mailbox_message_list *save_list;
    struct backup_mailbox_message **save_one;
};

static int _mailbox_message_row_cb(sqlite3_stmt *stmt, void *rock)
{
    struct _mailbox_message_row_rock *mbrrock =
        (struct _mailbox_message_row_rock *) rock;
    struct backup_mailbox_message *mailbox_message;
    char *guid_str = NULL;
    int r = 0;

    mailbox_message = xzmalloc(sizeof *mailbox_message);

    int column = 0;
    mailbox_message->id = _column_int(stmt, column++);
    mailbox_message->mailbox_id = _column_int(stmt, column++);
    mailbox_message->mailbox_uniqueid = xstrdupnull(_column_text(stmt, column++));
    mailbox_message->message_id = _column_int(stmt, column++);
    mailbox_message->last_chunk_id = _column_int(stmt, column++);
    mailbox_message->uid = _column_int(stmt, column++);
    mailbox_message->modseq = _column_int64(stmt, column++);
    mailbox_message->last_updated = _column_int64(stmt, column++);
    mailbox_message->flags = xstrdupnull(_column_text(stmt, column++));
    mailbox_message->internaldate = _column_int64(stmt, column++);
    guid_str = xstrdupnull(_column_text(stmt, column++));
    mailbox_message->size = _column_int(stmt, column++);
    mailbox_message->annotations = xstrdupnull(_column_text(stmt, column++));
    mailbox_message->expunged = _column_int(stmt, column++);

    message_guid_decode(&mailbox_message->guid, guid_str);
    free(guid_str);

    if (mbrrock->save_list) {
        if (!mbrrock->match_guid
            || message_guid_equal(mbrrock->match_guid, &mailbox_message->guid)) {
            backup_mailbox_message_list_add(mbrrock->save_list, mailbox_message);
            mailbox_message = NULL;
        }
    }
    else if (mbrrock->save_one) {
        *mbrrock->save_one = mailbox_message;
        mailbox_message = NULL;
    }

    if (mailbox_message)
        backup_mailbox_message_free(&mailbox_message);

    return r;
}

EXPORTED struct backup_mailbox_message_list *backup_get_mailbox_messages(
    struct backup *backup,
    int chunk_id)
{
    struct backup_mailbox_message_list *mailbox_message_list =
        xzmalloc(sizeof *mailbox_message_list);

    struct sqldb_bindval bval[] = {
        { ":last_chunk_id", SQLITE_INTEGER, { .i = chunk_id } },
        { NULL,             SQLITE_NULL,    { .s = NULL } },
    };

    const char *sql = chunk_id ?
        backup_index_mailbox_message_select_chunkid_sql :
        backup_index_mailbox_message_select_all_sql;

    struct _mailbox_message_row_rock mbrrock = {
        NULL,
        mailbox_message_list,
        NULL,
    };

    int r = sqldb_exec(backup->db, sql, bval, _mailbox_message_row_cb,
                       &mbrrock);

    if (r) {
        backup_mailbox_message_list_empty(mailbox_message_list);
        free(mailbox_message_list);
        return NULL;
    }

    return mailbox_message_list;
}

EXPORTED struct backup_mailbox_message *backup_get_mailbox_message(
    struct backup *backup,
    const char *uniqueid,
    const char *guid)
{
    struct backup_mailbox_message *mailbox_message = NULL;

    struct sqldb_bindval bval[] = {
        { ":uniqueid",      SQLITE_TEXT,    { .s = uniqueid } },
        { ":guid",          SQLITE_TEXT,    { .s = guid } },
        { NULL,             SQLITE_NULL,    { .s = NULL } },
    };

    struct _mailbox_message_row_rock mbrrock = {
        NULL, NULL, &mailbox_message,
    };

    int r = sqldb_exec(backup->db, backup_index_mailbox_message_select_one_sql,
                       bval, _mailbox_message_row_cb, &mbrrock);

    if (r) {
        syslog(LOG_DEBUG, "%s: something went wrong: %i %s %s",
                          __func__, r, uniqueid, guid);
    }

    return mailbox_message;
}

struct _mailbox_row_rock {
    sqldb_t *db;
    backup_mailbox_foreach_cb proc;
    void *rock;
    struct message_guid *match_guid;
    struct backup_mailbox_list *save_list;
    struct backup_mailbox **save_one;
    enum backup_mailbox_want_records want_records;
};

static int _mailbox_row_cb(sqlite3_stmt *stmt, void *rock)
{
    struct _mailbox_row_rock *mbrock = (struct _mailbox_row_rock *) rock;
    struct backup_mailbox *mailbox = xzmalloc(sizeof *mailbox);
    int r = 0;

    int column = 0;
    mailbox->id = _column_int(stmt, column++);
    mailbox->last_chunk_id = _column_int(stmt, column++);
    mailbox->uniqueid = xstrdupnull(_column_text(stmt, column++));
    mailbox->mboxname = xstrdupnull(_column_text(stmt, column++));
    mailbox->mboxtype = xstrdupnull(_column_text(stmt, column++));
    mailbox->last_uid = _column_int(stmt, column++);
    mailbox->highestmodseq = _column_int64(stmt, column++);
    mailbox->recentuid = _column_int(stmt, column++);
    mailbox->recenttime = _column_int64(stmt, column++);
    mailbox->last_appenddate = _column_int64(stmt, column++);
    mailbox->pop3_last_login = _column_int64(stmt, column++);
    mailbox->pop3_show_after = _column_int64(stmt, column++);
    mailbox->uidvalidity = _column_int(stmt, column++);
    mailbox->partition = xstrdupnull(_column_text(stmt, column++));
    mailbox->acl = xstrdupnull(_column_text(stmt, column++));
    mailbox->options = xstrdupnull(_column_text(stmt, column++));
    mailbox->sync_crc = _column_int(stmt, column++);
    mailbox->sync_crc_annot = _column_int(stmt, column++);
    mailbox->quotaroot = xstrdupnull(_column_text(stmt, column++));
    mailbox->xconvmodseq = _column_int64(stmt, column++);
    mailbox->annotations = xstrdupnull(_column_text(stmt, column++));
    mailbox->deleted = _column_int64(stmt, column++);

    if (mbrock->want_records) {
        if (mbrock->want_records == BACKUP_MAILBOX_MATCH_RECORDS && !mbrock->match_guid) {
            syslog(LOG_WARNING, "%s: request for guid-matched records without guid",
                   __func__);
            /* will return all records */
        }

        mailbox->records = xzmalloc(sizeof *mailbox->records);

        struct sqldb_bindval bval[] = {
            { ":mailbox_id",    SQLITE_INTEGER, { .i = mailbox->id } },
            { NULL,             SQLITE_NULL,    { .s = NULL } },
        };

        struct _mailbox_message_row_rock mbrrock = {
            mbrock->match_guid,
            mailbox->records,
            NULL,
        };

        r = sqldb_exec(mbrock->db,
                       backup_index_mailbox_message_select_mailbox_sql,
                       bval,
                       _mailbox_message_row_cb, &mbrrock);

        if (r) goto error;
    }

    if (mbrock->proc)
        r = mbrock->proc(mailbox, mbrock->rock);

    if (mbrock->save_list)
        backup_mailbox_list_add(mbrock->save_list, mailbox);
    else if (mbrock->save_one)
        *mbrock->save_one = mailbox;
    else
        backup_mailbox_free(&mailbox);

    return r;

error:
    if (mailbox) backup_mailbox_free(&mailbox);
    return -1;
}

EXPORTED int backup_mailbox_foreach(struct backup *backup,
                                    int chunk_id,
                                    enum backup_mailbox_want_records want_records,
                                    backup_mailbox_foreach_cb cb,
                                    void *rock)
{
    struct _mailbox_row_rock mbrock = { backup->db, cb, rock, NULL,
                                        NULL, NULL, want_records};

    struct sqldb_bindval bval[] = {
        { ":last_chunk_id", SQLITE_INTEGER, { .i = chunk_id } },
        { NULL,             SQLITE_NULL,    { .s = NULL } },
    };

    const char *sql = chunk_id ?
        backup_index_mailbox_select_chunkid_sql :
        backup_index_mailbox_select_all_sql;

    int r = sqldb_exec(backup->db, sql, bval, _mailbox_row_cb, &mbrock);

    return r;
}

EXPORTED struct backup_mailbox_list *backup_get_mailboxes(
    struct backup *backup,
    int chunk_id,
    enum backup_mailbox_want_records want_records)
{
    struct backup_mailbox_list *mailbox_list = xzmalloc(sizeof *mailbox_list);

    struct _mailbox_row_rock mbrock = { backup->db, NULL, NULL, NULL,
                                        mailbox_list, NULL, want_records};

    struct sqldb_bindval bval[] = {
        { ":last_chunk_id", SQLITE_INTEGER, { .i = chunk_id } },
        { NULL,             SQLITE_NULL,    { .s = NULL } },
    };

    const char *sql = chunk_id ?
        backup_index_mailbox_select_chunkid_sql :
        backup_index_mailbox_select_all_sql;

    int r = sqldb_exec(backup->db, sql, bval, _mailbox_row_cb, &mbrock);

    if (r) {
        backup_mailbox_list_empty(mailbox_list);
        free(mailbox_list);
        return NULL;
    }

    return mailbox_list;
}

EXPORTED struct backup_mailbox_list *backup_get_mailboxes_by_message(
    struct backup *backup,
    const struct backup_message *message,
    enum backup_mailbox_want_records want_records)
{
    char *guid = xstrdup(message_guid_encode(message->guid));
    struct backup_mailbox_list *mailbox_list = xzmalloc(sizeof *mailbox_list);

    struct _mailbox_row_rock mbrock = { backup->db, NULL, NULL, NULL,
                                        mailbox_list, NULL, want_records };

    if (want_records == BACKUP_MAILBOX_MATCH_RECORDS)
        mbrock.match_guid = message->guid;

    struct sqldb_bindval bval[] = {
        { ":guid", SQLITE_TEXT, { .s = guid } },
        { NULL,    SQLITE_NULL, { .s = NULL } },
    };

    int r = sqldb_exec(backup->db, backup_index_mailbox_select_message_guid_sql,
                       bval, _mailbox_row_cb, &mbrock);

    free(guid);

    if (r) {
        backup_mailbox_list_empty(mailbox_list);
        free(mailbox_list);
        return NULL;
    }

    return mailbox_list;
}

EXPORTED struct backup_mailbox *backup_get_mailbox_by_uniqueid(
    struct backup *backup,
    const char *uniqueid,
    enum backup_mailbox_want_records want_records)
{
    struct backup_mailbox *mailbox = NULL;

    struct _mailbox_row_rock mbrock = { backup->db, NULL, NULL, NULL,
                                        NULL, &mailbox, want_records };

    struct sqldb_bindval bval[] = {
        { ":uniqueid",  SQLITE_TEXT,    { .s = uniqueid } },
        { NULL,         SQLITE_NULL,    { .s = NULL } },
    };

    int r = sqldb_exec(backup->db, backup_index_mailbox_select_uniqueid_sql,
                       bval, _mailbox_row_cb, &mbrock);

    if (r) {
        if (mailbox) backup_mailbox_free(&mailbox);
        return NULL;
    }

    return mailbox;
}

EXPORTED struct backup_mailbox *backup_get_mailbox_by_name(
    struct backup *backup,
    const mbname_t *mbname,
    enum backup_mailbox_want_records want_records)
{
    struct backup_mailbox *mailbox = NULL;

    struct _mailbox_row_rock mbrock = { backup->db, NULL, NULL, NULL,
                                        NULL, &mailbox, want_records };

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

EXPORTED struct dlist *backup_mailbox_to_dlist(
    const struct backup_mailbox *mailbox)
{
    struct dlist *dl = dlist_newkvlist(NULL, "MAILBOX");

    dlist_setatom(dl, "UNIQUEID", mailbox->uniqueid);
    dlist_setatom(dl, "MBOXNAME", mailbox->mboxname);
    dlist_setatom(dl, "MBOXTYPE", mailbox->mboxtype);
    dlist_setnum32(dl, "LAST_UID", mailbox->last_uid);
    dlist_setnum64(dl, "HIGHESTMODSEQ", mailbox->highestmodseq);
    dlist_setnum32(dl, "RECENTUID", mailbox->recentuid);
    dlist_setdate(dl, "RECENTTIME", mailbox->recenttime);
    dlist_setdate(dl, "LAST_APPENDDATE", mailbox->last_appenddate);
    dlist_setdate(dl, "POP3_LAST_LOGIN", mailbox->pop3_last_login);
    dlist_setdate(dl, "POP3_SHOW_AFTER", mailbox->pop3_show_after);
    dlist_setnum32(dl, "UIDVALIDITY", mailbox->uidvalidity);
    dlist_setatom(dl, "PARTITION", mailbox->partition);
    dlist_setatom(dl, "ACL", mailbox->acl);
    dlist_setatom(dl, "OPTIONS", mailbox->options);
    dlist_setnum32(dl, "SYNC_CRC", mailbox->sync_crc);
    dlist_setnum32(dl, "SYNC_CRC_ANNOT", mailbox->sync_crc_annot);
    dlist_setatom(dl, "QUOTAROOT", mailbox->quotaroot);
    dlist_setnum64(dl, "XCONVMODSEQ", mailbox->xconvmodseq);

    /* if any flags or annotations from the index can't be parsed into dlist
     * format, we just quietly leave them out, and trust sync_client to notice
     * the difference and send updates to fix them */

    if (mailbox->annotations) {
        struct dlist *annots = NULL;
        dlist_parsemap(&annots, 0, 1, mailbox->annotations,
                       strlen(mailbox->annotations));
        if (annots) {
            annots->name = xstrdup("ANNOTATIONS");
            dlist_stitch(dl, annots);
        }
    }

    if (mailbox->records) {
        struct dlist *records = dlist_newlist(NULL, "RECORD");
        struct backup_mailbox_message *mailbox_message = mailbox->records->head;

        while (mailbox_message) {
            struct dlist *record = dlist_newkvlist(records, NULL);
            struct dlist *flags = NULL;

            dlist_setnum32(record, "UID", mailbox_message->uid);
            dlist_setnum64(record, "MODSEQ", mailbox_message->modseq);
            dlist_setdate(record, "LAST_UPDATED", mailbox_message->last_updated);
            dlist_setdate(record, "INTERNALDATE", mailbox_message->internaldate);
            dlist_setguid(record, "GUID", &mailbox_message->guid);
            dlist_setnum32(record, "SIZE", mailbox_message->size);

            /* FLAGS field is mandatory */
            if (mailbox_message->flags) {
                dlist_parsemap(&flags, 0, 1, mailbox_message->flags,
                               strlen(mailbox_message->flags));
                flags->name = xstrdup("FLAGS");
                dlist_stitch(record, flags);
            }
            else {
                flags = dlist_newlist(record, "FLAGS");
            }

            /* convert expunged to flag */
            if (mailbox_message->expunged)
                dlist_setflag(flags, "FLAG", "\\Expunged");

            if (mailbox_message->annotations) {
                struct dlist *annots = NULL;
                dlist_parsemap(&annots, 0, 1, mailbox_message->annotations,
                               strlen(mailbox_message->annotations));
                if (annots)  {
                    annots->name = xstrdup("ANNOTATIONS");
                    dlist_stitch(record, annots);
                }
            }

            mailbox_message = mailbox_message->next;
        }

        dlist_stitch(dl, records);
    }

    return dl;
}

EXPORTED struct backup_mailbox *backup_mailbox_clone(
    const struct backup_mailbox *mailbox)
{
    struct backup_mailbox *clone = xzmalloc(sizeof *clone);

    clone->id = mailbox->id;
    clone->last_chunk_id = mailbox->last_chunk_id;
    clone->last_uid = mailbox->last_uid;
    clone->highestmodseq = mailbox->highestmodseq;
    clone->recentuid = mailbox->recentuid;
    clone->recenttime = mailbox->recenttime;
    clone->last_appenddate = mailbox->last_appenddate;
    clone->pop3_last_login = mailbox->pop3_last_login;
    clone->pop3_show_after = mailbox->pop3_show_after;
    clone->uidvalidity = mailbox->uidvalidity;
    clone->sync_crc = mailbox->sync_crc;
    clone->sync_crc_annot = mailbox->sync_crc_annot;
    clone->xconvmodseq = mailbox->xconvmodseq;
    clone->deleted = mailbox->deleted;

    clone->uniqueid = xstrdupnull(mailbox->uniqueid);
    clone->mboxname = xstrdupnull(mailbox->mboxname);
    clone->mboxtype = xstrdupnull(mailbox->mboxtype);
    clone->partition = xstrdupnull(mailbox->partition);
    clone->acl = xstrdupnull(mailbox->acl);
    clone->options = xstrdupnull(mailbox->options);
    clone->quotaroot = xstrdupnull(mailbox->quotaroot);
    clone->annotations = xstrdupnull(mailbox->annotations);

    if (mailbox->records) {
        struct backup_mailbox_message *iter;

        clone->records = xzmalloc(sizeof *clone->records);

        for (iter = mailbox->records->head; iter; iter = iter->next) {
            backup_mailbox_message_list_add(clone->records,
                                            backup_mailbox_message_clone(iter));
        }
    }

    return clone;
}

EXPORTED struct backup_mailbox_message *backup_mailbox_message_clone(
                                    const struct backup_mailbox_message *orig)
{
    struct backup_mailbox_message *clone = xzmalloc(sizeof *clone);

    clone->id = orig->id;
    clone->mailbox_id = orig->mailbox_id;
    clone->message_id = orig->message_id;
    clone->last_chunk_id = orig->last_chunk_id;
    clone->uid = orig->uid;
    clone->modseq = orig->modseq;
    clone->last_updated = orig->last_updated;
    clone->internaldate = orig->internaldate;
    clone->guid = orig->guid;
    clone->size = orig->size;
    clone->expunged = orig->expunged;

    clone->mailbox_uniqueid = xstrdupnull(orig->mailbox_uniqueid);
    clone->flags = xstrdupnull(orig->flags);
    clone->annotations = xstrdupnull(orig->annotations);

    return clone;
}

EXPORTED void backup_mailbox_message_free(
    struct backup_mailbox_message **mailbox_messagep)
{
    struct backup_mailbox_message *mailbox_message = *mailbox_messagep;
    *mailbox_messagep = NULL;

    if (mailbox_message->flags) free(mailbox_message->flags);
    if (mailbox_message->annotations) free(mailbox_message->annotations);
    if (mailbox_message->mailbox_uniqueid) free(mailbox_message->mailbox_uniqueid);

    free(mailbox_message);
}

EXPORTED void backup_mailbox_free(struct backup_mailbox **mailboxp)
{
    struct backup_mailbox *mailbox = *mailboxp;
    *mailboxp = NULL;

    if (mailbox->uniqueid) free(mailbox->uniqueid);
    if (mailbox->mboxname) free(mailbox->mboxname);
    if (mailbox->mboxtype) free(mailbox->mboxtype);
    if (mailbox->partition) free(mailbox->partition);
    if (mailbox->acl) free(mailbox->acl);
    if (mailbox->options) free(mailbox->options);
    if (mailbox->quotaroot) free(mailbox->quotaroot);
    if (mailbox->annotations) free(mailbox->annotations);

    if (mailbox->records) {
        backup_mailbox_message_list_empty(mailbox->records);
        free(mailbox->records);
    }

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

    int id = 0;

    int r = sqldb_exec(backup->db, backup_index_message_select_guid_sql, bval,
                       _get_message_id_cb, &id);
    if (r) {
        syslog(LOG_ERR, "%s: something went wrong: %i %s",
                        __func__, r, guid);
        return -1;
    }

    return id;
}

EXPORTED void backup_message_free(struct backup_message **messagep)
{
    struct backup_message *message = *messagep;
    *messagep = NULL;

    if (message->guid) free(message->guid);
    if (message->partition) free(message->partition);

    free(message);
}

struct message_row_rock {
    backup_message_foreach_cb proc;
    void *rock;
    struct backup_message **save_one;
};

static int _message_row_cb(sqlite3_stmt *stmt, void *rock)
{
    struct message_row_rock *mrock = (struct message_row_rock *) rock;
    struct backup_message *message = xzmalloc(sizeof *message);
    const char *guid_str = NULL;
    int column = 0;
    int r = 0;

    message->id = _column_int(stmt, column++);
    guid_str = _column_text(stmt, column++);
    message->partition = xstrdupnull(_column_text(stmt, column++));
    message->chunk_id = _column_int(stmt, column++);
    message->offset = _column_int64(stmt, column++);
    message->length = _column_int64(stmt, column++);

    message->guid = xzmalloc(sizeof *message->guid);
    if (!message_guid_decode(message->guid, guid_str)) goto error;

    if (mrock->proc)
        r = mrock->proc(message, mrock->rock);

    if (mrock->save_one)
        *mrock->save_one = message;
    else
        backup_message_free(&message);

    return r;

error:
    if (message) backup_message_free(&message);
    return -1;
}

EXPORTED struct backup_message *backup_get_message(struct backup *backup,
                                                   const struct message_guid *guid)
{
    struct sqldb_bindval bval[] = {
        { ":guid",  SQLITE_TEXT,    { .s = message_guid_encode(guid) } },
        { NULL,     SQLITE_NULL,    { .s = NULL } },
    };

    struct backup_message *bm = NULL;

    struct message_row_rock mrock = { NULL, NULL, &bm };

    int r = sqldb_exec(backup->db, backup_index_message_select_guid_sql, bval,
                       _message_row_cb, &mrock);
    if (r) {
        syslog(LOG_ERR, "%s: something went wrong: %i %s",
                        __func__, r, message_guid_encode(guid));
        if (bm) backup_message_free(&bm);
        return NULL;
    }

    return bm;
}

EXPORTED int backup_message_foreach(struct backup *backup,
                                    int chunk_id, const time_t *sincep,
                                    backup_message_foreach_cb cb, void *rock)
{
    const char *sql = NULL;

    struct sqldb_bindval bval[] = {
        { ":chunk_id",  SQLITE_INTEGER, { .i = chunk_id } },
        { ":since",     SQLITE_NULL,    { .s = NULL } },
        { NULL,         SQLITE_NULL,    { .s = NULL } },
    };

    struct message_row_rock mrock = { cb, rock, NULL };

    if (chunk_id) {
        if (sincep) {
            struct sqldb_bindval *since_bval = &bval[1];
            assert(strcmp(since_bval->name, ":since") == 0);
            since_bval->type = SQLITE_INTEGER;
            since_bval->val.i = *sincep;
            sql = backup_index_message_select_live_chunkid_sql;
        }
        else {
            sql = backup_index_message_select_chunkid_sql;
        }
    }
    else {
        sql = backup_index_message_select_all_sql;
    }

    return sqldb_exec(backup->db, sql, bval, _message_row_cb, &mrock);
}

EXPORTED void backup_chunk_list_add(struct backup_chunk_list *list,
                                    struct backup_chunk *chunk)
{
    chunk->next = NULL;

    if (list->tail)
        list->tail->next = chunk;

    if (!list->head)
        list->head = chunk;

    list->tail = chunk;
    list->count++;
}

EXPORTED void backup_chunk_list_empty(struct backup_chunk_list *list)
{
    struct backup_chunk *curr, *next;
    curr = list->head;
    while (curr) {
        next = curr->next;
        backup_chunk_free(&curr);
        curr = next;
    }

    list->head = list->tail = NULL;
    list->count = 0;
}

EXPORTED void backup_chunk_list_free(struct backup_chunk_list **chunk_listp)
{
    struct backup_chunk_list *chunk_list = *chunk_listp;
    *chunk_listp = NULL;

    backup_chunk_list_empty(chunk_list);
    free(chunk_list);
}

struct _chunk_row_rock {
    struct backup_chunk_list *save_list;
    struct backup_chunk **save_one;
};

static int _chunk_row_cb(sqlite3_stmt *stmt, void *rock)
{
    struct _chunk_row_rock *crock = (struct _chunk_row_rock *) rock;

    struct backup_chunk *chunk = xzmalloc(sizeof(*chunk));

    int column = 0;
    chunk->id = _column_int(stmt, column++);
    chunk->ts_start = _column_int64(stmt, column++);
    chunk->ts_end = _column_int64(stmt, column++);
    chunk->offset = _column_int64(stmt, column++);
    chunk->length = _column_int64(stmt, column++);
    chunk->file_sha1 = xstrdupnull(_column_text(stmt, column++));
    chunk->data_sha1 = xstrdupnull(_column_text(stmt, column++));

    if (crock->save_list) {
        backup_chunk_list_add(crock->save_list, chunk);
    }
    else if (crock->save_one) {
        *crock->save_one = chunk;
    }
    else {
        syslog(LOG_DEBUG, "%s: useless invocation with nowhere to save to", __func__);
        backup_chunk_free(&chunk);
    }

    return 0;
}

EXPORTED struct backup_chunk_list *backup_get_chunks(struct backup *backup)
{
    struct backup_chunk_list *chunk_list = xzmalloc(sizeof *chunk_list);

    struct _chunk_row_rock crock = { chunk_list, NULL };

    int r = sqldb_exec(backup->db, backup_index_chunk_select_all_sql,
                       NULL, _chunk_row_cb, &crock);

    if (r) {
        backup_chunk_list_free(&chunk_list);
        return NULL;
    }

    return chunk_list;
}

EXPORTED struct backup_chunk_list *backup_get_live_chunks(struct backup *backup,
                                                          time_t since)
{
    struct backup_chunk_list *chunk_list = xzmalloc(sizeof *chunk_list);

    struct _chunk_row_rock crock = { chunk_list, NULL };

    struct sqldb_bindval bval[] = {
        { ":since", SQLITE_INTEGER, { .i = since } },
        { NULL,     SQLITE_NULL,    { .s = NULL  } },
    };

    int r = sqldb_exec(backup->db, backup_index_chunk_select_live_sql,
                       bval, _chunk_row_cb, &crock);

    if (r) {
        backup_chunk_list_free(&chunk_list);
        return NULL;
    }

    return chunk_list;
}

EXPORTED struct backup_chunk *backup_get_chunk(struct backup *backup,
                                               int chunk_id)
{
    struct backup_chunk *chunk = NULL;
    struct _chunk_row_rock crock = { NULL, &chunk };

    struct sqldb_bindval bval[] = {
        { ":id",    SQLITE_INTEGER, { .i = chunk_id } },
        { NULL,     SQLITE_NULL,    { .s = NULL     } },
    };

    int r = sqldb_exec(backup->db, backup_index_chunk_select_id_sql,
                       bval, _chunk_row_cb, &crock);

    if (r) {
        if (chunk) backup_chunk_free(&chunk);
        return NULL;
    }

    return chunk;
}

EXPORTED struct backup_chunk *backup_get_latest_chunk(struct backup *backup)
{
    struct backup_chunk *chunk = NULL;
    struct _chunk_row_rock crock = { NULL, &chunk };

    int r = sqldb_exec(backup->db, backup_index_chunk_select_latest_sql,
                       NULL, _chunk_row_cb, &crock);

    if (r) {
        if (chunk) backup_chunk_free(&chunk);
        return NULL;
    }

    return chunk;
}

EXPORTED void backup_chunk_free(struct backup_chunk **chunkp)
{
    struct backup_chunk *chunk = *chunkp;
    *chunkp = NULL;

    if (chunk->file_sha1) free(chunk->file_sha1);
    if (chunk->data_sha1) free(chunk->data_sha1);

    free(chunk);
}

struct _seen_row_rock {
    backup_seen_foreach_cb proc;
    void *rock;
};

static int _seen_row_cb(sqlite3_stmt *stmt, void *rock)
{
    struct _seen_row_rock *seenrock = (struct _seen_row_rock *) rock;
    struct backup_seen *seen = xzmalloc(sizeof *seen);
    int r = 0;

    int column = 0;
    seen->id = _column_int(stmt, column++);
    seen->last_chunk_id = _column_int(stmt, column++);
    seen->uniqueid = xstrdupnull(_column_text(stmt, column++));
    seen->lastread = _column_int64(stmt, column++);
    seen->lastuid = _column_int(stmt, column++);
    seen->lastchange = _column_int64(stmt, column++);
    seen->seenuids = xstrdupnull(_column_text(stmt, column++));

    if (seenrock->proc)
        r = seenrock->proc(seen, seenrock->rock);

    backup_seen_free(&seen);

    return r;
}

EXPORTED int backup_seen_foreach(struct backup *backup,
                                 int chunk_id,
                                 backup_seen_foreach_cb cb,
                                 void *rock)
{
    struct _seen_row_rock seenrock = { cb, rock };

    struct sqldb_bindval bval[] = {
        { ":last_chunk_id", SQLITE_INTEGER, { .i = chunk_id } },
        { NULL,             SQLITE_NULL,    { .s = NULL } },
    };

    const char *sql = chunk_id ?
        backup_index_seen_select_chunkid_sql :
        backup_index_seen_select_all_sql;

    int r = sqldb_exec(backup->db, sql, bval, _seen_row_cb, &seenrock);

    return r;
}

EXPORTED void backup_seen_free(struct backup_seen **seenp)
{
    struct backup_seen *seen = *seenp;
    *seenp = NULL;

    if (seen->uniqueid) free(seen->uniqueid);
    if (seen->seenuids) free(seen->seenuids);

    free(seen);
}

struct _subscription_row_rock {
    backup_subscription_foreach_cb proc;
    void *rock;
};

static int _subscription_row_cb(sqlite3_stmt *stmt, void *rock)
{
    struct _subscription_row_rock *subrock = (struct _subscription_row_rock *) rock;
    struct backup_subscription *sub = xzmalloc(sizeof *sub);
    int r = 0;

    int column = 0;
    sub->id = _column_int(stmt, column++);
    sub->last_chunk_id = _column_int(stmt, column++);
    sub->mboxname = xstrdupnull(_column_text(stmt, column++));
    sub->unsubscribed = _column_int64(stmt, column++);

    if (subrock->proc)
        r = subrock->proc(sub, subrock->rock);

    backup_subscription_free(&sub);

    return r;
}

EXPORTED int backup_subscription_foreach(struct backup *backup,
                                         int chunk_id,
                                         backup_subscription_foreach_cb cb,
                                         void *rock)
{
    struct _subscription_row_rock subrock = { cb, rock };

    struct sqldb_bindval bval[] = {
        { ":last_chunk_id", SQLITE_INTEGER, { .i = chunk_id } },
        { NULL,             SQLITE_NULL,    { .s = NULL } },
    };

    const char *sql = chunk_id ?
        backup_index_subscription_select_chunkid_sql :
        backup_index_subscription_select_all_sql;

    int r = sqldb_exec(backup->db, sql, bval, _subscription_row_cb, &subrock);

    return r;
}

EXPORTED void backup_subscription_free(struct backup_subscription **subp)
{
    struct backup_subscription *sub = *subp;
    *subp = NULL;

    if (sub->mboxname) free(sub->mboxname);

    free(sub);
}

struct _sieve_row_rock {
    backup_sieve_foreach_cb proc;
    void *rock;
};

static int _sieve_row_cb(sqlite3_stmt *stmt, void *rock)
{
    struct _sieve_row_rock *srock = (struct _sieve_row_rock *) rock;
    struct backup_sieve *sieve = xzmalloc(sizeof *sieve);
    int r = 0;

    int column = 0;
    sieve->id = _column_int(stmt, column++);
    sieve->chunk_id = _column_int(stmt, column++);
    sieve->last_update = _column_int64(stmt, column++);
    sieve->filename = xstrdupnull(_column_text(stmt, column++));
    message_guid_decode(&sieve->guid, _column_text(stmt, column++));
    sieve->offset = _column_int64(stmt, column++);
    sieve->deleted = _column_int64(stmt, column++);

    if (srock->proc)
        r = srock->proc(sieve, srock->rock);

    backup_sieve_free(&sieve);

    return r;
}

EXPORTED int backup_sieve_foreach(struct backup *backup,
                                  int chunk_id,
                                  backup_sieve_foreach_cb cb,
                                  void *rock)
{
    struct _sieve_row_rock srock = { cb, rock };

    struct sqldb_bindval bval[] = {
        { ":chunk_id",  SQLITE_INTEGER, { .i = chunk_id } },
        { NULL,         SQLITE_NULL,    { .s = NULL } },
    };

    const char *sql = chunk_id ?
        backup_index_sieve_select_chunkid_sql :
        backup_index_sieve_select_all_sql;

    int r = sqldb_exec(backup->db, sql, bval, _sieve_row_cb, &srock);

    return r;
}

EXPORTED void backup_sieve_free(struct backup_sieve **sievep)
{
    struct backup_sieve *sieve = *sievep;
    *sievep = NULL;

    if (sieve->filename) free(sieve->filename);

    free(sieve);
}
