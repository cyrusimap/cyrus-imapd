/* verify.c -- replication-based backup api - verify functions
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
#include <assert.h>

#include "lib/hash.h"
#include "lib/xmalloc.h"
#include "lib/xsha1.h"

#include "backup/api.h"
#include "backup/gzuncat.h"
#include "backup/sqlconsts.h"

#define BACKUP_INTERNAL_SOURCE /* this file is part of the backup API */
#include "backup/internal.h"

/* FIXME make it xsha1_file and do it properly */
#define SHA1_LIMIT_WHOLE_FILE ((size_t) -1)
extern const char *_sha1_file(int fd, const char *fname, size_t limit,
                              char buf[2 * SHA1_DIGEST_LENGTH + 1]);
/***********************************************/

/* FIXME do this properly too */
int _column_int(sqlite3_stmt *stmt, int column);
sqlite3_int64 _column_int64(sqlite3_stmt *stmt, int column);
char * _column_text(sqlite3_stmt *stmt, int column);
/***********************************************/

struct chunk {
    struct chunk *next;
    int id;
    time_t timestamp;
    off_t offset;
    size_t length;
    char *file_sha1;
    char *data_sha1;
};

struct chunk_list {
    struct chunk *head;
    struct chunk *tail;
};

static void chunk_list_add(struct chunk_list *list, struct chunk *chunk) {
    /* n.b. always inserts at head */
    chunk->next = list->head;
    list->head = chunk;
    if (!list->tail)
        list->tail = chunk;
}

static void chunk_list_empty(struct chunk_list *list) {
    struct chunk *curr, *next;
    curr = list->head;
    while (curr) {
        next = curr->next;
        if (curr->file_sha1) free(curr->file_sha1);
        if (curr->data_sha1) free(curr->data_sha1);
        free(curr);
        curr = next;
    }

    list->head = list->tail = NULL;
}

static int verify_chunk_checksums(struct backup *backup, struct chunk *chunk,
                                  struct gzuncat *gzuc);
static int verify_chunk_messages(struct backup *backup, struct chunk *chunk,
                                 struct gzuncat *gzuc, unsigned level);
static int verify_chunk_mailbox_links(struct backup *backup, struct chunk *chunk,
                                      struct gzuncat *gzuc);

static int chunk_select_cb(sqlite3_stmt *stmt, void *rock)
{
    struct chunk_list *list = (struct chunk_list *) rock;

    struct chunk *chunk = xzmalloc(sizeof(*chunk));

    int column = 0;
    chunk->id = _column_int(stmt, column++);
    chunk->timestamp = _column_int64(stmt, column++);
    chunk->offset = _column_int64(stmt, column++);
    chunk->length = _column_int64(stmt, column++);
    chunk->file_sha1 = _column_text(stmt, column++);
    chunk->data_sha1 = _column_text(stmt, column++);

    chunk_list_add(list, chunk);

    return 0;
}

EXPORTED int backup_verify(struct backup *backup, unsigned level)
{
    struct chunk_list chunk_list = {0};
    struct gzuncat *gzuc = NULL;
    int r = 0;

    /* don't double-verify last checksum when verifying all */
    if ((level & BACKUP_VERIFY_ALL_CHECKSUMS))
        level &= ~BACKUP_VERIFY_LAST_CHECKSUM;

    /* don't double-verify message links when verifying message guids */
    if ((level & BACKUP_VERIFY_MESSAGE_GUIDS))
        level &= ~BACKUP_VERIFY_MESSAGE_LINKS;

    r = sqldb_exec(backup->db, backup_index_chunk_select_all_sql,
                       NULL, chunk_select_cb, &chunk_list);
    if (r) goto done;
    if (!chunk_list.head) goto done;

    gzuc = gzuc_open(backup->fd);
    if (!gzuc) {
        r = -1;
        goto done;
    }

    if (!r && (level & BACKUP_VERIFY_LAST_CHECKSUM))
        r = verify_chunk_checksums(backup, chunk_list.head, gzuc);

    if (!r && level > BACKUP_VERIFY_LAST_CHECKSUM) {
        struct chunk *chunk = chunk_list.head;
        while (!r && chunk) {
            if (!r && (level & BACKUP_VERIFY_ALL_CHECKSUMS))
                r = verify_chunk_checksums(backup, chunk, gzuc);

            if (!r && (level & BACKUP_VERIFY_MESSAGES))
                r = verify_chunk_messages(backup, chunk, gzuc, level);

            if (!r && (level & BACKUP_VERIFY_MAILBOX_LINKS))
                r = verify_chunk_mailbox_links(backup, chunk, gzuc);

            chunk = chunk->next;
        }
    }

done:
    if (gzuc) gzuc_close(&gzuc);
    chunk_list_empty(&chunk_list);
    return r;
}

static int verify_chunk_checksums(struct backup *backup, struct chunk *chunk,
                                  struct gzuncat *gzuc)
{
    int r;

    if (!chunk->id) {
        fprintf(stderr, "%s: %s file checksum mismatch: not in index\n",
                __func__, backup->data_fname);
        r = -1;
        goto done;
    }

    /* validate file-prior-to-this-chunk checksum */
    char file_sha1[2 * SHA1_DIGEST_LENGTH + 1];
    _sha1_file(backup->fd, backup->data_fname, chunk->offset, file_sha1);
    r = strncmp(chunk->file_sha1, file_sha1, sizeof(file_sha1));
    if (r) {
        fprintf(stderr, "%s: %s (chunk %d) file checksum mismatch: %s on disk, %s in index\n",
                __func__, backup->data_fname, chunk->id, file_sha1, chunk->file_sha1);
        goto done;
    }

    /* validate data-within-this-chunk checksum */
    char buf[8192]; /* FIXME whatever */
    size_t len = 0;
    SHA_CTX sha_ctx;
    SHA1_Init(&sha_ctx);
    gzuc_member_start_from(gzuc, chunk->offset);
    while (!gzuc_member_eof(gzuc)) {
        ssize_t n = gzuc_read(gzuc, buf, sizeof(buf));
        if (n >= 0) {
            SHA1_Update(&sha_ctx, buf, n);
            len += n;
        }
    }
    gzuc_member_end(gzuc, NULL);
    if (len != chunk->length) {
        fprintf(stderr, "%s: %s (chunk %d) data length mismatch: "
                        SIZE_T_FMT " on disk,"
                        SIZE_T_FMT " in index\n",
                __func__, backup->data_fname, chunk->id, len, chunk->length);
        r = -1;
        goto done;
    }
    unsigned char sha1_raw[SHA1_DIGEST_LENGTH];
    char data_sha1[2 * SHA1_DIGEST_LENGTH + 1];
    SHA1_Final(sha1_raw, &sha_ctx);
    r = bin_to_hex(sha1_raw, SHA1_DIGEST_LENGTH, data_sha1, BH_LOWER);
    assert(r == 2 * SHA1_DIGEST_LENGTH);
    r = strncmp(chunk->data_sha1, data_sha1, sizeof(data_sha1));
    if (r) {
        fprintf(stderr, "%s: %s (chunk %d) data checksum mismatch: %s on disk, %s in index\n",
                __func__, backup->data_fname, chunk->id, data_sha1, chunk->data_sha1);
        goto done;
    }

done:
    fprintf(stderr, "%s: checksum %s!\n", __func__, r ? "failed" : "passed");
    return r;
}

static ssize_t _prot_fill_cb(unsigned char *buf, size_t len, void *rock)
{
    struct gzuncat *gzuc = (struct gzuncat *) rock;
    return gzuc_read(gzuc, buf, len);
}

struct verify_message_rock {
    struct gzuncat *gzuc;
    int verify_guid;
    struct dlist *cached_dlist;
    off_t cached_offset;
};

static int _verify_message_cb(const struct backup_message *message, void *rock)
{
    struct verify_message_rock *vmrock = (struct verify_message_rock *) rock;
    struct dlist *dl = NULL;
    struct dlist *di = NULL;
    int r;

    /* cache the dlist so that multiple reads from the same offset don't
     * cause expensive reverse seeks in decompression stream
     */
    if (!vmrock->cached_dlist || vmrock->cached_offset != message->offset) {
        if (vmrock->cached_dlist)
            dlist_free(&vmrock->cached_dlist);

        r = gzuc_seekto(vmrock->gzuc, message->offset);
        if (r) return r;

        struct protstream *ps = prot_readcb(_prot_fill_cb, vmrock->gzuc);
        prot_setisclient(ps, 1); /* don't sync literals */
        r = _parse_line(ps, NULL, NULL, &dl);
        prot_free(ps);

        if (r == EOF) return r;

        vmrock->cached_dlist = dl;
        vmrock->cached_offset = message->offset;
    }
    else {
        dl = vmrock->cached_dlist;
    }

    r = strcmp(dl->name, "MESSAGE");
    if (r) return r;

    r = -1;
    for (di = dl->head; di; di = di->next) {
        if (di->type != DL_SFILE)
            continue;

        r = message_guid_cmp(di->gval, message->guid);
        if (!r) {
            if (vmrock->verify_guid) {
                struct message_guid guid;
                message_guid_generate(&guid, di->sval, di->nval);
                r = message_guid_cmp(&guid, message->guid);
            }
            break;
        }
    }

    return r;
}

/* verify that each message exists within the chunk the index claims */
static int verify_chunk_messages(struct backup *backup, struct chunk *chunk,
                                 struct gzuncat *gzuc, unsigned level)
{
    struct verify_message_rock vmrock = {
        gzuc,
        (level & BACKUP_VERIFY_MESSAGE_GUIDS),
        NULL,
        0,
    };

    /* FIXME this is a mess */
    int r = gzuc_member_start_from(gzuc, chunk->offset);

    if (!r) r = backup_message_foreach(backup, chunk->id, _verify_message_cb,
                                       &vmrock);

    gzuc_member_end(gzuc, NULL);

    if (vmrock.cached_dlist)
        dlist_free(&vmrock.cached_dlist);

    fprintf(stderr, "%s: chunk %d %s!\n", __func__, chunk->id,
            r ? "failed" : "passed");
    return r;
}

static int mailbox_matches(const struct backup_mailbox *mailbox,
                           struct dlist *dlist)
{
    const char *mboxname = NULL;
    uint32_t last_uid = 0;
    modseq_t highestmodseq = 0;
    uint32_t recentuid = 0;
    time_t recenttime = 0;
    time_t last_appenddate = 0;
    uint32_t uidvalidity = 0;
    const char *partition = NULL;
    const char *acl = NULL;
    const char *options = NULL;
    modseq_t xconvmodseq = 0;
    struct synccrcs synccrcs = { 0, 0 };

    if (!dlist_getatom(dlist, "MBOXNAME", &mboxname)
        || strcmp(mboxname, mailbox->mboxname) != 0)
        return 0;

    if (!dlist_getnum32(dlist, "LAST_UID", &last_uid)
        || last_uid != mailbox->last_uid)
        return 0;

    if (!dlist_getnum64(dlist, "HIGHESTMODSEQ", &highestmodseq)
        || highestmodseq != mailbox->highestmodseq)
        return 0;

    if (!dlist_getnum32(dlist, "RECENTUID", &recentuid)
        || recentuid != mailbox->recentuid)
        return 0;

    if (!dlist_getdate(dlist, "RECENTTIME", &recenttime)
        || recenttime != mailbox->recenttime)
        return 0;

    if (!dlist_getdate(dlist, "LAST_APPENDDATE", &last_appenddate)
        || last_appenddate != mailbox->last_appenddate)
        return 0;

    if (!dlist_getnum32(dlist, "UIDVALIDITY", &uidvalidity)
        || uidvalidity != mailbox->uidvalidity)
        return 0;

    if (!dlist_getatom(dlist, "PARTITION", &partition)
        || strcmp(partition, mailbox->partition) != 0)
        return 0;

    if (!dlist_getatom(dlist, "ACL", &acl)
        || strcmp(acl, mailbox->acl) != 0)
        return 0;

    if (!dlist_getatom(dlist, "OPTIONS", &options)
        || strcmp(options, mailbox->options) != 0)
        return 0;

    /* optional */
    dlist_getnum64(dlist, "XCONVMODSEQ", &xconvmodseq);
    if (xconvmodseq != mailbox->xconvmodseq)
        return 0;

    /* CRCs */
    dlist_getnum32(dlist, "SYNC_CRC", &synccrcs.basic);
    dlist_getnum32(dlist, "SYNC_CRC_ANNOT", &synccrcs.annot);
    if (synccrcs.basic != mailbox->sync_crc)
        return 0;
    if (synccrcs.annot != mailbox->sync_crc_annot)
        return 0;

    fprintf(stderr, "%s: %s matches!\n", __func__, mailbox->uniqueid);
    return 1;
}

static int mailbox_message_matches(const struct backup_mailbox_message *mailbox_message,
                                   struct dlist *dlist)
{
    modseq_t modseq;
    uint32_t last_updated;
    uint32_t internaldate;
    uint32_t size;
    struct message_guid *guid;

    if (!dlist_getnum64(dlist, "MODSEQ", &modseq)
        || modseq != mailbox_message->modseq)
        return 0;

    if (!dlist_getnum32(dlist, "LAST_UPDATED", &last_updated)
        || last_updated != mailbox_message->last_updated)
        return 0;

    if (!dlist_getnum32(dlist, "INTERNALDATE", &internaldate)
        || internaldate != mailbox_message->internaldate)
        return 0;

    if (!dlist_getnum32(dlist, "SIZE", &size)
        || size != mailbox_message->size)
        return 0;

    if (!dlist_getguid(dlist, "GUID", &guid)
        || !message_guid_equal(guid, &mailbox_message->guid))
        return 0;

    fprintf(stderr, "%s: %s:%u matches!\n", __func__,
            mailbox_message->mailbox_uniqueid, mailbox_message->uid);
    return 1;
}

/* verify that the matching MAILBOX exists within the claimed chunk
 * for each mailbox or mailbox_message in the index
 */
static int verify_chunk_mailbox_links(struct backup *backup, struct chunk *chunk,
                                      struct gzuncat *gzuc)
{
    /*
     *   get list of mailboxes in chunk
     *   get list of mailbox_messages in chunk
     *   index mailboxes list by uniqueid
     *   index mailbox_messages list by uniqueid:uid
     *   open chunk
     *   foreach line in chunk
     *     read dlist
     *     skip if it's not a mailbox
     *     if details in dlist match details in mailbox
     *       remove from mailbox list/index
     *     foreach record in dlist
     *       if details in dlist match details in mailbox_message
     *       remove from mailbox_message list/index
     *   failed if either list of mailboxes or list of mailbox_messages is not empty
     */

    struct backup_mailbox_list *mailbox_list = NULL;
    struct backup_mailbox_message_list *mailbox_message_list = NULL;
    hash_table mailbox_list_index = HASH_TABLE_INITIALIZER;
    hash_table mailbox_message_list_index = HASH_TABLE_INITIALIZER;
    struct backup_mailbox *mailbox = NULL;
    struct backup_mailbox_message *mailbox_message = NULL;
    int r;

    mailbox_list = backup_get_mailboxes(backup, chunk->id, 0);
    mailbox_message_list = backup_get_mailbox_messages(backup, chunk->id);

    if (mailbox_list->count == 0 && mailbox_message_list->count == 0) {
        /* nothing we care about in this chunk */
        free(mailbox_list);
        free(mailbox_message_list);
        return 0;
    }

    if (mailbox_list->count) {
        /* build an index of the mailbox list */
        construct_hash_table(&mailbox_list_index, mailbox_list->count, 0); // FIXME pool?
        mailbox = mailbox_list->head;
        while (mailbox) {
            hash_insert(mailbox->uniqueid, mailbox, &mailbox_list_index);
            mailbox = mailbox->next;
        }
    }

    if (mailbox_message_list->count) {
        /* build an index of the mailbox message list */
        construct_hash_table(&mailbox_message_list_index,
                             mailbox_message_list->count, 0); // FIXME pool?
        mailbox_message = mailbox_message_list->head;
        while (mailbox_message) {
            char keybuf[1024]; // FIXME whatever
            snprintf(keybuf, sizeof(keybuf), "%s:%d",
                     mailbox_message->mailbox_uniqueid, mailbox_message->uid);
            hash_insert(keybuf, mailbox_message, &mailbox_message_list_index);
            mailbox_message = mailbox_message->next;
        }
    }

    r = gzuc_member_start_from(gzuc, chunk->offset); // FIXME error handling
    struct protstream *ps = prot_readcb(_prot_fill_cb, gzuc);
    prot_setisclient(ps, 1); /* don't sync literals */

    while (1) {
        struct buf cmd = BUF_INITIALIZER;
        struct dlist *dl = NULL;
        struct dlist *record = NULL;
        struct dlist *di = NULL;
        const char *uniqueid = NULL;
        int mailbox_removed = 0;

        int c = _parse_line(ps, NULL, &cmd, &dl);
        if (c == EOF) break;

        if (strcmp(buf_cstring(&cmd), "APPLY") != 0)
            goto next_line;

        if (strcmp(dl->name, "MAILBOX") != 0)
            goto next_line;

        if (!dlist_getatom(dl, "UNIQUEID", &uniqueid))
            goto next_line;

        if (mailbox_list->count) {
            mailbox = (struct backup_mailbox *) hash_lookup(uniqueid, &mailbox_list_index);
            if (!mailbox)
                goto next_line;

            if (!mailbox_matches(mailbox, dl))
                goto next_line;

            backup_mailbox_list_remove(mailbox_list, mailbox);
            hash_del(uniqueid, &mailbox_list_index);
            mailbox_removed = 1; /* don't free it yet, need it for record processing */
        }

        if (mailbox_message_list->count) {
            if (!dlist_getlist(dl, "RECORD", &record))
                goto next_line;

            for (di = record->head; di; di = di->next) {
                char keybuf[1024]; // FIXME whatever
                uint32_t uid;

                if (!dlist_getnum32(di, "UID", &uid))
                    continue;

                snprintf(keybuf, sizeof(keybuf), "%s:%d", uniqueid, uid);
                mailbox_message = (struct backup_mailbox_message *) hash_lookup(
                    keybuf, &mailbox_message_list_index);

                if (!mailbox_message)
                    continue;

                if (!mailbox_message_matches(mailbox_message, di))
                    continue;

                backup_mailbox_message_list_remove(mailbox_message_list, mailbox_message);
                hash_del(keybuf, &mailbox_message_list_index);
                backup_mailbox_message_free(&mailbox_message);
            }
        }

next_line:
        if (mailbox && mailbox_removed)
            backup_mailbox_free(&mailbox);
        if (dl)
            dlist_free(&dl);
    }

    prot_free(ps);
    gzuc_member_end(gzuc, NULL);

    /* anything left in either of the lists is missing from the chunk data. bad! */
    mailbox = mailbox_list->head;
    while (mailbox) {
        fprintf(stderr, "%s: chunk %d missing mailbox data for %s (%s)\n",
                __func__, chunk->id, mailbox->uniqueid, mailbox->mboxname);
        mailbox = mailbox->next;
    }

    mailbox_message = mailbox_message_list->head;
    while (mailbox_message) {
        fprintf(stderr, "%s: chunk %d missing mailbox_message data for %s uid %u\n",
                __func__, chunk->id, mailbox_message->mailbox_uniqueid,
                mailbox_message->uid);
        mailbox_message = mailbox_message->next;
    }

    if (!r) r = mailbox_list->count || mailbox_message_list->count ? -1 : 0;

    free_hash_table(&mailbox_list_index, NULL);
    free_hash_table(&mailbox_message_list_index, NULL);

    backup_mailbox_list_empty(mailbox_list);
    free(mailbox_list);

    backup_mailbox_message_list_empty(mailbox_message_list);
    free(mailbox_message_list);

    fprintf(stderr, "%s: chunk %d %s!\n", __func__, chunk->id,
            r ? "failed" : "passed");

    return r;
}
