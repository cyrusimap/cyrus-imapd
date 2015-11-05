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

static int verify_chunk_checksums(struct backup *backup, struct chunk *chunk);
static int verify_chunk_messages(struct backup *backup, struct chunk *chunk,
                                 struct gzuncat *gzuc, unsigned level);
static int verify_mailbox_links(struct backup *backup);
static int verify_message_guids(struct backup *backup);

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

    if (!r && (level & BACKUP_VERIFY_LAST_CHECKSUM))
        r = verify_chunk_checksums(backup, chunk_list.head);

    if (level > BACKUP_VERIFY_LAST_CHECKSUM) {
        gzuc = gzuc_open(backup->fd);
        if (!gzuc) {
            r = -1;
            goto done;
        }

        struct chunk *chunk = chunk_list.head;
        while (!r && chunk) {
            r = gzuc_member_start_from(gzuc, chunk->offset);

            if (!r && (level & BACKUP_VERIFY_ALL_CHECKSUMS))
                r = verify_chunk_checksums(backup, chunk);

            if (!r && (level & BACKUP_VERIFY_MESSAGES))
                r = verify_chunk_messages(backup, chunk, gzuc, level);

            if (!r)
                r = gzuc_member_end(gzuc, NULL);

            chunk = chunk->next;
        }
    }

    if (!r && (level & BACKUP_VERIFY_MAILBOX_LINKS))
        r = verify_mailbox_links(backup);

    if (!r && (level & BACKUP_VERIFY_MESSAGE_GUIDS))
        r = verify_message_guids(backup);

done:
    if (gzuc) gzuc_close(&gzuc);
    chunk_list_empty(&chunk_list);
    return r;
}

static int verify_chunk_checksums(struct backup *backup, struct chunk *chunk)
{
    struct gzuncat *gzuc = NULL;
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
    gzuc = gzuc_open(backup->fd);
    if (!gzuc) {
        r = -1;
        goto done;
    }

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
    if (gzuc) gzuc_close(&gzuc);
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
};

static int _verify_message_links_cb(const struct backup_message *message,
                                    void *rock)
{
    struct verify_message_rock *vmrock = (struct verify_message_rock *) rock;
    int r;

    /* FIXME - this algorithm is nasty
     * each MESSAGE line in the data stream that contains multiple
     * messages within it is going to result in the data preceding
     * it being decompressed n times, due to the repeated
     * gzuc_seekto's to read the same dlist over and over again
     */
    r = gzuc_seekto(vmrock->gzuc, message->offset);
    if (r) goto done;

    struct protstream *ps = prot_readcb(_prot_fill_cb, vmrock->gzuc);
    prot_setisclient(ps, 1); /* don't sync literals */

    struct dlist *dl = NULL;
    struct dlist *di = NULL;

    r = _parse_line(ps, NULL, NULL, &dl);
    if (r == EOF) goto done;

    r = strcmp(dl->name, "MESSAGE");
    if (r) goto done;

    r = -1;
    for (di = dl->head; di; di = di->next) {
        if (di->type != DL_SFILE)
            continue;

        r = message_guid_cmp(di->gval, message->guid);
        if (!r)
            break;
    }

done:
    if (dl) dlist_free(&dl);
    if (ps) prot_free(ps);

    return r;
}

/* verify that each message exists within the chunk the index claims */
static int verify_chunk_messages(struct backup *backup, struct chunk *chunk,
                                 struct gzuncat *gzuc, unsigned level)
{
    struct verify_message_rock vmrock = {
        gzuc,
        (level & BACKUP_VERIFY_MESSAGE_GUIDS),
    };

    int r = backup_message_foreach(backup, chunk->id, _verify_message_links_cb,
                                   &vmrock);

    fprintf(stderr, "%s: chunk %d %s!\n", __func__, chunk->id,
            r ? "failed" : "passed");
    return r;
}

/* verify that the matching MAILBOX exists within the claimed chunk
 * for each mailbox or mailbox_message in the index
 */
static int verify_mailbox_links(struct backup *backup)
{
    /*
     * get list of chunks
     * foreach chunk
     *   get list of mailboxes in chunk
     *   get list of mailbox_messages in chunk
     *   open chunk
     *   foreach line in chunk
     *     read dlist
     *     if it's a mailbox with records and it matches
     *       remove from mailbox_message list
     *       remove from mailbox_list
     *     if it's a mailbox and it matches
     *       remove from mailbox list
     *   failed if either list of mailboxes or list of mailbox_messages is not empty
     */

    /* FIXME write this */
    fprintf(stderr, "%s: not implemented\n", __func__);
    (void) backup;
    return 0;
}

/* verify that each message's on-disk data matches its recorded guid */
static int verify_message_guids(struct backup *backup)
{
    /*
     * get list of chunks
     * foreach chunk
     *   get list of messages in chunk
     *   open chunk
     *   foreach message
     *     seek to message offset
     *     read dlist
     *     look for matching guid in dlist
     *     re-calculate guid from content
     *       failed if doesn't match
     *
     * (probably dedup with verify_message_links...)
     */

    /* FIXME write this */
    fprintf(stderr, "%s: not implemented\n", __func__);
    (void) backup;
    return 0;
}
