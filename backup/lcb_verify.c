/* lcb_verify.c -- replication-based backup api - verify functions
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
#include <syslog.h>

#include "lib/gzuncat.h"
#include "lib/hash.h"
#include "lib/map.h"
#include "lib/xmalloc.h"
#include "lib/xsha1.h"

#include "backup/backup.h"

#define LIBCYRUS_BACKUP_SOURCE /* this file is part of libcyrus_backup */
#include "backup/lcb_internal.h"
#include "backup/lcb_sqlconsts.h"

static int verify_chunk_checksums(struct backup *backup, struct backup_chunk *chunk,
                                  struct gzuncat *gzuc, int verbose,
                                  FILE *out);
static int verify_chunk_messages(struct backup *backup, struct backup_chunk *chunk,
                                 struct gzuncat *gzuc, unsigned level,
                                 int verbose, FILE *out);
static int verify_chunk_mailbox_links(struct backup *backup, struct backup_chunk *chunk,
                                      struct gzuncat *gzuc, int verbose,
                                      FILE *out);

EXPORTED int backup_verify(struct backup *backup, unsigned level, int verbose, FILE *out)
{
    struct backup_chunk_list *chunk_list = NULL;
    struct gzuncat *gzuc = NULL;
    int r = 0;

    /* don't double-verify last checksum when verifying all */
    if ((level & BACKUP_VERIFY_ALL_CHECKSUMS))
        level &= ~BACKUP_VERIFY_LAST_CHECKSUM;

    /* don't double-verify message links when verifying message guids */
    if ((level & BACKUP_VERIFY_MESSAGE_GUIDS))
        level &= ~BACKUP_VERIFY_MESSAGE_LINKS;

    chunk_list = backup_get_chunks(backup);
    if (!chunk_list || !chunk_list->count) goto done;

    gzuc = gzuc_new(backup->fd);
    if (!gzuc) {
        r = -1;
        goto done;
    }

    if (!r && (level & BACKUP_VERIFY_LAST_CHECKSUM))
        r = verify_chunk_checksums(backup, chunk_list->tail, gzuc, verbose, out);

    if (!r && level > BACKUP_VERIFY_LAST_CHECKSUM) {
        struct backup_chunk *chunk = chunk_list->head;
        while (!r && chunk) {
            if (!r && (level & BACKUP_VERIFY_ALL_CHECKSUMS))
                r = verify_chunk_checksums(backup, chunk, gzuc, verbose, out);

            if (!r && (level & BACKUP_VERIFY_MESSAGES))
                r = verify_chunk_messages(backup, chunk, gzuc, level, verbose, out);

            if (!r && (level & BACKUP_VERIFY_MAILBOX_LINKS))
                r = verify_chunk_mailbox_links(backup, chunk, gzuc, verbose, out);

            chunk = chunk->next;
        }
    }

done:
    if (gzuc) gzuc_free(&gzuc);
    if (chunk_list) backup_chunk_list_free(&chunk_list);
    return r;
}

static int verify_chunk_checksums(struct backup *backup, struct backup_chunk *chunk,
                                  struct gzuncat *gzuc, int verbose, FILE *out)
{
    int r;
    char file_sha1[2 * SHA1_DIGEST_LENGTH + 1];
    char buf[8192]; /* FIXME whatever */
    size_t len = 0;
    SHA_CTX sha_ctx;
    unsigned char sha1_raw[SHA1_DIGEST_LENGTH];
    char data_sha1[2 * SHA1_DIGEST_LENGTH + 1];

    if (out && verbose)
        fprintf(out, "checking chunk %d checksums...\n", chunk->id);

    /* validate file-prior-to-this-chunk checksum */
    if (out && verbose > 1)
        fprintf(out, "  checking file checksum...\n");
    sha1_file(backup->fd, backup->data_fname, chunk->offset, file_sha1);
    r = strncmp(chunk->file_sha1, file_sha1, sizeof(file_sha1));
    if (r) {
        syslog(LOG_DEBUG, "%s: %s (chunk %d) file checksum mismatch: %s on disk, %s in index\n",
                __func__, backup->data_fname, chunk->id, file_sha1, chunk->file_sha1);
        if (out)
            fprintf(out, "file checksum mismatch for chunk %d: %s on disk, %s in index\n",
                    chunk->id, file_sha1, chunk->file_sha1);
        goto done;
    }

    /* validate data-within-this-chunk checksum */
    // FIXME length and data_sha1 are set at backup_append_end.
    //       detect and correctly report case where this hasn't occurred.
    if (out && verbose > 1)
        fprintf(out, "  checking data length\n");
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
        syslog(LOG_DEBUG, "%s: %s (chunk %d) data length mismatch: "
                        SIZE_T_FMT " on disk,"
                        SIZE_T_FMT " in index\n",
                __func__, backup->data_fname, chunk->id, len, chunk->length);
        if (out)
            fprintf(out, "data length mismatch for chunk %d: "
                         SIZE_T_FMT " on disk,"
                         SIZE_T_FMT " in index\n",
                    chunk->id, len, chunk->length);
        r = -1;
        goto done;
    }

    if (out && verbose > 1)
        fprintf(out, "  checking data checksum...\n");
    SHA1_Final(sha1_raw, &sha_ctx);
    r = bin_to_hex(sha1_raw, SHA1_DIGEST_LENGTH, data_sha1, BH_LOWER);
    assert(r == 2 * SHA1_DIGEST_LENGTH);
    r = strncmp(chunk->data_sha1, data_sha1, sizeof(data_sha1));
    if (r) {
        syslog(LOG_DEBUG, "%s: %s (chunk %d) data checksum mismatch: %s on disk, %s in index\n",
                __func__, backup->data_fname, chunk->id, data_sha1, chunk->data_sha1);
        if (out)
            fprintf(out, "data checksum mismatch for chunk %d: %s on disk, %s in index\n",
                    chunk->id, data_sha1, chunk->data_sha1);
        goto done;
    }

done:
    syslog(LOG_DEBUG, "%s: checksum %s!\n", __func__, r ? "failed" : "passed");
    if (out && verbose)
        fprintf(out, "%s\n", r ? "error" : "ok");
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
    int verbose;
    FILE *out;
};

static int _verify_message_cb(const struct backup_message *message, void *rock)
{
    struct verify_message_rock *vmrock = (struct verify_message_rock *) rock;
    struct dlist *dl = NULL;
    struct dlist *di = NULL;
    FILE *out = vmrock->out;
    int r;

    /* cache the dlist so that multiple reads from the same offset don't
     * cause expensive reverse seeks in decompression stream
     */
    if (!vmrock->cached_dlist || vmrock->cached_offset != message->offset) {
        struct protstream *ps;

        if (vmrock->cached_dlist) {
            dlist_unlink_files(vmrock->cached_dlist);
            dlist_free(&vmrock->cached_dlist);
        }

        r = gzuc_seekto(vmrock->gzuc, message->offset);
        if (r) return r;

        ps = prot_readcb(_prot_fill_cb, vmrock->gzuc);
        prot_setisclient(ps, 1); /* don't sync literals */
        r = parse_backup_line(ps, NULL, NULL, &dl);

        if (r == EOF) {
            const char *error = prot_error(ps);
            if (error && 0 != strcmp(error, PROT_EOF_STRING)) {
                syslog(LOG_ERR,
                       "%s: error reading message %i at offset " OFF_T_FMT ", byte %i: %s",
                       __func__, message->id, message->offset, prot_bytes_in(ps), error);
                if (out)
                    fprintf(out, "error reading message %i at offset " OFF_T_FMT ", byte %i: %s",
                            message->id, message->offset, prot_bytes_in(ps), error);
            }
            prot_free(ps);
            return r;
        }

        prot_free(ps);

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
        struct message_guid *guid = NULL;
        const char *fname = NULL;

        if (!dlist_tofile(di, NULL, &guid, NULL, &fname))
            continue;

        r = message_guid_cmp(guid, message->guid);
        if (!r) {
            if (vmrock->verify_guid) {
                const char *msg_base = NULL;
                size_t msg_len = 0;
                struct message_guid computed_guid;
                int fd;

                fd = open(fname, O_RDWR);
                if (fd != -1) {
                    map_refresh(fd, 1, &msg_base, &msg_len, MAP_UNKNOWN_LEN, fname, NULL);

                    message_guid_generate(&computed_guid, msg_base, msg_len);
                    r = message_guid_cmp(&computed_guid, message->guid);
                    if (r && out)
                        fprintf(out, "guid mismatch for message %i\n", message->id);

                    map_free(&msg_base, &msg_len);
                    close(fd);
                }
                else {
                    syslog(LOG_ERR, "IOERROR: %s open %s: %m", __func__, fname);
                    if (out)
                        fprintf(out, "error reading staging file for message %i\n", message->id);
                    r = -1;
                }
            }
            break;
        }
    }

    return r;
}

/* verify that each message exists within the chunk the index claims */
static int verify_chunk_messages(struct backup *backup, struct backup_chunk *chunk,
                                 struct gzuncat *gzuc, unsigned level,
                                 int verbose, FILE *out)
{
    int r;

    struct verify_message_rock vmrock = {
        gzuc,
        (level & BACKUP_VERIFY_MESSAGE_GUIDS),
        NULL,
        0,
        verbose,
        out,
    };

    if (out && verbose)
        fprintf(out, "checking chunk %d messages...\n", chunk->id);

    r = gzuc_member_start_from(gzuc, chunk->offset);
    if (!r) {
        r = backup_message_foreach(backup, chunk->id, NULL,
                                   _verify_message_cb, &vmrock);
        gzuc_member_end(gzuc, NULL);
    }

    if (vmrock.cached_dlist) {
        dlist_unlink_files(vmrock.cached_dlist);
        dlist_free(&vmrock.cached_dlist);
    }

    syslog(LOG_DEBUG, "%s: chunk %d %s!\n", __func__, chunk->id,
            r ? "failed" : "passed");
    if (out && verbose)
        fprintf(out, "%s\n", r ? "error" : "ok");

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

    syslog(LOG_DEBUG, "%s: %s matches!\n", __func__, mailbox->uniqueid);
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
        || (time_t) last_updated != mailbox_message->last_updated)
        return 0;

    if (!dlist_getnum32(dlist, "INTERNALDATE", &internaldate)
        || (time_t) internaldate != mailbox_message->internaldate)
        return 0;

    if (!dlist_getnum32(dlist, "SIZE", &size)
        || size != mailbox_message->size)
        return 0;

    if (!dlist_getguid(dlist, "GUID", &guid)
        || !message_guid_equal(guid, &mailbox_message->guid))
        return 0;

    syslog(LOG_DEBUG, "%s: %s:%u matches!\n", __func__,
            mailbox_message->mailbox_uniqueid, mailbox_message->uid);
    return 1;
}

/* verify that the matching MAILBOX exists within the claimed chunk
 * for each mailbox or mailbox_message in the index
 */
static int verify_chunk_mailbox_links(struct backup *backup, struct backup_chunk *chunk,
                                      struct gzuncat *gzuc, int verbose, FILE *out)
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
    struct protstream *ps;
    struct buf cmd = BUF_INITIALIZER;

    if (out && verbose)
        fprintf(out, "checking chunk %d mailbox links...\n", chunk->id);

    mailbox_list = backup_get_mailboxes(backup, chunk->id, BACKUP_MAILBOX_NO_RECORDS);
    mailbox_message_list = backup_get_mailbox_messages(backup, chunk->id);

    if (mailbox_list->count == 0 && mailbox_message_list->count == 0) {
        /* nothing we care about in this chunk */
        free(mailbox_list);
        free(mailbox_message_list);
        if (out && verbose)
            fprintf(out, "ok\n");
        return 0;
    }

    /* XXX consider whether the two hashes should use pools */

    if (mailbox_list->count) {
        /* build an index of the mailbox list */
        construct_hash_table(&mailbox_list_index, mailbox_list->count, 0);
        mailbox = mailbox_list->head;
        while (mailbox) {
            hash_insert(mailbox->uniqueid, mailbox, &mailbox_list_index);
            mailbox = mailbox->next;
        }
    }

    if (mailbox_message_list->count) {
        /* build an index of the mailbox message list */
        construct_hash_table(&mailbox_message_list_index,
                             mailbox_message_list->count, 0);
        mailbox_message = mailbox_message_list->head;
        while (mailbox_message) {
            char keybuf[1024]; // FIXME whatever
            snprintf(keybuf, sizeof(keybuf), "%s:%d",
                     mailbox_message->mailbox_uniqueid, mailbox_message->uid);
            hash_insert(keybuf, mailbox_message, &mailbox_message_list_index);
            mailbox_message = mailbox_message->next;
        }
    }

    r = gzuc_member_start_from(gzuc, chunk->offset);
    if (r) {
        syslog(LOG_ERR, "%s: error reading chunk %i at offset " OFF_T_FMT ": %s",
                        __func__, chunk->id, chunk->offset, zError(r));
        if (out)
            fprintf(out, "error reading chunk %i at offset " OFF_T_FMT ": %s",
                    chunk->id, chunk->offset, zError(r));
        goto done;
    }
    ps = prot_readcb(_prot_fill_cb, gzuc);
    prot_setisclient(ps, 1); /* don't sync literals */

    while (1) {
        struct dlist *dl = NULL;
        struct dlist *record = NULL;
        struct dlist *di = NULL;
        const char *uniqueid = NULL;

        int c = parse_backup_line(ps, NULL, &cmd, &dl);
        if (c == EOF) {
            const char *error = prot_error(ps);
            if (error && 0 != strcmp(error, PROT_EOF_STRING)) {
                syslog(LOG_ERR,
                       "%s: error reading chunk %i data at offset " OFF_T_FMT ", byte %i: %s",
                       __func__, chunk->id, chunk->offset, prot_bytes_in(ps), error);
                if (out)
                    fprintf(out, "error reading chunk %i data at offset " OFF_T_FMT ", byte %i: %s",
                            chunk->id, chunk->offset, prot_bytes_in(ps), error);
                r = EOF;
            }
            break;
        }

        if (strcmp(buf_cstring(&cmd), "APPLY") != 0)
            goto next_line;

        if (strcmp(dl->name, "MAILBOX") != 0)
            goto next_line;

        if (!dlist_getatom(dl, "UNIQUEID", &uniqueid))
            goto next_line;

        if (mailbox_list->count) {
            mailbox = (struct backup_mailbox *) hash_lookup(uniqueid, &mailbox_list_index);

            if (mailbox && mailbox_matches(mailbox, dl)) {
                backup_mailbox_list_remove(mailbox_list, mailbox);
                hash_del(uniqueid, &mailbox_list_index);
                backup_mailbox_free(&mailbox);
            }
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
        if (dl) {
            dlist_unlink_files(dl);
            dlist_free(&dl);
        }
    }
    buf_free(&cmd);

    prot_free(ps);
    gzuc_member_end(gzuc, NULL);

    /* anything left in either of the lists is missing from the chunk data. bad! */
    mailbox = mailbox_list->head;
    while (mailbox) {
        syslog(LOG_DEBUG, "%s: chunk %d missing mailbox data for %s (%s)\n",
                __func__, chunk->id, mailbox->uniqueid, mailbox->mboxname);
        if (out)
            fprintf(out, "chunk %d missing mailbox data for %s (%s)\n",
                    chunk->id, mailbox->uniqueid, mailbox->mboxname);
        mailbox = mailbox->next;
    }

    mailbox_message = mailbox_message_list->head;
    while (mailbox_message) {
        syslog(LOG_DEBUG, "%s: chunk %d missing mailbox_message data for %s uid %u\n",
                __func__, chunk->id, mailbox_message->mailbox_uniqueid,
                mailbox_message->uid);
        if (out)
            fprintf(out, "chunk %d missing mailbox_message data for %s uid %u\n",
                    chunk->id, mailbox_message->mailbox_uniqueid,
                    mailbox_message->uid);
        mailbox_message = mailbox_message->next;
    }

    if (!r) r = mailbox_list->count || mailbox_message_list->count ? -1 : 0;

done:
    free_hash_table(&mailbox_list_index, NULL);
    free_hash_table(&mailbox_message_list_index, NULL);

    backup_mailbox_list_empty(mailbox_list);
    free(mailbox_list);

    backup_mailbox_message_list_empty(mailbox_message_list);
    free(mailbox_message_list);

    syslog(LOG_DEBUG, "%s: chunk %d %s!\n", __func__, chunk->id,
            r ? "failed" : "passed");
    if (out && verbose)
        fprintf(out, "%s\n", r ? "error" : "ok");
    return r;
}
