/* lcb_read.c -- replication-based backup api - read functions
 *
 * Copyright (c) 1994-2016 Carnegie Mellon University.  All rights reserved.
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
#include "lib/map.h"
#include "lib/prot.h"
#include "lib/util.h"

#include "imap/imap_err.h"

#include "backup/backup.h"

#define LIBCYRUS_BACKUP_SOURCE /* this file is part of libcyrus_backup */
#include "backup/lcb_internal.h"
#include "backup/lcb_sqlconsts.h"

static ssize_t _prot_fill_cb(unsigned char *buf, size_t len, void *rock)
{
    struct gzuncat *gzuc = (struct gzuncat *) rock;
    return gzuc_read(gzuc, buf, len);
}

EXPORTED int backup_read_chunk_data(struct backup *backup,
                                    const struct backup_chunk *chunk,
                                    backup_read_data_cb proc, void *rock)
{
    struct gzuncat *gzuc = NULL;
    struct buf buf = BUF_INITIALIZER;
    int r = 0;

    gzuc = gzuc_new(backup->fd);

    gzuc_member_start_from(gzuc, chunk->offset);

    while (!gzuc_member_eof(gzuc)) {
        char tmp[8192]; /* FIXME whatever */
        ssize_t n = gzuc_read(gzuc, tmp, sizeof(tmp));
        if (n <= 0)
            break;

        buf_setmap(&buf, tmp, n);

        r = proc(&buf, rock);

        buf_reset(&buf);
    }
    gzuc_member_end(gzuc, NULL);

    gzuc_free(&gzuc);
    buf_free(&buf);
    return r;
}

EXPORTED int backup_read_message_data(struct backup *backup,
                                      const struct backup_message *message,
                                      backup_read_data_cb proc, void *rock)
{
    struct dlist *dl = NULL;
    struct dlist *di;
    int r;

    struct backup_chunk *chunk = backup_get_chunk(backup, message->chunk_id);
    if (!chunk) return -1;

    struct gzuncat *gzuc = gzuc_new(backup->fd);

    gzuc_member_start_from(gzuc, chunk->offset);
    r = gzuc_seekto(gzuc, message->offset);
    if (r) {
        gzuc_member_end(gzuc, NULL);
        gzuc_free(&gzuc);

        return r;
    }

    struct protstream *ps = prot_readcb(_prot_fill_cb, gzuc);
    prot_setisclient(ps, 1); /* don't sync literals */
    r = parse_backup_line(ps, NULL, NULL, &dl);
    prot_free(ps);

    gzuc_member_end(gzuc, NULL);
    gzuc_free(&gzuc);

    for (di = dl->head; di; di = di->next) {
        struct message_guid *guid = NULL;
        const char *fname = NULL;
        int fd;

        if (!dlist_tofile(di, NULL, &guid, NULL, &fname))
            continue;

        if (!message_guid_equal(message->guid, guid))
            continue;

        fd = open(fname, O_RDWR);
        if (fd != -1) {
            struct buf buf = BUF_INITIALIZER;

            buf_refresh_mmap(&buf, 1, fd, fname, MAP_UNKNOWN_LEN, NULL);
            close(fd);

            r = proc(&buf, rock);

            buf_free(&buf);
        }

        break;
    }

    dlist_unlink_files(dl);
    dlist_free(&dl);

    backup_chunk_free(&chunk);

    return r;
}

/* we can't link against imap/sync_support.c within the backup library,
 * so we need this nasty workaround where the caller provides a
 * pointer to sync_msgid_lookup for us to use.
 */
EXPORTED int backup_prepare_message_upload(struct backup *backup,
                                           const char *partition,
                                           struct sync_msgid_list *msgid_list,
                                           sync_msgid_lookup_func msgid_lookup,
                                           struct dlist **uploadp)
{
    struct dlist *upload = NULL;
    struct sync_msgid *msgid = NULL;
    struct gzuncat *gzuc = NULL;
    int r;

    /* nothing to do */
    if (!uploadp) return 0;

    upload = dlist_newlist(NULL, "MESSAGE");

    gzuc = gzuc_new(backup->fd);

    for (msgid = msgid_list->head; msgid; msgid = msgid->next) {
        struct backup_message *message = NULL;
        struct backup_chunk *chunk = NULL;
        struct dlist *dl = NULL;
        struct dlist *di, *next;

        /* already uploaded */
        if (!msgid->need_upload) continue;

        message = backup_get_message(backup, &msgid->guid);
        if (!message) {
            syslog(LOG_ERR, "%s: couldn't find message %s in backup %s",
                   __func__,
                   message_guid_encode(&msgid->guid),
                   backup->data_fname);
            goto next_msgid;
        }

        chunk = backup_get_chunk(backup, message->chunk_id);
        if (!chunk) goto next_msgid;

        /* read message contents from backup */
        gzuc_member_start_from(gzuc, chunk->offset);
        r = gzuc_seekto(gzuc, message->offset);
        if (!r) {
            struct protstream *ps = prot_readcb(_prot_fill_cb, gzuc);
            int c;
            prot_setisclient(ps, 1); /* don't sync literals */
            c = parse_backup_line(ps, NULL, NULL, &dl);
            prot_free(ps);
            ps = NULL;
            if (c == EOF) {
                xsyslog(LOG_ERR, "IOERROR: parse_backup_line failed",
                                 "guid=<%s> chunk=<%d> backup=<%s>",
                                 message_guid_encode(&msgid->guid),
                                 chunk->id,
                                 backup->data_fname);
                r = IMAP_IOERROR;
            }
        }
        gzuc_member_end(gzuc, NULL);
        if (r) goto next_msgid;

        /* A single backup line contains many messages, so process
         * them all while they're already decompressed.
         * Tricksy loop construct so we can unstitch safely.
         */
        next = dl->head;
        while ((di = next)) {
            struct message_guid *guid = NULL;
            struct sync_msgid *found_msgid = NULL;

            next = di->next;

            if (!dlist_tofile(di, NULL, &guid, NULL, NULL))
                continue;

            found_msgid = msgid_lookup(msgid_list, guid);
            if (!found_msgid)
                continue;

            /* found one we want, move to upload list */
            dlist_unstitch(dl, di);
            dlist_stitch(upload, di);

            /* set the destination partition */
            if (di->part) free(di->part);
            di->part = xstrdup(partition);

            /* flag that we're sending it */
            found_msgid->need_upload = 0;
            msgid_list->toupload--;
        }

next_msgid:
        if (dl) {
            dlist_unlink_files(dl);
            dlist_free(&dl);
        }

        if (chunk) backup_chunk_free(&chunk);
        if (message) backup_message_free(&message);
    }

    if (gzuc) gzuc_free(&gzuc);

    *uploadp = upload;
    return 0;
}
