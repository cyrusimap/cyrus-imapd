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
    struct backup_chunk *chunk = NULL;
    struct gzuncat *gzuc = NULL;
    struct dlist *dl = NULL;
    struct dlist *di;
    int r;

    chunk = backup_get_chunk(backup, message->chunk_id);
    if (!chunk) return -1;

    gzuc = gzuc_new(backup->fd);

    gzuc_member_start_from(gzuc, chunk->offset);
    r = gzuc_seekto(gzuc, message->offset);
    if (r) return r;

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

            buf_init_mmap(&buf, 1, fd, fname, MAP_UNKNOWN_LEN, NULL);
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
