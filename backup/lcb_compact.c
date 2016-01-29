/* lcb_compact.c -- replication-based backup api - backup compaction
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
#include <config.h>

#include <assert.h>
#include <syslog.h>

#include "lib/gzuncat.h"
#include "lib/libconfig.h"

#include "imap/imap_err.h"

#include "backup/backup.h"

#define LIBCYRUS_BACKUP_SOURCE /* this file is part of libcyrus_backup */
#include "backup/lcb_internal.h"
#include "backup/lcb_sqlconsts.h"

static int compact_open(const char *name,
                        struct backup **originalp,
                        struct backup **compactp,
                        enum backup_open_nonblock nonblock)
{
    struct backup *original = NULL;
    struct backup *compact = NULL;

    struct buf original_data_fname = BUF_INITIALIZER;
    struct buf original_index_fname = BUF_INITIALIZER;
    struct buf compact_data_fname = BUF_INITIALIZER;
    struct buf compact_index_fname = BUF_INITIALIZER;

    int r;

    buf_printf(&original_data_fname, "%s", name);
    buf_printf(&original_index_fname, "%s.index", name);
    buf_printf(&compact_data_fname, "%s.new", name);
    buf_printf(&compact_index_fname, "%s.index.new", name);

    r = backup_real_open(&original,
                         buf_cstring(&original_data_fname),
                         buf_cstring(&original_index_fname),
                         BACKUP_OPEN_NOREINDEX,
                         nonblock,
                         BACKUP_OPEN_NOCREATE);
    if (r) goto done;

    r = backup_real_open(&compact,
                         buf_cstring(&compact_data_fname),
                         buf_cstring(&compact_index_fname),
                         BACKUP_OPEN_NOREINDEX,
                         BACKUP_OPEN_NONBLOCK, // FIXME think about this
                         BACKUP_OPEN_CREATE_EXCL);
    if (r) {
        backup_close(&original);
        goto done;
    }

    *originalp = original;
    *compactp = compact;

done:
    buf_free(&original_data_fname);
    buf_free(&original_index_fname);
    buf_free(&compact_data_fname);
    buf_free(&compact_index_fname);

    return r;
}

static int compact_closerename(struct backup **originalp,
                               struct backup **compactp,
                               time_t now)
{
    struct backup *original = *originalp;
    struct backup *compact = *compactp;
    struct buf ts_data_fname = BUF_INITIALIZER;
    struct buf ts_index_fname = BUF_INITIALIZER;
    int r;

    buf_printf(&ts_data_fname, "%s.%ld", original->data_fname, now);
    buf_printf(&ts_index_fname, "%s.%ld", original->index_fname, now);

    /* link original files into timestamped names */
    r = link(original->data_fname, buf_cstring(&ts_data_fname));
    if (!r) link(original->index_fname, buf_cstring(&ts_index_fname));

    if (r) {
        /* on error, trash the new links and bail out */
        unlink(buf_cstring(&ts_data_fname));
        unlink(buf_cstring(&ts_index_fname));
        goto done;
    }

    /* replace original files with compacted files */
    r = rename(compact->data_fname, original->data_fname);
    if (!r) r = rename(compact->index_fname, original->index_fname);

    if (r) {
        /* on error, put original files back */
        unlink(original->data_fname);
        unlink(original->index_fname);
        link(buf_cstring(&ts_data_fname), original->data_fname);
        link(buf_cstring(&ts_index_fname), original->index_fname);
    }

    /* release our locks */
    backup_close(originalp);
    backup_close(compactp);

done:
    buf_free(&ts_data_fname);
    buf_free(&ts_index_fname);
    return r;
}

static int compact_required(struct backup_chunk_list *chunk_list)
{
    /* FIXME look for chunks that would benefit from compaction */
    (void) chunk_list;
    return 1;
}

static ssize_t _prot_fill_cb(unsigned char *buf, size_t len, void *rock)
{
    struct gzuncat *gzuc = (struct gzuncat *) rock;
    int r = gzuc_read(gzuc, buf, len);

    if (r < 0)
        syslog(LOG_ERR, "IOERROR: gzuc_read returned %i", r);
    if (r < -1)
        errno = EIO;

    return r;
}

/* returns:
 *   0 on success
 *   1 if compact was not needed
 *   negative on error
 */
EXPORTED int backup_compact(const char *name,
                            enum backup_open_nonblock nonblock,
                            int force, int verbose, FILE *out)
{
    struct backup *original = NULL;
    struct backup *compact = NULL;
    struct backup_chunk_list *keep_chunks = NULL;
    struct backup_chunk *chunk = NULL;
    struct gzuncat *gzuc = NULL;
    struct protstream *in = NULL;
    time_t since, chunk_start_time, ts;
    int r;

    r = compact_open(name, &original, &compact, nonblock);
    if (r) return r;

    /* calculate current time after obtaining locks, in case of a wait */
    const time_t now = time(NULL);

    const int retention_days = config_getint(IMAPOPT_BACKUP_RETENTION_DAYS);
    if (retention_days > 0) {
        since = now - (retention_days * 24 * 60 * 60);
    }
    else {
        /* zero or negative retention days means "keep forever" */
        since = -1;
    }

    keep_chunks = backup_get_live_chunks(original, since);
    if (!keep_chunks) goto error;

    if (!force && !compact_required(keep_chunks)) {
        /* nothing to do */
        backup_chunk_list_free(&keep_chunks);
        backup_unlink(&compact);
        backup_close(&original);
        return 1;
    }

    if (verbose) {
        fprintf(out, "keeping " SIZE_T_FMT " chunks:\n", keep_chunks->count);

        for (chunk = keep_chunks->head; chunk; chunk = chunk->next) {
            fprintf(out, " %d", chunk->id);
        }

        fprintf(out, "\n");
    }

    gzuc = gzuc_new(original->fd);
    if (!gzuc) goto error;

    chunk_start_time = -1;
    ts = 0;
    struct buf cmd = BUF_INITIALIZER;
    for (chunk = keep_chunks->head; chunk; chunk = chunk->next) {
        gzuc_member_start_from(gzuc, chunk->offset);

        in = prot_readcb(_prot_fill_cb, gzuc);

        while (1) {
            struct dlist *dl = NULL;

            int c = parse_backup_line(in, &ts, &cmd, &dl);

            if (c == EOF) {
                const char *error = prot_error(in);
                if (error && 0 != strcmp(error, PROT_EOF_STRING)) {
                    syslog(LOG_ERR,
                           "IOERROR: %s: error reading chunk at offset %jd, byte %i: %s\n",
                           name, chunk->offset, prot_bytes_in(in), error);

                    if (out)
                        fprintf(out, "error reading chunk at offset %jd, byte %i: %s\n",
                                chunk->offset, prot_bytes_in(in), error);

                    r = IMAP_IOERROR;
                    goto error;
                }

                break;
            }

            if (chunk_start_time == -1) {
                r = backup_append_start(compact, &ts, BACKUP_APPEND_NOFLUSH);
                if (r) goto error;
                chunk_start_time = ts;
            }

            // XXX if this line is worth keeping
            if (1) {
                // FIXME if message is removed due to unneeded chunk,
                // subsequent mailbox lines for it will fail here
                // so we need to be able to tell which lines apply to messages we don't want anymore
                r = backup_append(compact, dl, &ts, BACKUP_APPEND_NOFLUSH);
                if (r) goto error;
            }

            dlist_unlink_files(dl);
            dlist_free(&dl);
        }

        // XXX if we're due to start a new chunk
        if (1) {
            r = backup_append_end(compact, &ts);
            chunk_start_time = -1;
        }

        prot_free(in);
        in = NULL;
        gzuc_member_end(gzuc, NULL);
    }
    buf_free(&cmd);

    if (compact->append_state && compact->append_state->mode)
        backup_append_end(compact, &ts);

    gzuc_free(&gzuc);

    backup_chunk_list_free(&keep_chunks);

    /* if we get here okay, then the compact succeeded */
    r = compact_closerename(&original, &compact, now);
    if (r) goto error;

    return 0;

error:
    if (in) prot_free(in);
    if (gzuc) gzuc_free(&gzuc);
    if (keep_chunks) backup_chunk_list_free(&keep_chunks);
    if (compact) backup_unlink(&compact);
    if (original) backup_close(&original);

    return r ? r : -1;
}
