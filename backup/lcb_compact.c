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
#include <errno.h>
#include <syslog.h>

#include "lib/gzuncat.h"
#include "lib/libconfig.h"

#include "imap/imap_err.h"
#include "imap/sync_support.h"

#include "backup/backup.h"

#define LIBCYRUS_BACKUP_SOURCE /* this file is part of libcyrus_backup */
#include "backup/lcb_internal.h"
#include "backup/lcb_sqlconsts.h"

static size_t compact_minsize = 0;
static size_t compact_maxsize = 0;
static int compact_work_threshold = 0;

static void compact_readconfig(void)
{
    /* read and normalise config values */
    if (compact_minsize == 0) {
        compact_minsize = (size_t)
            MAX(0, 1024 * config_getint(IMAPOPT_BACKUP_COMPACT_MINSIZE));
    }

    if (compact_maxsize == 0) {
        compact_maxsize = (size_t)
            MAX(0, 1024 * config_getint(IMAPOPT_BACKUP_COMPACT_MAXSIZE));
    }

    if (compact_work_threshold == 0) {
        compact_work_threshold =
            MAX(1, config_getint(IMAPOPT_BACKUP_COMPACT_WORK_THRESHOLD));
    }
}

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
    if (!r) r = link(original->index_fname, buf_cstring(&ts_index_fname));

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
        if (link(buf_cstring(&ts_data_fname), original->data_fname))
            syslog(LOG_ERR, "IOERROR: failed to link file back (%s %s)!", buf_cstring(&ts_data_fname), original->data_fname);
        if (link(buf_cstring(&ts_index_fname), original->index_fname))
            syslog(LOG_ERR, "IOERROR: failed to link file back (%s %s)!", buf_cstring(&ts_index_fname), original->index_fname);
        goto done;
    }

    /* finally, clean up the timestamped ones */
    if (!config_getswitch(IMAPOPT_BACKUP_KEEP_PREVIOUS)) {
        unlink(buf_cstring(&ts_data_fname));
        unlink(buf_cstring(&ts_index_fname));
    }

    /* release our locks */
    backup_close(originalp);
    backup_close(compactp);

done:
    buf_free(&ts_data_fname);
    buf_free(&ts_index_fname);
    return r;
}

/* a small chunk is candidate for combining with the next
 * if the sum of their lengths is smaller than max_chunksize
 */
static int want_combine(size_t length, const struct backup_chunk *next_chunk)
{
    /* can't combine if there's no subsequent chunk */
    if (!next_chunk)
        return 0;

    /* don't combine if the chunks are both big enough already */
    if (length >= compact_minsize && next_chunk->length >= compact_minsize)
        return 0;

    /* no upper size limit, so combine them */
    if (!compact_maxsize)
        return 1;

    /* don't combine if upper size limit may be exceeded */
    if (length + next_chunk->length > compact_maxsize)
        return 0;

    /* combine */
    return 1;
}

/* a large chunk is candidate for splitting
 * if it won't create a new too-small chunk
 */
static int want_split(const struct backup_chunk *chunk, const size_t *wrotep)
{
    /* don't split if there's no maximum size */
    if (!compact_maxsize)
        return 0;

    /* don't split if we're writing and haven't written enough */
    if (wrotep && *wrotep < compact_maxsize)
        return 0;

    /* don't split if the chunk isn't long enough */
    if (chunk->length < compact_maxsize + compact_minsize)
        return 0;

    /* if we're not writing, we're done */
    if (!wrotep)
        return 1;

    /* we might have written past the desirable split boundary due to a big
     * dlist, so check whether the remainder is worth splitting for */
    size_t new_chunk_size = chunk->length - *wrotep;

    /* split if what's left is big enough to be its own chunk */
    if (new_chunk_size > compact_minsize)
        return 1;

    /* don't split it */
    return 0;
}

static int compact_required(struct backup_chunk_list *all_chunks,
                            struct backup_chunk_list *keep_chunks)
{
    struct backup_chunk *chunk;
    int to_be_compacted = 0;

    compact_readconfig();

    /* count chunks to be discarded */
    if (all_chunks->count > keep_chunks->count)
        to_be_compacted += all_chunks->count - keep_chunks->count;

    if (to_be_compacted >= compact_work_threshold)
        return 1;

    /* nothing more to do if there are no boundaries defined */
    if (!compact_minsize && !compact_maxsize)
        return 0;

    /* nothing more to do if the boundaries are contradictory */
    if (compact_minsize && compact_maxsize
        && compact_minsize >= compact_maxsize)
        return 0;

    /* count chunks to be combined/split */
    for (chunk = keep_chunks->head; chunk; chunk = chunk->next) {
        if (want_combine(chunk->length, chunk->next))
            to_be_compacted++;

        if (want_split(chunk, NULL))
            to_be_compacted++;

        if (to_be_compacted >= compact_work_threshold)
            return 1;
    }

    return 0;
}

static int want_append_message(struct dlist *dlist,
                               struct sync_msgid_list *keep_message_guids)
{
    struct dlist *di, *next;

    for (di = dlist->head; di; di = next) {
        struct message_guid *guid = NULL;

        /* save next pointer now in case we need to unstitch */
        next = di->next;

        if (!dlist_tofile(di, NULL, &guid, NULL, NULL))
            continue;

        if (!sync_msgid_lookup(keep_message_guids, guid)) {
            syslog(LOG_DEBUG, "%s: MESSAGE no longer needed: %s",
                                __func__, message_guid_encode(guid));
            dlist_unstitch(dlist, di);
            dlist_unlink_files(di);
            dlist_free(&di);
        }
    }

    if (dlist->head) {
        syslog(LOG_DEBUG, "%s: keeping MESSAGE line", __func__);
        return 1;
    }

    syslog(LOG_DEBUG, "%s: MESSAGE line has no more messages", __func__);
    return 0;
}

static int want_append_mailbox(struct backup *orig_backup,
                               int orig_chunk_id,
                               struct dlist *dlist)
{
    struct dlist *record = NULL;
    const char *uniqueid = NULL;
    struct backup_mailbox *mailbox = NULL;
    int mailbox_last_chunk_id = 0;

    if (!dlist_getatom(dlist, "UNIQUEID", &uniqueid)) {
        syslog(LOG_DEBUG, "%s: MAILBOX line with no UNIQUEID", __func__);
        return 1; /* better keep it for now */
    }

    dlist_getlist(dlist, "RECORD", &record);
    if (record && record->head) {
        struct dlist *ki = NULL, *next = NULL;
        int keep = 0;

        /* keep MAILBOX lines that contain the last RECORD for any message, */
        /* pruning out stale RECORDs */
        for (ki = record->head; ki; ki = next) {
            const char *guid = NULL;
            struct backup_mailbox_message *mailbox_message = NULL;

            /* save next pointer now in case we need to unstitch */
            next = ki->next;

            if (!dlist_getatom(ki, "GUID", &guid)) {
                syslog(LOG_DEBUG, "%s: MAILBOX RECORD with no GUID", __func__);
                keep = 1; /* better keep it for now */
                continue;
            }

            mailbox_message = backup_get_mailbox_message(orig_backup, uniqueid, guid);
            if (mailbox_message) {
                int mailbox_message_last_chunk_id = mailbox_message->last_chunk_id;
                backup_mailbox_message_free(&mailbox_message);

                if (mailbox_message_last_chunk_id == orig_chunk_id) {
                    syslog(LOG_DEBUG, "%s: keeping MAILBOX line containing last RECORD for guid %s",
                                        __func__, guid);
                    keep = 1;
                    continue;
                }
            }

            /* don't need this record */
            syslog(LOG_DEBUG, "%s: pruning stale MAILBOX RECORD for guid %s",
                              __func__, guid);
            dlist_unstitch(record, ki);
            dlist_unlink_files(ki);
            dlist_free(&ki);
        }

        if (keep) return 1;
    }

    mailbox = backup_get_mailbox_by_uniqueid(orig_backup, uniqueid,
                                             BACKUP_MAILBOX_NO_RECORDS);
    if (!mailbox) {
        /* what? */
        syslog(LOG_DEBUG, "%s: couldn't find mailbox entry for uniqueid %s", __func__, uniqueid);
        return 1; /* better keep it for now */
    }

    mailbox_last_chunk_id = mailbox->last_chunk_id;
    backup_mailbox_free(&mailbox);

    if (mailbox_last_chunk_id == orig_chunk_id) {
        /* keep all mailbox lines from the chunk recorded as its last */
        syslog(LOG_DEBUG, "%s: keeping MAILBOX line from its last known chunk", __func__);
        return 1;
    }

    syslog(LOG_DEBUG, "%s: discarding stale MAILBOX line (chunk %d, last %d, uniqueid %s)",
                        __func__, orig_chunk_id, mailbox_last_chunk_id, uniqueid);
    return 0;
}

static int want_append(struct backup *orig_backup,
                       int orig_chunk_id,
                       struct dlist *dlist,
                       struct sync_msgid_list *keep_message_guids)
{
    if (strcmp(dlist->name, "MESSAGE") == 0) {
        return want_append_message(dlist, keep_message_guids);
    }
    else if (strcmp(dlist->name, "MAILBOX") == 0) {
        return want_append_mailbox(orig_backup, orig_chunk_id, dlist);
    }
    /* FIXME detect other stale data types */
    else {
        return 1;
    }
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

static int _keep_message_guids_cb(const struct backup_message *message,
                                  void *rock)
{
    struct sync_msgid_list *list = (struct sync_msgid_list *) rock;
    sync_msgid_insert(list, message->guid);
    return 0;
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
    struct backup_chunk_list *all_chunks = NULL;
    struct backup_chunk_list *keep_chunks = NULL;
    struct backup_chunk *chunk = NULL;
    struct sync_msgid_list *keep_message_guids = NULL;
    struct gzuncat *gzuc = NULL;
    struct protstream *in = NULL;
    time_t since, chunk_start_time, ts;
    int r;

    compact_readconfig();

    r = compact_open(name, &original, &compact, nonblock);
    if (r) return r;

    /* calculate current time after obtaining locks, in case of a wait */
    const time_t now = time(NULL);

    const int retention = config_getduration(IMAPOPT_BACKUP_RETENTION, 'd');
    if (retention > 0) {
        since = now - retention;
    }
    else {
        /* zero or negative retention means "keep forever" */
        since = -1;
    }

    all_chunks = backup_get_chunks(original);
    if (!all_chunks) goto error;

    keep_chunks = backup_get_live_chunks(original, since);
    if (!keep_chunks) goto error;

    if (!force && !compact_required(all_chunks, keep_chunks)) {
        /* nothing to do */
        backup_chunk_list_free(&all_chunks);
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
        keep_message_guids = sync_msgid_list_create(0);
        r = backup_message_foreach(original, chunk->id, &since,
                                   _keep_message_guids_cb, keep_message_guids);
        if (r) goto error;

        gzuc_member_start_from(gzuc, chunk->offset);

        in = prot_readcb(_prot_fill_cb, gzuc);

        while (1) {
            struct dlist *dl = NULL;

            int c = parse_backup_line(in, &ts, &cmd, &dl);

            if (c == EOF) {
                const char *error = prot_error(in);
                if (error && 0 != strcmp(error, PROT_EOF_STRING)) {
                    syslog(LOG_ERR,
                           "IOERROR: %s: error reading chunk at offset " OFF_T_FMT ", byte %i: %s",
                           name, chunk->offset, prot_bytes_in(in), error);

                    if (out)
                        fprintf(out, "error reading chunk at offset " OFF_T_FMT ", byte %i: %s\n",
                                chunk->offset, prot_bytes_in(in), error);

                    /* chunk is corrupt, discard the rest of it and get on with
                     * the next.  the next replication will fill in anything that
                     * was lost.
                     */
                    goto next_chunk;
                }

                break;
            }

            if (chunk_start_time == -1) {
                r = backup_append_start(compact, &ts, BACKUP_APPEND_NOFLUSH);
                if (r) goto error;
                chunk_start_time = ts;
            }

            // XXX if this line is worth keeping
            if (want_append(original, chunk->id, dl, keep_message_guids)) {
                // FIXME if message is removed due to unneeded chunk,
                // subsequent mailbox lines for it will fail here
                // so we need to be able to tell which lines apply to messages we don't want anymore
                r = backup_append(compact, dl, &ts, BACKUP_APPEND_NOFLUSH);
                if (r) goto error;
            }

            dlist_unlink_files(dl);
            dlist_free(&dl);

            // if this line put us over compact_maxsize
            if (want_split(chunk, &compact->append_state->wrote)) {
                r = backup_append_end(compact, &ts);
                chunk_start_time = -1;

                if (verbose) {
                    fprintf(out, "splitting chunk %d\n", chunk->id);
                }
            }
        }
next_chunk:

        // if we're due to start a new chunk
        if (compact->append_state && compact->append_state->mode) {
            if (!want_combine(compact->append_state->wrote, chunk->next)) {
                r = backup_append_end(compact, &ts);
                chunk_start_time = -1;
            }
            else if (verbose) {
                fprintf(out, "combining chunks %d and %d\n",
                             chunk->id, chunk->next->id);
            }
        }

        prot_free(in);
        in = NULL;
        gzuc_member_end(gzuc, NULL);

        sync_msgid_list_free(&keep_message_guids);
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
    if (keep_message_guids) sync_msgid_list_free(&keep_message_guids);
    if (all_chunks) backup_chunk_list_free(&all_chunks);
    if (keep_chunks) backup_chunk_list_free(&keep_chunks);
    if (compact) backup_unlink(&compact);
    if (original) backup_close(&original);

    return r ? r : -1;
}
