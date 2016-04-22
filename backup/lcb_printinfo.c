/* lcb_printinfo.c -- replication-based backup api - printinfo function
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
#include <errno.h>
#include <syslog.h>

#include "backup/backup.h"

#define LIBCYRUS_BACKUP_SOURCE /* this file is part of libcyrus_backup */
#include "backup/lcb_internal.h"
#include "backup/lcb_sqlconsts.h"

typedef int (*detail_fn)(struct backup *, const char *, FILE *);

static int detail0(struct backup *backup, const char *userid, FILE *out);
static int detail_sz_ts(struct backup *backup, const char *userid, FILE *out);
static int detail_full(struct backup *backup, const char *userid, FILE *out);

static const detail_fn detail_funcs[] = {
    detail0,
    detail_sz_ts,
    detail_full,
};

static const size_t n_detail_funcs = sizeof(detail_funcs) / sizeof(detail_funcs[0]);

// FIXME maybe store userid in backup struct?
EXPORTED int backup_printinfo(struct backup *backup, const char *userid,
                              FILE *out, int detail)
{
    if (detail < 0) return -1;
    if ((unsigned) detail >= n_detail_funcs) detail = n_detail_funcs - 1;

    if (!userid) userid = "(unknown user)";

    return detail_funcs[detail](backup, userid, out);
}

static int detail0(struct backup *backup, const char *userid, FILE *out)
{
    fprintf(out, "%s\t%s\n", userid, backup->data_fname);

    return 0;
}

static int detail_sz_ts(struct backup *backup, const char *userid, FILE *out)
{
    struct backup_chunk *chunk = NULL;
    struct stat stat_buf;
    char timestamp[32] = "[unknown]";
    int r = 0;

    chunk = backup_get_latest_chunk(backup);
    if (chunk) {
        strftime(timestamp, sizeof(timestamp), "%F %T",
                 localtime(&chunk->ts_end));
        backup_chunk_free(&chunk);
    }

    r = fstat(backup->fd, &stat_buf);
    if (r) {
        fprintf(stderr, "fstat %s: %s\n", backup->data_fname, strerror(errno));
        stat_buf.st_size = -1;
    }

    fprintf(out, "%s\t" OFF_T_FMT "\t%s\t%s\n",
            userid,
            stat_buf.st_size,
            timestamp,
            backup->data_fname);

    return r;
}

static int detail_full(struct backup *backup, const char *userid, FILE *out)
{
    struct backup_chunk_list *all_chunks = NULL;
    struct backup_chunk *chunk = NULL;
    struct stat data_stat_buf, index_stat_buf;
    char data_timestamp[32] = "[unknown]";
    char index_timestamp[32] = "[unknown]";
    int r = 0;

    r = fstat(backup->fd, &data_stat_buf);
    if (r) {
        fprintf(stderr, "fstat %s: %s\n", backup->data_fname, strerror(errno));
        data_stat_buf.st_size = -1;
    }

    r = stat(backup->index_fname, &index_stat_buf);
    if (r) {
        fprintf(stderr, "stat %s: %s\n", backup->index_fname, strerror(errno));
        index_stat_buf.st_size = -1;
    }

    strftime(data_timestamp, sizeof(data_timestamp), "%F %T",
             localtime(&data_stat_buf.st_mtime));
    strftime(index_timestamp, sizeof(index_timestamp), "%F %T",
             localtime(&index_stat_buf.st_mtime));

    fprintf(out, "userid: %s\n", userid);
    fprintf(out, "  data: %s\n", backup->data_fname);
    fprintf(out, "        " OFF_T_FMT "\tmodified: %s\n",
                 data_stat_buf.st_size, data_timestamp);
    fprintf(out, " index: %s\n", backup->index_fname);
    fprintf(out, "        " OFF_T_FMT "\tmodified: %s\n",
                 index_stat_buf.st_size, index_timestamp);

    all_chunks = backup_get_chunks(backup);

    if (all_chunks) {
        double total_length = 0.0;

        fprintf(out, "chunks: " SIZE_T_FMT "\n", all_chunks->count);
        fprintf(out, "     id offset\tlength\tratio%%\tstart time           end time\n");

        for (chunk = all_chunks->head; chunk; chunk = chunk->next) {
            char ts_start[32] = "[unknown]";
            char ts_end[32] = "[unknown]";
            double ratio;

            strftime(ts_start, sizeof(ts_start), "%F %T",
                    localtime(&chunk->ts_start));
            strftime(ts_end, sizeof(ts_end), "%F %T",
                    localtime(&chunk->ts_end));

            if (chunk->next) {
                ratio = 100.0 * (chunk->next->offset - chunk->offset) / chunk->length;
            }
            else {
                ratio = 100.0 * (data_stat_buf.st_size - chunk->offset) / chunk->length;
            }

            total_length += chunk->length;

            fprintf(out, "%7d " OFF_T_FMT "\t" SIZE_T_FMT "\t%6.1f\t%s  %s\n",
                        chunk->id,
                        chunk->offset,
                        chunk->length,
                        ratio,
                        ts_start,
                        ts_end);
        }

        fprintf(out, "overall compression: %.1f%%\n",
                     100.0 * data_stat_buf.st_size / total_length);

        backup_chunk_list_free(&all_chunks);
    }

    fprintf(out, "\n");

    return r;
}
