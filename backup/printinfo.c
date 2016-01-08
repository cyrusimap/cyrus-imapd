/* printinfo.c -- replication-based backup api - printinfo function
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

#include "backup/api.h"
#include "backup/sqlconsts.h"

#define BACKUP_INTERNAL_SOURCE /* this file is part of the backup API */
#include "backup/internal.h"

typedef int (*detail_fn)(struct backup *, const char *, FILE *);

static int detail0(struct backup *backup, const char *userid, FILE *out);
static int detail_sz_ts(struct backup *backup, const char *userid, FILE *out);

static const detail_fn detail_funcs[] = {
    detail0,
    detail_sz_ts,
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
    if (!chunk) {
        fprintf(stderr, "%s %s: backup_get_latest_chunk failed\n",
                __func__, backup->data_fname);
        r = -1;
        goto done;
    }

    r = fstat(backup->fd, &stat_buf);
    if (r) {
        fprintf(stderr, "fstat %s: %s\n", backup->data_fname, strerror(errno));
        stat_buf.st_size = -1;
    }

    strftime(timestamp, sizeof(timestamp), "%F %T", localtime(&chunk->ts_end));

    fprintf(out, "%s\t" OFF_T_FMT "\t%s\t%s\n",
            userid,
            stat_buf.st_size,
            timestamp,
            backup->data_fname);

done:
    if (chunk) backup_chunk_free(&chunk);
    return r;
}
