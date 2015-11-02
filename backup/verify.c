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
    int id;
    time_t timestamp;
    off_t offset;
    size_t length;
    char *file_sha1;
    char *data_sha1;
};

static int _validate_cb(sqlite3_stmt *stmt, void *rock)
{
    struct chunk *chunk = (struct chunk *) rock;

    int column = 0;
    chunk->id = _column_int(stmt, column++);
    chunk->timestamp = _column_int64(stmt, column++);
    chunk->offset = _column_int64(stmt, column++);
    chunk->length = _column_int64(stmt, column++);
    chunk->file_sha1 = _column_text(stmt, column++);
    chunk->data_sha1 = _column_text(stmt, column++);

    return 0;
}

EXPORTED int backup_verify(struct backup *backup, int level)
{
    (void) level;
    struct chunk chunk = {0};
    struct gzuncat *gzuc = NULL;

    int r = sqldb_exec(backup->db, backup_index_chunk_select_latest_sql,
                       NULL, _validate_cb, &chunk);
    if (r) goto done;
    if (!chunk.id) {
        fprintf(stderr, "%s: %s file checksum mismatch: not in index\n",
                __func__, backup->data_fname);
        r = -1;
        goto done;
    }

    /* validate file-prior-to-this-chunk checksum */
    char file_sha1[2 * SHA1_DIGEST_LENGTH + 1];
    _sha1_file(backup->fd, backup->data_fname, chunk.offset, file_sha1);
    r = strncmp(chunk.file_sha1, file_sha1, sizeof(file_sha1));
    if (r) {
        fprintf(stderr, "%s: %s file checksum mismatch: %s on disk, %s in index\n",
                __func__, backup->data_fname, file_sha1, chunk.file_sha1);
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
    gzuc_member_start_from(gzuc, chunk.offset);
    while (!gzuc_member_eof(gzuc)) {
        ssize_t n = gzuc_read(gzuc, buf, sizeof(buf));
        if (n >= 0) {
            SHA1_Update(&sha_ctx, buf, n);
            len += n;
        }
    }
    if (len != chunk.length) {
        r = -1;
        goto done;
    }
    unsigned char sha1_raw[SHA1_DIGEST_LENGTH];
    char data_sha1[2 * SHA1_DIGEST_LENGTH + 1];
    SHA1_Final(sha1_raw, &sha_ctx);
    r = bin_to_hex(sha1_raw, SHA1_DIGEST_LENGTH, data_sha1, BH_LOWER);
    assert(r == 2 * SHA1_DIGEST_LENGTH);
    r = strncmp(chunk.data_sha1, data_sha1, sizeof(data_sha1));
    if (r) {
        fprintf(stderr, "%s: %s data checksum mismatch: %s on disk, %s in index\n",
                __func__, backup->data_fname, data_sha1, chunk.data_sha1);
        goto done;
    }

done:
    if (gzuc) gzuc_close(&gzuc);
    free(chunk.file_sha1);
    free(chunk.data_sha1);
    fprintf(stderr, "%s: checksum %s!\n", __func__, r ? "failed" : "passed");
    return r;
}

