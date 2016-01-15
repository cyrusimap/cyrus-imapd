/* api.c -- replication-based backup api
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

#include <config.h>

#include <assert.h>
#include <errno.h>
#include <syslog.h>
#include <zlib.h>

#include "lib/cyrusdb.h"
#include "lib/cyr_lock.h"
#include "lib/exitcodes.h"
#include "lib/gzuncat.h"
#include "lib/map.h"
#include "lib/sqldb.h"
#include "lib/util.h"
#include "lib/xmalloc.h"
#include "lib/xsha1.h"
#include "lib/xstrlcat.h"
#include "lib/xstrlcpy.h"

#include "imap/dlist.h"
#include "imap/global.h"
#include "imap/imap_err.h"

#include "backup/backup.h"

#define LIBCYRUS_BACKUP_SOURCE /* this file is part of libcyrus_backup */
#include "backup/lcb_internal.h"
#include "backup/lcb_sqlconsts.h"

const char *_sha1_file(int fd, const char *fname, size_t limit,
                              char buf[2 * SHA1_DIGEST_LENGTH + 1]);

/*
 * use cases:
 *  - backupd needs to be able to append to data stream and update index (exclusive)
 *  - backupd maybe needs to create a new backup from scratch (exclusive)
 *  - reindex needs to gzuc data stream and rewrite index (exclusive)
 *  - compress needs to rewrite data stream and index (exclusive)
 *  - restore needs to read data stream and index (shared)
 *
 * with only one shared case, might as well always lock exclusively...
 */
HIDDEN int backup_real_open(struct backup **backupp,
                            const char *data_fname, const char *index_fname,
                            enum backup_open_reindex reindex,
                            enum backup_open_nonblock nonblock,
                            enum backup_open_create create)
{
    struct backup *backup = xzmalloc(sizeof *backup);
    int r;

    backup->fd = -1;

    backup->data_fname = xstrdup(data_fname);
    backup->index_fname = xstrdup(index_fname);

    int open_flags = O_RDWR | O_APPEND;

    switch (create) {
    case BACKUP_OPEN_CREATE_EXCL:   open_flags |= O_EXCL;  /* fall thru */
    case BACKUP_OPEN_CREATE:        open_flags |= O_CREAT; /*           */
    case BACKUP_OPEN_NOCREATE:      break;
    }

    while (backup->fd == -1) {
        struct stat sbuf1, sbuf2;

        int fd = open(backup->data_fname,
                      open_flags,
                      S_IRUSR | S_IWUSR);
        if (fd < 0) {
            syslog(LOG_ERR, "IOERROR: open %s: %m", backup->data_fname);
            r = IMAP_IOERROR;
            goto error;
        }

        r = lock_setlock(fd, /*excl*/ 1, nonblock, backup->data_fname);
        if (r) {
            if (errno == EWOULDBLOCK || errno == EAGAIN) {
                r = IMAP_MAILBOX_LOCKED;
            }
            else {
                syslog(LOG_ERR, "IOERROR: lock_setlock: %s: %m", backup->data_fname);
                r = IMAP_IOERROR;
            }
            goto error;
        }

        r = fstat(fd, &sbuf1);
        if (!r) r = stat(backup->data_fname, &sbuf2);
        if (r) {
            syslog(LOG_ERR, "IOERROR: (f)stat %s: %m", backup->data_fname);
            r = IMAP_IOERROR;
            goto error;
        }

        if (sbuf1.st_ino == sbuf2.st_ino) {
            backup->fd = fd;
            break;
        }

        close(fd);
    }

    if (reindex) {
        // when reindexing, we want to move the old index out of the way
        // and create a new, empty one -- while holding the lock
        char oldindex_fname[PATH_MAX];
        snprintf(oldindex_fname, sizeof(oldindex_fname), "%s.%ld",
                 backup->index_fname, (int64_t) time(NULL));

        r = rename(backup->index_fname, oldindex_fname);
        if (r && errno != ENOENT) {
            syslog(LOG_ERR, "IOERROR: rename %s %s: %m", backup->index_fname, oldindex_fname);
            r = IMAP_IOERROR;
            goto error;
        }

        backup->oldindex_fname = xstrdup(oldindex_fname);
    }
    else {
        // if there's data in the data file but the index file is empty
        // or doesn't exist, insist on a reindex before opening
        struct stat data_statbuf;
        r = fstat(backup->fd, &data_statbuf);
        if (r) {
            syslog(LOG_ERR, "IOERROR: fstat %s: %m", backup->data_fname);
            r = IMAP_IOERROR;
            goto error;
        }
        if (data_statbuf.st_size > 0) {
            struct stat index_statbuf;
            r = stat(backup->index_fname, &index_statbuf);
            if (r && errno != ENOENT) {
                syslog(LOG_ERR, "IOERROR: stat %s: %m", backup->index_fname);
                r = IMAP_IOERROR;
                goto error;
            }

            if ((r && errno == ENOENT) || index_statbuf.st_size == 0) {
                syslog(LOG_ERR, "reindex needed: %s", backup->index_fname);
                r = IMAP_MAILBOX_BADFORMAT; // FIXME define special error code for this?
                goto error;
            }
        }
    }

    backup->db = sqldb_open(backup->index_fname, backup_index_initsql,
                            backup_index_version, backup_index_upgrade);
    if (!backup->db) {
        r = IMAP_INTERNAL; // FIXME what does it mean to error here?
        goto error;
    }

    // FIXME detect when last append didn't end correctly (no length/data_sha1)
    // and insist on reindex (can this happen with txns?)

    *backupp = backup;
    return 0;

error:
    backup_close(&backup);
    if (!r) r = IMAP_INTERNAL;
    return r;
}

EXPORTED int backup_open(struct backup **backupp,
                         const mbname_t *mbname,
                         enum backup_open_nonblock nonblock,
                         enum backup_open_create create)
{
    struct buf data_fname = BUF_INITIALIZER;
    struct buf index_fname = BUF_INITIALIZER;

    int r = backup_get_paths(mbname, &data_fname, &index_fname, create);
    if (r) goto done;

    r = backup_real_open(backupp,
                         buf_cstring(&data_fname), buf_cstring(&index_fname),
                         BACKUP_OPEN_NOREINDEX, nonblock, create);
    if (r) goto done;

    r = backup_verify(*backupp, BACKUP_VERIFY_QUICK, 0, NULL);
    if (r) backup_close(backupp);

done:
    buf_free(&data_fname);
    buf_free(&index_fname);

    return r;
}

/* Uses mkstemp() to create a new, unique, backup path for the given user.
 *
 * On success, the file is not unlinked, presuming that it will shortly be
 * used for storing backup data.  This also ensures its uniqueness remains:
 * this function won't generate the same value again as long as the previous
 * file is intact, so there's no user-rename race.
 *
 * If out_fd is non-NULL, on successful return it will contain an open, locked
 * file descriptor for the new file.  In this case the caller must unlock
 * and close the fd.
 *
 * On error, returns NULL and logs to syslog, without touching out_fd.
 */
static const char *_make_path(const mbname_t *mbname, int *out_fd)
{
    static char pathresult[PATH_MAX];

    const char *userid = mbname_userid(mbname);
    const char *partition = partlist_backup_select();
    const char *ret = NULL;

    if (!partition) {
        syslog(LOG_ERR,
               "unable to make backup path for %s: "
               "couldn't select partition",
               userid);
        return NULL;
    }

    char hash_buf[2];
    char *template = strconcat(partition,
                               "/", dir_hash_b(userid, 1, hash_buf),
                               "/", userid, "_XXXXXX",
                               NULL);

    /* make sure the destination directory exists */
    cyrus_mkdir(template, 0755);

    int fd = mkstemp(template);
    if (fd < 0) {
        syslog(LOG_ERR, "unable to make backup path for %s: %m", userid);
        goto error;
    }

    /* lock it -- even if we're just going to immediately unlock it */
    int r = lock_setlock(fd, /*excl*/ 1, /*nb*/ 0, template);
    if (r) {
        syslog(LOG_ERR,
               "unable to obtain exclusive lock on just-created file %s: %m",
               template);
        /* don't unlink it, we don't know what's in it */
        goto error;
    }

    /* save the path */
    if (strlcpy(pathresult, template, sizeof(pathresult)) >= sizeof(pathresult)) {
        syslog(LOG_ERR,
               "unable to make backup path for %s: path too long",
               userid);
        unlink(template);
        goto error;
    }
    ret = pathresult;

    /* save or close the fd */
    if (out_fd)
        *out_fd = fd;
    else
        close(fd);

    free(template);
    return ret;

error:
    if (fd >= 0) close(fd);
    free(template);
    return NULL;
}

EXPORTED int backup_get_paths(const mbname_t *mbname,
                              struct buf *data_fname, struct buf *index_fname,
                              enum backup_open_create create)
{
    char *backups_db_fname = xstrdupnull(config_getstring(IMAPOPT_BACKUPS_DB_PATH));
    if (!backups_db_fname)
        backups_db_fname = strconcat(config_dir, "/backups.db", NULL);

    struct db *backups_db = NULL;
    struct txn *tid = NULL;

    int r = cyrusdb_open(config_backups_db, backups_db_fname, CYRUSDB_CREATE,
                         &backups_db);
    if (r) goto done;

    const char *userid = mbname_userid(mbname);
    const char *backup_path = NULL;
    size_t path_len = 0;

    r = cyrusdb_fetch(backups_db,
                      userid, strlen(userid),
                      &backup_path, &path_len,
                      &tid);

    if (r == CYRUSDB_NOTFOUND && create) {
        syslog(LOG_DEBUG, "%s not found in backups.db, creating new record", userid);
        backup_path = _make_path(mbname, NULL);
        if (!backup_path) {
            r = IMAP_INTERNAL; /* FIXME ?? */
            goto done;
        }
        path_len = strlen(backup_path);

        r = cyrusdb_create(backups_db,
                           userid, strlen(userid),
                           backup_path, path_len,
                           &tid);
        if (r) cyrusdb_abort(backups_db, tid);
        else r = cyrusdb_commit(backups_db, tid);

        tid = NULL;

        /* if we didn't store it in the database successfully, trash the file,
         * it won't be used */
        if (r) unlink(backup_path);
    }

    if (r) goto done;

    if (path_len == 0) {
        syslog(LOG_DEBUG,
               "unexpectedly got zero length backup path for user %s",
               userid);
        r = IMAP_INTERNAL; /* FIXME ?? */
        goto done;
    }

    if (data_fname)
        buf_setmap(data_fname, backup_path, path_len);

    if (index_fname) {
        buf_setmap(index_fname, backup_path, path_len);
        buf_appendcstr(index_fname, ".index");
    }

done:
    if (backups_db) {
        if (tid) cyrusdb_abort(backups_db, tid);
        cyrusdb_close(backups_db);
    }
    free(backups_db_fname);
    return r;
}

/*
 * If index_fname is NULL, it will be automatically derived from data_fname
 */
EXPORTED int backup_open_paths(struct backup **backupp,
                               const char *data_fname,
                               const char *index_fname,
                               enum backup_open_nonblock nonblock,
                               enum backup_open_create create)
{
    if (index_fname)
        return backup_real_open(backupp, data_fname, index_fname,
                                BACKUP_OPEN_NOREINDEX, nonblock, create);
        /* FIXME verify */

    char *tmp = strconcat(data_fname, ".index", NULL);
    int r = backup_real_open(backupp, data_fname, tmp,
                             BACKUP_OPEN_NOREINDEX, nonblock, create);
    free(tmp);
    if (r) return r;

    r = backup_verify(*backupp, BACKUP_VERIFY_QUICK, 0, NULL);
    if (r) backup_close(backupp);

    return r;
}

EXPORTED int backup_close(struct backup **backupp)
{
    struct backup *backup = *backupp;
    *backupp = NULL;

    gzFile gzfile = NULL;
    int r1 = 0, r2 = 0;

    if (backup->append_state) {
        if (backup->append_state->mode != BACKUP_APPEND_INACTIVE)
            r1 = backup_append_end(backup);

        gzfile = backup->append_state->gzfile;

        free(backup->append_state);
        backup->append_state = NULL;
    }

    if (backup->db) r2 = sqldb_close(&backup->db);

    if (r2 && backup->oldindex_fname) {
        rename(backup->oldindex_fname, backup->index_fname);
        free(backup->oldindex_fname);
    }

    if (backup->fd >= 0) {
        /* closing the file will also release the lock on the fd */
        if (gzfile)
            gzclose_w(gzfile);
        else
            close(backup->fd);
    }

    if (backup->index_fname) free(backup->index_fname);
    if (backup->data_fname) free(backup->data_fname);

    free(backup);
    return r1 ? r1 : r2;
}

EXPORTED int backup_unlink(struct backup **backupp)
{
    struct backup *backup = *backupp;

    unlink(backup->index_fname);
    unlink(backup->data_fname);

    return backup_close(backupp);
}

EXPORTED const char *backup_get_data_fname(const struct backup *backup)
{
    return backup->data_fname;
}

EXPORTED const char *backup_get_index_fname(const struct backup *backup)
{
    return backup->index_fname;
}

/* limit is how much of the file to calculate the sha1 of (in bytes),
 * or SHA1_LIMIT_WHOLE_FILE for the whole file */
#define SHA1_LIMIT_WHOLE_FILE ((size_t) -1)
HIDDEN const char *_sha1_file(int fd, const char *fname, size_t limit,
                              char buf[2 * SHA1_DIGEST_LENGTH + 1])
{
    const char *map = NULL;
    size_t len = 0, calc_len;
    unsigned char sha1_raw[SHA1_DIGEST_LENGTH];
    int r;

    map_refresh(fd, /*onceonly*/ 1, &map, &len, MAP_UNKNOWN_LEN, fname, NULL);
    calc_len = limit == SHA1_LIMIT_WHOLE_FILE ? len : MIN(limit, len);
    xsha1((const unsigned char *) map, calc_len, sha1_raw);
    map_free(&map, &len);
    r = bin_to_hex(sha1_raw, SHA1_DIGEST_LENGTH, buf, BH_LOWER);
    assert(r == 2 * SHA1_DIGEST_LENGTH);

    return buf;
}

static int _append_start(struct backup *backup, time_t ts, off_t offset,
                         const char *file_sha1, int index_only, int noflush)
{
    if (backup->append_state != NULL
        && backup->append_state->mode != BACKUP_APPEND_INACTIVE) {
        fatal("backup append already started", EC_SOFTWARE);
    }

    if (!backup->append_state)
        backup->append_state = xzmalloc(sizeof(*backup->append_state));

    if (index_only) backup->append_state->mode |= BACKUP_APPEND_INDEXONLY;
    if (noflush) backup->append_state->mode |= BACKUP_APPEND_NOFLUSH;

    backup->append_state->wrote = 0;
    SHA1_Init(&backup->append_state->sha_ctx);

    char header[80];
    snprintf(header, sizeof(header), "# cyrus backup: chunk start\r\n");

    if (!index_only) {
        if (!backup->append_state->gzfile) {
            backup->append_state->gzfile = gzdopen(backup->fd, "ab");
            if (!backup->append_state->gzfile) {
                fprintf(stderr, "%s: gzdopen fd %i failed: %s\n",
                        __func__, backup->fd, strerror(errno));
                goto error;
            }
        }

        // FIXME check for error return
        gzwrite(backup->append_state->gzfile, header, strlen(header));
        if (!noflush)
            gzflush(backup->append_state->gzfile, Z_FULL_FLUSH);
    }

    SHA1_Update(&backup->append_state->sha_ctx, header, strlen(header));
    backup->append_state->wrote += strlen(header);

    struct sqldb_bindval bval[] = {
        { ":ts_start",  SQLITE_INTEGER, { .i = ts           } },
        { ":offset",    SQLITE_INTEGER, { .i = offset       } },
        { ":file_sha1", SQLITE_TEXT,    { .s = file_sha1    } },
        { NULL,         SQLITE_NULL,    { .s = NULL         } },
    };

    sqldb_begin(backup->db, "backup_append"); // FIXME what if this fails

    int r = sqldb_exec(backup->db, backup_index_start_sql, bval, NULL, NULL);
    if (r) {
        // FIXME handle this sensibly
        fprintf(stderr, "%s: something went wrong: %i\n", __func__, r);
        sqldb_rollback(backup->db, "backup_append");
        goto error;
    }

    backup->append_state->chunk_id = sqldb_lastid(backup->db);

    backup->append_state->mode |= BACKUP_APPEND_ACTIVE;
    return 0;

error:
    backup->append_state->mode = BACKUP_APPEND_INACTIVE;
    return -1;
}

EXPORTED int backup_append_start(struct backup *backup)
{
    char file_sha1[2 * SHA1_DIGEST_LENGTH + 1];
    off_t offset = lseek(backup->fd, 0, SEEK_END);

    _sha1_file(backup->fd, backup->data_fname, SHA1_LIMIT_WHOLE_FILE, file_sha1);

    return _append_start(backup, time(0), offset, file_sha1, 0, 0);
}

EXPORTED int backup_append(struct backup *backup, struct dlist *dlist, time_t ts)
{
    int r;
    if (!backup->append_state || backup->append_state->mode == BACKUP_APPEND_INACTIVE)
        fatal("backup append not started", EC_SOFTWARE);

    off_t start = backup->append_state->wrote;
    size_t len;

    /* build a buffer containing the data to be written */
    struct buf buf = BUF_INITIALIZER, ts_buf = BUF_INITIALIZER;
    dlist_printbuf(dlist, 1, &buf);
    buf_printf(&ts_buf, "%ld APPLY ", (int64_t) ts);
    buf_insert(&buf, 0, &ts_buf);
    buf_appendcstr(&buf, "\r\n");

    /* track the sha1sum */
    SHA1_Update(&backup->append_state->sha_ctx, buf_cstring(&buf), buf_len(&buf));

    /* if we're not in index-only mode, write the data out */
    if (!(backup->append_state->mode & BACKUP_APPEND_INDEXONLY)) {
        /* gzprintf's internal buffer is limited to about 8K, which
         * dlist will exceed if there's a message in it, so use gzwrite
         * rather than gzprintf for writing the dlist contents.
         */
        const char *p = buf_cstring(&buf);
        size_t left = buf_len(&buf);

        while (left) {
            int n = MIN(left, INT32_MAX);
            int wrote = gzwrite(backup->append_state->gzfile, p, n);
            if (wrote > 0) {
                left -= wrote;
                p += wrote;
            }
            else {
                const char *err = gzerror(backup->append_state->gzfile, &r);
                syslog(LOG_ERR, "IOERROR: %s gzwrite %s: %s", __func__, backup->data_fname, err);

                if (r == Z_STREAM_ERROR)
                    fatal("gzwrite: invalid stream", EC_IOERR);
                else if (r == Z_MEM_ERROR)
                    fatal("gzwrite: out of memory", EC_TEMPFAIL);

                goto error;
            }
        }

        if (!(backup->append_state->mode & BACKUP_APPEND_NOFLUSH)) {
            r = gzflush(backup->append_state->gzfile, Z_FULL_FLUSH);
            if (r != Z_OK) {
                syslog(LOG_ERR, "IOERROR: %s gzflush %s: %i %i", __func__, backup->data_fname, r, errno);
                goto error;
            }
        }
    }

    /* count the written bytes */
    len = buf_len(&buf);
    backup->append_state->wrote += buf_len(&buf);

    buf_free(&buf);

    /* update the index */
    return backup_index(backup, dlist, ts, start, len);

error:
    buf_free(&buf);
    return IMAP_INTERNAL;
}

static int _append_end(struct backup *backup, time_t ts)
{
    int r;

    if (!backup->append_state)
        fatal("backup append not started", EC_SOFTWARE);
    if (backup->append_state->mode == BACKUP_APPEND_INACTIVE)
        fatal("backup append not started", EC_SOFTWARE);

    if (!(backup->append_state->mode & BACKUP_APPEND_INDEXONLY)) {
        r = gzflush(backup->append_state->gzfile, Z_FINISH);
        if (r != Z_OK) {
            fprintf(stderr, "%s: gzflush failed: %i\n", __func__, r);
            // FIXME handle this sensibly
        }
    }

    unsigned char sha1_raw[SHA1_DIGEST_LENGTH];
    char data_sha1[2 * SHA1_DIGEST_LENGTH + 1];
    SHA1_Final(sha1_raw, &backup->append_state->sha_ctx);
    r = bin_to_hex(sha1_raw, SHA1_DIGEST_LENGTH, data_sha1, BH_LOWER);
    assert(r == 2 * SHA1_DIGEST_LENGTH);

    struct sqldb_bindval bval[] = {
        { ":id",        SQLITE_INTEGER, { .i = backup->append_state->chunk_id } },
        { ":ts_end",    SQLITE_INTEGER, { .i = ts                             } },
        { ":length",    SQLITE_INTEGER, { .i = backup->append_state->wrote    } },
        { ":data_sha1", SQLITE_TEXT,    { .s = data_sha1                      } },
        { NULL,         SQLITE_NULL,    { .s = NULL                           } },
    };

    r = sqldb_exec(backup->db, backup_index_end_sql, bval, NULL, NULL);
    if (r) {
        // FIXME handle this sensibly
        fprintf(stderr, "%s: something went wrong: %i\n", __func__, r);
        sqldb_rollback(backup->db, "backup_append");
    }
    else {
        sqldb_commit(backup->db, "backup_append");
    }

    backup->append_state->mode = BACKUP_APPEND_INACTIVE;
    backup->append_state->wrote = 0;

    return r;
}

EXPORTED int backup_append_end(struct backup *backup)
{
    return _append_end(backup, time(NULL));
}

EXPORTED int backup_append_abort(struct backup *backup)
{
    if (!backup->append_state)
        fatal("backup append not started", EC_SOFTWARE);
    if (backup->append_state == BACKUP_APPEND_INACTIVE)
        fatal("backup append not started", EC_SOFTWARE);

    sqldb_rollback(backup->db, "backup_append");

    // FIXME
    // can we truncate back to the length we started this append at?
    // ftruncate(2) says nothing about behaviour on descriptors
    // opened with O_APPEND...
    // seems like it might work, but test it first.

    // FIXME at least z_finish the damn file...

    backup->append_state->mode = BACKUP_APPEND_INACTIVE;
    return 0;
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

EXPORTED int backup_reindex(const char *name, int verbose, FILE *out)
{
    struct buf data_fname = BUF_INITIALIZER;
    struct buf index_fname = BUF_INITIALIZER;
    struct backup *backup = NULL;
    int r;

    buf_printf(&data_fname, "%s", name);
    buf_printf(&index_fname, "%s.index", name);

    r = backup_real_open(&backup,
                         buf_cstring(&data_fname), buf_cstring(&index_fname),
                         BACKUP_OPEN_REINDEX, BACKUP_OPEN_BLOCK,
                         BACKUP_OPEN_NOCREATE);
    buf_free(&index_fname);
    buf_free(&data_fname);
    if (r) return r;

    struct gzuncat *gzuc = gzuc_new(backup->fd);

    time_t prev_member_ts = -1;

    while (gzuc && !gzuc_eof(gzuc)) {
        gzuc_member_start(gzuc);
        off_t member_offset = gzuc_member_offset(gzuc);

        if (verbose)
            fprintf(out, "\nfound chunk at offset %jd\n\n", member_offset);

        struct protstream *member = prot_readcb(_prot_fill_cb, gzuc);
        prot_setisclient(member, 1); /* don't sync literals */

        // FIXME stricter timestamp sequence checks
        time_t member_start_ts = -1;
        time_t member_end_ts = -1;
        time_t ts = -1;

        while (1) {
            struct buf cmd = BUF_INITIALIZER;
            struct dlist *dl = NULL;

            int c = parse_backup_line(member, &ts, &cmd, &dl);
            if (c == EOF) {
                const char *error = prot_error(member);
                if (error && 0 != strcmp(error, PROT_EOF_STRING)) {
                    syslog(LOG_ERR,
                           "IOERROR: %s: error reading chunk at offset %jd, byte %i: %s\n",
                           name, member_offset, prot_bytes_in(member), error);

                    if (out)
                        fprintf(out, "error reading chunk at offset %jd, byte %i: %s\n",
                                member_offset, prot_bytes_in(member), error);

                    r = IMAP_IOERROR;
                }
                member_end_ts = ts;
                break;
            }

            if (member_start_ts == -1) {
                if (prev_member_ts != -1 && prev_member_ts > ts) {
                    fatal("member timestamp older than previous", EC_DATAERR);
                }
                member_start_ts = ts;
                char file_sha1[2 * SHA1_DIGEST_LENGTH + 1];
                _sha1_file(backup->fd, backup->data_fname, member_offset, file_sha1);
                _append_start(backup, member_start_ts, member_offset, file_sha1, 1, 0);
            }
            else if (member_start_ts > ts)
                fatal("line timestamp older than previous", EC_DATAERR);

            if (strcmp(buf_cstring(&cmd), "APPLY") != 0)
                continue;

            ucase(dl->name);

            r = backup_append(backup, dl, ts);
            if (r) {
                // FIXME do something
                syslog(LOG_ERR, "backup_append returned %d\n", r);
                fprintf(out, "backup_append returned %d\n", r);
            }
        }

        if (backup->append_state && backup->append_state->mode)
            _append_end(backup, member_end_ts);
        prot_free(member);
        gzuc_member_end(gzuc, NULL);

        prev_member_ts = member_start_ts;
    }

    if (verbose)
        fprintf(out, "reached end of file\n");

    gzuc_free(&gzuc);
    backup_close(&backup);

    return r;
}

struct _rename_meta {
    const char *userid;
    char *fname;
    char *ext_ptr;
    int fd;
};
#define RENAME_META_INITIALIZER { NULL, NULL, NULL, -1 }

static void _rename_meta_set_fname(struct _rename_meta *meta, const char *data_fname)
{
    size_t len = strlen(data_fname) + strlen(".index") + 1;
    meta->fname = xmalloc(len);
    snprintf(meta->fname, len, "%s.index", data_fname);
    meta->ext_ptr = strrchr(meta->fname, '.');
    *meta->ext_ptr = '\0';
}

static void _rename_meta_fini(struct _rename_meta *meta)
{
    if (meta->fname) free(meta->fname);
    memset(meta, 0, sizeof(*meta));
    meta->fd = -1;
}

EXPORTED int backup_rename(const mbname_t *old_mbname, const mbname_t *new_mbname)
{
    struct _rename_meta old = RENAME_META_INITIALIZER;
    struct _rename_meta new = RENAME_META_INITIALIZER;
    old.userid = mbname_userid(old_mbname);
    new.userid = mbname_userid(new_mbname);
    const char *path;
    size_t path_len;
    int r;

    /* bail out if the names are the same */
    if (strcmp(old.userid, new.userid) == 0)
        return 0;

    /* exclusively open backups database */
    char *backups_db_fname = xstrdup(config_getstring(IMAPOPT_BACKUPS_DB_PATH));
    if (!backups_db_fname)
        backups_db_fname = strconcat(config_dir, "/backups.db", NULL);

    struct db *backups_db = NULL;
    struct txn *tid = NULL;

    r = cyrusdb_lockopen(config_backups_db, backups_db_fname, 0,
                         &backups_db, &tid);
    if (r) goto error; // FIXME log

    /* make sure new_mbname isn't already in use */
    r = cyrusdb_fetch(backups_db,
                      new.userid, strlen(new.userid),
                      &path, &path_len,
                      &tid);
    if (!r) r = CYRUSDB_EXISTS;
    if (r) goto error;  // FIXME log

    /* locate (but not create) backup for old_mbname, open and lock it */
    r = cyrusdb_fetch(backups_db,
                      old.userid, strlen(old.userid),
                      &path, &path_len,
                      &tid);
    if (r) goto error;  // FIXME log

    _rename_meta_set_fname(&old, path);

    old.fd = open(old.fname,
                  O_RDWR | O_APPEND, /* no O_CREAT */
                  S_IRUSR | S_IWUSR);
    if (old.fd < 0) {
        syslog(LOG_ERR, "IOERROR: open %s: %m", old.fname);
        r = -1;
        goto error;
    }

    /* non-blocking, to avoid deadlock */
    r = lock_setlock(old.fd, /*excl*/ 1, /*nb*/ 1, old.fname);
    if (r) {
        syslog(LOG_ERR, "IOERROR: lock_setlock: %s: %m", old.fname);
        goto error;
    }

    /* make a path for new_mbname, open and lock it */
    path = _make_path(new_mbname, &new.fd);
    if (!path) goto error; // FIXME log
    _rename_meta_set_fname(&new, path);

    /* copy old data and index files to new paths */
    r = cyrus_copyfile(old.fname, new.fname, 0);
    if (r) goto error; // FIXME log
    *old.ext_ptr = *new.ext_ptr = '.';
    r = cyrus_copyfile(old.fname, new.fname, 0);
    *old.ext_ptr = *new.ext_ptr = '\0';
    if (r) goto error; // FIXME log

    /* files exist under both names now. try to update the database */
    r = cyrusdb_create(backups_db,
                       new.userid, strlen(new.userid),
                       new.fname, strlen(new.fname),
                       &tid);
    if (r) goto error; // FIXME log

    r = cyrusdb_delete(backups_db,
                       old.userid, strlen(old.userid),
                       &tid, 0);
    if (r) goto error; // FIXME log

    r = cyrusdb_commit(backups_db, tid);
    tid = NULL;
    if (r) goto error; // FIXME log

    /* database update succeeded. unlink old names */
    unlink(old.fname);
    *old.ext_ptr = '.';
    unlink(old.fname);
    *old.ext_ptr = '\0';

    /* unlock and close backup files */
    lock_unlock(new.fd, new.fname);
    close(new.fd);
    lock_unlock(old.fd, old.fname);
    close(old.fd);

    /* close backups database */
    cyrusdb_close(backups_db);

    /* clean up and exit */
    _rename_meta_fini(&old);
    _rename_meta_fini(&new);
    free(backups_db_fname);
    return 0;

error:
    /* we didn't finish, so unlink the new filenames if we got that far */
    if (new.fname) {
        unlink(new.fname);
        *new.ext_ptr = '.';
        unlink(new.fname);
        *new.ext_ptr = '\0';
    }

    /* close the files if we got that far (also unlocks) */
    if (new.fd != -1)
        close(new.fd);
    if (old.fd != -1)
        close(old.fd);

    /* abort any transaction and close the database */
    if (backups_db) {
        if (tid) cyrusdb_abort(backups_db, tid);
        cyrusdb_close(backups_db);
    }

    /* clean up and exit */
    _rename_meta_fini(&old);
    _rename_meta_fini(&new);
    if (backups_db_fname) free(backups_db_fname);
    return r;
}
