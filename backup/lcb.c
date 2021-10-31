/* lcb.c -- replication-based backup api
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
#include <dirent.h>
#include <errno.h>
#include <syslog.h>
#include <sysexits.h>
#include <zlib.h>

#include "lib/cyrusdb.h"
#include "lib/cyr_lock.h"
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

static const char *NOUSERID = "\%SHARED";

/* remove this process's staging directory.
 * will warn about and clean up files that are hanging around - these should
 * be removed by dlist_unlink_files but may be missed if we're shutdown by a
 * signal.
 */
EXPORTED void backup_cleanup_staging_path(void)
{
    char name[MAX_MAILBOX_PATH];
    const char *base = config_backupstagingpath();
    DIR *dirp;
    int r;

    r = snprintf(name, MAX_MAILBOX_PATH, "%s/sync./%lu",
                 base, (unsigned long) getpid());
    if (r >= MAX_MAILBOX_PATH) {
        /* path was truncated, don't try to delete it */
        return;
    }

    /* make sure it's empty */
    if ((dirp = opendir(name))) {
        struct dirent *d;
        while ((d = readdir(dirp))) {
            if (!strcmp(d->d_name, ".") || !strcmp(d->d_name, ".."))
                continue;

            char *tmp = strconcat(name, "/", d->d_name, NULL);
            syslog(LOG_INFO, "%s: unlinking leftover stage file: %s", __func__, tmp);
            unlink(tmp);
            free(tmp);
        }
        closedir(dirp);
    }

    r = rmdir(name);
    if (r && errno != ENOENT)
        syslog(LOG_WARNING, "%s rmdir %s: %m", __func__, name);
}

/*
 * use cases:
 *  - backupd needs to be able to append to data stream and update index (exclusive)
 *  - backupd maybe needs to create a new backup from scratch (exclusive)
 *  - reindex needs to gzuc data stream and rewrite index (exclusive)
 *  - compact needs to rewrite data stream and index (exclusive)
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
            switch (errno) {
            case EEXIST:
                r = IMAP_MAILBOX_EXISTS;
                break;
            case ENOENT:
                r = IMAP_MAILBOX_NONEXISTENT;
                break;
            default:
                xsyslog(LOG_ERR, "IOERROR: open failed",
                                 "filename=<%s>", backup->data_fname);
                r = IMAP_IOERROR;
                break;
            }

            goto error;
        }

        r = lock_setlock(fd, /*excl*/ 1, nonblock, backup->data_fname);
        if (r) {
            if (errno == EWOULDBLOCK || errno == EAGAIN) {
                r = IMAP_MAILBOX_LOCKED;
            }
            else {
                xsyslog(LOG_ERR, "IOERROR: lock_setlock failed",
                                 "filename=<%s>", backup->data_fname);
                r = IMAP_IOERROR;
            }
            goto error;
        }

        r = fstat(fd, &sbuf1);
        if (!r) r = stat(backup->data_fname, &sbuf2);
        if (r) {
            xsyslog(LOG_ERR, "IOERROR: stat failed",
                             "filename=<%s>", backup->data_fname);
            r = IMAP_IOERROR;
            close(fd);
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
        snprintf(oldindex_fname, sizeof(oldindex_fname), "%s.%" PRId64,
                 backup->index_fname, (int64_t) time(NULL));

        r = rename(backup->index_fname, oldindex_fname);
        if (r && errno != ENOENT) {
            xsyslog(LOG_ERR, "IOERROR: rename failed",
                             "source=<%s> dest=<%s>",
                             backup->index_fname, oldindex_fname);
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
            xsyslog(LOG_ERR, "IOERROR: fstat failed",
                             "filename=<%s>", backup->data_fname);
            r = IMAP_IOERROR;
            goto error;
        }
        if (data_statbuf.st_size > 0) {
            struct stat index_statbuf;
            r = stat(backup->index_fname, &index_statbuf);
            if (r && errno != ENOENT) {
                xsyslog(LOG_ERR, "IOERROR: stat failed",
                                 "filename=<%s>", backup->index_fname);
                r = IMAP_IOERROR;
                goto error;
            }

            if ((r && errno == ENOENT) || index_statbuf.st_size == 0) {
                xsyslog(LOG_ERR, "IOERROR: reindex needed",
                                 "filename=<%s>", backup->index_fname);
                r = IMAP_MAILBOX_BADFORMAT;
                goto error;
            }
        }
    }

    backup->db = sqldb_open(backup->index_fname, backup_index_initsql,
                            backup_index_version, backup_index_upgrade,
                            SQLDB_DEFAULT_TIMEOUT);
    if (!backup->db) {
        r = IMAP_INTERNAL; // FIXME what does it mean to error here?
        goto error;
    }

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
    /* XXX convert CYRUSDB return code to IMAP */
    if (r) goto done;

    r = backup_real_open(backupp,
                         buf_cstring(&data_fname), buf_cstring(&index_fname),
                         BACKUP_OPEN_NOREINDEX, nonblock, create);
    if (r) goto done;

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

    if (!userid) userid = NOUSERID;

    if (!partition) {
        syslog(LOG_ERR,
               "unable to make backup path for %s: "
               "couldn't select partition",
               userid);
        return NULL;
    }

    char hash_buf[2];
    char *template = strconcat(partition,
                               "/", dir_hash_b(userid, config_fulldirhash, hash_buf),
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
    struct db *backups_db = NULL;
    struct txn *tid = NULL;

    int r = backupdb_open(&backups_db, &tid);
    if (r) return r;

    const char *userid = mbname_userid(mbname);
    const char *backup_path = NULL;
    size_t path_len = 0;

    if (!userid) userid = NOUSERID;

    r = cyrusdb_fetch(backups_db,
                      userid, strlen(userid),
                      &backup_path, &path_len,
                      &tid);

    if (r == CYRUSDB_NOTFOUND && create) {
        syslog(LOG_DEBUG, "%s not found in backups.db, creating new record", userid);
        backup_path = _make_path(mbname, NULL);
        if (!backup_path) {
            r = CYRUSDB_INTERNAL;
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
        r = CYRUSDB_INTERNAL;
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

    char *tmp = strconcat(data_fname, ".index", NULL);
    int r = backup_real_open(backupp, data_fname, tmp,
                             BACKUP_OPEN_NOREINDEX, nonblock, create);
    free(tmp);

    return r;
}

EXPORTED int backup_close(struct backup **backupp)
{
    struct backup *backup = *backupp;
    *backupp = NULL;

    gzFile gzfile = NULL;
    int r1 = 0, r2 = 0;

    if (!backup) return 0;

    if (backup->append_state) {
        if (backup->append_state->mode != BACKUP_APPEND_INACTIVE)
            r1 = backup_append_end(backup, NULL);

        gzfile = backup->append_state->gzfile;

        free(backup->append_state);
        backup->append_state = NULL;
    }

    if (backup->db) r2 = sqldb_close(&backup->db);

    if (backup->oldindex_fname) {
        if (r2) {
            /* something went wrong closing the new index, put the old one back */
            rename(backup->oldindex_fname, backup->index_fname);
        }
        else {
            if (!config_getswitch(IMAPOPT_BACKUP_KEEP_PREVIOUS)) {
                unlink(backup->oldindex_fname);
            }
        }
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
    if (backup->oldindex_fname) free(backup->oldindex_fname);

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

EXPORTED int backup_stat(const struct backup *backup,
                         struct stat *data_statp,
                         struct stat *index_statp)
{
    struct stat data_statbuf, index_statbuf;
    int r;

    r = fstat(backup->fd, &data_statbuf);
    if (r) {
        xsyslog(LOG_ERR, "IOERROR: fstat failed",
                         "filename=<%s>", backup->data_fname);
        return IMAP_IOERROR;
    }

    r = stat(backup->index_fname, &index_statbuf);
    if (r) {
        xsyslog(LOG_ERR, "IOERROR: stat failed",
                         "filename=<%s>", backup->index_fname);
        return IMAP_IOERROR;
    }

    if (data_statp)
        memcpy(data_statp, &data_statbuf, sizeof data_statbuf);
    if (index_statp)
        memcpy(index_statp, &index_statbuf, sizeof index_statbuf);

    return 0;
}

static ssize_t _prot_fill_cb(unsigned char *buf, size_t len, void *rock)
{
    struct gzuncat *gzuc = (struct gzuncat *) rock;
    int r = gzuc_read(gzuc, buf, len);

    if (r < 0)
        xsyslog(LOG_ERR, "IOERROR: gzuc_read failed",
                         "return=<%d>", r);
    if (r < -1)
        errno = EIO;

    return r;
}

EXPORTED int backup_reindex(const char *name,
                            enum backup_open_nonblock nonblock,
                            int verbose, FILE *out)
{
    struct buf data_fname = BUF_INITIALIZER;
    struct buf index_fname = BUF_INITIALIZER;
    struct backup *backup = NULL;
    int r;

    buf_printf(&data_fname, "%s", name);
    buf_printf(&index_fname, "%s.index", name);

    r = backup_real_open(&backup,
                         buf_cstring(&data_fname), buf_cstring(&index_fname),
                         BACKUP_OPEN_REINDEX, nonblock,
                         BACKUP_OPEN_NOCREATE);
    buf_free(&index_fname);
    buf_free(&data_fname);
    if (r) return r;

    struct gzuncat *gzuc = gzuc_new(backup->fd);

    time_t prev_member_ts = -1;

    struct buf cmd = BUF_INITIALIZER;
    while (gzuc && !gzuc_eof(gzuc)) {
        gzuc_member_start(gzuc);
        off_t member_offset = gzuc_member_offset(gzuc);

        if (verbose)
            fprintf(out, "\nfound chunk at offset " OFF_T_FMT "\n\n", member_offset);

        struct protstream *member = prot_readcb(_prot_fill_cb, gzuc);
        prot_setisclient(member, 1); /* don't sync literals */

        // FIXME stricter timestamp sequence checks
        time_t member_start_ts = -1;
        time_t member_end_ts = -1;
        time_t ts = -1;

        while (1) {
            struct dlist *dl = NULL;

            int c = parse_backup_line(member, &ts, &cmd, &dl);
            if (c == EOF) {
                const char *error = prot_error(member);
                if (error && 0 != strcmp(error, PROT_EOF_STRING)) {
                    syslog(LOG_ERR,
                           "IOERROR: %s: error reading chunk at offset " OFF_T_FMT ", byte %i: %s",
                           name, member_offset, prot_bytes_in(member), error);

                    if (out)
                        fprintf(out, "error reading chunk at offset " OFF_T_FMT ", byte %i: %s\n",
                                member_offset, prot_bytes_in(member), error);

                    r = IMAP_IOERROR;
                }
                member_end_ts = ts;
                break;
            }

            if (member_start_ts == -1) {
                if (prev_member_ts != -1 && prev_member_ts > ts) {
                    fatal("member timestamp older than previous", EX_DATAERR);
                }
                member_start_ts = ts;
                char file_sha1[2 * SHA1_DIGEST_LENGTH + 1];
                sha1_file(backup->fd, backup->data_fname, member_offset, file_sha1);
                backup_real_append_start(backup, member_start_ts,
                                         member_offset, file_sha1, 1, 0);
            }
            else if (member_start_ts > ts)
                fatal("line timestamp older than previous", EX_DATAERR);

            if (strcmp(buf_cstring(&cmd), "APPLY") != 0) {
                dlist_unlink_files(dl);
                dlist_free(&dl);
                continue;
            }

            ucase(dl->name);

            r = backup_append(backup, dl, &ts, BACKUP_APPEND_NOFLUSH);
            if (r) {
                // FIXME do something
                syslog(LOG_ERR, "backup_append returned %d", r);
                fprintf(out, "backup_append returned %d\n", r);
            }

            dlist_unlink_files(dl);
            dlist_free(&dl);
        }

        if (backup->append_state && backup->append_state->mode)
            backup_real_append_end(backup, member_end_ts);
        prot_free(member);
        gzuc_member_end(gzuc, NULL);

        prev_member_ts = member_start_ts;
    }
    buf_free(&cmd);

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
    struct db *backups_db = NULL;
    struct txn *tid = NULL;
    struct _rename_meta old = RENAME_META_INITIALIZER;
    struct _rename_meta new = RENAME_META_INITIALIZER;
    old.userid = mbname_userid(old_mbname);
    new.userid = mbname_userid(new_mbname);
    const char *path;
    size_t path_len;
    int r;

    if (!old.userid) old.userid = NOUSERID;
    if (!new.userid) new.userid = NOUSERID;

    /* bail out if the names are the same */
    if (strcmp(old.userid, new.userid) == 0)
        return 0;

    /* exclusively open backups database */
    r = backupdb_open(&backups_db, &tid);
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
        xsyslog(LOG_ERR, "IOERROR: open failed",
                         "filename=<%s>", old.fname);
        r = -1;
        goto error;
    }

    /* non-blocking, to avoid deadlock */
    r = lock_setlock(old.fd, /*excl*/ 1, /*nb*/ 1, old.fname);
    if (r) {
        xsyslog(LOG_ERR, "IOERROR: lock_setlock failed",
                         "filename=<%s>", old.fname);
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
    return r;
}
