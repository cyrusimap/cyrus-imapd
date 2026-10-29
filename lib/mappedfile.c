/* mappedfile - interface to a mmaped, lockable, writable file */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

/* Interface to an mmaped file, including locking.
 *
 * Many different modules within Cyrus, including most of the
 * database engines, wrap an mmaped file with locking semantics,
 * refreshing the map on re-locking, and writing to a location
 * within the file.
 *
 * This module provides handy wrapper interfaces to each of those
 * items.  NOTE - it doesn't provide a guarantee that the same file
 * isn't opened twice, stomping all over the locks in the process.
 * To get that, you need to protect in the caller.
 *
 */


#include "mappedfile.h"

#include <config.h>

#include <libgen.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "assert.h"
#include "cyr_lock.h"
#include "libcyr_cfg.h"
#include "map.h"
#include "retry.h"
#include "util.h"
#include "xmalloc.h"

static void _ensure_mapped(struct mappedfile *mf, size_t offset, int update)
{
    /* we may be rewriting inside a file, so don't shrink, only extend */
    if (update) {
        if (offset > mf->map_size)
            mf->was_resized = 1;
        else
            offset = mf->map_size;
    }

    /* always give refresh another go, we may be map_nommap */
    buf_refresh_mmap(&mf->map_buf, /*onceonly*/0, mf->fd, mf->fname,
                  offset, /*mboxname*/NULL);

    mf->map_size = offset;
}

/* NOTE - we don't provide any guarantees that the file isn't open multiple
 * times.  So don't do that.  It will mess with your locking no end */
EXPORTED int mappedfile_open(struct mappedfile **mfp,
                             const char *fname, int flags)
{
    struct mappedfile *mf;
    struct stat sbuf;
    int openmode = (flags & MAPPEDFILE_RW) ? O_RDWR : O_RDONLY;
    int create = (flags & MAPPEDFILE_CREATE) ? 1 : 0;
    int r = -1;

    assert(fname);
    assert(!*mfp);

    mf = xzmalloc(sizeof(struct mappedfile));
    mf->fname = xstrdup(fname);
    mf->is_rw = (flags & MAPPEDFILE_RW) ? 1 : 0;

    mf->fd = open(mf->fname, openmode, 0644);
    if (mf->fd < 0 && errno == ENOENT) {
        if (!create || !mf->is_rw) {
            r = -errno;
            goto err;
        }
        int dirfd = xopendir(mf->fname, /*create*/1);
        if (dirfd < 0) {
            xsyslog_ev(LOG_ERR, "mappedfile.open.failed",
                       lf_s("mappedfile.step", "opendir"),
                       lf_s("sys.path", mf->fname));
            goto err;
        }
        char *copy = xstrdup(mf->fname);
        const char *leaf = basename(copy);
        mf->fd = openat(dirfd, leaf, O_RDWR | O_CREAT, 0644);
        free(copy);
        if (mf->fd >= 0) {
            if (fsync(dirfd) < 0) {
                xsyslog_ev(LOG_ERR, "mappedfile.open.failed",
                           lf_s("mappedfile.step", "fsync_dir"),
                           lf_s("sys.path", mf->fname));
                close(dirfd);
                goto err;
            }
        }
        close(dirfd);
    }

    if (mf->fd == -1) {
        xsyslog_ev(LOG_ERR, "mappedfile.open.failed",
                   lf_s("mappedfile.step", "open"),
                   lf_s("sys.path", mf->fname));
        r = -errno;
        goto err;
    }

    /* it's zero, but set it anyway */
    mf->lock_status = MF_UNLOCKED;
    mf->dirty = 0;

    r = fstat(mf->fd, &sbuf);
    if (r < 0) {
        xsyslog_ev(LOG_ERR, "mappedfile.open.failed",
                   lf_s("mappedfile.step", "fstat"),
                   lf_s("sys.path", mf->fname));
        goto err;
    }

    _ensure_mapped(mf, sbuf.st_size, /*update*/0);

    *mfp = mf;

    return 0;

err:
    mappedfile_close(&mf);
    return r;
}

EXPORTED int mappedfile_close(struct mappedfile **mfp)
{
    struct mappedfile *mf = *mfp;
    int r = 0;

    /* make this safe to call multiple times */
    if (!mf) return 0;

    assert(mf->lock_status == MF_UNLOCKED);
    assert(!mf->dirty);

    if (mf->fd >= 0)
        r = close(mf->fd);

    buf_free(&mf->map_buf);
    free(mf->fname);
    free(mf);

    *mfp = NULL;

    return r;
}

EXPORTED int mappedfile_readlock(struct mappedfile *mf)
{
    struct stat sbuf, sbuffile;
    int newfd = -1;

    assert(mf->lock_status == MF_UNLOCKED);
    assert(mf->fd != -1);
    assert(!mf->dirty);

    for (;;) {
        if (lock_shared(mf->fd, mf->fname) < 0) {
            xsyslog_ev(LOG_ERR, "mappedfile.lock.failed",
                       lf_s("mappedfile.step", "lock_shared"),
                       lf_s("sys.path", mf->fname));
            return -EIO;
        }

        if (fstat(mf->fd, &sbuf) == -1) {
            xsyslog_ev(LOG_ERR, "mappedfile.lock.failed",
                       lf_s("mappedfile.step", "fstat"),
                       lf_s("sys.path", mf->fname));
            lock_unlock(mf->fd, mf->fname);
            return -EIO;
        }

        if (stat(mf->fname, &sbuffile) == -1) {
            xsyslog_ev(LOG_ERR, "mappedfile.lock.failed",
                       lf_s("mappedfile.step", "stat"),
                       lf_s("sys.path", mf->fname));
            lock_unlock(mf->fd, mf->fname);
            return -EIO;
        }
        if (sbuf.st_ino == sbuffile.st_ino) break;
        buf_free(&mf->map_buf);

        newfd = open(mf->fname, O_RDWR, 0644);
        if (newfd == -1) {
            xsyslog_ev(LOG_ERR, "mappedfile.lock.failed",
                       lf_s("mappedfile.step", "open"),
                       lf_s("sys.path", mf->fname));
            lock_unlock(mf->fd, mf->fname);
            return -EIO;
        }

        dup2(newfd, mf->fd);
        close(newfd);
    }

    mf->lock_status = MF_READLOCKED;
    gettimeofday(&mf->starttime, 0);

    _ensure_mapped(mf, sbuf.st_size, /*update*/0);

    return 0;
}

EXPORTED int mappedfile_writelock(struct mappedfile *mf)
{
    int r;
    struct stat sbuf;
    const char *lockfailaction;
    int changed = 0;

    assert(mf->lock_status == MF_UNLOCKED);
    assert(mf->fd != -1);
    assert(mf->is_rw);
    assert(!mf->dirty);

    r = lock_reopen_ex(mf->fd, mf->fname, &sbuf, &lockfailaction, &changed);
    if (r < 0) {
        xsyslog_ev(LOG_ERR, "mappedfile.lock.failed",
                   lf_s("mappedfile.step", "lock_reopen"),
                   lf_s("sys.path", mf->fname),
                   lf_s("mappedfile.lock.action", lockfailaction));
        return r;
    }
    mf->lock_status = MF_WRITELOCKED;
    gettimeofday(&mf->starttime, 0);

    if (changed) buf_free(&mf->map_buf);

    _ensure_mapped(mf, sbuf.st_size, /*update*/0);

    return 0;
}

EXPORTED int mappedfile_unlock(struct mappedfile *mf)
{
    struct timeval endtime;
    double timediff;

    int r;

    /* make this safe to call multiple times */
    if (!mf) return 0;
    if (mf->lock_status == MF_UNLOCKED) return 0;

    assert(mf->fd != -1);
    assert(!mf->dirty);

    r = lock_unlock(mf->fd, mf->fname);
    if (r < 0) {
        xsyslog_ev(LOG_ERR, "mappedfile.unlock.failed",
                   lf_s("mappedfile.step", "lock_unlock"),
                   lf_s("sys.path", mf->fname));
        return r;
    }

    mf->lock_status = MF_UNLOCKED;
    gettimeofday(&endtime, 0);
    timediff = timesub(&mf->starttime, &endtime);
    if (timediff > 1.0) {
        xsyslog_ev(LOG_NOTICE, "mappedfile.lock.long",
                   lf_s("sys.path", mf->fname),
                   lf_duration("mappedfile.lock.duration", timediff));
    }

    return 0;
}

EXPORTED int mappedfile_commit(struct mappedfile *mf)
{
    assert(mf->fd != -1);

    if (!mf->dirty)
        return 0; /* nice, nothing to do */

    assert(mf->is_rw);

    if (mf->was_resized) {
        if (fsync(mf->fd) < 0) {
            xsyslog_ev(LOG_ERR, "mappedfile.commit.failed",
                       lf_s("mappedfile.step", "fsync"),
                       lf_s("sys.path", mf->fname));
            return -EIO;
        }
    }
    else {
        if (fdatasync(mf->fd) < 0) {
            xsyslog_ev(LOG_ERR, "mappedfile.commit.failed",
                       lf_s("mappedfile.step", "fdatasync"),
                       lf_s("sys.path", mf->fname));
            return -EIO;
        }
    }

    mf->dirty = 0;
    mf->was_resized = 0;

    return 0;
}

EXPORTED ssize_t mappedfile_pwrite(struct mappedfile *mf,
                                   const void *base, size_t len,
                                   off_t offset)
{
    ssize_t written;
    off_t pos;

    assert(mf->is_rw);
    assert(mf->fd != -1);
    assert(base);

    if (!len) return 0; /* nothing to write! */

    /* XXX - memcmp and don't both writing if it matches? */

    mf->dirty++;

    /* locate the file handle */
    pos = lseek(mf->fd, offset, SEEK_SET);
    if (pos < 0) {
        xsyslog_ev(LOG_ERR, "mappedfile.write.failed",
                   lf_s("mappedfile.step", "lseek"),
                   lf_s("sys.path", mf->fname),
                   lf_lld("mappedfile.offset", (long long) offset));
        return -1;
    }

    /* write the buffer */
    written = retry_write(mf->fd, base, len);
    if (written < 0) {
        xsyslog_ev(LOG_ERR, "mappedfile.write.failed",
                   lf_s("mappedfile.step", "write"),
                   lf_s("sys.path", mf->fname),
                   lf_zu("mappedfile.length", len),
                   lf_lld("mappedfile.offset", (long long) offset));
        return -1;
    }

    _ensure_mapped(mf, pos+written, /*update*/1);

    return written;
}

EXPORTED ssize_t mappedfile_pwritebuf(struct mappedfile *mf,
                                      const struct buf *buf,
                                      off_t offset)
{
    return mappedfile_pwrite(mf, buf->s, buf->len, offset);
}

EXPORTED ssize_t mappedfile_pwritev(struct mappedfile *mf,
                                    const struct iovec *iov, int nio,
                                    off_t offset)
{
    ssize_t written;
    off_t pos;

    assert(mf->is_rw);
    assert(mf->fd != -1);
    assert(iov);

    if (!nio) return 0; /* nothing to write! */

    /* XXX - memcmp and don't both writing if it matches? */

    mf->dirty++;

    /* locate the file handle */
    pos = lseek(mf->fd, offset, SEEK_SET);
    if (pos < 0) {
        xsyslog_ev(LOG_ERR, "mappedfile.write.failed",
                   lf_s("mappedfile.step", "lseek"),
                   lf_s("sys.path", mf->fname),
                   lf_lld("mappedfile.offset", (long long) offset));
        return -1;
    }

    /* write the buffer */
    written = retry_writev(mf->fd, iov, nio);
    if (written < 0) {
        size_t len = 0;
        int i;
        for (i = 0; i < nio; i++) {
            len += iov[i].iov_len;
        }
        xsyslog_ev(LOG_ERR, "mappedfile.write.failed",
                   lf_s("mappedfile.step", "writev"),
                   lf_s("sys.path", mf->fname),
                   lf_zu("mappedfile.length", len),
                   lf_lld("mappedfile.offset", (long long) offset));
        return -1;
    }

    _ensure_mapped(mf, pos+written, /*update*/1);

    return written;
}

EXPORTED int mappedfile_truncate(struct mappedfile *mf, off_t offset)
{
    int r;

    assert(mf->is_rw);
    assert(mf->fd != -1);

    mf->dirty++;

    r = ftruncate(mf->fd, offset);
    if (r < 0) {
        xsyslog_ev(LOG_ERR, "mappedfile.truncate.failed",
                   lf_s("mappedfile.step", "ftruncate"),
                   lf_s("sys.path", mf->fname));
        return r;
    }

    _ensure_mapped(mf, offset, /*update*/0);
    mf->was_resized = 1; /* force the fsync */

    return 0;
}

EXPORTED int mappedfile_rename(struct mappedfile *mf, const char *newname)
{
    int r = cyrus_rename(mf->fname, newname);
    if (r < 0) {
        xsyslog_ev(LOG_ERR, "mappedfile.rename.failed",
                   lf_s("old.sys.path", mf->fname),
                   lf_s("sys.path", newname));
        return r;
    }

    // rename done
    free(mf->fname);
    mf->fname = xstrdup(newname);
    return 0;
}
