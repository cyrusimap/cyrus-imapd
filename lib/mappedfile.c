/* mappedfile - interface to a mmaped, lockable, writable file
 *
 * Copyright (c) 1994-2011 Carnegie Mellon University.  All rights reserved.
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
 */

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

#define MF_UNLOCKED 0
#define MF_READLOCKED 1
#define MF_WRITELOCKED 2

struct mappedfile {
    char *fname;

    /* obviously you will need 64 bit size_t for 64 bit files... */
    struct buf map_buf;
    size_t map_size;

    /* the file itself */
    int fd;

    /* tracking */
    int lock_status;
    int dirty;
    int was_resized;
    int is_rw;
};

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
    buf_init_mmap(&mf->map_buf, /*onceonly*/0, mf->fd, mf->fname,
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
    int r;

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
        r = cyrus_mkdir(mf->fname, 0755);
        if (r < 0) {
            syslog(LOG_ERR, "IOERROR: cyrus_mkdir %s: %m", mf->fname);
            goto err;
        }
        mf->fd = open(mf->fname, O_RDWR | O_CREAT, 0644);
    }

    if (mf->fd == -1) {
        syslog(LOG_ERR, "IOERROR: open %s: %m", mf->fname);
        r = -errno;
        goto err;
    }

    /* it's zero, but set it anyway */
    mf->lock_status = MF_UNLOCKED;
    mf->dirty = 0;

    r = fstat(mf->fd, &sbuf);
    if (r < 0) {
        syslog(LOG_ERR, "IOERROR: fstat %s: %m", mf->fname);
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
            syslog(LOG_ERR, "IOERROR: lock_shared %s: %m", mf->fname);
            return -EIO;
        }

        if (fstat(mf->fd, &sbuf) == -1) {
            syslog(LOG_ERR, "IOERROR: fstat %s: %m", mf->fname);
            lock_unlock(mf->fd, mf->fname);
            return -EIO;
        }

        if (stat(mf->fname, &sbuffile) == -1) {
            syslog(LOG_ERR, "IOERROR: stat %s: %m", mf->fname);
            lock_unlock(mf->fd, mf->fname);
            return -EIO;
        }
        if (sbuf.st_ino == sbuffile.st_ino) break;
        buf_free(&mf->map_buf);

        newfd = open(mf->fname, O_RDWR, 0644);
        if (newfd == -1) {
            syslog(LOG_ERR, "IOERROR: open %s: %m", mf->fname);
            lock_unlock(mf->fd, mf->fname);
            return -EIO;
        }

        dup2(newfd, mf->fd);
        close(newfd);
    }

    mf->lock_status = MF_READLOCKED;

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
        syslog(LOG_ERR, "IOERROR: %s %s: %m", lockfailaction, mf->fname);
        return r;
    }
    mf->lock_status = MF_WRITELOCKED;

    if (changed) buf_free(&mf->map_buf);

    _ensure_mapped(mf, sbuf.st_size, /*update*/0);

    return 0;
}

EXPORTED int mappedfile_unlock(struct mappedfile *mf)
{
    int r;

    /* make this safe to call multiple times */
    if (!mf) return 0;
    if (mf->lock_status == MF_UNLOCKED) return 0;

    assert(mf->fd != -1);
    assert(!mf->dirty);

    r = lock_unlock(mf->fd, mf->fname);
    if (r < 0) {
        syslog(LOG_ERR, "IOERROR: lock_unlock %s: %m", mf->fname);
        return r;
    }

    mf->lock_status = MF_UNLOCKED;

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
            syslog(LOG_ERR, "IOERROR: %s fsync: %m", mf->fname);
            return -EIO;
        }
    }
    else {
        if (fdatasync(mf->fd) < 0) {
            syslog(LOG_ERR, "IOERROR: %s fdatasync: %m", mf->fname);
            return -EIO;
        }
    }

    mf->dirty = 0;
    mf->was_resized = 0;

    return 0;
}

EXPORTED ssize_t mappedfile_pwrite(struct mappedfile *mf,
                                   const char *base, size_t len,
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
        syslog(LOG_ERR, "IOERROR: %s seek to %llX: %m", mf->fname,
               (long long unsigned int)offset);
        return -1;
    }

    /* write the buffer */
    written = retry_write(mf->fd, base, len);
    if (written < 0) {
        syslog(LOG_ERR, "IOERROR: %s write %llu bytes at %llX: %m",
               mf->fname, (long long unsigned int)len,
               (long long unsigned int)offset);
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
        syslog(LOG_ERR, "IOERROR: %s seek to %llX: %m", mf->fname,
               (long long unsigned int)offset);
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
        syslog(LOG_ERR, "IOERROR: %s write %llu bytes at %llX: %m",
               mf->fname, (long long unsigned int)len,
               (long long unsigned int)offset);
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
        syslog(LOG_ERR, "IOERROR: ftruncate %s: %m", mf->fname);
        return r;
    }

    _ensure_mapped(mf, offset, /*update*/0);
    mf->was_resized = 1; /* force the fsync */

    return 0;
}

EXPORTED int mappedfile_rename(struct mappedfile *mf, const char *newname)
{
    char *copy = xstrdup(newname);
    const char *dir = dirname(copy);
    int r = 0;

#if defined(O_DIRECTORY)
    int dirfd = open(dir, O_RDONLY|O_DIRECTORY, 0600);
#else
    int dirfd = open(dir, O_RDONLY, 0600);
#endif
    if (dirfd < 0) {
        syslog(LOG_ERR, "IOERROR: mappedfile opendir (%s, %s): %m", mf->fname, newname);
        r = dirfd;
        goto done;
    }

    r = rename(mf->fname, newname);
    if (r < 0) {
        syslog(LOG_ERR, "IOERROR: mappedfile rename (%s, %s): %m", mf->fname, newname);
        goto done;
    }

    r = fsync(dirfd);
    if (r < 0) {
        syslog(LOG_ERR, "IOERROR: mappedfile rename (%s, %s): %m", mf->fname, newname);
        goto done;
    }

    free(mf->fname);
    mf->fname = xstrdup(newname);

 done:
    if (dirfd >= 0) close(dirfd);
    free(copy);
    return r;
}


EXPORTED int mappedfile_islocked(const struct mappedfile *mf)
{
    return (mf->lock_status != MF_UNLOCKED);
}

//FIXME this function is nowhere used
EXPORTED int mappedfile_isreadlocked(const struct mappedfile *mf)
{
    return (mf->lock_status == MF_READLOCKED);
}

EXPORTED int mappedfile_iswritelocked(const struct mappedfile *mf)
{
    return (mf->lock_status == MF_WRITELOCKED);
}

EXPORTED int mappedfile_iswritable(const struct mappedfile *mf)
{
    return !!mf->is_rw;
}

EXPORTED const char *mappedfile_base(const struct mappedfile *mf)
{
    /* XXX - require locked? */
    return mf->map_buf.s;
}

EXPORTED size_t mappedfile_size(const struct mappedfile *mf)
{
    return mf->map_size;
}

EXPORTED const struct buf *mappedfile_buf(const struct mappedfile *mf)
{
    return &mf->map_buf;
}

EXPORTED const char *mappedfile_fname(const struct mappedfile *mf)
{
    return mf->fname;
}
