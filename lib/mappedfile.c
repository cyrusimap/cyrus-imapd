/* mappedfile - interface to a mmaped, lockable, writable file
 *
 * Copyright (c) 1994-2008 Carnegie Mellon University.  All rights reserved.
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

#include "mappedfile.h"

#include <config.h>

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
   const char *map_base;
   size_t map_size;
   size_t map_len;

   /* the file itself */
   ino_t map_ino;
   int fd;

   /* tracking */
   int lock_status;
   int dirty;
};

static void _ensure_mapped(struct mappedfile *mf, size_t offset)
{
    /* we may be rewriting inside a file, so don't shrink, only extent */
    if (offset > mf->map_size) {
	mf->map_size = offset;
	map_refresh(mf->fd, 0, &mf->map_base, &mf->map_len, mf->map_size,
		    mf->fname, 0);
    }
}

/* NOTE - we don't provide any guarantees that the file isn't open multiple
 * times.  So don't do that.  It will mess with your locking no end */
int mappedfile_open(struct mappedfile **mfp,
		    const char *fname, int create)
{
    struct mappedfile *mf;
    struct stat sbuf;
    int r;

    assert(fname);
    assert(!*mfp);

    mf = xzmalloc(sizeof(struct mappedfile));
    mf->fname = xstrdup(fname);

    mf->fd = open(mf->fname, O_RDWR, 0644);
    if (mf->fd < 0 && errno == ENOENT) {
	if (!create) {
	    r = MF_NOTFOUND;
	    goto err;
	}
	if (cyrus_mkdir(mf->fname, 0755) < 0) {
	    syslog(LOG_ERR, "IOERROR: cyrus_mkdir %s: %m", mf->fname);
	    r = MF_IOERROR;
	    goto err;
	}
	mf->fd = open(mf->fname, O_RDWR | O_CREAT, 0644);
    }

    if (mf->fd == -1) {
	syslog(LOG_ERR, "IOERROR: open %s: %m", mf->fname);
	goto err;
    }

    /* it's zero, but set it anyway */
    mf->lock_status = MF_UNLOCKED;
    mf->dirty = 0;

    if (fstat(mf->fd, &sbuf) < 0) {
	syslog(LOG_ERR, "IOERROR: fstat %s: %m", mf->fname);
	r = MF_IOERROR;
	goto err;
    }

    _ensure_mapped(mf, sbuf.st_size);

    *mfp = mf;

    return 0;

err:
    free(mf->fname);
    free(mf);
    return r;
}

int mappedfile_close(struct mappedfile **mfp)
{
    struct mappedfile *mf = *mfp;
    int r;

    /* make this safe to call multiple times */
    if (!mf) return 0;

    assert(mf->lock_status == MF_UNLOCKED);
    assert(mf->fd != -1);
    assert(!mf->dirty);

    r = close(mf->fd);
    if (r) return MF_IOERROR; /* XXX - scream and shout */

    free(mf->fname);
    map_free(&mf->map_base, &mf->map_len);

    free(mf);

    *mfp = NULL;

    return 0;
}

int mappedfile_readlock(struct mappedfile *mf)
{
    struct stat sbuf, sbuffile;
    int newfd = -1;

    assert(mf);
    assert(mf->lock_status == MF_UNLOCKED);
    assert(mf->fd != -1);
    assert(!mf->dirty);

    for (;;) {
	if (lock_shared(mf->fd) < 0) {
	    syslog(LOG_ERR, "IOERROR: lock_shared %s: %m", mf->fname);
	    return MF_IOERROR;
	}

	if (fstat(mf->fd, &sbuf) == -1) {
	    syslog(LOG_ERR, "IOERROR: fstat %s: %m", mf->fname);
	    lock_unlock(mf->fd);
	    return MF_IOERROR;
	}

	if (stat(mf->fname, &sbuffile) == -1) {
	    syslog(LOG_ERR, "IOERROR: stat %s: %m", mf->fname);
	    lock_unlock(mf->fd);
	    return MF_IOERROR;
	}
	if (sbuf.st_ino == sbuffile.st_ino) break;

	newfd = open(mf->fname, O_RDWR, 0644);
	if (newfd == -1) {
	    syslog(LOG_ERR, "IOERROR: open %s: %m", mf->fname);
	    lock_unlock(mf->fd);
	    return MF_IOERROR;
	}

	dup2(newfd, mf->fd);
	close(newfd);
    }

    mf->lock_status = MF_READLOCKED;

    /* XXX - can we guarantee the fd isn't reused? */
    if (mf->map_ino != sbuf.st_ino) {
	mf->map_size = 0;
	map_free(&mf->map_base, &mf->map_len);
	mf->map_ino = sbuf.st_ino;
    }

    _ensure_mapped(mf, sbuf.st_size);

    return 0;
}

int mappedfile_writelock(struct mappedfile *mf)
{
    struct stat sbuf;
    const char *lockfailaction;

    assert(mf);
    assert(mf->lock_status == MF_UNLOCKED);
    assert(mf->fd != -1);
    assert(!mf->dirty);

    if (lock_reopen(mf->fd, mf->fname, &sbuf, &lockfailaction) < 0) {
	syslog(LOG_ERR, "IOERROR: %s %s: %m", lockfailaction, mf->fname);
	return MF_IOERROR;
    }
    mf->lock_status = MF_WRITELOCKED;

    /* XXX - can we guarantee the fd isn't reused? */
    if (mf->map_ino != sbuf.st_ino) {
	mf->map_size = 0;
	map_free(&mf->map_base, &mf->map_len);
	mf->map_ino = sbuf.st_ino;
    }

    _ensure_mapped(mf, sbuf.st_size);

    return 0;
}

int mappedfile_unlock(struct mappedfile *mf)
{
    assert(mf);
    assert(mf->fd != -1);
    assert(!mf->dirty);

    /* make this safe to call multiple times */
    if (!mf) return 0;
    if (mf->lock_status == MF_UNLOCKED) return 0;

    if (lock_unlock(mf->fd) < 0) {
	syslog(LOG_ERR, "IOERROR: lock_unlock %s: %m", mf->fname);
	return MF_IOERROR;
    }

    mf->lock_status = MF_UNLOCKED;

    return 0;
}

int mappedfile_commit(struct mappedfile *mf)
{
    assert(mf);
    assert(mf->lock_status == MF_WRITELOCKED);
    assert(mf->fd != -1);

    if (!mf->dirty)
	return 0; /* nice, nothing to do */

    if (fdatasync(mf->fd) < 0) {
	syslog(LOG_ERR, "IOERROR: %s fsync: %m", mf->fname);
	return MF_IOERROR;
    }

    mf->dirty = 0;

    return 0;
}

int mappedfile_write(struct mappedfile *mf, size_t *offsetp,
		     const char *base, size_t len)
{
    int n;

    assert(mf);
    assert(mf->lock_status == MF_WRITELOCKED);
    assert(mf->fd != -1);
    assert(offsetp);
    assert(base);

    if (!len) return 0; /* nothing to write! */

    /* XXX - memcmp and don't both writing if it matches? */

    mf->dirty++;

    /* locate the file handle */
    n = lseek(mf->fd, *offsetp, SEEK_SET);
    if (n < 0) return MF_IOERROR;

    /* write the buffer */
    n = retry_write(mf->fd, base, len);
    if (n < 0) return MF_IOERROR;

    *offsetp += n;

    _ensure_mapped(mf, *offsetp);

    return 0;
}

int mappedfile_writev(struct mappedfile *mf, size_t *offsetp,
		      const struct iovec *iov, int nio)
{
    int n;

    assert(mf);
    assert(mf->lock_status == MF_WRITELOCKED);
    assert(mf->fd != -1);
    assert(offsetp);
    assert(iov);

    if (!nio) return 0; /* nothing to write! */

    /* XXX - memcmp and don't both writing if it matches? */

    mf->dirty++;

    /* locate the file handle */
    n = lseek(mf->fd, *offsetp, SEEK_SET);
    if (n < 0) return MF_IOERROR;

    /* write the buffer */
    n = retry_writev(mf->fd, iov, nio);
    if (n < 0) return MF_IOERROR;

    *offsetp += n;

    _ensure_mapped(mf, *offsetp);

    return 0;
}

int mappedfile_truncate(struct mappedfile *mf, size_t offset)
{
    int r;

    assert(mf);
    assert(mf->lock_status == MF_WRITELOCKED);
    assert(mf->fd != -1);

    mf->dirty++;

    if (offset < mf->map_size) mf->map_size = offset;

    r = ftruncate(mf->fd, mf->map_size);
    if (r < 0) {
	syslog(LOG_ERR, "IOERROR: ftruncate %s: %m", mf->fname);
	return MF_IOERROR;
    }

    _ensure_mapped(mf, offset);

    return 0;
}

int mappedfile_rename(struct mappedfile *mf, const char *newname)
{
    int r;

    r = rename(mf->fname, newname);
    if (r < 0) {
	syslog(LOG_ERR, "IOERROR: rename (%s, %s): %m", mf->fname, newname);
	return MF_IOERROR;
    }

    /* XXX - fsync? */

    free(mf->fname);
    mf->fname = xstrdup(newname);

    return 0;
}


int mappedfile_islocked(struct mappedfile *mf)
{
    assert(mf);

    return (mf->lock_status != MF_UNLOCKED);
}

int mappedfile_isreadlocked(struct mappedfile *mf)
{
    assert(mf);

    return (mf->lock_status == MF_READLOCKED);
}

int mappedfile_iswritelocked(struct mappedfile *mf)
{
    assert(mf);

    return (mf->lock_status == MF_WRITELOCKED);
}

const char *mappedfile_base(struct mappedfile *mf)
{
    assert(mf);

    /* XXX - require locked? */
    return mf->map_base;
}

size_t mappedfile_size(struct mappedfile *mf)
{
    assert(mf);

    return mf->map_size;
}

const char *mappedfile_fname(struct mappedfile *mf)
{
    assert(mf);

    return mf->fname;
}
