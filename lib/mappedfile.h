/* mappedfile - interface to a mmaped, lockable, writable file */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef _MAPPEDFILE_H
#define _MAPPEDFILE_H

// includes
#include "buf.h"
#include <sys/types.h>
#include <sys/uio.h>

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

    struct timeval starttime;
};

#define MAPPEDFILE_CREATE (1<<0)
#define MAPPEDFILE_RW     (1<<1)

#define MF_UNLOCKED 0
#define MF_READLOCKED 1
#define MF_WRITELOCKED 2

extern int mappedfile_open(struct mappedfile **mfp,
                           const char *fname, int flags);
extern int mappedfile_close(struct mappedfile **mfp);

extern int mappedfile_readlock(struct mappedfile *mf);
extern int mappedfile_writelock(struct mappedfile *mf);
extern int mappedfile_unlock(struct mappedfile *mf);

extern int mappedfile_commit(struct mappedfile *mf);
extern ssize_t mappedfile_pwrite(struct mappedfile *mf,
                                 const void *base, size_t len,
                                 off_t offset);
extern ssize_t mappedfile_pwritebuf(struct mappedfile *mf,
                                    const struct buf *buf,
                                    off_t offset);
extern ssize_t mappedfile_pwritev(struct mappedfile *mf,
                                  const struct iovec *iov, int nio,
                                  off_t offset);
extern int mappedfile_truncate(struct mappedfile *mf, off_t offset);

extern int mappedfile_rename(struct mappedfile *mf, const char *newname);

#define mappedfile_islocked(mf) ((mf)->lock_status != MF_UNLOCKED)
#define mappedfile_isreadlocked(mf) ((mf)->lock_status == MF_READLOCKED)
#define mappedfile_iswritelocked(mf) ((mf)->lock_status == MF_WRITELOCKED)
#define mappedfile_iswritable(mf) (!!(mf)->is_rw)
#define mappedfile_base(mf) ((const char *)((mf)->map_buf.s))
#define mappedfile_size(mf) ((mf)->map_size)
#define mappedfile_buf(mf) ((const struct buf *)(&((mf)->map_buf)))
#define mappedfile_fname(mf) ((const char *)((mf)->fname))


#endif /* _MAPPEDFILE_H */
