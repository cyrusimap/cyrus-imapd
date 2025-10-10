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
