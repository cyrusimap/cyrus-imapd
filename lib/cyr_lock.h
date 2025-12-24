/* cyr_lock.h -- file locking primitives */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef INCLUDED_LOCK_H
#define INCLUDED_LOCK_H

#include <sys/stat.h>

extern const char lock_method_desc[];

extern double debug_locks_longer_than;

extern int lock_reopen_ex(int fd, const char *filename,
                          struct stat *sbuf, const char **failaction,
                          int *changed);
#define lock_reopen(fd, filename, sbuf, failaction) \
        lock_reopen_ex(fd, filename, sbuf, failaction, NULL)

extern int lock_setlock(int fd, int ex, int nb, const char *filename);
extern int lock_unlock(int fd, const char *filename);

/* compatibility defines for the older API */
#define lock_blocking(fd, fn) \
    lock_setlock((fd), /*exclusive*/1, /*blocking*/0, (fn))
#define lock_nonblocking(fd, fn) \
    lock_setlock((fd), /*exclusive*/1, /*nonblocking*/1, (fn))
#define lock_shared(fd, fn) \
    lock_setlock((fd), /*exclusive*/0, /*nonblocking*/0, (fn))

#endif /* INCLUDED_LOCK_H */
