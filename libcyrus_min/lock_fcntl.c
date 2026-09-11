/* lock_fcntl.c - Lock files using fcntl() */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include "cyr_lock.h"

#include <syslog.h>
#include <time.h>

EXPORTED const char lock_method_desc[] = "fcntl";

EXPORTED double debug_locks_longer_than = 0.0;

/*
 * Block until we obtain an exclusive lock on the file descriptor 'fd',
 * opened for reading and writing on the file named 'filename'.  If
 * 'filename' is replaced, will re-open it as 'fd' and acquire a lock
 * on the new file.
 *
 * On success, returns 0.  If a pointer to a struct stat is given as
 * 'sbuf', it is filled in.
 *
 * On failure, returns -1 with an error code in errno.  If
 * 'failaction' is provided, it is filled in with a pointer to a fixed
 * string naming the action that failed.
 *
 */
EXPORTED int lock_reopen_ex(int fd, const char *filename,
                            struct stat *sbuf, const char **failaction,
                            int *changed)
{
    int r;
    struct flock fl;
    struct stat sbuffile, sbufspare;
    int newfd;
    struct timeval starttime;
    if (debug_locks_longer_than)
        gettimeofday(&starttime, 0);


    if (!sbuf) sbuf = &sbufspare;

    for (;;) {
        fl.l_type= F_WRLCK;
        fl.l_whence = SEEK_SET;
        fl.l_start = 0;
        fl.l_len = 0;
        r = fcntl(fd, F_SETLKW, &fl);
        if (r == -1) {
            if (errno == EINTR) continue;
            if (failaction) *failaction = "locking";
            return -1;
        }

        r = fstat(fd, sbuf);
        if (!r) r = stat(filename, &sbuffile);
        if (r == -1) {
            if (failaction) *failaction = "stating";
            r = lock_unlock(fd, filename);
            return -1;
        }

        if (sbuf->st_ino == sbuffile.st_ino) {
            if (debug_locks_longer_than) {
                struct timeval endtime;
                gettimeofday(&endtime, 0);
                double locktime = (double)(endtime.tv_sec - starttime.tv_sec) +
                                  (double)(endtime.tv_usec - starttime.tv_usec)/1000000.0;
                if (locktime > debug_locks_longer_than) /* 10ms */
                    syslog(LOG_NOTICE, "locktimer: reopen %s (%0.2fs)", filename, locktime);
            }
            return 0;
        }

        if (changed) *changed = 1;

        newfd = open(filename, O_RDWR);
        if (newfd == -1) {
            if (failaction) *failaction = "opening";
            r = lock_unlock(fd, filename);
            return -1;
        }
        dup2(newfd, fd);
        close(newfd);
    }
}

/*
 * Obtain a lock on 'fd'.  The lock is exclusive if 'exclusive'
 * is true, otherwise shared.  Normally blocks until a lock is
 * obtained, but if 'nonblock' is true does not block and instead
 * fails with errno=EWOUDBLOCK if the lock cannot be obtained.
 *
 * Returns 0 for success, -1 for failure, with errno set to an
 * appropriate error code.
 */
EXPORTED int lock_setlock(int fd, int exclusive, int nonblock,
                          const char *filename)
{
    int r;
    struct flock fl;
    int type = (exclusive ? F_WRLCK : F_RDLCK);
    int cmd = (nonblock ? F_SETLK : F_SETLKW);
    struct timeval starttime;
    if (debug_locks_longer_than)
        gettimeofday(&starttime, 0);

    for (;;) {
        fl.l_type= type;
        fl.l_whence = SEEK_SET;
        fl.l_start = 0;
        fl.l_len = 0;
        r = fcntl(fd, cmd, &fl);
        if (r != -1) {
            if (debug_locks_longer_than) {
                struct timeval endtime;
                gettimeofday(&endtime, 0);
                double locktime = (double)(endtime.tv_sec - starttime.tv_sec) +
                                  (double)(endtime.tv_usec - starttime.tv_usec)/1000000.0;
                if (locktime > debug_locks_longer_than)
                    syslog(LOG_NOTICE, "locktimer: reopen %s (%0.2fs)", filename, locktime);
            }
            return 0;
        }
        if (errno == EINTR) continue;
        return -1;
    }
}

/*
 * Release any lock on 'fd'.  Always returns success.
 */
EXPORTED int lock_unlock(int fd, const char *filename __attribute__((unused)))
{
    struct flock fl;
    int r;

    fl.l_type= F_UNLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start = 0;
    fl.l_len = 0;

    for (;;) {
        r = fcntl(fd, F_SETLKW, &fl);
        if (r != -1) return 0;
        if (errno == EINTR) continue;
        /* XXX help! */
        return -1;
    }
}

