/* lock_fcntl.c -- Lock files using fcntl()
 $Id: lock_fcntl.c,v 1.9 1998/05/15 21:51:53 neplokh Exp $
 
 #        Copyright 1998 by Carnegie Mellon University
 #
 #                      All Rights Reserved
 #
 # Permission to use, copy, modify, and distribute this software and its
 # documentation for any purpose and without fee is hereby granted,
 # provided that the above copyright notice appear in all copies and that
 # both that copyright notice and this permission notice appear in
 # supporting documentation, and that the name of CMU not be
 # used in advertising or publicity pertaining to distribution of the
 # software without specific, written prior permission.
 #
 # CMU DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
 # ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL
 # CMU BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR
 # ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
 # WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
 # ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 # SOFTWARE.
 *
 */
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include "lock.h"

extern int errno;

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
int lock_reopen(fd, filename, sbuf, failaction)
int fd;
const char *filename;
struct stat *sbuf;
const char **failaction;
{
    int r;
    struct flock fl;
    struct stat sbuffile, sbufspare;
    int newfd;

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

	fstat(fd, sbuf);
	r = stat(filename, &sbuffile);
	if (r == -1) {
	    if (failaction) *failaction = "stating";
	    fl.l_type= F_UNLCK;
	    fl.l_whence = SEEK_SET;
	    fl.l_start = 0;
	    fl.l_len = 0;
	    r = fcntl(fd, F_SETLKW, &fl);
	    return -1;
	}

	if (sbuf->st_ino == sbuffile.st_ino) return 0;

	newfd = open(filename, O_RDWR);
	if (newfd == -1) {
	    if (failaction) *failaction = "opening";
	    fl.l_type= F_UNLCK;
	    fl.l_whence = SEEK_SET;
	    fl.l_start = 0;
	    fl.l_len = 0;
	    r = fcntl(fd, F_SETLKW, &fl);
	    return -1;
	}
	dup2(newfd, fd);
	close(newfd);
    }
}

/*
 * Obtain an exclusive lock on 'fd'.
 * Returns 0 for success, -1 for failure, with errno set to an
 * appropriate error code.
 */
int lock_blocking(fd)
int fd;
{
    int r;
    struct flock fl;

    for (;;) {
	fl.l_type= F_WRLCK;
	fl.l_whence = SEEK_SET;
	fl.l_start = 0;
	fl.l_len = 0;
	r = fcntl(fd, F_SETLKW, &fl);
	if (r != -1) return 0;
	if (errno == EINTR) continue;
	return -1;
    }
}

/*
 * Obtain a shared lock on 'fd'.
 * Returns 0 for success, -1 for failure, with errno set to an
 * appropriate error code.
 */
int lock_shared(fd)
int fd;
{
    int r;
    struct flock fl;

    for (;;) {
	fl.l_type= F_RDLCK;
	fl.l_whence = SEEK_SET;
	fl.l_start = 0;
	fl.l_len = 0;
	r = fcntl(fd, F_SETLKW, &fl);
	if (r != -1) return 0;
	if (errno == EINTR) continue;
	return -1;
    }
}

/*
 * Attempt to get an exclusive lock on 'fd' without blocking.
 * Returns 0 for success, -1 for failure, with errno set to an
 * appropriate error code.
 */
int lock_nonblocking(fd)
int fd;
{
    int r;
    struct flock fl;

    for (;;) {
	fl.l_type= F_WRLCK;
	fl.l_whence = SEEK_SET;
	fl.l_start = 0;
	fl.l_len = 0;
	r = fcntl(fd, F_SETLK, &fl);
	if (r != -1) return 0;
	if (errno == EINTR) continue;
	return -1;
    }
}

/*
 * Release any lock on 'fd'.  Always returns success.
 */
lock_unlock(fd)
int fd;
{ 
    struct flock fl;

    fl.l_type= F_UNLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start = 0;
    fl.l_len = 0;
    fcntl(fd, F_SETLKW, &fl);
    return 0;
}

