/* lock_fcntl.c -- Lock files using fcntl()
 $Id: lock_fcntl.c,v 1.16 2003/02/13 20:15:40 rjs3 Exp $
 
 * Copyright (c) 1998-2003 Carnegie Mellon University.  All rights reserved.
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
 *    prior written permission. For permission or any other legal
 *    details, please contact  
 *      Office of Technology Transfer
 *      Carnegie Mellon University
 *      5000 Forbes Avenue
 *      Pittsburgh, PA  15213-3890
 *      (412) 268-4387, fax: (412) 268-7395
 *      tech-transfer@andrew.cmu.edu
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
 *
 */
#include <config.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include "lock.h"

const char *lock_method_desc = "fcntl";

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
int lock_unlock(int fd)
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
        /* xxx help! */
        return -1;
    }
}

