/* lock_flock.c -- Lock files using flock()
 *
 * Copyright 1996, Carnegie Mellon University.  All Rights Reserved.
 * 
 * This software is made available for academic and research
 * purposes only.  No commercial license is hereby granted.
 * Copying and other reproduction is authorized only for research,
 * education, and other non-commercial purposes.  No warranties,
 * either expressed or implied, are made regarding the operation,
 * use, or results of the software.  Such a release does not permit
 * use of the code for commercial purposes or benefits by anyone
 * without specific, additional permission by the owner of the code.
 *
 */
#include <sys/file.h>
#include <sys/stat.h>
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
    struct stat sbuffile, sbufspare;
    int newfd;

    if (!sbuf) sbuf = &sbufspare;

    for (;;) {
	r = flock(fd, LOCK_EX);
	if (r == -1) {
	    if (errno == EINTR) continue;
	    if (failaction) *failaction = "locking";
	    return -1;
	}

	fstat(fd, sbuf);
	r = stat(filename, &sbuffile);
	if (r == -1) {
	    if (failaction) *failaction = "stating";
	    flock(fd, LOCK_UN);
	    return -1;
	}

	if (sbuf->st_ino == sbuffile.st_ino) return 0;

	newfd = open(filename, O_RDWR);
	if (newfd == -1) {
	    if (failaction) *failaction = "opening";
	    flock(fd, LOCK_UN);
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

    for (;;) {
	r = flock(fd, LOCK_EX);
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

    for (;;) {
	r = flock(fd, LOCK_SH);
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

    for (;;) {
	r = flock(fd, LOCK_EX|LOCK_NB);
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
    flock(fd, LOCK_UN);
    return 0;
}

