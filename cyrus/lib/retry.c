/* retry.c -- keep trying write system calls
 *
 *	(C) Copyright 1995 by Carnegie Mellon University
 *
 *                      All Rights Reserved
 *
 * Permission to use, copy, modify, and distribute this software and its 
 * documentation for any purpose and without fee is hereby granted, 
 * provided that the above copyright notice appear in all copies and that
 * both that copyright notice and this permission notice appear in 
 * supporting documentation, and that the name of CMU not be
 * used in advertising or publicity pertaining to distribution of the
 * software without specific, written prior permission.  
 * 
 * CMU DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
 * ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL
 * CMU BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR
 * ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
 * WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
 * ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 *
 */

#include <errno.h>
#include <sys/types.h>
#include <sys/uio.h>

extern int errno;

/*
 * Keep calling the write() system call with 'fd', 'buf', and 'nbyte'
 * until all the data is written out or an error occurs.
 */
retry_write(fd, buf, nbyte)
int fd;
char *buf;
unsigned nbyte;
{
    int n;
    int written = 0;

    if (nbyte == 0) return 0;

    for (;;) {
	n = write(fd, buf, nbyte);
	if (n == -1) {
	    if (errno == EINTR) continue;
	    return -1;
	}

	written += n;

	if (n >= nbyte) return written;

	buf += n;
	nbyte -= n;
    }
}

	
/*
 * Keep calling the writev() system call with 'fd', 'iov', and 'iovcnt'
 * until all the data is written out or an error occurs.
 */
retry_writev(fd, iov, iovcnt)
int fd;
struct iovec *iov;
int iovcnt;
{
    int n;
    int i;
    int written = 0;

    for (;;) {
	n = writev(fd, iov, iovcnt);
	if (n == -1) {
	    if (errno == EINTR) continue;
	    return -1;
	}

	written += n;

	for (i = 0; i < iovcnt; i++) {
	    if (iov[i].iov_len > n) {
		iov[i].iov_base += n;
		iov[i].iov_len -= n;
		break;
	    }
	    n -= iov[i].iov_len;
	    iov[i].iov_len = 0;
	}

	if (i == iovcnt) return written;
    }
}

	
