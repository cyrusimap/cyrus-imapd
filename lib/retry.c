/* retry.c -- keep trying write system calls
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

#include <config.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sysexits.h>
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

#include "retry.h"
#include "slowio.h"
#include "xmalloc.h"

/*
 * Keep calling the read() system call with 'fd', 'buf', and 'nbyte'
 * until all the data is read in or an error occurs.
 */
EXPORTED ssize_t retry_read(int fd, void *vbuf, size_t nbyte)
{
    size_t nread;
    char *buf = vbuf;

    for (nread = 0; nread < nbyte;) {
        ssize_t n = read(fd, buf + nread, nbyte - nread);
        if (n == 0) {
            /* end of file */
            return -1;
        }

        if (n == -1) {
            if (errno == EINTR || errno == EAGAIN) {
                continue;
            }
            return -1;
        }

        nread += n;

        slowio_maybe_delay_read(n);
    }

    return nread;
}

/*
 * Keep calling the write() system call with 'fd', 'buf', and 'nbyte'
 * until all the data is written out or an error occurs.
 */
EXPORTED ssize_t retry_write(int fd, const void *vbuf, size_t nbyte)
{
    const char *buf = vbuf;
    size_t written = 0;

    if (nbyte == 0) {
        return 0;
    }

    for (written = 0; written < nbyte;) {
        ssize_t n = write(fd, buf + written, nbyte - written);

        if (n == -1) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }

        written += n;

        slowio_maybe_delay_write(n);
    }

    return written;
}

/*
 * Keep calling the writev() system call with 'fd', 'iov', and 'iovcnt'
 * until all the data is written out or an error occurs.
 *
 * Now no longer destructive of parameters!
 */
EXPORTED ssize_t retry_writev(int fd, const struct iovec *srciov, int iovcnt)
{
    int i;
    ssize_t n;
    size_t written = 0;
    size_t len = 0;
    struct iovec *iov = NULL, *baseiov = NULL;
    static int iov_max =
#ifdef MAXIOV
        MAXIOV
#else
# ifdef IOV_MAX
        IOV_MAX
# else
        8192
# endif
#endif
        ;

    if (!iovcnt) {
        return 0;
    }

    for (i = 0; i < iovcnt; i++) {
        len += srciov[i].iov_len;
    }

    for (;;) {
        /* Try to write the (remaining) iov */
        n = writev(fd, srciov, iovcnt > iov_max ? iov_max : iovcnt);
        if (n == -1) {
            if (errno == EINVAL && iov_max > 10) {
                iov_max /= 2;
                continue;
            }
            if (errno == EINTR) {
                continue;
            }
            free(baseiov);
            return -1;
        }

        written += n;

        slowio_maybe_delay_write(n);

        if (written == len) {
            break;
        }

        /* Oh well, welcome to the slow path - we have copies */
        if (!baseiov) {
            iov = baseiov = xmalloc(iovcnt * sizeof(struct iovec));
            for (i = 0; i < iovcnt; i++) {
                iov[i].iov_base = srciov[i].iov_base;
                iov[i].iov_len = srciov[i].iov_len;
            }
        }

        /* Skip any iov that may have been written in full */
        while ((size_t) n >= iov->iov_len) {
            n -= iov->iov_len;
            iov++;
            iovcnt--;
            if (!iovcnt) {
                fatal("ran out of iov", EX_SOFTWARE);
            }
        }

        /* Skip whatever portion of the current iov that has been written */
        iov->iov_base += n;
        iov->iov_len -= n;

        srciov = iov;
    }

    free(baseiov);
    return written;
}
