/* retry.h -- Keep retrying write system calls */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef INCLUDED_RETRY_H
#define INCLUDED_RETRY_H

#include <sys/types.h>
#include <sys/uio.h>

extern ssize_t retry_read(int fd, void *buf, size_t nbyte);
extern ssize_t retry_write(int fd, const void *buf, size_t nbyte);
extern ssize_t retry_writev(int fd, const struct iovec *iov, int iovcnt);

/* add a buffer 's' of length 'len' to iovec 'iov' */
#define WRITEV_ADD_TO_IOVEC(iov, num_iov, s, len) \
    do { (iov)[(num_iov)].iov_base = (char *)(s); \
         (iov)[(num_iov)++].iov_len = (len); } while (0)

/* add a string 's' to iovec 'iov' */
#define WRITEV_ADDSTR_TO_IOVEC(iov, num_iov, s) WRITEV_ADD_TO_IOVEC(iov, num_iov, s, strlen(s))

#endif /* INCLUDED_RETRY_H */
