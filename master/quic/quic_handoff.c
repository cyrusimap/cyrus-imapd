/* quic_handoff.c - send a QUIC_HANDOFF_FD handoff, shared by both
 * dispatch backends */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>

#include <errno.h>
#include <string.h>
#include <sys/socket.h>

#include "master/quic/quic_handoff.h"

int quic_send_handoff(int fd, int sock, const struct quic_handoff *handoff)
{
    struct msghdr msg;
    struct iovec iov;
    union {
        struct cmsghdr align; /* for alignment only, never referenced */
        char buf[CMSG_SPACE(sizeof(int))];
    } cmsgbuf;
    struct cmsghdr *cmsg;
    ssize_t n;

    memset(&msg, 0, sizeof(msg));
    iov.iov_base = (void *) handoff;
    iov.iov_len = sizeof(*handoff);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsgbuf.buf;
    msg.msg_controllen = sizeof(cmsgbuf.buf);

    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cmsg), &sock, sizeof(sock));

    n = sendmsg(fd, &msg, 0);
    if (n != (ssize_t) sizeof(*handoff)) {
        if (n >= 0) errno = EMSGSIZE;
        return -1;
    }
    return 0;
}
