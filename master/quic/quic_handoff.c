/* quic_handoff.c - send/receive a QUIC_HANDOFF_FD handoff */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>

#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "master/quic/quic_handoff.h"

int quic_send_handoff(int handoff_fd, int recv_fd, int send_fd,
                      const struct quic_handoff *handoff)
{
    struct msghdr msg;
    struct iovec iov;
    union {
        struct cmsghdr align; /* for alignment only, never referenced */
        char buf[CMSG_SPACE(2 * sizeof(int))];
    } cmsgbuf;
    struct cmsghdr *cmsg;
    int fds[2];
    unsigned nfds = 1;
    ssize_t n;

    /* SCM_RIGHTS duplicates real descriptors, so -1 can't ride along as
     * a placeholder: it fails the whole sendmsg() with EBADF. */
    fds[0] = recv_fd;
    if (send_fd >= 0) fds[nfds++] = send_fd;

    memset(&cmsgbuf, 0, sizeof(cmsgbuf));
    memset(&msg, 0, sizeof(msg));
    iov.iov_base = (void *) handoff;
    iov.iov_len = sizeof(*handoff);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsgbuf.buf;
    msg.msg_controllen = CMSG_SPACE(nfds * sizeof(int));

    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(nfds * sizeof(int));
    memcpy(CMSG_DATA(cmsg), fds, nfds * sizeof(int));

    /* MSG_DONTWAIT: master's event loop must not wait on a worker that
     * hasn't read an earlier handoff.  MSG_NOSIGNAL: a worker that died
     * leaves master writing to a socketpair with no reader; take the
     * EPIPE, not the signal. */
    n = sendmsg(handoff_fd, &msg, MSG_DONTWAIT | MSG_NOSIGNAL);
    if (n != (ssize_t) sizeof(*handoff)) {
        if (n >= 0) errno = EMSGSIZE;
        return -1;
    }
    return 0;
}

int quic_recv_handoff(int handoff_fd, struct quic_handoff *out,
                      int *recv_fd, int *send_fd)
{
    struct msghdr msg;
    struct iovec iov;
    union {
        struct cmsghdr align; /* for alignment only, never referenced */
        char buf[CMSG_SPACE(2 * sizeof(int))];
    } cmsgbuf;
    struct cmsghdr *cmsg;
    ssize_t n;

    memset(&msg, 0, sizeof(msg));
    iov.iov_base = out;
    iov.iov_len = sizeof(*out);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsgbuf.buf;
    msg.msg_controllen = sizeof(cmsgbuf.buf);

    *recv_fd = *send_fd = -1;

    n = recvmsg(handoff_fd, &msg, 0);

    /* Pick up any fds even if the message turns out unusable: they're
     * already ours, and would leak otherwise */
    if (n >= 0) {
        for (cmsg = CMSG_FIRSTHDR(&msg); cmsg;
             cmsg = CMSG_NXTHDR(&msg, cmsg)) {
            if (cmsg->cmsg_level != SOL_SOCKET ||
                cmsg->cmsg_type != SCM_RIGHTS)
                continue;

            /* One fd for the connection, plus a send socket if the
             * sender passed one. */
            if (cmsg->cmsg_len >= CMSG_LEN(sizeof(int)))
                memcpy(recv_fd, CMSG_DATA(cmsg), sizeof(int));
            if (cmsg->cmsg_len >= CMSG_LEN(2 * sizeof(int)))
                memcpy(send_fd, CMSG_DATA(cmsg) + sizeof(int), sizeof(int));
            break;
        }
    }

    /* recvmsg() writes straight into *out, so a truncated message
     * leaves it holding the new prefix over the previous connection's
     * tail. Zero it on the way out instead of handing back a struct
     * that reads as half-valid. */
    if (n != (ssize_t) sizeof(*out) || *recv_fd < 0) {
        int saved_errno = n < 0 ? errno : EBADMSG;

        if (*recv_fd >= 0) close(*recv_fd);
        if (*send_fd >= 0) close(*send_fd);
        *recv_fd = *send_fd = -1;
        memset(out, 0, sizeof(*out));
        errno = saved_errno;
        return -1;
    }

    return 0;
}
