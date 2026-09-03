/* service.h */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef SERVICE_H
#define SERVICE_H

#include <stdint.h>
#include <sys/socket.h>

#include "master/quic/quic_cidlen.h"

enum {
    STATUS_FD = 3,
    LISTEN_FD = 4,

    /* proto="quic" workers only: an AF_UNIX/SOCK_SEQPACKET socket
     * master uses to hand this worker one QUIC connection per
     * recvmsg() -- there's no LISTEN_FD-style accept() for QUIC, since
     * a connection's own socket (struct quic_handoff below) is always
     * already tied to one peer: a connect()ed UDP socket for the eBPF
     * backend (master/quic/quic_ebpf.h), or one end of an AF_UNIX
     * socketpair for the userspace relay backend
     * (master/quic/quic_relay.h). Each message carries a struct
     * quic_handoff payload plus that connection's socket as
     * SCM_RIGHTS ancillary data. service.c's quic_recv_handoff()
     * dup2()s the enclosed fd onto STDIN_FILENO/STDOUT_FILENO -- same
     * as an accept()ed TCP socket -- before calling service_main(), so
     * it must be extracted before service_main() runs, not from
     * inside it. */
    QUIC_HANDOFF_FD = 5
};

/* QUIC_EBPF_CIDLEN (see master/quic/quic_cidlen.h) is pulled in above
 * rather than defined here, so imap/quic.c gets it via
 * QUIC_HANDOFF_FD/quic_handoff without needing to know
 * master/quic/quic_cidlen.h itself exists -- distinct from
 * master/quic/quic_parse.h's QUIC_MAX_CIDLEN, the protocol's own
 * upper bound on any CID, which stays master-dispatch-only. */

/* proto="quic" only: large enough to hold any single QUIC UDP
 * datagram whole. master's dispatch-time recv() (quic_dispatch_connection())
 * and the pkt[] below it relays verbatim must agree on this size, or
 * an unusually large Initial packet gets truncated; imap/quic.c
 * reuses it for its own post-handoff buffers, which have no hard
 * requirement to match but no reason not to. */
#define QUIC_PKT_BUFSIZE 2048

/* proto="quic" only: the payload of one QUIC_HANDOFF_FD message (see
 * above). service.c fills this in just before calling service_main(),
 * for imap/quic.c to read -- a plain extern, since the two live in
 * different translation units of the same httpd binary (same pattern
 * as e.g. httpd.c's httpd_saslconn).
 *
 * local_addr/local_addrlen is what getsockname() on the connection's
 * own fd would return for the eBPF backend's real per-connection UDP
 * socket -- master fills it in itself (already has it from
 * getsockname() on the rendezvous socket) since the worker can't: for
 * the userspace relay backend (master/quic/quic_relay.h), that fd is
 * one end of an AF_UNIX socketpair, whose getsockname() reports an
 * anonymous unix address, not the connection's real local IP:port. */
struct quic_handoff {
    uint8_t scid[QUIC_EBPF_CIDLEN];
    struct sockaddr_storage local_addr;
    socklen_t local_addrlen;
    struct sockaddr_storage peer_addr;
    socklen_t peer_addrlen;
    size_t pktlen;
    uint8_t pkt[QUIC_PKT_BUFSIZE];
};
extern struct quic_handoff quic_handoff;

enum {
    MASTER_SERVICE_AVAILABLE = 0x01,
    MASTER_SERVICE_UNAVAILABLE = 0x02,
    MASTER_SERVICE_CONNECTION = 0x03,
    MASTER_SERVICE_CONNECTION_MULTI = 0x04,

    /* proto="quic" only: sent instead of MASTER_SERVICE_AVAILABLE --
     * this worker finished (or never had) a connection and is now
     * blocked in quic_recv_handoff() on QUIC_HANDOFF_FD, ready for
     * another one (see quic_idle_pool_add()/quic_dispatch_connection()).
     * Kept distinct from MASTER_SERVICE_AVAILABLE because that
     * message's ready_workers bookkeeping doesn't fit quic's model --
     * see quic_dispatch_connection()'s comment for why. */
    MASTER_SERVICE_QUIC_IDLE = 0x05
};

extern int service_init(int argc, char **argv, char **envp);
extern int service_main(int argc, char **argv, char **envp);
extern int service_main_fd(int fd, int argc, char **argv, char **envp);
extern void service_abort(int error) __attribute__((noreturn));

enum {
    MAX_USE = 250,
    REUSE_TIMEOUT = 60
};

struct notify_message {
    int message;
    pid_t service_pid;
};

#endif
