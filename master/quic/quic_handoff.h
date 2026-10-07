/* quic_handoff.h - send/receive a QUIC_HANDOFF_FD handoff */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef MASTER_QUIC_HANDOFF_H
#define MASTER_QUIC_HANDOFF_H

#include <config.h>
#include <stdint.h>
#include <sys/socket.h>

#include "master/quic/quic_cidlen.h"

/* Large enough to hold any single QUIC UDP datagram whole. The
 * dispatch-time recv() and the pkt[] below it relays verbatim must
 * agree on this size, or a large Initial packet gets truncated. */
#define QUIC_PKT_BUFSIZE 2048

/* A client-chosen Destination Connection ID is at most this long
 * (NGTCP2_MAX_CIDLEN, RFC 9000 section 17.2) */
#define QUIC_MAX_ODCIDLEN 20

/* The QUIC versions to advertise, in master's Version Negotiation
 * packets and a worker's version_information transport parameter:
 * v1 (RFC 9000) and v2 (RFC 9369).  ngtcp2 decides which versions are
 * accepted, but can only test one, not list them.  An initializer for
 * a uint32_t array, for code that includes <ngtcp2/ngtcp2.h>. */
#define QUIC_ADVERTISED_VERSIONS { NGTCP2_PROTO_VER_V1, NGTCP2_PROTO_VER_V2 }

/* How many CIDs master pre-generates for one connection: cids[0] is
 * the primary (the SCID), cids[1..] a spare pool for migration. See
 * "A spare CID pool for future connection migration" in
 * quic-dispatch.rst.
 *
 * Must be at least 2: RFC 9000 puts active_connection_id_limit at a
 * minimum of 2, so a consumer needs a spare to hand out during an
 * ordinary handshake, not just a migrating one. */
#define QUIC_CID_POOL_SIZE 8

#if QUIC_CID_POOL_SIZE < 2
#error "QUIC_CID_POOL_SIZE must be at least 2"
#endif

/* The payload of one QUIC_HANDOFF_FD message
 * (see docsrc/concepts/features/quic-dispatch.rst).  The connection's
 * descriptors travel beside it, by SCM_RIGHTS: see quic_send_handoff().
 *
 * local_addr/local_addrlen is what getsockname() on the connection's
 * own fd would return for the eBPF backend's real per-connection UDP
 * socket -- master fills it in itself (already has it from
 * getsockname() on the rendezvous socket) since the worker can't: for
 * the userspace relay backend, that fd is one end of an AF_UNIX
 * socketpair, whose getsockname() reports an anonymous unix address,
 * not the connection's real local IP:port. */
struct quic_handoff {
    uint8_t cids[QUIC_CID_POOL_SIZE][QUIC_CIDLEN];
    uint8_t ncids;
    struct sockaddr_storage local_addr;
    socklen_t local_addrlen;
    struct sockaddr_storage peer_addr;
    socklen_t peer_addrlen;
    size_t pktlen;
    uint8_t pkt[QUIC_PKT_BUFSIZE];

    /* The DCID of the client's first Initial, recovered from the Retry
     * token in pkt that master verified, or odcidlen 0 if master sent
     * no Retry: the worker needs it for the original_dcid transport
     * parameter, and the token itself for ngtcp2_settings. */
    uint8_t odcid[QUIC_MAX_ODCIDLEN];
    uint8_t odcidlen;
};

/* Hand one QUIC connection to a worker over handoff_fd, master's end of
 * that worker's QUIC_HANDOFF_FD socketpair, with *handoff as the
 * payload.  recv_fd, where the worker receives the connection's
 * packets, and send_fd, where it sends them, travel by SCM_RIGHTS, an
 * fd number meaning nothing outside the process holding it.  send_fd
 * is -1 to have the worker send on recv_fd: the relay backend passes a
 * dup of the rendezvous socket, its recv_fd being a socketpair, and the
 * eBPF backend's recv_fd is already a real socket.  Send-only, since
 * master is the sole reader of the rendezvous socket.
 *
 * Closes neither fd -- the worker gets SCM_RIGHTS-duped copies -- and
 * handoff_fd stays open for later handoffs.  Never blocks: fails with
 * EAGAIN if the worker hasn't read enough of what was sent before.
 * Returns 0 on success, -1 (errno set) on failure. */
int quic_send_handoff(int handoff_fd, int recv_fd, int send_fd,
                      const struct quic_handoff *handoff);

/* Receive one handoff message sent by quic_send_handoff(), above, into
 * *out, with *recv_fd and *send_fd set to this process's own fds for
 * what the sender passed, *send_fd -1 if it passed none.  The caller
 * owns both and must close them.
 * Returns 0 on success, -1 (errno set; EBADMSG for a malformed
 * message) on failure, in which case *out is zeroed and both fds are
 * -1. */
int quic_recv_handoff(int handoff_fd, struct quic_handoff *out,
                      int *recv_fd, int *send_fd);

/* proto="quic" relay backend only: prepended to every datagram
 * quic_relay_forward() (master/quic/quic_relay.c) relays to a worker
 * over its connection socketpair, so the worker learns each
 * datagram's actual arrival address without a real network socket of
 * its own to recvfrom() on -- see "Tracking a moving peer address" in
 * docsrc/concepts/features/quic-dispatch.rst. Lives here rather than
 * quic_relay.h since the worker needs it too, and has no other reason
 * to see master's own relay-management API. Not meaningful on its own
 * without the datagram bytes that follow it in the same message. */
struct quic_relay_pkt_hdr {
    struct sockaddr_storage peer;
    socklen_t peerlen;
};

#endif /* MASTER_QUIC_HANDOFF_H */
