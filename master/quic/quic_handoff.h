/* quic_handoff.h - send/receive a QUIC_HANDOFF_FD handoff */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef MASTER_QUIC_HANDOFF_H
#define MASTER_QUIC_HANDOFF_H

#include <config.h>
#include <stdint.h>
#include <sys/socket.h>

/* The length of the Connection ID master assigns each connection for
 * dispatch: a policy choice of ours, not something QUIC dictates --
 * the protocol lets whichever endpoint generates a CID pick its own
 * length, from 1 to 20 bytes. Not to be confused with the
 * coincidentally equal RFC 9000 anti-amplification floor on a
 * client's first Destination Connection ID. */
#define QUIC_CIDLEN 8

/* Large enough to hold any single QUIC UDP datagram whole. The
 * dispatch-time recv() and the pkt[] below it relays verbatim must
 * agree on this size, or a large Initial packet gets truncated. */
#define QUIC_PKT_BUFSIZE 2048

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
 * (see docsrc/concepts/features/quic-dispatch.rst).
 *
 * send_fd is the socket to send this connection's outgoing packets
 * on, or -1 to send on the connection fd itself. Anything filling a
 * quic_handoff in must set it: 0 is a real fd, so a zeroed struct
 * would otherwise claim fd 0 was passed. An fd number means
 * nothing outside the process holding it, so this one doesn't travel
 * as payload: the sender names the fd to pass, quic_send_handoff()
 * passes it by SCM_RIGHTS, and quic_recv_handoff() overwrites the
 * field with the fd the receiver actually got.
 *
 * The relay passes a dup of the rendezvous socket, since its
 * connection fd is a socketpair. Send-only: master is the sole reader
 * of the rendezvous socket, and a worker reading from it would take
 * packets belonging to other connections.
 *
 * local_addr/local_addrlen is the connection's real local IP:port,
 * which master fills in itself (it already has it from getsockname()
 * on the rendezvous socket) since the worker can't: its connection fd
 * is one end of an AF_UNIX socketpair, whose getsockname() reports an
 * anonymous unix address instead. */
struct quic_handoff {
    /* Where the worker receives this connection's packets. Travels by
     * SCM_RIGHTS, not in the payload: the sender's fd number means
     * nothing to the receiver, so quic_recv_handoff() overwrites it
     * with the one it was handed. */
    int recv_fd;

    /* Where the worker sends this connection's outgoing packets, or -1
     * to send on recv_fd. Travels the same way, with the same caveat. */
    int send_fd;

    uint8_t cids[QUIC_CID_POOL_SIZE][QUIC_CIDLEN];
    uint8_t ncids;
    struct sockaddr_storage local_addr;
    socklen_t local_addrlen;
    struct sockaddr_storage peer_addr;
    socklen_t peer_addrlen;
    size_t pktlen;
    uint8_t pkt[QUIC_PKT_BUFSIZE];
};

/* Hand one QUIC connection to a worker over handoff_fd, master's end of
 * that worker's QUIC_HANDOFF_FD socketpair: handoff->recv_fd, plus
 * handoff->send_fd if it isn't -1, via SCM_RIGHTS, with *handoff as the
 * payload. Closes neither -- the worker gets SCM_RIGHTS-duped copies,
 * and handoff_fd stays open for later handoffs. Both dispatch backends
 * call this identically; what recv_fd is varies by backend.
 * Returns 0 on success, -1 (errno set) on failure. */
int quic_send_handoff(int handoff_fd, const struct quic_handoff *handoff);

/* Receive one handoff message sent by quic_send_handoff(), above,
 * setting out->recv_fd to this process's own fd for the connection and
 * out->send_fd likewise, or -1 if the sender passed none. The caller
 * owns both and must close them.
 * Returns 0 on success, -1 (errno set; EBADMSG for a malformed
 * message) on failure, in which case *out is zeroed. */
int quic_recv_handoff(int handoff_fd, struct quic_handoff *out);

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
