/* quic.h - generic per-worker QUIC transport session */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef QUIC_H
#define QUIC_H

#include <config.h>

#ifdef HAVE_NGTCP2

#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_ossl.h>
#include <openssl/ssl.h>

#include "master/service.h"   // quic_handoff, cidlen/bufsize consts
#include "tls.h"              // struct tls_alpn_t

/* One QUIC connection at a time per worker -- master.c's
 * quic_dispatch_connection() hands each new one over on fd 0, chosen
 * via eBPF steering or the userspace relay, the same way accept()
 * does for TCP. Knows nothing about which application protocol is
 * riding on top; see struct quic_app_ops below for that seam. */

struct quic_app_ops;

/* A QUIC transport connection. Embed this as the FIRST member of an
 * application's own session struct so a struct quic_session * and a
 * pointer to the app's own struct are interchangeable via a cast in
 * both directions -- quic.c only ever sees the embedded quic_session,
 * the app casts it back to its own type inside every quic_app_ops
 * callback. */
struct quic_session {
    ngtcp2_conn *qconn;
    SSL *ssl;
    ngtcp2_crypto_ossl_ctx *ossl_ctx;
    ngtcp2_crypto_conn_ref conn_ref;

    int fd;                      /* where datagrams arrive: a
                                  * deliberately unconnected UDP socket
                                  * (eBPF backend), or one end of an
                                  * AF_UNIX socketpair (relay backend);
                                  * fd 0 in a dispatched worker */
    int send_fd;                 /* where outgoing packets go: fd for
                                  * the eBPF backend, the rendezvous
                                  * socket master passed for the relay
                                  * backend (service_quic_send_fd()) */
    bool relayed;                /* fd is a socketpair to master, so
                                  * each datagram arrives behind a
                                  * struct quic_relay_pkt_hdr */

    ngtcp2_cid scid;

    /* Where quic_flush_output() writes and, once draining, where the
     * one CONNECTION_CLOSE goes. Set once from the handoff's
     * already-trusted addresses (quic_session_new()), and after that
     * ONLY by a SUCCESS result reaching the ngtcp2 path_validation
     * callback (RFC 9000 9.3). Never write these from a packet's
     * claimed source: the CID travels in cleartext, so such a packet
     * is cheap to forge, and ngtcp2_conn_read_pkt() returns success
     * even when the payload decrypts to nothing. */
    struct sockaddr_storage local_addr;
    socklen_t local_addrlen;
    struct sockaddr_storage peer_addr;
    socklen_t peer_addrlen;

    /* Spare CIDs master pre-registered in the dispatch backend for
     * this connection (quic_handoff.cids[1..], quic_handoff.h) --
     * quic_get_new_connection_id_cb() hands them out one at a time as
     * ngtcp2 asks for a fresh one, e.g. for a client to migrate to.
     * Fails the connection outright once exhausted (see that
     * callback) rather than hand out a CID neither dispatch backend
     * would recognize. */
    uint8_t cid_pool[QUIC_CID_POOL_SIZE][QUIC_CIDLEN];
    uint8_t ncids;
    uint8_t next_pool_cid;

    bool draining;                /* closing; stop accepting new work */

    /* When ngtcp2 last accepted a packet from the peer (quic_now()
     * time), for an application's own inactivity timer */
    ngtcp2_tstamp last_input;

    /* The relayed first Initial packet, valid once quic_session_new()
     * returns success. The app is expected to call
     * quic_process_datagram(qs, qs->first_pkt, qs->first_pktlen,
     * &qs->peer_addr, qs->peer_addrlen) itself, exactly once, right
     * after it finishes its own session setup (quic_session_new()
     * can't do this for you: your recv_stream_data callback needs your
     * own session object to already exist, and it doesn't until this
     * call returns). */
    uint8_t first_pkt[QUIC_PKT_BUFSIZE];
    size_t first_pktlen;

    const struct quic_app_ops *ops;
};

/* What quic.c needs from whichever application protocol is running
 * over a struct quic_session. quic.c calls these unconditionally (all
 * required, none optional) and always passes the embedding
 * quic_session -- the app casts it back to its own type. */
struct quic_app_ops {
    /* ngtcp2 handshake_completed. */
    void (*handshake_completed)(struct quic_session *qs);

    /* ngtcp2 recv_stream_data, |fin| set on the final delivery for a
     * stream. Returns the number of bytes consumed (may be less than
     * datalen -- an application framing layer may only count bytes
     * that free up flow-control credit, not payload it's still
     * buffering), or a negative NGTCP2_ERR_CALLBACK_FAILURE-compatible
     * value to abort the connection. */
    ngtcp2_ssize (*recv_stream_data)(struct quic_session *qs,
                                     int64_t stream_id,
                                     const uint8_t *data, size_t datalen,
                                     bool fin);

    /* ngtcp2 acked_stream_data_offset / stream_close / stream_reset. */
    void (*acked_stream_data)(struct quic_session *qs, int64_t stream_id,
                              uint64_t datalen);
    void (*stream_closed)(struct quic_session *qs, int64_t stream_id,
                          uint64_t app_error_code);
    void (*stream_reset)(struct quic_session *qs, int64_t stream_id,
                         uint64_t app_error_code);

    /* Called once right after quic_process_datagram() first succeeds,
     * and again after every subsequent one that didn't set
     * qs->draining, as well as before each delivery of stream data (0-RTT
     * data can come within the first datagram) -- so it must be cheap
     * once its work is done.  A chance to do credit-gated setup that can't
     * happen at quic_session_new() time (e.g. opening application-defined
     * control streams once uni-stream credit exists). Return nonzero
     * (having logged why) to abort the connection. */
    int (*io_ready)(struct quic_session *qs);

    /* Pull the next chunk of pending output for some stream. Fill up
     * to veccnt entries in vec, set *pstream_id (-1 if nothing
     * pending) and *pfin, return the vector count used, 0 if nothing
     * pending right now, or -1 on error (having logged why). Shaped to
     * mirror the writev-style callback contract common to QUIC
     * application-framing libraries, so an implementation built on top
     * of one can often just delegate straight through. */
    ngtcp2_ssize (*get_output)(struct quic_session *qs, int64_t *pstream_id,
                               int *pfin, ngtcp2_vec *vec, size_t veccnt);

    /* The transport actually sent |datalen| bytes of what get_output()
     * returned for |stream_id| -- record the write offset advancing,
     * the app's own bookkeeping for what's been flushed so far. */
    void (*advance_output)(struct quic_session *qs, int64_t stream_id,
                           size_t datalen);

    /* ngtcp2 couldn't accept more data for |stream_id| right now
     * (NGTCP2_ERR_STREAM_DATA_BLOCKED/SHUT_WR) -- don't ask
     * get_output() for it again until it un-blocks. */
    void (*block_output)(struct quic_session *qs, int64_t stream_id);

    /* ngtcp2 extend_max_stream_data: the peer raised |stream_id|'s
     * flow-control limit, so output held back by block_output() may
     * go again. Return nonzero to abort the connection. */
    int (*unblock_output)(struct quic_session *qs, int64_t stream_id);

    /* Free whatever the app owns (e.g. its own framing-library
     * session state, open transactions) before quic_session_free()
     * tears down the ngtcp2_conn/SSL underneath it. */
    void (*session_free)(struct quic_session *qs);
};

/* ALPN map plus which quic_app_ops to wire every ngtcp2 callback to,
 * for one application protocol riding on QUIC. */
struct quic_app {
    struct tls_alpn_t *alpn_map;
    const struct quic_app_ops *ops;
};

/* The current time, on the clock ngtcp2's own timers are set against.
 * An app whose own framing library also wants a "steadily increasing
 * clock" timestamp should use this one, not a clock of its own --
 * ngtcp2_conn_read_pkt() and whatever the app calls alongside it need
 * to agree on what "now" means. */
ngtcp2_tstamp quic_now(void);

/**
 * Create, once per process, the TLS 1.3 server context QUIC connections
 * use: tls_new_serverctx()'s shared settings plus tls_server_cert and
 * tls_server_key.  Later calls return the same context, whatever their
 * early_data.  Pass it to quic_session_new().
 *
 * @param ret         set to the context on success (may be NULL)
 * @param early_data  accept 0-RTT early data, with single-use session
 *                    tickets (see tls_enable_early_data()); no effect
 *                    if tls_session_timeout is 0
 * @return            0 on success, -1 (logged) on failure
 */
int quic_init_tls_ctx(SSL_CTX **ret, bool early_data);

/* Parse the relayed first Initial packet master handed off (the
 * process-global `quic_handoff` from master/quic/quic_handoff.h,
 * filled by service.c's quic_recv_handoff()) and create the
 * ngtcp2_conn for it, embedded in *qs (caller-allocated -- the first
 * member of the app's own session struct, already zeroed). |fd| is
 * the connection's own socket (conn->pin->fd in httpd.c terms).
 * Installs app->alpn_map on ssl_ctx and wires every ngtcp2 callback to
 * app->ops. |idle_timeout| is the idle timeout to offer (RFC 9000
 * 10.1), in seconds; 0 offers none. Does NOT process the first packet --
 * see qs->first_pkt's comment above. Returns 0 on success, or -1
 * (having logged why) on failure. */
int quic_session_new(struct quic_session *qs, int fd, SSL_CTX *ssl_ctx,
                     const struct quic_app *app, unsigned long idle_timeout);

/* Feed one QUIC datagram to ngtcp2, call ops->io_ready() if it wasn't
 * dropped, and flush any resulting output. |from|/|fromlen| only tells
 * ngtcp2 where to consider the packet arrived; neither backend
 * authenticates it, and it is NOT written to qs->peer_addr (see that
 * field's comment above).
 * Sets qs->draining if the connection is now done (peer
 * CONNECTION_CLOSE, protocol error, or ngtcp2 dropped it silently) --
 * check qs->draining after calling. */
void quic_process_datagram(struct quic_session *qs, const uint8_t *pkt,
                           size_t pktlen,
                           const struct sockaddr_storage *from,
                           socklen_t fromlen);

/* recvfrom()s one datagram from qs->fd (MSG_DONTWAIT) and feeds it to
 * quic_process_datagram() if there was one, along with wherever it
 * claims to have arrived from -- the eBPF backend's socket reports
 * this directly; the relay backend's AF_UNIX socketpair doesn't, so
 * it's carried instead in a struct quic_relay_pkt_hdr (quic_handoff.h)
 * prefixed to the payload. Returns true if the caller should close the
 * connection now, setting *close_reason to a static string explaining
 * why -- false means keep going. */
bool quic_input(struct quic_session *qs, const char **close_reason);

/**
 * Whether the handshake is still in progress, so that stream data
 * arriving now was sent as 0-RTT early data (RFC 9001 4.6).  Such data
 * can be replayed, so an application should act on it only if doing so
 * twice is harmless, e.g. by answering anything else with HTTP's 425
 * (Too Early, RFC 8470).  Without early_data to quic_init_tls_ctx() no
 * stream data arrives before the handshake completes, so this is then
 * false whenever an application has any to handle.
 *
 * @param qs  the connection
 * @return    true while data may be arriving as early data
 */
bool quic_in_early_data(struct quic_session *qs);

/* Flush any output ngtcp2/the app has queued. Call after anything that
 * might have queued new stream data (get_output() has more to give,
 * quic_handle_expiry() fired a PTO). Sets qs->draining on transport
 * failure. */
void quic_flush_output(struct quic_session *qs);

/* Microseconds until this connection's next ngtcp2 timer needs
 * servicing, at most 60 seconds.  Always >= 1 once a session exists
 * (ngtcp2 always has at least an idle timeout armed). */
unsigned long quic_get_timeout(struct quic_session *qs);

/**
 * Report the bytes of QUIC packets this connection has received and
 * sent so far, as counted by ngtcp2 (packets it discarded excluded).
 * Both are 0 with an ngtcp2 older than 1.16, which doesn't count them.
 *
 * @param qs         the connection
 * @param bytes_in   set to the bytes received
 * @param bytes_out  set to the bytes sent
 */
void quic_traffic(struct quic_session *qs,
                  uint64_t *bytes_in, uint64_t *bytes_out);

/**
 * Close the connection with a CONNECTION_CLOSE carrying an application
 * error code, e.g. when the application's own inactivity timer expires,
 * and set qs->draining.  Does nothing if it is already draining.
 *
 * @param qs              the connection
 * @param app_error_code  the application protocol's error code
 */
void quic_close(struct quic_session *qs, uint64_t app_error_code);

/* Service any due ngtcp2 timers and flush output. Sets qs->draining if
 * the connection is now done (e.g. idle timeout expired); the caller
 * should check it the same way as after quic_input(). */
void quic_handle_expiry(struct quic_session *qs);

/* Tear down qs: calls ops->session_free() first, then frees the
 * ngtcp2_conn/SSL/etc. underneath it. Does NOT free qs itself -- the
 * app owns that allocation. Safe to call on a zeroed/partially
 * initialized *qs (e.g. quic_session_new() failed partway through). */
void quic_session_free(struct quic_session *qs);

#endif /* HAVE_NGTCP2 */

#endif /* QUIC_H */
