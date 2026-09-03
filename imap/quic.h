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

/* One QUIC connection at a time per "-3" worker -- master.c's
 * quic_dispatch_connection() hands each new one over on fd 0, chosen
 * via eBPF steering or the userspace relay, the same way accept()
 * does for TCP. Knows nothing about which application protocol is
 * riding on top; see struct quic_app_ops below for that seam. */

struct quic_app_ops;

/* A QUIC transport connection. Embed this as the FIRST member of an
 * application's own session struct (see struct h3_context in
 * http_h3.c) so a struct quic_session * and a pointer to the app's
 * own struct are interchangeable via a cast in both directions --
 * quic.c only ever sees the embedded quic_session, the app casts it
 * back to its own type inside every quic_app_ops callback. */
struct quic_session {
    ngtcp2_conn *qconn;
    SSL *ssl;
    ngtcp2_crypto_ossl_ctx *ossl_ctx;
    ngtcp2_crypto_conn_ref conn_ref;

    int fd;                      /* connected UDP socket, or one end of
                                  * an AF_UNIX socketpair (relay
                                  * backend) -- always fd 0 */

    ngtcp2_cid scid;
    struct sockaddr_storage local_addr;
    socklen_t local_addrlen;
    struct sockaddr_storage peer_addr;
    socklen_t peer_addrlen;

    bool draining;                /* closing; stop accepting new work */

    /* The relayed first Initial packet, valid once quic_session_new()
     * returns success. The app is expected to call
     * quic_process_datagram(qs, qs->first_pkt, qs->first_pktlen) itself,
     * exactly once, right after it finishes its own session setup
     * (quic_session_new() can't do this for you: your recv_stream_data
     * callback needs your own session object to already exist, and it
     * doesn't until this call returns). */
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
     * datalen -- e.g. nghttp3_conn_read_stream2() only counts bytes
     * that free up flow-control credit, not DATA-frame payload), or a
     * negative NGTCP2_ERR_CALLBACK_FAILURE-compatible value to abort
     * the connection. */
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
     * qs->draining -- a chance to do credit-gated setup that can't
     * happen at quic_session_new() time (e.g. http_h3.c opening its
     * control/QPACK streams once uni-stream credit exists). Return
     * nonzero (having logged why) to abort the connection. */
    int (*io_ready)(struct quic_session *qs);

    /* Pull the next chunk of pending output for some stream. Fill up
     * to veccnt entries in vec, set *pstream_id (-1 if nothing
     * pending) and *pfin, return the vector count used, 0 if nothing
     * pending right now, or -1 on error (having logged why). Mirrors
     * nghttp3_conn_writev_stream()'s contract exactly -- http_h3.c's
     * implementation just IS nghttp3_conn_writev_stream, relying on
     * nghttp3_vec and ngtcp2_vec having identical layout. */
    ngtcp2_ssize (*get_output)(struct quic_session *qs, int64_t *pstream_id,
                               int *pfin, ngtcp2_vec *vec, size_t veccnt);

    /* The transport actually sent |datalen| bytes of what get_output()
     * returned for |stream_id| -- record the write offset advancing
     * (nghttp3_conn_add_write_offset's job). */
    void (*advance_output)(struct quic_session *qs, int64_t stream_id,
                           size_t datalen);

    /* ngtcp2 couldn't accept more data for |stream_id| right now
     * (NGTCP2_ERR_STREAM_DATA_BLOCKED/SHUT_WR) -- don't ask
     * get_output() for it again until it un-blocks
     * (nghttp3_conn_block_stream's job). */
    void (*block_output)(struct quic_session *qs, int64_t stream_id);

    /* Free whatever the app owns (e.g. nghttp3_conn, open
     * transactions) before quic_session_free() tears down the
     * ngtcp2_conn/SSL underneath it. */
    void (*session_free)(struct quic_session *qs);
};

/* ALPN map plus which quic_app_ops to wire every ngtcp2 callback to,
 * for one application protocol riding on QUIC. */
struct quic_app {
    struct tls_alpn_t *alpn_map;
    const struct quic_app_ops *ops;
};

/* The current time, on the clock ngtcp2's own timers are set against.
 * An app whose own library (e.g. nghttp3) also wants a "steadily
 * increasing clock" timestamp should use this one, not a clock of its
 * own -- ngtcp2_conn_read_pkt() and (say) nghttp3_conn_read_stream2()
 * need to agree on what "now" means. */
ngtcp2_tstamp quic_now(void);

/* Parse the relayed first Initial packet master handed off (the
 * process-global `quic_handoff` from master/service.h, filled by
 * service.c's quic_recv_handoff()) and create the ngtcp2_conn for it,
 * embedded in *qs (caller-allocated -- the first member of the app's
 * own session struct, already zeroed). |fd| is the connection's own
 * socket (conn->pin->fd in httpd.c terms). Installs app->alpn_map on
 * ssl_ctx and wires every ngtcp2 callback to app->ops. Does NOT
 * process the first packet -- see qs->first_pkt's comment above.
 * Returns 0 on success, or -1 (having logged why) on failure. */
int quic_session_new(struct quic_session *qs, int fd, SSL_CTX *ssl_ctx,
                     const struct quic_app *app);

/* Feed one QUIC datagram to ngtcp2, call ops->io_ready() if it wasn't
 * dropped, and flush any resulting output. Sets qs->draining if the
 * connection is now done (peer CONNECTION_CLOSE, protocol error, or
 * ngtcp2 dropped it silently) -- check qs->draining after calling. */
void quic_process_datagram(struct quic_session *qs, const uint8_t *pkt,
                           size_t pktlen);

/* recv()s one datagram from qs->fd (MSG_DONTWAIT) and feeds it to
 * quic_process_datagram() if there was one. Returns true if the
 * caller should close the connection now, setting *close_reason to a
 * static string explaining why -- false means keep going. */
bool quic_input(struct quic_session *qs, const char **close_reason);

/* Flush any output ngtcp2/the app has queued. Call after anything that
 * might have queued new stream data (get_output() has more to give,
 * quic_handle_expiry() fired a PTO). Sets qs->draining on transport
 * failure. */
void quic_flush_output(struct quic_session *qs);

/* Seconds until this connection's next ngtcp2 timer needs servicing.
 * Always >= 1 once a session exists (ngtcp2 always has at least an
 * idle timeout armed). */
unsigned long quic_get_timeout(struct quic_session *qs);

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
