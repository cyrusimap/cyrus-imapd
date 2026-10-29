/* http_h3.c - HTTP/3 (QUIC) support functions */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>
#include <sysexits.h>

#include "httpd.h"
#include "http_h3.h"

#if defined(HAVE_NGHTTP3) && defined(HAVE_NGTCP2) && defined(WITH_QUIC)

#include <errno.h>
#include <inttypes.h>
#include <string.h>
#include <syslog.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <sys/socket.h>

#include <openssl/rand.h>
#include <openssl/ssl.h>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_ossl.h>
#include <nghttp3/nghttp3.h>

#include "global.h"
#include "http_ws.h"
#include "master/service.h"     // quic_handoff, cidlen/bufsize consts
#include "retry.h"
#include "xmalloc.h"

/* generated headers are not necessarily in current directory */
#include "imap/http_err.h"

#define HTTP3_MAX_HEADERS          100
#define HTTP3_WRITEV_MAX            16
#define HTTP3_MAX_TX_UDP_PAYLOAD  1452

/* Most datagrams http3_input() reads before flushing output */
#define HTTP3_RECV_BATCH            64

/* Reads per recvmmsg(); each is one datagram, or under UDP_GRO a run of
 * them the kernel coalesced, up to 64KB */
#define HTTP3_RECV_MSGS              8
#define HTTP3_GRO_BUFSIZE        65536

/* Most packets flush_output() hands the kernel in one UDP_SEGMENT
 * send: as many full-sized ones as fit in one 64KB datagram */
#define HTTP3_GSO_MAX_PKTS  (65535 / HTTP3_MAX_TX_UDP_PAYLOAD)
#define HTTP3_GSO_BUFSIZE   (HTTP3_GSO_MAX_PKTS * HTTP3_MAX_TX_UDP_PAYLOAD)

/* Room for a 0-RTT ticket's appdata: the QUIC version (4 bytes, network
 * order), then the 0-RTT transport parameters the server offered */
#define HTTP3_TICKET_APPDATA_MAX   256

/* QUIC idle timeout when neither httptimeout nor websocket_timeout sets
 * one, in seconds */
#define HTTP3_MIN_TRANSPORT_IDLE (300)

/* Long enough for a client on a lossy path to get through several
 * retransmissions, short enough that one which abandoned its attempt
 * without a CONNECTION_CLOSE (as clients racing QUIC against TCP do)
 * doesn't hold this worker for the whole idle timeout */
#define HTTP3_HANDSHAKE_TIMEOUT  (10 * NGTCP2_SECONDS)

/* A response body chunk handed to nghttp3 via data_source_read_cb(),
 * awaiting acked_stream_data_cb()'s notice that the peer acked it.
 * nghttp3 treats read_data callback buffers as caller-owned
 * (NGHTTP3_BUF_TYPE_ALIEN) and may resend the same pointer to ngtcp2
 * for retransmission any time before it's acked -- freeing it earlier
 * is a use-after-free that only shows up on real packet loss (e.g. via
 * http3_idle()'s PTO handling). */
struct http3_sent_chunk {
    struct buf buf;
    unsigned acked;
};

/* HTTP/3 stream context (one per request) */
struct http3_stream {
    int64_t id;
    size_t num_resp_hdrs;
    nghttp3_nv resp_hdrs[HTTP3_MAX_HEADERS];
    ptrarray_t old_hdr_values;  /* from earlier header blocks on the stream */
    bool chunk_queued;          /* queued for data_source_read_cb */

    /* Owned copy of what's queued for data_source_read_cb(), not yet
     * handed to a struct http3_sent_chunk. flush_output() is
     * flow-control-bounded and may drain nothing, so resp_body_chunk()
     * can run again before it does: this accumulates across calls
     * (buf_appendmap(), never buf_setmap()). Overwriting would silently
     * drop whatever hadn't been read out yet. */
    struct buf pending_body;
    bool pending_last_chunk;
    ptrarray_t sent_chunks;     /* struct http3_sent_chunk *, FIFO, awaiting ack */
};

/* HTTP/3 session context -- one per connection.  A worker only ever
 * serves one QUIC connection at a time (see http3_start_session()), so
 * there's no per-connection copy of auth/session state here: the usual
 * httpd_saslconn/httpd_userid/etc. globals, set up once per connection
 * by service_main(), are already correct for "the" connection. */
struct http3_context {
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

    /* http3_input()'s HTTP3_RECV_MSGS read buffers, rbufsize bytes each */
    uint8_t *rbuf;
    size_t rbufsize;

    /* flush_output()'s batch of packets for one send, of
     * HTTP3_GSO_BUFSIZE; gso while the kernel takes UDP_SEGMENT sends */
    uint8_t *sbuf;
    bool gso;

    /* The path the connection starts on, from the handoff.  After
     * that ngtcp2 picks the path each packet goes out on, and moves to
     * a new peer address only for a packet that authenticated (RFC 9000
     * 9.3), so flush_output() sends wherever it says.  Never send to
     * a packet's claimed source: the CID travels in cleartext, so such
     * a packet is cheap to forge, and ngtcp2_conn_read_pkt() returns
     * success even when the payload decrypts to nothing. */
    struct sockaddr_storage local_addr;
    socklen_t local_addrlen;
    struct sockaddr_storage peer_addr;
    socklen_t peer_addrlen;

    /* Where the last packet ngtcp2 accepted came from.  Usually ngtcp2's
     * current peer address, but not when it couldn't move there, e.g.
     * with no spare CID left for the new path */
    struct sockaddr_storage last_from;
    socklen_t last_fromlen;

    /* Spare CIDs master pre-registered in the dispatch backend for
     * this connection (quic_handoff.cids[1..], quic_handoff.h) --
     * get_new_connection_id_cb() hands them out one at a time as
     * ngtcp2 asks for a fresh one, e.g. for a client to migrate to. */
    uint8_t cid_pool[QUIC_CID_POOL_SIZE][QUIC_CIDLEN];
    uint8_t ncids;
    uint8_t next_pool_cid;

    bool draining;                /* closing; stop accepting new work */

    /* When ngtcp2 last accepted a packet from the peer,
     * in now_ts() time, for idle_deadline() */
    ngtcp2_tstamp last_input;

    nghttp3_conn *h3conn;

    int64_t ctrl_stream_id;
    int64_t qenc_stream_id;
    int64_t qdec_stream_id;

    /* Every struct transaction_t from begin_headers_cb() still live
     * (http3_stream_close_cb() hasn't freed it). Needed because
     * nghttp3_conn_del() frees its own per-stream state but doesn't
     * invoke .stream_close for streams still open at deletion time --
     * any stream still open at teardown (idle timeout, abrupt reset,
     * mid-connection fatal()) would otherwise leak its transaction_t.
     * session_free() walks this to free what's left before
     * nghttp3_conn_del() runs. */
    ptrarray_t open_txns;

    /* WebSocket streams open, which put the connection under
     * websocket_timeout instead of httptimeout (see idle_deadline()) */
    unsigned ws_streams;

    /* websocket_timeout in seconds, 0 if WebSockets are disabled */
    long ws_timeout;
};

/* Stateless reset tokens are derived from this, once per worker */
static uint8_t static_secret[32];

/* The QUIC versions advertised in version_information. A client's
 * choice among the versions ngtcp2 supports is honoured as-is. */
static const uint32_t quic_versions[] = QUIC_ADVERTISED_VERSIONS;

static struct tls_alpn_t http3_alpn_map[] = {
    { "h3", NULL, NULL },
    {  "" , NULL, NULL }
};

/* The current time, on the clock ngtcp2's and nghttp3's timers share */
static ngtcp2_tstamp now_ts(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);

    return (ngtcp2_tstamp) ts.tv_sec * NGTCP2_SECONDS +
           (ngtcp2_tstamp) ts.tv_nsec;
}

/* When the connection's inactivity timeout expires, in now_ts() time,
 * or 0 for never: httptimeout, or websocket_timeout while a WebSocket is
 * open, the same switch HTTP/1.1 and HTTP/2 make */
static ngtcp2_tstamp idle_deadline(const struct http3_context *ctx)
{
    unsigned long idle = ctx->ws_streams ? ctx->ws_timeout : httpd_timeout;

    return idle ? ctx->last_input + idle * NGTCP2_SECONDS : 0;
}

/*
 * TLS context, and 0-RTT tickets
 */

static ngtcp2_conn *ssl_conn(SSL *ssl)
{
    ngtcp2_crypto_conn_ref *ref = SSL_get_app_data(ssl);

    return ref ? ref->get_conn(ref) : NULL;
}

/* Build a ticket's appdata for |qconn| (see HTTP3_TICKET_APPDATA_MAX);
 * returns its length, or -1 */
static ngtcp2_ssize ticket_appdata(ngtcp2_conn *qconn, uint32_t version,
                                   uint8_t *buf, size_t buflen)
{
    ngtcp2_ssize n;

    buf[0] = version >> 24;
    buf[1] = version >> 16;
    buf[2] = version >> 8;
    buf[3] = version;

    n = ngtcp2_conn_encode_0rtt_transport_params(qconn, buf + 4, buflen - 4);
    return n < 0 ? -1 : n + 4;
}

/* Record in each ticket what the client's 0-RTT will be held to */
static int gen_ticket_cb(SSL *ssl, void *arg __attribute__((unused)))
{
    ngtcp2_conn *qconn = ssl_conn(ssl);
    uint8_t buf[HTTP3_TICKET_APPDATA_MAX];
    ngtcp2_ssize n;

    if (!qconn) return 1;

    n = ticket_appdata(qconn, ngtcp2_conn_get_negotiated_version(qconn),
                       buf, sizeof(buf));
    /* A ticket without appdata still resumes, just never with 0-RTT */
    if (n > 0) {
        SSL_SESSION_set1_ticket_appdata(SSL_get0_session(ssl), buf, n);
    }
    return 1;
}

/* Accept early data only in the QUIC version the ticket was issued for,
 * and only while the server still offers the transport parameters the
 * client remembered from then (RFC 9000 7.4.1) */
static int allow_early_data_cb(SSL *ssl, void *arg __attribute__((unused)))
{
    ngtcp2_conn *qconn = ssl_conn(ssl);
    uint8_t want[HTTP3_TICKET_APPDATA_MAX];
    void *have;
    size_t havelen;
    ngtcp2_ssize n;

    if (!qconn ||
        !SSL_SESSION_get0_ticket_appdata(SSL_get0_session(ssl),
                                         &have, &havelen)) {
        return 0;
    }

    n = ticket_appdata(qconn, ngtcp2_conn_get_client_chosen_version(qconn),
                       want, sizeof(want));
    return n > 0 && (size_t) n == havelen && !memcmp(want, have, havelen);
}

/* The TLS 1.3 server context every QUIC connection of this worker uses:
 * tls_new_serverctx()'s shared settings plus tls_server_cert and
 * tls_server_key, and with |early_data| single-use 0-RTT tickets.
 * Returns NULL (logged) on failure. */
static SSL_CTX *new_tls_ctx(bool early_data)
{
    SSL_CTX *ctx;

    /* Self-contained: tls_new_serverctx() does its own OpenSSL
     * library-wide init, since a QUIC-only worker never calls
     * tls_init_serverengine() */
    ctx = tls_new_serverctx("TLS QUIC server engine");
    if (!ctx) return NULL;

    if (ngtcp2_crypto_ossl_init()) {
        xsyslog_ev(LOG_ERR, "tls.quic.ossl_init_failed");
        goto fail;
    }

    /* QUIC mandates TLS 1.3 */
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_options(ctx, SSL_OP_ALL | SSL_OP_NO_COMPRESSION);

    if (!tls_set_cert_stuff(ctx, config_getstring(IMAPOPT_TLS_SERVER_CERT),
                            config_getstring(IMAPOPT_TLS_SERVER_KEY))) {
        xsyslog_ev(LOG_ERR, "tls.quic.cert_load_failed");
        goto fail;
    }

    /* RFC 9001 4.6.1: QUIC always advertises the maximum */
    if (early_data && tls_set_session_db(ctx, config_ident) &&
        tls_enable_early_data(ctx, UINT32_MAX)) {
        SSL_CTX_set_session_ticket_cb(ctx, gen_ticket_cb, NULL, NULL);
        SSL_CTX_set_allow_early_data_cb(ctx, allow_early_data_cb, NULL);

        /* Each ticket costs a database write, and each is good for only
         * one connection, which only ever needs one */
        SSL_CTX_set_num_tickets(ctx, 1);
    }
    else {
        SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
    }

    tls_set_alpn_map(ctx, http3_alpn_map);

    return ctx;

fail:
    SSL_CTX_free(ctx);
    return NULL;
}

/*
 * ngtcp2 callbacks.  Their user_data is the struct http3_context (set in
 * ngtcp2_conn_server_new(), see conn_new()).
 */

static ngtcp2_conn *get_conn(ngtcp2_crypto_conn_ref *ref)
{
    struct http3_context *ctx = (struct http3_context *) ref->user_data;

    return ctx->qconn;
}

static void rand_cb(uint8_t *dest, size_t destlen,
                    const ngtcp2_rand_ctx *rand_ctx __attribute__((unused)))
{
    RAND_bytes(dest, (int) destlen);
}

static int get_new_connection_id_cb(ngtcp2_conn *qconn __attribute__((unused)),
                                    ngtcp2_cid *cid, uint8_t *token,
                                    size_t cidlen, void *user_data)
{
    struct http3_context *ctx = (struct http3_context *) user_data;

    /* Hand out the next pre-registered spare from master's CID pool
     * (quic_handoff.cids[1..]) so a client that migrates to it is
     * already routable -- see "A spare CID pool for future connection
     * migration" in quic-dispatch.rst. An unregistered CID is worse
     * than none: master's backend would silently drop packets
     * addressed to it, so fail the connection now rather than let it
     * go dark later, whenever the client happens to pick it. */
    if (ctx->next_pool_cid >= ctx->ncids) {
        xsyslog_ev(LOG_WARNING, "quic.conn.cid_pool_exhausted");
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    memcpy(cid->data, ctx->cid_pool[ctx->next_pool_cid++], cidlen);
    cid->datalen = cidlen;

    /* The token is from this worker's static_secret.  A packet to a dead
     * CID can only reach master (which has no secret and treats it as a
     * new connection), never a process that could honour the token, so
     * stateless reset does not actually function here; this just keeps
     * the advertised token well-formed. */
    if (ngtcp2_crypto_generate_stateless_reset_token(
            token, static_secret, sizeof(static_secret), cid)) {
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    return 0;
}

static int remove_connection_id_cb(ngtcp2_conn *qconn __attribute__((unused)),
                                   const ngtcp2_cid *cid __attribute__((unused)),
                                   void *user_data __attribute__((unused)))
{
    /* The peer retired this CID (RFC 9000 5.1.2). Nothing frees the
     * matching dispatch-layer registration -- there's no channel back
     * to master for that, so it sits unused until the connection
     * tears down and the whole pool goes at once. */
    xsyslog_ev(LOG_DEBUG, "quic.conn.cid_retired");
    return 0;
}

static int handshake_completed_cb(ngtcp2_conn *qconn __attribute__((unused)),
                                  void *user_data)
{
    struct http3_context *ctx = (struct http3_context *) user_data;
    int bits = SSL_get_cipher_bits(ctx->ssl, NULL);

    xsyslog_ev(LOG_DEBUG, "http3.handshake.completed");

    /* Deferred from service_main(); see httpd_get_clienthost() */
    httpd_get_clienthost(true);

    saslprops.ssf = bits > 0 ? (unsigned) bits : 1;
    if (saslprops_set_tls(&saslprops, httpd_saslconn) != SASL_OK) {
        xsyslog_ev(LOG_NOTICE, "http3.saslprops.failed");
    }
    return 0;
}

/* Open the HTTP/3 control and QPACK encoder/decoder streams and bind
 * them to the nghttp3 session. Peer transport-parameter uni-stream
 * credit may not exist yet after just one packet (a large ClientHello
 * can span multiple Initial packets), so this waits for credit rather
 * than failing, retried after every datagram and before every delivery
 * of stream data (0-RTT data can come within the first datagram).
 * Idempotent: stream id 0 is never a valid server-initiated
 * uni-stream id, so it doubles as the "not yet done" sentinel. */
static int open_ctrl_streams(struct http3_context *ctx)
{
    int rv;

    if (ctx->ctrl_stream_id) return 0;
    if (ngtcp2_conn_get_streams_uni_left(ctx->qconn) < 3) return 0;

    if ((rv = ngtcp2_conn_open_uni_stream(ctx->qconn,
                                          &ctx->ctrl_stream_id, NULL)) ||
        (rv = ngtcp2_conn_open_uni_stream(ctx->qconn,
                                          &ctx->qenc_stream_id, NULL)) ||
        (rv = ngtcp2_conn_open_uni_stream(ctx->qconn,
                                          &ctx->qdec_stream_id, NULL))) {
        xsyslog_ev(LOG_ERR, "http3.streams.open_failed",
                   lf_s("error", ngtcp2_strerror(rv)));
        return -1;
    }

    nghttp3_conn_bind_control_stream(ctx->h3conn, ctx->ctrl_stream_id);
    nghttp3_conn_bind_qpack_streams(ctx->h3conn, ctx->qenc_stream_id,
                                    ctx->qdec_stream_id);
    return 0;
}

static int recv_stream_data_cb(
    ngtcp2_conn *qconn, uint32_t flags, int64_t stream_id,
    uint64_t offset __attribute__((unused)),
    const uint8_t *data, size_t datalen, void *user_data,
    void *stream_user_data __attribute__((unused)))
{
    struct http3_context *ctx = (struct http3_context *) user_data;
    nghttp3_ssize nconsumed;

    if (open_ctrl_streams(ctx)) return NGTCP2_ERR_CALLBACK_FAILURE;

    nconsumed = nghttp3_conn_read_stream2(ctx->h3conn, stream_id, data,
                                          datalen,
                                          flags & NGTCP2_STREAM_DATA_FLAG_FIN,
                                          now_ts());
    if (nconsumed < 0) {
        xsyslog_ev(LOG_ERR, "http3.stream.read_failed",
                   lf_s("error", nghttp3_strerror((int) nconsumed)));
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    /* nghttp3 counts only framing as consumed; recv_data_cb()
     * returns the credit for DATA payload */
    ngtcp2_conn_extend_max_stream_offset(qconn, stream_id,
                                         (uint64_t) nconsumed);
    ngtcp2_conn_extend_max_offset(qconn, (uint64_t) nconsumed);

    return 0;
}

static int acked_stream_data_offset_cb(
    ngtcp2_conn *qconn __attribute__((unused)), int64_t stream_id,
    uint64_t offset __attribute__((unused)), uint64_t datalen,
    void *user_data, void *stream_user_data __attribute__((unused)))
{
    struct http3_context *ctx = (struct http3_context *) user_data;

    nghttp3_conn_add_ack_offset(ctx->h3conn, stream_id, datalen);
    return 0;
}

static int quic_stream_close_cb(
    ngtcp2_conn *qconn __attribute__((unused)),
    uint32_t flags __attribute__((unused)), int64_t stream_id,
    uint64_t app_error_code, void *user_data,
    void *stream_user_data __attribute__((unused)))
{
    struct http3_context *ctx = (struct http3_context *) user_data;

    nghttp3_conn_close_stream(ctx->h3conn, stream_id, app_error_code);

    /* ngtcp2 never raises the client's stream limit by itself: without
     * this a connection is done after initial_max_streams_bidi requests */
    if (ngtcp2_is_bidi_stream(stream_id)) {
        ngtcp2_conn_extend_max_streams_bidi(ctx->qconn, 1);
    }
    return 0;
}

static int quic_stream_reset_cb(
    ngtcp2_conn *qconn __attribute__((unused)), int64_t stream_id,
    uint64_t final_size __attribute__((unused)),
    uint64_t app_error_code __attribute__((unused)), void *user_data,
    void *stream_user_data __attribute__((unused)))
{
    struct http3_context *ctx = (struct http3_context *) user_data;

    nghttp3_conn_shutdown_stream_read(ctx->h3conn, stream_id);
    return 0;
}

static int extend_max_stream_data_cb(
    ngtcp2_conn *qconn __attribute__((unused)), int64_t stream_id,
    uint64_t max_data __attribute__((unused)), void *user_data,
    void *stream_user_data __attribute__((unused)))
{
    struct http3_context *ctx = (struct http3_context *) user_data;

    if (nghttp3_conn_unblock_stream(ctx->h3conn, stream_id))
        return NGTCP2_ERR_CALLBACK_FAILURE;
    return 0;
}

static const ngtcp2_callbacks quic_callbacks = {
    .recv_client_initial      = ngtcp2_crypto_recv_client_initial_cb,
    .recv_crypto_data         = ngtcp2_crypto_recv_crypto_data_cb,
    .handshake_completed      = handshake_completed_cb,
    .encrypt                  = ngtcp2_crypto_encrypt_cb,
    .decrypt                  = ngtcp2_crypto_decrypt_cb,
    .hp_mask                  = ngtcp2_crypto_hp_mask_cb,
    .recv_stream_data         = recv_stream_data_cb,
    .acked_stream_data_offset = acked_stream_data_offset_cb,
    .stream_close             = quic_stream_close_cb,
    .stream_reset             = quic_stream_reset_cb,
    .extend_max_stream_data   = extend_max_stream_data_cb,
    .rand                     = rand_cb,
    .get_new_connection_id    = get_new_connection_id_cb,
    .remove_connection_id     = remove_connection_id_cb,
    .update_key               = ngtcp2_crypto_update_key_cb,
    .delete_crypto_aead_ctx   = ngtcp2_crypto_delete_crypto_aead_ctx_cb,
    .delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
    .get_path_challenge_data  = ngtcp2_crypto_get_path_challenge_data_cb,
    .version_negotiation      = ngtcp2_crypto_version_negotiation_cb,
};

/*
 * Moving packets
 */

/* Send one packet along |path|, the one ngtcp2 chose for it, and if
 * it's a CONNECTION_CLOSE (|closing|), also to where the client last
 * sent from */
static void send_packet(struct http3_context *ctx, const ngtcp2_path *path,
                        const uint8_t *pkt, size_t len, bool closing)
{
    /* ctx->send_fd is unconnected under either backend -- the eBPF
     * backend's per-connection socket deliberately so, to keep a
     * migrating client's traffic from being tied to one source
     * address (see master.c's quic_dispatch_connection()), and the
     * relay backend's is master's own rendezvous socket, shared with
     * every other connection -- so every write needs an explicit
     * destination. */
    if (sendto(ctx->send_fd, pkt, len, 0, (struct sockaddr *) path->remote.addr,
               path->remote.addrlen) < 0) {
        /* client closed connection */
        xsyslog_ev(LOG_DEBUG, "quic.send.failed");
    }

    /* A client that moved where ngtcp2 couldn't follow (no spare CID
     * for the new path) is no longer listening on ngtcp2's path.  One
     * small packet is well within what RFC 9000 8.1 allows to an
     * unvalidated address; anything more must wait for validation. */
    if (closing && ctx->last_fromlen &&
        (ctx->last_fromlen != path->remote.addrlen ||
         memcmp(&ctx->last_from, path->remote.addr, ctx->last_fromlen)) &&
        sendto(ctx->send_fd, pkt, len, 0,
               (struct sockaddr *) &ctx->last_from, ctx->last_fromlen) < 0) {
        xsyslog_ev(LOG_DEBUG, "quic.send.failed");
    }
}

/* Send len bytes of packets, each segsize long but the last, which may
 * be shorter: in one sendmsg() under UDP_SEGMENT, or one at a time
 * where the kernel can't segment them */
static void send_batch(struct http3_context *ctx, const ngtcp2_path *path,
                          const uint8_t *buf, size_t len, size_t segsize)
{
#ifdef UDP_SEGMENT
    if (ctx->gso && len > segsize) {
        uint16_t seg = (uint16_t) segsize;
        union {
            char buf[CMSG_SPACE(sizeof(uint16_t))];
            struct cmsghdr align;
        } cbuf = { 0 };
        struct iovec iov = { .iov_base = (void *) buf, .iov_len = len };
        struct msghdr msg = {
            .msg_name = path->remote.addr,
            .msg_namelen = path->remote.addrlen,
            .msg_iov = &iov,
            .msg_iovlen = 1,
            .msg_control = cbuf.buf,
            .msg_controllen = sizeof(cbuf.buf),
        };
        struct cmsghdr *cm = CMSG_FIRSTHDR(&msg);

        cm->cmsg_level = IPPROTO_UDP;
        cm->cmsg_type = UDP_SEGMENT;
        cm->cmsg_len = CMSG_LEN(sizeof(seg));
        memcpy(CMSG_DATA(cm), &seg, sizeof(seg));

        if (sendmsg(ctx->send_fd, &msg, 0) >= 0) return;
        if (errno != EIO) {
            /* client closed connection */
            xsyslog_ev(LOG_DEBUG, "quic.send.failed");
            return;
        }

        /* EIO: the route can't segment (no checksum offload) */
        xsyslog_ev(LOG_DEBUG, "quic.send.gso_unavailable");
        ctx->gso = false;
    }
#endif

    for (size_t off = 0; off < len; off += segsize) {
        send_packet(ctx, path, buf + off,
                    len - off < segsize ? len - off : segsize, false);
    }
}

/* Send a CONNECTION_CLOSE carrying |ccerr| and start draining */
static void send_close(struct http3_context *ctx, const ngtcp2_ccerr *ccerr)
{
    uint8_t buf[QUIC_PKT_BUFSIZE];
    ngtcp2_path_storage ps;
    ngtcp2_pkt_info pi = { 0 };
    ngtcp2_ssize n;

    ngtcp2_path_storage_zero(&ps);
    n = ngtcp2_conn_write_connection_close(ctx->qconn, &ps.path, &pi,
                                           buf, sizeof(buf), ccerr, now_ts());
    if (n > 0) send_packet(ctx, &ps.path, buf, (size_t) n, true);

    ctx->draining = true;
}

/* Send whatever nghttp3 and ngtcp2 have queued.  On failure, closes the
 * connection with a CONNECTION_CLOSE and sets ctx->draining. */
static void flush_output(struct http3_context *ctx)
{
    ngtcp2_ccerr ccerr;
    ngtcp2_path_storage ps;             /* where ngtcp2 sends each packet */
    ngtcp2_path_storage batch_ps;       /* where the batch in sbuf goes */
    ngtcp2_tstamp now = now_ts();
    size_t off = 0;                     /* end of the batch in sbuf */
    size_t segsize = 0;                 /* its packets' size */
    size_t burst = 0;                   /* bytes written this flush */
    size_t quantum = ngtcp2_conn_get_send_quantum(ctx->qconn);

    ngtcp2_path_storage_zero(&ps);
    ngtcp2_path_storage_zero(&batch_ps);

    /* Bounded defensively: NGTCP2_ERR_STREAM_DATA_BLOCKED/NOT_FOUND
     * retry in place without making progress on rare races between
     * ngtcp2 and nghttp3's stream teardown -- don't loop forever within
     * a single flush if that happens, just pick it up on the next
     * cmdloop() iteration.  A burst also stops at the send quantum,
     * the most ngtcp2 may send without spacing packets out. */
    for (int iterations = 0; iterations < 10000 && burst < quantum;
         iterations++) {
        int64_t stream_id = -1;
        int fin = 0;
        nghttp3_vec vec[HTTP3_WRITEV_MAX];
        nghttp3_ssize veccnt = 0;
        ngtcp2_ssize datalen = 0;
        ngtcp2_pkt_info pi = { 0 };
        ngtcp2_ssize n;

        if (ngtcp2_conn_get_max_data_left(ctx->qconn) > 0) {
            veccnt = nghttp3_conn_writev_stream(ctx->h3conn, &stream_id, &fin,
                                                vec, HTTP3_WRITEV_MAX);
            if (veccnt < 0) {
                xsyslog_ev(LOG_ERR, "http3.stream.writev_failed",
                           lf_s("error", nghttp3_strerror((int) veccnt)));
                ngtcp2_ccerr_set_application_error(
                    &ccerr,
                    nghttp3_err_infer_quic_app_error_code((int) veccnt),
                    NULL, 0);
                goto close;
            }
        }

        /* nghttp3_vec and ngtcp2_vec have identical layout */
        n = ngtcp2_conn_writev_stream(ctx->qconn, &ps.path, &pi,
                                      ctx->sbuf + off, HTTP3_MAX_TX_UDP_PAYLOAD,
                                      &datalen,
                                      fin ? NGTCP2_WRITE_STREAM_FLAG_FIN
                                          : NGTCP2_WRITE_STREAM_FLAG_NONE,
                                      stream_id, (const ngtcp2_vec *) vec,
                                      (size_t) veccnt, now);

        if (n < 0) {
            switch (n) {
            case NGTCP2_ERR_STREAM_DATA_BLOCKED:
            case NGTCP2_ERR_STREAM_SHUT_WR:
                nghttp3_conn_block_stream(ctx->h3conn, stream_id);
                continue;
            case NGTCP2_ERR_STREAM_NOT_FOUND:
                continue;
            default:
                xsyslog_ev(LOG_ERR, "quic.conn.writev_failed",
                           lf_s("error", ngtcp2_strerror((int) n)));
                ngtcp2_ccerr_set_liberr(&ccerr, (int) n, NULL, 0);
                goto close;
            }
        }

        if (stream_id >= 0 && datalen >= 0) {
            nghttp3_conn_add_write_offset(ctx->h3conn, stream_id,
                                          (size_t) datalen);
        }

        if (n == 0) break;             /* nothing more to send */

        /* Batch packets for one send.  They must share a path, and all
         * but the last must be the same size, so a packet for another
         * path or a bigger one starts a new batch, and a smaller one, or
         * a full batch, ends this one. */
        if (off && ((size_t) n > segsize ||
                    !ngtcp2_path_eq(&ps.path, &batch_ps.path))) {
            send_batch(ctx, &batch_ps.path, ctx->sbuf, off, segsize);
            memmove(ctx->sbuf, ctx->sbuf + off, (size_t) n);
            off = 0;
        }
        if (!off) {
            segsize = (size_t) n;
            ngtcp2_path_copy(&batch_ps.path, &ps.path);
        }
        off += (size_t) n;
        burst += (size_t) n;
        if ((size_t) n < segsize ||
            off + HTTP3_MAX_TX_UDP_PAYLOAD > HTTP3_GSO_BUFSIZE) {
            send_batch(ctx, &batch_ps.path, ctx->sbuf, off, segsize);
            off = 0;
        }
    }
    if (off) send_batch(ctx, &batch_ps.path, ctx->sbuf, off, segsize);

    /* Pace what's left: ngtcp2 holds further packets back until the
     * time this sets, which ngtcp2_conn_get_expiry() then reports, so
     * http3_idle() sends the next burst when it's due.  Reuse the same
     * |now| as the writes above, as ngtcp2's examples do. */
    ngtcp2_conn_update_pkt_tx_time(ctx->qconn, now);
    return;

close:
    if (off) send_batch(ctx, &batch_ps.path, ctx->sbuf, off, segsize);

    /* Tell the client, or it waits out its idle timeout: ngtcp2 can still
     * write a CONNECTION_CLOSE after a failed write (e.g. when the spare
     * CID pool runs out) */
    send_close(ctx, &ccerr);
}

/* Feed one datagram to ngtcp2, leaving what results for
 * process_output().  |from| is only what the datagram claims:
 * neither backend authenticates it, so it counts only once ngtcp2 has
 * accepted the packet.  Sets ctx->draining if the connection is now
 * done. */
static void read_datagram(struct http3_context *ctx,
                          const uint8_t *pkt, size_t pktlen,
                          const struct sockaddr_storage *from,
                          socklen_t fromlen)
{
    ngtcp2_path path;
    ngtcp2_pkt_info pi = { 0 };
    ngtcp2_conn_info info;
    uint64_t pkt_recv;
    int rv;

    ngtcp2_addr_init(&path.local, (struct sockaddr *) &ctx->local_addr,
                     ctx->local_addrlen);
    ngtcp2_addr_init(&path.remote, (struct sockaddr *) from, fromlen);
    path.user_data = NULL;

    ngtcp2_conn_get_conn_info(ctx->qconn, &info);
    pkt_recv = info.pkt_recv;

    rv = ngtcp2_conn_read_pkt(ctx->qconn, &path, &pi, pkt, pktlen, now_ts());
    switch (rv) {
    case 0:
        break;

    case NGTCP2_ERR_DRAINING: {
        /* Routine: peer sent CONNECTION_CLOSE (RFC 9000 10.2), e.g. a
         * one-shot client done with its single request.  No reply
         * needed: the peer already discarded its side. */
        const ngtcp2_ccerr *ccerr = ngtcp2_conn_get_ccerr(ctx->qconn);
        struct buf reason = BUF_INITIALIZER;

        buf_appendmap(&reason, (const char *) ccerr->reason,
                      ccerr->reasonlen);
        xsyslog_ev(LOG_DEBUG, "quic.conn.closed_by_peer",
                   lf_s("quic.close.type",
                        ccerr->type == NGTCP2_CCERR_TYPE_APPLICATION
                            ? "application" : "transport"),
                   lf_llx("quic.close.code", ccerr->error_code),
                   lf_s_opt("quic.close.reason",
                            buf_len(&reason) ? buf_cstring(&reason) : NULL));
        buf_free(&reason);
        ctx->draining = true;
        return;
    }

    case NGTCP2_ERR_DROP_CONN:
        /* Routine, per ngtcp2's documented contract: drop silently, no
         * CONNECTION_CLOSE -- e.g. still handshaking and a stateless
         * reset or unsupported version means there's no point
         * continuing. */
        xsyslog_ev(LOG_DEBUG, "quic.conn.dropped",
                   lf_s("error", ngtcp2_strerror(rv)));
        ctx->draining = true;
        return;

    default: {
        /* An actual local/protocol error (e.g. NGTCP2_ERR_CRYPTO/PROTO):
         * ngtcp2's contract is to answer it with a CONNECTION_CLOSE */
        ngtcp2_ccerr ccerr;

        xsyslog_ev(LOG_WARNING, "quic.conn.read_failed",
                   lf_s("error", ngtcp2_strerror(rv)));

        ngtcp2_ccerr_set_liberr(&ccerr, rv, NULL, 0);
        send_close(ctx, &ccerr);
        return;
    }
    }

    /* Only a packet ngtcp2 accepted shows the peer is still there: one
     * with a valid CID and nothing decryptable is cheap to forge */
    ngtcp2_conn_get_conn_info(ctx->qconn, &info);
    if (info.pkt_recv != pkt_recv) {
        ctx->last_input = now_ts();
        if (fromlen <= sizeof(ctx->last_from)) {
            memcpy(&ctx->last_from, from, fromlen);
            ctx->last_fromlen = fromlen;
        }
    }
}

/* Feed one read from http3_input() to ngtcp2: a relayed datagram, a
 * datagram, or a run of them the kernel coalesced under UDP_GRO.
 * Returns how many datagrams it held. */
static int input_msg(struct http_connection *conn,
                     struct msghdr *msg, size_t len)
{
    struct http3_context *ctx = (struct http3_context *) conn->sess_ctx;
    const uint8_t *pkt = msg->msg_iov->iov_base;
    struct sockaddr_storage *from = msg->msg_name;
    socklen_t fromlen = msg->msg_namelen;
    size_t seglen = len;
    int n = 0;

    if (len == 0) {
        /* Under the relay this is EOF: master has dropped the
         * connection, and the fd stays readable forever.  On the eBPF
         * backend's real UDP socket a zero-length datagram is legal. */
        if (ctx->relayed) {
            conn->close_str = "dispatch closed the connection";
            conn->close = 1;
        }
        return 0;
    }
    if (msg->msg_flags & MSG_TRUNC) return 0;

    if (ctx->relayed) {
        /* The relay's socketpair has no real address: master prefixes
         * each datagram with the one it arrived from instead -- see
         * "Tracking a moving peer address" in quic-dispatch.rst. */
        struct quic_relay_pkt_hdr hdr;

        if (len < sizeof(hdr)) {
            xsyslog_ev(LOG_ERR, "quic.recv.short_relay_header");
            conn->close_str = "malformed relay message";
            conn->close = 1;
            return 0;
        }
        memcpy(&hdr, pkt, sizeof(hdr));
        memcpy(from, &hdr.peer, sizeof(*from));
        fromlen = hdr.peerlen;
        pkt += sizeof(hdr);
        len -= sizeof(hdr);
        seglen = len;
    }
#ifdef UDP_GRO
    else {
        /* A coalesced run: every datagram but the last is seglen long */
        for (struct cmsghdr *cm = CMSG_FIRSTHDR(msg); cm;
             cm = CMSG_NXTHDR(msg, cm)) {
            if (cm->cmsg_level == IPPROTO_UDP && cm->cmsg_type == UDP_GRO) {
                int gso;

                memcpy(&gso, CMSG_DATA(cm), sizeof(gso));
                if (gso > 0) seglen = (size_t) gso;
            }
        }
    }
#endif

    for (size_t off = 0; off < len && !ctx->draining; off += seglen, n++) {
        read_datagram(ctx, pkt + off, len - off < seglen ? len - off : seglen,
                      from, fromlen);
    }
    return n;
}

/* Act on what read_datagram() fed ngtcp2 */
static void process_output(struct http3_context *ctx)
{
    if (open_ctrl_streams(ctx)) {
        ctx->draining = true;
        return;
    }

    flush_output(ctx);
}

/*
 * nghttp3 (HTTP/3 framing) callbacks -- these bridge into httpd.c's
 * existing, transport-agnostic request-processing pipeline. Their
 * conn_user_data is the struct http_connection (set once in
 * nghttp3_conn_server_new(), see http3_start_session()).
 */

static void stream_free(struct transaction_t *txn)
{
    if (txn) {
        struct http3_stream *strm = (struct http3_stream *) txn->strm_ctx;

        if (strm) {
            struct http3_sent_chunk *chunk;

            for (size_t i = 0; i < HTTP3_MAX_HEADERS; i++) {
                free((void *) strm->resp_hdrs[i].value);
            }
            char *value;
            while ((value = ptrarray_pop(&strm->old_hdr_values))) free(value);
            ptrarray_fini(&strm->old_hdr_values);
            buf_free(&strm->pending_body);

            /* Stream is going away -- no more acks are coming for
             * whatever's still outstanding, so free it now. */
            while ((chunk = (struct http3_sent_chunk *)
                            ptrarray_pop(&strm->sent_chunks))) {
                buf_free(&chunk->buf);
                free(chunk);
            }
            ptrarray_fini(&strm->sent_chunks);
            free(strm);
        }

        txn->strm_ctx = NULL;
    }
}

static int begin_headers_cb(nghttp3_conn *h3conn __attribute__((unused)),
                            int64_t stream_id, void *conn_user_data,
                            void *stream_user_data __attribute__((unused)))
{
    struct http_connection *conn = (struct http_connection *) conn_user_data;
    struct http3_context *ctx = (struct http3_context *) conn->sess_ctx;
    struct http3_stream *strm;
    struct transaction_t *txn;
    hdrcache_t hdrs = spool_new_hdrcache();

    if (!hdrs) return NGHTTP3_ERR_CALLBACK_FAILURE;

    txn = xzmalloc(sizeof(struct transaction_t));
    txn->conn = conn;
    txn->meth = METH_UNKNOWN;
    txn->flags.ver = VER_3;
    txn->flags.vary = VARY_AE;
    /* The client's 1-RTT keys only come into use after its Finished,
     * which is what completes the handshake here, so a request that
     * arrives before that can only have been sent as 0-RTT */
    txn->flags.early = !ngtcp2_conn_get_handshake_completed(ctx->qconn);
    txn->req_line.ver = HTTP3_VERSION;
    txn->req_hdrs = hdrs;

    if (config_getswitch(IMAPOPT_HTTPALLOWCOMPRESS)) {
        zlib_init(txn);
        brotli_init(txn);
        zstd_init(txn);
    }

    strm = xzmalloc(sizeof(struct http3_stream));
    strm->id = stream_id;
    txn->strm_ctx = strm;
    ptrarray_add(&txn->done_callbacks, &stream_free);

    uint32_t version = ngtcp2_conn_get_negotiated_version(ctx->qconn);
    switch (version) {
    case NGTCP2_PROTO_VER_V1:
        buf_setcstr(&txn->buf, "1");
        break;
    case NGTCP2_PROTO_VER_V2:
        buf_setcstr(&txn->buf, "2");
        break;
    default:
        buf_printf(&txn->buf, "0x%.08X", version);
        break;
    }
    spool_replace_header(xstrdup(":quic-version"),
                         buf_release(&txn->buf), txn->req_hdrs);

    buf_printf(&txn->buf, "%" PRId64, stream_id);
    spool_replace_header(xstrdup(":stream-id"),
                         buf_release(&txn->buf), txn->req_hdrs);

    nghttp3_conn_set_stream_user_data(h3conn, stream_id, txn);
    ptrarray_append(&ctx->open_txns, txn);

    return 0;
}

static int recv_header_cb(nghttp3_conn *h3conn __attribute__((unused)),
                          int64_t stream_id __attribute__((unused)),
                          int32_t token __attribute__((unused)),
                          nghttp3_rcbuf *name, nghttp3_rcbuf *value,
                          uint8_t flags __attribute__((unused)),
                          void *conn_user_data __attribute__((unused)),
                          void *stream_user_data)
{
    struct transaction_t *txn = (struct transaction_t *) stream_user_data;
    nghttp3_vec nv, vv;
    char *my_name, *my_value;

    if (!txn) return 0;

    nv = nghttp3_rcbuf_get_buf(name);
    vv = nghttp3_rcbuf_get_buf(value);
    my_name = xstrndup((const char *) nv.base, nv.len);
    my_value = xstrndup((const char *) vv.base, vv.len);

    if (my_name[0] == ':') {
        switch (my_name[1]) {
        case 'm': /* :method */
            if (!strcmp("ethod", my_name+2)) txn->req_line.meth = my_value;
            break;

        case 'p': /* :path, :protocol */
            if (!strcmp("ath", my_name+2)) txn->req_line.uri = my_value;
            else if (!strcmp("rotocol", my_name+2) &&
                     !strcmp(my_value, WS_TOKEN)) {
                txn->flags.upgrade |= UPGRADE_WS;
            }
            break;
        }
    }

    spool_cache_header(my_name, my_value, txn->req_hdrs);

    return 0;
}

/* Stop reading a request that has already been answered, and ask the
 * client to stop sending the rest (RFC 9114 4.1).  Otherwise nghttp3
 * keeps checking the body, and a client that ends it early, short of
 * its Content-Length, fails the whole connection. */
static void stop_reading(struct http3_context *ctx, int64_t stream_id)
{
    nghttp3_conn_shutdown_stream_read(ctx->h3conn, stream_id);
    ngtcp2_conn_shutdown_stream_read(ctx->qconn, 0, stream_id,
                                     NGHTTP3_H3_NO_ERROR);
}

static int end_headers_cb(nghttp3_conn *h3conn __attribute__((unused)),
                          int64_t stream_id, int fin,
                          void *conn_user_data,
                          void *stream_user_data)
{
    struct transaction_t *txn = (struct transaction_t *) stream_user_data;
    struct http_connection *conn = (struct http_connection *) conn_user_data;
    struct http3_context *ctx = (struct http3_context *) conn->sess_ctx;
    int ret;

    if (!txn) return 0;

    if (txn->conn->logfd != -1) {
        /* telemetry log */
        struct buf *logbuf = &txn->conn->logbuf;

        buf_reset(logbuf);
        buf_printf(logbuf, "<" TIME_T_FMT "<", time(NULL));   /* timestamp */
        buf_printf(logbuf, "%s %s %s\r\n",                    /* request-line */
                  txn->req_line.meth, txn->req_line.uri, HTTP3_VERSION);
        spool_enum_hdrcache(txn->req_hdrs, &log_cachehdr, logbuf);
        buf_appendcstr(logbuf, "\r\n");
        retry_write(txn->conn->logfd, buf_base(logbuf), buf_len(logbuf));
    }

    ret = examine_request(txn, NULL);
    if (ret) {
        txn->req_body.flags |= BODY_DISCARD;
        error_response(ret, txn);
        if (!fin) stop_reading(ctx, stream_id);
        return 0;
    }

    if (txn->req_body.flags & BODY_CONTINUE) {
        txn->req_body.flags &= ~BODY_CONTINUE;
        response_header(HTTP_CONTINUE, txn);
        return 0;
    }

    if (txn->meth == METH_CONNECT) {
        /* Bootstrapping WebSockets (or a tunnel) doesn't have a
         * traditional request body to wait for -- the peer's WS
         * frames arrive as ordinary DATA right after this, which
         * recv_data_cb() forwards to ws_input() once txn->ws_ctx
         * is set below. */
        ret = process_request(txn);
        if (ret) {
            error_response(ret, txn);
            if (!fin) stop_reading(ctx, stream_id);
        }
        else if (txn->ws_ctx) ctx->ws_streams++;
    }

    return 0;
}

static int recv_data_cb(nghttp3_conn *h3conn __attribute__((unused)),
                        int64_t stream_id,
                        const uint8_t *data, size_t datalen,
                        void *conn_user_data,
                        void *stream_user_data)
{
    struct transaction_t *txn = (struct transaction_t *) stream_user_data;
    struct http_connection *conn = (struct http_connection *) conn_user_data;
    struct http3_context *ctx = (struct http3_context *) conn->sess_ctx;

    /* DATA payload isn't in what nghttp3_conn_read_stream2() reports as
     * consumed.  It's copied or dropped right here, so hand the credit
     * back now, or a body bigger than the stream window stalls. */
    ngtcp2_conn_extend_max_stream_offset(ctx->qconn, stream_id, datalen);
    ngtcp2_conn_extend_max_offset(ctx->qconn, datalen);

    if (!txn) return 0;
    if (txn->req_body.flags & BODY_DISCARD) return 0;

    if (datalen) {
        /* Flow control bounds only what's in flight, not the whole body.
         * A WebSocket's messages are limited by ws_input() instead, and
         * a tunnel's DATA is forwarded as it arrives. */
        if (!txn->ws_ctx && !txn->be && txn->req_body.max &&
            datalen > txn->req_body.max - txn->req_body.len) {
            txn->req_body.flags |= BODY_DISCARD;
            error_response(HTTP_CONTENT_TOO_LARGE, txn);
            stop_reading(ctx, stream_id);
            return 0;
        }

        txn->req_body.framing = FRAMING_HTTP3;
        txn->req_body.len += datalen;
        buf_appendmap(&txn->req_body.payload, (const char *) data, datalen);

        if (txn->conn->logfd != -1) {
            /* telemetry log */
            struct buf *logbuf = &txn->conn->logbuf;
            struct iovec iov[2];
            int niov = 0;

            buf_reset(logbuf);
            buf_printf(logbuf, "<" TIME_T_FMT "<", time(NULL));
            WRITEV_ADD_TO_IOVEC(iov, niov, buf_base(logbuf), buf_len(logbuf));
            WRITEV_ADD_TO_IOVEC(iov, niov, data, datalen);
            retry_writev(txn->conn->logfd, iov, niov);
        }
    }

    if (txn->be) {
        /* Tunnel - stream input to backend */
        prot_putbuf(txn->be->out, &txn->req_body.payload);
        prot_flush(txn->be->out);
        buf_reset(&txn->req_body.payload);
        return 0;
    }

    if (txn->ws_ctx) {
        /* WebSocket over HTTP/3 input. */
        ws_input(txn);

        if (txn->flags.conn & CONN_CLOSE) {
            /* Abort the stream so it doesn't hang around. Cascades
             * into quic_stream_close_cb() -> nghttp3_conn_close_stream()
             * teardown once processed. */
            ngtcp2_conn_shutdown_stream(ctx->qconn, 0, stream_id,
                                        NGHTTP3_H3_NO_ERROR);
        }
    }

    return 0;
}

static int end_stream_cb(nghttp3_conn *h3conn __attribute__((unused)),
                         int64_t stream_id __attribute__((unused)),
                         void *conn_user_data __attribute__((unused)),
                         void *stream_user_data)
{
    struct transaction_t *txn = (struct transaction_t *) stream_user_data;
    int ret;

    if (!txn) return 0;
    if (txn->req_body.flags & BODY_DISCARD) return 0;

    ret = process_request(txn);
    if (ret) error_response(ret, txn);

    return 0;
}

static int http3_stream_close_cb(nghttp3_conn *h3conn __attribute__((unused)),
                                 int64_t stream_id __attribute__((unused)),
                                 uint64_t app_error_code __attribute__((unused)),
                                 void *conn_user_data,
                                 void *stream_user_data)
{
    struct transaction_t *txn = (struct transaction_t *) stream_user_data;

    if (txn) {
        struct http_connection *conn =
            (struct http_connection *) conn_user_data;
        struct http3_context *ctx = (struct http3_context *) conn->sess_ctx;
        int idx = ptrarray_find(&ctx->open_txns, txn, 0);

        if (idx >= 0) ptrarray_remove(&ctx->open_txns, idx);
        if (txn->ws_ctx) ctx->ws_streams--;

        transaction_free(txn);
        free(txn);
    }

    return 0;
}

/* nghttp3.h's nghttp3_read_data_callback contract: data offered by
 * data_source_read_cb() is caller-owned and "must [be] retain[ed]
 * until they are safe to free" -- signaled by this callback. |datalen|
 * is the number of bytes newly acked (not cumulative), in stream
 * order, so it always lands at the front of sent_chunks first. */
static int acked_stream_data_cb(nghttp3_conn *h3conn __attribute__((unused)),
                                int64_t stream_id __attribute__((unused)),
                                uint64_t datalen,
                                void *conn_user_data __attribute__((unused)),
                                void *stream_user_data)
{
    struct transaction_t *txn = (struct transaction_t *) stream_user_data;
    struct http3_stream *strm = (struct http3_stream *) txn->strm_ctx;

    while (datalen && ptrarray_size(&strm->sent_chunks)) {
        struct http3_sent_chunk *chunk =
            (struct http3_sent_chunk *) ptrarray_nth(&strm->sent_chunks, 0);
        unsigned len = buf_len(&chunk->buf);
        unsigned remaining = len - chunk->acked;
        unsigned n = datalen < remaining ? (unsigned) datalen : remaining;

        chunk->acked += n;
        datalen -= n;

        if (chunk->acked >= len) {
            ptrarray_shift(&strm->sent_chunks);
            buf_free(&chunk->buf);
            free(chunk);
        }
    }

    return 0;
}

static const nghttp3_callbacks http3_callbacks = {
    .stream_close      = http3_stream_close_cb,
    .recv_data         = recv_data_cb,
    .begin_headers     = begin_headers_cb,
    .recv_header       = recv_header_cb,
    .end_headers       = end_headers_cb,
    .end_stream        = end_stream_cb,
    .acked_stream_data = acked_stream_data_cb,
};

/*
 * Response generation vtable: begin_resp_headers/add_resp_header/
 * end_resp_headers/resp_body_chunk, against nghttp3's nv/data-reader
 * API.
 */

static void begin_resp_headers(struct transaction_t *txn, long code)
{
    struct http3_stream *strm = (struct http3_stream *) txn->strm_ctx;

    strm->num_resp_hdrs = 0;

    if (txn->conn->logfd != -1) {
        /* telemetry log */
        struct buf *logbuf = &txn->conn->logbuf;

        buf_reset(logbuf);
        buf_printf(logbuf, ">" TIME_T_FMT ">", time(NULL));  /* timestamp */
        retry_write(txn->conn->logfd, buf_base(logbuf), buf_len(logbuf));
    }

    if (code) simple_hdr(txn, ":status", "%.3s", error_message(code));
}

static void add_resp_header(struct transaction_t *txn,
                            const char *name, struct buf *value)
{
    struct http3_stream *strm = (struct http3_stream *) txn->strm_ctx;

    if (strm->num_resp_hdrs >= HTTP3_MAX_HEADERS) {
        buf_free(value);
        return;
    }

    nghttp3_nv *nv = &strm->resp_hdrs[strm->num_resp_hdrs];

    /* The earlier block may not be encoded yet (flush_output() can drain
       nothing), so its value has to outlive it */
    if (nv->value) ptrarray_append(&strm->old_hdr_values, (void *) nv->value);

    nv->namelen = strlen(name);
    nv->name = (const uint8_t *) name;
    nv->valuelen = buf_len(value);
    nv->value = (const uint8_t *) buf_release(value);
    nv->flags = NGHTTP3_NV_FLAG_NO_COPY_VALUE;

    strm->num_resp_hdrs++;

    if (txn->conn->logfd != -1) {
        /* telemetry log */
        struct iovec iov[4];
        int niov = 0;

        if (name[0] == ':') {
            WRITEV_ADD_TO_IOVEC(iov, niov, "HTTP/3 ", 7);
        }
        else {
            WRITEV_ADD_TO_IOVEC(iov, niov, nv->name, nv->namelen);
            WRITEV_ADD_TO_IOVEC(iov, niov, ": ", 2);
        }
        WRITEV_ADD_TO_IOVEC(iov, niov, nv->value, nv->valuelen);
        WRITEV_ADD_TO_IOVEC(iov, niov, "\r\n", 2);
        retry_writev(txn->conn->logfd, iov, niov);
    }
}

static nghttp3_ssize data_source_read_cb(
    nghttp3_conn *h3conn __attribute__((unused)),
    int64_t stream_id __attribute__((unused)),
    nghttp3_vec *vec, size_t veccnt, uint32_t *pflags,
    void *conn_user_data __attribute__((unused)),
    void *stream_user_data)
{
    /* stream_user_data is the stream's struct transaction_t (set once
     * in begin_headers_cb and never touched again) -- the pending
     * chunk lives in its http3_stream, NOT as its own stream_user_data, so
     * stream_close/etc. can keep finding the txn they expect. */
    struct transaction_t *txn = (struct transaction_t *) stream_user_data;
    struct http3_stream *strm = (struct http3_stream *) txn->strm_ctx;
    size_t n;

    if (veccnt < 1) return NGHTTP3_ERR_NOMEM;

    if (!strm->chunk_queued) {
        /* nghttp3_conn_writev_stream() gathers up to veccnt entries
         * per call, so it routinely asks again immediately after
         * draining what's queued -- not just on the resume-race path.
         * Its read_data contract requires NGHTTP3_ERR_WOULDBLOCK here
         * unless this is EOF, or nghttp3_stream_write_data()'s
         * assertion (datalen || flags & NGHTTP3_DATA_FLAG_EOF) aborts
         * the process; nghttp3_conn_resume_stream() in
         * resp_body_chunk() covers the resume-when-ready half. */
        if (strm->pending_last_chunk) {
            *pflags |= NGHTTP3_DATA_FLAG_EOF;
            return 0;
        }
        return NGHTTP3_ERR_WOULDBLOCK;
    }

    n = buf_len(&strm->pending_body);
    strm->chunk_queued = false;
    if (strm->pending_last_chunk) *pflags |= NGHTTP3_DATA_FLAG_EOF;

    if (!n) {
        buf_free(&strm->pending_body);
        return 0;
    }

    /* Can't free this here -- see struct http3_sent_chunk's comment.
     * Ownership moves to sent_chunks (via buf_move(), no copy);
     * acked_stream_data_cb() frees it once acked, stream_free()
     * frees it if the stream closes first. */
    struct http3_sent_chunk *chunk = xzmalloc(sizeof(*chunk));
    buf_move(&chunk->buf, &strm->pending_body);

    vec[0].base = (uint8_t *) buf_base(&chunk->buf);
    vec[0].len = n;

    ptrarray_append(&strm->sent_chunks, chunk);

    return 1;
}

static int end_resp_headers(struct transaction_t *txn, long code)
{
    struct http3_context *ctx = (struct http3_context *) txn->conn->sess_ctx;
    struct http3_stream *strm = (struct http3_stream *) txn->strm_ctx;
    int r;

    if (txn->conn->logfd != -1) {
        /* telemetry log */
        retry_write(txn->conn->logfd, "\r\n", 2);
    }

    switch (code) {
    case 0:
        r = nghttp3_conn_submit_trailers(ctx->h3conn, strm->id,
                                         strm->resp_hdrs,
                                         strm->num_resp_hdrs);
        if (r) {
            xsyslog_ev(LOG_ERR, "http3.trailers.submit_failed",
                       lf_s("error", nghttp3_strerror(r)));
        }
        return r;

    case HTTP_CONTINUE:
    case HTTP_PROCESSING:
    case HTTP_EARLY_HINTS:
        /* nghttp3_conn_submit_response() would end the stream */
        r = nghttp3_conn_submit_info(ctx->h3conn, strm->id,
                                     strm->resp_hdrs, strm->num_resp_hdrs);
        if (r) {
            xsyslog_ev(LOG_ERR, "http3.info.submit_failed",
                       lf_s("error", nghttp3_strerror(r)));
        }
        return r;

    default: {
        /* nghttp3 can't attach a data reader to an already-submitted
         * response, so a response with a body gets its reader now.
         * Submitting here rather than at the first body chunk also sends
         * the headers of a response whose body may not start for a while,
         * e.g. a WebSocket bootstrap (RFC 9220). */
        nghttp3_data_reader dr = { .read_data = data_source_read_cb };
        bool has_body = txn->meth != METH_HEAD &&
            (txn->resp_body.len || (txn->flags.te & TE_CHUNKED));

        r = nghttp3_conn_submit_response(ctx->h3conn, strm->id,
                                         strm->resp_hdrs,
                                         strm->num_resp_hdrs,
                                         has_body ? &dr : NULL);
        if (r) {
            xsyslog_ev(LOG_ERR, "http3.response.submit_failed",
                       lf_s("error", nghttp3_strerror(r)));
        }
        return r;
    }
    }
}

static int resp_body_chunk(struct transaction_t *txn,
                           const char *data, unsigned datalen,
                           int last_chunk, MD5_CTX *md5ctx)
{
    static unsigned char md5[MD5_DIGEST_LENGTH];
    struct http3_context *ctx = (struct http3_context *) txn->conn->sess_ctx;
    struct http3_stream *strm = (struct http3_stream *) txn->strm_ctx;

    if (!(datalen || (txn->flags.te && last_chunk))) return 0;

    if (txn->conn->logfd != -1) {
        /* telemetry log */
        struct buf *logbuf = &txn->conn->logbuf;
        struct iovec iov[2];
        int niov = 0;

        buf_reset(logbuf);
        buf_printf(logbuf, ">" TIME_T_FMT ">", time(NULL));
        WRITEV_ADD_TO_IOVEC(iov, niov, buf_base(logbuf), buf_len(logbuf));
        WRITEV_ADD_TO_IOVEC(iov, niov, data, datalen);
        retry_writev(txn->conn->logfd, iov, niov);
    }

    if (txn->flags.te) {
        if (!last_chunk) {
            if (datalen && (txn->flags.trailer & TRAILER_CMD5)) {
                MD5Update(md5ctx, data, datalen);
            }
        }
        else if (txn->flags.trailer && (txn->flags.trailer & TRAILER_CMD5)) {
            MD5Final(md5, md5ctx);
        }
    }

    /* data points into the caller's buffer (e.g. an mmap()ed static
     * file), which it may free/unmap as soon as this call returns, and
     * nghttp3/ngtcp2 may need to retain whatever we hand them well
     * beyond that (for retransmission, until acked) -- so an owned
     * copy is unavoidable, not just an optimization. Append, don't
     * replace -- see struct http3_stream's pending_body comment. */
    if (datalen) buf_appendmap(&strm->pending_body, data, datalen);
    strm->pending_last_chunk = last_chunk;
    strm->chunk_queued = true;

    /* Before the flush below: once data_source_read_cb() reports EOF
     * the stream is finished, unless trailers are already submitted */
    if (last_chunk && (txn->flags.trailer & ~TRAILER_PROXY)) {
        begin_resp_headers(txn, 0);
        if (txn->flags.trailer & TRAILER_CMD5) content_md5_hdr(txn, md5);
        if ((txn->flags.trailer & TRAILER_CTAG) && txn->resp_body.ctag) {
            simple_hdr(txn, "CTag", "%s", txn->resp_body.ctag);
        }
        end_resp_headers(txn, 0);
    }

    nghttp3_conn_resume_stream(ctx->h3conn, strm->id);
    flush_output(ctx);

    return 0;
}

/*
 * Session lifecycle
 */

/* Set up ctx's QUIC connection from the handoff master sent: its
 * addresses, CID pool and first Initial packet (which the caller then
 * processes).  |idle_timeout| is the transport idle timeout to offer
 * (RFC 9000 10.1), in seconds.  Returns 0, or -1 (logged). */
static int conn_new(struct http3_context *ctx, int fd, SSL_CTX *ssl_ctx,
                    unsigned long idle_timeout)
{
    const struct quic_handoff *h = service_quic_handoff();
    ngtcp2_pkt_hd hd;
    ngtcp2_cid scid;
    ngtcp2_settings settings;
    ngtcp2_transport_params params;
    ngtcp2_path path;
    int rv;

    /* No handoff at all, or implausible sizes in one, means master's
     * dispatch contract is broken, not a per-connection problem */
    if (!h ||
        h->ncids < 1 ||
        h->ncids > QUIC_CID_POOL_SIZE ||
        h->local_addrlen > sizeof(ctx->local_addr) ||
        h->peer_addrlen > sizeof(ctx->peer_addr) ||
        h->pktlen > sizeof(h->pkt) ||
        h->odcidlen > sizeof(h->odcid)) {
        fatal("http3: implausible QUIC_HANDOFF_FD handoff"
              " (QUIC requires master's dispatch)",
              EX_SOFTWARE);
    }

    ctx->fd = fd;
    ctx->send_fd = service_quic_send_fd();
    if (ctx->send_fd < 0) ctx->send_fd = fd;

    /* Settle once which backend handed us this fd. recvfrom() can't
     * tell us per-datagram: on the relay backend's connected
     * socketpair it reports no address at all. */
    {
        struct sockaddr_storage me;
        socklen_t melen = sizeof(me);

        ctx->relayed = !getsockname(fd, (struct sockaddr *) &me, &melen) &&
                       me.ss_family == AF_UNIX;
    }

    /* On the eBPF backend's real UDP socket, have the kernel coalesce a
     * burst from the client into one read */
    ctx->rbufsize = QUIC_PKT_BUFSIZE + sizeof(struct quic_relay_pkt_hdr);
#ifdef UDP_GRO
    if (!ctx->relayed) {
        int one = 1;

        if (!setsockopt(fd, IPPROTO_UDP, UDP_GRO, &one, sizeof(one)))
            ctx->rbufsize = HTTP3_GRO_BUFSIZE;
    }
#endif
    ctx->rbuf = xmalloc(HTTP3_RECV_MSGS * ctx->rbufsize);
    ctx->sbuf = xmalloc(HTTP3_GSO_BUFSIZE);
#ifdef UDP_SEGMENT
    ctx->gso = true;
#endif

    ctx->ncids = h->ncids - 1;
    memcpy(ctx->cid_pool, h->cids[1], ctx->ncids * QUIC_CIDLEN);

    /* Deliberately not getsockname(fd): that is a real local address
     * only for the eBPF backend's UDP socket, and an anonymous AF_UNIX
     * one that crashes ngtcp2_path_eq() under the relay.  master's
     * getsockname() on the rendezvous socket is valid for either. */
    ctx->local_addrlen = h->local_addrlen;
    memcpy(&ctx->local_addr, &h->local_addr, ctx->local_addrlen);
    ctx->peer_addrlen = h->peer_addrlen;
    memcpy(&ctx->peer_addr, &h->peer_addr, ctx->peer_addrlen);
    ctx->last_input = now_ts();

    if (ngtcp2_accept(&hd, h->pkt, h->pktlen) != 0) {
        fatal("http3: relayed packet is not a valid QUIC Initial",
              EX_SOFTWARE);
    }

    ctx->ssl = SSL_new(ssl_ctx);
    if (!ctx->ssl) return -1;
    SSL_set_accept_state(ctx->ssl);

    if (ngtcp2_crypto_ossl_ctx_new(&ctx->ossl_ctx, ctx->ssl) ||
        ngtcp2_crypto_ossl_configure_server_session(ctx->ssl)) {
        return -1;
    }

    /* new_tls_ctx() allows early data only when asked to, and with a
     * session cache to make it replay-safe */
    if (SSL_CTX_get_max_early_data(ssl_ctx)) {
        SSL_set_quic_tls_early_data_enabled(ctx->ssl, 1);
    }

    ctx->conn_ref.get_conn = &get_conn;
    ctx->conn_ref.user_data = ctx;
    SSL_set_app_data(ctx->ssl, &ctx->conn_ref);

    memcpy(scid.data, h->cids[0], QUIC_CIDLEN);
    scid.datalen = QUIC_CIDLEN;

    ngtcp2_settings_default(&settings);
    settings.initial_ts = now_ts();
    settings.handshake_timeout = HTTP3_HANDSHAKE_TIMEOUT;
    settings.max_tx_udp_payload_size = HTTP3_MAX_TX_UDP_PAYLOAD;
    settings.no_pmtud = 1;

    /* Advertise both versions we speak in the version_information
     * transport parameter (RFC 9368), so a client learns v2 is
     * available here.  Deliberately not settings.preferred_versions:
     * that would have the server override a client's own choice. */
    settings.available_versions = quic_versions;
    settings.available_versionslen = VECTOR_SIZE(quic_versions);

    ngtcp2_transport_params_default(&params);
    params.initial_max_stream_data_bidi_local = 256 * 1024;
    params.initial_max_stream_data_bidi_remote = 256 * 1024;
    params.initial_max_stream_data_uni = 256 * 1024;
    params.initial_max_data = 1024 * 1024;
    params.initial_max_streams_bidi = 100;
    params.initial_max_streams_uni = 3;
    params.active_connection_id_limit = 4;
    params.max_idle_timeout = (ngtcp2_duration) idle_timeout * NGTCP2_SECONDS;
    params.original_dcid = hd.dcid;
    params.original_dcid_present = 1;

    if (h->odcidlen) {
        /* master sent a Retry and verified this Initial's token, which
         * proves the client's address: ngtcp2 needs the token for that,
         * and the client checks both CIDs (RFC 9000 section 7.3) */
        settings.token = hd.token;
        settings.tokenlen = hd.tokenlen;
        settings.token_type = NGTCP2_TOKEN_TYPE_RETRY;
        ngtcp2_cid_init(&params.original_dcid, h->odcid, h->odcidlen);
        params.retry_scid = hd.dcid;
        params.retry_scid_present = 1;
    }

    ngtcp2_addr_init(&path.local, (struct sockaddr *) &ctx->local_addr,
                     ctx->local_addrlen);
    ngtcp2_addr_init(&path.remote, (struct sockaddr *) &ctx->peer_addr,
                     ctx->peer_addrlen);
    path.user_data = NULL;

    rv = ngtcp2_conn_server_new(&ctx->qconn, &hd.scid, &scid, &path,
                                hd.version, &quic_callbacks,
                                &settings, &params, NULL, ctx);
    if (rv) {
        xsyslog_ev(LOG_ERR, "quic.conn.create_failed",
                   lf_s("error", ngtcp2_strerror(rv)));
        return -1;
    }

    ngtcp2_conn_set_tls_native_handle(ctx->qconn, ctx->ossl_ctx);

    return 0;
}

/* Free ctx and everything it owns; safe on a partly set up one */
static void context_free(struct http3_context *ctx)
{
    struct transaction_t *txn;

    /* This is what open_txns exists for (see struct http3_context) --
     * order doesn't matter, nghttp3_conn_del() below hasn't run yet. */
    while ((txn = (struct transaction_t *) ptrarray_pop(&ctx->open_txns))) {
        transaction_free(txn);
        free(txn);
    }
    ptrarray_fini(&ctx->open_txns);

    if (ctx->h3conn) nghttp3_conn_del(ctx->h3conn);
    if (ctx->qconn) ngtcp2_conn_del(ctx->qconn);
    if (ctx->ossl_ctx) ngtcp2_crypto_ossl_ctx_del(ctx->ossl_ctx);
    if (ctx->ssl) {
        SSL_set_app_data(ctx->ssl, NULL);
        /* QUIC closes with CONNECTION_CLOSE, never a TLS close_notify, so
         * say the TLS side is shut down too: otherwise SSL_free() takes
         * the connection for a failed one and drops its latest session
         * ticket from the session cache */
        SSL_set_shutdown(ctx->ssl, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
        SSL_free(ctx->ssl);
    }

    free(ctx->rbuf);
    free(ctx->sbuf);
    free(ctx);
}

static void session_free(struct http_connection *conn)
{
    struct http3_context *ctx = (struct http3_context *) conn->sess_ctx;

    if (!ctx) return;

    context_free(ctx);

    conn->sess_ctx = NULL;
    conn->tls_ctx = NULL;
}

static void session_done(struct http_connection *conn)
{
    /* Safety net for abnormal termination -- session_free() normally
     * already ran via conn->reset_callbacks at cmdloop()'s natural end
     * (sess_ctx is NULL and this is a no-op). No graceful
     * CONNECTION_CLOSE first: the peer just sees silence and falls
     * back to its own idle timeout. */
    session_free(conn);
}

HIDDEN void http3_init(struct http_connection *conn, SSL_CTX **ssl_ctx,
                       struct buf *serverinfo)
{
    buf_printf(serverinfo, " Nghttp3/%s Ngtcp2/%s",
               NGHTTP3_VERSION, NGTCP2_VERSION);

    *ssl_ctx = new_tls_ctx(config_getswitch(IMAPOPT_HTTP_ALLOW_0RTT));
    if (!*ssl_ctx) {
        fatal("http3: error initializing QUIC-capable TLS context",
              EX_SOFTWARE);
    }

    RAND_bytes(static_secret, sizeof(static_secret));

    ptrarray_add(&conn->shutdown_callbacks, &session_done);
}

HIDDEN void http3_altsvc(struct buf *altsvc)
{
    const char *sep = buf_len(altsvc) ? ", " : "";
    const char *config_altsvc = config_getstring(IMAPOPT_HTTP_H3_ALTSVC);

    if (config_altsvc) {
        buf_printf(altsvc, "%sh3=\"%s\"", sep, config_altsvc);
    }
}

HIDDEN int http3_start_session(struct http_connection *conn, SSL_CTX *ssl_ctx)
{
    const struct quic_handoff *h;
    struct http3_context *ctx;
    nghttp3_settings h3settings;

    if (conn->sess_ctx) return 0;

    ctx = xzmalloc(sizeof(struct http3_context));

    ctx->ws_timeout = ws_enabled ?
        config_getduration(IMAPOPT_WEBSOCKET_TIMEOUT) : 0;
    if (ctx->ws_timeout < 0) ctx->ws_timeout = 0;

    /* idle_deadline() times the connection out itself, with a
     * CONNECTION_CLOSE, so QUIC's own idle timer, which just goes quiet,
     * runs a little longer.  Without either timeout it still needs one:
     * unlike TCP, QUIC has no keepalive to notice a client that vanished. */
    unsigned long transport_idle = MAX(httpd_timeout, ctx->ws_timeout);
    transport_idle =
        transport_idle ? transport_idle + 2 : HTTP3_MIN_TRANSPORT_IDLE;

    nghttp3_settings_default(&h3settings);
    /* Bootstrapping WebSockets over HTTP/3 (RFC 9220). */
    h3settings.enable_connect_protocol = ws_enabled;
    if (nghttp3_conn_server_new(&ctx->h3conn, &http3_callbacks,
                                &h3settings, NULL, conn)) {
        xsyslog_ev(LOG_ERR, "http3.h3conn.create_failed");
        context_free(ctx);
        return -1;
    }

    if (conn_new(ctx, conn->pin->fd, ssl_ctx, transport_idle)) {
        context_free(ctx);
        return -1;
    }

    conn->tls_ctx = ctx->ssl;
    conn->sess_ctx = ctx;
    conn->begin_resp_headers = &begin_resp_headers;
    conn->add_resp_header = &add_resp_header;
    conn->end_resp_headers = &end_resp_headers;
    conn->resp_body_chunk = &resp_body_chunk;

    ptrarray_add(&conn->reset_callbacks, &session_free);

    /* h3 never touches conn->pin/pout for the actual QUIC datagrams
     * (see flush_output()/http3_input(), which use the session's
     * own fds directly) -- nothing there for the prot layer to log. */
    prot_setlog(conn->pin, PROT_NO_FD);
    prot_setlog(conn->pout, PROT_NO_FD);

    h = service_quic_handoff();
    read_datagram(ctx, h->pkt, h->pktlen, &ctx->peer_addr, ctx->peer_addrlen);
    if (!ctx->draining) process_output(ctx);

    return 0;
}

HIDDEN void http3_input(struct http_connection *conn)
{
    struct http3_context *ctx = (struct http3_context *) conn->sess_ctx;
    int total = 0;

    /* Read everything queued, up to HTTP3_RECV_BATCH datagrams, before
     * flushing, so a burst gets one round of output (and of ACKs)
     * rather than one per datagram.  MSG_DONTWAIT: cmdloop() can call
     * this on a false positive (a read timeout expiring counts as
     * "ready" too), and blocking here would starve http3_idle()'s
     * timers. */
    while (total < HTTP3_RECV_BATCH && !ctx->draining && !conn->close) {
#ifdef HAVE_RECVMMSG
        struct mmsghdr msgs[HTTP3_RECV_MSGS];
#else
        struct { struct msghdr msg_hdr; unsigned int msg_len; } msgs[1];
#endif
        struct sockaddr_storage from[VECTOR_SIZE(msgs)];
        struct iovec iov[VECTOR_SIZE(msgs)];
        char cbuf[VECTOR_SIZE(msgs)][CMSG_SPACE(sizeof(int))];
        int n;

        memset(msgs, 0, sizeof(msgs));
        for (size_t i = 0; i < VECTOR_SIZE(msgs); i++) {
            iov[i].iov_base = ctx->rbuf + i * ctx->rbufsize;
            iov[i].iov_len = ctx->rbufsize;
            msgs[i].msg_hdr.msg_name = &from[i];
            msgs[i].msg_hdr.msg_namelen = sizeof(from[i]);
            msgs[i].msg_hdr.msg_iov = &iov[i];
            msgs[i].msg_hdr.msg_iovlen = 1;
            msgs[i].msg_hdr.msg_control = cbuf[i];
            msgs[i].msg_hdr.msg_controllen = sizeof(cbuf[i]);
        }

#ifdef HAVE_RECVMMSG
        n = recvmmsg(ctx->fd, msgs, VECTOR_SIZE(msgs), MSG_DONTWAIT, NULL);
#else
        {
            ssize_t r = recvmsg(ctx->fd, &msgs[0].msg_hdr, MSG_DONTWAIT);

            n = r < 0 ? -1 : 1;
            if (r >= 0) msgs[0].msg_len = (unsigned int) r;
        }
#endif
        if (n < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
                /* client closed connection */
                xsyslog_ev(LOG_DEBUG, "quic.recv.failed");
                conn->close_str = "recv failed";
                conn->close = 1;
            }
            break;
        }

        for (int i = 0; i < n && !ctx->draining && !conn->close; i++) {
            total += input_msg(conn, &msgs[i].msg_hdr, msgs[i].msg_len);
        }

        if ((size_t) n < VECTOR_SIZE(msgs)) break;  /* queue drained */
    }

    if (total && !ctx->draining) process_output(ctx);

    if (ctx->draining) {
        conn->close_str = "QUIC connection draining";
        conn->close = 1;
    }
}

HIDDEN unsigned long http3_get_timeout(struct http_connection *conn)
{
    struct http3_context *ctx = (struct http3_context *) conn->sess_ctx;
    ngtcp2_tstamp now, expiry, deadline;

    if (!ctx) return 0;

    now = now_ts();

    /* The sooner of ngtcp2's next timer and idle_deadline() */
    expiry = ngtcp2_conn_get_expiry(ctx->qconn);
    deadline = idle_deadline(ctx);
    if (deadline && deadline < expiry) expiry = deadline;
    if (expiry <= now) return 1;

    /* Round up, so as never to wake before it's due.  Loss detection
     * timers are milliseconds on a fast path, so anything coarser makes
     * every lost packet stall the connection.  Cap at 60s so a long idle
     * timeout doesn't hold off shutdown/signal handling. */
    ngtcp2_tstamp usecs = (expiry - now + NGTCP2_MICROSECONDS - 1) /
                          NGTCP2_MICROSECONDS;
    return usecs < 60 * 1000000 ? (unsigned long) usecs : 60 * 1000000;
}

HIDDEN bool http3_traffic(struct http_connection *conn,
                          uint64_t *bytes_in, uint64_t *bytes_out)
{
    struct http3_context *ctx = (struct http3_context *) conn->sess_ctx;

    if (!ctx) return false;

    ngtcp2_conn_info info;

    ngtcp2_conn_get_conn_info(ctx->qconn, &info);
    *bytes_in = info.bytes_recv;
    *bytes_out = info.bytes_sent;
    return true;
}

HIDDEN void http3_idle(struct http_connection *conn)
{
    struct http3_context *ctx = (struct http3_context *) conn->sess_ctx;
    ngtcp2_tstamp now, deadline;

    if (!ctx) return;

    now = now_ts();

    if (!ctx->draining && ngtcp2_conn_get_expiry(ctx->qconn) <= now) {
        int rv = ngtcp2_conn_handle_expiry(ctx->qconn, now);

        if (rv) {
            xsyslog_ev(LOG_DEBUG, "quic.conn.expired",
                       lf_s("error", ngtcp2_strerror(rv)));
            ctx->draining = true;
        }
        else flush_output(ctx);
    }

    if (ctx->draining) {
        conn->close_str = "QUIC idle timeout";
        conn->close = 1;
        return;
    }

    deadline = idle_deadline(ctx);
    if (deadline && now >= deadline) {
        ngtcp2_ccerr ccerr;

        ngtcp2_ccerr_set_application_error(&ccerr, NGHTTP3_H3_NO_ERROR,
                                           NULL, 0);
        send_close(ctx, &ccerr);
        conn->close_str = "HTTP/3 idle timeout";
        conn->close = 1;
    }
}

#else /* !(HAVE_NGHTTP3 && HAVE_NGTCP2 && WITH_QUIC) */

HIDDEN void http3_init(struct http_connection *conn __attribute__((unused)),
                       SSL_CTX **ssl_ctx __attribute__((unused)),
                       struct buf *serverinfo __attribute__((unused)))
{
    fatal("HTTP/3 requested, but built without ngtcp2/nghttp3", EX_SOFTWARE);
}

HIDDEN void http3_altsvc(struct buf *altsvc __attribute__((unused)))
{
}

HIDDEN int http3_start_session(
    struct http_connection *conn __attribute__((unused)),
    SSL_CTX *ssl_ctx __attribute__((unused)))
{
    fatal("http3_start_session() called, but no ngtcp2/nghttp3", EX_SOFTWARE);
}

HIDDEN void http3_input(struct http_connection *conn __attribute__((unused)))
{
    fatal("http3_input() called, but no ngtcp2/nghttp3", EX_SOFTWARE);
}

HIDDEN unsigned long http3_get_timeout(
    struct http_connection *conn __attribute__((unused)))
{
    return 0;
}

HIDDEN void http3_idle(struct http_connection *conn __attribute__((unused)))
{
}

HIDDEN bool http3_traffic(struct http_connection *conn __attribute__((unused)),
                          uint64_t *bytes_in __attribute__((unused)),
                          uint64_t *bytes_out __attribute__((unused)))
{
    return false;
}

#endif /* HAVE_NGHTTP3 && HAVE_NGTCP2 && WITH_QUIC */
