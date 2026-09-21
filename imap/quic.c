/* quic.c - generic per-worker QUIC transport session */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>

#ifdef HAVE_NGTCP2

#include "quic.h"

#include <errno.h>
#include <string.h>
#include <sysexits.h>

#include <openssl/rand.h>

#include "libconfig.h"           // config_getduration()
#include "util.h"
#include "xmalloc.h"

#define QUIC_WRITEV_MAX           16
#define QUIC_MAX_TX_UDP_PAYLOAD 1452

static uint8_t quic_static_secret[32];
static bool quic_static_secret_ready = false;

/* The QUIC versions advertised in version_information. A client's
 * choice among the versions ngtcp2 supports is honoured as-is. */
static const uint32_t quic_versions[] = QUIC_ADVERTISED_VERSIONS;

ngtcp2_tstamp quic_now(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);

    return (ngtcp2_tstamp) ts.tv_sec * NGTCP2_SECONDS +
           (ngtcp2_tstamp) ts.tv_nsec;
}

int quic_init_tls_ctx(SSL_CTX **ret)
{
    static SSL_CTX *s_ctx_quic = NULL;
    const char *server_cert_file;
    const char *server_key_file;

    if (s_ctx_quic) {
        if (ret) *ret = s_ctx_quic;
        return 0;                              /* already running */
    }

    /* Self-contained: tls_new_serverctx() does its own OpenSSL
     * library-wide init rather than requiring tls_init_serverengine()
     * to have run first (a QUIC-only worker never calls that). Redoing
     * it here if tls_init_serverengine() *did* also run is harmless --
     * these calls are idempotent. */
    s_ctx_quic = tls_new_serverctx("TLS QUIC server engine");
    if (!s_ctx_quic) return -1;

    /* Needs OpenSSL's library-wide init (just done above), but not
     * tied to any particular SSL_CTX. */
    if (ngtcp2_crypto_ossl_init()) {
        xsyslog_ev(LOG_ERR, "tls.quic.ossl_init_failed");
        SSL_CTX_free(s_ctx_quic);
        s_ctx_quic = NULL;
        return -1;
    }

    /* QUIC mandates TLS 1.3 */
    SSL_CTX_set_min_proto_version(s_ctx_quic, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(s_ctx_quic, TLS1_3_VERSION);
    SSL_CTX_set_options(s_ctx_quic, SSL_OP_ALL | SSL_OP_NO_COMPRESSION);

    server_cert_file = config_getstring(IMAPOPT_TLS_SERVER_CERT);
    server_key_file = config_getstring(IMAPOPT_TLS_SERVER_KEY);
    if (!tls_set_cert_stuff(s_ctx_quic, server_cert_file, server_key_file)) {
        xsyslog_ev(LOG_ERR, "tls.quic.cert_load_failed");
        SSL_CTX_free(s_ctx_quic);
        s_ctx_quic = NULL;
        return -1;
    }

    /* Not shared with the TCP session cache/ticket infrastructure --
     * no 0-RTT support. */
    SSL_CTX_set_session_cache_mode(s_ctx_quic, SSL_SESS_CACHE_OFF);

    if (ret) *ret = s_ctx_quic;
    return 0;
}

/*
 * ngtcp2 <-> OpenSSL glue
 */

static ngtcp2_conn *quic_get_conn(ngtcp2_crypto_conn_ref *ref)
{
    struct quic_session *qs = (struct quic_session *) ref->user_data;
    return qs->qconn;
}

/*
 * ngtcp2 application callbacks (no ngtcp2_crypto_* helper exists for
 * these -- they're transport/app glue, not TLS-crypto logic). Their
 * user_data is the struct quic_session (set once in
 * ngtcp2_conn_server_new(), see quic_session_new()). Each is a thin
 * trampoline into qs->ops, except where noted.
 */

static void quic_rand_cb(
    uint8_t *dest, size_t destlen,
    const ngtcp2_rand_ctx *rand_ctx __attribute__((unused)))
{
    RAND_bytes(dest, (int) destlen);
}

static int quic_get_new_connection_id_cb(
    ngtcp2_conn *qconn __attribute__((unused)),
    ngtcp2_cid *cid, uint8_t *token, size_t cidlen,
    void *user_data)
{
    struct quic_session *qs = (struct quic_session *) user_data;

    /* Hand out the next pre-registered spare from master's CID pool
     * (quic_handoff.cids[1..]) so a client that migrates to it is
     * already routable -- see "A spare CID pool for future connection
     * migration" in quic-dispatch.rst. An unregistered CID is worse
     * than none: master's backend would silently drop packets
     * addressed to it, so fail the connection now rather than let it
     * go dark later, whenever the client happens to pick it. */
    if (qs->next_pool_cid >= qs->ncids) {
        xsyslog_ev(LOG_WARNING, "quic.conn.cid_pool_exhausted");
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    memcpy(cid->data, qs->cid_pool[qs->next_pool_cid++], cidlen);
    cid->datalen = cidlen;

    if (ngtcp2_crypto_generate_stateless_reset_token(
            token, quic_static_secret, sizeof(quic_static_secret), cid)) {
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    return 0;
}

static int quic_remove_connection_id_cb(
    ngtcp2_conn *qconn __attribute__((unused)),
    const ngtcp2_cid *cid __attribute__((unused)),
    void *user_data __attribute__((unused)))
{
    /* The peer retired this CID (RFC 9000 5.1.2's RETIRE_CONNECTION_ID):
     * ngtcp2 stops expecting it and replenishes via
     * quic_get_new_connection_id_cb() if needed. Nothing frees the
     * matching dispatch-layer registration -- there's no channel back
     * to master for that today, so it sits unused until the connection
     * tears down and the whole pool goes at once. */
    xsyslog_ev(LOG_DEBUG, "quic.conn.cid_retired");
    return 0;
}

static int quic_handshake_completed_cb(
    ngtcp2_conn *qconn __attribute__((unused)), void *user_data)
{
    struct quic_session *qs = (struct quic_session *) user_data;

    qs->ops->handshake_completed(qs);
    return 0;
}

static int quic_path_validation_cb(
    ngtcp2_conn *qconn __attribute__((unused)),
    uint32_t flags __attribute__((unused)), const ngtcp2_path *path,
    const ngtcp2_path *fallback_path __attribute__((unused)),
    ngtcp2_path_validation_result res, void *user_data)
{
    struct quic_session *qs = (struct quic_session *) user_data;

    /* The actual outcome of RFC 9000 9.3's PATH_CHALLENGE/PATH_RESPONSE
     * exchange: only a SUCCESS result means the peer has proven it can
     * both send *and* receive on this path, which is what
     * quic_flush_output() needs before trusting it. See struct
     * quic_session's peer_addr comment for why nothing else may set
     * that address. */
    if (res != NGTCP2_PATH_VALIDATION_RESULT_SUCCESS) return 0;

    qs->local_addrlen = (socklen_t) path->local.addrlen;
    memcpy(&qs->local_addr, path->local.addr, qs->local_addrlen);
    qs->peer_addrlen = (socklen_t) path->remote.addrlen;
    memcpy(&qs->peer_addr, path->remote.addr, qs->peer_addrlen);

    return 0;
}

static int quic_recv_stream_data_cb(
    ngtcp2_conn *qconn, uint32_t flags, int64_t stream_id,
    uint64_t offset __attribute__((unused)),
    const uint8_t *data, size_t datalen, void *user_data,
    void *stream_user_data __attribute__((unused)))
{
    struct quic_session *qs = (struct quic_session *) user_data;
    bool fin = flags & NGTCP2_STREAM_DATA_FLAG_FIN;
    ngtcp2_ssize nconsumed;

    nconsumed = qs->ops->recv_stream_data(qs, stream_id, data, datalen, fin);
    if (nconsumed < 0) return NGTCP2_ERR_CALLBACK_FAILURE;

    ngtcp2_conn_extend_max_stream_offset(qconn, stream_id,
                                         (uint64_t) nconsumed);
    ngtcp2_conn_extend_max_offset(qconn, (uint64_t) nconsumed);

    return 0;
}

static int quic_acked_stream_data_offset_cb(
    ngtcp2_conn *qconn __attribute__((unused)), int64_t stream_id,
    uint64_t offset __attribute__((unused)), uint64_t datalen,
    void *user_data, void *stream_user_data __attribute__((unused)))
{
    struct quic_session *qs = (struct quic_session *) user_data;

    qs->ops->acked_stream_data(qs, stream_id, datalen);
    return 0;
}

static int quic_stream_close_cb(ngtcp2_conn *qconn __attribute__((unused)),
                                uint32_t flags __attribute__((unused)),
                                int64_t stream_id, uint64_t app_error_code,
                                void *user_data,
                                void *stream_user_data __attribute__((unused)))
{
    struct quic_session *qs = (struct quic_session *) user_data;

    qs->ops->stream_closed(qs, stream_id, app_error_code);
    return 0;
}

static int quic_stream_reset_cb(ngtcp2_conn *qconn __attribute__((unused)),
                                int64_t stream_id,
                                uint64_t final_size __attribute__((unused)),
                                uint64_t app_error_code, void *user_data,
                                void *stream_user_data __attribute__((unused)))
{
    struct quic_session *qs = (struct quic_session *) user_data;

    qs->ops->stream_reset(qs, stream_id, app_error_code);
    return 0;
}

static int quic_extend_max_stream_data_cb(
    ngtcp2_conn *qconn __attribute__((unused)), int64_t stream_id,
    uint64_t max_data __attribute__((unused)), void *user_data,
    void *stream_user_data __attribute__((unused)))
{
    struct quic_session *qs = (struct quic_session *) user_data;

    if (qs->ops->unblock_output(qs, stream_id))
        return NGTCP2_ERR_CALLBACK_FAILURE;
    return 0;
}

static const ngtcp2_callbacks quic_ngtcp2_callbacks = {
    .recv_client_initial      = ngtcp2_crypto_recv_client_initial_cb,
    .recv_crypto_data         = ngtcp2_crypto_recv_crypto_data_cb,
    .handshake_completed      = quic_handshake_completed_cb,
    .path_validation          = quic_path_validation_cb,
    .encrypt                  = ngtcp2_crypto_encrypt_cb,
    .decrypt                  = ngtcp2_crypto_decrypt_cb,
    .hp_mask                  = ngtcp2_crypto_hp_mask_cb,
    .recv_stream_data         = quic_recv_stream_data_cb,
    .acked_stream_data_offset = quic_acked_stream_data_offset_cb,
    .stream_close             = quic_stream_close_cb,
    .stream_reset             = quic_stream_reset_cb,
    .extend_max_stream_data   = quic_extend_max_stream_data_cb,
    .rand                     = quic_rand_cb,
    .get_new_connection_id    = quic_get_new_connection_id_cb,
    .remove_connection_id     = quic_remove_connection_id_cb,
    .update_key               = ngtcp2_crypto_update_key_cb,
    .delete_crypto_aead_ctx   = ngtcp2_crypto_delete_crypto_aead_ctx_cb,
    .delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
    .get_path_challenge_data  = ngtcp2_crypto_get_path_challenge_data_cb,
    .version_negotiation      = ngtcp2_crypto_version_negotiation_cb,
};

int quic_session_new(struct quic_session *qs, int fd, SSL_CTX *ssl_ctx,
                     const struct quic_app *app, unsigned long idle_timeout)
{
    const struct quic_handoff *h = service_quic_handoff();
    uint8_t forced_scid[QUIC_CIDLEN];
    ngtcp2_pkt_hd hd;
    ngtcp2_cid my_scid;
    ngtcp2_settings settings;
    ngtcp2_transport_params params;
    ngtcp2_path path;
    SSL *ssl = NULL;
    ngtcp2_crypto_ossl_ctx *ossl_ctx = NULL;
    int rv;

    if (!quic_static_secret_ready) {
        RAND_bytes(quic_static_secret, sizeof(quic_static_secret));
        quic_static_secret_ready = true;
    }

    /* The handoff reaches us through service_quic_handoff(): master's
     * dispatch in a real worker, a test harness playing master's part
     * otherwise. Either way no handoff at all, or implausible sizes in
     * one, means that contract is broken, not a per-connection
     * problem. */
    if (!h ||
        h->ncids < 1 ||
        h->ncids > QUIC_CID_POOL_SIZE ||
        h->local_addrlen > sizeof(qs->local_addr) ||
        h->peer_addrlen > sizeof(qs->peer_addr) ||
        h->pktlen > sizeof(qs->first_pkt)) {
        fatal("quic: implausible QUIC_HANDOFF_FD handoff"
             " (QUIC requires master's dispatch)",
             EX_SOFTWARE);
    }

    qs->fd = fd;
    qs->send_fd = h->send_fd >= 0 ? h->send_fd : fd;

    /* Settle once which backend handed us this fd. recvfrom() can't
     * tell us per-datagram: on the relay backend's connected
     * socketpair it reports no address at all, leaving whatever the
     * caller passed in. */
    {
        struct sockaddr_storage me;
        socklen_t melen = sizeof(me);

        qs->relayed = !getsockname(fd, (struct sockaddr *) &me, &melen) &&
                      me.ss_family == AF_UNIX;
    }

    memcpy(forced_scid, h->cids[0], QUIC_CIDLEN);
    qs->ncids = h->ncids - 1;
    memcpy(qs->cid_pool, h->cids[1], qs->ncids * QUIC_CIDLEN);
    qs->next_pool_cid = 0;
    qs->local_addrlen = h->local_addrlen;
    memcpy(&qs->local_addr, &h->local_addr, qs->local_addrlen);
    qs->peer_addrlen = h->peer_addrlen;
    memcpy(&qs->peer_addr, &h->peer_addr, qs->peer_addrlen);
    qs->first_pktlen = h->pktlen;
    memcpy(qs->first_pkt, h->pkt, qs->first_pktlen);
    qs->last_input = quic_now();

    /* Deliberately not getsockname(fd, ...): that yields a real local
     * IP:port only for the eBPF backend's per-connection UDP socket.
     * Under the relay backend fd is an AF_UNIX socketpair, where it
     * returns an anonymous address -- a corrupt 2-byte "local"
     * sockaddr that crashes ngtcp2_path_eq(). master's getsockname()
     * on the real rendezvous socket is valid for either backend, so it
     * sends that address in quic_handoff instead. */

    if (ngtcp2_accept(&hd, qs->first_pkt, qs->first_pktlen) != 0) {
        fatal("quic: relayed packet is not a valid QUIC Initial",
             EX_SOFTWARE);
    }

    tls_set_alpn_map(ssl_ctx, app->alpn_map);

    ssl = SSL_new(ssl_ctx);
    if (!ssl) goto fail;
    SSL_set_accept_state(ssl);

    if (ngtcp2_crypto_ossl_ctx_new(&ossl_ctx, ssl)) goto fail;
    if (ngtcp2_crypto_ossl_configure_server_session(ssl)) goto fail;

    qs->conn_ref.get_conn = &quic_get_conn;
    qs->conn_ref.user_data = qs;
    SSL_set_app_data(ssl, &qs->conn_ref);

    memcpy(my_scid.data, forced_scid, QUIC_CIDLEN);
    my_scid.datalen = QUIC_CIDLEN;

    ngtcp2_settings_default(&settings);
    settings.initial_ts = quic_now();
    settings.max_tx_udp_payload_size = QUIC_MAX_TX_UDP_PAYLOAD;
    settings.no_pmtud = 1;

    /* Advertise both versions we speak in the version_information
     * transport parameter (RFC 9368's Fully-Deployed Versions), so a
     * client learns v2 is available here. Left unset, ngtcp2 would
     * advertise v1 alone. Deliberately not settings.preferred_versions:
     * that would have the server pick the version, overriding a
     * client that asked for one we also support, and there's nothing
     * to gain by moving it off its own choice. */
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

    ngtcp2_addr_init(&path.local, (struct sockaddr *) &qs->local_addr,
                     qs->local_addrlen);
    ngtcp2_addr_init(&path.remote, (struct sockaddr *) &qs->peer_addr,
                     qs->peer_addrlen);
    path.user_data = NULL;

    rv = ngtcp2_conn_server_new(&qs->qconn, &hd.scid, &my_scid, &path,
                                hd.version, &quic_ngtcp2_callbacks,
                                &settings, &params, NULL, qs);
    if (rv) {
        xsyslog_ev(LOG_ERR, "quic.conn.create_failed",
                   lf_s("error", ngtcp2_strerror(rv)));
        goto fail;
    }

    ngtcp2_conn_set_tls_native_handle(qs->qconn, ossl_ctx);
    qs->ssl = ssl;
    qs->ossl_ctx = ossl_ctx;
    qs->scid = my_scid;
    qs->ops = app->ops;

    return 0;

fail:
    if (ossl_ctx) ngtcp2_crypto_ossl_ctx_del(ossl_ctx);
    if (ssl) SSL_free(ssl);
    return -1;
}

void quic_flush_output(struct quic_session *qs)
{
    uint8_t out[QUIC_PKT_BUFSIZE];
    ngtcp2_path path;
    ngtcp2_pkt_info pi;
    ngtcp2_tstamp now = quic_now();

    ngtcp2_addr_init(&path.local, (struct sockaddr *) &qs->local_addr,
                     qs->local_addrlen);
    ngtcp2_addr_init(&path.remote, (struct sockaddr *) &qs->peer_addr,
                     qs->peer_addrlen);
    path.user_data = NULL;

    /* Bounded defensively: NGTCP2_ERR_STREAM_DATA_BLOCKED/NOT_FOUND
     * retry in place without making progress on rare races between
     * ngtcp2 and the app's own stream teardown -- don't loop forever
     * within a single flush if that happens, just pick it up on the
     * next cmdloop() iteration. */
    int iterations = 0;
    for (; iterations < 10000; iterations++) {
        int64_t stream_id = -1;
        int fin = 0;
        ngtcp2_vec vec[QUIC_WRITEV_MAX];
        ngtcp2_ssize veccnt = 0;
        ngtcp2_ssize datalen = 0;
        ngtcp2_ssize n;

        if (ngtcp2_conn_get_max_data_left(qs->qconn) > 0) {
            veccnt = qs->ops->get_output(qs, &stream_id, &fin,
                                         vec, QUIC_WRITEV_MAX);
            if (veccnt < 0) {
                qs->draining = true;
                return;
            }
        }

        memset(&pi, 0, sizeof(pi));
        n = ngtcp2_conn_writev_stream(qs->qconn, &path, &pi, out, sizeof(out),
                                      &datalen,
                                      fin ? NGTCP2_WRITE_STREAM_FLAG_FIN
                                          : NGTCP2_WRITE_STREAM_FLAG_NONE,
                                      stream_id, vec,
                                      (size_t) veccnt, now);

        if (n < 0) {
            switch (n) {
            case NGTCP2_ERR_STREAM_DATA_BLOCKED:
            case NGTCP2_ERR_STREAM_SHUT_WR:
                qs->ops->block_output(qs, stream_id);
                continue;
            case NGTCP2_ERR_STREAM_NOT_FOUND:
                continue;
            default:
                xsyslog_ev(LOG_ERR, "quic.conn.writev_failed",
                           lf_s("error", ngtcp2_strerror((int) n)));
                qs->draining = true;
                return;
            }
        }

        if (stream_id >= 0 && datalen >= 0) {
            qs->ops->advance_output(qs, stream_id, (size_t) datalen);
        }

        if (n == 0) break;             /* nothing more to send */

        /* qs->send_fd is unconnected under either backend -- the eBPF
         * backend's per-connection socket deliberately so, to keep a
         * migrating client's traffic from being tied to one source
         * address (see master.c's quic_dispatch_connection()), and the
         * relay backend's is master's own rendezvous socket, shared
         * with every other connection -- so every write needs an
         * explicit destination. */
        if (sendto(qs->send_fd, out, (size_t) n, 0,
                   (struct sockaddr *) &qs->peer_addr, qs->peer_addrlen) < 0) {
            /* client closed connection */
            xsyslog_ev(LOG_DEBUG, "quic.send.failed");
        }
    }
}

void quic_process_datagram(struct quic_session *qs, const uint8_t *pkt,
                           size_t pktlen,
                           const struct sockaddr_storage *from,
                           socklen_t fromlen)
{
    ngtcp2_path path;
    ngtcp2_pkt_info pi;
#if NGTCP2_VERSION_NUM >= 0x011000
    ngtcp2_conn_info info;
    uint64_t pkt_recv;
#endif
    int rv;

    /* |from| is only what this datagram claims -- unauthenticated, and
     * never written to qs->peer_addr (see its comment in quic.h).
     * qs->peer_addr/local_addr stay as the handoff or the last
     * validated path left them, for quic_flush_output() and the
     * CONNECTION_CLOSE below to write to. */
    ngtcp2_addr_init(&path.local, (struct sockaddr *) &qs->local_addr,
                     qs->local_addrlen);
    ngtcp2_addr_init(&path.remote, (struct sockaddr *) from, fromlen);
    path.user_data = NULL;
    memset(&pi, 0, sizeof(pi));

#if NGTCP2_VERSION_NUM >= 0x011000
    ngtcp2_conn_get_conn_info(qs->qconn, &info);
    pkt_recv = info.pkt_recv;
#endif

    rv = ngtcp2_conn_read_pkt(qs->qconn, &path, &pi, pkt, pktlen, quic_now());
    if (rv) {
        switch (rv) {
        case NGTCP2_ERR_DRAINING:
            /* Routine: peer sent CONNECTION_CLOSE (RFC 9000 10.2), e.g.
             * a one-shot client done with its single request --
             * unrelated to our own idle timeout (see
             * quic_handle_expiry()). No reply needed: the peer already
             * discarded its side. */
            xsyslog_ev(LOG_DEBUG, "quic.conn.closed_by_peer");
            qs->draining = true;
            return;
        case NGTCP2_ERR_DROP_CONN:
            /* Routine, per ngtcp2's documented contract: drop silently,
             * no CONNECTION_CLOSE -- e.g. still handshaking and a
             * stateless reset or unsupported version means there's no
             * point continuing. */
            xsyslog_ev(LOG_DEBUG, "quic.conn.dropped",
                       lf_s("error", ngtcp2_strerror(rv)));
            qs->draining = true;
            return;
        default: {
            /* Not routine -- an actual local/protocol error (e.g.
             * NGTCP2_ERR_CRYPTO/PROTO). ngtcp2's contract for every
             * other error code is to send a CONNECTION_CLOSE via
             * ngtcp2_conn_write_connection_close() rather than vanish
             * silently like the two routine cases above. */
            uint8_t buf[QUIC_PKT_BUFSIZE];
            ngtcp2_ccerr ccerr;
            ngtcp2_ssize n;

            xsyslog_ev(LOG_WARNING, "quic.conn.read_failed",
                       lf_s("error", ngtcp2_strerror(rv)));

            ngtcp2_ccerr_set_liberr(&ccerr, rv, NULL, 0);
            n = ngtcp2_conn_write_connection_close(qs->qconn, &path, &pi,
                                                   buf, sizeof(buf),
                                                   &ccerr, quic_now());
            if (n > 0 &&
                sendto(qs->send_fd, buf, (size_t) n, 0,
                      (struct sockaddr *) &qs->peer_addr,
                      qs->peer_addrlen) < 0) {
                /* client closed connection */
                xsyslog_ev(LOG_DEBUG, "quic.send.failed");
            }

            qs->draining = true;
            return;
        }
        }
    }

    /* Only a packet ngtcp2 accepted shows the peer is still there: one
     * with a valid CID and nothing decryptable is cheap to forge */
#if NGTCP2_VERSION_NUM >= 0x011000
    ngtcp2_conn_get_conn_info(qs->qconn, &info);
    if (info.pkt_recv != pkt_recv)
#endif
        qs->last_input = quic_now();

    if (qs->ops->io_ready(qs)) {
        qs->draining = true;
        return;
    }

    quic_flush_output(qs);
}

bool quic_input(struct quic_session *qs, const char **close_reason)
{
    uint8_t pktbuf[QUIC_PKT_BUFSIZE];
    struct sockaddr_storage from;
    socklen_t fromlen = sizeof(from);
    const uint8_t *pkt = pktbuf;
    size_t pktlen;
    struct quic_relay_pkt_hdr hdr;
    const struct sockaddr_storage *claimed_from;
    socklen_t claimed_fromlen;
    ssize_t n;

    /* MSG_DONTWAIT: we get called whenever the caller's input-ready
     * check reports our fd ready, but that can be a false positive
     * (a read-timeout expiring can count as "ready" too). A spurious
     * wakeup with nothing actually queued must not block here: that
     * would starve quic_handle_expiry()/quic_get_timeout(), which only
     * get a chance to run again once this call returns. */
    n = recvfrom(qs->fd, pktbuf, sizeof(pktbuf), MSG_DONTWAIT,
                (struct sockaddr *) &from, &fromlen);
    if (n < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
            /* client closed connection */
            xsyslog_ev(LOG_DEBUG, "quic.recv.failed");
            *close_reason = "recv failed";
            return true;
        }
        return false;
    }
    if (n == 0) {
        /* Under the relay this is EOF: master has dropped the
         * connection, and the fd stays readable forever, so returning
         * "keep going" would spin until the idle timeout. On the eBPF
         * backend the same fd is a real UDP socket, where a
         * zero-length datagram is legal and must not close anything. */
        if (!qs->relayed) return false;
        *close_reason = "dispatch closed the connection";
        return true;
    }
    pktlen = (size_t) n;
    claimed_from = &from;
    claimed_fromlen = fromlen;

    if (qs->relayed) {
        /* Relay backend: qs->fd is an AF_UNIX socketpair to master,
         * not a real network socket, so recvfrom()'s address here is
         * meaningless. master prefixes the datagram with the real one
         * instead -- see struct quic_relay_pkt_hdr (quic_handoff.h)
         * and "Tracking a moving peer address" in quic-dispatch.rst. */
        if (pktlen < sizeof(hdr)) {
            xsyslog_ev(LOG_ERR, "quic.recv.short_relay_header");
            *close_reason = "malformed relay message";
            return true;
        }
        memcpy(&hdr, pkt, sizeof(hdr));
        claimed_from = &hdr.peer;
        claimed_fromlen = hdr.peerlen;
        pkt += sizeof(hdr);
        pktlen -= sizeof(hdr);
    }
    /* eBPF backend: qs->fd is a real, deliberately unconnected UDP
     * socket (see master.c's quic_dispatch_connection()), so
     * recvfrom() already reports each datagram's true source,
     * including a migrating client's new one -- claimed_from/fromlen
     * already default to it above. */

    /* claimed_from is only what this datagram claims; it never reaches
     * qs->peer_addr (see that field's comment in quic.h). */
    quic_process_datagram(qs, pkt, pktlen, claimed_from, claimed_fromlen);

    if (qs->draining) {
        *close_reason = "QUIC connection draining";
        return true;
    }
    return false;
}

unsigned long quic_get_timeout(struct quic_session *qs)
{
    ngtcp2_tstamp now, exp;

    now = quic_now();
    exp = ngtcp2_conn_get_expiry(qs->qconn);
    if (exp <= now) return 1;

    /* Round up, so as never to wake before ngtcp2 wants us to.  Loss
     * detection timers are milliseconds on a fast path, so anything
     * coarser makes every lost packet stall the connection.  Cap at 60s
     * so a long idle timeout doesn't hold off shutdown/signal handling. */
    ngtcp2_tstamp diff = exp - now;
    ngtcp2_tstamp usecs = (diff + NGTCP2_MICROSECONDS - 1) /
                          NGTCP2_MICROSECONDS;
    return usecs < 60 * 1000000 ? (unsigned long) usecs : 60 * 1000000;
}

void quic_traffic(struct quic_session *qs,
                  uint64_t *bytes_in, uint64_t *bytes_out)
{
#if NGTCP2_VERSION_NUM >= 0x011000
    ngtcp2_conn_info info;

    ngtcp2_conn_get_conn_info(qs->qconn, &info);
    *bytes_in = info.bytes_recv;
    *bytes_out = info.bytes_sent;
#else
    (void) qs;
    *bytes_in = *bytes_out = 0;
#endif
}

void quic_close(struct quic_session *qs, uint64_t app_error_code)
{
    uint8_t buf[QUIC_PKT_BUFSIZE];
    ngtcp2_path path;
    ngtcp2_pkt_info pi;
    ngtcp2_ccerr ccerr;
    ngtcp2_ssize n;

    if (qs->draining) return;

    ngtcp2_addr_init(&path.local, (struct sockaddr *) &qs->local_addr,
                     qs->local_addrlen);
    ngtcp2_addr_init(&path.remote, (struct sockaddr *) &qs->peer_addr,
                     qs->peer_addrlen);
    path.user_data = NULL;
    memset(&pi, 0, sizeof(pi));

    ngtcp2_ccerr_set_application_error(&ccerr, app_error_code, NULL, 0);
    n = ngtcp2_conn_write_connection_close(qs->qconn, &path, &pi,
                                           buf, sizeof(buf), &ccerr,
                                           quic_now());
    if (n > 0 &&
        sendto(qs->send_fd, buf, (size_t) n, 0,
               (struct sockaddr *) &qs->peer_addr, qs->peer_addrlen) < 0) {
        /* client closed connection */
        xsyslog_ev(LOG_DEBUG, "quic.send.failed");
    }

    qs->draining = true;
}

void quic_handle_expiry(struct quic_session *qs)
{
    ngtcp2_tstamp now;

    if (qs->draining) return;

    now = quic_now();
    if (ngtcp2_conn_get_expiry(qs->qconn) > now) return;

    if (ngtcp2_conn_handle_expiry(qs->qconn, now)) {
        qs->draining = true;
    }
    else {
        quic_flush_output(qs);
    }
}

void quic_session_free(struct quic_session *qs)
{
    if (qs->ops) qs->ops->session_free(qs);

    if (qs->qconn) ngtcp2_conn_del(qs->qconn);
    if (qs->ossl_ctx) ngtcp2_crypto_ossl_ctx_del(qs->ossl_ctx);
    if (qs->ssl) {
        SSL_set_app_data(qs->ssl, NULL);
        SSL_free(qs->ssl);
    }
}

#endif /* HAVE_NGTCP2 */
