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

ngtcp2_tstamp quic_now(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);

    return (ngtcp2_tstamp) ts.tv_sec * NGTCP2_SECONDS +
           (ngtcp2_tstamp) ts.tv_nsec;
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
    void *user_data __attribute__((unused)))
{
    RAND_bytes(cid->data, (int) cidlen);
    cid->datalen = cidlen;

    if (ngtcp2_crypto_generate_stateless_reset_token(
            token, quic_static_secret, sizeof(quic_static_secret), cid)) {
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    /* No demux table to register this CID in: master's dispatch
     * backend already steers by our original SCID, and the same UDP
     * socket keeps receiving regardless of which CID the client
     * addresses it by. */
    return 0;
}

static int quic_handshake_completed_cb(
    ngtcp2_conn *qconn __attribute__((unused)), void *user_data)
{
    struct quic_session *qs = (struct quic_session *) user_data;

    qs->ops->handshake_completed(qs);
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

static const ngtcp2_callbacks quic_ngtcp2_callbacks = {
    .recv_client_initial      = ngtcp2_crypto_recv_client_initial_cb,
    .recv_crypto_data         = ngtcp2_crypto_recv_crypto_data_cb,
    .handshake_completed      = quic_handshake_completed_cb,
    .encrypt                  = ngtcp2_crypto_encrypt_cb,
    .decrypt                  = ngtcp2_crypto_decrypt_cb,
    .hp_mask                  = ngtcp2_crypto_hp_mask_cb,
    .recv_stream_data         = quic_recv_stream_data_cb,
    .acked_stream_data_offset = quic_acked_stream_data_offset_cb,
    .stream_close             = quic_stream_close_cb,
    .stream_reset             = quic_stream_reset_cb,
    .rand                     = quic_rand_cb,
    .get_new_connection_id    = quic_get_new_connection_id_cb,
    .update_key               = ngtcp2_crypto_update_key_cb,
    .delete_crypto_aead_ctx   = ngtcp2_crypto_delete_crypto_aead_ctx_cb,
    .delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
    .get_path_challenge_data  = ngtcp2_crypto_get_path_challenge_data_cb,
    .version_negotiation      = ngtcp2_crypto_version_negotiation_cb,
};

int quic_session_new(struct quic_session *qs, int fd, SSL_CTX *ssl_ctx,
                     const struct quic_app *app)
{
    uint8_t forced_scid[QUIC_EBPF_CIDLEN];
    ngtcp2_pkt_hd hd;
    ngtcp2_cid my_scid;
    ngtcp2_settings settings;
    ngtcp2_transport_params params;
    ngtcp2_path path;
    SSL *ssl = NULL;
    ngtcp2_crypto_ossl_ctx *ossl_ctx = NULL;
    long idle_timeout;
    int rv;

    if (!quic_static_secret_ready) {
        RAND_bytes(quic_static_secret, sizeof(quic_static_secret));
        quic_static_secret_ready = true;
    }

    qs->fd = fd;

    /* This connection was dispatched by master and handed to us in one
     * QUIC_HANDOFF_FD message (service.c's quic_recv_handoff() filled
     * in quic_handoff before calling us) -- there's no other way this
     * process was started with QUIC in mind, so implausible sizes here
     * mean the master<->worker dispatch contract itself is broken, not
     * a per-connection problem. */
    if (quic_handoff.local_addrlen > sizeof(qs->local_addr) ||
        quic_handoff.peer_addrlen > sizeof(qs->peer_addr) ||
        quic_handoff.pktlen > sizeof(qs->first_pkt)) {
        fatal("quic: implausible QUIC_HANDOFF_FD handoff"
             " (QUIC requires master's dispatch)",
             EX_SOFTWARE);
    }
    memcpy(forced_scid, quic_handoff.scid, QUIC_EBPF_CIDLEN);
    qs->local_addrlen = quic_handoff.local_addrlen;
    memcpy(&qs->local_addr, &quic_handoff.local_addr, qs->local_addrlen);
    qs->peer_addrlen = quic_handoff.peer_addrlen;
    memcpy(&qs->peer_addr, &quic_handoff.peer_addr, qs->peer_addrlen);
    qs->first_pktlen = quic_handoff.pktlen;
    memcpy(qs->first_pkt, quic_handoff.pkt, qs->first_pktlen);

    /* Deliberately not a getsockname(fd, ...) here: that only gives a
     * real local IP:port for the eBPF backend's per-connection UDP
     * socket. Under the relay backend, fd is one end of an AF_UNIX
     * socketpair to master, so getsockname() there returns an
     * anonymous unix address -- a corrupt 2-byte "local" sockaddr that
     * crashes ngtcp2_path_eq() (via ngtcp2_unreachable_fail()).
     * master's own getsockname() on the real rendezvous socket is
     * valid for either backend, so it hands that address over in
     * quic_handoff instead. */

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

    memcpy(my_scid.data, forced_scid, QUIC_EBPF_CIDLEN);
    my_scid.datalen = QUIC_EBPF_CIDLEN;

    ngtcp2_settings_default(&settings);
    settings.initial_ts = quic_now();
    settings.max_tx_udp_payload_size = QUIC_MAX_TX_UDP_PAYLOAD;
    settings.no_pmtud = 1;

    ngtcp2_transport_params_default(&params);
    params.initial_max_stream_data_bidi_local = 256 * 1024;
    params.initial_max_stream_data_bidi_remote = 256 * 1024;
    params.initial_max_stream_data_uni = 256 * 1024;
    params.initial_max_data = 1024 * 1024;
    params.initial_max_streams_bidi = 100;
    params.initial_max_streams_uni = 3;
    params.active_connection_id_limit = 4;
    /* We don't support connection migration: quic_process_datagram()
     * always feeds ngtcp2_conn_read_pkt() the path cached at handshake
     * time (qs->local_addr/peer_addr) rather than each packet's actual
     * arrival path (which quic_input()'s recv(), not recvfrom(),
     * doesn't even learn), and neither dispatch backend's steering
     * registers any CID beyond the original pair a migrating client
     * would have to stop using. Advertising support we can't honor
     * would just invite clients to attempt it and silently fail; this
     * transport parameter tells them not to bother. */
    params.disable_active_migration = 1;
    idle_timeout = config_getduration(IMAPOPT_QUIC_IDLE_TIMEOUT);
    params.max_idle_timeout =
        (ngtcp2_duration) (idle_timeout > 0 ? idle_timeout : 300)
        * NGTCP2_SECONDS;
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

        /* qs->fd is connected (see quic_session_new()) -- master's
         * dispatch gave us a socket already connect()ed to this one
         * client, so a plain send() suffices. */
        if (send(qs->fd, out, (size_t) n, 0) < 0) {
            /* client closed connection */
            xsyslog_ev(LOG_DEBUG, "quic.send.failed");
        }
    }
}

void quic_process_datagram(struct quic_session *qs, const uint8_t *pkt,
                           size_t pktlen)
{
    ngtcp2_path path;
    ngtcp2_pkt_info pi;
    int rv;

    ngtcp2_addr_init(&path.local, (struct sockaddr *) &qs->local_addr,
                     qs->local_addrlen);
    ngtcp2_addr_init(&path.remote, (struct sockaddr *) &qs->peer_addr,
                     qs->peer_addrlen);
    path.user_data = NULL;
    memset(&pi, 0, sizeof(pi));

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
            if (n > 0 && send(qs->fd, buf, (size_t) n, 0) < 0) {
                /* client closed connection */
                xsyslog_ev(LOG_DEBUG, "quic.send.failed");
            }

            qs->draining = true;
            return;
        }
        }
    }

    if (qs->ops->io_ready(qs)) {
        qs->draining = true;
        return;
    }

    quic_flush_output(qs);
}

bool quic_input(struct quic_session *qs, const char **close_reason)
{
    uint8_t pktbuf[QUIC_PKT_BUFSIZE];
    ssize_t n;

    /* MSG_DONTWAIT: we get called whenever the caller's input-ready
     * check reports our fd ready, but that can be a false positive
     * (a read-timeout expiring can count as "ready" too). A spurious
     * wakeup with nothing actually queued must not block here: that
     * would starve quic_handle_expiry()/quic_get_timeout(), which only
     * get a chance to run again once this call returns. */
    n = recv(qs->fd, pktbuf, sizeof(pktbuf), MSG_DONTWAIT);
    if (n < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
            /* client closed connection */
            xsyslog_ev(LOG_DEBUG, "quic.recv.failed");
            *close_reason = "recv failed";
            return true;
        }
        return false;
    }
    if (n == 0) return false;

    quic_process_datagram(qs, pktbuf, (size_t) n);

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

    /* Callers' timeout granularity is whole seconds -- round up so we
     * never wake up *before* ngtcp2 actually wants us to (firing a
     * QUIC timer up to ~1s late just means a slightly slower loss
     * recovery/ACK, not a correctness problem; cap at 60s so a very
     * long idle timeout doesn't stall shutdown/signal handling). */
    ngtcp2_tstamp diff = exp - now;
    unsigned long secs = (unsigned long) (diff / NGTCP2_SECONDS) + 1;
    return secs < 60 ? secs : 60;
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
