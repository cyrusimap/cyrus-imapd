/* quic.c - QUIC support functions
 *
 * Copyright (c) 1994-2021 Carnegie Mellon University.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The name "Carnegie Mellon University" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For permission or any legal
 *    details, please contact
 *      Carnegie Mellon University
 *      Center for Technology Transfer and Enterprise Creation
 *      4615 Forbes Avenue
 *      Suite 302
 *      Pittsburgh, PA  15213
 *      (412) 268-7393, fax: (412) 268-7395
 *      innovation@andrew.cmu.edu
 *
 * 4. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Computing Services
 *     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 */

#include <errno.h>
#include <sysexits.h>
#include <syslog.h>

#include "quic.h"
#include "xstrlcpy.h"

/* generated headers are not necessarily in current directory */
#include "imap/http_err.h"

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_openssl.h>

#include <openssl/rand.h>

#define RESET_TOKEN_MAGIC  '\r'
#define NEW_TOKEN_MAGIC    '\n'

struct quic_context {
    ngtcp2_conn *qconn;

    int sock;                            /* Output socket */
    ngtcp2_path_storage ps;
    ngtcp2_settings settings;
    ngtcp2_transport_params params;
    uint8_t token[NGTCP2_STATELESS_RESET_TOKENLEN];

    struct buf clienthost;

    SSL_CTX *tls_ctx;
    SSL *tls_conn;
    uint8_t tls_last_alert;

    struct quic_app_context *app_ctx;
};

static int set_encryption_secrets(SSL *ssl, OSSL_ENCRYPTION_LEVEL ossl_level,
                                  const uint8_t *read_secret,
                                  const uint8_t *write_secret,
                                  size_t secret_len)
{
    struct quic_context *ctx = (struct quic_context *) SSL_get_app_data(ssl);
    ngtcp2_crypto_level level =
        ngtcp2_crypto_openssl_from_ossl_encryption_level(ossl_level);

    syslog(LOG_DEBUG, "set_encryption_secrets(%d)", level);

    if (ngtcp2_crypto_derive_and_install_rx_key(ctx->qconn, NULL, NULL, NULL,
                                                level, read_secret,
                                                secret_len)) {
        syslog(LOG_NOTICE, "Error installing rx key");
        return 0;
    }

    if (write_secret) {
        if (ngtcp2_crypto_derive_and_install_tx_key(ctx->qconn, NULL, NULL, NULL,
                                                    level, write_secret,
                                                    secret_len)) {
            syslog(LOG_NOTICE, "Error installing tx key");
            return 0;
        }

        if (level == NGTCP2_CRYPTO_LEVEL_APPLICATION) {
            /* Initialize HTTP/3 connection */
            ctx->app_ctx->open_conn(ctx->app_ctx->conn);
        }
    }

    return 1;
}

static int add_handshake_data(SSL *ssl, OSSL_ENCRYPTION_LEVEL ossl_level,
                              const uint8_t *data, size_t len)
{
    struct quic_context *ctx = (struct quic_context *) SSL_get_app_data(ssl);
    ngtcp2_crypto_level level =
        ngtcp2_crypto_openssl_from_ossl_encryption_level(ossl_level);

    syslog(LOG_DEBUG, "add_handshake_data(%d, %ld)", level, len);

    int r = ngtcp2_conn_submit_crypto_data(ctx->qconn, level, data, len);
    if (r) {
        fatal("Error writing QUIC handshake data", EX_SOFTWARE);
    }

    return 1;
}

static int flush_flight(SSL *ssl __attribute__((unused)))
{
    return 1;
}

static int send_alert(SSL *ssl,
                      enum ssl_encryption_level_t level __attribute__((unused)),
                      uint8_t alert)
{
    struct quic_context *ctx = (struct quic_context *) SSL_get_app_data(ssl);

    ctx->tls_last_alert = alert;

    return 1;
}

static void log_printf(void *user_data __attribute__((unused)),
                       const char *fmt, ...)
{
    struct buf buf = BUF_INITIALIZER;
    va_list args;

    va_start(args, fmt);
    buf_vprintf(&buf, fmt, args);
    va_end(args);

    syslog(LOG_DEBUG, buf_cstring(&buf));

    buf_free(&buf);
}

static const SSL_QUIC_METHOD quic_method = {
    set_encryption_secrets,
    add_handshake_data,
    flush_flight,
    send_alert,
};

HIDDEN int quic_init(struct quic_context **ctx, struct quic_app_context *app)
{
    SSL_CTX *tls_ctx;
    struct sockaddr_storage local_addr;
    socklen_t local_addrlen = sizeof(local_addr);

    *ctx = NULL;

    if (!(app && app->alpn_map[0].id)) return HTTP_UNAVAILABLE;

    /* Setup QUIC TLS context (SSL_CTX already initialized by tls_init() */
    if (tls_init_serverengine("quic", 5, 1, &tls_ctx) == -1) {
        syslog(LOG_ERR, "error initializing QUIC TLS");
        return HTTP_SERVER_ERROR;
    }

    long options = SSL_CTX_get_options(tls_ctx);
    options |= (SSL_OP_SINGLE_ECDH_USE | SSL_OP_NO_ANTI_REPLAY);
    options &= ~(SSL_OP_NO_TLSv1_3 | SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS);

    SSL_CTX_set_options(tls_ctx, options);
    SSL_CTX_set_alpn_select_cb(tls_ctx, tls_alpn_select, (void *) app->alpn_map);

    if (!(SSL_CTX_set_min_proto_version(tls_ctx, TLS1_3_VERSION)
          && SSL_CTX_set_max_proto_version(tls_ctx, TLS1_3_VERSION)
          && SSL_CTX_set_quic_method(tls_ctx, &quic_method))) {
        syslog(LOG_ERR, "error initializing QUIC TLS");
        return HTTP_SERVER_ERROR;
    }

    *ctx = xzmalloc(sizeof(struct quic_context));

    (*ctx)->app_ctx = app;
    (*ctx)->tls_ctx = tls_ctx;
    (*ctx)->sock = atoi(getenv("CYRUS_QUIC_FD"));

    getsockname((*ctx)->sock, (struct sockaddr *) &local_addr, &local_addrlen);

    ngtcp2_path_storage *ps = &(*ctx)->ps;
    ngtcp2_path_storage_zero(ps);
    ngtcp2_addr_copy_byte(&ps->path.local,
                          (struct sockaddr *) &local_addr, local_addrlen);

    ngtcp2_settings *settings = &(*ctx)->settings;
    ngtcp2_settings_default(settings);
    if (config_getswitch(IMAPOPT_DEBUG)) {
        settings->log_printf = &log_printf;
    }

    ngtcp2_transport_params *params = &(*ctx)->params;
    ngtcp2_transport_params_default(params);
    params->initial_max_stream_data_bidi_local = 256 * 1024;
    params->initial_max_stream_data_bidi_remote = 256 * 1024;
    params->initial_max_stream_data_uni = 256 * 1024;
    params->initial_max_data = 256 * 1024;
    params->initial_max_streams_bidi = 100;
    params->initial_max_streams_uni = 3;
    params->max_idle_timeout = app->timeout * NGTCP2_SECONDS;

    return 0;
}

static void set_clienthost(struct quic_context *ctx)
{
    const ngtcp2_path *path = &ctx->ps.path;
    char hbuf[NI_MAXHOST];
    int niflags = NI_NUMERICHOST;

    if (getnameinfo(path->remote.addr, path->remote.addrlen,
                    hbuf, sizeof(hbuf), NULL, 0, NI_NAMEREQD) == 0) {
        buf_printf(&ctx->clienthost, "%s ", hbuf);
    }

#ifdef NI_WITHSCOPEID
    if (remotesock->sa_family == AF_INET6)
        niflags |= NI_WITHSCOPEID;
#endif
    if (getnameinfo(path->remote.addr, path->remote.addrlen,
                    hbuf, sizeof(hbuf), NULL, 0, niflags) != 0) {
        strlcpy(hbuf, "unknown", sizeof(hbuf));
    }
    buf_printf(&ctx->clienthost, "[%s]", hbuf);
}

static int handshake_completed_cb(ngtcp2_conn *conn,
                                  void *user_data __attribute__((unused)))
{
    SSL *ssl = ngtcp2_conn_get_tls_native_handle(conn);
    const char *tls_protocol = SSL_get_version(ssl);
    const SSL_CIPHER *cipher = SSL_get_current_cipher(ssl);
    const char *tls_cipher_name = SSL_CIPHER_get_name(cipher);
    int tls_cipher_algbits = 0;
    int tls_cipher_usebits = SSL_CIPHER_get_bits(cipher, &tls_cipher_algbits);
    const unsigned char *alpn = NULL;
    unsigned int alpn_len = 0;

    SSL_get0_alpn_selected(ssl, &alpn, &alpn_len);

    syslog(LOG_NOTICE,
           "%s with cipher %s (%d/%d bits %s); application protocol = %.*s",
           tls_protocol, tls_cipher_name,
           tls_cipher_usebits, tls_cipher_algbits,
           SSL_session_reused(ssl) ? "reused" : "new",
           alpn_len, (const char *) alpn);

    return 0;
}

static int recv_stream_data_cb(ngtcp2_conn *conn,
                               uint32_t flags, int64_t stream_id, uint64_t offset,
                               const uint8_t *data, size_t datalen,
                               void *user_data,
                               void *stream_user_data __attribute__((unused)))
{
    struct quic_context *ctx = user_data;
    int fin = flags & NGTCP2_STREAM_DATA_FLAG_FIN;

    syslog(LOG_DEBUG, "QUIC recv_stream_data(0x%x, %ld, %lu, %zu)",
           flags, stream_id, offset, datalen);

    ssize_t consumed = ctx->app_ctx->read_stream(ctx->app_ctx->conn,
                                                 stream_id, data, datalen, fin);

    ngtcp2_conn_extend_max_stream_offset(conn, stream_id, consumed);
    ngtcp2_conn_extend_max_offset(conn, consumed);

    return 0;
}

static int stream_open_cb(ngtcp2_conn *conn __attribute__((unused)),
                          int64_t stream_id,
                          void *user_data __attribute__((unused)))
{
    syslog(LOG_DEBUG, "QUIC stream_open(%ld)", stream_id);

    return 0;
}

static int stream_close_cb(ngtcp2_conn *conn __attribute__((unused)),
                           uint32_t flags, int64_t stream_id,
                           uint64_t app_error_code,
                           void *user_data __attribute__((unused)),
                           void *stream_user_data __attribute__((unused)))
{
    syslog(LOG_DEBUG, "QUIC stream_close(%u, %ld, %lu)",
           flags, stream_id, app_error_code);

    return 0;
}

static void rand_cb(uint8_t *dest, size_t destlen,
                    const ngtcp2_rand_ctx *rand_ctx __attribute__((unused)))
{
    int r = RAND_bytes(dest, destlen);

    syslog(LOG_DEBUG, "rand_cb(%zu): %d", destlen, r);
}

static int get_new_connection_id_cb(ngtcp2_conn *conn __attribute__((unused)),
                                    ngtcp2_cid *cid,
                                    uint8_t *token, size_t cidlen,
                                    void *user_data __attribute__((unused)))
{
    int r = RAND_bytes(cid->data, cidlen);

    if (r == 1) {
        cid->datalen = cidlen;

        r = RAND_bytes(token, NGTCP2_STATELESS_RESET_TOKENLEN);
    }

    syslog(LOG_DEBUG, "get_new_connection_id_cb(%zu): %d", cidlen, r);

    return (r == 1 ? 0 : NGTCP2_ERR_CALLBACK_FAILURE);
}

static ngtcp2_tstamp timestamp(void)
{
    struct timeval now;

    gettimeofday(&now, 0);

    return now.tv_sec * NGTCP2_SECONDS + now.tv_usec * NGTCP2_MICROSECONDS;
}

static ngtcp2_callbacks callbacks = {
    NULL, // client_initial
    ngtcp2_crypto_recv_client_initial_cb,
    ngtcp2_crypto_recv_crypto_data_cb,
    handshake_completed_cb,
    NULL, // recv_version_negotiation
    ngtcp2_crypto_encrypt_cb,
    ngtcp2_crypto_decrypt_cb,
    ngtcp2_crypto_hp_mask_cb,
    recv_stream_data_cb,
    NULL, // acked_stream_data_offset
    stream_open_cb,
    stream_close_cb,
    NULL, // recv_stateless_reset
    NULL, // recv_retry
    NULL, // extend_max_local_streams_bidi
    NULL, // extend_max_local_streams_uni
    rand_cb,
    get_new_connection_id_cb,
    NULL, // remove_connection_id
    ngtcp2_crypto_update_key_cb,
    NULL, // path_validation
    NULL, // select_preferred_addr
    NULL, // stream_reset
    NULL, // extend_max_remote_streams_bidi
    NULL, // extend_max_remote_streams_uni
    NULL, // extend_max_stream_data,
    NULL, // dcid_status
    NULL, // handshake_confirmed
    NULL, // recv_new_token
    ngtcp2_crypto_delete_crypto_aead_ctx_cb,
    ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
    NULL, // recv_datagram
    NULL, // ack_datagram
    NULL, // lost_datagram
    NULL, // get_path_challenge_data
    NULL, // stream_stop_sending
};

static void send_data(int sock, ngtcp2_path *path, uint8_t *data, ssize_t nwrite)
{
    ssize_t sent;

    do {
        sent = sendto(sock, data, nwrite, 0,
                      path->remote.addr, path->remote.addrlen);
    } while (sent < 0 && errno == EINTR);

    syslog(LOG_DEBUG, "send_data(): sent %zd of %zd bytes", sent, nwrite);

    if (sent != nwrite) {
    }
}

HIDDEN int quic_input(struct quic_context *ctx, struct protstream *pin)
{
    uint8_t data[USHRT_MAX], msg_count;
    size_t n, datalen, nread = 0;
    int r, i;

    /* Read messages from pipe */
    n = prot_read(pin, (char *) &msg_count, sizeof(msg_count));
    if (n < sizeof(msg_count)) goto ioerror;

    for (i = 0; i < msg_count; i++) {
        struct sockaddr_storage remote_addr;
        socklen_t remote_addrlen;
        uint8_t msg_type;

        n = prot_read(pin, (char *) &msg_type, sizeof(msg_type));
        if (n < sizeof(msg_type)) goto ioerror;

        switch (msg_type) {
        case QUIC_MSG_DATA:
            n = prot_read(pin, (char *) &datalen, sizeof(datalen));
            if (n < sizeof(datalen)) goto ioerror;

            for (; n && nread < datalen; nread += n) {
                n = prot_read(pin, (char *) data + nread, datalen - nread);
            }

            syslog(LOG_DEBUG, "quic_input: read %zd of %zd data bytes",
                   nread, datalen);

            if (nread < datalen) goto ioerror;
            break;

        case QUIC_MSG_ADDR:
            n = prot_read(pin, (char *) &remote_addrlen, sizeof(remote_addrlen));
            if (n < sizeof(remote_addrlen)) goto ioerror;

            n = prot_read(pin, (char *) &remote_addr, remote_addrlen);
            if (n < remote_addrlen) goto ioerror;

            syslog(LOG_DEBUG, "quic_input: read %zd of %u address bytes",
                   n, remote_addrlen);

            ngtcp2_addr_copy_byte(&ctx->ps.path.remote,
                          (struct sockaddr *) &remote_addr, remote_addrlen);

            set_clienthost(ctx);
            break;

        default:
            goto ioerror;
        }
    }

ioerror:
    if (n == 0) {
        if (prot_IS_EOF(pin)) {
            /* Client closed connection */
            syslog(LOG_DEBUG, "client closed connection");
        }
        else if (prot_error(pin)) {
            /* Client timeout or I/O error */
        }

        return EOF;
    }


    if (!ctx->qconn) {
        ngtcp2_cid scid;
        ngtcp2_pkt_hd hd;
        ssize_t nwrite;

        r = ngtcp2_accept(&hd, data, datalen);

        syslog(LOG_DEBUG, "ngtcp2_accept: %s", ngtcp2_strerror(r));

        if (r) {
            switch (r) {
            case NGTCP2_ERR_RETRY:
                /* Retry */
                break;

            case NGTCP2_ERR_VERSION_NEGOTIATION:
                /* Version negotiation */
                break;

            default:
                syslog(LOG_ERR,
                       "QUIC packet not acceptable as initial: %s",
                       ngtcp2_strerror(r));
                return EOF;
            }

            /* send_data() */
            return 0;
        }

        switch (hd.type) {
        case NGTCP2_PKT_INITIAL:
            syslog(LOG_DEBUG,
                   "initial packet; token len = %lu", hd.token.len);

            if (hd.token.len == 0) {
                ngtcp2_cid_init(&ctx->params.original_dcid,
                                hd.dcid.data, hd.dcid.datalen);
#if 0
                ctx->token[0] = RESET_TOKEN_MAGIC;
                r = RAND_bytes(ctx->token+1, sizeof(ctx->token)-1);

                ctx->params.retry_scid.datalen = NGTCP2_MAX_CIDLEN;
                r = RAND_bytes(ctx->params.retry_scid.data, NGTCP2_MAX_CIDLEN);
                ctx->params.retry_scid_present = 1;

                nwrite = ngtcp2_crypto_write_retry(data, sizeof(data),
                                                   hd.version, &hd.scid,
                                                   &ctx->params.retry_scid,
                                                   &hd.dcid,
                                                   ctx->token, sizeof(ctx->token));

                syslog(LOG_DEBUG, "ngtcp2_crypto_write_retry(): %ld", nwrite);

                send_data(ctx->sock, &ctx->ps.path, data, nwrite);

                return 0;
#endif
            }
            else if (hd.token.len != sizeof(ctx->token) ||
                     memcmp(hd.token.base, ctx->token, sizeof(ctx->token))) {
                syslog(LOG_DEBUG, "retry token mismatch");

                nwrite = ngtcp2_crypto_write_connection_close(data, sizeof(data),
                                                              hd.version,
                                                              &hd.scid, &hd.dcid,
                                                              NGTCP2_INVALID_TOKEN);

                syslog(LOG_DEBUG, "ngtcp2_crypto_write_connection_close(): %ld",
                       nwrite);

                send_data(ctx->sock, &ctx->ps.path, data, nwrite);

                return EOF;
            }
            else {
                ctx->settings.token.base = hd.token.base;
                ctx->settings.token.len  = hd.token.len;
            }

            break;

        case NGTCP2_PKT_0RTT:
            syslog(LOG_DEBUG, "0rtt packet");
            break;
        }


        ctx->settings.initial_ts = timestamp();

        scid.datalen = NGTCP2_MAX_CIDLEN;
        r = RAND_bytes(scid.data, scid.datalen);

        r = ngtcp2_conn_server_new(&ctx->qconn, &hd.scid, &scid,
                                   &ctx->ps.path, hd.version, &callbacks,
                                   &ctx->settings, &ctx->params, NULL, ctx);

        syslog(LOG_DEBUG, "ngtcp2_conn_server_new: %s",  ngtcp2_strerror(r));

        if (r) return EOF;

        SSL *tls_conn = ctx->tls_conn = SSL_new(ctx->tls_ctx);
        SSL_set_app_data(tls_conn, ctx);
        SSL_set_accept_state(tls_conn);
        SSL_set_quic_early_data_enabled(tls_conn, 0);

        ngtcp2_conn_set_tls_native_handle(ctx->qconn, tls_conn);
    }

    ngtcp2_pkt_info pi = { NGTCP2_ECN_NOT_ECT };
    r = ngtcp2_conn_read_pkt(ctx->qconn, &ctx->ps.path,
                             &pi, data, datalen, timestamp());

    syslog(LOG_DEBUG, "ngtcp2_conn_read_pkt: %s", ngtcp2_strerror(r));

    return (r ? EOF : 0);
}

HIDDEN int quic_output(struct quic_context *ctx, int64_t stream_id, int fin,
                       const struct iovec *iov, int iovcnt, ssize_t *datalen)
{
    uint8_t data[USHRT_MAX];
    ssize_t nwrite;
    uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_MORE |
        (fin ? NGTCP2_WRITE_STREAM_FLAG_FIN : 0);
    ngtcp2_path_storage ps;

    if (!ctx->qconn) {
        *datalen = -1;
        return 0;
    }

    ngtcp2_path_storage_zero(&ps);

    while ((nwrite = ngtcp2_conn_writev_stream(ctx->qconn, &ps.path, NULL,
                                               data, sizeof(data), datalen,
                                               flags, stream_id,
                                               (ngtcp2_vec *) iov, iovcnt,
                                               timestamp())) > 0) {

        syslog(LOG_DEBUG, "ngtcp2_conn_writev_stream(%ld, %d, %d): %ld, %ld",
               stream_id, iovcnt, fin, nwrite, *datalen);

        send_data(ctx->sock, &ps.path, data, nwrite);
    }

    syslog(LOG_DEBUG, "ngtcp2_conn_writev_stream(%ld, %d, %d): %ld, %ld",
           stream_id, iovcnt, fin, nwrite, *datalen);

    return (nwrite == NGTCP2_ERR_WRITE_MORE);
}

HIDDEN void quic_close(struct quic_context *ctx)
{
    if (ctx->qconn) {
        uint8_t data[USHRT_MAX];
        ssize_t nwrite;
        ngtcp2_path_storage ps;

        ngtcp2_path_storage_zero(&ps);

        nwrite = ngtcp2_conn_write_connection_close(ctx->qconn,
                                                    &ps.path, NULL,
                                                    data, sizeof(data),
                                                    NGTCP2_APPLICATION_ERROR,
                                                    timestamp());

        syslog(LOG_DEBUG, "ngtcp2_conn_write_connection_close(): %zd", nwrite);

        if (nwrite > 0) {
            send_data(ctx->sock, &ps.path, data, nwrite);
        }

        ngtcp2_conn_del(ctx->qconn);
        ctx->qconn = NULL;
    }

    if (ctx->tls_conn) {
        tls_reset_servertls(&ctx->tls_conn);
        ctx->tls_conn = NULL;
    }
}

HIDDEN void quic_shutdown(struct quic_context *ctx)
{
    syslog(LOG_DEBUG, "quic_shutdown()");

    tls_shutdown_serverengine();

    if (ctx->qconn) {
        ngtcp2_conn_del(ctx->qconn);
    }

    free(ctx);
}

HIDDEN int quic_open_stream(void *conn, unsigned bidi,
                            int64_t *stream_id, void *stream_user_data)
{
    struct quic_context *ctx = conn;
    int r;

    if (bidi) {
        r = ngtcp2_conn_open_bidi_stream(ctx->qconn, stream_id, stream_user_data);
    }
    else {
        r = ngtcp2_conn_open_uni_stream(ctx->qconn, stream_id, stream_user_data);
    }

    syslog(LOG_DEBUG, "quic_open_stream(%u): %ld, %s",
           bidi, *stream_id, ngtcp2_strerror(r));

    return r;
}

HIDDEN const char *quic_get_clienthost(void *conn)
{
    struct quic_context *ctx = conn;

    return buf_cstring(&ctx->clienthost);
}

HIDDEN const char *quic_version(void)
{
    return "Ngtcp2/ " NGTCP2_VERSION;
}
