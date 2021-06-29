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

#include "httpd.h"
#include "quic.h"

/* generated headers are not necessarily in current directory */
#include "imap/http_err.h"

#ifdef HAVE_QUIC

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_openssl.h>

#include <openssl/rand.h>

struct quic_context {
    ngtcp2_conn *qconn;

    int sock;                            /* Output socket */
    struct sockaddr_storage local_addr;
    socklen_t local_addrlen;
    SSL_CTX *tls_ctx;

    SSL *tls;

    struct buf crypto_data[3];
    uint8_t last_tls_alert;

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

#define MAX_CRYPTO_DATA  32768  // XXX  Can we assume <= 32KB ?

static int add_handshake_data(SSL *ssl, OSSL_ENCRYPTION_LEVEL ossl_level,
                              const uint8_t *data, size_t len)
{
    struct quic_context *ctx = (struct quic_context *) SSL_get_app_data(ssl);
    ngtcp2_crypto_level level =
        ngtcp2_crypto_openssl_from_ossl_encryption_level(ossl_level);
    struct buf *crypto_data = &ctx->crypto_data[level];
    size_t cur_pos = buf_len(crypto_data);

    syslog(LOG_DEBUG, "add_handshake_data(%d, %ld)", level, len);

    if (!buf_base(crypto_data)) {
        buf_ensure(crypto_data, MAX_CRYPTO_DATA);
    }

    assert(buf_len(crypto_data) + len <= MAX_CRYPTO_DATA);

    buf_appendmap(crypto_data, (const char *) data, len);
    data = (const uint8_t *) buf_base(crypto_data) + cur_pos;

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

    ctx->last_tls_alert = alert;

    return 1;
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
    (*ctx)->local_addrlen =  sizeof(struct sockaddr_storage);
    getsockname((*ctx)->sock,
                (struct sockaddr *) &(*ctx)->local_addr, &(*ctx)->local_addrlen);

    return 0;
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
           "QUIC: %s with cipher %s (%d/%d bits %s); application protocol = %.*s",
           tls_protocol, tls_cipher_name,
           tls_cipher_usebits, tls_cipher_algbits,
           SSL_session_reused(ssl) ? "reused" : "new",
           alpn_len, (const char *) alpn);

    return 0;
}

static int acked_crypto_offset_cb(ngtcp2_conn *conn __attribute__((unused)),
                                  ngtcp2_crypto_level level,
                                  uint64_t offset, uint64_t datalen,
                                  void *user_data __attribute__((unused)))
{
    struct quic_context *ctx = (struct quic_context *) user_data;

    syslog(LOG_DEBUG, "acked_crypto_offset(%d, %lu, %lu, %lu)",
           level, offset, datalen, buf_len(&ctx->crypto_data[level]));
#if 0
    if (offset + datalen >= buf_len(&ctx->crypto_data[level])) {
        buf_free(&ctx->crypto_data[level]);
    }
#endif
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

    syslog(LOG_DEBUG, "recv_stream_data(0x%x, %ld, %lu, %zu)",
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
    syslog(LOG_DEBUG, "stream_open(%lu)", stream_id);

    return 0;
}

static int rand_cb(uint8_t *dest, size_t destlen,
                   const ngtcp2_rand_ctx *rand_ctx __attribute__((unused)),
                   ngtcp2_rand_usage usage __attribute__((unused)))
{
    int r = RAND_bytes(dest, destlen);

    syslog(LOG_DEBUG, "rand_cb(%zu): %d", destlen, r);

    return (r == 1 ? 0 : NGTCP2_ERR_CALLBACK_FAILURE);
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
    acked_crypto_offset_cb,
    NULL, // acked_stream_data_offset
    stream_open_cb,
    NULL, // stream_close
    NULL, // recv_stateless_reset
    NULL, // recv_retry
    NULL, // extend_max_streams_bidi
    NULL, // extend_max_streams_uni
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
};

HIDDEN int quic_input(struct quic_context *ctx, struct protstream *pin)
{
    struct sockaddr_storage remote_addr;
    socklen_t remote_addrlen;
    uint8_t data[USHRT_MAX];
    ssize_t datalen, nread = 0;
    int n, r;

    prot_read(pin, (char *) &remote_addrlen, sizeof(remote_addrlen));
    prot_read(pin, (char *) &remote_addr, remote_addrlen);
    prot_read(pin, (char *) &datalen, sizeof(datalen));
    for (; datalen; datalen -= n, nread += n) {
        n = prot_read(pin, (char *) data + nread, datalen);
    }

    syslog(LOG_DEBUG, "quic_input: read %zd of %zd bytes", nread, datalen);

    if (nread == 0) {
        if (prot_IS_EOF(pin)) {
            /* Client closed connection */
            syslog(LOG_DEBUG, "client closed connection");
        }
        else if (prot_error(pin)) {
            /* Client timeout or I/O error */
        }

        return 1;
    }

    ngtcp2_path path = {
        { ctx->local_addrlen, (struct sockaddr *) &ctx->local_addr },
        { remote_addrlen, (struct sockaddr *) &remote_addr },
        NULL
    };

    uint32_t version = 0;
    const uint8_t *dcid, *scid;
    size_t dcidlen = 0, scidlen = 0;
    r = ngtcp2_pkt_decode_version_cid(&version, &dcid, &dcidlen,
                                      &scid, &scidlen, data,
                                      nread, NGTCP2_MAX_CIDLEN);

    syslog(LOG_DEBUG, "ngtcp2_pkt_decode_version_cid: %s (0x%x %ld %ld)",
           ngtcp2_strerror(r), version, dcidlen, scidlen);

    if (r == 1) {
        /* Version negotiation */
    }
    else if (r) {
        syslog(LOG_ERR,
               "Error decoding version and CID from QUIC packet header: %s",
               ngtcp2_strerror(r));
        return 0;
    }

    if (!ctx->qconn) {
        ngtcp2_cid scid;
        ngtcp2_pkt_hd hd;

        r = ngtcp2_accept(&hd, data, nread);

        syslog(LOG_DEBUG, "ngtcp2_accept: %s", ngtcp2_strerror(r));

        if (r == 1) {
            /* Version negotiation */
        }
        else if (r) {
            syslog(LOG_ERR,
                   "QUIC packet not acceptable as initial: %s",
                   ngtcp2_strerror(r));
            return 0;
        }

        switch (hd.type) {
        case NGTCP2_PKT_INITIAL:
            syslog(LOG_DEBUG,
                   "initial packet; token len = %lu", hd.token.len);
#if 0
            if (hd.token.len == 0) {
                uint8_t token[NGTCP2_STATELESS_RESET_TOKENLEN];

                r = get_new_connection_id_cb(NULL, &scid, token,
                                             NGTCP2_MAX_CIDLEN, NULL);

                nwrite = ngtcp2_crypto_write_retry(data, sizeof(data),
                                                   hd.version,
                                                   &hd.scid, &scid, &hd.dcid,
                                                   hd.dcid.data, hd.dcid.datalen);
//                                                       token, sizeof(token));

                do {
                    sent = sendto(ctx->sock, data, nwrite, 0,
                                  (struct sockaddr *) &remote_addr,
                                  remote_addrlen);
                } while (sent < 0 && errno == EINTR);

                syslog(LOG_DEBUG,
                       "write retry: sent %zd of %zd bytes\n", sent, nwrite);

                if (sent != nwrite) {
                }

                return 0;
            }
#endif
            break;

        case NGTCP2_PKT_0RTT:
            syslog(LOG_DEBUG, "0rtt packet");
            break;
        }

        ngtcp2_settings settings;
        ngtcp2_settings_default(&settings);
        settings.initial_ts = timestamp();
        if (config_getswitch(IMAPOPT_DEBUG)) {
            settings.log_printf = &log_printf;
        }
        if (hd.token.len) {
            settings.token.base = hd.token.base;
            settings.token.len  = hd.token.len;
        }

        ngtcp2_transport_params params;
        ngtcp2_transport_params_default(&params);
        memcpy(&params.original_dcid, &hd.dcid, sizeof(ngtcp2_cid));
        params.initial_max_stream_data_bidi_local = 256 * 1024;
        params.initial_max_stream_data_bidi_remote = 256 * 1024;
        params.initial_max_stream_data_uni = 256 * 1024;
        params.initial_max_data = 256 * 1024;
        params.initial_max_streams_bidi = 100;
        params.initial_max_streams_uni = 3;
        params.max_idle_timeout = httpd_timeout;

        scid.datalen = NGTCP2_MAX_CIDLEN;
        r = RAND_bytes(scid.data, scid.datalen);

        r = ngtcp2_conn_server_new(&ctx->qconn, &hd.scid, &scid, &path, version,
                                   &callbacks, &settings, &params, NULL, ctx);

        syslog(LOG_DEBUG, "ngtcp2_conn_server_new: %s",  ngtcp2_strerror(r));

        SSL *tls = ctx->tls = SSL_new(ctx->tls_ctx);
        SSL_set_app_data(tls, ctx);
        SSL_set_accept_state(tls);
        SSL_set_quic_early_data_enabled(tls, 0);

        ngtcp2_conn_set_tls_native_handle(ctx->qconn, tls);
    }

    ngtcp2_pkt_info pi = { NGTCP2_ECN_NOT_ECT };
    r = ngtcp2_conn_read_pkt(ctx->qconn, &path, &pi, data, nread, timestamp());

    syslog(LOG_DEBUG, "ngtcp2_conn_read_pkt: %s", ngtcp2_strerror(r));

    return 0;
}

HIDDEN ssize_t quic_output(struct quic_context *ctx, int64_t stream_id, int fin,
                           const struct iovec *iov, int iovcnt, ssize_t *datalen)
{
    uint8_t data[USHRT_MAX];
    ssize_t nwrite, sent;
    uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_MORE |
        (fin ? NGTCP2_WRITE_STREAM_FLAG_FIN : 0);
    ngtcp2_path_storage ps;

    syslog(LOG_DEBUG, "write stream (%ld, %d, %d)", stream_id, iovcnt, fin);

    ngtcp2_path_storage_zero(&ps);

    while ((nwrite = ngtcp2_conn_writev_stream(ctx->qconn, &ps.path, NULL,
                                               data, sizeof(data), datalen,
                                               flags, stream_id,
                                               (ngtcp2_vec *) iov, iovcnt,
                                               timestamp())) > 0) {
        do {
            sent = sendto(ctx->sock, data, nwrite, 0,
                          ps.path.remote.addr, ps.path.remote.addrlen);
        } while (sent < 0 && errno == EINTR);

        syslog(LOG_DEBUG, "write stream (%ld, %ld): sent %zd of %zd bytes\n",
               stream_id, *datalen, sent, nwrite);

        if (sent != nwrite) {
        }
    }

    syslog(LOG_DEBUG, "write stream (%ld, %ld)", stream_id, nwrite);

    return nwrite;
}

HIDDEN void quic_close(struct quic_context *ctx)
{
    syslog(LOG_DEBUG, "quic_close()");

    if (ctx->tls) {
        tls_reset_servertls(&ctx->tls);
        ctx->tls = NULL;
    }

    if (ctx->qconn) {
        ngtcp2_conn_del(ctx->qconn);
        ctx->qconn = NULL;
    }

    int i;
    for (i = 0; i < 3; i++) {
        buf_reset(&ctx->crypto_data[i]);
    }
}

HIDDEN void quic_shutdown(struct quic_context *ctx)
{
    syslog(LOG_DEBUG, "quic_shutdown()");

    tls_shutdown_serverengine();

    if (ctx->qconn) {
        ngtcp2_conn_del(ctx->qconn);
    }

    int i;
    for (i = 0; i < 3; i++) {
        buf_free(&ctx->crypto_data[i]);
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

HIDDEN const char *quic_version(void)
{
    return "Ngtcp2/ " NGTCP2_VERSION;
}

#else /* !HAVE_QUIC */

HIDDEN int quic_init(struct quic_context **ctx __attribute__((unused)),
                     struct quic_app_context *app __attribute__((unused)))
{
    return HTTP_NOT_IMPLEMENTED;
}

HIDDEN int quic_input(struct quic_context *ctx __attribute__((unused)),
                      struct protstream *pin  __attribute__((unused)))
{
    fatal("quic_input() called, but no Ngtcp2", EX_SOFTWARE);
}

HIDDEN void quic_close(struct quic_context *ctx __attribute__((unused)))
{
    fatal("quic_close() called, but no Ngtcp2", EX_SOFTWARE);
}


HIDDEN void quic_shutdown(struct quic_context *ctx __attribute__((unused)))
{
    fatal("quic_shutdown() called, but no Ngtcp2", EX_SOFTWARE);
}

#endif /* HAVE_QUIC */
