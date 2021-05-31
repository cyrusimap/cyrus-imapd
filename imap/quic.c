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

#include <sysexits.h>
#include <syslog.h>

#include "httpd.h"
#include "quic.h"

/* generated headers are not necessarily in current directory */
#include "imap/http_err.h"

#if defined(HAVE_NGTCP2) && defined(HAVE_QUIC_TLS) && defined(HAVE_TLS_ALPN)

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_openssl.h>

struct quic_context {
    ngtcp2_conn *conn;
    struct buf crypto_data[3];
    uint8_t last_tls_alert;
};

static int set_encryption_secrets(SSL *ssl, OSSL_ENCRYPTION_LEVEL ossl_level,
                                  const uint8_t *read_secret,
                                  const uint8_t *write_secret,
                                  size_t secret_len)
{
    struct quic_context *ctx = (struct quic_context *) SSL_get_app_data(ssl);
    ngtcp2_crypto_level level =
        ngtcp2_crypto_openssl_from_ossl_encryption_level(ossl_level);

    if (ngtcp2_crypto_derive_and_install_rx_key(ctx->conn, NULL, NULL, NULL,
                                                level, read_secret,
                                                secret_len)) {
        return 0;
    }

    if (write_secret) {
        if (ngtcp2_crypto_derive_and_install_tx_key(ctx->conn, NULL, NULL, NULL,
                                                    level, write_secret,
                                                    secret_len)) {
            return 0;
        }

        if (level == NGTCP2_CRYPTO_LEVEL_APPLICATION) {
            /* Initialize HTTP/3 connection */
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
    struct buf *crypto_data = &ctx->crypto_data[level];
    size_t cur_pos = buf_len(crypto_data);

    buf_appendmap(crypto_data, (const char *) data, len);
    data = (const uint8_t *) buf_base(crypto_data) + cur_pos;

    int r = ngtcp2_conn_submit_crypto_data(ctx->conn, level, data, len);
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

HIDDEN int quic_init(const struct tls_alpn_t alpn_map[],
                     struct buf *serverinfo)
{
    buf_printf(serverinfo, " Ngtcp2/%s", NGTCP2_VERSION);

    if (!(alpn_map && alpn_map[0].id)) return HTTP_UNAVAILABLE;

    /* Setup QUIC TLS context (SSL_CTX already initialized by tls_init() */
    SSL_CTX *ctx = NULL;
    if (tls_init_serverengine("quic", 5, 1, &ctx) == -1) {
        syslog(LOG_ERR, "error initializing QUIC TLS");
        return HTTP_SERVER_ERROR;
    }

    long options = SSL_CTX_get_options(ctx);
    options |= (SSL_OP_SINGLE_ECDH_USE | SSL_OP_NO_ANTI_REPLAY);
    options &= ~(SSL_OP_NO_TLSv1_3 | SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS);

    SSL_CTX_set_options(ctx, options);
    SSL_CTX_set_alpn_select_cb(ctx, tls_alpn_select, (void *) alpn_map);

    if (!(SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION)
          && SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION)
          && SSL_CTX_set_quic_method(ctx, &quic_method))) {
        syslog(LOG_ERR, "error initializing QUIC TLS");
        return HTTP_SERVER_ERROR;
    }

    return 0;
}

HIDDEN void quic_input(struct http_connection *conn)
{
    struct sockaddr_storage sfrom_storage;
    struct sockaddr *sfrom = (struct sockaddr *) &sfrom_storage;
    socklen_t sfromsiz = sizeof(struct sockaddr_storage);
    char buf[4096];
    ssize_t n;

    /* Simple echo server to get us started */
    n = recvfrom(conn->pin->fd, buf, sizeof(buf), 0, sfrom, &sfromsiz);
    if (n < 0) return;

    n = sendto(conn->pout->fd, buf, n, 0, sfrom, sfromsiz);

    return;
}

#else /* !HAVE_NGTCP2 */

HIDDEN int quic_init(const struct tls_alpn_t alpn_map[] __attribute__((unused)),
                     struct buf *serverinfo __attribute__((unused)))
{
    return HTTP_NOT_IMPLEMENTED;
}

HIDDEN void quic_input(struct http_connection *conn __attribute__((unused)))
{
    fatal("quic_input() called, but no Ngtcp2", EX_SOFTWARE);
}

#endif /* HAVE_NGTCP2 */
