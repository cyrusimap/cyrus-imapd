/* h3migrate.c - an HTTP/3 client that migrates its connection between
 * requests, for testing a server's QUIC connection migration */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

/*
 * h3migrate [-n migrations] [-t timeout] [-u user:pass] host port path
 *
 * GETs path, then for each migration moves the connection to a fresh
 * local UDP port (RFC 9000 9) and GETs it again.  The old socket is
 * closed first, so every response after a migration reached the new
 * port.  Prints one line per event:
 *
 *   response <n> <status> <body length> <local port>
 *   migrated <n> <local port>
 *   closed <reason>     the server closed the connection
 *   timeout <n>         no response to request <n> within the timeout
 *   stalled <n>         no spare connection ID to make migration <n>
 *                       with, within the timeout
 *
 * Exits 0 once every request has a response, 3 if the connection ended
 * or stalled first, and 1 on a local failure.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <getopt.h>
#include <netdb.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#include <nghttp3/nghttp3.h>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_ossl.h>

#define PKT_BUFSIZE  65536
#define CIDLEN       18
#define WRITEV_MAX   16

struct client {
    ngtcp2_conn *conn;
    nghttp3_conn *h3;
    SSL *ssl;
    ngtcp2_crypto_ossl_ctx *ossl_ctx;
    ngtcp2_crypto_conn_ref conn_ref;

    int sock;
    struct sockaddr_storage local, remote;
    socklen_t locallen, remotelen;

    bool handshake_done;
    const char *closed;         /* why the connection ended, if it has */

    /* the request in progress */
    int64_t stream_id;
    int status;
    size_t bodylen;
    bool done;
};

static ngtcp2_tstamp now(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (ngtcp2_tstamp) ts.tv_sec * NGTCP2_SECONDS +
           (ngtcp2_tstamp) ts.tv_nsec;
}

static void fail(const char *what, const char *why)
{
    fprintf(stderr, "h3migrate: %s: %s\n", what, why);
    exit(1);
}

static int local_port(const struct sockaddr_storage *ss)
{
    return ntohs(ss->ss_family == AF_INET6
                 ? ((const struct sockaddr_in6 *) ss)->sin6_port
                 : ((const struct sockaddr_in *) ss)->sin_port);
}

/* A UDP socket on a fresh ephemeral port, connected to the server, and
 * its local address */
static int new_socket(const struct client *cl,
                      struct sockaddr_storage *local, socklen_t *locallen)
{
    struct sockaddr_storage any = { .ss_family = cl->remote.ss_family };
    int sock = socket(cl->remote.ss_family, SOCK_DGRAM, 0);

    if (sock < 0) fail("socket", strerror(errno));
    if (bind(sock, (struct sockaddr *) &any, cl->remotelen) ||
        connect(sock, (struct sockaddr *) &cl->remote, cl->remotelen)) {
        fail("bind/connect", strerror(errno));
    }

    *locallen = sizeof(*local);
    if (getsockname(sock, (struct sockaddr *) local, locallen)) {
        fail("getsockname", strerror(errno));
    }
    return sock;
}

static void get_path(struct client *cl, ngtcp2_path *path)
{
    ngtcp2_addr_init(&path->local, (struct sockaddr *) &cl->local,
                     cl->locallen);
    ngtcp2_addr_init(&path->remote, (struct sockaddr *) &cl->remote,
                     cl->remotelen);
    path->user_data = NULL;
}

/*
 * nghttp3 callbacks
 */

static void extend_credit(struct client *cl, int64_t stream_id, size_t n)
{
    ngtcp2_conn_extend_max_stream_offset(cl->conn, stream_id, n);
    ngtcp2_conn_extend_max_offset(cl->conn, n);
}

static int h3_recv_header(nghttp3_conn *h3 __attribute__((unused)),
                          int64_t stream_id, int32_t token,
                          nghttp3_rcbuf *name __attribute__((unused)),
                          nghttp3_rcbuf *value, uint8_t flags
                          __attribute__((unused)),
                          void *user_data, void *stream_user_data
                          __attribute__((unused)))
{
    struct client *cl = user_data;

    if (stream_id == cl->stream_id && token == NGHTTP3_QPACK_TOKEN__STATUS) {
        nghttp3_vec v = nghttp3_rcbuf_get_buf(value);

        cl->status = atoi(strndupa((const char *) v.base, v.len));
    }
    return 0;
}

static int h3_recv_data(nghttp3_conn *h3 __attribute__((unused)),
                        int64_t stream_id, const uint8_t *data
                        __attribute__((unused)),
                        size_t datalen, void *user_data,
                        void *stream_user_data __attribute__((unused)))
{
    struct client *cl = user_data;

    if (stream_id == cl->stream_id) cl->bodylen += datalen;
    extend_credit(cl, stream_id, datalen);
    return 0;
}

static int h3_deferred_consume(nghttp3_conn *h3 __attribute__((unused)),
                               int64_t stream_id, size_t consumed,
                               void *user_data,
                               void *stream_user_data __attribute__((unused)))
{
    extend_credit(user_data, stream_id, consumed);
    return 0;
}

static int h3_end_stream(nghttp3_conn *h3 __attribute__((unused)),
                         int64_t stream_id, void *user_data,
                         void *stream_user_data __attribute__((unused)))
{
    struct client *cl = user_data;

    if (stream_id == cl->stream_id) cl->done = true;
    return 0;
}

static const nghttp3_callbacks h3_callbacks = {
    .recv_header     = h3_recv_header,
    .recv_data       = h3_recv_data,
    .deferred_consume = h3_deferred_consume,
    .end_stream      = h3_end_stream,
};

/*
 * ngtcp2 callbacks
 */

static ngtcp2_conn *get_conn(ngtcp2_crypto_conn_ref *ref)
{
    return ((struct client *) ref->user_data)->conn;
}

static void rand_cb(uint8_t *dest, size_t destlen,
                    const ngtcp2_rand_ctx *rand_ctx __attribute__((unused)))
{
    RAND_bytes(dest, (int) destlen);
}

static int get_new_connection_id(ngtcp2_conn *conn __attribute__((unused)),
                                 ngtcp2_cid *cid, uint8_t *token,
                                 size_t cidlen,
                                 void *user_data __attribute__((unused)))
{
    RAND_bytes(cid->data, (int) cidlen);
    cid->datalen = cidlen;
    RAND_bytes(token, NGTCP2_STATELESS_RESET_TOKENLEN);
    return 0;
}

static int handshake_completed(ngtcp2_conn *conn __attribute__((unused)),
                               void *user_data)
{
    ((struct client *) user_data)->handshake_done = true;
    return 0;
}

static int recv_stream_data(ngtcp2_conn *conn, uint32_t flags,
                            int64_t stream_id,
                            uint64_t offset __attribute__((unused)),
                            const uint8_t *data, size_t datalen,
                            void *user_data,
                            void *stream_user_data __attribute__((unused)))
{
    struct client *cl = user_data;
    nghttp3_ssize n;

    n = nghttp3_conn_read_stream2(cl->h3, stream_id, data, datalen,
                                  flags & NGTCP2_STREAM_DATA_FLAG_FIN, now());
    if (n < 0) return NGTCP2_ERR_CALLBACK_FAILURE;

    ngtcp2_conn_extend_max_stream_offset(conn, stream_id, (uint64_t) n);
    ngtcp2_conn_extend_max_offset(conn, (uint64_t) n);
    return 0;
}

static int acked_stream_data_offset(ngtcp2_conn *conn __attribute__((unused)),
                                    int64_t stream_id,
                                    uint64_t offset __attribute__((unused)),
                                    uint64_t datalen, void *user_data,
                                    void *stream_user_data
                                    __attribute__((unused)))
{
    struct client *cl = user_data;

    return nghttp3_conn_add_ack_offset(cl->h3, stream_id, datalen)
           ? NGTCP2_ERR_CALLBACK_FAILURE : 0;
}

static int stream_close(ngtcp2_conn *conn __attribute__((unused)),
                        uint32_t flags, int64_t stream_id,
                        uint64_t app_error_code, void *user_data,
                        void *stream_user_data __attribute__((unused)))
{
    struct client *cl = user_data;

    if (!(flags & NGTCP2_STREAM_CLOSE_FLAG_APP_ERROR_CODE_SET)) {
        app_error_code = NGHTTP3_H3_NO_ERROR;
    }
    switch (nghttp3_conn_close_stream(cl->h3, stream_id, app_error_code)) {
    case 0:
    case NGHTTP3_ERR_STREAM_NOT_FOUND:
        return 0;
    default:
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }
}

static int stream_reset(ngtcp2_conn *conn __attribute__((unused)),
                        int64_t stream_id,
                        uint64_t final_size __attribute__((unused)),
                        uint64_t app_error_code __attribute__((unused)),
                        void *user_data,
                        void *stream_user_data __attribute__((unused)))
{
    struct client *cl = user_data;

    return nghttp3_conn_shutdown_stream_read(cl->h3, stream_id)
           ? NGTCP2_ERR_CALLBACK_FAILURE : 0;
}

static int extend_max_stream_data(ngtcp2_conn *conn __attribute__((unused)),
                                  int64_t stream_id,
                                  uint64_t max_data __attribute__((unused)),
                                  void *user_data,
                                  void *stream_user_data
                                  __attribute__((unused)))
{
    struct client *cl = user_data;

    return nghttp3_conn_unblock_stream(cl->h3, stream_id)
           ? NGTCP2_ERR_CALLBACK_FAILURE : 0;
}

static const ngtcp2_callbacks callbacks = {
    .client_initial           = ngtcp2_crypto_client_initial_cb,
    .recv_crypto_data         = ngtcp2_crypto_recv_crypto_data_cb,
    .handshake_completed      = handshake_completed,
    .encrypt                  = ngtcp2_crypto_encrypt_cb,
    .decrypt                  = ngtcp2_crypto_decrypt_cb,
    .hp_mask                  = ngtcp2_crypto_hp_mask_cb,
    .recv_stream_data         = recv_stream_data,
    .acked_stream_data_offset = acked_stream_data_offset,
    .stream_close             = stream_close,
    .stream_reset             = stream_reset,
    .recv_retry               = ngtcp2_crypto_recv_retry_cb,
    .extend_max_stream_data   = extend_max_stream_data,
    .rand                     = rand_cb,
    .get_new_connection_id    = get_new_connection_id,
    .update_key               = ngtcp2_crypto_update_key_cb,
    .delete_crypto_aead_ctx   = ngtcp2_crypto_delete_crypto_aead_ctx_cb,
    .delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
    .get_path_challenge_data  = ngtcp2_crypto_get_path_challenge_data_cb,
    .version_negotiation      = ngtcp2_crypto_version_negotiation_cb,
};

/*
 * Moving packets
 */

static void flush(struct client *cl)
{
    uint8_t out[PKT_BUFSIZE];
    ngtcp2_path path;

    if (cl->closed) return;
    get_path(cl, &path);

    for (int i = 0; i < 10000; i++) {
        int64_t stream_id = -1;
        int fin = 0;
        nghttp3_vec vec[WRITEV_MAX];
        nghttp3_ssize veccnt = 0;
        ngtcp2_ssize datalen = -1;
        ngtcp2_pkt_info pi = { 0 };
        ngtcp2_ssize n;

        if (cl->h3 && ngtcp2_conn_get_max_data_left(cl->conn)) {
            veccnt = nghttp3_conn_writev_stream(cl->h3, &stream_id, &fin,
                                                vec, WRITEV_MAX);
            if (veccnt < 0) fail("nghttp3_conn_writev_stream",
                                 nghttp3_strerror((int) veccnt));
        }

        n = ngtcp2_conn_writev_stream(cl->conn, &path, &pi, out, sizeof(out),
                                      &datalen,
                                      fin ? NGTCP2_WRITE_STREAM_FLAG_FIN
                                          : NGTCP2_WRITE_STREAM_FLAG_NONE,
                                      stream_id, (const ngtcp2_vec *) vec,
                                      (size_t) veccnt, now());
        if (n < 0) {
            if (n == NGTCP2_ERR_STREAM_DATA_BLOCKED ||
                n == NGTCP2_ERR_STREAM_SHUT_WR) {
                nghttp3_conn_block_stream(cl->h3, stream_id);
                continue;
            }
            cl->closed = ngtcp2_strerror((int) n);
            return;
        }
        if (stream_id >= 0 && datalen >= 0) {
            nghttp3_conn_add_write_offset(cl->h3, stream_id, (size_t) datalen);
        }
        if (n == 0) return;

        send(cl->sock, out, (size_t) n, 0);
    }
}

static void input(struct client *cl)
{
    uint8_t buf[PKT_BUFSIZE];
    ngtcp2_path path;
    ssize_t n;

    get_path(cl, &path);

    while (!cl->closed &&
           (n = recv(cl->sock, buf, sizeof(buf), MSG_DONTWAIT)) > 0) {
        ngtcp2_pkt_info pi = { 0 };
        int rv = ngtcp2_conn_read_pkt(cl->conn, &path, &pi, buf, (size_t) n,
                                      now());

        if (rv == NGTCP2_ERR_DRAINING) cl->closed = "CONNECTION_CLOSE";
        else if (rv) cl->closed = ngtcp2_strerror(rv);
    }
}

/* Run the connection until *flag is set, it ends, or |secs| pass.
 * Returns whether *flag got set. */
static bool run_until(struct client *cl, const bool *flag, int secs)
{
    ngtcp2_tstamp deadline = now() + (ngtcp2_tstamp) secs * NGTCP2_SECONDS;

    while (!*flag && !cl->closed && now() < deadline) {
        struct pollfd pfd = { .fd = cl->sock, .events = POLLIN };
        ngtcp2_tstamp expiry = ngtcp2_conn_get_expiry(cl->conn);
        ngtcp2_tstamp t = now();
        ngtcp2_tstamp wait =
            expiry > t ? (expiry - t) / NGTCP2_MILLISECONDS : 0;

        flush(cl);
        poll(&pfd, 1, wait < 100 ? (int) wait : 100);
        if (pfd.revents & POLLIN) input(cl);

        if (!cl->closed && ngtcp2_conn_get_expiry(cl->conn) <= now() &&
            ngtcp2_conn_handle_expiry(cl->conn, now())) {
            cl->closed = "idle timeout";
        }
    }
    flush(cl);
    return *flag;
}

/* Open our HTTP/3 control streams, once the handshake has brought the
 * server's transport parameters */
static void open_ctrl_streams(struct client *cl)
{
    int64_t ctrl, qenc, qdec;

    if (ngtcp2_conn_open_uni_stream(cl->conn, &ctrl, NULL) ||
        ngtcp2_conn_open_uni_stream(cl->conn, &qenc, NULL) ||
        ngtcp2_conn_open_uni_stream(cl->conn, &qdec, NULL)) {
        fail("ngtcp2_conn_open_uni_stream", "no stream credit");
    }
    nghttp3_conn_bind_control_stream(cl->h3, ctrl);
    nghttp3_conn_bind_qpack_streams(cl->h3, qenc, qdec);
}

#define NV(n, v) { (uint8_t *) (n), (uint8_t *) (v), \
                   sizeof(n) - 1, strlen(v), NGHTTP3_NV_FLAG_NONE }

static bool request(struct client *cl, const char *authority,
                    const char *path, const char *auth, int secs)
{
    nghttp3_nv nva[] = {
        NV(":method", "GET"),
        NV(":scheme", "https"),
        NV(":authority", authority),
        NV(":path", path),
        NV("user-agent", "h3migrate"),
        NV("authorization", auth ? auth : ""),
    };
    int rv;

    cl->status = 0;
    cl->bodylen = 0;
    cl->done = false;

    rv = ngtcp2_conn_open_bidi_stream(cl->conn, &cl->stream_id, NULL);
    if (rv) fail("ngtcp2_conn_open_bidi_stream", ngtcp2_strerror(rv));

    rv = nghttp3_conn_submit_request(cl->h3, cl->stream_id, nva,
                                     auth ? 6 : 5, NULL, NULL);
    if (rv) fail("nghttp3_conn_submit_request", nghttp3_strerror(rv));

    return run_until(cl, &cl->done, secs);
}

/* Move the connection to a fresh local port, closing the old one.
 * Returns false if the server didn't provide a connection ID to move
 * to in time. */
static bool migrate(struct client *cl, int secs)
{
    ngtcp2_tstamp deadline = now() + (ngtcp2_tstamp) secs * NGTCP2_SECONDS;
    struct sockaddr_storage local;
    socklen_t locallen;
    int sock = new_socket(cl, &local, &locallen);

    while (!cl->closed) {
        ngtcp2_path path;
        bool never = false;
        int rv;

        ngtcp2_addr_init(&path.local, (struct sockaddr *) &local, locallen);
        ngtcp2_addr_init(&path.remote, (struct sockaddr *) &cl->remote,
                         cl->remotelen);
        path.user_data = NULL;

        rv = ngtcp2_conn_initiate_immediate_migration(cl->conn, &path, now());
        if (!rv) {
            close(cl->sock);
            cl->sock = sock;
            cl->local = local;
            cl->locallen = locallen;
            return true;
        }

        /* No spare CID from the server yet: keep the old path going a
         * little longer */
        if (rv != NGTCP2_ERR_CONN_ID_BLOCKED) {
            fail("ngtcp2_conn_initiate_immediate_migration",
                 ngtcp2_strerror(rv));
        }
        if (now() >= deadline) break;
        run_until(cl, &never, 1);
    }

    close(sock);
    return false;
}

static char *basic_auth(const char *userpass)
{
    size_t len = strlen(userpass);
    char *out = malloc(6 + 4 * ((len + 2) / 3) + 1);

    strcpy(out, "Basic ");
    EVP_EncodeBlock((unsigned char *) out + 6, (const unsigned char *) userpass,
                    (int) len);
    return out;
}

int main(int argc, char **argv)
{
    int migrations = 0, secs = 10, opt;
    const char *userpass = NULL;
    char *auth = NULL;
    char authority[300];
    struct addrinfo hints = { .ai_socktype = SOCK_DGRAM }, *ai;
    struct client cl = { .stream_id = -1 };
    SSL_CTX *ssl_ctx;
    ngtcp2_cid dcid, scid;
    ngtcp2_settings settings;
    ngtcp2_transport_params params;
    ngtcp2_path path;
    int rv;

    while ((opt = getopt(argc, argv, "n:t:u:")) != -1) {
        switch (opt) {
        case 'n': migrations = atoi(optarg); break;
        case 't': secs = atoi(optarg); break;
        case 'u': userpass = optarg; break;
        default:
            fprintf(stderr, "usage: h3migrate [-n migrations] [-t timeout]"
                            " [-u user:pass] host port path\n");
            return 1;
        }
    }
    if (argc - optind != 3) fail("usage", "host port path");
    const char *host = argv[optind], *port = argv[optind + 1];
    const char *urlpath = argv[optind + 2];

    snprintf(authority, sizeof(authority),
             strchr(host, ':') ? "[%s]:%s" : "%s:%s", host, port);
    if (userpass) auth = basic_auth(userpass);

    if ((rv = getaddrinfo(host, port, &hints, &ai))) {
        fail("getaddrinfo", gai_strerror(rv));
    }
    memcpy(&cl.remote, ai->ai_addr, ai->ai_addrlen);
    cl.remotelen = ai->ai_addrlen;
    freeaddrinfo(ai);
    cl.sock = new_socket(&cl, &cl.local, &cl.locallen);

    if (ngtcp2_crypto_ossl_init()) fail("ngtcp2_crypto_ossl_init", "failed");
    ssl_ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ssl_ctx, TLS1_3_VERSION);
    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_NONE, NULL);

    cl.ssl = SSL_new(ssl_ctx);
    SSL_set_connect_state(cl.ssl);
    SSL_set_alpn_protos(cl.ssl, (const uint8_t *) "\x02h3", 3);
    if (!strchr(host, ':')) SSL_set_tlsext_host_name(cl.ssl, host);
    if (ngtcp2_crypto_ossl_ctx_new(&cl.ossl_ctx, cl.ssl) ||
        ngtcp2_crypto_ossl_configure_client_session(cl.ssl)) {
        fail("TLS setup", "failed");
    }
    cl.conn_ref.get_conn = get_conn;
    cl.conn_ref.user_data = &cl;
    SSL_set_app_data(cl.ssl, &cl.conn_ref);

    dcid.datalen = CIDLEN;
    RAND_bytes(dcid.data, CIDLEN);
    scid.datalen = CIDLEN;
    RAND_bytes(scid.data, CIDLEN);

    ngtcp2_settings_default(&settings);
    settings.initial_ts = now();
    ngtcp2_transport_params_default(&params);
    params.initial_max_streams_uni = 3;
    params.initial_max_stream_data_bidi_local = 1024 * 1024;
    params.initial_max_stream_data_uni = 1024 * 1024;
    params.initial_max_data = 4 * 1024 * 1024;

    get_path(&cl, &path);
    rv = ngtcp2_conn_client_new(&cl.conn, &dcid, &scid, &path,
                                NGTCP2_PROTO_VER_V1, &callbacks,
                                &settings, &params, NULL, &cl);
    if (rv) fail("ngtcp2_conn_client_new", ngtcp2_strerror(rv));
    ngtcp2_conn_set_tls_native_handle(cl.conn, cl.ossl_ctx);

    /* The server's control streams can arrive with its first flight */
    nghttp3_settings h3settings;
    nghttp3_settings_default(&h3settings);
    if (nghttp3_conn_client_new(&cl.h3, &h3_callbacks, &h3settings, NULL,
                                &cl)) {
        fail("nghttp3_conn_client_new", "failed");
    }

    if (!run_until(&cl, &cl.handshake_done, secs)) {
        fail("handshake", cl.closed ? cl.closed : "timed out");
    }
    open_ctrl_streams(&cl);

    int status = 0;
    for (int i = 0; i <= migrations; i++) {
        if (i) {
            if (!migrate(&cl, secs)) {
                if (!cl.closed) printf("stalled %d\n", i);
                status = 3;
                break;
            }
            printf("migrated %d %d\n", i, local_port(&cl.local));
        }
        if (!request(&cl, authority, urlpath, auth, secs)) {
            if (!cl.closed) printf("timeout %d\n", i);
            status = 3;
            break;
        }
        printf("response %d %d %zu %d\n", i, cl.status, cl.bodylen,
               local_port(&cl.local));
        fflush(stdout);
    }
    if (cl.closed) {
        printf("closed %s\n", cl.closed);
        status = 3;
    }
    else {
        uint8_t buf[PKT_BUFSIZE];
        ngtcp2_ccerr ccerr;
        ngtcp2_pkt_info pi = { 0 };
        ngtcp2_ssize n;

        ngtcp2_ccerr_set_application_error(&ccerr, NGHTTP3_H3_NO_ERROR,
                                           NULL, 0);
        get_path(&cl, &path);
        n = ngtcp2_conn_write_connection_close(cl.conn, &path, &pi, buf,
                                               sizeof(buf), &ccerr, now());
        if (n > 0) send(cl.sock, buf, (size_t) n, 0);
    }

    nghttp3_conn_del(cl.h3);
    ngtcp2_conn_del(cl.conn);
    ngtcp2_crypto_ossl_ctx_del(cl.ossl_ctx);
    SSL_set_app_data(cl.ssl, NULL);
    SSL_free(cl.ssl);
    SSL_CTX_free(ssl_ctx);
    free(auth);
    close(cl.sock);

    return status;
}
