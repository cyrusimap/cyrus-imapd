/* test_quic_migration.c - drives a real ngtcp2 client, in-process,
 * through repeated QUIC connection migrations against a real
 * imap/quic.c server session, to exercise things live client traffic
 * can't practically be made to do on demand:
 *
 * - A migration actually working (the server's tracked peer address
 *   follows the client to its new source port).
 * - What happens once master's pre-registered spare CID pool
 *   (QUIC_CID_POOL_SIZE, quic_handoff.h) runs out --
 *   quic_get_new_connection_id_cb() (imap/quic.c) should fail the
 *   connection outright rather than hand out a CID neither dispatch
 *   backend would recognize. Also characterizes a shrunk pool
 *   (ncids=2, one spare) against clients wanting different
 *   active_connection_id_limit values: enough for an ordinary,
 *   non-migrating connection (the spare exactly covers the
 *   post-handshake top-up), but not enough headroom left over for
 *   ngtcp2's own follow-on replenishment once a migration starts
 *   using it -- this fires regardless of RETIRE_CONNECTION_ID:
 *   quic_remove_connection_id_cb (imap/quic.c) never fires in these
 *   scenarios. The migration itself still works; the connection just
 *   doesn't survive past it.
 * - The anti-spoofing property that an off-path attacker with none of
 *   the connection's keys can't redirect the server's replies just by
 *   sending a datagram carrying the real CID (which travels in
 *   cleartext) from an address the connection has never validated.
 *   imap/quic.c never writes such a claim into qs->peer_addr in the
 *   first place (see quic_input()), and separately,
 *   ngtcp2_conn_writev_stream() (called from quic_flush_output())
 *   documents that it writes the actual current path back through its
 *   |path| argument -- which aliases qs->peer_addr -- independent of
 *   whatever was fed to it, though only "if something is written to
 *   dest", so it isn't a reliable guarantee on its own.
 *   quic_path_validation_cb() is a third, explicit signal (RFC 9000
 *   9.3's PATH_CHALLENGE/PATH_RESPONSE outcome) that doesn't always
 *   fire before an immediate-migration scenario ends -- kept anyway
 *   since it's the correct, ngtcp2-sanctioned answer to "has this path
 *   actually been validated", not something to depend on a write-path
 *   side effect for.
 *
 * Not part of the build -- ad hoc verification only, same spirit as
 * quic_echo_server.c/test_quic_ebpf_steer.c.
 *
 * No dispatch backend is involved at all: like quic_echo_server.c,
 * this plays master's part by hand, constructing quic_handoff itself
 * from a real datagram read off a real, deliberately unconnected UDP
 * socket. The client side is hand-rolled directly against ngtcp2 and
 * ngtcp2_crypto_ossl (imap/quic.c has no client-side API -- it's a
 * server-only transport layer), migrating by binding a fresh loopback
 * UDP socket and calling ngtcp2_conn_initiate_immediate_migration().
 *
 * Build (from the repo root, after a normal `dar build`/`./myconfig.sh`
 * build so lib/libcyrus.la etc. already exist):
 *
 *   libtool --mode=link gcc -g -O0 \
 *     -I. -Ilib -Iimap -Imaster $(pkg-config --cflags libngtcp2 \
 *       libngtcp2_crypto_ossl openssl) \
 *     -o master/quic/test_quic_migration master/quic/test_quic_migration.c \
 *     imap/quic.c imap/tls.c \
 *     lib/libcyrus.la lib/libcyrus_min.la $(pkg-config --libs libngtcp2 \
 *       libngtcp2_crypto_ossl openssl)
 *
 * Run (needs a minimal config file, same as quic_echo_server.c -- a
 * writable configdirectory and a cert/key pair, e.g. `openssl req
 * -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout
 * key.pem -out cert.pem -days 1 -subj /CN=localhost`):
 *
 *   master/quic/test_quic_migration <config-file>
 */
#include <config.h>

#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <openssl/rand.h>
#include <openssl/ssl.h>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_ossl.h>

#include "libconfig.h"
#include "util.h"
#include "xmalloc.h"

#include "master/service.h"
#include "imap/quic.h"

/* Same stand-ins quic_echo_server.c needs and for the same reasons --
 * see its own comments on each of these. */
/* This plays master's part by hand, so it supplies the handoff
 * service.c would normally own, and the accessor imap/quic.c reads it
 * through. */
static struct quic_handoff quic_handoff;

const struct quic_handoff *service_quic_handoff(void)
{
    return quic_handoff.ncids ? &quic_handoff : NULL;
}

/* This plays master's part with one real socket, so there is no
 * separate send socket */
int service_quic_send_fd(void)
{
    return -1;
}

EXPORTED void fatal(const char *msg, int code)
{
    fprintf(stderr, "test_quic_migration: fatal: %s\n", msg);
    exit(code);
}

EXPORTED const char *config_tls_sessions_db;

EXPORTED void saslprops_reset(struct saslprops_t *saslprops)
{
    buf_reset(&saslprops->iplocalport);
    buf_reset(&saslprops->ipremoteport);
    buf_reset(&saslprops->authid);
    saslprops->ssf = 0;
    saslprops->cbinding.name = NULL;
}

static int npass = 0, nfail = 0;

static void check(bool cond, const char *what)
{
    if (cond) {
        printf("PASS: %s\n", what);
        npass++;
    }
    else {
        printf("FAIL: %s\n", what);
        nfail++;
    }
}

/* Private test ALPN -- neither side needs it to mean anything beyond
 * "both ends of this test agree on it". */
#define TEST_ALPN_ID "migrate-test"
static const uint8_t test_alpn_wire[] = {
    sizeof(TEST_ALPN_ID) - 1,
    'm', 'i', 'g', 'r', 'a', 't', 'e', '-', 't', 'e', 's', 't'
};
static struct tls_alpn_t test_alpn_map[] = {
    { TEST_ALPN_ID, NULL, NULL },
    { "",           NULL, NULL }
};

/*
 * Server side: imap/quic.c's real session machinery, with an app that
 * needs nothing beyond noticing the handshake finished -- this test
 * never opens a stream on either end.
 */

struct test_server {
    struct quic_session qs;
    bool handshake_done;
};

static void srv_handshake_completed(struct quic_session *qs)
{
    ((struct test_server *) qs)->handshake_done = true;
}

static ngtcp2_ssize srv_recv_stream_data(
    struct quic_session *qs __attribute__((unused)),
    int64_t stream_id __attribute__((unused)),
    const uint8_t *data __attribute__((unused)),
    size_t datalen, bool fin __attribute__((unused)))
{
    return (ngtcp2_ssize) datalen;
}

static void srv_acked_stream_data(
    struct quic_session *qs __attribute__((unused)),
    int64_t stream_id __attribute__((unused)),
    uint64_t datalen __attribute__((unused))) {}

static void srv_stream_closed(
    struct quic_session *qs __attribute__((unused)),
    int64_t stream_id __attribute__((unused)),
    uint64_t app_error_code __attribute__((unused))) {}

static void srv_stream_reset(
    struct quic_session *qs __attribute__((unused)),
    int64_t stream_id __attribute__((unused)),
    uint64_t app_error_code __attribute__((unused))) {}

static int srv_io_ready(struct quic_session *qs __attribute__((unused)))
{
    return 0;
}

static ngtcp2_ssize srv_get_output(
    struct quic_session *qs __attribute__((unused)),
    int64_t *pstream_id, int *pfin __attribute__((unused)),
    ngtcp2_vec *vec __attribute__((unused)),
    size_t veccnt __attribute__((unused)))
{
    *pstream_id = -1;
    return 0;
}

static void srv_advance_output(
    struct quic_session *qs __attribute__((unused)),
    int64_t stream_id __attribute__((unused)),
    size_t datalen __attribute__((unused))) {}

static void srv_block_output(
    struct quic_session *qs __attribute__((unused)),
    int64_t stream_id __attribute__((unused))) {}

static int srv_unblock_output(
    struct quic_session *qs __attribute__((unused)),
    int64_t stream_id __attribute__((unused))) { return 0; }

static void srv_session_free(struct quic_session *qs __attribute__((unused))) {}

static const struct quic_app_ops test_server_ops = {
    .handshake_completed = srv_handshake_completed,
    .recv_stream_data    = srv_recv_stream_data,
    .acked_stream_data   = srv_acked_stream_data,
    .stream_closed       = srv_stream_closed,
    .stream_reset        = srv_stream_reset,
    .io_ready            = srv_io_ready,
    .get_output          = srv_get_output,
    .advance_output      = srv_advance_output,
    .block_output        = srv_block_output,
    .unblock_output      = srv_unblock_output,
    .session_free        = srv_session_free,
};

/*
 * Client side: no equivalent in imap/quic.c (server-only), so this is
 * hand-rolled directly against ngtcp2/ngtcp2_crypto_ossl.
 */

struct test_client {
    ngtcp2_conn *conn;
    SSL *ssl;
    ngtcp2_crypto_ossl_ctx *ossl_ctx;
    ngtcp2_crypto_conn_ref conn_ref;

    int sock;
    struct sockaddr_storage local_addr, peer_addr;
    socklen_t local_addrlen, peer_addrlen;

    bool handshake_done;
};

static ngtcp2_tstamp test_now(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (ngtcp2_tstamp) ts.tv_sec * NGTCP2_SECONDS +
           (ngtcp2_tstamp) ts.tv_nsec;
}

static ngtcp2_conn *test_client_get_conn(ngtcp2_crypto_conn_ref *ref)
{
    return ((struct test_client *) ref->user_data)->conn;
}

static void test_client_rand_cb(
    uint8_t *dest, size_t destlen,
    const ngtcp2_rand_ctx *rand_ctx __attribute__((unused)))
{
    RAND_bytes(dest, (int) destlen);
}

static int test_client_get_new_connection_id_cb(
    ngtcp2_conn *conn __attribute__((unused)),
    ngtcp2_cid *cid, uint8_t *token, size_t cidlen,
    void *user_data __attribute__((unused)))
{
    RAND_bytes(cid->data, (int) cidlen);
    cid->datalen = cidlen;
    RAND_bytes(token, NGTCP2_STATELESS_RESET_TOKENLEN);
    return 0;
}

static int test_client_handshake_completed_cb(
    ngtcp2_conn *conn __attribute__((unused)), void *user_data)
{
    ((struct test_client *) user_data)->handshake_done = true;
    return 0;
}

static const ngtcp2_callbacks test_client_callbacks = {
    .client_initial           = ngtcp2_crypto_client_initial_cb,
    .recv_crypto_data         = ngtcp2_crypto_recv_crypto_data_cb,
    .handshake_completed      = test_client_handshake_completed_cb,
    .encrypt                  = ngtcp2_crypto_encrypt_cb,
    .decrypt                  = ngtcp2_crypto_decrypt_cb,
    .hp_mask                  = ngtcp2_crypto_hp_mask_cb,
    .rand                     = test_client_rand_cb,
    .get_new_connection_id    = test_client_get_new_connection_id_cb,
    .update_key               = ngtcp2_crypto_update_key_cb,
    .delete_crypto_aead_ctx   = ngtcp2_crypto_delete_crypto_aead_ctx_cb,
    .delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
    .get_path_challenge_data  = ngtcp2_crypto_get_path_challenge_data_cb,
    .version_negotiation      = ngtcp2_crypto_version_negotiation_cb,
    .recv_retry               = ngtcp2_crypto_recv_retry_cb,
};

/* A fresh loopback UDP socket, connected to server_addr (so plain
 * send()/recv() work) and bound to a fresh ephemeral port -- used both
 * for the client's very first socket and for each migration's new
 * one. */
static int test_make_client_socket(const struct sockaddr_storage *server_addr,
                                   socklen_t server_addrlen,
                                   struct sockaddr_storage *out_local,
                                   socklen_t *out_local_len)
{
    struct sockaddr_in bindaddr = { .sin_family = AF_INET,
                                    .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
                                    .sin_port = 0 };
    int sock = socket(AF_INET, SOCK_DGRAM, 0);

    if (sock < 0) return -1;
    if (bind(sock, (struct sockaddr *) &bindaddr, sizeof(bindaddr))) {
        close(sock);
        return -1;
    }
    if (connect(sock, (struct sockaddr *) server_addr, server_addrlen)) {
        close(sock);
        return -1;
    }
    *out_local_len = sizeof(*out_local);
    if (getsockname(sock, (struct sockaddr *) out_local, out_local_len)) {
        close(sock);
        return -1;
    }
    return sock;
}

/* Drain whatever ngtcp2 has queued for the client's current path,
 * mirroring imap/quic.c's own quic_flush_output(). */
static void test_client_flush(struct test_client *cl)
{
    for (;;) {
        uint8_t out[QUIC_PKT_BUFSIZE];
        ngtcp2_path path;
        ngtcp2_pkt_info pi;
        ngtcp2_ssize datalen;
        ngtcp2_ssize n;

        ngtcp2_addr_init(&path.local, (struct sockaddr *) &cl->local_addr,
                         cl->local_addrlen);
        ngtcp2_addr_init(&path.remote, (struct sockaddr *) &cl->peer_addr,
                         cl->peer_addrlen);
        path.user_data = NULL;
        memset(&pi, 0, sizeof(pi));

        n = ngtcp2_conn_writev_stream(cl->conn, &path, &pi, out, sizeof(out),
                                      &datalen, NGTCP2_WRITE_STREAM_FLAG_NONE,
                                      -1, NULL, 0, test_now());
        if (n < 0) {
            fprintf(stderr, "test_quic_migration: client writev failed: %s\n",
                   ngtcp2_strerror((int) n));
            return;
        }
        if (n == 0) break;

        if (send(cl->sock, out, (size_t) n, 0) < 0) {
            fprintf(stderr, "test_quic_migration: client send failed\n");
            return;
        }
    }
}

/* Read and process one datagram if the client's current socket has
 * one pending. Returns whether it did. */
static bool test_client_input(struct test_client *cl)
{
    uint8_t buf[QUIC_PKT_BUFSIZE];
    ngtcp2_path path;
    ngtcp2_pkt_info pi;
    ssize_t n;
    int rv;

    n = recv(cl->sock, buf, sizeof(buf), MSG_DONTWAIT);
    if (n <= 0) return false;

    ngtcp2_addr_init(&path.local, (struct sockaddr *) &cl->local_addr,
                     cl->local_addrlen);
    ngtcp2_addr_init(&path.remote, (struct sockaddr *) &cl->peer_addr,
                     cl->peer_addrlen);
    path.user_data = NULL;
    memset(&pi, 0, sizeof(pi));

    rv = ngtcp2_conn_read_pkt(cl->conn, &path, &pi, buf, (size_t) n,
                              test_now());
    if (rv) {
        fprintf(stderr, "test_quic_migration: client read_pkt: %s\n",
               ngtcp2_strerror(rv));
    }
    return true;
}

/* Pump both sides -- client flush/input, server quic_input() -- for
 * up to |rounds| short poll() cycles, or until the server session is
 * draining, whichever comes first. */
static void test_pump(struct test_client *cl, struct test_server *srv,
                      int rounds)
{
    int i;

    for (i = 0; i < rounds && !srv->qs.draining; i++) {
        struct pollfd pfds[2];

        test_client_flush(cl);

        pfds[0].fd = cl->sock;
        pfds[0].events = POLLIN;
        pfds[1].fd = srv->qs.fd;
        pfds[1].events = POLLIN;
        poll(pfds, 2, 50);

        if (pfds[0].revents & POLLIN) test_client_input(cl);
        if (pfds[1].revents & POLLIN) {
            const char *close_reason = NULL;

            quic_input(&srv->qs, &close_reason);
        }
    }
}

/* One full scenario: handshake, then repeatedly migrate the client to
 * a fresh loopback source port, until either the server session
 * starts draining or |max_migrations| is reached (0 attempts none, to
 * isolate whatever CID replenishment ordinary post-handshake setup
 * alone needs). ncids is the total handoff pool size (primary +
 * spares) master would have generated -- shrunk well below
 * QUIC_CID_POOL_SIZE to make exhaustion reachable in a handful of
 * migrations instead of needing to churn through the real production
 * pool size. aci_limit is the client's advertised
 * active_connection_id_limit, driving how many CIDs the server needs
 * to supply just to complete the handshake, before any migration. */
static void run_scenario(const char *label, uint8_t ncids,
                         uint32_t aci_limit, int max_migrations,
                         bool expect_exhaustion,
                         SSL_CTX *server_ssl_ctx, SSL_CTX *client_ssl_ctx)
{
    int server_sock;
    struct sockaddr_storage server_addr;
    socklen_t server_addrlen = sizeof(server_addr);
    struct test_client cl;
    struct test_server srv;
    ngtcp2_cid dcid, scid;
    ngtcp2_settings csettings;
    ngtcp2_transport_params cparams;
    ngtcp2_path initial_path;
    uint8_t pktbuf[QUIC_PKT_BUFSIZE];
    struct sockaddr_storage peer;
    socklen_t peerlen = sizeof(peer);
    struct sockaddr_storage local_addr;
    socklen_t local_addrlen = sizeof(local_addr);
    uint8_t cid_pool[QUIC_CID_POOL_SIZE][QUIC_CIDLEN];
    ssize_t n;
    int i;

    printf("--- scenario: %s ---\n", label);

    server_sock = socket(AF_INET, SOCK_DGRAM, 0);
    {
        struct sockaddr_in bindaddr = { .sin_family = AF_INET,
                                        .sin_addr.s_addr =
                                            htonl(INADDR_LOOPBACK),
                                        .sin_port = 0 };

        if (server_sock < 0 ||
            bind(server_sock, (struct sockaddr *) &bindaddr,
                sizeof(bindaddr))) {
            check(false, "set up server socket");
            return;
        }
    }
    getsockname(server_sock, (struct sockaddr *) &server_addr,
               &server_addrlen);

    memset(&cl, 0, sizeof(cl));
    cl.sock = test_make_client_socket(&server_addr, server_addrlen,
                                      &cl.local_addr, &cl.local_addrlen);
    if (cl.sock < 0) {
        check(false, "set up client socket");
        close(server_sock);
        return;
    }
    memcpy(&cl.peer_addr, &server_addr, server_addrlen);
    cl.peer_addrlen = server_addrlen;

    cl.ssl = SSL_new(client_ssl_ctx);
    SSL_set_connect_state(cl.ssl);
    SSL_set_alpn_protos(cl.ssl, test_alpn_wire, sizeof(test_alpn_wire));

    if (ngtcp2_crypto_ossl_ctx_new(&cl.ossl_ctx, cl.ssl) ||
        ngtcp2_crypto_ossl_configure_client_session(cl.ssl)) {
        check(false, "set up client TLS");
        goto done;
    }
    cl.conn_ref.get_conn = test_client_get_conn;
    cl.conn_ref.user_data = &cl;
    SSL_set_app_data(cl.ssl, &cl.conn_ref);

    RAND_bytes(dcid.data, QUIC_CIDLEN);
    dcid.datalen = QUIC_CIDLEN;
    RAND_bytes(scid.data, QUIC_CIDLEN);
    scid.datalen = QUIC_CIDLEN;

    ngtcp2_settings_default(&csettings);
    csettings.initial_ts = test_now();
    csettings.max_tx_udp_payload_size = 1452;
    csettings.no_pmtud = 1;

    ngtcp2_transport_params_default(&cparams);
    cparams.active_connection_id_limit = aci_limit;

    ngtcp2_addr_init(&initial_path.local,
                     (struct sockaddr *) &cl.local_addr, cl.local_addrlen);
    ngtcp2_addr_init(&initial_path.remote,
                     (struct sockaddr *) &cl.peer_addr, cl.peer_addrlen);
    initial_path.user_data = NULL;

    if (ngtcp2_conn_client_new(&cl.conn, &dcid, &scid, &initial_path,
                              NGTCP2_PROTO_VER_V1, &test_client_callbacks,
                              &csettings, &cparams, NULL, &cl)) {
        check(false, "create client ngtcp2_conn");
        goto done;
    }
    ngtcp2_conn_set_tls_native_handle(cl.conn, cl.ossl_ctx);

    /* First Initial packet, and the server's side of dispatch -- master
     * played by hand, exactly like quic_echo_server.c. */
    test_client_flush(&cl);

    n = recvfrom(server_sock, pktbuf, sizeof(pktbuf), 0,
                (struct sockaddr *) &peer, &peerlen);
    if (n < 0 || ngtcp2_accept(NULL, pktbuf, (size_t) n)) {
        check(false, "receive client's Initial packet");
        goto done;
    }
    getsockname(server_sock, (struct sockaddr *) &local_addr,
               &local_addrlen);

    RAND_bytes(cid_pool[0], sizeof(cid_pool));
    memset(&quic_handoff, 0, sizeof(quic_handoff));
    memcpy(quic_handoff.cids, cid_pool, (size_t) ncids * QUIC_CIDLEN);
    quic_handoff.ncids = ncids;
    memcpy(&quic_handoff.local_addr, &local_addr, local_addrlen);
    quic_handoff.local_addrlen = local_addrlen;
    memcpy(&quic_handoff.peer_addr, &peer, peerlen);
    quic_handoff.peer_addrlen = peerlen;
    quic_handoff.pktlen = (size_t) n;
    memcpy(quic_handoff.pkt, pktbuf, (size_t) n);

    memset(&srv, 0, sizeof(srv));
    if (quic_session_new(&srv.qs, server_sock, server_ssl_ctx,
                         &(struct quic_app) { test_alpn_map,
                                              &test_server_ops },
                         300)) {
        check(false, "quic_session_new");
        goto done_client;
    }
    quic_process_datagram(&srv.qs, srv.qs.first_pkt, srv.qs.first_pktlen,
                          &srv.qs.peer_addr, srv.qs.peer_addrlen);

    /* Handshake: pump until both sides report done, the session starts
     * draining (e.g. the pool couldn't even cover the client's
     * post-handshake active_connection_id_limit top-up), or we give up
     * waiting. */
    for (i = 0; i < 100 && !(cl.handshake_done && srv.handshake_done) &&
        !srv.qs.draining; i++) {
        test_pump(&cl, &srv, 1);
    }

    if (expect_exhaustion && srv.qs.draining) {
        /* Exhausted before the handshake even finished -- still a
         * pass: the point is a clean close, not surviving to migrate. */
        check(true, "connection closes once the spare CID pool "
                    "is exhausted");
        goto done_server;
    }

    check(cl.handshake_done && srv.handshake_done && !srv.qs.draining,
         "handshake completes");
    if (!(cl.handshake_done && srv.handshake_done) || srv.qs.draining) {
        goto done_server;
    }

    /* A couple of settle rounds so any post-handshake CID top-up
     * (NEW_CONNECTION_ID for the client's advertised
     * active_connection_id_limit) is already exchanged before the
     * first migration attempt. */
    test_pump(&cl, &srv, 10);

    bool migrated = false;

    for (i = 0; i < max_migrations && !srv.qs.draining; i++) {
        struct sockaddr_storage new_local;
        socklen_t new_local_len;
        int new_sock = test_make_client_socket(&server_addr, server_addrlen,
                                               &new_local, &new_local_len);
        ngtcp2_path mpath;
        int rv;

        if (new_sock < 0) {
            check(false, "create migration socket");
            break;
        }

        ngtcp2_addr_init(&mpath.local, (struct sockaddr *) &new_local,
                         new_local_len);
        ngtcp2_addr_init(&mpath.remote, (struct sockaddr *) &cl.peer_addr,
                         cl.peer_addrlen);
        mpath.user_data = NULL;

        rv = ngtcp2_conn_initiate_immediate_migration(cl.conn, &mpath,
                                                      test_now());
        if (rv) {
            /* CONN_ID_BLOCKED here just means we outran the server's
             * replenishment -- give it another settle round and retry
             * this same migration attempt rather than counting it. */
            close(new_sock);
            test_pump(&cl, &srv, 10);
            i--;
            continue;
        }

        close(cl.sock);
        cl.sock = new_sock;
        cl.local_addr = new_local;
        cl.local_addrlen = new_local_len;
        migrated = true;

        test_pump(&cl, &srv, 20);
    }

    /* Whether the pool later survives or not (checked below), a
     * migration that actually happened should already be reflected --
     * exhaustion is a separate failure (insufficient spares for
     * ngtcp2's own follow-on replenishment once the migration starts
     * using one), not the migration itself silently not taking
     * effect. */
    if (migrated) {
        struct sockaddr_in *srv_peer = (struct sockaddr_in *) &srv.qs.peer_addr;
        struct sockaddr_in *cl_local = (struct sockaddr_in *) &cl.local_addr;

        check(srv.qs.peer_addr.ss_family == AF_INET &&
             srv_peer->sin_port == cl_local->sin_port,
             "server's tracked peer address follows the last migration");
    }

    if (expect_exhaustion) {
        check(srv.qs.draining, "connection closes once the spare CID "
                              "pool is exhausted");
    }
    else {
        check(!srv.qs.draining, "connection survives without "
                                "exhausting the pool");
    }

done_server:
    quic_session_free(&srv.qs);
done_client:
    if (cl.conn) ngtcp2_conn_del(cl.conn);
    if (cl.ossl_ctx) ngtcp2_crypto_ossl_ctx_del(cl.ossl_ctx);
done:
    if (cl.ssl) {
        SSL_set_app_data(cl.ssl, NULL);
        SSL_free(cl.ssl);
    }
    close(cl.sock);
    close(server_sock);
}

/* Anti-spoofing: an off-path attacker who has observed the
 * connection's primary CID (it travels in cleartext in every packet's
 * header) but holds none of its cryptographic keys sends a
 * short-header packet carrying that CID, from a source address the
 * connection has never validated. Confirm this doesn't redirect the
 * server's replies -- see this file's header comment for how imap/quic.c
 * defends against it. Duplicates run_scenario()'s setup rather than sharing it,
 * to avoid touching its already-verified logic for this narrower
 * check. */
static void run_spoof_scenario(SSL_CTX *server_ssl_ctx, SSL_CTX *client_ssl_ctx)
{
    int server_sock, attacker_sock;
    struct sockaddr_storage server_addr;
    socklen_t server_addrlen = sizeof(server_addr);
    struct test_client cl;
    struct test_server srv;
    ngtcp2_cid dcid, scid;
    ngtcp2_settings csettings;
    ngtcp2_transport_params cparams;
    ngtcp2_path initial_path;
    uint8_t pktbuf[QUIC_PKT_BUFSIZE];
    struct sockaddr_storage peer;
    socklen_t peerlen = sizeof(peer);
    struct sockaddr_storage local_addr;
    socklen_t local_addrlen = sizeof(local_addr);
    uint8_t cid_pool[QUIC_CID_POOL_SIZE][QUIC_CIDLEN];
    ssize_t n;
    uint16_t real_client_port;
    int i;

    printf("--- scenario: spoofed packet, valid CID, no keys ---\n");

    server_sock = socket(AF_INET, SOCK_DGRAM, 0);
    {
        struct sockaddr_in bindaddr = { .sin_family = AF_INET,
                                        .sin_addr.s_addr =
                                            htonl(INADDR_LOOPBACK),
                                        .sin_port = 0 };

        if (server_sock < 0 ||
            bind(server_sock, (struct sockaddr *) &bindaddr,
                sizeof(bindaddr))) {
            check(false, "set up server socket");
            return;
        }
    }
    getsockname(server_sock, (struct sockaddr *) &server_addr,
               &server_addrlen);

    memset(&cl, 0, sizeof(cl));
    cl.sock = test_make_client_socket(&server_addr, server_addrlen,
                                      &cl.local_addr, &cl.local_addrlen);
    if (cl.sock < 0) {
        check(false, "set up client socket");
        close(server_sock);
        return;
    }
    memcpy(&cl.peer_addr, &server_addr, server_addrlen);
    cl.peer_addrlen = server_addrlen;

    cl.ssl = SSL_new(client_ssl_ctx);
    SSL_set_connect_state(cl.ssl);
    SSL_set_alpn_protos(cl.ssl, test_alpn_wire, sizeof(test_alpn_wire));

    if (ngtcp2_crypto_ossl_ctx_new(&cl.ossl_ctx, cl.ssl) ||
        ngtcp2_crypto_ossl_configure_client_session(cl.ssl)) {
        check(false, "set up client TLS");
        goto done;
    }
    cl.conn_ref.get_conn = test_client_get_conn;
    cl.conn_ref.user_data = &cl;
    SSL_set_app_data(cl.ssl, &cl.conn_ref);

    RAND_bytes(dcid.data, QUIC_CIDLEN);
    dcid.datalen = QUIC_CIDLEN;
    RAND_bytes(scid.data, QUIC_CIDLEN);
    scid.datalen = QUIC_CIDLEN;

    ngtcp2_settings_default(&csettings);
    csettings.initial_ts = test_now();
    csettings.max_tx_udp_payload_size = 1452;
    csettings.no_pmtud = 1;

    ngtcp2_transport_params_default(&cparams);
    cparams.active_connection_id_limit = 2;

    ngtcp2_addr_init(&initial_path.local,
                     (struct sockaddr *) &cl.local_addr, cl.local_addrlen);
    ngtcp2_addr_init(&initial_path.remote,
                     (struct sockaddr *) &cl.peer_addr, cl.peer_addrlen);
    initial_path.user_data = NULL;

    if (ngtcp2_conn_client_new(&cl.conn, &dcid, &scid, &initial_path,
                              NGTCP2_PROTO_VER_V1, &test_client_callbacks,
                              &csettings, &cparams, NULL, &cl)) {
        check(false, "create client ngtcp2_conn");
        goto done;
    }
    ngtcp2_conn_set_tls_native_handle(cl.conn, cl.ossl_ctx);

    test_client_flush(&cl);

    n = recvfrom(server_sock, pktbuf, sizeof(pktbuf), 0,
                (struct sockaddr *) &peer, &peerlen);
    if (n < 0 || ngtcp2_accept(NULL, pktbuf, (size_t) n)) {
        check(false, "receive client's Initial packet");
        goto done;
    }
    getsockname(server_sock, (struct sockaddr *) &local_addr,
               &local_addrlen);

    RAND_bytes(cid_pool[0], sizeof(cid_pool));
    memset(&quic_handoff, 0, sizeof(quic_handoff));
    memcpy(quic_handoff.cids, cid_pool, sizeof(cid_pool));
    quic_handoff.ncids = QUIC_CID_POOL_SIZE;
    memcpy(&quic_handoff.local_addr, &local_addr, local_addrlen);
    quic_handoff.local_addrlen = local_addrlen;
    memcpy(&quic_handoff.peer_addr, &peer, peerlen);
    quic_handoff.peer_addrlen = peerlen;
    quic_handoff.pktlen = (size_t) n;
    memcpy(quic_handoff.pkt, pktbuf, (size_t) n);

    memset(&srv, 0, sizeof(srv));
    if (quic_session_new(&srv.qs, server_sock, server_ssl_ctx,
                         &(struct quic_app) { test_alpn_map,
                                              &test_server_ops },
                         300)) {
        check(false, "quic_session_new");
        goto done_client;
    }
    quic_process_datagram(&srv.qs, srv.qs.first_pkt, srv.qs.first_pktlen,
                          &srv.qs.peer_addr, srv.qs.peer_addrlen);

    for (i = 0; i < 100 && !(cl.handshake_done && srv.handshake_done) &&
        !srv.qs.draining; i++) {
        test_pump(&cl, &srv, 1);
    }
    check(cl.handshake_done && srv.handshake_done && !srv.qs.draining,
         "handshake completes");
    if (!(cl.handshake_done && srv.handshake_done) || srv.qs.draining) {
        goto done_server;
    }
    test_pump(&cl, &srv, 10);

    real_client_port = ((struct sockaddr_in *) &cl.local_addr)->sin_port;

    /* The attack: a fresh socket the connection has never seen,
     * sending a short-header packet that carries the real primary CID
     * -- observable in cleartext on every packet -- but garbage where
     * the encrypted payload would be, since the attacker has none of
     * the connection's keys. */
    attacker_sock = socket(AF_INET, SOCK_DGRAM, 0);
    {
        struct sockaddr_in bindaddr = { .sin_family = AF_INET,
                                        .sin_addr.s_addr =
                                            htonl(INADDR_LOOPBACK),
                                        .sin_port = 0 };
        uint8_t spoof_pkt[64];

        if (attacker_sock < 0 ||
            bind(attacker_sock, (struct sockaddr *) &bindaddr,
                sizeof(bindaddr)) ||
            connect(attacker_sock, (struct sockaddr *) &server_addr,
                   server_addrlen)) {
            check(false, "set up attacker socket");
            goto done_server;
        }

        spoof_pkt[0] = 0x40; /* short header, fixed bit set */
        memcpy(spoof_pkt + 1, cid_pool[0], QUIC_CIDLEN);
        RAND_bytes(spoof_pkt + 1 + QUIC_CIDLEN,
                  sizeof(spoof_pkt) - 1 - QUIC_CIDLEN);

        if (send(attacker_sock, spoof_pkt, sizeof(spoof_pkt), 0) < 0) {
            check(false, "send spoofed packet");
            close(attacker_sock);
            goto done_server;
        }
    }

    /* Give the server a chance to process it -- and the real client a
     * chance to react to anything unexpected -- without letting the
     * real client's own traffic mask what the spoofed packet alone
     * did. */
    for (i = 0; i < 10; i++) {
        struct pollfd pfd = { .fd = srv.qs.fd, .events = POLLIN };

        if (poll(&pfd, 1, 50) > 0 && (pfd.revents & POLLIN)) {
            const char *close_reason = NULL;

            quic_input(&srv.qs, &close_reason);
        }
    }

    check(((struct sockaddr_in *) &srv.qs.peer_addr)->sin_port ==
         real_client_port,
         "spoofed packet doesn't move the server's tracked peer address");

    n = recv(attacker_sock, pktbuf, sizeof(pktbuf), MSG_DONTWAIT);
    check(n <= 0, "attacker's socket receives nothing back");

    /* The real client should still be able to talk to the server
     * afterward -- the spoofed packet shouldn't have broken the
     * legitimate path either. */
    test_pump(&cl, &srv, 5);
    check(((struct sockaddr_in *) &srv.qs.peer_addr)->sin_port ==
         real_client_port,
         "real client's path is still current after the spoof attempt");

    close(attacker_sock);

done_server:
    quic_session_free(&srv.qs);
done_client:
    if (cl.conn) ngtcp2_conn_del(cl.conn);
    if (cl.ossl_ctx) ngtcp2_crypto_ossl_ctx_del(cl.ossl_ctx);
done:
    if (cl.ssl) {
        SSL_set_app_data(cl.ssl, NULL);
        SSL_free(cl.ssl);
    }
    close(cl.sock);
    close(server_sock);
}

int main(int argc, char **argv)
{
    SSL_CTX *server_ssl_ctx, *client_ssl_ctx;

    if (argc != 2) {
        fprintf(stderr, "usage: %s <config-file>\n\n"
               "config-file needs at least:\n"
               "    configdirectory: /some/writable/dir\n"
               "    tls_server_cert: /path/to/cert.pem\n"
               "    tls_server_key: /path/to/key.pem\n", argv[0]);
        return 1;
    }

    config_read(argv[1], 0);

    if (quic_init_tls_ctx(&server_ssl_ctx, false)) {
        fprintf(stderr, "test_quic_migration: quic_init_tls_ctx "
               "failed (check tls_server_cert/tls_server_key)\n");
        return 1;
    }

    client_ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (!client_ssl_ctx) {
        fprintf(stderr, "test_quic_migration: client SSL_CTX_new failed\n");
        return 1;
    }
    SSL_CTX_set_min_proto_version(client_ssl_ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(client_ssl_ctx, TLS1_3_VERSION);
    SSL_CTX_set_verify(client_ssl_ctx, SSL_VERIFY_NONE, NULL);

    /* Control: a production-size pool comfortably survives one
     * migration, and the server's tracking actually follows it. */
    run_scenario("ordinary migration", QUIC_CID_POOL_SIZE, 2, 1, false,
                server_ssl_ctx, client_ssl_ctx);

    /* A pool with only one spare gets exhausted well within a handful
     * of migrations (in practice, after just the first: the spare
     * covers the post-handshake active_connection_id_limit top-up, so
     * the client's very first migration succeeds using an already-
     * issued CID, but ngtcp2 asks for a replenishment the empty pool
     * can't give once the migration starts using it -- not
     * RETIRE_CONNECTION_ID-driven: quic_remove_connection_id_cb
     * (imap/quic.c) never fires in this scenario). */
    run_scenario("spare CID pool exhaustion", 2, 2, 10, true,
                server_ssl_ctx, client_ssl_ctx);

    /* A pool of 2 (one spare) against an RFC-minimum client: an
     * ordinary, non-migrating connection survives fine -- the one
     * spare exactly covers the post-handshake
     * active_connection_id_limit top-up, with nothing left over. But
     * that means it has no headroom left for ngtcp2's own follow-on
     * replenishment once a migration starts using it, so even a
     * single migration still ends the connection (the migration
     * itself works -- see the peer-address check above -- it just
     * doesn't survive past it). */
    run_scenario("pool size 2, ordinary connection, no migration",
                2, 2, 0, false, server_ssl_ctx, client_ssl_ctx);
    run_scenario("pool size 2, one migration exhausts what's left",
                2, 2, 1, true, server_ssl_ctx, client_ssl_ctx);

    /* Sensitivity check: a client asking for more headroom than the
     * RFC minimum (active_connection_id_limit=4, not implausible in
     * practice) can exhaust a pool of 2 from ordinary handshake setup
     * alone, with zero migrations attempted. Still expected to close
     * cleanly, not hang or go dark. */
    run_scenario("pool size 2, more demanding client, no migration",
                2, 4, 0, true, server_ssl_ctx, client_ssl_ctx);

    run_spoof_scenario(server_ssl_ctx, client_ssl_ctx);

    printf("\n%d passed, %d failed\n", npass, nfail);
    return nfail ? 1 : 0;
}
