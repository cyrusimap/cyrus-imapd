/* quic_echo_server.c - standalone QUIC echo server, exercising
 * master/quic/quic_parse.c and imap/quic.c outside of Cyrus's own
 * master-dispatch/httpd machinery.
 *
 * Not part of the build -- ad hoc verification only, same spirit as
 * master/quic/test_quic_steer.c. Handles one connection at a time
 * (no fork, no dispatch): read a datagram on the rendezvous socket,
 * treat it as a QUIC Initial packet the way master.c's
 * quic_dispatch_connection() would, then hand it to imap/quic.c's
 * session machinery exactly the way imap/http_h3.c does -- proving
 * that a second QUIC-carried protocol really can reuse imap/quic.c
 * without knowing anything about HTTP/3.
 *
 * ALPN "hq-interop": what ngtcp2's own example client (examples/
 * hq_client_proto_codec.cc in the ngtcp2 source tree) speaks when not
 * built with nghttp3 support. Its "request" is one line, "<METHOD>
 * <path>\r\n" on a client-initiated bidi stream, FIN'd immediately;
 * it treats the response as an opaque byte stream and writes whatever
 * comes back to a file (or stdout) with zero validation -- so
 * echoing the request straight back is a legitimate, fully compatible
 * response as far as that client is concerned.
 *
 * Build (from the repo root, after a normal `dar build`/`./myconfig.sh`
 * build so lib/libcyrus.la etc. already exist -- both lib/libcyrus.la
 * *and* lib/libcyrus_min.la are needed, the low-level pieces this
 * file/imap/quic.c/imap/tls.c use (buf_*, xmalloc, config_*, lock_*,
 * ptrarray_*, ...) are split across the two):
 *
 *   libtool --mode=link gcc -g -O0 \
 *     -I. -Ilib -Iimap -Imaster $(pkg-config --cflags libngtcp2 \
 *       libngtcp2_crypto_ossl openssl) \
 *     -o master/quic/quic_echo_server master/quic/quic_echo_server.c \
 *     imap/quic.c imap/tls.c master/quic/quic_parse.c \
 *     lib/libcyrus.la lib/libcyrus_min.la $(pkg-config --libs libngtcp2 \
 *       libngtcp2_crypto_ossl openssl)
 *
 * Run (needs a minimal config file -- see usage() -- and a cert/key
 * pair, e.g. `openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256
 * -nodes -keyout key.pem -out cert.pem -days 1 -subj /CN=localhost`):
 *
 *   master/quic/quic_echo_server <config-file> <port>
 *
 * Testing against ngtcp2's own example client needs one extra step:
 * its stock `osslclient` binary (examples/osslclient in a built
 * ngtcp2 checkout -- there's no binary literally named "client", that
 * name is only the source file) negotiates ALPN "h3" by default, so
 * it won't talk to this server at all -- ngtcp2's build only wires up
 * an OpenSSL-backed "hq-interop" client (examples/hq_client_proto_codec.cc)
 * if you also have wolfSSL installed (the `wsslhqclient` target).
 * Without wolfSSL, build one by hand instead, reusing the OpenSSL
 * objects `make osslclient` already built for everything except the
 * proto codec (from ngtcp2's examples/ directory, after its own
 * `./configure && make`):
 *
 *   CPPFLAGS="-D_GNU_SOURCE -include arpa/inet.h -include netinet/ip.h \
 *     -I../lib/includes -I../crypto/includes -I../third-party/urlparse \
 *     -DWITH_EXAMPLE_OSSL -DWITH_EXAMPLE_HQ_PROTO_CODEC"
 *   for f in client client_base debug util shared \
 *            tls_client_context_ossl tls_client_session_ossl \
 *            tls_session_base_ossl util_openssl hq_client_proto_codec; do
 *     g++ -std=gnu++23 -g -O2 $CPPFLAGS -c $f.cc -o hq-$f.o
 *   done
 *   libtool --mode=link g++ -std=gnu++23 -g -O2 -no-install \
 *     -o osslhqclient hq-*.o \
 *     ../lib/libngtcp2.la ../crypto/ossl/libngtcp2_crypto_ossl.la \
 *     ../third-party/liburlparse.la \
 *     $(pkg-config --libs openssl) -lev -lnghttp3
 *
 * (the -include flags paper over two headers util.cc/shared.cc need
 * that the normal autotools build supplies some other way -- without
 * them, inet_pton/IPTOS_ECN_MASK fail to compile.) Then:
 *
 *   examples/osslhqclient 127.0.0.1 <port> "https://127.0.0.1/hello" -q
 *
 * ("hello" comes back as the response body -- along with the
 * "GET /hello\r\n" request line the client itself sent, since the
 * server has no way to distinguish path from the rest of the request
 * line -- it just echoes every byte it received. The URI's scheme is
 * ignored by this ALPN, "https://" is just what the client's URI
 * parser accepts -- "hq-interop://..." fails to parse.)
 */

#include <config.h>

#include <errno.h>
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

#include "libconfig.h"
#include "ptrarray.h"
#include "tls.h"
#include "util.h"
#include "xmalloc.h"

#include "master/service.h"
#include "master/quic/quic_parse.h"
#include "imap/quic.h"

/* master/service.h declares this extern (service.c normally defines
 * and populates it via QUIC_HANDOFF_FD) -- we populate it ourselves,
 * playing master's part by hand. */
EXPORTED struct quic_handoff quic_handoff;

/* Every Cyrus binary supplies its own -- lib/xmalloc.h declares it,
 * nothing defines it. No recursion guard or cleanup to do here, this
 * being a single-process, single-connection-at-a-time tool. */
EXPORTED void fatal(const char *msg, int code)
{
    fprintf(stderr, "quic_echo_server: fatal: %s\n", msg);
    exit(code);
}

/* imap/tls.c is one translation unit for both the TCP and QUIC TLS
 * engines; linking it in for tls_init_serverengine_quic() pulls in
 * tls_init_serverengine()/tls_prune_sessions() too, even though we
 * never call them. They're normally satisfied by imap/global.c,
 * which we don't otherwise need -- these are real (if unexercised)
 * stand-ins rather than stubs, so nothing breaks if that ever stops
 * being true. */
EXPORTED const char *config_tls_sessions_db;

EXPORTED void saslprops_reset(struct saslprops_t *saslprops)
{
    buf_reset(&saslprops->iplocalport);
    buf_reset(&saslprops->ipremoteport);
    buf_reset(&saslprops->authid);
    saslprops->ssf = 0;
    saslprops->cbinding.name = NULL;
}

static struct tls_alpn_t echo_alpn_map[] = {
    { "hq-interop", NULL, NULL },
    { "",           NULL, NULL }
};

/* One pending or in-flight stream: the bytes received so far, and how
 * much of that we've already handed to get_output(). Nothing is ever
 * freed early the way HTTP/3's chunked body handling has to -- the
 * whole echo fits in memory for as long as the stream is open. */
struct echo_stream {
    int64_t id;
    struct buf data;
    size_t sent;
    bool fin_received;
};

/* struct h3_context's pattern, one file over: a struct quic_session
 * embedded first so a struct echo_context * and a struct
 * quic_session * cast to each other, plus whatever this app needs.
 * "live" tracks every stream still open, the same reason struct
 * h3_context needs open_txns -- ngtcp2_conn_del() (called from
 * quic_session_free(), after our session_free() hook runs) has no
 * documented guarantee it fires stream_closed() for streams still
 * open at teardown, so anything left in "live" when session_free()
 * runs must be freed there instead of leaking. */
struct echo_context {
    struct quic_session qs;
    ptrarray_t live;
};

static struct echo_stream *echo_stream_find(struct echo_context *ctx,
                                            int64_t stream_id)
{
    return (struct echo_stream *)
        ngtcp2_conn_get_stream_user_data(ctx->qs.qconn, stream_id);
}

static struct echo_stream *echo_stream_new(struct echo_context *ctx,
                                           int64_t stream_id)
{
    struct echo_stream *es = xzmalloc(sizeof(*es));

    es->id = stream_id;
    ngtcp2_conn_set_stream_user_data(ctx->qs.qconn, stream_id, es);
    ptrarray_append(&ctx->live, es);
    return es;
}

static void echo_stream_free(struct echo_context *ctx,
                             struct echo_stream *es)
{
    int idx = ptrarray_find(&ctx->live, es, 0);

    if (idx >= 0) ptrarray_remove(&ctx->live, idx);
    buf_free(&es->data);
    free(es);
}

static void echo_handshake_completed(struct quic_session *qs
                                     __attribute__((unused)))
{
    fprintf(stderr, "quic_echo_server: handshake completed\n");
}

static ngtcp2_ssize echo_recv_stream_data(struct quic_session *qs,
                                          int64_t stream_id,
                                          const uint8_t *data,
                                          size_t datalen, bool fin)
{
    struct echo_context *ctx = (struct echo_context *) qs;
    struct echo_stream *es = echo_stream_find(ctx, stream_id);

    if (!es) es = echo_stream_new(ctx, stream_id);

    if (datalen) buf_appendmap(&es->data, (const char *) data, datalen);
    if (fin) es->fin_received = true;

    return (ngtcp2_ssize) datalen;
}

static void echo_acked_stream_data(struct quic_session *qs
                                   __attribute__((unused)),
                                   int64_t stream_id __attribute__((unused)),
                                   uint64_t datalen __attribute__((unused)))
{
    /* Nothing to do -- unlike HTTP/3's chunked response bodies, the
     * whole echo stays in es->data until the stream closes, so an ack
     * never needs to free anything early. */
}

static void echo_stream_closed(struct quic_session *qs, int64_t stream_id,
                               uint64_t app_error_code
                               __attribute__((unused)))
{
    struct echo_context *ctx = (struct echo_context *) qs;
    struct echo_stream *es = echo_stream_find(ctx, stream_id);

    if (es) echo_stream_free(ctx, es);
}

static void echo_stream_reset(struct quic_session *qs, int64_t stream_id,
                              uint64_t app_error_code __attribute__((unused)))
{
    /* Leave cleanup to stream_closed(), which ngtcp2 still calls after
     * a reset -- just stop offering this stream's data via
     * get_output() in the meantime. */
    struct echo_context *ctx = (struct echo_context *) qs;
    struct echo_stream *es = echo_stream_find(ctx, stream_id);

    if (es) es->fin_received = false;
}

static int echo_io_ready(struct quic_session *qs __attribute__((unused)))
{
    return 0;
}

static ngtcp2_ssize echo_get_output(struct quic_session *qs,
                                    int64_t *pstream_id, int *pfin,
                                    ngtcp2_vec *vec, size_t veccnt
                                    __attribute__((unused)))
{
    struct echo_context *ctx = (struct echo_context *) qs;
    int i;

    for (i = 0; i < ptrarray_size(&ctx->live); i++) {
        struct echo_stream *es = ptrarray_nth(&ctx->live, i);

        if (es->fin_received && es->sent < buf_len(&es->data)) {
            vec[0].base = (uint8_t *) buf_base(&es->data) + es->sent;
            vec[0].len = buf_len(&es->data) - es->sent;
            *pstream_id = es->id;
            *pfin = 1;
            return 1;
        }
    }

    *pstream_id = -1;
    return 0;
}

static void echo_advance_output(struct quic_session *qs, int64_t stream_id,
                                size_t datalen)
{
    struct echo_context *ctx = (struct echo_context *) qs;
    struct echo_stream *es = echo_stream_find(ctx, stream_id);

    if (es) es->sent += datalen;
}

static void echo_block_output(struct quic_session *qs
                              __attribute__((unused)),
                              int64_t stream_id __attribute__((unused)))
{
    /* Nothing to do -- quic_flush_output() just asks get_output()
     * again on its own next pass; no per-stream state to update. */
}

static void echo_session_free(struct quic_session *qs)
{
    struct echo_context *ctx = (struct echo_context *) qs;
    struct echo_stream *es;

    while ((es = (struct echo_stream *) ptrarray_pop(&ctx->live))) {
        buf_free(&es->data);
        free(es);
    }
    ptrarray_fini(&ctx->live);
}

static const struct quic_app_ops echo_quic_app_ops = {
    .handshake_completed = echo_handshake_completed,
    .recv_stream_data    = echo_recv_stream_data,
    .acked_stream_data   = echo_acked_stream_data,
    .stream_closed       = echo_stream_closed,
    .stream_reset        = echo_stream_reset,
    .io_ready            = echo_io_ready,
    .get_output          = echo_get_output,
    .advance_output      = echo_advance_output,
    .block_output        = echo_block_output,
    .session_free        = echo_session_free,
};

static void usage(const char *prog)
{
    fprintf(stderr,
           "usage: %s <config-file> <port>\n\n"
           "config-file needs at least:\n"
           "    configdirectory: /some/writable/dir\n"
           "    tls_server_cert: /path/to/cert.pem\n"
           "    tls_server_key: /path/to/key.pem\n",
           prog);
}

/* One connection, start to finish: run quic_input()/quic_handle_expiry()
 * until qs->draining, the same shape as httpd.c's cmdloop drives
 * http3_input()/http3_idle() -- just a plain loop instead of an event
 * loop shared with a dozen other things. */
static void echo_serve_one(struct echo_context *ctx)
{
    while (!ctx->qs.draining) {
        struct pollfd pfd = { .fd = ctx->qs.fd, .events = POLLIN };
        unsigned long timeout_sec = quic_get_timeout(&ctx->qs);
        int rv = poll(&pfd, 1, (int) timeout_sec * 1000);

        if (rv < 0) {
            if (errno == EINTR) continue;
            fprintf(stderr, "quic_echo_server: poll: %s\n", strerror(errno));
            break;
        }

        if (rv == 0) {
            quic_handle_expiry(&ctx->qs);
        }
        else {
            const char *close_reason = NULL;

            if (quic_input(&ctx->qs, &close_reason)) {
                fprintf(stderr, "quic_echo_server: connection closing (%s)\n",
                       close_reason);
                break;
            }
        }
    }
}

int main(int argc, char **argv)
{
    SSL_CTX *ssl_ctx;
    struct quic_app app = { echo_alpn_map, &echo_quic_app_ops };
    int listenfd;
    struct sockaddr_in6 local = { .sin6_family = AF_INET6 };

    if (argc != 3) {
        usage(argv[0]);
        return 1;
    }

    config_read(argv[1], 0);

    if (tls_init_serverengine_quic(&ssl_ctx)) {
        fprintf(stderr, "quic_echo_server: tls_init_serverengine_quic failed "
               "(check tls_server_cert/tls_server_key)\n");
        return 1;
    }

    listenfd = socket(AF_INET6, SOCK_DGRAM, 0);
    if (listenfd < 0) {
        perror("socket");
        return 1;
    }
    local.sin6_port = htons((uint16_t) atoi(argv[2]));
    if (bind(listenfd, (struct sockaddr *) &local, sizeof(local))) {
        perror("bind");
        return 1;
    }

    fprintf(stderr, "quic_echo_server: listening on UDP port %s (ALPN "
           "\"hq-interop\")\n", argv[2]);

    for (;;) {
        uint8_t pktbuf[QUIC_PKT_BUFSIZE];
        struct sockaddr_storage peer, local_addr;
        socklen_t peerlen = sizeof(peer), local_addrlen = sizeof(local_addr);
        ssize_t n;
        struct quic_initial_cids cids;
        uint8_t my_scid[QUIC_EBPF_CIDLEN];
        struct sockaddr unspec = { .sa_family = AF_UNSPEC };
        struct echo_context ctx;

        n = recvfrom(listenfd, pktbuf, sizeof(pktbuf), 0,
                    (struct sockaddr *) &peer, &peerlen);
        if (n < 0) {
            if (errno == EINTR) continue;
            perror("recvfrom");
            break;
        }

        /* Mirrors master.c's quic_dispatch_connection(): not a valid
         * Initial packet, nothing to dispatch. */
        if (quic_parse_initial(pktbuf, (size_t) n, &cids)) continue;

        if (getsockname(listenfd, (struct sockaddr *) &local_addr,
                        &local_addrlen)) {
            perror("getsockname");
            continue;
        }

        RAND_bytes(my_scid, sizeof(my_scid));

        if (connect(listenfd, (struct sockaddr *) &peer, peerlen)) {
            perror("connect");
            continue;
        }

        memset(&quic_handoff, 0, sizeof(quic_handoff));
        memcpy(quic_handoff.scid, my_scid, sizeof(my_scid));
        memcpy(&quic_handoff.local_addr, &local_addr, local_addrlen);
        quic_handoff.local_addrlen = local_addrlen;
        memcpy(&quic_handoff.peer_addr, &peer, peerlen);
        quic_handoff.peer_addrlen = peerlen;
        quic_handoff.pktlen = (size_t) n;
        memcpy(quic_handoff.pkt, pktbuf, (size_t) n);

        memset(&ctx, 0, sizeof(ctx));

        if (quic_session_new(&ctx.qs, listenfd, ssl_ctx, &app)) {
            fprintf(stderr, "quic_echo_server: quic_session_new failed\n");
        }
        else {
            fprintf(stderr, "quic_echo_server: new connection\n");
            quic_process_datagram(&ctx.qs, ctx.qs.first_pkt,
                                  ctx.qs.first_pktlen);
            echo_serve_one(&ctx);
            quic_session_free(&ctx.qs);
            fprintf(stderr, "quic_echo_server: connection done\n");
        }

        /* Back to listening for the next peer. */
        connect(listenfd, &unspec, sizeof(unspec));
    }

    close(listenfd);
    return 0;
}
