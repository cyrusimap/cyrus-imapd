/* quic_echo_server.c - standalone QUIC echo server, exercising
 * imap/quic.c outside of Cyrus's own master-dispatch/httpd
 * machinery.
 *
 * Not part of the build -- ad hoc verification only, same spirit as
 * master/quic/test_quic_ebpf_steer.c. Handles one connection at a time
 * (no fork, no dispatch): read a datagram on the rendezvous socket,
 * treat it as a QUIC Initial packet the way master.c's
 * quic_dispatch_connection() would, then hand it to imap/quic.c's
 * session machinery like any application-protocol consumer would --
 * proving that imap/quic.c's transport layer works standalone, with
 * no application-protocol framing library linked in at all.
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
 *     imap/quic.c imap/tls.c \
 *     lib/libcyrus.la lib/libcyrus_min.la $(pkg-config --libs libngtcp2 \
 *       libngtcp2_crypto_ossl openssl)
 *
 * Run (needs a minimal config file -- see usage() -- and a cert/key
 * pair, e.g. `openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256
 * -nodes -keyout key.pem -out cert.pem -days 1 -subj /CN=localhost`):
 *
 *   master/quic/quic_echo_server <config-file> <port>
 *
 * Testing against ngtcp2's own example client needs an OpenSSL-backed
 * "hq-interop" client built from its examples/hq_client_proto_codec.cc
 * (ngtcp2's stock `osslclient` negotiates ALPN "h3" by default and
 * won't talk to this server); build one separately from ngtcp2's own
 * examples/ tree. */

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
#include "imap/quic.h"

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

/* Every Cyrus binary supplies its own -- lib/xmalloc.h declares it,
 * nothing defines it. No recursion guard or cleanup to do here, this
 * being a single-process, single-connection-at-a-time tool. */
EXPORTED void fatal(const char *msg, int code)
{
    fprintf(stderr, "quic_echo_server: fatal: %s\n", msg);
    exit(code);
}

/* imap/quic.c's quic_init_tls_ctx() builds on imap/tls.c's shared
 * server-context helpers; linking tls.c in for those pulls in
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
 * freed early the way a chunked-body application protocol has to --
 * the whole echo fits in memory for as long as the stream is open. */
struct echo_stream {
    int64_t id;
    struct buf data;
    size_t sent;
    bool fin_received;
};

/* quic.h's embedding pattern: a struct quic_session embedded first so
 * a struct echo_context * and a struct quic_session * cast to each
 * other, plus whatever this app needs. "live" tracks every stream
 * still open -- ngtcp2_conn_del() (called from quic_session_free(),
 * after our session_free() hook runs) has no documented guarantee it
 * fires stream_closed() for streams still open at teardown, so
 * anything left in "live" when session_free() runs must be freed
 * there instead of leaking. */
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
    /* Nothing to do -- unlike a chunked-body application protocol,
     * the whole echo stays in es->data until the stream closes, so an
     * ack never needs to free anything early. */
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

static int echo_unblock_output(struct quic_session *qs
                               __attribute__((unused)),
                               int64_t stream_id __attribute__((unused)))
{
    /* Nothing to do, as for echo_block_output() */
    return 0;
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
    .unblock_output      = echo_unblock_output,
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
 * until qs->draining -- just a plain loop instead of an event loop
 * shared with a dozen other things. */
static void echo_serve_one(struct echo_context *ctx)
{
    while (!ctx->qs.draining) {
        struct pollfd pfd = { .fd = ctx->qs.fd, .events = POLLIN };
        unsigned long timeout_usec = quic_get_timeout(&ctx->qs);
        int rv = poll(&pfd, 1, (int) ((timeout_usec + 999) / 1000));

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

    if (quic_init_tls_ctx(&ssl_ctx, false)) {
        fprintf(stderr, "quic_echo_server: quic_init_tls_ctx failed "
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
            uint8_t cid_pool[QUIC_CID_POOL_SIZE][QUIC_CIDLEN];
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
        if (ngtcp2_accept(NULL, pktbuf, (size_t) n)) continue;

        if (getsockname(listenfd, (struct sockaddr *) &local_addr,
                        &local_addrlen)) {
            perror("getsockname");
            continue;
        }

        RAND_bytes(cid_pool[0], sizeof(cid_pool));

        if (connect(listenfd, (struct sockaddr *) &peer, peerlen)) {
            perror("connect");
            continue;
        }

        memset(&quic_handoff, 0, sizeof(quic_handoff));
        memcpy(quic_handoff.cids, cid_pool, sizeof(cid_pool));
        quic_handoff.ncids = QUIC_CID_POOL_SIZE;
        memcpy(&quic_handoff.local_addr, &local_addr, local_addrlen);
        quic_handoff.local_addrlen = local_addrlen;
        memcpy(&quic_handoff.peer_addr, &peer, peerlen);
        quic_handoff.peer_addrlen = peerlen;
        quic_handoff.pktlen = (size_t) n;
        memcpy(quic_handoff.pkt, pktbuf, (size_t) n);

        memset(&ctx, 0, sizeof(ctx));

        if (quic_session_new(&ctx.qs, listenfd, ssl_ctx, &app, 300)) {
            fprintf(stderr, "quic_echo_server: quic_session_new failed\n");
        }
        else {
            fprintf(stderr, "quic_echo_server: new connection\n");
            quic_process_datagram(&ctx.qs, ctx.qs.first_pkt,
                                  ctx.qs.first_pktlen, &ctx.qs.peer_addr,
                                  ctx.qs.peer_addrlen);
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
