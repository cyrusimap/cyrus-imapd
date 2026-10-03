/* http_h3.c - HTTP/3 (QUIC) support functions */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>
#include <sysexits.h>

#include "httpd.h"
#include "http_h3.h"

#if defined(HAVE_NGHTTP3) && defined(WITH_QUIC)

#include <inttypes.h>
#include <syslog.h>

#include <openssl/ssl.h>

#include <nghttp3/nghttp3.h>

#include "global.h"
#include "http_ws.h"
#include "quic.h"
#include "retry.h"
#include "xmalloc.h"

/* generated headers are not necessarily in current directory */
#include "imap/http_err.h"

#define H3_MAX_HEADERS  100

/* A response body chunk handed to nghttp3 via h3_data_source_read_cb(),
 * awaiting h3_acked_stream_data_cb()'s notice that the peer acked it.
 * nghttp3 treats read_data callback buffers as caller-owned
 * (NGHTTP3_BUF_TYPE_ALIEN) and may resend the same pointer to ngtcp2
 * for retransmission any time before it's acked -- freeing it earlier
 * is a use-after-free that only shows up on real packet loss (e.g. via
 * http3_idle()'s PTO handling). */
struct h3_sent_chunk {
    struct buf buf;
    unsigned acked;
};

/* HTTP/3 stream context (one per request) */
struct h3_stream {
    int64_t id;
    size_t num_resp_hdrs;
    nghttp3_nv resp_hdrs[H3_MAX_HEADERS];
    bool chunk_queued;          /* queued for h3_data_source_read_cb */

    /* Owned copy of what's queued for h3_data_source_read_cb(), not yet
     * handed to a struct h3_sent_chunk. quic_flush_output() is
     * flow-control-bounded and may drain nothing, so h3_resp_body_chunk()
     * can run again before it does: this accumulates across calls
     * (buf_appendmap(), never buf_setmap()). Overwriting would silently
     * drop whatever hadn't been read out yet. */
    struct buf pending_body;
    bool pending_last_chunk;
    ptrarray_t sent_chunks;     /* struct h3_sent_chunk *, FIFO, awaiting ack */
};

/* HTTP/3 session context -- one per connection, embedding the generic
 * QUIC transport session (imap/quic.h) as its first member so a
 * struct h3_context * and a struct quic_session * are interchangeable
 * via a cast. A worker only ever serves one QUIC connection at a time
 * (see http3_start_session()), so there's no per-connection copy of
 * auth/session state here: the usual httpd_saslconn/httpd_userid/etc.
 * globals, set up once per connection by service_main(), are already
 * correct for "the" connection. */
struct h3_context {
    struct quic_session qs;     /* MUST be first member */

    nghttp3_conn *h3conn;

    int64_t ctrl_stream_id;
    int64_t qenc_stream_id;
    int64_t qdec_stream_id;

    /* Every struct transaction_t from h3_begin_headers_cb() still live
     * (h3_stream_close_cb() hasn't freed it). Needed because
     * nghttp3_conn_del() frees its own per-stream state but doesn't
     * invoke .stream_close for streams still open at deletion time --
     * any stream still open at teardown (idle timeout, abrupt reset,
     * mid-connection fatal()) would otherwise leak its transaction_t.
     * h3_session_ops_free() walks this to free what's left before
     * nghttp3_conn_del() runs. */
    ptrarray_t open_txns;

    /* WebSocket streams open, which put the connection under
     * websocket_timeout instead of httptimeout (see h3_idle_deadline()) */
    unsigned ws_streams;
};

/* websocket_timeout, in seconds */
static long h3_ws_timeout;

/* QUIC idle timeout when neither httptimeout nor websocket_timeout sets
 * one, in seconds */
#define H3_MIN_TRANSPORT_IDLE (300)

/* When the connection's inactivity timeout expires, in quic_now() time,
 * or 0 for never: httptimeout, or websocket_timeout while a WebSocket is
 * open, the same switch HTTP/1.1 and HTTP/2 make */
static ngtcp2_tstamp h3_idle_deadline(const struct h3_context *ctx)
{
    unsigned long idle = ctx->ws_streams ? h3_ws_timeout : httpd_timeout;

    return idle ? ctx->qs.last_input + idle * NGTCP2_SECONDS : 0;
}

static struct tls_alpn_t h3_alpn_map[] = {
    { "h3", NULL, NULL },
    { "", NULL, NULL }
};

/*
 * struct quic_app_ops implementation -- see imap/quic.h. Each of
 * these bridges one ngtcp2 event (relayed through imap/quic.c) into
 * HTTP/3 handling.
 */

static void h3_handshake_completed(struct quic_session *qs)
{
    int bits = SSL_get_cipher_bits(qs->ssl, NULL);

    xsyslog_ev(LOG_DEBUG, "http3.handshake.completed");

    saslprops.ssf = bits > 0 ? (unsigned) bits : 1;
    if (saslprops_set_tls(&saslprops, httpd_saslconn) != SASL_OK) {
        xsyslog_ev(LOG_NOTICE, "http3.saslprops.failed");
    }
}

static ngtcp2_ssize h3_recv_stream_data(struct quic_session *qs,
                                        int64_t stream_id,
                                        const uint8_t *data, size_t datalen,
                                        bool fin)
{
    struct h3_context *ctx = (struct h3_context *) qs;
    nghttp3_ssize nconsumed;

    if (!ctx->h3conn) return 0;

    nconsumed = nghttp3_conn_read_stream2(ctx->h3conn, stream_id,
                                          data, datalen, fin, quic_now());
    if (nconsumed < 0) {
        xsyslog_ev(LOG_ERR, "http3.stream.read_failed",
                   lf_s("error", nghttp3_strerror((int) nconsumed)));
        return -1;
    }

    return nconsumed;
}

static void h3_acked_stream_data(struct quic_session *qs, int64_t stream_id,
                                 uint64_t datalen)
{
    struct h3_context *ctx = (struct h3_context *) qs;

    if (ctx->h3conn) {
        nghttp3_conn_add_ack_offset(ctx->h3conn, stream_id, datalen);
    }
}

static void h3_stream_closed(struct quic_session *qs, int64_t stream_id,
                             uint64_t app_error_code)
{
    struct h3_context *ctx = (struct h3_context *) qs;

    if (ctx->h3conn) {
        nghttp3_conn_close_stream(ctx->h3conn, stream_id, app_error_code);
    }
}

static void h3_stream_reset(struct quic_session *qs, int64_t stream_id,
                            uint64_t app_error_code __attribute__((unused)))
{
    struct h3_context *ctx = (struct h3_context *) qs;

    if (ctx->h3conn) nghttp3_conn_shutdown_stream_read(ctx->h3conn, stream_id);
}

/* Open the HTTP/3 control and QPACK encoder/decoder streams and bind
 * them to the nghttp3 session. Peer transport-parameter uni-stream
 * credit may not exist yet after just one packet (a large ClientHello
 * can span multiple Initial packets), so this waits for credit rather
 * than failing, retried on every io_ready() call.
 * Idempotent: stream id 0 is never a valid server-initiated
 * uni-stream id, so it doubles as the "not yet done" sentinel. */
static int h3_io_ready(struct quic_session *qs)
{
    struct h3_context *ctx = (struct h3_context *) qs;
    int rv;

    if (ctx->ctrl_stream_id) return 0;
    if (ngtcp2_conn_get_streams_uni_left(qs->qconn) < 3) return 0;

    if ((rv = ngtcp2_conn_open_uni_stream(qs->qconn,
                                          &ctx->ctrl_stream_id, NULL)) ||
        (rv = ngtcp2_conn_open_uni_stream(qs->qconn,
                                          &ctx->qenc_stream_id, NULL)) ||
        (rv = ngtcp2_conn_open_uni_stream(qs->qconn,
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

/* nghttp3_vec and ngtcp2_vec have identical layout (a base pointer and
 * a length) -- casting the array wholesale, rather than copying, is
 * relied on here and in quic_flush_output(). */
static ngtcp2_ssize h3_get_output(struct quic_session *qs,
                                  int64_t *pstream_id, int *pfin,
                                  ngtcp2_vec *vec, size_t veccnt)
{
    struct h3_context *ctx = (struct h3_context *) qs;
    nghttp3_ssize n;

    if (!ctx->h3conn) return 0;

    n = nghttp3_conn_writev_stream(ctx->h3conn, pstream_id, pfin,
                                   (nghttp3_vec *) vec, veccnt);
    if (n < 0) {
        xsyslog_ev(LOG_ERR, "http3.stream.writev_failed",
                   lf_s("error", nghttp3_strerror((int) n)));
        return -1;
    }
    return n;
}

static void h3_advance_output(struct quic_session *qs, int64_t stream_id,
                              size_t datalen)
{
    struct h3_context *ctx = (struct h3_context *) qs;

    if (ctx->h3conn) {
        nghttp3_conn_add_write_offset(ctx->h3conn, stream_id, datalen);
    }
}

static void h3_block_output(struct quic_session *qs, int64_t stream_id)
{
    struct h3_context *ctx = (struct h3_context *) qs;

    if (ctx->h3conn) nghttp3_conn_block_stream(ctx->h3conn, stream_id);
}

static int h3_unblock_output(struct quic_session *qs, int64_t stream_id)
{
    struct h3_context *ctx = (struct h3_context *) qs;

    if (!ctx->h3conn) return 0;
    return nghttp3_conn_unblock_stream(ctx->h3conn, stream_id);
}

static void h3_session_ops_free(struct quic_session *qs)
{
    struct h3_context *ctx = (struct h3_context *) qs;
    struct transaction_t *txn;

    /* This is what open_txns exists for (see struct h3_context) --
     * order doesn't matter, nghttp3_conn_del() below hasn't run yet. */
    while ((txn = (struct transaction_t *) ptrarray_pop(&ctx->open_txns))) {
        transaction_free(txn);
        free(txn);
    }
    ptrarray_fini(&ctx->open_txns);

    if (ctx->h3conn) nghttp3_conn_del(ctx->h3conn);
}

static const struct quic_app_ops h3_quic_app_ops = {
    .handshake_completed = h3_handshake_completed,
    .recv_stream_data    = h3_recv_stream_data,
    .acked_stream_data   = h3_acked_stream_data,
    .stream_closed       = h3_stream_closed,
    .stream_reset        = h3_stream_reset,
    .io_ready            = h3_io_ready,
    .get_output          = h3_get_output,
    .advance_output      = h3_advance_output,
    .block_output        = h3_block_output,
    .unblock_output      = h3_unblock_output,
    .session_free        = h3_session_ops_free,
};

static struct quic_app h3_quic_app = { h3_alpn_map, &h3_quic_app_ops };

/*
 * nghttp3 (HTTP/3 framing) callbacks -- these bridge into httpd.c's
 * existing, transport-agnostic request-processing pipeline. Their
 * conn_user_data is the struct http_connection (set once in
 * nghttp3_conn_server_new(), see http3_start_session()).
 */

static void h3_stream_free(struct transaction_t *txn)
{
    if (txn) {
        struct h3_stream *strm = (struct h3_stream *) txn->strm_ctx;

        if (strm) {
            struct h3_sent_chunk *chunk;

            for (size_t i = 0; i < strm->num_resp_hdrs; i++) {
                free((void *) strm->resp_hdrs[i].value);
            }
            buf_free(&strm->pending_body);

            /* Stream is going away -- no more acks are coming for
             * whatever's still outstanding, so free it now. */
            while ((chunk = (struct h3_sent_chunk *)
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

static int h3_begin_headers_cb(nghttp3_conn *h3conn __attribute__((unused)),
                               int64_t stream_id, void *conn_user_data,
                               void *stream_user_data __attribute__((unused)))
{
    struct http_connection *conn = (struct http_connection *) conn_user_data;
    struct h3_context *ctx = (struct h3_context *) conn->sess_ctx;
    struct h3_stream *strm;
    struct transaction_t *txn;
    hdrcache_t hdrs = spool_new_hdrcache();

    if (!hdrs) return NGHTTP3_ERR_CALLBACK_FAILURE;

    txn = xzmalloc(sizeof(struct transaction_t));
    txn->conn = conn;
    txn->meth = METH_UNKNOWN;
    txn->flags.ver = VER_3;
    txn->flags.vary = VARY_AE;
    txn->flags.early = quic_in_early_data(&ctx->qs);
    txn->req_line.ver = HTTP3_VERSION;
    txn->req_hdrs = hdrs;

    if (config_getswitch(IMAPOPT_HTTPALLOWCOMPRESS)) {
        zlib_init(txn);
        brotli_init(txn);
        zstd_init(txn);
    }

    strm = xzmalloc(sizeof(struct h3_stream));
    strm->id = stream_id;
    txn->strm_ctx = strm;
    ptrarray_add(&txn->done_callbacks, &h3_stream_free);

    uint32_t version = ngtcp2_conn_get_negotiated_version(ctx->qs.qconn);
    switch (version) {
    case NGTCP2_PROTO_VER_V1:
        buf_setcstr(&txn->buf, "v1");
        break;
    case NGTCP2_PROTO_VER_V2:
        buf_setcstr(&txn->buf, "v2");
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

static int h3_recv_header_cb(nghttp3_conn *h3conn __attribute__((unused)),
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

static int h3_end_headers_cb(nghttp3_conn *h3conn __attribute__((unused)),
                             int64_t stream_id __attribute__((unused)),
                             int fin __attribute__((unused)),
                             void *conn_user_data,
                             void *stream_user_data)
{
    struct transaction_t *txn = (struct transaction_t *) stream_user_data;
    struct http_connection *conn = (struct http_connection *) conn_user_data;
    struct h3_context *ctx = (struct h3_context *) conn->sess_ctx;
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
         * h3_recv_data_cb() forwards to ws_input() once txn->ws_ctx
         * is set below. */
        ret = process_request(txn);
        if (ret) error_response(ret, txn);
        else if (txn->ws_ctx) ctx->ws_streams++;
    }

    return 0;
}

static int h3_recv_data_cb(nghttp3_conn *h3conn __attribute__((unused)),
                           int64_t stream_id,
                           const uint8_t *data, size_t datalen,
                           void *conn_user_data,
                           void *stream_user_data)
{
    struct transaction_t *txn = (struct transaction_t *) stream_user_data;
    struct http_connection *conn = (struct http_connection *) conn_user_data;
    struct h3_context *ctx = (struct h3_context *) conn->sess_ctx;

    /* DATA payload isn't in what nghttp3_conn_read_stream2() reports as
     * consumed.  It's copied or dropped right here, so hand the credit
     * back now, or a body bigger than the stream window stalls. */
    ngtcp2_conn_extend_max_stream_offset(ctx->qs.qconn, stream_id, datalen);
    ngtcp2_conn_extend_max_offset(ctx->qs.qconn, datalen);

    if (!txn) return 0;
    if (txn->req_body.flags & BODY_DISCARD) return 0;

    if (datalen) {
        /* Flow control bounds only what's in flight, not the whole body.
         * A WebSocket's messages are limited by ws_input() instead. */
        if (!txn->ws_ctx && txn->req_body.max &&
            datalen > txn->req_body.max - txn->req_body.len) {
            txn->req_body.flags |= BODY_DISCARD;
            error_response(HTTP_CONTENT_TOO_LARGE, txn);

            /* Ask the client to stop sending the rest (RFC 9114 4.1.2) */
            nghttp3_conn_shutdown_stream_read(ctx->h3conn, stream_id);
            ngtcp2_conn_shutdown_stream_read(ctx->qs.qconn, 0, stream_id,
                                             NGHTTP3_H3_NO_ERROR);
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

    if (txn->ws_ctx) {
        /* WebSocket over HTTP/3 input. */
        ws_input(txn);

        if (txn->flags.conn & CONN_CLOSE) {
            /* Abort the stream so it doesn't hang around. Cascades
             * into the existing ngtcp2 stream_close_cb ->
             * nghttp3_conn_close_stream() teardown once processed. */
            ngtcp2_conn_shutdown_stream(ctx->qs.qconn, 0, stream_id,
                                        NGHTTP3_H3_NO_ERROR);
        }
    }

    return 0;
}

static int h3_end_stream_cb(nghttp3_conn *h3conn __attribute__((unused)),
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

static int h3_stream_close_cb(nghttp3_conn *h3conn __attribute__((unused)),
                              int64_t stream_id __attribute__((unused)),
                              uint64_t app_error_code __attribute__((unused)),
                              void *conn_user_data,
                              void *stream_user_data)
{
    struct transaction_t *txn = (struct transaction_t *) stream_user_data;

    if (txn) {
        struct http_connection *conn =
            (struct http_connection *) conn_user_data;
        struct h3_context *ctx = (struct h3_context *) conn->sess_ctx;
        int idx = ptrarray_find(&ctx->open_txns, txn, 0);

        if (idx >= 0) ptrarray_remove(&ctx->open_txns, idx);
        if (txn->ws_ctx) ctx->ws_streams--;

        transaction_free(txn);
        free(txn);
    }

    return 0;
}

/* nghttp3.h's nghttp3_read_data_callback contract: data offered by
 * h3_data_source_read_cb() is caller-owned and "must [be] retain[ed]
 * until they are safe to free" -- signaled by this callback. |datalen|
 * is the number of bytes newly acked (not cumulative), in stream
 * order, so it always lands at the front of sent_chunks first. */
static int h3_acked_stream_data_cb(nghttp3_conn *h3conn __attribute__((unused)),
                                   int64_t stream_id __attribute__((unused)),
                                   uint64_t datalen,
                                   void *conn_user_data __attribute__((unused)),
                                   void *stream_user_data)
{
    struct transaction_t *txn = (struct transaction_t *) stream_user_data;
    struct h3_stream *strm = (struct h3_stream *) txn->strm_ctx;

    while (datalen && ptrarray_size(&strm->sent_chunks)) {
        struct h3_sent_chunk *chunk =
            (struct h3_sent_chunk *) ptrarray_nth(&strm->sent_chunks, 0);
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

static const nghttp3_callbacks h3_nghttp3_callbacks = {
    .stream_close      = h3_stream_close_cb,
    .recv_data         = h3_recv_data_cb,
    .begin_headers     = h3_begin_headers_cb,
    .recv_header       = h3_recv_header_cb,
    .end_headers       = h3_end_headers_cb,
    .end_stream        = h3_end_stream_cb,
    .acked_stream_data = h3_acked_stream_data_cb,
};

/*
 * Response generation vtable: begin_resp_headers/add_resp_header/
 * end_resp_headers/resp_body_chunk, against nghttp3's nv/data-reader
 * API.
 */

static void h3_begin_resp_headers(struct transaction_t *txn, long code)
{
    struct h3_stream *strm = (struct h3_stream *) txn->strm_ctx;

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

static void h3_add_resp_header(struct transaction_t *txn,
                               const char *name, struct buf *value)
{
    struct h3_stream *strm = (struct h3_stream *) txn->strm_ctx;

    if (strm->num_resp_hdrs >= H3_MAX_HEADERS) {
        buf_free(value);
        return;
    }

    nghttp3_nv *nv = &strm->resp_hdrs[strm->num_resp_hdrs];

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

static nghttp3_ssize h3_data_source_read_cb(
    nghttp3_conn *h3conn __attribute__((unused)),
    int64_t stream_id __attribute__((unused)),
    nghttp3_vec *vec, size_t veccnt, uint32_t *pflags,
    void *conn_user_data __attribute__((unused)),
    void *stream_user_data)
{
    /* stream_user_data is the stream's struct transaction_t (set once
     * in h3_begin_headers_cb and never touched again) -- the pending
     * chunk lives in its h3_stream, NOT as its own stream_user_data, so
     * stream_close/etc. can keep finding the txn they expect. */
    struct transaction_t *txn = (struct transaction_t *) stream_user_data;
    struct h3_stream *strm = (struct h3_stream *) txn->strm_ctx;
    unsigned n;

    if (veccnt < 1) return NGHTTP3_ERR_NOMEM;

    if (!strm->chunk_queued) {
        /* nghttp3_conn_writev_stream() gathers up to veccnt entries
         * per call, so it routinely asks again immediately after
         * draining what's queued -- not just on the resume-race path.
         * Its read_data contract requires NGHTTP3_ERR_WOULDBLOCK here
         * unless this is EOF, or nghttp3_stream_write_data()'s
         * assertion (datalen || flags & NGHTTP3_DATA_FLAG_EOF) aborts
         * the process; nghttp3_conn_resume_stream() in
         * h3_resp_body_chunk() covers the resume-when-ready half. */
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

    /* Can't free this here -- see struct h3_sent_chunk's comment.
     * Ownership moves to sent_chunks (via buf_move(), no copy);
     * h3_acked_stream_data_cb() frees it once acked, h3_stream_free()
     * frees it if the stream closes first. */
    struct h3_sent_chunk *chunk = xzmalloc(sizeof(*chunk));
    buf_move(&chunk->buf, &strm->pending_body);

    vec[0].base = (uint8_t *) buf_base(&chunk->buf);
    vec[0].len = n;

    ptrarray_append(&strm->sent_chunks, chunk);

    return 1;
}

static int h3_end_resp_headers(struct transaction_t *txn, long code)
{
    struct h3_context *ctx = (struct h3_context *) txn->conn->sess_ctx;
    struct h3_stream *strm = (struct h3_stream *) txn->strm_ctx;
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

    default: {
        /* nghttp3 can't attach a data reader to an already-submitted
         * response, so a response with a body gets its reader now.
         * Submitting here rather than at the first body chunk also sends
         * the headers of a response whose body may not start for a while,
         * e.g. a WebSocket bootstrap (RFC 9220). */
        nghttp3_data_reader dr = { .read_data = h3_data_source_read_cb };
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

static int h3_resp_body_chunk(struct transaction_t *txn,
                              const char *data, unsigned datalen,
                              int last_chunk, MD5_CTX *md5ctx)
{
    static unsigned char md5[MD5_DIGEST_LENGTH];
    struct h3_context *ctx = (struct h3_context *) txn->conn->sess_ctx;
    struct h3_stream *strm = (struct h3_stream *) txn->strm_ctx;

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
     * replace -- see struct h3_stream's pending_body comment. */
    if (datalen) buf_appendmap(&strm->pending_body, data, datalen);
    strm->pending_last_chunk = last_chunk;
    strm->chunk_queued = true;
    nghttp3_conn_resume_stream(ctx->h3conn, strm->id);
    quic_flush_output(&ctx->qs);

    if (last_chunk && (txn->flags.trailer & ~TRAILER_PROXY)) {
        h3_begin_resp_headers(txn, 0);
        if (txn->flags.trailer & TRAILER_CMD5) content_md5_hdr(txn, md5);
        if ((txn->flags.trailer & TRAILER_CTAG) && txn->resp_body.ctag) {
            simple_hdr(txn, "CTag", "%s", txn->resp_body.ctag);
        }
        h3_end_resp_headers(txn, 0);
    }

    return 0;
}

/*
 * Session lifecycle
 */

static void h3_session_free(struct http_connection *conn)
{
    struct h3_context *ctx = (struct h3_context *) conn->sess_ctx;

    if (!ctx) return;

    quic_session_free(&ctx->qs);
    free(ctx);

    conn->sess_ctx = NULL;
    conn->tls_ctx = NULL;
}

static void h3_session_done(struct http_connection *conn)
{
    /* Safety net for abnormal termination -- h3_session_free() normally
     * already ran via conn->reset_callbacks at cmdloop()'s natural end
     * (sess_ctx is NULL and this is a no-op). No graceful
     * CONNECTION_CLOSE first: the peer just sees silence and falls
     * back to its own idle timeout. */
    h3_session_free(conn);
}

HIDDEN void http3_init(struct http_connection *conn, SSL_CTX **ssl_ctx,
                       struct buf *serverinfo)
{
    buf_printf(serverinfo, " Nghttp3/%s Ngtcp2/%s",
               NGHTTP3_VERSION, NGTCP2_VERSION);

    if (quic_init_tls_ctx(ssl_ctx, config_getswitch(IMAPOPT_HTTP_ALLOW_0RTT))) {
        fatal("http3: error initializing QUIC-capable TLS context",
              EX_SOFTWARE);
    }

    ptrarray_add(&conn->shutdown_callbacks, &h3_session_done);
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
    struct h3_context *ctx;
    nghttp3_settings h3settings;

    if (conn->sess_ctx) return 0;

    ctx = xzmalloc(sizeof(struct h3_context));

    h3_ws_timeout =
        ws_enabled ? config_getduration(IMAPOPT_WEBSOCKET_TIMEOUT) : 0;
    if (h3_ws_timeout < 0) h3_ws_timeout = 0;

    /* h3_idle_deadline() times the connection out itself, with a
     * CONNECTION_CLOSE, so QUIC's own idle timer, which just goes quiet,
     * runs a little longer.  Without either timeout it still needs one:
     * unlike TCP, QUIC has no keepalive to notice a client that vanished. */
    unsigned long transport_idle = MAX(httpd_timeout, h3_ws_timeout);
    transport_idle =
        transport_idle ? transport_idle + 2 : H3_MIN_TRANSPORT_IDLE;

    if (quic_session_new(&ctx->qs, conn->pin->fd, ssl_ctx, &h3_quic_app,
                         transport_idle)) {
        free(ctx);
        return -1;
    }

    nghttp3_settings_default(&h3settings);
    /* Bootstrapping WebSockets over HTTP/3 (RFC 9220). */
    h3settings.enable_connect_protocol = ws_enabled;
    if (nghttp3_conn_server_new(&ctx->h3conn, &h3_nghttp3_callbacks,
                                &h3settings, NULL, conn)) {
        xsyslog_ev(LOG_ERR, "http3.h3conn.create_failed");
        quic_session_free(&ctx->qs);
        free(ctx);
        return -1;
    }

    conn->tls_ctx = ctx->qs.ssl;
    conn->sess_ctx = ctx;
    conn->begin_resp_headers = &h3_begin_resp_headers;
    conn->add_resp_header = &h3_add_resp_header;
    conn->end_resp_headers = &h3_end_resp_headers;
    conn->resp_body_chunk = &h3_resp_body_chunk;

    ptrarray_add(&conn->reset_callbacks, &h3_session_free);

    /* h3 never touches conn->pin/pout for the actual QUIC datagrams
     * (see quic_flush_output()/quic_input(), which use the session's
     * own fds directly) -- nothing there for the prot layer to log. */
    prot_setlog(conn->pin, PROT_NO_FD);
    prot_setlog(conn->pout, PROT_NO_FD);

    quic_process_datagram(&ctx->qs, ctx->qs.first_pkt, ctx->qs.first_pktlen,
                          &ctx->qs.peer_addr, ctx->qs.peer_addrlen);

    return 0;
}

HIDDEN void http3_input(struct http_connection *conn)
{
    struct h3_context *ctx = (struct h3_context *) conn->sess_ctx;
    const char *close_reason;

    if (quic_input(&ctx->qs, &close_reason)) {
        conn->close_str = close_reason;
        conn->close = 1;
    }
}

HIDDEN unsigned long http3_get_timeout(struct http_connection *conn)
{
    struct h3_context *ctx = (struct h3_context *) conn->sess_ctx;
    unsigned long timeout;
    ngtcp2_tstamp deadline, now;

    if (!ctx) return 0;

    timeout = quic_get_timeout(&ctx->qs);

    deadline = h3_idle_deadline(ctx);
    if (deadline) {
        unsigned long idle = 1;

        now = quic_now();
        if (deadline > now) {
            idle = (deadline - now + NGTCP2_MICROSECONDS - 1) /
                   NGTCP2_MICROSECONDS;
        }
        if (idle < timeout) timeout = idle;
    }

    return timeout;
}

HIDDEN bool http3_traffic(struct http_connection *conn,
                          uint64_t *bytes_in, uint64_t *bytes_out)
{
    struct h3_context *ctx = (struct h3_context *) conn->sess_ctx;

    if (!ctx) return false;

    quic_traffic(&ctx->qs, bytes_in, bytes_out);
    return true;
}

HIDDEN void http3_idle(struct http_connection *conn)
{
    struct h3_context *ctx = (struct h3_context *) conn->sess_ctx;

    if (!ctx) return;

    quic_handle_expiry(&ctx->qs);

    if (ctx->qs.draining) {
        conn->close_str = "QUIC idle timeout";
        conn->close = 1;
    }
    else {
        ngtcp2_tstamp deadline = h3_idle_deadline(ctx);

        if (deadline && quic_now() >= deadline) {
            quic_close(&ctx->qs, NGHTTP3_H3_NO_ERROR);
            conn->close_str = "HTTP/3 idle timeout";
            conn->close = 1;
        }
    }
}

#else /* !(HAVE_NGHTTP3 && WITH_QUIC) */

HIDDEN void http3_init(struct http_connection *conn __attribute__((unused)),
                       SSL_CTX **ssl_ctx __attribute__((unused)),
                       struct buf *serverinfo __attribute__((unused)))
{
    fatal("HTTP/3 requested, but built without nghttp3", EX_SOFTWARE);
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

#endif /* HAVE_NGHTTP3 && WITH_QUIC */
