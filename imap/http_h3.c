/* http_h3.c - HTTP/3 support functions
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
#include "http_h3.h"
#include "http_ws.h"
#include "quic.h"
#include "retry.h"

/* generated headers are not necessarily in current directory */
#include "imap/http_err.h"

#ifdef WITH_HTTP3

#include <nghttp3/nghttp3.h>

#define QUIC_CTX(conn)  (conn->tls_ctx)

#define HTTP3_MAX_HEADERS  100

/* HTTP/3 stream context */
struct http3_stream {
    int64_t id;                         /* Stream ID */
    size_t num_resp_hdrs;               /* Number of response headers */
    nghttp3_nv resp_hdrs[HTTP3_MAX_HEADERS]; /* Array of response headers */

    ptrarray_t body_chunks;             /* Array of body chunks (buffers) */
    int next_chunk;                     /* Next chunk to send */
    unsigned blocked : 1;               /* Stream is blocked (no body chunks) */

    unsigned char md5[MD5_DIGEST_LENGTH];  /* MD5 of response body (trailer) */
};

static int acked_stream_data_cb(nghttp3_conn *conn __attribute__((unused)),
                                int64_t stream_id,
                                size_t datalen,
                                void *conn_user_data __attribute__((unused)),
                                void *stream_user_data __attribute__((unused)))
{
    syslog(LOG_DEBUG, "acked_stream_data(id=%ld): %lu", stream_id, datalen);

    return 0;
}

static int stream_close_cb(nghttp3_conn *conn, int64_t stream_id,
                           uint64_t app_error_code,
                           void *conn_user_data __attribute__((unused)),
                           void *stream_user_data)
{
    struct transaction_t *txn = stream_user_data;

    syslog(LOG_DEBUG, "H3 stream_close(id=%ld): %lu", stream_id, app_error_code);

    if (txn) {
        /* Memory cleanup */
        nghttp3_conn_set_stream_user_data(conn, stream_id, NULL);
        transaction_free(txn);
        free(txn);
    }

    return 0;
}

static int recv_data_cb(nghttp3_conn *conn __attribute__((unused)),
                        int64_t stream_id, const uint8_t *data, size_t datalen,
                        void *conn_user_data __attribute__((unused)),
                        void *stream_user_data)
{
    struct transaction_t *txn = stream_user_data;

    if (!txn) return 0;

    syslog(LOG_DEBUG, "H3 recv_data(id=%ld, len=%zu, txnflags=%#x)",
           stream_id, datalen, txn->req_body.flags);

    if (txn->req_body.flags & BODY_DISCARD) return 0;

    if (datalen) {
        txn->req_body.framing = FRAMING_HTTP3;
        txn->req_body.len += datalen;
        buf_appendmap(&txn->req_body.payload, (const char *) data, datalen);
    }

    return 0;
}

static void stream_done(struct transaction_t *txn)
{
    if (txn) {
        struct http3_stream *strm = txn->strm_ctx;

        if (strm) {
            int i;

            syslog(LOG_DEBUG, "H3 stream_done(%ld)", strm->id);

            for (i = 0; i < HTTP3_MAX_HEADERS; i++) {
                free(strm->resp_hdrs[i].value);
            }
            for (i = 0; i < ptrarray_size(&strm->body_chunks); i++) {
                struct buf *buf = ptrarray_nth(&strm->body_chunks, i);
                buf_destroy(buf);
            }
            ptrarray_fini(&strm->body_chunks);
            free(strm);
        }

        txn->strm_ctx = NULL;
    }
}

static int begin_headers_cb(nghttp3_conn *conn, int64_t stream_id,
                            void *conn_user_data,
                            void *stream_user_data __attribute__((unused)))
{
    syslog(LOG_DEBUG, "H3 begin_headers(%ld)", stream_id);

    struct transaction_t *txn = xzmalloc(sizeof(struct transaction_t));

    txn->conn = (struct http_connection *) conn_user_data;
    txn->meth = METH_UNKNOWN;
    txn->flags.ver = VER_3;
    txn->flags.vary = VARY_AE;
    txn->req_line.ver = HTTP3_VERSION;

    txn->conn->clienthost = quic_get_clienthost(QUIC_CTX(txn->conn));

    if (config_getswitch(IMAPOPT_HTTPALLOWCOMPRESS)) {
        zlib_init(txn);
        brotli_init(txn);
        zstd_init(txn);
    }

    /* Create header cache */
    if (!(txn->req_hdrs = spool_new_hdrcache())) {
        syslog(LOG_ERR, "Unable to create header cache");
        return NGHTTP3_ERR_CALLBACK_FAILURE;
    }


    struct http3_stream *strm = xzmalloc(sizeof(struct http3_stream));

    strm->id = stream_id;
    txn->strm_ctx = strm;
    ptrarray_add(&txn->done_callbacks, &stream_done);

    /* Tell syslog our stream-id */
    buf_printf(&txn->buf, "%ld", strm->id);
    spool_replace_header(xstrdup(":stream-id"),
                         buf_release(&txn->buf), txn->req_hdrs);

    nghttp3_conn_set_stream_user_data(conn, stream_id, txn);

    return 0;
}

static int recv_header_cb(nghttp3_conn *conn __attribute__((unused)),
                          int64_t stream_id,
                          int32_t token __attribute__((unused)),
                          nghttp3_rcbuf *name,
                          nghttp3_rcbuf *value,
                          uint8_t flags __attribute__((unused)),
                          void *conn_user_data __attribute__((unused)),
                          void *stream_user_data)
{
    struct transaction_t *txn = stream_user_data;

    if (!txn) return 0;

    nghttp3_vec h3name = nghttp3_rcbuf_get_buf(name);
    nghttp3_vec h3val = nghttp3_rcbuf_get_buf(value);

    char *my_name = xstrndup((const char *) h3name.base, h3name.len);
    char *my_value = xstrndup((const char *) h3val.base, h3val.len);

    syslog(LOG_DEBUG, "H3 recv_header(%ld:  %s: %s)",
           stream_id, my_name, my_value);

    if (my_name[0] == ':') {
        switch (my_name[1]) {
        case 'm': /* :method */
            if (!strcmp("ethod", my_name+2)) txn->req_line.meth = my_value;
            break;

        case 's': /* :scheme */
            break;

        case 'a': /* :authority */
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

static int end_headers_cb(nghttp3_conn *conn __attribute__((unused)),
                          int64_t stream_id, int fin,
                          void *conn_user_data __attribute__((unused)),
                          void *stream_user_data)
{
  syslog(LOG_DEBUG, "H3 end_headers(%ld, %d)", stream_id, fin);

    struct transaction_t *txn = stream_user_data;

    /* Examine request */
    int ret = examine_request(txn, NULL);

    if (ret) {
        txn->req_body.flags |= BODY_DISCARD;
        error_response(ret, txn);
    }
    else if (txn->req_body.flags & BODY_CONTINUE) {
        txn->req_body.flags &= ~BODY_CONTINUE;
        response_header(HTTP_CONTINUE, txn);
    }

    return 0;
}

static int end_stream_cb(nghttp3_conn *conn __attribute__((unused)),
                         int64_t stream_id,
                         void *conn_user_data __attribute__((unused)),
                         void *stream_user_data)
{
    struct transaction_t *txn = stream_user_data;

    syslog(LOG_DEBUG, "H3 end_stream(%ld, 0x%X)",
           stream_id, txn->req_body.flags);

    /* Check that we still want to process the request */
    if (!(txn->req_body.flags & BODY_DISCARD)) {
        /* Process the requested method */
        int ret = process_request(txn);

        /* Handle errors (success responses handled by method functions) */
        if (ret) error_response(ret, txn);
    }

    return 0;
}

static nghttp3_callbacks callbacks = {
    acked_stream_data_cb,
    stream_close_cb,
    recv_data_cb,
    NULL, // deferred_consume
    begin_headers_cb,
    recv_header_cb,
    end_headers_cb,
    NULL, // begin_trailers
    NULL, // recv_trailer
    NULL, // end_trailers
    NULL, // send_stop_sending
    end_stream_cb,
    NULL, // reset_stream
    NULL, // shutdown
};

static void begin_resp_headers(struct transaction_t *txn, long code);
static void add_resp_header(struct transaction_t *txn,
                            const char *name, struct buf *value);
static int end_resp_headers(struct transaction_t *txn, long code);
static int resp_body_chunk(struct transaction_t *txn,
                           const char *data, unsigned datalen,
                           int last_chunk, MD5_CTX *md5ctx);

static void _reset(struct http_connection *conn)
{
    quic_close(QUIC_CTX(conn));
}

static int open_conn(void *conn)
{
    struct http_connection *http_conn = conn;
    nghttp3_conn *h3_conn = NULL;
    nghttp3_settings settings;
    int64_t ctrl_stream_id, qpack_enc_stream_id, qpack_dec_stream_id;
    int r;

    syslog(LOG_DEBUG, "H3 open_conn()");

    http_conn->begin_resp_headers = &begin_resp_headers;
    http_conn->add_resp_header = &add_resp_header;
    http_conn->end_resp_headers = &end_resp_headers;
    http_conn->resp_body_chunk = &resp_body_chunk;

    nghttp3_settings_default(&settings);
    if (ws_enabled) settings.enable_connect_protocol = 1;

    r = nghttp3_conn_server_new(&h3_conn, &callbacks, &settings,
                                nghttp3_mem_default(), conn);
    http_conn->sess_ctx = h3_conn;

    ptrarray_add(&http_conn->reset_callbacks, &_reset);

    r = quic_open_stream(QUIC_CTX(http_conn), 0, &ctrl_stream_id, NULL);
    r = nghttp3_conn_bind_control_stream(h3_conn, ctrl_stream_id);

    r = quic_open_stream(QUIC_CTX(http_conn), 0, &qpack_enc_stream_id, NULL);
    r = quic_open_stream(QUIC_CTX(http_conn), 0, &qpack_dec_stream_id, NULL);
    r = nghttp3_conn_bind_qpack_streams(h3_conn, qpack_enc_stream_id,
                                        qpack_dec_stream_id);

    return r;
}

static void close_conn(void *conn)
{
    struct http_connection *http_conn = conn;

   syslog(LOG_DEBUG, "H3 close_conn()");

    if (http_conn && http_conn->sess_ctx) {
        nghttp3_conn_del((nghttp3_conn *) http_conn->sess_ctx);
    }
}

static ssize_t read_stream(void *conn, int64_t stream_id,
                           const uint8_t *src, size_t srclen, int fin)
{
    struct http_connection *http_conn = conn;

    ssize_t n = nghttp3_conn_read_stream((nghttp3_conn *) http_conn->sess_ctx,
                                         stream_id, src, srclen, fin);

    syslog(LOG_DEBUG, "nghttp3_conn_read_stream(id=%ld, len=%zu, fin=%d): %zi",
           stream_id, srclen, fin, n);

    return n;
}

static struct quic_app_context h3 = {
    NULL,  // conn
    0,     // timeout
    open_conn,
    close_conn,
    read_stream,
    { { "h3",    NULL, NULL },
      { "h3-32", NULL, NULL },
      { "h3-29", NULL, NULL },
      { NULL,    NULL, NULL } }
};

static void _shutdown(struct http_connection *conn)
{
    quic_shutdown(QUIC_CTX(conn));
}

HIDDEN int http3_init(struct http_connection *conn, struct buf *serverinfo)
{
    struct quic_context *qctx = NULL;

    buf_printf(serverinfo, " Nghttp3/%s %s", NGHTTP3_VERSION, quic_version());

    h3.conn = conn;
    h3.timeout = httpd_timeout;

    int r = quic_init(&qctx, &h3);

    if (!r) {
        QUIC_CTX(conn) = qctx;
        ptrarray_add(&conn->shutdown_callbacks, &_shutdown);
    }

    return r;
}

HIDDEN void http3_altsvc(struct buf *altsvc)
{
    const char *config_altsvc = config_getstring(IMAPOPT_HTTP_H3_ALTSVC);

    if (config_altsvc) {
        const char *sep = buf_len(altsvc) ? ", " : "";

        buf_printf(altsvc, "%sh3=\"%s\", h3-32=\"%s\", h3-29=\"%s\"",
                   sep, config_altsvc, config_altsvc, config_altsvc);
    }
}

static void http3_output(struct http_connection *conn)
{
    nghttp3_conn *h3_conn = conn->sess_ctx;
    int64_t stream_id = -1;
    int fin = 0, write_more;
    struct iovec iov[16];
    nghttp3_ssize iovcnt = 0;
    ssize_t datalen = 0;

    do {
        if (h3_conn) {
            iovcnt = nghttp3_conn_writev_stream(h3_conn, &stream_id, &fin,
                                                (nghttp3_vec *) iov,
                                                sizeof(iov) / sizeof(iov[0]));
            syslog(LOG_DEBUG,
                   "nghttp3_conn_writev_stream(): id=%ld, iovcnt=%ld, fin=%d",
                   stream_id, iovcnt, fin);
        }

        write_more = quic_output(QUIC_CTX(conn),
                                 stream_id, fin, iov, iovcnt, &datalen);

        if (datalen >= 0) {
            nghttp3_conn_add_write_offset(h3_conn, stream_id, datalen);
        }

    } while (write_more);
}

HIDDEN void http3_input(struct http_connection *conn)
{
    int r = quic_input(QUIC_CTX(conn), conn->pin);

    if (r) {
        conn->close = 1;
        conn->close_str = prot_error(conn->pin);
    }
    else {
        http3_output(conn);
    }
}

static void begin_resp_headers(struct transaction_t *txn, long code)
{
    struct http3_stream *strm = (struct http3_stream *) txn->strm_ctx;

    syslog(LOG_DEBUG, "H3 begin_resp_headers(%ld)", code);

    strm->num_resp_hdrs = 0;

    if (txn->conn->logfd != -1) {
        /* telemetry log */
        struct buf *logbuf = &txn->conn->logbuf;

        buf_reset(logbuf);
        buf_printf(logbuf, ">" TIME_T_FMT ">", time(NULL));  /* timestamp */
        write(txn->conn->logfd, buf_base(logbuf), buf_len(logbuf));
    }

    if (code) simple_hdr(txn, ":status", "%.3s", error_message(code));
}

static void add_resp_header(struct transaction_t *txn,
                            const char *name, struct buf *value)
{
    struct http3_stream *strm = (struct http3_stream *) txn->strm_ctx;

    syslog(LOG_DEBUG, "H3 add_resp_header(name = %s, num = %ld)",
           name, strm->num_resp_hdrs);

    if (strm->num_resp_hdrs >= HTTP3_MAX_HEADERS) {
        buf_free(value);
        return;
    }
    else {
        nghttp3_nv *nv = &strm->resp_hdrs[strm->num_resp_hdrs];

        free(nv->value);

        nv->namelen = strlen(name);
        nv->name = (uint8_t *) name;
        nv->valuelen = buf_len(value);
        nv->value = (uint8_t *) buf_release(value);
        nv->flags = NGHTTP3_NV_FLAG_NO_COPY_VALUE;

        strm->num_resp_hdrs++;

        if (txn->conn->logfd != -1) {
            /* telemetry log */
            struct iovec iov[4];
            int niov = 0;

            if (name[0] == ':') {
                /* :status */
                WRITEV_ADD_TO_IOVEC(iov, niov, "HTTP/3 ", 7);
            }
            else {
                WRITEV_ADD_TO_IOVEC(iov, niov, nv->name, nv->namelen);
                WRITEV_ADD_TO_IOVEC(iov, niov, ": ", 2);
            }
            WRITEV_ADD_TO_IOVEC(iov, niov, nv->value, nv->valuelen);
            WRITEV_ADD_TO_IOVEC(iov, niov, "\r\n", 2);
            writev(txn->conn->logfd, iov, niov);
        }
    }
}

static nghttp3_ssize read_data(nghttp3_conn *conn __attribute__((unused)),
                               int64_t stream_id,
                               nghttp3_vec *vec, size_t veccnt, uint32_t *pflags,
                               void *user_data __attribute__((unused)),
                               void *stream_user_data)
{
    struct transaction_t *txn = stream_user_data;
    struct http3_stream *strm = (struct http3_stream *) txn->strm_ctx;
    int num_chunks = ptrarray_size(&strm->body_chunks);
    size_t n = 0;

    *pflags = NGHTTP3_DATA_FLAG_NONE;

    for (; n < veccnt && strm->next_chunk < num_chunks; strm->next_chunk++) {
        struct buf *buf = ptrarray_nth(&strm->body_chunks, strm->next_chunk);

        vec[n].base = (uint8_t *) buf_base(buf);
        vec[n++].len = buf_len(buf);
    }

    if (!n) {
        strm->blocked = 1;
        return NGHTTP3_ERR_WOULDBLOCK;
    }
    else if (txn->flags.te & TE_CHUNKED) {
        if (!vec[n-1].len) {
            *pflags |= NGHTTP3_DATA_FLAG_EOF;

            if (txn->flags.trailer & ~TRAILER_PROXY) {
                *pflags |= NGHTTP3_DATA_FLAG_NO_END_STREAM;

                begin_resp_headers(txn, 0);
                if (txn->flags.trailer & TRAILER_CMD5) {
                    content_md5_hdr(txn, strm->md5);
                }
                if ((txn->flags.trailer & TRAILER_CTAG) && txn->resp_body.ctag) {
                    simple_hdr(txn, "CTag", "%s", txn->resp_body.ctag);
                }
                end_resp_headers(txn, 0);
            }
        }
    }
    else {
        *pflags |= NGHTTP3_DATA_FLAG_EOF;
    }

    syslog(LOG_DEBUG,
           "H3 read_data: id=%ld, n=%ld, flags=0x%X", stream_id, n, *pflags);

    return n;
}

static int end_resp_headers(struct transaction_t *txn, long code)
{
    nghttp3_conn *h3_conn = txn->conn->sess_ctx;
    struct http3_stream *strm = (struct http3_stream *) txn->strm_ctx;
    nghttp3_data_reader dr = { read_data }, *drp = NULL;
    int r = 0;

    syslog(LOG_DEBUG,
           "H3 end_resp_headers(code = %ld, len = %ld, flags.te = %#x)",
           code, txn->resp_body.len, txn->flags.te);

    if (txn->conn->logfd != -1) {
        /* telemetry log */
        write(txn->conn->logfd, "\r\n", 2);
    }

    switch (code) {
    case 0:
        /* Trailer */
        r = nghttp3_conn_submit_trailers(h3_conn, strm->id,
                                         strm->resp_hdrs, strm->num_resp_hdrs);

        syslog(LOG_DEBUG, "nghttp3_conn_submit_trailers(id=%ld): %s",
               strm->id, nghttp3_strerror(r));

        if (r) {
            syslog(LOG_ERR, "nghttp3_conn_submit_trailers(id=%ld): %s",
                   strm->id, nghttp3_strerror(r));
        }
        break;


    case HTTP_CONTINUE:
    case HTTP_PROCESSING:
        /* Provisional response */
        r = nghttp3_conn_submit_info(h3_conn, strm->id,
                                     strm->resp_hdrs, strm->num_resp_hdrs);

        syslog(LOG_DEBUG, "nghttp3_conn_submit_info(id=%ld): %s",
               strm->id, nghttp3_strerror(r));

        if (r) {
            syslog(LOG_ERR, "nghttp3_conn_submit_info(id=%ld): %s",
                   strm->id, nghttp3_strerror(r));
        }
        break;


    default:
        if (txn->meth != METH_HEAD &&
            (txn->resp_body.len || (txn->flags.te & TE_CHUNKED))) {
            /* Response has a body */
            drp = &dr;
        }

        r = nghttp3_conn_submit_response(h3_conn, strm->id,
                                         strm->resp_hdrs, strm->num_resp_hdrs, drp);

        syslog(LOG_DEBUG, "nghttp3_conn_submit_response(id=%ld): %s",
               strm->id, nghttp3_strerror(r));

        if (r) {
            syslog(LOG_ERR, "nghttp3_conn_submit_response(id=%ld): %s",
                   strm->id, nghttp3_strerror(r));
        }
        break;
    }

    return r;
}

static int resp_body_chunk(struct transaction_t *txn,
                           const char *data, unsigned datalen,
                           int last_chunk, MD5_CTX *md5ctx)
{
    struct http3_stream *strm = (struct http3_stream *) txn->strm_ctx;

    syslog(LOG_DEBUG, "H3 resp_body_chunk(datalen=%u, last=%d)",
           datalen, last_chunk);

    if (!datalen && !last_chunk) return 0;

    if (txn->conn->logfd != -1) {
        /* telemetry log */
        struct buf *logbuf = &txn->conn->logbuf;
        struct iovec iov[2];
        int niov = 0;

        buf_reset(logbuf);
        buf_printf(logbuf, ">" TIME_T_FMT ">", time(NULL));  /* timestamp */
        WRITEV_ADD_TO_IOVEC(iov, niov,
                            buf_base(logbuf), buf_len(logbuf));
        WRITEV_ADD_TO_IOVEC(iov, niov, data, datalen);
        writev(txn->conn->logfd, iov, niov);
    }

    if (txn->flags.te) {
        if (!last_chunk) {
            if (datalen && (txn->flags.trailer & TRAILER_CMD5)) {
                MD5Update(md5ctx, data, datalen);
            }
        }
        else if (txn->flags.trailer & TRAILER_CMD5) {
            MD5Final(strm->md5, md5ctx);
        }
    }


    struct buf *buf = buf_new();
    buf_setmap(buf, data, datalen);
    ptrarray_append(&strm->body_chunks, buf);

    if (strm->blocked) {
        strm->blocked = 0;
        nghttp3_conn_resume_stream(QUIC_CTX(txn->conn), strm->id);
    }

    return 0;
}

#else /* !WITH_HTTP3 */

HIDDEN int http3_init(struct http_connection *conn __attribute__((unused)),
                      struct buf *serverinfo __attribute__((unused)))
{
    return HTTP_NOT_IMPLEMENTED;
}

HIDDEN void http3_altsvc(struct buf *altsvc __attribute__((unused)))
{
}

HIDDEN void http3_input(struct http_connection *conn __attribute__((unused)))
{
    fatal("http3_input() called, but no Nghttp3", EX_SOFTWARE);
}

#endif /* WITH_HTTP3 */
