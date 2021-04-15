/* http_h2.c - HTTP/2 support functions
 *
 * Copyright (c) 1994-2018 Carnegie Mellon University.  All rights reserved.
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

#include <config.h>
#include <sysexits.h>

#include "httpd.h"
#include "http_h2.h"

#ifdef HAVE_NGHTTP2

#include <errno.h>
#include <syslog.h>

#include <sasl/saslutil.h>

#include "http_ws.h"
#include "prometheus.h"
#include "retry.h"

/* generated headers are not necessarily in current directory */
#include "imap/http_err.h"

#define HTTP2_MAX_HEADERS  100

/* HTTP/2 session context */
struct http2_context {
    nghttp2_session *session;           /* HTTP/2 session */
    nghttp2_option *options;            /* Config options for HTTP/2 session */
    unsigned ws_count;                  /* Count of WebSocket streams */
};

/* HTTP/2 stream context */
struct http2_stream {
    int32_t id;                         /* Stream ID */
    size_t num_resp_hdrs;               /* Number of response headers */
    nghttp2_nv resp_hdrs[HTTP2_MAX_HEADERS]; /* Array of response headers */
};

static nghttp2_session_callbacks *http2_callbacks = NULL;

static ssize_t send_cb(nghttp2_session *session __attribute__((unused)),
                       const uint8_t *data, size_t length,
                       int flags __attribute__((unused)),
                       void *user_data)
{
    struct http_connection *conn = (struct http_connection *) user_data;
    struct protstream *pout = conn->pout;
    int r;

    r = prot_write(pout, (const char *) data, length);

    syslog(LOG_DEBUG, "http2_send_cb(%zu): %d", length, r);

    if (r) return NGHTTP2_ERR_CALLBACK_FAILURE;

    return length;
}

static ssize_t recv_cb(nghttp2_session *session __attribute__((unused)),
                       uint8_t *buf, size_t length,
                       int flags __attribute__((unused)),
                       void *user_data)
{
    struct http_connection *conn = (struct http_connection *) user_data;
    struct protstream *pin = conn->pin;
    ssize_t n;

    
    n = prot_read(pin, (char *) buf, length);
    if (n) {
        /* We received some data - don't block next time
           Note: This callback gets called multiple times until it
           would block.  We don't actually want to block and prevent
           output from being submitted */
        prot_NONBLOCK(pin);
    }
    else if (!((struct http2_context *) conn->sess_ctx)->ws_count) {
        /* No data (and no WebSockets) -  block next time (for client timeout) */
        prot_BLOCK(pin);

        if (pin->eof) n = NGHTTP2_ERR_EOF;
        else if (pin->error) n = NGHTTP2_ERR_CALLBACK_FAILURE;
        else n = NGHTTP2_ERR_WOULDBLOCK;
    }

    syslog(LOG_DEBUG,
           "http2_recv_cb(%zu): n = %zd, eof = %d, err = '%s', errno = %m",
           length, n, pin->eof, pin->error ? pin->error : "");

    return n;
}

static ssize_t data_source_read_cb(nghttp2_session *sess __attribute__((unused)),
                                   int32_t stream_id,
                                   uint8_t *buf, size_t length,
                                   uint32_t *data_flags,
                                   nghttp2_data_source *source,
                                   void *user_data __attribute__((unused)))
{
    struct protstream *s = source->ptr;
    size_t n = prot_read(s, (char *) buf, length);

    syslog(LOG_DEBUG,
           "http2_data_source_read_cb(id=%d, len=%zu): n=%zu, eof=%d",
           stream_id, length, n, !s->cnt);

    if (!s->cnt) {
        *data_flags |= NGHTTP2_DATA_FLAG_EOF;
        prot_free(s);  /* Done with the protstream */
    }

    return n;
}

static int begin_headers_cb(nghttp2_session *session,
                            const nghttp2_frame *frame, void *user_data)
{
    if (frame->hd.type != NGHTTP2_HEADERS ||
        frame->headers.cat != NGHTTP2_HCAT_REQUEST) {
        return 0;
    }

    syslog(LOG_DEBUG, "http2_begin_headers_cb(id=%d, type=%d)",
           frame->hd.stream_id, frame->hd.type);

    struct transaction_t *txn = xzmalloc(sizeof(struct transaction_t));

    txn->conn = (struct http_connection *) user_data;
    txn->meth = METH_UNKNOWN;
    txn->flags.ver = VER_2;
    txn->flags.vary = VARY_AE;
    txn->req_line.ver = HTTP2_VERSION;

    if (config_getswitch(IMAPOPT_HTTPALLOWCOMPRESS)) {
        txn->zstrm = zlib_init();
        txn->brotli = brotli_init();
        txn->zstd = zstd_init();
    }


    struct http2_stream *strm = xzmalloc(sizeof(struct http2_stream));

    strm->id = frame->hd.stream_id;
    txn->strm_ctx = strm;

    /* Create header cache */
    if (!(txn->req_hdrs = spool_new_hdrcache())) {
        syslog(LOG_ERR, "Unable to create header cache");
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }

    nghttp2_session_set_stream_user_data(session, frame->hd.stream_id, txn);

    return 0;
}

static int header_cb(nghttp2_session *session,
                     const nghttp2_frame *frame,
                     const uint8_t *name, size_t namelen,
                     const uint8_t *value, size_t valuelen,
                     uint8_t flags __attribute__((unused)),
                     void *user_data __attribute__((unused)))
{
    if (frame->hd.type != NGHTTP2_HEADERS ||
        frame->headers.cat != NGHTTP2_HCAT_REQUEST) {
        return 0;
    }

    char *my_name, *my_value;
    struct transaction_t *txn =
        nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);

    if (!txn) return 0;

    my_name = xstrndup((const char *) name, namelen);
    my_value = xstrndup((const char *) value, valuelen);

    syslog(LOG_DEBUG, "http2_header_cb(%s: %s)", my_name, my_value);

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

static int data_chunk_recv_cb(nghttp2_session *session,
                              uint8_t flags __attribute__((unused)),
                              int32_t stream_id,
                              const uint8_t *data, size_t len,
                              void *user_data __attribute__((unused)))
{
    struct transaction_t *txn =
        nghttp2_session_get_stream_user_data(session, stream_id);

    if (!txn) return 0;

    syslog(LOG_DEBUG, "http2_data_chunk_recv_cb(id=%d, len=%zu, txnflags=%#x)",
           stream_id, len, txn->req_body.flags);

    if (txn->req_body.flags & BODY_DISCARD) return 0;

    if (len) {
        txn->req_body.framing = FRAMING_HTTP2;
        txn->req_body.len += len;
        buf_appendmap(&txn->req_body.payload, (const char *) data, len);
    }

    return 0;
}

static int frame_recv_cb(nghttp2_session *session,
                         const nghttp2_frame *frame,
                         void *user_data __attribute__((unused)))
{
    int ret = 0;
    struct transaction_t *txn =
        nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
    struct http2_context *ctx;
    struct buf *logbuf = NULL;

    if (!txn) return 0;

    ctx = (struct http2_context *) txn->conn->sess_ctx;

    syslog(LOG_DEBUG, "http2_frame_recv_cb(id=%d, type=%d, flags=%#x)",
           frame->hd.stream_id, frame->hd.type, frame->hd.flags);

    if ((txn->conn->logfd != -1) && (frame->hd.type <= NGHTTP2_HEADERS)) {
        /* telemetry log */
        logbuf = &txn->conn->logbuf;

        buf_reset(logbuf);
        buf_printf(logbuf, "<" TIME_T_FMT "<", time(NULL));   /* timestamp */
        write(txn->conn->logfd, buf_base(logbuf), buf_len(logbuf));
    }

    switch (frame->hd.type) {
    case NGHTTP2_HEADERS:
        if (frame->headers.cat == NGHTTP2_HCAT_REQUEST) {
            if (txn->conn->logfd != -1) {
                /* telemetry log */
                buf_reset(logbuf);
                buf_printf(logbuf, "%s %s %s\r\n",         /* request-line*/
                           txn->req_line.meth, txn->req_line.uri, HTTP2_VERSION);
                spool_enum_hdrcache(txn->req_hdrs,            /* header fields */
                                    &log_cachehdr, logbuf);
                buf_appendcstr(logbuf, "\r\n");            /* CRLF */
                write(txn->conn->logfd, buf_base(logbuf), buf_len(logbuf));
            }

            /* Examine request */
            ret = examine_request(txn, NULL);

            if (ret) {
                txn->req_body.flags |= BODY_DISCARD;
                error_response(ret, txn);
                break;
            }

            if (txn->req_body.flags & BODY_CONTINUE) {
                txn->req_body.flags &= ~BODY_CONTINUE;
                response_header(HTTP_CONTINUE, txn);
                break;
            }
        }

        GCC_FALLTHROUGH

    case NGHTTP2_DATA:
        if (txn->ws_ctx) {
            /* WebSocket over HTTP/2 input */
            ws_input(txn);

            if (txn->flags.conn & CONN_CLOSE) {
                /* Issue RST_STREAM so that stream does not hang around. */
                syslog(LOG_DEBUG, "nghttp2_submit_rst stream()");
                nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE,
                                          frame->hd.stream_id,
                                          NGHTTP2_NO_ERROR);
            }
            break;
        }

        if (txn->conn->logfd != -1) {
            /* telemetry log */
            write(txn->conn->logfd, buf_base(&txn->req_body.payload),
                  buf_len(&txn->req_body.payload));
        }

        if (txn->meth != METH_CONNECT) {
            /* Check that the client request has finished */
            if (!(frame->hd.flags & NGHTTP2_FLAG_END_STREAM)) break;
              
            /* Check that we still want to process the request */
            if (txn->req_body.flags & BODY_DISCARD) break;
        }

        /* Process the requested method */
        ret = process_request(txn);

        /* Handle errors (success responses handled by method functions) */
        if (ret) error_response(ret, txn);

        if (txn->flags.conn & CONN_CLOSE) {
            int32_t stream_id =
                nghttp2_session_get_last_proc_stream_id(ctx->session);

            syslog(LOG_DEBUG, "nghttp2_submit_goaway()");
            nghttp2_submit_goaway(session, NGHTTP2_FLAG_NONE, stream_id,
                                  NGHTTP2_NO_ERROR, NULL, 0);
        }
        else if (txn->ws_ctx) {
            /* Increment WebSocket stream count */
            ctx->ws_count++;
        }

        break;
    }

    return 0;
}

static int stream_close_cb(nghttp2_session *session, int32_t stream_id,
                           uint32_t error_code,
                           void *user_data __attribute__((unused)))
{
    struct transaction_t *txn =
        nghttp2_session_get_stream_user_data(session, stream_id);

    syslog(LOG_DEBUG, "http2_stream_close_cb(id=%d): '%s'",
           stream_id, nghttp2_http2_strerror(error_code));

    if (txn) {
        if (txn->ws_ctx) {
            /* Decrement WebSocket stream count */
            struct http2_context *http2_ctx =
                (struct http2_context *) txn->conn->sess_ctx;
            if (--http2_ctx->ws_count == 0) {
                /* No WebSockets -  block next time (for client timeout) */
                prot_BLOCK(txn->conn->pin);
            }
        }

        /* Memory cleanup */
        transaction_free(txn);
        free(txn);
    }

    return 0;
}

static int frame_not_send_cb(nghttp2_session *session,
                             const nghttp2_frame *frame,
                             int lib_error_code,
                             void *user_data __attribute__((unused)))
{
    syslog(LOG_DEBUG, "http2_frame_not_send_cb(id=%d, type=%d, flags=%#x)",
           frame->hd.stream_id, frame->hd.type, frame->hd.flags);

    /* Issue RST_STREAM so that stream does not hang around. */
    nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE,
                              frame->hd.stream_id, lib_error_code);

    return 0;
}

static int frame_send_cb(nghttp2_session *session __attribute__((unused)),
                         const nghttp2_frame *frame,
                         void *user_data __attribute__((unused)))
{
    syslog(LOG_DEBUG, "http2_frame_send_cb(id=%d, type=%d, flags=%#x)",
           frame->hd.stream_id, frame->hd.type, frame->hd.flags);

    return 0;
}

static int begin_frame_cb(nghttp2_session *session __attribute__((unused)),
                         const nghttp2_frame_hd *hd,
                         void *user_data __attribute__((unused)))
{
    syslog(LOG_DEBUG, "http2_begin_frame_cb(id=%d, type=%d, flags=%#x)",
           hd->stream_id, hd->type, hd->flags);

    return 0;
}


HIDDEN void http2_init(struct buf *serverinfo)
{
    int r;

    buf_printf(serverinfo, " Nghttp2/%s", NGHTTP2_VERSION);

    /* Setup HTTP/2 callbacks */
    if ((r = nghttp2_session_callbacks_new(&http2_callbacks))) {
        syslog(LOG_WARNING,
               "nghttp2_session_callbacks_new: %s", nghttp2_strerror(r));
        return;
    }

    nghttp2_session_callbacks_set_send_callback(http2_callbacks,
                                                &send_cb);
    nghttp2_session_callbacks_set_recv_callback(http2_callbacks,
                                                &recv_cb);
    nghttp2_session_callbacks_set_on_begin_headers_callback(http2_callbacks,
                                                            &begin_headers_cb);
    nghttp2_session_callbacks_set_on_header_callback(http2_callbacks,
                                                     &header_cb);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(http2_callbacks,
                                                              &data_chunk_recv_cb);
    nghttp2_session_callbacks_set_on_frame_recv_callback(http2_callbacks,
                                                         &frame_recv_cb);
    nghttp2_session_callbacks_set_on_stream_close_callback(http2_callbacks,
                                                           &stream_close_cb);
    nghttp2_session_callbacks_set_on_frame_not_send_callback(http2_callbacks,
                                                             &frame_not_send_cb);

    if (config_getswitch(IMAPOPT_DEBUG)) {
        nghttp2_session_callbacks_set_on_begin_frame_callback(http2_callbacks,
                                                              &begin_frame_cb);
        nghttp2_session_callbacks_set_on_frame_send_callback(http2_callbacks,
                                                             &frame_send_cb);
    }
}


HIDDEN int http2_enabled()
{
    return (http2_callbacks != NULL);
}

HIDDEN void http2_done()
{
    nghttp2_session_callbacks_del(http2_callbacks);
}


HIDDEN int http2_preface(struct http_connection *conn)
{
    if (http2_enabled()) {
        /* Check initial client input for HTTP/2 preface */
        int c;

        if (prot_lookahead(conn->pin,
                           NGHTTP2_CLIENT_MAGIC, NGHTTP2_CLIENT_MAGIC_LEN, &c)) {
            syslog(LOG_DEBUG, "HTTP/2 client connection preface");
            return 1;
        }
    }

    return 0;
}


#if HAVE_DECL_NGHTTP2_SETTINGS_ENABLE_CONNECT_PROTOCOL
static int nghttp2_extended_connect = 1;
#else
#define NGHTTP2_SETTINGS_ENABLE_CONNECT_PROTOCOL 0x08
static int nghttp2_extended_connect = 0;
#endif

HIDDEN int http2_start_session(struct transaction_t *txn,
                               struct http_connection *conn)
{
    nghttp2_settings_entry iv[] = {
        { NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100 },
        { NGHTTP2_SETTINGS_ENABLE_CONNECT_PROTOCOL, 1 }  /* MUST be last */
    };
    size_t niv = (sizeof(iv) / sizeof(iv[0])) - !ws_enabled();
    struct http2_context *ctx;
    int r;

    if (!conn) conn = txn->conn;

    if (conn->sess_ctx) return 0;

    ctx = xzmalloc(sizeof(struct http2_context));

    r = nghttp2_option_new(&ctx->options);
    if (r) {
        syslog(LOG_WARNING,
               "nghttp2_option_new: %s", nghttp2_strerror(r));
        free(ctx);
        return HTTP_SERVER_ERROR;
    }

    if (ws_enabled() && !nghttp2_extended_connect) {
        /* Need to forcefully allow :scheme, :path, :protocol pseudo-headers
           (this version of libnghttp2 doesn't understand extended CONNECT) */
        nghttp2_option_set_no_http_messaging(ctx->options, 1);
    }

    r = nghttp2_session_server_new2(&ctx->session,
                                    http2_callbacks, conn, ctx->options);
    if (r) {
        syslog(LOG_WARNING,
               "nghttp2_session_server_new2: %s", nghttp2_strerror(r));
        free(ctx);
        return HTTP_SERVER_ERROR;
    }

    conn->sess_ctx = ctx;

    if (txn && (txn->flags.conn & CONN_UPGRADE)) {
        struct http2_stream *strm;
        struct buf *buf = &txn->buf;
        unsigned outlen;

        const char **hdr = spool_getheader(txn->req_hdrs, "HTTP2-Settings");
        if (!hdr || hdr[1]) return 0;

        /* base64url decode the settings.
           Use the SASL base64 decoder after replacing the encoded values
           for chars 62 and 63 and adding appropriate padding. */
        buf_setcstr(buf, hdr[0]);
        buf_replace_char(buf, '-', '+');
        buf_replace_char(buf, '_', '/');
        buf_appendmap(buf, "==", (4 - (buf_len(buf) % 4)) % 4);
        r = sasl_decode64(buf_base(buf), buf_len(buf),
                          (char *) buf_base(buf), buf_len(buf), &outlen);
        if (r != SASL_OK) {
            syslog(LOG_WARNING, "sasl_decode64 failed: %s",
                   sasl_errstring(r, NULL, NULL));
        }
        else {
            r = nghttp2_session_upgrade2(ctx->session,
                                         (const uint8_t *) buf_base(buf),
                                         outlen, txn->meth == METH_HEAD, NULL);
            if (r) {
                syslog(LOG_WARNING, "nghttp2_session_upgrade: %s",
                       nghttp2_strerror(r));
            }
        }

        buf_reset(buf);
        if (r) return HTTP_BAD_REQUEST;

        /* tell client to start h2c upgrade (RFC 7540) */
        response_header(HTTP_SWITCH_PROT, txn);

        strm = xzmalloc(sizeof(struct http2_stream));
        strm->id = nghttp2_session_get_last_proc_stream_id(ctx->session);
        txn->strm_ctx = strm;
        txn->flags.ver = VER_2;
    }

    /* Don't do telemetry logging in prot layer */
    prot_setlog(conn->pin, PROT_NO_FD);
    prot_setlog(conn->pout, PROT_NO_FD);

    tcp_disable_nagle(1); /* output fd */

    r = nghttp2_submit_settings(ctx->session, NGHTTP2_FLAG_NONE, iv, niv);
    if (r) {
        syslog(LOG_ERR, "nghttp2_submit_settings: %s", nghttp2_strerror(r));
        return HTTP_SERVER_ERROR;
    }

    return 0;
}


HIDDEN void http2_end_session(void **http2_ctx, const char *msg)
{
    struct http2_context *ctx = (struct http2_context *) *http2_ctx;

    if (!ctx) return;

    /* End the session if we haven't already */
    if (nghttp2_session_want_read(ctx->session)) {
        int32_t stream_id =
            nghttp2_session_get_last_proc_stream_id(ctx->session);
        int r;

        if (!msg) msg = "Server unavailable";

        syslog(LOG_DEBUG, "nghttp2_submit_goaway(%s)", msg);

        r = nghttp2_submit_goaway(ctx->session, NGHTTP2_FLAG_NONE, stream_id,
                                  NGHTTP2_CANCEL,
                                  (const uint8_t *) msg, strlen(msg));
        if (r) {
            syslog(LOG_ERR, "nghttp2_submit_goaway: %s", nghttp2_strerror(r));
        }
        else {
            r = nghttp2_session_send(ctx->session);
            if (r) {
                syslog(LOG_ERR, "nghttp2_session_send: %s", nghttp2_strerror(r));
            }
        }
    }

    nghttp2_option_del(ctx->options);
    nghttp2_session_del(ctx->session);
    free(ctx);

    *http2_ctx = NULL;
}


static void http2_output(struct transaction_t *txn)
{
    struct http2_context *ctx = (struct http2_context *) txn->conn->sess_ctx;

    if (nghttp2_session_want_write(ctx->session)) {
        /* Send queued frame(s) */
        int r = nghttp2_session_send(ctx->session);
        if (r) {
            syslog(LOG_ERR, "nghttp2_session_send: %s", nghttp2_strerror(r));
            txn->flags.conn = CONN_CLOSE;
        }
    }
    else if (!nghttp2_session_want_read(ctx->session)) {
        /* We're done */
        syslog(LOG_DEBUG, "closing connection");
        txn->flags.conn = CONN_CLOSE;
        return;
    }
}


HIDDEN void http2_input(struct transaction_t *txn)
{
    struct http2_context *ctx = (struct http2_context *) txn->conn->sess_ctx;
    int want_read = nghttp2_session_want_read(ctx->session);
    int goaway = txn->flags.conn & CONN_CLOSE;
    nghttp2_error_code err = goaway ? NGHTTP2_REFUSED_STREAM : NGHTTP2_NO_ERROR;
    struct protstream *pin = txn->conn->pin;

    syslog(LOG_DEBUG, "http2_input()  goaway: %d, eof: %d, want read: %d",
           goaway, prot_IS_EOF(pin), want_read);


    if (want_read && !goaway) {
        /* Read frame(s) */
        int r = nghttp2_session_recv(ctx->session);

        if (!r) {
            /* Successfully received frames */
            syslog(LOG_DEBUG, "nghttp2_session_recv: success");
        }
        else if (r == NGHTTP2_ERR_EOF) {
            /* Client closed connection */
            syslog(LOG_DEBUG, "client closed connection");
            txn->flags.conn = CONN_CLOSE;
        }
        else {
            /* Failure */
            syslog(LOG_DEBUG, "nghttp2_session_recv: %s (%s)",
                   nghttp2_strerror(r), prot_error(pin));
            goaway = 1;

            if (r == NGHTTP2_ERR_CALLBACK_FAILURE) {
                /* Client timeout */
                txn->error.desc = prot_error(pin);
                err = NGHTTP2_REFUSED_STREAM;
            }
            else {
                txn->error.desc = nghttp2_strerror(r);

                if (r == NGHTTP2_ERR_NOMEM)
                    err = NGHTTP2_INTERNAL_ERROR;
                else if (r == NGHTTP2_ERR_BAD_CLIENT_MAGIC)
                    err = NGHTTP2_PROTOCOL_ERROR;
                else if (r == NGHTTP2_ERR_FLOODED)
                    err = NGHTTP2_ENHANCE_YOUR_CALM;
            }
        }
    }

    if (goaway) {
        /* Tell client we are closing session */
        int32_t stream_id =
            nghttp2_session_get_last_proc_stream_id(ctx->session);

        syslog(LOG_WARNING, "%s, closing connection", txn->error.desc);

        syslog(LOG_DEBUG, "nghttp2_submit_goaway()");
        int r = nghttp2_submit_goaway(ctx->session,
                                      NGHTTP2_FLAG_NONE, stream_id, err,
                                      (const uint8_t *) txn->error.desc,
                                      strlen(txn->error.desc));
        if (r) {
            syslog(LOG_ERR, "nghttp2_submit_goaway: %s", nghttp2_strerror(r));
        }

        txn->flags.conn = CONN_CLOSE;
    }

    /* Write frame(s) */
    http2_output(txn);

    return;
}


HIDDEN void http2_begin_headers(struct transaction_t *txn)
{
    struct http2_stream *strm = (struct http2_stream *) txn->strm_ctx;

    strm->num_resp_hdrs = 0;

    if (txn->conn->logfd != -1) {
        /* telemetry log */
        struct buf *logbuf = &txn->conn->logbuf;

        buf_reset(logbuf);
        buf_printf(logbuf, ">" TIME_T_FMT ">", time(NULL));  /* timestamp */
        write(txn->conn->logfd, buf_base(logbuf), buf_len(logbuf));
    }
}


HIDDEN void http2_add_header(struct transaction_t *txn,
                             const char  *name, struct buf *value)
{
    struct http2_stream *strm = (struct http2_stream *) txn->strm_ctx;

    if (strm->num_resp_hdrs >= HTTP2_MAX_HEADERS) {
        buf_free(value);
        return;
    }
    else {
        nghttp2_nv *nv = &strm->resp_hdrs[strm->num_resp_hdrs];

        free(nv->value);

        nv->namelen = strlen(name);
        nv->name = (uint8_t *) name;
        nv->valuelen = buf_len(value);
        nv->value = (uint8_t *) buf_release(value);
        nv->flags = NGHTTP2_NV_FLAG_NO_COPY_VALUE;

        strm->num_resp_hdrs++;

        if (txn->conn->logfd != -1) {
            /* telemetry log */
            struct iovec iov[4];
            int niov = 0;

            if (name[0] == ':') {
                /* :status */
                WRITEV_ADD_TO_IOVEC(iov, niov, "HTTP/2 ", 7);
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


HIDDEN int http2_end_headers(struct transaction_t *txn, long code)
{
    struct http2_context *ctx = (struct http2_context *) txn->conn->sess_ctx;
    struct http2_stream *strm = (struct http2_stream *) txn->strm_ctx;

    uint8_t flags = NGHTTP2_FLAG_NONE;
    int r;

    syslog(LOG_DEBUG,
           "end_resp_headers(code = %ld, len = %ld, flags.te = %#x)",
           code, txn->resp_body.len, txn->flags.te);

    if (txn->conn->logfd != -1) {
        /* telemetry log */
        write(txn->conn->logfd, "\r\n", 2);
    }

    switch (code) {
    case 0:
        /* Trailer */
        flags = NGHTTP2_FLAG_END_STREAM;
        break;

    case HTTP_CONTINUE:
    case HTTP_PROCESSING:
        /* Provisional response */
        break;

    case HTTP_NO_CONTENT:
    case HTTP_NOT_MODIFIED:
        /* MUST NOT include a body */
        flags = NGHTTP2_FLAG_END_STREAM;
        break;

    default:
        if (txn->meth == METH_HEAD) {
            /* MUST NOT include a body */
            flags = NGHTTP2_FLAG_END_STREAM;
        }
        else if (!(txn->resp_body.len || (txn->flags.te & TE_CHUNKED))) {
            /* Empty body */
            flags = NGHTTP2_FLAG_END_STREAM;
        }
        break;
    }

    syslog(LOG_DEBUG, "%s(id=%d, flags=%#x)",
           code ? "nghttp2_submit headers" : "nghttp2_submit_trailers",
           strm->id, flags);

    if (code) {
        r = nghttp2_submit_headers(ctx->session, flags, strm->id, NULL,
                                   strm->resp_hdrs, strm->num_resp_hdrs, NULL);
    }
    else {
        r = nghttp2_submit_trailer(ctx->session, strm->id,
                                   strm->resp_hdrs, strm->num_resp_hdrs);
    }
    if (r) {
        syslog(LOG_ERR, "%s: %s",
               code ? "nghttp2_submit headers" : "nghttp2_submit_trailers",
               nghttp2_strerror(r));
    }

    return r;
}


HIDDEN int http2_data_chunk(struct transaction_t *txn,
                            const char *data, unsigned datalen,
                            int last_chunk, MD5_CTX *md5ctx)
{
    static unsigned char md5[MD5_DIGEST_LENGTH];
    struct http2_context *ctx = (struct http2_context *) txn->conn->sess_ctx;
    struct http2_stream *strm = (struct http2_stream *) txn->strm_ctx;
    uint8_t flags = NGHTTP2_FLAG_END_STREAM;
    nghttp2_data_provider prd;
    int r;

    syslog(LOG_DEBUG, "http2_data_chunk(datalen=%u, last=%d)",
           datalen, last_chunk);

    if (datalen && (txn->conn->logfd != -1)) {
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

    /* NOTE: The protstream that we use as the data source MUST remain
       available until the data source read callback has retrieved all data.
       Also note that we need to make a copy of the data because data frames
       may not be sent prior to the original pointer becoming invalid.
    */
    struct protstream *s = prot_readmap(xmemdup(data, datalen), datalen);
    s->buf = s->ptr;
    s->buf_size = datalen;

    prd.source.ptr = s;
    prd.read_callback = data_source_read_cb;

    if (txn->flags.te) {
        if (!last_chunk) {
            flags = NGHTTP2_FLAG_NONE;
            if (datalen && (txn->flags.trailer & TRAILER_CMD5)) {
                MD5Update(md5ctx, data, datalen);
            }
        }
        else if (txn->flags.trailer) {
            flags = NGHTTP2_FLAG_NONE;
            if (txn->flags.trailer & TRAILER_CMD5) MD5Final(md5, md5ctx);
        }
    }

    syslog(LOG_DEBUG, "nghttp2_submit_data(id=%d, datalen=%d, flags=%#x)",
           strm->id, datalen, flags);

    r = nghttp2_submit_data(ctx->session, flags, strm->id, &prd);
    if (r) {
        syslog(LOG_ERR, "nghttp2_submit_data: %s", nghttp2_strerror(r));
        return HTTP_SERVER_ERROR;
    }
    else {
        http2_output(txn);

        if (last_chunk && (txn->flags.trailer & ~TRAILER_PROXY)) {
            begin_resp_headers(txn, 0);
            if (txn->flags.trailer & TRAILER_CMD5) content_md5_hdr(txn, md5);
            if ((txn->flags.trailer & TRAILER_CTAG) && txn->resp_body.ctag) {
                simple_hdr(txn, "CTag", "%s", txn->resp_body.ctag);
            }
            end_resp_headers(txn, 0);
        }
    }

    return 0;
}

HIDDEN int32_t http2_get_streamid(void *http2_strm)
{
    struct http2_stream *strm = (struct http2_stream *) http2_strm;

    return strm ? strm->id : 0;
}

HIDDEN void http2_end_stream(void *http2_strm)
{
    struct http2_stream *strm = (struct http2_stream *) http2_strm;
    int i;

    if (!strm) return;

    for (i = 0; i < HTTP2_MAX_HEADERS; i++) {
        free(strm->resp_hdrs[i].value);
    }
    free(strm);
}

#else /* !HAVE_NGHTTP2 */

HIDDEN void http2_init(struct buf *serverinfo __attribute__((unused))) {}

HIDDEN int http2_enabled()
{
    return 0;
}

HIDDEN void http2_done() {}

HIDDEN int http2_preface(struct http_connection *conn __attribute__((unused)))
{
    return 0;
}

HIDDEN int http2_start_session(struct transaction_t *txn __attribute__((unused)),
                               struct http_connection *c __attribute__((unused)))
{
    fatal("http2_start() called, but no Nghttp2", EX_SOFTWARE);
}

HIDDEN void http2_end_session(void **http2_ctx __attribute__((unused)),
                              const char *msg__attribute__((unused)))
{
}

HIDDEN void http2_input(struct transaction_t *txn __attribute__((unused)))
{
    fatal("http2_input() called, but no Nghttp2", EX_SOFTWARE);
}

HIDDEN void http2_begin_headers(struct transaction_t *txn __attribute__((unused)))
{
    fatal("http2_begin_headers() called, but no Nghttp2", EX_SOFTWARE);
}

HIDDEN void http2_add_header(struct transaction_t *txn __attribute__((unused)),
                             const char *name __attribute__((unused)),
                             struct buf *value __attribute__((unused)))
{
    fatal("http2_add_header() called, but no Nghttp2", EX_SOFTWARE);
}

HIDDEN int http2_end_headers(struct transaction_t *txn __attribute__((unused)),
                             long code __attribute__((unused)))
{
    fatal("http2_end_headers() called, but no Nghttp2", EX_SOFTWARE);
}

HIDDEN int http2_data_chunk(struct transaction_t *txn __attribute__((unused)),
                            const char *data __attribute__((unused)),
                            unsigned datalen __attribute__((unused)),
                            int last_chunk __attribute__((unused)),
                            MD5_CTX *md5ctx __attribute__((unused)))
{
    fatal("http2_data_chunk() called, but no Nghttp2", EX_SOFTWARE);
}

HIDDEN int32_t http2_get_streamid(void *http2_strm __attribute__((unused)))
{
    return 0;
}

HIDDEN void http2_end_stream(void *http2_strm __attribute__((unused))) {}

#endif /* HAVE_NGHTTP2 */
