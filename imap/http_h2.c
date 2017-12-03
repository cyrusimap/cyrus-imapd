/* http_h2.c - HTTP/2 support functions
 *
 * Copyright (c) 1994-2017 Carnegie Mellon University.  All rights reserved.
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

#include "exitcodes.h"
#include "httpd.h"
#include "md5.h"
#include "util.h"

int (*alpn_select_cb)(SSL *ssl,
                      const unsigned char **out, unsigned char *outlen,
                      const unsigned char *in, unsigned int inlen,
                      void *arg) = NULL;

#ifdef HAVE_NGHTTP2

#include <errno.h>
#include <syslog.h>

#include <sasl/saslutil.h>

#include "http_h2.h"

/* generated headers are not necessarily in current directory */
#include "imap/http_err.h"

nghttp2_session_callbacks *http2_callbacks = NULL;

static int _alpn_select_cb(SSL *ssl __attribute__((unused)),
                           const unsigned char **out, unsigned char *outlen,
                           const unsigned char *in, unsigned int inlen,
                           void *arg)
{
    int *is_h2 = (int *) arg;

    if (nghttp2_select_next_protocol((u_char **) out, outlen, in, inlen) == 1) {
        *is_h2 = 1;
        return SSL_TLSEXT_ERR_OK;
    }

    return SSL_TLSEXT_ERR_NOACK;
}

EXPORTED ssize_t http2_send_cb(nghttp2_session *session __attribute__((unused)),
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

EXPORTED ssize_t http2_recv_cb(nghttp2_session *session __attribute__((unused)),
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
    else {
        /* No data -  block next time (for client timeout) */
        prot_BLOCK(pin);

        if (pin->eof) n = NGHTTP2_ERR_EOF;
        else if (pin->error) n = NGHTTP2_ERR_CALLBACK_FAILURE;
        else n = NGHTTP2_ERR_WOULDBLOCK;
    }

    syslog(LOG_DEBUG,
           "http2_recv_cb(%zu): n = %zd, eof = %d, err = '%s', errno = %d",
           length, n, pin->eof, pin->error ? pin->error : "", errno);

    return n;
}

EXPORTED ssize_t http2_data_source_read_cb(nghttp2_session *session __attribute__((unused)),
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

EXPORTED int http2_begin_headers_cb(nghttp2_session *session,
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
    txn->http2.stream_id = frame->hd.stream_id;
    txn->meth = METH_UNKNOWN;
    txn->flags.ver = VER_2;
    txn->flags.vary = VARY_AE;
    txn->req_line.ver = HTTP2_VERSION;

    /* Create header cache */
    if (!(txn->req_hdrs = spool_new_hdrcache())) {
        syslog(LOG_ERR, "Unable to create header cache");
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }

    nghttp2_session_set_stream_user_data(session, frame->hd.stream_id, txn);

    return 0;
}

EXPORTED int http2_header_cb(nghttp2_session *session,
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

        case 'p': /* :path */
            if (!strcmp("ath", my_name+2)) txn->req_line.uri = my_value;
            break;
        }
    }

    spool_cache_header(my_name, my_value, txn->req_hdrs);

    return 0;
}

EXPORTED int http2_data_chunk_recv_cb(nghttp2_session *session,
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

EXPORTED int http2_frame_recv_cb(nghttp2_session *session,
                                 const nghttp2_frame *frame,
                                 void *user_data __attribute__((unused)))
{
    int ret = 0;
    struct transaction_t *txn =
        nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);

    if (!txn) return 0;

    syslog(LOG_DEBUG, "http2_frame_recv_cb(id=%d, type=%d, flags=%#x",
           frame->hd.stream_id, frame->hd.type, frame->hd.flags);

    switch (frame->hd.type) {
    case NGHTTP2_HEADERS:
        if (frame->headers.cat == NGHTTP2_HCAT_REQUEST) {
            /* Examine request */
            ret = examine_request(txn);

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
        /* Check that the client request has finished */
        if (!(frame->hd.flags & NGHTTP2_FLAG_END_STREAM)) break;

        /* Check that we still want to process the request */
        if (txn->req_body.flags & BODY_DISCARD) break;

        /* Process the requested method */
        if (txn->req_tgt.namespace->premethod) {
            ret = txn->req_tgt.namespace->premethod(txn);
        }
        if (!ret) {
            const struct method_t *meth_t =
                &txn->req_tgt.namespace->methods[txn->meth];

            ret = (*meth_t->proc)(txn, meth_t->params);
        }

        if (ret == HTTP_UNAUTHORIZED) {
            /* User must authenticate */
            ret = client_need_auth(txn, 0);
        }

        /* Handle errors (success responses handled by method functions) */
        if (ret) error_response(ret, txn);

        if (txn->flags.conn & CONN_CLOSE) {
            syslog(LOG_DEBUG, "nghttp2_submit_goaway()");

            nghttp2_submit_goaway(session, NGHTTP2_FLAG_NONE,
                                  nghttp2_session_get_last_proc_stream_id(
                                      txn->conn->http2_session),
                                  NGHTTP2_NO_ERROR, NULL, 0);
        }

        break;
    }

    return 0;
}

EXPORTED int http2_stream_close_cb(nghttp2_session *session, int32_t stream_id,
                                   uint32_t error_code __attribute__((unused)),
                                   void *user_data __attribute__((unused)))
{
    struct transaction_t *txn =
        nghttp2_session_get_stream_user_data(session, stream_id);

    syslog(LOG_DEBUG, "http2_stream_close_cb(id=%d)", stream_id);

    if (txn) {
        /* Memory cleanup */
        transaction_free(txn);
        free(txn);
    }
            
    return 0;
}

EXPORTED int http2_frame_not_send_cb(nghttp2_session *session,
                                     const nghttp2_frame *frame,
                                     int lib_error_code,
                                     void *user_data __attribute__((unused)))
{
    syslog(LOG_DEBUG, "http2_frame_not_send_cb(id=%d)", frame->hd.stream_id);

    /* Issue RST_STREAM so that stream does not hang around. */
    nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE,
                              frame->hd.stream_id, lib_error_code);

    return 0;
}


EXPORTED void http2_init(struct buf *serverinfo)
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
                                                &http2_send_cb);
    nghttp2_session_callbacks_set_recv_callback(http2_callbacks,
                                                &http2_recv_cb);
    nghttp2_session_callbacks_set_on_begin_headers_callback(http2_callbacks,
                                                            &http2_begin_headers_cb);
    nghttp2_session_callbacks_set_on_header_callback(http2_callbacks,
                                                     http2_header_cb);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(http2_callbacks,
                                                              http2_data_chunk_recv_cb);
    nghttp2_session_callbacks_set_on_frame_recv_callback(http2_callbacks,
                                                         http2_frame_recv_cb);
    nghttp2_session_callbacks_set_on_stream_close_callback(http2_callbacks,
                                                           &http2_stream_close_cb);
    nghttp2_session_callbacks_set_on_frame_not_send_callback(http2_callbacks,
                                                             &http2_frame_not_send_cb);

    /* Setup for ALPN */
    alpn_select_cb = &_alpn_select_cb;
}


EXPORTED void http2_done()
{
    nghttp2_session_callbacks_del(http2_callbacks);
}


EXPORTED int http2_preface(struct transaction_t *txn)
{
    if (http2_callbacks) {
        struct protstream *pin = txn->conn->pin;

        /* Force read of initial client input and check for HTTP/2 preface */
        prot_ungetc(prot_getc(pin), pin);
        if (!strncmp(NGHTTP2_CLIENT_MAGIC,
                     (const char *) pin->ptr, NGHTTP2_CLIENT_MAGIC_LEN)) {
            syslog(LOG_DEBUG, "HTTP/2 client connection preface");
            return 1;
        }
    }

    return 0;
}


EXPORTED int http2_start(struct http_connection *conn, struct transaction_t *txn)
{
    nghttp2_settings_entry iv = { NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100 };
    int r;

    r = nghttp2_session_server_new2((nghttp2_session **) &conn->http2_session,
                                    http2_callbacks, conn, conn->http2_options);
    if (r) {
        syslog(LOG_WARNING,
               "nghttp2_session_server_new: %s", nghttp2_strerror(r));
        return HTTP_SERVER_ERROR;
    }

    if (txn && (txn->flags.conn & CONN_UPGRADE)) {
        const char **hdr = spool_getheader(txn->req_hdrs, "HTTP2-Settings");
        if (!hdr || hdr[1]) return 0;

        /* base64url decode the settings.
           Use the SASL base64 decoder after replacing the encoded values
           for chars 62 and 63 and adding appropriate padding. */
        unsigned outlen;
        struct buf buf;
        buf_init_ro_cstr(&buf, hdr[0]);
        buf_replace_char(&buf, '-', '+');
        buf_replace_char(&buf, '_', '/');
        buf_appendmap(&buf, "==", (4 - (buf_len(&buf) % 4)) % 4);
        r = sasl_decode64(buf_base(&buf), buf_len(&buf),
                          (char *) buf_base(&buf), buf_len(&buf), &outlen);
        if (r != SASL_OK) {
            syslog(LOG_WARNING, "sasl_decode64 failed: %s",
                   sasl_errstring(r, NULL, NULL));
            buf_free(&buf);
            return HTTP_BAD_REQUEST;
        }
        r = nghttp2_session_upgrade2(conn->http2_session,
                                     (const uint8_t *) buf_base(&buf),
                                     outlen, txn->meth == METH_HEAD, NULL);
        buf_free(&buf);
        if (r) {
            syslog(LOG_WARNING, "nghttp2_session_upgrade: %s",
                   nghttp2_strerror(r));
            return HTTP_BAD_REQUEST;
        }

        /* tell client to start h2c upgrade (RFC 7540) */
        response_header(HTTP_SWITCH_PROT, txn);

        txn->flags.ver = VER_2;
        txn->http2.stream_id =
            nghttp2_session_get_last_proc_stream_id(conn->http2_session);
    }

    r = nghttp2_submit_settings(conn->http2_session, NGHTTP2_FLAG_NONE, &iv, 1);
    if (r) {
        syslog(LOG_ERR, "nghttp2_submit_settings: %s", nghttp2_strerror(r));
        return HTTP_SERVER_ERROR;
    }

    return 0;
}


EXPORTED void http2_end(struct http_connection *conn)
{
    nghttp2_option_del(conn->http2_options);
    nghttp2_session_del(conn->http2_session);
}


EXPORTED void http2_output(struct transaction_t *txn)
{
    if (nghttp2_session_want_write(txn->conn->http2_session)) {
        /* Send queued frame(s) */
        int r = nghttp2_session_send(txn->conn->http2_session);
        if (r) {
            syslog(LOG_ERR, "nghttp2_session_send: %s", nghttp2_strerror(r));
            txn->flags.conn = CONN_CLOSE;
        }
    }
}


EXPORTED void http2_input(struct transaction_t *txn)
{
    int want_read = nghttp2_session_want_read(txn->conn->http2_session);
    int goaway = txn->flags.conn & CONN_CLOSE;
    nghttp2_error_code err = goaway ? NGHTTP2_REFUSED_STREAM : NGHTTP2_NO_ERROR;

    syslog(LOG_DEBUG, "http2_input()  goaway: %d, eof: %d, want read: %d",
           goaway, txn->conn->pin->eof, want_read);

    if (want_read && !goaway) {
        /* Read frame(s) */
        int r = nghttp2_session_recv(txn->conn->http2_session);

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
                   nghttp2_strerror(r), prot_error(txn->conn->pin));
            goaway = 1;

            if (r == NGHTTP2_ERR_CALLBACK_FAILURE) {
                /* Client timeout */
                txn->error.desc = prot_error(txn->conn->pin);
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
            nghttp2_session_get_last_proc_stream_id(txn->conn->http2_session);

        syslog(LOG_WARNING, "%s, closing connection", txn->error.desc);

        syslog(LOG_DEBUG, "nghttp2_submit_goaway()");
        int r = nghttp2_submit_goaway(txn->conn->http2_session,
                                      NGHTTP2_FLAG_NONE, stream_id, err,
                                      (const uint8_t *) txn->error.desc,
                                      strlen(txn->error.desc));
        if (r) {
            syslog(LOG_ERR, "nghttp2_submit_goaway: %s", nghttp2_strerror(r));
        }
        else http2_output(txn);

        txn->flags.conn = CONN_CLOSE;
    }

    return;
}


EXPORTED void http2_add_header(struct transaction_t *txn,
                               const char  *name, struct buf *value)
{
    if (txn->http2.num_resp_hdrs >= HTTP2_MAX_HEADERS) {
        buf_free(value);
        return;
    }
    else {
        nghttp2_nv *nv = &txn->http2.resp_hdrs[txn->http2.num_resp_hdrs];

        free(nv->value);

        nv->namelen = strlen(name);
        nv->name = (uint8_t *) name;
        nv->valuelen = buf_len(value);
        nv->value = (uint8_t *) buf_release(value);
        nv->flags = NGHTTP2_NV_FLAG_NO_COPY_VALUE;

        txn->http2.num_resp_hdrs++;
    }
}


EXPORTED int http2_end_headers(struct transaction_t *txn, long code)
{
    uint8_t flags = NGHTTP2_FLAG_NONE;
    int r;

    syslog(LOG_DEBUG,
           "end_resp_headers(code = %ld, len = %ld, flags.te = %#x)",
           code, txn->resp_body.len, txn->flags.te);

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
           txn->http2.stream_id, flags);

    if (code) {
        r = nghttp2_submit_headers(txn->conn->http2_session,
                                   flags, txn->http2.stream_id, NULL,
                                   txn->http2.resp_hdrs,
                                   txn->http2.num_resp_hdrs, NULL);
    }
    else {
        r = nghttp2_submit_trailer(txn->conn->http2_session,
                                   txn->http2.stream_id,
                                   txn->http2.resp_hdrs,
                                   txn->http2.num_resp_hdrs);
    }
    if (r) {
        syslog(LOG_ERR, "%s: %s",
               code ? "nghttp2_submit headers" : "nghttp2_submit_trailers",
               nghttp2_strerror(r));
    }

    return r;
}


EXPORTED void http2_data_chunk(struct transaction_t *txn,
                               const char *data, unsigned datalen,
                               int last_chunk, MD5_CTX *md5ctx)
{
    static unsigned char md5[MD5_DIGEST_LENGTH];
    uint8_t flags = NGHTTP2_FLAG_END_STREAM;
    nghttp2_data_provider prd;
    int r;

    /* NOTE: The protstream that we use as the data source MUST remain
       available until the data source read callback has retrieved all data */
    prd.source.ptr = prot_readmap(data, datalen);
    prd.read_callback = http2_data_source_read_cb;

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
           txn->http2.stream_id, datalen, flags);

    r = nghttp2_submit_data(txn->conn->http2_session,
                            flags, txn->http2.stream_id, &prd);
    if (r) {
        syslog(LOG_ERR, "nghttp2_submit_data: %s", nghttp2_strerror(r));
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
}

#else /* !HAVE_NGHTTP2 */

void *http2_callbacks = NULL;

EXPORTED void http2_init(struct buf *serverinfo __attribute__((unused))) {}

EXPORTED void http2_done() {}

EXPORTED int http2_preface(struct transaction_t *txn __attribute__((unused)))
{
    return 0;
}

EXPORTED int http2_start(struct http_connection *conn __attribute__((unused)),
                         struct transaction_t *txn __attribute__((unused)))
{
    fatal("http2_start() called, but no Nghttp2", EC_SOFTWARE);
}

EXPORTED void http2_end(struct http_connection *conn __attribute__((unused))) {}

EXPORTED void http2_output(struct transaction_t *txn __attribute__((unused)))
{
    fatal("http2_output() called, but no Nghttp2", EC_SOFTWARE);
}

EXPORTED void http2_input(struct transaction_t *txn __attribute__((unused)))
{
    fatal("http2_input() called, but no Nghttp2", EC_SOFTWARE);
}

EXPORTED void http2_add_header(struct transaction_t *txn __attribute__((unused)),
                               const char *name __attribute__((unused)),
                               struct buf *value __attribute__((unused)))
{
    fatal("http2_add_header() called, but no Nghttp2", EC_SOFTWARE);
}

EXPORTED int http2_end_headers(struct transaction_t *txn __attribute__((unused)),
                               long code __attribute__((unused)))
{
    fatal("http2_end_headers() called, but no Nghttp2", EC_SOFTWARE);
}

EXPORTED void http2_data_chunk(struct transaction_t *txn __attribute__((unused)),
                               const char *data __attribute__((unused)),
                               unsigned datalen __attribute__((unused)),
                               int last_chunk __attribute__((unused)),
                               MD5_CTX *md5ctx __attribute__((unused)))
{
    fatal("http2_data_chunk() called, but no Nghttp2", EC_SOFTWARE);
}

#endif /* HAVE_NGHTTP2 */

