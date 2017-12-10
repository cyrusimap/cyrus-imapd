/* http_ws.c - WebSockets support functions
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
#include "util.h"

#ifdef HAVE_WSLAY

#include <errno.h>
#include <syslog.h>

#include <sasl/saslutil.h>

#include "http_h2.h"
#include "http_ws.h"
#include "tok.h"
#include "xsha1.h"

/* generated headers are not necessarily in current directory */
#include "imap/http_err.h"


#define WS_CKEY_LEN  24
#define WS_AKEY_LEN  28
#define WS_GUID      "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


/* WebSocket Extension flags */
enum {
    WS_EXT_PMCE_DEFLATE = (1<<0)     /* Per-Message Compression Ext (RFC 7692) */
};


/* WebSocket channel context */
struct ws_context {
    wslay_event_context_ptr event;
    struct buf log;
    int log_tail;
};


static const char *wslay_str_opcode(uint8_t opcode)
{
    switch (opcode) {
    case 0x0u:
        return "Continuation";
    case 0x1u:
        return "Text";
    case 0x2u:
        return "Binary";
    case 0x8u:
        return "Close";
    case 0x9u:
        return "Ping";
    case 0xau:
        return "Pong";
    default:
        return "Unknown opcode";
    }
}

static const char *wslay_strerror(int err_code)
{
    switch (err_code) {
    case 0:
        return "Success";
    case WSLAY_ERR_WANT_READ:
        return "Want to read more data from peer";
    case WSLAY_ERR_WANT_WRITE:
        return "Want to send more data to peer";
    case WSLAY_ERR_PROTO:
        return "Protocol error";
    case WSLAY_ERR_INVALID_ARGUMENT:
        return "Message is invalid";
    case WSLAY_ERR_INVALID_CALLBACK:
        return "Invalid callback";
    case WSLAY_ERR_NO_MORE_MSG:
        return "Could not queue message";
    case WSLAY_ERR_CALLBACK_FAILURE:
        return "The user callback function failed";
    case WSLAY_ERR_WOULDBLOCK:
        return "Operation would block";
    case WSLAY_ERR_NOMEM:
        return "Out of memory";
    default:
        return "Unknown error code";
    }
}

static ssize_t send_cb(wslay_event_context_ptr ev,
                       const uint8_t *data, size_t len,
                       int flags __attribute__((unused)),
                       void *user_data)
{
    struct transaction_t *txn = (struct transaction_t *) user_data;
    int r;

    r = prot_write(txn->conn->pout, (const char *) data, len);

    syslog(LOG_DEBUG, "ws_send_cb(%zu): %d", len, r);

    if (r) {
        wslay_event_set_error(ev, WSLAY_ERR_CALLBACK_FAILURE);
        return -1;
    }

    return len;
}

static ssize_t recv_cb(wslay_event_context_ptr ev,
                       uint8_t *buf, size_t len,
                       int flags __attribute__((unused)),
                       void *user_data)
{
    struct transaction_t *txn = (struct transaction_t *) user_data;
    struct protstream *pin = txn->conn->pin;
    ssize_t n;

    prot_NONBLOCK(pin);

    n = prot_read(txn->conn->pin, (char *) buf, len);
    if (!n) {
        /* No data */
        if (pin->eof)
            wslay_event_set_error(ev, WSLAY_ERR_NO_MORE_MSG);
        else if (pin->error)
            wslay_event_set_error(ev, WSLAY_ERR_CALLBACK_FAILURE);
        else
            wslay_event_set_error(ev, WSLAY_ERR_WOULDBLOCK);

        n = -1;
    }

    syslog(LOG_DEBUG,
           "ws_recv_cb(%zu): n = %zd, eof = %d, err = '%s', errno = %m",
           len, n, pin->eof, pin->error ? pin->error : "");

    return n;
}

void on_msg_recv_cb(wslay_event_context_ptr ev,
                    const struct wslay_event_on_msg_recv_arg *arg,
                    void *user_data)
{
    struct transaction_t *txn = (struct transaction_t *) user_data;
    struct ws_context *ctx = (struct ws_context *) txn->ws_ctx;

    /* Log the client request */
    buf_truncate(&ctx->log, ctx->log_tail);
    buf_printf(&ctx->log, " Recv(opcode=%s, rsv=0x%x, length=%ld",
               wslay_str_opcode(arg->opcode), arg->rsv, arg->msg_length);
    switch (arg->opcode) {
    case WSLAY_CONNECTION_CLOSE:
        buf_printf(&ctx->log, ", status=%d", arg->status_code);

        GCC_FALLTHROUGH

    case WSLAY_TEXT_FRAME:
        buf_printf(&ctx->log, ", msg='%s'", arg->msg ? (char *) arg->msg : "");
        break;
    }
    buf_putc(&ctx->log, ')');


    /* XXX  Do actual work here.
     *
     * For now, just echo back non-control messages.
     * Can be tested with:
     *   http://demos.kaazing.com/echo/
     *   https://github.com/websockets/wscat
     */
    if (!wslay_is_ctrl_frame(arg->opcode)) {
        struct wslay_event_msg msgarg = {
            arg->opcode, arg->msg, arg->msg_length
        };
        uint8_t rsv = WSLAY_RSV_NONE;

        wslay_event_queue_msg_ex(ev, &msgarg, rsv);


        /* Log the server response */
        buf_printf(&ctx->log, " => Send(opcode=%s, rsv=0x%x, length=%ld",
                   wslay_str_opcode(msgarg.opcode), rsv, msgarg.msg_length);
        if (arg->opcode == WSLAY_TEXT_FRAME) {
            buf_printf(&ctx->log, ", msg='%s'",
                       msgarg.msg ? (char *) msgarg.msg : "");
        }
        buf_putc(&ctx->log, ')');
    }

    syslog(LOG_INFO, "%s", buf_cstring(&ctx->log));
}


HIDDEN void ws_init(struct buf *serverinfo)
{
    buf_printf(serverinfo, " Wslay/%s", WSLAY_VERSION);
}


HIDDEN int ws_enabled()
{
    return 1;
}


HIDDEN void ws_done()
{
    return;
}


/* Parse Sec-WebSocket-Extensions header(s) for interesting extensions */
static void parse_extensions(struct transaction_t *txn)
{
    const char **ext =
        spool_getheader(txn->req_hdrs, "Sec-WebSocket-Extensions");
    int i;

    /* Look for interesting extensions.  Unknown == ignore */
    for (i = 0; ext && ext[i]; i++) {
        tok_t tok = TOK_INITIALIZER(ext[i], ",", TOK_TRIMLEFT|TOK_TRIMRIGHT);
        char *token;

        while ((token = tok_next(&tok))) {
            /* Check if client wants per-message compression */
            if (!strncmp("permessage-deflate", token, strcspn(token, " ;"))) {
//                txn->flags.ws_ext = WS_EXT_PMCE_DEFLATE;
            }
        }

        tok_fini(&tok);
    }
}


HIDDEN int ws_start_channel(struct transaction_t *txn)
{
    int r, ret = 0;
    const char **hdr;
    unsigned char sha1buf[SHA1_DIGEST_LENGTH];
    wslay_event_context_ptr ev;
    struct ws_context *ctx;
    struct wslay_event_callbacks callbacks = {
        recv_cb,
        send_cb,
        NULL,
        NULL,
        NULL,
        NULL,
        on_msg_recv_cb
    };

    /* Check for proper request method */
    if (txn->meth != METH_GET) goto err;

    /* Check for supported WebSocket version */
    hdr = spool_getheader(txn->req_hdrs, "Sec-WebSocket-Version");
    if (!hdr || hdr[1] || strcmp(hdr[0], WS_VERSION)) goto err;

    /* Check for supported WebSocket subprotocol */
    hdr = spool_getheader(txn->req_hdrs, "Sec-WebSocket-Protocol");
    /* XXX  TODO - based on CalConnect work */

    /* Check for WebSocket client key */
    hdr = spool_getheader(txn->req_hdrs, "Sec-WebSocket-Key");
    if (!hdr || hdr[1] || strlen(hdr[0]) != WS_CKEY_LEN) goto err;

    /* Create our accept key */
    buf_setcstr(&txn->buf, hdr[0]);
    buf_appendcstr(&txn->buf, WS_GUID);
    xsha1((unsigned char *) buf_base(&txn->buf), buf_len(&txn->buf), sha1buf);

    r = sasl_encode64((char *) sha1buf, SHA1_DIGEST_LENGTH,
                      (char *) buf_base(&txn->buf), WS_AKEY_LEN+1, NULL);
    if (r != SASL_OK) {
        syslog(LOG_WARNING, "sasl_encode64 failed: %s",
               sasl_errstring(r, NULL, NULL));
        ret = HTTP_SERVER_ERROR;
        goto err;
    }
    buf_truncate(&txn->buf, WS_AKEY_LEN);

    r = wslay_event_context_server_init(&ev, &callbacks, txn);
    if (r) {
        syslog(LOG_WARNING,
               "wslay_event_context_init: %s", wslay_strerror(r));
        ret = HTTP_SERVER_ERROR;
        goto err;
    }

    /* Check for supported WebSocket extensions */
    parse_extensions(txn);

    /* Create channel context */
    ctx = xzmalloc(sizeof(struct ws_context));
    ctx->event = ev;
    txn->ws_ctx = ctx;

    /* Prepare log buffer */

    /* Add client data */
    buf_printf(&ctx->log, "%s", txn->conn->clienthost);
    if (httpd_userid) buf_printf(&ctx->log, " as \"%s\"", httpd_userid);
    if ((hdr = spool_getheader(txn->req_hdrs, "User-Agent"))) {
        buf_printf(&ctx->log, " with \"%s\"", hdr[0]);
        if ((hdr = spool_getheader(txn->req_hdrs, "X-Client")))
            buf_printf(&ctx->log, " by \"%s\"", hdr[0]);
        else if ((hdr = spool_getheader(txn->req_hdrs, "X-Requested-With")))
            buf_printf(&ctx->log, " by \"%s\"", hdr[0]);
    }

    /* Add request-line */
    buf_printf(&ctx->log, "; \"%s %s %s/%s\"",
               txn->req_line.meth, txn->req_line.uri, WS_TOKEN, WS_VERSION);
    ctx->log_tail = buf_len(&ctx->log);

    /* Tell client to start WebSocket upgrade (RFC 6455) */
    return HTTP_SWITCH_PROT;

  err:
    txn->flags.conn = CONN_CLOSE;
    return ret ? ret : HTTP_BAD_REQUEST;
}


HIDDEN void ws_end_channel(void *ws_ctx)
{
    struct ws_context *ctx = (struct ws_context *) ws_ctx;

    if (!ctx) return;
    
    wslay_event_context_free(ctx->event);
    buf_free(&ctx->log);
}


HIDDEN void ws_output(struct transaction_t *txn)
{
    struct ws_context *ctx = (struct ws_context *) txn->ws_ctx;
    wslay_event_context_ptr ev = ctx->event;
    int want_write = wslay_event_want_write(ev);

    syslog(LOG_DEBUG, "ws_output()  eof: %d, want write: %d",
           txn->conn->pin->eof, want_write);

    if (want_write) {
        /* Send queued frame(s) */
        int r = wslay_event_send(ev);
        if (r) {
            syslog(LOG_ERR, "wslay_event_send: %s", wslay_strerror(r));
            txn->flags.conn = CONN_CLOSE;
        }
    }
}


HIDDEN void ws_input(struct transaction_t *txn)
{
    struct ws_context *ctx = (struct ws_context *) txn->ws_ctx;
    wslay_event_context_ptr ev = ctx->event;
    int want_read = wslay_event_want_read(ev);
    int want_write = wslay_event_want_write(ev);

    syslog(LOG_DEBUG, "ws_input()  eof: %d, want read: %d, want write: %d",
           txn->conn->pin->eof, want_read, want_write);

    if (want_read) {
        /* Read frame(s) */
        int r = wslay_event_recv(ev);

        if (!r) {
            /* Successfully received frames */
            syslog(LOG_DEBUG, "ws_event_recv: success");
        }
        else if (r == WSLAY_ERR_NO_MORE_MSG) {
            /* Client closed connection */
            syslog(LOG_DEBUG, "client closed connection");
            txn->flags.conn = CONN_CLOSE;
        }
        else {
            /* Failure */
            syslog(LOG_DEBUG, "ws_event_recv: %s (%s)",
                   wslay_strerror(r), prot_error(txn->conn->pin));

            if (r == WSLAY_ERR_CALLBACK_FAILURE) {
                /* Client timeout */
                txn->error.desc = prot_error(txn->conn->pin);
            }
            else {
                txn->error.desc = wslay_strerror(r);
            }

            /* Tell client we are closing session */
            syslog(LOG_WARNING, "%s, closing connection", txn->error.desc);

            syslog(LOG_DEBUG, "wslay_event_queue_close()");
            r = wslay_event_queue_close(ev, WSLAY_CODE_GOING_AWAY,
                                        (uint8_t *) txn->error.desc,
                                        strlen(txn->error.desc));
            if (r) {
                syslog(LOG_ERR,
                       "wslay_event_queue_close: %s", wslay_strerror(r));
            }
            else ws_output(txn);

            txn->flags.conn = CONN_CLOSE;
        }
    }
    else if (!want_write) {
        /* Connection is done */
        syslog(LOG_DEBUG, "connection closed");
        txn->flags.conn = CONN_CLOSE;
    }

    return;
}

#else /* !HAVE_WSLAY */

HIDDEN void ws_init(struct buf *serverinfo __attribute__((unused))) {}

HIDDEN int ws_enabled()
{
    return 0;
}

HIDDEN void ws_done() {}

HIDDEN int ws_start_channel(struct http_connection *conn __attribute__((unused)),
                            struct transaction_t *txn __attribute__((unused)))
{
    fatal("ws_start() called, but no Wslay", EC_SOFTWARE);
}

HIDDEN void ws_end_channel(struct transaction_t *txn __attribute__((unused))) {}

HIDDEN void ws_output(struct transaction_t *txn __attribute__((unused)))
{
    fatal("ws_output() called, but no Wslay", EC_SOFTWARE);
}

HIDDEN void ws_input(struct transaction_t *txn __attribute__((unused)))
{
    fatal("ws_input() called, but no Wslay", EC_SOFTWARE);
}

#endif /* HAVE_WSLAY */

