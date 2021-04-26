/* http_ws.c - WebSockets support functions
 *
 * Copyright (c) 1994-2020 Carnegie Mellon University.  All rights reserved.
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
#include "http_ws.h"
#include "util.h"

#ifdef HAVE_WSLAY

#include <errno.h>
#include <syslog.h>

#include <sasl/saslutil.h>

#include "http_h2.h"
#include "retry.h"
#include "telemetry.h"
#include "tok.h"
#include "xsha1.h"

/* generated headers are not necessarily in current directory */
#include "imap/http_err.h"


#define WS_CKEY_LEN  24
#define WS_AKEY_LEN  28
#define WS_GUID      "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


/* WebSocket Extension flags */
enum {
    EXT_PMCE_DEFLATE   = (1<<0)      /* Per-Message Compression Ext (RFC 7692) */
};

/* Supported WebSocket Extensions */
static struct ws_extension {
    const char *name;
    unsigned flag;
} extensions[] = {
#ifdef HAVE_ZLIB
    { "permessage-deflate", EXT_PMCE_DEFLATE },
#endif
    { NULL, 0 }
};


/* WebSocket channel context */
struct ws_context {
    wslay_event_context_ptr event;
    const char *accept_key;
    const char *protocol;
    ws_data_callback *data_cb;
    void *cb_rock;
    struct buf log;
    int log_tail;
    unsigned ext;                    /* Bitmask of negotiated extension(s) */

    struct buf h2_data;              /* Input data pointer when under HTTP/2 */

    union {
        struct {
            void *zstrm;             /* Zlib decompression context */
            unsigned no_context : 1;
            unsigned max_wbits;
        } deflate;
    } pmce;
};


static const char *wslay_opcode_as_str(enum wslay_opcode opcode)
{
    switch (opcode) {
    case WSLAY_CONTINUATION_FRAME:
        return "Continuation";
    case WSLAY_TEXT_FRAME:
        return "Text";
    case WSLAY_BINARY_FRAME:
        return "Binary";
    case WSLAY_CONNECTION_CLOSE:
        return "Close";
    case WSLAY_PING:
        return "Ping";
    case WSLAY_PONG:
        return "Pong";
    default:
        return "Unknown opcode";
    }
}

static const char *wslay_error_as_str(enum wslay_error err_code)
{
    switch (err_code) {
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
        return (err_code ? "Unknown error code" : "Success");
    }
}

static ssize_t h1_send_cb(wslay_event_context_ptr ev,
                          const uint8_t *data, size_t len,
                          int flags __attribute__((unused)),
                          void *user_data)
{
    struct transaction_t *txn = (struct transaction_t *) user_data;

    int r = prot_write(txn->conn->pout, (const char *) data, len);

    xsyslog(LOG_DEBUG, "WS send", "len=<%zu>, r=<%d>", len, r);

    if (r) {
        wslay_event_set_error(ev, WSLAY_ERR_CALLBACK_FAILURE);
        return -1;
    }

    return len;
}

static ssize_t h1_recv_cb(wslay_event_context_ptr ev,
                          uint8_t *buf, size_t len,
                          int flags __attribute__((unused)),
                          void *user_data)
{
    struct transaction_t *txn = (struct transaction_t *) user_data;
    struct protstream *pin = txn->conn->pin;
    ssize_t n;

    n = prot_read(pin, (char *) buf, len);
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

    xsyslog(LOG_DEBUG, "WS recv", "len=<%zu>, n=<%zd>, eof=<%d>, err=<%s>",
            len, n, pin->eof, pin->error ? pin->error : "");

    return n;
}

static ssize_t h2_send_cb(wslay_event_context_ptr ev,
                          const uint8_t *data, size_t len,
                          int flags, void *user_data)
{
    struct transaction_t *txn = (struct transaction_t *) user_data;
    int last_chunk = (txn->flags.conn & CONN_CLOSE) && !(flags & WSLAY_MSG_MORE);

    int r = http2_data_chunk(txn, (const char *) data, len,
                             last_chunk, NULL /* md5ctx */);

    xsyslog(LOG_DEBUG, "WS send", "len=<%zu>, r=<%d>", len, r);

    if (r) {
        wslay_event_set_error(ev, WSLAY_ERR_CALLBACK_FAILURE);
        return -1;
    }

    return len;
}

static ssize_t h2_recv_cb(wslay_event_context_ptr ev,
                          uint8_t *buf, size_t len,
                          int flags __attribute__((unused)),
                          void *user_data)
{
    struct transaction_t *txn = (struct transaction_t *) user_data;
    struct ws_context *ctx = (struct ws_context *) txn->ws_ctx;
    const char *dataptr = buf_base(&ctx->h2_data);
    size_t datalen = buf_len(&ctx->h2_data);
    ssize_t n;

    if (!dataptr) {
        /* New data has been read into the request body */
        dataptr = buf_base(&txn->req_body.payload);
        datalen = buf_len(&txn->req_body.payload);
    }

    if (!datalen) {
        /* No data */
        wslay_event_set_error(ev, WSLAY_ERR_WOULDBLOCK);

        /* Reset our input data pointer to NULL */
        buf_free(&ctx->h2_data);

        n = -1;
    }
    else {
        /* Don't return more data than requested */ 
        n = (datalen > len) ? len : datalen;

        /* Copy the input data into the output buffer */
        memcpy(buf, dataptr, n);

        /* Set our input data pointer to the remaining payload (if any) */
        buf_init_ro(&ctx->h2_data, dataptr + n, datalen - n);
    }

    xsyslog(LOG_DEBUG, "WS recv",
            "len=<%zu>, datalen=<%zu>, n=<%zd>", len, datalen, n);

    return n;
}


#ifdef HAVE_ZLIB
#include <zlib.h>

static void ws_zlib_init(struct transaction_t *txn, tok_t *params)
{
    struct ws_context *ctx = (struct ws_context *) txn->ws_ctx;
    unsigned client_max_wbits = MAX_WBITS;
    char *token;

    ctx->pmce.deflate.max_wbits = MAX_WBITS;

    /* Process parameters */
    while ((token = tok_next(params))) {
        char *value = strchr(token, '=');

        if (value) *value++ = '\0';

        if (!strcmp(token, "server_no_context_takeover")) {
            ctx->pmce.deflate.no_context = 1;
        }
        else if (!strcmp(token, "client_no_context_takeover")) {
            /* Don't HAVE to do anything here */
        }
        else if (!strcmp(token, "server_max_window_bits")) {
            if (value) {
                if (*value == '"') value++;
                ctx->pmce.deflate.max_wbits = atoi(value);
            }
            else ctx->pmce.deflate.max_wbits = 0;  /* force error */
        }
        else if (!strcmp(token, "client_max_window_bits")) {
            if (value) {
                if (*value == '"') value++;
                client_max_wbits = atoi(value);
            }
        }
    }

    /* (Re)configure compression context for raw deflate */
    if (txn->zstrm) deflateEnd(txn->zstrm);
    else txn->zstrm = xzmalloc(sizeof(z_stream));

    if (deflateInit2(txn->zstrm, Z_DEFAULT_COMPRESSION, Z_DEFLATED,
                     -ctx->pmce.deflate.max_wbits,
                     MAX_MEM_LEVEL, Z_DEFAULT_STRATEGY) != Z_OK) {
        free(txn->zstrm);
        txn->zstrm = NULL;
    }

    if (txn->zstrm) {
        /* Configure decompression context for raw deflate */
        ctx->pmce.deflate.zstrm = xzmalloc(sizeof(z_stream));
        if (inflateInit2(ctx->pmce.deflate.zstrm, -client_max_wbits) != Z_OK) {
            free(ctx->pmce.deflate.zstrm);
            ctx->pmce.deflate.zstrm = NULL;
        }
        else {
            /* Enable this PMCE */
            ctx->ext = EXT_PMCE_DEFLATE;
        }
    }
}

static void ws_zlib_done(struct ws_context *ctx)
{
    if (ctx->pmce.deflate.zstrm) {
        inflateEnd(ctx->pmce.deflate.zstrm);
        free(ctx->pmce.deflate.zstrm);
    }
}

static int zlib_decompress(struct transaction_t *txn,
                           const char *buf, unsigned len)
{
    struct ws_context *ctx = (struct ws_context *) txn->ws_ctx;
    z_stream *zstrm = ctx->pmce.deflate.zstrm;

    if (!zstrm) {
        xsyslog(LOG_ERR, "WS: no z_stream", NULL);
        return -1;
    }

    zstrm->next_in = (Bytef *) buf;
    zstrm->avail_in = len;

    buf_reset(&txn->zbuf);

    do {
        int zr;

        buf_ensure(&txn->zbuf, 4096);

        zstrm->next_out = (Bytef *) txn->zbuf.s + txn->zbuf.len;
        zstrm->avail_out = txn->zbuf.alloc - txn->zbuf.len;

        zr = inflate(zstrm, Z_SYNC_FLUSH);
        if (!(zr == Z_OK || zr == Z_STREAM_END || zr == Z_BUF_ERROR)) {
            /* something went wrong */
            xsyslog(LOG_ERR, "WS inflate error",
                    "zr=<%d>, msg=<%s>", zr, zstrm->msg);
            return -1;
        }

        txn->zbuf.len = txn->zbuf.alloc - zstrm->avail_out;

    } while (!zstrm->avail_out);

    return 0;
}
#else /* !HAVE_ZLIB */

#define MAX_WBITS 0

static void ws_zlib_init(struct transaction_t *txn __attribute__((unused)),
                         tok_t *params __attribute__((unused))) { }

static void ws_zlib_done(struct ws_context *ctx __attribute__((unused))) { }

static int zlib_decompress(struct transaction_t *txn __attribute__((unused)),
                           const char *buf __attribute__((unused)),
                           unsigned len __attribute__((unused)))
{
    fatal("zlib_decompress() called, but no Zlib", EX_SOFTWARE);
}

#endif /* HAVE_ZLIB */


static void on_frame_recv_start_cb(wslay_event_context_ptr ev __attribute__((unused)),
                                   const struct wslay_event_on_frame_recv_start_arg *arg,
                                   void *user_data __attribute__((unused)))
{
    xsyslog(LOG_DEBUG, "WS frame start",
            "opcode=<%s>, rsv=<0x%x>, fin=<0x%x>, length=<%ld>",
           wslay_opcode_as_str(arg->opcode), arg->rsv, arg->fin, arg->payload_length);
}

#define COMP_FAILED_ERR    "Compressing message failed"
#define DECOMP_FAILED_ERR  "Decompressing message failed"

static void on_msg_recv_cb(wslay_event_context_ptr ev,
                           const struct wslay_event_on_msg_recv_arg *arg,
                           void *user_data)
{
    struct transaction_t *txn = (struct transaction_t *) user_data;
    struct ws_context *ctx = (struct ws_context *) txn->ws_ctx;
    struct buf inbuf = BUF_INITIALIZER, outbuf = BUF_INITIALIZER;
    struct wslay_event_msg msgarg = { arg->opcode, NULL, 0 };
    uint8_t rsv = WSLAY_RSV_NONE;
    double cmdtime, nettime;
    const char *err_msg;
    const char *pmce_str = NULL;
    int r, err_code = 0;
    int logfd = -1;

    /* Place client request into a buf */
    buf_init_ro(&inbuf, (const char *) arg->msg, arg->msg_length);

    /* Decompress request, if necessary */
    if (wslay_get_rsv1(arg->rsv)) {
        if (ctx->ext & EXT_PMCE_DEFLATE) {
            pmce_str = "deflate";

            /* Add trailing 4 bytes */
            buf_appendmap(&inbuf, "\x00\x00\xff\xff", 4);

            r = zlib_decompress(txn, buf_base(&inbuf), buf_len(&inbuf));
            if (r) {
                xsyslog(LOG_ERR, "WS: zlib_decompress() failed", NULL);
            }
        }
        else {
            xsyslog(LOG_ERR, "WS: unknown PMCE", NULL);
            r = -1;
        }

        if (r) {
            err_code = WSLAY_CODE_PROTOCOL_ERROR;
            err_msg = DECOMP_FAILED_ERR;
            goto err;
        }

        buf_move(&inbuf, &txn->zbuf);
    }

    /* Log the uncompressed client request */
    buf_truncate(&ctx->log, ctx->log_tail);
    buf_appendcstr(&ctx->log, " (");
    if (txn->strm_ctx) {
        buf_printf(&ctx->log, "stream-id=%d; ",
                   http2_get_streamid(txn->strm_ctx));
    }
    buf_printf(&ctx->log, "opcode=%s; rsv=0x%x; length=%ld",
               wslay_opcode_as_str(arg->opcode), arg->rsv, arg->msg_length);
    if (pmce_str) {
        buf_printf(&ctx->log, " [%ld]; pmce=%s", buf_len(&inbuf), pmce_str);
        pmce_str = NULL;
    }

    switch (arg->opcode) {
    case WSLAY_CONNECTION_CLOSE:
        buf_printf(&ctx->log, "; status=%d; msg='%s'", arg->status_code,
                   buf_len(&inbuf) ? buf_cstring(&inbuf)+2 : "");
        txn->flags.conn = CONN_CLOSE;
        break;

    case WSLAY_TEXT_FRAME:
    case WSLAY_BINARY_FRAME:
        session_new_id();
        logfd = telemetry_log(httpd_userid, NULL, NULL, 0);
        if (logfd >= 0) {
            /* Telemetry logging */
            struct iovec iov[2];
            int niov = 0;

            assert(!buf_len(&txn->buf));
            buf_printf(&txn->buf, "<" TIME_T_FMT "<", time(NULL));  /* timestamp */
            WRITEV_ADD_TO_IOVEC(iov, niov,
                                buf_base(&txn->buf), buf_len(&txn->buf));
            WRITEV_ADD_TO_IOVEC(iov, niov, buf_base(&inbuf), buf_len(&inbuf));
            writev(logfd, iov, niov);
            buf_reset(&txn->buf);
        }

        /* Process the request */
        r = ctx->data_cb(arg->opcode, &inbuf, &outbuf, &ctx->log, &ctx->cb_rock);
        if (r) {
            switch (r) {
            case HTTP_NO_CONTENT:
                /* Nothing to output */
                break;
            case HTTP_SERVER_ERROR:
                err_code = WSLAY_CODE_INTERNAL_SERVER_ERROR;
                break;
            case HTTP_NOT_ACCEPTABLE:
                err_code = WSLAY_CODE_UNSUPPORTED_DATA;
                break;
            default:
                err_code = WSLAY_CODE_INVALID_FRAME_PAYLOAD_DATA;
                break;
            }

            err_msg = error_message(r);
            goto err;
        }

        if (logfd >= 0) {
            /* Telemetry logging */
            struct iovec iov[2];
            int niov = 0;

            assert(!buf_len(&txn->buf));
            buf_printf(&txn->buf, ">" TIME_T_FMT ">", time(NULL));  /* timestamp */
            WRITEV_ADD_TO_IOVEC(iov, niov,
                                buf_base(&txn->buf), buf_len(&txn->buf));
            WRITEV_ADD_TO_IOVEC(iov, niov, buf_base(&outbuf), buf_len(&outbuf));
            writev(logfd, iov, niov);
            buf_reset(&txn->buf);
        }

        /* Compress the server response, if supported by the client */
        size_t orig_len = buf_len(&outbuf);
        if (ctx->ext & EXT_PMCE_DEFLATE) {
            r = zlib_compress(txn,
                              ctx->pmce.deflate.no_context ? COMPRESS_START : 0,
                              buf_base(&outbuf), buf_len(&outbuf));
            if (r) {
                xsyslog(LOG_ERR, "WS: zlib_compress() failed", NULL);

                err_code = WSLAY_CODE_INTERNAL_SERVER_ERROR;
                err_msg = COMP_FAILED_ERR;
                goto err;
            }

            /* Trim the trailing 4 bytes */
            buf_truncate(&txn->zbuf, buf_len(&txn->zbuf) - 4);
            buf_move(&outbuf, &txn->zbuf);

            rsv |= WSLAY_RSV1_BIT;
            pmce_str = "deflate";
        }

        /* Queue the server response */
        msgarg.msg = (const uint8_t *) buf_base(&outbuf);
        msgarg.msg_length = buf_len(&outbuf);
        wslay_event_queue_msg_ex(ev, &msgarg, rsv);

        /* Log the server response */
        buf_printf(&ctx->log,
                   ") => \"Success\" (opcode=%s; rsv=0x%x; length=%ld",
                   wslay_opcode_as_str(msgarg.opcode), rsv, msgarg.msg_length);
        if (pmce_str) {
            buf_printf(&ctx->log, " [%ld]; pmce=%s", orig_len, pmce_str);
        }

        /* close out the telemetry log for this action */
        if (logfd >= 0) close(logfd);
        logfd = -1;

        break;
    }

  err:
    if (logfd >= 0) close(logfd);

    if (err_code) {
        size_t err_msg_len = strlen(err_msg);

        xsyslog(LOG_DEBUG, "WS close", NULL);
        wslay_event_queue_close(ev, err_code, (uint8_t *) err_msg, err_msg_len);

        /* Log the server response */
        buf_printf(&ctx->log,
                   ") => \"Fail\" (opcode=%s; rsv=0x%x; length=%ld"
                   "; status=%d; msg='%s'",
                   wslay_opcode_as_str(WSLAY_CONNECTION_CLOSE), rsv, err_msg_len,
                   err_code, err_msg);
    }

    /* Add timing stats */
    cmdtime_endtimer(&cmdtime, &nettime);
    buf_printf(&ctx->log, ") [timing: cmd=%f net=%f total=%f]",
               cmdtime, nettime, cmdtime + nettime);

    syslog(LOG_INFO, "%s", buf_cstring(&ctx->log));

    buf_free(&inbuf);
    buf_free(&outbuf);
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
    struct ws_context *ctx = (struct ws_context *) txn->ws_ctx;
    const char **ext_hdr =
        spool_getheader(txn->req_hdrs, "Sec-WebSocket-Extensions");
    int i;

    /* Look for interesting extensions.  Unknown == ignore */
    for (i = 0; ext_hdr && ext_hdr[i]; i++) {
        tok_t ext = TOK_INITIALIZER(ext_hdr[i], ",", TOK_TRIMLEFT|TOK_TRIMRIGHT);
        char *token;

        while ((token = tok_next(&ext))) {
            struct ws_extension *extp = extensions;
            tok_t param;

            tok_initm(&param, token, ";", TOK_TRIMLEFT|TOK_TRIMRIGHT);
            token = tok_next(&param);

            /* Locate a matching extension */
            while (extp->name && strcmp(token, extp->name)) extp++;

            /* Check if client wants per-message compression */
            if (config_getswitch(IMAPOPT_HTTPALLOWCOMPRESS)) {
                if (extp->flag == EXT_PMCE_DEFLATE) {
                    ws_zlib_init(txn, &param);
                }

                if (ctx->ext) {
                    /* Compression has been enabled */
                    wslay_event_config_set_allowed_rsv_bits(ctx->event,
                                                            WSLAY_RSV1_BIT);
                }
            }
            tok_fini(&param);
        }

        tok_fini(&ext);
    }
}


HIDDEN int ws_start_channel(struct transaction_t *txn,
                            const char *protocol, ws_data_callback *data_cb)
{
    int r, resp_code;
    const char **hdr, *accept_key = NULL;
    wslay_event_context_ptr ev;
    struct ws_context *ctx;
    struct wslay_event_callbacks callbacks = {
        NULL, /* recv (assigned below)            */
        NULL, /* send (assigned below)            */
        NULL, /* genmask                          */
        NULL, /* on_frame_recv_start (debug only) */
        NULL, /* on_frame_recv_chunk              */
        NULL, /* on_frame_recv_end                */
        on_msg_recv_cb
    };

    /* Check for supported WebSocket version */
    hdr = spool_getheader(txn->req_hdrs, "Sec-WebSocket-Version");
    if (!hdr) {
        txn->error.desc = "Missing WebSocket version";
        return HTTP_BAD_REQUEST;
    }
    else if (hdr[1]) {
        txn->error.desc = "Multiple WebSocket versions";
        return HTTP_BAD_REQUEST;
    }
    else if (strcmp(hdr[0], WS_VERSION)) {
        txn->error.desc = "Unsupported WebSocket version";
        return HTTP_UPGRADE;
    }

    if (protocol) {
        /* Check for supported WebSocket subprotocol */
        int i, found = 0;

        hdr = spool_getheader(txn->req_hdrs, "Sec-WebSocket-Protocol");
        if (!hdr) {
            txn->error.desc = "Missing WebSocket protocol";
            return HTTP_BAD_REQUEST;
        }

        for (i = 0; !found && hdr[i]; i++) {
            tok_t tok = TOK_INITIALIZER(hdr[i], ",", TOK_TRIMLEFT|TOK_TRIMRIGHT);
            char *token;

            while ((token = tok_next(&tok))) {
                if (!strcmp(token, protocol)) {
                    found = 1;
                    break;
                }
            }
            tok_fini(&tok);
        }
        if (!found) {
            txn->error.desc = "Unsupported WebSocket protocol";
            return HTTP_BAD_REQUEST;
        }
    }

    if (txn->flags.ver == VER_1_1) {
        unsigned char sha1buf[SHA1_DIGEST_LENGTH];

        /* Check for WebSocket client key */
        hdr = spool_getheader(txn->req_hdrs, "Sec-WebSocket-Key");
        if (!hdr) {
            txn->error.desc = "Missing WebSocket client key";
            return HTTP_BAD_REQUEST;
        }
        else if (hdr[1]) {
            txn->error.desc = "Multiple WebSocket client keys";
            return HTTP_BAD_REQUEST;
        }
        else if (strlen(hdr[0]) != WS_CKEY_LEN) {
            txn->error.desc = "Invalid WebSocket client key";
            return HTTP_BAD_REQUEST;
        }

        /* Create WebSocket accept key */
        buf_setcstr(&txn->buf, hdr[0]);
        buf_appendcstr(&txn->buf, WS_GUID);
        xsha1((u_char *) buf_base(&txn->buf), buf_len(&txn->buf), sha1buf);

        buf_ensure(&txn->buf, WS_AKEY_LEN+1);
        accept_key = buf_base(&txn->buf);

        r = sasl_encode64((char *) sha1buf, SHA1_DIGEST_LENGTH,
                          (char *) accept_key, WS_AKEY_LEN+1, NULL);
        if (r != SASL_OK) {
            xsyslog(LOG_WARNING, "WS base64 encode failed", "r=<%d>", r);
        }

        /* Link the WS context into the connection so we can
           properly close the WS during an abnormal shut_down() */
        txn->conn->ws_ctx = &txn->ws_ctx;

        callbacks.recv_callback = &h1_recv_cb;
        callbacks.send_callback = &h1_send_cb;

        resp_code = HTTP_SWITCH_PROT;
    }
    else {
        /* HTTP/2 - Treat WS data as chunked response */
        txn->flags.te = TE_CHUNKED;

        callbacks.recv_callback = &h2_recv_cb;
        callbacks.send_callback = &h2_send_cb;

        resp_code = HTTP_OK;
    }

    if (config_getswitch(IMAPOPT_DEBUG)) {
        callbacks.on_frame_recv_start_callback = &on_frame_recv_start_cb;
    }

    /* Create server context */
    r = wslay_event_context_server_init(&ev, &callbacks, txn);
    if (r) {
        xsyslog(LOG_WARNING, "WS init failed", "err=<%s>", wslay_error_as_str(r));
        return HTTP_SERVER_ERROR;
    }

    /* Create channel context */
    ctx = xzmalloc(sizeof(struct ws_context));
    ctx->event = ev;
    ctx->accept_key = accept_key;
    ctx->protocol = protocol;
    ctx->data_cb = data_cb;
    txn->ws_ctx = ctx;

    /* Check for supported WebSocket extensions */
    parse_extensions(txn);

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
    buf_printf(&ctx->log, "; \"WebSocket/%s via %s\"",
               protocol ? protocol : "echo" , txn->req_line.ver);
    ctx->log_tail = buf_len(&ctx->log);

    /* Tell client that WebSocket negotiation has succeeded */
    response_header(resp_code, txn);

    /* Force the response to the client immediately */
    prot_flush(txn->conn->pout);

    /* Set connection as non-blocking */
    prot_NONBLOCK(txn->conn->pin);

    /* Don't do telemetry logging in prot layer */
    prot_setlog(txn->conn->pin, PROT_NO_FD);
    prot_setlog(txn->conn->pout, PROT_NO_FD);

    return 0;
}


HIDDEN void ws_add_resp_hdrs(struct transaction_t *txn)
{
    struct ws_context *ctx = (struct ws_context *) txn->ws_ctx;

    if (!ctx) {
        simple_hdr(txn, "Sec-WebSocket-Version", "%s", WS_VERSION);
        return;
    }

    if (ctx->accept_key) {
        simple_hdr(txn, "Sec-WebSocket-Accept", "%s", ctx->accept_key);
    }

    if (ctx->protocol) {
        simple_hdr(txn, "Sec-WebSocket-Protocol", "%s", ctx->protocol);
    }

    if (ctx->ext & EXT_PMCE_DEFLATE) {
        simple_hdr(txn, "Sec-WebSocket-Extensions",
                   "permessage-deflate%s; server_max_window_bits=%u",
                   ctx->pmce.deflate.no_context ?
                   "; server_no_context_takeover" : "",
                   ctx->pmce.deflate.max_wbits);
    }
}


HIDDEN void ws_end_channel(void **ws_ctx, const char *msg)
{
    if (!ws_ctx || !*ws_ctx) return;

    struct ws_context *ctx = (struct ws_context *) *ws_ctx;
    wslay_event_context_ptr ev = ctx->event;

    /* Close the WS if we haven't already */
    if (!wslay_event_get_close_sent(ev)) {
        int r;

        if (!msg) msg = "Server unavailable";

        xsyslog(LOG_DEBUG, "WS close", "msg=<%s>", msg);

        r = wslay_event_queue_close(ev, WSLAY_CODE_GOING_AWAY,
                                    (uint8_t *) msg, strlen(msg));
        if (r) {
            xsyslog(LOG_ERR, "WS close failed",
                    "err=<%s>", wslay_error_as_str(r));
        }
        else {
            r = wslay_event_send(ev);
            if (r) {
                xsyslog(LOG_ERR, "WS send failed",
                        "err=<%s>", wslay_error_as_str(r));
            }
        }
    }

    wslay_event_context_free(ev);
    buf_free(&ctx->log);

    if (ctx->cb_rock) {
        /* Cleanup cb_rock */
        ctx->data_cb(0, NULL, NULL, NULL, &ctx->cb_rock);
    }

    ws_zlib_done(ctx);

    free(ctx);

    *ws_ctx = NULL;
}


static void ws_output(struct transaction_t *txn)
{
    struct ws_context *ctx = (struct ws_context *) txn->ws_ctx;
    wslay_event_context_ptr ev = ctx->event;
    int want_read = wslay_event_want_read(ev);
    int want_write = wslay_event_want_write(ev);

    errno = 0;

    xsyslog(LOG_DEBUG, "WS output", "eof=<%d>, want read=<%d>, want write=<%d>",
            txn->conn->pin->eof, want_read, want_write);

    if (want_write) {
        /* Send queued frame(s) */
        int r = wslay_event_send(ev);
        if (r) {
            xsyslog(LOG_ERR, "WS send failed", "err=<%s>", wslay_error_as_str(r));
            txn->flags.conn = CONN_CLOSE;
        }
    }
    else if (!want_read) {
        /* Connection is done */
        xsyslog(LOG_DEBUG, "closing connection", NULL);
        txn->flags.conn = CONN_CLOSE;
    }
}


HIDDEN void ws_input(struct transaction_t *txn)
{
    struct ws_context *ctx = (struct ws_context *) txn->ws_ctx;
    wslay_event_context_ptr ev = ctx->event;
    int want_read = wslay_event_want_read(ev);
    int want_write = wslay_event_want_write(ev);
    int goaway = txn->flags.conn & CONN_CLOSE;

    errno = 0;

    xsyslog(LOG_DEBUG, "WS input", "eof=<%d>, want read=<%d>, want write=<%d>",
            txn->conn->pin->eof, want_read, want_write);

    if (want_read && !goaway) {
        /* Read frame(s) */
        int r = wslay_event_recv(ev);

        if (!r) {
            /* Successfully received frames */
            xsyslog(LOG_DEBUG, "WS recv: success", NULL);

            /* Reset request payload buffer */
            buf_reset(&txn->req_body.payload);
        }
        else if (r == WSLAY_ERR_NO_MORE_MSG) {
            /* Client closed connection */
            xsyslog(LOG_DEBUG, "WS: client closed connection", NULL);
            txn->flags.conn = CONN_CLOSE;
        }
        else {
            /* Failure */
            xsyslog(LOG_DEBUG, "WS recv failed", "err=<%s>, prot err=<%s>",
                    wslay_error_as_str(r), prot_error(txn->conn->pin));
            goaway = 1;

            if (r == WSLAY_ERR_CALLBACK_FAILURE) {
                /* Client timeout */
                txn->error.desc = prot_error(txn->conn->pin);
            }
            else {
                txn->error.desc = wslay_error_as_str(r);
            }
        }
    }

    if (goaway) {
        /* Tell client we are closing session */
        xsyslog(LOG_WARNING, "closing connection", "msg=<%s>", txn->error.desc);

        xsyslog(LOG_DEBUG, "WS close", NULL);
        int r = wslay_event_queue_close(ev, WSLAY_CODE_GOING_AWAY,
                                        (uint8_t *) txn->error.desc,
                                        strlen(txn->error.desc));
        if (r) {
            xsyslog(LOG_ERR, "WS close failed", "err=<%s", wslay_error_as_str(r));
        }

        txn->flags.conn = CONN_CLOSE;
    }

    /* Write frame(s) */
    ws_output(txn);

    return;
}

#else /* !HAVE_WSLAY */

HIDDEN void ws_init(struct buf *serverinfo __attribute__((unused))) {}

HIDDEN int ws_enabled()
{
    return 0;
}

HIDDEN void ws_done() {}

HIDDEN int ws_start_channel(struct transaction_t *txn __attribute__((unused)),
                            const char *protocol __attribute__((unused)),
                            ws_data_callback *data_cb __attribute__((unused)))
{
    fatal("ws_start() called, but no Wslay", EX_SOFTWARE);
}

HIDDEN void ws_add_resp_hdrs(struct transaction_t *txn __attribute__((unused)))
{
}

HIDDEN void ws_end_channel(void **ws_ctx __attribute__((unused)),
                           const char *msg __attribute__((unused)))
{
}

HIDDEN void ws_input(struct transaction_t *txn __attribute__((unused)))
{
    fatal("ws_input() called, but no Wslay", EX_SOFTWARE);
}

#endif /* HAVE_WSLAY */
