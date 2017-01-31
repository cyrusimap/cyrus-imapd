/* httpd.c -- HTTP/WebDAV/CalDAV server protocol parsing
 *
 * Copyright (c) 1994-2011 Carnegie Mellon University.  All rights reserved.
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


#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/param.h>
#include <syslog.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#include "prot.h"

#include <sasl/sasl.h>
#include <sasl/saslutil.h>

#include "httpd.h"
#include "http_proxy.h"

#include "acl.h"
#include "assert.h"
#include "util.h"
#include "iptostring.h"
#include "global.h"
#include "tls.h"
#include "map.h"

#include "acl.h"
#include "exitcodes.h"
#include "imapd.h"
#include "proc.h"
#include "version.h"
#include "xstrlcpy.h"
#include "xstrlcat.h"
#include "sync_log.h"
#include "telemetry.h"
#include "backend.h"
#include "proxy.h"
#include "userdeny.h"
#include "message.h"
#include "idle.h"
#include "times.h"
#include "tok.h"
#include "wildmat.h"
#include "md5.h"

/* generated headers are not necessarily in current directory */
#include "imap/http_err.h"

#ifdef WITH_DAV
#include "http_dav.h"
#endif

#include <libxml/tree.h>
#include <libxml/HTMLtree.h>
#include <libxml/uri.h>

#ifdef HAVE_ZLIB
#include <zlib.h>
#endif /* HAVE_ZLIB */

#ifdef HAVE_BROTLI
#include <brotli/encode.h>

BrotliEncoderState *brotli_init()
{
    BrotliEncoderState *brotli = BrotliEncoderCreateInstance(NULL, NULL, NULL);

    if (brotli) {
        BrotliEncoderSetParameter(brotli, BROTLI_PARAM_MODE,
                                  BROTLI_DEFAULT_MODE);
        BrotliEncoderSetParameter(brotli, BROTLI_PARAM_QUALITY,
                                  BROTLI_DEFAULT_QUALITY);
        BrotliEncoderSetParameter(brotli, BROTLI_PARAM_LGWIN,
                                  BROTLI_DEFAULT_WINDOW);
        BrotliEncoderSetParameter(brotli, BROTLI_PARAM_LGBLOCK, 0);
    }

    return brotli;
}
#endif /* HAVE_BROTLI */


static const char tls_message[] =
    HTML_DOCTYPE
    "<html>\n<head>\n<title>TLS Required</title>\n</head>\n" \
    "<body>\n<h2>TLS is required prior to authentication</h2>\n" \
    "Use <a href=\"%s\">%s</a> instead.\n" \
    "</body>\n</html>\n";

extern int optind;
extern char *optarg;
extern int opterr;

#ifdef HAVE_SSL
static SSL *tls_conn;
#endif /* HAVE_SSL */

sasl_conn_t *httpd_saslconn; /* the sasl connection context */

static struct wildmat *allow_cors = NULL;
int httpd_timeout, httpd_keepalive;
char *httpd_userid = NULL;
char *httpd_extrafolder = NULL;
char *httpd_extradomain = NULL;
struct auth_state *httpd_authstate = 0;
int httpd_userisadmin = 0;
int httpd_userisproxyadmin = 0;
int httpd_userisanonymous = 1;
static const char *httpd_clienthost = "[local]";
const char *httpd_localip = NULL, *httpd_remoteip = NULL;
struct protstream *httpd_out = NULL;
struct protstream *httpd_in = NULL;
struct protgroup *protin = NULL;
static int httpd_logfd = -1;

static sasl_ssf_t extprops_ssf = 0;
int https = 0;
int httpd_tls_done = 0;
int httpd_tls_required = 0;
unsigned avail_auth_schemes = 0; /* bitmask of available auth schemes */
unsigned long config_httpmodules;
int config_httpprettytelemetry;

static time_t compile_time;
struct buf serverinfo = BUF_INITIALIZER;

int ignorequota = 0;
int apns_enabled = 0;

#ifdef HAVE_NGHTTP2

static nghttp2_session_callbacks *http2_callbacks = NULL;

#if OPENSSL_VERSION_NUMBER >= 0x10002000L
static int alpn_select_cb(SSL *ssl __attribute__((unused)),
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
#endif /* OPENSSL_VERSION_NUMBER >= 0x10002000L */

static ssize_t http2_send_cb(nghttp2_session *session __attribute__((unused)),
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

static ssize_t http2_recv_cb(nghttp2_session *session __attribute__((unused)),
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

static ssize_t http2_data_source_read_cb(nghttp2_session *session __attribute__((unused)),
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

    if (!s->cnt) *data_flags |= NGHTTP2_DATA_FLAG_EOF;

    return n;
}

static int http2_begin_headers_cb(nghttp2_session *session,
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

static int http2_header_cb(nghttp2_session *session,
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

static int http2_data_chunk_recv_cb(nghttp2_session *session,
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

static int examine_request(struct transaction_t *txn);

static int client_need_auth(struct transaction_t *txn, int sasl_result);

static void transaction_free(struct transaction_t *txn);

static int http2_frame_recv_cb(nghttp2_session *session,
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

static int http2_stream_close_cb(nghttp2_session *session, int32_t stream_id,
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

static int http2_frame_not_send_cb(nghttp2_session *session,
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


static int starthttp2(struct http_connection *conn, struct transaction_t *txn)
{
    int r;
    nghttp2_settings_entry iv =
        { NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100 };

    r = nghttp2_session_server_new2(&conn->http2_session,
                                    http2_callbacks, conn, conn->http2_options);
    if (r) {
        syslog(LOG_WARNING,
               "nghttp2_session_server_new: %s", nghttp2_strerror(r));
        return r;
    }

    if (txn && txn->flags.conn & CONN_UPGRADE) {
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
            return r;
        }
        r = nghttp2_session_upgrade2(conn->http2_session,
                                     (const uint8_t *) buf_base(&buf),
                                     outlen, txn->meth == METH_HEAD, NULL);
        buf_free(&buf);
        if (r) {
            syslog(LOG_WARNING, "nghttp2_session_upgrade: %s",
                   nghttp2_strerror(r));
            return r;
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
        return r;
    }

    return 0;
}
#else
static int starthttp2(void *conn __attribute__((unused)),
                      struct transaction_t *txn __attribute__((unused)))
{
    fatal("starthttp2() called, but no Nghttp2", EC_SOFTWARE);
}
#endif /* HAVE_NGHTTP2 */


static void digest_send_success(struct transaction_t *txn,
                                const char *name __attribute__((unused)),
                                const char *data)
{
    simple_hdr(txn, "Authentication-Info", data);
}

/* List of HTTP auth schemes that we support */
struct auth_scheme_t auth_schemes[] = {
    { AUTH_BASIC, "Basic", NULL, AUTH_SERVER_FIRST | AUTH_BASE64, NULL, NULL },
    { AUTH_DIGEST, "Digest", HTTP_DIGEST_MECH, AUTH_NEED_REQUEST|AUTH_SERVER_FIRST,
      &digest_send_success, digest_recv_success },
    { AUTH_SPNEGO, "Negotiate", "GSS-SPNEGO", AUTH_BASE64, NULL, NULL },
    { AUTH_NTLM, "NTLM", "NTLM", AUTH_NEED_PERSIST | AUTH_BASE64, NULL, NULL },
    { -1, NULL, NULL, 0, NULL, NULL }
};


/* the sasl proxy policy context */
static struct proxy_context httpd_proxyctx = {
    0, 1, &httpd_authstate, &httpd_userisadmin, &httpd_userisproxyadmin
};

/* signal to config.c */
const int config_need_data = CONFIG_NEED_PARTITION_DATA;

/* current namespace */
HIDDEN struct namespace httpd_namespace;

/* PROXY STUFF */
/* we want a list of our outgoing connections here and which one we're
   currently piping */

/* the current server most commands go to */
struct backend *backend_current = NULL;

/* our cached connections */
struct backend **backend_cached = NULL;

/* end PROXY stuff */

static int starttls(struct transaction_t *txn, int *http2);
void usage(void);
void shut_down(int code) __attribute__ ((noreturn));

/* Enable the resetting of a sasl_conn_t */
static int reset_saslconn(sasl_conn_t **conn);

static void cmdloop(struct http_connection *conn);
static int parse_expect(struct transaction_t *txn);
static int parse_connection(struct transaction_t *txn);
static int parse_ranges(const char *hdr, unsigned long len,
                        struct range **ranges);
static int proxy_authz(const char **authzid, struct transaction_t *txn);
static void auth_success(struct transaction_t *txn, const char *userid);
static int http_auth(const char *creds, struct transaction_t *txn);

static int meth_get(struct transaction_t *txn, void *params);
static int meth_propfind_root(struct transaction_t *txn, void *params);


static struct {
    char *ipremoteport;
    char *iplocalport;
    sasl_ssf_t ssf;
    char *authid;
} saslprops = {NULL,NULL,0,NULL};

static struct sasl_callback mysasl_cb[] = {
    { SASL_CB_GETOPT, (mysasl_cb_ft *) &mysasl_config, NULL },
    { SASL_CB_PROXY_POLICY, (mysasl_cb_ft *) &mysasl_proxy_policy, (void*) &httpd_proxyctx },
    { SASL_CB_CANON_USER, (mysasl_cb_ft *) &mysasl_canon_user, NULL },
    { SASL_CB_LIST_END, NULL, NULL }
};

/* Array of HTTP methods known by our server. */
const struct known_meth_t http_methods[] = {
    { "ACL",            0 },
    { "BIND",           0 },
    { "COPY",           METH_NOBODY },
    { "DELETE",         METH_NOBODY },
    { "GET",            METH_NOBODY },
    { "HEAD",           METH_NOBODY },
    { "LOCK",           0 },
    { "MKCALENDAR",     0 },
    { "MKCOL",          0 },
    { "MOVE",           METH_NOBODY },
    { "OPTIONS",        METH_NOBODY },
    { "PATCH",          0 },
    { "POST",           0 },
    { "PROPFIND",       0 },
    { "PROPPATCH",      0 },
    { "PUT",            0 },
    { "REPORT",         0 },
    { "TRACE",          METH_NOBODY },
    { "UNBIND",         0 },
    { "UNLOCK",         METH_NOBODY },
    { NULL,             0 }
};

/* Namespace to fetch static content from filesystem */
struct namespace_t namespace_default = {
    URL_NS_DEFAULT, 1, "", NULL, 0 /* no auth */,
    /*mbtype*/0,
    ALLOW_READ,
    NULL, NULL, NULL, NULL, NULL,
    {
        { NULL,                 NULL },                 /* ACL          */
        { NULL,                 NULL },                 /* BIND         */
        { NULL,                 NULL },                 /* COPY         */
        { NULL,                 NULL },                 /* DELETE       */
        { &meth_get,            NULL },                 /* GET          */
        { &meth_get,            NULL },                 /* HEAD         */
        { NULL,                 NULL },                 /* LOCK         */
        { NULL,                 NULL },                 /* MKCALENDAR   */
        { NULL,                 NULL },                 /* MKCOL        */
        { NULL,                 NULL },                 /* MOVE         */
        { &meth_options,        NULL },                 /* OPTIONS      */
        { NULL,                 NULL },                 /* PATCH        */
        { NULL,                 NULL },                 /* POST         */
        { &meth_propfind_root,  NULL },                 /* PROPFIND     */
        { NULL,                 NULL },                 /* PROPPATCH    */
        { NULL,                 NULL },                 /* PUT          */
        { NULL,                 NULL },                 /* REPORT       */
        { &meth_trace,          NULL },                 /* TRACE        */
        { NULL,                 NULL },                 /* UNBIND       */
        { NULL,                 NULL },                 /* UNLOCK       */
    }
};

/* Array of different namespaces and features supported by the server */
struct namespace_t *namespaces[] = {
    &namespace_jmap,
    &namespace_tzdist,          /* MUST be before namespace_calendar!! */
#ifdef WITH_DAV
    &namespace_calendar,
    &namespace_freebusy,
    &namespace_addressbook,
    &namespace_drive,
    &namespace_principal,       /* MUST be after namespace_cal & addr & drive */
    &namespace_notify,          /* MUST be after namespace_principal */
    &namespace_applepush,       /* MUST be after namespace_cal & addr */
#ifdef HAVE_IANA_PARAMS
    &namespace_ischedule,
    &namespace_domainkey,
#endif /* HAVE_IANA_PARAMS */
#endif /* WITH_DAV */
    &namespace_rss,
    &namespace_dblookup,
    &namespace_admin,
    &namespace_default,         /* MUST be present and be last!! */
    NULL,
};


static void httpd_reset(void)
{
    int i;
    int bytes_in = 0;
    int bytes_out = 0;

    /* Do any namespace specific cleanup */
    for (i = 0; namespaces[i]; i++) {
        if (namespaces[i]->enabled && namespaces[i]->reset)
            namespaces[i]->reset();
    }

    proc_cleanup();

    /* close backend connections */
    i = 0;
    while (backend_cached && backend_cached[i]) {
        proxy_downserver(backend_cached[i]);
        free(backend_cached[i]->context);
        free(backend_cached[i]);
        i++;
    }
    if (backend_cached) free(backend_cached);
    backend_cached = NULL;
    backend_current = NULL;

    if (httpd_in) {
        prot_NONBLOCK(httpd_in);
        prot_fill(httpd_in);
        bytes_in = prot_bytes_in(httpd_in);
        prot_free(httpd_in);
    }

    if (httpd_out) {
        prot_flush(httpd_out);
        bytes_out = prot_bytes_out(httpd_out);
        prot_free(httpd_out);
    }

    if (config_auditlog) {
        syslog(LOG_NOTICE,
               "auditlog: traffic sessionid=<%s> bytes_in=<%d> bytes_out=<%d>",
               session_id(), bytes_in, bytes_out);
    }

    httpd_in = httpd_out = NULL;

    if (protin) protgroup_reset(protin);

#ifdef HAVE_SSL
    if (tls_conn) {
        tls_reset_servertls(&tls_conn);
        tls_conn = NULL;
    }
#endif

    cyrus_reset_stdio();

    httpd_clienthost = "[local]";
    if (httpd_logfd != -1) {
        close(httpd_logfd);
        httpd_logfd = -1;
    }
    if (httpd_userid != NULL) {
        free(httpd_userid);
        httpd_userid = NULL;
    }
    httpd_userisanonymous = 1;
    if (httpd_extrafolder != NULL) {
        free(httpd_extrafolder);
        httpd_extrafolder = NULL;
    }
    if (httpd_extradomain != NULL) {
        free(httpd_extradomain);
        httpd_extradomain = NULL;
    }
    if (httpd_authstate) {
        auth_freestate(httpd_authstate);
        httpd_authstate = NULL;
    }
    if (httpd_saslconn) {
        sasl_dispose(&httpd_saslconn);
        httpd_saslconn = NULL;
    }
    httpd_tls_done = 0;

    if(saslprops.iplocalport) {
       free(saslprops.iplocalport);
       saslprops.iplocalport = NULL;
    }
    if(saslprops.ipremoteport) {
       free(saslprops.ipremoteport);
       saslprops.ipremoteport = NULL;
    }
    if(saslprops.authid) {
       free(saslprops.authid);
       saslprops.authid = NULL;
    }
    saslprops.ssf = 0;

    session_new_id();
}

/*
 * run once when process is forked;
 * MUST NOT exit directly; must return with non-zero error code
 */
int service_init(int argc __attribute__((unused)),
                 char **argv __attribute__((unused)),
                 char **envp __attribute__((unused)))
{
    int r, events, opt, i;
    int allow_trace = config_getswitch(IMAPOPT_HTTPALLOWTRACE);

    LIBXML_TEST_VERSION

    initialize_http_error_table();

    if (geteuid() == 0) fatal("must run as the Cyrus user", EC_USAGE);
    setproctitle_init(argc, argv, envp);

    /* set signal handlers */
    signals_set_shutdown(&shut_down);
    signal(SIGPIPE, SIG_IGN);

    /* load the SASL plugins */
    global_sasl_init(1, 1, mysasl_cb);

    /* open the mboxlist, we'll need it for real work */
    mboxlist_init(0);
    mboxlist_open(NULL);

    /* open the quota db, we'll need it for expunge */
    quotadb_init(0);
    quotadb_open(NULL);

    /* open the user deny db */
    denydb_init(0);
    denydb_open(/*create*/0);

    /* open annotations.db, we'll need it for collection properties */
    annotatemore_open();

    /* setup for sending IMAP IDLE notifications */
    idle_enabled();

    /* Set namespace */
    if ((r = mboxname_init_namespace(&httpd_namespace, 1)) != 0) {
        syslog(LOG_ERR, "%s", error_message(r));
        fatal(error_message(r), EC_CONFIG);
    }

    /* open the mboxevent system */
    events = mboxevent_init();
    apns_enabled = (events & EVENT_APPLEPUSHSERVICE_DAV);

    mboxevent_setnamespace(&httpd_namespace);

    while ((opt = getopt(argc, argv, "sp:q")) != EOF) {
        switch(opt) {
        case 's': /* https (do TLS right away) */
            https = 1;
            if (!tls_enabled()) {
                syslog(LOG_ERR, "https: required OpenSSL options not present");
                fatal("https: required OpenSSL options not present",
                      EC_CONFIG);
            }
            break;

        case 'q':
            ignorequota = 1;
            break;

        case 'p': /* external protection */
            extprops_ssf = atoi(optarg);
            break;

        default:
            usage();
        }
    }

    /* Create a protgroup for input from the client and selected backend */
    protin = protgroup_new(2);

    config_httpprettytelemetry = config_getswitch(IMAPOPT_HTTPPRETTYTELEMETRY);

    if (config_getstring(IMAPOPT_HTTPALLOWCORS)) {
        allow_cors =
            split_wildmats((char *) config_getstring(IMAPOPT_HTTPALLOWCORS),
                           NULL);
    }

    /* Construct serverinfo string */
    buf_printf(&serverinfo, "Cyrus-HTTP/%s Cyrus-SASL/%u.%u.%u",
               cyrus_version(),
               SASL_VERSION_MAJOR, SASL_VERSION_MINOR, SASL_VERSION_STEP);
#ifdef HAVE_SSL
    buf_printf(&serverinfo, " OpenSSL/%s", SHLIB_VERSION_NUMBER);
#endif

#ifdef HAVE_NGHTTP2
    buf_printf(&serverinfo, " Nghttp2/%s", NGHTTP2_VERSION);

    /* Setup HTTP/2 callbacks */
    if ((r = nghttp2_session_callbacks_new(&http2_callbacks))) {
        syslog(LOG_WARNING,
               "nghttp2_session_callbacks_new: %s", nghttp2_strerror(r));
    }
    else {
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
    }
#endif /* HAVE_NGHTTP2 */

#ifdef HAVE_ZLIB
    buf_printf(&serverinfo, " Zlib/%s", ZLIB_VERSION);
#endif
#ifdef HAVE_BROTLI
    uint32_t version = BrotliEncoderVersion();
    buf_printf(&serverinfo, " Brotli/%u.%u.%u",
               (version >> 24) & 0xfff, (version >> 12) & 0xfff, version & 0xfff);
#endif
    buf_printf(&serverinfo, " LibXML%s", LIBXML_DOTTED_VERSION);

    /* Do any namespace specific initialization */
    config_httpmodules = config_getbitfield(IMAPOPT_HTTPMODULES);
    for (i = 0; namespaces[i]; i++) {
        if (allow_trace) namespaces[i]->allow |= ALLOW_TRACE;
        if (namespaces[i]->init) namespaces[i]->init(&serverinfo);
    }

    compile_time = calc_compile_time(__TIME__, __DATE__);

    return 0;
}


static volatile sig_atomic_t gotsigalrm = 0;

static void sigalrm_handler(int sig __attribute__((unused)))
{
    gotsigalrm = 1;
}


/*
 * run for each accepted connection
 */
int service_main(int argc __attribute__((unused)),
                 char **argv __attribute__((unused)),
                 char **envp __attribute__((unused)))
{
    sasl_security_properties_t *secprops=NULL;
    const char *mechlist, *mech;
    int mechcount = 0;
    size_t mechlen;
    struct auth_scheme_t *scheme;
    struct http_connection http_conn;

    session_new_id();

    signals_poll();

    sync_log_init();

    httpd_in = prot_new(0, 0);
    httpd_out = prot_new(1, 1);
    protgroup_insert(protin, httpd_in);

    /* Find out name of client host */
    httpd_clienthost = get_clienthost(0, &httpd_localip, &httpd_remoteip);

    /* other params should be filled in */
    if (sasl_server_new("HTTP", config_servername, NULL, NULL, NULL, NULL,
                        SASL_USAGE_FLAGS, &httpd_saslconn) != SASL_OK)
        fatal("SASL failed initializing: sasl_server_new()",EC_TEMPFAIL);

    /* will always return something valid */
    secprops = mysasl_secprops(0);

    /* no HTTP clients seem to use "auth-int" */
    secprops->max_ssf = 0;                              /* "auth" only */
    secprops->maxbufsize = 0;                           /* don't need maxbuf */
    if (sasl_setprop(httpd_saslconn, SASL_SEC_PROPS, secprops) != SASL_OK)
        fatal("Failed to set SASL property", EC_TEMPFAIL);
    if (sasl_setprop(httpd_saslconn, SASL_SSF_EXTERNAL, &extprops_ssf) != SASL_OK)
        fatal("Failed to set SASL property", EC_TEMPFAIL);

    if (httpd_localip) {
        sasl_setprop(httpd_saslconn, SASL_IPLOCALPORT, httpd_localip);
        saslprops.iplocalport = xstrdup(httpd_localip);
    }

    if (httpd_remoteip) {
        char hbuf[NI_MAXHOST], *p;

        sasl_setprop(httpd_saslconn, SASL_IPREMOTEPORT, httpd_remoteip);
        saslprops.ipremoteport = xstrdup(httpd_remoteip);

        /* Create pre-authentication telemetry log based on client IP */
        strlcpy(hbuf, httpd_remoteip, NI_MAXHOST);
        if ((p = strchr(hbuf, ';'))) *p = '\0';
        httpd_logfd = telemetry_log(hbuf, httpd_in, httpd_out, 0);
    }

    /* See which auth schemes are available to us */
    if ((extprops_ssf >= 2) || config_getswitch(IMAPOPT_ALLOWPLAINTEXT)) {
        avail_auth_schemes |= (1 << AUTH_BASIC);
    }
    sasl_listmech(httpd_saslconn, NULL, NULL, " ", NULL,
                  &mechlist, NULL, &mechcount);
    for (mech = mechlist; mechcount--; mech += ++mechlen) {
        mechlen = strcspn(mech, " \0");
        for (scheme = auth_schemes; scheme->name; scheme++) {
            if (scheme->saslmech && !strncmp(mech, scheme->saslmech, mechlen)) {
                avail_auth_schemes |= (1 << scheme->idx);
                break;
            }
        }
    }
    httpd_tls_required =
        config_getswitch(IMAPOPT_TLS_REQUIRED) || !avail_auth_schemes;

    proc_register(config_ident, httpd_clienthost, NULL, NULL, NULL);

    /* Set inactivity timer */
    httpd_timeout = config_getint(IMAPOPT_HTTPTIMEOUT);
    if (httpd_timeout < 0) httpd_timeout = 0;
    httpd_timeout *= 60;
    prot_settimeout(httpd_in, httpd_timeout);
    prot_setflushonread(httpd_in, httpd_out);

    /* Setup HTTP connection */
    memset(&http_conn, 0, sizeof(struct http_connection));
    http_conn.pin = httpd_in;
    http_conn.pout = httpd_out;

    /* we were connected on https port so we should do
       TLS negotiation immediatly */
    if (https == 1) {
        int r, http2 = 0;

        r = starttls(NULL, &http2);
        if (!r && http2) r = starthttp2(&http_conn, NULL);
        if (r) shut_down(0);
    }

    /* Setup the signal handler for keepalive heartbeat */
    httpd_keepalive = config_getint(IMAPOPT_HTTPKEEPALIVE);
    if (httpd_keepalive < 0) httpd_keepalive = 0;
    if (httpd_keepalive) {
        struct sigaction action;

        sigemptyset(&action.sa_mask);
        action.sa_flags = 0;
#ifdef SA_RESTART
        action.sa_flags |= SA_RESTART;
#endif
        action.sa_handler = sigalrm_handler;
        if (sigaction(SIGALRM, &action, NULL) < 0) {
            syslog(LOG_ERR, "unable to install signal handler for %d: %m", SIGALRM);
            httpd_keepalive = 0;
        }
    }

    if (config_getswitch(IMAPOPT_HTTPALLOWCOMPRESS)) {
#ifdef HAVE_ZLIB
        http_conn.zstrm = xzmalloc(sizeof(z_stream));
        /* Always use gzip format because IE incorrectly uses raw deflate */
        if (deflateInit2(http_conn.zstrm, Z_DEFAULT_COMPRESSION, Z_DEFLATED,
                         16+MAX_WBITS /* gzip */,
                         MAX_MEM_LEVEL, Z_DEFAULT_STRATEGY) != Z_OK) {
            free(http_conn.zstrm);
            http_conn.zstrm = NULL;
        }
#endif
#ifdef HAVE_BROTLI
        http_conn.brotli = brotli_init();
#endif
    }

    cmdloop(&http_conn);

    /* Closing connection */

    /* cleanup */
    signal(SIGALRM, SIG_IGN);
    httpd_reset();

#ifdef HAVE_NGHTTP2
    nghttp2_option_del(http_conn.http2_options);
    nghttp2_session_del(http_conn.http2_session);
#endif

#ifdef HAVE_ZLIB
    if (http_conn.zstrm) {
        deflateEnd(http_conn.zstrm);
        free(http_conn.zstrm);
    }
#endif
#ifdef HAVE_BROTLI
    if (http_conn.brotli) BrotliEncoderDestroyInstance(http_conn.brotli);
#endif

    return 0;
}


/* Called by service API to shut down the service */
void service_abort(int error)
{
    shut_down(error);
}


void usage(void)
{
    prot_printf(httpd_out, "%s: usage: httpd [-C <alt_config>] [-s]\r\n",
                error_message(HTTP_SERVER_ERROR));
    prot_flush(httpd_out);
    exit(EC_USAGE);
}


/*
 * Cleanly shut down and exit
 */
void shut_down(int code)
{
    int i;
    int bytes_in = 0;
    int bytes_out = 0;

    in_shutdown = 1;

    if (allow_cors) free_wildmats(allow_cors);

    /* Do any namespace specific cleanup */
    for (i = 0; namespaces[i]; i++) {
        if (namespaces[i]->enabled && namespaces[i]->shutdown)
            namespaces[i]->shutdown();
    }

    xmlCleanupParser();

    proc_cleanup();

    /* close backend connections */
    i = 0;
    while (backend_cached && backend_cached[i]) {
        proxy_downserver(backend_cached[i]);
        free(backend_cached[i]->context);
        free(backend_cached[i]);
        i++;
    }
    if (backend_cached) free(backend_cached);

    sync_log_done();

    mboxlist_close();
    mboxlist_done();

    quotadb_close();
    quotadb_done();

    denydb_close();
    denydb_done();

    annotatemore_close();

    if (httpd_in) {
        prot_NONBLOCK(httpd_in);
        prot_fill(httpd_in);
        bytes_in = prot_bytes_in(httpd_in);
        prot_free(httpd_in);
    }

    if (httpd_out) {
        prot_flush(httpd_out);
        bytes_out = prot_bytes_out(httpd_out);
        prot_free(httpd_out);
    }

    if (protin) protgroup_free(protin);

    if (config_auditlog)
        syslog(LOG_NOTICE,
               "auditlog: traffic sessionid=<%s> bytes_in=<%d> bytes_out=<%d>",
               session_id(), bytes_in, bytes_out);

#ifdef HAVE_SSL
    tls_shutdown_serverengine();
#endif

#ifdef HAVE_NGHTTP2
    nghttp2_session_callbacks_del(http2_callbacks);
#endif

    cyrus_done();

    exit(code);
}


void fatal(const char* s, int code)
{
    static int recurse_code = 0;

    if (recurse_code) {
        /* We were called recursively. Just give up */
        proc_cleanup();
        exit(recurse_code);
    }
    recurse_code = code;
    if (httpd_out) {
        prot_printf(httpd_out,
                    "HTTP/1.1 %s\r\n"
                    "Content-Type: text/plain\r\n"
                    "Connection: close\r\n\r\n"
                    "Fatal error: %s\r\n",
                    error_message(HTTP_SERVER_ERROR), s);
        prot_flush(httpd_out);
    }
    syslog(LOG_ERR, "Fatal error: %s", s);
    shut_down(code);
}


#ifdef HAVE_SSL
static int starttls(struct transaction_t *txn, int *http2)
{
    int https = (txn == NULL);
    int result;
    int *layerp;
    sasl_ssf_t ssf;
    char *auth_id;
    SSL_CTX *ctx = NULL;

    /* SASL and openssl have different ideas about whether ssf is signed */
    layerp = (int *) &ssf;

    result=tls_init_serverengine("http",
                                 5,        /* depth to verify */
                                 !https,   /* can client auth? */
                                 &ctx);

    if (result == -1) {
        syslog(LOG_ERR, "error initializing TLS");

        if (txn) txn->error.desc = "Error initializing TLS";
        return HTTP_SERVER_ERROR;
    }

#if (defined HAVE_NGHTTP2 && OPENSSL_VERSION_NUMBER >= 0x10002000L)
    if (http2_callbacks) {
        /* enable TLS ALPN extension */
        SSL_CTX_set_alpn_select_cb(ctx, alpn_select_cb, http2);
    }
#else
    (void) http2; /* silence 'unused variable http2' warning */
#endif

    if (!https) {
        /* tell client to start TLS upgrade (RFC 2817) */
        response_header(HTTP_SWITCH_PROT, txn);
    }

    result=tls_start_servertls(0, /* read */
                               1, /* write */
                               https ? 180 : httpd_timeout,
                               layerp,
                               &auth_id,
                               &tls_conn);

    /* if error */
    if (result == -1) {
        syslog(LOG_NOTICE, "starttls failed: %s", httpd_clienthost);

        if (txn) txn->error.desc = "Error negotiating TLS";
        return HTTP_BAD_REQUEST;
    }

    /* tell SASL about the negotiated layer */
    result = sasl_setprop(httpd_saslconn, SASL_SSF_EXTERNAL, &ssf);
    if (result == SASL_OK) {
        saslprops.ssf = ssf;

        result = sasl_setprop(httpd_saslconn, SASL_AUTH_EXTERNAL, auth_id);
    }
    if (result != SASL_OK) {
        syslog(LOG_NOTICE, "sasl_setprop() failed: starttls()");

        fatal("sasl_setprop() failed: starttls()", EC_TEMPFAIL);
    }
    if (saslprops.authid) {
        free(saslprops.authid);
        saslprops.authid = NULL;
    }
    if (auth_id) saslprops.authid = xstrdup(auth_id);

    /* tell the prot layer about our new layers */
    prot_settls(httpd_in, tls_conn);
    prot_settls(httpd_out, tls_conn);

    httpd_tls_done = 1;
    httpd_tls_required = 0;

    avail_auth_schemes |= (1 << AUTH_BASIC);

    return 0;
}
#else
static int starttls(struct transaction_t *txn __attribute__((unused)),
                    int *http2 __attribute__((unused)))
{
    fatal("starttls() called, but no OpenSSL", EC_SOFTWARE);
}
#endif /* HAVE_SSL */


/* Reset the given sasl_conn_t to a sane state */
static int reset_saslconn(sasl_conn_t **conn)
{
    int ret;
    sasl_security_properties_t *secprops = NULL;

    sasl_dispose(conn);
    /* do initialization typical of service_main */
    ret = sasl_server_new("HTTP", config_servername, NULL, NULL, NULL, NULL,
                          SASL_USAGE_FLAGS, conn);
    if(ret != SASL_OK) return ret;

    if(saslprops.ipremoteport)
       ret = sasl_setprop(*conn, SASL_IPREMOTEPORT,
                          saslprops.ipremoteport);
    if(ret != SASL_OK) return ret;

    if(saslprops.iplocalport)
       ret = sasl_setprop(*conn, SASL_IPLOCALPORT,
                          saslprops.iplocalport);
    if(ret != SASL_OK) return ret;
    secprops = mysasl_secprops(0);

    /* no HTTP clients seem to use "auth-int" */
    secprops->max_ssf = 0;                              /* "auth" only */
    secprops->maxbufsize = 0;                           /* don't need maxbuf */
    ret = sasl_setprop(*conn, SASL_SEC_PROPS, secprops);
    if(ret != SASL_OK) return ret;
    /* end of service_main initialization excepting SSF */

    /* If we have TLS/SSL info, set it */
    if(saslprops.ssf) {
        ret = sasl_setprop(*conn, SASL_SSF_EXTERNAL, &saslprops.ssf);
    } else {
        ret = sasl_setprop(*conn, SASL_SSF_EXTERNAL, &extprops_ssf);
    }

    if(ret != SASL_OK) return ret;

    if(saslprops.authid) {
       ret = sasl_setprop(*conn, SASL_AUTH_EXTERNAL, saslprops.authid);
       if(ret != SASL_OK) return ret;
    }
    /* End TLS/SSL Info */

    return SASL_OK;
}


static int parse_request_line(struct transaction_t *txn)
{
    struct request_line_t *req_line = &txn->req_line;
    char *p;
    tok_t tok;
    int ret = 0;

    /* Trim CRLF from request-line */
    p = req_line->buf + strlen(req_line->buf);
    if (p[-1] == '\n') *--p = '\0';
    if (p[-1] == '\r') *--p = '\0';

    /* Parse request-line = method SP request-target SP HTTP-version CRLF */
    tok_initm(&tok, req_line->buf, " ", 0);
    if (!(req_line->meth = tok_next(&tok))) {
        ret = HTTP_BAD_REQUEST;
        txn->error.desc = "Missing method in request-line";
    }
    else if (!(req_line->uri = tok_next(&tok))) {
        ret = HTTP_BAD_REQUEST;
        txn->error.desc = "Missing request-target in request-line";
    }
    else if ((size_t) (p - req_line->buf) > MAX_REQ_LINE - 2) {
        /* request-line overran the size of our buffer */
        ret = HTTP_URI_TOO_LONG;
        buf_printf(&txn->buf,
                   "Length of request-line MUST be less than %u octets",
                   MAX_REQ_LINE);
        txn->error.desc = buf_cstring(&txn->buf);
    }
    else if (!(req_line->ver = tok_next(&tok))) {
        ret = HTTP_BAD_REQUEST;
        txn->error.desc = "Missing HTTP-version in request-line";
    }
    else if (tok_next(&tok)) {
        ret = HTTP_BAD_REQUEST;
        txn->error.desc = "Unexpected extra argument(s) in request-line";
    }

    /* Check HTTP-Version - MUST be HTTP/1.x */
    else if (strlen(req_line->ver) != HTTP_VERSION_LEN
             || strncmp(req_line->ver, HTTP_VERSION, HTTP_VERSION_LEN-1)
             || !isdigit(req_line->ver[HTTP_VERSION_LEN-1])) {
        ret = HTTP_BAD_VERSION;
        buf_printf(&txn->buf,
                   "This server only speaks %.*sx",
                   HTTP_VERSION_LEN-1, HTTP_VERSION);
        txn->error.desc = buf_cstring(&txn->buf);
    }
    else if (req_line->ver[HTTP_VERSION_LEN-1] == '0') {
        /* HTTP/1.0 connection */
        txn->flags.ver = VER_1_0;
    }
    tok_fini(&tok);

    return ret;
}


static int client_need_auth(struct transaction_t *txn, int sasl_result)
{
    if (httpd_tls_required) {
        /* We only support TLS+Basic, so tell client to use TLS */
        const char **hdr;

        /* Check which response is required */
        if ((hdr = spool_getheader(txn->req_hdrs, "Upgrade")) &&
            strstr(hdr[0], TLS_VERSION)) {
            /* Client (Murder proxy) supports RFC 2817 (TLS upgrade) */

            txn->flags.conn |= CONN_UPGRADE;
            txn->flags.upgrade = UPGRADE_TLS;
            return HTTP_UPGRADE;
        }
        else {
            /* All other clients use RFC 2818 (HTTPS) */
            const char *path = txn->req_uri->path;
            const char *query = URI_QUERY(txn->req_uri);
            struct buf *html = &txn->resp_body.payload;

            /* Create https URL */
            hdr = spool_getheader(txn->req_hdrs, "Host");
            buf_printf(&txn->buf, "https://%s", hdr[0]);
            if (strcmp(path, "*")) {
                buf_appendcstr(&txn->buf, path);
                if (query) buf_printf(&txn->buf, "?%s", query);
            }

            txn->location = buf_cstring(&txn->buf);

            /* Create HTML body */
            buf_reset(html);
            buf_printf(html, tls_message,
                       buf_cstring(&txn->buf), buf_cstring(&txn->buf));

            /* Output our HTML response */
            txn->resp_body.type = "text/html; charset=utf-8";
            return HTTP_MOVED;
        }
    }
    else {
        /* Tell client to authenticate */
        if (sasl_result == SASL_CONTINUE)
            txn->error.desc = "Continue authentication exchange";
        else if (sasl_result) txn->error.desc = "Authentication failed";
        else txn->error.desc =
                 "Must authenticate to access the specified target";

        return HTTP_UNAUTHORIZED;
    }
}


static int examine_request(struct transaction_t *txn)
{
    int ret = 0, r = 0, i;
    const char **hdr, *query;
    const struct namespace_t *namespace;
    const struct method_t *meth_t;
    struct request_line_t *req_line = &txn->req_line;

    /* Check for HTTP method override */
    if (!strcmp(req_line->meth, "POST") &&
        (hdr = spool_getheader(txn->req_hdrs, "X-HTTP-Method-Override"))) {
        txn->flags.override = 1;
        req_line->meth = (char *) hdr[0];
    }

    /* Check Method against our list of known methods */
    for (txn->meth = 0; (txn->meth < METH_UNKNOWN) &&
             strcmp(http_methods[txn->meth].name, req_line->meth);
         txn->meth++);

    if (txn->meth == METH_UNKNOWN) return HTTP_NOT_IMPLEMENTED;

    /* Parse request-target URI */
    if (!(txn->req_uri = parse_uri(txn->meth, req_line->uri, 1,
                                   &txn->error.desc))) {
        return HTTP_BAD_REQUEST;
    }

    /* Check for mandatory Host header (HTTP/1.1+ only) */
    if ((hdr = spool_getheader(txn->req_hdrs, "Host")) && hdr[1]) {
        txn->error.desc = "Too many Host headers";
        return HTTP_BAD_REQUEST;
    }
    else if (!hdr) {
        switch (txn->flags.ver) {
        case VER_2:
            /* HTTP/2 - create a Host header from :authority */
            hdr = spool_getheader(txn->req_hdrs, ":authority");
            spool_cache_header(xstrdup("Host"), xstrdup(hdr[0]), txn->req_hdrs);
            break;

        case VER_1_0:
            /* HTTP/1.0 - create a Host header from URI */
            if (txn->req_uri->server) {
                buf_setcstr(&txn->buf, txn->req_uri->server);
                if (txn->req_uri->port)
                    buf_printf(&txn->buf, ":%d", txn->req_uri->port);
            }
            else buf_setcstr(&txn->buf, config_servername);

            spool_cache_header(xstrdup("Host"),
                               xstrdup(buf_cstring(&txn->buf)), txn->req_hdrs);
            buf_reset(&txn->buf);
            break;

        case VER_1_1:
        default:
            txn->error.desc = "Missing Host header";
            return HTTP_BAD_REQUEST;
        }
    }

    /* Check message framing */
    if ((ret = http_parse_framing(txn->flags.ver == VER_2, txn->req_hdrs,
                                  &txn->req_body, &txn->error.desc))) return ret;

    /* Check for Expectations */
    if ((ret = parse_expect(txn))) return ret;

    /* Check for Connection options */
    if ((ret = parse_connection(txn))) return ret;

    syslog(LOG_DEBUG, "conn flags: %#x  upgrade flags: %#x  tls req: %d",
           txn->flags.conn, txn->flags.upgrade, httpd_tls_required);
    if (txn->flags.conn & CONN_UPGRADE) {
        /* Read any request body (can't upgrade in middle of request) */
        txn->req_body.flags |= BODY_DECODE;
        ret = http_read_body(httpd_in, httpd_out,
                             txn->req_hdrs, &txn->req_body, &txn->error.desc);
        if (ret) {
            txn->flags.conn = CONN_CLOSE;
            return ret;
        }

        if (txn->flags.upgrade & UPGRADE_TLS) {
            int http2 = 0;
            if ((ret = starttls(txn, &http2))) {
                txn->flags.conn = CONN_CLOSE;
                return ret;
            }
            if (http2) txn->flags.upgrade |= UPGRADE_HTTP2;
        }

        syslog(LOG_DEBUG, "upgrade flags: %#x  tls req: %d",
               txn->flags.upgrade, httpd_tls_required);
        if ((txn->flags.upgrade & UPGRADE_HTTP2) && !httpd_tls_required) {
            if ((ret = starthttp2(txn->conn, httpd_tls_done ? NULL : txn))) {
                txn->flags.conn = CONN_CLOSE;
                return ret;
            }
        }

        txn->flags.conn &= ~CONN_UPGRADE;
        txn->flags.upgrade = 0;
    }
    else if (!httpd_tls_done && txn->flags.ver == VER_1_1) {
        /* Advertise available upgrade protocols */
        txn->flags.conn |= CONN_UPGRADE;
        txn->flags.upgrade = UPGRADE_HTTP2;
        if (config_mupdate_server && config_getstring(IMAPOPT_PROXYSERVERS))
            txn->flags.upgrade |= UPGRADE_TLS;
    }

    query = URI_QUERY(txn->req_uri);

    /* Find the namespace of the requested resource */
    for (i = 0; namespaces[i]; i++) {
        const char *path = txn->req_uri->path;
        size_t len;

        /* Skip disabled namespaces */
        if (!namespaces[i]->enabled) continue;

        /* Handle any /.well-known/ bootstrapping */
        if (namespaces[i]->well_known) {
            len = strlen(namespaces[i]->well_known);
            if (!strncmp(path, namespaces[i]->well_known, len) &&
                (!path[len] || path[len] == '/')) {

                hdr = spool_getheader(txn->req_hdrs, "Host");
                buf_reset(&txn->buf);
                buf_printf(&txn->buf, "%s://%s",
                           https? "https" : "http", hdr[0]);
                buf_appendcstr(&txn->buf, namespaces[i]->prefix);
                buf_appendcstr(&txn->buf, path + len);
                if (query) buf_printf(&txn->buf, "?%s", query);
                txn->location = buf_cstring(&txn->buf);

                return HTTP_MOVED;
            }
        }

        /* See if the prefix matches - terminated with NUL or '/' */
        len = strlen(namespaces[i]->prefix);
        if (!strncmp(path, namespaces[i]->prefix, len) &&
            (!path[len] || (path[len] == '/') || !strcmp(path, "*"))) {
            break;
        }
    }
    if ((namespace = namespaces[i])) {
        txn->req_tgt.namespace = namespace;
        txn->req_tgt.allow = namespace->allow;

        /* Check if method is supported in this namespace */
        meth_t = &namespace->methods[txn->meth];
        if (!meth_t->proc) return HTTP_NOT_ALLOWED;

        /* Check if method expects a body */
        else if ((http_methods[txn->meth].flags & METH_NOBODY) &&
                 (txn->req_body.framing != FRAMING_LENGTH ||
                  /* XXX  Will break if client sends just a last-chunk */
                  txn->req_body.len)) {
            return HTTP_BAD_MEDIATYPE;
        }
    } else {
        /* XXX  Should never get here */
        return HTTP_SERVER_ERROR;
    }

    /* Perform authentication, if necessary */
    if ((hdr = spool_getheader(txn->req_hdrs, "Authorization"))) {
        if (httpd_userid) {
            /* Reauth - reinitialize */
            syslog(LOG_DEBUG, "reauth - reinit");
            reset_saslconn(&httpd_saslconn);
            txn->auth_chal.scheme = NULL;
        }

        if (httpd_tls_required) {
            /* TLS required - redirect handled below */
            ret = HTTP_UNAUTHORIZED;
        }
        else {
            /* Check the auth credentials */
            r = http_auth(hdr[0], txn);
            if ((r < 0) || !txn->auth_chal.scheme) {
                /* Auth failed - reinitialize */
                syslog(LOG_DEBUG, "auth failed - reinit");
                reset_saslconn(&httpd_saslconn);
                txn->auth_chal.scheme = NULL;
                ret = HTTP_UNAUTHORIZED;
            }
            else if (r == SASL_CONTINUE) {
                /* Continue with multi-step authentication */
                ret = HTTP_UNAUTHORIZED;
            }
        }
    }
    else if (!httpd_userid && txn->auth_chal.scheme) {
        /* Started auth exchange, but client didn't engage - reinit */
        syslog(LOG_DEBUG, "client didn't complete auth - reinit");
        reset_saslconn(&httpd_saslconn);
        txn->auth_chal.scheme = NULL;
    }

    /* Perform proxy authorization, if necessary */
    else if (saslprops.authid &&
             (hdr = spool_getheader(txn->req_hdrs, "Authorize-As")) &&
             *hdr[0]) {
        const char *authzid = hdr[0];

        r = proxy_authz(&authzid, txn);
        if (r) {
            /* Proxy authz failed - reinitialize */
            syslog(LOG_DEBUG, "proxy authz failed - reinit");
            reset_saslconn(&httpd_saslconn);
            txn->auth_chal.scheme = NULL;
            ret = HTTP_UNAUTHORIZED;
        }
        else {
            auth_success(txn, authzid);
        }
    }

    /* Register service/module and method */
    buf_printf(&txn->buf, "%s%s", config_ident,
               namespace->well_known ? strrchr(namespace->well_known, '/') :
               namespace->prefix);
    proc_register(buf_cstring(&txn->buf), httpd_clienthost, httpd_userid,
                  txn->req_line.uri, txn->req_line.meth);
    buf_reset(&txn->buf);

    /* Request authentication, if necessary */
    switch (txn->meth) {
    case METH_GET:
    case METH_HEAD:
        /* Let method processing function decide if auth is needed */
        break;

    default:
        if (!httpd_userid && namespace->need_auth) {
            /* Authentication required */
            ret = HTTP_UNAUTHORIZED;
        }
    }

    if (ret) return client_need_auth(txn, r);

    /* Check if this is a Cross-Origin Resource Sharing request */
    if (allow_cors && (hdr = spool_getheader(txn->req_hdrs, "Origin"))) {
        const char *err = NULL;
        xmlURIPtr uri = parse_uri(METH_UNKNOWN, hdr[0], 0, &err);

        if (uri && uri->scheme && uri->server) {
            int o_https = !strcasecmp(uri->scheme, "https");

            if ((https == o_https) &&
                !strcasecmp(uri->server,
                            *spool_getheader(txn->req_hdrs, "Host"))) {
                txn->flags.cors = CORS_SIMPLE;
            }
            else {
                struct wildmat *wild;

                /* Create URI w/o path or default port */
                assert(!buf_len(&txn->buf));
                buf_printf(&txn->buf, "%s://%s",
                           lcase(uri->scheme), lcase(uri->server));
                if (uri->port &&
                    ((o_https && uri->port != 443) ||
                     (!o_https && uri->port != 80))) {
                    buf_printf(&txn->buf, ":%d", uri->port);
                }

                /* Check Origin against the 'httpallowcors' wildmat */
                for (wild = allow_cors; wild->pat; wild++) {
                    if (wildmat(buf_cstring(&txn->buf), wild->pat)) {
                        /* If we have a non-negative match, allow request */
                        if (!wild->not) txn->flags.cors = CORS_SIMPLE;
                        break;
                    }
                }
                buf_reset(&txn->buf);
            }
        }
        xmlFreeURI(uri);
    }

    /* Check if we should compress response body

       XXX  Do we want to support deflate even though M$
       doesn't implement it correctly (raw deflate vs. zlib)? */
    if (txn->conn->zstrm &&
        txn->flags.ver == VER_1_1 &&
        (hdr = spool_getheader(txn->req_hdrs, "TE"))) {
        struct accept *e, *enc = parse_accept(hdr);

        for (e = enc; e && e->token; e++) {
            if (e->qual > 0.0 &&
                (!strcasecmp(e->token, "gzip") ||
                 !strcasecmp(e->token, "x-gzip"))) {
                txn->flags.te = TE_GZIP;
            }
            free(e->token);
        }
        if (enc) free(enc);
    }
    else if ((txn->conn->zstrm || txn->conn->brotli) &&
             (hdr = spool_getheader(txn->req_hdrs, "Accept-Encoding"))) {
        struct accept *e, *enc = parse_accept(hdr);
        float qual = 0.0;

        for (e = enc; e && e->token; e++) {
            if (e->qual > 0.0) {
                /* Favor Brotli over GZIP if q values are equal */
                if (txn->conn->brotli &&
                    (e->qual >= qual) && !strcasecmp(e->token, "br")) {
                    txn->resp_body.enc = CE_BR;
                    qual = e->qual;
                }
                else if (txn->conn->zstrm &&
                         (e->qual > qual) && (!strcasecmp(e->token, "gzip") ||
                                              !strcasecmp(e->token, "x-gzip"))) {
                    txn->resp_body.enc = CE_GZIP;
                    qual = e->qual;
                }
            }
            free(e->token);
        }
        if (enc) free(enc);
    }

    /* Parse any query parameters */
    construct_hash_table(&txn->req_qparams, 10, 1);
    if (query) parse_query_params(txn, query);

    return 0;
}


static void transaction_reset(struct transaction_t *txn)
{
    txn->meth = METH_UNKNOWN;

    memset(&txn->flags, 0, sizeof(struct txn_flags_t));
    txn->flags.ver = VER_1_1;
    txn->flags.vary = VARY_AE;

    memset(&txn->req_line, 0, sizeof(struct request_line_t));

    if (txn->req_uri) xmlFreeURI(txn->req_uri);
    txn->req_uri = NULL;

    /* XXX - split this into a req_tgt cleanup */
    free(txn->req_tgt.userid);
    mboxlist_entry_free(&txn->req_tgt.mbentry);
    memset(&txn->req_tgt, 0, sizeof(struct request_target_t));

    free_hash_table(&txn->req_qparams, (void (*)(void *)) &freestrlist);

    if (txn->req_hdrs) spool_free_hdrcache(txn->req_hdrs);
    txn->req_hdrs = NULL;

    txn->req_body.flags = 0;
    buf_reset(&txn->req_body.payload);

    txn->auth_chal.param = NULL;
    txn->location = NULL;
    memset(&txn->error, 0, sizeof(struct error_t));

    memset(&txn->resp_body, 0,  /* Don't zero the response payload buffer */
           sizeof(struct resp_body_t) - sizeof(struct buf));
    buf_reset(&txn->resp_body.payload);

    buf_reset(&txn->buf);
}


static void transaction_free(struct transaction_t *txn)
{
#ifdef HAVE_NGHTTP2
    size_t i;

    for (i = 0; i < HTTP2_MAX_HEADERS; i++) {
        free(txn->http2.resp_hdrs[i].value);
    }
#endif /* HAVE_NGHTTP2 */

    transaction_reset(txn);

    buf_free(&txn->req_body.payload);
    buf_free(&txn->resp_body.payload);
    buf_free(&txn->zbuf);
    buf_free(&txn->buf);
}


/*
 * Top-level command loop parsing
 */
static void cmdloop(struct http_connection *conn)
{
    int empty = 0;
    struct transaction_t txn;

    /* Start with an empty (clean) transaction */
    memset(&txn, 0, sizeof(struct transaction_t));
    txn.conn = conn;

    /* Pre-allocate our working buffer */
    buf_ensure(&txn.buf, 1024);

    for (;;) {
        int ret = 0;

        /* Reset txn state */
        transaction_reset(&txn);

        /* Check for input from client */
        do {
            /* Flush any buffered output */
#ifdef HAVE_NGHTTP2
            if (conn->http2_session &&
                nghttp2_session_want_write(conn->http2_session)) {
                /* Send queued frame(s) */
                int r = nghttp2_session_send(conn->http2_session);
                if (r) {
                    syslog(LOG_ERR,
                           "nghttp2_session_send: %s", nghttp2_strerror(r));
                    /* XXX  can we do anything else here? */
                    transaction_free(&txn);
                    return;
                }
            }
#endif /* HAVE_NGHTTP2 */

            prot_flush(httpd_out);
            if (backend_current) prot_flush(backend_current->out);

            /* Check for shutdown file */
            if (shutdown_file(txn.buf.s, txn.buf.alloc) ||
                (httpd_userid &&
                 userdeny(httpd_userid, config_ident, txn.buf.s, txn.buf.alloc))) {
                txn.error.desc = txn.buf.s;
                ret = HTTP_UNAVAILABLE;
                break;
            }

            signals_poll();

        } while (!proxy_check_input(protin, httpd_in, httpd_out,
                                    backend_current ? backend_current->in : NULL,
                                    NULL, 0));

        
#ifdef HAVE_NGHTTP2
        if (conn->http2_session) {
            syslog(LOG_DEBUG, "ret: %d, eof: %d, want read: %d", ret,
                   httpd_in->eof, nghttp2_session_want_read(conn->http2_session));
            if (nghttp2_session_want_read(conn->http2_session)) {
                if (!ret) {
                    /* Read frame(s) */
                    int r = nghttp2_session_recv(conn->http2_session);
                    if (!r) continue;
                    else if (r != NGHTTP2_ERR_EOF) {
                        syslog(LOG_WARNING, "nghttp2_session_recv: %s (%s)",
                               nghttp2_strerror(r), prot_error(httpd_in));
                        txn.error.desc = prot_error(httpd_in);
                        ret = HTTP_TIMEOUT;
                    }
                }

                if (ret) {
                    /* Tell client we are closing session */
                    syslog(LOG_WARNING, "%s, closing connection", txn.error.desc);
                    syslog(LOG_DEBUG, "nghttp2_submit_goaway()");
                    nghttp2_submit_goaway(conn->http2_session, NGHTTP2_FLAG_NONE,
                                          nghttp2_session_get_last_proc_stream_id(
                                              conn->http2_session),
                                          NGHTTP2_NO_ERROR,
                                          (const uint8_t *) txn.error.desc,
                                          strlen(txn.error.desc));
                    continue;
                }
            }
            else if (ret) {
                protgroup_free(protin);
                shut_down(0);
            }

            /* client closed connection */
            syslog(LOG_DEBUG, "client closed connection");
            transaction_free(&txn);
            return;
        }
#endif /* HAVE_NGHTTP2 */


        if (ret) {
            txn.flags.conn = CONN_CLOSE;
            error_response(ret, &txn);
            protgroup_free(protin);
            shut_down(0);
        }

        /* Read request-line */
        struct request_line_t *req_line = &txn.req_line;
        syslog(LOG_DEBUG, "read & parse request-line");
        if (!prot_fgets(req_line->buf, MAX_REQ_LINE+1, httpd_in)) {
            txn.error.desc = prot_error(httpd_in);
            if (txn.error.desc && strcmp(txn.error.desc, PROT_EOF_STRING)) {
                /* client timed out */
                syslog(LOG_WARNING, "%s, closing connection", txn.error.desc);
                ret = HTTP_TIMEOUT;
            }
            else {
                /* client closed connection */
            }

            txn.flags.conn = CONN_CLOSE;
            goto done;
        }

        /* Ignore 1 empty line before request-line per RFC 7230 Sec 3.5 */
        if (!empty++ && !strcspn(req_line->buf, "\r\n")) continue;
        empty = 0;


#ifdef HAVE_NGHTTP2
        /* Check for HTTP/2 client connection preface */
        if (http2_callbacks &&
            !strncmp(NGHTTP2_CLIENT_MAGIC,
                     req_line->buf, strlen(req_line->buf))) {
            syslog(LOG_DEBUG, "HTTP/2 client connection preface");

            /* Read remainder of preface */
            prot_readbuf(httpd_in, &txn.req_body.payload,
                         NGHTTP2_CLIENT_MAGIC_LEN - strlen(req_line->buf));

            /* Tell library not to look for preface */
            nghttp2_option_new(&conn->http2_options);
            nghttp2_option_set_no_recv_client_magic(conn->http2_options, 1);

            /* Start HTTP/2 */
            ret = starthttp2(conn, &txn);
            if (ret) {
                /* XXX  what do we do here? */
                transaction_free(&txn);
                return;
            }

            continue;
        }
#endif /* HAVE_NGHTTP2 */


        /* Parse request-line = method SP request-target SP HTTP-version CRLF */
        ret = parse_request_line(&txn);

        /* Parse headers */
        if (!ret) {
            ret = http_read_headers(httpd_in, 1 /* read_sep */,
                                    &txn.req_hdrs, &txn.error.desc);
        }

        if (ret) {
            txn.flags.conn = CONN_CLOSE;
            goto done;
        }

        /* Examine request */
        ret = examine_request(&txn);
        if (ret) goto done;

        /* Start method processing alarm (HTTP/1.1 only) */
        if (txn.flags.ver == VER_1_1) alarm(httpd_keepalive);

        /* Process the requested method */
        if (txn.req_tgt.namespace->premethod) {
            ret = txn.req_tgt.namespace->premethod(&txn);
        }
        if (!ret) {
            const struct method_t *meth_t =
                &txn.req_tgt.namespace->methods[txn.meth];

            ret = (*meth_t->proc)(&txn, meth_t->params);
        }

        if (ret == HTTP_UNAUTHORIZED) {
            /* User must authenticate */
            ret = client_need_auth(&txn, 0);
        }

      done:
        /* Handle errors (success responses handled by method functions) */
        if (ret) error_response(ret, &txn);

        /* Read and discard any unread request body */
        if (!(txn.flags.conn & CONN_CLOSE)) {
            txn.req_body.flags |= BODY_DISCARD;
            if (http_read_body(httpd_in, httpd_out,
                               txn.req_hdrs, &txn.req_body, &txn.error.desc)) {
                txn.flags.conn = CONN_CLOSE;
            }
        }

        if (txn.flags.conn & CONN_CLOSE) {
            /* Memory cleanup */
            transaction_free(&txn);
            return;
        }

        continue;
    }
}

/****************************  Parsing Routines  ******************************/

/* Parse URI, returning the path */
EXPORTED xmlURIPtr parse_uri(unsigned meth, const char *uri, unsigned path_reqd,
                    const char **errstr)
{
    xmlURIPtr p_uri;  /* parsed URI */

    /* Parse entire URI */
    if ((p_uri = xmlParseURI(uri)) == NULL) {
        *errstr = "Illegal request target URI";
        goto bad_request;
    }

    if (p_uri->scheme) {
        /* Check sanity of scheme */

        if (strcasecmp(p_uri->scheme, "http") &&
            strcasecmp(p_uri->scheme, "https")) {
            *errstr = "Unsupported URI scheme";
            goto bad_request;
        }
    }

    /* Check sanity of path */
    if (path_reqd && (!p_uri->path || !*p_uri->path)) {
        *errstr = "Empty path in target URI";
        goto bad_request;
    }
    else if (p_uri->path) {
        if ((p_uri->path[0] != '/') &&
            (strcmp(p_uri->path, "*") || (meth != METH_OPTIONS))) {
            /* No special URLs except for "OPTIONS * HTTP/1.1" */
            *errstr = "Illegal request target URI";
            goto bad_request;
        }
        else if (strstr(p_uri->path, "/..")) {
            /* Don't allow access up directory tree */
            *errstr = "Illegal request target URI";
            goto bad_request;
        }
        else if (strlen(p_uri->path) > MAX_MAILBOX_PATH) {
            *errstr = "Request target URI too long";
            goto bad_request;
        }
    }

    return p_uri;

  bad_request:
    if (p_uri) xmlFreeURI(p_uri);
    return NULL;
}


/* Calculate compile time of a file for use as Last-Modified and/or ETag */
EXPORTED time_t calc_compile_time(const char *time, const char *date)
{
    struct tm tm;
    char month[4];
    const char *monthname[] = {
        "Jan", "Feb", "Mar", "Apr", "May", "Jun",
        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
    };

    memset(&tm, 0, sizeof(struct tm));
    tm.tm_isdst = -1;
    sscanf(time, "%02d:%02d:%02d", &tm.tm_hour, &tm.tm_min, &tm.tm_sec);
    sscanf(date, "%s %2d %4d", month, &tm.tm_mday, &tm.tm_year);
    tm.tm_year -= 1900;
    for (tm.tm_mon = 0; tm.tm_mon < 12; tm.tm_mon++) {
        if (!strcmp(month, monthname[tm.tm_mon])) break;
    }

    return mktime(&tm);
}

/* Parse Expect header(s) for interesting expectations */
static int parse_expect(struct transaction_t *txn)
{
    const char **exp = spool_getheader(txn->req_hdrs, "Expect");
    int i, ret = 0;

    /* Expect not supported by HTTP/1.0 clients */
    if (exp && txn->flags.ver == VER_1_0) return HTTP_EXPECT_FAILED;

    /* Look for interesting expectations.  Unknown == error */
    for (i = 0; !ret && exp && exp[i]; i++) {
        tok_t tok = TOK_INITIALIZER(exp[i], ",", TOK_TRIMLEFT|TOK_TRIMRIGHT);
        char *token;

        while (!ret && (token = tok_next(&tok))) {
            /* Check if client wants acknowledgment before sending body */ 
            if (!strcasecmp(token, "100-continue")) {
                syslog(LOG_DEBUG, "Expect: 100-continue");
                txn->req_body.flags |= BODY_CONTINUE;
            }
            else {
                txn->error.desc = "Unsupported Expectation";
                ret = HTTP_EXPECT_FAILED;
            }
        }

        tok_fini(&tok);
    }

    return ret;
}


/* Parse Connection header(s) for interesting options */
static int parse_connection(struct transaction_t *txn)
{
    const char **conn = spool_getheader(txn->req_hdrs, "Connection");
    int i;

    if (conn && txn->flags.ver == VER_2) {
        txn->error.desc = "Connection not allowed in HTTP/2";
        return HTTP_BAD_REQUEST;
    }

    if (!httpd_timeout || txn->flags.ver == VER_1_0) {
        /* Non-persistent connection by default */
        txn->flags.conn |= CONN_CLOSE;
    }

    /* Look for interesting connection tokens */
    for (i = 0; conn && conn[i]; i++) {
        tok_t tok = TOK_INITIALIZER(conn[i], ",", TOK_TRIMLEFT|TOK_TRIMRIGHT);
        char *token;

        while ((token = tok_next(&tok))) {
            switch (txn->flags.ver) {
            case VER_1_1:
                if (!strcasecmp(token, "Upgrade")) {
                    /* Client wants to upgrade */
                    const char **upgrade =
                        spool_getheader(txn->req_hdrs, "Upgrade");

                    if (upgrade && upgrade[0]) {
                        syslog(LOG_NOTICE,
                               "client requested upgrade to %s", upgrade[0]);

                        if (!httpd_tls_done && tls_enabled() &&
                            !strncmp(upgrade[0], TLS_VERSION,
                                     strcspn(upgrade[0], " ,"))) {
                            /* Upgrade to TLS */
                            txn->flags.conn |= CONN_UPGRADE;
                            txn->flags.upgrade |= UPGRADE_TLS;
                        }
#ifdef HAVE_NGHTTP2
                        else if (http2_callbacks &&
                                 !strncmp(upgrade[0],
                                          NGHTTP2_CLEARTEXT_PROTO_VERSION_ID,
                                          strcspn(upgrade[0], " ,"))) {
                            /* Upgrade to HTTP/2 */
                            txn->flags.conn |= CONN_UPGRADE;
                            txn->flags.upgrade |= UPGRADE_HTTP2;
                        }
#endif /* HAVE_NGHTTP2 */
                        else {
                            /* Unknown/unsupported protocol - no upgrade */
                        }
                    }
                }
                else if (!strcasecmp(token, "close")) {
                    /* Non-persistent connection */
                    txn->flags.conn |= CONN_CLOSE;
                }
                break;

            case VER_1_0:
                if (httpd_timeout && !strcasecmp(token, "keep-alive")) {
                    /* Persistent connection */
                    txn->flags.conn = CONN_KEEPALIVE;
                }
                break;
            }
        }

        tok_fini(&tok);
    }

    return 0;
}


/* Compare accept quality values so that they sort in descending order */
static int compare_accept(const struct accept *a1, const struct accept *a2)
{
    if (a2->qual < a1->qual) return -1;
    if (a2->qual > a1->qual) return 1;
    return 0;
}

struct accept *parse_accept(const char **hdr)
{
    int i, n = 0, alloc = 0;
    struct accept *ret = NULL;
#define GROW_ACCEPT 10;

    for (i = 0; hdr && hdr[i]; i++) {
        tok_t tok = TOK_INITIALIZER(hdr[i], ";,", TOK_TRIMLEFT|TOK_TRIMRIGHT);
        char *token;

        while ((token = tok_next(&tok))) {
            if (!strncmp(token, "q=", 2)) {
                if (!ret) break;
                ret[n-1].qual = strtof(token+2, NULL);
            }
            else {
                if (n + 1 >= alloc)  {
                    alloc += GROW_ACCEPT;
                    ret = xrealloc(ret, alloc * sizeof(struct accept));
                }
                ret[n].token = xstrdup(token);
                ret[n].qual = 1.0;
                ret[++n].token = NULL;
            }
        }
        tok_fini(&tok);
    }

    qsort(ret, n, sizeof(struct accept),
          (int (*)(const void *, const void *)) &compare_accept);

    return ret;
}


/* Parse the query string and add key/value pairs to hash table */
void parse_query_params(struct transaction_t *txn, const char *query)
{
    tok_t tok;
    char *param;

    assert(!buf_len(&txn->buf));  /* Unescape buffer */

    tok_init(&tok, query, "&", TOK_TRIMLEFT|TOK_TRIMRIGHT|TOK_EMPTY);
    while ((param = tok_next(&tok))) {
        struct strlist *vals;
        char *key, *value;
        size_t len;

        /* Split param into key and optional value */
        key = param;
        value = strchr(param, '=');

        if (!value) value = "";
        else *value++ = '\0';
        len = strlen(value);
        buf_ensure(&txn->buf, len+1);

        vals = hash_lookup(key, &txn->req_qparams);
        appendstrlist(&vals, xmlURIUnescapeString(value, len, txn->buf.s));
        hash_insert(key, vals, &txn->req_qparams);
    }
    tok_fini(&tok);

    buf_reset(&txn->buf);
}


/****************************  Response Routines  *****************************/


/* Create HTTP-date ('buf' must be at least 30 characters) */
EXPORTED char *httpdate_gen(char *buf, size_t len, time_t t)
{
    static char *month[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun",
                             "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
    static char *wday[] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };

    struct tm *tm = gmtime(&t);

    snprintf(buf, len, "%3s, %02d %3s %4d %02d:%02d:%02d GMT",
             wday[tm->tm_wday],
             tm->tm_mday, month[tm->tm_mon], tm->tm_year + 1900,
             tm->tm_hour, tm->tm_min, tm->tm_sec);

    return buf;
}


/* Create an HTTP Status-Line given response code */
EXPORTED const char *http_statusline(long code)
{
    static struct buf statline = BUF_INITIALIZER;
    static unsigned tail = 0;

    if (!tail) {
        buf_setcstr(&statline, HTTP_VERSION);
        buf_putc(&statline, ' ');
        tail = buf_len(&statline);
    }

    buf_truncate(&statline, tail);
    buf_appendcstr(&statline, error_message(code));
    return buf_cstring(&statline);
}


/* Output an HTTP response header.
 * 'code' specifies the HTTP Status-Code and Reason-Phrase.
 * 'txn' contains the transaction context
 */

EXPORTED void simple_hdr(struct transaction_t *txn,
                         const char *name, const char *value, ...)
{
    struct buf buf = BUF_INITIALIZER;
    va_list args;

    va_start(args, value);
    buf_vprintf(&buf, value, args);
    va_end(args);

    syslog(LOG_DEBUG, "simple_hdr(%s: %s)", name, buf_cstring(&buf));

#ifdef HAVE_NGHTTP2
    if (txn->flags.ver == VER_2) {
        if (txn->http2.num_resp_hdrs >= HTTP2_MAX_HEADERS) {
            buf_free(&buf);
            return;
        }

        nghttp2_nv *nv = &txn->http2.resp_hdrs[txn->http2.num_resp_hdrs];

        free(nv->value);

        nv->namelen = strlen(name);
        nv->name = (uint8_t *) name;
        nv->valuelen = buf_len(&buf);
        nv->value = (uint8_t *) buf_release(&buf);
        nv->flags = NGHTTP2_NV_FLAG_NO_COPY_VALUE;

        txn->http2.num_resp_hdrs++;
        return;
    }
#endif /* HAVE_NGHTTP2 */

    prot_printf(txn->conn->pout, "%c%s: ", toupper(name[0]), name+1);
    prot_puts(txn->conn->pout, buf_cstring(&buf));
    prot_puts(txn->conn->pout, "\r\n");

    buf_free(&buf);
}

#define WWW_Authenticate(name, param)                           \
    simple_hdr(txn, "WWW-Authenticate", param ? "%s %s" : "%s", name, param)

#define Access_Control_Expose(hdr)                              \
    simple_hdr(txn, "Access-Control-Expose-Headers", hdr)

EXPORTED void comma_list_hdr(struct transaction_t *txn, const char *name,
                             const char *vals[], unsigned flags, ...)
{
    struct buf buf = BUF_INITIALIZER;
    const char *sep = "";
    va_list args;
    int i;

    va_start(args, flags);

    for (i = 0; vals[i]; i++) {
        if (flags & (1 << i)) {
            buf_appendcstr(&buf, sep);
            buf_vprintf(&buf, vals[i], args);
            sep = ", ";
        }
        else {
            /* discard any unused args */
            vsnprintf(NULL, 0, vals[i], args);
        }
    }

    va_end(args);

    simple_hdr(txn, name, buf_cstring(&buf));

    buf_free(&buf);
}

EXPORTED void list_auth_schemes(struct transaction_t *txn)
{
    struct auth_challenge_t *auth_chal = &txn->auth_chal;
    unsigned conn_close = (txn->flags.conn & CONN_CLOSE);
    struct auth_scheme_t *scheme;

    /* Advertise available schemes that can work with the type of connection */
    for (scheme = auth_schemes; scheme->name; scheme++) {
        if ((avail_auth_schemes & (1 << scheme->idx)) &&
            !(conn_close && (scheme->flags & AUTH_NEED_PERSIST))) {
            auth_chal->param = NULL;

            if (scheme->flags & AUTH_SERVER_FIRST) {
                /* Generate the initial challenge */
                http_auth(scheme->name, txn);

                if (!auth_chal->param) continue;  /* If fail, skip it */
            }
            WWW_Authenticate(scheme->name, auth_chal->param);
        }
    }
}

EXPORTED void allow_hdr(struct transaction_t *txn,
                        const char *name, unsigned allow)
{
    const char *meths[] = {
        "OPTIONS, GET, HEAD", "POST", "PUT", "PATCH", "DELETE", "TRACE", NULL
    };

    comma_list_hdr(txn, name, meths, allow);

    if (allow & ALLOW_DAV) {
        simple_hdr(txn, name, "PROPFIND, REPORT, COPY%s%s%s%s%s",
                   (allow & ALLOW_DELETE)    ? ", MOVE" : "",
                   (allow & ALLOW_PROPPATCH) ? ", PROPPATCH" : "",
                   (allow & ALLOW_MKCOL)     ? ", MKCOL" : "",
                   (allow & ALLOW_WRITE)     ? ", LOCK, UNLOCK" : "",
                   (allow & ALLOW_ACL)       ? ", ACL" : "");
        if ((allow & ALLOW_CAL) && (allow & ALLOW_MKCOL))
            simple_hdr(txn, name, "MKCALENDAR");
    }
}

EXPORTED void accept_patch_hdr(struct transaction_t *txn,
                               const struct patch_doc_t *patch)
{
    struct buf buf = BUF_INITIALIZER;
    const char *sep = "";
    int i;

    for (i = 0; patch[i].format; i++) {
        buf_appendcstr(&buf, sep);
        buf_appendcstr(&buf, patch[i].format);
        sep = ", ";
    }

    simple_hdr(txn, "Accept-Patch", buf_cstring(&buf));

    buf_free(&buf);
}

#define MD5_BASE64_LEN 25   /* ((MD5_DIGEST_LENGTH / 3) + 1) * 4 */

EXPORTED void content_md5_hdr(struct transaction_t *txn,
                              const unsigned char *md5)
{
    char base64[MD5_BASE64_LEN+1];

    sasl_encode64((char *) md5, MD5_DIGEST_LENGTH,
                  base64, MD5_BASE64_LEN, NULL);
    simple_hdr(txn, "Content-MD5", base64);
}

EXPORTED void begin_resp_headers(struct transaction_t *txn, long code)
{
#ifdef HAVE_NGHTTP2
    if (txn->flags.ver == VER_2) {
        txn->http2.num_resp_hdrs = 0;
        if (code) simple_hdr(txn, ":status", "%.3s", error_message(code));
        return;
    }
#endif /* HAVE_NGHTTP2 */

    if (code) prot_printf(txn->conn->pout, "%s\r\n", http_statusline(code));
    return;
}

EXPORTED int end_resp_headers(struct transaction_t *txn, long code)
{
#ifdef HAVE_NGHTTP2
    if (txn->flags.ver == VER_2) {
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
            return r;
        }

        return 0;
    }
#else
    (void) code; /* silence 'unused variable code' warning */
#endif /* HAVE_NGHTTP2 */

    /* CRLF terminating the header block */
    prot_puts(txn->conn->pout, "\r\n");

    return 0;
}


EXPORTED void response_header(long code, struct transaction_t *txn)
{
    time_t now;
    char datestr[30];
    const char **hdr;
    struct auth_challenge_t *auth_chal = &txn->auth_chal;
    struct resp_body_t *resp_body = &txn->resp_body;
    static struct buf log = BUF_INITIALIZER;

    /* Stop method processing alarm */
    alarm(0);
    gotsigalrm = 0;


    /* Status-Line */
    begin_resp_headers(txn, code);


    switch (code) {
    default:
        /* Final response */
        now = time(0);
        httpdate_gen(datestr, sizeof(datestr), now);
        simple_hdr(txn, "Date", datestr);

        if (txn->flags.ver == VER_2) break;

        /* Fall through and specify connection options - HTTP/1.x only */

    case HTTP_SWITCH_PROT:
        if (txn->flags.conn) {
            /* Construct Connection header */
            const char *conn_tokens[] =
                { "close", "Upgrade", "Keep-Alive", NULL };

            comma_list_hdr(txn, "Connection", conn_tokens, txn->flags.conn);

            if (txn->flags.upgrade) {
                /* Construct Upgrade header */
                const char *upgrd_tokens[] =
                    { TLS_VERSION,
#ifdef HAVE_NGHTTP2
                      NGHTTP2_CLEARTEXT_PROTO_VERSION_ID,
#endif
                      NULL };

                comma_list_hdr(txn, "Upgrade", upgrd_tokens, txn->flags.upgrade);
            }
            if (txn->flags.conn & CONN_KEEPALIVE) {
                simple_hdr(txn, "Keep-Alive", "timeout=%d", httpd_timeout);
            }
        }

        if (code != HTTP_SWITCH_PROT) break;

        /* Fall through as provisional response */

    case HTTP_CONTINUE:
    case HTTP_PROCESSING:
        /* Provisional response - nothing else needed */
        end_resp_headers(txn, code);

        /* Force the response to the client immediately */
        prot_flush(httpd_out);

        return;
    }


    /* Control Data */
    if (httpd_tls_done) {
        simple_hdr(txn, "Strict-Transport-Security", "max-age=600");
    }
    if (txn->location) {
        simple_hdr(txn, "Location", txn->location);
    }
    if (txn->flags.mime) {
        simple_hdr(txn, "MIME-Version", "1.0");
    }
    if (txn->flags.cc) {
        /* Construct Cache-Control header */
        const char *cc_dirs[] =
            { "must-revalidate", "no-cache", "no-store", "no-transform",
              "public", "private", "max-age=%d", NULL };

        comma_list_hdr(txn, "Cache-Control",
                       cc_dirs, txn->flags.cc, resp_body->maxage);

        if (txn->flags.cc & CC_MAXAGE) {
            httpdate_gen(datestr, sizeof(datestr), now + resp_body->maxage);
            simple_hdr(txn, "Expires", datestr);
        }
    }
    if (txn->flags.cors) {
        /* Construct Cross-Origin Resource Sharing headers */
        simple_hdr(txn, "Access-Control-Allow-Origin",
                      *spool_getheader(txn->req_hdrs, "Origin"));
        simple_hdr(txn, "Access-Control-Allow-Credentials", "true");

        if (txn->flags.cors == CORS_PREFLIGHT) {
            allow_hdr(txn, "Access-Control-Allow-Methods", txn->req_tgt.allow);

            for (hdr = spool_getheader(txn->req_hdrs,
                                       "Access-Control-Request-Headers");
                 hdr && *hdr; hdr++) {
                simple_hdr(txn, "Access-Control-Allow-Headers", *hdr);
            }
            simple_hdr(txn, "Access-Control-Max-Age", "3600");
        }
    }
    if (txn->flags.vary && !(txn->flags.cc & CC_NOCACHE)) {
        /* Construct Vary header */
        const char *vary_hdrs[] =
            { "Accept", "Accept-Encoding", "Brief", "Prefer", NULL };

        comma_list_hdr(txn, "Vary", vary_hdrs, txn->flags.vary);
    }


    /* Authentication Challenges */
    if (code == HTTP_UNAUTHORIZED) {
        if (!auth_chal->scheme) {
            /* Require authentication by advertising all available schemes */
            list_auth_schemes(txn);
        }
        else {
            /* Continue with current authentication exchange */
            WWW_Authenticate(auth_chal->scheme->name, auth_chal->param);
        }
    }
    else if (auth_chal->param) {
        /* Authentication completed with success data */
        if (auth_chal->scheme->send_success) {
            /* Special handling of success data for this scheme */
            auth_chal->scheme->send_success(txn, auth_chal->scheme->name,
                                            auth_chal->param);
        }
        else {
            /* Default handling of success data */
            WWW_Authenticate(auth_chal->scheme->name, auth_chal->param);
        }
    }

    
    /* Response Context */
    if (txn->req_tgt.allow & ALLOW_ISCHEDULE) {
        simple_hdr(txn, "iSchedule-Version", "1.0");

        if (resp_body->iserial) {
            simple_hdr(txn, "iSchedule-Capabilities", "%ld", resp_body->iserial);
        }
    }
    if (resp_body->link) {
        simple_hdr(txn, "Link", resp_body->link);
    }
    if (resp_body->patch) {
        accept_patch_hdr(txn, resp_body->patch);
    }

    switch (code) {
    case HTTP_OK:
        switch (txn->meth) {
        case METH_GET:
        case METH_HEAD:
            /* Construct Accept-Ranges header for GET and HEAD responses */
            simple_hdr(txn, "Accept-Ranges",
                       txn->flags.ranges ? "bytes" : "none");
            break;

        case METH_OPTIONS:
            if (config_serverinfo == IMAP_ENUM_SERVERINFO_ON) {
                simple_hdr(txn, "Server", buf_cstring(&serverinfo));
            }

            if (!httpd_userid && !auth_chal->scheme) {
                /* Advertise all available auth schemes */
                list_auth_schemes(txn);
            }

            if (txn->req_tgt.allow & ALLOW_DAV) {
                /* Construct DAV header(s) based on namespace of request URL */
                simple_hdr(txn, "DAV", "1, 2, 3, access-control,"
                           " extended-mkcol, resource-sharing");
                if (txn->req_tgt.allow & ALLOW_CAL) {
                    simple_hdr(txn, "DAV", "calendar-access%s%s",
                               (txn->req_tgt.allow & ALLOW_CAL_SCHED) ?
                               ", calendar-auto-schedule" : "",
                               (txn->req_tgt.allow & ALLOW_CAL_NOTZ) ?
                               ", calendar-no-timezone" : "");
                    simple_hdr(txn, "DAV", "calendar-query-extended%s%s",
                               (txn->req_tgt.allow & ALLOW_CAL_AVAIL) ?
                               ", calendar-availability" : "",
                               (txn->req_tgt.allow & ALLOW_CAL_ATTACH) ?
                               ", calendar-managed-attachments" : "");

                    /* Backwards compatibility with older Apple clients */
                    simple_hdr(txn, "DAV", "calendarserver-sharing%s",
                               (txn->req_tgt.allow &
                                (ALLOW_CAL_AVAIL | ALLOW_CAL_SCHED)) ==
                               (ALLOW_CAL_AVAIL | ALLOW_CAL_SCHED) ?
                               ", inbox-availability" : "");
                }
                if (txn->req_tgt.allow & ALLOW_CARD) {
                    simple_hdr(txn, "DAV", "addressbook");
                }
            }

            /* Access-Control-Allow-Methods supersedes Allow */
            if (txn->flags.cors != CORS_PREFLIGHT) {
                /* Construct Allow header(s) */
                allow_hdr(txn, "Allow", txn->req_tgt.allow);
            }
            break;
        }
        break;

    case HTTP_NOT_ALLOWED:
        /* Construct Allow header(s) for 405 response */
        allow_hdr(txn, "Allow", txn->req_tgt.allow);
        break;

    case HTTP_BAD_CE:
        /* Construct Accept-Encoding header for 415 response */
#ifdef HAVE_ZLIB
        simple_hdr(txn, "Accept-Encoding", "gzip, deflate");
#else
        simple_hdr(txn, "Accept-Encoding", "identity");
#endif
        break;
    }


    /* Validators */
    if (resp_body->lock) {
        simple_hdr(txn, "Lock-Token", "<%s>", resp_body->lock);
        if (txn->flags.cors) Access_Control_Expose("Lock-Token");
    }
    if (resp_body->ctag) {
        simple_hdr(txn, "CTag", "%s", resp_body->ctag);
        if (txn->flags.cors) Access_Control_Expose("CTag");
    }
    if (resp_body->stag) {
        simple_hdr(txn, "Schedule-Tag", "\"%s\"", resp_body->stag);
        if (txn->flags.cors) Access_Control_Expose("Schedule-Tag");
    }
    if (resp_body->etag) {
        simple_hdr(txn, "ETag", "%s\"%s\"",
                      resp_body->enc ? "W/" : "", resp_body->etag);
        if (txn->flags.cors) Access_Control_Expose("ETag");
    }
    if (resp_body->lastmod) {
        /* Last-Modified MUST NOT be in the future */
        resp_body->lastmod = MIN(resp_body->lastmod, now);
        httpdate_gen(datestr, sizeof(datestr), resp_body->lastmod);
        simple_hdr(txn, "Last-Modified", datestr);
    }


    /* Representation Metadata */
    if (resp_body->prefs) {
        /* Construct Preference-Applied header */
        const char *prefs[] =
            { "return=minimal", "return=representation", "depth-noroot", NULL };

        comma_list_hdr(txn, "Preference-Applied", prefs, resp_body->prefs);
        if (txn->flags.cors) Access_Control_Expose("Preference-Applied");
    }
    if (resp_body->cmid) {
        simple_hdr(txn, "Cal-Managed-ID", "\"%s\"", resp_body->cmid);
        if (txn->flags.cors) Access_Control_Expose("Cal-Managed-ID");
    }
    if (resp_body->type) {
        simple_hdr(txn, "Content-Type", resp_body->type);

        if (resp_body->fname) {
            simple_hdr(txn, "Content-Disposition",
                       "attachment; filename=\"%s\"", resp_body->fname);
        }
        if (txn->resp_body.enc) {
            /* Construct Content-Encoding header */
            const char *ce[] =
                { "deflate", "gzip", "br", NULL };

            comma_list_hdr(txn, "Content-Encoding", ce, txn->resp_body.enc);
        }
        if (resp_body->lang) {
            simple_hdr(txn, "Content-Language", resp_body->lang);
        }
        if (resp_body->loc) {
            simple_hdr(txn, "Content-Location", resp_body->loc);
            if (txn->flags.cors) Access_Control_Expose("Content-Location");
        }
        if (resp_body->md5) {
            content_md5_hdr(txn, resp_body->md5);
        }
    }


    /* Payload */
    switch (code) {
    case HTTP_NO_CONTENT:
    case HTTP_NOT_MODIFIED:
        /* MUST NOT include a body */
        resp_body->len = 0;
        break;

    case HTTP_PARTIAL:
    case HTTP_BAD_RANGE:
        if (resp_body->range) {
            simple_hdr(txn, "Content-Range", "bytes %lu-%lu/%lu",
                       resp_body->range->first, resp_body->range->last,
                       resp_body->len);

            /* Set actual content length of range */
            resp_body->len =
                resp_body->range->last - resp_body->range->first + 1;

            free(resp_body->range);
        }
        else {
            simple_hdr(txn, "Content-Range", "bytes */%lu", resp_body->len);
            resp_body->len = 0;  /* No content */
        }

        /* Fall through and specify framing */

    default:
        if (txn->flags.te) {
            /* HTTP/1.1 only - we use close-delimiting for HTTP/1.0 */
            if (txn->flags.ver == VER_1_1) {
                /* Construct Transfer-Encoding header */
                const char *te[] =
                    { "deflate", "gzip", "chunked", NULL };

                comma_list_hdr(txn, "Transfer-Encoding", te, txn->flags.te);
            }

            if (txn->flags.trailer & ~TRAILER_PROXY) {
                /* Construct Trailer header */
                const char *trailer_hdrs[] = { "Content-MD5", NULL };

                comma_list_hdr(txn, "Trailer", trailer_hdrs, txn->flags.trailer);
            }
        }
        else if (resp_body->len || txn->meth != METH_HEAD) {
            simple_hdr(txn, "Content-Length", "%lu", resp_body->len);
        }
    }


    /* End of headers */
    end_resp_headers(txn, code);


    /* Log the client request and our response */
    buf_reset(&log);
    /* Add client data */
    buf_printf(&log, "%s", httpd_clienthost);
    if (httpd_userid) buf_printf(&log, " as \"%s\"", httpd_userid);
    if (txn->req_hdrs &&
        (hdr = spool_getheader(txn->req_hdrs, "User-Agent"))) {
        buf_printf(&log, " with \"%s\"", hdr[0]);
        if ((hdr = spool_getheader(txn->req_hdrs, "X-Client")))
            buf_printf(&log, " by \"%s\"", hdr[0]);
        else if ((hdr = spool_getheader(txn->req_hdrs, "X-Requested-With")))
            buf_printf(&log, " by \"%s\"", hdr[0]);
    }
    /* Add request-line */
    buf_appendcstr(&log, "; \"");
    if (txn->req_line.meth) {
        buf_printf(&log, "%s",
                   txn->flags.override ? "POST" : txn->req_line.meth);
        if (txn->req_line.uri) {
            buf_printf(&log, " %s", txn->req_line.uri);
            if (txn->req_line.ver) {
                buf_printf(&log, " %s", txn->req_line.ver);
                if (code != HTTP_URI_TOO_LONG && *txn->req_line.buf) {
                    char *p = txn->req_line.ver + strlen(txn->req_line.ver) + 1;
                    if (*p) buf_printf(&log, " %s", p);
                }
            }
        }
    }
    buf_appendcstr(&log, "\"");
    if (txn->req_hdrs) {
        /* Add any request modifying headers */
        const char *sep = " (";

        if (txn->flags.override) {
            buf_printf(&log, "%smethod-override=%s", sep, txn->req_line.meth);
            sep = "; ";
        }
        if ((hdr = spool_getheader(txn->req_hdrs, "Origin"))) {
            buf_printf(&log, "%sorigin=%s", sep, hdr[0]);
            sep = "; ";
        }
        if ((hdr = spool_getheader(txn->req_hdrs, "Referer"))) {
            buf_printf(&log, "%sreferer=%s", sep, hdr[0]);
            sep = "; ";
        }
        if ((hdr = spool_getheader(txn->req_hdrs, "Destination"))) {
            buf_printf(&log, "%sdestination=%s", sep, hdr[0]);
            sep = "; ";
        }
        if ((hdr = spool_getheader(txn->req_hdrs, "Lock-Token"))) {
            buf_printf(&log, "%slock-token=%s", sep, hdr[0]);
            sep = "; ";
        }
        if ((hdr = spool_getheader(txn->req_hdrs, "If"))) {
            buf_printf(&log, "%sif=%s", sep, hdr[0]);
            sep = "; ";
        }
        if ((hdr = spool_getheader(txn->req_hdrs, "If-Schedule-Tag-Match"))) {
            buf_printf(&log, "%sif-schedule-tag-match=%s", sep, hdr[0]);
            sep = "; ";
        }
        else if ((hdr = spool_getheader(txn->req_hdrs, "If-Match"))) {
            buf_printf(&log, "%sif-match=%s", sep, hdr[0]);
            sep = "; ";
        }
        else if ((hdr = spool_getheader(txn->req_hdrs, "If-Unmodified-Since"))) {
            buf_printf(&log, "%sif-unmodified-since=%s", sep, hdr[0]);
            sep = "; ";
        }
        if ((hdr = spool_getheader(txn->req_hdrs, "If-None-Match"))) {
            buf_printf(&log, "%sif-none-match=%s", sep, hdr[0]);
            sep = "; ";
        }
        else if ((hdr = spool_getheader(txn->req_hdrs, "If-Modified-Since"))) {
            buf_printf(&log, "%sif-modified-since=%s", sep, hdr[0]);
            sep = "; ";
        }
        if ((hdr = spool_getheader(txn->req_hdrs, ":type"))) {
            buf_printf(&log, "%stype=%s", sep, hdr[0]);
            sep = "; ";
        }
        if ((hdr = spool_getheader(txn->req_hdrs, "Depth"))) {
            buf_printf(&log, "%sdepth=%s", sep, hdr[0]);
            sep = "; ";
        }
        if (*sep == ';') buf_appendcstr(&log, ")");
    }
    /* Add response */
    buf_printf(&log, " => \"%s %s\"",
               txn->flags.ver == VER_2 ? HTTP2_VERSION : HTTP_VERSION,
               error_message(code));
    /* Add any auxiliary response data */
    if (txn->location) {
        buf_printf(&log, " (location=%s)", txn->location);
    }
    else if (txn->flags.cors) {
        buf_appendcstr(&log, " (allow-origin)");
    }
    else if (txn->error.desc) {
        buf_printf(&log, " (error=%s)", txn->error.desc);
    }
    syslog(LOG_INFO, "%s", buf_cstring(&log));
}


EXPORTED void keepalive_response(struct transaction_t *txn)
{
    if (gotsigalrm) {
        response_header(HTTP_PROCESSING, txn);
        alarm(httpd_keepalive);
    }
}


/*
 * Output an HTTP response with multipart body data.
 *
 * An initial call with 'code' != 0 will output a response header
 * and the preamble.
 * All subsequent calls should have 'code' = 0 to output just a body part.
 * A final call with 'len' = 0 ends the multipart body.
 */
EXPORTED void write_multipart_body(long code, struct transaction_t *txn,
                          const char *buf, unsigned len)
{
    static char boundary[100];
    struct buf *body = &txn->resp_body.payload;

    if (code) {
        const char *preamble =
            "This is a message with multiple parts in MIME format.\r\n";

        txn->flags.mime = 1;

        /* Create multipart boundary */
        snprintf(boundary, sizeof(boundary), "%s-%ld-%ld-%ld",
                 *spool_getheader(txn->req_hdrs, "Host"),
                 (long) getpid(), (long) time(0), (long) rand());

        /* Create Content-Type w/ boundary */
        assert(!buf_len(&txn->buf));
        buf_printf(&txn->buf, "%s; boundary=\"%s\"",
                   txn->resp_body.type, boundary);
        txn->resp_body.type = buf_cstring(&txn->buf);

        /* Setup for chunked response and begin multipart */
        txn->flags.te |= TE_CHUNKED;
        if (!buf) {
            buf = preamble;
            len = strlen(preamble);
        }
        write_body(code, txn, buf, len);
    }
    else if (len) {
        /* Output delimiter and MIME part-headers */
        buf_reset(body);
        buf_printf(body, "\r\n--%s\r\n", boundary);
        buf_printf(body, "Content-Type: %s\r\n", txn->resp_body.type);
        if (txn->resp_body.range) {
            buf_printf(body, "Content-Range: bytes %lu-%lu/%lu\r\n",
                       txn->resp_body.range->first,
                       txn->resp_body.range->last,
                       txn->resp_body.len);
        }
        buf_printf(body, "Content-Length: %d\r\n\r\n", len);
        write_body(0, txn, buf_cstring(body), buf_len(body));

        /* Output body-part data */
        write_body(0, txn, buf, len);
    }
    else {
        const char *epilogue = "\r\nEnd of MIME multipart body.\r\n";

        /* Output close-delimiter and epilogue */
        buf_reset(body);
        buf_printf(body, "\r\n--%s--\r\n%s", boundary, epilogue);
        write_body(0, txn, buf_cstring(body), buf_len(body));

        /* End of output */
        write_body(0, txn, NULL, 0);
    }
}


/* Output multipart/byteranges */
static void multipart_byteranges(struct transaction_t *txn,
                                 const char *msg_base)
{
    /* Save Content-Range and Content-Type pointers */
    struct range *range = txn->resp_body.range;
    const char *type = txn->resp_body.type;

    /* Start multipart response */
    txn->resp_body.range = NULL;
    txn->resp_body.type = "multipart/byteranges";
    write_multipart_body(HTTP_PARTIAL, txn, NULL, 0);

    txn->resp_body.type = type;
    while (range) {
        unsigned long offset = range->first;
        unsigned long datalen = range->last - range->first + 1;
        struct range *next = range->next;

        /* Output range as body part */
        txn->resp_body.range = range;
        write_multipart_body(0, txn, msg_base + offset, datalen);

        /* Cleanup */
        free(range);
        range = next;
    }

    /* End of multipart body */
    write_multipart_body(0, txn, NULL, 0);
}


/*
 * Output an HTTP response with body data, compressed as necessary.
 *
 * For chunked body data, an initial call with 'code' != 0 will output
 * a response header and the first body chunk.
 * All subsequent calls should have 'code' = 0 to output just the body chunk.
 * A final call with 'len' = 0 ends the chunked body.
 *
 * NOTE: HTTP/1.0 clients can't handle chunked encoding,
 *       so we use bare chunks and close the connection when done.
 */
EXPORTED void write_body(long code, struct transaction_t *txn,
                         const char *buf, unsigned len)
{
    unsigned is_dynamic = code ? (txn->flags.te & TE_CHUNKED) : 1;
    unsigned outlen = len, offset = 0;
    int do_md5 = (txn->meth == METH_HEAD) ? 0 :
        config_getswitch(IMAPOPT_HTTPCONTENTMD5);
    static MD5_CTX ctx;
    static unsigned char md5[MD5_DIGEST_LENGTH];

    syslog(LOG_DEBUG, "write_body(code = %ld, flags.te = %#x, len = %u)",
           code, txn->flags.te, len);

    if (!is_dynamic && len < GZIP_MIN_LEN) {
        /* Don't compress small static content */
        txn->resp_body.enc = CE_IDENTITY;
        txn->flags.te = TE_NONE;
    }

    /* Compress data */
    if (txn->resp_body.enc == CE_BR) {
#ifdef HAVE_BROTLI
        /* Only flush for static content or on last (zero-length) chunk */
        unsigned op = (is_dynamic && len) ?
            BROTLI_OPERATION_FLUSH : BROTLI_OPERATION_FINISH;
        BrotliEncoderState *brotli = txn->conn->brotli;
        const uint8_t *next_in = (const uint8_t *) buf;
        size_t avail_in = (size_t) len;

        buf_ensure(&txn->zbuf, BrotliEncoderMaxCompressedSize(avail_in));
        buf_reset(&txn->zbuf);

        do {
            uint8_t *next_out = (uint8_t *) txn->zbuf.s + txn->zbuf.len;
            size_t avail_out = txn->zbuf.alloc - txn->zbuf.len;

            if (!BrotliEncoderCompressStream(brotli, op,
                                             &avail_in, &next_in,
                                             &avail_out, &next_out, NULL)) {
                syslog(LOG_ERR, "Brotli: Error while compressing data");
                fatal("Brotli: Error while compressing data", EC_SOFTWARE);
            }

            txn->zbuf.len = txn->zbuf.alloc - avail_out;
        } while (avail_in || BrotliEncoderHasMoreOutput(brotli));

        buf = txn->zbuf.s;
        outlen = txn->zbuf.len;

        if (BrotliEncoderIsFinished(brotli)) {
            BrotliEncoderDestroyInstance(brotli);
            txn->conn->brotli = brotli_init();
        }
#else
        /* XXX should never get here */
        fatal("Brotli Compression requested, but not available", EC_SOFTWARE);
#endif /* HAVE_BROTLI */
    }
    else if (txn->resp_body.enc || txn->flags.te & ~TE_CHUNKED) {
#ifdef HAVE_ZLIB
        /* Only flush for static content or on last (zero-length) chunk */
        unsigned flush = (is_dynamic && len) ? Z_NO_FLUSH : Z_FINISH;
        z_stream *zstrm = txn->conn->zstrm;

        if (code) deflateReset(zstrm);

        zstrm->next_in = (Bytef *) buf;
        zstrm->avail_in = len;

        buf_ensure(&txn->zbuf, deflateBound(zstrm, zstrm->avail_in));
        buf_reset(&txn->zbuf);

        do {
            zstrm->next_out = (Bytef *) txn->zbuf.s + txn->zbuf.len;
            zstrm->avail_out = txn->zbuf.alloc - txn->zbuf.len;

            deflate(zstrm, flush);
            txn->zbuf.len = txn->zbuf.alloc - zstrm->avail_out;

        } while (!zstrm->avail_out);

        buf = txn->zbuf.s;
        outlen = txn->zbuf.len;
#else
        /* XXX should never get here */
        fatal("Compression requested, but no zlib", EC_SOFTWARE);
#endif /* HAVE_ZLIB */
    }

    if (code) {
        /* Initial call - prepare response header based on CE, TE and version */
        if (do_md5) MD5Init(&ctx);

        if (txn->flags.te & ~TE_CHUNKED) {
            /* Transfer-Encoded content MUST be chunked */
            txn->flags.te |= TE_CHUNKED;

            if (!is_dynamic) {
                /* Handle static content as last chunk */
                len = 0;
            }
        }

        if (!(txn->flags.te & TE_CHUNKED)) {
            /* Full/partial body (no encoding).
             *
             * In all cases, 'resp_body.len' is used to specify complete-length
             * In the case of a 206 or 416 response, Content-Length will be
             * set accordingly in response_header().
             */
            txn->resp_body.len = outlen;

            if (code == HTTP_PARTIAL) {
                /* check_precond() tells us that this is a range request */
                code = parse_ranges(*spool_getheader(txn->req_hdrs, "Range"),
                                    outlen, &txn->resp_body.range);

                switch (code) {
                case HTTP_OK:
                    /* Full body (unknown range-unit) */
                    break;

                case HTTP_PARTIAL:
                    /* One or more range request(s) */
                    txn->resp_body.len = outlen;

                    if (txn->resp_body.range->next) {
                        /* Multiple ranges */
                        multipart_byteranges(txn, buf);
                        return;
                    }
                    else {
                        /* Single range - set data parameters accordingly */
                        offset += txn->resp_body.range->first;
                        outlen = txn->resp_body.range->last -
                            txn->resp_body.range->first + 1;
                    }
                    break;

                case HTTP_BAD_RANGE:
                    /* No valid ranges */
                    outlen = 0;
                    break;
                }
            }

            if (outlen && do_md5) {
                MD5Update(&ctx, buf+offset, outlen);
                MD5Final(md5, &ctx);
                txn->resp_body.md5 = md5;
            }
        }
        else if (txn->flags.ver == VER_1_0) {
            /* HTTP/1.0 doesn't support chunked - close-delimit the body */
            txn->flags.conn = CONN_CLOSE;
        }
        else if (do_md5) txn->flags.trailer = TRAILER_CMD5;

        response_header(code, txn);

        /* MUST NOT send a body for 1xx/204/304 response or any HEAD response */
        switch (code) {
        case HTTP_CONTINUE:
        case HTTP_SWITCH_PROT:
        case HTTP_PROCESSING:
        case HTTP_NO_CONTENT:
        case HTTP_NOT_MODIFIED:
            return;

        default:
            if (txn->meth == METH_HEAD) return;
        }
    }

    /* Output data */
#ifdef HAVE_NGHTTP2
    if (txn->flags.ver == VER_2) {
        int r;
        uint8_t flags = NGHTTP2_FLAG_END_STREAM;
        struct protstream *s = prot_readmap(buf + offset, outlen);
        nghttp2_data_provider prd;

        prd.source.ptr = s;
        prd.read_callback = http2_data_source_read_cb;

        if (txn->flags.te & TE_CHUNKED) {
            if (len) {
                flags = NGHTTP2_FLAG_NONE;
                if (outlen && (txn->flags.trailer & TRAILER_CMD5)) {
                    MD5Update(&ctx, buf + offset, outlen);
                }
            }
            else if (txn->flags.trailer) {
                flags = NGHTTP2_FLAG_NONE;
                if (txn->flags.trailer & TRAILER_CMD5) MD5Final(md5, &ctx);
            }
        }

        syslog(LOG_DEBUG,
               "nghttp2_submit_data(id=%d, len=%d, outlen=%d, flags=%#x)",
               txn->http2.stream_id, len, outlen, flags);

        r = nghttp2_submit_data(txn->conn->http2_session,
                                flags, txn->http2.stream_id, &prd);
        if (r) {
            syslog(LOG_ERR, "nghttp2_submit_data: %s", nghttp2_strerror(r));
        }
        else {
            r = nghttp2_session_send(txn->conn->http2_session);
            if (r) {
                syslog(LOG_ERR, "nghttp2_session_send: %s", nghttp2_strerror(r));
            }
        }

        if (!len && (txn->flags.trailer & TRAILER_CMD5)) {
            begin_resp_headers(txn, 0);
            content_md5_hdr(txn, md5);
            end_resp_headers(txn, 0);
        }

        prot_free(s);
        return;
    }
#endif /* HAVE_NGHTTP2 */

    if ((txn->flags.te & TE_CHUNKED) && txn->flags.ver == VER_1_1) {
        /* HTTP/1.1 chunk */
        if (outlen) {
            syslog(LOG_DEBUG, "write_body: chunk(%d)", outlen);
            prot_printf(httpd_out, "%x\r\n", outlen);
            prot_write(httpd_out, buf, outlen);
            prot_puts(httpd_out, "\r\n");

            if (txn->flags.trailer & TRAILER_CMD5) MD5Update(&ctx, buf, outlen);
        }
        if (!len) {
            /* Terminate the HTTP/1.1 body with a zero-length chunk */
            syslog(LOG_DEBUG, "write_body: last chunk");
            prot_puts(httpd_out, "0\r\n");

            /* Trailer */
            if (txn->flags.trailer & TRAILER_CMD5) {
                syslog(LOG_DEBUG, "write_body: trailer");
                MD5Final(md5, &ctx);
                content_md5_hdr(txn, md5);
            }

            if (txn->flags.trailer != TRAILER_PROXY) {
                syslog(LOG_DEBUG, "write_body: CRLF");
                prot_puts(httpd_out, "\r\n");
            }
        }
    }
    else {
        /* Full body or HTTP/1.0 close-delimited body */
        prot_write(httpd_out, buf + offset, outlen);
    }
}


/* Output an HTTP response with application/xml body */
EXPORTED void xml_response(long code, struct transaction_t *txn, xmlDocPtr xml)
{
    xmlChar *buf;
    int bufsiz;

    switch (code) {
    case HTTP_OK:
    case HTTP_CREATED:
    case HTTP_NO_CONTENT:
    case HTTP_MULTI_STATUS:
        break;

    default:
        /* Neither Brief nor Prefer affect error response bodies */
        txn->flags.vary &= ~(VARY_BRIEF | VARY_PREFER);
        txn->resp_body.prefs = 0;
    }

    /* Dump XML response tree into a text buffer */
    xmlDocDumpFormatMemoryEnc(xml, &buf, &bufsiz, "utf-8",
                              config_httpprettytelemetry);

    if (buf) {
        /* Output the XML response */
        txn->resp_body.type = "application/xml; charset=utf-8";

        write_body(code, txn, (char *) buf, bufsiz);

        /* Cleanup */
        xmlFree(buf);
    }
    else {
        txn->error.precond = 0;
        txn->error.desc = "Error dumping XML tree\r\n";
        error_response(HTTP_SERVER_ERROR, txn);
    }
}

EXPORTED void buf_printf_markup(struct buf *buf, unsigned level, const char *fmt, ...)
{
    va_list args;
    const char *eol = "\n";

    if (!config_httpprettytelemetry) {
        level = 0;
        eol = "";
    }

    va_start(args, fmt);

    buf_printf(buf, "%*s", level * MARKUP_INDENT, "");
    buf_vprintf(buf, fmt, args);
    buf_appendcstr(buf, eol);

    va_end(args);
}


/* Output an HTTP error response with optional XML or HTML body */
EXPORTED void error_response(long code, struct transaction_t *txn)
{
    struct buf *html = &txn->resp_body.payload;

    /* Neither Brief nor Prefer affect error response bodies */
    txn->flags.vary &= ~(VARY_BRIEF | VARY_PREFER);
    txn->resp_body.prefs = 0;

#ifdef WITH_DAV
    if (code != HTTP_UNAUTHORIZED && txn->error.precond) {
        xmlNodePtr root = xml_add_error(NULL, &txn->error, NULL);

        if (root) {
            xml_response(code, txn, root->doc);
            xmlFreeDoc(root->doc);
            return;
        }
    }
#endif /* WITH_DAV */

    if (!txn->error.desc) {
        switch (code) {
            /* 4xx codes */
        case HTTP_BAD_REQUEST:
            txn->error.desc =
                "The request was not understood by this server.";
            break;

        case HTTP_NOT_FOUND:
            txn->error.desc =
                "The requested URL was not found on this server.";
            break;

        case HTTP_NOT_ALLOWED:
            txn->error.desc =
                "The requested method is not allowed for the URL.";
            break;

        case HTTP_GONE:
            txn->error.desc =
                "The requested URL has been removed from this server.";
            break;

            /* 5xx codes */
        case HTTP_SERVER_ERROR:
            txn->error.desc =
                "The server encountered an internal error.";
            break;

        case HTTP_NOT_IMPLEMENTED:
            txn->error.desc =
                "The requested method is not implemented by this server.";
            break;

        case HTTP_UNAVAILABLE:
            txn->error.desc =
                "The server is unable to process the request at this time.";
            break;
        }
    }

    if (txn->error.desc) {
        const char **hdr, *host = "";
        char *port = NULL;
        unsigned level = 0;

        if (txn->req_hdrs &&
            (hdr = spool_getheader(txn->req_hdrs, "Host")) &&
            hdr[0] && *hdr[0]) {
            host = (char *) hdr[0];
            if ((port = strchr(host, ':'))) *port++ = '\0';
        }
        else if (config_serverinfo != IMAP_ENUM_SERVERINFO_OFF) {
            host = config_servername;
        }
        if (!port) {
            port = (saslprops.iplocalport) ?
                strchr(saslprops.iplocalport, ';')+1 : "";
        }

        buf_printf_markup(html, level, HTML_DOCTYPE);
        buf_printf_markup(html, level++, "<html>");
        buf_printf_markup(html, level++, "<head>");
        buf_printf_markup(html, level, "<title>%s</title>",
                          error_message(code));
        buf_printf_markup(html, --level, "</head>");
        buf_printf_markup(html, level++, "<body>");
        buf_printf_markup(html, level, "<h1>%s</h1>", error_message(code)+4);
        buf_printf_markup(html, level, "<p>%s</p>", txn->error.desc);
        buf_printf_markup(html, level, "<hr>");
        buf_printf_markup(html, level,
                          "<address>%s Server at %s Port %s</address>",
                          buf_cstring(&serverinfo), host, port);
        buf_printf_markup(html, --level, "</body>");
        buf_printf_markup(html, --level, "</html>");

        txn->resp_body.type = "text/html; charset=utf-8";
    }

    write_body(code, txn, buf_cstring(html), buf_len(html));
}


static int proxy_authz(const char **authzid, struct transaction_t *txn)
{
    static char authzbuf[MAX_MAILBOX_BUFFER];
    unsigned authzlen;
    int status;

    syslog(LOG_DEBUG, "proxy_auth: authzid='%s'", *authzid);

    /* Free userid & authstate previously allocated for auth'd user */
    if (httpd_userid) {
        free(httpd_userid);
        httpd_userid = NULL;
    }
    if (httpd_extrafolder) {
        free(httpd_extrafolder);
        httpd_extrafolder = NULL;
    }
    if (httpd_extradomain) {
        free(httpd_extradomain);
        httpd_extradomain = NULL;
    }
    if (httpd_authstate) {
        auth_freestate(httpd_authstate);
        httpd_authstate = NULL;
    }

    if (!(config_mupdate_server && config_getstring(IMAPOPT_PROXYSERVERS))) {
        /* Not a backend in a Murder - proxy authz is not allowed */
        syslog(LOG_NOTICE, "badlogin: %s %s %s %s",
               httpd_clienthost, txn->auth_chal.scheme->name, saslprops.authid,
               "proxy authz attempted on non-Murder backend");
        return SASL_NOAUTHZ;
    }

    /* Canonify the authzid */
    status = mysasl_canon_user(httpd_saslconn, NULL,
                               *authzid, strlen(*authzid),
                               SASL_CU_AUTHZID, NULL,
                               authzbuf, sizeof(authzbuf), &authzlen);
    if (status) {
        syslog(LOG_NOTICE, "badlogin: %s %s %s invalid user",
               httpd_clienthost, txn->auth_chal.scheme->name,
               beautify_string(*authzid));
        return status;
    }

    /* See if auth'd user is allowed to proxy */
    status = mysasl_proxy_policy(httpd_saslconn, &httpd_proxyctx,
                                 authzbuf, authzlen,
                                 saslprops.authid, strlen(saslprops.authid),
                                 NULL, 0, NULL);

    if (status) {
        syslog(LOG_NOTICE, "badlogin: %s %s %s %s",
               httpd_clienthost, txn->auth_chal.scheme->name, saslprops.authid,
               sasl_errdetail(httpd_saslconn));
        return status;
    }

    *authzid = authzbuf;

    return status;
}


/* Write cached header (redacting authorization credentials) to buffer. */
static void log_cachehdr(const char *name, const char *contents, void *rock)
{
    struct buf *buf = (struct buf *) rock;

    /* Ignore private headers in our cache */
    if (name[0] == ':') return;

    buf_printf(buf, "%c%s: ", toupper(name[0]), name+1);
    if (!strcmp(name, "authorization")) {
        /* Replace authorization credentials with an ellipsis */
        const char *creds = strchr(contents, ' ') + 1;
        buf_printf(buf, "%.*s%-*s\r\n", (int) (creds - contents), contents,
                   (int) strlen(creds), "...");
    }
    else buf_printf(buf, "%s\r\n", contents);
}


static void auth_success(struct transaction_t *txn, const char *userid)
{
    struct auth_scheme_t *scheme = txn->auth_chal.scheme;
    int i;

    httpd_userid = xstrdup(userid);
    httpd_userisanonymous = is_userid_anonymous(httpd_userid);

    syslog(LOG_NOTICE, "login: %s %s %s%s %s SESSIONID=<%s>",
           httpd_clienthost, httpd_userid, scheme->name,
           httpd_tls_done ? "+TLS" : "", "User logged in",
           session_id());


    /* Recreate telemetry log entry for request (w/ credentials redacted) */
    assert(!buf_len(&txn->buf));
    buf_printf(&txn->buf, "<%ld<", time(NULL));         /* timestamp */
    buf_printf(&txn->buf, "%s %s %s\r\n",               /* request-line*/
               txn->req_line.meth, txn->req_line.uri, txn->req_line.ver);
    spool_enum_hdrcache(txn->req_hdrs,                  /* header fields */
                        &log_cachehdr, &txn->buf);
    buf_appendcstr(&txn->buf, "\r\n");                  /* CRLF */
    buf_append(&txn->buf, &txn->req_body.payload);      /* message body */
    buf_appendmap(&txn->buf,                            /* buffered input */
                  (const char *) httpd_in->ptr, httpd_in->cnt);

    if (httpd_logfd != -1) {
        /* Rewind log to current request and truncate it */
        off_t end = lseek(httpd_logfd, 0, SEEK_END);

        ftruncate(httpd_logfd, end - buf_len(&txn->buf));

        /* Close existing telemetry log */
        close(httpd_logfd);
    }

    prot_setlog(httpd_in, PROT_NO_FD);
    prot_setlog(httpd_out, PROT_NO_FD);

    /* Create telemetry log based on new userid */
    httpd_logfd = telemetry_log(httpd_userid, httpd_in, httpd_out, 0);

    if (httpd_logfd != -1) {
        /* Log credential-redacted request */
        write(httpd_logfd, buf_cstring(&txn->buf), buf_len(&txn->buf));
    }

    buf_reset(&txn->buf);

    /* Do any namespace specific post-auth processing */
    for (i = 0; namespaces[i]; i++) {
        if (namespaces[i]->enabled && namespaces[i]->auth)
            namespaces[i]->auth(httpd_userid);
    }
}


/* Perform HTTP Authentication based on the given credentials ('creds').
 * Returns the selected auth scheme and any server challenge in 'chal'.
 * May be called multiple times if auth scheme requires multiple steps.
 * SASL status between steps is maintained in 'status'.
 */
#define BASE64_BUF_SIZE 21848   /* per RFC 4422: ((16K / 3) + 1) * 4  */

static int http_auth(const char *creds, struct transaction_t *txn)
{
    struct auth_challenge_t *chal = &txn->auth_chal;
    static int status = SASL_OK;
    int slen;
    const char *clientin = NULL, *realm = NULL, *user, **authzid;
    unsigned int clientinlen = 0;
    struct auth_scheme_t *scheme;
    static char base64[BASE64_BUF_SIZE+1];
    const void *canon_user;

    /* Split credentials into auth scheme and response */
    slen = strcspn(creds, " \0");
    if ((clientin = strchr(creds, ' '))) clientinlen = strlen(++clientin);

    syslog(LOG_DEBUG,
           "http_auth: status=%d   scheme='%s'   creds='%.*s%s'",
           status, chal->scheme ? chal->scheme->name : "",
           slen, creds, clientin ? " <response>" : "");

    /* Free userid & authstate previously allocated for auth'd user */
    if (httpd_userid) {
        free(httpd_userid);
        httpd_userid = NULL;
    }
    if (httpd_extrafolder) {
        free(httpd_extrafolder);
        httpd_extrafolder = NULL;
    }
    if (httpd_extradomain) {
        free(httpd_extradomain);
        httpd_extradomain = NULL;
    }
    if (httpd_authstate) {
        auth_freestate(httpd_authstate);
        httpd_authstate = NULL;
    }
    chal->param = NULL;

    if (chal->scheme) {
        /* Use current scheme, if possible */
        scheme = chal->scheme;

        if (strncasecmp(scheme->name, creds, slen)) {
            /* Changing auth scheme -> reset state */
            syslog(LOG_DEBUG, "http_auth: changing scheme");
            reset_saslconn(&httpd_saslconn);
            chal->scheme = NULL;
            status = SASL_OK;
        }
    }

    if (!chal->scheme) {
        /* Find the client-specified auth scheme */
        syslog(LOG_DEBUG, "http_auth: find client scheme");
        for (scheme = auth_schemes; scheme->name; scheme++) {
            if (slen && !strncasecmp(scheme->name, creds, slen)) {
                /* Found a supported scheme, see if its available */
                if (!(avail_auth_schemes & (1 << scheme->idx))) scheme = NULL;
                break;
            }
        }
        if (!scheme || !scheme->name) {
            /* Didn't find a matching scheme that is available */
            syslog(LOG_DEBUG, "Unknown auth scheme '%.*s'", slen, creds);
            return SASL_NOMECH;
        }
        /* We found it! */
        syslog(LOG_DEBUG, "http_auth: found matching scheme: %s", scheme->name);
        chal->scheme = scheme;
        status = SASL_OK;
    }

    /* Base64 decode any client response, if necesary */
    if (clientin && (scheme->flags & AUTH_BASE64)) {
        int r = sasl_decode64(clientin, clientinlen,
                              base64, BASE64_BUF_SIZE, &clientinlen);
        if (r != SASL_OK) {
            syslog(LOG_ERR, "Base64 decode failed: %s",
                   sasl_errstring(r, NULL, NULL));
            return r;
        }
        clientin = base64;
    }

    /* Get realm - based on namespace of URL */
    switch (txn->req_tgt.namespace->id) {
    case URL_NS_DEFAULT:
    case URL_NS_PRINCIPAL:
        realm = config_getstring(IMAPOPT_DAV_REALM);
        break;

    case URL_NS_CALENDAR:
        realm = config_getstring(IMAPOPT_CALDAV_REALM);
        break;

    case URL_NS_ADDRESSBOOK:
        realm = config_getstring(IMAPOPT_CARDDAV_REALM);
        break;

    case URL_NS_RSS:
        realm = config_getstring(IMAPOPT_RSS_REALM);
        break;
    }
    if (!realm) realm = config_servername;

#ifdef SASL_HTTP_REQUEST
    /* Setup SASL HTTP request, if necessary */
    if (scheme->flags & AUTH_NEED_REQUEST) {
        sasl_http_request_t sasl_http_req;

        sasl_http_req.method = txn->req_line.meth;
        sasl_http_req.uri = txn->req_line.uri;
        sasl_http_req.entity = NULL;
        sasl_http_req.elen = 0;
        sasl_http_req.non_persist = txn->flags.conn & CONN_CLOSE;
        sasl_setprop(httpd_saslconn, SASL_HTTP_REQUEST, &sasl_http_req);
    }
#endif /* SASL_HTTP_REQUEST */

    if (scheme->idx == AUTH_BASIC) {
        /* Basic (plaintext) authentication */
        char *pass;
        char *extra;
        char *plus;
        char *domain;

        if (!clientin) {
            /* Create initial challenge (base64 buffer is static) */
            snprintf(base64, BASE64_BUF_SIZE, "realm=\"%s\"", realm);
            chal->param = base64;
            chal->scheme = NULL;  /* make sure we don't reset the SASL ctx */
            return status;
        }

        /* Split credentials into <user> ':' <pass>.
         * We are working with base64 buffer, so we can modify it.
         */
        user = base64;
        pass = strchr(base64, ':');
        if (!pass) {
            syslog(LOG_ERR, "Basic auth: Missing password");
            return SASL_BADPARAM;
        }
        *pass++ = '\0';
        domain = strchr(user, '@');
        if (domain) *domain++ = '\0';
        extra = strchr(user, '%');
        if (extra) *extra++ = '\0';
        plus = strchr(user, '+');
        if (plus) *plus++ = '\0';
        /* Verify the password */
        char *realuser = domain ? strconcat(user, "@", domain, (char *)NULL) : xstrdup(user);
        status = sasl_checkpass(httpd_saslconn, realuser, strlen(realuser),
                                pass, strlen(pass));
        memset(pass, 0, strlen(pass));          /* erase plaintext password */

        if (status) {
            syslog(LOG_NOTICE, "badlogin: %s Basic %s %s",
                   httpd_clienthost, realuser, sasl_errdetail(httpd_saslconn));
            free(realuser);

            /* Don't allow user probing */
            if (status == SASL_NOUSER) status = SASL_BADAUTH;
            return status;
        }
        free(realuser);

        /* Successful authentication - fall through */
        httpd_extrafolder = xstrdupnull(plus);
        httpd_extradomain = xstrdupnull(extra);
    }
    else {
        /* SASL-based authentication (Digest, Negotiate, NTLM) */
        const char *serverout = NULL;
        unsigned int serveroutlen = 0;

        if (status == SASL_CONTINUE) {
            /* Continue current authentication exchange */
            syslog(LOG_DEBUG, "http_auth: continue %s", scheme->saslmech);
            status = sasl_server_step(httpd_saslconn, clientin, clientinlen,
                                      &serverout, &serveroutlen);
        }
        else {
            /* Start new authentication exchange */
            syslog(LOG_DEBUG, "http_auth: start %s", scheme->saslmech);
            status = sasl_server_start(httpd_saslconn, scheme->saslmech,
                                       clientin, clientinlen,
                                       &serverout, &serveroutlen);
        }

        /* Failure - probably bad client response */
        if ((status != SASL_OK) && (status != SASL_CONTINUE)) {
            syslog(LOG_ERR, "SASL failed: %s",
                   sasl_errstring(status, NULL, NULL));
            return status;
        }

        /* Base64 encode any server challenge, if necesary */
        if (serverout && (scheme->flags & AUTH_BASE64)) {
            int r = sasl_encode64(serverout, serveroutlen,
                                   base64, BASE64_BUF_SIZE, NULL);
            if (r != SASL_OK) {
                syslog(LOG_ERR, "Base64 encode failed: %s",
                       sasl_errstring(r, NULL, NULL));
                return r;
            }
            serverout = base64;
        }

        chal->param = serverout;

        if (status == SASL_CONTINUE) {
            /* Need another step to complete authentication */
            return status;
        }

        /* Successful authentication
         *
         * HTTP doesn't support security layers,
         * so don't attach SASL context to prot layer.
         */
    }

    /* Get the userid from SASL - already canonicalized */
    status = sasl_getprop(httpd_saslconn, SASL_USERNAME, &canon_user);
    if (status != SASL_OK) {
        syslog(LOG_ERR, "weird SASL error %d getting SASL_USERNAME", status);
        return status;
    }
    user = (const char *) canon_user;

    if (saslprops.authid) free(saslprops.authid);
    saslprops.authid = xstrdup(user);

    authzid = spool_getheader(txn->req_hdrs, "Authorize-As");
    if (authzid && *authzid[0]) {
        /* Trying to proxy as another user */
        user = authzid[0];

        status = proxy_authz(&user, txn);
        if (status) return status;
    }

    auth_success(txn, user);

    return status;
}


/*************************  Method Execution Routines  ************************/


/* Compare an etag in a header to a resource etag.
 * Returns 0 if a match, non-zero otherwise.
 */
EXPORTED int etagcmp(const char *hdr, const char *etag)
{
    size_t len;

    if (!etag) return -1;               /* no representation       */
    if (!strcmp(hdr, "*")) return 0;    /* any representation      */

    len = strlen(etag);
    if (!strncmp(hdr, "W/", 2)) hdr+=2; /* skip weak prefix        */
    if (*hdr++ != '\"') return 1;       /* match/skip open DQUOTE  */
    if (strlen(hdr) != len+1) return 1; /* make sure lengths match */
    if (hdr[len] != '\"') return 1;     /* match close DQUOTE      */

    return strncmp(hdr, etag, len);
}


/* Compare a resource etag to a comma-separated list and/or multiple headers
 * looking for a match.  Returns 1 if a match is found, 0 otherwise.
 */
static unsigned etag_match(const char *hdr[], const char *etag)
{
    unsigned i, match = 0;
    tok_t tok;
    char *token;

    for (i = 0; !match && hdr[i]; i++) {
        tok_init(&tok, hdr[i], ",", TOK_TRIMLEFT|TOK_TRIMRIGHT);
        while (!match && (token = tok_next(&tok))) {
            if (!etagcmp(token, etag)) match = 1;
        }
        tok_fini(&tok);
    }

    return match;
}


static int parse_ranges(const char *hdr, unsigned long len,
                        struct range **ranges)
{
    int ret = HTTP_BAD_RANGE;
    struct range *new, *tail = *ranges = NULL;
    tok_t tok;
    char *token;

    if (!len) return HTTP_OK;  /* need to know length of representation */

    /* we only handle byte-unit */
    if (!hdr || strncmp(hdr, "bytes=", 6)) return HTTP_OK;

    tok_init(&tok, hdr+6, ",", TOK_TRIMLEFT|TOK_TRIMRIGHT);
    while ((token = tok_next(&tok))) {
        /* default to entire representation */
        unsigned long first = 0;
        unsigned long last = len - 1;
        char *p, *endp;

        if (!(p = strchr(token, '-'))) continue;  /* bad byte-range-set */

        if (p == token) {
            /* suffix-byte-range-spec */
            unsigned long suffix = strtoul(++p, &endp, 10);

            if (endp == p || *endp) continue;  /* bad suffix-length */
            if (!suffix) continue;      /* unsatisfiable suffix-length */

            /* don't start before byte zero */
            if (suffix < len) first = len - suffix;
        }
        else {
            /* byte-range-spec */
            first = strtoul(token, &endp, 10);
            if (endp != p) continue;      /* bad first-byte-pos */
            if (first >= len) continue;   /* unsatisfiable first-byte-pos */

            if (*++p) {
                /* last-byte-pos */
                last = strtoul(p, &endp, 10);
                if (*endp || last < first) continue; /* bad last-byte-pos */

                /* don't go past end of representation */
                if (last >= len) last = len - 1;
            }
        }

        ret = HTTP_PARTIAL;

        /* Coalesce overlapping ranges, or those with a gap < 80 bytes */
        if (tail &&
            first >= tail->first && (long) (first - tail->last) < 80) {
            tail->last = MAX(last, tail->last);
            continue;
        }

        /* Create a new range and append it to linked list */
        new = xzmalloc(sizeof(struct range));
        new->first = first;
        new->last = last;

        if (tail) tail->next = new;
        else *ranges = new;
        tail = new;
    }

    tok_fini(&tok);

    return ret;
}


/* Check headers for any preconditions.
 *
 * Interaction is complex and is documented in RFC 7232
 */
EXPORTED int check_precond(struct transaction_t *txn,
                           const char *etag, time_t lastmod)
{
    hdrcache_t hdrcache = txn->req_hdrs;
    const char **hdr;
    time_t since = 0;

    /* Step 1 */
    if ((hdr = spool_getheader(hdrcache, "If-Match"))) {
        if (!etag_match(hdr, etag)) return HTTP_PRECOND_FAILED;

        /* Continue to step 3 */
    }

    /* Step 2 */
    else if ((hdr = spool_getheader(hdrcache, "If-Unmodified-Since"))) {
        if (time_from_rfc822(hdr[0], &since) < 0) return HTTP_BAD_REQUEST;

        if (lastmod > since) return HTTP_PRECOND_FAILED;

        /* Continue to step 3 */
    }

    /* Step 3 */
    if ((hdr = spool_getheader(hdrcache, "If-None-Match"))) {
        if (etag_match(hdr, etag)) {
            if (txn->meth == METH_GET || txn->meth == METH_HEAD)
                return HTTP_NOT_MODIFIED;
            else
                return HTTP_PRECOND_FAILED;
        }

        /* Continue to step 5 */
    }

    /* Step 4 */
    else if ((txn->meth == METH_GET || txn->meth == METH_HEAD) &&
             (hdr = spool_getheader(hdrcache, "If-Modified-Since"))) {
        if (time_from_rfc822(hdr[0], &since) < 0) return HTTP_BAD_REQUEST;

        if (lastmod <= since) return HTTP_NOT_MODIFIED;

        /* Continue to step 5 */
    }

    /* Step 5 */
    if (txn->flags.ranges &&  /* Only if we support Range requests */
        txn->meth == METH_GET && (hdr = spool_getheader(hdrcache, "Range"))) {

        if ((hdr = spool_getheader(hdrcache, "If-Range"))) {
            time_from_rfc822(hdr[0], &since); /* error OK here, could be an etag */
        }

        /* Only process Range if If-Range isn't present or validator matches */
        if (!hdr || (since && (lastmod <= since)) || !etagcmp(hdr[0], etag))
            return HTTP_PARTIAL;
    }

    /* Step 6 */
    return HTTP_OK;
}


const struct mimetype {
    const char *ext;
    const char *type;
    unsigned int compressible;
} mimetypes[] = {
    { ".css",  "text/css", 1 },
    { ".htm",  "text/html", 1 },
    { ".html", "text/html", 1 },
    { ".ics",  "text/calendar", 1 },
    { ".ifb",  "text/calendar", 1 },
    { ".text", "text/plain", 1 },
    { ".txt",  "text/plain", 1 },

    { ".cgm",  "image/cgm", 1 },
    { ".gif",  "image/gif", 0 },
    { ".jpg",  "image/jpeg", 0 },
    { ".jpeg", "image/jpeg", 0 },
    { ".png",  "image/png", 0 },
    { ".svg",  "image/svg+xml", 1 },
    { ".tif",  "image/tiff", 1 },
    { ".tiff", "image/tiff", 1 },

    { ".aac",  "audio/aac", 0 },
    { ".m4a",  "audio/mp4", 0 },
    { ".mp3",  "audio/mpeg", 0 },
    { ".mpeg", "audio/mpeg", 0 },
    { ".oga",  "audio/ogg", 0 },
    { ".ogg",  "audio/ogg", 0 },
    { ".wav",  "audio/wav", 0 },

    { ".avi",  "video/x-msvideo", 0 },
    { ".mov",  "video/quicktime", 0 },
    { ".m4v",  "video/mp4", 0 },
    { ".ogv",  "video/ogg", 0 },
    { ".qt",   "video/quicktime", 0 },
    { ".wmv",  "video/x-ms-wmv", 0 },

    { ".bz",   "application/x-bzip", 0 },
    { ".bz2",  "application/x-bzip2", 0 },
    { ".gz",   "application/gzip", 0 },
    { ".gzip", "application/gzip", 0 },
    { ".tgz",  "application/gzip", 0 },
    { ".zip",  "application/zip", 0 },

    { ".doc",  "application/msword", 1 },
    { ".jcs",  "application/calendar+json", 1 },
    { ".jfb",  "application/calendar+json", 1 },
    { ".js",   "application/javascript", 1 },
    { ".json", "application/json", 1 },
    { ".pdf",  "application/pdf", 1 },
    { ".ppt",  "application/vnd.ms-powerpoint", 1 },
    { ".sh",   "application/x-sh", 1 },
    { ".tar",  "application/x-tar", 1 },
    { ".xcs",  "application/calendar+xml", 1 },
    { ".xfb",  "application/calendar+xml", 1 },
    { ".xls",  "application/vnd.ms-excel", 1 },
    { ".xml",  "application/xml", 1 },

    { NULL, NULL, 0 }
};


static int list_well_known(struct transaction_t *txn)
{
    static struct buf body = BUF_INITIALIZER;
    static time_t lastmod = 0;
    struct stat sbuf;
    int precond;

    /* stat() imapd.conf for Last-Modified and ETag */
    stat(config_filename, &sbuf);
    assert(!buf_len(&txn->buf));
    buf_printf(&txn->buf, "%ld-%ld-%ld",
               compile_time, sbuf.st_mtime, sbuf.st_size);
    sbuf.st_mtime = MAX(compile_time, sbuf.st_mtime);

    /* Check any preconditions, including range request */
    txn->flags.ranges = 1;
    precond = check_precond(txn, buf_cstring(&txn->buf), sbuf.st_mtime);

    switch (precond) {
    case HTTP_OK:
    case HTTP_NOT_MODIFIED:
        /* Fill in ETag, Last-Modified, and Expires */
        txn->resp_body.etag = buf_cstring(&txn->buf);
        txn->resp_body.lastmod = sbuf.st_mtime;
        txn->resp_body.maxage = 86400;  /* 24 hrs */
        txn->flags.cc |= CC_MAXAGE;

        if (precond != HTTP_NOT_MODIFIED) break;

    default:
        /* We failed a precondition - don't perform the request */
        return precond;
    }

    if (txn->resp_body.lastmod > lastmod) {
        const char *proto = NULL, *host = NULL;
        unsigned i, level = 0;

        /* Start HTML */
        buf_reset(&body);
        buf_printf_markup(&body, level, HTML_DOCTYPE);
        buf_printf_markup(&body, level++, "<html>");
        buf_printf_markup(&body, level++, "<head>");
        buf_printf_markup(&body, level,
                          "<title>%s</title>", "Well-Known Locations");
        buf_printf_markup(&body, --level, "</head>");
        buf_printf_markup(&body, level++, "<body>");
        buf_printf_markup(&body, level,
                          "<h2>%s</h2>", "Well-Known Locations");
        buf_printf_markup(&body, level++, "<ul>");

        /* Add the list of enabled /.well-known/ URLs */
        http_proto_host(txn->req_hdrs, &proto, &host);
        for (i = 0; namespaces[i]; i++) {

            if (namespaces[i]->enabled && namespaces[i]->well_known) {
                buf_printf_markup(&body, level,
                                  "<li><a href=\"%s://%s%s\">%s</a></li>",
                                  proto, host, namespaces[i]->prefix,
                                  namespaces[i]->well_known);
            }
        }

        /* Finish HTML */
        buf_printf_markup(&body, --level, "</ul>");
        buf_printf_markup(&body, --level, "</body>");
        buf_printf_markup(&body, --level, "</html>");

        lastmod = txn->resp_body.lastmod;
    }

    /* Output the HTML response */
    txn->resp_body.type = "text/html; charset=utf-8";
    write_body(precond, txn, buf_cstring(&body), buf_len(&body));

    return 0;
}


#define WELL_KNOWN_PREFIX "/.well-known"

/* Perform a GET/HEAD request */
static int meth_get(struct transaction_t *txn,
                    void *params __attribute__((unused)))
{
    int ret = 0, r, fd = -1, precond, len;
    const char *prefix, *urls, *path, *ext;
    static struct buf pathbuf = BUF_INITIALIZER;
    struct stat sbuf;
    const char *msg_base = NULL;
    size_t msg_size = 0;
    struct resp_body_t *resp_body = &txn->resp_body;

    /* Check if this is a request for /.well-known/ listing */
    len = strlen(WELL_KNOWN_PREFIX);
    if (!strncmp(txn->req_uri->path, WELL_KNOWN_PREFIX, len)) {
        if (txn->req_uri->path[len] == '/') len++;
        if (txn->req_uri->path[len] == '\0') return list_well_known(txn);
        else return HTTP_NOT_FOUND;
    }

    /* Serve up static pages */
    prefix = config_getstring(IMAPOPT_HTTPDOCROOT);
    if (!prefix) return HTTP_NOT_FOUND;

    if (*prefix != '/') {
        /* Remote content */
        struct backend *be;

        be = proxy_findserver(prefix, &http_protocol, httpd_userid,
                              &backend_cached, NULL, NULL, httpd_in);
        if (!be) return HTTP_UNAVAILABLE;

        return http_pipe_req_resp(be, txn);
    }

    /* Local content */
    if ((urls = config_getstring(IMAPOPT_HTTPALLOWEDURLS))) {
        tok_t tok = TOK_INITIALIZER(urls, " \t", TOK_TRIMLEFT|TOK_TRIMRIGHT);
        char *token;

        while ((token = tok_next(&tok)) && strcmp(token, txn->req_uri->path));
        tok_fini(&tok);

        if (!token) return HTTP_NOT_FOUND;
    }

    buf_setcstr(&pathbuf, prefix);
    buf_appendcstr(&pathbuf, txn->req_uri->path);
    path = buf_cstring(&pathbuf);

    /* See if path is a directory and look for index.html */
    if (!(r = stat(path, &sbuf)) && S_ISDIR(sbuf.st_mode)) {
        buf_appendcstr(&pathbuf, "/index.html");
        path = buf_cstring(&pathbuf);
        r = stat(path, &sbuf);
    }

    /* See if file exists and get Content-Length & Last-Modified time */
    if (r || !S_ISREG(sbuf.st_mode)) return HTTP_NOT_FOUND;

    if (!resp_body->type) {
        /* Caller hasn't specified the Content-Type */
        resp_body->type = "application/octet-stream";

        if ((ext = strrchr(path, '.'))) {
            /* Try to use filename extension to identity Content-Type */
            const struct mimetype *mtype;

            for (mtype = mimetypes; mtype->ext; mtype++) {
                if (!strcasecmp(ext, mtype->ext)) {
                    resp_body->type = mtype->type;
                    if (!mtype->compressible) {
                        /* Never compress non-compressible resources */
                        txn->resp_body.enc = CE_IDENTITY;
                        txn->flags.te = TE_NONE;
                        txn->flags.vary &= ~VARY_AE;
                    }
                    break;
                }
            }
        }
    }

    /* Generate Etag */
    assert(!buf_len(&txn->buf));
    buf_printf(&txn->buf, "%ld-%ld", (long) sbuf.st_mtime, (long) sbuf.st_size);

    /* Check any preconditions, including range request */
    txn->flags.ranges = 1;
    precond = check_precond(txn, buf_cstring(&txn->buf), sbuf.st_mtime);

    switch (precond) {
    case HTTP_OK:
    case HTTP_PARTIAL:
    case HTTP_NOT_MODIFIED:
        /* Fill in ETag, Last-Modified, and Expires */
        resp_body->etag = buf_cstring(&txn->buf);
        resp_body->lastmod = sbuf.st_mtime;
        resp_body->maxage = 86400;  /* 24 hrs */
        txn->flags.cc |= CC_MAXAGE;
        if (!httpd_userisanonymous) txn->flags.cc |= CC_PUBLIC;

        if (precond != HTTP_NOT_MODIFIED) break;

    default:
        /* We failed a precondition - don't perform the request */
        resp_body->type = NULL;
        return precond;
    }

    if (txn->meth == METH_GET) {
        /* Open and mmap the file */
        if ((fd = open(path, O_RDONLY)) == -1) return HTTP_SERVER_ERROR;
        map_refresh(fd, 1, &msg_base, &msg_size, sbuf.st_size, path, NULL);
    }

    write_body(precond, txn, msg_base, sbuf.st_size);

    if (fd != -1) {
        map_free(&msg_base, &msg_size);
        close(fd);
    }

    return ret;
}


/* Perform an OPTIONS request */
EXPORTED int meth_options(struct transaction_t *txn, void *params)
{
    parse_path_t parse_path = (parse_path_t) params;
    int r, i;

    /* Response should not be cached */
    txn->flags.cc |= CC_NOCACHE;

    /* Response doesn't have a body, so no Vary */
    txn->flags.vary = 0;

    /* Special case "*" - show all features/methods available on server */
    if (!strcmp(txn->req_uri->path, "*")) {
        for (i = 0; namespaces[i]; i++) {
            if (namespaces[i]->enabled)
                txn->req_tgt.allow |= namespaces[i]->allow;
        }
    }
    else {
        if (parse_path) {
            /* Parse the path */
            r = parse_path(txn->req_uri->path, &txn->req_tgt, &txn->error.desc);
            if (r) return r;
        }

        if (txn->flags.cors) {
            const char **hdr =
                spool_getheader(txn->req_hdrs, "Access-Control-Request-Method");

            if (hdr) {
                /* CORS preflight request */
                unsigned meth;

                txn->flags.cors = CORS_PREFLIGHT;

                /* Check Method against our list of known methods */
                for (meth = 0; (meth < METH_UNKNOWN) &&
                         strcmp(http_methods[meth].name, hdr[0]); meth++);

                if (meth == METH_UNKNOWN) txn->flags.cors = 0;
                else {
                    /* Check Method against those supported by the resource */
                    if (!txn->req_tgt.namespace->methods[meth].proc)
                        txn->flags.cors = 0;
                }
            }
        }
    }

    response_header(HTTP_OK, txn);
    return 0;
}


/* Perform an PROPFIND request on "/" iff we support CalDAV */
static int meth_propfind_root(struct transaction_t *txn,
                              void *params __attribute__((unused)))
{
    assert(txn);

#ifdef WITH_DAV
    /* Apple iCal and Evolution both check "/" */
    if (!strcmp(txn->req_uri->path, "/") ||
        !strcmp(txn->req_uri->path, "/dav/")) {
        /* Array of known "live" properties */
        const struct prop_entry root_props[] = {

            /* WebDAV ACL (RFC 3744) properties */
            { "principal-collection-set", NS_DAV, PROP_COLLECTION,
              propfind_princolset, NULL, NULL },

            /* WebDAV Current Principal (RFC 5397) properties */
            { "current-user-principal", NS_DAV, PROP_COLLECTION,
              propfind_curprin, NULL, NULL },

            { NULL, 0, 0, NULL, NULL, NULL }
        };

        struct meth_params root_params = {
            .propfind = { DAV_FINITE_DEPTH, root_props }
        };

        /* Make a working copy of target path */
        strlcpy(txn->req_tgt.path, txn->req_uri->path,
                sizeof(txn->req_tgt.path));
        txn->req_tgt.tail = txn->req_tgt.path + strlen(txn->req_tgt.path);

        txn->req_tgt.allow |= ALLOW_DAV;
        return meth_propfind(txn, &root_params);
    }
#endif /* WITH_DAV */

    return HTTP_NOT_ALLOWED;
}


/* Write cached header to buf, excluding any that might have sensitive data. */
static void trace_cachehdr(const char *name, const char *contents, void *rock)
{
    struct buf *buf = (struct buf *) rock;
    const char **hdr, *sensitive[] =
        { "authorization", "cookie", "proxy-authorization", NULL };

    /* Ignore private headers in our cache */
    if (name[0] == ':') return;

    for (hdr = sensitive; *hdr && strcmp(name, *hdr); hdr++);

    if (!*hdr) buf_printf(buf, "%c%s: %s\r\n",
                          toupper(name[0]), name+1, contents);
}

/* Perform an TRACE request */
EXPORTED int meth_trace(struct transaction_t *txn, void *params)
{
    parse_path_t parse_path = (parse_path_t) params;
    const char **hdr;
    unsigned long max_fwd = -1;
    struct buf *msg = &txn->resp_body.payload;

    /* Response should not be cached */
    txn->flags.cc |= CC_NOCACHE;

    /* Make sure method is allowed */
    if (!(txn->req_tgt.allow & ALLOW_TRACE)) return HTTP_NOT_ALLOWED;

    if ((hdr = spool_getheader(txn->req_hdrs, "Max-Forwards"))) {
        max_fwd = strtoul(hdr[0], NULL, 10);
    }

    if (max_fwd && parse_path) {
        /* Parse the path */
        int r;

        if ((r = parse_path(txn->req_uri->path,
                            &txn->req_tgt, &txn->error.desc))) return r;

        if (txn->req_tgt.mbentry && txn->req_tgt.mbentry->server) {
            /* Remote mailbox */
            struct backend *be;

            be = proxy_findserver(txn->req_tgt.mbentry->server,
                                  &http_protocol, httpd_userid,
                                  &backend_cached, NULL, NULL, httpd_in);
            if (!be) return HTTP_UNAVAILABLE;

            return http_pipe_req_resp(be, txn);
        }

        /* Local mailbox */
    }

    /* Echo the request back to the client as a message/http:
     *
     * - Piece the Request-line back together
     * - Use all non-sensitive cached headers from client
     */
    buf_reset(msg);
    buf_printf(msg, "TRACE %s %s\r\n", txn->req_line.uri, txn->req_line.ver);
    spool_enum_hdrcache(txn->req_hdrs, &trace_cachehdr, msg);
    buf_appendcstr(msg, "\r\n");

    txn->resp_body.type = "message/http";
    txn->resp_body.len = buf_len(msg);

    write_body(HTTP_OK, txn, buf_cstring(msg), buf_len(msg));

    return 0;
}

/* simple wrapper to implicity add READFB if we have the READ ACL */
EXPORTED int httpd_myrights(struct auth_state *authstate, const mbentry_t *mbentry)
{
    int rights = 0;

    if (mbentry && mbentry->acl) {
        rights = cyrus_acl_myrights(authstate, mbentry->acl);

        if (mbentry->mbtype == MBTYPE_CALENDAR &&
            (rights & DACL_READ) == DACL_READ) {
            rights |= DACL_READFB;
        }
    }

    return rights;
}
