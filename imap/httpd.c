/* httpd.c -- HTTP/RSS/xDAV/JMAP/TZdist/iSchedule server protocol parsing
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
#include <sysexits.h>
#include <syslog.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#include "prot.h"

#include <sasl/sasl.h>
#include <sasl/saslutil.h>
#include <jansson.h>

#include "httpd.h"
#include "http_h2.h"
#include "http_proxy.h"
#include "http_ws.h"

#include "acl.h"
#include "assert.h"
#include "util.h"
#include "iptostring.h"
#include "global.h"
#include "tls.h"
#include "map.h"

#include "imapd.h"
#include "proc.h"
#include "version.h"
#include "stristr.h"
#include "xstrlcpy.h"
#include "xstrlcat.h"
#include "telemetry.h"
#include "backend.h"
#include "prometheus.h"
#include "proxy.h"
#include "sync_support.h"
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

static unsigned accept_encodings = 0;

#ifdef HAVE_ZLIB
#include <zlib.h>

HIDDEN void *zlib_init()
{
    z_stream *zstrm = xzmalloc(sizeof(z_stream));

    /* Always use gzip format because IE incorrectly uses raw deflate */
    if (deflateInit2(zstrm, Z_DEFAULT_COMPRESSION, Z_DEFLATED,
                     16+MAX_WBITS /* gzip */,
                     MAX_MEM_LEVEL, Z_DEFAULT_STRATEGY) != Z_OK) {
        free(zstrm);
        return NULL;
    }
    else {
        accept_encodings |= CE_DEFLATE | CE_GZIP;
        return zstrm;
    }
}

HIDDEN int zlib_compress(struct transaction_t *txn, unsigned flags,
                         const char *buf, unsigned len)
{
    z_stream *zstrm = txn->zstrm;
    unsigned flush, pending;

    if (flags & COMPRESS_START) deflateReset(zstrm);

    if (txn->ws_ctx) flush = Z_SYNC_FLUSH;
    else {
        /* Only flush for static content or on last (zero-length) chunk */
        if (flags & COMPRESS_END) flush = Z_FINISH;
        else flush = Z_NO_FLUSH;
    }

    zstrm->next_in = (Bytef *) buf;
    zstrm->avail_in = len;

    buf_reset(&txn->zbuf);
    buf_ensure(&txn->zbuf, deflateBound(zstrm, zstrm->avail_in));

    do {
        int zr;

        zstrm->next_out = (Bytef *) txn->zbuf.s + txn->zbuf.len;
        zstrm->avail_out = txn->zbuf.alloc - txn->zbuf.len;

        zr = deflate(zstrm, flush);
        if (!(zr == Z_OK || zr == Z_STREAM_END || zr == Z_BUF_ERROR)) {
            /* something went wrong */
            syslog(LOG_ERR, "zlib deflate error: %d %s", zr, zstrm->msg);
            return -1;
        }

        txn->zbuf.len = txn->zbuf.alloc - zstrm->avail_out;

        if (zstrm->avail_out) {
            pending = 0;
        }
        else {
            /* http://www.zlib.net/manual.html says:
             * If deflate returns with avail_out == 0, this function must be
             * called again with the same value of the flush parameter and
             * more output space (updated avail_out), until the flush is
             * complete (deflate returns with non-zero avail_out).
             * In the case of a Z_FULL_FLUSH or Z_SYNC_FLUSH, make sure
             * that avail_out is greater than six to avoid repeated
             * flush markers due to avail_out == 0 on return.
             */
#ifdef HAVE_DEFLATE_PENDING
            zr = deflatePending(zstrm, &pending, Z_NULL);
            if (zr != Z_OK) {
                /* something went wrong */
                syslog(LOG_ERR, "zlib deflate error: %d %s", zr, zstrm->msg);
                return -1;
            }
#else
            /* Even if we have used all input, this will return non-zero */
            pending = deflateBound(zstrm, zstrm->avail_in);
#endif

            buf_ensure(&txn->zbuf, pending);
        }

    } while (pending);

    return 0;
}

static void zlib_done(z_stream *zstrm)
{
    if (zstrm) {
        deflateEnd(zstrm);
        free(zstrm);
    }
}
#else /* !HAVE_ZLIB */

HIDDEN void *zlib_init() { return NULL; }

HIDDEN int zlib_compress(struct transaction_t *txn __attribute__((unused)),
                         unsigned flags __attribute__((unused)),
                         const char *buf __attribute__((unused)),
                         unsigned len __attribute__((unused)))
{
    fatal("Compression requested, but no zlib", EX_SOFTWARE);
}

static void zlib_done(void *zstrm __attribute__((unused))) { }

#endif /* HAVE_ZLIB */


#ifdef HAVE_BROTLI
#include <brotli/encode.h>

HIDDEN void *brotli_init()
{
    BrotliEncoderState *brotli = BrotliEncoderCreateInstance(NULL, NULL, NULL);

    if (brotli) {
        BrotliEncoderSetParameter(brotli, BROTLI_PARAM_MODE,
                                  BROTLI_DEFAULT_MODE);
        BrotliEncoderSetParameter(brotli, BROTLI_PARAM_QUALITY,
                                  BROTLI_DEFAULT_QUALITY);
        BrotliEncoderSetParameter(brotli, BROTLI_PARAM_LGWIN,
                                  BROTLI_DEFAULT_WINDOW);
        BrotliEncoderSetParameter(brotli, BROTLI_PARAM_LGBLOCK,
                                  BROTLI_MAX_INPUT_BLOCK_BITS);
    }

    return brotli;
}

static int brotli_compress(struct transaction_t *txn,
                           unsigned flags, const char *buf, unsigned len)
{
    /* Only flush for static content or on last (zero-length) chunk */
    unsigned op = (flags & COMPRESS_END) ?
        BROTLI_OPERATION_FINISH : BROTLI_OPERATION_FLUSH;
    BrotliEncoderState *brotli = txn->brotli;
    const uint8_t *next_in = (const uint8_t *) buf;
    size_t avail_in = (size_t) len;

    buf_reset(&txn->zbuf);
    buf_ensure(&txn->zbuf, BrotliEncoderMaxCompressedSize(avail_in));

    do {
        uint8_t *next_out = (uint8_t *) txn->zbuf.s + txn->zbuf.len;
        size_t avail_out = txn->zbuf.alloc - txn->zbuf.len;

        if (!BrotliEncoderCompressStream(brotli, op,
                                         &avail_in, &next_in,
                                         &avail_out, &next_out, NULL)) {
            syslog(LOG_ERR, "Brotli: Error while compressing data");
            return -1;
        }

        txn->zbuf.len = txn->zbuf.alloc - avail_out;
    } while (avail_in || BrotliEncoderHasMoreOutput(brotli));

    if (BrotliEncoderIsFinished(brotli)) {
        BrotliEncoderDestroyInstance(brotli);
        txn->brotli = brotli_init();
    }

    return 0;
}

static void brotli_done(BrotliEncoderState *brotli)
{
    if (brotli) BrotliEncoderDestroyInstance(brotli);
}

#else /* !HAVE_BROTLI */

HIDDEN void *brotli_init() { return NULL; }

static int brotli_compress(struct transaction_t *txn __attribute__((unused)),
                           unsigned flags __attribute__((unused)),
                           const char *buf __attribute__((unused)),
                           unsigned len __attribute__((unused)))
{
    fatal("Brotli Compression requested, but not available", EX_SOFTWARE);
}

static void brotli_done(void *brotli __attribute__((unused))) {}

#endif /* HAVE_BROTLI */


#ifdef HAVE_ZSTD
#include <zstd.h>
#include <zstd_errors.h>

HIDDEN void *zstd_init()
{
    ZSTD_CCtx *cctx = ZSTD_createCCtx();

    if (cctx) {
        ZSTD_CCtx_setParameter(cctx, ZSTD_c_compressionLevel,
                               ZSTD_CLEVEL_DEFAULT);
        ZSTD_CCtx_setParameter(cctx, ZSTD_c_checksumFlag, 1);
    }

    return cctx;
}

static int zstd_compress(struct transaction_t *txn,
                         unsigned flags, const char *buf, unsigned len)
{
    /* Only flush for static content or on last (zero-length) chunk */
    ZSTD_EndDirective mode = (flags & COMPRESS_END) ? ZSTD_e_end : ZSTD_e_flush;
    ZSTD_inBuffer input = { buf, len, 0 };
    ZSTD_CCtx *cctx = txn->zstd;
    size_t remaining;

    if (flags & COMPRESS_START) ZSTD_CCtx_reset(cctx, ZSTD_reset_session_only);

    buf_reset(&txn->zbuf);
    buf_ensure(&txn->zbuf, ZSTD_compressBound(len));

    ZSTD_outBuffer output = { txn->zbuf.s, txn->zbuf.alloc, 0 };
    do {
        remaining = ZSTD_compressStream2(cctx, &output, &input, mode);

        if (ZSTD_isError(remaining)) {
            syslog(LOG_ERR, "Zstandard: %s",
                   ZSTD_getErrorString(ZSTD_getErrorCode(remaining)));
            return -1;
        }
    } while (remaining || (input.pos != input.size));

    buf_truncate(&txn->zbuf, output.pos);

    return 0;
}

static void zstd_done(ZSTD_CCtx *cctx)
{
    if (cctx) ZSTD_freeCCtx(cctx);
}

#else /* !HAVE_ZSTD */

HIDDEN void *zstd_init() { return NULL; }

static int zstd_compress(struct transaction_t *txn __attribute__((unused)),
                           unsigned flags __attribute__((unused)),
                           const char *buf __attribute__((unused)),
                           unsigned len __attribute__((unused)))
{
    fatal("Zstandard Compression requested, but not available", EX_SOFTWARE);
}

static void zstd_done(void *brotli __attribute__((unused))) {}

#endif /* HAVE_ZSTD */


static const char tls_message[] =
    HTML_DOCTYPE
    "<html>\n<head>\n<title>TLS Required</title>\n</head>\n" \
    "<body>\n<h2>TLS is required prior to authentication</h2>\n" \
    "Use <a href=\"%s\">%s</a> instead.\n" \
    "</body>\n</html>\n";

extern int optind;
extern char *optarg;
extern int opterr;

sasl_conn_t *httpd_saslconn; /* the sasl connection context */

static struct wildmat *allow_cors = NULL;
int httpd_timeout, httpd_keepalive;
char *httpd_authid = NULL;
char *httpd_userid = NULL;
char *httpd_extrafolder = NULL;
char *httpd_extradomain = NULL;
struct auth_state *httpd_authstate = 0;
int httpd_userisadmin = 0;
int httpd_userisproxyadmin = 0;
int httpd_userisanonymous = 1;
const char *httpd_localip = NULL, *httpd_remoteip = NULL;
struct protstream *httpd_out = NULL;
struct protstream *httpd_in = NULL;
struct protgroup *protin = NULL;
strarray_t *httpd_log_headers = NULL;
static struct http_connection http_conn;

static sasl_ssf_t extprops_ssf = 0;
int https = 0;
int httpd_tls_required = 0;
unsigned avail_auth_schemes = 0; /* bitmask of available auth schemes */
unsigned long config_httpmodules;
int config_httpprettytelemetry;

static time_t compile_time;
struct buf serverinfo = BUF_INITIALIZER;

int ignorequota = 0;
int apns_enabled = 0;

/* List of HTTP auth schemes that we support -
   in descending order of security properties */
struct auth_scheme_t auth_schemes[] = {
    { AUTH_SPNEGO, "Negotiate", "GSS-SPNEGO",
      AUTH_BASE64 | AUTH_SUCCESS_WWW },
    { AUTH_SCRAM_SHA256, "SCRAM-SHA-256", "SCRAM-SHA-256",
      AUTH_NEED_PERSIST | AUTH_SERVER_FIRST | AUTH_BASE64 |
      AUTH_REALM_PARAM | AUTH_DATA_PARAM },
    { AUTH_SCRAM_SHA1, "SCRAM-SHA-1", "SCRAM-SHA-1",
      AUTH_NEED_PERSIST | AUTH_SERVER_FIRST | AUTH_BASE64 |
      AUTH_REALM_PARAM | AUTH_DATA_PARAM },
    { AUTH_DIGEST, "Digest", HTTP_DIGEST_MECH,
      AUTH_NEED_REQUEST | AUTH_SERVER_FIRST },
    { AUTH_NTLM, "NTLM", "NTLM",
      AUTH_NEED_PERSIST | AUTH_BASE64 },
    { AUTH_BEARER, "Bearer", NULL,
      AUTH_SERVER_FIRST | AUTH_REALM_PARAM },
      AUTH_SCHEME_BASIC,
    { 0, NULL, NULL, 0 }
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

static int starttls(struct transaction_t *txn, struct http_connection *conn);
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
static int auth_success(struct transaction_t *txn, const char *userid);
static int http_auth(const char *creds, struct transaction_t *txn);

static int meth_get(struct transaction_t *txn, void *params);
static int meth_propfind_root(struct transaction_t *txn, void *params);

static struct saslprops_t saslprops = SASLPROPS_INITIALIZER;

static struct sasl_callback mysasl_cb[] = {
    { SASL_CB_GETOPT, (mysasl_cb_ft *) &mysasl_config, NULL },
    { SASL_CB_PROXY_POLICY, (mysasl_cb_ft *) &mysasl_proxy_policy, (void*) &httpd_proxyctx },
    { SASL_CB_CANON_USER, (mysasl_cb_ft *) &mysasl_canon_user, NULL },
    { SASL_CB_LIST_END, NULL, NULL }
};

/* Array of HTTP methods known by our server. */
const struct known_meth_t http_methods[] = {
    { "ACL",           0,                          CYRUS_HTTP_ACL_TOTAL },
    { "BIND",          0,                          CYRUS_HTTP_BIND_TOTAL },
    { "CONNECT",       METH_NOBODY,                CYRUS_HTTP_CONNECT_TOTAL },
    { "COPY",          METH_NOBODY,                CYRUS_HTTP_COPY_TOTAL },
    { "DELETE",        METH_NOBODY,                CYRUS_HTTP_DELETE_TOTAL },
    { "GET",           METH_NOBODY | METH_SAFE,    CYRUS_HTTP_GET_TOTAL },
    { "HEAD",          METH_NOBODY | METH_SAFE,    CYRUS_HTTP_HEAD_TOTAL },
    { "LOCK",          0,                          CYRUS_HTTP_LOCK_TOTAL },
    { "MKCALENDAR",    0,                          CYRUS_HTTP_MKCALENDAR_TOTAL },
    { "MKCOL",         0,                          CYRUS_HTTP_MKCOL_TOTAL },
    { "MOVE",          METH_NOBODY,                CYRUS_HTTP_MOVE_TOTAL },
    { "OPTIONS",       METH_NOBODY | METH_SAFE,    CYRUS_HTTP_OPTIONS_TOTAL },
    { "PATCH",         0,                          CYRUS_HTTP_PATCH_TOTAL },
    { "POST",          0,                          CYRUS_HTTP_POST_TOTAL },
    { "PROPFIND",      METH_SAFE,                  CYRUS_HTTP_PROPFIND_TOTAL },
    { "PROPPATCH",     0,                          CYRUS_HTTP_PROPPATCH_TOTAL },
    { "PUT",           0,                          CYRUS_HTTP_PUT_TOTAL },
    { "REPORT",        METH_SAFE,                  CYRUS_HTTP_REPORT_TOTAL },
    { "SEARCH",        METH_SAFE,                  CYRUS_HTTP_SEARCH_TOTAL },
    { "TRACE",         METH_NOBODY | METH_SAFE,    CYRUS_HTTP_TRACE_TOTAL },
    { "UNBIND",        0,                          CYRUS_HTTP_UNBIND_TOTAL },
    { "UNLOCK",        METH_NOBODY,                CYRUS_HTTP_UNLOCK_TOTAL },
    { NULL,            0,                          0 }
};

/* WebSocket handler */
static ws_data_callback ws_echo;

static struct connect_params ws_params = {
    "/", NULL /* sub-protocol */, &ws_echo
};

/* Namespace to fetch static content from filesystem */
struct namespace_t namespace_default = {
    URL_NS_DEFAULT, 1, "default", "", NULL,
    http_allow_noauth, /*authschemes*/0,
    /*mbtype*/0,
    ALLOW_READ,
    NULL, NULL, NULL, NULL, NULL, NULL,
    {
        { NULL,                 NULL },                 /* ACL          */
        { NULL,                 NULL },                 /* BIND         */
        { &meth_connect,        &ws_params },           /* CONNECT      */
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
struct namespace_t *http_namespaces[] = {
#ifdef WITH_JMAP
    &namespace_jmap,
#endif
    &namespace_tzdist,          /* MUST be before namespace_calendar!! */
#ifdef WITH_DAV
    &namespace_calendar,
    &namespace_freebusy,
    &namespace_addressbook,
    &namespace_drive,
    &namespace_principal,       /* MUST be after namespace_cal & addr & drive */
    &namespace_notify,          /* MUST be after namespace_principal */
    &namespace_applepush,       /* MUST be after namespace_cal & addr */
    &namespace_ischedule,
    &namespace_domainkey,
#endif /* WITH_DAV */
    &namespace_rss,
    &namespace_dblookup,
    &namespace_admin,
    &namespace_prometheus,
    &namespace_cgi,
    &namespace_default,         /* MUST be present and be last!! */
    NULL,
};


static void httpd_reset(struct http_connection *conn)
{
    int i;
    int bytes_in = 0;
    int bytes_out = 0;

    /* Do any namespace specific cleanup */
    for (i = 0; http_namespaces[i]; i++) {
        if (http_namespaces[i]->enabled && http_namespaces[i]->reset)
            http_namespaces[i]->reset();
    }

    /* Reset available authentication schemes */
    avail_auth_schemes = 0;

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

    index_text_extractor_destroy();

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
    if (conn->tls_ctx) {
        tls_reset_servertls((SSL **) &conn->tls_ctx);
        conn->tls_ctx = NULL;
    }
#endif

    xmlFreeParserCtxt(conn->xml);

    http2_end_session(&conn->sess_ctx, NULL);

    conn->ws_ctx = NULL;

    cyrus_reset_stdio();

    conn->clienthost = "[local]";
    buf_free(&conn->logbuf);
    if (conn->logfd != -1) {
        close(conn->logfd);
        conn->logfd = -1;
    }
    if (httpd_authid != NULL) {
        free(httpd_authid);
        httpd_authid = NULL;
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

    saslprops_reset(&saslprops);

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
    unsigned long version;
    unsigned int status, patch, fix, minor, major;

    LIBXML_TEST_VERSION

    if (geteuid() == 0) fatal("must run as the Cyrus user", EX_USAGE);
    setproctitle_init(argc, argv, envp);

    /* Initialize HTTP connection */
    memset(&http_conn, 0, sizeof(struct http_connection));

    /* set signal handlers */
    signals_set_shutdown(&shut_down);
    signal(SIGPIPE, SIG_IGN);

    /* load the SASL plugins */
    global_sasl_init(1, 1, mysasl_cb);

    /* setup for sending IMAP IDLE notifications */
    idle_enabled();

    /* Set namespace */
    if ((r = mboxname_init_namespace(&httpd_namespace, 1)) != 0) {
        fatal(error_message(r), EX_CONFIG);
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
                fatal("https: required OpenSSL options not present",
                      EX_CONFIG);
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

    httpd_log_headers = strarray_split(config_getstring(IMAPOPT_HTTPLOGHEADERS),
                                       " ", STRARRAY_TRIM | STRARRAY_LCASE);

    if (config_getstring(IMAPOPT_HTTPALLOWCORS)) {
        allow_cors =
            split_wildmats((char *) config_getstring(IMAPOPT_HTTPALLOWCORS),
                           NULL);
    }

    /* Construct serverinfo string */
    buf_printf(&serverinfo,
               "Cyrus-HTTP/%s Cyrus-SASL/%u.%u.%u Lib/XML%s Jansson/%s",
               CYRUS_VERSION,
               SASL_VERSION_MAJOR, SASL_VERSION_MINOR, SASL_VERSION_STEP,
               LIBXML_DOTTED_VERSION, JANSSON_VERSION);

    http2_init(&serverinfo);
    ws_init(&serverinfo);

#ifdef HAVE_SSL
    version = OPENSSL_VERSION_NUMBER;
    status  = version & 0x0f; version >>= 4;
    patch   = version & 0xff; version >>= 8;
    fix     = version & 0xff; version >>= 8;
    minor   = version & 0xff; version >>= 8;
    major   = version & 0xff;
    
    buf_printf(&serverinfo, " OpenSSL/%u.%u.%u", major, minor, fix);

    if (status == 0) buf_appendcstr(&serverinfo, "-dev");
    else if (status < 15) buf_printf(&serverinfo, "-beta%u", status);
    else if (patch) buf_putc(&serverinfo, patch + 'a' - 1);
#endif

#ifdef HAVE_ZLIB
    buf_printf(&serverinfo, " Zlib/%s", ZLIB_VERSION);
#endif
#ifdef HAVE_BROTLI
    version = BrotliEncoderVersion();
    fix     = version & 0xfff; version >>= 12;
    minor   = version & 0xfff; version >>= 12;
    major   = version & 0xfff;

    buf_printf(&serverinfo, " Brotli/%u.%u.%u", major, minor, fix);
#endif
#ifdef HAVE_ZSTD
    buf_printf(&serverinfo, " Zstd/%s", ZSTD_versionString());
#endif

    /* Initialize libical */
    ical_support_init();

    /* Do any namespace specific initialization */
    config_httpmodules = config_getbitfield(IMAPOPT_HTTPMODULES);
    for (i = 0; http_namespaces[i]; i++) {
        if (allow_trace) http_namespaces[i]->allow |= ALLOW_TRACE;
        if (http_namespaces[i]->init) http_namespaces[i]->init(&serverinfo);
    }

    compile_time = calc_compile_time(__TIME__, __DATE__);

    prometheus_increment(CYRUS_HTTP_READY_LISTENERS);

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

    /* fatal/shut_down will adjust these, so we need to set them early */
    prometheus_decrement(CYRUS_HTTP_READY_LISTENERS);
    prometheus_increment(CYRUS_HTTP_ACTIVE_CONNECTIONS);

    session_new_id();

    signals_poll();

    httpd_in = prot_new(0, 0);
    httpd_out = prot_new(1, 1);
    protgroup_insert(protin, httpd_in);

    /* Setup HTTP connection */
    memset(&http_conn, 0, sizeof(struct http_connection));
    http_conn.pin = httpd_in;
    http_conn.pout = httpd_out;
    http_conn.logfd = -1;

    /* Create XML parser context */
    if (!(http_conn.xml = xmlNewParserCtxt())) {
        fatal("Unable to create XML parser", EX_TEMPFAIL);
    }

    /* Find out name of client host */
    http_conn.clienthost = get_clienthost(0, &httpd_localip, &httpd_remoteip);

    if (httpd_localip && httpd_remoteip) {
        buf_setcstr(&saslprops.ipremoteport, httpd_remoteip);
        buf_setcstr(&saslprops.iplocalport, httpd_localip);
    }

    /* other params should be filled in */
    if (sasl_server_new("HTTP", config_servername, NULL,
                        buf_cstringnull_ifempty(&saslprops.iplocalport),
                        buf_cstringnull_ifempty(&saslprops.ipremoteport),
                        NULL, SASL_USAGE_FLAGS, &httpd_saslconn) != SASL_OK)
        fatal("SASL failed initializing: sasl_server_new()",EX_TEMPFAIL);

    /* will always return something valid */
    secprops = mysasl_secprops(0);

    /* no HTTP clients seem to use "auth-int" */
    secprops->max_ssf = 0;                              /* "auth" only */
    secprops->maxbufsize = 0;                           /* don't need maxbuf */
    if (sasl_setprop(httpd_saslconn, SASL_SEC_PROPS, secprops) != SASL_OK)
        fatal("Failed to set SASL property", EX_TEMPFAIL);
    if (sasl_setprop(httpd_saslconn, SASL_SSF_EXTERNAL, &extprops_ssf) != SASL_OK)
        fatal("Failed to set SASL property", EX_TEMPFAIL);

    if (httpd_remoteip) {
        char hbuf[NI_MAXHOST], *p;

        /* Create pre-authentication telemetry log based on client IP */
        strlcpy(hbuf, httpd_remoteip, NI_MAXHOST);
        if ((p = strchr(hbuf, ';'))) *p = '\0';
        http_conn.logfd = telemetry_log(hbuf, httpd_in, httpd_out, 0);
    }

    /* See which auth schemes are available to us */
    avail_auth_schemes = 0; /* Reset auth schemes for each connection */
    if ((extprops_ssf >= 2) || config_getswitch(IMAPOPT_ALLOWPLAINTEXT)) {
        avail_auth_schemes |=  AUTH_BASIC;
    }
    sasl_listmech(httpd_saslconn, NULL, NULL, " ", NULL,
                  &mechlist, NULL, &mechcount);
    for (mech = mechlist; mechcount--; mech += ++mechlen) {
        mechlen = strcspn(mech, " \0");
        for (scheme = auth_schemes; scheme->name; scheme++) {
            if (scheme->saslmech && !strncmp(mech, scheme->saslmech, mechlen)) {
                avail_auth_schemes |= scheme->id;
                break;
            }
        }
    }
    httpd_tls_required =
        config_getswitch(IMAPOPT_TLS_REQUIRED) || !avail_auth_schemes;

    proc_register(config_ident, http_conn.clienthost, NULL, NULL, NULL);

    /* Set inactivity timer */
    httpd_timeout = config_getduration(IMAPOPT_HTTPTIMEOUT, 'm');
    if (httpd_timeout < 0) httpd_timeout = 0;
    prot_settimeout(httpd_in, httpd_timeout);
    prot_setflushonread(httpd_in, httpd_out);

    /* we were connected on https port so we should do
       TLS negotiation immediately */
    if (https == 1) {
        if (starttls(NULL, &http_conn) != 0) shut_down(0);
    }
    else if (http2_preface(&http_conn)) {
        /* HTTP/2 client connection preface */
        if (http2_start_session(NULL, &http_conn) != 0)
            fatal("Failed initializing HTTP/2 session", EX_TEMPFAIL);
    }

    /* Setup the signal handler for keepalive heartbeat */
    httpd_keepalive = config_getduration(IMAPOPT_HTTPKEEPALIVE, 's');
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

    index_text_extractor_init(httpd_in);

    /* count the connection, now that it's established */
    prometheus_increment(CYRUS_HTTP_CONNECTIONS_TOTAL);

    cmdloop(&http_conn);

    prometheus_decrement(CYRUS_HTTP_ACTIVE_CONNECTIONS);

    /* Closing connection */

    /* cleanup */
    signal(SIGALRM, SIG_IGN);
    httpd_reset(&http_conn);

    prometheus_increment(CYRUS_HTTP_READY_LISTENERS);

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
    exit(EX_USAGE);
}


/*
 * Cleanly shut down and exit
 */
void shut_down(int code)
{
    int i;
    int bytes_in = 0;
    int bytes_out = 0;
    const char *msg = NULL;

    in_shutdown = 1;

    if (allow_cors) free_wildmats(allow_cors);

    strarray_free(httpd_log_headers);

    if (code) msg = http_conn.fatal;

    ws_end_channel(http_conn.ws_ctx, msg);
    http2_end_session(&http_conn.sess_ctx, msg);

    buf_free(&http_conn.logbuf);

    /* Do any namespace specific cleanup */
    for (i = 0; http_namespaces[i]; i++) {
        if (http_namespaces[i]->enabled && http_namespaces[i]->shutdown)
            http_namespaces[i]->shutdown();
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

    index_text_extractor_destroy();

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

        /* one less active connection */
        prometheus_decrement(CYRUS_HTTP_ACTIVE_CONNECTIONS);
    }
    else {
        /* one less ready listener */
        prometheus_decrement(CYRUS_HTTP_READY_LISTENERS);
    }

    prometheus_increment(code ? CYRUS_HTTP_SHUTDOWN_TOTAL_STATUS_ERROR
                              : CYRUS_HTTP_SHUTDOWN_TOTAL_STATUS_OK);

    if (protin) protgroup_free(protin);

    if (config_auditlog)
        syslog(LOG_NOTICE,
               "auditlog: traffic sessionid=<%s> bytes_in=<%d> bytes_out=<%d>",
               session_id(), bytes_in, bytes_out);

#ifdef HAVE_SSL
    tls_shutdown_serverengine();
#endif

    saslprops_free(&saslprops);

    http2_done();

    cyrus_done();

    exit(code);
}


EXPORTED void fatal(const char* s, int code)
{
    static int recurse_code = 0;
    const char *fatal = "Fatal error: ";

    if (recurse_code) {
        /* We were called recursively. Just give up */
        proc_cleanup();
        if (httpd_out) {
            /* one less active connection */
            prometheus_decrement(CYRUS_HTTP_ACTIVE_CONNECTIONS);
        }
        else {
            /* one less ready listener */
            prometheus_decrement(CYRUS_HTTP_READY_LISTENERS);
        }
        prometheus_increment(CYRUS_HTTP_SHUTDOWN_TOTAL_STATUS_ERROR);
        exit(recurse_code);
    }
    recurse_code = code;

    if (http_conn.sess_ctx || http_conn.ws_ctx) {
        /* Pass fatal string to shut_down() */
        http_conn.fatal = s;
    }
    else if (httpd_out) {
        /* Spit out a response if this is a HTTP/1.x connection */
        prot_printf(httpd_out,
                    "HTTP/1.0 %s\r\n"
                    "Content-Type: text/plain\r\n"
                    "Content-Length: %zu\r\n"
                    "Connection: close\r\n"
                    "\r\n"
                    "%s%s\r\n",
                    error_message(HTTP_SERVER_ERROR),
                    strlen(fatal) + strlen(s) + 2, fatal, s);
        prot_flush(httpd_out);
    }

    syslog(LOG_ERR, "%s%s", fatal, s);
    shut_down(code);
}


#ifdef HAVE_SSL

static unsigned h2_is_available(void *http_conn)
{
    return (http2_enabled() && http2_start_session(NULL, http_conn) == 0);
}

struct tls_alpn_t http_alpn_map[] = {
    { "h2",       &h2_is_available, &http_conn },
    { "http/1.1", NULL,             NULL },
    { NULL,       NULL,             NULL }
};

static int starttls(struct transaction_t *txn, struct http_connection *conn)
{
    int https = (txn == NULL);
    int result;
    SSL_CTX *ctx = NULL;

    if (!conn) conn = txn->conn;

    result=tls_init_serverengine("http",
                                 5,        /* depth to verify */
                                 !https,   /* can client auth? */
                                 &ctx);

    if (result == -1) {
        syslog(LOG_ERR, "error initializing TLS");

        if (txn) txn->error.desc = "Error initializing TLS";
        return HTTP_SERVER_ERROR;
    }

#ifdef HAVE_TLS_ALPN
    /* enable TLS ALPN extension */
    SSL_CTX_set_alpn_select_cb(ctx, tls_alpn_select, http_alpn_map);
#endif

    if (!https) {
        /* tell client to start TLS upgrade (RFC 2817) */
        response_header(HTTP_SWITCH_PROT, txn);
    }

    result=tls_start_servertls(0, /* read */
                               1, /* write */
                               https ? 180 : httpd_timeout,
                               &saslprops,
                               (SSL **) &conn->tls_ctx);

    /* if error */
    if (result == -1) {
        syslog(LOG_NOTICE, "starttls failed: %s", conn->clienthost);

        if (txn) txn->error.desc = "Error negotiating TLS";
        return HTTP_BAD_REQUEST;
    }

    /* tell SASL about the negotiated layer */
    result = saslprops_set_tls(&saslprops, httpd_saslconn);
    if (result != SASL_OK) {
        syslog(LOG_NOTICE, "saslprops_set_tls() failed: cmd_starttls()");
        if (https == 0) {
            fatal("saslprops_set_tls() failed: cmd_starttls()", EX_TEMPFAIL);
        } else {
            shut_down(0);
        }
    }

    /* tell the prot layer about our new layers */
    prot_settls(httpd_in, conn->tls_ctx);
    prot_settls(httpd_out, conn->tls_ctx);

    httpd_tls_required = 0;

    avail_auth_schemes |= AUTH_BASIC;

    return 0;
}
#else
static int starttls(struct transaction_t *txn __attribute__((unused)),
                    struct http_connection *conn __attribute__((unused)))
{
    fatal("starttls() called, but no OpenSSL", EX_SOFTWARE);
}
#endif /* HAVE_SSL */


/* Reset the given sasl_conn_t to a sane state */
static int reset_saslconn(sasl_conn_t **conn)
{
    int ret;
    sasl_security_properties_t *secprops = NULL;

    sasl_dispose(conn);
    /* do initialization typical of service_main */
    ret = sasl_server_new("HTTP", config_servername, NULL,
                          buf_cstringnull_ifempty(&saslprops.iplocalport),
                          buf_cstringnull_ifempty(&saslprops.ipremoteport),
                          NULL, SASL_USAGE_FLAGS, conn);
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
        ret = saslprops_set_tls(&saslprops, *conn);
    } else {
        ret = sasl_setprop(*conn, SASL_SSF_EXTERNAL, &extprops_ssf);
    }

    if(ret != SASL_OK) return ret;
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
            stristr(hdr[0], TLS_VERSION)) {
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
            hdr = spool_getheader(txn->req_hdrs, ":authority");
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


static int check_method(struct transaction_t *txn)
{
    const char **hdr;
    struct request_line_t *req_line = &txn->req_line;

    if (txn->flags.redirect) return 0;

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

    return 0;
}

static int preauth_check_hdrs(struct transaction_t *txn)
{
    int ret = 0;
    const char **hdr;

    if (txn->flags.redirect) return 0;

    /* Check for mandatory Host header (HTTP/1.1+ only) */
    if ((hdr = spool_getheader(txn->req_hdrs, "Host"))) {
        if (hdr[1]) {
            txn->error.desc = "Too many Host headers";
            return HTTP_BAD_REQUEST;
        }

        /* Create an :authority pseudo header from Host */
        spool_cache_header(xstrdup(":authority"),
                           xstrdup(hdr[0]), txn->req_hdrs);
    }
    else {
        switch (txn->flags.ver) {
        case VER_2:
            /* HTTP/2 - check for :authority pseudo header */
            if (spool_getheader(txn->req_hdrs, ":authority")) break;

            /* Fall through and create an :authority pseudo header */
            GCC_FALLTHROUGH

        case VER_1_0:
            /* HTTP/1.0 - create an :authority pseudo header from URI */
            if (txn->req_uri->server) {
                buf_setcstr(&txn->buf, txn->req_uri->server);
                if (txn->req_uri->port)
                    buf_printf(&txn->buf, ":%d", txn->req_uri->port);
            }
            else buf_setcstr(&txn->buf, config_servername);

            spool_cache_header(xstrdup(":authority"),
                               buf_release(&txn->buf), txn->req_hdrs);
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
        ret = http_read_req_body(txn);
        if (ret) {
            txn->flags.conn = CONN_CLOSE;
            return ret;
        }

        if (txn->flags.upgrade & UPGRADE_TLS) {
            if ((ret = starttls(txn, NULL))) {
                txn->flags.conn = CONN_CLOSE;
                return ret;
            }

            /* Don't advertise TLS Upgrade anymore */
            txn->flags.upgrade &= ~UPGRADE_TLS;
        }

        syslog(LOG_DEBUG, "upgrade flags: %#x  tls req: %d",
               txn->flags.upgrade, httpd_tls_required);
        if ((txn->flags.upgrade & UPGRADE_HTTP2) && !httpd_tls_required) {
            if ((ret = http2_start_session(txn, NULL))) {
                txn->flags.conn = CONN_CLOSE;
                return ret;
            }

            /* Upgrade header field mechanism not available under HTTP/2 */
            txn->flags.upgrade = 0;
        }
    }
    else if (!txn->conn->tls_ctx && txn->flags.ver == VER_1_1) {
        /* Advertise available upgrade protocols */
        if (tls_enabled() &&
            config_mupdate_server && config_getstring(IMAPOPT_PROXYSERVERS)) {
            txn->flags.upgrade |= UPGRADE_TLS;
        }
        if (http2_enabled()) txn->flags.upgrade |= UPGRADE_HTTP2;
    }

    if (txn->flags.upgrade) txn->flags.conn |= CONN_UPGRADE;
    else txn->flags.conn &= ~CONN_UPGRADE;

    return 0;
}


static int check_namespace(struct transaction_t *txn)
{
    int i;
    const char **hdr, *query = URI_QUERY(txn->req_uri);
    const struct namespace_t *namespace;
    const struct method_t *meth_t;

    /* Find the namespace of the requested resource */
    for (i = 0; http_namespaces[i]; i++) {
        const char *path = txn->req_uri->path;
        size_t len;

        /* Skip disabled namespaces */
        if (!http_namespaces[i]->enabled) continue;

        /* Handle any /.well-known/ bootstrapping */
        if (http_namespaces[i]->well_known) {
            len = strlen(http_namespaces[i]->well_known);
            if (!strncmp(path, http_namespaces[i]->well_known, len) &&
                (!path[len] || path[len] == '/')) {

                hdr = spool_getheader(txn->req_hdrs, ":authority");
                buf_reset(&txn->buf);
                buf_printf(&txn->buf, "%s://%s",
                           https ? "https" : "http", hdr[0]);
                buf_appendcstr(&txn->buf, http_namespaces[i]->prefix);
                buf_appendcstr(&txn->buf, path + len);
                if (query) buf_printf(&txn->buf, "?%s", query);
                txn->location = buf_cstring(&txn->buf);

                return HTTP_MOVED;
            }
        }

        /* See if the prefix matches - terminated with NUL or '/' */
        len = strlen(http_namespaces[i]->prefix);
        if (!strncmp(path, http_namespaces[i]->prefix, len) &&
            (!path[len] || (path[len] == '/') || !strcmp(path, "*"))) {
            break;
        }
    }
    if ((namespace = http_namespaces[i])) {
        txn->req_tgt.namespace = namespace;
        txn->req_tgt.allow = namespace->allow;

        /* Check if method is supported in this namespace */
        meth_t = &namespace->methods[txn->meth];
        if (!meth_t->proc) return HTTP_NOT_ALLOWED;

        if (config_getswitch(IMAPOPT_READONLY) &&
              !(http_methods[txn->meth].flags & METH_SAFE) &&
              !(namespace->allow & ALLOW_READONLY)) {
            return HTTP_NOT_ALLOWED;
        }

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

    /* See if this namespace whitelists auth schemes */
    if (namespace->auth_schemes) {
        avail_auth_schemes = (namespace->auth_schemes & avail_auth_schemes);

        /* Bearer auth must be advertised and supported by the namespace */
        if ((namespace->auth_schemes & AUTH_BEARER) && namespace->bearer) {
            avail_auth_schemes |= AUTH_BEARER;
        }
    }

    return 0;
}


static int auth_check_hdrs(struct transaction_t *txn, int *sasl_result)
{
    int ret = 0, r = 0;
    const char **hdr;

    if (txn->flags.redirect) return 0;

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
                if (r == SASL_UNAVAIL) {
                    /* The namespace to authenticate to is unavailable.
                     * There could be any reason for this, e.g. the DAV
                     * handler could have run into a timeout for the
                     * user's dabatase. In any case, there's no sense
                     * to challenge the client for authentication. */
                    ret = HTTP_UNAVAILABLE;
                }
                else if (r == SASL_FAIL) {
                    ret = HTTP_SERVER_ERROR;
                }
                else {
                    ret = HTTP_UNAUTHORIZED;
                }
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

    /* Drop auth credentials, if not a backend in a Murder */
    else if (!config_mupdate_server || !config_getstring(IMAPOPT_PROXYSERVERS)) {
        syslog(LOG_DEBUG, "drop auth creds");

        free(httpd_userid);
        httpd_userid = NULL;

        free(httpd_extrafolder);
        httpd_extrafolder = NULL;

        free(httpd_extradomain);
        httpd_extradomain = NULL;

        if (httpd_authstate) {
            auth_freestate(httpd_authstate);
            httpd_authstate = NULL;
        }
    }

    /* Perform proxy authorization, if necessary */
    else if (httpd_authid &&
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
            ret = auth_success(txn, authzid);
        }
    }

    *sasl_result = r;

    return ret;
}


static void postauth_check_hdrs(struct transaction_t *txn)
{
    const char **hdr;

    if (txn->flags.redirect) return;

    /* Check if this is a Cross-Origin Resource Sharing request */
    if (allow_cors && (hdr = spool_getheader(txn->req_hdrs, "Origin"))) {
        const char *err = NULL;
        xmlURIPtr uri = parse_uri(METH_UNKNOWN, hdr[0], 0, &err);

        if (uri && uri->scheme && uri->server) {
            int o_https = !strcasecmp(uri->scheme, "https");

            if ((https == o_https) &&
                !strcasecmp(uri->server,
                            *spool_getheader(txn->req_hdrs, ":authority"))) {
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
    if (txn->zstrm &&
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
    else if ((txn->zstrm || txn->brotli || txn->zstd) &&
             (hdr = spool_getheader(txn->req_hdrs, "Accept-Encoding"))) {
        struct accept *e, *enc = parse_accept(hdr);
        float qual = 0.0;

        for (e = enc; e && e->token; e++) {
            if (e->qual > 0.0 && e->qual >= qual) {
                unsigned ce = CE_IDENTITY;
                encode_proc_t proc = NULL;

                if (txn->zstd && !strcasecmp(e->token, "zstd")) {
                    ce = CE_ZSTD;
                    proc = &zstd_compress;
                }
                else if (txn->brotli && !strcasecmp(e->token, "br")) {
                    ce = CE_BR;
                    proc = &brotli_compress;
                }
                else if (txn->zstrm && (!strcasecmp(e->token, "gzip") ||
                                        !strcasecmp(e->token, "x-gzip"))) {
                    ce = CE_GZIP;
                    proc = &zlib_compress;
                }
                else {
                    /* Unknown/unsupported */
                    e->qual = 0.0;
                }

                /* Favor Zstandard over Brotli over GZIP if q values are equal */
                if (e->qual > qual || txn->resp_body.enc.type < ce) {
                    txn->resp_body.enc.type = ce;
                    txn->resp_body.enc.proc = proc;
                    qual = e->qual;
                }
            }
            free(e->token);
        }
        if (enc) free(enc);
    }
}


EXPORTED int examine_request(struct transaction_t *txn, const char *uri)
{
    int ret = 0, sasl_result = 0;
    const char *query;
    const struct namespace_t *namespace;
    struct request_line_t *req_line = &txn->req_line;

    if (!uri) uri = req_line->uri;

    /* Check method */
    if ((ret = check_method(txn))) return ret;

    /* Parse request-target URI */
    if (!(txn->req_uri = parse_uri(txn->meth, uri, 1, &txn->error.desc))) {
        return HTTP_BAD_REQUEST;
    }

    /* Perform pre-authentication check of headers */
    if ((ret = preauth_check_hdrs(txn))) return ret;

    /* Find the namespace of the requested resource */
    if ((ret = check_namespace(txn))) return ret;

    /* Perform check of authentication headers */
    ret = auth_check_hdrs(txn, &sasl_result);

    if (ret && ret != HTTP_UNAUTHORIZED) return ret;

    /* Register service/module and method */
    namespace = txn->req_tgt.namespace;
    buf_printf(&txn->buf, "%s%s", config_ident,
               namespace->well_known ? strrchr(namespace->well_known, '/') :
               namespace->prefix);
    proc_register(buf_cstring(&txn->buf), txn->conn->clienthost, httpd_userid,
                  txn->req_tgt.path, txn->req_line.meth);
    buf_reset(&txn->buf);

    /* Request authentication, if necessary */
    if (!httpd_userid && namespace->need_auth(txn)) {
        ret = HTTP_UNAUTHORIZED;
    }

    if (ret) return client_need_auth(txn, sasl_result);

    /* Parse any query parameters */
    construct_hash_table(&txn->req_qparams, 10, 1);
    query = URI_QUERY(txn->req_uri);
    if (query) parse_query_params(txn, query);

    /* Perform post-authentication check of headers */
    postauth_check_hdrs(txn);

    return 0;
}


EXPORTED int process_request(struct transaction_t *txn)
{
    int ret = 0;

    if (txn->req_tgt.namespace->premethod) {
        ret = txn->req_tgt.namespace->premethod(txn);
    }
    if (!ret) {
        const struct method_t *meth_t =
            &txn->req_tgt.namespace->methods[txn->meth];
        
        ret = (*meth_t->proc)(txn, meth_t->params);

        prometheus_increment(
            prometheus_lookup_label(http_methods[txn->meth].metric,
                                    txn->req_tgt.namespace->name));
    }

    if (ret == HTTP_UNAUTHORIZED) {
        /* User must authenticate */
        ret = client_need_auth(txn, 0);
    }

    return ret;
}


static int http1_input(struct transaction_t *txn)
{
    struct request_line_t *req_line = &txn->req_line;
    int ignore_empty = 1, ret = 0;

    do {
        /* Read request-line */
        syslog(LOG_DEBUG, "read & parse request-line");
        if (!prot_fgets(req_line->buf, MAX_REQ_LINE+1, httpd_in)) {
            txn->error.desc = prot_error(httpd_in);
            if (txn->error.desc && strcmp(txn->error.desc, PROT_EOF_STRING)) {
                /* client timed out */
                syslog(LOG_WARNING, "%s, closing connection", txn->error.desc);
                ret = HTTP_TIMEOUT;
            }
            else {
                /* client closed connection */
                syslog(LOG_DEBUG, "client closed connection");
            }

            txn->flags.conn = CONN_CLOSE;
            return ret;
        }

        /* Ignore 1 empty line before request-line per RFC 7230 Sec 3.5 */
    } while (ignore_empty-- && (strcspn(req_line->buf, "\r\n") == 0));


    /* Parse request-line = method SP request-target SP HTTP-version CRLF */
    ret = parse_request_line(txn);

    /* Parse headers */
    if (!ret) {
        ret = http_read_headers(httpd_in, 1 /* read_sep */,
                                &txn->req_hdrs, &txn->error.desc);
    }

    if (ret) {
        txn->flags.conn = CONN_CLOSE;
        goto done;
    }

    /* Examine request */
    ret = examine_request(txn, NULL);
    if (ret) goto done;

    /* Start method processing alarm (HTTP/1.1 only) */
    if (txn->flags.ver == VER_1_1) alarm(httpd_keepalive);

    /* Process the requested method */
    ret = process_request(txn);

  done:
    /* Handle errors (success responses handled by method functions) */
    if (ret) error_response(ret, txn);

    /* Read and discard any unread request body */
    if (!(txn->flags.conn & CONN_CLOSE)) {
        txn->req_body.flags |= BODY_DISCARD;
        if (http_read_req_body(txn)) {
            txn->flags.conn = CONN_CLOSE;
        }
    }

    return 0;
}


static void transaction_reset(struct transaction_t *txn)
{
    txn->meth = METH_UNKNOWN;

    memset(&txn->flags, 0, sizeof(struct txn_flags_t));
    txn->flags.ver = VER_1_1;
    txn->flags.vary = VARY_AE;

    memset(&txn->req_line, 0, sizeof(struct request_line_t));

    /* Reset Bearer auth scheme for each transaction */
    avail_auth_schemes &= ~AUTH_BEARER;

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

    strarray_fini(&txn->resp_body.links);
    memset(&txn->resp_body, 0,  /* Don't zero the response payload buffer */
           sizeof(struct resp_body_t) - sizeof(struct buf));
    buf_reset(&txn->resp_body.payload);

    /* Pre-allocate our working buffer */
    buf_reset(&txn->buf);
    buf_ensure(&txn->buf, 1024);
}


EXPORTED void transaction_free(struct transaction_t *txn)
{
    transaction_reset(txn);

    ws_end_channel(&txn->ws_ctx, NULL);

    http2_end_stream(txn->strm_ctx);

    zlib_done(txn->zstrm);
    zstd_done(txn->zstd);
    brotli_done(txn->brotli);

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
    struct transaction_t txn;

    /* Start with an empty (clean) transaction */
    memset(&txn, 0, sizeof(struct transaction_t));
    txn.conn = conn;

    if (config_getswitch(IMAPOPT_HTTPALLOWCOMPRESS)) {
        txn.zstrm = zlib_init();
        txn.zstd = zstd_init();
        txn.brotli = brotli_init();
    }

    /* Enable command timer */
    cmdtime_settimer(1);

    /* Enable provisional responses for long-running mailbox ops */
    mailbox_set_wait_cb((mailbox_wait_cb_t *) &keepalive_response, &txn);

    do {
        int ret = 0;

        /* Reset txn state */
        transaction_reset(&txn);

        /* make sure nothing leaked */
        assert(!open_mailboxes_exist());
        assert(!open_mboxlocks_exist());

        sync_log_reset();

        /* Check for input from client */
        do {
            /* Flush any buffered output */
            prot_flush(httpd_out);
            if (backend_current) prot_flush(backend_current->out);

            /* Check for shutdown file */
            if (shutdown_file(txn.buf.s, txn.buf.alloc) ||
                (httpd_userid &&
                 userdeny(httpd_userid, config_ident, txn.buf.s, txn.buf.alloc))) {
                txn.error.desc = txn.buf.s;
                txn.flags.conn = CONN_CLOSE;
                ret = HTTP_SHUTDOWN;
                break;
            }

            signals_poll();

            syslog(LOG_DEBUG, "proxy_check_input()");

        } while (!proxy_check_input(protin, httpd_in, httpd_out,
                                    backend_current ? backend_current->in : NULL,
                                    NULL, 0));

        
        /* Start command timer */
        cmdtime_starttimer();

        if (txn.conn->sess_ctx) {
            /* HTTP/2 input */
            http2_input(&txn);
        }
        else if (txn.ws_ctx) {
            /* WebSocket over HTTP/1.1 input */
            ws_input(&txn);
        }
        else if (!ret) {
            /* HTTP/1.x request */
            http1_input(&txn);
        }

        if (ret == HTTP_SHUTDOWN) {
            syslog(LOG_WARNING,
                   "Shutdown file: \"%s\", closing connection", txn.error.desc);
            protgroup_free(protin);
            shut_down(0);
        }

    } while (!(txn.flags.conn & CONN_CLOSE));

    /* Memory cleanup */
    transaction_free(&txn);
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
        size_t pathlen = strlen(p_uri->path);
        if ((p_uri->path[0] != '/') &&
            (strcmp(p_uri->path, "*") || (meth != METH_OPTIONS))) {
            /* No special URLs except for "OPTIONS * HTTP/1.1" */
            *errstr = "Illegal request target URI";
            goto bad_request;
        }
        else if (strstr(p_uri->path, "/../")) {
            /* Don't allow access up directory tree */
            *errstr = "Illegal request target URI";
            goto bad_request;
        }
        else if (pathlen >= 3 && !strcmp("/..", p_uri->path + pathlen - 3)) {
            /* Don't allow access up directory tree */
            *errstr = "Illegal request target URI";
            goto bad_request;
        }
        else if (pathlen > MAX_MAILBOX_PATH) {
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

    memset(&tm, 0, sizeof(struct tm));
    tm.tm_isdst = -1;
    sscanf(time, "%02d:%02d:%02d", &tm.tm_hour, &tm.tm_min, &tm.tm_sec);
    sscanf(date, "%3s %2d %4d", month, &tm.tm_mday, &tm.tm_year);
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
                        if (!txn->conn->tls_ctx && tls_enabled() &&
                            !strncasecmp(upgrade[0], TLS_VERSION,
                                         strcspn(upgrade[0], " ,"))) {
                            /* Upgrade to TLS */
                            txn->flags.conn |= CONN_UPGRADE;
                            txn->flags.upgrade |= UPGRADE_TLS;
                        }
                        else if (http2_enabled() &&
                                 !strncasecmp(upgrade[0],
                                              NGHTTP2_CLEARTEXT_PROTO_VERSION_ID,
                                              strcspn(upgrade[0], " ,"))) {
                            /* Upgrade to HTTP/2 */
                            txn->flags.conn |= CONN_UPGRADE;
                            txn->flags.upgrade |= UPGRADE_HTTP2;
                        }
                        else if (ws_enabled() &&
                                 !strncasecmp(upgrade[0], WS_TOKEN,
                                              strcspn(upgrade[0], " ,"))) {
                            /* Upgrade to WebSockets */
                            txn->flags.conn |= CONN_UPGRADE;
                            txn->flags.upgrade |= UPGRADE_WS;
                        }
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
    struct tm *tm = gmtime(&t);

    snprintf(buf, len, "%3s, %02d %3s %4d %02d:%02d:%02d GMT",
             wday[tm->tm_wday],
             tm->tm_mday, monthname[tm->tm_mon], tm->tm_year + 1900,
             tm->tm_hour, tm->tm_min, tm->tm_sec);

    return buf;
}


/* Create an HTTP Status-Line given response code */
EXPORTED const char *http_statusline(unsigned ver, long code)
{
    static struct buf statline = BUF_INITIALIZER;

    if (ver == VER_2) buf_setcstr(&statline, HTTP2_VERSION);
    else {
        buf_setmap(&statline, HTTP_VERSION, HTTP_VERSION_LEN-1);
        buf_putc(&statline, ver + '0');
    }

    buf_putc(&statline, ' ');
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

    if (txn->flags.ver == VER_2) {
        http2_add_header(txn, name, &buf);
    }
    else {
        prot_printf(txn->conn->pout, "%c%s: ", toupper(name[0]), name+1);
        prot_puts(txn->conn->pout, buf_cstring(&buf));
        prot_puts(txn->conn->pout, "\r\n");

        buf_free(&buf);
    }
}

#define WWW_Authenticate(name, param)                           \
    simple_hdr(txn, "WWW-Authenticate", param ? "%s %s" : "%s", name, param)

#define Access_Control_Expose(hdr)                              \
    simple_hdr(txn, "Access-Control-Expose-Headers", hdr)

static void comma_list_body(struct buf *buf,
                            const char *vals[], unsigned flags, int has_args, va_list args)
{
    const char *sep = "";
    int i;

    for (i = 0; vals[i]; i++) {
        if (flags & (1 << i)) {
            buf_appendcstr(buf, sep);
            if (has_args) buf_vprintf(buf, vals[i], args);
            else buf_appendcstr(buf, vals[i]);
            sep = ", ";
        }
        else if (has_args) {
            /* discard any unused args */
            vsnprintf(NULL, 0, vals[i], args);
        }
    }
}

EXPORTED void comma_list_hdr(struct transaction_t *txn, const char *name,
                             const char *vals[], unsigned flags, ...)
{
    struct buf buf = BUF_INITIALIZER;
    va_list args;

    va_start(args, flags);

    comma_list_body(&buf, vals, flags, 1, args);

    va_end(args);

    simple_hdr(txn, name, "%s", buf_cstring(&buf));

    buf_free(&buf);
}

EXPORTED void list_auth_schemes(struct transaction_t *txn)
{
    struct auth_challenge_t *auth_chal = &txn->auth_chal;
    unsigned conn_close = (txn->flags.conn & CONN_CLOSE);
    struct auth_scheme_t *scheme;

    /* Advertise available schemes that can work with the type of connection */
    for (scheme = auth_schemes; scheme->name; scheme++) {
        if ((avail_auth_schemes & scheme->id) &&
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
        "OPTIONS, GET, HEAD", "POST", "PUT",
        "PATCH", "DELETE", "TRACE", "CONNECT", NULL
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

    simple_hdr(txn, "Accept-Patch", "%s", buf_cstring(&buf));

    buf_free(&buf);
}

#define MD5_BASE64_LEN 25   /* ((MD5_DIGEST_LENGTH / 3) + 1) * 4 */

EXPORTED void content_md5_hdr(struct transaction_t *txn,
                              const unsigned char *md5)
{
    char base64[MD5_BASE64_LEN+1];

    sasl_encode64((char *) md5, MD5_DIGEST_LENGTH, base64, MD5_BASE64_LEN, NULL);
    simple_hdr(txn, "Content-MD5", "%s", base64);
}

EXPORTED void begin_resp_headers(struct transaction_t *txn, long code)
{
    if (txn->flags.ver == VER_2) {
        http2_begin_headers(txn);
        if (code) simple_hdr(txn, ":status", "%.3s", error_message(code));
    }
    else if (code) prot_printf(txn->conn->pout, "%s\r\n",
                               http_statusline(txn->flags.ver, code));
}

EXPORTED int end_resp_headers(struct transaction_t *txn, long code)
{
    int r = 0;

    if (txn->flags.ver == VER_2) {
        r = http2_end_headers(txn, code);
    }
    else {
        /* CRLF terminating the header block */
        prot_puts(txn->conn->pout, "\r\n");
    }

    return r;
}


/* Write end-to-end header (ignoring hop-by-hop) from cache to protstream. */
static void write_cachehdr(const char *name, const char *contents,
                           const char *raw __attribute__((unused)), void *rock)
{
    struct transaction_t *txn = (struct transaction_t *) rock;
    const char **hdr, *hop_by_hop[] =
        { "connection", "content-length", "content-type", "date", "forwarded",
          "keep-alive", "location", "status", "strict-transport-security",
          "upgrade", "via", NULL };

    /* Ignore private headers in our cache */
    if (name[0] == ':') return;

    for (hdr = hop_by_hop; *hdr; hdr++) {
        if (!strcasecmp(name, *hdr)) return;
    }

    simple_hdr(txn, name, "%s", contents);
}

EXPORTED void response_header(long code, struct transaction_t *txn)
{
    int i, size;
    time_t now;
    char datestr[30];
    va_list noargs;
    double cmdtime, nettime;
    const char **hdr, *sep;
    struct auth_challenge_t *auth_chal = &txn->auth_chal;
    struct resp_body_t *resp_body = &txn->resp_body;
    struct buf *logbuf = &txn->conn->logbuf;
    const char *upgrd_tokens[] =
        { TLS_VERSION, NGHTTP2_CLEARTEXT_PROTO_VERSION_ID, WS_TOKEN, NULL };
    const char *te[] = { "deflate", "gzip", "chunked", NULL };
    const char *ce[] = { "deflate", "gzip", "br", "zstd", NULL };

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
        simple_hdr(txn, "Date", "%s", datestr);

        /* Fall through and specify connection options and/or links */
        GCC_FALLTHROUGH

    case HTTP_SWITCH_PROT:
        if (txn->flags.conn && (txn->flags.ver < VER_2)) {
            /* Construct Connection header */
            const char *conn_tokens[] =
                { "close", "Upgrade", "Keep-Alive", NULL };

            comma_list_hdr(txn, "Connection", conn_tokens, txn->flags.conn);

            if (txn->flags.upgrade) {
                /* Construct Upgrade header */
                comma_list_hdr(txn, "Upgrade", upgrd_tokens, txn->flags.upgrade);

                if (txn->flags.upgrade & UPGRADE_WS) {
                    /* Add WebSocket headers */
                    ws_add_resp_hdrs(txn);
                }
            }
            if (txn->flags.conn & CONN_KEEPALIVE) {
                simple_hdr(txn, "Keep-Alive", "timeout=%d", httpd_timeout);
            }
        }

        /* Fall through and specify links */
        GCC_FALLTHROUGH

    case HTTP_EARLY_HINTS:
        size = strarray_size(&resp_body->links);
        for (i = 0; i < size; i++) {
            simple_hdr(txn, "Link", "%s", strarray_nth(&resp_body->links, i));
        }

        if (code >= HTTP_OK) break;

        /* Fall through as provisional response */
        GCC_FALLTHROUGH

    case HTTP_CONTINUE:
    case HTTP_PROCESSING:
        /* Provisional response - nothing else needed */
        end_resp_headers(txn, code);

        /* Force the response to the client immediately */
        prot_flush(httpd_out);

        /* Restart method processing alarm (HTTP/1.1 only) */
        if (!txn->ws_ctx && (txn->flags.ver == VER_1_1)) alarm(httpd_keepalive);

        goto log;
    }


    /* Control Data */
    if (txn->conn->tls_ctx) {
        simple_hdr(txn, "Strict-Transport-Security", "max-age=600");
    }
    if (txn->location) {
        simple_hdr(txn, "Location", "%s", txn->location);
    }
    if (txn->flags.mime) {
        simple_hdr(txn, "MIME-Version", "1.0");
    }
    if (txn->flags.cc) {
        /* Construct Cache-Control header */
        const char *cc_dirs[] =
            { "must-revalidate", "no-cache", "no-store", "no-transform",
              "public", "private", "max-age=%d", "immutable", NULL };

        comma_list_hdr(txn, "Cache-Control",
                       cc_dirs, txn->flags.cc, resp_body->maxage);

        if (txn->flags.cc & CC_MAXAGE) {
            httpdate_gen(datestr, sizeof(datestr), now + resp_body->maxage);
            simple_hdr(txn, "Expires", "%s", datestr);
        }
    }
    if (txn->flags.cors) {
        /* Construct Cross-Origin Resource Sharing headers */
        simple_hdr(txn, "Access-Control-Allow-Origin", "%s",
                      *spool_getheader(txn->req_hdrs, "Origin"));
        simple_hdr(txn, "Access-Control-Allow-Credentials", "true");

        if (txn->flags.cors == CORS_PREFLIGHT) {
            allow_hdr(txn, "Access-Control-Allow-Methods", txn->req_tgt.allow);

            for (hdr = spool_getheader(txn->req_hdrs,
                                       "Access-Control-Request-Headers");
                 hdr && *hdr; hdr++) {
                simple_hdr(txn, "Access-Control-Allow-Headers", "%s", *hdr);
            }
            simple_hdr(txn, "Access-Control-Max-Age", "3600");
        }
    }
    if (txn->flags.vary && !(txn->flags.cc & CC_NOCACHE)) {
        /* Construct Vary header */
        const char *vary_hdrs[] = { "Accept", "Accept-Encoding", "Brief",
                                    "Prefer", "If-None-Match",
                                    "CalDAV-Timezones", NULL };

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
        if (auth_chal->scheme->flags & AUTH_SUCCESS_WWW) {
            /* Special handling of success data for this scheme */
            WWW_Authenticate(auth_chal->scheme->name, auth_chal->param);
        }
        else {
            /* Default handling of success data */
            simple_hdr(txn, "Authentication-Info", "%s", auth_chal->param);
        }
    }

    /* Response Context */
    if (txn->req_tgt.allow & ALLOW_ISCHEDULE) {
        simple_hdr(txn, "iSchedule-Version", "1.0");

        if (resp_body->iserial) {
            simple_hdr(txn, "iSchedule-Capabilities", TIME_T_FMT, resp_body->iserial);
        }
    }
    if (resp_body->patch) {
        accept_patch_hdr(txn, resp_body->patch);
    }

    switch (code) {
    case HTTP_OK:
        switch (txn->meth) {
        case METH_CONNECT:
            if (txn->ws_ctx) {
                /* Add WebSocket headers */
                ws_add_resp_hdrs(txn);
            }
            break;

        case METH_GET:
        case METH_HEAD:
            /* Construct Accept-Ranges header for GET and HEAD responses */
            simple_hdr(txn, "Accept-Ranges",
                       txn->flags.ranges ? "bytes" : "none");
            break;

        case METH_OPTIONS:
            if (config_serverinfo == IMAP_ENUM_SERVERINFO_ON) {
                simple_hdr(txn, "Server", "%s", buf_cstring(&serverinfo));
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

        /* Fall through and specify supported content codings */
        GCC_FALLTHROUGH

    case HTTP_CREATED:
    case HTTP_ACCEPTED:
    case HTTP_NO_CONTENT:
    case HTTP_RESET_CONTENT:
    case HTTP_PARTIAL:
    case HTTP_MULTI_STATUS:
        if (accept_encodings && buf_len(&txn->req_body.payload)) {
            comma_list_hdr(txn, "Accept-Encoding", ce, accept_encodings);
        }
        break;

    case HTTP_NOT_ALLOWED:
        /* Construct Allow header(s) for 405 response */
        allow_hdr(txn, "Allow", txn->req_tgt.allow);
        break;

    case HTTP_BAD_CE:
        /* Construct Accept-Encoding header for 415 response */
        if (accept_encodings) {
            comma_list_hdr(txn, "Accept-Encoding", ce, accept_encodings);
        }
        else simple_hdr(txn, "Accept-Encoding", "identity");
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
                      resp_body->enc.proc ? "W/" : "", resp_body->etag);
        if (txn->flags.cors) Access_Control_Expose("ETag");
    }
    if (resp_body->lastmod) {
        /* Last-Modified MUST NOT be in the future */
        resp_body->lastmod = MIN(resp_body->lastmod, now);
        httpdate_gen(datestr, sizeof(datestr), resp_body->lastmod);
        simple_hdr(txn, "Last-Modified", "%s", datestr);
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
        simple_hdr(txn, "Cal-Managed-ID", "%s", resp_body->cmid);
        if (txn->flags.cors) Access_Control_Expose("Cal-Managed-ID");
    }
    if (resp_body->type) {
        simple_hdr(txn, "Content-Type", "%s", resp_body->type);
        if (resp_body->dispo.fname) {
            /* Construct Content-Disposition header */
            const unsigned char *p = (const unsigned char *)resp_body->dispo.fname;
            char *encfname = NULL;
            for (p = (unsigned char *)resp_body->dispo.fname; p && *p; p++) {
                if (*p >= 0x80) {
                    encfname = charset_encode_mimexvalue(resp_body->dispo.fname, NULL);
                    break;
                }
            }
            if (encfname) {
                simple_hdr(txn, "Content-Disposition", "%s; filename*=%s",
                        resp_body->dispo.attach ? "attachment" : "inline",
                        encfname);
            }
            else {
                simple_hdr(txn, "Content-Disposition", "%s; filename=\"%s\"",
                        resp_body->dispo.attach ? "attachment" : "inline",
                        resp_body->dispo.fname);
            }
            free(encfname);
        }
        if (txn->resp_body.enc.proc) {
            /* Construct Content-Encoding header */
            comma_list_hdr(txn, "Content-Encoding", ce, txn->resp_body.enc.type);
        }
        if (resp_body->lang) {
            simple_hdr(txn, "Content-Language", "%s", resp_body->lang);
        }
        if (resp_body->loc) {
            xmlChar *uri = xmlURIEscapeStr(BAD_CAST resp_body->loc, BAD_CAST ":/?=");
            simple_hdr(txn, "Content-Location", "%s", (const char *) uri);
            free(uri);

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
        GCC_FALLTHROUGH

    default:
        if (txn->flags.te) {
            /* HTTP/1.1 only - we use close-delimiting for HTTP/1.0 */
            if (txn->flags.ver == VER_1_1) {
                /* Construct Transfer-Encoding header */
                comma_list_hdr(txn, "Transfer-Encoding", te, txn->flags.te);
            }

            if (txn->flags.trailer & ~TRAILER_PROXY) {
                /* Construct Trailer header */
                const char *trailer_hdrs[] = { "Content-MD5", "CTag", NULL };

                comma_list_hdr(txn, "Trailer", trailer_hdrs, txn->flags.trailer);
            }
        }
        else {
            /* Content-Length */
            switch (txn->meth) {
            case METH_CONNECT:
                /* MUST NOT include per Section 4.3.6 of RFC 7231 */
                break;

            case METH_HEAD:
                if (!resp_body->len) {
                    /* We don't know if the length is zero or if it wasn't set -
                       MUST NOT include if it doesn't match what would be
                       returned for GET, per Section 3.3.2 of RFC 7231 */
                    break;
                }

                GCC_FALLTHROUGH

            default:
                simple_hdr(txn, "Content-Length", "%lu", resp_body->len);
                break;
            }
        }
    }


    /* Extra headers */
    if (resp_body->extra_hdrs) {
        spool_enum_hdrcache(resp_body->extra_hdrs, &write_cachehdr, txn);
    }


    /* End of headers */
    end_resp_headers(txn, code);


  log:
    /* Log the client request and our response */
    buf_reset(logbuf);

    /* Add client data */
    buf_printf(logbuf, "%s", txn->conn->clienthost);
    if (httpd_userid) buf_printf(logbuf, " as \"%s\"", httpd_userid);
    if (txn->req_hdrs &&
        (hdr = spool_getheader(txn->req_hdrs, "User-Agent"))) {
        buf_printf(logbuf, " with \"%s\"", hdr[0]);
        if ((hdr = spool_getheader(txn->req_hdrs, "X-Client")))
            buf_printf(logbuf, " by \"%s\"", hdr[0]);
        else if ((hdr = spool_getheader(txn->req_hdrs, "X-Requested-With")))
            buf_printf(logbuf, " by \"%s\"", hdr[0]);
    }

    /* Add session id */
    buf_printf(logbuf, " via SESSIONID=<%s>", session_id());

    /* Add request-line */
    buf_appendcstr(logbuf, "; \"");
    if (txn->req_line.meth) {
        buf_printf(logbuf, "%s",
                   txn->flags.override ? "POST" : txn->req_line.meth);
        if (txn->req_line.uri) {
            buf_printf(logbuf, " %s", txn->req_line.uri);
            if (txn->req_line.ver) {
                buf_printf(logbuf, " %s", txn->req_line.ver);
                if (code != HTTP_URI_TOO_LONG && *txn->req_line.buf) {
                    const char *p =
                        txn->req_line.ver + strlen(txn->req_line.ver) + 1;
                    if (*p) buf_printf(logbuf, " %s", p);
                }
            }
        }
    }
    buf_appendcstr(logbuf, "\"");

    if (txn->req_hdrs) {
        /* Add any request modifying headers */
        sep = " (";

        if (txn->flags.override) {
            buf_printf(logbuf, "%smethod-override=%s", sep, txn->req_line.meth);
            sep = "; ";
        }
        if ((hdr = spool_getheader(txn->req_hdrs, "Origin"))) {
            buf_printf(logbuf, "%sorigin=%s", sep, hdr[0]);
            sep = "; ";
        }
        if ((hdr = spool_getheader(txn->req_hdrs, "Referer"))) {
            buf_printf(logbuf, "%sreferer=%s", sep, hdr[0]);
            sep = "; ";
        }
        if (txn->flags.upgrade &&
            (hdr = spool_getheader(txn->req_hdrs, "Upgrade"))) {
            buf_printf(logbuf, "%supgrade=%s", sep, hdr[0]);
            sep = "; ";
        }
        if (code == HTTP_CONTINUE || code == HTTP_EXPECT_FAILED) {
            hdr = spool_getheader(txn->req_hdrs, "Expect");
            buf_printf(logbuf, "%sexpect=%s", sep, hdr[0]);
            sep = "; ";
        }
        if ((hdr = spool_getheader(txn->req_hdrs, "Transfer-Encoding"))) {
            buf_printf(logbuf, "%stx-encoding=%s", sep, hdr[0]);
            sep = "; ";
        }
        if ((hdr = spool_getheader(txn->req_hdrs, "Content-Encoding"))) {
            buf_printf(logbuf, "%scnt-encoding=%s", sep, hdr[0]);
            sep = "; ";
        }
        if (txn->auth_chal.scheme) {
            buf_printf(logbuf, "%sauth=%s", sep, txn->auth_chal.scheme->name);
            sep = "; ";
        }
        if ((hdr = spool_getheader(txn->req_hdrs, "Destination"))) {
            buf_printf(logbuf, "%sdestination=%s", sep, hdr[0]);
            sep = "; ";
        }
        if ((hdr = spool_getheader(txn->req_hdrs, "Lock-Token"))) {
            buf_printf(logbuf, "%slock-token=%s", sep, hdr[0]);
            sep = "; ";
        }
        if ((hdr = spool_getheader(txn->req_hdrs, "If"))) {
            buf_printf(logbuf, "%sif=%s", sep, hdr[0]);
            sep = "; ";
        }
        if ((hdr = spool_getheader(txn->req_hdrs, "If-Schedule-Tag-Match"))) {
            buf_printf(logbuf, "%sif-schedule-tag-match=%s", sep, hdr[0]);
            sep = "; ";
        }
        else if ((hdr = spool_getheader(txn->req_hdrs, "If-Match"))) {
            buf_printf(logbuf, "%sif-match=%s", sep, hdr[0]);
            sep = "; ";
        }
        else if ((hdr = spool_getheader(txn->req_hdrs, "If-Unmodified-Since"))) {
            buf_printf(logbuf, "%sif-unmodified-since=%s", sep, hdr[0]);
            sep = "; ";
        }
        if ((hdr = spool_getheader(txn->req_hdrs, "If-None-Match"))) {
            buf_printf(logbuf, "%sif-none-match=%s", sep, hdr[0]);
            sep = "; ";
        }
        else if ((hdr = spool_getheader(txn->req_hdrs, "If-Modified-Since"))) {
            buf_printf(logbuf, "%sif-modified-since=%s", sep, hdr[0]);
            sep = "; ";
        }
        if ((hdr = spool_getheader(txn->req_hdrs, ":type"))) {
            buf_printf(logbuf, "%stype=%s", sep, hdr[0]);
            sep = "; ";
        }
        if ((hdr = spool_getheader(txn->req_hdrs, ":token"))) {
            buf_printf(logbuf, "%stoken=%s", sep, hdr[0]);
            sep = "; ";
        }
        if ((hdr = spool_getheader(txn->req_hdrs, ":jmap"))) {
            buf_printf(logbuf, "%sjmap=%s", sep, hdr[0]);
            sep = "; ";
        }
        if ((hdr = spool_getheader(txn->req_hdrs, ":dblookup"))) {
            buf_printf(logbuf, "%slookup=%s", sep, hdr[0]);
            sep = "; ";
        }
        if ((hdr = spool_getheader(txn->req_hdrs, "Depth"))) {
            buf_printf(logbuf, "%sdepth=%s", sep, hdr[0]);
            sep = "; ";
        }
        if ((hdr = spool_getheader(txn->req_hdrs, "Prefer"))) {
            buf_printf(logbuf, "%sprefer=%s", sep, hdr[0]);
            sep = "; ";
        }
        else if ((hdr = spool_getheader(txn->req_hdrs, "Brief"))) {
            buf_printf(logbuf, "%sbrief=%s", sep, hdr[0]);
            sep = "; ";
        }
        if ((hdr = spool_getheader(txn->req_hdrs, "CalDAV-Timezones"))) {
            buf_printf(logbuf, "%scaldav-timezones=%s", sep, hdr[0]);
            sep = "; ";
        }

        /* Add httplogheaders */
        size = strarray_size(httpd_log_headers);
        for (i = 0; i < size; i++) {
            const char *name = strarray_nth(httpd_log_headers, i);

            if ((hdr = spool_getheader(txn->req_hdrs, name))) {
                buf_printf(logbuf, "%s%s=\"%s\"", sep, name, hdr[0]);
                sep = "; ";
            }
        }

        if (*sep == ';') buf_appendcstr(logbuf, ")");
    }

    if (txn->flags.redirect) {
        /* Add CGI local redirect */
        buf_printf(logbuf, " => \"%s %s %s\"",
                   txn->req_line.meth, txn->req_tgt.path, txn->req_line.ver);
    }

    /* Add response */
    buf_printf(logbuf, " => \"%s\"", http_statusline(txn->flags.ver, code));

    /* Add any auxiliary response data */
    sep = " (";
    if (txn->strm_ctx) {
        buf_printf(logbuf, "%sstream-id=%d", sep,
                   http2_get_streamid(txn->strm_ctx));
        sep = "; ";
    }
    if (code == HTTP_SWITCH_PROT || code == HTTP_UPGRADE) {
        buf_printf(logbuf, "%supgrade=", sep);
        comma_list_body(logbuf, upgrd_tokens, txn->flags.upgrade, 0, noargs);
        sep = "; ";
    }
    if (txn->flags.te) {
        buf_printf(logbuf, "%stx-encoding=", sep);
        comma_list_body(logbuf, te, txn->flags.te, 0, noargs);
        sep = "; ";
    }
    if (resp_body->enc.proc && (resp_body->len || txn->flags.te)) {
        buf_printf(logbuf, "%scnt-encoding=", sep);
        comma_list_body(logbuf, ce, resp_body->enc.type, 0, noargs);
        sep = "; ";
    }
    if (txn->location) {
        buf_printf(logbuf, "%slocation=%s", sep, txn->location);
        sep = "; ";
    }
    else if (txn->flags.cors) {
        buf_printf(logbuf, "%sallow-origin", sep);
        sep = "; ";
    }
    else if (txn->error.desc) {
        buf_printf(logbuf, "%serror=%s", sep, txn->error.desc);
        sep = "; ";
    }
    if (*sep == ';') buf_appendcstr(logbuf, ")");

    /* Add timing stats */
    cmdtime_endtimer(&cmdtime, &nettime);
    buf_printf(logbuf, " [timing: cmd=%f net=%f total=%f]",
               cmdtime, nettime, cmdtime + nettime);

    syslog(LOG_INFO, "%s", buf_cstring(logbuf));
}


#ifdef HAVE_DECLARE_OPTIMIZE
EXPORTED inline void keepalive_response(struct transaction_t *txn)
    __attribute__((always_inline, optimize("-O3")));
#endif
EXPORTED void keepalive_response(struct transaction_t *txn)
{
    if (gotsigalrm) {
        response_header(HTTP_PROCESSING, txn);
    }
}


/*
 * Output an HTTP response with multipart body data.
 *
 * An initial call with 'code' != 0 will output a response header
 * and the preamble.
 *
 * All subsequent calls should have 'code' = 0 to output just a body part.
 * A body part may include custom headers (exluding Content-Type and Length),
 * which must be properly folded and must end with CRLF.
 *
 * A final call with 'len' = 0 ends the multipart body.
 */
EXPORTED void write_multipart_body(long code, struct transaction_t *txn,
                                   const char *buf, unsigned len,
                                   const char *part_headers)
{
    static char boundary[100];
    struct buf *body = &txn->resp_body.payload;

    if (code) {
        const char *preamble =
            "This is a message with multiple parts in MIME format.\r\n";

        txn->flags.mime = 1;

        /* Create multipart boundary */
        snprintf(boundary, sizeof(boundary), "%s-%ld-%ld-%ld",
                 *spool_getheader(txn->req_hdrs, ":authority"),
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
        buf_printf(body, "Content-Length: %d\r\n", len);
        if (part_headers) {
            buf_appendcstr(body, part_headers);
        }
        buf_appendcstr(body, "\r\n");
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
    write_multipart_body(HTTP_PARTIAL, txn, NULL, 0, NULL);

    txn->resp_body.type = type;
    while (range) {
        unsigned long offset = range->first;
        unsigned long datalen = range->last - range->first + 1;
        struct range *next = range->next;

        /* Output range as body part */
        txn->resp_body.range = range;
        write_multipart_body(0, txn, msg_base + offset, datalen, NULL);

        /* Cleanup */
        free(range);
        range = next;
    }

    /* End of multipart body */
    write_multipart_body(0, txn, NULL, 0, NULL);
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
    unsigned outlen = len, offset = 0, last_chunk;
    int do_md5 = (txn->meth == METH_HEAD) ? 0 :
        config_getswitch(IMAPOPT_HTTPCONTENTMD5);
    static MD5_CTX ctx;
    static unsigned char md5[MD5_DIGEST_LENGTH];

    syslog(LOG_DEBUG, "write_body(code = %ld, flags.te = %#x, len = %u)",
           code, txn->flags.te, len);

    if (txn->flags.te & TE_CHUNKED) last_chunk = !(code || len);
    else {
        /* Handle static content as last chunk */
        last_chunk = 1;

        if (len < GZIP_MIN_LEN) {
            /* Don't compress small static content */
            txn->resp_body.enc.type = CE_IDENTITY;
            txn->resp_body.enc.proc = NULL;
            txn->flags.te = TE_NONE;
        }
    }

    /* Compress data */
    if (txn->resp_body.enc.proc || txn->flags.te & ~TE_CHUNKED) {
        unsigned flags = 0;

        if (code) flags |= COMPRESS_START;
        if (last_chunk) flags |= COMPRESS_END;

        if (txn->resp_body.enc.proc(txn, flags, buf, len) < 0) {
            fatal("Error while compressing data", EX_SOFTWARE);
        }

        buf = txn->zbuf.s;
        outlen = txn->zbuf.len;
    }

    if (code) {
        /* Initial call - prepare response header based on CE, TE and version */
        if (do_md5) MD5Init(&ctx);

        if (txn->flags.te & ~TE_CHUNKED) {
            /* Transfer-Encoded content MUST be chunked */
            txn->flags.te |= TE_CHUNKED;
        }

        if (!txn->flags.te) {
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
        else if (do_md5) txn->flags.trailer |= TRAILER_CMD5;

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
    if (txn->flags.ver == VER_2) {
        /* HTTP/2 chunk */
        if (outlen || txn->flags.te) {
            http2_data_chunk(txn, buf + offset, outlen, last_chunk, &ctx);
        }
    }
    else if (txn->flags.te && txn->flags.ver == VER_1_1) {
        /* HTTP/1.1 chunk */
        if (outlen) {
            syslog(LOG_DEBUG, "write_body: chunk(%d)", outlen);
            prot_printf(httpd_out, "%x\r\n", outlen);
            prot_write(httpd_out, buf, outlen);
            prot_puts(httpd_out, "\r\n");

            if (txn->flags.trailer & TRAILER_CMD5) MD5Update(&ctx, buf, outlen);
        }
        if (last_chunk) {
            /* Terminate the HTTP/1.1 body with a zero-length chunk */
            syslog(LOG_DEBUG, "write_body: last chunk");
            prot_puts(httpd_out, "0\r\n");

            /* Trailer */
            if (txn->flags.trailer & TRAILER_CMD5) {
                syslog(LOG_DEBUG, "write_body: trailer Content-MD5");
                MD5Final(md5, &ctx);
                content_md5_hdr(txn, md5);
            }
            if ((txn->flags.trailer & TRAILER_CTAG) && txn->resp_body.ctag) {
                syslog(LOG_DEBUG, "write_body: trailer CTag");
                simple_hdr(txn, "CTag", "%s", txn->resp_body.ctag);
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
        if (txn->flags.te & TE_CHUNKED) {
            /* Start of XML chunked response */
            xmlChar *cp;
            int n;

            /* Leave root element open */
            for (cp = buf + --bufsiz, n = 0; *cp != '/'; cp--, n++);
            if (*(cp+1) == '>') memmove(cp, cp+1, n);  /* <root/> */
            else bufsiz -= n+1;  /* </root> */
        }

        /* Output the XML response */
        txn->resp_body.type = "application/xml; charset=utf-8";

        write_body(code, txn, (char *) buf, bufsiz);

        /* Cleanup */
        xmlFree(buf);
    }
    else {
        txn->error.precond = 0;
        txn->error.desc = "Error dumping XML tree";
        error_response(HTTP_SERVER_ERROR, txn);
    }
}

/* Output a chunk of an XML response */
EXPORTED void xml_partial_response(struct transaction_t *txn,
                                   xmlDocPtr doc, xmlNodePtr node,
                                   unsigned level, xmlBufferPtr *buf)
{
    const char *eol = "\n";
    unsigned n;

    if (!config_httpprettytelemetry) {
        level = 0;
        eol = "";
    }

    /* Start with clean buffer */
    if (!*buf) *buf = xmlBufferCreate();

    if (node) {
        /* Add leading indent to buffer */
        for (n = 0; n < level * MARKUP_INDENT; n++) xmlBufferCCat(*buf, " ");

        /* Dump XML node into buffer */
        xmlNodeDump(*buf, doc, node, level, config_httpprettytelemetry);

        /* Add trailing EOL to buffer */
        xmlBufferCCat(*buf, eol);
    }
    else {
        /* End of chunked XML response */
        xmlNodePtr root = xmlDocGetRootElement(doc);

        /* Add close of root element to buffer */
        xmlBufferCCat(*buf, "</");
        if (root->ns->prefix) {
            xmlBufferCat(*buf, root->ns->prefix);
            xmlBufferCCat(*buf, ":");
        }
        xmlBufferCat(*buf, root->name);
        xmlBufferCCat(*buf, ">");

        /* Add trailing EOL to buffer */
        xmlBufferCCat(*buf, eol);
    }

    if (txn) {
        /* Output the XML buffer */
        write_body(0, txn,
                   (char *) xmlBufferContent(*buf), xmlBufferLength(*buf));

        /* Reset the buffer for next chunk */
        xmlBufferEmpty(*buf);
    }
}

EXPORTED void buf_printf_markup(struct buf *buf, unsigned level,
                                const char *fmt, ...)
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
        const char **hdr, *host = config_servername;
        char *port = NULL;
        unsigned level = 0;

        if (txn->req_hdrs &&
            (hdr = spool_getheader(txn->req_hdrs, ":authority")) &&
            hdr[0] && *hdr[0]) {
            host = (char *) hdr[0];
            if ((port = strchr(host, ':'))) *port++ = '\0';
        }

        if (!port) {
            port = (buf_len(&saslprops.iplocalport)) ?
                strchr(buf_cstring(&saslprops.iplocalport), ';')+1 : "";
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
        if (config_serverinfo) {
            buf_printf_markup(html, level, "<hr>");
            buf_printf_markup(html, level,
                              "<address>%s Server at %s Port %s</address>",
                              (config_serverinfo == IMAP_ENUM_SERVERINFO_ON) ?
                              buf_cstring(&serverinfo) : "HTTP",
                              host, port);
        }
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
               txn->conn->clienthost, txn->auth_chal.scheme->name, httpd_authid,
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
               txn->conn->clienthost, txn->auth_chal.scheme->name,
               beautify_string(*authzid));
        return status;
    }

    /* See if auth'd user is allowed to proxy */
    status = mysasl_proxy_policy(httpd_saslconn, &httpd_proxyctx,
                                 authzbuf, authzlen,
                                 httpd_authid, strlen(httpd_authid),
                                 NULL, 0, NULL);

    if (status) {
        syslog(LOG_NOTICE, "badlogin: %s %s %s %s",
               txn->conn->clienthost, txn->auth_chal.scheme->name, httpd_authid,
               sasl_errdetail(httpd_saslconn));
        return status;
    }

    *authzid = authzbuf;

    return status;
}


/* Write cached header (redacting authorization credentials) to buffer. */
HIDDEN void log_cachehdr(const char *name, const char *contents,
                         const char *raw, void *rock)
{
    struct buf *buf = (struct buf *) rock;

    /* Ignore private headers in our cache */
    if (name[0] == ':') return;

    if (!strcasecmp(name, "authorization") && strchr(contents, ' ')) {
        /* Replace authorization credentials with an ellipsis */
        const char *creds = strchr(contents, ' ') + 1;
        buf_printf(buf, "%c%s: %.*s%-*s\r\n", toupper(name[0]), name+1,
                   (int) (creds - contents), contents,
                   (int) strlen(creds), "...");
    }
    else if (raw)
        buf_appendcstr(buf, raw);
    else
        buf_printf(buf, "%c%s: %s\r\n", toupper(name[0]), name+1, contents);
}


static int auth_success(struct transaction_t *txn, const char *userid)
{
    struct auth_scheme_t *scheme = txn->auth_chal.scheme;
    int logfd = txn->conn->logfd;
    int i;

    httpd_userid = xstrdup(userid);
    httpd_userisanonymous = is_userid_anonymous(httpd_userid);

    syslog(LOG_NOTICE, "login: %s %s %s%s %s SESSIONID=<%s>",
           txn->conn->clienthost, httpd_userid, scheme->name,
           txn->conn->tls_ctx ? "+TLS" : "", "User logged in",
           session_id());


    /* Recreate telemetry log entry for request (w/ credentials redacted) */
    assert(!buf_len(&txn->buf));
    buf_printf(&txn->buf, "<" TIME_T_FMT "<", time(NULL)); /* timestamp */
    buf_printf(&txn->buf, "%s %s %s\r\n",               /* request-line*/
               txn->req_line.meth, txn->req_line.uri, txn->req_line.ver);
    spool_enum_hdrcache(txn->req_hdrs,                  /* header fields */
                        &log_cachehdr, &txn->buf);
    buf_appendcstr(&txn->buf, "\r\n");                  /* CRLF */
    buf_append(&txn->buf, &txn->req_body.payload);      /* message body */
    buf_appendmap(&txn->buf,                            /* buffered input */
                  (const char *) httpd_in->ptr, httpd_in->cnt);

    if (logfd != -1) {
        /* Rewind log to current request and truncate it */
        off_t end = lseek(logfd, 0, SEEK_END);

        if (ftruncate(logfd, end - buf_len(&txn->buf)))
            syslog(LOG_ERR, "IOERROR: failed to truncate http log");

        /* Close existing telemetry log */
        close(logfd);
    }

    prot_setlog(httpd_in, PROT_NO_FD);
    prot_setlog(httpd_out, PROT_NO_FD);

    /* Create telemetry log based on new userid */
    if (txn->conn->sess_ctx)
        txn->conn->logfd = logfd = telemetry_log(userid, NULL, NULL, 0);
    else
        txn->conn->logfd = logfd = telemetry_log(userid, httpd_in, httpd_out, 0);

    if (logfd != -1) {
        /* Log credential-redacted request */
        if (write(logfd, buf_cstring(&txn->buf), buf_len(&txn->buf)) < 0)
            syslog(LOG_ERR, "IOERROR: failed to write to http log");
    }

    buf_reset(&txn->buf);

    /* Do any namespace specific post-auth processing */
    for (i = 0; http_namespaces[i]; i++) {
        if (http_namespaces[i]->enabled && http_namespaces[i]->auth) {
            int ret = http_namespaces[i]->auth(httpd_userid);
            if (ret) return ret;
        }
    }

    return 0;
}

/* Perform HTTP Authentication based on the given credentials ('creds').
 * Returns the selected auth scheme and any server challenge in 'chal'.
 * May be called multiple times if auth scheme requires multiple steps.
 * SASL status between steps is maintained in 'status'.
 */
#define MAX_AUTHPARAM_SIZE 10   /* "sid=,data=" */
#define MAX_BASE64_SIZE 21848   /* per RFC 4422: ((16K / 3) + 1) * 4  */
#define BASE64_BUF_SIZE (MAX_AUTHPARAM_SIZE +MAX_SESSIONID_SIZE +MAX_BASE64_SIZE)

static int http_auth(const char *creds, struct transaction_t *txn)
{
    struct auth_challenge_t *chal = &txn->auth_chal;
    static int status = SASL_OK;
    int slen, r;
    const char *clientin = NULL, *realm = NULL, *user, **authzid;
    unsigned int clientinlen = 0;
    struct auth_scheme_t *scheme;
    static char base64[BASE64_BUF_SIZE+1];
    const void *canon_user = NULL;

    /* Split credentials into auth scheme and response */
    slen = strcspn(creds, " ");
    if ((clientin = strchr(creds + slen, ' '))) {
        while (strchr(" ", *++clientin));  /* Trim leading 1*SP */
        clientinlen = strlen(clientin);
    }

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
                if (!(avail_auth_schemes & scheme->id)) scheme = NULL;
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

        if (!clientin && (scheme->flags & AUTH_REALM_PARAM)) {
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

            /* Create initial challenge (base64 buffer is static) */
            snprintf(base64, BASE64_BUF_SIZE, "realm=\"%s\"", realm);
            chal->param = base64;
            chal->scheme = NULL;  /* make sure we don't reset the SASL ctx */
            return status;
        }
    }

    /* Parse any auth parameters, if necessary */
    if (clientin && (scheme->flags & AUTH_DATA_PARAM)) {
        const char *sid = NULL;
        unsigned int sid_len;

        r = http_parse_auth_params(clientin, NULL /* realm */, NULL,
                                   &sid, &sid_len, &clientin, &clientinlen);
        if (r != SASL_OK) return r;

        if (sid) {
            const char *mysid = session_id();

            if (sid_len != strlen(mysid) ||
                strncmp(mysid, sid, sid_len)) {
                syslog(LOG_ERR, "%s: Incorrect 'sid' parameter in credentials",
                       scheme->name);
                return SASL_BADAUTH;
            }
        }
    }

    /* Base64 decode any client response, if necessary */
    if (clientin && (scheme->flags & AUTH_BASE64)) {
        r = sasl_decode64(clientin, clientinlen,
                          base64, BASE64_BUF_SIZE, &clientinlen);
        if (r != SASL_OK) {
            syslog(LOG_ERR, "Base64 decode failed: %s",
                   sasl_errstring(r, NULL, NULL));
            return r;
        }
        clientin = base64;
    }

    if (scheme->id == AUTH_BASIC) {
        /* Basic (plaintext) authentication */
        char *pass;
        char *extra;
        char *plus;
        char *domain;

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
        char *realuser =
            domain ? strconcat(user, "@", domain, (char *) NULL) : xstrdup(user);

        status = sasl_checkpass(httpd_saslconn, realuser, strlen(realuser),
                                pass, strlen(pass));
        memset(pass, 0, strlen(pass));          /* erase plaintext password */

        if (status) {
            if (*user == '\0')  // TB can send "Authorization: Basic Og=="
                txn->error.desc = "All-whitespace username.";
            syslog(LOG_NOTICE, "badlogin: %s Basic %s %s",
                   txn->conn->clienthost, realuser,
                   sasl_errdetail(httpd_saslconn));
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
    else if (scheme->id == AUTH_BEARER) {
        /* Bearer authentication */
        assert(txn->req_tgt.namespace->bearer);

        /* Call namespace bearer authentication.
         * We are working with base64 buffer, so the namespace can
         * write the canonicalized userid into the buffer */
        base64[0] = 0;
        status = txn->req_tgt.namespace->bearer(clientin,
                                                base64, BASE64_BUF_SIZE);
        if (status) return status;
        canon_user = user = base64;

        /* Successful authentication - fall through */
        httpd_extrafolder = NULL;
        httpd_extradomain = NULL;
        httpd_authstate = auth_newstate(user);
    }
    else {
        /* SASL-based authentication (SCRAM_*, Digest, Negotiate, NTLM) */
        const char *serverout = NULL;
        unsigned int serveroutlen = 0;
        unsigned int auth_params_len = 0;

#ifdef SASL_HTTP_REQUEST
        /* Setup SASL HTTP request, if necessary */
        sasl_http_request_t sasl_http_req;

        if (scheme->flags & AUTH_NEED_REQUEST) {
            sasl_http_req.method = txn->req_line.meth;
            sasl_http_req.uri = txn->req_line.uri;
            sasl_http_req.entity = NULL;
            sasl_http_req.elen = 0;
            sasl_http_req.non_persist = txn->flags.conn & CONN_CLOSE;
            sasl_setprop(httpd_saslconn, SASL_HTTP_REQUEST, &sasl_http_req);
        }
#endif /* SASL_HTTP_REQUEST */

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

        /* Prepend any auth parameters, if necessary */
        if (scheme->flags & AUTH_DATA_PARAM) {
            auth_params_len = snprintf(base64,
                                       MAX_AUTHPARAM_SIZE + MAX_SESSIONID_SIZE,
                                       "sid=%s%s", session_id(),
                                       serverout ? ",data=" : "");
        }

        /* Base64 encode any server challenge, if necessary */
        if (serverout && (scheme->flags & AUTH_BASE64)) {
            r = sasl_encode64(serverout, serveroutlen,
                              base64 + auth_params_len, MAX_BASE64_SIZE, NULL);
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

    if (!canon_user) {
        /* Get the userid from SASL - already canonicalized */
        status = sasl_getprop(httpd_saslconn, SASL_USERNAME, &canon_user);
        if (status != SASL_OK) {
            syslog(LOG_ERR, "weird SASL error %d getting SASL_USERNAME", status);
            return status;
        }
        user = (const char *) canon_user;
    }

    if (httpd_authid) free(httpd_authid);
    httpd_authid = xstrdup(user);

    authzid = spool_getheader(txn->req_hdrs, "Authorize-As");
    if (authzid && *authzid[0]) {
        /* Trying to proxy as another user */
        user = authzid[0];

        status = proxy_authz(&user, txn);
        if (status) return status;
    }

    /* Post-process the successful authentication. */
    r = auth_success(txn, user);
    if (r == HTTP_UNAVAILABLE) {
        status = SASL_UNAVAIL;
    }
    else if (r) {
        /* Any error here comes after the user already logged in,
         * so avoid to return SASL_BADAUTH. It would trigger the
         * HTTP handler to send UNAUTHORIZED, and might confuse
         * users that provided their correct credentials. */
        syslog(LOG_ERR, "auth_success returned error: %s", error_message(r));
        status = SASL_FAIL;
    }

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
        if (time_from_rfc5322(hdr[0], &since, DATETIME_FULL) < 0)
            return HTTP_BAD_REQUEST;

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
        if (time_from_rfc5322(hdr[0], &since, DATETIME_FULL) < 0)
            return HTTP_BAD_REQUEST;

        if (lastmod <= since) return HTTP_NOT_MODIFIED;

        /* Continue to step 5 */
    }

    /* Step 5 */
    if (txn->flags.ranges &&  /* Only if we support Range requests */
        txn->meth == METH_GET && (hdr = spool_getheader(hdrcache, "Range"))) {

        if ((hdr = spool_getheader(hdrcache, "If-Range"))) {
            time_from_rfc5322(hdr[0], &since, DATETIME_FULL); /* error OK here, could be an etag */
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
    buf_printf(&txn->buf, TIME_T_FMT "-" TIME_T_FMT "-" OFF_T_FMT,
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

        GCC_FALLTHROUGH

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
        for (i = 0; http_namespaces[i]; i++) {

            if (http_namespaces[i]->enabled && http_namespaces[i]->well_known) {
                buf_printf_markup(&body, level,
                                  "<li><a href=\"%s://%s%s\">%s</a></li>",
                                  proto, host, http_namespaces[i]->prefix,
                                  http_namespaces[i]->well_known);
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


/*
 * WebSockets data callback (no sub-protocol): Echo back non-control messages.
 *
 * Can be tested with:
 *   https://github.com/websockets/wscat
 *   https://addons.mozilla.org/en-US/firefox/addon/simple-websocket-client/
 *   https://chrome.google.com/webstore/detail/simple-websocket-client/gobngblklhkgmjhbpbdlkglbhhlafjnh
 *   https://chrome.google.com/webstore/detail/web-socket-client/lifhekgaodigcpmnakfhaaaboididbdn
 *
 * WebSockets over HTTP/2 currently only available in:
 *   https://www.google.com/chrome/browser/canary.html
 */
static int ws_echo(enum wslay_opcode opcode __attribute__((unused)),
                   struct buf *inbuf, struct buf *outbuf,
                   struct buf *logbuf __attribute__((unused)),
                   void **rock __attribute__((unused)))
{
    buf_init_ro(outbuf, buf_base(inbuf), buf_len(inbuf));

    return 0;
}


HIDDEN int meth_connect(struct transaction_t *txn, void *params)
{
    struct connect_params *cparams = (struct connect_params *) params;

    /* Bootstrap WebSockets over HTTP/2, if requested */
    if ((txn->flags.ver != VER_2) ||
        !ws_enabled() || !cparams || !cparams->endpoint) {
        return HTTP_NOT_IMPLEMENTED;
    }

    if (strcmp(txn->req_uri->path, cparams->endpoint)) return HTTP_NOT_ALLOWED;

    if (!(txn->flags.upgrade & UPGRADE_WS)) {
        txn->error.desc = "Missing/unsupported :protocol value ";
        return HTTP_BAD_REQUEST;
    }

    int ret = ws_start_channel(txn, cparams->subprotocol, cparams->data_cb);

    return (ret == HTTP_UPGRADE) ? HTTP_BAD_REQUEST : ret;
}


#define WELL_KNOWN_PREFIX "/.well-known"

/* Perform a GET/HEAD request */
static int meth_get(struct transaction_t *txn,
                    void *params __attribute__((unused)))
{
    int r, fd = -1, precond, len;
    const char *prefix, *urls, *path, *ext;
    static struct buf pathbuf = BUF_INITIALIZER;
    struct stat sbuf;
    const char *msg_base = NULL;
    size_t msg_size = 0;
    struct resp_body_t *resp_body = &txn->resp_body;

    /* Upgrade to WebSockets over HTTP/1.1 on root, if requested */
    if (!strcmp(txn->req_uri->path, "/")) {
        if (txn->flags.upgrade & UPGRADE_WS) {
            return ws_start_channel(txn, NULL, &ws_echo);
        }

        if (ws_enabled()) {
            txn->flags.upgrade |= UPGRADE_WS;
            txn->flags.conn |= CONN_UPGRADE;
        }
    }

    /* Check if this is a request for /.well-known/ listing */
    len = strlen(WELL_KNOWN_PREFIX);
    if (!strncmp(txn->req_uri->path, WELL_KNOWN_PREFIX, len)) {
        if (txn->req_uri->path[len] == '/') len++;
        if (txn->req_uri->path[len] == '\0') {
            return list_well_known(txn);
        }

        return HTTP_NOT_FOUND;
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
                        txn->resp_body.enc.type = CE_IDENTITY;
                        txn->resp_body.enc.proc = NULL;
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

        GCC_FALLTHROUGH

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

    return 0;
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
        for (i = 0; http_namespaces[i]; i++) {
            if (http_namespaces[i]->enabled)
                txn->req_tgt.allow |= http_namespaces[i]->allow;
        }

        if (ws_enabled() && (txn->flags.ver == VER_2)) {
            /* CONNECT allowed for bootstrapping WebSocket over HTTP/2 */
            txn->req_tgt.allow |= ALLOW_CONNECT;
        }
    }
    else {
        if (parse_path) {
            /* Parse the path */
            r = parse_path(txn->req_uri->path, &txn->req_tgt, &txn->error.desc);
            if (r) return r;
        }
        else if (!strcmp(txn->req_uri->path, "/") &&
                 ws_enabled() && (txn->flags.ver == VER_2)) {
            /* WS 'echo' endpoint */
            txn->req_tgt.allow |= ALLOW_CONNECT;
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
static void trace_cachehdr(const char *name, const char *contents, const char *raw, void *rock)
{
    struct buf *buf = (struct buf *) rock;
    const char **hdr, *sensitive[] =
        { "authorization", "cookie", "proxy-authorization", NULL };

    /* Ignore private headers in our cache */
    if (name[0] == ':') return;

    for (hdr = sensitive; *hdr && strcmp(name, *hdr); hdr++);

    if (!*hdr) {
        if (raw) buf_appendcstr(buf, raw);
        else buf_printf(buf, "%c%s: %s\r\n",
                            toupper(name[0]), name+1, contents);
    }
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

/* Allow unauthenticated GET/HEAD, deny all other unauthenticated requests */
EXPORTED int http_allow_noauth_get(struct transaction_t *txn)
{
    /* Inverse logic: True means we *require* authentication */
    switch (txn->meth) {
    case METH_GET:
    case METH_HEAD:
        /* Let method processing function decide if auth is needed */
        return 0;
    default:
        return 1;
    }
}

/* Allow unauthenticated requests */
EXPORTED int http_allow_noauth(struct transaction_t *txn __attribute__((unused)))
{
    return 0;
}


/* Read the body of a request */
EXPORTED int http_read_req_body(struct transaction_t *txn)
{
    struct body_t *body = &txn->req_body;

    syslog(LOG_DEBUG, "http_read_req_body(flags=%#x, framing=%d)",
           body->flags, body->framing);

    if (body->flags & BODY_DONE) return 0;
    body->flags |= BODY_DONE;

    if (body->flags & BODY_CONTINUE) {
        body->flags &= ~BODY_CONTINUE;

        if (body->flags & BODY_DISCARD) {
            /* Don't care about the body and client hasn't sent it, we're done */
            return 0;
        }

        /* Tell client to send the body */
        response_header(HTTP_CONTINUE, txn);
    }

    /* Read body from client */
    return http_read_body(txn->conn->pin, txn->req_hdrs, body, &txn->error.desc);
}
