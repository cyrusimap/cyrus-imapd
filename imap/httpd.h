/* httpd.h -- Common state for HTTP/RSS/xDAV/JMAP/TZdist/iSchedule daemon
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

#ifndef HTTPD_H
#define HTTPD_H

#include <sasl/sasl.h>
#include <libxml/tree.h>
#include <libxml/uri.h>
#include <libical/ical.h>

#include "annotate.h" /* for strlist */
#include "hash.h"
#include "http_client.h"
#include "mailbox.h"
#include "prometheus.h"
#include "spool.h"

#define MAX_REQ_LINE    8000  /* minimum size per RFC 7230 */
#define MARKUP_INDENT   2     /* # spaces to indent each line of markup */
#define GZIP_MIN_LEN    300   /* minimum length of data to gzip */

#define COMPRESS_START (1<<0)
#define COMPRESS_END   (1<<1)

#define DFLAG_UNBIND    "DAV:unbind"
#define DFLAG_UNCHANGED "DAV:unchanged"

/* XML namespace URIs */
#define XML_NS_CYRUS    "http://cyrusimap.org/ns/"

/* Supported TLS version for Upgrade */
#define TLS_VERSION      "TLS/1.2"

/* Supported HTML DOCTYPE */
#define HTML_DOCTYPE \
    "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\" " \
    "\"http://www.w3.org/TR/html4/loose.dtd\">"

#define XML_DECLARATION \
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>"

/* Macro to return proper response code when user privileges are insufficient */
#define HTTP_NO_PRIVS \
    (httpd_userid && !is_userid_anonymous(httpd_userid) ? \
     HTTP_FORBIDDEN : HTTP_UNAUTHORIZED)

/* Macro to access query part of URI */
#if LIBXML_VERSION >= 20700
#define URI_QUERY(uri) uri->query_raw
#else
#define URI_QUERY(uri) uri->query
#endif

/* SASL usage based on availability */
#if defined(SASL_NEED_HTTP) && defined(SASL_HTTP_REQUEST)
  #define HTTP_DIGEST_MECH "DIGEST-MD5"
  #define SASL_USAGE_FLAGS (SASL_NEED_HTTP | SASL_SUCCESS_DATA)
#else
  #define HTTP_DIGEST_MECH NULL  /* not supported by our SASL version */
  #define SASL_USAGE_FLAGS SASL_SUCCESS_DATA
#endif /* SASL_NEED_HTTP */

/* Array of HTTP methods known by our server. */
struct known_meth_t {
    const char *name;
    unsigned flags;
    enum prom_labelled_metric metric;
};
extern const struct known_meth_t http_methods[];
extern struct namespace_t *http_namespaces[];

/* Flags for known methods*/
enum {
    METH_NOBODY =       (1<<0), /* Method does not expect a body */
    METH_SAFE =         (1<<1), /* Method is "safe" */
};


/* Path namespaces */
enum {
    URL_NS_DEFAULT = 0,
    URL_NS_PRINCIPAL,
    URL_NS_NOTIFY,
    URL_NS_CALENDAR,
    URL_NS_FREEBUSY,
    URL_NS_ADDRESSBOOK,
    URL_NS_DRIVE,
    URL_NS_ISCHEDULE,
    URL_NS_DOMAINKEY,
    URL_NS_TZDIST,
    URL_NS_RSS,
    URL_NS_DBLOOKUP,
#ifdef WITH_JMAP
    URL_NS_JMAP,
#endif
    URL_NS_ADMIN,
    URL_NS_APPLEPUSH,
    URL_NS_PROMETHEUS,
    URL_NS_CGI,
};

/* Bitmask of features/methods to allow, based on URL */
enum {
    ALLOW_READ =        (1<<0), /* Read resources/properties */
    ALLOW_POST =        (1<<1), /* Post to a URL */
    ALLOW_WRITE =       (1<<2), /* Create/modify/lock resources */
    ALLOW_PATCH =       (1<<3), /* Patch resources */
    ALLOW_DELETE =      (1<<4), /* Delete resources/collections */
    ALLOW_TRACE =       (1<<5), /* TRACE a request */
    ALLOW_CONNECT =     (1<<6), /* Establish a tunnel */

    ALLOW_DAV =         (1<<8), /* WebDAV specific methods/features */
    ALLOW_PROPPATCH  =  (1<<9), /* Modify properties */
    ALLOW_MKCOL =       (1<<10),/* Create collections */
    ALLOW_ACL =         (1<<11),/* Modify access control list */
    ALLOW_USERDATA =    (1<<12),/* Store per-user data for resource */

    ALLOW_CAL =         (1<<16),/* CalDAV specific methods/features */
    ALLOW_CAL_SCHED =   (1<<17),/* CalDAV Scheduling specific features */
    ALLOW_CAL_AVAIL =   (1<<18),/* CalDAV Availability specific features */
    ALLOW_CAL_NOTZ =    (1<<19),/* CalDAV TZ by Ref specific features */
    ALLOW_CAL_ATTACH =  (1<<20),/* CalDAV Managed Attachments features */

    ALLOW_CARD =        (1<<24),/* CardDAV specific methods/features */

    ALLOW_READONLY =    (1<<30),/* Allow "unsafe" methods when readonly */

    ALLOW_ISCHEDULE =   (1<<31) /* iSchedule specific methods/features */
};

#define ALLOW_READ_MASK ~(ALLOW_POST|ALLOW_WRITE|ALLOW_DELETE|ALLOW_PATCH\
                          |ALLOW_PROPPATCH|ALLOW_MKCOL|ALLOW_ACL)


typedef struct transaction_t txn_t;

struct auth_scheme_t {
    unsigned id;                /* Identifier of the scheme */
    const char *name;           /* HTTP auth scheme name */
    const char *saslmech;       /* Corresponding SASL mech name */
    unsigned flags;             /* Bitmask of requirements/features */
                                /* Optional function to send success data */
};

/* Auth scheme identifiers */
enum {
    AUTH_BASIC        = (1<<0),
    AUTH_DIGEST       = (1<<1),
    AUTH_SPNEGO       = (1<<2),
    AUTH_NTLM         = (1<<3),
    AUTH_BEARER       = (1<<4),
    AUTH_SCRAM_SHA1   = (1<<5),
    AUTH_SCRAM_SHA256 = (1<<6)
};

/* Auth scheme flags */
enum {
    AUTH_NEED_PERSIST = (1<<0), /* Persistent connection required */
    AUTH_NEED_REQUEST = (1<<1), /* Request-line required */
    AUTH_SERVER_FIRST = (1<<2), /* SASL mech is server-first */
    AUTH_BASE64       = (1<<3), /* Base64 encode/decode challenge/response */
    AUTH_REALM_PARAM  = (1<<4), /* Need "realm" parameter in initial challenge */
    AUTH_DATA_PARAM   = (1<<5), /* Challenge/credentials use auth-params */
    AUTH_SUCCESS_WWW  = (1<<6)  /* Success data uses WWW-Authenticate header */
};

#define AUTH_SCHEME_BASIC { AUTH_BASIC, "Basic", NULL, \
                            AUTH_SERVER_FIRST | AUTH_REALM_PARAM | AUTH_BASE64 }

/* List of HTTP auth schemes that we support */
extern struct auth_scheme_t auth_schemes[];


/* Request-line context */
struct request_line_t {
    char buf[MAX_REQ_LINE+1];   /* working copy of request-line */
    const char *meth;           /* method */
    const char *uri;            /* request-target */
    const char *ver;            /* HTTP-version */
};


/* Request target context */
struct request_target_t {
    char path[MAX_MAILBOX_PATH+1]; /* working copy of URL path */
    char *tail;                 /* tail of original request path */
    const struct namespace_t *namespace; /* namespace of path */
    char *userid;               /* owner of collection (needs freeing) */
    char *collection;           /* ptr to collection name */
    size_t collen;
    char *resource;             /* ptr to resource name */
    size_t reslen;
    unsigned flags;             /* target-specific flags/meta-data */
    unsigned long allow;        /* bitmask of allowed features/methods */
    mbentry_t *mbentry;         /* mboxlist entry of target collection */
    const char *mboxprefix;     /* mailbox prefix */
};

/* Request target flags */
enum {
    TGT_SERVER_INFO = 1,
    TGT_DAV_SHARED,
    TGT_SCHED_INBOX,
    TGT_SCHED_OUTBOX,
    TGT_MANAGED_ATTACH,
    TGT_DRIVE_ROOT,
    TGT_DRIVE_USER,
    TGT_USER_ZZZZ
};

/* Function to parse URI path and generate a mailbox name */
typedef int (*parse_path_t)(const char *path, struct request_target_t *tgt,
                            const char **resultstr);

/* Auth challenge context */
struct auth_challenge_t {
    struct auth_scheme_t *scheme;       /* Selected AUTH scheme */
    const char *param;                  /* Server challenge */
};

/* Meta-data for error response */
struct error_t {
    const char *desc;                   /* Error description */
    unsigned precond;                   /* [Cal]DAV precondition */
    xmlNodePtr node;                    /* XML node to be added to error */
    const char *resource;               /* Resource href to be added to error */
    int rights;                         /* Privileges needed by resource */
};

struct range {
    unsigned long first;
    unsigned long last;
    struct range *next;
};

struct patch_doc_t {
    const char *format;                 /* MIME format of patch document */
    int (*proc)();                      /* Function to parse and apply doc */
};

typedef int (*encode_proc_t)(struct transaction_t *txn,
                             unsigned flags, const char *buf, unsigned len);


/* Meta-data for response body (payload & representation headers) */
struct resp_body_t {
    ulong len;                          /* Content-Length   */
    struct range *range;                /* Content-Range    */
    struct {
        const char *fname;
        unsigned attach : 1;
    } dispo;                            /* Content-Dispo    */
    struct {
        unsigned char type;
        encode_proc_t proc;
    } enc;                              /* Content-Encoding */
    const char *lang;                   /* Content-Language */
    const char *loc;                    /* Content-Location */
    const u_char *md5;                  /* Content-MD5      */
    const char *type;                   /* Content-Type     */
    const struct patch_doc_t *patch;    /* Accept-Patch     */
    unsigned prefs;                     /* Prefer           */
    strarray_t links;                   /* Link(s)          */
    const char *lock;                   /* Lock-Token       */
    const char *ctag;                   /* CTag             */
    const char *etag;                   /* ETag             */
    time_t lastmod;                     /* Last-Modified    */
    time_t maxage;                      /* Expires          */
    const char *stag;                   /* Schedule-Tag     */
    const char *cmid;                   /* Cal-Managed-ID   */
    time_t iserial;                     /* iSched serial#   */
    hdrcache_t extra_hdrs;              /* Extra headers    */
    struct buf payload;                 /* Payload          */
};

/* Transaction flags */
struct txn_flags_t {
    unsigned long ver      : 2;         /* HTTP version of request */
    unsigned long conn     : 3;         /* Connection opts on req/resp */
    unsigned long upgrade  : 3;         /* Upgrade protocols */
    unsigned long override : 1;         /* HTTP method override */
    unsigned long cors     : 3;         /* Cross-Origin Resource Sharing */
    unsigned long mime     : 1;         /* MIME-conformant response */
    unsigned long te       : 3;         /* Transfer-Encoding for resp */
    unsigned long cc       : 8;         /* Cache-Control directives for resp */
    unsigned long ranges   : 1;         /* Accept range requests for resource */
    unsigned long vary     : 6;         /* Headers on which response can vary */
    unsigned long trailer  : 3;         /* Headers which will be in trailer */
    unsigned long redirect : 1;         /* CGI local redirect */
};

/* HTTP connection context */
struct http_connection {
    struct protstream *pin;             /* Input protstream */
    struct protstream *pout;            /* Output protstream */
    const char *clienthost;             /* Name of client host */
    int logfd;                          /* Telemetry log file */
    struct buf logbuf;                  /* Telemetry log buffer */

    void *tls_ctx;                      /* TLS context */
    void *sess_ctx;                     /* HTTP/2+ session context */
    void *ws_ctx;                       /* WebSocket context (HTTP/1.1 only) */

    xmlParserCtxtPtr xml;               /* XML parser content */
};


/* Transaction context */
struct transaction_t {
    struct http_connection *conn;       /* Global connection context */
    void *strm_ctx;                     /* HTTP/2+ stream context */
    void *ws_ctx;                       /* WebSocket channel context */
    unsigned meth;                      /* Index of Method to be performed */
    struct txn_flags_t flags;           /* Flags for this txn */
    struct request_line_t req_line;     /* Parsed request-line */
    xmlURIPtr req_uri;                  /* Parsed request-target URI */
    struct request_target_t req_tgt;    /* Parsed request-target path */
    hash_table req_qparams;             /* Parsed query params */
    hdrcache_t req_hdrs;                /* Cached HTTP headers */
    struct body_t req_body;             /* Buffered request body */
    struct auth_challenge_t auth_chal;  /* Authentication challenge */
    const char *location;               /* Location of resource */
    struct error_t error;               /* Error response meta-data */
    struct resp_body_t resp_body;       /* Response body meta-data */
    struct buf zbuf;                    /* Compression buffer */
    struct buf buf;                     /* Working buffer - currently used for:
                                           httpd:
                                             - telemetry of auth'd request
                                             - error desc string
                                             - Location hdr on redirects
                                             - Etag for static docs
                                           http_rss:
                                             - Content-Type for MIME parts
                                             - URL for feed & items
                                           http_caldav:
                                             - precond error resource URL
                                           http_ischedule:
                                             - error desc string
                                        */

    void *zstrm;                        /* Zlib compression context */
    void *brotli;                       /* Brotli compression context */
    void *zstd;                         /* Zstandard compression context */
};

/* HTTP version flags */
enum {
    VER_1_0 =           0,
    VER_1_1 =           1,
    VER_2 =             2
};

/* Connection token flags */
enum {
    CONN_CLOSE =        (1<<0),
    CONN_UPGRADE =      (1<<1),
    CONN_KEEPALIVE =    (1<<2)
};

/* Upgrade protocol flags */
enum {
    UPGRADE_TLS =       (1<<0),
    UPGRADE_HTTP2 =     (1<<1),
    UPGRADE_WS =        (1<<2)
};

/* Cross-Origin Resource Sharing flags */
enum {
    CORS_NONE =         0,
    CORS_SIMPLE =       1,
    CORS_PREFLIGHT =    2
};

/* Content-Encoding flags (coding of representation) */
enum {
    CE_IDENTITY =       0,      /* no encoding          */
    CE_DEFLATE  =       (1<<0), /* ZLIB      - RFC 1950 */
    CE_GZIP     =       (1<<1), /* GZIP      - RFC 1952 */
    CE_BR       =       (1<<2), /* Brotli    - RFC 7932 */
    CE_ZSTD     =       (1<<3)  /* Zstandard - RFC 8878 */
};

/* Cache-Control directive flags */
enum {
    CC_REVALIDATE =     (1<<0),
    CC_NOCACHE =        (1<<1),
    CC_NOSTORE =        (1<<2),
    CC_NOTRANSFORM =    (1<<3),
    CC_PUBLIC =         (1<<4),
    CC_PRIVATE =        (1<<5),
    CC_MAXAGE =         (1<<6),
    CC_IMMUTABLE =      (1<<7), /* RFC 8246 */
};

/* Vary header flags (headers used in selecting/producing representation) */
enum {
    VARY_ACCEPT =       (1<<0),
    VARY_AE =           (1<<1), /* Accept-Encoding */
    VARY_BRIEF =        (1<<2),
    VARY_PREFER =       (1<<3),
    VARY_IFNONE =       (1<<4), /* If-None-Match */
    VARY_CALTZ =        (1<<5)  /* CalDAV-Timezones */
};

/* Trailer header flags */
enum {
    TRAILER_CMD5 =      (1<<0), /* Content-MD5 will be generated */
    TRAILER_CTAG =      (1<<1), /* CTag will be returned */
    TRAILER_PROXY =     (1<<2)  /* Trailer(s) will be proxied from origin */
};

typedef int (*premethod_proc_t)(struct transaction_t *txn);
typedef int (*method_proc_t)(struct transaction_t *txn, void *params);

struct method_t {
    method_proc_t proc;         /* Function to perform the method */
    void *params;               /* Parameters to pass to the method */
};

struct connect_params {
    /* WebSocket parameters */
    const char *endpoint;
    const char *subprotocol;
    const void *data_cb;
};

struct namespace_t {
    unsigned id;                /* Namespace identifier */
    unsigned enabled;           /* Is this namespace enabled? */
    const char *name;           /* Text name of this namespace ([A-Z][a-z][0-9]+) */
    const char *prefix;         /* Prefix of URL path denoting namespace */
    const char *well_known;     /* Any /.well-known/ URI */
    int (*need_auth)(txn_t *);  /* Function run prior to unauthorized requests */
    unsigned auth_schemes;      /* Bitmask of allowed auth schemes, 0 for any */
    int mboxtype;               /* What mbtype can be seen in this namespace? */
    unsigned long allow;        /* Bitmask of allowed features/methods */
    void (*init)(struct buf *); /* Function run during service startup */
    int (*auth)(const char *);  /* Function run after authentication */
    void (*reset)(void);        /* Function run before change in auth */
    void (*shutdown)(void);     /* Function run during service shutdown */
    int (*premethod)(txn_t *);  /* Function run prior to any method */
    int (*bearer)(const char *, /* Function run to authenticate Bearer token */
                  char *, size_t);
    struct method_t methods[];  /* Array of functions to perform HTTP methods.
                                 * MUST be an entry for EACH method listed,
                                 * and in the SAME ORDER in which they appear
                                 * in the http_methods[] array.
                                 * If the method is not supported,
                                 * the function pointer MUST be NULL.
                                 */
};

struct accept {
    char *token;
    float qual;
    struct accept *next;
};

extern struct namespace_t namespace_default;
extern struct namespace_t namespace_principal;
extern struct namespace_t namespace_notify;
extern struct namespace_t namespace_calendar;
extern struct namespace_t namespace_freebusy;
extern struct namespace_t namespace_addressbook;
extern struct namespace_t namespace_drive;
extern struct namespace_t namespace_ischedule;
extern struct namespace_t namespace_domainkey;
extern struct namespace_t namespace_tzdist;
#ifdef WITH_JMAP
extern struct namespace_t namespace_jmap;
#endif
extern struct namespace_t namespace_rss;
extern struct namespace_t namespace_dblookup;
extern struct namespace_t namespace_admin;
extern struct namespace_t namespace_applepush;
extern struct namespace_t namespace_prometheus;
extern struct namespace_t namespace_cgi;


/* XXX  These should be included in struct transaction_t */
extern struct buf serverinfo;
extern struct backend **backend_cached;
extern struct protstream *httpd_in;
extern struct protstream *httpd_out;
extern int https;
extern sasl_conn_t *httpd_saslconn;
extern int httpd_timeout;
extern int httpd_userisadmin;
extern int httpd_userisproxyadmin;
extern int httpd_userisanonymous;
extern char *httpd_userid;
extern char *httpd_extrafolder;
extern char *httpd_extradomain;
extern struct auth_state *httpd_authstate;
extern struct namespace httpd_namespace;
extern const char *httpd_localip, *httpd_remoteip;
extern unsigned long config_httpmodules;
extern int config_httpprettytelemetry;
extern strarray_t *httpd_log_headers;

extern int ignorequota;
extern int apns_enabled;

extern xmlURIPtr parse_uri(unsigned meth, const char *uri, unsigned path_reqd,
                           const char **errstr);
extern struct accept *parse_accept(const char **hdr);
extern void parse_query_params(struct transaction_t *txn, const char *query);
extern time_t calc_compile_time(const char *time, const char *date);
extern const char *http_statusline(unsigned ver, long code);
extern char *httpdate_gen(char *buf, size_t len, time_t t);
extern void begin_resp_headers(struct transaction_t *txn, long code);
extern int end_resp_headers(struct transaction_t *txn, long code);
extern void simple_hdr(struct transaction_t *txn,
                       const char *name, const char *value, ...)
                      __attribute__((format(printf, 3, 4)));
extern void content_md5_hdr(struct transaction_t *txn,
                            const unsigned char *md5);
extern void comma_list_hdr(struct transaction_t *txn,
                           const char *hdr, const char *vals[],
                           unsigned flags, ...);
extern void response_header(long code, struct transaction_t *txn);
extern void buf_printf_markup(struct buf *buf, unsigned level,
                              const char *fmt, ...)
                             __attribute__((format(printf, 3, 4)));
extern void keepalive_response(struct transaction_t *txn);
extern void error_response(long code, struct transaction_t *txn);
extern void html_response(long code, struct transaction_t *txn, xmlDocPtr html);
extern void xml_response(long code, struct transaction_t *txn, xmlDocPtr xml);
extern void xml_partial_response(struct transaction_t *txn,
                                 xmlDocPtr doc, xmlNodePtr node,
                                 unsigned level, xmlBufferPtr *buf);
extern void write_body(long code, struct transaction_t *txn,
                       const char *buf, unsigned len);
extern void write_multipart_body(long code, struct transaction_t *txn,
                                 const char *buf, unsigned len,
                                 const char *part_headers);

extern int meth_connect(struct transaction_t *txn, void *params);
extern int meth_options(struct transaction_t *txn, void *params);
extern int meth_trace(struct transaction_t *txn, void *params);
extern int etagcmp(const char *hdr, const char *etag);
extern int check_precond(struct transaction_t *txn,
                         const char *etag, time_t lastmod);

extern void log_cachehdr(const char *name, const char *contents,
                         const char *raw, void *rock);

extern int examine_request(struct transaction_t *txn, const char *uri);
extern int process_request(struct transaction_t *txn);
extern void transaction_free(struct transaction_t *txn);

extern int httpd_myrights(struct auth_state *authstate, const mbentry_t *mbentry);
extern int http_allow_noauth(struct transaction_t *txn);
extern int http_allow_noauth_get(struct transaction_t *txn);
extern int http_read_req_body(struct transaction_t *txn);

extern void *zlib_init();
extern int zlib_compress(struct transaction_t *txn, unsigned flags,
                         const char *buf, unsigned len);

extern void *zstd_init();
extern void *brotli_init();

#endif /* HTTPD_H */
