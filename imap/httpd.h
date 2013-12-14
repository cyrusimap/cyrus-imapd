/* httpd.h -- Common state for HTTP/RSS/WebDAV/CalDAV/iSchedule daemon
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

#ifndef HTTPD_H
#define HTTPD_H

#include <sasl/sasl.h>
#include <libxml/tree.h>
#include <libxml/uri.h>

#ifdef HAVE_ZLIB
#include <zlib.h>
#endif /* HAVE_ZLIB */

#include "mailbox.h"
#include "spool.h"

#define MAX_REQ_LINE	8000  /* minimum size per HTTPbis */
#define MARKUP_INDENT	2     /* # spaces to indent each line of markup */
#define GZIP_MIN_LEN	300   /* minimum length of data to gzip */

/* Supported HTTP version */
#define HTTP_VERSION	 "HTTP/1.1"
#define HTTP_VERSION_LEN 8

/* Supported TLS version for Upgrade */
#define TLS_VERSION	 "TLS/1.0"

/* Supported HTML DOCTYPE */
#define HTML_DOCTYPE \
    "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\" " \
    "\"http://www.w3.org/TR/html4/loose.dtd\">"

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
};
extern const struct known_meth_t http_methods[];

/* Flags for known methods*/
enum {
    METH_NOBODY =	(1<<0),	/* Method does not expect a body */
};

/* Index into known HTTP methods - needs to stay in sync with array */
enum {
    METH_ACL = 0,
    METH_COPY,
    METH_DELETE,
    METH_GET,
    METH_HEAD,
    METH_LOCK,
    METH_MKCALENDAR,
    METH_MKCOL,
    METH_MOVE,
    METH_OPTIONS,
    METH_POST,
    METH_PROPFIND,
    METH_PROPPATCH,
    METH_PUT,
    METH_REPORT,
    METH_TRACE,
    METH_UNLOCK,

    METH_UNKNOWN,  /* MUST be last */
};


/* Path namespaces */
enum {
    URL_NS_DEFAULT = 0,
    URL_NS_PRINCIPAL,
    URL_NS_CALENDAR,
    URL_NS_ADDRESSBOOK,
    URL_NS_ISCHEDULE,
    URL_NS_DOMAINKEY,
    URL_NS_TIMEZONE,
    URL_NS_RSS
};

/* Bitmask of features/methods to allow, based on URL */
enum {
    ALLOW_READ =	(1<<0),	/* Read resources/properties */
    ALLOW_POST =	(1<<1),	/* Post to a URL */
    ALLOW_WRITE =	(1<<2),	/* Create/modify/lock resources */
    ALLOW_DELETE =	(1<<3),	/* Delete resources/collections */
    ALLOW_TRACE =	(1<<4),	/* TRACE a request */
    ALLOW_DAV =		(1<<5),	/* WebDAV specific methods/features */
    ALLOW_WRITECOL =	(1<<6),	/* Create/modify collections */
    ALLOW_CAL =		(1<<7),	/* CalDAV specific methods/features */
    ALLOW_CAL_SCHED =	(1<<8),	/* CalDAV Scheduling specific features */
    ALLOW_CARD =	(1<<9),	/* CardDAV specific methods/features */
    ALLOW_ISCHEDULE =	(1<<10)	/* iSchedule specific methods/features */
};

struct auth_scheme_t {
    unsigned idx;		/* Index value of the scheme */
    const char *name;		/* HTTP auth scheme name */
    const char *saslmech;	/* Corresponding SASL mech name */
    unsigned flags;		/* Bitmask of requirements/features */
    	     			/* Optional function to send success data */
    void (*send_success)(const char *name, const char *data);
    	     			/* Optional function to recv success data */
    const char *(*recv_success)(hdrcache_t hdrs);
};

/* Index into available schemes */
enum {
    AUTH_BASIC = 0,
    AUTH_DIGEST,
    AUTH_SPNEGO,
    AUTH_NTLM
};

/* Auth scheme flags */
enum {
    AUTH_NEED_PERSIST =	(1<<0),	/* Persistent connection required */
    AUTH_NEED_REQUEST =	(1<<1),	/* Request-line required */
    AUTH_SERVER_FIRST =	(1<<2),	/* SASL mech is server-first */
    AUTH_BASE64 =	(1<<3)	/* Base64 encode/decode auth data */
};

/* List of HTTP auth schemes that we support */
extern struct auth_scheme_t auth_schemes[];

extern const char *digest_recv_success(hdrcache_t hdrs);


/* Request-line context */
struct request_line_t {
    char buf[MAX_REQ_LINE+1];	/* working copy of request-line */
    char *meth;			/* method */
    char *uri;			/* request-target */
    char *ver;			/* HTTP-version */
};


/* Request target context */
struct request_target_t {
    char path[MAX_MAILBOX_PATH+1]; /* working copy of URL path */
    char *tail;			/* tail of original request path */
    unsigned namespace;		/* namespace of path */
    char *user;			/* ptr to owner of collection (NULL = shared) */
    size_t userlen;
    char *collection;		/* ptr to collection name */
    size_t collen;
    char *resource;		/* ptr to resource name */
    size_t reslen;
    unsigned flags;		/* target-specific flags/meta-data */
    unsigned long allow;	/* bitmask of allowed features/methods */
    char mboxname[MAX_MAILBOX_BUFFER+1];
};

/* Request target flags */
enum {
    TGT_SCHED_INBOX = 1,
    TGT_SCHED_OUTBOX
};

/* Function to parse URI path and generate a mailbox name */
typedef int (*parse_path_t)(const char *path,
			    struct request_target_t *tgt, const char **errstr);

/* Auth challenge context */
struct auth_challenge_t {
    struct auth_scheme_t *scheme;	/* Selected AUTH scheme */
    const char *param;	 		/* Server challenge */
};

/* Meta-data for error response */
struct error_t {
    const char *desc;			/* Error description */
    unsigned precond;			/* [Cal]DAV precondition */
    const char *resource;		/* Resource which lacks privileges */
    int rights;  			/* Privileges needed by resource */
};

struct range {
    unsigned long first;
    unsigned long last;
    struct range *next;
};

/* Context for reading request/response body */
struct body_t {
    unsigned char flags;		/* Disposition flags */
    unsigned char framing;		/* Message framing   */
    unsigned char te;			/* Transfer-Encoding */
    unsigned max;			/* Max allowed len   */
    ulong len; 				/* Content-Length    */
    struct buf payload;			/* Payload	     */
};

/* Message Framing flags */
enum {
    FRAMING_UNKNOWN = 0,
    FRAMING_LENGTH,
    FRAMING_CHUNKED,
    FRAMING_CLOSE
};


/* Meta-data for response body (payload & representation headers) */
struct resp_body_t {
    ulong len; 		/* Content-Length   */
    struct range *range;/* Content-Range    */
    const char *fname;	/* Content-Dispo    */
    unsigned char enc;	/* Content-Encoding */
    const char *lang;	/* Content-Language */
    const char *loc;	/* Content-Location */
    const u_char *md5;	/* Content-MD5      */
    const char *type;	/* Content-Type     */
    unsigned prefs;	/* Prefer	    */
    const char *lock;	/* Lock-Token       */
    const char *etag;	/* ETag             */
    time_t lastmod;	/* Last-Modified    */
    time_t maxage;	/* Expires	    */
    const char *stag;	/* Schedule-Tag     */
    time_t iserial;	/* iSched serial#   */
    struct buf payload;	/* Payload	    */
};

/* Transaction flags */
struct txn_flags_t {
    unsigned char ver1_0;		/* Request from HTTP/1.0 client */
    unsigned char conn;			/* Connection opts on req/resp */
    unsigned char override;		/* HTTP method override */
    unsigned char cors;			/* Cross-Origin Resource Sharing */
    unsigned char mime;			/* MIME-conformant response */
    unsigned char te;			/* Transfer-Encoding for resp */
    unsigned char cc;			/* Cache-Control directives for resp */
    unsigned char ranges;		/* Accept range requests for resource */
    unsigned char vary;			/* Headers on which response varied */
    unsigned char trailer;		/* Headers which will be in trailer */
};

/* Transaction context */
struct transaction_t {
    unsigned meth;			/* Index of Method to be performed */
    struct txn_flags_t flags;		/* Flags for this txn */
    struct request_line_t req_line;	/* Parsed request-line */
    xmlURIPtr req_uri;	  		/* Parsed request-target URI */
    struct request_target_t req_tgt;	/* Parsed request-target path */
    hdrcache_t req_hdrs;    		/* Cached HTTP headers */
    struct body_t req_body;		/* Buffered request body */
    struct auth_challenge_t auth_chal;	/* Authentication challenge */
    const char *location;   		/* Location of resource */
    struct error_t error;		/* Error response meta-data */
    struct resp_body_t resp_body;	/* Response body meta-data */
#ifdef HAVE_ZLIB
    z_stream zstrm;			/* Compression context */
    struct buf zbuf;			/* Compression buffer */
#endif
    struct buf buf;	    		/* Working buffer - currently used for:
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
};

/* Connection token flags */
enum {
    CONN_CLOSE =	(1<<0),
    CONN_UPGRADE = 	(1<<1),
    CONN_KEEPALIVE =	(1<<2)
};

/* Cross-Origin Resource Sharing flags */
enum {
    CORS_NONE =		0,
    CORS_SIMPLE =	1,
    CORS_PREFLIGHT =	2
};

/* read_body() flags */
enum {
    BODY_RESPONSE =	(1<<0),	/* Response body, otherwise request */
    BODY_CONTINUE =	(1<<1),	/* Expect:100-continue request */
    BODY_CLOSE =	(1<<1),	/* Close-delimited response body */
    BODY_DECODE = 	(1<<2),	/* Decode any Content-Encoding */
    BODY_DISCARD =	(1<<3),	/* Discard body (don't buffer or decode) */
    BODY_DONE =		(1<<4)	/* Body has been read */
};

/* Transfer-Encoding flags (coding of response payload) */
enum {
    TE_NONE =		0,
    TE_DEFLATE =	(1<<0),	/* Implies TE_CHUNKED as final coding */
    TE_GZIP =		(1<<1),	/* Implies TE_CHUNKED as final coding */
    TE_CHUNKED =	(1<<2)  /* MUST be last */
};

/* Content-Encoding flags (coding of representation) */
enum {
    CE_IDENTITY =	0,
    CE_DEFLATE =	(1<<0),
    CE_GZIP =		(1<<1)
};

/* Cache-Control directive flags */
enum {
    CC_REVALIDATE =	(1<<0),
    CC_NOCACHE =	(1<<1),
    CC_NOSTORE =	(1<<2),
    CC_NOTRANSFORM =	(1<<3),
    CC_PUBLIC =	   	(1<<4),
    CC_PRIVATE =	(1<<5),
    CC_MAXAGE =	   	(1<<6)
};

/* Vary header flags (headers used in selecting/producing representation) */
enum {
    VARY_ACCEPT =	(1<<0),
    VARY_AE =		(1<<1),	/* Accept-Encoding */
    VARY_BRIEF =	(1<<2),
    VARY_PREFER =	(1<<3)
};

/* Trailer header flags */
enum {
    TRAILER_CMD5 =	(1<<0)  /* Content-MD5 */
};

typedef int (*method_proc_t)(struct transaction_t *txn, void *params);
typedef int (*filter_proc_t)(struct transaction_t *txn,
			     const char *base, unsigned long len);

struct method_t {
    method_proc_t proc;		/* Function to perform the method */
    void *params;		/* Parameters to pass to the method */
};

struct namespace_t {
    unsigned id;		/* Namespace identifier */
    unsigned enabled;		/* Is this namespace enabled? */
    const char *prefix;		/* Prefix of URL path denoting namespace */
    const char *well_known;	/* Any /.well-known/ URI */
    unsigned need_auth;		/* Do we need to auth for this namespace? */
    unsigned long allow;	/* Bitmask of allowed features/methods */
    void (*init)(struct buf *serverinfo);
    void (*auth)(const char *userid);
    void (*reset)(void);
    void (*shutdown)(void);
    struct method_t methods[];	/* Array of functions to perform HTTP methods.
				 * MUST be an entry for EACH method listed,
				 * and in the SAME ORDER in which they appear,
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
extern struct namespace_t namespace_calendar;
extern struct namespace_t namespace_addressbook;
extern struct namespace_t namespace_ischedule;
extern struct namespace_t namespace_domainkey;
extern struct namespace_t namespace_timezone;
extern struct namespace_t namespace_rss;


/* XXX  These should be included in struct transaction_t */
extern struct buf serverinfo;
extern struct backend **backend_cached;
extern struct protstream *httpd_in;
extern struct protstream *httpd_out;
extern int https;
extern int httpd_tls_done;
extern int httpd_timeout;
extern int httpd_userisadmin;
extern int httpd_userisproxyadmin;
extern char *httpd_userid, *proxy_userid;
extern struct auth_state *httpd_authstate;
extern struct namespace httpd_namespace;
extern struct sockaddr_storage httpd_localaddr, httpd_remoteaddr;
extern unsigned long config_httpmodules;
extern int config_httpprettytelemetry;

extern xmlURIPtr parse_uri(unsigned meth, const char *uri, unsigned path_reqd,
			   const char **errstr);
extern struct accept *parse_accept(const char **hdr);
extern int is_mediatype(const char *pat, const char *type);
extern time_t calc_compile_time(const char *time, const char *date);
extern int http_mailbox_open(const char *name, struct mailbox **mailbox,
			     int locktype);
extern const char *http_statusline(long code);
extern char *rfc3339date_gen(char *buf, size_t len, time_t t);
extern char *httpdate_gen(char *buf, size_t len, time_t t);
extern void comma_list_hdr(const char *hdr, const char *vals[],
			   unsigned flags, ...);
extern void response_header(long code, struct transaction_t *txn);
extern void buf_printf_markup(struct buf *buf, unsigned level,
			      const char *fmt, ...);
extern void error_response(long code, struct transaction_t *txn);
extern void html_response(long code, struct transaction_t *txn, xmlDocPtr html);
extern void xml_response(long code, struct transaction_t *txn, xmlDocPtr xml);
extern void write_body(long code, struct transaction_t *txn,
		       const char *buf, unsigned len);
extern void write_multipart_body(long code, struct transaction_t *txn,
				 const char *buf, unsigned len);
extern int meth_options(struct transaction_t *txn, void *params);
extern int meth_trace(struct transaction_t *txn, void *params);
extern int etagcmp(const char *hdr, const char *etag);
extern int check_precond(struct transaction_t *txn, const void *data,
			 const char *etag, time_t lastmod);
extern int parse_framing(hdrcache_t hdrs, struct body_t *body,
			 const char **errstr);
extern int read_body(struct protstream *pin, hdrcache_t hdrs,
		     struct body_t *body, const char **errstr);

#endif /* HTTPD_H */
