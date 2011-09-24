/* httpd.h -- Common state for HTTP/WebDAV/CalDAV daemon
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

#include <libxml/tree.h>

#include "mailbox.h"
#include "spool.h"

/* Supported HTTP version */
#define HTTP_VERSION	"HTTP/1.1"

/* XML namespace URIs */
#define XML_NS_DAV	"DAV:"
#define XML_NS_CAL	"urn:ietf:params:xml:ns:caldav"
#define XML_NS_CS	"http://calendarserver.org/ns/"
#define XML_NS_APPLE	"http://apple.com/ns/ical/"
#define XML_NS_CYRUS	"http://cyrusimap.org/ns/"

/* Cyrus-specific privileges */
#define DACL_MKCOL	ACL_CREATE	/* CY:make-collection */
#define DACL_ADDRSRC	ACL_POST	/* CY:add-resource */
#define DACL_RMCOL	ACL_DELETEMBOX	/* CY:remove-collection */
#define DACL_RMRSRC	ACL_DELETEMSG	/* CY:remove-resource */
#define DACL_ADMIN	ACL_ADMIN	/* CY:admin (aggregates
					   DAV:read-acl, write-acl, unlock) */

/* WebDAV (RFC 3744) privileges */
#define DACL_READ	ACL_READ	/* DAV:read (aggregates
					   DAV:read-current-user-privilege-set
					   and CALDAV:read-free-busy) */
#define DACL_WRITECONT	ACL_INSERT	/* DAV:write-content */
#define DACL_WRITEPROPS	ACL_WRITE	/* DAV:write-properties */
#define DACL_BIND	(DACL_MKCOL\
			 |DACL_ADDRSRC)	/* DAV:bind */
#define DACL_UNBIND	(DACL_RMCOL\
			 |DACL_RMRSRC)	/* DAV:unbind */
#define DACL_WRITE	(DACL_WRITECONT\
			 |DACL_WRITEPROPS\
			 |DACL_BIND\
			 |DACL_UNBIND)	/* DAV:write */
#define DACL_ALL	(DACL_READ\
			 |DACL_WRITE\
			 |DACL_ADMIN)	/* DAV:all */

/* CalDAV (RFC 4791) privileges */
#define DACL_READFB	ACL_USER9	/* CALDAV:read-free-busy
					   (implicit if user has DAV:read) */

/* Path namespaces */
enum {
    URL_NS_DEFAULT = 0,
    URL_NS_PRINCIPAL,
    URL_NS_CALENDAR,
    URL_NS_ADDRESSBOOK,
    URL_NS_RSS
};

/* Bitmask of features/methods to allow, based on URL */
enum {
    ALLOW_READ =	(1<<0),
    ALLOW_WRITE =	(1<<1),
    ALLOW_DAV =		(1<<2),
    ALLOW_CAL =		(1<<3),
    ALLOW_CARD =	(1<<4),
    ALLOW_ALL =		0xff
};

/* Request target context */
struct request_target_t {
    char path[MAX_MAILBOX_PATH+1]; /* working copy of URL path */
    unsigned namespace;		/* namespace of path */
    char *user;			/* ptr to owner of collection (NULL = shared) */
    size_t userlen;
    char *collection;		/* ptr to collection name */
    size_t collen;
    char *resource;		/* ptr to resource name */
    size_t reslen;
    unsigned long allow;	/* bitmask of allowed features/methods */
};

/* Auth challenge context */
struct auth_challenge_t {
    struct auth_scheme_t *scheme;	/* Selected AUTH scheme */
    const char *param;	 		/* Server challenge */
};

/* Meta-data for response body (payload & representation headers) */
struct resp_body_t {
    ulong len; 		/* Content-Length   */
    const char *enc;	/* Content-Encoding */
    const char *lang;	/* Content-Language */
    const char *loc;	/* Content-Location */
    const char *type;	/* Content-Type     */
    time_t lastmod;	/* Last-Modified    */
};

/* Transaction context */
struct transaction_t {
    const char *meth;			/* Method to be performed */
    unsigned flags;			/* Flags for this txn */
    struct request_target_t req_tgt;	/* Parsed target URL */
    hdrcache_t req_hdrs;    		/* Cached HTTP headers */
    struct buf req_body;		/* Buffered request body */
    struct auth_challenge_t auth_chal;	/* Authentication challenge */
    const char *loc;	    		/* Location: of resp representation */
    const char *etag;			/* ETag: of response representation */
    const char *errstr;			/* Error string */
    struct resp_body_t resp_body;	/* Response body meta-data */
};

typedef int (*method_proc_t)(struct transaction_t *txn);

struct namespace_t {
    unsigned id;		/* Namespace identifier */
    const char *prefix;		/* Prefix of URL path denoting namespace */
    unsigned need_auth;		/* Do we need to auth for this namespace? */
    unsigned long allow;	/* Bitmask of allowed features/methods */
    method_proc_t proc[];	/* Functions to perform HTTP methods.
				 * MUST be a function pointer for EACH method
				 * (or NULL if method not supported)
				 * listed in, and in the SAME ORDER in which
				 * they appear in, the http_methods[] array.
				 */
};

extern const struct namespace_t namespace_calendar;
extern const struct namespace_t namespace_principal;
extern const struct namespace_t namespace_rss;
extern const struct namespace_t namespace_default;


extern struct namespace httpd_namespace;

extern const char *http_statusline(long code);
extern int target_to_mboxname(struct request_target_t *req_tgt, char *mboxname);
extern void response_header(long code, struct transaction_t *txn);
extern void error_response(long code, struct transaction_t *txn);
extern void xml_response(long code, struct transaction_t *txn, xmlDocPtr xml);
extern int meth_options(struct transaction_t *txn);

#endif /* HTTPD_H */
