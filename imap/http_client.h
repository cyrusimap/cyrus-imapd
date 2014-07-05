/* http_client.h - HTTP client-side support functions
 *
 * Copyright (c) 1994-2014 Carnegie Mellon University.  All rights reserved.
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

#ifndef _HTTP_CLIENT_H
#define _HTTP_CLIENT_H

#include "backend.h"
#include "spool.h"

/* Supported HTTP version */
#define HTTP_VERSION	 "HTTP/1.1"
#define HTTP_VERSION_LEN 8

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

/* Transfer-Encoding flags (coding of response payload) */
enum {
    TE_NONE =		0,
    TE_DEFLATE =	(1<<0),	/* Implies TE_CHUNKED as final coding */
    TE_GZIP =		(1<<1),	/* Implies TE_CHUNKED as final coding */
    TE_CHUNKED =	(1<<2), /* MUST be last */
    TE_UNKNOWN =	0xff
};

/* http_read_body() flags */
enum {
    BODY_RESPONSE =	(1<<0),	/* Response body, otherwise request */
    BODY_CONTINUE =	(1<<1),	/* Expect:100-continue request */
    BODY_CLOSE =	(1<<2),	/* Close-delimited response body */
    BODY_DECODE = 	(1<<3),	/* Decode any Content-Encoding */
    BODY_DISCARD =	(1<<4),	/* Discard body (don't buffer or decode) */
    BODY_DONE =		(1<<5)	/* Body has been read */
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


extern int is_mediatype(const char *pat, const char *type);
extern int http_parse_framing(hdrcache_t hdrs, struct body_t *body,
			      const char **errstr);
extern int http_read_body(struct protstream *pin, struct protstream *pout,
			  hdrcache_t hdrs, struct body_t *body,
			  const char **errstr);
extern int http_read_response(struct backend *be, unsigned meth, unsigned *code,
			      const char **statline, hdrcache_t *hdrs,
			      struct body_t *body, const char **errstr);

#endif /* _HTTP_CLIENT_H */
