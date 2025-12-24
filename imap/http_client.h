/* http_client.h - HTTP client-side support functions */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef _HTTP_CLIENT_H
#define _HTTP_CLIENT_H

#include "backend.h"
#include "spool.h"

/* Supported HTTP version */
#define HTTP2_VERSION    "HTTP/2"
#define HTTP_VERSION     "HTTP/1.1"

/* Context for reading request/response body */
struct body_t {
    unsigned char flags;                /* Disposition flags */
    unsigned char framing;              /* Message framing   */
    unsigned char te;                   /* Transfer-Encoding */
    unsigned max;                       /* Max allowed len   */
    unsigned long len;                  /* Content-Length    */
    struct buf payload;                 /* Payload           */
};

/* Message Framing flags */
enum {
    FRAMING_UNKNOWN = 0,
    FRAMING_HTTP2,
    FRAMING_LENGTH,
    FRAMING_CHUNKED,
    FRAMING_CLOSE
};

/* Transfer-Encoding flags (coding of response payload) */
enum {
    TE_NONE =           0,
    TE_DEFLATE =        (1<<0), /* Implies TE_CHUNKED as final coding */
    TE_GZIP =           (1<<1), /* Implies TE_CHUNKED as final coding */
    TE_CHUNKED =        (1<<2), /* MUST be last */
    TE_UNKNOWN =        0xff
};

/* http_read_body() flags */
enum {
    BODY_RESPONSE =     (1<<0), /* Response body, otherwise request */
    BODY_CONTINUE =     (1<<1), /* Expect:100-continue request */
    BODY_CLOSE =        (1<<2), /* Close-delimited response body */
    BODY_DECODE =       (1<<3), /* Decode any Content-Encoding */
    BODY_DISCARD =      (1<<4), /* Discard body (don't buffer or decode) */
    BODY_DONE =         (1<<5)  /* Body has been read */
};

/* Index into known HTTP methods - needs to stay in sync with array */
enum {
    METH_ACL = 0,
    METH_BIND,
    METH_CONNECT,
    METH_COPY,
    METH_DELETE,
    METH_GET,
    METH_HEAD,
    METH_LOCK,
    METH_MKCALENDAR,
    METH_MKCOL,
    METH_MOVE,
    METH_OPTIONS,
    METH_PATCH,
    METH_POST,
    METH_PROPFIND,
    METH_PROPPATCH,
    METH_PUT,
    METH_REPORT,
    METH_SEARCH,
    METH_TRACE,
    METH_UNBIND,
    METH_UNLOCK,

    METH_UNKNOWN,  /* MUST be last */
};


extern int is_mediatype(const char *pat, const char *type);
extern int http_parse_framing(int http2, hdrcache_t hdrs, struct body_t *body,
                              const char **errstr);
extern int http_read_headers(struct protstream *pin, int read_sep,
                             hdrcache_t *hdrs, const char **errstr);
extern int http_read_body(struct protstream *pin, hdrcache_t hdrs,
                          struct body_t *body, const char **errstr);
extern int http_read_response(struct backend *be, unsigned meth, unsigned *code,
                              hdrcache_t *hdrs, struct body_t *body,
                              const char **errstr);
extern long http_status_to_code(unsigned status);
extern int http_parse_auth_params(const char *params,
                                  const char **realm, unsigned int *realm_len,
                                  const char **sid, unsigned int *sid_len,
                                  const char **data, unsigned int *data_len);

#endif /* _HTTP_CLIENT_H */
