/* httpd_h2.h -HTTP/2 support functions */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef HTTP_H2_H
#define HTTP_H2_H

#include <config.h>

#ifdef HAVE_NGHTTP2
#include <nghttp2/nghttp2.h>
#endif

#include "util.h"

#define HTTP2_CLEARTEXT_ID  "h2c"

extern int http2_init(struct http_connection *conn, struct buf *serverinfo);

extern void http2_altsvc(struct buf *altsvc);

extern int http2_preface(struct http_connection *conn);

extern int http2_start_session(struct transaction_t *txn,
                               struct http_connection *conn);

extern void http2_input(struct http_connection *conn);

#endif /* HTTP_H2_H */
