/* httpd_h2.h -HTTP/2 support functions
 *
 * Copyright (c) 1994-2018 Carnegie Mellon University.  All rights reserved.
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

#ifndef HTTP_H2_H
#define HTTP_H2_H

#include <config.h>

#ifdef HAVE_NGHTTP2
#include <nghttp2/nghttp2.h>

#else /* !HAVE_NGHTTP2 */

#define NGHTTP2_PROTO_ALPN                 ""
#define NGHTTP2_CLEARTEXT_PROTO_VERSION_ID ""

#endif /* HAVE_NGHTTP2 */

#include "md5.h"
#include "util.h"

extern void http2_init(struct buf *serverinfo);

extern int http2_enabled();

extern void http2_done();

extern int http2_preface(struct http_connection *conn);

extern int http2_start_session(struct transaction_t *txn,
                               struct http_connection *conn);

extern void http2_end_session(void *http2_ctx);

extern void http2_input(struct transaction_t *txn);

extern void http2_begin_headers(struct transaction_t *txn);

extern void http2_add_header(struct transaction_t *txn,
                             const char *name, struct buf *value);

extern int http2_end_headers(struct transaction_t *txn, long code);

extern int http2_data_chunk(struct transaction_t *txn,
                            const char *data, unsigned datalen,
                            int last_chunk, MD5_CTX *md5ctx);

extern int32_t http2_get_streamid(void *http2_strm);

extern void http2_end_stream(void *http2_strm);

#endif /* HTTP_H2_H */
