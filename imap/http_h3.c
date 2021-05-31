/* http_h3.c - HTTP/3 support functions
 *
 * Copyright (c) 1994-2021 Carnegie Mellon University.  All rights reserved.
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

#include <sysexits.h>
#include <syslog.h>

#include "httpd.h"
#include "http_h3.h"
#include "quic.h"

/* generated headers are not necessarily in current directory */
#include "imap/http_err.h"

#ifdef HAVE_NGHTTP3

#include <nghttp3/nghttp3.h>

static const struct tls_alpn_t http3_alpn_map[] = {
    { "h3",    NULL, NULL },
    { "h3-32", NULL, NULL },
    { "h3-29", NULL, NULL },
    { NULL,    NULL, NULL }
};

HIDDEN int http3_init(struct http_connection *conn __attribute__((unused)),
                      struct buf *serverinfo)
{
    buf_printf(serverinfo, " Nghttp3/%s", NGHTTP3_VERSION);

    return quic_init(http3_alpn_map, serverinfo);
}

HIDDEN void http3_input(struct http_connection *conn)
{
    quic_input(conn);
}
 
#else /* !HAVE_NGHTTP3 */

HIDDEN int http3_init(struct http_connection *conn __attribute__((unused)),
                      struct buf *serverinfo __attribute__((unused)))
{
    return HTTP_NOT_IMPLEMENTED;
}

HIDDEN void http3_input(struct transaction_t *txn __attribute__((unused)))
{
    fatal("http3_input() called, but no Nghttp3", EX_SOFTWARE);
}

#endif /* HAVE_NGHTTP3 */
