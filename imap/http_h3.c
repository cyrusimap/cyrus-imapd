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

#include "httpd.h"
#include "http_h3.h"

#if defined(HAVE_NGHTTP3) && defined(HAVE_NGTCP2) && defined(HAVE_QUIC_TLS)

#include <nghttp3/nghttp3.h>
#include <ngtcp2/ngtcp2.h>

HIDDEN int http3_enabled()
{
    return (1);
}

HIDDEN void http3_init(struct http_connection *conn __attribute__((unused)),
                       struct buf *serverinfo)
{
    buf_printf(serverinfo, " Nghttp3/%s", NGHTTP3_VERSION);
    buf_printf(serverinfo, " Ngtcp2/%s", NGTCP2_VERSION);
}

HIDDEN void http3_input(struct http_connection *conn)
{
    struct sockaddr_storage sfrom_storage;
    struct sockaddr *sfrom = (struct sockaddr *) &sfrom_storage;
    socklen_t sfromsiz = sizeof(struct sockaddr_storage);
    char buf[4096];
    ssize_t n;

    /* Simple echo server to get us started */
    n = recvfrom(conn->pin->fd, buf, sizeof(buf), 0, sfrom, &sfromsiz);
    if (n < 0) return;

    n = sendto(conn->pout->fd, buf, n, 0, sfrom, sfromsiz);

    return;
}
 
#else /* !HAVE_NGHTTP3 */

HIDDEN void http3_init(struct http_connection *conn __attribute__((unused)),
                       struct buf *serverinfo __attribute__((unused)))
{
}

HIDDEN int http3_enabled()
{
    return 0;
}

#endif /* HAVE_NGHTTP3 */
