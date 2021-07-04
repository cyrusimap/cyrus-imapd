/* quic.h - QUIC support functions
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

#ifndef QUIC_H
#define QUIC_H

#include <config.h>

#include "tls.h"
#include "util.h"

struct quic_context;

struct quic_app_context {
    void *conn;
    int (*open_conn)(void *conn);
    void (*close_conn)(void *conn);
    ssize_t (*read_stream)(void *conn, int64_t stream_id,
                           const uint8_t *src, size_t srclen, int fin);
    struct tls_alpn_t alpn_map[];
};

extern int quic_init(struct quic_context **ctx, struct quic_app_context *app);

extern int quic_input(struct quic_context *ctx, struct protstream *pin);

extern int quic_output(struct quic_context *ctx, int64_t stream_id, int fin,
                       const struct iovec *iov, int iovcnt, ssize_t *datalen);

extern void quic_close(struct quic_context *ctx);

extern void quic_shutdown(struct quic_context *ctx);

extern int quic_open_stream(void *conn, unsigned bidi,
                            int64_t *stream_id, void *stream_user_data);

extern const char *quic_version(void);

#endif /* QUIC_H */
