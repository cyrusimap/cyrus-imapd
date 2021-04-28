/* httpd_ws.h -WebSocket support functions
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

#ifndef HTTP_WS_H
#define HTTP_WS_H

#include <config.h>

#ifdef HAVE_WSLAY
#include <wslay/wslay.h>

#else /* !HAVE_WSLAY */

enum wslay_opcode {
    WSLAY_TEXT_FRAME
};

#endif /* HAVE_WSLAY */


/* Supported WebSocket version for Upgrade */
#define WS_TOKEN         "websocket"
#define WS_VERSION       "13"

extern void ws_init(struct http_connection *conn, struct buf *serverinfo);

extern int ws_enabled();

typedef int ws_data_callback(enum wslay_opcode opcode,
                             struct buf *inbuf, struct buf *outbuf,
                             struct buf *logbuf, void **rock);

extern int ws_start_channel(struct transaction_t *txn,
                            const char *sub_prot, ws_data_callback *data_cb);

extern void ws_add_resp_hdrs(struct transaction_t *txn);

extern void ws_end_channel(void **ws_ctx, const char *msg);

extern void ws_input(struct transaction_t *txn);

#endif /* HTTP_WS_H */
