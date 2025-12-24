/* httpd_ws.h -WebSocket support functions */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

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

extern int ws_init(struct http_connection *conn, struct buf *serverinfo);

typedef int ws_data_callback(struct transaction_t *txn, enum wslay_opcode opcode,
                             struct buf *inbuf, struct buf *outbuf,
                             struct buf *logbuf);

extern int ws_start_channel(struct transaction_t *txn,
                            const char *sub_prot, ws_data_callback *data_cb);

extern void ws_add_resp_hdrs(struct transaction_t *txn);

extern void ws_input(struct transaction_t *txn);

extern void ws_send(struct transaction_t *txn, struct buf *outbuf);

#endif /* HTTP_WS_H */
