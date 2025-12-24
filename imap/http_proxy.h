/* http_proxy.h - HTTP proxy support functions */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef _HTTP_PROXY_H
#define _HTTP_PROXY_H

#include "proxy.h"
#include "http_h2.h"


extern struct protocol_t http_protocol;

extern void http_proto_host(hdrcache_t req_hdrs,
                            const char **proto, const char **host);
extern int http_pipe_req_resp(struct backend *be, struct transaction_t *txn);
extern int http_proxy_copy(struct backend *src_be, struct backend *dest_be,
                           struct transaction_t *txn);
extern int http_proxy_h2_connect(struct backend *be, struct transaction_t *txn);
extern int http_proxy_check_input(struct http_connection *conn,
                                  ptrarray_t *pipes,
                                  unsigned long timeout_sec);
extern long http_status_to_code(unsigned code);

#endif /* _HTTP_PROXY_H */
