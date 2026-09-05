/* http_h3.h - HTTP/3 (QUIC) support functions */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef HTTP_H3_H
#define HTTP_H3_H

#include <config.h>

#include <stdbool.h>
#include <stdint.h>

#include "tls.h"
#include "util.h"

/* One QUIC connection at a time per proto="quic" httpd worker, same as
 * every other httpd worker: master.c's quic_dispatch_connection() hands each
 * one over the way accept() does for TCP, so fd 0 arrives already
 * dedicated to one client. Unlike accept()'s result it never names the
 * client -- eBPF's socket is deliberately unconnected (for migration),
 * the relay's is a socketpair to master -- so imap/quic.c tracks the
 * peer address itself. See docsrc/concepts/features/quic-dispatch.rst.
 * A worker may be reused across connections (master.c's idle-worker
 * pool), but HTTP/3 plugs into service_main()/cmdloop() like any other
 * protocol: no multiplexing, no separate event loop.
 *
 * The QUIC transport itself (imap/quic.h) doesn't know HTTP/3 exists;
 * this maps nghttp3's request/response model onto it. */

/* Once per worker: builds the QUIC TLS context into *ssl_ctx
 * (quic_init_tls_ctx()), adds the library versions to serverinfo, and
 * registers session teardown. Fatals if the context can't be built, or
 * if built without ngtcp2/nghttp3, since a proto="quic" worker exists
 * only to serve QUIC -- there's no fallback path to return control to. */
extern void http3_init(struct http_connection *conn, SSL_CTX **ssl_ctx,
                       struct buf *serverinfo);

/* Append "h3=..." to the Alt-Svc header value being constructed. */
extern void http3_altsvc(struct buf *altsvc);

/* Establish the QUIC connection on fd 0 and handshake far enough to
 * process the first Initial packet master already handed off (see the
 * top of this file). ssl_ctx is the TLS context http3_init() built.
 * Called once per connection from service_main(), in place of
 * starttls()/h2's ALPN dance -- QUIC's TLS handshake is intrinsic to
 * the transport, not a separate step. Returns 0 on success. */
extern int http3_start_session(struct http_connection *conn, SSL_CTX *ssl_ctx);

/* Called from cmdloop() whenever fd 0 is readable: reads and processes
 * exactly one QUIC datagram, then flushes any pending output. */
extern void http3_input(struct http_connection *conn);

/* Microseconds until this connection's next ngtcp2 timer (loss
 * detection, idle timeout, etc.) needs servicing -- cmdloop() uses this
 * instead of blocking forever on input, since QUIC (unlike TCP) needs to
 * act on its own even when the peer sends nothing. Always returns a
 * value >= 1 once a session exists (ngtcp2 always has at least an idle
 * timeout armed). */
extern unsigned long http3_get_timeout(struct http_connection *conn);

/* Called from cmdloop() when http3_get_timeout()'s deadline arrives
 * with no input pending: services any due ngtcp2 timers and flushes
 * output. */
extern void http3_idle(struct http_connection *conn);

/**
 * Report the traffic of conn's HTTP/3 connection, which never passes
 * through httpd's protstreams, for the audit log.
 *
 * @param conn       the connection
 * @param bytes_in   set to the bytes received, if there is a session
 * @param bytes_out  set to the bytes sent, if there is a session
 * @return           false, leaving both alone, if conn has no HTTP/3
 *                   session
 */
extern bool http3_traffic(struct http_connection *conn,
                          uint64_t *bytes_in, uint64_t *bytes_out);

#endif /* HTTP_H3_H */
