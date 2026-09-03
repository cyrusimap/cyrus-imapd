/* http_h3.h - HTTP/3 (QUIC) support functions */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef HTTP_H3_H
#define HTTP_H3_H

#include <config.h>

#include "tls.h"
#include "util.h"

/* One QUIC connection at a time per "httpd -3" worker, same as every
 * other httpd worker -- master.c's quic_dispatch_connection() hands
 * each new one over, chosen via eBPF-based kernel steering, the same
 * way accept() does for TCP, so fd 0 always arrives already connected
 * to one client. A worker may be reused across many connections (see
 * master.c's idle-worker pool), but HTTP/3 plugs into
 * service_main()/cmdloop() the same way: no multiplexing, no
 * separate event loop, within a single connection.
 *
 * The QUIC transport itself (imap/quic.h) doesn't know HTTP/3 exists;
 * this maps nghttp3's request/response model onto it. */

/* Sets up everything HTTP/3 needs besides the TLS context -- the
 * nghttp3 callback table and ALPN map. (The TLS context itself is
 * httpd.c's job: tls_init() builds it, and already fatals before this
 * is ever called if that failed.) Fatals if built without ngtcp2/
 * nghttp3, since an "httpd -3" worker exists only to serve QUIC --
 * there's no fallback path to return control to. */
extern void http3_init(struct http_connection *conn, struct buf *serverinfo);

/* Append "h3=..." to the Alt-Svc header value being constructed. */
extern void http3_altsvc(struct buf *altsvc);

/* Establish the QUIC connection on fd 0 and handshake far enough to
 * process the relayed first Initial packet. ssl_ctx is the TLS context
 * httpd.c's tls_init() built. Called once per connection from
 * service_main(), in place of starttls()/h2's ALPN dance -- QUIC's TLS
 * handshake is intrinsic to the transport, not a separate step. Returns
 * 0 on success. */
extern int http3_start_session(struct http_connection *conn, SSL_CTX *ssl_ctx);

/* Called from cmdloop() whenever fd 0 is readable: reads and processes
 * exactly one QUIC datagram, then flushes any pending output. */
extern void http3_input(struct http_connection *conn);

/* Seconds until this connection's next ngtcp2 timer (loss detection,
 * idle timeout, etc.) needs servicing -- cmdloop() uses this instead of
 * blocking forever on input, since QUIC (unlike TCP) needs to act on
 * its own even when the peer sends nothing. Always returns a value
 * >= 1 once a session exists (ngtcp2 always has at least an idle
 * timeout armed). */
extern unsigned long http3_get_timeout(struct http_connection *conn);

/* Called from cmdloop() when http3_get_timeout()'s deadline arrives
 * with no input pending: services any due ngtcp2 timers and flushes
 * output. */
extern void http3_idle(struct http_connection *conn);

#endif /* HTTP_H3_H */
