/* tls.h - STARTTLS helper functions for imapd
 * Tim Martin
 * 9/21/99
 *
 *  Based upon Lutz Jaenicke's TLS patches for postfix
 *
 * Copyright (c) 1999-2000 Carnegie Mellon University.  All rights reserved.
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
 *    prior written permission. For permission or any other legal
 *    details, please contact  
 *      Office of Technology Transfer
 *      Carnegie Mellon University
 *      5000 Forbes Avenue
 *      Pittsburgh, PA  15213-3890
 *      (412) 268-4387, fax: (412) 268-7395
 *      tech-transfer@andrew.cmu.edu
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
 */

#ifndef INCLUDED_TLS_H
#define INCLUDED_TLS_H

/* is tls enabled? */
int tls_enabled(const char *ident);

#define CONFIG_DB_TLS (&cyrusdb_db3_nosync)

#ifdef HAVE_SSL

#include <openssl/ssl.h>

/* init tls */
int tls_init_serverengine(const char *ident,
			  int verifydepth, /* depth to verify */
			  int askcert,     /* 1 = client auth */
			  int requirecert, /* 1 = require client auth */
			  int tlsonly);

/* start tls negotiation */
int tls_start_servertls(int readfd, int writefd, 
			int *layerbits, char **authid, SSL **ret);

/* reset tls */
int tls_reset_servertls(SSL **conn);

/* shutdown/cleanup tls */
int tls_shutdown_serverengine(void);

/* remove expired sessions from the external cache */
int tls_prune_sessions(void);

/* fill string buffer with info about tls connection */
int tls_get_info(SSL *conn, char *buf, size_t len);

#endif /* HAVE_SSL */

#endif /* INCLUDED_TLS_H */
