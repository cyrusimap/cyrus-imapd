/* backend.h -- IMAP server proxy for Cyrus Murder
 *
 * Copyright (c) 1998-2003 Carnegie Mellon University.  All rights reserved.
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

/* $Id: backend.h,v 1.7.2.7 2006/01/17 20:15:20 murch Exp $ */

#ifndef _INCLUDED_BACKEND_H
#define _INCLUDED_BACKEND_H

#include "global.h"
#include "mboxlist.h"
#include "prot.h"
#include "protocol.h"
#include "tls.h"

/* Functionality to bring up/down connections to backend servers */

struct backend {
    char hostname[MAX_PARTITION_LEN];
    struct sockaddr_storage addr;
    int sock;

    /* protocol we're speaking */
    struct protocol_t *prot;

    /* service-specific context */
    void *context;

    /* only used by imapd and nntpd */
    struct protstream *clientin; /* input stream from client to proxy */
    struct backend **current, **inbox; /* pointers to current/inbox be ptrs */
    struct prot_waitevent *timeout; /* event for idle timeout */

    sasl_conn_t *saslconn;
#ifdef HAVE_SSL
    SSL *tlsconn;
    SSL_SESSION *tlssess;
#endif /* HAVE_SSL */

    unsigned long capability;

    struct buf last_result;
    struct protstream *in; /* from the be server to me, the proxy */
    struct protstream *out; /* to the be server */
};

/* if cache is NULL, returns a new struct backend, otherwise returns
 * cache on success (and returns NULL on failure, but leaves cache alone) */
struct backend *backend_connect(struct backend *cache, const char *server,
				struct protocol_t *prot, const char *userid,
				sasl_callback_t *cb, const char **auth_status);
int backend_ping(struct backend *s);
void backend_disconnect(struct backend *s);

#define CAPA(s, c) ((s)->capability & (c))

#endif /* _INCLUDED_BACKEND_H */
