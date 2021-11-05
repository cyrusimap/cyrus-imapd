/* backend.h -- IMAP server proxy for Cyrus Murder
 *
 * Copyright (c) 1994-2008 Carnegie Mellon University.  All rights reserved.
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
 */

#ifndef _INCLUDED_BACKEND_H
#define _INCLUDED_BACKEND_H

#include "global.h"
#include "mboxlist.h"
#include "prot.h"
#include "protocol.h"
#include "tls.h"

/* Functionality to bring up/down connections to backend servers */

struct backend_cap_params {
    unsigned long capa;
    char *params;       /* each BAR from FOO=BAR, in order, space separated */
};

struct backend {
    char hostname[MAX_PARTITION_LEN];
    char banner[2048];
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
    sasl_callback_t *sasl_cb;
    sasl_ssf_t ext_ssf;
#ifdef HAVE_SSL
    SSL *tlsconn;
    SSL_SESSION *tlssess;
#endif /* HAVE_SSL */

    unsigned long capability;
    int num_cap_params;
    struct backend_cap_params *cap_params;

    struct buf last_result;
    struct protstream *in; /* from the be server to me, the proxy */
    struct protstream *out; /* to the be server */
};

/* if cache is NULL, returns a new struct backend, otherwise returns
 * cache on success (and returns NULL on failure, but leaves cache alone) */
struct backend *backend_connect(struct backend *cache, const char *server,
                                struct protocol_t *prot, const char *userid,
                                sasl_callback_t *cb, const char **auth_status,
                                int logfd);

/* returns a new struct backend, where the infd and outfd file descriptors
 * are used to open the backend's 'in' and 'out' protstreams. Note that piped
 * backends do not support authentication */
struct backend *backend_connect_pipe(int infd, int outfd, struct protocol_t *prot,
                                     int do_tls, int logfd);

int backend_starttls(   struct backend *s,
                        struct tls_cmd_t *tls_cmd,
                        const char *c_cert_file,
                        const char *c_key_file);

int backend_ping(struct backend *s, const char *userid);
void backend_disconnect(struct backend *s);
char *intersect_mechlists(char *config, char *server);
char *backend_get_cap_params(const struct backend *, unsigned long capa);

int backend_version(struct backend *);
int backend_supports_sieve_mailbox(struct backend *);

#define CAPA(s, c) ((s)->capability & (c))

#endif /* _INCLUDED_BACKEND_H */
