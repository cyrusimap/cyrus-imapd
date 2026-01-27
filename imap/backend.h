/* backend.h - IMAP server proxy for Cyrus Murder */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

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
    SSL *tlsconn;
    SSL_SESSION *tlssess;

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

#define CAPA(s, c) ((s) ? (s)->capability & (c) : 0)

#endif /* _INCLUDED_BACKEND_H */
