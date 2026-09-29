/* tls.h - STARTTLS helper functions for imapd */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */
/* Based upon Lutz Jaenicke's TLS patches for postfix */

#ifndef INCLUDED_TLS_H
#define INCLUDED_TLS_H

/* is tls enabled? */
int tls_enabled(void);

/* is starttls enabled? */
int tls_starttls_enabled(void);

/* name of the SSL/TLS sessions database */
#define FNAME_TLSSESSIONS "/tls_sessions.db"

#define MAX_TLS_ALPN_ID (15)
struct tls_alpn_t {
    char id[MAX_TLS_ALPN_ID + 1];
    unsigned (*check_availability)(void *rock);
    void *rock;
};

#include <stdbool.h>

#include <openssl/ssl.h>

#include "global.h" /* for saslprops_t */

/* init tls */
int tls_init_serverengine(const char *ident,
                          int verifydepth, /* depth to verify */
                          int askcert,     /* 1 = client auth */
                          SSL_CTX **ret);

int tls_init_clientengine(int verifydepth,
                          const char *var_server_cert,
                          const char *var_server_key);

/* start tls negotiation */
int tls_start_servertls(int readfd, int writefd, int timeout,
                        struct saslprops_t *saslprops,
                        const struct tls_alpn_t *alpn_map,
                        SSL **ret);

/* Accept TLS 1.3 early data on connections tls_start_servertls_early()
 * starts.  Since early data can be replayed, each session can then be
 * resumed only once.  Returns false if sessions aren't being cached. */
bool tls_enable_early_data(void);

/* tls_start_servertls() on the fds of pin and pout, which accepts early
 * data if enabled: it then returns with the handshake still open and the
 * first of it in pin, which must not have read anything yet.  pin reads
 * the rest, then finishes the handshake, so SSL_is_init_finished() is 0
 * exactly while pin is handing out early data. */
int tls_start_servertls_early(struct protstream *pin,
                              struct protstream *pout, int timeout,
                              struct saslprops_t *saslprops,
                              const struct tls_alpn_t *alpn_map,
                              SSL **ret);

int tls_start_clienttls(int readfd, int writefd,
                        int *layerbits, char **authid,
                        const struct tls_alpn_t *alpn_map,
                        SSL **ret, SSL_SESSION **sess);

/* query which (if any) ALPN protocol was chosen
 * caller must free the returned string
 */
char *tls_get_alpn_protocol(const SSL *conn);

/* reset tls */
int tls_reset_servertls(SSL **conn);

/* shutdown/cleanup tls */
int tls_shutdown_serverengine(void);

/* remove expired sessions from the external cache */
int tls_prune_sessions(void);

/* fill string buffer with info about tls connection */
int tls_get_info(SSL *conn, char *buf, size_t len);

#endif /* INCLUDED_TLS_H */
