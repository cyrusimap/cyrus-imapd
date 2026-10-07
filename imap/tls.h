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
#include <stdint.h>

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

/**
 * Create a server SSL_CTX with the settings every Cyrus server context
 * shares (PRNG seeding, info and SNI callbacks, the tls_eccurve group),
 * for a caller to specialise, as tls_init_serverengine() does for TCP
 * and quic_init_tls_ctx() for QUIC.  Does OpenSSL's library-wide init
 * itself, so it needn't follow any other tls_*() call.
 *
 * @param tag  names the context in log messages
 * @return     a new SSL_CTX, or NULL (logged) on failure
 */
SSL_CTX *tls_new_serverctx(const char *tag);

/**
 * Load a certificate and its private key into ctx.  Both may be in one
 * file, and each argument may name two files separated by a comma for a
 * second certificate and key (e.g. RSA and ECDSA).  With no cert_file,
 * leave ctx as it is.
 *
 * @param ctx        the context to load into
 * @param cert_file  PEM certificate (chain) file(s), or NULL
 * @param key_file   PEM private key file(s); NULL means cert_file
 * @return           1 on success (or nothing to do), 0 (logged) on failure
 */
int tls_set_cert_stuff(SSL_CTX *ctx, const char *cert_file,
                       const char *key_file);

/**
 * Keep a server context's sessions in the session database shared by
 * every process (tls_sessions_db_path), for tls_session_timeout, under
 * stateful tickets that just name a stored session.
 * tls_init_serverengine() does this for its own context.
 *
 * @param ctx    a server context
 * @param ident  session ID context; sessions resume only under the same one
 * @return       false if tls_session_timeout is 0, so no sessions are kept
 */
bool tls_set_session_db(SSL_CTX *ctx, const char *ident);

/* How much early data a TCP client may send: one TLS record */
#define TLS_MAX_EARLY_DATA (16384)

/**
 * Let a server context that keeps its sessions in the session database
 * (see tls_set_session_db()) accept TLS 1.3 early data.  Early data can
 * be replayed, so each session can then be resumed only once: the
 * lookup removes it in the same transaction that reads it, which makes
 * early data replay-safe across processes.  OpenSSL's own anti-replay
 * check, which needs its in-process cache, is turned off.  For
 * tls_init_serverengine()'s context, tls_start_servertls_early() then
 * reads early data.
 *
 * @param ctx  a server context
 * @param max  the most early data a client may send (and the
 *             max_early_data_size its tickets advertise)
 * @return     false if ctx doesn't keep sessions in the database
 */
bool tls_enable_early_data(SSL_CTX *ctx, uint32_t max);

/* Install (or, if alpn_map is empty/NULL, clear) the server-side ALPN
 * selection callback on ctx. */
void tls_set_alpn_map(SSL_CTX *ctx, const struct tls_alpn_t *alpn_map);

/* start tls negotiation */
int tls_start_servertls(int readfd, int writefd, int timeout,
                        struct saslprops_t *saslprops,
                        const struct tls_alpn_t *alpn_map,
                        SSL **ret);

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
