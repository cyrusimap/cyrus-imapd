/* quic_relay.c - userspace QUIC connection dispatch/relay for master */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>

#include <errno.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/socket.h>

#include "master/quic/quic_relay.h"

#include "lib/hash.h"
#include "lib/util.h"
#include "lib/xmalloc.h"

#define QUIC_RELAY_KEYLEN (QUIC_CIDLEN * 2 + 1)


/* The owning record for one live connection -- reachable via
 * quic_relay_conns under `key`, and optionally also via
 * quic_relay_aliases under any of `alias_keys[0..nalias-1]` (see
 * quic_relay_add_alias()). Never duplicated: the two tables can't
 * both independently own the same `sock`, so there's one owning
 * record per connection, found by any of its keys. alias_keys is sized for the client's
 * original DCID plus every spare CID in the pool (QUIC_CID_POOL_SIZE,
 * quic_handoff.h). */
struct quic_relay_conn {
    int sock;
    struct sockaddr_storage peer;
    socklen_t peerlen;
    char key[QUIC_RELAY_KEYLEN];
    char alias_keys[QUIC_CID_POOL_SIZE][QUIC_RELAY_KEYLEN];
    uint8_t nalias;
};

/* key(cid) -> struct quic_relay_conn * (owning). */
static hash_table quic_relay_conns = HASH_TABLE_INITIALIZER;
/* key(cid) -> xstrdup()'d key into quic_relay_conns above (not owning
 * -- just a redirect). */
static hash_table quic_relay_aliases = HASH_TABLE_INITIALIZER;

static void quic_relay_bytes_to_hex(const uint8_t *data, size_t len, char *out)
{
    static const char hexdigits[] = "0123456789abcdef";

    for (size_t i = 0; i < len; i++) {
        out[i*2]   = hexdigits[data[i] >> 4];
        out[i*2+1] = hexdigits[data[i] & 0xf];
    }
    out[len*2] = '\0';
}

/* True if key is already registered, as either a primary connection
 * or an alias -- the collision check both quic_relay_add_conn() and
 * quic_relay_add_alias() need before inserting a new key. */
static bool quic_relay_key_taken(const char *key)
{
    return hash_lookup(key, &quic_relay_conns) ||
           hash_lookup(key, &quic_relay_aliases);
}

/* Free conn, every alias entry it has, and its socket. The caller
 * hash_del()s conn out of quic_relay_conns first -- that step is
 * theirs, not this function's. */
static void quic_relay_free_conn(struct quic_relay_conn *conn)
{
    for (int i = 0; i < conn->nalias; i++)
        free(hash_del(conn->alias_keys[i], &quic_relay_aliases));
    close(conn->sock);
    free(conn);
}

void quic_relay_init(void)
{
    /* Mandatory, not an optimization: on a HASH_TABLE_INITIALIZER'd
     * table lib/hash.c's table_index() shifts by (64 - size_log2) with
     * size_log2 == 0 -- undefined, and in practice an unreduced index
     * into a NULL bucket array, so the first hash_insert() crashes.
     * 256 is a plain guess at concurrent quic connections; tables
     * degrade gracefully (not incorrectly) past their initial size, so
     * it isn't a hard cap.
     *
     * Idempotent: master calls this whenever a quic service first
     * appears in a config read, which is every reload that has one. */
    if (hash_constructed(&quic_relay_conns)) return;

    construct_hash_table(&quic_relay_conns, 256, 0);
    construct_hash_table(&quic_relay_aliases, 256, 0);
}

int quic_relay_add_conn(const uint8_t cid[QUIC_CIDLEN], int sock,
                        const struct sockaddr_storage *peer, socklen_t peerlen)
{
    struct quic_relay_conn *conn;
    char key[QUIC_RELAY_KEYLEN];

    quic_relay_bytes_to_hex(cid, QUIC_CIDLEN, key);
    if (quic_relay_key_taken(key)) return -1;

    conn = xzmalloc(sizeof(*conn));
    conn->sock = sock;
    memcpy(&conn->peer, peer, peerlen);
    conn->peerlen = peerlen;
    memcpy(conn->key, key, sizeof(key));

    hash_insert(key, conn, &quic_relay_conns);
    return 0;
}

int quic_relay_add_alias(const uint8_t primary_cid[QUIC_CIDLEN],
                         const uint8_t cid[QUIC_CIDLEN])
{
    char primary_key[QUIC_RELAY_KEYLEN], key[QUIC_RELAY_KEYLEN];
    struct quic_relay_conn *conn;

    quic_relay_bytes_to_hex(cid, QUIC_CIDLEN, key);
    if (quic_relay_key_taken(key)) return -1;

    quic_relay_bytes_to_hex(primary_cid, QUIC_CIDLEN, primary_key);
    conn = hash_lookup(primary_key, &quic_relay_conns);
    if (!conn || conn->nalias >= QUIC_CID_POOL_SIZE) return -1;

    hash_insert(key, xstrdup(primary_key), &quic_relay_aliases);
    memcpy(conn->alias_keys[conn->nalias++], key, sizeof(key));
    return 0;
}

int quic_relay_del_conn(const uint8_t cid[QUIC_CIDLEN])
{
    char key[QUIC_RELAY_KEYLEN];
    char *alias_target;
    struct quic_relay_conn *conn;

    quic_relay_bytes_to_hex(cid, QUIC_CIDLEN, key);

    alias_target = hash_del(key, &quic_relay_aliases);
    if (alias_target) {
        free(alias_target);
        return 0;
    }

    conn = hash_del(key, &quic_relay_conns);
    if (!conn) return -1;

    quic_relay_free_conn(conn);
    return 0;
}

bool quic_relay_forward(const uint8_t *dcid, uint8_t dcidlen,
                        const uint8_t *pkt, size_t pktlen,
                        const struct sockaddr_storage *peer, socklen_t peerlen)
{
    char key[QUIC_RELAY_KEYLEN];
    struct quic_relay_conn *conn;

    /* Every cid we ever register (primary or alias) is exactly
     * QUIC_CIDLEN bytes -- anything else definitely isn't a
     * route we have. This is NOT a reason for the caller to skip
     * treating pkt as a possible new connection: a brand new
     * connection's client-chosen initial DCID can legitimately be any
     * length from 8 to 20 bytes, unrelated to the length we pick for
     * our own CIDs. */
    if (dcidlen != QUIC_CIDLEN) return false;

    quic_relay_bytes_to_hex(dcid, QUIC_CIDLEN, key);
    conn = hash_lookup(key, &quic_relay_conns);
    if (!conn) {
        char *alias_target = hash_lookup(key, &quic_relay_aliases);
        if (!alias_target) return false;
        conn = hash_lookup(alias_target, &quic_relay_conns);
        if (!conn) return false;    /* shouldn't happen: stale alias */
    }

    if (peerlen != conn->peerlen || memcmp(peer, &conn->peer, peerlen)) {
        memcpy(&conn->peer, peer, peerlen);
        conn->peerlen = peerlen;
    }

    {
        struct quic_relay_pkt_hdr hdr = { conn->peer, conn->peerlen };
        struct iovec iov[2] = {
            { &hdr, sizeof(hdr) },
            { (void *) pkt, pktlen },
        };
        struct msghdr msg = { .msg_iov = iov, .msg_iovlen = 2 };

        /* MSG_DONTWAIT: a worker that stopped reading must not block
         * master's event loop. Dropping the datagram is what the
         * client's own loss recovery already handles.
         * MSG_NOSIGNAL: a worker that died must not kill master. */
        if (sendmsg(conn->sock, &msg, MSG_DONTWAIT | MSG_NOSIGNAL) < 0) {
            xsyslog_ev(LOG_ERR, "quic.relay.forward_failed");
        }
    }
    return true;
}

static void quic_relay_shutdown_cb(const char *key __attribute__((unused)),
                                   void *data,
                                   void *rock __attribute__((unused)))
{
    struct quic_relay_conn *conn = (struct quic_relay_conn *) data;
    close(conn->sock);
    free(conn);
}

void quic_relay_shutdown(void)
{
    hash_enumerate(&quic_relay_conns, &quic_relay_shutdown_cb, NULL);
    free_hash_table(&quic_relay_conns, NULL);
    free_hash_table(&quic_relay_aliases, free);
}
