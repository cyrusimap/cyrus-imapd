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

#define QUIC_RELAY_KEYLEN (QUIC_EBPF_CIDLEN * 2 + 1)

/* The owning record for one live connection -- reachable via
 * quic_relay_conns under `key`, and optionally also via
 * quic_relay_aliases under `alias_key` (see quic_relay_add_alias()).
 * Never duplicated: unlike the eBPF backend's SOCKHASH, where two map
 * keys can cheaply point at the same kernel socket, our two tables
 * can't both independently own (and close()) the same `sock` -- so
 * there's one owning record per connection, found by either key. */
struct quic_relay_conn {
    int sock;
    int rendezvous_sock;
    struct sockaddr_storage peer;
    socklen_t peerlen;
    char key[QUIC_RELAY_KEYLEN];
    char alias_key[QUIC_RELAY_KEYLEN];
    bool has_alias;
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

/* Free conn and its alias entry (if any) and close its socket --
 * shared by quic_relay_del_conn()'s primary-removal path and
 * quic_relay_process_ready()'s EOF-driven cleanup, which both reach
 * this after already hash_del()ing conn out of quic_relay_conns
 * themselves (the caller, not this function, owns that step, since
 * one wants to report a miss and the other doesn't). */
static void quic_relay_free_conn(struct quic_relay_conn *conn)
{
    if (conn->has_alias) free(hash_del(conn->alias_key, &quic_relay_aliases));
    close(conn->sock);
    free(conn);
}

void quic_relay_init(void)
{
    /* hash_insert()/hash_lookup() do `hash % table->size` unconditionally
     * (lib/hash.c) -- a HASH_TABLE_INITIALIZER'd table (size == 0)
     * divides by zero on first use, so construct_hash_table() here is
     * mandatory, not an optimization. 256 is a plain guess at
     * concurrent quic connections; tables degrade gracefully (not
     * incorrectly) past their initial size, so it isn't a hard cap. */
    construct_hash_table(&quic_relay_conns, 256, 0);
    construct_hash_table(&quic_relay_aliases, 256, 0);
}

int quic_relay_add_conn(const uint8_t cid[QUIC_EBPF_CIDLEN], int sock,
                        int rendezvous_sock,
                        const struct sockaddr_storage *peer, socklen_t peerlen)
{
    struct quic_relay_conn *conn;
    char key[QUIC_RELAY_KEYLEN];

    quic_relay_bytes_to_hex(cid, QUIC_EBPF_CIDLEN, key);
    if (quic_relay_key_taken(key)) return -1;

    conn = xzmalloc(sizeof(*conn));
    conn->sock = sock;
    conn->rendezvous_sock = rendezvous_sock;
    memcpy(&conn->peer, peer, peerlen);
    conn->peerlen = peerlen;
    memcpy(conn->key, key, sizeof(key));

    hash_insert(key, conn, &quic_relay_conns);
    return 0;
}

int quic_relay_add_alias(const uint8_t primary_cid[QUIC_EBPF_CIDLEN],
                         const uint8_t cid[QUIC_EBPF_CIDLEN])
{
    char primary_key[QUIC_RELAY_KEYLEN], key[QUIC_RELAY_KEYLEN];
    struct quic_relay_conn *conn;

    quic_relay_bytes_to_hex(cid, QUIC_EBPF_CIDLEN, key);
    if (quic_relay_key_taken(key)) return -1;

    quic_relay_bytes_to_hex(primary_cid, QUIC_EBPF_CIDLEN, primary_key);
    conn = hash_lookup(primary_key, &quic_relay_conns);
    if (!conn) return -1;

    hash_insert(key, xstrdup(primary_key), &quic_relay_aliases);
    memcpy(conn->alias_key, key, sizeof(key));
    conn->has_alias = true;
    return 0;
}

int quic_relay_del_conn(const uint8_t cid[QUIC_EBPF_CIDLEN])
{
    char key[QUIC_RELAY_KEYLEN];
    char *alias_target;
    struct quic_relay_conn *conn;

    quic_relay_bytes_to_hex(cid, QUIC_EBPF_CIDLEN, key);

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
     * QUIC_EBPF_CIDLEN bytes -- anything else definitely isn't a
     * route we have. This is NOT a reason for the caller to skip
     * treating pkt as a possible new connection: a brand new
     * connection's client-chosen initial DCID can legitimately be any
     * length from 8 to 20 bytes, unrelated to the length we pick for
     * our own CIDs. */
    if (dcidlen != QUIC_EBPF_CIDLEN) return false;

    quic_relay_bytes_to_hex(dcid, QUIC_EBPF_CIDLEN, key);
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

    if (write(conn->sock, pkt, pktlen) < 0) {
        xsyslog_ev(LOG_ERR, "quic.relay.forward_failed");
    }
    return true;
}

struct quic_relay_fds_rock {
    fd_set *rfds;
    int *maxfd;
};

static void quic_relay_add_fds_cb(const char *key __attribute__((unused)),
                                  void *data, void *rock)
{
    struct quic_relay_conn *conn = (struct quic_relay_conn *) data;
    struct quic_relay_fds_rock *r = (struct quic_relay_fds_rock *) rock;

    FD_SET(conn->sock, r->rfds);
    if (conn->sock > *r->maxfd) *r->maxfd = conn->sock;
}

void quic_relay_add_fds(fd_set *rfds, int *maxfd)
{
    struct quic_relay_fds_rock rock = { rfds, maxfd };
    hash_enumerate(&quic_relay_conns, &quic_relay_add_fds_cb, &rock);
}

/* Backstop against a single select() tick somehow seeing more
 * connections finish at once than this -- vanishingly unlikely (it
 * would take this many simultaneous worker deaths), and any left over
 * just get caught on the next tick, since an EOF'd fd stays readable
 * until actually removed. */
#define QUIC_RELAY_MAX_CLOSED_PER_TICK 256

struct quic_relay_ready_rock {
    fd_set *rfds;
    char closed_keys[QUIC_RELAY_MAX_CLOSED_PER_TICK][QUIC_RELAY_KEYLEN];
    int nclosed;
};

static void quic_relay_process_ready_cb(const char *key __attribute__((unused)),
                                        void *data, void *rock)
{
    struct quic_relay_conn *conn = (struct quic_relay_conn *) data;
    struct quic_relay_ready_rock *r = (struct quic_relay_ready_rock *) rock;
    uint8_t buf[QUIC_PKT_BUFSIZE];
    ssize_t n;

    if (!FD_ISSET(conn->sock, r->rfds)) return;

    n = recv(conn->sock, buf, sizeof(buf), 0);
    if (n < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) {
        /* Transient -- select() said readable, but a signal or a
         * spurious wakeup got in the way. Try again next tick;
         * definitely not "the connection is done". */
        return;
    }
    if (n <= 0) {
        /* Worker exited (EOF, n == 0) or the socketpair genuinely
         * errored -- either way this connection is done; queue it for
         * removal (can't hash_del() safely while hash_enumerate() is
         * iterating). */
        if (r->nclosed < QUIC_RELAY_MAX_CLOSED_PER_TICK) {
            memcpy(r->closed_keys[r->nclosed++], conn->key,
                  sizeof(conn->key));
        }
        return;
    }

    if (sendto(conn->rendezvous_sock, buf, (size_t) n, 0,
              (struct sockaddr *) &conn->peer, conn->peerlen) < 0) {
        xsyslog_ev(LOG_ERR, "quic.relay.sendto_failed");
    }
}

void quic_relay_process_ready(fd_set *rfds)
{
    struct quic_relay_ready_rock rock;

    rock.rfds = rfds;
    rock.nclosed = 0;
    hash_enumerate(&quic_relay_conns, &quic_relay_process_ready_cb, &rock);

    for (int i = 0; i < rock.nclosed; i++) {
        struct quic_relay_conn *conn =
            hash_del(rock.closed_keys[i], &quic_relay_conns);
        if (conn) quic_relay_free_conn(conn);
    }
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
