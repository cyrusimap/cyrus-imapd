/* quic_relay.h - userspace QUIC connection dispatch/relay for master */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef MASTER_QUIC_RELAY_H
#define MASTER_QUIC_RELAY_H

#include <config.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>

#include "master/service.h"

/* Userspace relay backend for QUIC dispatch -- see "Userspace relay"
 * in quic-dispatch.rst for what it is and why. Needs no elevated
 * privileges at all, but every packet a client sends passes through
 * master for its whole life, not just the first one. Outgoing packets
 * don't: workers send those themselves (see send_fd in
 * quic_handoff.h).
 *
 * master never reads from a connection's socketpair, and so never
 * waits on one: a connection is unregistered when its worker reports
 * itself idle or is reaped, the same ways every other Cyrus service's
 * children are accounted for. */

/* Construct the relay's tables. Idempotent, so master can call it
 * every time a quic service appears in a config read rather than only
 * at startup -- one can first appear at a reload. */
void quic_relay_init(void);

/* Register a brand new connection under cid (the SCID master chose
 * for it). sock is master's own end
 * of the connection's socketpair (the far end already handed to a
 * worker); the caller still owns it -- quic_relay_del_conn() closes
 * it. peer/peerlen is the client's current address. Returns -1 if cid
 * is already taken. */
int quic_relay_add_conn(const uint8_t cid[QUIC_CIDLEN], int sock,
                        const struct sockaddr_storage *peer, socklen_t peerlen);

/* Register cid as an additional route to the connection already under
 * primary_cid -- see "A spare CID pool for future connection
 * migration" in quic-dispatch.rst for what this is used for. Returns
 * -1 if cid is already registered, primary_cid isn't a real
 * connection, or the connection already has as many aliases as it can
 * hold. */
int quic_relay_add_alias(const uint8_t primary_cid[QUIC_CIDLEN],
                         const uint8_t cid[QUIC_CIDLEN]);

/* Remove cid -- works whether it's a primary registration (closes the
 * connection's socket and removes any alias pointing at it too) or an
 * alias (removes just the alias, leaving the primary alone). Returns
 * -1 if cid isn't registered under either role. */
int quic_relay_del_conn(const uint8_t cid[QUIC_CIDLEN]);

/* Look up dcid/dcidlen (primary or alias); if found, relay pkt/pktlen
 * to it, prefixed with a struct quic_relay_pkt_hdr carrying its
 * current peer address (updated first if it changed -- see "Tracking
 * a moving peer address" in quic-dispatch.rst), and return true.
 * Returns false if dcid isn't known, so the caller treats pkt as a
 * possible new connection. */
bool quic_relay_forward(const uint8_t *dcid, uint8_t dcidlen,
                        const uint8_t *pkt, size_t pktlen,
                        const struct sockaddr_storage *peer, socklen_t peerlen);

/* Close and unregister every connection -- call at shutdown. */
void quic_relay_shutdown(void);

#endif /* MASTER_QUIC_RELAY_H */
