/* quic_relay.h - userspace QUIC connection dispatch/relay for master */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef MASTER_QUIC_RELAY_H
#define MASTER_QUIC_RELAY_H

#include <config.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/select.h>
#include <sys/socket.h>

#include "master/quic/quic_parse.h"
#include "master/service.h"

/* Alternative to master/quic/quic_ebpf.c's eBPF-based dispatch -- see
 * quic_dispatch_connection() in master.c, which picks a backend via
 * quic_use_ebpf. Instead of the kernel steering packets straight to a
 * per-connection socket, master itself stays in the data path for a
 * proto="quic" connection's whole life, demultiplexing by Connection
 * ID in userspace and relaying datagrams to/from a
 * one-connection-per-worker httpd process over an AF_UNIX/SOCK_DGRAM
 * socketpair. The far end is handed to the worker exactly like the
 * eBPF backend's real UDP socket (via quic_send_handoff()), so
 * nothing downstream -- service.c, imap/quic.c, worker reuse -- needs
 * to know which backend dispatched a connection.
 *
 * Trade-off: no kernel/BPF/capability machinery at all -- master
 * drops privileges normally, retaining nothing -- but it now touches
 * every packet of every connection for its whole life, not just the
 * first one. */

/* One-time setup. Unlike quic_ebpf_init(), needs no elevated
 * privileges/capabilities -- safe to call after become_cyrus() (or
 * not at all, if have_quic_service is false). */
void quic_relay_init(void);

/* Register a brand new connection under cid (the SCID master chose
 * for it) -- mirrors quic_ebpf_add_conn()'s role in the eBPF backend.
 * sock is master's own end of the connection's socketpair (the far
 * end already handed to a worker); the caller still owns it --
 * quic_relay_del_conn()/quic_relay_process_ready()'s teardown closes
 * it, matching quic_ebpf_del_conn()'s contract. rendezvous_sock is the
 * real UDP socket to relay outgoing packets back out on; peer/peerlen
 * is the client's current address. Returns -1 (unregistered) if cid
 * is already taken -- shouldn't happen for a fresh random CID, but
 * checked for symmetry with quic_ebpf_add_conn()'s collision report. */
int quic_relay_add_conn(const uint8_t cid[QUIC_EBPF_CIDLEN], int sock,
                        int rendezvous_sock,
                        const struct sockaddr_storage *peer, socklen_t peerlen);

/* Register cid as an additional route to the connection already under
 * primary_cid -- see quic_dispatch_connection()'s comment on why (the
 * client's original DCID, so first-flight retransmits/bursts still
 * find this connection even though they're not addressed to our
 * chosen SCID). Returns -1 if cid is already registered, or
 * primary_cid isn't a real connection (shouldn't happen -- the caller
 * just created it). */
int quic_relay_add_alias(const uint8_t primary_cid[QUIC_EBPF_CIDLEN],
                         const uint8_t cid[QUIC_EBPF_CIDLEN]);

/* Remove cid -- works whether it's a primary registration (closes the
 * connection's socket and removes any alias pointing at it too) or an
 * alias (removes just the alias, leaving the primary and the
 * connection itself alone). Mirrors quic_ebpf_del_conn(), used
 * identically by quic_dispatch_connection()'s error-cleanup paths
 * regardless of which kind of cid it's cleaning up. Returns -1 if cid
 * isn't registered under either role. */
int quic_relay_del_conn(const uint8_t cid[QUIC_EBPF_CIDLEN]);

/* Look up dcid/dcidlen (primary or alias) among registered
 * connections; if found, relay pkt/pktlen to it -- updating its known
 * peer address first in case it changed (NAT rebinding, the same
 * "trust whoever sends the right CID" model as the eBPF backend's
 * kernel steering) -- and return true. Returns false if dcid isn't
 * known, so the caller treats pkt as a possible new connection. */
bool quic_relay_forward(const uint8_t *dcid, uint8_t dcidlen,
                        const uint8_t *pkt, size_t pktlen,
                        const struct sockaddr_storage *peer, socklen_t peerlen);

/* Add every registered connection's master-side socketpair fd to
 * rfds/maxfd for select() -- call every time through the main loop; a
 * no-op if nothing is registered. */
void quic_relay_add_fds(fd_set *rfds, int *maxfd);

/* After select(): relay anything a registered connection's worker
 * just sent back out its rendezvous socket to its peer; drop (close,
 * unregister) any connection whose worker has gone -- call every time
 * through the main loop; a no-op if nothing is registered. */
void quic_relay_process_ready(fd_set *rfds);

/* Close and unregister every connection -- call at shutdown. */
void quic_relay_shutdown(void);

#endif /* MASTER_QUIC_RELAY_H */
