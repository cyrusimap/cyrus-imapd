/* quic_ebpf.h - eBPF-based per-connection QUIC dispatch for master */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef MASTER_QUIC_EBPF_H
#define MASTER_QUIC_EBPF_H

#include <config.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/socket.h>

#include "master/master.h"
#include "master/quic/quic_cidlen.h"

#ifdef HAVE_LIBBPF

/**
 * Create a UDP socket bound to @p addr, a quic service's address, as a
 * member of that port's SO_REUSEPORT group, which the steering program
 * picks within.
 *
 * @param s           the service, for logging
 * @param addr        the service's address
 * @param addrlen     its length
 * @param rendezvous  for the service's rendezvous socket rather than a
 *                    connection's: also allow binding while the socket
 *                    it replaces is still bound, and size its receive
 *                    queue (quic_set_rcvbuf())
 * @return            the socket, or -1 (logged) on failure
 */
int quic_ebpf_socket(struct service *s, const struct sockaddr *addr,
                     socklen_t addrlen, bool rendezvous);

/* Allocate an index for a new connection's socket in s's steering
 * sockarray, filling in *index on success. Call once per connection,
 * before any quic_ebpf_add_conn() calls for it -- every CID in that
 * connection's pool shares the one index, since they all name the same
 * socket. Returns 0 on success, -1 if the steering map is exhausted. */
int quic_ebpf_add_sock(struct service *s, int sock, uint32_t *index);

/* Register cid -> the socket at index (from quic_ebpf_add_sock()) in
 * s's CID lookup map. Only the sockarray auto-cleans on close, so
 * quic_ebpf_del_conn() is required for every CID a connection
 * registered, once that connection ends. */
int quic_ebpf_add_conn(struct service *s, const uint8_t cid[QUIC_CIDLEN],
                       uint32_t index);
int quic_ebpf_del_conn(struct service *s, const uint8_t cid[QUIC_CIDLEN]);

/* Return index (from quic_ebpf_add_sock()) to s's free list. Call
 * once per connection, after its quic_ebpf_del_conn() calls and once
 * its socket has closed: the sockarray entry is already gone by then,
 * this only reclaims the index number. */
void quic_ebpf_del_sock(struct service *s, uint32_t index);

/* Undo quic_ebpf_init_service(): close the loaded bpf object and free
 * s->quic_ebpf_ctx. Call once per service at shutdown; a no-op if
 * quic_ebpf_init_service() never ran for s or already did. */
void quic_ebpf_shutdown_service(struct service *s);

/* Re-bind each not-yet-steered QUIC service's rendezvous socket to its
 * own address, now that master has dropped to the cyrus uid
 * (SO_REUSEPORT group membership requires an exact uid match across
 * every member), then call quic_ebpf_init_service() on the result.
 * Call right after quic_drop_privs(), and again after a reload that
 * may have added services: one already steered is skipped untouched,
 * so a reload neither rebinds a live socket nor attaches a second
 * program to it. A no-op if no quic services are configured. */
void quic_rebind_rendezvous_sockets(void);

/* These two bracket become_cyrus() (lib/util.c), which does the uid
 * change itself. A uid change would otherwise clear master's
 * capabilities, and a non-root process can't get them back, so the
 * keeping has to be armed beforehand:
 *
 *      quic_keep_privs();    // before
 *      become_cyrus();
 *      quic_drop_privs();    // after
 *
 * Both return 0 on success. Calling quic_drop_privs() without the
 * arming fails rather than silently running without the capabilities
 * the steering program needs. */
int quic_keep_privs(void);

/* Narrow to the capabilities steering needs for the life of master:
 *
 *   CAP_NET_BIND_SERVICE  runtime: bind each per-connection socket to
 *                         the privileged port, as the cyrus user, same
 *                         as every other service.
 *   CAP_BPF               runtime: the per-connection map updates that
 *                         steer a CID to its socket -- every bpf(2) call
 *                         needs it wherever unprivileged BPF is off, as
 *                         on a hardened kernel -- and also to load
 *                         cyr_quic_steer.bpf.o.
 *   CAP_PERFMON           load only: the verifier relaxation the
 *                         program's packet-pointer arithmetic needs.
 *   CAP_NET_ADMIN         attach only: SO_ATTACH_REUSEPORT_EBPF.
 *
 * Loading and attaching happen at startup and on any reload that adds a
 * QUIC service; the load/attach-only capabilities are kept for life
 * only because a dropped one can't be regained for the next reload.
 * quic_ebpf.c says exactly why loading needs each. CAP_SETUID/CAP_SETGID
 * go with everything else, so this can't be used to regain root. */
int quic_drop_privs(void);

#endif /* HAVE_LIBBPF */

#endif /* MASTER_QUIC_EBPF_H */
