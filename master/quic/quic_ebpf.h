/* quic_ebpf.h - eBPF-based per-connection QUIC dispatch for master */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef MASTER_QUIC_EBPF_H
#define MASTER_QUIC_EBPF_H

#include <config.h>
#include <stdint.h>
#include <stddef.h>

#include "master/service.h"
#include "master/quic/quic_parse.h"

#ifdef HAVE_LIBBPF

/* Load master/quic/cyr_quic_steer.bpf.o and attach it to the TC
 * ingress hook of every interface in ifnames (a whitespace-separated
 * list, e.g. "lo eth0") -- one shared program/maps, multiple
 * attachment points. If ifnames is NULL/empty, auto-discover every
 * interface the host has (via if_nameindex()) instead, skipping (not
 * failing on) any that won't attach -- an explicit list, by contrast,
 * requires every named interface to succeed, or the whole call fails
 * and unwinds via quic_ebpf_shutdown(): a typo here should be loud,
 * not silently drop QUIC dispatch on one network.
 *
 * Must be called while master is still fully root (TC attach needs
 * CAP_NET_ADMIN) -- before quic_drop_privs(), and before any
 * quic_ebpf_add_port() calls (they need the map this opens). Call
 * once regardless of interface/service count: everything shares this
 * one program, disambiguated by port (quic_ebpf_add_port(),
 * quic_ebpf_set_fallback()), not by which interface a packet arrived
 * on. Returns 0 on success. */
int quic_ebpf_init(const char *ifnames);

/* Register port (host byte order) as one cyr_quic_steer should steer
 * -- i.e. one a proto="quic" service is actually listening on.
 * Without this, steer() leaves that port's packets to ordinary kernel
 * socket lookup, which breaks down once a per-connection socket joins
 * the port's SO_REUSEPORT group (see quic_ebpf_set_fallback()). Safe
 * to call redundantly (e.g. a service's ipv4/ipv6 Services[] entries
 * sharing one port) and only after quic_ebpf_init(). */
int quic_ebpf_add_port(uint16_t port);

/* Undo quic_ebpf_init(): detach cyr_quic_steer from every interface it
 * attached to, destroying each one's clsact qdisc, then close the
 * loaded bpf object (program and maps, shared across all of them).
 * Without this, the TC program and steering map survive master's exit
 * on every one of those interfaces -- so the next master instance
 * finds stale filters (from a dead process's meaningless map)
 * fighting its fresh ones, doubling up on every packet. Needs
 * CAP_NET_ADMIN, which quic_drop_privs() retains for exactly this.
 * Call once at shutdown; a no-op if quic_ebpf_init() never ran or
 * already did. */
int quic_ebpf_shutdown(void);

/* Insert/remove a per-connection socket in the steering map, keyed by
 * its QUIC_EBPF_CIDLEN-byte server-chosen CID. Safe to call after
 * quic_drop_privs(): these just use the map fd quic_ebpf_init()
 * already opened while root; no capability needed per-call.
 *
 * quic_ebpf_del_conn() is deliberately unused in the steady-state
 * lifecycle: closing a SOCKHASH-member socket removes its map entry
 * automatically (verified against this kernel -- re-inserting the
 * same key right after close() succeeds with BPF_NOEXIST). A worker's
 * socket closes with it when the process exits, cleaning up the map
 * entry for free. quic_ebpf_del_conn() exists for the rarer case of
 * evicting an entry without killing its socket. */
int quic_ebpf_add_conn(const uint8_t cid[QUIC_EBPF_CIDLEN], int sock);
int quic_ebpf_del_conn(const uint8_t cid[QUIC_EBPF_CIDLEN]);

/* Register sock as the fallback destination (see steer() in
 * master/quic/cyr_quic_steer.bpf.c) for port/family packets whose CID
 * doesn't match any connection from quic_ebpf_add_conn() -- new
 * connections, and anything that fails to parse as QUIC. sock is that
 * port/family's own rendezvous socket. Without this, such packets
 * fall through to the kernel's own SO_REUSEPORT consistent-hash
 * selection across every socket sharing the port -- which, once any
 * per-connection socket also joins that group, can deliver a brand
 * new connection's first packet to some unrelated existing worker
 * instead. Keyed on port *and* family so multiple quic services on
 * different ports don't clobber each other. Call once per port/family
 * in play, after quic_drop_privs() and after
 * quic_rebind_rendezvous_sockets() has given the rendezvous socket its
 * final fd. */
int quic_ebpf_set_fallback(int family, uint16_t port, int sock);

/* Re-bind every proto="quic" service's rendezvous socket to its own
 * address, now that master has dropped to the cyrus uid -- see
 * quic_ebpf.c's own comment on this function for why (SO_REUSEPORT
 * group membership requires an exact uid match). Call once, right
 * after quic_drop_privs(); a no-op if no quic services are
 * configured. */
void quic_rebind_rendezvous_sockets(void);

/* Like become_cyrus() (lib/util.c), but for master's own process:
 * drops to the configured Cyrus uid/gid while retaining only
 * CAP_NET_BIND_SERVICE and CAP_NET_ADMIN (CAP_SETUID/CAP_SETGID are
 * dropped with everything else, so this can't be used to regain
 * root).
 *
 * CAP_NET_BIND_SERVICE: each new QUIC connection's socket must bind
 * the same (likely privileged, e.g. 443) local port as the service's
 * rendezvous socket -- bpf_sk_assign() requires the assigned socket's
 * bound port to match the packet's destination port. So master needs
 * this for its entire lifetime, not just at startup like other Cyrus
 * services.
 *
 * CAP_NET_ADMIN: needed for quic_ebpf_shutdown() to detach the TC
 * program and destroy its qdisc at shutdown -- without it that call
 * fails EPERM and the stale attachment outlives the process (see
 * quic_ebpf_shutdown()'s own comment).
 *
 * Doesn't weaken worker security: every forked/exec'd service
 * (including httpd) still drops all privilege via its own
 * become_cyrus()/cyrus_init(); only master's own QUIC dispatch code
 * runs with these two capabilities retained. */
int quic_drop_privs(void);

#endif /* HAVE_LIBBPF */

#endif /* MASTER_QUIC_EBPF_H */
