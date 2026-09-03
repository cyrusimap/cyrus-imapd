/* cyr_quic_steer.bpf.c - TC classifier that steers QUIC packets by
 * Destination Connection ID to a per-connection socket. */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

/*
 * Why a TC classifier and not a BPF_PROG_TYPE_SK_LOOKUP program:
 *
 * SK_LOOKUP's ctx only exposes L3/L4 metadata (addresses, ports,
 * protocol) -- no payload access, so it can't read the QUIC
 * Destination Connection ID inside the UDP payload. A TC classifier
 * operates on a real __sk_buff, so it can read the payload (via
 * bpf_skb_load_bytes()), extract the CID, look it up in a
 * BPF_MAP_TYPE_SOCKHASH master populates, and bpf_sk_assign() the
 * packet straight to that connection's socket -- which also works for
 * a *connected* UDP socket, unlike SK_LOOKUP's bpf_sk_assign(),
 * documented to accept only unconnected ones.
 *
 * Packets whose CID isn't in the map (new connections, or anything
 * that fails to parse as QUIC) fall through to normal socket lookup,
 * landing on master's rendezvous socket.
 */

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "quic_cidlen.h"

/* Family bits used to build a per-(port,family) fallback key below --
 * arbitrary as long as steer() and quic_ebpf_set_fallback() agree. */
#define QUIC_FAMILY_V4 ((__u64) 0)
#define QUIC_FAMILY_V6 ((__u64) 1)

struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(max_entries, 65536);
    __type(key, __u64);
    __type(value, __u32);
} quic_conns SEC(".maps");

/* Set of UDP ports (host byte order) with a proto="quic" service
 * listening -- one entry per configured service (multiple services
 * can share this one interface/program), populated by userspace
 * before traffic flows. Value is unused: a lookup hit alone means
 * "steer this port". 16 ports is already generous for a single
 * host's worth of QUIC listeners; raise if that's ever not enough. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16);
    __type(key, __u32);
    __type(value, __u8);
} quic_port SEC(".maps");

static __always_inline int steer(struct __sk_buff *skb, __u32 l4_off,
                                 __u64 family)
{
    __u16 dport;
    __u32 port_key;
    __u32 udp_payload_off;
    __u8 first_byte;
    __u32 cid_off;
    __u8 dcid_len;
    __u64 key = 0, fallback_key;
    struct bpf_sock *sk;

    if (bpf_skb_load_bytes(skb, l4_off + offsetof(struct udphdr, dest),
                           &dport, sizeof(dport)))
        return TC_ACT_OK;

    port_key = bpf_ntohs(dport);
    if (!bpf_map_lookup_elem(&quic_port, &port_key)) return TC_ACT_OK;

    /* Reserved quic_conns key for this port+family's rendezvous socket
     * -- see the fallback lookup below; must match
     * quic_ebpf_set_fallback() in quic_ebpf.c. Packing port and family
     * (rather than one fixed key per family) is what lets multiple
     * proto="quic" services on different ports share this
     * program/interface, each falling back to its own rendezvous
     * socket. A real CID colliding with a reserved slot is a
     * ~1-in-2^64 event per attempt -- the same risk this scheme
     * already accepts for CIDs colliding with each other. */
    fallback_key = ((__u64) port_key << 1) | family;

    udp_payload_off = l4_off + sizeof(struct udphdr);

    if (bpf_skb_load_bytes(skb, udp_payload_off, &first_byte, 1))
        return TC_ACT_OK;

    if (first_byte & 0x80) {
        /* Long header: type(1) + version(4) + dcid_len(1), then DCID */
        if (bpf_skb_load_bytes(skb, udp_payload_off + 5, &dcid_len, 1))
            return TC_ACT_OK;
        cid_off = udp_payload_off + 6;
    }
    else {
        /* Short header: no self-described length -- every CID we
         * hand out is exactly QUIC_EBPF_CIDLEN, so assume that. */
        dcid_len = QUIC_EBPF_CIDLEN;
        cid_off = udp_payload_off + 1;
    }

    if (dcid_len < QUIC_EBPF_CIDLEN) return TC_ACT_OK;

    if (bpf_skb_load_bytes(skb, cid_off, &key, QUIC_EBPF_CIDLEN))
        return TC_ACT_OK;

    sk = bpf_map_lookup_elem(&quic_conns, &key);
    if (!sk) {
        /* No specific connection matched this CID (a new connection,
         * or one whose steering entry hasn't landed yet) -- explicitly
         * assign the rendezvous socket for this address family, rather
         * than falling through to ordinary socket lookup. Every
         * per-connection socket also binds this same port via
         * SO_REUSEPORT (bpf_sk_assign() requires it), making them
         * indistinguishable from the rendezvous socket to the kernel's
         * reuseport selection -- without this explicit assign, a brand
         * new connection's first packet could land on some unrelated
         * existing connection's socket instead. */
        sk = bpf_map_lookup_elem(&quic_conns, &fallback_key);
    }
    if (sk) {
        bpf_sk_assign(skb, sk, 0);
        bpf_sk_release(sk);
    }

    return TC_ACT_OK;
}

SEC("tc")
int cyr_quic_steer(struct __sk_buff *skb)
{
    __u16 h_proto;
    __u8 ip_proto;

    if (bpf_skb_load_bytes(skb, offsetof(struct ethhdr, h_proto),
                           &h_proto, sizeof(h_proto)))
        return TC_ACT_OK;
    h_proto = bpf_ntohs(h_proto);

    if (h_proto == ETH_P_IP) {
        __u8 vihl;

        if (bpf_skb_load_bytes(skb, ETH_HLEN, &vihl, 1))
            return TC_ACT_OK;
        if (bpf_skb_load_bytes(skb,
                               ETH_HLEN + offsetof(struct iphdr, protocol),
                               &ip_proto, 1))
            return TC_ACT_OK;
        if (ip_proto != IPPROTO_UDP) return TC_ACT_OK;

        return steer(skb, ETH_HLEN + (vihl & 0x0F) * 4, QUIC_FAMILY_V4);
    }
    else if (h_proto == ETH_P_IPV6) {
        if (bpf_skb_load_bytes(skb,
                               ETH_HLEN + offsetof(struct ipv6hdr, nexthdr),
                               &ip_proto, 1))
            return TC_ACT_OK;
        if (ip_proto != IPPROTO_UDP) return TC_ACT_OK;

        /* Assumes no IPv6 extension headers between the fixed header
         * and UDP. */
        return steer(skb, ETH_HLEN + sizeof(struct ipv6hdr), QUIC_FAMILY_V6);
    }

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
