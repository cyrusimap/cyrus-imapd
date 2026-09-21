/* cyr_quic_steer.bpf.c - SK_REUSEPORT program that steers QUIC packets
 * by Destination Connection ID to a per-connection socket. */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

/* Runs at the point the kernel picks a socket from a SO_REUSEPORT
 * group, so this program *is* the selection and nothing afterward can
 * override it.
 *
 * Attached with SO_ATTACH_REUSEPORT_EBPF on the rendezvous socket (see
 * quic_ebpf_init_service()), scoped to that socket's reuseport group --
 * no port filter map or per-interface attachment needed.
 */

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>

#include "quic_cidlen.h"

/* Reserved index for the rendezvous socket itself -- see
 * quic_ebpf_init_service(). Real connections start at 1. */
#define QUIC_FALLBACK_INDEX 0

/* CID -> index into quic_socks below. BPF_MAP_TYPE_REUSEPORT_SOCKARRAY
 * is fixed-size and indexed by small integers, not directly keyable by
 * an arbitrary 8-byte CID, hence the two-map indirection. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);
    __type(value, __u32);
} quic_cid_index SEC(".maps");

/* index -> the actual per-connection socket. */
struct {
    __uint(type, BPF_MAP_TYPE_REUSEPORT_SOCKARRAY);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, __u64);
} quic_socks SEC(".maps");

SEC("sk_reuseport")
int cyr_quic_steer(struct sk_reuseport_md *ctx)
{
    /* Offsets are from the UDP header (RFC 9000's own framing starts
     * right after it).  Read with bpf_skb_load_bytes() rather than
     * through ctx->data, which only spans the skb's linear area: a
     * padded Initial, or a burst of short-header packets the sender
     * aggregated with UDP GSO, routinely isn't linear past its headers,
     * and steering an established connection's packets to master on
     * that account drops them. */
    __u8 first_byte;
    __u32 cid_off;
    __u8 dcid_len;
    __u64 key = 0;
    __u32 *index;
    __u32 fallback = QUIC_FALLBACK_INDEX;

/* Send this packet to the rendezvous socket and stop. Used for every
 * packet this program can't classify as well as for a CID miss:
 * returning SK_PASS without selecting leaves the choice to the
 * kernel's default reuseport hash, which would scatter it across the
 * per-connection sockets. */
#define STEER_TO_MASTER()                                            \
    do {                                                             \
        bpf_sk_select_reuseport(ctx, &quic_socks, &fallback, 0);     \
        return SK_PASS;                                              \
    } while (0)

    if (bpf_skb_load_bytes(ctx, sizeof(struct udphdr), &first_byte, 1))
        STEER_TO_MASTER();

    if (first_byte & 0x80) {
        /* Long header (RFC 9000 section 17.2): type(1) + version(4) +
         * dcid_len(1), then DCID. */
        if (bpf_skb_load_bytes(ctx, sizeof(struct udphdr) + 5, &dcid_len, 1))
            STEER_TO_MASTER();
        cid_off = sizeof(struct udphdr) + 6;
    }
    else {
        /* Short header (RFC 9000 section 17.3): no self-described
         * length -- every CID we hand out is exactly QUIC_CIDLEN,
         * so assume that. */
        dcid_len = QUIC_CIDLEN;
        cid_off = sizeof(struct udphdr) + 1;
    }

    if (dcid_len < QUIC_CIDLEN) STEER_TO_MASTER();
    if (bpf_skb_load_bytes(ctx, cid_off, &key, QUIC_CIDLEN))
        STEER_TO_MASTER();

    index = bpf_map_lookup_elem(&quic_cid_index, &key);
    if (!index) {
        /* CID miss: a new connection, or a steering entry that hasn't
         * landed yet. */
        STEER_TO_MASTER();
    }

    bpf_sk_select_reuseport(ctx, &quic_socks, index, 0);
    return SK_PASS;
}

char _license[] SEC("license") = "GPL";
