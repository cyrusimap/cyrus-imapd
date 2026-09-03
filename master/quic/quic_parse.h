/* quic_parse.h - QUIC packet parsing */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef MASTER_QUIC_PARSE_H
#define MASTER_QUIC_PARSE_H

#include <config.h>
#include <stdint.h>
#include <stddef.h>

/* Server-chosen and client-chosen Connection IDs always fit in 20
 * bytes (ngtcp2's own NGTCP2_MAX_CIDLEN) -- distinct from
 * QUIC_EBPF_CIDLEN (master/service.h), the shorter fixed length *we*
 * generate for our own steering/relay purposes. */
#define QUIC_MAX_CIDLEN  20

struct quic_initial_cids {
    uint8_t dcid[QUIC_MAX_CIDLEN];
    uint8_t dcidlen;
    uint8_t scid[QUIC_MAX_CIDLEN];
    uint8_t scidlen;
    uint32_t version;
};

/* Parse buf/len as a QUIC long-header Initial packet, filling *out on
 * success. Returns 0 on success, -1 if this doesn't look like one
 * (wrong header form, unrecognized version, truncated, etc). */
int quic_parse_initial(const uint8_t *buf, size_t len,
                       struct quic_initial_cids *out);

/* Extract the Destination Connection ID from a QUIC packet of any
 * type (long or short header) for routing purposes -- not a validity
 * check, and unlike quic_parse_initial(), doesn't require an Initial
 * packet. Only used by the userspace relay backend
 * (master/quic/quic_relay.c); the eBPF backend does the equivalent
 * in-kernel, in cyr_quic_steer.bpf.c's steer().
 *
 * For a short-header packet, *dcidlen comes back as cidlen
 * unconditionally -- short headers don't self-describe DCID length,
 * but every connection either backend dispatches uses that fixed
 * length. Returns 0 and fills *dcidlen/dcid on success, -1 if buf is
 * too short for a DCID, or (long header) if the self-described length
 * exceeds QUIC_MAX_CIDLEN. */
int quic_extract_dcid(const uint8_t *buf, size_t len, uint8_t cidlen,
                      uint8_t dcid[QUIC_MAX_CIDLEN], uint8_t *dcidlen);

#endif /* MASTER_QUIC_PARSE_H */
