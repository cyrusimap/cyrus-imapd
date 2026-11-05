/* quic_cidlen.h - length of the Connection ID master assigns each
 * QUIC connection for dispatch */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef MASTER_QUIC_CIDLEN_H
#define MASTER_QUIC_CIDLEN_H

/* A dispatch policy choice of ours, not something QUIC or ngtcp2
 * dictates -- the protocol lets whichever endpoint generates a CID
 * pick its own length, from NGTCP2_MIN_CIDLEN (1) to
 * NGTCP2_MAX_CIDLEN (20). Not to be confused with the coincidentally
 * equal NGTCP2_MIN_INITIAL_DCIDLEN, an unrelated RFC 9000
 * anti-amplification floor.
 *
 * Its own header rather than master/service.h, because
 * cyr_quic_steer.bpf.c needs it too and can't #include service.h's
 * userspace-only headers. */
#define QUIC_CIDLEN 8

#endif /* MASTER_QUIC_CIDLEN_H */
