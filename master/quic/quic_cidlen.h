/* quic_cidlen.h - length of the Connection ID master assigns each
 * QUIC connection for dispatch */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef MASTER_QUIC_CIDLEN_H
#define MASTER_QUIC_CIDLEN_H

/* A dispatch policy choice of ours, not something QUIC or ngtcp2
 * dictates -- the protocol lets whichever endpoint generates a CID
 * pick its own length, anywhere from NGTCP2_MIN_CIDLEN (1) to
 * NGTCP2_MAX_CIDLEN (20). Not to be confused with
 * NGTCP2_MIN_INITIAL_DCIDLEN (also 8, coincidentally): that's the
 * client's initial DCID floor, an unrelated RFC 9000 anti-
 * amplification requirement.
 *
 * Its own header, rather than living in master/service.h alongside
 * everything else proto="quic" needs, because
 * master/quic/cyr_quic_steer.bpf.c has to see it too: that file is
 * compiled separately by clang -target bpf (see Makefile.am) and
 * can't #include master/service.h, which pulls in userspace-only
 * headers (<sys/socket.h>, struct quic_handoff) a kernel-verified BPF
 * program has no business with. */
#define QUIC_EBPF_CIDLEN 8

#endif /* MASTER_QUIC_CIDLEN_H */
