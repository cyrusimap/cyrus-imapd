/* quic_handoff.h - send a QUIC_HANDOFF_FD handoff, shared by both
 * dispatch backends */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef MASTER_QUIC_HANDOFF_H
#define MASTER_QUIC_HANDOFF_H

#include <config.h>

#include "master/service.h"

/* Hand one QUIC connection to a worker over fd -- master's end of
 * that worker's QUIC_HANDOFF_FD socketpair (see service.h) -- as a
 * single sendmsg(): sock via SCM_RIGHTS, *handoff as the payload
 * (service.c's quic_recv_handoff() receives it). Does not close sock
 * or fd -- the caller closes its own copy of sock once this
 * returns success (the worker gets its own SCM_RIGHTS-duped copy),
 * and keeps fd open for future handoffs to the same worker.
 * Returns 0 on success, -1 (errno set) on failure.
 *
 * Pure sendmsg()/SCM_RIGHTS plumbing, no eBPF dependency -- both
 * dispatch backends call this identically (see
 * quic_dispatch_connection() in master.c), differing only in what
 * sock is (a real UDP socket for eBPF, one end of an AF_UNIX
 * socketpair to master for the relay backend). */
int quic_send_handoff(int fd, int sock, const struct quic_handoff *handoff);

#endif /* MASTER_QUIC_HANDOFF_H */
