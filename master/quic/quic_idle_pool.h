/* quic_idle_pool.h - idle QUIC worker tracking for master */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef MASTER_QUIC_IDLE_POOL_H
#define MASTER_QUIC_IDLE_POOL_H

#include <config.h>
#include <sys/types.h>

#include "master/master.h"

/* One worker that is ready for a connection. */
struct quic_idle_worker {
    pid_t pid;
    int fd;     /* == the owning centry's quic_fd */
};

/* Record that pid (whose centry already has fd stored) is ready for
 * quic_dispatch_connection() to hand it a connection. Paired with the
 * ready_workers++ its caller does, so the two stay in step. */
void quic_idle_pool_push(struct service *s, pid_t pid, int fd);

/* Remove and return a ready worker for s, or NULL if none are
 * available. The result is a static scratch slot: don't free() it,
 * and it's only valid until the next call. The caller must then hand
 * it a connection, or treat it as dead if that fails. */
struct quic_idle_worker *quic_idle_pool_pop(struct service *s);

/* Remove pid from s's idle pool, if present. Doesn't touch its fd --
 * that's the caller's call (reap_child() closes it, dispatch
 * doesn't). A no-op, not an error, if pid was never in the pool. */
void quic_idle_pool_remove(struct service *s, pid_t pid);

/* Free s's pool storage. Doesn't touch any fds -- reap_child() owns
 * those via each centry's quic_fd. Safe on an empty or never-used
 * pool, and the pool stays usable afterward. */
void quic_idle_pool_fini(struct service *s);

#endif /* MASTER_QUIC_IDLE_POOL_H */
