/* quic_idle_pool.c - idle QUIC worker tracking for master */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>

#include "master/quic/quic_idle_pool.h"

#include "lib/dynarray.h"

void quic_idle_pool_push(struct service *s, pid_t pid, int fd)
{
    struct quic_idle_worker w = { .pid = pid, .fd = fd };

    /* Lazy init: s is calloc'd/memset before first use, so a zeroed
     * dynarray_t (membsize == 0) reliably means "never pushed to". */
    if (!s->quic_idle_workers.membsize) {
        dynarray_init(&s->quic_idle_workers, sizeof(struct quic_idle_worker));
    }
    dynarray_append(&s->quic_idle_workers, &w);
}

struct quic_idle_worker *quic_idle_pool_pop(struct service *s)
{
    /* A single scratch slot to copy the popped entry into before
     * dynarray_truncate() zeroes its old spot -- safe since master is
     * single-threaded and callers use the result before popping
     * again. */
    static struct quic_idle_worker popped;
    int n = dynarray_size(&s->quic_idle_workers);
    struct quic_idle_worker *w;

    if (!n) return NULL;

    /* Pop from the tail -- O(1), no need to shift anything down. */
    w = dynarray_nth(&s->quic_idle_workers, n - 1);
    popped = *w;
    dynarray_truncate(&s->quic_idle_workers, n - 1);
    return &popped;
}

void quic_idle_pool_remove(struct service *s, pid_t pid)
{
    int n = dynarray_size(&s->quic_idle_workers);

    for (int i = 0; i < n; i++) {
        struct quic_idle_worker *w = dynarray_nth(&s->quic_idle_workers, i);

        if (w->pid == pid) {
            /* Order doesn't matter here -- overwrite with the tail
             * member and drop it, instead of shifting everything
             * down. */
            struct quic_idle_worker *tail =
                dynarray_nth(&s->quic_idle_workers, n - 1);

            *w = *tail;
            dynarray_truncate(&s->quic_idle_workers, n - 1);
            return;
        }
    }
}

void quic_idle_pool_fini(struct service *s)
{
    dynarray_fini(&s->quic_idle_workers);
}
