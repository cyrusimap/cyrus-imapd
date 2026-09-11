/* slowio -- artificially slow I/O ops */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef INCLUDED_SLOWIO_H
#define INCLUDED_SLOWIO_H

#include <config.h>
#include <time.h>

#ifdef ENABLE_DEBUG_SLOWIO
#define slowio_reset()              slowio_reset_impl()
#define slowio_maybe_delay_read(n)  slowio_maybe_delay_read_impl(n)
#define slowio_maybe_delay_write(n) slowio_maybe_delay_write_impl(n)
#else
#define slowio_reset()              do {} while(0)
#define slowio_maybe_delay_read(n)  do {} while(0)
#define slowio_maybe_delay_write(n) do {} while(0)
#endif /* ENABLE_DEBUG_SLOWIO */

#define SLOWIO_MAX_BYTES_SEC (6250000) /* ~50Mbps */

struct slowio {
    struct timespec last_delay;
    size_t bytes_since_last_delay;
};

extern void slowio_reset_impl(void);
extern void slowio_maybe_delay_read_impl(ssize_t n_bytes);
extern void slowio_maybe_delay_write_impl(ssize_t n_bytes);
extern void slowio_maybe_delay_impl(struct slowio *slowio, ssize_t n_bytes);

#endif
