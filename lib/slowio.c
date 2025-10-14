/* slowio -- artificially slow I/O ops
 *
 * Copyright (c) 1994-2024 Carnegie Mellon University.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The name "Carnegie Mellon University" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For permission or any legal
 *    details, please contact
 *      Carnegie Mellon University
 *      Center for Technology Transfer and Enterprise Creation
 *      4615 Forbes Avenue
 *      Suite 302
 *      Pittsburgh, PA  15213
 *      (412) 268-7393, fax: (412) 268-7395
 *      innovation@andrew.cmu.edu
 *
 * 4. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Computing Services
 *     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <errno.h>
#include <math.h>
#include <syslog.h>

#include "libconfig.h"
#include "slowio.h"
#include "util.h"

static struct slowio slowio_read = { 0 };
static struct slowio slowio_write = { 0 };
static double slowio_min_elapsed = NAN;

EXPORTED void slowio_reset_impl(void)
{
    memset(&slowio_read, 0, sizeof(slowio_read));
    memset(&slowio_write, 0, sizeof(slowio_write));
}

EXPORTED void slowio_maybe_delay_read_impl(ssize_t n_bytes)
{
    if (config_debug_slowio) {
        slowio_maybe_delay_impl(&slowio_read, n_bytes);
    }
}

EXPORTED void slowio_maybe_delay_write_impl(ssize_t n_bytes)
{
    if (config_debug_slowio) {
        slowio_maybe_delay_impl(&slowio_write, n_bytes);
    }
}

EXPORTED void slowio_maybe_delay_impl(struct slowio *slowio, ssize_t n_bytes)
{
    const double max_bytes_per_sec = SLOWIO_MAX_BYTES_SEC;
    struct timespec now;

    if (n_bytes < 0) {
        return; /* that wasn't a valid I/O op! */
    }

    if (isnan(slowio_min_elapsed)) {
        struct timespec res;

        /* initialise slowio_min_elapsed to the resolution of the clock */
        if (0 == clock_getres(CLOCK_PROCESS_CPUTIME_ID, &res)) {
            slowio_min_elapsed = res.tv_sec + res.tv_nsec / 1000000000.0;
        }
        else {
            xsyslog(LOG_DEBUG, "clock_getres failed", NULL);
            errno = 0;
            slowio_min_elapsed = 0.000001; /* XXX idk, 1μs */
        }
    }

    if (cyrus_gettime(CLOCK_PROCESS_CPUTIME_ID, &now)) {
        xsyslog(LOG_DEBUG, "cyrus_gettime failed", NULL);
        errno = 0;
        return;
    }

    if (slowio->last_delay.tv_sec == 0 && slowio->last_delay.tv_nsec == 0
        && slowio->bytes_since_last_delay == 0)
    {
        /* first time called, just initialise */
        slowio->last_delay = now;
        slowio->bytes_since_last_delay = n_bytes;
        return;
    }

    if (n_bytes == 0) {
        return; /* nothing else to do */
    }

    slowio->bytes_since_last_delay += n_bytes;
    /* XXX alas, timesub() is for timeval, not timespec */
    double elapsed =
        (double) (now.tv_sec - slowio->last_delay.tv_sec)
        + (double) (now.tv_nsec - slowio->last_delay.tv_nsec) / 1000000000.0;

    if (slowio->bytes_since_last_delay == 0) {
        return;
    }

    /* can't divide by zero, but if bytes have arrived without any observable
     * time having passed, we're running extremely fast and must delay!
     */
    if (elapsed <= 0.0) {
        elapsed = slowio_min_elapsed;
    }

    if (slowio->bytes_since_last_delay / elapsed > max_bytes_per_sec) {
        double delay =
            (slowio->bytes_since_last_delay / max_bytes_per_sec) - elapsed;
        double delay_s, delay_ns;
        struct timespec sleeptime;
        int r;

        delay_s = floor(delay);
        delay_ns = (delay - delay_s) * 1000000000.0;

        sleeptime.tv_sec = (time_t) delay_s;
        sleeptime.tv_nsec = (int32_t) delay_ns;

        do {
            errno = 0;
            r = nanosleep(&sleeptime, &sleeptime);
        } while (r == -1 && errno == EINTR);

        cyrus_gettime(CLOCK_PROCESS_CPUTIME_ID, &slowio->last_delay);
        slowio->bytes_since_last_delay = 0;
    }
}
