/* gmtoff_tm.c - Get offset from GMT by calling gmtime and subtracting */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>

/*
 * Returns the GMT offset of the struct tm 'tm', obtained from 'time'.
 */
EXPORTED int gmtoff_of(struct tm *tm, time_t time)
{
    struct tm local, gmt;
    struct tm *gtm;
    long offset;

    local = *tm;
    gtm = gmtime(&time);
    gmt = *gtm;

    /* Assume we are never more than 24 hours away. */
    offset = local.tm_yday - gmt.tm_yday;
    if (offset > 1) {
        offset = -24;
    } else if (offset < -1) {
        offset = 24;
    } else {
        offset *= 24;
    }

    /* Scale in the hours and minutes; ignore seconds. */
    offset += local.tm_hour - gmt.tm_hour;
    offset *= 60;
    offset += local.tm_min - gmt.tm_min;

    /* Restore the data in the struct 'tm' points to */
    *tm = local;
    return offset * 60;
}
