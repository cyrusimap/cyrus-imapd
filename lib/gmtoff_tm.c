/* gmtoff_tm.c - Get offset from GMT from the tm_gmtoff struct member */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>

/*
 * Returns the GMT offset of the struct tm 'tm', obtained from 'time'.
 */
EXPORTED int gmtoff_of(struct tm *tm, time_t time __attribute__((unused)))
{
    return tm->tm_gmtoff;
}
