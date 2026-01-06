/* unit-timeofday.h - time of day warping utilities for unit tests */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef CUNIT_UNIT_TIMEOFDAY_H
#define CUNIT_UNIT_TIMEOFDAY_H

#include <sys/types.h>

extern void time_push_rate(long n, long d);
extern void time_push_stop(void);
extern void time_push_fixed(time_t fixed);
extern void time_pop(void);
extern void time_restore(void);


extern int real_gettimeofday(struct timeval *, ...);
extern time_t real_time(time_t *tp);
extern unsigned int real_sleep(unsigned int seconds);
extern int real_nanosleep(const struct timespec *duration,
                          struct timespec *remainder);

#endif /* CUNIT_UNIT_TIMEOFDAY_H */
