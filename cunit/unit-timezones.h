/* unit-timezones.h - timezone utilities for unit tests */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef CUNIT_UNIT_TIMEZONES_H
#define CUNIT_UNIT_TIMEZONES_H

#include <stdio.h>
#include <stdarg.h>

#define TZ_UTC          "UTC+00"
#define TZ_NEWYORK      "EST+05"
#define TZ_MELBOURNE    "AEST-11" /* XXX 11 is AEDT not AEST... */

extern void push_tz(const char *tz);
extern void pop_tz(void);
extern void restore_tz(void);

#endif /* CUNIT_UNIT_TIMEZONES_H */
