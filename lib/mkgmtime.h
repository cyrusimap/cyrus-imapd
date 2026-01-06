/* mkgmtime.h -- make a time_t from a gmtime struct tm */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef INCLUDED_MKGMTIME_H
#define INCLUDED_MKGMTIME_H

#include <time.h>

extern time_t mkgmtime(struct tm * const tmp);

#endif /* INCLUDED_MKGMTIME_H */
