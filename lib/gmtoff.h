/* gmtoff.h -- Get GMT offset */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef INCLUDED_GMTOFF_H
#define INCLUDED_GMTOFF_H

#include <time.h>

extern int gmtoff_of(struct tm *tm, time_t time);

#endif /* INCLUDED_GMTOFF_H */

