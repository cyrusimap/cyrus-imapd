/* calsched_support.h -- utility functions for dealing with calendar scheduling */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef SCHED_UTIL_H
#define SCHED_UTIL_H

#include <libical/ical.h>

#include "mailbox.h"
#include "strarray.h"

extern int caldav_caluseraddr_read(const char *mboxname,
                                   const char *userid,
                                   strarray_t *addresses);

extern int caldav_caluseraddr_write(struct mailbox *mbox,
                                    const char *userid,
                                    strarray_t *addresses);

extern void get_schedule_addresses(const char *mboxname,
                                   const char *userid, strarray_t *addresses);

#endif /* SCHED_UTIL_H */
