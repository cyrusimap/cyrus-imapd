/* calsched_support.h - utility functions for dealing with calendar scheduling */
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

/**
 * Get the calendar user addresses that userid schedules as in mailbox
 * mboxname: the calendar-user-address-set stored for them, less any address
 * of another local user (see sched_addresses_restrict(), with userid and the
 * owner of mboxname), or if that leaves none, userid's own addresses in the
 * calendar_user_address_set domains.
 */
extern void get_schedule_addresses(const char *mboxname,
                                   const char *userid, strarray_t *addresses);

/**
 * Remove from addresses every address of a local user other than userid
 * and ownerid, either of which may be NULL.
 *
 * An address of a local user is one get_schedule_addresses() would give
 * that user by default: its domain is one of the calendar_user_address_set
 * domains, and its local part less any +detail, with or without the domain,
 * names an existing user, compared without regard to case.  Other
 * addresses, such as an alias a user lists in their
 * calendar-user-address-set, are kept.
 */
extern void sched_addresses_restrict(strarray_t *addresses,
                                     const char *userid,
                                     const char *ownerid);

#endif /* SCHED_UTIL_H */
