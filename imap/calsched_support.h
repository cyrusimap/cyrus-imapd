/* calsched_support.h - utility functions for dealing with calendar scheduling */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef SCHED_UTIL_H
#define SCHED_UTIL_H

#include <libical/ical.h>
#include <stdbool.h>

#include "mailbox.h"
#include "mboxlist.h"
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
 * Find the local user a calendar user address belongs to: the user that
 * scheduling delivers to at that address.
 *
 * The address's domain must be one of the calendar_user_address_set
 * domains, compared without regard to case.  Its local part, less any
 * +detail, names the user, as given or else lowercased.  With virtdomains
 * on, that is the user in the address's domain or, if defdomain_fallback is
 * set and there is none, the user in the default domain, whose default
 * addresses are in every calendar_user_address_set domain.  The user must
 * have a calendar home or, failing that, an INBOX.
 *
 * @param addr      the address, with or without "mailto:"
 * @param defdomain_fallback  whether a default domain user can hold an
 *                  address in another domain: true when asking whose
 *                  address it is, false when routing to it
 * @param mlookup   looks up a mailbox by name; NULL for mboxlist_lookup()
 * @param calhomep  if not NULL, set to the user's calendar home, or to NULL
 *                  if they have none; the caller frees it
 * @return the userid, which the caller frees, or NULL if the address is
 *         no local user's
 */
extern char *caladdress_userid(const char *addr, bool defdomain_fallback,
                               int (*mlookup)(const char *, mbentry_t **),
                               mbentry_t **calhomep);

/**
 * Remove from addresses every address of a local user (see
 * caladdress_userid()) other than userid and ownerid, either of which may
 * be NULL.  Other addresses, such as an alias a user lists in their
 * calendar-user-address-set, are kept.
 */
extern void sched_addresses_restrict(strarray_t *addresses,
                                     const char *userid,
                                     const char *ownerid);

#endif /* SCHED_UTIL_H */
