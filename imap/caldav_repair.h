/* caldav_repair.h - repair CalDAV database invariant violations */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef CALDAV_REPAIR_H
#define CALDAV_REPAIR_H

#include <config.h>

/** Repair resources that share an iCalendar UID. */
#define DAV_REPAIR_UID_CONFLICTS (1<<0)

/** Every repair mode. */
#define DAV_REPAIR_ALL           0x0000ffff

/** Perform the selected repairs, rather than only reporting them. */
#define DAV_REPAIR_REALLY        (1<<16)

/** Report of what a repair pass found and did. */
struct caldav_repair_stats {
    unsigned groups;   /**< iCalendar UIDs found in more than one resource */
    unsigned merged;   /**< resources folded into another and expunged */
    unsigned reuided;  /**< resources given a new iCalendar UID */
    unsigned failed;   /**< groups left unrepaired because of an error */
};

/**
 * Repair iCalendar UIDs that exist in more than one CalDAV resource.
 *
 * For each such group one resource keeps its identity -- its iCalendar UID,
 * its resource name and its createdmodseq, and so the JMAP id clients already
 * hold.  The others are merged into it when no component and no per-user datum
 * would be lost, and otherwise are split off whole under a fresh iCalendar
 * UID, resource name and createdmodseq, with the original UID recorded in an
 * X-CYRUS-ORIGINAL-UID property.
 *
 * The plan is written to stdout either way; it is only executed if @a flags
 * has DAV_REPAIR_REALLY.
 *
 * Must be called with the user namespace lock held.
 *
 * @param userid  the user whose calendars to repair
 * @param flags   DAV_REPAIR_* mask
 * @param stats   accumulates what was found and done; may not be NULL
 * @return 0 on success, an IMAP error code if the pass could not run.
 *         A group that could not be repaired is counted in @a stats and does
 *         not fail the pass.
 */
extern int caldav_repair_uid_conflicts(const char *userid, int flags,
                                       struct caldav_repair_stats *stats);

#endif /* CALDAV_REPAIR_H */
