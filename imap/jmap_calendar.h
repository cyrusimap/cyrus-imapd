/* jmap_calendar.h -- Routines for handling JMAP calendars */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef JMAP_CALENDAR_H
#define JMAP_CALENDAR_H

#include <config.h>

#include "jmap_api.h"
#include "json_support.h"
#include "ptrarray.h"
#include "util.h"

extern json_t *jmap_calendar_events_from_msg(jmap_req_t *req,
                                             const char *mboxid, uint32_t uid,
                                             hash_table *icsbody_by_partid,
                                             unsigned allow_max_uids,
                                             const struct buf *mime);

#endif /* JMAP_CALENDAR_H */
