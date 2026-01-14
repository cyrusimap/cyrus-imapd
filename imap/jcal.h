/* jcal.h - Routines for converting iCalendar to/from jCal */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>

#include <libical/ical.h>
#include <jansson.h>

#include "util.h"

extern struct buf *icalcomponent_as_jcal_string(icalcomponent* comp);
extern icalcomponent *jcal_string_as_icalcomponent(const struct buf *);

extern json_t *icalcomponent_as_jcal_array(icalcomponent* comp);
extern icalcomponent *jcal_array_as_icalcomponent(json_t *);

extern const char *begin_jcal(struct buf *buf, struct mailbox *mailbox,
                              const char *prodid, const char *name,
                              const char *desc, const char *color);
extern void end_jcal(struct buf *buf);
