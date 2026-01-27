/* xcal.h - Routines for converting iCalendar to/from xCal */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef XCAL_H
#define XCAL_H

#include <config.h>

#include <libical/ical.h>

#include "util.h"

#define XML_NS_ICALENDAR        "urn:ietf:params:xml:ns:icalendar-2.0"

extern const char *icalproperty_value_kind_as_string(icalproperty *prop);
extern const char *icaltime_as_iso_string(const struct icaltimetype tt);
extern const char *icalvalue_utcoffset_as_iso_string(const icalvalue* value);
extern void icalrecurrencetype_add_as_xxx(struct icalrecurrencetype *recur,
                                          void *obj,
                                          void (*add_int)(void *, const char *,
                                                          int),
                                          void (*add_str)(void *, const char *,
                                                          const char *));
extern struct icalrecurrencetype *
icalrecur_add_rule(struct icalrecurrencetype **rt,
                   const char *rpart, void *data,
                   int (*get_int)(void *),
                   const char* (*get_str)(void *));

extern struct buf *icalcomponent_as_xcal_string(icalcomponent* comp);
extern icalcomponent *xcal_string_as_icalcomponent(const struct buf *buf);
extern const char *begin_xcal(struct buf *buf, struct mailbox *mailbox,
                              const char *prodid, const char *name,
                              const char *desc, const char *color);
extern void end_xcal(struct buf *buf);

#endif /* XCAL_H */
