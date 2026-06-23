/* jcal.h - Routines for converting iCalendar to/from jCal */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef JCAL_H
#define JCAL_H

#include <config.h>

#include <libical/ical.h>
#include <jansson.h>

#include "util.h"

extern struct buf *icalcomponent_as_jcal_string(icalcomponent* comp);
extern icalcomponent *jcal_string_as_icalcomponent(const struct buf *);

extern json_t *icalcomponent_as_jcal_array(icalcomponent* comp);
extern icalcomponent *jcal_array_as_icalcomponent(json_t *);

extern json_t *icalproperty_as_jcal_array(icalproperty *prop);
extern icalproperty *jcal_array_as_icalproperty(json_t *);

extern void icalparameter_to_jcal_parameter(icalparameter *param,
                                            json_t *jparams);
#endif
