/* jscalendar.h -- Routines for converting JSCalendar and iCalendar
 *
 * Copyright (c) 2026 Fastmail Pty Ltd
 *
 */

#ifndef JSCAL_H
#define JSCAL_H

#ifdef __cplusplus
extern "C" {
#endif

#include "jmap_util.h"

#include <jansson.h>
#include <libical/ical.h>

/** @brief Configuration for JSCalendar/iCalendar conversion */
typedef struct {
    /**
     *  When converting an Alert object with action "email", this is
     *  the default email address URI to set in the ATTENDEE property
     *  of the VALARM, unless the "iCalComponent" property of the Alert
     *  object already contains ATTENDEE properties.
     *
     *  If the value is NULL then no ATTENDEE property is set. Note this
     *  violates the VALARM definition in RFC 5545, section 3.6.6.*
     */
    const char *emailalert_default_uri;

    /** 
     *  When converting an Alert object with action "display", this is
     *  the default string value to set in the DESCRIPTION property
     *  of the VALARM, unless the "iCalComponent" property of the Alert
     *  object already contains DESCRIPTION property.
     *
     *  If the value is NULL then no DESCRIPTION property is set. Note this
     *  violates the VALARM definition in RFC 5545, section 3.6.6. */
    const char *displayalert_default_description;

    /**
     *  Toggles if to use iCalendar conversion properties. If true, the
     *  "iCalComponent" conversion property will be read when converting
     *  to iCalendar and set when converting to JSCalendar.
     */
    bool use_icalendar_convprops;
} jscalendar_cfg_t;

/** @brief Convert a JSCalendar object to an iCalendar object.
 *
 *  @param cfg     Conversion configuration, or NULL for defaults.
 *  @param jobj    JSON object representing a JSCalendar Group or Event.
 *  @param parser  JMAP parser used to report property errors.
 *  @return        A newly allocated iCalendar object, or NULL on error. */
extern icalcomponent *jscalendar_to_ical(jscalendar_cfg_t *cfg,
                                         json_t *jobj,
                                         struct jmap_parser *parser);

/** @brief Convert an iCalendar object to a JSCalendar Group object.
 *
 *  @param cfg   Conversion configuration, or NULL for defaults.
 *  @param vcal  An iCalendar VCALENDAR component.
 *  @return      A newly allocated JSON object representing a JSCalendar Group,
 *               or NULL on error. */
extern json_t *jscalendar_from_ical(jscalendar_cfg_t *cfg,
                                    icalcomponent *vcal);

#ifdef __cplusplus
}
#endif

#endif
