/* jscalendar.h -- Routines for converting JSCalendar and iCalendar
 *
 * Copyright (c) 2025 Fastmail Pty Ltd
 *
 */

#ifndef JSCAL_H
#define JSCAL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <jansson.h>
#include <libical/ical.h>

typedef struct {
    // When converting an Alert object with action "email", this is
    // the default email address URI to set in the ATTENDEE property
    // of the VALARM, unless the "iCalComponent" property of the Alert
    // object already contains ATTENDEE properties.
    //
    // If the value is NULL then no ATTENDEE property is set. Note this
    // violates the VALARM definition in RFC 5545, section 3.6.6.
    const char *emailalert_default_uri;

    // When converting an Alert object with action "display", this is
    // the default string value to set in the DESCRIPTION property
    // of the VALARM, unless the "iCalComponent" property of the Alert
    // object already contains DESCRIPTION property.
    //
    // If the value is NULL then no DESCRIPTION property is set. Note this
    // violates the VALARM definition in RFC 5545, section 3.6.6.
    const char *displayalert_default_description;

    // Toggles if to ignore iCalendar conversion properties. If true, the
    // "iCalComponent" conversion property will be ignored when converting
    // to iCalendar and not set when converting to JSCalendar.
    bool ignore_icalendar_convprops;
} jscalendar_cfg_t;

extern bool jscalendar_validate(json_t *jgroup, json_t **invalid);
extern icalcomponent *jscalendar_to_ical(json_t *jgroup, jscalendar_cfg_t *);
extern json_t *jscalendar_from_ical(jscalendar_cfg_t *, icalcomponent *vcal);

#ifdef __cplusplus
}
#endif

#endif
