/* jmap_ical.h --Routines to convert JMAP calendar events and iCalendar
 *
 * Copyright (c) 1994-2016 Carnegie Mellon University.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The name "Carnegie Mellon University" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For permission or any legal
 *    details, please contact
 *      Carnegie Mellon University
 *      Center for Technology Transfer and Enterprise Creation
 *      4615 Forbes Avenue
 *      Suite 302
 *      Pittsburgh, PA  15213
 *      (412) 268-7393, fax: (412) 268-7395
 *      innovation@andrew.cmu.edu
 *
 * 4. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Computing Services
 *     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 */

#ifndef JMAPICAL_H
#define JMAPICAL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <jansson.h>
#include <libical/ical.h>

#define JMAPICAL_ERROR_UNKNOWN  -1
#define JMAPICAL_ERROR_CALLBACK 1
#define JMAPICAL_ERROR_MEMORY   2
#define JMAPICAL_ERROR_ICAL     3
#define JMAPICAL_ERROR_PROPS    4
#define JMAPICAL_ERROR_UID      5

/* Custom iCalendar properties */
#define JMAPICAL_XPROP_LOCATION      "X-JMAP-LOCATION"
/* FIXME libical doesn't parse USEDEFAULTALERTS, must use X-prefix */
#define JMAPICAL_XPROP_USEDEFALERTS  "X-JMAP-USEDEFAULTALERTS"
#define JMAPICAL_XPROP_ATTACH        "X-ATTACH" /* used for DISPLAY/AUDIO VALARMs */

/* Custom iCalendar parameters */
#define JMAPICAL_XPARAM_CID           "X-JMAP-CID"
#define JMAPICAL_XPARAM_DESCRIPTION   "X-JMAP-DESCRIPTION"
#define JMAPICAL_XPARAM_DISPLAY       "X-JMAP-DISPLAY"
#define JMAPICAL_XPARAM_FEATURE       "X-JMAP-FEATURE"
#define JMAPICAL_XPARAM_GEO           "X-JMAP-GEO"
#define JMAPICAL_XPARAM_ID            "X-JMAP-ID"
#define JMAPICAL_XPARAM_LINKID        "X-JMAP-LINKID"
#define JMAPICAL_XPARAM_LOCATIONID    "X-JMAP-LOCATIONID"
#define JMAPICAL_XPARAM_NAME          "X-JMAP-NAME"
#define JMAPICAL_XPARAM_REL           "X-JMAP-REL"
#define JMAPICAL_XPARAM_ROLE          "X-JMAP-ROLE"
#define JMAPICAL_XPARAM_RSVP_URI      "X-JMAP-RSVP-URI"
#define JMAPICAL_XPARAM_TZID          "X-JMAP-TZID"

#define JMAPICAL_XPARAM_DTSTAMP       "X-DTSTAMP" /* used for iMIP ATTENDEE replies */
#define JMAPICAL_XPARAM_SEQUENCE      "X-SEQUENCE" /*used for iMIP ATTENDEE replies */
#define JMAPICAL_XPARAM_TITLE         "X-TITLE" /* Apple uses that for locations */


const char* jmapical_strerror(int err);

typedef struct {
    int code;      /* one of the predefined jmapical error codes, or zero */
    json_t *props; /* erroneous JMAP properties, if any. */
} jmapical_err_t;

/* Converts the iCalendar component ical to JMAP.
 *
 * Does not set the id, calendarId, participantId or any extension properties.
 *
 * ical:  must contain one VEVENT, and any number of recurrences
 * props: optional JSON object whose keys name the properties to be converted
 * err:   optional error receiver
 */
json_t* jmapical_tojmap(icalcomponent *ical, json_t *props, jmapical_err_t *err);

/* Convert the JMAP object obj to iCalendar.
 *
 * ojb:  must contain a JMAP calendar event
 * ical: optional iCalendar VEVENT to mix obj into
 * err:  optional error receiver
 */
icalcomponent* jmapical_toical(json_t *obj, icalcomponent *ical, jmapical_err_t *err);
void icalcomponent_add_required_timezones(icalcomponent *ical);

/* for CalDAV content negotiation */
struct buf *icalcomponent_as_jevent_string(icalcomponent *ical);
icalcomponent *jevent_string_as_icalcomponent(const struct buf *buf);


#ifdef __cplusplus
}
#endif

#endif 
