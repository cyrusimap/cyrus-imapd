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

#include "jmap_util.h"

#define JMAPICAL_ERROR_UNKNOWN  -1
#define JMAPICAL_ERROR_CALLBACK 1
#define JMAPICAL_ERROR_MEMORY   2
#define JMAPICAL_ERROR_ICAL     3
#define JMAPICAL_ERROR_PROPS    4
#define JMAPICAL_ERROR_UID      5

/* Custom iCalendar properties */
#define JMAPICAL_XPROP_LOCATION      "X-JMAP-LOCATION"

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
#define JMAPICAL_XPARAM_COMMENT       "X-COMMENT" /*used for iMIP ATTENDEE replies */
#define JMAPICAL_XPARAM_TITLE         "X-TITLE" /* Apple uses that for locations */
#define JMAPICAL_XPARAM_ISDEFAULT     "X-IS-DEFAULT" /* Prop value is default */

struct jmapical_jmapcontext {
    void (*blobid_from_href)(struct buf *blobid,
                             const char *href,
                             const char *managedid,
                             void *rock);
    void (*href_from_blobid)(struct buf *href,
                             struct buf *managedid,
                             const char *blobid,
                             void *rock);
    char *emailalert_defaultrecipient;
    void *rock;
};


/* Converts the iCalendar component ical to JSCalendar.
 * Returns NULL on error.
 */
json_t* jmapical_tojmap(icalcomponent *ical, hash_table *props,
                        struct jmapical_jmapcontext *jmapctx);

/* Converts the iCalendar component ical to an array of JSCalendar objects.
 * Returns NULL on error.
 */
json_t *jmapical_tojmap_all(icalcomponent *ical, hash_table *props,
                            struct jmapical_jmapcontext *jmapctx);

/* Convert the jsevent to iCalendar.
 * The oldical argument points to the previous VCALENDAR of the event,
 * or NULL.
 * Returns a new ical component, or NULL on error.
 */
icalcomponent* jmapical_toical(json_t *jsevent, icalcomponent *oldical,
			       json_t *invalid,
                               struct jmapical_jmapcontext *jmapctx);


/* Convert the iCalendar VALARM to a JSCalendar Alert.
 * Return NULL on error. */
json_t *jmapical_alert_from_ical(icalcomponent *valarm);

/* Convert alert to iCalendar VALARM. Returns NULL on error */
extern icalcomponent *jmapical_alert_to_ical(json_t *alert, struct jmap_parser *parser,
                                             const char *alert_uid,
                                             const char *description,
                                             const char *email_summary,
                                             const char *email_recipient);


void icalcomponent_add_required_timezones(icalcomponent *ical);

/* for CalDAV content negotiation */
struct buf *icalcomponent_as_jevent_string(icalcomponent *ical);
icalcomponent *jevent_string_as_icalcomponent(const struct buf *buf);

/* Base type for JSCalendar LocalDateTime and UTCDateTime */

struct jmapical_datetime {
    int year;
    int month; // Jan=1
    int day;
    int hour;
    int minute;
    int second;
    bit64 nano;
};

#define JMAPICAL_DATETIME_INITIALIZER { 0, 0, 0, 0, 0, 0, 0 }

/* True if all components are zero */
extern int jmapical_datetime_has_zero_time(const struct jmapical_datetime *dt);

/* Convert DateTime to ical date, truncating time components */
extern struct icaltimetype jmapical_datetime_to_icaldate(const struct jmapical_datetime *dt);

/* Convert DateTime to ical time, truncating subseconds */
extern icaltimetype jmapical_datetime_to_icaltime(const struct jmapical_datetime *dt,
                                                  const icaltimezone* zone);

/* Convert ical time to DateTime with zero subseconds  */
extern void jmapical_datetime_from_icaltime(icaltimetype icaldt, struct jmapical_datetime *dt);

/* Compare DateTime a and b, using semantics suitable for qsort */
extern int jmapical_datetime_compare(const struct jmapical_datetime *a,
                                     const struct jmapical_datetime *b);

/* Convert icaltime value and subseconds parameter to DateTime */
extern int jmapical_datetime_from_icalprop(icalproperty *prop, struct jmapical_datetime *dt);

/* JSCalendar LocalDateTime */
extern void jmapical_localdatetime_as_string(const struct jmapical_datetime *dt, struct buf *dst);
extern int jmapical_localdatetime_from_string(const char *val, struct jmapical_datetime *dt);

/* JSCalendar UTCDateTime */
extern void jmapical_utcdatetime_as_string(const struct jmapical_datetime *dt, struct buf *dst);
extern int jmapical_utcdatetime_from_string(const char *val, struct jmapical_datetime *dt);

/* JSCalendar Duration */

struct jmapical_duration {
    int is_neg;
    unsigned int days;
    unsigned int weeks;
    unsigned int hours;
    unsigned int minutes;
    unsigned int seconds;
    bit64 nanos;
};

#define JMAPICAL_DURATION_INITIALIZER { 0, 0, 0, 0, 0, 0, 0 }

/* True if all components are zero */
extern int jmapical_duration_has_zero_time(const struct jmapical_duration *dur);

/* Convert Duration to ical duration, truncating subseconds */
extern struct icaldurationtype jmapical_duration_to_icalduration(const struct jmapical_duration *dur);

/* Convert ical duration to Duration with zero subseconds */
extern void jmapical_duration_from_icalduration(struct icaldurationtype icaldur,
                                                struct jmapical_duration *dur);

/* Calculate time-range between t1 and t2 into Duration dur */
extern void jmapical_duration_between_unixtime(time_t t1, bit64 t1nanos,
                                               time_t t2, bit64 t2nanos,
                                               struct jmapical_duration *dur);

extern void jmapical_duration_between_utctime(const struct jmapical_datetime *t1,
                                              const struct jmapical_datetime *t2,
                                              struct jmapical_duration *dur);

extern void jmapical_duration_as_string(const struct jmapical_duration *dur, struct buf *buf);
extern int jmapical_duration_from_string(const char *val, struct jmapical_duration *dur);

#ifdef __cplusplus
}
#endif

#endif 
