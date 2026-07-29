/* jmap_ical.c - Common code for JMAP for Calendars */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef JMAPICAL_H
#define JMAPICAL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <jansson.h>
#include <libical/ical.h>

#include "jmap_api.h"
#include "jmap_util.h"


/* Custom iCalendar properties.
 *
 * Note that jscalendar.c defines its own PROP_XJMAP_* names for several of
 * these same X-properties. These are the copies read by the CalDAV and
 * iCalendar support layers. */
#define JMAPICAL_XPROP_ID              "X-JMAP-ID"
#define JMAPICAL_XPROP_SHOWWITHOUTTIME "X-JMAP-SHOW-WITHOUT-TIME"
#define JMAPICAL_XPROP_MAYINVITESELF   "X-JMAP-MAY-INVITE-SELF"
#define JMAPICAL_XPROP_MAYINVITEOTHERS "X-JMAP-MAY-INVITE-OTHERS"
#define JMAPICAL_XPROP_HIDEATTENDEES   "X-JMAP-HIDE-ATTENDEES"
#define JMAPICAL_XPROP_SENTBY          "X-JMAP-SENT-BY"

/* Custom iCalendar parameters */
#define JMAPICAL_XPARAM_ROLE          "X-JMAP-ROLE"

#define JMAPICAL_XPARAM_DTSTAMP       "X-DTSTAMP" /* used for iMIP ATTENDEE replies */
#define JMAPICAL_XPARAM_SEQUENCE      "X-SEQUENCE" /*used for iMIP ATTENDEE replies */

typedef struct jstimezones jstimezones_t;

struct jmapical_ctx {
    jmap_req_t *req;
    struct buf buf;
    struct {
        struct buf url;
        const char *baseurl;
        struct webdav_db *db;
        struct mailbox *mbox;
        int lock;
        int err;
    } attachments;
    struct {
        json_t *serverset;
        json_t *replyto;
        char *emailalert_recipient;
        unsigned ignore_orphan_timezones : 1;
        unsigned no_sanitize_timestamps : 1;
        unsigned allow_method : 1;
    } to_ical;
    struct {
        struct {
            const char *mboxid;
            uint32_t uid;
            const char *partid;
        } cyrus_msg;
        unsigned want_icalprops : 1;
        unsigned dont_guess_timezones : 1;
    } from_ical;
    const strarray_t *schedule_addresses;
    bool (*jsevent_is_origin_cb)(json_t *jsevent, const strarray_t *schedule_addresses);
};

extern struct jmapical_ctx *jmapical_context_new(jmap_req_t *req,
        const strarray_t *schedule_addresses);

extern void jmapical_context_free(struct jmapical_ctx**);

extern int jmapical_context_open_attachments(struct jmapical_ctx *jmapctx);


/* jstimezones allows to resolve standard and non-standard timezone
 * identifiers to ical timezones. It mainly is useful to handle
 * iCalendar data that embeds non-standard VTIMEZONES */
typedef struct jstimezones jstimezones_t;

/* Create a resolver for VTIMEZONEs embedded in VCALENDAR ical.
 * If no_guess is true, then the resolver does not attempt to
 * guess IANA timezone identifiers for non-IANA timezones
 * and preserves them in the custom "cyrusimap.org:timeZones"
 * property in the CalendarEvent */
extern jstimezones_t *jstimezones_new(icalcomponent *ical, int no_guess);

/* Resolve tzid to a timezone.
 *
 * If jstzones is not NULL, first look up the timezones in the custom
 * resolver. If not found, lookup tzid in the standard timezones.
 *
 * Returns NULL if no timezone is found.
 */
extern icaltimezone *jstimezones_lookup_tzid(jstimezones_t* jstzones, const char *tzid);

/* Free a timezone resolver */
extern void jstimezones_free(jstimezones_t **jstzonesptr);

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

/* True if all time components are zero */
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

/* True if all time components are zero */
extern int jmapical_duration_has_zero_time(const struct jmapical_duration *dur);

/* Convert Duration to ical duration, truncating subseconds */
extern struct icaldurationtype jmapical_duration_to_icalduration(const struct jmapical_duration *dur);

/* Convert ical duration to Duration with zero subseconds */
extern void jmapical_duration_from_icalduration(struct icaldurationtype icaldur,
                                                struct jmapical_duration *dur);

/* Convert ical duration property value to Duration with subseconds */
extern int jmapical_duration_from_icalprop(icalproperty *prop, struct jmapical_duration *dur);

/* Calculate time-range between t1 and t2 into Duration dur */
extern void jmapical_duration_between_unixtime(time_t t1, bit64 t1nanos,
                                               time_t t2, bit64 t2nanos,
                                               struct jmapical_duration *dur);

extern void jmapical_duration_between_utctime(const struct jmapical_datetime *t1,
                                              const struct jmapical_datetime *t2,
                                              struct jmapical_duration *dur);

extern void jmapical_duration_as_string(const struct jmapical_duration *dur, struct buf *buf);
extern int jmapical_duration_from_string(const char *val, struct jmapical_duration *dur);

extern void jmapical_remove_peruserprops(json_t *jevent);


#ifdef __cplusplus
}
#endif

#endif 
