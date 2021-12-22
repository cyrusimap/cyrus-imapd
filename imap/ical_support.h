/* ical_support.h -- Helper functions for libical
 *
 * Copyright (c) 1994-2015 Carnegie Mellon University.  All rights reserved.
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

#ifndef ICAL_SUPPORT_H
#define ICAL_SUPPORT_H

#include <config.h>

#ifdef HAVE_ICAL

#include <libical/ical.h>
#undef icalerror_warn
#define icalerror_warn(message) \
{syslog(LOG_WARNING, "icalerror: %s(), %s:%d: %s", __FUNCTION__, __FILE__, __LINE__, message);}

#include "mailbox.h"

#define ICALENDAR_CONTENT_TYPE "text/calendar; charset=utf-8"

#define PER_USER_CAL_DATA                                       \
    DAV_ANNOT_NS "<" XML_NS_CYRUS ">per-user-calendar-data"

#ifndef HAVE_NEW_CLONE_API
/* Allow us to compile without #ifdef HAVE_NEW_CLONE_API everywhere */
#define icalcomponent_clone           icalcomponent_new_clone
#define icalproperty_clone            icalproperty_new_clone
#define icalparameter_clone           icalparameter_new_clone
#endif

/* Initialize libical timezones. */
extern void ical_support_init(void);

extern int cyrus_icalrestriction_check(icalcomponent *ical);

extern const char *icalparameter_get_value_as_string(icalparameter *param);
extern struct icaldatetimeperiodtype
icalproperty_get_datetimeperiod(icalproperty *prop);
extern time_t icaltime_to_timet(icaltimetype t, const icaltimezone *floatingtz);
extern void icalproperty_set_xparam(icalproperty *prop,
                                    const char *name, const char *val, int purge);

/* Returns if default alerts are explicitly enabled (1) or disabled (0).
   Returns -1 otherwise. */
extern int icalcomponent_read_usedefaultalerts(icalcomponent *comp);

/* Adds default alerts to ical, if either the X-USE-DEFAULTALERTS property
 * is set to TRUE, or force is non-zero. */
extern void icalcomponent_add_defaultalerts(icalcomponent *ical,
                                            icalcomponent *alarms_withtime,
                                            icalcomponent *alarms_withdate,
                                            int force);

/* If range is a NULL period, callback() is executed for ALL occurrences,
   otherwise callback() is only executed for occurrences that overlap the range.
   callback() returns true (1) while it wants more occurrences, 0 to finish.
   If comp is a VCALENDAR then in addition to the main component, any embedded
   component with RECURRENCE-ID is included in the occurrences.
   If comp is a VEVENT or similar, only RRULE and RDATEs are considered. */
extern int icalcomponent_myforeach(icalcomponent *comp,
                                   struct icalperiodtype range,
                                   const icaltimezone *floatingtz,
                                   int (*callback) (icalcomponent *comp,
                                                    icaltimetype start,
                                                    icaltimetype end,
                                                    icaltimetype recurid,
                                                    void *data),
                                   void *callback_data);


extern icalcomponent *icalcomponent_new_stream(struct mailbox *mailbox,
                                               const char *prodid,
                                               const char *name,
                                               const char *desc,
                                               const char *color);

extern icalcomponent *ical_string_as_icalcomponent(const struct buf *buf);
extern struct buf *my_icalcomponent_as_ical_string(icalcomponent* comp);

extern icalcomponent *record_to_ical(struct mailbox *mailbox,
                                     const struct index_record *record,
                                     strarray_t *schedule_addresses);

extern const char *get_icalcomponent_errstr(icalcomponent *ical);

extern void icalcomponent_remove_invitee(icalcomponent *comp,
                                         icalproperty *prop);
extern icalproperty *icalcomponent_get_first_invitee(icalcomponent *comp);
extern icalproperty *icalcomponent_get_next_invitee(icalcomponent *comp);
extern const char *icalproperty_get_invitee(icalproperty *prop);

extern icaltimetype icalcomponent_get_recurrenceid_with_zone(icalcomponent *c);

extern icalproperty *icalcomponent_get_x_property_by_name(icalcomponent *comp,
                                                          const char *name);

extern struct icalperiodtype icalcomponent_get_utc_timespan(icalcomponent *comp,
                                                            icalcomponent_kind kind,
                                                            icaltimezone *floating_tz);

extern struct icalperiodtype icalrecurrenceset_get_utc_timespan(icalcomponent *ical,
                                                                icalcomponent_kind kind,
                                                                icaltimezone *floating_tz,
                                                                unsigned *is_recurring,
                                                                void (*comp_cb)(icalcomponent*,
                                                                                void*),
                                                                void *cb_rock);

extern void icaltime_set_utc(struct icaltimetype *t, int set);
extern icaltimetype icaltime_convert_to_utc(const struct icaltimetype tt,
                                            icaltimezone *floating_zone);

extern int icalcomponent_apply_vpatch(icalcomponent *ical,
                                      icalcomponent *vpatch,
                                      int *num_changes, const char **errstr);

/* Functions to work around libical TZID prefixes */
extern const char *icaltimezone_get_location_tzid(const icaltimezone *zone);
extern const char *icaltime_get_location_tzid(icaltimetype t);

extern icaltimezone *icaltimezone_get_cyrus_timezone_from_tzid(const char *tzid);

struct observance {
    const char *name;
    icaltimetype onset;
    int offset_from;
    int offset_to;
    int is_daylight;
    int is_std;
    int is_gmt;
};

extern void icaltimezone_truncate_vtimezone_advanced(icalcomponent *vtz,
                                                     icaltimetype *startp, icaltimetype *endp,
                                                     icalarray *obsarray,
                                                     struct observance **proleptic,
                                                     icalcomponent **eternal_std,
                                                     icalcomponent **eternal_dst,
                                                     icaltimetype *last_dtstart,
                                                     int ms_compatible);

/* Functions that should be declared in libical */
#define icaltimezone_set_zone_directory set_zone_directory

#define icalcomponent_get_tzuntil_property(comp) \
    icalcomponent_get_first_property(comp, ICAL_TZUNTIL_PROPERTY)

#define icalcomponent_get_acknowledged_property(comp) \
    icalcomponent_get_first_property(comp, ICAL_ACKNOWLEDGED_PROPERTY)

#ifndef HAVE_RFC7986_COLOR

/* Replacement for missing function in 3.0.0 <= libical < 3.0.5 */

extern icalproperty *icalproperty_new_color(const char *v);

#endif /* HAVE_RFC7986_COLOR */

#ifndef HAVE_RSCALE

/* Functions to replace those not available in libical < v1.0 */

#define icalrecurrencetype_month_is_leap(month) 0
#define icalrecurrencetype_month_month(month) month

#endif /* HAVE_RSCALE */


/* Wrappers to fetch managed attachment parameters by kind */

#define icalproperty_get_filename_parameter(prop) \
    icalproperty_get_first_parameter(prop, ICAL_FILENAME_PARAMETER)

#define icalproperty_get_managedid_parameter(prop) \
    icalproperty_get_first_parameter(prop, ICAL_MANAGEDID_PARAMETER)

#define icalproperty_get_size_parameter(prop) \
    icalproperty_get_first_parameter(prop, ICAL_SIZE_PARAMETER)

/* Wrappers to fetch scheduling parameters by kind */

#define icalproperty_get_scheduleagent_parameter(prop) \
    icalproperty_get_first_parameter(prop, ICAL_SCHEDULEAGENT_PARAMETER)

#define icalproperty_get_scheduleforcesend_parameter(prop) \
    icalproperty_get_first_parameter(prop, ICAL_SCHEDULEFORCESEND_PARAMETER)

#define icalproperty_get_schedulestatus_parameter(prop) \
    icalproperty_get_first_parameter(prop, ICAL_SCHEDULESTATUS_PARAMETER)

#endif /* HAVE_ICAL */

#endif /* ICAL_SUPPORT_H */
