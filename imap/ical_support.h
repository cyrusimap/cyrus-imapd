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

#include "mailbox.h"

#define PER_USER_CAL_DATA \
    DAV_ANNOT_NS "<" XML_NS_CYRUS ">per-user-calendar-data"

#ifndef HAVE_VAVAILABILITY
/* Allow us to compile without #ifdef HAVE_VAVAILABILITY everywhere */
#define ICAL_VAVAILABILITY_COMPONENT  ICAL_X_COMPONENT
#define ICAL_XAVAILABLE_COMPONENT     ICAL_X_COMPONENT
#endif

#ifndef HAVE_VPOLL
/* Allow us to compile without #ifdef HAVE_VPOLL everywhere */
#define ICAL_VPOLL_COMPONENT          ICAL_NO_COMPONENT
#define ICAL_VVOTER_COMPONENT         ICAL_X_COMPONENT
#define ICAL_METHOD_POLLSTATUS        ICAL_METHOD_NONE
#define ICAL_VOTER_PROPERTY           ICAL_NO_PROPERTY
#define icalproperty_get_voter        icalproperty_get_attendee
#endif

#ifndef HAVE_VPATCH
/* Allow us to compile without #ifdef HAVE_VPATCH everywhere */
#define ICAL_VPATCH_COMPONENT         ICAL_NO_COMPONENT
#define ICAL_XPATCH_COMPONENT         ICAL_X_COMPONENT
#endif

/* Initialize libical timezones. */
extern void ical_support_init(void);

extern const char *icalparameter_get_value_as_string(icalparameter *param);
extern struct icaldatetimeperiodtype
icalproperty_get_datetimeperiod(icalproperty *prop);
extern time_t icaltime_to_timet(icaltimetype t, const icaltimezone *floatingtz);

/* If range is a NULL period, callback() is executed for ALL occurrences,
   otherwise callback() is only executed for occurrences that overlap the range.
   callback() returns true (1) while it wants more occurrences, 0 to finish */
extern int icalcomponent_myforeach(icalcomponent *comp,
                                   struct icalperiodtype range,
                                   const icaltimezone *floatingtz,
                                   int (*callback) (icalcomponent *comp,
                                                    icaltimetype start,
                                                    icaltimetype end,
                                                    void *data),
                                   void *callback_data);


extern icalcomponent *ical_string_as_icalcomponent(const struct buf *buf);
extern struct buf *my_icalcomponent_as_ical_string(icalcomponent* comp);

extern icalcomponent *record_to_ical(struct mailbox *mailbox,
                                     const struct index_record *record,
                                     char **schedule_userid);

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
                                                            icalcomponent_kind kind);

extern struct icalperiodtype icalrecurrenceset_get_utc_timespan(icalcomponent *ical,
                                                                icalcomponent_kind kind,
                                                                unsigned *is_recurring,
                                                                void (*comp_cb)(icalcomponent*,
                                                                                void*),
                                                                void *cb_rock);

extern void icaltime_set_utc(struct icaltimetype *t, int set);

extern int icalcomponent_apply_vpatch(icalcomponent *ical,
                                      icalcomponent *vpatch,
                                      int *num_changes, const char **errstr);

/* Functions that should be declared in libical */
#define icaltimezone_set_zone_directory set_zone_directory


/* Functions not declared in in libical < v2.0 */

#if !HAVE_DECL_ICAL_STATUS_DELETED
#define ICAL_STATUS_DELETED ICAL_STATUS_CANCELLED
#endif

#if !HAVE_DECL_ICALPROPERTY_GET_PARENT
extern icalcomponent *icalproperty_get_parent(const icalproperty *property);
#endif

#if !HAVE_DECL_ICALRECUR_FREQ_TO_STRING
extern const char *icalrecur_freq_to_string(icalrecurrencetype_frequency kind);
#endif

#if !HAVE_DECL_ICALRECUR_WEEKDAY_TO_STRING
extern const char *icalrecur_weekday_to_string(icalrecurrencetype_weekday kind);
#endif


#ifdef HAVE_TZDIST_PROPS

#define icalcomponent_get_tzuntil_property(comp) \
    icalcomponent_get_first_property(comp, ICAL_TZUNTIL_PROPERTY)

#else /* !HAVE_TZDIST_PROPS */

/* Functions to replace those not available in libical < v2.0 */

#define icalcomponent_get_tzuntil_property(comp) \
    icalcomponent_get_x_property_by_name(comp, "TZUNTIL")

extern icalproperty *icalproperty_new_tzidaliasof(const char *v);
extern icalproperty *icalproperty_new_tzuntil(struct icaltimetype v);

#endif /* HAVE_TZDIST_PROPS */


#ifdef HAVE_VALARM_EXT_PROPS

#define icalcomponent_get_acknowledged_property(comp) \
    icalcomponent_get_first_property(comp, ICAL_ACKNOWLEDGED_PROPERTY)

#else /* !HAVE_VALARM_EXT_PROPS */

/* Functions to replace those not available in libical < v1.0 */

#define icalcomponent_get_acknowledged_property(comp) \
    icalcomponent_get_x_property_by_name(comp, "ACKNOWLEDGED")

extern icalproperty *icalproperty_new_acknowledged(struct icaltimetype v);
extern struct icaltimetype icalproperty_get_acknowledged(const icalproperty *prop);

#endif /* HAVE_VALARM_EXT_PROPS */


#ifndef HAVE_RSCALE

/* Functions to replace those not available in libical < v1.0 */

#define icalrecurrencetype_month_is_leap(month) 0
#define icalrecurrencetype_month_month(month) month

#endif /* HAVE_RSCALE */


#ifdef HAVE_MANAGED_ATTACH_PARAMS

/* Wrappers to fetch managed attachment parameters by kind */

#define icalproperty_get_filename_parameter(prop) \
    icalproperty_get_first_parameter(prop, ICAL_FILENAME_PARAMETER)

#define icalproperty_get_managedid_parameter(prop) \
    icalproperty_get_first_parameter(prop, ICAL_MANAGEDID_PARAMETER)

#define icalproperty_get_size_parameter(prop) \
    icalproperty_get_first_parameter(prop, ICAL_SIZE_PARAMETER)

#elif defined(HAVE_IANA_PARAMS)

/* Functions to replace those not available in libical < v2.0 */

extern icalparameter* icalproperty_get_iana_parameter_by_name(icalproperty *prop,
                                                              const char *name);

extern icalparameter *icalparameter_new_filename(const char *fname);

extern void icalparameter_set_filename(icalparameter *param, const char *fname);

extern icalparameter *icalparameter_new_managedid(const char *id);

extern const char *icalparameter_get_managedid(icalparameter *param);

extern void icalparameter_set_managedid(icalparameter *param, const char *id);

extern icalparameter *icalparameter_new_size(const char *sz);

extern const char *icalparameter_get_size(icalparameter *param);

extern void icalparameter_set_size(icalparameter *param, const char *sz);

/* Wrappers to fetch managed attachment parameters by kind */

#define icalproperty_get_filename_parameter(prop) \
    icalproperty_get_iana_parameter_by_name(prop, "FILENAME")

#define icalproperty_get_managedid_parameter(prop) \
    icalproperty_get_iana_parameter_by_name(prop, "MANAGED-ID")

#define icalproperty_get_size_parameter(prop) \
    icalproperty_get_iana_parameter_by_name(prop, "SIZE")

#else /* !HAVE_IANA_PARAMS */

/* Dummy functions to allow compilation with libical < v0.48 */

#define icalparameter_new_filename(fname) NULL

#define icalparameter_set_filename(param, fname) (void) param

#define icalparameter_new_managedid(id) NULL

#define icalparameter_get_managedid(param) ""

#define icalparameter_set_managedid(param, id) (void) param

#define icalparameter_new_size(sz) NULL

#define icalparameter_set_size(param, sz) (void) param

#define icalproperty_get_filename_parameter(prop) NULL

#define icalproperty_get_managedid_parameter(prop) NULL

#define icalproperty_get_size_parameter(prop) NULL

#endif /* HAVE_MANAGED_ATTACH_PARAMS */


#ifdef HAVE_SCHEDULING_PARAMS

/* Wrappers to fetch scheduling parameters by kind */

#define icalproperty_get_scheduleagent_parameter(prop) \
    icalproperty_get_first_parameter(prop, ICAL_SCHEDULEAGENT_PARAMETER)

#define icalproperty_get_scheduleforcesend_parameter(prop) \
    icalproperty_get_first_parameter(prop, ICAL_SCHEDULEFORCESEND_PARAMETER)

#define icalproperty_get_schedulestatus_parameter(prop) \
    icalproperty_get_first_parameter(prop, ICAL_SCHEDULESTATUS_PARAMETER)

#else /* !HAVE_SCHEDULING_PARAMS */

typedef enum {
    ICAL_SCHEDULEAGENT_X,
    ICAL_SCHEDULEAGENT_SERVER,
    ICAL_SCHEDULEAGENT_CLIENT,
    ICAL_SCHEDULEAGENT_NONE
} icalparameter_scheduleagent;

typedef enum {
    ICAL_SCHEDULEFORCESEND_X,
    ICAL_SCHEDULEFORCESEND_REQUEST,
    ICAL_SCHEDULEFORCESEND_REPLY,
    ICAL_SCHEDULEFORCESEND_NONE
} icalparameter_scheduleforcesend;


#ifdef HAVE_IANA_PARAMS

/* Functions to replace those not available in libical < v1.0 */

extern icalparameter_scheduleagent
icalparameter_get_scheduleagent(icalparameter *param);

extern icalparameter_scheduleforcesend
icalparameter_get_scheduleforcesend(icalparameter *param);

extern icalparameter *icalparameter_new_schedulestatus(const char *stat);

/* Wrappers to fetch scheduling parameters by kind */

#define icalproperty_get_scheduleagent_parameter(prop) \
    icalproperty_get_iana_parameter_by_name(prop, "SCHEDULE-AGENT")

#define icalproperty_get_scheduleforcesend_parameter(prop) \
    icalproperty_get_iana_parameter_by_name(prop, "SCHEDULE-FORCE-SEND")

#define icalproperty_get_schedulestatus_parameter(prop) \
    icalproperty_get_iana_parameter_by_name(prop, "SCHEDULE-STATUS")

#else /* !HAVE_IANA_PARAMS */

/* Dummy functions to allow compilation with libical < v0.48 */

#define icalparameter_get_scheduleagent(param) ICAL_SCHEDULEAGENT_NONE

#define icalparameter_get_scheduleforcesend(param) ICAL_SCHEDULEFORCESEND_NONE

#define icalparameter_new_schedulestatus(stat) NULL; \
    (void) stat  /* silence compiler */

#define icalproperty_get_scheduleagent_parameter(prop) NULL

#define icalproperty_get_scheduleforcesend_parameter(prop) NULL

#define icalproperty_get_schedulestatus_parameter(prop) NULL

#endif /* HAVE_IANA_PARAMS */

#endif /* HAVE_SCHEDULING_PARAMS */

#endif /* HAVE_ICAL */

#endif /* ICAL_SUPPORT_H */
