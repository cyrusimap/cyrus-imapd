/* ical_support.h -- Helper functions for libical */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef ICAL_SUPPORT_H
#define ICAL_SUPPORT_H

#include <config.h>

#ifdef HAVE_ICAL

#include <libical/ical.h>
#undef icalerror_warn
#define icalerror_warn(message) \
{syslog(LOG_WARNING, "icalerror: %s(), %s:%d: %s", __FUNCTION__, __FILE__, __LINE__, message);}

#include "dav_util.h"
#include "mailbox.h"

#define ICALENDAR_CONTENT_TYPE "text/calendar; charset=utf-8"

#define PER_USER_CAL_DATA                                       \
    DAV_ANNOT_NS "<" XML_NS_CYRUS ">per-user-calendar-data"

typedef struct icalrecurrencetype icalrecurrencetype_t;

extern icalrecurrencetype_t *icalvalue_get_recurrence(const icalvalue *val);

#define icalproperty_get_recurrence(prop)                       \
    icalvalue_get_recurrence(icalproperty_get_value(prop))

#define icalproperty_set_recurrence(prop, rt)                   \
    icalproperty_set_value(prop, icalvalue_new_recurrence(rt))

#ifdef HAVE_RECUR_BY_REF
#define ICAL_RECURRENCE_ARRAY_MAX            0x7f7f
#define icalrecurrence_iterator_new(rt, tt)  icalrecur_iterator_new(rt, tt)
#define icalvalue_new_recurrence(rt)         icalvalue_new_recur(rt)
#define icalvalue_set_recurrence(val, rt)    icalvalue_set_recur(val, rt)
#define icalrecur_byrule_size(rt, rule)      (rt->by[rule].size)
#define icalrecur_byrule_data(rt, rule)      (rt->by[rule].data)

#else /* !HAVE_RECUR_BY_REF */
typedef enum icalrecurrencetype_byrule
{
    ICAL_BY_MONTH = 0,
    ICAL_BY_WEEK_NO,
    ICAL_BY_YEAR_DAY,
    ICAL_BY_MONTH_DAY,
    ICAL_BY_DAY,
    ICAL_BY_HOUR,
    ICAL_BY_MINUTE,
    ICAL_BY_SECOND,
    ICAL_BY_SET_POS,

    ICAL_BY_NUM_PARTS
} icalrecurrencetype_byrule;

#define icalrecurrence_iterator_new(rt, tt)  icalrecur_iterator_new(*(rt), tt)
#define icalvalue_new_recurrence(rt)         icalvalue_new_recur(*(rt))
#define icalvalue_set_recurrence(val, rt)    icalvalue_set_recur(val, *(rt))

extern icalrecurrencetype_t *icalrecurrencetype_new(void);
extern icalrecurrencetype_t *icalrecurrencetype_clone(icalrecurrencetype_t *rt);
extern icalrecurrencetype_t *icalrecurrencetype_new_from_string(const char *str);
extern void icalrecurrencetype_unref(icalrecurrencetype_t *rt);
extern short *icalrecur_byrule_data(icalrecurrencetype_t *rt,
                                    icalrecurrencetype_byrule rule);
extern short icalrecur_byrule_size(icalrecurrencetype_t *rt,
                                   icalrecurrencetype_byrule rule);
#endif /* HAVE_RECUR_BY_REF */

#ifdef HAVE_PARTTYPE_VOTER
#define HAVE_VPOLL_SUPPORT
#endif

#ifndef HAVE_NEW_CLONE_API
/* Allow us to compile without #ifdef HAVE_NEW_CLONE_API everywhere */
#define icalcomponent_clone           icalcomponent_new_clone
#define icalproperty_clone            icalproperty_new_clone
#define icalparameter_clone           icalparameter_new_clone
#endif

#ifndef HAVE_GET_COMPONENT_NAME
/* This should never match anything in the wild
   which means that we can't patch X- components */
#define icalcomponent_get_component_name(comp)  "X-CYR-"
#endif

/* Initialize libical timezones. */
extern void ical_support_init(void);

extern int cyrus_icalrestriction_check(icalcomponent *ical);

extern const char *icalparameter_get_value_as_string(icalparameter *param);
extern struct icaldatetimeperiodtype
icalproperty_get_datetimeperiod(icalproperty *prop);
extern time_t icaltime_to_timet(icaltimetype t, const icaltimezone *floatingtz);
extern void icalproperty_set_xparam(icalproperty *prop,
                                    const char *name, const char *val, int replace);
extern const char *icalproperty_get_xparam_value(icalproperty *prop,
                                                 const char *name);


/* Strip per-user data to personalize iCalendar resource.
 *
 * COLOR and CATEGORIES properties are not stripped.
 * Instead, they are added to the per-user VPATCH when the
 * user overwrites them in their copy of the resource.
 */
#define ICAL_PERSONAL_DATA_INITIALIZER         \
    "CALDATA %(VPATCH {324+}\r\n"         \
    "BEGIN:VPATCH\r\n"                    \
    "VERSION:1\r\n"                       \
    "DTSTAMP:19760401T005545Z\r\n"        \
    "UID:strip-owner-cal-data\r\n"        \
    "BEGIN:PATCH\r\n"                     \
    "PATCH-TARGET:/VCALENDAR/ANY\r\n"     \
    "PATCH-DELETE:/VALARM\r\n"            \
    "PATCH-DELETE:#TRANSP\r\n"            \
    "PATCH-DELETE:#X-MOZ-LASTACK\r\n"     \
    "PATCH-DELETE:#X-MOZ-SNOOZE-TIME\r\n" \
    "PATCH-DELETE:#X-APPLE-DEFAULT-ALARM\r\n" \
    "PATCH-DELETE:#X-JMAP-USEDEFAULTALERTS\r\n" \
    "END:PATCH\r\n"                       \
    "END:VPATCH\r\n)"

extern void icalcomponent_add_personal_data(icalcomponent *ical, struct buf *userdata);
extern void icalcomponent_add_personal_data_from_dl(icalcomponent *ical, struct dlist *dl);

struct icalsupport_personal_data {
    time_t lastmod;
    modseq_t modseq;
    int usedefaultalerts;
    icalcomponent *vpatch;
    struct message_guid guid; // read-only
};

extern int icalsupport_encode_personal_data(struct buf *value,
                                            struct icalsupport_personal_data *data);

extern int icalsupport_decode_personal_data(const struct buf *value,
                                            struct icalsupport_personal_data *data);

extern void icalsupport_personal_data_fini(struct icalsupport_personal_data *data);

extern int icalcomponent_get_usedefaultalerts(icalcomponent *comp);
extern void icalcomponent_set_usedefaultalerts(icalcomponent *comp, int use, const char *atag);


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
                                                    int is_standalone,
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

#define ICAL_SUPPORT_STRICT 0
#define ICAL_SUPPORT_ALLOW_INVALID_IANA_TIMEZONE (1<<0)
extern const char *get_icalcomponent_errstr(icalcomponent *ical, unsigned flags);

extern void icalcomponent_remove_invitee(icalcomponent *comp,
                                         icalproperty *prop);
extern icalproperty *icalcomponent_get_first_invitee(icalcomponent *comp);
extern icalproperty *icalcomponent_get_next_invitee(icalcomponent *comp);
extern const char *icalproperty_get_invitee(icalproperty *prop);
extern const char *icalproperty_get_decoded_calendaraddress(icalproperty *prop);

extern icaltimetype icalcomponent_get_recurrenceid_with_zone(icalcomponent *c);

extern icalproperty *icalcomponent_get_x_property_by_name(icalcomponent *comp,
                                                          const char *name);

extern void icalcomponent_remove_x_property_by_name(icalcomponent *comp,
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
                                                     struct observance *proleptic,
                                                     icalcomponent **eternal_std,
                                                     icalcomponent **eternal_dst,
                                                     icaltimetype *last_dtstart,
                                                     int ms_compatible);

extern int ical_categories_is_color(icalproperty *cprop);

/* Normalizes both standard and cyrus-extensions */
extern void icalcomponent_normalize_x(icalcomponent *ical);

/* Returns true if the component's main temporal such as dtstart is of type DATE */
extern int icalcomponent_temporal_is_date(icalcomponent *comp);

#ifdef WITH_JMAP
extern const char *icalcomponent_get_jmapid(icalcomponent *comp);
extern void icalcomponent_set_jmapid(icalcomponent *comp, const char *id);
#endif

/* Functions that should be declared in libical */

#define icalcomponent_get_tzuntil_property(comp) \
    icalcomponent_get_first_property(comp, ICAL_TZUNTIL_PROPERTY)

#define icalcomponent_get_acknowledged_property(comp) \
    icalcomponent_get_first_property(comp, ICAL_ACKNOWLEDGED_PROPERTY)

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

#ifdef HAVE_LIBICALVCARD

#include <libical/vcard.h>

/**
 * Looks up a property parameter by name.
 *
 * @param prop   The vCard property.
 * @param name   The name of the parameter to look up.
 *
 * This function looks up and returns the first property parameter
 * having the same name as @p name. The name is compared case-insensitively.
 *
 * @return The parameter, or NULL otherwise.
 */
extern vcardparameter *vcardproperty_get_parameter_by_name(vcardproperty *prop,
                                                           const char *name);
#endif /* HAVE_LIBICALVCARD */

#endif /* ICAL_SUPPORT_H */
