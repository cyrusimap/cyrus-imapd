/* ical_support.c -- Helper functions for libical
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

#include <config.h>

#include <string.h>

#include "caldav_db.h"
#include "ical_support.h"
#include "message.h"
#include "util.h"

#ifdef HAVE_ICAL

#if (SIZEOF_TIME_T > 4)
static time_t epoch    = (time_t) LONG_MIN;
static time_t eternity = (time_t) LONG_MAX;
#else
static time_t epoch    = (time_t) INT_MIN;
static time_t eternity = (time_t) INT_MAX;
#endif

struct recurrence_data {
    icalcomponent *comp;
    icaltimetype dtstart;
    icaltimetype dtend;
    icaltime_span span; /* for sorting, etc */
};

const char *icalparameter_get_value_as_string(icalparameter *param)
{
    char *buf;

    buf = icalparameter_as_ical_string_r(param);
    icalmemory_add_tmp_buffer(buf);

    buf = strchr(buf, '=');
    if (*++buf == '"') *(strchr(++buf, '"')) = '\0';
    return buf;
}

EXPORTED struct icaldatetimeperiodtype
icalproperty_get_datetimeperiod(icalproperty *prop)
{
    struct icaldatetimeperiodtype ret = { icaltime_null_time(),
                                          icalperiodtype_null_period() };
    if (!prop) return ret;

    ret = icalvalue_get_datetimeperiod(icalproperty_get_value(prop));

    icalparameter *param =
        icalproperty_get_first_parameter(prop, ICAL_TZID_PARAMETER);

    if (param) {
        const char *tzid = icalparameter_get_tzid(param);
        icaltimezone *tz = NULL;

        icalcomponent *c;
        for (c = icalproperty_get_parent(prop); c != NULL;
             c = icalcomponent_get_parent(c)) {
            tz = icalcomponent_get_timezone(c, tzid);
            if (tz != NULL)
                break;
        }

        if (tz == NULL)
            tz = icaltimezone_get_builtin_timezone_from_tzid(tzid);

        if (tz != NULL) {
            if (icalperiodtype_is_null_period(ret.period))
                ret.time = icaltime_set_timezone(&ret.time, tz);
            else {
                ret.period.start = icaltime_set_timezone(&ret.period.start, tz);
                if (icaldurationtype_is_null_duration(ret.period.duration))
                    ret.period.end = icaltime_set_timezone(&ret.period.end, tz);
            }
        }
    }

    return ret;
}


static int sort_overrides(const void *ap, const void *bp)
{
    struct recurrence_data *a = (struct recurrence_data *)ap;
    struct recurrence_data *b = (struct recurrence_data *)bp;

    return (a->span.start - b->span.start);
}

static struct recurrence_data *_add_override(icalarray *array,
                                             icaltimetype dtstart,
                                             icaltimetype dtend,
                                             icalcomponent *comp,
                                             const icaltimezone *floatingtz)
{
    struct recurrence_data *data = NULL;
    size_t i;

    time_t start = icaltime_to_timet(dtstart, floatingtz);
    time_t end = icaltime_to_timet(dtend, floatingtz);

    for (i = 0; i < array->num_elements; i++) {
        struct recurrence_data *item = icalarray_element_at(array, i);
        if (item->span.start != start) continue;
        data = item;
        break;
    }

    if (!data) {
        struct recurrence_data new;
        icalarray_append(array, &new);
        data = icalarray_element_at(array, i);
    }

    data->span.start = start;
    data->dtstart = dtstart;
    data->span.end = end;
    data->dtend = dtend;
    data->comp = comp;

    return data;
}

EXPORTED time_t icaltime_to_timet(icaltimetype t, const icaltimezone *floatingtz)
{
    if (icaltime_is_null_time(t))
        return 0;

    const icaltimezone *zone = floatingtz;

    if (icaltime_is_utc(t))
        zone = icaltimezone_get_utc_timezone();
    else if (t.zone)
        zone = t.zone;

    if (!zone) zone = icaltimezone_get_utc_timezone();

    return icaltime_as_timet_with_zone(t, zone);
}

static int span_compare_range(icaltime_span *span, icaltime_span *range)
{
    if (span->start >= range->end) return 1;  /* span starts later than range */
    if (span->end <= range->start) return -1; /* span ends earlier than range */
    return 0; /* span overlaps range */
}

EXPORTED extern int icalcomponent_myforeach(icalcomponent *ical,
                                   struct icalperiodtype range,
                                   const icaltimezone *floatingtz,
                                   int (*callback) (icalcomponent *comp,
                                                    icaltimetype start,
                                                    icaltimetype end,
                                                    void *data),
                                   void *callback_data)
{
    icalarray *overrides = icalarray_new(sizeof(struct recurrence_data), 16);
    struct icaldurationtype event_length = icaldurationtype_null_duration();
    struct icaltimetype dtstart = icaltime_null_time();
    icaltime_span range_span = {
        icaltime_to_timet(range.start, NULL),
        icaltime_to_timet(range.end, NULL), 0 /* is_busy */
    };

    if (!range_span.start) range_span.start = epoch;
    if (!range_span.end) {
        if (!icaldurationtype_is_null_duration(range.duration)) {
            icaltimetype end = icaltime_add(range.start, range.duration);
            range_span.end = icaltime_to_timet(end, NULL);
        }
        else range_span.end = eternity;
    }

    icalcomponent *mastercomp = NULL, *comp;

    switch (icalcomponent_isa(ical)) {
    case ICAL_VCALENDAR_COMPONENT:
        comp = icalcomponent_get_first_real_component(ical);
        break;

    case ICAL_VAVAILABILITY_COMPONENT:
        comp = icalcomponent_get_first_component(ical, ICAL_XAVAILABLE_COMPONENT);
        break;

    default:
        comp = ical;
        break;
    }

    icalcomponent_kind kind = icalcomponent_isa(comp);

    /* find the master component */
    for (; comp; comp = icalcomponent_get_next_component(ical, kind)) {
        icalproperty *prop =
            icalcomponent_get_first_property(comp, ICAL_RECURRENCEID_PROPERTY);
        if (prop) continue;
        mastercomp = comp;
        break;
    }

    /* find event length first, we'll need it for overrides */
    if (mastercomp) {
        dtstart = icalcomponent_get_dtstart(mastercomp);
        event_length = icalcomponent_get_duration(mastercomp);
        if (icaldurationtype_is_null_duration(event_length) &&
            icaltime_is_date(dtstart)) {
            event_length = icaldurationtype_from_int(60 * 60 * 24);  /* P1D */
        }

        /* add any RDATEs first, since EXDATE items can override them */
        icalproperty *prop;
        for (prop = icalcomponent_get_first_property(mastercomp,
                                                     ICAL_RDATE_PROPERTY);
             prop;
             prop = icalcomponent_get_next_property(mastercomp,
                                                    ICAL_RDATE_PROPERTY)) {
            struct icaldatetimeperiodtype rdate =
                icalproperty_get_datetimeperiod(prop);
            icaltimetype mystart = rdate.time;
            icaltimetype myend = rdate.time;
            if (icalperiodtype_is_null_period(rdate.period)) {
                myend = icaltime_add(mystart, event_length);
            }
            else {
                mystart = rdate.period.start;
                if (icaldurationtype_is_null_duration(rdate.period.duration))
                    myend = rdate.period.end;
                else
                    myend = icaltime_add(mystart, rdate.period.duration);
            }
            if (icaltime_is_null_time(mystart))
                continue;

            _add_override(overrides, mystart, myend, mastercomp, floatingtz);
        }

        /* track any EXDATEs */
        for (prop = icalcomponent_get_first_property(mastercomp,
                                                     ICAL_EXDATE_PROPERTY);
             prop;
             prop = icalcomponent_get_next_property(mastercomp,
                                                    ICAL_EXDATE_PROPERTY)) {
            struct icaltimetype exdate = icalproperty_get_exdate(prop);
            _add_override(overrides, exdate, exdate, NULL, floatingtz);
        }
    }

    /* finally, add any RECURRENCE-ID overrides
       Per Cyrus Daboo, these should probably supercede EXDATEs
       (don't throw away potentially valid data)
    */
    for (comp = icalcomponent_get_first_component(ical, kind);
         comp;
         comp = icalcomponent_get_next_component(ical, kind)) {
        struct icaltimetype recur =
            icalcomponent_get_recurrenceid_with_zone(comp);
        if (icaltime_is_null_time(recur)) continue;

        /* this is definitely a recurrence override */
        struct icaltimetype mystart = icalcomponent_get_dtstart(comp);
        struct icaltimetype myend = icalcomponent_get_dtend(comp);

        if (icaltime_compare(mystart, recur)) {
            /* DTSTART has changed: add an exception for RECURRENCE-ID */
            _add_override(overrides, recur, recur, NULL, floatingtz);
        }
        _add_override(overrides, mystart, myend, comp, floatingtz);
    }

    /* sort all overrides in order */
    icalarray_sort(overrides, sort_overrides);

    /* now we can do the RRULE, because we have all overrides */
    icalrecur_iterator *rrule_itr = NULL;
    if (mastercomp) {
        icalproperty *rrule =
            icalcomponent_get_first_property(mastercomp, ICAL_RRULE_PROPERTY);
        if (rrule) {
            struct icalrecurrencetype recur = icalproperty_get_rrule(rrule);

            /* check if span of RRULE overlaps range */
            icaltime_span recur_span = {
                icaltime_to_timet(dtstart, floatingtz),
                icaltime_to_timet(recur.until, NULL), 0 /* is_busy */
            };
            if (!recur_span.end) recur_span.end = eternity;

            if (!span_compare_range(&recur_span, &range_span)) {
                rrule_itr = icalrecur_iterator_new(recur, dtstart);
#ifdef HAVE_RECUR_ITERATOR_START
                if (icaltime_compare(range.start, dtstart) > 0) {
                    icalrecur_iterator_set_start(rrule_itr, range.start);
                }
#endif
            }
        }
    }

    size_t onum = 0;
    struct recurrence_data *data = overrides->num_elements ?
        icalarray_element_at(overrides, onum) : NULL;
    struct icaltimetype ritem = rrule_itr ?
        icalrecur_iterator_next(rrule_itr) : dtstart;

    while (data || !icaltime_is_null_time(ritem)) {
        time_t otime = data ? data->span.start : eternity;
        time_t rtime = icaltime_to_timet(ritem, floatingtz);

        if (icaltime_is_null_time(ritem) || (data && otime <= rtime)) {
            /* an overridden recurrence */
            if (data->comp &&
                !span_compare_range(&data->span, &range_span) &&
                !callback(data->comp, data->dtstart, data->dtend, callback_data))
                goto done;

            /* if they're both the same time, it's a precisely overridden
             * recurrence, so increment both */
            if (rtime == otime) {
                /* incr recurrences */
                ritem = rrule_itr ?
                    icalrecur_iterator_next(rrule_itr) : icaltime_null_time();
            }

            /* incr overrides */
            onum++;
            data = (onum < overrides->num_elements) ?
                icalarray_element_at(overrides, onum) : NULL;
        }
        else {
            /* a non-overridden recurrence */
            struct icaltimetype thisend = icaltime_add(ritem, event_length);
            icaltime_span this_span = {
                rtime, icaltime_to_timet(thisend, floatingtz), 0 /* is_busy */
            };
            int r = span_compare_range(&this_span, &range_span);

            if (r > 0 || /* gone past the end of range */
                (!r && !callback(mastercomp, ritem, thisend, callback_data)))
                goto done;

            /* incr recurrences */
            ritem = rrule_itr ?
                icalrecur_iterator_next(rrule_itr) : icaltime_null_time();
        }
    }

 done:
    if (rrule_itr) icalrecur_iterator_free(rrule_itr);

    icalarray_free(overrides);

    return 0;
}


EXPORTED icalcomponent *ical_string_as_icalcomponent(const struct buf *buf)
{
    return icalparser_parse_string(buf_cstring(buf));
}

EXPORTED struct buf *my_icalcomponent_as_ical_string(icalcomponent* comp)
{
    char *str = icalcomponent_as_ical_string_r(comp);
    struct buf *ret = buf_new();

    buf_initm(ret, str, strlen(str));

    return ret;
}

EXPORTED icalcomponent *record_to_ical(struct mailbox *mailbox,
                              const struct index_record *record,
                              char **schedule_userid)
{
    icalcomponent *ical = NULL;
    message_t *m = message_new_from_record(mailbox, record);
    struct buf buf = BUF_INITIALIZER;

    /* Load message containing the resource and parse iCal data */
    if (!message_get_field(m, "rawbody", MESSAGE_RAW, &buf)) {
        ical = icalparser_parse_string(buf_cstring(&buf));
    }

    /* extract the schedule user header */
    if (schedule_userid) {
        buf_reset(&buf);
        if (!message_get_field(m, "x-schedule-user-address",
                               MESSAGE_DECODED|MESSAGE_TRIM, &buf)) {
            if (buf.len) *schedule_userid = buf_release(&buf);
        }
    }

    buf_free(&buf);
    message_unref(&m);
    return ical;
}

EXPORTED const char *get_icalcomponent_errstr(icalcomponent *ical)
{
    icalcomponent *comp;

    for (comp = icalcomponent_get_first_component(ical, ICAL_ANY_COMPONENT);
         comp;
         comp = icalcomponent_get_next_component(ical, ICAL_ANY_COMPONENT)) {
        icalproperty *prop;

        for (prop = icalcomponent_get_first_property(comp, ICAL_ANY_PROPERTY);
             prop;
             prop = icalcomponent_get_next_property(comp, ICAL_ANY_PROPERTY)) {

            if (icalproperty_isa(prop) == ICAL_XLICERROR_PROPERTY) {
                const char *errstr = icalproperty_get_xlicerror(prop);
                char propname[256];

                if (!errstr) return "Unknown iCal parsing error";

                /* Check if this is an empty property error */
                if (sscanf(errstr,
                           "No value for %s property", propname) == 1) {
                    /* Empty LOCATION is OK */
                    if (!strcasecmp(propname, "LOCATION")) continue;
                    if (!strcasecmp(propname, "COMMENT")) continue;
                    if (!strcasecmp(propname, "DESCRIPTION")) continue;
                    if (!strcasecmp(propname, "SUMMARY")) continue;
                }
                else {
                    /* Ignore unknown property errors */
                    if (!strncmp(errstr, "Parse error in property name", 28))
                        continue;
                }

                return errstr;
            }
        }
    }

    return NULL;
}


EXPORTED void icalcomponent_remove_invitee(icalcomponent *comp, icalproperty *prop)
{
    if (icalcomponent_isa(comp) == ICAL_VPOLL_COMPONENT) {
        icalcomponent *vvoter = icalproperty_get_parent(prop);

        icalcomponent_remove_component(comp, vvoter);
        icalcomponent_free(vvoter);
    }
    else {
        icalcomponent_remove_property(comp, prop);
        icalproperty_free(prop);
    }
}


EXPORTED icalproperty *icalcomponent_get_first_invitee(icalcomponent *comp)
{
    icalproperty *prop;

    if (icalcomponent_isa(comp) == ICAL_VPOLL_COMPONENT) {
        icalcomponent *vvoter =
            icalcomponent_get_first_component(comp, ICAL_VVOTER_COMPONENT);

        prop = icalcomponent_get_first_property(vvoter, ICAL_VOTER_PROPERTY);
    }
    else {
        prop = icalcomponent_get_first_property(comp, ICAL_ATTENDEE_PROPERTY);
    }

    return prop;
}

EXPORTED icalproperty *icalcomponent_get_next_invitee(icalcomponent *comp)
{
    icalproperty *prop;

    if (icalcomponent_isa(comp) == ICAL_VPOLL_COMPONENT) {
        icalcomponent *vvoter =
            icalcomponent_get_next_component(comp, ICAL_VVOTER_COMPONENT);

        prop = icalcomponent_get_first_property(vvoter, ICAL_VOTER_PROPERTY);
    }
    else {
        prop = icalcomponent_get_next_property(comp, ICAL_ATTENDEE_PROPERTY);
    }

    return prop;
}

EXPORTED const char *icalproperty_get_invitee(icalproperty *prop)
{
    const char *recip;

    if (icalproperty_isa(prop) == ICAL_VOTER_PROPERTY) {
        recip = icalproperty_get_voter(prop);
    }
    else {
        recip = icalproperty_get_attendee(prop);
    }

    return recip;
}


EXPORTED icaltimetype icalcomponent_get_recurrenceid_with_zone(icalcomponent *comp)
{
    icalproperty *prop =
        icalcomponent_get_first_property(comp, ICAL_RECURRENCEID_PROPERTY);

    struct icaldatetimeperiodtype dtp = icalproperty_get_datetimeperiod(prop);
    return dtp.time;
}


icalproperty *icalcomponent_get_x_property_by_name(icalcomponent *comp,
                                                   const char *name)
{
    icalproperty *prop;

    for (prop = icalcomponent_get_first_property(comp, ICAL_X_PROPERTY);
         prop && strcmp(icalproperty_get_x_name(prop), name);
         prop = icalcomponent_get_next_property(comp, ICAL_X_PROPERTY));

    return prop;
}


/* Get time period (start/end) of a component based in RFC 4791 Sec 9.9 */
struct icalperiodtype icalcomponent_get_utc_timespan(icalcomponent *comp,
                                                     icalcomponent_kind kind)
{
    icaltimezone *utc = icaltimezone_get_utc_timezone();
    struct icalperiodtype period;

    period.start = icaltime_convert_to_zone(icalcomponent_get_dtstart(comp), utc);
    period.end   = icaltime_convert_to_zone(icalcomponent_get_dtend(comp), utc);
    period.duration = icaldurationtype_null_duration();

    switch (kind) {
    case ICAL_VEVENT_COMPONENT:
        if (icaltime_is_null_time(period.end)) {
            /* No DTEND or DURATION */
            if (icaltime_is_date(period.start)) {
                /* DTSTART is not DATE-TIME */
                struct icaldurationtype dur = icaldurationtype_null_duration();

                dur.days = 1;
                period.end = icaltime_add(period.start, dur);
            }
            else
                memcpy(&period.end, &period.start, sizeof(struct icaltimetype));
        }
        break;

#ifdef HAVE_VPOLL
    case ICAL_VPOLL_COMPONENT:
#endif
    case ICAL_VTODO_COMPONENT: {
        struct icaltimetype due = (kind == ICAL_VPOLL_COMPONENT) ?
            icalcomponent_get_dtend(comp) : icalcomponent_get_due(comp);

        if (!icaltime_is_null_time(period.start)) {
            /* Has DTSTART */
            if (icaltime_is_null_time(period.end)) {
                /* No DURATION */
                memcpy(&period.end, &period.start, sizeof(struct icaltimetype));

                if (!icaltime_is_null_time(due)) {
                    /* Has DUE (DTEND for VPOLL) */
                    if (icaltime_compare(due, period.start) < 0)
                        memcpy(&period.start, &due, sizeof(struct icaltimetype));
                    if (icaltime_compare(due, period.end) > 0)
                        memcpy(&period.end, &due, sizeof(struct icaltimetype));
                }
            }
        }
        else {
            icalproperty *prop;

            /* No DTSTART */
            if (!icaltime_is_null_time(due)) {
                /* Has DUE (DTEND for VPOLL) */
                memcpy(&period.start, &due, sizeof(struct icaltimetype));
                memcpy(&period.end, &due, sizeof(struct icaltimetype));
            }
            else if ((prop =
                      icalcomponent_get_first_property(comp, ICAL_COMPLETED_PROPERTY))) {
                /* Has COMPLETED */
                period.start =
                    icaltime_convert_to_zone(icalproperty_get_completed(prop), utc);
                memcpy(&period.end, &period.start, sizeof(struct icaltimetype));

                if ((prop =
                     icalcomponent_get_first_property(comp, ICAL_CREATED_PROPERTY))) {
                    /* Has CREATED */
                    struct icaltimetype created =
                        icaltime_convert_to_zone(icalproperty_get_created(prop), utc);
                    if (icaltime_compare(created, period.start) < 0)
                        memcpy(&period.start, &created, sizeof(struct icaltimetype));
                    if (icaltime_compare(created, period.end) > 0)
                        memcpy(&period.end, &created, sizeof(struct icaltimetype));
                }
            }
            else if ((prop =
                      icalcomponent_get_first_property(comp, ICAL_CREATED_PROPERTY))) {
                /* Has CREATED */
                period.start =
                    icaltime_convert_to_zone(icalproperty_get_created(prop), utc);
                period.end = icaltime_from_timet_with_zone(caldav_eternity, 0, NULL);
            }
            else {
                /* Always */
                period.start = icaltime_from_timet_with_zone(caldav_epoch, 0, NULL);
                period.end   = icaltime_from_timet_with_zone(caldav_eternity, 0, NULL);
            }
        }
        break;
    }

    case ICAL_VJOURNAL_COMPONENT:
        if (!icaltime_is_null_time(period.start)) {
            /* Has DTSTART */
            memcpy(&period.end, &period.start, sizeof(struct icaltimetype));

            if (icaltime_is_date(period.start)) {
                /* DTSTART is not DATE-TIME */
                struct icaldurationtype dur;

                dur = icaldurationtype_from_int(60*60*24 - 1);  /* P1D */
                icaltime_add(period.end, dur);
            }
        }
        else {
            /* Never */
            period.start = icaltime_from_timet_with_zone(caldav_eternity, 0, NULL);
            period.end   = icaltime_from_timet_with_zone(caldav_epoch, 0, NULL);
        }
        break;

    case ICAL_VFREEBUSY_COMPONENT:
        if (icaltime_is_null_time(period.start) ||
            icaltime_is_null_time(period.end)) {
            /* No DTSTART or DTEND */
            icalproperty *fb =
                icalcomponent_get_first_property(comp, ICAL_FREEBUSY_PROPERTY);

            if (fb) {
                /* Has FREEBUSY */
                /* XXX  Convert FB period into our period */
            }
            else {
                /* Never */
                period.start = icaltime_from_timet_with_zone(caldav_eternity, 0, NULL);
                period.end   = icaltime_from_timet_with_zone(caldav_epoch, 0, NULL);
            }
        }
        break;

    case ICAL_VAVAILABILITY_COMPONENT:
        if (icaltime_is_null_time(period.start)) {
            /* No DTSTART */
            period.start = icaltime_from_timet_with_zone(caldav_epoch, 0, NULL);
        }
        if (icaltime_is_null_time(period.end)) {
            /* No DTEND */
            period.end = icaltime_from_timet_with_zone(caldav_eternity, 0, NULL);
        }
        break;

    default:
        break;
    }

    return period;
}


/* icalcomponent_foreach_recurrence() callback to find earliest/latest time */
static void utc_timespan_cb(icalcomponent *comp, struct icaltime_span *span, void *rock)
{
    struct icalperiodtype *period = (struct icalperiodtype *) rock;
    int is_date = icaltime_is_date(icalcomponent_get_dtstart(comp));
    icaltimezone *utc = icaltimezone_get_utc_timezone();
    struct icaltimetype start =
        icaltime_from_timet_with_zone(span->start, is_date, utc);
    struct icaltimetype end =
        icaltime_from_timet_with_zone(span->end, is_date, utc);

    if (icaltime_compare(start, period->start) < 0)
        memcpy(&period->start, &start, sizeof(struct icaltimetype));

    if (icaltime_compare(end, period->end) > 0)
        memcpy(&period->end, &end, sizeof(struct icaltimetype));
}

/* Determine the UTC time span of all components within ical of type kind. */
struct icalperiodtype icalrecurrenceset_get_utc_timespan(icalcomponent *ical,
                                                         icalcomponent_kind kind,
                                                         unsigned *is_recurring,
                                                         void (*comp_cb)(icalcomponent*,
                                                                         void*),
                                                         void *cb_rock)
{
    struct icalperiodtype span;
    icalcomponent *comp = icalcomponent_get_first_component(ical, kind);
    unsigned recurring = 0;

    /* Initialize span to be nothing */
    span.start = icaltime_from_timet_with_zone(caldav_eternity, 0, NULL);
    span.end = icaltime_from_timet_with_zone(caldav_epoch, 0, NULL);
    span.duration = icaldurationtype_null_duration();

    do {
        struct icalperiodtype period;
        icalproperty *rrule;

        /* Get base dtstart and dtend */
        period = icalcomponent_get_utc_timespan(comp, kind);

        /* See if its a recurring event */
        rrule = icalcomponent_get_first_property(comp, ICAL_RRULE_PROPERTY);
        if (rrule ||
            icalcomponent_get_first_property(comp, ICAL_RDATE_PROPERTY) ||
            icalcomponent_get_first_property(comp, ICAL_EXDATE_PROPERTY)) {
            /* Recurring - find widest time range that includes events */
            unsigned expand = recurring = 1;

            if (rrule) {
                struct icalrecurrencetype recur = icalproperty_get_rrule(rrule);

                if (!icaltime_is_null_time(recur.until)) {
                    /* Recurrence ends - calculate dtend of last recurrence */
                    struct icaldurationtype duration;
                    icaltimezone *utc = icaltimezone_get_utc_timezone();

                    duration = icaltime_subtract(period.end, period.start);
                    period.end =
                        icaltime_add(icaltime_convert_to_zone(recur.until, utc),
                                duration);

                    /* Do RDATE expansion only */
                    /* Temporarily remove RRULE to allow for expansion of
                     * remaining recurrences. */
                    icalcomponent_remove_property(comp, rrule);
                }
                else if (!recur.count) {
                    /* Recurrence never ends - set end of span to eternity */
                    span.end =
                        icaltime_from_timet_with_zone(caldav_eternity, 0, NULL);

                    /* Skip RRULE & RDATE expansion */
                    expand = 0;
                }
            }

            /* Expand (remaining) recurrences */
            if (expand) {
                icalcomponent_foreach_recurrence(
                        comp,
                        icaltime_from_timet_with_zone(caldav_epoch, 0, NULL),
                        icaltime_from_timet_with_zone(caldav_eternity, 0, NULL),
                        utc_timespan_cb, &span);

                /* Add RRULE back, if we had removed it before. */
                if (rrule && !icalproperty_get_parent(rrule)) {
                    icalcomponent_add_property(comp, rrule);
                }
            }
        }

        /* Check our dtstart and dtend against span */
        if (icaltime_compare(period.start, span.start) < 0)
            memcpy(&span.start, &period.start, sizeof(struct icaltimetype));

        if (icaltime_compare(period.end, span.end) > 0)
            memcpy(&span.end, &period.end, sizeof(struct icaltimetype));

        /* Execute callback on this component */
        if (comp_cb) comp_cb(comp, cb_rock);

    } while ((comp = icalcomponent_get_next_component(ical, kind)));

    if (is_recurring) *is_recurring = recurring;

    return span;
}


#ifndef HAVE_TZDIST_PROPS

/* Functions to replace those not available in libical < v2.0 */

icalproperty *icalproperty_new_tzidaliasof(const char *v)
{
    icalproperty *prop = icalproperty_new_x(v);
    icalproperty_set_x_name(prop, "TZID-ALIAS-OF");
    return prop;
}

icalproperty *icalproperty_new_tzuntil(struct icaltimetype v)
{
    icalproperty *prop = icalproperty_new_x(icaltime_as_ical_string(v));
    icalproperty_set_x_name(prop, "TZUNTIL");
    return prop;
}

#endif /* HAVE_TZDIST_PROPS */


#ifndef HAVE_VALARM_EXT_PROPS

/* Functions to replace those not available in libical < v1.0 */

icalproperty *icalproperty_new_acknowledged(struct icaltimetype v)
{
    icalproperty *prop = icalproperty_new_x(icaltime_as_ical_string(v));
    icalproperty_set_x_name(prop, "ACKNOWLEDGED");
    return prop;
}

void icalproperty_set_acknowledged(icalproperty *prop, struct icaltimetype v)
{
    icalproperty_set_x(prop, icaltime_as_ical_string(v));
}

struct icaltimetype icalproperty_get_acknowledged(const icalproperty *prop)
{
    return icaltime_from_string(icalproperty_get_x(prop));
}

#endif /* HAVE_VALARM_EXT_PROPS */


#ifdef HAVE_IANA_PARAMS

#ifndef HAVE_MANAGED_ATTACH_PARAMS

icalparameter* icalproperty_get_iana_parameter_by_name(icalproperty *prop,
                                                       const char *name)
{
    icalparameter *param;

    for (param = icalproperty_get_first_parameter(prop, ICAL_IANA_PARAMETER);
         param && strcmp(icalparameter_get_iana_name(param), name);
         param = icalproperty_get_next_parameter(prop, ICAL_IANA_PARAMETER));

    return param;
}

/* Functions to replace those not available in libical < v2.0 */

icalparameter *icalparameter_new_filename(const char *fname)
{
    icalparameter *param = icalparameter_new(ICAL_IANA_PARAMETER);

    icalparameter_set_iana_name(param, "FILENAME");
    icalparameter_set_iana_value(param, fname);

    return param;
}

void icalparameter_set_filename(icalparameter *param, const char *fname)
{
    icalparameter_set_iana_value(param, fname);
}

icalparameter *icalparameter_new_managedid(const char *id)
{
    icalparameter *param = icalparameter_new(ICAL_IANA_PARAMETER);

    icalparameter_set_iana_name(param, "MANAGED-ID");
    icalparameter_set_iana_value(param, id);

    return param;
}

const char *icalparameter_get_managedid(icalparameter *param)
{
    return icalparameter_get_iana_value(param);
}

void icalparameter_set_managedid(icalparameter *param, const char *id)
{
    icalparameter_set_iana_value(param, id);
}

icalparameter *icalparameter_new_size(const char *sz)
{
    icalparameter *param = icalparameter_new(ICAL_IANA_PARAMETER);

    icalparameter_set_iana_name(param, "SIZE");
    icalparameter_set_iana_value(param, sz);

    return param;
}

const char *icalparameter_get_size(icalparameter *param)
{
    return icalparameter_get_iana_value(param);
}

void icalparameter_set_size(icalparameter *param, const char *sz)
{
    icalparameter_set_iana_value(param, sz);
}

#endif /* HAVE_MANAGED_ATTACH_PARAMS */


#ifndef HAVE_SCHEDULING_PARAMS

/* Functions to replace those not available in libical < v1.0 */

icalparameter_scheduleagent
icalparameter_get_scheduleagent(icalparameter *param)
{
    const char *agent = NULL;

    if (param) agent = icalparameter_get_iana_value(param);

    if (!agent) return ICAL_SCHEDULEAGENT_NONE;
    else if (!strcmp(agent, "SERVER")) return ICAL_SCHEDULEAGENT_SERVER;
    else if (!strcmp(agent, "CLIENT")) return ICAL_SCHEDULEAGENT_CLIENT;
    else return ICAL_SCHEDULEAGENT_X;
}

icalparameter_scheduleforcesend
icalparameter_get_scheduleforcesend(icalparameter *param)
{
    const char *force = NULL;

    if (param) force = icalparameter_get_iana_value(param);

    if (!force) return ICAL_SCHEDULEFORCESEND_NONE;
    else if (!strcmp(force, "REQUEST")) return ICAL_SCHEDULEFORCESEND_REQUEST;
    else if (!strcmp(force, "REPLY")) return ICAL_SCHEDULEFORCESEND_REPLY;
    else return ICAL_SCHEDULEFORCESEND_X;
}

icalparameter *icalparameter_new_schedulestatus(const char *stat)
{
    icalparameter *param = icalparameter_new(ICAL_IANA_PARAMETER);

    icalparameter_set_iana_name(param, "SCHEDULE-STATUS");
    icalparameter_set_iana_value(param, stat);

    return param;
}

#endif /* HAVE_SCHEDULING_PARAMS */

#endif /* HAVE_IANA_PARAMS */

#endif /* HAVE_ICAL */
