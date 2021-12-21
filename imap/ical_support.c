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
#include <sysexits.h>
#include <syslog.h>

#include "assert.h"
#include "caldav_db.h"
#include "global.h"
#include "ical_support.h"
#include "icu_wrap.h"
#include "message.h"
#include "strhash.h"
#include "stristr.h"
#include "util.h"

#ifdef HAVE_ICAL

static int initialized = 0;

EXPORTED void ical_support_init(void)
{
    if (initialized) return;

    /* Initialize timezones path */
    const char *tzpath = config_getstring(IMAPOPT_ZONEINFO_DIR);
    icalarray *timezones;

    if (tzpath) {
        syslog(LOG_DEBUG, "using timezone data from zoneinfo_dir=%s", tzpath);
        icaltimezone_set_zone_directory((char *) tzpath);
        icaltimezone_set_tzid_prefix("");
        icaltimezone_set_builtin_tzdata(1);
    }
    else {
        syslog(LOG_DEBUG, "zoneinfo_dir is unset, libical will find "
                           "its own timezone data");
    }

    /* make sure libical actually finds some timezone data! */
    assert(icalerrno == 0);
    timezones = icaltimezone_get_builtin_timezones();
    if (icalerrno != 0) {
        syslog(LOG_ERR, "libical error while loading timezones: %s",
                        icalerror_strerror(icalerrno));
    }

    if (timezones->num_elements == 0) {
        fatal("No timezones found! Please check/set zoneinfo_dir in imapd.conf",
              EX_CONFIG);
    }

    syslog(LOG_DEBUG, "%s: found " SIZE_T_FMT " timezones",
                       __func__, timezones->num_elements);

    initialized = 1;
}

EXPORTED int cyrus_icalrestriction_check(icalcomponent *ical)
{
    icalcomponent *comp;
    icalproperty *prop;

    for (comp = icalcomponent_get_first_component(ical, ICAL_ANY_COMPONENT);
         comp;
         comp = icalcomponent_get_next_component(ical, ICAL_ANY_COMPONENT)) {

        switch (icalcomponent_isa(comp)) {
        case ICAL_VTIMEZONE_COMPONENT:
            /* Strip COMMENT properties from VTIMEZONEs */
            /* XXX  These were added by KSM in a previous version of vzic,
               but libical doesn't allow them in its restrictions checks */
            prop = icalcomponent_get_first_property(comp, ICAL_COMMENT_PROPERTY);
            if (prop) {
                icalcomponent_remove_property(comp, prop);
                icalproperty_free(prop);
            }
            break;

        case ICAL_VEVENT_COMPONENT:
            /* Strip TZID properies from VEVENTs */
            /* XXX  Zoom invites contain these,
               but libical doesn't allow them in its restrictions checks */
            prop = icalcomponent_get_first_property(comp, ICAL_TZID_PROPERTY);
            if (prop) {
                icalcomponent_remove_property(comp, prop);
                icalproperty_free(prop);
            }

            /* Strip CALSCALE properies from VEVENTs */
            /* XXX  CiviCRM invites contain these,
               but libical doesn't allow them in its restrictions checks */
            prop = icalcomponent_get_first_property(comp, ICAL_CALSCALE_PROPERTY);
            if (prop) {
                icalcomponent_remove_property(comp, prop);
                icalproperty_free(prop);
            }
            break;

        default:
            break;
        }
    }

    return icalrestriction_check(ical);
}

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

EXPORTED const char *icalparameter_get_value_as_string(icalparameter *param)
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

static struct icaltimetype icalcomponent_get_mydatetime(icalcomponent *comp, icalproperty *prop)
{
    icalcomponent *c;
    icalparameter *param;
    struct icaltimetype ret;

    ret = icalvalue_get_datetime(icalproperty_get_value(prop));

    if ((param = icalproperty_get_first_parameter(prop, ICAL_TZID_PARAMETER)) != NULL) {
        const char *tzid = icalparameter_get_tzid(param);
        if (!strcmpsafe(tzid, "Etc/UTC") || !strcmpsafe(tzid, "UTC")) {
            /* Use UTC singleton for Etc/UTC */
            ret = icaltime_set_timezone(&ret, icaltimezone_get_utc_timezone());
        }
        else {
            /* Use Cyrus-internal timezone */
            icaltimezone *mytz = icaltimezone_get_builtin_timezone(tzid);
            if (mytz == NULL)
                mytz = icaltimezone_get_builtin_timezone_from_tzid(tzid);
            if (mytz == NULL) {
                /* see if its a MS Windows TZID */
                char *icutzid = icu_getIDForWindowsID(tzid);
                if (icutzid)
                    mytz = icaltimezone_get_builtin_timezone_from_tzid(icutzid);
                free(icutzid);
            }
            if (mytz != NULL) {
                ret = icaltime_set_timezone(&ret, mytz);
            }
            else {
                /* Use embedded VTIMEZONE */
                icaltimezone *tz = NULL;
                for (c = comp; c != NULL; c = icalcomponent_get_parent(c)) {
                    tz = icalcomponent_get_timezone(c, tzid);
                    if (tz != NULL)
                        break;
                }
                if (tz != NULL)
                    ret =icaltime_set_timezone(&ret, tz);
            }
        }
    }

    return ret;
}

static icaltimetype icalcomponent_get_mydtstart(icalcomponent *comp)
{
    icalproperty *prop =
        icalcomponent_get_first_property(comp, ICAL_DTSTART_PROPERTY);
    return prop ?
        icalcomponent_get_mydatetime(comp, prop) :
        icaltime_null_time();
}

static icaltimetype icalcomponent_get_mydtend(icalcomponent *comp)
{
    struct icaltimetype dtstart = icalcomponent_get_mydtstart(comp);
    struct icaltimetype dtend = icaltime_null_time();

    icalproperty *end_prop =
        icalcomponent_get_first_property(comp, ICAL_DTEND_PROPERTY);
    icalproperty *dur_prop =
        icalcomponent_get_first_property(comp, ICAL_DURATION_PROPERTY);

    if (end_prop) {
        dtend = icalcomponent_get_mydatetime(comp, end_prop);
        if (!dtend.zone)
            dtend.zone = dtstart.zone;
    }
    else if (dur_prop) {
        dtend.zone = dtstart.zone;
        struct icaldurationtype duration;
        if (icalproperty_get_value(dur_prop)) {
            duration = icalproperty_get_duration(dur_prop);
        } else {
            duration = icaldurationtype_null_duration();
        }
        dtend = icaltime_add(dtstart, duration);
    }
    else dtend = dtstart;

    return dtend;
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

EXPORTED int icalcomponent_myforeach(icalcomponent *ical,
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
        dtstart = icalcomponent_get_mydtstart(mastercomp);
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
            struct icaltimetype exdate = icalcomponent_get_mydatetime(mastercomp, prop);
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
        struct icaltimetype mystart = icalcomponent_get_mydtstart(comp);
        struct icaltimetype myend = icalcomponent_get_mydtend(comp);

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
                if (rrule_itr && (recur.count > 0)) {
                    icalrecur_iterator_set_start(rrule_itr, range.start);
                }
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

EXPORTED icalcomponent *icalcomponent_new_stream(struct mailbox *mailbox,
                                                 const char *prodid,
                                                 const char *name,
                                                 const char *desc,
                                                 const char *color)
{
    struct buf buf = BUF_INITIALIZER;
    icalcomponent *ical;
    icalproperty *prop;

    buf_printf(&buf, "%x-%s-%u", strhash(config_servername),
               mailbox_uniqueid(mailbox), mailbox->i.uidvalidity);

    ical = icalcomponent_vanew(ICAL_VCALENDAR_COMPONENT,
                               icalproperty_new_version("2.0"),
                               icalproperty_new_prodid(prodid),
                               icalproperty_new_uid(buf_cstring(&buf)),
                               icalproperty_new_lastmodified(
                                   icaltime_from_timet_with_zone(mailbox->index_mtime,
                                                                 0, NULL)),
                               icalproperty_new_name(name),
                               0);

    buf_free(&buf);

    prop = icalproperty_new_x(name);
    icalproperty_set_x_name(prop, "X-WR-CALNAME");
    icalcomponent_add_property(ical, prop);

    if (desc) {
        prop = icalproperty_new_description(desc);
        icalcomponent_add_property(ical, prop);
    }

    if (color) {
        prop = icalproperty_new_color(color);
        icalcomponent_add_property(ical, prop);
    }

    return ical;
}

EXPORTED icalcomponent *ical_string_as_icalcomponent(const struct buf *buf)
{
    const char *rawical = buf_cstring(buf);
    icalcomponent *ical = icalparser_parse_string(rawical);

    if (!ical && !stristr(rawical, "END:VCALENDAR")) {
        char *fixed = strconcat(rawical, "END:VCALENDAR", NULL);
        ical = icalparser_parse_string(fixed);
        free(fixed);
    }

    return ical;
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
                              strarray_t *schedule_addresses)
{
    icalcomponent *ical = NULL;
    message_t *m = message_new_from_record(mailbox, record);
    struct buf buf = BUF_INITIALIZER;

    /* Load message containing the resource and parse iCal data */
    if (!message_get_field(m, "rawbody", MESSAGE_RAW, &buf)) {
        ical = icalparser_parse_string(buf_cstring(&buf));
    }

    /* extract the schedule user header */
    if (schedule_addresses) {
        buf_reset(&buf);
        if (!message_get_field(m, "x-schedule-user-address",
                               MESSAGE_DECODED|MESSAGE_TRIM, &buf)) {
            if (buf.len) {
                strarray_t *vals = strarray_split(buf_cstring(&buf), ",", STRARRAY_TRIM);
                int i;
                for (i = 0; i < strarray_size(vals); i++) {
                    const char *email = strarray_nth(vals, i);
                    if (!strncasecmp(email, "mailto:", 7)) email += 7;
                    strarray_add(schedule_addresses, email);
                }
                strarray_free(vals);
            }
        }
    }

    /* Remove all X-LIC-ERROR properties */
    if (ical) icalcomponent_strip_errors(ical);

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
                           "No value for %255s property", propname) == 1) {
                    /* Empty LOCATION is OK */
                    if (!strcasecmp(propname, "LOCATION")) continue;
                    if (!strcasecmp(propname, "COMMENT")) continue;
                    if (!strcasecmp(propname, "DESCRIPTION")) continue;
                    if (!strcasecmp(propname, "SUMMARY")) continue;

                    /* For iOS 11 */
                    if (!strcasecmp(propname, "URL")) continue;
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


EXPORTED void icalcomponent_remove_invitee(icalcomponent *comp,
                                           icalproperty *prop)
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


EXPORTED icaltimetype
icalcomponent_get_recurrenceid_with_zone(icalcomponent *comp)
{
    icalproperty *prop =
        icalcomponent_get_first_property(comp, ICAL_RECURRENCEID_PROPERTY);

    struct icaldatetimeperiodtype dtp = icalproperty_get_datetimeperiod(prop);
    return dtp.time;
}


EXPORTED icalproperty *icalcomponent_get_x_property_by_name(icalcomponent *comp,
                                                            const char *name)
{
    icalproperty *prop;

    for (prop = icalcomponent_get_first_property(comp, ICAL_X_PROPERTY);
         prop && strcmp(icalproperty_get_x_name(prop), name);
         prop = icalcomponent_get_next_property(comp, ICAL_X_PROPERTY));

    return prop;
}

EXPORTED icaltimetype icaltime_convert_to_utc(const struct icaltimetype tt,
                                              icaltimezone *floating_zone)
{
    icaltimezone *from_zone = (icaltimezone *) tt.zone;
    icaltimezone *utc = icaltimezone_get_utc_timezone();
    struct icaltimetype ret = tt;

    /* If it's a date do nothing */
    if (tt.is_date) {
        return ret;
    }

    if (tt.zone == utc) {
        return ret;
    }

    /* If it's a floating time use the passed in zone */
    if (from_zone == NULL) {
        from_zone = floating_zone;

        if (from_zone == NULL) {
            /* Leave the time as floating */
            return ret;
        }
    }

    icaltimezone_convert_time(&ret, from_zone, utc);
    ret.zone = utc;

    return ret;
}


/* Get time period (start/end) of a component based in RFC 4791 Sec 9.9 */
EXPORTED struct icalperiodtype
icalcomponent_get_utc_timespan(icalcomponent *comp,
                               icalcomponent_kind kind,
                               icaltimezone *floating_tz)
{
    struct icalperiodtype period;

    period.start = icaltime_convert_to_utc(icalcomponent_get_mydtstart(comp),
                                           floating_tz);
    period.end   = icaltime_convert_to_utc(icalcomponent_get_mydtend(comp),
                                           floating_tz);
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

    case ICAL_VPOLL_COMPONENT:
    case ICAL_VTODO_COMPONENT: {
        struct icaltimetype due = (kind == ICAL_VPOLL_COMPONENT) ?
            icalcomponent_get_mydtend(comp) : icalcomponent_get_due(comp);

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
                    icaltime_convert_to_utc(icalproperty_get_completed(prop), NULL);
                memcpy(&period.end, &period.start, sizeof(struct icaltimetype));

                if ((prop =
                     icalcomponent_get_first_property(comp, ICAL_CREATED_PROPERTY))) {
                    /* Has CREATED */
                    struct icaltimetype created =
                        icaltime_convert_to_utc(icalproperty_get_created(prop), NULL);
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
                    icaltime_convert_to_utc(icalproperty_get_created(prop), NULL);
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
    int is_date = icaltime_is_date(icalcomponent_get_mydtstart(comp));
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
EXPORTED struct icalperiodtype
icalrecurrenceset_get_utc_timespan(icalcomponent *ical,
                                   icalcomponent_kind kind,
                                   icaltimezone *floating_tz,
                                   unsigned *is_recurring,
                                   void (*comp_cb)(icalcomponent*, void*),
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
        period = icalcomponent_get_utc_timespan(comp, kind, floating_tz);

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

EXPORTED void icaltime_set_utc(struct icaltimetype *t, int set)
{
    icaltime_set_timezone(t, set ? icaltimezone_get_utc_timezone() : NULL);
}


enum {
    ACTION_UPDATE = 1,
    ACTION_DELETE,
    ACTION_SETPARAM
};

enum {
    SEGMENT_COMP = 1,
    SEGMENT_PROP,
    SEGMENT_PARAM
};

union match_criteria_t {
    struct {
        char *uid;                /* component UID (optional) */
        icaltimetype rid;         /* component RECURRENCE-ID (optional) */
    } comp;
    struct {
        char *param;              /* parameter name (optional) */
        char *value;              /* prop/param value (optional) */
        unsigned not:1;           /* not equal? */
    } prop;
};

struct path_segment_t {
    unsigned type;                    /* Is it comp, prop, or param segment? */
    unsigned kind;                    /* libical kind of comp, prop, or param */
    union match_criteria_t match;     /* match criteria (depends on 'type') */
    unsigned action;                  /* patch action (create,update,setparam)*/
    void *data;                       /* patch data (depends on 'action') */

    struct path_segment_t *sibling;
    struct path_segment_t *child;
};

struct patch_data_t {
    icalcomponent *patch;             /* component containing patch data */
    struct path_segment_t *delete;    /* list of PATCH-DELETE actions */
    struct path_segment_t *setparam;  /* list of PATCH-PARAMETER items */
};

static int parse_target_path(char *path, struct path_segment_t **path_seg,
                             unsigned action, void *data,
                             const char **errstr)
{
    char *p, sep;
    struct path_segment_t *tail = NULL, *new;

    for (sep = *path++; sep == '/';) {
        p = path + strcspn(path, "[/#");
        if ((sep = *p)) *p++ = '\0';

        new = xzmalloc(sizeof(struct path_segment_t));
        new->type = SEGMENT_COMP;
        new->kind = icalcomponent_string_to_kind(path);
        /* Initialize RID as invalid time rather than NULL time
           since NULL time is used for empty RID (master component) */
        new->match.comp.rid.year = -1;

        if (!*path_seg) *path_seg = new;
        else tail->child = new;
        tail = new;

        path = p;

        if (sep == '[') {
            /* Parse comp-match */
            const char *prefix = "UID=";
            size_t prefix_len = strlen(prefix);

            if (!(p = strchr(path, ']'))) {
                *errstr = "Badly formatted comp-match";
                return -1;
            }

            /* Parse uid-match */
            if (!strncmp(path, prefix, prefix_len)) {
                path += prefix_len;
                *p++ = '\0';
                new->match.comp.uid = xstrdup(path);
                sep = *p++;
                path = p;
            }

            /* Parse rid-match */
            if (sep == '[') {
                prefix = "RID=";
                prefix_len = strlen(prefix);

                if (strncmp(path, prefix, prefix_len) ||
                    !(p = strchr(path, ']'))) {
                    *errstr = "Badly formatted rid-match";
                    return -1;
                }

                path += prefix_len;
                *p++ = '\0';
                if (*path && strcmp(path, "M")) {
                    new->match.comp.rid = icaltime_from_string(path);
                    if (icaltime_is_null_time(new->match.comp.rid)) {
                        *errstr = "Invalid recurrence-id";
                        return -1;
                    }
                }
                else new->match.comp.rid = icaltime_null_time();

                sep = *p++;
                path = p;
            }
        }
    }

    if (sep == '#' && !*path_seg) {
        /* Parse prop-segment */
        p = path + strcspn(path, "[;=");
        if ((sep = *p)) *p++ = '\0';

        new = xzmalloc(sizeof(struct path_segment_t));
        new->type = SEGMENT_PROP;
        new->kind = icalproperty_string_to_kind(path);

        if (!*path_seg) *path_seg = new;
        else tail->child = new;
        tail = new;

        path = p;

        if (sep == '[') {
            /* Parse prop-match (MUST start with '=' or '!' or '@') */
            if (strspn(path, "=!@") != 1 || !(p = strchr(path, ']'))) {
                *errstr = "Badly formatted prop-match";
                return -1;
            }

            *p++ = '\0';
            if (*path == '@') {
                /* Parse param-match */
                size_t namelen = strcspn(++path, "!=");
                new->match.prop.param = xstrndup(path, namelen);
                path += namelen;
            }

            if (*path) {
                /* Parse prop/param [not]equal value */
                if (*path++ == '!') new->match.prop.not = 1;
                new->match.prop.value = xstrdup(path);
            }

            sep = *p++;
            path = p;
        }

        if (sep == ';') {
            /* Parse param-segment */
            p = path + strcspn(path, "=");
            if ((sep = *p)) *p++ = '\0';

            new = xzmalloc(sizeof(struct path_segment_t));
            new->type = SEGMENT_PARAM;
            new->kind = icalparameter_string_to_kind(path);

            tail->child = new;
            tail = new;

            path = p;
        }

        if (sep == '=' && action == ACTION_DELETE) {
            /* Parse value-segment */
            new->data = xstrdup(path);
        }
        else if (sep != '\0') {
            *errstr = "Invalid separator following prop-segment";
            return -1;
        }
    }
    else if (sep != '\0') {
        *errstr = "Invalid separator following comp-segment";
        return -1;
    }

    tail->action = action;
    if (!tail->data) tail->data = data;

    return 0;
}

static void apply_patch(struct path_segment_t *path_seg,
                        void *parent, int *num_changes);

static char *remove_single_value(const char *oldstr, const char *single)
{
    char *newstr = NULL;
    strarray_t *values = strarray_split(oldstr, ",", STRARRAY_TRIM);
    int idx = strarray_find(values, single, 0);

    if (idx >= 0) {
        /* Found the single value, remove it, and create new string */
        strarray_remove(values, idx);
        newstr = strarray_join(values, ",");
    }
    strarray_free(values);

    return newstr;
}

/* Apply a patch action to a parameter segment */
static void apply_patch_parameter(struct path_segment_t *path_seg,
                                  icalproperty *parent, int *num_changes)
{
    icalparameter *param =
        icalproperty_get_first_parameter(parent, path_seg->kind);
    if (!param) return;

    if (path_seg->action == ACTION_DELETE) {
        switch (path_seg->kind) {
        case ICAL_MEMBER_PARAMETER:
            /* Multi-valued parameter */
            if (path_seg->data) {
                /* Check if entire parameter value == single value */
                const char *single = (const char *) path_seg->data;
                const char *param_val = icalparameter_get_value_as_string(param);

                if (strcmp(param_val, single)) {
                    /* Not an exact match, try to remove single value */
                    char *newval = remove_single_value(param_val, single);
                    if (newval) {
                        *num_changes += 1;
                        icalparameter_set_member(param, newval);
                        free(newval);
                    }
                    break;
                }
            }

            /* Fall through and delete entire parameter */
            GCC_FALLTHROUGH

        default:
            *num_changes += 1;
            icalproperty_remove_parameter_by_ref(parent, param);
            break;
        }
    }
}

static int apply_param_match(icalproperty *prop, union match_criteria_t *match)
{
    icalparameter_kind kind;
    icalparameter *param;
    int ret = 1;

    /* XXX  Need to handle X- parameters */

    kind = icalparameter_string_to_kind(match->prop.param);
    param = icalproperty_get_first_parameter(prop, kind);
    if (!param) {
        /* property doesn't have this parameter */
        ret = match->prop.not;
    }
    else if (match->prop.value) {
        const char *param_val = icalparameter_get_value_as_string(param);

        ret = !strcmp(match->prop.value, param_val);
        if (match->prop.not) ret = !ret;  /* invert */
    }

    return ret;
}

/* Apply a patch action to a property segment */
static void apply_patch_property(struct path_segment_t *path_seg,
                                 icalcomponent *parent, int *num_changes)
{
    icalproperty *prop, *nextprop;
    icalparameter *param;

    /* Iterate through each property */
    for (prop = icalcomponent_get_first_property(parent, path_seg->kind);
         prop; prop = nextprop) {
        nextprop = icalcomponent_get_next_property(parent, path_seg->kind);

        /* Check prop-match */
        int match = 1;
        if (path_seg->match.prop.param) {
            /* Check param-match */
            match = apply_param_match(prop, &path_seg->match);
        }
        else if (path_seg->match.prop.value) {
            /* Check prop-[not-]equal */
            const char *prop_val = icalproperty_get_value_as_string(prop);

            match = !strcmp(path_seg->match.prop.value, prop_val);
            if (path_seg->match.prop.not) match = !match;  /* invert */
        }
        if (!match) continue;

        if (path_seg->child) {
            /* Recurse into next segment */
            apply_patch(path_seg->child, prop, num_changes);
        }
        else if (path_seg->action == ACTION_DELETE) {
            /* Delete existing property */
            switch (path_seg->kind) {
            case ICAL_RDATE_PROPERTY:
            case ICAL_EXDATE_PROPERTY:
            case ICAL_FREEBUSY_PROPERTY:
            case ICAL_CATEGORIES_PROPERTY:
            case ICAL_RESOURCES_PROPERTY:
            case ICAL_ACCEPTRESPONSE_PROPERTY:
            case ICAL_POLLPROPERTIES_PROPERTY:
                /* Multi-valued property */
                if (path_seg->data) {
                    /* Check if entire property value == single value */
                    const char *single = (const char *) path_seg->data;
                    const char *propval = icalproperty_get_value_as_string(prop);

                    if (strcmp(propval, single)) {
                        /* Not an exact match, try to remove single value */
                        char *newval = remove_single_value(propval, single);
                        if (newval) {
                            *num_changes += 1;
                            icalproperty_set_value(prop,
                                                   icalvalue_new_string(newval));
                            free(newval);
                        }
                        break;
                    }
                }

                /* Fall through and delete entire property */
                GCC_FALLTHROUGH

            default:
                *num_changes += 1;
                icalcomponent_remove_property(parent, prop);
                icalproperty_free(prop);
                break;
            }
        }
        else if (path_seg->action == ACTION_SETPARAM) {
            /* Set parameter(s) from those on PATCH-PARAMETER */
            icalproperty *pp_prop = (icalproperty *) path_seg->data;

            *num_changes += 1;
            for (param = icalproperty_get_first_parameter(pp_prop,
                                                          ICAL_ANY_PARAMETER);
                 param;
                 param = icalproperty_get_next_parameter(pp_prop,
                                                         ICAL_ANY_PARAMETER)) {
                icalproperty_set_parameter(prop, icalparameter_clone(param));
            }
        }
    }
}

static void create_override(icalcomponent *master, struct icaltime_span *span,
                            void *rock)
{
    icalcomponent *new;
    icalproperty *prop, *next;
    struct icaltimetype dtstart, dtend, now;
    const icaltimezone *tz = NULL;
    const char *tzid;
    int is_date;

    now = icaltime_current_time_with_zone(icaltimezone_get_utc_timezone());

    new = icalcomponent_clone(master);

    for (prop = icalcomponent_get_first_property(new, ICAL_ANY_PROPERTY);
         prop; prop = next) {
        next = icalcomponent_get_next_property(new, ICAL_ANY_PROPERTY);

        switch (icalproperty_isa(prop)) {
        case ICAL_DTSTART_PROPERTY:
            /* Set DTSTART for this recurrence */
            dtstart = icalproperty_get_dtstart(prop);
            is_date = icaltime_is_date(dtstart);
            tz = icaltime_get_timezone(dtstart);

            dtstart = icaltime_from_timet_with_zone(span->start, is_date, tz);
            icaltime_set_timezone(&dtstart, tz);
            icalproperty_set_dtstart(prop, dtstart);

            /* Add RECURRENCE-ID for this recurrence */
            prop = icalproperty_new_recurrenceid(dtstart);
            tzid = icaltimezone_get_location_tzid((icaltimezone *) tz);
            if (tzid) {
                icalproperty_add_parameter(prop, icalparameter_new_tzid(tzid));
            }
            icalcomponent_add_property(new, prop);
            break;

        case ICAL_DTEND_PROPERTY:
            /* Set DTEND for this recurrence */
            dtend = icalproperty_get_dtend(prop);
            is_date = icaltime_is_date(dtend);
            tz = icaltime_get_timezone(dtend);

            dtend = icaltime_from_timet_with_zone(span->end, is_date, tz);
            icaltime_set_timezone(&dtend, tz);
            icalproperty_set_dtend(prop, dtend);
            break;

        case ICAL_RRULE_PROPERTY:
        case ICAL_RDATE_PROPERTY:
        case ICAL_EXDATE_PROPERTY:
            /* Remove recurrence properties */
            icalcomponent_remove_property(new, prop);
            icalproperty_free(prop);
            break;

        case ICAL_DTSTAMP_PROPERTY:
            /* Update DTSTAMP */
            icalproperty_set_dtstamp(prop, now);
            break;

        case ICAL_CREATED_PROPERTY:
            /* Update CREATED */
            icalproperty_set_created(prop, now);
            break;

        case ICAL_LASTMODIFIED_PROPERTY:
            /* Update LASTMODIFIED */
            icalproperty_set_lastmodified(prop, now);
            break;

        default:
            break;
        }
    }

    *((icalcomponent **) rock) = new;
}

/* Apply property updates */
static void apply_property_updates(struct patch_data_t *patch,
                                   icalcomponent *parent, int *num_changes)
{
    icalproperty *prop = NULL, *nextprop, *newprop;

    for (newprop = icalcomponent_get_first_property(patch->patch,
                                                    ICAL_ANY_PROPERTY);
         newprop;
         newprop = icalcomponent_get_next_property(patch->patch,
                                                   ICAL_ANY_PROPERTY)) {
        icalproperty_kind kind = icalproperty_isa(newprop);
        icalparameter_patchaction action = ICAL_PATCHACTION_BYNAME;
        icalparameter *actionp;
        union match_criteria_t byparam;

        memset(&byparam, 0, sizeof(union match_criteria_t));
        newprop = icalproperty_clone(newprop);

        actionp = icalproperty_get_first_parameter(newprop,
                                                   ICAL_PATCHACTION_PARAMETER);
        if (actionp) {
            action = icalparameter_get_patchaction(actionp);
            if (action == ICAL_PATCHACTION_X) {
                /* libical treats DQUOTEd BYPARAM as X value */
                const char *byparam_prefix = "BYPARAM@";
                const char *x_val = icalparameter_get_xvalue(actionp);
                if (!strncmp(x_val, byparam_prefix, strlen(byparam_prefix))) {
                    /* Parse param-match */
                    const char *p = x_val + strlen(byparam_prefix);
                    size_t namelen = strcspn(p, "!=");
                    byparam.prop.param = xstrndup(p, namelen);
                    p += namelen;

                    if (*p) {
                        if (*p++ == '!') byparam.prop.not = 1;
                        byparam.prop.value = xstrdup(p);
                    }
                    action = ICAL_PATCHACTION_BYPARAM;
                }
            }

            icalproperty_remove_parameter_by_ref(newprop, actionp);
            icalparameter_free(actionp);
        }

        if (action != ICAL_PATCHACTION_CREATE) {
            /* Delete properties matching those being updated */
            const char *value = icalproperty_get_value_as_string(newprop);

            for (prop = icalcomponent_get_first_property(parent, kind);
                 prop; prop = nextprop) {
                int match = 1;

                nextprop = icalcomponent_get_next_property(parent, kind);

                if (action == ICAL_PATCHACTION_BYVALUE) {
                    match = !strcmp(value,
                                    icalproperty_get_value_as_string(prop));
                }
                else if (action == ICAL_PATCHACTION_BYPARAM) {
                    /* Check param-match */
                    match = apply_param_match(prop, &byparam);
                    free(byparam.prop.param);
                    free(byparam.prop.value);
                }
                if (!match) continue;

                icalcomponent_remove_property(parent, prop);
                icalproperty_free(prop);
            }
        }

        *num_changes += 1;
        icalcomponent_add_property(parent, newprop);
    }
}

/* Apply property updates */
static void apply_component_updates(struct patch_data_t *patch,
                                    icalcomponent *parent, int *num_changes)
{
    icalcomponent *comp, *nextcomp, *newcomp;

    for (newcomp = icalcomponent_get_first_component(patch->patch,
                                                     ICAL_ANY_COMPONENT);
         newcomp;
         newcomp = icalcomponent_get_next_component(patch->patch,
                                                    ICAL_ANY_COMPONENT)){
        icalcomponent_kind kind = icalcomponent_isa(newcomp);
        const char *uid = icalcomponent_get_uid(newcomp);
        icaltimetype rid = icalcomponent_get_recurrenceid(newcomp);

        newcomp = icalcomponent_clone(newcomp);

        /* Delete components matching those being updated */
        for (comp = icalcomponent_get_first_component(parent, kind);
             uid && comp; comp = nextcomp) {
            const char *thisuid = icalcomponent_get_uid(comp);

            nextcomp = icalcomponent_get_next_component(parent, kind);

            if (thisuid &&  /* VALARMs make not have a UID */
                (strcmp(uid, thisuid) ||
                 icaltime_compare(rid, icalcomponent_get_recurrenceid(comp)))) {
                /* skip */
                continue;
            }

            icalcomponent_remove_component(parent, comp);
            icalcomponent_free(comp);
        }

        *num_changes += 1;
        icalcomponent_add_component(parent, newcomp);
    }
}

/* Apply a patch action to a component segment */
static void apply_patch_component(struct path_segment_t *path_seg,
                                 icalcomponent *parent, int *num_changes)
{
    icalcomponent *comp, *nextcomp, *master = NULL;

    /* Iterate through each component */
    if (path_seg->kind == ICAL_VCALENDAR_COMPONENT)
        comp = parent;
    else
        comp = icalcomponent_get_first_component(parent, path_seg->kind);

    for (; comp; comp = nextcomp) {
        nextcomp = icalcomponent_get_next_component(parent, path_seg->kind);

        /* Check comp-match */
        if (path_seg->match.comp.uid &&
            strcmpnull(path_seg->match.comp.uid, icalcomponent_get_uid(comp))) {
            continue;  /* UID doesn't match */
        }

        if (icaltime_is_valid_time(path_seg->match.comp.rid)) {
            icaltimetype recurid =
                icalcomponent_get_recurrenceid_with_zone(comp);

            if (icaltime_is_null_time(recurid)) master = comp;
            if (icaltime_compare(recurid, path_seg->match.comp.rid)) {
                if (!nextcomp && master) {
                    /* Possibly add an override recurrence.
                       Set start and end to coincide with recurrence */
                    icalcomponent *override = NULL;
                    struct icaltimetype start = path_seg->match.comp.rid;
                    struct icaltimetype end =
                        icaltime_add(start, icalcomponent_get_duration(master));
                    icalcomponent_foreach_recurrence(master, start, end,
                                                     &create_override,
                                                     &override);
                    if (!override) break;  /* Can't override - done */

                    /* Act on new overridden component */
                    icalcomponent_add_component(parent, override);
                    comp = override;
                }
                else continue;  /* RECURRENCE-ID doesn't match */
            }
            else {
                /* RECURRENCE-ID matches - done after processing this comp */
                nextcomp = NULL;
            }
        }

        if (path_seg->child) {
            /* Recurse into next segment */
            apply_patch(path_seg->child, comp, num_changes);
        }
        else if (path_seg->action == ACTION_DELETE) {
            /* Delete existing component */
            *num_changes += 1;
            icalcomponent_remove_component(parent, comp);
            icalcomponent_free(comp);
        }
        else if (path_seg->action == ACTION_UPDATE) {
            /* Patch existing component */
            struct patch_data_t *patch = (struct patch_data_t *) path_seg->data;
            struct path_segment_t *path_seg2;

            /* Process all PATCH-DELETEs first */
            for (path_seg2 = patch->delete;
                 path_seg2; path_seg2 = path_seg2->sibling) {
                apply_patch(path_seg2, comp, num_changes);
            }

            /* Process all PATCH-SETPARAMETERs second */
            for (path_seg2 = patch->setparam;
                 path_seg2; path_seg2 = path_seg2->sibling) {
                apply_patch(path_seg2, comp, num_changes);
            }

            /* Process all components updates third */
            apply_component_updates(patch, comp, num_changes);

            /* Process all property updates last */
            apply_property_updates(patch, comp, num_changes);
        }
    }
}

/* Apply a patch action to a target segment */
static void apply_patch(struct path_segment_t *path_seg,
                        void *parent, int *num_changes)
{
    switch (path_seg->type) {
    case SEGMENT_COMP:
        apply_patch_component(path_seg, parent, num_changes);
        break;

    case SEGMENT_PROP:
        apply_patch_property(path_seg, parent, num_changes);
        break;

    case SEGMENT_PARAM:
        apply_patch_parameter(path_seg, parent, num_changes);
        break;
    }
}

static void path_segment_free(struct path_segment_t *path_seg)
{
    struct path_segment_t *next;

    for (; path_seg; path_seg = next) {
        next = path_seg->child;

        switch (path_seg->type) {
        case SEGMENT_COMP:
            free(path_seg->match.comp.uid);
            break;

        case SEGMENT_PROP:
            free(path_seg->match.prop.param);
            free(path_seg->match.prop.value);
            break;

        case SEGMENT_PARAM:
            break;
        }

        free(path_seg);
    }
}

EXPORTED int icalcomponent_apply_vpatch(icalcomponent *ical,
                                        icalcomponent *vpatch,
                                        int *num_changes, const char **errstr)
{
    icalcomponent *patch;
    icalproperty *prop, *nextprop;
    int r, junkcount;
    const char *junkerr;

    if (!num_changes) num_changes = &junkcount;
    if (!errstr) errstr = &junkerr;

    /* Process each patch sub-component */
    for (patch = icalcomponent_get_first_component(vpatch, ICAL_ANY_COMPONENT);
         patch;
         patch = icalcomponent_get_next_component(vpatch, ICAL_ANY_COMPONENT)) {
        struct path_segment_t *target = NULL;
        struct patch_data_t patch_data = { NULL, NULL, NULL };
        r = 0;

        if (icalcomponent_isa(patch) != ICAL_XPATCH_COMPONENT) {
            /* Unknown patch action */
            *errstr = "Unsupported patch action";
            r = -1;
            goto done;
        }

        /* This function is destructive of PATCH components, make a clone */
        patch_data.patch = patch = icalcomponent_clone(patch);

        prop = icalcomponent_get_first_property(patch,
                                                ICAL_PATCHTARGET_PROPERTY);
        if (!prop) {
            *errstr = "Missing TARGET";
            r = -1;
            goto done;
        }

        /* Parse PATCH-TARGET */
        char *path = xstrdup(icalproperty_get_patchtarget(prop));

        icalcomponent_remove_property(patch, prop);
        icalproperty_free(prop);

        r = parse_target_path(path, &target, ACTION_UPDATE, &patch_data, errstr);
        free(path);

        if (r) goto done;
        else if (!target || target->type != SEGMENT_COMP ||
                 target->kind != ICAL_VCALENDAR_COMPONENT ||
                 target->match.comp.uid) {
            *errstr = "Initial segment of PATCH-TARGET"
                " MUST be an unmatched VCALENDAR";
            r = -1;
            goto done;
        }

        /* Parse and remove all PATCH-DELETEs and PATCH-PARAMETERs */
        for (prop = icalcomponent_get_first_property(patch, ICAL_ANY_PROPERTY);
             prop; prop = nextprop) {

            icalproperty_kind kind = icalproperty_isa(prop);
            struct path_segment_t *ppath = NULL;

            nextprop = icalcomponent_get_next_property(patch, ICAL_ANY_PROPERTY);

            if (kind == ICAL_PATCHDELETE_PROPERTY) {
                path = xstrdup(icalproperty_get_patchdelete(prop));

                icalcomponent_remove_property(patch, prop);
                icalproperty_free(prop);

                r = parse_target_path(path, &ppath, ACTION_DELETE, NULL, errstr);
                free(path);

                if (r) goto done;
                else if (!ppath ||
                         (ppath->type == SEGMENT_COMP &&
                          ppath->kind == ICAL_VCALENDAR_COMPONENT)) {
                    *errstr = "Initial segment of PATCH-DELETE"
                        " MUST NOT be VCALENDAR";
                    r = -1;
                    goto done;
                }
                else {
                    /* Add this delete path to our list */
                    ppath->sibling = patch_data.delete;
                    patch_data.delete = ppath;
                }
            }
            else if (kind == ICAL_PATCHPARAMETER_PROPERTY) {
                path = xstrdup(icalproperty_get_patchparameter(prop));

                icalcomponent_remove_property(patch, prop);

                r = parse_target_path(path, &ppath,
                                      ACTION_SETPARAM, prop, errstr);
                free(path);

                if (r) goto done;
                else if (!ppath || ppath->type != SEGMENT_PROP) {
                    *errstr = "Initial segment of PATCH-PARAMETER"
                        " MUST be a property";
                    r = -1;
                    goto done;
                }
                else {
                    /* Add this setparam path to our list */
                    ppath->sibling = patch_data.setparam;
                    patch_data.setparam = ppath;
                }
            }
        }

        /* Apply this patch to the target component */
        apply_patch(target, ical, num_changes);

      done:
        if (patch) icalcomponent_free(patch);
        if (target) {
            struct path_segment_t *next;

            /* Cleanup target paths */
            path_segment_free(target);
            for (target = patch_data.delete; target; target = next) {
                next = target->sibling;
                if (target->data) free(target->data);
                path_segment_free(target);
            }
            for (target = patch_data.setparam; target; target = next) {
                next = target->sibling;
                if (target->data) icalproperty_free(target->data);
                path_segment_free(target);
            }
        }

        if (r) return r;
    }

    return 0;
}


#ifndef HAVE_RFC7986_COLOR

/* Replacement for missing function in 3.0.0 <= libical < 3.0.5 */

EXPORTED icalproperty *icalproperty_new_color(const char *v)
{
    icalproperty *prop = icalproperty_new_x(v);
    icalproperty_set_x_name(prop, "COLOR");
    return prop;
}

#endif /* HAVE_RFC7986_COLOR */

EXPORTED const char *icaltimezone_get_location_tzid(const icaltimezone *zone)
{
    const char *v = icaltimezone_get_location((icaltimezone*) zone);
    if (!v) v = icaltimezone_get_tzid((icaltimezone*) zone);
    return v;
}

EXPORTED const char *icaltime_get_location_tzid(icaltimetype t)
{
    return icaltimezone_get_location_tzid(t.zone);
}

static void icalproperty_remove_xparam(icalproperty *prop, const char *name)
{
    icalparameter *param, *next;

    for (param = icalproperty_get_first_parameter(prop, ICAL_ANY_PARAMETER);
         param;
         param = next) {

        next = icalproperty_get_next_parameter(prop, ICAL_ANY_PARAMETER);
        if (strcasecmpsafe(icalparameter_get_xname(param), name)) {
            continue;
        }
        icalproperty_remove_parameter_by_ref(prop, param);
    }
}

EXPORTED void icalproperty_set_xparam(icalproperty *prop,
                                      const char *name, const char *val, int purge)
{
    icalparameter *param;

    if (purge) icalproperty_remove_xparam(prop, name);

    param = icalparameter_new(ICAL_X_PARAMETER);
    icalparameter_set_xname(param, name);
    icalparameter_set_xvalue(param, val);
    icalproperty_add_parameter(prop, param);
}

#endif /* HAVE_ICAL */
