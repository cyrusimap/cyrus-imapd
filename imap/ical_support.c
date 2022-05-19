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
#include "icu_wrap.h"

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

EXPORTED icaltimezone *icaltimezone_get_cyrus_timezone_from_tzid(const char *tzid)
{
    if (!tzid)
        return NULL;

    /* Use UTC singleton for Etc/UTC */
    if (!strcmp(tzid, "Etc/UTC") || !strcmp(tzid, "UTC"))
        return icaltimezone_get_utc_timezone();

    icaltimezone *tz = icaltimezone_get_builtin_timezone(tzid);
    if (tz == NULL)
        tz = icaltimezone_get_builtin_timezone_from_tzid(tzid);
    if (tz == NULL) {
        /* see if its a MS Windows TZID */
        char *icutzid = icu_getIDForWindowsID(tzid);
        if (icutzid) {
            tz = icaltimezone_get_builtin_timezone(icutzid);
            if (tz == NULL)
                tz = icaltimezone_get_builtin_timezone_from_tzid(icutzid);
            free(icutzid);
        }
    }
    return tz;
}

static struct icaltimetype icalcomponent_get_mydatetime(icalcomponent *comp, icalproperty *prop)
{
    icalcomponent *c;
    icalparameter *param;
    struct icaltimetype ret;

    ret = icalvalue_get_datetime(icalproperty_get_value(prop));

    if ((param = icalproperty_get_first_parameter(prop, ICAL_TZID_PARAMETER)) != NULL) {
        const char *tzid = icalparameter_get_tzid(param);
        icaltimezone *tz = icaltimezone_get_cyrus_timezone_from_tzid(tzid);
        if (tz == NULL) {
            /* Use embedded VTIMEZONE */
            for (c = comp; c != NULL; c = icalcomponent_get_parent(c)) {
                tz = icalcomponent_get_timezone(c, tzid);
                if (tz != NULL)
                    break;
            }
        }
        if (tz != NULL)
            ret = icaltime_set_timezone(&ret, tz);
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

struct multirrule_iterator_entry {
    struct icaltimetype next;
    icalrecur_iterator *icaliter;
};

struct multirrule_iterator {
    struct multirrule_iterator_entry *entries;
    size_t nentries;
    size_t nalloced;
};

static void multirrule_iterator_fini(struct multirrule_iterator *iter)
{
    if (!iter) return;

    size_t i;
    for (i = 0; i < iter->nentries; i++) {
        icalrecur_iterator_free(iter->entries[i].icaliter);
    }
    free(iter->entries);
    iter->entries = NULL;
    iter->nentries = 0;
    iter->nalloced = 0;
}

static void multirrule_iterator_add(struct multirrule_iterator *iter,
                                    struct icalrecurrencetype recur,
                                    icaltimetype dtstart,
                                    icaltimetype range_start)
{
    icalrecur_iterator *icaliter = icalrecur_iterator_new(recur, dtstart);
    if (!icaliter) return;
    if (recur.count > 0) {
        icalrecur_iterator_set_start(icaliter, range_start);
    }

    iter->nentries++;
    if (iter->nentries > iter->nalloced) {
        iter->nalloced = iter->nalloced ? iter->nalloced * 2 : 4;
        iter->entries = xrealloc(iter->entries,
                iter->nalloced * sizeof(struct multirrule_iterator_entry));
    }

    struct multirrule_iterator_entry *entry = iter->entries + iter->nentries - 1;
    entry->icaliter = icaliter;
    entry->next = icalrecur_iterator_next(entry->icaliter);
}

static icaltimetype multirrule_iterator_next(struct multirrule_iterator *iter)
{
    if (!iter->nentries) return icaltime_null_time();

    // XXX if linear search turns out to be too slow use a priority queue
    icaltimetype next = iter->entries[0].next;
    size_t i, min = 0;
    for (i = 1; i < iter->nentries; i++) {
        struct multirrule_iterator_entry *entry = iter->entries + i;
        if (icaltime_is_null_time(entry->next)) {
            continue;
        }
        if (icaltime_is_null_time(next) || icaltime_compare(next, entry->next) > 0) {
            min = i;
            next = entry->next;
        }
    }
    iter->entries[min].next = icalrecur_iterator_next(iter->entries[min].icaliter);
    return next;
}

static struct multirrule_iterator
multirrule_iterator_for_range(icalcomponent *comp,
                              struct icalperiodtype range,
                              icaltime_span range_span,
                              icaltimetype dtstart,
                              const icaltimezone *floatingtz,
                              icalproperty_kind kind)
{
    struct multirrule_iterator iter = { NULL, 0, 0 };
    if (!comp) return iter;

    icalproperty *rrule;
    for (rrule = icalcomponent_get_first_property(comp, kind);
         rrule;
         rrule = icalcomponent_get_next_property(comp, kind)) {

        struct icalrecurrencetype recur = kind == ICAL_EXRULE_PROPERTY ?
            icalproperty_get_exrule(rrule) : icalproperty_get_rrule(rrule);

        /* check if span of RRULE overlaps range */
        icaltime_span recur_span = {
            icaltime_to_timet(dtstart, floatingtz),
            icaltime_to_timet(recur.until, NULL), 0 /* is_busy */
        };
        if (!recur_span.end) recur_span.end = eternity;

        if (!span_compare_range(&recur_span, &range_span)) {
            multirrule_iterator_add(&iter, recur, dtstart, range.start);
        }
    }

    return iter;
}

EXPORTED int icalcomponent_myforeach(icalcomponent *ical,
                                   struct icalperiodtype range,
                                   const icaltimezone *floatingtz,
                                   int (*callback) (icalcomponent *comp,
                                                    icaltimetype start,
                                                    icaltimetype end,
                                                    icaltimetype recurid,
                                                    int is_standalone,
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
    int is_standalone = !mastercomp;

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
    struct multirrule_iterator rrule_itr = multirrule_iterator_for_range(mastercomp,
            range, range_span, dtstart, floatingtz, ICAL_RRULE_PROPERTY);
    struct multirrule_iterator exrule_itr = multirrule_iterator_for_range(mastercomp,
            range, range_span, dtstart, floatingtz, ICAL_EXRULE_PROPERTY);

    size_t onum = 0;
    struct recurrence_data *data = overrides->num_elements ?
        icalarray_element_at(overrides, onum) : NULL;
    struct icaltimetype ritem = rrule_itr.nentries ?
        multirrule_iterator_next(&rrule_itr) : dtstart;
    struct icaltimetype xitem = exrule_itr.nentries ?
        multirrule_iterator_next(&exrule_itr) : icaltime_null_time();

    int has_rrule = !!icalcomponent_get_first_property(mastercomp, ICAL_RRULE_PROPERTY);

    while (data || !icaltime_is_null_time(ritem)) {
        time_t otime = data ? data->span.start : eternity;
        time_t rtime = icaltime_to_timet(ritem, floatingtz);

        if (icaltime_is_null_time(ritem) || (data && otime <= rtime)) {
            icaltimetype recurid = icalcomponent_get_recurrenceid(data->comp);
            /* an overridden recurrence */
            if (data->comp &&
                !span_compare_range(&data->span, &range_span) &&
                !callback(data->comp, data->dtstart, data->dtend, recurid,
                    is_standalone, callback_data))
                goto done;

            /* if they're both the same time, it's a precisely overridden
             * recurrence, so increment both */
            if (rtime == otime) {
                /* incr recurrences */
                ritem = rrule_itr.nentries ?
                    multirrule_iterator_next(&rrule_itr) : icaltime_null_time();
            }

            /* incr overrides */
            onum++;
            data = (onum < overrides->num_elements) ?
                icalarray_element_at(overrides, onum) : NULL;
        }
        else {
            /* a non-overridden recurrence */

            /* check if this recurrence-id is excluded */
            while (!icaltime_is_null_time(xitem) && icaltime_compare(xitem, ritem) < 0) {
                xitem = multirrule_iterator_next(&exrule_itr);
            }
            if (icaltime_compare(xitem, ritem)) {
                /* not excluded - process this recurrence-id */
                struct icaltimetype thisend = icaltime_add(ritem, event_length);
                icaltime_span this_span = {
                    rtime, icaltime_to_timet(thisend, floatingtz), 0 /* is_busy */
                };

                int r = span_compare_range(&this_span, &range_span);
                if (r > 0)
                    goto done; /* gone past the end of range */

                if (!r) {
                    icaltimetype recurid = ritem;
                    recurid.zone = dtstart.zone;
                    r = callback(mastercomp, ritem, thisend, has_rrule ?
                            recurid : icaltime_null_time(), is_standalone, callback_data);
                    if (!r) goto done;
                }
            }

            /* incr recurrences */
            ritem = rrule_itr.nentries ?
                multirrule_iterator_next(&rrule_itr) : icaltime_null_time();
        }
    }

 done:
    multirrule_iterator_fini(&exrule_itr);
    multirrule_iterator_fini(&rrule_itr);

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

    if (prop == 0) {
        return icaltime_null_time();
    }

    return icalproperty_get_datetime_with_component(prop, comp);
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
        ptrarray_t detached_rrules = PTRARRAY_INITIALIZER;

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
                do {
                    struct icalrecurrencetype recur = icalproperty_get_rrule(rrule);
                    if (!icaltime_is_null_time(recur.until)) {
                        /* Recurrence ends - calculate dtend of last recurrence */
                        struct icaldurationtype duration;
                        icaltimezone *utc = icaltimezone_get_utc_timezone();

                        duration = icaltime_subtract(period.end, period.start);
                        icaltimetype end =
                            icaltime_add(icaltime_convert_to_zone(recur.until, utc),
                                    duration);

                        if (icaltime_compare(period.end, end) < 0)
                            period.end = end;

                        /* Do RDATE expansion only */
                        /* Temporarily remove RRULE to allow for expansion of
                         * remaining recurrences. */
                        icalcomponent_remove_property(comp, rrule);
                        ptrarray_append(&detached_rrules, rrule);
                    }
                    else if (!recur.count) {
                        /* Recurrence never ends - set end of span to eternity */
                        span.end =
                            icaltime_from_timet_with_zone(caldav_eternity, 0, NULL);

                        /* Skip RRULE & RDATE expansion */
                        expand = 0;
                    }
                    rrule = icalcomponent_get_next_property(comp, ICAL_RRULE_PROPERTY);
                } while (expand && rrule);
            }

            /* Expand (remaining) recurrences */
            if (expand) {
                icalcomponent_foreach_recurrence(
                        comp,
                        icaltime_from_timet_with_zone(caldav_epoch, 0, NULL),
                        icaltime_from_timet_with_zone(caldav_eternity, 0, NULL),
                        utc_timespan_cb, &span);
            }

            /* Add RRULEs back, if we had removed them before. */
            if (ptrarray_size(&detached_rrules)) {
                /* Detach any remaining RRULEs, then add them in order */
                for (rrule = icalcomponent_get_first_property(comp, ICAL_RRULE_PROPERTY);
                     rrule;
                     rrule = icalcomponent_get_next_property(comp, ICAL_RRULE_PROPERTY)) {
                    icalcomponent_remove_property(comp, rrule);
                    ptrarray_append(&detached_rrules, rrule);
                }
                int i;
                for (i = 0; i < ptrarray_size(&detached_rrules); i++) {
                    rrule = ptrarray_nth(&detached_rrules, i);
                    icalcomponent_add_property(comp, rrule);
                }
            }

            ptrarray_fini(&detached_rrules);
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
    char *xname;                      /* name of element, if type 'X' */
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
        if (new->kind == ICAL_X_COMPONENT) new->xname = xstrdup(path);
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
        if (new->kind == ICAL_X_PROPERTY) new->xname = xstrdup(path);

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
            if (new->kind == ICAL_X_PARAMETER) new->xname = xstrdup(path);

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
    icalparameter *param, *nextparam;

    if (path_seg->action != ACTION_DELETE) return;

    /* Iterate through each parameter */
    for (param = icalproperty_get_first_parameter(parent, path_seg->kind);
         param; param = nextparam) {
        nextparam = icalproperty_get_next_parameter(parent, path_seg->kind);

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
                    continue;
                }
            }
            break;

        case ICAL_X_PARAMETER:
            /* Check X- parameter name match */
            if (strcmp(path_seg->xname, icalparameter_get_iana_name(param))) {
                continue;
            }
            break;
        }

        *num_changes += 1;
        icalproperty_remove_parameter_by_ref(parent, param);
    }
}

static int apply_param_match(icalproperty *prop, union match_criteria_t *match)
{
    icalparameter_kind kind;
    icalparameter *param;
    int ret = 0;

    kind = icalparameter_string_to_kind(match->prop.param);

    /* Iterate through each parameter */
    for (param = icalproperty_get_first_parameter(prop, kind);
         !ret && param; param = icalproperty_get_next_parameter(prop, kind)) {
        /* Check X- parameter name match */
        if (kind == ICAL_X_PARAMETER &&
            strcmp(match->prop.param, icalparameter_get_iana_name(param))) {
            continue;
        }
        else if (match->prop.value) {
            const char *param_val = icalparameter_get_value_as_string(param);

            ret = !strcmp(match->prop.value, param_val);
        }
        else {
            ret = 1;
        }
    }

    if (match->prop.not) ret = !ret;  /* invert */

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

        /* Check X- property name match */
        if (path_seg->kind == ICAL_X_PROPERTY &&
            strcmp(path_seg->xname, icalproperty_get_property_name(prop))) {
            continue;
        }

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

        /* Check X- component name match */
        if (path_seg->kind == ICAL_X_COMPONENT &&
            strcmp(path_seg->xname, icalcomponent_get_component_name(comp))) {
            continue;
        }

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

        free(path_seg->xname);
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

EXPORTED int icalcomponent_read_usedefaultalerts(icalcomponent *comp)
{
    icalcomponent *ical = NULL;
    icalcomponent_kind kind = ICAL_NO_COMPONENT;

    if (icalcomponent_isa(comp) == ICAL_VCALENDAR_COMPONENT) {
        ical = comp;
        comp = icalcomponent_get_first_real_component(ical);
        kind = icalcomponent_isa(comp);
    }
    do {
        icalproperty *prop;
        for (prop = icalcomponent_get_first_property(comp, ICAL_X_PROPERTY); prop;
             prop = icalcomponent_get_next_property(comp, ICAL_X_PROPERTY)) {
            const char *propname = icalproperty_get_x_name(prop);
            if (!strcasecmp(propname, "X-APPLE-DEFAULT-ALARM")) {
                const char *val = icalproperty_get_value_as_string(prop);
                return !strcasecmpsafe(val, "TRUE");
            }
        }
        if (ical) comp = icalcomponent_get_next_component(ical, kind);
    } while (ical && comp);

    return -1;
}

EXPORTED void icalcomponent_set_usedefaultalerts(icalcomponent *comp)
{
    icalcomponent *ical = NULL;
    icalcomponent_kind kind = ICAL_NO_COMPONENT;

    if (icalcomponent_isa(comp) == ICAL_VCALENDAR_COMPONENT) {
        ical = comp;
        comp = icalcomponent_get_first_real_component(ical);
        kind = icalcomponent_isa(comp);
    }
    do {
        int has_usedefaultalerts = 0;

        icalproperty *prop, *nextprop;
        for (prop = icalcomponent_get_first_property(comp, ICAL_X_PROPERTY); prop;
             prop = nextprop) {

            nextprop = icalcomponent_get_next_property(comp, ICAL_X_PROPERTY);

            if (strcasecmp(icalproperty_get_x_name(prop), "X-APPLE-DEFAULT-ALARM"))
                continue;

            const char *val = icalproperty_get_value_as_string(prop);
            if (strcasecmpsafe(val, "TRUE") || has_usedefaultalerts) {
                // Remove conflicting or duplicate entries
                icalcomponent_remove_property(comp, prop);
                icalproperty_free(prop);
            }
            else has_usedefaultalerts = 1;
        }

        if (!has_usedefaultalerts) {
            prop = icalproperty_new(ICAL_X_PROPERTY);
            icalproperty_set_x_name(prop, "X-APPLE-DEFAULT-ALARM");
            icalproperty_set_value(prop, icalvalue_new_boolean(1));
            icalcomponent_add_property(comp, prop);
        }

        if (ical) comp = icalcomponent_get_next_component(ical, kind);
    } while (ical && comp);
}

EXPORTED void icalcomponent_add_defaultalerts(icalcomponent *ical,
                                              icalcomponent *withtime,
                                              icalcomponent *withdate,
                                              int force)
{
    if (!withtime && !withdate)
        return;

    icalcomponent *comp = icalcomponent_get_first_real_component(ical);
    icalcomponent_kind kind = icalcomponent_isa(comp);
    if (kind != ICAL_VEVENT_COMPONENT && kind != ICAL_VTODO_COMPONENT)
        return;

    /* Add default alarms */
    for ( ; comp; comp = icalcomponent_get_next_component(ical, kind)) {
        if (force || icalcomponent_read_usedefaultalerts(comp) > 0) {

            /* Determine which default alarms to add */
            int is_date;
            if (kind == ICAL_VTODO_COMPONENT) {
                if (icalcomponent_get_first_property(comp, ICAL_DTSTART_PROPERTY))
                    is_date = icalcomponent_get_dtstart(comp).is_date;
                else if (icalcomponent_get_first_property(comp, ICAL_DUE_PROPERTY))
                    is_date = icalcomponent_get_due(comp).is_date;
                else
                    is_date = 1;
            }
            else is_date = icalcomponent_get_dtstart(comp).is_date;

            icalcomponent *alerts = is_date ?  withdate : withtime;

            /* Remove VALARMs in component */
            icalcomponent *curr, *next = NULL;
            for (curr = icalcomponent_get_first_component(comp, ICAL_VALARM_COMPONENT);
                    curr; curr = next) {
                next = icalcomponent_get_next_component(comp, ICAL_VALARM_COMPONENT);
                icalcomponent_remove_component(comp, curr);
                icalcomponent_free(curr);
            }

            /* Add default VALARMs */
            for (curr = icalcomponent_get_first_component(alerts, ICAL_VALARM_COMPONENT);
                 curr;
                 curr = icalcomponent_get_next_component(alerts, ICAL_VALARM_COMPONENT)) {

                icalcomponent *alarm = icalcomponent_clone(curr);

                /* Replace default description with component summary */
                const char *desc = icalcomponent_get_summary(comp);
                if (desc && *desc != '\0') {
                    icalproperty *prop =
                        icalcomponent_get_first_property(alarm, ICAL_DESCRIPTION_PROPERTY);
                    if (prop) {
                        icalcomponent_remove_property(alarm, prop);
                        icalproperty_free(prop);
                    }
                    prop = icalproperty_new_description(desc);
                    icalcomponent_add_property(alarm, prop);
                }

                /* Add alarm */
                icalcomponent_add_component(comp, alarm);
            }
        }
    }
}

static void check_tombstone(struct observance *tombstone,
                            struct observance *obs)
{
    if (icaltime_compare(obs->onset, tombstone->onset) > 0) {
        /* onset is closer to cutoff than existing tombstone */
        tombstone->name = icalmemory_tmp_copy(obs->name);
        tombstone->offset_from = tombstone->offset_to = obs->offset_to;
        tombstone->is_daylight = obs->is_daylight;
        tombstone->onset = obs->onset;
    }
}

struct rdate {
    icalproperty *prop;
    struct icaldatetimeperiodtype date;
};

static int rdate_compare(const void *rdate1, const void *rdate2)
{
    return icaltime_compare(((struct rdate *) rdate1)->date.time,
                            ((struct rdate *) rdate2)->date.time);
}

static int observance_compare(const void *obs1, const void *obs2)
{
    return icaltime_compare(((struct observance *) obs1)->onset,
                            ((struct observance *) obs2)->onset);
}

static void icalproperty_get_isstd_isgmt(icalproperty *prop,
                                         struct observance *obs)
{
    const char *time_type =
        icalproperty_get_parameter_as_string(prop, "X-OBSERVED-AT");

    if (!time_type) time_type = "W";

    switch (time_type[0]) {
    case 'G': case 'g':
    case 'U': case 'u':
    case 'Z': case 'z':
        obs->is_gmt = obs->is_std = 1;
        break;
    case 'S': case 's':
        obs->is_gmt = 0;
        obs->is_std = 1;
        break;
    case 'W': case 'w':
    default:
        obs->is_gmt = obs->is_std = 0;
        break;
    }
}

EXPORTED void icaltimezone_truncate_vtimezone_advanced(icalcomponent *vtz,
                                                       icaltimetype *startp, icaltimetype *endp,
                                                       icalarray *obsarray,
                                                       struct observance *proleptic,
                                                       icalcomponent **eternal_std,
                                                       icalcomponent **eternal_dst,
                                                       icaltimetype *last_dtstart,
                                                       int ms_compatible)
{
    icaltimetype start = *startp, end = *endp;
    icalcomponent *comp, *nextc, *tomb_std = NULL, *tomb_day = NULL;
    icalproperty *prop, *proleptic_prop = NULL;
    struct observance tombstone;
    unsigned need_tomb = !icaltime_is_null_time(start);
    unsigned adjust_start = !icaltime_is_null_time(start);
    unsigned adjust_end = !icaltime_is_null_time(end);

    if (last_dtstart) *last_dtstart = icaltime_null_time();

    /* See if we have a proleptic tzname in VTIMEZONE */
    for (prop = icalcomponent_get_first_property(vtz, ICAL_X_PROPERTY);
         prop;
         prop = icalcomponent_get_next_property(vtz, ICAL_X_PROPERTY)) {
        if (!strcmp("X-PROLEPTIC-TZNAME", icalproperty_get_x_name(prop))) {
            proleptic_prop = prop;
            break;
        }
    }

    memset(&tombstone, 0, sizeof(struct observance));
    tombstone.name = icalmemory_tmp_copy(proleptic_prop ?
                                         icalproperty_get_x(proleptic_prop) :
                                         "LMT");
    if (!proleptic_prop ||
        !icalproperty_get_parameter_as_string(prop, "X-NO-BIG-BANG"))
      tombstone.onset.year = -1;

    /* Process each VTMEZONE STANDARD/DAYLIGHT subcomponent */
    for (comp = icalcomponent_get_first_component(vtz, ICAL_ANY_COMPONENT);
         comp; comp = nextc) {
        icalproperty *dtstart_prop = NULL, *rrule_prop = NULL;
        icalarray *rdate_array = icalarray_new(sizeof(struct rdate), 10);
        icaltimetype dtstart;
        struct observance obs;
        unsigned n, trunc_dtstart = 0;
        int r;

        nextc = icalcomponent_get_next_component(vtz, ICAL_ANY_COMPONENT);

        memset(&obs, 0, sizeof(struct observance));
        obs.offset_from = obs.offset_to = INT_MAX;
        obs.is_daylight = (icalcomponent_isa(comp) == ICAL_XDAYLIGHT_COMPONENT);

        /* Grab the properties that we require to expand recurrences */
        for (prop = icalcomponent_get_first_property(comp, ICAL_ANY_PROPERTY);
             prop;
             prop = icalcomponent_get_next_property(comp, ICAL_ANY_PROPERTY)) {

            switch (icalproperty_isa(prop)) {
            case ICAL_TZNAME_PROPERTY:
                obs.name = icalproperty_get_tzname(prop);
                break;

            case ICAL_DTSTART_PROPERTY:
                dtstart_prop = prop;
                obs.onset = dtstart = icalproperty_get_dtstart(prop);
                icalproperty_get_isstd_isgmt(prop, &obs);
                if (last_dtstart && icaltime_compare(dtstart, *last_dtstart))
                    *last_dtstart = dtstart;
                break;

            case ICAL_TZOFFSETFROM_PROPERTY:
                obs.offset_from = icalproperty_get_tzoffsetfrom(prop);
                break;

            case ICAL_TZOFFSETTO_PROPERTY:
                obs.offset_to = icalproperty_get_tzoffsetto(prop);
                break;

            case ICAL_RRULE_PROPERTY:
                rrule_prop = prop;
                break;

            case ICAL_RDATE_PROPERTY: {
                struct rdate rdate = { prop, icalproperty_get_rdate(prop) };

                icalarray_append(rdate_array, &rdate);
                break;
            }

            default:
                /* ignore all other properties */
                break;
            }
        }

        /* We MUST have DTSTART, TZNAME, TZOFFSETFROM, and TZOFFSETTO */
        if (!dtstart_prop || !obs.name ||
            obs.offset_from == INT_MAX || obs.offset_to == INT_MAX) {
            icalarray_free(rdate_array);
            continue;
        }

        /* Adjust DTSTART observance to UTC */
        icaltime_adjust(&obs.onset, 0, 0, 0, -obs.offset_from);
        icaltime_set_utc(&obs.onset, 1);

        /* Check DTSTART vs window close */
        if (!icaltime_is_null_time(end) &&
            icaltime_compare(obs.onset, end) >= 0) {
            /* All observances occur on/after window close - remove component */
            icalcomponent_remove_component(vtz, comp);
            icalcomponent_free(comp);

            /* Actual range end == request range end */
            adjust_end = 0;

            /* Nothing else to do */
            icalarray_free(rdate_array);
            continue;
        }

        /* Check DTSTART vs window open */
        r = icaltime_compare(obs.onset, start);
        if (r < 0) {
            /* DTSTART is prior to our window open - check it vs tombstone */
            if (need_tomb) check_tombstone(&tombstone, &obs);

            /* Adjust it */
            trunc_dtstart = 1;

            /* Actual range start == request range start */
            adjust_start = 0;
        }
        else {
            /* DTSTART is on/after our window open */
            if (r == 0) need_tomb = 0;

            if (obsarray && !rrule_prop) {
                /* Add the DTSTART observance to our array */
                icalarray_append(obsarray, &obs);
            }
        }

        if (rrule_prop) {
            struct icalrecurrencetype rrule =
                icalproperty_get_rrule(rrule_prop);
            icalrecur_iterator *ritr = NULL;
            unsigned eternal = icaltime_is_null_time(rrule.until);
            unsigned trunc_until = 0;

            if (eternal) {
                if (obs.is_daylight) {
                    if (eternal_dst) *eternal_dst = comp;
                }
                else if (eternal_std) *eternal_std = comp;
            }

            /* Check RRULE duration */
            if (!eternal && icaltime_compare(rrule.until, start) < 0) {
                /* RRULE ends prior to our window open -
                   check UNTIL vs tombstone */
                obs.onset = rrule.until;
                if (need_tomb) check_tombstone(&tombstone, &obs);

                /* Remove RRULE */
                icalcomponent_remove_property(comp, rrule_prop);
                icalproperty_free(rrule_prop);
            }
            else {
                /* RRULE ends on/after our window open */
                if (!icaltime_is_null_time(end) &&
                    (eternal || icaltime_compare(rrule.until, end) >= 0)) {
                    /* RRULE ends after our window close - need to adjust it */
                    trunc_until = 1;
                }

                if (!eternal) {
                    /* Adjust UNTIL to local time (for iterator) */
                    icaltime_adjust(&rrule.until, 0, 0, 0, obs.offset_from);
                    icaltime_set_utc(&rrule.until, 0);
                }

                if (trunc_dtstart) {
                    /* Bump RRULE start to 1 year prior to our window open */
                    dtstart.year = start.year - 1;
                    dtstart.month = start.month;
                    dtstart.day = start.day;
                    icaltime_normalize(dtstart);
                }

                ritr = icalrecur_iterator_new(rrule, dtstart);
            }

            /* Process any RRULE observances within our window */
            if (ritr) {
                icaltimetype recur, prev_onset;

                /* Mark original DTSTART (UTC) */
                dtstart = obs.onset;

                while (!icaltime_is_null_time(obs.onset = recur =
                                              icalrecur_iterator_next(ritr))) {
                    unsigned ydiff;

                    /* Adjust observance to UTC */
                    icaltime_adjust(&obs.onset, 0, 0, 0, -obs.offset_from);
                    icaltime_set_utc(&obs.onset, 1);

                    if (trunc_until && icaltime_compare(obs.onset, end) >= 0) {
                        /* Observance is on/after window close */

                        /* Actual range end == request range end */
                        adjust_end = 0;

                        /* Check if DSTART is within 1yr of prev onset */
                        ydiff = prev_onset.year - dtstart.year;
                        if (ydiff <= 1) {
                            /* Remove RRULE */
                            icalcomponent_remove_property(comp, rrule_prop);
                            icalproperty_free(rrule_prop);

                            if (ydiff) {
                                /* Add previous onset as RDATE */
                                struct icaldatetimeperiodtype rdate = {
                                    prev_onset,
                                    icalperiodtype_null_period()
                                };
                                prop = icalproperty_new_rdate(rdate);
                                icalcomponent_add_property(comp, prop);
                            }
                        }
                        else if (!eternal) {
                            /* Set UNTIL to previous onset */
                            rrule.until = prev_onset;
                            icalproperty_set_rrule(rrule_prop, rrule);
                        }

                        /* We're done */
                        break;
                    }

                    /* Check observance vs our window open */
                    r = icaltime_compare(obs.onset, start);
                    if (r < 0) {
                        /* Observance is prior to our window open -
                           check it vs tombstone */
                        if (ms_compatible) {
                            /* XXX  We don't want to move DTSTART of the RRULE
                               as Outlook/Exchange doesn't appear to like
                               truncating the frontend of RRULEs */
                            need_tomb = 0;
                            trunc_dtstart = 0;
                            if (proleptic_prop) {
                                icalcomponent_remove_property(vtz,
                                                              proleptic_prop);
                                icalproperty_free(proleptic_prop);
                                proleptic_prop = NULL;
                            }
                        }
                        if (need_tomb) check_tombstone(&tombstone, &obs);
                    }
                    else {
                        /* Observance is on/after our window open */
                        if (r == 0) need_tomb = 0;

                        if (trunc_dtstart) {
                            /* Make this observance the new DTSTART */
                            icalproperty_set_dtstart(dtstart_prop, recur);
                            dtstart = obs.onset;
                            trunc_dtstart = 0;

                            if (last_dtstart &&
                                icaltime_compare(dtstart, *last_dtstart) > 0) {
                                *last_dtstart = dtstart;
                            }

                            /* Check if new DSTART is within 1yr of UNTIL */
                            ydiff = rrule.until.year - recur.year;
                            if (!trunc_until && ydiff <= 1) {
                                /* Remove RRULE */
                                icalcomponent_remove_property(comp, rrule_prop);
                                icalproperty_free(rrule_prop);

                                if (ydiff) {
                                    /* Add UNTIL as RDATE */
                                    struct icaldatetimeperiodtype rdate = {
                                        rrule.until,
                                        icalperiodtype_null_period()
                                    };
                                    prop = icalproperty_new_rdate(rdate);
                                    icalcomponent_add_property(comp, prop);
                                }
                            }
                        }

                        if (obsarray) {
                            /* Add the observance to our array */
                            icalarray_append(obsarray, &obs);
                        }
                        else if (!trunc_until) {
                            /* We're done */
                            break;
                        }
                    }
                    prev_onset = obs.onset;
                }
                icalrecur_iterator_free(ritr);
            }
        }

        /* Sort the RDATEs by onset */
        icalarray_sort(rdate_array, &rdate_compare);

        /* Check RDATEs */
        for (n = 0; n < rdate_array->num_elements; n++) {
            struct rdate *rdate = icalarray_element_at(rdate_array, n);

            if (n == 0 && icaltime_compare(rdate->date.time, dtstart) == 0) {
                /* RDATE is same as DTSTART - remove it */
                icalcomponent_remove_property(comp, rdate->prop);
                icalproperty_free(rdate->prop);
                continue;
            }

            obs.onset = rdate->date.time;
            icalproperty_get_isstd_isgmt(rdate->prop, &obs);

            /* Adjust observance to UTC */
            icaltime_adjust(&obs.onset, 0, 0, 0, -obs.offset_from);
            icaltime_set_utc(&obs.onset, 1);

            if (!icaltime_is_null_time(end) &&
                icaltime_compare(obs.onset, end) >= 0) {
                /* RDATE is after our window close - remove it */
                icalcomponent_remove_property(comp, rdate->prop);
                icalproperty_free(rdate->prop);

                /* Actual range end == request range end */
                adjust_end = 0;

                continue;
            }

            r = icaltime_compare(obs.onset, start);
            if (r < 0) {
                /* RDATE is prior to window open - check it vs tombstone */
                if (need_tomb) check_tombstone(&tombstone, &obs);

                /* Remove it */
                icalcomponent_remove_property(comp, rdate->prop);
                icalproperty_free(rdate->prop);

                /* Actual range start == request range start */
                adjust_start = 0;
            }
            else {
                /* RDATE is on/after our window open */
                if (r == 0) need_tomb = 0;

                if (trunc_dtstart) {
                    /* Make this RDATE the new DTSTART */
                    icalproperty_set_dtstart(dtstart_prop,
                                             rdate->date.time);
                    trunc_dtstart = 0;

                    icalcomponent_remove_property(comp, rdate->prop);
                    icalproperty_free(rdate->prop);
                }

                if (obsarray) {
                    /* Add the observance to our array */
                    icalarray_append(obsarray, &obs);
                }
            }
        }
        icalarray_free(rdate_array);

        /* Final check */
        if (trunc_dtstart) {
            /* All observances in comp occur prior to window open, remove it
               unless we haven't saved a tombstone comp of this type yet */
            if (icalcomponent_isa(comp) == ICAL_XDAYLIGHT_COMPONENT) {
                if (!tomb_day) {
                    tomb_day = comp;
                    comp = NULL;
                }
            }
            else if (!tomb_std) {
                tomb_std = comp;
                comp = NULL;
            }

            if (comp) {
                icalcomponent_remove_component(vtz, comp);
                icalcomponent_free(comp);
            }
        }
    }

    if (need_tomb && !icaltime_is_null_time(tombstone.onset)) {
        /* Need to add tombstone component/observance starting at window open
           as long as its not prior to start of TZ data */
        icalcomponent *tomb;
        icalproperty *prop, *nextp;

        if (obsarray) {
            /* Add the tombstone to our array */
            tombstone.onset = start;
            tombstone.is_gmt = tombstone.is_std = 1;
            icalarray_append(obsarray, &tombstone);
        }

        /* Determine which tombstone component we need */
        if (tombstone.is_daylight) {
            tomb = tomb_day;
            tomb_day = NULL;
        }
        else {
            tomb = tomb_std;
            tomb_std = NULL;
        }

        /* Set property values on our tombstone */
        for (prop = icalcomponent_get_first_property(tomb, ICAL_ANY_PROPERTY);
             prop; prop = nextp) {

            nextp = icalcomponent_get_next_property(tomb, ICAL_ANY_PROPERTY);

            switch (icalproperty_isa(prop)) {
            case ICAL_TZNAME_PROPERTY:
                icalproperty_set_tzname(prop, tombstone.name);
                break;
            case ICAL_TZOFFSETFROM_PROPERTY:
                icalproperty_set_tzoffsetfrom(prop, tombstone.offset_from);
                break;
            case ICAL_TZOFFSETTO_PROPERTY:
                icalproperty_set_tzoffsetto(prop, tombstone.offset_to);
                break;
            case ICAL_DTSTART_PROPERTY:
                /* Adjust window open to local time */
                icaltime_adjust(&start, 0, 0, 0, tombstone.offset_from);
                icaltime_set_utc(&start, 0);

                icalproperty_set_dtstart(prop, start);
                break;
            default:
                icalcomponent_remove_property(tomb, prop);
                icalproperty_free(prop);
                break;
            }
        }

        /* Remove X-PROLEPTIC-TZNAME as it no longer applies */
        if (proleptic_prop) {
            icalcomponent_remove_property(vtz, proleptic_prop);
            icalproperty_free(proleptic_prop);
        }
    }

    /* Remove any unused tombstone components */
    if (tomb_std) {
        icalcomponent_remove_component(vtz, tomb_std);
        icalcomponent_free(tomb_std);
    }
    if (tomb_day) {
        icalcomponent_remove_component(vtz, tomb_day);
        icalcomponent_free(tomb_day);
    }

    if (obsarray) {
        struct observance *obs;

        /* Sort the observances by onset */
        icalarray_sort(obsarray, &observance_compare);

        /* Set offset_to for tombstone, if necessary */
        obs = icalarray_element_at(obsarray, 0);
        if (!tombstone.offset_to) tombstone.offset_to = obs->offset_from;

        /* Adjust actual range if necessary */
        if (adjust_start) {
            *startp = obs->onset;
        }
        if (adjust_end) {
            obs = icalarray_element_at(obsarray, obsarray->num_elements-1);
            *endp = obs->onset;
            icaltime_adjust(endp, 0, 0, 0, 1);
        }
    }

    if (proleptic) {
        memcpy(proleptic, &tombstone, sizeof(struct observance));
    }
}

static icaltimezone *tz_from_tzid(const char *tzid)
{
    if (!tzid)
        return NULL;

    /* libical doesn't return the UTC singleton for Etc/UTC */
    if (!strcmp(tzid, "Etc/UTC") || !strcmp(tzid, "UTC"))
        return icaltimezone_get_utc_timezone();

    return icaltimezone_get_builtin_timezone(tzid);
}

static void collect_timezones_cb(icalparameter *param, void *data)
{
    ptrarray_t *tzs = (ptrarray_t*) data;
    int i;
    icaltimezone *tz;

    tz = tz_from_tzid(icalparameter_get_tzid(param));
    if (!tz) {
        return;
    }
    for (i = 0; i < tzs->count; i++) {
        if (ptrarray_nth(tzs, i) == tz) {
            return;
        }
    }
    ptrarray_push(tzs, tz);
}

EXPORTED void icalcomponent_add_required_timezones(icalcomponent *ical)
{
    icalcomponent *comp, *tzcomp, *next;
    icalproperty *prop;
    struct icalperiodtype span;
    ptrarray_t tzs = PTRARRAY_INITIALIZER;

    /* Determine recurrence span. */
    comp = icalcomponent_get_first_real_component(ical);
    span = icalrecurrenceset_get_utc_timespan(ical, icalcomponent_isa(comp),
                                              NULL, NULL, NULL, NULL);

    /* Remove all VTIMEZONE components for known TZIDs. This operation is
     * a bit hairy: we could expunge a timezone which is in use by an ical
     * property that is unknown to us. But since we don't know what to
     * look for, we can't make sure to preserve these timezones. */
    for (tzcomp = icalcomponent_get_first_component(ical,
                                                    ICAL_VTIMEZONE_COMPONENT);
         tzcomp;
         tzcomp = next) {

        next = icalcomponent_get_next_component(ical,
                ICAL_VTIMEZONE_COMPONENT);

        prop = icalcomponent_get_first_property(tzcomp, ICAL_TZID_PROPERTY);
        if (prop) {
            const char *tzid = icalproperty_get_tzid(prop);
            if (tzid && tz_from_tzid(tzid)) {
                icalcomponent_remove_component(ical, tzcomp);
                icalcomponent_free(tzcomp);
            }
        }
    }

    /* Collect timezones by TZID */
    icalcomponent_foreach_tzid(ical, collect_timezones_cb, &tzs);

    /* Now add each timezone, truncated by this events span. */
    int i;
    for (i = 0; i < tzs.count; i++) {
        icaltimezone *tz = ptrarray_nth(&tzs, i);

        /* Clone tz to overwrite its TZID property. */
        icalcomponent *tzcomp =
            icalcomponent_clone(icaltimezone_get_component(tz));
        icalproperty *tzprop =
            icalcomponent_get_first_property(tzcomp, ICAL_TZID_PROPERTY);
        icalproperty_set_tzid(tzprop, icaltimezone_get_location(tz));

        /* Truncate the timezone to the events timespan. */
        icaltimezone_truncate_vtimezone_advanced(tzcomp, &span.start, &span.end,
                NULL, NULL, NULL, NULL, NULL, 1 /* ms_compatible */);

        if (icaltime_as_timet_with_zone(span.end, NULL) < caldav_eternity) {
            /* Add TZUNTIL to timezone */
            icalproperty *tzuntil = icalproperty_new_tzuntil(span.end);
            icalcomponent_add_property(tzcomp, tzuntil);
        }

        /* Strip any COMMENT property */
        /* XXX  These were added by KSM in a previous version of vzic,
           but libical doesn't allow them in its restrictions checks */
        tzprop = icalcomponent_get_first_property(tzcomp, ICAL_COMMENT_PROPERTY);
        if (tzprop) {
            icalcomponent_remove_property(tzcomp, tzprop);
            icalproperty_free(tzprop);
        }

        /* Add the truncated timezone. */
        icalcomponent_add_component(ical, tzcomp);
    }

    ptrarray_fini(&tzs);
}

#endif /* HAVE_ICAL */
