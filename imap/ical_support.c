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
#include "ptrarray.h"
#include "xmalloc.h"

#ifdef HAVE_ICAL

struct recurrence_data {
    icalcomponent *comp;
    icaltimetype dtstart;
    icaltimetype dtend;
    icaltime_span span; /* for sorting, etc */
};

static struct icaltimetype _my_datetime(icalcomponent *comp,
                                        icalproperty_kind kind)
{
    icalproperty *prop = icalcomponent_get_first_property(comp, kind);
    if (!prop) return icaltime_null_time();

    struct icaltimetype ret =
        icalvalue_get_datetime(icalproperty_get_value(prop));

    /* skip timezones if it's UTC */
    if (icaltime_is_utc(ret))
        return ret;

    icalparameter *param =
        icalproperty_get_first_parameter(prop, ICAL_TZID_PARAMETER);

    if (param) {
        const char *tzid = icalparameter_get_tzid(param);
        icaltimezone *tz = NULL;

        icalcomponent *c;
        for (c = comp; c != NULL; c = icalcomponent_get_parent(c)) {
            tz = icalcomponent_get_timezone(c, tzid);
            if (tz != NULL)
                break;
        }

        if (tz == NULL)
            tz = icaltimezone_get_builtin_timezone_from_tzid(tzid);

        if (tz != NULL)
            ret = icaltime_set_timezone(&ret, tz);
    }

    return ret;
}


static int sort_overrides(const void **ap, const void **bp)
{
    struct recurrence_data *a = (struct recurrence_data *)*ap;
    struct recurrence_data *b = (struct recurrence_data *)*bp;

    return (a->span.start - b->span.start);
}

static struct recurrence_data *_add_override(ptrarray_t *array,
                                             icaltimetype dtstart,
                                             icaltimetype dtend,
                                             icalcomponent *comp,
                                             const icaltimezone *floatingtz)
{
    struct recurrence_data *data = NULL;
    int i;

    time_t start = icaltime_to_timet(dtstart, floatingtz);
    time_t end = icaltime_to_timet(dtend, floatingtz);

    for (i = 0; i < array->count; i++) {
        struct recurrence_data *item = ptrarray_nth(array, i);
        if (item->span.start != start) continue;
        data = item;
        break;
    }

    if (!data) {
        data = xzmalloc(sizeof(struct recurrence_data));
        ptrarray_append(array, data);
    }

    data->span.start = start;
    data->dtstart = dtstart;
    data->span.end = end;
    data->dtend = dtend;
    data->comp = comp;

    return data;
}

time_t icaltime_to_timet(icaltimetype t, const icaltimezone *floatingtz)
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

extern int icalcomponent_myforeach(icalcomponent *ical,
                                   const icaltimezone *floatingtz,
                                   int (*callback) (icalcomponent *comp,
                                                    icaltimetype start,
                                                    icaltimetype end,
                                                    void *data),
                                   void *callback_data)
{
    ptrarray_t overrides = PTRARRAY_INITIALIZER;
    struct icaldurationtype event_length = icaldurationtype_null_duration();
    struct icaltimetype dtstart = icaltime_null_time();
    int i;

    icalcomponent *mastercomp = NULL;

    icalcomponent *comp = icalcomponent_get_first_real_component(ical);
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
        struct icaltimetype dtend = icalcomponent_get_dtend(mastercomp);

        if (!icaltime_is_null_time(dtend)) {
            /* if there's an end, we calculate the duration */
            struct icaltimetype dtend = _my_datetime(comp, ICAL_DTEND_PROPERTY);
            icaltime_span basespan = icaltime_span_new(dtstart, dtend, 1);
            event_length =
                icaldurationtype_from_int(basespan.end - basespan.start);
        }

        /* add any RDATEs first, since EXDATE items can override them */
        icalproperty *prop;
        for (prop = icalcomponent_get_first_property(mastercomp,
                                                     ICAL_RDATE_PROPERTY);
             prop;
             prop = icalcomponent_get_next_property(mastercomp,
                                                    ICAL_RDATE_PROPERTY)) {
            struct icaldatetimeperiodtype rdate = icalproperty_get_rdate(prop);
            icaltimetype mystart = rdate.time;
            icaltimetype myend = rdate.time;
            if (icalperiodtype_is_null_period(rdate.period)) {
                myend = icaltime_add(mystart, event_length);
            }
            else {
                mystart = rdate.period.start;
                myend = rdate.period.end;
            }
            if (icaltime_is_null_time(mystart))
                continue;

            _add_override(&overrides, mystart, myend, mastercomp, floatingtz);
        }

        /* track any EXDATEs */
        for (prop = icalcomponent_get_first_property(mastercomp,
                                                     ICAL_EXDATE_PROPERTY);
             prop;
             prop = icalcomponent_get_next_property(mastercomp,
                                                    ICAL_EXDATE_PROPERTY)) {
            struct icaltimetype exdate = icalproperty_get_exdate(prop);
            _add_override(&overrides, exdate, exdate, NULL, floatingtz);
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
            _add_override(&overrides, recur, recur, NULL, floatingtz);
        }
        _add_override(&overrides, mystart, myend, comp, floatingtz);
    }

    /* sort all overrides in order */
    ptrarray_sort(&overrides, sort_overrides);

    /* now we can do the RRULE, because we have all overrides */
    icalrecur_iterator *rrule_itr = NULL;
    if (mastercomp) {
        icalproperty *rrule =
            icalcomponent_get_first_property(mastercomp, ICAL_RRULE_PROPERTY);
        if (rrule) {
            struct icalrecurrencetype recur = icalproperty_get_rrule(rrule);
            rrule_itr = icalrecur_iterator_new(recur, dtstart);
        }
    }

    int onum = 0;
    struct recurrence_data *data = overrides.count ?
        ptrarray_nth(&overrides, onum) : NULL;
    struct icaltimetype ritem = rrule_itr ?
        icalrecur_iterator_next(rrule_itr) : dtstart;

    do {
        time_t otime = data ? data->span.start : 0;
        time_t rtime = icaltime_to_timet(ritem, floatingtz);

        if (!rtime || otime <= rtime) {
            /* an overridden recurrence */
            if (data->comp &&
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
            data = (onum < overrides.count) ?
                ptrarray_nth(&overrides, onum) : NULL;
        }
        else {
            /* a non-overridden recurrence */
            struct icaltimetype thisend = icaltime_add(ritem, event_length);
            if (!callback(mastercomp, ritem, thisend, callback_data))
                goto done;

            /* incr recurrences */
            ritem = rrule_itr ?
                icalrecur_iterator_next(rrule_itr) : icaltime_null_time();
        }

    } while (data || !icaltime_is_null_time(ritem));

 done:
    if (rrule_itr) icalrecur_iterator_free(rrule_itr);

    for (i = 0; i < overrides.count; i++)
        free(overrides.data[i]);
    ptrarray_fini(&overrides);

    return 0;
}


icalcomponent *ical_string_as_icalcomponent(const struct buf *buf)
{
    return icalparser_parse_string(buf_cstring(buf));
}

struct buf *my_icalcomponent_as_ical_string(icalcomponent* comp)
{
    char *str = icalcomponent_as_ical_string_r(comp);
    struct buf *ret = buf_new();

    buf_initm(ret, str, strlen(str));

    return ret;
}

icalcomponent *record_to_ical(struct mailbox *mailbox,
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

const char *get_icalcomponent_errstr(icalcomponent *ical)
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


void icalcomponent_remove_invitee(icalcomponent *comp, icalproperty *prop)
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


icalproperty *icalcomponent_get_first_invitee(icalcomponent *comp)
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

icalproperty *icalcomponent_get_next_invitee(icalcomponent *comp)
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

const char *icalproperty_get_invitee(icalproperty *prop)
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


icaltimetype icalcomponent_get_recurrenceid_with_zone(icalcomponent *comp)
{
    return _my_datetime(comp, ICAL_RECURRENCEID_PROPERTY);
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
