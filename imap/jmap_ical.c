/* jmap_ical.c --Routines to convert calendar events between JMAP and iCalendar
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

#include <config.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <ctype.h>
#include <string.h>
#include <syslog.h>
#include <assert.h>

#include "acl.h"
#include "annotate.h"
#include "append.h"
#include "caldav_db.h"
#include "carddav_db.h"
#include "global.h"
#include "hash.h"
#include "httpd.h"
#include "http_caldav.h"
#include "http_carddav.h"
#include "http_caldav_sched.h"
#include "http_dav.h"
#include "http_jmap.h"
#include "http_proxy.h"
#include "ical_support.h"
#include "icu_wrap.h"
#include "json_support.h"
#include "mailbox.h"
#include "mboxlist.h"
#include "mboxname.h"
#include "parseaddr.h"
#include "seen.h"
#include "statuscache.h"
#include "stristr.h"
#include "times.h"
#include "util.h"
#include "vcard_support.h"
#include "version.h"
#include "xmalloc.h"
#include "xsha1.h"
#include "xstrlcat.h"
#include "xstrlcpy.h"
#include "zoneinfo_db.h"

/* for sasl_encode64 */
#include <sasl/sasl.h>
#include <sasl/saslutil.h>

/* generated headers are not necessarily in current directory */
#include "imap/http_err.h"
#include "imap/imap_err.h"

#include "jmap_ical.h"

static int is_valid_jmapid(const char *s)
{
    if (!s) return 0;
    size_t i;
    for (i = 0; s[i] && i < 256; i++) {
        char c = s[i];
        if (!((('0' <= c) && (c <= '9')) ||
              (('a' <= c) && (c <= 'z')) ||
              (('A' <= c) && (c <= 'Z')) ||
              ((c == '-' || c == '_')))) {
            return 0;
        }
    }
    return i > 0 && s[i] == '\0';
}

/* Forward declarations */
static json_t *calendarevent_from_ical(icalcomponent *comp, hash_table *props, icalcomponent *master);
static void calendarevent_to_ical(icalcomponent *comp, struct jmap_parser *parser, json_t *jsevent);

static char *sha1key(const char *val)
{
    unsigned char dest[SHA1_DIGEST_LENGTH];
    char idbuf[2*SHA1_DIGEST_LENGTH+1];
    int r;

    xsha1((const unsigned char *) val, strlen(val), dest);
    r = bin_to_hex(dest, SHA1_DIGEST_LENGTH, idbuf, BH_LOWER);
    assert(r == 2*SHA1_DIGEST_LENGTH);
    idbuf[2*SHA1_DIGEST_LENGTH] = '\0';
    return xstrdup(idbuf);
}

static char *mailaddr_from_uri(const char *uri)
{
    if (!uri || strncasecmp(uri, "mailto:", 7)) {
        return NULL;
    }
    uri += 7;
    const char *p = strchr(uri, '?');
    if (!p) return address_canonicalise(uri);

    char *tmp = xstrndup(uri, p - uri);
    char *ret = address_canonicalise(uri);
    free(tmp);
    return ret;
}

static char *normalized_uri(const char *uri)
{
    const char *col = strchr(uri, ':');
    if (!col) return xstrdupnull(uri);

    struct buf buf = BUF_INITIALIZER;
    buf_setmap(&buf, uri, col - uri);
    buf_lcase(&buf);
    buf_appendcstr(&buf, col);
    return buf_release(&buf);
}

static char *mailaddr_to_uri(const char *addr)
{
    struct buf buf = BUF_INITIALIZER;
    buf_setcstr(&buf, "mailto:");
    buf_appendcstr(&buf, addr);
    return buf_release(&buf);
}

static void remove_icalxparam(icalproperty *prop, const char *name)
{
    icalparameter *param, *next;

    for (param = icalproperty_get_first_parameter(prop, ICAL_X_PARAMETER);
         param;
         param = next) {

        next = icalproperty_get_next_parameter(prop, ICAL_X_PARAMETER);
        if (strcasecmp(icalparameter_get_xname(param), name)) {
            continue;
        }
        icalproperty_remove_parameter_by_ref(prop, param);
    }
}


static const char*
get_icalxparam_value(icalproperty *prop, const char *name)
{
    icalparameter *param;

    for (param = icalproperty_get_first_parameter(prop, ICAL_X_PARAMETER);
         param;
         param = icalproperty_get_next_parameter(prop, ICAL_X_PARAMETER)) {

        if (strcasecmp(icalparameter_get_xname(param), name)) {
            continue;
        }
        return icalparameter_get_xvalue(param);
    }

    return NULL;
}

static void
set_icalxparam(icalproperty *prop, const char *name, const char *val, int purge)
{
    icalparameter *param;

    if (purge) remove_icalxparam(prop, name);

    param = icalparameter_new(ICAL_X_PARAMETER);
    icalparameter_set_xname(param, name);
    icalparameter_set_xvalue(param, val);
    icalproperty_add_parameter(prop, param);
}

/* Compare the value of the first occurences of property kind in components
 * a and b. Return 0 if they match or if both do not contain kind. Note that
 * this function does not define an order on property values, so it can't be
 * used for sorting. */
int compare_icalprop(icalcomponent *a, icalcomponent *b,
                     icalproperty_kind kind) {
    icalproperty *pa, *pb;
    icalvalue *va, *vb;

    pa = icalcomponent_get_first_property(a, kind);
    pb = icalcomponent_get_first_property(b, kind);
    if (!pa && !pb) {
        return 0;
    }

    va = icalproperty_get_value(pa);
    vb = icalproperty_get_value(pb);
    enum icalparameter_xliccomparetype cmp = icalvalue_compare(va, vb);
    return cmp != ICAL_XLICCOMPARETYPE_EQUAL;
}

static const char*
get_icalxprop_value(icalcomponent *comp, const char *name)
{
    icalproperty *prop;

    for (prop = icalcomponent_get_first_property(comp, ICAL_X_PROPERTY);
         prop;
         prop = icalcomponent_get_next_property(comp, ICAL_X_PROPERTY)) {

        if (strcasecmp(icalproperty_get_x_name(prop), name)) {
            continue;
        }
        return icalproperty_get_value_as_string(prop);
    }

    return NULL;
}

/* Remove and deallocate any x-properties with name in comp. */
static void remove_icalxprop(icalcomponent *comp, const char *name)
{
    icalproperty *prop, *next;
    icalproperty_kind kind = ICAL_X_PROPERTY;

    for (prop = icalcomponent_get_first_property(comp, kind);
         prop;
         prop = next) {

        next = icalcomponent_get_next_property(comp, kind);

        if (strcasecmp(icalproperty_get_x_name(prop), name))
            continue;

        icalcomponent_remove_property(comp, prop);
        icalproperty_free(prop);
    }
}

static char *xjmapid_from_ical(icalproperty *prop)
{
    const char *id = (char *) get_icalxparam_value(prop, JMAPICAL_XPARAM_ID);
    if (id) return xstrdup(id);
    return sha1key(icalproperty_as_ical_string(prop));
}

static void xjmapid_to_ical(icalproperty *prop, const char *id)
{
    struct buf buf = BUF_INITIALIZER;
    icalparameter *param;

    buf_setcstr(&buf, JMAPICAL_XPARAM_ID);
    buf_appendcstr(&buf, "=");
    buf_appendcstr(&buf, id);
    param = icalparameter_new_from_string(buf_cstring(&buf));
    icalproperty_add_parameter(prop, param);

    buf_free(&buf);
}

static icaltimezone *tz_from_tzid(const char *tzid)
{
    icaltimezone *tz = NULL;

    if (!tzid)
        return NULL;

    /* libical doesn't return the UTC singleton for Etc/UTC */
    if (!strcmp(tzid, "Etc/UTC") || !strcmp(tzid, "UTC"))
        return icaltimezone_get_utc_timezone();

    tz = icaltimezone_get_builtin_timezone(tzid);

    if (!tz) {
        /* see if its a MS Windows TZID */
        char *my_tzid = icu_getIDForWindowsID(tzid);

        if (!my_tzid) return NULL;

        tz = icaltimezone_get_builtin_timezone(my_tzid);

        free(my_tzid);
    }

    return tz;
}

/* Determine the Olson TZID, if any, of the ical property prop. */
static const char *tzid_from_icalprop(icalproperty *prop, int guess) {
    const char *tzid = NULL;
    icalparameter *param = NULL;

    if (prop) param = icalproperty_get_first_parameter(prop, ICAL_TZID_PARAMETER);
    if (param) tzid = icalparameter_get_tzid(param);
    /* Check if the tzid already corresponds to an Olson name. */
    if (tzid) {
        icaltimezone *tz = tz_from_tzid(tzid);
        if (!tz && guess) {
            /* Try to guess the timezone. */
            icalvalue *val = icalproperty_get_value(prop);
            icaltimetype dt = icalvalue_get_datetime(val);
            tzid = dt.zone ? icaltimezone_get_location((icaltimezone*) dt.zone) : NULL;
            tzid = tzid && tz_from_tzid(tzid) ? tzid : NULL;
        } else if (tz) return icaltimezone_get_tzid(tz);
    } else {
        icalvalue *val = icalproperty_get_value(prop);
        icaltimetype dt = icalvalue_get_datetime(val);
        if (icaltime_is_valid_time(dt) && icaltime_is_utc(dt)) {
            tzid = "Etc/UTC";
        }
    }
    return tzid;
}

/* Determine the Olson TZID, if any, of the first ical property of
 * kind in component comp. */
static const char *tzid_from_ical(icalcomponent *comp,
                                  icalproperty_kind kind) {
    icalproperty *prop = icalcomponent_get_first_property(comp, kind);
    if (!prop) {
        return NULL;
    }
    return tzid_from_icalprop(prop, 1/*guess*/);
}

static struct icaltimetype dtstart_from_ical(icalcomponent *comp)
{
    struct icaltimetype dt;
    const char *tzid;

    dt = icalcomponent_get_dtstart(comp);
    if (dt.zone) return dt;

    if ((tzid = tzid_from_ical(comp, ICAL_DTSTART_PROPERTY))) {
        dt.zone = tz_from_tzid(tzid);
    }
    else if ((tzid = tzid_from_ical(comp, ICAL_DTEND_PROPERTY))) {
        /* Seen in the wild: a floating DTSTART and a DTEND with TZID */
        dt.zone = tz_from_tzid(tzid);
    }

    return dt;
}

static struct icaltimetype dtend_from_ical(icalcomponent *comp)
{
    struct icaltimetype dtend;
    icalproperty *prop;
    struct icaltimetype dtstart = dtstart_from_ical(comp);

    if ((prop = icalcomponent_get_first_property(comp, ICAL_DTEND_PROPERTY))) {
        dtend = icalproperty_get_dtend(prop);
        if (!dtend.zone) {
            const char *tzid = tzid_from_icalprop(prop, 1);
            dtend.zone = tz_from_tzid(tzid);
        }
    }
    else dtend = icalcomponent_get_dtend(comp);

    /* Normalize floating DTEND to DTSTART time zone, if any */
    if (!dtend.zone) dtend.zone = dtstart.zone;

    return dtend;
}


/* Convert time t to a RFC3339 formatted localdate string. Return the number
 * of bytes written to buf sized size, excluding the terminating null byte. */
static int timet_to_localdate(time_t t, char* buf, size_t size) {
    int n = time_to_rfc3339(t, buf, size);
    if (n && buf[n-1] == 'Z') {
        buf[n-1] = '\0';
        n--;
    }
    return n;
}

/* Convert icaltime to a RFC3339 formatted localdate string.
 * The returned string is owned by the caller or NULL on error.
 */
static char* localdate_from_icaltime_r(icaltimetype icaltime) {
    icaltimetype myicaltime = icaltime;
    if (myicaltime.is_date) {
        myicaltime.hour = 0;
        myicaltime.minute = 0;
        myicaltime.second = 0;
    }

    char *s = xzmalloc(RFC3339_DATETIME_MAX);
    time_t t = icaltime_as_timet(myicaltime);
    if (!timet_to_localdate(t, s, RFC3339_DATETIME_MAX)) {
        free(s);
        return NULL;
    }
    return s;
}

/* Convert icaltime to a RFC3339 formatted string.
 *
 * The returned string is owned by the caller or NULL on error.
 */
static char* utcdate_from_icaltime_r(icaltimetype icaltime) {
    char *s;
    time_t t;
    int n;

    s = xzmalloc(RFC3339_DATETIME_MAX);
    if (!s) {
        return NULL;
    }

    t = icaltime_as_timet(icaltime);

    n = time_to_rfc3339(t, s, RFC3339_DATETIME_MAX);
    if (!n) {
        free(s);
        return NULL;
    }
    return s;
}

/* Convert RFC3339 formatted utcdate to icaltime.
 * Return -1 on error.
 */
static int icaltime_from_utcdate(const char *utcdate, icaltimetype *icaltime) {
    if (strlen(utcdate) != 20 || utcdate[19] != 'Z') {
        return -1;
    }

    time_t tm;
    int n = time_from_iso8601(utcdate, &tm);
    if (n < 0) return -1;

    icaltimezone *utc = icaltimezone_get_utc_timezone();
    *icaltime = icaltime_from_timet_with_zone(tm, 0, utc);
    return n;
}

/* Compare int in ascending order. */
static int compare_int(const void *aa, const void *bb)
{
    const int *a = aa, *b = bb;
    return (*a < *b) ? -1 : (*a > *b);
}

/* Return the identity of i. This is a helper for recur_byX. */
static int identity_int(int i) {
    return i;
}

/*
 * Conversion from iCalendar to JMAP
 */

/* Convert at most nmemb entries in the ical recurrence byDay/Month/etc array
 * named byX using conv. Return a new JSON array, sorted in ascending order. */
static json_t* recurrence_byX_fromical(short byX[], size_t nmemb, int (*conv)(int)) {
    json_t *jbd = json_pack("[]");

    size_t i;
    int tmp[nmemb];
    for (i = 0; i < nmemb && byX[i] != ICAL_RECURRENCE_ARRAY_MAX; i++) {
        tmp[i] = conv(byX[i]);
    }

    size_t n = i;
    qsort(tmp, n, sizeof(int), compare_int);
    for (i = 0; i < n; i++) {
        json_array_append_new(jbd, json_pack("i", tmp[i]));
    }

    return jbd;
}

/* Convert the ical recurrence recur to a JMAP recurrenceRule */
static json_t*
recurrence_from_ical(icalcomponent *comp)
{
    char *s = NULL;
    size_t i;
    json_t *recur;
    struct buf buf = BUF_INITIALIZER;
    icalproperty *prop;
    struct icalrecurrencetype rrule;

    prop = icalcomponent_get_first_property(comp, ICAL_RRULE_PROPERTY);
    if (!prop) {
        return json_null();
    }
    rrule = icalproperty_get_rrule(prop);
    if (rrule.freq == ICAL_NO_RECURRENCE) {
        return json_null();
    }

    recur = json_pack("{}");

    /* frequency */
    s = lcase(xstrdup(icalrecur_freq_to_string(rrule.freq)));
    json_object_set_new(recur, "frequency", json_string(s));
    free(s);

    json_object_set_new(recur, "interval", json_pack("i", rrule.interval));

#ifdef HAVE_RSCALE
    /* rscale */
    if (rrule.rscale) {
        s = xstrdup(rrule.rscale);
        s = lcase(s);
        json_object_set_new(recur, "rscale", json_string(s));
        free(s);
    } else json_object_set_new(recur, "rscale", json_string("gregorian"));

    /* skip */
    const char *skip = NULL;
    switch (rrule.skip) {
        case ICAL_SKIP_BACKWARD:
            skip = "backward";
            break;
        case ICAL_SKIP_FORWARD:
            skip = "forward";
            break;
        case ICAL_SKIP_OMIT:
            /* fall through */
        default:
            skip = "omit";
    }
    json_object_set_new(recur, "skip", json_string(skip));
#endif

    /* firstDayOfWeek */
    s = xstrdup(icalrecur_weekday_to_string(rrule.week_start));
    s = lcase(s);
    json_object_set_new(recur, "firstDayOfWeek", json_string(s));
    free(s);

    /* byDay */
    json_t *jbd = json_pack("[]");
    for (i = 0; i < ICAL_BY_DAY_SIZE; i++) {
        json_t *jday;
        icalrecurrencetype_weekday weekday;
        int pos;

        if (rrule.by_day[i] == ICAL_RECURRENCE_ARRAY_MAX) {
            break;
        }

        jday = json_pack("{}");
        weekday = icalrecurrencetype_day_day_of_week(rrule.by_day[i]);

        s = xstrdup(icalrecur_weekday_to_string(weekday));
        s = lcase(s);
        json_object_set_new(jday, "day", json_string(s));
        free(s);

        pos = icalrecurrencetype_day_position(rrule.by_day[i]);
        if (pos) {
            json_object_set_new(jday, "nthOfPeriod", json_integer(pos));
        }

        if (json_object_size(jday)) {
            json_array_append_new(jbd, jday);
        } else {
            json_decref(jday);
        }
    }
    if (json_array_size(jbd)) {
        json_object_set_new(recur, "byDay", jbd);
    } else {
        json_decref(jbd);
    }

    /* byMonth */
    json_t *jbm = json_pack("[]");
    for (i = 0; i < ICAL_BY_MONTH_SIZE; i++) {
        short bymonth;

        if (rrule.by_month[i] == ICAL_RECURRENCE_ARRAY_MAX) {
            break;
        }

        bymonth = rrule.by_month[i];
        buf_printf(&buf, "%d", icalrecurrencetype_month_month(bymonth));
        if (icalrecurrencetype_month_is_leap(bymonth)) {
            buf_appendcstr(&buf, "L");
        }
        json_array_append_new(jbm, json_string(buf_cstring(&buf)));
        buf_reset(&buf);

    }
    if (json_array_size(jbm)) {
        json_object_set_new(recur, "byMonth", jbm);
    } else {
        json_decref(jbm);
    }

    if (rrule.by_month_day[0] != ICAL_RECURRENCE_ARRAY_MAX) {
        json_object_set_new(recur, "byMonthDay",
                recurrence_byX_fromical(rrule.by_month_day,
                    ICAL_BY_MONTHDAY_SIZE, &identity_int));
    }
    if (rrule.by_year_day[0] != ICAL_RECURRENCE_ARRAY_MAX) {
        json_object_set_new(recur, "byYearDay",
                recurrence_byX_fromical(rrule.by_year_day,
                    ICAL_BY_YEARDAY_SIZE, &identity_int));
    }
    if (rrule.by_week_no[0] != ICAL_RECURRENCE_ARRAY_MAX) {
        json_object_set_new(recur, "byWeekNo",
                recurrence_byX_fromical(rrule.by_week_no,
                    ICAL_BY_WEEKNO_SIZE, &identity_int));
    }
    if (rrule.by_hour[0] != ICAL_RECURRENCE_ARRAY_MAX) {
        json_object_set_new(recur, "byHour",
                recurrence_byX_fromical(rrule.by_hour,
                    ICAL_BY_HOUR_SIZE, &identity_int));
    }
    if (rrule.by_minute[0] != ICAL_RECURRENCE_ARRAY_MAX) {
        json_object_set_new(recur, "byMinute",
                recurrence_byX_fromical(rrule.by_minute,
                    ICAL_BY_MINUTE_SIZE, &identity_int));
    }
    if (rrule.by_second[0] != ICAL_RECURRENCE_ARRAY_MAX) {
        json_object_set_new(recur, "bySecond",
                recurrence_byX_fromical(rrule.by_second,
                    ICAL_BY_SECOND_SIZE, &identity_int));
    }
    if (rrule.by_set_pos[0] != ICAL_RECURRENCE_ARRAY_MAX) {
        json_object_set_new(recur, "bySetPosition",
                recurrence_byX_fromical(rrule.by_set_pos,
                    ICAL_BY_SETPOS_SIZE, &identity_int));
    }

    if (rrule.count != 0) {
        /* Recur count takes precedence over until. */
        json_object_set_new(recur, "count", json_integer(rrule.count));
    } else if (!icaltime_is_null_time(rrule.until)) {
        /* Convert iCalendar UNTIL to start timezone */
        const char *tzid = NULL;
        icalproperty *dtstart_prop =
            icalcomponent_get_first_property(comp, ICAL_DTSTART_PROPERTY);
        if (dtstart_prop) {
            icalparameter *tzid_param =
                icalproperty_get_first_parameter(dtstart_prop, ICAL_TZID_PARAMETER);
            if (tzid_param) tzid = icalparameter_get_tzid(tzid_param);
        }
        icaltimezone *tz = tz_from_tzid(tzid);
        icaltimetype dtuntil;
        if (rrule.until.is_date) {
            dtuntil = rrule.until;
            dtuntil.hour = 23;
            dtuntil.minute = 59;
            dtuntil.second = 59;
            dtuntil.is_date = 0;
        }
        else {
            dtuntil = icaltime_convert_to_zone(rrule.until, tz);
        }
        char *until = localdate_from_icaltime_r(dtuntil);
        if (until) json_object_set_new(recur, "until", json_string(until));
        free(until);
    }

    if (!json_object_size(recur)) {
        json_decref(recur);
        recur = json_null();
    }

    buf_free(&buf);
    return recur;
}

static json_t*
override_rdate_from_ical(icalproperty *prop)
{
    /* returns a JSON object with a single key value pair */
    json_t *override = json_pack("{}");
    json_t *o = json_pack("{}");
    struct icaldatetimeperiodtype rdate = icalproperty_get_rdate(prop);
    icaltimetype id;

    if (!icaltime_is_null_time(rdate.time)) {
        id = rdate.time;
    } else {
        /* PERIOD */
        struct icaldurationtype dur;
        id = rdate.period.start;

        /* Determine duration */
        if (!icaltime_is_null_time(rdate.period.end)) {
            dur = icaltime_subtract(rdate.period.end, id);
        } else {
            dur = rdate.period.duration;
        }

        json_object_set_new(o, "duration",
                json_string(icaldurationtype_as_ical_string(dur)));
    }

    if (!icaltime_is_null_time(id)) {
        char *t = localdate_from_icaltime_r(id);
        json_object_set_new(override, t, o);
        free(t);
    }

    if (!json_object_size(override)) {
        json_decref(override);
        json_decref(o);
        override = NULL;
    }
    return override;
}

static json_t*
override_exdate_from_ical(icalproperty *prop, const char *tzid_start)
{
    json_t *override = json_pack("{}");
    icaltimetype id = icalproperty_get_exdate(prop);
    const char *tzid_xdate;

    tzid_xdate = tzid_from_icalprop(prop, 1);
    if (tzid_start && tzid_xdate && strcmp(tzid_start, tzid_xdate)) {
        icaltimezone *tz_xdate = tz_from_tzid(tzid_xdate);
        icaltimezone *tz_start = tz_from_tzid(tzid_start);
        if (tz_xdate && tz_start) {
            if (id.zone) id.zone = tz_xdate;
            id = icaltime_convert_to_zone(id, tz_start);
        }
    }

    if (!icaltime_is_null_time(id)) {
        char *t = localdate_from_icaltime_r(id);
        json_object_set_new(override, t, json_pack("{s:b}", "excluded", 1));
        free(t);
    }

    if (!json_object_size(override)) {
        json_decref(override);
        override = NULL;
    }

    return override;
}

static json_t*
overrides_from_ical(icalcomponent *comp, json_t *event, const char *tzid_start)
{
    icalproperty *prop;
    json_t *overrides = json_pack("{}");
    const char *uid = icalcomponent_get_uid(comp);

    /* RDATE */
    for (prop = icalcomponent_get_first_property(comp, ICAL_RDATE_PROPERTY);
         prop;
         prop = icalcomponent_get_next_property(comp, ICAL_RDATE_PROPERTY)) {

        json_t *override = override_rdate_from_ical(prop);
        if (override) {
            json_object_update(overrides, override);
            json_decref(override);
        }
    }

    /* EXDATE */
    for (prop = icalcomponent_get_first_property(comp, ICAL_EXDATE_PROPERTY);
         prop;
         prop = icalcomponent_get_next_property(comp, ICAL_EXDATE_PROPERTY)) {

        json_t *override = override_exdate_from_ical(prop, tzid_start);
        if (override) {
            json_object_update(overrides, override);
            json_decref(override);
        }
    }

    /* VEVENT exceptions */
    json_t *exceptions = json_pack("{}");
    icalcomponent *excomp, *ical;

    ical = icalcomponent_get_parent(comp);
    for (excomp = icalcomponent_get_first_component(ical, ICAL_VEVENT_COMPONENT);
         excomp;
         excomp = icalcomponent_get_next_component(ical, ICAL_VEVENT_COMPONENT)) {

        if (excomp == comp) continue; /* skip toplevel promoted object */

        /* Skip unrelated VEVENTs */
        const char *exuid = icalcomponent_get_uid(excomp);
        if (strcmpsafe(exuid, uid)) continue;

        /* Convert VEVENT exception to JMAP */
        json_t *ex = calendarevent_from_ical(excomp, NULL, comp);
        if (!ex) continue;

        /* Recurrence-id */
        /* Convert the recurrence-id into the timezone of the main event.
         * Some clients generate the recurrence id as UTC date time,
         * even if the main VEVENT has a DTSTART with a TZID */
        icaltimetype icalrecurid = icalcomponent_get_recurrenceid(excomp);
        if ((prop = icalcomponent_get_first_property(comp, ICAL_DTSTART_PROPERTY))) {
            icalrecurid.is_date = icalproperty_get_dtstart(prop).is_date;
            if (!icalrecurid.is_date) {
                icalparameter *tzid_param =
                    icalproperty_get_first_parameter(prop, ICAL_TZID_PARAMETER);
                if (tzid_param) {
                    const char *start_tzid = icalparameter_get_tzid(tzid_param);
                    if (start_tzid) {
                        icaltimezone *start_tz = tz_from_tzid(start_tzid);
                        if (start_tz) {
                            icalrecurid = icaltime_convert_to_zone(icalrecurid, start_tz);
                        }
                    }
                }
            }
        }
        char *recurid = localdate_from_icaltime_r(icalrecurid);

        /* start */
        const char *exstart = json_string_value(json_object_get(ex, "start"));
        if (exstart && !strcmp(exstart, recurid)) {
            json_object_del(ex, "start");
        }

        /* Create override patch */
        json_t *diff = jmap_patchobject_create(event, ex);
        json_object_del(diff, "@type");
        json_object_del(diff, "uid");
        json_object_del(diff, "relatedTo");
        json_object_del(diff, "prodId");
        json_object_del(diff, "method");
        json_object_del(diff, "isAllDay");
        json_object_del(diff, "recurrenceRule");
        json_object_del(diff, "recurrenceOverrides");
        json_object_del(diff, "replyTo");
        if (json_is_null(json_object_get(diff, "start"))) {
            json_object_del(diff, "start");
        }

        /* Set override at recurrence id */
        json_object_set_new(exceptions, recurid, diff);
        json_decref(ex);
        free(recurid);
    }

    json_object_update(overrides, exceptions);
    json_decref(exceptions);

    if (!json_object_size(overrides)) {
        json_decref(overrides);
        overrides = json_null();
    }

    return overrides;
}

static int match_uri(const char *uri1, const char *uri2)
{
    const char *col1 = strchr(uri1, ':');
    const char *col2 = strchr(uri2, ':');

    if (col1 == NULL && col2 == NULL) {
        return !strcmp(uri1, uri2);
    }
    else if (col1 && col2 && (col1-uri1) == (col2-uri2)) {
        size_t schemelen = col1-uri1;
        return !strncasecmp(uri1, uri2, schemelen) &&
               !strcmp(uri1+schemelen, uri2+schemelen);
    }
    else return 0;
}

static json_t*
rsvpto_from_ical(icalproperty *prop)
{
    json_t *rsvpTo = json_object();
    struct buf buf = BUF_INITIALIZER;

    /* Read RVSP methods defined in RSVP-URI x-parameters. A RSVP-URI
     * x-parameter value is of the form method:uri. If no method is defined,
     * it's interpreted as the "web" method for legacy reasons. */
    icalparameter *param, *next;
    for (param = icalproperty_get_first_parameter(prop, ICAL_X_PARAMETER);
            param;
            param = next) {

        next = icalproperty_get_next_parameter(prop, ICAL_X_PARAMETER);
        if (strcasecmp(icalparameter_get_xname(param), JMAPICAL_XPARAM_RSVP_URI)) {
            continue;
        }

        const char *val = icalparameter_get_xvalue(param);
        const char *col1 = strchr(val, ':');
        const char *col2 = col1 ? strchr(col1 + 1, ':') : NULL;
        if (!col2) {
            json_object_set_new(rsvpTo, "web", json_string(val));
        } else {
            buf_setmap(&buf, val, col1 - val);
            json_object_set_new(rsvpTo, buf_cstring(&buf), json_string(col1 + 1));
        }
    }

    /* Read URI from property value and check if this URI already is defined.
     * If it isn't, this could be because an iCalendar client updated the
     * property value, but kept the RSVP x-params. */
    const char *caladdress = icalproperty_get_value_as_string(prop);
    int caladdress_is_defined = 0;
    json_t *jval;
    const char *key;
    json_object_foreach(rsvpTo, key, jval) {
        if (match_uri(caladdress, json_string_value(jval))) {
            caladdress_is_defined = 1;
            break;
        }
    }
    if (!caladdress_is_defined) {
        if (!strncasecmp(caladdress, "mailto:", 7))
            json_object_set_new(rsvpTo, "imip", json_string(caladdress));
        else
            json_object_set_new(rsvpTo, "other", json_string(caladdress));
    }

    if (!json_object_size(rsvpTo)) {
        json_decref(rsvpTo);
        rsvpTo = json_null();
    }

    buf_free(&buf);
    return rsvpTo;
}

static json_t *participant_from_ical(icalproperty *prop,
                                     hash_table *attendee_by_uri,
                                     hash_table *id_by_uri,
                                     icalproperty *orga)
{
    json_t *p = json_object();
    icalparameter *param;
    struct buf buf = BUF_INITIALIZER;

    /* FIXME invitedBy */

    /* sendTo */
    json_t *sendTo = rsvpto_from_ical(prop);
    json_object_set_new(p, "sendTo", sendTo ? sendTo : json_null());

    /* email */
    char *email = NULL;
    param = icalproperty_get_first_parameter(prop, ICAL_EMAIL_PARAMETER);
    if (param) {
        email = xstrdupnull(icalparameter_get_value_as_string(param));
    }
    else if (json_object_get(sendTo, "imip")) {
        const char *uri = json_string_value(json_object_get(sendTo, "imip"));
        email = mailaddr_from_uri(uri);
    }
    json_object_set_new(p, "email", email ? json_string(email) : json_null());
    free(email);

    /* name */
    const char *name = NULL;
    param = icalproperty_get_first_parameter(prop, ICAL_CN_PARAMETER);
    if (param) {
        name = icalparameter_get_cn(param);
    }
    json_object_set_new(p, "name", json_string(name ? name : ""));

    /* kind */
    const char *kind = NULL;
    param = icalproperty_get_first_parameter(prop, ICAL_CUTYPE_PARAMETER);
    if (param) {
        icalparameter_cutype cutype = icalparameter_get_cutype(param);
        switch (cutype) {
            case ICAL_CUTYPE_INDIVIDUAL:
                kind = "individual";
                break;
            case ICAL_CUTYPE_GROUP:
                kind = "group";
                break;
            case ICAL_CUTYPE_RESOURCE:
                kind = "resource";
                break;
            case ICAL_CUTYPE_ROOM:
                kind = "location";
                break;
            default:
                kind = "unknown";
        }
    }
    if (kind) {
        json_object_set_new(p, "kind", json_string(kind));
    }

    /* attendance */
    const char *attendance = NULL;
    icalparameter_role ical_role = ICAL_ROLE_REQPARTICIPANT;
    param = icalproperty_get_first_parameter(prop, ICAL_ROLE_PARAMETER);
    if (param) {
        ical_role = icalparameter_get_role(param);
        switch (ical_role) {
            case ICAL_ROLE_REQPARTICIPANT:
                attendance = "required";
                break;
            case ICAL_ROLE_OPTPARTICIPANT:
                attendance = "optional";
                break;
            case ICAL_ROLE_NONPARTICIPANT:
                attendance = "none";
                break;
            case ICAL_ROLE_CHAIR:
                /* fall through */
            default:
                attendance = "required";
        }
    }
    if (!attendance) attendance = "required";
    json_object_set_new(p, "attendance", json_string(attendance));

    /* roles */
    json_t *roles = json_object();
    for (param = icalproperty_get_first_parameter(prop, ICAL_X_PARAMETER);
         param;
         param = icalproperty_get_next_parameter(prop, ICAL_X_PARAMETER)) {

        if (strcmp(icalparameter_get_xname(param), JMAPICAL_XPARAM_ROLE))
            continue;

        buf_setcstr(&buf, icalparameter_get_xvalue(param));
        json_object_set_new(roles, buf_lcase(&buf), json_true());
    }
    if (!json_object_get(roles, "owner")) {
        const char *o = icalproperty_get_organizer(orga);
        const char *a = icalproperty_get_attendee(prop);
        if (!strcasecmpsafe(o, a)) {
            json_object_set_new(roles, "owner", json_true());
            json_object_set_new(roles, "attendee", json_true());
        }
    }
    if (ical_role == ICAL_ROLE_CHAIR) {
        json_object_set_new(roles, "chair", json_true());
    }
    if (!json_object_size(roles)) {
        json_object_set_new(roles, "attendee", json_true());
    }
    json_object_set_new(p, "roles", roles);

    /* locationId */
    const char *locid;
    if ((locid = get_icalxparam_value(prop, JMAPICAL_XPARAM_LOCATIONID))) {
        json_object_set_new(p, "locationId", json_string(locid));
    }

    /* participationStatus */
    const char *partstat = NULL;
    short depth = 0;
    icalproperty *partstat_prop = prop;
    while (!partstat) {
        param = icalproperty_get_first_parameter(partstat_prop, ICAL_PARTSTAT_PARAMETER);
        if (!param) break;
        icalparameter_partstat pst = icalparameter_get_partstat(param);
        switch (pst) {
            case ICAL_PARTSTAT_ACCEPTED:
                partstat = "accepted";
                break;
            case ICAL_PARTSTAT_DECLINED:
                partstat = "declined";
                break;
            case ICAL_PARTSTAT_TENTATIVE:
                partstat = "tentative";
                break;
            case ICAL_PARTSTAT_NEEDSACTION:
                partstat = "needs-action";
                break;
            case ICAL_PARTSTAT_DELEGATED:
                /* Follow the delegate chain */
                param = icalproperty_get_first_parameter(prop, ICAL_DELEGATEDTO_PARAMETER);
                if (param) {
                    const char *to = icalparameter_get_delegatedto(param);
                    if (!to) continue;
                    char *uri = normalized_uri(to);
                    partstat_prop = hash_lookup(uri, attendee_by_uri);
                    free(uri);
                    if (partstat_prop) {
                        /* Determine PARTSTAT from delegate. */
                        if (++depth > 64) {
                            /* This is a pathological case: libical does
                             * not check for infinite DELEGATE chains, so we
                             * make sure not to fall in an endless loop. */
                            partstat = "none";
                        }
                        continue;
                    }
                }
                /* fallthrough */
            default:
                partstat = "none";
        }
    }
    if (!partstat || !strcmp(partstat,  "none"))
        partstat = "needs-action";
    json_object_set_new(p, "participationStatus", json_string(partstat));

    /* expectReply */
    int expect_reply = 0;
    param = icalproperty_get_first_parameter(prop, ICAL_RSVP_PARAMETER);
    if (param) {
        icalparameter_rsvp val = icalparameter_get_rsvp(param);
        expect_reply = val == ICAL_RSVP_TRUE;
    }
    json_object_set_new(p, "expectReply", json_boolean(expect_reply));

    /* delegatedTo */
    json_t *delegatedTo = json_object();
    for (param = icalproperty_get_first_parameter(prop, ICAL_DELEGATEDTO_PARAMETER);
         param;
         param = icalproperty_get_next_parameter(prop, ICAL_DELEGATEDTO_PARAMETER)) {

        char *uri = normalized_uri(icalparameter_get_delegatedto(param));
        const char *to_id = hash_lookup(uri, id_by_uri);
        free(uri);
        if (to_id) json_object_set_new(delegatedTo, to_id, json_true());
    }
    if (json_object_size(delegatedTo)) {
        json_object_set_new(p, "delegatedTo", delegatedTo);
    }
    else {
        json_decref(delegatedTo);
    }

    /* delegatedFrom */
    json_t *delegatedFrom = json_object();
    for (param = icalproperty_get_first_parameter(prop, ICAL_DELEGATEDFROM_PARAMETER);
         param;
         param = icalproperty_get_next_parameter(prop, ICAL_DELEGATEDFROM_PARAMETER)) {

        char *uri = normalized_uri(icalparameter_get_delegatedfrom(param));
        const char *from_id = hash_lookup(uri, id_by_uri);
        free(uri);
        if (from_id) json_object_set_new(delegatedFrom, from_id, json_true());
    }
    if (json_object_size(delegatedFrom)) {
        json_object_set_new(p, "delegatedFrom", delegatedFrom);
    }
    else {
        json_decref(delegatedFrom);
    }

    /* memberof */
    json_t *memberOf = json_object();
    for (param = icalproperty_get_first_parameter(prop, ICAL_MEMBER_PARAMETER);
         param;
         param = icalproperty_get_next_parameter(prop, ICAL_MEMBER_PARAMETER)) {

        char *uri = normalized_uri(icalparameter_get_member(param));
        char *id = xstrdupnull(hash_lookup(uri, id_by_uri));
        if (!id) id = sha1key(uri);
        json_object_set_new(memberOf, id, json_true());
        free(id);
        free(uri);
    }
    if (json_object_size(memberOf)) {
        json_object_set_new(p, "memberOf", memberOf);
    } else {
        json_decref(memberOf);
    }

    /* linkIds */
    json_t *linkIds = json_object();
    for (param = icalproperty_get_first_parameter(prop, ICAL_X_PARAMETER);
         param;
         param = icalproperty_get_next_parameter(prop, ICAL_X_PARAMETER)) {

        if (strcmp(icalparameter_get_xname(param), JMAPICAL_XPARAM_LINKID))
            continue;

        buf_setcstr(&buf, icalparameter_get_xvalue(param));
        json_object_set_new(linkIds, buf_lcase(&buf), json_true());
    }
    if (json_object_size(linkIds)) {
        json_object_set_new(p, "linkIds", linkIds);
    }
    else {
        json_decref(linkIds);
    } 

    /* scheduleSequence */
    long schedule_sequence = 0;
    const char *xval = get_icalxparam_value(prop, JMAPICAL_XPARAM_SEQUENCE);
    if (xval) {
        bit64 res;
        if (parsenum(xval, &xval, strlen(xval), &res) == 0) {
            schedule_sequence = res;
        }
    }
    json_object_set_new(p, "scheduleSequence", json_integer(schedule_sequence));

    /* scheduleUpdated */
    if ((xval = get_icalxparam_value(prop, JMAPICAL_XPARAM_DTSTAMP))) {
        icaltimetype dtstamp = icaltime_from_string(xval);
        if (!icaltime_is_null_time(dtstamp) && !dtstamp.is_date &&
                dtstamp.zone == icaltimezone_get_utc_timezone()) {
            char *tmp = utcdate_from_icaltime_r(dtstamp);
            json_object_set_new(p, "scheduleUpdated", json_string(tmp));
            free(tmp);
        }
    }

    buf_free(&buf);
    return p;
}

static json_t*
participant_from_icalorganizer(icalproperty *orga)
{
    json_t *jorga = json_object();

    /* name */
    icalparameter *param;
    const char *name = NULL;
    if ((param = icalproperty_get_first_parameter(orga, ICAL_CN_PARAMETER))) {
        name = icalparameter_get_cn(param);
    }
    json_object_set_new(jorga, "name", json_string(name ? name : ""));

    /* roles */
    json_object_set_new(jorga, "roles", json_pack("{s:b}", "owner", 1));

    /* sendTo */
    /* email */
    const char *caladdress = icalproperty_get_value_as_string(orga);
    if (!strncasecmp(caladdress, "mailto:", 7)) {
        json_object_set_new(jorga, "sendTo", json_pack("{s:s}", "imip", caladdress));
        char *email = mailaddr_from_uri(caladdress);
        json_object_set_new(jorga, "email", json_string(email));
        free(email);
    }
    else {
        json_object_set_new(jorga, "sendTo", json_pack("{s:s}", "other", caladdress));
        json_object_set_new(jorga, "email", json_null());
    }

    /* Set default values */
    json_object_set_new(jorga, "attendance", json_string("required"));
    json_object_set_new(jorga, "participationStatus", json_string("needs-action"));
    json_object_set_new(jorga, "scheduleSequence", json_integer(0));
    json_object_set_new(jorga, "expectReply", json_false());

    return jorga;
}

/* Convert the ical ORGANIZER/ATTENDEEs in comp to CalendarEvent participants */
static json_t*
participants_from_ical(icalcomponent *comp)
{
    struct hash_table attendee_by_uri = HASH_TABLE_INITIALIZER;
    struct hash_table id_by_uri = HASH_TABLE_INITIALIZER;
    icalproperty *prop;
    json_t *participants = json_object();

    /* Collect all attendees in a map to lookup delegates and their ids. */
    construct_hash_table(&attendee_by_uri, 32, 0);
    construct_hash_table(&id_by_uri, 32, 0);
    for (prop = icalcomponent_get_first_property(comp, ICAL_ATTENDEE_PROPERTY);
         prop;
         prop = icalcomponent_get_next_property(comp, ICAL_ATTENDEE_PROPERTY)) {

        /* Map normalized URI to ATTENDEE */
        char *uri = normalized_uri(icalproperty_get_value_as_string(prop));
        hash_insert(uri, prop, &attendee_by_uri);

        /* Map mailto:URI to ID */
        char *id = xstrdupnull(get_icalxparam_value(prop, JMAPICAL_XPARAM_ID));
        if (!id) id = sha1key(uri);
        hash_insert(uri, id, &id_by_uri);
        free(uri);
    }


    /* Map ATTENDEE to JSCalendar */
    icalproperty *orga = icalcomponent_get_first_property(comp, ICAL_ORGANIZER_PROPERTY);
    for (prop = icalcomponent_get_first_property(comp, ICAL_ATTENDEE_PROPERTY);
         prop;
         prop = icalcomponent_get_next_property(comp, ICAL_ATTENDEE_PROPERTY)) {

        char *uri = normalized_uri(icalproperty_get_value_as_string(prop));
        const char *id = hash_lookup(uri, &id_by_uri);
        json_t *p = participant_from_ical(prop, &attendee_by_uri, &id_by_uri, orga);
        json_object_set_new(participants, id, p);
        free(uri);
    }

    if (orga) {
        const char *caladdress = icalproperty_get_value_as_string(orga);
        char *uri = normalized_uri(caladdress);
        if (!hash_lookup(uri, &attendee_by_uri)) {
            /* Add a default participant for the organizer. */
            char *id = xstrdupnull(get_icalxparam_value(orga, JMAPICAL_XPARAM_ID));
            if (!id) id = sha1key(uri);
            json_t *jorga = participant_from_icalorganizer(orga);
            json_object_set_new(participants, id, jorga);
            free(id);
        }
        free(uri);
    }

    if (!json_object_size(participants)) {
        json_decref(participants);
        participants = json_null();
    }
    free_hash_table(&attendee_by_uri, NULL);
    free_hash_table(&id_by_uri, free);
    return participants;
}

static json_t*
link_from_ical(icalproperty *prop)
{
    /* href */
    const char *href = NULL;
    if (icalproperty_isa(prop) == ICAL_ATTACH_PROPERTY) {
        icalattach *attach = icalproperty_get_attach(prop);
        /* Ignore ATTACH properties with value BINARY. */
        if (!attach || !icalattach_get_is_url(attach)) {
            return NULL;
        }
        href = icalattach_get_url(attach);
    }
    else if (icalproperty_isa(prop) == ICAL_URL_PROPERTY) {
        href = icalproperty_get_value_as_string(prop);
    }
    if (!href || *href == '\0') return NULL;

    json_t *link = json_pack("{s:s}", "href", href);
    icalparameter *param = NULL;
    const char *s;

    /* cid */
    if ((s = get_icalxparam_value(prop, JMAPICAL_XPARAM_CID))) {
        json_object_set_new(link, "cid", json_string(s));
    }

    /* type */
    param = icalproperty_get_first_parameter(prop, ICAL_FMTTYPE_PARAMETER);
    if (param && ((s = icalparameter_get_fmttype(param)))) {
        json_object_set_new(link, "type", json_string(s));
    }

    /* title - reuse the same x-param as Apple does for their locations  */
    if ((s = get_icalxparam_value(prop, JMAPICAL_XPARAM_TITLE))) {
        json_object_set_new(link, "title", json_string(s));
    }

    /* size */
    json_int_t size = -1;
    param = icalproperty_get_size_parameter(prop);
    if (param) {
        if ((s = icalparameter_get_size(param))) {
            char *ptr;
            size = strtol(s, &ptr, 10);
            json_object_set_new(link, "size",
                    ptr && *ptr == '\0' ? json_integer(size) : json_null());
        }
    }

    /* rel */
    const char *rel = get_icalxparam_value(prop, JMAPICAL_XPARAM_REL);
    if (!rel)
        rel = icalproperty_isa(prop) == ICAL_URL_PROPERTY ? "describedby" :
                                                            "enclosure";
    json_object_set_new(link, "rel", json_string(rel));

    /* display */
    if ((s = get_icalxparam_value(prop, JMAPICAL_XPARAM_DISPLAY))) {
        json_object_set_new(link, "display", json_string(s));
    }


    return link;
}

static json_t*
links_from_ical(icalcomponent *comp)
{
    icalproperty* prop;
    json_t *ret = json_pack("{}");

    /* Read iCalendar ATTACH properties */
    for (prop = icalcomponent_get_first_property(comp, ICAL_ATTACH_PROPERTY);
         prop;
         prop = icalcomponent_get_next_property(comp, ICAL_ATTACH_PROPERTY)) {

        char *id = xstrdupnull(get_icalxparam_value(prop, JMAPICAL_XPARAM_ID));
        if (!id) id = sha1key(icalproperty_get_value_as_string(prop));
        json_t *link = link_from_ical(prop);
        if (link) json_object_set_new(ret, id, link);
        free(id);
    }

    /* Read iCalendar URL property. Should only be one. */
    for (prop = icalcomponent_get_first_property(comp, ICAL_URL_PROPERTY);
         prop;
         prop = icalcomponent_get_next_property(comp, ICAL_URL_PROPERTY)) {

        char *id = xstrdupnull(get_icalxparam_value(prop, JMAPICAL_XPARAM_ID));
        if (!id) id = sha1key(icalproperty_get_value_as_string(prop));
        json_t *link = link_from_ical(prop);
        if (link) json_object_set_new(ret, id, link);
        free(id);
    }

    if (!json_object_size(ret)) {
        json_decref(ret);
        ret = json_null();
    }

    return ret;
}

/* Convert the VALARMS in the VEVENT comp to CalendarEvent alerts.
 * Adds any ATTACH properties found in VALARM components to the
 * event 'links' property. */
static json_t*
alerts_from_ical(icalcomponent *comp)
{
    json_t* alerts = json_pack("{}");
    icalcomponent* alarm;
    hash_table snoozes;
    ptrarray_t alarms = PTRARRAY_INITIALIZER;

    construct_hash_table(&snoozes, 32, 0);

    /* Split VALARMS into regular alerst and their snoozing VALARMS */
    for (alarm = icalcomponent_get_first_component(comp, ICAL_VALARM_COMPONENT);
         alarm;
         alarm = icalcomponent_get_next_component(comp, ICAL_VALARM_COMPONENT)) {

        icalparameter *param = NULL;
        const char *uid = NULL;

        /* Ignore alarms with NONE action. */
        icalproperty *prop = icalcomponent_get_first_property(alarm, ICAL_ACTION_PROPERTY);
        if (prop) {
            icalvalue *val = icalproperty_get_value(prop);
            if (val && !strcasecmp(icalvalue_as_ical_string(val), "NONE")) {
                continue;
            }
        }

        /* Check for RELATED-TO property... */
        prop = icalcomponent_get_first_property(alarm, ICAL_RELATEDTO_PROPERTY);
        if (!prop) {
            ptrarray_push(&alarms, alarm);
            continue;
        }
        /* .. that has a UID value... */
        uid = icalproperty_get_value_as_string(prop);
        if (!uid || !strlen(uid)) {
            ptrarray_push(&alarms, alarm);
            continue;
        }
        /* ... and it's RELTYPE is set to SNOOZE */
        param = icalproperty_get_first_parameter(prop, ICAL_RELTYPE_PARAMETER);
        if (!param || strcasecmp(icalparameter_get_xvalue(param), "SNOOZE")) {
            ptrarray_push(&alarms, alarm);
            continue;
        }

        /* Must be a SNOOZE alarm */
        hash_insert(uid, alarm, &snoozes);
    }

    while ((alarm = (icalcomponent*) ptrarray_pop(&alarms))) {
        icalproperty* prop;
        icalparameter *param;

        json_t *alert = json_object();

        /* alert id */
        char *id = (char *) icalcomponent_get_uid(alarm);
        if (!id) {
            id = sha1key(icalcomponent_as_ical_string(alarm));
        } else {
            id = xstrdup(id);
        }

        /* Determine TRIGGER and RELATED parameter */
        struct icaltriggertype trigger = {
            icaltime_null_time(), icaldurationtype_null_duration()
        };
        icalparameter_related related = ICAL_RELATED_START;
        prop = icalcomponent_get_first_property(alarm, ICAL_TRIGGER_PROPERTY);
        if (prop) {
            trigger = icalproperty_get_trigger(prop);
            param = icalproperty_get_first_parameter(prop, ICAL_RELATED_PARAMETER);
            if (param) {
                related = icalparameter_get_related(param);
                if (related != ICAL_RELATED_START && related != ICAL_RELATED_END) {
                    free(id);
                    continue;
                }
            }
        }

        /* Determine duration between alarm and start/end */
        struct icaldurationtype duration;
        if (!icaldurationtype_is_null_duration(trigger.duration) ||
             icaltime_is_null_time(trigger.time)) {
            duration = trigger.duration;
        } else {
            icaltimetype ttrg, tref;
            icaltimezone *utc = icaltimezone_get_utc_timezone();

            ttrg = icaltime_convert_to_zone(trigger.time, utc);
            if (related == ICAL_RELATED_START) {
                tref = icaltime_convert_to_zone(dtstart_from_ical(comp), utc);
            } else {
                tref = icaltime_convert_to_zone(dtend_from_ical(comp), utc);
            }
            duration = icaltime_subtract(ttrg, tref);
        }

        /*  action */
        const char *action = "display";
        prop = icalcomponent_get_first_property(alarm, ICAL_ACTION_PROPERTY);
        if (prop && icalproperty_get_action(prop) == ICAL_ACTION_EMAIL) {
            action = "email";
        }
        json_object_set_new(alert, "action", json_string(action));

        /* relativeTo */
        const char *relative_to = "before-start";
        if (duration.is_neg) {
            relative_to = related == ICAL_RELATED_START ?
                "before-start" : "before-end";
        } else {
            relative_to = related == ICAL_RELATED_START ?
                "after-start" : "after-end";
        }
        json_object_set_new(alert, "relativeTo", json_string(relative_to));

        /* offset*/
        duration.is_neg = 0;
        char *offset = icaldurationtype_as_ical_string_r(duration);
        json_object_set_new(alert, "offset", json_string(offset));
        json_object_set_new(alerts, id, alert);
        free(offset);

        /* acknowledged */
        if ((prop = icalcomponent_get_acknowledged_property(alarm))) {
            icaltimetype t = icalproperty_get_acknowledged(prop);
            if (icaltime_is_valid_time(t)) {
                char *val = utcdate_from_icaltime_r(t);
                json_object_set_new(alert, "acknowledged", json_string(val));
                free(val);
            }
        }

        /* snoozed */
        icalcomponent *snooze;
        const char *uid;
        if ((uid = icalcomponent_get_uid(alarm)) &&
            (snooze = hash_lookup(uid, &snoozes)) &&
            (prop = icalcomponent_get_first_property(snooze,
                                        ICAL_TRIGGER_PROPERTY))) {
            icaltimetype t = icalproperty_get_trigger(prop).time;
            if (!icaltime_is_null_time(t) && icaltime_is_valid_time(t)) {
                char *val = utcdate_from_icaltime_r(t);
                json_object_set_new(alert, "snoozed", json_string(val));
                free(val);
            }
        }

        free(id);
    }

    if (!json_object_size(alerts)) {
        json_decref(alerts);
        alerts = json_null();
    }

    ptrarray_fini(&alarms);
    free_hash_table(&snoozes, NULL);
    return alerts;
}



/* Convert a VEVENT ical component to CalendarEvent keywords */
static json_t*
keywords_from_ical(icalcomponent *comp)
{
    icalproperty* prop;
    json_t *ret = json_object();

    for (prop = icalcomponent_get_first_property(comp, ICAL_CATEGORIES_PROPERTY);
         prop;
         prop = icalcomponent_get_next_property(comp, ICAL_CATEGORIES_PROPERTY)) {
        json_object_set_new(ret, icalproperty_get_categories(prop), json_true());
    }
    if (!json_object_size(ret)) {
        json_decref(ret);
        ret = json_null();
    }

    return ret;
}

/* Convert a VEVENT ical component to CalendarEvent relatedTo */
static json_t*
relatedto_from_ical(icalcomponent *comp)
{
    icalproperty* prop;
    json_t *ret = json_pack("{}");

    for (prop = icalcomponent_get_first_property(comp, ICAL_RELATEDTO_PROPERTY);
         prop;
         prop = icalcomponent_get_next_property(comp, ICAL_RELATEDTO_PROPERTY)) {

        const char *uid = icalproperty_get_value_as_string(prop);
        if (!uid || !strlen(uid)) continue;

        icalparameter *param = NULL;
        json_t *relation = json_object();
        for (param = icalproperty_get_first_parameter(prop, ICAL_RELTYPE_PARAMETER);
             param;
             param = icalproperty_get_next_parameter(prop, ICAL_RELTYPE_PARAMETER)) {

            const char *reltype = icalparameter_get_xvalue(param);
            if (reltype && *reltype) {
                char *s = lcase(xstrdup(reltype));
                json_object_set_new(relation, s, json_true());
                free(s);
            }
            else json_object_set_new(relation, "parent", json_true());
        }

        if (!json_object_size(relation)) {
            json_decref(relation);
            relation = json_null();
        }

        json_object_set_new(ret, uid, json_pack("{s:o}", "relation", relation));
    }

    if (!json_object_size(ret)) {
        json_decref(ret);
        ret = json_null();
    }

    return ret;
}

static json_t* location_from_ical(icalproperty *prop, json_t *links)
{
    icalparameter *param;
    json_t *loc = json_object();

    /* name */
    const char *name = icalvalue_get_text(icalproperty_get_value(prop));
    json_object_set_new(loc, "name", json_string(name ? name : ""));

    /* rel */
    const char *rel = get_icalxparam_value(prop, JMAPICAL_XPARAM_REL);
    if (!rel) rel = "unknown";
    json_object_set_new(loc, "rel", json_string(rel));

    /* description */
    const char *desc = get_icalxparam_value(prop, JMAPICAL_XPARAM_DESCRIPTION);
    json_object_set_new(loc, "description", desc ? json_string(desc) : json_null());

    /* timeZone */
    const char *tzid = get_icalxparam_value(prop, JMAPICAL_XPARAM_TZID);
    json_object_set_new(loc, "timeZone", tzid ? json_string(tzid) : json_null());

    /* coordinates */
    const char *coord = get_icalxparam_value(prop, JMAPICAL_XPARAM_GEO);
    json_object_set_new(loc, "coordinates", coord ? json_string(coord) : json_null());

    /* linkIds (including altrep) */
    json_t *linkids = json_object();
    for (param = icalproperty_get_first_parameter(prop, ICAL_X_PARAMETER);
         param;
         param = icalproperty_get_next_parameter(prop, ICAL_X_PARAMETER)) {

        if (strcasecmp(icalparameter_get_xname(param), JMAPICAL_XPARAM_LINKID)) {
            continue;
        }
        const char *s = icalparameter_get_xvalue(param);
        if (!s) continue;
        json_object_set_new(linkids, s, json_true());
    }
    const char *altrep = NULL;
    param = icalproperty_get_first_parameter(prop, ICAL_ALTREP_PARAMETER);
    if (param) altrep = icalparameter_get_altrep(param);
    if (altrep) {
        char *tmp = sha1key(altrep);
        json_object_set_new(links, tmp, json_pack("{s:s}", "href", altrep));
        json_object_set_new(linkids, tmp, json_true());
        free(tmp);
    }
    if (!json_object_size(linkids)) {
        json_decref(linkids);
        linkids = json_null();
    }
    json_object_set_new(loc, "linkIds", linkids);

    return loc;
}

static json_t *coordinates_from_ical(icalproperty *prop)
{
    /* Use verbatim coordinate string, rather than the parsed ical value */
    const char *p, *val = icalproperty_get_value_as_string(prop);
    struct buf buf = BUF_INITIALIZER;
    json_t *c;

    p = strchr(val, ';');
    if (!p) return NULL;

    buf_setcstr(&buf, "geo:");
    buf_appendmap(&buf, val, p-val);
    buf_appendcstr(&buf, ",");
    val = p + 1;
    buf_appendcstr(&buf, val);

    c = json_string(buf_cstring(&buf));
    buf_free(&buf);
    return c;
}

static json_t*
locations_from_ical(icalcomponent *comp, json_t *links)
{
    icalproperty* prop;
    json_t *loc, *locations = json_pack("{}");
    char *id;

    /* Handle end locations */
    const char *tzidstart = tzid_from_ical(comp, ICAL_DTSTART_PROPERTY);
    const char *tzidend = tzid_from_ical(comp, ICAL_DTEND_PROPERTY);
    if (tzidstart && tzidend && strcmp(tzidstart, tzidend)) {
        prop = icalcomponent_get_first_property(comp, ICAL_DTEND_PROPERTY);
        id = xjmapid_from_ical(prop);
        loc = json_pack("{s:s s:s}", "timeZone", tzidend, "rel", "end");
        json_object_set_new(locations, id, loc);
        free(id);
    }

    /* LOCATION */
    if ((prop = icalcomponent_get_first_property(comp, ICAL_LOCATION_PROPERTY))) {
        id = xjmapid_from_ical(prop);
        if ((loc = location_from_ical(prop, links))) {
            json_object_set_new(locations, id, loc);
        }
        free(id);
    }

    /* GEO */
    if ((prop = icalcomponent_get_first_property(comp, ICAL_GEO_PROPERTY))) {
        json_t *coord = coordinates_from_ical(prop);
        if (coord) {
            loc = json_pack("{s:o}", "coordinates", coord);
            id = xjmapid_from_ical(prop);
            json_object_set_new(locations, id, loc);
            free(id);
        }
    }

    /* Lookup X-property locations */
    for (prop = icalcomponent_get_first_property(comp, ICAL_X_PROPERTY);
         prop;
         prop = icalcomponent_get_next_property(comp, ICAL_X_PROPERTY)) {

        const char *name = icalproperty_get_property_name(prop);

        /* X-APPLE-STRUCTURED-LOCATION */
        /* FIXME Most probably,
         * a X-APPLE-STRUCTURED-LOCATION may occur only once and
         * always comes with a LOCATION. But who knows for sure? */
        if (!strcmp(name, "X-APPLE-STRUCTURED-LOCATION")) {
            const char *title, *uri;
            icalvalue *val;

            val = icalproperty_get_value(prop);
            if (icalvalue_isa(val) != ICAL_URI_VALUE) continue;

            uri = icalvalue_as_ical_string(val);
            if (strncmp(uri, "geo:", 4)) continue;

            loc = json_pack("{s:s}", "coordinates", uri);
            if ((title = get_icalxparam_value(prop, JMAPICAL_XPARAM_TITLE))) {
                json_object_set_new(loc, "name", json_string(title));
            }

            id = xjmapid_from_ical(prop);
            json_object_set_new(locations, id, loc);
            free(id);
            continue;
        }

        if (strcmp(name, JMAPICAL_XPROP_LOCATION)) {
            continue;
        }

        /* X-JMAP-LOCATION */
        id = xjmapid_from_ical(prop);
        loc = location_from_ical(prop, links);
        if (loc) json_object_set_new(locations, id, loc);
        free(id);
    }

    if (!json_object_size(locations)) {
        json_decref(locations);
        locations = json_null();
    }

    return locations;
}

static json_t*
virtuallocations_from_ical(icalcomponent *comp)
{
    icalproperty* prop;
    json_t *locations = json_pack("{}");

    for (prop = icalcomponent_get_first_property(comp, ICAL_CONFERENCE_PROPERTY);
         prop;
         prop = icalcomponent_get_next_property(comp, ICAL_CONFERENCE_PROPERTY)) {

        char *id = xjmapid_from_ical(prop);
        json_t *loc = json_object();

        const char *uri = icalproperty_get_value_as_string(prop);
        if (uri) json_object_set_new(loc, "uri", json_string(uri));

        const char *name = "";
        icalparameter *param = icalproperty_get_first_parameter(prop, ICAL_LABEL_PARAMETER);
        if (param) name = icalparameter_get_label(param);
        if (!name) name = "";
        json_object_set_new(loc, "name", json_string(name));

        const char *desc = get_icalxparam_value(prop, JMAPICAL_XPARAM_DESCRIPTION);
        if (desc) json_object_set_new(loc, "description", json_string(desc));

        if (uri) json_object_set_new(locations, id, loc);
        free(id);
    }

    if (!json_object_size(locations)) {
        json_decref(locations);
        locations = json_null();
    }

    return locations;
}

static struct icaldurationtype duration_from_ical(icalcomponent *comp)
{
    struct icaldurationtype dur = icaldurationtype_null_duration();
    struct icaltimetype dtstart, dtend;

    dtstart = dtstart_from_ical(comp);
    dtend = dtend_from_ical(comp);

    if (!icaltime_is_null_time(dtend)) {
        time_t tstart, tend;

        tstart = icaltime_as_timet_with_zone(dtstart, dtstart.zone);
        tend = icaltime_as_timet_with_zone(dtend, dtend.zone);
        dur = icaldurationtype_from_int((int)(tend - tstart));
        if (icaldurationtype_is_bad_duration(dur) || dur.is_neg) {
            dur = icaldurationtype_null_duration();
        }
    }

    return dur;
}

static json_t*
locale_from_ical(icalcomponent *comp)
{
    icalproperty *sum, *dsc;
    icalparameter *param = NULL;
    const char *lang = NULL;

    sum = icalcomponent_get_first_property(comp, ICAL_SUMMARY_PROPERTY);
    dsc = icalcomponent_get_first_property(comp, ICAL_DESCRIPTION_PROPERTY);

    if (sum) {
        param = icalproperty_get_first_parameter(sum, ICAL_LANGUAGE_PARAMETER);
    }
    if (!param && dsc) {
        param = icalproperty_get_first_parameter(dsc, ICAL_LANGUAGE_PARAMETER);
    }
    if (param) {
        lang = icalparameter_get_language(param);
    }

    return lang ? json_string(lang) : json_null();
}

/* Convert the libical VEVENT comp to a CalendarEvent 
 *
 * master: if not NULL, treat comp as a VEVENT exception
 * props:  if not NULL, only convert properties named as keys
 */
static json_t*
calendarevent_from_ical(icalcomponent *comp, hash_table *props, icalcomponent *master)
{
    icalproperty* prop = NULL;
    int is_exception = master != NULL;
    hash_table *wantprops = NULL;
    json_t *event = json_pack("{s:s}", "@type", "jsevent");

    if (jmap_wantprop(props, "recurrenceOverrides") && !is_exception) {
        /* Fetch all properties if recurrenceOverrides are requested,
         * otherwise we might return incomplete override patches */
        wantprops = props;
        props = NULL;
    }

    /* Initialize time fields */
    struct icaltimetype dtstart = icalcomponent_get_dtstart(comp);
    struct icaldurationtype dur = duration_from_ical(comp);
    int is_allday = 0;

    /* Handle bogus mix of floating and time zoned types */
    const char *tzid_start = tzid_from_ical(comp, ICAL_DTSTART_PROPERTY);
    if (!tzid_start) tzid_start = tzid_from_ical(comp, ICAL_DTEND_PROPERTY);

    /* Initialize isAllDay */
    if (icaltime_is_date(icalcomponent_get_dtstart(comp))) {
        is_allday = 1;
        tzid_start = NULL;
    }
    else is_allday = 0;

    /* start */
    if (jmap_wantprop(props, "start")) {
        char *s = localdate_from_icaltime_r(dtstart);
        json_object_set_new(event, "start", json_string(s));
        free(s);
    }

    /* timeZone */
    if (jmap_wantprop(props, "timeZone")) {
        json_object_set_new(event, "timeZone", tzid_start ?
                json_string(tzid_start) : json_null());
    }

    /* duration */
    if (jmap_wantprop(props, "duration")) {
        char *s = icaldurationtype_as_ical_string_r(dur);
        json_object_set_new(event, "duration", json_string(s));
        free(s);
    }

    /* isAllDay */
    if (jmap_wantprop(props, "isAllDay") && !is_exception) {
        json_object_set_new(event, "isAllDay", json_boolean(is_allday));
    }

    /* uid */
    const char *uid = icalcomponent_get_uid(comp);
    if (uid && !is_exception) {
        json_object_set_new(event, "uid", json_string(uid));
    }

    /* relatedTo */
    if (jmap_wantprop(props, "relatedTo") && !is_exception) {
        json_object_set_new(event, "relatedTo", relatedto_from_ical(comp));
    }

    /* prodId */
    if (jmap_wantprop(props, "prodId") && !is_exception) {
        icalcomponent *ical = icalcomponent_get_parent(comp);
        const char *prodid = NULL;
        prop = icalcomponent_get_first_property(ical, ICAL_PRODID_PROPERTY);
        if (prop) prodid = icalproperty_get_prodid(prop);
        json_object_set_new(event, "prodId",
                prodid ? json_string(prodid) : json_null());
    }

    /* created */
    if (jmap_wantprop(props, "created")) {
        json_t *val = json_null();
        prop = icalcomponent_get_first_property(comp, ICAL_CREATED_PROPERTY);
        if (prop) {
            char *t = utcdate_from_icaltime_r(icalproperty_get_created(prop));
            if (t) {
                val = json_string(t);
                free(t);
            }
        }
        json_object_set_new(event, "created", val);
    }

    /* updated */
    if (jmap_wantprop(props, "updated")) {
        json_t *val = json_null();
        prop = icalcomponent_get_first_property(comp, ICAL_DTSTAMP_PROPERTY);
        if (prop) {
            char *t = utcdate_from_icaltime_r(icalproperty_get_dtstamp(prop));
            if (t) {
                val = json_string(t);
                free(t);
            }
        }
        json_object_set_new(event, "updated", val);
    }

    /* sequence */
    if (jmap_wantprop(props, "sequence")) {
        json_object_set_new(event, "sequence",
                json_integer(icalcomponent_get_sequence(comp)));
    }

    /* priority */
    if (jmap_wantprop(props, "priority")) {
        int priority = 0;
        prop = icalcomponent_get_first_property(comp, ICAL_PRIORITY_PROPERTY);
        if (prop) priority = icalproperty_get_priority(prop);
        json_object_set_new(event, "priority", json_integer(priority));
    }

    /* title */
    if (jmap_wantprop(props, "title")) {
        const char *title= "";
        prop = icalcomponent_get_first_property(comp, ICAL_SUMMARY_PROPERTY);
        if (prop) {
            title = icalproperty_get_summary(prop);
            if (!title) title = "";
        }
        json_object_set_new(event, "title", json_string(title));
    }

    /* description */
    if (jmap_wantprop(props, "description") || jmap_wantprop(props, "descriptionContentType")) {
        const char *desc = "";
        prop = icalcomponent_get_first_property(comp, ICAL_DESCRIPTION_PROPERTY);
        if (prop) {
            desc = icalproperty_get_description(prop);
            if (!desc) desc = "";
        }
        if (jmap_wantprop(props, "description")) {
            json_object_set_new(event, "description", json_string(desc));
        }
        if (jmap_wantprop(props, "descriptionContentType")) {
            json_object_set_new(event, "descriptionContentType", json_string("text/plain"));
        }
    }

    /* method */
    if (jmap_wantprop(props, "method")) {
        icalcomponent *ical = icalcomponent_get_parent(comp);
        if (ical) {
            icalproperty_method icalmethod = icalcomponent_get_method(ical);
            if (icalmethod != ICAL_METHOD_NONE) {
                char *method = xstrdupsafe(icalenum_method_to_string(icalmethod));
                lcase(method);
                json_object_set_new(event, "method", json_string(method));
                free(method);
            }
        }
    }

    /* color */
    if (jmap_wantprop(props, "color")) {
        prop = icalcomponent_get_first_property(comp, ICAL_COLOR_PROPERTY);
        if (prop) {
            json_object_set_new(event, "color",
                    json_string(icalproperty_get_color(prop)));
        }
    }

    /* keywords */
    if (jmap_wantprop(props, "keywords")) {
        json_object_set_new(event, "keywords", keywords_from_ical(comp));
    }

    /* links */
    if (jmap_wantprop(props, "links")) {
        json_object_set_new(event, "links", links_from_ical(comp));
    }

    /* locale */
    if (jmap_wantprop(props, "locale")) {
        json_object_set_new(event, "locale", locale_from_ical(comp));
    }

    /* locations */
    if (jmap_wantprop(props, "locations")) {
        json_t *links = json_object();
        json_object_set_new(event, "locations", locations_from_ical(comp, links));
        if (json_object_size(links)) {
            if (JNOTNULL(json_object_get(event, "links"))) {
                json_object_update(json_object_get(event, "links"), links);
            } else {
                json_object_set(event, "links", links);
            }
        }
        json_decref(links);
    }

    /* virtualLocations */
    if (jmap_wantprop(props, "virtualLocations")) {
        json_object_set_new(event, "virtualLocations", virtuallocations_from_ical(comp));
    }

    /* recurrenceRule */
    if (jmap_wantprop(props, "recurrenceRule") && !is_exception) {
        json_object_set_new(event, "recurrenceRule", recurrence_from_ical(comp));
    }

    /* status */
    if (jmap_wantprop(props, "status")) {
        const char *status = "confirmed";
        switch (icalcomponent_get_status(comp)) {
            case ICAL_STATUS_TENTATIVE:
                status = "tentative";
                break;
            case ICAL_STATUS_CONFIRMED:
                status = "confirmed";
                break;
            case ICAL_STATUS_CANCELLED:
                status = "cancelled";
                break;
            default:
                status = "confirmed";
        }
        json_object_set_new(event, "status", json_string(status));
    }

    /* freeBusyStatus */
    if (jmap_wantprop(props, "freeBusyStatus")) {
        const char *fbs = "busy";
        if ((prop = icalcomponent_get_first_property(comp,
                                                     ICAL_TRANSP_PROPERTY))) {
            if (icalproperty_get_transp(prop) == ICAL_TRANSP_TRANSPARENT) {
                fbs = "free";
            }
        }
        json_object_set_new(event, "freeBusyStatus", json_string(fbs));
    }

    /* privacy */
    if (jmap_wantprop(props, "privacy")) {
        const char *prv = "public";
        if ((prop = icalcomponent_get_first_property(comp, ICAL_CLASS_PROPERTY))) {
            switch (icalproperty_get_class(prop)) {
                case ICAL_CLASS_CONFIDENTIAL:
                    prv = "secret";
                    break;
                case ICAL_CLASS_PRIVATE:
                    prv = "private";
                    break;
                default:
                    prv = "public";
            }
        }
        json_object_set_new(event, "privacy", json_string(prv));
    }

    /* replyTo */
    if (jmap_wantprop(props, "replyTo") && !is_exception) {
        if ((prop = icalcomponent_get_first_property(comp, ICAL_ORGANIZER_PROPERTY))) {
            json_object_set_new(event, "replyTo",rsvpto_from_ical(prop));
        }
    }

    /* participants */
    if (jmap_wantprop(props, "participants")) {
        json_object_set_new(event, "participants", participants_from_ical(comp));
    }

    /* useDefaultAlerts */
    if (jmap_wantprop(props, "useDefaultAlerts")) {
        const char *v = get_icalxprop_value(comp, JMAPICAL_XPROP_USEDEFALERTS);
        json_object_set_new(event, "useDefaultAlerts",
                json_boolean(v && !strcasecmp(v, "true")));
    }

    /* alerts */
    if (jmap_wantprop(props, "alerts")) {
        json_object_set_new(event, "alerts", alerts_from_ical(comp));
    }

    /* recurrenceOverrides - must be last to generate patches */
    if (jmap_wantprop(props, "recurrenceOverrides") && !is_exception) {
        json_object_set_new(event, "recurrenceOverrides",
                overrides_from_ical(comp, event, tzid_start));
    }

    if (wantprops) {
        jmap_filterprops(event, wantprops);
    }

    return event;
}

json_t*
jmapical_tojmap_all(icalcomponent *ical, hash_table *props)
{
    icalcomponent* comp;

    /* Locate all main VEVENTs. */
    ptrarray_t todo = PTRARRAY_INITIALIZER;
    icalcomponent *firstcomp =
        icalcomponent_get_first_component(ical, ICAL_VEVENT_COMPONENT);
    for (comp = firstcomp;
         comp;
         comp = icalcomponent_get_next_component(ical, ICAL_VEVENT_COMPONENT)) {

        icalproperty *recurid = icalcomponent_get_first_property(comp, ICAL_RECURRENCEID_PROPERTY);
        if (recurid) continue;

        if (icalcomponent_get_uid(comp) == NULL) continue;

        ptrarray_append(&todo, comp);
    }
    /* magic promote to toplevel for the first item */
    if (firstcomp && !ptrarray_size(&todo)) {
        ptrarray_append(&todo, firstcomp);
    }
    else if (!ptrarray_size(&todo)) {
        return json_array();
    }

    /* Convert the VEVENTs to JMAP. */
    json_t *events = json_array();
    while ((comp = ptrarray_pop(&todo))) {
        json_t *jsevent = calendarevent_from_ical(comp, props, NULL);
        if (jsevent) json_array_append_new(events, jsevent);
    }

    ptrarray_fini(&todo);
    return events;
}

json_t*
jmapical_tojmap(icalcomponent *ical, hash_table *props)
{
    json_t *jsevents = jmapical_tojmap_all(ical, props);
    json_t *ret = NULL;
    if (json_array_size(jsevents)) {
        ret = json_incref(json_array_get(jsevents, 0));
    }
    json_decref(jsevents);
    return ret;
}

/*
 * Convert to iCalendar from JMAP
 */

/* defined in http_tzdist */
extern void icalcomponent_add_required_timezones(icalcomponent *ical);

/* Remove and deallocate any properties of kind in comp. */
static void remove_icalprop(icalcomponent *comp, icalproperty_kind kind)
{
    icalproperty *prop, *next;

    for (prop = icalcomponent_get_first_property(comp, kind);
         prop;
         prop = next) {

        next = icalcomponent_get_next_property(comp, kind);
        icalcomponent_remove_property(comp, prop);
        icalproperty_free(prop);
    }
}

/* Convert the JMAP local datetime in buf to tm time.
   Return non-zero on success. */
static int localdate_to_tm(const char *buf, struct tm *tm) {
    /* Initialize tm. We don't know about daylight savings time here. */
    memset(tm, 0, sizeof(struct tm));
    tm->tm_isdst = -1;

    /* Parse LocalDate. */
    const char *p = strptime(buf, "%Y-%m-%dT%H:%M:%S", tm);
    if (!p || *p) {
        return 0;
    }
    return 1;
}

static int tm_to_icaltime(struct tm tm,
                          icaltimezone *tz,
                          int is_allday,
                          icaltimetype *dt)
{
    char *s = NULL;
    if (is_allday) {
        if (tm.tm_hour != 0 || tm.tm_min != 0 || tm.tm_sec != 0) return 0;
        s = xcalloc(10, sizeof(char));
        strftime(s, 9, "%Y%m%d", &tm);
    }
    else {
        s = xcalloc(19, sizeof(char));
        size_t n = strftime(s, 18, "%Y%m%dT%H%M%S", &tm);
        if (tz == icaltimezone_get_utc_timezone()) s[n]='Z';
    }
    icaltimetype tmp = icaltime_from_string(s);
    free(s);
    if (icaltime_is_null_time(tmp)) {
        return 0;
    }
    tmp.zone = tz;
    tmp.is_date = is_allday;
    *dt = tmp;
    return 1;
}

/* Convert the JMAP local datetime formatted buf into ical datetime dt
 * using timezone tz. Return non-zero on success.
 */
static int localdate_to_icaltime(const char *buf,
                                 icaltimezone *tz,
                                 int is_allday,
                                 icaltimetype *dt)
{
    struct tm tm;
    int r = localdate_to_tm(buf, &tm);
    if (!r) return 0;
    return tm_to_icaltime(tm, tz, is_allday, dt);
}

static int utcdate_to_icaltime(const char *src,
                               icaltimetype *dt)
{
    struct buf buf = BUF_INITIALIZER;
    size_t len = strlen(src);
    int r;
    icaltimezone *utc = icaltimezone_get_utc_timezone();

    if (!len || src[len-1] != 'Z') {
        return 0;
    }

    buf_setmap(&buf, src, len-1);
    r = localdate_to_icaltime(buf_cstring(&buf), utc, 0, dt);
    buf_free(&buf);
    return r;
}

/* Add or overwrite the datetime property kind in comp. If tz is not NULL, set
 * the TZID parameter on the property. Also take care to purge conflicting
 * datetime properties such as DTEND and DURATION. */
static icalproperty *dtprop_to_ical(icalcomponent *comp,
                                    icaltimetype dt,
                                    int purge,
                                    enum icalproperty_kind kind) {
    icalproperty *prop;

    /* Purge existing property. */
    if (purge) {

        remove_icalprop(comp, kind);
    }

    /* Resolve DTEND/DURATION conflicts. */
    if (kind == ICAL_DTEND_PROPERTY) {
        remove_icalprop(comp, ICAL_DURATION_PROPERTY);
    } else if (kind == ICAL_DURATION_PROPERTY) {
        remove_icalprop(comp, ICAL_DTEND_PROPERTY);
    }

    /* backwards compatible way to set date or datetime */
    icalvalue *val =
        dt.is_date ? icalvalue_new_date(dt) : icalvalue_new_datetime(dt);
    if (!val) {
        syslog(LOG_ERR, "dtprop_to_ical: invalid time value");
        return NULL;
    }

    /* Set the new property. */
    prop = icalproperty_new(kind);
    icalproperty_set_value(prop, val);
    if (dt.zone && !icaltime_is_utc(dt)) {
        icalparameter *param =
            icalproperty_get_first_parameter(prop, ICAL_TZID_PARAMETER);
        /* XXX libical uses non-const icaltimezone pointer for read-only */
        const char *tzid = icaltimezone_get_location((icaltimezone*)dt.zone);
        if (param) {
            icalparameter_set_tzid(param, tzid);
        } else {
            icalproperty_add_parameter(prop,icalparameter_new_tzid(tzid));
        }
    }
    icalcomponent_add_property(comp, prop);
    return prop;
}

static int location_is_endtimezone(json_t *loc)
{
    const char *rel = json_string_value(json_object_get(loc, "rel"));
    if (!rel) return 0;
    return json_object_get(loc, "timeZone") && !strcmp(rel, "end");
}

/* Update the start and end properties of VEVENT comp, as defined by
 * the JMAP calendarevent event. */
static void
startend_to_ical(icalcomponent *comp, struct jmap_parser *parser, json_t *event)
{
    /* isAllDay */
    int is_allday = 0;
    json_t *jprop = json_object_get(event, "isAllDay");
    if (json_is_boolean(jprop)) {
        is_allday = json_boolean_value(jprop);
    } else if (JNOTNULL(jprop)) {
        jmap_parser_invalid(parser, "isAllDay");
    }

    /* timeZone */
    icaltimezone *tzstart = NULL;
    jprop = json_object_get(event, "timeZone");
    if (json_is_string(jprop)) {
        const char *val = json_string_value(jprop);
        tzstart = tz_from_tzid(val);
        if (!tzstart || is_allday) {
            jmap_parser_invalid(parser, "timeZone");
        }
    } else if (JNOTNULL(jprop)) {
        jmap_parser_invalid(parser, "timeZone");
    }

    /* Read end timezone */
    icaltimezone *tzend = tzstart;
    const char *endzone_location_id = NULL;
    json_t *locations = json_object_get(event, "locations");
    if (json_is_object(locations)) {
        json_t *jval;
        const char *id;
        jmap_parser_push(parser, "locations");
        json_object_foreach(locations, id, jval) {
            if (!location_is_endtimezone(jval)) {
                continue;
            }
            /* Pick the first location with timeZone and rel=end */
            jmap_parser_push(parser, id);
            endzone_location_id = id;
            json_t *timeZone = json_object_get(jval, "timeZone");
            if (json_is_string(timeZone)) {
                tzend = tz_from_tzid(json_string_value(timeZone));
                if (!tzend || !tzstart) {
                    jmap_parser_invalid(parser, "timeZone");
                }
            }
            else if (JNOTNULL(jprop)) {
                jmap_parser_invalid(parser, "timeZone");
            }
            jmap_parser_pop(parser);
            break;
        }
        jmap_parser_pop(parser);
    } else if (JNOTNULL(locations)) {
        jmap_parser_invalid(parser, "locations");
    }

    /* Read duration */
    struct icaldurationtype dur = icaldurationtype_null_duration();
    jprop = json_object_get(event, "duration");
    if (json_is_string(jprop)) {
        dur = icaldurationtype_from_string(json_string_value(jprop));
        if (icaldurationtype_is_bad_duration(dur)) {
            jmap_parser_invalid(parser, "duration");
        }
    } else if (JNOTNULL(jprop)) {
        jmap_parser_invalid(parser, "duration");
    }
    if (is_allday) {
        if (!icaldurationtype_is_bad_duration(dur) && (dur.hours || dur.minutes || dur.seconds)) {
            jmap_parser_invalid(parser, "duration");
        }
    }

    /* Read start */
    struct icaltimetype dtstart = icaltime_null_time();
    jprop = json_object_get(event, "start");
    if (json_is_string(jprop)) {
        const char *val = json_string_value(jprop);
        if (!localdate_to_icaltime(val, tzstart, is_allday, &dtstart)) {
            jmap_parser_invalid(parser, "start");
        }
    } else {
        jmap_parser_invalid(parser, "start");
    }

    /* Bail out for property errors */
    if (json_array_size(parser->invalid))
        return;

    /* Purge and rebuild start and end */
    remove_icalprop(comp, ICAL_DTSTART_PROPERTY);
    remove_icalprop(comp, ICAL_DTEND_PROPERTY);
    remove_icalprop(comp, ICAL_DURATION_PROPERTY);

    dtprop_to_ical(comp, dtstart, 1, ICAL_DTSTART_PROPERTY);
    if (tzstart != tzend) {
        /* Add DTEND */
        icaltimetype dtend;
        icalproperty *prop;

        dtend = icaltime_add(dtstart, dur);
        dtend = icaltime_convert_to_zone(dtend, tzend);
        prop = dtprop_to_ical(comp, dtend, 1, ICAL_DTEND_PROPERTY);
        if (prop) xjmapid_to_ical(prop, endzone_location_id);
    } else {
        /* Add DURATION */
        icalcomponent_set_duration(comp, dur);
    }
}

static void
participant_roles_to_ical(icalproperty *prop,
                          struct jmap_parser *parser,
                          json_t *roles,
                          icalparameter_role ical_role,
                          int is_replyto)
{
    if (!json_object_size(roles)) {
        jmap_parser_invalid(parser, "roles");
        return;
    }

    const char *key;
    json_t *jval;
    jmap_parser_push(parser, "roles");
    json_object_foreach(roles, key, jval) {
        if (jval != json_true()) {
            jmap_parser_invalid(parser, key);
        }
    }
    jmap_parser_pop(parser);

    int has_owner = json_object_get(roles, "owner") == json_true();
    int has_chair = json_object_get(roles, "chair") == json_true();
    int has_attendee = json_object_get(roles, "attendee") == json_true();
    size_t xroles_count = json_object_size(roles);

    /* Try to map roles to iCalendar without falling back to X-ROLE */
    if (has_chair && ical_role == ICAL_ROLE_REQPARTICIPANT) {
        /* Can use iCalendar ROLE=CHAIR parameter */
        xroles_count--;
    }
    if (has_owner && is_replyto) {
        /* This is the ORGANIZER or its ATTENDEE, which is implicit "owner" */
        xroles_count--;
    }
    if (has_attendee) {
        /* Default role for ATTENDEE without X-ROLE is "attendee" */
        xroles_count--;
    }
    if (xroles_count == 0) {
        /* No need to set X-ROLE parameters on this ATTENDEE */
        if (has_chair) {
            icalparameter *param = icalparameter_new_role(ICAL_ROLE_CHAIR);
            icalproperty_add_parameter(prop, param);
        }
    }
    else {
        /* Map roles to X-ROLE */
        json_object_foreach(roles, key, jval) {
            /* Try to use standard CHAIR role */
            if (!strcasecmp(key, "CHAIR") && ical_role == ICAL_ROLE_REQPARTICIPANT) {
                icalparameter *param = icalparameter_new_role(ICAL_ROLE_CHAIR);
                icalproperty_add_parameter(prop, param);
            } else {
                set_icalxparam(prop, JMAPICAL_XPARAM_ROLE, key, 0);
            }
        }
    }
}

static int is_valid_rsvpmethod(const char *s)
{
    if (!s) return 0;
    size_t i;
    for (i = 0; s[i]; i++) {
        if (!isascii(s[i]) || !isalpha(s[i])) {
            return 0;
        }
    }
    return i > 0;
}

static int
participant_equals(json_t *jpart1, json_t *jpart2)
{
    /* Special-case sendTo URI values */
    json_t *jsendTo1 = json_object_get(jpart1, "sendTo");
    json_t *jsendTo2 = json_object_get(jpart2, "sendTo");
    if (jsendTo1 == NULL || jsendTo1 == json_null()) {
        json_t *jemail = json_object_get(jpart1, "email");
        if (json_is_string(jemail)) {
            char *tmp = strconcat("mailto:", json_string_value(jemail), NULL);
            json_object_set_new(jpart1, "sendTo", json_pack("{s:s}", "imip", tmp));
            free(tmp);
        }
        jsendTo1 = json_object_get(jpart1, "sendTo");
    }
    if (jsendTo2 == NULL || jsendTo2 == json_null()) {
        json_t *jemail = json_object_get(jpart2, "email");
        if (json_is_string(jemail)) {
            char *tmp = strconcat("mailto:", json_string_value(jemail), NULL);
            json_object_set_new(jpart2, "sendTo", json_pack("{s:s}", "imip", tmp));
            free(tmp);
        }
        jsendTo2 = json_object_get(jpart2, "sendTo");
    }
    if (json_object_size(jsendTo1) != json_object_size(jsendTo2)) return 0;
    if (JNOTNULL(jsendTo1)) {
        json_t *juri1;
        const char *method;
        json_object_foreach(jsendTo1, method, juri1) {
            json_t *juri2 = json_object_get(jsendTo2, method);
            if (!juri2) return 0;
            const char *uri1 = json_string_value(juri1);
            const char *uri2 = json_string_value(juri2);
            if (!uri1 || !uri2 || !match_uri(uri1, uri2)) return 0;
        }
    }

    json_t *jval1 = json_copy(jpart1);
    json_t *jval2 = json_copy(jpart2);
    json_object_del(jval1, "sendTo");
    json_object_del(jval2, "sendTo");

    /* Remove default values */
    if (!strcmpsafe(json_string_value(json_object_get(jval1, "name")), ""))
        json_object_del(jval1, "name");
    if (!strcmpsafe(json_string_value(json_object_get(jval2, "name")), ""))
        json_object_del(jval2, "name");

    if (!strcmpsafe(json_string_value(json_object_get(jval1, "participationStatus")), "needs-action"))
        json_object_del(jval1, "participationStatus");
    if (!strcmpsafe(json_string_value(json_object_get(jval2, "participationStatus")), "needs-action"))
        json_object_del(jval2, "participationStatus");

    if (!strcmpsafe(json_string_value(json_object_get(jval1, "attendance")), "required"))
        json_object_del(jval1, "attendance");
    if (!strcmpsafe(json_string_value(json_object_get(jval2, "attendance")), "required"))
        json_object_del(jval2, "attendance");

    if (!json_boolean_value(json_object_get(jval1, "expectReply")))
        json_object_del(jval1, "expectReply");
    if (!json_boolean_value(json_object_get(jval2, "expectReply")))
        json_object_del(jval2, "expectReply");

    if (json_integer_value(json_object_get(jval1, "scheduleSequence")) == 0)
        json_object_del(jval1, "scheduleSequence");
    if (json_integer_value(json_object_get(jval2, "scheduleSequence")) == 0)
        json_object_del(jval2, "scheduleSequence");

    /* Unify JSON null to NULL */
    json_t *jprop;
    const char *key;
    void *tmp;
    json_object_foreach_safe(jval1, tmp, key, jprop) {
        if (json_is_null(jprop)) json_object_del(jval1, key);
    }
    json_object_foreach_safe(jval2, tmp, key, jprop) {
        if (json_is_null(jprop)) json_object_del(jval2, key);
    }

    int is_equal = json_equal(jval1, jval2);
    json_decref(jval1);
    json_decref(jval2);
    return is_equal;
}



static void
participant_to_ical(icalcomponent *comp,
                    struct jmap_parser *parser,
                    const char *id,
                    json_t *jpart,
                    json_t *participants,
                    json_t *links,
                    const char *orga_uri,
                    hash_table *caladdress_by_participant_id)
{
    const char *caladdress = hash_lookup(id, caladdress_by_participant_id);
    icalproperty *prop = icalproperty_new_attendee(caladdress);
    set_icalxparam(prop, JMAPICAL_XPARAM_ID, id, 1);

    icalproperty *orga = icalcomponent_get_first_property(comp, ICAL_ORGANIZER_PROPERTY);
    int is_orga = match_uri(caladdress, orga_uri);
    if (is_orga) set_icalxparam(orga, JMAPICAL_XPARAM_ID, id, 1);

    /* name */
    json_t *jname = json_object_get(jpart, "name");
    if (json_is_string(jname)) {
        const char *name = json_string_value(jname);
        icalproperty_add_parameter(prop, icalparameter_new_cn(name));
        if (is_orga) {
            icalproperty_add_parameter(orga, icalparameter_new_cn(name));
        }
    }
    else if (JNOTNULL(jname)) {
        jmap_parser_invalid(parser, "name");
    }

    /* sendTo */
    json_t *sendTo = json_object_get(jpart, "sendTo");
    if (json_object_size(sendTo)) {
        jmap_parser_push(parser, "sendTo");
        struct buf buf = BUF_INITIALIZER;

        /* Only set RSVP URI x-params if not trivial */
        int set_rsvp_uris = 0;
        if (json_object_size(sendTo) > 1) {
            set_rsvp_uris = 1;
        }
        else {
            const char *method = json_object_iter_key(json_object_iter(sendTo));
            set_rsvp_uris = strcmp(method, "imip") && strcmp(method, "other");
        }

        const char *key;
        json_t *jval;
        /* Process RSVP URIs */
        json_object_foreach(sendTo, key, jval) {
            if (!is_valid_rsvpmethod(key) || !json_is_string(jval)) {
                jmap_parser_invalid(parser, key);
                continue;
            }
            if (!set_rsvp_uris) continue;

            buf_setcstr(&buf, key);
            buf_putc(&buf, ':');
            buf_appendcstr(&buf, json_string_value(jval));
            set_icalxparam(prop, JMAPICAL_XPARAM_RSVP_URI, buf_cstring(&buf), 0);
        }

        buf_free(&buf);
        jmap_parser_pop(parser);
    }
    else if (JNOTNULL(sendTo)) {
        jmap_parser_invalid(parser, "sendTo");
    }

    /* email */
    json_t *jemail = json_object_get(jpart, "email");
    if (json_is_string(jemail)) {
        const char *uri = icalproperty_get_value_as_string(prop);
        const char *email = json_string_value(jemail);
        if (!match_uri(uri, email)) {
            icalproperty_add_parameter(prop, icalparameter_new_email(email));
            if (is_orga) {
                icalproperty_add_parameter(orga, icalparameter_new_email(email));
            }
        }
    }
    else if (JNOTNULL(jemail)) {
        jmap_parser_invalid(parser, "email");
    }

    /* kind */
    json_t *kind = json_object_get(jpart, "kind");
    if (json_is_string(kind)) {
        icalparameter *param = NULL;
        char *tmp = ucase(xstrdup(json_string_value(kind)));
        icalparameter_cutype cu;
        if (!strcmp(tmp, "LOCATION"))
            cu = ICAL_CUTYPE_ROOM;
        else
            cu = icalparameter_string_to_enum(tmp);
        switch (cu) {
            case ICAL_CUTYPE_INDIVIDUAL:
            case ICAL_CUTYPE_GROUP:
            case ICAL_CUTYPE_RESOURCE:
            case ICAL_CUTYPE_ROOM:
                param = icalparameter_new_cutype(cu);
                icalproperty_add_parameter(prop, param);
                break;
            default:
                /* ignore */ ;
        }
        free(tmp);
    }
    else if (JNOTNULL(kind)) {
        jmap_parser_invalid(parser, "kind");
    }

    /* attendance */
    icalparameter_role ical_role = ICAL_ROLE_REQPARTICIPANT;
    json_t *attendance = json_object_get(jpart, "attendance");
    if (json_is_string(attendance)) {
        const char *s = json_string_value(attendance);
        if (!strcasecmp(s, "required")) {
            ical_role = ICAL_ROLE_REQPARTICIPANT;
        }
        else if (!strcasecmp(s, "optional")) {
            ical_role = ICAL_ROLE_OPTPARTICIPANT;
        }
        else if (!strcasecmp(s, "none")) {
            ical_role = ICAL_ROLE_NONPARTICIPANT;
        }
        if (ical_role != ICAL_ROLE_REQPARTICIPANT) {
            icalproperty_add_parameter(prop, icalparameter_new_role(ical_role));
        }
    }
    else if (JNOTNULL(attendance)) {
        jmap_parser_invalid(parser, "attendance");
    }

    /* roles */
    json_t *roles = json_object_get(jpart, "roles");
    if (json_object_size(roles)) {
        participant_roles_to_ical(prop, parser, roles, ical_role, is_orga);
    }
    else if (roles) {
        jmap_parser_invalid(parser, "roles");
    }

    /* locationId */
    json_t *locationId = json_object_get(jpart, "locationId");
    if (json_is_string(locationId)) {
        const char *s = json_string_value(locationId);
        set_icalxparam(prop, JMAPICAL_XPARAM_LOCATIONID, s, 1);
    }
    else if (JNOTNULL(locationId)) {
        jmap_parser_invalid(parser, "locationId");
    }

    /* participationStatus */
    icalparameter_partstat ps = ICAL_PARTSTAT_NONE;
    json_t *participationStatus = json_object_get(jpart, "participationStatus");
    if (json_is_string(participationStatus)) {
        char *tmp = ucase(xstrdup(json_string_value(participationStatus)));
        ps = icalparameter_string_to_enum(tmp);
        switch (ps) {
            case ICAL_PARTSTAT_NEEDSACTION:
            case ICAL_PARTSTAT_ACCEPTED:
            case ICAL_PARTSTAT_DECLINED:
            case ICAL_PARTSTAT_TENTATIVE:
                break;
            default:
                jmap_parser_invalid(parser, "participationStatus");
                ps = ICAL_PARTSTAT_NONE;
        }
        free(tmp);
    }
    else if (JNOTNULL(participationStatus)) {
        jmap_parser_invalid(parser, "participationStatus");
    }
    if (ps != ICAL_PARTSTAT_NONE) {
        icalproperty_add_parameter(prop, icalparameter_new_partstat(ps));
    }

    /* expectReply */
    json_t *expectReply = json_object_get(jpart, "expectReply");
    if (json_is_boolean(expectReply)) {
        icalparameter *param = NULL;
        if (expectReply == json_true()) {
            param = icalparameter_new_rsvp(ICAL_RSVP_TRUE);
            if (ps == ICAL_PARTSTAT_NONE) {
                icalproperty_add_parameter(prop,
                        icalparameter_new_partstat(ICAL_PARTSTAT_NEEDSACTION));
            }
        }
        else {
            param = icalparameter_new_rsvp(ICAL_RSVP_FALSE);
        }
        icalproperty_add_parameter(prop, param);
    }
    else if (JNOTNULL(expectReply)) {
        jmap_parser_invalid(parser, "expectReply");
    }

    /* delegatedTo */
    json_t *delegatedTo = json_object_get(jpart, "delegatedTo");
    if (json_object_size(delegatedTo)) {
        const char *id;
        json_t *jval;
        json_object_foreach(delegatedTo, id, jval) {
            json_t *delegatee = json_object_get(participants, id);
            if (is_valid_jmapid(id) && delegatee && jval == json_true()) {
                const char *uri = hash_lookup(id, caladdress_by_participant_id);
                if (uri) {
                    icalproperty_add_parameter(prop, icalparameter_new_delegatedto(uri));
                }
            }
            else {
                jmap_parser_push(parser, "delegatedTo");
                jmap_parser_invalid(parser, id);
                jmap_parser_pop(parser);
            }
        }
    }
    else if (JNOTNULL(delegatedTo)) {
        jmap_parser_invalid(parser, "delegatedTo");
    }

    /* delegatedFrom */
    json_t *delegatedFrom = json_object_get(jpart, "delegatedFrom");
    if (json_object_size(delegatedFrom)) {
        const char *id;
        json_t *jval;
        json_object_foreach(delegatedFrom, id, jval) {
            json_t *delegator = json_object_get(participants, id);
            if (is_valid_jmapid(id) && delegator && jval == json_true()) {
                const char *uri = hash_lookup(id, caladdress_by_participant_id);
                if (uri) {
                    icalproperty_add_parameter(prop, icalparameter_new_delegatedfrom(uri));
                }
            }
            else {
                jmap_parser_push(parser, "delegatedFrom");
                jmap_parser_invalid(parser, id);
                jmap_parser_pop(parser);
            }
        }
    }
    else if (JNOTNULL(delegatedFrom)) {
        jmap_parser_invalid(parser, "delegatedFrom");
    }

    /* memberOf */
    json_t *memberOf = json_object_get(jpart, "memberOf");
    if (json_object_size(memberOf)) {
        const char *id;
        json_t *jval;
        json_object_foreach(memberOf, id, jval) {
            json_t *group = json_object_get(participants, id);
            if (is_valid_jmapid(id) && group && jval == json_true()) {
                const char *uri = hash_lookup(id, caladdress_by_participant_id);
                if (uri) {
                    icalproperty_add_parameter(prop, icalparameter_new_member(uri));
                }
            }
            else {
                jmap_parser_push(parser, "memberOf");
                jmap_parser_invalid(parser, id);
                jmap_parser_pop(parser);
            }
        }
    }
    else if (JNOTNULL(memberOf)) {
        jmap_parser_invalid(parser, "memberOf");
    }

    /* linkIds */
    json_t *linkIds = json_object_get(jpart, "linkIds");
    if (json_object_size(linkIds)) {
        const char *id;
        json_t *jval;
        json_object_foreach(linkIds, id, jval) {
            if (!is_valid_jmapid(id) || !json_object_get(links, id) || jval != json_true()) {
                jmap_parser_push(parser, "linkIds");
                jmap_parser_invalid(parser, id);
                jmap_parser_pop(parser);
                continue;
            }
            set_icalxparam(prop, JMAPICAL_XPARAM_LINKID, id, 0);
        }
    }
    else if (JNOTNULL(linkIds)) {
        jmap_parser_invalid(parser, "linkIds");
    }

    /* scheduleSequence */
    json_t *scheduleSequence = json_object_get(jpart, "scheduleSequence");
    if (json_is_integer(scheduleSequence) && json_integer_value(scheduleSequence) >= 0) {
        struct buf buf = BUF_INITIALIZER;
        buf_printf(&buf, "%lld", json_integer_value(scheduleSequence));
        set_icalxparam(prop, JMAPICAL_XPARAM_SEQUENCE, buf_cstring(&buf), 0);
        buf_free(&buf);
    }
    else if (JNOTNULL(scheduleSequence)) {
        jmap_parser_invalid(parser, "scheduleSequence");
    }

    /* scheduleUpdated */
    json_t *scheduleUpdated = json_object_get(jpart, "scheduleUpdated");
    if (json_is_string(scheduleUpdated)) {
        const char *s = json_string_value(scheduleUpdated);
        icaltimetype dtstamp;
        if (utcdate_to_icaltime(s, &dtstamp)) {
            char *tmp = icaltime_as_ical_string_r(dtstamp);
            set_icalxparam(prop, JMAPICAL_XPARAM_DTSTAMP, tmp, 0);
            free(tmp);
        }
        else {
            jmap_parser_invalid(parser, "scheduleSequence");
        }
    }
    else if (JNOTNULL(scheduleUpdated)) {
        jmap_parser_invalid(parser, "scheduleSequence");
    }

    if (is_orga) {
        /* We might get away by not creating an ATTENDEE, if the
         * participant is owner of the event and all its JSCalendar
         * properties can be mapped to the ORGANIZER property. */
        json_t *jorga = participant_from_icalorganizer(orga);
        if (participant_equals(jorga, jpart)) {
            icalproperty_free(prop);
            prop = NULL;
        }
        json_decref(jorga);
        if (!prop) return;
    }

    icalcomponent_add_property(comp, prop);
}

/* Create or update the ORGANIZER and ATTENDEEs in the VEVENT component comp as
 * defined by the participants and replyTo property. */
static void
participants_to_ical(icalcomponent *comp, struct jmap_parser *parser, json_t *event)
{
    /* Purge existing ATTENDEEs and ORGANIZER */
    remove_icalprop(comp, ICAL_ATTENDEE_PROPERTY);
    remove_icalprop(comp, ICAL_ORGANIZER_PROPERTY);

    json_t *jval = NULL;
    const char *key = NULL;

    /* If participants are set, replyTo must be set */
    json_t *replyTo = json_object_get(event, "replyTo");
    if (JNOTNULL(replyTo) && !json_object_size(replyTo)) {
        jmap_parser_invalid(parser, "replyTo");
    }
    json_t *participants = json_object_get(event, "participants");
    if (JNOTNULL(participants) && !json_object_size(participants)) {
        jmap_parser_invalid(parser, "participants");
    }
    if (JNOTNULL(replyTo) != JNOTNULL(participants)) {
        jmap_parser_invalid(parser, "replyTo");
        jmap_parser_invalid(parser, "participants");
        return;
    }
    else if (!JNOTNULL(replyTo)) return;

    /* OK, there's both replyTo and participants set. */

    /* Parse replyTo */
    jmap_parser_push(parser, "replyTo");
    json_object_foreach(replyTo, key, jval) {
        if (!is_valid_rsvpmethod(key) || !json_is_string(jval)) {
            jmap_parser_invalid(parser, key);
            continue;
        }
    }
    jmap_parser_pop(parser);

    /* Map participant ids to their iCalendar CALADDRESS */
    hash_table caladdress_by_participant_id = HASH_TABLE_INITIALIZER;
    construct_hash_table(&caladdress_by_participant_id, json_object_size(participants)+1, 0);
    json_object_foreach(participants, key, jval) {
        if (!is_valid_jmapid(key)) continue;
        char *caladdress = NULL;
        json_t *sendTo = json_object_get(jval, "sendTo");
        if (json_object_get(sendTo, "imip")) {
            caladdress = xstrdup(json_string_value(json_object_get(sendTo, "imip")));
        }
        else if (json_object_get(sendTo, "other")) {
            caladdress = xstrdup(json_string_value(json_object_get(sendTo, "other")));
        }
        else if (json_object_size(sendTo)) {
            const char *anymethod = json_object_iter_key(json_object_iter(sendTo));
            caladdress = xstrdup(json_string_value(json_object_get(sendTo, anymethod)));
        }
        else if (json_object_get(jval, "email")) {
            caladdress = mailaddr_to_uri(json_string_value(json_object_get(jval, "email")));
        }
        if (!caladdress) continue; /* reported later as error */
        hash_insert(key, caladdress, &caladdress_by_participant_id);
    }

    /* Pick the ORGANIZER URI */
    const char *orga_method = NULL;
    if (json_object_get(replyTo, "imip")) {
        orga_method = "imip";
    }
    else if (json_object_get(replyTo, "other")) {
        orga_method = "other";
    }
    else {
        orga_method = json_object_iter_key(json_object_iter(replyTo));
    }
    const char *orga_uri = json_string_value(json_object_get(replyTo, orga_method));

    /* Create the ORGANIZER property */
    icalproperty *orga = icalproperty_new_organizer(orga_uri);
    /* Keep track of the RSVP URIs and their method */
    if (json_object_size(replyTo) > 1 || (strcmp(orga_method, "imip") && strcmp(orga_method, "other"))) {
        struct buf buf = BUF_INITIALIZER;
        json_object_foreach(replyTo, key, jval) {
            buf_setcstr(&buf, key);
            buf_putc(&buf, ':');
            buf_appendcstr(&buf, json_string_value(jval));
            set_icalxparam(orga, JMAPICAL_XPARAM_RSVP_URI, buf_cstring(&buf), 0);
        }
        buf_free(&buf);
    }
    icalcomponent_add_property(comp, orga);


    /* Process participants */
    jmap_parser_push(parser, "participants");
    json_t *links = json_object_get(event, "links");
    json_object_foreach(participants, key, jval) {
        jmap_parser_push(parser, key);
        if (!is_valid_jmapid(key)) {
            jmap_parser_invalid(parser, NULL);
            jmap_parser_pop(parser);
            continue;
        }

        const char *caladdress = hash_lookup(key, &caladdress_by_participant_id);
        if (!caladdress) {
            jmap_parser_invalid(parser, "sendTo");
            jmap_parser_invalid(parser, "email");
            jmap_parser_pop(parser);
            continue;
        }

        /* Map participant to iCalendar */
        participant_to_ical(comp, parser, key, jval, participants, links,
                            orga_uri, &caladdress_by_participant_id);
        jmap_parser_pop(parser);
    }
    jmap_parser_pop(parser);

    free_hash_table(&caladdress_by_participant_id, free);
}

static int is_valid_regrel(const char *rel)
{
    // RFC 8288, section 3.3, reg-rel-type:
    const char *p = rel;
    while ((('a' <= *p) && (*p <= 'z')) ||
           (('0' <= *p) && (*p <= '9')) ||
           ((*p == '.') && p > rel) ||
           ((*p == '-') && p > rel)) {
        p++;
    }
    return *p == '\0' && p > rel;
}

static void
links_to_ical(icalcomponent *comp, struct jmap_parser *parser, json_t *links)
{
    icalproperty *prop;
    struct buf buf = BUF_INITIALIZER;

    /* Purge existing attachments */
    remove_icalprop(comp, ICAL_ATTACH_PROPERTY);
    remove_icalprop(comp, ICAL_URL_PROPERTY);

    jmap_parser_push(parser, "links");

    const char *id;
    json_t *link;
    json_object_foreach(links, id, link) {
        const char *href = NULL;
        const char *type = NULL;
        const char *title = NULL;
        const char *rel = NULL;
        const char *cid = NULL;
        const char *display = NULL;
        json_int_t size = -1;
        json_t *jprop = NULL;

        jmap_parser_push(parser, id);
        if (!is_valid_jmapid(id)) {
            jmap_parser_invalid(parser, id);
            jmap_parser_pop(parser);
            continue;
        }

        /* href */
        href = json_string_value(json_object_get(link, "href"));
        if (!href || !strlen(href)) {
            jmap_parser_invalid(parser, "href");
            href = NULL;
        }

        /* type */
        jprop = json_object_get(link, "type");
        if (json_is_string(jprop)) {
            type = json_string_value(jprop);
        }
        else if (JNOTNULL(jprop)) {
            jmap_parser_invalid(parser, "type");
        }

        /* title */
        jprop = json_object_get(link, "title");
        if (json_is_string(jprop)) {
            title = json_string_value(jprop);
        }
        else if (JNOTNULL(jprop)) {
            jmap_parser_invalid(parser, "title");
        }

        /* cid */
        jprop = json_object_get(link, "cid");
        if (json_is_string(jprop)) {
            cid = json_string_value(jprop);
        }
        else if (JNOTNULL(jprop)) {
            jmap_parser_invalid(parser, "cid");
        }

        /* display */
        jprop = json_object_get(link, "display");
        if (json_is_string(jprop)) {
            display = json_string_value(jprop);
        }
        else if (JNOTNULL(jprop)) {
            jmap_parser_invalid(parser, "display");
        }

        /* rel */
        jprop = json_object_get(link, "rel");
        if (json_is_string(jprop)) {
            rel = json_string_value(jprop);
            if (!is_valid_regrel(rel)) {
                jmap_parser_invalid(parser, "rel");
            }
        }
        else if (JNOTNULL(jprop)) {
            jmap_parser_invalid(parser, "rel");
        }

        /* size */
        jprop = json_object_get(link, "size");
        if (json_is_integer(jprop)) {
            size = json_integer_value(jprop);
            if (size < 0) {
                jmap_parser_invalid(parser, "size");
            }
        } else if (JNOTNULL(jprop)) {
            jmap_parser_invalid(parser, "size");
        }

        jmap_parser_pop(parser);

        if (href && !json_array_size(parser->invalid)) {
            /* Build iCalendar property */
            if (!strcmpsafe(rel, "describedby") &&
                !icalcomponent_get_first_property(comp, ICAL_URL_PROPERTY) &&
                json_object_size(link) == 2) {

                prop = icalproperty_new(ICAL_URL_PROPERTY);
                icalproperty_set_value(prop, icalvalue_new_uri(href));
            }
            else {
                icalattach *icalatt = icalattach_new_from_url(href);
                prop = icalproperty_new_attach(icalatt);
                icalattach_unref(icalatt);
            }

            /* type */
            if (type) {
                icalproperty_add_parameter(prop,
                        icalparameter_new_fmttype(type));
            }

            /* title */
            if (title) {
                set_icalxparam(prop, JMAPICAL_XPARAM_TITLE, title, 1);
            }

            /* cid */
            if (cid) set_icalxparam(prop, JMAPICAL_XPARAM_CID, cid, 1);

            /* size */
            if (size >= 0) {
                buf_printf(&buf, "%"JSON_INTEGER_FORMAT, size);
                icalproperty_add_parameter(prop,
                        icalparameter_new_size(buf_cstring(&buf)));
                buf_reset(&buf);
            }

            /* rel */
            if (rel && strcmp(rel, "enclosure"))
                set_icalxparam(prop, JMAPICAL_XPARAM_REL, rel, 1);

            /* Set custom id */
            set_icalxparam(prop, JMAPICAL_XPARAM_ID, id, 1);

            /* display */
            if (display) set_icalxparam(prop, JMAPICAL_XPARAM_DISPLAY, display, 1);

            /* Add ATTACH property. */
            icalcomponent_add_property(comp, prop);
        }
        buf_free(&buf);
    }

    jmap_parser_pop(parser);
}

static void
description_to_ical(icalcomponent *comp, struct jmap_parser *parser, json_t *jsevent)
{
    remove_icalprop(comp, ICAL_DESCRIPTION_PROPERTY);

    const char *desc = NULL;

    json_t *jprop = json_object_get(jsevent, "description");
    if (json_is_string(jprop)) {
        desc = json_string_value(jprop);
    }
    else if JNOTNULL(jprop) {
        jmap_parser_invalid(parser, "description");
    }

    jprop = json_object_get(jsevent, "descriptionContentType");
    if (json_is_string(jprop)) {
        const char *content_type = json_string_value(jprop);
        /* FIXME
         * We'd like to support HTML descriptions, but with iCalendar being
         * our storage format there really isn't a good way to deal with
         * that. We can't rely on iCalendar clients correctly handling the
         * ALTREP parameters on DESCRIPTION, and we don't want to make the
         * CalDAV PUT code deal with comparing old vs new descriptions to
         * try figuring out what the client did.
         * This should become more sane to handle if we start using
         * JSCalendar for storage.
         */
        if (content_type && strcasecmp(content_type, "TEXT/PLAIN")) {
            jmap_parser_invalid(parser, "descriptionContentType");
        }
    }
    else if JNOTNULL(jprop) {
        jmap_parser_invalid(parser, "descriptionContentType");
    }

    if (desc) icalcomponent_set_description(comp, desc);
}

/* Create or update the VALARMs in the VEVENT component comp as defined by the
 * JMAP alerts. */
static void
alerts_to_ical(icalcomponent *comp, struct jmap_parser *parser, json_t *alerts)
{
    icalcomponent *alarm, *next;

    /* Purge all VALARMs. */
    for (alarm = icalcomponent_get_first_component(comp, ICAL_VALARM_COMPONENT);
         alarm;
         alarm = next) {
        next = icalcomponent_get_next_component(comp, ICAL_VALARM_COMPONENT);
        icalcomponent_remove_component(comp, alarm);
        icalcomponent_free(alarm);
    }

    if (!JNOTNULL(alerts)) {
        return;
    }

    const char *id;
    json_t *alert;
    jmap_parser_push(parser, "alerts");
    json_object_foreach(alerts, id, alert) {
        icalproperty *prop;
        icalparameter *param;

        if (!is_valid_jmapid(id)) {
            jmap_parser_invalid(parser, id);
            continue;
        }

        alarm = icalcomponent_new_valarm();
        icalcomponent_set_uid(alarm, id);

        /* offset */
        struct icaltriggertype trigger = {
            icaltime_null_time(), icaldurationtype_null_duration()
        };
        json_t *jprop = json_object_get(alert, "offset");
        if (json_is_string(jprop)) {
            const char *val = json_string_value(jprop);
            trigger.duration = icaldurationtype_from_string(val);
            if (icaldurationtype_is_bad_duration(trigger.duration)) {
                jmap_parser_invalid(parser, "offset");
            }
        } else {
            jmap_parser_invalid(parser, "offset");
        }

        /* relativeTo */
        icalparameter_related rel = ICAL_RELATED_START;
        trigger.duration.is_neg = 1;
        jprop = json_object_get(alert, "relativeTo");
        if (json_is_string(jprop)) {
            const char *val = json_string_value(jprop);
            if (!strcmp(val, "before-start")) {
                rel = ICAL_RELATED_START;
            } else if (!strcmp(val, "after-start")) {
                rel = ICAL_RELATED_START;
                trigger.duration.is_neg = 0;
            } else if (!strcmp(val, "before-end")) {
                rel = ICAL_RELATED_END;
            } else if (!strcmp(val, "after-end")) {
                rel = ICAL_RELATED_END;
                trigger.duration.is_neg = 0;
            } else {
                jmap_parser_invalid(parser, "relativeTo");
            }
        } else if (JNOTNULL(jprop)) {
            jmap_parser_invalid(parser, "relativeTo");
        }

        /* Add TRIGGER */
        prop = icalproperty_new_trigger(trigger);
        param = icalparameter_new_related(rel);
        icalproperty_add_parameter(prop, param);
        icalcomponent_add_property(alarm, prop);

        /* snoozed */
        jprop = json_object_get(alert, "snoozed");
        if (json_is_string(jprop)) {
            const char *val = json_string_value(jprop);
            struct icaltriggertype snooze_trigger = {
                icaltime_null_time(), icaldurationtype_null_duration()
            };
            if (utcdate_to_icaltime(val, &snooze_trigger.time)) {
                icalcomponent *snooze = icalcomponent_new_valarm();

                /* Add RELATED-TO */
                remove_icalprop(snooze, ICAL_UID_PROPERTY);
                prop = icalproperty_new_relatedto(id);
                param = icalparameter_new(ICAL_RELTYPE_PARAMETER);
                icalparameter_set_xvalue(param, "SNOOZE");
                icalproperty_add_parameter(prop, param);
                icalcomponent_add_property(snooze, prop);

                /* Add TRIGGER */
                prop = icalproperty_new_trigger(snooze_trigger);
                icalcomponent_add_property(snooze, prop);
                icalcomponent_add_component(comp, snooze);
            } else {
                jmap_parser_invalid(parser, "snoozed");
            }
        } else if (JNOTNULL(jprop)) {
            jmap_parser_invalid(parser, "snoozed");
        }

        /* acknowledged */
        jprop = json_object_get(alert, "acknowledged");
        if (json_is_string(jprop)) {
            const char *val = json_string_value(jprop);
            icaltimetype t;
            if (utcdate_to_icaltime(val, &t)) {
                prop = icalproperty_new_acknowledged(t);
                icalcomponent_add_property(alarm, prop);
            } else {
                jmap_parser_invalid(parser, "acknowledged");
            }
        } else if (JNOTNULL(jprop)) {
            jmap_parser_invalid(parser, "acknowledged");
        }


        /* action */
        icalproperty_action action = ICAL_ACTION_DISPLAY;
        jprop = json_object_get(alert, "action");
        if (json_is_string(jprop)) {
            const char *val = json_string_value(jprop);
            if (!strcmp(val, "email")) {
                action = ICAL_ACTION_EMAIL;
            } else if (!strcmp(val, "display")) {
                action = ICAL_ACTION_DISPLAY;
            } else {
                jmap_parser_invalid(parser, "action");
            }
        } else if (JNOTNULL(jprop)) {
            jmap_parser_invalid(parser, "action");
        }
        prop = icalproperty_new_action(action);
        icalcomponent_add_property(alarm, prop);

        if (action == ICAL_ACTION_EMAIL) {
            /* ATTENDEE */
            const char *annotname = DAV_ANNOT_NS "<" XML_NS_CALDAV ">calendar-user-address-set";
            char *mailboxname = caldav_mboxname(httpd_userid, NULL);
            struct buf buf = BUF_INITIALIZER;
            int r = annotatemore_lookupmask(mailboxname, annotname, httpd_userid, &buf);

            char *recipient = NULL;
            if (!r && buf.len > 7 && !strncasecmp(buf_cstring(&buf), "mailto:", 7)) {
                recipient = buf_release(&buf);
            } else {
                recipient = strconcat("mailto:", httpd_userid, NULL);
            }
            icalcomponent_add_property(alarm, icalproperty_new_attendee(recipient));
            free(recipient);

            buf_free(&buf);
            free(mailboxname);

            /* SUMMARY */
            const char *summary = icalcomponent_get_summary(comp);
            if (!summary) summary = "Your event alert";
            icalcomponent_add_property(alarm, icalproperty_new_summary(summary));
        }

        /* DESCRIPTION is required for both email and display */
        const char *description = icalcomponent_get_description(comp);
        if (!description) description = "";
        icalcomponent_add_property(alarm, icalproperty_new_description(description));

        icalcomponent_add_component(comp, alarm);
    }
    jmap_parser_pop(parser);

}

/* Convert and print the JMAP byX recurrence value to ical into buf, otherwise
 * report the erroneous fieldName as invalid. If lower or upper is not NULL,
 * make sure that every byX value is within these bounds. */
static void recurrence_byX_to_ical(json_t *rrule,
                                   struct jmap_parser *parser,
                                   const char *fieldName,
                                   struct buf *icalbuf,
                                   const char *tag,
                                   int lower,
                                   int upper,
                                   int allow_zero)
{
    json_t *byX = json_object_get(rrule, fieldName);
    if (!json_array_size(byX)) {
        if (JNOTNULL(byX) && !json_is_array(byX)) {
            jmap_parser_invalid(parser, fieldName);
        }
        return;
    }

    /* Convert the array. */
    buf_printf(icalbuf, ";%s=", tag);
    size_t i;
    for (i = 0; i < json_array_size(byX); i++) {
        int val;
        int err = json_unpack(json_array_get(byX, i), "i", &val);
        if (!err && !allow_zero && !val) {
            err = 1;
        }
        if (!err && ((lower != INT_MIN && val < lower) || (upper != INT_MAX && val > upper))) {
            err = 2;
        }
        if (err) {
            jmap_parser_push_index(parser, fieldName, i, NULL);
            jmap_parser_invalid(parser, NULL);
            jmap_parser_pop(parser);
            continue;
        }
        /* Convert the byX value to ical. */
        if (i) buf_printf(icalbuf, "%c", ',');
        buf_printf(icalbuf, "%d", val);
    }
}

/* Create or overwrite the RRULE in the VEVENT component comp as defined by the
 * JMAP recurrence. */
static void
recurrence_to_ical(icalcomponent *comp, struct jmap_parser *parser, json_t *rrule)
{
    struct buf buf = BUF_INITIALIZER;

    /* Purge existing RRULE. */
    icalproperty *prop, *next;
    for (prop = icalcomponent_get_first_property(comp, ICAL_RRULE_PROPERTY);
         prop;
         prop = next) {
        next = icalcomponent_get_next_property(comp, ICAL_RRULE_PROPERTY);
        icalcomponent_remove_property(comp, prop);
        icalproperty_free(prop);
    }
    if (!JNOTNULL(rrule)) {
        return;
    }

    jmap_parser_push(parser, "recurrenceRule");

    /* frequency */
    const char *freq = NULL;
    json_t *jprop = json_object_get(rrule, "frequency");
    if (json_is_string(jprop)) {
        const char *val = json_string_value(jprop);
        if (!strcasecmp(val, "yearly") ||
            !strcasecmp(val, "monthly") ||
            !strcasecmp(val, "weekly") ||
            !strcasecmp(val, "daily") ||
            !strcasecmp(val, "hourly") ||
            !strcasecmp(val, "minutely") ||
            !strcasecmp(val, "secondly")) {
            freq = val;
        }
    }
    if (freq) {
        buf_printf(&buf, "FREQ=%s", freq);
    } else {
        jmap_parser_invalid(parser, "frequency");
    }

    /* interval */
    int interval = 1;
    jprop = json_object_get(rrule, "interval");
    if (json_is_integer(jprop)) {
        interval = json_integer_value(jprop);
        if (interval > 1) {
            buf_printf(&buf, ";INTERVAL=%d", interval);
        } else if (interval < 1) {
            jmap_parser_invalid(parser, "interval");
        }
    }

    /* skip */
    char *skip = NULL;
    jprop = json_object_get(rrule, "skip");
    if (json_is_string(jprop)) {
        skip = xstrdup(json_string_value(jprop));
        ucase(skip);
    } else if (JNOTNULL(jprop)) {
        jmap_parser_invalid(parser, "skip");
    }

    /* rscale */
    jprop = json_object_get(rrule, "rscale");
    if (json_is_string(jprop)) {
        char *rscale = xstrdup(json_string_value(jprop));
        ucase(rscale);
        if (strcmp(rscale, "GREGORIAN") || (skip && strcmp(skip, "OMIT"))) {
            buf_printf(&buf, ";RSCALE=%s", rscale);
            if (skip) buf_printf(&buf, ";SKIP=%s", skip);
        }
        free(rscale);
    } else if (JNOTNULL(jprop)) {
        jmap_parser_invalid(parser, "rscale");
    }
    free(skip);

    /* firstDayOfWeek */
    jprop = json_object_get(rrule, "firstDayOfWeek");
    if (json_is_string(jprop)) {
        char *day = xstrdup(json_string_value(jprop));
        ucase(day);
        if (icalrecur_string_to_weekday(day) != ICAL_NO_WEEKDAY) {
            buf_printf(&buf, ";WKST=%s", day);
        } else {
            jmap_parser_invalid(parser, "firstDayOfWeek");
        }
        free(day);
    } else if (JNOTNULL(jprop)) {
        jmap_parser_invalid(parser, "firstDayOfWeek");
    }

    /* byDay */
    json_t *byday = json_object_get(rrule, "byDay");
    if (json_array_size(byday) > 0) {
        size_t i;
        json_t *bd;

        jmap_parser_push(parser, "byDay");
        buf_appendcstr(&buf, ";BYDAY=");
        json_array_foreach(byday, i, bd) {
            char *day = NULL;
            json_int_t nth = 0;
            jmap_parser_push_index(parser, "byDay", i, NULL);

            /* day */
            day = xstrdupnull(json_string_value(json_object_get(bd, "day")));
            if (day) {
                ucase(day);
                if (icalrecur_string_to_weekday(day) == ICAL_NO_WEEKDAY) {
                    free(day);
                    day = NULL;
                }
            }
            if (!day) jmap_parser_invalid(parser, "day");

            /* nthOfPeriod */
            json_t *jnth = json_object_get(bd, "nthOfPeriod");
            if (json_is_integer(jnth)) {
                nth = json_integer_value(jnth);
            }
            else if (JNOTNULL(jnth)) {
                jmap_parser_invalid(parser, "nthOfPeriod");
            }

            /* Append day */
            if (!json_array_size(parser->invalid)) {
                if (i > 0) buf_appendcstr(&buf, ",");
                if (nth) buf_printf(&buf, "%+"JSON_INTEGER_FORMAT, nth);
                buf_appendcstr(&buf, day);
            }

            free(day);
            jmap_parser_pop(parser);
        }
    } else if (byday) {
        jmap_parser_invalid(parser, "byDay");
    }

    /* byMonth */
    json_t *bymonth = json_object_get(rrule, "byMonth");
    if (json_is_array(bymonth)) {
        size_t i;
        json_t *jval;
        buf_printf(&buf, ";BYMONTH=");
        json_array_foreach(bymonth, i, jval) {
            const char *s = json_string_value(jval);
            jmap_parser_push_index(parser, "byMonth", i, NULL);
            if (!s) {
                jmap_parser_invalid(parser, NULL);
                jmap_parser_pop(parser);
                continue;
            }
            int val;
            char leap = 0, dummy = 0;
            int matched = sscanf(s, "%2d%c%c", &val, &leap, &dummy);
            if (matched < 1 || matched > 2 || (leap && leap != 'L') || val < 1) {
                jmap_parser_invalid(parser, NULL);
                jmap_parser_pop(parser);
                continue;
            }
            if (i) buf_putc(&buf, ',');
            buf_printf(&buf, "%d", val);
            if (leap) buf_putc(&buf, 'L');
            jmap_parser_pop(parser);
        }
    }
    else if (JNOTNULL(bymonth)) {
        jmap_parser_invalid(parser, "byMonth");
    }

    /* byYearDay */
    recurrence_byX_to_ical(rrule, parser, "byYearDay", &buf, "BYYEARDAY", -366, 366, 0);
    /* byWeekNo */
    recurrence_byX_to_ical(rrule, parser, "byWeekNo", &buf, "BYWEEKNO", -53, 53, 0);
    /* byMonthDay */
    recurrence_byX_to_ical(rrule, parser, "byMonthDay", &buf, "BYMONTHDAY", -31, 31, 0);
    /* byHour */
    recurrence_byX_to_ical(rrule, parser, "byHour", &buf, "BYHOUR", 0, 23, 1);
    /* byMinute */
    recurrence_byX_to_ical(rrule, parser, "byMinute", &buf, "BYMINUTE", 0, 59, 1);
    /* bySecond */
    recurrence_byX_to_ical(rrule, parser, "bySecond", &buf, "BYSECOND", 0, 59, 1);
    /* bySetPosition */
    recurrence_byX_to_ical(rrule, parser, "bySetPosition", &buf,"BYSETPOS", INT_MIN, INT_MAX, 1);

    if (json_object_get(rrule, "count") && json_object_get(rrule, "until")) {
        jmap_parser_invalid(parser, "count");
        jmap_parser_invalid(parser, "until");
    }

    /* count */
    jprop = json_object_get(rrule, "count");
    if (json_is_integer(jprop)) {
        int count = json_integer_value(jprop);
        if (count > 0 && !json_object_get(rrule, "until")) {
            buf_printf(&buf, ";COUNT=%d", count);
        } else {
            jmap_parser_invalid(parser, "count");
        }
    } else if (JNOTNULL(jprop)) {
        jmap_parser_invalid(parser, "count");
    }

    /* until */
    jprop = json_object_get(rrule, "until");
    const char *until = json_string_value(jprop);
    if (until) {
        icaltimetype dtloc;
        int is_allday = icalcomponent_get_dtstart(comp).is_date;
        icaltimezone *tzstart = tz_from_tzid(tzid_from_ical(comp, ICAL_DTSTART_PROPERTY));
        struct tm tm;
        if (localdate_to_tm(until, &tm)) {
            if (is_allday) {
                tm.tm_hour = 0;
                tm.tm_min = 0;
                tm.tm_sec = 0;
            }
            if (tm_to_icaltime(tm, tzstart, is_allday, &dtloc)) {
                icaltimezone *utc = icaltimezone_get_utc_timezone();
                icaltimetype dt = icaltime_convert_to_zone(dtloc, utc);
                buf_printf(&buf, ";UNTIL=%s", icaltime_as_ical_string(dt));
            } else {
                jmap_parser_invalid(parser, "until");
            }
        } else {
            jmap_parser_invalid(parser, "until");
        }
    } else if (JNOTNULL(jprop)) {
        jmap_parser_invalid(parser, "until");
    }

    if (!json_array_size(parser->invalid)) {
        /* Add RRULE to component */
        struct icalrecurrencetype rt =
            icalrecurrencetype_from_string(buf_ucase(&buf));
        if (rt.freq != ICAL_NO_RECURRENCE) {
            icalcomponent_add_property(comp, icalproperty_new_rrule(rt));
        } else {
            syslog(LOG_ERR, "jmap_ical: generated bogus RRULE: %s", buf_cstring(&buf));
            jmap_parser_invalid(parser, NULL);
        }
    }

    jmap_parser_pop(parser);
    buf_free(&buf);
}

/* Create or overwrite JMAP keywords in comp */
static void
keywords_to_ical(icalcomponent *comp, struct jmap_parser *parser, json_t *keywords)
{
    icalproperty *prop, *next;

    /* Purge existing keywords from component */
    for (prop = icalcomponent_get_first_property(comp, ICAL_CATEGORIES_PROPERTY);
         prop;
         prop = next) {

        next = icalcomponent_get_next_property(comp, ICAL_CATEGORIES_PROPERTY);
        icalcomponent_remove_property(comp, prop);
        icalproperty_free(prop);
    }

    /* Add keywords */
    json_t *jval;
    const char *keyword;
    json_object_foreach(keywords, keyword, jval) {
        if (jval != json_true()) {
            jmap_parser_push(parser, "keywords");
            jmap_parser_invalid(parser, keyword);
            jmap_parser_pop(parser);
            continue;
        }
        // FIXME known bug: libical doesn't properly
        // handle multi-values separated by comma,
        // if a single entry contains a comma.
        prop = icalproperty_new_categories(keyword);
        icalcomponent_add_property(comp, prop);
    }
}

/* Create or overwrite JMAP relatedTo in comp */
static void
relatedto_to_ical(icalcomponent *comp, struct jmap_parser *parser, json_t *relatedTo)
{
    icalproperty *prop, *next;
    icalparameter *param;

    /* Purge existing relatedTo properties from component */
    for (prop = icalcomponent_get_first_property(comp, ICAL_RELATEDTO_PROPERTY);
         prop;
         prop = next) {

        next = icalcomponent_get_next_property(comp, ICAL_RELATEDTO_PROPERTY);
        icalcomponent_remove_property(comp, prop);
        icalproperty_free(prop);
    }
    if (relatedTo == NULL || relatedTo == json_null()) return;

    /* Add relatedTo */
    const char *uid = NULL;
    json_t *relationObj = NULL;
    jmap_parser_push(parser, "relatedTo");
    json_object_foreach(relatedTo, uid, relationObj) {
        jmap_parser_push(parser, uid);
        json_t *relation = json_object_get(relationObj, "relation");
        if (json_object_size(relation)) {
            prop = icalproperty_new_relatedto(uid);
            json_t *jval;
            const char *reltype;
            jmap_parser_push(parser, "relation");
            json_object_foreach(relation, reltype, jval) {
                if (jval == json_true()) {
                    char *s = ucase(xstrdup(reltype));
                    param = icalparameter_new(ICAL_RELTYPE_PARAMETER);
                    icalparameter_set_xvalue(param, s);
                    icalproperty_add_parameter(prop, param);
                    free(s);
                }
                else {
                    jmap_parser_invalid(parser, reltype);
                }
            }
            icalcomponent_add_property(comp, prop);
            jmap_parser_pop(parser);
        }
        else if (relation == NULL || relation == json_null()) {
            icalcomponent_add_property(comp, icalproperty_new_relatedto(uid));
        }
        else if (!json_is_object(relation)) {
            jmap_parser_invalid(parser, "relation");
        }
        else if (!json_object_size(relationObj)) {
            jmap_parser_invalid(parser, NULL);
        }
        jmap_parser_pop(parser);
    }
    jmap_parser_pop(parser);
}

static int
validate_location(json_t *loc, struct jmap_parser *parser, json_t *links)
{
    size_t invalid_cnt = json_array_size(parser->invalid);
    json_t *jprop = NULL;

    /* At least one property other than rel MUST be set */
    if (json_object_size(loc) == 0 ||
        (json_object_size(loc) == 1 && json_object_get(loc, "rel"))) {
        jmap_parser_invalid(parser, NULL);
        return 0;
    }

    jprop = json_object_get(loc, "name");
    if (JNOTNULL(jprop) && !json_is_string(jprop))
        jmap_parser_invalid(parser, "name");

    jprop = json_object_get(loc, "description");
    if (JNOTNULL(jprop) && !json_is_string(jprop))
        jmap_parser_invalid(parser, "description");

    jprop = json_object_get(loc, "rel");
    if (JNOTNULL(jprop) && !json_is_string(jprop))
        jmap_parser_invalid(parser, "rel");

    jprop = json_object_get(loc, "coordinates");
    if (JNOTNULL(jprop) && !json_is_string(jprop))
        jmap_parser_invalid(parser, "coordinates");

    jprop = json_object_get(loc, "timeZone");
    if (json_is_string(jprop)) {
        if (!tz_from_tzid(json_string_value(jprop)))
            jmap_parser_invalid(parser, "timeZone");
    }
    else if (JNOTNULL(jprop)) {
        jmap_parser_invalid(parser, "timeZone");
    }

    /* linkIds */
    const char *id;
    json_t *jval;
    json_t *linkids = json_object_get(loc, "linkIds");
    if (JNOTNULL(linkids) && json_is_object(linkids)) {
        jmap_parser_push(parser, "linkIds");
        json_object_foreach(linkids, id, jval) {
            if (!is_valid_jmapid(id) || !json_object_get(links, id) || jval != json_true()) {
                jmap_parser_invalid(parser, id);
            }
        }
        jmap_parser_pop(parser);
    }
    else if (JNOTNULL(linkids)) {
        jmap_parser_invalid(parser, "linkIds");
    }

    /* Location is valid, if no invalid property has been added */
    return json_array_size(parser->invalid) == invalid_cnt;
}

static void
location_to_ical(icalcomponent *comp, const char *id, json_t *loc)
{
    const char *name = json_string_value(json_object_get(loc, "name"));
    const char *rel = json_string_value(json_object_get(loc, "rel"));

    /* Gracefully handle bogus values */
    if (rel && !strcmp(rel, "unknown")) rel = NULL;

    /* Determine which property kind to use for this location.
     * Always try to create at least one LOCATION, even if CONFERENCE
     * would be more appropriate, to gracefully handle legacy clients. */
    icalproperty *prop;
    if (!icalcomponent_get_first_property(comp, ICAL_LOCATION_PROPERTY)) {
        prop = icalproperty_new(ICAL_LOCATION_PROPERTY);
    } else {
        prop = icalproperty_new(ICAL_X_PROPERTY);
        icalproperty_set_x_name(prop, JMAPICAL_XPROP_LOCATION);
    }

    /* Keep user-supplied location id */
    xjmapid_to_ical(prop, id);

    /* name, rel */
    icalvalue *val = icalvalue_new_from_string(ICAL_TEXT_VALUE, name);
    icalproperty_set_value(prop, val);
    if (rel) set_icalxparam(prop, JMAPICAL_XPARAM_REL, rel, 0);

    /* description, timeZone, coordinates */
    const char *s = json_string_value(json_object_get(loc, "description"));
    if (s) set_icalxparam(prop, JMAPICAL_XPARAM_DESCRIPTION, s, 0);
    s = json_string_value(json_object_get(loc, "timeZone"));
    if (s) set_icalxparam(prop, JMAPICAL_XPARAM_TZID, s, 0);
    s = json_string_value(json_object_get(loc, "coordinates"));
    if (s) set_icalxparam(prop, JMAPICAL_XPARAM_GEO, s, 0);

    /* linkIds */
    json_t *jval;
    const char *key;
    json_object_foreach(json_object_get(loc, "linkIds"), key, jval) {
        set_icalxparam(prop, JMAPICAL_XPARAM_LINKID, key, 0);
    }

    icalcomponent_add_property(comp, prop);
}

/* Create or overwrite the JMAP locations in comp */
static void
locations_to_ical(icalcomponent *comp, struct jmap_parser *parser, json_t *locations, json_t *links)
{
    json_t *loc;
    const char *id;

    /* Purge existing locations */
    remove_icalprop(comp, ICAL_LOCATION_PROPERTY);
    remove_icalprop(comp, ICAL_GEO_PROPERTY);
    remove_icalxprop(comp, JMAPICAL_XPROP_LOCATION);
    remove_icalxprop(comp, "X-APPLE-STRUCTURED-LOCATION");

    /* Bail out if no location needs to be set */
    if (!JNOTNULL(locations)) {
        return;
    }

    /* Add locations */
    jmap_parser_push(parser, "locations");
    json_object_foreach(locations, id, loc) {
        /* Validate the location id */
        if (!is_valid_jmapid(id)) {
            jmap_parser_invalid(parser, id);
            continue;
        }
        /* Ignore end timeZone locations */
        if (location_is_endtimezone(loc)) {
            continue;
        }
        jmap_parser_push(parser, id);
        /* Validate and add location */
        if (validate_location(loc, parser, links)) {
            location_to_ical(comp, id, loc);
        }
        jmap_parser_pop(parser);
    }
    jmap_parser_pop(parser);
}

/* Create or overwrite the JMAP virtualLocations in comp */
static void
virtuallocations_to_ical(icalcomponent *comp, struct jmap_parser *parser, json_t *locations)
{
    json_t *loc;
    const char *id;

    remove_icalprop(comp, ICAL_CONFERENCE_PROPERTY);
    if (!JNOTNULL(locations)) {
        return;
    }

    jmap_parser_push(parser, "virtualLocations");
    json_object_foreach(locations, id, loc) {
        /* Validate the location id */
        if (!is_valid_jmapid(id)) {
            jmap_parser_invalid(parser, id);
            continue;
        }

        jmap_parser_push(parser, id);

        icalproperty *prop = icalproperty_new(ICAL_CONFERENCE_PROPERTY);
        xjmapid_to_ical(prop, id);

        /* uri */
        json_t *juri = json_object_get(loc, "uri");
        if (json_is_string(juri)) {
            const char *uri = json_string_value(juri);
            icalvalue *val = icalvalue_new_from_string(ICAL_URI_VALUE, uri);
            icalproperty_set_value(prop, val);
        }
        else {
            jmap_parser_invalid(parser, "uri");
        }

        /* name */
        json_t *jname = json_object_get(loc, "name");
        if (json_is_string(juri)) {
            const char *name = json_string_value(jname);
            icalproperty_add_parameter(prop, icalparameter_new_label(name));
        }
        else {
            jmap_parser_invalid(parser, "uri");
        }


        /* description */
        json_t *jdescription = json_object_get(loc, "description");
        if (json_is_string(jdescription)) {
            const char *desc = json_string_value(jdescription);
            set_icalxparam(prop, JMAPICAL_XPARAM_DESCRIPTION, desc, 0);
        }
        else if (JNOTNULL(jdescription)) {
            jmap_parser_invalid(parser, "description");
        }

        icalcomponent_add_property(comp, prop);
        jmap_parser_pop(parser);
    }
    jmap_parser_pop(parser);
}

static void set_language_icalprop(icalcomponent *comp, icalproperty_kind kind,
                                  const char *lang)
{
    icalproperty *prop;
    icalparameter *param;

    prop = icalcomponent_get_first_property(comp, kind);
    if (!prop) return;

    icalproperty_remove_parameter_by_kind(prop, ICAL_LANGUAGE_PARAMETER);
    if (!lang) return;

    param = icalparameter_new(ICAL_LANGUAGE_PARAMETER);
    icalparameter_set_language(param, lang);
    icalproperty_add_parameter(prop, param);
}

static void
overrides_to_ical(icalcomponent *comp, struct jmap_parser *parser, json_t *overrides)
{
    json_t *override, *master;
    const char *id;
    icalcomponent *excomp, *next, *ical;

    /* Purge EXDATE, RDATE */
    remove_icalprop(comp, ICAL_RDATE_PROPERTY);
    remove_icalprop(comp, ICAL_EXDATE_PROPERTY);

    /* Remove existing VEVENT exceptions */
    ical = icalcomponent_get_parent(comp);
    for (excomp = icalcomponent_get_first_component(ical, ICAL_VEVENT_COMPONENT);
         excomp;
         excomp = next) {

        next = icalcomponent_get_next_component(ical, ICAL_VEVENT_COMPONENT);
        if (excomp == comp) continue;
        icalcomponent_remove_component(ical, excomp);
    }

    if (json_is_null(overrides)) return;

    /* Determine value type of main event DTSTART */
    int is_date = icalcomponent_get_dtstart(comp).is_date;
    icaltimezone *tzstart = tz_from_tzid(tzid_from_ical(comp, ICAL_DTSTART_PROPERTY));

    /* Convert current master event to JMAP */
    master = calendarevent_from_ical(comp, NULL, NULL);
    if (!master) return;
    json_object_del(master, "recurrenceRule");
    json_object_del(master, "recurrenceOverrides");

    jmap_parser_push(parser, "recurrenceOverrides");
    json_object_foreach(overrides, id, override) {
        icaltimetype start = icaltime_null_time();

        if (!localdate_to_icaltime(id, tzstart, is_date, &start)) {
            jmap_parser_invalid(parser, id);
            continue;
        }

        json_t *excluded = json_object_get(override, "excluded");
        if (excluded) {
            if (json_object_size(override) == 1 && excluded == json_true()) {
                /* Add EXDATE */
                dtprop_to_ical(comp, start, 0, ICAL_EXDATE_PROPERTY);
            }
            else {
                jmap_parser_invalid(parser, id);
                continue;
            }
        } else if (!json_object_size(override)) {
            /* Add RDATE */
            dtprop_to_ical(comp, start, 0, ICAL_RDATE_PROPERTY);
        } else {
            /* Add VEVENT exception */
            json_t *ex, *val;
            const char *key;
            int ignore = 0;

            /* JMAP spec: "A pointer MUST NOT start with one of the following
             * prefixes; any patch with a such a key MUST be ignored" */
            json_object_foreach(override, key, val) {
                if (!strcmp(key, "uid") ||
                    !strcmp(key, "relatedTo") ||
                    !strcmp(key, "prodId") ||
                    !strcmp(key, "isAllDay") ||
                    !strcmp(key, "recurrenceRule") ||
                    !strcmp(key, "recurrenceOverrides") ||
                    !strcmp(key, "replyTo") ||
                    !strcmp(key, "participantId")) {

                    ignore = 1;
                }
            }
            if (ignore)
                continue;

            /* If the override doesn't have a custom start date, use
             * the LocalDate in the recurrenceOverrides object key */
            if (!json_object_get(override, "start")) {
                json_object_set_new(override, "start", json_string(id));
            }

            /* Create overridden event from patch and master event */
            if (!(ex = jmap_patchobject_apply(master, override))) {
                jmap_parser_invalid(parser, id);
                continue;
            }

            /* Create a new VEVENT for this override */
            excomp = icalcomponent_new_vevent();
            dtprop_to_ical(excomp, start, 1, ICAL_RECURRENCEID_PROPERTY);
            icalcomponent_set_uid(excomp, icalcomponent_get_uid(comp));

            /* Convert the override event to iCalendar */
            jmap_parser_push(parser, id);
            calendarevent_to_ical(excomp, parser, ex);
            jmap_parser_pop(parser);

            /* Add the exception */
            icalcomponent_add_component(ical, excomp);
            json_decref(ex);
        }
    }
    jmap_parser_pop(parser);

    json_decref(master);
}

/* Create or overwrite the iCalendar properties in VEVENT comp based on the
 * properties the JMAP calendar event. This writes a *complete* jsevent and
 * does not implement patch object semantics.
 */
static void
calendarevent_to_ical(icalcomponent *comp, struct jmap_parser *parser, json_t *event)
{
    icalproperty *prop = NULL;
    int is_exc = icalcomponent_get_first_property(comp, ICAL_RECURRENCEID_PROPERTY) != NULL;

    /* Do not preserve any current contents */
    json_incref(event);

    json_t *jprop = json_object_get(event, "excluded");
    if (jprop && jprop != json_false()) {
        jmap_parser_invalid(parser, "excluded");
    }

    /* uid */
    const char *uid = json_string_value(json_object_get(event, "uid"));
    if (uid) icalcomponent_set_uid(comp, uid);
    else jmap_parser_invalid(parser, "uid");

    jprop = json_object_get(event, "@type");
    if (JNOTNULL(jprop) && json_is_string(jprop)) {
        if (strcmp(json_string_value(jprop), "jsevent")) {
            jmap_parser_invalid(parser, "@type");
        }
    } else if (JNOTNULL(jprop)) {
        jmap_parser_invalid(parser, "@type");
    }

    /* start, duration, timeZone */
    startend_to_ical(comp, parser, event);

    /* relatedTo */
    jprop = json_object_get(event, "relatedTo");
    if (json_is_null(jprop) || json_object_size(jprop)) {
        relatedto_to_ical(comp, parser, jprop);
    } else if (jprop) {
        jmap_parser_invalid(parser, "relatedTo");
    }

    /* sequence */
    jprop = json_object_get(event, "sequence");
    if (json_is_integer(jprop)) {
        json_int_t val = json_integer_value(jprop);
        if (val >= 0 && val <= INT_MAX) {
            icalcomponent_set_sequence(comp, (int)val);
        }
        else jmap_parser_invalid(parser, "sequence");
    } else if (jprop) {
        jmap_parser_invalid(parser, "sequence");
    }

    /* prodId */
    if (!is_exc) {
        struct buf buf = BUF_INITIALIZER;
        const char *prod_id = NULL;

        jprop = json_object_get(event, "prodId");
        if (json_is_string(jprop)) {
            prod_id = json_string_value(jprop);
        }
        else if (JNOTNULL(jprop)) {
            jmap_parser_invalid(parser, "prodId");
        }

        if (!prod_id) {
            /* Use same product id like jcal.c */
            buf_setcstr(&buf, "-//CyrusIMAP.org/Cyrus ");
            buf_appendcstr(&buf, CYRUS_VERSION);
            buf_appendcstr(&buf, "//EN");
            prod_id = buf_cstring(&buf);
        }
        /* Set PRODID in the VCALENDAR */
        icalcomponent *ical = icalcomponent_get_parent(comp);
        remove_icalprop(ical, ICAL_PRODID_PROPERTY);
        prop = icalproperty_new_prodid(prod_id);
        icalcomponent_add_property(ical, prop);
        buf_free(&buf);
    }

    /* created */
    jprop = json_object_get(event, "created");
    if (json_is_string(jprop)) {
        icaltimetype dt;
        if (icaltime_from_utcdate(json_string_value(jprop), &dt) > 0) {
            dtprop_to_ical(comp, dt, 1, ICAL_CREATED_PROPERTY);
        }
        else {
            jmap_parser_invalid(parser, "created");
        }
    } else if (JNOTNULL(jprop)) {
        jmap_parser_invalid(parser, "created");
    }

    /* updated */
    jprop = json_object_get(event, "updated");
    if (json_is_string(jprop)) {
        icaltimetype dt;
        if (icaltime_from_utcdate(json_string_value(jprop), &dt) > 0) {
            dtprop_to_ical(comp, dt, 1, ICAL_DTSTAMP_PROPERTY);
        }
        else {
            jmap_parser_invalid(parser, "updated");
        }
    } else if (jprop == NULL) {
        icaltimetype now = \
            icaltime_current_time_with_zone(icaltimezone_get_utc_timezone());
        dtprop_to_ical(comp, now, 1, ICAL_DTSTAMP_PROPERTY);
    } else {
        jmap_parser_invalid(parser, "updated");
    }

    jprop = json_object_get(event, "priority");
    if (json_integer_value(jprop) >= 0 || json_integer_value(jprop) <= 9) {
        remove_icalprop(comp, ICAL_PRIORITY_PROPERTY);
        prop = icalproperty_new_priority(json_integer_value(jprop));
        icalcomponent_add_property(comp, prop);
    } else if (JNOTNULL(jprop)) {
        jmap_parser_invalid(parser, "priority");
    }

    /* title */
    jprop = json_object_get(event, "title");
    if (json_is_string(jprop)) {
        icalcomponent_set_summary(comp, json_string_value(jprop));
    }
    else if (JNOTNULL(jprop)) {
        jmap_parser_invalid(parser, "title");
    }

    /* description and descriptionContentType */
    description_to_ical(comp, parser, event);

    /* method */
    jprop = json_object_get(event, "method");
    if (json_is_string(jprop)) {
        const char *method = json_string_value(jprop);
        icalproperty_method icalmethod = icalenum_string_to_method(method);
        if (icalmethod != ICAL_METHOD_NONE && !is_exc) {
            icalcomponent *ical = icalcomponent_get_parent(comp);
            icalcomponent_set_method(ical, icalmethod);
        }
        else {
            jmap_parser_invalid(parser, "method");
        }
    } else if (JNOTNULL(jprop)) {
        jmap_parser_invalid(parser, "method");
    }

    /* color */
    jprop = json_object_get(event, "color");
    if (json_is_string(jprop)) {
        const char *val = json_string_value(jprop);
        if (strlen(val)) {
            prop = icalproperty_new_color(val);
            icalcomponent_add_property(comp, prop);
        }
    } else if (JNOTNULL(jprop)) {
        jmap_parser_invalid(parser, "color");
    }

    /* keywords */
    jprop = json_object_get(event, "keywords");
    if (json_is_null(jprop) || json_is_object(jprop)) {
        keywords_to_ical(comp, parser, jprop);
    } else if (jprop) {
        jmap_parser_invalid(parser, "keywords");
    }

    /* links */
    jprop = json_object_get(event, "links");
    if (json_is_null(jprop) || json_object_size(jprop)) {
        links_to_ical(comp, parser, jprop);
    } else if (jprop) {
        jmap_parser_invalid(parser, "links");
    }

    /* locale */
    jprop = json_object_get(event, "locale");
    if (json_is_string(jprop)) {
        set_language_icalprop(comp, ICAL_SUMMARY_PROPERTY, NULL);
        set_language_icalprop(comp, ICAL_DESCRIPTION_PROPERTY, NULL);
        const char *val = json_string_value(jprop);
        if (strlen(val)) {
            set_language_icalprop(comp, ICAL_SUMMARY_PROPERTY, val);
        }
    } else if (json_is_null(jprop)) {
        set_language_icalprop(comp, ICAL_SUMMARY_PROPERTY, NULL);
        set_language_icalprop(comp, ICAL_DESCRIPTION_PROPERTY, NULL);
    } else if (jprop) {
        jmap_parser_invalid(parser, "locale");
    }

    /* locations */
    jprop = json_object_get(event, "locations");
    if (json_is_null(jprop) || json_object_size(jprop)) {
        json_t *links = json_object_get(event, "links");
        locations_to_ical(comp, parser, jprop, links);
    } else if (jprop) {
        jmap_parser_invalid(parser, "locations");
    }

    /* virtualLocations */
    jprop = json_object_get(event, "virtualLocations");
    if (json_is_null(jprop) || json_object_size(jprop)) {
        virtuallocations_to_ical(comp, parser, jprop);
    } else if (jprop) {
        jmap_parser_invalid(parser, "virtualLocations");
    }

    /* recurrenceRule */
    jprop = json_object_get(event, "recurrenceRule");
    if (json_is_null(jprop) || json_is_object(jprop)) {
        if (!is_exc) recurrence_to_ical(comp, parser, jprop);
    } else if (jprop) {
        jmap_parser_invalid(parser, "recurrenceRule");
    }

    /* status */
    enum icalproperty_status status = ICAL_STATUS_NONE;
    jprop = json_object_get(event, "status");
    if (json_is_string(jprop)) {
        const char *val = json_string_value(jprop);
        if (!strcmp(val, "confirmed")) {
            status = ICAL_STATUS_CONFIRMED;
        } else if (!strcmp(val, "cancelled")) {
            status = ICAL_STATUS_CANCELLED;
        } else if (!strcmp(val, "tentative")) {
            status = ICAL_STATUS_TENTATIVE;
        } else {
            jmap_parser_invalid(parser, "status");
        }
    } else if (json_is_null(jprop) || !jprop) {
        status = ICAL_STATUS_CONFIRMED;
    } else {
        jmap_parser_invalid(parser, "status");
    }
    if (status != ICAL_STATUS_NONE) {
        remove_icalprop(comp, ICAL_STATUS_PROPERTY);
        icalcomponent_set_status(comp, status);
    }

    /* freeBusyStatus */
    jprop = json_object_get(event, "freeBusyStatus");
    if (json_is_string(jprop)) {
        const char *val = json_string_value(jprop);
        enum icalproperty_transp v = ICAL_TRANSP_NONE;
        if (!strcmp(val, "free")) {
            v = ICAL_TRANSP_TRANSPARENT;
        } else if (!strcmp(val, "busy")) {
            v = ICAL_TRANSP_OPAQUE;
        } else {
            jmap_parser_invalid(parser, "freeBusyStatus");
        }
        if (v != ICAL_TRANSP_NONE) {
            prop = icalcomponent_get_first_property(comp, ICAL_TRANSP_PROPERTY);
            if (prop) {
                icalproperty_set_transp(prop, v);
            } else {
                icalcomponent_add_property(comp, icalproperty_new_transp(v));
            }
        }
    } else if (JNOTNULL(jprop)) {
        jmap_parser_invalid(parser, "freeBusyStatus");
    }

    /* privacy */
    jprop = json_object_get(event, "privacy");
    if (json_is_string(jprop)) {
        const char *val = json_string_value(jprop);
        enum icalproperty_class v = ICAL_CLASS_NONE;
        if (!strcmp(val, "public")) {
            v = ICAL_CLASS_PUBLIC;
        } else if (!strcmp(val, "private")) {
            v = ICAL_CLASS_PRIVATE;
        } else if (!strcmp(val, "secret")) {
            v = ICAL_CLASS_CONFIDENTIAL;
        } else {
            jmap_parser_invalid(parser, "privacy");
        }
        if (v != ICAL_CLASS_NONE) {
            prop = icalcomponent_get_first_property(comp, ICAL_CLASS_PROPERTY);
            if (prop) {
                icalproperty_set_class(prop, v);
            } else {
                icalcomponent_add_property(comp, icalproperty_new_class(v));
            }
        }
    } else if (JNOTNULL(jprop)) {
        jmap_parser_invalid(parser, "privacy");
    }

    /* replyTo and participants */
    participants_to_ical(comp, parser, event);

    /* participantId: readonly */

    /* useDefaultAlerts */
    jprop = json_object_get(event, "useDefaultAlerts");
    if (json_is_boolean(jprop)) {
        remove_icalxprop(comp, JMAPICAL_XPROP_USEDEFALERTS);
        if (json_boolean_value(jprop)) {
            icalvalue *icalval = icalvalue_new_boolean(1);
            prop = icalproperty_new(ICAL_X_PROPERTY);
            icalproperty_set_x_name(prop, JMAPICAL_XPROP_USEDEFALERTS);
            icalproperty_set_value(prop, icalval);
            icalcomponent_add_property(comp, prop);
        }
    } else if (JNOTNULL(jprop)) {
        jmap_parser_invalid(parser, "useDefaultAlerts");
    }

    /* alerts */
    jprop = json_object_get(event, "alerts");
    if (json_is_null(jprop) || json_object_size(jprop)) {
        alerts_to_ical(comp, parser, jprop);
    } else if (jprop) {
        jmap_parser_invalid(parser, "alerts");
    }

    /* recurrenceOverrides - must be last to apply patches */
    jprop = json_object_get(event, "recurrenceOverrides");
    if (json_is_null(jprop) || json_is_object(jprop)) {
        overrides_to_ical(comp, parser, jprop);
    } else if (jprop) {
        jmap_parser_invalid(parser, "recurrenceOverrides");
    }

    /* Bail out for property errors */
    if (json_array_size(parser->invalid)) {
        json_decref(event);
        return;
    }

    /* Check JMAP specification conditions on the generated iCalendar file, so 
     * this also doubles as a sanity check. Note that we *could* report a
     * property here as invalid, which had only been set by the client in a
     * previous request. */

    /* Either both organizer and attendees are null, or neither are. */
    if ((icalcomponent_get_first_property(comp, ICAL_ORGANIZER_PROPERTY) == NULL) !=
        (icalcomponent_get_first_property(comp, ICAL_ATTENDEE_PROPERTY) == NULL)) {
        jmap_parser_invalid(parser, "replyTo");
        jmap_parser_invalid(parser, "participants");
    }
    json_decref(event);
}

icalcomponent*
jmapical_toical(json_t *jsevent, json_t *invalid)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    icalcomponent *ical = NULL;
    icalcomponent *comp = NULL;

    /* Create a new VCALENDAR. */
    ical = icalcomponent_new_vcalendar();
    icalcomponent_add_property(ical, icalproperty_new_version("2.0"));
    icalcomponent_add_property(ical, icalproperty_new_calscale("GREGORIAN"));

    /* Create a new VEVENT. */
    icaltimezone *utc = icaltimezone_get_utc_timezone();
    struct icaltimetype now =
        icaltime_from_timet_with_zone(time(NULL), 0, utc);
    comp = icalcomponent_new_vevent();
    icalcomponent_set_sequence(comp, 0);
    icalcomponent_set_dtstamp(comp, now);
    icalcomponent_add_property(comp, icalproperty_new_created(now));
    icalcomponent_add_component(ical, comp);

    /* Convert the JMAP calendar event to ical. */
    calendarevent_to_ical(comp, &parser, jsevent);
    icalcomponent_add_required_timezones(ical);

    /* Report any property errors. */
    if (json_array_size(parser.invalid)) {
        if (invalid) json_array_extend(invalid, parser.invalid);
        if (ical) icalcomponent_free(ical);
        ical = NULL;
    }

#if 0
    if (ical &&
        (!icalrestriction_check(ical) || icalcomponent_count_errors(ical))) {
        syslog(LOG_ERR, "jmapical_toical: %s", get_icalcomponent_errstr(ical));
        if (!ctx->err->code) ctx->err->code = JMAPICAL_ERROR_UNKNOWN;
        icalcomponent_free(ical);
        ical = NULL;
    }
#endif

    jmap_parser_fini(&parser);
    return ical;
}

const char *
jmapical_strerror(int err)
{
    switch (err) {
        case 0:
            return "jmapical: success";
        case JMAPICAL_ERROR_CALLBACK:
            return "jmapical: callback error";
        case JMAPICAL_ERROR_MEMORY:
            return "jmapical: no memory";
        case JMAPICAL_ERROR_ICAL:
            return "jmapical: iCalendar error";
        case JMAPICAL_ERROR_PROPS:
            return "jmapical: property error";
        case JMAPICAL_ERROR_UID:
            return "jmapical: iCalendar uid error";
        default:
            return "jmapical: unknown error";
    }
}

/*
 * Construct a jevent string for an iCalendar component.
 */
EXPORTED struct buf *icalcomponent_as_jevent_string(icalcomponent *ical)
{
    struct buf *ret;
    json_t *jcal;
    size_t flags = JSON_PRESERVE_ORDER;
    char *buf;

    if (!ical) return NULL;

    jcal = jmapical_tojmap(ical, NULL);

    flags |= (config_httpprettytelemetry ? JSON_INDENT(2) : JSON_COMPACT);
    buf = json_dumps(jcal, flags);

    json_decref(jcal);

    ret = buf_new();
    buf_initm(ret, buf, strlen(buf));

    return ret;
}

EXPORTED icalcomponent *jevent_string_as_icalcomponent(const struct buf *buf)
{
    json_t *obj;
    json_error_t jerr;
    icalcomponent *ical;
    const char *str = buf_cstring(buf);

    if (!str) return NULL;

    obj = json_loads(str, 0, &jerr);
    if (!obj) {
        syslog(LOG_WARNING, "json parse error: '%s'", jerr.text);
        return NULL;
    }

    ical = jmapical_toical(obj, NULL);

    json_decref(obj);

    return ical;
}

