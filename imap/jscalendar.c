/* jscalendar.c -- Routines for converting JSCalendar and iCalendar
 *
 * Copyright (c) 2025 Fastmail Pty Ltd
 *
 */

#include <config.h>

#include <string.h>
#include <syslog.h>

#include "ical_support.h"
#include "jcal.h"
#include "jmap_util.h"
#include "jscalendar.h"
#include "json_support.h"
#include "ptrarray.h"
#include "strarray.h"
#include "util.h"
#include "xcal.h"

// ---------------

#define myicalcomponent_foreach_component(comp, comp_kind, subcomp, iter)      \
    for (iter = icalcomponent_begin_component(comp, comp_kind);                \
         (subcomp = icalcompiter_deref(&iter));                                \
         icalcompiter_next(&iter))

#define myicalcomponent_foreach_property(comp, prop_kind, prop, iter)          \
    for (iter = icalcomponent_begin_property(comp, prop_kind);                 \
         (prop = icalpropiter_deref(&iter));                                   \
         icalpropiter_next(&iter))

#define myicalproperty_foreach_parameter(prop, param_kind, param, iter)        \
    for (iter = icalproperty_begin_parameter(prop, param_kind);                \
         (param = icalparamiter_deref(&iter));                                 \
         icalparamiter_next(&iter))

static bool myicalproperty_has_name(icalproperty *prop, const char *name)
{
    icalproperty_kind kind = icalproperty_isa(prop);
    const char *prop_name = NULL;

    if (kind == ICAL_X_PROPERTY)
        prop_name = icalproperty_get_x_name(prop);
    else if (kind == ICAL_IANA_PROPERTY)
        prop_name = icalproperty_get_iana_name(prop);
    else
        prop_name = icalproperty_kind_to_string(kind);

     return !strcasecmpsafe(name, prop_name);
}

static bool myicalparameter_has_name(icalparameter *param, const char *name)
{
    icalparameter_kind param_kind = icalparameter_isa(param);
    const char *param_name = NULL;

    if (param_kind == ICAL_X_PARAMETER)
        param_name = icalparameter_get_xname(param);
    else if (param_kind == ICAL_IANA_PARAMETER)
        param_name = icalparameter_get_iana_name(param);
    else
        param_name = icalparameter_kind_to_string(param_kind);

     return !strcasecmpsafe(name, param_name);
}

static icalparameter *myicalparameter_new_jsid(const char *key)
{
    icalparameter *param = icalparameter_new_iana(key);
    icalparameter_set_iana_name(param, "JSID");
    return param;
}

__attribute__((unused))
static const char *myicalparameter_get_jsid(icalparameter *param)
{
    if (!myicalparameter_has_name(param, "JSID")) return NULL;
    return icalparameter_get_value_as_string(param);
}


static icalparameter *myicalparameter_new_jsptr(const char *ptr)
{
    icalparameter *param = icalparameter_new_iana(ptr);
    icalparameter_set_iana_name(param, "JSPTR");
    return param;
}

static const char *myicalparameter_get_jsptr(icalparameter *param)
{
    if (!myicalparameter_has_name(param, "JSPTR")) return NULL;
    return icalparameter_get_value_as_string(param);
}

static icalproperty *myicalproperty_new_jsid(const char *key)
{
    icalproperty *prop = icalproperty_new_iana(key);
    icalproperty_set_iana_name(prop, "JSID");
    return prop;
}

__attribute__((unused))
static const char *myicalproperty_get_jsid(icalproperty *prop)
{
    if (!myicalproperty_has_name(prop, "JSID")) return NULL;
    icalvalue *value = icalproperty_get_value(prop);
    if (icalvalue_isa(value) != ICAL_TEXT_VALUE) return NULL;
    return icalvalue_get_text(value);
}

static icalproperty *myicalproperty_new_jsprop(const char *val)
{
    icalproperty *prop = icalproperty_new_iana(val);
    icalproperty_set_iana_name(prop, "JSPROP");
    return prop;
}

static const char *myicalproperty_get_jsprop(icalproperty *prop)
{
    if (!myicalproperty_has_name(prop, "JSPROP")) return NULL;
    icalvalue *value = icalproperty_get_value(prop);
    if (icalvalue_isa(value) != ICAL_TEXT_VALUE) return NULL;
    return icalvalue_get_text(value);
}

static icalproperty *myicalproperty_new_coordinates(const char *uri)
{
    icalproperty *prop = icalproperty_new(ICAL_IANA_PROPERTY);
    icalproperty_set_iana_name(prop, "COORDINATES");
    icalproperty_set_value(prop, icalvalue_new_uri(uri));
    return prop;
}

static const char *myicalproperty_get_coordinates(icalproperty *prop)
{
    if (!myicalproperty_has_name(prop, "COORDINATES")) return NULL;
    icalvalue *value = icalproperty_get_value(prop);
    if (icalvalue_isa(value) != ICAL_URI_VALUE) return NULL;
    return icalvalue_get_uri(value);
}

static icalproperty *myicalproperty_new_showwithouttime(bool val)
{
    icalproperty *prop = icalproperty_new(ICAL_IANA_PROPERTY);
    icalproperty_set_iana_name(prop, "SHOW-WITHOUT-TIME");
    icalproperty_set_value(prop, icalvalue_new_boolean(val));
    return prop;
}

static bool myicalproperty_get_showwithouttime(icalproperty *prop)
{
    if (!myicalproperty_has_name(prop, "SHOW-WITHOUT-TIME")) return false;
    icalvalue *value = icalproperty_get_value(prop);
    switch (icalvalue_isa(value)) {
        case ICAL_BOOLEAN_VALUE:
            return icalvalue_get_boolean(value);
        case ICAL_TEXT_VALUE:
            return !strcasecmpsafe("TRUE", icalvalue_get_text(value));
        default:
            return false;
    }
}

static bool myicaltime_has_zero_time(icaltimetype t)
{
    return t.hour == 0 && t.minute == 0 && t.second == 0;
}

static bool myicalduration_has_zero_time(struct icaldurationtype d)
{
    return d.hours == 0 && d.minutes == 0 && d.seconds == 0;
}

static icalproperty *myicalcomponent_get_property(icalcomponent *comp,
                                                  icalproperty_kind kind)
{
    icalpropiter iter = icalcomponent_begin_property(comp, kind);
    return icalpropiter_deref(&iter);
}

static icalparameter *myicalproperty_get_parameter(icalproperty *prop,
                                                   icalparameter_kind kind)
{
    icalparamiter paramiter = icalproperty_begin_parameter(prop, kind);
    return icalparamiter_deref(&paramiter);
}

static bool myicalproperty_is_derived(icalproperty *prop)
{
    icalparameter *param =
        myicalproperty_get_parameter(prop, ICAL_DERIVED_PARAMETER);
    return param && icalparameter_get_derived(param) == ICAL_DERIVED_TRUE;
}

static icalproperty *myicalcomponent_get_nonderived_property(
    icalcomponent *comp, icalproperty_kind kind)
{
    icalproperty *prop;
    icalpropiter it;
    myicalcomponent_foreach_property(comp, kind, prop, it)
    {
        if (!myicalproperty_is_derived(prop)) return prop;
    }
    return NULL;
}

static icalparameter *myicalproperty_get_parameter_by_name(icalproperty *prop, const char *name)
{
    icalparamiter it;
    icalparameter *param;

    myicalproperty_foreach_parameter(prop, ICAL_ANY_PARAMETER, param, it) {
        if (myicalparameter_has_name(param, name)) {
            return param;
        }
    }

    return NULL;
}

static icalproperty *myicalcomponent_get_property_by_name(icalcomponent *comp, const char *name)
{
    icalpropiter it;
    icalproperty *prop;

    myicalcomponent_foreach_property(comp, ICAL_ANY_PROPERTY, prop, it) {
        if (myicalproperty_has_name(prop, name)) {
            return prop;
        }
    }

    return NULL;
}

// ---------------

static bool is_known_param(icalproperty *prop, icalparameter *param)
{
    icalproperty_kind prop_kind = icalproperty_isa(prop);
    icalparameter_kind param_kind = icalparameter_isa(param);

    switch (param_kind) {
    case ICAL_TZID_PARAMETER:
    case ICAL_VALUE_PARAMETER:
        return true;
    default:
        if (myicalparameter_has_name(param, "JSID")) {
            return true;
        }
        if (myicalparameter_has_name(param, "X-JMAP-ID")) {
            return true;
        }
        // fallthrough
    }

    switch (prop_kind) {
    case ICAL_ATTACH_PROPERTY:
    case ICAL_IMAGE_PROPERTY:
    case ICAL_LINK_PROPERTY:
        switch (param_kind) {
        case ICAL_DISPLAY_PARAMETER:
        case ICAL_ENCODING_PARAMETER:
        case ICAL_FMTTYPE_PARAMETER:
        case ICAL_LABEL_PARAMETER:
        case ICAL_LINKREL_PARAMETER:
        case ICAL_SIZE_PARAMETER:
            return true;
        default:
            return false;
        }

    case ICAL_ATTENDEE_PROPERTY:
    case ICAL_ORGANIZER_PROPERTY:
        switch (param_kind) {
        case ICAL_CN_PARAMETER:
        case ICAL_EMAIL_PARAMETER:
        case ICAL_SCHEDULEAGENT_PARAMETER:
        case ICAL_SCHEDULEFORCESEND_PARAMETER:
        case ICAL_SCHEDULESTATUS_PARAMETER:
            return true;
        default:
            return false;
        }

    case ICAL_CONFERENCE_PROPERTY:
        switch (param_kind) {
        case ICAL_FEATURE_PARAMETER:
        case ICAL_LABEL_PARAMETER:
            return true;
        default:
            return false;
        }

    case ICAL_DESCRIPTION_PROPERTY:
    case ICAL_STYLEDDESCRIPTION_PROPERTY:
        switch (param_kind) {
        case ICAL_FMTTYPE_PARAMETER:
            return true;
        default:
            return false;
        }

    case ICAL_NAME_PROPERTY:
    case ICAL_SUMMARY_PROPERTY:
        switch (param_kind) {
        case ICAL_LANGUAGE_PARAMETER:
            return true;
        default:
            return false;
        }

    default:
        return false;
    }
}

static bool is_known_prop(icalcomponent *comp, icalproperty *prop)
{
    icalcomponent_kind comp_kind = icalcomponent_isa(comp);
    icalproperty_kind prop_kind = icalproperty_isa(prop);

    if (myicalproperty_has_name(prop, "JSID"))
        return true;

    if (myicalproperty_has_name(prop, "X-JMAP-ID"))
        return true;

    if (myicalproperty_has_name(prop, "JSPROP"))
        return true;

    switch (comp_kind) {
    case ICAL_VALARM_COMPONENT:
        switch (prop_kind) {
        case ICAL_ACKNOWLEDGED_PROPERTY:
            return true;
        case ICAL_ACTION_PROPERTY:
            switch (icalproperty_get_action(prop)) {
            case ICAL_ACTION_DISPLAY:
            case ICAL_ACTION_EMAIL:
            case ICAL_ACTION_NONE:
                return true;
            default:
                return false;
            }
        case ICAL_RELATEDTO_PROPERTY:
        case ICAL_TRIGGER_PROPERTY:
            return true;
        default:
            return false;
        }

    case ICAL_VCALENDAR_COMPONENT:
        switch (prop_kind) {
        case ICAL_ATTACH_PROPERTY:
        case ICAL_CATEGORIES_PROPERTY:
        case ICAL_CALSCALE_PROPERTY:
        case ICAL_COLOR_PROPERTY:
        case ICAL_CONCEPT_PROPERTY:
        case ICAL_CREATED_PROPERTY:
        case ICAL_DESCRIPTION_PROPERTY:
        case ICAL_IMAGE_PROPERTY:
        case ICAL_LASTMODIFIED_PROPERTY:
        case ICAL_LINK_PROPERTY:
        case ICAL_METHOD_PROPERTY:
        case ICAL_NAME_PROPERTY:
        case ICAL_PRODID_PROPERTY:
        case ICAL_SOURCE_PROPERTY:
        case ICAL_STYLEDDESCRIPTION_PROPERTY:
        case ICAL_UID_PROPERTY:
        case ICAL_VERSION_PROPERTY:
            return true;
        default:
            return false;
        }
        break;

    case ICAL_VEVENT_COMPONENT:
    case ICAL_VTODO_COMPONENT:
        switch (prop_kind) {
        case ICAL_ATTACH_PROPERTY:
        case ICAL_ATTENDEE_PROPERTY:
        case ICAL_CATEGORIES_PROPERTY:
        case ICAL_CLASS_PROPERTY:
        case ICAL_COLOR_PROPERTY:
        case ICAL_COMPLETED_PROPERTY:
        case ICAL_CONCEPT_PROPERTY:
        case ICAL_CONFERENCE_PROPERTY:
        case ICAL_CREATED_PROPERTY:
        case ICAL_DESCRIPTION_PROPERTY:
        case ICAL_DTEND_PROPERTY:
        case ICAL_DTSTAMP_PROPERTY:
        case ICAL_DTSTART_PROPERTY:
        case ICAL_DUE_PROPERTY:
        case ICAL_DURATION_PROPERTY:
        case ICAL_ESTIMATEDDURATION_PROPERTY:
        case ICAL_EXDATE_PROPERTY:
        case ICAL_GEO_PROPERTY:
        case ICAL_IMAGE_PROPERTY:
        case ICAL_LASTMODIFIED_PROPERTY:
        case ICAL_LINK_PROPERTY:
        case ICAL_LOCATION_PROPERTY:
        case ICAL_ORGANIZER_PROPERTY:
        case ICAL_PERCENTCOMPLETE_PROPERTY:
        case ICAL_PRIORITY_PROPERTY:
        case ICAL_RDATE_PROPERTY:
        case ICAL_RECURRENCEID_PROPERTY:
        case ICAL_RELATEDTO_PROPERTY:
        case ICAL_RRULE_PROPERTY:
        case ICAL_SEQUENCE_PROPERTY:
        case ICAL_STATUS_PROPERTY:
        case ICAL_STYLEDDESCRIPTION_PROPERTY:
        case ICAL_SUMMARY_PROPERTY:
        case ICAL_TRANSP_PROPERTY:
        case ICAL_UID_PROPERTY:
        case ICAL_URL_PROPERTY:
        case ICAL_VERSION_PROPERTY:
            return true;
        default:
            if (myicalproperty_has_name(prop, "COORDINATES") ||
                myicalproperty_has_name(prop, "SHOW-WITHOUT-TIME")) {
                return true;
            }
            return false;
        }

    case ICAL_VLOCATION_COMPONENT:
        switch (prop_kind) {
        case ICAL_ATTACH_PROPERTY:
        case ICAL_DESCRIPTION_PROPERTY:
        case ICAL_GEO_PROPERTY:
        case ICAL_IMAGE_PROPERTY:
        case ICAL_LINK_PROPERTY:
        case ICAL_NAME_PROPERTY:
        case ICAL_LOCATIONTYPE_PROPERTY:
        case ICAL_STYLEDDESCRIPTION_PROPERTY:
            return true;
        default:
            if (myicalproperty_has_name(prop, "COORDINATES")) {
                return true;
            }
            return false;
        }

    case ICAL_PARTICIPANT_COMPONENT:
        switch (prop_kind) {
        case ICAL_ATTACH_PROPERTY:
        case ICAL_CALENDARADDRESS_PROPERTY:
        case ICAL_DESCRIPTION_PROPERTY:
        case ICAL_IMAGE_PROPERTY:
        case ICAL_LINK_PROPERTY:
        case ICAL_NAME_PROPERTY:
        case ICAL_PERCENTCOMPLETE_PROPERTY:
        case ICAL_STYLEDDESCRIPTION_PROPERTY:
            return true;
        default:
            return false;
        }

    default:
        return false;
    }
}

static bool is_known_comp(icalcomponent *parent, icalcomponent *comp)
{
    icalcomponent_kind comp_kind = icalcomponent_isa(comp);

    switch (icalcomponent_isa(parent)) {
    case ICAL_VCALENDAR_COMPONENT:
        switch (comp_kind) {
        case ICAL_VEVENT_COMPONENT:
        case ICAL_VTIMEZONE_COMPONENT:
        case ICAL_VTODO_COMPONENT:
            return true;
        default:
            return false;
        }
        break;
    case ICAL_VEVENT_COMPONENT:
    case ICAL_VTODO_COMPONENT:
        switch (comp_kind) {
        case ICAL_VALARM_COMPONENT:
        case ICAL_PARTICIPANT_COMPONENT:
        case ICAL_VLOCATION_COMPONENT:
            return true;
        default:
            return false;
        };

    default:
        return false;
    }
}

// ---------------

static bool is_usable_uid(const char *str)
{
    size_t len = strlen(str);

    // Check if it looks like a UUID.
    if (len == 36) {
        size_t i;

        for (i = 0; i < len; i++) {
            if (i == 8 || i == 13 || i == 18 || i == 23) {
                if (str[i] != '-') break;
            }
            else if (!isxdigit(str[i])) {
                break;
            }
        }

        // It's a UUID, use it.
        if (i == len) return true;
    }

    // Check for a reasonable length.
    if (len < 24 || len > 64) return false;

    // Check contents and charachter count.
    size_t chars_count[128] = { 0 };
    size_t max_count = 0;
    for (size_t i = 0; i < len; i++) {
        char c = str[i];

        // Only allow alphanumerics and commonly seen punctuation.
        if (!isalnum(c) && !strchr("-_@.:", c)) {
            return false;
        }

        // Count character.
        chars_count[(size_t) c]++;

        // Count most-occurring character.
        if (max_count < chars_count[(size_t) c]) {
            max_count = chars_count[(size_t) c];
        }
    }

    // No character may occur more often then 20% of length.
    if (max_count > len * 0.2) return false;

    // Looks reasonable enough.
    return true;
}

// ---------------
struct geouri
{
    char *coords[3];
    char *p;
};

static void geouri_fini(struct geouri *geouri)
{
    int i;
    for (i = 0; i < 3; i++) xzfree(geouri->coords[i]);
    xzfree(geouri->p);
}

static bool geouri_parse(const char *uri, struct geouri *geouri)
{
    const char *str = uri;
    geouri_fini(geouri);

    // geo:
    if (strncmpsafe("geo:", str, 4)) return false;
    str += 4;

    // coord-a "," coord-b [ "," coord-c ]
    int i;
    for (i = 0; i < 3; i++) {
        if ((geouri->coords[0] || geouri->coords[1])) {
            if (*str != ',') break;
            str++;
        }

        const char *num = str;

        if (*str == '-') num++;

        for (; isdigit(*num); num++) {
        }
        if (num == str) break;

        if (*num == '.') {
            const char *frac = ++num;

            for (; isdigit(*frac); frac++) {
            }
            if (frac == num) break;

            num = frac;
        }

        geouri->coords[i] = xstrndup(str, num - str);
        str = num;
    }

    if (!geouri->coords[0] || !geouri->coords[1]) return false;

    if (str[0] == ';') {
        geouri->p = xstrdup(str);
    }
    else if (str[0]) {
        geouri_fini(geouri);
        return false;
    }

    return true;
}

static struct icalgeotype geouri_to_icalgeo(const char *uri, bool *is_lossy)
{
    struct icalgeotype icalgeo = { 0 };
    icalgeo.lat[0] = '0';
    icalgeo.lon[0] = '0';

    struct geouri geouri = { 0 };
    if (!geouri_parse(uri, &geouri)) {
        *is_lossy = true;
        return icalgeo;
    }

    *is_lossy = geouri.coords[2] || geouri.p;

    size_t n = strlen(geouri.coords[0]);
    if (n >= ICAL_GEO_LEN) {
        n = ICAL_GEO_LEN - 1;
        *is_lossy = true;
    }
    strncpy(icalgeo.lat, geouri.coords[0], n);

    n = strlen(geouri.coords[1]);
    if (n >= ICAL_GEO_LEN) {
        n = ICAL_GEO_LEN - 1;
        *is_lossy = true;
    }
    strncpy(icalgeo.lon, geouri.coords[1], n);

    return icalgeo;
}

// ---------------

static icalproperty *jicalproperty_to_icalproperty(json_t *jprop)
{
    const char *name = json_string_value(json_object_get(jprop, "name"));
    if (!name) return NULL;

    // TODO handle IANA properties unknown to libical
    icalproperty_kind kind = icalproperty_string_to_kind(name);
    if (kind == ICAL_NO_PROPERTY) return NULL;

    icalproperty *prop = icalproperty_new(kind);
    if (kind == ICAL_X_PROPERTY) {
        icalproperty_set_x_name(prop, name);
    }

    const char *vtype = json_string_value(json_object_get(jprop, "valueType"));
    if (vtype) {
        icalvalue_kind vkind = icalvalue_string_to_kind(vtype);
        if (vkind) icalproperty_set_value(prop, icalvalue_new(vkind));
    }

    json_t *jparams = json_object_get(jprop, "parameters");
    const char *param_name;
    json_t *param_jval;
    json_object_foreach(jparams, param_name, param_jval)
    {
        const char *val = json_string_value(param_jval);
        if (!val) continue;
        icalproperty_set_parameter_from_string(prop, param_name, val);
    }

    return prop;
}

static icaltimetype parse_datetime(const char *val, const char **end)
{
    struct tm tm;
    memset(&tm, 0, sizeof(struct tm));
    tm.tm_isdst = -1;

    const char *p = strptime(val, "%Y-%m-%dT%H:%M:%S", &tm);
    if (!p) {
        *end = val;
        return icaltime_null_time();
    }

    if (*p == '.' && isdigit(p[1])) {
        // ignore nanoseconds
        while (isdigit(*++p)) {
        }
    }
    *end = p;

    icaltimetype t = icaltime_null_time();
    t.year = tm.tm_year + 1900;
    t.month = tm.tm_mon + 1;
    t.day = tm.tm_mday;
    t.hour = tm.tm_hour;
    t.minute = tm.tm_min;
    t.second = tm.tm_sec;

    return t;
}

static icaltimetype utctime_to_icaltime(const char *s)
{
    const char *end;
    icaltimetype t = parse_datetime(s, &end);
    if (end[0] != 'Z' || end[1]) return icaltime_null_time();
    t.zone = icaltimezone_get_utc_timezone();
    return t;
}

static icaltimetype localtime_to_icaltime(const char *s)
{
    const char *end;
    icaltimetype t = parse_datetime(s, &end);
    if (end[0]) return icaltime_null_time();
    return t;
}

static const char *localtime_from_icaltime(icaltimetype t, struct buf *buf)
{
    buf_reset(buf);
    buf_printf(buf,
               "%04d-%02d-%02dT%02d:%02d:%02d",
               t.year,
               t.month,
               t.day,
               t.is_date ? 0 : t.hour,
               t.is_date ? 0 : t.minute,
               t.is_date ? 0 : t.second);
    return buf_cstring(buf);
}

static const char *utctime_from_icaltime(icaltimetype t, struct buf *buf)
{
    localtime_from_icaltime(t, buf);
    buf_putc(buf, 'Z');
    return buf_cstring(buf);
}

static struct icalrecurrencetype *rrule_to_ical(json_t *jrrule,
                                                icaltimezone *tz_until)
{
    struct icalrecurrencetype *recur = NULL;
    struct buf buf = BUF_INITIALIZER;

    // frequency
    const char *freq = json_string_value(json_object_get(jrrule, "frequency"));
    //clang-format off
    if (strcasecmp(freq, "yearly") && strcasecmp(freq, "monthly")
        && strcasecmp(freq, "weekly") && strcasecmp(freq, "daily")
        && strcasecmp(freq, "hourly") && strcasecmp(freq, "minutely")
        && strcasecmp(freq, "secondly"))
    {
        return NULL;
    }
    //clang-format on
    buf_printf(&buf, "FREQ=%s", freq);

    // interval
    json_int_t ival = json_integer_value(json_object_get(jrrule, "interval"));
    if (ival > 1) buf_printf(&buf, ";INTERVAL=%lld", ival);

    // rscale
    // omit
    const char *rscale = json_string_value(json_object_get(jrrule, "rscale"));
    if (rscale) {
        const char *skip = json_string_value(json_object_get(jrrule, "skip"));
        if (strcasecmp(rscale, "GREGORIAN")
            || (skip && strcasecmp(skip, "OMIT"))) {
            buf_printf(&buf, ";RSCALE=%s", rscale);
            if (skip) buf_printf(&buf, ";SKIP=%s", skip);
        }
    }

    // firstDayOfWeek
    const char *fdow =
        json_string_value(json_object_get(jrrule, "firstDayOfWeek"));
    if (fdow) buf_printf(&buf, ";WKST=%s", fdow);

    // byDay
    json_t *jbyday = json_object_get(jrrule, "byDay");
    if (json_array_size(jbyday)) {
        buf_appendcstr(&buf, ";BYDAY=");
        size_t i;
        json_t *jnday;
        json_array_foreach(jbyday, i, jnday)
        {
            const char *day = json_string_value(json_object_get(jnday, "day"));
            json_int_t n =
                json_integer_value(json_object_get(jnday, "nthOfPeriod"));

            if (i) buf_putc(&buf, ',');
            if (n) buf_printf(&buf, "%lld", n);
            buf_appendcstr(&buf, day);
        }
    }

    //clang-format off
    static struct
    {
        const char *name;
        const char *icalname;
    } byx[] = {
        {"byMonthDay",     "BYMONTHDAY"},
        { "byMonth",       "BYMONTH"   },
        { "byYearDay",     "BYYEARDAY" },
        { "byWeekNo",      "BYWEEKNO"  },
        { "byHour",        "BYHOUR"    },
        { "byMinute",      "BYMINUTE"  },
        { "bySecond",      "BYSECOND"  },
        { "bySetPosition", "BYSETPOS"  },
    };
    //clang-format on

    for (size_t i = 0; i < sizeof(byx) / sizeof(byx[0]); i++) {
        json_t *jbyx = json_object_get(jrrule, byx[i].name);
        if (json_array_size(jbyx)) {
            buf_printf(&buf, ";%s=", byx[i].icalname);
            size_t j;
            json_t *jval;
            json_array_foreach(jbyx, j, jval)
            {
                if (j) buf_putc(&buf, ',');
                if (json_is_string(jval)) {
                    buf_appendcstr(&buf, json_string_value(jval));
                }
                else {
                    buf_printf(&buf, "%lld", json_integer_value(jval));
                }
            }
        }
    }

    // count
    json_int_t count = json_integer_value(json_object_get(jrrule, "count"));
    if (count > 0 && !json_object_get(jrrule, "until"))
        buf_printf(&buf, ";COUNT=%lld", count);

    // until
    const char *until = json_string_value(json_object_get(jrrule, "until"));
    if (until) {
        icaltimetype t = localtime_to_icaltime(until);
        t.zone = tz_until;
        icaltimezone *utc = icaltimezone_get_utc_timezone();
        t = icaltime_convert_to_zone(t, utc);
        buf_printf(&buf, ";UNTIL=%s", icaltime_as_ical_string(t));
    }

    // All done.
    recur = icalrecurrencetype_new_from_string(buf_ucase(&buf));
    buf_free(&buf);
    return recur;
}

static json_t *rrule_from_ical(struct icalrecurrencetype *rrule,
                               icaltimezone *tz_until)
{
    struct buf buf = BUF_INITIALIZER;

    const char *freq = NULL;
    switch (rrule->freq) {
    case ICAL_SECONDLY_RECURRENCE:
        freq = "secondly";
        break;
    case ICAL_MINUTELY_RECURRENCE:
        freq = "minutely";
        break;
    case ICAL_HOURLY_RECURRENCE:
        freq = "hourly";
        break;
    case ICAL_DAILY_RECURRENCE:
        freq = "daily";
        break;
    case ICAL_WEEKLY_RECURRENCE:
        freq = "weekly";
        break;
    case ICAL_MONTHLY_RECURRENCE:
        freq = "monthly";
        break;
    case ICAL_YEARLY_RECURRENCE:
        freq = "yearly";
        break;
    case ICAL_NO_RECURRENCE:
        return false;
    }

    json_t *jrrule = json_pack("{s:s}", "@type", "RecurrenceRule");
    json_object_set_new(jrrule, "frequency", json_string(freq));

    // interval
    if (rrule->interval > 0) {
        json_object_set_new(jrrule, "interval", json_integer(rrule->interval));
    }

    // rscale
    if (rrule->rscale && strcasecmp(rrule->rscale, "gregorian")) {
        buf_setcstr(&buf, rrule->rscale);
        const char *rscale = buf_lcase(&buf);
        json_object_set_new(jrrule, "rscale", json_string(rscale));
        buf_free(&buf);
    }

    // skip
    struct buf skip = BUF_INITIALIZER;
    switch (rrule->skip) {
    case ICAL_SKIP_BACKWARD:
        buf_setcstr(&skip, "backward");
        break;
    case ICAL_SKIP_FORWARD:
        buf_setcstr(&skip, "forward");
        break;
    case ICAL_SKIP_OMIT:
    case ICAL_SKIP_UNDEFINED:
        break;
    }
    if (buf_len(&skip)) {
        json_object_set_new(jrrule, "skip", json_string(buf_lcase(&skip)));
    }

    // firstDayOfWeek
    static const char *const weekdays[7] = { "su", "mo", "tu", "we",
                                             "th", "fr", "sa" };

    switch (rrule->week_start) {
    case ICAL_NO_WEEKDAY:
    case ICAL_MONDAY_WEEKDAY:
        break;
    default: {
        json_object_set_new(
            jrrule,
            "firstDayOfWeek",
            json_string(weekdays[rrule->week_start - ICAL_SUNDAY_WEEKDAY]));
    }
    }

    for (enum icalrecurrencetype_byrule byrule = ICAL_BY_MONTH;
         byrule < ICAL_BY_NUM_PARTS;
         byrule++)
    {

        if (!rrule->by[byrule].size) continue;

        const char *jbyrule_name;
        switch (byrule) {
        case ICAL_BY_MONTH:
            jbyrule_name = "byMonth";
            break;
        case ICAL_BY_WEEK_NO:
            jbyrule_name = "byWeekNo";
            break;
        case ICAL_BY_YEAR_DAY:
            jbyrule_name = "byYearDay";
            break;
        case ICAL_BY_MONTH_DAY:
            jbyrule_name = "byMonthDay";
            break;
        case ICAL_BY_DAY:
            jbyrule_name = "byDay";
            break;
        case ICAL_BY_HOUR:
            jbyrule_name = "byHour";
            break;
        case ICAL_BY_MINUTE:
            jbyrule_name = "byMinute";
            break;
        case ICAL_BY_SECOND:
            jbyrule_name = "bySecond";
            break;
        case ICAL_BY_SET_POS:
            jbyrule_name = "bySetPosition";
            break;
        default:
            continue; // ignore
        }

        json_t *jbyrule_vals = json_array();

        for (short i = 0; i < rrule->by[byrule].size; i++) {
            short val = rrule->by[byrule].data[i];
            json_t *jval;
            switch (byrule) {
            case ICAL_BY_MONTH:
                buf_reset(&buf);
                buf_printf(&buf, "%d", icalrecurrencetype_month_month(val));
                if (icalrecurrencetype_month_is_leap(val)) buf_putc(&buf, 'L');
                jval = json_string(buf_cstring(&buf));
                break;
            case ICAL_BY_DAY: {
                enum icalrecurrencetype_weekday wday =
                    icalrecurrencetype_day_day_of_week(val);
                jval = json_pack("{s:s s:s}",
                                 "@type",
                                 "NDay",
                                 "day",
                                 weekdays[wday - ICAL_SUNDAY_WEEKDAY]);
                int pos = icalrecurrencetype_day_position(val);
                if (pos) {
                    json_object_set_new(jval, "nthOfPeriod", json_integer(pos));
                }
                break;
            }
            default:
                jval = json_integer(val);
            }
            json_array_append_new(jbyrule_vals, jval);
        }

        if (json_array_size(jbyrule_vals)) {
            json_object_set(jrrule, jbyrule_name, jbyrule_vals);
        }
        json_decref(jbyrule_vals);
    }

    // until
    if (!icaltime_is_null_time(rrule->until)) {
        icaltimetype t = icaltime_convert_to_zone(rrule->until, tz_until);
        const char *until = localtime_from_icaltime(t, &buf);
        json_object_set_new(jrrule, "until", json_string(until));
    }
    // count
    else if (rrule->count > 0) {
        json_object_set_new(jrrule, "count", json_integer(rrule->count));
    }

    buf_free(&buf);
    return jrrule;
}

enum get_ical_flags {
    GET_ICAL_CREATE = (1 << 0),
    GET_ICAL_KEEPKNOWN = (1 << 1),
};

static icalcomponent *jobj_get_icalcomp(jscalendar_cfg_t *cfg,
                                        json_t *jobj,
                                        icalcomponent_kind want_kind,
                                        enum get_ical_flags flags)
{
    icalcomponent *comp = NULL;

    if (!cfg->use_icalendar_convprops) {
        if (want_kind != ICAL_ANY_COMPONENT && (flags & GET_ICAL_CREATE)) {
            comp = icalcomponent_new(want_kind);
        }
        return comp;
    }

    json_t *jcomp = json_object_get(jobj, "iCalendar");
    if (jcomp) {
        const char *name = json_string_value(json_object_get(jcomp, "name"));
        if (name) {
            json_t *jcalprops = json_object_get(jcomp, "properties");
            if (!jcalprops) jcalprops = json_array();

            json_t *jcalcomps = json_object_get(jcomp, "components");
            if (!jcalcomps) jcalcomps = json_array();

            json_t *jcal = json_pack("[s,O,O]", name, jcalprops, jcalcomps);
            comp = jcal_array_as_icalcomponent(jcal);

            if (want_kind != ICAL_ANY_COMPONENT
                && icalcomponent_isa(comp) != want_kind) {
                if (comp) icalcomponent_free(comp);
                comp = NULL;
            }

            if (comp && !(flags & GET_ICAL_KEEPKNOWN)) {
                // Remove known properties and subcomponents.
                icalpropiter pi =
                    icalcomponent_begin_property(comp, ICAL_ANY_PROPERTY);
                icalproperty *prop = icalpropiter_deref(&pi);
                while (prop) {
                    icalproperty *next = icalpropiter_next(&pi);
                    if (is_known_prop(comp, prop)) {
                        icalcomponent_remove_property(comp, prop);
                    }
                    prop = next;
                }
                icalcompiter ci =
                    icalcomponent_begin_component(comp, ICAL_ANY_COMPONENT);
                icalcomponent *subcomp = icalcompiter_deref(&ci);
                while (subcomp) {
                    icalcomponent *next = icalcompiter_next(&ci);
                    if (is_known_comp(comp, subcomp)) {
                        icalcomponent_remove_component(comp, subcomp);
                    }
                    subcomp = next;
                }
            }

            json_decref(jcal);
        }
    }

    if (!comp && want_kind != ICAL_ANY_COMPONENT && (flags & GET_ICAL_CREATE))
        comp = icalcomponent_new(want_kind);

    return comp;
}

static icalproperty *jobj_get_icalprop(jscalendar_cfg_t *cfg,
                                       json_t *jobj,
                                       const char *proppath,
                                       icalproperty_kind want_kind,
                                       enum get_ical_flags flags)
{
    icalproperty *prop = NULL;

    if (!cfg->use_icalendar_convprops) {
        if (want_kind != ICAL_ANY_PROPERTY && (flags & GET_ICAL_CREATE)) {
            prop = icalproperty_new(want_kind);
        }
        return prop;
    }

    json_t *jcomp = json_object_get(jobj, "iCalendar");
    if (jcomp) {
        json_t *jconvprops = json_object_get(jcomp, "convertedProperties");
        if (jconvprops) {
            json_t *jconvprop = json_object_get(jconvprops, proppath);
            if (jconvprop) {
                prop = jicalproperty_to_icalproperty(jconvprop);
                if (want_kind != ICAL_ANY_PROPERTY
                    && icalproperty_isa(prop) != want_kind) {
                    if (prop) icalproperty_free(prop);
                    prop = NULL;
                }
                if (prop && (!(flags & GET_ICAL_KEEPKNOWN))) {
                    // Remove known parameters.
                    icalparamiter pi =
                        icalproperty_begin_parameter(prop, ICAL_ANY_PARAMETER);
                    icalparameter *param = icalparamiter_deref(&pi);
                    while (param) {
                        icalparameter *next = icalparamiter_next(&pi);
                        if (is_known_param(prop, param)) {
                            icalproperty_remove_parameter_by_ref(prop, param);
                        }
                        param = next;
                    }
                }
                if (prop) {
                    // Always omit VALUE parameter.
                    icalproperty_remove_parameter_by_kind(prop,
                                                          ICAL_VALUE_PARAMETER);
                }
            }
        }
    }

    if (!prop && want_kind != ICAL_ANY_PROPERTY && (flags & GET_ICAL_CREATE))
        prop = icalproperty_new(want_kind);

    return prop;
}

// ---------------

static const char *const JSCAL_UUID5NAMESPACE =
    "7f1e1965-ae73-4454-b088-232c90730ce2";

static void myicalproperty_make_uuid5(icalproperty *prop, struct buf *buf)
{
    const char *s = icalproperty_get_value_as_string(prop);
    buf_setcstr(
        buf,
        makeuuid5(JSCAL_UUID5NAMESPACE, (const unsigned char *) s, strlen(s)));
    buf_cstring(buf);
}

static void jsid_to_prop(icalproperty *prop, const char *key, bool force)
{
    if (force) {
        icalproperty_add_parameter(prop, myicalparameter_new_jsid(key));
        return;
    }

    struct buf buf = BUF_INITIALIZER;
    myicalproperty_make_uuid5(prop, &buf);
    bool is_derived = !strcmp(key, buf_cstring(&buf));
    buf_free(&buf);
    if (!is_derived) {
        icalproperty_add_parameter(prop, myicalparameter_new_jsid(key));
    }
}

static bool prop_has_jsid(icalproperty *prop)
{
    return myicalproperty_get_parameter_by_name(prop, "JSID") ||
           myicalproperty_get_parameter_by_name(prop, "X-JMAP-ID");
}

static const char *jsid_from_prop(icalproperty *prop,
                                  json_t *jobj,
                                  struct buf *buf)
{
    // Use JSID parameter value, if set.
    const char *jsid = NULL;
    icalparameter *param = myicalproperty_get_parameter_by_name(prop, "JSID");
    if (param) jsid = icalparameter_get_iana(param);
    if (!jsid) {
        param = myicalproperty_get_parameter_by_name(prop, "X-JMAP-ID");
        if (param) jsid = icalparameter_get_x(param);
    }
    if (jsid && !json_object_get(jobj, jsid)) {
        buf_setcstr(buf, jsid);
        return buf_cstring(buf);
    }

    // Generate UUIDv5 from property value.
    myicalproperty_make_uuid5(prop, buf);
    if (!json_object_get(jobj, buf_cstring(buf))) {
        return buf_cstring(buf);
    }

    // Generating random UUIDv4.
    buf_setcstr(buf, makeuuid());
    return buf_cstring(buf);
}

static void jsid_to_comp(icalcomponent *comp, const char *jsid)
{
    struct buf buf = BUF_INITIALIZER;

    if (icalcomponent_isa(comp) == ICAL_PARTICIPANT_COMPONENT) {
        // Omit JSID property if it is derived from CALENDAR-ADDRESS property.
        icalproperty *prop =
            myicalcomponent_get_property(comp, ICAL_CALENDARADDRESS_PROPERTY);
        if (prop) {
            buf_reset(&buf);
            myicalproperty_make_uuid5(prop, &buf);
            if (!strcmp(jsid, buf_cstring(&buf))) goto done;
        }
    }

    // Omit JSID property if it is derived from UID property.
    const char *uid = icalcomponent_get_uid(comp);
    if (uid) {
        bool derived_from_uid = !strcmp(uid, jsid);
        if (!derived_from_uid) {
            buf_reset(&buf);
            if (!charset_decode(&buf, jsid, strlen(jsid), ENCODING_BASE64URL)) {
                derived_from_uid = !strcmp(uid, buf_cstring(&buf));
            }
        }
        if (derived_from_uid) goto done;
    }
    else if (is_usable_uid(jsid)) {
        // Omit JSID property and instead set UID if the component does not
        // have a UID property and the key is reasonable to use as UID.
        icalcomponent_add_property(comp, icalproperty_new_uid(jsid));
        goto done;
    }

    icalcomponent_add_property(comp, myicalproperty_new_jsid(jsid));

done:
    buf_free(&buf);
}

static bool comp_has_jsid(icalcomponent *prop)
{
    return myicalcomponent_get_property_by_name(prop, "JSID") ||
           myicalcomponent_get_property_by_name(prop, "X-JMAP-ID");
}

static const char *jsid_from_comp(icalcomponent *comp,
                                  json_t *jobj,
                                  struct buf *buf)
{
    buf_reset(buf);

    // Use JSID property value, if set.
    icalproperty *prop = myicalcomponent_get_property_by_name(comp, "JSID");
    if (!prop) prop = myicalcomponent_get_property_by_name(comp, "X-JMAP-ID");
    if (prop) {
        const char *jsid = icalproperty_get_value_as_string(prop);
        if (jsid && !json_object_get(jobj, jsid)) {
            buf_setcstr(buf, jsid);
            return buf_cstring(buf);
        }
    }

    if (icalcomponent_isa(comp) == ICAL_PARTICIPANT_COMPONENT) {
        // Generate UUIDv5 from CALENDAR-ADDRESS property.
        prop =
            myicalcomponent_get_property(comp, ICAL_CALENDARADDRESS_PROPERTY);
        if (prop) {
            myicalproperty_make_uuid5(prop, buf);
            if (!json_object_get(jobj, buf_cstring(buf))) {
                return buf_cstring(buf);
            }
        }
    }

    // Use UID property value, either verbatim or base64-encoded.
    const char *uid = icalcomponent_get_uid(comp);
    if (uid) {
        if (jmap_is_valid_id(uid) && is_usable_uid(uid)) {
            buf_setcstr(buf, uid);
        }
        else {
            charset_encode(buf, uid, strlen(uid), ENCODING_BASE64URL);
        }

        if (buf_len(buf) && !json_object_get(jobj, buf_cstring(buf))) {
            return buf_cstring(buf);
        }
    }

    // Generate a UUID5 for the normalized iCalendar and our custom namespace.
    icalcomponent *mycomp = icalcomponent_clone(comp);
    icalcomponent_normalize(mycomp);
    const char *s = icalcomponent_as_ical_string(mycomp);
    icalcomponent_free(mycomp);

    const char *key =
        makeuuid5(JSCAL_UUID5NAMESPACE, (const unsigned char *) s, strlen(s));
    if (key && !json_object_get(jobj, key)) {
        buf_setcstr(buf, key);
        return buf_cstring(buf);
    }

    // Fallback generating some random UUID4.
    buf_setcstr(buf, makeuuid());
    return buf_cstring(buf);
}

// ---------------

static void relatedto_to_ical(jscalendar_cfg_t *cfg __attribute__((unused)),
                              json_t *jobj,
                              icalcomponent *comp,
                              const char *(*keytouid)(const char *, void *),
                              void *rock)
{
    json_t *jrelto = json_object_get(jobj, "relatedTo");
    if (!json_object_size(jrelto)) return;

    const char *key;
    json_t *jrelobj;
    json_object_foreach(jrelto, key, jrelobj)
    {
        // Convert key to RELATED-TO value.
        const char *uid = keytouid ? keytouid(key, rock) : key;
        if (!uid) continue;

        json_t *jrels = json_object_get(jrelobj, "relation");
        if (json_object_size(jrels)) {
            // RELATED-TO only allows one RELTYPE parameter, but may occur
            // multiple times for the same property value. In contrast,
            // relatedTo only allows a key to occur once but supports
            // multiple relation types. Convert each Relation object
            // to multiple RELATED-TO properties having the same value.
            for (void *it = json_object_iter(jrels); it;
                 it = json_object_iter_next(jrels, it))
            {
                const char *reltype = json_object_iter_key(it);
                icalparameter *param = icalparameter_new_from_value_string(
                    ICAL_RELTYPE_PARAMETER, reltype);
                if (param) {
                    icalproperty *prop = icalproperty_new_relatedto(uid);
                    icalproperty_add_parameter(prop, param);
                    icalcomponent_add_property(comp, prop);
                }
            }
        }
        else {
            icalcomponent_add_property(comp, icalproperty_new_relatedto(uid));
        }
    }
}

static bool jobject_has_xprops(json_t *jobj)
{
    for (void *it = json_object_iter(jobj); it;
         it = json_object_iter_next(jobj, it))
    {
        if (strchr(json_object_iter_key(it), ':')) return true;
    }
    return false;
}

static bool vendorexts_to_ical(jscalendar_cfg_t *cfg __attribute__((unused)),
                               json_t *jobj,
                               struct jmap_parser *parser,
                               icalcomponent *comp)
{
    const char *name;
    json_t *jval;
    struct jmap_parser myparser = JMAP_PARSER_INITIALIZER;
    if (!parser) parser = &myparser;
    bool did_write = false;

    json_object_foreach(jobj, name, jval)
    {
        if (!strchr(name, ':')) continue;

        char *val = json_dumps(jval, JSON_ENCODE_ANY | JSON_COMPACT);
        icalproperty *prop = myicalproperty_new_jsprop(val);
        icalproperty_add_parameter(
            prop, myicalparameter_new_jsptr(jmap_parser_path_at(parser, name)));
        icalcomponent_add_property(comp, prop);
        free(val);

        did_write = true;
    }

    jmap_parser_fini(&myparser);
    return did_write;
}

static const char *alerts_relatedto_to_ical_cb(const char *key, void *rock)
{
    hash_table *valarm_by_jsid = rock;
    icalcomponent *valarm = hash_lookup(key, valarm_by_jsid);
    return icalcomponent_get_uid(valarm);
}

static void alerts_to_ical(jscalendar_cfg_t *cfg,
                           json_t *jobj,
                           icalcomponent *comp)
{
    json_t *jalerts = json_object_get(jobj, "alerts");
    if (!json_object_size(jalerts)) return;

    hash_table valarm_by_jsid = HASH_TABLE_INITIALIZER;
    construct_hash_table(&valarm_by_jsid, json_object_size(jalerts) + 1, 0);

    // Initialize VALARMs, including their UID property.
    const char *key;
    json_t *jalert;
    json_object_foreach(jalerts, key, jalert)
    {
        // Ignore Alerts with unknown trigger types.
        json_t *jtrigger = json_object_get(jalert, "trigger");
        const char *typ = json_string_value(json_object_get(jtrigger, "@type"));
        if (typ && strcmp(typ, "OffsetTrigger")
            && strcmp(typ, "AbsoluteTrigger"))
            continue;

        icalcomponent *valarm = jobj_get_icalcomp(
            cfg, jalert, ICAL_VALARM_COMPONENT, GET_ICAL_CREATE);
        jsid_to_comp(valarm, key);

        // Set UID, if none set already.
        if (!icalcomponent_get_uid(valarm)) {
            icalcomponent_add_property(valarm,
                                       icalproperty_new_uid(makeuuid()));
        }

        hash_insert(key, valarm, &valarm_by_jsid);
    }

    // Convert alerts.
    json_object_foreach(jalerts, key, jalert)
    {
        icalcomponent *valarm = hash_lookup(key, &valarm_by_jsid);
        if (!valarm) continue;

        json_t *jtrigger = json_object_get(jalert, "trigger");
        const char *typ = json_string_value(json_object_get(jtrigger, "@type"));
        if (!strcmpsafe(typ, "AbsoluteTrigger")) {
            const char *when =
                json_string_value(json_object_get(jtrigger, "when"));
            struct icaltriggertype trigger = {
                icaltime_null_time(), icaldurationtype_null_duration()
            };
            trigger.time = utctime_to_icaltime(when);
            icalcomponent_add_property(valarm,
                                       icalproperty_new_trigger(trigger));
        }
        else {
            const char *offset =
                json_string_value(json_object_get(jtrigger, "offset"));
            const char *relative_to =
                json_string_value(json_object_get(jtrigger, "relativeTo"));
            struct icaltriggertype trigger = {
                icaltime_null_time(), icaldurationtype_null_duration()
            };
            if (offset) trigger.duration = icaldurationtype_from_string(offset);
            icalproperty *prop = icalproperty_new_trigger(trigger);
            if (!strcmpsafe(relative_to, "start")) {
                icalproperty_add_parameter(
                    prop, icalparameter_new_related(ICAL_RELATED_START));
            }
            else if (!strcmpsafe(relative_to, "end")) {
                icalproperty_add_parameter(
                    prop, icalparameter_new_related(ICAL_RELATED_END));
            }
            icalcomponent_add_property(valarm, prop);
        }

        json_t *jval;

        if (JNOTNULL(jval = json_object_get(jalert, "acknowledged"))) {
            icaltimetype t = utctime_to_icaltime(json_string_value(jval));
            icalcomponent_add_property(valarm,
                                       icalproperty_new_acknowledged(t));
        }

        relatedto_to_ical(
            cfg, jalert, valarm, alerts_relatedto_to_ical_cb, &valarm_by_jsid);

        // Convert action.
        icalproperty_action was_action = icalproperty_get_action(
            icalcomponent_get_first_property(valarm, ICAL_ACTION_PROPERTY));
        jval = json_object_get(jalert, "action");
        if (!strcasecmpsafe(json_string_value(jval), "email")
            && was_action != ICAL_ACTION_EMAIL)
        {
            icalcomponent_remove_property_by_kind(valarm, ICAL_ACTION_PROPERTY);
            icalcomponent_add_property(
                valarm, icalproperty_new_action(ICAL_ACTION_EMAIL));
            if (!myicalcomponent_get_property(valarm, ICAL_ATTENDEE_PROPERTY)
                && cfg->emailalert_default_uri)
            {
                icalcomponent_add_property(
                    valarm,
                    icalproperty_new_attendee(cfg->emailalert_default_uri));
            }
        }
        else if (was_action == ICAL_ACTION_NONE
                 || was_action == ICAL_ACTION_EMAIL) {
            icalcomponent_remove_property_by_kind(valarm, ICAL_ACTION_PROPERTY);
            icalcomponent_add_property(
                valarm, icalproperty_new_action(ICAL_ACTION_DISPLAY));
            if (!myicalcomponent_get_property(valarm, ICAL_DESCRIPTION_PROPERTY)
                && cfg->displayalert_default_description)
            {
                icalcomponent_add_property(
                    valarm,
                    icalproperty_new_description(
                        cfg->displayalert_default_description));
            }
        }

        vendorexts_to_ical(cfg, jalert, NULL, valarm);
        icalcomponent_add_component(comp, valarm);
    }

    free_hash_table(&valarm_by_jsid, NULL);
}

static void categories_to_ical(jscalendar_cfg_t *cfg __attribute__((unused)),
                               json_t *jobj,
                               icalcomponent *comp)
{
    json_t *jcategories = json_object_get(jobj, "categories");
    if (!json_object_size(jcategories)) return;

    for (void *it = json_object_iter(jcategories); it;
         it = json_object_iter_next(jcategories, it))
    {
        const char *category = json_object_iter_key(it);
        icalproperty *prop = icalproperty_new_concept(category);
        icalcomponent_add_property(comp, prop);
    }
}

static void description_to_ical(jscalendar_cfg_t *cfg,
                                json_t *jobj,
                                icalcomponent *comp)
{
    json_t *jval = json_object_get(jobj, "description");
    if (JNULL(jval)) return;
    const char *desc = json_string_value(jval);

    const char *mtype =
        json_string_value(json_object_get(jobj, "descriptionContentType"));

    icalproperty_kind prop_kind = ICAL_DESCRIPTION_PROPERTY;
    if (mtype && strcasecmp("text/plain", mtype)) {
        prop_kind = ICAL_STYLEDDESCRIPTION_PROPERTY;
    }
    icalproperty *prop =
        jobj_get_icalprop(cfg, jobj, "description", prop_kind, GET_ICAL_CREATE);
    if (prop_kind == ICAL_STYLEDDESCRIPTION_PROPERTY) {
        icalproperty_add_parameter(prop, icalparameter_new_fmttype(mtype));
    }
    icalproperty_set_value(prop, icalvalue_new_text(desc));

    icalcomponent_add_property(comp, prop);
}

static void keywords_to_ical(jscalendar_cfg_t *cfg __attribute__((unused)),
                             json_t *jobj,
                             icalcomponent *comp)
{
    json_t *jkeywords = json_object_get(jobj, "keywords");
    if (!json_object_size(jkeywords)) return;

    for (void *it = json_object_iter(jkeywords); it;
         it = json_object_iter_next(jkeywords, it))
    {
        const char *keyword = json_object_iter_key(it);
        icalproperty *prop = icalproperty_new_categories(keyword);
        icalcomponent_add_property(comp, prop);
    }
}

static void links_to_ical(jscalendar_cfg_t *cfg,
                          json_t *jobj,
                          icalcomponent *comp)
{
    json_t *jlinks = json_object_get(jobj, "links");
    if (!json_object_size(jlinks)) return;
    struct buf buf = BUF_INITIALIZER;

    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    jmap_parser_push(&parser, "links");

    const char *key;
    json_t *jlink;
    json_object_foreach(jlinks, key, jlink)
    {
        jmap_parser_push(&parser, key);

        const char *href = json_string_value(json_object_get(jlink, "href"));

        // Determine which property kind to use, keep using former one.
        icalproperty *prop =
            jobj_get_icalprop(cfg,
                              jobj,
                              jmap_parser_path_at(&parser, "href"),
                              ICAL_ANY_PROPERTY,
                              0);
        if (!prop) {
            if (JNOTNULL(json_object_get(jlink, "display")))
                prop = icalproperty_new(ICAL_IMAGE_PROPERTY);
            else if (JNOTNULL(json_object_get(jlink, "rel")))
                prop = icalproperty_new(ICAL_LINK_PROPERTY);
            else
                prop = icalproperty_new(ICAL_ATTACH_PROPERTY);
        }

        // Determine property value data type and set value.
        if (!strncasecmp("data:", href, 5)
            && icalproperty_isa(prop) != ICAL_LINK_PROPERTY)
        {
            struct buf fmttype = BUF_INITIALIZER;
            const char *s = href + 5;
            const char *p = strchr(s, ';');
            if (p) {
                buf_setmap(&fmttype, s, p - s);
                s = p + 1;
            }

            if (!strncasecmp("base64,", s, 7)) {
                s += 7;
                icalattach *icalatt = icalattach_new_from_data(s, NULL, NULL);
                icalproperty_set_value(prop, icalvalue_new_attach(icalatt));
                icalproperty_add_parameter(
                    prop, icalparameter_new_encoding(ICAL_ENCODING_BASE64));

                if (buf_len(&fmttype)) {
                    icalproperty_add_parameter(
                        prop, icalparameter_new_fmttype(buf_cstring(&fmttype)));
                }
            }
            else {
                icalproperty_set_value(prop, icalvalue_new_uri(href));
            }

            buf_free(&fmttype);
        }
        else {
            icalproperty_set_value(prop, icalvalue_new_uri(href));
        }

        json_t *jval;

        if (JNOTNULL(jval = json_object_get(jlink, "contentType"))) {
            icalproperty_remove_parameter_by_kind(prop, ICAL_FMTTYPE_PARAMETER);
            const char *s = json_string_value(jval);
            icalproperty_add_parameter(prop, icalparameter_new_fmttype(s));
        }

        if (JNOTNULL(jval = json_object_get(jlink, "display"))) {
            icalenumarray *displays = icalenumarray_new(json_object_size(jval));
            icalenumarray_element elem = { 0 };
            for (void *it = json_object_iter(jval); it;
                 it = json_object_iter_next(jval, it))
            {
                icalparameter_display display =
                    icalparameter_string_to_enum(json_object_iter_key(it));
                if (display != ICAL_DISPLAY_NONE) {
                    elem.val = display;
                    icalenumarray_add(displays, &elem);
                }
            }

            if (icalenumarray_size(displays)) {
                icalparameter *param =
                    icalparameter_new(ICAL_DISPLAY_PARAMETER);
                icalparameter_set_display(param, displays);
                icalproperty_add_parameter(prop, param);
            }
            else {
                icalenumarray_free(displays);
            }
        }

        if (JNOTNULL(jval = json_object_get(jlink, "rel"))) {
            const char *rel = json_string_value(jval);
            if (icalproperty_isa(prop) != ICAL_IMAGE_PROPERTY
                || strcasecmp("icon", rel)) {
                icalproperty_add_parameter(prop,
                                           icalparameter_new_linkrel(rel));
            }
        }

        if (JNOTNULL(jval = json_object_get(jlink, "size"))) {
            json_int_t size = json_integer_value(jval);
            buf_reset(&buf);
            buf_printf(&buf, "%" JSON_INTEGER_FORMAT, size);
            icalproperty_add_parameter(
                prop, icalparameter_new_size(buf_cstring(&buf)));
        }

        if (JNOTNULL(jval = json_object_get(jlink, "title"))) {
            const char *title = json_string_value(jval);
            icalproperty_add_parameter(prop, icalparameter_new_label(title));
        }

        // Add property.
        icalcomponent_add_property(comp, prop);
        bool has_vendorexts = vendorexts_to_ical(cfg, jlink, &parser, comp);

        // Set JSID parameter, if required.
        jsid_to_prop(prop, key, has_vendorexts);

        jmap_parser_pop(&parser);
    }

    buf_free(&buf);
    jmap_parser_fini(&parser);
}

static void locations_to_ical(jscalendar_cfg_t *cfg,
                              json_t *jobj,
                              icalcomponent *comp)
{
    json_t *jlocs = json_object_get(jobj, "locations");
    if (!json_object_size(jlocs)) return;

    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    jmap_parser_push(&parser, "locations");

    const char *mainloc_id =
        json_string_value(json_object_get(jobj, "mainLocationId"));
    if (JNULL(json_object_get(json_object_get(jlocs, mainloc_id), "name")))
        mainloc_id = NULL;

    const char *key;
    json_t *jloc;
    json_object_foreach(jlocs, key, jloc)
    {
        jmap_parser_push(&parser, key);

        // Use VLOCATION component if it was set before.
        icalcomponent *vloc =
            jobj_get_icalcomp(cfg, jloc, ICAL_VLOCATION_COMPONENT, 0);

        if (JNOTNULL(json_object_get(jloc, "links"))) {
            if (!vloc) vloc = icalcomponent_new_vlocation();
            links_to_ical(cfg, jloc, vloc);
        }

        json_t *jval;

        if (JNOTNULL(jval = json_object_get(jloc, "locationTypes"))) {
            if (!vloc) vloc = icalcomponent_new_vlocation();
            struct buf buf = BUF_INITIALIZER;
            for (void *iter = json_object_iter(jval); iter;
                 iter = json_object_iter_next(jval, iter))
            {
                if (buf_len(&buf)) buf_putc(&buf, ',');
                buf_appendcstr(&buf, json_object_iter_key(iter));
            }

            if (buf_len(&buf)) {
                icalvalue *val = icalvalue_new_text(buf_cstring(&buf));
                icalproperty *prop =
                    icalproperty_new(ICAL_LOCATIONTYPE_PROPERTY);
                icalproperty_set_value(prop, val);
                icalcomponent_add_property(vloc, prop);
            }

            buf_free(&buf);
        }

        if (JNOTNULL(jval = json_object_get(jloc, "coordinates"))) {
            const char *coords = json_string_value(jval);

            // Convert coordinates to GEO value.
            bool icalgeo_is_lossy = false;
            struct icalgeotype icalgeo =
                geouri_to_icalgeo(coords, &icalgeo_is_lossy);

            // Set GEO property in VEVENT/VTODO, if it was set before.
            icalproperty *maingeo_prop =
                jobj_get_icalprop(cfg,
                                  jobj,
                                  jmap_parser_path_at(&parser, "coordinates"),
                                  ICAL_GEO_PROPERTY,
                                  0);
            if (maingeo_prop) {
                icalproperty_set_value(maingeo_prop,
                                       icalvalue_new_geo(icalgeo));
                if (icalgeo_is_lossy) {
                    icalproperty_add_parameter(
                        maingeo_prop,
                        icalparameter_new_derived(ICAL_DERIVED_TRUE));
                }
                icalcomponent_add_property(comp, maingeo_prop);
            }

            // Set GEO property in VLOCATION, if it was set before.
            icalproperty *prop = jobj_get_icalprop(
                cfg, jloc, "coordinates", ICAL_ANY_PROPERTY, 0);
            if (icalproperty_isa(prop) == ICAL_GEO_PROPERTY) {
                // Set GEO if it was set before.
                icalproperty_set_value(prop, icalvalue_new_geo(icalgeo));
                if (icalgeo_is_lossy) {
                    icalproperty_add_parameter(
                        prop, icalparameter_new_derived(ICAL_DERIVED_TRUE));
                }
                if (!vloc) vloc = icalcomponent_new_vlocation();
                icalcomponent_add_property(vloc, prop);
            }
            else if (prop && !myicalproperty_has_name(prop, "COORDINATES")) {
                icalproperty_free(prop);
                prop = NULL;
            }

            // Set COORDINATES property in VLOCATION.
            if ((!prop && !maingeo_prop) || icalgeo_is_lossy) {
                if (!prop) prop = myicalproperty_new_coordinates(coords);
                if (!vloc) vloc = icalcomponent_new_vlocation();
                icalcomponent_add_property(vloc, prop);
            }
        }

        // Convert any vendor extension properties.
        if (jobject_has_xprops(jloc)) {
            if (!vloc) vloc = icalcomponent_new_vlocation();
            vendorexts_to_ical(cfg, jloc, NULL, vloc);
        }

        // Convert "name" at the very last: we won't create a VLOCATION
        // component unless we had to due to a previous conversion rule.

        if (JNOTNULL(jval = json_object_get(jloc, "name"))) {
            const char *name = json_string_value(jval);
            icalproperty *mainloc_prop = NULL;

            if (!strcmpsafe(key, mainloc_id) || (!mainloc_id && !vloc)) {
                // Set the LOCATION property in the VEVENT/VTODO.
                icalproperty *prop =
                    jobj_get_icalprop(cfg,
                                      jobj,
                                      jmap_parser_path_at(&parser, "name"),
                                      ICAL_LOCATION_PROPERTY,
                                      GET_ICAL_CREATE);
                icalproperty_set_value(prop, icalvalue_new_text(name));
                icalcomponent_add_property(comp, prop);
                mainloc_prop = prop;
                mainloc_id = key;
            }
            else if (!vloc) {
                vloc = icalcomponent_new_vlocation();
            }

            if (vloc) {
                // Set the NAME property in the VLOCATION.
                icalproperty *prop = jobj_get_icalprop(
                    cfg, jloc, "name", ICAL_NAME_PROPERTY, GET_ICAL_CREATE);
                icalproperty_set_value(prop, icalvalue_new_text(name));
                icalcomponent_add_property(vloc, prop);
                if (mainloc_prop) {
                    icalproperty_add_parameter(
                        mainloc_prop,
                        icalparameter_new_derived(ICAL_DERIVED_TRUE));
                }
            }
            else if (mainloc_prop) {
                jsid_to_prop(mainloc_prop, key, false);
            }
        }

        if (vloc && icalcomponent_count_properties(vloc, ICAL_ANY_PROPERTY)) {
            jsid_to_comp(vloc, key);
            // Set UID, if none set already.
            if (!icalcomponent_get_uid(vloc)) {
                icalcomponent_add_property(vloc,
                                           icalproperty_new_uid(makeuuid()));
            }
            icalcomponent_add_component(comp, vloc);
        }

        jmap_parser_pop(&parser);
    }
}

static void participants_to_ical(jscalendar_cfg_t *cfg,
                                 json_t *jobj,
                                 icalcomponent *comp)
{
    // Set ORGANIZER property.
    icalproperty *organizer = NULL;
    json_t *jval;
    if (JNOTNULL(jval = json_object_get(jobj, "organizerCalendarAddress"))) {
        organizer = jobj_get_icalprop(cfg,
                                      jobj,
                                      "organizerCalendarAddress",
                                      ICAL_ORGANIZER_PROPERTY,
                                      GET_ICAL_CREATE);
        const char *caladdr = json_string_value(jval);
        icalproperty_set_value(organizer, icalvalue_new_caladdress(caladdr));
        icalcomponent_add_property(comp, organizer);
    }

    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    jmap_parser_push(&parser, "participants");

    const char *key;
    json_t *jpart;
    json_object_foreach(json_object_get(jobj, "participants"), key, jpart)
    {
        jmap_parser_push(&parser, key);

        // Determine ATTENDEE and CALENDAR-ADDRESS properties.
        icalproperty *attendee = NULL;
        icalproperty *caladdrprop = NULL;

        json_t *jval = json_object_get(jpart, "calendarAddress");
        const char *caladdr = json_string_value(jval);
        if (caladdr) {
            bool is_organizer =
                organizer
                && !strcmp(caladdr, icalproperty_get_organizer(organizer));

            attendee = jobj_get_icalprop(
                cfg,
                jobj,
                jmap_parser_path_at(&parser, "calendarUserAddress"),
                ICAL_ATTENDEE_PROPERTY,
                0);

            // Check if "calendarAddress" was set from CALENDAR-ADDRESS.
            caladdrprop = jobj_get_icalprop(cfg,
                                            jpart,
                                            "calendarAddress",
                                            ICAL_CALENDARADDRESS_PROPERTY,
                                            0);
            if (caladdrprop) {
                icalproperty_set_value(caladdrprop,
                                       icalvalue_new_caladdress(caladdr));
            }

            if (json_object_size(jval =
                                     json_object_get(jpart, "delegatedFrom"))) {
                if (!attendee)
                    attendee = icalproperty_new(ICAL_ATTENDEE_PROPERTY);
                icalstrarray *vals = icalstrarray_new(json_object_size(jval));
                for (void *iter = json_object_iter(jval); iter;
                     iter = json_object_iter_next(jval, iter))
                {
                    const char *uri = json_object_iter_key(iter);
                    icalstrarray_append(vals, uri);
                }
                icalparameter *param =
                    icalparameter_new(ICAL_DELEGATEDFROM_PARAMETER);
                icalparameter_set_delegatedfrom(param, vals);
                icalproperty_add_parameter(attendee, param);
            }

            if (JNOTNULL(jval = json_object_get(jpart, "delegatedTo"))) {
                if (!attendee)
                    attendee = icalproperty_new(ICAL_ATTENDEE_PROPERTY);
                icalstrarray *vals = icalstrarray_new(json_object_size(jval));
                for (void *iter = json_object_iter(jval); iter;
                     iter = json_object_iter_next(jval, iter))
                {
                    const char *uri = json_object_iter_key(iter);
                    icalstrarray_append(vals, uri);
                }
                icalparameter *param =
                    icalparameter_new(ICAL_DELEGATEDTO_PARAMETER);
                icalparameter_set_delegatedto(param, vals);
                icalproperty_add_parameter(attendee, param);
            }

            if (JNOTNULL(jval = json_object_get(jpart, "email"))) {
                if (!attendee)
                    attendee = icalproperty_new(ICAL_ATTENDEE_PROPERTY);
                const char *email = json_string_value(jval);
                icalproperty_add_parameter(attendee,
                                           icalparameter_new_email(email));

                if (is_organizer) {
                    icalproperty_add_parameter(organizer,
                                               icalparameter_new_email(email));
                }
            }

            if (JNOTNULL(jval = json_object_get(jpart, "expectReply"))) {
                if (!attendee)
                    attendee = icalproperty_new(ICAL_ATTENDEE_PROPERTY);
                icalparameter_rsvp rsvp =
                    json_boolean_value(jval) ? ICAL_RSVP_TRUE : ICAL_RSVP_FALSE;
                icalproperty_add_parameter(attendee,
                                           icalparameter_new_rsvp(rsvp));
            }

            if (JNOTNULL(jval = json_object_get(jpart, "kind"))) {
                if (!attendee)
                    attendee = icalproperty_new(ICAL_ATTENDEE_PROPERTY);
                icalparameter_cutype cu =
                    icalparameter_string_to_enum(json_string_value(jval));
                if (cu != ICAL_CUTYPE_NONE) {
                    icalproperty_add_parameter(attendee,
                                               icalparameter_new_cutype(cu));
                }
            }

            if (JNOTNULL(jval = json_object_get(jpart, "memberOf"))) {
                if (!attendee)
                    attendee = icalproperty_new(ICAL_ATTENDEE_PROPERTY);
                icalstrarray *vals = icalstrarray_new(json_object_size(jval));
                for (void *iter = json_object_iter(jval); iter;
                     iter = json_object_iter_next(jval, iter))
                {
                    const char *uri = json_object_iter_key(iter);
                    icalstrarray_append(vals, uri);
                }
                icalparameter *param = icalparameter_new(ICAL_MEMBER_PARAMETER);
                icalparameter_set_member(param, vals);
                icalproperty_add_parameter(attendee, param);
            }

            if (JNOTNULL(jval = json_object_get(jpart, "name"))) {
                if (!attendee)
                    attendee = icalproperty_new(ICAL_ATTENDEE_PROPERTY);
                const char *name = json_string_value(jval);
                icalproperty_add_parameter(attendee,
                                           icalparameter_new_cn(name));

                if (is_organizer) {
                    icalproperty_add_parameter(organizer,
                                               icalparameter_new_cn(name));
                }
            }

            json_t *jpartstat = json_object_get(jpart, "participationStatus");
            json_t *jprogress = json_object_get(jpart, "progress");
            if (JNOTNULL(jpartstat) || JNOTNULL(jprogress)) {
                if (!attendee)
                    attendee = icalproperty_new(ICAL_ATTENDEE_PROPERTY);
                icalparameter_partstat partstat = ICAL_PARTSTAT_NONE;
                const char *ps = json_string_value(jprogress);
                if (!ps) ps = json_string_value(jpartstat);
                if (ps) partstat = icalparameter_string_to_enum(ps);
                if (partstat != ICAL_PARTSTAT_NONE) {
                    icalproperty_add_parameter(
                        attendee, icalparameter_new_partstat(partstat));
                }
            }

            if (JNOTNULL(jval = json_object_get(jpart, "roles"))) {
                icalparameter_role role = ICAL_ROLE_NONE;
                for (void *iter = json_object_iter(jval); iter;
                     iter = json_object_iter_next(jval, iter))
                {
                    const char *s = json_object_iter_key(iter);
                    if (!strcmp("owner", s) && !is_organizer) {
                        role = ICAL_ROLE_X; // will become OWNER
                    }
                    else if (!strcmp("chair", s)) {
                        role = ICAL_ROLE_CHAIR;
                    }
                    else if (!strcmp("required", s)) {
                        if (role > ICAL_ROLE_REQPARTICIPANT)
                            role = ICAL_ROLE_REQPARTICIPANT;
                    }
                    else if (!strcmp("optional", s)) {
                        if (role > ICAL_ROLE_OPTPARTICIPANT)
                            role = ICAL_ROLE_OPTPARTICIPANT;
                    }
                    else if (!strcmp("informational", s)) {
                        if (role > ICAL_ROLE_NONPARTICIPANT)
                            role = ICAL_ROLE_NONPARTICIPANT;
                    }
                }
                if (role != ICAL_ROLE_NONE) {
                    if (!attendee)
                        attendee = icalproperty_new(ICAL_ATTENDEE_PROPERTY);
                    icalparameter *param = icalparameter_new_role(role);
                    if (role == ICAL_ROLE_X) {
                        icalparameter_set_xvalue(param, "OWNER");
                    }
                    icalproperty_add_parameter(attendee, param);
                }
            }

            if (JNOTNULL(jval = json_object_get(jpart, "sentBy"))) {
                if (!attendee)
                    attendee = icalproperty_new(ICAL_ATTENDEE_PROPERTY);
                const char *uri = json_string_value(jval);
                icalproperty_add_parameter(attendee,
                                           icalparameter_new_sentby(uri));

                if (is_organizer) {
                    icalproperty_add_parameter(organizer,
                                               icalparameter_new_sentby(uri));
                }
            }

            if (attendee) {
                icalproperty_set_value(attendee,
                                       icalvalue_new_caladdress(caladdr));
            }
        }

        // Use PARTICIPANT component if it was set before.
        icalcomponent *part =
            jobj_get_icalcomp(cfg, jpart, ICAL_PARTICIPANT_COMPONENT, 0);

        if (JNOTNULL(jval = json_object_get(jpart, "description"))) {
            if (!part) part = icalcomponent_new_participant();
            description_to_ical(cfg, jpart, part);
        }

        if (JNOTNULL(jval = json_object_get(jpart, "links"))) {
            if (!part) part = icalcomponent_new_participant();
            links_to_ical(cfg, jpart, part);
        }

        if (JNOTNULL(jval = json_object_get(jpart, "percentComplete"))) {
            icalproperty *prop =
                jobj_get_icalprop(cfg,
                                  jpart,
                                  "percentComplete",
                                  ICAL_PERCENTCOMPLETE_PROPERTY,
                                  GET_ICAL_CREATE);
            if (!part) part = icalcomponent_new_participant();
            json_int_t percent = json_integer_value(jval);
            icalproperty_set_value(prop, icalvalue_new_integer(percent));
            icalcomponent_add_property(part, prop);
        }

        if (jobject_has_xprops(jpart)) {
            if (!part) part = icalcomponent_new_participant();
            vendorexts_to_ical(cfg, jpart, NULL, part);
        }

        // Convert "name" last, we won't create PARTICIPANT component
        // just for setting the SUMMARY property if ATTENDEE is enough.
        jval = json_object_get(jpart, "name");
        if (JNOTNULL(jval)) {
            if (!attendee && !part) part = icalcomponent_new_participant();
            if (part) {
                icalproperty *prop = jobj_get_icalprop(
                    cfg, jpart, "name", ICAL_SUMMARY_PROPERTY, GET_ICAL_CREATE);
                const char *name = json_string_value(jval);
                icalproperty_set_value(prop, icalvalue_new_text(name));
                icalcomponent_add_property(part, prop);
            }
        }

        // Omit ATTENDEE if ORGANIZER is an exact copy of it.
        if (attendee && organizer
            && !strcmp(icalproperty_get_organizer(organizer),
                       icalproperty_get_attendee(attendee)))
        {
            // Compare the iCalendar parameters and value
            // of the ATTENDEE and ORGANIZER properties.
            icalproperty *props[2] = { icalproperty_clone(organizer),
                                       icalproperty_clone(attendee) };
            icalproperty_normalize(props[0]);
            icalproperty_normalize(props[1]);

            struct buf bufs[2] = { BUF_INITIALIZER, BUF_INITIALIZER };
            buf_setcstr(&bufs[0], icalproperty_as_ical_string(props[0]));
            buf_setcstr(&bufs[1], icalproperty_as_ical_string(props[1]));

            const char *ical_orga = buf_cstring(&bufs[0]);
            if (!strncasecmp(ical_orga, "ORGANIZER", 9)) ical_orga += 9;

            const char *ical_attd = buf_cstring(&bufs[1]);
            if (!strncasecmp(ical_attd, "ATTENDEE", 8)) ical_attd += 8;

            if (!strcmp(ical_orga, ical_attd)) {
                // All parameters and value match, omit ATTENDEE.
                icalproperty_free(attendee);
                attendee = NULL;
            }

            icalproperty_free(props[0]);
            icalproperty_free(props[1]);
            buf_free(&bufs[0]);
            buf_free(&bufs[1]);
        }

        // Make sure either ATTENDEE or PARTICIPANT is set.
        if (caladdr && !attendee && !part) {
            attendee = icalproperty_new_attendee(caladdr);
        }

        // Add ATTENDEE property.
        if (attendee) icalcomponent_add_property(comp, attendee);

        // Add PARTICIPANT component.
        if (part) {
            if (attendee && !caladdrprop) {
                const char *caladdr = icalproperty_get_attendee(attendee);
                caladdrprop = icalproperty_new_calendaraddress(caladdr);
            }
            if (caladdrprop) icalcomponent_add_property(part, caladdrprop);
            icalcomponent_add_component(comp, part);
        }

        // Set object key in iCalendar. Prefer setting it
        // only on PARTICIPANT, possibly reusing its CALENDAR-ADDRESS
        // or UID property. Otherwise set key on ATTENDEE or ORGANIZER.
        if (attendee && !caladdrprop) jsid_to_prop(attendee, key, false);
        if (part) jsid_to_comp(part, key);
        if (organizer && !attendee && !caladdrprop)
            jsid_to_prop(organizer, key, false);

        // Set UID, if none set already.
        if (part && !icalcomponent_get_uid(part)) {
            icalcomponent_add_property(part, icalproperty_new_uid(makeuuid()));
        }

        jmap_parser_pop(&parser);
    }

    jmap_parser_fini(&parser);
}

static void virtuallocations_to_ical(jscalendar_cfg_t *cfg
                                     __attribute__((unused)),
                                     json_t *jobj,
                                     icalcomponent *comp)
{
    json_t *jvlocs = json_object_get(jobj, "virtualLocations");
    if (!json_object_size(jvlocs)) return;

    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    jmap_parser_push(&parser, "virtualLocations");

    const char *key;
    json_t *jvloc;
    json_object_foreach(jvlocs, key, jvloc)
    {
        jmap_parser_push(&parser, key);

        // Create CONFERENCE property.
        const char *uri = json_string_value(json_object_get(jvloc, "uri"));
        icalproperty *conf =
            jobj_get_icalprop(cfg,
                              jobj,
                              jmap_parser_path_at(&parser, "uri"),
                              ICAL_CONFERENCE_PROPERTY,
                              GET_ICAL_CREATE);
        icalproperty_set_value(conf, icalvalue_new_uri(uri));

        json_t *jval;

        if (json_object_size(jval = json_object_get(jvloc, "features"))) {
            icalenumarray *features = icalenumarray_new(json_object_size(jval));
            icalenumarray_element elem = { 0 };
            for (void *it = json_object_iter(jval); it;
                 it = json_object_iter_next(jval, it))
            {
                icalparameter_feature feature =
                    icalparameter_string_to_enum(json_object_iter_key(it));
                if (feature != ICAL_FEATURE_NONE) {
                    elem.val = feature;
                    icalenumarray_add(features, &elem);
                }
            }

            if (icalenumarray_size(features)) {
                icalparameter *param =
                    icalparameter_new(ICAL_FEATURE_PARAMETER);
                icalparameter_set_feature(param, features);
                icalproperty_add_parameter(conf, param);
            }
            else {
                icalenumarray_free(features);
            }
        }

        if (JNOTNULL(jval = json_object_get(jvloc, "name"))) {
            const char *name = json_string_value(jval);
            icalproperty_add_parameter(conf, icalparameter_new_label(name));
        }

        // Add CONFERENCE property.
        bool has_vendorexts = vendorexts_to_ical(cfg, jvloc, &parser, comp);
        jsid_to_prop(conf, key, has_vendorexts);
        icalcomponent_add_property(comp, conf);

        jmap_parser_pop(&parser);
    }

    jmap_parser_fini(&parser);
}

// ---------------

static void timeprop_set_value(icalproperty *prop,
                               icalvalue_kind value_kind,
                               const char *tzid,
                               icaltimetype *t)
{
    // Detach converted TZID parameter.
    icalparameter *tzid_param =
        myicalproperty_get_parameter(prop, ICAL_TZID_PARAMETER);
    if (tzid_param) {
        tzid_param = icalparameter_clone(tzid_param);
        icalproperty_remove_parameter_by_ref(prop, tzid_param);
    }
    icalproperty_remove_parameter_by_kind(prop, ICAL_VALUE_PARAMETER);

    // Set datetime or date value.
    t->is_date = value_kind == ICAL_DATE_VALUE;
    t->zone = tzid ? icaltimezone_get_cyrus_timezone_from_tzid(tzid) : NULL;
    icalproperty_set_value(prop, icalvalue_new_datetimedate(*t));

    // Set TZID parameter.
    if (tzid && t->zone != icaltimezone_get_utc_timezone()) {
        // Try preserving former TZID parameter.
        if (tzid_param) {
            const char *former_tzid = icalparameter_get_tzid(tzid_param);
            if (!former_tzid
                || icaltimezone_get_cyrus_timezone_from_tzid(former_tzid)
                       != t->zone)
            {
                // Former TZID parameter doesn't resolve to same timezone
                // like the current datetime value. Can't preserve it.
                icalparameter_free(tzid_param);
                tzid_param = NULL;
            }
        }

        if (!tzid_param) {
            tzid_param = icalparameter_new_tzid(tzid);
        }

        icalproperty_add_parameter(prop, tzid_param);
    }
    else if (tzid_param) {
        icalparameter_free(tzid_param);
        tzid_param = NULL;
    }
}

static void timeprops_to_ical(jscalendar_cfg_t *cfg,
                              json_t *jobj,
                              icalcomponent *comp)
{
    json_t *jval;

    icaltimetype start = icaltime_null_time();
    if (JNOTNULL(jval = json_object_get(jobj, "start"))) {
        start = localtime_to_icaltime(json_string_value(jval));
    }

    const char *start_tzid = NULL;
    if (JNOTNULL(jval = json_object_get(jobj, "timeZone"))) {
        start_tzid = json_string_value(jval);
    }

    icaltimetype due = icaltime_null_time();
    if (JNOTNULL(jval = json_object_get(jobj, "due"))) {
        due = localtime_to_icaltime(json_string_value(jval));
    }

    icaltimetype recurid = icaltime_null_time();
    if (JNOTNULL(jval = json_object_get(jobj, "recurrenceId"))) {
        recurid = localtime_to_icaltime(json_string_value(jval));
    }

    const char *recurid_tzid = NULL;
    if (JNOTNULL(jval = json_object_get(jobj, "recurrenceIdTimeZone"))) {
        recurid_tzid = json_string_value(jval);
    }

    struct icaldurationtype duration = icaldurationtype_null_duration();
    if (JNOTNULL(jval = json_object_get(jobj, "duration"))) {
        duration = icaldurationtype_from_string(json_string_value(jval));
    }

    const char *end_tzid = NULL;
    if (JNOTNULL(jval = json_object_get(jobj, "endTimeZone"))) {
        end_tzid = json_string_value(jval);
    }

    struct icaldurationtype estimated_duration =
        icaldurationtype_null_duration();
    if (JNOTNULL(jval = json_object_get(jobj, "estimatedDuration"))) {
        estimated_duration =
            icaldurationtype_from_string(json_string_value(jval));
    }

    bool show_without_time = false;
    if (JNOTNULL(jval = json_object_get(jobj, "showWithoutTime"))) {
        show_without_time = json_boolean_value(jval);
    }

    json_t *jrrule = json_object_get(jobj, "recurrenceRule");

    // Determine if to use DATE or DATETIME value type.
    icalvalue_kind value_kind = ICAL_DATETIME_VALUE;
    if (show_without_time && !start_tzid && !end_tzid && !recurid_tzid
        && myicaltime_has_zero_time(start) && myicaltime_has_zero_time(due)
        && myicaltime_has_zero_time(recurid)
        && myicalduration_has_zero_time(duration)
        && myicalduration_has_zero_time(estimated_duration))
    {
        value_kind = ICAL_DATE_VALUE;

        json_t *jrovrs = json_object_get(jobj, "recurrenceOverrides");
        const char *ovrid;
        json_t *jval;
        json_object_foreach(jrovrs, ovrid, jval)
        {
            if (!myicaltime_has_zero_time(localtime_to_icaltime(ovrid))) {
                value_kind = ICAL_DATETIME_VALUE;
                break;
            }
        }
    }

    // Set DTSTART property.
    icalproperty *dtstart =
        jobj_get_icalprop(cfg,
                          jobj,
                          "start",
                          ICAL_DTSTART_PROPERTY,
                          GET_ICAL_KEEPKNOWN | GET_ICAL_CREATE);
    timeprop_set_value(dtstart, value_kind, start_tzid, &start);
    icalcomponent_add_property(comp, dtstart);

    // Set DUE property.
    if (!icaltime_is_null_time(due)) {
        icalproperty *prop =
            jobj_get_icalprop(cfg,
                              jobj,
                              "due",
                              ICAL_DUE_PROPERTY,
                              GET_ICAL_KEEPKNOWN | GET_ICAL_CREATE);
        timeprop_set_value(prop, value_kind, start_tzid, &due);
        icalcomponent_add_property(comp, prop);
    }

    // Set RECURRENCE-ID property.
    if (!icaltime_is_null_time(recurid)) {
        icalproperty *prop =
            jobj_get_icalprop(cfg,
                              jobj,
                              "recurrenceId",
                              ICAL_RECURRENCEID_PROPERTY,
                              GET_ICAL_KEEPKNOWN | GET_ICAL_CREATE);
        timeprop_set_value(prop, value_kind, recurid_tzid, &recurid);
        icalcomponent_add_property(comp, prop);
    }

    // Set DURATION or DTEND property.
    if (!icaldurationtype_is_null_duration(duration)) {
        // Keep using DTEND if it was set originally.
        icalproperty *dtend = jobj_get_icalprop(
            cfg, jobj, "duration", ICAL_DTEND_PROPERTY, GET_ICAL_KEEPKNOWN);
        if (!dtend && (end_tzid && strcmpsafe(start_tzid, end_tzid))) {
            // Must use DTEND if end timezone differs.
            dtend = icalproperty_new(ICAL_DTEND_PROPERTY);
        }
        if (dtend) {
            // Convert start + duration to DTEND.
            if (!end_tzid) end_tzid = start_tzid;
            icaltimezone *utc = icaltimezone_get_utc_timezone();
            icaltimezone *tz_end =
                icaltimezone_get_cyrus_timezone_from_tzid(end_tzid);

            icaltimetype t_start_utc = icaltime_convert_to_zone(start, utc);
            icaltimetype t_end_utc = icalduration_extend(t_start_utc, duration);
            icaltimetype end = icaltime_convert_to_zone(t_end_utc, tz_end);

            timeprop_set_value(dtend, value_kind, end_tzid, &end);
            icalcomponent_add_property(comp, dtend);
        }
        else {
            icalcomponent_add_property(comp,
                                       icalproperty_new_duration(duration));
        }
    }

    // Set ESTIMATED-DURATION property.
    if (!icaldurationtype_is_null_duration(estimated_duration)) {
        icalproperty *prop =
            icalproperty_new_estimatedduration(estimated_duration);
        icalcomponent_add_property(comp, prop);
    }

    // Set SHOW-WITHOUT-TIME property.
    if (show_without_time && value_kind != ICAL_DATE_VALUE) {
        icalcomponent_add_property(comp, myicalproperty_new_showwithouttime(true));
    }

    // Set RRULE property.
    if (JNOTNULL(jrrule)) {
        icaltimezone *tz = NULL;
        if (start_tzid)
            tz = icaltimezone_get_cyrus_timezone_from_tzid(start_tzid);
        struct icalrecurrencetype *rrule = rrule_to_ical(jrrule, tz);
        if (rrule) {
            icalcomponent_add_property(comp, icalproperty_new_rrule(rrule));
        }
    }
}

static void entry_to_ical(jscalendar_cfg_t *cfg,
                          json_t *jentry,
                          icalcomponent *ical);

static void sanitize_override_patch(json_t *jpatch)
{
    static const char * const skip_prefixes[] = {
        "@type",
        "method",
        "organizerCalendarAddress",
        "privacy",
        "prodId",
        "recurrenceId",
        "recurrenceIdTimeZone",
        "recurrenceOverrides",
        "recurrenceRule",
        "relatedTo",
        "uid",
        NULL
    };
    strarray_t del_keys = STRARRAY_INITIALIZER;
    const char *pkey;
    json_t *pval;
    json_object_foreach(jpatch, pkey, pval) {
        for (int i = 0; skip_prefixes[i]; i++) {
            if (!strncmp(pkey, skip_prefixes[i], strlen(skip_prefixes[i]))) {
                strarray_append(&del_keys, pkey);
                break;
            }
        }
    }
    for (int i = 0; i < strarray_size(&del_keys); i++) {
        json_object_del(jpatch, strarray_nth(&del_keys, i));
    }
    strarray_fini(&del_keys);
}

static void recuroverrides_to_ical(jscalendar_cfg_t *cfg,
                                   json_t *jentry,
                                   icalcomponent *comp)
{
    json_t *jovrs = json_object_get(jentry, "recurrenceOverrides");
    if (JNULL(jovrs)) return;

    icalcomponent *ical = icalcomponent_get_parent(comp);

    json_t *jmaster = json_copy(jentry);
    json_object_del(jmaster, "recurrenceId");
    json_object_del(jmaster, "recurrenceIdTimeZone");
    json_object_del(jmaster, "recurrenceRule");
    json_object_del(jmaster, "recurrenceOverrides");

    icalproperty *dtstart =
        icalcomponent_get_first_property(comp, ICAL_DTSTART_PROPERTY);
    icalparameter *tzid_master =
        icalproperty_get_first_parameter(dtstart, ICAL_TZID_PARAMETER);
    icaltimetype t_master = icalproperty_get_dtstart(dtstart);

    const char *recurid;
    json_t *jpatch;
    json_object_foreach(jovrs, recurid, jpatch)
    {
        icaltimetype icalrecurid = localtime_to_icaltime(recurid);
        icalrecurid.zone = t_master.zone;
        icalrecurid.is_date = t_master.is_date;
        icalparameter *tzid =
            tzid_master ? icalparameter_clone(tzid_master) : NULL;

        sanitize_override_patch(jpatch);

        if (!json_object_size(jpatch)) {
            struct icaldatetimeperiodtype rdate = { .time = icalrecurid };
            icalproperty *prop = icalproperty_new_rdate(rdate);
            if (tzid) icalproperty_add_parameter(prop, tzid);
            icalcomponent_add_property(comp, prop);
        }
        else if (json_object_get(jpatch, "excluded")) {
            icalproperty *prop = icalproperty_new_exdate(icalrecurid);
            if (tzid) icalproperty_add_parameter(prop, tzid);
            icalcomponent_add_property(comp, prop);
        }
        else {
            json_t *jovr = jmap_patchobject_apply(jmaster, jpatch, NULL, 0);
            if (JNOTNULL(jovr)) {
                icalcomponent *ovrical = icalcomponent_new_vcalendar();
                entry_to_ical(cfg, jovr, ovrical);
                icalcomponent *ovrcomp =
                    icalcomponent_get_first_real_component(ovrical);
                if (ovrcomp) {
                    icalcomponent_remove_component(ovrical, ovrcomp);
                    icalproperty *prop =
                        icalproperty_new_recurrenceid(icalrecurid);
                    if (tzid) icalproperty_add_parameter(prop, tzid);
                    icalcomponent_add_property(ovrcomp, prop);
                    icalcomponent_add_component(ical, ovrcomp);
                }
                icalcomponent_free(ovrical);
            }
            json_decref(jovr);
        }
    }
}

static void entry_to_ical(jscalendar_cfg_t *cfg,
                          json_t *jentry,
                          icalcomponent *ical)
{
    const char *type = json_string_value(json_object_get(jentry, "@type"));
    icalcomponent_kind want_comp_kind;
    if (!strcmpsafe("Event", type)) {
        want_comp_kind = ICAL_VEVENT_COMPONENT;
    }
    else if (!strcmpsafe("Task", type)) {
        want_comp_kind = ICAL_VTODO_COMPONENT;
    }
    else
        return;

    icalcomponent *comp =
        jobj_get_icalcomp(cfg, jentry, want_comp_kind, GET_ICAL_CREATE);
    icalcomponent_add_component(ical, comp);

    bool have_method =
        !!icalcomponent_get_first_property(ical, ICAL_METHOD_PROPERTY);
    bool have_prodid =
        !!icalcomponent_get_first_property(ical, ICAL_PRODID_PROPERTY);

    // Convert properties.

    timeprops_to_ical(cfg, jentry, comp);
    alerts_to_ical(cfg, jentry, comp);
    categories_to_ical(cfg, jentry, comp);
    description_to_ical(cfg, jentry, comp);
    keywords_to_ical(cfg, jentry, comp);
    links_to_ical(cfg, jentry, comp);
    locations_to_ical(cfg, jentry, comp);
    participants_to_ical(cfg, jentry, comp);
    relatedto_to_ical(cfg, jentry, comp, NULL, NULL);
    recuroverrides_to_ical(cfg, jentry, comp);
    virtuallocations_to_ical(cfg, jentry, comp);

    json_t *jval;

    if (JNOTNULL(jval = json_object_get(jentry, "color"))) {
        icalproperty *prop = jobj_get_icalprop(
            cfg, jentry, "color", ICAL_COLOR_PROPERTY, GET_ICAL_CREATE);
        const char *s = json_string_value(jval);
        icalproperty_set_value(prop, icalvalue_new_text(s));
        icalcomponent_add_property(comp, prop);
    }

    if (JNOTNULL(jval = json_object_get(jentry, "created"))) {
        icalproperty *prop = jobj_get_icalprop(
            cfg, jentry, "created", ICAL_CREATED_PROPERTY, GET_ICAL_CREATE);
        icaltimetype t = utctime_to_icaltime(json_string_value(jval));
        icalproperty_set_value(prop, icalvalue_new_datetime(t));
        icalcomponent_add_property(comp, prop);
    }

    if (JNOTNULL(jval = json_object_get(jentry, "freeBusyStatus"))) {
        icalproperty *prop = jobj_get_icalprop(cfg,
                                               jentry,
                                               "freeBusyStatus",
                                               ICAL_TRANSP_PROPERTY,
                                               GET_ICAL_CREATE);
        const char *s = json_string_value(jval);
        enum icalproperty_transp transp = ICAL_TRANSP_OPAQUE;
        if (!strcasecmpsafe(s, "free")) transp = ICAL_TRANSP_TRANSPARENT;
        icalproperty_set_value(prop, icalvalue_new_transp(transp));
        icalcomponent_add_property(comp, prop);
    }

    jval = json_object_get(jentry, "method");
    if (JNOTNULL(jval) && !have_method) {
        icalproperty_method m =
            icalproperty_string_to_method(json_string_value(jval));
        if (m != ICAL_METHOD_NONE) {
            icalcomponent_add_property(ical, icalproperty_new_method(m));
        }
    }

    if (JNOTNULL(jval = json_object_get(jentry, "percentComplete"))) {
        icalproperty *prop = jobj_get_icalprop(cfg,
                                               jentry,
                                               "percentComplete",
                                               ICAL_PERCENTCOMPLETE_PROPERTY,
                                               GET_ICAL_CREATE);
        json_int_t i = json_integer_value(jval);
        icalproperty_set_value(prop, icalvalue_new_integer(i));
        icalcomponent_add_property(comp, prop);
    }

    if (JNOTNULL(jval = json_object_get(jentry, "priority"))) {
        icalproperty *prop = jobj_get_icalprop(
            cfg, jentry, "priority", ICAL_PRIORITY_PROPERTY, GET_ICAL_CREATE);
        json_int_t i = json_integer_value(jval);
        icalproperty_set_value(prop, icalvalue_new_integer(i));
        icalcomponent_add_property(comp, prop);
    }

    if (JNOTNULL(jval = json_object_get(jentry, "privacy"))) {
        icalproperty *prop = jobj_get_icalprop(
            cfg, jentry, "privacy", ICAL_CLASS_PROPERTY, GET_ICAL_CREATE);
        icalproperty_class class = ICAL_CLASS_NONE;
        const char *s = json_string_value(jval);
        if (!strcasecmpsafe("public", s))
            class = ICAL_CLASS_PUBLIC;
        else if (!strcasecmpsafe("private", s))
            class = ICAL_CLASS_PRIVATE;
        else if (!strcasecmpsafe("secret", s))
            class = ICAL_CLASS_CONFIDENTIAL;

        if (class != ICAL_CLASS_NONE) {
            icalproperty_set_class(prop, class);
            icalcomponent_add_property(comp, prop);
        }
    }

    jval = json_object_get(jentry, "prodId");
    if (JNOTNULL(jval) && !have_prodid) {
        const char *s = json_string_value(jval);
        icalcomponent_add_property(ical, icalproperty_new_prodid(s));
    }

    if (icalcomponent_isa(comp) == ICAL_VTODO_COMPONENT)
        jval = json_object_get(jentry, "progress");
    else
        jval = json_object_get(jentry, "status");
    if (JNOTNULL(jval)) {
        const char *s = json_string_value(jval);
        icalproperty_status status = icalproperty_string_to_status(s);
        if (status != ICAL_STATUS_NONE) {
            icalcomponent_add_property(comp, icalproperty_new_status(status));
        }
    }

    if (JNOTNULL(jval = json_object_get(jentry, "sequence"))) {
        icalproperty *prop = jobj_get_icalprop(
            cfg, jentry, "sequence", ICAL_SEQUENCE_PROPERTY, GET_ICAL_CREATE);
        json_int_t i = json_integer_value(jval);
        icalproperty_set_value(prop, icalvalue_new_integer(i));
        icalcomponent_add_property(comp, prop);
    }

    if (JNOTNULL(jval = json_object_get(jentry, "title"))) {
        icalproperty *prop = jobj_get_icalprop(
            cfg, jentry, "title", ICAL_SUMMARY_PROPERTY, GET_ICAL_CREATE);
        const char *s = json_string_value(jval);
        icalproperty_set_value(prop, icalvalue_new_text(s));
        icalcomponent_add_property(comp, prop);
        const char *l = json_string_value(json_object_get(jentry, "locale"));
        if (l) icalproperty_add_parameter(prop, icalparameter_new_language(l));
    }

    if (JNOTNULL(jval = json_object_get(jentry, "uid"))) {
        const char *s = json_string_value(jval);
        icalcomponent_add_property(comp, icalproperty_new_uid(s));
    }

    if (JNOTNULL(jval = json_object_get(jentry, "updated"))) {
        icaltimetype t = utctime_to_icaltime(json_string_value(jval));
        icalcomponent_add_property(comp, icalproperty_new_dtstamp(t));
        // Also reset LAST-MODIFIED property.
        icalcomponent_add_property(comp, icalproperty_new_lastmodified(t));
    }

    // Vendor extension properties.
    vendorexts_to_ical(cfg, jentry, NULL, comp);
}

// ---------------

static bool is_stringset(json_t *jval, strarray_t *enums)
{
    bool is_valid = false;
    void *it = json_object_iter(jval);
    if (it) {
        while (json_object_iter_value(it) == json_true()) {
            const char *s = json_object_iter_key(it);
            if (enums && strarray_find(enums, s, 0) < 0) break;
            it = json_object_iter_next(jval, it);
        }
        is_valid = it == NULL;
    }
    return is_valid;
}

static bool is_duration(json_t *jval)
{
    bool is_valid = false;
    const char *s = json_string_value(jval);
    if (s) {
        struct icaldurationtype dur = icaldurationtype_from_string(s);
        is_valid = !icaldurationtype_is_bad_duration(dur) && !dur.is_neg;
    }
    return is_valid;
}

static bool is_signedduration(json_t *jval)
{
    bool is_valid = false;
    const char *s = json_string_value(jval);
    if (s) {
        struct icaldurationtype dur = icaldurationtype_from_string(s);
        is_valid = !icaldurationtype_is_bad_duration(dur);
    }
    return is_valid;
}

static bool is_localdatetime(json_t *jval)
{
    bool is_valid = false;
    const char *s = json_string_value(jval);
    if (s) {
        struct tm tm = { 0 };
        const char *p = strptime(s, "%Y-%m-%dT%H:%M:%S", &tm);
        is_valid = p && *p == '\0';
    }
    return is_valid;
}

static bool is_utcdatetime(json_t *jval)
{
    bool is_valid = false;
    const char *s = json_string_value(jval);
    if (s) {
        struct tm tm = { 0 };
        const char *p = strptime(s, "%Y-%m-%dT%H:%M:%S", &tm);
        if (p && *p == 'Z') p++;
        is_valid = p && *p == '\0';
    }
    return is_valid;
}

static bool is_vendorext_key(const char *key)
{
    // TODO this check could be more thoroughly
    return !!strchr(key, ':');
}

static bool is_timezone(json_t *jtzid)
{
    if (json_is_null(jtzid)) return true;
    const char *tzid = json_string_value(jtzid);
    return tzid && !!icaltimezone_get_builtin_timezone(tzid);
}

static json_int_t JMAP_INT_MIN = -(1LL << 53) + 1;
static json_int_t JMAP_INT_MAX = (1LL << 53) - 1;

static bool is_intarray(json_t *jarray, json_int_t min, json_int_t max)
{
    if (!json_is_array(jarray)) return false;
    size_t i;
    json_t *jval;
    json_array_foreach(jarray, i, jval)
    {
        json_int_t v = json_integer_value(jval);
        if (!json_is_integer(jval) || v < min || v > max) return false;
    }
    return true;
}

static void validate_jicalproperty(struct jmap_parser *parser, json_t *jprop)
{
    if (!json_is_object(jprop)) {
        jmap_parser_invalid(parser, NULL);
        return;
    }

    const char *key;
    json_t *jval;
    json_object_foreach(jprop, key, jval)
    {
        if (!strcmp("@type", key)) {
            if (strcmpsafe("ICalProperty", json_string_value(jval)))
                jmap_parser_invalid(parser, key);
        }
        else if (!strcmp("name", key)) {
            if (!json_is_string(jval)) jmap_parser_invalid(parser, key);
        }
        else if (!strcmp("parameters", key)) {
            if (!json_is_object(jval)) jmap_parser_invalid(parser, key);
        }
        else if (!strcmp("valueType", key)) {
            if (!json_is_string(jval)) jmap_parser_invalid(parser, key);
        }
        else {
            jmap_parser_invalid(parser, key);
        }
    }
}

static void validate_jicalcomponent(struct jmap_parser *parser, json_t *jcomp)
{
    if (!json_is_object(jcomp)) {
        jmap_parser_invalid(parser, NULL);
        return;
    }

    const char *key;
    json_t *jval;
    json_object_foreach(jcomp, key, jval)
    {
        if (!strcmp("@type", key)) {
            if (strcmpsafe("ICalComponent", json_string_value(jval)))
                jmap_parser_invalid(parser, key);
        }
        else if (!strcmp("components", key)) {
            if (!json_is_array(jval)) jmap_parser_invalid(parser, key);
        }
        else if (!strcmp("convertedProperties", key)) {
            if (json_is_object(jval)) {
                jmap_parser_push(parser, key);
                const char *path;
                json_t *jprop;
                json_object_foreach(jval, path, jprop)
                {
                    jmap_parser_push(parser, path);
                    validate_jicalproperty(parser, jprop);
                    jmap_parser_pop(parser);
                }
                jmap_parser_pop(parser);
            }
            else
                jmap_parser_invalid(parser, key);
        }
        else if (!strcmp("name", key)) {
            if (!json_is_string(jval)) jmap_parser_invalid(parser, key);
        }
        else if (!strcmp("properties", key)) {
            if (!json_is_array(jval)) jmap_parser_invalid(parser, key);
        }
        else {
            jmap_parser_invalid(parser, key);
        }
    }
}

static void validate_relatedto(struct jmap_parser *parser, json_t *jrelto)
{
    if (!json_is_object(jrelto)) {
        jmap_parser_invalid(parser, NULL);
        return;
    }

    const char *relkey;
    json_t *jrel;
    json_object_foreach(jrelto, relkey, jrel)
    {
        if (!json_is_object(jrel)) {
            jmap_parser_invalid(parser, relkey);
            continue;
        }

        jmap_parser_push(parser, relkey);

        const char *key;
        json_t *jval;
        json_object_foreach(jrel, key, jval)
        {
            if (!strcmp("@type", key)) {
                if (strcmpsafe("Relation", json_string_value(jval)))
                    jmap_parser_invalid(parser, key);
            }
            else if (!strcmp("relation", key)) {
                if (!json_is_object(jval) ||
                        (json_object_size(jval) && !is_stringset(jval, NULL))) {
                    jmap_parser_invalid(parser, key);
                }
            }
            // Extension properties
            else if (!is_vendorext_key(key)) {
                jmap_parser_invalid(parser, key);
            }
        }

        jmap_parser_pop(parser);
    }
}

static void validate_trigger(struct jmap_parser *parser, json_t *jtrigger)
{
    if (!json_is_object(jtrigger)) {
        jmap_parser_invalid(parser, NULL);
        return;
    }

    const char *type = json_string_value(json_object_get(jtrigger, "@type"));
    bool is_absolute = false;
    bool is_unknown = false;
    if (!strcmpsafe("AbsoluteTrigger", type)) {
        is_absolute = true;
    }
    else if (type && strcmp("OffsetTrigger", type)) {
        is_unknown = true;
    }

    const char *key;
    json_t *jval;
    json_object_foreach(jtrigger, key, jval)
    {
        if (!strcmp("@type", key)) {
            if (!json_is_string(jval)) jmap_parser_invalid(parser, key);
        }
        else if (!strcmp("offset", key)) {
            if (!is_signedduration(jval) || is_absolute)
                jmap_parser_invalid(parser, key);
        }
        else if (!strcmp("relativeTo", key)) {
            if (!json_is_string(jval) || is_absolute)
                jmap_parser_invalid(parser, key);
        }
        else if (!strcmp("when", key)) {
            if (!is_utcdatetime(jval) || !is_absolute)
                jmap_parser_invalid(parser, key);
        }
        // Extension properties
        else if (!is_vendorext_key(key)) {
            jmap_parser_invalid(parser, key);
        }
        else if (!is_unknown) {
            jmap_parser_invalid(parser, key);
        }
    }

    if (!json_object_get(jtrigger, "offset") && !is_absolute && !is_unknown) {
        jmap_parser_invalid(parser, "offset");
    }

    if (!json_object_get(jtrigger, "when") && is_absolute) {
        jmap_parser_invalid(parser, "when");
    }
}

static void validate_alerts(struct jmap_parser *parser, json_t *jalerts)
{
    if (!json_is_object(jalerts)) {
        jmap_parser_invalid(parser, NULL);
        return;
    }

    const char *id;
    json_t *jlink;
    json_object_foreach(jalerts, id, jlink)
    {
        if (!jmap_is_valid_id(id)) {
            jmap_parser_invalid(parser, id);
            continue;
        }

        jmap_parser_push(parser, id);
        const char *key;
        json_t *jval;
        json_object_foreach(jlink, key, jval)
        {
            if (!strcmp("@type", key)) {
                if (strcmpsafe("Alert", json_string_value(jval)))
                    jmap_parser_invalid(parser, key);
            }
            else if (!strcmp("acknowledged", key)) {
                if (!is_utcdatetime(jval)) jmap_parser_invalid(parser, key);
            }
            else if (!strcmp("action", key)) {
                if (!json_is_string(jval)) jmap_parser_invalid(parser, key);
            }
            else if (!strcmp("relatedTo", key)) {
                if (!json_is_null(jval)) {
                    jmap_parser_push(parser, key);
                    validate_relatedto(parser, jval);
                    jmap_parser_pop(parser);
                }
            }
            else if (!strcmp("trigger", key)) {
                if (!json_is_null(jval)) {
                    jmap_parser_push(parser, key);
                    validate_trigger(parser, jval);
                    jmap_parser_pop(parser);
                }
                else {
                    jmap_parser_invalid(parser, key);
                }
            }
            // Extension properties
            else if (!strcmp("iCalendar", key)) {
                if (!json_is_null(jval)) {
                    jmap_parser_push(parser, key);
                    validate_jicalcomponent(parser, jval);
                    jmap_parser_pop(parser);
                }
            }
            else if (!is_vendorext_key(key)) {
                jmap_parser_invalid(parser, key);
            }
        }

        if (!json_object_get(jlink, "trigger")) {
            jmap_parser_invalid(parser, "trigger");
        }

        jmap_parser_pop(parser);
    }
}

static void validate_links(struct jmap_parser *parser, json_t *jlinks)
{
    if (!json_is_object(jlinks)) {
        jmap_parser_invalid(parser, NULL);
        return;
    }

    const char *id;
    json_t *jlink;
    json_object_foreach(jlinks, id, jlink)
    {
        if (!jmap_is_valid_id(id)) {
            jmap_parser_invalid(parser, id);
            continue;
        }

        jmap_parser_push(parser, id);
        const char *key;
        json_t *jval;
        json_object_foreach(jlink, key, jval)
        {
            if (!strcmp("@type", key)) {
                if (strcmpsafe("Link", json_string_value(jval)))
                    jmap_parser_invalid(parser, key);
            }
            else if (!strcmp("contentType", key)) {
                if (!json_is_string(jval)) jmap_parser_invalid(parser, key);
            }
            else if (!strcmp("display", key)) {
                static strarray_t enums = STRARRAY_INITIALIZER;
                if (!strarray_size(&enums)) {
                    strarray_append(&enums, "badge");
                    strarray_append(&enums, "fullsize");
                    strarray_append(&enums, "graphic");
                    strarray_append(&enums, "thumbnail");
                }
                if (!is_stringset(jval, &enums))
                    jmap_parser_invalid(parser, key);
            }
            else if (!strcmp("href", key)) {
                if (!json_is_string(jval)) jmap_parser_invalid(parser, key);
            }
            else if (!strcmp("rel", key)) {
                if (!json_is_string(jval)) jmap_parser_invalid(parser, key);
            }
            else if (!strcmp("size", key)) {
                if (!json_is_integer(jval) || json_integer_value(jval) < 0)
                    jmap_parser_invalid(parser, key);
            }
            else if (!strcmp("title", key)) {
                if (!json_is_string(jval)) jmap_parser_invalid(parser, key);
            }
            // Extension properties
            else if (!is_vendorext_key(key)) {
                jmap_parser_invalid(parser, key);
            }
        }

        if (!json_object_get(jlink, "href")) {
            jmap_parser_invalid(parser, "href");
        }

        jmap_parser_pop(parser);
    }
}

static void validate_locations(struct jmap_parser *parser, json_t *jlocs)
{
    if (!json_is_object(jlocs)) {
        jmap_parser_invalid(parser, NULL);
        return;
    }

    const char *id;
    json_t *jlink;
    json_object_foreach(jlocs, id, jlink)
    {
        if (!jmap_is_valid_id(id)) {
            jmap_parser_invalid(parser, id);
            continue;
        }

        jmap_parser_push(parser, id);
        const char *key;
        json_t *jval;
        json_object_foreach(jlink, key, jval)
        {
            if (!strcmp("@type", key)) {
                if (strcmpsafe("Location", json_string_value(jval)))
                    jmap_parser_invalid(parser, key);
            }
            else if (!strcmp("coordinates", key)) {
                if (!json_is_string(jval)) jmap_parser_invalid(parser, key);
            }
            else if (!strcmp("links", key)) {
                if (!json_is_null(jval)) {
                    jmap_parser_push(parser, key);
                    validate_links(parser, jval);
                    jmap_parser_pop(parser);
                }
            }
            else if (!strcmp("locationTypes", key)) {
                if (!is_stringset(jval, NULL)) jmap_parser_invalid(parser, key);
            }
            else if (!strcmp("name", key)) {
                if (!json_is_string(jval)) jmap_parser_invalid(parser, key);
            }
            // Extension properties
            else if (!strcmp("iCalendar", key)) {
                jmap_parser_push(parser, key);
                validate_jicalcomponent(parser, jval);
                jmap_parser_pop(parser);
            }
            else if (!is_vendorext_key(key)) {
                jmap_parser_invalid(parser, key);
            }
        }

        jmap_parser_pop(parser);
    }
}

static void validate_participants(struct jmap_parser *parser,
                                  const char *entry_type,
                                  json_t *jparts)
{
    if (!json_is_object(jparts)) {
        jmap_parser_invalid(parser, NULL);
        return;
    }

    const char *id;
    json_t *jpart;
    json_object_foreach(jparts, id, jpart)
    {
        if (!jmap_is_valid_id(id)) {
            jmap_parser_invalid(parser, id);
            continue;
        }

        jmap_parser_push(parser, id);
        const char *key;
        json_t *jval;
        json_object_foreach(jpart, key, jval)
        {
            if (!strcmp("@type", key)) {
                if (strcmpsafe("Participant", json_string_value(jval)))
                    jmap_parser_invalid(parser, key);
            }
            else if (!strcmp("calendarAddress", key)) {
                if (!json_is_string(jval)) jmap_parser_invalid(parser, key);
            }
            else if (!strcmp("delegatedFrom", key)) {
                if (!is_stringset(jval, NULL)) jmap_parser_invalid(parser, key);
            }
            else if (!strcmp("delegatedTo", key)) {
                if (!is_stringset(jval, NULL)) jmap_parser_invalid(parser, key);
            }
            else if (!strcmp("description", key)) {
                if (!json_is_string(jval)) jmap_parser_invalid(parser, key);
            }
            else if (!strcmp("descriptionContentType", key)) {
                if (!json_is_string(jval)) jmap_parser_invalid(parser, key);
            }
            else if (!strcmp("email", key)) {
                if (!json_is_string(jval)) jmap_parser_invalid(parser, key);
            }
            else if (!strcmp("expectReply", key)) {
                if (!json_is_boolean(jval)) jmap_parser_invalid(parser, key);
            }
            else if (!strcmp("kind", key)) {
                if (!json_is_string(jval)) jmap_parser_invalid(parser, key);
            }
            else if (!strcmp("links", key)) {
                if (!json_is_null(jval)) {
                    jmap_parser_push(parser, key);
                    validate_links(parser, jval);
                    jmap_parser_pop(parser);
                }
            }
            else if (!strcmp("memberOf", key)) {
                if (!is_stringset(jval, NULL)) jmap_parser_invalid(parser, key);
            }
            else if (!strcmp("name", key)) {
                if (!json_is_string(jval)) jmap_parser_invalid(parser, key);
            }
            else if (!strcmp("participationStatus", key)) {
                if (!json_is_string(jval)) jmap_parser_invalid(parser, key);
            }
            else if (!strcmp("percentComplete", key)
                     && !strcmpsafe("Task", entry_type)) {
                json_int_t v = json_integer_value(jval);
                if (!json_is_integer(jval) || v < 0 || v > 100)
                    jmap_parser_invalid(parser, key);
            }
            else if (!strcmp("progress", key)
                     && !strcmpsafe("Task", entry_type)) {
                if (!json_is_string(jval)) jmap_parser_invalid(parser, key);
            }
            else if (!strcmp("roles", key)) {
                if (!is_stringset(jval, NULL)) jmap_parser_invalid(parser, key);
            }
            else if (!strcmp("sentBy", key)) {
                if (!json_is_string(jval)) jmap_parser_invalid(parser, key);
            }
            // Extension properties
            else if (!strcmp("iCalendar", key)) {
                jmap_parser_push(parser, key);
                validate_jicalcomponent(parser, jval);
                jmap_parser_pop(parser);
            }
            else if (!is_vendorext_key(key)) {
                jmap_parser_invalid(parser, key);
            }
        }

        if (!json_object_get(jpart, "calendarAddress")
            && (json_object_get(jpart, "kind")
                || json_object_get(jpart, "roles")
                || json_object_get(jpart, "participationStatus")
                || json_object_get(jpart, "expectReply")
                || json_object_get(jpart, "sentBy")
                || json_object_get(jpart, "delegatedTo")
                || json_object_get(jpart, "delegatedFrom")
                || json_object_get(jpart, "memberOf")))
        {
            jmap_parser_invalid(parser, "calendarAddress");
        }

        jmap_parser_pop(parser);
    }
}

static void validate_virtuallocations(struct jmap_parser *parser,
                                      json_t *jvlocs)
{
    if (!json_is_object(jvlocs)) {
        jmap_parser_invalid(parser, NULL);
        return;
    }

    const char *id;
    json_t *jlink;
    json_object_foreach(jvlocs, id, jlink)
    {
        if (!jmap_is_valid_id(id)) {
            jmap_parser_invalid(parser, id);
            continue;
        }

        jmap_parser_push(parser, id);
        const char *key;
        json_t *jval;
        json_object_foreach(jlink, key, jval)
        {
            if (!strcmp("@type", key)) {
                if (strcmpsafe("VirtualLocation", json_string_value(jval)))
                    jmap_parser_invalid(parser, key);
            }
            else if (!strcmp("features", key)) {
                static strarray_t enums = STRARRAY_INITIALIZER;
                if (!strarray_size(&enums)) {
                    strarray_append(&enums, "audio");
                    strarray_append(&enums, "chat");
                    strarray_append(&enums, "feed");
                    strarray_append(&enums, "moderator");
                    strarray_append(&enums, "phone");
                    strarray_append(&enums, "screen");
                    strarray_append(&enums, "video");
                }
                if (!is_stringset(jval, &enums))
                    jmap_parser_invalid(parser, key);
            }
            else if (!strcmp("name", key)) {
                if (!json_is_string(jval)) jmap_parser_invalid(parser, key);
            }
            else if (!strcmp("uri", key)) {
                if (!json_is_string(jval)) jmap_parser_invalid(parser, key);
            }
            // Extension properties
            else if (!is_vendorext_key(key)) {
                jmap_parser_invalid(parser, key);
            }
        }

        if (!json_object_get(jlink, "uri")) {
            jmap_parser_invalid(parser, "uri");
        }

        jmap_parser_pop(parser);
    }
}

static void validate_recurrencerule_nday(struct jmap_parser *parser,
                                         json_t *jnday)
{
    if (!json_is_object(jnday)) {
        jmap_parser_invalid(parser, NULL);
        return;
    }

    const char *key;
    json_t *jval;
    json_object_foreach(jnday, key, jval)
    {
        if (!strcmp("@type", key)) {
            if (strcmpsafe("NDay", json_string_value(jval)))
                jmap_parser_invalid(parser, key);
        }
        else if (!strcmp("day", key)) {
            static strarray_t enums = STRARRAY_INITIALIZER;
            if (!strarray_size(&enums)) {
                strarray_append(&enums, "mo");
                strarray_append(&enums, "tu");
                strarray_append(&enums, "we");
                strarray_append(&enums, "th");
                strarray_append(&enums, "fr");
                strarray_append(&enums, "sa");
                strarray_append(&enums, "su");
            }
            const char *s = json_string_value(jval);
            if (!s || strarray_find(&enums, s, 0) < 0)
                jmap_parser_invalid(parser, key);
        }
        else if (!strcmp("nthOfPeriod", key)) {
            json_int_t v = json_integer_value(jval);
            if (!json_is_integer(jval) || v == 0)
                jmap_parser_invalid(parser, key);
        }
        // Extension properties
        else if (!is_vendorext_key(key)) {
            jmap_parser_invalid(parser, key);
        }
    }

    if (!json_object_get(jnday, "day")) {
        jmap_parser_invalid(parser, "day");
    }
}

static void validate_recurrencerule(struct jmap_parser *parser, json_t *jrrule)
{
    if (!json_is_object(jrrule)) {
        jmap_parser_invalid(parser, NULL);
        return;
    }

    const char *key;
    json_t *jval;
    json_object_foreach(jrrule, key, jval)
    {
        if (!strcmp("@type", key)) {
            if (strcmpsafe("RecurrenceRule", json_string_value(jval)))
                jmap_parser_invalid(parser, key);
        }
        else if (!strcmp("byDay", key)) {
            if (json_is_array(jval)) {
                size_t i = 0;
                json_t *jnday;
                json_array_foreach(jval, i, jnday)
                {
                    jmap_parser_push_index(parser, key, i, NULL);
                    validate_recurrencerule_nday(parser, jnday);
                    jmap_parser_pop(parser);
                }
                if (i < json_array_size(jval)) jmap_parser_invalid(parser, key);
            }
            else if (!json_is_null(jval)) {
                jmap_parser_invalid(parser, key);
            }
        }
        else if (!strcmp("byHour", key)) {
            if (!json_is_null(jval) && !is_intarray(jval, 0, 23))
                jmap_parser_invalid(parser, key);
        }
        else if (!strcmp("byMinute", key)) {
            if (!json_is_null(jval) && !is_intarray(jval, 0, 59))
                jmap_parser_invalid(parser, key);
        }
        else if (!strcmp("byMonth", key)) {
            if (json_is_array(jval)) {
                size_t i = 0;
                json_t *jmonth;
                json_array_foreach(jval, i, jmonth)
                {
                    const char *s = json_string_value(jmonth);
                    if (!s) break;
                    uint32_t month = 0;
                    const char *p = NULL;
                    if (parseuint32(s, &p, &month) < 0
                        || (p[0] && (p[0] != 'L' || p[1])))
                        break;
                }
                if (i < json_array_size(jval)) jmap_parser_invalid(parser, key);
            }
            else if (!json_is_null(jval)) {
                jmap_parser_invalid(parser, key);
            }
        }
        else if (!strcmp("byMonthDay", key)) {
            if (!json_is_null(jval)
                && !is_intarray(jval, JMAP_INT_MIN, JMAP_INT_MAX))
                jmap_parser_invalid(parser, key);
        }
        else if (!strcmp("byWeekNo", key)) {
            if (!json_is_null(jval)
                && !is_intarray(jval, JMAP_INT_MIN, JMAP_INT_MAX))
                jmap_parser_invalid(parser, key);
        }
        else if (!strcmp("bySecond", key)) {
            if (!json_is_null(jval) && !is_intarray(jval, 0, 60))
                jmap_parser_invalid(parser, key);
        }
        else if (!strcmp("bySetPosition", key)) {
            if (!json_is_null(jval)
                && !is_intarray(jval, JMAP_INT_MIN, JMAP_INT_MAX))
                jmap_parser_invalid(parser, key);
        }
        else if (!strcmp("byYearDay", key)) {
            if (!json_is_null(jval)
                && !is_intarray(jval, JMAP_INT_MIN, JMAP_INT_MAX))
                jmap_parser_invalid(parser, key);
        }
        else if (!strcmp("count", key)) {
            json_int_t v = json_integer_value(jval);
            if (!json_is_integer(jval) || v < 0)
                jmap_parser_invalid(parser, key);
        }
        else if (!strcmp("firstDayOfWeek", key)) {
            static strarray_t enums = STRARRAY_INITIALIZER;
            if (!strarray_size(&enums)) {
                strarray_append(&enums, "mo");
                strarray_append(&enums, "tu");
                strarray_append(&enums, "we");
                strarray_append(&enums, "th");
                strarray_append(&enums, "fr");
                strarray_append(&enums, "sa");
                strarray_append(&enums, "su");
            }
            const char *s = json_string_value(jval);
            if (!s || strarray_find(&enums, s, 0) < 0)
                jmap_parser_invalid(parser, key);
        }
        else if (!strcmp("frequency", key)) {
            static strarray_t enums = STRARRAY_INITIALIZER;
            if (!strarray_size(&enums)) {
                strarray_append(&enums, "yearly");
                strarray_append(&enums, "monthly");
                strarray_append(&enums, "weekly");
                strarray_append(&enums, "daily");
                strarray_append(&enums, "hourly");
                strarray_append(&enums, "minutely");
                strarray_append(&enums, "secondly");
            }
            const char *s = json_string_value(jval);
            if (!s || strarray_find(&enums, s, 0) < 0)
                jmap_parser_invalid(parser, key);
        }
        else if (!strcmp("interval", key)) {
            json_int_t v = json_integer_value(jval);
            if (!json_is_integer(jval) || v < 1)
                jmap_parser_invalid(parser, key);
        }
        else if (!strcmp("rscale", key)) {
            if (!json_is_string(jval)) jmap_parser_invalid(parser, key);
        }
        else if (!strcmp("skip", key)) {
            static strarray_t enums = STRARRAY_INITIALIZER;
            if (!strarray_size(&enums)) {
                strarray_append(&enums, "omit");
                strarray_append(&enums, "backward");
                strarray_append(&enums, "forward");
            }
            const char *s = json_string_value(jval);
            if (!s || strarray_find(&enums, s, 0) < 0)
                jmap_parser_invalid(parser, key);
        }
        else if (!strcmp("until", key)) {
            if (!is_localdatetime(jval)) jmap_parser_invalid(parser, key);
        }
        // Extension properties
        else if (!is_vendorext_key(key)) {
            jmap_parser_invalid(parser, key);
        }
    }

    if (!json_object_get(jrrule, "frequency")) {
        jmap_parser_invalid(parser, "frequency");
    }

    if (json_object_get(jrrule, "count") && json_object_get(jrrule, "until")) {
        jmap_parser_invalid(parser, "count");
        jmap_parser_invalid(parser, "until");
    }
}

static void validate_entry(struct jmap_parser *parser, json_t *jentry);

static void validate_recurrenceoverrides(struct jmap_parser *parser,
                                         json_t *jentry,
                                         json_t *jovrs)
{
    if (!json_is_object(jovrs)) {
        jmap_parser_invalid(parser, NULL);
        return;
    }

    json_t *jmaster = json_copy(jentry);
    json_object_del(jmaster, "recurrenceId");
    json_object_del(jmaster, "recurrenceIdTimeZone");
    json_object_del(jmaster, "recurrenceRule");
    json_object_del(jmaster, "recurrenceOverrides");

    const char *recurid;
    json_t *jpatch;
    json_object_foreach(jovrs, recurid, jpatch)
    {
        if (icaltime_is_null_time(localtime_to_icaltime(recurid))) {
            // Invalid recurrence id, skip validating patch-object.
            jmap_parser_invalid(parser, recurid);
            continue;
        }

        // Validate patch-object.
        jmap_parser_push(parser, recurid);
        json_t *jexcl = json_object_get(jpatch, "excluded");
        if (jexcl && (jexcl != json_true() || json_object_size(jpatch) > 1)) {
            // 'excluded' must only be set exlusively and must be 'true'
            jmap_parser_invalid(parser, "excluded");
        }
        else if (!jexcl && json_object_size(jpatch)) {
            // Apply the patch object to produce the recurrence override.
            json_t *jinvalid = json_array();
            json_t *jovr = jmap_patchobject_apply(jmaster, jpatch, jinvalid, 0);
            if (JNOTNULL(jovr) && !json_array_size(jinvalid)) {
                // The patch-object is valid, let's validate if the resulting
                // recurrence override is valid, too.
                struct jmap_parser ovrparser = JMAP_PARSER_INITIALIZER;
                validate_entry(&ovrparser, jovr);
                if (json_array_size(ovrparser.invalid)) {
                    // The override is invalid. Prune the list of invalid
                    // properties and keep only the ones set in the patch.
                    for (size_t i = 0; i < json_array_size(ovrparser.invalid);
                         i++) {
                        const char *invalidpath = json_string_value(
                            json_array_get(ovrparser.invalid, i));
                        const char *patchpath;
                        json_t *jpatchval;
                        // XXX this is O(n*m) where n is the count of invalid
                        // paths and m is the count of paths in the patch.
                        // Both of these should be fairly small.
                        json_object_foreach(jpatch, patchpath, jpatchval)
                        {
                            size_t n = strlen(patchpath);
                            if (!strncmp(patchpath, invalidpath, n)) {
                                if (!invalidpath[n] || invalidpath[n] == '/') {
                                    json_array_append_new(
                                        jinvalid, json_string(invalidpath));
                                }
                            }
                        }
                    }
                }
                jmap_parser_fini(&ovrparser);
            }

            if (json_array_size(jinvalid)) {
                // Either the patch-object is invalid or the resulting override
                // is invalid. Report all invalid paths, prefixed by the path to
                // this override in the recurrenceOverrides property.
                struct buf buf = BUF_INITIALIZER;
                // Set base path.
                buf_setcstr(&buf, jmap_parser_path(parser));
                size_t nbasepath = buf_len(&buf);
                for (size_t i = 0; i < json_array_size(jinvalid); i++) {
                    // Report base path + patch object path as invalid.
                    const char *path =
                        json_string_value(json_array_get(jinvalid, i));
                    if (path[0] != '/') buf_putc(&buf, '/');
                    buf_appendcstr(&buf, path);
                    jmap_parser_invalid_path(parser, buf_cstring(&buf));
                    // Reset buffer to base path.
                    buf_truncate(&buf, nbasepath);
                }
                buf_free(&buf);
            }

            json_decref(jinvalid);
        }

        jmap_parser_pop(parser);
    }
}

static void validate_entry(struct jmap_parser *parser, json_t *jentry)
{
    if (!json_is_object(jentry)) {
        jmap_parser_invalid(parser, NULL);
        return;
    }

    const char *entry_type =
        json_string_value(json_object_get(jentry, "@type"));
    bool is_task = false;
    if (!entry_type) {
        jmap_parser_invalid(parser, "@type");
        return;
    }
    else if (!strcmp("Task", entry_type)) {
        is_task = true;
    }
    else if (strcmp("Event", entry_type)) {
        jmap_parser_invalid(parser, "@type");
        return;
    }

    const char *key;
    json_t *jval;
    json_object_foreach(jentry, key, jval)
    {
        if (!strcmp("@type", key)) {
            if (!json_is_string(jval)) jmap_parser_invalid(parser, key);
        }
        else if (!strcmp("alerts", key)) {
            if (!json_is_null(jval)) {
                jmap_parser_push(parser, key);
                validate_alerts(parser, jval);
                jmap_parser_pop(parser);
            }
        }
        else if (!strcmp("categories", key)) {
            if (!is_stringset(jval, NULL)) jmap_parser_invalid(parser, key);
        }
        else if (!strcmp("color", key)) {
            if (!json_is_string(jval)) jmap_parser_invalid(parser, key);
        }
        else if (!strcmp("created", key)) {
            if (!is_utcdatetime(jval)) jmap_parser_invalid(parser, key);
        }
        else if (!strcmp("description", key)) {
            if (!json_is_string(jval)) jmap_parser_invalid(parser, key);
        }
        else if (!strcmp("descriptionContentType", key)) {
            if (!json_is_string(jval)) jmap_parser_invalid(parser, key);
        }
        else if (!strcmp("due", key)) {
            if (!is_localdatetime(jval) || !is_task)
                jmap_parser_invalid(parser, key);
        }
        else if (!strcmp("duration", key)) {
            if (!is_duration(jval) || is_task) jmap_parser_invalid(parser, key);
        }
        else if (!strcmp("endTimeZone", key)) {
            if (!is_timezone(jval) || is_task) jmap_parser_invalid(parser, key);
        }
        else if (!strcmp("estimatedDuration", key)) {
            if (!is_duration(jval) || !is_task)
                jmap_parser_invalid(parser, key);
        }
        else if (!strcmp("freeBusyStatus", key)) {
            if (!json_is_string(jval)) jmap_parser_invalid(parser, key);
        }
        else if (!strcmp("keywords", key)) {
            if (!is_stringset(jval, NULL)) jmap_parser_invalid(parser, key);
        }
        else if (!strcmp("links", key)) {
            if (!json_is_null(jval)) {
                jmap_parser_push(parser, key);
                validate_links(parser, jval);
                jmap_parser_pop(parser);
            }
        }
        else if (!strcmp("locale", key)) {
            if (!json_is_string(jval)) jmap_parser_invalid(parser, key);
        }
        else if (!strcmp("locations", key)) {
            if (!json_is_null(jval)) {
                jmap_parser_push(parser, key);
                validate_locations(parser, jval);
                jmap_parser_pop(parser);
            }
        }
        else if (!strcmp("mainLocationId", key)) {
            const char *s = json_string_value(jval);
            if (!s || !jmap_is_valid_id(s)) jmap_parser_invalid(parser, key);
        }
        else if (!strcmp("method", key)) {
            if (!json_is_string(jval)) jmap_parser_invalid(parser, key);
        }
        else if (!strcmp("organizerCalendarAddress", key)) {
            if (!json_is_string(jval)) jmap_parser_invalid(parser, key);
        }
        else if (!strcmp("participants", key)) {
            if (!json_is_null(jval)) {
                jmap_parser_push(parser, key);
                validate_participants(parser, entry_type, jval);
                jmap_parser_pop(parser);
            }
        }
        else if (!strcmp("percentComplete", key)) {
            json_int_t v = json_integer_value(jval);
            if (!json_is_integer(jval) || v < 0 || v > 100 || !is_task)
                jmap_parser_invalid(parser, key);
        }
        else if (!strcmp("priority", key)) {
            json_int_t v = json_integer_value(jval);
            if (!json_is_integer(jval) || v < 0 || v > 9)
                jmap_parser_invalid(parser, key);
        }
        else if (!strcmp("privacy", key)) {
            if (!json_is_string(jval)) jmap_parser_invalid(parser, key);
        }
        else if (!strcmp("prodId", key)) {
            if (!json_is_string(jval)) jmap_parser_invalid(parser, key);
        }
        else if (!strcmp("progress", key)) {
            if (!json_is_string(jval) || !is_task)
                jmap_parser_invalid(parser, key);
        }
        else if (!strcmp("recurrenceId", key)) {
            if (!is_localdatetime(jval)) jmap_parser_invalid(parser, key);
        }
        else if (!strcmp("recurrenceIdTimeZone", key)) {
            if (!is_timezone(jval)) jmap_parser_invalid(parser, key);
        }
        else if (!strcmp("recurrenceOverrides", key)) {
            if (!json_is_null(jval)) {
                jmap_parser_push(parser, key);
                validate_recurrenceoverrides(parser, jentry, jval);
                jmap_parser_pop(parser);
            }
        }
        else if (!strcmp("recurrenceRule", key)) {
            if (!json_is_null(jval)) {
                jmap_parser_push(parser, key);
                validate_recurrencerule(parser, jval);
                jmap_parser_pop(parser);
            }
        }
        else if (!strcmp("relatedTo", key)) {
            if (!json_is_null(jval)) {
                jmap_parser_push(parser, key);
                validate_relatedto(parser, jval);
                jmap_parser_pop(parser);
            }
        }
        else if (!strcmp("sequence", key)) {
            json_int_t v = json_integer_value(jval);
            if (!json_is_integer(jval) || v < 0)
                jmap_parser_invalid(parser, key);
        }
        else if (!strcmp("showWithoutTime", key)) {
            if (!json_is_boolean(jval)) jmap_parser_invalid(parser, key);
        }
        else if (!strcmp("start", key)) {
            if (!is_localdatetime(jval)) jmap_parser_invalid(parser, key);
        }
        else if (!strcmp("status", key)) {
            if (!json_is_string(jval) || is_task)
                jmap_parser_invalid(parser, key);
        }
        else if (!strcmp("timeZone", key)) {
            if (!is_timezone(jval) && !json_is_null(jval))
                jmap_parser_invalid(parser, key);
        }
        else if (!strcmp("title", key)) {
            if (!json_is_string(jval)) jmap_parser_invalid(parser, key);
        }
        else if (!strcmp("uid", key)) {
            if (!json_is_string(jval)) jmap_parser_invalid(parser, key);
        }
        else if (!strcmp("updated", key)) {
            if (!is_utcdatetime(jval)) jmap_parser_invalid(parser, key);
        }
        else if (!strcmp("virtualLocations", key)) {
            if (!json_is_null(jval)) {
                jmap_parser_push(parser, key);
                validate_virtuallocations(parser, jval);
                jmap_parser_pop(parser);
            }
        }
        // Extension properties
        else if (!strcmp("iCalendar", key)) {
            if (!json_is_null(jval)) {
                jmap_parser_push(parser, key);
                validate_jicalcomponent(parser, jval);
                jmap_parser_pop(parser);
            }
        }
        // JMAP Calendar properties
        else if (!strcmp("baseEventId", key) ||
                 !strcmp("blobId", key) ||
                 !strcmp("calendarIds", key) ||
                 !strcmp("hideAttendees", key) ||
                 !strcmp("id", key) ||
                 !strcmp("isDraft", key) ||
                 !strcmp("isOrigin", key) ||
                 !strcmp("mayInviteOthers", key) ||
                 !strcmp("mayInviteSelf", key) ||
                 !strcmp("scheduleSequence", key) ||
                 !strcmp("scheduleUpdated", key) ||
                 !strcmp("useDefaultAlerts", key) ||
                 !strcmp("utcStart", key) ||
                 !strcmp("utcEnd", key)) {
            // ignore
        }
        else if (!is_vendorext_key(key)) {
            jmap_parser_invalid(parser, key);
        }
    }

    if (JNOTNULL(json_object_get(jentry, "endTimeZone"))
        && JNULL(json_object_get(jentry, "timeZone")))
    {
        jmap_parser_invalid(parser, "endTimeZone");
    }

    if (json_object_get(jentry, "recurrenceIdTimeZone")
        && !json_object_get(jentry, "recurrenceId"))
    {
        jmap_parser_invalid(parser, "recurrenceIdTimeZone");
    }

    if (json_object_get(jentry, "recurrenceOverrides")
        && (!json_object_get(jentry, "recurrenceRule")
            || json_object_get(jentry, "recurrenceId")))
    {
        jmap_parser_invalid(parser, "recurrenceOverrides");
    }

    if (json_object_get(jentry, "recurrenceRule")
        && json_object_get(jentry, "recurrenceId"))
    {
        jmap_parser_invalid(parser, "recurrenceRule");
    }

    if (!is_task && !json_object_get(jentry, "start")) {
        jmap_parser_invalid(parser, "start");
    }

    if (is_task) {
        if (JNOTNULL(json_object_get(jentry, "timeZone"))
            || json_object_get(jentry, "showWithoutTime") == json_true())
        {
            if (!json_object_get(jentry, "due")
                && !json_object_get(jentry, "start")) {
                jmap_parser_invalid(parser, "due");
                jmap_parser_invalid(parser, "start");
            }
        }
    }
}

static void validate_group(struct jmap_parser *parser, json_t *jgroup)
{
    if (!json_is_object(jgroup)) {
        jmap_parser_invalid(parser, NULL);
        return;
    }

    const char *key;
    json_t *jval;
    json_object_foreach(jgroup, key, jval)
    {
        if (!strcmp("@type", key)) {
            if (strcmpsafe("Group", json_string_value(jval)))
                jmap_parser_invalid(parser, key);
        }
        else if (!strcmp("categories", key)) {
            if (!is_stringset(jval, NULL)) jmap_parser_invalid(parser, key);
        }
        else if (!strcmp("color", key)) {
            if (!json_is_string(jval)) jmap_parser_invalid(parser, key);
        }
        else if (!strcmp("created", key)) {
            if (!is_utcdatetime(jval)) jmap_parser_invalid(parser, key);
        }
        else if (!strcmp("description", key)) {
            if (!json_is_string(jval)) jmap_parser_invalid(parser, key);
        }
        else if (!strcmp("descriptionContentType", key)) {
            if (!json_is_string(jval)) jmap_parser_invalid(parser, key);
        }
        else if (!strcmp("entries", key)) {
            if (json_is_array(jval)) {
                for (size_t i = 0; i < json_array_size(jval); i++) {
                    jmap_parser_push_index(parser, key, i, NULL);
                    validate_entry(parser, json_array_get(jval, i));
                    jmap_parser_pop(parser);
                }
            }
            else {
                jmap_parser_invalid(parser, key);
            }
        }
        else if (!strcmp("keywords", key)) {
            if (!is_stringset(jval, NULL)) jmap_parser_invalid(parser, key);
        }
        else if (!strcmp("links", key)) {
            if (!json_is_null(jval)) {
                jmap_parser_push(parser, key);
                validate_links(parser, jval);
                jmap_parser_pop(parser);
            }
        }
        else if (!strcmp("locale", key)) {
            if (!json_is_string(jval)) jmap_parser_invalid(parser, key);
        }
        else if (!strcmp("prodId", key)) {
            if (!json_is_string(jval)) jmap_parser_invalid(parser, key);
        }
        else if (!strcmp("source", key)) {
            if (!json_is_string(jval)) jmap_parser_invalid(parser, key);
        }
        else if (!strcmp("title", key)) {
            if (!json_is_string(jval)) jmap_parser_invalid(parser, key);
        }
        else if (!strcmp("uid", key)) {
            if (!json_is_string(jval)) jmap_parser_invalid(parser, key);
        }
        else if (!strcmp("updated", key)) {
            if (!is_utcdatetime(jval)) jmap_parser_invalid(parser, key);
        }
        // Extension properties
        else if (!strcmp("iCalendar", key)) {
            jmap_parser_push(parser, key);
            validate_jicalcomponent(parser, jval);
            jmap_parser_pop(parser);
        }
        else if (!is_vendorext_key(key)) {
            jmap_parser_invalid(parser, key);
        }
    }

    if (!json_object_get(jgroup, "entries"))
        jmap_parser_invalid(parser, "entries");
}

static void group_to_ical(jscalendar_cfg_t *cfg,
                          json_t *jgroup,
                          icalcomponent *ical)
{
    json_t *jentries = json_object_get(jgroup, "entries");
    json_t *jentry;
    size_t i;
    json_array_foreach(jentries, i, jentry)
    {
        entry_to_ical(cfg, jentry, ical);
    }

    categories_to_ical(cfg, jgroup, ical);
    description_to_ical(cfg, jgroup, ical);
    keywords_to_ical(cfg, jgroup, ical);
    links_to_ical(cfg, jgroup, ical);

    json_t *jval;

    if (JNOTNULL(jval = json_object_get(jgroup, "color"))) {
        icalproperty *prop = jobj_get_icalprop(
            cfg, jgroup, "color", ICAL_COLOR_PROPERTY, GET_ICAL_CREATE);
        const char *s = json_string_value(jval);
        icalproperty_set_value(prop, icalvalue_new_text(s));
        icalcomponent_add_property(ical, prop);
    }

    if (JNOTNULL(jval = json_object_get(jgroup, "created"))) {
        icalproperty *prop = jobj_get_icalprop(
            cfg, jgroup, "created", ICAL_CREATED_PROPERTY, GET_ICAL_CREATE);
        icaltimetype t = utctime_to_icaltime(json_string_value(jval));
        icalproperty_set_value(prop, icalvalue_new_datetime(t));
        icalcomponent_add_property(ical, prop);
    }

    if (JNOTNULL(jval = json_object_get(jgroup, "prodId"))) {
        icalproperty *prop = jobj_get_icalprop(
            cfg, jgroup, "prodId", ICAL_PRODID_PROPERTY, GET_ICAL_CREATE);
        const char *s = json_string_value(jval);
        icalproperty_set_value(prop, icalvalue_new_text(s));
        icalcomponent_add_property(ical, prop);
    }

    if (JNOTNULL(jval = json_object_get(jgroup, "source"))) {
        icalproperty *prop = jobj_get_icalprop(
            cfg, jgroup, "source", ICAL_SOURCE_PROPERTY, GET_ICAL_CREATE);
        const char *s = json_string_value(jval);
        icalproperty_set_value(prop, icalvalue_new_uri(s));
        icalcomponent_add_property(ical, prop);
    }

    if (JNOTNULL(jval = json_object_get(jgroup, "title"))) {
        icalproperty *prop = jobj_get_icalprop(
            cfg, jgroup, "title", ICAL_NAME_PROPERTY, GET_ICAL_CREATE);
        const char *s = json_string_value(jval);
        icalproperty_set_value(prop, icalvalue_new_text(s));
        icalcomponent_add_property(ical, prop);
        const char *l = json_string_value(json_object_get(jgroup, "locale"));
        if (l) icalproperty_add_parameter(prop, icalparameter_new_language(l));
    }

    if (JNOTNULL(jval = json_object_get(jgroup, "uid"))) {
        const char *s = json_string_value(jval);
        icalcomponent_add_property(ical, icalproperty_new_uid(s));
    }

    if (JNOTNULL(jval = json_object_get(jgroup, "updated"))) {
        icaltimetype t = utctime_to_icaltime(json_string_value(jval));
        icalcomponent_add_property(ical, icalproperty_new_lastmodified(t));
    }

    vendorexts_to_ical(cfg, jgroup, NULL, ical);
}

EXPORTED icalcomponent *jscalendar_to_ical(jscalendar_cfg_t *cfg,
                                           json_t *jobj,
                                           struct jmap_parser *parser)
{
    jscalendar_cfg_t mycfg = { 0 };
    if (!cfg) cfg = &mycfg;

    struct jmap_parser myparser = JMAP_PARSER_INITIALIZER;
    if (!parser) parser = &myparser;

    icalcomponent *ical = NULL;

    const char *type = json_string_value(json_object_get(jobj, "@type"));
    if (!strcasecmpsafe(type, "Group")) {
        validate_group(parser, jobj);
    }
    else {
        validate_entry(parser, jobj);
    }

    if (json_array_size(parser->invalid))
        goto done;

    ical = jobj_get_icalcomp(
        cfg, jobj, ICAL_VCALENDAR_COMPONENT, GET_ICAL_CREATE);
    icalcomponent_add_property(ical, icalproperty_new_version("2.0"));
    icalcomponent_add_property(ical, icalproperty_new_calscale("GREGORIAN"));

    if (!strcasecmpsafe(type, "Group")) {
        group_to_ical(cfg, jobj, ical);
    }
    else {
        entry_to_ical(cfg, jobj, ical);
    }

    icalcomponent_add_required_timezones(ical);

done:
    jmap_parser_fini(&myparser);
    return ical;
}

// ---------------

static json_t *jobj_set_icalcomp_name(jscalendar_cfg_t *cfg,
                                      json_t *jobj,
                                      icalcomponent *comp)
{
    if (!cfg->use_icalendar_convprops) return NULL;

    const char *comp_name = icalcomponent_get_component_name(comp);
    struct buf buf = BUF_INITIALIZER;

    json_t *jcomp = json_object_get(jobj, "iCalendar");
    if (!jcomp) {
        jcomp = json_pack("{s:s}", "@type", "ICalComponent");
        buf_setcstr(&buf, comp_name);
        buf_lcase(&buf);
        json_object_set_new(jcomp, "name", json_string(buf_cstring(&buf)));
        json_object_set_new(jobj, "iCalendar", jcomp);
    }

    buf_free(&buf);
    return jcomp;
}

static json_t *jobj_set_icalcomp(jscalendar_cfg_t *cfg,
                                 json_t *jobj,
                                 icalcomponent *comp)
{
    if (!cfg->use_icalendar_convprops) return NULL;

    json_t *jcomps = json_array();
    json_t *jprops = json_array();
    json_t *jcomp = NULL;

    icalproperty *prop;
    icalpropiter prop_iter;
    myicalcomponent_foreach_property(comp, ICAL_ANY_PROPERTY, prop, prop_iter)
    {
        if (!is_known_prop(comp, prop)) {
            json_array_append_new(jprops, icalproperty_as_jcal_array(prop));
        }
    }

    icalcomponent *subcomp;
    icalcompiter comp_iter;
    myicalcomponent_foreach_component(
        comp, ICAL_ANY_COMPONENT, subcomp, comp_iter)
    {
        if (!is_known_comp(comp, subcomp)) {
            json_array_append_new(jcomps, icalcomponent_as_jcal_array(subcomp));
        }
    }

    if (json_array_size(jcomps) || json_array_size(jprops)) {
        jcomp = jobj_set_icalcomp_name(cfg, jobj, comp);
        if (json_array_size(jcomps))
            json_object_set(jcomp, "components", jcomps);
        if (json_array_size(jprops))
            json_object_set(jcomp, "properties", jprops);
    }

    json_decref(jcomps);
    json_decref(jprops);
    return jcomp;
}

static json_t *jobj_set_icalprop_name(jscalendar_cfg_t *cfg,
                                      json_t *jobj,
                                      const char *key,
                                      icalproperty *prop)
{
    if (!cfg->use_icalendar_convprops) return NULL;

    icalcomponent *comp = icalproperty_get_parent(prop);
    if (!comp) return NULL;

    json_t *jcomp = jobj_set_icalcomp_name(cfg, jobj, comp);
    json_t *jconvprops =
        json_object_get_vanew(jcomp, "convertedProperties", "{}");

    json_t *jicalprop = json_object_get(jconvprops, key);
    if (!jicalprop) {
        jicalprop = json_pack("{s:s}", "@type", "ICalProperty");
        struct buf buf = BUF_INITIALIZER;
        buf_setcstr(&buf, icalproperty_get_property_name(prop));
        json_object_set_new(jicalprop, "name", json_string(buf_lcase(&buf)));
        buf_free(&buf);
        json_object_set_new(jconvprops, key, jicalprop);
    }
    return jicalprop;
}

static json_t *jobj_set_icalprop_valuetype(jscalendar_cfg_t *cfg,
                                           json_t *jobj,
                                           const char *key,
                                           icalproperty *prop)
{
    if (!cfg->use_icalendar_convprops) return NULL;

    json_t *jicalprop = jobj_set_icalprop_name(cfg, jobj, key, prop);
    if (!jicalprop) return NULL;

    struct buf buf = BUF_INITIALIZER;
    buf_setcstr(&buf, icalproperty_value_kind_as_string(prop));
    json_object_set_new(jicalprop, "valueType", json_string(buf_lcase(&buf)));
    buf_free(&buf);

    return jicalprop;
}

static void jobj_set_icalprop_param(jscalendar_cfg_t *cfg,
                                    json_t *jobj,
                                    const char *key,
                                    icalproperty *prop,
                                    icalparameter *param)
{
    if (!cfg->use_icalendar_convprops) return;

    json_t *jicalprop = jobj_set_icalprop_name(cfg, jobj, key, prop);
    json_t *jparams = json_object_get_vanew(jicalprop, "parameters", "{}");
    icalparameter_to_jcal_parameter(param, jparams);
}

static void jobj_set_icalprop_params(jscalendar_cfg_t *cfg,
                                     json_t *jobj,
                                     const char *key,
                                     icalproperty *prop)
{
    if (!cfg->use_icalendar_convprops) return;

    json_t *jparams = json_object();

    icalparameter *param;
    icalparamiter it;
    myicalproperty_foreach_parameter(prop, ICAL_ANY_PARAMETER, param, it)
    {
        if (!is_known_param(prop, param))
            icalparameter_to_jcal_parameter(param, jparams);
    }

    if (json_object_size(jparams)) {
        json_t *jicalprop = jobj_set_icalprop_name(cfg, jobj, key, prop);
        json_object_set(jicalprop, "parameters", jparams);
    }

    json_decref(jparams);
}

static void jobj_set_icalprop(jscalendar_cfg_t *cfg,
                              json_t *jobj,
                              const char *key,
                              json_t *jval,
                              icalproperty *prop)
{
    json_object_set_new(jobj, key, jval);
    jobj_set_icalprop_params(cfg, jobj, key, prop);
}

// ---------------

static void vendorexts_from_ical(icalcomponent *comp, json_t *jobj)
{
    json_t *jpatch = json_object();

    icalproperty *prop;
    icalpropiter iter;
    myicalcomponent_foreach_property(comp, ICAL_IANA_PROPERTY, prop, iter)
    {
        if (!myicalproperty_has_name(prop, "JSPROP")) {
            continue;
        }

        icalparameter *param = myicalproperty_get_parameter_by_name(prop, "JSPTR");
        if (!param) continue;

        const char *ptr = myicalparameter_get_jsptr(param);
        if (!ptr || ptr[0] == '/') continue;

        const char *val = myicalproperty_get_jsprop(prop);
        if (!val) continue;

        json_t *jval = json_loads(val, JSON_DECODE_ANY, NULL);
        if (JNULL(jval)) continue;

        /*
         * Ignore any nested pointer, unless it points into the "links"
         * or "virtualLocations" properties. For any other property,
         * the JSPROP property should be set on the iCalendar component
         * of the nested object type.
         */
        strarray_t *segs = strarray_split(ptr, "/", 0);
        const char *propname = NULL;
        if (strarray_size(segs) == 3) {
            if ((!strcmp(strarray_nth(segs, 0), "links") ||
                 !strcmp(strarray_nth(segs, 0), "virtualLocations"))
                && strlen(strarray_nth(segs, 1))) {
                propname = strarray_nth(segs, 2);
            }
        }
        else if (strarray_size(segs) == 1) {
            propname = strarray_nth(segs, 0);
        }

        if (propname) {
            const char *colon = strchr(propname, ':');
            if (colon && colon > propname && colon[1])
                json_object_set_new(jpatch, ptr, jval);
        }

        strarray_free(segs);
    }

    if (json_object_size(jpatch))
        jmap_patchobject_applym(jobj, jpatch, NULL, PATCH_KEEP_EXISTING);

    json_decref(jpatch);
}

static void relatedto_from_ical(jscalendar_cfg_t *cfg __attribute__((unused)),
                                icalcomponent *comp,
                                json_t *jobj,
                                const char *(*uidtokey)(const char *, void *),
                                void *rock)
{
    json_t *jrelto = json_object();
    struct buf buf = BUF_INITIALIZER;

    icalproperty *prop;
    icalpropiter prop_iter;
    myicalcomponent_foreach_property(
        comp, ICAL_RELATEDTO_PROPERTY, prop, prop_iter)
    {
        const char *uid = icalproperty_get_relatedto(prop);
        const char *key = uidtokey ? uidtokey(uid, rock) : uid;
        json_t *jrelobj =
            json_object_get_vanew(jrelto, key, "{s:s}", "@type", "Relation");

        json_t *jrel = json_object_get_vanew(jrelobj, "relation", "{}");
        icalparameter *param;
        icalparamiter param_iter;
        myicalproperty_foreach_parameter(
            prop, ICAL_RELTYPE_PARAMETER, param, param_iter)
        {
            buf_setcstr(&buf, icalparameter_get_value_as_string(param));
            json_object_set_new(jrel, buf_lcase(&buf), json_true());
        }

        if (!json_object_size(jrel)) {
            json_object_del(jrelobj, "relation");
        }
    }

    if (json_object_size(jrelto)) json_object_set(jobj, "relatedTo", jrelto);

    buf_free(&buf);
    json_decref(jrelto);
}

static const char *alerts_from_ical_cb(const char *uid, void *rock)
{
    return hash_lookup(uid, (hash_table *) rock);
}

static void alerts_from_ical(jscalendar_cfg_t *cfg,
                             icalcomponent *comp,
                             json_t *jobj)
{
    json_t *jalerts = json_object();
    struct buf buf = BUF_INITIALIZER;

    // Get Alert key for each VALARM, we'll need it to convert RELATED-TO.
    hashu64_table alertkey_by_ptr = HASHU64_TABLE_INITIALIZER;
    hash_table alertkey_by_uid = HASH_TABLE_INITIALIZER;
    size_t ncomps = icalcomponent_count_components(comp, ICAL_VALARM_COMPONENT);
    construct_hashu64_table(&alertkey_by_ptr, ncomps + 1, 0);
    construct_hash_table(&alertkey_by_uid, ncomps + 1, 0);

    icalcomponent *valarm;
    icalcompiter comp_iter;
    myicalcomponent_foreach_component(
        comp, ICAL_VALARM_COMPONENT, valarm, comp_iter)
    {
        const char *key = jsid_from_comp(valarm, jalerts, &buf);
        hashu64_insert((uintptr_t) valarm, xstrdup(key), &alertkey_by_ptr);
        const char *uid = icalcomponent_get_uid(valarm);
        if (uid) hash_insert(uid, xstrdup(key), &alertkey_by_uid);
    }

    // Convert VALARMs.
    myicalcomponent_foreach_component(
        comp, ICAL_VALARM_COMPONENT, valarm, comp_iter)
    {
        const char *key = hashu64_lookup((uintptr_t) valarm, &alertkey_by_ptr);
        json_t *jalert = json_pack("{s:s}", "@type", "Alert");
        icalproperty *prop;

        if ((prop = myicalcomponent_get_property(valarm,
                                                 ICAL_ACKNOWLEDGED_PROPERTY))) {
            icaltimetype t = icalproperty_get_acknowledged(prop);
            json_t *jval = json_string(utctime_from_icaltime(t, &buf));
            jobj_set_icalprop(cfg, jalert, "acknowledged", jval, prop);
        }

        if ((prop = myicalcomponent_get_property(valarm, ICAL_ACTION_PROPERTY)))
        {
            // Omit ACTION=DISPLAY, preserve unknown ACTION in
            // "iCalendar" property.
            if (icalproperty_get_action(prop) == ICAL_ACTION_EMAIL) {
                json_t *jval = json_string("email");
                jobj_set_icalprop(cfg, jalert, "action", jval, prop);
            }
        }

        if ((prop =
                 myicalcomponent_get_property(valarm, ICAL_TRIGGER_PROPERTY))) {

            struct icaltriggertype trigger = icalproperty_get_trigger(prop);
            json_t *jtrigger = NULL;

            if (!icaltime_is_null_time(trigger.time)) {
                jtrigger = json_pack("{s:s}", "@type", "AbsoluteTrigger");
                const char *ts = utctime_from_icaltime(trigger.time, &buf);
                json_object_set_new(jtrigger, "when", json_string(ts));
            }
            else {
                jtrigger = json_pack("{s:s}", "@type", "OffsetTrigger");
                const char *dur =
                    icaldurationtype_as_ical_string(trigger.duration);
                json_object_set_new(jtrigger, "offset", json_string(dur));

                icalparameter *param =
                    myicalproperty_get_parameter(prop, ICAL_RELATED_PARAMETER);
                if (param) {
                    if (icalparameter_get_related(param) == ICAL_RELATED_END) {
                        json_object_set_new(
                            jtrigger, "relativeTo", json_string("end"));
                    }
                }
            }

            json_object_set_new(jalert, "trigger", jtrigger);
        }

        relatedto_from_ical(
            cfg, valarm, jalert, alerts_from_ical_cb, &alertkey_by_uid);

        jobj_set_icalcomp(cfg, jalert, valarm);
        vendorexts_from_ical(valarm, jalert);

        json_object_set_new(jalerts, key, jalert);
    }

    if (json_object_size(jalerts)) json_object_set(jobj, "alerts", jalerts);

    free_hashu64_table(&alertkey_by_ptr, free);
    free_hash_table(&alertkey_by_uid, free);

    buf_free(&buf);
    json_decref(jalerts);
}

static void categories_from_ical(jscalendar_cfg_t *cfg __attribute__((unused)),
                                 icalcomponent *comp,
                                 json_t *jobj)
{
    json_t *jcategories = json_object();

    icalproperty *prop;
    icalpropiter prop_iter;
    myicalcomponent_foreach_property(
        comp, ICAL_CONCEPT_PROPERTY, prop, prop_iter)
    {
        const char *concept = icalproperty_get_categories(prop);
        json_object_set_new(jcategories, concept, json_true());
    }

    if (json_object_size(jcategories))
        json_object_set(jobj, "categories", jcategories);

    json_decref(jcategories);
}

static void description_from_ical(jscalendar_cfg_t *cfg __attribute__((unused)),
                                  icalcomponent *comp,
                                  json_t *jobj)
{
    icalparameter *fmttype = NULL;

    icalproperty *prop = NULL;
    if ((prop = myicalcomponent_get_nonderived_property(
             comp, ICAL_STYLEDDESCRIPTION_PROPERTY)))
    {
        fmttype = myicalproperty_get_parameter(prop, ICAL_FMTTYPE_PARAMETER);
    }
    else {
        prop = myicalcomponent_get_nonderived_property(
            comp, ICAL_DESCRIPTION_PROPERTY);
    }

    if (prop) {
        const char *desc = icalvalue_get_text(icalproperty_get_value(prop));
        jobj_set_icalprop(cfg, jobj, "description", json_string(desc), prop);
        if (fmttype) {
            const char *s = icalparameter_get_fmttype(fmttype);
            json_object_set_new(jobj, "descriptionContentType", json_string(s));
        }
    }
}

static void keywords_from_ical(jscalendar_cfg_t *cfg __attribute__((unused)),
                               icalcomponent *comp,
                               json_t *jobj)
{
    json_t *jkeywords = json_object();

    icalproperty *prop;
    icalpropiter prop_iter;
    myicalcomponent_foreach_property(
        comp, ICAL_CATEGORIES_PROPERTY, prop, prop_iter)
    {
        const char *category = icalproperty_get_categories(prop);
        json_object_set_new(jkeywords, category, json_true());
    }

    if (json_object_size(jkeywords))
        json_object_set(jobj, "keywords", jkeywords);

    json_decref(jkeywords);
}

static void links_from_ical(jscalendar_cfg_t *cfg __attribute__((unused)),
                            icalcomponent *comp,
                            json_t *jobj)
{
    json_t *jlinks = json_object();
    struct buf href = BUF_INITIALIZER;
    struct buf buf = BUF_INITIALIZER;
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;

    jmap_parser_push(&parser, "links");

    icalproperty *prop;
    icalpropiter prop_iter;
    myicalcomponent_foreach_property(comp, ICAL_ANY_PROPERTY, prop, prop_iter)
    {
        switch (icalproperty_isa(prop)) {
        case ICAL_ATTACH_PROPERTY:
        case ICAL_IMAGE_PROPERTY:
        case ICAL_LINK_PROPERTY:
            break;
        default:
            continue;
        }

        // Determine value type.
        icalvalue *value = icalproperty_get_value(prop);
        icalvalue_kind value_kind = icalvalue_isa(value);
        const char *strval = NULL;
        switch (value_kind) {
        case ICAL_ATTACH_VALUE: {
            icalattach *attach = icalvalue_get_attach(value);
            if (icalattach_get_is_url(attach)) {
                strval = icalattach_get_url(attach);
                value_kind = ICAL_URI_VALUE;
            }
            else {
                strval = (const char *) icalattach_get_data(attach);
                value_kind = ICAL_BINARY_VALUE;
            }
            break;
        }
        case ICAL_BINARY_VALUE:
            strval = (const char *) icalvalue_get_binary(value);
            break;
        case ICAL_URI_VALUE:
            strval = icalvalue_get_uri(value);
            break;
        default:
            continue;
        }
        if (!strval) continue;

        // Build href from value.
        if (value_kind == ICAL_BINARY_VALUE) {
            buf_setcstr(&href, "data:");
            icalparameter *param =
                myicalproperty_get_parameter(prop, ICAL_FMTTYPE_PARAMETER);
            if (param) {
                buf_appendcstr(&href, icalparameter_get_fmttype(param));
            }
            buf_appendcstr(&href, ";base64,");
            buf_appendcstr(&href, strval);
        }
        else {
            buf_setcstr(&href, strval);
        }

        json_t *jlink = json_pack("{s:s}", "@type", "Link");
        json_object_set_new(jlink, "href", json_string(buf_cstring(&href)));

        // Set Link properties.
        icalparameter *param;
        icalparamiter param_iter;
        myicalproperty_foreach_parameter(
            prop, ICAL_ANY_PARAMETER, param, param_iter)
        {
            icalparameter_kind param_kind = icalparameter_isa(param);
            if (param_kind == ICAL_DISPLAY_PARAMETER
                && icalproperty_isa(prop) == ICAL_IMAGE_PROPERTY)
            {
                json_t *jdisplay = json_object();
                for (size_t i = 0; i < icalparameter_get_display_size(param);
                     ++i) {
                    icalparameter_display display =
                        icalparameter_get_display_nth(param, i);
                    if (display != ICAL_DISPLAY_X) {
                        buf_setcstr(&buf,
                                    icalparameter_enum_to_string(display));
                        json_object_set_new(
                            jdisplay, buf_lcase(&buf), json_true());
                    }
                }
                if (json_object_size(jdisplay)) {
                    json_object_set(jlink, "display", jdisplay);
                }
                json_decref(jdisplay);
            }
            else if (param_kind == ICAL_FMTTYPE_PARAMETER) {
                json_object_set_new(
                    jlink,
                    "contentType",
                    json_string(icalparameter_get_fmttype(param)));
            }
            else if (param_kind == ICAL_LABEL_PARAMETER) {
                json_object_set_new(
                    jlink,
                    "title",
                    json_string(icalparameter_get_label(param)));
            }
            else if (param_kind == ICAL_LINKREL_PARAMETER) {
                const char *rel = icalparameter_get_linkrel(param);
                json_object_set_new(jlink, "rel", json_string(rel));
            }
            else if (param_kind == ICAL_SIZE_PARAMETER) {
                bit64 num;
                const char *end;
                if (!parsenum(icalparameter_get_size(param), &end, 0, &num)
                    && *end == '\0') {
                    json_object_set_new(jlink, "size", json_integer(num));
                }
            }
        }

        const char *key = jsid_from_prop(prop, jlinks, &buf);
        json_object_set_new(jlinks, key, jlink);

        // Preserve conversion-specific info, if necessary.
        jmap_parser_push(&parser, key);
        jmap_parser_push(&parser, "href");

        if (value_kind == ICAL_BINARY_VALUE) {
            jobj_set_icalprop_valuetype(
                cfg, jobj, jmap_parser_path(&parser), prop);
        }
        else if (icalproperty_isa(prop) == ICAL_IMAGE_PROPERTY) {
            if (myicalproperty_get_parameter(prop, ICAL_LINKREL_PARAMETER))
                jobj_set_icalprop_name(
                    cfg, jobj, jmap_parser_path(&parser), prop);
        }
        else if (icalproperty_isa(prop) == ICAL_LINK_PROPERTY) {
            if (!myicalproperty_get_parameter(prop, ICAL_LINKREL_PARAMETER))
                jobj_set_icalprop_name(
                    cfg, jobj, jmap_parser_path(&parser), prop);
        }
        else if (icalproperty_isa(prop) != ICAL_ATTACH_PROPERTY) {
            jobj_set_icalprop_name(cfg, jobj, jmap_parser_path(&parser), prop);
        }
        jobj_set_icalprop_params(cfg, jobj, jmap_parser_path(&parser), prop);

        jmap_parser_pop(&parser);
        jmap_parser_pop(&parser);
    }

    if (json_object_size(jlinks)) json_object_set(jobj, "links", jlinks);

    json_decref(jlinks);
    buf_free(&buf);
    buf_free(&href);
    jmap_parser_fini(&parser);
}

static void participant_from_icalprop(icalproperty *prop, json_t *jpart)
{
    const char *caladdr =
        icalvalue_get_caladdress(icalproperty_get_value(prop));
    if (caladdr)
        json_object_set_new(jpart, "calendarAddress", json_string(caladdr));

    icalparameter *param;
    icalparamiter param_iter;
    myicalproperty_foreach_parameter(
        prop, ICAL_ANY_PARAMETER, param, param_iter)
    {
        icalparameter_kind param_kind = icalparameter_isa(param);

        if (param_kind == ICAL_CN_PARAMETER) {
            const char *name = icalparameter_get_cn(param);
            json_object_set_new(jpart, "name", json_string(name));
        }

        else if (param_kind == ICAL_PARTSTAT_PARAMETER) {
            icalparameter_partstat icalpartstat =
                icalparameter_get_partstat(param);
            const char *partstat = NULL;
            const char *progress = NULL;

            switch (icalpartstat) {
            case ICAL_PARTSTAT_NEEDSACTION:
                partstat = "needs-action";
                break;
            case ICAL_PARTSTAT_ACCEPTED:
                partstat = "accepted";
                break;
            case ICAL_PARTSTAT_DECLINED:
                partstat = "declined";
                break;
            case ICAL_PARTSTAT_TENTATIVE:
                partstat = "tentative";
                break;
            case ICAL_PARTSTAT_DELEGATED:
                partstat = "delegated";
                break;
            case ICAL_PARTSTAT_COMPLETED:
                progress = "completed";
                break;
            case ICAL_PARTSTAT_INPROCESS:
                progress = "in-process";
                break;
            case ICAL_PARTSTAT_FAILED:
                progress = "failed";
                break;
            case ICAL_PARTSTAT_X:
            case ICAL_PARTSTAT_NONE:
                break;
            }

            if (progress && !partstat) partstat = "accepted";

            if (partstat) {
                json_object_set_new(
                    jpart, "participationStatus", json_string(partstat));
                if (progress)
                    json_object_set_new(
                        jpart, "progress", json_string(progress));
            }
        }

        else if (param_kind == ICAL_CUTYPE_PARAMETER) {
            icalparameter_cutype cutype = icalparameter_get_cutype(param);
            if (cutype == ICAL_CUTYPE_INDIVIDUAL)
                json_object_set_new(jpart, "kind", json_string("individual"));
            else if (cutype == ICAL_CUTYPE_GROUP)
                json_object_set_new(jpart, "kind", json_string("group"));
            else if (cutype == ICAL_CUTYPE_RESOURCE)
                json_object_set_new(jpart, "kind", json_string("resource"));
            else if (cutype == ICAL_CUTYPE_ROOM)
                json_object_set_new(jpart, "kind", json_string("location"));
        }

        else if (param_kind == ICAL_DELEGATEDFROM_PARAMETER) {
            json_t *jdelegs =
                json_object_get_vanew(jpart, "delegatedFrom", "{}");
            for (size_t i = 0; i < icalparameter_get_delegatedfrom_size(param);
                 i++) {
                const char *uri = icalparameter_get_delegatedfrom_nth(param, i);
                json_object_set_new(jdelegs, uri, json_true());
            }
        }

        else if (param_kind == ICAL_DELEGATEDTO_PARAMETER) {
            json_t *jdelegs = json_object_get_vanew(jpart, "delegatedTo", "{}");
            for (size_t i = 0; i < icalparameter_get_delegatedto_size(param);
                 i++) {
                const char *uri = icalparameter_get_delegatedto_nth(param, i);
                json_object_set_new(jdelegs, uri, json_true());
            }
        }

        else if (param_kind == ICAL_MEMBER_PARAMETER) {
            json_t *jmemberof = json_object_get_vanew(jpart, "memberOf", "{}");
            for (size_t i = 0; i < icalparameter_get_member_size(param); i++) {
                const char *uri = icalparameter_get_member_nth(param, i);
                json_object_set_new(jmemberof, uri, json_true());
            }
        }

        else if (param_kind == ICAL_EMAIL_PARAMETER) {
            const char *email = icalparameter_get_email(param);
            json_object_set_new(jpart, "email", json_string(email));
        }

        else if (param_kind == ICAL_RSVP_PARAMETER) {
            if (icalparameter_get_rsvp(param) == ICAL_RSVP_TRUE)
                json_object_set_new(jpart, "expectReply", json_true());
        }

        else if (param_kind == ICAL_ROLE_PARAMETER) {
            icalparameter_role role = icalparameter_get_role(param);
            json_t *jroles = json_object_get_vanew(jpart, "roles", "{}");
            if (role == ICAL_ROLE_CHAIR)
                json_object_set_new(jroles, "chair", json_true());
            else if (role == ICAL_ROLE_NONPARTICIPANT)
                json_object_set_new(jroles, "informational", json_true());
            else if (role == ICAL_ROLE_OPTPARTICIPANT)
                json_object_set_new(jroles, "optional", json_true());
            else if (role == ICAL_ROLE_REQPARTICIPANT)
                json_object_set_new(jroles, "required", json_true());
            else if (!strcasecmpsafe("OWNER", icalparameter_get_value_as_string(param)))
                json_object_set_new(jroles, "owner", json_true());
            if (!json_object_size(jroles)) json_object_del(jpart, "roles");
        }

        else if (param_kind == ICAL_SENTBY_PARAMETER) {
            const char *sentby = icalparameter_get_sentby(param);
            json_object_set_new(jpart, "sentBy", json_string(sentby));
        }
    }
}

static void locations_from_ical(jscalendar_cfg_t *cfg,
                                icalcomponent *comp,
                                json_t *jobj)
{
    json_t *jlocs = json_object();
    struct buf buf = BUF_INITIALIZER;
    char *mainloc_id = NULL;
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    jmap_parser_push(&parser, "locations");

    icalproperty *mainloc_prop =
        myicalcomponent_get_property(comp, ICAL_LOCATION_PROPERTY);
    if (mainloc_prop) {
        if (prop_has_jsid(mainloc_prop)) {
            mainloc_id = xstrdup(jsid_from_prop(mainloc_prop, jlocs, &buf));
        }

        if (!myicalproperty_is_derived(mainloc_prop)) {
            json_t *jloc = json_pack("{s:s}", "@type", "Location");
            const char *name = icalproperty_get_location(mainloc_prop);
            json_object_set_new(jloc, "name", json_string(name));
            if (!mainloc_id)
                mainloc_id = xstrdup(jsid_from_prop(mainloc_prop, jlocs, &buf));
            json_object_set_new(jlocs, mainloc_id, jloc);
        }
    }

    icalproperty *prop =
        myicalcomponent_get_nonderived_property(comp, ICAL_GEO_PROPERTY);
    if (prop) {
        json_t *jloc = json_object_get(jlocs, mainloc_id);
        if (!jloc) {
            jloc = json_pack("{s:s}", "@type", "Location");
            const char *key = jsid_from_prop(prop, jlocs, &buf);
            json_object_set_new(jlocs, key, jloc);
            jmap_parser_push(&parser, key);
        }
        else {
            jmap_parser_push(&parser, mainloc_id);
        }
        struct icalgeotype icalgeo = icalproperty_get_geo(prop);
        buf_setcstr(&buf, "geo:");
        buf_printf(&buf, "%s,%s", icalgeo.lat, icalgeo.lon);
        json_object_set_new(
            jloc, "coordinates", json_string(buf_cstring(&buf)));

        // Keep note that this converted from GEO.
        jobj_set_icalprop_name(
            cfg, jobj, jmap_parser_path_at(&parser, "coordinates"), prop);

        jmap_parser_pop(&parser);
    }

    // Find the VLOCATION for the main location, if any.
    icalcomponent *mainloc_vloc = NULL;
    icalcomponent *vloc;
    icalcompiter comp_iter;
    myicalcomponent_foreach_component(
        comp, ICAL_VLOCATION_COMPONENT, vloc, comp_iter)
    {
        // Match VLOCATION by Location id.
        if (comp_has_jsid(vloc)) {
            const char *vloc_id = jsid_from_comp(vloc, jlocs, &buf);
            if (!strcmpsafe(mainloc_id, vloc_id)) {
                mainloc_vloc = vloc;
                break;
            }
        }

        // Match VLOCATION by value of main location name.
        prop = myicalcomponent_get_property(vloc, ICAL_NAME_PROPERTY);
        if (prop && mainloc_prop) {
            const char *this_loc = icalproperty_get_name(prop);
            const char *main_loc = icalproperty_get_location(mainloc_prop);
            if (!strcasecmpsafe(this_loc, main_loc)) {
                mainloc_vloc = vloc;
                if (!mainloc_id)
                    mainloc_id = xstrdupnull(jsid_from_comp(vloc, jlocs, &buf));
            }
        }
    }

    // Convert VLOCATION components.
    myicalcomponent_foreach_component(
        comp, ICAL_VLOCATION_COMPONENT, vloc, comp_iter)
    {
        json_t *jloc = NULL;
        if (mainloc_vloc == vloc) {
            jloc = json_object_get(jlocs, mainloc_id);
        }
        if (!jloc) {
            jloc = json_pack("{s:s}", "@type", "Location");
            const char *key = jsid_from_comp(vloc, jlocs, &buf);
            json_object_set_new(jlocs, key, jloc);
        }

        links_from_ical(cfg, vloc, jloc);

        prop = myicalcomponent_get_property_by_name(vloc, "COORDINATES");
        if (prop) {
            json_t *jval = json_string(myicalproperty_get_coordinates(prop));
            jobj_set_icalprop(cfg, jloc, "coordinates", jval, prop);
        }

        prop = myicalcomponent_get_nonderived_property(vloc, ICAL_GEO_PROPERTY);
        if (prop) {
            struct icalgeotype icalgeo = icalproperty_get_geo(prop);
            buf_setcstr(&buf, "geo:");
            buf_printf(&buf, "%s,%s", icalgeo.lat, icalgeo.lon);
            json_t *jval = json_string(buf_cstring(&buf));
            jobj_set_icalprop(cfg, jloc, "coordinates", jval, prop);
            // Keep note that this converted from GEO.
            jobj_set_icalprop_name(cfg, jloc, "coordinates", prop);
        }

        prop = myicalcomponent_get_property(vloc, ICAL_NAME_PROPERTY);
        if (prop) {
            json_t *jval = json_string(icalproperty_get_name(prop));
            jobj_set_icalprop(cfg, jloc, "name", jval, prop);
        }

        icalpropiter prop_iter;
        myicalcomponent_foreach_property(
            vloc, ICAL_LOCATIONTYPE_PROPERTY, prop, prop_iter)
        {
            json_t *jltyps = json_object_get_vanew(jloc, "locationTypes", "{}");
            const char *ltyp = icalproperty_get_locationtype(prop);
            json_object_set_new(jltyps, ltyp, json_true());
        }

        jobj_set_icalcomp(cfg, jloc, vloc);
        vendorexts_from_ical(vloc, jloc);

        // Keep track this Location converted from a VLOCATION.
        jobj_set_icalcomp_name(cfg, jloc, vloc);
    }

    if (mainloc_id && json_object_size(jlocs) > 1)
        json_object_set_new(jobj, "mainLocationId", json_string(mainloc_id));

    if (json_object_size(jlocs)) json_object_set(jobj, "locations", jlocs);

    json_decref(jlocs);
    free(mainloc_id);
    jmap_parser_fini(&parser);
    buf_free(&buf);
}

static void participants_from_ical(jscalendar_cfg_t *cfg
                                   __attribute__((unused)),
                                   icalcomponent *comp,
                                   json_t *jobj)
{
    json_t *jparts = json_object();
    struct buf buf = BUF_INITIALIZER;
    json_t *jpart_by_caladdr = json_object();

    // Convert ORGANIZER.
    icalproperty *organizer =
        myicalcomponent_get_property(comp, ICAL_ORGANIZER_PROPERTY);
    icalproperty *organizer_attendee = NULL;
    if (organizer) {
        const char *caladdr = icalproperty_get_organizer(organizer);
        json_object_set_new(
            jobj, "organizerCalendarAddress", json_string(caladdr));

        // Find ATTENDEE for ORGANIZER and check if any ATTENDEE is OWNER.
        icalproperty *attendee;
        icalpropiter prop_iter;
        bool owner_role_is_set = false;
        myicalcomponent_foreach_property(
            comp, ICAL_ATTENDEE_PROPERTY, attendee, prop_iter)
        {
            const char *attcaladdr = icalproperty_get_attendee(attendee);
            if (!strcmpsafe(caladdr, attcaladdr)) {
                organizer_attendee = attendee;
            }

            icalparameter *param =
                myicalproperty_get_parameter(attendee, ICAL_ROLE_PARAMETER);
            if (param &&
                    !strcasecmpsafe("OWNER", icalparameter_get_value_as_string(param)))
                owner_role_is_set = true;
        }

        if (!owner_role_is_set || organizer_attendee != NULL
            || icalproperty_count_parameters(organizer))
        {
            // Convert ORGANIZER to Participant.
            struct buf key = BUF_INITIALIZER;
            json_t *jpart = json_pack("{s:s}", "@type", "Participant");
            json_object_set(jpart_by_caladdr, caladdr, jpart);
            participant_from_icalprop(organizer, jpart);

            if (organizer_attendee) {
                participant_from_icalprop(organizer_attendee, jpart);
                // Get JSID key from ATTENDEE, if set.
                if (!prop_has_jsid(organizer) && prop_has_jsid(organizer_attendee)) {
                    jsid_from_prop(organizer_attendee, jparts, &key);
                }
            }

            json_t *jroles = json_object_get_vanew(jpart, "roles", "{}");
            json_object_set_new(jroles, "owner", json_true());
            if (!buf_len(&key)) {
                jsid_from_prop(organizer, jparts, &key);
            }
            json_object_set_new(jparts, buf_cstring(&key), jpart);
            buf_free(&key);
        }
    }

    // Convert ATTENDEEs.
    icalproperty *attendee;
    icalpropiter prop_iter;
    myicalcomponent_foreach_property(
        comp, ICAL_ATTENDEE_PROPERTY, attendee, prop_iter)
    {
        // We already dealt with the ORGANIZER's ATTENDEE.
        if (attendee == organizer_attendee) continue;

        const char *caladdr = icalproperty_get_attendee(attendee);
        json_t *jpart = json_object_get(jpart_by_caladdr, caladdr);
        if (!jpart) {
            jpart = json_pack("{s:s}", "@type", "Participant");
            json_object_set(jpart_by_caladdr, caladdr, jpart);
            const char *key = jsid_from_prop(attendee, jparts, &buf);
            json_object_set_new(jparts, key, jpart);
        }
        participant_from_icalprop(attendee, jpart);
    }

    // Convert PARTICIPANT components.
    icalcomponent *part;
    icalcompiter comp_iter;
    myicalcomponent_foreach_component(
        comp, ICAL_PARTICIPANT_COMPONENT, part, comp_iter)
    {
        icalproperty *prop;

        json_t *jpart = NULL;
        if ((prop = myicalcomponent_get_property(
                 part, ICAL_CALENDARADDRESS_PROPERTY))) {
            const char *caladdr = icalproperty_get_calendaraddress(prop);
            jpart = json_object_get(jpart_by_caladdr, caladdr);
            if (!jpart) {
                jpart = json_pack("{s:s}", "@type", "Participant");
                json_object_set(jpart_by_caladdr, caladdr, jpart);
                const char *key = jsid_from_comp(part, jparts, &buf);
                json_object_set_new(jparts, key, jpart);
            }

            if (!json_object_get(jpart, "calendarAddress")) {
                jobj_set_icalprop(
                    cfg, jpart, "calendarAddress", json_string(caladdr), prop);
                jobj_set_icalprop_name(cfg, jpart, "calendarAddress", prop);
            }
        }

        if (!jpart) {
            jpart = json_pack("{s:s}", "@type", "Participant");
            const char *key = jsid_from_comp(part, jparts, &buf);
            json_object_set_new(jparts, key, jpart);
        }

        description_from_ical(cfg, part, jpart);
        links_from_ical(cfg, part, jpart);

        if ((prop = myicalcomponent_get_property(part, ICAL_SUMMARY_PROPERTY)))
        {
            const char *name = icalproperty_get_summary(prop);
            jobj_set_icalprop(cfg, jpart, "name", json_string(name), prop);
        }

        jobj_set_icalcomp(cfg, jpart, part);
        vendorexts_from_ical(part, jpart);
    }

    if (json_object_size(jparts)) json_object_set(jobj, "participants", jparts);

    json_decref(jpart_by_caladdr);
    json_decref(jparts);
    buf_free(&buf);
}

static void timeprops_from_ical(jscalendar_cfg_t *cfg __attribute__((unused)),
                                icalcomponent *comp,
                                json_t *jobj)
{
    struct buf buf = BUF_INITIALIZER;

    icaltimetype dtstart = icaltime_null_time();
    icalproperty *dtstart_prop =
        myicalcomponent_get_property(comp, ICAL_DTSTART_PROPERTY);
    if (dtstart_prop) {
        dtstart = icalproperty_get_dtstart(dtstart_prop);
        icalparameter *tzid_param =
            myicalproperty_get_parameter(dtstart_prop, ICAL_TZID_PARAMETER);
        if (tzid_param) {
            const char *tzid = icalparameter_get_tzid(tzid_param);
            dtstart.zone = icaltimezone_get_cyrus_timezone_from_tzid(tzid);
            if (!icaltimezone_is_builtin_timezone_tzid(tzid)) {
                jobj_set_icalprop_param(
                    cfg, jobj, "start", dtstart_prop, tzid_param);
            }
        }
        json_t *jval = json_string(localtime_from_icaltime(dtstart, &buf));
        jobj_set_icalprop(cfg, jobj, "start", jval, dtstart_prop);

        const char *jtzid = icaltimezone_get_location_tzid(dtstart.zone);
        if (jtzid) {
            json_object_set_new(jobj, "timeZone", json_string(jtzid));
        }
        else if (dtstart.is_date) {
            json_object_set_new(jobj, "showWithoutTime", json_true());
        }
    }

    icalproperty *prop;

    if (dtstart_prop && icalcomponent_isa(comp) == ICAL_VEVENT_COMPONENT) {
        struct icaldurationtype duration = icaldurationtype_null_duration();

        if ((prop = myicalcomponent_get_property(comp, ICAL_DTEND_PROPERTY))) {
            icaltimetype dtend = icalproperty_get_dtend(prop);
            // Determine end timezone.
            icalparameter *tzid_param =
                myicalproperty_get_parameter(prop, ICAL_TZID_PARAMETER);
            if (tzid_param) {
                const char *tzid = icalparameter_get_tzid(tzid_param);
                dtend.zone = icaltimezone_get_cyrus_timezone_from_tzid(tzid);
                if (dtstart.zone != dtend.zone) {
                    const char *jtzid =
                        icaltimezone_get_location_tzid(dtend.zone);
                    if (jtzid) {
                        json_object_set_new(
                            jobj, "endTimeZone", json_string(jtzid));
                    }
                    if (!icaltimezone_is_builtin_timezone_tzid(tzid)) {
                        jobj_set_icalprop_param(
                            cfg, jobj, "duration", prop, tzid_param);
                    }
                }
            }
            // Determine duration.
            icaltimetype utc_start = icaltime_convert_to_zone(
                dtstart, icaltimezone_get_utc_timezone());
            icaltimetype utc_end = icaltime_convert_to_zone(
                dtend, icaltimezone_get_utc_timezone());
            duration = icalduration_from_times(utc_end, utc_start);
            duration = icaldurationtype_normalize(duration);

            if (dtstart.zone == dtend.zone) {
                // Keep track that duration got converted from DTEND.
                jobj_set_icalprop_name(cfg, jobj, "duration", prop);
            }
        }
        else {
            prop = myicalcomponent_get_property(comp, ICAL_DURATION_PROPERTY);
            if (prop) duration = icalproperty_get_duration(prop);
        }

        if (!icaldurationtype_is_null_duration(duration)) {
            const char *dur = icaldurationtype_as_ical_string(duration);
            json_object_set_new(jobj, "duration", json_string(dur));
        }
    }

    if (icalcomponent_isa(comp) == ICAL_VTODO_COMPONENT) {
        prop =
            myicalcomponent_get_property(comp, ICAL_ESTIMATEDDURATION_PROPERTY);
        if (prop) {
            const char *dur = icalproperty_get_value_as_string(prop);
            json_object_set_new(jobj, "estimatedDuration", json_string(dur));
        }

        prop = myicalcomponent_get_property(comp, ICAL_DUE_PROPERTY);
        if (prop) {
            icaltimetype due = icalproperty_get_due(prop);
            icalparameter *tzid_param =
                myicalproperty_get_parameter(prop, ICAL_TZID_PARAMETER);
            if (tzid_param) {
                const char *tzid = icalparameter_get_tzid(tzid_param);
                due.zone = icaltimezone_get_cyrus_timezone_from_tzid(tzid);
            }
            if (dtstart_prop && dtstart.zone != due.zone) {
                due = icaltime_convert_to_zone(due,
                                               (icaltimezone *) dtstart.zone);
            }
            json_t *jval = json_string(localtime_from_icaltime(due, &buf));
            jobj_set_icalprop(cfg, jobj, "due", jval, prop);

            if (!dtstart_prop) {
                const char *jtzid = icaltimezone_get_location_tzid(due.zone);
                if (jtzid) {
                    json_object_set_new(jobj, "timeZone", json_string(jtzid));
                }
                else if (due.is_date) {
                    json_object_set_new(jobj, "showWithoutTime", json_true());
                }
            }
        }
    }

    if ((prop = myicalcomponent_get_property(comp, ICAL_RECURRENCEID_PROPERTY)))
    {
        icaltimetype recurid = icalproperty_get_recurrenceid(prop);
        icalparameter *tzid_param =
            myicalproperty_get_parameter(prop, ICAL_TZID_PARAMETER);
        if (tzid_param) {
            const char *tzid = icalparameter_get_tzid(tzid_param);
            recurid.zone = icaltimezone_get_cyrus_timezone_from_tzid(tzid);
            if (!icaltimezone_is_builtin_timezone_tzid(tzid)) {
                jobj_set_icalprop_param(
                    cfg, jobj, "recurrenceId", prop, tzid_param);
            }
        }
        json_t *jval = json_string(localtime_from_icaltime(recurid, &buf));
        jobj_set_icalprop(cfg, jobj, "recurrenceId", jval, prop);

        const char *jtzid = icaltimezone_get_location_tzid(recurid.zone);
        if (jtzid) {
            json_object_set_new(
                jobj, "recurrenceIdTimeZone", json_string(jtzid));
        }
    }

    prop = myicalcomponent_get_property(comp, ICAL_RRULE_PROPERTY);
    if (prop && dtstart_prop) {
        struct icalrecurrencetype *rrule = icalproperty_get_rrule(prop);
        json_t *jrrule = rrule_from_ical(rrule, (icaltimezone *) dtstart.zone);
        json_object_set_new(jobj, "recurrenceRule", jrrule);
    }

    if ((prop = myicalcomponent_get_property_by_name(comp, "SHOW-WITHOUT-TIME")))
    {
        if (myicalproperty_get_showwithouttime(prop)) {
            json_object_set_new(jobj, "showWithoutTime", json_true());
        }
    }

    buf_free(&buf);
}

static void entry_from_ical(jscalendar_cfg_t *cfg,
                            icalcomponent *comp,
                            json_t *jobj,
                            ptrarray_t *overrides);

static void overrides_from_ical(jscalendar_cfg_t *cfg,
                                icalcomponent *comp,
                                json_t *jobj,
                                ptrarray_t *overrides)
{
    struct buf buf = BUF_INITIALIZER;
    json_t *jovrs = json_object();

    icaltimetype dtstart = icaltime_null_time();
    icalproperty *dtstart_prop =
        myicalcomponent_get_property(comp, ICAL_DTSTART_PROPERTY);
    if (dtstart_prop) {
        dtstart = icalproperty_get_dtstart(dtstart_prop);
        icalparameter *tzid_param =
            myicalproperty_get_parameter(dtstart_prop, ICAL_TZID_PARAMETER);
        if (tzid_param) {
            const char *tzid = icalparameter_get_tzid(tzid_param);
            dtstart.zone = icaltimezone_get_cyrus_timezone_from_tzid(tzid);
        }
    }

    icalproperty *prop;
    icalpropiter prop_iter;
    myicalcomponent_foreach_property(comp, ICAL_ANY_PROPERTY, prop, prop_iter)
    {
        icalproperty_kind kind = icalproperty_isa(prop);
        if (kind != ICAL_RDATE_PROPERTY && kind != ICAL_EXDATE_PROPERTY)
            continue;

        icaltimetype t = icaltime_null_time();
        if (kind == ICAL_RDATE_PROPERTY)
            t = icalproperty_get_rdate(prop).time;
        else
            t = icalproperty_get_exdate(prop);

        if (icaltime_is_null_time(t)) continue;

        icalparameter *tzid_param =
            myicalproperty_get_parameter(prop, ICAL_TZID_PARAMETER);
        if (tzid_param) {
            const char *tzid = icalparameter_get_tzid(tzid_param);
            t.zone = icaltimezone_get_cyrus_timezone_from_tzid(tzid);
        }

        if (dtstart_prop && dtstart.zone != t.zone) {
            t = icaltime_convert_to_zone(t, (icaltimezone *) dtstart.zone);
        }

        json_t *jovr = json_object();
        if (kind == ICAL_EXDATE_PROPERTY)
            json_object_set_new(jovr, "excluded", json_true());
        const char *recurid = localtime_from_icaltime(t, &buf);
        json_object_set_new(jovrs, recurid, jovr);
    }

    for (int i = 0; i < ptrarray_size(overrides); i++) {
        icalcomponent *ovrc = ptrarray_nth(overrides, i);

        prop = myicalcomponent_get_property(ovrc, ICAL_RECURRENCEID_PROPERTY);
        if (!prop) continue;

        icaltimetype icalrecurid = icalproperty_get_recurrenceid(prop);
        icalparameter *tzid_param =
            myicalproperty_get_parameter(prop, ICAL_TZID_PARAMETER);
        if (tzid_param) {
            const char *tzid = icalparameter_get_tzid(tzid_param);
            icalrecurid.zone = icaltimezone_get_cyrus_timezone_from_tzid(tzid);
        }
        if (dtstart_prop && dtstart.zone != icalrecurid.zone) {
            // Bogus: RECURRENCE-ID TZID differs from main component's DTSTART.
            icalrecurid = icaltime_convert_to_zone(
                icalrecurid, (icaltimezone *) dtstart.zone);
        }

        json_t *jovr = json_object();
        entry_from_ical(cfg, ovrc, jovr, NULL);
        json_object_del(jovr, "recurrenceId");
        json_object_del(jovr, "recurrenceIdTimeZone");

        json_t *jpatch = jmap_patchobject_create(jobj, jovr, 0);
        json_object_del(jpatch, "method");
        json_object_del(jpatch, "prodId");
        json_object_del(jpatch, "recurrenceOverrides");
        json_object_del(jpatch, "recurrenceRule");
        const char *recurid = localtime_from_icaltime(icalrecurid, &buf);

        const char *ovr_start = json_string_value(json_object_get(jpatch, "start"));
        if (!strcmpsafe(recurid, ovr_start)) {
            json_object_del(jpatch, "start");
        }
        json_object_set_new(jovrs, recurid, jpatch);
    }

    if (json_object_size(jovrs))
        json_object_set(jobj, "recurrenceOverrides", jovrs);

    json_decref(jovrs);
    buf_free(&buf);
}

static void virtuallocations_from_ical(jscalendar_cfg_t *cfg
                                       __attribute__((unused)),
                                       icalcomponent *comp,
                                       json_t *jobj)
{
    json_t *jvlocs = json_object();
    struct buf buf = BUF_INITIALIZER;
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    jmap_parser_push(&parser, "virtualLocations");

    icalproperty *prop;
    icalpropiter prop_iter;
    myicalcomponent_foreach_property(
        comp, ICAL_CONFERENCE_PROPERTY, prop, prop_iter)
    {
        const char *uri = icalproperty_get_conference(prop);
        json_t *jvloc = json_pack("{s:s}", "@type", "VirtualLocation");
        json_object_set_new(jvloc, "uri", json_string(uri));
        const char *key = jsid_from_prop(prop, jvlocs, &buf);
        json_object_set_new(jvlocs, key, jvloc);
        jmap_parser_push(&parser, key);

        icalparameter *param;
        icalparamiter param_iter;
        myicalproperty_foreach_parameter(
            prop, ICAL_ANY_PARAMETER, param, param_iter)
        {
            icalparameter_kind param_kind = icalparameter_isa(param);

            if (param_kind == ICAL_FEATURE_PARAMETER) {
                json_t *jfeatures = json_object();
                for (size_t i = 0; i < icalparameter_get_feature_size(param);
                     i++) {
                    icalparameter_feature feature =
                        icalparameter_get_feature_nth(param, i);
                    if (feature != ICAL_FEATURE_X) {
                        buf_setcstr(&buf,
                                    icalparameter_enum_to_string(feature));
                        json_object_set_new(
                            jfeatures, buf_lcase(&buf), json_true());
                    }
                }
                if (json_object_size(jfeatures))
                    json_object_set(jvloc, "features", jfeatures);
                json_decref(jfeatures);
            }
            else if (param_kind == ICAL_LABEL_PARAMETER) {
                const char *name = icalparameter_get_label(param);
                json_object_set_new(jvloc, "name", json_string(name));
            }
        }

        jobj_set_icalprop_params(
            cfg, jobj, jmap_parser_path_at(&parser, "uri"), prop);

        jmap_parser_pop(&parser);
    }

    if (json_object_size(jvlocs))
        json_object_set(jobj, "virtualLocations", jvlocs);

    json_decref(jvlocs);
    jmap_parser_fini(&parser);
    buf_free(&buf);
}

static void entry_from_ical(jscalendar_cfg_t *cfg,
                            icalcomponent *comp,
                            json_t *jobj,
                            ptrarray_t *overrides)
{
    if (icalcomponent_isa(comp) == ICAL_VTODO_COMPONENT)
        json_object_set_new(jobj, "@type", json_string("Task"));
    else
        json_object_set_new(jobj, "@type", json_string("Event"));

    timeprops_from_ical(cfg, comp, jobj);
    alerts_from_ical(cfg, comp, jobj);
    categories_from_ical(cfg, comp, jobj);
    description_from_ical(cfg, comp, jobj);
    keywords_from_ical(cfg, comp, jobj);
    links_from_ical(cfg, comp, jobj);
    locations_from_ical(cfg, comp, jobj);
    participants_from_ical(cfg, comp, jobj);
    relatedto_from_ical(cfg, comp, jobj, NULL, NULL);
    virtuallocations_from_ical(cfg, comp, jobj);

    struct buf buf = BUF_INITIALIZER;
    icalproperty *prop;

    if ((prop = myicalcomponent_get_property(comp, ICAL_CLASS_PROPERTY))) {
        icalproperty_class class = icalproperty_get_class(prop);
        if (class == ICAL_CLASS_PUBLIC)
            jobj_set_icalprop(
                cfg, jobj, "privacy", json_string("public"), prop);
        else if (class == ICAL_CLASS_PRIVATE)
            jobj_set_icalprop(
                cfg, jobj, "privacy", json_string("private"), prop);
        else
            jobj_set_icalprop(
                cfg, jobj, "privacy", json_string("secret"), prop);
    }

    if ((prop = myicalcomponent_get_property(comp, ICAL_COLOR_PROPERTY))) {
        const char *color = icalproperty_get_color(prop);
        jobj_set_icalprop(cfg, jobj, "color", json_string(color), prop);
    }

    if ((prop = myicalcomponent_get_property(comp, ICAL_CREATED_PROPERTY))) {
        icaltimetype t = icalproperty_get_created(prop);
        json_t *jval = json_string(utctime_from_icaltime(t, &buf));
        jobj_set_icalprop(cfg, jobj, "created", jval, prop);
    }

    if ((prop = myicalcomponent_get_property(comp, ICAL_DTSTAMP_PROPERTY))) {
        icaltimetype t = icalproperty_get_dtstamp(prop);
        json_t *jval = json_string(utctime_from_icaltime(t, &buf));
        jobj_set_icalprop(cfg, jobj, "updated", jval, prop);
    }

    if ((prop =
             myicalcomponent_get_property(comp, ICAL_PERCENTCOMPLETE_PROPERTY))
        && icalcomponent_isa(comp) == ICAL_VTODO_COMPONENT)
    {
        int val = icalproperty_get_percentcomplete(prop);
        jobj_set_icalprop(
            cfg, jobj, "percentComplete", json_integer(val), prop);
    }

    if ((prop = myicalcomponent_get_property(comp, ICAL_PRIORITY_PROPERTY))) {
        int seq = icalproperty_get_priority(prop);
        jobj_set_icalprop(cfg, jobj, "priority", json_integer(seq), prop);
    }

    if ((prop = myicalcomponent_get_property(comp, ICAL_SEQUENCE_PROPERTY))) {
        int seq = icalproperty_get_sequence(prop);
        jobj_set_icalprop(cfg, jobj, "sequence", json_integer(seq), prop);
    }

    if ((prop = myicalcomponent_get_property(comp, ICAL_STATUS_PROPERTY))) {
        icalproperty_status status = icalproperty_get_status(prop);
        buf_setcstr(&buf, icalproperty_status_to_string(status));
        json_t *jval = json_string(buf_lcase(&buf));
        if (icalcomponent_isa(comp) == ICAL_VTODO_COMPONENT)
            jobj_set_icalprop(cfg, jobj, "progress", jval, prop);
        else
            jobj_set_icalprop(cfg, jobj, "status", jval, prop);
    }

    if ((prop = myicalcomponent_get_property(comp, ICAL_TRANSP_PROPERTY))) {
        const char *s = icalproperty_get_transp(prop) == ICAL_TRANSP_TRANSPARENT
                            ? "free"
                            : "busy";
        jobj_set_icalprop(cfg, jobj, "freeBusyStatus", json_string(s), prop);
    }

    if ((prop = myicalcomponent_get_property(comp, ICAL_SUMMARY_PROPERTY))) {
        json_t *jval = json_string(icalproperty_get_name(prop));
        jobj_set_icalprop(cfg, jobj, "title", jval, prop);
        icalparameter *param =
            myicalproperty_get_parameter(prop, ICAL_LANGUAGE_PARAMETER);
        if (param) {
            const char *l = icalparameter_get_language(param);
            json_object_set_new(jobj, "locale", json_string(l));
        }
    }

    if ((prop = myicalcomponent_get_property(comp, ICAL_UID_PROPERTY))) {
        json_t *jval = json_string(icalproperty_get_uid(prop));
        jobj_set_icalprop(cfg, jobj, "uid", jval, prop);
    }

    if (icalcomponent_get_parent(comp)) {
        icalcomponent *ical = icalcomponent_get_parent(comp);
        if ((prop = myicalcomponent_get_property(ical, ICAL_METHOD_PROPERTY))) {
            buf_setcstr(&buf, icalproperty_get_value_as_string(prop));
            json_object_set_new(jobj, "method", json_string(buf_lcase(&buf)));
        }

        if ((prop = myicalcomponent_get_property(ical, ICAL_PRODID_PROPERTY))) {
            const char *prodid = icalproperty_get_prodid(prop);
            json_object_set_new(jobj, "prodId", json_string(prodid));
        }
    }

    overrides_from_ical(cfg, comp, jobj, overrides);

    jobj_set_icalcomp(cfg, jobj, comp);
    vendorexts_from_ical(comp, jobj);

    buf_free(&buf);
}

static void entries_from_ical(jscalendar_cfg_t *cfg,
                              icalcomponent *ical,
                              json_t *jobj)
{
    struct buf buf = BUF_INITIALIZER;

    // Hash components by kind and UID.
    hash_table comps = HASH_TABLE_INITIALIZER;
    size_t ncomps = icalcomponent_count_components(ical, ICAL_ANY_COMPONENT);
    construct_hash_table(&comps, ncomps + 1, 0);

    icalcomponent *comp;
    icalcompiter comp_iter;
    myicalcomponent_foreach_component(ical, ICAL_ANY_COMPONENT, comp, comp_iter)
    {
        icalcomponent_kind kind = icalcomponent_isa(comp);
        if (kind != ICAL_VEVENT_COMPONENT && kind != ICAL_VTODO_COMPONENT)
            continue;

        const char *uid = icalcomponent_get_uid(comp);
        if (!uid) continue;

        buf_setcstr(&buf, icalcomponent_kind_to_string(kind));
        buf_putc(&buf, '/');
        buf_appendcstr(&buf, uid);

        ptrarray_t *complist = hash_lookup(buf_cstring(&buf), &comps);
        if (!complist) {
            complist = ptrarray_new();
            hash_insert(buf_cstring(&buf), complist, &comps);
        }

        if (myicalcomponent_get_property(comp, ICAL_RECURRENCEID_PROPERTY))
            ptrarray_append(complist, comp);
        else
            ptrarray_unshift(complist, comp);
    }

    json_t *jentries = json_array();

    // Process entries by kind and UID.
    hash_iter *hit = hash_table_iter(&comps);
    while (hash_iter_next(hit)) {
        ptrarray_t *complist = hash_iter_val(hit);
        icalcomponent *comp;
        while ((comp = ptrarray_shift(complist))) {
            json_t *jentry = json_object();
            icalcomponent *next = ptrarray_nth(complist, 0);
            if (next
                && !myicalcomponent_get_property(comp,
                                                 ICAL_RECURRENCEID_PROPERTY)
                && myicalcomponent_get_property(next,
                                                ICAL_RECURRENCEID_PROPERTY))
            {
                // Convert main component and all recurrence overrides.
                entry_from_ical(cfg, comp, jentry, complist);
                ptrarray_truncate(complist, 0);
            }
            else {
                // Convert main component or stand-alone instance.
                entry_from_ical(cfg, comp, jentry, NULL);
            }
            json_array_append_new(jentries, jentry);
        }
        ptrarray_free(complist);
    }
    hash_iter_free(&hit);

    json_object_set_new(jobj, "entries", jentries);

    free_hash_table(&comps, NULL);
    buf_free(&buf);
}

EXPORTED json_t *jscalendar_from_ical(jscalendar_cfg_t *cfg,
                                      icalcomponent *ical)
{
    jscalendar_cfg_t mycfg = { 0 };
    if (!cfg) cfg = &mycfg;

    json_t *jobj = json_pack("{s:s}", "@type", "Group");
    struct buf buf = BUF_INITIALIZER;

    categories_from_ical(cfg, ical, jobj);
    keywords_from_ical(cfg, ical, jobj);
    entries_from_ical(cfg, ical, jobj);
    description_from_ical(cfg, ical, jobj);
    links_from_ical(cfg, ical, jobj);

    icalproperty *prop;

    if ((prop = myicalcomponent_get_property(ical, ICAL_COLOR_PROPERTY))) {
        json_t *jval = json_string(icalproperty_get_color(prop));
        jobj_set_icalprop(cfg, jobj, "color", jval, prop);
    }

    if ((prop = myicalcomponent_get_property(ical, ICAL_CREATED_PROPERTY))) {
        icaltimetype t = icalproperty_get_created(prop);
        json_t *jval = json_string(utctime_from_icaltime(t, &buf));
        jobj_set_icalprop(cfg, jobj, "created", jval, prop);
    }

    if ((prop =
             myicalcomponent_get_property(ical, ICAL_LASTMODIFIED_PROPERTY)))
    {
        icaltimetype t = icalproperty_get_lastmodified(prop);
        json_t *jval = json_string(utctime_from_icaltime(t, &buf));
        jobj_set_icalprop(cfg, jobj, "updated", jval, prop);
    }

    if ((prop = myicalcomponent_get_property(ical, ICAL_NAME_PROPERTY))) {
        json_t *jval = json_string(icalproperty_get_name(prop));
        jobj_set_icalprop(cfg, jobj, "title", jval, prop);
        icalparameter *param =
            myicalproperty_get_parameter(prop, ICAL_LANGUAGE_PARAMETER);
        if (param) {
            const char *l = icalparameter_get_language(param);
            json_object_set(jobj, "locale", json_string(l));
        }
    }

    if ((prop = myicalcomponent_get_property(ical, ICAL_PRODID_PROPERTY))) {
        const char *prodid = icalproperty_get_prodid(prop);
        jobj_set_icalprop(cfg, jobj, "prodId", json_string(prodid), prop);
    }

    if ((prop = myicalcomponent_get_property(ical, ICAL_SOURCE_PROPERTY))) {
        json_t *jval = json_string(icalproperty_get_source(prop));
        jobj_set_icalprop(cfg, jobj, "source", jval, prop);
    }

    if ((prop = myicalcomponent_get_property(ical, ICAL_UID_PROPERTY))) {
        json_t *jval = json_string(icalproperty_get_uid(prop));
        jobj_set_icalprop(cfg, jobj, "uid", jval, prop);
    }

    jobj_set_icalcomp(cfg, jobj, ical);
    vendorexts_from_ical(ical, jobj);

    buf_free(&buf);
    return jobj;
}
