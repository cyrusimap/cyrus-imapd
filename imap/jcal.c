/* jcal.c -- Routines for converting iCalendar to/from jCal
 *
 * Copyright (c) 1994-2013 Carnegie Mellon University.  All rights reserved.
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

#include <stdio.h>  /* for snprintf() */
#include <stddef.h> /* for offsetof() macro */
#include <syslog.h>

#include "global.h"
#include "ical_support.h"
#include "json_support.h"
#include "jcal.h"
#include "xcal.h"
#include "tok.h"
#include "util.h"
#include "version.h"
#include "xstrlcat.h"


/*
 * Construct a JSON string for an iCalendar Period.
 */
static char *icalperiodtype_as_json_string(struct icalperiodtype p)
{
    static char str[42];
    const char *start;
    const char *end;

    start = icaltime_as_iso_string(p.start);
    snprintf(str, sizeof(str), "%s/", start);

    if (!icaltime_is_null_time(p.end))
        end = icaltime_as_iso_string(p.end);
    else
        end = icaldurationtype_as_ical_string(p.duration);

    strlcat(str, end, sizeof(str));

    return str;
}


/*
 * Add an iCalendar recur-rule-part to a JSON recur object.
 */
static void icalrecur_add_obj_to_json_object(json_t *jrecur, const char *rpart,
                                             json_t *obj)
{
    json_t *old_rpart = json_object_get(jrecur, rpart);

    if (old_rpart) {
        /* Already have a value for this BY* rpart - needs to be an array */
        json_t *byarray;

        if (!json_is_array(old_rpart)) {
            /* Create an array from existing value */
            byarray = json_array();
            json_array_append(byarray, old_rpart);
            json_object_set_new(jrecur, rpart, byarray);
        }
        else byarray = old_rpart;

        /* Append value to array */
        json_array_append_new(byarray, obj);
    }
    else json_object_set_new(jrecur, rpart, obj);
}

static void icalrecur_add_int_to_json_object(void *jrecur, const char *rpart,
                                             int i)
{
    icalrecur_add_obj_to_json_object(jrecur, rpart, json_integer(i));
}

static void icalrecur_add_string_to_json_object(void *jrecur, const char *rpart,
                                                const char *s)
{
    icalrecur_add_obj_to_json_object(jrecur, rpart, json_string(s));
}


/*
 * Construct a JSON "structured value" for an iCalendar REQUEST-STATUS.
 */
static json_t *icalreqstattype_as_json_array(struct icalreqstattype stat)
{
    json_t *jstat;
    char code[22];

    icalerror_check_arg_rz((stat.code != ICAL_UNKNOWN_STATUS),"Status");

    if (!stat.desc) stat.desc = icalenum_reqstat_desc(stat.code);

    jstat = json_array();

    snprintf(code, sizeof(code), "%u.%u",
             icalenum_reqstat_major(stat.code),
             icalenum_reqstat_minor(stat.code));

    json_array_append_new(jstat, json_string(code));
    json_array_append_new(jstat, json_string(stat.desc));
    if (stat.debug) json_array_append_new(jstat, json_string(stat.debug));

    return jstat;
}


/*
 * Construct the proper JSON object for an iCalendar value.
 */
static json_t *icalvalue_as_json_object(const icalvalue *value)
{
    const char *str = NULL;
    json_t *obj;

    switch (icalvalue_isa(value)) {
    case ICAL_BOOLEAN_VALUE:
        return json_boolean(icalvalue_get_integer(value));

    case ICAL_DATE_VALUE:
        str = icaltime_as_iso_string(icalvalue_get_date(value));
        break;

    case ICAL_DATETIME_VALUE:
        str = icaltime_as_iso_string(icalvalue_get_datetime(value));
        break;

    case ICAL_DATETIMEPERIOD_VALUE: {
        struct icaldatetimeperiodtype dtp =
            icalvalue_get_datetimeperiod(value);

        if (!icaltime_is_null_time(dtp.time))
            str = icaltime_as_iso_string(dtp.time);
        else
            str = icalperiodtype_as_json_string(dtp.period);
        break;
    }

    case ICAL_FLOAT_VALUE:
        return json_real(icalvalue_get_float(value));

    case ICAL_GEO_VALUE: {
        struct icalgeotype geo = icalvalue_get_geo(value);

        obj = json_array();
#ifdef ICAL_GEO_LEN
        json_array_append_new(obj, json_real(atof(geo.lat)));
        json_array_append_new(obj, json_real(atof(geo.lon)));
#else
        json_array_append_new(obj, json_real(geo.lat));
        json_array_append_new(obj, json_real(geo.lon));
#endif
        return obj;
    }

    case ICAL_INTEGER_VALUE:
        return json_integer(icalvalue_get_integer(value));

    case ICAL_PERIOD_VALUE:
        str = icalperiodtype_as_json_string(icalvalue_get_period(value));
        break;

    case ICAL_RECUR_VALUE: {
        struct icalrecurrencetype *recur = icalvalue_get_recurrence(value);

        obj = json_object();
        icalrecurrencetype_add_as_xxx(recur, obj,
                                      &icalrecur_add_int_to_json_object,
                                      &icalrecur_add_string_to_json_object);
        icalrecurrencetype_unref(recur);
        return obj;
    }

    case ICAL_REQUESTSTATUS_VALUE:
        return
            icalreqstattype_as_json_array(icalvalue_get_requeststatus(value));

    case ICAL_TRIGGER_VALUE: {
        struct icaltriggertype trig = icalvalue_get_trigger(value);

        if (!icaltime_is_null_time(trig.time))
            str = icaltime_as_iso_string(trig.time);
        else
            str = icaldurationtype_as_ical_string(trig.duration);
        break;
    }

    case ICAL_UTCOFFSET_VALUE:
        str = icalvalue_utcoffset_as_iso_string(value);
        break;

    default:
        str = icalvalue_as_ical_string(value);
        break;
    }

    return (str ? json_string(str) : NULL);
}


/*
 * Add an iCalendar parameter to an existing JSON object.
 */
static void icalparameter_as_json_object_member(icalparameter *param,
                                                json_t *jparams)
{
    icalparameter_kind kind;
    const char *kind_string, *value_string;

    kind = icalparameter_isa(param);

    switch (kind) {
    case ICAL_X_PARAMETER:
        kind_string = icalparameter_get_xname(param);
        break;

    case ICAL_IANA_PARAMETER:
        kind_string = icalparameter_get_iana_name(param);
        break;

    default:                    /* XXX: Is the default case here deliberate?? */
        kind_string = icalparameter_kind_to_string(kind);
        if (kind_string) break;

        GCC_FALLTHROUGH

    case ICAL_NO_PARAMETER:
    case ICAL_ANY_PARAMETER:
            icalerror_set_errno(ICAL_BADARG_ERROR);
            return;
    }

    /* XXX  Need to handle multi-valued parameters */
    value_string = icalparameter_get_xvalue(param);
    if (!value_string) {
        icalparameter_value value = icalparameter_get_value(param);

        if (value) value_string = icalparameter_enum_to_string(value);
    }
    if (!value_string) return;

    json_object_set_new(jparams, lcase(icalmemory_tmp_copy(kind_string)),
                        json_string(value_string));
}


/*
 * Construct a JSON array for an iCalendar property.
 */
static json_t *icalproperty_as_json_array(icalproperty *prop)
{
    icalproperty_kind prop_kind;
    const char *x_name, *property_name = NULL;
    icalparameter *param;
    const char *type = NULL;
    const icalvalue *value;
    json_t *jprop, *jparams;

    if (!prop) return NULL;

    prop_kind = icalproperty_isa(prop);
    x_name = icalproperty_get_x_name(prop);

    if (prop_kind == ICAL_X_PROPERTY && x_name)
        property_name = x_name;
    else
        property_name = icalproperty_kind_to_string(prop_kind);

    if (!property_name) {
        icalerror_warn("Got a property of an unknown kind.");
        return NULL;
    }

    /* Create property array */
    jprop = json_array();


    /* Add property name */
    json_array_append_new(jprop,
                          json_string(lcase(icalmemory_tmp_copy(property_name))));


    /* Add parameters */
    jparams = json_object();
    for (param = icalproperty_get_first_parameter(prop, ICAL_ANY_PARAMETER);
         param != 0;
         param = icalproperty_get_next_parameter(prop, ICAL_ANY_PARAMETER)) {

        if (icalparameter_isa(param) == ICAL_VALUE_PARAMETER) continue;

        icalparameter_as_json_object_member(param, jparams);
    }
    json_array_append_new(jprop, jparams);


    /* Add type */
    type = icalproperty_value_kind_as_string(prop);
    json_array_append_new(jprop, json_string(lcase(icalmemory_tmp_copy(type))));


    /* Add value */
    value = icalproperty_get_value(prop);
    if (value) {
        switch (icalproperty_isa(prop)) {
        case ICAL_CATEGORIES_PROPERTY:
        case ICAL_RESOURCES_PROPERTY:
        case ICAL_POLLPROPERTIES_PROPERTY:
            if (icalvalue_isa(value) == ICAL_TEXT_VALUE) {
                /* Handle multi-valued properties */
                const char *str = icalvalue_as_ical_string(value);
                tok_t tok;

                tok_init(&tok, str, ",", TOK_TRIMLEFT|TOK_TRIMRIGHT|TOK_EMPTY);
                while ((str = tok_next(&tok))) {
                    if (*str) json_array_append_new(jprop, json_string(str));
                }
                tok_fini(&tok);
                break;
            }
            GCC_FALLTHROUGH

        default:
            json_array_append_new(jprop, icalvalue_as_json_object(value));
            break;
        }
    }

    return jprop;
}


/*
 * Construct a JSON array for an iCalendar component.
 */
EXPORTED json_t *icalcomponent_as_jcal_array(icalcomponent *comp)
{
    icalcomponent *c;
    icalproperty *p;
    icalcomponent_kind kind;
    const char* kind_string;
    json_t *jcomp, *jprops, *jsubs;

    if (!comp) return NULL;

    kind = icalcomponent_isa(comp);
    switch (kind) {
    case ICAL_NO_COMPONENT:
        return NULL;
        break;

    case ICAL_X_COMPONENT:
        kind_string = ""; //comp->x_name;
        break;

    default:
        kind_string = icalcomponent_kind_to_string(kind);
    }


    /* Create component array */
    jcomp = json_array();


    /* Add component name */
    json_array_append_new(jcomp,
        json_string(lcase(icalmemory_tmp_copy(kind_string))));


    /* Add properties */
    jprops = json_array();
    for (p = icalcomponent_get_first_property(comp, ICAL_ANY_PROPERTY);
         p;
         p = icalcomponent_get_next_property(comp, ICAL_ANY_PROPERTY)) {

        json_array_append_new(jprops, icalproperty_as_json_array(p));
    }
    json_array_append_new(jcomp, jprops);


    /* Add sub-components */
    jsubs = json_array();
    for (c = icalcomponent_get_first_component(comp, ICAL_ANY_COMPONENT);
         c;
         c = icalcomponent_get_next_component(comp, ICAL_ANY_COMPONENT)) {

        json_array_append_new(jsubs, icalcomponent_as_jcal_array(c));
    }
    json_array_append_new(jcomp, jsubs);

    return jcomp;
}


/*
 * Construct a jCal string for an iCalendar component.
 */
struct buf *icalcomponent_as_jcal_string(icalcomponent *ical)
{
    struct buf *ret;
    json_t *jcal;
    size_t flags = JSON_PRESERVE_ORDER;
    char *buf;

    if (!ical) return NULL;

    jcal = icalcomponent_as_jcal_array(ical);

    flags |= (config_httpprettytelemetry ? JSON_INDENT(2) : JSON_COMPACT);
    buf = json_dumps(jcal, flags);

    json_decref(jcal);

    ret = buf_new();
    buf_initm(ret, buf, strlen(buf));

    return ret;
}


static void buf_appendjson(struct buf *buf, json_t *jvalue)
{
    switch (json_typeof(jvalue)) {
    case JSON_ARRAY: {
        size_t i, n = json_array_size(jvalue);
        const char *sep = "";

        for (i = 0; i < n; i++, sep = ",") {
            buf_appendcstr(buf, sep);
            buf_appendjson(buf, json_array_get(jvalue, i));
        }
        break;
    }

    case JSON_STRING:
        buf_appendcstr(buf, json_string_value(jvalue));
        break;

    case JSON_INTEGER:
        buf_printf(buf, "%" JSON_INTEGER_FORMAT, json_integer_value(jvalue));
        break;

    case JSON_REAL:
        buf_printf(buf, "%f", json_real_value(jvalue));
        break;

    case JSON_TRUE:
    case JSON_FALSE:
        buf_printf(buf, "%d", json_boolean_value(jvalue));
        break;

    default:
        /* Shouldn't get here - ignore object */
        break;
    }
}


/*
 * Construct an iCalendar property value from a JSON object.
 */
static icalvalue *json_object_to_icalvalue(json_t *jvalue,
                                           icalvalue_kind kind)
{
    icalvalue *value = NULL;
    int len, i;

    switch (kind) {
    case ICAL_BOOLEAN_VALUE:
        if (json_is_boolean(jvalue))
            value = icalvalue_new_integer(json_is_true(jvalue));
        else
            syslog(LOG_WARNING, "jCal boolean object expected");
        break;

    case ICAL_FLOAT_VALUE:
        if (json_is_real(jvalue))
            value = icalvalue_new_float((float) json_real_value(jvalue));
        else
            syslog(LOG_WARNING, "jCal double object expected");
        break;

    case ICAL_GEO_VALUE:
        /* MUST be an array of 2 doubles */
        if (json_is_array(jvalue) && (len = json_array_size(jvalue)) != 2) {

            for (i = 0;
                 i < len && json_is_real(json_array_get(jvalue, i));
                 i++);
            if (i == len) {
                struct icalgeotype geo;
                double lat = json_real_value(json_array_get(jvalue, 0));
                double lon = json_real_value(json_array_get(jvalue, 1));

#ifdef ICAL_GEO_LEN
                snprintf(geo.lat, ICAL_GEO_LEN-1, "%lf", lat);
                snprintf(geo.lon, ICAL_GEO_LEN-1, "%lf", lon);
#else
                geo.lat = lat;
                geo.lon = lon;
#endif

                value = icalvalue_new_geo(geo);
            }
        }
        if (!value)
            syslog(LOG_WARNING, "jCal array object of 2 doubles expected");
        break;

    case ICAL_INTEGER_VALUE:
        if (json_is_integer(jvalue))
            value = icalvalue_new_integer((int) json_integer_value(jvalue));
        else if (json_is_string(jvalue))
            value = icalvalue_new_integer(atoi(json_string_value(jvalue)));
        else
            syslog(LOG_WARNING, "jCal integer object expected");
        break;

    case ICAL_RECUR_VALUE:
        if (json_is_object(jvalue)) {
            struct buf rrule = BUF_INITIALIZER;
            struct icalrecurrencetype *rt;
            const char *key, *sep = "";
            json_t *val;

            /* create an iCal RRULE string from jCal 'recur' object */
            json_object_foreach(jvalue, key, val) {
                char *mykey = xstrdup(key);
                buf_printf(&rrule, "%s%s=", sep, ucase(mykey));
                buf_appendjson(&rrule, val);
                sep = ";";
                free(mykey);
            }

            /* parse our iCal RRULE string */
            rt = icalrecurrencetype_new_from_string(buf_cstring(&rrule));
            buf_free(&rrule);

            if (rt->freq != ICAL_NO_RECURRENCE) value = icalvalue_new_recurrence(rt);
            icalrecurrencetype_unref(rt);
        }
        else
            syslog(LOG_WARNING, "jCal object object expected");
        break;

    case ICAL_REQUESTSTATUS_VALUE:
        /* MUST be an array of 2-3 strings */
        if (json_is_array(jvalue) &&
            ((len = json_array_size(jvalue)) == 2 || len == 3)) {

            for (i = 0;
                 i < len && json_is_string(json_array_get(jvalue, i));
                 i++);
            if (i == len) {
                struct icalreqstattype rst =
                    { ICAL_UNKNOWN_STATUS, NULL, NULL };
                short maj, min;

                if (sscanf(json_string_value(json_array_get(jvalue, 0)),
                           "%hd.%hd", &maj, &min) == 2) {
                    rst.code = icalenum_num_to_reqstat(maj, min);
                }
                if (rst.code == ICAL_UNKNOWN_STATUS) {
                    syslog(LOG_WARNING, "Unknown request-status code");
                    break;
                }

                rst.desc =
                    json_string_value(json_array_get(jvalue, 1));
                rst.debug = (len < 3) ? NULL :
                    json_string_value(json_array_get(jvalue, 2));

                value = icalvalue_new_requeststatus(rst);
            }
        }
        if (!value)
            syslog(LOG_WARNING, "jCal array object of 2-3 strings expected");
        break;

    case ICAL_UTCOFFSET_VALUE:
        if (json_is_string(jvalue)) {
            int utcoffset, hours, minutes, seconds = 0;
            char sign;

            if (sscanf(json_string_value(jvalue), "%c%02d:%02d:%02d",
                       &sign, &hours, &minutes, &seconds) < 3) {
                syslog(LOG_WARNING, "Unexpected utc-offset format");
                break;
            }

            utcoffset = hours*3600 + minutes*60 + seconds;

            if (sign == '-') utcoffset = -utcoffset;

            value = icalvalue_new_utcoffset(utcoffset);
        }
        else
            syslog(LOG_WARNING, "jCal string object expected");
        break;

    default:
        if (json_is_string(jvalue))
            value = icalvalue_new_from_string(kind,
                                              json_string_value(jvalue));
        else
            syslog(LOG_WARNING, "jCal string object expected");
        break;
    }

    return value;
}


/*
 * Construct an iCalendar property from a JSON array.
 */
static icalproperty *json_array_to_icalproperty(json_t *jprop)
{
    json_t *jtype, *jparams, *jvaltype, *jvalue;
    const char *propname, *typestr, *key;
    icalproperty_kind kind;
    icalproperty *prop = NULL;
    icalvalue_kind valkind;
    icalvalue *value;
    int len;

    /* Sanity check the types of the jCal property object */
    if (!json_is_array(jprop) || (len = json_array_size(jprop)) < 4) {
        syslog(LOG_WARNING,
               "jCal component object is not an array of 4+ objects");
        return NULL;
    }

    jtype = json_array_get(jprop, 0);
    jparams = json_array_get(jprop, 1);
    jvaltype = json_array_get(jprop, 2);

    if (!json_is_string(jtype) ||
        !json_is_object(jparams) || !json_is_string(jvaltype)) {
        syslog(LOG_WARNING, "jCal property array contains incorrect objects");
        return NULL;
    }

    /* Get the property type */
    propname = ucase(icalmemory_tmp_copy(json_string_value(jtype)));
    kind = icalenum_string_to_property_kind(propname);
    if (kind == ICAL_NO_PROPERTY) {
        syslog(LOG_WARNING, "Unknown jCal property type: %s", propname);
        return NULL;
    }

    /* Get the value type */
    typestr = json_string_value(jvaltype);
    valkind = !strcmp(typestr, "unknown") ? ICAL_X_VALUE :
        icalenum_string_to_value_kind(ucase(icalmemory_tmp_copy(typestr)));
    if (valkind == ICAL_NO_VALUE) {
        syslog(LOG_WARNING, "Unknown jCal value type for %s property: %s",
               propname, typestr);
        return NULL;
    }
    else if (valkind == ICAL_TEXT_VALUE) {
        /* "text" also includes enumerated types - grab type from property */
        valkind = icalproperty_kind_to_value_kind(kind);
    }

    /* Create new property */
    prop = icalproperty_new(kind);
    if (!prop) {
        syslog(LOG_ERR, "Creation of new %s property failed", propname);
        return NULL;
    }
    if (kind == ICAL_X_PROPERTY) icalproperty_set_x_name(prop, propname);

    /* Add parameters */
    json_object_foreach(jparams, key, jvalue) {
        /* XXX  Need to handle multi-valued parameters */
        icalproperty_set_parameter_from_string(prop,
                                               ucase(icalmemory_tmp_copy(key)),
                                               json_string_value(jvalue));
    }

    /* Add value */
    jvalue = json_array_get(jprop, 3);
    switch (kind) {
    case ICAL_CATEGORIES_PROPERTY:
    case ICAL_RESOURCES_PROPERTY:
    case ICAL_POLLPROPERTIES_PROPERTY:
        if (json_is_string(jvalue) && len > 4) {
            /* Handle multi-valued properties */
            struct buf buf = BUF_INITIALIZER;
            int i;

            buf_setcstr(&buf, json_string_value(jvalue));
            for (i = 4; i < len; i++) {
                buf_putc(&buf, ',');
                jvalue = json_array_get(jprop, i);
                buf_appendcstr(&buf, json_string_value(jvalue));
            }
            value = icalvalue_new_from_string(valkind, buf_cstring(&buf));
            buf_free(&buf);
            break;
        }
        GCC_FALLTHROUGH

    default:
        value = json_object_to_icalvalue(jvalue, valkind);
        if (!value) {
            syslog(LOG_ERR, "Creation of new %s property value failed",
                   propname);
            goto error;
        }
        break;
    }

    icalproperty_set_value(prop, value);

    return prop;

  error:
    icalproperty_free(prop);
    return NULL;
}


/*
 * Construct an iCalendar component from a JSON object.
 */
EXPORTED icalcomponent *jcal_array_as_icalcomponent(json_t *jobj)
{
    json_t *jtype, *jprops, *jsubs;
    const char *type;
    icalcomponent_kind kind;
    icalcomponent *comp = NULL;
    size_t i;

    /* Sanity check the types of the jCal component object */
    if (!json_is_array(jobj) || json_array_size(jobj) != 3) {
        syslog(LOG_WARNING,
               "jCal component object is not an array of 3 objects");
        return NULL;
    }

    jtype = json_array_get(jobj, 0);
    jprops = json_array_get(jobj, 1);
    jsubs = json_array_get(jobj, 2);

    if (!json_is_string(jtype) ||
        !json_is_array(jprops) || !json_is_array(jsubs)) {
        syslog(LOG_WARNING, "jCal component array contains incorrect objects");
        return NULL;
    }

    type = json_string_value(jtype);
    kind = icalenum_string_to_component_kind(ucase(icalmemory_tmp_copy(type)));
    if (kind == ICAL_NO_COMPONENT) {
        syslog(LOG_WARNING, "Unknown jCal component type: %s", type);
        return NULL;
    }

    /* Create new component */
    comp = icalcomponent_new(kind);
    if (!comp) {
        syslog(LOG_ERR, "Creation of new %s component failed", type);
        return NULL;
    }

    /* Add properties */
    for (i = 0; i < json_array_size(jprops); i++) {
        icalproperty *prop =
            json_array_to_icalproperty(json_array_get(jprops, i));

        if (!prop) goto error;

        icalcomponent_add_property(comp, prop);
    }

    /* Add sub-components */
    for (i = 0; i < json_array_size(jsubs); i++) {
        icalcomponent *sub =
            jcal_array_as_icalcomponent(json_array_get(jsubs, i));

        if (!sub) goto error;

        icalcomponent_add_component(comp, sub);
    }

    return comp;

  error:
    icalcomponent_free(comp);
    return NULL;
}


/*
 * Construct an iCalendar component from a jCal string.
 */
EXPORTED icalcomponent *jcal_string_as_icalcomponent(const struct buf *buf)
{
    json_t *jcal;
    json_error_t jerr;
    icalcomponent *ical;
    const char *str = buf_cstring(buf);

    if (!str) return NULL;

    jcal = json_loads(str, 0, &jerr);
    if (!jcal) {
        syslog(LOG_WARNING, "json parse error: '%s'", jerr.text);
        return NULL;
    }

    ical = jcal_array_as_icalcomponent(jcal);

    json_decref(jcal);

    return ical;
}


EXPORTED const char *begin_jcal(struct buf *buf, struct mailbox *mailbox,
                                const char *prodid, const char *name,
                                const char *desc, const char *color)
{
    icalcomponent *ical;
    icalproperty *prop;
    json_t *jprops;
    char *jbuf;
    size_t flags = JSON_PRESERVE_ORDER;

    flags |= (config_httpprettytelemetry ? JSON_INDENT(2) : JSON_COMPACT);

    /* Add toplevel properties */
    ical = icalcomponent_new_stream(mailbox, prodid, name, desc, color);
    jprops = json_array();

    for (prop = icalcomponent_get_first_property(ical, ICAL_ANY_PROPERTY);
         prop;
         prop = icalcomponent_get_next_property(ical, ICAL_ANY_PROPERTY)) {

        json_array_append_new(jprops, icalproperty_as_json_array(prop));
    }
    icalcomponent_free(ical);

    jbuf = json_dumps(jprops, flags);
    json_decref(jprops);

    /* Begin jCal stream */
    buf_reset(buf);
    buf_printf(buf, "[ \"vcalendar\",\r\n%s, [\r\n", jbuf);
    free(jbuf);

    return ",";
}


EXPORTED void end_jcal(struct buf *buf)
{
    /* End jCal stream */
    buf_setcstr(buf, "]]\r\n");
}
