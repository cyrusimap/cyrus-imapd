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

#ifdef WITH_JSON

#include <stdio.h>  /* for snprintf() */
#include <stdlib.h> /* for free() */
#include <string.h> /* for strcpy(), others */
#include <stddef.h> /* for offsetof() macro */

#include "httpd.h"
#include "jcal.h"
#include "util.h"
#include "xstrlcat.h"


/*
 * Construct an ISO.8601.2004 string for an iCalendar Date/Date-Time.
 */
static char *icaltime_as_json_string(const struct icaltimetype tt)
{
    static char str[21];
    const char *fmt;

    if (tt.is_date) fmt = "%04d-%02d-%02d";
    else if (tt.is_utc) fmt = "%04d-%02d-%02dT%02d:%02d:%02dZ";
    else fmt = "%04d-%02d-%02dT%02d:%02d:%02d";

    snprintf(str, sizeof(str), fmt, tt.year, tt.month, tt.day,
	     tt.hour, tt.minute, tt.second);

    return str;
}


/*
 * Construct a JSON object for an iCalendar Period.
 */
static char *icalperiodtype_as_json_string(struct icalperiodtype p)
{
    static char str[42];
    const char *start;
    const char *end;

    start = icaltime_as_json_string(p.start);
    snprintf(str, sizeof(str), "%s/", start);

    if (!icaltime_is_null_time(p.end))
	end = icaltime_as_json_string(p.end);
    else
	end = icaldurationtype_as_ical_string(p.duration);

    strlcat(str, end, sizeof(str));
    
    return str;
}


/*
 * Construct a JSON object for an iCalendar RRULE.
 */
static const struct {
    const char *str;
    size_t offset;
    int limit;
} recurmap[] = 
{
    {"bysecond",
     offsetof(struct icalrecurrencetype, by_second), ICAL_BY_SECOND_SIZE - 1},
    {"byminute",
     offsetof(struct icalrecurrencetype, by_minute), ICAL_BY_MINUTE_SIZE - 1},
    {"byhour",
     offsetof(struct icalrecurrencetype, by_hour), ICAL_BY_HOUR_SIZE - 1},
    {"byday",
     offsetof(struct icalrecurrencetype, by_day), ICAL_BY_DAY_SIZE - 1},
    {"bymonthday",
     offsetof(struct icalrecurrencetype, by_month_day),ICAL_BY_MONTHDAY_SIZE-1},
    {"byyearday",
     offsetof(struct icalrecurrencetype, by_year_day), ICAL_BY_YEARDAY_SIZE-1},
    {"byweekno",
     offsetof(struct icalrecurrencetype, by_week_no), ICAL_BY_WEEKNO_SIZE - 1},
    {"bymonth",
     offsetof(struct icalrecurrencetype, by_month), ICAL_BY_MONTH_SIZE - 1},
    {"bysetpos",
     offsetof(struct icalrecurrencetype, by_set_pos), ICAL_BY_SETPOS_SIZE - 1},
    {0,0,0},
};


extern const char* icalrecur_freq_to_string(icalrecurrencetype_frequency kind);
extern const char* icalrecur_weekday_to_string(icalrecurrencetype_weekday kind);

static json_object*
icalrecurrencetype_as_json_object(struct icalrecurrencetype *recur)
{
    char temp[20];
    int i,j;
    json_object *jrecur;

    if (recur->freq == ICAL_NO_RECURRENCE) return NULL;

    jrecur = json_object_new_object();

    json_object_object_add(jrecur, "freq",
	json_object_new_string(icalrecur_freq_to_string(recur->freq)));

    if (recur->until.year) {
	json_object_object_add(jrecur, "until",
	    json_object_new_string(icaltime_as_json_string(recur->until)));
    }

    if (recur->count) {
	json_object_object_add(jrecur, "count",
			       json_object_new_int(recur->count));
    }

    if (recur->interval != 1) {
	json_object_object_add(jrecur, "interval",
			       json_object_new_int(recur->interval));
    }

    for (j = 0; recurmap[j].str; j++){
	short *array = (short *)(recurmap[j].offset + (size_t)recur);
	int limit = recurmap[j].limit;

	/* Skip unused arrays */
	if (array[0] != ICAL_RECURRENCE_ARRAY_MAX) {

	    for (i=0; i< limit && array[i] != ICAL_RECURRENCE_ARRAY_MAX; i++) {
		if (j == 3) { /* BYDAY */
		    const char *daystr;
		    int pos;

		    daystr = icalrecur_weekday_to_string(
			icalrecurrencetype_day_day_of_week(array[i]));
		    pos = icalrecurrencetype_day_position(array[i]);  
		    
		    if (pos == 0) {
			json_object_object_add(jrecur, recurmap[j].str,
					       json_object_new_string(daystr));
		    } else {
			snprintf(temp, sizeof(temp), "%d%s", pos, daystr);
			json_object_object_add(jrecur, recurmap[j].str,
					       json_object_new_string(temp));
		    }                  
		} else {
		    json_object_object_add(jrecur, recurmap[j].str,
					   json_object_new_int(array[i]));
		}
	    }	 
	}
    }

    /* Monday is the default, so no need to write that out */
    if (recur->week_start != ICAL_MONDAY_WEEKDAY && 
	recur->week_start != ICAL_NO_WEEKDAY) {
	const char *daystr;

	daystr = icalrecur_weekday_to_string(
	    icalrecurrencetype_day_day_of_week(recur->week_start));
	json_object_object_add(jrecur, "wkst",
			       json_object_new_string(daystr));
    }

    return jrecur;
}


/*
 * Construct a JSON "structured value" for an iCalendar REQUEST-STATUS.
 */
static json_object *icalreqstattype_as_json_array(struct icalreqstattype stat)
{
    json_object *jstat;
    char code[22];

    icalerror_check_arg_rz((stat.code != ICAL_UNKNOWN_STATUS),"Status");

    if (!stat.desc) stat.desc = icalenum_reqstat_desc(stat.code);

    jstat = json_object_new_array();
  
    snprintf(code, sizeof(code), "%u.%u",
	     icalenum_reqstat_major(stat.code),
	     icalenum_reqstat_minor(stat.code));

    json_object_array_add(jstat, json_object_new_string(code));
    json_object_array_add(jstat, json_object_new_string(stat.desc));
    if (stat.debug)
	json_object_array_add(jstat, json_object_new_string(stat.debug));

    return jstat;
}


/*
 * Construct an ISO.8601.2004 string for an iCalendar UTC Offset.
 */
static char* icalvalue_utcoffset_as_json_string(const icalvalue* value)
{    
    static char str[10];
    const char *fmt;
    int off, h, m, s;
    char sign;

    off = icalvalue_get_utcoffset(value);

    if (abs(off) == off) sign = '+';
    else sign = '-';

    h = off/3600;
    m = (off - (h*3600))/ 60;
    s = (off - (h*3600) - (m*60));

    if (s > 0) fmt = "%c%02d:%02d:%02d";
    else fmt = "%c%02d:%02d";

    snprintf(str, sizeof(str), fmt, sign, abs(h), abs(m), abs(s));

    return str;
}


/*
 * Construct the proper JSON object for an iCalendar value.
 */
static json_object *icalvalue_as_json_object(const icalvalue *value)
{
    const char *str;
    json_object *obj;

    switch (icalvalue_isa(value)) {
    case ICAL_BOOLEAN_VALUE:
	return json_object_new_boolean(icalvalue_get_integer(value));

    case ICAL_DATE_VALUE:
	str = icaltime_as_json_string(icalvalue_get_date(value));
	return json_object_new_string(str);

    case ICAL_DATETIME_VALUE:
	str = icaltime_as_json_string(icalvalue_get_datetime(value));
	return json_object_new_string(str);

    case ICAL_DATETIMEPERIOD_VALUE: {
	struct icaldatetimeperiodtype dtp =
	    icalvalue_get_datetimeperiod(value);

	if (!icaltime_is_null_time(dtp.time))
	    str = icaltime_as_json_string(dtp.time);
	else
	    str = icalperiodtype_as_json_string(dtp.period);
	return json_object_new_string(str);
    }

    case ICAL_FLOAT_VALUE:
	return json_object_new_double(icalvalue_get_float(value));

    case ICAL_GEO_VALUE: {
	struct icalgeotype geo = icalvalue_get_geo(value);

	obj = json_object_new_array();
	json_object_array_add(obj, json_object_new_double(geo.lat));
	json_object_array_add(obj, json_object_new_double(geo.lon));
	return obj;
    }

    case ICAL_INTEGER_VALUE:
	return json_object_new_int(icalvalue_get_integer(value));

    case ICAL_PERIOD_VALUE:
	str = icalperiodtype_as_json_string(icalvalue_get_period(value));
	return json_object_new_string(str);

    case ICAL_RECUR_VALUE: {
	struct icalrecurrencetype recur = icalvalue_get_recur(value);
	return icalrecurrencetype_as_json_object(&recur);
    }

    case ICAL_REQUESTSTATUS_VALUE:
	return
	    icalreqstattype_as_json_array(icalvalue_get_requeststatus(value));

    case ICAL_TRIGGER_VALUE: {
	struct icaltriggertype trig = icalvalue_get_trigger(value);

	if (!icaltime_is_null_time(trig.time))
	    str = icaltime_as_json_string(trig.time);
	else
	    str = icaldurationtype_as_ical_string(trig.duration);
	return json_object_new_string(str);
    }

    case ICAL_UTCOFFSET_VALUE:
	str = icalvalue_utcoffset_as_json_string(value);
	return json_object_new_string(str);

    default:
	str = icalvalue_as_ical_string_r(value);
	if (str) {
	    obj = json_object_new_string(str);
	    free((void *) str);
	    return obj;
	}
    }

    return NULL;
}


/*
 * Add an iCalendar parameter to an existing JSON object.
 */
static void icalparameter_as_json_object_member(icalparameter *param,
						json_object *jparams)
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

    default:
	kind_string = icalparameter_kind_to_string(kind);
	if (kind_string) break;

    case ICAL_NO_PARAMETER:
    case ICAL_ANY_PARAMETER:
	    icalerror_set_errno(ICAL_BADARG_ERROR);
	    return;
    }

    value_string = icalparameter_get_xvalue(param);
    if (!value_string) {
	icalparameter_value value = icalparameter_get_value(param);

	if (value) value_string = icalparameter_enum_to_string(value);
    }
    if (!value_string) return;

    json_object_object_add(jparams, kind_string,
			   json_object_new_string(value_string));
}


/*
 * Determine the type (kind) of an iCalendar property value.
 */
extern icalvalue_kind icalproperty_kind_to_value_kind(icalproperty_kind kind);

static icalvalue_kind icalproperty_get_value_kind(icalproperty *prop)
{
    icalvalue_kind param_kind = ICAL_NO_VALUE;
    icalparameter *val_param;

    val_param = icalproperty_get_first_parameter(prop, ICAL_VALUE_PARAMETER);
    if (val_param) {
	param_kind = icalparameter_value_to_value_kind(
	    icalparameter_get_value(val_param));
    }

    if (param_kind != ICAL_NO_VALUE) {
	/* Use the kind specified in the VALUE param */
	return param_kind;
    }
    else {
	icalvalue_kind val_kind = ICAL_NO_VALUE;
	icalvalue *value = icalproperty_get_value(prop);

	if (value) val_kind = icalvalue_isa(value);
	
	if (val_kind != ICAL_NO_VALUE) {
	    /* Use the kind determined from the property value */
	    return val_kind;
	}
    }

    /* Use the default kind for the property */
    return icalproperty_kind_to_value_kind(icalproperty_isa(prop));
} 


/*
 * Construct a JSON array for an iCalendar property.
 */
static json_object *icalproperty_as_json_array(icalproperty *prop)
{   
    icalproperty_kind prop_kind;
    const char *x_name, *property_name = NULL; 
    icalparameter *param;
    icalvalue_kind val_kind;
    const char *kind_string = NULL;
    const icalvalue *value;
    json_object *jprop, *jparams;

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
    jprop = json_object_new_array();


    /* Add property name */
    json_object_array_add(jprop,
	json_object_new_string(lcase(icalmemory_tmp_copy(property_name))));


    /* Add parameters */
    jparams = json_object_new_object();
    json_object_array_add(jprop, jparams);

    for (param = icalproperty_get_first_parameter(prop, ICAL_ANY_PARAMETER);
	 param != 0;
	 param = icalproperty_get_next_parameter(prop, ICAL_ANY_PARAMETER)) {

	if (icalparameter_isa(param) == ICAL_VALUE_PARAMETER) continue;

	icalparameter_as_json_object_member(param, jparams);
    }


    /* Add type */
    val_kind = icalproperty_get_value_kind(prop);
    if (val_kind == ICAL_X_VALUE)
	kind_string = "unknown";
    else
	kind_string = icalvalue_kind_to_string(val_kind);

    json_object_array_add(jprop,
	json_object_new_string(lcase(icalmemory_tmp_copy(kind_string))));


    /* Add value */
    value = icalproperty_get_value(prop);
    if (value) json_object_array_add(jprop, icalvalue_as_json_object(value));

    return jprop;
}


/*
 * Construct a JSON array for an iCalendar component.
 */
static json_object *icalcomponent_as_json_array(icalcomponent *comp)
{
    icalcomponent *c;
    icalproperty *p;
    icalcomponent_kind kind;
    const char* kind_string;
    json_object *jcomp, *jprops, *jsubs;

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


    /* Create property array */
    jcomp = json_object_new_array();


    /* Add component name */
    json_object_array_add(jcomp,
	json_object_new_string(lcase(icalmemory_tmp_copy(kind_string))));


    /* Add properties */
    jprops = json_object_new_array();
    json_object_array_add(jcomp, jprops);

    for (p = icalcomponent_get_first_property(comp, ICAL_ANY_PROPERTY);
	 p;
	 p = icalcomponent_get_next_property(comp, ICAL_ANY_PROPERTY)) {

	icalerror_assert((p!=0),"Got a null property");
	json_object_array_add(jprops, icalproperty_as_json_array(p));
    }
   
   
    /* Add sub-components */
    jsubs = json_object_new_array();
    json_object_array_add(jcomp, jsubs);

    for (c = icalcomponent_get_first_component(comp, ICAL_ANY_COMPONENT);
	 c;
	 c = icalcomponent_get_next_component(comp, ICAL_ANY_COMPONENT)) {

	json_object_array_add(jsubs, icalcomponent_as_json_array(c));
    }
   
    return jcomp;
}


/*
 * Construct a jCal string for an iCalendar component.
 */
const char *icalcomponent_as_jcal_string(icalcomponent *ical)
{
    json_object *jcal;
    const char *buf;

    jcal = icalcomponent_as_json_array(ical);

    buf = json_object_to_json_string_ext(jcal,
					 config_httpprettytelemetry ?
					 JSON_C_TO_STRING_PRETTY :
					 JSON_C_TO_STRING_PLAIN);
    buf = icalmemory_tmp_copy(buf);

    json_object_put(jcal);

    return buf;
}

#endif  /* WITH_JSON */
