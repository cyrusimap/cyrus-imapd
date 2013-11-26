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
#include <stddef.h> /* for offsetof() macro */
#include <syslog.h>

#include "httpd.h"
#include "jcal.h"
#include "xcal.h"
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
static void icalrecur_add_int_to_json_object(void *jrecur, const char *rpart,
					     int i)
{
    json_object_object_add((json_object *) jrecur, rpart,
			   json_object_new_int(i));
}

static void icalrecur_add_string_to_json_object(void *jrecur, const char *rpart,
						const char *s)
{
    json_object_object_add((json_object *) jrecur, rpart,
			   json_object_new_string(s));
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
 * Construct the proper JSON object for an iCalendar value.
 */
static json_object *icalvalue_as_json_object(const icalvalue *value)
{
    const char *str = NULL;
    json_object *obj;

    switch (icalvalue_isa(value)) {
    case ICAL_BOOLEAN_VALUE:
	return json_object_new_boolean(icalvalue_get_integer(value));

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
	break;

    case ICAL_RECUR_VALUE: {
	struct icalrecurrencetype recur = icalvalue_get_recur(value);

	obj = json_object_new_object();
	icalrecurrencetype_add_as_xxx(&recur, obj,
				      &icalrecur_add_int_to_json_object,
				      &icalrecur_add_string_to_json_object);
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

    return (str ? json_object_new_string(str) : NULL);
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

    /* XXX  Need to handle multi-valued parameters */
    value_string = icalparameter_get_xvalue(param);
    if (!value_string) {
	icalparameter_value value = icalparameter_get_value(param);

	if (value) value_string = icalparameter_enum_to_string(value);
    }
    if (!value_string) return;

    json_object_object_add(jparams, lcase(icalmemory_tmp_copy(kind_string)),
			   json_object_new_string(value_string));
}


/*
 * Construct a JSON array for an iCalendar property.
 */
static json_object *icalproperty_as_json_array(icalproperty *prop)
{   
    icalproperty_kind prop_kind;
    const char *x_name, *property_name = NULL; 
    icalparameter *param;
    const char *type = NULL;
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
    type = icalproperty_value_kind_as_string(prop);
    json_object_array_add(jprop,
	json_object_new_string(lcase(icalmemory_tmp_copy(type))));


    /* Add value */
    /* XXX  Need to handle multi-valued properties */
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

    if (!ical) return NULL;

    jcal = icalcomponent_as_json_array(ical);

    buf = json_object_to_json_string_ext(jcal,
					 config_httpprettytelemetry ?
					 JSON_C_TO_STRING_PRETTY :
					 JSON_C_TO_STRING_PLAIN);
    buf = icalmemory_tmp_copy(buf);

    json_object_put(jcal);

    return buf;
}


struct icalrecur_parser {
    const char* rule;
    char* copy;
    char* this_clause;
    char* next_clause;

    struct icalrecurrencetype rt;
};

extern icalrecurrencetype_frequency icalrecur_string_to_freq(const char* str);
extern void icalrecur_add_byrules(struct icalrecur_parser *parser, short *array,
				  int size, char* vals);
extern void icalrecur_add_bydayrules(struct icalrecur_parser *parser,
				     const char* vals);

/*
 * Construct an iCalendar property value from a JSON object.
 */
static icalvalue *json_object_to_icalvalue(json_object *jvalue,
					   icalvalue_kind kind)
{
    icalvalue *value = NULL;
    int len, i;

    switch (kind) {
    case ICAL_BOOLEAN_VALUE:
	if (json_object_is_type(jvalue, json_type_boolean))
	    value = icalvalue_new_integer(json_object_get_boolean(jvalue));
	else
	    syslog(LOG_WARNING, "jCal boolean object expected");
	break;

    case ICAL_FLOAT_VALUE:
	if (json_object_is_type(jvalue, json_type_double))
	    value = icalvalue_new_float((float) json_object_get_double(jvalue));
	else
	    syslog(LOG_WARNING, "jCal double object expected");
	break;

    case ICAL_GEO_VALUE:
	/* MUST be an array of 2 doubles */
	if (json_object_is_type(jvalue, json_type_array) &&
	    (len = json_object_array_length(jvalue)) != 2) {

	    for (i = 0;
		 i < len &&
		     json_object_is_type(
			 json_object_array_get_idx(jvalue, i),
			 json_type_double);
		 i++);
	    if (i == len) {
		struct icalgeotype geo;

		geo.lat =
		    json_object_get_double(json_object_array_get_idx(jvalue, 0));
		geo.lon =
		    json_object_get_double(json_object_array_get_idx(jvalue, 1));

		value = icalvalue_new_geo(geo);
	    }
	}
	if (!value)
	    syslog(LOG_WARNING, "jCal array object of 2 doubles expected");
	break;

    case ICAL_INTEGER_VALUE:
	if (json_object_is_type(jvalue, json_type_int))
	    value = icalvalue_new_integer(json_object_get_int(jvalue));
	else
	    syslog(LOG_WARNING, "jCal integer object expected");
	break;

    case ICAL_RECUR_VALUE:
	if (json_object_is_type(jvalue, json_type_object)) {
	    struct icalrecurrencetype *rt = NULL;

	    json_object_object_foreach(jvalue, key, val) {
		rt = icalrecur_add_rule(&rt, key, val,
		    (int (*)(void *)) &json_object_get_int,
		    (const char * (*)(void *)) &json_object_get_string);
		if (!rt) break;
	    }

            if (rt && rt->freq != ICAL_NO_RECURRENCE)
		value = icalvalue_new_recur(*rt);
	}
	else
	    syslog(LOG_WARNING, "jCal object object expected");
	break;

    case ICAL_REQUESTSTATUS_VALUE:
	/* MUST be an array of 2-3 strings */
	if (json_object_is_type(jvalue, json_type_array) &&
	    ((len = json_object_array_length(jvalue)) == 2 || len == 3)) {

	    for (i = 0;
		 i < len &&
		     json_object_is_type(
			 json_object_array_get_idx(jvalue, i),
			 json_type_string);
		 i++);
	    if (i == len) {
		struct icalreqstattype rst =
		    { ICAL_UNKNOWN_STATUS, NULL, NULL };
		short maj, min;

		if (sscanf(json_object_get_string(
			       json_object_array_get_idx(jvalue, 0)),
			   "%hd.%hd", &maj, &min) == 2) {
		    rst.code = icalenum_num_to_reqstat(maj, min);
		}
		if (rst.code == ICAL_UNKNOWN_STATUS) {
		    syslog(LOG_WARNING, "Unknown request-status code");
		    break;
		}

		rst.desc =
		    json_object_get_string(json_object_array_get_idx(jvalue, 1));
		rst.debug = (len < 3) ? NULL :
		    json_object_get_string(json_object_array_get_idx(jvalue, 2));

		value = icalvalue_new_requeststatus(rst);
	    }
	}
	if (!value)
	    syslog(LOG_WARNING, "jCal array object of 2-3 strings expected");
	break;

    case ICAL_UTCOFFSET_VALUE:
	if (json_object_is_type(jvalue, json_type_string)) {
	    int utcoffset, hours, minutes, seconds = 0;
	    char sign;

	    if (sscanf(json_object_get_string(jvalue), "%c%02d:%02d:%02d",
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
	if (json_object_is_type(jvalue, json_type_string))
	    value = icalvalue_new_from_string(kind,
					      json_object_get_string(jvalue));
	else
	    syslog(LOG_WARNING, "jCal string object expected");
	break;
    }

    return value;
}


/*
 * Construct an iCalendar property from a JSON array.
 */
static icalproperty *json_array_to_icalproperty(json_object *jprop)
{
    json_object *jtype, *jparams, *jvaltype, *jvalue;
    const char *propname, *typestr;
    icalproperty_kind kind;
    icalproperty *prop = NULL;
    icalvalue_kind valkind;
    icalvalue *value;

    /* Sanity check the types of the jCal property object */
    if (!json_object_is_type(jprop, json_type_array) ||
	json_object_array_length(jprop) < 4) {
	syslog(LOG_WARNING,
	       "jCal component object is not an array of 4+ objects");
	return NULL;
    }

    jtype = json_object_array_get_idx(jprop, 0);
    jparams = json_object_array_get_idx(jprop, 1);
    jvaltype = json_object_array_get_idx(jprop, 2);

    if (!json_object_is_type(jtype, json_type_string) ||
	!json_object_is_type(jparams, json_type_object) ||
	!json_object_is_type(jvaltype, json_type_string)) {
	syslog(LOG_WARNING, "jCal property array contains incorrect objects");
	return NULL;
    }

    /* Get the property type */
    propname = ucase(icalmemory_tmp_copy(json_object_get_string(jtype)));
    kind = icalenum_string_to_property_kind(propname);
    if (kind == ICAL_NO_PROPERTY) {
	syslog(LOG_WARNING, "Unknown jCal property type: %s", propname);
	return NULL;
    }

    /* Get the value type */
    typestr = json_object_get_string(jvaltype);
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
    json_object_object_foreach(jparams, key, val) {
	/* XXX  Need to handle multi-valued parameters */
	icalproperty_set_parameter_from_string(prop,
					       ucase(icalmemory_tmp_copy(key)),
					       json_object_get_string(val));
    }

    /* Add value */
    /* XXX  Need to handle multi-valued properties */
    jvalue = json_object_array_get_idx(jprop, 3);
    value = json_object_to_icalvalue(jvalue, valkind);
    if (!value) {
	syslog(LOG_ERR, "Creation of new %s property value failed", propname);
	goto error;
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
static icalcomponent *json_object_to_icalcomponent(json_object *jobj)
{
    json_object *jtype, *jprops, *jsubs;
    const char *type;
    icalcomponent_kind kind;
    icalcomponent *comp = NULL;
    int i;

    /* Sanity check the types of the jCal component object */
    if (!json_object_is_type(jobj, json_type_array) ||
	json_object_array_length(jobj) != 3) {
	syslog(LOG_WARNING,
	       "jCal component object is not an array of 3 objects");
	return NULL;
    }

    jtype = json_object_array_get_idx(jobj, 0);
    jprops = json_object_array_get_idx(jobj, 1);
    jsubs = json_object_array_get_idx(jobj, 2);

    if (!json_object_is_type(jtype, json_type_string) ||
	!json_object_is_type(jprops, json_type_array) ||
	!json_object_is_type(jsubs, json_type_array)) {
	syslog(LOG_WARNING, "jCal component array contains incorrect objects");
	return NULL;
    }

    type = json_object_get_string(jtype);
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
    for (i = 0; i < json_object_array_length(jprops); i++) {
	icalproperty *prop =
	    json_array_to_icalproperty(json_object_array_get_idx(jprops, i));

	if (!prop) goto error;

	icalcomponent_add_property(comp, prop);
    }

    /* Add sub-components */
    for (i = 0; i < json_object_array_length(jsubs); i++) {
	icalcomponent *sub =
	    json_object_to_icalcomponent(json_object_array_get_idx(jsubs, i));

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
EXPORTED icalcomponent *jcal_string_as_icalcomponent(const char *str)
{
    json_object *jcal;
    enum json_tokener_error jerr;
    icalcomponent *ical;

    if (!str) return NULL;

    jcal = json_tokener_parse_verbose(str, &jerr);
    if (!jcal) {
	syslog(LOG_WARNING, "json parse error: '%s'",
	       json_tokener_error_desc(jerr));
	return NULL;
    }

    ical = json_object_to_icalcomponent(jcal);

    json_object_put(jcal);

    return ical;
}


EXPORTED const char *begin_jcal(struct buf *buf)
{
    /* Begin jCal stream */
    buf_reset(buf);
    buf_printf_markup(buf, 0, "[");
    buf_printf_markup(buf, 1, "\"vcalendar\",");
    buf_printf_markup(buf, 1, "[");
    buf_printf_markup(buf, 2, "[");
    buf_printf_markup(buf, 3, "\"prodid\",");
    buf_printf_markup(buf, 3, "{");
    buf_printf_markup(buf, 3, "},");
    buf_printf_markup(buf, 3, "\"text\",");
    buf_printf_markup(buf, 3, "\"-//CyrusIMAP.org/Cyrus %s//EN\"",
		      cyrus_version());
    buf_printf_markup(buf, 2, "],");
    buf_printf_markup(buf, 2, "[");
    buf_printf_markup(buf, 3, "\"version\",");
    buf_printf_markup(buf, 3, "{");
    buf_printf_markup(buf, 3, "},");
    buf_printf_markup(buf, 3, "\"text\",");
    buf_printf_markup(buf, 3, "\"2.0\"");
    buf_printf_markup(buf, 2, "]");
    buf_printf_markup(buf, 1, "],");
    buf_printf_markup(buf, 0, "[");

    return ",";
}


EXPORTED void end_jcal(struct buf *buf)
{
    /* End jCal stream */
    buf_setcstr(buf, "]]");
}

#endif  /* WITH_JSON */
