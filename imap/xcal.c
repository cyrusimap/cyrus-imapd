/* xcal.c -- Routines for converting iCalendar to/from xCal
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

#include <libxml/tree.h>

#include "httpd.h"
#include "ical_support.h"
#include "tok.h"
#include "util.h"
#include "version.h"
#include "xcal.h"
#include "xml_support.h"


/*
 * Determine the type (kind) of an iCalendar property value.
 */
const char *icalproperty_value_kind_as_string(icalproperty *prop)
{
    icalvalue_kind kind = ICAL_NO_VALUE;
    icalparameter *val_param;

    val_param = icalproperty_get_first_parameter(prop, ICAL_VALUE_PARAMETER);
    if (val_param) {
        /* Use the kind specified in the VALUE param */
        kind = icalparameter_value_to_value_kind(
            icalparameter_get_value(val_param));
    }

    if (kind == ICAL_NO_VALUE) {
        icalvalue *value = icalproperty_get_value(prop);

        if (value) {
            /* Use the kind determined from the property value */
            kind = icalvalue_isa(value);
        }
    }

    if (kind == ICAL_NO_VALUE) {
        /* Use the default kind for the property */
        kind = icalproperty_kind_to_value_kind(icalproperty_isa(prop));
    }

    switch (kind) {
    case ICAL_X_VALUE:
        return "unknown";

    case ICAL_ACTION_VALUE:
    case ICAL_CARLEVEL_VALUE:
    case ICAL_CLASS_VALUE:
    case ICAL_CMD_VALUE:
    case ICAL_METHOD_VALUE:
    case ICAL_QUERYLEVEL_VALUE:
    case ICAL_STATUS_VALUE:
    case ICAL_TRANSP_VALUE:
        return "text";

    default:
        return icalvalue_kind_to_string(kind);
    }
}


/*
 * Construct an ISO.8601.2004 string for an iCalendar Date/Date-Time.
 */
const char *icaltime_as_iso_string(const struct icaltimetype tt)
{
    static char str[21];
    const char *fmt;

    if (icaltime_is_date(tt)) fmt = "%04d-%02d-%02d";
    else if (icaltime_is_utc(tt)) fmt = "%04d-%02d-%02dT%02d:%02d:%02dZ";
    else fmt = "%04d-%02d-%02dT%02d:%02d:%02d";

    snprintf(str, sizeof(str), fmt, tt.year, tt.month, tt.day,
             tt.hour, tt.minute, tt.second);

    return str;
}


/*
 * Construct an ISO.8601.2004 string for an iCalendar UTC Offset.
 */
const char *icalvalue_utcoffset_as_iso_string(const icalvalue* value)
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
 * Add iCalendar recur-rule-parts to a structured element.
 */
void icalrecurrencetype_add_as_xxx(struct icalrecurrencetype *recur, void *obj,
                                   void (*add_int)(void *, const char *, int),
                                   void (*add_str)(void *, const char *,
                                                   const char *))
{
    char *rrule, *rpart;
    tok_t rparts;

    /* generate an iCal RRULE string */
    rrule = icalrecurrencetype_as_string_r(recur);

    /* split string into rparts & values */
    tok_initm(&rparts, rrule, "=;", TOK_TRIMLEFT|TOK_TRIMRIGHT);
    while ((rpart = (char *)tok_next(&rparts))) {
        if (!strcmp(rpart, "UNTIL")) {
            /* need to translate date format to ISO */
            struct icaltimetype until = icaltime_from_string(tok_next(&rparts));

            add_str(obj, "until", icaltime_as_iso_string(until));
        }
        else {
            /* assume the rpart has multiple values - split them */
            tok_t vlist;
            const char *val;
            char *p;

            tok_init(&vlist, tok_next(&rparts), ",",
                     TOK_TRIMLEFT|TOK_TRIMRIGHT);
            while ((val = tok_next(&vlist))) {
                if (add_int) {
                    /* try converting value to integer */
                    int n = strtol(val, &p, 10);

                    if (n && !*p) {
                        add_int(obj, lcase(rpart), n);
                        continue;
                    }
                }

                add_str(obj, lcase(rpart), val);
            }
            tok_fini(&vlist);
        }
    }
    tok_fini(&rparts);

    free(rrule);
}


/*
 * Add an XML element for an iCalendar Period.
 */
static void icalperiodtype_add_as_xml_element(xmlNodePtr xtype,
                                              struct icalperiodtype p)
{
    const char *start;
    const char *end;

    start = icaltime_as_iso_string(p.start);
    xmlNewTextChild(xtype, NULL, BAD_CAST "start", BAD_CAST start);

    if (!icaltime_is_null_time(p.end)) {
        end = icaltime_as_iso_string(p.end);
        xmlNewTextChild(xtype, NULL, BAD_CAST "end", BAD_CAST end);
    }
    else {
        end = icaldurationtype_as_ical_string(p.duration);
        xmlNewTextChild(xtype, NULL, BAD_CAST "duration", BAD_CAST end);
    }
}


/*
 * Add an iCalendar recur-rule-part to a XML recur element.
 */
static void icalrecur_add_string_as_xml_element(void *xrecur, const char *rpart,
                                                const char *s)
{
    xmlNewTextChild((xmlNodePtr) xrecur, NULL, BAD_CAST rpart, BAD_CAST s);
}


/*
 * Construct an XML element for an iCalendar parameter.
 */
static xmlNodePtr icalparameter_as_xml_element(icalparameter *param)
{
    icalparameter_kind kind;
    icalparameter_value value;
    const char *kind_string, *type_string, *value_string;
    xmlNodePtr xparam;

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

        GCC_FALLTHROUGH

    case ICAL_NO_PARAMETER:
    case ICAL_ANY_PARAMETER:
            icalerror_set_errno(ICAL_BADARG_ERROR);
            return NULL;
    }

    /* Get value type */
    switch (kind) {
    case ICAL_ALTREP_PARAMETER:
    case ICAL_DIR_PARAMETER:
        type_string = "uri";
        break;

    case ICAL_DELEGATEDFROM_PARAMETER:
    case ICAL_DELEGATEDTO_PARAMETER:
    case ICAL_MEMBER_PARAMETER:
    case ICAL_SENTBY_PARAMETER:
        type_string = "cal-address";
        break;

    case ICAL_RSVP_PARAMETER:
        type_string = "boolean";
        break;

    default:
        type_string = "text";
        break;
    }

    /* XXX  Need to handle multi-valued parameters */
    value = icalparameter_get_value(param);
    if (value == ICAL_VALUE_X) value_string = icalparameter_get_xvalue(param);
    else value_string = icalparameter_enum_to_string(value);
    if (!value_string) return NULL;

    xparam = xmlNewNode(NULL, BAD_CAST lcase(icalmemory_tmp_copy(kind_string)));
    xmlNewTextChild(xparam, NULL, BAD_CAST type_string, BAD_CAST value_string);

    return xparam;
}


/*
 * Add the proper XML element for an iCalendar value.
 */
static void icalproperty_add_value_as_xml_element(xmlNodePtr xprop,
                                                  icalproperty *prop)

{
    const char *type, *str = NULL;
    xmlNodePtr xtype;
    const icalvalue *value;
    char buf[40];

    /* Add type */
    type = lcase(icalmemory_tmp_copy(
                     icalproperty_value_kind_as_string(prop)));
    xtype = xmlNewChild(xprop, NULL, BAD_CAST type, NULL);


    /* Add value */
    value = icalproperty_get_value(prop);

    switch (icalvalue_isa(value)) {
    case ICAL_DATE_VALUE:
        str = icaltime_as_iso_string(icalvalue_get_date(value));
        break;

    case ICAL_DATETIME_VALUE:
        str = icaltime_as_iso_string(icalvalue_get_datetime(value));
        break;

    case ICAL_DATETIMEPERIOD_VALUE: {
        struct icaldatetimeperiodtype dtp =
            icalvalue_get_datetimeperiod(value);

        if (!icaltime_is_null_time(dtp.time)) {
            str = icaltime_as_iso_string(dtp.time);
            break;
        }
        else {
            icalperiodtype_add_as_xml_element(xtype, dtp.period);
            return;
        }
    }

    case ICAL_GEO_VALUE: {
        struct icalgeotype geo = icalvalue_get_geo(value);

        snprintf(buf, sizeof(buf), "%f", geo.lat);
        xmlNewTextChild(xtype, NULL, BAD_CAST "latitude", BAD_CAST buf);
        snprintf(buf, sizeof(buf), "%f", geo.lon);
        xmlNewTextChild(xtype, NULL, BAD_CAST "longitude", BAD_CAST buf);
        return;
    }

    case ICAL_PERIOD_VALUE:
        icalperiodtype_add_as_xml_element(xtype, icalvalue_get_period(value));
        return;

    case ICAL_RECUR_VALUE: {
        struct icalrecurrencetype recur = icalvalue_get_recur(value);

        icalrecurrencetype_add_as_xxx(&recur, xtype, NULL,
                                      &icalrecur_add_string_as_xml_element);
        return;
    }

    case ICAL_REQUESTSTATUS_VALUE: {
        struct icalreqstattype stat = icalvalue_get_requeststatus(value);

        if (!stat.desc) stat.desc = icalenum_reqstat_desc(stat.code);

        snprintf(buf, sizeof(buf), "%u.%u",
                 icalenum_reqstat_major(stat.code),
                 icalenum_reqstat_minor(stat.code));
        xmlNewTextChild(xtype, NULL, BAD_CAST "code", BAD_CAST buf);
        xmlNewTextChild(xtype, NULL, BAD_CAST "description", BAD_CAST stat.desc);
        if (stat.debug)
            xmlNewTextChild(xtype, NULL, BAD_CAST "data", BAD_CAST stat.debug);

        return;
    }

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

        switch (icalproperty_isa(prop)) {
        case ICAL_CATEGORIES_PROPERTY:
        case ICAL_RESOURCES_PROPERTY:
        case ICAL_POLLPROPERTIES_PROPERTY:
            if (strchr(str, ',')) {
                /* Handle multi-valued properties */
                tok_t tok;

                tok_init(&tok, str, ",", TOK_TRIMLEFT|TOK_TRIMRIGHT|TOK_EMPTY);
                str = tok_next(&tok);
                xmlAddChild(xtype, xmlNewText(BAD_CAST str));

                while ((str = tok_next(&tok))) {
                    if (*str) {
                        xtype = xmlNewChild(xprop, NULL, BAD_CAST type, NULL);
                        xmlAddChild(xtype, xmlNewText(BAD_CAST str));
                    }
                }
                tok_fini(&tok);
                return;
            }

        default: break;
        }

        break;
    }

    if (str) xmlAddChild(xtype, xmlNewText(BAD_CAST str));
}


/*
 * Construct an XML element for an iCalendar property.
 */
static xmlNodePtr icalproperty_as_xml_element(icalproperty *prop)
{
    icalproperty_kind prop_kind;
    const char *x_name, *property_name = NULL;
    icalparameter *param;
    xmlNodePtr xprop, xparams = NULL;

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

    /* Create property */
    xprop = xmlNewNode(NULL,
                       BAD_CAST lcase(icalmemory_tmp_copy(property_name)));


    /* Add parameters */
    for (param = icalproperty_get_first_parameter(prop, ICAL_ANY_PARAMETER);
         param != 0;
         param = icalproperty_get_next_parameter(prop, ICAL_ANY_PARAMETER)) {

        if (icalparameter_isa(param) == ICAL_VALUE_PARAMETER) continue;

        if (!xparams)
            xparams = xmlNewChild(xprop, NULL, BAD_CAST "parameters", NULL);

        xmlAddChild(xparams, icalparameter_as_xml_element(param));
    }


    /* Add value */
    icalproperty_add_value_as_xml_element(xprop, prop);

    return xprop;
}


/*
 * Construct a XML element for an iCalendar component.
 */
static xmlNodePtr icalcomponent_as_xml_element(icalcomponent *comp)
{
    icalcomponent *c;
    icalproperty *p;
    icalcomponent_kind kind;
    const char* kind_string;
    xmlNodePtr xcomp, xprops = NULL, xsubs = NULL;

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


    /* Create component */
    xcomp = xmlNewNode(NULL,
                       BAD_CAST lcase(icalmemory_tmp_copy(kind_string)));


    /* Add properties */
    for (p = icalcomponent_get_first_property(comp, ICAL_ANY_PROPERTY);
         p;
         p = icalcomponent_get_next_property(comp, ICAL_ANY_PROPERTY)) {

        if (!xprops)
            xprops = xmlNewChild(xcomp, NULL, BAD_CAST "properties", NULL);

        xmlAddChild(xprops, icalproperty_as_xml_element(p));
    }


    /* Add sub-components */
    for (c = icalcomponent_get_first_component(comp, ICAL_ANY_COMPONENT);
         c;
         c = icalcomponent_get_next_component(comp, ICAL_ANY_COMPONENT)) {

        if (!xsubs)
            xsubs = xmlNewChild(xcomp, NULL, BAD_CAST "components", NULL);

        xmlAddChild(xsubs, icalcomponent_as_xml_element(c));
    }

    return xcomp;
}


/*
 * Construct a xcal string for an iCalendar component.
 */
struct buf *icalcomponent_as_xcal_string(icalcomponent *ical)
{
    struct buf *ret;
    xmlDocPtr doc;
    xmlNodePtr root, xcomp;
    xmlChar *buf;
    int bufsiz;

    if (!ical) return NULL;

    doc = xmlNewDoc(BAD_CAST "1.0");
    root = xmlNewNode(NULL, BAD_CAST "icalendar");
    xmlNewNs(root, BAD_CAST XML_NS_ICALENDAR, NULL);
    xmlDocSetRootElement(doc, root);

    xcomp = icalcomponent_as_xml_element(ical);

    xmlAddChild(root, xcomp);

    if (!xmlStrcmp(xcomp->name, BAD_CAST "vcalendar")) {
        /* Complete iCalendar stream */
        xmlDocDumpFormatMemoryEnc(doc, &buf, &bufsiz, "utf-8",
                                  config_httpprettytelemetry);
    }
    else {
        /* Single iCalendar object */
        xmlBufferPtr xbuf = xmlBufferCreate();

        bufsiz = xmlNodeDump(xbuf, doc, xcomp,
                             0, config_httpprettytelemetry);
        buf = xmlBufferDetach(xbuf);
        xmlBufferFree(xbuf);
    }

    xmlFreeDoc(doc);

    ret = buf_new();
    buf_initm(ret, (char *) buf, bufsiz);

    return ret;
}


static void append_byrule(char *byrule, struct buf *vals, struct buf *rrule)
{
    /* append BY* rule to RRULE buffer */
    buf_printf(rrule, ";%s=%s", ucase(byrule), buf_cstring(vals));

    /* free the vals buffer */
    buf_free(vals);
    free(vals);
}


/*
 * Construct an iCalendar property value from XML content.
 */
static icalvalue *xml_element_to_icalvalue(xmlNodePtr xtype,
                                           icalvalue_kind kind)
{
    icalvalue *value = NULL;
    xmlNodePtr node;
    xmlChar *content = NULL;

    switch (kind) {

    case ICAL_GEO_VALUE: {
        struct icalgeotype geo;

        node = xmlFirstElementChild(xtype);
        if (!node) {
            syslog(LOG_WARNING, "Missing <latitude> XML element");
            break;
        }
        else if (xmlStrcmp(node->name, BAD_CAST "latitude")) {
            syslog(LOG_WARNING,
                   "Expected <latitude> XML element, received %s", node->name);
            break;
        }

        content = xmlNodeGetContent(node);
        geo.lat = atof((const char *) content);

        node = xmlNextElementSibling(node);
        if (!node) {
            syslog(LOG_WARNING, "Missing <longitude> XML element");
            break;
        }
        else if (xmlStrcmp(node->name, BAD_CAST "longitude")) {
            syslog(LOG_WARNING,
                   "Expected <longitude> XML element, received %s", node->name);
            break;
        }

        xmlFree(content);
        content = xmlNodeGetContent(node);
        geo.lon = atof((const char *) content);

        value = icalvalue_new_geo(geo);

        break;
    }

    case ICAL_PERIOD_VALUE: {
        struct icalperiodtype p;

        p.start = p.end = icaltime_null_time();
        p.duration = icaldurationtype_from_int(0);

        node = xmlFirstElementChild(xtype);
        if (!node) {
            syslog(LOG_WARNING, "Missing <start> XML element");
            break;
        }
        else if (xmlStrcmp(node->name, BAD_CAST "start")) {
            syslog(LOG_WARNING,
                   "Expected <start> XML element, received %s", node->name);
            break;
        }

        content = xmlNodeGetContent(node);
        p.start = icaltime_from_string((const char *) content);
        if (icaltime_is_null_time(p.start)) break;

        node = xmlNextElementSibling(node);
        if (!node) {
            syslog(LOG_WARNING, "Missing <end> / <duration> XML element");
            break;
        }
        else if (!xmlStrcmp(node->name, BAD_CAST "end")) {
            xmlFree(content);
            content = xmlNodeGetContent(node);
            p.end = icaltime_from_string((const char *) content);
            if (icaltime_is_null_time(p.end)) break;
        }
        else if (!xmlStrcmp(node->name, BAD_CAST "duration")) {
            xmlFree(content);
            content = xmlNodeGetContent(node);
            p.duration = icaldurationtype_from_string((const char *) content);
            if (icaldurationtype_as_int(p.duration) == 0) break;
        }
        else {
            syslog(LOG_WARNING,
                   "Expected <end> / <duration> XML element, received %s",
                   node->name);
            break;
        }

        value = icalvalue_new_period(p);

        break;
    }

    case ICAL_RECUR_VALUE: {
        struct buf rrule = BUF_INITIALIZER;
        struct hash_table byrules;
        struct icalrecurrencetype rt;
        char *sep = "";

        construct_hash_table(&byrules, 10, 1);

        /* create an iCal RRULE string from xCal <recur> sub-elements */
        for (node = xmlFirstElementChild(xtype); node;
             node = xmlNextElementSibling(node)) {

            content = xmlNodeGetContent(node);
            if (!xmlStrncmp(node->name, BAD_CAST "by", 2)) {
                /* BY* rules can have a list of values -
                   assemble them using a hash table */
                struct buf *vals =
                    hash_lookup((const char *) node->name, &byrules);

                if (vals) {
                    /* append this value to existing list */
                    buf_printf(vals, ",%s", (char *) content);
                }
                else {
                    /* create new list with this value */
                    vals = xzmalloc(sizeof(struct buf));
                    buf_setcstr(vals, (char *) content);
                    hash_insert((char *) node->name, vals, &byrules);
                }
            }
            else {
                /* single value rpart */
                buf_printf(&rrule, "%s%s=%s", sep,
                           ucase((char *) node->name), (char *) content);
                sep = ";";
            }

            xmlFree(content);
            content = NULL;
        }

        /* append the BY* rules to RRULE buffer */
        hash_enumerate(&byrules,
                       (void (*)(const char*, void*, void*)) &append_byrule,
                       &rrule);
        free_hash_table(&byrules, NULL);

        /* parse our iCal RRULE string */
        rt = icalrecurrencetype_from_string(buf_cstring(&rrule));
        buf_free(&rrule);

        if (rt.freq != ICAL_NO_RECURRENCE) value = icalvalue_new_recur(rt);

        break;
    }

    case ICAL_REQUESTSTATUS_VALUE: {
        struct icalreqstattype rst = { ICAL_UNKNOWN_STATUS, NULL, NULL };
        short maj, min;

        node = xmlFirstElementChild(xtype);
        if (!node) {
            syslog(LOG_WARNING, "Missing <code> XML element");
            break;
        }
        else if (xmlStrcmp(node->name, BAD_CAST "code")) {
            syslog(LOG_WARNING,
                   "Expected <code> XML element, received %s", node->name);
            break;
        }

        content = xmlNodeGetContent(node);
        if (sscanf((const char *) content, "%hd.%hd", &maj, &min) == 2) {
            rst.code = icalenum_num_to_reqstat(maj, min);
        }
        if (rst.code == ICAL_UNKNOWN_STATUS) {
            syslog(LOG_WARNING, "Unknown request-status code");
            break;
        }

        node = xmlNextElementSibling(node);
        if (!node) {
            syslog(LOG_WARNING, "Missing <description> XML element");
            break;
        }
        else if (xmlStrcmp(node->name, BAD_CAST "description")) {
            syslog(LOG_WARNING,
                   "Expected <description> XML element, received %s",
                   node->name);
            break;
        }

        xmlFree(content);
        content = xmlNodeGetContent(node);
        rst.desc = (const char *) content;

        node = xmlNextElementSibling(node);
        if (node) {
            if (xmlStrcmp(node->name, BAD_CAST "data")) {
                syslog(LOG_WARNING,
                       "Expected <data> XML element, received %s", node->name);
                break;
            }

            xmlFree(content);
            content = xmlNodeGetContent(node);
            rst.debug = (const char *) content;
        }

        value = icalvalue_new_requeststatus(rst);
        break;
    }

    case ICAL_UTCOFFSET_VALUE: {
        int n, utcoffset, hours, minutes, seconds = 0;
        char sign;

        content = xmlNodeGetContent(xtype);
        n = sscanf((const char *) content, "%c%02d:%02d:%02d",
                   &sign, &hours, &minutes, &seconds);

        if (n < 3) {
            syslog(LOG_WARNING, "Unexpected utc-offset format");
            break;
        }

        utcoffset = hours*3600 + minutes*60 + seconds;

        if (sign == '-') utcoffset = -utcoffset;

        value = icalvalue_new_utcoffset(utcoffset);
        break;
    }

    default:
        content = xmlNodeGetContent(xtype);
        value = icalvalue_new_from_string(kind, (const char *) content);
        break;
    }

    if (content) xmlFree(content);

    return value;
}


/*
 * Construct an iCalendar property from a XML element.
 */
static icalproperty *xml_element_to_icalproperty(xmlNodePtr xprop)
{
    const char *propname, *typestr;
    icalproperty_kind kind;
    icalproperty *prop = NULL;
    icalvalue_kind valkind;
    icalvalue *value;
    xmlNodePtr node;

    /* Get the property type */
    propname = ucase(icalmemory_tmp_copy((const char *) xprop->name));
    kind = icalenum_string_to_property_kind(propname);
    if (kind == ICAL_NO_PROPERTY) {
        syslog(LOG_WARNING, "Unknown xCal property type: %s", propname);
        return NULL;
    }

    /* Create new property */
    prop = icalproperty_new(kind);
    if (!prop) {
        syslog(LOG_ERR, "Creation of new %s property failed", propname);
        return NULL;
    }
    if (kind == ICAL_X_PROPERTY) icalproperty_set_x_name(prop, propname);


    /* Add parameters */
    node = xmlFirstElementChild(xprop);
    if (node && !xmlStrcmp(node->name, BAD_CAST "parameters")) {
        xmlNodePtr xparam;

        for (xparam = xmlFirstElementChild(node); xparam;
             xparam = xmlNextElementSibling(xparam)) {
            char *paramname =
                ucase(icalmemory_tmp_copy((const char *) xparam->name));
            xmlChar *paramval = xmlNodeGetContent(xmlFirstElementChild(xparam));

            /* XXX  Need to handle multi-valued parameters */
            icalproperty_set_parameter_from_string(prop, paramname,
                                                   (const char *) paramval);

            xmlFree(paramval);
        }

        node = xmlNextElementSibling(node);
    }

    /* Get the value type */
    if (!node) {
        syslog(LOG_WARNING, "Missing xCal value for %s property",
               propname);
        return NULL;
    }
    typestr = ucase(icalmemory_tmp_copy((const char *) node->name));
    valkind = !strcmp(typestr, "UNKNOWN") ? ICAL_X_VALUE :
        icalenum_string_to_value_kind(typestr);
    if (valkind == ICAL_NO_VALUE) {
        syslog(LOG_WARNING, "Unknown xCal value type for %s property: %s",
               propname, typestr);
        return NULL;
    }
    else if (valkind == ICAL_TEXT_VALUE) {
        /* "text" also includes enumerated types - grab type from property */
        valkind = icalproperty_kind_to_value_kind(kind);
    }


    /* Add value */
    switch (kind) {
    case ICAL_CATEGORIES_PROPERTY:
    case ICAL_RESOURCES_PROPERTY:
    case ICAL_POLLPROPERTIES_PROPERTY:
        if (valkind == ICAL_TEXT_VALUE) {
            /* Handle multi-valued properties */
            struct buf buf = BUF_INITIALIZER;
            xmlChar *content = NULL;

            content = xmlNodeGetContent(node);
            buf_setcstr(&buf, (const char *) content);
            free(content);

            while ((node = xmlNextElementSibling(node))) {
                buf_putc(&buf, ',');
                content = xmlNodeGetContent(node);
                buf_appendcstr(&buf, (const char *) content);
                free(content);
            }

            value = icalvalue_new_from_string(valkind, buf_cstring(&buf));
            buf_free(&buf);
            break;
        }
        GCC_FALLTHROUGH

    default:
        value = xml_element_to_icalvalue(node, valkind);
        if (!value) {
            syslog(LOG_ERR, "Parsing %s property value failed", propname);
            goto error;
        }
    }

    icalproperty_set_value(prop, value);


    /* Sanity check */
    if ((node = xmlNextElementSibling(node))) {
        syslog(LOG_WARNING,
        "Unexpected XML element in property: %s", node->name);
        goto error;
    }

    return prop;

  error:
    icalproperty_free(prop);
    return NULL;
}


/*
 * Construct an iCalendar component from a XML element.
 */
static icalcomponent *xml_element_to_icalcomponent(xmlNodePtr xcomp)
{
    icalcomponent_kind kind;
    icalcomponent *comp = NULL;
    xmlNodePtr node, xprop, xsub;

    if (!xcomp) return NULL;

    /* Get component type */
    kind =
        icalenum_string_to_component_kind(
            ucase(icalmemory_tmp_copy((const char *) xcomp->name)));
    if (kind == ICAL_NO_COMPONENT) {
        syslog(LOG_WARNING, "Unknown xCal component type: %s", xcomp->name);
        return NULL;
    }

    /* Create new component */
    comp = icalcomponent_new(kind);
    if (!comp) {
        syslog(LOG_ERR, "Creation of new %s component failed", xcomp->name);
        return NULL;
    }

    /* Add properties */
    node = xmlFirstElementChild(xcomp);
    if (!node || xmlStrcmp(node->name, BAD_CAST "properties")) {
        syslog(LOG_WARNING,
               "Expected <properties> XML element, received %s", node->name);
        goto error;
    }
    for (xprop = xmlFirstElementChild(node); xprop;
         xprop = xmlNextElementSibling(xprop)) {
        icalproperty *prop = xml_element_to_icalproperty(xprop);

        if (!prop) goto error;

        icalcomponent_add_property(comp, prop);
    }

    /* Add sub-components */
    if (!(node = xmlNextElementSibling(node))) return comp;

    if (xmlStrcmp(node->name, BAD_CAST "components")) {
        syslog(LOG_WARNING,
               "Expected <components> XML element, received %s", node->name);
        goto error;
    }

    for (xsub = xmlFirstElementChild(node); xsub;
         xsub = xmlNextElementSibling(xsub)) {
        icalcomponent *sub = xml_element_to_icalcomponent(xsub);

        if (!sub) goto error;

        icalcomponent_add_component(comp, sub);
    }

    /* Sanity check */
    if ((node = xmlNextElementSibling(node))) {
        syslog(LOG_WARNING,
        "Unexpected XML element in component: %s", node->name);
        goto error;
    }

    return comp;

  error:
    icalcomponent_free(comp);
    return NULL;
}


/*
 * Construct an iCalendar component from an xCal string.
 */
icalcomponent *xcal_string_as_icalcomponent(const struct buf *buf)
{
    xmlParserCtxtPtr ctxt;
    xmlDocPtr doc = NULL;
    xmlNodePtr root;
    icalcomponent *ical = NULL;

    if (!buf_len(buf)) return NULL;

    /* Parse the XML request */
    ctxt = xmlNewParserCtxt();
    if (ctxt) {
        doc = xmlCtxtReadMemory(ctxt, buf_base(buf), buf_len(buf), NULL, NULL,
                                XML_PARSE_NOWARNING);
        xmlFreeParserCtxt(ctxt);
    }
    if (!doc) {
        syslog(LOG_WARNING, "XML parse error");
        return NULL;
    }

    /* Get root element */
    if (!(root = xmlDocGetRootElement(doc)) ||
        xmlStrcmp(root->name, BAD_CAST "icalendar") ||
        xmlStrcmp(root->ns->href, BAD_CAST XML_NS_ICALENDAR)) {
        syslog(LOG_WARNING,
               "XML root element is not %s:icalendar", XML_NS_ICALENDAR);
        goto done;
    }

    ical = xml_element_to_icalcomponent(xmlFirstElementChild(root));

  done:
    xmlFreeDoc(doc);

    return ical;
}


const char *begin_xcal(struct buf *buf, struct mailbox *mailbox,
                       const char *prodid, const char *name,
                       const char *desc, const char *color)
{
    icalcomponent *ical;
    icalproperty *prop;
    xmlDocPtr doc;
    xmlNodePtr props;
    xmlBufferPtr xmlbuf;

    /* Add toplevel properties */
    ical = icalcomponent_new_stream(mailbox, prodid, name, desc, color);
    doc = xmlNewDoc(BAD_CAST "1.0");
    props = xmlNewNode(NULL, BAD_CAST "properties");
    xmlDocSetRootElement(doc, props);

    for (prop = icalcomponent_get_first_property(ical, ICAL_ANY_PROPERTY);
         prop;
         prop = icalcomponent_get_next_property(ical, ICAL_ANY_PROPERTY)) {

        xmlAddChild(props, icalproperty_as_xml_element(prop));
    }
    icalcomponent_free(ical);


    /* Dump XML node into buffer */
    xmlbuf = xmlBufferCreate();
    xmlNodeDump(xmlbuf, doc, props, 1, config_httpprettytelemetry);
    xmlFreeDoc(doc);

    /* Begin xCal stream */
    buf_setcstr(buf, "<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n");
    buf_printf(buf, "<icalendar xmlns=\"%s\">\r\n", XML_NS_ICALENDAR);
    buf_appendcstr(buf, "<vcalendar>\r\n  ");
    buf_appendmap(buf,
                  (char *) xmlBufferContent(xmlbuf), xmlBufferLength(xmlbuf));
    buf_appendcstr(buf, "\r\n<components>\r\n");
    xmlBufferFree(xmlbuf);

    return "";
}


void end_xcal(struct buf *buf)
{
    /* End xCal stream */
    buf_setcstr(buf, "\r\n</components>\r\n</vcalendars>\r\n</icalendar>");
}
