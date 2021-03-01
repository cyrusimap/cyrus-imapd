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
#include "http_carddav.h"
#include "http_caldav_sched.h"
#include "http_dav.h"
#include "http_jmap.h"
#include "http_proxy.h"
#include "ical_support.h"
#include "json_support.h"
#include "mailbox.h"
#include "mboxlist.h"
#include "mboxname.h"
#include "parseaddr.h"
#include "seen.h"
#include "statuscache.h"
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

/* A helper structure to organize iCalendar components */
struct icalcomps {
    hash_table by_uidrecurid; /* pointer to icalcomponent */
    hash_table by_uid; /* ptrarray_t of icalcomponent */
    struct buf buf;
};

#define ICALCOMPS_INITIALIZER { \
    HASH_TABLE_INITIALIZER, \
    HASH_TABLE_INITIALIZER, \
    BUF_INITIALIZER \
}

static const char *make_uidrecurid(icalcomponent *comp, struct buf *buf)
{
    const char *uid = icalcomponent_get_uid(comp);
    if (!uid) return NULL;

    icalproperty *recurid = icalcomponent_get_first_property(comp,
            ICAL_RECURRENCEID_PROPERTY);
    if (!recurid) return NULL;

    buf_setcstr(buf, uid);
    buf_putc(buf, ';');
    // append complete prop, including any TZID
    buf_appendcstr(buf, icalproperty_as_ical_string(recurid));
    return buf_cstring(buf);
}

static void icalcomps_init(struct icalcomps *comps, icalcomponent *ical)
{
    int ncomps = icalcomponent_count_components(ical, ICAL_VEVENT_COMPONENT);
    construct_hash_table(&comps->by_uidrecurid, ncomps + 1, 0);
    construct_hash_table(&comps->by_uid, ncomps + 1, 0);

    icalcomponent *comp;
    for (comp = icalcomponent_get_first_component(ical, ICAL_VEVENT_COMPONENT);
         comp;
         comp = icalcomponent_get_next_component(ical, ICAL_VEVENT_COMPONENT)) {

        const char *uid = icalcomponent_get_uid(comp);
        if (!uid) continue;
        icalproperty *recurid =icalcomponent_get_first_property(comp,
                ICAL_RECURRENCEID_PROPERTY);

        ptrarray_t *complist = hash_lookup(uid, &comps->by_uid);
        if (!complist) {
            complist = ptrarray_new();
            hash_insert(uid, complist, &comps->by_uid);
        }
        if (recurid) {
            ptrarray_append(complist, comp);
        }
        else {
            // main component goes first
            ptrarray_unshift(complist, comp);
        }

        const char *uidrecurid = make_uidrecurid(comp, &comps->buf);
        if (uidrecurid) {
            hash_insert(uidrecurid, comp, &comps->by_uidrecurid);
        }
    }

    buf_reset(&comps->buf);
}

static void icalcomps_fini(struct icalcomps *comps)
{
    if (comps->by_uid.size) {
        hash_iter *hit = hash_table_iter(&comps->by_uid);
        while (hash_iter_next(hit)) {
            ptrarray_t *complist = hash_iter_val(hit);
            ptrarray_free(complist);
        }
        hash_iter_free(&hit);
        free_hash_table(&comps->by_uid, NULL);
    }
    if (comps->by_uidrecurid.size) {
        free_hash_table(&comps->by_uidrecurid, NULL);
    }
    buf_free(&comps->buf);
}

static icalcomponent *icalcomps_by_uidrecurid(struct icalcomps *comps,
                                              icalcomponent *ofcomp)
{
    if (!comps || !comps->by_uidrecurid.size) {
        return NULL;
    }

    const char *uidrecurid = make_uidrecurid(ofcomp, &comps->buf);
    if (!uidrecurid) {
        return NULL;
    }

    return hash_lookup(uidrecurid, &comps->by_uidrecurid);
}

static ptrarray_t *icalcomps_by_uid(struct icalcomps *comps, const char *uid)
{
    if (!comps || !comps->by_uid.size) {
        return NULL;
    }
    return hash_lookup(uid, &comps->by_uid);
}

typedef struct jstimezones {
    hash_table bytzid;
    hash_table byjstzid;
    ptrarray_t tzs;
} jstimezones_t;

#define JSTIMEZONES_INITIALIZER { \
    HASH_TABLE_INITIALIZER, \
    HASH_TABLE_INITIALIZER, \
    PTRARRAY_INITIALIZER \
}

/* Forward declarations */
static json_t *calendarevent_from_ical(icalcomponent *comp, hash_table *props,
                                       int is_override, ptrarray_t *overrides,
                                       jstimezones_t *jtzcache,
                                       struct jmapical_jmapcontext *jmapctx);

static void calendarevent_to_ical(icalcomponent *comp,
                                  struct jmap_parser *parser, json_t *jsevent,
                                  struct icalcomps *oldcomps,
                                  jstimezones_t *jtzcache,
                                  struct jmapical_jmapcontext *jmapctx);

#define JMAPICAL_SHA1KEY_LEN (2*SHA1_DIGEST_LENGTH+1)

static const char *sha1key(const char *val, char *keybuf)
{
    if (!val) return NULL;

    unsigned char dest[SHA1_DIGEST_LENGTH];

    xsha1((const unsigned char *) val, strlen(val), dest);
    int r = bin_to_hex(dest, SHA1_DIGEST_LENGTH, keybuf, BH_LOWER);
    assert(r == 2*SHA1_DIGEST_LENGTH);
    keybuf[2*SHA1_DIGEST_LENGTH] = '\0';
    return keybuf;
}

static char *normalized_uri(const char *uri)
{
    if (!uri) return NULL;

    struct buf buf = BUF_INITIALIZER;
    const char *col = strchr(uri, ':');
    if (col) {
        /* Normalize URI scheme to lower case */
        buf_setmap(&buf, uri, col - uri);
        buf_lcase(&buf);
        buf_appendcstr(&buf, col);
    }
    else buf_setcstr(&buf, uri);

    buf_trim(&buf);
    if (!buf_len(&buf)) {
        buf_free(&buf);
        return NULL;
    }
    return buf_release(&buf);
}


static const char*
get_icalxparam_value(icalproperty *prop, const char *name)
{
    icalparameter *param;

    for (param = icalproperty_get_first_parameter(prop, ICAL_ANY_PARAMETER);
         param;
         param = icalproperty_get_next_parameter(prop, ICAL_ANY_PARAMETER)) {

        if (strcasecmpsafe(icalparameter_get_xname(param), name)) {
            continue;
        }
        return icalparameter_get_xvalue(param);
    }

    return NULL;
}

static void unescape_ical_text(struct buf *buf, const char *s)
{
    for (; *s; s++) {
        if (*s == '\\') {
            switch (*++s) {
                case 'n':
                case 'N':
                    buf_putc(buf, '\n');
                    break;
                case '\\':
                case ';':
                case ',':
                    buf_putc(buf, *s);
                    break;
                default:
                    buf_putc(buf, *(s-1));
                    buf_putc(buf, *s);
            }
        }
        else buf_putc(buf, *s);
    }
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

static const char *xjmapid_from_icalm(struct buf *dst, icalproperty *prop)
{
    buf_reset(dst);
    const char *id = get_icalxparam_value(prop, JMAPICAL_XPARAM_ID);
    if (!id) {
        char keybuf[JMAPICAL_SHA1KEY_LEN];
        id = sha1key(icalproperty_as_ical_string(prop), keybuf);
    }
    if (id) buf_setcstr(dst, id);
    return buf_cstring(dst);
}

static char *xjmapid_from_ical(icalproperty *prop)
{
    struct buf buf = BUF_INITIALIZER;
    xjmapid_from_icalm(&buf, prop);
    return buf_len(&buf) ? buf_release(&buf) : NULL;
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

static icalproperty* findprop_byid(icalcomponent *comp, const char *id,
                                   icalproperty_kind kind)
{
    icalproperty *prop = NULL;

    for (prop = icalcomponent_get_first_property(comp, kind);
         prop;
         prop = icalcomponent_get_next_property(comp, kind)) {

        const char *oldid = get_icalxparam_value(prop, JMAPICAL_XPARAM_ID);
        char keybuf[JMAPICAL_SHA1KEY_LEN];
        if (!oldid)
            oldid = sha1key(icalproperty_get_value_as_string(prop), keybuf);
        if (!strcmp(id, oldid)) break;
    }

    return prop;
}

static void jstimezones_add_icaltz(jstimezones_t *jstzones,
                                   const char *jstzid,
                                   icaltimezone *tz)
{
    if (!jstzones->tzs.count) {
        construct_hash_table(&jstzones->bytzid, 128, 0);
        construct_hash_table(&jstzones->byjstzid, 128, 0);

    }

    const char *tzid = icaltimezone_get_tzid(tz);
    if (!strcasecmp(tzid, "UTC")) {
        tzid = "Etc/UTC";
    }
    hash_insert(tzid, tz, &jstzones->bytzid);
    hash_insert(jstzid ? jstzid : tzid, tz, &jstzones->byjstzid);
    ptrarray_append(&jstzones->tzs, tz);
}

HIDDEN icaltimezone *jstimezones_lookup_tzid(jstimezones_t *jstzones, const char *tzid)
{
    if (!tzid) return NULL;

    /* UTC is special */
    if (!strcasecmp(tzid, "UTC")) {
        tzid = "Etc/UTC";
    }

    /* Lookup in custom timezones */
    if (jstzones && jstzones->tzs.count) {
        icaltimezone *tz = hash_lookup(tzid, &jstzones->bytzid);
        if (tz) return tz;
    }

    /* Lookup in standard timezones */
    return icaltimezone_get_cyrus_timezone_from_tzid(tzid);
}

static icaltimezone *jstimezones_lookup_jstzid(jstimezones_t *jstzones, const char *jstzid)
{
    if (!jstzid) return NULL;

    if (*jstzid == '/') {
        if (jstzones && jstzones->tzs.count) {
            return hash_lookup(jstzid, &jstzones->byjstzid);
        }
        else return NULL;
    }
    else {
        // matches tzid: lookup in standard timezones only
        return jstimezones_lookup_tzid(NULL, jstzid);
    }
}

static const char *jstimezones_get_jstzid(jstimezones_t *jstzones, const char *tzid)
{
    if (!tzid) return NULL;

    /* UTC is special */
    if (!strcasecmp(tzid, "Etc/UTC")) {
        return tzid;
    }

    if (jstzones && jstzones->tzs.count) {
        icaltimezone *tz = hash_lookup(tzid, &jstzones->bytzid);
        if (tz) {
            icalcomponent *tzcomp = icaltimezone_get_component(tz);
            if (tzcomp) {
                const char *jstzid = get_icalxprop_value(tzcomp, JMAPICAL_XPROP_ID);
                if (jstzid) return jstzid;
            }
        }
    }

    const char *jstzid = NULL;
    icaltimezone *tz = icaltimezone_get_cyrus_timezone_from_tzid(tzid);
    if (tz) {
        jstzid = icaltimezone_get_location(tz);
        if (!jstzid) icaltimezone_get_tzid(tz);
    }
    return jstzid;
}

static void jstimezones_add_vtimezones(jstimezones_t *jstzones, icalcomponent *ical)
{
    icalcomponent *tzcomp;
    icalproperty *prop;

    size_t count = 0;
    for (tzcomp = icalcomponent_get_first_component(ical, ICAL_VTIMEZONE_COMPONENT);
         tzcomp;
         tzcomp = icalcomponent_get_next_component(ical, ICAL_VTIMEZONE_COMPONENT)) {
        count++;
    }

    struct buf idbuf = BUF_INITIALIZER;

    for (tzcomp = icalcomponent_get_first_component(ical, ICAL_VTIMEZONE_COMPONENT);
         tzcomp;
         tzcomp = icalcomponent_get_next_component(ical, ICAL_VTIMEZONE_COMPONENT)) {

        prop = icalcomponent_get_first_property(tzcomp, ICAL_TZID_PROPERTY);
        if (!prop) continue;

        /* Ignore IANA and Windows timezone ids */
        const char *tzid = icalproperty_get_tzid(prop);
        if (!tzid || !*tzid || icaltimezone_get_cyrus_timezone_from_tzid(tzid)) {
            continue;
        }


        icalcomponent *mytzcomp = icalcomponent_clone(tzcomp);
        prop = icalproperty_new_x(tzid);
        icalproperty_set_x_name(prop, "X-LIC-LOCATION");
        icalcomponent_add_property(mytzcomp, prop);

        const char *jstzid = get_icalxprop_value(mytzcomp, JMAPICAL_XPROP_ID);
        if (!jstzid || *jstzid != '/') {
            buf_reset(&idbuf);
            buf_putc(&idbuf, '/');
            buf_appendcstr(&idbuf, jstzid ? jstzid : tzid);
            jstzid = buf_cstring(&idbuf);
            prop = icalproperty_new_x(jstzid);
            icalproperty_set_x_name(prop, JMAPICAL_XPROP_ID);
            icalcomponent_add_property(mytzcomp, prop);
        }
        icaltimezone *tz = icaltimezone_new();
        icaltimezone_set_component(tz, mytzcomp);

        jstimezones_add_icaltz(jstzones, jstzid, tz);
    }

    buf_free(&idbuf);
}

static void jstimezones_fini(jstimezones_t *jstzones)
{
    if (jstzones->byjstzid.size) {
        free_hash_table(&jstzones->byjstzid, NULL);
    }
    if (jstzones->bytzid.size) {
        free_hash_table(&jstzones->bytzid, NULL);
    }

    icaltimezone *tz;
    while ((tz = ptrarray_pop(&jstzones->tzs))) {
        icaltimezone_free(tz, 1);
    }
    ptrarray_fini(&jstzones->tzs);
}

HIDDEN jstimezones_t *jstimezones_new(icalcomponent *ical)
{
    jstimezones_t *jstzones = xzmalloc(sizeof(struct jstimezones));
    jstimezones_add_vtimezones(jstzones, ical);
    return jstzones;
}

HIDDEN void jstimezones_free(jstimezones_t **jstzonesptr)
{
    if (!jstzonesptr || !*jstzonesptr) return;
    jstimezones_fini(*jstzonesptr);
    free(*jstzonesptr);
    *jstzonesptr = NULL;
}

HIDDEN int jmapical_datetime_has_zero_time(const struct jmapical_datetime *dt)
{
    return dt->hour == 0 && dt->minute == 0 && dt->second == 0 && dt->nano == 0;
}

HIDDEN struct icaltimetype jmapical_datetime_to_icaldate(const struct jmapical_datetime *dt)
{
    struct icaltimetype icaldt = icaltime_null_time();
    icaldt.year = dt->year;
    icaldt.month = dt->month;
    icaldt.day = dt->day;
    icaldt.hour = dt->hour;
    icaldt.minute = dt->minute;
    icaldt.second = dt->second;
    icaldt.is_date = 1;
    return icaldt;
}

HIDDEN icaltimetype jmapical_datetime_to_icaltime(const struct jmapical_datetime *dt,
                                                  const icaltimezone* zone)
{
    struct icaltimetype icaldt = icaltime_null_time();
    icaldt.year = dt->year;
    icaldt.month = dt->month;
    icaldt.day = dt->day;
    icaldt.hour = dt->hour;
    icaldt.minute = dt->minute;
    icaldt.second = dt->second;
    icaldt.is_date = 0;
    icaldt.zone = zone;
    return icaldt;
}


HIDDEN void jmapical_datetime_from_icaltime(icaltimetype icaldt, struct jmapical_datetime *dt)
{
    memset(dt, 0, sizeof(struct jmapical_datetime));
    dt->year = icaldt.year;
    dt->month = icaldt.month;
    dt->day = icaldt.day;
    dt->hour = icaldt.hour;
    dt->minute = icaldt.minute;
    dt->second = icaldt.second;
}

HIDDEN int jmapical_datetime_compare(const struct jmapical_datetime *a,
                                     const struct jmapical_datetime *b)
{
    if (a->year != b->year)
        return a->year > b->year ? 1 : -1;
    if (a->month != b->month)
        return a->month > b->month ? 1 : -1;
    if (a->day != b->day)
        return a->day > b->day ? 1 : -1;
    if (a->hour != b->hour)
        return a->hour > b->hour ? 1 : -1;
    if (a->minute != b->minute)
        return a->minute > b->minute ? 1 : -1;
    if (a->second != b->second)
        return a->second > b->second ? 1 : -1;
    if (a->nano != b->nano)
        return a->nano > b->nano ? 1 : -1;
    return 0;
}

static void format_datetime(const struct jmapical_datetime *dt, struct buf *dst)
{
    buf_reset(dst);
    buf_printf(dst, "%04d-%02d-%02dT%02d:%02d:%02d",
            dt->year, dt->month, dt->day, dt->hour, dt->minute, dt->second);
    if (dt->nano) {
        buf_printf(dst, ".%.9llu", dt->nano);
        int n = buf_len(dst);
        const char *b = buf_base(dst);
        while (b[n-1] == '0') n--;
        buf_truncate(dst, n);
    }
    buf_cstring(dst);
}

HIDDEN void jmapical_localdatetime_as_string(const struct jmapical_datetime *dt, struct buf *dst)
{
    format_datetime(dt, dst);
    buf_cstring(dst);
}

HIDDEN void jmapical_utcdatetime_as_string(const struct jmapical_datetime *dt, struct buf *dst)
{
    format_datetime(dt, dst);
    buf_putc(dst, 'Z');
    buf_cstring(dst);
}

static const char *parse_fracsec(const char *val, bit64 *nanoptr)
{
    const char *end = NULL;
    bit64 nano = 0;
    if (parsenum(val, &end, 9, &nano) >= 0) {
        /* Normalize to nanoseconds */
        ssize_t i, n = end - val;
        for (i = 0; i < 9 - n; i++) {
            nano *= 10;
        }
        /* Skip remaining fractional seconds */
        while (isdigit(*end)) end++;
        /* No trailing zeros allowed */
        if (end[-1] == '0') {
            return NULL;
        }
        *nanoptr = nano;
        return end;
    }
    else return NULL;
}

static const char *parse_datetime(const char *val, struct jmapical_datetime *dt)
{
    struct tm tm;
    memset(&tm, 0, sizeof(struct tm));
    tm.tm_isdst = -1;

    const char *p = strptime(val, "%Y-%m-%dT%H:%M:%S", &tm);
    if (!p) return NULL;

    memset(dt, 0, sizeof(struct jmapical_datetime));
    dt->year = tm.tm_year + 1900;
    dt->month = tm.tm_mon + 1;
    dt->day = tm.tm_mday;
    dt->hour = tm.tm_hour;
    dt->minute = tm.tm_min;
    dt->second = tm.tm_sec;

    if (*p == '.') p = parse_fracsec(p+1, &dt->nano);

    return p;
}

HIDDEN int jmapical_localdatetime_from_string(const char *val, struct jmapical_datetime *dt)
{
    const char *p = parse_datetime(val, dt);
    return (!p || p[0] != '\0') ? -1 : 0;
}

HIDDEN int jmapical_utcdatetime_from_string(const char *val, struct jmapical_datetime *dt)
{
    const char *p = parse_datetime(val, dt);
    return (!p || p[0] != 'Z' || p[1] != '\0') ? -1 : 0;
}

HIDDEN int jmapical_datetime_from_icalprop(icalproperty *prop, struct jmapical_datetime *dt)
{
    icaltimetype icaldt = icalvalue_get_datetimedate(icalproperty_get_value(prop));
    if (!icaltime_is_valid_time(icaldt)) return -1;

    jmapical_datetime_from_icaltime(icaldt, dt);

    return 0;
}

HIDDEN int jmapical_duration_has_zero_time(const struct jmapical_duration *dur)
{
    return dur->hours == 0 && dur->minutes == 0 &&
           dur->seconds == 0 && dur->nanos == 0;
}

HIDDEN struct icaldurationtype jmapical_duration_to_icalduration(const struct jmapical_duration *dur)
{
    struct icaldurationtype icaldur = icaldurationtype_null_duration();

    icaldur.is_neg = dur->is_neg;
    icaldur.days = dur->days;
    icaldur.weeks = dur->weeks;
    icaldur.hours = dur->hours;
    icaldur.minutes = dur->minutes;
    icaldur.seconds = dur->seconds;

    return icaldur;
}

HIDDEN void jmapical_duration_from_icalduration(struct icaldurationtype icaldur,
                                                struct jmapical_duration *dur)
{
    memset(dur, 0, sizeof(struct jmapical_duration));
    dur->is_neg = icaldur.is_neg;
    dur->days = icaldur.days;
    dur->weeks = icaldur.weeks;
    dur->hours = icaldur.hours;
    dur->minutes = icaldur.minutes;
    dur->seconds = icaldur.seconds;
}

HIDDEN int jmapical_duration_from_icalprop(icalproperty *prop, struct jmapical_duration *dur)
{
    struct icaldurationtype icaldur = icalproperty_get_duration(prop);
    jmapical_duration_from_icalduration(icaldur, dur);
    return 0;
}

HIDDEN void jmapical_duration_between_unixtime(time_t t1, bit64 t1nanos,
                                               time_t t2, bit64 t2nanos,
                                               struct jmapical_duration *dur)
{
    const icaltimezone *utc = icaltimezone_get_utc_timezone();
    int is_neg = t1 > t2 || (t1 == t2 && t1nanos > t2nanos);
    bit64 nanos = 0;

    time_t tx = is_neg ? t2 : t1;
    bit64 txnanos = is_neg ? t2nanos : t1nanos;

    time_t ty = is_neg ? t1 : t2;
    bit64 tynanos = is_neg ? t1nanos : t2nanos;

    if (txnanos < tynanos) {
        nanos = tynanos - txnanos;
    }
    else if (txnanos > tynanos) {
        nanos = (1000000000 - txnanos) + tynanos;
        if (tx != ty) ty -= 1;
    }

    icaltimetype icaltx = icaltime_from_timet_with_zone(tx, 0, utc);
    icaltimetype icalty = icaltime_from_timet_with_zone(ty, 0, utc);
    struct icaldurationtype icaldur = icaltime_subtract(icalty, icaltx);
    icaldur.is_neg = is_neg;
    jmapical_duration_from_icalduration(icaldur, dur);
    dur->nanos = nanos;
}

HIDDEN void jmapical_duration_between_utctime(const struct jmapical_datetime *t1,
                                              const struct jmapical_datetime *t2,
                                              struct jmapical_duration *dur)
{
    const icaltimezone *utc = icaltimezone_get_utc_timezone();

    icaltimetype t1ical = jmapical_datetime_to_icaltime(t1, utc);
    icaltimetype t2ical = jmapical_datetime_to_icaltime(t2, utc);

    time_t t1unix = icaltime_as_timet_with_zone(t1ical, utc);
    time_t t2unix = icaltime_as_timet_with_zone(t2ical, utc);

    jmapical_duration_between_unixtime(t1unix, t1->nano, t2unix, t2->nano, dur);
}

HIDDEN int jmapical_duration_from_string(const char *val, struct jmapical_duration *dur)
{
    bit64 nanos = 0;
    char *myval = NULL;

    const char *fracsec = strchr(val, '.');
    if (fracsec) {
        // Parse fractional seconds.
        const char *p = parse_fracsec(fracsec + 1, &nanos);
        if (!p || p[0] != 'S' || p[1] != '\0') return -1;
        // Truncate to iCalendar duration.
        myval = xstrdup(val);
        myval[fracsec-val] = 'S';
        myval[fracsec-val+1] = '\0';
        val = myval;
    }

    // Parse iCalendar duration.
    struct icaldurationtype icaldur = icaldurationtype_from_string(val);
    free(myval);
    if (icaldurationtype_is_bad_duration(icaldur)) return -1;
    jmapical_duration_from_icalduration(icaldur, dur);
    dur->nanos = nanos;

    return 0;
}

HIDDEN void jmapical_duration_as_string(const struct jmapical_duration *dur, struct buf *buf)
{
    struct icaldurationtype icaldur = jmapical_duration_to_icalduration(dur);
    char *tmp = icaldurationtype_as_ical_string_r(icaldur);

    buf_setcstr(buf, tmp);
    if (dur->nanos) {
        const char *b = buf_base(buf);
        int n = buf_len(buf);
        /* Append fracsec part */
        if (b[n-1] == 'S') {
            buf_truncate(buf, n-1);
        }
        else {
            buf_putc(buf, '0');
        }
        buf_printf(buf, ".%.9llu", dur->nanos);
        /* Truncate trailing zeros */
        b = buf_base(buf);
        n = buf_len(buf);
        while (b[n-1] == '0') n--;
        buf_truncate(buf, n);
        buf_putc(buf, 'S');
    }

    free(tmp);
    buf_cstring(buf);
}

/* Determine the TZID, if any, of the ical property prop. */
static const char *tzid_from_icalprop(icalproperty *prop, int guess,
                                      jstimezones_t *jstzones)
{
    const char *tzid = NULL;
    icalparameter *param = NULL;

    if (prop) param = icalproperty_get_first_parameter(prop, ICAL_TZID_PARAMETER);
    if (param) tzid = icalparameter_get_tzid(param);
    /* Check if the tzid already corresponds to an existing timezone. */
    if (tzid) {
        icaltimezone *tz = jstimezones_lookup_tzid(jstzones, tzid);
        if (!tz && guess) {
            /* Try to guess the timezone. */
            icalvalue *val = icalproperty_get_value(prop);
            icaltimetype dt = icalvalue_get_datetime(val);
            tzid = dt.zone ? icaltimezone_get_location((icaltimezone*) dt.zone) : NULL;
            tzid = tzid && icaltimezone_get_cyrus_timezone_from_tzid(tzid) ? tzid : NULL;
        } else if (tz == icaltimezone_get_utc_timezone()) {
            /* XXX  libical may not set tzid or location */
            return tzid;
        } else if (tz) return icaltimezone_get_location(tz);
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
                                  icalproperty_kind kind,
                                  jstimezones_t *jstzones)
{
    icalproperty *prop = icalcomponent_get_first_property(comp, kind);
    if (!prop) {
        return NULL;
    }
    return tzid_from_icalprop(prop, 1, jstzones);
}

static struct icaltimetype dtstart_from_ical(icalcomponent *comp,
                                             jstimezones_t *jstzones)
{
    struct icaltimetype dt = icalcomponent_get_dtstart(comp);

    const char *tzid = tzid_from_ical(comp, ICAL_DTSTART_PROPERTY, jstzones);
    /* Seen in the wild: a floating DTSTART and a DTEND with TZID */
    if (!tzid) tzid = tzid_from_ical(comp, ICAL_DTEND_PROPERTY, jstzones);
    if (!tzid) return dt;

    icaltimezone *tz = jstimezones_lookup_tzid(jstzones, tzid);
    if (tz && tz != dt.zone) {
        icaltimezone *utc = icaltimezone_get_utc_timezone();
        if (dt.zone != utc) {
            // Prefer our IANA timezone definition
            dt.zone = tz;
        }
        else {
            // Bogus UTC datetime with TZID
            dt = icaltime_convert_to_zone(dt, tz);
        }
    }

    return dt;
}

static struct icaltimetype dtend_from_ical(icalcomponent *comp,
                                           jstimezones_t *jstzones)
{
    struct icaltimetype dtend = icaltime_null_time();
    icalproperty *end_prop = icalcomponent_get_first_property(comp, ICAL_DTEND_PROPERTY);
    icalproperty *dur_prop = icalcomponent_get_first_property(comp, ICAL_DURATION_PROPERTY);
    struct icaltimetype dtstart = dtstart_from_ical(comp, jstzones);

    if (end_prop) {
        dtend = icalproperty_get_dtend(end_prop);
        const char *tzid = tzid_from_icalprop(end_prop, 1, jstzones);
        icaltimezone* tz = icaltimezone_get_cyrus_timezone_from_tzid(tzid);
        if (tz && tz != dtend.zone) {
            icaltimezone *utc = icaltimezone_get_utc_timezone();
            if (dtend.zone != utc) {
                // Prefer our IANA timezone definition
                dtend.zone = tz;
            }
            else {
                // Bogus UTC datetime with TZID
                dtend = icaltime_convert_to_zone(dtend, tz);
            }
        }
    }
    else if (dur_prop) {
        struct icaldurationtype duration;
        if (icalproperty_get_value(dur_prop)) {
            duration = icalproperty_get_duration(dur_prop);
        } else {
            duration = icaldurationtype_null_duration();
        }
        dtend = icaltime_add(dtstart, duration);
    }
    else dtend = dtstart;

    /* Normalize floating DTEND to DTSTART time zone, if any */
    if (!dtend.zone) dtend.zone = dtstart.zone;

    return dtend;
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

static json_t* relatedto_from_ical(icalcomponent*);

/* Convert at most nmemb entries in the ical recurrence byDay/Month/etc array
 * named byX using conv. Return a new JSON array, sorted in ascending order. */
static json_t* recurrence_byX_fromical(short byX[], size_t nmemb, int (*conv)(int)) {
    json_t *jbd = json_array();

    size_t i;
    int tmp[nmemb];
    for (i = 0; i < nmemb && byX[i] != ICAL_RECURRENCE_ARRAY_MAX; i++) {
        tmp[i] = conv(byX[i]);
    }

    size_t n = i;
    qsort(tmp, n, sizeof(int), compare_int);
    for (i = 0; i < n; i++) {
        json_array_append_new(jbd, json_integer(tmp[i]));
    }

    return jbd;
}

/* Convert the ical recurrence prop to a JMAP recurrenceRule */
static json_t* recurrencerule_from_ical(icalproperty *prop, icaltimezone *untiltz)
{
    char *s = NULL;
    struct buf buf = BUF_INITIALIZER;
    size_t i;

    struct icalrecurrencetype rrule = icalproperty_get_rrule(prop);
    if (rrule.freq == ICAL_NO_RECURRENCE) {
        return json_null();
    }

    json_t *recur = json_pack("{s:s}", "@type", "RecurrenceRule");

    /* frequency */
    s = lcase(xstrdup(icalrecur_freq_to_string(rrule.freq)));
    json_object_set_new(recur, "frequency", json_string(s));
    free(s);

    json_object_set_new(recur, "interval", json_integer(rrule.interval));

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
    json_t *jbd = json_array();
    for (i = 0; i < ICAL_BY_DAY_SIZE; i++) {
        json_t *jday;
        icalrecurrencetype_weekday weekday;
        int pos;

        if (rrule.by_day[i] == ICAL_RECURRENCE_ARRAY_MAX) {
            break;
        }

        jday = json_object();
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
            json_object_set_new(jday, "@type", json_string("NDay"));
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
    json_t *jbm = json_array();
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
        icaltimetype dtuntil;
        if (rrule.until.is_date) {
            dtuntil = rrule.until;
            dtuntil.hour = 23;
            dtuntil.minute = 59;
            dtuntil.second = 59;
            dtuntil.is_date = 0;
        }
        else {
            dtuntil = icaltime_convert_to_zone(rrule.until, untiltz);
        }
        struct jmapical_datetime until = JMAPICAL_DATETIME_INITIALIZER;
        jmapical_datetime_from_icaltime(dtuntil, &until);
        struct buf buf = BUF_INITIALIZER;
        jmapical_localdatetime_as_string(&until, &buf);
        json_object_set_new(recur, "until", json_string(buf_cstring(&buf)));
        buf_free(&buf);
    }

    if (!json_object_size(recur)) {
        json_decref(recur);
        recur = json_null();
    }

    buf_free(&buf);
    return recur;
}

/* Convert the ical recurrence recur to a JMAP recurrenceRule */
static json_t* recurrencerules_from_ical(icalcomponent *comp,
                                         icalproperty_kind kind,
                                         jstimezones_t *jstzones)
{

    json_t *jrrules = json_array();

    /* Determine timezone to convert UNTIL to */
    const char *tzid = NULL;
    icalproperty *dtstart_prop =
        icalcomponent_get_first_property(comp, ICAL_DTSTART_PROPERTY);
    if (dtstart_prop) {
        icalparameter *tzid_param =
            icalproperty_get_first_parameter(dtstart_prop, ICAL_TZID_PARAMETER);
        if (tzid_param) tzid = icalparameter_get_tzid(tzid_param);
    }
    icaltimezone *untiltz = jstimezones_lookup_tzid(jstzones, tzid);

    icalproperty *prop;
    for (prop = icalcomponent_get_first_property(comp, kind);
         prop;
         prop = icalcomponent_get_next_property(comp, kind)) {

        json_t *jrrule = recurrencerule_from_ical(prop, untiltz);
        if (JNOTNULL(jrrule)) json_array_append_new(jrrules, jrrule);
    }

    if (!json_array_size(jrrules)) {
        json_decref(jrrules);
        jrrules = NULL;
    }

    return jrrules;
}

static json_t*
override_rdate_from_ical(icalproperty *prop)
{
    /* returns a JSON object with a single key value pair */
    json_t *override = json_object();
    json_t *o = json_object();
    struct icaldatetimeperiodtype rdate = icalproperty_get_rdate(prop);
    struct buf buf = BUF_INITIALIZER;
    struct jmapical_datetime rdatedt = JMAPICAL_DATETIME_INITIALIZER;

    if (!icaltime_is_null_time(rdate.time)) {
        jmapical_datetime_from_icaltime(rdate.time, &rdatedt);
    } else {
        /* PERIOD */
        jmapical_datetime_from_icaltime(rdate.period.start, &rdatedt);

        /* Determine duration */
        struct icaldurationtype icaldur;
        if (!icaltime_is_null_time(rdate.period.end)) {
            icaldur = icaltime_subtract(rdate.period.end, rdate.period.start);
        } else {
            icaldur = rdate.period.duration;
        }
        struct jmapical_duration dur = JMAPICAL_DURATION_INITIALIZER;
        jmapical_duration_from_icalduration(icaldur, &dur);
        jmapical_duration_as_string(&dur, &buf);
        json_object_set_new(o, "duration", json_string(buf_cstring(&buf)));
        buf_reset(&buf);
    }

    if (!icaltime_is_null_time(rdate.time) ||
        !icaltime_is_null_time(rdate.period.start)) {
        jmapical_localdatetime_as_string(&rdatedt, &buf);
        json_object_set_new(override, buf_cstring(&buf), o);
        buf_reset(&buf);
    }

    if (!json_object_size(override)) {
        json_decref(override);
        json_decref(o);
        override = NULL;
    }

    buf_free(&buf);
    return override;
}

static json_t*
override_exdate_from_ical(icalproperty *prop, const char *tzid_start,
                          jstimezones_t *jstzones)
{
    json_t *override = json_object();
    icaltimetype exdate = icalproperty_get_exdate(prop);

    const char *tzid_xdate = tzid_from_icalprop(prop, 1, jstzones);
    if (tzid_start && tzid_xdate && strcmp(tzid_start, tzid_xdate)) {
        icaltimezone *tz_xdate = jstimezones_lookup_tzid(jstzones, tzid_xdate);
        icaltimezone *tz_start = jstimezones_lookup_tzid(jstzones, tzid_start);
        if (tz_xdate && tz_start) {
            if (exdate.zone) exdate.zone = tz_xdate;
            exdate = icaltime_convert_to_zone(exdate, tz_start);
        }
    }

    if (!icaltime_is_null_time(exdate)) {
        struct jmapical_datetime exdatedt = JMAPICAL_DATETIME_INITIALIZER;
        jmapical_datetime_from_icaltime(exdate, &exdatedt);
        struct buf buf = BUF_INITIALIZER;
        jmapical_localdatetime_as_string(&exdatedt, &buf);
        json_object_set_new(override, buf_cstring(&buf), json_pack("{s:b}", "excluded", 1));
        buf_free(&buf);
    }

    if (!json_object_size(override)) {
        json_decref(override);
        override = NULL;
    }

    return override;
}

static json_t*
overrides_from_ical(icalcomponent *comp, ptrarray_t *icaloverrides,
                    json_t *event, const char *tzid_start,
                    jstimezones_t *jstzones,
                    struct jmapical_jmapcontext *jmapctx)
{
    icalproperty *prop;
    json_t *overrides = json_object();

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

        json_t *override = override_exdate_from_ical(prop, tzid_start, jstzones);
        if (override) {
            json_object_update(overrides, override);
            json_decref(override);
        }
    }

    /* VEVENT exceptions */
    json_t *exceptions = json_object();

    int i;
    for (i = 0; i < ptrarray_size(icaloverrides); i++) {
        icalcomponent *excomp = ptrarray_nth(icaloverrides, i);

        /* Convert VEVENT exception to JMAP */
        json_t *ex = calendarevent_from_ical(excomp, NULL, 1, NULL, jstzones, jmapctx);
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
                        icaltimezone *start_tz = jstimezones_lookup_tzid(jstzones, start_tzid);
                        if (start_tz) {
                            icalrecurid = icaltime_convert_to_zone(icalrecurid, start_tz);
                        }
                    }
                }
            }
        }

        /* Format recurrence id */
        struct jmapical_datetime exrecurdt = JMAPICAL_DATETIME_INITIALIZER;
        jmapical_datetime_from_icaltime(icalrecurid, &exrecurdt);
        struct buf buf = BUF_INITIALIZER;
        jmapical_localdatetime_as_string(&exrecurdt, &buf);
        char *recurid = buf_release(&buf);

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
        json_object_del(diff, "recurrenceId");
        json_object_del(diff, "recurrenceRules");
        json_object_del(diff, "recurrenceOverrides");
        json_object_del(diff, "excludedRecurrenceRules");
        json_object_del(diff, "replyTo");
        if (json_is_null(json_object_get(diff, "start"))) {
            json_object_del(diff, "start");
        }
        if (json_is_null(json_object_get(diff, "showWithoutTime"))) {
            json_object_del(diff, "showWithoutTime");
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
    const char *val = icalproperty_get_value_as_string(prop);
    if (!val) goto done;
    buf_setcstr(&buf, val);
    buf_trim(&buf);
    if (!buf_len(&buf)) goto done;

    const char *caladdress = buf_cstring(&buf);
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

done:
    if (!json_object_size(rsvpTo)) {
        json_decref(rsvpTo);
        rsvpTo = json_null();
    }

    buf_free(&buf);
    return rsvpTo;
}

static json_t*
link_from_ical(icalproperty *prop, struct jmapical_jmapcontext *jmapctx)
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

    json_t *link = json_pack("{s:s: s:s}", "@type", "Link", "href", href);
    icalparameter *param = NULL;
    const char *s;

    /* blobId */
    if (jmapctx && jmapctx->blobid_from_href) {
        param = icalproperty_get_managedid_parameter(prop);
        const char *mid = param ? icalparameter_get_managedid(param) : NULL;
        struct buf blobid = BUF_INITIALIZER;
        jmapctx->blobid_from_href(&blobid, href, mid, jmapctx->rock);
        if (buf_len(&blobid)) {
            json_object_set_new(link, "blobId", json_string(buf_cstring(&blobid)));
        }
        buf_free(&blobid);
    }

    /* cid */
    if ((s = get_icalxparam_value(prop, JMAPICAL_XPARAM_CID))) {
        json_object_set_new(link, "cid", json_string(s));
    }

    /* contentType */
    param = icalproperty_get_first_parameter(prop, ICAL_FMTTYPE_PARAMETER);
    if (param && ((s = icalparameter_get_fmttype(param)))) {
        json_object_set_new(link, "contentType", json_string(s));
    }

    /* title - reuse the same x-param as Apple does for their locations  */
    if ((s = get_icalxparam_value(prop, JMAPICAL_XPARAM_TITLE))) {
        struct buf buf = BUF_INITIALIZER;
        unescape_ical_text(&buf, s);
        json_object_set_new(link, "title", json_string(buf_cstring(&buf)));
        buf_free(&buf);
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
    if (!rel && icalproperty_isa(prop) == ICAL_URL_PROPERTY) {
        rel = "describedby";
    }
    json_object_set_new(link, "rel", json_string(rel));

    /* display */
    if ((s = get_icalxparam_value(prop, JMAPICAL_XPARAM_DISPLAY))) {
        json_object_set_new(link, "display", json_string(s));
    }


    return link;
}

static json_t* linksbyprop_from_ical(icalcomponent *comp,
                                     struct jmapical_jmapcontext *jmapctx)
{
    icalproperty* prop;
    json_t *ret = json_object();

    /* Read iCalendar ATTACH properties */
    for (prop = icalcomponent_get_first_property(comp, ICAL_ATTACH_PROPERTY);
         prop;
         prop = icalcomponent_get_next_property(comp, ICAL_ATTACH_PROPERTY)) {

        const char *propname = get_icalxparam_value(prop, JMAPICAL_XPARAM_PARENTPROP);
        if (!propname) propname = "links";
        json_t *jlinks = json_object_get(ret, propname);
        if (!jlinks) {
            jlinks = json_object();
            json_object_set_new(ret, propname, jlinks);
        }

        const char *parentid = get_icalxparam_value(prop, JMAPICAL_XPARAM_PARENTID);
        if (parentid) {
            json_t *jproplinks = json_object_get(jlinks, parentid);
            if (!jproplinks) {
                jproplinks = json_object();
                json_object_set_new(jlinks, parentid, jproplinks);
            }
            jlinks = jproplinks;
        }

        const char *id = get_icalxparam_value(prop, JMAPICAL_XPARAM_ID);
        char keybuf[JMAPICAL_SHA1KEY_LEN];
        if (!id) id = sha1key(icalproperty_get_value_as_string(prop), keybuf);
        json_t *link = link_from_ical(prop, jmapctx);
        if (link) json_object_set_new(jlinks, id, link);
    }

    /* Read iCalendar URL property. Should only be one. */
    for (prop = icalcomponent_get_first_property(comp, ICAL_URL_PROPERTY);
         prop;
         prop = icalcomponent_get_next_property(comp, ICAL_URL_PROPERTY)) {

        const char *propname = get_icalxparam_value(prop, JMAPICAL_XPARAM_PARENTPROP);
        if (!propname) propname = "links";
        json_t *jlinks = json_object_get(ret, propname);
        if (!jlinks) {
            jlinks = json_object();
            json_object_set_new(ret, propname, jlinks);
        }

        const char *parentid = get_icalxparam_value(prop, JMAPICAL_XPARAM_PARENTID);
        if (parentid) {
            json_t *jproplinks = json_object_get(jlinks, parentid);
            if (!jproplinks) {
                jproplinks = json_object();
                json_object_set_new(jlinks, parentid, jproplinks);
            }
            jlinks = jproplinks;
        }

        const char *id = get_icalxparam_value(prop, JMAPICAL_XPARAM_ID);
        char keybuf[JMAPICAL_SHA1KEY_LEN];
        if (!id) id = sha1key(icalproperty_get_value_as_string(prop), keybuf);
        json_t *link = link_from_ical(prop, jmapctx);
        if (link) json_object_set_new(jlinks, id, link);
    }

    if (!json_object_size(ret)) {
        json_decref(ret);
        ret = json_null();
    }

    return ret;
}

static json_t *participant_from_ical(icalproperty *prop,
                                     hash_table *id_by_uri,
                                     icalproperty *orga,
                                     json_t *links)
{
    json_t *p = json_pack("{s:s}", "@type", "Participant");
    icalparameter *param;
    struct buf buf = BUF_INITIALIZER;

    /* sendTo */
    json_t *sendTo = rsvpto_from_ical(prop);
    json_object_set_new(p, "sendTo", sendTo ? sendTo : json_null());

    /* email */
    param = icalproperty_get_first_parameter(prop, ICAL_EMAIL_PARAMETER);
    if (param) {
        const char *email = icalparameter_get_value_as_string(param);
        if (email && *email) {
            json_object_set_new(p, "email", json_string(email));
        }
    }

    /* name */
    const char *name = NULL;
    param = icalproperty_get_first_parameter(prop, ICAL_CN_PARAMETER);
    if (param) {
        name = icalparameter_get_cn(param);
        if (name && *name) json_object_set_new(p, "name", json_string(name));
    }

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

    /* roles */
    json_t *roles = json_object();
    icalparameter_role ical_role = ICAL_ROLE_REQPARTICIPANT;
    param = icalproperty_get_first_parameter(prop, ICAL_ROLE_PARAMETER);
    if (param) {
        ical_role = icalparameter_get_role(param);
        switch (ical_role) {
            case ICAL_ROLE_OPTPARTICIPANT:
                json_object_set_new(roles, "optional", json_true());
                break;
            case ICAL_ROLE_NONPARTICIPANT:
                json_object_set_new(roles, "informational", json_true());
                break;
            case ICAL_ROLE_CHAIR:
                json_object_set_new(roles, "chair", json_true());
                json_object_set_new(roles, "attendee", json_true());
                break;
            default:
                json_object_set_new(roles, "attendee", json_true());
                break;  // nothing to add
        }
    }
    for (param = icalproperty_get_first_parameter(prop, ICAL_X_PARAMETER);
         param;
         param = icalproperty_get_next_parameter(prop, ICAL_X_PARAMETER)) {

        if (strcmp(icalparameter_get_xname(param), JMAPICAL_XPARAM_ROLE))
            continue;

        buf_setcstr(&buf, icalparameter_get_xvalue(param));
        json_object_set_new(roles, buf_lcase(&buf), json_true());
        buf_reset(&buf);
    }
    if (!json_object_get(roles, "owner")) {
        const char *o = icalproperty_get_organizer(orga);
        const char *a = icalproperty_get_attendee(prop);
        if (!strcasecmpsafe(o, a)) {
            json_object_set_new(roles, "owner", json_true());
            json_object_set_new(roles, "attendee", json_true());
        }
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
                partstat = "delegated";
                break;
            default:
                partstat = "none";
        }
    }
    if (!partstat || !strcmp(partstat,  "none"))
        partstat = "needs-action";
    json_object_set_new(p, "participationStatus", json_string(partstat));

    /* description */
    const char *desc = get_icalxparam_value(prop, JMAPICAL_XPARAM_DESCRIPTION);
    if (desc) {
        unescape_ical_text(&buf, desc);
        json_object_set_new(p, "description", json_string(buf_cstring(&buf)));
        buf_reset(&buf);
    }

    /* expectReply */
    int expect_reply = 0;
    param = icalproperty_get_first_parameter(prop, ICAL_RSVP_PARAMETER);
    if (param) {
        icalparameter_rsvp val = icalparameter_get_rsvp(param);
        expect_reply = val == ICAL_RSVP_TRUE;
    }
    json_object_set_new(p, "expectReply", json_boolean(expect_reply));

    /* language */
    param = icalproperty_get_first_parameter(prop, ICAL_LANGUAGE_PARAMETER);
    if (param) {
        const char *l = icalparameter_get_language(param);
        json_object_set_new(p, "language", json_string(l));
    }

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
        const char *id = hash_lookup(uri, id_by_uri);
        char keybuf[JMAPICAL_SHA1KEY_LEN];
        if (!id) id = sha1key(uri, keybuf);
        json_object_set_new(memberOf, id, json_true());
        free(uri);
    }
    if (json_object_size(memberOf)) {
        json_object_set_new(p, "memberOf", memberOf);
    } else {
        json_decref(memberOf);
    }

    /* links */
    param = icalproperty_get_first_parameter(prop, ICAL_DIR_PARAMETER);
    if (param) {
        const char *dir = icalparameter_get_dir(param);
        if (dir) {
            const char *linkid = get_icalxparam_value(prop, JMAPICAL_XPARAM_LINKID);
            char keybuf[JMAPICAL_SHA1KEY_LEN];
            if (!linkid) {
                /* Generate a link id from the dir value. Note that the
                 * id will stick to this link, even if its href changes. */
                linkid = sha1key(dir, keybuf);
            }
            if (!links) {
                links = json_object();
            }
            json_object_set_new(links, linkid, json_pack("{s:s}", "href", dir));
        }
    }
    if (links) json_object_set_new(p, "links", links);

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
        icaltimetype icaltstamp = icaltime_from_string(xval);
        if (!icaltime_is_null_time(icaltstamp) && !icaltstamp.is_date &&
                icaltstamp.zone == icaltimezone_get_utc_timezone()) {
            struct jmapical_datetime tstamp = JMAPICAL_DATETIME_INITIALIZER;
            jmapical_datetime_from_icaltime(icaltstamp, &tstamp);
            jmapical_utcdatetime_as_string(&tstamp, &buf);
            json_object_set_new(p, "scheduleUpdated", json_string(buf_cstring(&buf)));
            buf_reset(&buf);
        }
    }

    /* scheduleStatus */
    param = icalproperty_get_first_parameter(prop, ICAL_SCHEDULESTATUS_PARAMETER);
    if (param) {
        json_t *jschedstat = json_array();
        const char *str = icalparameter_get_schedulestatus(param);
        strarray_t *vals = strarray_split(str, ",", STRARRAY_TRIM);
        if (strarray_size(vals)) {
            int i;
            for (i = 0; i < strarray_size(vals); i++) {
                json_array_append_new(jschedstat,
                        json_string(strarray_nth(vals, i)));
            }
        }
        strarray_free(vals);
        if (!json_array_size(jschedstat)) {
            json_decref(jschedstat);
            jschedstat = json_null();
        }
        json_object_set_new(p, "scheduleStatus", jschedstat);
    }

    /* participationComment */
    const char *comment = get_icalxparam_value(prop, JMAPICAL_XPARAM_COMMENT);
    if (comment) {
        unescape_ical_text(&buf, comment);
        json_object_set_new(p, "participationComment", json_string(buf_cstring(&buf)));
        buf_reset(&buf);
    }

    buf_free(&buf);
    return p;
}

static json_t*
participant_from_icalorganizer(icalproperty *orga)
{
    const char *caladdress = icalproperty_get_value_as_string(orga);
    if (!caladdress || !*caladdress) {
        return json_null();
    }

    json_t *jorga = json_pack("{s:s}", "@type", "Participant");
    icalparameter *param;

    /* name */
    if ((param = icalproperty_get_first_parameter(orga, ICAL_CN_PARAMETER))) {
        const char *name = icalparameter_get_cn(param);
        if (name && *name) {
            json_object_set_new(jorga, "name", json_string(name));
        }
    }

    /* roles */
    json_object_set_new(jorga, "roles", json_pack("{s:b}", "owner", 1));

    /* sendTo */
    if (!strncasecmp(caladdress, "mailto:", 7)) {
        json_object_set_new(jorga, "sendTo", json_pack("{s:s}", "imip", caladdress));
    }
    else {
        json_object_set_new(jorga, "sendTo", json_pack("{s:s}", "other", caladdress));
    }

    /* email */
    param = icalproperty_get_first_parameter(orga, ICAL_EMAIL_PARAMETER);
    if (param) {
        const char *email = icalparameter_get_value_as_string(param);
        if (email && *email) {
            json_object_set_new(jorga, "email", json_string(email));
        }
    }

    /* Set default values */
    json_object_set_new(jorga, "participationStatus", json_string("needs-action"));
    json_object_set_new(jorga, "scheduleSequence", json_integer(0));
    json_object_set_new(jorga, "expectReply", json_false());

    return jorga;
}

/* Convert the ical ORGANIZER/ATTENDEEs in comp to CalendarEvent participants */
static json_t*
participants_from_ical(icalcomponent *comp, json_t *linksbyparticipant)
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
        if (!uri) continue;
        hash_insert(uri, prop, &attendee_by_uri);

        /* Map mailto:URI to ID */
        const char *id = get_icalxparam_value(prop, JMAPICAL_XPARAM_ID);
        char keybuf[JMAPICAL_SHA1KEY_LEN];
        if (!id) id = sha1key(uri, keybuf);
        hash_insert(uri, xstrdup(id), &id_by_uri);
        free(uri);
    }

    /* Map ATTENDEE to JSCalendar */
    icalproperty *orga = icalcomponent_get_first_property(comp, ICAL_ORGANIZER_PROPERTY);
    for (prop = icalcomponent_get_first_property(comp, ICAL_ATTENDEE_PROPERTY);
         prop;
         prop = icalcomponent_get_next_property(comp, ICAL_ATTENDEE_PROPERTY)) {

        char *uri = normalized_uri(icalproperty_get_value_as_string(prop));
        if (!uri) continue;
        const char *id = hash_lookup(uri, &id_by_uri);
        json_t *p = participant_from_ical(prop, &id_by_uri, orga,
                json_incref(json_object_get(linksbyparticipant, id)));
        json_object_set_new(participants, id, p);
        free(uri);
    }

    if (orga) {
        const char *caladdress = icalproperty_get_value_as_string(orga);
        char *uri = normalized_uri(caladdress);
        if (uri) {
            if (!hash_lookup(uri, &attendee_by_uri)) {
                /* Add a default participant for the organizer. */
                const char *id = get_icalxparam_value(orga, JMAPICAL_XPARAM_ID);
                char keybuf[JMAPICAL_SHA1KEY_LEN];
                if (!id) id = sha1key(uri, keybuf);
                json_t *jorga = participant_from_icalorganizer(orga);
                json_object_set_new(participants, id, jorga);
            }
            free(uri);
        }
    }

    if (!json_object_size(participants)) {
        json_decref(participants);
        participants = json_null();
    }
    free_hash_table(&attendee_by_uri, NULL);
    free_hash_table(&id_by_uri, free);
    return participants;
}

HIDDEN json_t *jmapical_alert_from_ical(icalcomponent *valarm)
{
    /* Determine TRIGGER and RELATED parameter */
    struct icaltriggertype trigger = {
        icaltime_null_time(), icaldurationtype_null_duration()
    };
    icalparameter_related related = ICAL_RELATED_START;
    icalproperty *triggerprop = icalcomponent_get_first_property(valarm, ICAL_TRIGGER_PROPERTY);
    if (triggerprop) {
        trigger = icalproperty_get_trigger(triggerprop);
        icalparameter *param = icalproperty_get_first_parameter(triggerprop, ICAL_RELATED_PARAMETER);
        if (param) {
            related = icalparameter_get_related(param);
            if (related != ICAL_RELATED_START && related != ICAL_RELATED_END) {
                return NULL;
            }
        }
    }

    json_t *alert = json_pack("{s:s}", "@type", "Alert");
    struct buf buf = BUF_INITIALIZER;
    icalproperty *prop;

    /* trigger */
    json_t *jtrigger = json_object();
    if (!icaldurationtype_is_null_duration(trigger.duration) ||
            icaltime_is_null_time(trigger.time)) {

        /* Convert to offset trigger */
        json_object_set_new(jtrigger, "@type", json_string("OffsetTrigger"));
        struct jmapical_duration duration = JMAPICAL_DURATION_INITIALIZER;
        jmapical_duration_from_icalduration(trigger.duration, &duration);

        /* relativeTo */
        const char *relative_to = related == ICAL_RELATED_START ?  "start" : "end";
        json_object_set_new(jtrigger, "relativeTo", json_string(relative_to));

        /* offset*/
        jmapical_duration_as_string(&duration, &buf);
        json_object_set_new(jtrigger, "offset", json_string(buf_cstring(&buf)));
        buf_reset(&buf);
    } else {
        /* Convert to absolute trigger */
        json_object_set_new(jtrigger, "@type", json_string("AbsoluteTrigger"));

        struct jmapical_datetime when = JMAPICAL_DATETIME_INITIALIZER;
        jmapical_datetime_from_icalprop(triggerprop, &when);
        jmapical_utcdatetime_as_string(&when, &buf);

        /* when */
        json_object_set_new(jtrigger, "when", json_string(buf_cstring(&buf)));
    }

    json_object_set_new(alert, "trigger", jtrigger);

    /*  action */
    const char *action = "display";
    prop = icalcomponent_get_first_property(valarm, ICAL_ACTION_PROPERTY);
    if (prop && icalproperty_get_action(prop) == ICAL_ACTION_EMAIL) {
        action = "email";
    }
    json_object_set_new(alert, "action", json_string(action));

    /* acknowledged */
    if ((prop = icalcomponent_get_acknowledged_property(valarm))) {
        struct jmapical_datetime tstamp = JMAPICAL_DATETIME_INITIALIZER;
        jmapical_datetime_from_icalprop(prop, &tstamp);
        jmapical_utcdatetime_as_string(&tstamp, &buf);
        json_t *jval = json_string(buf_cstring(&buf));
        buf_reset(&buf);
        json_object_set_new(alert, "acknowledged", jval);
    }

    /* relatedTo */
    json_t *jrelatedto = relatedto_from_ical(valarm);
    if (JNOTNULL(jrelatedto)) {
        json_object_set_new(alert, "relatedTo", jrelatedto);
    }

    buf_free(&buf);
    return alert;
}

/* Convert the VALARMS in the VEVENT comp to CalendarEvent alerts.
 * Adds any ATTACH properties found in VALARM components to the
 * event 'links' property. */
static json_t*
alerts_from_ical(icalcomponent *comp)
{
    json_t* alerts = json_object();
    icalcomponent* alarm;

    for (alarm = icalcomponent_get_first_component(comp, ICAL_VALARM_COMPONENT);
         alarm;
         alarm = icalcomponent_get_next_component(comp, ICAL_VALARM_COMPONENT)) {

        /* alert id */
        const char *id = icalcomponent_get_uid(alarm);
        char keybuf[JMAPICAL_SHA1KEY_LEN];
        if (!id) id = sha1key(icalcomponent_as_ical_string(alarm), keybuf);

        json_t *alert = jmapical_alert_from_ical(alarm);
        if (alert) json_object_set_new(alerts, id, alert);
    }

    if (!json_object_size(alerts)) {
        json_decref(alerts);
        alerts = json_null();
    }

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
    json_t *ret = json_object();
    struct buf buf = BUF_INITIALIZER;

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

            switch (icalparameter_get_reltype(param)) {
                case ICAL_RELTYPE_PARENT:
                    buf_setcstr(&buf, "parent");
                    break;
                case ICAL_RELTYPE_CHILD:
                    buf_setcstr(&buf, "child");
                    break;
                case ICAL_RELTYPE_SIBLING:
                    buf_setcstr(&buf, "sibling");
                    break;
                default:
                    {
                        const char *reltypestr = icalparameter_get_xvalue(param);
                        if (reltypestr) {
                            buf_setcstr(&buf, reltypestr);
                            buf_lcase(&buf);
                            buf_trim(&buf);
                        }
                    }
            }
            if (buf_len(&buf)) {
                json_object_set_new(relation, buf_cstring(&buf), json_true());
            }

            buf_reset(&buf);
        }

        json_object_set_new(ret, uid, json_pack("{s:s s:o}",
                    "@type", "Relation", "relation", relation));

    }

    if (!json_object_size(ret)) {
        json_decref(ret);
        ret = json_null();
    }

    return ret;
}

static json_t* location_from_ical(icalproperty *prop, json_t *links,
                                  jstimezones_t *jstzones)
{
    icalparameter *param;
    json_t *loc = json_pack("{s:s}", "@type", "Location");

    /* name */
    const char *name = icalvalue_get_text(icalproperty_get_value(prop));
    if (name) json_object_set_new(loc, "name", json_string(name));

    /* rel */
    const char *rel = get_icalxparam_value(prop, JMAPICAL_XPARAM_REL);
    if (rel) json_object_set_new(loc, "relativeTo", json_string(rel));

    /* description */
    const char *desc = get_icalxparam_value(prop, JMAPICAL_XPARAM_DESCRIPTION);
    if (desc && *desc) {
        struct buf buf = BUF_INITIALIZER;
        unescape_ical_text(&buf, desc);
        json_object_set_new(loc, "description", json_string(buf_cstring(&buf)));
        buf_free(&buf);
    }

    /* timeZone */
    const char *timezone = get_icalxparam_value(prop, JMAPICAL_XPARAM_TZID);
    if (jstimezones_lookup_jstzid(jstzones, timezone)) {
        json_object_set_new(loc, "timeZone", json_string(timezone));
    }

    /* coordinates */
    const char *coord = get_icalxparam_value(prop, JMAPICAL_XPARAM_GEO);
    if (coord) json_object_set_new(loc, "coordinates", json_string(coord));

    /* locationTypes */
    json_t *loctypes = NULL;
    for (param = icalproperty_get_first_parameter(prop, ICAL_ANY_PARAMETER);
         param;
         param = icalproperty_get_next_parameter(prop, ICAL_ANY_PARAMETER)) {

        if (!strcasecmpsafe(icalparameter_get_xname(param),
                            JMAPICAL_XPARAM_LOCATIONTYPE)) {
            const char *loctype = icalparameter_get_xvalue(param);
            if (loctype) {
                if (!loctypes) loctypes = json_object();
                json_object_set_new(loctypes, loctype, json_true());
            }
        }
    }
    if (loctypes) json_object_set_new(loc, "locationTypes", loctypes);

    /* links (including altrep) */
    param = icalproperty_get_first_parameter(prop, ICAL_ALTREP_PARAMETER);
    if (param) {
        const char *altrep = icalparameter_get_altrep(param);
        if (altrep) {
            if (!json_is_object(links)) links = json_object();
            char keybuf[JMAPICAL_SHA1KEY_LEN];
            sha1key(altrep, keybuf);
            json_object_set_new(links, keybuf, json_pack("{s:s}", "href", altrep));
        }
    }
    if (links) json_object_set_new(loc, "links", links);

    return loc;
}

static json_t *coordinates_from_ical(icalproperty *prop)
{
    /* Use verbatim coordinate string, rather than the parsed ical value */
    const char *p, *val = icalproperty_get_value_as_string(prop);
    struct buf buf = BUF_INITIALIZER;
    json_t *c;

    if (!val) return NULL;

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
locations_from_ical(icalcomponent *comp, json_t *linksbyloc,
                    jstimezones_t *jstzones)
{
    icalproperty* prop;
    json_t *loc, *locations = json_object();
    struct buf buf = BUF_INITIALIZER;
    char *id;

    /* Handle end locations */
    const char *tzidstart = tzid_from_ical(comp, ICAL_DTSTART_PROPERTY, jstzones);
    const char *tzidend = tzid_from_ical(comp, ICAL_DTEND_PROPERTY, jstzones);
    if (tzidstart && tzidend && strcmp(tzidstart, tzidend)) {
        prop = icalcomponent_get_first_property(comp, ICAL_DTEND_PROPERTY);
        id = xjmapid_from_ical(prop);
        const char *jstzid = jstimezones_get_jstzid(jstzones, tzidend);
        if (jstzid) {
            loc = json_pack("{s:s s:s}", "timeZone", jstzid, "relativeTo", "end");
            json_object_set_new(locations, id, loc);
        }
        free(id);
    }

    /* LOCATION */
    if ((prop = icalcomponent_get_first_property(comp, ICAL_LOCATION_PROPERTY))) {
        id = xjmapid_from_ical(prop);
        json_t *links = json_incref(json_object_get(linksbyloc, id));
        if ((loc = location_from_ical(prop, links, jstzones))) {
            json_object_set_new(locations, id, loc);
        }
        else json_decref(links);
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
        if (!strcmp(name, "X-APPLE-STRUCTURED-LOCATION")) {
            const char *title, *uri;
            icalvalue *val;

            val = icalproperty_get_value(prop);
            if (icalvalue_isa(val) != ICAL_URI_VALUE) continue;

            uri = icalvalue_as_ical_string(val);
            if (strncmp(uri, "geo:", 4)) continue;

            loc = json_pack("{s:s}", "coordinates", uri);
            if ((title = get_icalxparam_value(prop, JMAPICAL_XPARAM_TITLE))) {
                struct buf buf = BUF_INITIALIZER;
                unescape_ical_text(&buf, title);
                json_object_set_new(loc, "name", json_string(buf_cstring(&buf)));
                buf_free(&buf);
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

        json_t *links = json_incref(json_object_get(linksbyloc, id));
        if ((loc = location_from_ical(prop, links, jstzones))) {
            json_object_set_new(locations, id, loc);
        }
        else json_decref(links);
        free(id);
    }

    if (!json_object_size(locations)) {
        json_decref(locations);
        locations = json_null();
    }
    buf_free(&buf);

    return locations;
}

static json_t*
virtuallocations_from_ical(icalcomponent *comp)
{
    icalproperty* prop;
    json_t *locations = json_object();

    for (prop = icalcomponent_get_first_property(comp, ICAL_CONFERENCE_PROPERTY);
         prop;
         prop = icalcomponent_get_next_property(comp, ICAL_CONFERENCE_PROPERTY)) {

        char *id = xjmapid_from_ical(prop);
        json_t *loc = json_pack("{s:s}", "@type", "VirtualLocation");

        const char *uri = icalproperty_get_value_as_string(prop);
        if (uri) json_object_set_new(loc, "uri", json_string(uri));

        icalparameter *param = icalproperty_get_first_parameter(prop, ICAL_LABEL_PARAMETER);
        if (param) {
            const char *name = icalparameter_get_label(param);
            if (name && *name) json_object_set_new(loc, "name", json_string(name));
        }

        const char *desc = get_icalxparam_value(prop, JMAPICAL_XPARAM_DESCRIPTION);
        if (desc && *desc) {
            struct buf buf = BUF_INITIALIZER;
            unescape_ical_text(&buf, desc);
            json_object_set_new(loc, "description", json_string(buf_cstring(&buf)));
            buf_free(&buf);
        }

        if (uri) json_object_set_new(locations, id, loc);
        free(id);
    }

    if (!json_object_size(locations)) {
        json_decref(locations);
        locations = json_null();
    }

    return locations;
}

static void duration_from_vevent(icalcomponent *comp, struct jmapical_duration *dur,
                                 jstimezones_t *jstzones)
{
    struct icaltimetype dtstart = dtstart_from_ical(comp, jstzones);
    struct icaltimetype dtend = dtend_from_ical(comp, jstzones);
    if (!icaltime_is_null_time(dtend)) {
        time_t tstart = icaltime_as_timet_with_zone(dtstart, dtstart.zone);
        time_t tend = icaltime_as_timet_with_zone(dtend, dtend.zone);
        jmapical_duration_between_unixtime(tstart, 0, tend, 0, dur);
    }
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

static void format_tzoffset(struct buf *buf, int offset)
{
    if (offset < 0) {
        buf_putc(buf, '-');
        offset *= -1;
    }
    else buf_putc(buf, '+');

    int hours = offset / 3600;
    offset %= 3600;
    int minutes = offset / 60;
    offset %= 60;
    int seconds = offset;
    buf_printf(buf, "%02d", hours);
    buf_printf(buf, "%02d", minutes);
    if (seconds) buf_printf(buf, "%02d", seconds);
}

static json_t *timezonerule_from_ical(icalcomponent *tzrule)
{
    json_t *jtzrule = json_object();
    struct buf buf = BUF_INITIALIZER;
    icalproperty *prop;

    json_object_set_new(jtzrule, "@type", json_string("TimeZoneRule"));

    prop = icalcomponent_get_first_property(tzrule, ICAL_DTSTART_PROPERTY);
    if (prop) {
        icaltimetype dtstart = icalproperty_get_dtstart(prop);
        struct jmapical_datetime dt = JMAPICAL_DATETIME_INITIALIZER;
        jmapical_datetime_from_icaltime(dtstart, &dt);
        jmapical_localdatetime_as_string(&dt, &buf);
        json_object_set_new(jtzrule, "start", json_string(buf_cstring(&buf)));
        buf_reset(&buf);
    }

    prop = icalcomponent_get_first_property(tzrule, ICAL_TZOFFSETFROM_PROPERTY);
    if (prop) {
        format_tzoffset(&buf, icalproperty_get_tzoffsetfrom(prop));
        json_object_set_new(jtzrule, "offsetFrom", json_string(buf_cstring(&buf)));
        buf_reset(&buf);
    }

    prop = icalcomponent_get_first_property(tzrule, ICAL_TZOFFSETTO_PROPERTY);
    if (prop) {
        format_tzoffset(&buf, icalproperty_get_tzoffsetto(prop));
        json_object_set_new(jtzrule, "offsetTo", json_string(buf_cstring(&buf)));
        buf_reset(&buf);
    }

    json_t *rrules = json_array();
    for (prop = icalcomponent_get_first_property(tzrule, ICAL_RRULE_PROPERTY);
         prop;
         prop = icalcomponent_get_next_property(tzrule, ICAL_RRULE_PROPERTY)) {

        json_t *rrule = recurrencerule_from_ical(prop, NULL);
        if (rrule) json_array_append_new(rrules, rrule);
    }
    if (!json_array_size(rrules)) {
        json_decref(rrules);
        rrules = NULL;
    }
    if (rrules) json_object_set_new(jtzrule, "recurrenceRules", rrules);

    json_t *overrides = json_object();
    for (prop = icalcomponent_get_first_property(tzrule, ICAL_RDATE_PROPERTY);
         prop;
         prop = icalcomponent_get_next_property(tzrule, ICAL_RDATE_PROPERTY)) {

        struct icaldatetimeperiodtype rdate = icalproperty_get_rdate(prop);
        if (!icaltime_is_null_time(rdate.time)) {
            struct jmapical_datetime dt = JMAPICAL_DATETIME_INITIALIZER;
            jmapical_datetime_from_icaltime(rdate.time, &dt);

            jmapical_localdatetime_as_string(&dt, &buf);
            json_object_set_new(jtzrule, buf_cstring(&buf), json_object());
            buf_reset(&buf);
        }
    }
    if (!json_object_size(overrides)) {
        json_decref(overrides);
        overrides = NULL;
    }
    if (overrides) json_object_set_new(jtzrule, "recurrenceOverrides", overrides);

    json_t *names = json_object();
    for (prop = icalcomponent_get_first_property(tzrule, ICAL_TZNAME_PROPERTY);
         prop;
         prop = icalcomponent_get_next_property(tzrule, ICAL_TZNAME_PROPERTY)) {

        const char *tzname = icalproperty_get_tzname(prop);
        if (tzname && *tzname) {
            json_object_set_new(names, tzname, json_true());
        }
    }
    if (!json_object_size(names)) {
        json_decref(names);
        names = NULL;
    }
    if (names) json_object_set_new(jtzrule, "names", names);

    json_t *comments = json_array();
    for (prop = icalcomponent_get_first_property(tzrule, ICAL_COMMENT_PROPERTY);
         prop;
         prop = icalcomponent_get_next_property(tzrule, ICAL_COMMENT_PROPERTY)) {

        const char *comment = icalproperty_get_comment(prop);
        if (comment && *comment) {
            json_array_append_new(comments, json_string(comment));
        }
    }
    if (!json_array_size(comments)) {
        json_decref(comments);
        comments = NULL;
    }
    if (comments) json_object_set_new(jtzrule, "comments", comments);

    buf_free(&buf);
    return jtzrule;
}

static void read_custom_jstzids(json_t *jsevent, strarray_t *tzids)
{
    ptrarray_t work = PTRARRAY_INITIALIZER;
    const char *pname;
    json_t *jval;

    /* Prepare to process both the main event and overrides */
    ptrarray_append(&work, jsevent);
    json_object_foreach(jsevent, pname, jval) {
        if (!strcmp(pname, "recurrenceOverrides")) {
            ptrarray_append(&work, jval);
        }
    }

    /* Find all all timeZone property values */
    json_t *jpatch;
    while ((jpatch = ptrarray_pop(&work))) {
        json_object_foreach(jpatch, pname, jval) {
            const char *tzid = NULL;
            if (!strcmp(pname, "timeZone")) {
                tzid = json_string_value(jval);
            }
            else if (!strcmp(pname, "location")) {
                tzid = json_string_value(json_object_get(jval, "timeZone"));
            }
            else if (!strncmp(pname, "locations/", 10)) {
                pname += 10;
                const char *p = strchr(pname, '/');
                if (!strcmp(p + 1, "timeZone")) {
                    tzid = json_string_value(jval);
                }
            }
            if (tzid && *tzid == '/') {
                strarray_add(tzids, tzid);
            }
        }
    }

    ptrarray_fini(&work);
}

static json_t *timezones_from_ical(json_t *jsevent, jstimezones_t *jstzones)
{
    if (!jstzones || !jstzones->tzs.count) return NULL;

    strarray_t want_tzids = STRARRAY_INITIALIZER;
    read_custom_jstzids(jsevent, &want_tzids);
    if (!strarray_size(&want_tzids)) return NULL;

    json_t *jtimezones = json_object();
    struct buf buf = BUF_INITIALIZER;
    hash_iter *iter = hash_table_iter(&jstzones->byjstzid);

    while (hash_iter_next(iter)) {
        buf_reset(&buf);

        const char *jstzid = hash_iter_key(iter);
        icaltimezone *tz = hash_iter_val(iter);

        /* Skip orphaned timezones */
        if (strarray_find(&want_tzids, jstzid, 0) < 0) {
            continue;
        }

        /* Add timezone */
        json_t *jtimezone = json_object();
        json_object_set_new(jtimezone, "@type", json_string("TimeZone"));
        json_object_set_new(jtimezones, jstzid, jtimezone);
        /* Populate timezone properties */

        icalcomponent *tzcomp = icaltimezone_get_component(tz);
        icalproperty *prop;

        prop = icalcomponent_get_first_property(tzcomp, ICAL_TZID_PROPERTY);
        if (prop) {
            json_object_set_new(jtimezone, "tzId",
                    json_string(icalproperty_get_tzid(prop)));
        }

        prop = icalcomponent_get_first_property(tzcomp, ICAL_TZURL_PROPERTY);
        if (prop) {
            json_object_set_new(jtimezone, "url",
                    json_string(icalproperty_get_url(prop)));
        }

        prop = icalcomponent_get_first_property(tzcomp, ICAL_LASTMODIFIED_PROPERTY);
        if (prop) {
            icaltimetype icaldt = icalproperty_get_lastmodified(prop);
            struct jmapical_datetime dt = JMAPICAL_DATETIME_INITIALIZER;
            jmapical_datetime_from_icaltime(icaldt, &dt);
            jmapical_utcdatetime_as_string(&dt, &buf);
            json_object_set_new(jtimezone, "updated",
                    json_string(buf_cstring(&buf)));
            buf_reset(&buf);
        }

        prop = icalcomponent_get_first_property(tzcomp, ICAL_TZUNTIL_PROPERTY);
        if (prop) {
            icaltimetype icaldt = icalproperty_get_tzuntil(prop);
            struct jmapical_datetime dt = JMAPICAL_DATETIME_INITIALIZER;
            jmapical_datetime_from_icaltime(icaldt, &dt);
            jmapical_utcdatetime_as_string(&dt, &buf);
            json_object_set_new(jtimezone, "validUntil",
                    json_string(buf_cstring(&buf)));
            buf_reset(&buf);
        }

        json_t *jaliases = json_object();
        for (prop = icalcomponent_get_first_property(tzcomp, ICAL_TZIDALIASOF_PROPERTY);
             prop;
             prop = icalcomponent_get_next_property(tzcomp, ICAL_TZIDALIASOF_PROPERTY)) {
            const char *alias = icalproperty_get_tzidaliasof(prop);
            if (alias && *alias) {
                json_object_set_new(jaliases, alias, json_true());
            }
        }
        if (!json_object_size(jaliases)) {
            json_decref(jaliases);
            jaliases = NULL;
        }
        if (jaliases) json_object_set_new(jtimezone, "aliases", jaliases);

        icalcomponent *tzrule;

        json_t *standard = json_array();
        for (tzrule = icalcomponent_get_first_component(tzcomp, ICAL_XSTANDARD_COMPONENT);
             tzrule;
             tzrule = icalcomponent_get_next_component(tzcomp, ICAL_XSTANDARD_COMPONENT)) {

            json_t *jtzrule = timezonerule_from_ical(tzrule);
            if (jtzrule) json_array_append_new(standard, jtzrule);
        }
        if (!json_array_size(standard)) {
            json_decref(standard);
            standard = NULL;
        }
        if (standard) json_object_set_new(jtimezone, "standard", standard);

        json_t *daylight = json_array();
        for (tzrule = icalcomponent_get_first_component(tzcomp, ICAL_XDAYLIGHT_COMPONENT);
             tzrule;
             tzrule = icalcomponent_get_next_component(tzcomp, ICAL_XDAYLIGHT_COMPONENT)) {

            json_t *jtzrule = timezonerule_from_ical(tzrule);
            if (jtzrule) json_array_append_new(daylight, jtzrule);
        }
        if (!json_array_size(daylight)) {
            json_decref(daylight);
            daylight = NULL;
        }
        if (daylight) json_object_set_new(jtimezone, "daylight", daylight);
    }

    /* Clean up state */
    hash_iter_free(&iter);
    if (!json_object_size(jtimezones)) {
        json_decref(jtimezones);
        jtimezones = NULL;
    }
    buf_free(&buf);
    strarray_fini(&want_tzids);

    return jtimezones;
}

/* Convert the libical VEVENT comp to a CalendarEvent 
 *
 * master: if not NULL, treat comp as a VEVENT exception
 * props:  if not NULL, only convert properties named as keys
 */
static json_t*
calendarevent_from_ical(icalcomponent *comp, hash_table *props,
                        int is_override, ptrarray_t *overrides,
                        jstimezones_t *jstzones,
                        struct jmapical_jmapcontext *jmapctx)
{
    icalproperty* prop = NULL;
    hash_table *wantprops = NULL;
    json_t *event = json_pack("{s:s}", "@type", "JSEvent");
    struct buf buf = BUF_INITIALIZER;
    jstimezones_t myjstzones = JSTIMEZONES_INITIALIZER;

    /* Read custom timezones */
    if (!jstzones) {
        icalcomponent *ical = icalcomponent_get_parent(comp);
        jstimezones_add_vtimezones(&myjstzones, ical);
        jstzones = &myjstzones;
    }

    if (jmap_wantprop(props, "recurrenceOverrides") && !is_override) {
        /* Fetch all properties if recurrenceOverrides are requested,
         * otherwise we might return incomplete override patches */
        wantprops = props;
        props = NULL;
    }

    /* Handle bogus mix of floating and time zoned types */
    // use jstzid?
    char *tzid_start = xstrdupnull(tzid_from_ical(comp,
                ICAL_DTSTART_PROPERTY, jstzones));
    if (!tzid_start) {
        tzid_start = xstrdupnull(tzid_from_ical(comp,
                    ICAL_DTEND_PROPERTY, jstzones));
    }

    /* start */
    if (jmap_wantprop(props, "start")) {
        struct jmapical_datetime start = JMAPICAL_DATETIME_INITIALIZER;
        if ((prop = icalcomponent_get_first_property(comp, ICAL_DTSTART_PROPERTY))) {
            icaltimetype dtstart = dtstart_from_ical(comp, jstzones);
            jmapical_datetime_from_icaltime(dtstart, &start);
        }
        jmapical_localdatetime_as_string(&start, &buf);
        json_object_set_new(event, "start", json_string(buf_cstring(&buf)));
        buf_reset(&buf);
    }

    /* timeZone */
    if (jmap_wantprop(props, "timeZone")) {
        const char *jstzid = jstimezones_get_jstzid(jstzones, tzid_start);
        json_object_set_new(event, "timeZone",
                jstzid ? json_string(jstzid) : json_null());
    }

    /* duration */
    if (jmap_wantprop(props, "duration")) {
        struct jmapical_duration dur = JMAPICAL_DURATION_INITIALIZER;
        duration_from_vevent(comp, &dur, jstzones);
        jmapical_duration_as_string(&dur, &buf);
        json_object_set_new(event, "duration", json_string(buf_cstring(&buf)));
        buf_reset(&buf);
    }

    /* showWithoutTime */
    if (jmap_wantprop(props, "showWithoutTime")) {
        int show_without_time = 0;

        const char *strval = get_icalxprop_value(comp, JMAPICAL_XPROP_SHOWWITHOUTTIME);
        if (strval) {
            show_without_time = !strcasecmp(strval, "TRUE");
        }
        else {
            show_without_time = icaltime_is_date(icalcomponent_get_dtstart(comp));
        }
        json_object_set_new(event, "showWithoutTime", json_boolean(show_without_time));
    }

    /* uid */
    const char *uid = icalcomponent_get_uid(comp);
    if (uid && !is_override) {
        json_object_set_new(event, "uid", json_string(uid));
    }

    /* relatedTo */
    if (jmap_wantprop(props, "relatedTo") && !is_override) {
        json_object_set_new(event, "relatedTo", relatedto_from_ical(comp));
    }

    /* prodId */
    if (jmap_wantprop(props, "prodId") && !is_override) {
        icalcomponent *ical = icalcomponent_get_parent(comp);
        const char *prodid = NULL;
        prop = icalcomponent_get_first_property(ical, ICAL_PRODID_PROPERTY);
        if (prop) prodid = icalproperty_get_prodid(prop);
        json_object_set_new(event, "prodId",
                prodid ? json_string(prodid) : json_null());
    }

    /* created */
    if (jmap_wantprop(props, "created")) {
        struct jmapical_datetime created = JMAPICAL_DATETIME_INITIALIZER;
        if ((prop = icalcomponent_get_first_property(comp, ICAL_CREATED_PROPERTY))) {
            jmapical_datetime_from_icalprop(prop, &created);
            jmapical_utcdatetime_as_string(&created, &buf);
            json_t *jval = json_string(buf_cstring(&buf));
            buf_reset(&buf);
            json_object_set_new(event, "created", jval);
        }
    }

    /* updated */
    if (jmap_wantprop(props, "updated")) {
        struct jmapical_datetime updated = JMAPICAL_DATETIME_INITIALIZER;
        if ((prop = icalcomponent_get_first_property(comp, ICAL_DTSTAMP_PROPERTY))) {
            jmapical_datetime_from_icalprop(prop, &updated);
            jmapical_utcdatetime_as_string(&updated, &buf);
            json_t* jval = json_string(buf_cstring(&buf));
            buf_reset(&buf);
            json_object_set_new(event, "updated", jval);
        }
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
        if (jmap_wantprop(props, "description")) {
            prop = icalcomponent_get_first_property(comp, ICAL_DESCRIPTION_PROPERTY);
            if (prop) {
                const char *desc = icalproperty_get_description(prop);
                if (desc && *desc) {
                    json_object_set_new(event, "description", json_string(desc));
                }
            }
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

    /* locale */
    if (jmap_wantprop(props, "locale")) {
        json_object_set_new(event, "locale", locale_from_ical(comp));
    }

    if (jmap_wantprop(props, "links") ||
        jmap_wantprop(props, "locations") ||
        jmap_wantprop(props, "participants")) {

        /* This is a bit gnarly, iterating over comp might destroy the
         * comp-internal property further above the call stack. To
         * prevent this subtle bug, we first collect all links into
         * a JSON object that groups links by property and id. */
        json_t *linksbyprop = linksbyprop_from_ical(comp, jmapctx);

        /* links */
        if (jmap_wantprop(props, "links")) {
            json_t *links = json_object_get(linksbyprop, "links");
            json_object_set(event, "links", links ? links : json_null()); // incref
        }
        /* locations */
        if (jmap_wantprop(props, "locations")) {
            json_object_set_new(event, "locations",
                    locations_from_ical(comp,
                        json_object_get(linksbyprop, "locations"), jstzones));
        }
        /* participants */
        if (jmap_wantprop(props, "participants")) {
            json_object_set_new(event, "participants",
                    participants_from_ical(comp,
                        json_object_get(linksbyprop, "participants")));
        }

        json_decref(linksbyprop);
    }

    /* virtualLocations */
    if (jmap_wantprop(props, "virtualLocations")) {
        json_object_set_new(event, "virtualLocations",
                virtuallocations_from_ical(comp));
    }

    /* replyTo */
    if (jmap_wantprop(props, "replyTo") && !is_override) {
        if ((prop = icalcomponent_get_first_property(comp, ICAL_ORGANIZER_PROPERTY))) {
            json_object_set_new(event, "replyTo",rsvpto_from_ical(prop));
        }
    }

    /* recurrenceRules */
    if (jmap_wantprop(props, "recurrenceRules") && !is_override) {
        json_object_set_new(event, "recurrenceRules",
                recurrencerules_from_ical(comp, ICAL_RRULE_PROPERTY, jstzones));
    }

    /* excludedRecurrenceRules */
    if (jmap_wantprop(props, "excludedRecurrenceRules") && !is_override) {
        json_object_set_new(event, "excludedRecurrenceRules",
                recurrencerules_from_ical(comp, ICAL_EXRULE_PROPERTY, jstzones));
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
    if (jmap_wantprop(props, "replyTo") && !is_override) {
        if ((prop = icalcomponent_get_first_property(comp, ICAL_ORGANIZER_PROPERTY))) {
            json_t *jreplyto = rsvpto_from_ical(prop);
            if (jreplyto) {
                json_object_set_new(event, "replyTo", jreplyto);
            }
        }
    }

    /* useDefaultAlerts */
    if (jmap_wantprop(props, "useDefaultAlerts")) {
        const char *v = get_icalxprop_value(comp, "X-APPLE-DEFAULT-ALARM");
        if (!v) {
            /* Our previous jscalendar draft implementation used a custom
             * extension property to denote useDefaultAlerts. We won't
             * write this property anymore but fall back reading it. */
            v = get_icalxprop_value(comp, "X-JMAP-USEDEFAULTALERTS");
        }
        json_object_set_new(event, "useDefaultAlerts",
                json_boolean(!strcasecmpsafe(v, "true")));
    }

    /* alerts */
    if (jmap_wantprop(props, "alerts")) {
        json_object_set_new(event, "alerts", alerts_from_ical(comp));
    }

    if (!is_override) {
        /* must go go last, we need all other properties to be set */

        /* recurrenceOverrides */
        if (jmap_wantprop(props, "recurrenceOverrides")) {
            json_object_set_new(event, "recurrenceOverrides",
                    overrides_from_ical(comp, overrides, event,
                        tzid_start, jstzones, jmapctx));
        }

        /* timeZones - requires overrides set in the event already */
        if (jmap_wantprop(props, "timeZones")) {
            json_t *jtimezones = timezones_from_ical(event, jstzones);
            if (JNOTNULL(jtimezones)) {
                json_object_set_new(event, "timeZones", jtimezones);
            }
        }
    }

    if (wantprops) {
        jmap_filterprops(event, wantprops);
    }

    if (jstzones == &myjstzones) jstimezones_fini(&myjstzones);
    free(tzid_start);
    buf_free(&buf);
    return event;
}

json_t*
jmapical_tojmap_all(icalcomponent *ical, hash_table *props,
                    struct jmapical_jmapcontext *jmapctx)
{
    icalcomponent* comp;
    int has_overrides = 0;
    hash_table overrides_by_uid = HASH_TABLE_INITIALIZER;

    /* Locate all main VEVENTs. */
    ptrarray_t todo = PTRARRAY_INITIALIZER;
    icalcomponent *firstcomp =
        icalcomponent_get_first_component(ical, ICAL_VEVENT_COMPONENT);
    for (comp = firstcomp;
         comp;
         comp = icalcomponent_get_next_component(ical, ICAL_VEVENT_COMPONENT)) {

        if (!icalcomponent_get_uid(comp)) continue;

        if (icalcomponent_get_first_property(comp, ICAL_RECURRENCEID_PROPERTY)) {
            has_overrides = 1;
            continue;
        }

        ptrarray_append(&todo, comp);
    }
    /* magic promote to toplevel for the first item */
    if (firstcomp && !ptrarray_size(&todo)) {
        ptrarray_append(&todo, firstcomp);
    }
    else if (!ptrarray_size(&todo)) {
        return json_array();
    }

    if (has_overrides) {
        /* Map overrides by UID */
        construct_hash_table(&overrides_by_uid, ptrarray_size(&todo), 0);

        for (comp = icalcomponent_get_first_component(ical, ICAL_VEVENT_COMPONENT);
             comp;
             comp = icalcomponent_get_next_component(ical, ICAL_VEVENT_COMPONENT)) {

            const char *uid = icalcomponent_get_uid(comp);
            if (!uid) continue;

            if (!icalcomponent_get_first_property(comp, ICAL_RECURRENCEID_PROPERTY)) {
                continue;
            }

            ptrarray_t *overrides = hash_lookup(uid, &overrides_by_uid);
            if (!overrides) {
                overrides = ptrarray_new();
                hash_insert(uid, overrides, &overrides_by_uid);
            }
            ptrarray_append(overrides, comp);
        }
    }

    /* Convert the VEVENTs to JMAP. */
    json_t *events = json_array();
    while ((comp = ptrarray_pop(&todo))) {
        ptrarray_t *overrides = NULL;
        if (has_overrides) {
            const char *uid = icalcomponent_get_uid(comp);
            overrides = hash_lookup(uid, &overrides_by_uid);
        }
        json_t *jsevent = calendarevent_from_ical(comp,
                props, 0, overrides, NULL, jmapctx);
        if (jsevent) json_array_append_new(events, jsevent);
    }

    if (has_overrides) {
        hash_iter *hit = hash_table_iter(&overrides_by_uid);
        while (hash_iter_next(hit)) {
            ptrarray_t *overrides = hash_iter_val(hit);
            ptrarray_free(overrides);
        }
        hash_iter_free(&hit);
        free_hash_table(&overrides_by_uid, NULL);
    }
    ptrarray_fini(&todo);

    return events;
}

json_t*
jmapical_tojmap(icalcomponent *ical, hash_table *props,
                struct jmapical_jmapcontext *jmapctx)
{
    json_t *jsevents = jmapical_tojmap_all(ical, props, jmapctx);
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

static int validate_type(struct jmap_parser *parser, json_t *jobj, const char *wanttype)
{
    json_t *jtype = json_object_get(jobj, "@type");
    if (jtype && jtype != json_null()) {
        if (!json_is_string(jtype) || strcasecmp(json_string_value(jtype), wanttype)) {
            jmap_parser_invalid(parser, "@type");
            return 0;
        }
    }
    return 1;
}

static void relatedto_to_ical(icalcomponent *, struct jmap_parser *, json_t *);

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

/* Add or overwrite the datetime property kind in comp. If tz is not NULL, set
 * the TZID parameter on the property. Also take care to purge conflicting
 * datetime properties such as DTEND and DURATION. */
static icalproperty *insert_icaltimeprop(icalcomponent *comp,
                                         icaltimetype dt,
                                         int remove_existing,
                                         enum icalproperty_kind kind)
{
    icalproperty *prop;

    /* Purge existing property. */
    if (remove_existing) {
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
        syslog(LOG_ERR, "insert_icaltimeprop: invalid time value");
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
    const char *rel = json_string_value(json_object_get(loc, "relativeTo"));
    if (!rel) return 0;
    return json_object_get(loc, "timeZone") && !strcmp(rel, "end");
}

/* Update the start and end properties of VEVENT comp, as defined by
 * the JMAP calendarevent event. */
static void
startend_to_ical(icalcomponent *comp, struct jmap_parser *parser,
                 json_t *event,
                 jstimezones_t *jstzones)
{
    json_t *jprop;

    /* timeZone */
    icaltimezone *tzstart = NULL;
    jprop = json_object_get(event, "timeZone");
    if (json_is_string(jprop)) {
        const char *jstzid = json_string_value(jprop);
        tzstart = jstimezones_lookup_jstzid(jstzones, jstzid);
        if (!tzstart) {
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
            const char *jstzid = json_string_value(json_object_get(jval, "timeZone"));
            if (timezone) {
                tzend = jstimezones_lookup_jstzid(jstzones, jstzid);
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
    struct jmapical_duration dur = JMAPICAL_DURATION_INITIALIZER;
    jprop = json_object_get(event, "duration");
    if (json_is_string(jprop)) {
        if (jmapical_duration_from_string(json_string_value(jprop), &dur) < 0) {
            jmap_parser_invalid(parser, "duration");
        }
    } else if (JNOTNULL(jprop)) {
        jmap_parser_invalid(parser, "duration");
    }

    /* Read start */
    struct jmapical_datetime start = JMAPICAL_DATETIME_INITIALIZER;
    jprop = json_object_get(event, "start");
    if (json_is_string(jprop)) {
        if (jmapical_localdatetime_from_string(json_string_value(jprop), &start) < 0) {
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

    /* Add DTSTART */
    int is_date = 0;
    if (!tzstart && !tzend && jmapical_datetime_has_zero_time(&start) &&
            jmapical_duration_has_zero_time(&dur)) {
        /* Determine if to store DTSTART as DATE type */
        is_date = 1;
        /* Check recurrence frequency */
        json_t *jrrules = json_object_get(event, "recurrenceRules");
        if (json_array_size(jrrules)) {
            json_t *jrrule = json_array_get(jrrules, 0);
            if (json_is_object(jrrule)) {
                const char *freq = json_string_value(json_object_get(jrrule, "frequency"));
                if (!strcmpsafe(freq, "hourly") ||
                        !strcmpsafe(freq, "minutely") ||
                        !strcmpsafe(freq, "secondly")) {
                    is_date = 0;
                }
                else {
                    /* Check that all overrides have zero time */
                    json_t *joverrides = json_object_get(event, "recurrenceOverrides");
                    const char *recuridval;
                    json_t *jval;
                    json_object_foreach(joverrides, recuridval, jval) {
                        struct jmapical_datetime recurid = JMAPICAL_DATETIME_INITIALIZER;
                        if ((jmapical_localdatetime_from_string(recuridval, &recurid) >= 0) &&
                                !jmapical_datetime_has_zero_time(&recurid)) {
                            is_date = 0;
                            break;
                        }
                    }
                }
            }
        }
        if (json_object_get(event, "showWithoutTime") == json_false()) {
            /* Explicitly set to false. Keep start as floating time. */
            is_date = 0;
        }
    }

    struct icaltimetype dtstart = is_date ?
        jmapical_datetime_to_icaldate(&start) :
        jmapical_datetime_to_icaltime(&start, tzstart);
    insert_icaltimeprop(comp, dtstart, 1, ICAL_DTSTART_PROPERTY);
    if (tzstart != tzend) {
        /* Add DTEND */
        struct icaldurationtype icaldur = jmapical_duration_to_icalduration(&dur);
        icaltimetype dtend = icaltime_add(dtstart, icaldur);
        dtend = icaltime_convert_to_zone(dtend, tzend);
        icalproperty *prop = insert_icaltimeprop(comp, dtend, 1, ICAL_DTEND_PROPERTY);
        if (prop) xjmapid_to_ical(prop, endzone_location_id);
    } else {
        /* Add DURATION */
        struct icaldurationtype icaldur = jmapical_duration_to_icalduration(&dur);
        icalproperty *prop = icalproperty_new_duration(icaldur);
        icalcomponent_add_property(comp, prop);
    }

    json_t *jshowWithoutTime = json_object_get(event, "showWithoutTime");
    if (json_is_boolean(jshowWithoutTime)) {
        int show_without_time = json_boolean_value(jshowWithoutTime);
        /* Only set in iCalendar if it isn't implied by DTSTART value type */
        if ((is_date == 0) != (show_without_time == 0)) {
            icalproperty *prop = icalproperty_new(ICAL_X_PROPERTY);
            icalproperty_set_x_name(prop, JMAPICAL_XPROP_SHOWWITHOUTTIME);
            icalvalue *icalval = icalvalue_new_boolean(show_without_time);
            icalproperty_set_value(prop, icalval);
            icalcomponent_add_property(comp, prop);
        }
    }
    else if (JNOTNULL(jshowWithoutTime)) {
        jmap_parser_invalid(parser, "showWithoutTime");
    }

}

static void
participant_roles_to_ical(icalproperty *prop,
                          struct jmap_parser *parser,
                          json_t *roles)
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

    icalparameter_role ical_role = ICAL_ROLE_REQPARTICIPANT;
    int has_chair = json_object_get(roles, "chair") == json_true();
    int has_optional = json_object_get(roles, "optional") == json_true();
    int has_informational = json_object_get(roles, "informational") == json_true();

    /* Try to map roles to iCalendar without falling back to X-ROLE */
    if (has_chair && ical_role == ICAL_ROLE_REQPARTICIPANT) {
        /* Can use iCalendar ROLE=CHAIR parameter */
        ical_role = ICAL_ROLE_CHAIR;
    }
    if (has_optional && ical_role == ICAL_ROLE_REQPARTICIPANT) {
        /* Can use iCalendar ROLE=OPT-PARTICIPANT parameter */
        ical_role = ICAL_ROLE_OPTPARTICIPANT;
    }
    if (has_informational && ical_role == ICAL_ROLE_REQPARTICIPANT) {
        /* Can use iCalendar ROLE=NON-PARTICIPANT parameter */
        ical_role = ICAL_ROLE_NONPARTICIPANT;
    }

    /* Map roles */
    json_object_foreach(roles, key, jval) {
        if (!strcasecmp(key, "CHAIR") && ical_role == ICAL_ROLE_CHAIR) continue;
        if (!strcasecmp(key, "OPTIONAL") && ical_role == ICAL_ROLE_OPTPARTICIPANT) continue;
        if (!strcasecmp(key, "INFORMATIONAL") && ical_role == ICAL_ROLE_NONPARTICIPANT) continue;
        // everything else needs an XROLE
        icalproperty_set_xparam(prop, JMAPICAL_XPARAM_ROLE, key, 0);
    }

    if (ical_role != ICAL_ROLE_REQPARTICIPANT) {
        icalparameter *param = icalparameter_new_role(ical_role);
        icalproperty_add_parameter(prop, param);
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

static icalcomponent *oldcomp_of(icalcomponent *comp, struct icalcomps *oldcomps)
{
    if (!oldcomps) return NULL;

	icalcomponent *oldcomp = icalcomps_by_uidrecurid(oldcomps, comp);
	if (!oldcomp) {
		// fall back using main component
        const char *uid = icalcomponent_get_uid(comp);
		ptrarray_t *complist = icalcomps_by_uid(oldcomps, uid);
		if (complist) {
			oldcomp = ptrarray_nth(complist, 0);
		}
	}

    return oldcomp;
}

static void links_to_ical(icalcomponent *comp, struct icalcomps *oldcomps,
                          struct jmap_parser *parser, json_t *links,
                          const char *parentprop, const char *parentid,
                          struct jmapical_jmapcontext *jmapctx)
{
    icalproperty *prop;
    struct buf buf = BUF_INITIALIZER;
    struct buf blobhref = BUF_INITIALIZER;
    struct buf blobmid = BUF_INITIALIZER;
    icalcomponent *oldcomp = oldcomp_of(comp, oldcomps);

    jmap_parser_push(parser, "links");

    const char *id;
    json_t *link;
    json_object_foreach(links, id, link) {
        buf_reset(&buf);

        const char *href = NULL;
        const char *blobid = NULL;
        const char *contenttype = NULL;
        const char *title = NULL;
        const char *rel = NULL;
        const char *cid = NULL;
        const char *display = NULL;
        json_int_t size = -1;
        json_t *jprop = NULL;

        size_t invalid_count = json_array_size(parser->invalid);

        jmap_parser_push(parser, id);

        if (!is_valid_jmapid(id)) {
            jmap_parser_invalid(parser, id);
        }

        validate_type(parser, link, "Link");

        /* href */
        href = json_string_value(json_object_get(link, "href"));

        /* blobId */
        json_t *jblobid = json_object_get(link, "blobId");
        if (jmapctx && jmapctx->href_from_blobid && json_is_string(jblobid)) {
            blobid = json_string_value(json_object_get(link, "blobId"));
            jmapctx->href_from_blobid(&blobhref, &blobmid, blobid, jmapctx->rock);
            if (buf_len(&blobhref)) {
                if (!href || !strcmp(href, buf_cstring(&blobhref))) {
                    href = buf_cstring(&blobhref);
                }
                else jmap_parser_invalid(parser, "blobId");
            }
        }
        else if (JNOTNULL(jblobid)) {
            jmap_parser_invalid(parser, "blobId");
        }

        if (!href || *href == '\0') {
            jmap_parser_invalid(parser, "href");
            href = NULL;
        }

        /* contentType */
        jprop = json_object_get(link, "contentType");
        if (json_is_string(jprop)) {
            contenttype = json_string_value(jprop);
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

        if (json_array_size(parser->invalid) > invalid_count) {
            continue;
        }

        /* Make Link objects stick to their iCalendar type */
        icalproperty_kind oldkind = ICAL_NO_PROPERTY;
        if (oldcomp) {
            /* XXX - A Link object that previously mapped to a URL
             * property again maps to a URL property in the
             * new component. That violates RFC 5545 and
             * RFC 7986 which both limit the number of URLs per
             * component to one. But the CalDAV client that
             * generated the previous component chose to not
             * conform to that requirement, so we stick to that. */
            prop = findprop_byid(oldcomp, id, ICAL_URL_PROPERTY);
            if (!prop) {
                prop = findprop_byid(oldcomp, id, ICAL_ATTACH_PROPERTY);
            }
            if (prop) {
                oldkind = icalproperty_isa(prop);
            }
        }
        icalproperty_kind kind = oldkind;

        /* Determine iCalendar type by Link properties */
        if (kind == ICAL_NO_PROPERTY) {
            if (!strcmpsafe(rel, "describedby") &&
                    !cid && !contenttype && !display &&
                    !icalcomponent_get_first_property(comp, ICAL_URL_PROPERTY)) {

                kind = ICAL_URL_PROPERTY;
            }
            else kind = ICAL_ATTACH_PROPERTY;
        }

        /* Build iCalendar property */
        if (kind == ICAL_URL_PROPERTY) {
            prop = icalproperty_new(ICAL_URL_PROPERTY);
            icalproperty_set_value(prop, icalvalue_new_uri(href));
        }
        else {
            icalattach *icalatt = icalattach_new_from_url(href);
            prop = icalproperty_new_attach(icalatt);
            icalattach_unref(icalatt);

            if (buf_len(&blobmid)) {
                icalproperty_add_parameter(prop,
                        icalparameter_new_managedid(buf_cstring(&blobmid)));
            }
        }

        /* contentType */
        if (contenttype) {
            icalproperty_add_parameter(prop,
                    icalparameter_new_fmttype(contenttype));
        }

        /* rel */
        if (rel && (kind != ICAL_URL_PROPERTY || strcmp(rel, "describedby")))
            icalproperty_set_xparam(prop, JMAPICAL_XPARAM_REL, rel, 1);

        /* title */
        if (title) {
            icalproperty_set_xparam(prop, JMAPICAL_XPARAM_TITLE, title, 1);
        }

        /* cid */
        if (cid) icalproperty_set_xparam(prop, JMAPICAL_XPARAM_CID, cid, 1);

        /* size */
        if (size >= 0) {
            buf_printf(&buf, "%"JSON_INTEGER_FORMAT, size);
            icalproperty_add_parameter(prop,
                    icalparameter_new_size(buf_cstring(&buf)));
            buf_reset(&buf);
        }

        /* display */
        if (display) icalproperty_set_xparam(prop, JMAPICAL_XPARAM_DISPLAY, display, 1);

        /* Set custom id */
        icalproperty_set_xparam(prop, JMAPICAL_XPARAM_ID, id, 1);

        /* Set parent. Note that jmapical_sanitize_ical depends on this. */
        if (parentprop) {
            icalproperty_set_xparam(prop, JMAPICAL_XPARAM_PARENTPROP, parentprop, 1);
        }
        if (parentid) {
            icalproperty_set_xparam(prop, JMAPICAL_XPARAM_PARENTID, parentid, 1);
        }

        /* Add ATTACH property. */
        icalcomponent_add_property(comp, prop);
    }

    jmap_parser_pop(parser);
    buf_free(&blobhref);
    buf_free(&blobmid);
    buf_free(&buf);
}

static void
participant_to_ical(icalcomponent *comp,
                    icalproperty *oldattendee,
                    struct jmap_parser *parser,
                    const char *partid,
                    json_t *jpart,
                    json_t *participants,
                    const char *orga_uri,
                    hash_table *caladdress_by_participant_id,
                    int allow_organizer_attendee_only,
                    struct jmapical_jmapcontext *jmapctx)
{
    const char *caladdress = hash_lookup(partid, caladdress_by_participant_id);
    icalproperty *prop = icalproperty_new_attendee(caladdress);
    icalproperty_set_xparam(prop, JMAPICAL_XPARAM_ID, partid, 1);
    icaltimezone *utc = icaltimezone_get_utc_timezone();
    icalparameter *param;

    icalproperty *orga = icalcomponent_get_first_property(comp, ICAL_ORGANIZER_PROPERTY);
    int is_orga = orga_uri ? match_uri(caladdress, orga_uri) : 0;
    if (is_orga) icalproperty_set_xparam(orga, JMAPICAL_XPARAM_ID, partid, 1);

    /* FIXME invitedBy */

    /* name */
    json_t *jname = json_object_get(jpart, "name");
    if (json_is_string(jname)) {
        const char *name = json_string_value(jname);
        if (*name) {
            icalproperty_add_parameter(prop, icalparameter_new_cn(name));
            if (is_orga) {
                icalproperty_add_parameter(orga, icalparameter_new_cn(name));
            }
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
            icalproperty_set_xparam(prop, JMAPICAL_XPARAM_RSVP_URI, buf_cstring(&buf), 0);
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
        const char *email = json_string_value(jemail);
        if (*email) {
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

    /* roles */
    json_t *roles = json_object_get(jpart, "roles");
    if (json_object_size(roles)) {
        participant_roles_to_ical(prop, parser, roles);
    }
    else if (roles) {
        jmap_parser_invalid(parser, "roles");
    }

    /* locationId */
    json_t *locationId = json_object_get(jpart, "locationId");
    if (json_is_string(locationId)) {
        const char *s = json_string_value(locationId);
        icalproperty_set_xparam(prop, JMAPICAL_XPARAM_LOCATIONID, s, 1);
    }
    else if (JNOTNULL(locationId)) {
        jmap_parser_invalid(parser, "locationId");
    }

    /* language */
    json_t *language = json_object_get(jpart, "language");
    if (json_is_string(language)) {
        const char *l = json_string_value(language);
        if (*l) {
            icalproperty_add_parameter(prop, icalparameter_new_language(l));
        }

    }
    else if (JNOTNULL(language)) {
        jmap_parser_invalid(parser, "language");
    }

    /* description */
    json_t *description = json_object_get(jpart, "description");
    if (json_is_string(description)) {
        const char *s = json_string_value(description);
        if (*s) icalproperty_set_xparam(prop, JMAPICAL_XPARAM_DESCRIPTION, s, 0);
    }
    else if (JNOTNULL(description)) {
        jmap_parser_invalid(parser, "description");
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

    /* links */
    json_t *links = json_object_get(jpart, "links");
    if (oldattendee) {
        /* Link objects generated from DIR parameter stick to DIR */
        param = icalproperty_get_first_parameter(oldattendee, ICAL_DIR_PARAMETER);
        if (param) {
            const char *linkid = get_icalxparam_value(prop, JMAPICAL_XPARAM_LINKID);
            char keybuf[JMAPICAL_SHA1KEY_LEN];
            if (!linkid) {
                linkid = sha1key(icalparameter_get_dir(param), keybuf);
            }
            json_t *link = json_object_get(links, linkid);
            const char *href = json_string_value(json_object_get(link, "href"));
            if (href && (json_object_size(link) == 1 ||
                        (json_object_size(link) == 2 && json_object_get(link, "@type")))) {

                icalproperty_add_parameter(prop, icalparameter_new_dir(href));
                icalproperty_set_xparam(prop, JMAPICAL_XPARAM_LINKID, linkid, 1);
                json_object_del(links, linkid);
            }
        }
    }
    if (json_object_size((links))) {
        jmap_parser_push(parser, "links");
        links_to_ical(comp, NULL, parser, links, "participants", partid, jmapctx);
        jmap_parser_pop(parser);
    }

    /* scheduleSequence */
    json_t *scheduleSequence = json_object_get(jpart, "scheduleSequence");
    if (json_is_integer(scheduleSequence) && json_integer_value(scheduleSequence) >= 0) {
        struct buf buf = BUF_INITIALIZER;
        buf_printf(&buf, "%lld", json_integer_value(scheduleSequence));
        icalproperty_set_xparam(prop, JMAPICAL_XPARAM_SEQUENCE, buf_cstring(&buf), 0);
        buf_free(&buf);
    }
    else if (JNOTNULL(scheduleSequence)) {
        jmap_parser_invalid(parser, "scheduleSequence");
    }

    /* scheduleUpdated */
    json_t *scheduleUpdated = json_object_get(jpart, "scheduleUpdated");
    if (json_is_string(scheduleUpdated)) {
        struct jmapical_datetime tstamp = JMAPICAL_DATETIME_INITIALIZER;
        if (jmapical_utcdatetime_from_string(json_string_value(scheduleUpdated), &tstamp) >= 0) {
            icaltimetype icaltstamp = jmapical_datetime_to_icaltime(&tstamp, utc);
            char *tmp = icaltime_as_ical_string_r(icaltstamp);
            icalproperty_set_xparam(prop, JMAPICAL_XPARAM_DTSTAMP, tmp, 0);
            free(tmp);
        }
        else {
            jmap_parser_invalid(parser, "scheduleSequence");
        }
    }
    else if (JNOTNULL(scheduleUpdated)) {
        jmap_parser_invalid(parser, "scheduleSequence");
    }

    /* FIXME scheduleAgent */
    /* FIXME scheduleForceSend */

    /* scheduleStatus */
    json_t *scheduleStatus = json_object_get(jpart, "scheduleStatus");
    if (json_array_size(scheduleStatus)) {
        struct buf buf = BUF_INITIALIZER;
        size_t i;
        json_t *jval;
        json_array_foreach(scheduleStatus, i, jval) {
            const char *str = json_string_value(jval);
            int is_valid = 0;
            /* RFC5545, 3.8.8.3: statcode = 1*DIGIT 1*2("." 1*DIGIT) */
            if (str && isdigit(str[0]) &&
                (!str[1] ||
                 (str[1] == '.' && isdigit(str[2]) &&
                    (!str[3] ||
                     (str[3] == '.' && isdigit(str[4]) && !str[5]))))) {
                is_valid = 1;
            }
            if (is_valid) {
                if (i) buf_putc(&buf, ',');
                buf_appendcstr(&buf, str);
            }
            else {
                jmap_parser_push_index(parser, "scheduleStatus", i, NULL);
                jmap_parser_invalid(parser, NULL);
                jmap_parser_pop(parser);
            }
        }
        if (buf_len(&buf)) {
            icalproperty_add_parameter(prop,
                    icalparameter_new_schedulestatus(buf_cstring(&buf)));
        }
        buf_free(&buf);
    }
    else if (JNOTNULL(scheduleStatus)) {
        jmap_parser_invalid(parser, "scheduleStatus");
    }

    /* participationComment */
    json_t *jcomment = json_object_get(jpart, "participationComment");
    if (json_is_string(jcomment)) {
        const char *comment = json_string_value(jcomment);
        if (*comment) {
            icalproperty_set_xparam(prop, JMAPICAL_XPARAM_COMMENT, comment, 1);
        }
    }
    else if (JNOTNULL(jcomment)) {
        jmap_parser_invalid(parser, "participationComment");
    }

    if (is_orga) {
        /* We might get away by not creating an ATTENDEE, if the
         * participant is owner of the event and all its JSCalendar
         * properties can be mapped to the ORGANIZER property.
         * But only if there is at least one other ATTENDEE, or the
         * original data already only contained an ORGANIZER. */
        json_t *jorga = participant_from_icalorganizer(orga);
        if (participant_equals(jorga, jpart) &&
                (hash_numrecords(caladdress_by_participant_id) > 1 ||
                 allow_organizer_attendee_only)) {
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
static void participants_to_ical(icalcomponent *comp,
                                 struct jmap_parser *parser,
                                 json_t *event,
                                 struct icalcomps *oldcomps,
                                 struct jmapical_jmapcontext *jmapctx)
{
    /* Purge existing ATTENDEEs and ORGANIZER */
    remove_icalprop(comp, ICAL_ATTENDEE_PROPERTY);
    remove_icalprop(comp, ICAL_ORGANIZER_PROPERTY);

    /* Basic validation first */
    json_t *replyTo = json_object_get(event, "replyTo");
    if (JNOTNULL(replyTo) && !json_object_size(replyTo)) {
        jmap_parser_invalid(parser, "replyTo");
    }
    json_t *participants = json_object_get(event, "participants");
    if (JNOTNULL(participants) && !json_object_size(participants)) {
        jmap_parser_invalid(parser, "participants");
    }

    hash_table caladdress_by_participant_id = HASH_TABLE_INITIALIZER;
    construct_hash_table(&caladdress_by_participant_id,
            json_object_size(participants)+1, 0);

    /* Hash previous ATTENDEEs */
    hash_table oldattendees_by_jmapid = HASH_TABLE_INITIALIZER;
    construct_hash_table(&oldattendees_by_jmapid,
            json_object_size(participants)+1, 0);

    hash_table oldattendees_by_caladdress = HASH_TABLE_INITIALIZER;
    construct_hash_table(&oldattendees_by_caladdress,
            json_object_size(participants)+1, 0);

    icalcomponent *oldcomp = oldcomp_of(comp, oldcomps);
    if (oldcomp) {
        icalproperty *oldatt;
        for (oldatt = icalcomponent_get_first_property(oldcomp, ICAL_ATTENDEE_PROPERTY);
             oldatt;
             oldatt = icalcomponent_get_next_property(oldcomp, ICAL_ATTENDEE_PROPERTY)) {
            char *jmapid = xjmapid_from_ical(oldatt);
            if (jmapid) {
                hash_insert(jmapid, oldatt, &oldattendees_by_jmapid);
            }
            const char *caladdress = icalproperty_get_attendee(oldatt);
            if (caladdress) {
                hash_insert(caladdress, oldatt, &oldattendees_by_caladdress);
            }
            free(jmapid);
        }
    }

    /* iCalendar events may only contain an ORGANIZER or an ATTENDEE.
     * We allow to update such events, but we reject them during creation. */
    int allow_organizer_attendee_only = 0;
    if (oldcomps) {
        const char *uid = icalcomponent_get_uid(comp);
        ptrarray_t *complist = icalcomps_by_uid(oldcomps, uid);
        if (complist) {
            int i;
            for (i = 0; i < ptrarray_size(complist); i++) {
                icalcomponent *tmp = ptrarray_nth(complist, i);
                icalproperty *orga = icalcomponent_get_first_property(tmp, ICAL_ORGANIZER_PROPERTY);
                icalproperty *attd = icalcomponent_get_first_property(tmp, ICAL_ATTENDEE_PROPERTY);
                allow_organizer_attendee_only = (orga == NULL) != (attd == NULL);

                if (!allow_organizer_attendee_only) {
                    /* Treat empty-valued caladdress properties as non-existent */
                    char *orgauri = normalized_uri(icalproperty_get_value_as_string(orga));
                    char *attduri = normalized_uri(icalproperty_get_value_as_string(attd));
                    allow_organizer_attendee_only = (orgauri == NULL) != (attduri == NULL);
                    free(orgauri);
                    free(attduri);
                }

                if (allow_organizer_attendee_only)
                    break;
            }
        }
    }

    json_t *jval = NULL;

    if (!allow_organizer_attendee_only) {
        /* If participants are set, replyTo must be set */
        if (JNOTNULL(replyTo) != JNOTNULL(participants)) {
            jmap_parser_invalid(parser, "replyTo");
            jmap_parser_invalid(parser, "participants");
            goto done;
        }
    }

    /* Parse replyTo */
    if (JNOTNULL(replyTo)) {
        jmap_parser_push(parser, "replyTo");
        const char *method;
        json_object_foreach(replyTo, method, jval) {
            if (!is_valid_rsvpmethod(method) || !json_is_string(jval)) {
                jmap_parser_invalid(parser, method);
                continue;
            }
        }
        jmap_parser_pop(parser);
    }

    /* Map participant ids to their iCalendar CALADDRESS */
    const char *partid;
    json_object_foreach(participants, partid, jval) {
        if (!is_valid_jmapid(partid)) continue;
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
        if (!caladdress) continue; /* reported later as error */
        hash_insert(partid, caladdress, &caladdress_by_participant_id);
    }

    const char *orga_method = NULL;
    const char *orga_uri = NULL;
    if (JNOTNULL(replyTo)) {
        /* Pick the ORGANIZER URI */
        if (json_object_get(replyTo, "imip")) {
            orga_method = "imip";
        }
        else if (json_object_get(replyTo, "other")) {
            orga_method = "other";
        }
        else {
            orga_method = json_object_iter_key(json_object_iter(replyTo));
        }
        orga_uri = json_string_value(json_object_get(replyTo, orga_method));

        /* Create the ORGANIZER property */
        icalproperty *orga = icalproperty_new_organizer(orga_uri);
        /* Keep track of the RSVP URIs and their method */
        if (json_object_size(replyTo) > 1 || (strcmp(orga_method, "imip") && strcmp(orga_method, "other"))) {
            struct buf buf = BUF_INITIALIZER;
            const char *method;
            json_object_foreach(replyTo, method, jval) {
                buf_setcstr(&buf, method);
                buf_putc(&buf, ':');
                buf_appendcstr(&buf, json_string_value(jval));
                icalproperty_set_xparam(orga, JMAPICAL_XPARAM_RSVP_URI, buf_cstring(&buf), 0);
            }
            buf_free(&buf);
        }
        icalcomponent_add_property(comp, orga);
    }

    /* Process participants */
    jmap_parser_push(parser, "participants");
    json_object_foreach(participants, partid, jval) {
        jmap_parser_push(parser, partid);
        if (!is_valid_jmapid(partid)) {
            jmap_parser_invalid(parser, NULL);
            jmap_parser_pop(parser);
            continue;
        }

        validate_type(parser, jval, "Participant");

        const char *caladdress = hash_lookup(partid, &caladdress_by_participant_id);
        if (!caladdress) {
            jmap_parser_invalid(parser, "sendTo");
            jmap_parser_pop(parser);
            continue;
        }

        /* Lookup former ATTENDEE, if any. */
        icalproperty *oldattendee = hash_lookup(partid, &oldattendees_by_jmapid);
        if (!oldattendee) {
            oldattendee = hash_lookup(caladdress, &oldattendees_by_caladdress);
        }

        /* Map participant to iCalendar */
        participant_to_ical(comp, oldattendee, parser, partid, jval,
                            participants, orga_uri,
                            &caladdress_by_participant_id,
                            allow_organizer_attendee_only,
                            jmapctx);
        jmap_parser_pop(parser);
    }
    jmap_parser_pop(parser);

done:
    free_hash_table(&caladdress_by_participant_id, free);
    free_hash_table(&oldattendees_by_jmapid, NULL);
    free_hash_table(&oldattendees_by_caladdress, NULL);
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
        /* We'd like to support HTML descriptions, but with iCalendar being
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

    if (desc && *desc) icalcomponent_set_description(comp, desc);
}

HIDDEN icalcomponent *jmapical_alert_to_ical(json_t *alert,
                                             struct jmap_parser *parser,
                                             const char *alert_uid,
                                             const char *summary,
                                             const char *description,
                                             const char *email_recipient)
{
    icalcomponent *alarm = icalcomponent_new_valarm();
    icalproperty *prop;
    icalparameter *param;
    icaltimezone *utc = icaltimezone_get_utc_timezone();
    size_t invalid_prop_count = json_array_size(parser->invalid);

    validate_type(parser, alert, "Alert");
    if (alert_uid) icalcomponent_set_uid(alarm, alert_uid);

    /* trigger */
    struct icaltriggertype trigger = {
        icaltime_null_time(), icaldurationtype_null_duration()
    };
    json_t *jtrigger = json_object_get(alert, "trigger");
    if (json_is_object(jtrigger)) {
        const char *triggertype = json_string_value(json_object_get(jtrigger, "@type"));
        if (!strcmpsafe(triggertype, "OffsetTrigger")) {
            jmap_parser_push(parser, "trigger");

            /* offset */
            struct jmapical_duration offset = JMAPICAL_DURATION_INITIALIZER;
            json_t *joffset = json_object_get(jtrigger, "offset");
            if (json_is_string(joffset)) {
                if (jmapical_duration_from_string(json_string_value(joffset), &offset) < 0) {
                    jmap_parser_invalid(parser, "offset");
                }
            } else {
                jmap_parser_invalid(parser, "offset");
            }

            /* relativeTo */
            icalparameter_related rel = ICAL_RELATED_START;
            json_t *jrelativeTo = json_object_get(jtrigger, "relativeTo");
            if (json_is_string(jrelativeTo)) {
                const char *val = json_string_value(jrelativeTo);
                if (!strcmp(val, "start")) {
                    rel = ICAL_RELATED_START;
                } else if (!strcmp(val, "end")) {
                    rel = ICAL_RELATED_END;
                } else {
                    jmap_parser_invalid(parser, "relativeTo");
                }
            } else if (JNOTNULL(jrelativeTo)) {
                jmap_parser_invalid(parser, "relativeTo");
            }

            jmap_parser_pop(parser);

            /* Add offset trigger */
            trigger.duration = jmapical_duration_to_icalduration(&offset);
            prop = icalproperty_new_trigger(trigger);
            param = icalparameter_new_related(rel);
            icalproperty_add_parameter(prop, param);
            icalcomponent_add_property(alarm, prop);
        }
        else if (!strcmpsafe(triggertype, "AbsoluteTrigger")) {
            jmap_parser_push(parser, "trigger");

            json_t *jwhen = json_object_get(jtrigger, "when");
            struct jmapical_datetime when = JMAPICAL_DATETIME_INITIALIZER;
            if (json_is_string(jwhen) &&
                    jmapical_utcdatetime_from_string(json_string_value(jwhen), &when) >= 0) {

                /* Add absolute trigger */
                trigger.time = jmapical_datetime_to_icaltime(&when, utc);
                prop = icalproperty_new_trigger(trigger);
                icalcomponent_add_property(alarm, prop);
            }
            else jmap_parser_invalid(parser, "when");

            jmap_parser_pop(parser);
        }
        else {
            /* XXX should preserve unknown triggers */
        }
    }
    else jmap_parser_invalid(parser, "trigger");

    /* acknowledged */
    json_t *jacknowledged = json_object_get(alert, "acknowledged");
    if (json_is_string(jacknowledged)) {
        struct jmapical_datetime acktime = JMAPICAL_DATETIME_INITIALIZER;
        if (jmapical_utcdatetime_from_string(json_string_value(jacknowledged), &acktime) >= 0) {
            prop = icalproperty_new_acknowledged(jmapical_datetime_to_icaltime(&acktime, utc));
            icalcomponent_add_property(alarm, prop);
        } else {
            jmap_parser_invalid(parser, "acknowledged");
        }
    } else if (JNOTNULL(jacknowledged)) {
        jmap_parser_invalid(parser, "acknowledged");
    }

    /* action */
    icalproperty_action action = ICAL_ACTION_DISPLAY;
    json_t *jaction = json_object_get(alert, "action");
    if (json_is_string(jaction)) {
        const char *val = json_string_value(jaction);
        if (!strcmp(val, "email")) {
            action = ICAL_ACTION_EMAIL;
        } else if (!strcmp(val, "display")) {
            action = ICAL_ACTION_DISPLAY;
        } else {
            jmap_parser_invalid(parser, "action");
        }
    } else if (JNOTNULL(jaction)) {
        jmap_parser_invalid(parser, "action");
    }
    prop = icalproperty_new_action(action);
    icalcomponent_add_property(alarm, prop);

    /* relatedTo */
    json_t *jrelatedto = json_object_get(alert, "relatedTo");
    if (json_is_object(jrelatedto)) {
        relatedto_to_ical(alarm, parser, jrelatedto);
    }
    else if (JNOTNULL(jrelatedto)) {
        jmap_parser_invalid(parser, "relatedTo");
    }

    if (action == ICAL_ACTION_EMAIL) {
        /* ATTENDEE */
        icalcomponent_add_property(alarm, icalproperty_new_attendee(email_recipient));

        /* SUMMARY */
        if (summary && *summary != '\0') {
            icalcomponent_add_property(alarm, icalproperty_new_summary(summary));
        }
        else {
            prop = icalproperty_new_summary("Reminder");
            icalproperty_set_xparam(prop, JMAPICAL_XPARAM_ISDEFAULT, "TRUE", 0);
            icalcomponent_add_property(alarm, prop);
        }
    }

    /* DESCRIPTION is required for both email and display */
    const char *desc = summary;
    if (!desc || *desc == '\0') desc = description;
    if (!desc || *desc == '\0') {
        prop = icalproperty_new_description("Reminder");
        icalproperty_set_xparam(prop, JMAPICAL_XPARAM_ISDEFAULT, "TRUE", 0);
        icalcomponent_add_property(alarm, prop);
    }
    else {
        icalcomponent_add_property(alarm, icalproperty_new_description(desc));
    }

    if (invalid_prop_count < json_array_size(parser->invalid)) {
        icalcomponent_free(alarm);
        alarm = NULL;
    }

    return alarm;
}

/* Create or update the VALARMs in the VEVENT component comp as defined by the
 * JMAP alerts. */
static void
alerts_to_ical(icalcomponent *comp, struct jmap_parser *parser, json_t *alerts,
               struct jmapical_jmapcontext *jmapctx)
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
        if (!is_valid_jmapid(id)) {
            jmap_parser_invalid(parser, id);
            continue;
        }
        jmap_parser_push(parser, id);

        alarm = jmapical_alert_to_ical(alert, parser, id,
                icalcomponent_get_summary(comp),
                icalcomponent_get_description(comp),
                jmapctx->emailalert_defaultrecipient);

        if (alarm) icalcomponent_add_component(comp, alarm);
        jmap_parser_pop(parser);
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
recurrencerule_to_ical(icalcomponent *comp, struct jmap_parser *parser,
                       icalproperty_kind kind, json_t *rrule,
                       jstimezones_t *jstzones)
{
    struct buf buf = BUF_INITIALIZER;

    validate_type(parser, rrule, "RecurrenceRule");

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
        /* Only include RSCALE/SKIP when required to not break legacy clients */
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

        buf_appendcstr(&buf, ";BYDAY=");
        json_array_foreach(byday, i, bd) {
            char *day = NULL;
            json_int_t nth = 0;
            jmap_parser_push_index(parser, "byDay", i, NULL);

            validate_type(parser, bd, "NDay");

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
    if (json_is_string(jprop)) {
        struct jmapical_datetime until = JMAPICAL_DATETIME_INITIALIZER;
        if (jmapical_localdatetime_from_string(json_string_value(jprop), &until) >= 0) {
            int is_date = icalcomponent_get_dtstart(comp).is_date;
            const char *tzidstart = tzid_from_ical(comp, ICAL_DTSTART_PROPERTY, jstzones);
            icaltimezone *tzstart = jstimezones_lookup_tzid(jstzones, tzidstart);
            icaltimetype untilutc;
            if (is_date) {
                untilutc = jmapical_datetime_to_icaldate(&until);
            }
            else {
                icaltimetype untillocal = jmapical_datetime_to_icaltime(&until, tzstart);
                icaltimezone *utc = icaltimezone_get_utc_timezone();
                untilutc = icaltime_convert_to_zone(untillocal, utc);
            }
            buf_printf(&buf, ";UNTIL=%s", icaltime_as_ical_string(untilutc));
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
            icalproperty *prop = NULL;
            if (kind == ICAL_RRULE_PROPERTY) {
                prop = icalproperty_new_rrule(rt);
            }
            else if (kind == ICAL_EXRULE_PROPERTY) {
                prop = icalproperty_new_exrule(rt);
            }
            if (prop) icalcomponent_add_property(comp, prop);
        } else {
            syslog(LOG_ERR, "jmap_ical: generated bogus RRULE: %s", buf_cstring(&buf));
            jmap_parser_invalid(parser, NULL);
        }
        // XXX this should go to libical
        if (rt.rscale) {
            free(rt.rscale);
            rt.rscale = NULL;
        }
        icalrecurrencetype_clear(&rt);
    }

    buf_free(&buf);
}

/* Create or overwrite the RRULE in the VEVENT component comp as defined by the
 * JMAP recurrence. */
static void
recurrencerules_to_ical(icalcomponent *comp, struct jmap_parser *parser,
                        icalproperty_kind kind, json_t *rrules,
                        jstimezones_t *jstzones)
{
    /* Purge existing RRULE. */
    icalproperty *prop, *next;
    for (prop = icalcomponent_get_first_property(comp, kind);
         prop;
         prop = next) {
        next = icalcomponent_get_next_property(comp, kind);
        icalcomponent_remove_property(comp, prop);
        icalproperty_free(prop);
    }
    if (!JNOTNULL(rrules) || !json_array_size(rrules)) {
        return;
    }

    jmap_parser_push(parser, "recurrenceRules");

    size_t i;
    json_t *rrule;
    json_array_foreach(rrules, i, rrule) {
        jmap_parser_push_index(parser, NULL, i, NULL);
        recurrencerule_to_ical(comp, parser, kind, rrule, jstzones);
        jmap_parser_pop(parser);
    }

    jmap_parser_pop(parser);
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
        // known bug: libical doesn't properly
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

        validate_type(parser, relationObj, "Relation");

        /* relation */
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
        else if (json_is_object(relation) || relation == NULL || relation == json_null()) {
            icalcomponent_add_property(comp, icalproperty_new_relatedto(uid));
        }
        else if (!json_is_object(relation)) {
            jmap_parser_invalid(parser, "relation");
        }

        jmap_parser_pop(parser);
    }
    jmap_parser_pop(parser);
}

static int
validate_location(json_t *loc, struct jmap_parser *parser, json_t *links,
                  jstimezones_t *jstzones)
{
    size_t invalid_cnt = json_array_size(parser->invalid);
    json_t *jprop = NULL;
    json_t *jtype = json_object_get(links, "@type");

    validate_type(parser, loc, "Location");

    /* At least one property other than rel MUST be set */
    if ((json_object_size(loc) == 0) ||
        (json_object_size(loc) == 1 && !JNOTNULL(jtype) &&
         json_object_get(loc, "relativeTo")) ||
        (json_object_size(loc) == 2 && JNOTNULL(jtype) &&
         json_object_get(loc, "relativeTo"))) {
        jmap_parser_invalid(parser, NULL);
        return 0;
    }

    jprop = json_object_get(loc, "name");
    if (JNOTNULL(jprop) && !json_is_string(jprop))
        jmap_parser_invalid(parser, "name");

    jprop = json_object_get(loc, "description");
    if (JNOTNULL(jprop) && !json_is_string(jprop))
        jmap_parser_invalid(parser, "description");

    jprop = json_object_get(loc, "relativeTo");
    if (JNOTNULL(jprop) && !json_is_string(jprop))
        jmap_parser_invalid(parser, "relativeTo");

    jprop = json_object_get(loc, "coordinates");
    if (JNOTNULL(jprop) && !json_is_string(jprop))
        jmap_parser_invalid(parser, "coordinates");

    jprop = json_object_get(loc, "timeZone");
    if (json_is_string(jprop)) {
        const char *jstzid = json_string_value(jprop);
        if (!jstimezones_lookup_jstzid(jstzones, jstzid)) {
            jmap_parser_invalid(parser, "timeZone");
        }
    }
    else if (JNOTNULL(jprop)) {
        jmap_parser_invalid(parser, "timeZone");
    }

    /* locationTypes */
    json_t *loctypes = json_object_get(loc, "locationTypes");
    if (json_object_size(loctypes)) {
        jmap_parser_push(parser, "locationTypes");
        const char *loctype;
        json_t *jval;
        json_object_foreach(loctypes, loctype, jval) {
            const char *p;
            for (p = loctype; isalpha(*p) || *p == '-'; p++) {}
            if (jval != json_true() || *p || p == loctype) {
                jmap_parser_invalid(parser, loctype);
            }
        }
        jmap_parser_pop(parser);
    }
    else if (JNOTNULL(loctypes)) {
        jmap_parser_invalid(parser, "locationTypes");
    }

    /* linkIds */
    json_t *linkids = json_object_get(loc, "linkIds");
    if (JNOTNULL(linkids) && json_is_object(linkids)) {
        const char *linkid;
        json_t *jval;
        jmap_parser_push(parser, "linkIds");
        json_object_foreach(linkids, linkid, jval) {
            if (!is_valid_jmapid(linkid) || !json_object_get(links, linkid) ||
                    jval != json_true()) {
                jmap_parser_invalid(parser, linkid);
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
location_to_ical(icalcomponent *comp, struct jmap_parser *parser,
                 const char *parentprop, const char *id,
                 json_t *loc,
                 struct jmapical_jmapcontext *jmapctx)
{
    const char *name = json_string_value(json_object_get(loc, "name"));
    if (name && !*name) name = NULL;
    const char *rel = json_string_value(json_object_get(loc, "relativeTo"));
    if (rel && !*rel) rel = NULL;

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
    icalproperty_set_value(prop, val); // XXX doesn't support empty string
    if (rel) icalproperty_set_xparam(prop, JMAPICAL_XPARAM_REL, rel, 0);

    /* description, timeZone, coordinates */
    const char *s = json_string_value(json_object_get(loc, "description"));
    if (s && *s) icalproperty_set_xparam(prop, JMAPICAL_XPARAM_DESCRIPTION, s, 0);
    s = json_string_value(json_object_get(loc, "timeZone"));
    if (s) {
        if (*s == '/') s++;
        icalproperty_set_xparam(prop, JMAPICAL_XPARAM_TZID, s, 0); 
    }
    s = json_string_value(json_object_get(loc, "coordinates"));
    if (s && *s) icalproperty_set_xparam(prop, JMAPICAL_XPARAM_GEO, s, 0);

    /* locationTypes */
    json_t *loctypes = json_object_get(loc, "locationTypes");
    if (json_is_object(loctypes)) {
        const char *loctype;
        json_t *jval;
        json_object_foreach(loctypes, loctype, jval) {
            icalproperty_set_xparam(prop, JMAPICAL_XPARAM_LOCATIONTYPE, loctype, 0);
        }
    }

    /* links */
    json_t *links = json_object_get(loc, "links");
    if (JNOTNULL(links)) {
        jmap_parser_push(parser, "links");
        links_to_ical(comp, NULL, parser, links, parentprop, id, jmapctx);
        jmap_parser_pop(parser);
    }

    icalcomponent_add_property(comp, prop);
}

/* Create or overwrite the JMAP locations in comp */
static void
locations_to_ical(icalcomponent *comp, struct jmap_parser *parser,
                  json_t *locations, json_t *links,
                  jstimezones_t *jstzones,
                  struct jmapical_jmapcontext *jmapctx)
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
        jmap_parser_push(parser, id);
        /* Validate and add location */
        if (validate_location(loc, parser, links, jstzones)) {
            location_to_ical(comp, parser, "locations", id, loc, jmapctx);
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

        validate_type(parser, loc, "VirtualLocation");

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
        if (json_is_string(jname)) {
            const char *name = json_string_value(jname);
            if (*name) {
                icalproperty_add_parameter(prop, icalparameter_new_label(name));
            }
        }
        else if (JNOTNULL(jname)) {
            jmap_parser_invalid(parser, "name");
        }

        /* description */
        json_t *jdescription = json_object_get(loc, "description");
        if (json_is_string(jdescription)) {
            const char *desc = json_string_value(jdescription);
            if (desc && *desc) {
                icalproperty_set_xparam(prop, JMAPICAL_XPARAM_DESCRIPTION, desc, 0);
            }
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

static int parse_tzoffset(const char *str, int *offsetp)
{
    /* sign */
    int sign = *str == '+' ? 1 : *str == '-' ? -1 : 0;
    int offset = 0;
    if (!sign) return -1;
    str++;

    /* time-hour */
    if (isdigit(str[0]) && isdigit(str[1])) {
        int val = (str[0] - '0') * 10 + (str[1] - '0');
        if (val > 23) return -1;
        offset += val * 60 * 60;
    }
    else return -1;
    str += 2;

    /* time-minute */
    if (isdigit(str[0]) && isdigit(str[1])) {
        int val = (str[0] - '0') * 10 + (str[1] - '0');
        if (val > 59) return -1;
        offset += val * 60;
    }
    else return -1;
    str += 2;

    if (*str) {
        /* time-second */
        if (isdigit(str[0]) && isdigit(str[1])) {
            int val = (str[0] - '0') * 10 + (str[1] - '0');
            if (val > 60) return -1;
            offset += val;
        }
        else return -1;
        str += 2;
    }

    if (*str) return -1;

    *offsetp = offset * sign;
    return 0;
}

static void timezonerule_to_ical(icalcomponent *tzrule, struct jmap_parser *parser,
                                 json_t *jtzrule)
{
    validate_type(parser, jtzrule, "TimeZoneRule");

    json_t *jprop = json_object_get(jtzrule, "start");
    if (json_is_string(jprop)) {
        struct jmapical_datetime dt = JMAPICAL_DATETIME_INITIALIZER;
        if (jmapical_localdatetime_from_string(json_string_value(jprop), &dt) >= 0) {
                icaltimetype icaldt = jmapical_datetime_to_icaltime(&dt, NULL);
                icalcomponent_add_property(tzrule,
                        icalproperty_new_dtstart(icaldt));
        }
        else jmap_parser_invalid(parser, "start");
    }
    else jmap_parser_invalid(parser, "start");

    jprop = json_object_get(jtzrule, "offsetFrom");
    if (json_is_string(jprop)) {
        int offset;
        if (parse_tzoffset(json_string_value(jprop), &offset) >= 0) {
            icalcomponent_add_property(tzrule,
                    icalproperty_new_tzoffsetfrom(offset));
        }
        else jmap_parser_invalid(parser, "offsetFrom");
    }
    else jmap_parser_invalid(parser, "offsetFrom");

    jprop = json_object_get(jtzrule, "offsetTo");
    if (json_is_string(jprop)) {
        int offset;
        if (parse_tzoffset(json_string_value(jprop), &offset) >= 0) {
            icalcomponent_add_property(tzrule,
                    icalproperty_new_tzoffsetto(offset));
        }
        else jmap_parser_invalid(parser, "offsetTo");
    }
    else jmap_parser_invalid(parser, "offsetTo");

    jprop = json_object_get(jtzrule, "recurrenceRules");
    if (json_is_array(jprop)) {
        size_t i;
        json_t *jval;
        json_array_foreach(jprop, i, jval) {
            jmap_parser_push_index(parser, "recurrenceRules", i, NULL);
            recurrencerule_to_ical(tzrule, parser, ICAL_RRULE_PROPERTY, jval, NULL);
            jmap_parser_pop(parser);
        }
    }
    else if (JNOTNULL(jprop)) {
        jmap_parser_invalid(parser, "recurrenceRules");
    }

    jprop = json_object_get(jtzrule, "recurrenceOverrides");
    if (json_is_object(jprop)) {
        jmap_parser_push(parser, "recurrenceoverrides");
        const char *recurid;
        json_t *jval;
        json_object_foreach(jprop, recurid, jval) {
            struct jmapical_datetime dt = JMAPICAL_DATETIME_INITIALIZER;
            if ((jmapical_localdatetime_from_string(json_string_value(jprop), &dt) >= 0) &&
                    json_is_object(jval) && !json_object_size(jval)) {

                struct icaldatetimeperiodtype val = {
                    jmapical_datetime_to_icaltime(&dt, NULL),
                    icalperiodtype_null_period()
                };
                icalcomponent_add_property(tzrule, icalproperty_new_rdate(val));
            }
            else jmap_parser_invalid(parser, recurid);
        }
        jmap_parser_pop(parser);
    }
    else if (JNOTNULL(jprop)) {
        jmap_parser_invalid(parser, "recurrenceOverrides");
    }

    jprop = json_object_get(jtzrule, "names");
    if (json_is_object(jprop)) {
        jmap_parser_push(parser, "names");
        const char *name;
        json_t *jval;
        json_object_foreach(jprop, name, jval) {
            if (jval == json_true()) {
                icalcomponent_add_property(tzrule, icalproperty_new_tzname(name));
            }
            else jmap_parser_invalid(parser, name);
        }
        jmap_parser_pop(parser);
    }
    else if (JNOTNULL(jprop)) {
        jmap_parser_invalid(parser, "names");
    }

    jprop = json_object_get(jtzrule, "comments");
    if (json_is_array(jprop)) {
        size_t i;
        json_t *jval;
        json_array_foreach(jprop, i, jval) {
            if (json_is_string(jval)) {
                icalcomponent_add_property(tzrule,
                        icalproperty_new_comment(json_string_value(jval)));
            }
            else {
                jmap_parser_push_index(parser, "comments", i, NULL);
                jmap_parser_invalid(parser, NULL);
                jmap_parser_pop(parser);
            }
        }
    }
    else if (JNOTNULL(jprop)) {
        jmap_parser_invalid(parser, "comments");
    }
}

static void timezones_to_ical(icalcomponent *ical,
                              struct jmap_parser *parser,
                              json_t *jevent,
                              json_t *jtimezones)
{
    icaltimezone *utc = icaltimezone_get_utc_timezone();

    jmap_parser_push(parser, "timeZones");

    /* Check for orphaned timezones */
    strarray_t custom_jstzids = STRARRAY_INITIALIZER;
    read_custom_jstzids(jevent, &custom_jstzids);

    json_t *jtimezone;
    const char *jstzid;
    json_object_foreach(jtimezones, jstzid, jtimezone) {

        jmap_parser_push(parser, jstzid);

        size_t invalid_count = json_array_size(parser->invalid);

        icalcomponent *tzcomp = icalcomponent_new_vtimezone();

        validate_type(parser, jtimezone, "TimeZone");

        const char *tzid = json_string_value(json_object_get(jtimezone, "tzId"));
        /* Don't allow IANA and Windows timezone ids */
        if (icaltimezone_get_cyrus_timezone_from_tzid(tzid)) {
            jmap_parser_invalid(parser, "tzId");
        }
        else if (tzid) {
            icalcomponent_add_property(tzcomp, icalproperty_new_tzid(tzid));
        }
        else jmap_parser_invalid(parser, "tzId");

        icalproperty *prop = icalproperty_new_x(jstzid);
        icalproperty_set_x_name(prop, JMAPICAL_XPROP_ID);
        icalcomponent_add_property(tzcomp, prop);

        json_t *jprop = json_object_get(jtimezone, "updated");
        if (json_is_string(jprop)) {
            struct jmapical_datetime dt = JMAPICAL_DATETIME_INITIALIZER;
            if (jmapical_utcdatetime_from_string(json_string_value(jprop), &dt) >= 0) {
                icaltimetype icaldt = jmapical_datetime_to_icaltime(&dt, utc);
                icalcomponent_add_property(tzcomp,
                        icalproperty_new_lastmodified(icaldt));
            }
            else jmap_parser_invalid(parser, "updated");
        }
        else if (JNOTNULL(jprop)) {
            jmap_parser_invalid(parser, "url");
        }

        jprop = json_object_get(jtimezone, "url");
        if (json_is_string(jprop)) {
            icalcomponent_add_property(tzcomp,
                    icalproperty_new_tzurl(json_string_value(jprop)));
        }
        else if (JNOTNULL(jprop)) {
            jmap_parser_invalid(parser, "url");
        }

        jprop = json_object_get(jtimezone, "validUntil");
        if (json_is_string(jprop)) {
            struct jmapical_datetime dt = JMAPICAL_DATETIME_INITIALIZER;
            if (jmapical_utcdatetime_from_string(json_string_value(jprop), &dt) >= 0) {
                icaltimetype icaldt = jmapical_datetime_to_icaltime(&dt, utc);
                icalcomponent_add_property(tzcomp,
                        icalproperty_new_tzuntil(icaldt));
            }
            else jmap_parser_invalid(parser, "validUntil");
        }
        else if (JNOTNULL(jprop)) {
            jmap_parser_invalid(parser, "validUntil");
        }


        jprop = json_object_get(jtimezone, "aliases");
        if (json_is_object(jprop)) {
            jmap_parser_push(parser, "aliases");
            const char *alias;
            json_t *jval;
            json_object_foreach(jprop, alias, jval) {
                if (jval == json_true()) {
                    icalcomponent_add_property(tzcomp,
                            icalproperty_new_tzidaliasof(alias));
                }
                else jmap_parser_invalid(parser, alias);
            }
            jmap_parser_pop(parser);
        }
        else if (JNOTNULL(jprop)) {
            jmap_parser_invalid(parser, "aliases");
        }

        jprop = json_object_get(jtimezone, "standard");
        if (json_is_array(jprop)) {
            size_t i;
            json_t *jval;
            json_array_foreach(jprop, i, jval) {
                jmap_parser_push_index(parser, "standard", i, NULL);
                icalcomponent *tzrule = icalcomponent_new_xstandard();
                timezonerule_to_ical(tzrule, parser, jval);
                icalcomponent_add_component(tzcomp, tzrule);
                jmap_parser_pop(parser);
            }
        }
        else if (JNOTNULL(jprop)) {
            jmap_parser_invalid(parser, "standard");
        }

        jprop = json_object_get(jtimezone, "daylight");
        if (json_is_array(jprop)) {
            size_t i;
            json_t *jval;
            json_array_foreach(jprop, i, jval) {
                jmap_parser_push_index(parser, "daylight", i, NULL);
                icalcomponent *tzrule = icalcomponent_new_xdaylight();
                timezonerule_to_ical(tzrule, parser, jval);
                icalcomponent_add_component(tzcomp, tzrule);
                jmap_parser_pop(parser);
            }
        }
        else if (JNOTNULL(jprop)) {
            jmap_parser_invalid(parser, "daylight");
        }

        if (invalid_count == json_array_size(parser->invalid)) {
            if (strarray_find(&custom_jstzids, jstzid, 0) < 0) {
                jmap_parser_invalid(parser, NULL);
            }
        }

        jmap_parser_pop(parser);

        icalcomponent_add_component(ical, tzcomp);
    }

    strarray_fini(&custom_jstzids);

    jmap_parser_pop(parser);
}

static void overrides_to_ical(icalcomponent *comp,
                              struct jmap_parser *parser,
                              json_t *overrides,
                              struct icalcomps *oldcomps,
                              jstimezones_t *jstzones,
                              struct jmapical_jmapcontext *jmapctx)
{
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
    const char *tzidstart = tzid_from_ical(comp, ICAL_DTSTART_PROPERTY, jstzones);
    icaltimezone *tzstart = jstimezones_lookup_tzid(jstzones, tzidstart);

    /* Convert current master event to JMAP */
    json_t *master = calendarevent_from_ical(comp, NULL, 0, NULL, jstzones, jmapctx);
    if (!master) return;
    json_object_del(master, "recurrenceRules");
    json_object_del(master, "recurrenceOverrides");
    json_object_del(master, "excludedRecurrenceRules");

    jmap_parser_push(parser, "recurrenceOverrides");
    json_t *joverride;
    const char *recuridval;
    json_object_foreach(overrides, recuridval, joverride) {
        struct jmapical_datetime recurid = JMAPICAL_DATETIME_INITIALIZER;

        if (jmapical_localdatetime_from_string(recuridval, &recurid) < 0) {
            jmap_parser_invalid(parser, recuridval);
            continue;
        }
        else if (is_date && !jmapical_datetime_has_zero_time(&recurid)) {
            jmap_parser_invalid(parser, recuridval);
            continue;
        }

        json_t *excluded = json_object_get(joverride, "excluded");
        if (excluded == json_true()) {
            if (json_object_size(joverride) == 1) {
                /* Add EXDATE */
                struct icaltimetype exdate = is_date ?
                    jmapical_datetime_to_icaldate(&recurid) :
                    jmapical_datetime_to_icaltime(&recurid, tzstart);
                insert_icaltimeprop(comp, exdate, 0, ICAL_EXDATE_PROPERTY);
            }
            else {
                /* excluded overrides MUST NOT define any other property */
                jmap_parser_invalid(parser, recuridval);
            }
        } else if (!json_object_size(joverride)) {
            /* Add RDATE */
            struct icaltimetype rdate = is_date ?
                jmapical_datetime_to_icaldate(&recurid) :
                jmapical_datetime_to_icaltime(&recurid, tzstart);
            insert_icaltimeprop(comp, rdate, 0, ICAL_RDATE_PROPERTY);
        } else {
            /* Add VEVENT exception */
            json_t *myoverride = json_copy(joverride); // shallow copy

            /* JMAP spec: "A pointer MUST NOT start with one of the following
             * prefixes; any patch with a such a key MUST be ignored" */
            const char *key;
            json_t *jval;
            json_object_foreach(joverride, key, jval) {
                if (!strcmp(key, "@type") ||
                    !strcmp(key, "uid") ||
                    !strcmp(key, "relatedTo") ||
                    !strcmp(key, "prodId") ||
                    !strcmp(key, "method") ||
                    !strcmp(key, "recurrenceId") ||
                    !strcmp(key, "recurrenceRules") ||
                    !strcmp(key, "recurrenceOverrides") ||
                    !strcmp(key, "excludedRecurrenceRules") ||
                    !strcmp(key, "excluded") ||
                    !strcmp(key, "replyTo")) {

                    json_object_del(myoverride, key);
                }
            }
            if (!json_object_size(myoverride)) {
                json_decref(myoverride);
                continue;
            }

            /* If the override doesn't have a custom start date, use
             * the LocalDate in the recurrenceOverrides object key */
            if (!json_object_get(myoverride, "start")) {
                json_object_set_new(myoverride, "start", json_string(recuridval));
            }

            /* Create overridden event from patch and master event */
            json_t *ex;
            if (!(ex = jmap_patchobject_apply(master, myoverride, NULL))) {
                jmap_parser_invalid(parser, recuridval);
                json_decref(myoverride);
                continue;
            }

            /* Create a new VEVENT for this override */
            excomp = icalcomponent_new_vevent();
            struct icaltimetype icalrecurid = is_date ?
                jmapical_datetime_to_icaldate(&recurid) :
                jmapical_datetime_to_icaltime(&recurid, tzstart);
            insert_icaltimeprop(excomp, icalrecurid, 1, ICAL_RECURRENCEID_PROPERTY);
            icalcomponent_set_uid(excomp, icalcomponent_get_uid(comp));

            /* Convert the override event to iCalendar */
            jmap_parser_push(parser, recuridval);
            /* recurrenceId */
            json_t *jrecurrenceId = json_object_get(myoverride, "recurrenceId");
            if (json_is_string(jrecurrenceId)) {
                const char *val = json_string_value(jrecurrenceId);
                struct jmapical_datetime dt = JMAPICAL_DATETIME_INITIALIZER;
                if (jmapical_localdatetime_from_string(val, &dt) < 0 ||
                    jmapical_datetime_compare(&dt, &recurid) != 0) {
                    jmap_parser_invalid(parser, "recurrenceId");
                }
            }
            else if (jrecurrenceId) {
                jmap_parser_invalid(parser, "recurrenceId");
            }
            calendarevent_to_ical(excomp, parser, ex, oldcomps, jstzones, jmapctx);
            jmap_parser_pop(parser);

            /* Add the exception */
            icalcomponent_add_component(ical, excomp);
            json_decref(ex);
            json_decref(myoverride);
        }
    }
    jmap_parser_pop(parser);

    json_decref(master);
}

/* Create or overwrite the iCalendar properties in VEVENT comp based on the
 * properties the JMAP calendar event. This writes a *complete* jsevent and
 * does not implement patch object semantics.
 */
static void calendarevent_to_ical(icalcomponent *comp,
                                  struct jmap_parser *parser,
                                  json_t *event,
                                  struct icalcomps *oldcomps,
                                  jstimezones_t *jstzones,
                                  struct jmapical_jmapcontext *jmapctx)
{
    icalproperty *prop = NULL;
    icaltimezone *utc = icaltimezone_get_utc_timezone();
    jstimezones_t myjstzones = JSTIMEZONES_INITIALIZER;

    /* Caller must set UID and RECURRENCEID in iCalendar */
    const char *uid = icalcomponent_get_uid(comp);
    if (!uid) {
        jmap_parser_invalid(parser, "uid");
        return;
    }
    int is_exc = icalcomponent_get_first_property(comp, ICAL_RECURRENCEID_PROPERTY) != NULL;

    json_t *jprop = json_object_get(event, "excluded");
    if (jprop && jprop != json_false()) {
        jmap_parser_invalid(parser, "excluded");
    }

    jprop = json_object_get(event, "@type");
    if (JNOTNULL(jprop) && json_is_string(jprop)) {
        if (strcmp(json_string_value(jprop), "JSEvent")) {
            jmap_parser_invalid(parser, "@type");
        }
    } else if (JNOTNULL(jprop)) {
        jmap_parser_invalid(parser, "@type");
    }

    /* timeZones */
    icalcomponent *ical = icalcomponent_get_parent(comp);
    jprop = json_object_get(event, "timeZones");
    if (json_is_object(jprop)) {
        timezones_to_ical(ical, parser, event, jprop);
    } else if (JNOTNULL(jprop)) {
        jmap_parser_invalid(parser, "timeZones");
    }
    if (!jstzones) {
        jstimezones_add_vtimezones(&myjstzones, ical);
        jstzones = &myjstzones;
    }

    /* start, duration, timeZone */
    startend_to_ical(comp, parser, event, jstzones);

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
        struct jmapical_datetime tstamp = JMAPICAL_DATETIME_INITIALIZER;
        if (jmapical_utcdatetime_from_string(json_string_value(jprop), &tstamp) >= 0) {
            icaltimetype dt = jmapical_datetime_to_icaltime(&tstamp, utc);
            insert_icaltimeprop(comp, dt, 1, ICAL_CREATED_PROPERTY);
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
        struct jmapical_datetime tstamp = JMAPICAL_DATETIME_INITIALIZER;
        if (jmapical_utcdatetime_from_string(json_string_value(jprop), &tstamp) >= 0) {
            icaltimetype dt = jmapical_datetime_to_icaltime(&tstamp, utc);
            insert_icaltimeprop(comp, dt, 1, ICAL_DTSTAMP_PROPERTY);
        }
        else {
            jmap_parser_invalid(parser, "updated");
        }
    } else if (jprop == NULL) {
        icaltimetype now = \
            icaltime_current_time_with_zone(icaltimezone_get_utc_timezone());
        insert_icaltimeprop(comp, now, 1, ICAL_DTSTAMP_PROPERTY);
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
        const char *summary = json_string_value(jprop);
        if (strlen(summary)) icalcomponent_set_summary(comp, summary);
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
        links_to_ical(comp, oldcomps, parser, jprop, NULL, NULL, jmapctx);
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
        locations_to_ical(comp, parser, jprop, links, jstzones, jmapctx);
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

    /* recurrenceRules */
    jprop = json_object_get(event, "recurrenceRules");
    if (json_is_null(jprop) || json_is_array(jprop)) {
        if (!is_exc) recurrencerules_to_ical(comp, parser,
                ICAL_RRULE_PROPERTY, jprop, jstzones);
    } else if (jprop) {
        jmap_parser_invalid(parser, "recurrenceRules");
    }

    /* excludedRecurrenceRules */
    jprop = json_object_get(event, "excludedRecurrenceRules");
    if (json_is_null(jprop) || json_is_array(jprop)) {
        if (!is_exc) recurrencerules_to_ical(comp, parser,
                ICAL_EXRULE_PROPERTY, jprop, jstzones);
    } else if (jprop) {
        jmap_parser_invalid(parser, "excludedRecurrenceRules");
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
    } else if (JNOTNULL(jprop)) {
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
    participants_to_ical(comp, parser, event, oldcomps, jmapctx);

    /* useDefaultAlerts */
    jprop = json_object_get(event, "useDefaultAlerts");
    if (json_is_boolean(jprop)) {
        remove_icalxprop(comp, "X-APPLE-DEFAULT-ALARM");
        if (json_boolean_value(jprop)) {
            prop = icalproperty_new(ICAL_X_PROPERTY);
            icalproperty_set_x_name(prop, "X-APPLE-DEFAULT-ALARM");
            icalproperty_set_value(prop, icalvalue_new_boolean(1));
            icalcomponent_add_property(comp, prop);
        }
    } else if (JNOTNULL(jprop)) {
        jmap_parser_invalid(parser, "useDefaultAlerts");
    }

    /* alerts */
    jprop = json_object_get(event, "alerts");
    if (json_is_null(jprop) || json_object_size(jprop)) {
        alerts_to_ical(comp, parser, jprop, jmapctx);
    } else if (jprop) {
        jmap_parser_invalid(parser, "alerts");
    }

    /* FIXME localizations */
    /* FIXME categories */

    /* recurrenceOverrides - must be last to apply patches */
    jprop = json_object_get(event, "recurrenceOverrides");
    if (json_is_null(jprop) || json_is_object(jprop)) {
        overrides_to_ical(comp, parser, jprop, oldcomps, jstzones, jmapctx);
    } else if (jprop) {
        jmap_parser_invalid(parser, "recurrenceOverrides");
    }

    if (jstzones == &myjstzones) jstimezones_fini(&myjstzones);
}

icalcomponent*
jmapical_toical(json_t *jsevent, icalcomponent *oldical, json_t *invalid,
                struct jmapical_jmapcontext *jmapctx)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    icalcomponent *ical = NULL;
    struct icalcomps oldcomps = ICALCOMPS_INITIALIZER;

    if (oldical) {
        // Keep track of previous VEVENT versions
        icalcomps_init(&oldcomps, oldical);
    }

    /* uid */
    const char *uid = json_string_value(json_object_get(jsevent, "uid"));
    if (uid) {
        /* Create a new VCALENDAR. */
        ical = icalcomponent_new_vcalendar();
        icalcomponent_add_property(ical, icalproperty_new_version("2.0"));
        icalcomponent_add_property(ical, icalproperty_new_calscale("GREGORIAN"));

        /* Create a new VEVENT. */
        icaltimezone *utc = icaltimezone_get_utc_timezone();
        struct icaltimetype now =
            icaltime_from_timet_with_zone(time(NULL), 0, utc);
        icalcomponent *comp = icalcomponent_new_vevent();
        icalcomponent_set_uid(comp, uid);
        icalcomponent_set_sequence(comp, 0);
        icalcomponent_set_dtstamp(comp, now);
        icalcomponent_add_property(comp, icalproperty_new_created(now));
        icalcomponent_add_component(ical, comp);

        /* Convert the JMAP calendar event to ical. */
        calendarevent_to_ical(comp, &parser, jsevent, &oldcomps, NULL, jmapctx);
        icalcomponent_add_required_timezones(ical);
    }
    else jmap_parser_invalid(&parser, "uid");

    /* Report any property errors. */
    if (json_array_size(parser.invalid)) {
        if (invalid) json_array_extend(invalid, parser.invalid);
        if (ical) icalcomponent_free(ical);
        ical = NULL;
    }

    icalcomps_fini(&oldcomps);
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

    jcal = jmapical_tojmap(ical, NULL, NULL);

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

    ical = jmapical_toical(obj, NULL, NULL, NULL);

    json_decref(obj);

    return ical;
}
