/* json_support.c -- Helper functions for jansson and JSON */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */


#include <config.h>

#include <string.h>
#include <time.h>

#include "json_support.h"

static int parse_date(json_t *json, unsigned utc)
{
    const char *s = NULL;
    struct tm date;

    if (!json_is_string(json)) return 0;

    /* parse full-date and partial-time up to time-secfrac */
    s = strptime(json_string_value(json), "%Y-%m-%dT%H:%M:%S", &date);
    if (!s) return 0;

    /* parse time-secfrac */
    if (*s == '.') {
        while (Uisdigit(*(++s)));
    }

    if (utc) {
        /* time-offset MUST be "Z" */
        return (!strcmp(s, "Z"));
    }

    /* parse time-numoffset */
    if (*s == '-' || *s == '+') s++;
    s = strptime(s, "%H:%M", &date);

    return (s && *s == '\0');
}

int json_is_date(json_t *json)
{
    return parse_date(json, 0);
}

int json_is_utcdate(json_t *json)
{
    return parse_date(json, 1);
}

int json_array_find(json_t *array, const char *needle)
{
    size_t i;
    json_t *val;

    json_array_foreach(array, i, val) {
        if (!strcmp(needle, json_string_value(val))) return i;
    }

    return -1;
}

/* Get the property with the given key, if it exists.
   Otherwise, create is with the given json_pack() args */
json_t *json_object_get_vanew(json_t *obj, const char *key,
                              const char *fmt, ...)
{
    json_t *val = json_object_get(obj, key);

    if (!val) {
        json_error_t jerr;
        va_list va;

        va_start(va, fmt);
        val = json_vpack_ex(&jerr, 0, fmt, va);
        va_end(va);

        json_object_set_new(obj, key, val);
    }

    return val;
}
