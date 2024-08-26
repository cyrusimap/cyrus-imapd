/* json_support.c -- Helper functions for jansson and JSON
 *
 * Copyright (c) 1994-2019 Carnegie Mellon University.  All rights reserved.
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
