/* json_support.h - Helper functions for jansson and JSON */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */


#ifndef JSON_SUPPORT_H
#define JSON_SUPPORT_H

#include <config.h>
#include <jansson.h>

#include "util.h"

#define JNOTNULL(item)          ((item) ? (json_is_null(item) == 0) : 0)
#define JNULL(item)             ((item) ? (json_is_null(item)) : 1)

/* jansson replacement functions for those missing in older versions */
/* ... none at present! */

/* utility functions not present in any libjansson */
EXPORTED int json_is_date(json_t *json);
EXPORTED int json_is_utcdate(json_t *json);

EXPORTED int json_array_find(json_t *array, const char *needle);

EXPORTED json_t *json_object_get_vanew(json_t *obj, const char *key,
                                       const char *fmt, ...);

#endif /* JSON_SUPPORT_H */
