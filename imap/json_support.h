/* json_support.h -- Helper functions for jansson and JSON
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


#ifndef JSON_SUPPORT_H
#define JSON_SUPPORT_H

#include <config.h>
#include <jansson.h>

#include "util.h"

#define JNOTNULL(item)          ((item) ? (json_is_null(item) == 0) : 0)
#define JNULL(item)             ((item) ? (json_is_null(item)) : 1)

/* jansson replacement functions for those missing in older versions */

#ifndef json_boolean
#define json_boolean(val)       ((val) ? json_true() : json_false())
#endif /* json_boolean */

#ifndef json_boolean_value
#define json_boolean_value(val) ((val) == json_true() ? 1 : 0)
#endif /* json_boolean_value */

#ifndef json_object_foreach
#define json_object_foreach(obj, key, val)                      \
     void *_iter_;                                              \
     for (_iter_ = json_object_iter(obj);                       \
          _iter_                                                \
              && (key = json_object_iter_key(_iter_))           \
              && (val = json_object_iter_value(_iter_));        \
          _iter_ = json_object_iter_next(obj, _iter_))
#endif /* json_object_foreach */

#ifndef json_object_foreach_safe
#define json_object_foreach_safe(object, n, key, value)     \
    for(key = json_object_iter_key(json_object_iter(object)), \
            n = json_object_iter_next(object, json_object_key_to_iter(key)); \
        key && (value = json_object_iter_value(json_object_key_to_iter(key))); \
        key = json_object_iter_key(n), \
n = json_object_iter_next(object, json_object_key_to_iter(key)))
#endif /* json_object_foreach_safe */

#ifndef json_array_foreach
#define json_array_foreach(array, index, value)                 \
    for (index = 0;                                             \
         index < json_array_size(array)                         \
             && (value = json_array_get(array, index));         \
         index++)
#endif /* json_array_foreach */

EXPORTED int json_is_date(json_t *json);
EXPORTED int json_is_utcdate(json_t *json);

EXPORTED int json_array_find(json_t *array, const char *needle);

EXPORTED const char *json_array_get_string(const json_t *array, size_t index);

#ifdef NEED_JANSSON_JSON_DUMPB
/* https://jansson.readthedocs.io/en/2.11/apiref.html#c.json_dumpb */
EXPORTED size_t json_dumpb(const json_t *json,
                           char *buffer, size_t size, size_t flags);
#endif

#endif /* JSON_SUPPORT_H */
