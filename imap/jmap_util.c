/* jmap_util.c -- Helper routines for JMAP
 *
 * Copyright (c) 1994-2018 Carnegie Mellon University.  All rights reserved.
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

#include "jmap_util.h"

EXPORTED int jmap_readprop_full(json_t *root, const char *prefix, const char *name,
                              int mandatory, json_t *invalid, const char *fmt,
                              void *dst)
{
    int r = 0;
    json_t *jval = json_object_get(root, name);
    if (!jval && mandatory) {
        r = -1;
    } else if (jval) {
        json_error_t err;
        if (json_unpack_ex(jval, &err, 0, fmt, dst)) {
            r = -2;
        } else {
            r = 1;
        }
    }
    if (r < 0 && prefix) {
        struct buf buf = BUF_INITIALIZER;
        buf_printf(&buf, "%s.%s", prefix, name);
        json_array_append_new(invalid, json_string(buf_cstring(&buf)));
        buf_free(&buf);
    } else if (r < 0) {
        json_array_append_new(invalid, json_string(name));
    }
    return r;
}

EXPORTED int jmap_pointer_needsencode(const char *src)
{
    return strchr(src, '/') || strchr(src, '~');
}

EXPORTED char* jmap_pointer_encode(const char *src)
{
    struct buf buf = BUF_INITIALIZER;
    const char *base, *top;
    buf_ensure(&buf, strlen(src));

    base = src;
    top = base;
    while (*base) {
        for (top = base; *top && *top != '~' && *top != '/'; top++)
            ;
        if (!*top) break;

        buf_appendmap(&buf, base, top-base);
        if (*top == '~') {
            buf_appendmap(&buf, "~0", 2);
            top++;
        } else if (*top == '/') {
            buf_appendmap(&buf, "~1", 2);
            top++;
        }
        base = top;
    }
    buf_appendmap(&buf, base, top-base);
    return buf_release(&buf);
}

EXPORTED char *jmap_pointer_decode(const char *src, size_t len)
{
    struct buf buf = BUF_INITIALIZER;
    const char *base, *top, *end;

    buf_ensure(&buf, len);
    end = src + len;

    base = src;
    while (base < end && (top = strchr(base, '~')) && top < end) {
        buf_appendmap(&buf, base, top-base);

        if (top < end-1 && *(top+1) == '0') {
            buf_appendcstr(&buf, "~");
            base = top + 2;
        } else if (top < end-1 && *(top+1) == '1') {
            buf_appendcstr(&buf, "/");
            base = top + 2;
        } else {
            buf_appendcstr(&buf, "~");
            base = top + 1;
        }
    }
    if (base < end) {
        buf_appendmap(&buf, base, end-base);
    }

    return buf_release(&buf);
}

EXPORTED json_t* jmap_patchobject_apply(json_t *val, json_t *patch)
{
    const char *path;
    json_t *newval, *dst;

    dst = json_deep_copy(val);
    json_object_foreach(patch, path, newval) {
        /* Start traversal at root object */
        json_t *it = dst;
        const char *base = path, *top;
        /* Find path in object tree */
        while ((top = strchr(base, '/'))) {
            char *name = jmap_pointer_decode(base, top-base);
            it = json_object_get(it, name);
            free(name);
            base = top + 1;
        }
        if (!it) {
            /* No such path in 'val' */
            json_decref(dst);
            return NULL;
        }
        /* Replace value at path */
        char *name = jmap_pointer_decode(base, strlen(base));
        if (newval == json_null()) {
            json_object_del(it, name);
        } else {
            json_object_set(it, name, newval);
        }
        free(name);
    }

    return dst;
}

static void jmap_patchobject_set(json_t *diff, struct buf *path,
                                 const char *key, json_t *val)
{
    char *enckey = jmap_pointer_encode(key);
    size_t len = buf_len(path);
    if (len) buf_appendcstr(path, "/");
    buf_appendcstr(path, enckey);
    json_object_set(diff, buf_cstring(path), val);
    buf_truncate(path, len);
    free(enckey);
}

static void jmap_patchobject_diff(json_t *diff, struct buf *path,
                                  json_t *src, json_t *dst)
{
    if (!json_is_object(src) || !json_is_object(dst))
        return;

    const char *key;
    json_t *val;

    // Add any properties that are set in dst but not in src
    json_object_foreach(dst, key, val) {
        if (json_object_get(src, key) == NULL) {
            jmap_patchobject_set(diff, path, key, val);
        }
    }

    // Remove any properties that are set in src but not in dst
    json_object_foreach(src, key, val) {
        if (json_object_get(dst, key) == NULL) {
            jmap_patchobject_set(diff, path, key, json_null());
        }
    }

    // Handle properties that exist in both src and dst
    json_object_foreach(dst, key, val) {
        json_t *srcval = json_object_get(src, key);
        if (!srcval) {
            continue;
        }
        if (json_typeof(val) != JSON_OBJECT) {
            if (!json_equal(val, srcval)) {
                jmap_patchobject_set(diff, path, key, val);
            }
        }
        else if (json_typeof(srcval) != JSON_OBJECT) {
            jmap_patchobject_set(diff, path, key, val);
        }
        else {
            char *enckey = jmap_pointer_encode(key);
            size_t len = buf_len(path);
            if (len) buf_appendcstr(path, "/");
            buf_appendcstr(path, enckey);
            jmap_patchobject_diff(diff, path, srcval, val);
            buf_truncate(path, len);
            free(enckey);
        }
    }
}

EXPORTED json_t *jmap_patchobject_create(json_t *src, json_t *dst)
{
    json_t *diff = json_object();
    struct buf buf = BUF_INITIALIZER;

    jmap_patchobject_diff(diff, &buf, src, dst);

    buf_free(&buf);
    return diff;
}
