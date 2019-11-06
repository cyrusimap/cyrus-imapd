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
#include <syslog.h>

#include <sasl/saslutil.h>

#include "annotate.h"
#include "carddav_db.h"
#include "global.h"
#include "hash.h"
#include "index.h"
#include "jmap_util.h"
#include "json_support.h"
#include "search_query.h"
#include "times.h"
#include "xapian_wrap.h"

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

EXPORTED json_t* jmap_patchobject_apply(json_t *val, json_t *patch, json_t *invalid)
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
            if (invalid) {
                json_array_append_new(invalid, json_string(path));
            }
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

EXPORTED void jmap_filterprops(json_t *jobj, hash_table *props)
{
    if (!props) return;

    const char *key;
    json_t *jval;
    void *tmp;
    json_object_foreach_safe(jobj, tmp, key, jval) {
        if (!hash_lookup(key, props)) {
            json_object_del(jobj, key);
        }
    }
}

static void address_to_smtp(smtp_addr_t *smtpaddr, json_t *addr)
{
    smtpaddr->addr = xstrdup(json_string_value(json_object_get(addr, "email")));

    const char *key;
    json_t *val;
    json_object_foreach(json_object_get(addr, "parameters"), key, val) {
        /* We never take AUTH at face value */
        if (!strcasecmp(key, "AUTH")) {
            continue;
        }
        /* We handle FUTURERELEASE ourselves */
        else if (!strcasecmp(key, "HOLDFOR") || !strcasecmp(key, "HOLDUNTIL")) {
            continue;
        }
        smtp_param_t *param = xzmalloc(sizeof(smtp_param_t));
        param->key = xstrdup(key);
        param->val = xstrdup(json_string_value(val));
        ptrarray_append(&smtpaddr->params, param);
    }
}

EXPORTED void jmap_emailsubmission_envelope_to_smtp(smtp_envelope_t *smtpenv,
                                                    json_t *env)
{
    address_to_smtp(&smtpenv->from, json_object_get(env, "mailFrom"));
    size_t i;
    json_t *val;
    json_array_foreach(json_object_get(env, "rcptTo"), i, val) {
        smtp_addr_t *smtpaddr = xzmalloc(sizeof(smtp_addr_t));
        address_to_smtp(smtpaddr, val);
        ptrarray_append(&smtpenv->rcpts, smtpaddr);
    }
}

EXPORTED json_t *jmap_fetch_snoozed(const char *mbox, uint32_t uid)
{
    /* get the snoozed annotation */
    const char *annot = IMAP_ANNOT_NS "snoozed";
    struct buf value = BUF_INITIALIZER;
    json_t *snooze = NULL;
    int r;

    r = annotatemore_msg_lookup(mbox, uid, annot, "", &value);

    if (!r) {
        if (!buf_len(&value)) {
            /* get the legacy snoozed-until annotation */
            annot = IMAP_ANNOT_NS "snoozed-until";

            r = annotatemore_msg_lookup(mbox, uid, annot, "", &value);
            if (!r && buf_len(&value)) {
                /* build a SnoozeDetails object from the naked "until" value */
                snooze = json_pack("{s:s}",
                                   "until", json_string(buf_cstring(&value)));
            }
        }
        else {
            json_error_t jerr;

            snooze = json_loads(buf_cstring(&value), 0, &jerr);
        }
    }

    buf_free(&value);

    return snooze;
}

EXPORTED int jmap_email_keyword_is_valid(const char *keyword)
{
    const char *p;

    if (*keyword == '\0') {
        return 0;
    }
    if (strlen(keyword) > 255) {
        return 0;
    }
    for (p = keyword; *p; p++) {
        if (*p < 0x21 || *p > 0x7e) {
            return 0;
        }
        switch(*p) {
            case '(':
            case ')':
            case '{':
            case ']':
            case '%':
            case '*':
            case '"':
            case '\\':
                return 0;
            default:
                ;
        }
    }
    return 1;
}

EXPORTED const char *jmap_keyword_to_imap(const char *keyword)
{
    if (!strcasecmp(keyword, "$Seen")) {
        return "\\Seen";
    }
    else if (!strcasecmp(keyword, "$Flagged")) {
        return "\\Flagged";
    }
    else if (!strcasecmp(keyword, "$Answered")) {
        return "\\Answered";
    }
    else if (!strcasecmp(keyword, "$Draft")) {
        return "\\Draft";
    }
    else if (jmap_email_keyword_is_valid(keyword)) {
        return keyword;
    }
    return NULL;
}

HIDDEN void jmap_parser_fini(struct jmap_parser *parser)
{
    strarray_fini(&parser->path);
    json_decref(parser->invalid);
    buf_free(&parser->buf);
}

HIDDEN void jmap_parser_push(struct jmap_parser *parser, const char *prop)
{
    strarray_push(&parser->path, prop);
}

HIDDEN void jmap_parser_push_index(struct jmap_parser *parser, const char *prop,
                                   size_t index, const char *name)
{
    /* TODO make this more clever: won't need to printf most of the time */
    buf_reset(&parser->buf);
    if (name) buf_printf(&parser->buf, "%s[%zu:%s]", prop, index, name);
    else buf_printf(&parser->buf, "%s[%zu]", prop, index);
    strarray_push(&parser->path, buf_cstring(&parser->buf));
    buf_reset(&parser->buf);
}

HIDDEN void jmap_parser_push_name(struct jmap_parser *parser,
                                  const char *prop, const char *name)
{
    /* TODO make this more clever: won't need to printf most of the time */
    buf_reset(&parser->buf);
    buf_printf(&parser->buf, "%s{%s}", prop, name);
    strarray_push(&parser->path, buf_cstring(&parser->buf));
    buf_reset(&parser->buf);
}

HIDDEN void jmap_parser_pop(struct jmap_parser *parser)
{
    free(strarray_pop(&parser->path));
}

HIDDEN const char* jmap_parser_path(struct jmap_parser *parser, struct buf *buf)
{
    int i;
    buf_reset(buf);

    for (i = 0; i < parser->path.count; i++) {
        const char *p = strarray_nth(&parser->path, i);
        if (jmap_pointer_needsencode(p)) {
            char *tmp = jmap_pointer_encode(p);
            buf_appendcstr(buf, tmp);
            free(tmp);
        } else {
            buf_appendcstr(buf, p);
        }
        if ((i + 1) < parser->path.count) {
            buf_appendcstr(buf, "/");
        }
    }

    return buf_cstring(buf);
}

HIDDEN void jmap_parser_invalid(struct jmap_parser *parser, const char *prop)
{
    if (prop)
        jmap_parser_push(parser, prop);

    json_array_append_new(parser->invalid,
            json_string(jmap_parser_path(parser, &parser->buf)));

    if (prop)
        jmap_parser_pop(parser);
}

HIDDEN json_t *jmap_server_error(int r)
{
    return json_pack("{s:s, s:s}",
                     "type", "serverError",
                     "description", error_message(r));
}

HIDDEN char *jmap_encode_base64_nopad(const char *data, size_t len)
{
    if (!len) return NULL;

    /* Encode data */
    size_t b64len = ((len + 2) / 3) << 2;
    char *b64 = xzmalloc(b64len + 1);
    if (sasl_encode64(data, len, b64, b64len + 1, NULL) != SASL_OK) {
        free(b64);
        return NULL;
    }
    /* Remove padding */
    char *end = b64 + strlen(b64) - 1;
    while (*end == '=') {
        *end = '\0';
        end--;
    }

    return b64;
}

HIDDEN char *jmap_decode_base64_nopad(const char *b64, size_t b64len)
{
    /* Pad base64 data. */
    size_t myb64len = b64len;
    switch (b64len % 4) {
        case 3:
            myb64len += 1;
            break;
        case 2:
            myb64len += 2;
            break;
        case 1:
            return NULL;
        default:
            ; // do nothing
    }
    char *myb64 = xzmalloc(myb64len+1);
    memcpy(myb64, b64, b64len);
    switch (myb64len - b64len) {
        case 2:
            myb64[b64len+1] = '=';
            // fall through
        case 1:
            myb64[b64len] = '=';
            break;
        default:
            ; // do nothing
    }
    /* Decode data. */
    size_t datalen = ((4 * myb64len / 3) + 3) & ~3;
    char *data = xzmalloc(datalen + 1);
    if (sasl_decode64(myb64, myb64len, data, datalen, NULL) != SASL_OK) {
        free(data);
        free(myb64);
        return NULL;
    }

    free(myb64);
    return data;
}
