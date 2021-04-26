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
#include <assert.h>
#include <errno.h>

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

#ifdef HAVE_LIBCHARDET
#include <chardet/chardet.h>
#endif

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"

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
    struct buf xtext = BUF_INITIALIZER;
    json_object_foreach(json_object_get(addr, "parameters"), key, val) {
        /* We never take AUTH at face value */
        if (!strcasecmp(key, "AUTH")) {
            continue;
        }
        /* We handle FUTURERELEASE ourselves */
        else if (!strcasecmp(key, "HOLDFOR") || !strcasecmp(key, "HOLDUNTIL")) {
            continue;
        }
        /* Encode xtext value */
        if (json_is_string(val)) {
            const char *p;
            for (p = json_string_value(val); *p; p++) {
                if (('!' <= *p && *p <= '~') && *p != '=' && *p != '+') {
                    buf_putc(&xtext, *p);
                }
                else buf_printf(&xtext, "+%02X", *p);
            }
        }
        /* Build parameter */
        smtp_param_t *param = xzmalloc(sizeof(smtp_param_t));
        param->key = xstrdup(key);
        param->val = buf_len(&xtext) ? xstrdup(buf_cstring(&xtext)) : NULL;
        ptrarray_append(&smtpaddr->params, param);
        buf_reset(&xtext);
    }
    buf_free(&xtext);
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

            snooze = json_loadb(buf_base(&value), buf_len(&value), 0, &jerr);
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
    switch (r) {
    case IMAP_CONVERSATION_GUIDLIMIT:
        return json_pack("{s:s}", "type", "tooManyMailboxes");
    case IMAP_QUOTA_EXCEEDED:
        return json_pack("{s:s}", "type", "overQuota");
    default:
        return json_pack("{s:s, s:s}",
                         "type", "serverFail",
                         "description", error_message(r));
    }
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

EXPORTED const char *jmap_decode_to_utf8(const char *charset, int encoding,
                                         const char *data, size_t datalen,
                                         float confidence,
                                         char **val,
                                         int *is_encoding_problem)
{
    charset_t cs = charset_lookupname(charset);
    char *text = NULL;
    *val = NULL;
    const char *charset_id = charset_canon_name(cs);
    assert(confidence >= 0.0 && confidence <= 1.0);

    /* Attempt fast path without allocation */
    if (encoding == ENCODING_NONE && data[datalen] == '\0' &&
            !strcasecmp(charset_id, "UTF-8")) {
        struct char_counts counts = charset_count_validutf8(data, datalen);
        if (!counts.invalid) {
            charset_free(&cs);
            return data;
        }
    }

    /* Can't use fast path. Allocate and try to detect charset. */
    if (cs == CHARSET_UNKNOWN_CHARSET || encoding == ENCODING_UNKNOWN) {
        syslog(LOG_INFO, "decode_to_utf8 error (%s, %s)",
                charset, encoding_name(encoding));
        if (is_encoding_problem) *is_encoding_problem = 1;
        goto done;
    }
    text = charset_to_utf8(data, datalen, cs, encoding);
    if (!text) {
        if (is_encoding_problem) *is_encoding_problem = 1;
        goto done;
    }

    size_t textlen = strlen(text);
    struct char_counts counts = charset_count_validutf8(text, textlen);
    if (is_encoding_problem)
        *is_encoding_problem = counts.invalid || counts.replacement;

    if (!strncasecmp(charset_id, "UTF-32", 6)) {
        /* Special-handle UTF-32. Some clients announce the wrong endianess. */
        if (counts.invalid || counts.replacement) {
            charset_t guess_cs = CHARSET_UNKNOWN_CHARSET;
            if (!strcasecmp(charset_id, "UTF-32") || !strcasecmp(charset_id, "UTF-32BE"))
                guess_cs = charset_lookupname("UTF-32LE");
            else
                guess_cs = charset_lookupname("UTF-32BE");
            char *guess = charset_to_utf8(data, datalen, guess_cs, encoding);
            if (guess) {
                struct char_counts guess_counts = charset_count_validutf8(guess, strlen(guess));
                if (guess_counts.valid > counts.valid) {
                    free(text);
                    text = guess;
                    counts = guess_counts;
                    textlen = strlen(text);
                    charset_id = charset_canon_name(guess_cs);
                }
            }
            charset_free(&guess_cs);
        }
    }
    else if (!charset_id || !strcasecmp("US-ASCII", charset_id)) {
        int has_cntrl = 0;
        size_t i;
        for (i = 0; i < textlen; i++) {
            if (iscntrl(text[i])) {
                has_cntrl = 1;
                break;
            }
        }
        if (has_cntrl) {
            /* Could be ISO-2022-JP */
            charset_t guess_cs = charset_lookupname("ISO-2022-JP");
            if (guess_cs != CHARSET_UNKNOWN_CHARSET) {
                char *guess = charset_to_utf8(data, datalen, guess_cs, encoding);
                if (guess) {
                    struct char_counts guess_counts = charset_count_validutf8(guess, strlen(guess));
                    if (!guess_counts.invalid && !guess_counts.replacement) {
                        free(text);
                        text = guess;
                        counts = guess_counts;
                        textlen = strlen(text);
                        charset_id = charset_canon_name(guess_cs);
                    }
                    else free(guess);
                }
                charset_free(&guess_cs);
            }
        }
    }

#ifdef HAVE_LIBCHARDET
    if (counts.invalid || counts.replacement) {
        static Detect *d = NULL;
        if (!d) d = detect_init();

        DetectObj *obj = detect_obj_init();
        if (!obj) goto done;
        detect_reset(&d);

        struct buf buf = BUF_INITIALIZER;
        charset_decode(&buf, data, datalen, encoding);
        buf_cstring(&buf);
        if (detect_handledata_r(&d, buf_base(&buf), buf_len(&buf), &obj) == CHARDET_SUCCESS) {
            charset_t guess_cs = charset_lookupname(obj->encoding);
            if (guess_cs != CHARSET_UNKNOWN_CHARSET) {
                char *guess = charset_to_utf8(data, datalen, guess_cs, encoding);
                if (guess) {
                    struct char_counts guess_counts =
                        charset_count_validutf8(guess, strlen(guess));
                    if ((guess_counts.valid > counts.valid) &&
                        (obj->confidence >= confidence)) {
                        free(text);
                        text = guess;
                        counts = guess_counts;
                    }
                    else {
                        free(guess);
                    }
                }
                charset_free(&guess_cs);
            }
        }
        detect_obj_free(&obj);
        buf_free(&buf);
    }
#endif

done:
    charset_free(&cs);
    *val = text;
    return text;
}

/*
 * The blobId syntax for raw message data is:
 *
 * <mailbox id> "_" <message UID> [ "_" <userid> [ "_" <subpart> [ "_" <SHA1> ]]]
 *
 * <userid> is currently used to personalize iCalendar data and may be empty
 * <subpart> is currently used to target vCard/iCalendar properties
 *   with data: URI values (e.g. vCard PHOTO/LOGO/SOUND or iCalendar IMAGE)
 * <SHA1> is used to target a <subpart> having a specific value
 */
EXPORTED const char *jmap_encode_rawdata_blobid(const char prefix,
                                                const char *mboxid,
                                                uint32_t uid,
                                                const char *userid,
                                                const char *subpart,
                                                struct message_guid *guid,
                                                struct buf *dst)
{
    buf_reset(dst);

    /* Set smart blob prefix */
    buf_putc(dst, prefix);

    /* Encode mailbox id */
    buf_appendcstr(dst, mboxid);
    
    /* Encode message UID */
    buf_printf(dst, "_%u", uid);

    /* Encode user id */
    if (userid || subpart) {
        char *b64 = NULL;

        buf_putc(dst, '_');
        if (userid) {
            b64 = jmap_encode_base64_nopad(userid, strlen(userid));
            if (!b64) {
                buf_reset(dst);
                return NULL;
            }
            buf_appendcstr(dst, b64);
            free(b64);
        }

        /* Encode subpart */
        if (subpart) {
            buf_putc(dst, '_');
            b64 = jmap_encode_base64_nopad(subpart, strlen(subpart));
            if (!b64) {
                buf_reset(dst);
                return NULL;
            }
            buf_appendcstr(dst, b64);
            free(b64);

            if (guid) {
                /* Encode subpart data GUID */
                buf_printf(dst, "_%s", message_guid_encode(guid));
            }
        }
    }

    return buf_cstring(dst);
}

EXPORTED int jmap_decode_rawdata_blobid(const char *blobid,
                                        char **mboxidptr,
                                        uint32_t *uidptr,
                                        char **useridptr,
                                        char **subpartptr,
                                        struct message_guid *guidptr)
{
    char *mboxid = NULL;
    uint32_t uid = 0;
    char *userid = NULL;
    char *subpart = NULL;
    struct message_guid guid;
    int is_valid = 0;

    /* Decode mailbox id */
    const char *base = blobid+1;
    const char *p = strchr(base, '_');
    if (!p) goto done;
    mboxid = xstrndup(base, p-base);
    if (!*mboxid) goto done;
    base = p + 1;

    /* Decode message UID */
    if (*base == '\0') goto done;
    char *endptr = NULL;
    errno = 0;
    uid = strtoul(base, &endptr, 10);
    if (errno == ERANGE || (*endptr && *endptr != '_')) {
        goto done;
    }
    base = endptr;

    /* Decode userid */
    if (*base == '_') {
        base += 1;
        p = strchr(base, '_');
        size_t len = p ? (size_t) (p - base) : strlen(base);
        if (len) {
            userid = jmap_decode_base64_nopad(base, len);
            if (!userid) goto done;
        }
        base += len;

        /* Decode subpart */
        if (*base == '_') {
            base += 1;
            p = strchr(base, '_');
            len = p ? (size_t) (p - base) : strlen(base);
            if (len) {
                subpart = jmap_decode_base64_nopad(base, p-base);
                if (!subpart) goto done;
            }
            base += len;

            /* Decode subpart data GUID */
            if (*base == '_') {
                base += 1;
                if (!message_guid_decode(&guid, base)) goto done;
            }
        }
    }

    /* All done */
    *uidptr = uid;
    *mboxidptr = mboxid;
    mboxid = NULL;
    if (useridptr) {
        *useridptr = userid;
        userid = NULL;
    }
    if (subpartptr) {
        *subpartptr = subpart;
        subpart = NULL;
    }
    if (guidptr) message_guid_copy(guidptr, &guid);
    is_valid = 1;

done:
    free(mboxid);
    free(userid);
    free(subpart);
    if (!is_valid) {
        if (guidptr) message_guid_set_null(guidptr);
    }
    return is_valid;
}

EXPORTED json_t *jmap_header_as_raw(const char *raw)
{
    if (!raw) return json_null();

    size_t len = strlen(raw);
    if (len > 1 && raw[len-1] == '\n' && raw[len-2] == '\r') len -= 2;
    return json_stringn(raw, len);
}

static char *_decode_mimeheader(const char *raw)
{
    if (!raw) return NULL;

    int is_8bit = 0;
    const char *p;
    for (p = raw; *p; p++) {
        if (*p & 0x80) {
            is_8bit = 1;
            break;
        }
    }

    char *val = NULL;
    if (is_8bit) {
        int r = 0;
        const char *cval = jmap_decode_to_utf8("utf-8", ENCODING_NONE,
                                               raw, strlen(raw), 0.0, &val, &r);
        if (!val) val = xstrdupnull(cval);
    }
    if (!val) {
        val = charset_decode_mimeheader(raw, CHARSET_KEEPCASE);
    }
    return val;
}

EXPORTED json_t *jmap_header_as_text(const char *raw)
{
    if (!raw) return json_null();

    /* TODO this could be optimised to omit unfolding, decoding
     * or normalisation, or all, if ASCII */
    /* Unfold and remove CRLF */
    char *unfolded = charset_unfold(raw, strlen(raw), 0);
    char *p = strchr(unfolded, '\r');
    while (p && *(p + 1) != '\n') {
        p = strchr(p + 1, '\r');
    }
    if (p) *p = '\0';

    /* Trim starting SP */
    const char *trimmed = unfolded;
    while (isspace(*trimmed)) {
        trimmed++;
    }

    /* Decode header */
    char *decoded = _decode_mimeheader(trimmed);

    /* Convert to Unicode NFC */
    char *normalized = charset_utf8_normalize(decoded);

    json_t *result = json_string(normalized);
    free(normalized);
    free(decoded);
    free(unfolded);
    return result;
}

EXPORTED json_t *jmap_header_as_date(const char *raw)
{
    if (!raw) return json_null();

    struct offsettime t;
    if (offsettime_from_rfc5322(raw, &t, DATETIME_FULL) == -1) {
        if (!strchr(raw, '\r')) return json_null();
        char *tmp = charset_unfold(raw, strlen(raw), CHARSET_UNFOLD_SKIPWS);
        int r = offsettime_from_rfc5322(tmp, &t, DATETIME_FULL);
        free(tmp);
        if (r == -1) return json_null();
    }

    char cbuf[ISO8601_DATETIME_MAX+1] = "";
    offsettime_to_iso8601(&t, cbuf, sizeof(cbuf), 1);
    return json_string(cbuf);
}

static void _remove_ws(char *s)
{
    char *d = s;
    do {
        while (isspace(*s))
            s++;
    } while ((*d++ = *s++));
}

EXPORTED json_t *jmap_header_as_urls(const char *raw)
{
    if (!raw) return json_null();

    /* A poor man's implementation of RFC 2369, returning anything
     * between < and >. */
    json_t *urls = json_array();
    const char *base = raw;
    const char *top = raw + strlen(raw);
    while (base < top) {
        const char *lo = strchr(base, '<');
        if (!lo) break;
        const char *hi = strchr(lo, '>');
        if (!hi) break;
        char *tmp = charset_unfold(lo + 1, hi - lo - 1, CHARSET_UNFOLD_SKIPWS);
        _remove_ws(tmp);
        if (*tmp) json_array_append_new(urls, json_string(tmp));
        free(tmp);
        base = hi + 1;
    }
    if (!json_array_size(urls)) {
        json_decref(urls);
        urls = json_null();
    }
    return urls;
}

EXPORTED json_t *jmap_header_as_messageids(const char *raw)
{
    if (!raw) return json_null();
    json_t *msgids = json_array();
    char *unfolded = charset_unfold(raw, strlen(raw), CHARSET_UNFOLD_SKIPWS);

    const char *p = unfolded;

    while (*p) {
        /* Skip preamble */
        while (isspace(*p) || *p == ',') p++;
        if (!*p) break;

        /* Find end of id */
        const char *q = p;
        if (*p == '<') {
            while (*q && *q != '>') q++;
        }
        else {
            while (*q && !isspace(*q)) q++;
        }

        /* Read id */
        char *val = xstrndup(*p == '<' ? p + 1 : p,
                             *q == '>' ? q - p - 1 : q - p);
        if (*p == '<') {
            _remove_ws(val);
        }
        if (*val) {
            /* calculate the value that would be created if this was
             * fed back into an Email/set and make sure it would
             * validate */
            char *msgid = strconcat("<", val, ">", NULL);
            int r = conversations_check_msgid(msgid, strlen(msgid));
            if (!r) json_array_append_new(msgids, json_string(val));
            free(msgid);
        }
        free(val);

        /* Reset iterator */
        p = *q ? q + 1 : q;
    }


    if (!json_array_size(msgids)) {
        json_decref(msgids);
        msgids = json_null();
    }
    free(unfolded);
    return msgids;
}

static json_t *_header_as_addresses(const char *raw, enum header_form form)
{
    if (!raw) return json_null();

    struct address *addrs = NULL;
    parseaddr_list(raw, &addrs);
    json_t *result = jmap_emailaddresses_from_addr(addrs, form);
    parseaddr_free(addrs);
    return result;
}

EXPORTED json_t *jmap_header_as_addresses(const char *raw)
{
    return _header_as_addresses(raw, HEADER_FORM_ADDRESSES);
}

EXPORTED json_t *jmap_header_as_groupedaddresses(const char *raw)
{
    return _header_as_addresses(raw, HEADER_FORM_GROUPEDADDRESSES);
}

EXPORTED json_t *jmap_emailaddresses_from_addr(struct address *addr,
                                               enum header_form form)
{
    if (!addr) return json_null();

    json_t *result = json_array();

    const char *groupname = NULL;
    json_t *addresses = json_array();

    struct buf buf = BUF_INITIALIZER;
    while (addr) {
        const char *domain = addr->domain;
        if (!strcmpsafe(domain, "unspecified-domain")) {
            domain = NULL;
        }
        if (!addr->name && addr->mailbox && !domain) {
            /* Start of group. */
            if (form == HEADER_FORM_GROUPEDADDRESSES) {
                if (form == HEADER_FORM_GROUPEDADDRESSES) {
                    if (groupname || json_array_size(addresses)) {
                        json_t *group = json_object();
                        json_object_set_new(group, "name",
                                groupname ? json_string(groupname) : json_null());
                        json_object_set_new(group, "addresses", addresses);
                        json_array_append_new(result, group);
                        addresses = json_array();
                    }
                    groupname = NULL;
                }
                groupname = addr->mailbox;
            }
        }
        else if (!addr->name && !addr->mailbox) {
            /* End of group */
            if (form == HEADER_FORM_GROUPEDADDRESSES) {
                if (groupname || json_array_size(addresses)) {
                    json_t *group = json_object();
                    json_object_set_new(group, "name",
                            groupname ? json_string(groupname) : json_null());
                    json_object_set_new(group, "addresses", addresses);
                    json_array_append_new(result, group);
                    addresses = json_array();
                }
                groupname = NULL;
            }
        }
        else {
            /* Regular address */
            json_t *jemailaddr = json_object();
            if (addr->name) {
                char *tmp = _decode_mimeheader(addr->name);
                if (tmp) json_object_set_new(jemailaddr, "name", json_string(tmp));
                free(tmp);
            } else {
                json_object_set_new(jemailaddr, "name", json_null());
            }
            if (addr->mailbox) {
                buf_setcstr(&buf, addr->mailbox);
                if (domain) {
                    buf_putc(&buf, '@');
                    buf_appendcstr(&buf, domain);
                }
                json_object_set_new(jemailaddr, "email", json_string(buf_cstring(&buf)));
                buf_reset(&buf);
            } else {
                json_object_set_new(jemailaddr, "email", json_null());
            }
            json_array_append_new(addresses, jemailaddr);
        }
        addr = addr->next;
    }
    buf_free(&buf);

    if (form == HEADER_FORM_GROUPEDADDRESSES) {
        if (groupname || json_array_size(addresses)) {
            json_t *group = json_object();
            json_object_set_new(group, "name",
                    groupname ? json_string(groupname) : json_null());
            json_object_set_new(group, "addresses", addresses);
            json_array_append_new(result, group);
        }
        else json_decref(addresses);
    }
    else {
        json_decref(result);
        result = addresses;
    }

    return result;
}

EXPORTED void jmap_set_blobid(const struct message_guid *guid, char *buf)
{
    buf[0] = 'G';
    memcpy(buf+1, message_guid_encode(guid), JMAP_BLOBID_SIZE-2);
    buf[JMAP_BLOBID_SIZE-1] = '\0';
}

EXPORTED void jmap_set_emailid(const struct message_guid *guid, char *buf)
{
    buf[0] = 'M';
    memcpy(buf+1, message_guid_encode(guid), JMAP_EMAILID_SIZE-2);
    buf[JMAP_EMAILID_SIZE-1] = '\0';
}

EXPORTED void jmap_set_threadid(conversation_id_t cid, char *buf)
{
    buf[0] = 'T';
    memcpy(buf+1, conversation_id_encode(cid), JMAP_THREADID_SIZE-2);
    buf[JMAP_THREADID_SIZE-1] = 0;
}
