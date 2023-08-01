/* vcard_support.h -- Helper functions for vcard
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
#include <libxml/tree.h>

#include "vcard_support.h"
#include "syslog.h"

#include "global.h"

EXPORTED struct vparse_card *vcard_parse_string(const char *str)
{
    struct vparse_state vparser;
    struct vparse_card *vcard = NULL;
    int vr;

    memset(&vparser, 0, sizeof(struct vparse_state));

    vparser.base = str;
    vparse_set_multival(&vparser, "adr", ';');
    vparse_set_multival(&vparser, "org", ';');
    vparse_set_multival(&vparser, "n", ';');
    vparse_set_multival(&vparser, "nickname", ',');
    vparse_set_multival(&vparser, "categories", ',');
    vparse_set_multiparam(&vparser, "type");
    vr = vparse_parse(&vparser, 0);
    if (vr) {
        struct vparse_errorpos pos;
        vparse_fillpos(&vparser, &pos);
        if (pos.startpos < 60) {
            int len = pos.errorpos - pos.startpos;
            syslog(LOG_ERR, "vcard error %s at line %d char %d: %.*s ---> %.*s <---",
                   vparse_errstr(vr), pos.errorline, pos.errorchar,
                   pos.startpos, str, len, str + pos.startpos);
        }
        else if (pos.errorpos - pos.startpos < 40) {
            int len = pos.errorpos - pos.startpos;
            syslog(LOG_ERR, "vcard error %s at line %d char %d: ... %.*s ---> %.*s <---",
                   vparse_errstr(vr), pos.errorline, pos.errorchar,
                   40 - len, str + pos.errorpos - 40,
                   len, str + pos.startpos);
        }
        else {
            syslog(LOG_ERR, "error %s at line %d char %d: %.*s ... %.*s <--- (started at line %d char %d)",
                   vparse_errstr(vr), pos.errorline, pos.errorchar,
                   20, str + pos.startpos,
                   20, str + pos.errorpos - 20,
                   pos.startline, pos.startchar);
        }
    }
    else {
        vcard = vparser.card;
        vparser.card = NULL;
    }
    vparse_free(&vparser);

    return vcard;
}

EXPORTED struct vparse_card *vcard_parse_buf(const struct buf *buf)
{
    return vcard_parse_string(buf_cstring(buf));
}

EXPORTED struct buf *vcard_as_buf(struct vparse_card *vcard)
{
    struct buf *buf = buf_new();

    vparse_tobuf(vcard, buf);

    return buf;
}

EXPORTED struct vparse_card *record_to_vcard(struct mailbox *mailbox,
                                    const struct index_record *record)
{
    struct buf buf = BUF_INITIALIZER;
    struct vparse_card *vcard = NULL;

    /* Load message containing the resource and parse vcard data */
    if (!mailbox_map_record(mailbox, record, &buf)) {
        vcard = vcard_parse_string(buf_cstring(&buf) + record->header_size);
        buf_free(&buf);
    }

    return vcard;
}

struct image_magic {
    size_t offset;
    size_t len;
    uint8_t data[8];
};

static const struct image_signature {
    const char *mediatype;
    struct image_magic magic[2];
} image_signatures[] = {
    { "image/bmp",  { { 0, 2, { 0x42, 0x4D } },                         // "BM"
                      { 0, 0, { 0x00 } } } },
    { "image/gif",  { { 0, 6, { 0x47, 0x49, 0x46, 0x38, 0x37, 0x61 } }, // "GIF87a"
                      { 0, 0, { 0x00 } } } },
    { "image/gif",  { { 0, 6, { 0x47, 0x49, 0x46, 0x38, 0x39, 0x61 } }, // "GIF89a"
                      { 0, 0, { 0x00 } } } },
    { "image/jpeg", { { 0, 4, { 0xFF, 0xD8, 0xFF, 0xE0 } },
                      { 6, 5, { 0x4A, 0x46, 0x49, 0x46, 0x00 } } } },   // "JFIF\0"
    { "image/jpeg", { { 0, 4, { 0xFF, 0xD8, 0xFF, 0xE0 } },
                      { 6, 5, { 0x4A, 0x46, 0x58, 0x58, 0x00 } } } },   // "JFXX\0"
    { "image/jpeg", { { 0, 4, { 0xFF, 0xD8, 0xFF, 0xE1 } },
                      { 6, 5, { 0x45, 0x78, 0x69, 0x66, 0x00 } } } },   // "Exif\0"
    { "image/png",  { { 0, 8, { 0x89,
                                0x50, 0x4E, 0x47, 0x0D, 0x0A,           // "PNG\r\n"
                                0x1A, 0x0A } },
                      { 0, 0, { 0x00 } } } },
    { "image/tiff", { { 0, 4, { 0x49, 0x49, 0x2A, 0x00 } },             // "II*\0"
                      { 0, 0, { 0x00 } } } },
    { "image/tiff", { { 0, 4, { 0x4D, 0x4D, 0x00, 0x2A } },             // "MM\0*"
                      { 0, 0, { 0x00 } } } },
    { "image/webp", { { 0, 4, { 0x52, 0x49, 0x46, 0x46 } },             // "RIFF"
                      { 8, 4, { 0x57, 0x45, 0x42, 0x50 } } } },         // "WEBP"
    { 0 }
};

/* Decode a base64-encoded binary vCard property and calculate a GUID. */
static size_t _prop_decode_value(const char *data,
                                 struct buf *decoded,
                                 char **content_type,
                                 struct message_guid *guid)
{
    char *decbuf = NULL;
    size_t size = 0;

    /* Decode property value */
    charset_decode_mimebody(data, strlen(data), ENCODING_BASE64, &decbuf, &size);
    if (!decbuf) return 0;

    if (content_type && !*content_type) {
        /* Attempt to detect the content type */
        const struct image_signature *sig;

        for (sig = image_signatures; sig->mediatype; sig++) {
            int i;
            for (i = 0; sig->magic[i].len && i < 2; i++) {
                if (size - sig->magic[i].offset <= sig->magic[i].len ||
                    memcmp(decbuf + sig->magic[i].offset,
                           sig->magic[i].data, sig->magic[i].len)) {
                    break;
                }
            }
            if (i == 2 || !sig->magic[i].len) {
                *content_type = xstrdup(sig->mediatype);
                break;
            }
        }

        if (!*content_type) {
            xmlDocPtr doc = xmlReadMemory(decbuf, size, NULL, NULL,
                                          XML_PARSE_NOERROR |
                                          XML_PARSE_NOWARNING);
            if (doc) {
                xmlNodePtr root = xmlDocGetRootElement(doc);
                if (!xmlStrcmp(root->name, BAD_CAST "svg")) {
                    *content_type = xstrdup("image/svg+xml");
                }
                xmlFreeDoc(doc);
            }
        }
    }

    if (guid) {
        /* Generate GUID from decoded property value */
        message_guid_generate(guid, decbuf, size);
    }

    if (decoded) {
        /* Return the value in the specified buffer */
        buf_setmap(decoded, decbuf, size);
    }
    free(decbuf);

    return size;
}

EXPORTED size_t vcard_prop_decode_value(struct vparse_entry *prop,
                                        struct buf *value,
                                        char **content_type,
                                        struct message_guid *guid)
{
    struct vparse_param *param;
    char *data, *mt, *b64;

    if (!prop) return 0;

    if (content_type) *content_type = NULL;

    /* Make sure we have base64-encoded data */
    if (((param = vparse_get_param(prop, "encoding")) &&
         !strcasecmp("b", param->value))) {
        /* vCard v3 */
        data = prop->v.value;

        if (content_type && (param = vparse_get_param(prop, "type"))) {
            struct buf buf = BUF_INITIALIZER;

            buf_setcstr(&buf, param->value);
            if (strncmp("image/", buf_lcase(&buf), 6))
                buf_insertcstr(&buf, 0, "image/");

            *content_type = buf_release(&buf);
        }
    }
    else if (!strncmp("data:", prop->v.value, 5) &&
             (mt = prop->v.value + 5) &&
             (b64 = strstr(mt, ";base64,"))) {
        /* data URI -- data:[<media type>][;base64],<data> */
        size_t mt_len = b64 - mt;

        data = b64 + 8;

        if (content_type && mt_len)
            *content_type = xstrndup(mt, mt_len);
    }
    else {
        return 0;
    }
    
    /* Decode property value */
    return _prop_decode_value(data, value, content_type, guid);
}

EXPORTED void vcard_to_v3(struct vparse_card *vcard)
{
    struct vparse_entry *ventry, *next;
    struct vparse_param *vparam;
    struct buf buf = BUF_INITIALIZER;

    for (ventry = vcard->objects->properties; ventry; ventry = next) {
        const char *name = ventry->name;
        const char *propval = ventry->v.value;

        next = ventry->next;

        if (!name) continue;
        if (!propval) continue;

        if (!strcasecmp(name, "version")) {
            /* Set proper VERSION */
            vparse_set_value(ventry, "3.0");
        }
        else if (!strcasecmp(name, "uid")) {
            /* Rewrite UID property */
            vparam = vparse_get_param(ventry, "value");
            if (vparam && !strcasecmpsafe(vparam->value, "text")) {
                /* text -> text (default) */
                vparse_delete_params(ventry, "value");
            }
            else if (!strncmp(propval, "urn:uuid:", 9)) {
                /* uuid URN -> text */
                buf_setcstr(&buf, propval+9);
                vparse_set_value(ventry, buf_cstring(&buf));
            }
            else {
                /* uri (default) -> uri */
                vparse_add_param(ventry, "VALUE", "uri");
            }
        }
        else if (!strcasecmp(name, "key")   ||
                 !strcasecmp(name, "logo")  ||
                 !strcasecmp(name, "photo") ||
                 !strcasecmp(name, "sound")) {
            /* Rewrite KEY, LOGO, PHOTO, SOUND properties */
            if (!strncmp(propval, "data:", 5)) {
                /* Rewrite data: URI as 'b' encoded value */
                const char *type = propval + 5;
                const char *base64 = strstr(type, ";base64,");
                const char *data = NULL;
                size_t typelen = 0;

                if (base64) {
                    vparse_add_param(ventry, "ENCODING", "b");

                    data = base64 + 7;
                    typelen = base64 - type;
                }
                else if ((data = strchr(type, ','))) {
                    typelen = data - type;
                }

                if (typelen) {
                    const char *subtype;

                    buf_setmap(&buf, type, typelen);
                    subtype = strchr(buf_ucase(&buf), '/');
                    if (subtype) {
                        vparse_add_param(ventry, "TYPE", subtype+1);
                    }
                }

                buf_setcstr(&buf, data ? data+1 : "");
                vparse_set_value(ventry, buf_cstring(&buf));
            }
            else if ((vparam = vparse_get_param(ventry, "mediatype"))) {
                /* Rename MEDIATYPE parameter */
                free(vparam->name);
                vparam->name = xstrdup("type");
            }
        }
        else if (!strcasecmp(name, "kind")) {
            /* Rename KIND property */
            free(ventry->name);
            ventry->name = xstrdup("x-addressbookserver-kind");
        }
        else if (!strcasecmp(name, "member")) {
            /* Rename MEMBER property */
            free(ventry->name);
            ventry->name = xstrdup("x-addressbookserver-member");
        }
    }

    buf_free(&buf);
}

EXPORTED void vcard_to_v4(struct vparse_card *vcard)
{
    struct vparse_entry *ventry, *next;
    struct vparse_param *vparam;
    struct buf buf = BUF_INITIALIZER;

    for (ventry = vcard->objects->properties; ventry; ventry = next) {
        const char *name = ventry->name;
        const char *propval = ventry->v.value;

        next = ventry->next;

        if (!name) continue;
        if (!propval) continue;

        if (!strcasecmp(name, "version")) {
            /* Set proper VERSION */
            vparse_set_value(ventry, "4.0");
        }
        else if (!strcasecmp(name, "uid")) {
            /* Rewrite UID property */
            vparam = vparse_get_param(ventry, "value");
            if (vparam && !strcasecmpsafe(vparam->value, "uri")) {
                /* uri -> uri (default) */
                vparse_delete_params(ventry, "value");
            }
            else if (strncmp(propval, "urn:uuid:", 9)) {
                /* text (default) -> uuid URN */
                buf_setcstr(&buf, "urn:uuid:");
                buf_appendcstr(&buf, propval);
                vparse_set_value(ventry, buf_cstring(&buf));
            }
        }
        else if (!strcasecmp(name, "key")   ||
                 !strcasecmp(name, "logo")  ||
                 !strcasecmp(name, "photo") ||
                 !strcasecmp(name, "sound")) {
            /* Rewrite KEY, LOGO, PHOTO, SOUND properties */
            vparam = vparse_get_param(ventry, "value");
            if (!vparam || strcasecmp(vparam->value, "uri")) {
                /* Rewrite 'b' encoded value as data: URI */
                buf_setcstr(&buf, "data:");

                vparam = vparse_get_param(ventry, "type");
                if (vparam && vparam->value) {
                    switch (toupper(name[0])) {
                    case 'K':
                        buf_appendcstr(&buf, lcase(vparam->value));
                        break;
                    case 'S':
                        buf_printf(&buf, "audio/%s", lcase(vparam->value));
                        break;
                    default:
                        buf_printf(&buf, "image/%s", lcase(vparam->value));
                        break;
                    }
                }
                vparse_delete_params(ventry, "type");

                vparam = vparse_get_param(ventry, "encoding");
                if (vparam && !strcasecmpsafe(vparam->value, "b")) {
                    buf_appendcstr(&buf, ";base64");
                }
                vparse_delete_params(ventry, "encoding");

                buf_printf(&buf, ",%s", propval);
                vparse_set_value(ventry, buf_cstring(&buf));
            }
            else if ((vparam = vparse_get_param(ventry, "type"))) {
                /* Rename TYPE parameter */
                free(vparam->name);
                vparam->name = xstrdup("mediatype");
            }
        }
        else if (!strncasecmp(name, "x-addressbookserver-", 20)) {
            /* Rename X-ADDRESSBOOKSERVER-* properties */
            char *newname = xstrdup(name+20);

            free(ventry->name);
            ventry->name = newname;
        }
    }

    buf_free(&buf);
}

#ifdef HAVE_LIBICALVCARD

EXPORTED vcardcomponent *vcard_parse_buf_x(const struct buf *buf)
{
    return vcardparser_parse_string(buf_cstring(buf));
}

EXPORTED struct buf *vcard_as_buf_x(vcardcomponent *vcard)
{
    char *str = vcardcomponent_as_vcard_string_r(vcard);
    struct buf *ret = buf_new();

    buf_initm(ret, str, strlen(str));

    return ret;
}

EXPORTED vcardcomponent *record_to_vcard_x(struct mailbox *mailbox,
                                           const struct index_record *record)
{
    struct buf buf = BUF_INITIALIZER;
    vcardcomponent *vcard = NULL;

    /* Load message containing the resource and parse vcard data */
    if (!mailbox_map_record(mailbox, record, &buf)) {
        vcard = vcardcomponent_new_from_string(buf_cstring(&buf) +
                                               record->header_size);
        buf_free(&buf);
    }

    return vcard;
}

EXPORTED size_t vcard_prop_decode_value_x(vcardproperty *prop,
                                          struct buf *value,
                                          char **content_type,
                                          struct message_guid *guid)
{
    const char *data = vcardvalue_get_uri(vcardproperty_get_value(prop));
    vcardparameter *param;
    const char *mt, *b64;

    if (!prop) return 0;

    if (content_type) *content_type = NULL;

    /* Make sure we have base64-encoded data */
    param = vcardproperty_get_first_parameter(prop, VCARD_ENCODING_PARAMETER);
    if (param &&
        vcardparameter_get_encoding(param) == VCARD_ENCODING_B) {
        /* vCard v3 */

        param = vcardproperty_get_first_parameter(prop, VCARD_TYPE_PARAMETER);
        if (param && content_type) {
            vcardenumarray *subtypes = vcardparameter_get_type(param);
            struct buf buf = BUF_INITIALIZER;
            const char *type;

            switch (vcardproperty_isa(prop)) {
            case VCARD_PHOTO_PROPERTY:
            case VCARD_LOGO_PROPERTY:
                type = "image/";
                break;
            case VCARD_SOUND_PROPERTY:
                type = "audio/";
                break;
            default:
                type = "application/";
                break;
            }

            for (size_t i = 0; i < vcardenumarray_size(subtypes); i++) {
                const vcardenumarray_element *subtype =
                    vcardenumarray_element_at(subtypes, i);

                if (subtype->xvalue && strcasecmp(subtype->xvalue, "PREF")) {
                    buf_setcstr(&buf, subtype->xvalue);
                    break;
                }
            }

            if (strncmp(type, buf_lcase(&buf), strlen(type)))
                buf_insertcstr(&buf, 0, type);

            *content_type = buf_release(&buf);
        }
    }
    else if (!strncmp("data:", data, 5) &&
             (mt = data + 5) &&
             (b64 = strstr(mt, ";base64,"))) {
        /* data URI -- data:[<media type>][;base64],<data> */
        size_t mt_len = b64 - mt;

        data = b64 + 8;

        if (content_type && mt_len)
            *content_type = xstrndup(mt, mt_len);
    }
    else {
        return 0;
    }
    
    /* Decode property value */
    return _prop_decode_value(data, value, content_type, guid);
}

EXPORTED void vcard_to_v3_x(vcardcomponent *vcard)
{
    vcardproperty *prop, *next;
    struct buf buf = BUF_INITIALIZER;

    for (prop = vcardcomponent_get_first_property(vcard, VCARD_ANY_PROPERTY);
         prop; prop = next) {
        const char *propval = vcardproperty_get_value_as_string(prop);
        const char *key = NULL;
        vcardproperty *new;
        vcardparameter *param;

        next = vcardcomponent_get_next_property(vcard, VCARD_ANY_PROPERTY);

        switch (vcardproperty_isa(prop)) {
        case VCARD_VERSION_PROPERTY:
            /* Set proper VERSION */
            vcardproperty_set_version(prop, VCARD_VERSION_30);
            break;

        case VCARD_UID_PROPERTY:
            /* Rewrite UID property */
            param = vcardproperty_get_first_parameter(prop,
                                                      VCARD_VALUE_PARAMETER);
            if (param && vcardparameter_get_value(param) == VCARD_VALUE_TEXT) {
                /* text -> text (default) */
                vcardproperty_remove_parameter_by_ref(prop, param);
            }
            else if (!strncmp(propval, "urn:uuid:", 9)) {
                /* uuid URN -> text */
                buf_setcstr(&buf, propval+9);
                vcardproperty_set_uid(prop, buf_cstring(&buf));
            }
            else {
                /* uri (default) -> uri */
                vcardproperty_set_parameter(prop,
                                            vcardparameter_new_value(VCARD_VALUE_URI));
            }
            break;

        case VCARD_KEY_PROPERTY:
        case VCARD_LOGO_PROPERTY:
        case VCARD_PHOTO_PROPERTY:
        case VCARD_SOUND_PROPERTY:
            /* Rewrite KEY, LOGO, PHOTO, SOUND properties */
            if (!strncmp(propval, "data:", 5)) {
                /* Rewrite data: URI as 'b' encoded value */
                const char *type = propval + 5;
                const char *base64 = strstr(type, ";base64,");
                const char *data = NULL;
                size_t typelen = 0;

                if (base64) {
                    vcardproperty_add_parameter(prop,
                                                vcardparameter_new_encoding(VCARD_ENCODING_B));

                    data = base64 + 7;
                    typelen = base64 - type;
                }
                else if ((data = strchr(type, ','))) {
                    typelen = data - type;
                }

                if (typelen) {
                    const char *subtype;

                    buf_setmap(&buf, type, typelen);
                    subtype = strchr(buf_ucase(&buf), '/');
                    if (subtype) {
                        vcardenumarray *array = vcardenumarray_new(1);
                        vcardenumarray_element e =
                            {  VCARD_TYPE_X, subtype+1 };

                        vcardenumarray_append(array, &e);
                        vcardproperty_add_parameter(prop,
                                                    vcardparameter_new_type(array));
                    }
                }

                buf_setcstr(&buf, data ? data+1 : "");
                vcardproperty_set_value_from_string(prop,
                                                    buf_cstring(&buf), "NO");
            }
            else if ((param =
                      vcardproperty_get_first_parameter(prop,
                                                        VCARD_MEDIATYPE_PARAMETER))) {
                /* Rename MEDIATYPE parameter */
                vcardenumarray *array = vcardenumarray_new(1);
                vcardenumarray_element e =
                    { VCARD_TYPE_X, vcardparameter_get_mediatype(param) };

                vcardenumarray_append(array, &e);
                vcardproperty_add_parameter(prop,
                                            vcardparameter_new_type(array));
                vcardproperty_remove_parameter_by_ref(prop, param);
            }
            break;

        case VCARD_KIND_PROPERTY:
            /* Rename KIND, MEMBER properties */
            key = "X-ADDRESSBOOKSERVER-KIND";

            GCC_FALLTHROUGH

        case VCARD_MEMBER_PROPERTY:
            if (!key) key = "X-ADDRESSBOOKSERVER-MEMBER";

            new = vcardproperty_new_x(propval);
            vcardproperty_set_x_name(new, key);
            vcardcomponent_add_property(vcard, new);
            vcardcomponent_remove_property(vcard, prop);
            break;

        default:
            break;
        }
    }

    buf_free(&buf);
}

EXPORTED void vcard_to_v4_x(vcardcomponent *vcard)
{
    vcardproperty *prop, *next;
    struct buf buf = BUF_INITIALIZER;

    for (prop = vcardcomponent_get_first_property(vcard, VCARD_ANY_PROPERTY);
         prop; prop = next) {
        const char *propval = vcardproperty_get_value_as_string(prop);
        const char *str = NULL;
        vcardparameter *param;

        next = vcardcomponent_get_next_property(vcard, VCARD_ANY_PROPERTY);

        switch (vcardproperty_isa(prop)) {
        case VCARD_VERSION_PROPERTY:
            /* Set proper VERSION */
            vcardproperty_set_version(prop, VCARD_VERSION_40);
            break;

        case VCARD_UID_PROPERTY:
            /* Rewrite UID property */
            param = vcardproperty_get_first_parameter(prop,
                                                      VCARD_VALUE_PARAMETER);
            if (param && vcardparameter_get_value(param) == VCARD_VALUE_URI) {
                /* uri -> uri (default) */
                vcardproperty_remove_parameter_by_ref(prop, param);
            }
            else if (strncmp(propval, "urn:uuid:", 9)) {
                /* text (default) -> uuid URN */
                buf_setcstr(&buf, "urn:uuid:");
                buf_appendcstr(&buf, propval);
                vcardproperty_set_uid(prop, buf_cstring(&buf));
            }
            break;

        case VCARD_KEY_PROPERTY:
            /* Rewrite KEY, LOGO, PHOTO, SOUND properties */
            str = "";

            GCC_FALLTHROUGH

        case VCARD_LOGO_PROPERTY:
        case VCARD_PHOTO_PROPERTY:
            if (!str) str = "image/";

            GCC_FALLTHROUGH

        case VCARD_SOUND_PROPERTY:
            if (!str) str = "audio/";

            param = vcardproperty_get_first_parameter(prop,
                                                      VCARD_VALUE_PARAMETER);
            if (!param || vcardparameter_get_value(param) != VCARD_VALUE_URI) {
                /* Rewrite 'b' encoded value as data: URI */
                buf_setcstr(&buf, "data:");

                param = vcardproperty_get_first_parameter(prop,
                                                          VCARD_TYPE_PARAMETER);
                if (param) {
                    vcardenumarray *array = vcardparameter_get_type(param);
                    const vcardenumarray_element *e =
                        vcardenumarray_element_at(array, 0);

                    if (e->xvalue) {
                        buf_appendcstr(&buf, str);
                        buf_appendcstr(&buf, e->xvalue);
                        buf_lcase(&buf);
                    }

                    vcardproperty_remove_parameter_by_ref(prop, param);
                }

                param = vcardproperty_get_first_parameter(prop,
                                                          VCARD_ENCODING_PARAMETER);
                if (param) {
                    if (vcardparameter_get_encoding(param) == VCARD_ENCODING_B) {
                        buf_appendcstr(&buf, ";base64");
                    }

                    vcardproperty_remove_parameter_by_ref(prop, param);
                }

                buf_printf(&buf, ",%s", propval);
                vcardproperty_set_value_from_string(prop,
                                                    buf_cstring(&buf), "NO");
            }
            else if ((param =
                      vcardproperty_get_first_parameter(prop,
                                                        VCARD_TYPE_PARAMETER))) {
                /* Rename TYPE parameter */
                vcardenumarray *array = vcardparameter_get_type(param);
                const vcardenumarray_element *e =
                    vcardenumarray_element_at(array, 0);

                if (e->xvalue) {
                    buf_setcstr(&buf, e->xvalue);
                    vcardproperty_add_parameter(prop,
                                                vcardparameter_new_mediatype(buf_ucase(&buf)));
                    vcardproperty_remove_parameter_by_ref(prop, param);
                }
            }
            break;

        case VCARD_X_PROPERTY:
            str = vcardproperty_get_x_name(prop);

            if (!strncasecmp(str, "x-addressbookserver-", 20)) {
                /* Rename X-ADDRESSBOOKSERVER-* properties */
                buf_setcstr(&buf, str+20);
                vcardproperty_set_x_name(prop, buf_cstring(&buf));
            }
            break;

        default:
            break;
        }
    }

    buf_free(&buf);
}

EXPORTED const char *vcardproperty_get_xparam_value(vcardproperty *prop,
                                                    const char *name)
{
    vcardparameter *param;

    for (param = vcardproperty_get_first_parameter(prop, VCARD_ANY_PARAMETER);
         param;
         param = vcardproperty_get_next_parameter(prop, VCARD_ANY_PARAMETER)) {

        if (strcasecmpsafe(vcardparameter_get_xname(param), name)) {
            continue;
        }
        return vcardparameter_get_xvalue(param);
    }

    return NULL;
}

#endif /* HAVE_LIBVCARDVCARD */
