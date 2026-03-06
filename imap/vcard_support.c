/* vcard_support.h -- Helper functions for vcard */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/uri.h>

#include "vcard_support.h"
#include "syslog.h"

#include "global.h"
#include "hash.h"

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
            for (i = 0; i < 2 && sig->magic[i].len; i++) {
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

EXPORTED  vcardcomponent *vcard_parse_string(const char *str)
{
    vcardcomponent *vcard = vcardcomponent_new_from_string(str);

    /* Remove all X-LIC-ERROR properties */
    if (vcard) vcardcomponent_strip_errors(vcard);

    return vcard;
}

EXPORTED vcardcomponent *vcard_parse_buf(const struct buf *buf)
{
    return vcardparser_parse_string(buf_cstring(buf));
}

EXPORTED struct buf *vcard_as_buf(vcardcomponent *vcard)
{
    char *str = vcardcomponent_as_vcard_string_r(vcard);
    struct buf *ret = buf_new();

    if (str) buf_initm(ret, str, strlen(str));

    return ret;
}

EXPORTED vcardcomponent *record_to_vcard(struct mailbox *mailbox,
                                         const struct index_record *record)
{
    struct buf buf = BUF_INITIALIZER;
    vcardcomponent *vcard = NULL;

    /* Load message containing the resource and parse vCard data */
    if (!mailbox_map_record(mailbox, record, &buf)) {
        vcard = vcard_parse_string(buf_cstring(&buf) + record->header_size);
        buf_free(&buf);
    }

    return vcard;
}

EXPORTED size_t vcard_prop_decode_value(vcardproperty *prop,
                                        struct buf *value,
                                        char **content_type,
                                        struct message_guid *guid)
{
    const char *data = NULL;
    const vcardvalue *val;
    vcardparameter *param;
    const char *mt, *b64;

    if (!prop) return 0;

    val = vcardproperty_get_value(prop);
    if (vcardvalue_isa(val) == VCARD_X_VALUE)
        data = vcardvalue_get_x(val);
    else
        data = vcardvalue_get_uri(val);

    if (!data) return 0;

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

                if (subtype->xvalue) {
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
