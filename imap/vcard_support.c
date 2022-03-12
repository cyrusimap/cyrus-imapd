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

/* Decode a base64-encoded binary vCard property and calculate a GUID.

   XXX  This currently assumes vCard v3.
*/
EXPORTED size_t vcard_prop_decode_value(struct vparse_entry *prop,
                                        struct buf *value,
                                        char **content_type,
                                        struct message_guid *guid)
{
    struct vparse_param *param;
    size_t size = 0;

    if (!prop) return 0;

    /* Make sure value=binary (default) and encoding=b (base64) */
    if ((!(param = vparse_get_param(prop, "value")) ||
         !strcasecmp("binary", param->value)) &&
        ((param = vparse_get_param(prop, "encoding")) &&
         !strcasecmp("b", param->value))) {

        char *decbuf = NULL;

        /* Decode property value */
        if (charset_decode_mimebody(prop->v.value, strlen(prop->v.value),
                                    ENCODING_BASE64,
                                    &decbuf, &size) == prop->v.value) return 0;

        if (content_type) {
            struct vparse_param *type = vparse_get_param(prop, "type");

            if (!type) {
                *content_type = NULL;

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
            else {
                struct buf buf = BUF_INITIALIZER;

                lcase(type->value);
                if (strncmp(type->value, "image/", 6))
                    buf_setcstr(&buf, "image/");
                buf_appendcstr(&buf, type->value);

                *content_type = buf_release(&buf);
            }
        }

        if (guid) {
            /* Generate GUID from decoded property value */
            message_guid_generate(guid, decbuf, size);
        }

        if (value) {
            /* Return the value in the specified buffer */
            buf_setmap(value, decbuf, size);
        }
        free(decbuf);
    }

    return size;
}

EXPORTED void vcard_to_v3(struct vparse_card *vcard)
{
    struct vparse_entry *ventry, *next;
    struct vparse_param *vparam;
    struct buf buf = BUF_INITIALIZER;

    for (ventry = vcard->objects->properties; ventry; ventry = next) {
        const char *name = ventry->name;
        char *propval = ventry->v.value;

        next = ventry->next;

        if (!name) continue;
        if (!propval) continue;

        if (!strcasecmp(name, "version")) {
            /* Set proper VERSION */
            vparse_set_value(ventry, "3.0");
        }
        else if (!strcasecmp(name, "key")   ||
                 !strcasecmp(name, "logo")  ||
                 !strcasecmp(name, "photo") ||
                 !strcasecmp(name, "sound")) {
            /* Rewrite KEY, LOGO, PHOTO, SOUND properties */
            if (!strncmp(propval, "data:", 5)) {
                /* Rewrite data: URI as 'b' encoded value */
                char *type = propval + 5;
                char *encoding = strchr(type, ';');
                char *data = strchr(encoding ? encoding : type, ',');

                if (encoding) {
                    *encoding++ = '\0';
                }
                if (data && !strcmpnull(encoding, "base64")) {
                    *data++ = '\0';
                    vparse_set_value(ventry, data);
                    vparse_add_param(ventry, "ENCODING", "b");

                    if (toupper(name[0]) != 'K' && (type = strchr(type, '/'))) {
                        /* Only use subtype for LOGO, PHOTO, SOUND */
                        type++;
                    }
                    if (type && *type) {
                        buf_setcstr(&buf, type);
                        vparse_add_param(ventry, "TYPE", buf_ucase(&buf));
                    }
                }
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
