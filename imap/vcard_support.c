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

struct preferred_prop {
    void *prop;  // either vparse_entry* or vcardproperty*
    int level;
};

static void check_pref(void *prop, const char *name, int level,
                       struct hash_table *pref_table)
{
    struct preferred_prop *pp = hash_lookup(name, pref_table);

    if (!pp) {
        pp = xmalloc(sizeof(struct preferred_prop));
        hash_insert(name, pp, pref_table);
        pp->level = INT_MAX;
    }
    if (level < pp->level) {
        pp->prop = prop;
        pp->level = level;
    }
}

static void add_type_pref(const char *key __attribute__((unused)),
                          void *data, void *rock __attribute__((unused)))
{
    int is_ventry = !!rock;

    if (is_ventry) {
        struct vparse_entry *ventry = ((struct preferred_prop *) data)->prop;

        vparse_add_param(ventry, "TYPE", "pref");
    }
#ifdef HAVE_LIBICALVCARD
    else {
        vcardenumarray_element pref = { .val = VCARD_TYPE_PREF };
        vcardproperty *prop = ((struct preferred_prop *) data)->prop;

        vcardproperty_add_type_parameter(prop, &pref);
    }
#endif
}

EXPORTED void vcard_to_v3(struct vparse_card *vcard)
{
    struct vparse_entry *ventry, *next;
    struct vparse_param *vparam;
    struct buf buf = BUF_INITIALIZER;
    struct hash_table pref_table = HASH_TABLE_INITIALIZER;

    /* Create hash table of preferred properties */
    construct_hash_table(&pref_table, 10, 1);


    for (ventry = vcard->objects->properties; ventry; ventry = next) {
        const char *name = ventry->name;
        const char *propval = ventry->v.value;
        struct vparse_param **paramp = &ventry->params;

        next = ventry->next;

        if (!name) continue;
        if (!propval) continue;

        buf_reset(&buf);

        /* Find the most preferred properties (lowest PREF)
         *   AND
         * Replace MEDIATYPE with TYPE=<subtype>
         */
        while (*paramp) {
            vparam = *paramp;

            if (!strcasecmpsafe(vparam->name, "pref") ||
                !strcasecmpsafe(vparam->name, "mediatype")) {

                if (strchr("Pp", vparam->name[0])) {
                    check_pref(ventry, name, atoi(vparam->value), &pref_table);
                }
                else {
                    buf_setcstr(&buf, vparam->value);
                }

                *paramp = vparam->next;
                vparam->next = NULL;
                vparse_free_param(vparam);
            }
            else {
                paramp = &vparam->next;
            }
        }

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
                const char *data = "";
                size_t typelen = 0;

                if (base64) {
                    vparse_add_param(ventry, "ENCODING", "b");

                    data = base64 + 8;
                    typelen = base64 - type;
                }
                else if ((data = strchr(type, ','))) {
                    typelen = data++ - type;
                }

                if (typelen) {
                    buf_setmap(&buf, type, typelen);
                }

                /* Reset the property value to just the binary data */
                memmove(ventry->v.value, data, strlen(data) + 1); // include NUL
            }
            else {
                vparse_add_param(ventry, "VALUE", "uri");
            }

            if (buf_len(&buf)) {
                /* Add TYPE=<subtype> parameter */
                const char *subtype = strchr(buf_ucase(&buf), '/');

                if (subtype) {
                    vparse_add_param(ventry, "TYPE", subtype + 1);
                }
            }
        }
        else if (!strcasecmp(name, "geo")) {
            /* Rewrite GEO property */
            if (!strncmp(propval, "geo:", 4)) {
                buf_setcstr(&buf, propval+4);
                buf_replace_char(&buf, ',', ';');
                vparse_set_value(ventry, buf_cstring(&buf));
            }
        }
        else if (!strcasecmp(name, "tz")) {
            /* Rewrite TZ property */
            vparam = vparse_get_param(ventry, "value");
            if (!vparam) {
                vparse_add_param(ventry, "VALUE", "text");
            }
            else if (!strcasecmpsafe(vparam->value, "utc-offset")) {
                unsigned hour, min = 0;
                char sign;
                sscanf(propval, "%c%02d%02d)", &sign, &hour, &min);
                buf_printf(&buf, "%c%02d:%02d", sign, hour, min);
                vparse_set_value(ventry, buf_cstring(&buf));
                vparse_delete_params(ventry, "value");
            }
        }
        else if (!strcasecmp(name, "tel")) {
            /* Rewrite TEL property from tel: uri to text */
            if (!strncmp(propval, "tel:", 4)) {
                buf_setcstr(&buf, propval + 4);
                vparse_set_value(ventry, buf_cstring(&buf));
                vparse_delete_params(ventry, "value");
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

    /* Add TYPE=pref parameter to preferred properties */
    hash_enumerate(&pref_table, &add_type_pref, (void *) 1);

    free_hash_table(&pref_table, free);
    buf_free(&buf);
}

static int vcard_value_is_uri(const char *val)
{
    if (!val) return 0;
    xmlURIPtr xuri = xmlParseURI(val);
    int is_uri = xuri && xuri->scheme;
    xmlFreeURI(xuri);
    return is_uri;
}

static const char *known_types[] = {
    "WORK", "HOME", "TEXT", "VOICE", "FAX", "CELL", "VIDEO", "PAGER", "TEXTPHONE",
    "CONTACT", "ACQUAINTANCE", "FRIEND", "MET", "CO-WORKER", "COLLEAGUE",
    "CO-RESIDENT", "NEIGHBOR", "CHILD", "PARENT", "SIBLING", "SPOUSE", "KIN",
    "MUSE", "CRUSH", "DATE", "SWEETHEART", "ME", "AGENT", "EMERGENCY", "PREF",
    "MAIN-NUMBER", "BILLING", "DELIVERY", NULL
};

EXPORTED void vcard_to_v4(struct vparse_card *vcard)
{
    struct vparse_entry *ventry, *next;
    struct vparse_param *vparam;
    struct buf buf = BUF_INITIALIZER;
    int is_v4 = 0;

    ventry = vparse_get_entry(vcard->objects, NULL, "VERSION");
    if (ventry) {
        char *val = vparse_get_value(ventry);
        is_v4 = !strcmpsafe("4.0", val);
        free(val);
    }

    for (ventry = vcard->objects->properties; ventry; ventry = next) {
        const char *name = ventry->name;
        const char *propval = ventry->v.value;
        struct vparse_param **paramp = &ventry->params;
        struct vparse_param *type = NULL;

        next = ventry->next;

        if (!name) continue;
        if (!propval) continue;

        buf_reset(&buf);

        while (*paramp) {
            vparam = *paramp;

            /* Replace TYPE=pref with PREF=1
             *   AND
             * Replace TYPE=subtype with MEDIATYPE or data:<mediatype>
             *
             * XXX  We assume that the first unknown TYPE is the subtype
             */
            if (vparam->value && !strcasecmpsafe(vparam->name, "type")) {
                const char **val = known_types;

                for (; *val && strcasecmp(*val, vparam->value); val++);
                if (!*val) {
                    *paramp = vparam->next;
                    vparam->next = NULL;
                    type = vparam;
                    continue;
                }
                else if (!strcmp(*val, "PREF")) {
                    *paramp = vparam->next;
                    vparam->next = NULL;
                    vparse_free_param(vparam);

                    vparse_add_param(ventry, "PREF", "1");
                    continue;
                }
            }

            paramp = &vparam->next;
        }

        if (!is_v4 && !strcasecmp(name, "version")) {
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
            else if (!is_v4 && strncmp(propval, "urn:uuid:", 9)) {
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
            if (type) {
                switch (toupper(name[0])) {
                case 'K':
                    buf_appendcstr(&buf, lcase(type->value));
                    break;
                case 'S':
                    buf_printf(&buf, "audio/%s", lcase(type->value));
                    break;
                default:
                    buf_printf(&buf, "image/%s", lcase(type->value));
                    break;
                }

                vparse_free_param(type);
                type = NULL;
            }

            vparam = vparse_get_param(ventry, "value");

            if ((vparam && strcasecmp(vparam->value, "uri")) ||
                vparse_get_param(ventry, "encoding") ||
                !vcard_value_is_uri(propval)) {
                /* Rewrite 'b' encoded value as data: URI */
                buf_insertcstr(&buf, 0, "data:");

                vparam = vparse_get_param(ventry, "encoding");
                if (vparam && !strcasecmpsafe(vparam->value, "b")) {
                    buf_appendcstr(&buf, ";base64");
                }
                vparse_delete_params(ventry, "encoding");

                buf_printf(&buf, ",%s", propval);
                vparse_set_value(ventry, buf_cstring(&buf));
            }
            else {
                vparse_delete_params(ventry, "value");

                if (buf_len(&buf)) {
                    /* Add MEDIATYPE parameter */
                    vparse_add_param(ventry, "MEDIATYPE", buf_cstring(&buf));
                }
            }
        }
        else if (!strcasecmp(name, "geo")) {
            /* Rewrite GEO property */
            if (strncmp(propval, "geo:", 4)) {
                buf_setcstr(&buf, "geo:");
                buf_appendcstr(&buf, propval);
                buf_replace_char(&buf, ';', ',');
                vparse_set_value(ventry, buf_cstring(&buf));
            }
        }
        else if (!strcasecmp(name, "TZ")) {
            /* Rewrite TZ property */
            vparam = vparse_get_param(ventry, "value");
            if (!vparam) {
                buf_setcstr(&buf, propval);
                buf_replace_all(&buf, ":", "");
                vparse_set_value(ventry, buf_cstring(&buf));
                vparse_add_param(ventry, "VALUE", "utc-offset");
            }
            else if (!strcasecmpsafe(vparam->value, "text")) {
                vparse_delete_params(ventry, "value");
            }
        }
        else if (!strncasecmp(name, "x-addressbookserver-", 20)) {
            /* Rename X-ADDRESSBOOKSERVER-* properties */
            char *newname = xstrdup(name+20);

            free(ventry->name);
            ventry->name = newname;
        }

        if (type) {
            /* Unused TYPE parameter - insert it back into the list */
            type->next = ventry->params;
            ventry->params = type;
        }
    }

    buf_free(&buf);
}

#ifdef HAVE_LIBICALVCARD

EXPORTED  vcardcomponent *vcard_parse_string_x(const char *str)
{
    vcardcomponent *vcard = vcardcomponent_new_from_string(str);

    /* Remove all X-LIC-ERROR properties */
    if (vcard) vcardcomponent_strip_errors(vcard);

    return vcard;
}

EXPORTED vcardcomponent *vcard_parse_buf_x(const struct buf *buf)
{
    return vcardparser_parse_string(buf_cstring(buf));
}

EXPORTED struct buf *vcard_as_buf_x(vcardcomponent *vcard)
{
    char *str = vcardcomponent_as_vcard_string_r(vcard);
    struct buf *ret = buf_new();

    if (str) buf_initm(ret, str, strlen(str));

    return ret;
}

EXPORTED vcardcomponent *record_to_vcard_x(struct mailbox *mailbox,
                                           const struct index_record *record)
{
    struct buf buf = BUF_INITIALIZER;
    vcardcomponent *vcard = NULL;

    /* Load message containing the resource and parse vCard data */
    if (!mailbox_map_record(mailbox, record, &buf)) {
        vcard = vcard_parse_string_x(buf_cstring(&buf) + record->header_size);
        buf_free(&buf);
    }

    return vcard;
}

EXPORTED size_t vcard_prop_decode_value_x(vcardproperty *prop,
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

#endif /* HAVE_LIBVCARDVCARD */
