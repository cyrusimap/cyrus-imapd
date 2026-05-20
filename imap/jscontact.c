/* jscontact.c -- Routines for converting JSContact and vCard */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>

#include <string.h>
#include <syslog.h>

#include <libxml/uri.h>

#include "hash.h"
#include "http_dav.h"
#include "jmap_api.h"
#include "jscontact.h"
#include "json_support.h"
#include "mailbox.h"
#include "mkgmtime.h"
#include "times.h"
#include "tok.h"
#include "util.h"
#include "vcard_support.h"
#include "xmalloc.h"

/* generated headers are not necessarily in current directory */
#include "imap/http_err.h"
#include "imap/jmap_props/contact_card.h"

static json_t *jscard_from_vcard(jscontact_ctx_t *ctx, vcardcomponent *vcard);

static void jscard_to_vcard(jscontact_ctx_t *ctx, vcardcomponent *card,
                            json_t *arg, struct jmap_parser *parser);

HIDDEN json_t *jscontact_from_vcard(jscontact_ctx_t *ctx, vcardcomponent *vcard)
{
    jscontact_ctx_t myctx = { .set_vcard_convprops = true };

    return jscard_from_vcard(ctx ? ctx : &myctx, vcard);
}

HIDDEN vcardcomponent *jscontact_to_vcard(jscontact_ctx_t *ctx,
                                          json_t *jcard,
                                          struct jmap_parser *parser)
{
    jscontact_ctx_t myctx = { 0 };

    if (!ctx) ctx = &myctx;

    vcardcomponent *card =
        vcardcomponent_vanew(VCARD_VCARD_COMPONENT,
                             vcardproperty_new_version(VCARD_VERSION_40),
                             NULL);

    // Set UID. JMAP ContactCard/set take care of this, too.
    if (ctx->uid_prop) {
        vcardcomponent_add_property(card, vcardproperty_clone(ctx->uid_prop));
    }
    else {
        const char *uid = ctx->uid;
        if (!uid) uid = json_string_value(json_object_get(jcard, "uid"));
        if (uid) {
            vcardproperty *uidprop = vcardproperty_new_uid(uid);
            xmlURIPtr xuri = xmlParseURI(uid);
            if (!xuri || !xuri->scheme) {
                vcardproperty_set_value(uidprop, vcardvalue_new_text(uid));
            }
            xmlFreeURI(xuri);
            vcardcomponent_add_property(card, uidprop);
        }
    }

    jscard_to_vcard(ctx, card, jcard, parser);

    if (json_array_size(parser->invalid) || ctx->blob_error) {
        vcardcomponent_free(card);
        card = NULL;
    }

    return card;
}

/*****************************************************************************
 * The remainder of this file is verbatim from jmap_contact.c
 ****************************************************************************/

static json_t *jmap_utf8string(const char *s)
{
    struct buf buf = BUF_INITIALIZER;
    jmap_decode_to_utf8("utf-8", ENCODING_NONE, s, strlen(s), 1.0, &buf, NULL);
    json_t *jval = json_string(buf_cstring(&buf));
    buf_free(&buf);
    return jval;
}

struct comp_kind {
    unsigned idx;      /* index of vCard property field  */
    const char *name;  /* name of JSContact component    */
    unsigned flags;    /* flags dictating field handling */
    unsigned alt_idx;  /* idx of related vCard field     */
};

/* Flags governing conversion to/from vCard */
#define FIELD_BWD  (1<<0)  /* To vCard:
                              Add value to the legacy (backward-compat) field  */
#define FIELD_NOEX (1<<1)  /* To vCard:
                              Extended vCard fields aren't needed for this
                              field alone since the same-named JS component
                              maps to a legacy field                           */
#define FIELD_SKIP (1<<2)  /* To vCard:
                              Skip this field entirely
                              From vCard:
                              Skip this field if the extended field exists     */
#define FIELD_VAL  (1<<3)  /* From vCard:
                              Ignore value if it appears in the extended field */

/* JSContact Name components - ordered per vcard_n_field */
// clang-format off
static const struct comp_kind n_comp_kinds[] = {
    { VCARD_N_FAMILY,          "surname",       FIELD_VAL,  VCARD_N_SECONDARY  },
    { VCARD_N_GIVEN,           "given",         0,          0                  },
    { VCARD_N_ADDITIONAL,      "given2",        0,          0                  },
    { VCARD_N_PREFIX,          "title",         0,          0                  },
    { VCARD_N_SUFFIX,          "credential",    FIELD_VAL,  VCARD_N_GENERATION },
    /* Extended fields (RFC 9554) */
    { VCARD_N_SECONDARY,       "surname2",      FIELD_BWD,  VCARD_N_FAMILY     },
    { VCARD_N_GENERATION,      "generation",    FIELD_BWD,  VCARD_N_SUFFIX     },
    { 0,                       NULL,            0,          0                  }
};
// clang-format on

/* JSContact Address components - ordered per vcard_adr_field */
// clang-format off
static const struct comp_kind adr_comp_kinds[] = {
    { VCARD_ADR_PO_BOX,        "postOfficeBox", 0,          0                  },
    { VCARD_ADR_EXTENDED,      "apartment",     FIELD_SKIP, VCARD_ADR_APARTMENT },
    { VCARD_ADR_STREET,        "name",          FIELD_SKIP, VCARD_ADR_STREET_NUMBER },
    { VCARD_ADR_LOCALITY,      "locality",      0,          0                  },
    { VCARD_ADR_REGION,        "region",        0,          0                  },
    { VCARD_ADR_POSTAL_CODE,   "postcode",      0,          0                  },
    { VCARD_ADR_COUNTRY,       "country",       0,          0                  },
    /* Extended fields (RFC 9554) */
    { VCARD_ADR_ROOM,          "room",          FIELD_BWD,  VCARD_ADR_EXTENDED },
    { VCARD_ADR_APARTMENT,     "apartment",     FIELD_BWD |
                                                FIELD_NOEX, VCARD_ADR_EXTENDED },
    { VCARD_ADR_FLOOR,         "floor",         FIELD_BWD,  VCARD_ADR_EXTENDED },
    { VCARD_ADR_STREET_NUMBER, "number",        FIELD_BWD,  VCARD_ADR_STREET   },
    { VCARD_ADR_STREET_NAME,   "name",          FIELD_BWD |
                                                FIELD_NOEX, VCARD_ADR_STREET   },
    { VCARD_ADR_BUILDING,      "building",      FIELD_BWD,  VCARD_ADR_EXTENDED },
    { VCARD_ADR_BLOCK,         "block",         FIELD_BWD,  VCARD_ADR_STREET   },
    { VCARD_ADR_SUBDISTRICT,   "subdistrict",   FIELD_BWD,  VCARD_ADR_STREET   },
    { VCARD_ADR_DISTRICT,      "district",      FIELD_BWD,  VCARD_ADR_STREET   },
    { VCARD_ADR_LANDMARK,      "landmark",      FIELD_BWD,  VCARD_ADR_STREET   },
    { VCARD_ADR_DIRECTION,     "direction",     FIELD_BWD,  VCARD_ADR_STREET   },
    { 0,                       NULL,            0,          0                  }
};
// clang-format on

#define ALLOW_CALSCALE_PARAM      (1<<0)
#define ALLOW_INDEX_PARAM         (1<<1)
#define ALLOW_LANGUAGE_PARAM      (1<<2)
#define ALLOW_LABEL_PARAM         (1<<3)
#define ALLOW_LEVEL_PARAM         (1<<4)
#define ALLOW_MEDIATYPE_PARAM     (1<<5)
#define ALLOW_PREF_PARAM          (1<<6)
#define ALLOW_SERVICETYPE_PARAM   (1<<7)
#define ALLOW_TYPE_PARAM          (1<<8)
#define ALLOW_USERNAME_PARAM      (1<<9)

static const char *_prop_id(vcardproperty *prop)
{
    static struct message_guid guid = MESSAGE_GUID_INITIALIZER;
    vcardparameter *param =
        vcardproperty_get_first_parameter(prop, VCARD_PROPID_PARAMETER);

    /* Use PROP-ID if we have it */
    if (param) {
        return vcardparameter_get_propid(param);
    }
    else {
        /* Otherwise, use hash of property value */
        const char *value = vcardproperty_get_value_as_string(prop);

        message_guid_generate(&guid, value, strlen(value));

        return message_guid_encode(&guid);
    }
}

static char *_value_to_uri_blobid(vcardproperty *prop,
                                  struct mailbox *mailbox,
                                  struct index_record *record,
                                  vcardproperty_version version,
                                  char **type, char **blobid)
{
    const char *val;

    val = vcardvalue_as_vcard_string(vcardproperty_get_value(prop));

    if (!blobid && version == VCARD_VERSION_40) {
        return xstrdup(val);
    }

    struct message_guid guid;
    size_t size = vcard_prop_decode_value(prop, NULL, type, &guid);

    if (size) {
        vcardparameter *param =
            vcardproperty_get_first_parameter(prop, VCARD_ENCODING_PARAMETER);
        struct buf buf = BUF_INITIALIZER;

        if (!*type) *type = xstrdup("application/octet-stream");

        if (param) {
            vcardproperty_remove_parameter_by_ref(prop, param);
            vcardproperty_remove_parameter_by_kind(prop, VCARD_TYPE_PARAMETER);
        }

        if (mailbox && record && blobid) {
            const char *prop_name = vcardproperty_get_property_name(prop);

            jmap_encode_rawdata_blobid('V', mailbox_uniqueid(mailbox),
                                       record->uid, NULL, NULL,
                                       prop_name, &guid, &buf);
            *blobid = buf_release(&buf);
            return NULL;
        }
        else if (param) {
            /* Build data: uri */
            buf_printf(&buf, "data:%s;base64,%s",
                       *type, vcardvalue_get_uri(vcardproperty_get_value(prop)));
            return buf_release(&buf);
        }
    }

    return xstrdup(val);
}

static json_t *vcardtime_to_jmap_utcdate(vcardtimetype t)
{
    char datestr[ISO8601_DATETIME_MAX+1] = "";
    struct tm tm = { 0 };

    tm.tm_sec = t.second;
    tm.tm_min = t.minute;
    tm.tm_hour = t.hour;
    tm.tm_mday = t.day;
    tm.tm_mon = t.month - 1;
    tm.tm_year = t.year - 1900;
    tm.tm_isdst = -1;

    time_to_iso8601(mkgmtime(&tm) - (t.utcoffset * 60),
                    datestr, sizeof(datestr), 1);

    return json_string(datestr);
}

static json_t *_to_jmap_date(vcardproperty *prop)
{
    vcardtimetype date = vcardproperty_get_bday(prop);

    if (vcardtime_is_timestamp(date)) {
        return json_pack("{s:s s:o}",
                         "@type", "Timestamp",
                         "utc", vcardtime_to_jmap_utcdate(date));
    }

    int y = date.year, m = date.month, d = date.day;
    json_t *jdate = json_object();
    vcardparameter *param;

    for (param = vcardproperty_get_first_parameter(prop, VCARD_X_PARAMETER);
         param;
         param = vcardproperty_get_next_parameter(prop, VCARD_X_PARAMETER)) {
        const char *param_name = vcardparameter_get_xname(param);

        if (!strcasecmp(param_name, "X-APPLE-OMIT-YEAR")) {
            /* XXX compare value with actual year? */
            y = 0;
        }
        else if (!strncasecmp(param_name, "X-FM-NO-", 8)) {
            param_name += 8;

            if (!strcasecmp(param_name, "MONTH"))
                m = 0;
            else if (!strcasecmp(param_name, "DAY"))
                d = 0;
        }
    }

    /* sigh, magic year 1604 has been seen without X-APPLE-OMIT-YEAR, making
     * me wonder what the bloody point is */
    if (y > 0 && y != 1604) json_object_set_new(jdate, "year",  json_integer(y));
    if (m > 0) json_object_set_new(jdate, "month", json_integer(m));
    if (d > 0) json_object_set_new(jdate, "day",   json_integer(d));

    return jdate;
}

static void _unmapped_param(json_t *obj,
                            vcardparameter *param, char *param_value)
{
    vcardparameter_kind param_kind = vcardparameter_isa(param);
    json_t *params = json_object_get_vanew(obj, "vCardParams", "{}");
    struct buf buf = BUF_INITIALIZER;

    if (param_kind == VCARD_IANA_PARAMETER) {
        buf_setcstr(&buf, vcardparameter_get_iana_name(param));
    }
    else if (param_kind == VCARD_X_PARAMETER) {
        buf_setcstr(&buf, vcardparameter_get_xname(param));
    }
    else {
        buf_setcstr(&buf, vcardparameter_kind_to_string(param_kind));
    }

    json_object_set_new(params, buf_lcase(&buf), jmap_utf8string(param_value));

    buf_free(&buf);
}

static void _add_vcard_params(json_t *obj, vcardproperty *prop,
                              unsigned param_flags, bool convert_unknown)
{
    vcardproperty_kind prop_kind = vcardproperty_isa(prop);
    struct buf buf = BUF_INITIALIZER;
    vcardparameter *param;

    for (param = vcardproperty_get_first_parameter(prop, VCARD_ANY_PARAMETER);
         param;
         param = vcardproperty_get_next_parameter(prop, VCARD_ANY_PARAMETER)) {
        vcardparameter_kind param_kind = vcardparameter_isa(param);
        char *param_str = vcardparameter_as_vcard_string(param);
        char *param_value = strchr(param_str, '=') + 1;
        const char *key = NULL;

        switch (param_kind) {
        case VCARD_ALTID_PARAMETER:
            /* Handled by localization code */
            continue;

        case VCARD_AUTHOR_PARAMETER:
            key = "uri";

            GCC_FALLTHROUGH

        case VCARD_AUTHORNAME_PARAMETER:
            if (!key) key = "name";

            if (prop_kind == VCARD_NOTE_PROPERTY) {
                json_t *author =
                    json_object_get_vanew(obj, "author", "{}");

                json_object_set_new(author, key,
                                    json_string(param_value));
                continue;
            }
            break;

        case VCARD_CALSCALE_PARAMETER:
            if (param_flags & ALLOW_CALSCALE_PARAM) {
                json_object_set_new(obj, "calendarScale",
                                    json_string(lcase(param_value)));
                continue;
            }
            break;

        case VCARD_CC_PARAMETER:
            if (prop_kind == VCARD_ADR_PROPERTY) {
                json_object_set_new(obj, "countryCode",
                                    json_string(lcase(param_value)));
                continue;
            }
            break;

        case VCARD_CREATED_PARAMETER:
            if (prop_kind == VCARD_NOTE_PROPERTY) {
                vcardtimetype time = vcardparameter_get_created(param);
                char datestr[ISO8601_DATETIME_MAX];

                sprintf(datestr, "%4d-%02d-%02dT%02d:%02d:%02d",
                        time.year, time.month, time.day,
                        time.hour, time.minute, time.second);
                if (time.utcoffset) {
                    sprintf(datestr + strlen(datestr), "%+03d:%02d",
                            time.utcoffset / 60, abs(time.utcoffset % 60));
                }
                else {
                    strcat(datestr, "Z");
                }

                json_object_set_new(obj, "created", json_string(datestr));
                continue;
            }
            break;

        case VCARD_GEO_PARAMETER:
            if (prop_kind == VCARD_ADR_PROPERTY) {
                json_object_set_new(obj, "coordinates",
                                    json_string(param_value));
                continue;
            }
            break;

        case VCARD_INDEX_PARAMETER:
            if (param_flags & ALLOW_INDEX_PARAM) {
                json_object_set_new(obj, "listAs",
                                    json_integer(vcardparameter_get_index(param)));
                continue;
            }
            break;

        case VCARD_LANGUAGE_PARAMETER:
            /* Handled by localization code */
            continue;

        case VCARD_LABEL_PARAMETER:
            /* Should be handled by the properties that use it */
            break;

        case VCARD_LEVEL_PARAMETER:
            if (param_flags & ALLOW_LEVEL_PARAM) {
                const char *level = NULL;

                switch (vcardparameter_get_level(param)) {
                case VCARD_LEVEL_LOW:
                case VCARD_LEVEL_BEGINNER:
                    level = "low";
                    break;

                case VCARD_LEVEL_MEDIUM:
                case VCARD_LEVEL_AVERAGE:
                    level = "medium";
                    break;

                case VCARD_LEVEL_HIGH:
                case VCARD_LEVEL_EXPERT:
                    level = "high";
                    break;

                default:
                    break;
                }

                if (level) {
                    json_object_set_new(obj, "level", json_string(level));
                    continue;
                }
            }
            break;

        case VCARD_MEDIATYPE_PARAMETER:
            if (param_flags & ALLOW_MEDIATYPE_PARAM) {
                json_object_set_new(obj, "mediaType",
                                    json_string(param_value));
                continue;
            }
            break;

        case VCARD_PREF_PARAMETER:
            if (param_flags & ALLOW_PREF_PARAM) {
                json_object_set_new(obj, "pref",
                                    json_integer(vcardparameter_get_pref(param)));
                continue;
            }
            break;

        case VCARD_PROPID_PARAMETER:
            /* Should be handled by the properties that use it */
            continue;

        servicetype:
        case VCARD_SERVICETYPE_PARAMETER:
            if (param_flags & ALLOW_SERVICETYPE_PARAM) {
                json_object_set_new(obj, "service", json_string(param_value));
                continue;
            }
            break;

        case VCARD_TYPE_PARAMETER:
            if (param_flags & ALLOW_TYPE_PARAM) {
                vcardenumarray *array = vcardparameter_get_type(param);

                for (size_t i = 0; i < vcardenumarray_size(array); i++) {
                    const vcardenumarray_element *e =
                        vcardenumarray_element_at(array, i);
                    const char *type = NULL, *val = NULL;

                    switch (e->val) {
                    case VCARD_TYPE_PREF:
                        if (param_flags & ALLOW_PREF_PARAM) {
                            /* v3 TYPE=PREF */
                            json_object_set_new(obj, "pref", json_integer(1));
                            continue;
                        }
                        break;

                    case VCARD_TYPE_HOME:
                        val = "private";

                        GCC_FALLTHROUGH

                    case VCARD_TYPE_WORK:
                        type = "contexts";
                        break;

                    case VCARD_TYPE_BILLING:
                    case VCARD_TYPE_DELIVERY:
                        if (prop_kind == VCARD_ADR_PROPERTY) {
                            type = "contexts";
                        }
                        break;

                    case VCARD_TYPE_CELL:
                        val = "mobile";

                        GCC_FALLTHROUGH

                    case VCARD_TYPE_TEXT:
                    case VCARD_TYPE_VOICE:
                    case VCARD_TYPE_FAX:
                    case VCARD_TYPE_VIDEO:
                    case VCARD_TYPE_PAGER:
                    case VCARD_TYPE_TEXTPHONE:
                    case VCARD_TYPE_MAINNUMBER:
                        if (prop_kind == VCARD_TEL_PROPERTY) {
                            type = "features";
                        }
                        break;

                    default:
                        if (prop_kind == VCARD_RELATED_PROPERTY) {
                            type = "relation";
                        }
                        else if (param_flags & ALLOW_SERVICETYPE_PARAM) {
                            goto servicetype;
                        }
                        break;
                    }

                    if (type) {
                        json_t *jprop = json_object_get_vanew(obj, type, "{}");

                        if (!val) {
                            if (e->xvalue) {
                                val = e->xvalue;
                            }
                            else {
                                buf_setcstr(&buf,
                                            vcardparameter_enum_to_string(e->val));
                                val = buf_lcase(&buf);
                            }
                        }

                        json_object_set_new(jprop, val, json_true());
                    }
                    else if (convert_unknown) {
                        /* Unknown/unexpected TYPE */
                        _unmapped_param(obj, param, param_value);
                    }
                }
            }
            continue;

        case VCARD_TZ_PARAMETER:
            if (prop_kind == VCARD_ADR_PROPERTY) {
                /* XXX  TODO: Check for URI or UTC-OFFSET */
                json_object_set_new(obj, "timeZone",
                                    json_string(param_value));
                continue;
            }
            break;

        username:
        case VCARD_USERNAME_PARAMETER:
            if (param_flags & ALLOW_USERNAME_PARAM) {
                json_object_set_new(obj, "user", jmap_utf8string(param_value));
                continue;
            }
            break;

        case VCARD_VALUE_PARAMETER:
            /* Should be handled by the properties that use it */
            continue;

        case VCARD_X_PARAMETER:
            if ((param_flags & ALLOW_SERVICETYPE_PARAM) &&
                !strcasecmp(vcardparameter_get_xname(param), "X-SERVICE-TYPE")) {
                goto servicetype;
            }
            else if ((param_flags & ALLOW_USERNAME_PARAM) &&
                !strcasecmp(vcardparameter_get_xname(param), "X-USER")) {
                goto username;
            }
            break;

        default:
            break;
        }

        if (convert_unknown) {
            /* Unknown/unexpected parameter [value]*/
            _unmapped_param(obj, param, param_value);
        }
    }

    buf_free(&buf);
}

struct card_rock {
    json_t *card;
    json_t *patch;
    const char *deflang;
    hash_table *labels;
    hash_table *adrs;
    hash_table *orgs;
    jscontact_ctx_t *ctx;
    struct buf *buf;
    vcardproperty_version version;
};

static void jscomps_from_vcard(json_t *obj, vcardproperty *prop,
                               vcardstructuredtype *st,
                               const struct comp_kind *comp_kinds)
{
    vcardparameter *param;
    vcardstrarray *sa;
    const char *val, *val_prop_name = "value";
    json_t *comps, *comp = NULL;
    size_t i, j = 0;

    param = vcardproperty_get_first_parameter(prop, VCARD_PHONETIC_PARAMETER);
    if (param) {
        vcardparameter_phonetic phonetic = vcardparameter_get_phonetic(param);
        struct buf buf = BUF_INITIALIZER;

        if (phonetic == VCARD_PHONETIC_X) {
            buf_setcstr(&buf, vcardparameter_get_xvalue(param));
        }
        else {
            buf_setcstr(&buf, vcardparameter_enum_to_string(phonetic));
            buf_lcase(&buf);
        }
        json_object_set_new(obj, "phoneticSystem",
                            json_string(buf_cstring(&buf)));
        buf_free(&buf);

        val_prop_name = "phonetic";

        /* Remove PHONETIC parameter */
        vcardproperty_remove_parameter_by_ref(prop, param);
    }

    param = vcardproperty_get_first_parameter(prop, VCARD_SCRIPT_PARAMETER);
    if (param) {
        json_object_set_new(obj, "phoneticScript",
                            json_string(vcardparameter_get_script(param)));

        /* Remove SCRIPT parameter */
        vcardproperty_remove_parameter_by_ref(prop, param);
    }

    param = vcardproperty_get_first_parameter(prop, VCARD_JSCOMPS_PARAMETER);
    if (param) {
        /* Validate the JSCOMPS references. If any is false, ignore JSCOMPS. */
        vcardstructuredtype *jscomps = vcardparameter_get_jscomps(param);
        size_t num_jscomps = vcardstructured_num_fields(jscomps);
        size_t num_comp_kinds = 0;

        while (comp_kinds[num_comp_kinds].name) num_comp_kinds++;

        for (i = 1; i < num_jscomps; i++) {
            sa = vcardstructured_field_at(jscomps, i);
            val = vcardstrarray_element_at(sa, 0);
            if (!val) break;

            if (*val == 's') {
                /* separator: must carry a value */
                if (!vcardstrarray_element_at(sa, 1)) break;
            }
            else {
                int field_idx = atoi(val);
                int val_idx = 0;

                if (field_idx < 0 ||
                    field_idx >= (int) vcardstructured_num_fields(st) ||
                    field_idx >= (int) num_comp_kinds) break;

                if (vcardstrarray_size(sa) > 1)
                    val_idx = atoi(vcardstrarray_element_at(sa, 1));

                val = vcardstrarray_element_at(
                        vcardstructured_field_at(st, field_idx), val_idx);
                if (!val || !*val) break;
            }
        }

        if (i < num_jscomps) {
            /* Bogus reference: drop the JSCOMPS parameter */
            vcardproperty_remove_parameter_by_ref(prop, param);
            param = NULL;
        }
    }

    if (param) {
        /* Order components per JSCOMPS */
        vcardstructuredtype *jscomps = vcardparameter_get_jscomps(param);

        json_object_set_new(obj, "isOrdered", json_true());

        sa = vcardstructured_field_at(jscomps, 0);
        if (sa) {
            /* add default separator, if not " " */
            val = vcardstrarray_element_at(sa, 1);
            if (strcmpsafe(" ", val)) {
                json_object_set_new(obj, "defaultSeparator", json_string(val));
            }
        }

        for (i = 1; i < vcardstructured_num_fields(jscomps); i++) {
            const char *kind;

            sa = vcardstructured_field_at(jscomps, i);
            val = vcardstrarray_element_at(sa, 0);
            if (*val == 's') {
                kind = "separator";
                val = vcardstrarray_element_at(sa, 1);
            }
            else {
                int field_idx = atoi(val);
                int val_idx = 0;

                if (field_idx >= (int) vcardstructured_num_fields(st)) continue;

                kind = comp_kinds[field_idx].name;

                if (vcardstrarray_size(sa) > 1)
                    val_idx = atoi(vcardstrarray_element_at(sa, 1));

                val = vcardstrarray_element_at(vcardstructured_field_at(st, field_idx), val_idx);
            }

            if (*val) {
                /* This assumes that JSCOMPS are identical
                   for props paired by ALTID */
                comps = json_object_get_vanew(obj, "components", "[]");
                if (json_array_size(comps) > j) {
                    /* Grab the existing component by position */
                    comp = json_array_get(comps, j);
                }
                else {
                    comp = json_pack("{s:s}", "kind", kind);
                    json_array_append_new(comps, comp);
                }
                json_object_set_new(comp, val_prop_name, jmap_utf8string(val));
                j++;
            }
        }

        /* Remove JSCOMPS parameter */
        vcardproperty_remove_parameter_by_ref(prop, param);
        return;
    }

    /* Iterate through all components and values */
    for (const struct comp_kind *ckind = comp_kinds;
         ckind->name && ckind->idx < vcardstructured_num_fields(st); ckind++) {
        if ((ckind->flags & FIELD_SKIP) &&
            vcardstructured_num_fields(st) > ckind->alt_idx) {
            continue;
        }

        sa = vcardstructured_field_at(st, ckind->idx);
        for (i = 0; sa && i < vcardstrarray_size(sa); i++) {
            val = vcardstrarray_element_at(sa, i);

            if (*val) {
                /* Skip legacy values that appear in extended fields */
                if (ckind->flags & FIELD_VAL) {
                    vcardstrarray *alt_sa = vcardstructured_field_at(st, ckind->alt_idx);
                    if (alt_sa
                        && vcardstrarray_find(alt_sa, val)
                               < vcardstrarray_size(alt_sa))
                        continue;
                }

                comps = json_object_get_vanew(obj, "components", "[]");
                if (json_array_size(comps) > j) {
                    size_t k;

                    /* Find the existing component by name */
                    json_array_foreach(comps, k, comp) {
                        if (!strcmp(ckind->name,
                                    json_string_value(json_object_get(comp, "kind")))) {
                            break;
                        }
                    }
                    if (k > json_array_size(comps)) continue;
                }
                else {
                    comp = json_pack("{s:s}", "kind", ckind->name);
                    json_array_append_new(comps, comp);
                }
                json_object_set_new(comp, val_prop_name, jmap_utf8string(val));
                j++;
            }
        }
    }
}

static void vcardvalues_to_json(const char *values, vcardvalue_kind vkind,
                                json_t *jvals)
{
    const char *val, *p = strchr(values, ',');
    tok_t vals = { 0 };

    if (p && (p == values || p[-1] != '\\')) {
        tok_init(&vals, values, ",", TOK_EMPTY);
        val = tok_next(&vals);
    }
    else {
        val = values;
    }

    do {
        json_t *jval = NULL;

        switch (vkind) {
        case VCARD_BOOLEAN_VALUE:
            jval = json_boolean(!strcasecmp("TRUE", val));
            break;

        case VCARD_INTEGER_VALUE: {
            /* Could we do anything useful with endptr?
               At this point we just trust that the stored vCard is valid */
            int64_t i64 = strtoll(val, NULL, 10);
            jval = json_integer(i64);
            break;
        }

        case VCARD_FLOAT_VALUE: {
            /* Could we do anything useful with endptr?
               At this point we just trust that the stored vCard is valid */
            double d = strtod(val, NULL);
            jval = json_real(d);
            break;
        }

        default: {
            char *dequoted = vcardvalue_strdup_and_dequote_text(&val, NULL);
            jval = jmap_utf8string(dequoted);
            free(dequoted);
            break;
        }
        }

        json_array_append_new(jvals, jval);

    } while ((val = tok_next(&vals)));

    tok_fini(&vals);
}

static json_t *_jsonline_from_vcard(vcardproperty *prop,
                                    const char *prop_id,
                                    json_t *obj,
                                    bool set_vcard_convprops,
                                    unsigned *param_flags)
{
    json_t *jprop = NULL;

    const char *prop_name = vcardproperty_get_property_name(prop);

    if (!strcasecmpsafe("X-CYRUS-ONLINESERVICE", prop_name)) {
        // This property has a structured value in form "<user>;<uri>".
        const char *val = vcardproperty_get_value_as_string(prop);
        if (!val) goto done;

        vcardstructuredtype *stt = vcardstructured_new_from_string(val);
        if (!stt) goto done;

        // At least one of user and uri must be set.
        const char *user = NULL, *uri = NULL;
        if (vcardstructured_num_fields(stt) == 2) {
            if (vcardstrarray_size(vcardstructured_field_at(stt, 0)) == 1) {
                user = vcardstrarray_element_at(vcardstructured_field_at(stt, 0), 0);
                if (!strlen(user)) user = NULL;
            }
            if (vcardstrarray_size(vcardstructured_field_at(stt, 1)) == 1) {
                uri = vcardstrarray_element_at(vcardstructured_field_at(stt, 1), 0);
                if (!strlen(uri)) uri = NULL;
            }
        }

        if (!user && !uri) {
            vcardstructured_unref(stt);
            goto done;
        }

        // Convert OnlineService object.
        jprop = json_pack("{s:s* s:s*}", "user", user, "uri", uri);
        vcardstructured_unref(stt);

        *param_flags =
            ALLOW_TYPE_PARAM | ALLOW_PREF_PARAM | ALLOW_LABEL_PARAM |
            ALLOW_SERVICETYPE_PARAM;
    }
    else if (!strcasecmpsafe("X-FM-ONLINE-OTHER", prop_name)) {
        // This property was set prior to JMAP for Contacts.
        // We'll convert it to an OnlineService but convert
        // it back to vCard using a different property kind.
        const char *val = vcardproperty_get_value_as_string(prop);
        if (!val || !strlen(val)) goto done;

        // Determine if the value begins with an URI scheme and
        // contains some data in addition to that scheme.
        // For URI scheme definition, see RFC 3986 Section 3.1.
        bool has_scheme = false;
        const char *p = strchr(val, ':');
        if (p && p[1] && isalnum(val[0])) {
            has_scheme = true;
            for (const char *s = val + 1; s < p; s++) {
                if (!isalpha(*s) && !strchr("+-.", *s)) {
                    has_scheme = false;
                    break;
                }
            }
        }

        // Convert OnlineService object.
        jprop = json_pack("{s:s}", has_scheme ? "uri" : "user", val);

        vcardparameter *param =
            vcardproperty_get_first_parameter(prop, VCARD_LABEL_PARAMETER);
        if (param) {
            const char *label = vcardparameter_get_label(param);
            json_object_set_new(jprop, "service", json_string(label));
            // Remove parameter, we neither want it later to get
            // converted to the "label" property nor preserved as
            // an unknown vCard parameter.
            vcardproperty_remove_parameter_by_ref(prop, param);
        }
    }
    else if (!strcasecmpsafe("X-SOCIAL-PROFILE", prop_name)) {
        // This property was set prior to JMAP for Contacts.
        // Not to be confused with Apple's X-SOCIALPROFILE.
        // We'll convert it to an OnlineService but convert
        // it back to vCard using a different property kind.
        const char *uri = vcardproperty_get_value_as_string(prop);
        if (uri && !strlen(uri)) uri = NULL;

        const char *user = NULL;
        vcardparameter *param =
            vcardproperty_get_parameter_by_name(prop, "X-USER");
        if (param) {
            user = vcardparameter_get_x(param);
            if (!strlen(user)) user = NULL;
        }

        // At least one of user and uri must be set.
        if (!uri && !user) goto done;

        const char *service = NULL;
        for (param = vcardproperty_get_first_parameter(prop, VCARD_TYPE_PARAMETER);
             param;
             param = vcardproperty_get_next_parameter(prop, VCARD_TYPE_PARAMETER)) {
            const vcardenumarray_element *elem =
                vcardenumarray_element_at(vcardparameter_get_type(param), 0);
            if (elem && elem->xvalue) {
                service = elem->xvalue;
            }
        }

        // Convert OnlineService object.
        jprop = json_pack("{s:s* s:s* s:s*}",
                "uri", uri, "user", user, "service", service);

        // Remove processed parameters, we don't want them to be
        // handled later as unknown parameters.
        vcardproperty_remove_parameter_by_name(prop, "TYPE");
        vcardproperty_remove_parameter_by_name(prop, "X-USER");
    }
    else if (!strcasecmpsafe("IMPP", prop_name)) {
        const char *uri = vcardproperty_get_impp(prop);
        if (!uri || !strlen(uri)) goto done;

        json_t *jvparams = NULL;

        // Support USERNAME parameter (defined in RFC 9554). Also
        // support X-USER, which some clients set. We'll keep track
        // of which parameter we used to set the 'user' property in
        // vCardParams, so that we know to convert that OnlineService
        // back to an IMPP property and that parameter if the 'user'
        // property is set.
        const char *user = NULL;
        vcardparameter *param =
            vcardproperty_get_first_parameter(prop, VCARD_USERNAME_PARAMETER);
        if (param) {
            user = vcardparameter_get_username(param);
            jvparams = json_pack("{s:s}", "username", user);
        }
        else {
            param = vcardproperty_get_parameter_by_name(prop, "X-USER");
            if (param) {
                user = vcardparameter_get_x(param);
                jvparams = json_pack("{s:s}", "x-user", user);
            }
        }

        jprop = json_pack("{s:s* s:s* s:o*}", "uri", uri, "user", user,
                          "vCardParams", jvparams);

        // Remove processed parameters, we don't want them to be
        // handled later as unknown parameters.
        vcardproperty_remove_parameter_by_name(prop, "USERNAME");
        vcardproperty_remove_parameter_by_name(prop, "X-USER");

        *param_flags =
            ALLOW_TYPE_PARAM | ALLOW_PREF_PARAM | ALLOW_LABEL_PARAM |
            ALLOW_SERVICETYPE_PARAM;
    }
    else if (!strcasecmpsafe("SOCIALPROFILE", prop_name)) {
        vcardvalue *val = vcardproperty_get_value(prop);
        const char *uri = NULL;
        const char *user = NULL;

        // Read property value.
        vcardparameter *param =
            vcardproperty_get_first_parameter(prop, VCARD_VALUE_PARAMETER);
        if (param) {
            switch (vcardparameter_get_value(param)) {
                case VCARD_VALUE_TEXT:
                    user = vcardvalue_get_text(val);
                    break;
                case VCARD_VALUE_URI:
                    uri = vcardvalue_get_uri(val);
                    break;
                default:
                    break;
            }
        }
        else {
            uri = vcardproperty_get_value_as_string(prop);
        }

        if (!uri && !user) goto done;

        if (!user) {
            // If we haven't read the user name from the property value,
            // try reading it from the USERNAME parameter.
            param =
                vcardproperty_get_first_parameter(prop, VCARD_USERNAME_PARAMETER);
            if (param)
                user = vcardparameter_get_username(param);
        }

        jprop = json_pack("{s:s* s:s*}", "uri", uri, "user", user);

        *param_flags =
            ALLOW_TYPE_PARAM | ALLOW_PREF_PARAM | ALLOW_LABEL_PARAM |
            ALLOW_SERVICETYPE_PARAM;
    }

    if (jprop) {
        struct buf buf = BUF_INITIALIZER;
        buf_setcstr(&buf, prop_name);
        if (set_vcard_convprops) {
            json_object_set_new(jprop, "vCardName", json_string(buf_lcase(&buf)));
        }
        buf_free(&buf);

        json_t *services = json_object_get_vanew(obj, "onlineServices", "{}");
        json_object_set_new(services, prop_id, jprop);
    }

done:
    return jprop;
}

static void jsprop_from_vcard(vcardproperty *prop, json_t *obj,
                              const char *prop_id, struct card_rock *crock)
{
    vcardparameter *param;

    if (crock->ctx->ignore_derived_props &&
        (param = vcardproperty_get_first_parameter(prop,
                                                   VCARD_DERIVED_PARAMETER)) &&

        vcardparameter_get_derived(param) == VCARD_DERIVED_TRUE) {
        /* Don't convert this property */
        return;
    }

    vcardproperty_kind prop_kind = vcardproperty_isa(prop);
    const char *prop_group = vcardproperty_get_group(prop);
    vcardvalue *value = vcardproperty_get_value(prop);
    const char *prop_value;
    const char *label = prop_group ?  /* Apple label? */
        hash_lookup(prop_group, crock->labels) : NULL;
    unsigned param_flags = 0;
    const char *kind = NULL;
    json_t *jprop = NULL;
    struct {
        const char *key;
        json_t *val;
    } subprop = { 0 };

    switch (vcardvalue_isa(value)) {
    case VCARD_X_VALUE:
        prop_value = vcardvalue_get_x(value);
        break;

    case VCARD_TEXT_VALUE:
        prop_value = vcardvalue_get_text(value);
        break;

    default:
        prop_value = vcardvalue_as_vcard_string(value);
        break;
    }

    switch (prop_kind) {
        /* Apple Properties */
    case VCARD_X_PROPERTY: {
        const char *prop_name = vcardproperty_get_property_name(prop);

        if (!strcmp(prop_name, "X-ADDRESSBOOKSERVER-KIND")) {
            goto kind;
        }
        else if (!strcmp(prop_name, "X-ADDRESSBOOKSERVER-MEMBER")) {
            goto member;
        }
        else if (!strcmp(prop_name, "X-FM-OTHERACCOUNT-MEMBER")) {
            if (!strncmp(prop_value, VCARD_MEMBER_URI_PREFIX,
                         VCARD_MEMBER_URI_PREFIX_LEN))
                prop_value += VCARD_MEMBER_URI_PREFIX_LEN;
            goto member;
        }
        else if (!strcasecmp(prop_name, "X-CYRUS-ONLINESERVICE")) {
            goto online;
        }
        else if (!strcasecmp(prop_name, "X-FM-ONLINE-OTHER")) {
            goto online;
        }
        else if (!strcasecmp(prop_name, "X-SOCIAL-PROFILE")) {
            goto online;
        }
        else if (prop_group) {
            if (!strcasecmp(prop_name, VCARD_APPLE_ABADR_PROPERTY)) {
                kind = "countryCode";
                buf_setcstr(crock->buf, prop_value);
                prop_value = buf_lcase(crock->buf);
                goto grouped_geo;
            }
            else if (!strcasecmp(prop_name, VCARD_APPLE_LABEL_PROPERTY)) {
                /* Ignore -- handled elsewhere */
                return;
            }
        }

        goto unmapped;
    }

        /* General Properties */
    kind:
    case VCARD_KIND_PROPERTY:
        buf_setcstr(crock->buf, prop_value);

        if (!strcmp("group", buf_lcase(crock->buf))) {
            /* members should default to {} */
            json_object_get_vanew(obj, "members", "{}");
        }

        json_object_set_new(obj, "kind", json_string(buf_cstring(crock->buf)));
        break;

    case VCARD_SOURCE_PROPERTY:
        kind = "entry";

    directories:
        {
            json_t *dirs = json_object_get_vanew(obj, "directories", "{}");

            param_flags = ALLOW_TYPE_PARAM | ALLOW_PREF_PARAM |
                ALLOW_LABEL_PARAM | ALLOW_MEDIATYPE_PARAM;

            jprop = json_pack("{s:s s:o}",
                              "kind", kind, "uri", jmap_utf8string(prop_value));

            json_object_set_new(dirs, prop_id, jprop);
        }
        break;

    case VCARD_XML_PROPERTY:
        goto unmapped;

        /* Identification Properties */
    case VCARD_BDAY_PROPERTY:
        kind = "birth";

        GCC_FALLTHROUGH

    case VCARD_DEATHDATE_PROPERTY:
        if (!kind) kind = "death";

        GCC_FALLTHROUGH

    case VCARD_ANNIVERSARY_PROPERTY:
        if (!kind) kind = "wedding";

        subprop.key = "date";
        subprop.val = _to_jmap_date(prop);

        param_flags = ALLOW_CALSCALE_PARAM;

    anniversaries:
        {
            json_t *annivs = json_object_get_vanew(obj, "anniversaries", "{}");

            jprop = json_object_get_vanew(annivs, prop_id, "{s:s}", "kind", kind);

            json_object_set_new(jprop, subprop.key, subprop.val);
        }
        break;

    case VCARD_BIRTHPLACE_PROPERTY:
        kind = "birth";

        GCC_FALLTHROUGH

    case VCARD_DEATHPLACE_PROPERTY: {
        if (!kind) kind = "death";

        const char *comp = "full";

        param = vcardproperty_get_first_parameter(prop, VCARD_VALUE_PARAMETER);
        if (param && vcardparameter_get_value(param) == VCARD_VALUE_URI) {
            if (strncmp(prop_value, "geo:", 4)) goto unmapped;
            comp = "coordinates";
        }

        subprop.key = "place";
        subprop.val = json_pack("{s:o}", comp, jmap_utf8string(prop_value));

        goto anniversaries;
    }

    case VCARD_GRAMGENDER_PROPERTY: {
        json_t *speakto = json_object_get_vanew(obj, "speakToAs", "{}");

        buf_setcstr(crock->buf, prop_value);
        json_object_set_new(speakto, "grammaticalGender",
                            json_string(buf_lcase(crock->buf)));
        break;
    }

    case VCARD_PRONOUNS_PROPERTY: {
        json_t *speakto = json_object_get_vanew(obj, "speakToAs", "{}");
        json_t *pronouns = json_object_get_vanew(speakto, "pronouns", "{}");

        param_flags = ALLOW_TYPE_PARAM | ALLOW_PREF_PARAM;

        jprop = json_pack("{s:o}", "pronouns", jmap_utf8string(prop_value));

        json_object_set_new(pronouns, prop_id, jprop);
        break;
    }

    case VCARD_FN_PROPERTY:
        json_object_set_new(json_object_get_vanew(obj, "name", "{}"),
                            "full", jmap_utf8string(prop_value));
        break;

    case VCARD_N_PROPERTY: {
        vcardstructuredtype *n = vcardproperty_get_n(prop);

        jprop = json_object_get_vanew(obj, "name", "{}");

        jscomps_from_vcard(jprop, prop, n, n_comp_kinds);

        param = vcardproperty_get_first_parameter(prop, VCARD_SORTAS_PARAMETER);
        if (param) {
            vcardstrarray *sorts = vcardparameter_get_sortas(param);
            json_t *sortas = json_object();

            if (vcardstrarray_size(sorts) <= vcardstructured_num_fields(n)) {
                const struct comp_kind *ckind;
                for (ckind = n_comp_kinds; ckind->name; ckind++) {
                    if (ckind->idx < vcardstrarray_size(sorts)) {
                        const char *val =
                            vcardstrarray_element_at(sorts, ckind->idx);

                        if (!*val) continue;

                        // Sanity-check the SORT-AS parameter:
                        // If it sets a component to sort by, then that
                        // component must also be set in the N property.
                        bool have_ncomp = false;

                        if (ckind->idx < vcardstructured_num_fields(n)) {
                            vcardstrarray *ncomp = vcardstructured_field_at(n, ckind->idx);
                            const char *nval = vcardstrarray_element_at(ncomp, 0);
                            if (nval && *nval) {
                                have_ncomp = true;
                            }
                        }

                        if (!have_ncomp) {
                            // Bogus SORT-AS parameter. Ignore it.
                            json_decref(sortas);
                            sortas = NULL;
                            break;
                        }

                        json_object_set_new(sortas,
                                            ckind->name, jmap_utf8string(val));
                    }
                }
            }

            if (json_object_size(sortas)) {
                json_object_set(jprop, "sortAs", sortas);
            }

            json_decref(sortas);

            /* Remove SORT-AS parameter */
            vcardproperty_remove_parameter_by_ref(prop, param);
        }
        break;
    }

    case VCARD_NICKNAME_PROPERTY: {
        json_t *nicks = json_object_get_vanew(obj, "nicknames", "{}");
        vcardstrarray *names = vcardproperty_get_nickname(prop);
        size_t i;

        param_flags = ALLOW_TYPE_PARAM | ALLOW_PREF_PARAM;

        for (i = 0; i < vcardstrarray_size(names); i++) {
            const char *name = vcardstrarray_element_at(names, i);

            jprop = json_pack("{s:o}", "name", jmap_utf8string(name));

            json_object_set_new(nicks, prop_id, jprop);
        }
        break;
    }

    case VCARD_PHOTO_PROPERTY:
        kind = "photo";

    media:
        {
            json_t *media = json_object_get_vanew(obj, "media", "{}");
            char *uri = NULL, *type = NULL, *blobid = NULL;

            param_flags = ALLOW_TYPE_PARAM | ALLOW_PREF_PARAM |
                ALLOW_LABEL_PARAM | ALLOW_MEDIATYPE_PARAM;

            uri = _value_to_uri_blobid(prop,
                    crock->ctx->mailbox, crock->ctx->record, crock->version,
                                       &type, &blobid);

            jprop = json_pack("{s:s s:s* s:s* s:s*}",
                              "kind", kind, "mediaType", type,
                              "uri", uri, "blobId", blobid);

            json_object_set_new(media, prop_id, jprop);

            free(blobid);
            free(type);
            free(uri);
        }
        break;

        /* Delivery Addressing Properties */
    case VCARD_ADR_PROPERTY: {
        vcardstructuredtype *adr = vcardproperty_get_adr(prop);
        json_t *addrs = json_object_get_vanew(obj, "addresses", "{}");

        param_flags = ALLOW_TYPE_PARAM | ALLOW_PREF_PARAM | ALLOW_LABEL_PARAM;

        jprop = json_object_get_vanew(addrs, prop_id, "{}");

        param = vcardproperty_get_first_parameter(prop, VCARD_LABEL_PARAMETER);
        if (param) {
            json_object_set_new(jprop, "full",
                                jmap_utf8string(vcardparameter_get_label(param)));

            /* Remove LABEL parameter */
            vcardproperty_remove_parameter_by_ref(prop, param);
        }

        jscomps_from_vcard(jprop, prop, adr, adr_comp_kinds);
        break;
    }

        /* Communications Properties */
    case VCARD_EMAIL_PROPERTY: {
        json_t *emails = json_object_get_vanew(obj, "emails", "{}");

        param_flags = ALLOW_TYPE_PARAM |
            ALLOW_PREF_PARAM | ALLOW_LABEL_PARAM;

        jprop = json_pack("{s:o}", "address", jmap_utf8string(prop_value));

        json_object_set_new(emails, prop_id, jprop);
        break;
    }

    online:
    case VCARD_IMPP_PROPERTY:
    case VCARD_SOCIALPROFILE_PROPERTY:
      jprop =
          _jsonline_from_vcard(prop, prop_id, obj,
                               crock->ctx->set_vcard_convprops, &param_flags);
      break;

    case VCARD_LANG_PROPERTY: {
        json_t *langs = json_object_get_vanew(obj, "preferredLanguages", "{}");

        param_flags = ALLOW_TYPE_PARAM | ALLOW_PREF_PARAM;

        jprop = json_pack("{s:o}", "language", jmap_utf8string(prop_value));

        json_object_set_new(langs, prop_id, jprop);
        break;
    }

    case VCARD_LANGUAGE_PROPERTY:
        json_object_set_new(obj, "language", jmap_utf8string(prop_value));
        break;

    case VCARD_TEL_PROPERTY: {
        json_t *phones = json_object_get_vanew(obj, "phones", "{}");

        param_flags = ALLOW_TYPE_PARAM |
            ALLOW_PREF_PARAM | ALLOW_LABEL_PARAM;

        jprop = json_pack("{s:o}", "number", jmap_utf8string(prop_value));

        json_object_set_new(phones, prop_id, jprop);
        break;
    }

        /* Geographical Properties */
    case VCARD_GEO_PROPERTY: {
        vcardgeotype geo = vcardproperty_get_geo(prop);

        kind = "coordinates";

        if (geo.uri) {
            prop_value = geo.uri;
        }
        else {
            buf_reset(crock->buf);
            buf_printf(crock->buf, "geo:%s,%s", geo.coords.lat, geo.coords.lon);
            prop_value = buf_cstring(crock->buf);
        }

        GCC_FALLTHROUGH
    }

    case VCARD_TZ_PROPERTY:
        if (!kind) {
            vcardtztype tz = vcardproperty_get_tz(prop);

            kind = "timeZone";

            if (tz.uri) {
                goto unmapped;
            }
            else if (tz.tzid) {
                prop_value = tz.tzid;
            }
            else if (!tz.utcoffset) {
                prop_value = "Etc/UTC";
            }
            else {
                buf_reset(crock->buf);
                buf_printf(crock->buf, "Etc/GMT%+d", -tz.utcoffset / 3600);
                prop_value = buf_cstring(crock->buf);
            }
        }

    grouped_geo:
        {
            strarray_t *ids =
                hash_lookup(prop_group ? prop_group : "", crock->adrs);

            if (!ids) goto unmapped;

            for (int i = 0; i < strarray_size(ids); i++) {
                json_t *addrs = json_object_get_vanew(obj, "addresses", "{}");
                const char *prop_id = strarray_nth(ids, i);

                jprop = json_object_get_vanew(addrs, prop_id, "{}");

                json_object_set_new(jprop, kind, json_string(prop_value));
            }
        }
        break;

        /* Organizational Properties */
    case VCARD_CONTACTURI_PROPERTY:
        kind = "contact";

    links:
        {
            json_t *links = json_object_get_vanew(obj, "links", "{}");

            param_flags = ALLOW_TYPE_PARAM |
                ALLOW_PREF_PARAM | ALLOW_LABEL_PARAM;

            jprop = json_pack("{s:s* s:o}",
                              "kind", kind, "uri", jmap_utf8string(prop_value));

            json_object_set_new(links, prop_id, jprop);
        }
        break;

    case VCARD_LOGO_PROPERTY:
        kind = "logo";
        goto media;

    member:
    case VCARD_MEMBER_PROPERTY: {
        json_t *members = json_object_get_vanew(obj, "members", "{}");

        json_object_set_new(members, prop_value, json_true());
        break;
    }

    case VCARD_ORG_PROPERTY: {
        json_t *orgs = json_object_get_vanew(obj, "organizations", "{}");
        vcardstrarray *org = vcardproperty_get_org(prop);
        const char *name = vcardstrarray_element_at(org, 0);
        size_t num_comp = vcardstrarray_size(org);
        json_t *units = num_comp > 1 ? json_array() : NULL;
        vcardstrarray *sortas = NULL;
        const char *sort = NULL;

        if (!org) {
            /* Value was not parsed as structured, so use the raw value */
            name = prop_value;
        }

        param = vcardproperty_get_first_parameter(prop, VCARD_SORTAS_PARAMETER);
        if (param) {
            sortas = vcardparameter_get_sortas(param);
            sort = vcardstrarray_element_at(sortas, 0);
            if (!*sort) sort = NULL;
        }

        jprop = json_pack("{s:o* s:o* s:s*}",
                          "name", name && *name ? jmap_utf8string(name) : NULL,
                          "units", units, "sortAs", sort);

        for (size_t i = 1; i < num_comp; i++) {
            name = vcardstrarray_element_at(org, i);
            if (sortas && i < vcardstrarray_size(sortas)) {
                sort = vcardstrarray_element_at(sortas, i);
                if (!*sort) sort = NULL;
            }
            else {
                sort = NULL;
            }
            json_array_append_new(units,
                                  json_pack("{s:o s:s*}",
                                            "name", jmap_utf8string(name),
                                            "sortAs", sort));
        }

        /* Remove SORT-AS parameter */
        if (param) {
            vcardproperty_remove_parameter_by_ref(prop, param);
        }

        json_object_set_new(orgs, prop_id, jprop);
        break;
    }

    case VCARD_RELATED_PROPERTY: {
        json_t *relatedto = json_object_get_vanew(obj, "relatedTo", "{}");

        param_flags = ALLOW_TYPE_PARAM;

        jprop = json_pack("{s:{}}", "relation");

        json_object_set_new(relatedto, prop_value, jprop);
        break;
    }

    case VCARD_ROLE_PROPERTY:
        kind = "role";

        GCC_FALLTHROUGH

    case VCARD_TITLE_PROPERTY: {
        json_t *titles = json_object_get_vanew(obj, "titles", "{}");
        const char *org = NULL;

        if (prop_group) {
            org = hash_lookup(prop_group, crock->orgs);
        }

        json_object_set_new(titles, prop_id,
                            json_pack("{s:s* s:o s:s*}",
                                      "kind", kind,
                                      "name", jmap_utf8string(prop_value),
                                      "organizationId", org));
        break;
    }

        /* Personal Information Properties */
    case VCARD_EXPERTISE_PROPERTY:
    case VCARD_HOBBY_PROPERTY:
    case VCARD_INTEREST_PROPERTY: {
        json_t *personal = json_object_get_vanew(obj, "personalInfo", "{}");

        param_flags = ALLOW_INDEX_PARAM | ALLOW_LEVEL_PARAM;

        buf_setcstr(crock->buf, vcardproperty_get_property_name(prop));

        jprop = json_object_get_vanew(personal, prop_id,
                                      "{s:s s:s}",
                                      "kind", buf_lcase(crock->buf),
                                      "value", prop_value);
        break;
    }

    case VCARD_ORGDIRECTORY_PROPERTY:
        kind = "directory";
        goto directories;

        /* Explanatory Properties */
    case VCARD_CATEGORIES_PROPERTY: {
        json_t *keywords = json_object_get_vanew(obj, "keywords", "{}");
        vcardstrarray *cat = vcardproperty_get_categories(prop);
        size_t i;

        for (i = 0; i < vcardstrarray_size(cat); i++) {
            json_object_set_new(keywords,
                                vcardstrarray_element_at(cat, i), json_true());
        }
        break;
    }

    case VCARD_CLIENTPIDMAP_PROPERTY:
        goto unmapped;

    case VCARD_CREATED_PROPERTY:
        json_object_set_new(obj, "created",
                            vcardtime_to_jmap_utcdate(vcardproperty_get_created(prop)));
        break;

    case VCARD_NOTE_PROPERTY: {
        json_t *notes = json_object_get_vanew(obj, "notes", "{}");

        jprop = json_pack("{s:o}", "note", jmap_utf8string(prop_value));

        json_object_set_new(notes, prop_id, jprop);
        break;
    }

    case VCARD_PRODID_PROPERTY:
        json_object_set_new(obj, "prodId", jmap_utf8string(prop_value));
        break;

    case VCARD_REV_PROPERTY:
        json_object_set_new(obj, "updated",
                            vcardtime_to_jmap_utcdate(vcardproperty_get_rev(prop)));
        break;

    case VCARD_SOUND_PROPERTY:
        kind = "sound";
        goto media;

    case VCARD_UID_PROPERTY:
        json_object_set_new(obj, "uid", jmap_utf8string(prop_value));
        break;

    case VCARD_URL_PROPERTY:
        goto links;

    case VCARD_VERSION_PROPERTY:
        /* Never round-tripped: the Card is converted back to a v4 vCard,
           whatever version this one had. */
        break;

        /* Security Properties */
    case VCARD_KEY_PROPERTY: {
        json_t *keys = json_object_get_vanew(obj, "cryptoKeys", "{}");
        char *uri = NULL, *type = NULL, *blobid = NULL;

        param_flags = ALLOW_TYPE_PARAM | ALLOW_PREF_PARAM |
            ALLOW_LABEL_PARAM | ALLOW_MEDIATYPE_PARAM;

        uri = _value_to_uri_blobid(prop,
                crock->ctx->mailbox, crock->ctx->record, crock->version,
                &type, &blobid);

        jprop = json_pack("{s:s* s:s* s:s*}",
                          "mediaType", type, "uri", uri, "blobId", blobid);

        json_object_set_new(keys, prop_id, jprop);

        free(blobid);
        free(type);
        free(uri);
        break;
    }

        /* Calendar Properties */
    case VCARD_CALADRURI_PROPERTY: {
        json_t *addrs = json_object_get_vanew(obj, "schedulingAddresses", "{}");

        param_flags = ALLOW_TYPE_PARAM | ALLOW_PREF_PARAM | ALLOW_LABEL_PARAM;

        jprop = json_pack("{s:s}", "uri", prop_value);

        json_object_set_new(addrs, prop_id, jprop);
        break;
    }

    case VCARD_CALURI_PROPERTY:
        kind = "calendar";

        GCC_FALLTHROUGH

    case VCARD_FBURL_PROPERTY: {
        json_t *cals = json_object_get_vanew(obj, "calendars", "{}");

        if (!kind) kind = "freeBusy";

        param_flags = ALLOW_TYPE_PARAM | ALLOW_PREF_PARAM |
            ALLOW_LABEL_PARAM | ALLOW_MEDIATYPE_PARAM;

        jprop = json_pack("{s:s s:s}", "kind", kind, "uri", prop_value);

        json_object_set_new(cals, prop_id, jprop);
        break;
    }

        /* Custom JSContact Properties */
    case VCARD_JSPROP_PROPERTY: {
        json_t *val = json_loads(vcardproperty_get_jsprop(prop),
                                 JSON_DECODE_ANY, NULL);
        if (val) {
            param = vcardproperty_get_first_parameter(prop,
                                                      VCARD_JSPTR_PARAMETER);

            if (!crock->patch) crock->patch = json_object();
            json_object_set_new(crock->patch,
                                vcardparameter_get_jsptr(param), val);
        }
        break;
    }

        /* Unmapped Properties (jCard-encoded) */
    unmapped:
    default: if (crock->ctx->set_vcard_convprops) {
        json_t *props = json_object_get_vanew(obj, "vCardProps", "[]");
        json_t *jtype, *jparams = json_object();
        const char *type = NULL;

        for (param = vcardproperty_get_first_parameter(prop,
                                                       VCARD_ANY_PARAMETER);
             param;
             param = vcardproperty_get_next_parameter(prop,
                                                      VCARD_ANY_PARAMETER)) {
            vcardparameter_kind param_kind = vcardparameter_isa(param);
            char *param_str = vcardparameter_as_vcard_string(param);
            char *param_value = strchr(param_str, '=') + 1;

            if (param_kind == VCARD_X_PARAMETER)
                buf_setcstr(crock->buf, vcardparameter_get_xname(param));
            else
                buf_setcstr(crock->buf, vcardparameter_kind_to_string(param_kind));

            if (param_kind == VCARD_VALUE_PARAMETER) {
                type = lcase(param_value);
            }
            else {
                int is_multivalued = 0;  /* XXX  Create JSON array? */
                json_t *val;

                vcardvalue_kind param_vkind =
                    vcardparameter_kind_value_kind(param_kind, &is_multivalued);

                switch (param_vkind) {
                case VCARD_INTEGER_VALUE:
                    val = json_integer(vcardparameter_get_index(param));
                    break;

                case VCARD_BOOLEAN_VALUE:
                    val = json_boolean(VCARD_DERIVED_TRUE ==
                                       vcardparameter_get_derived(param));
                    break;

                default:
                    val = jmap_utf8string(param_value);
                    break;
                }

                json_object_set_new(jparams, buf_lcase(crock->buf), val);
            }
        }

        vcardvalue_kind prop_vkind;
        if (type) {
            prop_vkind = vcardvalue_string_to_kind(type);
        }
        else {
            prop_vkind = vcardproperty_kind_to_value_kind(prop_kind);

            switch (prop_vkind) {
            case VCARD_X_VALUE:
            case VCARD_NO_VALUE:
                type = "unknown";
                break;

            case VCARD_TZ_VALUE:
            case VCARD_GEO_VALUE:
            case VCARD_KIND_VALUE:
            case VCARD_TEXT_VALUE:
            case VCARD_VERSION_VALUE:
            case VCARD_TEXTLIST_VALUE:
            case VCARD_GRAMGENDER_VALUE:
            case VCARD_STRUCTURED_VALUE:
                type = "text";
                break;

            default:
                buf_setcstr(crock->buf, vcardvalue_kind_to_string(prop_vkind));
                type = buf_lcase(crock->buf);
                break;
            }
        }

        jtype = json_string(type);

        if (prop_group) {
            json_object_set_new(jparams, "group", jmap_utf8string(prop_group));

            if (label) {
                /* Apple label */
                buf_setcstr(crock->buf, VCARD_APPLE_LABEL_PROPERTY);
                json_array_append_new(props,
                                      json_pack("[s {s:o} s o]",
                                                buf_lcase(crock->buf),
                                                "group",
                                                jmap_utf8string(prop_group),
                                                "text",
                                                jmap_utf8string(label)));
            }
        }

        buf_setcstr(crock->buf, vcardproperty_get_property_name(prop));

        json_t *jprop = json_pack("[s o o]",
                                  buf_lcase(crock->buf), jparams, jtype);

        json_array_append_new(props, jprop);

        switch (prop_vkind) {
        case VCARD_X_VALUE:
            /* There is no way to detect a structured TEXT value in a X- prop */
            json_array_append_new(jprop, json_string(prop_value));
            break;
        case VCARD_BOOLEAN_VALUE:
        case VCARD_INTEGER_VALUE:
        case VCARD_FLOAT_VALUE:
            if (strchr(prop_value, ';')) {
                tok_t comps = TOK_INITIALIZER(prop_value, "\\;", 0);
                json_t *jcomps = json_array();
                const char *comp;

                while ((comp = tok_next(&comps))) {
                    vcardvalues_to_json(comp, prop_vkind, jcomps);
                }

                json_array_append_new(jprop, jcomps);
                break;
            }

            /* Fall through */
            GCC_FALLTHROUGH

        default:
            vcardvalues_to_json(prop_value, prop_vkind, jprop);
            break;
        }

        return;
    }
    }

    if (jprop) {
        _add_vcard_params(jprop, prop, param_flags,
                crock->ctx->set_vcard_convprops);

        if (label && (param_flags & ALLOW_LABEL_PARAM)) {
            /* Apple label */
            json_object_set_new(jprop, "label", jmap_utf8string(label));
        }
    }

}

static void free_props_by_altid(void *val)
{
    free_hash_table((hash_table *) val, (void (*)(void *)) &ptrarray_free);
    free(val);
}

static void props_by_altid_cb(const char *altid, void *val, void *rock)
{
    ptrarray_t *props = val;
    struct card_rock *crock = rock;
    const char *prop_id = NULL;
    int i;

    /* Look for property with default language and translate it into the Card */
    for (i = 0; i < ptrarray_size(props); i++) {
        vcardproperty *prop = ptrarray_nth(props, i);
        const char *lang = NULL;

        vcardparameter *param =
            vcardproperty_get_first_parameter(prop, VCARD_LANGUAGE_PARAMETER);
        if (param) {
            lang = vcardparameter_get_language(param);
        }

        if (!lang || !strcmpsafe(lang, crock->deflang)) {
            ptrarray_remove(props, i);
            prop_id = *altid ? altid : _prop_id(prop);
            jsprop_from_vcard(prop, crock->card, prop_id, crock);
            break;
        }
    }

    /* Process the remaining properties with non-default languages */
    for (i = 0; i < ptrarray_size(props); i++) {
        vcardproperty *prop = ptrarray_nth(props, i);
        vcardparameter *param =
            vcardproperty_get_first_parameter(prop, VCARD_LANGUAGE_PARAMETER);

        if (param) {
            /* Translate into the "localizations" property as a patch */
            const char *lang = vcardparameter_get_language(param);
            json_t *l10n =
                json_object_get_vanew(crock->card, "localizations", "{}");
            json_t *tmp = json_object();

            if (!prop_id) prop_id = *altid ? altid : _prop_id(prop);

            jsprop_from_vcard(prop, tmp, prop_id, crock);
            json_object_update_new(json_object_get_vanew(l10n, lang, "{}"),
                                   jmap_patchobject_create(crock->card, tmp,
                                                           PATCH_NO_REMOVE |
                                                           PATCH_ALLOW_ARRAY));
            json_decref(tmp);
        }
        else {
            /* No language - translate into the toplevel Card */
            jsprop_from_vcard(prop, crock->card, _prop_id(prop), crock);
        }
    }
}

static void props_by_name_cb(const char *name __attribute__((unused)),
                             void *val, void *rock)
{
    hash_enumerate((hash_table *) val, &props_by_altid_cb, rock);
}

/* Convert the vCard to JSContact Card properties */
static json_t *jscard_from_vcard(jscontact_ctx_t *ctx, vcardcomponent *vcard)
{
    /* Default to kind:individual for /query.
       Will be overwritten by KIND property if present. */
    json_t *jcard = json_pack("{s:s s:s s:s}",
                              "@type", "Card",
                              "version", "1.0",
                              "kind", "individual");
    hash_table props_by_name = HASH_TABLE_INITIALIZER;
    hash_table labels = HASH_TABLE_INITIALIZER;
    hash_table adrs = HASH_TABLE_INITIALIZER;
    hash_table orgs = HASH_TABLE_INITIALIZER;
    struct buf buf = BUF_INITIALIZER;
    struct card_rock crock = {
        jcard, NULL, NULL, &labels, &adrs, &orgs,
        ctx, &buf, VCARD_VERSION_NONE
    };
    struct mailbox *mailbox = ctx->mailbox;
    struct index_record *record = ctx->record;
    vcardproperty *prop;
    vcardparameter *param;

    /* Iterate through the vCard properties:
       - Fetch VERSION for sanity checking
       - Fetch LANGUAGE for localizations
       - Fetch ADRs for combining with geographic properties
       - Fetch ORGs for pairing with grouped TITLE/ROLE
       - Fetch Apple-style labels for pairing with grouped properties
       - Sort them by name and then by altid for calculating localizations
    */
    size_t nprops = vcardcomponent_count_properties(vcard, VCARD_ANY_PROPERTY, 0);
    construct_hash_table(&props_by_name, nprops + 1, 0);
    construct_hash_table(&adrs, nprops + 1, 0);
    construct_hash_table(&orgs, nprops + 1, 0);
    construct_hash_table(&labels, nprops + 1, 0);
    for (prop = vcardcomponent_get_first_property(vcard, VCARD_ANY_PROPERTY);
         prop;
         prop = vcardcomponent_get_next_property(vcard, VCARD_ANY_PROPERTY)) {
        const char *prop_name = vcardproperty_get_property_name(prop);
        const char *group = vcardproperty_get_group(prop);
        const char *altid = "";
        hash_table *props_by_altid;
        ptrarray_t *props;
        int prop_idx = -1;  /* append */

        switch (vcardproperty_isa(prop)) {
        case VCARD_VERSION_PROPERTY:
            crock.version = vcardproperty_get_version(prop);
            break;

        case VCARD_LANGUAGE_PROPERTY:
            crock.deflang = vcardproperty_get_language(prop);
            break;

        case VCARD_ADR_PROPERTY: {
            strarray_t *ids = hash_lookup(group ? group : "", &adrs);

            if (!ids) {
                ids = strarray_new();
                hash_insert(group ? group : "", ids, &adrs);
            }
            strarray_append(ids, _prop_id(prop));

            /* Fall through */
            GCC_FALLTHROUGH
        }

        case VCARD_N_PROPERTY:
            if (vcardproperty_get_first_parameter(prop, VCARD_JSCOMPS_PARAMETER)) {
                /* Always place props with JSCOMPS at the head of the list
                   so the component order is set before handling any PHONETICS */
                prop_idx = 0;
            }
            break;

        case VCARD_ORG_PROPERTY:
            if (group) hash_insert(group, xstrdup(_prop_id(prop)), &orgs);
            break;

        case VCARD_X_PROPERTY:
            if (group && !strcasecmp(prop_name, VCARD_APPLE_LABEL_PROPERTY)) {
                vcardvalue *val = vcardproperty_get_value(prop);
                const char *label = NULL;
                switch (vcardvalue_isa(val)) {
                    case VCARD_TEXT_VALUE:
                        label = vcardvalue_get_text(val);
                        break;
                    case VCARD_X_VALUE:
                        label = vcardvalue_get_x(val);
                        break;
                    default:
                        label = vcardvalue_as_vcard_string(val);
                }

                size_t label_len = strlen(label);

                /* Check and adjust for weird (localized?) labels */
                if (label_len > 8 && !strncmp(label, "_$!<", 4)) {
                    label += 4;      // skip "_$!<" prefix
                    label_len -= 8;  // and trim ">!$_" suffix
                }

                hash_insert(group, xstrndup(label, label_len), &labels);
            }
            break;

        default:
            break;
        }

        param = vcardproperty_get_first_parameter(prop, VCARD_ALTID_PARAMETER);
        if (param) {
            altid = vcardparameter_get_altid(param);
        }

        props_by_altid = hash_lookup(prop_name, &props_by_name);
        if (!props_by_altid) {
            props_by_altid = xzmalloc(sizeof(hash_table));
            construct_hash_table(props_by_altid, nprops + 1, 0);
            hash_insert(prop_name, props_by_altid, &props_by_name);
        }

        props = hash_lookup(altid, props_by_altid);
        if (!props) {
            props = ptrarray_new();
            hash_insert(altid, props, props_by_altid);
        }

        if (prop_idx < 0) {
            ptrarray_append(props, prop);
        }
        else {
            ptrarray_insert(props, prop_idx, prop);
        }
    }

    ctx->version = crock.version;

    if (crock.version == VCARD_VERSION_NONE || crock.version == VCARD_VERSION_X)
        goto done;

    /* Don't combine geographical props unless at least one ADR has GROUP set */
    if (hash_count(&adrs) == 1 && hash_lookup("", &adrs)) {
        strarray_free(hash_del("", &adrs));
    }

    /* Translate vCard props to JS props */
    hash_enumerate(&props_by_name, &props_by_name_cb, &crock);

    if (crock.patch) {
        json_t *patched = jmap_patchobject_apply(jcard, crock.patch, NULL, 0);

        json_decref(crock.patch);
        if (patched) {
            json_decref(jcard);
            jcard = patched;
        }
        else {
            /* The JSPTR of at least one of the JSPROP properties pointed into
             * a JSContact subtree that the vCard-to-JSContact conversion did
             * not reconstruct, so the patch could not be applied. Keep the
             * unpatched card as defined in RFC 9555, Section 3.2.1.  The
             * JSPROP contents are preserved in the stored vCard and a client
             * that requests them directly can still retrieve them. */
            syslog(LOG_NOTICE,
                   "jscard_from_vcard: patch failed for record %u:%s",
                   record  ? record->uid : 0,
                   mailbox ? mailbox_name(mailbox) : "<none>");
        }
    }

    /* Sanity check some properties */
    json_t *jprop = json_object_get(jcard, "name");
    if (jprop &&
        /* Need at least one of the following, otherwise remove it */
        !json_object_get(jprop, "components") &&
        !json_object_get(jprop, "full")) {
        json_object_del(jcard, "name");
    }

    jprop = json_object_get(jcard, "addresses");
    if (jprop) {
        const char *id;
        json_t *adr;
        void *tmp;

        json_object_foreach_safe(jprop, tmp, id, adr) {
            /* Need at least one of the following, otherwise remove it */
            if (!json_object_get(adr, "components") &&
                !json_object_get(adr, "countryCode") &&
                !json_object_get(adr, "coordinates") &&
                !json_object_get(adr, "timeZone") &&
                !json_object_get(adr, "full")) {
                json_object_del(jprop, id);
            }
        }

        if (!json_object_size(jprop)) {
            /* If no addresses, remove it */
            json_object_del(jcard, "addresses");
        }
    }

  done:
    buf_free(&buf);
    free_hash_table(&labels, &free);
    free_hash_table(&orgs, &free);
    free_hash_table(&adrs, (void (*)(void *)) &strarray_free);
    free_hash_table(&props_by_name, &free_props_by_altid);

    return jcard;
}

struct l10n_by_id_t {
    const char *deflang;
    const char *lang;
    hash_table *patches;
};

static void _jsunknown_to_vcard(struct jmap_parser *parser,
                                const char *key, json_t *jval,
                                const char *known_props[],
                                vcardcomponent *card)
{
    if (key) {
        for (int i = 0; known_props && known_props[i]; i++) {
            if (!strcasecmp(key, known_props[i])) {
                jmap_parser_invalid(parser, key);
                return;
            }
        }

        jmap_parser_push(parser, key);
    }

    const char *ptr = jmap_parser_path(parser);
    char *val = json_dumps(jval, JSON_COMPACT|JSON_ENCODE_ANY);
    vcardproperty *prop =
        vcardproperty_vanew_jsprop(val,
                                   vcardparameter_new_jsptr(ptr),
                                   NULL);

    vcardcomponent_add_property(card, prop);

    if (key) jmap_parser_pop(parser);
    free(val);
}

static unsigned jssimple_to_vcard(struct jmap_parser *parser,
                                  const char *key, const char *lang,
                                  json_t *jval, vcardcomponent *card,
                                  vcardproperty_kind pkind,
                                  vcardvalue_kind vkind)
{
    vcardproperty *prop = NULL;
    vcardvalue *val = NULL;

    switch (vkind) {
    case VCARD_KIND_VALUE:
    case VCARD_TEXT_VALUE:
    case VCARD_GRAMGENDER_VALUE:
        if (!json_is_string(jval)) {
            jmap_parser_invalid(parser, key);
            return 0;
        }
        else {
            val = vcardvalue_new_from_string(vkind, json_string_value(jval));
        }
        break;

    case VCARD_TIMESTAMP_VALUE:
        if (!json_is_utcdate(jval)) {
            jmap_parser_invalid(parser, key);
            return 0;
        }
        else {
            vcardtimetype tt = vcardtime_from_string(json_string_value(jval), 0);
            val = vcardvalue_new_timestamp(tt);
        }
        break;

    default:
        jmap_parser_invalid(parser, key);
        return 0;
    }

    prop = vcardproperty_new(pkind);
    vcardproperty_set_value(prop, val);
    vcardcomponent_add_property(card, prop);

    if (lang && *lang) {
        vcardproperty_add_parameter(prop, vcardparameter_new_language(lang));
    }

    return 1;
}
static void _jsmultikey_to_card(struct jmap_parser *parser, json_t *jval,
                                const char *key, vcardcomponent *card,
                                vcardproperty_kind pkind)
{
    vcardstrarray *text = NULL;
    const char *id;
    json_t *obj;

    if (!json_is_object(jval)) {
        jmap_parser_invalid(parser, key);
        return;
    }

    jmap_parser_push(parser, key);

    json_object_foreach(jval, id, obj) {

        jmap_parser_push(parser, id);

        if (!json_is_true(obj)) {
            jmap_parser_invalid(parser, id);
        }
        else if (vcardproperty_is_multivalued(pkind)) {
            if (!text) text = vcardstrarray_new(1);
            vcardstrarray_append(text, id);
        }
        else {
            vcardproperty *prop = vcardproperty_new(pkind);

            vcardproperty_set_value_from_string(prop, id, "NO");

            vcardcomponent_add_property(card, prop);
        }

        jmap_parser_pop(parser);
    }

    if (text) {
        vcardproperty *prop = vcardproperty_new(pkind);

        vcardproperty_set_value(prop, vcardvalue_new_textlist(text));
        vcardcomponent_add_property(card, prop);
    }

    jmap_parser_pop(parser);
}

static void _jsparam_to_vcard(struct jmap_parser *parser,
                              const char *key, json_t *jval,
                              vcardproperty *prop,
                              vcardparameter_kind pkind,
                              unsigned *groupnum)
{
    json_t *jprop = json_object_get(jval, key);
    vcardparameter *new = NULL, *param = NULL;
    static struct buf buf = BUF_INITIALIZER;

    if (!jprop) return;

    switch (pkind) {
    case VCARD_TYPE_PARAMETER:
        if (json_is_object(jprop)) {
            const char *type;
            json_t *set;

            param = vcardproperty_get_first_parameter(prop, pkind);
            if (!param) param = new = vcardparameter_new(pkind);

            json_object_foreach(jprop, type, set) {
                const char *mytype;

                if (!strcasecmp("private", type))
                    mytype = "home";
                else if (!strcasecmp("mobile", type))
                    mytype = "cell";
                else
                    mytype = type;

                vcardparameter_add_value_from_string(param, mytype);
            }
        }
        break;

    case VCARD_PREF_PARAMETER:
    case VCARD_INDEX_PARAMETER:
        if (json_is_integer(jprop)) {
            param = new = vcardparameter_new(pkind);
            vcardparameter_set_pref(param, json_integer_value(jprop));
        }
        break;

    case VCARD_CREATED_PARAMETER:
        if (json_is_utcdate(jprop)) {
            vcardtimetype tt = vcardtime_from_string(json_string_value(jprop), 0);

            param = new = vcardparameter_new_created(tt);
        }
        break;

    case VCARD_LEVEL_PARAMETER:
        if (json_is_string(jprop)) {
            const char *val = json_string_value(jprop);

            if (vcardproperty_isa(prop) == VCARD_EXPERTISE_PROPERTY) {
                if (!strcasecmp("low", val)) {
                    val = "beginner";
                }
                else if (!strcasecmp("medium", val)) {
                    val = "average";
                }
                else if (!strcasecmp("high", val)) {
                    val = "expert";
                }
            }

            if (*val) {
                param = new = vcardparameter_new(VCARD_LEVEL_PARAMETER);
                vcardparameter_set_value_from_string(param, val);
            }
            else {
                /* Treat an empty string the same as an absent value rather
                   than emitting an empty-valued parameter (e.g. LEVEL=) */
                jprop = NULL;
            }
        }
        break;

    case VCARD_X_PARAMETER:
        /* label translates to a grouped X-ABLabel property */
        if (json_is_string(jprop)) {
            const char *val = json_string_value(jprop);

            if (*val) {
                vcardproperty *label = vcardproperty_new(VCARD_X_PROPERTY);
                vcardproperty_set_value(label, vcardvalue_new_text(val));
                const char *group;

                vcardproperty_set_x_name(label, VCARD_APPLE_LABEL_PROPERTY);
                vcardcomponent_add_property(vcardproperty_get_parent(prop), label);

                buf_setcstr(&buf, vcardproperty_get_property_name(prop));
                buf_truncate(&buf, MIN(5, buf_len(&buf)));
                buf_printf(&buf, "%u", (*groupnum)++);
                group = buf_lcase(&buf);

                vcardproperty_set_group(label, group);
                vcardproperty_set_group(prop, group);
            }
            /* Treat an empty string the same as an absent value rather than
               emitting an empty X-ABLabel property */
            jprop = NULL;
        }
        break;

    default:
        if (json_is_string(jprop)) {
            const char *val = json_string_value(jprop);

            if (*val) {
                param = new = vcardparameter_new(pkind);
                vcardparameter_set_value_from_string(param, val);
            }
            else {
                /* Treat an empty string the same as an absent value rather
                   than emitting an empty-valued parameter (e.g. CC="") */
                jprop = NULL;
            }
        }
        break;
    }

    if (param) {
        if (new) vcardproperty_add_parameter(prop, param);
    }
    else if (jprop) {
        jmap_parser_invalid(parser, key);
    }

    json_object_del(jval, key);
}

struct param_prop_t {
    const char *key;
    vcardparameter_kind kind;
};

// clang-format off
struct param_prop_t phone_param_props[] = {
    { "features", VCARD_TYPE_PARAMETER  },
    { "label",    VCARD_X_PARAMETER     },
    { "pref",     VCARD_PREF_PARAMETER  },
    { "contexts", VCARD_TYPE_PARAMETER  },
    { NULL,       0                     }
};
// clang-format on

#define comm_param_props    (phone_param_props+1)  // label, context & pref
#define pref_param_props    (phone_param_props+2)  // context & pref
#define context_param_props (phone_param_props+3)  // context

// clang-format off
struct param_prop_t directories_param_props[] = {
    { "listAs",    VCARD_INDEX_PARAMETER     },
    { "mediaType", VCARD_MEDIATYPE_PARAMETER },
    { "label",     VCARD_X_PARAMETER         },
    { "pref",      VCARD_PREF_PARAMETER      },
    { "contexts",  VCARD_TYPE_PARAMETER      },
    { NULL,       0                          }
};
// clang-format on

#define resource_param_props (directories_param_props+1)  // no listAs

#define WANT_PROPID_FLAG (1<<0)
#define WANT_ALTID_FLAG  (1<<1)

typedef vcardproperty* (*prop_cb_t)(struct jmap_parser *parser, json_t *obj,
                                    const char *id, vcardcomponent *card,
                                    void *rock);

static void _vcardparams_to_prop(json_t *jparams, vcardproperty *prop)
{
    const char *name;
    json_t *jval;
    struct buf buf = BUF_INITIALIZER;

    json_object_foreach(jparams, name, jval) {
        vcardparameter *param;

        if (!strcmp(name, "group")) {
            vcardproperty_set_group(prop, json_string_value(jval));
            continue;
        }

        vcardparameter_kind kind = vcardparameter_string_to_kind(name);
        switch (kind) {
        case VCARD_X_PARAMETER:
        case VCARD_NO_PARAMETER:
        case VCARD_IANA_PARAMETER:
            param = vcardparameter_new(VCARD_IANA_PARAMETER);
            buf_setcstr(&buf, name);
            vcardparameter_set_iana_name(param, buf_ucase(&buf));
            break;

        default:
            param = vcardparameter_new(kind);
            break;
        }

        if (json_is_string(jval)) {
            vcardparameter_set_value_from_string(param, json_string_value(jval));
        }
        else if (json_is_boolean(jval)) {
            vcardparameter_set_derived(param, json_boolean_value(jval) ?
                                       VCARD_DERIVED_TRUE : VCARD_DERIVED_FALSE);
        }
        else if (json_is_integer(jval)) {
            vcardparameter_set_index(param, json_integer_value(jval));
        }
        else {
            char *val = json_dumps(jval, JSON_COMPACT);
            param = vcardparameter_new_iana(val);
            free(val);
        }

        vcardproperty_add_parameter(prop, param);
    }

    buf_free(&buf);
}

static unsigned _jsobject_to_card(struct jmap_parser *parser, json_t *obj,
                                  const char *id, const char *type, prop_cb_t cb,
                                  struct param_prop_t param_props[],
                                  unsigned flags, const char *lang,
                                  vcardcomponent *card, void *rock,
                                  unsigned *groupnum)
{
    vcardproperty *prop = NULL;
    const char *myprops[] = { "@type", NULL };
    const char *key;
    json_t *jprop;
    int r = 0;

    jprop = json_object_get(obj, "@type");
    if (jprop && strcmpsafe(type, json_string_value(jprop))) {
        jmap_parser_invalid(parser, "@type");
        return 0;
    }
    json_object_del(obj, "@type");

    prop = cb(parser, obj, id, card, rock);

    if (prop) {
        struct param_prop_t *pprop;
        json_t *jprop;

        vcardcomponent_add_property(card, prop);

        if (flags & WANT_PROPID_FLAG) {
            vcardproperty_add_parameter(prop, vcardparameter_new_propid(id));
        }
        if (flags & WANT_ALTID_FLAG) {
            vcardproperty_add_parameter(prop, vcardparameter_new_altid(id));
        }
        if (lang && *lang) {
            vcardproperty_add_parameter(prop, vcardparameter_new_language(lang));
        }

        for (pprop = param_props; pprop && pprop->key; pprop++) {
            _jsparam_to_vcard(parser, pprop->key, obj, prop, pprop->kind, groupnum);
        }

        jprop = json_object_get(obj, "vCardParams");
        if (json_is_object(jprop)) {
            _vcardparams_to_prop(jprop, prop);

            json_object_del(obj, "vCardParams");
        }

        r = 1;
    }

    /* Add unknown properties */
    json_object_foreach(obj, key, jprop) {
        _jsunknown_to_vcard(parser, key, jprop, myprops, card);
    }

    return r;
}

struct l10n_rock {
    unsigned is_multi: 1;
    unsigned *groupnum;
    union {
        void (*prop_cb)(struct jmap_parser *, json_t *,
                        struct l10n_by_id_t *, vcardcomponent *);
        struct {
            const char *type;
            prop_cb_t prop_cb;
            struct param_prop_t *param_props;
            void *rock;
        } multi;
    } u;
};

static void _jsl10n_to_vcard(struct jmap_parser *parser, json_t *obj,
                             const char *key, const char *id,
                             struct l10n_by_id_t *l10n,
                             vcardcomponent *card, struct l10n_rock *rock)
{
    json_t *patches =
        l10n->patches ? hash_del(id ? id : "", l10n->patches) : NULL;

    if (patches) {
        /* Apply localization patches and add new objects to Card */
        struct buf buf = BUF_INITIALIZER;
        const char *lang;
        json_t *jpatch;

        json_object_foreach(patches, lang, jpatch) {
            json_t *altobj = json_object_get(jpatch, "");
            json_t *invalid = NULL, *patched = NULL;

            if (!altobj) {
                invalid = json_array();
                altobj = patched = jmap_patchobject_apply(obj, jpatch, invalid,
                                                          PATCH_ALLOW_ARRAY);
            }

            if (altobj) {
                if (rock->is_multi) {
                    const char *this_lang =
                        strcasecmpsafe(l10n->deflang, lang) ? lang : NULL;

                    _jsobject_to_card(parser, altobj, id,
                                      rock->u.multi.type,
                                      rock->u.multi.prop_cb,
                                      rock->u.multi.param_props,
                                      WANT_PROPID_FLAG | WANT_ALTID_FLAG,
                                      this_lang, card,
                                      rock->u.multi.rock,
                                      rock->groupnum);
                }
                else {
                    struct l10n_by_id_t my_l10n = { l10n->deflang, lang, NULL };

                    rock->u.prop_cb(parser, altobj, &my_l10n, card);
                }

                if (patched) json_decref(patched);
            }
            else {
                json_t *path;
                size_t len, i;

                buf_printf(&buf, "localizations/%s/", lang);
                if (id) buf_printf(&buf, "%s/", id);
                buf_printf(&buf, "%s/", key);
                len = buf_len(&buf);

                json_array_foreach(invalid, i, path) {
                    buf_appendcstr(&buf, json_string_value(path));
                    jmap_parser_invalid_path(parser, buf_cstring(&buf));
                    buf_truncate(&buf, len);
                }
                buf_reset(&buf);
            }

            if (invalid) json_decref(invalid);
        }

        json_decref(patches);
        buf_free(&buf);
    }
}

static void _jsmultiobject_to_card(struct jmap_parser *parser, json_t *jval,
                                   const char *key, const char *type,
                                   prop_cb_t prop_cb, unsigned flags,
                                   struct param_prop_t param_props[],
                                   struct l10n_by_id_t *l10n,
                                   vcardcomponent *card, void *rock)
{
    unsigned groupnum = 0;
    struct l10n_rock lrock =
        { 1, &groupnum, { .multi = { type, prop_cb, param_props, rock}} };
    const char *id;
    json_t *obj;
    void *tmp;

    if (!json_is_object(jval)) {
        jmap_parser_invalid(parser, key);
        return;
    }

    jmap_parser_push(parser, key);

    json_object_foreach_safe(jval, tmp, id, obj) {
        jmap_parser_push(parser, id);

        _jsl10n_to_vcard(parser, obj, key, id, l10n, card, &lrock);

        if (l10n->lang) {
            flags |= WANT_ALTID_FLAG;
        }

        /* Add base object to Card */
        bool added = _jsobject_to_card(parser, obj, id, type, prop_cb,
                                       param_props, flags, l10n->lang,
                                       card, rock, &groupnum);

        json_object_del(jval, id);
        jmap_parser_pop(parser);

        if (!added) break;
    }

    jmap_parser_pop(parser);
}

static vcardproperty *_jsrelation_to_vcard(struct jmap_parser *parser,
                                           json_t *obj, const char *id,
                                           vcardcomponent *card __attribute__((unused)),
                                           void *rock __attribute__((unused)))
{
    json_t *jprop = jprop = json_object_get(obj, "relation");
    vcardproperty *prop = NULL;

    if (!jprop || !json_is_object(jprop)) {
        jmap_parser_invalid(parser, "relation");
    }
    else {
        const char *valkind = "URI";
        size_t i, len = strlen(id);
        int have_scheme = 0;

        for (i = 0; i < len; i++) {
            if (!isascii(id[i]) || !isprint(id[i]) || isspace(id[i])) {
                break;
            }
            else if (i && id[i] == ':') {
                have_scheme = 1;
            }
        }
        if (!have_scheme || i < len) {
            valkind = "TEXT";
        }

        prop = vcardproperty_new(VCARD_RELATED_PROPERTY);
        vcardproperty_set_value_from_string(prop, id, valkind);
    }

    return prop;
}

static const struct comp_kind *_field_name_to_kind(const char *name,
                                                   const struct comp_kind *comps)
{
    const struct comp_kind *comp;

    for (comp = comps; comp->name; comp++) {
        if (!(comp->flags & FIELD_SKIP) && !strcmpsafe(name, comp->name)) {
            return comp;
        }
    }

    return NULL;
}

struct jscomps_args {
    vcardproperty *(*vanew_prop)(vcardstructuredtype*, ...);
    unsigned min_num_comps;
    unsigned max_num_comps;
    const char *id;
    const char *comp_type;
    const struct comp_kind *comp_kinds;
    struct buf *derived;
};

static void _jsname_concat_components(json_t *name, struct buf *buf)
{
    json_t *comps = json_object_get(name, "components");

    buf_reset(buf);

    if (json_boolean_value(json_object_get(name, "isOrdered"))) {
        const char *defsep =
            json_string_value(json_object_get(name, "defaultSeparator"));
        const char *sep = NULL;

        if (!defsep) defsep = " ";

        for (size_t i = 0; i < json_array_size(comps); i++) {
            json_t *comp = json_array_get(comps, i);
            const char *kind = json_string_value(json_object_get(comp, "kind"));
            const char *val = json_string_value(json_object_get(comp, "value"));

            if (kind && !strcmp(kind, "separator")) {
                sep = val;
            }
            else {
                if (buf_len(buf)) buf_appendcstr(buf, sep ? sep : defsep);
                if (val) buf_appendcstr(buf, val);
                sep = NULL;
            }
        }
    }
    else {
        static const unsigned fn_order[] = {
            VCARD_N_PREFIX, VCARD_N_GIVEN, VCARD_N_ADDITIONAL,
            VCARD_N_FAMILY, VCARD_N_SUFFIX
        };
        for (size_t f = 0; f < sizeof(fn_order) / sizeof(fn_order[0]); f++) {
            for (size_t i = 0; i < json_array_size(comps); i++) {
                json_t *comp = json_array_get(comps, i);
                const char *kind =
                    json_string_value(json_object_get(comp, "kind"));
                const struct comp_kind *ckind =
                    kind ? _field_name_to_kind(kind, n_comp_kinds) : NULL;
                const char *val =
                    json_string_value(json_object_get(comp, "value"));

                if (!ckind || !val || !*val) continue;

                if (ckind->idx == fn_order[f] ||
                    ((ckind->flags & FIELD_BWD) &&
                     ckind->alt_idx == fn_order[f])) {
                    if (buf_len(buf)) buf_putc(buf, ' ');
                    buf_appendcstr(buf, val);
                }
            }
        }
    }
}

static vcardproperty *_jscomps_to_vcard(struct jmap_parser *parser, json_t *obj,
                                        vcardcomponent *card,
                                        struct jscomps_args *args)
{
    json_t *comps = json_object_get(obj, "components");

    if (!comps) {
        if (args->max_num_comps != VCARD_NUM_ADR_FIELDS) return NULL;
    }
    else if (!json_array_size(comps)) {
        jmap_parser_invalid(parser, "components");
        return 0;
    }

    vcardstructuredtype *vals = vcardstructured_new(args->max_num_comps);
    vcardstructuredtype *ph = vcardstructured_new(args->max_num_comps);
    size_t i, size = json_array_size(comps);
    vcardstructuredtype *jscomps = NULL;
    vcardproperty *prop = NULL;
    const char *defsep = " ", *sep = NULL, *ph_system = NULL;
    struct buf buf = BUF_INITIALIZER;
    vcardstrarray *entry;
    json_t *jprop;
    int isordered = 0;
    bool needs_extended = false;

    jprop = json_object_get(obj, "phoneticSystem");
    if (json_is_string(jprop)) {
        ph_system = json_string_value(jprop);
    }
    else if (jprop) {
        jmap_parser_invalid(parser, "phoneticSystem");
        goto fail;
    }

    jprop = json_object_get(obj, "isOrdered");
    if (jprop) {
        if (!json_is_boolean(jprop)) {
            jmap_parser_invalid(parser, "isOrdered");
            goto fail;
        }

        isordered = json_boolean_value(jprop);
    }

    if (isordered) {
        jscomps = vcardstructured_new(1); // for separator, regardless if specified

        jprop = json_object_get(obj, "defaultSeparator");
        if (json_is_string(jprop)) {
            defsep = json_string_value(jprop);

            /* Add default separator entry to JSCOMPS (if not SP) */
            if (strcmp(defsep, " ")) {
                entry = vcardstrarray_new(2);
                vcardstrarray_append(entry, "s");
                vcardstrarray_append(entry, defsep);
                vcardstructured_set_field_at(jscomps, 0, entry);
            }
        }
        else if (jprop) {
            jmap_parser_invalid(parser, "defaultSeparator");
            goto fail;
        }
    }

    for (i = 0; i < size; i++) {
        json_t *comp = json_array_get(comps, i);
        const char *key, *kind = NULL, *val = NULL, *phonetic = NULL;
        const char *myprops[] = { "@type", "kind", "value", "phonetic", NULL };
        json_t *jsubprop;

        jmap_parser_push_index(parser, "components", i, NULL);

        json_object_foreach(comp, key, jsubprop) {
            if (!strcmp("@type", key)) {
                if (strcmpsafe(args->comp_type, json_string_value(jsubprop))) {
                    jmap_parser_invalid(parser, "@type");
                    break;
                }
            }
            else if (!strcmp("kind", key)) {
                kind = json_string_value(jsubprop);
            }
            else if (!strcmp("value", key)) {
                val = json_string_value(jsubprop);
            }
            else if (!strcmp("phonetic", key)) {
                if (!ph_system || !json_is_string(jsubprop)) {
                    jmap_parser_invalid(parser, "phonetic");
                    break;
                }

                phonetic = json_string_value(jsubprop);
            }
            else {
                jmap_parser_pop(parser);
                _jsunknown_to_vcard(parser, "components", comps, myprops, card);
                goto fail;
            }
        }

        if (!val) {
            jmap_parser_invalid(parser, "value");
            break;
        }

        if (!kind) {
            jmap_parser_invalid(parser, "kind");
            break;
        }
        else if (!strcmp(kind, "separator")) {
            if (isordered) {
                /* Add separator entry to JSCOMPS */
                sep = val;
                buf_setcstr(&buf, sep);
                entry = vcardstrarray_new(2);
                vcardstrarray_append(entry, "s");
                vcardstrarray_append(entry, buf_cstring(&buf));
                vcardstructured_set_field_at(jscomps,
                        vcardstructured_num_fields(jscomps), entry);
            }
            else {
                jmap_parser_invalid(parser, "kind");
                break;
            }
        }
        else {
            const struct comp_kind *ckind =
                _field_name_to_kind(kind, args->comp_kinds);
            vcardstrarray *field;

            if (!ckind) {
                jmap_parser_invalid(parser, "kind");
                break;
            }

            /* Add phonetic to proper field */
            if (phonetic) {
                field = vcardstructured_field_at(ph, ckind->idx);
                if (!field) {
                    field = vcardstrarray_new(1);
                    vcardstructured_set_field_at(ph, ckind->idx, field);
                }
                vcardstrarray_append(field, phonetic);
            }

            /* Add value to proper field */
            field = vcardstructured_field_at(vals, ckind->idx);
            if (!field) {
                field = vcardstrarray_new(1);
                vcardstructured_set_field_at(vals, ckind->idx, field);
            }
            vcardstrarray_append(field, val);

            if (isordered) {
                /* Add positional entry (field idx [value idx]) to JSCOMPS */
                entry = vcardstrarray_new(2);
                buf_reset(&buf);
                buf_printf(&buf, "%d", ckind->idx);
                vcardstrarray_append(entry, buf_cstring(&buf));
                if (vcardstrarray_size(field) > 1) {
                    buf_reset(&buf);
                    buf_printf(&buf, "%lu", vcardstrarray_size(field) - 1);
                    vcardstrarray_append(entry, buf_cstring(&buf));
                }
                vcardstructured_set_field_at(jscomps,
                        vcardstructured_num_fields(jscomps), entry);
            }

            /* Also add values from extended fields to legacy fields */
            if (ckind->flags & FIELD_BWD) {
                field = vcardstructured_field_at(vals, ckind->alt_idx);
                if (!field) {
                    field = vcardstrarray_new(1);
                    vcardstructured_set_field_at(vals, ckind->alt_idx, field);
                }
                vcardstrarray_append(field, val);

                /* We need extended fields unless this one
                   maps to a legacy field with the same JS component name */
                if (!(ckind->flags & FIELD_NOEX))
                    needs_extended = true;
            }
        }

        jmap_parser_pop(parser);
    }

    if (i != size) {
        jmap_parser_pop(parser);
        goto fail;
    }

    if (args->derived) {
        /* Derive the full-name string from the components */
        _jsname_concat_components(obj, args->derived);
    }

    if (!needs_extended) {
        /* Shrink number of fields being used */
        vcardstructured_set_num_fields(vals, args->min_num_comps);
        vcardstructured_set_num_fields(ph, args->min_num_comps);
    }

    prop = args->vanew_prop(vals,
                            jscomps ? vcardparameter_new_jscomps(jscomps) : NULL,
                            NULL);

    if (ph_system) {
        vcardproperty_add_parameter(prop, vcardparameter_new_altid(args->id));

        /* Add alternate property */
        vcardparameter *param = vcardparameter_new(VCARD_PHONETIC_PARAMETER);

        vcardparameter_set_value_from_string(param, ph_system);
        vcardcomponent_add_property(card,
                                    args->vanew_prop(ph,
                                                     vcardparameter_new_altid(args->id),
                                                     param,
                                                     NULL));
    }

    json_object_del(obj, "components");
    json_object_del(obj, "isOrdered");
    json_object_del(obj, "phoneticSystem");
    json_object_del(obj, "defaultSeparator");

    buf_free(&buf);

    vcardstructured_unref(vals);
    vcardstructured_unref(ph);
    vcardstructured_unref(jscomps);

    return prop;

  fail:
    vcardstructured_unref(vals);
    vcardstructured_unref(ph);
    vcardstructured_unref(jscomps);

    if (args->derived) {
        buf_reset(args->derived);
    }
    buf_free(&buf);

    json_object_del(obj, "components");
    json_object_del(obj, "isOrdered");
    json_object_del(obj, "phoneticSystem");
    json_object_del(obj, "defaultSeparator");

    return NULL;
}

static void _jsname_to_vcard(struct jmap_parser *parser, json_t *jval,
                             struct l10n_by_id_t *l10n,
                             vcardcomponent *card)
{
    struct l10n_rock lrock = { 0, NULL, { .prop_cb = &_jsname_to_vcard } };
    struct jscomps_args args = {
        &vcardproperty_vanew_n, VCARD_NUM_BASE_N_FIELDS, VCARD_NUM_N_FIELDS,
        "n1", "NameComponent", n_comp_kinds, NULL
    };
    const char *myprops[] = {
        "@type", "full", "sortAs",
        "phoneticSystem", "isOrdered", "defaultSeparator", "components", NULL
    };
    vcardstrarray *sortas = NULL;
    vcardproperty *prop = NULL;
    const char *key, *fullName = NULL;
    struct buf buf = BUF_INITIALIZER;
    json_t *jprop, *jsubprop;
    size_t i;

    if (!json_is_object(jval)) {
        jmap_parser_invalid(parser, "name");
        return;
    }

    _jsl10n_to_vcard(parser, jval, "name", NULL, l10n, card, &lrock);

    jmap_parser_push(parser, "name");

    /* Add base object to Card */
    jprop = json_object_get(jval, "@type");
    if (jprop && strcmpsafe("Name", json_string_value(jprop))) {
        jmap_parser_invalid(parser, "@type");
        goto done;
    }

    jprop = json_object_get(jval, "full");
    if (json_is_string(jprop)) {
        buf_setcstr(&buf, json_string_value(jprop));
        buf_trim(&buf);

        if (buf_len(&buf)) {
            fullName = buf_cstring(&buf);
        }
    }
    else if (jprop || !json_object_get(jval, "components")) {
        jmap_parser_invalid(parser, "full");
        goto done;
    }

    if (json_object_get(jval, "sortAs") &&
        !json_object_get(jval, "components")) {
        jmap_parser_invalid(parser, "sortAs");
        goto done;
    }

    /* Only derive the full-name string here when it is emitted as a
       localized FN below; otherwise _jscard_derive_fn() derives it once. */
    if (!fullName && l10n->lang && *l10n->lang) args.derived = &buf;

    prop = _jscomps_to_vcard(parser, jval, card, &args);

    if (prop) {
        vcardcomponent_add_property(card, prop);

        if (l10n->lang) {
            vcardproperty_add_parameter(prop, vcardparameter_new_altid("n1"));

            if (*l10n->lang) {
                vcardproperty_add_parameter(prop,
                                            vcardparameter_new_language(l10n->lang));
            }
        }

        jprop = json_object_get(jval, "sortAs");
        if (jprop) {
            const char *fields[VCARD_NUM_N_FIELDS] = { 0 };
            unsigned last_field = 0;
            void *tmp;

            if (!json_is_object(jprop)) {
                jmap_parser_invalid(parser, "sortAs");
                goto done;
            }

            jmap_parser_push(parser, "sortAs");

            json_object_foreach_safe(jprop, tmp, key, jsubprop) {
                const struct comp_kind *ckind =
                    _field_name_to_kind(key, n_comp_kinds);

                if (!ckind) {
                    _jsunknown_to_vcard(parser, key, jsubprop, myprops, card);
                }

                fields[ckind->idx] = json_string_value(jsubprop);
                last_field = MAX(last_field, ckind->idx);
            }

            sortas = vcardstrarray_new(1);

            for (i = 0; i <= (size_t) last_field; i++) {
                vcardstrarray_append(sortas, fields[i] ? fields[i] : "");
            }

            /* Add SORT-AS parameter */
            vcardproperty_add_parameter(prop, vcardparameter_new_sortas_list(sortas));

            jmap_parser_pop(parser);
        }
    }

    if (l10n->lang && *l10n->lang && buf_len(&buf)) {
        /* Add localized FN property; non-localized FN is derived later */
        prop = vcardproperty_vanew_fn(
            buf_cstring(&buf),
            !fullName ? vcardparameter_new_derived(VCARD_DERIVED_TRUE) : 0,
            NULL);
        vcardcomponent_add_property(card, prop);
        vcardproperty_add_parameter(prop,
                                    vcardparameter_new_language(l10n->lang));
    }

    json_object_del(jval, "@type");
    json_object_del(jval, "full");
    json_object_del(jval, "sortAs");

    /* Add unknown properties */
    json_object_foreach(jval, key, jprop) {
        _jsunknown_to_vcard(parser, key, jprop, myprops, card);
    }

  done:
    jmap_parser_pop(parser);
    buf_free(&buf);
}

static vcardproperty *_jsnickname_to_vcard(struct jmap_parser *parser,
                                           json_t *obj,
                                           const char *id __attribute__((unused)),
                                           vcardcomponent *card __attribute__((unused)),
                                           void *rock __attribute__((unused)))
{
    const char *val = json_string_value(json_object_get(obj, "name"));
    vcardproperty *prop = NULL;

    if (!val) {
        jmap_parser_invalid(parser, "name");
    }
    else {
        vcardstrarray *sa = vcardstrarray_new(1);

        vcardstrarray_append(sa, val);

        prop = vcardproperty_new_nickname(sa);

        json_object_del(obj, "name");
    }

    return prop;
}

static vcardproperty *_jsorg_to_vcard(struct jmap_parser *parser, json_t *obj,
                                      const char *id, vcardcomponent *card,
                                      void *rock)
{
    hash_table *groups = rock;
    vcardstrarray *units = NULL, *sortas = NULL;
    vcardproperty *prop = NULL;
    json_t *jprop;

    jprop = json_object_get(obj, "name");
    if (json_is_string(jprop)) {
        units = vcardstrarray_new(1);
        vcardstrarray_append(units, json_string_value(jprop));
    }
    else if (jprop) {
        jmap_parser_invalid(parser, "name");
        return NULL;
    }

    jprop = json_object_get(obj, "sortAs");
    if (json_is_string(jprop)) {
        sortas = vcardstrarray_new(1);
        vcardstrarray_append(sortas, json_string_value(jprop));
    }
    else if (jprop) {
        jmap_parser_invalid(parser, "sortAs");
        if (units) vcardstrarray_free(units);
        return NULL;
    }

    jprop = json_object_get(obj, "units");
    if (json_is_array(jprop)) {
        size_t i, size = json_array_size(jprop);

        if (!units) {
            units = vcardstrarray_new(1);
            vcardstrarray_append(units, "");
        }

        for (i = 0; i < size; i++) {
            const char *myprops[] = { "@type", "name", "sortAs", NULL };
           json_t *unit = json_array_get(jprop, i);
            const char *key, *val;
            json_t *jsubprop;

            jmap_parser_push_index(parser, "units", i, NULL);

            jsubprop = json_object_get(unit, "@type");
            if (jsubprop && strcmpsafe("OrgUnit", json_string_value(jsubprop))) {
                jmap_parser_invalid(parser, "@type");
                break;
            }

            val = json_string_value(json_object_get(unit, "name"));
            if (val) {
                vcardstrarray_append(units, val);
            }
            else {
                jmap_parser_invalid(parser, "name");
                break;
            }

            jsubprop = json_object_get(unit, "sortAs");
            if (json_is_string(jsubprop)) {
                size_t num_empty;

                if (!sortas) {
                    sortas = vcardstrarray_new(1);
                }

                num_empty = i - vcardstrarray_size(sortas) + 1;
                while (num_empty--) {
                    vcardstrarray_append(sortas, "");
                }

                vcardstrarray_append(sortas, json_string_value(jsubprop));
            }
            else if (jsubprop) {
                jmap_parser_invalid(parser, "sortAs");
            }

            json_object_del(unit, "@type");
            json_object_del(unit, "name");
            json_object_del(unit, "sortAs");

            /* Add unknown properties */
            json_object_foreach(unit, key, jsubprop) {
                _jsunknown_to_vcard(parser, key, jsubprop, myprops, card);
            }

            jmap_parser_pop(parser);
        }

        if (i != size) {
            jmap_parser_pop(parser);
            vcardstrarray_free(units);
            units = NULL;
        }
    }
    else if (jprop) {
        jmap_parser_invalid(parser, "units");
    }

    if (units) {
        ptrarray_t *props = hash_lookup(id, groups);

        prop =  vcardproperty_new_org(units);
        if (sortas) {
            vcardproperty_add_parameter(prop, vcardparameter_new_sortas_list(sortas));
        }

        if (!props) {
            props = ptrarray_new();
            hash_insert(id, props, groups);
        }
        ptrarray_append(props, prop);
    }
    else if (sortas) {
        vcardstrarray_free(sortas);
    }

    json_object_del(obj, "name");
    json_object_del(obj, "units");
    json_object_del(obj, "sortAs");

    return prop;
}

static vcardproperty *_jspronoun_to_vcard(struct jmap_parser *parser, json_t *obj,
                                          const char *id __attribute__((unused)),
                                          vcardcomponent *card __attribute__((unused)),
                                          void *rock __attribute__((unused)))
{
    const char *val = json_string_value(json_object_get(obj, "pronouns"));
    vcardproperty *prop = NULL;

    if (!val) {
        jmap_parser_invalid(parser, "pronouns");
    }
    else {
        prop = vcardproperty_new_pronouns(val);

        json_object_del(obj, "pronouns");
    }

    return prop;
}

static void _jsspeak_to_vcard(struct jmap_parser *parser,
                              json_t *jval, struct l10n_by_id_t *l10n,
                              vcardcomponent *card)
{
    struct l10n_rock lrock = { 0, NULL, { .prop_cb = &_jsspeak_to_vcard } };
    const char *myprops[] = { "@type", "grammaticalGender", "pronouns", NULL };
    json_t *jprop;
    const char *key;

    if (!json_is_object(jval)) {
        jmap_parser_invalid(parser, "speakToAs");
        return;
    }

    _jsl10n_to_vcard(parser, jval, "speakToAs", NULL, l10n, card, &lrock);
    jmap_parser_push(parser, "speakToAs");

    /* Add base object to Card */
    jprop = json_object_get(jval, "@type");
    if (jprop && strcmpsafe("SpeakToAs", json_string_value(jprop))) {
        jmap_parser_invalid(parser, "@type");
        goto done;
    }

    jprop = json_object_get(jval, "grammaticalGender");
    if (jprop) {
        if (!jssimple_to_vcard(parser, "grammaticalGender", l10n->lang, jprop,
                               card, VCARD_GRAMGENDER_PROPERTY,
                               VCARD_GRAMGENDER_VALUE)) {
            goto done;
        }
    }

    jprop = json_object_get(jval, "pronouns");
    if (jprop) {
        _jsmultiobject_to_card(parser, jprop, "pronouns", "Pronouns",
                               &_jspronoun_to_vcard, WANT_PROPID_FLAG,
                               pref_param_props, l10n, card, NULL);
    }

    json_object_del(jval, "@type");
    json_object_del(jval, "grammaticalGender");
    json_object_del(jval, "pronouns");

    /* Add unknown properties */
    json_object_foreach(jval, key, jprop) {
        _jsunknown_to_vcard(parser, key, jprop, myprops, card);
    }

  done:
    jmap_parser_pop(parser);
}

static vcardproperty *_jstitle_to_vcard(struct jmap_parser *parser, json_t *obj,
                                        const char *id __attribute__((unused)),
                                        vcardcomponent *card __attribute__((unused)),
                                        void *rock)
{
    hash_table *groups = rock;
    vcardproperty_kind kind = VCARD_NO_PROPERTY;
    vcardproperty *prop = NULL;
    json_t *jprop;
    const char *val;

    jprop = json_object_get(obj, "kind");
    if (json_is_string(jprop)) {
        val = json_string_value(jprop);

        if (!strcmp("title", val)) {
            kind = VCARD_TITLE_PROPERTY;
        }
        else if (!strcmp("role", val)) {
            kind = VCARD_ROLE_PROPERTY;
        }
        else {
            jmap_parser_invalid(parser, "kind");
        }
    }
    else if (jprop) {
        jmap_parser_invalid(parser, "kind");
    }
    else {
        kind = VCARD_TITLE_PROPERTY;
    }

    if (kind != VCARD_NO_PROPERTY) {
        val = json_string_value(json_object_get(obj, "name"));
        if (!val) {
            jmap_parser_invalid(parser, "name");
        }
        else {
            json_t *jprop = json_object_get(obj, "organizationId");

            prop = vcardproperty_new(kind);
            vcardproperty_set_value_from_string(prop, val, "TEXT");

            if (json_is_string(jprop)) {
                const char *group = json_string_value(jprop);
                ptrarray_t *props = hash_lookup(group, groups);

                if (!props) {
                    props = ptrarray_new();
                    hash_insert(group, props, groups);
                }
                ptrarray_append(props, prop);

                json_object_del(obj, "organizationId");
            }
            else if (jprop) {
                jmap_parser_invalid(parser, "organizationId");
            }

            json_object_del(obj, "kind");
            json_object_del(obj, "name");
        }
    }

    return prop;
}

struct comm_rock {
    const char *val_key;
    vcardproperty_kind kind;
};

static vcardproperty *_jscomm_to_vcard(struct jmap_parser *parser, json_t *obj,
                                       const char *id __attribute__((unused)),
                                       vcardcomponent *card __attribute__((unused)),
                                       void *rock)
{
    struct comm_rock *crock = rock;
    vcardproperty *prop = NULL;
    const char *val = json_string_value(json_object_get(obj, crock->val_key));
    const char *val_kind = "URI";

    if (!val) {
        jmap_parser_invalid(parser, crock->val_key);
    }
    else {
        size_t i, len = strlen(val), have_scheme = 0;

        for (i = 0; i < len; i++) {
            if (!isascii(val[i]) || !isprint(val[i]) || isspace(val[i]))
                break;
            else if (i && val[i] == ':')
                have_scheme = 1;
        }

        if (!have_scheme || i < len) val_kind = "TEXT";

        prop = vcardproperty_new(crock->kind);
        vcardproperty_set_value_from_string(prop, val, val_kind);

        json_object_del(obj, crock->val_key);
    }

    return prop;
}

static vcardproperty *_jsonline_to_vcard(struct jmap_parser *parser, json_t *obj,
                                         const char *id __attribute__((unused)),
                                         vcardcomponent *card __attribute__((unused)),
                                         void *rock __attribute__((unused)))
{
    const char *service = NULL, *user = NULL, *uri = NULL;
    vcardproperty *prop = NULL;
    struct buf buf = BUF_INITIALIZER;

    // Validate OnlineService object.

    json_t *jprop = json_object_get(obj, "service");
    if (json_is_string(jprop)) {
        service = json_string_value(jprop);
    }
    else if (jprop) {
        jmap_parser_invalid(parser, "service");
    }

    jprop = json_object_get(obj, "user");
    if (json_is_string(jprop)) {
        user = json_string_value(jprop);
    }
    else if (jprop) {
        jmap_parser_invalid(parser, "user");
    }

    jprop = json_object_get(obj, "uri");
    if (json_is_string(jprop)) {
        uri = json_string_value(jprop);
    }
    else if (jprop) {
        jmap_parser_invalid(parser, "uri");
    }

    if (!uri && !user) {
        // One of uri or user must be set.
        jmap_parser_invalid(parser, "uri");
        jmap_parser_invalid(parser, "user");
        goto done;
    }

    const char *vcardname =
        json_string_value(json_object_get(obj, "vCardName"));
    json_t *jvcardparams = json_object_get(obj, "vCardParams");

    // Convert OnlineService to vCard property.

    if (!strcasecmpsafe(vcardname, "SOCIALPROFILE")) {
        // Use SOCIALPROFILE property if object was converted from it.
        prop = vcardproperty_new(VCARD_SOCIALPROFILE_PROPERTY);

        if (uri) {
            vcardproperty_set_value(prop, vcardvalue_new_uri(uri));
            if (user) {
              vcardproperty_add_parameter(prop,
                                          vcardparameter_new_username(user));
            }
        }
        else {
            vcardproperty_set_value(prop, vcardvalue_new_text(user));
            vcardproperty_add_parameter(
                prop, vcardparameter_new_value(VCARD_VALUE_TEXT));
        }

        if (service) {
            vcardproperty_add_parameter(prop,
                    vcardparameter_new_servicetype(service));
        }
    } else if ((!user && !vcardname) ||
               (!strcasecmpsafe(vcardname, "IMPP") &&
                (!user ||
                 (user && (json_object_get(jvcardparams, "username") ||
                           json_object_get(jvcardparams, "x-user")))))) {
      // Use IMPP if 'user' isn't set and this is a new OnlineService object,
      // or if the property got converted from IMPP and either 'user' isn't
      // set or the USERNAME or X-USER parameters already were set.
      prop = vcardproperty_new(VCARD_IMPP_PROPERTY);
      vcardproperty_set_value(prop, vcardvalue_new_uri(uri));

      if (service) {
          vcardparameter *param = vcardparameter_new_x(service);
          vcardparameter_set_xname(param, "X-SERVICE-TYPE");
          vcardproperty_add_parameter(prop, param);
      }

      if (user) {
          vcardparameter *param;
          if (json_object_get(jvcardparams, "x-user")) {
              param = vcardparameter_new_x(user);
              vcardparameter_set_xname(param, "X-USER");
          }
          else {
              param = vcardparameter_new_username(user);
          }
          vcardproperty_add_parameter(prop, param);
      }

      json_object_del(jvcardparams, "username");
      json_object_del(jvcardparams, "x-user");

    } else {
        // Use X-CYRUS-ONLINESERVICE in all other cases.
        vcardstructuredtype *st = vcardstructured_new(2);
        vcardstrarray *field = vcardstrarray_new(1);
        if (user) vcardstrarray_add(field, user);
        vcardstructured_set_field_at(st, 0, field);

        field = vcardstrarray_new(1);
        if (uri) vcardstrarray_add(field, uri);
        vcardstructured_set_field_at(st, 1, field);

        prop = vcardproperty_new(VCARD_X_PROPERTY);
        vcardproperty_set_x_name(prop, "X-CYRUS-ONLINESERVICE");
        vcardproperty_set_value(prop, vcardvalue_new_structured(st));
        vcardstructured_unref(st);

        if (service) {
            vcardparameter *param = vcardparameter_new_x(service);
            vcardparameter_set_xname(param, "X-SERVICE-TYPE");
            vcardproperty_add_parameter(prop, param);
        }
    }

done:
    json_object_del(obj, "service");
    json_object_del(obj, "user");
    json_object_del(obj, "uri");
    json_object_del(obj, "vCardName");

    buf_free(&buf);

    return prop;
}

static vcardproperty *_jspreflang_to_vcard(struct jmap_parser *parser,
                                           json_t *obj,
                                           const char *id __attribute__((unused)),
                                           vcardcomponent *card __attribute__((unused)),
                                           void *rock __attribute__((unused)))
{
    const char *lang = json_string_value(json_object_get(obj, "language"));
    vcardproperty *prop = NULL;

    if (!lang) {
        jmap_parser_invalid(parser, "language");
    }
    else {
        prop = vcardproperty_new_lang(lang);

        json_object_del(obj, "language");
    }

    return prop;
}

struct resource_map {
    const char *kind;
    vcardproperty_kind pkind;
    unsigned supports_blobid : 1;
};

struct resource_rock {
    struct resource_map *map;
    jscontact_ctx_t *ctx;
};

static vcardproperty *_jsresource_to_vcard(struct jmap_parser *parser, json_t *obj,
                                           const char *id,
                                           vcardcomponent *card __attribute__((unused)),
                                           void *rock)
{
    struct resource_rock *rrock = rock;
    struct resource_map *m;
    vcardproperty_kind pkind;
    const char *mkind, *uri = NULL;
    struct buf buf = BUF_INITIALIZER;
    char *media_type = NULL;
    json_t *jprop;

    mkind = json_string_value(json_object_get(obj, "kind"));
    for (m = rrock->map; m->kind; m++) {
        if (!strcmpnull(m->kind, mkind)) {
            break;
        }
    }
    pkind = m->pkind;

    if (pkind == VCARD_NO_PROPERTY) {
        jmap_parser_invalid(parser, "kind");
        goto fail;
    }

    jprop = json_object_get(obj, "uri");
    if (json_is_string(jprop)) {
        uri = json_string_value(jprop);
    }
    else if (jprop) {
        jmap_parser_invalid(parser, "uri");
        goto fail;
    }

    media_type =
        xstrdupnull(json_string_value(json_object_get(obj, "mediaType")));

    if (m->supports_blobid) {
        jscontact_ctx_t *ctx = rrock->ctx;
        struct buf blob = BUF_INITIALIZER;
        bool have_blob = false;

        /* blobId supersedes uri */
        jprop = json_object_get(obj, "blobId");
        if (jprop) {
            /* Extract blobId */
            if (!json_is_string(jprop) || !ctx->getblob) {
                jmap_parser_invalid(parser, "blobId");
                goto fail;
            }

            struct buf blobtype = BUF_INITIALIZER;
            int r = ctx->getblob(ctx->blob_rock,
                                 json_string_value(json_object_get(obj,
                                                                   "accountId")),
                                 json_string_value(jprop),
                                 media_type, &blob, &blobtype);

            /* A media type that is not a MIME type is of no use here */
            if (!r && buf_len(&blobtype) && !strchr(buf_cstring(&blobtype), '/'))
                r = HTTP_NOT_ACCEPTABLE;

            if (r) {
                buf_free(&blobtype);
                buf_free(&blob);
                if (r == HTTP_NOT_ACCEPTABLE)
                    jmap_parser_invalid(parser, "mediaType");
                else
                    ctx->blob_error = r;
                goto fail;
            }

            buf_printf(&buf, "data:%s;base64,", buf_lcase(&blobtype));

            const char *base = buf_base(&blob);
            size_t len = buf_len(&blob);

            /* Pre-flight base64 encoder to determine length */
            size_t len64 = 0;
            charset_b64encode_mimebody(NULL, len, NULL,
                                    &len64, NULL, 0 /* no wrap */);

            /* Now encode the blob */
            buf_ensure(&buf, len64+1);
            charset_b64encode_mimebody(base, len,
                                    (char *) buf_base(&buf) + buf_len(&buf),
                                    &len64, NULL, 0 /* no wrap */);
            buf_truncate(&buf, buf_len(&buf) + len64);
            uri = buf_cstring(&buf);

            if (!media_type) media_type = buf_release(&blobtype);
            else buf_free(&blobtype);
            have_blob = true;

            json_object_del(obj, "blobId");
            json_object_del(obj, "accountId");
        }
        else if (uri && !strncmp(uri, "data:", 5)) {
            const char *comma = strchr(uri, ',');
            char *decbuf = NULL;
            size_t size = 0;

            if (!comma) {
                jmap_parser_invalid(parser, "uri");
                goto fail;
            }

            if (!media_type) {
                const char *mt = uri + 5;

                size = strcspn(mt, ";,");
                if (size) {
                    media_type = xstrndup(mt, size);
                }
            }

            /* Decode property value */
            const char *data = comma + 1;
            charset_decode_mimebody(data, strlen(data),
                                    ENCODING_BASE64, &decbuf, &size);
            buf_initm(&blob, decbuf, size);
            have_blob = true;
        }

        if (have_blob) {
            /* The media type is encoded in the data: URI */
            json_object_del(obj, "mediaType");

            /* Let the caller assign a blob id to this value */
            if (ctx->addblob) {
                ctx->addblob(ctx->blob_rock, id,
                             vcardproperty_kind_to_string(pkind),
                             media_type, &blob);
            }
        }

        buf_free(&blob);
    }

    if (!uri) {
        jmap_parser_invalid(parser, "uri");
        goto fail;
    }

    vcardproperty *prop = vcardproperty_new(pkind);
    vcardproperty_set_value_from_string(prop, uri, "URI");

    json_object_del(obj, "kind");
    json_object_del(obj, "uri");

    free(media_type);
    buf_free(&buf);

    return prop;

  fail:
    free(media_type);
    buf_free(&buf);

    return NULL;
}

static vcardproperty *_jsaddr_to_vcard(struct jmap_parser *parser, json_t *obj,
                                       const char *id, vcardcomponent *card,
                                       void *rock __attribute__((unused)))
{
    struct jscomps_args args = {
        &vcardproperty_vanew_adr, VCARD_NUM_BASE_ADR_FIELDS, VCARD_NUM_ADR_FIELDS,
        id, "AddressComponent", adr_comp_kinds, NULL
    };
    json_t *comps = json_object_get(obj, "components");

    if (comps && !json_boolean_value(json_object_get(obj, "isOrdered"))) {
        /* Bubble sort the components by kind
           (for building extended/street fields) */
        size_t i, j, size = json_array_size(comps);

        for (i = 0; i < size - 1; i++) {
            int swap = 0;

            for (j = 0; j < size - i - 1; j++) {
                json_t *comp1 = json_array_get(comps, j);
                json_t *comp2 = json_array_get(comps, j+1);
                const char *kind1 =
                    json_string_value(json_object_get(comp1, "kind"));
                const char *kind2 =
                    json_string_value(json_object_get(comp2, "kind"));
                const struct comp_kind *ckind1 =
                    kind1 ? _field_name_to_kind(kind1, adr_comp_kinds) : NULL;
                const struct comp_kind *ckind2 =
                    kind2 ? _field_name_to_kind(kind2, adr_comp_kinds) : NULL;

                if (!ckind1 || !ckind2) break;

                if (ckind1 > ckind2) {
                    json_t *tmp = json_copy(comp1);
                    json_array_set(comps, j, comp2);
                    json_array_set_new(comps, j+1, tmp);
                    swap = 1;
                }
            }

            if (!swap) break;
        }
    }

    return _jscomps_to_vcard(parser, obj, card, &args);
}

static vcardproperty *_jsanniv_to_vcard(struct jmap_parser *parser,
                                        json_t *anniv, const char *id,
                                        vcardcomponent *card,
                                        void *rock __attribute__((unused)))
{
    vcardproperty_kind date_kind, place_kind = VCARD_NO_PROPERTY;
    vcardproperty *prop = NULL;
    json_t *jprop, *jsubprop;
    const char *key, *val;

    val = json_string_value(json_object_get(anniv, "kind"));
    if (!strcmpsafe("birth", val)) {
        date_kind = VCARD_BDAY_PROPERTY;
        place_kind = VCARD_BIRTHPLACE_PROPERTY;
    }
    else if (!strcmpsafe("death", val)) {
        date_kind = VCARD_DEATHDATE_PROPERTY;
        place_kind = VCARD_DEATHPLACE_PROPERTY;
    }
    else if (!strcmpsafe("wedding", val)) {
        date_kind = VCARD_ANNIVERSARY_PROPERTY;
    }
    else {
        _jsunknown_to_vcard(parser, NULL, anniv, NULL, card);
        return NULL;
    }

    json_object_del(anniv, "kind");

    jprop = json_object_get(anniv, "date");
    if (json_is_object(jprop)) {
        const char *myprops[] = {
            "@type", "year", "month", "day", "calendarScale", "utc", NULL
        };
        const char *calscale = NULL;
        vcardvalue *value = NULL;
        vcardtimetype tt;

        jmap_parser_push(parser, "date");

        jsubprop = json_object_get(jprop, "@type");
        if (!jsubprop ||  // defaultType
            !strcmpsafe("PartialDate", json_string_value(jsubprop))) {

            json_object_del(jprop, "@type");

            tt = vcardtime_null_date();

            jsubprop = json_object_get(jprop, "year");
            if (json_is_integer(jsubprop)) {
                tt.year = json_integer_value(jsubprop);
                json_object_del(jprop, "year");
            }
            else if (jsubprop) {
                jmap_parser_invalid(parser, "year");
            }

            jsubprop = json_object_get(jprop, "month");
            if (json_is_integer(jsubprop)) {
                tt.month = json_integer_value(jsubprop);
                json_object_del(jprop, "month");
            }
            else if (jsubprop) {
                jmap_parser_invalid(parser, "month");
            }

            jsubprop = json_object_get(jprop, "day");
            if (json_is_integer(jsubprop)) {
                tt.day = json_integer_value(jsubprop);
                json_object_del(jprop, "day");
            }
            else if (jsubprop) {
                jmap_parser_invalid(parser, "day");
            }

            jsubprop = json_object_get(jprop, "calendarScale");
            if (json_is_string(jsubprop)) {
                calscale = json_string_value(jsubprop);
            }
            else if (jsubprop) {
                jmap_parser_invalid(parser, "calendarScale");
            }

            if (!vcardtime_is_null_datetime(tt)) {
                value = vcardvalue_new_date(tt);
            }
        }
        else if (!strcmpsafe("Timestamp", json_string_value(jsubprop))) {
            jsubprop = json_object_get(jprop, "utc");
            if (!json_is_utcdate(jsubprop)) {
                jmap_parser_invalid(parser, "utc");
            }
            else {
                tt = vcardtime_from_string(json_string_value(jsubprop), 0);
                value = vcardvalue_new_timestamp(tt);
                json_object_del(jprop, "utc");
            }
        }
        else {
            jmap_parser_invalid(parser, "@type");
        }

        if (value) {
            prop = vcardproperty_new(date_kind);
            vcardproperty_set_value(prop, value);

            if (calscale) {
                vcardparameter *param =
                    vcardparameter_new_from_value_string(VCARD_CALSCALE_PARAMETER,
                                                         calscale);
                vcardproperty_add_parameter(prop, param);
            }

            json_object_del(jprop, "@type");
            json_object_del(jprop, "calendarScale");
        }

        /* Add unknown properties */
        json_object_foreach(jprop, key, jsubprop) {
            _jsunknown_to_vcard(parser, key, jsubprop, myprops, card);
        }

        json_object_del(anniv, "date");

        jmap_parser_pop(parser);
    }
    else if (jprop) {
        jmap_parser_invalid(parser, "date");
        return NULL;
    }

    jprop = json_object_get(anniv, "place");
    if (json_is_object(jprop)) {
        if (place_kind != VCARD_NO_PROPERTY) {
            const char *myprops[] = { "@type", "full", "coordinates", NULL };

            jmap_parser_push(parser, "place");

            jsubprop = json_object_get(jprop, "@type");
            if (jsubprop && strcmpsafe("Address", json_string_value(jsubprop))) {
                jmap_parser_invalid(parser, "@type");
            }
            else {
                const char *val_kind = NULL;

                if ((val =
                     json_string_value(json_object_get(jprop, "full")))) {
                    val_kind = "TEXT";
                }
                else if ((val =
                          json_string_value(json_object_get(jprop,
                                                            "coordinates")))) {
                    val_kind = "URI";
                }

                if (val_kind) {
                    vcardproperty *myprop = vcardproperty_new(place_kind);

                    vcardproperty_set_value_from_string(myprop, val, val_kind);

                    if (!prop) {
                        prop = myprop;
                    }
                    else {
                        vcardproperty_add_parameter(myprop,
                                                    vcardparameter_new_propid(id));
                        vcardcomponent_add_property(card, myprop);
                    }
                }

                json_object_del(jprop, "@type");
                json_object_del(jprop, "full");
                json_object_del(jprop, "coordinates");

                /* Add unknown properties */
                json_object_foreach(jprop, key, jsubprop) {
                    _jsunknown_to_vcard(parser, key, jsubprop, myprops, card);
                }
            }

            jmap_parser_pop(parser);
        }
        else {
            _jsunknown_to_vcard(parser, "place", jprop, NULL, card);
        }

        json_object_del(anniv, "place");
    }
    else if (jprop) {
        jmap_parser_invalid(parser, "place");
        return NULL;
    }

    return prop;
}

static vcardproperty *_jsnote_to_vcard(struct jmap_parser *parser,
                                       json_t *obj,
                                       const char *id __attribute__((unused)),
                                       vcardcomponent *card __attribute__((unused)),
                                       void *rock __attribute__((unused)))
{
    vcardproperty *prop = NULL;
    json_t *jprop;
    const char *val;

    val = json_string_value(json_object_get(obj, "note"));
    if (!val) {
        jmap_parser_invalid(parser, "note");
        return NULL;
    }

    prop = vcardproperty_new_note(val);

    jprop = json_object_get(obj, "author");
    if (json_is_object(jprop)) {
        const char *myprops[] = { "@type", "name", "uri", NULL };
        json_t *jsubprop;
        const char *key;

        jmap_parser_push(parser, "author");

        jsubprop = json_object_get(jprop, "@type");
        if (jsubprop && strcmpsafe("Author", json_string_value(jsubprop))) {
            jmap_parser_invalid(parser, "@type");
        }
        else {
            jsubprop = json_object_get(jprop, "name");
            if (json_is_string(jsubprop)) {
                val = json_string_value(jsubprop);
                vcardproperty_add_parameter(prop,
                                            vcardparameter_new_authorname(val));

                json_object_del(jprop, "name");
            }
            else if (jsubprop) {
                jmap_parser_invalid(parser, "name");
            }

            jsubprop = json_object_get(jprop, "uri");
            if (json_is_string(jsubprop)) {
                val = json_string_value(jsubprop);
                vcardproperty_add_parameter(prop, vcardparameter_new_author(val));

                json_object_del(jprop, "uri");
            }
            else if (jsubprop) {
                jmap_parser_invalid(parser, "uri");
            }
        }

        json_object_del(jprop, "@type");

        /* Add unknown properties */
        json_object_foreach(jprop, key, jsubprop) {
            _jsunknown_to_vcard(parser, key, jsubprop, myprops, card);
        }

        json_object_del(obj, "author");

        jmap_parser_pop(parser);
    }
    else if (jprop) {
        jmap_parser_invalid(parser, "author");
    }

    json_object_del(obj, "note");

    return prop;
}

static vcardproperty *_jspersonal_to_vcard(struct jmap_parser *parser,
                                           json_t *obj,
                                           const char *id __attribute__((unused)),
                                           vcardcomponent *card __attribute__((unused)),
                                           void *rock __attribute__((unused)))
{
    vcardproperty_kind pkind;
    vcardproperty *prop = NULL;
    const char *val;

    val = json_string_value(json_object_get(obj, "kind"));
    if (!strcmpsafe("expertise", val)) {
        pkind = VCARD_EXPERTISE_PROPERTY;
    }
    else if (!strcmpsafe("hobby", val)) {
        pkind = VCARD_HOBBY_PROPERTY;
    }
    else if (!strcmpsafe("interest", val)) {
        pkind = VCARD_INTEREST_PROPERTY;
    }
    else {
        jmap_parser_invalid(parser, "kind");
        return NULL;
    }

    val = json_string_value(json_object_get(obj, "value"));
    if (!val) {
        jmap_parser_invalid(parser, "value");
        return NULL;
    }

    prop = vcardproperty_new(pkind);
    vcardproperty_set_value_from_string(prop, val, "TEXT");

    json_object_del(obj, "kind");
    json_object_del(obj, "value");

    return prop;
}

static void _set_groups(const char *key, void *val,
                        void *rock __attribute__((unused)))
{
    ptrarray_t *props = val;
    int i;

    for (i = 0; i < ptrarray_size(props); i++) {
        vcardproperty *prop = ptrarray_nth(props, i);

        vcardproperty_set_group(prop, key);
    }
}

struct bad_patch_rock {
    struct jmap_parser *parser;
    const char *key;
};

static void _invalid_l10n_patches_by_id(const char *id, void *val, void *rock)
{
    struct bad_patch_rock *brock = rock;
    json_t *patches = val, *jpatch;
    const char *lang;

    json_object_foreach(patches, lang, jpatch) {
        jmap_parser_push(brock->parser, lang);
        jmap_parser_push(brock->parser, brock->key);

        if (json_object_size(jpatch)) {
            struct buf buf = BUF_INITIALIZER;
            const char *path;
            int len;

            jmap_parser_push(brock->parser, id);
            buf_setcstr(&buf, jmap_parser_path(brock->parser));
            len = buf_len(&buf);

            json_object_foreach(jpatch, path, val) {
                if (*path) {
                    buf_putc(&buf, '/');
                    buf_appendcstr(&buf, path);
                }
                jmap_parser_invalid_path(brock->parser, buf_cstring(&buf));
                buf_truncate(&buf, len);
            }

            jmap_parser_pop(brock->parser);
            buf_free(&buf);
        }
        else {
            jmap_parser_invalid(brock->parser, id);
        }

        jmap_parser_pop(brock->parser);
        jmap_parser_pop(brock->parser);
    }

    json_decref(patches);
}

static void _invalid_l10n_patches_by_key(const char *key, void *val, void *rock)
{
    struct bad_patch_rock brock = { rock /* parser */, key };
    hash_table *patches_by_id = val;

    hash_enumerate(patches_by_id, &_invalid_l10n_patches_by_id, &brock);
    free_hash_table(patches_by_id, NULL);
    free(patches_by_id);
}

static const char *jprop_value_to_string(json_t *jval,
                                         vcardparameter_value val_type,
                                         struct buf *buf)
{
    const char *valstr = NULL;

    buf_reset(buf);

    switch (val_type) {
    case VCARD_VALUE_BOOLEAN:
        if (json_is_boolean(jval)) {
            buf_setcstr(buf, json_boolean_value(jval) ? "TRUE" : "FALSE");
            valstr = buf_cstring(buf);
        }
        break;

    case VCARD_VALUE_INTEGER:
        if (json_is_integer(jval)) {
            buf_printf(buf, "%" JSON_INTEGER_FORMAT,
                       json_integer_value(jval));
            valstr = buf_cstring(buf);
        }
        break;

    case VCARD_VALUE_FLOAT:
        if (json_is_real(jval)) {
            /* Write out 15 decimal digits */
            buf_printf(buf, "%.15f", json_real_value(jval));
            /* Strip trailing decimal zeros */
            int len = buf_len(buf);
            const char *endp = buf_base(buf) + len - 1;
            while (*endp-- == '0') len--;
            buf_truncate(buf, len);
            valstr = buf_cstring(buf);
        }
        break;

    default:
        if (json_is_string(jval)) {
            valstr = json_string_value(jval);
        }
        break;
    }

    return valstr;
}

static vcardstrarray *jprop_values_to_strarray(json_t *jvals, size_t idx,
                                               vcardparameter_value val_type,
                                               struct buf *buf)
{
    vcardstrarray *sa = vcardstrarray_new(1);
    size_t nvals = json_array_size(jvals);

    for (; idx < nvals; idx++) {
        json_t *jval = json_array_get(jvals, idx);
        const char *valstr = jprop_value_to_string(jval, val_type, buf);

        if (!valstr) {
            vcardstrarray_free(sa);
            return NULL;
        }

        vcardstrarray_append(sa, valstr);
    }

    return sa;
}

static void _vcardprops_to_card(struct jmap_parser *parser, json_t *jprops,
                                vcardcomponent *card)
{
    size_t i;
    json_t *jprop;
    struct buf buf = BUF_INITIALIZER;

    if (!json_is_array(jprops)) {
        jmap_parser_invalid(parser, "vCardProps");
        return;
    }

    jmap_parser_push(parser, "vCardProps");

    json_array_foreach(jprops, i, jprop) {
        const char *name, *typestr, *valstr;
        json_t *params, *jval;
        vcardstrarray *vals = NULL;

        // parse first 4 args
        if (json_unpack(jprop, "[soso]", &name, &params, &typestr, &jval)) break;

        // params MUST be an object
        if (!json_is_object(params)) break;

        // sanity check the value
        switch (json_typeof(jval)) {
        case JSON_OBJECT:
        case JSON_NULL:
            goto error;

        case JSON_ARRAY:
        // a structured value MUST be the only one & MUST NOT have too many comps
        if (json_array_size(jprop) > 4 || json_array_size(jval) > 20) goto error;

        default:
            break;
        }

        vcardproperty *prop = vcardproperty_new_x("");
        vcardparameter_value val_type = vcardparameter_string_to_enum(typestr);

        buf_setcstr(&buf, name);
        vcardproperty_set_x_name(prop, buf_ucase(&buf));
        vcardcomponent_add_property(card, prop);

        // string_to_enum might give us a TYPE enum rather than a VALUE enum
        if ((unsigned) val_type == VCARD_TYPE_TEXT)
            val_type = VCARD_VALUE_TEXT;
        else if ((unsigned) val_type == VCARD_TYPE_DATE)
            val_type = VCARD_VALUE_DATE;

        if (val_type)
          vcardproperty_add_parameter(prop, vcardparameter_new_value(val_type));

        _vcardparams_to_prop(params, prop);

        if (json_is_array(jval)) {
            vcardstructuredtype *st = vcardstructured_new(0);
            json_t *jcomp;
            size_t j;

            json_array_foreach(jval, j, jcomp) {
                if (json_is_array(jcomp)) {
                    vals = jprop_values_to_strarray(jcomp, 0, val_type, &buf);
                }
                else {
                    valstr = jprop_value_to_string(jcomp, val_type, &buf);
                    if (valstr) {
                        vals = vcardstrarray_new(1);
                        vcardstrarray_append(vals, valstr);
                    }
                }

                if (!vals) {
                    vcardstructured_unref(st);
                    goto error;
                }

                vcardstructured_set_field_at(st,
                        vcardstructured_num_fields(st), vals);
            }

            vcardproperty_set_value(prop, vcardvalue_new_structured(st));
            vcardstructured_unref(st);
        }
        else if (val_type) {
            vals = jprop_values_to_strarray(jprop, 3, val_type, &buf);

            if (!vals) goto error;

            vcardproperty_set_value(prop, vcardvalue_new_textlist(vals));
        }
        else {
            if (json_is_string(jval)) {
                buf_setcstr(&buf, json_string_value(jval));
            }
            else {
                char *tmp = json_dumps(jval, JSON_ENCODE_ANY);
                buf_setcstr(&buf, tmp);
                free(tmp);
            }
            vcardproperty_set_value(prop, vcardvalue_new_x(buf_cstring(&buf)));
        }
    }

 error:
    if (i < json_array_size(jprops)) {
        buf_reset(&buf);
        buf_printf(&buf, "%zu", i);
        jmap_parser_invalid(parser, buf_cstring(&buf));
    }

    jmap_parser_pop(parser);
    buf_free(&buf);
}

#define PROP_LANG_TAG_PREFIX      "cyrusimap.org:lang:"
#define PROP_LANG_TAG_PREFIX_LEN  19

static void reject_reserved_props(json_t *jsobj, struct jmap_parser *parser)
{
    if (JNULL(jsobj)) return;

    const char *key;
    json_t *jval;
    json_object_foreach(jsobj, key, jval) {
        if (!strcasecmp(key, "extra")) {
            jmap_parser_invalid(parser, key);
        }
        else if (strchr(key, '/')) {
            strarray_t *segs = strarray_split(key, "/", STRARRAY_LCASE);
            for (int i = 0; i < strarray_size(segs); i++) {
                if (!strcmp(strarray_nth(segs, i), "extra")) {
                    jmap_parser_invalid(parser, key);
                    break;
                }
            }
            strarray_free(segs);
        }

        for (size_t i = 0; i < json_array_size(jval); i++) {
            jmap_parser_push_index(parser, key, i, NULL);
            reject_reserved_props(json_array_get(jval, i), parser);
            jmap_parser_pop(parser);
        }

        if (json_object_size(jval)) {
            jmap_parser_push(parser, key);
            reject_reserved_props(jval, parser);
            jmap_parser_pop(parser);
        }
    }
}

/* Determine the value for the default (non-localized) FN property. */
static void _jscard_derive_fn(json_t *arg, const char *deflang,
                              vcardcomponent *card,
                              struct buf *fn, bool *is_derived)
{
    json_t *name = json_object_get(arg, "name");

    if (!json_is_object(name) && deflang) {
        /* No base name: fall back to the default-language localized name,
           stored under a language-tagged key (see PROP_LANG_TAG_PREFIX). */
        struct buf key = BUF_INITIALIZER;
        buf_printf(&key, "%s%s:name", PROP_LANG_TAG_PREFIX, deflang);
        name = json_object_get(arg, buf_cstring(&key));
        buf_free(&key);
    }

    buf_reset(fn);
    *is_derived = true;

    if (json_is_object(name)) {
        // Use provided full name, if set.
        const char *full = json_string_value(json_object_get(name, "full"));

        if (full) {
            /* Use the verbatim full name, but ignore whitespace-only values. */
            buf_setcstr(fn, full);
            buf_trim(fn);
            if (buf_len(fn)) {
                buf_setcstr(fn, full);
                *is_derived = false;
            }
        }

        // Derive FN from Name components.
        if (!buf_len(fn)) _jsname_concat_components(name, fn);
    }

    if (!buf_len(fn)) {
        // Derive FN from non-name properties.
        static const struct {
            const char *prop;
            const char *key;
        } derive_props[] = {
            { "organizations", "name" },
            { "nicknames",     "name" },
            { "emails",        "address" },
            { "phones",        "number" },
        };

        for (size_t i = 0;
             !buf_len(fn) && i < sizeof(derive_props) / sizeof(derive_props[0]);
             i++) {
            json_t *jprop = json_object_get(arg, derive_props[i].prop);

            const char *id;
            json_t *jobj;
            json_object_foreach (jprop, id, jobj) {
                const char *val = json_string_value(
                    json_object_get(jobj, derive_props[i].key));

                if (val) {
                    buf_setcstr(fn, val);
                    buf_trim(fn);
                    if (buf_len(fn)) break;
                }
            }
        }
    }

    if (!buf_len(fn)) {
        // Derive FN from UID.
        vcardproperty *uidprop =
            vcardcomponent_get_first_property(card, VCARD_UID_PROPERTY);
        if (uidprop) {
            const char *val = vcardproperty_get_value_as_string(uidprop);

            if (val) {
                /* Strip the "urn:uuid:" URI scheme, if present. */
                if (!strncmp(val, VCARD_MEMBER_URI_PREFIX,
                             VCARD_MEMBER_URI_PREFIX_LEN))
                    val += VCARD_MEMBER_URI_PREFIX_LEN;
                buf_setcstr(fn, val);
                buf_trim(fn);
            }
        }
    }

    // Fallback to "No Name".
    if (!buf_len(fn)) buf_setcstr(fn, "No Name");
}

static void jscard_to_vcard(jscontact_ctx_t *ctx,
                            vcardcomponent *card,
                            json_t *arg,
                            struct jmap_parser *parser)
{
    const char *key, *deflang = NULL, *lang, *p;
    json_t *jval;
    hash_table groups = HASH_TABLE_INITIALIZER;
    hash_table l10n_by_key = HASH_TABLE_INITIALIZER;
    struct buf buf = BUF_INITIALIZER;
    struct buf fn = BUF_INITIALIZER;
    bool fn_is_derived = false;
    unsigned has_localized_name = 0;

    /* Using reserved props is invalid */
    reject_reserved_props(arg, parser);

    /* Estimate upper bound for required vCard groups */
    size_t ngroups = 0;
    json_object_foreach(arg, key, jval) {
        ngroups += json_object_size(jval);
    }
    construct_hash_table(&groups, ngroups + 1, 0);

    /* Estimate upper bound for localized property count */
    size_t nl10n = 0;
    json_object_foreach(json_object_get(arg, "localizations"), lang, jval) {
        nl10n++;
    }
    construct_hash_table(&l10n_by_key, nl10n + 1, 0);

    deflang = json_string_value(json_object_get(arg, "language"));
    json_object_foreach(json_object_get(arg, "localizations"), lang, jval) {
        json_t *jsubval;

        json_object_foreach(jval, key, jsubval) {
            p = strchr(key, '/');

            if (p) {
                /* Localization patch:
                 *
                 * Patches are stored in a hash table (by property key)
                 * of hash tables (by object id) of JSON patches (by lang).
                 */
                hash_table *patches_by_id;
                const char *prop_key, *id = p+1, *path = "";
                json_t *patches_by_lang, *patch;

                buf_setmap(&buf, key, p - key);
                prop_key = buf_cstring(&buf);
                patches_by_id = hash_lookup(prop_key, &l10n_by_key);
                if (!patches_by_id) {
                    patches_by_id = xzmalloc(sizeof(hash_table));
                    construct_hash_table(patches_by_id, ngroups + 1, 0);
                    hash_insert(prop_key, patches_by_id, &l10n_by_key);
                }

                if (!strcmp(prop_key, "name") ||
                    !strcmp(prop_key, "speakToAs")) {
                    path = id;
                    id = "";
                }
                else {
                    p = strchr(id, '/');
                    if (p) {
                        buf_setmap(&buf, id, p - id);
                        id = buf_cstring(&buf);
                        path = ++p;
                    }
                }

                patches_by_lang = hash_lookup(id, patches_by_id);
                if (!patches_by_lang) {
                    patches_by_lang = json_object();
                    hash_insert(id, patches_by_lang, patches_by_id);
                }

                patch = json_object_get(patches_by_lang, lang);
                if (!patch) {
                    patch = json_object();
                    json_object_set_new(patches_by_lang, lang, patch);
                }

                json_object_set(patch, path, jsubval);
            }
            else {
                /* Localization object:
                 *
                 * Prefix the property key with vendor + language tags
                 * and add the object to the Card for normal processing.
                 */
                if (!strcmp("name", key)) {
                    has_localized_name = 1;
                }

                buf_reset(&buf);
                buf_printf(&buf, "%s%s:%s", PROP_LANG_TAG_PREFIX, lang, key);
                json_object_set(arg, buf_cstring(&buf), jsubval);
            }
        }
    }

    /* Derive the FN value before the properties get removed from arg */
    _jscard_derive_fn(arg, deflang, card, &fn, &fn_is_derived);

    json_object_foreach(arg, key, jval) {
        struct l10n_by_id_t l10n = { deflang, NULL, NULL };
        const char *mykey;

        if (!strcmp(key, "uid")) {
            /* The UID property is set from the Card's uid before the
               conversion starts, so there is nothing left to convert. */
            if (!json_is_string(jval) ||
                (ctx->uid && strcmp(ctx->uid, json_string_value(jval)))) {
                jmap_parser_invalid(parser, "uid");
            }
            continue;
        }

        /* Localization property? */
        if (!strncmp(PROP_LANG_TAG_PREFIX, key, PROP_LANG_TAG_PREFIX_LEN)) {
            /* Strip prefix and get language tag */
            lang = key + PROP_LANG_TAG_PREFIX_LEN;
            p = strchr(lang, ':');

            buf_setmap(&buf, lang, p - lang);
            lang = buf_cstring(&buf);
            mykey = ++p;

            /* If language tag == deflang,
               don't add LANGUAGE parameter, but still force ALTID parameter */
            l10n.lang = strcasecmpsafe(lang, l10n.deflang) ? lang : "";

            jmap_parser_push(parser, "localizations");
            jmap_parser_push(parser, lang);
        }
        else {
            /* Fetch any localization patches for this property */
            l10n.patches = hash_lookup(key, &l10n_by_key);
            if (l10n.patches) {
                /* Force ALTID parameter */
                l10n.lang = "";
            }
            mykey = key;
        }

        /* Metadata properties */
        if (!strcmp(mykey, "@type")) {
            if (strcmpsafe("Card", json_string_value(jval))) {
                jmap_parser_invalid(parser, "@type");
            }
        }
        else if (!strcmp(mykey, "version")) {
            if (strcmpsafe("1.0", json_string_value(jval))) {
                jmap_parser_invalid(parser, "version");
            }
        }
        else if (!strcmp(mykey, "created")) {
            jssimple_to_vcard(parser, mykey, l10n.lang,
                              jval, card,
                              VCARD_CREATED_PROPERTY,
                              VCARD_TIMESTAMP_VALUE);
        }
        else if (!strcmp(mykey, "kind")) {
            jssimple_to_vcard(parser, mykey, l10n.lang,
                              jval, card,
                              VCARD_KIND_PROPERTY,
                              VCARD_KIND_VALUE);
        }
        else if (!strcmp(mykey, "language")) {
            jssimple_to_vcard(parser, mykey, l10n.lang,
                              jval, card,
                              VCARD_LANGUAGE_PROPERTY,
                              VCARD_TEXT_VALUE);
        }
        else if (!strcmp(mykey, "members")) {
            _jsmultikey_to_card(parser, jval, mykey, card,
                                VCARD_MEMBER_PROPERTY);
        }
        else if (!strcmp(mykey, "prodId")) {
            jssimple_to_vcard(parser, mykey, l10n.lang,
                              jval, card,
                              VCARD_PRODID_PROPERTY,
                              VCARD_TEXT_VALUE);
        }
        else if (!strcmp(mykey, "relatedTo")) {
            struct param_prop_t relation_props[] = {
                { "relation", VCARD_TYPE_PARAMETER  },
                { NULL,       0                     }
            };

            _jsmultiobject_to_card(parser, jval,
                                   mykey, "Relation",
                                   &_jsrelation_to_vcard,
                                   0 /* no flags */,
                                   relation_props, &l10n,
                                   card, NULL);
        }
        else if (!strcmp(mykey, "updated")) {
            jssimple_to_vcard(parser, mykey, l10n.lang,
                              jval, card,
                              VCARD_REV_PROPERTY,
                              VCARD_TIMESTAMP_VALUE);
        }

        /* Name and Organization properties */
        else if (!strcmp(mykey, "name")) {
            if (!l10n.lang && has_localized_name) {
                l10n.lang = "";
            }
            _jsname_to_vcard(parser, jval, &l10n, card);
        }
        else if (!strcmp(mykey, "nicknames")) {
            _jsmultiobject_to_card(parser, jval,
                                   mykey, "Nickname",
                                   &_jsnickname_to_vcard,
                                   WANT_PROPID_FLAG,
                                   pref_param_props, &l10n,
                                   card, NULL);
        }
        else if (!strcmp(mykey, "organizations")) {
            _jsmultiobject_to_card(parser, jval,
                                   mykey, "Organization",
                                   &_jsorg_to_vcard,
                                   WANT_PROPID_FLAG,
                                   context_param_props, &l10n,
                                   card, &groups);
        }
        else if (!strcmp(mykey, "speakToAs")) {
            _jsspeak_to_vcard(parser, jval, &l10n, card);
        }
        else if (!strcmp(mykey, "titles")) {
            _jsmultiobject_to_card(parser, jval,
                                   mykey, "Title",
                                   &_jstitle_to_vcard,
                                   WANT_PROPID_FLAG,
                                   NULL, &l10n,
                                   card, &groups);
        }

        /* Contact properties */
        else if (!strcmp(mykey, "emails")) {
            struct comm_rock crock = { "address", VCARD_EMAIL_PROPERTY };

            _jsmultiobject_to_card(parser, jval,
                                   mykey, "EmailAddress",
                                   &_jscomm_to_vcard,
                                   WANT_PROPID_FLAG,
                                   comm_param_props, &l10n,
                                   card, &crock);
        }
        else if (!strcmp(mykey, "onlineServices")) {
            _jsmultiobject_to_card(parser, jval,
                                   mykey, "OnlineService",
                                   &_jsonline_to_vcard,
                                   WANT_PROPID_FLAG,
                                   comm_param_props, &l10n,
                                   card, NULL);
        }
        else if (!strcmp(mykey, "phones")) {
            struct comm_rock crock = { "number", VCARD_TEL_PROPERTY };

            _jsmultiobject_to_card(parser, jval,
                                   mykey, "Phone",
                                   &_jscomm_to_vcard,
                                   WANT_PROPID_FLAG,
                                   phone_param_props, &l10n,
                                   card, &crock);
        }
        else if (!strcmp(mykey, "preferredLanguages")) {
            _jsmultiobject_to_card(parser, jval,
                                   mykey, "LanguagePref",
                                   &_jspreflang_to_vcard,
                                   WANT_PROPID_FLAG,
                                   pref_param_props, &l10n,
                                   card, NULL);
        }

        /* Calendaring and Scheduling properties*/
        else if (!strcmp(mykey, "calendars")) {
            struct resource_map map[] = {
                { "calendar", VCARD_CALURI_PROPERTY, 0 },
                { "freeBusy", VCARD_FBURL_PROPERTY,  0 },
                { NULL,       VCARD_NO_PROPERTY,     0 }
            };
            struct resource_rock rrock = { map, ctx };

            _jsmultiobject_to_card(parser, jval,
                                   mykey, "Calendar",
                                   &_jsresource_to_vcard,
                                   WANT_PROPID_FLAG,
                                   resource_param_props,
                                   &l10n, card, &rrock);
        }
        else if (!strcmp(mykey, "schedulingAddresses")) {
            struct comm_rock crock = { "uri", VCARD_CALADRURI_PROPERTY };

            _jsmultiobject_to_card(parser, jval,
                                   mykey, "SchedulingAddress",
                                   &_jscomm_to_vcard,
                                   WANT_PROPID_FLAG,
                                   comm_param_props, &l10n,
                                   card, &crock);
        }

        /* Address and Location properties */
        else if (!strcmp(mykey, "addresses")) {
            struct param_prop_t addr_props[] = {
                { "label",       VCARD_X_PARAMETER     },
                { "pref",        VCARD_PREF_PARAMETER  },
                { "contexts",    VCARD_TYPE_PARAMETER  },
                { "timeZone",    VCARD_TZ_PARAMETER    },
                { "countryCode", VCARD_CC_PARAMETER    },
                { "coordinates", VCARD_GEO_PARAMETER   },
                { "full",        VCARD_LABEL_PARAMETER },
                { NULL,          0                     }
            };

            _jsmultiobject_to_card(parser, jval,
                                   mykey, "Address",
                                   &_jsaddr_to_vcard,
                                   WANT_PROPID_FLAG,
                                   addr_props, &l10n,
                                   card, NULL);
        }

        /* Resource properties */
        else if (!strcmp(mykey, "cryptoKeys")) {
            struct resource_map map[] = {
                { NULL, VCARD_KEY_PROPERTY, 1 }
            };
            struct resource_rock rrock = { map, ctx };

            _jsmultiobject_to_card(parser, jval,
                                   mykey, "CryptoKey",
                                   &_jsresource_to_vcard,
                                   WANT_PROPID_FLAG,
                                   resource_param_props,
                                   &l10n, card, &rrock);
        }
        else if (!strcmp(mykey, "directories")) {
            struct resource_map map[] = {
                { "directory", VCARD_ORGDIRECTORY_PROPERTY, 0 },
                { "entry",     VCARD_SOURCE_PROPERTY,       0 },
                { NULL,        VCARD_NO_PROPERTY,           0 }
            };
            struct resource_rock rrock = { map, ctx };

            _jsmultiobject_to_card(parser, jval,
                                   mykey, "Directory",
                                   &_jsresource_to_vcard,
                                   WANT_PROPID_FLAG,
                                   directories_param_props,
                                   &l10n, card, &rrock);
        }
        else if (!strcmp(mykey, "links")) {
            struct resource_map map[] = {
                { "contact", VCARD_CONTACTURI_PROPERTY, 0 },
                { NULL,      VCARD_URL_PROPERTY,        0 }
            };
            struct resource_rock rrock = { map, ctx };

            _jsmultiobject_to_card(parser, jval,
                                   mykey, "Link",
                                   &_jsresource_to_vcard,
                                   WANT_PROPID_FLAG,
                                   resource_param_props,
                                   &l10n, card, &rrock);
        }
        else if (!strcmp(mykey, "media")) {
            struct resource_map map[] = {
                { "photo", VCARD_PHOTO_PROPERTY, 1 },
                { "sound", VCARD_SOUND_PROPERTY, 1 },
                { "logo",  VCARD_LOGO_PROPERTY,  1 },
                { NULL,    VCARD_NO_PROPERTY,    0 }
            };
            struct resource_rock rrock = { map, ctx };

            _jsmultiobject_to_card(parser, jval,
                                   mykey, "Media",
                                   &_jsresource_to_vcard,
                                   WANT_PROPID_FLAG,
                                   resource_param_props,
                                   &l10n, card, &rrock);
        }

        /* Multilingual properties */
        else if (!strcmp(mykey, "localizations")) {
            /* Handled elsewhere */
        }

        /* Additional properties */
        else if (!strcmp(mykey, "anniversaries")) {
            _jsmultiobject_to_card(parser, jval,
                                   mykey, "Anniversary",
                                   &_jsanniv_to_vcard,
                                   WANT_PROPID_FLAG,
                                   NULL, &l10n, card, NULL);
        }
        else if (!strcmp(mykey, "keywords")) {
            _jsmultikey_to_card(parser, jval, mykey, card,
                                VCARD_CATEGORIES_PROPERTY);
        }
        else if (!strcmp(mykey, "notes")) {
            struct param_prop_t note_props[] = {
                { "created", VCARD_CREATED_PARAMETER },
                { NULL,      0                       }
            };

            _jsmultiobject_to_card(parser, jval,
                                   mykey, "Note",
                                   &_jsnote_to_vcard,
                                   WANT_PROPID_FLAG,
                                   note_props, &l10n,
                                   card, NULL);
        }
        else if (!strcmp(mykey, "personalInfo")) {
            struct param_prop_t personal_props[] = {
                { "label",  VCARD_X_PARAMETER     },
                { "level",  VCARD_LEVEL_PARAMETER },
                { "listAs", VCARD_INDEX_PARAMETER },
                { NULL,     0                     }
            };

            _jsmultiobject_to_card(parser, jval,
                                   mykey, "PersonalInfo",
                                   &_jspersonal_to_vcard,
                                   WANT_PROPID_FLAG,
                                   personal_props, &l10n,
                                   card, NULL);
        }

        /* Unmapped vCard properties */
        else if (!strcmp(mykey, "vCardProps")) {
            _vcardprops_to_card(parser, jval, card);
        }

        else {
            /* Known property with wrong case is invalid */
            unsigned i;
            for (i = card_props.map->min_hash;
                 i <= card_props.map->max_hash;
                 i++) {
                const jmap_property_t *prop = &card_props.map->array[i];

                if (!strcasecmpsafe(mykey, prop->name)) {
                    jmap_parser_invalid(parser, mykey);
                }
            }

            if (i > card_props.map->max_hash) {
                _jsunknown_to_vcard(parser, mykey, jval, NULL, card);
            }
        }

        if (l10n.lang) {
            jmap_parser_pop(parser);
            jmap_parser_pop(parser);
        }
    }

    /* Report and free and invalid localization patches */
    jmap_parser_push(parser, "localizations");
    hash_enumerate(&l10n_by_key, &_invalid_l10n_patches_by_key, parser);
    free_hash_table(&l10n_by_key, NULL);
    jmap_parser_pop(parser);

    if (json_array_size(parser->invalid) || ctx->blob_error) goto done;

    /* Set group label on grouped properties */
    hash_enumerate(&groups, &_set_groups, NULL);

    /* Add the default FN derived from the Card unless one was already set.
     * (Localized FNs carry a LANGUAGE parameter; the default one does not.) */
    bool have_default_fn = false;
    vcardproperty *fnprop;
    for (fnprop = vcardcomponent_get_first_property(card, VCARD_FN_PROPERTY);
         fnprop;
         fnprop = vcardcomponent_get_next_property(card, VCARD_FN_PROPERTY)) {
        if (!vcardproperty_get_first_parameter(fnprop, VCARD_LANGUAGE_PARAMETER)) {
            have_default_fn = true;
            break;
        }
    }

    if (!have_default_fn) {
        vcardproperty *prop = vcardproperty_new_fn(buf_cstring(&fn));

        if (fn_is_derived) {
            vcardproperty_add_parameter(prop,
                    vcardparameter_new_derived(VCARD_DERIVED_TRUE));
        }

        vcardcomponent_add_property(card, prop);
    }

  done:
    free_hash_table(&groups, (void (*)(void *)) &ptrarray_free);
    free_hash_table(&l10n_by_key, NULL);
    buf_free(&buf);
    buf_free(&fn);
}
