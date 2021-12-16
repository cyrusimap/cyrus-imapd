/* caldav_util.c -- utility functions for dealing with CALDAV database
 *
 * Copyright (c) 1994-2021 Carnegie Mellon University.  All rights reserved.
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

#include "acl.h"
#include "caldav_alarm.h"
#include "caldav_db.h"
#include "caldav_util.h"
#include "http_dav.h"
#include "mailbox.h"
#include "proxy.h"
#include "strarray.h"
#include "strhash.h"
#include "syslog.h"
#include "times.h"
#include "util.h"
#include "zoneinfo_db.h"

/* generated headers are not necessarily in current directory */
#include "imap/http_err.h"
#include "imap/imap_err.h"


static icaltimezone *utc_zone = NULL;

/* Replace TZID aliases with the actual TZIDs */
EXPORTED void replace_tzid_aliases(icalcomponent *ical,
                                   struct hash_table *tzid_table)
{
    icalproperty *prop;
    for (prop = icalcomponent_get_first_property(ical, ICAL_ANY_PROPERTY);
         prop;
         prop = icalcomponent_get_next_property(ical, ICAL_ANY_PROPERTY)) {
        icalparameter *param =
            icalproperty_get_first_parameter(prop, ICAL_TZID_PARAMETER);
        if (!param) continue;

        const char *tzid =
            hash_lookup(icalparameter_get_tzid(param), tzid_table);
        if (tzid) icalparameter_set_tzid(param, tzid);
    }

    icalcomponent *comp;
    for (comp = icalcomponent_get_first_component(ical, ICAL_ANY_COMPONENT);
         comp;
         comp = icalcomponent_get_next_component(ical, ICAL_ANY_COMPONENT)) {
        replace_tzid_aliases(comp, tzid_table);
    }
}


/* Strip all VTIMEZONE components for known TZIDs */
EXPORTED void strip_vtimezones(icalcomponent *ical)
{
    struct hash_table tzid_table;
    icalcomponent *vtz, *next;

    /* Create hash table for TZID aliases */
    construct_hash_table(&tzid_table, 10, 1);

    for (vtz = icalcomponent_get_first_component(ical, ICAL_VTIMEZONE_COMPONENT);
         vtz; vtz = next) {

        next = icalcomponent_get_next_component(ical, ICAL_VTIMEZONE_COMPONENT);

        icalproperty *prop =
            icalcomponent_get_first_property(vtz, ICAL_TZID_PROPERTY);
        const char *tzid = icalproperty_get_tzid(prop);
        struct zoneinfo zi;

        if (tzid && !zoneinfo_lookup(tzid, &zi)) {
            if (zi.type == ZI_LINK) {
                /* Add this alias to our table */
                hash_insert(tzid, xstrdup(zi.data->s), &tzid_table);
            }
            freestrlist(zi.data);

            icalcomponent_remove_component(ical, vtz);
            icalcomponent_free(vtz);
        }
    }

    if (hash_numrecords(&tzid_table)) {
        /* Replace all TZID aliases with actual TZIDs.
           Note: This NEEDS to be done, otherwise looking up the
           builtin timezone will fail on a TZID mismatch. */
        replace_tzid_aliases(ical, &tzid_table);
    }
    free_hash_table(&tzid_table, free);
}

EXPORTED void add_personal_data_from_dl(icalcomponent *ical, struct dlist *dl)
{
    const char *icalstr;
    icalcomponent *vpatch;

    /* Parse the value and fetch the patch */
    dlist_getatom(dl, "VPATCH", &icalstr);
    vpatch = icalparser_parse_string(icalstr);

    /* Apply the patch to the "base" resource */
    icalcomponent_apply_vpatch(ical, vpatch, NULL, NULL);

    icalcomponent_free(vpatch);
}

EXPORTED void add_personal_data(icalcomponent *ical, struct buf *userdata)
{
    struct dlist *dl;
    dlist_parsemap(&dl, 1, 0, buf_base(userdata), buf_len(userdata));
    add_personal_data_from_dl(ical, dl);
    dlist_free(&dl);
}

EXPORTED int caldav_read_usedefaultalerts(struct dlist *dl,
                                          struct mailbox *mailbox,
                                          const struct index_record *record,
                                          icalcomponent **icalp)
{
    /* Read from annotation */
    if (dl) {
        const char *val = NULL;
        if (dlist_getatom(dl, "USEDEFAULTALERTS", &val)) {
            return !strcasecmp(val, "YES");
        }
        if (dlist_getatom(dl, "VPATCH", &val)) {
            icalcomponent *vpatch = icalparser_parse_string(val);
            if (vpatch) {
                int ret = icalcomponent_read_usedefaultalerts(vpatch);
                icalcomponent_free(vpatch);
                if (ret >= 0) return ret;
            }
        }
    }

    /* Read from client-supplied iCalendar data */
    if (icalp && *icalp) {
        int ret = icalcomponent_read_usedefaultalerts(*icalp);
        if (ret >= 0) return ret;
    }

    /* Read from record */
    if (!mailbox || !record) return 0;

    icalcomponent *myical = record_to_ical(mailbox, record, NULL);
    int ret = 0;

    if (dl) add_personal_data_from_dl(myical, dl);
    ret = icalcomponent_read_usedefaultalerts(myical);
    if (icalp) {
        *icalp = myical;
    }
    else icalcomponent_free(myical);

    return ret >= 0 ? ret : 0;
}

static void caldav_read_defaultalarms_guid(const char *mboxname,
                                           const char *userid,
                                           const char *annot,
                                           struct message_guid *guid)
{
    struct buf buf = BUF_INITIALIZER;
    message_guid_set_null(guid);
    struct dlist *dl = NULL;

    annotatemore_lookupmask(mboxname, annot, userid, &buf);
    if (buf_len(&buf)) {
        /* Attempt to read guid from dlist */
        if (dlist_parsemap(&dl, 1, 0, buf.s, buf.len) == 0) {
            const char *guidrep = NULL;
            dlist_getatom(dl, "GUID", &guidrep);
            if (guidrep) {
                message_guid_decode(guid, guidrep);
                goto done;
            }
        }
        /* Fallback to generating guid from iCalendar data */
        message_guid_generate(guid, buf.s, buf.len);
    }

done:
    dlist_free(&dl);
    buf_free(&buf);
}

static void add_defaultalarm_guid(const char *mboxname, const char *userid,
                                  char *buf, size_t *buflen)
{
    struct message_guid withtime_guid;
    caldav_read_defaultalarms_guid(mboxname, userid,
            CALDAV_DEFAULTALARMS_ANNOT_WITHTIME, &withtime_guid);
    if (!message_guid_isnull(&withtime_guid)) {
        message_guid_export(&withtime_guid, buf + (*buflen));
        *buflen += MESSAGE_GUID_SIZE;
    }

    struct message_guid withdate_guid;
    caldav_read_defaultalarms_guid(mboxname, userid,
            CALDAV_DEFAULTALARMS_ANNOT_WITHTIME, &withdate_guid);
    if (!message_guid_isnull(&withdate_guid)) {
        message_guid_export(&withdate_guid, buf + (*buflen));
        *buflen += MESSAGE_GUID_SIZE;
    }
}

EXPORTED int caldav_get_validators(struct mailbox *mailbox, void *data,
                                   const char *userid, struct index_record *record,
                                   const char **etag, time_t *lastmod)
{

    const struct caldav_data *cdata = (const struct caldav_data *) data;
    struct buf userdata = BUF_INITIALIZER;

    int r = dav_get_validators(mailbox, data, userid, record, etag, lastmod);
    if (r) return r;

    if ((namespace_calendar.allow & ALLOW_USERDATA) &&
        cdata->dav.imap_uid && cdata->comp_flags.shared &&
        caldav_is_personalized(mailbox, cdata, userid, &userdata)) {
        struct dlist *dl;

        /* Parse the userdata and fetch the validators */
        dlist_parsemap(&dl, 1, 0, buf_base(&userdata), buf_len(&userdata));

        if (etag) {
            char buf[4*MESSAGE_GUID_SIZE];
            size_t buf_len = 2*MESSAGE_GUID_SIZE;
            struct message_guid *user_guid;

            dlist_getguid(dl, "GUID", &user_guid);

            /* Per-user ETag is GUID of concatenated GUIDs */
            message_guid_export(&record->guid, buf);
            message_guid_export(user_guid, buf+MESSAGE_GUID_SIZE);

            /* Read default alarm GUID from per-user data */
            icalcomponent *ical = NULL;
            int defaultalerts = caldav_read_usedefaultalerts(dl, mailbox, record, &ical);
            if (defaultalerts) {
                add_defaultalarm_guid(mailbox_name(mailbox), userid, buf, &buf_len);
            }
            icalcomponent_free(ical);

            /* Generate ETag */
            message_guid_generate(user_guid, buf, buf_len);
            *etag = message_guid_encode(user_guid);
        }
        if (lastmod) {
            time_t user_lastmod;

            dlist_getdate(dl, "LASTMOD", &user_lastmod);

            /* Per-user Last-Modified is latest mod time */
            *lastmod = MAX(record->internaldate, user_lastmod);
        }

        dlist_free(&dl);
        buf_free(&userdata);
    }
    else if (cdata->comp_flags.defaultalerts) {
        char buf[4*MESSAGE_GUID_SIZE];
        size_t buf_len = MESSAGE_GUID_SIZE;

        message_guid_export(&record->guid, buf);
        add_defaultalarm_guid(mailbox_name(mailbox), userid, buf, &buf_len);

        struct message_guid guid;
        message_guid_generate(&guid, buf, buf_len);
        *etag = message_guid_encode(&guid);
    }

    return 0;
}


/* Strip per-user data to personalize iCalendar resource.
 *
 * COLOR and CATEGORIES properties are not stripped.
 * Instead, they are added to the per-user VPATCH when the
 * user overwrites them in their copy of the resource.
 */
#define STRIP_OWNER_CAL_DATA              \
    "CALDATA %(VPATCH {285+}\r\n"         \
    "BEGIN:VPATCH\r\n"                    \
    "VERSION:1\r\n"                       \
    "DTSTAMP:19760401T005545Z\r\n"        \
    "UID:strip-owner-cal-data\r\n"        \
    "BEGIN:PATCH\r\n"                     \
    "PATCH-TARGET:/VCALENDAR/ANY\r\n"     \
    "PATCH-DELETE:/VALARM\r\n"            \
    "PATCH-DELETE:#TRANSP\r\n"            \
    "PATCH-DELETE:#X-MOZ-LASTACK\r\n"     \
    "PATCH-DELETE:#X-MOZ-SNOOZE-TIME\r\n" \
    "PATCH-DELETE:#X-APPLE-DEFAULT-ALARM\r\n" \
    "END:PATCH\r\n"                       \
    "END:VPATCH\r\n)"


EXPORTED int caldav_is_personalized(struct mailbox *mailbox,
                                    const struct caldav_data *cdata,
                                    const char *userid,
                                    struct buf *userdata)
{
    if (caldav_is_secretarymode(mailbox_name(mailbox))) return 0;

    if (cdata->comp_flags.shared) {
        /* Lookup per-user calendar data */
        int r = mailbox_get_annotate_state(mailbox, cdata->dav.imap_uid, NULL);

        if (!r) {
            mbname_t *mbname = NULL;

            if (mailbox->i.options & OPT_IMAP_SHAREDSEEN) {
                /* No longer using per-user-data - use owner data */
                mbname = mbname_from_intname(mailbox_name(mailbox));
                userid = mbname_userid(mbname);
            }

            r = mailbox_annotation_lookup(mailbox, cdata->dav.imap_uid,
                                          PER_USER_CAL_DATA, userid, userdata);
            mbname_free(&mbname);
        }

        if (!r && buf_len(userdata)) return 1;
        buf_free(userdata);
    }
    else if (!(mailbox->i.options & OPT_IMAP_SHAREDSEEN) &&
             !mboxname_userownsmailbox(userid, mailbox_name(mailbox))) {
        buf_init_ro_cstr(userdata, STRIP_OWNER_CAL_DATA);
        return 1;
    }

    return 0;
}

EXPORTED icalcomponent *caldav_record_to_ical(struct mailbox *mailbox,
                                              const struct caldav_data *cdata,
                                              const char *userid,
                                              strarray_t *schedule_addresses)
{
    icalcomponent *ical = NULL;
    struct index_record record;

    /* Fetch index record for the cal resource */
    if (mailbox_find_index_record(mailbox, cdata->dav.imap_uid, &record)) {
        return NULL;
    }

    ical = record_to_ical(mailbox, &record, schedule_addresses);

    if (userid && (namespace_calendar.allow & ALLOW_USERDATA)) {
        struct buf userdata = BUF_INITIALIZER;

        if (caldav_is_personalized(mailbox, cdata, userid, &userdata)) {
            add_personal_data(ical, &userdata);
        }

        buf_free(&userdata);
    }

    return ical;
}

static int compare_properties(icalproperty *propa, icalproperty *propb)
{
    int cmp = 0;

    if (strcmp(icalproperty_as_ical_string(propa),
                icalproperty_as_ical_string(propb))) {
        icalproperty *mypropa = icalproperty_clone(propa);
        icalproperty *mypropb = icalproperty_clone(propb);

        icalproperty_remove_parameter_by_name(mypropa, "X-JMAP-ID");
        icalproperty_remove_parameter_by_name(mypropb, "X-JMAP-ID");
        cmp = strcmp(icalproperty_as_ical_string(mypropa),
                     icalproperty_as_ical_string(mypropb));

        icalproperty_free(mypropa);
        icalproperty_free(mypropb);
    }

    return cmp;
}



/*
 * Compare two components and extract per-user data (alarms, transparency).
 *
 * NOTE: This function assumes that both components has been normalized
 */
static int extract_personal_data(icalcomponent *ical, icalcomponent *oldical,
                                 icalcomponent *vpatch, struct buf *path,
                                 int read_only, unsigned *num_changes)
{
    icalcomponent *comp, *nextcomp, *oldcomp = NULL, *patch = NULL;
    icalproperty *prop, *nextprop, *oldprop = NULL;
    int r;

    /* Add this component to path */
    size_t path_len = buf_len(path);
    buf_printf(path, "/%s",
               icalcomponent_kind_to_string(icalcomponent_isa(ical)));

    prop = icalcomponent_get_first_property(ical, ICAL_UID_PROPERTY);
    if (prop) {
        buf_printf(path, "[UID=%s]", icalproperty_get_uid(prop));
        prop = icalcomponent_get_first_property(ical,
                                                ICAL_RECURRENCEID_PROPERTY);
        buf_printf(path, "[RID=%s]",
                   prop ? icalproperty_get_value_as_string(prop) : "M");
    }

    if (oldical) {
        oldprop = icalcomponent_get_first_property(oldical, ICAL_ANY_PROPERTY);
        oldcomp = icalcomponent_get_first_component(oldical, ICAL_ANY_COMPONENT);
    }

    for (prop = icalcomponent_get_first_property(ical, ICAL_ANY_PROPERTY);
         prop; prop = nextprop) {
        const char *xname = NULL, *oldxname;
        icalproperty_kind kind = icalproperty_isa(prop);
        icalproperty_kind oldkind =
            oldprop ? icalproperty_isa(oldprop) : ICAL_NO_PROPERTY;

        nextprop = icalcomponent_get_next_property(ical, ICAL_ANY_PROPERTY);

        if (oldkind == ICAL_NO_PROPERTY) {
            /* No more components in old component */
            r = -1;
        }
        else if (kind == oldkind) {
            if (kind == ICAL_X_PROPERTY) {
                /* Compare property names alphabetically */
                xname = icalproperty_get_x_name(prop);
                oldxname = icalproperty_get_x_name(oldprop);
                r = strcmp(xname, oldxname);
            }
            else r = 0;
        }
        else {
            /* Compare property names alphabetically */
            r = strcmp(icalproperty_kind_to_string(kind),
                       icalproperty_kind_to_string(oldkind));
        }

        if (r == 0) {
            switch (kind) {
            case ICAL_CALSCALE_PROPERTY:
            case ICAL_PRODID_PROPERTY:
            case ICAL_DTSTAMP_PROPERTY:
            case ICAL_LASTMODIFIED_PROPERTY:
                /* Ok to modify these - ignore */
                break;

            case ICAL_X_PROPERTY:
                if (!strcmpsafe(xname, "X-MOZ-GENERATION")) {
                    /* Ok to modify these - ignore */
                    break;
                }

                GCC_FALLTHROUGH

            default:
                {
                    if (compare_properties(prop, oldprop)) {
                        /* Property has been updated in ical */
                        if (read_only) {
                            return HTTP_FORBIDDEN;
                        }
                        if (num_changes) (*num_changes)++;
                    }
                    break;
                }
            }
        }
        else if (r < 0) {
            /* Property has been added to ical */
            switch (kind) {
            case ICAL_CALSCALE_PROPERTY:
            case ICAL_PRODID_PROPERTY:
            case ICAL_DTSTAMP_PROPERTY:
            case ICAL_LASTMODIFIED_PROPERTY:
                /* Ok to add these - ignore */
                break;

            case ICAL_X_PROPERTY:
                xname = icalproperty_get_x_name(prop);
                if (strcmp(xname, "X-APPLE-DEFAULT-ALARM") &&
                    (strncmp(xname, "X-MOZ-", 6) ||
                     (strcmp(xname+6, "LASTACK") &&
                      strcmp(xname+6, "SNOOZE-TIME")))) {
                    if (read_only) return HTTP_FORBIDDEN;
                    if (num_changes) (*num_changes)++;
                    break;
                }

                GCC_FALLTHROUGH

            case ICAL_TRANSP_PROPERTY:
            case ICAL_COLOR_PROPERTY:
            case ICAL_CATEGORIES_PROPERTY:
                /* Add per-user property to VPATCH */
                if (!patch) {
                    patch = icalcomponent_vanew(ICAL_XPATCH_COMPONENT,
                                                icalproperty_new_patchtarget(
                                                    buf_cstring(path)),
                                                0);
                    icalcomponent_add_component(vpatch, patch);
                }

                icalcomponent_remove_property(ical, prop);
                icalcomponent_add_property(patch, prop);
                break;

            default:
                if (read_only) return HTTP_FORBIDDEN;
                if (num_changes) (*num_changes)++;
                break;
            }

            continue;  /* Do NOT increment to next old property */
        }
        else {
            /* Property has been removed from ical */
            switch (oldkind) {
            case ICAL_CALSCALE_PROPERTY:
            case ICAL_PRODID_PROPERTY:
            case ICAL_DTSTAMP_PROPERTY:
            case ICAL_LASTMODIFIED_PROPERTY:
                /* Ok to remove these - ignore */
                break;

            default:
                if (read_only) return HTTP_FORBIDDEN;
                if (num_changes) (*num_changes)++;
                break;
            }
        }

        oldprop = icalcomponent_get_next_property(oldical, ICAL_ANY_PROPERTY);
    }

    for (comp = icalcomponent_get_first_component(ical, ICAL_ANY_COMPONENT);
         comp; comp = nextcomp) {
        icalcomponent_kind kind = icalcomponent_isa(comp);
        icalcomponent_kind oldkind =
            oldcomp ? icalcomponent_isa(oldcomp) : ICAL_NO_COMPONENT;

        nextcomp = icalcomponent_get_next_component(ical, ICAL_ANY_COMPONENT);

        if (oldkind == ICAL_NO_COMPONENT) {
            /* No more components in old component */
            r = -1;
        }
        else if (kind == oldkind) {
            if (kind == ICAL_X_COMPONENT) {
                /* Compare component names alphabetically */

                /* XXX  Need a new libical function */
                r = 0;
            }
            else r = 0;
        }
        else {
            /* Compare component names alphabetically */
            r = strcmp(icalcomponent_kind_to_string(kind),
                       icalcomponent_kind_to_string(oldkind));
        }

        if (r == 0) {
            r = extract_personal_data(comp, oldcomp, vpatch,
                                      path, read_only, num_changes);
            if (r) return r;
        }
        else if (r < 0) {
            /* Component has been added to ical */
            switch (kind) {
            case ICAL_VALARM_COMPONENT:
                /* Add per-user component to VPATCH */
                if (!patch) {
                    patch = icalcomponent_vanew(ICAL_XPATCH_COMPONENT,
                                                icalproperty_new_patchtarget(
                                                    buf_cstring(path)),
                                                0);
                    icalcomponent_add_component(vpatch, patch);
                }

                icalcomponent_remove_component(ical, comp);
                icalcomponent_add_component(patch, comp);
                break;

            default:
                if (read_only) return HTTP_FORBIDDEN;
                if (num_changes) (*num_changes)++;

                r = extract_personal_data(comp, oldcomp, vpatch,
                                          path, read_only, num_changes);
                if (r) return r;
                break;
            }

            continue;  /* Do NOT increment to next old component */
        }
        else if (read_only) {
            return HTTP_FORBIDDEN;
        }
        else {
            /* Component has been removed from ical */
            if (num_changes) (*num_changes)++;
        }

        oldcomp = icalcomponent_get_next_component(oldical, ICAL_ANY_COMPONENT);
    }

    /* Trim this component from path */
    buf_truncate(path, path_len);

    return 0;
}


static int write_personal_data(const char *userid,
                               struct mailbox *mailbox,
                               uint32_t uid,
                               modseq_t modseq,
                               int usedefaultalerts,
                               icalcomponent *vpatch)
{
    struct message_guid guid;
    struct buf value = BUF_INITIALIZER;
    const char *icalstr = icalcomponent_as_ical_string(vpatch);
    struct dlist *dl = dlist_newkvlist(NULL, "CALDATA");
    int ret;

    ret = mailbox_get_annotate_state(mailbox, uid, NULL);
    if (ret) return ret;

    dlist_setdate(dl, "LASTMOD", time(0));
    dlist_setnum64(dl, "MODSEQ", modseq);
    message_guid_generate(&guid, icalstr, strlen(icalstr));
    dlist_setguid(dl, "GUID", &guid);
    dlist_setatom(dl, "VPATCH", icalstr);
    dlist_setatom(dl, "USEDEFAULTALERTS", usedefaultalerts ? "YES" : "NO");
    dlist_printbuf(dl, 1, &value);
    dlist_free(&dl);

    ret = mailbox_annotation_write(mailbox, uid,
                                   PER_USER_CAL_DATA, userid, &value);
    buf_free(&value);

    return ret;
}


/*
 * Handle stripping per-user data from existing and/or new shared resource.
 *
 * Logic is as follows:
 * 
 *   Owner   R/W   Exists Shared   EO  SO  EU  SU  PD
 *   ------------------------------------------------
 *            0      0                             Y
 *     0      0      1      0      Y   Y   Y
 *     0      0      1      1              Y
 *     0      1      0                     Y   Y
 *     0      1      1      0      Y       Y   ?
 *     0      1      1      1              Y   ?
 *     1      0      1                     Y
 *     1      1      0                         Y
 *     1      1      1      0                  Y
 *     1      1      1      1              Y   ?
 *
 *   EO = Extract Owner Data
 *   SO = Store Owner Resource
 *   EU = Extract User Data
 *   SU = Store User Resource
 *   PD = Permission Denied
 */
static int personalize_resource(struct transaction_t *txn,
                                struct mailbox *mailbox,
                                icalcomponent *ical,
                                struct caldav_data *cdata,
                                const char *userid,
                                icalcomponent **store_me,
                                icalcomponent **userdata,
                                const strarray_t *schedule_addresses)

{
    int is_owner, rights, read_only, ret = 0;
    mbname_t *mbname;
    const char *owner;
    icalcomponent *oldical = NULL;
    unsigned num_changes = 0;
    struct auth_state *authstate = auth_newstate(userid);
    char *resource = xstrdupnull(cdata->dav.resource);

    *store_me = ical;

    if (!utc_zone) utc_zone = icaltimezone_get_utc_timezone();

    /* Check ownership and ACL for current user */
    mbname = mbname_from_intname(mailbox_name(mailbox));
    owner = mbname_userid(mbname);
    is_owner = !strcmpsafe(owner, userid);

    rights = cyrus_acl_myrights(authstate, mailbox_acl(mailbox));
    auth_freestate(authstate);

    if (rights & DACL_WRITECONT) {
        /* User has read-write access */
        read_only = 0;
    }
    else if (cdata->dav.imap_uid && (rights & DACL_WRITEOWNRSRC) &&
            (!cdata->organizer ||
             (schedule_addresses &&
              strarray_find(schedule_addresses, cdata->organizer, 0) >= 0))) {
        /* User may update resource whey they are organizer */
        read_only = 0;
    }
    else if (rights & DACL_UPDATEPRIVATE) {
        /* User may only update their per-user properties */
        read_only = 1;
    }
    else if (cdata->dav.imap_uid &&
             !(mailbox->i.options & OPT_IMAP_SHAREDSEEN)) {
        /* User has read-only access to existing resource */
        read_only = 1;
    }
    else {
        /* DAV:need-privileges */
        txn->error.precond = DAV_NEED_PRIVS;
        txn->error.resource = txn->req_tgt.path;
        txn->error.rights = DACL_WRITECONT;
        ret = HTTP_NO_PRIVS;
        goto done;
    }

    if (cdata->dav.imap_uid &&
        (!is_owner || read_only || cdata->comp_flags.shared)) {
        syslog(LOG_NOTICE, "LOADING ICAL %u", cdata->dav.imap_uid);

        /* Load message containing the existing resource and parse iCal data */
        oldical = caldav_record_to_ical(mailbox, cdata, NULL, NULL);
        if (!oldical) {
            txn->error.desc = "Failed to read record";
            ret = HTTP_SERVER_ERROR;
            goto done;
        }
    }

    if (cdata->dav.imap_uid && !is_owner && !cdata->comp_flags.shared) {
        /* Split owner's personal data from resource */

        /* Create UID for owner VPATCH */
        assert(!buf_len(&txn->buf));
        buf_printf(&txn->buf, "%x-%x-%x", strhash(mailbox_name(mailbox)),
                   strhash(resource), strhash(owner));

        *userdata =
            icalcomponent_vanew(ICAL_VPATCH_COMPONENT,
                                icalproperty_new_version("1"),
                                icalproperty_new_dtstamp(
                                    icaltime_from_timet_with_zone(time(0),
                                                                  0,
                                                                  utc_zone)),
                                icalproperty_new_uid(buf_cstring(&txn->buf)),
                                0);
        buf_reset(&txn->buf);

        /* Extract personal info from owner's resource and create vpatch */
        int usedefaultalerts = icalcomponent_read_usedefaultalerts(oldical) > 0;
        ret = extract_personal_data(oldical, NULL, *userdata,
                                    &txn->buf /* path */, 0 /* read_only */,
                                    &num_changes);
        buf_reset(&txn->buf);

        if (!ret) ret = write_personal_data(owner, mailbox, cdata->dav.imap_uid,
                                            cdata->dav.modseq, usedefaultalerts,
                                            *userdata);

        if (ret) goto done;

        if (read_only) {
            /* Resource to store is the existing resource just stripped */
            *store_me = oldical;
        }

        icalcomponent_free(*userdata);
        *userdata = NULL;
    }

    if (!is_owner || read_only ||
        (cdata->dav.imap_uid && cdata->comp_flags.shared)) {
        /* Extract personal info from user's resource and create vpatch */
        if (oldical) {
            /* Normalize existing resource for comparison */
            icalcomponent_normalize(oldical);

            /* Normalize new resource for comparison */
            icalcomponent_normalize(ical);
        }

        /* Create UID for sharee VPATCH */
        assert(!buf_len(&txn->buf));
        buf_printf(&txn->buf, "%x-%x-%x", strhash(mailbox_name(mailbox)),
                   strhash(resource), strhash(userid));

        *userdata =
            icalcomponent_vanew(ICAL_VPATCH_COMPONENT,
                                icalproperty_new_version("1"),
                                icalproperty_new_dtstamp(
                                    icaltime_from_timet_with_zone(time(0),
                                                                  0,
                                                                  utc_zone)),
                                icalproperty_new_uid(buf_cstring(&txn->buf)),
                                0);
        buf_reset(&txn->buf);

        /* Extract personal info from new resource and add to vpatch */
        /* XXX  DO NOT reinitialize num_changes.  We need the changes
           from rewriting owner resource to force storage of that resource */
        ret = extract_personal_data(ical, oldical, *userdata,
                                    &txn->buf /* path */, read_only,
                                    &num_changes);
        buf_reset(&txn->buf);

        if (ret) goto done;

        if (cdata->dav.imap_uid) {
            if (!num_changes) {
                /* No resource to store (per-user data change only) */
                ret = HTTP_NO_CONTENT;
                *store_me = NULL;
                goto done;
            }
        }

        cdata->comp_flags.shared = 1;
    }

  done:
    if (oldical && (*store_me != oldical)) icalcomponent_free(oldical);
    mbname_free(&mbname);
    free(resource);

    return ret;
}

HIDDEN int caldav_is_secretarymode(const char *mboxname)
{
    mbname_t *mbname = mbname_from_intname(mboxname);
    int is_secretarymode = 0;

    const strarray_t *boxes = mbname_boxes(mbname);
    const char *prefix = config_getstring(IMAPOPT_CALENDARPREFIX);
    if (strarray_size(boxes) && !strcmpsafe(prefix, strarray_nth(boxes, 0))) {
        mbname_truncate_boxes(mbname, 1);
        static const char *annot =
            DAV_ANNOT_NS "<" XML_NS_JMAPCAL ">sharees-act-as";
        struct buf val = BUF_INITIALIZER;
        annotatemore_lookup(mbname_intname(mbname), annot, "", &val);
        is_secretarymode = !strcmp(buf_cstring(&val), "secretary");
        buf_free(&val);
    }

    mbname_free(&mbname);
    return is_secretarymode;
}

static void strip_schedule_params(icalcomponent *ical)
{
    icalcomponent *comp = icalcomponent_get_first_real_component(ical);
    if (!comp) return;

    /* Only remove SCHEDULE-FORCE-SEND */

    icalcomponent_kind kind = icalcomponent_isa(comp);
    for (comp = icalcomponent_get_first_component(ical, kind);
            comp;
            comp = icalcomponent_get_next_component(ical, kind)) {

        /* Grab the organizer */
        icalproperty *prop = icalcomponent_get_first_property(comp, ICAL_ORGANIZER_PROPERTY);

        /* Remove CalDAV Scheduling parameters from organizer */
        icalproperty_remove_parameter_by_name(prop, "SCHEDULE-FORCE-SEND");

        /* Remove CalDAV Scheduling parameters from attendees */
        for (prop = icalcomponent_get_first_invitee(comp);
                prop;
                prop = icalcomponent_get_next_invitee(comp)) {
            icalproperty_remove_parameter_by_name(prop, "SCHEDULE-FORCE-SEND");
        }
    }
}

/* Store the iCal data in the specified calendar/resource */
EXPORTED int caldav_store_resource(struct transaction_t *txn, icalcomponent *ical,
                                   struct mailbox *mailbox, const char *resource,
                                   modseq_t createdmodseq,
                                   struct caldav_db *caldavdb,
                                   unsigned flags, const char *userid,
                                   const strarray_t *add_imapflags,
                                   const strarray_t *del_imapflags,
                                   const strarray_t *schedule_addresses)
{
    int ret;
    icalcomponent *comp, *userdata = NULL, *store_ical = ical;
    icalcomponent_kind kind;
    icalproperty_method meth;
    icalproperty *prop;
    unsigned mykind = 0, tzbyref = 0;
    const char *organizer = NULL;
    const char *prop_annot =
        DAV_ANNOT_NS "<" XML_NS_CALDAV ">supported-calendar-component-set";
    struct buf attrib = BUF_INITIALIZER;
    struct caldav_data *cdata;
    const char *uid;
    struct index_record *oldrecord = NULL, record;
    char datestr[80], *mimehdr;
    const char *sched_tag;
    uint32_t newuid = 0;
    strarray_t myimapflags = STRARRAY_INITIALIZER;
    int usedefaultalerts = 0; // for per-user data
    int is_secretarymode = caldav_is_secretarymode(mailbox_name(mailbox));

    /* Copy add_imapflags, we might need to add some flags */
    if (add_imapflags) strarray_cat(&myimapflags, add_imapflags);

    if (!utc_zone) utc_zone = icaltimezone_get_utc_timezone();

    /* Check for supported component type */
    comp = icalcomponent_get_first_real_component(ical);
    uid = icalcomponent_get_uid(comp);
    kind = icalcomponent_isa(comp);
    switch (kind) {
    case ICAL_VEVENT_COMPONENT: mykind = CAL_COMP_VEVENT; break;
    case ICAL_VTODO_COMPONENT: mykind = CAL_COMP_VTODO; break;
    case ICAL_VJOURNAL_COMPONENT: mykind = CAL_COMP_VJOURNAL; break;
    case ICAL_VFREEBUSY_COMPONENT: mykind = CAL_COMP_VFREEBUSY; break;
    case ICAL_VAVAILABILITY_COMPONENT: mykind = CAL_COMP_VAVAILABILITY; break;
    case ICAL_VPOLL_COMPONENT: mykind = CAL_COMP_VPOLL; break;
    default:
        txn->error.precond = CALDAV_SUPP_COMP;
        return HTTP_FORBIDDEN;
    }

    if (!annotatemore_lookupmask_mbox(mailbox, prop_annot, txn->userid, &attrib)
        && attrib.len) {
        unsigned long supp_comp = strtoul(buf_cstring(&attrib), NULL, 10);

        buf_free(&attrib);

        if (!(mykind & supp_comp)) {
            txn->error.precond = CALDAV_SUPP_COMP;
            return HTTP_FORBIDDEN;
        }
    }

    /* Find message UID for the resource, if exists */
    /* XXX  We can't assume that txn->req_tgt.mbentry is our target,
       XXX  because we may have been called as part of a COPY/MOVE */
    const mbentry_t mbentry = { .name = (char *)mailbox_name(mailbox),
                                .uniqueid = (char *)mailbox_uniqueid(mailbox) };
    caldav_lookup_resource(caldavdb, &mbentry, resource, &cdata, 0);

    /* does it already exist? */
    if (cdata->dav.imap_uid) {
        newuid = cdata->dav.imap_uid;
        /* Check for change of iCalendar UID */
        if (strcmp(cdata->ical_uid, uid)) {
            /* CALDAV:no-uid-conflict */
            txn->error.precond = CALDAV_UID_CONFLICT;
            return HTTP_FORBIDDEN;
        }
        /* Fetch index record for the resource */
        int r = mailbox_find_index_record(mailbox, cdata->dav.imap_uid, &record);
        if (!r) {
            oldrecord = &record;
        }
        else {
            xsyslog(LOG_ERR,
                    "Couldn't find index record corresponding to CalDAV DB record",
                    "mailbox=<%s> record=<%u> error=<%s>",
                    mailbox_name(mailbox), cdata->dav.imap_uid, error_message(r));
        }
    }

    /* Remove all X-LIC-ERROR properties */
    icalcomponent_strip_errors(ical);

    /* Remove all VTIMEZONE components for known TZIDs */
    if (namespace_calendar.allow & ALLOW_CAL_NOTZ) {
        strip_vtimezones(ical);
        tzbyref = 1;
    }

    /* Remove schedule parameters */
    strip_schedule_params(ical);

    /* Set Schedule-Tag, if any */
    if (flags & NEW_STAG) {
        if (oldrecord) sched_tag = message_guid_encode(&oldrecord->guid);
        else sched_tag = NULL_ETAG;
    }
    else if (organizer) sched_tag = cdata->sched_tag;
    else sched_tag = cdata->sched_tag = NULL;

    /* If we are just stripping VTIMEZONEs from resource, flag it */
    if (flags & TZ_STRIP) strarray_append(&myimapflags, DFLAG_UNCHANGED);
    else if (mailbox->i.options & OPT_IMAP_SHAREDSEEN) {
        cdata->comp_flags.shared = 0;
    }
    else if (userid && (namespace_calendar.allow & ALLOW_USERDATA) && !is_secretarymode) {
        usedefaultalerts = icalcomponent_read_usedefaultalerts(ical) > 0;
        ret = personalize_resource(txn, mailbox, ical,
                cdata, userid, &store_ical, &userdata, schedule_addresses);

        if (ret) goto done;

        if (store_ical != ical) {
            comp = icalcomponent_get_first_real_component(store_ical);
            uid = icalcomponent_get_uid(comp);
            kind = icalcomponent_isa(comp);
        }
    }

    /* Create and cache RFC 5322 header fields for resource */
    prop = icalcomponent_get_first_property(comp, ICAL_ORGANIZER_PROPERTY);
    if (prop) {
        organizer = icalproperty_get_organizer(prop);
        if (organizer) {
            if (!strncasecmp(organizer, "mailto:", 7)) organizer += 7;
            assert(!buf_len(&txn->buf));
            buf_printf(&txn->buf, "<%s>", organizer);
            mimehdr = charset_encode_mimeheader(buf_cstring(&txn->buf),
                                                buf_len(&txn->buf), 0);
            spool_replace_header(xstrdup("From"), mimehdr, txn->req_hdrs);
            buf_reset(&txn->buf);
        }
    }

    prop = icalcomponent_get_first_property(comp, ICAL_SUMMARY_PROPERTY);
    if (prop) {
        mimehdr = charset_encode_mimeheader(icalproperty_get_summary(prop), 0, 0);
        spool_replace_header(xstrdup("Subject"), mimehdr, txn->req_hdrs);
    }
    else spool_replace_header(xstrdup("Subject"),
                            xstrdup(icalcomponent_kind_to_string(kind)),
                            txn->req_hdrs);

    if (strarray_size(schedule_addresses)) {
        char *value = strarray_join(schedule_addresses, ",");
        mimehdr = charset_encode_mimeheader(value, 0, 0);
        spool_replace_header(xstrdup("X-Schedule-User-Address"),
                             mimehdr, txn->req_hdrs);
        free(value);
    }

    time_to_rfc5322(icaltime_as_timet_with_zone(icalcomponent_get_dtstamp(comp),
                                               utc_zone),
                   datestr, sizeof(datestr));
    spool_replace_header(xstrdup("Date"), xstrdup(datestr), txn->req_hdrs);

    /* Use SHA1(uid)@servername as Message-ID */
    struct message_guid uuid;
    message_guid_generate(&uuid, uid, strlen(uid));
    buf_printf(&txn->buf, "<%s@%s>",
               message_guid_encode(&uuid), config_servername);
    spool_replace_header(xstrdup("Message-ID"),
                         buf_release(&txn->buf), txn->req_hdrs);

    buf_setcstr(&txn->buf, ICALENDAR_CONTENT_TYPE);
    if ((meth = icalcomponent_get_method(store_ical)) != ICAL_METHOD_NONE) {
        buf_printf(&txn->buf, "; method=%s",
                   icalproperty_method_to_string(meth));
    }
    buf_printf(&txn->buf, "; component=%s", icalcomponent_kind_to_string(kind));
    spool_replace_header(xstrdup("Content-Type"),
                         buf_release(&txn->buf), txn->req_hdrs);

    buf_printf(&txn->buf, "attachment;\r\n\tfilename=\"%s\"", resource);
    if (sched_tag) buf_printf(&txn->buf, ";\r\n\tschedule-tag=%s", sched_tag);
    if (tzbyref) buf_printf(&txn->buf, ";\r\n\ttz-by-ref=true");
    if (cdata->comp_flags.shared) {
        buf_printf(&txn->buf, ";\r\n\tper-user-data=true");
    }
    spool_replace_header(xstrdup("Content-Disposition"),
                         buf_release(&txn->buf), txn->req_hdrs);

    spool_remove_header(xstrdup("Content-Description"), txn->req_hdrs);

    /* Store the resource */
    ret = dav_store_resource(txn, icalcomponent_as_ical_string(store_ical), 0,
                             mailbox, oldrecord, createdmodseq, &myimapflags,
                             del_imapflags);
    strarray_fini(&myimapflags);

    newuid = mailbox->i.last_uid;

  done:
    switch (ret) {
    case HTTP_CREATED:
    case HTTP_NO_CONTENT:
        if ((namespace_calendar.allow & ALLOW_USERDATA) &&
            cdata->comp_flags.shared) {

            /* either the UID created by dav_store_resource,
             * or if nothing but per-user data was changed,
             * the UID of the existing record */
            assert(newuid);

            /* Ensure we have an astate connected to the mailbox,
             * so that the annotation txn will be committed
             * when we close the mailbox */
            annotate_state_t *astate = NULL;

            if (oldrecord && (newuid != oldrecord->uid) &&
                !mailbox_get_annotate_state(mailbox, newuid, &astate)) {
                /* Copy across all per-message annotations.

                   XXX  Hack until we fix annotation copying in
                   append_fromstage() to preserve userid of private annots. */
                annotate_msg_copy(mailbox, oldrecord->uid,
                                  mailbox, newuid, NULL);
            }

            if (!is_secretarymode) {
                int r = write_personal_data(userid, mailbox, newuid,
                        mailbox->i.highestmodseq+1,
                        usedefaultalerts, userdata);
                if (r) {
                    /* XXX  We have already written the stripped resource
                       so we're pretty screwed.  All message annotations
                       need to be handled (properly) in append_fromstage()
                       so storing resource and annotations is atomic.
                       */
                    txn->error.desc = error_message(r);
                    ret = HTTP_SERVER_ERROR;
                    goto done;
                }
            }

            if (store_ical) {
                /* Write shared modseq for resource */
                buf_printf(&txn->buf, MODSEQ_FMT, mailbox->i.highestmodseq);
                mailbox_get_annotate_state(mailbox, newuid, NULL);
                mailbox_annotation_write(mailbox, newuid, SHARED_MODSEQ,
                                         /* shared */ "", &txn->buf);
                buf_reset(&txn->buf);
            }

            if (!cdata->organizer || (flags & PREFER_REP)) {
                /* Read index record for new message (always the last one) */
                struct index_record newrecord;

                cdata->dav.alive = 1;
                cdata->dav.imap_uid = newuid;

                caldav_get_validators(mailbox, cdata, userid, &newrecord,
                                      &txn->resp_body.etag,
                                      &txn->resp_body.lastmod);

                if (flags & PREFER_REP) {
                    /* Re-insert per-user data */
                    icalcomponent_apply_vpatch(ical, userdata, NULL, NULL);
                }
            }
        }

        if (cdata->organizer) {
            if (flags & NEW_STAG) txn->resp_body.stag = sched_tag;

            if (!(flags & PREFER_REP)) {
                /* iCal data has been rewritten - don't return validators */
                txn->resp_body.lastmod = 0;
                txn->resp_body.etag = NULL;
            }
        }
        break;
    }

    if (userdata) icalcomponent_free(userdata);
    if (store_ical && (store_ical != ical)) icalcomponent_free(store_ical);

    return ret;
}

static int _create_mailbox(const char *userid, const char *mailboxname,
                           int type, unsigned long comp_types,
                           int useracl, int anyoneacl, const char *displayname,
                           const struct namespace *namespace,
                           const struct auth_state *authstate,
                           struct mboxlock **namespacelockp)
{
    char rights[100];
    struct mailbox *mailbox = NULL;

    int r = mboxlist_lookup(mailboxname, NULL, NULL);
    if (r != IMAP_MAILBOX_NONEXISTENT) return r;

    if (!*namespacelockp) {
        *namespacelockp = mboxname_usernamespacelock(mailboxname);
        // maybe we lost the race on this one
        r = mboxlist_lookup(mailboxname, NULL, NULL);
        if (r != IMAP_MAILBOX_NONEXISTENT) return r;
    }

    /* Create locally */
    mbentry_t mbentry = MBENTRY_INITIALIZER;
    mbentry.name = (char *) mailboxname;
    mbentry.mbtype = type;
    r = mboxlist_createmailbox(&mbentry, 0/*options*/, 0/*highestmodseq*/,
                               0/*isadmin*/, userid, authstate,
                               0/*flags*/, displayname ? &mailbox : NULL);
    if (!r && displayname) {
        annotate_state_t *astate = NULL;

        r = mailbox_get_annotate_state(mailbox, 0, &astate);
        if (!r) {
            const char *disp_annot = DAV_ANNOT_NS "<" XML_NS_DAV ">displayname";
            const char *comp_annot =
                DAV_ANNOT_NS "<" XML_NS_CALDAV ">supported-calendar-component-set";
            struct buf value = BUF_INITIALIZER;

            buf_init_ro_cstr(&value, displayname);
            r = annotate_state_writemask(astate, disp_annot, userid, &value);
            if (!r && comp_types) {
                buf_reset(&value);
                buf_printf(&value, "%lu", comp_types);
                r = annotate_state_writemask(astate, comp_annot, userid, &value);
            }
            buf_free(&value);
        }

        mailbox_close(&mailbox);
    }
    if (!r && useracl) {
        cyrus_acl_masktostr(useracl, rights);
        r = mboxlist_setacl(namespace, mailboxname, userid, rights,
                            1, userid, authstate);
    }
    if (!r && anyoneacl) {
        cyrus_acl_masktostr(anyoneacl, rights);
        r = mboxlist_setacl(namespace, mailboxname, "anyone", rights,
                            1, userid, authstate);
    }

    if (r) syslog(LOG_ERR, "IOERROR: failed to create %s (%s)",
                  mailboxname, error_message(r));
    return r;
}

EXPORTED unsigned long config_types_to_caldav_types(void)
{
    unsigned long config_types =
        config_getbitfield(IMAPOPT_CALENDAR_COMPONENT_SET);
    unsigned long types = 0;

    if (config_types & IMAP_ENUM_CALENDAR_COMPONENT_SET_VEVENT)
        types |= CAL_COMP_VEVENT;
    if (config_types & IMAP_ENUM_CALENDAR_COMPONENT_SET_VTODO)
        types |= CAL_COMP_VTODO;
    if (config_types & IMAP_ENUM_CALENDAR_COMPONENT_SET_VJOURNAL)
        types |= CAL_COMP_VJOURNAL;
    if (config_types & IMAP_ENUM_CALENDAR_COMPONENT_SET_VFREEBUSY)
        types |= CAL_COMP_VFREEBUSY;
    if (config_types & IMAP_ENUM_CALENDAR_COMPONENT_SET_VAVAILABILITY)
        types |= CAL_COMP_VAVAILABILITY;
#ifdef VPOLL
    if (config_types & IMAP_ENUM_CALENDAR_COMPONENT_SET_VPOLL)
        types |= CAL_COMP_VPOLL;
#endif

    return types;
}

EXPORTED int caldav_create_defaultcalendars(const char *userid,
                                            const struct namespace *namespace,
                                            const struct auth_state *authstate,
                                            mbentry_t **mbentryp)
{
    int r;
    char *mailboxname;
    struct mboxlock *namespacelock = NULL;

    /* calendar-home-set */
    mailboxname = caldav_mboxname(userid, NULL);
    r = mboxlist_lookup(mailboxname, NULL, NULL);
    if (r == IMAP_MAILBOX_NONEXISTENT) {
        /* Find location of INBOX */
        char *inboxname = mboxname_user_mbox(userid, NULL);
        mbentry_t *mbentry = NULL;

        r = proxy_mlookup(inboxname, &mbentry, NULL, NULL);
        free(inboxname);

        if (!r) {
            if (mbentry->server) {
                r = IMAP_MAILBOX_NONEXISTENT;

                if (mbentryp) {
                    *mbentryp = mbentry;
                    mbentry = NULL;
                }
            }
            else {
                r = _create_mailbox(userid, mailboxname, MBTYPE_CALENDAR, 0,
                                    ACL_ALL | DACL_READFB, DACL_READFB, NULL,
                                    namespace, authstate, &namespacelock);
            }
        }
        else if (r == IMAP_MAILBOX_NONEXISTENT) {
            r = IMAP_INVALID_USER;
        }

        mboxlist_entry_free(&mbentry);
    }

    free(mailboxname);
    if (r) goto done;

    if (config_getswitch(IMAPOPT_CALDAV_CREATE_DEFAULT)) {
        /* Default calendar */
        unsigned long comp_types = config_types_to_caldav_types();

        mailboxname = caldav_mboxname(userid, SCHED_DEFAULT);
        r = _create_mailbox(userid, mailboxname, MBTYPE_CALENDAR, comp_types,
                            ACL_ALL | DACL_READFB, DACL_READFB,
                            config_getstring(IMAPOPT_CALENDAR_DEFAULT_DISPLAYNAME),
                            namespace, authstate, &namespacelock);
        free(mailboxname);
        if (r) goto done;
    }

    if (config_getswitch(IMAPOPT_CALDAV_CREATE_SCHED) &&
        namespace_calendar.allow & ALLOW_CAL_SCHED) {
        /* Scheduling Inbox */
        mailboxname = caldav_mboxname(userid, SCHED_INBOX);
        r = _create_mailbox(userid, mailboxname, MBTYPE_CALENDAR, 0,
                            ACL_ALL | DACL_SCHED, DACL_SCHED, NULL,
                            namespace, authstate, &namespacelock);
        free(mailboxname);
        if (r) goto done;

        /* Scheduling Outbox */
        mailboxname = caldav_mboxname(userid, SCHED_OUTBOX);
        r = _create_mailbox(userid, mailboxname, MBTYPE_CALENDAR, 0,
                            ACL_ALL | DACL_SCHED, 0, NULL,
                            namespace, authstate, &namespacelock);
        free(mailboxname);
        if (r) goto done;
    }

    if (config_getswitch(IMAPOPT_CALDAV_CREATE_ATTACH) &&
        namespace_calendar.allow & ALLOW_CAL_ATTACH) {
        /* Managed Attachment Collection */
        mailboxname = caldav_mboxname(userid, MANAGED_ATTACH);
        r = _create_mailbox(userid, mailboxname, MBTYPE_COLLECTION, 0,
                            ACL_ALL, ACL_READ, NULL,
                            namespace, authstate, &namespacelock);
        free(mailboxname);
        if (r) goto done;
    }

  done:
    if (namespacelock) mboxname_release(&namespacelock);
    return r;
}

static int caldav_read_defaultalarms(const char *mboxname,
                                     const char *userid,
                                     const char *annot,
                                     struct buf *buf)
{
    struct buf mybuf = BUF_INITIALIZER;
    annotatemore_lookupmask(mboxname, annot, userid, &mybuf);
    if (buf_len(&mybuf)) {
        struct dlist *dl = NULL;
        if (dlist_parsemap(&dl, 1, 0, buf_base(&mybuf), buf_len(&mybuf)) == 0) {
            const char *content = NULL;
            if (dlist_getatom(dl, "CONTENT", &content)) {
                buf_setcstr(buf, content);
            }
        }
        if (!buf_len(buf)) {
            buf_copy(buf, &mybuf);
        }
        dlist_free(&dl);
    }
    buf_free(&mybuf);
    return 0;
}

EXPORTED icalcomponent *caldav_read_calendar_icalalarms(const char *mboxname,
                                                        const char *userid,
                                                        const char *annot)
{
    icalcomponent *ical = NULL;
    struct buf buf = BUF_INITIALIZER;
    caldav_read_defaultalarms(mboxname, userid, annot, &buf);
    if (buf_len(&buf)) {
        ical = icalparser_parse_string(buf_cstring(&buf));
        if (ical) {
            if (icalcomponent_isa(ical) == ICAL_VALARM_COMPONENT) {
                /* libical wraps multiple VALARMs in a XROOT component,
                 * so also wrap a single VALARM for consistency */
                icalcomponent *root = icalcomponent_new(ICAL_XROOT_COMPONENT);
                icalcomponent_add_component(root, ical);
                ical = root;
            }
        }
    }
    buf_free(&buf);
    return ical;
}

EXPORTED void caldav_format_defaultalarms_annot(struct buf *dst, const char *icalstr)
{
    struct dlist *dl = dlist_newkvlist(NULL, "DEFAULTALARMS");
    struct message_guid guid;
    message_guid_generate(&guid, icalstr, strlen(icalstr));
    dlist_setatom(dl, "CONTENT", icalstr);
    dlist_setatom(dl, "GUID", message_guid_encode(&guid));
    dlist_printbuf(dl, 1, dst);
    dlist_free(&dl);
}


EXPORTED int caldav_write_defaultalarms(struct mailbox *mailbox,
                                        const char *userid,
                                        const char *annot,
                                        icalcomponent *ical)
{
    annotate_state_t *astate;
    int r = mailbox_get_annotate_state(mailbox, 0, &astate);
    if (r) return r;

    struct buf val = BUF_INITIALIZER;
    if (ical) {
        struct buf raw = BUF_INITIALIZER;

        if (icalcomponent_isa(ical) != ICAL_VALARM_COMPONENT) {
            icalcomponent *comp;
            for (comp = icalcomponent_get_first_component(ical, ICAL_VALARM_COMPONENT);
                 comp;
                 comp = icalcomponent_get_next_component(ical, ICAL_VALARM_COMPONENT)) {
                buf_appendcstr(&raw, icalcomponent_as_ical_string(comp));
            }
        }
        else buf_setcstr(&raw, icalcomponent_as_ical_string(ical));

        caldav_format_defaultalarms_annot(&val, buf_cstring(&raw));
        buf_free(&raw);
    }

    r = annotate_state_writemask(astate, annot, userid, &val);
    buf_free(&val);

    return r;
}


struct bumpdefaultalarms_data {
    bitvector_t bump;
    bitvector_t shared;
};

static int bumpdefaultalarms_cb(void *rock, struct caldav_data *cdata)
{
    struct bumpdefaultalarms_data *data = rock;

    if (cdata->comp_flags.defaultalerts) {
        /* Definitely bump this record */
        bv_set(&data->bump, cdata->dav.imap_uid);
    }
    if (cdata->comp_flags.shared) {
        /* Inspect per-user data later */
        bv_set(&data->shared, cdata->dav.imap_uid);
    }

    return 0;
}

EXPORTED int caldav_bump_defaultalarms(struct mailbox *mailbox)
{
    struct mailbox_iter *iter = NULL;
    mbentry_t *mbentry = NULL;
    struct caldav_db *db = NULL;
    int r = 0;

    struct bumpdefaultalarms_data data = { BV_INITIALIZER, BV_INITIALIZER };

    /* Gather record uids of events with default alerts */
    db = caldav_open_mailbox(mailbox);
    if (!db) {
        syslog(LOG_ERR, "%s: can't open caldav.db for %s",
                __func__, mailbox_name(mailbox));
        r = HTTP_SERVER_ERROR;
        goto done;
    }

    r = mboxlist_lookup_by_uniqueid(mailbox_uniqueid(mailbox), &mbentry, NULL);
    if (r) {
        syslog(LOG_ERR, "%s: failed to lookup mbentry %s: %s",
                __func__, mailbox_uniqueid(mailbox), error_message(r));
        r = HTTP_SERVER_ERROR;
        goto done;
    }
    r = caldav_foreach(db, mbentry, bumpdefaultalarms_cb, &data);
    if (r) {
        syslog(LOG_ERR, "%s: failed to iterate caldav.db %s: %s",
                __func__, mailbox_name(mailbox), error_message(r));
        r = HTTP_SERVER_ERROR;
        goto done;
    }
    if ((bv_first_set(&data.bump) < 0) && (bv_first_set(&data.shared) < 0)) {
        goto done;
    }

    /* Bump modseqs of calendar event records */
    iter = mailbox_iter_init(mailbox, 0, ITER_SKIP_EXPUNGED);
    if (!iter) {
        syslog(LOG_ERR, "%s: can't open mailbox iterator for %s",
                __func__, mailbox_name(mailbox));
        r = HTTP_SERVER_ERROR;
        goto done;
    }

    /* Need to switch to message scope */
    if (mailbox->annot_state) {
        int annot_scope = annotate_state_scope(mailbox->annot_state);
        if (annot_scope != ANNOTATION_SCOPE_MESSAGE) {
            annotate_state_commit(&mailbox->annot_state);
        }
    }

    /* Iterate records */
    const message_t *msg;
    struct buf userdata = BUF_INITIALIZER;
    struct dlist *dl = NULL; // parsed user data

    while ((msg = mailbox_iter_step(iter))) {
        const struct index_record *record = msg_record(msg);
        struct index_record copyrecord = *record;
        buf_reset(&userdata);
        dlist_free(&dl);

        if (!bv_isset(&data.bump, record->uid) && bv_isset(&data.shared, record->uid)) {
            /* Check per-user data */
            mailbox_annotation_lookup(mailbox, record->uid, PER_USER_CAL_DATA,
                                      httpd_userid, &userdata);
            if (buf_len(&userdata)) {
                /* Parse the userdata and fetch the validators */
                dlist_parsemap(&dl, 1, 0, buf_base(&userdata), buf_len(&userdata));
                if (caldav_read_usedefaultalerts(dl, mailbox, record, NULL)) {
                    bv_set(&data.bump, record->uid);
                }
            }
        }

        if (!bv_isset(&data.bump, record->uid)) {
            continue;
        }

        /* Bump record */
        r = mailbox_rewrite_index_record(mailbox, &copyrecord);
        if (r) {
            syslog(LOG_ERR, "%s: rewrite index record %s:%d: %s",
                    __func__, mailbox_name(mailbox), record->uid, error_message(r));
            continue;
        }
        if (dl) {
            /* Update modseq in the per-user data */
            dlist_updatedate(dl, "LASTMOD", copyrecord.last_updated);
            dlist_updatenum64(dl, "MODSEQ", copyrecord.modseq);
            buf_reset(&userdata);
            dlist_printbuf(dl, 1, &userdata);
            r = annotate_state_write(mailbox->annot_state, PER_USER_CAL_DATA,
                                     httpd_userid, &userdata);
            if (r) {
                syslog(LOG_ERR, "%s: can't update per-user modseq for record %s:%d: %s",
                        __func__, mailbox_name(mailbox), record->uid, error_message(r));
                continue;
            }
        }
        r = caldav_alarm_touch_record(mailbox, record, /*force*/1);
        if (r) {
            syslog(LOG_ERR, "%s: touch alarms for index record %s:%d: %s",
                    __func__, mailbox_name(mailbox), record->uid, error_message(r));
            continue;
        }
    }
    buf_free(&userdata);
    dlist_free(&dl);

done:
    bv_fini(&data.shared);
    bv_fini(&data.bump);
    mailbox_iter_done(&iter);
    mboxlist_entry_free(&mbentry);
    caldav_close(db);
    return r;
}

HIDDEN void caldav_attachment_url(struct buf *buf,
                                  const char *userid,
                                  const char *proto,
                                  const char *host,
                                  const char *managedid)
{
    buf_printf(buf, "%s://%s%s/%s/%s/%s%s",
            proto, host, namespace_calendar.prefix,
            USER_COLLECTION_PREFIX,
            userid, MANAGED_ATTACH, managedid);
}

