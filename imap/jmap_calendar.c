/* jmap_calendar.c -- Routines for handling JMAP calendar messages
 *
 * Copyright (c) 1994-2014 Carnegie Mellon University.  All rights reserved.
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

#include <ctype.h>
#include <errno.h>
#include <assert.h>
#include <string.h>
#include <syslog.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "acl.h"
#include "annotate.h"
#include "append.h"
#include "caldav_db.h"
#include "caldav_util.h"
#include "cyr_qsort_r.h"
#include "dynarray.h"
#include "global.h"
#include "hash.h"
#include "httpd.h"
#include "http_caldav_sched.h"
#include "http_dav.h"
#include "http_dav_sharing.h"
#include "http_jmap.h"
#include "http_proxy.h"
#include "ical_support.h"
#include "mboxname.h"
#include "json_support.h"
#include "jmap_ical.h"
#include "search_query.h"
#include "seen.h"
#include "stristr.h"
#include "sync_log.h"
#include "times.h"
#include "user.h"
#include "util.h"
#include "webdav_db.h"
#include "xapian_wrap.h"
#include "xmalloc.h"
#include "xsha1.h"
#include "zoneinfo_db.h"

/* generated headers are not necessarily in current directory */
#include "imap/http_err.h"
#include "imap/imap_err.h"

static int jmap_calendar_get(struct jmap_req *req);
static int jmap_calendar_changes(struct jmap_req *req);
static int jmap_calendar_set(struct jmap_req *req);
static int jmap_calendarevent_get(struct jmap_req *req);
static int jmap_calendarevent_changes(struct jmap_req *req);
static int jmap_calendarevent_query(struct jmap_req *req);
static int jmap_calendarevent_set(struct jmap_req *req);
static int jmap_calendarevent_copy(struct jmap_req *req);
static int jmap_calendarevent_parse(jmap_req_t *req);
static int jmap_principal_get(struct jmap_req *req);
static int jmap_principal_query(struct jmap_req *req);
static int jmap_principal_changes(struct jmap_req *req);
static int jmap_principal_querychanges(struct jmap_req *req);
static int jmap_principal_set(struct jmap_req *req);
static int jmap_principal_getavailability(struct jmap_req *req);
static int jmap_calendareventnotification_get(struct jmap_req *req);
static int jmap_calendareventnotification_set(struct jmap_req *req);
static int jmap_calendareventnotification_changes(struct jmap_req *req);
static int jmap_calendareventnotification_query(struct jmap_req *req);
static int jmap_calendareventnotification_querychanges(struct jmap_req *req);
static int jmap_participantidentity_get(struct jmap_req *req);
static int jmap_participantidentity_set(struct jmap_req *req);
static int jmap_participantidentity_changes(struct jmap_req *req);
static int jmap_sharenotification_get(struct jmap_req *req);
static int jmap_sharenotification_set(struct jmap_req *req);
static int jmap_sharenotification_changes(struct jmap_req *req);
static int jmap_sharenotification_query(struct jmap_req *req);
static int jmap_sharenotification_querychanges(struct jmap_req *req);

static int jmap_calendarevent_getblob(jmap_req_t *req, jmap_getblob_context_t *ctx);

#define JMAPCACHE_CALVERSION 22

static jmap_method_t jmap_calendar_methods_standard[] = {
    {
        "Calendar/get",
        JMAP_URN_CALENDARS,
        &jmap_calendar_get,
        JMAP_NEED_CSTATE
    },
    {
        "Calendar/changes",
        JMAP_URN_CALENDARS,
        &jmap_calendar_changes,
        JMAP_NEED_CSTATE
    },
    {
        "Calendar/set",
        JMAP_URN_CALENDARS,
        &jmap_calendar_set,
        JMAP_NEED_CSTATE | JMAP_READ_WRITE
    },
    {
        "CalendarEvent/get",
        JMAP_URN_CALENDARS,
        &jmap_calendarevent_get,
        JMAP_NEED_CSTATE
    },
    {
        "CalendarEvent/changes",
        JMAP_URN_CALENDARS,
        &jmap_calendarevent_changes,
        JMAP_NEED_CSTATE
    },
    {
        "CalendarEvent/query",
        JMAP_URN_CALENDARS,
        &jmap_calendarevent_query,
        JMAP_NEED_CSTATE
    },
    {
        "CalendarEvent/set",
        JMAP_URN_CALENDARS,
        &jmap_calendarevent_set,
        JMAP_NEED_CSTATE | JMAP_READ_WRITE
    },
    {
        "CalendarEvent/copy",
        JMAP_URN_CALENDARS,
        &jmap_calendarevent_copy,
        JMAP_NEED_CSTATE | JMAP_READ_WRITE
    },
    {
        "CalendarEvent/parse",
        JMAP_CALENDARS_EXTENSION,
        &jmap_calendarevent_parse,
        JMAP_NEED_CSTATE
    },
    {
        "CalendarEventNotification/get",
        JMAP_URN_CALENDARS,
        &jmap_calendareventnotification_get,
        JMAP_NEED_CSTATE
    },
    {
        "CalendarEventNotification/set",
        JMAP_URN_CALENDARS,
        &jmap_calendareventnotification_set,
        JMAP_NEED_CSTATE | JMAP_READ_WRITE
    },
    {
        "CalendarEventNotification/changes",
        JMAP_URN_CALENDARS,
        &jmap_calendareventnotification_changes,
        JMAP_NEED_CSTATE
    },
    {
        "CalendarEventNotification/query",
        JMAP_URN_CALENDARS,
        &jmap_calendareventnotification_query,
        JMAP_NEED_CSTATE
    },
    {
        "CalendarEventNotification/queryChanges",
        JMAP_URN_CALENDARS,
        &jmap_calendareventnotification_querychanges,
        JMAP_NEED_CSTATE
    },
    {
        "ParticipantIdentity/get",
        JMAP_URN_CALENDARS,
        &jmap_participantidentity_get,
        JMAP_NEED_CSTATE
    },
    {
        "ParticipantIdentity/changes",
        JMAP_URN_CALENDARS,
        &jmap_participantidentity_changes,
        JMAP_NEED_CSTATE
    },
    {
        "ParticipantIdentity/set",
        JMAP_URN_CALENDARS,
        &jmap_participantidentity_set,
        JMAP_NEED_CSTATE | JMAP_READ_WRITE
    },
    {
        "Principal/get",
        JMAP_URN_PRINCIPALS,
        &jmap_principal_get,
        JMAP_NEED_CSTATE
    },
    {
        "Principal/query",
        JMAP_URN_PRINCIPALS,
        &jmap_principal_query,
        JMAP_NEED_CSTATE
    },
    {
        "Principal/changes",
        JMAP_URN_PRINCIPALS,
        &jmap_principal_changes,
        JMAP_NEED_CSTATE
    },
    {
        "Principal/queryChanges",
        JMAP_URN_PRINCIPALS,
        &jmap_principal_querychanges,
        JMAP_NEED_CSTATE
    },
    {
        "Principal/set",
        JMAP_URN_PRINCIPALS,
        &jmap_principal_set,
        JMAP_NEED_CSTATE | JMAP_READ_WRITE
    },
    {
        "Principal/getAvailability",
        JMAP_URN_PRINCIPALS,
        &jmap_principal_getavailability,
        JMAP_NEED_CSTATE
    },
    {
        "ShareNotification/get",
        JMAP_URN_PRINCIPALS,
        &jmap_sharenotification_get,
        JMAP_NEED_CSTATE
    },
    {
        "ShareNotification/set",
        JMAP_URN_PRINCIPALS,
        &jmap_sharenotification_set,
        JMAP_NEED_CSTATE | JMAP_READ_WRITE
    },
    {
        "ShareNotification/changes",
        JMAP_URN_PRINCIPALS,
        &jmap_sharenotification_changes,
        JMAP_NEED_CSTATE
    },
    {
        "ShareNotification/query",
        JMAP_URN_PRINCIPALS,
        &jmap_sharenotification_query,
        JMAP_NEED_CSTATE
    },
    {
        "ShareNotification/queryChanges",
        JMAP_URN_PRINCIPALS,
        &jmap_sharenotification_querychanges,
        JMAP_NEED_CSTATE
    },
    { NULL, NULL, NULL, 0}
};

jmap_method_t jmap_calendar_methods_nonstandard[] = {
    { NULL, NULL, NULL, 0}
};

HIDDEN void jmap_calendar_init(jmap_settings_t *settings)
{
    jmap_method_t *mp;

    for (mp = jmap_calendar_methods_standard; mp->name; mp++) {
        hash_insert(mp->name, mp, &settings->methods);
    }

    json_object_set_new(settings->server_capabilities,
            JMAP_URN_CALENDARS, json_object());

    json_object_set_new(settings->server_capabilities,
            JMAP_URN_PRINCIPALS, json_object());

    if (config_getswitch(IMAPOPT_JMAP_NONSTANDARD_EXTENSIONS)) {
        json_object_set_new(settings->server_capabilities,
                JMAP_CALENDARS_EXTENSION, json_object());

        for (mp = jmap_calendar_methods_nonstandard; mp->name; mp++) {
            hash_insert(mp->name, mp, &settings->methods);
        }
    }

    ptrarray_append(&settings->getblob_handlers, jmap_calendarevent_getblob);
}

HIDDEN void jmap_calendar_capabilities(json_t *account_capabilities,
                                       struct auth_state *authstate,
                                       const char *authuserid,
                                       const char *accountid)
{
    char *calhomename = caldav_mboxname(accountid, NULL);
    mbentry_t *mbentry = NULL;
    int r = mboxlist_lookup(calhomename, &mbentry, NULL);
    if (r) {
        xsyslog(LOG_ERR, "can't lookup calendar home",
                "calhomename=%s error=%s",
                calhomename, error_message(r));
        return;
    }
    int rights = httpd_myrights(authstate, mbentry);
    struct buf buf = BUF_INITIALIZER;

    json_t *calcapa = json_object();
    int is_main_account = !strcmpsafe(authuserid, accountid);

    /* minDateTime, maxDateTime */
    char timebuf[RFC3339_DATETIME_MAX+1];
    time_to_rfc3339(caldav_epoch + 1, timebuf, RFC3339_DATETIME_MAX);
    timebuf[RFC3339_DATETIME_MAX] = '\0';
    json_object_set_new(calcapa, "minDateTime", json_string(timebuf));
    time_to_rfc3339(caldav_eternity - 1, timebuf, RFC3339_DATETIME_MAX);
    timebuf[RFC3339_DATETIME_MAX] = '\0';
    json_object_set_new(calcapa, "maxDateTime", json_string(timebuf));

    /* maxExpandedQueryDuration - we don't really care */
    json_object_set_new(calcapa, "maxExpandedQueryDuration", json_string("P365D"));

    /* maxParticipantsPerEvent */
    json_object_set_new(calcapa, "maxParticipantsPerEvent", json_null());

    /* mayCreateCalendar */
    if (is_main_account) {
        json_object_set_new(calcapa, "mayCreateCalendar", json_true());
    }
    else {
        json_object_set_new(calcapa, "mayCreateCalendar",
                json_boolean(rights & JACL_CREATECHILD));
    }

    /* shareesActAs */
    static const char *annot =
        DAV_ANNOT_NS "<" XML_NS_JMAPCAL ">sharees-act-as";
    annotatemore_lookup_mbe(mbentry, annot, "", &buf);
    if (!buf_len(&buf)) buf_setcstr(&buf, "self");
    json_object_set_new(calcapa, "shareesActAs", json_string(buf_cstring(&buf)));
    buf_reset(&buf);

    /* maxCalendarsPerEvent */
    json_object_set_new(calcapa, "maxCalendarsPerEvent", json_integer(1));

    json_object_set_new(account_capabilities, JMAP_URN_CALENDARS, calcapa);

    if (config_getswitch(IMAPOPT_JMAP_NONSTANDARD_EXTENSIONS)) {
        json_object_set_new(account_capabilities, JMAP_CALENDARS_EXTENSION, json_object());
    }

    /* urn:ietf:params:jmap:principals */
    json_t *principalcap = json_object();
    json_object_set_new(principalcap, "currentUserPrincipalId",
            is_main_account ? json_string(accountid) : json_null());

    json_t *calprincipalcap = json_object();
    json_object_set_new(calprincipalcap, "accountId", json_string(accountid));
    json_object_set_new(calprincipalcap, "account", json_null());
    json_object_set_new(calprincipalcap, "mayGetAvailability",
            is_main_account ? json_true() : json_boolean(rights & JACL_READFB));

    strarray_t schedule_addresses = STRARRAY_INITIALIZER;
    get_schedule_addresses(NULL, calhomename, accountid, &schedule_addresses);
    if (strarray_size(&schedule_addresses)) {
        const char *addr = strarray_nth(&schedule_addresses, 0);
        if (strncasecmp(addr, "mailto:", 7)) {
            buf_setcstr(&buf, "mailto:");
        }
        buf_appendcstr(&buf, addr);
        json_object_set_new(calprincipalcap, "sendTo",
                json_pack("{s:s}", "imip", buf_cstring(&buf)));
        buf_reset(&buf);
    }
    else json_object_set_new(calprincipalcap, "sendTo", json_null());
    strarray_fini(&schedule_addresses);

    json_object_set_new(principalcap, JMAP_URN_CALENDARS, calprincipalcap);

    json_object_set_new(account_capabilities, JMAP_URN_PRINCIPALS, principalcap);

    /* urn:ietf:params:jmap:principals:owner */
    json_t *ownercap = json_object();
    json_object_set_new(ownercap, "accountIdForPrincipal",
            json_string(accountid));
    json_object_set_new(ownercap, "principalId",
            json_string(accountid));
    json_object_set_new(account_capabilities,
           "urn:ietf:params:jmap:principals:owner", ownercap);

    free(calhomename);
    mboxlist_entry_free(&mbentry);
    buf_free(&buf);
}

/* Helper flags for CalendarEvent/set */
#define JMAP_CREATE     (1<<0) /* Current request is a create. */
#define JMAP_UPDATE     (1<<1) /* Current request is an update. */
#define JMAP_DESTROY    (1<<2) /* Current request is a destroy. */

/* Return a non-zero value if uid maps to a special-purpose calendar mailbox,
 * that may not be read or modified by the user. */
static int jmap_calendar_isspecial(mbname_t *mbname) {
    if (!mboxname_iscalendarmailbox(mbname_intname(mbname), 0)) return 1;

    const strarray_t *boxes = mbname_boxes(mbname);
    const char *lastname = strarray_nth(boxes, boxes->count - 1);

    /* Don't return user.foo.#calendars */
    if (!strcmp(lastname, config_getstring(IMAPOPT_CALENDARPREFIX))) {
        return 1;
    }

    /* SCHED_INBOX  and SCHED_OUTBOX end in "/", so trim them */
    if (!strncmp(lastname, SCHED_INBOX, strlen(SCHED_INBOX)-1)) return 1;
    if (!strncmp(lastname, SCHED_OUTBOX, strlen(SCHED_OUTBOX)-1)) return 1;
    if (!strncmp(lastname, MANAGED_ATTACH, strlen(MANAGED_ATTACH)-1)) return 1;
    return 0;
}

struct getcalendars_rock {
    struct jmap_req *req;
    struct jmap_get *get;
    int skip_hidden;
};

static json_t *getcalendar_defaultalerts(const char *userid,
                                         const char *mboxname,
                                         const char *annot)
{
    icalcomponent *ical = caldav_read_calendar_icalalarms(mboxname, userid, annot);
    if (!ical) return json_array();

    json_t *alerts = json_array();
    icalcomponent *valarm;
    for (valarm = icalcomponent_get_first_component(ical, ICAL_VALARM_COMPONENT);
         valarm;
         valarm = icalcomponent_get_next_component(ical, ICAL_VALARM_COMPONENT)) {
        json_t *alert = jmapical_alert_from_ical(valarm);
        if (alert) json_array_append_new(alerts, alert);
    }

    icalcomponent_free(ical);
    return alerts;
}

static json_t *calendarrights_to_jmap(int rights, int is_owner)
{
    static int writerights = DACL_WRITECONT|DACL_WRITEPROPS;
    static int mayupdateprivate = DACL_PROPRSRC|ACL_SETSEEN;
    static int mayupdateall = DACL_WRITECONT|DACL_WRITEPROPS|DACL_CHANGEORG;
    static int mayremoveall = DACL_RMRSRC|DACL_CHANGEORG;
    if (is_owner) rights |= JACL_RSVP;

    return json_pack("{s:b s:b s:b s:b s:b s:b s:b s:b s:b s:b s:b}",
            "mayReadFreeBusy",
            (rights & JACL_READFB) == JACL_READFB,
            "mayReadItems",
            (rights & JACL_READITEMS) == JACL_READITEMS,
            "mayAddItems",
            (rights & JACL_ADDITEMS) == JACL_ADDITEMS,
            "mayRSVP",
            (rights & JACL_RSVP) == JACL_RSVP,
            "mayDelete",
            (rights & JACL_DELETE) == JACL_DELETE,
            "mayAdmin",
            (rights & JACL_ADMIN) == JACL_ADMIN,
            "mayUpdatePrivate",
            (rights & mayupdateprivate) == mayupdateprivate,
            "mayUpdateOwn",
            (rights & writerights) == writerights,
            "mayUpdateAll",
            (rights & mayupdateall) == mayupdateall,
            "mayRemoveOwn",
            (rights & DACL_RMRSRC) == DACL_RMRSRC,
            "mayRemoveAll",
            (rights & mayremoveall) == mayremoveall);
}

static json_t *calendarrights_to_sharewith(int rights)
{
    return calendarrights_to_jmap(rights, 0);
}

static int calendar_sharewith_to_rights(int rights, json_t *jsharewith)
{
    static int writerights = DACL_WRITECONT|DACL_WRITEPROPS;
    static int mayupdateprivate = DACL_PROPRSRC|ACL_SETSEEN;
    static int mayupdateall = DACL_WRITECONT|DACL_WRITEPROPS|DACL_CHANGEORG;
    static int mayremoveall = DACL_RMRSRC|DACL_CHANGEORG;
    int newrights = rights;

    json_t *jval;
    const char *name;
    json_object_foreach(jsharewith, name, jval) {
        int mask;
        if (!strcmp("mayReadFreeBusy", name))
            mask = JACL_READFB;
        else if (!strcmp("mayReadItems", name))
            mask = JACL_READITEMS;
        else if (!strcmp("mayAddItems", name))
            mask = JACL_ADDITEMS;
        else if (!strcmp("mayRSVP", name))
            mask = JACL_RSVP;
        else if (!strcmp("mayDelete", name))
            mask = JACL_DELETE;
        else if (!strcmp("mayAdmin", name))
            mask = JACL_ADMIN;
        else if (!strcmp("mayUpdatePrivate", name))
            mask = mayupdateprivate;
        else if (!strcmp("mayUpdateOwn", name))
            mask = writerights;
        else if (!strcmp("mayUpdateAll", name))
            mask = mayupdateall;
        else if (!strcmp("mayRemoveOwn", name))
            mask = DACL_RMRSRC;
        else if (!strcmp("mayRemoveAll", name))
            mask = mayremoveall;
        else
            continue;

        if (json_boolean_value(jval))
            newrights |= mask;
        else
            newrights &= ~mask;
    }

    return newrights;
}

static int getcalendars_cb(const mbentry_t *mbentry, void *vrock)
{
    struct getcalendars_rock *rock = vrock;
    jmap_req_t *req = rock->req;
    mbname_t *mbname = NULL;
    int r = 0;

    /* Only calendars... */
    if (mbtype_isa(mbentry->mbtype) != MBTYPE_CALENDAR) return 0;

    /* ...which are at least readable or visible... */
    if (!jmap_hasrights_mbentry(rock->req, mbentry, JACL_READITEMS))
        return rock->skip_hidden ? 0 : IMAP_PERMISSION_DENIED;

    // needed for some fields
    int rights = jmap_myrights_mbentry(rock->req, mbentry);

    /* ...and contain VEVENTs. */
    struct buf attrib = BUF_INITIALIZER;
    static const char *calcompset_annot =
        DAV_ANNOT_NS "<" XML_NS_CALDAV ">supported-calendar-component-set";
    unsigned long supported_components = -1; /* ALL component types by default. */
    r = annotatemore_lookupmask_mbe(mbentry, calcompset_annot,
                                    rock->req->accountid, &attrib);
    if (attrib.len) {
        supported_components = strtoul(buf_cstring(&attrib), NULL, 10);
        buf_free(&attrib);
    }
    if (!(supported_components & CAL_COMP_VEVENT)) {
        goto done;
    }

    /* OK, we want this one... */
    mbname = mbname_from_intname(mbentry->name);
    /* ...unless it's one of the special names. */
    if (jmap_calendar_isspecial(mbname)) {
        r = 0;
        goto done;
    }

    json_t *obj = json_object();

    const strarray_t *boxes = mbname_boxes(mbname);
    const char *id = strarray_nth(boxes, boxes->count-1);
    json_object_set_new(obj, "id", json_string(id));

    if (jmap_wantprop(rock->get->props, "x-href")) {
        // XXX - should the x-ref for a shared calendar point
        // to the authenticated user's calendar home?
        char *xhref = jmap_xhref(mbentry->name, NULL);
        json_object_set_new(obj, "x-href", json_string(xhref));
        free(xhref);
    }

    if (jmap_wantprop(rock->get->props, "role")) {
        const char *role = NULL;
        char *defaultname = caldav_scheddefault(rock->req->accountid);
        if (!strcmpsafe(id, defaultname)) role = "inbox";
        free(defaultname);
        json_object_set_new(obj, "role",
                            role ? json_string(role) : json_null());
    }

    if (jmap_wantprop(rock->get->props, "name")) {
        buf_reset(&attrib);
        static const char *displayname_annot =
            DAV_ANNOT_NS "<" XML_NS_DAV ">displayname";
        r = annotatemore_lookupmask_mbe(mbentry, displayname_annot,
                                        req->userid, &attrib);
        /* fall back to last part of mailbox name */
        if (r || !attrib.len) buf_setcstr(&attrib, id);
        json_object_set_new(obj, "name", json_string(buf_cstring(&attrib)));
        buf_free(&attrib);
    }

    if (jmap_wantprop(rock->get->props, "description")) {
        buf_reset(&attrib);
        static const char *description_annot =
            DAV_ANNOT_NS "<" XML_NS_DAV ">description";
        r = annotatemore_lookupmask_mbe(mbentry, description_annot,
                                    req->userid, &attrib);
        json_object_set_new(obj, "description", buf_len(&attrib) ?
                            json_string(buf_cstring(&attrib)) : json_null());
        buf_free(&attrib);
    }

    if (jmap_wantprop(rock->get->props, "color")) {
        struct buf attrib = BUF_INITIALIZER;
        static const char *color_annot =
            DAV_ANNOT_NS "<" XML_NS_APPLE ">calendar-color";
        r = annotatemore_lookupmask_mbe(mbentry, color_annot,
                                        req->userid, &attrib);
        if (!r && attrib.len)
            json_object_set_new(obj, "color", json_string(buf_cstring(&attrib)));
        buf_free(&attrib);
    }

    if (jmap_wantprop(rock->get->props, "sortOrder")) {
        long sort_order = 0;
        buf_reset(&attrib);
        static const char *order_annot =
            DAV_ANNOT_NS "<" XML_NS_APPLE ">calendar-order";
        r = annotatemore_lookupmask_mbe(mbentry, order_annot,
                                        req->userid, &attrib);
        if (!r && attrib.len) {
            char *ptr;
            long val = strtol(buf_cstring(&attrib), &ptr, 10);
            if (ptr && *ptr == '\0') {
                sort_order = val;
            }
            else {
                /* Ignore, but report non-numeric calendar-order values */
                syslog(LOG_WARNING, "sortOrder: strtol(%s) failed",
                       buf_cstring(&attrib));
            }
        }
        json_object_set_new(obj, "sortOrder", json_integer(sort_order));
        buf_free(&attrib);
    }

    if (jmap_wantprop(rock->get->props, "isVisible")) {
        int is_visible = 1;
        buf_reset(&attrib);
        static const char *visible_annot =
            DAV_ANNOT_NS "<" XML_NS_CALDAV ">X-FM-isVisible";
        r = annotatemore_lookupmask_mbe(mbentry, visible_annot,
                                        req->userid, &attrib);
        if (!r && attrib.len) {
            const char *val = buf_cstring(&attrib);
            if (!strncmp(val, "true", 4) || !strncmp(val, "1", 1)) {
                is_visible = 1;
            } else if (!strncmp(val, "false", 5) || !strncmp(val, "0", 1)) {
                is_visible = 0;
            } else {
                /* Report invalid value and fall back to default. */
                syslog(LOG_WARNING,
                       "isVisible: invalid annotation value: %s", val);
                is_visible = 1;
            }
        }
        json_object_set_new(obj, "isVisible", json_boolean(is_visible));
        buf_free(&attrib);
    }

    if (jmap_wantprop(rock->get->props, "isSubscribed")) {
        int is_subscribed;
        if (mboxname_userownsmailbox(req->userid, mbentry->name)) {
            /* Users always subscribe their own calendars */
            is_subscribed = 1;
        }
        else {
            /* Lookup mailbox subscriptions */
            is_subscribed = mboxlist_checksub(mbentry->name, req->userid) == 0;
        }
        json_object_set_new(obj, "isSubscribed", json_boolean(is_subscribed));
    }

    if (jmap_wantprop(rock->get->props, "includeInAvailability")) {
        buf_reset(&attrib);
        static const char *transp_annot =
            DAV_ANNOT_NS "<" XML_NS_CALDAV ">schedule-calendar-transp";
        r = annotatemore_lookupmask_mbe(mbentry, transp_annot,
                                    req->userid, &attrib);
        if (!strcmpsafe(buf_cstring(&attrib), "transparent")) {
            json_object_set_new(obj, "includeInAvailability",
                                json_string("none"));
        }
        else if (!strcmpsafe(buf_cstring(&attrib), "opaque-attending")) {
            json_object_set_new(obj, "includeInAvailability",
                                json_string("attending"));
        }
        else {
            json_object_set_new(obj, "includeInAvailability",
                                json_string("all"));
        }
        buf_free(&attrib);
    }

    if (jmap_wantprop(rock->get->props, "defaultAlertsWithTime")) {
        static const char *annot =
            DAV_ANNOT_NS "<" XML_NS_CALDAV ">default-alarm-vevent-datetime";
        json_object_set_new(obj, "defaultAlertsWithTime",
                getcalendar_defaultalerts(req->userid, mbentry->name, annot));
    }

    if (jmap_wantprop(rock->get->props, "defaultAlertsWithoutTime")) {
        static const char *annot =
            DAV_ANNOT_NS "<" XML_NS_CALDAV ">default-alarm-vevent-date";
        json_object_set_new(obj, "defaultAlertsWithoutTime",
                getcalendar_defaultalerts(req->userid, mbentry->name, annot));
    }

    if (jmap_wantprop(rock->get->props, "timeZone")) {
        buf_reset(&attrib);
        static const char *tzid_annot =
            DAV_ANNOT_NS "<" XML_NS_CALDAV ">calendar-timezone-id";
        r = annotatemore_lookupmask_mbe(mbentry, tzid_annot,
                                    req->userid, &attrib);
        if (buf_len(&attrib)) {
            json_object_set_new(obj, "timeZone",
                                json_string(buf_cstring(&attrib)));
        }
        else {
            static const char *tz_annot =
                DAV_ANNOT_NS "<" XML_NS_CALDAV ">calendar-timezone";
            r = annotatemore_lookupmask_mbe(mbentry, tz_annot,
                                    req->userid, &attrib);
            if (buf_len(&attrib)) {
                icalcomponent *ical, *vtz;
                icalproperty *tzid;

                ical = icalparser_parse_string(buf_cstring(&attrib));
                vtz = icalcomponent_get_first_component(ical,
                                                        ICAL_VTIMEZONE_COMPONENT);
                tzid = icalcomponent_get_first_property(vtz, ICAL_TZID_PROPERTY);
                json_object_set_new(obj, "timeZone",
                                    json_string(icalproperty_get_tzid(tzid)));
                icalcomponent_free(ical);
            }
            else {
                json_object_set_new(obj, "timeZone", json_null());
            }
        }
        buf_free(&attrib);
    }

    if (jmap_wantprop(rock->get->props, "myRights")) {
        json_object_set_new(obj, "myRights",
                calendarrights_to_jmap(rights,
                    !strcmp(rock->req->userid, rock->req->accountid)));
    }

    if (jmap_wantprop(rock->get->props, "shareWith")) {
        json_t *sharewith = jmap_get_sharewith(mbentry,
                calendarrights_to_sharewith);
        json_object_set_new(obj, "shareWith", sharewith);
    }

    json_array_append_new(rock->get->list, obj);

done:
    buf_free(&attrib);
    mbname_free(&mbname);
    return r;
}

static const jmap_property_t calendar_props[] = {
    {
        "id",
        NULL,
        JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE | JMAP_PROP_ALWAYS_GET
    },
    {
        "role",
        NULL,
        0
    },
    {
        "name",
        NULL,
        0
    },
    {
        "description",
        NULL,
        0
    },
    {
        "color",
        NULL,
        0
    },
    {
        "sortOrder",
        NULL,
        0
    },
    {
        "isVisible",
        NULL,
        0
    },
    {
        "isSubscribed",
        NULL,
        0
    },
    {
        "includeInAvailability",
        NULL,
        0
    },
    {
        "defaultAlertsWithTime",
        NULL,
        0
    },
    {
        "defaultAlertsWithoutTime",
        NULL,
        0
    },
    {
        "timeZone",
        NULL,
        0
    },
    {
        "participantIdentities",
        NULL,
        0
    },
    {
        "shareWith",
        NULL,
        0
    },
    {
        "myRights",
        NULL,
        JMAP_PROP_SERVER_SET
    },

    /* FM extensions (do ALL of these get through to Cyrus?) */
    {
        "syncedFrom",
        JMAP_CALENDARS_EXTENSION,
        0
    },
    {
        "isEventsPublic",
        JMAP_CALENDARS_EXTENSION,
        0
    },
    {
        "isFreeBusyPublic",
        JMAP_CALENDARS_EXTENSION,
        0
    },
    {
        "eventsUrl",
        JMAP_CALENDARS_EXTENSION,
        JMAP_PROP_SERVER_SET
    },
    {
        "freeBusyUrl",
        JMAP_CALENDARS_EXTENSION,
        JMAP_PROP_SERVER_SET
    },
    {
        "calDavUrl",
        JMAP_CALENDARS_EXTENSION,
        JMAP_PROP_SERVER_SET
    },
    {
        "x-href",
        JMAP_CALENDARS_EXTENSION,
        JMAP_PROP_SERVER_SET
    },

    { NULL, NULL, 0 }
};

static int has_calendars_cb(const mbentry_t *mbentry, void *rock)
{
    jmap_req_t *req = rock;
    if (mbtype_isa(mbentry->mbtype) == MBTYPE_CALENDAR &&
            jmap_hasrights_mbentry(req, mbentry, JACL_LOOKUP)) {
        return CYRUSDB_DONE;
    }
    return 0;
}

static int has_calendars(jmap_req_t *req)
{
    mbname_t *mbname = mbname_from_userid(req->accountid);
    mbname_push_boxes(mbname, config_getstring(IMAPOPT_CALENDARPREFIX));
    int r = mboxlist_mboxtree(mbname_intname(mbname), has_calendars_cb,
                              req, MBOXTREE_SKIP_ROOT);
    mbname_free(&mbname);
    return r == CYRUSDB_DONE;
}

static int jmap_calendar_get(struct jmap_req *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_get get;
    json_t *err = NULL;
    int r = 0;


    /* Parse request */
    jmap_get_parse(req, &parser, calendar_props, /*allow_null_ids*/1,
                   NULL, NULL, &get, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    if (!has_calendars(req)) {
        jmap_ok(req, jmap_get_reply(&get));
        goto done;
    }

    /* Build callback data */
    struct getcalendars_rock rock = { req, &get, 1 /*skiphidden*/ };

    /* Does the client request specific mailboxes? */
    if (JNOTNULL(get.ids)) {
        size_t i;
        json_t *jval;

        rock.skip_hidden = 0; /* complain about missing ACL rights */
        json_array_foreach(get.ids, i, jval) {
            const char *id = json_string_value(jval);
            char *mboxname = caldav_mboxname(req->accountid, id);
            mbentry_t *mbentry = NULL;

            r = mboxlist_lookup(mboxname, &mbentry, NULL);
            if (r == IMAP_NOTFOUND || !mbentry) {
                json_array_append(get.not_found, jval);
                r = 0;
            }
            else {
                r = getcalendars_cb(mbentry, &rock);
                if (r == IMAP_PERMISSION_DENIED) {
                    json_array_append(get.not_found, jval);
                    r = 0;
                }
            }

            if (mbentry) mboxlist_entry_free(&mbentry);
            free(mboxname);
            if (r) goto done;
        }
    }
    else {
        // XXX: replace with a function which only looks inside INBOX.#calendars
        r = mboxlist_usermboxtree(req->accountid, req->authstate, &getcalendars_cb, &rock, MBOXTREE_INTERMEDIATES);
        if (r) goto done;
    }

    /* Build response */
    json_t *jstate = jmap_getstate(req, MBTYPE_CALENDAR, /*refresh*/0);
    get.state = xstrdup(json_string_value(jstate));
    json_decref(jstate);
    jmap_ok(req, jmap_get_reply(&get));

done:
    jmap_parser_fini(&parser);
    jmap_get_fini(&get);
    return r;
}

struct calendarchanges_rock {
    jmap_req_t *req;
    struct jmap_changes *changes;
};

static int getcalendarchanges_cb(const mbentry_t *mbentry, void *vrock)
{
    struct calendarchanges_rock *rock = (struct calendarchanges_rock *) vrock;
    mbname_t *mbname = NULL;
    jmap_req_t *req = rock->req;
    int r = 0;

    /* Ignore old changes. */
    if (mbentry->foldermodseq <= rock->changes->since_modseq) {
        goto done;
    }

    /* Ignore any mailboxes that aren't (possibly deleted) calendars. */
    if (!mboxname_iscalendarmailbox(mbentry->name, mbentry->mbtype))
        return 0;

    /* Ignore mailboxes that are hidden from us. */
    /* XXX Deleted mailboxes loose their ACL so we can't determine
     * if they ever could be read by the authenticated user. We
     * need to leak these deleted entries to not mess up client state. */
    if (!(mbentry->mbtype & MBTYPE_DELETED) || strcmpsafe(mbentry->acl, "")) {
        if (!jmap_hasrights_mbentry(req, mbentry, JACL_READITEMS)) return 0;
    }

    /* Ignore special-purpose calendar mailboxes. */
    mbname = mbname_from_intname(mbentry->name);
    if (jmap_calendar_isspecial(mbname)) {
        goto done;
    }

    /* Ignore calendars that don't store VEVENTs */
    struct buf attrib = BUF_INITIALIZER;
    static const char *calcompset_annot =
        DAV_ANNOT_NS "<" XML_NS_CALDAV ">supported-calendar-component-set";
    unsigned long supported_components = -1; /* ALL component types by default. */
    r = annotatemore_lookupmask_mbe(mbentry, calcompset_annot,
                                    rock->req->accountid, &attrib);
    if (attrib.len) {
        supported_components = strtoul(buf_cstring(&attrib), NULL, 10);
        buf_free(&attrib);
    }
    if (!(supported_components & CAL_COMP_VEVENT)) {
        goto done;
    }

    const strarray_t *boxes = mbname_boxes(mbname);
    const char *id = strarray_nth(boxes, boxes->count-1);

    /* Report this calendar as created, updated or destroyed. */
    if (mbentry->mbtype & MBTYPE_DELETED) {
        if (mbentry->createdmodseq <= rock->changes->since_modseq)
            json_array_append_new(rock->changes->destroyed, json_string(id));
    }
    else {
        if (mbentry->createdmodseq <= rock->changes->since_modseq)
            json_array_append_new(rock->changes->updated, json_string(id));
        else
            json_array_append_new(rock->changes->created, json_string(id));
    }

done:
    mbname_free(&mbname);
    return r;
}

static int jmap_calendar_changes(struct jmap_req *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_changes changes;
    json_t *err = NULL;
    int r = 0;

    /* Parse request */
    jmap_changes_parse(req, &parser, req->counters.caldavfoldersdeletedmodseq,
                       NULL, NULL, &changes, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    if (!has_calendars(req)) {
        jmap_ok(req, jmap_changes_reply(&changes));
        goto done;
    }

    /* Lookup any changes. */
    char *mboxname = caldav_mboxname(req->accountid, NULL);
    struct calendarchanges_rock rock = { req, &changes };

    r = mboxlist_mboxtree(mboxname, getcalendarchanges_cb, &rock,
                          MBOXTREE_TOMBSTONES|MBOXTREE_SKIP_ROOT);
    free(mboxname);
    if (r) {
        jmap_error(req, json_pack("{s:s}", "type", "cannotCalculateChanges"));
        r = 0;
        goto done;
    }

    /* Determine new state.  XXX  what about max_changes? */
    changes.new_modseq = /*changes.has_more_changes ? rock.highestmodseq :*/
        jmap_highestmodseq(req, MBTYPE_CALENDAR);

    /* Build response */
    jmap_ok(req, jmap_changes_reply(&changes));

  done:
    jmap_changes_fini(&changes);
    jmap_parser_fini(&parser);
    if (r) {
        jmap_error(req, jmap_server_error(r));
    }
    return 0;
}

static char *_emailalert_defaultrecipient(const char *userid)
{
    const char *annotname = DAV_ANNOT_NS "<" XML_NS_CALDAV ">calendar-user-address-set";
    char *mailboxname = caldav_mboxname(userid, NULL);
    struct buf buf = BUF_INITIALIZER;
    int r = annotatemore_lookupmask(mailboxname, annotname, userid, &buf);

    char *recipient = NULL;

    if (!r && buf_len(&buf)) {
        strarray_t *values = strarray_split(buf_cstring(&buf), ",", STRARRAY_TRIM);
        const char *item = strarray_nth(values, 0);
        if (!strncasecmp(item, "mailto:", 7)) item += 7;
        recipient = strconcat("mailto:", item, NULL);
        strarray_free(values);
    }
    else if (strchr(userid, '@')) {
        recipient = strconcat("mailto:", userid, NULL);
    }
    else {
        recipient = strconcat("mailto:", userid, "@", config_defdomain, NULL);
    }

    buf_free(&buf);
    free(mailboxname);
    return recipient;
}

/* jmap calendar APIs */

enum { TRANSP_TRANSPARENT = 0, TRANSP_OPAQUE_ATTENDING, TRANSP_OPAQUE };

struct setcalendar_props {
    const char *name;
    const char *desc;
    const char *color;
    const char *tzid;
    int sortOrder;
    int isVisible;
    int isSubscribed;
    int transp;
    json_t *participant_identities;
    struct {
        json_t *With;
        int overwrite_acl;
    } share;
    long comp_types;
    ptrarray_t *defaultalerts_withtime;    // list of VALARM icalcomponent*
    ptrarray_t *defaultalerts_withouttime; // list of VALARM icalcomponent*
};

static void setcalendar_props_fini(struct setcalendar_props *props)
{
    if (props->defaultalerts_withtime) {
        icalcomponent *valarm;
        while ((valarm = ptrarray_pop(props->defaultalerts_withtime))) {
            icalcomponent_free(valarm);
        }
        ptrarray_free(props->defaultalerts_withtime);
    }
    if (props->defaultalerts_withouttime) {
        icalcomponent *valarm;
        while ((valarm = ptrarray_pop(props->defaultalerts_withouttime))) {
            icalcomponent_free(valarm);
        }
        ptrarray_free(props->defaultalerts_withouttime);
    }
}

static void setcalendar_readprops(jmap_req_t *req,
                                  struct jmap_parser *parser,
                                  struct setcalendar_props *props,
                                  json_t *arg,
                                  int is_create)
{
    memset(props, 0, sizeof(struct setcalendar_props));

    if (is_create) {
        props->isVisible = 1;
        props->isSubscribed = 1;
        props->transp = -1;
        props->share.overwrite_acl = 1;
        props->comp_types = config_types_to_caldav_types();
    }
    else {
        props->sortOrder = -1;
        props->isVisible = -1;
        props->isSubscribed = -1;
        props->share.overwrite_acl = 1;
        props->transp = -1;
        props->comp_types = -1;
    }

    /* name */
    json_t *jprop = json_object_get(arg, "name");
    if (json_is_string(jprop)) {
        props->name = json_string_value(jprop);
        if (strnlen(props->name, 256) == 256) {
            jmap_parser_invalid(parser, "name");
        }
    }
    else if (is_create || JNOTNULL(jprop)) {
        jmap_parser_invalid(parser, "name");
    }

    /* color */
    jprop = json_object_get(arg, "color");
    if (json_is_string(jprop)) {
        props->color = json_string_value(jprop);
    }
    else if (JNOTNULL(jprop)) {
        jmap_parser_invalid(parser, "color");
    }

    /* sortOrder */
    jprop = json_object_get(arg, "sortOrder");
    if (json_is_integer(jprop)) {
        props->sortOrder = json_integer_value(jprop);
        if (props->sortOrder < 0) {
            jmap_parser_invalid(parser, "sortOrder");
        }
    }
    else if (JNOTNULL(jprop)) {
        jmap_parser_invalid(parser, "sortOrder");
    }

    /* isVisible */
    jprop = json_object_get(arg, "isVisible");
    if (json_is_boolean(jprop)) {
        props->isVisible = json_boolean_value(jprop);
    }
    else if (JNOTNULL(jprop)) {
        jmap_parser_invalid(parser, "isVisible");
    }

    /* isSubscribed */
    jprop = json_object_get(arg, "isSubscribed");
    if (json_is_boolean(jprop)) {
        props->isSubscribed = json_boolean_value(jprop);
        if (!strcmp(req->accountid, req->userid)) {
            if (!props->isSubscribed) {
                /* unsubscribing own calendars isn't supported */
                jmap_parser_invalid(parser, "isSubscribed");
            }
            else props->isSubscribed = -1; // ignore
        }
    }
    else if (JNOTNULL(jprop)) {
        jmap_parser_invalid(parser, "isSubscribed");
    }

    /* description */
    jprop = json_object_get(arg, "description");
    if (json_is_string(jprop)) {
        props->desc = json_string_value(jprop);
    }
    else if (JNOTNULL(jprop)) {
        jmap_parser_invalid(parser, "description");
    }

    /* shareWith */
    if (!is_create) {
        json_t *shareWith = NULL;
        /* Is shareWith overwritten or patched? */
        jmap_parse_sharewith_patch(arg, &shareWith);
        if (shareWith) {
            props->share.overwrite_acl = 0;
            json_object_set_new(arg, "shareWith", shareWith);
        }
    }
    jprop = json_object_get(arg, "shareWith");
    if (json_is_object(jprop) || json_is_null(jprop)) {
        props->share.With = jprop;
    }
    else if (jprop) {
        jmap_parser_invalid(parser, "shareWith");
    }

    /* participantIdentities */
    jprop = json_object_get(arg, "participantIdentities");
    if (json_array_size(jprop)) {
        size_t i;
        json_t *jval;
        props->participant_identities = jprop;
        json_array_foreach(jprop, i, jval) {
            if (json_is_object(jval)) {
                jmap_parser_push_index(parser, "participantIdentities", i, NULL);
                const char *propname;
                json_t *jv;
                struct buf buf = BUF_INITIALIZER;
                json_object_foreach(jval, propname, jv) {
                    if (!strcmp(propname, "name")) {
                        if (JNOTNULL(jv) && !json_is_string(jv)) {
                            jmap_parser_invalid(parser, "name");
                        }
                    }
                    else if (!strcmp(propname, "type") || !strcmp(propname, "uri")) {
                        const char *s = json_string_value(jv);
                        if (s) buf_setcstr(&buf, s);
                        buf_trim(&buf);
                        if (!s || buf_len(&buf) == 0) {
                            jmap_parser_invalid(parser, propname);
                        }
                        buf_reset(&buf);
                    }
                    else jmap_parser_invalid(parser, propname);
                }
                buf_free(&buf);
                jmap_parser_pop(parser);
            }
            else {
                jmap_parser_push_index(parser, "participantIdentities", i, NULL);
                jmap_parser_invalid(parser, NULL);
                jmap_parser_pop(parser);
            }
        }
    }
    else if (jprop) {
        jmap_parser_invalid(parser, "participantIdentities");
    }

    /* includeInAvailablity */
    jprop = json_object_get(arg, "includeInAvailability");
    if (json_is_string(jprop)) {
        const char *avail = json_string_value(jprop);
        props->transp = -1;
        if (!strcmp(avail, "all")) {
            props->transp = TRANSP_OPAQUE;
        }
        else if (!strcmp(avail, "none")) {
            props->transp = TRANSP_TRANSPARENT;
        }
        else if (!strcmp(avail, "attending")) {
            props->transp = TRANSP_OPAQUE_ATTENDING;
        }
        if (props->transp == -1) {
            jmap_parser_invalid(parser, "includeInAvailablity");
        }
    }
    else if (JNOTNULL(jprop)) {
        jmap_parser_invalid(parser, "includeInAvailablity");
    }

    /* timeZone */
    jprop = json_object_get(arg, "timeZone");
    if (json_is_string(jprop)) {
        props->tzid = json_string_value(jprop);
        /* Verify we have tzid record in the database */
        if (icaltimezone_get_cyrus_timezone_from_tzid(props->tzid) == NULL) {
            jmap_parser_invalid(parser, "timeZone");
        }
    }
    else if (JNOTNULL(jprop)) {
        jmap_parser_invalid(parser, "timeZone");
    }

    /* myRights */
    jprop = json_object_get(arg, "myRights");
    if (JNOTNULL(jprop)) {
        /* The myRights property is server-set and MUST NOT be set. */
        jmap_parser_invalid(parser, "myRights");
    }

    char *emailalert_recipient = _emailalert_defaultrecipient(req->userid);

    /* defaultAlertsWithTime */
    jprop = json_object_get(arg, "defaultAlertsWithTime");
    if (json_is_array(jprop)) {
        size_t i;
        json_t *jalert;
        json_array_foreach(jprop, i, jalert) {
            jmap_parser_push_index(parser, "defaultAlertsWithTime", i, NULL);
            char *id = xstrdup(makeuuid());
            icalcomponent *valarm =
                jmapical_alert_to_ical(jalert, parser, id, NULL, NULL,
                                       emailalert_recipient);
            if (valarm) {
                if (!props->defaultalerts_withtime) {
                    props->defaultalerts_withtime = ptrarray_new();
                }
                ptrarray_append(props->defaultalerts_withtime, valarm);
            }
            free(id);
            jmap_parser_pop(parser);
        }
    }
    else if (json_is_null(jprop)) {
        props->defaultalerts_withtime = ptrarray_new();
    }
    else if (jprop) {
        jmap_parser_invalid(parser, "defaultAlertsWithTime");
    }

    /* defaultAlertsWithoutTime */
    jprop = json_object_get(arg, "defaultAlertsWithoutTime");
    if (json_is_array(jprop)) {
        size_t i;
        json_t *jalert;
        json_array_foreach(jprop, i, jalert) {
            jmap_parser_push_index(parser, "defaultAlertsWithoutTime", i, NULL);
            char *id = xstrdup(makeuuid());
            icalcomponent *valarm =
                jmapical_alert_to_ical(jalert, parser, id, NULL, NULL,
                                       emailalert_recipient);
            if (valarm) {
                if (!props->defaultalerts_withouttime) {
                    props->defaultalerts_withouttime = ptrarray_new();
                }
                ptrarray_append(props->defaultalerts_withouttime, valarm);
            }
            free(id);
            jmap_parser_pop(parser);
        }
    }
    else if (json_is_null(jprop)) {
        props->defaultalerts_withouttime = ptrarray_new();
    }
    else if (jprop) {
        jmap_parser_invalid(parser, "defaultAlertsWithoutTime");
    }

    /* role - just make sure its valid */
    jprop = json_object_get(arg, "role");
    if (JNOTNULL(jprop) && strcmpsafe(json_string_value(jprop), "inbox")) {
        jmap_parser_invalid(parser, "role");
    }

    free(emailalert_recipient);
}

/* Write  the calendar properties in the calendar mailbox named mboxname.
 * NULL values and negative integers are ignored. Return 0 on success. */
static int setcalendar_writeprops(jmap_req_t *req,
                               const char *mboxname,
                               struct setcalendar_props *props,
                               int ignore_acl)
{
    struct mailbox *mbox = NULL;
    annotate_state_t *astate = NULL;
    struct buf val = BUF_INITIALIZER;
    int r;

    if (!jmap_hasrights(req, mboxname, JACL_READITEMS) && !ignore_acl)
        return IMAP_MAILBOX_NONEXISTENT;

    r = jmap_openmbox(req, mboxname, &mbox, 1);
    if (r) {
        syslog(LOG_ERR, "jmap_openmbox(req, %s) failed: %s",
                mboxname, error_message(r));
        return r;
    }

    r = mailbox_get_annotate_state(mbox, 0, &astate);
    if (r) {
        syslog(LOG_ERR, "IOERROR: failed to open annotations %s: %s",
                mailbox_name(mbox), error_message(r));
    }

    /* name */
    if (!r && props->name) {
        buf_setcstr(&val, props->name);
        static const char *displayname_annot =
            DAV_ANNOT_NS "<" XML_NS_DAV ">displayname";
        r = annotate_state_writemask(astate, displayname_annot, req->userid, &val);
        if (r) {
            syslog(LOG_ERR, "failed to write annotation %s: %s",
                    displayname_annot, error_message(r));
        }
        buf_reset(&val);
    }
    /* description */
    if (!r && props->desc) {
        buf_setcstr(&val, props->desc);
        static const char *description_annot =
            DAV_ANNOT_NS "<" XML_NS_DAV ">description";
        r = annotate_state_writemask(astate, description_annot, req->userid, &val);
        if (r) {
            syslog(LOG_ERR, "failed to write annotation %s: %s",
                    description_annot, error_message(r));
        }
        buf_reset(&val);
    }
    /* color */
    if (!r && props->color) {
        buf_setcstr(&val, props->color);
        static const char *color_annot =
            DAV_ANNOT_NS "<" XML_NS_APPLE ">calendar-color";
        r = annotate_state_writemask(astate, color_annot, req->userid, &val);
        if (r) {
            syslog(LOG_ERR, "failed to write annotation %s: %s",
                    color_annot, error_message(r));
        }
        buf_reset(&val);
    }
    /* sortOrder */
    if (!r && props->sortOrder >= 0) {
        buf_printf(&val, "%d", props->sortOrder);
        static const char *sortOrder_annot =
            DAV_ANNOT_NS "<" XML_NS_APPLE ">calendar-order";
        r = annotate_state_writemask(astate, sortOrder_annot, req->userid, &val);
        if (r) {
            syslog(LOG_ERR, "failed to write annotation %s: %s",
                    sortOrder_annot, error_message(r));
        }
        buf_reset(&val);
    }
    /* isVisible */
    if (!r && props->isVisible >= 0) {
        buf_setcstr(&val, props->isVisible ? "true" : "false");
        static const char *visible_annot =
            DAV_ANNOT_NS "<" XML_NS_CALDAV ">X-FM-isVisible";
        r = annotate_state_writemask(astate, visible_annot, req->userid, &val);
        if (r) {
            syslog(LOG_ERR, "failed to write annotation %s: %s",
                    visible_annot, error_message(r));
        }
        buf_reset(&val);
    }

    /* participantIdentities */
    if (!r && json_is_array(props->participant_identities)) {
        static const char *annot =
            DAV_ANNOT_NS "<" XML_NS_CALDAV ">calendar-user-address-set";
        size_t i;
        json_t *jpid;
        json_array_foreach(props->participant_identities, i, jpid) {
            const char *uri = json_string_value(json_object_get(jpid, "uri"));
            if (!uri) continue;
            buf_appendcstr(&val, uri);
            if (i < json_array_size(props->participant_identities)-1)
                buf_putc(&val, ',');
        }
        r = annotate_state_writemask(astate, annot, req->userid, &val);
        if (r) {
            syslog(LOG_ERR, "failed to write annotation %s: %s",
                   annot, error_message(r));
        }
        buf_reset(&val);
    }

    /* isSubscribed */
    if (!r && props->isSubscribed >= 0) {
        /* Update subscription database */
        r = mboxlist_changesub(mboxname, req->userid, req->authstate,
                               props->isSubscribed, 0, /*notify*/1);

        /* Set invite status for CalDAV */
        buf_setcstr(&val, props->isSubscribed ? "invite-accepted" : "invite-declined");
        static const char *invite_annot =
            DAV_ANNOT_NS "<" XML_NS_DAV ">invite-status";
        r = annotate_state_writemask(astate, invite_annot, req->userid, &val);
        if (r) {
            syslog(LOG_ERR, "failed to write annotation %s: %s",
                    invite_annot, error_message(r));
        }
        buf_reset(&val);
    }

    /* includeInAvailability */
    if (!r && props->transp >= 0) {
        switch (props->transp) {
        case TRANSP_TRANSPARENT:
            buf_setcstr(&val, "transparent");
            break;
        case TRANSP_OPAQUE_ATTENDING:
            buf_setcstr(&val, "opaque-attending");
            break;
        default:
            buf_setcstr(&val, "opaque");
            break;
        }
        static const char *transp_annot =
            DAV_ANNOT_NS "<" XML_NS_CALDAV ">schedule-calendar-transp";
        r = annotate_state_writemask(astate, transp_annot, req->userid, &val);
        if (r) {
            syslog(LOG_ERR, "failed to write annotation %s: %s",
                   transp_annot, error_message(r));
        }
        buf_reset(&val);
    }

    /* timeZone */
    if (!r && props->tzid) {
        buf_setcstr(&val, props->tzid);
        static const char *tzid_annot =
            DAV_ANNOT_NS "<" XML_NS_CALDAV ">calendar-timezone-id";
        r = annotate_state_writemask(astate, tzid_annot, req->userid, &val);
        if (r) {
            syslog(LOG_ERR, "failed to write annotation %s: %s",
                    tzid_annot, error_message(r));
        }
        buf_reset(&val);
    }

    /* shareWith */
    if (!r && props->share.With) {
        r = jmap_set_sharewith(mbox, props->share.With,
                props->share.overwrite_acl, calendar_sharewith_to_rights);
        if (!r) {
            char *userid = mboxname_to_userid(mailbox_name(mbox));
            r = caldav_update_shareacls(userid);
            free(userid);
        }
    }

    /* supported components */
    if (!r && props->comp_types >= 0) {
        const char *comp_annot =
            DAV_ANNOT_NS "<" XML_NS_CALDAV ">supported-calendar-component-set";
        buf_printf(&val, "%lu", (unsigned long) props->comp_types);
        r = annotate_state_writemask(astate, comp_annot, req->userid, &val);
        if (r) {
            syslog(LOG_ERR, "failed to write annotation %s: %s",
                    comp_annot, error_message(r));
        }
        buf_reset(&val);
    }

    /* defaultAlertsWithTime */
    if (!r && (props->defaultalerts_withtime || props->defaultalerts_withouttime)) {
        if (props->defaultalerts_withtime) {
            /* Wrap alarms with XROOT component */
            icalcomponent *ical = icalcomponent_new(ICAL_XROOT_COMPONENT);
            int i;
            for (i = 0; i < ptrarray_size(props->defaultalerts_withtime); i++) {
                icalcomponent *valarm = ptrarray_nth(props->defaultalerts_withtime, i);
                icalcomponent_add_component(ical, valarm);
            }
            /* XROOT component takes ownership of alarms */
            ptrarray_fini(props->defaultalerts_withtime);
            /* Write alarms */
            r = caldav_write_defaultalarms(mbox, req->userid,
                    CALDAV_DEFAULTALARMS_ANNOT_WITHTIME, ical);
            if (r) {
                syslog(LOG_ERR, "failed to write annotation %s: %s",
                        CALDAV_DEFAULTALARMS_ANNOT_WITHTIME, error_message(r));
            }
            icalcomponent_free(ical);
        }
        if (!r && props->defaultalerts_withouttime) {
            /* Wrap alarms with XROOT component */
            icalcomponent *ical = icalcomponent_new(ICAL_XROOT_COMPONENT);
            int i;
            for (i = 0; i < ptrarray_size(props->defaultalerts_withouttime); i++) {
                icalcomponent *valarm = ptrarray_nth(props->defaultalerts_withouttime, i);
                icalcomponent_add_component(ical, valarm);
            }
            /* XROOT component takes ownership of alarms */
            ptrarray_fini(props->defaultalerts_withouttime);
            /* Write alarms */
            r = caldav_write_defaultalarms(mbox, req->userid,
                    CALDAV_DEFAULTALARMS_ANNOT_WITHDATE, ical);
            if (r) {
                syslog(LOG_ERR, "failed to write annotation %s: %s",
                        CALDAV_DEFAULTALARMS_ANNOT_WITHDATE, error_message(r));
            }
            icalcomponent_free(ical);
        }
        if (!r) {
            r = caldav_bump_defaultalarms(mbox);
            if (r) {
                syslog(LOG_ERR, "failed to bump default alarms for %s: %s",
                        mailbox_name(mbox), error_message(r));
            }
        }
    }

    buf_free(&val);
    if (mbox) {
        if (r) mailbox_abort(mbox);
        jmap_closembox(req, &mbox);
    }
    return r;
}

static int _calendar_hasevents_cb(void *rock __attribute__((unused)),
                                  struct caldav_data *cdata __attribute__((unused)))
{
    /* Any alive event will do */
    return CYRUSDB_DONE;
}

/* Delete the calendar mailbox named mboxname for the userid in req. */
static void setcalendars_destroy(jmap_req_t *req, const char *calid,
                                 int destroy_events, json_t **err)
{
    char *mboxname = caldav_mboxname(req->accountid, calid);
    char *defaultname = caldav_scheddefault(req->accountid);
    mbname_t *mbname = mbname_from_intname(mboxname);
    mbentry_t *mbentry = NULL;
    struct buf buf = BUF_INITIALIZER;
    struct caldav_db *db = NULL;
    int r = 0;

    /* Make sure we don't delete special calendars */
    if (!mbname || jmap_calendar_isspecial(mbname)) {
        *err = json_pack("{s:s}", "type", "notFound");
        goto done;
    }

    jmap_mboxlist_lookup(mboxname, &mbentry, NULL);

    /* Check ACL */
    if (!mbentry || !jmap_hasrights_mbentry(req, mbentry, JACL_READITEMS)) {
        *err = json_pack("{s:s}", "type", "notFound");
        goto done;
    }
    else if (!jmap_hasrights_mbentry(req, mbentry, JACL_DELETE)) {
        *err = json_pack("{s:s}", "type", "accountReadOnly");
        goto done;
    }

    db = caldav_open_userid(req->accountid);
    if (!db) {
        xsyslog(LOG_ERR, "caldav_open_mailbox failed", "accountid=<%s>",
                req->accountid);
        goto done;
    }

    /* Validate onDestroyRemoveEvents */
    if (!destroy_events) {
        r = caldav_foreach(db, mbentry, _calendar_hasevents_cb, NULL);
        if (r == CYRUSDB_DONE) {
            *err = json_pack("{s:s}", "type", "calendarHasEvents");
            goto done;
        }
        else if (r) {
            *err = jmap_server_error(r);
            goto done;
        }
    }

    /* Delete calendar */
    r = caldav_delmbox(db, mbentry);
    if (r) {
        xsyslog(LOG_ERR, "failed to delete mailbox from caldav_db",
                "mboxname=<%s> mboxid=<%s> err=<%s>",
                mbentry->name, mbentry->uniqueid, error_message(r));
        goto done;
    }
    if (r) goto done;

    jmap_myrights_delete(req, mboxname);

    /* Remove from subscriptions db */
    mboxlist_changesub(mboxname, req->userid, req->authstate, 0, 1, 0);

    struct mboxevent *mboxevent = mboxevent_new(EVENT_MAILBOX_DELETE);
    if (mboxlist_delayed_delete_isenabled()) {
        r = mboxlist_delayed_deletemailbox(mboxname,
                httpd_userisadmin || httpd_userisproxyadmin,
                req->userid, req->authstate, mboxevent,
                MBOXLIST_DELETE_CHECKACL|MBOXLIST_DELETE_KEEP_INTERMEDIARIES);
    } else {
        r = mboxlist_deletemailbox(mboxname,
                httpd_userisadmin || httpd_userisproxyadmin,
                req->userid, req->authstate, mboxevent,
                MBOXLIST_DELETE_CHECKACL|MBOXLIST_DELETE_KEEP_INTERMEDIARIES);
    }
    mboxevent_free(&mboxevent);

    if (!r) r = caldav_update_shareacls(req->accountid);

done:
    if (db) {
        int rr = caldav_close(db);
        if (!r) r = rr;
    }
    if (r && *err == NULL) {
        if (r == IMAP_MAILBOX_NONEXISTENT) {
            *err = json_pack("{s:s}", "type", "notFound");
        }
        else {
            *err = jmap_server_error(r);
        }
    }
    free(mboxname);
    free(defaultname);
    mbname_free(&mbname);
    mboxlist_entry_free(&mbentry);
    buf_free(&buf);
}

static char *setcalendars_create_rewriteacl(jmap_req_t *req, const char *parentacl)
{

    /* keep just the owner and admin parts of the new ACL!  Everything
     * else will be added from share.With.  */
    char *newacl = xstrdup("");
    char *acl = xstrdup(parentacl);
    char *userid;
    char *nextid = NULL;
    for (userid = acl; userid; userid = nextid) {
        char *rightstr;
        int access;

        rightstr = strchr(userid, '\t');
        if (!rightstr) break;
        *rightstr++ = '\0';

        nextid = strchr(rightstr, '\t');
        if (!nextid) break;
        *nextid++ = '\0';

        if (!strcmp(userid, req->accountid) || is_system_user(userid)) {
            /* owner or system */
            cyrus_acl_strtomask(rightstr, &access);
            int r = cyrus_acl_set(&newacl, userid,
                    ACL_MODE_SET, access, NULL, NULL);
            if (r) {
                syslog(LOG_ERR, "IOERROR: failed to set_acl for calendar create (%s, %s) %s",
                        userid, req->accountid, error_message(r));
                free(newacl);
                newacl = NULL;
                goto done;
            }
        }
    }

done:
    free(acl);
    return newacl;
}

static void setcalendars_create(struct jmap_req *req,
                                const char *creation_id,
                                json_t *arg,
                                json_t **record,
                                json_t **err)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct setcalendar_props props;
    mbentry_t *mbparent = NULL;
    char *parentname = caldav_mboxname(req->accountid, NULL);
    char *uid = xstrdup(makeuuid());
    char *mboxname = caldav_mboxname(req->accountid, uid);
    int r = 0;

    /* Parse and validate properties. */
    setcalendar_readprops(req, &parser, &props, arg, /*is_create*/1);
    if (props.share.With) {
        if (!jmap_hasrights(req, parentname, ACL_ADMIN)) {
            jmap_parser_invalid(&parser, "shareWith");
        }
    }
    if (props.participant_identities && !jmap_is_using(req, JMAP_CALENDARS_EXTENSION)) {
        jmap_parser_invalid(&parser, "participantIdentities");
    }
    if (json_array_size(parser.invalid)) {
        *err = json_pack("{s:s, s:O}",
                "type", "invalidProperties",
                "properties", parser.invalid);
        goto done;
    }

    /* Make sure we are allowed to create the calendar */
    mboxlist_lookup(parentname, &mbparent, NULL);
    if (!jmap_hasrights_mbentry(req, mbparent, JACL_CREATECHILD)) {
        *err = json_pack("{s:s}", "type", "accountReadOnly");
        goto done;
    }

    /* Create the calendar */
    char *acl = setcalendars_create_rewriteacl(req, mbparent->acl);
    if (!acl || acl[0] == '\0') {
        r = IMAP_INTERNAL;
        free(acl);
        goto done;
    }
    mbentry_t mbentry = MBENTRY_INITIALIZER;
    mbentry.name = mboxname;
    mbentry.acl = acl;
    mbentry.mbtype = MBTYPE_CALENDAR;
    r = mboxlist_createmailbox(&mbentry, 0/*options*/, 0/*highestmodseq*/,
            0/*isadmin*/, httpd_userid, httpd_authstate,
            0/*flags*/, NULL/*mailboxptr*/);
    free(acl);
    if (r) {
        syslog(LOG_ERR, "IOERROR: failed to create %s (%s)",
                mboxname, error_message(r));
        goto done;
    }
    r = setcalendar_writeprops(req, mboxname, &props, /*ignore_acl*/1);
    if (r) {
        int rr = mboxlist_deletemailbox(mboxname, 1, "", NULL, NULL, 0);
        if (rr) {
            syslog(LOG_ERR, "could not delete mailbox %s: %s",
                    mboxname, error_message(rr));
        }
        goto done;
    }

    /* Report calendar as created. */
    *record = json_pack("{s:s}", "id", uid);
    jmap_add_id(req, creation_id, uid);

done:
    if (r && *err == NULL) {
        switch (r) {
            case IMAP_PERMISSION_DENIED:
                *err = json_pack("{s:s}", "type", "accountReadOnly");
                break;
            default:
                *err = jmap_server_error(r);
        }
    }
    mboxlist_entry_free(&mbparent);
    setcalendar_props_fini(&props);
    jmap_parser_fini(&parser);
    free(parentname);
    free(mboxname);
    free(uid);
}

static void setcalendars_update(jmap_req_t *req,
                                const char *uid,
                                json_t *arg,
                                json_t **record,
                                json_t **err)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    char *mboxname = caldav_mboxname(req->accountid, uid);
    mbname_t *mbname = mbname_from_intname(mboxname);

    /* Make sure we don't mess up special calendars */
    if (jmap_calendar_isspecial(mbname)) {
        *err = json_pack("{s:s}", "type", "notFound");
        goto done;
    }

    /* Parse and validate properties. */
    struct setcalendar_props props;
    setcalendar_readprops(req, &parser, &props, arg, /*is_create*/0);
    if (props.share.With) {
        if (!jmap_hasrights(req, mboxname, ACL_ADMIN)) {
            jmap_parser_invalid(&parser, "shareWith");
        }
    }
    if (json_array_size(parser.invalid)) {
        *err = json_pack("{s:s, s:O}",
                "type", "invalidProperties",
                "properties", parser.invalid);
        goto done;
    }

    /* Update the calendar */
    int r = setcalendar_writeprops(req, mboxname, &props, /*ignore_acl*/0);
    if (r) {
        switch (r) {
            case IMAP_MAILBOX_NONEXISTENT:
            case IMAP_NOTFOUND:
                *err = json_pack("{s:s}", "type", "notFound");
                break;
            case IMAP_PERMISSION_DENIED:
                *err = json_pack("{s:s}", "type", "accountReadOnly");
                break;
            default:
                *err = jmap_server_error(r);
        }
        goto done;
    }

    /* Report calendar as updated. */
    *record = json_null();

done:
    setcalendar_props_fini(&props);
    jmap_parser_fini(&parser);
    mbname_free(&mbname);
    free(mboxname);
}

static int setcalendars_parse_args(jmap_req_t *req __attribute__((unused)),
                                   struct jmap_parser *parser __attribute__((unused)),
                                   const char *arg, json_t *val, void *rock)
{
    int *on_destroy_remove_events = rock;
    *on_destroy_remove_events = 0;

    if (!strcmp(arg, "onDestroyRemoveEvents")) {
        if (json_is_boolean(val)) {
            *on_destroy_remove_events = json_boolean_value(val);
            return 1;
        }
    }
    return 0;
}

struct roleupdate {
    int updates_inbox;
    char *old_inboxid;
    char *new_inboxid;
};

#define JMAP_CALENDARS_ROLEUPDATE_INITIALIZER { 0, NULL, NULL }

static void roleupdate_fini(struct roleupdate *ru)
{
    free(ru->old_inboxid);
    free(ru->new_inboxid);
}

static int roleupdate_plan(jmap_req_t *req,
                           struct jmap_set *set,
                           struct roleupdate *ru)
{
    const char *key;
    json_t *jarg;
    size_t i;

    /* Does this request update the inbox? */
    ru->updates_inbox = json_array_size(set->destroy) > 0; // could destroy inbox
    if (!ru->updates_inbox) {
        json_object_foreach(set->create, key, jarg) {
            if (json_object_get(jarg, "role")) {
                ru->updates_inbox = 1;
                break;
            }
        }
    }
    if (!ru->updates_inbox) {
        json_object_foreach(set->update, key, jarg) {
            if (json_object_get(jarg, "role")) {
                ru->updates_inbox = 1;
                break;
            }
        }
    }
    if (!ru->updates_inbox) {
        return 0;
    }

    /* XXX - moving the inbox role from one calendar to the other
     * is prone to race conditions. We would like to prevent these
     * by locking the calendar home for the duration of the request.
     * We can't because the code we share with CalDAV has no access
     * to our request-scoped JMAP mailbox cache. So we need to make
     * sure the calendar home mailbox is closed, before we e.g. try
     * to destroy a calendar. */

    /* Load ACL */
    char *calhomename = caldav_mboxname(req->accountid, NULL);
    int haverights = !strcmp(req->userid, req->accountid) ||
                     jmap_hasrights(req, calhomename, JACL_ADMIN);

    /* Check if the final state of inbox updates is valid */
    ru->old_inboxid = caldav_scheddefault(req->accountid);
    strarray_t inboxes = STRARRAY_INITIALIZER;
    strarray_append(&inboxes, ru->old_inboxid);
    json_object_foreach(set->create, key, jarg) {
        json_t *jval = json_object_get(jarg, "role");
        if (!strcmpsafe("inbox", json_string_value(jval))) {
            if (haverights) {
                strarray_appendm(&inboxes, strconcat("#", key, NULL));
            }
            else {
                json_object_set_new(set->not_created, key,
                        json_pack("{s:s}", "type", "forbidden"));
            }
        }
    }
    json_object_foreach(set->update, key, jarg) {
        json_t *jval = json_object_get(jarg, "role");
        if (!strcmpsafe("inbox", json_string_value(jval))) {
            if (haverights) {
                strarray_append(&inboxes, key);
            }
            else {
                json_object_set_new(set->not_updated, key,
                        json_pack("{s:s}", "type", "forbidden"));
            }
        }
        else if (json_is_null(jval)) {
            if (haverights) {
                strarray_remove_all(&inboxes, key);
            }
            else {
                json_object_set_new(set->not_updated, key,
                        json_pack("{s:s}", "type", "forbidden"));
            }
        }
    }
    json_array_foreach(set->destroy, i, jarg) {
        if (!strcmpsafe(ru->old_inboxid, json_string_value(jarg))) {
            if (haverights) {
                strarray_remove_all(&inboxes, ru->old_inboxid);
            }
            else {
                json_object_set_new(set->not_destroyed, key,
                        json_pack("{s:s}", "type", "forbidden"));
            }
        }
    }

    if (strarray_size(&inboxes) > 1) {
        json_object_foreach(set->create, key, jarg) {
            if (json_object_get(set->not_created, key)) {
                continue;
            }
            json_t *jval = json_object_get(jarg, "role");
            if (!strcmpsafe("inbox", json_string_value(jval))) {
                json_object_set_new(set->not_created, key,
                        json_pack("{s:s s:[s]}",
                            "type", "invalidProperties", "properties", "role"));
            }
        }
        json_object_foreach(set->update, key, jarg) {
            if (json_object_get(set->not_updated, key)) {
                continue;
            }
            json_t *jval = json_object_get(jarg, "role");
            if (!strcmpsafe("inbox", json_string_value(jval))) {
                json_object_set_new(set->not_updated, key,
                        json_pack("{s:s s:[s]}",
                            "type", "invalidProperties", "properties", "role"));
            }
        }
    }
    else if (strarray_size(&inboxes) == 1) {
        ru->new_inboxid = strarray_pop(&inboxes);
        if (!strcmp(ru->old_inboxid, ru->new_inboxid)) {
            free(ru->new_inboxid);
            ru->new_inboxid = NULL;
        }
    }
    strarray_fini(&inboxes);

    free(calhomename);
    return 0;
}

static int roleupdate_pickany_inboxid_cb(const mbentry_t *mbentry, void *rock)
{
    int r = 0;
    if (mbentry->mbtype & MBTYPE_CALENDAR) {
        mbname_t *mbname = mbname_from_intname(mbentry->name);
        if (!jmap_calendar_isspecial(mbname)) {
            char **new_inboxidptr = rock;
            *new_inboxidptr = mbname_pop_boxes(mbname);
            r = CYRUSDB_DONE;
        }
        mbname_free(&mbname);
    }
    return r;
}

static int roleupdate_exec(jmap_req_t *req,
                           struct jmap_set *set,
                           struct roleupdate *ru)
{
    if (!ru->old_inboxid) return 0;

    /* Lock calendar home */
    struct mailbox *calhome = NULL;
    int r = 0;
    {
        char *calhomename = caldav_mboxname(req->accountid, NULL);
        r = jmap_openmbox(req, calhomename, &calhome, 1);
        free(calhomename);
    }
    if (r) return r;

    char *new_inboxid = xstrdupnull(ru->new_inboxid);

    if (new_inboxid) {
        if (new_inboxid[0] == '#') {
            const char *tmp = jmap_lookup_id(req, new_inboxid + 1);
            free(new_inboxid);
            new_inboxid = xstrdupnull(tmp);
        }
        else if (!json_object_get(set->updated, new_inboxid)) {
            free(new_inboxid);
            new_inboxid = NULL;
        }
    }

    if (!new_inboxid) {
        /* Try to keep the old inbox */
        char *mboxname = caldav_mboxname(req->accountid, ru->old_inboxid);
        mbentry_t *mbentry = NULL;
        if (!mboxlist_lookup(mboxname, &mbentry, NULL) && mbentry->mbtype != MBTYPE_DELETED) {
            mbname_t *mbname = mbname_from_intname(mbentry->name);
            new_inboxid = mbname_pop_boxes(mbname);
            mbname_free(&mbname);
        }
        mboxlist_entry_free(&mbentry);
        free(mboxname);
    }
    if (!new_inboxid) {
        /* Try to use the Cyrus default */
        char *mboxname = caldav_mboxname(req->accountid, SCHED_DEFAULT);
        mbentry_t *mbentry = NULL;
        if (!mboxlist_lookup(mboxname, &mbentry, NULL) && mbentry->mbtype != MBTYPE_DELETED) {
            mbname_t *mbname = mbname_from_intname(mbentry->name);
            new_inboxid = mbname_pop_boxes(mbname);
            mbname_free(&mbname);
        }
        mboxlist_entry_free(&mbentry);
        free(mboxname);
    }
    if (!new_inboxid) {
        /* Pick any */
        mboxlist_mboxtree(mailbox_name(calhome), roleupdate_pickany_inboxid_cb,
                          &new_inboxid, MBOXTREE_SKIP_ROOT);
    }
    if (!new_inboxid) {
        xsyslog(LOG_WARNING, "cannot pick new scheduling default", "user=<%s>",
                req->accountid);
        r = 0;
        goto done;
    }

    const char *annotname =
        DAV_ANNOT_NS "<" XML_NS_CALDAV ">schedule-default-calendar";

    annotate_state_t *calhomeastate = NULL;
    r = mailbox_get_annotate_state(calhome, 0, &calhomeastate);
    if (!r) {
        struct buf buf = BUF_INITIALIZER;
        buf_setcstr(&buf, new_inboxid);
        r = annotate_state_writemask(calhomeastate, annotname, req->userid, &buf);
        buf_free(&buf);
    }
    if (r) {
        syslog(LOG_ERR, "IOERROR: %s: failed to set scheduling default %s for %s: %s",
                __FILE__, new_inboxid, req->accountid, error_message(r));
        goto done;
    }

done:
    jmap_closembox(req, &calhome);
    free(new_inboxid);
    return r;
}

static int jmap_calendar_set(struct jmap_req *req)
{
    struct mboxlock *namespacelock = user_namespacelock(req->accountid);
    struct jmap_parser argparser = JMAP_PARSER_INITIALIZER;
    struct roleupdate roleupdate = JMAP_CALENDARS_ROLEUPDATE_INITIALIZER;
    struct jmap_set set;
    int on_destroy_remove_events = 0;
    json_t *err = NULL;
    int r = 0;

    /* Parse arguments */
    jmap_set_parse(req, &argparser, calendar_props, setcalendars_parse_args,
                   &on_destroy_remove_events, &set, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    if (set.if_in_state) {
        /* TODO rewrite state function to use char* not json_t* */
        json_t *jstate = json_string(set.if_in_state);
        if (jmap_cmpstate(req, jstate, MBTYPE_CALENDAR)) {
            jmap_error(req, json_pack("{s:s}", "type", "stateMismatch"));
            json_decref(jstate);
            goto done;
        }
        json_decref(jstate);
        set.old_state = xstrdup(set.if_in_state);
    }
    else {
        json_t *jstate = jmap_getstate(req, MBTYPE_CALENDAR, /*refresh*/0);
        set.old_state = xstrdup(json_string_value(jstate));
        json_decref(jstate);
    }

    r = caldav_create_defaultcalendars(req->accountid,
                                       &httpd_namespace, httpd_authstate, NULL);
    if (r == IMAP_MAILBOX_NONEXISTENT) {
        /* The account exists but does not have a root mailbox. */
        json_t *err = json_pack("{s:s}", "type", "accountNoCalendars");
        json_array_append_new(req->response, json_pack("[s,o,s]",
                    "error", err, req->tag));
        r = 0;
        goto done;
    }
    if (r) {
        goto done;
    }

    r = roleupdate_plan(req, &set, &roleupdate);
    if (r) goto done;

    /* create */
    const char *key;
    json_t *arg;
    json_object_foreach(set.create, key, arg) {
        if (json_object_get(set.not_created, key)) {
            continue;
        }
        if (!strlen(key)) {
            json_t *err= json_pack("{s:s}", "type", "invalidArguments");
            json_object_set_new(set.not_created, key, err);
            continue;
        }
        if (json_object_get(set.not_created, key)) {
            continue;
        }
        json_t *record = NULL, *err = NULL;
        setcalendars_create(req, key, arg, &record, &err);
        if (!err) {
            json_object_set_new(set.created, key, record);
        }
        else json_object_set_new(set.not_created, key, err);
    }

    /* update */
    const char *id;
    json_object_foreach(set.update, id, arg) {
        if (json_object_get(set.not_updated, id)) {
            continue;
        }
        const char *calid = id;
        if (calid && calid[0] == '#') {
            const char *newcalid = jmap_lookup_id(req, calid + 1);
            if (!newcalid) {
                json_object_set_new(set.not_updated, id,
                        json_pack("{s:s}", "type", "notFound"));
                continue;
            }
            calid = newcalid;
        }
        json_t *record = NULL, *err = NULL;
        setcalendars_update(req, calid, arg, &record, &err);
        if (!err) {
            json_object_set_new(set.updated, id, record);
        }
        else json_object_set_new(set.not_updated, id, err);
    }

    /* destroy */
    size_t index;
    json_t *jid;

    json_array_foreach(set.destroy, index, jid) {
        const char *id = json_string_value(jid);
        if (json_object_get(set.not_destroyed, id)) {
            continue;
        }
        /* Resolve calid */
        const char *calid = id;
        if (calid && calid[0] == '#') {
            const char *newcalid = jmap_lookup_id(req, calid + 1);
            if (!newcalid) {
                json_t *err = json_pack("{s:s}", "type", "notFound");
                json_object_set_new(set.not_destroyed, id, err);
                continue;
            }
            calid = newcalid;
        }
        json_t *err = NULL;
        setcalendars_destroy(req, calid, on_destroy_remove_events, &err);
        if (!err) {
            json_array_append_new(set.destroyed, json_string(id));
        }
        else json_object_set_new(set.not_destroyed, id, err);
    }

    r = roleupdate_exec(req, &set, &roleupdate);
    if (r) goto done;

    // TODO refactor jmap_getstate to return a string, once
    // all code has been migrated to the new JMAP parser.
    json_t *jstate = jmap_getstate(req, MBTYPE_CALENDAR, /*refresh*/1);
    set.new_state = xstrdup(json_string_value(jstate));
    json_decref(jstate);

    jmap_ok(req, jmap_set_reply(&set));

done:
    roleupdate_fini(&roleupdate);
    mboxname_release(&namespacelock);
    jmap_parser_fini(&argparser);
    jmap_set_fini(&set);
    return r;
}

struct calendarevent_getblob_rock {
    const char *boundary;
    struct buf *buf;
};

static int _calendarevent_getblob_cb(const char *mailbox __attribute__((unused)),
                                     uint32_t uid __attribute__((unused)),
                                     const char *entry __attribute__((unused)),
                                     const char *userid,
                                     const struct buf *value,
                                     const struct annotate_metadata *mdata __attribute__((unused)),
                                     void *vrock)
{
    if (!buf_len(value)) return 0;

    struct calendarevent_getblob_rock *rock = vrock;
    struct buf *buf = rock->buf;

    /* Parse the value and fetch the patch */
    struct dlist *dl;
    const char *vpatchstr = NULL;
    dlist_parsemap(&dl, 1, 0, buf_base(value), buf_len(value));
    dlist_getatom(dl, "VPATCH", &vpatchstr);
    if (vpatchstr) {
        /* Write VPATCH blob */
        buf_printf(buf, "\r\n--%s\r\n", rock->boundary);
        buf_appendcstr(buf, "Content-Type: text/calendar; component=VPATCH\r\n");
        buf_printf(buf, "Content-Length: %zu\r\n", strlen(vpatchstr));
        if (userid) buf_printf(buf, "X-UserId: %s\r\n", userid);
        buf_appendcstr(buf, "\r\n");
        buf_appendcstr(buf, vpatchstr);
    }

    dlist_free(&dl);
    return 0;
}

/* Fetch a specific MIME parameter from a list */
static const char *get_param(struct param *params, const char *attrib)
{
    struct param *p;

    for (p = params; p && strcasecmp(p->attribute, attrib); p = p->next);

    return (p ? p->value : NULL);
}

static int jmap_calendarevent_getblob(jmap_req_t *req, jmap_getblob_context_t *ctx)
{
    struct mailbox *mailbox = NULL;
    icalcomponent *ical = NULL;
    char *mboxid = NULL;
    char *userid = NULL;
    uint32_t uid;
    int res = HTTP_OK;
    mbentry_t *freeme = NULL;
    int r;

    if (ctx->blobid[0] != 'I') return 0;

    if (!jmap_decode_rawdata_blobid(ctx->blobid, &mboxid, &uid,
                                    &userid, NULL, NULL)) {
        res = HTTP_BAD_REQUEST;
        goto done;
    }

    /* Validate user id */
    if ((userid && strcmp(userid, req->userid)) || (!userid && (!httpd_userisadmin))) {
        res = HTTP_NOT_FOUND;
        goto done;
    }

    const mbentry_t *mbentry;
    if (ctx->from_accountid) {
        mboxlist_lookup_by_uniqueid(mboxid, &freeme, NULL);
        mbentry = freeme;
    }
    else {
        mbentry = jmap_mbentry_by_uniqueid(req, mboxid);
    }
    if (!jmap_hasrights_mbentry(req, mbentry, JACL_READITEMS)) {
        res = HTTP_NOT_FOUND;
        goto done;
    }

    /* Open mailbox, we need it now */
    if ((r = jmap_openmbox(req, mbentry->name, &mailbox, 0))) {
        ctx->errstr = error_message(r);
        res = HTTP_SERVER_ERROR;
        goto done;
    }

    /* Make sure client can handle blob type. */
    if (ctx->accept_mime) {
        if (userid) {
            if (strcmp(ctx->accept_mime, "application/octet-stream") &&
                strcmp(ctx->accept_mime, "text/calendar")) {
                res = HTTP_NOT_ACCEPTABLE;
                goto done;
            }
        }
        else if (strcmp(ctx->accept_mime, "multipart/mixed")) {
            res = HTTP_NOT_ACCEPTABLE;
            goto done;
        }
    }

    /* Load iCalendar data */
    const char *comp_type = NULL;
    struct body *body = NULL;
    struct index_record record;
    if (!mailbox_find_index_record(mailbox, uid, &record) &&
        !mailbox_cacherecord(mailbox, &record)) {

        message_read_bodystructure(&record, &body);

        comp_type = get_param(body->params, "COMPONENT");

        if (userid) {
            /* Fetch ical resource with personalized data */
            struct caldav_data cdata = {
                .dav.imap_uid = record.uid,
                .comp_flags.shared =
                    !strcasecmpsafe(get_param(body->disposition_params,
                                              "PER-USER-DATA"), "TRUE")
            };

            ical = caldav_record_to_ical(mailbox, &cdata, req->userid, NULL);
        }
        else {
            /* Fetch ical resource without personalized data */
            ical = record_to_ical(mailbox, &record, NULL);
        }
    }
    if (!ical) {
        ctx->errstr = "failed to load record";
        res = HTTP_SERVER_ERROR;
        goto done;
    }

    if (userid) {
        /* Set Content headers */
        if (!ctx->accept_mime || !strcmp(ctx->accept_mime, "text/calendar")) {
            buf_setcstr(&ctx->content_type, "text/calendar");
            if (comp_type)
                buf_printf(&ctx->content_type, "; component=%s", comp_type);
        }

        /* Write body */
        buf_setcstr(&ctx->blob, icalcomponent_as_ical_string(ical));
    }
    else {
        /* Create multipart body */
        const char *preamble =
            "This is a message with multiple parts in MIME format.\r\n";
        const char *epilogue = "\r\nEnd of MIME multipart body.\r\n";
        char boundary[100];
        struct buf *blob = &ctx->blob;

        snprintf(boundary, sizeof(boundary), "%s-%ld-%ld-%ld",
                 *spool_getheader(req->txn->req_hdrs, ":authority"),
                 (long) getpid(), (long) time(0), (long) rand());

        buf_reset(&ctx->content_type);
        buf_printf(&ctx->content_type,
                "multipart/mixed; boundary=\"%s\"", boundary);

        buf_setcstr(blob, preamble);

        /* Write main component body */
        buf_printf(blob, "\r\n--%s\r\n", boundary);
        buf_appendcstr(blob, "Content-Type: text/calendar");
        
        if (comp_type) buf_printf(blob, "; component=%s", comp_type);
        buf_appendcstr(blob, "\r\n");

        const char *icalstr = icalcomponent_as_ical_string(ical);
        buf_printf(blob, "Content-Length: %zu\r\n", strlen(icalstr));
        buf_appendcstr(blob, "\r\n");
        buf_appendcstr(blob, icalstr);

        /* Write userdata parts */
        struct calendarevent_getblob_rock rock = { boundary, blob };
        annotatemore_findall_mailbox(mailbox, uid, PER_USER_CAL_DATA, 0,
                                     _calendarevent_getblob_cb, &rock, 0);

        /* Write close-delimiter and epilogue */
        buf_printf(blob, "\r\n--%s--\r\n%s", boundary, epilogue);
    }

    buf_setcstr(&ctx->encoding, "8BIT");

    message_free_body(body);
    free(body);

done:
    if (res != HTTP_OK && !ctx->errstr) {
        const char *desc = NULL;
        switch (res) {
            case HTTP_BAD_REQUEST:
                desc = "invalid calendar event blobid";
                break;
            case HTTP_NOT_FOUND:
                desc = "failed to find blob by calendar blobid";
                break;
            default:
                desc = error_message(res);
        }
        ctx->errstr = desc;
    }
    if (ical) icalcomponent_free(ical);
    if (mailbox) jmap_closembox(req, &mailbox);
    mboxlist_entry_free(&freeme);
    free(mboxid);
    free(userid);
    return res;
}

struct event_id {
    const char *raw; /* as requested by client */
    char *uid;
    char *recurid;
};

/* Return NULL if id is neither a simple UID or structured id */
static struct event_id *parse_eventid(const char *id)
{
    struct event_id *eid = xzmalloc(sizeof(struct event_id));
    const char *p;

    if ((p = strchr(id, ';')) == NULL) {
        eid->raw = id;
        eid->uid = xstrdup(id);
        return eid;
    }
    if (*p + 1 == '\0') {
        free(eid);
        return NULL;
    }
    eid->raw = id;
    eid->uid = xstrndup(id, p - id);
    eid->recurid = xstrdup(p + 1);

    return eid;
}

static void free_eventid(struct event_id **eidptr)
{
    if (eidptr == NULL || *eidptr == NULL) return;

    struct event_id *eid = *eidptr;
    free(eid->uid);
    free(eid->recurid);
    free(eid);
    *eidptr = NULL;
}

struct getcalendarevents_rock {
    struct caldav_db *db;
    struct jmap_req *req;
    struct jmap_get *get;
    struct mailbox *mailbox;
    mbentry_t *mbentry;
    mbname_t *mbname;
    hashu64_table jmapcache;
    ptrarray_t *want_eventids;
    int check_acl;
    const char *sched_inboxname;
    const char *sched_outboxname;
    hash_table floatingtz_by_mboxid;
    ptrarray_t malloced_fallbacktzs;
    struct jmapical_datetime overrides_before;
    struct jmapical_datetime overrides_after;
    int reduce_participants;
};

struct recurid_instanceof_rock {
    icaltimetype recurid;
    int found;
};

static int _recurid_instanceof_cb(icalcomponent *comp __attribute__((unused)),
                                  icaltimetype start,
                                  icaltimetype end __attribute__((unused)),
                                  void *vrock)
{
    struct recurid_instanceof_rock *rock = vrock;
    struct icaltimetype recurid = rock->recurid;

    if (start.is_date && !recurid.is_date) {
        start.is_date = 0;
        start.hour = 0;
        start.minute = 0;
        start.second = 0;
    }
    else if (!start.is_date && recurid.is_date) {
        recurid.is_date = 0;
        recurid.hour = 0;
        recurid.minute = 0;
        recurid.second = 0;
    }

    int cmp = icaltime_compare(start, recurid);
    if (cmp == 0) {
        rock->found = 1;
    }
    return cmp < 0;
}

static int _recurid_is_instanceof(icaltimetype recurid, icalcomponent *ical, int rrule_only)
{
    icaltimetype tstart = recurid;
    icaltime_adjust(&tstart, -1, 0, 0, 0);
    icaltimetype tend = recurid;
    icaltime_adjust(&tend, 1, 0, 0, 0);
    struct icalperiodtype timerange = {
        tstart, tend, icaldurationtype_null_duration()
    };
    struct recurid_instanceof_rock rock = { recurid, 0 };
    icalcomponent *mycomp = NULL;

    if (rrule_only) {
        if (icalcomponent_isa(ical) == ICAL_VCALENDAR_COMPONENT) {
            /* Find the master component */
            icalcomponent *comp = icalcomponent_get_first_real_component(ical);
            icalcomponent_kind kind = icalcomponent_isa(comp);
            icalcomponent *mastercomp = NULL;

            for (; comp; comp = icalcomponent_get_next_component(ical, kind)) {
                if (!icalcomponent_get_first_property(comp, ICAL_RECURRENCEID_PROPERTY)) {
                    mastercomp = comp;
                    break;
                }
            }
            if (!mastercomp) {
                return 0;
            }
            ical = mastercomp;
        }
        if (icalcomponent_get_first_property(ical, ICAL_RDATE_PROPERTY)) {
            /* Remove RDATEs */
            mycomp = icalcomponent_clone(ical);
            icalproperty *next;
            icalproperty *prop = icalcomponent_get_first_property(mycomp, ICAL_RDATE_PROPERTY);
            for ( ; prop; prop = next) {
                next = icalcomponent_get_next_property(mycomp, ICAL_RDATE_PROPERTY);
                icalcomponent_remove_property(mycomp, prop);
                icalproperty_free(prop);
            }
            ical = mycomp;
        }
    }

    icalcomponent_myforeach(ical, timerange, NULL, _recurid_instanceof_cb, &rock);
    int found = rock.found;
    if (mycomp) icalcomponent_free(mycomp);
    return found;
}

static void getcalendarevents_get_utctimes_internal(json_t *jsevent,
                                                    const char *startstr,
                                                    const char *durstr,
                                                    const char *jstzid,
                                                    jstimezones_t *jstzones,
                                                    icaltimezone *floatingtz)
{
    icaltimezone *utc = icaltimezone_get_utc_timezone();

    /* Read start */
    struct jmapical_datetime startdt = JMAPICAL_DATETIME_INITIALIZER;
    if (jmapical_localdatetime_from_string(startstr, &startdt) == -1) return;

    /* Read timeZone */
    icaltimezone *tz = NULL;
    if (jstzid) {
        tz = jstimezones_lookup_tzid(jstzones, jstzid);
    }
    if (!tz) tz = floatingtz;
    if (!tz) tz = utc;

    /* Read duration */
    struct jmapical_duration dur = JMAPICAL_DURATION_INITIALIZER;
    if (durstr && jmapical_duration_from_string(durstr, &dur) == -1) return;

    /* Determine end */
    struct jmapical_datetime enddt = JMAPICAL_DATETIME_INITIALIZER;
    icaltimetype startical = jmapical_datetime_to_icaltime(&startdt, tz);
    struct icaldurationtype durical = jmapical_duration_to_icalduration(&dur);
    icaltimetype endical = icaltime_add(startical, durical);
    if (startdt.nano + dur.nanos >= 1000000000) {
        endical = icaltime_add(endical, icaldurationtype_from_int(1));
        jmapical_datetime_from_icaltime(endical, &enddt);
        enddt.nano = (startdt.nano + dur.nanos) - 1000000000;
    }
    else {
        jmapical_datetime_from_icaltime(endical, &enddt);
        enddt.nano = startdt.nano + dur.nanos;
    }

    /* Convert start and end to UTC */
    if (tz != utc) {
        icaltimetype icalloc = jmapical_datetime_to_icaltime(&startdt, tz);
        icaltimetype icalutc = icaltime_convert_to_zone(icalloc, utc);
        bit64 nano = startdt.nano;
        jmapical_datetime_from_icaltime(icalutc, &startdt);
        startdt.nano = nano;

        icalloc = jmapical_datetime_to_icaltime(&enddt, tz);
        icalutc = icaltime_convert_to_zone(icalloc, utc);
        nano = enddt.nano;
        jmapical_datetime_from_icaltime(icalutc, &enddt);
        enddt.nano = nano;
    }

    /* Set utcStart, utcEnd */
    struct buf buf = BUF_INITIALIZER;
    jmapical_utcdatetime_as_string(&startdt, &buf);
    json_object_set_new(jsevent, "utcStart", json_string(buf_cstring(&buf)));
    jmapical_utcdatetime_as_string(&enddt, &buf);
    json_object_set_new(jsevent, "utcEnd", json_string(buf_cstring(&buf)));
    buf_free(&buf);
}

static void getcalendarevents_get_utctimes(json_t *jsevent,
                                           jstimezones_t *jstzones,
                                           icaltimezone *floatingtz)
{
    const char *start = json_string_value(json_object_get(jsevent, "start"));
    const char *dur = json_string_value(json_object_get(jsevent, "duration"));
    const char *jstzid = json_string_value(json_object_get(jsevent, "timeZone"));

    /* Set utcStart, utcEnd on main event */
    getcalendarevents_get_utctimes_internal(jsevent, start, dur,
            jstzid, jstzones, floatingtz);

    /* Set utcStart, utcEnd on recurrence overrides, if any */
    json_t *joverrides = json_object_get(jsevent, "recurrenceOverrides");
    if (JNOTNULL(joverrides)) {
        const char *recurid;
        json_t *jovr;
        json_object_foreach(joverrides, recurid, jovr) {
            const char *startovr = json_string_value(json_object_get(jovr, "start"));
            if (!startovr) startovr = recurid;
            const char *durovr = json_string_value(json_object_get(jovr, "duration"));
            if (!durovr) durovr = dur;
            const char *jstzidovr = json_string_value(json_object_get(jovr, "timeZone"));
            if (!jstzidovr) jstzidovr = jstzid;
            getcalendarevents_get_utctimes_internal(jovr, startovr, durovr,
                                                    jstzidovr, jstzones, floatingtz);
        }
    }
}

static void getcalendarevents_filterinstance(json_t *myevent,
                                             hash_table *props,
                                             const char *id,
                                             const char *ical_uid)
{
    json_object_del(myevent, "recurrenceOverrides");
    json_object_del(myevent, "recurrenceRules");
    json_object_del(myevent, "excludedRecurrenceRules");
    jmap_filterprops(myevent, props);
    json_object_set_new(myevent, "id", json_string(id));
    json_object_set_new(myevent, "uid", json_string(ical_uid));
    json_object_set_new(myevent, "@type", json_string("JSEvent"));
}

static int getcalendarevents_getinstances(json_t *jsevent,
                                           struct caldav_data *cdata,
                                           icalcomponent *ical,
                                           jstimezones_t *jstzones,
                                           icaltimezone *floatingtz,
                                           struct getcalendarevents_rock *rock)
{
    jmap_req_t *req = rock->req;
    hash_table *props = rock->get->props;
    icalcomponent *myical = NULL;
    mbentry_t *mbentry = jmap_mbentry_from_dav(req, &cdata->dav);
    int r = 0;

    int i;
    for (i = 0; i < ptrarray_size(rock->want_eventids); i++) {
        struct event_id *eid = ptrarray_nth(rock->want_eventids, i);
        if (eid->recurid == NULL) continue;

        /* Client requested event recurrence instance */
        json_t *override = json_object_get(
                json_object_get(jsevent, "recurrenceOverrides"), eid->recurid);
        if (override) {
            if (json_object_get(override, "excluded") != json_true()) {
                /* Instance is a recurrence override */
                json_t *myevent = jmap_patchobject_apply(jsevent, override, NULL);
                getcalendarevents_filterinstance(myevent, props, eid->raw, cdata->ical_uid);
                if (json_object_get(override, "start") == NULL) {
                    json_object_set_new(myevent, "start", json_string(eid->recurid));
                }
                json_object_set_new(myevent, "recurrenceId", json_string(eid->recurid));
                json_array_append_new(rock->get->list, myevent);
            }
            else {
                /* Instance is excluded */
                json_array_append_new(rock->get->not_found, json_string(eid->raw));
            }
        }
        else {
            /* Check if RRULE generates an instance at this timestamp */
            if (!ical) {
                /* Open calendar mailbox. */
                if (!rock->mailbox || strcmp(mailbox_name(rock->mailbox), mbentry->name)) {
                    jmap_closembox(req, &rock->mailbox);
                    r = jmap_openmbox(req, mbentry->name, &rock->mailbox, 0);
                    if (r) goto done;
                }
                myical = caldav_record_to_ical(rock->mailbox, cdata, req->userid, NULL);
                if (!myical) {
                    syslog(LOG_ERR, "caldav_record_to_ical failed for record %u:%s",
                            cdata->dav.imap_uid, mailbox_name(rock->mailbox));
                    json_array_append_new(rock->get->not_found, json_string(eid->raw));
                    continue;
                }
                else ical = myical;
            }
            struct jmapical_datetime timestamp = JMAPICAL_DATETIME_INITIALIZER;
            if (jmapical_localdatetime_from_string(eid->recurid, &timestamp) < 0) {
                json_array_append_new(rock->get->not_found, json_string(eid->raw));
                continue;
            }
            icaltimetype icalrecurid = jmapical_datetime_to_icaltime(&timestamp, NULL);
            if (!_recurid_is_instanceof(icalrecurid, ical, 1/*rrule_only*/)) {
                json_array_append_new(rock->get->not_found, json_string(eid->raw));
                continue;
            }

            /* Build instance */
            struct buf buf = BUF_INITIALIZER;
            jmapical_localdatetime_as_string(&timestamp, &buf);
            json_t *jstart = json_string(buf_cstring(&buf));
            buf_free(&buf);

            json_t *myevent = json_deep_copy(jsevent);
            json_object_set_new(myevent, "start", jstart);
            if (jmap_wantprop(props, "utcStart") || jmap_wantprop(props, "utcEnd")) {
                getcalendarevents_get_utctimes(myevent, jstzones, floatingtz);
            }
            getcalendarevents_filterinstance(myevent, props, eid->raw, cdata->ical_uid);
            json_object_set_new(myevent, "recurrenceId", json_string(eid->recurid));
            json_array_append_new(rock->get->list, myevent);
        }
    }

done:
    if (myical) icalcomponent_free(myical);
    mboxlist_entry_free(&mbentry);
    return r;
}

static icaltimezone *calendarevent_get_floatingtz(const mbentry_t *mbentry,
                                                  const char *userid,
                                                  int *is_malloced)
{
    struct buf buf = BUF_INITIALIZER;
    icaltimezone *tz = NULL;
    *is_malloced = 0;

    static const char *tzid_annot =
        DAV_ANNOT_NS "<" XML_NS_CALDAV ">calendar-timezone-id";
    static const char *tz_annot =
        DAV_ANNOT_NS "<" XML_NS_CALDAV ">calendar-timezone";

    annotatemore_lookupmask_mbe(mbentry, tzid_annot, userid, &buf);

    if (buf_len(&buf)) {
        tz = icaltimezone_get_cyrus_timezone_from_tzid(buf_cstring(&buf));
        buf_reset(&buf);
    }
    if (!tz) {
        annotatemore_lookupmask_mbe(mbentry, tz_annot, userid, &buf);
        if (buf_len(&buf)) {
            icalcomponent *ical = icalparser_parse_string(buf_cstring(&buf));
            if (ical && icalcomponent_isa(ical) == ICAL_VCALENDAR_COMPONENT) {
                icalcomponent *comp =
                    icalcomponent_get_first_component(ical, ICAL_VTIMEZONE_COMPONENT);
                if (comp) {
                    tz = icaltimezone_new();
                    *is_malloced = 1;
                    icaltimezone_set_component(tz, icalcomponent_clone(comp));
                }
            }
            if (ical) icalcomponent_free(ical);
            buf_reset(&buf);
        }
    }
    /* XXX - read from DAV_ANNOT_NS "<" XML_NS_CALDAV ">calendar-timezone" ? */
    /* XXX - how to convert VTIMEZONE to icaltimezone* ? */
    if (!tz) tz = icaltimezone_get_utc_timezone();

    buf_free(&buf);
    return tz;
}

struct jmapcontext_rock {
    jmap_req_t *req;
    /* Fields required for Link.blobId */
    struct buf davbaseurl;
    const char *davproto;
    const char *davhost;
    struct webdav_db *webdavdb;
    struct mailbox *davattachments;
};

static void jmapcontext_blobid_from_href(struct buf *blobid,
                                         const char *href,
                                         const char *managedid,
                                         void *vrock)
{
    struct jmapcontext_rock *rock = vrock;
    const struct buf *baseurl = &rock->davbaseurl;

    buf_reset(blobid);

    if (strncmpsafe(href, baseurl->s, baseurl->len)) {
        /* HREF doesn't match base url for DAV attachments */
        return;
    }
    const char *mid = href + baseurl->len;

    if (*mid == '\0' || (managedid && strcmp(managedid, mid))) {
        /* MANAGED-ID and resource id differ - invalid blobId */
        return;
    }

    /* JMAP blob handler expects G blob-ids */
    buf_putc(blobid, 'G');
    buf_appendcstr(blobid, mid);
}

static int copyblob(jmap_req_t *req, const char *blobid, struct mailbox *dstmbox)
{
    msgrecord_t *mr = NULL;
    struct mailbox *srcmbox = NULL;
    struct body *srcbody = NULL;
    const struct body *srcpart = NULL;
    struct body *dstbody = NULL;
    struct buf blob = BUF_INITIALIZER;
    struct stagemsg *stage = NULL;
    time_t internaldate = time(NULL);
    struct appendstate as;

    /* Lookup blob */
    int r = jmap_findblob(req, NULL, blobid, &srcmbox, &mr, &srcbody, &srcpart, &blob);
    if (r) goto done;

    /* Write blob to file */
    const char *blob_base = srcpart ? blob.s + srcpart->header_offset : blob.s;
    size_t size = srcpart ? srcpart->header_size + srcpart->content_size : blob.len;
    FILE *fp = append_newstage(mailbox_name(dstmbox), time(NULL), 0, &stage);
    if (!fp) {
        syslog(LOG_ERR, "%s: append_newstage(%s) failed", __func__, mailbox_name(dstmbox));
        r = IMAP_INTERNAL;
        goto done;
    }
    fwrite(blob_base, size, 1, fp);
    if (ferror(fp)) {
        syslog(LOG_ERR, "%s: ferror(%s): %s", __func__,
                append_stagefname(stage), strerror(errno));
        r = IMAP_IOERROR;
        fclose(fp);
        goto done;
    }
    fclose(fp);

    /* Append blob to mailbox */
    r = append_setup_mbox(&as, dstmbox, req->userid, httpd_authstate, 0, NULL, 0, 0, 0);
    if (r) goto done;

    strarray_t flags = STRARRAY_INITIALIZER;
    r = append_fromstage(&as, &dstbody, stage, 0,
                         internaldate, &flags, 0, NULL);
	if (r)
        append_abort(&as);
    else
        append_commit(&as);

done:
    if (stage) append_removestage(stage);
	if (dstbody) {
        message_free_body(dstbody);
        free(dstbody);
    }
    if (srcbody) {
        message_free_body(srcbody);
        free(srcbody);
    }
    jmap_closembox(req, &srcmbox);
    msgrecord_unref(&mr);
    buf_free(&blob);
    return r;
}


static void jmapcontext_href_from_blobid(struct buf *href,
                                         struct buf *managedid,
                                         const char *blobid,
                                         void *vrock)
{
    struct jmapcontext_rock *rock = vrock;
    jmap_req_t *req = rock->req;
    buf_reset(href);
    buf_reset(managedid);

    if (!rock->davattachments) {
        // Lazily open DAV attachment when we need it.
        char *mboxname = caldav_mboxname(req->accountid, MANAGED_ATTACH);
        int r = jmap_openmbox(req, mboxname, &rock->davattachments, /*rw*/1);
        if (r) {
            syslog(LOG_ERR, "%s: can't open %s: %s",
                    __func__, mboxname, error_message(r));
        }
        free(mboxname);
        if (r) return;
    }

    if (!rock->webdavdb) {
        // (Re)open WebDAV attachments DB.
        rock->webdavdb = mailbox_open_webdav(rock->davattachments);
        if (!rock->webdavdb) {
            syslog(LOG_ERR, "%s: mailbox_open_webdav(%s) failed",
                    __func__, mailbox_name(rock->davattachments));
            return;
        }
    }

    // Check if blob exists in WebDAV attachments
    const char *mid = *blobid == 'G' ? blobid + 1 : blobid;
    struct webdav_data *wdata;
    int r = webdav_lookup_uid(rock->webdavdb, mid, &wdata);
    if (r && r != CYRUSDB_NOTFOUND) {
        syslog(LOG_ERR, "%s: webdav_lookup_uid(%s) failed: %s",
                __func__, mid, cyrusdb_strerror(r));
        return;
    }
    if (r == CYRUSDB_NOTFOUND) {
        // Copy blob from JMAP blobs to managed attachments
        r = copyblob(req, blobid, rock->davattachments);
        if (r) {
            syslog(LOG_ERR, "jmap: copyblob(%s): %s",
                    blobid, error_message(r));
            return;
        }
    }

    // Set the blob href and managed-id.
    caldav_attachment_url(href, req->accountid,
            rock->davproto, rock->davhost, mid);
    buf_setcstr(managedid, mid);
}

HIDDEN void jmap_calendarcontext_init(struct jmapical_jmapcontext *ctx, jmap_req_t *req)
{
    memset(ctx, 0, sizeof(struct jmapical_jmapcontext));

    struct jmapcontext_rock *rock = xzmalloc(sizeof(struct jmapcontext_rock));
    rock->req = req;
    ctx->rock = rock;

    /* Initialize context for Link.blobId */
    const char *davproto = config_getstring(IMAPOPT_WEBDAV_ATTACHMENT_SCHEME);
    const char *davhost = config_getstring(IMAPOPT_WEBDAV_ATTACHMENT_HOST);
    if (davproto && davhost) {
        ctx->blobid_from_href = jmapcontext_blobid_from_href;
        ctx->href_from_blobid = jmapcontext_href_from_blobid;
        rock->davproto = davproto;
        rock->davhost = davhost;
        caldav_attachment_url(&rock->davbaseurl, req->accountid,
                rock->davproto, rock->davhost, "");
    }
    else {
        syslog(LOG_ERR, "%s: can't determine base URL for WebDAV attachments."
                " Disabling support for Link.blobId property. Did you configure"
                " WebDAV managed attachments in imapd.conf?", __func__);
    }

    /* Initialize context for email alerts */
    ctx->emailalert_defaultrecipient = _emailalert_defaultrecipient(req->userid);
}


HIDDEN void jmap_calendarcontext_fini(struct jmapical_jmapcontext *ctx)
{
    struct jmapcontext_rock *rock = ctx->rock;
    buf_free(&rock->davbaseurl);
    if (rock->davattachments) jmap_closembox(rock->req, &rock->davattachments);
    free(rock);
    free(ctx->emailalert_defaultrecipient);
}

static int getcalendarevents_cb(void *vrock, struct caldav_data *cdata)
{
    struct getcalendarevents_rock *rock = vrock;
    int r = 0;
    icalcomponent* ical = NULL;
    json_t *jsevent = NULL;
    jmap_req_t *req = rock->req;
    hash_table *props = rock->get->props;
    strarray_t schedule_addresses = STRARRAY_INITIALIZER;
    msgrecord_t *mr = NULL;
    jstimezones_t *jstzones = NULL;

    struct jmapical_jmapcontext jmapctx;
    jmap_calendarcontext_init(&jmapctx, req);

    if (!cdata->dav.alive)
        return 0;

    /* check that it's the right type */
    if (cdata->comp_type != CAL_COMP_VEVENT)
        return 0;

    /* Lookup mailbox entry */
    if (!rock->mbentry ||
            (cdata->dav.mailbox_byname &&
             strcmp(rock->mbentry->name, cdata->dav.mailbox)) ||
            (!cdata->dav.mailbox_byname &&
             strcmp(rock->mbentry->uniqueid, cdata->dav.mailbox))) {
        mboxlist_entry_free(&rock->mbentry);
        rock->mbentry = jmap_mbentry_from_dav(req, &cdata->dav);
        if (!rock->mbentry) {
            xsyslog(LOG_ERR, "no mbentry for mailbox",
                    "dav.mailbox=<%s> dav.mailbox_byname=<%d>",
                    cdata->dav.mailbox, cdata->dav.mailbox_byname);
            return 0;
        }
        mbname_free(&rock->mbname);
        rock->mbname = mbname_from_intname(rock->mbentry->name);
    }

    /* Check mailbox ACL rights */
    if (!rock->mbentry ||
            !jmap_hasrights_mbentry(req, rock->mbentry, JACL_READITEMS)) {
        r = 0;
        goto done;
    }
    if (!strcmpsafe(rock->mbentry->name, rock->sched_inboxname) ||
        !strcmpsafe(rock->mbentry->name, rock->sched_outboxname))
        goto done;

    /* Lookup fall-back time zone on calendar collection */
    icaltimezone *floatingtz = hash_lookup(rock->mbentry->uniqueid,
            &rock->floatingtz_by_mboxid);
    if (!floatingtz) {
        int is_malloced = 0;
        floatingtz =
            calendarevent_get_floatingtz(rock->mbentry,
                    req->userid, &is_malloced);
        hash_insert(rock->mbentry->uniqueid, floatingtz,
                &rock->floatingtz_by_mboxid);
        if (is_malloced)
            ptrarray_append(&rock->malloced_fallbacktzs, floatingtz);
    }

    int need_ical = jmap_wantprop(props, "utcStart") || jmap_wantprop(props, "utcEnd");

    if (cdata->jmapversion == JMAPCACHE_CALVERSION && !need_ical) {
        json_error_t jerr;
        jsevent = json_loads(cdata->jmapdata, 0, &jerr);
        if (jsevent) goto gotevent;
    }

    /* Open calendar mailbox. */
    if (!rock->mailbox || strcmp(mailbox_uniqueid(rock->mailbox), rock->mbentry->uniqueid)) {
        jmap_closembox(req, &rock->mailbox);
        r = jmap_openmbox_by_uniqueid(req, rock->mbentry->uniqueid, &rock->mailbox, 0);
        if (r) goto done;
    }

    /* Load message containing the resource and parse iCal data */
    ical = caldav_record_to_ical(rock->mailbox, cdata, req->userid, &schedule_addresses);
    if (!ical) {
        syslog(LOG_ERR, "caldav_record_to_ical failed for record %u:%s",
                cdata->dav.imap_uid, mailbox_name(rock->mailbox));
        r = IMAP_INTERNAL;
        goto done;
    }
    jstzones = jstimezones_new(ical);

    /* Convert to JMAP */
    jsevent = jmapical_tojmap(ical, NULL, &jmapctx);
    if (!jsevent) {
        syslog(LOG_ERR, "jmapical_tojson: can't convert %u:%s",
                cdata->dav.imap_uid, mailbox_name(rock->mailbox));
        r = IMAP_INTERNAL;
        goto done;
    }
    icalcomponent_free(ical);
    ical = NULL;

    /* Add isDraft to cached event, we remove it later if not requested */
    mr = msgrecord_from_uid(rock->mailbox, cdata->dav.imap_uid);
    if (!mr) {
        syslog(LOG_ERR, "msgrecord_from_uid failed for %s:%d",
                mailbox_name(rock->mailbox), cdata->dav.imap_uid);
        r = IMAP_INTERNAL;
        goto done;
    }
    uint32_t system_flags = 0;
    r = msgrecord_get_systemflags(mr, &system_flags);
    if (r) {
        syslog(LOG_ERR, "msgrecord_get_systemflags failed for %s:%d: %s",
                mailbox_name(rock->mailbox), cdata->dav.imap_uid, error_message(r));
        goto done;
    }
    json_object_set_new(jsevent, "isDraft", json_boolean(system_flags & FLAG_DRAFT));

    /* Add to cache */
    hashu64_insert(cdata->dav.rowid, json_dumps(jsevent, 0), &rock->jmapcache);

gotevent:

    /* Add JMAP-only fields. */
    if (jmap_wantprop(rock->get->props, "x-href")) {
        char *xhref = jmap_xhref(rock->mbentry->name, cdata->dav.resource);
        json_object_set_new(jsevent, "x-href", json_string(xhref));
        free(xhref);
    }
    if (jmap_wantprop(props, "calendarIds")) {
        const strarray_t *boxes = mbname_boxes(rock->mbname);
        json_object_set_new(jsevent, "calendarIds", json_pack("{s:b}",
                    strarray_nth(boxes, -1), 1));
    }

    unsigned want_blobId = jmap_wantprop(rock->get->props, "blobId");
    unsigned want_debugBlobId = jmap_wantprop(rock->get->props, "debugBlobId");
    if (want_blobId || want_debugBlobId) {
        struct buf blobid = BUF_INITIALIZER;

        if (want_blobId) {
            json_t *jblobid = json_null();
            if (jmap_encode_rawdata_blobid('I', rock->mbentry->uniqueid,
                    cdata->dav.imap_uid, req->userid, NULL, NULL, &blobid)) {
                jblobid = json_string(buf_cstring(&blobid));
            }
            json_object_set_new(jsevent, "blobId", jblobid);
        }
        if (want_debugBlobId) {
            json_t *jblobid = json_null();
            if (httpd_userisadmin) {
                if (jmap_encode_rawdata_blobid('I', rock->mbentry->uniqueid,
                        cdata->dav.imap_uid, NULL, NULL, NULL, &blobid)) {
                    jblobid = json_string(buf_cstring(&blobid));
                }
            }
            json_object_set_new(jsevent, "debugBlobId", jblobid);
        }

        buf_free(&blobid);
    }

    /* Set utcStart and utcEnd */
    if (jmap_wantprop(props, "utcStart") || jmap_wantprop(props, "utcEnd")) {
        getcalendarevents_get_utctimes(jsevent, jstzones, floatingtz);
    }

    /* Process recurrenceOverrides[Before,After] */
    if (!jmapical_datetime_has_zero_time(&rock->overrides_before) ||
        !jmapical_datetime_has_zero_time(&rock->overrides_after)) {

        json_t *joverrides = json_object_get(jsevent, "recurrenceOverrides");

        if (json_object_size(joverrides)) {
            const char *tzid = json_string_value(json_object_get(jsevent, "timeZone"));
            icaltimezone *utc = icaltimezone_get_utc_timezone();
            icaltimezone *tz = NULL;
            if (tzid) tz = icaltimezone_get_cyrus_timezone_from_tzid(tzid);
            if (!tz) tz = floatingtz;
            if (!tz) tz = utc;

            /* Filter overrides */
            const char *rid;
            json_t *jval;
            void *tmp;
            json_object_foreach_safe(joverrides, tmp, rid, jval) {
                struct jmapical_datetime ridt = JMAPICAL_DATETIME_INITIALIZER;
                if (jmapical_localdatetime_from_string(rid, &ridt) < 0) {
                    continue;
                }
                if (tz != utc) {
                    /* Convert recurid to UTC */
                    icaltimetype icalrid = jmapical_datetime_to_icaltime(&ridt, tz);
                    icalrid = icaltime_convert_to_zone(icalrid, utc);
                    bit64 nano = ridt.nano;
                    jmapical_datetime_from_icaltime(icalrid, &ridt);
                    ridt.nano = nano;
                }
                if (!jmapical_datetime_has_zero_time(&rock->overrides_before) &&
                        jmapical_datetime_compare(&ridt, &rock->overrides_before) >= 0) {
                    /* Remove override */
                    json_object_del(joverrides, rid);
                }
                if (!jmapical_datetime_has_zero_time(&rock->overrides_after) &&
                        jmapical_datetime_compare(&ridt, &rock->overrides_after) < 0) {
                    /* Remove override */
                    json_object_del(joverrides, rid);
                }
            }
        }
    }

    /* Remove isDraft if client didn't ask for it */
    if (!jmap_is_using(req, JMAP_URN_CALENDARS) || !jmap_wantprop(props, "isDraft")) {
        json_object_del(jsevent, "isDraft");
    }

    /* reduceParticipants */
    if (rock->reduce_participants) {
        if (strarray_size(&schedule_addresses) == 0) {
            get_schedule_addresses(NULL, rock->mbentry->name, req->userid,
                                   &schedule_addresses);
        }
        json_t *jparticipants = json_object_get(jsevent, "participants");
        const char *participant_id;
        json_t *jparticipant;
        void *tmp;
        json_object_foreach_safe(jparticipants, tmp, participant_id, jparticipant) {
            if (json_object_get(json_object_get(jparticipant, "roles"), "owner")) {
                continue;
            }
            json_t *jsendto = json_object_get(jparticipant,"sendTo");
            const char *uri = json_string_value(json_object_get(jsendto, "imip"));
            if (uri && !strncasecmp(uri, "mailto:", 7)) {
                /* XXX case-insensitive comparison of complete email addresses
                 * isn't entirely correct: only the domain is case-insensitive.
                 * But better allow false positives. */
                if (!strcasecmp(req->userid, uri + 7)) {
                    continue;
                }
                if (strarray_find_case(&schedule_addresses, uri + 7, 0) >= 0) {
                    continue;
                }
            }
            json_object_del(jparticipants, participant_id);
        }
    }

    if (rock->want_eventids == NULL) {
        /* Client requested all events */
        jmap_filterprops(jsevent, props);
        json_object_set_new(jsevent, "id", json_string(cdata->ical_uid));
        json_object_set_new(jsevent, "uid", json_string(cdata->ical_uid));
        json_object_set_new(jsevent, "@type", json_string("JSEvent"));
        json_array_append_new(rock->get->list, jsevent);
    }
    else {
        /* Expand main event, if requested */
        int i;
        for (i = 0; i < ptrarray_size(rock->want_eventids); i++) {
            struct event_id *eid = ptrarray_nth(rock->want_eventids, i);
            if (eid->recurid == NULL) {
                json_t *myevent = json_deep_copy(jsevent);
                jmap_filterprops(myevent, props);
                json_object_set_new(myevent, "id", json_string(cdata->ical_uid));
                json_object_set_new(myevent, "uid", json_string(cdata->ical_uid));
                json_object_set_new(myevent, "@type", json_string("JSEvent"));
                json_array_append_new(rock->get->list, myevent);
            }
        }
        /* Expand instances, if requested */
        r = getcalendarevents_getinstances(jsevent, cdata, ical,
                jstzones, floatingtz, rock);
        json_decref(jsevent);
        if (r) goto done;
    }

done:
    jstimezones_free(&jstzones);
    strarray_fini(&schedule_addresses);
    if (ical) icalcomponent_free(ical);
    jmap_calendarcontext_fini(&jmapctx);
    msgrecord_unref(&mr);
    return r;
}

static const jmap_property_t event_props[] = {
    {
        "id",
        NULL,
        JMAP_PROP_IMMUTABLE | JMAP_PROP_ALWAYS_GET
    },
    {
        "calendarIds",
        NULL,
        0
    },

    /* JSCalendar common properties */
    {
        "@type",
        NULL,
        0
    },
    {
        "uid",
        NULL,
        0
    },
    {
        "relatedTo",
        NULL,
        0
    },
    {
        "prodId",
        NULL,
        0
    },
    {
        "created",
        NULL,
        0
    },
    {
        "updated",
        NULL,
        0
    },
    {
        "sequence",
        NULL,
        0
    },
    {
        "method",
        NULL,
        0
    },
    {
        "title",
        NULL,
        0
    },
    {
        "description",
        NULL,
        0
    },
    {
        "descriptionContentType",
        NULL,
        0
    },
    {
        "locations",
        NULL,
        0
    },
    {
        "virtualLocations",
        NULL,
        0
    },
    {
        "links",
        NULL,
        0
    },
    {
        "locale",
        NULL,
        0
    },
    {
        "keywords",
        NULL,
        0
    },
    {
        "categories",
        NULL,
        0
    },
    {
        "color",
        NULL,
        0
    },
    {
        "recurrenceId",
        NULL,
        0
    },
    {
        "recurrenceRules",
        NULL,
        0
    },
    {
        "recurrenceOverrides",
        NULL,
        0
    },
    {
        "excluded",
        NULL,
        0
    },
    {
        "excludedRecurrenceRules",
        NULL,
        0
    },
    {
        "priority",
        NULL,
        0
    },
    {
        "freeBusyStatus",
        NULL,
        0
    },
    {
        "privacy",
        NULL,
        0
    },
    {
        "replyTo",
        NULL,
        0
    },
    {
        "participants",
        NULL,
        0
    },
    {
        "useDefaultAlerts",
        NULL,
        0
    },
    {
        "alerts",
        NULL,
        0
    },
    {
        "localizations",
        NULL,
        0
    },
    {
        "timeZones",
        NULL,
        0
    },

    /* JSEvent properties */
    {
        "start",
        NULL,
        0
    },
    {
        "timeZone",
        NULL,
        0
    },
    {
        "duration",
        NULL,
        0
    },
    {
        "showWithoutTime",
        NULL,
        0
    },
    {
        "status",
        NULL,
        0
    },

    /* JMAP Calendars spec */
    {
        "isDraft",
        JMAP_URN_CALENDARS,
        0
    },
    {
        "utcStart",
        JMAP_URN_CALENDARS,
        JMAP_PROP_SKIP_GET
    },
    {
        "utcEnd",
        JMAP_URN_CALENDARS,
        JMAP_PROP_SKIP_GET
    },

    /* FM specific */
    {
        "x-href",
        JMAP_CALENDARS_EXTENSION,
        0
    },
    {
        "blobId",
        JMAP_CALENDARS_EXTENSION,
        JMAP_PROP_SERVER_SET | JMAP_PROP_SKIP_GET
    },
    {
        "debugBlobId",
        JMAP_DEBUG_EXTENSION,
        JMAP_PROP_SERVER_SET | JMAP_PROP_SKIP_GET
    },
    { NULL, NULL, 0 }
};

static void cachecalendarevents_cb(uint64_t rowid, void *payload, void *vrock)
{
    const char *eventrep = payload;
    struct getcalendarevents_rock *rock = vrock;

    // there's no way to return errors, but luckily it doesn't matter if we
    // fail to cache
    caldav_write_jmapcache(rock->db, rowid, rock->req->userid,
                           JMAPCACHE_CALVERSION, eventrep);
}

struct getcalendarevents_args {
    struct jmapical_datetime overrides_before;
    struct jmapical_datetime overrides_after;
};

static int getcalendarevents_parse_args(jmap_req_t *req __attribute__((unused)),
                                        struct jmap_parser *parser __attribute__((unused)),
                                        const char *arg,
                                        json_t *val,
                                        void *vrock)
{
    struct getcalendarevents_rock *rock = vrock;

    if (!strcmp(arg, "recurrenceOverridesAfter")) {
        const char *s = json_string_value(val);
        if (!s) return 0;
        if (jmapical_utcdatetime_from_string(s, &rock->overrides_after) == 0) {
            return 1;
        }
    }
    else if (!strcmp(arg, "recurrenceOverridesBefore")) {
        const char *s = json_string_value(val);
        if (!s) return 0;
        if (jmapical_utcdatetime_from_string(s, &rock->overrides_before) == 0) {
            return 1;
        }
    }
    else if (!strcmp(arg, "reduceParticipants")) {
        if (json_is_boolean(val)) {
            rock->reduce_participants = json_boolean_value(val);
            return 1;
        }
    }

    return 0;
}

static int jmap_calendarevent_get(struct jmap_req *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    char *sched_inboxname = caldav_mboxname(req->accountid, SCHED_INBOX);
    char *sched_outboxname = caldav_mboxname(req->accountid, SCHED_OUTBOX);
    struct jmap_get get;
    struct caldav_db *db = NULL;
    json_t *err = NULL;
    int r = 0;

    /* Build callback data */
    int checkacl = strcmp(req->accountid, req->userid);
    struct getcalendarevents_rock rock = { NULL /* db */,
                                           req, &get,
                                           NULL /* mbox */,
                                           NULL /* mbentry */,
                                           NULL /* mbname */,
                                           HASHU64_TABLE_INITIALIZER, /* cache */
                                           NULL, /* want_eventids */
                                           checkacl,
                                           sched_inboxname,
                                           sched_outboxname,
                                           HASH_TABLE_INITIALIZER, /* utctimes_fallbacktz */
                                           PTRARRAY_INITIALIZER,
                                           JMAPICAL_DATETIME_INITIALIZER,
                                           JMAPICAL_DATETIME_INITIALIZER,
                                           0 /* reduce_participants */
    };

    construct_hashu64_table(&rock.jmapcache, 512, 0);
    construct_hash_table(&rock.floatingtz_by_mboxid, 64, 0);

    /* Parse request */
    jmap_get_parse(req, &parser, event_props, /*allow_null_ids*/1,
                   getcalendarevents_parse_args, &rock, &get, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    if (!has_calendars(req)) {
        jmap_ok(req, jmap_get_reply(&get));
        goto done;
    }

    rock.db = db = caldav_open_userid(req->accountid);
    if (!db) {
        syslog(LOG_ERR,
               "caldav_open_mailbox failed for user %s", req->accountid);
        r = IMAP_INTERNAL;
        goto done;
    }

    /* Does the client request specific events? */
    if (json_array_size(get.ids)) {
        size_t i;
        json_t *jval;
        hash_table eventids_by_uid = HASH_TABLE_INITIALIZER;
        construct_hash_table(&eventids_by_uid, json_array_size(get.ids), 0);

        /* Split into single-valued uids and event recurrence instance ids */
        json_array_foreach(get.ids, i, jval) {
            const char *id = json_string_value(jval);
            struct event_id *eid = parse_eventid(id);
            if (eid) {
                ptrarray_t *eventids = hash_lookup(eid->uid, &eventids_by_uid);
                if (!eventids) {
                    eventids = ptrarray_new();
                    hash_insert(eid->uid, eventids, &eventids_by_uid);
                }
                ptrarray_append(eventids, eid);
            }
            else json_array_append(get.not_found, jval);
        }

        /* Lookup events by UID */
        hash_iter *iter = hash_table_iter(&eventids_by_uid);
        while (hash_iter_next(iter)) {
            const char *uid = hash_iter_key(iter);
            size_t nseen = json_array_size(get.list) + json_array_size(get.not_found);
            rock.want_eventids = hash_iter_val(iter);
            r = caldav_get_events(db, req->userid, NULL, uid, &getcalendarevents_cb, &rock);
            if (r) break;
            if (nseen == json_array_size(get.list) + json_array_size(get.not_found)) {
                /* caldavdb silently ignores non-existent uids */
                int j;
                for (j = 0; j < ptrarray_size(rock.want_eventids); j++) {
                    struct event_id *eid = ptrarray_nth(rock.want_eventids, j);
                    json_array_append_new(rock.get->not_found, json_string(eid->raw));
                }
            }
        }
        hash_iter_free(&iter);

        /* Clean up memory */
        iter = hash_table_iter(&eventids_by_uid);
        while (hash_iter_next(iter)) {
            ptrarray_t *eventids = hash_iter_val(iter);
            struct event_id *eid;
            while ((eid = ptrarray_pop(eventids))) {
                free_eventid(&eid);
            }
            ptrarray_free(eventids);
        }
        hash_iter_free(&iter);
        free_hash_table(&eventids_by_uid, NULL);
    } else if (json_is_null(get.ids) || get.ids == NULL) {
        /* Return all visible events */
        r = caldav_get_events(db, req->userid, NULL, NULL, &getcalendarevents_cb, &rock);
    }
    if (r) goto done;

    if (hashu64_count(&rock.jmapcache)) {
        r = caldav_begin(db);
        if (!r) hashu64_enumerate(&rock.jmapcache, cachecalendarevents_cb, &rock);
        if (r) caldav_abort(db);
        else r = caldav_commit(db);
        if (r) goto done;
    }

    /* Build response */
    json_t *jstate = jmap_getstate(req, MBTYPE_CALENDAR, /*refresh*/0);
    get.state = xstrdup(json_string_value(jstate));
    json_decref(jstate);
    jmap_ok(req, jmap_get_reply(&get));

done:
    jmap_parser_fini(&parser);
    jmap_get_fini(&get);
    free(sched_inboxname);
    free(sched_outboxname);
    if (db) caldav_close(db);
    if (rock.mailbox) jmap_closembox(req, &rock.mailbox);
    if (rock.mbentry) mboxlist_entry_free(&rock.mbentry);
    if (rock.mbname) mbname_free(&rock.mbname);
    free_hashu64_table(&rock.jmapcache, free);
    free_hash_table(&rock.floatingtz_by_mboxid, NULL); /* values owned by libical */
    if (ptrarray_size(&rock.malloced_fallbacktzs)) {
        icaltimezone *tz;
        while ((tz = ptrarray_pop(&rock.malloced_fallbacktzs))) {
            icaltimezone_free(tz, 1);
        }
        ptrarray_fini(&rock.malloced_fallbacktzs);
    }
    return r;
}

static int setcalendarevents_schedule(jmap_req_t *req,
                                      const strarray_t *schedule_addresses,
                                      icalcomponent *oldical,
                                      icalcomponent *ical,
                                      int mode)
{
    /* Determine if any scheduling is required. */
    icalcomponent *src = mode & JMAP_DESTROY ? oldical : ical;
    icalcomponent *comp =
        icalcomponent_get_first_component(src, ICAL_VEVENT_COMPONENT);
    icalproperty *prop =
        icalcomponent_get_first_property(comp, ICAL_ORGANIZER_PROPERTY);
    if (!prop) return 0;
    const char *organizer = icalproperty_get_organizer(prop);
    if (!organizer) return 0;
    if (!strncasecmp(organizer, "mailto:", 7)) organizer += 7;

    /* Validate create/update. */
    if (oldical && (mode & (JMAP_CREATE|JMAP_UPDATE))) {
        /* Don't allow ORGANIZER to be updated */
        const char *oldorganizer = NULL;

        icalcomponent *oldcomp = NULL;
        icalproperty *prop = NULL;
        oldcomp =
            icalcomponent_get_first_component(oldical, ICAL_VEVENT_COMPONENT);
        if (oldcomp) {
            prop = icalcomponent_get_first_property(oldcomp,
                                                    ICAL_ORGANIZER_PROPERTY);
        }
        if (prop) oldorganizer = icalproperty_get_organizer(prop);
        if (oldorganizer) {
            if (!strncasecmp(oldorganizer, "mailto:", 7)) oldorganizer += 7;
            if (strcasecmp(oldorganizer, organizer)) {
                /* XXX This should become a set error. */
                return 0;
            }
        }
    }

    if (organizer &&
            /* XXX Hack for Outlook */ icalcomponent_get_first_invitee(comp)) {
        /* Send scheduling message. */
        if (strarray_find_case(schedule_addresses, organizer, 0) >= 0) {
            /* Organizer scheduling object resource */
            sched_request(req->userid, schedule_addresses, organizer, oldical, ical);
        } else {
            /* Attendee scheduling object resource */
            int omit_reply = 0;
            if (oldical && (mode & JMAP_DESTROY)) {
                for (prop = icalcomponent_get_first_property(comp, ICAL_ATTENDEE_PROPERTY);
                     prop;
                     prop = icalcomponent_get_next_property(comp, ICAL_ATTENDEE_PROPERTY)) {
                    const char *addr = icalproperty_get_attendee(prop);
                    if (!addr || strncasecmp(addr, "mailto:", 7) || strcasecmp(strarray_nth(schedule_addresses, 0), addr+7))
                        continue;
                    icalparameter *param = icalproperty_get_first_parameter(prop, ICAL_PARTSTAT_PARAMETER);
                    omit_reply = !param || icalparameter_get_partstat(param) == ICAL_PARTSTAT_NEEDSACTION;
                    break;
                }
            }
            if (!omit_reply && strarray_size(schedule_addresses))
                sched_reply(req->userid, schedule_addresses, oldical, ical);
        }
    }

    return 0;
}

static void remove_itip_properties(icalcomponent *ical)
{
    icalproperty *prop, *next;
    icalproperty_kind kind = ICAL_METHOD_PROPERTY;

    for (prop = icalcomponent_get_first_property(ical, kind);
         prop;
         prop = next) {

        next = icalcomponent_get_next_property(ical, kind);
        icalcomponent_remove_property(ical, prop);
        icalproperty_free(prop);
    }

}

static void setcalendarevents_set_utctimes(json_t *event,
                                           icaltimezone *fallbacktz,
                                           json_t *invalid)
{
    struct jmapical_datetime startdt = JMAPICAL_DATETIME_INITIALIZER;
    struct jmapical_duration dur = JMAPICAL_DURATION_INITIALIZER;
    icaltimezone *tz = NULL;
    struct buf buf = BUF_INITIALIZER;

    /* Validate utcStart */
    json_t *jutcStart = json_object_get(event, "utcStart");
    if (json_is_string(jutcStart)) {
        if (jmapical_utcdatetime_from_string(json_string_value(jutcStart), &startdt) == -1) {
            json_array_append_new(invalid, json_string("utcStart"));
        }
    }
    else json_array_append_new(invalid, json_string("utcStart")); // must be set

    /* Validate utcEnd and determine duration */
    json_t *jutcEnd = json_object_get(event, "utcEnd");
    if (json_is_string(jutcEnd)) {
        struct jmapical_datetime enddt = JMAPICAL_DATETIME_INITIALIZER;
        if (jmapical_utcdatetime_from_string(json_string_value(jutcEnd), &enddt) >= 0) {
            jmapical_duration_between_utctime(&startdt, &enddt, &dur);
            if (dur.is_neg) {
                json_array_append_new(invalid, json_string("utcEnd"));
            }
        }
        else json_array_append_new(invalid, json_string("utcEnd"));
    }
    else if (JNOTNULL(jutcEnd)) {
        json_array_append_new(invalid, json_string("utcEnd"));
    }

    /* Return early for bogus values */
    if (json_array_size(invalid)) goto done;

    /* Determine timeZone */
    json_t *jtimeZone = json_object_get(event, "timeZone");
    if (json_is_string(jtimeZone)) {
        const char *tzid = json_string_value(jtimeZone);
        tz = icaltimezone_get_cyrus_timezone_from_tzid(tzid);
        if (!tz) goto done; /* bogus timeZone */
    }
    else if (!jtimeZone || json_is_null(jtimeZone)) {
        tz = fallbacktz ? fallbacktz : icaltimezone_get_utc_timezone();
    }

    /* Convert UTC start to local start */
    icaltimezone *utc = icaltimezone_get_utc_timezone();
    if (tz != utc) {
        icaltimetype startical = jmapical_datetime_to_icaltime(&startdt, utc);
        bit64 nano = startdt.nano;
        startical = icaltime_convert_to_zone(startical, tz);
        jmapical_datetime_from_icaltime(startical, &startdt);
        startdt.nano = nano;
    }

    /* Set start */
    json_t *jstart = json_object_get(event, "start");
    jmapical_localdatetime_as_string(&startdt, &buf);
    if (json_is_string(jstart)) {
        if (strcmp(json_string_value(jstart), buf_cstring(&buf))) {
            json_array_append_new(invalid, json_string("utcStart"));
        }
    }
    else if (!jstart) {
        json_object_set_new(event, "start", json_string(buf_cstring(&buf)));
    }

    /* Set duration */
    json_t *jduration = json_object_get(event, "duration");
    jmapical_duration_as_string(&dur, &buf);
    if (json_is_string(jduration) && jutcEnd) {
        if (strcmp(json_string_value(jduration), buf_cstring(&buf))) {
            json_array_append_new(invalid, json_string("utcEnd"));
        }
    }
    else if (!jduration && !jmapical_duration_has_zero_time(&dur)) {
        json_object_set_new(event, "duration", json_string(buf_cstring(&buf)));
    }

    /* Set timeZone */
    if (!fallbacktz && (!jtimeZone || json_is_null(jtimeZone))) {
        json_object_set_new(event, "timeZone", json_string("Etc/UTC"));
    }

done:
    buf_free(&buf);
}

static void remove_peruserprops(json_t *jevent)
{
    json_object_del(jevent, "keywords");
    json_object_del(jevent, "color");
    json_object_del(jevent, "freeBusyStatus");
    json_object_del(jevent, "useDefaultAlerts");
    json_object_del(jevent, "alerts");

    json_t *joverrides = json_object_get(jevent, "recurrenceOverrides");
    const char *recurid;
    json_t *joverride;
    void *tmp;
    json_object_foreach_safe(joverrides, tmp, recurid, joverride) {
        json_object_del(joverride, "keywords");
        json_object_del(joverride, "color");
        json_object_del(joverride, "freeBusyStatus");
        json_object_del(joverride, "useDefaultAlerts");
        json_object_del(joverride, "alerts");
        const char *prop;
        json_t *jpatch;
        void *tmp2;
        json_object_foreach_safe(joverride, tmp2, prop, jpatch) {
            if (!strncmp(prop, "alerts/", 7)) {
                json_object_del(joverride, prop);
            }
        }
        if (!json_object_size(joverride)) {
            json_object_del(joverrides, recurid);
        }
    }
}


static char *jmap_notifmboxname(const char *userid)
{
    /* Create notification mailbox name from the parsed path */
    mbname_t *mbname = mbname_from_userid(userid);
    mbname_push_boxes(mbname, config_getstring(IMAPOPT_JMAPNOTIFICATIONFOLDER));
    char *mboxname = xstrdup(mbname_intname(mbname));
    mbname_free(&mbname);
    return mboxname;
}

static int create_notify_collection(const char *userid, mbentry_t **mbentryptr)
{
    /* notifications collection */
    char *notifmboxname = jmap_notifmboxname(userid);

    int r = mboxlist_lookup(notifmboxname, mbentryptr, NULL);
    if (r == IMAP_MAILBOX_NONEXISTENT) {
        /* lock the namespace lock and try again */
        struct mboxlock *namespacelock = user_namespacelock(userid);

        mbentry_t mbentry = MBENTRY_INITIALIZER;
        mbentry.name = notifmboxname;
        mbentry.mbtype = MBTYPE_JMAPNOTIFY;
        r = mboxlist_createmailbox(&mbentry, 0/*options*/, 0/*highestmodseq*/,
                                   1/*isadmin*/, userid, NULL/*authstate*/,
                                   0/*flags*/, NULL/*mboxptr*/);

        /* we lost the race, that's OK */
        if (r == IMAP_MAILBOX_LOCKED) r = 0;
        if (r) syslog(LOG_ERR, "IOERROR: failed to create %s (%s)",
                      notifmboxname, error_message(r));

        r = mboxlist_lookup(notifmboxname, mbentryptr, NULL);
        mboxname_release(&namespacelock);
    }

    free(notifmboxname);
    return r;
}

#define JMAP_NOTIF_CALENDAREVENT "jmap-notif-calendarevent"


static char *eventnotif_fromheader(const char *userid)
{
    struct buf buf = BUF_INITIALIZER;
    if (strchr(userid, '@')) {
        buf_printf(&buf, "<%s>", userid);
    }
    else {
        buf_printf(&buf, "<%s@%s>", userid, config_servername);
    }
    char *notfrom = charset_encode_mimeheader(buf_cstring(&buf), buf_len(&buf), 0);
    buf_free(&buf);
    return notfrom;
}

static int append_eventnotif(const char *from,
                             const char *authuserid,
                             struct auth_state *authstate,
                             struct mailbox *notifmbox,
                             const char *calmboxname,
                             time_t created,
                             json_t *jnotif)
{
    struct stagemsg *stage = NULL;
    int r = 0;
    char *notifstr = json_dumps(jnotif, 0);
    struct buf buf = BUF_INITIALIZER;
    const char *type = json_string_value(json_object_get(jnotif, "type"));
    const char *ical_uid = json_string_value(json_object_get(jnotif, "calendarEventId"));

    if (!strcmp(type, "destroyed")) {
        /* Expunge all former event notifications for this UID */
        struct mailbox_iter *iter = mailbox_iter_init(notifmbox, 0, 0);
        message_t *msg;
        while ((msg = (message_t *) mailbox_iter_step(iter))) {
            buf_reset(&buf);
            if (message_get_subject(msg, &buf) ||
                    strcmp(JMAP_NOTIF_CALENDAREVENT, buf_cstring(&buf))) {
                continue;
            }
            const struct body *body;
            if (message_get_cachebody(msg, &body)) {
                continue;
            }
            int matches_uid = 0;
            struct dlist *dl = NULL;
            if (!dlist_parsemap(&dl, 1, 0, body->description,
                        strlen(body->description))) {
                const char *val;
                matches_uid = dlist_getatom(dl, "ID", &val) &&
                              !strcmp(val, ical_uid);
            }
            dlist_free(&dl);
            if (!matches_uid) continue;

            struct index_record record = *msg_record(msg);
            if (!(record.system_flags & FLAG_DELETED) &&
                !(record.internal_flags & FLAG_INTERNAL_EXPUNGED)) {
                record.internal_flags |= FLAG_INTERNAL_EXPUNGED;
                 mailbox_rewrite_index_record(notifmbox, &record);
            }
        }
        mailbox_iter_done(&iter);
    }
    buf_reset(&buf);

    FILE *fp = append_newstage(mailbox_name(notifmbox), created, 0, &stage);
    if (!fp) {
        xsyslog(LOG_ERR, "append_newstage failed", "name=%s", mailbox_name(notifmbox));
        r = HTTP_SERVER_ERROR;
        goto done;
    }

    fputs("From: ", fp);
    fputs(from, fp);
    fputs("\r\n", fp);

    fputs("Subject: " JMAP_NOTIF_CALENDAREVENT "\r\n", fp);

    char date5322[RFC5322_DATETIME_MAX+1];
    time_to_rfc5322(created, date5322, RFC5322_DATETIME_MAX);
    fputs("Date: ", fp);
    fputs(date5322, fp);
    fputs("\r\n", fp);

    fprintf(fp, "Message-ID: <%s-%ld@%s>\r\n", makeuuid(), created, config_servername);
    fputs("Content-Type: application/json; charset=utf-8\r\n", fp);
    fputs("Content-Transfer-Encoding: 8bit\r\n", fp);

    struct dlist *dl = dlist_newkvlist(NULL, "N");
    dlist_setdate(dl, "S", created);
    dlist_setatom(dl, "T", JMAP_NOTIF_CALENDAREVENT);
    dlist_setatom(dl, "ID", ical_uid);
    dlist_setatom(dl, "NT", type);
    dlist_setatom(dl, "M", calmboxname);
    dlist_printbuf(dl, 1, &buf);
    fputs("Content-Description: ", fp);
    fputs(buf_cstring(&buf), fp);
    fputs("\r\n", fp);
    buf_reset(&buf);
    dlist_free(&dl);

    fprintf(fp, "Content-Length: %zu\r\n", strlen(notifstr));
    fputs("MIME-Version: 1.0\r\n", fp);

    fputs("\r\n", fp);
    fputs(notifstr, fp);

    fclose(fp);
    if (r) goto done;

    struct appendstate as;
    r = append_setup_mbox(&as, notifmbox, authuserid, authstate,
            0, NULL, 0, 0, EVENT_MESSAGE_NEW);
    if (r) goto done;

    struct body *body = NULL;
    r = append_fromstage(&as, &body, stage, created, 0, NULL, 0, NULL);
    message_free_body(body);
    free(body);
    if (!r) {
        append_commit(&as);
    }
    else {
        append_abort(&as);
    }

done:
    append_removestage(stage);
    buf_free(&buf);
    free(notifstr);
    return r;
}

json_t *build_eventnotif(const char *type,
                         time_t created,
                         const char *byprincipal,
                         const char *byname,
                         const char *byemail,
                         const char *ical_uid,
                         const char *comment,
                         int is_draft,
                         json_t *jevent,
                         json_t *jpatch)
{
    json_t *jn = json_object();

    json_object_set_new(jn, "type", json_string(type));
    json_object_set_new(jn, "calendarEventId", json_string(ical_uid));
    json_object_set_new(jn, "isDraft", json_boolean(is_draft));

    char date3339[RFC3339_DATETIME_MAX+1];
    time_to_rfc3339(created, date3339, RFC3339_DATETIME_MAX);
    json_object_set_new(jn, "created", json_string(date3339));

    json_t *jchangedby = json_object();
    if (byemail) {
        if (!strncasecmp(byemail, "mailto:", 7)) byemail += 7;
        json_object_set_new(jchangedby, "email", json_string(byemail));
    }
    if (byname) {
        json_object_set_new(jchangedby, "name", json_string(byname));
    }
    if (byprincipal) {
        json_object_set_new(jchangedby, "calendarPrincipalId",
                json_string(byprincipal));
    }
    if (!json_object_size(jchangedby)) {
        json_decref(jchangedby);
        jchangedby = json_null();
    }
    json_object_set_new(jn, "changedBy", jchangedby);

    if (comment) {
        json_object_set_new(jn, "comment", json_string(comment));
    }
    if (jpatch) {
        json_object_set(jn, "eventPatch", jpatch);
    }
    if (jevent) {
        json_object_set(jn, "event", jevent);
    }

    return jn;
}


static int create_eventnotif(jmap_req_t *req,
                             struct mailbox *notifmbox,
                             const char *calmboxname,
                             const char *type,
                             const char *ical_uid,
                             const strarray_t *schedule_addresses,
                             const char *comment,
                             int is_draft,
                             json_t *jevent,
                             json_t *jpatch)
{
    if (!notifmbox) {
        xsyslog(LOG_ERR, "can not create event notification (null notifmbox)",
                "calendar=%s ical_uid=%s", calmboxname, ical_uid);
        return 0;
    }

    time_t now = time(NULL);

    const char *byemail = schedule_addresses ?
        strarray_nth(schedule_addresses, 0) : NULL;

    struct buf byname = BUF_INITIALIZER;
    const char *annotname = DAV_ANNOT_NS "<" XML_NS_DAV ">displayname";
    char *calhomename = caldav_mboxname(req->userid, NULL);
    annotatemore_lookupmask(calhomename, annotname, req->userid, &byname);
    free(calhomename);

    json_t *jnotif = build_eventnotif(type, now, req->userid,
            buf_cstring(&byname), byemail, ical_uid, comment,
            is_draft, jevent, jpatch);

    char *from = eventnotif_fromheader(req->userid);
    int r = append_eventnotif(from, req->userid, req->authstate, notifmbox,
            calmboxname, now, jnotif);
    free(from);

    json_decref(jnotif);
    buf_free(&byname);
    return r;
}

HIDDEN int jmap_create_caldaveventnotif(struct transaction_t *txn,
                                        const char *calmboxname,
                                        const char *ical_uid,
                                        const strarray_t *schedule_addresses,
                                        int is_draft,
                                        icalcomponent *oldical,
                                        icalcomponent *newical)
{
    mbname_t *mbname = mbname_from_intname(calmboxname);
    const char *accountid = mbname_userid(mbname);
    struct mailbox *notifmbox = NULL;
    mbentry_t *notifmb = NULL;
    time_t now = time(NULL);
    json_t *jevent = NULL;
    json_t *jpatch = NULL;
    int r = 0;

    assert(oldical || newical);

    if ((user_isnamespacelocked(accountid) == LOCK_SHARED) ||
        (user_isnamespacelocked(httpd_userid) == LOCK_SHARED)) {
        /* bail out, before notification mailbox crashes on invalid lock */
        xsyslog(LOG_ERR, "can not exlusively lock jmapnotify collection",
                "accountid=%s", accountid);
        goto done;
    }

    r = create_notify_collection(accountid, &notifmb);
    if (r) {
        xsyslog(LOG_ERR, "can not create jmapnotify collection",
                "accountid=%s error=%s", accountid, error_message(r));
        goto done;
    }

    r = mailbox_open_iwl(notifmb->name, &notifmbox);
    if (r) {
        xsyslog(LOG_ERR, "can not open notification mailbox",
                "name=%s", notifmb->name);
        goto done;
    }

    const char *type;
    if (oldical) {
        jevent = jmapical_tojmap(oldical, NULL, NULL);
        if (newical) {
            type = "updated";
            json_t *tmp = jmapical_tojmap(newical, NULL, NULL);
            jpatch = jmap_patchobject_create(jevent, tmp);
            json_decref(tmp);
        }
        else type = "destroyed";
    }
    else {
        type = "created";
        jevent = jmapical_tojmap(newical, NULL, NULL);
    }
    if (!jevent) goto done;

    remove_peruserprops(jevent);
    remove_peruserprops(jpatch);

    /* Determine who triggered that event notification */
    struct buf byname = BUF_INITIALIZER;
    const char *byemail = NULL;
    const char *byprincipal = NULL;
    const char **hdr;
    char *from = NULL;

    if ((hdr = spool_getheader(txn->req_hdrs, "Schedule-Sender-Address"))) {
        byemail = *hdr;
        if (!strncasecmp(byemail, "mailto:", 7)) {
            byemail += 7;
        }
        from = strconcat("<", byemail, ">", NULL);
        if ((hdr = spool_getheader(txn->req_hdrs, "Schedule-Sender-name"))) {
            char *val = charset_decode_mimeheader(*hdr, CHARSET_KEEPCASE);
            if (val) buf_initmcstr(&byname, val);
        }
    }
    else {
        from = eventnotif_fromheader(httpd_userid);
        byprincipal = httpd_userid;
        static const char *annotname = DAV_ANNOT_NS "<" XML_NS_DAV ">displayname";
        char *calhomename = caldav_mboxname(httpd_userid, NULL);
        annotatemore_lookupmask(calhomename, annotname, httpd_userid, &byname);
        free(calhomename);
        byemail = strarray_nth(schedule_addresses, 0);
    }

    json_t *jnotif = build_eventnotif(type, now,
            byprincipal, buf_cstring(&byname), byemail,
            ical_uid, NULL, is_draft, jevent, jpatch);

    r = append_eventnotif(from, httpd_userid, httpd_authstate, notifmbox,
                          calmboxname, now, jnotif);

    json_decref(jnotif);
    buf_free(&byname);
    free(from);

done:
    json_decref(jevent);
    json_decref(jpatch);
    mailbox_close(&notifmbox);
    mboxlist_entry_free(&notifmb);
    mbname_free(&mbname);
    return r;
}

static int setcalendarevents_create(jmap_req_t *req,
                                    const char *account_id,
                                    struct mailbox *notifmbox,
                                    json_t *event,
                                    struct caldav_db *db,
                                    json_t *invalid,
                                    int send_scheduling_messages,
                                    json_t *create)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    int needrights = JACL_ADDITEMS|JACL_SETMETADATA;
    char *uid = NULL;
    json_t *jval;
    int r = 0;

    struct mailbox *mbox = NULL;
    char *mboxname = NULL;
    char *resource = NULL;

    icalcomponent *ical = NULL;
    strarray_t schedule_addresses = STRARRAY_INITIALIZER;

    static int icalendar_max_size = -1;
    if (icalendar_max_size < 0) {
        icalendar_max_size = config_getint(IMAPOPT_ICALENDAR_MAX_SIZE);
        if (icalendar_max_size <= 0) icalendar_max_size = INT_MAX;
    }

    struct jmapical_jmapcontext jmapctx;
    jmap_calendarcontext_init(&jmapctx, req);
 
    /* Validate uid */
    struct caldav_data *mycdata = NULL;
    if ((uid = (char *) json_string_value(json_object_get(event, "uid")))) {
        /* Use custom iCalendar UID from request object */
        uid = xstrdup(uid);
        r = caldav_lookup_uid(db, uid, &mycdata);
        if (r == CYRUSDB_NOTFOUND) {
            r = 0;
        }
        else if (!r) {
            json_array_append_new(invalid, json_string("uid"));
        }
    }  else {
        /* Create a iCalendar UID */
        static int maxattempts = 3;
        int i;
        for (i = 0; i < maxattempts; i++) {
            free(uid);
            uid = xstrdup(makeuuid());
            r = caldav_lookup_uid(db, uid, &mycdata);
            if (r == CYRUSDB_NOTFOUND) {
                r = 0;
                break;
            }
        }
        if (i == maxattempts) {
            errno = 0;
            xsyslog(LOG_ERR, "can not create unique uid", "attempts=<%d>", i);
            r = IMAP_INTERNAL;
        }
    }
    if (r) goto done;

    /* Validate calendarId */
    const char *calendarId = NULL;
    jval = json_object_get(event, "calendarIds");
    if (json_object_size(jval) == 1) {
        void *iter = json_object_iter(jval);
        if (json_object_iter_value(iter) == json_true()) {
            calendarId = json_object_iter_key(iter);
        }
    }
    if (calendarId && *calendarId == '#') {
        calendarId = jmap_lookup_id(req, calendarId + 1);
    }
    if (!calendarId || !*calendarId) {
        jmap_parser_invalid(&parser, "calendarIds");
        goto done;
    }

    /* Validate isDraft */
    int is_draft = 0;
    jmap_readprop(event, "isDraft", 0, parser.invalid, "b", &is_draft);

    /* Determine mailbox and resource name of calendar event.
     * We attempt to reuse the UID as DAV resource name; but
     * only if it looks like a reasonable URL path segment. */
    struct buf buf = BUF_INITIALIZER;
    mboxname = caldav_mboxname(account_id, calendarId);
    const char *p;
    for (p = uid; *p; p++) {
        if ((*p >= '0' && *p <= '9') ||
            (*p >= 'a' && *p <= 'z') ||
            (*p >= 'A' && *p <= 'Z') ||
            (*p == '@' || *p == '.') ||
            (*p == '_' || *p == '-')) {
            continue;
        }
        break;
    }
    if (*p == '\0' && p - uid >= 16 && p - uid <= 200) {
        buf_setcstr(&buf, uid);
    } else {
        buf_setcstr(&buf, makeuuid());
    }
    buf_appendcstr(&buf, ".ics");
    resource = buf_newcstring(&buf);
    buf_free(&buf);

    /* Check permissions. */
    if (!jmap_hasrights(req, mboxname, needrights)) {
        jmap_parser_invalid(&parser, "calendarIds");
        r = 0;
        goto done;
    }

    /* Open mailbox for writing */
    r = jmap_openmbox(req, mboxname, &mbox, 1);
    if (r) {
        syslog(LOG_ERR, "jmap_openmbox(req, %s) failed: %s", mboxname, error_message(r));
        if (r == IMAP_MAILBOX_NONEXISTENT) {
            jmap_parser_invalid(&parser, "calendarIds");
            r = 0;
        }
        goto done;
    }

    /* Set uid */
    if (!json_object_get(event, "uid")) {
        json_object_set_new(event, "uid", json_string(uid));
    }

    /* Set created, updated */
    if (!json_object_get(event, "created") || !json_object_get(event, "updated")) {
        char datestr[RFC3339_DATETIME_MAX+1];
        time_to_rfc3339(time(NULL), datestr, RFC3339_DATETIME_MAX);
        datestr[RFC3339_DATETIME_MAX] = '\0';
        if (!json_object_get(event, "created")) {
            json_object_set_new(event, "created", json_string(datestr));
        }
        if (!json_object_get(event, "updated")) {
            json_object_set_new(event, "updated", json_string(datestr));
        }
    }

    /* Check utcStart and utcEnd */
    if (JNOTNULL(json_object_get(event, "utcStart")) ||
        JNOTNULL(json_object_get(event, "utcEnd"))) {
        /* Ignore calendar timezone - if event does not define its
         * timezone then fall back to Etc/UTC for utcStart/utcEnd */
        setcalendarevents_set_utctimes(event, NULL, parser.invalid);
    }

    /* Convert JSEvent to iCalendar */
    ical = jmapical_toical(event, NULL, parser.invalid, &jmapctx);
    if (json_array_size(parser.invalid)) {
        r = 0;
        goto done;
    } else if (!ical) {
        r = IMAP_INTERNAL;
        goto done;
    }
    else if (icalendar_max_size != INT_MAX &&
        strlen(icalcomponent_as_ical_string(ical)) > (size_t) icalendar_max_size) {
        r = IMAP_MESSAGE_TOO_LARGE;
        goto done;
    }

    /* Handle scheduling. */
    get_schedule_addresses(NULL, mboxname, req->userid, &schedule_addresses);
    if (!is_draft && send_scheduling_messages) {
        r = setcalendarevents_schedule(req, &schedule_addresses,
                                       NULL, ical, JMAP_CREATE);
        if (r) goto done;
    }

    /* Remove METHOD property */
    remove_itip_properties(ical);

    /* Store the VEVENT. */
    struct transaction_t txn;
    memset(&txn, 0, sizeof(struct transaction_t));
    txn.req_hdrs = spool_new_hdrcache();
    txn.userid = req->userid;
    txn.authstate = req->authstate;

    /* Locate the mailbox */
    r = proxy_mlookup(mailbox_name(mbox), &txn.req_tgt.mbentry, NULL, NULL);
    if (r) {
        syslog(LOG_ERR, "mlookup(%s) failed: %s", mailbox_name(mbox), error_message(r));
    }
    else {
        strarray_t add_imapflags = STRARRAY_INITIALIZER;
        if (is_draft) strarray_append(&add_imapflags, "\\draft");
        r = caldav_store_resource(&txn, ical, mbox, resource, 0,
                                  db, 0, req->userid,
                                  &add_imapflags, /*del_imapflags*/NULL,
                                  &schedule_addresses);
        strarray_fini(&add_imapflags);
        if (r == HTTP_CREATED || HTTP_NO_CONTENT) {
            r = 0;
        }
        else if (r) {
            syslog(LOG_ERR, "caldav_store_resource failed for user %s: %s",
                    req->accountid, error_message(r));
        }
        if (!r) {
            json_t *event_copy = json_deep_copy(event);
            remove_peruserprops(event_copy);
            int r2 = create_eventnotif(req, notifmbox, mailbox_name(mbox), "created", uid,
                    &schedule_addresses, NULL, is_draft, event_copy, NULL);
            if (r2) {
                xsyslog(LOG_WARNING, "could not create notification",
                        "uid=%s error=%s", uid, error_message(r2));
            }
            json_decref(event_copy);
        }
    }
    mboxlist_entry_free(&txn.req_tgt.mbentry);
    spool_free_hdrcache(txn.req_hdrs);
    buf_free(&txn.buf);
    if (r) goto done;

    json_object_set_new(create, "uid", json_string(uid));
    json_object_set_new(create, "id", json_string(uid));

    char *xhref = jmap_xhref(mailbox_name(mbox), resource);
    json_object_set_new(create, "x-href", json_string(xhref));
    free(xhref);

    if (jmap_is_using(req, JMAP_CALENDARS_EXTENSION)) {
        struct buf blobid = BUF_INITIALIZER;
        if (jmap_encode_rawdata_blobid('I', mailbox_uniqueid(mbox), mbox->i.last_uid,
                                       req->userid, NULL, NULL, &blobid)) {
            json_object_set_new(create, "blobId",
                                json_string(buf_cstring(&blobid)));
        }
        buf_reset(&blobid);
        if (jmap_encode_rawdata_blobid('I', mailbox_uniqueid(mbox), mbox->i.last_uid,
                                       NULL, NULL, NULL, &blobid)) {
            json_object_set_new(create, "debugBlobId",
                                json_string(buf_cstring(&blobid)));
        }
        buf_free(&blobid);
    }

done:
    if (mbox) jmap_closembox(req, &mbox);
    if (ical) icalcomponent_free(ical);
    strarray_fini(&schedule_addresses);
    if (json_array_size(parser.invalid)) {
        json_array_extend(invalid, parser.invalid);
    }
    jmap_parser_fini(&parser);
    jmap_calendarcontext_fini(&jmapctx);
    free(resource);
    free(mboxname);
    free(uid);
    return r;
}

static int updates_peruserprops_only_internal(json_t *jdiff, strarray_t *participant_peruserprops)
{
    const char *prop;
    json_t *jval;
    void *tmp;

    json_object_foreach_safe(jdiff, tmp, prop, jval) {
        if (!strcmp(prop, "recurrenceOverrides")) {
            const char *recurid;
            json_t *joverride;
            json_object_foreach(jval, recurid, joverride) {
                if (!updates_peruserprops_only_internal(joverride, participant_peruserprops)) {
                    return 0;
                }
            }
            continue;
        }
        else if (!strcmp(prop, "participants")) {
            /* Patches *all* participants */
            return 0;
        }
        else if (!strncmp(prop, "recurrenceOverrides/", 20)) {
            /* Does prop point *into* an override? */
            const char *p = strchr(prop + 21, '/');
            if (!p) {
                /* Override value is a JSON object */
                if (!updates_peruserprops_only_internal(jval, participant_peruserprops)) {
                    return 0;
                }
                continue;
            }
            /* fall through */
            prop = p + 1;
        }

        if (strcmp(prop, "keywords") &&
            strcmp(prop, "color") &&
            strcmp(prop, "freeBusyStatus") &&
            strcmp(prop, "useDefaultAlerts") &&
            strcmp(prop, "alerts") &&
            strncmp(prop, "alerts/", 7) &&
            (strarray_find(participant_peruserprops, prop, 0) < 0)) {
            /* Patches some non-user property */
            return 0;
        }
    }

    return 1;
}

static int eventpatch_updates_peruserprops_only(json_t *jdiff, strarray_t *participant_ids)
{
    strarray_t participant_peruserprops = STRARRAY_INITIALIZER;

    if (participant_ids) {
        int i;
        for (i = 0; i < strarray_size(participant_ids); i++) {
            const char *participant_id = strarray_nth(participant_ids, i);
            strarray_appendm(&participant_peruserprops,
                    strconcat("participants/", participant_id, "/participationStatus", NULL));
            strarray_appendm(&participant_peruserprops,
                    strconcat("participants/", participant_id, "/participationComment", NULL));
            strarray_appendm(&participant_peruserprops,
                    strconcat("participants/", participant_id, "/expectReply", NULL));
        }
    }

    int ret = updates_peruserprops_only_internal(jdiff, &participant_peruserprops);
    strarray_fini(&participant_peruserprops);
    return ret;
}

static int eventpatch_updates_recurrenceoverrides(json_t *event_patch)
{
    const char *prop;
    json_t *jval;
    json_object_foreach(event_patch, prop, jval) {
        if (!strncmp(prop, "recurrenceOverrides/", 20) && strchr(prop + 21, '/')) {
            return 1;
        }
    }
    return 0;
}

static int eventpatch_updates_utctimes(json_t *event_patch)
{
    if (JNOTNULL(json_object_get(event_patch, "utcStart"))) {
        return 1;
    }
    if (JNOTNULL(json_object_get(event_patch, "utcEnd"))) {
        return 1;
    }

    json_t *joverride;
    const char *recurid;
    json_object_foreach(json_object_get(event_patch, "recurrenceOverrides"), recurid, joverride) {
        if (JNOTNULL(json_object_get(joverride, "utcStart"))) {
            return 1;
        }
        if (JNOTNULL(json_object_get(joverride, "utcEnd"))) {
            return 1;
        }
    }

    const char *prop;
    json_t *jval;
    json_object_foreach(event_patch, prop, jval) {
        if (!strncmp(prop, "recurrenceOverrides/", 20)) {
            const char *p = strchr(prop + 21, '/');
            if (p) {
                if (!strcmp(p + 1, "utcStart")) {
                    return 1;
                }
                if (!strcmp(p + 1, "utcEnd")) {
                    return 1;
                }
            }
            else {
                if (JNOTNULL(json_object_get(jval, "utcStart"))) {
                    return 1;
                }
                if (JNOTNULL(json_object_get(jval, "utcEnd"))) {
                    return 1;
                }
            }
        }
    }
    return 0;
}

/* XXX - the argument list of this function is insane */
static int setcalendarevents_apply_patch(struct jmapical_jmapcontext *jmapctx,
                                         json_t *old_event,
                                         json_t *event_patch,
                                         icalcomponent *oldical,
                                         const char *recurid,
                                         json_t *invalid,
                                         strarray_t *schedule_addresses,
                                         icalcomponent **newical,
                                         icaltimezone *floatingtz,
                                         json_t *update,
                                         json_t **err)
{
    json_t *new_event = NULL;
    strarray_t participant_ids = STRARRAY_INITIALIZER;
    int r = 0;
    jstimezones_t *jstzones = jstimezones_new(oldical);

    if (schedule_addresses) {
        json_t *jparticipants = json_object_get(old_event, "participants");
        json_t *jparticipant;
        const char *participant_id;
        json_object_foreach(jparticipants, participant_id, jparticipant) {
            json_t *jsendto = json_object_get(jparticipant, "sendTo");
            const char *uri = json_string_value(json_object_get(jsendto, "imip"));
            if (uri && !strncasecmp(uri, "mailto:", 7)) {
                if (strarray_find_case(schedule_addresses, uri + 7, 0) >= 0) {
                    strarray_append(&participant_ids, participant_id);
                }
            }
        }
    }

    if (recurid) {
        /* Update or create an override */
        struct jmapical_datetime recuriddt = JMAPICAL_DATETIME_INITIALIZER;
        if (jmapical_localdatetime_from_string(recurid, &recuriddt) < 0) {
            r = IMAP_NOTFOUND;
            goto done;
        }
        icaltimetype icalrecurid = jmapical_datetime_to_icaltime(&recuriddt, NULL);

        int is_rdate = !_recurid_is_instanceof(icalrecurid, oldical, 1/*rrule_only*/);

        json_t *old_overrides = json_object_get(old_event, "recurrenceOverrides");
        json_t *old_override = json_object_get(old_overrides, recurid);
        json_t *new_instance = NULL;
        json_t *new_override = NULL;
        if (old_override) {
            /* Patch an existing override */
            json_t *old_instance = jmap_patchobject_apply(old_event, old_override, NULL);
            new_instance = jmap_patchobject_apply(old_instance, event_patch, invalid);
            json_decref(old_instance);
        }
        else {
            /* Create a new override */
            new_instance = jmap_patchobject_apply(old_event, event_patch, invalid);
        }
        if (!new_instance) {
            *err = json_pack("{s:s}", "type", "invalidPatch");
            goto done;
        }

        /* Handle UTC time updates */
        if (json_object_get(event_patch, "utcStart") || json_object_get(event_patch, "utcEnd")) {
            if (!json_object_get(event_patch, "start")) {
                json_object_del(new_instance, "start");
            }
            if (json_object_get(event_patch, "utcEnd") && !json_object_get(event_patch, "duration")) {
                json_object_del(new_instance, "duration");
            }
            setcalendarevents_set_utctimes(new_instance, floatingtz, invalid);
        }

        json_object_del(new_instance, "recurrenceRules");
        json_object_del(new_instance, "recurrenceOverrides");
        json_object_del(new_instance, "excludedRecurrenceRules");
        new_override = jmap_patchobject_create(old_event, new_instance);
        json_object_del(new_override, "@type");
        json_object_del(new_override, "method");
        json_object_del(new_override, "prodId");
        json_object_del(new_override, "recurrenceId");
        json_object_del(new_override, "recurrenceRules");
        json_object_del(new_override, "recurrenceOverrides");
        json_object_del(new_override, "excludedRecurrenceRules");
        json_object_del(new_override, "relatedTo");
        json_object_del(new_override, "replyTo");
        json_object_del(new_override, "uid");
        json_decref(new_instance);

        if (json_boolean_value(json_object_get(new_override, "excluded"))) {
            if (is_rdate) {
                /* No need to set it in recurrenceOverrides */
                json_decref(new_override);
                new_override = NULL;
            }
            else if (json_object_size(new_override) > 1) {
                /* Normalize excluded override */
                json_decref(new_override);
                new_override = json_pack("{s:b}", "excluded", 1);
            }
        }
        else if (json_object_size(new_override) == 0) {
            if (!is_rdate) {
                /* No need to set it in recurrenceOverrides */
                json_decref(new_override);
                new_override = NULL;
            }
        }

        /* Create the new JSEvent */
        new_event = json_deep_copy(old_event);
        json_t *new_overrides = json_object_get(new_event, "recurrenceOverrides");
        if (new_override) {
            /* Update or create override */
            if (new_overrides == NULL || json_is_null(new_overrides)) {
                new_overrides = json_object();
                json_object_set_new(new_event, "recurrenceOverrides", new_overrides);
            }
            json_object_set_new(new_overrides, recurid, new_override);
        } else {
            /* Remove existing override */
            json_object_del(new_overrides, recurid);
        }
    }
    else {
        /* Update a regular event */
        if (eventpatch_updates_recurrenceoverrides(event_patch)) {
            /* Split patch into main event and override patches */
            json_t *mainevent_patch = json_object();
            json_t *overrides_patch = json_object();
            const char *key;
            json_t *jval;
            json_object_foreach(event_patch, key, jval) {
                if (!strncmp(key, "recurrenceOverrides/", 20)) {
                    json_object_set(overrides_patch, key, jval);
                }
                else {
                    json_object_set(mainevent_patch, key, jval);
                }
            }

            /* Apply patch to main event */
            json_t *old_mainevent = json_deep_copy(old_event);
            json_object_del(old_mainevent, "recurrenceOverrides");
            new_event = jmap_patchobject_apply(old_mainevent, mainevent_patch, invalid);
            if (!new_event) {
                *err = json_pack("{s:s}", "type", "invalidPatch");
                json_decref(old_mainevent);
                goto done;
            }

            /* Expand current overrides from patched main event */
            json_t *old_overrides = json_object_get(old_event, "recurrenceOverrides");
            json_t *old_exp_overrides = json_object();
            json_t *old_override;
            const char *recurid;
            json_object_foreach(old_overrides, recurid, old_override) {
                if (json_boolean_value(json_object_get(old_override, "excluded"))) {
                    json_object_set(old_exp_overrides, recurid, old_override);
                    continue;
                }
                json_t *override = jmap_patchobject_apply(new_event, old_override, NULL);
                if (override) {
                    json_object_set_new(old_exp_overrides, recurid, override);
                }
            }
            if (!json_object_size(old_exp_overrides)) {
                json_decref(old_exp_overrides);
                old_exp_overrides = json_null();
            }

            /* Apply override patches to expanded overrides */
            json_t *new_exp_overrides = NULL;
            if (json_object_size(old_exp_overrides)) {
                json_t *old_wrapper = json_pack("{s:O}", "recurrenceOverrides", old_exp_overrides);
                json_t *new_wrapper = jmap_patchobject_apply(old_wrapper, overrides_patch, invalid);
                if (!new_wrapper) {
                    *err = json_pack("{s:s}", "type", "invalidPatch");
                    json_decref(old_wrapper);
                    goto done;
                }
                new_exp_overrides = json_incref(json_object_get(new_wrapper, "recurrenceOverrides"));
                json_decref(old_wrapper);
                json_decref(new_wrapper);
            }

            /* Diff patched overrides with patched main event */
            json_t *new_overrides = json_object();
            struct buf buf = BUF_INITIALIZER;
            json_object_foreach(new_exp_overrides, recurid, jval) {
                /* Don't diff excluded overrides */
                if (json_boolean_value(json_object_get(jval, "excluded"))) {
                    json_object_set(new_overrides, recurid, jval);
                    continue;
                }
                /* Don't diff replaced overrides */
                buf_setcstr(&buf, "recurrenceOverrides/");
                buf_appendcstr(&buf, recurid);
                if (json_object_get(overrides_patch, buf_cstring(&buf))) {
                    json_object_set(new_overrides, recurid, jval);
                    continue;
                }
                /* Diff updated override */
                json_t *new_override = jmap_patchobject_create(new_event, jval);
                if (!new_override) continue;
                json_object_set_new(new_overrides, recurid, new_override);
            }
            buf_free(&buf);
            if (!json_object_size(new_overrides)) {
                json_decref(new_overrides);
                new_overrides = json_null();
            }

            /* Combine new main event with new overrides */
            json_object_set_new(new_event, "recurrenceOverrides", new_overrides);

            json_decref(mainevent_patch);
            json_decref(overrides_patch);
            json_decref(old_exp_overrides);
            json_decref(new_exp_overrides);
            json_decref(old_mainevent);
        }
        else {
            /* Apply the patch as provided */
            new_event = jmap_patchobject_apply(old_event, event_patch, invalid);
            if (!new_event) {
                *err = json_pack("{s:s}", "type", "invalidPatch");
                goto done;
            }
        }

        /* Handle UTC time updates */
        if (eventpatch_updates_utctimes(event_patch)) {
            json_t *jnew_overrides = json_object_get(new_event, "recurrenceOverrides");
            if (JNOTNULL(jnew_overrides)) {
                /* Reject UTC times if they differ from old event */
                getcalendarevents_get_utctimes(old_event, jstzones, floatingtz);
                json_t *jnew_utcStart = json_object_get(new_event, "utcStart");
                json_t *jnew_utcEnd = json_object_get(new_event, "utcEnd");
                if (JNOTNULL(jnew_utcStart)) {
                    json_t *jold_utcStart = json_object_get(old_event, "utcStart");
                    if (!json_equal(jold_utcStart, jnew_utcStart)) {
                        json_array_append_new(invalid, json_string("utcStart"));
                    }
                }
                if (JNOTNULL(jnew_utcEnd)) {
                    json_t *jold_utcEnd = json_object_get(old_event, "utcEnd");
                    if (!json_equal(jold_utcEnd, jnew_utcEnd)) {
                        json_array_append_new(invalid, json_string("utcEnd"));
                    }
                }
                json_t *jold_overrides = json_object_get(old_event, "recurrenceOverrides");
                json_t *jnew_override;
                const char *recurid;
                struct buf buf = BUF_INITIALIZER;
                json_object_foreach(jnew_overrides, recurid, jnew_override) {
                    json_t *jold_override = json_object_get(jold_overrides, recurid);
                    jnew_utcStart = json_object_get(jnew_override, "utcStart");
                    jnew_utcEnd = json_object_get(jnew_override, "utcEnd");

                    if (JNOTNULL(jnew_utcStart)) {
                        json_t *jold_utcStart = json_object_get(jold_override, "utcStart");
                        if (!jold_utcStart || !json_equal(jold_utcStart, jnew_utcStart)) {
                            buf_setcstr(&buf, "recurrenceOverrides/");
                            buf_appendcstr(&buf, recurid);
                            buf_appendcstr(&buf, "/utcStart");
                            json_array_append_new(invalid, json_string(buf_cstring(&buf)));
                            buf_reset(&buf);
                        }
                    }
                    if (JNOTNULL(jnew_utcEnd)) {
                        json_t *jold_utcEnd = json_object_get(jold_override, "utcEnd");
                        if (!jold_utcEnd || !json_equal(jold_utcEnd, jnew_utcEnd)) {
                            buf_setcstr(&buf, "recurrenceOverrides/");
                            buf_appendcstr(&buf, recurid);
                            buf_appendcstr(&buf, "/utcEnd");
                            json_array_append_new(invalid, json_string(buf_cstring(&buf)));
                            buf_reset(&buf);
                        }
                    }
                }
                buf_free(&buf);
            } else {
                /* Allow updating UTC times for non-recurring events */
                if (!json_object_get(event_patch, "start")) {
                    json_object_del(new_event, "start");
                }
                if (json_object_get(event_patch, "utcEnd") && !json_object_get(event_patch, "duration")) {
                    json_object_del(new_event, "duration");
                }
                setcalendarevents_set_utctimes(new_event, floatingtz, invalid);
            }
        }
    }

    /* Determine if to bump sequence */
    json_t *jdiff = jmap_patchobject_create(old_event, new_event);
    json_object_del(jdiff, "updated");
    if (!eventpatch_updates_peruserprops_only(jdiff, &participant_ids)) {
        json_int_t oldseq = json_integer_value(json_object_get(old_event, "sequence"));
        json_int_t newseq = json_integer_value(json_object_get(new_event, "sequence"));
        if (newseq <= oldseq) {
            json_int_t newseq = oldseq + 1;
            json_object_set_new(new_event, "sequence", json_integer(newseq));
            json_object_set_new(update, "sequence", json_integer(newseq));
        }
    }
    json_decref(jdiff);

    /* Convert to iCalendar */
    *newical = jmapical_toical(new_event, oldical, invalid, jmapctx);

done:
    jstimezones_free(&jstzones);
    json_decref(new_event);
    strarray_fini(&participant_ids);
    return r;
}

static int setcalendarevents_update(jmap_req_t *req,
                                    struct mailbox *notifmbox,
                                    json_t *event_patch,
                                    struct event_id *eid,
                                    struct caldav_db *db,
                                    json_t *invalid,
                                    int send_scheduling_messages,
                                    json_t *update,
                                    json_t **err)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    int needrights = JACL_UPDATEITEMS|JACL_SETMETADATA;
    int r = 0;

    struct caldav_data *cdata = NULL;
    struct mailbox *mbox = NULL;
    char *mboxname = NULL;
    struct mailbox *dstmbox = NULL;
    char *dstmboxname = NULL;
    struct mboxevent *mboxevent = NULL;
    char *resource = NULL;

    icalcomponent *oldical = NULL;
    icalcomponent *ical = NULL;
    struct index_record record;
    strarray_t schedule_addresses = STRARRAY_INITIALIZER;
    mbentry_t *mbentry = NULL;
    strarray_t del_imapflags = STRARRAY_INITIALIZER;
    json_t *old_event = NULL;

    static int icalendar_max_size = -1;
    if (icalendar_max_size < 0) {
        icalendar_max_size = config_getint(IMAPOPT_ICALENDAR_MAX_SIZE);
        if (icalendar_max_size <= 0) icalendar_max_size = INT_MAX;
    }

    /* Validate calendarId */
    const char *calendarId = NULL;
    json_t *jval = json_object_get(event_patch, "calendarIds");
    if (JNOTNULL(jval)) {
        if (json_object_size(jval) == 1) {
            void *iter = json_object_iter(jval);
            if (json_object_iter_value(iter) == json_true()) {
                calendarId = json_object_iter_key(iter);
            }
        }
        if (calendarId && *calendarId == '#') {
            calendarId = jmap_lookup_id(req, calendarId + 1);
        }
        if (!calendarId || !*calendarId) {
            jmap_parser_invalid(&parser, "calendarIds");
            goto done;
        }
    }

    /* Determine mailbox and resource name of calendar event. */
    r = caldav_lookup_uid(db, eid->uid, &cdata);
    if (r && r != CYRUSDB_NOTFOUND) {
        syslog(LOG_ERR,
               "caldav_lookup_uid(%s) failed: %s", eid->uid, error_message(r));
        goto done;
    }
    if (r == CYRUSDB_NOTFOUND || !cdata->dav.alive ||
            !cdata->dav.rowid || !cdata->dav.imap_uid ||
            cdata->comp_type != CAL_COMP_VEVENT) {
        r = IMAP_NOTFOUND;
        goto done;
    }

    mbentry = jmap_mbentry_from_dav(req, &cdata->dav);

    /* Check permissions. */
    if (!mbentry || !jmap_hasrights_mbentry(req, mbentry, needrights)) {
        if (mbentry) jmap_parser_push(&parser, mbentry->name);
        jmap_parser_invalid(&parser, "calendarIds");
        if (mbentry) jmap_parser_pop(&parser);
        r = 0;
        goto done;
    }

    mboxname = xstrdup(mbentry->name);
    resource = xstrdup(cdata->dav.resource);

    /* Open mailbox for writing */
    r = jmap_openmbox_by_uniqueid(req, mbentry->uniqueid, &mbox, 1);
    if (r == IMAP_MAILBOX_NONEXISTENT) {
        jmap_parser_push(&parser, mbentry->name);
        jmap_parser_invalid(&parser, "calendarIds");
        jmap_parser_pop(&parser);
        r = 0;
        goto done;
    }
    else if (r) {
        syslog(LOG_ERR, "jmap_openmbox(req, %s) failed: %s",
                mboxname, error_message(r));
        goto done;
    }

    /* Fetch index record for the resource */
    memset(&record, 0, sizeof(struct index_record));
    r = mailbox_find_index_record(mbox, cdata->dav.imap_uid, &record);
    if (r == IMAP_NOTFOUND) {
        jmap_parser_push(&parser, mbentry->name);
        jmap_parser_invalid(&parser, "calendarIds");
        jmap_parser_pop(&parser);
        r = 0;
        goto done;
    } else if (r) {
        syslog(LOG_ERR, "mailbox_index_record(0x%x) failed: %s",
                cdata->dav.imap_uid, error_message(r));
        goto done;
    }
    /* Load VEVENT from record, personalizing as needed. */
    oldical = caldav_record_to_ical(mbox, cdata, req->userid, &schedule_addresses);
    if (!oldical) {
        syslog(LOG_ERR, "record_to_ical failed for record %u:%s",
                cdata->dav.imap_uid, mailbox_name(mbox));
        r = IMAP_INTERNAL;
        goto done;
    }
    /* Validate isDraft */
    json_t *jisDraft = json_object_get(event_patch, "isDraft");
    if (json_is_boolean(jisDraft)) {
        if (json_boolean_value(jisDraft)) {
            if (!(record.system_flags & FLAG_DRAFT)) {
                /* Can't set draft flag on non-draft */
                jmap_parser_invalid(&parser, "isDraft");
            }
        }
        else if (record.system_flags & FLAG_DRAFT) {
            strarray_append(&del_imapflags, "\\draft");
        }
    }
    else if (JNOTNULL(jisDraft)) {
        jmap_parser_invalid(&parser, "isDraft");
    }

    /* Read UTC times fallback timezone from source mailbox */
    int tz_is_malloced = 0;
    icaltimezone *floatingtz =
        calendarevent_get_floatingtz(mbentry, req->userid, &tz_is_malloced);

    /* Apply patch */
    struct jmapical_jmapcontext jmapctx;
    jmap_calendarcontext_init(&jmapctx, req);
    old_event = jmapical_tojmap(oldical, NULL, &jmapctx);
    if (!old_event) {
        r = IMAP_INTERNAL;
        goto done;
    }
    json_object_del(old_event, "updated");
    r = setcalendarevents_apply_patch(&jmapctx,
            old_event, event_patch,
            oldical, eid->recurid,
            invalid, &schedule_addresses,
            &ical, floatingtz, update, err);
    jmap_calendarcontext_fini(&jmapctx);

    if (json_array_size(parser.invalid)) {
        r = 0;
        goto done;
    }
    else if (icalendar_max_size != INT_MAX && ical &&
        strlen(icalcomponent_as_ical_string(ical)) > (size_t) icalendar_max_size) {
        r = IMAP_MESSAGE_TOO_LARGE;
        goto done;
    }
    else if (r) goto done;

    if (calendarId) {
        /* Check, if we need to move the event. */
        dstmboxname = caldav_mboxname(req->accountid, calendarId);
        if (strcmp(mailbox_name(mbox), dstmboxname)) {
            /* Check permissions */
            if (!jmap_hasrights(req, dstmboxname, needrights)) {
                jmap_parser_invalid(&parser, "calendarIds");
                r = 0;
                goto done;
            }
            /* Open destination mailbox for writing. */
            r = jmap_openmbox(req, dstmboxname, &dstmbox, 1);
            if (r == IMAP_MAILBOX_NONEXISTENT) {
                jmap_parser_invalid(&parser, "calendarIds");
                r = 0;
                goto done;
            } else if (r) {
                syslog(LOG_ERR, "jmap_openmbox(req, %s) failed: %s",
                        dstmboxname, error_message(r));
                goto done;
            }
        }
    }

    /* Manage attachments */
    int ret = caldav_manage_attachments(req->accountid, ical, oldical);
    if (ret && ret != HTTP_NOT_FOUND) {
        syslog(LOG_ERR, "caldav_manage_attachments: %s", error_message(ret));
        r = IMAP_INTERNAL;
        goto done;
    }

    /* Handle scheduling. */
    get_schedule_addresses(NULL, mboxname, req->userid, &schedule_addresses);
    if (!(record.system_flags & FLAG_DRAFT) && send_scheduling_messages) {
        r = setcalendarevents_schedule(req, &schedule_addresses,
                                       oldical, ical, JMAP_UPDATE);
        if (r) goto done;
    }

    if (dstmbox) {
        /* Expunge the resource from mailbox. */
        record.internal_flags |= FLAG_INTERNAL_EXPUNGED;
        mboxevent = mboxevent_new(EVENT_MESSAGE_EXPUNGE);
        r = mailbox_rewrite_index_record(mbox, &record);
        if (r) {
            syslog(LOG_ERR, "mailbox_rewrite_index_record (%s) failed: %s",
                    cdata->dav.mailbox, error_message(r));
            jmap_closembox(req, &mbox);
            goto done;
        }
        mboxevent_extract_record(mboxevent, mbox, &record);
        mboxevent_extract_mailbox(mboxevent, mbox);
        mboxevent_set_numunseen(mboxevent, mbox, -1);
        mboxevent_set_access(mboxevent, NULL, NULL,
                             req->userid, cdata->dav.mailbox, 0);
        jmap_closembox(req, &mbox);
        mboxevent_notify(&mboxevent);
        mboxevent_free(&mboxevent);

        /* Close the mailbox we moved the event from. */
        jmap_closembox(req, &mbox);
        mbox = dstmbox;
        dstmbox = NULL;
        free(mboxname);
        mboxname = dstmboxname;
        dstmboxname = NULL;
    }


    /* Remove METHOD property */
    remove_itip_properties(ical);

    /* Store the updated VEVENT. */
    struct transaction_t txn;
    memset(&txn, 0, sizeof(struct transaction_t));
    txn.req_hdrs = spool_new_hdrcache();
    txn.userid = req->userid;
    txn.authstate = req->authstate;

    r = proxy_mlookup(mailbox_name(mbox), &txn.req_tgt.mbentry, NULL, NULL);
    if (r) {
        syslog(LOG_ERR, "mlookup(%s) failed: %s", mailbox_name(mbox), error_message(r));
    }
    else {
        r = caldav_store_resource(&txn, ical, mbox, resource, record.createdmodseq,
                                  db, 0, req->userid,
                                  NULL, &del_imapflags, &schedule_addresses);
        if (r == HTTP_CREATED || r == HTTP_NO_CONTENT) {
            json_t *patch_copy = json_deep_copy(event_patch);
            remove_peruserprops(patch_copy);
            remove_peruserprops(old_event);
            if (json_object_size(patch_copy)) {
                int r2 = create_eventnotif(req, notifmbox, mailbox_name(mbox),
                        "updated", eid->uid, &schedule_addresses, NULL,
                        record.system_flags & FLAG_DRAFT, old_event, patch_copy);
                if (r2) {
                    xsyslog(LOG_WARNING, "could not create notification",
                            "uid=%s error=%s", eid->uid, error_message(r2));
                }
            }
            json_decref(patch_copy);
        }
    }
    transaction_free(&txn);
    if (r && r != HTTP_CREATED && r != HTTP_NO_CONTENT) {
        syslog(LOG_ERR, "caldav_store_resource failed for user %s: %s",
               req->accountid, error_message(r));
        goto done;
    }
    r = 0;

    if (jmap_is_using(req, JMAP_CALENDARS_EXTENSION)) {
        struct buf blobid = BUF_INITIALIZER;
        if (jmap_encode_rawdata_blobid('I', mailbox_uniqueid(mbox), mbox->i.last_uid,
                                       req->userid, NULL, NULL, &blobid)) {
            json_object_set_new(update, "blobId",
                                json_string(buf_cstring(&blobid)));
        }
        buf_reset(&blobid);
        if (jmap_encode_rawdata_blobid('I', mailbox_uniqueid(mbox), mbox->i.last_uid,
                                       NULL, NULL, NULL, &blobid)) {
            json_object_set_new(update, "debugBlobId",
                                json_string(buf_cstring(&blobid)));
        }
        buf_free(&blobid);
    }

done:
    if (mbox) jmap_closembox(req, &mbox);
    if (dstmbox) jmap_closembox(req, &dstmbox);
    if (ical) icalcomponent_free(ical);
    if (oldical) icalcomponent_free(oldical);
    if (json_array_size(parser.invalid)) {
        json_array_extend(invalid, parser.invalid);
    }
    jmap_parser_fini(&parser);
    json_decref(old_event);
    strarray_fini(&del_imapflags);
    strarray_fini(&schedule_addresses);
    free(dstmboxname);
    free(resource);
    free(mboxname);
    mboxlist_entry_free(&mbentry);
    return r;
}

static int setcalendarevents_destroy(jmap_req_t *req,
                                     struct mailbox *notifmbox,
                                     struct event_id *eid,
                                     struct caldav_db *db,
                                     int send_scheduling_messages)
{
    int r;
    int needrights = JACL_REMOVEITEMS;

    struct caldav_data *cdata = NULL;
    struct mailbox *mbox = NULL;
    char *mboxname = NULL;
    struct mboxevent *mboxevent = NULL;
    char *resource = NULL;

    icalcomponent *oldical = NULL;
    icalcomponent *ical = NULL;
    struct index_record record;
    strarray_t schedule_addresses = STRARRAY_INITIALIZER;
    mbentry_t *mbentry = NULL;

    if (eid->recurid) {
        /* Destroying a recurrence instance is setting it excluded */
        json_t *event_patch = json_pack("{s:b}", "excluded", 1);
        json_t *invalid = json_array();
        json_t *update = NULL;
        json_t *err = NULL;
        r = setcalendarevents_update(req, notifmbox, event_patch, eid, db,
                invalid, send_scheduling_messages, update, &err);
        json_decref(event_patch);
        json_decref(update);
        if (err || (!r && json_array_size(invalid))) {
            r = IMAP_INTERNAL;
            json_decref(err);
        }
        json_decref(invalid);
        return r;
    }

    /* Determine mailbox and resource name of calendar event. */
    r = caldav_lookup_uid(db, eid->uid, &cdata);
    if (r) {
        syslog(LOG_ERR,
               "caldav_lookup_uid(%s) failed: %s", eid->uid, cyrusdb_strerror(r));
        r = CYRUSDB_NOTFOUND ? IMAP_NOTFOUND : IMAP_INTERNAL;
        goto done;
    }

    mbentry = jmap_mbentry_from_dav(req, &cdata->dav);

    /* Check permissions. */
    if (!mbentry || !jmap_hasrights_mbentry(req, mbentry, JACL_READITEMS)) {
        r = IMAP_NOTFOUND;
        goto done;
    }
    if (!jmap_hasrights_mbentry(req, mbentry, needrights)) {
        r = IMAP_PERMISSION_DENIED;
        goto done;
    }

    mboxname = xstrdup(mbentry->name);
    resource = xstrdup(cdata->dav.resource);

    /* Open mailbox for writing */
    r = jmap_openmbox(req, mboxname, &mbox, 1);
    if (r) {
        syslog(LOG_ERR, "jmap_openmbox(req, %s) failed: %s",
                mboxname, error_message(r));
        goto done;
    }

    /* Fetch index record for the resource. Need this for scheduling. */
    memset(&record, 0, sizeof(struct index_record));
    r = mailbox_find_index_record(mbox, cdata->dav.imap_uid, &record);
    if (r) {
        syslog(LOG_ERR, "mailbox_index_record(0x%x) failed: %s",
                cdata->dav.imap_uid, error_message(r));
        goto done;
    }
    /* Load VEVENT from record. */
    oldical = record_to_ical(mbox, &record, &schedule_addresses);
    if (!oldical) {
        syslog(LOG_ERR, "record_to_ical failed for record %u:%s",
                cdata->dav.imap_uid, mailbox_name(mbox));
        r = IMAP_INTERNAL;
        goto done;
    }

    /* Handle scheduling. */
    get_schedule_addresses(NULL, mboxname, req->userid, &schedule_addresses);
    if (!(record.system_flags & FLAG_DRAFT) && send_scheduling_messages) {
        r = setcalendarevents_schedule(req, &schedule_addresses,
                                       oldical, ical, JMAP_DESTROY);
        if (r) goto done;
    }

    /* Manage attachments */
    int ret = caldav_manage_attachments(req->accountid, NULL, oldical);
    if (ret && ret != HTTP_NOT_FOUND) {
        syslog(LOG_ERR, "caldav_manage_attachments: %s", error_message(ret));
        r = IMAP_INTERNAL;
        goto done;
    }

    /* Expunge the resource from mailbox. */
    record.internal_flags |= FLAG_INTERNAL_EXPUNGED;
    mboxevent = mboxevent_new(EVENT_MESSAGE_EXPUNGE);
    r = mailbox_rewrite_index_record(mbox, &record);
    if (r) {
        syslog(LOG_ERR, "mailbox_rewrite_index_record (%s) failed: %s",
                cdata->dav.mailbox, error_message(r));
        jmap_closembox(req, &mbox);
        goto done;
    }

    /* Create notification */
    struct jmapical_jmapcontext jmapctx;
    jmap_calendarcontext_init(&jmapctx, req);
    json_t *old_event = jmapical_tojmap(oldical, NULL, &jmapctx);
    json_object_del(old_event, "updated");
    remove_peruserprops(old_event);
    int r2 = create_eventnotif(req, notifmbox, mailbox_name(mbox), "destroyed", eid->uid,
            &schedule_addresses, NULL,
            record.system_flags & FLAG_DRAFT, old_event, NULL);
    if (r2) {
        xsyslog(LOG_WARNING, "could not create notification",
                "uid=%s error=%s", eid->uid, error_message(r2));
    }
    json_decref(old_event);
    jmap_calendarcontext_fini(&jmapctx);

    /* Create mboxevent */
    mboxevent_extract_record(mboxevent, mbox, &record);
    mboxevent_extract_mailbox(mboxevent, mbox);
    mboxevent_set_numunseen(mboxevent, mbox, -1);
    mboxevent_set_access(mboxevent, NULL, NULL,
                         req->userid, cdata->dav.mailbox, 0);
    mboxevent_notify(&mboxevent);
    mboxevent_free(&mboxevent);

done:
    if (mbox) jmap_closembox(req, &mbox);
    if (oldical) icalcomponent_free(oldical);
    strarray_fini(&schedule_addresses);
    free(resource);
    free(mboxname);
    mboxlist_entry_free(&mbentry);
    return r;
}

static struct event_id *setcalendarevents_parse_id(jmap_req_t *req, const char *id)
{
    if (id && id[0] == '#') {
        const char *newid = jmap_lookup_id(req, id + 1);
        if (!newid) return NULL;
        id = newid;
    }
    return parse_eventid(id);
}

static int setcalendarevents_parse_args(jmap_req_t *req __attribute__((unused)),
                                        struct jmap_parser *parser __attribute__((unused)),
                                        const char *arg,
                                        json_t *val,
                                        void *vrock)
{
    int *send_scheduling_messages = vrock;

    if (!strcmp(arg, "sendSchedulingMessages")) {
        if (json_is_boolean(val)) {
            *send_scheduling_messages = json_boolean_value(val);
            return 1;
        }
    }

    return 0;
}

static int jmap_calendarevent_set(struct jmap_req *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_set set;
    json_t *err = NULL;
    struct caldav_db *db = NULL;
    struct event_id *eid = NULL;
    const char *id;
    int r = 0;
    int send_scheduling_messages = 1;
    struct mailbox *notifmbox = NULL;
    mbentry_t *notifmb = NULL;

    /* Parse arguments */
    jmap_set_parse(req, &parser, event_props, setcalendarevents_parse_args,
                   &send_scheduling_messages, &set, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    if (set.if_in_state) {
        /* TODO rewrite state function to use char* not json_t* */
        json_t *jstate = json_string(set.if_in_state);
        if (jmap_cmpstate(req, jstate, MBTYPE_CALENDAR)) {
            jmap_error(req, json_pack("{s:s}", "type", "stateMismatch"));
            goto done;
        }
        json_decref(jstate);
        set.old_state = xstrdup(set.if_in_state);
    }
    else {
        json_t *jstate = jmap_getstate(req, MBTYPE_CALENDAR, /*refresh*/0);
        set.old_state = xstrdup(json_string_value(jstate));
        json_decref(jstate);
    }

    r = caldav_create_defaultcalendars(req->accountid,
                                       &httpd_namespace, httpd_authstate, NULL);
    if (r == IMAP_MAILBOX_NONEXISTENT) {
        /* The account exists but does not have a root mailbox. */
        json_t *err = json_pack("{s:s}", "type", "accountNoCalendars");
        json_array_append_new(req->response, json_pack("[s,o,s]",
                    "error", err, req->tag));
        return 0;
    } else if (r) return r;

    db = caldav_open_userid(req->accountid);
    if (!db) {
        syslog(LOG_ERR, "caldav_open_mailbox failed for user %s", req->userid);
        r = IMAP_INTERNAL;
        goto done;
    }

    /* Open notifications mailbox, but continue even on error. */
    r = create_notify_collection(req->accountid, &notifmb);
    if (!r) {
        r = jmap_openmbox(req, notifmb->name, &notifmbox, 1);
    }
    if (r) {
        xsyslog(LOG_WARNING, "can not open jmapnotify collection",
                "accountid=%s error=%s", req->accountid, error_message(r));
        r = 0;
    }

    /* create */
    const char *key;
    json_t *arg;
    json_object_foreach(set.create, key, arg) {
        /* Validate calendar event id. */
        if (!strlen(key)) {
            json_t *err= json_pack("{s:s}", "type", "invalidArguments");
            json_object_set_new(set.not_created, key, err);
            continue;
        }

        /* Create the calendar event. */
        json_t *invalid = json_array();
        json_t *create = json_object();
        r = setcalendarevents_create(req, req->accountid, notifmbox, arg, db,
                                     invalid, send_scheduling_messages, create);
        if (r) {
            json_t *err = NULL;
            switch (r) {
                case HTTP_FORBIDDEN:
                case IMAP_PERMISSION_DENIED:
                    err = json_pack("{s:s}", "type", "forbidden");
                    break;
                case IMAP_QUOTA_EXCEEDED:
                    err = json_pack("{s:s}", "type", "overQuota");
                    break;
                case IMAP_MESSAGE_TOO_LARGE:
                    err = json_pack("{s:s}", "type", "tooLarge");
                    break;
                default:
                    err = jmap_server_error(r);
            }
            json_object_set_new(set.not_created, key, err);
            json_decref(create);
            json_decref(invalid);
            r = 0;
            continue;
        }
        else if (json_array_size(invalid)) {
            json_t *err = json_pack("{s:s s:o}",
                                    "type", "invalidProperties",
                                    "properties", invalid);
            json_object_set_new(set.not_created, key, err);
            json_decref(create);
            continue;
        }
        json_decref(invalid);

        /* Report calendar event as created. */
        const char *id = json_string_value(json_object_get(create, "id"));
        json_object_set_new(set.created, key, create);
        jmap_add_id(req, key, id);
    }


    /* update */
    json_object_foreach(set.update, id, arg) {
        free_eventid(&eid);

        eid = setcalendarevents_parse_id(req, id);
        if (!eid) {
            json_object_set_new(set.not_updated, id,
                    json_pack("{s:s}", "type", "notFound"));
            continue;
        }

        const char *uidval = NULL;
        if ((uidval = json_string_value(json_object_get(arg, "uid")))) {
            /* The uid property must match the current iCalendar UID */
            if (strcmp(uidval, eid->uid)) {
                json_t *err = json_pack(
                    "{s:s, s:o}",
                    "type", "invalidProperties",
                    "properties", json_pack("[s]"));
                json_object_set_new(set.not_updated, eid->raw, err);
                continue;
            }
        }

        /* Update the calendar event. */
        json_t *invalid = json_array();
        json_t *update = json_object();
        json_t *err = NULL;
        r = setcalendarevents_update(req, notifmbox, arg, eid, db, invalid,
                                     send_scheduling_messages, update, &err);
        if (r || err) {
            if (!err) {
                switch (r) {
                    case IMAP_NOTFOUND:
                        err = json_pack("{s:s}", "type", "notFound");
                        break;
                    case HTTP_FORBIDDEN:
                    case IMAP_PERMISSION_DENIED:
                        err = json_pack("{s:s}", "type", "forbidden");
                        break;
                    case HTTP_NO_STORAGE:
                    case IMAP_QUOTA_EXCEEDED:
                        err = json_pack("{s:s}", "type", "overQuota");
                        break;
                    case IMAP_MESSAGE_TOO_LARGE:
                        err = json_pack("{s:s}", "type", "tooLarge");
                        break;
                    default:
                        err = jmap_server_error(r);
                }
            }
            json_object_set_new(set.not_updated, eid->raw, err);
            json_decref(invalid);
            json_decref(update);
            r = 0;
            continue;
        }

        if (json_array_size(invalid)) {
            json_t *err = json_pack(
                "{s:s, s:o}", "type", "invalidProperties",
                "properties", invalid);
            json_object_set_new(set.not_updated, eid->raw, err);
            json_decref(update);
            continue;
        }
        json_decref(invalid);

        if(!json_object_size(update)) {
            json_decref(update);
            update = json_null();
        }

        /* Report calendar event as updated. */
        json_object_set_new(set.updated, eid->raw, update);
    }
    free_eventid(&eid);


    /* destroy */
    size_t index;
    json_t *juid;

    json_array_foreach(set.destroy, index, juid) {
        free_eventid(&eid);

        const char *id = json_string_value(juid);
        if (!id) continue;

        eid = setcalendarevents_parse_id(req, id);
        if (!eid) {
            json_object_set_new(set.not_destroyed, id,
                    json_pack("{s:s}", "type", "notFound"));
            continue;
        }

        /* Destroy the calendar event. */
        r = setcalendarevents_destroy(req, notifmbox, eid, db,
                                      send_scheduling_messages);
        if (r == IMAP_NOTFOUND) {
            json_t *err = json_pack("{s:s}", "type", "notFound");
            json_object_set_new(set.not_destroyed, eid->raw, err);
            r = 0;
            continue;
        } else if (r == IMAP_PERMISSION_DENIED) {
            json_t *err = json_pack("{s:s}", "type", "forbidden");
            json_object_set_new(set.not_destroyed, eid->raw, err);
            r = 0;
            continue;
        } else if (r) {
            goto done;
        }

        /* Report calendar event as destroyed. */
        json_array_append_new(set.destroyed, json_string(eid->raw));
    }
    free_eventid(&eid);


    // TODO refactor jmap_getstate to return a string, once
    // all code has been migrated to the new JMAP parser.
    json_t *jstate = jmap_getstate(req, MBTYPE_CALENDAR, /*refresh*/1);
    set.new_state = xstrdup(json_string_value(jstate));
    json_decref(jstate);

    jmap_ok(req, jmap_set_reply(&set));

done:
    jmap_closembox(req, &notifmbox);
    mboxlist_entry_free(&notifmb);
    jmap_parser_fini(&parser);
    jmap_set_fini(&set);
    if (db) caldav_close(db);
    free_eventid(&eid);
    return r;
}

struct geteventchanges_rock {
    jmap_req_t *req;
    struct jmap_changes *changes;
    size_t seen_records;
    modseq_t highestmodseq;
    int check_acl;
    hash_table *mboxrights;
};

static void strip_spurious_deletes(struct geteventchanges_rock *urock)
{
    /* if something is mentioned in both DELETEs and UPDATEs, it's probably
     * a move.  O(N*M) algorithm, but there are rarely many, and the alternative
     * of a hash will cost more */
    unsigned i, j;

    for (i = 0; i < json_array_size(urock->changes->destroyed); i++) {
        const char *del = json_string_value(json_array_get(urock->changes->destroyed, i));

        for (j = 0; j < json_array_size(urock->changes->updated); j++) {
            const char *up =
                json_string_value(json_array_get(urock->changes->updated, j));
            if (!strcmpsafe(del, up)) {
                json_array_remove(urock->changes->destroyed, i--);
                break;
            }
        }
    }
}

static int geteventchanges_cb(void *vrock, struct caldav_data *cdata)
{
    struct geteventchanges_rock *rock = vrock;
    jmap_req_t *req = rock->req;
    struct jmap_changes *changes = rock->changes;
    mbentry_t *mbentry = jmap_mbentry_from_dav(req, &cdata->dav);

    /* Check permissions */
    int rights = mbentry ? jmap_hasrights_mbentry(req, mbentry, JACL_READITEMS) : 0;
    mboxlist_entry_free(&mbentry);
    if (!rights)
        return 0;

    if (cdata->comp_type != CAL_COMP_VEVENT)
        return 0;

    /* Count, but don't process items that exceed the maximum record count. */
    if (changes->max_changes && ++(rock->seen_records) > changes->max_changes) {
        changes->has_more_changes = 1;
        return 0;
    }

    /* Report item as updated or destroyed. */
    if (cdata->dav.alive) {
        if (cdata->dav.createdmodseq <= changes->since_modseq)
            json_array_append_new(changes->updated, json_string(cdata->ical_uid));
        else
            json_array_append_new(changes->created, json_string(cdata->ical_uid));
    } else {
        if (cdata->dav.createdmodseq <= changes->since_modseq)
            json_array_append_new(changes->destroyed, json_string(cdata->ical_uid));
    }

    if (cdata->dav.modseq > rock->highestmodseq) {
        rock->highestmodseq = cdata->dav.modseq;
    }

    return 0;
}

static int jmap_calendarevent_changes(struct jmap_req *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_changes changes;
    json_t *err = NULL;
    struct caldav_db *db;
    struct geteventchanges_rock rock = {
        req,
        &changes,
        0            /*seen_records*/,
        0            /*highestmodseq*/,
        strcmp(req->accountid, req->userid) /* check_acl */,
        NULL         /*mboxrights*/
    };
    int r = 0;

    db = caldav_open_userid(req->accountid);
    if (!db) {
        syslog(LOG_ERR, "caldav_open_mailbox failed for user %s", req->accountid);
        r = IMAP_INTERNAL;
        goto done;
    }

    /* Parse request */
    jmap_changes_parse(req, &parser, req->counters.caldavdeletedmodseq,
                       NULL, NULL, &changes, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    /* Lookup changes. */
    r = caldav_get_updates(db, changes.since_modseq, NULL /*mbentry*/,
                           CAL_COMP_VEVENT, 
                           changes.max_changes ? (int) changes.max_changes + 1 : -1,
                           &geteventchanges_cb, &rock);
    if (r) goto done;
    strip_spurious_deletes(&rock);

    /* Determine new state. */
    changes.new_modseq = changes.has_more_changes ?
        rock.highestmodseq : jmap_highestmodseq(req, MBTYPE_CALENDAR);

    /* Build response */
    jmap_ok(req, jmap_changes_reply(&changes));

  done:
    jmap_changes_fini(&changes);
    jmap_parser_fini(&parser);
    if (rock.mboxrights) {
        free_hash_table(rock.mboxrights, free);
        free(rock.mboxrights);
    }
    if (db) caldav_close(db);
    if (r) {
        jmap_error(req, jmap_server_error(r));
    }
    return 0;
}

static void eventquery_read_timerange(json_t *filter, time_t *before, time_t *after)
{
    *before = caldav_eternity;
    *after = caldav_epoch;

    if (!JNOTNULL(filter)) {
        return;
    }

    if (json_object_get(filter, "conditions")) {
        json_t *val;
        size_t i;
        time_t bf, af;

        json_array_foreach(json_object_get(filter, "conditions"), i, val) {
            const char *op =
                json_string_value(json_object_get(filter, "operator"));
            bf = caldav_eternity;
            af = caldav_epoch;

            eventquery_read_timerange(val, &bf, &af);

            if (bf != caldav_eternity) {
                if (!strcmp(op, "OR")) {
                    if (*before == caldav_eternity || *before < bf) {
                        *before = bf;
                    }
                }
                else if (!strcmp(op, "AND")) {
                    if (*before == caldav_eternity || *before > bf) {
                        *before = bf;
                    }
                }
                else if (!strcmp(op, "NOT")) {
                    if (*after == caldav_epoch || *after < bf) {
                        *after = bf;
                    }
                }
            }

            if (af != caldav_epoch) {
                if (!strcmp(op, "OR")) {
                    if (*after == caldav_epoch || *after > af) {
                        *after = af;
                    }
                }
                else if (!strcmp(op, "AND")) {
                    if (*after == caldav_epoch || *after < af) {
                        *after = af;
                    }
                }
                else if (!strcmp(op, "NOT")) {
                    if (*before == caldav_eternity || *before < af) {
                        *before = af;
                    }
                }
            }
        }
    } else {
        const char *sb = json_string_value(json_object_get(filter, "before"));
        const char *sa = json_string_value(json_object_get(filter, "after"));

        if (!sb || time_from_iso8601(sb, before) == -1) {
            *before = caldav_eternity;
        }
        if (!sa || time_from_iso8601(sa, after) == -1) {
            *after = caldav_epoch;
        }
    }
}

static int eventquery_have_textsearch(json_t *filter)
{
    if (!JNOTNULL(filter))
        return 0;

    json_t *jval;
    size_t i;
    json_array_foreach(json_object_get(filter, "conditions"), i, jval) {
        if (eventquery_have_textsearch(jval))
            return 1;
    }

    if (json_object_get(filter, "inCalendars") ||
        json_object_get(filter, "text") ||
        json_object_get(filter, "title") ||
        json_object_get(filter, "description") ||
        json_object_get(filter, "location") ||
        json_object_get(filter, "owner") ||
        json_object_get(filter, "attendee")) {
        return 1;
    }

    return 0;
}

struct eventquery_match {
    char *ical_uid;
    char *utcstart;
    icalcomponent *ical;
    char *recurid;
};

static void eventquery_match_fini(struct eventquery_match *match)
{
    if (!match) return;
    free(match->ical_uid);
    free(match->utcstart);
    free(match->recurid);
    if (match->ical) icalcomponent_free(match->ical);
}

static void eventquery_match_free(struct eventquery_match **matchp) {
    if (!matchp || !*matchp) return;
    eventquery_match_fini(*matchp);
    free(*matchp);
    *matchp = NULL;
}

struct eventquery_cmp_rock {
    enum caldav_sort *sort;
    size_t nsort;
};

static int eventquery_cmp QSORT_R_COMPAR_ARGS(const void *va,
                                              const void *vb,
                                              void *vrock)
{
    enum caldav_sort *sort = ((struct eventquery_cmp_rock*)vrock)->sort;
    size_t nsort = ((struct eventquery_cmp_rock*)vrock)->nsort;
    struct eventquery_match *ma = (struct eventquery_match*) *(void**)va;
    struct eventquery_match *mb = (struct eventquery_match*) *(void**)vb;
    size_t i;

    for (i = 0; i < nsort; i++) {
        int ret = 0;
        switch (sort[i] & ~CAL_SORT_DESC) {
            case CAL_SORT_UID:
                ret = strcmp(ma->ical_uid, mb->ical_uid);
                break;
            case CAL_SORT_START:
                ret = strcmp(ma->utcstart, mb->utcstart);
                break;
            default:
                ret = 0;
        }
        if (ret)
            return sort[i] & CAL_SORT_DESC ? -ret : ret;
    }

    return 0;
}

struct eventquery_rock {
    jmap_req_t *req;
    int expandrecur;
    struct mailbox *mailbox;
    ptrarray_t *matches;
    const char *sched_inboxname;
    const char *sched_outboxname;
};

static int eventquery_cb(void *vrock, struct caldav_data *cdata)
{
    struct eventquery_rock *rock = vrock;
    jmap_req_t *req = rock->req;
    int r = 0;

    if (!cdata->dav.alive || cdata->comp_type != CAL_COMP_VEVENT) {
        return 0;
    }

    mbentry_t *mbentry = jmap_mbentry_from_dav(req, &cdata->dav);

    /* Check permissions */
    int rights = mbentry ? jmap_hasrights_mbentry(req, mbentry, JACL_READITEMS) : 0;
    if (!rights) goto done;

    if (!strcmpsafe(mbentry->name, rock->sched_inboxname) ||
        !strcmpsafe(mbentry->name, rock->sched_outboxname))
        goto done;

    struct eventquery_match *match = xzmalloc(sizeof(struct eventquery_match));
    match->ical_uid = xstrdup(cdata->ical_uid);
    match->utcstart = xstrdup(cdata->dtstart);
    if (rock->expandrecur) {
        /* Load iCalendar data */
        if (!rock->mailbox || strcmp(mailbox_name(rock->mailbox), mbentry->name)) {
            if (rock->mailbox) {
                jmap_closembox(req, &rock->mailbox);
            }
            r = jmap_openmbox(req, mbentry->name, &rock->mailbox, 0);
            if (r) goto done;
        }
        match->ical = caldav_record_to_ical(rock->mailbox, cdata, req->userid, NULL);
        if (!match->ical) {
            syslog(LOG_ERR, "%s: can't load ical for ical uid %s",
                    __func__, cdata->ical_uid);
            eventquery_match_free(&match);
            r = IMAP_INTERNAL;
        }
    }
    ptrarray_append(rock->matches, match);

 done:
    mboxlist_entry_free(&mbentry);
    return r;
}

static void eventquery_textsearch_match(search_expr_t *parent, const char *s, const char *name)
{
    search_expr_t *e;
    const search_attr_t *attr = search_attr_find(name);

    e = search_expr_new(parent, SEOP_FUZZYMATCH);
    e->attr = attr;
    e->value.s = xstrdup(s);
    if (!e->value.s) {
        e->op = SEOP_FALSE;
        e->attr = NULL;
    }
}

static search_expr_t *eventquery_textsearch_build(jmap_req_t *req,
                                                  json_t *filter,
                                                  search_expr_t *parent)
{
    search_expr_t *this, *e;
    const char *s;
    size_t i;
    json_t *val, *arg;

    if (!JNOTNULL(filter)) {
        return search_expr_new(parent, SEOP_TRUE);
    }

    if ((s = json_string_value(json_object_get(filter, "operator")))) {
        enum search_op op = SEOP_UNKNOWN;

        if (!strcmp("AND", s)) {
            op = SEOP_AND;
        } else if (!strcmp("OR", s)) {
            op = SEOP_OR;
        } else if (!strcmp("NOT", s)) {
            op = SEOP_NOT;
        }

        this = search_expr_new(parent, op);
        e = op == SEOP_NOT ? search_expr_new(this, SEOP_OR) : this;

        json_array_foreach(json_object_get(filter, "conditions"), i, val) {
            eventquery_textsearch_build(req, val, e);
        }
    } else {
        this = search_expr_new(parent, SEOP_AND);

        if ((arg = json_object_get(filter, "inCalendars"))) {
            e = search_expr_new(this, SEOP_OR);
            json_array_foreach(arg, i, val) {
                const char *id = json_string_value(val);
                search_expr_t *m = search_expr_new(e, SEOP_MATCH);
                m->attr = search_attr_find("folder");
                m->value.s = caldav_mboxname(req->accountid, id);
            }
        }

        if ((s = json_string_value(json_object_get(filter, "text")))) {
            e = search_expr_new(this, SEOP_OR);
            eventquery_textsearch_match(e, s, "body");
            eventquery_textsearch_match(e, s, "subject");
            eventquery_textsearch_match(e, s, "from");
            eventquery_textsearch_match(e, s, "to");
            eventquery_textsearch_match(e, s, "location");
        }
        if ((s = json_string_value(json_object_get(filter, "title")))) {
            eventquery_textsearch_match(this, s, "subject");
        }
        if ((s = json_string_value(json_object_get(filter, "description")))) {
            eventquery_textsearch_match(this, s, "body");
        }
        if ((s = json_string_value(json_object_get(filter, "location")))) {
            eventquery_textsearch_match(this, s, "location");
        }
        if ((s = json_string_value(json_object_get(filter, "owner")))) {
            eventquery_textsearch_match(this, s, "from");
        }
        if ((s = json_string_value(json_object_get(filter, "attendee")))) {
            eventquery_textsearch_match(this, s, "to");
        }
    }

    return this;
}


static int eventquery_search_run(jmap_req_t *req,
                                 json_t *filter,
                                 struct caldav_db *db,
                                 time_t before, time_t after,
                                 enum caldav_sort *sort,
                                 size_t nsort,
                                 int expandrecur,
                                 const char *sched_inboxname,
                                 const char *sched_outboxname,
                                 ptrarray_t *matches)
{
    int r, i;
    struct searchargs *searchargs = NULL;
    struct index_init init;
    struct index_state *state = NULL;
    search_query_t *query = NULL;
    struct sortcrit *sortcrit = NULL;
    struct buf buf = BUF_INITIALIZER;
    char *icalbefore = NULL;
    char *icalafter = NULL;
    icaltimezone *utc = icaltimezone_get_utc_timezone();
    struct mailbox *mailbox = NULL;
    const char *wantuid = json_string_value(json_object_get(filter, "uid"));

    if (before != caldav_eternity) {
        icaltimetype t = icaltime_from_timet_with_zone(before, 0, utc);
        icalbefore = icaltime_as_ical_string_r(t);
    }
    if (after != caldav_epoch) {
        icaltimetype t = icaltime_from_timet_with_zone(after, 0, utc);
        icalafter = icaltime_as_ical_string_r(t);
    }

    /* Build searchargs */
    searchargs = new_searchargs(NULL, GETSEARCH_CHARSET_FIRST,
            &jmap_namespace, req->accountid, req->authstate, 0);
    searchargs->root = eventquery_textsearch_build(req, filter, NULL);

    sortcrit = xzmalloc(2 * sizeof(struct sortcrit));
    sortcrit[0].key = SORT_FOLDER;
    sortcrit[1].key = SORT_SEQUENCE;

    /* Run the search query */
    memset(&init, 0, sizeof(init));
    init.userid = req->accountid;
    init.authstate = req->authstate;
    init.want_expunged = 0;
    init.want_mbtype = MBTYPE_CALENDAR;
    init.examine_mode = 1;

    char *mboxname = mboxname_user_mbox(req->accountid, config_getstring(IMAPOPT_CALENDARPREFIX));
    r = index_open(mboxname, &init, &state);
    free(mboxname);
    if (r) goto done;

    query = search_query_new(state, searchargs);
    query->sortcrit = sortcrit;
    query->multiple = 1;
    query->need_ids = 1;
    query->want_expunged = 0;
    query->want_mbtype = MBTYPE_CALENDAR;
    r = search_query_run(query);
    if (r && r != IMAP_NOTFOUND) goto done;

    /* Process result */
    for (i = 0 ; i < query->merged_msgdata.count; i++) {
        MsgData *md = ptrarray_nth(&query->merged_msgdata, i);
        search_folder_t *folder = md->folder;
        struct caldav_data *cdata;
        mbentry_t *mbentry = NULL;

        if (!folder) continue;

        mboxlist_lookup_allow_all(folder->mboxname, &mbentry, NULL);

        /* Check permissions */
        if (!mbentry || !jmap_hasrights_mbentry(req, mbentry, JACL_READITEMS)) {
            mboxlist_entry_free(&mbentry);
            continue;
        }

        if (!strcmpsafe(mbentry->name, sched_inboxname) ||
            !strcmpsafe(mbentry->name, sched_outboxname)) {
            mboxlist_entry_free(&mbentry);
            goto done;
        }

        /* Fetch the CalDAV db record */
        if (caldav_lookup_imapuid(db, mbentry, md->uid, &cdata, 0) == 0) {

            /* Check time-range */
            if (icalafter && strcmp(cdata->dtend, icalafter) <= 0) {
                mboxlist_entry_free(&mbentry);
                continue;
            }
            if (icalbefore && strcmp(cdata->dtstart, icalbefore) >= 0) {
                mboxlist_entry_free(&mbentry);
                continue;
            }

            if (wantuid && strcmp(wantuid, cdata->ical_uid))
                continue;

            struct eventquery_match *match = xzmalloc(sizeof(struct eventquery_match));
            match->ical_uid = xstrdup(cdata->ical_uid);
            match->utcstart = xstrdup(cdata->dtstart);
            if (expandrecur) {
                /* Load iCalendar data */
                if (!mailbox || strcmp(mailbox_name(mailbox), mbentry->name)) {
                    if (mailbox) {
                        jmap_closembox(req, &mailbox);
                    }
                    r = jmap_openmbox(req, mbentry->name, &mailbox, 0);
                }

                match->ical = caldav_record_to_ical(mailbox, cdata, req->userid, NULL);
                if (!match->ical) {
                    syslog(LOG_ERR, "%s: can't load ical for ical uid %s",
                           __func__, cdata->ical_uid);
                    free(match->ical_uid);
                    free(match->utcstart);
                    free(match);
                    r = IMAP_INTERNAL;
                }
            }
            ptrarray_append(matches, match);
        }

        mboxlist_entry_free(&mbentry);
        if (r) goto done;
    }

    if (!expandrecur) {
        struct eventquery_cmp_rock rock = { sort, nsort };
        cyr_qsort_r(matches->data, matches->count, sizeof(void*),
                    (int(*)(const void*, const void*, void*))eventquery_cmp, &rock);
    }

    r = 0;

done:
    index_close(&state);
    if (searchargs) freesearchargs(searchargs);
    if (sortcrit) freesortcrit(sortcrit);
    if (query) search_query_free(query);
    jmap_closembox(req, &mailbox);
    free(icalbefore);
    free(icalafter);
    buf_free(&buf);
    return r;
}

struct eventquery_fastpath_rock {
    jmap_req_t *req;
    struct jmap_query *query;
    const char *sched_inboxname;
    const char *sched_outboxname;
};

static int eventquery_fastpath_cb(void *vrock, struct caldav_data *cdata)
{
    struct eventquery_fastpath_rock *rock = vrock;
    jmap_req_t *req = rock->req;
    struct jmap_query *query = rock->query;

    assert(query->position >= 0);

    /* Check type and permissions */
    if (!cdata->dav.alive || cdata->comp_type != CAL_COMP_VEVENT) {
        return 0;
    }

    mbentry_t *mbentry = jmap_mbentry_from_dav(req, &cdata->dav);
    if (!mbentry) return 0;

    /* don't include the scheduling magic calendars */
    if (!strcmpsafe(mbentry->name, rock->sched_inboxname) ||
        !strcmpsafe(mbentry->name, rock->sched_outboxname)) {
        mboxlist_entry_free(&mbentry);
        return 0;
    }

    /* Check permissions */
    int rights = jmap_hasrights_mbentry(req, mbentry, JACL_READITEMS);
    mboxlist_entry_free(&mbentry);
    if (!rights) return 0;

    query->total++;

    /* Check search window */
    if (query->have_limit && json_array_size(query->ids) >= query->limit) {
        return 0;
    }
    if (query->position && (size_t) query->position <= query->total - 1) {
        return 0;
    }

    json_array_append_new(query->ids, json_string(cdata->ical_uid));

    return 0;
}

struct eventquery_recur_rock {
    ptrarray_t *matches;
    struct buf *buf;
    icaltimetype lastseen;
};

static const char *eventquery_recur_make_recurid(icalcomponent *comp,
                                                 icaltimetype start,
                                                 struct buf *buf)
{
    struct jmapical_datetime recuriddt = JMAPICAL_DATETIME_INITIALIZER;

    icalproperty *prop;
    if ((prop = icalcomponent_get_first_property(comp, ICAL_RECURRENCEID_PROPERTY))) {
        /* Recurrence override. */
        jmapical_datetime_from_icalprop(prop, &recuriddt);
    }
    else {
        /* RDATE or regular reccurence instance */
        for (prop = icalcomponent_get_first_property(comp, ICAL_RDATE_PROPERTY);
             prop;
             prop = icalcomponent_get_next_property(comp, ICAL_RDATE_PROPERTY)) {
            /* Read subseconds from RDATE */
            struct icaldatetimeperiodtype tval = icalproperty_get_rdate(prop);
            if (icaltime_compare(tval.time, start)) {
                /* XXX - could handle PERIOD type here */
                struct jmapical_datetime tmpdt = JMAPICAL_DATETIME_INITIALIZER;
                jmapical_datetime_from_icalprop(prop, &tmpdt);
                recuriddt.nano = tmpdt.nano;
                break;
            }
        }
        if (!recuriddt.nano) {
            /* Read subseconds from DTSTART */
            jmapical_datetime_from_icaltime(start, &recuriddt);
            prop = icalcomponent_get_first_property(comp, ICAL_DTSTART_PROPERTY);
            struct jmapical_datetime tmpdt = JMAPICAL_DATETIME_INITIALIZER;
            if (prop) jmapical_datetime_from_icalprop(prop, &tmpdt);
            recuriddt.nano = tmpdt.nano;
        }
    }

    buf_reset(buf);
    jmapical_localdatetime_as_string(&recuriddt, buf);
    return buf_cstring(buf);
}

static int eventquery_recur_cb(icalcomponent *comp,
                               icaltimetype start,
                               icaltimetype end __attribute__((unused)),
                               void *vrock)
{
    struct eventquery_recur_rock *rock = vrock;

    if (icaltime_compare(rock->lastseen, start)) {
        icaltimezone *utc = icaltimezone_get_utc_timezone();
        icaltimetype utcstart = icaltime_convert_to_zone(start, utc);

        struct eventquery_match *match = xzmalloc(sizeof(struct eventquery_match));
        match->ical_uid = xstrdup(icalcomponent_get_uid(comp));
        match->utcstart = xstrdup(icaltime_as_ical_string(utcstart));
        match->recurid = xstrdup(eventquery_recur_make_recurid(comp, start, rock->buf));
        ptrarray_append(rock->matches, match);
    }
    rock->lastseen = start;

    return 1;
}

static int eventquery_run(jmap_req_t *req,
                          struct jmap_query *query,
                          int expandrecur,
                          json_t **err)
{
    time_t before = caldav_eternity;
    time_t after = caldav_epoch;
    int r = HTTP_NOT_IMPLEMENTED;
    enum caldav_sort *sort = NULL;
    size_t nsort = 0;
    char *sched_inboxname = caldav_mboxname(req->accountid, SCHED_INBOX);
    char *sched_outboxname = caldav_mboxname(req->accountid, SCHED_OUTBOX);

    /* Sanity check arguments */
    eventquery_read_timerange(query->filter, &before, &after);
    if (expandrecur && before == caldav_eternity) {
        /* Reject unbounded time-ranges for recurrence expansion */
        *err = json_pack("{s:s s:[s] s:s}", "type", "invalidArguments",
                "arguments", "expandRecurrences",
                "description","upper time-range filter MUST be set");
        return 0;
    }

    ptrarray_t matches = PTRARRAY_INITIALIZER;

    /* Open Caldav DB */
    struct caldav_db *db = caldav_open_userid(req->accountid);
    if (!db) {
        syslog(LOG_ERR, "%s:%s: can't open caldav db for %s",
                        __FILE__, __func__, req->accountid);
        r = IMAP_INTERNAL;
        goto done;
    }

    /* Parse sort */
    if (json_array_size(query->sort)) {
        nsort = json_array_size(query->sort);
        sort = xzmalloc(nsort * sizeof(enum caldav_sort));
        json_t *jval;
        size_t i;
        json_array_foreach(query->sort, i, jval) {
            const char *prop = json_string_value(json_object_get(jval, "property"));
            if (!strcmp(prop, "start"))
                sort[i] = CAL_SORT_START;
            else if (!strcmp(prop, "uid"))
                sort[i] = CAL_SORT_UID;
            else
                sort[i] = CAL_SORT_NONE;
            if (json_object_get(jval, "isAscending") == json_false()) {
                sort[i] |= CAL_SORT_DESC;
            }
        }
    }

    int have_textsearch = eventquery_have_textsearch(query->filter);

    /* Attempt to fast-path trivial query */

    if (!have_textsearch && !expandrecur && query->position >= 0 && !query->anchor) {
        struct eventquery_fastpath_rock rock = {
            req, query, sched_inboxname, sched_outboxname
        };
        const char *wantuid = json_string_value(json_object_get(query->filter, "uid"));
        if (wantuid) {
            /* Super fast path!  We only want a single UID */
            struct caldav_data *cdata = NULL;
            r = caldav_lookup_uid(db, wantuid, &cdata);
            if (!r) eventquery_fastpath_cb(&rock, cdata);
            if (r == CYRUSDB_NOTFOUND) r = 0;
        }
        else {
            /* Fast-path: we can offload most processing to Caldav DB. */
            r = caldav_foreach_timerange(db, NULL, after, before, sort, nsort,
                                         eventquery_fastpath_cb, &rock);
        }
        goto done;
    }

    /* Handle non-trivial query */

    if (have_textsearch) {
        /* Query and sort matches in search backend. */
        r = eventquery_search_run(req, query->filter, db, before, after,
                                  sort, nsort, expandrecur,
                                  sched_inboxname, sched_outboxname,
                                  &matches);
        if (r) goto done;
    }
    else {
        /* Query and sort matches in Caldav DB. */
        struct eventquery_rock rock = {
            req, expandrecur, NULL, &matches,
            sched_inboxname, sched_outboxname
        };

        enum caldav_sort mboxsort = CAL_SORT_MAILBOX;
        r = caldav_foreach_timerange(db, NULL, after, before,
                                     expandrecur ? &mboxsort : sort,
                                     expandrecur ? 1 : nsort,
                                     eventquery_cb, &rock);
        jmap_closembox(req, &rock.mailbox);
    }

    if (expandrecur) {
        /* Expand and sort recurrence instance matches */
        icaltimezone *utc = icaltimezone_get_utc_timezone();
        struct icalperiodtype timerange = {
            icaltime_from_timet_with_zone(after, 0, utc),
            icaltime_from_timet_with_zone(before, 0, utc),
            icaldurationtype_null_duration()
        };
        ptrarray_t mymatches = PTRARRAY_INITIALIZER;
        struct buf buf = BUF_INITIALIZER;
        struct eventquery_match *match;
        while ((match = ptrarray_pop(&matches))) {
            icalcomponent *comp = icalcomponent_get_first_real_component(match->ical);
            icalcomponent_kind kind = icalcomponent_isa(comp);

            int is_recurring = 0;
            for (; comp; comp = icalcomponent_get_next_component(match->ical, kind)) {
                if (icalcomponent_get_first_property(comp, ICAL_RRULE_PROPERTY) ||
                    icalcomponent_get_first_property(comp, ICAL_RDATE_PROPERTY)) {
                    is_recurring = 1;
                    break;
                }
            }

            if (is_recurring) {
                /* Expand all instances, we need them for totals */
                /* XXX - need tooManyRecurrenceInstances error ? */
                struct eventquery_recur_rock rock = {
                    &mymatches, &buf, icaltime_null_time()
                };
                icalcomponent_myforeach(match->ical, timerange, utc,
                                        eventquery_recur_cb, &rock);
                eventquery_match_free(&match);
            }
            else ptrarray_append(&mymatches, match);
        }
        buf_free(&buf);

        ptrarray_fini(&matches);
        matches = mymatches;

        struct eventquery_cmp_rock rock = { sort, nsort };
        cyr_qsort_r(matches.data, matches.count, sizeof(void*), eventquery_cmp, &rock);
    }

    query->total = ptrarray_size(&matches);

    /* Determine start position of result list */
    size_t startpos = 0;
    if (query->anchor) {
        size_t j;
        for (j = 0; j < (size_t) ptrarray_size(&matches); j++) {
            struct eventquery_match *m = ptrarray_nth(&matches, j);
            if (!strcmp(query->anchor, m->ical_uid)) {
                /* Found anchor */
                if (query->anchor_offset < 0) {
                    startpos = (size_t) -query->anchor_offset > j ?
                        0 : j + query->anchor_offset;
                }
                else {
                    startpos = j + query->anchor_offset;
                }
                break;
            }
        }
    }
    else if (query->position < 0) {
        startpos = -query->position > ptrarray_size(&matches) ?
            0 : ptrarray_size(&matches) + query->position;
    }
    else startpos = query->position;
    query->result_position = startpos;

    /* Build result list */
    size_t i;
    struct buf buf = BUF_INITIALIZER;
    for (i = startpos; i < (size_t) ptrarray_size(&matches); i++) {
        if (query->have_limit && json_array_size(query->ids) >= query->limit) {
            break;
        }
        struct eventquery_match *m = ptrarray_nth(&matches, i);
        const char *id;
        if (m->recurid) {
            buf_setcstr(&buf, m->ical_uid);
            buf_putc(&buf, ';');
            buf_appendcstr(&buf, m->recurid);
            id = buf_cstring(&buf);
        }
        else id = m->ical_uid;
        json_array_append_new(query->ids, json_string(id));
    }
    buf_free(&buf);

done:
    if (db) caldav_close(db);
    if (ptrarray_size(&matches)) {
        int j;
        for (j = 0; j < ptrarray_size(&matches); j++) {
            struct eventquery_match *match = ptrarray_nth(&matches, j);
            eventquery_match_free(&match);
        }
    }
    free(sched_inboxname);
    free(sched_outboxname);
    ptrarray_fini(&matches);
    free(sort);
    return r;
}

static void calendarevent_validatefilter(jmap_req_t *req __attribute__((unused)),
                                         struct jmap_parser *parser,
                                         json_t *filter,
                                         json_t *unsupported __attribute__((unused)),
                                         void *rock __attribute__((unused)),
                                         json_t **err __attribute__((unused)))
{
    const char *field;
    json_t *arg;

    json_object_foreach(filter, field, arg) {
        if (!strcmp(field, "inCalendars")) {
            if (!(json_is_array(arg) && json_array_size(arg))) {
                jmap_parser_invalid(parser, field);
            }
            else {
                size_t i;
                json_t *uid;
                json_array_foreach(arg, i, uid) {
                    const char *id = json_string_value(uid);
                    if (!id || id[0] == '#') {
                        jmap_parser_push_index(parser, field, i, id);
                        jmap_parser_invalid(parser, NULL);
                        jmap_parser_pop(parser);
                    }
                }
            }
        }
        else if (!strcmp(field, "before") ||
                 !strcmp(field, "after")) {
            const char *s;
            if ((s = json_string_value(arg))) {
                int is_valid = 0;
                size_t len = strlen(s);
                if (len && s[len-1] == 'Z') {
                    /* Validate UTCDateTime */
                    struct tm tm;
                    memset(&tm, 0, sizeof(struct tm));
                    tm.tm_isdst = -1;
                    const char *p = strptime(s, "%Y-%m-%dT%H:%M:%S", &tm);
                    is_valid = p && *p == 'Z';
                }
                if (!is_valid) jmap_parser_invalid(parser, field);
            }
            else jmap_parser_invalid(parser, field);
        }
        else if (!strcmp(field, "text") ||
                 !strcmp(field, "title") ||
                 !strcmp(field, "description") ||
                 !strcmp(field, "location") ||
                 !strcmp(field, "uid") ||
                 !strcmp(field, "owner") ||
                 !strcmp(field, "attendee")) {
            if (!json_is_string(arg)) {
                jmap_parser_invalid(parser, field);
            }
        }
        else {
            jmap_parser_invalid(parser, field);
        }
    }
}

static int calendarevent_validatecomparator(jmap_req_t *req __attribute__((unused)),
                                            struct jmap_comparator *comp,
                                            void *rock __attribute__((unused)),
                                            json_t **err __attribute__((unused)))
{
    /* Reject any collation */
    if (comp->collation) {
        return 0;
    }
    if (!strcmp(comp->property, "start") ||
        !strcmp(comp->property, "uid")) {
        return 1;
    }
    return 0;
}

static int _calendarevent_queryargs_parse(jmap_req_t *req __attribute__((unused)),
                                          struct jmap_parser *parser __attribute__((unused)),
                                          const char *argname,
                                          json_t *argval,
                                          void *rock)
{
    if (strcmp(argname, "expandRecurrences")) return 0;

    if (json_is_boolean(argval)) {
        int *expandrecur = rock;
        *expandrecur = json_boolean_value(argval);
    }
    else {
        jmap_parser_invalid(parser, argname);
    }
    return 1;
}

static int jmap_calendarevent_query(struct jmap_req *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_query query;
    int expandrecur = 0;

    /* Parse request */
    json_t *err = NULL;
    jmap_query_parse(req, &parser,
                     _calendarevent_queryargs_parse, &expandrecur,
                     calendarevent_validatefilter, NULL,
                     calendarevent_validatecomparator, NULL,
                     &query, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }
    if (json_array_size(parser.invalid)) {
        err = json_pack("{s:s}", "type", "invalidArguments");
        json_object_set(err, "arguments", parser.invalid);
        jmap_error(req, err);
        goto done;
    }

    int r = eventquery_run(req, &query, expandrecur, &err);
    if (r || err) {
        if (!err) err = jmap_server_error(r);
        jmap_error(req, err);
        goto done;
    }

    /* Build response */
    json_t *jstate = jmap_getstate(req, MBTYPE_CALENDAR, /*refresh*/0);
    query.query_state = xstrdup(json_string_value(jstate));
    json_decref(jstate);

    json_t *res = jmap_query_reply(&query);
    jmap_ok(req, res);

done:
    jmap_query_fini(&query);
    jmap_parser_fini(&parser);
    return 0;
}

static void _calendarevent_copy(jmap_req_t *req,
                                struct mailbox *notifmbox,
                                json_t *jevent,
                                struct caldav_db *src_db,
                                struct caldav_db *dst_db,
                                json_t **new_event,
                                json_t **set_err)
{
    struct jmap_parser myparser = JMAP_PARSER_INITIALIZER;
    icalcomponent *src_ical = NULL;
    json_t *dst_event = NULL;
    struct mailbox *src_mbox = NULL;
    strarray_t schedule_addresses = STRARRAY_INITIALIZER;
    mbentry_t *mbentry = NULL;
    struct jmapical_jmapcontext jmapctx;
    jmap_calendarcontext_init(&jmapctx, req);
    int r = 0;

    /* Read mandatory properties */
    const char *src_id = json_string_value(json_object_get(jevent, "id"));
    if (!src_id) {
        jmap_parser_invalid(&myparser, "id");
    }
    const char *dst_calendar_id = NULL;
    json_t * jval = json_object_get(jevent, "calendarIds");
    if (json_object_size(jval) == 1) {
        void *iter = json_object_iter(jval);
        if (json_object_iter_value(iter) == json_true()) {
            dst_calendar_id = json_object_iter_key(iter);
        }
    }
    if (dst_calendar_id && *dst_calendar_id == '#') {
        dst_calendar_id = jmap_lookup_id(req, dst_calendar_id + 1);
    }
    if (!dst_calendar_id || !*dst_calendar_id) {
        jmap_parser_invalid(&myparser, "calendarIds");
    }
    if (json_array_size(myparser.invalid)) {
        *set_err = json_pack("{s:s s:O}", "type", "invalidProperties",
                                          "properties", myparser.invalid);
        goto done;
    }

    /* Lookup event */
    struct caldav_data *cdata = NULL;
    r = caldav_lookup_uid(src_db, src_id, &cdata);
    if (r && r != CYRUSDB_NOTFOUND) {
        syslog(LOG_ERR, "caldav_lookup_uid(%s) failed: %s", src_id, error_message(r));
        goto done;
    }
    if (r == CYRUSDB_NOTFOUND || !cdata->dav.alive || !cdata->dav.rowid ||
            !cdata->dav.imap_uid || cdata->comp_type != CAL_COMP_VEVENT) {
        *set_err = json_pack("{s:s}", "type", "notFound");
        goto done;
    }

    mbentry = jmap_mbentry_from_dav(req, &cdata->dav);

    if (!mbentry || !jmap_hasrights_mbentry(req, mbentry, JACL_READITEMS)) {
        *set_err = json_pack("{s:s}", "type", "notFound");
        goto done;
    }

    /* Read source event */
    r = jmap_openmbox(req, mbentry->name, &src_mbox, /*rw*/0);
    if (r) goto done;
    src_ical = caldav_record_to_ical(src_mbox, cdata, req->userid, &schedule_addresses);
    if (!src_ical) {
        syslog(LOG_ERR, "calendarevent_copy: can't convert %s to JMAP", src_id);
        r = IMAP_INTERNAL;
        goto done;
    }

    /* Patch JMAP event */
    json_t *src_event = jmapical_tojmap(src_ical, NULL, &jmapctx);
    if (src_event) {
        dst_event = jmap_patchobject_apply(src_event, jevent, NULL);
    }
    json_decref(src_event);
    if (!dst_event) {
        syslog(LOG_ERR, "calendarevent_copy: can't convert to ical: %s", src_id);
        r = IMAP_INTERNAL;
        goto done;
    }

    /* Create event */
    json_t *invalid = json_array();
    *new_event = json_pack("{}");
    *new_event = json_object();
    r = setcalendarevents_create(req, req->accountid, notifmbox, dst_event,
                                 dst_db, invalid, /*send_schedule*/0, *new_event);
    if (r || json_array_size(invalid)) {
        if (!r) {
            *set_err = json_pack("{s:s s:o}", "type", "invalidProperties",
                                              "properties", invalid);
        }
        goto done;
    }
    json_decref(invalid);
    json_object_set(*new_event, "id", json_object_get(*new_event, "uid"));

done:
    if (r && *set_err == NULL) {
        if (r == CYRUSDB_NOTFOUND)
            *set_err = json_pack("{s:s}", "type", "notFound");
        else
            *set_err = jmap_server_error(r);
        return;
    }
    mboxlist_entry_free(&mbentry);
    jmap_closembox(req, &src_mbox);
    strarray_fini(&schedule_addresses);
    if (src_ical) icalcomponent_free(src_ical);
    json_decref(dst_event);
    jmap_calendarcontext_fini(&jmapctx);
    jmap_parser_fini(&myparser);
}

static int jmap_calendarevent_copy(struct jmap_req *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_copy copy;
    json_t *err = NULL;
    struct caldav_db *src_db = NULL;
    struct caldav_db *dst_db = NULL;
    json_t *destroy_events = json_array();
    struct mailbox *notifmbox = NULL;
    mbentry_t *notifmb = NULL;

    /* Parse request */
    jmap_copy_parse(req, &parser, NULL, NULL, &copy, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    src_db = caldav_open_userid(copy.from_account_id);
    if (!src_db) {
        jmap_error(req, json_pack("{s:s}", "type", "fromAccountNotFound"));
        goto done;
    }
    dst_db = caldav_open_userid(req->accountid);
    if (!dst_db) {
        jmap_error(req, json_pack("{s:s}", "type", "toAccountNotFound"));
        goto done;
    }

    /* Open notifications mailbox, but continue even on error. */
    int r = create_notify_collection(req->accountid, &notifmb);
    if (!r) {
        r = jmap_openmbox(req, notifmb->name, &notifmbox, 1);
    }
    if (r) {
        xsyslog(LOG_WARNING, "can not open jmapnotify collection",
                "accountid=%s error=%s", req->accountid, error_message(r));
    }

    /* Process request */
    const char *creation_id;
    json_t *jevent;
    json_object_foreach(copy.create, creation_id, jevent) {
        /* Copy event */
        json_t *set_err = NULL;
        json_t *new_event = NULL;

        _calendarevent_copy(req, notifmbox, jevent, src_db, dst_db,
                            &new_event, &set_err);
        if (set_err) {
            json_object_set_new(copy.not_created, creation_id, set_err);
            continue;
        }

        // copy the ID for later deletion
        json_array_append(destroy_events, json_object_get(jevent, "id"));

        /* Report event as created */
        json_object_set_new(copy.created, creation_id, new_event);
        const char *event_id = json_string_value(json_object_get(new_event, "id"));
        jmap_add_id(req, creation_id, event_id);
    }

    /* Build response */
    jmap_ok(req, jmap_copy_reply(&copy));

    /* Destroy originals, if requested */
    if (copy.on_success_destroy_original && json_array_size(destroy_events)) {
        json_t *subargs = json_object();
        json_object_set(subargs, "destroy", destroy_events);
        json_object_set_new(subargs, "accountId", json_string(copy.from_account_id));
        jmap_add_subreq(req, "CalendarEvent/set", subargs, NULL);
    }

done:
    jmap_closembox(req, &notifmbox);
    mboxlist_entry_free(&notifmb);
    json_decref(destroy_events);
    if (src_db) caldav_close(src_db);
    if (dst_db) caldav_close(dst_db);
    jmap_parser_fini(&parser);
    jmap_copy_fini(&copy);
    return 0;
}

static int _calendarevent_parseargs_parse(jmap_req_t *req __attribute__((unused)),
                                          struct jmap_parser *parser,
                                          const char *key,
                                          json_t *arg,
                                          void *rock)
{
    hash_table **props = (hash_table **) rock;

    if (!strcmp(key, "properties")) {
        if (json_is_array(arg)) {
            size_t i;
            json_t *val;

            *props = xzmalloc(sizeof(hash_table));
            construct_hash_table(*props, json_array_size(arg) + 1, 0);
            json_array_foreach(arg, i, val) {
                const char *s = json_string_value(val);
                if (!s) {
                    jmap_parser_push_index(parser, "properties", i, s);
                    jmap_parser_invalid(parser, NULL);
                    jmap_parser_pop(parser);
                    continue;
                }
                hash_insert(s, (void*)1, *props);
            }
        }
        else if (JNOTNULL(arg)) {
            return 0;
        }

        return 1;
    }

    return 0;
}

static int jmap_calendarevent_parse(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_parse parse;
    hash_table *props = NULL;
    json_t *err = NULL;

    /* Parse request */
    jmap_parse_parse(req, &parser,
                     &_calendarevent_parseargs_parse, &props, &parse, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    /* Process request */
    jmap_getblob_context_t blob_ctx;
    jmap_getblob_ctx_init(&blob_ctx, NULL, NULL, "text/calendar", 1);

    json_t *jval;
    size_t i;
    json_array_foreach(parse.blob_ids, i, jval) {
        const char *blobid = json_string_value(jval);
        icalcomponent *ical = NULL;
        json_t *events = NULL;
        int r = 0;

        if (!blobid) continue;

        /* Find blob */
        blob_ctx.blobid = blobid;
        if (blobid[0] == '#') {
            blob_ctx.blobid = jmap_lookup_id(req, blobid + 1);
            if (!blob_ctx.blobid) {
                json_array_append_new(parse.not_found, json_string(blobid));
                continue;
            }
        }

        buf_reset(&blob_ctx.blob);
        r = jmap_getblob(req, &blob_ctx);
        if (r) {
            json_array_append_new(parse.not_found, json_string(blobid));
            continue;
        }

        ical = icalparser_parse_string(buf_cstring(&blob_ctx.blob));
        if (ical) {
            events = jmapical_tojmap_all(ical, props, NULL);
            icalcomponent_free(ical);
        }

        if (events) {
            if (json_array_size(events) > 1) {
                json_object_set_new(parse.parsed, blobid,
                                    json_pack("{ s:s s:o }",
                                              "@type", "jsgroup",
                                              "entries", events));
            }
            else {
                json_object_set(parse.parsed, blobid, json_array_get(events, 0));
                json_decref(events);
            }
        }
        else {
            json_array_append_new(parse.not_parsable, json_string(blobid));
        }
    }

    jmap_getblob_ctx_fini(&blob_ctx);

    /* Build response */
    jmap_ok(req, jmap_parse_reply(&parse));

done:
    jmap_parser_fini(&parser);
    jmap_parse_fini(&parse);
    free_hash_table(props, NULL);
    free(props);
    return 0;
}

static const jmap_property_t calendarprincipal_props[] = {
    {
        "id",
        NULL,
        JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE | JMAP_PROP_ALWAYS_GET
    },
    {
        "name",
        NULL,
        JMAP_PROP_SERVER_SET
    },
    {
        "description",
        NULL,
        JMAP_PROP_SERVER_SET
    },
    {
        "email",
        NULL,
        JMAP_PROP_SERVER_SET
    },
    {
        "type",
        NULL,
        JMAP_PROP_SERVER_SET
    },
    {
        "timeZone",
        NULL,
        0,
    },
    {
        "mayGetAvailability",
        NULL,
        JMAP_PROP_SERVER_SET
    },
    {
        "accountId",
        NULL,
        JMAP_PROP_SERVER_SET
    },
    {
        "account",
        NULL,
        JMAP_PROP_SERVER_SET
    },
    {
        "sendTo",
        NULL,
        JMAP_PROP_SERVER_SET
    },
    { NULL, NULL, 0 }
};

typedef int(*principal_foreach_fn)
    (jmap_req_t* req, const char* accountid, int rights, void* rock);

struct principal_foreach_rock {
    jmap_req_t *req;
    principal_foreach_fn proc;
    void *rock;
    struct buf accountid;
    int rights;
};

static int principal_foreach_cb(struct findall_data *data, void *rock)
{
    if (!data || !data->mbentry || !data->mbname) return 0;

    struct principal_foreach_rock *myrock = rock;
    struct jmap_req *req = myrock->req;

    if (!jmap_hasrights_mbentry(req, data->mbentry, JACL_LOOKUP)) {
        return 0;
    }

    const char *accountid = mbname_userid(data->mbname);
    int r = 0;
    if (strcmp(accountid, buf_cstring(&myrock->accountid))) {
        if (buf_len(&myrock->accountid)) {
            r = myrock->proc(req, buf_cstring(&myrock->accountid),
                             myrock->rights, myrock->rock);
        }
        buf_setcstr(&myrock->accountid, accountid);
        myrock->rights = jmap_myrights_mbentry(req, data->mbentry);
    }
    else {
        myrock->rights |= jmap_myrights_mbentry(req, data->mbentry);
    }

    return r;
}

static int principal_foreach(struct jmap_req *req, principal_foreach_fn proc, void *rock)
{
    /* Find shared accounts */
    const char *prefix = config_getstring(IMAPOPT_CALENDARPREFIX);
    strarray_t patterns = STRARRAY_INITIALIZER;
    char *userpat = strconcat("user.*.", prefix, NULL);
    userpat[4] = jmap_namespace.hier_sep;
    userpat[6] = jmap_namespace.hier_sep;
    strarray_append(&patterns, userpat);
    struct principal_foreach_rock myrock = {
        req, proc, rock, BUF_INITIALIZER, 0
    };
    int r = mboxlist_findallmulti(&jmap_namespace, &patterns, 0, req->userid,
                                  req->authstate, principal_foreach_cb, &myrock);
    strarray_fini(&patterns);
    free(userpat);
    if (buf_len(&myrock.accountid)) {
        r = proc(req, buf_cstring(&myrock.accountid), myrock.rights, rock);
    }

    /* Add own account */
    if (!r) r = proc(req, req->userid, JACL_ALL, rock);

    buf_free(&myrock.accountid);
    return r;
}


static json_t *buildprincipal(struct jmap_req *req,
                              hash_table *props,
                              json_t *jaccount,
                              int rights,
                              const char *accountid)
{
    char *calhomename = caldav_mboxname(accountid, NULL);
    json_t *jp = json_object();
    struct buf buf = BUF_INITIALIZER;
    strarray_t addrs = STRARRAY_INITIALIZER;
    get_schedule_addresses(NULL, calhomename, accountid, &addrs);

    json_object_set_new(jp, "id", json_string(accountid));

    if (jmap_wantprop(props, "name")) {
        static const char *annot = DAV_ANNOT_NS "<" XML_NS_DAV ">displayname";
        annotatemore_lookupmask(calhomename, annot, req->userid, &buf);
        json_object_set_new(jp, "name", json_string(buf_cstring(&buf)));
        buf_reset(&buf);
    }

    if (jmap_wantprop(props, "description")) {
        static const char *annot = DAV_ANNOT_NS "<" XML_NS_CALDAV ">calendar-description";
        annotatemore_lookupmask(calhomename, annot, req->userid, &buf);
        json_object_set_new(jp, "description", buf_len(&buf) ?
                json_string(buf_cstring(&buf)) : json_null());
        buf_reset(&buf);
    }

    if (jmap_wantprop(props, "email")) {
        json_t *jemail = json_null();
        if (strarray_size(&addrs)) {
            jemail = json_string(strarray_nth(&addrs, 0));
        }
        json_object_set_new(jp, "email", jemail);
    }

    if (jmap_wantprop(props, "type")) {
        /* XXX - how to determine type? also see propfind_calusertype */
        json_object_set_new(jp, "type", json_string("individual"));
    }

    if (jmap_wantprop(props, "timeZone")) {
        static const char *tzid_annot =
            DAV_ANNOT_NS "<" XML_NS_CALDAV ">calendar-timezone-id";
        static const char *tz_annot =
            DAV_ANNOT_NS "<" XML_NS_CALDAV ">calendar-timezone";

        annotatemore_lookupmask(calhomename, tzid_annot, accountid, &buf);
        if (!buf_len(&buf)) {
            annotatemore_lookupmask(calhomename, tz_annot, accountid, &buf);
            if (buf_len(&buf)) {
                icalcomponent *ical = icalparser_parse_string(buf_cstring(&buf));
                if (ical && icalcomponent_isa(ical) == ICAL_VCALENDAR_COMPONENT) {
                    icalcomponent *comp =
                        icalcomponent_get_first_component(ical, ICAL_VTIMEZONE_COMPONENT);
                    if (comp) {
                        icalproperty *prop =
                            icalcomponent_get_first_property(comp, ICAL_TZID_PROPERTY);
                        if (prop) {
                            buf_setcstr(&buf, icalproperty_get_tzid(prop));
                        }
                    }
                }
                if (ical) icalcomponent_free(ical);
            }
        }

        json_object_set_new(jp, "timeZone", buf_len(&buf) ?
                json_string(buf_cstring(&buf)) : json_null());
        buf_reset(&buf);
    }

    if (jmap_wantprop(props, "mayGetAvailability")) {
        json_object_set_new(jp, "mayGetAvailability",
                json_boolean(rights & JACL_READFB));
    }

    if (jmap_wantprop(props, "accountId")) {
        json_object_set_new(jp, "accountId", json_string(accountid));
    }

    if (jmap_wantprop(props, "account")) {
        json_object_set(jp, "account", jaccount ? jaccount : json_null());
    }

    if (jmap_wantprop(props, "sendTo")) {
        json_t *jsendTo = json_null();
        if (strarray_size(&addrs)) {
            const char *addr = strarray_nth(&addrs, 0);
            if (strncasecmp(addr, "mailto:", 7)) {
                buf_setcstr(&buf, "mailto:");
            }
            buf_appendcstr(&buf, addr);
            jsendTo = json_pack("{s:s}", "imip", buf_cstring(&buf));
            buf_reset(&buf);
        }
        json_object_set_new(jp, "sendTo", jsendTo);
    }

    free(calhomename);
    strarray_fini(&addrs);
    buf_free(&buf);
    return jp;
}

struct principal_get_rock {
    struct jmap_get *get;
    json_t *jaccounts;
    hash_table *wantids;
    SHA_CTX *sha1;
};

static int principal_state_init(jmap_req_t *req, SHA_CTX *sha1)
{
    SHA1_Init(sha1);
    char *calhomename = caldav_mboxname(req->userid, NULL);
    struct mailbox *mbox = NULL;
    int r = jmap_openmbox(req, calhomename, &mbox, 0);
    if (!r) {
        struct buf buf = BUF_INITIALIZER;
        buf_printf(&buf, "%s" MODSEQ_FMT, req->userid, mailbox_foldermodseq(mbox));
        SHA1_Update(sha1, buf_base(&buf), buf_len(&buf));
        buf_free(&buf);
    }
    jmap_closembox(req, &mbox);
    free(calhomename);
    return r;
}

static void principal_state_update(jmap_req_t *req __attribute__((unused)),
                                   SHA_CTX *sha1,
                                   const char *accountid)
{
    SHA1_Update(sha1, accountid, strlen(accountid));
}

static char *principal_state_string(SHA_CTX *sha1)
{
    uint8_t digest[SHA1_DIGEST_LENGTH];
    SHA1_Final(digest, sha1);
    char hexdigest[SHA1_DIGEST_LENGTH*2 + 1];
    bin_to_lchex(digest, SHA1_DIGEST_LENGTH, hexdigest);
    hexdigest[SHA1_DIGEST_LENGTH*2] = '\0';
    return xstrdup(hexdigest);
}

static int principal_state_current_cb(jmap_req_t *req,
                                      const char *accountid,
                                      int rights __attribute__((unused)),
                                      void *rock)
{
    SHA_CTX *sha1 = rock;
    if (strcmp(req->userid, accountid)) {
        principal_state_update(req, sha1, accountid);
    }
    return 0;
}

static int principal_currentstate(jmap_req_t *req, char **state)
{
    /* Principal state is the hash of the authenticated userid, its
     * calendar home folder modseq and the account ids of all accounts
     * it where at least one calendar or the calendar home is visible */
    SHA_CTX sha1;
    principal_state_init(req, &sha1);
    int r = principal_foreach(req, principal_state_current_cb, &sha1);
    if (!r) {
        *state = principal_state_string(&sha1);
    }
    return r;
}

static int principal_get_cb(jmap_req_t *req, const char *accountid,
                            int rights, void *rock)
{
    struct principal_get_rock *getrock = rock;

    /* Update state */
    SHA1_Update(getrock->sha1, accountid, strlen(accountid));

    /* Convert princpial */
    if (hash_del(accountid, getrock->wantids)) {
        struct jmap_get *get = getrock->get;
        json_t *jaccount = json_object_get(getrock->jaccounts, accountid);
        json_t *jp = buildprincipal(req, get->props, jaccount, rights, accountid);
        if (jp) {
            if (strcmp(req->userid, accountid)) {
                principal_state_update(req, getrock->sha1, accountid);
            }
            json_array_append_new(get->list, jp);
        }
        else {
            json_array_append_new(get->not_found, json_string(accountid));
        }
    }

    return 0;
}

static int jmap_principal_get(struct jmap_req *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_get get;
    json_t *err = NULL;

    jmap_get_parse(req, &parser, calendarprincipal_props, 0, NULL, NULL, &get, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    json_t *jaccounts = NULL, *jprimary_accounts = NULL;
    if (jmap_wantprop(get.props, "account")) {
        jaccounts = json_object();
        jprimary_accounts = json_object();
        jmap_accounts(jaccounts, jprimary_accounts);
    }

    /* Determine which princpials to fetch */
    hash_table wantids = HASH_TABLE_INITIALIZER;
    construct_hash_table(&wantids, json_array_size(get.ids) + 1, 0);
    size_t i;
    json_t *jval;
    json_array_foreach(get.ids, i, jval) {
        hash_insert(json_string_value(jval), (void*)0x1, &wantids);
    }

    /* Traverse principals */
    SHA_CTX sha1;
    principal_state_init(req, &sha1);
    struct principal_get_rock rock = { &get, jaccounts, &wantids, &sha1 };
    int r = principal_foreach(req, principal_get_cb, &rock);
    if (r) {
        jmap_error(req, jmap_server_error(r));
        goto done;
    }
    get.state = principal_state_string(&sha1);

    json_decref(jaccounts);
    json_decref(jprimary_accounts);
    hash_iter *it = hash_table_iter(&wantids);
    while (hash_iter_next(it)) {
        json_array_append_new(get.not_found, json_string(hash_iter_key(it)));
    }
    hash_iter_free(&it);
    free_hash_table(&wantids, NULL);
    if (r) {
        jmap_error(req, jmap_server_error(r));
        goto done;
    }


    jmap_ok(req, jmap_get_reply(&get));

done:
    jmap_parser_fini(&parser);
    jmap_get_fini(&get);
    return 0;
}

static void principal_query_validatefilter(jmap_req_t *req __attribute__((unused)),
                                           struct jmap_parser *parser,
                                           json_t *filter,
                                           json_t *unsupported __attribute__((unused)),
                                           void *rock __attribute__((unused)),
                                           json_t **err __attribute__((unused)))
{
    const char *field;
    json_t *arg;

    json_object_foreach(filter, field, arg) {
        if (!strcmp(field, "accountIds")) {
            if (json_is_array(arg)) {
                size_t i;
                json_t *jval;
                json_array_foreach(arg, i, jval) {
                    if (!json_is_string(jval)) {
                        jmap_parser_push_index(parser, "accountIds", i, NULL);
                        jmap_parser_invalid(parser, NULL);
                        jmap_parser_pop(parser);
                    }
                }
            }
            else jmap_parser_invalid(parser, field);
        }
        else if (!strcmp(field, "email") ||
                 !strcmp(field, "name") ||
                 !strcmp(field, "text") ||
                 !strcmp(field, "type") ||
                 !strcmp(field, "timeZone")) {
            if (!json_is_string(arg)) {
                jmap_parser_invalid(parser, field);
            }
        }
        else {
            jmap_parser_invalid(parser, field);
        }
    }
}

static int principal_query_validatecomparator(jmap_req_t *req __attribute__((unused)),
                                              struct jmap_comparator *comp,
                                              void *rock __attribute__((unused)),
                                              json_t **err __attribute__((unused)))
{
    /* Reject any collation */
    if (comp->collation) {
        return 0;
    }
    if (!strcmp(comp->property, "id")) {
        return 1;
    }
    return 0;
}

struct principalfilter_expr {
    const char *op;
    ptrarray_t conditions;
    json_t *jaccountids;
    xapian_query_t *email;
    xapian_query_t *name;
    xapian_query_t *text;
    const char *type;
    const char *timezone;
};

struct principalfilter {
    /* Query-scoped context */
    hash_table props;
    struct xapian_dbw *dbw;
    struct xapian_db *db;
    struct principalfilter_expr *root;
    /* Principal-scoped context */
    char guidrep[MESSAGE_GUID_SIZE*2];
    int xqmatches;
};

static struct principalfilter_expr *principalfilter_buildexpr(json_t *jfilter,
                                                              struct principalfilter *filter)
{
    struct principalfilter_expr *expr = xzmalloc(sizeof(struct principalfilter_expr));

    expr->op = json_string_value(json_object_get(jfilter, "operator"));
    if (expr->op) {
        size_t i;
        json_t *jval;
        json_array_foreach(json_object_get(jfilter, "conditions"), i, jval) {
            struct principalfilter_expr *subexpr =
                principalfilter_buildexpr(jval, filter);
            if (subexpr) ptrarray_append(&expr->conditions, subexpr);
        }
    }
    else {
        expr->jaccountids = json_object_get(jfilter, "accountIds");

        const char *s;
        if ((s = json_string_value(json_object_get(jfilter, "email")))) {
            hash_insert("email", (void*)0x1, &filter->props);
            expr->email = xapian_query_new_match(filter->db, SEARCH_PART_FROM, s);
        }
        if ((s = json_string_value(json_object_get(jfilter, "name")))) {
            hash_insert("name", (void*)0x1, &filter->props);
            expr->name = xapian_query_new_match(filter->db, SEARCH_PART_SUBJECT, s);
        }
        if ((s = json_string_value(json_object_get(jfilter, "text")))) {
            hash_insert("email", (void*)0x1, &filter->props);
            hash_insert("name", (void*)0x1, &filter->props);
            hash_insert("description", (void*)0x1, &filter->props);
            xapian_query_t *xqs[3], *xq;
            size_t count = 0;
            xq = xapian_query_new_match(filter->db, SEARCH_PART_FROM, s);
            if (xq) xqs[count++] = xq;
            xq = xapian_query_new_match(filter->db, SEARCH_PART_SUBJECT, s);
            if (xq) xqs[count++] = xq;
            xq = xapian_query_new_match(filter->db, SEARCH_PART_BODY, s);
            if (xq) xqs[count++] = xq;
            if (count) {
                expr->text = xapian_query_new_compound(filter->db, 1, xqs, count);
            }
        }
        if ((s = json_string_value(json_object_get(jfilter, "type")))) {
            hash_insert("type", (void*)0x1, &filter->props);
            expr->type = s;
        }
        if ((s = json_string_value(json_object_get(jfilter, "timeZone")))) {
            hash_insert("timeZone", (void*)0x1, &filter->props);
            expr->timezone = s;
        }
    }

    return expr;
}

static int principalfilter_init(json_t *jfilter, struct principalfilter *filter)
{
    if (!jfilter) return 0;

    construct_hash_table(&filter->props, 8, 0);
    int r = xapian_dbw_openmem(&filter->dbw);
    if (r) return r;
    r = xapian_db_opendbw(filter->dbw, &filter->db);
    if (r) return r;
    filter->root = principalfilter_buildexpr(jfilter, filter);
    return 0;
}

static void principalfilter_finiexpr(struct principalfilter_expr *expr)
{
    int i;
    for (i = 0; i < ptrarray_size(&expr->conditions); i++) {
        struct principalfilter_expr *se = ptrarray_nth(&expr->conditions, i);
        principalfilter_finiexpr(se);
        free(se);
    }
    ptrarray_fini(&expr->conditions);

    if (expr->email)
        xapian_query_free(expr->email);
    if (expr->name)
        xapian_query_free(expr->name);
    if (expr->text)
        xapian_query_free(expr->text);
}

static void principalfilter_fini(struct principalfilter *filter)
{
    if (filter->props.size)
        free_hash_table(&filter->props, NULL);
    if (filter->db)
        xapian_db_close(filter->db);
    if (filter->dbw)
        xapian_dbw_close(filter->dbw);
    if (filter->root) {
        principalfilter_finiexpr(filter->root);
        free(filter->root);
    }
}

static int principalfilter_matchexpr_cb(void *base, size_t n, void *rock)
{
    struct principalfilter *filter = rock;
    size_t i;
    for (i = 0; i < n; i++) {
        if (!memcmp(base + i, filter->guidrep, MESSAGE_GUID_SIZE*2)) {
            filter->xqmatches = 1;
            return CYRUSDB_DONE;
        }
    }
    return 0;
}

static int principalfilter_matchexpr(json_t *jp,
                                     struct principalfilter *filter,
                                     struct principalfilter_expr *expr)
{
    if (!expr) return 1;

    if (expr->op) {
        int i;
        for (i = 0; i < ptrarray_size(&expr->conditions); i++) {
            struct principalfilter_expr *subexpr = ptrarray_nth(&expr->conditions, i);
            if (principalfilter_matchexpr(jp, filter, subexpr)) {
                if (!strcmp(expr->op, "OR"))
                    return 1;
                else if (!strcmp(expr->op, "NOT"))
                    return 0;
            }
            else {
                if (!strcmp(expr->op, "AND"))
                    return 0;
            }
            return strcmp(expr->op, "OR");
        }
    }
    else {
        if (expr->jaccountids) {
            const char *accountid = json_string_value(json_object_get(jp, "id"));
            int matches = 0;
            json_t *jval;
            size_t i;
            json_array_foreach(expr->jaccountids, i, jval) {
                if (!strcmpsafe(accountid, json_string_value(jval))) {
                    matches = 1;
                    break;
                }
            }
            if (!matches) return 0;
        }
        if (expr->email) {
            filter->xqmatches = 0;
            xapian_query_run(filter->db, expr->email,
                    principalfilter_matchexpr_cb, filter);
            if (!filter->xqmatches) return 0;
        }
        if (expr->name) {
            filter->xqmatches = 0;
            xapian_query_run(filter->db, expr->name,
                    principalfilter_matchexpr_cb, filter);
            if (!filter->xqmatches) return 0;
        }
        if (expr->text) {
            filter->xqmatches = 0;
            xapian_query_run(filter->db, expr->text,
                    principalfilter_matchexpr_cb, filter);
            if (!filter->xqmatches) return 0;
        }
        if (expr->type) {
            const char *s = json_string_value(json_object_get(jp, "type"));
            if (strcmpsafe(expr->type, s)) {
                return 0;
            }
        }
        if (expr->timezone) {
            const char *s = json_string_value(json_object_get(jp, "timeZone"));
            if (strcmpsafe(expr->timezone, s)) {
                return 0;
            }
        }
    }


    return 1;
}

static int principalfilter_match(json_t *jp, struct principalfilter *filter)
{
    const char *id = json_string_value(json_object_get(jp, "id"));
    if (!id) return 0;

    /* Set principal-scoped context */
    struct message_guid guid;
    message_guid_generate(&guid, id, strlen(id));
    memcpy(filter->guidrep, message_guid_encode(&guid), MESSAGE_GUID_SIZE*2);

    struct buf buf = BUF_INITIALIZER;
    const char *s;

    /* Index principal for text matching */
    xapian_dbw_begin_doc(filter->dbw, &guid, XAPIAN_WRAP_DOCTYPE_MSG);
    if ((s = json_string_value(json_object_get(jp, "email")))) {
        buf_setcstr(&buf, s);
        xapian_dbw_doc_part(filter->dbw, &buf, SEARCH_PART_FROM);
        buf_reset(&buf);
    }
    if ((s = json_string_value(json_object_get(jp, "name")))) {
        buf_setcstr(&buf, s);
        xapian_dbw_doc_part(filter->dbw, &buf, SEARCH_PART_SUBJECT);
        buf_reset(&buf);
    }
    if ((s = json_string_value(json_object_get(jp, "description")))) {
        buf_setcstr(&buf, s);
        xapian_dbw_doc_part(filter->dbw, &buf, SEARCH_PART_BODY);
        buf_reset(&buf);
    }
    xapian_dbw_end_doc(filter->dbw, 1);

    /* Evaluate filter */
    int matches = principalfilter_matchexpr(jp, filter, filter->root);

    buf_free(&buf);
    return matches;
}

struct principal_query_rock {
    struct jmap_req *req;
    struct jmap_query *query;
    struct principalfilter *filter;
    strarray_t *matches;
};

static int principal_query_cb(jmap_req_t *req, const char *accountid, int rights, void *rock)
{
    struct principal_query_rock *qrock = rock;
    struct jmap_query *query = qrock->query;

    if (query->filter) {
        struct principalfilter *filter = qrock->filter;
        json_t *jp = buildprincipal(req, &filter->props, NULL, rights, accountid);
        if (jp && principalfilter_match(jp, filter)) {
            /* Matches filter */
            strarray_append(qrock->matches, accountid);
        }
        json_decref(jp);
    }
    else {
        /* No filter - always matches */
        strarray_append(qrock->matches, accountid);
    }

    return 0;
}

static int principalid_cmp QSORT_R_COMPAR_ARGS(const void *va,
                                               const void *vb,
                                               void *rock)
{
    intptr_t is_ascending = (intptr_t) rock;
    const char *sa = (*(const char **)va);
    const char *sb = (*(const char **)vb);
    return strcmp(sa, sb) * (is_ascending ? 1 : -1);
}

static int principal_query(jmap_req_t *req, struct jmap_query *query, json_t **err)
{
    strarray_t matches = STRARRAY_INITIALIZER;
    struct principalfilter filter = {
        HASH_TABLE_INITIALIZER,
        NULL, NULL, NULL, { 0 }, 0
    };

    /* Find principals */
    principalfilter_init(query->filter, &filter);
    struct principal_query_rock rock = { req, query, &filter, &matches };
    int r = principal_foreach(req, principal_query_cb, &rock);
    if (r) {
        *err = jmap_server_error(r);
        goto done;
    }

    /* Make query state */
    SHA_CTX sha1;
    SHA1_Init(&sha1);
    size_t i;
    for (i = 0; i < (size_t) strarray_size(&matches); i++) {
        const char *id = strarray_nth(&matches, i);
        SHA1_Update(&sha1, id, strlen(id));
    }
    uint8_t digest[SHA1_DIGEST_LENGTH];
    SHA1_Final(digest, &sha1);
    char hexdigest[SHA1_DIGEST_LENGTH*2 + 1];
    bin_to_lchex(digest, SHA1_DIGEST_LENGTH, hexdigest);
    hexdigest[SHA1_DIGEST_LENGTH*2] = '\0';
    query->query_state = xstrdup(hexdigest);

    query->total = json_array_size(query->ids);

    /* Sort matches - only sort by id is supported */
    int is_ascending = 1;
    if (json_array_size(query->sort)) {
        json_t *jcomp = json_array_get(query->sort, 0);
        if (json_object_get(jcomp, "isAscending") == json_false()) {
            is_ascending = 0;
        }
    }
    cyr_qsort_r(matches.data, matches.count, sizeof(char*),
                principalid_cmp, (void*)(intptr_t) is_ascending);

    /* Apply windowing */
    size_t startpos = 0;
    if (query->anchor) {
        ssize_t j;
        for (j = 0; j < strarray_size(&matches); j++) {
            if (!strcmpsafe(query->anchor, strarray_nth(&matches, j))) {
                /* Found anchor */
                if (query->anchor_offset < 0) {
                    startpos = -query->anchor_offset > j ?
                        0 : j + query->anchor_offset;
                }
                else {
                    startpos = j + query->anchor_offset;
                }
                break;
            }
        }
    }
    else if (query->position < 0) {
        startpos = ((size_t) -query->position) > (size_t) strarray_size(&matches) ?
            0 : strarray_size(&matches) + query->position;
    }
    else startpos = query->position;
    /* Build result list */
    for (i = startpos; i < (size_t) strarray_size(&matches); i++) {
        if (query->have_limit && json_array_size(query->ids) >= query->limit) {
            break;
        }
        json_array_append_new(query->ids,
                json_string(strarray_nth(&matches, i)));
    }

done:
    principalfilter_fini(&filter);
    strarray_fini(&matches);
    return 0;
}

static int jmap_principal_query(struct jmap_req *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_query query;

    /* Parse request */
    json_t *err = NULL;
    jmap_query_parse(req, &parser, NULL, NULL,
                     principal_query_validatefilter, NULL,
                     principal_query_validatecomparator, NULL,
                     &query, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }
    if (json_array_size(parser.invalid)) {
        err = json_pack("{s:s}", "type", "invalidArguments");
        json_object_set(err, "arguments", parser.invalid);
        jmap_error(req, err);
        goto done;
    }

    /* Run query */
    principal_query(req, &query, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    /* All done */
    jmap_ok(req, jmap_query_reply(&query));

done:
    jmap_query_fini(&query);
    jmap_parser_fini(&parser);
    return 0;
}

static int jmap_principal_changes(struct jmap_req *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_changes changes;
    json_t *err = NULL;

    jmap_changes_parse(req, &parser, 0, NULL, NULL, &changes, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }
    jmap_error(req, json_pack("{s:s}", "type", "cannotCalculateChanges"));

  done:
    jmap_changes_fini(&changes);
    jmap_parser_fini(&parser);
    return 0;
}

static int jmap_principal_querychanges(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_querychanges query;

    json_t *err = NULL;
    jmap_querychanges_parse(req, &parser, NULL, NULL,
                            principal_query_validatefilter, NULL,
                            principal_query_validatecomparator, NULL,
                            &query, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }
    jmap_error(req, json_pack("{s:s}", "type", "cannotCalculateChanges"));

done:
    jmap_querychanges_fini(&query);
    jmap_parser_fini(&parser);
    return 0;
}

static int jmap_principal_set(struct jmap_req *req)
{
    struct jmap_parser argparser = JMAP_PARSER_INITIALIZER;
    struct jmap_set set;
    json_t *err = NULL;

    jmap_set_parse(req, &argparser, calendarprincipal_props, NULL, NULL, &set, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    int r = principal_currentstate(req, &set.old_state);
    if (r) {
        jmap_error(req, jmap_server_error(r));
        goto done;
    }
    if (set.if_in_state && strcmp(set.if_in_state, set.old_state)) {
        jmap_error(req, json_pack("{s:s}", "type", "stateMismatch"));
        goto done;
    }

    /* create */
    const char *id;
    json_t *jarg;
    json_object_foreach(set.create, id, jarg) {
        json_object_set_new(set.not_created, id,
                json_pack("{s:s}", "type", "forbidden"));
    }

    /* update */
    json_object_foreach(set.update, id, jarg) {
        /* Only allow updates for authenticated user principal */
        if (strcmp(id, req->userid)) {
            json_object_set_new(set.not_updated, id,
                    json_pack("{s:s}", "type", "forbidden"));
            continue;
        }
        /* Validate properties */
        json_t *invalid = json_array();
        const char *pname;
        json_t *jprop;
        json_object_foreach(jarg, pname, jprop) {
            if (strcmp(pname, "timeZone")) {
                json_array_append_new(invalid, json_string(pname));
            }
        }
        if (json_array_size(invalid)) {
            json_object_set_new(set.not_updated, id,
                    json_pack("{s:s s:o}", "type", "invalidProperties",
                        "properties", invalid));
            continue;
        }
        json_decref(invalid);
        /* Update princpial */
        const char *tzid = json_string_value(json_object_get(jarg, "timeZone"));
        if (tzid) {
            icaltimezone *tz;
            if ((tz = icaltimezone_get_cyrus_timezone_from_tzid(tzid))) {
                char *calhomename = caldav_mboxname(req->userid, NULL);
                struct mailbox *mbox = NULL;
                int r = jmap_openmbox(req, calhomename, &mbox, 1);
                if (!r) {
                    annotate_state_t *astate = NULL;
                    r = mailbox_get_annotate_state(mbox, 0, &astate);
                    if (!r) {
                        static const char *tzid_annot =
                            DAV_ANNOT_NS "<" XML_NS_CALDAV ">calendar-timezone-id";
                        static const char *tz_annot =
                            DAV_ANNOT_NS "<" XML_NS_CALDAV ">calendar-timezone";

                        struct buf val = BUF_INITIALIZER;
                        buf_setcstr(&val, tzid);
                        r = annotate_state_writemask(astate, tzid_annot, req->userid, &val);
                        icalcomponent *vtz = icaltimezone_get_component(tz);
                        if (vtz) {
                            buf_setcstr(&val, icalcomponent_as_ical_string(vtz));
                            int r2 = annotate_state_writemask(astate, tz_annot, req->userid, &val);
                            if (!r) r = r2;
                        }
                        buf_free(&val);
                    }
                }
                jmap_closembox(req, &mbox);
                free(calhomename);
                if (!r) {
                    json_object_set_new(set.updated, id, json_object());
                }
                else json_object_set_new(set.not_updated, id, jmap_server_error(r));
            }
            else json_object_set_new(set.not_updated, id, json_pack("{s:s s:[s]}",
                        "type", "invalidProperties", "properties", "timeZone"));
        }
    }

    /* destroy */
    size_t i;
    json_array_foreach(set.destroy, i, jarg) {
        json_object_set_new(set.not_destroyed, json_string_value(jarg),
                json_pack("{s:s}", "type", "forbidden"));
    }

    r = principal_currentstate(req, &set.new_state);
    if (r) {
        jmap_error(req, jmap_server_error(r));
        goto done;
    }

    jmap_ok(req, jmap_set_reply(&set));

done:
    jmap_parser_fini(&argparser);
    jmap_set_fini(&set);
    return 0;
}

struct busyperiod {
    struct jmapical_datetime utcstart;
    struct jmapical_datetime utcend;
    icalproperty_status status;
    json_t *jevent;
};

#define JMAP_BUSYPERIOD_INITIALIZER {\
    JMAPICAL_DATETIME_INITIALIZER, \
    JMAPICAL_DATETIME_INITIALIZER, \
    ICAL_STATUS_NONE, \
    NULL \
}

struct principal_getavailability_rock {
    /* Request-scoped context */
    jmap_req_t *req;
    struct buf *buf;
    icaltimetype icalstart;
    icaltimetype icalend;
    const char *principalid;
    struct dynarray *busyperiods;
    int show_details;
    struct jmapical_jmapcontext *jmapctx;
    hash_table *eventprops;
    int cumulatedrights;
    /* Mailbox-scoped context */
    struct mailbox *mbox;
    mbentry_t *mbentry;
    int checkacl;
    int rights;
    icaltimezone *floatingtz;
    /* Event-scoped context */
    json_t *jevent;
};

static int getavailability_ishidden(icalcomponent *comp)
{
    icalproperty *prop;
    prop = icalcomponent_get_first_property(comp, ICAL_TRANSP_PROPERTY);
    if (prop && icalproperty_get_transp(prop) == ICAL_TRANSP_TRANSPARENT) {
        return 0;
    }
    prop = icalcomponent_get_first_property(comp, ICAL_CLASS_PROPERTY);
    if (prop && icalproperty_get_class(prop) == ICAL_CLASS_CONFIDENTIAL) {
        return 0;
    }
    prop = icalcomponent_get_first_property(comp, ICAL_STATUS_PROPERTY);
    if (prop && icalproperty_get_status(prop) == ICAL_STATUS_CANCELLED) {
        return 0;
    }
    return 1;
}

static int principal_getavailability_ical_cb(icalcomponent *comp,
                                              icaltimetype start,
                                              icaltimetype end,
                                              void *vrock)
{
    if (!getavailability_ishidden(comp)) return 1;

    struct principal_getavailability_rock *rock = vrock;
    struct jmapical_datetime dt = JMAPICAL_DATETIME_INITIALIZER;
    icalproperty *prop;
    struct busyperiod bp = JMAP_BUSYPERIOD_INITIALIZER;

    /* Convert to UTC */
    icaltimezone *utc = icaltimezone_get_utc_timezone();
    icaltimetype utcstart = icaltime_convert_to_zone(start, utc);
    icaltimetype utcend = icaltime_convert_to_zone(end, utc);

    /* Handle fractional seconds */
    bit64 startnano = 0;
    bit64 endnano = 0;
    prop = icalcomponent_get_first_property(comp, ICAL_DTSTART_PROPERTY);
    if (prop) {
        jmapical_datetime_from_icalprop(prop, &dt);
        startnano = dt.nano;
    }
    prop = icalcomponent_get_first_property(comp, ICAL_DURATION_PROPERTY);
    if (prop) {
        struct jmapical_duration dur = JMAPICAL_DURATION_INITIALIZER;
        jmapical_duration_from_icalprop(prop,  &dur);
        endnano = startnano + dur.nanos;
        if (endnano > 1000000000) {
            icaltime_adjust(&utcend, 0, 0, 0, endnano / 1000000000);
            endnano %= 1000000000;
        }
    }
    else {
        prop = icalcomponent_get_first_property(comp, ICAL_DTEND_PROPERTY);
        if (prop) {
            jmapical_datetime_from_icalprop(prop, &dt);
            endnano = dt.nano;
        }
    }

    /* utcStart and utcEnd */
    jmapical_datetime_from_icaltime(utcstart, &bp.utcstart);
    bp.utcstart.nano = startnano;
    jmapical_datetime_from_icaltime(utcend, &bp.utcend);
    bp.utcend.nano = endnano;

    /* busyStatus */
    bp.status = ICAL_STATUS_NONE;
    prop = icalcomponent_get_first_property(comp, ICAL_STATUS_PROPERTY);
    if (prop) {
        bp.status = icalproperty_get_status(prop);
    }

    /* event */
    enum icalproperty_class class = ICAL_CLASS_NONE;
    prop = icalcomponent_get_first_property(comp, ICAL_CLASS_PROPERTY);
    if (prop) class = icalproperty_get_class(prop);
    if (rock->show_details && rock->jevent &&
            class != ICAL_CLASS_PRIVATE && class != ICAL_CLASS_CONFIDENTIAL) {

        /* Build event instance */
        json_t *jevent = NULL;
        prop = icalcomponent_get_first_property(comp, ICAL_RECURRENCEID_PROPERTY);
        if (prop) {
            /* A recurrence override. */
            json_t *joverrides = json_object_get(rock->jevent, "recurrenceOverrides");
            jmapical_datetime_from_icalprop(prop, &dt);
            jmapical_localdatetime_as_string(&dt, rock->buf);
            const char *recurid;
            json_t *jval;
            json_object_foreach(joverrides, recurid, jval) {
                if (!strcmpsafe(recurid, buf_cstring(rock->buf))) {
                    jevent = jmap_patchobject_apply(rock->jevent, jval, NULL);
                    break;
                }
            }
            buf_reset(rock->buf);
        }
        if (!jevent) {
            /* Copy from main event */
            jevent = json_copy(rock->jevent); // shallow copy
        }

        /* Set start */
        jmapical_datetime_from_icaltime(start, &dt);
        dt.nano = startnano;
        jmapical_localdatetime_as_string(&dt, rock->buf);
        json_object_set_new(jevent, "start", json_string(buf_cstring(rock->buf)));
        buf_reset(rock->buf);

        /* Filter properties and set event */
        json_object_del(jevent, "recurrenceOverrides");
        json_object_del(jevent, "recurrenceRules");
        json_object_del(jevent, "excludedRecurrenceRules");
        jmap_filterprops(jevent, rock->eventprops);
        bp.jevent = jevent;
    }

    dynarray_append(rock->busyperiods, &bp);

    return 1;
}

static int principal_getavailability_cb(void *vrock, struct caldav_data *cdata)
{
    struct principal_getavailability_rock *rock = vrock;
    icalcomponent *ical = NULL;
    int r = 0;

    if (cdata->comp_type != CAL_COMP_VEVENT) return 0;

    /* Lookup mailbox entry */
    if (!rock->mbentry ||
            (cdata->dav.mailbox_byname &&
             strcmp(rock->mbentry->name, cdata->dav.mailbox)) ||
            (!cdata->dav.mailbox_byname &&
             strcmp(rock->mbentry->uniqueid, cdata->dav.mailbox))) {
        mboxlist_entry_free(&rock->mbentry);
        rock->mbentry = jmap_mbentry_from_dav(rock->req, &cdata->dav);
        if (!rock->mbentry) {
            xsyslog(LOG_ERR, "no mbentry for mailbox",
                    "dav.mailbox=<%s> dav.mailbox_byname=<%d>",
                    cdata->dav.mailbox, cdata->dav.mailbox_byname);
            return 0;
        }
    }

    if (!rock->mbox || strcmp(mailbox_uniqueid(rock->mbox), rock->mbentry->uniqueid)) {
        /* reset state for calendar collection */
        if (rock->mbox) {
            jmap_closembox(rock->req, &rock->mbox);
        }
        if (rock->floatingtz) {
            icaltimezone_free(rock->floatingtz, 1);
            rock->floatingtz = NULL;
        }
        rock->rights = 0;
        /* check ACL */
        if (rock->checkacl) {
            rock->rights = jmap_myrights_mbentry(rock->req, rock->mbentry);
            rock->cumulatedrights |= rock->rights;
            if (!(rock->rights & JACL_READFB)) {
                goto done;
            }
        }
        /* check if the collection is marked as transparent */
        const char *annot =
            DAV_ANNOT_NS "<" XML_NS_CALDAV ">schedule-calendar-transp";

        if (!annotatemore_lookupmask_mbe(rock->mbentry, annot, rock->req->userid,
                    rock->buf)) {
            if (!strcmp(buf_cstring(rock->buf), "transparent")) {
                goto done;
            }
            buf_reset(rock->buf);
        }
        r = jmap_openmbox(rock->req, rock->mbentry->name, &rock->mbox, 0);
        if (r) goto done;
        rock->floatingtz = caldav_get_calendar_tz(rock->mbentry->name,
                rock->req->userid);
    }

    ical = caldav_record_to_ical(rock->mbox, cdata, NULL, NULL);
    if (!ical) goto done;

    icalcomponent *comp = icalcomponent_get_first_real_component(ical);
    if (!comp || !getavailability_ishidden(comp)) {
        goto done;
    }

    /* Check mailbox-scoped ACL for showDetails */
    if (rock->show_details && rock->checkacl && !(rock->rights & ACL_READ)) {
        rock->show_details = 0;
    }
    if (rock->show_details) {
        /* Fetch all properties, we need them for recurrence overrides */
        rock->jevent = jmapical_tojmap(ical, NULL, rock->jmapctx);
    }

    struct icalperiodtype timerange = {
        rock->icalstart, rock->icalend, icaldurationtype_null_duration()
    };
    icalcomponent_myforeach(ical, timerange, rock->floatingtz,
            principal_getavailability_ical_cb, rock);
    json_decref(rock->jevent);
    rock->jevent = NULL;

done:
    if (ical) icalcomponent_free(ical);
    buf_reset(rock->buf);
    return r;
}

static int busyperiod_cmp QSORT_R_COMPAR_ARGS(const void *va,
                                              const void *vb,
                                              void *rock __attribute__((unused)))
{
    const struct busyperiod *a = va;
    const struct busyperiod *b = vb;

    int cmp = jmapical_datetime_compare(&a->utcstart, &b->utcstart);
    if (cmp) return cmp;

    if (a->jevent && !b->jevent) {
        return -1;
    }
    else if (!a->jevent && b->jevent) {
        return 1;
    }

    if (a->status != b->status) {
        if (a->status == ICAL_STATUS_CONFIRMED) {
            return -1;
        }
        if (b->status == ICAL_STATUS_CONFIRMED) {
            return 1;
        }
        if (a->status != ICAL_STATUS_TENTATIVE) {
            return -1;
        }
        if (b->status != ICAL_STATUS_TENTATIVE) {
            return 1;
        }
    }

    return 0;
}

static void principal_getavailability(jmap_req_t *req,
                                      const char *principalid,
                                      struct jmapical_datetime *dtstart,
                                      struct jmapical_datetime *dtend,
                                      int show_details,
                                      hash_table *props)
{
    struct caldav_db *db = caldav_open_userid(principalid);
    if (!db) {
        jmap_error(req, json_pack("{s:s s:s}", "type", "serverFail",
                    "description", "cannot open caldav db"));
        return;
    }

    icaltimezone *utc = icaltimezone_get_utc_timezone();
    struct buf buf = BUF_INITIALIZER;
    int checkacl = strcmp(req->userid, principalid);
    struct dynarray *busyperiods = dynarray_new(sizeof(struct busyperiod));
    struct jmapical_jmapcontext jmapctx;
    jmap_calendarcontext_init(&jmapctx, req);

    /* Lookup busytime across calendars */
    icaltimetype icalstart = jmapical_datetime_to_icaltime(dtstart, utc);
    time_t tstart = icaltime_as_timet_with_zone(icalstart, utc);
    icaltimetype icalend = jmapical_datetime_to_icaltime(dtend, utc);
    time_t tend = icaltime_as_timet_with_zone(icalend, utc);
    struct principal_getavailability_rock rock = {
        req,
        &buf,
        icalstart,
        icalend,
        principalid,
        busyperiods,
        show_details,
        &jmapctx,
        props,
        0,
        NULL,
        NULL,
        checkacl,
        0,
        NULL,
        NULL
    };

    enum caldav_sort sort[] = { CAL_SORT_MAILBOX };
    int r = caldav_foreach_timerange(db, NULL, tstart, tend, sort, 1,
                                     principal_getavailability_cb, &rock);
    if (r) jmap_error(req, jmap_server_error(r));
    if (rock.mbox) {
        jmap_closembox(req, &rock.mbox);
    }
    if (rock.mbentry) {
        mboxlist_entry_free(&rock.mbentry);
    }
    if (rock.floatingtz) {
        icaltimezone_free(rock.floatingtz, 1);
        rock.floatingtz = NULL;
    }
    if (r) return;

    /* Check cumulated calendar ACLs */
    if (checkacl) {
        if (!(rock.cumulatedrights & JACL_LOOKUP)) {
            jmap_error(req, json_pack("{s:s}", "type", "notFound"));
            goto done;
        }
        else if (!(rock.cumulatedrights & JACL_READFB)) {
            jmap_error(req, json_pack("{s:s}", "type", "forbidden"));
            goto done;
        }
    }

    /* The server MUST merge and split BusyPeriod objects where the “event”
     * property is null, such that none of them overlap and either there is a
     * gap in time between any two objects (the utcEnd of one does not equal
     * the utcStart of another) or those objects have a different busyStatus
     * property. If there are overlapping BusyPeriod time ranges with
     * different “busyStatus” properties the server MUST choose the value in
     * the following order: confirmed > unavailable > tentative. */
    cyr_qsort_r(busyperiods->data, busyperiods->count, sizeof(struct busyperiod),
            (int(*)(const void*, const void*, void*))busyperiod_cmp, NULL);
    int count = dynarray_size(busyperiods) ? 1 : 0;
    int i;
    for (i = 1; i < dynarray_size(busyperiods); i++) {
        struct busyperiod *bp = dynarray_nth(busyperiods, i);
        struct busyperiod *prevbp = dynarray_nth(busyperiods, count-1);
        if (bp->jevent || bp->status != prevbp->status ||
                jmapical_datetime_compare(&prevbp->utcend, &bp->utcstart) < 0) {
            /* Insert new busy period */
            dynarray_set(busyperiods, count++, bp);
        }
        else if (jmapical_datetime_compare(&prevbp->utcend, &bp->utcend) < 0) {
            /* Merge busy period */
            prevbp->utcend = bp->utcend;
        }
    }

    /* Build result */

    json_t *jbusyperiods = json_array();
    for (i = 0; i < count; i++) {
        struct busyperiod *bp = dynarray_nth(busyperiods, i);
        json_t *jb = json_object();

        /* utcStart */
        jmapical_utcdatetime_as_string(&bp->utcstart, &buf);
        json_object_set_new(jb, "utcStart", json_string(buf_cstring(&buf)));
        buf_reset(&buf);

        /* utcEnd */
        jmapical_utcdatetime_as_string(&bp->utcend, &buf);
        json_object_set_new(jb, "utcEnd", json_string(buf_cstring(&buf)));
        buf_reset(&buf);

        /* busyStatus */
        const char *busystatus = NULL;
        if (bp->status == ICAL_STATUS_TENTATIVE) {
            busystatus = "tentative";
        }
        else if (bp->status == ICAL_STATUS_CONFIRMED) {
            busystatus = "confirmed";
        }
        else if (bp->status == ICAL_STATUS_NONE) {
            busystatus = "unavailable";
        }
        json_object_set_new(jb, "busyStatus", json_string(busystatus));

        /* event */
        json_object_set(jb, "event", bp->jevent ? bp->jevent : json_null());

        json_array_append_new(jbusyperiods, jb);
    }
    jmap_ok(req, json_pack("{s:o}", "list", jbusyperiods));

done:
    buf_free(&buf);
    caldav_close(db);
    for (i = 0; i < dynarray_size(busyperiods); i++) {
        struct busyperiod *bp = dynarray_nth(busyperiods, i);
        json_decref(bp->jevent);
    }
    dynarray_free(&busyperiods);
    jmap_calendarcontext_fini(&jmapctx);
}

static int jmap_principal_getavailability(struct jmap_req *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    char *principalid = NULL;
    int show_details = 0;
    hash_table *props = NULL;

    struct jmapical_datetime dtstart = JMAPICAL_DATETIME_INITIALIZER;
    struct jmapical_datetime dtend = JMAPICAL_DATETIME_INITIALIZER;

    /* Parse arguments */
    const char *s;
    json_t *myargs = json_copy(req->args); // shallow copy
    if ((s = json_string_value(json_object_get(myargs, "id")))) {
        principalid = xstrdup(s);
        json_object_del(myargs, "id");
    }
    if ((s = json_string_value(json_object_get(myargs, "utcStart")))) {
        if (jmapical_utcdatetime_from_string(s, &dtstart) == 0) {
            json_object_del(myargs, "utcStart");
        }
    }
    if ((s = json_string_value(json_object_get(myargs, "utcEnd")))) {
        if (jmapical_utcdatetime_from_string(s, &dtend) == 0) {
            json_object_del(myargs, "utcEnd");
        }
    }
    if (json_is_boolean(json_object_get(myargs, "showDetails"))) {
        show_details = json_boolean_value(json_object_get(myargs, "showDetails"));
        json_object_del(myargs, "showDetails");
    }

    json_t *jprops = json_object_get(myargs, "eventProperties");
    if (json_is_array(jprops)) {
        props = xzmalloc(sizeof(hash_table));
        construct_hash_table(props, json_array_size(jprops) + 1, 0);
        json_t *jval;
        size_t i;
        json_array_foreach(jprops, i, jval) {
            const char *name = json_string_value(jval);
            const jmap_property_t *propdef = NULL;
            if (name) {
                propdef = jmap_property_find(name, event_props);
                if (propdef && propdef->capability &&
                        !jmap_is_using(req, propdef->capability)) {
                    propdef = NULL;
                }
            }
            if (propdef) {
                hash_insert(name, (void*)1, props);
            }
            else {
                jmap_parser_push_index(&parser, "eventProperties", i, name);
                jmap_parser_invalid(&parser, NULL);
                jmap_parser_pop(&parser);
            }
        }
        json_object_del(myargs, "eventProperties");
    }
    else if (jprops == NULL || json_is_null(jprops)) {
        json_object_del(myargs, "eventProperties");
    }

    if (json_object_size(myargs)) {
        const char *pname;
        json_t *jval;
        json_object_foreach(myargs, pname, jval) {
            jmap_parser_invalid(&parser, pname);
        }
        jmap_error(req, json_pack("{s:s s:O}", "type", "invalidArguments",
                    "arguments", parser.invalid));
        goto done;
    }
    json_decref(myargs);

    principal_getavailability(req, principalid, &dtstart, &dtend, show_details, props);

done:
    if (props) {
        free_hash_table(props, NULL);
        free(props);
    }
    jmap_parser_fini(&parser);
    free(principalid);
    return 0;
}

/* Notification helper functions */

struct find_notifuid_rock {
    int foldernum;
    uint32_t uid;
    int check_seen;
    struct seqset *seenuids;
};

static int find_notifuid_cb(const conv_guidrec_t *rec, void *vrock)
{
    struct find_notifuid_rock *rock = vrock;
    if (rec->foldernum != rock->foldernum) {
        return 0;
    }
    if ((rec->system_flags & FLAG_DELETED) ||
        (rec->internal_flags & FLAG_INTERNAL_EXPUNGED)) {
        return 0;
    }
    if (rock->check_seen) {
        if ((!rock->seenuids && rec->system_flags & FLAG_SEEN) ||
            (rock->seenuids && seqset_ismember(rock->seenuids, rec->uid))) {
            return 0;
        }
    }
    rock->uid = rec->uid;
    return CYRUSDB_DONE;
}

struct notifsearch_entry {
    struct message_guid guid;
    int is_tombstone;
    modseq_t modseq;
    time_t created;
};

struct notifsearch {
    const char *notiftype;
    int want_expunged;
    modseq_t since_modseq;
    int (*match)(message_t *msg, struct notifsearch_entry*, void*);
    void *matchrock;
    int (*sort)QSORT_R_COMPAR_ARGS(const void*, const void*, void*);
    void *sortrock;
    int check_seen;
};

static struct seqset *_readseen(struct mailbox *mbox, const char *userid)
{
    struct seqset *seenuids = NULL;
    struct seen *seendb = NULL;

    int r = seen_open(userid, SEEN_SILENT, &seendb);
    if (!r) {
        struct seendata sd = SEENDATA_INITIALIZER;
        r = seen_read(seendb, mailbox_uniqueid(mbox), &sd);
        if (!r) {
            seenuids = seqset_parse(sd.seenuids, NULL, sd.lastuid);
            seen_freedata(&sd);
        }
    }
    else if (r == IMAP_NOTFOUND) {
        seenuids = seqset_init(1, SEQ_MERGE);
    }
    if (r) {
        xsyslog(LOG_ERR, "can not read seen state",
                "userid=%s error=%s", userid, error_message(r));
    }

    seen_close(&seendb);
    return seenuids;
}

static void notifsearch_run(const char *userid,
                            struct mailbox *notifmbox,
                            struct notifsearch *search,
                            struct dynarray *entries,
                            json_t **errp)
{
    struct buf buf = BUF_INITIALIZER;
    struct seqset *seenuids = NULL;

    if (search->check_seen && !mailbox_internal_seen(notifmbox, userid)) {
        seenuids = _readseen(notifmbox, userid);
        if (!seenuids) {
            *errp = json_pack("{s:s s:s}", "type", "serverFail",
                    "description", "can not read seen state");
            return;
        }
    }

    struct mailbox_iter *iter = mailbox_iter_init(notifmbox, 0, 0);
    message_t *msg;
    while ((msg = (message_t *) mailbox_iter_step(iter))) {
        struct notifsearch_entry entry = { MESSAGE_GUID_INITIALIZER, 0, 0, 0 };

        if (search->notiftype) {
            if (message_get_subject(msg, &buf) ||
                    strcmp(search->notiftype, buf_cstring(&buf))) {
                continue;
            }
        }

        const struct index_record *record = msg_record(msg);

        if ((record->system_flags & FLAG_DELETED) ||
            (record->internal_flags & FLAG_INTERNAL_EXPUNGED)) {
            if (search->check_seen) {
                continue;
            }
            else entry.is_tombstone = 1;
        }
        else if (search->check_seen) {
            entry.is_tombstone = (!seenuids && (record->system_flags & FLAG_SEEN)) ||
                (seenuids && seqset_ismember(seenuids, record->uid));
        }
        entry.created = record->internaldate;
        message_guid_copy(&entry.guid, &record->guid);
        entry.modseq = record->modseq;

        if (!search->want_expunged && entry.is_tombstone) {
            continue;
        }
        if (search->since_modseq) {
            if (entry.modseq <= search->since_modseq) {
                // no change since last /changes call - ignore
                continue;
            }
            if (search->check_seen) {
                // seen flags are managed per sharee but the record modseq
                // is global. in order to track changes we always bump
                // the modseq of a record if its seen flag got set for one
                // of the sharees. this allows to report this notification
                // as destroyed, but as a consequence sharees may see the
                // same notification as destroyed multiple times. we assume
                // that clients just ignore these duplicate destroys.
                if (record->createdmodseq > search->since_modseq) {
                    if (entry.is_tombstone) {
                        // notification got created and dismissed
                        // since last /changes call - ignore
                        continue;
                    }
                }
                else if (!entry.is_tombstone) {
                    // notification must have been reported as 'added'
                    // in a previous /changes call - ignore
                    continue;
                }
            }
        }
        if (search->match && !search->match(msg, &entry, search->matchrock)) {
            continue;
        }

        dynarray_append(entries, &entry);
    }
    mailbox_iter_done(&iter);

    if (search->sort) {
        cyr_qsort_r(entries->data, entries->count,
                sizeof(struct notifsearch_entry),
                (int(*)(const void*, const void*, void*))search->sort,
                search->sortrock);
    }

    seqset_free(&seenuids);
    buf_free(&buf);
}

static int notifsearch_entry_modseq_cmp QSORT_R_COMPAR_ARGS(const void *va,
                                                            const void *vb,
                                                            void *rock __attribute__((unused)))
{
    const struct notifsearch_entry *a = va;
    const struct notifsearch_entry *b = vb;
    if (a->modseq < b->modseq)
        return -1;
    else if (a->modseq > b->modseq)
        return 1;
    else
        return 0;
}

static int notifsearch_entry_created_cmp QSORT_R_COMPAR_ARGS(const void *va,
                                                             const void *vb,
                                                             void *rock)
{
    const struct notifsearch_entry *a = va;
    const struct notifsearch_entry *b = vb;
    intptr_t is_ascending = (intptr_t) rock;
    int sign = is_ascending ? 1 : -1;

    if (a->created < b->created)
        return -1 * sign;
    else if (a->created > b->created)
        return 1 * sign;
    else
        return 0;
}

static void notif_query(struct jmap_req *req,
                        struct jmap_query *query,
                        struct mailbox *notifmbox,
                        struct notifsearch *search,
                        json_t **errp)
{
    /* Find entries */
    struct dynarray *entries = dynarray_new(sizeof(struct notifsearch_entry));
    notifsearch_run(req->userid, notifmbox, search, entries, errp);
    if (*errp) goto done;

    query->total = dynarray_size(entries);

    /* Apply windowing */
    size_t startpos = 0;
    if (query->anchor) {
        ssize_t j;
        for (j = 0; j < dynarray_size(entries); j++) {
            struct notifsearch_entry *entry = dynarray_nth(entries, j);
            if (!strcmpsafe(query->anchor, message_guid_encode(&entry->guid))) {
                /* Found anchor */
                if (query->anchor_offset < 0) {
                    startpos = -query->anchor_offset > j ?
                        0 : j + query->anchor_offset;
                }
                else {
                    startpos = j + query->anchor_offset;
                }
                break;
            }
        }
    }
    else if (query->position < 0) {
        startpos = ((size_t) -query->position) > (size_t) dynarray_size(entries) ?
            0 : dynarray_size(entries) + query->position;
    }
    else startpos = query->position;
    query->result_position = startpos;
    /* Build result list */
    size_t i;
    for (i = startpos; i < (size_t) dynarray_size(entries); i++) {
        if (query->have_limit && json_array_size(query->ids) >= query->limit) {
            break;
        }
        struct notifsearch_entry *entry = dynarray_nth(entries, i);
        json_array_append_new(query->ids,
                json_string(message_guid_encode(&entry->guid)));
    }

done:
    dynarray_free(&entries);
}

static void notif_get(struct jmap_req *req,
                      struct jmap_get *get,
                      const mbentry_t *notifmb,
                      int check_seen,
                      json_t*(*tojmap)(jmap_req_t*, message_t*, hash_table*, void*),
                      void *tojmap_rock,
                      json_t **err)
{
    struct mailbox *notifmbox = NULL;
    struct seqset *seenuids = NULL;

    int r = jmap_openmbox(req, notifmb->name, &notifmbox, 0);
    if (r) {
        if (r != IMAP_MAILBOX_NONEXISTENT) {
            *err = jmap_server_error(r);
        }
        goto done;
    }

    if (check_seen && !mailbox_internal_seen(notifmbox, req->userid)) {
        seenuids = _readseen(notifmbox, req->userid);
        if (!seenuids) {
            *err = json_pack("{s:s s:s}", "type", "serverFail",
                    "description", "can not read seen state");
            goto done;
        }
    }

    if (JNOTNULL(get->ids)) {
        json_t *jval;
        size_t i;
        int foldernum = conversation_folder_number(req->cstate,
                CONV_FOLDER_KEY_MBE(req->cstate, notifmb), 0);
        json_array_foreach(get->ids, i, jval) {
            const char *id = json_string_value(jval);
            json_t *jn = NULL;
            struct find_notifuid_rock rock = {
                foldernum, 0, check_seen, seenuids
            };
            conversations_guid_foreach(req->cstate, id, find_notifuid_cb, &rock);
            if (rock.uid) {
                message_t *msg = message_new_from_mailbox(notifmbox, rock.uid);
                if (msg) {
                    jn = tojmap(req, msg, get->props, tojmap_rock);
                    message_unref(&msg);
                }
            }
            if (jn) {
                json_array_append_new(get->list, jn);
            }
            else json_array_append_new(get->not_found, json_string(id));
        }
    }
    else {
        struct mailbox_iter *iter = mailbox_iter_init(notifmbox, 0, 0);
        message_t *msg;
        while ((msg = (message_t *) mailbox_iter_step(iter))) {
            uint32_t system_flags;
            uint32_t internal_flags;
            if (message_get_systemflags(msg, &system_flags) ||
                    message_get_internalflags(msg, &internal_flags)) {
                continue;
            }
            if ((system_flags & FLAG_DELETED) ||
                (internal_flags & FLAG_INTERNAL_EXPUNGED)) {
                continue;
            }
            if (check_seen) {
                uint32_t uid;
                if (message_get_uid(msg, &uid)) {
                    continue;
                }
                if ((!seenuids && system_flags & FLAG_SEEN) ||
                    (seenuids && seqset_ismember(seenuids, uid))) {
                    continue;
                }
            }
            json_t *jn = tojmap(req, msg, get->props, tojmap_rock);
            if (jn) json_array_append_new(get->list, jn);
        }
        mailbox_iter_done(&iter);
    }

done:
    jmap_closembox(req, &notifmbox);
    seqset_free(&seenuids);
}

static void notif_set(struct jmap_req *req,
                      struct jmap_set *set,
                      const mbentry_t *notifmb,
                      int set_seen,
                      modseq_t statemodseq,
                      time_t expunge_all_before,
                      json_t **err)
{
    struct mailbox *notifmbox = NULL;
    struct seen *seendb = NULL;
    struct seqset *seenuids = NULL;
    struct buf buf = BUF_INITIALIZER;

    buf_printf(&buf, MODSEQ_FMT, statemodseq);
    set->old_state = buf_release(&buf);

    if (set->if_in_state && strcmp(set->old_state, set->if_in_state)) {
        jmap_error(req, json_pack("{s:s}", "type", "stateMismatch"));
        goto done;
    }

    const char *id;
    json_t *jval;
    json_object_foreach(set->create, id, jval) {
        json_object_set_new(set->not_created, id,
                json_pack("{s:s}", "type", "forbidden"));
    }
    json_object_foreach(set->update, id, jval) {
        json_object_set_new(set->not_updated, id,
                json_pack("{s:s}", "type", "forbidden"));
    }

    if (!json_array_size(set->destroy)) goto done;

    int r = jmap_openmbox(req, notifmb->name, &notifmbox, 1);
    if (r) {
        *err = jmap_server_error(r);
        goto done;
    }

    if (set_seen && !mailbox_internal_seen(notifmbox, req->userid)) {
        r = seen_open(req->userid, SEEN_CREATE, &seendb);
        if (r) {
            buf_setcstr(&buf, "can not open seen.db: ");
            buf_appendcstr(&buf, error_message(r));
            *err = json_pack("{s:s s:s}", "type", "serverFail",
                    "description", buf_cstring(&buf));
            goto done;
        }
        struct seendata sd = SEENDATA_INITIALIZER;
        r = seen_lockread(seendb, mailbox_uniqueid(notifmbox), &sd);
        if (r) {
            buf_setcstr(&buf, "can not read seen.db: ");
            buf_appendcstr(&buf, error_message(r));
            *err = json_pack("{s:s s:s}", "type", "serverFail",
                    "description", buf_cstring(&buf));
            goto done;
        }
        seenuids = seqset_parse(sd.seenuids, NULL, sd.lastuid);
        seen_freedata(&sd);
    }

    int foldernum = conversation_folder_number(req->cstate,
            CONV_FOLDER_KEY_MBE(req->cstate, notifmb), 0);

    size_t i;
    json_array_foreach(set->destroy, i, jval) {
        const char *id = json_string_value(jval);
        struct find_notifuid_rock rock = {
            foldernum, 0, set_seen, seenuids
        };
        struct index_record record;
        r = conversations_guid_foreach(req->cstate, id, find_notifuid_cb, &rock);
        if (rock.uid) {
            r = mailbox_find_index_record(notifmbox, rock.uid, &record);
            if (!r) {
                if (set_seen) {
                    if (seenuids) {
                        seqset_add(seenuids, record.uid, 1);
                    }
                    else {
                        record.system_flags |= FLAG_SEEN;
                    }
                }
                else {
                    record.internal_flags |= FLAG_INTERNAL_EXPUNGED;
                }
                r = mailbox_rewrite_index_record(notifmbox, &record);
            }
        }
        if (!r && rock.uid) {
            json_array_append(set->destroyed, jval);
        }
        else {
            json_object_set_new(set->not_destroyed, id,
                    r ? jmap_server_error(r) :
                         json_pack("{s:s}", "type", "notFound"));
        }
    }

    if (seenuids) {
        /* Write seen.db */
        struct seendata sd = SEENDATA_INITIALIZER;
        sd.seenuids = seqset_cstring(seenuids);
        if (!sd.seenuids) sd.seenuids = xstrdup("");
        sd.lastread = time(NULL);
        sd.lastchange = sd.lastread;
        sd.lastuid = seqset_last(seenuids);
        r = seen_write(seendb, mailbox_uniqueid(notifmbox), &sd);
        seen_freedata(&sd);
        if (r) {
            buf_setcstr(&buf, "can not write seen.db: ");
            buf_appendcstr(&buf, error_message(r));
            json_array_foreach(set->destroyed, i, jval) {
                json_object_set_new(set->not_destroyed,
                        json_string_value(jval),
                        json_pack("{s:s s:s}",
                            "type", "serverFail",
                            "description", buf_cstring(&buf)));
            }
            json_array_clear(set->destroyed);
            buf_reset(&buf);
            goto done;
        }
        /* seen.db won't bump the modseq, so force that here */
        mboxname_nextmodseq(notifmb->name, statemodseq, MBTYPE_JMAPNOTIFY, 0);
    }

    if (expunge_all_before) {
        struct mailbox_iter *iter = mailbox_iter_init(notifmbox, 0, 0);
        message_t *msg;
        while ((msg = (message_t *) mailbox_iter_step(iter))) {
            struct index_record record = *msg_record(msg);
            if (record.internaldate < expunge_all_before &&
                !(record.system_flags & FLAG_DELETED) &&
                !(record.internal_flags & FLAG_INTERNAL_EXPUNGED)) {
                    record.internal_flags |= FLAG_INTERNAL_EXPUNGED;
                    mailbox_rewrite_index_record(notifmbox, &record);
            }
        }
        mailbox_iter_done(&iter);
    }

done:
    seqset_free(&seenuids);
    seen_close(&seendb);
    jmap_closembox(req, &notifmbox);
    buf_free(&buf);
}

static void notif_changes(struct jmap_req *req,
                          struct jmap_changes *changes,
                          modseq_t statemodseq,
                          modseq_t statedeletedmodseq,
                          const char *notifmboxname,
                          const char *notiftype,
                          int check_seen,
                          int (*match)(message_t *msg, struct notifsearch_entry*, void*),
                          void *matchrock,
                          json_t **errp)
{
    if (changes->since_modseq < statedeletedmodseq) {
        *errp = json_pack("{s:s}", "type", "cannotCalculateChanges");
        return;
    }

    struct dynarray *entries = dynarray_new(sizeof(struct notifsearch_entry));
    struct mailbox *notifmbox = NULL;

    int r = jmap_openmbox(req, notifmboxname, &notifmbox, 0);
    if (r) {
        if (r == IMAP_MAILBOX_NONEXISTENT) {
            changes->new_modseq = statemodseq;
        }
        else *errp = jmap_server_error(r);
        goto done;
    }

    /* Lookup and sort entries */
    struct notifsearch search = {
        notiftype,
        1, /* want_expunged */
        changes->since_modseq,
        match,
        matchrock,
        notifsearch_entry_modseq_cmp,
        NULL,   /* sortrock */
        check_seen
    };
    notifsearch_run(req->userid, notifmbox, &search, entries, errp);
    if (*errp) goto done;

    /* Clamp entries to maxChanges and determine newState */
    if (changes->max_changes && changes->max_changes < (size_t) dynarray_size(entries)) {
        dynarray_truncate(entries, changes->max_changes);
        struct notifsearch_entry *entry = dynarray_nth(entries, -1);
        changes->new_modseq = entry->modseq;
        changes->has_more_changes = 1;
    }
    else if (dynarray_size(entries)) {
        struct notifsearch_entry *entry = dynarray_nth(entries, -1);
        changes->new_modseq = entry->modseq;
    }
    else changes->new_modseq = statemodseq;

    /* Build response */
    int i;
    for (i = 0; i < dynarray_size(entries); i++) {
        struct notifsearch_entry *entry = dynarray_nth(entries, i);
        json_array_append_new(entry->is_tombstone ?
                changes->destroyed : changes->created,
                json_string(message_guid_encode(&entry->guid)));
    }

done:
    dynarray_free(&entries);
    jmap_closembox(req, &notifmbox);
}


static const jmap_property_t sharenotification_props[] = {
    {
        "id",
        NULL,
        JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE | JMAP_PROP_ALWAYS_GET
    },
    {
        "created",
        NULL,
        JMAP_PROP_SERVER_SET
    },
    {
        "changedBy",
        NULL,
        JMAP_PROP_SERVER_SET
    },
    {
        "objectType",
        NULL,
        JMAP_PROP_SERVER_SET
    },
    {
        "objectAccountId",
        NULL,
        JMAP_PROP_SERVER_SET
    },
    {
        "objectId",
        NULL,
        JMAP_PROP_SERVER_SET
    },
    {
        "oldRights",
        NULL,
        JMAP_PROP_SERVER_SET
    },
    {
        "newRights",
        NULL,
        JMAP_PROP_SERVER_SET
    },
    { NULL, NULL, 0 }
};

static json_t *sharenotif_tojmap(jmap_req_t *req, message_t *msg, hash_table *props,
                                 void *rock __attribute__((unused)))
{
    struct buf buf = BUF_INITIALIZER;
    json_t *jn = NULL;
    mbname_t *mbname = NULL;
    struct dlist *dl = NULL;
    xmlDocPtr doc = NULL;

    /* Make sure it's a calendar share notification */
    if (message_get_subject(msg, &buf) ||
            strcmp(buf_cstring(&buf), SHARE_INVITE_NOTIFICATION)) {
        goto done;
    }
    buf_reset(&buf);

    /* Read message */
    uint32_t uid;
    message_get_uid(msg, &uid);

    const struct message_guid *guid = NULL;
    if (message_get_guid(msg, &guid)) {
        goto done;
    }

    struct index_record record = *msg_record(msg);
    if ((record.system_flags & FLAG_DELETED) ||
            (record.internal_flags & FLAG_INTERNAL_EXPUNGED)) {
        goto done;
    }

    const struct body *body;
    int r = message_get_cachebody(msg, &body);
    if (r) {
        xsyslog(LOG_ERR, "can't open cachebody", "uid=%d error=%s",
                uid, error_message(r));
        goto done;
    }
    r = dlist_parsemap(&dl, 1, 0, body->description, strlen(body->description));
    if (r) {
        xsyslog(LOG_ERR, "can't parse description", "uid=%d error=%s",
                uid, error_message(r));
        goto done;
    }

    struct dlist *ddl = dlist_getchild(dl, "D");
    if (ddl) {
        const char *mboxname;
        if (dlist_getatom(ddl, "M", &mboxname) &&
                mboxname_iscalendarmailbox(mboxname, 0)) {
            mbname = mbname_from_intname(mboxname);
        }
    }
    if (!mbname) goto done;

    /* Parse XML notification */
    if (!message_get_body(msg, &buf)) {
        xmlParserCtxtPtr ctxt = xmlNewParserCtxt();
        if (ctxt) {
            doc = xmlCtxtReadMemory(ctxt, buf_base(&buf), buf_len(&buf),
                    NULL, NULL, XML_PARSE_NOWARNING);
            xmlFreeParserCtxt(ctxt);
        }
        buf_reset(&buf);
    }
    if (!doc) goto done;
    xmlNodePtr root = xmlDocGetRootElement(doc);
    if (!root) goto done;

    /* id */
    jn = json_object();
    json_object_set_new(jn, "id", json_string(message_guid_encode(guid)));

    if (jmap_wantprop(props, "created")) {
        xmlNodePtr node = xmlFirstElementChild(root);
        if (node && !xmlStrcmp(node->name, BAD_CAST "dtstamp")) {
            xmlChar *val = xmlNodeGetContent(node);
            json_object_set_new(jn, "created", json_string((const char*) val));
            xmlFree(val);
        }
    }

    const char *calid = strarray_nth(mbname_boxes(mbname), -1);
    if (jmap_wantprop(props, "objectType")) {
        json_object_set_new(jn, "objectType", json_string("Calendar"));
    }
    if (jmap_wantprop(props, "objectId")) {
        json_object_set_new(jn, "objectId", json_string(calid));
    }
    if (jmap_wantprop(props, "objectAccountId")) {
        json_object_set_new(jn, "objectAccountId",
                json_string(mbname_userid(mbname)));
    }

    xmlNodePtr node;
    for (node = xmlFirstElementChild(xmlLastElementChild(root)); node;
            node = xmlNextElementSibling(node)) {

        if (jmap_wantprop(props, "changedBy") &&
                !xmlStrcmp(node->name, BAD_CAST "principal")) {
            json_t *changedby = json_object();
            xmlChar *xhref = NULL;
            xmlChar *xname = NULL;
            xmlNodePtr node2;
            for (node2 = xmlFirstElementChild(node);
                    node2; node2 = xmlNextElementSibling(node2)) {
                if (!xmlStrcmp(node2->name, BAD_CAST "href")) {
                    xhref = xmlNodeGetContent(node2);
                }
                else if (!xmlStrcmp(node2->name, BAD_CAST "prop")) {
                    xmlNodePtr node3 = xmlFirstElementChild(node2);
                    if (node3 && !xmlStrcmp(node3->name, BAD_CAST "displayname")) {
                        xname = xmlNodeGetContent(node3);
                    }
                }
            }
            if (xhref) {
                const char *href = (const char *) xhref;
                struct request_target_t tgt = { 0 };
                tgt.allow = ALLOW_CAL;
                const char *errstr = NULL;
                if (principal_parse_path(href, &tgt, &errstr) == 0) {
                    json_object_set_new(changedby, "principalId",
                            json_string(tgt.userid));

                    json_t *email = json_null();
                    char *calhomename = caldav_mboxname(tgt.userid, NULL);
                    strarray_t addrs = STRARRAY_INITIALIZER;
                    get_schedule_addresses(NULL, calhomename, tgt.userid, &addrs);
                    if (strarray_size(&addrs)) {
                        const char *addr = strarray_nth(&addrs, 0);
                        if (!strncasecmp(addr, "mailto:", 7)) addr += 7;
                        if (*addr) email = json_string(strarray_nth(&addrs, 0));
                    }
                    json_object_set_new(changedby, "email", email);
                    strarray_fini(&addrs);
                    free(calhomename);
                    request_target_fini(&tgt);
                }
            }
            if (xname) {
                json_object_set_new(changedby, "name",
                        json_string((const char *)xname));
            }
            if (!json_object_size(changedby)) {
                json_decref(changedby);
                changedby = json_null();
            }
            json_object_set_new(jn, "changedBy", changedby);
            xmlFree(xname);
            xmlFree(xhref);
        }
    }

    if (jmap_wantprop(props, "oldRights") || jmap_wantprop(props, "newRights")) {
        json_t *oldrights = json_null();
        json_t *newrights = json_null();
        struct dlist *xl = dlist_getchild(dlist_getchild(dl, "X"), "ACL");
        if (xl) {
            const char *aclstr = NULL;
            int is_owner = !strcmp(req->userid, mbname_userid(mbname));
            if (dlist_getatom(xl, "OLD", &aclstr) && *aclstr) {
                int rights;
                if (cyrus_acl_strtomask(aclstr, &rights) == 0) {
                    oldrights = calendarrights_to_jmap(rights, is_owner);
                }
            }
            if (dlist_getatom(xl, "NEW", &aclstr) && *aclstr) {
                int rights;
                if (cyrus_acl_strtomask(aclstr, &rights) == 0) {
                    newrights = calendarrights_to_jmap(rights, is_owner);
                }
            }
        }
        if (jmap_wantprop(props, "oldRights")) {
            json_object_set_new(jn, "oldRights", oldrights);
        }
        else json_decref(oldrights);
        if (jmap_wantprop(props, "newRights")) {
            json_object_set_new(jn, "newRights", newrights);
        }
        else json_decref(newrights);
    }

done:
    if (doc) xmlFreeDoc(doc);
    mbname_free(&mbname);
    dlist_free(&dl);
    buf_free(&buf);
    return jn;
}

static int jmap_sharenotification_get(struct jmap_req *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_get get;
    json_t *err = NULL;
    mbentry_t *notifymb = NULL;

    jmap_get_parse(req, &parser, sharenotification_props,
                   1, NULL, NULL, &get, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }


    int r = dav_lookup_notify_collection(req->accountid, &notifymb);
    if (!r) {
        if (!jmap_hasrights_mbentry(req, notifymb, JACL_READITEMS)) {
            r = IMAP_PERMISSION_DENIED;
        }
    }
    if (!r) {
        notif_get(req, &get, notifymb, 0, sharenotif_tojmap, NULL, &err);
        if (err) {
            jmap_error(req, err);
            goto done;
        }
    }
    else if (r) {
        xsyslog(r == IMAP_MAILBOX_NONEXISTENT ? LOG_WARNING : LOG_ERR,
                "no DAV notification mailbox found",
                "accountid=<%s>", req->accountid);
        if (r != IMAP_MAILBOX_NONEXISTENT) {
            jmap_error(req, jmap_server_error(r));
            goto done;
        }
    }

    struct buf buf = BUF_INITIALIZER;
    buf_printf(&buf, MODSEQ_FMT, req->counters.davnotificationmodseq);
    get.state = buf_release(&buf);
    buf_free(&buf);


    jmap_ok(req, jmap_get_reply(&get));

done:
    mboxlist_entry_free(&notifymb);
    jmap_parser_fini(&parser);
    jmap_get_fini(&get);
    return 0;
}

static int jmap_sharenotification_set(struct jmap_req *req)
{
    struct mboxlock *namespacelock = user_namespacelock(req->accountid);
    struct jmap_parser argparser = JMAP_PARSER_INITIALIZER;
    struct jmap_set set;
    json_t *err = NULL;
    mbentry_t *notifmb = NULL;

    jmap_set_parse(req, &argparser, NULL, NULL, NULL, &set, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    int r = dav_lookup_notify_collection(req->accountid, &notifmb);
    if (!r) {
        static int needrights = JACL_READITEMS|JACL_REMOVEITEMS;
        if (!jmap_hasrights_mbentry(req, notifmb, needrights)) {
            r = IMAP_PERMISSION_DENIED;
        }
    }
    if (r) {
        jmap_error(req, jmap_server_error(r));
        goto done;
    }

    notif_set(req, &set, notifmb, 0, req->counters.davnotificationmodseq, 0, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    if (json_array_size(set.destroyed)) {
        mboxname_read_counters(notifmb->name, &req->counters);
    }
    struct buf buf = BUF_INITIALIZER;
    buf_printf(&buf, MODSEQ_FMT, req->counters.davnotificationmodseq);
    set.new_state = buf_release(&buf);
    jmap_ok(req, jmap_set_reply(&set));

done:
    mboxlist_entry_free(&notifmb);
    mboxname_release(&namespacelock);
    jmap_parser_fini(&argparser);
    jmap_set_fini(&set);
    return 0;
}

static int jmap_sharenotification_changes(struct jmap_req *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_changes changes;
    mbentry_t *notifmb = NULL;
    json_t *err = NULL;

    jmap_changes_parse(req, &parser, req->counters.davnotificationdeletedmodseq,
                       NULL, NULL, &changes, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    int r = dav_lookup_notify_collection(req->accountid, &notifmb);
    if (!r) {
        static int needrights = JACL_READITEMS;
        if (!jmap_hasrights_mbentry(req, notifmb, needrights)) {
            r = IMAP_PERMISSION_DENIED;
        }
    }
    if (r) {
        jmap_error(req, jmap_server_error(r));
        goto done;
    }

    notif_changes(req, &changes,
            req->counters.davnotificationmodseq,
            req->counters.davnotificationdeletedmodseq,
            notifmb->name, SHARE_INVITE_NOTIFICATION,
            /*check_seen*/0, NULL, NULL, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    jmap_ok(req, jmap_changes_reply(&changes));

  done:
    mboxlist_entry_free(&notifmb);
    jmap_changes_fini(&changes);
    jmap_parser_fini(&parser);
    return 0;
}

static void sharenotif_validatefilter(jmap_req_t *req __attribute__((unused)),
                                      struct jmap_parser *parser,
                                      json_t *filter,
                                      json_t *unsupported __attribute__((unused)),
                                      void *rock __attribute__((unused)),
                                      json_t **err __attribute__((unused)))
{
    const char *field;
    json_t *arg;
    json_object_foreach(filter, field, arg) {
        if (!strcmp(field, "after") || !strcmp(field, "before")) {
            if (JNOTNULL(arg)) {
                struct jmapical_datetime dt = JMAPICAL_DATETIME_INITIALIZER;
                const char *s = json_string_value(arg);
                if (!s || jmapical_utcdatetime_from_string(s, &dt) == -1) {
                    jmap_parser_invalid(parser, field);
                }
            }
        }
        else if (!strcmp(field, "objectType")) {
            if (!json_is_string(arg)) {
                jmap_parser_invalid(parser, field);
            }
        }
        else if (!strcmp(field, "objectAccountId")) {
            if (!json_is_string(arg)) {
                jmap_parser_invalid(parser, field);
            }
        }
        else {
            jmap_parser_invalid(parser, field);
        }
    }
}

static int sharenotif_validatecomparator(jmap_req_t *req __attribute__((unused)),
                                            struct jmap_comparator *comp,
                                            void *rock __attribute__((unused)),
                                            json_t **err __attribute__((unused)))
{
    if (comp->collation) {
        return 0;
    }
    if (!strcmp(comp->property, "created")) {
        return 1;
    }
    return 0;
}

struct sharenotif_match_rock {
    time_t before;
    time_t after;
    const char *objectaccountid;
};

static int sharenotif_match(message_t *msg, struct notifsearch_entry *entry, void *vrock)
{
    struct sharenotif_match_rock *rock = vrock;

    /* before */
    if (rock->before && entry->created >= rock->before) {
        return 0;
    }
    /* after */
    if (rock->after && entry->created < rock->after) {
        return 0;
    }
    /* objectAccountId */
    if (rock->objectaccountid) {
        const struct body *body;
        int r = message_get_cachebody(msg, &body);
        if (r) return 0;

        struct dlist *dl;
        r = dlist_parsemap(&dl, 1, 0, body->description, strlen(body->description));
        if (r) return 0;

        int matches = 0;
        struct dlist *ddl = dlist_getchild(dl, "D");
        if (ddl) {
            const char *mboxname;
            if (dlist_getatom(ddl, "M", &mboxname) &&
                    mboxname_iscalendarmailbox(mboxname, 0)) {
                mbname_t *mbname = mbname_from_intname(mboxname);
                if (mbname) {
                    matches = !strcmp(mbname_userid(mbname), rock->objectaccountid);
                }
                mbname_free(&mbname);
            }
        }
        dlist_free(&dl);
        return matches;
    }

    return 1;
}

static int jmap_sharenotification_query(struct jmap_req *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_query query;
    struct mailbox *notifmbox = NULL;
    mbentry_t *notifmb = NULL;

    /* Parse request */
    json_t *err = NULL;
    jmap_query_parse(req, &parser, NULL, NULL,
                     sharenotif_validatefilter, NULL,
                     sharenotif_validatecomparator, NULL,
                     &query, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }
    if (json_array_size(parser.invalid)) {
        err = json_pack("{s:s}", "type", "invalidArguments");
        json_object_set(err, "arguments", parser.invalid);
        jmap_error(req, err);
        goto done;
    }

    /* Read filter. Only simple FilterCondition is supported. */
    if (JNOTNULL(json_object_get(query.filter, "op"))) {
        jmap_error(req, json_pack("{s:s}", "type", "unsupportedFilter"));
        goto done;
    }
    if (json_array_size(query.sort) > 1) {
        jmap_error(req, json_pack("{s:s}", "type", "unsupportedFilter"));
        goto done;
    }
    time_t after = 0, before = 0;
    const icaltimezone *utc = icaltimezone_get_utc_timezone();
    json_t *jval = json_object_get(query.filter, "before");
    if (json_is_string(jval)) {
        struct jmapical_datetime dt = JMAPICAL_DATETIME_INITIALIZER;
        if (!jmapical_utcdatetime_from_string(json_string_value(jval), &dt)) {
            icaltimetype icaldt = jmapical_datetime_to_icaltime(&dt, utc);
            before = icaltime_as_timet_with_zone(icaldt, utc);
        }
    }
    jval = json_object_get(query.filter, "after");
    if (json_is_string(jval)) {
        struct jmapical_datetime dt = JMAPICAL_DATETIME_INITIALIZER;
        if (!jmapical_utcdatetime_from_string(json_string_value(jval), &dt)) {
            icaltimetype icaldt = jmapical_datetime_to_icaltime(&dt, utc);
            after = icaltime_as_timet_with_zone(icaldt, utc);
        }
    }

    jval = json_object_get(query.filter, "objectType");
    const char *objecttype = json_string_value(jval);
    jval = json_object_get(query.filter, "objectAccountId");
    const char *objectaccountid = json_string_value(jval);

    int is_ascending = 1;
    jval = json_object_get(json_array_get(query.sort, 0), "isAscending");
    if (jval) {
        is_ascending = json_boolean_value(jval);
    }

    int r = dav_lookup_notify_collection(req->accountid, &notifmb);
    if (!r) {
        static int needrights = JACL_READITEMS;
        if (jmap_hasrights_mbentry(req, notifmb, needrights)) {
            r = jmap_openmbox(req, notifmb->name, &notifmbox, 0);
        }
        else r = IMAP_PERMISSION_DENIED;
    }
    if (r) {
        jmap_error(req, jmap_server_error(r));
        goto done;
    }

    /* Ignore anything but calendar share notifications */
    if (objecttype && strcmp(objecttype, "Calendar")) {
        jmap_ok(req, jmap_query_reply(&query));
        goto done;
    }

    /* Run query */
    struct sharenotif_match_rock rock = {
        before, after, objectaccountid
    };

    struct notifsearch search = {
        SHARE_INVITE_NOTIFICATION,
        0, /* want_expunged */
        0, /* since_modseq */
        sharenotif_match,
        &rock,
        notifsearch_entry_created_cmp,
        (void*)(intptr_t) is_ascending,
        0 /* check_seen */
    };
    notif_query(req, &query, notifmbox, &search, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    struct buf buf = BUF_INITIALIZER;
    buf_printf(&buf, MODSEQ_FMT, req->counters.davnotificationmodseq);
    query.query_state = buf_release(&buf);

    json_t *res = jmap_query_reply(&query);
    jmap_ok(req, res);

done:
    jmap_closembox(req, &notifmbox);
    mboxlist_entry_free(&notifmb);
    jmap_query_fini(&query);
    jmap_parser_fini(&parser);
    return 0;
}

static int jmap_sharenotification_querychanges(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_querychanges query;

    json_t *err = NULL;
    jmap_querychanges_parse(req, &parser, NULL, NULL,
                            sharenotif_validatefilter, NULL,
                            sharenotif_validatecomparator, NULL,
                            &query, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }
    jmap_error(req, json_pack("{s:s}", "type", "cannotCalculateChanges"));

done:
    jmap_querychanges_fini(&query);
    jmap_parser_fini(&parser);
    return 0;
}

static const jmap_property_t calendareventnotification_props[] = {
    {
        "id",
        NULL,
        JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE | JMAP_PROP_ALWAYS_GET
    },
    {
        "created",
        NULL,
        JMAP_PROP_SERVER_SET
    },
    {
        "changedBy",
        NULL,
        JMAP_PROP_SERVER_SET
    },
    {
        "comment",
        NULL,
        JMAP_PROP_SERVER_SET
    },
    {
        "type",
        NULL,
        JMAP_PROP_SERVER_SET
    },
    {
        "calendarEventId",
        NULL,
        0,
    },
    {
        "isDraft",
        NULL,
        JMAP_PROP_SERVER_SET
    },
    {
        "event",
        NULL,
        JMAP_PROP_SERVER_SET
    },
    {
        "eventPatch",
        NULL,
        JMAP_PROP_SERVER_SET
    },
    { NULL, NULL, 0 }
};

struct eventnotif_tojmap_rock {
    int check_acl;
    const char *notfrom;
};

static json_t *eventnotif_tojmap(jmap_req_t *req,
                                 message_t *msg,
                                 hash_table *props,
                                 void *vrock)
{
    struct buf buf = BUF_INITIALIZER;
    struct eventnotif_tojmap_rock *rock = vrock;
    json_t *jn = NULL;

    if (message_get_from(msg, &buf) ||
            !strcmp(buf_cstring(&buf), rock->notfrom)) {
        goto done;
    }
    buf_reset(&buf);

    if (message_get_subject(msg, &buf) ||
            strcmp(buf_cstring(&buf), JMAP_NOTIF_CALENDAREVENT)) {
        goto done;
    }
    buf_reset(&buf);

    const struct message_guid *guid = NULL;
    if (message_get_guid(msg, &guid)) {
        goto done;
    }

    struct index_record record = *msg_record(msg);
    if ((record.system_flags & FLAG_DELETED) ||
            (record.internal_flags & FLAG_INTERNAL_EXPUNGED)) {
        goto done;
    }

    if (rock->check_acl) {
        /* Check ACL */
        // XXX - we really want to use mailbox-by-id here
        int have_rights = 0;
        const struct body *body;
        if (!message_get_cachebody(msg, &body)) {
            struct dlist *dl = NULL;
            if (!dlist_parsemap(&dl, 1, 0, body->description,
                        strlen(body->description))) {
                const char *mboxname;
                if (dlist_getatom(dl, "M", &mboxname)) {
                    have_rights = jmap_hasrights(req, mboxname, JACL_READITEMS);
                }
            }
            dlist_free(&dl);
        }
        if (!have_rights) goto done;
    }

    int r = message_get_body(msg, &buf);
    if (r) {
        uint32_t msguid;
        message_get_uid(msg, &msguid);
        xsyslog(LOG_ERR, "can't read notification", "uid=%d error=%s",
                msguid, error_message(r));
        goto done;
    }

    json_error_t jerr;
    jn = json_loads(buf_cstring(&buf), 0, &jerr);
    if (!jn) {
        uint32_t msguid;
        message_get_uid(msg, &msguid);
        xsyslog(LOG_ERR, "can't parse notification", "uid=%d error=%s",
                msguid, jerr.text);
        goto done;
    }
    jmap_filterprops(jn, props);
    json_object_set_new(jn, "id", json_string(message_guid_encode(guid)));

done:
    buf_free(&buf);
    return jn;
}

static int jmap_calendareventnotification_get(struct jmap_req *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_get get;
    json_t *err = NULL;
    char *notifmboxname = jmap_notifmboxname(req->accountid);
    char *notfrom = eventnotif_fromheader(req->userid);
    mbentry_t *notifmb = NULL;

    jmap_get_parse(req, &parser, calendareventnotification_props,
                   1, NULL, NULL, &get, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    struct eventnotif_tojmap_rock rock = {
        strcmp(req->accountid, req->userid), notfrom
    };
    int r = mboxlist_lookup(notifmboxname, &notifmb, NULL);
    if (!r) {
        notif_get(req, &get, notifmb, 1, eventnotif_tojmap, &rock, &err);
        if (err) {
            jmap_error(req, err);
            goto done;
        }
    }
    else if (r) {
        xsyslog(r == IMAP_MAILBOX_NONEXISTENT ? LOG_WARNING : LOG_ERR,
                "no JMAP notification mailbox found",
                "accountid=<%s>", req->accountid);
        if (r != IMAP_MAILBOX_NONEXISTENT) {
            jmap_error(req, jmap_server_error(r));
            goto done;
        }
    }

    struct buf buf = BUF_INITIALIZER;
    buf_printf(&buf, MODSEQ_FMT, req->counters.jmapnotificationmodseq);
    get.state = buf_release(&buf);
    buf_free(&buf);

    jmap_ok(req, jmap_get_reply(&get));

done:
    free(notifmboxname);
    free(notfrom);
    mboxlist_entry_free(&notifmb);
    jmap_parser_fini(&parser);
    jmap_get_fini(&get);
    return 0;
}

static void eventnotif_validatefilter(jmap_req_t *req __attribute__((unused)),
                                      struct jmap_parser *parser,
                                      json_t *filter,
                                      json_t *unsupported __attribute__((unused)),
                                      void *rock __attribute__((unused)),
                                      json_t **err __attribute__((unused)))
{
    const char *field;
    json_t *arg;

    json_object_foreach(filter, field, arg) {
        if (!strcmp(field, "after") || !strcmp(field, "before")) {
            if (JNOTNULL(arg)) {
                struct jmapical_datetime dt = JMAPICAL_DATETIME_INITIALIZER;
                const char *s = json_string_value(arg);
                if (!s || jmapical_utcdatetime_from_string(s, &dt) == -1) {
                    jmap_parser_invalid(parser, field);
                }
            }
        }
        else if (!strcmp(field, "type")) {
            const char *s = json_string_value(arg);
            if (strcmpsafe(s, "created") &&
                strcmpsafe(s, "updated") &&
                strcmpsafe(s, "destroyed")) {
                jmap_parser_invalid(parser, field);
            }
        }
        else if (!strcmp(field, "calendarEventIds")) {
            if (json_is_array(arg)) {
                size_t i;
                json_t *val;
                json_array_foreach(arg, i, val) {
                    const char *s = json_string_value(val);
                    if (!s) {
                        jmap_parser_push_index(parser, "calendarEventIds", i, NULL);
                        jmap_parser_invalid(parser, NULL);
                        jmap_parser_pop(parser);
                        continue;
                    }
                }
            }
            else jmap_parser_invalid(parser, field);
        }
        else {
            jmap_parser_invalid(parser, field);
        }
    }
}

static int eventnotif_validatecomparator(jmap_req_t *req __attribute__((unused)),
                                            struct jmap_comparator *comp,
                                            void *rock __attribute__((unused)),
                                            json_t **err __attribute__((unused)))
{
    if (comp->collation) {
        return 0;
    }
    if (!strcmp(comp->property, "created")) {
        return 1;
    }
    return 0;
}

struct eventnotif_match_rock {
    /* Callback state */
    jmap_req_t *req;
    struct buf buf;
    const char *notfrom;
    int check_acl;
    /* Filter criteria */
    time_t before;
    time_t after;
    const char *type;
    hash_table *eventids;
};

static int eventnotif_match(message_t *msg, struct notifsearch_entry *entry, void *vrock)
{
    struct eventnotif_match_rock *rock = vrock;

    if (rock->before && entry->created >= rock->before) {
        return 0;
    }
    if (rock->after && entry->created < rock->after) {
        return 0;
    }
    buf_reset(&rock->buf);
    if (message_get_from(msg, &rock->buf) ||
            !strcmpsafe(rock->notfrom, buf_cstring(&rock->buf))) {
        return 0;
    }

    if (rock->check_acl || rock->eventids || rock->type) {
        /* Parse content-description */
        const char *ical_uid = NULL;
        const char *type = NULL;
        const char *mboxname = NULL;
        struct dlist *dl = NULL;
        const struct body *body;
        if (!message_get_cachebody(msg, &body)) {
            if (!dlist_parsemap(&dl, 1, 0, body->description,
                        strlen(body->description))) {
                dlist_getatom(dl, "M", &mboxname);
                dlist_getatom(dl, "ID", &ical_uid);
                dlist_getatom(dl, "NT", &type);
            }
        }
        if (!dl || !ical_uid || !type || !mboxname) {
            dlist_free(&dl);
            return 0;
        }
        /* Evaluate criteria and ACL */
        int matches = 1;
        if (rock->eventids && !hash_lookup(ical_uid, rock->eventids)) {
            matches = 0;
        }
        if (rock->type && strcmp(rock->type, type)) {
            matches = 0;
        }
        if (rock->check_acl && !jmap_hasrights(rock->req, mboxname, JACL_READITEMS)) {
            matches = 0;
        }
        dlist_free(&dl);
        if (!matches) {
            return 0;
        }
    }

    return 1;
}

static int jmap_calendareventnotification_query(struct jmap_req *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_query query;
    struct mailbox *notifmbox = NULL;
    hash_table eventids = HASH_TABLE_INITIALIZER;

    /* Parse request */
    json_t *err = NULL;
    jmap_query_parse(req, &parser, NULL, NULL,
                     eventnotif_validatefilter, NULL,
                     eventnotif_validatecomparator, NULL,
                     &query, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }
    if (json_array_size(parser.invalid)) {
        err = json_pack("{s:s}", "type", "invalidArguments");
        json_object_set(err, "arguments", parser.invalid);
        jmap_error(req, err);
        goto done;
    }

    /* Read filter. Only simple FilterCondition is supported. */
    if (JNOTNULL(json_object_get(query.filter, "op"))) {
        jmap_error(req, json_pack("{s:s}", "type", "unsupportedFilter"));
        goto done;
    }
    if (json_array_size(query.sort) > 1) {
        jmap_error(req, json_pack("{s:s}", "type", "unsupportedFilter"));
        goto done;
    }
    time_t after = 0, before = 0;
    const icaltimezone *utc = icaltimezone_get_utc_timezone();
    json_t *jval = json_object_get(query.filter, "before");
    if (json_is_string(jval)) {
        struct jmapical_datetime dt = JMAPICAL_DATETIME_INITIALIZER;
        if (!jmapical_utcdatetime_from_string(json_string_value(jval), &dt)) {
            icaltimetype icaldt = jmapical_datetime_to_icaltime(&dt, utc);
            before = icaltime_as_timet_with_zone(icaldt, utc);
        }
    }
    jval = json_object_get(query.filter, "after");
    if (json_is_string(jval)) {
        struct jmapical_datetime dt = JMAPICAL_DATETIME_INITIALIZER;
        if (!jmapical_utcdatetime_from_string(json_string_value(jval), &dt)) {
            icaltimetype icaldt = jmapical_datetime_to_icaltime(&dt, utc);
            after = icaltime_as_timet_with_zone(icaldt, utc);
        }
    }
    jval = json_object_get(query.filter, "calendarEventIds");
    if (json_is_array(jval)) {
        construct_hash_table(&eventids, json_array_size(jval)+1, 0);
        json_t *jid;
        size_t i;
        json_array_foreach(jval, i, jid) {
            hash_insert(json_string_value(jid), (void*)1, &eventids);
        }
    }
    const char *type = NULL;
    jval = json_object_get(query.filter, "type");
    if (json_is_string(jval)) {
        type = json_string_value(jval);
    }

    /* Read sort */
    int is_ascending = 1;
    jval = json_object_get(json_array_get(query.sort, 0), "isAscending");
    if (jval) {
        is_ascending = json_boolean_value(jval);
    }

    char *notifmboxname = jmap_notifmboxname(req->accountid);
    int r = jmap_openmbox(req, notifmboxname, &notifmbox, 0);
    free(notifmboxname);
    if (r == IMAP_MAILBOX_NONEXISTENT) {
        r = 0;
    }
    else if (r) {
        jmap_error(req, jmap_server_error(r));
        goto done;
    }

    if (notifmbox) {
        char *notfrom = eventnotif_fromheader(req->userid);
        struct eventnotif_match_rock matchrock = {
            req,
            BUF_INITIALIZER,
            notfrom,
            strcmp(req->accountid, req->userid),
            before,
            after,
            type,
            eventids.size ? &eventids : NULL
        };
        struct notifsearch search = {
            JMAP_NOTIF_CALENDAREVENT,
            0, /* want_expunged */
            0, /* since_modseq */
            eventnotif_match,
            &matchrock,
            notifsearch_entry_created_cmp,
            (void*)(intptr_t) is_ascending,
            1 /* check_seen */
        };
        notif_query(req, &query, notifmbox, &search, &err);
        buf_free(&matchrock.buf);
        free(notfrom);
        if (err) {
            jmap_error(req, err);
            goto done;
        }
    }

    struct buf buf = BUF_INITIALIZER;
    buf_printf(&buf, MODSEQ_FMT, req->counters.jmapnotificationmodseq);
    query.query_state = buf_release(&buf);

    json_t *res = jmap_query_reply(&query);
    jmap_ok(req, res);

done:
    if (eventids.size) free_hash_table(&eventids, NULL);
    jmap_closembox(req, &notifmbox);
    jmap_query_fini(&query);
    jmap_parser_fini(&parser);
    return 0;
}

static int jmap_calendareventnotification_set(struct jmap_req *req)
{
    struct mboxlock *namespacelock = user_namespacelock(req->accountid);
    char *notifmboxname = jmap_notifmboxname(req->accountid);
    struct jmap_parser argparser = JMAP_PARSER_INITIALIZER;
    struct jmap_set set;
    json_t *err = NULL;
    mbentry_t *notifmb = NULL;

    jmap_set_parse(req, &argparser, NULL, NULL, NULL, &set, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    int r = mboxlist_lookup(notifmboxname, &notifmb, NULL);
    if (r) {
        jmap_error(req, jmap_server_error(r));
        goto done;
    }

    time_t expunge_all_before = time(NULL) - 60 * 60 * 24 * 30; // TODO add config option?
    notif_set(req, &set, notifmb, 1, req->counters.jmapnotificationmodseq,
            expunge_all_before, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    if (json_array_size(set.destroyed)) {
        mboxname_read_counters(notifmboxname, &req->counters);
    }
    struct buf buf = BUF_INITIALIZER;
    buf_printf(&buf, MODSEQ_FMT, req->counters.jmapnotificationmodseq);
    set.new_state = buf_release(&buf);
    jmap_ok(req, jmap_set_reply(&set));

done:
    mboxlist_entry_free(&notifmb);
    free(notifmboxname);
    mboxname_release(&namespacelock);
    jmap_parser_fini(&argparser);
    jmap_set_fini(&set);
    return 0;
}

static int jmap_calendareventnotification_changes(struct jmap_req *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_changes changes;
    json_t *err = NULL;

    jmap_changes_parse(req, &parser, req->counters.jmapnotificationdeletedmodseq,
                       NULL, NULL, &changes, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    char *notifmboxname = jmap_notifmboxname(req->accountid);
    char *notfrom = eventnotif_fromheader(req->userid);
    struct eventnotif_match_rock matchrock = {
        req,
        BUF_INITIALIZER,
        notfrom,
        strcmp(req->accountid, req->userid),
        0,
        0,
        NULL,
        NULL
    };
    notif_changes(req, &changes,
            req->counters.jmapnotificationmodseq,
            req->counters.jmapnotificationdeletedmodseq,
            notifmboxname, JMAP_NOTIF_CALENDAREVENT,
            /*check_seen*/1, eventnotif_match, &matchrock, &err);
    buf_free(&matchrock.buf);
    free(notifmboxname);
    free(notfrom);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    jmap_ok(req, jmap_changes_reply(&changes));

  done:
    jmap_changes_fini(&changes);
    jmap_parser_fini(&parser);
    return 0;
}

static int jmap_calendareventnotification_querychanges(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_querychanges query;

    json_t *err = NULL;
    jmap_querychanges_parse(req, &parser, NULL, NULL,
                            sharenotif_validatefilter, NULL,
                            sharenotif_validatecomparator, NULL,
                            &query, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }
    jmap_error(req, json_pack("{s:s}", "type", "cannotCalculateChanges"));

done:
    jmap_querychanges_fini(&query);
    jmap_parser_fini(&parser);
    return 0;
}

static const jmap_property_t participantidentity_props[] = {
    {
        "id",
        NULL,
        JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE | JMAP_PROP_ALWAYS_GET
    },
    {
        "name",
        NULL,
        0
    },
    {
        "sendTo",
        NULL,
        0
    },
    { NULL, NULL, 0 }
};

static int jmap_participantidentity_get(struct jmap_req *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_get get;
    json_t *err = NULL;
    int r = 0;
    struct buf buf = BUF_INITIALIZER;

    if (!has_calendars(req)) {
        jmap_error(req, json_pack("{s:s}", "type", "accountNoCalendars"));
        return 0;
    }

    /* Parse request */
    jmap_get_parse(req, &parser, participantidentity_props, 1,
                   NULL, NULL, &get, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    /* Map current participant identities by id */
    strarray_t addrs = STRARRAY_INITIALIZER;
    json_t *jpartidsbyid = json_object();

    char *calhomename = caldav_mboxname(req->userid, NULL);
    get_schedule_addresses(NULL, calhomename, req->userid, &addrs);
    free(calhomename);
    calhomename = NULL;

    int i;
    for (i = 0; i < strarray_size(&addrs); i++) {
        const char *addr = strarray_nth(&addrs, i);
        json_t *jpartid = json_object();

        /* id */
        char idbuf[2*SHA1_DIGEST_LENGTH+1];
        unsigned char sha1buf[SHA1_DIGEST_LENGTH];
        xsha1((const unsigned char *) addr, strlen(addr), sha1buf);
        bin_to_hex(sha1buf, SHA1_DIGEST_LENGTH, idbuf, BH_LOWER);
        idbuf[2*SHA1_DIGEST_LENGTH] = '\0';
        json_object_set_new(jpartid, "id", json_string(idbuf));

        if (jmap_wantprop(get.props, "name")) {
            json_object_set_new(jpartid, "name", json_string(""));
        }

        /* sendTo */
        if (jmap_wantprop(get.props, "sendTo")) {
            if (!strchr(addr, ':')) buf_setcstr(&buf, "mailto:");
            buf_appendcstr(&buf, addr);
            json_object_set_new(jpartid, "sendTo",
                    json_pack("{s:s}", "imip", buf_cstring(&buf)));
            buf_reset(&buf);
        }

        json_object_set_new(jpartidsbyid, idbuf, jpartid);
    }

    if (JNOTNULL(get.ids)) {
        size_t i;
        json_t *jid;
        json_array_foreach(get.ids, i, jid) {
            const char *id = json_string_value(jid);
            json_t *jpartid = json_object_get(jpartidsbyid, id);
            if (jpartid) {
                json_array_append(get.list, jpartid);
            }
            else {
                json_array_append(get.not_found, jid);
            }
        }
    }
    else {
        const char *id;
        json_t *jpartid;
        json_object_foreach(jpartidsbyid, id, jpartid) {
            json_array_append(get.list, jpartid);
        }
    }

    json_decref(jpartidsbyid);
    strarray_fini(&addrs);

    /* Build response */
    json_t *jstate = jmap_getstate(req, MBTYPE_CALENDAR, 0);
    get.state = xstrdup(json_string_value(jstate));
    json_decref(jstate);
    jmap_ok(req, jmap_get_reply(&get));

done:
    jmap_parser_fini(&parser);
    jmap_get_fini(&get);
    buf_free(&buf);
    return r;
}

static int jmap_participantidentity_set(struct jmap_req *req)
{
    struct jmap_parser argparser = JMAP_PARSER_INITIALIZER;
    struct jmap_set set;
    json_t *err = NULL;
    int r = 0;

    jmap_set_parse(req, &argparser, participantidentity_props,
                   NULL, NULL, &set, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    const char *key;
    json_t *jarg;
    json_object_foreach(set.create, key, jarg) {
        json_object_set_new(set.not_created, key,
                json_pack("{s:s}", "type", "forbidden"));
    }
    json_object_foreach(set.update, key, jarg) {
        json_object_set_new(set.not_updated, key,
                json_pack("{s:s}", "type", "forbidden"));
    }
    size_t i;
    json_array_foreach(set.destroy, i, jarg) {
        json_object_set_new(set.not_destroyed,
                json_string_value(jarg),
                json_pack("{s:s}", "type", "forbidden"));
    }

    json_t *jstate = jmap_getstate(req, MBTYPE_CALENDAR, 1);
    set.new_state = xstrdup(json_string_value(jstate));
    json_decref(jstate);

    jmap_ok(req, jmap_set_reply(&set));

done:
    jmap_parser_fini(&argparser);
    jmap_set_fini(&set);
    return r;
}

static int jmap_participantidentity_changes(struct jmap_req *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_changes changes;
    json_t *err = NULL;

    jmap_changes_parse(req, &parser, req->counters.caldavfoldersdeletedmodseq,
                       NULL, NULL, &changes, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }
    jmap_error(req, json_pack("{s:s}", "type", "cannotCalculateChanges"));

  done:
    jmap_changes_fini(&changes);
    jmap_parser_fini(&parser);
    return 0;
}
