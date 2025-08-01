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

#include <libxml/parser.h>

#include "acl.h"
#include "annotate.h"
#include "append.h"
#include "caldav_db.h"
#include "caldav_util.h"
#include "cyr_qsort_r.h"
#include "defaultalarms.h"
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
#include "jmap_notif.h"
#include "jmap_util.h"
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
static int jmap_calendarevent_participantreply(jmap_req_t *req);
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
static int jmap_calendarpreferences_get(struct jmap_req *req);
static int jmap_calendarpreferences_set(struct jmap_req *req);

static int jmap_calendarevent_getblob(jmap_req_t *req, jmap_getblob_context_t *ctx);

#define JMAPCACHE_CALVERSION 26

// clang-format off
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
        JMAP_READ_WRITE // can't open conversations until we have locks ordered
    },
    {
        "CalendarEvent/parse",
        JMAP_URN_CALENDARS,
        &jmap_calendarevent_parse,
        JMAP_NEED_CSTATE
    },
    {
        "CalendarEvent/participantReply",
        JMAP_CALENDARS_EXTENSION,
        &jmap_calendarevent_participantreply,
        JMAP_NEED_CSTATE | JMAP_READ_WRITE
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
    {
        "CalendarPreferences/get",
        JMAP_URN_CALENDAR_PREFERENCES,
        &jmap_calendarpreferences_get,
        0
    },
    {
        "CalendarPreferences/set",
        JMAP_URN_CALENDAR_PREFERENCES,
        &jmap_calendarpreferences_set,
        JMAP_READ_WRITE
    },
    { NULL, NULL, NULL, 0}
};
// clang-format on

// clang-format off
jmap_method_t jmap_calendar_methods_nonstandard[] = {
    { NULL, NULL, NULL, 0}
};
// clang-format on

HIDDEN void jmap_calendar_init(jmap_settings_t *settings)
{
    jmap_add_methods(jmap_calendar_methods_standard, settings);

    json_object_set_new(settings->server_capabilities,
            JMAP_URN_CALENDARS, json_object());

    json_object_set_new(settings->server_capabilities,
            JMAP_URN_PRINCIPALS, json_object());

    json_object_set_new(settings->server_capabilities,
            JMAP_URN_CALENDAR_PREFERENCES, json_object());

    if (config_getswitch(IMAPOPT_JMAP_NONSTANDARD_EXTENSIONS)) {

        json_object_set_new(settings->server_capabilities,
                JMAP_CALENDARS_EXTENSION, json_pack("{s:b}", "isRFC", 1));

        jmap_add_methods(jmap_calendar_methods_nonstandard, settings);
    }

    ptrarray_append(&settings->getblob_handlers, jmap_calendarevent_getblob);
}

HIDDEN void jmap_calendar_capabilities(json_t *account_capabilities,
                                       struct auth_state *authstate,
                                       const char *authuserid,
                                       const char *accountid)
{
    char *calhomename = caldav_mboxname(accountid, NULL);
    struct buf buf = BUF_INITIALIZER;
    mbentry_t *mbentry = NULL;
    int r = mboxlist_lookup(calhomename, &mbentry, NULL);
    if (r) {
        xsyslog(LOG_ERR, "can't lookup calendar home",
                "calhomename=%s error=%s",
                calhomename, error_message(r));
        goto done;
    }
    int rights = httpd_myrights(authstate, mbentry);

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
    get_schedule_addresses(calhomename, accountid, &schedule_addresses);
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

    json_object_set_new(account_capabilities,
            JMAP_URN_CALENDAR_PREFERENCES, json_object());

 done:
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

static json_t *alerts_from_ical(icalcomponent *ical)
{
    json_t *alerts = json_object();
    struct buf buf = BUF_INITIALIZER;

    icalcomponent *valarm;
    for (valarm = icalcomponent_get_first_component(ical, ICAL_VALARM_COMPONENT);
         valarm;
         valarm = icalcomponent_get_next_component(ical, ICAL_VALARM_COMPONENT)) {
        buf_reset(&buf);
        json_t *alert = jmapical_alert_from_ical(valarm, &buf);
        if (alert) {
            json_object_set_new(alerts, buf_cstring(&buf), alert);
        }
    }

    if (!json_object_size(alerts)) {
        json_decref(alerts);
        alerts = json_null();
    }

    buf_free(&buf);
    return alerts;
}

static int getcalendar_defaultalerts(const char *mboxname,
                                     const char *userid,
                                     json_t **with_timep,
                                     json_t **without_timep)
{
    struct defaultalarms defalarms = DEFAULTALARMS_INITIALIZER;
    int r = defaultalarms_load(mboxname, userid, &defalarms);
    if (r) return r;

    if (with_timep) {
        *with_timep = defalarms.with_time.ical ?
            alerts_from_ical(defalarms.with_time.ical) : NULL;
    }

    if (without_timep) {
        *without_timep = defalarms.with_date.ical ?
            alerts_from_ical(defalarms.with_date.ical) : NULL;
    }

    defaultalarms_fini(&defalarms);

    return 0;
}

static json_t *calendarrights_to_jmap(int rights, int is_owner)
{
    if (is_owner) rights |= JACL_RSVP;

    return json_pack("{s:b s:b s:b s:b s:b s:b s:b s:b}",
            "mayReadFreeBusy",
            (rights & JACL_READFB) == JACL_READFB,
            "mayReadItems",
            (rights & JACL_READITEMS) == JACL_READITEMS,
            "mayWriteAll",
            (rights & (JACL_WRITEALL|JACL_RSVP)) == (JACL_WRITEALL|JACL_RSVP),
            "mayWriteOwn",
            (((rights & JACL_WRITEOWN) == JACL_WRITEOWN) ||
             ((rights & JACL_WRITEALL) == JACL_WRITEALL)),
            "mayUpdatePrivate",
            (((rights & JACL_UPDATEPRIVATE) == JACL_UPDATEPRIVATE) ||
             ((rights & JACL_WRITEALL) == JACL_WRITEALL)),
            "mayRSVP",
            (rights & JACL_RSVP) == JACL_RSVP,
            "mayDelete",
            (rights & JACL_DELETE) == JACL_DELETE,
            "mayAdmin",
            (rights & JACL_ADMIN_CALENDAR) == JACL_ADMIN_CALENDAR);
}

static json_t *calendarrights_to_sharewith(int rights)
{
    return calendarrights_to_jmap(rights, 0);
}

static int calendar_sharewith_to_rights(int rights, json_t *jsharewith)
{
    int newrights = rights;

    /* Apply shareWith in two passes: in the first, remove
     * rights that were explicitly set to false (or null).
     * In the second pass, add rights that were set to true.
     * This prevents that the order of rights in the patch
     * impacts the resulting ACL mask. */
    json_t *jval;
    const char *name;
    int iteration = 1;
calendar_sharewith_to_rights_iter:
    json_object_foreach(jsharewith, name, jval) {
        int mask;
        if (!strcmp("mayReadFreeBusy", name))
            mask = JACL_READFB;
        else if (!strcmp("mayReadItems", name))
            mask = JACL_READITEMS;
        else if (!strcmp("mayWriteAll", name))
            mask = JACL_WRITEALL|JACL_RSVP;
        else if (!strcmp("mayWriteOwn", name))
            mask = JACL_WRITEOWN;
        else if (!strcmp("mayUpdatePrivate", name))
            mask = JACL_UPDATEPRIVATE;
        else if (!strcmp("mayRSVP", name))
            mask = JACL_RSVP;
        else if (!strcmp("mayDelete", name))
            mask = JACL_DELETE;
        else if (!strcmp("mayAdmin", name))
            mask = JACL_ADMIN_CALENDAR;
        else
            continue;

        if (iteration == 1 && !json_boolean_value(jval))
            newrights &= ~mask;
        else if (iteration == 2 && json_boolean_value(jval))
            newrights |= mask;
    }
    if (++iteration == 2) goto calendar_sharewith_to_rights_iter;

    /* Can always set calendar properties for read-only calendars,
       but we need to flag the account as isReadOnly=false, so include ACL_WRITE. */
    if (newrights & ~JACL_READFB) {
        newrights |= ACL_WRITE;
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

    if (jmap_wantprop(rock->get->props, "defaultAlertsWithTime") ||
        jmap_wantprop(rock->get->props, "defaultAlertsWithoutTime")) {

        json_t *with_time = NULL, *without_time = NULL;
        getcalendar_defaultalerts(mbentry->name, req->userid,
                &with_time, &without_time);

        if (jmap_wantprop(rock->get->props, "defaultAlertsWithTime"))
            json_object_set_new(obj, "defaultAlertsWithTime", with_time);

        if (jmap_wantprop(rock->get->props, "defaultAlertsWithoutTime"))
            json_object_set_new(obj, "defaultAlertsWithoutTime", without_time);
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

    if (jmap_wantprop(rock->get->props, "mailboxUniqueId")) {
        json_object_set_new(obj, "mailboxUniqueId",
                            json_string(mbentry->uniqueid));
    }

    json_array_append_new(rock->get->list, obj);

done:
    buf_free(&attrib);
    mbname_free(&mbname);
    return r;
}

// clang-format off
static const jmap_property_t calendar_props[] = {
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
        "mailboxUniqueId",
        JMAP_CALENDARS_EXTENSION,
        JMAP_PROP_SERVER_SET
    },
    {
        "x-href",
        JMAP_DEBUG_EXTENSION,
        JMAP_PROP_SERVER_SET
    },

    { NULL, NULL, 0 }
};
// clang-format on

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
    struct jmap_get get = JMAP_GET_INITIALIZER;
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
        get.state = modseqtoa(jmap_modseq(req, MBTYPE_CALENDAR, 0));
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

            mboxlist_entry_free(&mbentry);
            free(mboxname);
            if (r) goto done;
        }
    }
    else {
        char *calhomename = caldav_mboxname(req->accountid, NULL);
        r = mboxlist_mboxtree(calhomename,
                              &getcalendars_cb, &rock, MBOXTREE_SKIP_ROOT);
        free(calhomename);
        if (r) goto done;
    }

    /* Build response */
    get.state = modseqtoa(jmap_modseq(req, MBTYPE_CALENDAR, 0));
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
    if (mbentry->mbtype & MBTYPE_DELETED ||
            // leak unshared calendars, they might have been shared before
            !jmap_hasrights_mbentry(req, mbentry, JACL_READITEMS)) {
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
    struct jmap_changes changes = JMAP_CHANGES_INITIALIZER;
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
        changes.new_modseq = changes.since_modseq;
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
        jmap_modseq(req, MBTYPE_CALENDAR, 0);

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
    icalcomponent *defaultalarms_with_time;
    icalcomponent *defaultalarms_with_date;
};

static void setcalendar_props_fini(struct setcalendar_props *props)
{
    if (props->defaultalarms_with_time)
        icalcomponent_free(props->defaultalarms_with_time);

    if (props->defaultalarms_with_date)
        icalcomponent_free(props->defaultalarms_with_date);
}

static void setcalendar_parsealerts(struct jmap_parser *parser,
                                    const char *propname,
                                    json_t *arg,
                                    const char *emailrecipient,
                                    icalcomponent **alarmsp)
{
    icalcomponent *alarms = icalcomponent_new(ICAL_XROOT_COMPONENT);

    json_t *jprop = json_object_get(arg, propname);
    if (json_is_object(jprop)) {
        jmap_parser_push(parser, propname);
        const char *id;
        json_t *jalert;
        json_object_foreach(jprop, id, jalert) {
            jmap_parser_push(parser, id);
            icalcomponent *valarm =
                jmapical_alert_to_ical(jalert, parser, id,
                        NULL, NULL, emailrecipient);
            if (valarm) {
                icalcomponent_add_component(alarms, valarm);
            }
            jmap_parser_pop(parser);
        }
        jmap_parser_pop(parser);
    }
    else if (JNOTNULL(jprop)) {
        jmap_parser_invalid(parser, propname);
    }

    *alarmsp = alarms;
}

static void setcalendar_parseprops(jmap_req_t *req,
                                  struct jmap_parser *parser,
                                  struct setcalendar_props *props,
                                  json_t *arg,
                                  const char *mboxname)
{
    int is_create = (mboxname == NULL);

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
    if (json_object_size(jprop)) {
        // Validate rights
        const char *sharee;
        json_t *jrights;
        json_object_foreach(jprop, sharee, jrights) {
            if (json_object_size(jrights)) {
                const char *right;
                json_t *jval;
                json_object_foreach(jrights, right, jval) {
                    if (!json_is_boolean(jval) ||
                            (strcmp(right, "mayReadFreeBusy") &&
                             strcmp(right, "mayReadItems") &&
                             strcmp(right, "mayWriteAll") &&
                             strcmp(right, "mayWriteOwn") &&
                             strcmp(right, "mayUpdatePrivate") &&
                             strcmp(right, "mayRSVP") &&
                             strcmp(right, "mayAdmin") &&
                             strcmp(right, "mayDelete"))) {

                        jmap_parser_push(parser, "shareWith");
                        jmap_parser_push(parser, "sharee");
                        jmap_parser_invalid(parser, right);
                        jmap_parser_pop(parser);
                        jmap_parser_pop(parser);
                    }
                }
            }
            else if (!json_is_null(jrights)) {
                jmap_parser_push(parser, "shareWith");
                jmap_parser_invalid(parser, sharee);
                jmap_parser_pop(parser);
            }
        }
    }
    else if JNOTNULL(jprop) {
        jmap_parser_invalid(parser, "shareWith");
    }
    props->share.With = jprop;

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

    /* defaultAlertsWithTime */
    /* defaultAlertsWithoutTime */
    {
        /* Determine if default alerts are patched */
        json_t *jalertargs = json_deep_copy(arg);
        const char *pname;
        json_t *jval;
        void *tmp;
        json_object_foreach_safe(jalertargs, tmp, pname, jval) {
            if (strcmp(pname, "defaultAlertsWithTime") &&
                strncmp(pname, "defaultAlertsWithTime/", 22) &&
                strcmp(pname, "defaultAlertsWithoutTime") &&
                strncmp(pname, "defaultAlertsWithoutTime/", 25)) {
                json_object_del(jalertargs, pname);
            }
        }

        if (json_object_size(jalertargs)) {
            /* Read current alerts - we always write the whole lot */
            json_t *cur_with_time = NULL, *cur_without_time = NULL;
            int r = getcalendar_defaultalerts(mboxname, req->userid,
                    &cur_with_time, &cur_without_time);

            if (!r) {
                json_t *cur_alerts = json_pack("{s:o s:o}",
                        "defaultAlertsWithTime",
                        cur_with_time ? cur_with_time : json_null(),
                        "defaultAlertsWithoutTime",
                        cur_without_time ? cur_without_time : json_null());

                /* Apply update patch to alerts */
                json_t *invalid = json_array();
                json_t *new_alerts = jmap_patchobject_apply(cur_alerts,
                        jalertargs, invalid, 0);

                if (!json_array_size(invalid)) {
                    /* Parse new alerts */
                    struct jmapical_ctx *jmapctx = jmapical_context_new(req, NULL);
                    setcalendar_parsealerts(parser, "defaultAlertsWithTime",
                            new_alerts, jmapctx->to_ical.emailalert_recipient,
                            &props->defaultalarms_with_time);
                    setcalendar_parsealerts(parser, "defaultAlertsWithoutTime",
                            new_alerts, jmapctx->to_ical.emailalert_recipient,
                            &props->defaultalarms_with_date);
                    jmapical_context_free(&jmapctx);
                }
                else {
                    json_array_extend(parser->invalid, invalid);
                }

                json_decref(invalid);
                json_decref(new_alerts);
                json_decref(cur_alerts);
            }
            else {
                xsyslog(LOG_ERR,
                        "could not load default alerts - ignoring arguments",
                        "err=<%s>", error_message(r));
            }
        }

        json_decref(jalertargs);
    }
}

/* Write  the calendar properties in the calendar mailbox named mboxname.
 * NULL values and negative integers are ignored. Return 0 on success. */
static int setcalendar_writeprops(jmap_req_t *req,
                                  struct mailbox *mbox,
                                  struct setcalendar_props *props)
{
    annotate_state_t *astate = NULL;
    struct buf val = BUF_INITIALIZER;
    int r;

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
        strarray_t new = STRARRAY_INITIALIZER;

        strarray_t old = STRARRAY_INITIALIZER;
        caldav_caluseraddr_read(mailbox_name(mbox), req->userid, &old);

        size_t i;
        json_t *jpid;
        json_array_foreach(props->participant_identities, i, jpid) {
            const char *uri = json_string_value(json_object_get(jpid, "uri"));
            if (!uri) continue;
            strarray_append(&new, uri);
        }

        r = caldav_caluseraddr_write(mbox, req->userid, &new);
        if (r) {
            xsyslog(LOG_ERR, "failed to write participant identities",
                    "err=<%s>", error_message(r));
        }

        strarray_fini(&new);
        strarray_fini(&old);
    }

    /* isSubscribed */
    if (!r && props->isSubscribed >= 0) {
        /* Update subscription database */
        r = mboxlist_changesub(mailbox_name(mbox), req->userid, req->authstate,
                               props->isSubscribed, 0, /*notify*/1, /*silent*/0);

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
    /* defaultAlertsWithoutTime */
    if (!r && (props->defaultalarms_with_time || props->defaultalarms_with_date)) {
        int r = defaultalarms_save(mbox, req->userid,
                props->defaultalarms_with_time,
                props->defaultalarms_with_date);
        if (r) {
            xsyslog(LOG_ERR, "failed to write defaultalarms",
                    "mboxid=<%s> mboxname=<%s> userid=<%s> err=<%s>",
                    mailbox_uniqueid(mbox), mailbox_name(mbox),
                    req->userid, error_message(r));
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
    return r;
}

static int set_scheddefault(jmap_req_t *req, annotate_state_t *astate, const char *colname)
{
    int r = 0;

    struct buf buf = BUF_INITIALIZER;
    buf_setcstr(&buf, colname ? colname : "");

    const char *annot =
        DAV_ANNOT_NS "<" XML_NS_CALDAV ">schedule-default-calendar";

    if (colname) {
        struct mailbox *mbox = NULL;
        char *mboxname = caldav_mboxname(req->accountid, colname);
        // Make sure it exists and is writable
        r = mailbox_open_iwl(mboxname, &mbox);
        if (!r) {
            if (httpd_myrights(req->authstate, mbox->mbentry) & ACL_INSERT)
                r = annotate_state_writemask(astate, annot, req->accountid, &buf);
            else
                r = IMAP_PERMISSION_DENIED;
        }
        mailbox_close(&mbox);
        free(mboxname);
    }
    else {
        r = annotate_state_writemask(astate, annot, req->accountid, &buf);
    }

    buf_free(&buf);
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
    char *defaultname = caldav_scheddefault(req->accountid, 0);
    mbname_t *mbname = mbname_from_intname(mboxname);
    mbentry_t *mbentry = NULL;
    struct buf buf = BUF_INITIALIZER;
    struct caldav_db *db = NULL;
    char *calhome_name = caldav_mboxname(req->accountid, NULL);
    annotate_state_t *calhome_astate = NULL;
    struct mailbox *calhome_mbox = NULL;
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
    mboxlist_changesub(mboxname, req->userid, req->authstate, 0, 1, 0, 1);

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

    /* Update default calendar - must go last */
    if (!strcmpsafe(defaultname, calid)) {
        int r2 = mailbox_open_iwl(calhome_name, &calhome_mbox);
        if (r2) {
            xsyslog(LOG_ERR, "can not open calendar home mailbox",
                    "err=<%s>", error_message(r));
            goto done;
        }
        r2 = mailbox_get_annotate_state(calhome_mbox, 0, &calhome_astate);
        if (r2) {
            xsyslog(LOG_ERR, "can not get calendar home annotation state",
                    "err=<%s>", error_message(r2));
            goto done;
        }

        // Set default calendar to null
        r2 = set_scheddefault(req, calhome_astate, NULL);
        if (r2) {
            xsyslog(LOG_ERR, "can not set default calendar to null",
                    "err=<%s>", error_message(r2));
            goto done;
        }

        // Pick new default calendar
        char *newdefaultname = caldav_scheddefault(req->accountid, 1);
        if (newdefaultname) {
            r2 = set_scheddefault(req, calhome_astate, newdefaultname);
            if (r2) {
                xsyslog(LOG_ERR, "can not set new default calendar",
                        "name=<%s> err=<%s>", newdefaultname, error_message(r2));
            }
            free(newdefaultname);
        }
    }

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
    mailbox_close(&calhome_mbox);
    free(calhome_name);
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
    mbentry_t *mbparent = NULL, *mbentry = NULL;
    char *parentname = caldav_mboxname(req->accountid, NULL);
    char *uid = xstrdup(makeuuid());
    char *mboxname = caldav_mboxname(req->accountid, uid);
    struct mailbox *mbox = NULL;
    int r = 0;

    /* Parse and validate properties. */
    setcalendar_parseprops(req, &parser, &props, arg, /*is_create*/NULL);
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
    mbentry_t mymbentry = MBENTRY_INITIALIZER;
    mymbentry.name = mboxname;
    mymbentry.acl = acl;
    mymbentry.mbtype = MBTYPE_CALENDAR;
    r = mboxlist_createmailbox(&mymbentry, 0/*options*/, 0/*highestmodseq*/,
            0/*isadmin*/, req->userid, req->authstate,
            0/*flags*/, &mbox);
    free(acl);
    if (r) {
        syslog(LOG_ERR, "IOERROR: failed to create %s (%s)",
                mboxname, error_message(r));
        goto done;
    }

    // Initialize JMAP calendar
    r = caldav_init_jmapcalendar(req->userid, mbox);
    if (r) {
        xsyslog(LOG_ERR, "jmap_init_calendar_mailbox failed",
                "mboxname=<%s> err=<%s>",
                mboxname, error_message(r));
        goto done;
    }

    // Reset JMAP mboxlist cache for the new mailbox
    r = jmap_mboxlist_lookup(mboxname, &mbentry, NULL);
    if (r) {
        xsyslog(LOG_ERR, "jmap_mboxlist_lookup failed",
                "mboxname=<%s> err=<%s>",
                mboxname, error_message(r));
        goto done;
    }

    r = setcalendar_writeprops(req, mbox, &props);
    if (r) {
        xsyslog(LOG_ERR, "setcalendar_writeprops failed",
                "mboxname=<%s> err=<%s>",
                mboxname, error_message(r));
        mailbox_abort(mbox);
        mailbox_close(&mbox);
        int rr = mboxlist_deletemailbox(mboxname, 1, "", NULL, NULL, 0);
        if (rr) {
            syslog(LOG_ERR, "could not delete mailbox %s: %s",
                    mboxname, error_message(rr));
        }
        goto done;
    }

    /* Report calendar as created. */
    *record = json_pack("{s:s s:o}", "id", uid,
                        "myRights",
                        calendarrights_to_jmap(jmap_myrights_mbentry(req, mbentry),
                                               !strcmp(req->userid, req->accountid)));
    if (jmap_is_using(req, JMAP_CALENDARS_EXTENSION)) {
        json_object_set_new(*record, "mailboxUniqueId",
                        json_string(mbentry->uniqueid));
    }
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
    mailbox_close(&mbox);
    mboxlist_entry_free(&mbparent);
    mboxlist_entry_free(&mbentry);
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
    struct mailbox *mbox = NULL;

    /* Make sure we don't mess up special calendars */
    if (jmap_calendar_isspecial(mbname)) {
        *err = json_pack("{s:s}", "type", "notFound");
        goto done;
    }

    /* Parse and validate properties. */
    struct setcalendar_props props;
    setcalendar_parseprops(req, &parser, &props, arg, mboxname);
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

    if (!jmap_hasrights(req, mboxname, JACL_READITEMS)) {
        *err = json_pack("{s:s}", "type", "notFound");
        goto done;
    }

    /* Update the calendar */
    int r = mailbox_open_iwl(mboxname, &mbox);
    if (!r) {
        r = setcalendar_writeprops(req, mbox, &props);
        if (r) {
            xsyslog(LOG_ERR, "setcalendar_writeprops failed",
                    "mboxname=<%s> err=<%s>",
                    mboxname, error_message(r));
            mailbox_abort(mbox);
            mailbox_close(&mbox);
        }
    }
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
    mailbox_close(&mbox);
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

static int jmap_calendar_set(struct jmap_req *req)
{
    struct mboxlock *namespacelock = user_namespacelock(req->accountid);
    struct jmap_parser argparser = JMAP_PARSER_INITIALIZER;
    struct jmap_set set = JMAP_SET_INITIALIZER;
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
        if (atomodseq_t(set.if_in_state) != jmap_modseq(req, MBTYPE_CALENDAR, 0)) {
            jmap_error(req, json_pack("{s:s}", "type", "stateMismatch"));
            goto done;
        }
        set.old_state = xstrdup(set.if_in_state);
    }
    else {
        set.old_state = modseqtoa(jmap_modseq(req, MBTYPE_CALENDAR, 0));
    }

    r = caldav_create_defaultcalendars(req->accountid,
                                       &httpd_namespace, req->authstate, NULL);
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

    set.new_state = modseqtoa(jmap_modseq(req, MBTYPE_CALENDAR, JMAP_MODSEQ_RELOAD));

    jmap_ok(req, jmap_set_reply(&set));

done:
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
    dlist_parsemap(&dl, 1, buf_base(value), buf_len(value));
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
    char *partid = NULL;
    uint32_t uid;
    int res = HTTP_OK;
    mbentry_t *freeme = NULL;
    char *subpart = NULL;
    struct message_guid guid = MESSAGE_GUID_INITIALIZER;
    int r;

    if (ctx->blobid[0] != 'I') return 0;

    if (!jmap_decode_rawdata_blobid(ctx->blobid, &mboxid, &uid, &partid,
                                    &userid, &subpart, &guid)) {
        res = HTTP_BAD_REQUEST;
        goto done;
    }
    if (!strcmpsafe(subpart, "G")) {
        // G subpart encodes the guid of the iCalendar blob
        xzfree(subpart);
    }

    /* Validate user id if this doesn't target a subpart */
    if (!subpart) {
        if ((userid && strcmp(userid, req->userid)) || (!userid && (!httpd_userisadmin))) {
            res = HTTP_NOT_FOUND;
            goto done;
        }
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
    r = mailbox_open_irl(mbentry->name, &mailbox);
    if (r) {
        ctx->errstr = error_message(r);
        res = HTTP_SERVER_ERROR;
        goto done;
    }

    /* Make sure client can handle blob type. */
    if (ctx->accept_mime && !subpart) {
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
    const struct body *part = NULL;
    struct index_record record;
    if (!mailbox_find_index_record(mailbox, uid, &record) &&
        !mailbox_cacherecord(mailbox, &record)) {

        if (!subpart && !message_guid_equal(&guid, &record.guid)) {
            // guid of iCalendar blob must match
            res = HTTP_NOT_FOUND;
            goto done;
        }

        message_read_bodystructure(&record, &body);

        if (partid) {
            ptrarray_t todo = PTRARRAY_INITIALIZER;
            ptrarray_append(&todo, body);
            while ((part = ptrarray_pop(&todo))) {
                if (!strcmpsafe(part->part_id, partid))
                    break;
                int i;
                for (i = 0; i < part->numparts; i++)
                    ptrarray_append(&todo, part->subpart + i);
            }
            ptrarray_fini(&todo);
            if (!part) goto done;
        }
        else part = body;

        comp_type = get_param(part->params, "COMPONENT");

        if (userid) {
            /* Fetch ical resource with personalized data */
            struct caldav_data cdata = {
                .dav.imap_uid = record.uid,
                .comp_flags.shared =
                    !strcasecmpsafe(get_param(part->disposition_params,
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

    if (subpart) {
        icalcomponent *comp = icalcomponent_get_first_real_component(ical);
        icalcomponent_kind kind = icalcomponent_isa(comp);
        int gotblob = 0;
        for ( ; comp && !gotblob; comp = icalcomponent_get_next_component(ical, kind)) {
            icalproperty *prop;
            for (prop = icalcomponent_get_first_property(comp, ICAL_ATTACH_PROPERTY);
                 prop && !gotblob;
                 prop = icalcomponent_get_next_property(comp, ICAL_ATTACH_PROPERTY)) {

                icalattach *attach = icalproperty_get_attach(prop);
                if (!attach || icalattach_get_is_url(attach))
                    continue;

                icalparameter *param = icalproperty_get_first_parameter(prop, ICAL_ENCODING_PARAMETER);
                if (!param || icalparameter_get_encoding(param) != ICAL_ENCODING_BASE64)
                    continue;

                buf_reset(&ctx->blob);
                const char *data = (const char *) icalattach_get_data(attach);
                if (charset_decode(&ctx->blob, data, strlen(data), ENCODING_BASE64))
                    continue;

                struct message_guid blobguid = MESSAGE_GUID_INITIALIZER;
                message_guid_generate(&blobguid, buf_base(&ctx->blob), buf_len(&ctx->blob));

                if (!message_guid_equal(&guid, &blobguid)) {
                    buf_reset(&ctx->blob);
                    continue;
                }

                // Found the blob!
                gotblob = 1;
                param = icalproperty_get_first_parameter(prop, ICAL_FMTTYPE_PARAMETER);
                if (param)
                    buf_setcstr(&ctx->content_type, icalparameter_get_fmttype(param));
            }
        }
        if (!gotblob) res = HTTP_NOT_FOUND;
    }
    else if (userid) {
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
    mailbox_close(&mailbox);
    mboxlist_entry_free(&freeme);
    free(mboxid);
    free(partid);
    free(userid);
    free(subpart);
    return res;
}

static void add_calendarevent_blobids(json_t *jsevent,
                                      const char *mboxid,
                                      uint32_t imap_uid,
                                      const char *userid,
                                      const struct message_guid *guid)
{
    struct buf blobid = BUF_INITIALIZER;

    json_t *jblobid = json_null();
    if (jmap_encode_rawdata_blobid('I', mboxid, imap_uid, NULL,
                userid, "G", guid, &blobid)) {
        jblobid = json_string(buf_cstring(&blobid));
    }
    json_object_set_new(jsevent, "blobId", jblobid);

    jblobid = json_null();
    if (jmap_encode_rawdata_blobid('I', mboxid, imap_uid, NULL,
                NULL, "G", guid, &blobid)) {
        jblobid = json_string(buf_cstring(&blobid));
    }
    json_object_set_new(jsevent, "debugBlobId", jblobid);

    buf_free(&blobid);
}

struct getcalendarevents_rock {
    /* Request-scoped context */
    struct caldav_db *db;
    struct jmap_req *req;
    struct jmap_get *get;
    struct jmapical_ctx *jmapctx;
    int check_acl;
    hash_table floatingtz_by_mboxid;
    ptrarray_t malloced_fallbacktzs;
    struct jmapical_datetime overrides_before;
    struct jmapical_datetime overrides_after;
    int reduce_participants;
    int is_sharee;
    hashu64_table cache_jsevents;
    ptrarray_t *want_eventids;
    struct buf buf;

    /* Mailbox-scoped context */
    struct mailbox *mailbox;
    mbentry_t *mbentry;
    mbname_t *mbname;
    strarray_t schedule_addresses;

    /* Event-scoped context */
    uint32_t imap_uid;
    icalcomponent *ical;
    hash_table ical_instances_by_recurid;
    struct message_guid guid;
    int is_draft;
};

struct recurid_instanceof_rock {
    icaltimetype recurid;
    int found;
};

static int _recurid_instanceof_cb(icalcomponent *comp __attribute__((unused)),
                                  icaltimetype start,
                                  icaltimetype end __attribute__((unused)),
                                  icaltimetype recurid __attribute__((unused)),
                                  int is_standalone __attribute__((unused)),
                                  void *vrock)
{
    struct recurid_instanceof_rock *rock = vrock;

    if (start.is_date && !rock->recurid.is_date) {
        start.is_date = 0;
        start.hour = 0;
        start.minute = 0;
        start.second = 0;
    }
    else if (!start.is_date && rock->recurid.is_date) {
        recurid.is_date = 0;
        recurid.hour = 0;
        recurid.minute = 0;
        recurid.second = 0;
    }

    int cmp = icaltime_compare(start, rock->recurid);
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
    jmapical_datetime_from_icaltime(endical, &enddt);

    /* Convert start and end to UTC */
    if (tz != utc) {
        icaltimetype icalloc = jmapical_datetime_to_icaltime(&startdt, tz);
        icaltimetype icalutc = icaltime_convert_to_zone(icalloc, utc);
        jmapical_datetime_from_icaltime(icalutc, &startdt);

        icalloc = jmapical_datetime_to_icaltime(&enddt, tz);
        icalutc = icaltime_convert_to_zone(icalloc, utc);
        jmapical_datetime_from_icaltime(icalutc, &enddt);
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

static void getcalendarevents_del_utctimes(jmap_req_t *req,
                                           hash_table *props,
                                           json_t *jsevent)
{
    int want_utcstart = 0;
    int want_utcend = 0;

    if (jmap_is_using(req, JMAP_URN_CALENDARS) && props) {
        want_utcstart = jmap_wantprop(props, "utcStart");
        want_utcend = jmap_wantprop(props, "utcEnd");
    }
    if (want_utcstart && want_utcend) return;

    if (!want_utcstart)
        json_object_del(jsevent, "utcStart");
    if (!want_utcend)
        json_object_del(jsevent, "utcEnd");

    const char *recurid;
    json_t *jovr;
    json_object_foreach(json_object_get(jsevent, "recurrenceOverrides"), recurid, jovr) {
        if (!want_utcstart)
            json_object_del(jovr, "utcStart");
        if (!want_utcend)
            json_object_del(jovr, "utcEnd");
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
    json_object_set_new(myevent, "@type", json_string("Event"));
}

static void format_icaltimestr_to_datetimestr(const char *icalval, struct buf *buf)
{
    buf_reset(buf);

    size_t len = strlen(icalval);
    if (len != 8 && len != 15 && len != 16) return;

    /* Convert iCalendar recurrence id to DateTime */
    const char *v = icalval;
    // YYYY-MM-DD
    buf_appendmap(buf, v, 4);
    v += 4;
    buf_putc(buf, '-');
    buf_appendmap(buf, v, 2);
    v += 2;
    buf_putc(buf, '-');
    buf_appendmap(buf, v, 2);
    v += 2;
    // HH:MM:ss - omit 'Z'
    if (*v == 'T') {
        buf_putc(buf, 'T');
        v += 1;
        buf_appendmap(buf, v, 2);
        v += 2;
        buf_putc(buf, ':');
        buf_appendmap(buf, v, 2);
        v += 2;
        buf_putc(buf, ':');
        buf_appendmap(buf, v, 2);
        v += 2;
        if (*v != 'Z' && *v) buf_reset(buf);
    }
    else buf_appendcstr(buf, "T00:00:00");
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
    json_t *jrtzid = json_object_get(jsevent, "timeZone");
    struct buf baseidbuf = BUF_INITIALIZER;
    int r = 0;

    mbentry_t *mbentry = jmap_mbentry_from_dav(req, &cdata->dav);
    if (!mbentry) goto done;

    int i;
    for (i = 0; i < ptrarray_size(rock->want_eventids); i++) {
        struct jmap_caleventid *eid = ptrarray_nth(rock->want_eventids, i);
        if (!eid->ical_recurid) continue;

        format_icaltimestr_to_datetimestr(eid->ical_recurid, &rock->buf);
        const char *jscalrecurid = buf_cstring(&rock->buf);

        struct jmap_caleventid base_eid = { .ical_uid = eid->ical_uid };
        jmap_caleventid_encode(&base_eid, &baseidbuf);

        /* Client requested event recurrence instance */
        json_t *override = json_object_get(
                json_object_get(jsevent, "recurrenceOverrides"), jscalrecurid);
        if (override) {
            if (json_object_get(override, "excluded") != json_true()) {
                /* Instance is a recurrence override */
              json_t *myevent = jmap_patchobject_apply(jsevent, override, NULL, 0);
                getcalendarevents_filterinstance(myevent, props, eid->raw, cdata->ical_uid);
                if (json_object_get(override, "start") == NULL) {
                    json_object_set_new(myevent, "start", json_string(jscalrecurid));
                }
                json_object_set_new(myevent, "baseEventId",
                        json_string(buf_cstring(&baseidbuf)));
                json_object_set_new(myevent, "recurrenceId", json_string(jscalrecurid));
                json_object_set(myevent, "recurrenceIdTimeZone", jrtzid);
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
                    mailbox_close(&rock->mailbox);
                    r = mailbox_open_irl(mbentry->name, &rock->mailbox);
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
            if (jmapical_localdatetime_from_string(jscalrecurid, &timestamp) < 0) {
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
            json_object_set_new(myevent, "baseEventId",
                    json_string(buf_cstring(&baseidbuf)));
            json_object_set_new(myevent, "recurrenceId", json_string(jscalrecurid));
            json_object_set(myevent, "recurrenceIdTimeZone", jrtzid);
            json_array_append_new(rock->get->list, myevent);
        }
    }

done:
    if (myical) icalcomponent_free(myical);
    mboxlist_entry_free(&mbentry);
    buf_free(&baseidbuf);
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


static void context_begin_cdata(struct jmapical_ctx *jmapctx,
                                mbentry_t *mbentry,
                                struct caldav_data *cdata)
{
    jmapctx->from_ical.cyrus_msg.mboxid = mbentry->uniqueid;
    jmapctx->from_ical.cyrus_msg.uid = cdata->dav.imap_uid;
    jmapctx->from_ical.cyrus_msg.partid = NULL;
}

static void context_end_cdata(struct jmapical_ctx *jmapctx)
{
    jmapctx->from_ical.cyrus_msg.mboxid = NULL;
    jmapctx->from_ical.cyrus_msg.uid = 0;
    jmapctx->from_ical.cyrus_msg.partid = NULL;
}

static void getcalendarevents_reduce_participants_internal(json_t *jparticipants,
                                                           json_t *keep_ids,
                                                           const char *userid,
                                                           strarray_t *schedule_addresses)
{
    const char *participant_id;
    json_t *jparticipant;
    void *tmp;
    json_object_foreach_safe(jparticipants, tmp, participant_id, jparticipant) {
        if (json_object_get(keep_ids, participant_id))
            continue;

        if (json_object_get(json_object_get(jparticipant, "roles"), "owner"))
            continue;

        json_t *jsendto = json_object_get(jparticipant,"sendTo");
        const char *uri = json_string_value(json_object_get(jsendto, "imip"));
        if (uri && !strncasecmp(uri, "mailto:", 7)) {
            if (!strcasecmp(userid, uri + 7)) {
                json_object_set_new(keep_ids,
                        participant_id, json_true());
                continue;
            }

            if (strarray_contains_case(schedule_addresses, uri + 7)) {
                json_object_set_new(keep_ids,
                        participant_id, json_true());
                continue;
            }
        }

        json_object_del(jparticipants, participant_id);
    }
}

static void getcalendarevents_reduce_participants(json_t *jsevent,
                                                  const char *userid,
                                                  strarray_t *schedule_addresses)
{
    json_t *keep_ids = json_object();

    // Reduce participants of main event

    json_t *jparticipants = json_object_get(jsevent, "participants");
    getcalendarevents_reduce_participants_internal(jparticipants, keep_ids,
            userid, schedule_addresses);
    if (!json_object_size(jparticipants))
        json_object_del(jsevent, "participants");

    // Reduce participants in overrides

    struct buf buf = BUF_INITIALIZER;
    json_t *joverrides = json_object_get(jsevent, "recurrenceOverrides");
    const char *recur_id;
    json_t *joverride;
    void *tmp;

    json_object_foreach_safe(joverrides, tmp, recur_id, joverride) {
        const char *pname;
        json_t *jval;
        json_object_foreach_safe(joverride, tmp, pname, jval) {

            if (!strcmp(pname, "participants")) {
                getcalendarevents_reduce_participants_internal(jval, keep_ids,
                        userid, schedule_addresses);
                if (!json_object_size(jval))
                    json_object_del(joverride, pname);
            }
            else if (!strncmp(pname, "participants/", 13)) {
                const char *path = pname + 13;

                const char *p = strchr(path, '/');
                if (p) {
                    // partially patches a participant of the main event
                    buf_setmap(&buf, path, p - path);
                    if (!json_object_get(keep_ids, buf_cstring(&buf))) {
                        json_object_del(joverride, pname);
                    }
                }
                else {
                    // completely patches or adds a participant
                    json_t *myparticipants = json_object();
                    json_object_set(myparticipants, path, jval);
                    getcalendarevents_reduce_participants_internal(myparticipants,
                            keep_ids, userid, schedule_addresses);
                    if (!json_object_size(myparticipants))
                        json_object_del(joverride, pname);
                    json_decref(myparticipants);
                }
            }
        }
    }

    json_decref(keep_ids);
    buf_free(&buf);
}

static void getcalendarevents_del_privateprops(json_t *jsevent)
{
    static json_t *publicprops = NULL;
    if (!publicprops) {
        publicprops = json_object();
        json_object_set_new(publicprops, "calendarIds", json_true());
        json_object_set_new(publicprops, "created", json_true());
        json_object_set_new(publicprops, "due", json_true());
        json_object_set_new(publicprops, "duration", json_true());
        json_object_set_new(publicprops, "estimatedDuration", json_true());
        json_object_set_new(publicprops, "excluded", json_true());
        json_object_set_new(publicprops, "excludedRecurrenceRules", json_true());
        json_object_set_new(publicprops, "freeBusyStatus", json_true());
        json_object_set_new(publicprops, "id", json_true());
        json_object_set_new(publicprops, "isDraft", json_true());
        json_object_set_new(publicprops, "privacy", json_true());
        json_object_set_new(publicprops, "recurrenceId", json_true());
        json_object_set_new(publicprops, "recurrenceIdTimeZone", json_true());
        json_object_set_new(publicprops, "recurrenceRules", json_true());
        json_object_set_new(publicprops, "recurrenceOverrides", json_true());
        json_object_set_new(publicprops, "sequence", json_true());
        json_object_set_new(publicprops, "showWithoutTime", json_true());
        json_object_set_new(publicprops, "start", json_true());
        json_object_set_new(publicprops, "timeZone", json_true());
        json_object_set_new(publicprops, "uid", json_true());
        json_object_set_new(publicprops, "updated", json_true());
        json_object_set_new(publicprops, "utcStart", json_true());
        json_object_set_new(publicprops, "utcEnd", json_true());
    }

    const char *key;
    json_t *jval;
    void *tmp;
    json_object_foreach_safe(jsevent, tmp, key, jval) {
        if (!json_object_get(publicprops, key)) {
            json_object_del(jsevent, key);
        }
    }

    json_t *joverrides = json_object_get(jsevent, "recurrenceOverrides");
    json_object_foreach_safe(joverrides, tmp, key, jval) {
        // this may leave the override empty, but let's
        // include it in case it is an rdate
        getcalendarevents_del_privateprops(jval);
    }
}

static void _icalcomponent_free_cb(void *val)
{
    icalcomponent_free((icalcomponent*)val);
}

static void remove_jsicalprops(json_t *jsobj, struct jmap_parser *parser)
{
    static size_t icalprops_len = 0;
    if (!icalprops_len) {
        icalprops_len = strlen(JMAPICAL_JSPROP_ICALPROPS);
    }

    const char *name;
    json_t *jval;
    void *tmp;
    json_object_foreach_safe(jsobj, tmp, name, jval) {

        if (json_is_object(jval)) {
            if (parser) jmap_parser_push(parser, name);
            remove_jsicalprops(jval, parser);
            if (parser) jmap_parser_pop(parser);
        }
        else if (json_is_array(jval)) {
            size_t i;
            json_t *jval2;
            json_array_foreach(jval, i, jval2) {
                if (json_is_object(jval2)) {
                    if (parser) jmap_parser_push_index(parser, name, i, NULL);
                    remove_jsicalprops(jval, parser);
                    if (parser) jmap_parser_pop(parser);
                }
            }
        }

        // Remove iCalProps patches
        const char *s = strstr(name, JMAPICAL_JSPROP_ICALPROPS);
        if (s && (s == name || (s[-1] == '/')) &&
                (!s[icalprops_len] || s[icalprops_len] == '/')) {
            if (parser) jmap_parser_invalid_path(parser, name);
            json_object_del(jsobj, name);
        }
    }

    // Remove iCalProps property
    if (json_object_del(jsobj, JMAPICAL_JSPROP_ICALPROPS) == 0) {
        if (parser) jmap_parser_invalid(parser, JMAPICAL_JSPROP_ICALPROPS);
    }

}

static int getcalendarevents_cb(void *vrock, struct caldav_jscal *jscal)
{
    struct getcalendarevents_rock *rock = vrock;
    int r = 0;
    json_t *jsevent = NULL;
    jmap_req_t *req = rock->req;
    hash_table *props = rock->get->props;
    msgrecord_t *mr = NULL;
    jstimezones_t *jstzones = NULL;
    struct jmapical_ctx *jmapctx = rock->jmapctx;
    struct caldav_data *cdata = &jscal->cdata;
    icalcomponent *ical_instance = NULL;

    if (!cdata->dav.alive || !jscal->alive)
        return 0;

    if (rock->is_sharee) {
        // sharee must not see secret events
        if (cdata->comp_flags.privacy == CAL_PRIVACY_SECRET)
            return 0;
    }

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
        if (mbname_isdeleted(rock->mbname)) {
            xsyslog(LOG_ERR, "corrupt ical_objs table detected: "
                    "mailbox is deleted, but ical_objs row exists",
                    "mboxid=<%s> imap_uid=<%d>",
                    rock->mbentry->uniqueid, cdata->dav.imap_uid);
            return 0;
        }

        const char *sched_userid = req->accountid;
        strarray_truncate(&rock->schedule_addresses, 0);
        get_schedule_addresses(rock->mbentry->name, sched_userid,
                &rock->schedule_addresses);

        // reset ical iterator state
        if (rock->ical) {
            icalcomponent_free(rock->ical);
            rock->ical = NULL;
        }
        rock->imap_uid = 0;
    }

    /* Check mailbox ACL rights */
    if (!rock->mbentry ||
            !jmap_hasrights_mbentry(req, rock->mbentry, JACL_READITEMS)) {
        r = 0;
        goto done;
    }

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

    /* Try to read from cache */
    if (jscal->cacheversion == JMAPCACHE_CALVERSION) {
        json_error_t jerr;
        jsevent = json_loads(jscal->cachedata, 0, &jerr);
        if (jsevent) goto gotevent;
    }

    if ((rock->imap_uid != cdata->dav.imap_uid) || !rock->ical) {
        /* Reset iterator state */
        if (rock->ical) {
            icalcomponent_free(rock->ical);
            rock->ical = NULL;
        }
        rock->imap_uid = cdata->dav.imap_uid;
        rock->is_draft = 0;
        message_guid_set_null(&rock->guid);
        if (rock->ical_instances_by_recurid.size)
            free_hash_table(&rock->ical_instances_by_recurid, _icalcomponent_free_cb);

        /* Open calendar mailbox. */
        if (!rock->mailbox || strcmp(mailbox_uniqueid(rock->mailbox), rock->mbentry->uniqueid)) {
            mailbox_close(&rock->mailbox);
            r = jmap_openmbox_by_uniqueid(req, rock->mbentry->uniqueid, &rock->mailbox, 0);
            if (r) goto done;
        }

        /* Load message containing the resource and parse iCal data */
        rock->ical = caldav_record_to_ical(rock->mailbox, cdata, req->userid, NULL);
        if (!rock->ical) {
            syslog(LOG_ERR, "caldav_record_to_ical failed for record %u:%s",
                    cdata->dav.imap_uid, mailbox_name(rock->mailbox));
            r = IMAP_INTERNAL;
            rock->imap_uid = 0;
            goto done;
        }

        /* Determine is event is a draft */
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
        rock->is_draft = system_flags & FLAG_DRAFT;

        r = msgrecord_get_guid(mr, &rock->guid);
        if (r) {
            xsyslog(LOG_ERR, "could not read message guid",
                    "mboxname=<%s> uid=<%d> err=<%s>",
                    mailbox_uniqueid(rock->mailbox), rock->imap_uid,
                    error_message(r));
            message_guid_set_null(&rock->guid);
            r = 0;
        }
    }

    if (jscal->ical_recurid[0]) {
        if (!rock->ical_instances_by_recurid.size) {
            // first time we see a recurrence instance for this ical data.
            // prepare for any further callback calls for the same UID

            // step 1: count the number of instances and initialize the
            // standalone instance cache.
            // The database ensures that we only run into this case if there
            // is no main event available, so each component in the iCalendar
            // data must have a recurrence-id
            size_t ncomps = 0;
            icalcomponent *comp = icalcomponent_get_first_real_component(rock->ical);
            icalcomponent_kind kind = icalcomponent_isa(comp);
            for ( ; comp; comp = icalcomponent_get_next_component(rock->ical, kind)) {
                ncomps++;
            }

            construct_hash_table(&rock->ical_instances_by_recurid, ncomps + 1, 0);

            // step 2: remove each component and cache by recurrence id
            icalcomponent *nextcomp;
            for (comp = icalcomponent_get_first_real_component(rock->ical);
                    comp; comp = nextcomp) {

                nextcomp = icalcomponent_get_next_component(rock->ical, kind);

                icalproperty *prop =
                    icalcomponent_get_first_property(comp, ICAL_RECURRENCEID_PROPERTY);
                if (prop) {
                    const char *recurid = icalproperty_get_value_as_string(prop);
                    icalcomponent_remove_component(rock->ical, comp);
                    if (!hash_lookup(recurid, &rock->ical_instances_by_recurid)) {
                        hash_insert(icalproperty_get_value_as_string(prop), comp,
                                &rock->ical_instances_by_recurid);
                    }
                    else icalcomponent_free(comp); // ignore duplicate
                }
            }
        }

        // inject the current instance in the embedding VCALENDAR.
        // we'll remove it again at the end of the callback
        ical_instance = hash_lookup(jscal->ical_recurid,
                 &rock->ical_instances_by_recurid);
        if (!ical_instance) goto done;
        icalcomponent_add_component(rock->ical, ical_instance);
    }

    jstzones = jstimezones_new(rock->ical, 0);

    /* Convert to JMAP */
    context_begin_cdata(jmapctx, rock->mbentry, cdata);
    jsevent = jmapical_tojmap(rock->ical, NULL, jmapctx);
    context_end_cdata(jmapctx);
    if (!jsevent) {
        syslog(LOG_ERR, "jmapical_tojson: can't convert %u:%s",
                cdata->dav.imap_uid, mailbox_name(rock->mailbox));
        r = IMAP_INTERNAL;
        goto done;
    }

    /* Add isDraft to cached event, we remove it later if not requested */
    json_object_set_new(jsevent, "isDraft", json_boolean(rock->is_draft));

    /* Set utcStart and utcEnd */
    getcalendarevents_get_utctimes(jsevent, jstzones, floatingtz);

    // Set blobId and debugBlobId
    if (!message_guid_isnull(&rock->guid)) {
        add_calendarevent_blobids(jsevent, rock->mbentry->uniqueid,
                cdata->dav.imap_uid, req->userid, &rock->guid);
    }

    /* Add to cache */
    json_t *cached = hashu64_lookup(cdata->dav.rowid, &rock->cache_jsevents);
    if (!cached) {
        cached = json_object();
        hashu64_insert(cdata->dav.rowid, cached, &rock->cache_jsevents);
    }
    json_object_set(cached, jscal->ical_recurid, jsevent);
    jsevent = json_deep_copy(jsevent);

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
    if (jmap_wantprop(props, "isOrigin")) {
        json_object_set_new(jsevent, "isOrigin",
                json_boolean(jmapical_is_origin(jsevent,
                        &rock->schedule_addresses)));
    }

    /* Update event properties based on JMAP request capabilities */
    const char *linkid;
    json_t *jlink;
    json_object_foreach(json_object_get(jsevent, "links"), linkid, jlink) {
        if (jmap_is_using(req, JMAP_CALENDARS_EXTENSION)) {
            if (json_object_get(jlink, "blobId"))
                json_object_del(jlink, "href");
        }
        else json_object_del(jlink, "blobId");
    }

    if (!jmap_is_using(req, JMAP_CALENDARS_EXTENSION)) {
        json_object_del(jsevent, "blobId");
        json_object_del(jsevent, "debugBlobId");
        remove_jsicalprops(jsevent, NULL);
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
                    jmapical_datetime_from_icaltime(icalrid, &ridt);
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

    /* Remove UTC start/end if client didn't ask for it */
    getcalendarevents_del_utctimes(req, props, jsevent);


    /* reduceParticipants and hideAttendees */
    if (rock->reduce_participants ||
            (json_boolean_value(json_object_get(jsevent, "hideAttendees")) &&
             !jmap_hasrights_mbentry(rock->req, rock->mbentry, JACL_WRITEALL))) {

        getcalendarevents_reduce_participants(jsevent, req->userid, &rock->schedule_addresses);
    }

    /* Filter shared event by privacy */
    if (rock->is_sharee && cdata->comp_flags.privacy != CAL_PRIVACY_PUBLIC) {
        getcalendarevents_del_privateprops(jsevent);
    }

    if (rock->want_eventids == NULL) {
        /* Client requested all events */
        jmap_filterprops(jsevent, props);
        struct jmap_caleventid eid = {
            .ical_uid = cdata->ical_uid,
            .ical_recurid = jscal->ical_recurid,
        };
        const char *id = jmap_caleventid_encode(&eid, &rock->buf);
        json_object_set_new(jsevent, "id", json_string(id));
        json_object_set_new(jsevent, "uid", json_string(cdata->ical_uid));
        json_object_set_new(jsevent, "@type", json_string("Event"));
        json_array_append(rock->get->list, jsevent);
    }
    else {
        /* Client requested specific event ids */
        int i;
        for (i = 0; i < ptrarray_size(rock->want_eventids); i++) {
            struct jmap_caleventid *eid = ptrarray_nth(rock->want_eventids, i);
            if (!strcmpsafe(eid->ical_recurid, jscal->ical_recurid)) {
                json_t *myevent = json_deep_copy(jsevent);
                jmap_filterprops(myevent, props);
                struct jmap_caleventid eid = {
                    .ical_uid = cdata->ical_uid,
                    .ical_recurid = jscal->ical_recurid,
                };
                const char *id = jmap_caleventid_encode(&eid, &rock->buf);
                json_object_set_new(myevent, "id", json_string(id));
                json_object_set_new(myevent, "uid", json_string(cdata->ical_uid));
                json_object_set_new(myevent, "@type", json_string("Event"));
                json_array_append_new(rock->get->list, myevent);
                buf_reset(&rock->buf);
            }
        }
        if (!jscal->ical_recurid[0]) {
            /* Expand instances, if requested */
            r = getcalendarevents_getinstances(jsevent, cdata, rock->ical,
                    jstzones, floatingtz, rock);
            if (r) goto done;
        }
    }

done:
    if (ical_instance) {
        icalcomponent_remove_component(rock->ical, ical_instance);
    }
    jstimezones_free(&jstzones);
    json_decref(jsevent);
    msgrecord_unref(&mr);
    return r;
}

// clang-format off
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
        "recurrenceIdTimeZone",
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
        "sentBy",
        NULL,
        0
    },

    /* Event properties */
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
    {
        "mayInviteSelf",
        JMAP_URN_CALENDARS,
        0
    },
    {
        "mayInviteOthers",
        JMAP_URN_CALENDARS,
        0
    },
    {
        "hideAttendees",
        JMAP_URN_CALENDARS,
        0
    },
    {
        "isOrigin",
        JMAP_URN_CALENDARS,
        0
    },
    {
        "baseEventId",
        JMAP_URN_CALENDARS,
        JMAP_PROP_SERVER_SET
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
        JMAP_PROP_SERVER_SET
    },
    {
        "debugBlobId",
        JMAP_DEBUG_EXTENSION,
        JMAP_PROP_SERVER_SET
    },
    {
        JMAPICAL_JSPROP_ICALPROPS,
        JMAP_CALENDARS_EXTENSION,
        JMAP_PROP_SERVER_SET|JMAP_PROP_SKIP_GET
    },
    { NULL, NULL, 0 }
};
// clang-format on

static void cachecalendarevents_cb(uint64_t rowid, void *payload, void *vrock)
{
    struct getcalendarevents_rock *rock = vrock;
    json_t *cached_events = payload;

    json_t *jsevent;
    const char *ical_recurid;
    json_object_foreach(cached_events, ical_recurid, jsevent) {
        // there's no way to return errors, but luckily it doesn't matter if we
        // fail to cache
        char *data = json_dumps(jsevent, 0);
        caldav_write_jscalcache(rock->db, rowid, ical_recurid,
                rock->req->userid, JMAPCACHE_CALVERSION, data);
        json_decref(jsevent);
        free(data);
    }
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
    struct jmap_get get = JMAP_GET_INITIALIZER;
    struct caldav_db *db = NULL;
    json_t *err = NULL;
    int r = 0;
    struct jmapical_ctx *jmapctx = jmapical_context_new(req, NULL);

    /* Build callback data */
    int checkacl = strcmp(req->accountid, req->userid);
    struct getcalendarevents_rock rock = {
        .req = req,
        .get = &get,
        .check_acl = checkacl,
        .jmapctx = jmapctx,
        .is_sharee = strcmp(req->accountid, req->userid)
    };
    construct_hashu64_table(&rock.cache_jsevents, 512, 0);
    construct_hash_table(&rock.floatingtz_by_mboxid, 64, 0);

    /* Parse request */
    jmap_get_parse(req, &parser, event_props, /*allow_null_ids*/1,
                   getcalendarevents_parse_args, &rock, &get, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    /* Only include iCalProps if asked for */
    if (get.props && jmap_wantprop(get.props, JMAPICAL_JSPROP_ICALPROPS)) {
        rock.jmapctx->from_ical.want_icalprops = 1;
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
            struct jmap_caleventid *eid = jmap_caleventid_decode(id);
            ptrarray_t *eventids = hash_lookup(eid->ical_uid, &eventids_by_uid);
            if (!eventids) {
                eventids = ptrarray_new();
                hash_insert(eid->ical_uid, eventids, &eventids_by_uid);
            }
            ptrarray_append(eventids, eid);
        }

        /* Lookup events by UID */
        hash_iter *iter = hash_table_iter(&eventids_by_uid);
        while (hash_iter_next(iter)) {
            const char *uid = hash_iter_key(iter);
            size_t nseen = json_array_size(get.list) + json_array_size(get.not_found);
            rock.want_eventids = hash_iter_val(iter);
            struct caldav_jscal_filter jscal_filter = CALDAV_JSCAL_FILTER_INITIALIZER;
            caldav_jscal_filter_by_ical_uid(&jscal_filter, uid, NULL);
            enum caldav_sort sort[] = {
                CAL_SORT_MAILBOX, CAL_SORT_IMAP_UID
            };
            r = caldav_foreach_jscal(db, req->userid, &jscal_filter, NULL,
                    sort, 2, &getcalendarevents_cb, &rock);
            caldav_jscal_filter_fini(&jscal_filter);
            if (r) break;
            if (nseen == json_array_size(get.list) + json_array_size(get.not_found)) {
                /* caldavdb silently ignores non-existent uids */
                int j;
                for (j = 0; j < ptrarray_size(rock.want_eventids); j++) {
                    struct jmap_caleventid *eid = ptrarray_nth(rock.want_eventids, j);
                    json_array_append_new(rock.get->not_found, json_string(eid->raw));
                }
            }
        }
        hash_iter_free(&iter);

        /* Clean up memory */
        iter = hash_table_iter(&eventids_by_uid);
        while (hash_iter_next(iter)) {
            ptrarray_t *eventids = hash_iter_val(iter);
            struct jmap_caleventid *eid;
            while ((eid = ptrarray_pop(eventids))) {
                jmap_caleventid_free(&eid);
            }
            ptrarray_free(eventids);
        }
        hash_iter_free(&iter);
        free_hash_table(&eventids_by_uid, NULL);
    } else if (json_is_null(get.ids) || get.ids == NULL) {
        /* Return all visible events */
        enum caldav_sort sort[] = {
            CAL_SORT_MAILBOX, CAL_SORT_IMAP_UID
        };
        r = caldav_foreach_jscal(db, req->userid, NULL, NULL,
                sort, 2, &getcalendarevents_cb, &rock);
    }
    if (r) goto done;

    if (hashu64_count(&rock.cache_jsevents)) {
        r = caldav_begin(db);
        if (!r) {
            hashu64_enumerate(&rock.cache_jsevents,
                cachecalendarevents_cb, &rock);
            r = caldav_commit(db);
        }
        if (r) {
            xsyslog(LOG_ERR, "failed to cache calendar events, ignoring error",
                    "userid=<%s> accountid=<%s> err=<%s>",
                    req->userid, req->accountid, error_message(r));
            r = 0;
        }
    }

    /* Build response */
    get.state = modseqtoa(jmap_modseq(req, MBTYPE_CALENDAR, 0));
    jmap_ok(req, jmap_get_reply(&get));

done:
    jmapical_context_free(&jmapctx);
    jmap_parser_fini(&parser);
    jmap_get_fini(&get);
    if (db) caldav_close(db);
    mailbox_close(&rock.mailbox);
    mboxlist_entry_free(&rock.mbentry);
    mbname_free(&rock.mbname);
    if (rock.ical) icalcomponent_free(rock.ical);
    if (rock.ical_instances_by_recurid.size)
        free_hash_table(&rock.ical_instances_by_recurid, _icalcomponent_free_cb);
    free_hashu64_table(&rock.cache_jsevents, (void(*)(void*))json_decref);
    free_hash_table(&rock.floatingtz_by_mboxid, NULL); /* values owned by libical */
    if (ptrarray_size(&rock.malloced_fallbacktzs)) {
        icaltimezone *tz;
        while ((tz = ptrarray_pop(&rock.malloced_fallbacktzs))) {
            icaltimezone_free(tz, 1);
        }
        ptrarray_fini(&rock.malloced_fallbacktzs);
    }
    strarray_fini(&rock.schedule_addresses);
    buf_free(&rock.buf);
    return r;
}

static int setcalendarevents_schedule(const char *sched_userid,
                                      const strarray_t *schedule_addresses,
                                      icalcomponent *oldical,
                                      icalcomponent *newical,
                                      int mode)
{
    int r = 0;

    /* Make local copies so we can rewrite attachments */
    if (oldical) oldical = icalcomponent_clone(oldical);
    if (newical) newical = icalcomponent_clone(newical);

    /* Determine if any scheduling is required. */
    icalcomponent *comp =
        icalcomponent_get_first_component(mode & JMAP_DESTROY ?
                oldical : newical, ICAL_VEVENT_COMPONENT);
    icalproperty *prop =
        icalcomponent_get_first_property(comp, ICAL_ORGANIZER_PROPERTY);
    if (!prop) goto done;

    const char *organizer = icalproperty_get_decoded_calendaraddress(prop);
    if (!organizer) goto done;
    if (organizer &&
            /* XXX Hack for Outlook */ icalcomponent_get_first_invitee(comp)) {

        /* Send scheduling message. */
        if (strarray_contains_case(schedule_addresses, organizer)) {
            /* Organizer scheduling object resource */
            sched_request(sched_userid, sched_userid, schedule_addresses, organizer,
                          oldical, newical, SCHED_MECH_JMAP_SET);
        } else {
            /* Attendee scheduling object resource */
            int omit_reply = 0;
            if (oldical && (mode & JMAP_DESTROY)) {
                for (prop = icalcomponent_get_first_property(comp, ICAL_ATTENDEE_PROPERTY);
                     prop;
                     prop = icalcomponent_get_next_property(comp, ICAL_ATTENDEE_PROPERTY)) {
                    const char *addr = icalproperty_get_decoded_calendaraddress(prop);
                    if (strcasecmpsafe(strarray_nth(schedule_addresses, 0), addr))
                        continue;
                    icalparameter *param =
                        icalproperty_get_first_parameter(prop, ICAL_PARTSTAT_PARAMETER);
                    omit_reply =
                        !param || icalparameter_get_partstat(param) == ICAL_PARTSTAT_NEEDSACTION;
                    break;
                }
            }
            if (!omit_reply && strarray_size(schedule_addresses))
                sched_reply(sched_userid, sched_userid, schedule_addresses,
                            oldical, newical, SCHED_MECH_JMAP_SET);
        }
    }

done:
    if (oldical) icalcomponent_free(oldical);
    if (newical) icalcomponent_free(newical);
    return r;
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
        startical = icaltime_convert_to_zone(startical, tz);
        jmapical_datetime_from_icaltime(startical, &startdt);
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

static void merge_missing_vevents(icalcomponent *dstical, icalcomponent *srcical)
{
    hash_table have = HASH_TABLE_INITIALIZER;
    construct_hash_table(&have, 32, 0);
    struct buf buf = BUF_INITIALIZER;

    int iteration;
    for (iteration = 0; iteration < 2; iteration++) {
        // First pass: determine existing components
        // Second pass: add missing components
        icalcomponent *ical = iteration == 0 ? dstical : srcical;

        icalcomponent *comp;
        for (comp = icalcomponent_get_first_component(ical, ICAL_VEVENT_COMPONENT);
             comp;
             comp = icalcomponent_get_next_component(ical, ICAL_VEVENT_COMPONENT)) {

            buf_setcstr(&buf, icalcomponent_get_uid(comp));
            icalproperty *prop = icalcomponent_get_first_property(comp,
                    ICAL_RECURRENCEID_PROPERTY);
            buf_putc(&buf, ';');
            buf_appendcstr(&buf, prop ?
                    icalproperty_get_value_as_string(prop) : "norecurid");
            icalparameter *param = prop ?
                icalproperty_get_first_parameter(prop, ICAL_TZID_PARAMETER) : NULL;
            buf_putc(&buf, ';');
            buf_appendcstr(&buf, param ?
                    icalparameter_get_value_as_string(param) : "notzid");

            if (iteration == 0) {
                hash_insert(buf_cstring(&buf), (void*)1, &have);
            }
            else if (!hash_lookup(buf_cstring(&buf), &have)) {
                icalcomponent *mycomp = icalcomponent_clone(comp);
                icalcomponent_add_component(dstical, mycomp);
            }
        }
    }
    icalcomponent_add_required_timezones(dstical);

    buf_free(&buf);
    free_hash_table(&have, NULL);
}

struct createevent {
    mbentry_t *mbentry;
    json_t *jsevent;
    struct caldav_db *db;
    json_t *serverset;
    icalcomponent *ical;
    icalcomponent *comp;
    char *ical_uid;
    char *ical_recurid;
    char *resourcename;
    const char *sched_userid;
    strarray_t schedule_addresses;
    icalcomponent *ical_standalone;
};

static int createevent_lookup_calendar(jmap_req_t *req,
                                       struct jmap_parser *parser,
                                       struct createevent *create)
{
    const char *calendarid = NULL;

    json_t *jval = json_object_get(create->jsevent, "calendarIds");
    if (json_object_size(jval) != 1) {
        // multiple calendar ids are not supported
        jmap_parser_invalid(parser, "calendarIds");
        return 0;
    }

    void *iter = json_object_iter(jval);
    if (json_object_iter_value(iter) == json_true()) {
        calendarid = json_object_iter_key(iter);
    }
    if (calendarid && *calendarid == '#') {
        calendarid = jmap_lookup_id(req, calendarid + 1);
    }
    if (!calendarid) {
        jmap_parser_invalid(parser, "calendarIds");
        return 0;
    }

    int need_rights = JACL_ADDITEMS|JACL_SETMETADATA;
    char *mboxname = caldav_mboxname(req->accountid, calendarid);
    int r = mboxlist_lookup(mboxname, &create->mbentry, NULL);
    xzfree(mboxname);
    if (r || !jmap_hasrights_mbentry(req, create->mbentry, need_rights)) {
        jmap_parser_invalid(parser, "calendarIds");
        if (r == IMAP_MAILBOX_NONEXISTENT) r = 0;
    }
    else {
        create->sched_userid = req->accountid;
        get_schedule_addresses(mboxname, create->sched_userid,
                &create->schedule_addresses);
    }
    return r;
}

static int createevent_toical(jmap_req_t *req,
                              struct jmap_parser *parser,
                              struct createevent *create)
{
    struct jmapical_ctx *jmapctx =
        jmapical_context_new(req, &create->schedule_addresses);
    struct buf buf = BUF_INITIALIZER;
    int r = 0;

    jmapctx->to_ical.serverset = create->serverset;

    // Validate extension properties
    json_t *jval = json_object_get(create->jsevent, "isDraft");
    if (jval && !json_is_boolean(jval)) {
        jmap_parser_invalid(parser, "isDraft");
    }

    // Validate utcStart and utcEnd */
    if (JNOTNULL(json_object_get(create->jsevent, "utcStart")) ||
        JNOTNULL(json_object_get(create->jsevent, "utcEnd"))) {
        /* Ignore calendar timezone - if event does not define its
         * timezone then fall back to Etc/UTC for utcStart/utcEnd */
        setcalendarevents_set_utctimes(create->jsevent, NULL, parser->invalid);
    }

    // Validate privacy on shared calendars
    if (strcmp(req->accountid, req->userid)) {
        const char *privacy =
            json_string_value(json_object_get(create->jsevent, "privacy"));
        if (privacy && strcmp(privacy, "public")) {
            jmap_parser_invalid(parser, "privacy");
        }
    }

    // Set iCalendar UID
    if (!json_object_get(create->jsevent, "uid")) {
        struct caldav_data *cdata = NULL;
        static int maxattempts = 3;
        int i;
        for (i = 0; i < maxattempts; i++) {
            buf_setcstr(&buf, makeuuid());
            r = caldav_lookup_uid(create->db, buf_cstring(&buf), &cdata);
            if (r == CYRUSDB_NOTFOUND) {
                json_object_set_new(create->jsevent, "uid",
                        json_string(buf_cstring(&buf)));
                r = 0;
                break;
            }
            else if (r) goto done;
        }
        if (i == maxattempts) {
            errno = 0;
            xsyslog(LOG_ERR, "can not create unique uid", "attempts=<%d>", i);
            r = IMAP_INTERNAL;
            goto done;
        }
        buf_reset(&buf);
    }

    create->ical = jmapical_toical(create->jsevent, NULL, parser->invalid,
            create->serverset, &create->comp, NULL, jmapctx);

    if (jmap_is_using(req, JMAP_CALENDARS_EXTENSION)) {
        json_object_set_new(create->serverset, "isOrigin",
                json_boolean(jmapical_is_origin(create->jsevent,
                        &create->schedule_addresses)));
    }

done:
    jmapical_context_free(&jmapctx);
    if (r && create->ical) {
        icalcomponent_free(create->ical);
        create->ical = NULL;
        create->comp = NULL;
    }
    buf_free(&buf);
    return r;
}

struct createevent_load_ical_rock {
    const char *ical_recurid;
    int seen_recurid;
    uint32_t imap_uid;
    char *uniqueid;
    char *resourcename;
};

int createevent_load_ical_cb(void *vrock, struct caldav_jscal *jscal)
{
    struct createevent_load_ical_rock *rock = vrock;

    if (!rock->imap_uid) {
        if (jscal->cdata.dav.mailbox_byname) {
            mbentry_t *mbentry = NULL;
            if (!mboxlist_lookup(jscal->cdata.dav.mailbox, &mbentry, NULL)) {
                rock->uniqueid = xstrdup(mbentry->uniqueid);
                rock->imap_uid = jscal->cdata.dav.imap_uid;
            }
            mboxlist_entry_free(&mbentry);
        }
        else {
            rock->uniqueid = xstrdup(jscal->cdata.dav.mailbox);
            rock->imap_uid = jscal->cdata.dav.imap_uid;
        }
    }

    if (!rock->resourcename)
        rock->resourcename = xstrdup(jscal->cdata.dav.resource);

    if (!rock->seen_recurid)
        rock->seen_recurid =
            !strcmp(jscal->ical_recurid, rock->ical_recurid);

    return 0;
}

static int createevent_load_ical(jmap_req_t *req,
                                 struct jmap_parser *parser,
                                 struct createevent *create)
{
    struct caldav_jscal_filter jscal_filter = CALDAV_JSCAL_FILTER_INITIALIZER;
    caldav_jscal_filter_by_ical_uid(&jscal_filter, create->ical_uid, NULL);
    struct createevent_load_ical_rock rock = {
        .ical_recurid = create->ical_recurid ? create->ical_recurid : ""
    };
    int r = caldav_foreach_jscal(create->db, NULL, &jscal_filter,
            NULL, NULL, 0, createevent_load_ical_cb, &rock);
    if (r) goto done;

    if (rock.imap_uid) {
        // Event with this UID already exists
        if (rock.seen_recurid) {
            // This recurrence id (empty for main event) already exists.
            jmap_parser_invalid(parser, "uid");
            if (create->ical_recurid)
                jmap_parser_invalid(parser, "recurrenceId");
            goto done;
        }

        if (create->ical_recurid) {
            // Merge new recurrence instance with existing iCalendar data.
            struct mailbox *srcmbox = NULL;
            struct caldav_data *cdata = NULL;

            // Keep pruned standalone instance for iTIP
            create->ical_standalone = icalcomponent_clone(create->ical);

            r = jmap_openmbox_by_uniqueid(req, rock.uniqueid, &srcmbox, 0);
            if (r) goto done;

            r = caldav_lookup_uid(create->db, create->ical_uid, &cdata);
            if (r) goto done;

            create->resourcename = xstrdup(cdata->dav.resource);

            icalcomponent *srcical = caldav_record_to_ical(srcmbox,
                    cdata, req->userid, NULL);
            if (srcical) {
                merge_missing_vevents(create->ical, srcical);
                icalcomponent_free(srcical);
                srcical = NULL;
            }

            mailbox_close(&srcmbox);
        }

        if (!create->resourcename) {
            create->resourcename = rock.resourcename;
            rock.resourcename = NULL;
        }
    }


done:
    caldav_jscal_filter_fini(&jscal_filter);
    xzfree(rock.uniqueid);
    xzfree(rock.resourcename);
    return r;
}

static int createevent_store(jmap_req_t *req,
                             struct jmap_parser *parser,
                             struct createevent *create,
                             struct mailbox *notifmbox,
                             int send_itip)
{
    struct mailbox *mbox = NULL;
    struct buf buf = BUF_INITIALIZER;
    struct transaction_t txn = {
        .req_hdrs = spool_new_hdrcache(),
        .userid = req->userid,
        .authstate = req->authstate
    };
    int r = 0;

    static int64_t icalendar_max_size = -1;
    if (icalendar_max_size < 0) {
        icalendar_max_size = config_getbytesize(IMAPOPT_ICALENDAR_MAX_SIZE, 'B');
        if (icalendar_max_size <= 0) icalendar_max_size = BYTESIZE_UNLIMITED;
    }

    // Make event id. Main events use empty string as recurrence id.
    create->ical_uid = xstrdup(icalcomponent_get_uid(create->comp));
    icalproperty *prop = icalcomponent_get_first_property(create->comp,
            ICAL_RECURRENCEID_PROPERTY);
    create->ical_recurid = prop ?
        xstrdup(icalproperty_get_value_as_string(prop)) : NULL;

    // Open calendar mailbox.
    r = jmap_openmbox_by_uniqueid(req, create->mbentry->uniqueid, &mbox, 1);
    if (r) {
        xsyslog(LOG_ERR, "jmap_openmbox failed", "mboxname=<%s> err=<%s>",
                create->mbentry->name, error_message(r));
        if (r == IMAP_MAILBOX_NONEXISTENT) {
            jmap_parser_invalid(parser, "calendarIds");
            r = 0;
        }
        goto done;
    }

    // Handle existing iCalendar data for this UID.
    r = createevent_load_ical(req, parser, create);
    if (r || json_array_size(parser->invalid)) goto done;

    // Sanity-check iCalendar data
    size_t ical_len = strlen(icalcomponent_as_ical_string(create->ical));
    if (ical_len > (size_t) icalendar_max_size) {
        r = IMAP_MESSAGE_TOO_LARGE;
        goto done;
    }

    // Process managed attachments
    int r2 = caldav_manage_attachments(req->accountid, create->ical, NULL);
    if (r2 && r2 != HTTP_NOT_FOUND) {
        xsyslog(LOG_ERR, "caldav_manage_attachments failed", "err=<%s>",
                error_message(r2));
        r = IMAP_INTERNAL;
        goto done;
    }

    // Handle scheduling
    int is_draft = json_boolean_value(json_object_get(create->jsevent, "isDraft"));
    if (send_itip && !is_draft) {
        icalcomponent *sched_ical = create->ical_standalone ?
            create->ical_standalone : create->ical;
        r = setcalendarevents_schedule(create->sched_userid,
                &create->schedule_addresses, NULL, sched_ical, JMAP_CREATE);
        if (r) goto done;
        remove_itip_properties(create->ical);
    }

    // Use UID as DAV resource name, or generate name.
    if (!create->resourcename) {
        const char *p;
        for (p = create->ical_uid; *p; p++) {
            if ((*p >= '0' && *p <= '9') ||
                    (*p >= 'a' && *p <= 'z') ||
                    (*p >= 'A' && *p <= 'Z') ||
                    (*p == '@' || *p == '.') ||
                    (*p == '_' || *p == '-')) {
                continue;
            }
            break;
        }
        if (!*p && p - create->ical_uid >= 16 && p - create->ical_uid <= 200)
            buf_setcstr(&buf, create->ical_uid);
        else
            buf_setcstr(&buf, makeuuid());
        buf_appendcstr(&buf, ".ics");
        create->resourcename = buf_newcstring(&buf);
        buf_reset(&buf);
    }

    // Write to database
    strarray_t add_imapflags = STRARRAY_INITIALIZER;
    if (is_draft) strarray_append(&add_imapflags, "\\draft");
    r = caldav_store_resource(&txn, create->ical, mbox,
            create->resourcename, 0, create->db, PERMS_NOKEEP,
            req->userid, &add_imapflags, NULL, &create->schedule_addresses);
    strarray_fini(&add_imapflags);
    if (r && r != HTTP_CREATED && r != HTTP_NO_CONTENT) {
        xsyslog(LOG_ERR, "caldav_store_resource failed",
                "accountid=<%s> err=<%s>",
                req->accountid, error_message(r));
        goto done;
    }
    r = 0;

    if (calendar_has_sharees(mbox->mbentry)) {
        // Create notification
        json_t *myevent = json_deep_copy(create->jsevent);
        jmapical_remove_peruserprops(myevent);
        r2 = jmap_create_caleventnotif(notifmbox, req->userid, req->authstate,
                mailbox_name(mbox), "created", create->ical_uid,
                &create->schedule_addresses, NULL,
                is_draft, myevent, NULL);
        if (r2) {
            xsyslog(LOG_WARNING, "could not create notification",
                    "uid=%s error=%s", create->ical_uid, error_message(r2));
        }
        json_decref(myevent);
    }

    // Set server-set properties
    struct jmap_caleventid eid = {
        .ical_uid = create->ical_uid,
        .ical_recurid = create->ical_recurid,
    };
    json_object_set_new(create->serverset, "id",
            json_string(jmap_caleventid_encode(&eid, &buf)));

    json_object_set_new(create->serverset, "uid",
            json_string(eid.ical_uid));

    {
        char *xhref = jmap_xhref(mailbox_name(mbox), create->resourcename);
        json_object_set_new(create->serverset, "x-href", json_string(xhref));
        free(xhref);
    }

    if (jmap_is_using(req, JMAP_CALENDARS_EXTENSION)) {
        struct index_record record;
        if (!mailbox_find_index_record(mbox, mbox->i.last_uid, &record)) {
            add_calendarevent_blobids(create->serverset, mailbox_uniqueid(mbox),
                    mbox->i.last_uid, req->userid, &record.guid);
        }
    }

done:
    spool_free_hdrcache(txn.req_hdrs);
    mailbox_close(&mbox);
    buf_free(&txn.buf);
    buf_free(&buf);
    return r;
}

static void setcalendarevents_create(jmap_req_t *req,
                                     json_t *jsevent,
                                     struct caldav_db *db,
                                     struct mailbox *notifmbox,
                                     int send_itip,
                                     json_t *serverset,
                                     json_t **errptr)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    int r = 0;

    struct createevent create = {
        .jsevent = json_deep_copy(jsevent),
        .db = db,
        .serverset = serverset
    };

    remove_jsicalprops(create.jsevent, &parser);
    if (json_array_size(parser.invalid)) goto done;

    r = createevent_lookup_calendar(req, &parser, &create);
    if (r || json_array_size(parser.invalid)) goto done;

    r = createevent_toical(req, &parser, &create);
    if (r || json_array_size(parser.invalid)) goto done;

    r = createevent_store(req, &parser, &create, notifmbox, send_itip);
    if (r || json_array_size(parser.invalid)) goto done;

done:
    if (r) {
        switch (r) {
            case HTTP_FORBIDDEN:
            case IMAP_PERMISSION_DENIED:
                *errptr = json_pack("{s:s}", "type", "forbidden");
                break;
            case IMAP_QUOTA_EXCEEDED:
                *errptr = json_pack("{s:s}", "type", "overQuota");
                break;
            case IMAP_MESSAGE_TOO_LARGE:
                *errptr = json_pack("{s:s}", "type", "tooLarge");
                break;
            default:
                *errptr = jmap_server_error(r);
        }
    }
    else if (json_array_size(parser.invalid)) {
        *errptr = json_pack("{s:s s:O}",
                "type", "invalidProperties",
                "properties", parser.invalid);
    }

    mboxlist_entry_free(&create.mbentry);
    if (create.ical) {
        icalcomponent_free(create.ical);
        create.ical = NULL;
    }
    if (create.ical_standalone) {
        icalcomponent_free(create.ical_standalone);
        create.ical_standalone = NULL;
    }
    free(create.ical_uid);
    free(create.ical_recurid);
    free(create.resourcename);
    json_decref(create.jsevent);
    strarray_fini(&create.schedule_addresses);
    jmap_parser_fini(&parser);
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

static void updateevent_validate_ids(json_t *old, json_t *new, json_t *invalid)
{
    if (strcmpsafe(json_string_value(json_object_get(old, "uid")),
                json_string_value(json_object_get(new, "uid")))) {
        json_array_append_new(invalid, json_string("uid"));
    }
    if (strcmpsafe(json_string_value(json_object_get(old, "recurrenceId")),
                json_string_value(json_object_get(new, "recurrenceId")))) {
        json_array_append_new(invalid, json_string("recurrenceId"));
    }
    if (strcmpsafe(json_string_value(json_object_get(old, "recurrenceIdTimeZone")),
                json_string_value(json_object_get(new, "recurrenceIdTimeZone")))) {
        json_array_append_new(invalid, json_string("recurrenceIdTimeZone"));
    }
}

static void updateevent_apply_patch_override(struct jmap_caleventid *eid,
                                             json_t *old_event,
                                             json_t *event_patch,
                                             icalcomponent *oldical,
                                             icaltimezone *floatingtz,
                                             json_t **new_eventp,
                                             json_t *invalid,
                                             json_t **err)
{
    icaltimetype icalrecuriddt = icaltime_from_string(eid->ical_recurid);
    struct jmapical_datetime recuriddt = JMAPICAL_DATETIME_INITIALIZER;
    jmapical_datetime_from_icaltime(icalrecuriddt, &recuriddt);
    struct jmap_caleventid base_eid = { .ical_uid = eid->ical_uid };
    struct buf buf = BUF_INITIALIZER;

    jmapical_localdatetime_as_string(&recuriddt, &buf);
    char *recurid = xstrdupnull(buf_cstring(&buf));
    buf_reset(&buf);

    jmap_caleventid_encode(&base_eid, &buf);
    char *baseid = xstrdupnull(buf_cstring(&buf));
    buf_reset(&buf);

    json_t *new_event = NULL;
    json_t *jprop = NULL;

    int is_rdate = !_recurid_is_instanceof(icalrecuriddt, oldical, 1);

    json_t *old_overrides = json_object_get(old_event, "recurrenceOverrides");
    json_t *old_override = json_object_get(old_overrides, recurid);
    json_t *new_instance = NULL;
    json_t *new_override = NULL;
    if (old_override) {
        /* Patch an existing override */
        json_t *old_instance = jmap_patchobject_apply(old_event, old_override, NULL, 0);
        new_instance = jmap_patchobject_apply(old_instance, event_patch, invalid, 0);
        updateevent_validate_ids(old_instance, new_instance, invalid);
        json_decref(old_instance);
    }
    else {
        /* Create a new override */
        new_instance = jmap_patchobject_apply(old_event, event_patch, invalid, 0);
        updateevent_validate_ids(old_event, new_instance, invalid);
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

    /* Can keep existing baseEventId */
    jprop = json_object_get(event_patch, "baseEventId");
    if (jprop && strcmpsafe(json_string_value(jprop), baseid)) {
        json_array_append_new(invalid, json_string("baseEventId"));
    }

    json_object_del(new_instance, "recurrenceRules");
    json_object_del(new_instance, "recurrenceOverrides");
    json_object_del(new_instance, "excludedRecurrenceRules");
    new_override = jmap_patchobject_create(old_event, new_instance, 0/*no_remove*/);
    json_object_del(new_override, "@type");
    json_object_del(new_override, "method");
    json_object_del(new_override, "prodId");
    json_object_del(new_override, "recurrenceId");
    json_object_del(new_override, "recurrenceIdTimeZone");
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

    /* Create the new Event */
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

done:
    *new_eventp = new_event;
    free(recurid);
    free(baseid);
    buf_free(&buf);
}

static void updateevent_apply_patch_event(json_t *old_event,
                                          json_t *event_patch,
                                          icalcomponent *oldical,
                                          icaltimezone *floatingtz,
                                          json_t **new_eventp,
                                          json_t *invalid,
                                          json_t **err)
{
    jstimezones_t *jstzones = jstimezones_new(oldical, 1);
    json_t *new_event = NULL;
    json_t *jprop;

    jprop = json_object_get(event_patch, "baseEventId");
    if (jprop) {
        json_array_append_new(invalid, json_string("baseEventId"));
    }

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
        new_event = jmap_patchobject_apply(old_mainevent, mainevent_patch, invalid, 0);
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
            json_t *override = jmap_patchobject_apply(new_event, old_override, NULL, 0);
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
            json_t *new_wrapper = jmap_patchobject_apply(old_wrapper, overrides_patch, invalid, 0);
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
            json_t *new_override = jmap_patchobject_create(new_event, jval, 0/*no_remove*/);
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
        new_event = jmap_patchobject_apply(old_event, event_patch, invalid, 0);
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

done:
    *new_eventp = new_event;
    jstimezones_free(&jstzones);
}

static void updateevent_bump_sequence(json_t *old_event,
                                      json_t *new_event,
                                      json_t *update,
                                      strarray_t *schedule_addresses)
{
    /* Bump sequence iff... */

    /* ... server is the source of the event */
    json_t *jreplyto = json_object_get(new_event, "replyTo");
    if (JNOTNULL(jreplyto)) {
        const char *addr = json_string_value(json_object_get(jreplyto, "imip"));
        if (addr && !strncasecmp(addr, "mailto:", 7) &&
                !strarray_contains(schedule_addresses, addr + 7)) {
            return;
        }
    }

    /* ... a non per-user property got updated */
    int updates_shared_prop = 0;
    json_t *jpatch = jmap_patchobject_create(old_event, new_event, 0/*no_remove*/);
    const char *path;
    json_t *jval;
    void *tmp;
    json_object_foreach_safe(jpatch, tmp, path, jval) {
        if (!strncmp(path, "recurrenceOverrides/", 20)) {
            path = strchr(path + 20, '/');
            if (!path) continue;
            path++;
        }

        if (strcmp(path, "method") &&
            strcmp(path, "keywords") && strncmp(path, "keywords/", 9) &&
            strcmp(path, "color") &&
            strcmp(path, "freeBusyStatus") &&
            strcmp(path, "useDefaultAlerts") &&
            strcmp(path, "alerts") && strncmp(path, "alerts/", 7) &&
            strcmp(path, "calendarIds") && strncmp(path, "calendarIds/", 12) &&
            strcmp(path, "isDraft")) {

            updates_shared_prop = 1;
            break;
        }
    }
    json_decref(jpatch);
    if (!updates_shared_prop)
        return;

    /* ... sequence property is not updated, or <= current sequence */
    json_int_t new_seq =
        json_integer_value(json_object_get(new_event, "sequence"));
    json_int_t old_seq =
        json_integer_value(json_object_get(old_event, "sequence"));
    if (new_seq > old_seq) return;

    new_seq = old_seq + 1;
    json_object_set_new(new_event, "sequence", json_integer(new_seq));
    json_object_set_new(update, "sequence", json_integer(new_seq));
}

struct updateevent {
    struct jmap_caleventid *eid;
    json_t *event_patch;
    int is_standalone;
    json_t *serverset;

    mbentry_t *mbentry;
    struct caldav_data *cdata;
    strarray_t *schedule_addresses;

    json_t *old_event;
    icalcomponent *oldical;
    icalcomponent *newical;

    jstimezones_t *jstzones;
};

static int updateevent_apply_patch(jmap_req_t *req,
                                   struct updateevent *update,
                                   json_t *invalid,
                                   json_t *serverset,
                                   json_t **err)


{
    json_t *new_event = NULL;
    json_t *old_event = NULL;
    int r = 0;

    int floatingtz_is_malloced = 0;
    icaltimezone *floatingtz =
        calendarevent_get_floatingtz(update->mbentry, req->userid,
                &floatingtz_is_malloced);

    if (update->eid->ical_recurid && !update->is_standalone) {
        // XXX caldav.db version 15 stores standalone instances by their
        // recurrence id. But until the DAV databases got reconstructed,
        // we might encounter db records with an empty recurid column.
        icalcomponent *comp;
        for (comp = icalcomponent_get_first_real_component(update->oldical);
             comp && icalcomponent_get_first_property(comp, ICAL_RECURRENCEID_PROPERTY);
             comp = icalcomponent_get_next_component(update->oldical,
                 icalcomponent_isa(comp))) { }

        update->is_standalone = !comp;
    }

    // prepare iCalendar data
    icalcomponent *myoldical = update->oldical;
    if (update->is_standalone) {
        // prune any other standalone instances from iCalendar data
        myoldical = icalcomponent_clone(update->oldical);
        icalcomponent *comp, *nextcomp;
        for (comp = icalcomponent_get_first_real_component(myoldical);
             comp; comp = nextcomp) {

            nextcomp = icalcomponent_get_next_component(myoldical,
                    icalcomponent_isa(comp));

            icalproperty *prop = icalcomponent_get_first_property(comp,
                    ICAL_RECURRENCEID_PROPERTY);
            if (!prop) {
                // there is something very wrong here
                update->is_standalone = 0;
                icalcomponent_free(myoldical);
                myoldical = update->oldical;
                break;
            }
            const char *ical_recurid = icalproperty_get_value_as_string(prop);
            if (strcmpsafe(update->eid->ical_recurid, ical_recurid)) {
                icalcomponent_remove_component(myoldical, comp);
                icalcomponent_free(comp);
            }
        }
    }

    // Set up conversion context
    struct jmapical_ctx *jmapctx = jmapical_context_new(req,
            update->schedule_addresses);
    jmapctx->to_ical.serverset = update->serverset;
    jmapctx->from_ical.dont_guess_timezones = 1;
    jmapctx->from_ical.want_icalprops = 1;
    jmapctx->to_ical.ignore_orphan_timezones = 1;

    // Read old event
    context_begin_cdata(jmapctx, update->mbentry, update->cdata);
    old_event = jmapical_tojmap(myoldical, NULL, jmapctx);
    if (!old_event) {
        r = IMAP_INTERNAL;
        goto done;
    }
    update->old_event = json_deep_copy(old_event);

    json_object_del(old_event, "updated");

    // Apply the patch
    if (update->eid->ical_recurid && !update->is_standalone) {
        /* Update or create an override */
        updateevent_apply_patch_override(update->eid, update->old_event,
                update->event_patch, myoldical, floatingtz,
                &new_event, invalid, err);
        if (!new_event) goto done;
    }
    else {
        // Validate privacy on shared calendars
        if (strcmp(req->accountid, req->userid)) {
            const char *new_privacy =
                json_string_value(json_object_get(update->event_patch, "privacy"));
            if (new_privacy && strcmp(new_privacy, "public")) {
                json_array_append_new(invalid, json_string("privacy"));
            }
        }

        /* Update a regular event or standalone instance */
        updateevent_apply_patch_event(update->old_event, update->event_patch,
                myoldical, floatingtz, &new_event, invalid, err);
        if (!new_event) goto done;
    }

    updateevent_validate_ids(update->old_event, new_event, invalid);

    updateevent_bump_sequence(update->old_event, new_event,
            update->serverset, update->schedule_addresses);

    /* Convert to iCalendar */
    icalcomponent *newical = jmapical_toical(new_event, myoldical,
            invalid, update->serverset, NULL, &update->jstzones, jmapctx);
    if (!newical || json_array_size(invalid)) {
        if (newical) icalcomponent_free(newical);
        goto done;
    }

    if (update->is_standalone)
        merge_missing_vevents(newical, update->oldical);

    update->newical = newical;

    if (jmap_is_using(req, JMAP_CALENDARS_EXTENSION)) {
        int old_is_origin = jmapical_is_origin(old_event, update->schedule_addresses);
        int new_is_origin = jmapical_is_origin(new_event, update->schedule_addresses);
        if (old_is_origin != new_is_origin) {
            json_object_set_new(serverset, "isOrigin", json_boolean(new_is_origin));
        }
    }

done:
    if (myoldical && myoldical != update->oldical)
        icalcomponent_free(myoldical);
    if (floatingtz_is_malloced)
        icaltimezone_free(floatingtz, 1);
    jmapical_context_free(&jmapctx);
    json_decref(old_event);
    json_decref(new_event);
    return r;
}

int updateevent_check_exists_cb(void *vrock __attribute__((unused)),
                                struct caldav_jscal *jscal __attribute__((unused)))
{
    return CYRUSDB_DONE;
}

static int remove_itip_cb(void *rock, struct caldav_jscal *jscal)
{
    struct mailbox *inbox = (struct mailbox *) rock;
    struct index_record record = { 0 };

    /* Expunge the resource from mailbox. */
    if (!mailbox_find_index_record(inbox, jscal->cdata.dav.imap_uid, &record)) {
        record.internal_flags |= FLAG_INTERNAL_EXPUNGED;
        int r = mailbox_rewrite_index_record(inbox, &record);
        if (r) {
            syslog(LOG_ERR, "mailbox_rewrite_index_record (%s:%u) failed: %s",
                   mailbox_name(inbox), jscal->cdata.dav.imap_uid,
                   error_message(r));
        }
    }

    return 0;
}

static void remove_itip_messages(struct caldav_db *db,
                                 struct mailbox *inbox,
                                 const char *uid,
                                 const char *recurid)
{
    if (inbox) {
        struct caldav_jscal_filter jscal_filter = CALDAV_JSCAL_FILTER_INITIALIZER;
        caldav_jscal_filter_by_ical_uid(&jscal_filter, uid, recurid);
        caldav_jscal_filter_by_mbentry(&jscal_filter, inbox->mbentry);

        caldav_foreach_jscal(db, NULL, &jscal_filter, NULL, NULL, 0,
                &remove_itip_cb, inbox);
        caldav_jscal_filter_fini(&jscal_filter);
    }
}

static int check_eventid_exists(struct jmap_caleventid *eid,
                                struct caldav_db *db, int *is_standalone)
{
    struct caldav_jscal_filter jscal_filter = CALDAV_JSCAL_FILTER_INITIALIZER;
    caldav_jscal_filter_by_ical_uid(&jscal_filter, eid->ical_uid, eid->ical_recurid);
    int r = caldav_foreach_jscal(db, NULL, &jscal_filter, NULL, NULL, 0,
                                 updateevent_check_exists_cb, NULL);
    caldav_jscal_filter_fini(&jscal_filter);
    if (r && r != CYRUSDB_DONE)
        goto done;

    *is_standalone = (r == CYRUSDB_DONE);
    if (!*is_standalone) {
        struct caldav_jscal_filter jscal_filter = CALDAV_JSCAL_FILTER_INITIALIZER;
        // if it isn't there must be a main event
        caldav_jscal_filter_by_ical_uid(&jscal_filter, eid->ical_uid, "");
        r = caldav_foreach_jscal(db, NULL, &jscal_filter, NULL, NULL, 0,
                                 updateevent_check_exists_cb, NULL);
        caldav_jscal_filter_fini(&jscal_filter);
    }

done:
    return (r != CYRUSDB_DONE) ? HTTP_NOT_FOUND : 0;
}

static void setcalendarevents_update(jmap_req_t *req,
                                     struct mailbox *notifmbox,
                                     struct mailbox *schedinbox,
                                     json_t *event_patch,
                                     struct jmap_caleventid *eid,
                                     struct caldav_db *db,
                                     int send_scheduling_messages,
                                     json_t *serverset,
                                     json_t **err)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    int r = 0;

    mbentry_t *mbentry = NULL;
    struct caldav_data *cdata = NULL;
    struct mailbox *mbox = NULL;
    struct mailbox *dstmbox = NULL;
    mbentry_t *dstmbentry = NULL;
    struct mboxevent *mboxevent = NULL;
    char *resource = NULL;
    strarray_t del_imapflags = STRARRAY_INITIALIZER;
    strarray_t schedule_addresses = STRARRAY_INITIALIZER;

    struct updateevent update = {
        .event_patch = json_deep_copy(event_patch),
        .eid = eid,
        .serverset = serverset,
    };

    remove_jsicalprops(update.event_patch, &parser);
    if (json_array_size(parser.invalid)) goto done;

    static int64_t icalendar_max_size = -1;
    if (icalendar_max_size < 0) {
        icalendar_max_size = config_getbytesize(IMAPOPT_ICALENDAR_MAX_SIZE, 'B');
        if (icalendar_max_size <= 0) icalendar_max_size = BYTESIZE_UNLIMITED;
    }

    // Determine if event is a standalone recurrence instance
    if (eid->ical_recurid) {
        r = check_eventid_exists(eid, db, &update.is_standalone);
        if (r) goto done;
    }

    /* Determine mailbox and resource name of calendar event. */
    r = caldav_lookup_uid(db, eid->ical_uid, &cdata);
    if (r && r != CYRUSDB_NOTFOUND) {
        syslog(LOG_ERR,
               "caldav_lookup_uid(%s) failed: %s", eid->ical_uid, error_message(r));
        goto done;
    }
    if (r == CYRUSDB_NOTFOUND || !cdata->dav.alive ||
            !cdata->dav.rowid || !cdata->dav.imap_uid ||
            cdata->comp_type != CAL_COMP_VEVENT) {
        r = IMAP_NOTFOUND;
        goto done;
    }

    mbentry = jmap_mbentry_from_dav(req, &cdata->dav);
    if (!mbentry) {
        xsyslog(LOG_WARNING, "no mbentry for mailbox",
                "dav.mailbox=<%s> dav.mailbox_byname=<%d>",
                cdata->dav.mailbox, cdata->dav.mailbox_byname);
        r = IMAP_NOTFOUND;
        goto done;
    }

    resource = xstrdup(cdata->dav.resource);

    if (mboxname_isdeletedmailbox(mbentry->name, NULL)) {
        xsyslog(LOG_ERR, "corrupt ical_objs table detected: "
                "mailbox is deleted, but ical_objs row exists",
                "mboxid=<%s> imap_uid=<%d>",
                mbentry->uniqueid, cdata->dav.imap_uid);
        r = IMAP_NOTFOUND;
        goto done;
    }

    /* Check read permission. */
    if (!jmap_hasrights_mbentry(req, mbentry, JACL_READITEMS)) {
        r = IMAP_NOTFOUND;
        goto done;
    }

    /* Check privacy for sharees */
    if (strcmp(req->accountid, req->userid)) {
        if (cdata->comp_flags.privacy != CAL_PRIVACY_PUBLIC) {
            r = cdata->comp_flags.privacy == CAL_PRIVACY_SECRET ?
                IMAP_NOTFOUND : IMAP_PERMISSION_DENIED;
            goto done;
        }
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

    /* Open mailboxes for writing */
    r = jmap_openmbox_by_uniqueid(req, mbentry->uniqueid, &mbox, 1);
    if (r == IMAP_MAILBOX_NONEXISTENT) {
        jmap_parser_push(&parser, mbentry->name);
        jmap_parser_invalid(&parser, "calendarIds");
        jmap_parser_pop(&parser);
        r = 0;
        goto done;
    }
    else if (r) {
        syslog(LOG_ERR, "jmap_openmbox_by_uniqueid(req, %s) failed: %s",
                mbentry->name, error_message(r));
        goto done;
    }
    /* Determine target mailbox */
    if (calendarId) {
        char *dstmboxname = caldav_mboxname(req->accountid, calendarId);
        if (strcmp(mbentry->name, dstmboxname)) {
            r = mboxlist_lookup(dstmboxname, &dstmbentry, NULL);
        }
        free(dstmboxname);
        if (!r && dstmbentry) {
            r = jmap_openmbox_by_uniqueid(req, dstmbentry->uniqueid, &dstmbox, 1);
        }
        if (r == IMAP_MAILBOX_NONEXISTENT) {
            jmap_parser_invalid(&parser, "calendarIds");
            r = 0;
            goto done;
        }
        else if (r) goto done;
    }

    const char *sched_userid = req->accountid;
    get_schedule_addresses(mbentry->name, sched_userid, &schedule_addresses);

    if (dstmbentry) {
        /* Validate permissions for move */
        if (!jmap_hasrights_mbentry(req, mbentry, JACL_REMOVEITEMS)) {
            *err = json_pack("{s:s}", "type", "forbidden");
            goto done;
        }
        if (!jmap_hasrights_mbentry(req, dstmbentry, JACL_ADDITEMS|JACL_SETMETADATA)) {
            *err = json_pack("{s:s}", "type", "forbidden");
            goto done;
        }
    }

    /* Fetch index record for the resource */
    struct index_record record = { 0 };
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
    update.oldical = caldav_record_to_ical(mbox, cdata, req->userid, NULL);
    if (!update.oldical) {
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

    /* Apply patch */
    update.mbentry = mbentry;
    update.cdata = cdata;
    update.schedule_addresses = &schedule_addresses;
    r = updateevent_apply_patch(req, &update, parser.invalid, serverset, err);
    if (json_array_size(parser.invalid) || *err) {
        r = 0;
        goto done;
    }
    else if (update.newical) {
        size_t ical_size = strlen(icalcomponent_as_ical_string(update.newical));
        if (ical_size > (size_t) icalendar_max_size) {
            r = IMAP_MESSAGE_TOO_LARGE;
            goto done;
        }
    }
    else if (r) goto done;

    if (dstmbox) {
        /* Expunge the resource from mailbox. */
        record.internal_flags |= FLAG_INTERNAL_EXPUNGED;
        mboxevent = mboxevent_new(EVENT_MESSAGE_EXPUNGE);
        r = mailbox_rewrite_index_record(mbox, &record);
        if (r) {
            syslog(LOG_ERR, "mailbox_rewrite_index_record (%s) failed: %s",
                    cdata->dav.mailbox, error_message(r));
            mailbox_close(&mbox);
            goto done;
        }
        mboxevent_extract_record(mboxevent, mbox, &record);
        mboxevent_extract_mailbox(mboxevent, mbox);
        mboxevent_set_numunseen(mboxevent, mbox, -1);
        mboxevent_set_access(mboxevent, NULL, NULL,
                             req->userid, cdata->dav.mailbox, 0);
        mboxevent_notify(&mboxevent);
        mboxevent_free(&mboxevent);

        /* Close the mailbox we moved the event from. */
        mailbox_close(&mbox);
        mbox = dstmbox;
        dstmbox = NULL;
    }


    /* Remove METHOD property */
    remove_itip_properties(update.newical);

    /* Store the updated VEVENT. */
    struct transaction_t txn = {
        .req_hdrs = spool_new_hdrcache(),
        .userid = req->userid,
        .authstate = req->authstate
    };
    r = proxy_mlookup(mailbox_name(mbox), &txn.req_tgt.mbentry, NULL, NULL);
    if (r) {
        syslog(LOG_ERR, "mlookup(%s) failed: %s", mailbox_name(mbox), error_message(r));
    }
    else {
        r = caldav_store_resource(&txn, update.newical,
                mbox, resource, record.createdmodseq,
                db, PERMS_NOKEEP, req->userid,
                NULL, &del_imapflags, &schedule_addresses);
        if (calendar_has_sharees(mbox->mbentry)) {
            // Create notification
            if (r == HTTP_CREATED || r == HTTP_NO_CONTENT) {
                json_t *patch_copy = json_deep_copy(event_patch);
                jmapical_remove_peruserprops(patch_copy);
                jmapical_remove_peruserprops(update.old_event);
                if (json_object_size(patch_copy)) {
                    int r2 = jmap_create_caleventnotif(notifmbox, req->userid,
                            req->authstate, mailbox_name(mbox), "updated",
                            eid->ical_uid, &schedule_addresses, NULL,
                            record.system_flags & FLAG_DRAFT,
                            update.old_event, patch_copy);
                    if (r2) {
                        xsyslog(LOG_WARNING, "could not create notification",
                                "uid=%s error=%s", eid->ical_uid, error_message(r2));
                    }
                }
                json_decref(patch_copy);
            }
        }
    }
    transaction_free(&txn);
    if (r && r != HTTP_CREATED && r != HTTP_NO_CONTENT) {
        syslog(LOG_ERR, "caldav_store_resource failed for user %s: %s",
               req->accountid, error_message(r));
        goto done;
    }
    r = 0;

    /* Remove related iTIP messages from CalDAV Scheduling Inbox */
    remove_itip_messages(db, schedinbox, eid->ical_uid,
                         update.is_standalone ? eid->ical_recurid : NULL);

    /* Handle scheduling. */
    if (!(record.system_flags & FLAG_DRAFT) && send_scheduling_messages) {
        r = setcalendarevents_schedule(sched_userid, &schedule_addresses,
                update.oldical, update.newical, JMAP_UPDATE);
        if (r) goto done;
    }

    /* Manage attachments */
    int ret = caldav_manage_attachments(req->accountid,
            update.newical, update.oldical);
    if (ret && ret != HTTP_NOT_FOUND) {
        syslog(LOG_ERR, "caldav_manage_attachments: %s", error_message(ret));
        r = IMAP_INTERNAL;
        goto done;
    }

    if (jmap_is_using(req, JMAP_CALENDARS_EXTENSION)) {
        struct index_record record;
        if (!mailbox_find_index_record(mbox, mbox->i.last_uid, &record)) {
            add_calendarevent_blobids(serverset, mailbox_uniqueid(mbox),
                    mbox->i.last_uid, req->userid, &record.guid);
        }
    }

done:
    if (*err == NULL) {
        if (r) {
            switch (r) {
                case HTTP_NOT_FOUND:
                case IMAP_NOTFOUND:
                    *err = json_pack("{s:s}", "type", "notFound");
                    break;
                case HTTP_FORBIDDEN:
                case IMAP_PERMISSION_DENIED:
                    *err = json_pack("{s:s}", "type", "forbidden");
                    break;
                case HTTP_NO_STORAGE:
                case IMAP_QUOTA_EXCEEDED:
                    *err = json_pack("{s:s}", "type", "overQuota");
                    break;
                case IMAP_MESSAGE_TOO_LARGE:
                    *err = json_pack("{s:s}", "type", "tooLarge");
                    break;
                default:
                    *err = jmap_server_error(r);
            }
        }
        else if (json_array_size(parser.invalid)) {
            *err = json_pack( "{s:s, s:O}", "type", "invalidProperties",
                    "properties", parser.invalid);
        }
    }

    if (update.newical)
        icalcomponent_free(update.newical);
    if (update.oldical)
        icalcomponent_free(update.oldical);
    json_decref(update.old_event);
    json_decref(update.event_patch);
    jstimezones_free(&update.jstzones);

    mailbox_close(&mbox);
    mailbox_close(&dstmbox);
    jmap_parser_fini(&parser);
    strarray_fini(&del_imapflags);
    strarray_fini(&schedule_addresses);
    mboxlist_entry_free(&mbentry);
    mboxlist_entry_free(&dstmbentry);
    free(resource);
}

static icalcomponent *prune_vevent_instances(icalcomponent *ical,
                                             const char *recurid,
                                             int want_recurid)
{
    // want_recurid = 0: prune instance
    // want_recurid = 1: prune all other instances
    want_recurid = !!want_recurid;

    icalcomponent *myical = icalcomponent_clone(ical);
    icalcomponent *comp, *nextcomp;
    for (comp = icalcomponent_get_first_component(myical,
                ICAL_VEVENT_COMPONENT);
         comp;
         comp = nextcomp) {

        nextcomp = icalcomponent_get_next_component(myical,
                ICAL_VEVENT_COMPONENT);

        icalproperty *prop = icalcomponent_get_first_property(comp,
                ICAL_RECURRENCEID_PROPERTY);
        if (!prop) continue;

        int is_recurid = !strcmpsafe(recurid,
                icalproperty_get_value_as_string(prop));

        if (is_recurid != want_recurid) {
            icalcomponent_remove_component(myical, comp);
            icalcomponent_free(comp);
        }
    }

    return myical;
}

static int setcalendarevents_destroy(jmap_req_t *req,
                                     struct mailbox *notifmbox,
                                     struct mailbox *schedinbox,
                                     struct jmap_caleventid *eid,
                                     struct caldav_db *db,
                                     int send_scheduling_messages)
{
    int r = 0;

    struct caldav_data *cdata = NULL;
    struct mailbox *mbox = NULL;
    char *mboxname = NULL;
    struct mboxevent *mboxevent = NULL;
    char *resource = NULL;

    icalcomponent *oldical = NULL;
    icalcomponent *newical = NULL;
    json_t *old_event = NULL;
    struct index_record record;
    strarray_t schedule_addresses = STRARRAY_INITIALIZER;
    mbentry_t *mbentry = NULL;

    // Determine if event is a standalone recurrence instance
    int is_standalone_instance = 0;
    if (eid->ical_recurid) {
        struct caldav_jscal_filter jscal_filter = CALDAV_JSCAL_FILTER_INITIALIZER;
        caldav_jscal_filter_by_ical_uid(&jscal_filter, eid->ical_uid, eid->ical_recurid);
        r = caldav_foreach_jscal(db, NULL, &jscal_filter, NULL, NULL, 0,
                updateevent_check_exists_cb, NULL);
        caldav_jscal_filter_fini(&jscal_filter);
        if (r && r != CYRUSDB_DONE) {
            goto done;
        }
        is_standalone_instance = r == CYRUSDB_DONE;
        if (!is_standalone_instance) {
            // if it isn't there must be a main event
            struct caldav_jscal_filter jscal_filter = CALDAV_JSCAL_FILTER_INITIALIZER;
            caldav_jscal_filter_by_ical_uid(&jscal_filter, eid->ical_uid, "");
            r = caldav_foreach_jscal(db, NULL, &jscal_filter, NULL, NULL, 0,
                    updateevent_check_exists_cb, NULL);
            caldav_jscal_filter_fini(&jscal_filter);
            if (r != CYRUSDB_DONE) {
                r = HTTP_NOT_FOUND;
                goto done;
            }
        }
        r = 0;
    }

    if (eid->ical_recurid && !is_standalone_instance) {
        /* Destroying a recurrence instance is setting it excluded */
        json_t *event_patch = json_pack("{s:b}", "excluded", 1);
        json_t *update = NULL;
        json_t *err = NULL;
        setcalendarevents_update(req, notifmbox, schedinbox, event_patch, eid, db,
                send_scheduling_messages, update, &err);
        json_decref(event_patch);
        json_decref(update);
        if (err) {
            r = IMAP_INTERNAL;
            json_decref(err);
        }
        return r;
    }

    /* Determine mailbox and resource name of calendar event. */
    r = caldav_lookup_uid(db, eid->ical_uid, &cdata);
    if (r) {
        syslog(LOG_ERR,
               "caldav_lookup_uid(%s) failed: %s", eid->ical_uid, cyrusdb_strerror(r));
        r = CYRUSDB_NOTFOUND ? IMAP_NOTFOUND : IMAP_INTERNAL;
        goto done;
    }

    mbentry = jmap_mbentry_from_dav(req, &cdata->dav);
    if (!mbentry) {
        xsyslog(LOG_WARNING, "no mbentry for mailbox",
                "dav.mailbox=<%s> dav.mailbox_byname=<%d>",
                cdata->dav.mailbox, cdata->dav.mailbox_byname);
        r = IMAP_NOTFOUND;
        goto done;
    }
    mboxname = xstrdup(mbentry->name);
    resource = xstrdup(cdata->dav.resource);

    if (mboxname_isdeletedmailbox(mbentry->name, NULL)) {
        xsyslog(LOG_ERR, "corrupt ical_objs table detected: "
                "mailbox is deleted, but ical_objs row exists",
                "mboxid=<%s> imap_uid=<%d>",
                mbentry->uniqueid, cdata->dav.imap_uid);
        r = IMAP_NOTFOUND;
        goto done;
    }

    const char *sched_userid = req->accountid;
    get_schedule_addresses(mboxname, sched_userid, &schedule_addresses);

    /* Check permissions. */
    if (!mbentry || !jmap_hasrights_mbentry(req, mbentry, JACL_READITEMS)) {
        r = IMAP_NOTFOUND;
        goto done;
    }
    if (!jmap_hasrights_mbentry(req, mbentry, JACL_REMOVEITEMS)) {
        if (!jmap_hasrights_mbentry(req, mbentry, JACL_WRITEOWN) ||
                (cdata->organizer &&
                 !strarray_contains(&schedule_addresses, cdata->organizer))) {
            r = IMAP_PERMISSION_DENIED;
            goto done;
        }
    }

    /* Check privacy for sharees */
    if (strcmp(req->accountid, req->userid)) {
        if (cdata->comp_flags.privacy != CAL_PRIVACY_PUBLIC) {
            r = cdata->comp_flags.privacy == CAL_PRIVACY_SECRET ?
                IMAP_NOTFOUND : IMAP_PERMISSION_DENIED;
            goto done;
        }
    }

    /* Open mailbox for writing */
    r = mailbox_open_iwl(mboxname, &mbox);
    if (r) goto done;

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

    if (is_standalone_instance) {
        // Read event from iCalendar data
        icalcomponent *myical = prune_vevent_instances(oldical,
                eid->ical_recurid, 1);
        struct jmapical_ctx *jmapctx = jmapical_context_new(req, &schedule_addresses);
        context_begin_cdata(jmapctx, mbentry, cdata);
        old_event = jmapical_tojmap(myical, NULL, jmapctx);
        jmapical_context_free(&jmapctx);
        newical = NULL;
        icalcomponent_free(myical);

        // Remove instance from iCalendar data
        myical = prune_vevent_instances(oldical, eid->ical_recurid, 0);
        if (!icalcomponent_get_first_real_component(myical)) {
            icalcomponent_free(myical);
            myical = NULL;
        }
        newical = myical;
    }
    else {
        struct jmapical_ctx *jmapctx = jmapical_context_new(req, &schedule_addresses);
        context_begin_cdata(jmapctx, mbentry, cdata);
        old_event = jmapical_tojmap(oldical, NULL, jmapctx);
        jmapical_context_free(&jmapctx);
        newical = NULL;
    }

    /* Handle scheduling. */
    if (!(record.system_flags & FLAG_DRAFT) && send_scheduling_messages) {
        r = setcalendarevents_schedule(sched_userid, &schedule_addresses,
                oldical, newical, JMAP_DESTROY);
        if (r) goto done;
    }

    /* Manage attachments */
    int ret = caldav_manage_attachments(req->accountid, newical, oldical);
    if (ret && ret != HTTP_NOT_FOUND) {
        syslog(LOG_ERR, "caldav_manage_attachments: %s", error_message(ret));
        r = IMAP_INTERNAL;
        goto done;
    }

    if (!newical) {
        /* Expunge the resource from mailbox. */
        record.internal_flags |= FLAG_INTERNAL_EXPUNGED;
        mboxevent = mboxevent_new(EVENT_MESSAGE_EXPUNGE);
        r = mailbox_rewrite_index_record(mbox, &record);
        if (r) {
            syslog(LOG_ERR, "mailbox_rewrite_index_record (%s) failed: %s",
                    cdata->dav.mailbox, error_message(r));
            mailbox_close(&mbox);
            goto done;
        }
    }
    else {
        /* Update resource */
        struct transaction_t txn = {
            .req_hdrs = spool_new_hdrcache(),
            .userid = req->userid,
            .authstate = req->authstate
        };
        r = caldav_store_resource(&txn, newical, mbox,
                resource, record.createdmodseq, db, PERMS_NOKEEP, req->userid,
                NULL, NULL, &schedule_addresses);
        transaction_free(&txn);
        if (r && r != HTTP_CREATED && r != HTTP_NO_CONTENT) {
            xsyslog(LOG_ERR, "caldav_store_resource", "err=<%s>",
                    error_message(r));
            goto done;
        }
        r = 0;
    }

    if (calendar_has_sharees(mbox->mbentry)) {
        /* Create notification */
        jmapical_remove_peruserprops(old_event);
        int r2 = jmap_create_caleventnotif(notifmbox, req->userid,
                req->authstate, mailbox_name(mbox), "destroyed",
                eid->ical_uid, &schedule_addresses, NULL,
                record.system_flags & FLAG_DRAFT, old_event, NULL);
        if (r2) {
            xsyslog(LOG_WARNING, "could not create notification",
                    "uid=%s error=%s", eid->ical_uid, error_message(r2));
        }
    }

    /* Create mboxevent */
    mboxevent_extract_record(mboxevent, mbox, &record);
    mboxevent_extract_mailbox(mboxevent, mbox);
    mboxevent_set_numunseen(mboxevent, mbox, -1);
    mboxevent_set_access(mboxevent, NULL, NULL,
                         req->userid, cdata->dav.mailbox, 0);
    mboxevent_notify(&mboxevent);
    mboxevent_free(&mboxevent);

    /* Remove related iTIP messages from CalDAV Scheduling Inbox */
    remove_itip_messages(db, schedinbox, eid->ical_uid,
                         is_standalone_instance ? eid->ical_recurid : NULL);

done:
    mailbox_close(&mbox);
    if (oldical) icalcomponent_free(oldical);
    if (newical) icalcomponent_free(newical);
    json_decref(old_event);
    strarray_fini(&schedule_addresses);
    free(resource);
    free(mboxname);
    mboxlist_entry_free(&mbentry);
    return r;
}

static struct jmap_caleventid *setcalendarevents_parse_id(jmap_req_t *req, const char *id)
{
    if (id && id[0] == '#') {
        const char *newid = jmap_lookup_id(req, id + 1);
        if (!newid) return NULL;
        id = newid;
    }
    return jmap_caleventid_decode(id);
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
    struct jmap_set set = JMAP_SET_INITIALIZER;
    json_t *err = NULL;
    struct caldav_db *db = NULL;
    struct jmap_caleventid *eid = NULL;
    const char *id;
    int r = 0;
    int send_itip = 1;
    struct mailbox *schedinbox = NULL;
    struct mailbox *notifmbox = NULL;
    mbentry_t *notifmb = NULL;

    /* Parse arguments */
    jmap_set_parse(req, &parser, event_props, setcalendarevents_parse_args,
                   &send_itip, &set, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    if (set.if_in_state) {
        if (atomodseq_t(set.if_in_state) != jmap_modseq(req, MBTYPE_CALENDAR, 0)) {
            jmap_error(req, json_pack("{s:s}", "type", "stateMismatch"));
            goto done;
        }
        set.old_state = xstrdup(set.if_in_state);
    }
    else {
        set.old_state = modseqtoa(jmap_modseq(req, MBTYPE_CALENDAR, 0));
    }

    r = caldav_create_defaultcalendars(req->accountid,
                                       &httpd_namespace, req->authstate, NULL);
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

    /* Open CalDAV Scheduling Inbox, but continue even on error. */
    char *inboxname = caldav_mboxname(req->accountid, SCHED_INBOX);
    r = mailbox_open_iwl(inboxname, &schedinbox);
    if (r) {
        xsyslog(LOG_WARNING, "can not open CalDAV Scheduling Inbox",
                "accountid=%s error=%s", req->accountid, error_message(r));
        r = 0;
    }
    free(inboxname);

    /* Open notifications mailbox, but continue even on error. */
    r = jmap_create_notify_collection(req->accountid, &notifmb);
    if (!r) r = mailbox_open_iwl(notifmb->name, &notifmbox);
    if (r) {
        xsyslog(LOG_WARNING, "can not open jmapnotify collection",
                "accountid=%s error=%s", req->accountid, error_message(r));
        r = 0;
    }

    /* destroy */
    size_t index;
    json_t *juid;

    json_array_foreach(set.destroy, index, juid) {
        jmap_caleventid_free(&eid);

        const char *id = json_string_value(juid);
        if (!id) continue;

        eid = setcalendarevents_parse_id(req, id);
        if (!eid) {
            json_object_set_new(set.not_destroyed, id,
                    json_pack("{s:s}", "type", "notFound"));
            continue;
        }

        /* Destroy the calendar event. */
        r = setcalendarevents_destroy(req, notifmbox, schedinbox, eid, db, send_itip);
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
    jmap_caleventid_free(&eid);



    /* create */
    const char *key;
    json_t *arg;
    json_object_foreach(set.create, key, arg) {
        /* Validate calendar event id. */
        if (!strlen(key)) {
            json_t *err = json_pack("{s:s}", "type", "invalidArguments");
            json_object_set_new(set.not_created, key, err);
            continue;
        }

        json_t *create = json_object();
        json_t *err = NULL;
        setcalendarevents_create(req, arg, db, notifmbox, send_itip, create, &err);
        if (err) {
            json_object_set_new(set.not_created, key, err);
        }
        else {
            const char *id = json_string_value(json_object_get(create, "id"));
            json_object_set(set.created, key, create);
            jmap_add_id(req, key, id);
        }
        json_decref(create);
    }

    /* update */
    json_object_foreach(set.update, id, arg) {
        jmap_caleventid_free(&eid);

        eid = setcalendarevents_parse_id(req, id);
        if (!eid) {
            json_object_set_new(set.not_updated, id,
                    json_pack("{s:s}", "type", "notFound"));
            continue;
        }

        const char *uidval = NULL;
        if ((uidval = json_string_value(json_object_get(arg, "uid")))) {
            /* The uid property must match the current iCalendar UID */
            if (strcmp(uidval, eid->ical_uid)) {
                json_t *err = json_pack(
                    "{s:s, s:o}",
                    "type", "invalidProperties",
                    "properties", json_pack("[s]"));
                json_object_set_new(set.not_updated, eid->raw, err);
                continue;
            }
        }

        /* Update the calendar event. */
        json_t *update = json_object();
        json_t *err = NULL;
        setcalendarevents_update(req, notifmbox, schedinbox, arg, eid, db,
                send_itip, update, &err);
        if (err) {
            json_object_set_new(set.not_updated, eid->raw, err);
            json_decref(update);
            r = 0;
            continue;
        }

        if (!json_object_size(update)) {
            json_decref(update);
            update = json_null();
        }

        /* Report calendar event as updated. */
        json_object_set_new(set.updated, eid->raw, update);
    }
    jmap_caleventid_free(&eid);


    set.new_state = modseqtoa(jmap_modseq(req, MBTYPE_CALENDAR, JMAP_MODSEQ_RELOAD));

    jmap_ok(req, jmap_set_reply(&set));

done:
    mailbox_close(&schedinbox);
    mailbox_close(&notifmbox);
    mboxlist_entry_free(&notifmb);
    jmap_parser_fini(&parser);
    jmap_set_fini(&set);
    if (db) caldav_close(db);
    jmap_caleventid_free(&eid);
    return r;
}

struct geteventchanges_rock {
    jmap_req_t *req;
    struct jmap_changes *changes;
    size_t seen_records;
    modseq_t highestmodseq;
    int check_acl;
    hash_table *mboxrights;
    int is_sharee;
    struct buf buf;
};

static void strip_spurious_changes(struct geteventchanges_rock *urock)
{
    /* if something is mentioned in both DELETEs and UPDATEs, or
     * both CREATEs and DESTROYs, it's probably a move.
     * O(N*M) algorithm, but there are rarely many, and the alternative
     * of a hash will cost more */
    unsigned i, j;

    for (i = 0; i < json_array_size(urock->changes->destroyed); i++) {
        const char *del = json_string_value(json_array_get(urock->changes->destroyed, i));

        for (j = 0; j < json_array_size(urock->changes->created); j++) {
            const char *cr =
                json_string_value(json_array_get(urock->changes->created, j));
            if (!strcmpsafe(del, cr)) {
                json_array_append_new(urock->changes->updated, json_string(del));
                json_array_remove(urock->changes->destroyed, i--);
                json_array_remove(urock->changes->created, j--);
                break;
            }
        }
    }

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

static int geteventchanges_cb(void *vrock, struct caldav_jscal *jscal)
{
    struct geteventchanges_rock *rock = vrock;
    jmap_req_t *req = rock->req;
    struct jmap_changes *changes = rock->changes;

    mbentry_t *mbentry = jmap_mbentry_from_dav(req, &jscal->cdata.dav);
    if (!mbentry)
        goto done;

    /* Check permissions */
    int rights = jmap_hasrights_mbentry(req, mbentry, JACL_READITEMS);
    if (!rights)
        goto done;

    if (mbtype_isa(mbentry->mbtype) != MBTYPE_CALENDAR)
        goto done;

    // check privacy
    if (rock->is_sharee && jscal->cdata.comp_flags.privacy == CAL_PRIVACY_SECRET)
        goto done;

    if (jscal->cdata.comp_type != CAL_COMP_VEVENT)
        goto done;

    /* Count, but don't process items that exceed the maximum record count. */
    if (changes->max_changes && ++(rock->seen_records) > changes->max_changes) {
        changes->has_more_changes = 1;
        goto done;
    }

    struct jmap_caleventid eid = {
        .ical_uid = jscal->cdata.ical_uid,
        .ical_recurid = jscal->ical_recurid
    };
    const char *id = jmap_caleventid_encode(&eid, &rock->buf);

    /* Report item as updated or destroyed. */
    if (jscal->alive) {
        if (jscal->createdmodseq <= changes->since_modseq)
            json_array_append_new(changes->updated, json_string(id));
        else
            json_array_append_new(changes->created, json_string(id));
    } else {
        if (jscal->createdmodseq <= changes->since_modseq)
            json_array_append_new(changes->destroyed, json_string(id));
    }

    if (jscal->modseq > rock->highestmodseq) {
        rock->highestmodseq = jscal->modseq;
    }

done:
    mboxlist_entry_free(&mbentry);
    return 0;
}

static int jmap_calendarevent_changes(struct jmap_req *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_changes changes = JMAP_CHANGES_INITIALIZER;
    json_t *err = NULL;
    struct caldav_db *db;
    struct geteventchanges_rock rock = {
        .req = req,
        .changes = &changes,
        .check_acl = strcmp(req->accountid, req->userid),
        .is_sharee = strcmp(req->accountid, req->userid),
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
    struct caldav_jscal_window jscal_window = {
        .aftermodseq = changes.since_modseq,
        .maxcount = changes.max_changes ? changes.max_changes + 1 : 0,
        .tombstones = 1,
    };
    enum caldav_sort sort[] = { CAL_SORT_MODSEQ };
    r = caldav_foreach_jscal(db, NULL, NULL, &jscal_window, sort, 1,
            geteventchanges_cb, &rock);
    if (r) goto done;
    strip_spurious_changes(&rock);

    /* Determine new state. */
    changes.new_modseq = changes.has_more_changes ?
        rock.highestmodseq : jmap_modseq(req, MBTYPE_CALENDAR, 0);

    /* Build response */
    jmap_ok(req, jmap_changes_reply(&changes));

  done:
    jmap_changes_fini(&changes);
    jmap_parser_fini(&parser);
    if (rock.mboxrights) {
        free_hash_table(rock.mboxrights, free);
        free(rock.mboxrights);
    }
    buf_free(&rock.buf);
    if (db) caldav_close(db);
    if (r) {
        jmap_error(req, jmap_server_error(r));
    }
    return 0;
}

static inline time_t eventquery_read_datetime(const char *val,
                                              icaltimezone *zone,
                                              time_t defaultval)
{
    struct jmapical_datetime dt = JMAPICAL_DATETIME_INITIALIZER;
    if (val && jmapical_localdatetime_from_string(val, &dt) >= 0) {
        icaltimetype icaldt = jmapical_datetime_to_icaltime(&dt, zone);
        return icaltime_as_timet_with_zone(icaldt, zone);
    }
    else return defaultval;
}

struct eventquery_args {
    int expandrecur;
    icaltimezone *zone;
};

static void eventquery_read_timerange(json_t *filter,
                                      struct eventquery_args args,
                                      time_t *before, time_t *after)
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

            eventquery_read_timerange(val, args, &bf, &af);

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
        const char *s = json_string_value(json_object_get(filter, "before"));
        *before = eventquery_read_datetime(s, args.zone, caldav_eternity);

        s = json_string_value(json_object_get(filter, "after"));
        *after = eventquery_read_datetime(s, args.zone, caldav_epoch);
    }
}

struct eventquery_match {
    char *ical_uid;
    char *utcstart;
    icalcomponent *ical;
    char *ical_recurid;
};

static void eventquery_match_fini(struct eventquery_match *match)
{
    if (!match) return;
    free(match->ical_uid);
    free(match->utcstart);
    free(match->ical_recurid);
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
            case CAL_SORT_ICAL_UID:
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
    int is_sharee;
};

static int eventquery_cb(void *vrock, struct caldav_jscal *jscal)
{
    struct eventquery_rock *rock = vrock;
    jmap_req_t *req = rock->req;
    int r = 0;

    if (!jscal->cdata.dav.alive || jscal->cdata.comp_type != CAL_COMP_VEVENT) {
        return 0;
    }

    if (rock->is_sharee && jscal->cdata.comp_flags.privacy == CAL_PRIVACY_SECRET)
        return 0;

    mbentry_t *mbentry = jmap_mbentry_from_dav(req, &jscal->cdata.dav);
    if (!mbentry)
        goto done;

    /* Check permissions */
    int rights = jmap_hasrights_mbentry(req, mbentry, JACL_READITEMS);
    if (!rights) goto done;

    struct eventquery_match *match = xzmalloc(sizeof(struct eventquery_match));
    match->ical_uid = xstrdup(jscal->cdata.ical_uid);
    match->utcstart = xstrdup(jscal->dtstart);
    if (jscal->ical_recurid[0]) {
        match->ical_recurid = xstrdup(jscal->ical_recurid);
    }
    else if (rock->expandrecur) {
        /* Load iCalendar data for main event */
        if (!rock->mailbox || strcmp(mailbox_name(rock->mailbox), mbentry->name)) {
            mailbox_close(&rock->mailbox);
            r = mailbox_open_irl(mbentry->name, &rock->mailbox);
            if (r) {
                syslog(LOG_ERR, "%s: can't open mailbox %s",
                       __func__, mbentry->name);
                eventquery_match_free(&match);
                goto done;
            }
        }
        match->ical = caldav_record_to_ical(rock->mailbox, &jscal->cdata, req->userid, NULL);
        if (!match->ical) {
            syslog(LOG_ERR, "%s: can't load ical for ical uid %s",
                    __func__, jscal->cdata.ical_uid);
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

struct eventquery_textsearch_cb_rock {
    jmap_req_t *req;
    const char *icalbefore;
    const char *icalafter;
    ptrarray_t *matches;
    int expandrecur;
    struct mailbox *mailbox;
    int is_sharee;
};

static int eventquery_textsearch_cb(void *vrock, struct caldav_jscal *jscal)
{
    struct eventquery_textsearch_cb_rock *rock = vrock;

    // Check privacy
    if (rock->is_sharee && jscal->cdata.comp_flags.privacy == CAL_PRIVACY_SECRET)
        return 0;

    /* Check time-range */
    if (rock->icalafter && strcmp(jscal->dtend, rock->icalafter) <= 0)
        return 0;
    if (rock->icalbefore && strcmp(jscal->dtstart, rock->icalbefore) >= 0)
        return 0;

    struct eventquery_match *match = xzmalloc(sizeof(struct eventquery_match));
    match->ical_uid = xstrdup(jscal->cdata.ical_uid);
    match->utcstart = xstrdup(jscal->dtstart);
    if (jscal->ical_recurid[0]) {
        match->ical_recurid = xstrdup(jscal->ical_recurid);
    }
    else if (rock->expandrecur) {
        /* Load iCalendar data */
        match->ical = caldav_record_to_ical(rock->mailbox,
                &jscal->cdata, rock->req->userid, NULL);
        if (!match->ical) {
            xsyslog(LOG_ERR, "can't load ical", "ical_uid=<%s>",
                    jscal->cdata.ical_uid);
            free(match->ical_uid);
            free(match->utcstart);
            free(match);
            return IMAP_INTERNAL;
        }
    }
    ptrarray_append(rock->matches, match);

    return 0;
}

static int eventquery_textsearch_run(jmap_req_t *req,
                                 json_t *filter,
                                 struct caldav_db *db,
                                 time_t before, time_t after,
                                 enum caldav_sort *sort,
                                 size_t nsort,
                                 int expandrecur,
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
    int is_sharee = strcmp(req->accountid, req->userid);
    char *sched_inboxname = caldav_mboxname(req->accountid, SCHED_INBOX);

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
        mbentry_t *mbentry = NULL;

        if (!folder) continue;

        mboxlist_lookup_allow_all(folder->mboxname, &mbentry, NULL);

        /* Check permissions */
        if (!mbentry || !jmap_hasrights_mbentry(req, mbentry, JACL_READITEMS)) {
            mboxlist_entry_free(&mbentry);
            continue;
        }

        /* don't include the scheduling magic calendars */
        if (!strcmpsafe(mbentry->name, sched_inboxname)) {
            mboxlist_entry_free(&mbentry);
            continue;
        }

        if (expandrecur) {
            if (!mailbox || strcmp(mailbox_name(mailbox), mbentry->name)) {
                mailbox_close(&mailbox);
                r = mailbox_open_irl(mbentry->name, &mailbox);
                if (r) goto done;
            }
        }

        /* Fetch the CalDAV db records */ // XXX use linear scan for all MsgData
        struct caldav_jscal_filter jscal_filter = CALDAV_JSCAL_FILTER_INITIALIZER;
        if (wantuid) caldav_jscal_filter_by_ical_uid(&jscal_filter, wantuid, NULL);
        caldav_jscal_filter_by_imap_uid(&jscal_filter, md->uid);
        caldav_jscal_filter_by_mbentrym(&jscal_filter, mbentry);

        struct eventquery_textsearch_cb_rock rock = {
            req, icalbefore, icalafter, matches, expandrecur, mailbox, is_sharee
        };
        caldav_foreach_jscal(db, NULL, &jscal_filter, NULL, NULL, 0,
                eventquery_textsearch_cb, &rock);

        caldav_jscal_filter_fini(&jscal_filter);
        if (r) goto done;
    }

    if (!expandrecur && matches->count) {
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
    mailbox_close(&mailbox);
    free(sched_inboxname);
    free(icalbefore);
    free(icalafter);
    buf_free(&buf);
    return r;
}

struct eventquery_fastpath_rock {
    jmap_req_t *req;
    struct jmap_query *query;
    int is_sharee;
    struct buf buf;
};

static int eventquery_fastpath_cb(void *vrock, struct caldav_jscal *jscal)
{
    struct eventquery_fastpath_rock *rock = vrock;
    jmap_req_t *req = rock->req;
    struct jmap_query *query = rock->query;
    mbentry_t *mbentry = NULL;
    struct buf *buf = &rock->buf;

    assert(query->position >= 0);

    /* Check type and permissions */
    if (!jscal->alive || jscal->cdata.comp_type != CAL_COMP_VEVENT)
        goto done;

    mbentry = jmap_mbentry_from_dav(req, &jscal->cdata.dav);
    if (!mbentry) goto done;

    if (mboxname_isdeletedmailbox(mbentry->name, NULL)) {
        xsyslog(LOG_ERR, "corrupt ical_objs table detected: "
                "mailbox is deleted, but ical_objs row exists",
                "mboxid=<%s> imap_uid=<%d>",
                mbentry->uniqueid, jscal->cdata.dav.imap_uid);
        goto done;
    }

    /* Check permissions */
    int rights = jmap_hasrights_mbentry(req, mbentry, JACL_READITEMS);
    if (!rights) goto done;

    // Check privacy
    if (rock->is_sharee &&
            jscal->cdata.comp_flags.privacy == CAL_PRIVACY_SECRET)
        goto done;

    query->total++;

    /* Check search window */
    if (query->have_limit && json_array_size(query->ids) >= query->limit)
        goto done;

    if ((size_t)query->position > query->total - 1)
        goto done;

    struct jmap_caleventid eid = {
        .ical_uid =jscal->cdata.ical_uid,
        .ical_recurid = jscal->ical_recurid,
    };
    const char *id = jmap_caleventid_encode(&eid, buf);
    json_array_append_new(query->ids, json_string(id));

done:
    mboxlist_entry_free(&mbentry);
    return 0;
}

struct eventquery_recur_rock {
    ptrarray_t *matches;
    struct buf *buf;
    icaltimetype lastseen;
    icaltimezone *utc;
};

static int eventquery_recur_cb(icalcomponent *comp,
                               icaltimetype start,
                               icaltimetype end __attribute__((unused)),
                               icaltimetype recurid __attribute__((unused)),
                               int is_standalone __attribute__((unused)),
                               void *vrock)
{
    struct eventquery_recur_rock *rock = vrock;

    if (icaltime_compare(rock->lastseen, start)) {
        icaltimetype utcstart = icaltime_convert_to_zone(start, rock->utc);

        icalproperty *prop =
            icalcomponent_get_first_property(comp, ICAL_RECURRENCEID_PROPERTY);
        icaltimetype recurid = prop ?
            icalproperty_get_recurrenceid(prop) : start;

        struct eventquery_match *match = xzmalloc(sizeof(struct eventquery_match));
        match->ical_uid = xstrdup(icalcomponent_get_uid(comp));
        match->utcstart = xstrdup(icaltime_as_ical_string(utcstart));
        match->ical_recurid = xstrdup(icaltime_as_ical_string(recurid));
        ptrarray_append(rock->matches, match);
    }
    rock->lastseen = start;

    return 1;
}

#define JMAPICAL_EVENTQUERY_ARGS_INITIALIZER { \
    0, icaltimezone_get_utc_timezone() \
}

static int _calendarevent_queryargs_parse(jmap_req_t *req __attribute__((unused)),
                                          struct jmap_parser *parser __attribute__((unused)),
                                          const char *argname,
                                          json_t *argval,
                                          void *rock)
{
    struct eventquery_args *args = rock;
    int r = 0;

    if (!strcmp(argname, "expandRecurrences")) {
        if (json_is_boolean(argval)) {
            args->expandrecur = json_boolean_value(argval);
        }
        else jmap_parser_invalid(parser, argname);
        r = 1;
    }
    else if (!strcmp(argname, "timeZone")) {
        if (json_is_string(argval)) {
            args->zone = jstimezones_lookup_tzid(NULL, json_string_value(argval));
        }
        if (!args->zone)
            jmap_parser_invalid(parser, argname);
        r = 1;
    }

    return r;
}

static struct caldav_jscal_filter *build_jscal_filter(jmap_req_t *req,
                                                      json_t *jfilter,
                                                      struct eventquery_args *args,
                                                      int *needs_xapian)
{
    struct caldav_jscal_filter *filter = caldav_jscal_filter_new();
    const char *s;

    if (json_array_size(json_object_get(jfilter, "inCalendars"))) {
        size_t i;
        json_t *jval;
        json_array_foreach(json_object_get(jfilter, "inCalendars"), i, jval) {
            const char *id = json_string_value(jval);
            char *mboxname = caldav_mboxname(req->accountid, id);
            mbentry_t *mbentry = NULL;

            int r = mboxlist_lookup(mboxname, &mbentry, NULL);
            if (!r && jmap_hasrights_mbentry(req, mbentry, JACL_READITEMS)) {
                caldav_jscal_filter_by_mbentrym(filter, mbentry);
            }
            else if (r != IMAP_MAILBOX_NONEXISTENT) {
                xsyslog(LOG_WARNING, "could not lookup calendar",
                        "calendarId=<%s> err=<%s>", id, error_message(r));
            }

            free(mboxname);
        }

        if (!ptrarray_size(&filter->mbentries))
            filter->op = CALDAV_JSCAL_FALSE;
    }

    // Return early for trivial expressions
    if (filter->op == CALDAV_JSCAL_FALSE) {
        return filter;
    }

    s = json_string_value(json_object_get(jfilter, "uid"));
    if (s)
        caldav_jscal_filter_by_ical_uid(filter, s, NULL);

    s = json_string_value(json_object_get(jfilter, "before"));
    if (s) {
        time_t t = eventquery_read_datetime(s, args->zone, caldav_eternity);
        if (t != caldav_eternity)
            caldav_jscal_filter_by_before(filter, &t);
    }

    s = json_string_value(json_object_get(jfilter, "after"));
    if (s) {
        time_t t = eventquery_read_datetime(s, args->zone, caldav_epoch);
        if (t != caldav_epoch)
            caldav_jscal_filter_by_after(filter, &t);
    }

    s = json_string_value(json_object_get(jfilter, "operator"));
    if (s) {
        filter->op = CALDAV_JSCAL_NOOP;
        if (!strcasecmp(s, "AND"))
            filter->op = CALDAV_JSCAL_AND;
        else if (!strcasecmp(s, "OR"))
            filter->op = CALDAV_JSCAL_OR;
        else if (!strcasecmp(s, "NOT"))
            filter->op = CALDAV_JSCAL_NOT;

        if (filter->op != CALDAV_JSCAL_NOOP) {
            size_t i;
            json_t *jsub;
            json_array_foreach(json_object_get(jfilter, "conditions"), i, jsub) {

                // Special-handle OR(uid, uid, ...)
                if (filter->op == CALDAV_JSCAL_OR &&
                    json_object_size(jfilter) == 2 && // "operator", "conditions"
                    json_object_size(jsub) == 1 &&   // "uid"
                    (s = json_string_value(json_object_get(jsub, "uid")))) {

                    caldav_jscal_filter_by_ical_uid(filter, s, NULL);
                }
                else {
                    ptrarray_append(&filter->subfilters,
                            build_jscal_filter(req, jsub, args, needs_xapian));
                }
            }
        }
    }

    if (json_object_get(jfilter, "text") ||
        json_object_get(jfilter, "title") ||
        json_object_get(jfilter, "description") ||
        json_object_get(jfilter, "location") ||
        json_object_get(jfilter, "owner") ||
        json_object_get(jfilter, "attendee")) {
        *needs_xapian = 1;
    }

    return filter;
}

static int eventquery_run(jmap_req_t *req,
                          struct jmap_query *query,
                          struct eventquery_args args,
                          json_t **debug,
                          json_t **err)
{
    time_t before = caldav_eternity;
    time_t after = caldav_epoch;
    int r = 0, r_db = 0;
    enum caldav_sort *sort = NULL;
    struct buf buf = BUF_INITIALIZER;
    size_t nsort = 0;
    int is_sharee = strcmp(req->accountid, req->userid);
    struct caldav_jscal_filter *jscal_filter = NULL;
    int is_fastpath = 0;

    /* Sanity check arguments */
    eventquery_read_timerange(query->filter, args, &before, &after);
    if (args.expandrecur && before == caldav_eternity) {
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
                sort[i] = CAL_SORT_ICAL_UID;
            else
                sort[i] = CAL_SORT_NONE;
            if (json_object_get(jval, "isAscending") == json_false()) {
                sort[i] |= CAL_SORT_DESC;
            }
        }
    }

    int needs_xapian = 0;
    jscal_filter = build_jscal_filter(req, query->filter, &args, &needs_xapian);

    /* Attempt to fast-path trivial query */
    if (!needs_xapian && !args.expandrecur && query->position >= 0 && !query->anchor) {
        struct eventquery_fastpath_rock rock = {
            req, query, is_sharee, BUF_INITIALIZER
        };
        r_db = caldav_foreach_jscal(db, req->userid, jscal_filter, NULL,
                sort, nsort, eventquery_fastpath_cb, &rock);
        buf_free(&rock.buf);
        is_fastpath = 1;
        goto done;
    }

    /* Handle non-trivial query */
    if (needs_xapian) {
        /* Query and sort matches in search backend. */
        r = eventquery_textsearch_run(req, query->filter, db, before, after,
                sort, nsort, args.expandrecur,&matches);
        if (r) goto done;
    }
    else {
        /* Query and sort matches in Caldav DB. */
        struct eventquery_rock rock = {
            req, args.expandrecur, NULL, &matches, is_sharee
        };

        enum caldav_sort mboxsort = CAL_SORT_MAILBOX;
        r_db = caldav_foreach_jscal(db, req->userid, jscal_filter, NULL,
                                     args.expandrecur ? &mboxsort : sort,
                                     args.expandrecur ? 1 : nsort,
                                     eventquery_cb, &rock);
        mailbox_close(&rock.mailbox);
        if (r_db) goto done;
    }

    if (args.expandrecur) {
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
                    &mymatches, &buf, icaltime_null_time(),
                    icaltimezone_get_utc_timezone(),
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
            struct jmap_caleventid eid = {
                .ical_uid = m->ical_uid,
                .ical_recurid = m->ical_recurid
            };
            jmap_caleventid_encode(&eid, &buf);
            if (!strcmp(query->anchor, buf_cstring(&buf))) {
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
            buf_reset(&buf);
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
    for (i = startpos; i < (size_t) ptrarray_size(&matches); i++) {
        if (query->have_limit && json_array_size(query->ids) >= query->limit) {
            break;
        }
        struct eventquery_match *match = ptrarray_nth(&matches, i);
        struct jmap_caleventid eid = {
            .ical_uid = match->ical_uid,
            .ical_recurid = match->ical_recurid,
        };
        json_array_append_new(query->ids,
                json_string(jmap_caleventid_encode(&eid, &buf)));
    }

done:
    if (r_db == SQLDB_ERR_LIMIT && !*err) {
        *err = json_pack("{s:s}", "type", "unsupportedFilter");
    }
    else if (r_db) {
        r = HTTP_SERVER_ERROR;
    }
    if (jmap_is_using(req, JMAP_DEBUG_EXTENSION) && !*err) {
        *debug = json_pack("{s:b}", "isFastPath", is_fastpath);
    }
    if (db) caldav_close(db);
    if (ptrarray_size(&matches)) {
        int j;
        for (j = 0; j < ptrarray_size(&matches); j++) {
            struct eventquery_match *match = ptrarray_nth(&matches, j);
            eventquery_match_free(&match);
        }
    }
    ptrarray_fini(&matches);
    caldav_jscal_filter_fini(jscal_filter);
    free(jscal_filter);
    buf_free(&buf);
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
                struct jmapical_datetime dt = JMAPICAL_DATETIME_INITIALIZER;
                if (jmapical_localdatetime_from_string(s, &dt) < 0) {
                    jmap_parser_invalid(parser, field);
                }
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

static int jmap_calendarevent_query(struct jmap_req *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_query query = JMAP_QUERY_INITIALIZER;
    struct eventquery_args args = JMAPICAL_EVENTQUERY_ARGS_INITIALIZER;

    /* Parse request */
    json_t *err = NULL;
    jmap_query_parse(req, &parser,
                     _calendarevent_queryargs_parse, &args,
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

    json_t *debug = NULL;
    int r = eventquery_run(req, &query, args, &debug, &err);
    if (r || err) {
        if (!err) err = jmap_server_error(r);
        jmap_error(req, err);
        goto done;
    }

    /* Build response */
    query.query_state = modseqtoa(jmap_modseq(req, MBTYPE_CALENDAR, 0));

    json_t *res = jmap_query_reply(&query);
    if (debug) {
        json_object_set_new(res, "debug", debug);
    }
    jmap_ok(req, res);

done:
    jmap_query_fini(&query);
    jmap_parser_fini(&parser);
    return 0;
}

static void _calendarevent_copy(jmap_req_t *req,
                                struct jmap_copy *copy,
                                struct mailbox *notifmbox,
                                json_t *jevent,
                                struct caldav_db *src_db,
                                struct caldav_db *dst_db,
                                json_t **new_event,
                                json_t **set_err)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    icalcomponent *src_ical = NULL;
    json_t *dst_event = NULL;
    struct mailbox *src_mbox = NULL;
    strarray_t schedule_addresses = STRARRAY_INITIALIZER;
    mbentry_t *mbentry = NULL;
    int r = 0;

    /* Read mandatory properties */
    const char *src_id = json_string_value(json_object_get(jevent, "id"));
    if (!src_id) {
        jmap_parser_invalid(&parser, "id");
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
        jmap_parser_invalid(&parser, "calendarIds");
    }
    if (json_array_size(parser.invalid)) {
        *set_err = json_pack("{s:s s:O}", "type", "invalidProperties",
                                          "properties", parser.invalid);
        goto done;
    }

    /* Lookup event */
    struct jmap_caleventid *eid = jmap_caleventid_decode(src_id);
    struct caldav_data *cdata = NULL;
    r = caldav_lookup_uid(src_db, eid->ical_uid, &cdata);
    jmap_caleventid_free(&eid);
    if (r && r != CYRUSDB_NOTFOUND) {
        syslog(LOG_ERR, "caldav_lookup_uid(%s) failed: %s", src_id, error_message(r));
        goto done;
    }
    if (r == CYRUSDB_NOTFOUND || !cdata->dav.alive || !cdata->dav.rowid ||
            !cdata->dav.imap_uid || cdata->comp_type != CAL_COMP_VEVENT) {
        *set_err = json_pack("{s:s}", "type", "notFound");
        goto done;
    }

    /* Check privacy */
    if (cdata->comp_flags.privacy != CAL_PRIVACY_PUBLIC) {
        if (strcmp(copy->from_account_id, req->userid)) {
            // can't copy a non-public shared event anywhere
            *set_err = json_pack("{s:s}", "type",
                    cdata->comp_flags.privacy == CAL_PRIVACY_SECRET ?
                    "notFound" : "forbidden");
        }
        else {
            // may copy own event anywhere if made public
            const char *new_privacy =
                json_string_value(json_object_get(jevent, "privacy"));
            if (strcmpsafe(new_privacy, "public")) {
                *set_err = json_pack("{s:s s:[s]}",
                        "type", "invalidProperties",
                        "properties", "privacy");
            }
        }
        if (*set_err) goto done;
    }

    mbentry = jmap_mbentry_from_dav(req, &cdata->dav);
    if (!mbentry || !jmap_hasrights_mbentry(req, mbentry, JACL_READITEMS)) {
        *set_err = json_pack("{s:s}", "type", "notFound");
        goto done;
    }

    if (mboxname_isdeletedmailbox(mbentry->name, NULL)) {
        xsyslog(LOG_ERR, "corrupt ical_objs table detected: "
                "mailbox is deleted, but ical_objs row exists",
                "mboxid=<%s> imap_uid=<%d>",
                mbentry->uniqueid, cdata->dav.imap_uid);
        r = CYRUSDB_NOTFOUND;
        goto done;
    }

    /* Read source event */
    r = mailbox_open_irl(mbentry->name, &src_mbox);
    if (r) goto done;
    src_ical = caldav_record_to_ical(src_mbox, cdata, req->userid, &schedule_addresses);
    if (!src_ical) {
        syslog(LOG_ERR, "calendarevent_copy: can't convert %s to JMAP", src_id);
        r = IMAP_INTERNAL;
        goto done;
    }

    /* Patch JMAP event */
    struct jmapical_ctx *jmapctx = jmapical_context_new(req, &schedule_addresses);
    jmapctx->to_ical.no_sanitize_timestamps = 1;
    context_begin_cdata(jmapctx, mbentry, cdata);
    json_t *src_event = jmapical_tojmap(src_ical, NULL, jmapctx);
    if (src_event) {
        dst_event = jmap_patchobject_apply(src_event, jevent, NULL, 0);
    }
    json_decref(src_event);
    if (!dst_event) {
        syslog(LOG_ERR, "calendarevent_copy: can't convert to ical: %s", src_id);
        r = IMAP_INTERNAL;
        goto done;
    }
    jmapical_context_free(&jmapctx);

    /* Create event */
    *new_event = json_object();
    setcalendarevents_create(req, dst_event, dst_db, notifmbox, 0,
            *new_event, set_err);
    if (*set_err) goto done;

done:
    if (r && *set_err == NULL) {
        if (r == CYRUSDB_NOTFOUND)
            *set_err = json_pack("{s:s}", "type", "notFound");
        else
            *set_err = jmap_server_error(r);
        return;
    }
    mboxlist_entry_free(&mbentry);
    mailbox_close(&src_mbox);
    strarray_fini(&schedule_addresses);
    if (src_ical) icalcomponent_free(src_ical);
    json_decref(dst_event);
    jmap_parser_fini(&parser);
}

static int jmap_calendarevent_copy(struct jmap_req *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_copy copy = JMAP_COPY_INITIALIZER;
    json_t *err = NULL;
    struct caldav_db *src_db = NULL;
    struct caldav_db *dst_db = NULL;
    json_t *destroy_events = json_array();
    struct mailbox *notifmbox = NULL;
    mbentry_t *notifmb = NULL;
    struct mboxlock *srcnamespacelock = NULL;
    struct mboxlock *dstnamespacelock = NULL;
    char *srcinbox = NULL;
    char *dstinbox = NULL;

    /* Parse request */
    jmap_copy_parse(req, &parser, NULL, NULL, &copy, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    srcinbox = mboxname_user_mbox(copy.from_account_id, NULL);
    dstinbox = mboxname_user_mbox(req->accountid, NULL);
    if (strcmp(srcinbox, dstinbox) < 0) {
        srcnamespacelock = mboxname_usernamespacelock(srcinbox);
        dstnamespacelock = mboxname_usernamespacelock(dstinbox);
    }
    else {
        dstnamespacelock = mboxname_usernamespacelock(dstinbox);
        srcnamespacelock = mboxname_usernamespacelock(srcinbox);
    }

    if (copy.if_from_in_state) {
        struct mboxname_counters counters;
        assert (!mboxname_read_counters(srcinbox, &counters));
        if (atomodseq_t(copy.if_from_in_state) != counters.caldavmodseq) {
            jmap_error(req, json_pack("{s:s}", "type", "stateMismatch"));
            goto done;
        }
    }

    if (copy.if_in_state) {
        if (atomodseq_t(copy.if_in_state) != jmap_modseq(req, MBTYPE_CALENDAR, 0)) {
            jmap_error(req, json_pack("{s:s}", "type", "stateMismatch"));
            goto done;
        }
        copy.old_state = xstrdup(copy.if_in_state);
    }
    else {
        copy.old_state = modseqtoa(jmap_modseq(req, MBTYPE_CALENDAR, 0));
    }

    // now we can open the cstate
    int r = conversations_open_user(req->accountid, 0, &req->cstate);
    if (r) {
        syslog(LOG_ERR, "jmap_email_copy: can't open converstaions: %s",
                        error_message(r));
        jmap_error(req, jmap_server_error(r));
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
    r = jmap_create_notify_collection(req->accountid, &notifmb);
    if (!r) r = mailbox_open_iwl(notifmb->name, &notifmbox);
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

        _calendarevent_copy(req, &copy, notifmbox, jevent, src_db, dst_db,
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
    copy.new_state = modseqtoa(jmap_modseq(req, MBTYPE_CALENDAR, JMAP_MODSEQ_RELOAD));
    jmap_ok(req, jmap_copy_reply(&copy));

    /* Destroy originals, if requested */
    if (copy.on_success_destroy_original && json_array_size(destroy_events)) {
        json_t *subargs = json_object();
        json_object_set(subargs, "destroy", destroy_events);
        json_object_set_new(subargs, "accountId", json_string(copy.from_account_id));
        if (copy.destroy_from_if_in_state) {
            json_object_set_new(subargs, "ifInState",
                                json_string(copy.destroy_from_if_in_state));
        }
        jmap_add_subreq(req, "CalendarEvent/set", subargs, NULL);
    }

done:
    mailbox_close(&notifmbox);
    mboxlist_entry_free(&notifmb);
    json_decref(destroy_events);
    if (src_db) caldav_close(src_db);
    if (dst_db) caldav_close(dst_db);
    mboxname_release(&srcnamespacelock);
    mboxname_release(&dstnamespacelock);
    jmap_parser_fini(&parser);
    jmap_copy_fini(&copy);
    free(srcinbox);
    free(dstinbox);
    return 0;
}

struct calendareventparse_args {
    hash_table *props;
    int repair_broken_ical;
};

static int _calendareventparse_args_parse(jmap_req_t *req,
                                          struct jmap_parser *parser,
                                          const char *key,
                                          json_t *arg,
                                          void *rock)
{
    struct calendareventparse_args *parseargs = rock;

    if (!strcmp(key, "properties")) {
        if (json_is_array(arg)) {
            size_t i;
            json_t *val;

            parseargs->props = xzmalloc(sizeof(hash_table));
            construct_hash_table(parseargs->props, json_array_size(arg) + 1, 0);
            json_array_foreach(arg, i, val) {
                const char *s = json_string_value(val);
                if (!s) {
                    jmap_parser_push_index(parser, "properties", i, s);
                    jmap_parser_invalid(parser, NULL);
                    jmap_parser_pop(parser);
                    continue;
                }
                hash_insert(s, (void*)1, parseargs->props);
            }

            return 1;
        }
    }
    else if (jmap_is_using(req, JMAP_CALENDARS_EXTENSION)) {
        if (!strcmp(key, "repairBrokenIcal")) {
            if (json_is_boolean(arg)) {
                parseargs->repair_broken_ical = json_boolean_value(arg);
                return 1;
            }
        }
    }

    return 0;
}

static int jmap_calendarevent_parse(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_parse parse = JMAP_QUERYCHANGES_INITIALIZER;
    struct calendareventparse_args args = { 0 };
    json_t *err = NULL;

    /* Parse request */
    jmap_parse_parse(req, &parser,
                     &_calendareventparse_args_parse, &args, &parse, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    /* Process request */
    jmap_getblob_context_t blob_ctx;
    jmap_getblob_ctx_init(&blob_ctx, NULL, NULL, "text/calendar", 1);

    struct jmapical_ctx *jmapctx = jmapical_context_new(req, NULL);
    jmapctx->from_ical.repair_broken_ical = args.repair_broken_ical;

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
            events = jmapical_tojmap_all(ical, args.props, jmapctx);
            icalcomponent_free(ical);
        }

        switch (json_array_size(events)) {
        case 0:
            json_array_append_new(parse.not_parsable, json_string(blobid));
            json_decref(events);
            break;
        case 1:
            json_object_set(parse.parsed, blobid, json_array_get(events, 0));
            json_decref(events);
            break;
        default:
            json_object_set_new(parse.parsed, blobid,
                json_pack("{ s:s s:o }", "@type", "Group", "entries", events));
        }
    }

    jmapical_context_free(&jmapctx);
    jmap_getblob_ctx_fini(&blob_ctx);

    /* Build response */
    jmap_ok(req, jmap_parse_reply(&parse));

done:
    jmap_parser_fini(&parser);
    jmap_parse_fini(&parse);
    if (args.props) {
        free_hash_table(args.props, NULL);
        free(args.props);
    }
    return 0;
}

static int jmap_calendarevent_participantreply(struct jmap_req *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    const char *part_email = NULL;
    const char *part_stat = NULL;
    struct caldav_db *db = NULL;
    struct caldav_data *cdata = NULL;
    mbentry_t *mbentry = NULL;
    struct mailbox *mbox = NULL;
    strarray_t schedule_addr = STRARRAY_INITIALIZER;
    struct updateevent update = { .schedule_addresses = &schedule_addr };
    icalparameter_partstat ical_part_stat = ICAL_PARTSTAT_NONE;
    json_t *res = json_object();
    json_t *err = NULL;
    int r = 0;

    /* Parse arguments */
    json_t *jprop = json_object_get(req->args, "eventId");
    if (!json_is_string(jprop) ||
        !(update.eid = jmap_caleventid_decode(json_string_value(jprop)))) {
        jmap_parser_invalid(&parser, "eventId");
    }
    jprop = json_object_get(req->args, "participantEmail");
    if (json_is_string(jprop)) {
        const char *uri = json_string_value(jprop);
        if (!strncasecmp(uri, "mailto:", 7)) uri += 7;

        char *addr = xmlURIUnescapeString(uri, strlen(uri), NULL);
        strarray_appendm(&schedule_addr, addr);
        part_email = addr;
    }
    else {
        jmap_parser_invalid(&parser, "participantEmail");
    }
    jprop = json_object_get(req->args, "updates");
    if (json_is_object(jprop)) {
        jmap_parser_push(&parser, "updates");
        jprop = json_object_get(jprop, "participationStatus");
        if (json_is_string(jprop)) {
            part_stat = json_string_value(jprop);
            char *tmp = ucase(xstrdup(part_stat));
            ical_part_stat = icalparameter_string_to_enum(tmp);
            free(tmp);
        }

        switch (ical_part_stat) {
        case ICAL_PARTSTAT_ACCEPTED:
        case ICAL_PARTSTAT_DECLINED:
        case ICAL_PARTSTAT_TENTATIVE:
            break;
        default:
            jmap_parser_invalid(&parser, "participationStatus");
        }

        jmap_parser_pop(&parser);
    }
    else {
        jmap_parser_invalid(&parser, "updates");
    }

    if (json_array_size(parser.invalid)) {
        syslog(LOG_NOTICE, "failed to parse RSVP");
        goto done;
    }

    db = caldav_open_userid(req->accountid);
    if (!db) {
        syslog(LOG_ERR,
               "caldav_open_mailbox failed for user %s", req->accountid);
        r = IMAP_INTERNAL;
        goto done;
    }

    /* Determine if event is a standalone recurrence instance */
    if (update.eid->ical_recurid) {
        r = check_eventid_exists(update.eid, db, &update.is_standalone);
        if (r) {
            syslog(LOG_NOTICE, "can't find event with UID: %s %s",
                   update.eid->ical_uid,
                   update.eid->ical_recurid ? update.eid->ical_recurid : "");
            goto done;
        }
    }

    /* Determine mailbox and IMAP UID of calendar event. */
    r = caldav_lookup_uid(db, update.eid->ical_uid, &cdata);
    if (r && r != CYRUSDB_NOTFOUND) {
        syslog(LOG_ERR, "caldav_lookup_uid(%s) failed: %s",
               update.eid->ical_uid, error_message(r));
        goto done;
    }
    if (r == CYRUSDB_NOTFOUND || !cdata->dav.alive ||
            !cdata->dav.rowid || !cdata->dav.imap_uid ||
            cdata->comp_type != CAL_COMP_VEVENT) {
        syslog(LOG_NOTICE, "can't find DAV event record for UID: %s",
               update.eid->ical_uid);
        r = IMAP_NOTFOUND;
        goto done;
    }

    mbentry = jmap_mbentry_from_dav(req, &cdata->dav);
    if (!mbentry) {
        xsyslog(LOG_WARNING, "no mbentry for mailbox",
                "dav.mailbox=<%s> dav.mailbox_byname=<%d>",
                cdata->dav.mailbox, cdata->dav.mailbox_byname);
        r = IMAP_NOTFOUND;
        goto done;
    }

    if (mboxname_isdeletedmailbox(mbentry->name, NULL)) {
        xsyslog(LOG_ERR, "corrupt ical_objs table detected: "
                "mailbox is deleted, but ical_objs row exists",
                "mboxid=<%s> imap_uid=<%d>",
                mbentry->uniqueid, cdata->dav.imap_uid);
        r = IMAP_NOTFOUND;
        goto done;
    }

    /* Check permissions. */
    if (!mbentry || !jmap_hasrights_mbentry(req, mbentry, JACL_READITEMS)) {
        syslog(LOG_NOTICE, "no permissions to read event");
        r = IMAP_NOTFOUND;
        goto done;
    }

    /* Check privacy for sharees */
    if (strcmp(req->accountid, req->userid)) {
        if (cdata->comp_flags.privacy != CAL_PRIVACY_PUBLIC) {
            syslog(LOG_NOTICE, "no permissions for sharee to read event");
            r = cdata->comp_flags.privacy == CAL_PRIVACY_SECRET ?
                IMAP_NOTFOUND : IMAP_PERMISSION_DENIED;
            goto done;
        }
    }

    /* Open mailbox for reading */
    r = mailbox_open_irl(mbentry->name, &mbox);
    if (r) goto done;

    /* Fetch index record for the resource. */
    struct index_record record = { };
    r = mailbox_find_index_record(mbox, cdata->dav.imap_uid, &record);
    if (r) {
        syslog(LOG_ERR, "mailbox_index_record(0x%x) failed: %s",
                cdata->dav.imap_uid, error_message(r));
        goto done;
    }
    /* Load VEVENT from record. */
    update.oldical = record_to_ical(mbox, &record, NULL);
    if (!update.oldical) {
        syslog(LOG_ERR, "record_to_ical failed for record %u:%s",
                cdata->dav.imap_uid, mbentry->name);
        r = IMAP_INTERNAL;
        goto done;
    }
    mailbox_close(&mbox);

    /* Find participantId */
    icalcomponent *comp = icalcomponent_get_first_real_component(update.oldical);
    icalcomponent_kind kind = icalcomponent_isa(comp);
    const char *part_id = NULL;

    for (; comp; comp = icalcomponent_get_next_component(update.oldical, kind)) {
        icalproperty *prop =
            icalcomponent_get_first_property(comp, ICAL_RECURRENCEID_PROPERTY);

        if (update.eid->ical_recurid) {
            /* Is it the correct override? */
            if (!prop || strcmp(update.eid->ical_recurid,
                                icalproperty_get_value_as_string(prop))) {
                continue;
            }
        }
        else if (prop) {
            /* Not the master */
            continue;
        }

        prop = find_attendee(comp, part_email);
        if (prop) {
            /* Compare partStat */
            icalparameter *param =
                icalproperty_get_first_parameter(prop, ICAL_PARTSTAT_PARAMETER);
            if (ical_part_stat == icalparameter_get_partstat(param)) {
                errno = 0;
                xsyslog(LOG_ERR, "ignoring redundant RSVP (same partStat)",
                        "eventid=<%s> recurid=<%s>"
                        " attendee=<%s> participationStatus=<%s>",
                        update.eid->ical_uid,
                        update.eid->ical_recurid ? update.eid->ical_recurid : "",
                        part_email, part_stat);
                json_object_set_new(res, "scheduleStatus",
                                    json_string(SCHEDSTAT_SUCCESS));
                goto no_op;
            }

            part_id = jmap_partid_from_ical(prop);
            break;
        }
    }

    if (!part_id) {
        syslog(LOG_NOTICE, "failed to find participantId in event");
        r = HTTP_NOT_FOUND;
        goto done;
    }

    /* Create patch */
    struct buf buf = BUF_INITIALIZER;
    const char *ical_recurid = update.eid->ical_recurid; // save a copy
    if (update.eid->ical_recurid && !update.is_standalone) {
        struct icaltimetype tt = icaltime_from_string(update.eid->ical_recurid);
        struct jmapical_datetime dt;

        /* Add recurrence-id to buf */
        jmapical_datetime_from_icaltime(tt, &dt);
        jmapical_localdatetime_as_string(&dt, &buf);

        /* Prepend BEFORE recurrence-id */
        buf_insertcstr(&buf, 0, "recurrenceOverrides/");

        /* Append trailing slash */
        buf_putc(&buf, '/');

        /* Done with recurid (and keeping it causes the patch to fail) */
        update.eid->ical_recurid = NULL;
    }
    buf_printf(&buf, "participants/%s/participationStatus", part_id);

    update.event_patch = json_pack("{s:s}", buf_cstring(&buf), part_stat);
    update.mbentry = mbentry;
    update.cdata = cdata;
    buf_free(&buf);

    /* Apply patch */
    r = updateevent_apply_patch(req, &update, parser.invalid, NULL, &err);
    if (err || r || json_array_size(parser.invalid)) {
        syslog(LOG_NOTICE, "failed to patch RSVP into event");
        goto done;
    }

    /* Create and send the reply */
    sched_reply(req->accountid, req->accountid, &schedule_addr,
                update.oldical, update.newical, SCHED_MECH_JMAP_PARTREPLY);

    /* Get SCHEDULE-STATUS */
    const char *organizer = NULL;
    const char *sched_stat = NULL;
    for (comp = icalcomponent_get_first_component(update.newical, kind);
         comp;
         comp = icalcomponent_get_next_component(update.newical, kind)) {
        icalproperty *prop =
            icalcomponent_get_first_property(comp, ICAL_RECURRENCEID_PROPERTY);

        if (ical_recurid) {
            /* Is it the correct override? */
            if (!prop ||
                strcmp(ical_recurid, icalproperty_get_value_as_string(prop))) {
                continue;
            }
        }
        else if (prop) {
            /* Not the master */
            continue;
        }

        prop = icalcomponent_get_first_property(comp, ICAL_ORGANIZER_PROPERTY);
        organizer = icalproperty_get_decoded_calendaraddress(prop);

        icalparameter *param = icalproperty_get_schedulestatus_parameter(prop);
        sched_stat = icalparameter_get_schedulestatus(param);
        json_object_set_new(res, "scheduleStatus", json_string(sched_stat));

        prop = find_attendee(comp, part_email);
        param = icalparameter_new_scheduleforcesend(ICAL_SCHEDULEFORCESEND_REQUEST);
        icalproperty_add_parameter(prop, param);
        break;
    }

    /* Create and send an update request to the attendee that replied */
    schedule_one_attendee(req->accountid, req->accountid, NULL, organizer,
                          part_email, caldav_get_historical_cutoff(),
                          update.oldical, update.newical,
                          SCHED_MECH_JMAP_PARTREPLY);

no_op:
    /* Build response */
    req->accountid = NULL;
    jmap_ok(req, res);

done:
    if (!err) {
        if (json_array_size(parser.invalid)) {
            err = json_pack("{s:s}", "type", "invalidArguments");
            json_object_set(err, "arguments", parser.invalid);
        }
        else if (r) {
            switch (r) {
            case HTTP_NOT_FOUND:
            case IMAP_NOTFOUND:
                err = json_pack("{s:s}", "type", "notFound");
                break;
            default:
                err = jmap_server_error(r);
            }
        }
    }
    if (err) {
        char *errstr = json_dumps(err, JSON_COMPACT);
        syslog(LOG_NOTICE, "RSVP failed: %s", errstr);
        free(errstr);

        jmap_error(req, err);
    }

    jmap_parser_fini(&parser);
    jmap_caleventid_free(&update.eid);
    if (db) caldav_close(db);
    mailbox_close(&mbox);
    if (update.oldical) icalcomponent_free(update.oldical);
    if (update.newical) icalcomponent_free(update.newical);
    jstimezones_free(&update.jstzones);
    json_decref(update.event_patch);
    json_decref(update.old_event);
    strarray_fini(&schedule_addr);
    mboxlist_entry_free(&mbentry);
    return 0;
}

// clang-format off
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
// clang-format on

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
    get_schedule_addresses(calhomename, accountid, &addrs);

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
    SHA1_CTX *sha1;
};

static int principal_state_init(jmap_req_t *req, SHA1_CTX *sha1)
{
    SHA1Init(sha1);
    char *calhomename = caldav_mboxname(req->userid, NULL);
    struct mailbox *mbox = NULL;
    int r = mailbox_open_irl(calhomename, &mbox);
    if (!r) {
        struct buf buf = BUF_INITIALIZER;
        buf_printf(&buf, "%s" MODSEQ_FMT, req->userid, mailbox_foldermodseq(mbox));
        SHA1Update(sha1, buf_base(&buf), buf_len(&buf));
        buf_free(&buf);
    }
    mailbox_close(&mbox);
    free(calhomename);
    return r;
}

static void principal_state_update(jmap_req_t *req __attribute__((unused)),
                                   SHA1_CTX *sha1,
                                   const char *accountid)
{
    SHA1Update(sha1, accountid, strlen(accountid));
}

static char *principal_state_string(SHA1_CTX *sha1)
{
    uint8_t digest[SHA1_DIGEST_LENGTH];
    SHA1Final(digest, sha1);
    char hexdigest[SHA1_DIGEST_LENGTH*2 + 1];
    bin_to_hex(digest, SHA1_DIGEST_LENGTH, hexdigest, BH_LOWER);
    hexdigest[SHA1_DIGEST_LENGTH*2] = '\0';
    return xstrdup(hexdigest);
}

static int principal_state_current_cb(jmap_req_t *req,
                                      const char *accountid,
                                      int rights __attribute__((unused)),
                                      void *rock)
{
    SHA1_CTX *sha1 = rock;
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
    SHA1_CTX sha1;
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
    SHA1Update(getrock->sha1, accountid, strlen(accountid));

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
    struct jmap_get get = JMAP_GET_INITIALIZER;
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
    SHA1_CTX sha1;
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
    SHA1_CTX sha1;
    SHA1Init(&sha1);
    size_t i;
    for (i = 0; i < (size_t) strarray_size(&matches); i++) {
        const char *id = strarray_nth(&matches, i);
        SHA1Update(&sha1, id, strlen(id));
    }
    uint8_t digest[SHA1_DIGEST_LENGTH];
    SHA1Final(digest, &sha1);
    char hexdigest[SHA1_DIGEST_LENGTH*2 + 1];
    bin_to_hex(digest, SHA1_DIGEST_LENGTH, hexdigest, BH_LOWER);
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
    struct jmap_query query = JMAP_QUERY_INITIALIZER;

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
    struct jmap_changes changes = JMAP_CHANGES_INITIALIZER;
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
    struct jmap_querychanges query = JMAP_QUERYCHANGES_INITIALIZER;

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
    struct jmap_set set = JMAP_SET_INITIALIZER;
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
                int r = mailbox_open_iwl(calhomename, &mbox);
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
                mailbox_close(&mbox);
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
    struct jmapical_ctx *jmapctx;
    hash_table *eventprops;
    int cumulatedrights;
    icaltimezone *utc;
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
                                             icaltimetype recurid __attribute__((unused)),
                                             int is_standalone __attribute__((unused)),
                                             void *vrock)
{
    if (!getavailability_ishidden(comp)) return 1;

    struct principal_getavailability_rock *rock = vrock;
    struct jmapical_datetime dt = JMAPICAL_DATETIME_INITIALIZER;
    icalproperty *prop;
    struct busyperiod bp = JMAP_BUSYPERIOD_INITIALIZER;

    /* Convert to UTC */
    icaltimetype utcstart = icaltime_convert_to_zone(start, rock->utc);
    icaltimetype utcend = icaltime_convert_to_zone(end, rock->utc);

    /* Check timerange */
    if (icaltime_compare(utcend, rock->icalstart) <= 0 ||
        icaltime_compare(utcstart, rock->icalend) >= 0)
        return 0;

    /* utcStart and utcEnd */
    jmapical_datetime_from_icaltime(utcstart, &bp.utcstart);
    jmapical_datetime_from_icaltime(utcend, &bp.utcend);

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
                    jevent = jmap_patchobject_apply(rock->jevent, jval, NULL, 0);
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

static int principal_getavailability_cb(void *vrock, struct caldav_jscal *jscal)
{
    struct principal_getavailability_rock *rock = vrock;
    icalcomponent *ical = NULL;
    struct caldav_data *cdata = &jscal->cdata;
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
        mailbox_close(&rock->mbox);
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
        r = mailbox_open_irl(rock->mbentry->name, &rock->mbox);
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
    icalcomponent_kind kind = icalcomponent_isa(comp);

    /* Check mailbox-scoped ACL for showDetails */
    if (rock->show_details && rock->checkacl && !(rock->rights & ACL_READ)) {
        rock->show_details = 0;
    }
    if (rock->show_details) {
        /* Fetch all properties, we need them for recurrence overrides */
        context_begin_cdata(rock->jmapctx, rock->mbentry, cdata);
        rock->jevent = jmapical_tojmap(ical, NULL, rock->jmapctx);
        context_end_cdata(rock->jmapctx);
    }

    /* Build BusyPeriod objects */
    if (!jscal->ical_recurid[0]) {
        // expand recurrences of main event
        struct icalperiodtype timerange = {
            rock->icalstart, rock->icalend, icaldurationtype_null_duration()
        };
        icalcomponent_myforeach(ical, timerange, rock->floatingtz,
                principal_getavailability_ical_cb, rock);
    }
    else {
        for (comp = icalcomponent_get_first_real_component(ical);
             comp;
             comp = icalcomponent_get_next_component(ical, kind)) {

            icalproperty *prop =
                icalcomponent_get_first_property(comp, ICAL_RECURRENCEID_PROPERTY);
            if (!prop) continue;

            if (strcmpsafe(jscal->ical_recurid, icalproperty_get_value_as_string(prop)))
                continue;

            /* Callback will take care of filtering time range */
            icaltimetype dtstart = icalcomponent_get_dtstart(comp);
            icaltimetype dtend = icalcomponent_get_dtend(comp);
            principal_getavailability_ical_cb(comp, dtstart, dtend,
                    icaltime_null_time(), 0, rock);
        }
    }

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
    struct jmapical_ctx *jmapctx = jmapical_context_new(req, NULL);

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
        jmapctx,
        props,
        0,
        icaltimezone_get_utc_timezone(),
        NULL,
        NULL,
        checkacl,
        0,
        NULL,
        NULL
    };

    enum caldav_sort sort[] = { CAL_SORT_MAILBOX };

    struct caldav_jscal_filter jscal_filter = CALDAV_JSCAL_FILTER_INITIALIZER;
    caldav_jscal_filter_by_before(&jscal_filter, &tend);
    caldav_jscal_filter_by_after(&jscal_filter, &tstart);
    int r = caldav_foreach_jscal(db, NULL, &jscal_filter, NULL, sort, 1,
                                 principal_getavailability_cb, &rock);
    caldav_jscal_filter_fini(&jscal_filter);
    if (r) jmap_error(req, jmap_server_error(r));
    mailbox_close(&rock.mbox);
    mboxlist_entry_free(&rock.mbentry);
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
            if (count != i) {
                /* Insert new busy period */
                dynarray_set(busyperiods, count, bp);
            }
            count++;
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
    jmapical_context_free(&jmapctx);
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
    seqset_t *seenuids;
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

static seqset_t *_readseen(struct mailbox *mbox, const char *userid)
{
    seqset_t *seenuids = NULL;
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
    seqset_t *seenuids = NULL;

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
        entry.created = record->internaldate.tv_sec;
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

    if (search->sort && entries->count) {
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
    seqset_t *seenuids = NULL;

    int r = mailbox_open_irl(notifmb->name, &notifmbox);
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
    mailbox_close(&notifmbox);
    seqset_free(&seenuids);
}

static void notif_set(struct jmap_req *req,
                      struct jmap_set *set,
                      const mbentry_t *notifmb,
                      int set_seen,
                      modseq_t statemodseq,
                      json_t **err)
{
    struct mailbox *notifmbox = NULL;
    struct seen *seendb = NULL;
    seqset_t *seenuids = NULL;
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

    int r = mailbox_open_iwl(notifmb->name, &notifmbox);
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

done:
    seqset_free(&seenuids);
    seen_close(&seendb);
    mailbox_close(&notifmbox);
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

    int r = mailbox_open_irl(notifmboxname, &notifmbox);
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
    mailbox_close(&notifmbox);
}

// clang-format off
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
// clang-format on

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
    r = dlist_parsemap(&dl, 1, body->description, strlen(body->description));
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
                struct request_target_t tgt = { .allow = ALLOW_CAL };
                const char *errstr = NULL;
                if (principal_parse_path(href, &tgt, &errstr) == 0) {
                    json_object_set_new(changedby, "principalId",
                            json_string(tgt.userid));

                    json_t *email = json_null();
                    char *calhomename = caldav_mboxname(tgt.userid, NULL);
                    strarray_t addrs = STRARRAY_INITIALIZER;
                    get_schedule_addresses(calhomename, tgt.userid, &addrs);
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
    struct jmap_get get = JMAP_GET_INITIALIZER;
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
    struct jmap_set set = JMAP_SET_INITIALIZER;
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

    notif_set(req, &set, notifmb, 0, req->counters.davnotificationmodseq, &err);
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
    struct jmap_changes changes = JMAP_CHANGES_INITIALIZER;
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
        r = dlist_parsemap(&dl, 1, body->description, strlen(body->description));
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
    struct jmap_query query = JMAP_QUERY_INITIALIZER;
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
            r = mailbox_open_irl(notifmb->name, &notifmbox);
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
    mailbox_close(&notifmbox);
    mboxlist_entry_free(&notifmb);
    jmap_query_fini(&query);
    jmap_parser_fini(&parser);
    return 0;
}

static int jmap_sharenotification_querychanges(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_querychanges query = JMAP_QUERYCHANGES_INITIALIZER;

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

// clang-format off
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
// clang-format on

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
            if (!dlist_parsemap(&dl, 1, body->description,
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
    struct jmap_get get = JMAP_GET_INITIALIZER;
    json_t *err = NULL;
    char *notifmboxname = jmap_notifmboxname(req->accountid);
    char *notfrom = jmap_caleventnotif_format_fromheader(req->userid);
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
            if (!dlist_parsemap(&dl, 1, body->description,
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
    struct jmap_query query = JMAP_QUERY_INITIALIZER;
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
    int r = mailbox_open_irl(notifmboxname, &notifmbox);
    free(notifmboxname);
    if (r == IMAP_MAILBOX_NONEXISTENT) {
        r = 0;
    }
    else if (r) {
        jmap_error(req, jmap_server_error(r));
        goto done;
    }

    if (notifmbox) {
        char *notfrom = jmap_caleventnotif_format_fromheader(req->userid);
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
    mailbox_close(&notifmbox);
    jmap_query_fini(&query);
    jmap_parser_fini(&parser);
    return 0;
}

static int jmap_calendareventnotification_set(struct jmap_req *req)
{
    struct mboxlock *namespacelock = user_namespacelock(req->accountid);
    char *notifmboxname = jmap_notifmboxname(req->accountid);
    struct jmap_parser argparser = JMAP_PARSER_INITIALIZER;
    struct jmap_set set = JMAP_SET_INITIALIZER;
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

    notif_set(req, &set, notifmb, 1, req->counters.jmapnotificationmodseq, &err);
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
    struct jmap_changes changes = JMAP_CHANGES_INITIALIZER;
    json_t *err = NULL;

    jmap_changes_parse(req, &parser, req->counters.jmapnotificationdeletedmodseq,
                       NULL, NULL, &changes, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    char *notifmboxname = jmap_notifmboxname(req->accountid);
    char *notfrom = jmap_caleventnotif_format_fromheader(req->userid);
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
    struct jmap_querychanges query = JMAP_QUERYCHANGES_INITIALIZER;

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

// clang-format off
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
// clang-format on

static void encode_participantidentity_id(struct buf *buf, const char *addr)
{
    char idbuf[2*SHA1_DIGEST_LENGTH+1];
    unsigned char sha1buf[SHA1_DIGEST_LENGTH];
    xsha1((const unsigned char *) addr, strlen(addr), sha1buf);
    bin_to_hex(sha1buf, SHA1_DIGEST_LENGTH, idbuf, BH_LOWER);
    idbuf[2*SHA1_DIGEST_LENGTH] = '\0';
    buf_setcstr(buf, idbuf);
}

static int jmap_participantidentity_get(struct jmap_req *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_get get = JMAP_GET_INITIALIZER;
    json_t *err = NULL;
    int r = 0;
    struct buf buf = BUF_INITIALIZER;
    struct buf idbuf = BUF_INITIALIZER;

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
    get_schedule_addresses(calhomename, req->userid, &addrs);
    free(calhomename);
    calhomename = NULL;

    int i;
    for (i = 0; i < strarray_size(&addrs); i++) {
        const char *addr = strarray_nth(&addrs, i);
        json_t *jpartid = json_object();

        /* id */
        encode_participantidentity_id(&idbuf, addr);
        json_object_set_new(jpartid, "id",
                json_string(buf_cstring(&idbuf)));

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

        json_object_set_new(jpartidsbyid, buf_cstring(&idbuf), jpartid);
        buf_reset(&idbuf);
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
    get.state = modseqtoa(jmap_modseq(req, MBTYPE_CALENDAR, 0));
    jmap_ok(req, jmap_get_reply(&get));

done:
    jmap_parser_fini(&parser);
    jmap_get_fini(&get);
    buf_free(&idbuf);
    buf_free(&buf);
    return r;
}

static int jmap_participantidentity_set(struct jmap_req *req)
{
    struct jmap_parser argparser = JMAP_PARSER_INITIALIZER;
    struct jmap_set set = JMAP_SET_INITIALIZER;
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

    set.new_state = modseqtoa(jmap_modseq(req, MBTYPE_CALENDAR, JMAP_MODSEQ_RELOAD));

    jmap_ok(req, jmap_set_reply(&set));

done:
    jmap_parser_fini(&argparser);
    jmap_set_fini(&set);
    return r;
}

static int jmap_participantidentity_changes(struct jmap_req *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_changes changes = JMAP_CHANGES_INITIALIZER;
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

HIDDEN json_t *jmap_calendar_events_from_msg(jmap_req_t *req,
                                             const char *mboxid,
                                             uint32_t uid,
                                             hash_table *icsbody_by_partid,
                                             unsigned allow_max_uids,
                                             const struct buf *mime)
{
    json_t *jsevents_by_partid = json_object();
    struct jmapical_ctx *jmapctx = jmapical_context_new(req, NULL);
    struct buf buf = BUF_INITIALIZER;
    struct buf rewritebufs[CALDAV_REWRITE_ATTACHPROP_TO_URL_NBUFS];
    memset(rewritebufs, 0, sizeof(struct buf) * CALDAV_REWRITE_ATTACHPROP_TO_URL_NBUFS);

    hash_iter *hit = hash_table_iter(icsbody_by_partid);
    while (hash_iter_next(hit)) {
        const char *partid = hash_iter_key(hit);
        struct body *part = hash_iter_val(hit);

        /* Parse iCalendar data */
        icalcomponent *ical = NULL;
        char *decbuf = NULL;
        size_t declen = 0;
        const char *content = buf_base(mime) + part->content_offset;
        const char *rawical = charset_decode_mimebody(content, part->content_size,
                part->charset_enc, &decbuf, &declen);
        if (!rawical) continue;
        buf_setmap(&buf, rawical, declen);
        ical = ical_string_as_icalcomponent(&buf);
        free(decbuf);
        if (!ical) continue;

        if (allow_max_uids) {
            // VCALENDAR must not contain more than allow_max_uids main events
            hash_table seen_uids = HASH_TABLE_INITIALIZER;
            construct_hash_table(&seen_uids, allow_max_uids + 1, 0);

            icalcomponent *comp = icalcomponent_get_first_real_component(ical);
            while (comp && (unsigned)hash_numrecords(&seen_uids) <= allow_max_uids) {
                icalcomponent_kind kind = icalcomponent_isa(comp);

                const char *uid = icalcomponent_get_uid(comp);
                if (uid && !hash_lookup(uid, &seen_uids))
                    hash_insert(uid, (void*)1, &seen_uids);

                comp = icalcomponent_get_next_component(ical, kind);
            }

            unsigned nseen_uids = hash_numrecords(&seen_uids);
            free_hash_table(&seen_uids, NULL);

            if (nseen_uids > allow_max_uids) {
                icalcomponent_free(ical);
                continue;
            }
        }

        if (icalcomponent_get_method(ical) != ICAL_METHOD_NONE) {
            /* In-place rewrite BINARY ATTACH to managed attachment */
            icalcomponent *comp = icalcomponent_get_first_real_component(ical);
            if (!comp) continue;
            icalcomponent_kind kind = icalcomponent_isa(comp);
            for ( ; comp; comp = icalcomponent_get_next_component(ical, kind)) {
                icalproperty *prop = icalcomponent_get_first_property(comp, ICAL_ATTACH_PROPERTY);
                for ( ; prop; prop = icalcomponent_get_next_property(comp, ICAL_ATTACH_PROPERTY)) {

                    icalvalue *icalval = icalproperty_get_value(prop);
                    if (!icalval || icalvalue_isa(icalval) != ICAL_ATTACH_VALUE)
                        continue;

                    icalattach *attach = icalproperty_get_attach(prop);
                    if (!attach || icalattach_get_is_url(attach))
                        continue;

                    if (!jmapical_context_open_attachments(jmapctx)) {
                        caldav_rewrite_attachprop_to_url(jmapctx->attachments.db,
                                prop, &jmapctx->attachments.url, rewritebufs);
                        int j;
                        for (j = 0; j < CALDAV_REWRITE_ATTACHPROP_TO_URL_NBUFS; j++)
                            buf_reset(&rewritebufs[j]);
                    }
                }
            }
        }

        /* Convert to Event */
        jmapctx->from_ical.cyrus_msg.mboxid = mboxid;
        jmapctx->from_ical.cyrus_msg.uid = uid;
        jmapctx->from_ical.cyrus_msg.partid = partid;
        jmapctx->from_ical.repair_broken_ical = 1;
        json_t *jsevents = jmapical_tojmap_all(ical, NULL, jmapctx);
        if (json_array_size(jsevents)) {
            json_object_set_new(jsevents_by_partid, part->part_id, jsevents);
        }
        icalcomponent_free(ical);
    }
    hash_iter_free(&hit);

    jmapical_context_free(&jmapctx);
    if (!json_object_size(jsevents_by_partid)) {
        json_decref(jsevents_by_partid);
        jsevents_by_partid = json_null();
    }

    int j;
    for (j = 0; j < CALDAV_REWRITE_ATTACHPROP_TO_URL_NBUFS; j++)
        buf_free(&rewritebufs[j]);
    buf_free(&buf);
    return jsevents_by_partid;
}

// clang-format off
static const jmap_property_t calendarpreferences_props[] = {
    {
        "id",
        NULL,
        JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE | JMAP_PROP_ALWAYS_GET
    },
    {
        "defaultCalendarId",
        NULL,
        0
    },
    {
        "defaultParticipantIdentityId",
        NULL,
        0
    },
    { NULL, NULL, 0 }
};
// clang-format on

static int jmap_calendarpreferences_get(struct jmap_req *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_get get = JMAP_GET_INITIALIZER;
    json_t *err = NULL;
    struct buf buf = BUF_INITIALIZER;
    char *calhomename = NULL;
    mbentry_t *mbcalhome = NULL;
    int r = 0;

    if (!has_calendars(req)) {
        jmap_error(req, json_pack("{s:s}", "type", "accountNoCalendars"));
        return 0;
    }

    /* Parse request */
    jmap_get_parse(req, &parser, calendarpreferences_props, 1,
                   NULL, NULL, &get, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    /* Check ACL */
    calhomename = caldav_mboxname(req->accountid, NULL);
    r = mboxlist_lookup(calhomename, &mbcalhome, NULL);
    if (r) {
        jmap_error(req, jmap_server_error(r));
        xsyslog(LOG_INFO, "cannot lookup calendar home",
                "calname=<%s> err=<%s>", calhomename, error_message(r));
        r = 0;
        goto done;
    }
    if (!jmap_hasrights_mbentry(req, mbcalhome, JACL_LOOKUP)) {
        jmap_error(req, json_pack("{s:s}", "type", "forbidden"));
        goto done;
    }

    int want_singleton = 1;
    if (json_array_size(get.ids)) {
        want_singleton = 0;
        size_t i;
        for (i = 0; i < json_array_size(get.ids); i++) {
            const char *id = json_string_value(json_array_get(get.ids, i));
            if (strcmp(id, "singleton")) {
                json_array_append_new(get.not_found, json_string(id));
            }
            else want_singleton = 1;
        }
    }

    if (want_singleton) {
        json_t *jprefs = json_object();
        json_object_set_new(jprefs, "id", json_string("singleton"));

        if (jmap_wantprop(get.props, "defaultCalendarId")) {
            json_t *jid = json_null();
            char *scheddefault = caldav_scheddefault(req->accountid, 0);
            if (scheddefault) {
                jid = json_string(scheddefault);
            }
            json_object_set_new(jprefs, "defaultCalendarId", jid);
            free(scheddefault);
        }

        if (jmap_wantprop(get.props, "defaultParticipantIdentityId")) {
            json_t *jpartid = json_null();

            strarray_t caluseraddr = STRARRAY_INITIALIZER;
            if (!caldav_caluseraddr_read(mbcalhome->name, req->accountid, &caluseraddr)) {
                const char *addr = strarray_nth(&caluseraddr, 0);
                if (addr) {
                    if (!strncasecmp(addr, "mailto:", 7)) addr += 7;
                    encode_participantidentity_id(&buf, addr);
                    jpartid = json_string(buf_cstring(&buf));
                    buf_reset(&buf);
                }
            }
            strarray_fini(&caluseraddr);

            json_object_set_new(jprefs, "defaultParticipantIdentityId", jpartid);
        }

        json_array_append_new(get.list, jprefs);
    }

    buf_printf(&buf, MODSEQ_FMT, mbcalhome->foldermodseq);
    get.state = buf_release(&buf);
    jmap_ok(req, jmap_get_reply(&get));

done:
    mboxlist_entry_free(&mbcalhome);
    free(calhomename);
    jmap_parser_fini(&parser);
    jmap_get_fini(&get);
    buf_free(&buf);
    return r;
}

static void calendarpreferences_set(struct jmap_req *req,
                                    struct jmap_parser *parser,
                                    json_t *jprefs,
                                    mbentry_t *mbcalhome,
                                    json_t *server_set,
                                    json_t **err)
{
    json_t *jcalid = NULL;
    json_t *jpartid = NULL;
    struct buf buf = BUF_INITIALIZER;
    int r = 0;

    struct mailbox *calhomembox = NULL;
    annotate_state_t *astate = NULL;
    json_t *jalertsprefs = NULL;

    /* Validate properties */

    const char *prop;
    json_t *jval;
    json_object_foreach(jprefs, prop, jval) {
        if (!strcmp(prop, "id")) {
            const char *id = json_string_value(jval);
            if ((id && strcmp(id, "singleton")) || !id) {
                jmap_parser_invalid(parser, "id");
            }
        }
        else if (!strcmp(prop, "defaultCalendarId")) {
            if (json_is_string(jval) || json_is_null(jval)) {
                jcalid = jval;
            }
            else {
                jmap_parser_invalid(parser, "defaultCalendarId");
            }
        }
        else if (!strcmp(prop, "defaultParticipantIdentityId")) {
            if (json_is_string(jval) || json_is_null(jval)) {
                jpartid = jval;
            }
            else {
                jmap_parser_invalid(parser, "defaultParticipantIdentityId");
            }
        }
        else {
            jmap_parser_invalid(parser, prop);
        }
    }

    if (json_array_size(parser->invalid)) {
        *err = json_pack("{s:s, s:O}",
                    "type", "invalidProperties",
                    "properties", parser->invalid);
        goto done;
    }

    r = mailbox_open_iwl(mbcalhome->name, &calhomembox);
    if (r) {
        xsyslog(LOG_ERR, "can not open calendar home mailbox",
                "err=<%s>", error_message(r));
        goto done;
    }
    r = mailbox_get_annotate_state(calhomembox, 0, &astate);
    if (r) {
        xsyslog(LOG_ERR, "can not open get annotation state",
                "err=<%s>", error_message(r));
        goto done;
    }

    /* Set default calendar */
    if (jcalid) {
        char *server_set_default_calid = NULL;
        if (json_is_null(jcalid)) {
            server_set_default_calid = caldav_scheddefault(req->accountid, 1);
            r = set_scheddefault(req, astate, server_set_default_calid);
        }
        else {
            r = set_scheddefault(req, astate, json_string_value(jcalid));
        }
        if (r) {
            if (r == IMAP_MAILBOX_NONEXISTENT || r == IMAP_PERMISSION_DENIED) {
                *err = json_pack("{s:s, s:[s]}",
                        "type", "invalidProperties",
                        "properties", "defaultCalendarId");
                r = 0;
                goto done;
            }
            else {
                xsyslog(LOG_ERR, "can not write schedule default calendar",
                        "err=<%s>", error_message(r));
                goto done;
            }
        }
        if (server_set_default_calid) {
            json_object_set_new(server_set, "defaultCalendarId",
                    json_string(server_set_default_calid));
        }
        xzfree(server_set_default_calid);
    }

    /* Set default participant identity */
    if (jpartid) {
        const char *partid = json_string_value(jpartid);

        strarray_t caluseraddr = STRARRAY_INITIALIZER;
        r = caldav_caluseraddr_read(mbcalhome->name, req->userid, &caluseraddr);
        if (!r) {
            if (partid) {
                int i;
                for (i = 0; i < strarray_size(&caluseraddr); i++) {
                    const char *addr = strarray_nth(&caluseraddr, i);
                    if (!strncasecmp(addr, "mailto:", 7)) addr += 7;
                    encode_participantidentity_id(&buf, addr);
                    if (!strcmp(partid, buf_cstring(&buf))) {
                        break;
                    }
                }
                if (i < strarray_size(&caluseraddr)) {
                    // move preferred address to first position, as Apple
                    // and Mozilla CalDAV clients expect it there
                    if (i > 0) {
                        char *val = strarray_remove(&caluseraddr, i);
                        strarray_unshiftm(&caluseraddr, val);
                    }
                    r = caldav_caluseraddr_write(calhomembox, req->userid, &caluseraddr);
                }
                else {
                    jmap_parser_invalid(parser, "defaultParticipantIdentityId");
                }
            }
            else {
                // The defaultParticipantIdentity setting can't be removed,
                // there always needs to be one set. Just tell the client
                // we set a new one which matches the one we already had.
                const char *addr = strarray_nth(&caluseraddr, 0);
                if (addr) {
                    if (!strncasecmp(addr, "mailto:", 7)) addr += 7;
                    encode_participantidentity_id(&buf, addr);
                    json_t *jpartid = json_string(buf_cstring(&buf));
                    buf_reset(&buf);
                    json_object_set_new(
                        server_set, "defaultParticipantIdentityId", jpartid);
                }
            }
        }
        strarray_fini(&caluseraddr);

        if (r) {
            xsyslog(LOG_ERR, "can not set schedule addresses",
                    "err=<%s>", error_message(r));
            goto done;
        }
    }

done:
    if (r && *err == NULL) {
        *err = jmap_server_error(r);
    }
    mailbox_close(&calhomembox);
    json_decref(jalertsprefs);
    buf_free(&buf);
}

static int jmap_calendarpreferences_set(struct jmap_req *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_set set = JMAP_SET_INITIALIZER;
    json_t *err = NULL;
    int r = 0;

    struct buf buf = BUF_INITIALIZER;
    char *calhomename = caldav_mboxname(req->accountid, NULL);
    mbentry_t *mbcalhome = NULL;

    jmap_set_parse(req, &parser, calendarpreferences_props,
                   NULL, NULL, &set, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    /* Check ACL */
    r = mboxlist_lookup(calhomename, &mbcalhome, NULL);
    if (r) {
        jmap_error(req, jmap_server_error(r));
        xsyslog(LOG_INFO, "cannot lookup calendar home",
                "calname=<%s> err=<%s>", calhomename, error_message(r));
        r = 0;
        goto done;
    }
    if (!jmap_hasrights_mbentry(req, mbcalhome, JACL_LOOKUP|JACL_SETKEYWORDS)) {
        jmap_error(req, json_pack("{s:s}", "type", "forbidden"));
        goto done;
    }

    /* Check state */
    buf_printf(&buf, MODSEQ_FMT, mbcalhome->foldermodseq);
    if (set.if_in_state && strcmp(set.if_in_state, buf_cstring(&buf))) {
        jmap_error(req, json_pack("{s:s}", "type", "stateMismatch"));
        goto done;
    }
    set.old_state = buf_release(&buf);

    /* Reject invalid operations */
    const char *key;
    json_t *jarg;
    json_object_foreach(set.create, key, jarg) {
        json_object_set_new(set.not_created, key,
                json_pack("{s:s}", "type", "forbidden"));
    }
    json_object_foreach(set.update, key, jarg) {
        if (strcmp(key, "singleton")) {
            json_object_set_new(set.not_updated, key,
                    json_pack("{s:s}", "type", "notFound"));
        }
    }
    size_t i;
    json_array_foreach(set.destroy, i, jarg) {
        json_object_set_new(set.not_destroyed,
                json_string_value(jarg),
                json_pack("{s:s}", "type",
                    strcmp(key, "singleton") ? "notFound" : "forbidden"));
    }

    json_t *jprefs = json_object_get(set.update, "singleton");
    if (JNOTNULL(jprefs)) {
        json_t *server_set = json_object();
        json_t *err = NULL;
        calendarpreferences_set(req, &parser, jprefs, mbcalhome, server_set, &err);
        if (!json_object_size(server_set)) {
            json_decref(server_set);
            server_set = json_null();
        }
        if (err) {
            json_object_set_new(set.not_updated, "singleton", err);
        }
        else {
            json_object_set(set.updated, "singleton", server_set);
        }
        json_decref(server_set);
    }

    // Reload foldermodseq
    mboxlist_entry_free(&mbcalhome);
    mboxlist_lookup(calhomename, &mbcalhome, NULL);
    buf_printf(&buf, MODSEQ_FMT, mbcalhome->foldermodseq);
    set.new_state = buf_release(&buf);

    jmap_ok(req, jmap_set_reply(&set));

done:
    mboxlist_entry_free(&mbcalhome);
    free(calhomename);
    jmap_parser_fini(&parser);
    jmap_set_fini(&set);
    return r;
}
