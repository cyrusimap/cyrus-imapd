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
#include "caldav_db.h"
#include "cyr_qsort_r.h"
#include "global.h"
#include "hash.h"
#include "httpd.h"
#include "http_caldav.h"
#include "http_caldav_sched.h"
#include "http_dav.h"
#include "http_jmap.h"
#include "http_proxy.h"
#include "ical_support.h"
#include "json_support.h"
#include "jmap_ical.h"
#include "search_query.h"
#include "times.h"
#include "user.h"
#include "util.h"
#include "xmalloc.h"

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

static int jmap_calendarevent_getblob(jmap_req_t *req, jmap_getblob_context_t *ctx);

#define JMAPCACHE_CALVERSION 19

jmap_method_t jmap_calendar_methods_standard[] = {
    // we have no standard for JMAP calendars yet!
    { NULL, NULL, NULL, 0}
};

jmap_method_t jmap_calendar_methods_nonstandard[] = {
    {
        "Calendar/get",
        JMAP_CALENDARS_EXTENSION,
        &jmap_calendar_get,
        JMAP_NEED_CSTATE
    },
    {
        "Calendar/changes",
        JMAP_CALENDARS_EXTENSION,
        &jmap_calendar_changes,
        JMAP_NEED_CSTATE
    },
    {
        "Calendar/set",
        JMAP_CALENDARS_EXTENSION,
        &jmap_calendar_set,
        JMAP_NEED_CSTATE | JMAP_READ_WRITE
    },
    {
        "CalendarEvent/get",
        JMAP_CALENDARS_EXTENSION,
        &jmap_calendarevent_get,
        JMAP_NEED_CSTATE
    },
    {
        "CalendarEvent/changes",
        JMAP_CALENDARS_EXTENSION,
        &jmap_calendarevent_changes,
        JMAP_NEED_CSTATE
    },
    {
        "CalendarEvent/query",
        JMAP_CALENDARS_EXTENSION,
        &jmap_calendarevent_query,
        JMAP_NEED_CSTATE
    },
    {
        "CalendarEvent/set",
        JMAP_CALENDARS_EXTENSION,
        &jmap_calendarevent_set,
        JMAP_NEED_CSTATE | JMAP_READ_WRITE
    },
    {
        "CalendarEvent/copy",
        JMAP_CALENDARS_EXTENSION,
        &jmap_calendarevent_copy,
        JMAP_NEED_CSTATE | JMAP_READ_WRITE
    },
    {
        "CalendarEvent/parse",
        JMAP_CALENDARS_EXTENSION,
        &jmap_calendarevent_parse,
        JMAP_NEED_CSTATE
    },
    { NULL, NULL, NULL, 0}
};

HIDDEN void jmap_calendar_init(jmap_settings_t *settings)
{
    jmap_method_t *mp;

    for (mp = jmap_calendar_methods_standard; mp->name; mp++) {
        hash_insert(mp->name, mp, &settings->methods);
    }

    if (config_getswitch(IMAPOPT_JMAP_NONSTANDARD_EXTENSIONS)) {
        json_object_set_new(settings->server_capabilities,
                JMAP_CALENDARS_EXTENSION, json_object());

        for (mp = jmap_calendar_methods_nonstandard; mp->name; mp++) {
            hash_insert(mp->name, mp, &settings->methods);
        }
    }

    ptrarray_append(&settings->getblob_handlers, jmap_calendarevent_getblob);
}

HIDDEN void jmap_calendar_capabilities(json_t *account_capabilities)
{
    if (config_getswitch(IMAPOPT_JMAP_NONSTANDARD_EXTENSIONS)) {
        json_object_set_new(account_capabilities, JMAP_CALENDARS_EXTENSION, json_object());
    }
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

static json_t *get_schedule_address_set(const char *userid,
                                        const char *mboxname)
{
    struct buf attrib = BUF_INITIALIZER;
    json_t *val = json_array();
    static const char *annot =
        DAV_ANNOT_NS "<" XML_NS_CALDAV ">calendar-user-address-set";
    int r = annotatemore_lookupmask(mboxname, annot, httpd_userid, &attrib);
    if (r || !attrib.len) {
        // fetch from my own principal
        char *prinmbox = mboxname_user_mbox(httpd_userid, "#calendars");
        r = annotatemore_lookupmask(prinmbox, annot, httpd_userid, &attrib);
        free(prinmbox);
    }
    if (!r && attrib.len) {
        strarray_t *values = strarray_split(buf_cstring(&attrib), ",", STRARRAY_TRIM);
        int i;
        for (i = 0; i < strarray_size(values); i++) {
            const char *item = strarray_nth(values, i);
            if (!strncasecmp(item, "mailto:", 7)) item += 7;
            char *value = strconcat("mailto:", item, NULL);
            json_array_append_new(val, json_string(value));
            free(value);
        }
        strarray_free(values);
    }
    else if (strchr(userid, '@')) {
        char *value = strconcat("mailto:", userid, NULL);
        json_array_append_new(val, json_string(value));
        free(value);
    }
    else {
        const char *domain = httpd_extradomain ? httpd_extradomain : config_defdomain;
        char *value = strconcat("mailto:", userid, "@", domain, NULL);
        json_array_append_new(val, json_string(value));
        free(value);
    }
    buf_free(&attrib);
    return val;
}

static int getcalendars_cb(const mbentry_t *mbentry, void *vrock)
{
    struct getcalendars_rock *rock = vrock;
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
    r = annotatemore_lookupmask(mbentry->name, calcompset_annot,
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
        r = annotatemore_lookupmask(mbentry->name, displayname_annot,
                                    httpd_userid, &attrib);
        /* fall back to last part of mailbox name */
        if (r || !attrib.len) buf_setcstr(&attrib, id);
        json_object_set_new(obj, "name", json_string(buf_cstring(&attrib)));
        buf_free(&attrib);
    }

    if (jmap_wantprop(rock->get->props, "color")) {
        struct buf attrib = BUF_INITIALIZER;
        static const char *color_annot =
            DAV_ANNOT_NS "<" XML_NS_APPLE ">calendar-color";
        r = annotatemore_lookupmask(mbentry->name, color_annot,
                                    httpd_userid, &attrib);
        if (buf_len(&attrib))
            json_object_set_new(obj, "color", json_string(buf_cstring(&attrib)));
        buf_free(&attrib);
    }

    if (jmap_wantprop(rock->get->props, "sortOrder")) {
        long sort_order = 0;
        buf_reset(&attrib);
        static const char *order_annot =
            DAV_ANNOT_NS "<" XML_NS_APPLE ">calendar-order";
        r = annotatemore_lookupmask(mbentry->name, order_annot,
                                    httpd_userid, &attrib);
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
        r = annotatemore_lookupmask(mbentry->name, visible_annot,
                                    httpd_userid, &attrib);
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
        if (mboxname_userownsmailbox(httpd_userid, mbentry->name)) {
            /* Users always subscribe their own calendars */
            is_subscribed = 1;
        }
        else {
            /* Lookup mailbox subscriptions */
            is_subscribed = mboxlist_checksub(mbentry->name, httpd_userid) == 0;
        }
        json_object_set_new(obj, "isSubscribed", json_boolean(is_subscribed));
    }

    int writerights = JACL_ADDITEMS|JACL_SETMETADATA;

    if (jmap_wantprop(rock->get->props, "mayReadFreeBusy")) {
        json_object_set_new(obj, "mayReadFreeBusy",
                            ((rights & JACL_READFB) == JACL_READFB) ? json_true() : json_false());
    }

    if (jmap_wantprop(rock->get->props, "mayReadItems")) {
        json_object_set_new(obj, "mayReadItems",
                            ((rights & JACL_READITEMS) == JACL_READITEMS) ? json_true() : json_false());
    }

    if (jmap_wantprop(rock->get->props, "mayAddItems")) {
        json_object_set_new(obj, "mayAddItems",
                            ((rights & writerights) == writerights) ? json_true() : json_false());
    }

    if (jmap_wantprop(rock->get->props, "mayModifyItems")) {
        json_object_set_new(obj, "mayModifyItems",
                            ((rights & writerights) == writerights) ? json_true() : json_false());
    }

    if (jmap_wantprop(rock->get->props, "mayRemoveItems")) {
        json_object_set_new(obj, "mayRemoveItems",
                            ((rights & JACL_REMOVEITEMS) == JACL_REMOVEITEMS) ? json_true() : json_false());
    }

    if (jmap_wantprop(rock->get->props, "mayRename")) {
        json_object_set_new(obj, "mayRename",
                            ((rights & JACL_RENAME) == JACL_RENAME) ? json_true() : json_false());
    }

    if (jmap_wantprop(rock->get->props, "mayDelete")) {
        json_object_set_new(obj, "mayDelete",
                            ((rights & JACL_DELETE) == JACL_DELETE) ? json_true() : json_false());
    }

    if (jmap_wantprop(rock->get->props, "mayAdmin")) {
        json_object_set_new(obj, "mayAdmin",
                            ((rights & JACL_ADMIN) == JACL_ADMIN) ? json_true() : json_false());
    }

    if (jmap_wantprop(rock->get->props, "shareWith")) {
        json_t *sharewith = jmap_get_sharewith(mbentry);
        json_object_set_new(obj, "shareWith", sharewith);
    }

    if (jmap_wantprop(rock->get->props, "scheduleAddressSet")) {
        json_t *set = get_schedule_address_set(rock->req->userid, mbentry->name);
        json_object_set_new(obj, "scheduleAddressSet", set);
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
        "name",
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
        "mayReadFreeBusy",
        NULL,
        JMAP_PROP_SERVER_SET
    },
    {
        "mayReadItems",
        NULL,
        JMAP_PROP_SERVER_SET
    },
    {
        "mayAddItems",
        NULL,
        JMAP_PROP_SERVER_SET
    },
    {
        "mayModifyItems",
        NULL,
        JMAP_PROP_SERVER_SET
    },
    {
        "mayRemoveItems",
        NULL,
        JMAP_PROP_SERVER_SET
    },
    {
        "mayRename",
        NULL,
        JMAP_PROP_SERVER_SET
    },
    {
        "mayDelete",
        NULL,
        JMAP_PROP_SERVER_SET
    },

    /* FM extensions (do ALL of these get through to Cyrus?) */
    {
        "mayAdmin",
        JMAP_CALENDARS_EXTENSION,
        JMAP_PROP_SERVER_SET
    },
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
        "shareWith",
        JMAP_CALENDARS_EXTENSION,
        0
    },
    {
        "x-href",
        JMAP_CALENDARS_EXTENSION,
        JMAP_PROP_SERVER_SET
    },
    {
        "scheduleAddressSet",
        JMAP_CALENDARS_EXTENSION,
        0
    },

    { NULL, NULL, 0 }
};

static int has_calendars_cb(const mbentry_t *mbentry, void *rock)
{
    jmap_req_t *req = rock;
    if (mbtype_isa(mbentry->mbtype) == MBTYPE_CALENDAR &&
            jmap_hasrights_mbentry(req, mbentry, JACL_READITEMS)) {
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

    if (!has_calendars(req)) {
        jmap_error(req, json_pack("{s:s}", "type", "accountNoCalendars"));
        return 0;
    }

    /* Parse request */
    jmap_get_parse(req, &parser, calendar_props, /*allow_null_ids*/1,
                   NULL, NULL, &get, &err);
    if (err) {
        jmap_error(req, err);
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
    r = annotatemore_lookupmask(mbentry->name, calcompset_annot,
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

    if (!has_calendars(req)) {
        jmap_error(req, json_pack("{s:s}", "type", "accountNoCalendars"));
        return 0;
    }

    /* Parse request */
    jmap_changes_parse(req, &parser, req->counters.caldavfoldersdeletedmodseq,
                       NULL, NULL, &changes, &err);
    if (err) {
        jmap_error(req, err);
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

/* jmap calendar APIs */

struct setcalendar_props {
    const char *name;
    const char *color;
    int sortOrder;
    int isVisible;
    int isSubscribed;
    json_t *scheduleAddressSet;
    struct {
        json_t *With;
        int overwrite_acl;
    } share;
    long comp_types;
};              

/* Update the calendar properties in the calendar mailbox named mboxname.
 * NULL values and negative integers are ignored. Return 0 on success. */
static int setcalendars_update(jmap_req_t *req,
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
                mbox->name, error_message(r));
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
    /* scheduleAddressSet */
    if (!r && json_is_array(props->scheduleAddressSet)) {
        static const char *annot =
            DAV_ANNOT_NS "<" XML_NS_CALDAV ">calendar-user-address-set";
        strarray_t *array = strarray_new();
        size_t i;
        json_t *jval;
        json_array_foreach(props->scheduleAddressSet, i, jval) {
            strarray_add(array, json_string_value(jval));
        }
        char *joined = strarray_join(array, ",");
        buf_setcstr(&val, joined);
        r = annotate_state_writemask(astate, annot, req->userid, &val);
        if (r) {
            syslog(LOG_ERR, "failed to write annotation %s: %s",
                   annot, error_message(r));
        }
        free(joined);
        strarray_free(array);
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
    /* shareWith */
    if (!r && props->share.With) {
        r = jmap_set_sharewith(mbox,
                               props->share.With, props->share.overwrite_acl);
        if (!r) {
            char *userid = mboxname_to_userid(mbox->name);
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

    buf_free(&val);
    if (r) {
        mailbox_abort(mbox);
    }
    jmap_closembox(req, &mbox);
    return r;
}

/* Delete the calendar mailbox named mboxname for the userid in req. */
static int setcalendars_destroy(jmap_req_t *req, const char *mboxname)
{
    if (!jmap_hasrights(req, mboxname, JACL_READITEMS))
        return IMAP_NOTFOUND;
    if (!jmap_hasrights(req, mboxname, JACL_DELETE))
        return IMAP_PERMISSION_DENIED;

    char *userid = mboxname_to_userid(mboxname);
    struct caldav_db *db = caldav_open_userid(userid);
    if (!db) {
        syslog(LOG_ERR, "caldav_open_mailbox failed for user %s", userid);
        free(userid);
        return IMAP_INTERNAL;
    }
    /* XXX 
     * JMAP spec says that: "A calendar MAY be deleted that is currently
     * associated with one or more events. In this case, the events belonging
     * to this calendar MUST also be deleted. Conceptually, this MUST happen
     * prior to the calendar itself being deleted, and MUST generate a push
     * event that modifies the calendarState for the account, and has a
     * clientId of null, to indicate that a change has been made to the
     * calendar data not explicitly requested by the client."
     *
     * Need the Events API for this requirement.
     */
    int r = caldav_delmbox(db, mboxname);
    if (r) {
        syslog(LOG_ERR, "failed to delete mailbox from caldav_db: %s",
                error_message(r));
        free(userid);
        return r;
    }
    jmap_myrights_delete(req, mboxname);

    /* Remove from subscriptions db */
    mboxlist_changesub(mboxname, req->userid, req->authstate, 0, 1, 0);

    struct mboxevent *mboxevent = mboxevent_new(EVENT_MAILBOX_DELETE);
    if (mboxlist_delayed_delete_isenabled()) {
        r = mboxlist_delayed_deletemailbox(mboxname,
                httpd_userisadmin || httpd_userisproxyadmin,
                httpd_userid, req->authstate, mboxevent,
                MBOXLIST_DELETE_CHECKACL);
    } else {
        r = mboxlist_deletemailbox(mboxname,
                httpd_userisadmin || httpd_userisproxyadmin,
                httpd_userid, req->authstate, mboxevent,
                MBOXLIST_DELETE_CHECKACL);
    }
    mboxevent_free(&mboxevent);

    if (!r) r = caldav_update_shareacls(userid);

    int rr = caldav_close(db);
    if (!r) r = rr;

    free(userid);

    return r;
}

static int jmap_calendar_set(struct jmap_req *req)
{
    struct mboxlock *namespacelock = user_namespacelock(req->accountid);
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_set set;
    json_t *err = NULL;
    int r = 0;

    /* Parse arguments */
    jmap_set_parse(req, &parser, calendar_props, NULL, NULL, &set, &err);
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

    r = caldav_create_defaultcalendars(req->accountid);
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
    json_t *arg, *record;
    json_object_foreach(set.create, key, arg) {
        /* Validate calendar id. */
        if (!strlen(key)) {
            json_t *err= json_pack("{s:s}", "type", "invalidArguments");
            json_object_set_new(set.not_created, key, err);
            continue;
        }

        /* Parse and validate properties. */
        json_t *invalid = json_array(), *shareWith = NULL;
        const char *name = NULL;
        const char *color = NULL;
        int32_t sortOrder = 0;
        int isVisible = 1;
        int isSubscribed = 1;
        int pe; /* parse error */
        short flag;
        json_t *scheduleAddressSet = NULL;

        /* Mandatory properties. */
        pe = jmap_readprop(arg, "name", 1,  invalid, "s", &name);
        if (pe > 0 && strnlen(name, 256) == 256) {
            json_array_append_new(invalid, json_string("name"));
        }

        jmap_readprop(arg, "color", 0,  invalid, "s", &color);

        pe = jmap_readprop(arg, "sortOrder", 0,  invalid, "i", &sortOrder);
        if (pe > 0 && sortOrder < 0) {
            json_array_append_new(invalid, json_string("sortOrder"));
        }
        jmap_readprop(arg, "isVisible", 0,  invalid, "b", &isVisible);
        pe = jmap_readprop(arg, "isSubscribed", 0,  invalid, "b", &isSubscribed);
        if (pe > 0 && !strcmp(req->accountid, req->userid)) {
            if (!isSubscribed) {
                /* XXX unsubscribing own calendars isn't supported */
                json_array_append_new(invalid, json_string("isSubscribed"));
            }
            else {
                isSubscribed = -1; // ignore
            }
        }

        /* Optional properties. */
        jmap_readprop(arg, "shareWith", 0,  invalid, "o", &shareWith);

        jmap_readprop(arg, "scheduleAddressSet", 0,  invalid, "o", &scheduleAddressSet);

        /* Optional properties. If present, these MUST be set to true. */
        flag = 1; jmap_readprop(arg, "mayReadFreeBusy", 0,  invalid, "b", &flag);
        if (!flag) {
            json_array_append_new(invalid, json_string("mayReadFreeBusy"));
        }
        flag = 1; jmap_readprop(arg, "mayReadItems", 0,  invalid, "b", &flag);
        if (!flag) {
            json_array_append_new(invalid, json_string("mayReadItems"));
        }
        flag = 1; jmap_readprop(arg, "mayAddItems", 0,  invalid, "b", &flag);
        if (!flag) {
            json_array_append_new(invalid, json_string("mayAddItems"));
        }
        flag = 1; jmap_readprop(arg, "mayModifyItems", 0,  invalid, "b", &flag);
        if (!flag) {
            json_array_append_new(invalid, json_string("mayModifyItems"));
        }
        flag = 1; jmap_readprop(arg, "mayRemoveItems", 0,  invalid, "b", &flag);
        if (!flag) {
            json_array_append_new(invalid, json_string("mayRemoveItems"));
        }
        flag = 1; jmap_readprop(arg, "mayRename", 0,  invalid, "b", &flag);
        if (!flag) {
            json_array_append_new(invalid, json_string("mayRename"));
        }
        flag = 1; jmap_readprop(arg, "mayDelete", 0,  invalid, "b", &flag);
        if (!flag) {
            json_array_append_new(invalid, json_string("mayDelete"));
        }
        flag = 1; jmap_readprop(arg, "mayAdmin", 0,  invalid, "b", &flag);
        if (!flag) {
            json_array_append_new(invalid, json_string("mayAdmin"));
        }

        /* Report any property errors and bail out. */
        if (json_array_size(invalid)) {
            json_t *err = json_pack("{s:s, s:o}",
                                    "type", "invalidProperties",
                                    "properties", invalid);
            json_object_set_new(set.not_created, key, err);
            continue;
        }
        json_decref(invalid);

        /* Make sure we are allowed to create the calendar */
        char *parentname = caldav_mboxname(req->accountid, NULL);
        mbentry_t *mbparent = NULL;
        mboxlist_lookup(parentname, &mbparent, NULL);
        free(parentname);
        if (!jmap_hasrights_mbentry(req, mbparent, JACL_CREATECHILD)) {
            json_t *err = json_pack("{s:s}", "type", "accountReadOnly");
            json_object_set_new(set.not_created, key, err);
            mboxlist_entry_free(&mbparent);
            continue;
        }
        char *newacl = xstrdup("");
        char *acl = xstrdup(mbparent->acl);
        mboxlist_entry_free(&mbparent);

        /* keep just the owner and admin parts of the new ACL!  Everything
         * else will be added from share.With.  All this crap should be
         * modularised some more rather than open-coded, but here we go */
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
                r = cyrus_acl_set(&newacl, userid,
                                  ACL_MODE_SET, access, NULL, NULL);
                if (r) {
                    free(acl);
                    free(newacl);
                    syslog(LOG_ERR, "IOERROR: failed to set_acl for calendar create (%s, %s) %s",
                                    userid, req->accountid, error_message(r));
                    goto done;
                }
            }
        }
        free(acl);

        /* Create the calendar */
        char *uid = xstrdup(makeuuid());
        char *mboxname = caldav_mboxname(req->accountid, uid);
        r = mboxlist_createsync(mboxname, MBTYPE_CALENDAR,
                                NULL /* partition */,
                                httpd_userid, httpd_authstate,
                                /*options*/0, /*uidvalidity*/0,
                                0, 0, 0, newacl, /*uniqueid*/NULL,
                                /*localonly*/0, /*keep_intermediaries*/0,
                                /*mailboxptr*/NULL);
        free(newacl);
        if (r) {
            syslog(LOG_ERR, "IOERROR: failed to create %s (%s)",
                   mboxname, error_message(r));
            if (r == IMAP_PERMISSION_DENIED) {
                json_t *err = json_pack("{s:s}", "type", "accountReadOnly");
                json_object_set_new(set.not_created, key, err);
            }
            free(uid);
            free(mboxname);
            goto done;
        }
        struct setcalendar_props props = {
            name, color, sortOrder, isVisible, isSubscribed, scheduleAddressSet,
            { shareWith, /*overwrite_acl*/ 1}, config_types_to_caldav_types()
        };
        r = setcalendars_update(req, mboxname, &props, /*ignore_acl*/1);
        if (r) {
            free(uid);
            int rr = mboxlist_delete(mboxname);
            if (rr) {
                syslog(LOG_ERR, "could not delete mailbox %s: %s",
                       mboxname, error_message(rr));
            }
            free(mboxname);
            goto done;
        }

        /* Report calendar as created. */
        record = json_pack("{s:s}", "id", uid);

        /* Add additional properties */
        if (jmap_is_using(req, JMAP_CALENDARS_EXTENSION)) {
            json_t *addrset = get_schedule_address_set(req->userid, mboxname);
            if (addrset) json_object_set_new(record, "scheduleAddressSet", addrset);
        }

        json_object_set_new(set.created, key, record);
        jmap_add_id(req, key, uid);
        free(uid);
        free(mboxname);
    }

    /* update */
    const char *uid;
    json_object_foreach(set.update, uid, arg) {

        /* Validate uid */
        if (!uid) {
            continue;
        }
        if (uid && uid[0] == '#') {
            const char *newuid = jmap_lookup_id(req, uid + 1);
            if (!newuid) {
                json_t *err = json_pack("{s:s}", "type", "notFound");
                json_object_set_new(set.not_updated, uid, err);
                continue;
            }
            uid = newuid;
        }

        /* Parse and validate properties. */
        json_t *invalid = json_array(), *shareWith = NULL;

        char *mboxname = caldav_mboxname(req->accountid, uid);
        const char *name = NULL;
        const char *color = NULL;
        int32_t sortOrder = -1;
        int isVisible = -1;
        int isSubscribed = -1;
        int overwrite_acl = 1;
        int flag;
        json_t *scheduleAddressSet = NULL;
        int pe = 0; /* parse error */
        pe = jmap_readprop(arg, "name", 0,  invalid, "s", &name);
        if (pe > 0 && strnlen(name, 256) == 256) {
            json_array_append_new(invalid, json_string("name"));
        }
        jmap_readprop(arg, "color", 0,  invalid, "s", &color);
        pe = jmap_readprop(arg, "sortOrder", 0,  invalid, "i", &sortOrder);
        if (pe > 0 && sortOrder < 0) {
            json_array_append_new(invalid, json_string("sortOrder"));
        }
        jmap_readprop(arg, "isVisible", 0,  invalid, "b", &isVisible);
        pe = jmap_readprop(arg, "isSubscribed", 0,  invalid, "b", &isSubscribed);
        if (pe > 0 && !strcmp(req->accountid, req->userid)) {
            if (!isSubscribed) {
                /* XXX unsubscribing own calendars isn't supported */
                json_array_append_new(invalid, json_string("isSubscribed"));
            }
            else {
                isSubscribed = -1; // ignore
            }
        }

        /* Is shareWith overwritten or patched? */
        jmap_parse_sharewith_patch(arg, &shareWith);
        if (shareWith) {
            overwrite_acl = 0;
            json_object_set_new(arg, "shareWith", shareWith);
        }
        pe = jmap_readprop(arg, "shareWith", 0,  invalid, "o", &shareWith);
        if (pe > 0 && !jmap_hasrights(req, mboxname, JACL_ADMIN)) {
            json_array_append_new(invalid, json_string("shareWith"));
        }

        jmap_readprop(arg, "scheduleAddressSet", 0,  invalid, "o", &scheduleAddressSet);

        /* The mayFoo properties are immutable and MUST NOT set. */
        pe = jmap_readprop(arg, "mayReadFreeBusy", 0,  invalid, "b", &flag);
        if (pe > 0) {
            json_array_append_new(invalid, json_string("mayReadFreeBusy"));
        }
        pe = jmap_readprop(arg, "mayReadItems", 0,  invalid, "b", &flag);
        if (pe > 0) {
            json_array_append_new(invalid, json_string("mayReadItems"));
        }
        pe = jmap_readprop(arg, "mayAddItems", 0,  invalid, "b", &flag);
        if (pe > 0) {
            json_array_append_new(invalid, json_string("mayAddItems"));
        }
        pe = jmap_readprop(arg, "mayModifyItems", 0,  invalid, "b", &flag);
        if (pe > 0) {
            json_array_append_new(invalid, json_string("mayModifyItems"));
        }
        pe = jmap_readprop(arg, "mayRemoveItems", 0,  invalid, "b", &flag);
        if (pe > 0) {
            json_array_append_new(invalid, json_string("mayRemoveItems"));
        }
        pe = jmap_readprop(arg, "mayRename", 0,  invalid, "b", &flag);
        if (pe > 0) {
            json_array_append_new(invalid, json_string("mayRename"));
        }
        pe = jmap_readprop(arg, "mayDelete", 0,  invalid, "b", &flag);
        if (pe > 0) {
            json_array_append_new(invalid, json_string("mayDelete"));
        }

        /* Report any property errors and bail out. */
        if (json_array_size(invalid)) {
            json_t *err = json_pack("{s:s, s:o}",
                                    "type", "invalidProperties",
                                    "properties", invalid);
            json_object_set_new(set.not_updated, uid, err);
            free(mboxname);
            continue;
        }
        json_decref(invalid);

        /* Make sure we don't mess up special calendars */
        mbname_t *mbname = mbname_from_intname(mboxname);
        if (!mbname || jmap_calendar_isspecial(mbname)) {
            json_t *err = json_pack("{s:s}", "type", "notFound");
            json_object_set_new(set.not_updated, uid, err);
            mbname_free(&mbname);
            free(mboxname);
            continue;
        }
        mbname_free(&mbname);

        /* Update the calendar */
        struct setcalendar_props props = {
            name, color, sortOrder, isVisible, isSubscribed, scheduleAddressSet,
            { shareWith, overwrite_acl}, /*comp_types*/ -1
        };
        r = setcalendars_update(req, mboxname, &props, /*ignore_acl*/0);
        free(mboxname);
        if (r == IMAP_NOTFOUND || r == IMAP_MAILBOX_NONEXISTENT) {
            json_t *err = json_pack("{s:s}", "type", "notFound");
            json_object_set_new(set.not_updated, uid, err);
            r = 0;
            continue;
        }
        else if (r == IMAP_PERMISSION_DENIED) {
            json_t *err = json_pack("{s:s}", "type", "accountReadOnly");
            json_object_set_new(set.not_updated, uid, err);
            r = 0;
            continue;
        }

        /* Report calendar as updated. */
        json_object_set_new(set.updated, uid, json_null());
    }


    /* destroy */
    size_t index;
    json_t *juid;

    json_array_foreach(set.destroy, index, juid) {

        /* Validate uid */
        const char *uid = json_string_value(juid);
        if (!uid) {
            continue;
        }
        if (uid && uid[0] == '#') {
            const char *newuid = jmap_lookup_id(req, uid + 1);
            if (!newuid) {
                json_t *err = json_pack("{s:s}", "type", "notFound");
                json_object_set_new(set.not_destroyed, uid, err);
                continue;
            }
            uid = newuid;
        }

        /* Make sure we don't delete special calendars */
        char *mboxname = caldav_mboxname(req->accountid, uid);
        mbname_t *mbname = mbname_from_intname(mboxname);
        if (!mbname || jmap_calendar_isspecial(mbname)) {
            json_t *err = json_pack("{s:s}", "type", "notFound");
            json_object_set_new(set.not_destroyed, uid, err);
            mbname_free(&mbname);
            free(mboxname);
            continue;
        }
        mbname_free(&mbname);

        /* Destroy calendar. */
        r = setcalendars_destroy(req, mboxname);
        free(mboxname);
        if (r == IMAP_NOTFOUND || r == IMAP_MAILBOX_NONEXISTENT) {
            json_t *err = json_pack("{s:s}", "type", "notFound");
            json_object_set_new(set.not_destroyed, uid, err);
            r = 0;
            continue;
        } else if (r == IMAP_PERMISSION_DENIED) {
            json_t *err = json_pack("{s:s}", "type", "accountReadOnly");
            json_object_set_new(set.not_destroyed, uid, err);
            r = 0;
            continue;
        } else if (r) {
            goto done;
        }

        /* Report calendar as destroyed. */
        json_array_append_new(set.destroyed, json_string(uid));
    }


    // TODO refactor jmap_getstate to return a string, once
    // all code has been migrated to the new JMAP parser.
    json_t *jstate = jmap_getstate(req, MBTYPE_CALENDAR, /*refresh*/1);
    set.new_state = xstrdup(json_string_value(jstate));
    json_decref(jstate);

    jmap_ok(req, jmap_set_reply(&set));

done:
    mboxname_release(&namespacelock);
    jmap_parser_fini(&parser);
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
        mboxlist_lookup_by_uniqueid(mboxid, &freeme);
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
            struct buf buf = BUF_INITIALIZER;

            buf_setcstr(&buf, "text/calendar");
            if (comp_type) buf_printf(&buf, "; component=%s", comp_type);
            ctx->content_type = buf_release(&buf);
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
        struct buf buf = BUF_INITIALIZER;

        snprintf(boundary, sizeof(boundary), "%s-%ld-%ld-%ld",
                 *spool_getheader(req->txn->req_hdrs, ":authority"),
                 (long) getpid(), (long) time(0), (long) rand());

        buf_printf(&buf, "multipart/mixed; boundary=\"%s\"", boundary);
        ctx->content_type = buf_release(&buf);

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
        annotatemore_findall(mailbox->name, uid,
                             PER_USER_CAL_DATA, 0, _calendarevent_getblob_cb,
                             &rock, 0);

        /* Write close-delimiter and epilogue */
        buf_printf(blob, "\r\n--%s--\r\n%s", boundary, epilogue);
    }

    ctx->encoding = xstrdup("8BIT");

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
    hashu64_table jmapcache;
    ptrarray_t *want_eventids;
    int check_acl;
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

static void getcalendarevents_filterinstance(json_t *myevent,
                                             hash_table *props,
                                             const char *id,
                                             const char *ical_uid)
{
    json_object_del(myevent, "recurrenceOverrides");
    json_object_del(myevent, "recurrenceRule");
    jmap_filterprops(myevent, props);
    json_object_set_new(myevent, "id", json_string(id));
    json_object_set_new(myevent, "uid", json_string(ical_uid));
    json_object_set_new(myevent, "@type", json_string("jsevent"));
}

static int getcalendarevents_getinstances(json_t *jsevent,
                                           struct caldav_data *cdata,
                                           icalcomponent *ical,
                                           struct getcalendarevents_rock *rock)
{
    jmap_req_t *req = rock->req;
    icalcomponent *myical = NULL;
    int r = 0;

    int i;
    for (i = 0; i < ptrarray_size(rock->want_eventids); i++) {
        struct event_id *eid = ptrarray_nth(rock->want_eventids, i);

        if (eid->recurid == NULL) {
            /* Client requested main event */
            json_t *myevent = json_deep_copy(jsevent);
            jmap_filterprops(myevent, rock->get->props);
            json_object_set_new(myevent, "id", json_string(cdata->ical_uid));
            json_object_set_new(myevent, "uid", json_string(cdata->ical_uid));
            json_object_set_new(myevent, "@type", json_string("jsevent"));
            json_array_append_new(rock->get->list, myevent);
            continue;
        }

        /* Client requested event recurrence instance */
        json_t *override = json_object_get(
                json_object_get(jsevent, "recurrenceOverrides"), eid->recurid);
        if (override) {
            if (json_object_get(override, "excluded") != json_true()) {
                /* Instance is a recurrence override */
                json_t *myevent = jmap_patchobject_apply(jsevent, override, NULL);
                getcalendarevents_filterinstance(myevent, rock->get->props, eid->raw, cdata->ical_uid);
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
                if (!rock->mailbox || strcmp(rock->mailbox->name, cdata->dav.mailbox)) {
                    jmap_closembox(req, &rock->mailbox);
                    r = jmap_openmbox(req, cdata->dav.mailbox, &rock->mailbox, 0);
                    if (r) goto done;
                }
                myical = caldav_record_to_ical(rock->mailbox, cdata, httpd_userid, NULL);
                if (!myical) {
                    syslog(LOG_ERR, "caldav_record_to_ical failed for record %u:%s",
                            cdata->dav.imap_uid, rock->mailbox->name);
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
            getcalendarevents_filterinstance(myevent, rock->get->props, eid->raw, cdata->ical_uid);
            json_object_set_new(myevent, "start", jstart);
            json_object_set_new(myevent, "recurrenceId", json_string(eid->recurid));
            json_array_append_new(rock->get->list, myevent);
        }
    }

done:
    if (myical) icalcomponent_free(myical);
    return r;
}

static const char *find_participant_by_addr(json_t *participants, const char *addr)
{
    if (!strncasecmp(addr, "mailto:", 7)) addr += 7;

    const char *id;
    json_t *jpart;
    json_object_foreach(participants, id, jpart) {
        json_t *jsendTo = json_object_get(jpart, "sendTo");
        const char *val = json_string_value(json_object_get(jsendTo, "imip"));
        if (val && !strncasecmp(val, "mailto:", 7)) {
            val += 7;
        }
        else if (!val) {
            // email shouldn't be used for scheduling, but it allows
            // to identify the Participant by their email address
            val = json_string_value(json_object_get(jpart, "email"));
        }
        if (!strcasecmpsafe(val, addr)) {
            return id;
        }
    }

    return NULL;
}

static int getcalendarevents_cb(void *vrock, struct caldav_data *cdata)
{
    struct getcalendarevents_rock *rock = vrock;
    int r = 0;
    icalcomponent* ical = NULL;
    json_t *jsevent = NULL;
    jmap_req_t *req = rock->req;
    strarray_t schedule_addresses = STRARRAY_INITIALIZER;

    if (!cdata->dav.alive)
        return 0;

    /* Check component type and ACL */
    if (cdata->comp_type != CAL_COMP_VEVENT ||
       !jmap_hasrights(req, cdata->dav.mailbox, JACL_READITEMS)) {
        return 0;
    }

    if (cdata->jmapversion == JMAPCACHE_CALVERSION) {
        json_error_t jerr;
        jsevent = json_loads(cdata->jmapdata, 0, &jerr);
        if (jsevent) goto gotevent;
    }

    /* Open calendar mailbox. */
    if (!rock->mailbox || strcmp(rock->mailbox->name, cdata->dav.mailbox)) {
        jmap_closembox(req, &rock->mailbox);
        r = jmap_openmbox(req, cdata->dav.mailbox, &rock->mailbox, 0);
        if (r) goto done;
    }

    /* Load message containing the resource and parse iCal data */
    ical = caldav_record_to_ical(rock->mailbox, cdata, httpd_userid, &schedule_addresses);
    if (!ical) {
        syslog(LOG_ERR, "caldav_record_to_ical failed for record %u:%s",
                cdata->dav.imap_uid, rock->mailbox->name);
        r = IMAP_INTERNAL;
        goto done;
    }

    /* Convert to JMAP */
    jsevent = jmapical_tojmap(ical, NULL);
    if (!jsevent) {
        syslog(LOG_ERR, "jmapical_tojson: can't convert %u:%s",
                cdata->dav.imap_uid, rock->mailbox->name);
        r = IMAP_INTERNAL;
        goto done;
    }
    icalcomponent_free(ical);
    ical = NULL;

    /* Add participant id */
    json_t *jparticipants = json_object_get(jsevent, "participants");
    const char *participant_id = NULL;
    int i;
    for (i = 0; i < strarray_size(&schedule_addresses); i++) {
        participant_id = find_participant_by_addr(jparticipants,
                strarray_nth(&schedule_addresses, i));
        if (participant_id) break;
    }
    json_object_set_new(jsevent, "participantId", participant_id ?
            json_string(participant_id) : json_null());

    /* Add to cache */
    hashu64_insert(cdata->dav.rowid, json_dumps(jsevent, 0), &rock->jmapcache);

gotevent:

    /* Add JMAP-only fields. */
    if (jmap_wantprop(rock->get->props, "x-href")) {
        char *xhref = jmap_xhref(cdata->dav.mailbox, cdata->dav.resource);
        json_object_set_new(jsevent, "x-href", json_string(xhref));
        free(xhref);
    }
    if (jmap_wantprop(rock->get->props, "calendarId")) {
        json_object_set_new(jsevent, "calendarId",
                            json_string(strrchr(cdata->dav.mailbox, '.')+1));
    }

    unsigned want_blobId = jmap_wantprop(rock->get->props, "blobId");
    unsigned want_debugBlobId = jmap_wantprop(rock->get->props, "debugBlobId");
    if (want_blobId || want_debugBlobId) {
        struct buf blobid = BUF_INITIALIZER;
        const char *uniqueid = NULL;

        /* Get uniqueid of calendar mailbox */
        if (!rock->mailbox || strcmp(rock->mailbox->name, cdata->dav.mailbox)) {
            if (!rock->mbentry || strcmp(rock->mbentry->name, cdata->dav.mailbox)) {
                mboxlist_entry_free(&rock->mbentry);
                r = jmap_mboxlist_lookup(cdata->dav.mailbox, &rock->mbentry, NULL);
            }
            if (rock->mbentry) {
                uniqueid = rock->mbentry->uniqueid;
            }
        }
        else {
            uniqueid = rock->mailbox->uniqueid;
        }

        if (want_blobId) {
            json_t *jblobid = json_null();
            if (uniqueid &&
                jmap_encode_rawdata_blobid('I', uniqueid, cdata->dav.imap_uid,
                                           req->userid, NULL, NULL, &blobid)) {
                jblobid = json_string(buf_cstring(&blobid));
            }
            json_object_set_new(jsevent, "blobId", jblobid);
        }
        if (want_debugBlobId) {
            json_t *jblobid = json_null();
            if (httpd_userisadmin) {
                if (uniqueid &&
                    jmap_encode_rawdata_blobid('I', uniqueid, cdata->dav.imap_uid,
                                               NULL, NULL, NULL, &blobid)) {
                    jblobid = json_string(buf_cstring(&blobid));
                }
            }
            json_object_set_new(jsevent, "debugBlobId", jblobid);
        }

        buf_free(&blobid);
    }

    if (rock->want_eventids == NULL) {
        /* Client requested all events */
        jmap_filterprops(jsevent, rock->get->props);
        json_object_set_new(jsevent, "id", json_string(cdata->ical_uid));
        json_object_set_new(jsevent, "uid", json_string(cdata->ical_uid));
        json_object_set_new(jsevent, "@type", json_string("jsevent"));
        json_array_append_new(rock->get->list, jsevent);
    }
    else {
        /* Client requested specific event ids */
        r = getcalendarevents_getinstances(jsevent, cdata, ical, rock);
        json_decref(jsevent);
        if (r) goto done;
    }

done:
    strarray_fini(&schedule_addresses);
    if (ical) icalcomponent_free(ical);
    return r;
}

static const jmap_property_t event_props[] = {
    {
        "id",
        NULL,
        JMAP_PROP_IMMUTABLE | JMAP_PROP_ALWAYS_GET
    },
    {
        "calendarId",
        NULL,
        0
    },
    {
        "participantId",
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
        "recurrenceRule",
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
    caldav_write_jmapcache(rock->db, rowid, httpd_userid,
                           JMAPCACHE_CALVERSION, eventrep);
}

static int jmap_calendarevent_get(struct jmap_req *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_get get;
    struct caldav_db *db = NULL;
    json_t *err = NULL;
    int r = 0;

    if (!has_calendars(req)) {
        jmap_error(req, json_pack("{s:s}", "type", "accountNoCalendars"));
        return 0;
    }

    /* Build callback data */
    int checkacl = strcmp(req->accountid, req->userid);
    struct getcalendarevents_rock rock = { NULL /* db */,
                                           req, &get,
                                           NULL /* mbox */,
                                           NULL /* mbentry */,
                                           HASHU64_TABLE_INITIALIZER, /* cache */
                                           NULL, /* want_eventids */
                                           checkacl };

    construct_hashu64_table(&rock.jmapcache, 512, 0);

    /* Parse request */
    jmap_get_parse(req, &parser, event_props, /*allow_null_ids*/1,
                   NULL, NULL, &get, &err);
    if (err) {
        jmap_error(req, err);
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
            r = caldav_get_events(db, httpd_userid, NULL, uid, &getcalendarevents_cb, &rock);
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
        r = caldav_get_events(db, httpd_userid, NULL, NULL, &getcalendarevents_cb, &rock);
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
    if (db) caldav_close(db);
    if (rock.mailbox) jmap_closembox(req, &rock.mailbox);
    if (rock.mbentry) mboxlist_entry_free(&rock.mbentry);
    free_hashu64_table(&rock.jmapcache, free);
    return r;
}

static int setcalendarevents_schedule(jmap_req_t *req,
                                      const char *mboxname,
                                      strarray_t *schedule_addresses,
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

    get_schedule_addresses(req->txn->req_hdrs, mboxname,
                           req->userid, schedule_addresses);

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

static const char *validate_participant_id(json_t *event,
                                           strarray_t *schedule_addresses,
                                           json_t *invalid)
{
    json_t *jparticipantId = json_object_get(event, "participantId");
    if (json_is_string(jparticipantId)) {
        const char *participant_id = json_string_value(jparticipantId);
        json_t *jparticipants = json_object_get(event, "participants");
        json_t *jpart = json_object_get(jparticipants, participant_id);

        json_t *jsendTo = json_object_get(jpart, "sendTo");
        const char *val = json_string_value(json_object_get(jsendTo, "imip"));
        if (val && !strncasecmp(val, "mailto:", 7)) {
            val += 7;
        }
        else if (!val) {
            // email shouldn't be used for scheduling, but it allows
            // to identify the Participant by their email address
            val = json_string_value(json_object_get(jpart, "email"));
        }
        if (val && *val) {
            /* Found the participant. Reset schedule address. */
            strarray_addfirst_case(schedule_addresses, val);
            return participant_id;
        }
        else {
            json_array_append_new(invalid, json_string("participantId"));
        }
    }
    else if (JNOTNULL(jparticipantId)) {
        json_array_append_new(invalid, json_string("participantId"));
    }
    return NULL;
}


static int setcalendarevents_create(jmap_req_t *req,
                                    const char *account_id,
                                    json_t *event,
                                    struct caldav_db *db,
                                    json_t *invalid,
                                    json_t *create)
{
    int r, pe;
    int needrights = JACL_ADDITEMS|JACL_SETMETADATA;
    char *uid = NULL;

    struct mailbox *mbox = NULL;
    char *mboxname = NULL;
    char *resource = NULL;

    icalcomponent *ical = NULL;
    const char *calendarId = NULL;
    strarray_t schedule_addresses = STRARRAY_INITIALIZER;

    if ((uid = (char *) json_string_value(json_object_get(event, "uid")))) {
        /* Use custom iCalendar UID from request object */
        uid = xstrdup(uid);
    }  else {
        /* Create a iCalendar UID */
        uid = xstrdup(makeuuid());
    }

    /* Validate calendarId */
    pe = jmap_readprop(event, "calendarId", 1, invalid, "s", &calendarId);
    if (pe > 0 && *calendarId &&*calendarId == '#') {
        calendarId = jmap_lookup_id(req, calendarId + 1);
        if (!calendarId) {
            json_array_append_new(invalid, json_string("calendarId"));
        }
    }
    if (json_array_size(invalid)) {
        free(uid);
        return 0;
    }

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
        json_array_append_new(invalid, json_string("calendarId"));
        r = 0; goto done;
    }

    /* Open mailbox for writing */
    r = jmap_openmbox(req, mboxname, &mbox, 1);
    if (r) {
        syslog(LOG_ERR, "jmap_openmbox(req, %s) failed: %s", mboxname, error_message(r));
        if (r == IMAP_MAILBOX_NONEXISTENT) {
            json_array_append_new(invalid, json_string("calendarId"));
            r = 0;
        }
        goto done;
    }

    /* Convert the JMAP calendar event to ical. */
    if (!json_object_get(event, "uid")) {
        json_object_set_new(event, "uid", json_string(uid));
    }

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
    ical = jmapical_toical(event, NULL, invalid);

    // check that participantId is either not present or is a valid participant
    validate_participant_id(event, &schedule_addresses, invalid);

    if (json_array_size(invalid)) {
        r = 0;
        goto done;
    } else if (!ical) {
        r = IMAP_INTERNAL;
        goto done;
    }

    /* Handle scheduling. */
    r = setcalendarevents_schedule(req, mboxname, &schedule_addresses,
                                   NULL, ical, JMAP_CREATE);
    if (r) goto done;

    /* Remove METHOD property */
    remove_itip_properties(ical);

    /* Store the VEVENT. */
    struct transaction_t txn;
    memset(&txn, 0, sizeof(struct transaction_t));
    txn.req_hdrs = spool_new_hdrcache();
    /* XXX - fix userid */

    /* Locate the mailbox */
    r = proxy_mlookup(mbox->name, &txn.req_tgt.mbentry, NULL, NULL);
    if (r) {
        syslog(LOG_ERR, "mlookup(%s) failed: %s", mbox->name, error_message(r));
    }
    else {
        r = caldav_store_resource(&txn, ical, mbox, resource, 0,
                                  db, 0, httpd_userid, &schedule_addresses);
    }
    mboxlist_entry_free(&txn.req_tgt.mbentry);
    spool_free_hdrcache(txn.req_hdrs);
    buf_free(&txn.buf);
    if (r && r != HTTP_CREATED && r != HTTP_NO_CONTENT) {
        syslog(LOG_ERR, "caldav_store_resource failed for user %s: %s",
               req->accountid, error_message(r));
        goto done;
    }
    r = 0;
    json_object_set_new(create, "uid", json_string(uid));

    char *xhref = jmap_xhref(mbox->name, resource);
    json_object_set_new(create, "x-href", json_string(xhref));
    free(xhref);

    if (jmap_is_using(req, JMAP_CALENDARS_EXTENSION)) {
        struct buf blobid = BUF_INITIALIZER;
        if (jmap_encode_rawdata_blobid('I', mbox->uniqueid, mbox->i.last_uid,
                                       req->userid, NULL, NULL, &blobid)) {
            json_object_set_new(create, "blobId",
                                json_string(buf_cstring(&blobid)));
        }
        buf_reset(&blobid);
        if (jmap_encode_rawdata_blobid('I', mbox->uniqueid, mbox->i.last_uid,
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
    free(resource);
    free(mboxname);
    free(uid);
    return r;
}

static int eventpatch_updates_peruserprops_only(json_t *jdiff, const char *participant_id)
{
    strarray_t userprops = STRARRAY_INITIALIZER;
    if (participant_id) {
        strarray_appendm(&userprops,
                strconcat("participants/", participant_id, "/participationStatus", NULL));
        strarray_appendm(&userprops,
                strconcat("participants/", participant_id, "/participationComment", NULL));
        strarray_appendm(&userprops,
                strconcat("participants/", participant_id, "/expectReply", NULL));
    }

    const char *prop;
    json_t *jval;
    int ret = 1;
    void *tmp;

    json_object_foreach_safe(jdiff, tmp, prop, jval) {
        if (!strcmp(prop, "recurrenceOverrides")) {
            const char *recurid;
            json_t *joverride;
            json_object_foreach(jval, recurid, joverride) {
                if (!eventpatch_updates_peruserprops_only(joverride, participant_id)) {
                    ret = 0;
                    goto done;
                }
            }
            continue;
        }
        else if (!strcmp(prop, "participants")) {
            /* Patches *all* participants */
            ret = 0;
            goto done;
        }
        else if (!strncmp(prop, "recurrenceOverrides/", 20)) {
            /* Does prop point *into* an override? */
            const char *p = strchr(prop + 21, '/');
            if (!p) {
                /* Override value is a JSON object */
                if (!eventpatch_updates_peruserprops_only(jval, participant_id)) {
                    ret = 0;
                    goto done;
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
            (!participant_id || strarray_find(&userprops, prop, 0) < 0)) {
            /* Patches some non-user property */
            ret = 0;
            goto done;
        }
    }

done:
    strarray_fini(&userprops);
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

static int setcalendarevents_apply_patch(json_t *event_patch,
                                         icalcomponent *oldical,
                                         const char *recurid,
                                         json_t *invalid,
                                         strarray_t *schedule_addresses,
                                         icalcomponent **newical,
                                         json_t *update,
                                         json_t **err)
{
    json_t *old_event = NULL;
    json_t *new_event = NULL;
    int r = 0;

    old_event = jmapical_tojmap(oldical, NULL);
    if (!old_event) {
        r = IMAP_INTERNAL;
        goto done;
    }
    json_object_del(old_event, "updated");

    /* Add participant id to old_event */
    json_t *jparticipants = json_object_get(old_event, "participants");
    const char *participant_id = NULL;
    int i;
    for (i = 0; i < strarray_size(schedule_addresses); i++) {
        participant_id = find_participant_by_addr(jparticipants,
                    strarray_nth(schedule_addresses, i));
        if (participant_id) break;
    }
    json_object_set_new(old_event, "participantId", participant_id ?
            json_string(participant_id) : json_null());

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
        json_object_del(new_instance, "recurrenceRule");
        json_object_del(new_instance, "recurrenceOverrides");
        new_override = jmap_patchobject_create(old_event, new_instance);
        json_object_del(new_override, "@type");
        json_object_del(new_override, "method");
        json_object_del(new_override, "prodId");
        json_object_del(new_override, "recurrenceId");
        json_object_del(new_override, "recurrenceRule");
        json_object_del(new_override, "recurrenceOverrides");
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
            /* The happy path - just apply the patch as provided */
            new_event = jmap_patchobject_apply(old_event, event_patch, invalid);
            if (!new_event) {
                *err = json_pack("{s:s}", "type", "invalidPatch");
                goto done;
            }
        }
    }

    // check that participantId is either not present or is a valid participant
    participant_id = validate_participant_id(new_event, schedule_addresses, invalid);

    /* Determine if to bump sequence */
    json_t *jdiff = jmap_patchobject_create(old_event, new_event);
    json_object_del(jdiff, "updated");
    if (!eventpatch_updates_peruserprops_only(jdiff, participant_id)) {
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
    *newical = jmapical_toical(new_event, oldical, invalid);

done:
    json_decref(new_event);
    json_decref(old_event);
    return r;
}

static int setcalendarevents_update(jmap_req_t *req,
                                    json_t *event_patch,
                                    struct event_id *eid,
                                    struct caldav_db *db,
                                    json_t *invalid,
                                    json_t *update,
                                    json_t **err)
{
    int r, pe;
    int needrights = JACL_UPDATEITEMS|JACL_SETMETADATA;

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
    const char *calendarId = NULL;
    strarray_t schedule_addresses = STRARRAY_INITIALIZER;

    /* Validate calendarId */
    pe = jmap_readprop(event_patch, "calendarId", 0, invalid, "s", &calendarId);
    if (pe > 0 && *calendarId && *calendarId == '#') {
        calendarId = jmap_lookup_id(req, calendarId + 1);
        if (!calendarId) {
            json_array_append_new(invalid, json_string("calendarId"));
        }
    }
    if (json_array_size(invalid)) {
        r = 0;
        goto done;
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
    mboxname = xstrdup(cdata->dav.mailbox);
    resource = xstrdup(cdata->dav.resource);

    /* Check permissions. */
    if (!jmap_hasrights(req, mboxname, needrights)) {
        json_array_append_new(invalid, json_string("calendarId"));
        r = 0;
        goto done;
    }

    /* Open mailbox for writing */
    r = jmap_openmbox(req, mboxname, &mbox, 1);
    if (r == IMAP_MAILBOX_NONEXISTENT) {
        json_array_append_new(invalid, json_string("calendarId"));
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
        json_array_append_new(invalid, json_string("calendarId"));
        r = 0;
        goto done;
    } else if (r) {
        syslog(LOG_ERR, "mailbox_index_record(0x%x) failed: %s",
                cdata->dav.imap_uid, error_message(r));
        goto done;
    }
    /* Load VEVENT from record, personalizing as needed. */
    oldical = caldav_record_to_ical(mbox, cdata, httpd_userid, &schedule_addresses);
    if (!oldical) {
        syslog(LOG_ERR, "record_to_ical failed for record %u:%s",
                cdata->dav.imap_uid, mbox->name);
        r = IMAP_INTERNAL;
        goto done;
    }
    /* Apply patch */
    r = setcalendarevents_apply_patch(event_patch, oldical, eid->recurid,
                                      invalid, &schedule_addresses, &ical, update, err);
    if (json_array_size(invalid)) {
        r = 0;
        goto done;
    }
    else if (r) goto done;

    if (calendarId) {
        /* Check, if we need to move the event. */
        dstmboxname = caldav_mboxname(req->accountid, calendarId);
        if (strcmp(mbox->name, dstmboxname)) {
            /* Check permissions */
            if (!jmap_hasrights(req, dstmboxname, needrights)) {
                json_array_append_new(invalid, json_string("calendarId"));
                r = 0;
                goto done;
            }
            /* Open destination mailbox for writing. */
            r = jmap_openmbox(req, dstmboxname, &dstmbox, 1);
            if (r == IMAP_MAILBOX_NONEXISTENT) {
                json_array_append_new(invalid, json_string("calendarId"));
                r = 0;
                goto done;
            } else if (r) {
                syslog(LOG_ERR, "jmap_openmbox(req, %s) failed: %s",
                        dstmboxname, error_message(r));
                goto done;
            }
        }
    }

    /* Handle scheduling. */
    r = setcalendarevents_schedule(req, mboxname, &schedule_addresses,
                                   oldical, ical, JMAP_UPDATE);
    if (r) goto done;


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
    /* XXX - fix userid */
    r = proxy_mlookup(mbox->name, &txn.req_tgt.mbentry, NULL, NULL);
    if (r) {
        syslog(LOG_ERR, "mlookup(%s) failed: %s", mbox->name, error_message(r));
    }
    else {
        r = caldav_store_resource(&txn, ical, mbox, resource, record.createdmodseq,
                                  db, 0, httpd_userid, &schedule_addresses);
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
        if (jmap_encode_rawdata_blobid('I', mbox->uniqueid, mbox->i.last_uid,
                                       req->userid, NULL, NULL, &blobid)) {
            json_object_set_new(update, "blobId",
                                json_string(buf_cstring(&blobid)));
        }
        buf_reset(&blobid);
        if (jmap_encode_rawdata_blobid('I', mbox->uniqueid, mbox->i.last_uid,
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
    strarray_fini(&schedule_addresses);
    free(dstmboxname);
    free(resource);
    free(mboxname);
    return r;
}

static int setcalendarevents_destroy(jmap_req_t *req,
                                     struct event_id *eid,
                                     struct caldav_db *db)
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

    if (eid->recurid) {
        /* Destroying a recurrence instance is setting it excluded */
        json_t *event_patch = json_pack("{s:b}", "excluded", 1);
        json_t *invalid = json_array();
        json_t *update = NULL;
        json_t *err = NULL;
        r = setcalendarevents_update(req, event_patch, eid, db, invalid, update, &err);
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
    mboxname = xstrdup(cdata->dav.mailbox);
    resource = xstrdup(cdata->dav.resource);

    /* Check permissions. */
    if (!jmap_hasrights(req, mboxname, JACL_READITEMS)) {
        r = IMAP_NOTFOUND;
        goto done;
    }
    if (!jmap_hasrights(req, mboxname, needrights)) {
        r = IMAP_PERMISSION_DENIED;
        goto done;
    }

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
                cdata->dav.imap_uid, mbox->name);
        r = IMAP_INTERNAL;
        goto done;
    }

    /* Handle scheduling. */
    r = setcalendarevents_schedule(req, mboxname, &schedule_addresses,
                                   oldical, ical, JMAP_DESTROY);
    if (r) goto done;


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

done:
    if (mbox) jmap_closembox(req, &mbox);
    if (oldical) icalcomponent_free(oldical);
    strarray_fini(&schedule_addresses);
    free(resource);
    free(mboxname);
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


static int jmap_calendarevent_set(struct jmap_req *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_set set;
    json_t *err = NULL;
    struct caldav_db *db = NULL;
    struct event_id *eid = NULL;
    const char *id;
    int r = 0;

    /* Parse arguments */
    jmap_set_parse(req, &parser, event_props, NULL, NULL, &set, &err);
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

    r = caldav_create_defaultcalendars(req->accountid);
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
        r = setcalendarevents_create(req, req->accountid, arg, db, invalid, create);
        if (r) {
            json_t *err;
            switch (r) {
                case HTTP_FORBIDDEN:
                case IMAP_PERMISSION_DENIED:
                    err = json_pack("{s:s}", "type", "forbidden");
                    break;
                case IMAP_QUOTA_EXCEEDED:
                    err = json_pack("{s:s}", "type", "overQuota");
                    break;
                default:
                    err = jmap_server_error(r);
            }
            json_object_set_new(set.not_created, key, err);
            json_decref(create);
            r = 0;
            continue;
        }
        if (json_array_size(invalid)) {
            json_t *err = json_pack("{s:s s:o}",
                                    "type", "invalidProperties",
                                    "properties", invalid);
            json_object_set_new(set.not_created, key, err);
            json_decref(create);
            continue;
        }
        json_decref(invalid);

        /* Report calendar event as created. */
        const char *uid = json_string_value(json_object_get(create, "uid"));
        json_object_set_new(create, "id", json_string(uid));
        json_object_set_new(set.created, key, create);
        jmap_add_id(req, key, uid);
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
        r = setcalendarevents_update(req, arg, eid, db, invalid, update, &err);
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
        r = setcalendarevents_destroy(req, eid, db);
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

    /* Check permissions */
    if (!jmap_hasrights(req, cdata->dav.mailbox, JACL_READITEMS))
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
    r = caldav_get_updates(db, changes.since_modseq, NULL /*mboxname*/,
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
};

static int eventquery_cb(void *vrock, struct caldav_data *cdata)
{
    struct eventquery_rock *rock = vrock;
    jmap_req_t *req = rock->req;

    if (!cdata->dav.alive || cdata->comp_type != CAL_COMP_VEVENT) {
        return 0;
    }
    if (!jmap_hasrights(rock->req, cdata->dav.mailbox, JACL_READITEMS)) {
        return 0;
    }

    struct eventquery_match *match = xzmalloc(sizeof(struct eventquery_match));
    match->ical_uid = xstrdup(cdata->ical_uid);
    match->utcstart = xstrdup(cdata->dtstart);
    if (rock->expandrecur) {
        /* Load iCalendar data */
        if (!rock->mailbox || strcmp(rock->mailbox->name, cdata->dav.mailbox)) {
            if (rock->mailbox) {
                jmap_closembox(req, &rock->mailbox);
            }
            int r = jmap_openmbox(req, cdata->dav.mailbox, &rock->mailbox, 0);
            if (r) return r;
        }
        match->ical = caldav_record_to_ical(rock->mailbox, cdata, req->userid, NULL);
        if (!match->ical) {
            syslog(LOG_ERR, "%s: can't load ical for ical uid %s",
                    __func__, cdata->ical_uid);
            eventquery_match_free(&match);
            return IMAP_INTERNAL;
        }
    }
    ptrarray_append(rock->matches, match);

    return 0;
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

    char *mboxname = mboxname_user_mbox(req->accountid, "#calendars");
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
        if (!folder || !jmap_hasrights(req, folder->mboxname, JACL_READITEMS)) {
            continue;
        }

        struct caldav_data *cdata;
        if (caldav_lookup_imapuid(db, folder->mboxname, md->uid, &cdata, 0) == 0) {

            /* Check time-range */
            if (icalafter && strcmp(cdata->dtend, icalafter) <= 0)
                continue;
            if (icalbefore && strcmp(cdata->dtstart, icalbefore) >= 0)
                continue;

            if (wantuid && strcmp(wantuid, cdata->ical_uid))
                continue;

            struct eventquery_match *match = xzmalloc(sizeof(struct eventquery_match));
            match->ical_uid = xstrdup(cdata->ical_uid);
            match->utcstart = xstrdup(cdata->dtstart);
            if (expandrecur) {
                /* Load iCalendar data */
                if (!mailbox || strcmp(mailbox->name, cdata->dav.mailbox)) {
                    if (mailbox) {
                        jmap_closembox(req, &mailbox);
                    }
                    r = jmap_openmbox(req, cdata->dav.mailbox, &mailbox, 0);
                    if (r) goto done;
                }

                match->ical = caldav_record_to_ical(mailbox, cdata, req->userid, NULL);
                if (!match->ical) {
                    syslog(LOG_ERR, "%s: can't load ical for ical uid %s",
                           __func__, cdata->ical_uid);
                    free(match->ical_uid);
                    free(match->utcstart);
                    free(match);
                    r = IMAP_INTERNAL;
                    goto done;
                }
            }
            ptrarray_append(matches, match);
        }
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
};

static int eventquery_fastpath_cb(void *rock, struct caldav_data *cdata)
{
    jmap_req_t *req = ((struct eventquery_fastpath_rock*)rock)->req;
    struct jmap_query *query = ((struct eventquery_fastpath_rock*)rock)->query;

    assert(query->position >= 0);

    /* Check type and permissions */
    if (!cdata->dav.alive || cdata->comp_type != CAL_COMP_VEVENT) {
        return 0;
    }
    if (!jmap_hasrights(req, cdata->dav.mailbox, JACL_READITEMS)) {
        return 0;
    }

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
    icaltimezone *utc = icaltimezone_get_utc_timezone();
    icaltimetype utcstart = icaltime_convert_to_zone(start, utc);

    struct eventquery_match *match = xzmalloc(sizeof(struct eventquery_match));
    match->ical_uid = xstrdup(icalcomponent_get_uid(comp));
    match->utcstart = xstrdup(icaltime_as_ical_string(utcstart));
    match->recurid = xstrdup(eventquery_recur_make_recurid(comp, start, rock->buf));
    ptrarray_append(rock->matches, match);

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
        struct eventquery_fastpath_rock rock = { req, query };
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
                                  sort, nsort, expandrecur, &matches);
        if (r) goto done;
    }
    else {
        /* Query and sort matches in Caldav DB. */
        struct eventquery_rock rock = { req, expandrecur, NULL, &matches };
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
                struct eventquery_recur_rock rock = { &mymatches, &buf };
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
    ptrarray_fini(&matches);
    free(sort);
    return r;
}

static void validatefilter(jmap_req_t *req __attribute__((unused)),
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

static int validatecomparator(jmap_req_t *req __attribute__((unused)),
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
                     validatefilter, NULL,
                     validatecomparator, NULL,
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
    int r = 0;

    /* Read mandatory properties */
    const char *src_id = json_string_value(json_object_get(jevent, "id"));
    const char *dst_calendar_id = json_string_value(json_object_get(jevent, "calendarId"));
    if (!src_id) {
        jmap_parser_invalid(&myparser, "id");
    }
    if (!dst_calendar_id) {
        jmap_parser_invalid(&myparser, "calendarId");
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
    if (!jmap_hasrights(req, cdata->dav.mailbox, JACL_READITEMS)) {
        *set_err = json_pack("{s:s}", "type", "notFound");
        goto done;
    }

    /* Read source event */
    r = jmap_openmbox(req, cdata->dav.mailbox, &src_mbox, /*rw*/0);
    if (r) goto done;
    src_ical = caldav_record_to_ical(src_mbox, cdata, httpd_userid, &schedule_addresses);
    if (!src_ical) {
        syslog(LOG_ERR, "calendarevent_copy: can't convert %s to JMAP", src_id);
        r = IMAP_INTERNAL;
        goto done;
    }

    /* Patch JMAP event */
    json_t *src_event = jmapical_tojmap(src_ical, NULL);
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
    *new_event = json_object();
    r = setcalendarevents_create(req, req->accountid, dst_event,
                                 dst_db, invalid, *new_event);
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
    jmap_closembox(req, &src_mbox);
    strarray_fini(&schedule_addresses);
    if (src_ical) icalcomponent_free(src_ical);
    json_decref(dst_event);
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

    /* Process request */
    const char *creation_id;
    json_t *jevent;
    json_object_foreach(copy.create, creation_id, jevent) {
        /* Copy event */
        json_t *set_err = NULL;
        json_t *new_event = NULL;

        _calendarevent_copy(req, jevent, src_db, dst_db, &new_event, &set_err);
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
    jmap_getblob_context_t ctx;
    jmap_getblob_ctx_init(&ctx, NULL, NULL, "text/calendar", 1);

    json_t *jval;
    size_t i;
    json_array_foreach(parse.blob_ids, i, jval) {
        const char *blobid = json_string_value(jval);
        icalcomponent *ical = NULL;
        json_t *event = NULL;
        int r = 0;

        if (!blobid) continue;

        /* Find blob */
        ctx.blobid = blobid;
        if (blobid[0] == '#') {
            ctx.blobid = jmap_lookup_id(req, blobid + 1);
            if (!ctx.blobid) {
                json_array_append_new(parse.not_found, json_string(blobid));
                continue;
            }
        }

        buf_reset(&ctx.blob);
        r = jmap_getblob(req, &ctx);
        if (r) {
            json_array_append_new(parse.not_found, json_string(blobid));
            continue;
        }

        ical = icalparser_parse_string(buf_cstring(&ctx.blob));
        if (ical) {
            event = jmapical_tojmap(ical, props);
            icalcomponent_free(ical);
        }

        if (event) {
            json_object_set_new(parse.parsed, blobid, event);
        }
        else {
            json_array_append_new(parse.not_parsable, json_string(blobid));
        }
    }

    jmap_getblob_ctx_fini(&ctx);

    /* Build response */
    jmap_ok(req, jmap_parse_reply(&parse));

done:
    jmap_parser_fini(&parser);
    jmap_parse_fini(&parse);
    free_hash_table(props, NULL);
    free(props);
    return 0;
}
