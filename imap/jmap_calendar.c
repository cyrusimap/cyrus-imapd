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
#include <assert.h>
#include <string.h>
#include <syslog.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "annotate.h"
#include "caldav_db.h"
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
#include "stristr.h"
#include "times.h"
#include "util.h"
#include "xmalloc.h"

/* generated headers are not necessarily in current directory */
#include "imap/http_err.h"
#include "imap/imap_err.h"

static int getCalendars(struct jmap_req *req);
static int getCalendarsUpdates(struct jmap_req *req);
static int setCalendars(struct jmap_req *req);
static int getCalendarEvents(struct jmap_req *req);
static int getCalendarEventsUpdates(struct jmap_req *req);
static int getCalendarEventsList(struct jmap_req *req);
static int setCalendarEvents(struct jmap_req *req);
static int getCalendarPreferences(struct jmap_req *req);

jmap_method_t jmap_calendar_methods[] = {
    { "Calendar/get",             &getCalendars },
    { "Calendar/changes",         &getCalendarsUpdates },
    { "Calendar/set",             &setCalendars },
    { "CalendarEvent/get",        &getCalendarEvents },
    { "CalendarEvent/changes",    &getCalendarEventsUpdates },
    { "CalendarEvent/query",      &getCalendarEventsList },
    { "CalendarEvent/set",        &setCalendarEvents },
    { "CalendarPreference/get",   &getCalendarPreferences },
    { NULL,                       NULL}
};

int jmap_calendar_init(hash_table *methods, json_t *capabilities __attribute__((unused)))
{
    jmap_method_t *mp;
    for (mp = jmap_calendar_methods; mp->name; mp++) {
        hash_insert(mp->name, mp, methods);
    }
    return 0;
}

static int _wantprop(hash_table *props, const char *name)
{
    if (!props) return 1;
    if (hash_lookup(name, props)) return 1;
    return 0;
}

static int JNOTNULL(json_t *item)
{
   if (!item) return 0;
   if (json_is_null(item)) return 0;
   return 1;
}

static int readprop_full(json_t *root,
                         const char *prefix,
                         const char *name,
                         int mandatory,
                         json_t *invalid,
                         const char *fmt,
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

#define readprop(root, name,  mandatory, invalid, fmt, dst) \
    readprop_full((root), NULL, (name), (mandatory), (invalid), (fmt), (dst))

/* Helper flags for setCalendarEvents */
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
    json_t *found;
    struct hash_table *props;
    struct mailbox *mailbox;
    int skip_hidden;
};

static int getcalendars_cb(const mbentry_t *mbentry, void *vrock)
{
    struct getcalendars_rock *rock = vrock;
    mbname_t *mbname = NULL;
    int r = 0;

    /* Only calendars... */
    if (!(mbentry->mbtype & MBTYPE_CALENDAR)) return 0;

    /* ...which are at least readable or visible... */
    int rights = jmap_myrights(rock->req, mbentry);
    if ((rights & DACL_READ) != DACL_READ) {
        return rock->skip_hidden ? 0 : IMAP_PERMISSION_DENIED;
    }

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

    json_t *obj = json_pack("{}");

    const strarray_t *boxes = mbname_boxes(mbname);
    const char *id = strarray_nth(boxes, boxes->count-1);
    json_object_set_new(obj, "id", json_string(id));

    if (_wantprop(rock->props, "x-href")) {
        // FIXME - should the x-ref for a shared calendar point
        // to the authenticated user's calendar home?
        char *xhref = jmap_xhref(mbentry->name, NULL);
        json_object_set_new(obj, "x-href", json_string(xhref));
        free(xhref);
    }

    if (_wantprop(rock->props, "name")) {
        struct buf attrib = BUF_INITIALIZER;
        static const char *displayname_annot =
            DAV_ANNOT_NS "<" XML_NS_DAV ">displayname";
        r = annotatemore_lookupmask(mbentry->name, displayname_annot,
                                    httpd_userid, &attrib);
        /* fall back to last part of mailbox name */
        if (r || !attrib.len) buf_setcstr(&attrib, id);
        json_object_set_new(obj, "name", json_string(buf_cstring(&attrib)));
        buf_free(&attrib);
    }

    if (_wantprop(rock->props, "color")) {
        struct buf attrib = BUF_INITIALIZER;
        static const char *color_annot =
            DAV_ANNOT_NS "<" XML_NS_APPLE ">calendar-color";
        r = annotatemore_lookupmask(mbentry->name, color_annot,
                                    httpd_userid, &attrib);
        if (!r && attrib.len)
            json_object_set_new(obj, "color", json_string(buf_cstring(&attrib)));
        buf_free(&attrib);
    }

    if (_wantprop(rock->props, "sortOrder")) {
        struct buf attrib = BUF_INITIALIZER;
        static const char *order_annot =
            DAV_ANNOT_NS "<" XML_NS_APPLE ">calendar-order";
        r = annotatemore_lookupmask(mbentry->name, order_annot,
                                    httpd_userid, &attrib);
        if (!r && attrib.len) {
            char *ptr;
            long val = strtol(buf_cstring(&attrib), &ptr, 10);
            if (ptr && *ptr == '\0') {
                json_object_set_new(obj, "sortOrder", json_integer(val));
            }
            else {
                /* Ignore, but report non-numeric calendar-order values */
                syslog(LOG_WARNING, "sortOrder: strtol(%s) failed",
                       buf_cstring(&attrib));
            }
        }
        buf_free(&attrib);
    }

    if (_wantprop(rock->props, "isVisible")) {
        struct buf attrib = BUF_INITIALIZER;
        static const char *color_annot =
            DAV_ANNOT_NS "<" XML_NS_CALDAV ">X-FM-isVisible";
        r = annotatemore_lookupmask(mbentry->name, color_annot,
                                    httpd_userid, &attrib);
        if (!r && attrib.len) {
            const char *val = buf_cstring(&attrib);
            if (!strncmp(val, "true", 4) || !strncmp(val, "1", 1)) {
                json_object_set_new(obj, "isVisible", json_true());
            } else if (!strncmp(val, "false", 5) || !strncmp(val, "0", 1)) {
                json_object_set_new(obj, "isVisible", json_false());
            } else {
                /* Report invalid value and fall back to default. */
                syslog(LOG_WARNING,
                       "isVisible: invalid annotation value: %s", val);
                json_object_set_new(obj, "isVisible", json_string("true"));
            }
        }
        buf_free(&attrib);
    }

    if (_wantprop(rock->props, "mayReadFreeBusy")) {
        json_object_set_new(obj, "mayReadFreeBusy",
                            rights & DACL_READFB ? json_true() : json_false());
    }

    if (_wantprop(rock->props, "mayReadItems")) {
        json_object_set_new(obj, "mayReadItems",
                            rights & DACL_READ ? json_true() : json_false());
    }

    if (_wantprop(rock->props, "mayAddItems")) {
        json_object_set_new(obj, "mayAddItems",
                            rights & DACL_WRITECONT ? json_true() : json_false());
    }

    if (_wantprop(rock->props, "mayModifyItems")) {
        json_object_set_new(obj, "mayModifyItems",
                            rights & DACL_WRITECONT ? json_true() : json_false());
    }

    if (_wantprop(rock->props, "mayRemoveItems")) {
        json_object_set_new(obj, "mayRemoveItems",
                            rights & DACL_RMRSRC ? json_true() : json_false());
    }

    if (_wantprop(rock->props, "mayRename")) {
        json_object_set_new(obj, "mayRename",
                            rights & DACL_RMCOL ? json_true() : json_false());
    }

    if (_wantprop(rock->props, "mayDelete")) {
        json_object_set_new(obj, "mayDelete",
                            rights & DACL_RMCOL ? json_true() : json_false());
    }

    json_array_append_new(rock->found, obj);

done:
    mbname_free(&mbname);
    return r;
}


static int getCalendars(struct jmap_req *req)
{
    struct getcalendars_rock rock = {
        req,
        json_pack("[]") /*found*/,
        NULL            /*props*/,
        NULL            /*mailbox*/,
        1               /*skiphidden */
    };
    int r = 0;

    r = caldav_create_defaultcalendars(req->accountid);
    if (r == IMAP_MAILBOX_NONEXISTENT) {
        /* The account exists but does not have a root mailbox. */
        json_t *err = json_pack("{s:s}", "type", "accountNoCalendars");
        json_array_append_new(req->response, json_pack("[s,o,s]",
                    "error", err, req->tag));
        return 0;
    } else if (r) return r;

    json_t *properties = json_object_get(req->args, "properties");
    if (properties && json_array_size(properties)) {
        rock.props = xzmalloc(sizeof(struct hash_table));
        construct_hash_table(rock.props, json_array_size(properties), 0);
        int i;
        int size = json_array_size(properties);
        for (i = 0; i < size; i++) {
            const char *id = json_string_value(json_array_get(properties, i));
            if (id == NULL) continue;
            /* 1 == properties */
            hash_insert(id, (void *)1, rock.props);
        }
    }

    json_t *want = json_object_get(req->args, "ids");
    json_t *notfound = json_array();
    if (JNOTNULL(want)) {
        size_t i;
        json_t *jval;
        rock.skip_hidden = 0; /* complain about missing ACL rights */
        json_array_foreach(want, i, jval) {
            const char *id = json_string_value(jval);
            /* FIXME - this should probably done everywhere */
            if (!id) {
                json_t *err = json_pack("{s:s, s:[s]}",
                        "type", "invalidArguments", "arguments", "ids");
                json_array_append_new(req->response, json_pack("[s,o,s]",
                            "error", err, req->tag));
                r = 0;
                goto done;
            }
            if (id && id[0] == '#') {
                id = jmap_lookup_id(req, id + 1);
            }
            if (!id) {
                json_array_append(notfound, jval);
                continue;
            }

            char *mboxname = caldav_mboxname(req->accountid, id);
            mbentry_t *mbentry = NULL;

            r = mboxlist_lookup(mboxname, &mbentry, NULL);
            if (r == IMAP_NOTFOUND || !mbentry) {
                json_array_append(notfound, jval);
                r = 0;
                goto doneloop;
            }

            r = getcalendars_cb(mbentry, &rock);
            if (r == IMAP_PERMISSION_DENIED) {
                json_array_append(notfound, jval);
                r = 0;
                goto doneloop;
            }

doneloop:
            if (mbentry) mboxlist_entry_free(&mbentry);
            free(mboxname);
            if (r) goto done;
        }
    }
    else {
        r = jmap_mboxlist(req, &getcalendars_cb, &rock);
        if (r) goto done;
    }

    json_t *calendars = json_pack("{}");
    json_incref(rock.found);
    json_object_set_new(calendars, "accountId", json_string(req->accountid));
    json_object_set_new(calendars, "state", jmap_getstate(req, MBTYPE_CALENDAR));
    json_object_set_new(calendars, "list", rock.found);
    if (json_array_size(notfound)) {
        json_object_set_new(calendars, "notFound", notfound);
    }
    else {
        json_decref(notfound);
        json_object_set_new(calendars, "notFound", json_null());
    }

    json_t *item = json_pack("[]");
    json_array_append_new(item, json_string("Calendar/get"));
    json_array_append_new(item, calendars);
    json_array_append_new(item, json_string(req->tag));

    json_array_append_new(req->response, item);

done:
    if (rock.props) {
        free_hash_table(rock.props, NULL);
        free(rock.props);
    }
    json_decref(rock.found);
    return r;
}

struct calendarupdates_rock {
    jmap_req_t *req;
    modseq_t oldmodseq;
    json_t *changed;
    json_t *destroyed;
};

static int getcalendarupdates_cb(const mbentry_t *mbentry, void *vrock)
{
    struct calendarupdates_rock *rock = (struct calendarupdates_rock *) vrock;
    mbname_t *mbname = NULL;
    jmap_req_t *req = rock->req;
    int r = 0;

    /* Ignore old changes. */
    if (mbentry->foldermodseq <= rock->oldmodseq) {
        goto done;
    }

    /* Ignore mailboxes that are hidden from us */
    int rights = jmap_myrights(req, mbentry);
    if (!(rights & DACL_READ)) return 0;

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

    /* Report this calendar as changed or destroyed. */
    if (mbentry->mbtype & MBTYPE_CALENDAR) {
        json_array_append_new(rock->changed, json_string(id));
    } else if (mbentry->mbtype & MBTYPE_DELETED) {
        json_array_append_new(rock->destroyed, json_string(id));
    }

done:
    mbname_free(&mbname);
    return r;
}

static int getCalendarsUpdates(struct jmap_req *req)
{
    int r, pe;
    json_t *invalid;
    const char *since = NULL;
    int dofetch = 0;
    struct buf buf = BUF_INITIALIZER;
    modseq_t oldmodseq = 0;

    r = caldav_create_defaultcalendars(req->accountid);
    if (r == IMAP_MAILBOX_NONEXISTENT) {
        /* The account exists but does not have a root mailbox. */
        json_t *err = json_pack("{s:s}", "type", "accountNoCalendars");
        json_array_append_new(req->response, json_pack("[s,o,s]",
                    "error", err, req->tag));
        return 0;
    } else if (r) return r;

    /* Parse and validate arguments. */
    invalid = json_pack("[]");
    pe = readprop(req->args, "sinceState", 1 /*mandatory*/, invalid, "s", &since);
    if (pe > 0) {
        oldmodseq = atomodseq_t(since);
        if (!oldmodseq) {
            json_array_append_new(invalid, json_string("sinceState"));
        }
    }
    readprop(req->args, "fetchRecords", 0 /*mandatory*/, invalid, "b", &dofetch);
    if (json_array_size(invalid)) {
        json_t *err = json_pack("{s:s, s:o}",
                                "type", "invalidArguments", "arguments", invalid);
        json_array_append_new(req->response,
                              json_pack("[s,o,s]", "error", err, req->tag));
        r = 0;
        goto done;
    }
    json_decref(invalid);

    /* Lookup any updates. */
    char *mboxname = caldav_mboxname(req->accountid, NULL);
    struct calendarupdates_rock rock = {
        req,
        oldmodseq,
        json_pack("[]"),
        json_pack("[]")
    };
    r = mboxlist_mboxtree(mboxname, getcalendarupdates_cb, &rock,
                          MBOXTREE_TOMBSTONES|MBOXTREE_SKIP_ROOT);
    free(mboxname);
    if (r) {
        json_t *err = json_pack("{s:s}", "type", "cannotCalculateChanges");
        json_array_append_new(req->response,
                              json_pack("[s,o,s]", "error", err, req->tag));
        json_decref(rock.changed);
        json_decref(rock.destroyed);
        goto done;
    }

    /* Create response. */
    json_t *calendarUpdates = json_pack("{}");
    json_object_set_new(calendarUpdates, "accountId",
                        json_string(req->accountid));
    json_object_set_new(calendarUpdates, "oldState", json_string(since));
    json_object_set_new(calendarUpdates, "newState",
                        jmap_getstate(req, MBTYPE_CALENDAR));

    json_object_set_new(calendarUpdates, "changed", rock.changed);
    json_object_set_new(calendarUpdates, "destroyed", rock.destroyed);

    json_t *item = json_pack("[]");
    json_array_append_new(item, json_string("Calendar/changes"));
    json_array_append_new(item, calendarUpdates);
    json_array_append_new(item, json_string(req->tag));
    json_array_append_new(req->response, item);

    if (dofetch) {
        struct jmap_req subreq = *req; // struct copy, woot
        subreq.args = json_pack("{}");
        json_object_set(subreq.args, "ids", rock.changed);
        r = getCalendars(&subreq);
        json_decref(subreq.args);
    }

  done:
    buf_free(&buf);
    return r;
}

/* jmap calendar APIs */

/* Update the calendar properties in the calendar mailbox named mboxname.
 * NULL values and negative integers are ignored. Return 0 on success. */
static int setcalendars_update(jmap_req_t *req,
                               const char *mboxname,
                               const char *name,
                               const char *color,
                               int sortOrder,
                               int isVisible)
{
    struct mailbox *mbox = NULL;
    annotate_state_t *astate = NULL;
    struct buf val = BUF_INITIALIZER;
    int r;

    int rights = jmap_myrights_byname(req, mboxname);
    if (!(rights & DACL_READ)) {
        return IMAP_MAILBOX_NONEXISTENT;
    } else if (!(rights & DACL_WRITE)) {
        return IMAP_PERMISSION_DENIED;
    }

    r = mailbox_open_iwl(mboxname, &mbox);
    if (r) {
        syslog(LOG_ERR, "mailbox_open_iwl(%s) failed: %s",
                mboxname, error_message(r));
        return r;
    }

    r = mailbox_get_annotate_state(mbox, 0, &astate);
    if (r) {
        syslog(LOG_ERR, "IOERROR: failed to open annotations %s: %s",
                mbox->name, error_message(r));
    }
    /* name */
    if (!r && name) {
        buf_setcstr(&val, name);
        static const char *displayname_annot =
            DAV_ANNOT_NS "<" XML_NS_DAV ">displayname";
        r = annotate_state_writemask(astate, displayname_annot,
                                     httpd_userid, &val);
        if (r) {
            syslog(LOG_ERR, "failed to write annotation %s: %s",
                    displayname_annot, error_message(r));
        }
        buf_reset(&val);
    }
    /* color */
    if (!r && color) {
        buf_setcstr(&val, color);
        static const char *color_annot =
            DAV_ANNOT_NS "<" XML_NS_APPLE ">calendar-color";
        r = annotate_state_writemask(astate, color_annot, httpd_userid, &val);
        if (r) {
            syslog(LOG_ERR, "failed to write annotation %s: %s",
                    color_annot, error_message(r));
        }
        buf_reset(&val);
    }
    /* sortOrder */
    if (!r && sortOrder >= 0) {
        buf_printf(&val, "%d", sortOrder);
        static const char *sortOrder_annot =
            DAV_ANNOT_NS "<" XML_NS_APPLE ">calendar-order";
        r = annotate_state_writemask(astate, sortOrder_annot,
                                     httpd_userid, &val);
        if (r) {
            syslog(LOG_ERR, "failed to write annotation %s: %s",
                    sortOrder_annot, error_message(r));
        }
        buf_reset(&val);
    }
    /* isVisible */
    if (!r && isVisible >= 0) {
        buf_setcstr(&val, isVisible ? "true" : "false");
        static const char *sortOrder_annot =
            DAV_ANNOT_NS "<" XML_NS_CALDAV ">X-FM-isVisible";
        r = annotate_state_writemask(astate, sortOrder_annot,
                                     httpd_userid, &val);
        if (r) {
            syslog(LOG_ERR, "failed to write annotation %s: %s",
                    sortOrder_annot, error_message(r));
        }
        buf_reset(&val);
    }

    buf_free(&val);
    if (r) {
        mailbox_abort(mbox);
    }
    mailbox_close(&mbox);
    return r;
}

/* Delete the calendar mailbox named mboxname for the userid in req. */
static int setcalendars_destroy(jmap_req_t *req, const char *mboxname)
{
    int r, rights;

    rights = jmap_myrights_byname(req, mboxname);
    if (!(rights & DACL_READ)) {
        return IMAP_NOTFOUND;
    } else if (!(rights & DACL_RMCOL)) {
        return IMAP_PERMISSION_DENIED;
    }

    struct caldav_db *db = caldav_open_userid(req->userid);
    if (!db) {
        syslog(LOG_ERR, "caldav_open_mailbox failed for user %s", req->userid);
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
    r = caldav_delmbox(db, mboxname);
    if (r) {
        syslog(LOG_ERR, "failed to delete mailbox from caldav_db: %s",
                error_message(r));
        return r;
    }
    jmap_myrights_delete(req, mboxname);

    struct mboxevent *mboxevent = mboxevent_new(EVENT_MAILBOX_DELETE);
    if (mboxlist_delayed_delete_isenabled()) {
        r = mboxlist_delayed_deletemailbox(mboxname,
                httpd_userisadmin || httpd_userisproxyadmin,
                httpd_userid, req->authstate, mboxevent,
                1 /* checkacl */, 0 /* local_only */, 0 /* force */);
    } else {
        r = mboxlist_deletemailbox(mboxname,
                httpd_userisadmin || httpd_userisproxyadmin,
                httpd_userid, req->authstate, mboxevent,
                1 /* checkacl */, 0 /* local_only */, 0 /* force */);
    }
    mboxevent_free(&mboxevent);

    int rr = caldav_close(db);
    if (!r) r = rr;

    return r;
}

static int setCalendars(struct jmap_req *req)
{
    int r = 0;
    json_t *set = NULL;

    json_t *state = json_object_get(req->args, "ifInState");
    if (state && jmap_cmpstate(req, state, MBTYPE_CALENDAR)) {
        json_array_append_new(req->response, json_pack("[s, {s:s}, s]",
                    "error", "type", "stateMismatch", req->tag));
        goto done;
    }
    set = json_pack("{s:s}", "accountId", req->accountid);
    json_object_set_new(set, "oldState", jmap_getstate(req, MBTYPE_CALENDAR));

    r = caldav_create_defaultcalendars(req->accountid);
    if (r == IMAP_MAILBOX_NONEXISTENT) {
        /* The account exists but does not have a root mailbox. */
        json_t *err = json_pack("{s:s}", "type", "accountNoCalendars");
        json_array_append_new(req->response, json_pack("[s,o,s]",
                    "error", err, req->tag));
        return 0;
    } else if (r) return r;

    json_t *create = json_object_get(req->args, "create");
    if (create) {
        json_t *created = json_pack("{}");
        json_t *notCreated = json_pack("{}");
        json_t *record;

        const char *key;
        json_t *arg;
        json_object_foreach(create, key, arg) {
            /* Validate calendar id. */
            if (!strlen(key)) {
                json_t *err= json_pack("{s:s}", "type", "invalidArguments");
                json_object_set_new(notCreated, key, err);
                continue;
            }

            /* Parse and validate properties. */
            json_t *invalid = json_pack("[]");
            const char *name = NULL;
            const char *color = NULL;
            int32_t sortOrder = -1;
            int isVisible = 0;
            int pe; /* parse error */
            short flag;

            /* Mandatory properties. */
            pe = readprop(arg, "name", 1,  invalid, "s", &name);
            if (pe > 0 && strnlen(name, 256) == 256) {
                json_array_append_new(invalid, json_string("name"));
            }

            readprop(arg, "color", 1,  invalid, "s", &color);

            pe = readprop(arg, "sortOrder", 1,  invalid, "i", &sortOrder);
            if (pe > 0 && sortOrder < 0) {
                json_array_append_new(invalid, json_string("sortOrder"));
            }
            pe = readprop(arg, "isVisible", 1,  invalid, "b", &isVisible);
            if (pe > 0 && !isVisible) {
                json_array_append_new(invalid, json_string("isVisible"));
            }
            /* Optional properties. If present, these MUST be set to true. */
            flag = 1; readprop(arg, "mayReadFreeBusy", 0,  invalid, "b", &flag);
            if (!flag) {
                json_array_append_new(invalid, json_string("mayReadFreeBusy"));
            }
            flag = 1; readprop(arg, "mayReadItems", 0,  invalid, "b", &flag);
            if (!flag) {
                json_array_append_new(invalid, json_string("mayReadItems"));
            }
            flag = 1; readprop(arg, "mayAddItems", 0,  invalid, "b", &flag);
            if (!flag) {
                json_array_append_new(invalid, json_string("mayAddItems"));
            }
            flag = 1; readprop(arg, "mayModifyItems", 0,  invalid, "b", &flag);
            if (!flag) {
                json_array_append_new(invalid, json_string("mayModifyItems"));
            }
            flag = 1; readprop(arg, "mayRemoveItems", 0,  invalid, "b", &flag);
            if (!flag) {
                json_array_append_new(invalid, json_string("mayRemoveItems"));
            }
            flag = 1; readprop(arg, "mayRename", 0,  invalid, "b", &flag);
            if (!flag) {
                json_array_append_new(invalid, json_string("mayRename"));
            }
            flag = 1; readprop(arg, "mayDelete", 0,  invalid, "b", &flag);
            if (!flag) {
                json_array_append_new(invalid, json_string("mayDelete"));
            }

            /* Report any property errors and bail out. */
            if (json_array_size(invalid)) {
                json_t *err = json_pack("{s:s, s:o}",
                        "type", "invalidProperties", "properties", invalid);
                json_object_set_new(notCreated, key, err);
                continue;
            }
            json_decref(invalid);

            /* Prepare the ACL for this calendar */
            struct buf acl = BUF_INITIALIZER;
            if (strcmp(req->accountid, req->userid)) {
                /* Make sure we are allowed to create the calendar */
                char *parentname = caldav_mboxname(req->accountid, NULL);
                mbentry_t *mbparent = NULL;
                mboxlist_lookup(parentname, &mbparent, NULL);
                free(parentname);
                int rights = jmap_myrights(req, mbparent);
                if (!(rights & DACL_MKCOL)) {
                    json_t *err = json_pack("{s:s}", "type", "accountReadOnly");
                    json_object_set_new(notCreated, key, err);
                    mboxlist_entry_free(&mbparent);
                    continue;
                }
                /* Copy the calendar home ACL for this shared calendar */
                buf_setcstr(&acl, mbparent->acl);
                mboxlist_entry_free(&mbparent);
            } else {
                /* Users may always create their own calendars */
                char rights[100];
                cyrus_acl_masktostr(DACL_ALL | DACL_READFB, rights);
                buf_printf(&acl, "%s\t%s\t", httpd_userid, rights);
                cyrus_acl_masktostr(DACL_READFB, rights);
                buf_printf(&acl, "%s\t%s\t", "anyone", rights);
            }

            /* Create the calendar */
            char *uid = xstrdup(makeuuid());
            char *mboxname = caldav_mboxname(req->accountid, uid);
            r = mboxlist_createsync(mboxname, MBTYPE_CALENDAR,
                    NULL /* partition */,
                    req->userid, req->authstate,
                    0 /* options */, 0 /* uidvalidity */,
                    0 /* highestmodseq */, buf_cstring(&acl),
                    NULL /* uniqueid */, 0 /* local_only */,
                    NULL /* mboxptr */);
            buf_free(&acl);
            if (r) {
                syslog(LOG_ERR, "IOERROR: failed to create %s (%s)",
                        mboxname, error_message(r));
                if (r == IMAP_PERMISSION_DENIED) {
                    json_t *err = json_pack("{s:s}", "type", "accountReadOnly");
                    json_object_set_new(notCreated, key, err);
                }
                free(mboxname);
                goto done;
            }
            r = setcalendars_update(req, mboxname,
                                    name, color, sortOrder, isVisible);
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

            free(mboxname);

            /* Report calendar as created. */
            record = json_pack("{s:s}", "id", uid);
            json_object_set_new(created, key, record);
            jmap_add_id(req, key, uid);
            free(uid);
        }

        if (json_object_size(created)) {
            json_object_set(set, "created", created);
        }
        json_decref(created);

        if (json_object_size(notCreated)) {
            json_object_set(set, "notCreated", notCreated);
        }
        json_decref(notCreated);
    }

    json_t *update = json_object_get(req->args, "update");
    if (update) {
        json_t *updated = json_pack("{}");
        json_t *notUpdated = json_pack("{}");

        const char *uid;
        json_t *arg;
        json_object_foreach(update, uid, arg) {

            /* Validate uid */
            if (!uid) {
                continue;
            }
            if (uid && uid[0] == '#') {
                const char *newuid = jmap_lookup_id(req, uid + 1);
                if (!newuid) {
                    json_t *err = json_pack("{s:s}", "type", "notFound");
                    json_object_set_new(notUpdated, uid, err);
                    continue;
                }
                uid = newuid;
            }

            /* Parse and validate properties. */
            json_t *invalid = json_pack("[]");

            const char *name = NULL;
            const char *color = NULL;
            int32_t sortOrder = -1;
            int isVisible = -1;
            int flag;
            int pe = 0; /* parse error */
            pe = readprop(arg, "name", 0,  invalid, "s", &name);
            if (pe > 0 && strnlen(name, 256) == 256) {
                json_array_append_new(invalid, json_string("name"));
            }
            readprop(arg, "color", 0,  invalid, "s", &color);
            pe = readprop(arg, "sortOrder", 0,  invalid, "i", &sortOrder);
            if (pe > 0 && sortOrder < 0) {
                json_array_append_new(invalid, json_string("sortOrder"));
            }
            readprop(arg, "isVisible", 0,  invalid, "b", &isVisible);

            /* The mayFoo properties are immutable and MUST NOT set. */
            pe = readprop(arg, "mayReadFreeBusy", 0,  invalid, "b", &flag);
            if (pe > 0) {
                json_array_append_new(invalid, json_string("mayReadFreeBusy"));
            }
            pe = readprop(arg, "mayReadItems", 0,  invalid, "b", &flag);
            if (pe > 0) {
                json_array_append_new(invalid, json_string("mayReadItems"));
            }
            pe = readprop(arg, "mayAddItems", 0,  invalid, "b", &flag);
            if (pe > 0) {
                json_array_append_new(invalid, json_string("mayAddItems"));
            }
            pe = readprop(arg, "mayModifyItems", 0,  invalid, "b", &flag);
            if (pe > 0) {
                json_array_append_new(invalid, json_string("mayModifyItems"));
            }
            pe = readprop(arg, "mayRemoveItems", 0,  invalid, "b", &flag);
            if (pe > 0) {
                json_array_append_new(invalid, json_string("mayRemoveItems"));
            }
            pe = readprop(arg, "mayRename", 0,  invalid, "b", &flag);
            if (pe > 0) {
                json_array_append_new(invalid, json_string("mayRename"));
            }
            pe = readprop(arg, "mayDelete", 0,  invalid, "b", &flag);
            if (pe > 0) {
                json_array_append_new(invalid, json_string("mayDelete"));
            }

            /* Report any property errors and bail out. */
            if (json_array_size(invalid)) {
                json_t *err = json_pack("{s:s, s:o}",
                        "type", "invalidProperties", "properties", invalid);
                json_object_set_new(notUpdated, uid, err);
                continue;
            }
            json_decref(invalid);

            /* Make sure we don't mess up special calendars */
            char *mboxname = caldav_mboxname(req->accountid, uid);
            mbname_t *mbname = mbname_from_intname(mboxname);
            if (!mbname || jmap_calendar_isspecial(mbname)) {
                json_t *err = json_pack("{s:s}", "type", "notFound");
                json_object_set_new(notUpdated, uid, err);
                mbname_free(&mbname);
                free(mboxname);
                continue;
            }
            mbname_free(&mbname);

            /* Update the calendar */
            r = setcalendars_update(req, mboxname,
                                    name, color, sortOrder, isVisible);
            free(mboxname);
            if (r == IMAP_NOTFOUND || r == IMAP_MAILBOX_NONEXISTENT) {
                json_t *err = json_pack("{s:s}", "type", "notFound");
                json_object_set_new(notUpdated, uid, err);
                r = 0;
                continue;
            }
            else if (r == IMAP_PERMISSION_DENIED) {
                json_t *err = json_pack("{s:s}", "type", "accountReadOnly");
                json_object_set_new(notUpdated, uid, err);
                r = 0;
                continue;
            }

            /* Report calendar as updated. */
            json_object_set_new(updated, uid, json_null());
        }

        if (json_object_size(updated)) {
            json_object_set(set, "updated", updated);
        }
        json_decref(updated);
        if (json_object_size(notUpdated)) {
            json_object_set(set, "notUpdated", notUpdated);
        }
        json_decref(notUpdated);
    }

    json_t *destroy = json_object_get(req->args, "destroy");
    if (destroy) {
        json_t *destroyed = json_pack("[]");
        json_t *notDestroyed = json_pack("{}");

        size_t index;
        json_t *juid;

        json_array_foreach(destroy, index, juid) {

            /* Validate uid */
            const char *uid = json_string_value(juid);
            if (!uid) {
                continue;
            }
            if (uid && uid[0] == '#') {
                const char *newuid = jmap_lookup_id(req, uid + 1);
                if (!newuid) {
                    json_t *err = json_pack("{s:s}", "type", "notFound");
                    json_object_set_new(notDestroyed, uid, err);
                    continue;
                }
                uid = newuid;
            }

            /* Do not allow to remove the default calendar. */
            char *mboxname = caldav_mboxname(req->accountid, NULL);
            static const char *defaultcal_annot =
                DAV_ANNOT_NS "<" XML_NS_CALDAV ">schedule-default-calendar";
            struct buf attrib = BUF_INITIALIZER;
            r = annotatemore_lookupmask(mboxname, defaultcal_annot,
                                        req->accountid, &attrib);
            free(mboxname);
            const char *defaultcal = "Default";
            if (!r && attrib.len) {
                defaultcal = buf_cstring(&attrib);
            }
            if (!strcmp(uid, defaultcal)) {
                /* XXX - The isDefault set error is not documented in the spec. */
                json_t *err = json_pack("{s:s}", "type", "isDefault");
                json_object_set_new(notDestroyed, uid, err);
                buf_free(&attrib);
                continue;
            }
            buf_free(&attrib);

            /* Make sure we don't delete special calendars */
            mboxname = caldav_mboxname(req->accountid, uid);
            mbname_t *mbname = mbname_from_intname(mboxname);
            if (!mbname || jmap_calendar_isspecial(mbname)) {
                json_t *err = json_pack("{s:s}", "type", "notFound");
                json_object_set_new(notDestroyed, uid, err);
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
                json_object_set_new(notDestroyed, uid, err);
                r = 0;
                continue;
            } else if (r == IMAP_PERMISSION_DENIED) {
                json_t *err = json_pack("{s:s}", "type", "accountReadOnly");
                json_object_set_new(notDestroyed, uid, err);
                r = 0;
                continue;
            } else if (r) {
                goto done;
            }

            /* Report calendar as destroyed. */
            json_array_append_new(destroyed, json_string(uid));
        }

        if (json_array_size(destroyed)) {
            json_object_set(set, "destroyed", destroyed);
        }
        json_decref(destroyed);
        if (json_object_size(notDestroyed)) {
            json_object_set(set, "notDestroyed", notDestroyed);
        }
        json_decref(notDestroyed);
    }

    /* Set newState field in calendarsSet. */
    if (json_object_get(set, "created") ||
        json_object_get(set, "updated") ||
        json_object_get(set, "destroyed")) {

        r = jmap_bumpstate(req, MBTYPE_CALENDAR);
        if (r) goto done;
    }
    json_object_set_new(set, "newState", jmap_getstate(req, MBTYPE_CALENDAR));

    json_incref(set);
    json_t *item = json_pack("[]");
    json_array_append_new(item, json_string("Calendar/set"));
    json_array_append_new(item, set);
    json_array_append_new(item, json_string(req->tag));
    json_array_append_new(req->response, item);

done:
    if (set) json_decref(set);
    return r;
}

/* FIXME dup from jmapical.c */
/* Convert the JMAP local datetime in buf to tm time. Return non-zero on success. */
static int localdate_to_tm(const char *buf, struct tm *tm) {
    /* Initialize tm. We don't know about daylight savings time here. */
    memset(tm, 0, sizeof(struct tm));
    tm->tm_isdst = -1;

    /* Parse LocalDate. */
    const char *p = strptime(buf, "%Y-%m-%dT%H:%M:%S", tm);
    if (!p || *p) {
        return 0;
    }
    return 1;
}

/* FIXME dup from jmapical.c */
static int localdate_to_icaltime(const char *buf,
                                 icaltimetype *dt,
                                 icaltimezone *tz,
                                 int is_allday) {
    struct tm tm;
    int r;
    char *s = NULL;
    icaltimetype tmp;
    int is_utc;
    size_t n;

    r = localdate_to_tm(buf, &tm);
    if (!r) return 0;

    if (is_allday && (tm.tm_sec || tm.tm_min || tm.tm_hour)) {
        return 0;
    }

    is_utc = tz == icaltimezone_get_utc_timezone();

    /* Can't use icaltime_from_timet_with_zone since it tries to convert
     * t from UTC into tz. Let's feed ical a DATETIME string, instead. */
    s = xcalloc(19, sizeof(char));
    n = strftime(s, 18, "%Y%m%dT%H%M%S", &tm);
    if (is_utc) {
        s[n]='Z';
    }
    tmp = icaltime_from_string(s);
    free(s);
    if (icaltime_is_null_time(tmp)) {
        return 0;
    }
    tmp.zone = tz;
    tmp.is_date = is_allday;
    *dt = tmp;
    return 1;
}

/* FIXME dup from jmapical.c */
static int utcdate_to_icaltime(const char *src,
                               icaltimetype *dt)
{
    struct buf buf = BUF_INITIALIZER;
    size_t len = strlen(src);
    int r;
    icaltimezone *utc = icaltimezone_get_utc_timezone();

    if (!len || src[len-1] != 'Z') {
        return 0;
    }

    buf_setmap(&buf, src, len-1);
    r = localdate_to_icaltime(buf_cstring(&buf), dt, utc, 0);
    buf_free(&buf);
    return r;
}

struct getcalendarevents_rock {
    struct jmap_req *req;
    json_t *found;
    struct hash_table *props;
    struct mailbox *mailbox;
    int check_acl;
};

static int getcalendarevents_cb(void *vrock, struct caldav_data *cdata)
{
    struct getcalendarevents_rock *rock = vrock;
    int r = 0;
    icalcomponent* ical = NULL;
    json_t *obj, *jprops = NULL;
    jmapical_err_t err;
    jmap_req_t *req = rock->req;

    if (!cdata->dav.alive) {
        return 0;
    }

    /* Check mailbox ACL rights */
    int rights = jmap_myrights_byname(req, cdata->dav.mailbox);
    if (!(rights & DACL_READ))
        return 0;

    /* Open calendar mailbox. */
    if (!rock->mailbox || strcmp(rock->mailbox->name, cdata->dav.mailbox)) {
        mailbox_close(&rock->mailbox);
        r = mailbox_open_irl(cdata->dav.mailbox, &rock->mailbox);
        if (r) goto done;
    }

    /* Load message containing the resource and parse iCal data */
    ical = caldav_record_to_ical(rock->mailbox, cdata, httpd_userid, NULL);
    if (!ical) {
        syslog(LOG_ERR, "caldav_record_to_ical failed for record %u:%s",
                cdata->dav.imap_uid, rock->mailbox->name);
        r = IMAP_INTERNAL;
        goto done;
    }

    /* Convert to JMAP */
    memset(&err, 0, sizeof(jmapical_err_t));
    if (rock->props) {
        /* XXX That's clumsy: the JMAP properties have already been converted
         * to a Cyrus hash, but the jmapical API requires a JSON object. */
        strarray_t *keys = hash_keys(rock->props);
        int i;
        jprops = json_pack("{}");
        for (i = 0; i < strarray_size(keys); i++) {
            json_object_set(jprops, strarray_nth(keys, i), json_null());
        }
        strarray_free(keys);
    }
    obj = jmapical_tojmap(ical, jprops,  &err);
    if (!obj || err.code) {
        syslog(LOG_ERR, "jmapical_tojson: %s\n", jmapical_strerror(err.code));
        r = IMAP_INTERNAL;
        goto done;
    }
    icalcomponent_free(ical);
    ical = NULL;

    /* Add participant id */
    if (_wantprop(rock->props, "participantId") && rock->req->userid) {
        const char *userid = rock->req->userid;
        const char *id;
        json_t *p;
        struct buf buf = BUF_INITIALIZER;

        json_object_foreach(json_object_get(obj, "participants"), id, p) {
            struct caldav_sched_param sparam;
            const char *addr;

            addr = json_string_value(json_object_get(p, "email"));
            if (!addr) continue;

            buf_setcstr(&buf, "mailto:");
            buf_appendcstr(&buf, addr);

            bzero(&sparam, sizeof(struct caldav_sched_param));
            if (caladdress_lookup(addr, &sparam, userid) || !sparam.isyou) {
                sched_param_fini(&sparam);
                continue;
            }

            /* First participant that matches isyou wins */
            json_object_set_new(obj, "participantId", json_string(id));
            sched_param_fini(&sparam);
            break;
        }

        buf_free(&buf);
    }

    /* Add JMAP-only fields. */
    if (_wantprop(rock->props, "x-href")) {
        char *xhref = jmap_xhref(cdata->dav.mailbox, cdata->dav.resource);
        json_object_set_new(obj, "x-href", json_string(xhref));
        free(xhref);
    }
    if (_wantprop(rock->props, "calendarId")) {
        json_object_set_new(obj, "calendarId",
                            json_string(strrchr(cdata->dav.mailbox, '.')+1));
    }
    json_object_set_new(obj, "id", json_string(cdata->ical_uid));

    /* Add JMAP event to response */
    json_array_append_new(rock->found, obj);

done:
    if (ical) icalcomponent_free(ical);
    if (jprops) json_decref(jprops);
    return r;
}

static int getCalendarEvents(struct jmap_req *req)
{
    struct getcalendarevents_rock rock = {
        req,
        json_pack("[]") /*found*/,
        NULL            /*props*/,
        NULL            /*mailbox*/,
        strcmp(req->accountid, req->userid) /*checkacl*/,
    };
    int r = 0;

    r = caldav_create_defaultcalendars(req->accountid);
    if (r == IMAP_MAILBOX_NONEXISTENT) {
        /* The account exists but does not have a root mailbox. */
        json_t *err = json_pack("{s:s}", "type", "accountNoCalendars");
        json_array_append_new(req->response, json_pack("[s,o,s]",
                    "error", err, req->tag));
        return 0;
    } else if (r) return r;

    json_t *properties = json_object_get(req->args, "properties");
    if (properties && json_array_size(properties)) {
        rock.props = xzmalloc(sizeof(struct hash_table));
        construct_hash_table(rock.props, json_array_size(properties), 0);
        int i;
        int size = json_array_size(properties);
        for (i = 0; i < size; i++) {
            const char *id = json_string_value(json_array_get(properties, i));
            if (id == NULL) continue;
            /* 1 == properties */
            hash_insert(id, (void *)1, rock.props);
        }
    }

    struct caldav_db *db = caldav_open_userid(req->accountid);
    if (!db) {
        syslog(LOG_ERR,
               "caldav_open_mailbox failed for user %s", req->accountid);
        r = IMAP_INTERNAL;
        goto done;
    }

    json_t *want = json_object_get(req->args, "ids");
    json_t *notfound = json_array();
    if (want) {
        size_t i;
        json_t *jval;
        json_array_foreach(want, i, jval) {
            const char *id = json_string_value(jval);
            if (id && id[0] == '#') {
                id = jmap_lookup_id(req, id + 1);
            }
            if (!id) continue;
            size_t nfound = json_array_size(rock.found);
            r = caldav_get_events(db, NULL, id, &getcalendarevents_cb, &rock);
            if (r || nfound == json_array_size(rock.found)) {
                json_array_append_new(notfound, json_string(id));
            }
        }
    } else {
        r = caldav_get_events(db, NULL, NULL, &getcalendarevents_cb, &rock);
        if (r) goto done;
    }

    json_t *events = json_pack("{}");
    json_object_set_new(events, "state", jmap_getstate(req, MBTYPE_CALENDAR));

    json_incref(rock.found);
    json_object_set_new(events, "accountId", json_string(req->accountid));
    json_object_set_new(events, "list", rock.found);
    if (json_array_size(notfound)) {
        json_object_set_new(events, "notFound", notfound);
    } else {
        json_decref(notfound);
        json_object_set_new(events, "notFound", json_null());
    }

    json_t *item = json_pack("[]");
    json_array_append_new(item, json_string("CalendarEvent/get"));
    json_array_append_new(item, events);
    json_array_append_new(item, json_string(req->tag));

    json_array_append_new(req->response, item);

done:
    if (rock.props) {
        free_hash_table(rock.props, NULL);
        free(rock.props);
    }
    json_decref(rock.found);
    if (db) caldav_close(db);
    if (rock.mailbox) mailbox_close(&rock.mailbox);
    return r;
}

static int setcalendarevents_schedule(jmap_req_t *req,
                                      char **schedaddrp,
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

    if (!*schedaddrp) {
        const char **hdr =
            spool_getheader(req->txn->req_hdrs, "Schedule-Address");
        if (hdr) *schedaddrp = xstrdup(hdr[0]);
    }

    /* XXX - after legacy records are gone, we can strip this and just not send a
     * cancellation if deleting a record which was never replied to... */
    if (!*schedaddrp) {
        /* userid corresponding to target */
        *schedaddrp = xstrdup(req->userid);

        /* or overridden address-set for target user */
        const char *annotname =
            DAV_ANNOT_NS "<" XML_NS_CALDAV ">calendar-user-address-set";
        char *mailboxname = caldav_mboxname(*schedaddrp, NULL);
        struct buf buf = BUF_INITIALIZER;
        int r = annotatemore_lookupmask(mailboxname, annotname,
                                        *schedaddrp, &buf);
        free(mailboxname);
        if (!r && buf.len > 7 && !strncasecmp(buf_cstring(&buf), "mailto:", 7)) {
            free(*schedaddrp);
            *schedaddrp = xstrdup(buf_cstring(&buf) + 7);
        }
        buf_free(&buf);
    }

    /* Validate create/update. */
    if (oldical && (mode & (JMAP_CREATE|JMAP_UPDATE))) {
        /* Don't allow ORGANIZER to be changed */
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
        if (!strcmpsafe(organizer, *schedaddrp)) {
            /* Organizer scheduling object resource */
            sched_request(req->userid, *schedaddrp, oldical, ical);
        } else {
            /* Attendee scheduling object resource */
            sched_reply(req->userid, *schedaddrp, oldical, ical);
        }
    }

    return 0;
}

static int setcalendarevents_create(jmap_req_t *req,
                                    json_t *event,
                                    struct caldav_db *db,
                                    char **uidptr,
                                    json_t *invalid)
{
    int r, pe;
    int needrights = DACL_WRITE;
    char *uid = NULL;

    struct mailbox *mbox = NULL;
    char *mboxname = NULL;
    char *resource = NULL;

    icalcomponent *oldical = NULL;
    icalcomponent *ical = NULL;
    const char *calendarId = NULL;
    char *schedule_address = NULL;

    if ((uid = (char *) json_string_value(json_object_get(event, "uid")))) {
        /* Use custom iCalendar UID from request object */
        uid = xstrdup(uid);
    }  else {
        /* Create a iCalendar UID */
        uid = xstrdup(makeuuid());
    }

    /* Validate calendarId */
    pe = readprop(event, "calendarId", 1, invalid, "s", &calendarId);
    if (pe > 0 && *calendarId &&*calendarId == '#') {
        calendarId = jmap_lookup_id(req, calendarId + 1);
        if (!calendarId) {
            json_array_append_new(invalid, json_string("calendarId"));
        }
    }
    if (json_array_size(invalid)) {
        free(uid);
        *uidptr = NULL;
        return 0;
    }

    /* Determine mailbox and resource name of calendar event.
     * We attempt to reuse the UID as DAV resource name; but
     * only if it looks like a reasonable URL path segment. */
    struct buf buf = BUF_INITIALIZER;
    mboxname = caldav_mboxname(req->accountid, calendarId);
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
    int rights = jmap_myrights_byname(req, mboxname);
    if (!(rights & needrights)) {
        json_array_append_new(invalid, json_string("calendarId"));
        free(uid);
        r = 0; goto done;
    }

    /* Open mailbox for writing */
    r = mailbox_open_iwl(mboxname, &mbox);
    if (r) {
        syslog(LOG_ERR, "mailbox_open_iwl(%s) failed: %s",
                mboxname, error_message(r));
        goto done;
    }

    /* Convert the JMAP calendar event to ical. */
    jmapical_err_t err;
    memset(&err, 0, sizeof(jmapical_err_t));

    if (!json_object_get(event, "uid")) {
        json_object_set_new(event, "uid", json_string(uid));
    }
    ical = jmapical_toical(event, oldical, &err);

    if (err.code == JMAPICAL_ERROR_PROPS) {
        json_array_extend(invalid, err.props);
        json_decref(err.props);
        free(uid);
        r = 0; goto done;
    } else if (err.code) {
        syslog(LOG_ERR, "jmapical_toical: %s", jmapical_strerror(err.code));
        r = IMAP_INTERNAL;
        goto done;
    }

    /* Handle scheduling. */
    r = setcalendarevents_schedule(req, &schedule_address,
                                   oldical, ical, JMAP_CREATE);
    if (r) goto done;

    /* Store the VEVENT. */
    struct transaction_t txn;
    memset(&txn, 0, sizeof(struct transaction_t));
    txn.req_hdrs = spool_new_hdrcache();
    /* XXX - fix userid */

    /* Locate the mailbox */
    r = http_mlookup(mbox->name, &txn.req_tgt.mbentry, NULL);
    if (r) {
        syslog(LOG_ERR, "mlookup(%s) failed: %s", mbox->name, error_message(r));
    }
    else {
        r = caldav_store_resource(&txn, ical, mbox, resource,
                                  db, 0, httpd_userid, schedule_address);
    }
    mboxlist_entry_free(&txn.req_tgt.mbentry);
    spool_free_hdrcache(txn.req_hdrs);
    buf_free(&txn.buf);
    if (r && r != HTTP_CREATED && r != HTTP_NO_CONTENT) {
        syslog(LOG_ERR, "caldav_store_resource failed for user %s: %s",
               req->accountid, error_message(r));
        r = IMAP_INTERNAL;
        goto done;
    }
    r = 0;
    *uidptr = uid;

done:
    if (r) {
        *uidptr = NULL;
        free(uid);
    }
    if (mbox) mailbox_close(&mbox);
    if (ical) icalcomponent_free(ical);
    free(schedule_address);
    free(resource);
    free(mboxname);
    return r;
}

static int setcalendarevents_update(jmap_req_t *req,
                                    json_t *event,
                                    const char *id,
                                    struct caldav_db *db,
                                    json_t *invalid)
{
    int r, pe;
    int needrights = DACL_RMRSRC|DACL_WRITE;

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
    char *schedule_address = NULL;

    /* Validate calendarId */
    pe = readprop(event, "calendarId", 0, invalid, "s", &calendarId);
    if (pe > 0 && *calendarId && *calendarId == '#') {
        calendarId = jmap_lookup_id(req, calendarId + 1);
        if (!calendarId) {
            json_array_append_new(invalid, json_string("calendarId"));
        }
    }
    if (json_array_size(invalid)) {
        return 0;
    }

    /* Determine mailbox and resource name of calendar event. */
    r = caldav_lookup_uid(db, id, &cdata);
    if (r && r != CYRUSDB_NOTFOUND) {
        syslog(LOG_ERR,
               "caldav_lookup_uid(%s) failed: %s", id, error_message(r));
        goto done;
    }
    if (r == CYRUSDB_NOTFOUND || !cdata->dav.alive ||
            !cdata->dav.rowid || !cdata->dav.imap_uid) {
        r = IMAP_NOTFOUND;
        goto done;
    }
    mboxname = xstrdup(cdata->dav.mailbox);
    resource = xstrdup(cdata->dav.resource);

    /* Check permissions. */
    int rights = jmap_myrights_byname(req, mboxname);
    if (!(rights & needrights)) {
        json_array_append_new(invalid, json_string("calendarId"));
        r = 0;
        goto done;
    }

    /* Open mailbox for writing */
    r = mailbox_open_iwl(mboxname, &mbox);
    if (r == IMAP_MAILBOX_NONEXISTENT) {
        json_array_append_new(invalid, json_string("calendarId"));
        r = 0;
        goto done;
    }
    else if (r) {
        syslog(LOG_ERR, "mailbox_open_iwl(%s) failed: %s",
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
    /* Load VEVENT from record. */
    oldical = record_to_ical(mbox, &record, &schedule_address);
    if (!oldical) {
        syslog(LOG_ERR, "record_to_ical failed for record %u:%s",
                cdata->dav.imap_uid, mbox->name);
        r = IMAP_INTERNAL;
        goto done;
    }

    /* Convert the JMAP calendar event to ical. */
    jmapical_err_t err;
    memset(&err, 0, sizeof(jmapical_err_t));

    if (!json_object_get(event, "uid")) {
        json_object_set_new(event, "uid", json_string(id));
    }
    ical = jmapical_toical(event, oldical, &err);

    if (err.code == JMAPICAL_ERROR_PROPS) {
        /* Handle any property errors and bail out. */
        json_array_extend(invalid, err.props);
        r = 0; goto done;
    } else if (err.code) {
        syslog(LOG_ERR, "jmapical_toical: %s", jmapical_strerror(err.code));
        r = IMAP_INTERNAL;
        goto done;
    }

    if (calendarId) {
        /* Check, if we need to move the event. */
        dstmboxname = caldav_mboxname(req->accountid, calendarId);
        if (strcmp(mbox->name, dstmboxname)) {
            /* Check permissions */
            int dstrights = jmap_myrights_byname(req, dstmboxname);
            if (!(dstrights & needrights)) {
                json_array_append_new(invalid, json_string("calendarId"));
                r = 0;
                goto done;
            }
            /* Open destination mailbox for writing. */
            r = mailbox_open_iwl(dstmboxname, &dstmbox);
            if (r == IMAP_MAILBOX_NONEXISTENT) {
                json_array_append_new(invalid, json_string("calendarId"));
                r = 0;
                goto done;
            } else if (r) {
                syslog(LOG_ERR, "mailbox_open_iwl(%s) failed: %s",
                        dstmboxname, error_message(r));
                goto done;
            }
        }
    }

    /* Handle scheduling. */
    r = setcalendarevents_schedule(req, &schedule_address,
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
            mailbox_close(&mbox);
            goto done;
        }
        mboxevent_extract_record(mboxevent, mbox, &record);
        mboxevent_extract_mailbox(mboxevent, mbox);
        mboxevent_set_numunseen(mboxevent, mbox, -1);
        mboxevent_set_access(mboxevent, NULL, NULL,
                             req->userid, cdata->dav.mailbox, 0);
        mailbox_close(&mbox);
        mboxevent_notify(&mboxevent);
        mboxevent_free(&mboxevent);

        /* Close the mailbox we moved the event from. */
        mailbox_close(&mbox);
        mbox = dstmbox;
        dstmbox = NULL;
        free(mboxname);
        mboxname = dstmboxname;
        dstmboxname = NULL;
    }

    /* Store the updated VEVENT. */
    struct transaction_t txn;
    memset(&txn, 0, sizeof(struct transaction_t));
    txn.req_hdrs = spool_new_hdrcache();
    /* XXX - fix userid */
    r = http_mlookup(mbox->name, &txn.req_tgt.mbentry, NULL);
    if (r) {
        syslog(LOG_ERR, "mlookup(%s) failed: %s", mbox->name, error_message(r));
    }
    else {
        r = caldav_store_resource(&txn, ical, mbox, resource,
                                  db, 0, httpd_userid, schedule_address);
    }
    transaction_free(&txn);
    if (r && r != HTTP_CREATED && r != HTTP_NO_CONTENT) {
        syslog(LOG_ERR, "caldav_store_resource failed for user %s: %s",
               req->accountid, error_message(r));
        if (r == HTTP_FORBIDDEN)
            r = IMAP_PERMISSION_DENIED;
        else
            r = IMAP_INTERNAL;

        goto done;
    }
    r = 0;

done:
    if (mbox) mailbox_close(&mbox);
    if (dstmbox) mailbox_close(&dstmbox);
    if (ical) icalcomponent_free(ical);
    if (oldical) icalcomponent_free(oldical);
    free(schedule_address);
    free(dstmboxname);
    free(resource);
    free(mboxname);
    return r;
}

static int setcalendarevents_destroy(jmap_req_t *req,
                                     const char *id,
                                     struct caldav_db *db)
{
    int r, rights;
    int needrights = DACL_RMRSRC;

    struct caldav_data *cdata = NULL;
    struct mailbox *mbox = NULL;
    char *mboxname = NULL;
    struct mboxevent *mboxevent = NULL;
    char *resource = NULL;

    icalcomponent *oldical = NULL;
    icalcomponent *ical = NULL;
    struct index_record record;
    char *schedule_address = NULL;

    /* Determine mailbox and resource name of calendar event. */
    r = caldav_lookup_uid(db, id, &cdata);
    if (r) {
        syslog(LOG_ERR,
               "caldav_lookup_uid(%s) failed: %s", id, cyrusdb_strerror(r));
        r = CYRUSDB_NOTFOUND ? IMAP_NOTFOUND : IMAP_INTERNAL;
        goto done;
    }
    mboxname = xstrdup(cdata->dav.mailbox);
    resource = xstrdup(cdata->dav.resource);

    /* Check permissions. */
    rights = jmap_myrights_byname(req, mboxname);
    if (!(rights & needrights)) {
        r = rights & DACL_READ ? IMAP_PERMISSION_DENIED : IMAP_NOTFOUND;
        goto done;
    }

    /* Open mailbox for writing */
    r = mailbox_open_iwl(mboxname, &mbox);
    if (r) {
        syslog(LOG_ERR, "mailbox_open_iwl(%s) failed: %s",
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
    oldical = record_to_ical(mbox, &record, &schedule_address);
    if (!oldical) {
        syslog(LOG_ERR, "record_to_ical failed for record %u:%s",
                cdata->dav.imap_uid, mbox->name);
        r = IMAP_INTERNAL;
        goto done;
    }

    /* Handle scheduling. */
    r = setcalendarevents_schedule(req, &schedule_address,
                                   oldical, ical, JMAP_DESTROY);
    if (r) goto done;


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
    mailbox_close(&mbox);
    mboxevent_notify(&mboxevent);
    mboxevent_free(&mboxevent);

    /* Keep the VEVENT in the database but set alive to 0, to report
     * with getCalendarEventsUpdates. */
    cdata->dav.alive = 0;
    cdata->dav.modseq = record.modseq;
    cdata->dav.imap_uid = record.uid;
    r = caldav_write(db, cdata);

done:
    if (mbox) mailbox_close(&mbox);
    if (oldical) icalcomponent_free(oldical);
    free(schedule_address);
    free(resource);
    free(mboxname);
    return r;
}

static int setCalendarEvents(struct jmap_req *req)
{
    struct caldav_db *db = NULL;
    json_t *set = NULL;
    int r = 0;

    json_t *state = json_object_get(req->args, "ifInState");
    if (state && jmap_cmpstate(req, state, MBTYPE_CALENDAR)) {
        json_array_append_new(req->response, json_pack("[s, {s:s}, s]",
                    "error", "type", "stateMismatch", req->tag));
        goto done;
    }

    set = json_pack("{s:s}", "accountId", req->accountid);
    json_object_set_new(set, "oldState", jmap_getstate(req, MBTYPE_CALENDAR));

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

    json_t *create = json_object_get(req->args, "create");
    if (create) {
        json_t *created = json_pack("{}");
        json_t *notCreated = json_pack("{}");

        const char *key;
        json_t *arg;
        json_object_foreach(create, key, arg) {
            char *uid = NULL;

            /* Validate calendar event id. */
            if (!strlen(key)) {
                json_t *err= json_pack("{s:s}", "type", "invalidArguments");
                json_object_set_new(notCreated, key, err);
                continue;
            }

            /* Create the calendar event. */
            json_t *invalid = json_pack("[]");
            r = setcalendarevents_create(req, arg, db, &uid, invalid);
            if (r) {
                json_t *err = json_pack("{s:s, s:o}",
                        "type", "internalError", "message", error_message(r));
                json_object_set_new(notCreated, key, err);
                r = 0;
                free(uid);
                continue;
            }
            if (json_array_size(invalid)) {
                json_t *err = json_pack("{s:s, s:o}",
                        "type", "invalidProperties", "properties", invalid);
                json_object_set_new(notCreated, key, err);
                free(uid);
                continue;
            }
            json_decref(invalid);

            /* Report calendar event as created. */
            json_object_set_new(created, key, json_pack("{s:s}", "id", uid));
            jmap_add_id(req, key, uid);
            free(uid);
        }

        if (json_object_size(created)) {
            json_object_set(set, "created", created);
        }
        json_decref(created);

        if (json_object_size(notCreated)) {
            json_object_set(set, "notCreated", notCreated);
        }
        json_decref(notCreated);

    }

    json_t *update = json_object_get(req->args, "update");
    if (update) {
        json_t *updated = json_pack("{}");
        json_t *notUpdated = json_pack("{}");

        const char *uid;
        json_t *arg;

        json_object_foreach(update, uid, arg) {
            const char *val = NULL;

            /* Validate uid. */
            if (!uid) {
                continue;
            }
            if (uid && uid[0] == '#') {
                const char *newuid = jmap_lookup_id(req, uid + 1);
                if (!newuid) {
                    json_t *err = json_pack("{s:s}", "type", "notFound");
                    json_object_set_new(notUpdated, uid, err);
                    continue;
                }
                uid = newuid;
            }

            if ((val = (char *)json_string_value(json_object_get(arg, "uid")))) {
                /* The uid property must match the current iCalendar UID */
                if (strcmp(val, uid)) {
                    json_t *err = json_pack(
                            "{s:s, s:o}",
                            "type", "invalidProperties",
                            "properties", json_pack("[s]"));
                    json_object_set_new(notUpdated, uid, err);
                    continue;
                }
            }

            /* Update the calendar event. */
            json_t *invalid = json_pack("[]");
            r = setcalendarevents_update(req, arg, uid, db, invalid);
            if (r == IMAP_NOTFOUND) {
                json_t *err = json_pack("{s:s}", "type", "notFound");
                json_object_set_new(notUpdated, uid, err);
                json_decref(invalid);
                r = 0;
                continue;
            } else if (r) {
                json_decref(invalid);
                goto done;
            }
            if (json_array_size(invalid)) {
                    json_t *err = json_pack(
                            "{s:s, s:o}", "type", "invalidProperties",
                            "properties", invalid);
                    json_object_set_new(notUpdated, uid, err);
                    continue;
            }
            json_decref(invalid);

            /* Report calendar event as updated. */
            json_object_set_new(updated, uid, json_null());
        }

        if (json_object_size(updated)) {
            json_object_set(set, "updated", updated);
        }
        json_decref(updated);
        if (json_object_size(notUpdated)) {
            json_object_set(set, "notUpdated", notUpdated);
        }
        json_decref(notUpdated);
    }

    json_t *destroy = json_object_get(req->args, "destroy");
    if (destroy) {
        json_t *destroyed = json_pack("[]");
        json_t *notDestroyed = json_pack("{}");

        size_t index;
        json_t *juid;

        json_array_foreach(destroy, index, juid) {
            /* Validate uid. */
            const char *uid = json_string_value(juid);
            if (!uid) {
                continue;
            }
            if (uid && uid[0] == '#') {
                const char *newuid = jmap_lookup_id(req, uid + 1);
                if (!newuid) {
                    json_t *err = json_pack("{s:s}", "type", "notFound");
                    json_object_set_new(notDestroyed, uid, err);
                    continue;
                }
                uid = newuid;
            }

            /* Destroy the calendar event. */
            r = setcalendarevents_destroy(req, uid, db);
            if (r == IMAP_NOTFOUND) {
                json_t *err = json_pack("{s:s}", "type", "notFound");
                json_object_set_new(notDestroyed, uid, err);
                r = 0;
                continue;
            } else if (r == IMAP_PERMISSION_DENIED) {
                json_t *err = json_pack("{s:s}", "type", "forbidden");
                json_object_set_new(notDestroyed, uid, err);
                r = 0;
                continue;
            } else if (r) {
                goto done;
            }

            /* Report calendar event as destroyed. */
            json_array_append_new(destroyed, json_string(uid));
        }

        if (json_array_size(destroyed)) {
            json_object_set(set, "destroyed", destroyed);
        }
        json_decref(destroyed);
        if (json_object_size(notDestroyed)) {
            json_object_set(set, "notDestroyed", notDestroyed);
        }
        json_decref(notDestroyed);
    }

    /* Set newState field in calendarsSet. */
    if (json_object_get(set, "created") ||
        json_object_get(set, "updated") ||
        json_object_get(set, "destroyed")) {

        r = jmap_bumpstate(req, MBTYPE_CALENDAR);
        if (r) goto done;
    }
    json_object_set_new(set, "newState", jmap_getstate(req, MBTYPE_CALENDAR));

    json_incref(set);
    json_t *item = json_pack("[]");
    json_array_append_new(item, json_string("CalendarEvent/set"));
    json_array_append_new(item, set);
    json_array_append_new(item, json_string(req->tag));
    json_array_append_new(req->response, item);

done:
    if (db) caldav_close(db);
    if (set) json_decref(set);
    return r;
}

struct geteventupdates_rock {
    jmap_req_t *req;
    json_t *changed;
    json_t *destroyed;
    size_t seen_records;
    size_t max_records;
    modseq_t highestmodseq;
    int check_acl;
    hash_table *mboxrights;
};

static void strip_spurious_deletes(struct geteventupdates_rock *urock)
{
    /* if something is mentioned in both DELETEs and UPDATEs, it's probably
     * a move.  O(N*M) algorithm, but there are rarely many, and the alternative
     * of a hash will cost more */
    unsigned i, j;

    for (i = 0; i < json_array_size(urock->destroyed); i++) {
        const char *del = json_string_value(json_array_get(urock->destroyed, i));

        for (j = 0; j < json_array_size(urock->changed); j++) {
            const char *up =
                json_string_value(json_array_get(urock->changed, j));
            if (!strcmpsafe(del, up)) {
                json_array_remove(urock->destroyed, i--);
                break;
            }
        }
    }
}

static int geteventupdates_cb(void *vrock, struct caldav_data *cdata)
{
    struct geteventupdates_rock *rock = vrock;
    jmap_req_t *req = rock->req;

    /* Count, but don't process items that exceed the maximum record count. */
    if (rock->max_records && ++(rock->seen_records) > rock->max_records) {
        return 0;
    }

    /* Check permissions */
    int rights = jmap_myrights_byname(req, cdata->dav.mailbox);
    if (!(rights & DACL_READ))
        return 0;

    /* Report item as updated or destroyed. */
    if (cdata->dav.alive) {
        json_array_append_new(rock->changed, json_string(cdata->ical_uid));
    } else {
        json_array_append_new(rock->destroyed, json_string(cdata->ical_uid));
    }

    if (cdata->dav.modseq > rock->highestmodseq) {
        rock->highestmodseq = cdata->dav.modseq;
    }

    return 0;
}

static int getCalendarEventsUpdates(struct jmap_req *req)
{
    int r, pe;
    json_t *invalid;
    struct caldav_db *db;
    const char *since;
    modseq_t oldmodseq = 0;
    json_int_t maxChanges = 0;
    int dofetch = 0;
    struct buf buf = BUF_INITIALIZER;

    db = caldav_open_userid(req->accountid);
    if (!db) {
        syslog(LOG_ERR, "caldav_open_mailbox failed for user %s", req->accountid);
        return IMAP_INTERNAL;
    }

    /* Parse and validate arguments. */
    invalid = json_pack("[]");
    pe = readprop(req->args, "sinceState", 1 /*mandatory*/, invalid, "s", &since);
    if (pe > 0) {
        oldmodseq = atomodseq_t(since);
        if (!oldmodseq) {
            json_array_append_new(invalid, json_string("sinceState"));
        }
    }
    pe = readprop(req->args,
                  "maxChanges", 0 /*mandatory*/, invalid, "I", &maxChanges);
    if (pe > 0) {
        if (maxChanges <= 0) {
            json_array_append_new(invalid, json_string("maxChanges"));
        }
    }
    readprop(req->args, "fetchRecords", 0 /*mandatory*/, invalid, "b", &dofetch);
    if (json_array_size(invalid)) {
        json_t *err = json_pack("{s:s, s:o}",
                                "type", "invalidArguments", "arguments", invalid);
        json_array_append_new(req->response,
                              json_pack("[s,o,s]", "error", err, req->tag));
        return 0;
    }
    json_decref(invalid);

    /* Lookup updates. */
    struct geteventupdates_rock rock = {
        req,
        json_array() /*changed*/,
        json_array() /*destroyed*/,
        0            /*seen_records*/,
        maxChanges   /*max_records*/,
        0            /*highestmodseq*/,
        strcmp(req->accountid, req->userid) /* check_acl */,
        NULL         /*mboxrights*/
    };
    r = caldav_get_updates(db, oldmodseq, NULL /*mboxname*/, CAL_COMP_VEVENT, 
                           maxChanges ? maxChanges + 1 : -1,
                           &geteventupdates_cb, &rock);
    if (r) goto done;
    strip_spurious_deletes(&rock);

    /* Determine new state. */
    modseq_t newstate;
    int more = rock.max_records ? rock.seen_records > rock.max_records : 0;
    if (more) {
        newstate = rock.highestmodseq;
    } else {
        newstate = jmap_highestmodseq(req, MBTYPE_CALENDAR);
    }

    /* Create response. */
    json_t *eventUpdates = json_pack("{}");
    json_object_set_new(eventUpdates, "accountId", json_string(req->accountid));
    json_object_set_new(eventUpdates, "oldState", json_string(since));

    buf_printf(&buf, MODSEQ_FMT, newstate);
    json_object_set_new(eventUpdates, "newState", json_string(buf_cstring(&buf)));
    buf_reset(&buf);

    json_object_set_new(eventUpdates, "hasMoreUpdates", json_boolean(more));
    json_object_set(eventUpdates, "changed", rock.changed);
    json_object_set(eventUpdates, "destroyed", rock.destroyed);

    json_t *item = json_pack("[]");
    json_array_append_new(item, json_string("CalendarEvent/changes"));
    json_array_append_new(item, eventUpdates);
    json_array_append_new(item, json_string(req->tag));
    json_array_append_new(req->response, item);

    /* Fetch updated records, if requested. */
    if (dofetch) {
        json_t *props = json_object_get(req->args, "fetchRecordProperties");
        struct jmap_req subreq = *req;
        subreq.args = json_pack("{}");
        json_object_set(subreq.args, "ids", rock.changed);
        if (props) json_object_set(subreq.args, "properties", props);
        r = getCalendarEvents(&subreq);
        json_decref(subreq.args);
    }

  done:
    buf_free(&buf);
    if (rock.changed) json_decref(rock.changed);
    if (rock.destroyed) json_decref(rock.destroyed);
    if (rock.mboxrights) {
        free_hash_table(rock.mboxrights, free);
        free(rock.mboxrights);
    }
    if (db) caldav_close(db);
    return r;
}

static void match_fuzzy(search_expr_t *parent, const char *s, const char *name)
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

static search_expr_t *buildsearch(jmap_req_t *req, json_t *filter,
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
            buildsearch(req, val, e);
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
            match_fuzzy(e, s, "body");
            match_fuzzy(e, s, "subject");
            match_fuzzy(e, s, "from");
            match_fuzzy(e, s, "to");
            match_fuzzy(e, s, "location");
        }
        if ((s = json_string_value(json_object_get(filter, "title")))) {
            match_fuzzy(this, s, "subject");
        }
        if ((s = json_string_value(json_object_get(filter, "description")))) {
            match_fuzzy(this, s, "body");
        }
        if ((s = json_string_value(json_object_get(filter, "location")))) {
            match_fuzzy(this, s, "location");
        }
        if ((s = json_string_value(json_object_get(filter, "owner")))) {
            match_fuzzy(this, s, "from");
        }
        if ((s = json_string_value(json_object_get(filter, "attendee")))) {
            match_fuzzy(this, s, "to");
        }
    }

    return this;
}

static void filter_timerange(json_t *filter, time_t *before, time_t *after,
                             int *skip_search)
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

            filter_timerange(val, &bf, &af, skip_search);

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

        if (json_object_get(filter, "text") ||
            json_object_get(filter, "title") ||
            json_object_get(filter, "description") ||
            json_object_get(filter, "location") ||
            json_object_get(filter, "owner") ||
            json_object_get(filter, "attendee")) {

            *skip_search = 0;
        }
    }
}

struct search_timerange_rock {
    jmap_req_t *req;
    hash_table *search_timerange;  /* hash of all UIDs within timerange */
    size_t seen;               /* seen uids inside and outside of window */
    int check_acl;             /* if true, check mailbox ACL for read access */
    hash_table *mboxrights;    /* cache of (int) ACLs, keyed by mailbox name */

    int build_result; /* if true, filter search window and buidl result */
    size_t limit;     /* window limit */
    size_t pos;       /* window start position */
    json_t *result;   /* windowed search result */
};

static int search_timerange_cb(void *vrock, struct caldav_data *cdata)
{
    struct search_timerange_rock *rock = vrock;
    jmap_req_t *req = rock->req;

    /* Ignore tombstones */
    if (!cdata->dav.alive) {
        return 0;
    }

    /* Check permissions */
    int rights = jmap_myrights_byname(req, cdata->dav.mailbox);
    if (!(rights & ACL_READ))
        return 0;

    /* Keep track of this event */
    hash_insert(cdata->ical_uid, (void*)1, rock->search_timerange);
    rock->seen++;

    if (rock->build_result) {
        /* Is it within the search window? */
        if (rock->pos > rock->seen) {
            return 0;
        }
        if (rock->limit && json_array_size(rock->result) >= rock->limit) {
            return 0;
        }
        /* Add the event to the result list */
        json_array_append_new(rock->result, json_string(cdata->ical_uid));
    }
    return 0;
}

static int jmapevent_search(jmap_req_t *req, json_t *filter,
                            size_t limit, size_t pos,
                            size_t *total, json_t **eventids)
{
    int r, i;
    struct searchargs *searchargs = NULL;
    struct index_init init;
    struct index_state *state = NULL;
    search_query_t *query = NULL;
    struct caldav_db *db = NULL;
    time_t before, after;
    char *icalbefore = NULL, *icalafter = NULL;
    hash_table *search_timerange = NULL;
    int skip_search = 1;
    icaltimezone *utc = icaltimezone_get_utc_timezone();
    struct sortcrit *sortcrit = NULL;
    hash_table mboxrights = HASH_TABLE_INITIALIZER;
    int check_acl = strcmp(req->accountid, req->userid);

    if (check_acl) {
        construct_hash_table(&mboxrights, 128, 0);
    }

    /* Initialize return values */
    *eventids = json_pack("[]");
    *total = 0;

    /* Determine the filter timerange, if any */
    filter_timerange(filter, &before, &after, &skip_search);
    if (before != caldav_eternity) {
        icaltimetype t = icaltime_from_timet_with_zone(before, 0, utc);
        icalbefore = icaltime_as_ical_string_r(t);
    }
    if (after != caldav_epoch) {
        icaltimetype t = icaltime_from_timet_with_zone(after, 0, utc);
        icalafter = icaltime_as_ical_string_r(t);
    }
    if (!icalbefore && !icalafter) {
        skip_search = 0;
    }

    /* Open the CalDAV database */
    db = caldav_open_userid(req->accountid);
    if (!db) {
        syslog(LOG_ERR,
               "caldav_open_mailbox failed for user %s", req->accountid);
        r = IMAP_INTERNAL;
        goto done;
    }

    /* Filter events by timerange */
    if (before != caldav_eternity || after != caldav_epoch) {
        search_timerange = xzmalloc(sizeof(hash_table));
        construct_hash_table(search_timerange, 64, 0);

        struct search_timerange_rock rock = {
            req,
            search_timerange,
            0, /*seen*/
            check_acl,
            &mboxrights,
            skip_search, /*build_result*/
            limit,
            pos,
            *eventids /*result*/
        };
        r = caldav_foreach_timerange(db, NULL,
                                     after, before, search_timerange_cb, &rock);
        if (r) goto done;

        *total = rock.seen;
    }

    /* Can we skip search? */
    if (skip_search) goto done;

    /* Reset search results */
    *total = 0;
    json_array_clear(*eventids);

    /* Build searchargs */
    searchargs = new_searchargs(NULL, GETSEARCH_CHARSET_FIRST,
            &jmap_namespace, req->accountid, req->authstate, 0);
    searchargs->root = buildsearch(req, filter, NULL);

    /* Need some stable sort criteria for windowing */
    sortcrit = xzmalloc(2 * sizeof(struct sortcrit));
    sortcrit[0].flags |= SORT_REVERSE;
    sortcrit[0].key = SORT_ARRIVAL;
    sortcrit[1].key = SORT_SEQUENCE;

    /* Run the search query */
    memset(&init, 0, sizeof(init));
    init.userid = req->accountid;
    init.authstate = req->authstate;
    init.want_expunged = 0;
    init.want_mbtype = MBTYPE_CALENDAR;

    r = index_open(req->inboxname, &init, &state);
    if (r) goto done;

    query = search_query_new(state, searchargs);
    query->sortcrit = sortcrit;
    query->multiple = 1;
    query->need_ids = 1;
    query->want_expunged = 0;
    query->want_mbtype = MBTYPE_CALENDAR;
    r = search_query_run(query);
    if (r && r != IMAP_NOTFOUND) goto done;
    r = 0;

    /* Aggregate result */
    for (i = 0 ; i < query->merged_msgdata.count; i++) {
        MsgData *md = ptrarray_nth(&query->merged_msgdata, i);
        search_folder_t *folder = md->folder;
        struct caldav_data *cdata;

        if (!folder) continue;

        /* Check permissions */
        int rights = jmap_myrights_byname(req, folder->mboxname);
        if (!(rights & ACL_READ))
            continue;

        /* Fetch the CalDAV db record */
        r = caldav_lookup_imapuid(db, folder->mboxname, md->uid, &cdata, 0);
        if (r) continue;

        /* Filter by timerange, if any */
        if (search_timerange && !hash_lookup(cdata->ical_uid, search_timerange)) {
            continue;
        }

        /* It's a legit search hit... */
        *total = *total + 1;

        /* ...probably outside the search window? */
        if (limit && json_array_size(*eventids) + 1 > limit) {
            continue;
        }
        if (pos >= *total) {
            continue;
        }

        /* Add the search result */
        json_array_append_new(*eventids, json_string(cdata->ical_uid));
    }

done:
    if (state) {
        state->mailbox = NULL;
        index_close(&state);
    }
    if (search_timerange) {
        free_hash_table(search_timerange, NULL);
        free(search_timerange);
    }
    free_hash_table(&mboxrights, free);
    if (searchargs) freesearchargs(searchargs);
    if (sortcrit) freesortcrit(sortcrit);
    if (query) search_query_free(query);
    if (db) caldav_close(db);
    free(icalbefore);
    free(icalafter);
    return r;
}

static void validatefilter(json_t *filter, const char *prefix, json_t *invalid)
{
    struct buf buf = BUF_INITIALIZER;
    icaltimetype timeval;
    const char *s;
    json_t *arg, *val;
    size_t i;

    if (!JNOTNULL(filter) || json_typeof(filter) != JSON_OBJECT) {
        json_array_append_new(invalid, json_string(prefix));
        return;
    }

    if (readprop_full(filter, prefix, "operator", 0, invalid, "s", &s) > 0) {

        if (strcmp("AND", s) && strcmp("OR", s) && strcmp("NOT", s)) {
            buf_printf(&buf, "%s.%s", prefix, "operator");
            json_array_append_new(invalid, json_string(buf_cstring(&buf)));
            buf_reset(&buf);
        }

        arg = json_object_get(filter, "conditions");
        if (!json_array_size(arg)) {
            buf_printf(&buf, "%s.conditions", prefix);
            json_array_append_new(invalid, json_string(buf_cstring(&buf)));
            buf_reset(&buf);
        }

        json_array_foreach(arg, i, val) {
            buf_printf(&buf, "%s.conditions[%zu]", prefix, i);
            validatefilter(val, buf_cstring(&buf), invalid);
            buf_reset(&buf);
        }
    }
    else {
        arg = json_object_get(filter, "inCalendars");
        if (arg && json_array_size(arg)) {
            size_t i;
            json_t *uid;
            json_array_foreach(arg, i, uid) {
                const char *id = json_string_value(uid);
                if (!id || id[0] == '#') {
                    buf_printf(&buf, "%s.calendars[%zu]", prefix, i);
                    json_array_append_new(invalid, json_string(buf_cstring(&buf)));
                    buf_reset(&buf);
                }
            }
        }
        else if (JNOTNULL(arg) && !json_array_size(arg)) {
            buf_printf(&buf, "%s.%s", prefix, "inCalendars");
            json_array_append_new(invalid, json_string(buf_cstring(&buf)));
            buf_reset(&buf);
        }

        if (JNOTNULL(json_object_get(filter, "after"))) {
            if (readprop_full(filter, prefix, "after", 1, invalid, "s", &s) > 0) {
                if (!utcdate_to_icaltime(s, &timeval)) {
                    buf_printf(&buf, "%s.%s", prefix, "after");
                    json_array_append_new(invalid, json_string(buf_cstring(&buf)));
                    buf_reset(&buf);
                }
            }
        }
        if (JNOTNULL(json_object_get(filter, "before"))) {
            if (readprop_full(filter, prefix, "before", 1, invalid, "s", &s) > 0) {
                if (!utcdate_to_icaltime(s, &timeval)) {
                    buf_printf(&buf, "%s.%s", prefix, "before");
                    json_array_append_new(invalid, json_string(buf_cstring(&buf)));
                    buf_reset(&buf);
                }
            }
        }

        if (JNOTNULL(json_object_get(filter, "text"))) {
            readprop_full(filter, prefix, "text", 1, invalid, "s", &s);
        }
        if (JNOTNULL(json_object_get(filter, "summary"))) {
            readprop_full(filter, prefix, "summary", 1, invalid, "s", &s);
        }
        if (JNOTNULL(json_object_get(filter, "description"))) {
            readprop_full(filter, prefix, "description", 1, invalid, "s", &s);
        }
        if (JNOTNULL(json_object_get(filter, "location"))) {
            readprop_full(filter, prefix, "location", 1, invalid, "s", &s);
        }
        if (JNOTNULL(json_object_get(filter, "owner"))) {
            readprop_full(filter, prefix, "owner", 1, invalid, "s", &s);
        }
        if (JNOTNULL(json_object_get(filter, "attendee"))) {
            readprop_full(filter, prefix, "attendee", 1, invalid, "s", &s);
        }
    }

    buf_free(&buf);
}

static int getCalendarEventsList(struct jmap_req *req)
{
    int r = 0, pe;
    json_t *invalid;
    int dofetch = 0;
    json_t *filter;
    size_t total = 0;
    json_t *events = NULL;

    /* Parse and validate arguments. */
    invalid = json_pack("[]");

    /* filter */
    filter = json_object_get(req->args, "filter");
    if (JNOTNULL(filter)) {
        validatefilter(filter, "filter", invalid);
    }

    /* position */
    json_int_t pos = 0;
    if (JNOTNULL(json_object_get(req->args, "position"))) {
        pe = readprop(req->args, "position",
                      0 /*mandatory*/, invalid, "I", &pos);
        if (pe > 0 && pos < 0) {
            json_array_append_new(invalid, json_string("position"));
        }
    }

    /* limit */
    json_int_t limit = 0;
    if (JNOTNULL(json_object_get(req->args, "limit"))) {
        pe = readprop(req->args, "limit",
                      0 /*mandatory*/, invalid, "I", &limit);
        if (pe > 0 && limit < 0) {
            json_array_append_new(invalid, json_string("limit"));
        }
    }

    /* fetchCalendarEvents */
    if (JNOTNULL(json_object_get(req->args, "fetchCalendarEvents"))) {
        readprop(req->args, "fetchCalendarEvents",
                 0 /*mandatory*/, invalid, "b", &dofetch);
    }

    if (json_array_size(invalid)) {
        json_t *err = json_pack("{s:s, s:o}",
                                "type", "invalidArguments", "arguments", invalid);
        json_array_append_new(req->response,
                              json_pack("[s,o,s]", "error", err, req->tag));
        r = 0;
        goto done;
    }
    json_decref(invalid);

    /* Call search */
    r = jmapevent_search(req, filter, limit, pos, &total, &events);
    if (r) goto done;

    /* Prepare response. */
    json_t *eventList = json_pack("{}");
    json_object_set_new(eventList, "accountId", json_string(req->accountid));
    json_object_set_new(eventList, "state", jmap_getstate(req, MBTYPE_CALENDAR));
    json_object_set_new(eventList, "position", json_integer(pos));
    json_object_set_new(eventList, "total", json_integer(total));
    json_object_set(eventList, "ids", events);
    if (filter) json_object_set(eventList, "filter", filter);

    json_t *item = json_pack("[]");
    json_array_append_new(item, json_string("CalendarEvent/query"));
    json_array_append_new(item, eventList);
    json_array_append_new(item, json_string(req->tag));
    json_array_append_new(req->response, item);

    /* Fetch updated records, if requested. */
    if (dofetch) {
        struct jmap_req subreq = *req;
        subreq.args = json_pack("{}");
        json_object_set_new(subreq.args, "accountId",
                            json_string(req->accountid));
        json_object_set(subreq.args, "ids", events);
        r = getCalendarEvents(&subreq);
        json_decref(subreq.args);
    }

done:
    if (events) json_decref(events);
    return r;
}

static int getCalendarPreferences(struct jmap_req *req)
{
    /* Just a dummy implementation to make the JMAP web client happy. */
    json_t *item = json_pack("[]");
    json_t *res = json_pack("{}");
    json_array_append_new(item, json_string("CalendarPreference/get"));
    json_array_append_new(item, res);
    json_object_set_new(res, "accountId", json_string(req->accountid));
    json_array_append_new(item, json_string(req->tag));
    json_array_append_new(req->response, item);
    return 0;
}
