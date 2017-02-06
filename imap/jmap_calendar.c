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
#include <jansson.h>
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
#include "ical_support.h"
#include "imap_err.h"
#include "jmap_ical.h"
#include "stristr.h"
#include "times.h"
#include "util.h"
#include "xmalloc.h"

#include "jmap_common.h"

/* generated headers are not necessarily in current directory */
#include "imap/http_err.h"


static int getCalendars(struct jmap_req *req);
static int getCalendarUpdates(struct jmap_req *req);
static int setCalendars(struct jmap_req *req);
static int getCalendarEvents(struct jmap_req *req);
static int getCalendarEventUpdates(struct jmap_req *req);
static int getCalendarEventList(struct jmap_req *req);
static int setCalendarEvents(struct jmap_req *req);
static int getCalendarPreferences(struct jmap_req *req);

jmap_msg_t jmap_calendar_messages[] = {
    { "getCalendars",           &getCalendars },
    { "getCalendarUpdates",     &getCalendarUpdates },
    { "setCalendars",           &setCalendars },
    { "getCalendarEvents",      &getCalendarEvents },
    { "getCalendarEventUpdates",&getCalendarEventUpdates },
    { "getCalendarEventList",   &getCalendarEventList },
    { "setCalendarEvents",      &setCalendarEvents },
    { "getCalendarPreferences", &getCalendarPreferences },
    { NULL,                     NULL}
};

/* FIXME DUPLICATE START */

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

struct updates_rock {
    json_t *changed;
    json_t *removed;

    size_t seen_records;
    size_t max_records;

    struct mailbox *mailbox;
    short fetchmodseq;
    modseq_t highestmodseq;
};

static void strip_spurious_deletes(struct updates_rock *urock)
{
    /* if something is mentioned in both DELETEs and UPDATEs, it's probably
     * a move.  O(N*M) algorithm, but there are rarely many, and the alternative
     * of a hash will cost more */
    unsigned i, j;

    for (i = 0; i < json_array_size(urock->removed); i++) {
        const char *del = json_string_value(json_array_get(urock->removed, i));

        for (j = 0; j < json_array_size(urock->changed); j++) {
            const char *up =
                json_string_value(json_array_get(urock->changed, j));
            if (!strcmpsafe(del, up)) {
                json_array_remove(urock->removed, i--);
                break;
            }
        }
    }
}

static void updates_rock_update(struct updates_rock *rock,
                                struct dav_data dav,
                                const char *uid) {

    /* Count, but don't process items that exceed the maximum record count. */
    if (rock->max_records && ++(rock->seen_records) > rock->max_records) {
        return;
    }

    /* Report item as updated or removed. */
    if (dav.alive) {
        json_array_append_new(rock->changed, json_string(uid));
    } else {
        json_array_append_new(rock->removed, json_string(uid));
    }

    /* Fetch record to determine modseq. */
    if (rock->fetchmodseq) {
        struct index_record record;
        int r;

        if (!rock->mailbox || strcmp(rock->mailbox->name, dav.mailbox)) {
            mailbox_close(&rock->mailbox);
            r = mailbox_open_irl(dav.mailbox, &rock->mailbox);
            if (r) {
                syslog(LOG_INFO, "mailbox_open_irl(%s) failed: %s",
                        dav.mailbox, error_message(r));
                return;
            }
        }
        r = mailbox_find_index_record(rock->mailbox, dav.imap_uid, &record);
        if (r) {
            syslog(LOG_INFO, "mailbox_find_index_record(%s,%d) failed: %s",
                    rock->mailbox->name, dav.imap_uid, error_message(r));
            mailbox_close(&rock->mailbox);
            return;
        }
        if (record.modseq > rock->highestmodseq) {
            rock->highestmodseq = record.modseq;
        }
    }
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

/* FIXME DUPLICATE END */

/* Helper flags for setCalendarEvents */
#define JMAP_CREATE     (1<<0) /* Current request is a create. */
#define JMAP_UPDATE     (1<<1) /* Current request is an update. */
#define JMAP_DESTROY    (1<<2) /* Current request is a destroy. */

/* Return a non-zero value if uid maps to a special-purpose calendar mailbox,
 * that may not be read or modified by the user. */
static int jmap_calendar_ishidden(const char *uid) {
    if (!strcmp(uid, "#calendars")) return 1;
    /* SCHED_INBOX  and SCHED_OUTBOX end in "/", so trim them */
    if (!strncmp(uid, SCHED_INBOX, strlen(SCHED_INBOX)-1)) return 1;
    if (!strncmp(uid, SCHED_OUTBOX, strlen(SCHED_OUTBOX)-1)) return 1;
    if (!strncmp(uid, MANAGED_ATTACH, strlen(MANAGED_ATTACH)-1)) return 1;
    return 0;
}

struct calendars_rock {
    struct jmap_req *req;
    json_t *array;
    struct hash_table *props;
    struct mailbox *mailbox;
    int rows;
};

/* Determine, if mboxname is a Cyrus calendar mailbox AND is able to
 * store VEVENTs. Store the result in is_cal.
 *
 * By default, any Cyrus calendar mailbox is able to store VEVENTs,
 * unless this is explicitly ruled out by setting the
 * {CALDAV}:supported-calendar-component-set property on the mailbox.
 *
 * userid must be allowed to lookup annotations on mboxname.
 *
 * Return non-zero on error. */
static int jmap_mboxname_is_calendar(const char *mboxname, const char *userid, int *is_cal)
{
    struct buf attrib = BUF_INITIALIZER;
    static const char *calcompset_annot =
        DAV_ANNOT_NS "<" XML_NS_CALDAV ">supported-calendar-component-set";
    unsigned long types = -1; /* ALL component types by default. */

    if (!mboxname_iscalendarmailbox(mboxname, 0)) {
        *is_cal = 0;
        return 0;
    }

    int r = annotatemore_lookupmask(mboxname, calcompset_annot, userid, &attrib);
    if (r) goto done;
    if (attrib.len) {
        types = strtoul(buf_cstring(&attrib), NULL, 10);
    }
    *is_cal = types & CAL_COMP_VEVENT;
done:
    buf_free(&attrib);
    return r;
}

static int getcalendars_cb(const mbentry_t *mbentry, void *rock)
{
    struct calendars_rock *crock = (struct calendars_rock *)rock;
    int r;

    /* Only calendars... */
    if (!(mbentry->mbtype & MBTYPE_CALENDAR)) return 0;

    /* ...which are at least readable or visible... */
    int rights = httpd_myrights(crock->req->authstate, mbentry);
    /* XXX - What if just READFB is set? */
    if (!(rights & (DACL_READ|DACL_READFB))) {
        return 0;
    }

    /* ...and contain VEVENTs. */
    int is_cal = 0;
    r = jmap_mboxname_is_calendar(mbentry->name, httpd_userid, &is_cal);
    if (r || !is_cal) {
        goto done;
    }

    /* OK, we want this one... */
    const char *collection = strrchr(mbentry->name, '.') + 1;

    /* ...unless it's one of the special names. */
    if (jmap_calendar_ishidden(collection)) return 0;

    crock->rows++;

    json_t *obj = json_pack("{}");

    json_object_set_new(obj, "id", json_string(collection));

    if (_wantprop(crock->props, "x-href")) {
        char *xhref = jmap_xhref(mbentry->name, NULL);
        json_object_set_new(obj, "x-href", json_string(xhref));
        free(xhref);
    }

    if (_wantprop(crock->props, "name")) {
        struct buf attrib = BUF_INITIALIZER;
        static const char *displayname_annot =
            DAV_ANNOT_NS "<" XML_NS_DAV ">displayname";
        r = annotatemore_lookupmask(mbentry->name, displayname_annot, httpd_userid, &attrib);
        /* fall back to last part of mailbox name */
        if (r || !attrib.len) buf_setcstr(&attrib, collection);
        json_object_set_new(obj, "name", json_string(buf_cstring(&attrib)));
        buf_free(&attrib);
    }

    if (_wantprop(crock->props, "color")) {
        struct buf attrib = BUF_INITIALIZER;
        static const char *color_annot =
            DAV_ANNOT_NS "<" XML_NS_APPLE ">calendar-color";
        r = annotatemore_lookupmask(mbentry->name, color_annot, httpd_userid, &attrib);
        if (!r && attrib.len)
            json_object_set_new(obj, "color", json_string(buf_cstring(&attrib)));
        buf_free(&attrib);
    }

    if (_wantprop(crock->props, "sortOrder")) {
        struct buf attrib = BUF_INITIALIZER;
        static const char *order_annot =
            DAV_ANNOT_NS "<" XML_NS_APPLE ">calendar-order";
        r = annotatemore_lookupmask(mbentry->name, order_annot, httpd_userid, &attrib);
        if (!r && attrib.len) {
            char *ptr;
            long val = strtol(buf_cstring(&attrib), &ptr, 10);
            if (ptr && *ptr == '\0') {
                json_object_set_new(obj, "sortOrder", json_integer(val));
            }
            else {
                /* Ignore, but report non-numeric calendar-order values */
                syslog(LOG_WARNING, "sortOrder: strtol(%s) failed", buf_cstring(&attrib));
            }
        }
        buf_free(&attrib);
    }

    if (_wantprop(crock->props, "isVisible")) {
        struct buf attrib = BUF_INITIALIZER;
        static const char *color_annot =
            DAV_ANNOT_NS "<" XML_NS_CALDAV ">X-FM-isVisible";
        r = annotatemore_lookupmask(mbentry->name, color_annot, httpd_userid, &attrib);
        if (!r && attrib.len) {
            const char *val = buf_cstring(&attrib);
            if (!strncmp(val, "true", 4) || !strncmp(val, "1", 1)) {
                json_object_set_new(obj, "isVisible", json_true());
            } else if (!strncmp(val, "false", 5) || !strncmp(val, "0", 1)) {
                json_object_set_new(obj, "isVisible", json_false());
            } else {
                /* Report invalid value and fall back to default. */
                syslog(LOG_WARNING, "isVisible: invalid annotation value: %s", val);
                json_object_set_new(obj, "isVisible", json_string("true"));
            }
        }
        buf_free(&attrib);
    }

    if (_wantprop(crock->props, "mayReadFreeBusy")) {
        int bool = rights & DACL_READFB;
        json_object_set_new(obj, "mayReadFreeBusy", bool ? json_true() : json_false());
    }

    if (_wantprop(crock->props, "mayReadItems")) {
        int bool = rights & DACL_READ;
        json_object_set_new(obj, "mayReadItems", bool ? json_true() : json_false());
    }

    if (_wantprop(crock->props, "mayAddItems")) {
        int bool = rights & DACL_WRITECONT;
        json_object_set_new(obj, "mayAddItems", bool ? json_true() : json_false());
    }

    if (_wantprop(crock->props, "mayModifyItems")) {
        int bool = rights & DACL_WRITECONT;
        json_object_set_new(obj, "mayModifyItems", bool ? json_true() : json_false());
    }

    if (_wantprop(crock->props, "mayRemoveItems")) {
        int bool = rights & DACL_RMRES;
        json_object_set_new(obj, "mayRemoveItems", bool ? json_true() : json_false());
    }

    if (_wantprop(crock->props, "mayRename")) {
        int bool = rights & DACL_RMCOL;
        json_object_set_new(obj, "mayRename", bool ? json_true() : json_false());
    }

    if (_wantprop(crock->props, "mayDelete")) {
        int bool = rights & DACL_RMCOL;
        json_object_set_new(obj, "mayDelete", bool ? json_true() : json_false());
    }

    json_array_append_new(crock->array, obj);

done:
    return r;
}


/* jmap calendar APIs */

/* Update the calendar properties in the calendar mailbox named mboxname.
 * NULL values and negative integers are ignored. Return 0 on success. */
static int jmap_update_calendar(const char *mboxname,
                                const struct jmap_req *req,
                                const char *name,
                                const char *color,
                                int sortOrder,
                                int isVisible)
{
    struct mailbox *mbox = NULL;
    mbentry_t mbentry;
    int rights;
    annotate_state_t *astate = NULL;
    struct buf val = BUF_INITIALIZER;
    int r;

    r = mailbox_open_iwl(mboxname, &mbox);
    if (r) {
        syslog(LOG_ERR, "mailbox_open_iwl(%s) failed: %s",
                mboxname, error_message(r));
        return r;
    }
    mbentry.acl = mbox->acl;
    mbentry.mbtype = mbox->mbtype;
    rights = httpd_myrights(req->authstate, &mbentry);
    if (!(rights & DACL_READ)) {
        r = IMAP_MAILBOX_NONEXISTENT;
    } else if (!(rights & DACL_WRITE)) {
        r = IMAP_PERMISSION_DENIED;
    }
    if (r) {
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
        r = annotate_state_writemask(astate, displayname_annot, httpd_userid, &val);
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
        r = annotate_state_writemask(astate, sortOrder_annot, httpd_userid, &val);
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
        r = annotate_state_writemask(astate, sortOrder_annot, httpd_userid, &val);
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
static int jmap_delete_calendar(const char *mboxname, const struct jmap_req *req) {
    struct mailbox *mbox = NULL;
    mbentry_t *mbentry = NULL;
    int r, rights;

    r = mboxlist_lookup(mboxname, &mbentry, NULL);
    if (r) {
        syslog(LOG_ERR, "mboxlist_lookup(%s) failed: %s",
                mboxname, error_message(r));
        return r;
    }

    mailbox_close(&mbox);
    rights = httpd_myrights(req->authstate, mbentry);
    mboxlist_entry_free(&mbentry);

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

static int getCalendars(struct jmap_req *req)
{
    struct calendars_rock rock;
    int r = 0;

    r = caldav_create_defaultcalendars(req->userid);
    if (r == IMAP_MAILBOX_NONEXISTENT) {
        /* The account exists but does not have a root mailbox. */
        json_t *err = json_pack("{s:s}", "type", "accountNoCalendars");
        json_array_append_new(req->response, json_pack("[s,o,s]",
                    "error", err, req->tag));
        return 0;
    } else if (r) return r;

    rock.array = json_pack("[]");
    rock.req = req;
    rock.props = NULL;
    rock.rows = 0;

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
    if (want) {
        int i;
        int size = json_array_size(want);
        for (i = 0; i < size; i++) {
            const char *id = json_string_value(json_array_get(want, i));
            if (id && id[0] == '#') {
                id = hash_lookup(id + 1, &req->idmap->calendars);
            }
            if (!id) continue;
            rock.rows = 0;
            char *mboxname = caldav_mboxname(req->userid, id);
            r = mboxlist_mboxtree(mboxname, &getcalendars_cb, &rock, MBOXTREE_SKIP_CHILDREN);
            free(mboxname);
            if (r) goto done;
            if (!rock.rows) {
                json_array_append_new(notfound, json_string(id));
            }
        }
    }
    else {
        r = mboxlist_usermboxtree(req->userid, &getcalendars_cb, &rock, /*flags*/0);
        if (r) goto done;
    }

    json_t *calendars = json_pack("{}");
    json_incref(rock.array);
    json_object_set_new(calendars, "accountId", json_string(req->userid));
    json_object_set_new(calendars, "state", jmap_getstate(MBTYPE_CALENDAR, req));
    json_object_set_new(calendars, "list", rock.array);
    if (json_array_size(notfound)) {
        json_object_set_new(calendars, "notFound", notfound);
    }
    else {
        json_decref(notfound);
        json_object_set_new(calendars, "notFound", json_null());
    }

    json_t *item = json_pack("[]");
    json_array_append_new(item, json_string("calendars"));
    json_array_append_new(item, calendars);
    json_array_append_new(item, json_string(req->tag));

    json_array_append_new(req->response, item);

done:
    if (rock.props) {
        free_hash_table(rock.props, NULL);
        free(rock.props);
    }
    json_decref(rock.array);
    return r;
}

struct calendarupdates_rock {
    modseq_t oldmodseq;
    json_t *changed;
    json_t *removed;
};

static int getcalendarupdates_cb(const mbentry_t *mbentry, void *vrock) {
    struct calendarupdates_rock *rock = (struct calendarupdates_rock *) vrock;
    /* Ignore any mailboxes aren't (possibly deleted) calendars. */
    if (!(mbentry->mbtype & (MBTYPE_CALENDAR|MBTYPE_DELETED))) {
        return 0;
    }
    /* Ignore special-purpose calendar mailboxes. */
    const char *uid = strrchr(mbentry->name, '.');
    if (uid) {
        uid++;
    } else {
        uid = mbentry->name;
    }
    if (jmap_calendar_ishidden(uid)) {
        return 0;
    }
    int iscal;
    jmap_mboxname_is_calendar(mbentry->name, httpd_userid, &iscal);
    if (!iscal) {
        return 0;
    }

    /* Ignore old changes. */
    if (mbentry->foldermodseq <= rock->oldmodseq) {
        return 0;
    }

    /* Report this calendar as changed or removed. */
    if (mbentry->mbtype & MBTYPE_CALENDAR) {
        json_array_append_new(rock->changed, json_string(uid));
    } else if (mbentry->mbtype & MBTYPE_DELETED) {
        json_array_append_new(rock->removed, json_string(uid));
    }

    return 0;
}

static int getCalendarUpdates(struct jmap_req *req)
{
    int r, pe;
    json_t *invalid;
    struct caldav_db *db;
    const char *since = NULL;
    int dofetch = 0;
    struct buf buf = BUF_INITIALIZER;
    modseq_t oldmodseq = 0;

    r = caldav_create_defaultcalendars(req->userid);
    if (r == IMAP_MAILBOX_NONEXISTENT) {
        /* The account exists but does not have a root mailbox. */
        json_t *err = json_pack("{s:s}", "type", "accountNoCalendars");
        json_array_append_new(req->response, json_pack("[s,o,s]",
                    "error", err, req->tag));
        return 0;
    } else if (r) return r;


    db = caldav_open_userid(req->userid);
    if (!db) {
        syslog(LOG_ERR, "caldav_open_mailbox failed for user %s", req->userid);
        r = IMAP_INTERNAL;
        goto done;
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
    readprop(req->args, "fetchRecords", 0 /*mandatory*/, invalid, "b", &dofetch);
    if (json_array_size(invalid)) {
        json_t *err = json_pack("{s:s, s:o}", "type", "invalidArguments", "arguments", invalid);
        json_array_append_new(req->response, json_pack("[s,o,s]", "error", err, req->tag));
        r = 0;
        goto done;
    }
    json_decref(invalid);

    /* Lookup any updates. */
    char *mboxname = caldav_mboxname(req->userid, NULL);
    struct calendarupdates_rock rock;
    memset(&rock, 0, sizeof(struct calendarupdates_rock));
    rock.oldmodseq = oldmodseq;
    rock.changed = json_pack("[]");
    rock.removed = json_pack("[]");
    r = mboxlist_mboxtree(mboxname, getcalendarupdates_cb, &rock,
            MBOXTREE_TOMBSTONES|MBOXTREE_SKIP_ROOT);
    free(mboxname);
    if (r) {
        json_t *err = json_pack("{s:s}", "type", "cannotCalculateChanges");
        json_array_append_new(req->response, json_pack("[s,o,s]", "error", err, req->tag));
        json_decref(rock.changed);
        json_decref(rock.removed);
        goto done;
    }

    /* Create response. */
    json_t *calendarUpdates = json_pack("{}");
    json_object_set_new(calendarUpdates, "accountId", json_string(req->userid));
    json_object_set_new(calendarUpdates, "oldState", json_string(since));
    json_object_set_new(calendarUpdates, "newState", jmap_getstate(MBTYPE_CALENDAR, req));

    json_object_set_new(calendarUpdates, "changed", rock.changed);
    json_object_set_new(calendarUpdates, "removed", rock.removed);

    json_t *item = json_pack("[]");
    json_array_append_new(item, json_string("calendarUpdates"));
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
    if (db) caldav_close(db);
    return r;
}

static int setCalendars(struct jmap_req *req)
{
    int r = 0;
    json_t *set = NULL;

    json_t *state = json_object_get(req->args, "ifInState");
    if (state && jmap_checkstate(state, MBTYPE_CALENDAR, req)) {
        json_array_append_new(req->response, json_pack("[s, {s:s}, s]",
                    "error", "type", "stateMismatch", req->tag));
        goto done;
    }
    set = json_pack("{s:s}", "accountId", req->userid);
    json_object_set_new(set, "oldState", jmap_getstate(MBTYPE_CALENDAR, req));

    r = caldav_create_defaultcalendars(req->userid);
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

            /* Create a calendar named uid. */
            char *uid = xstrdup(makeuuid());
            char *mboxname = caldav_mboxname(req->userid, uid);
            char rights[100];
            struct buf acl = BUF_INITIALIZER;
            buf_reset(&acl);
            cyrus_acl_masktostr(ACL_ALL | DACL_READFB, rights);
            buf_printf(&acl, "%s\t%s\t", httpd_userid, rights);
            cyrus_acl_masktostr(DACL_READFB, rights);
            buf_printf(&acl, "%s\t%s\t", "anyone", rights);
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
            r = jmap_update_calendar(mboxname, req, name, color, sortOrder, isVisible);
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
            /* hash_insert takes ownership of uid. */
            hash_insert(key, uid, &req->idmap->calendars);
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
                const char *newuid = hash_lookup(uid + 1, &req->idmap->calendars);
                if (!newuid) {
                    json_t *err = json_pack("{s:s}", "type", "notFound");
                    json_object_set_new(notUpdated, uid, err);
                    continue;
                }
                uid = newuid;
            }
            if (jmap_calendar_ishidden(uid)) {
                json_t *err = json_pack("{s:s}", "type", "notFound");
                json_object_set_new(notUpdated, uid, err);
                continue;
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

            /* Update the calendar named uid. */
            char *mboxname = caldav_mboxname(req->userid, uid);
            r = jmap_update_calendar(mboxname, req, name, color, sortOrder, isVisible);
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
                const char *newuid = hash_lookup(uid + 1, &req->idmap->calendars);
                if (!newuid) {
                    json_t *err = json_pack("{s:s}", "type", "notFound");
                    json_object_set_new(notDestroyed, uid, err);
                    continue;
                }
                uid = newuid;
            }
            if (jmap_calendar_ishidden(uid)) {
                json_t *err = json_pack("{s:s}", "type", "notFound");
                json_object_set_new(notDestroyed, uid, err);
                continue;
            }

            /* Do not allow to remove the default calendar. */
            char *mboxname = caldav_mboxname(req->userid, NULL);
            static const char *defaultcal_annot =
                DAV_ANNOT_NS "<" XML_NS_CALDAV ">schedule-default-calendar";
            struct buf attrib = BUF_INITIALIZER;
            r = annotatemore_lookupmask(mboxname, defaultcal_annot, httpd_userid, &attrib);
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

            /* Destroy calendar. */
            mboxname = caldav_mboxname(req->userid, uid);
            r = jmap_delete_calendar(mboxname, req);
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

        r = jmap_bumpstate(MBTYPE_CALENDAR, req);
        if (r) goto done;
    }
    json_object_set_new(set, "newState", jmap_getstate(MBTYPE_CALENDAR, req));

    json_incref(set);
    json_t *item = json_pack("[]");
    json_array_append_new(item, json_string("calendarsSet"));
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

static int getcalendarevents_cb(void *rock, struct caldav_data *cdata)
{
    struct calendars_rock *crock = (struct calendars_rock *)rock;
    struct index_record record;
    int r = 0;
    icalcomponent* ical = NULL;
    json_t *obj, *jprops = NULL;
    jmapical_err_t err;

    if (!cdata->dav.alive) {
        return 0;
    }

    /* Open calendar mailbox. */
    if (!crock->mailbox || strcmp(crock->mailbox->name, cdata->dav.mailbox)) {
        mailbox_close(&crock->mailbox);
        r = mailbox_open_irl(cdata->dav.mailbox, &crock->mailbox);
        if (r) goto done;
    }

    /* Locate calendar event ical data in mailbox. */
    r = mailbox_find_index_record(crock->mailbox, cdata->dav.imap_uid, &record);
    if (r) goto done;

    crock->rows++;

    /* Load VEVENT from record. */
    ical = record_to_ical(crock->mailbox, &record, NULL);
    if (!ical) {
        syslog(LOG_ERR, "record_to_ical failed for record %u:%s",
                cdata->dav.imap_uid, crock->mailbox->name);
        r = IMAP_INTERNAL;
        goto done;
    }

    /* Convert to JMAP */
    memset(&err, 0, sizeof(jmapical_err_t));
    if (crock->props) {
        /* XXX That's clumsy: the JMAP properties have already been converted
         * to a Cyrus hash, but the jmapical API requires a JSON object. */
        strarray_t *keys = hash_keys(crock->props);
        int i;
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

    /* Add participant id */
    if (_wantprop(crock->props, "participantId") && crock->req->userid) {
        const char *userid = crock->req->userid;
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
                sched_param_free(&sparam);
                continue;
            }

            /* First participant that matches isyou wins */
            json_object_set_new(obj, "participantId", json_string(id));
            sched_param_free(&sparam);
            break;
        }

        buf_free(&buf);
    }

    /* Add JMAP-only fields. */
    if (_wantprop(crock->props, "x-href")) {
        char *xhref = jmap_xhref(cdata->dav.mailbox, cdata->dav.resource);
        json_object_set_new(obj, "x-href", json_string(xhref));
        free(xhref);
    }
    if (_wantprop(crock->props, "calendarId")) {
        json_object_set_new(obj, "calendarId", json_string(strrchr(cdata->dav.mailbox, '.')+1));
    }
    json_object_set_new(obj, "id", json_string(cdata->ical_uid));

    /* Add JMAP event to response */
    json_array_append_new(crock->array, obj);

done:
    if (ical) icalcomponent_free(ical);
    if (jprops) json_decref(jprops);
    return r;
}

static int getCalendarEvents(struct jmap_req *req)
{
    struct calendars_rock rock;
    int r = 0;

    r = caldav_create_defaultcalendars(req->userid);
    if (r == IMAP_MAILBOX_NONEXISTENT) {
        /* The account exists but does not have a root mailbox. */
        json_t *err = json_pack("{s:s}", "type", "accountNoCalendars");
        json_array_append_new(req->response, json_pack("[s,o,s]",
                    "error", err, req->tag));
        return 0;
    } else if (r) return r;

    rock.array = json_pack("[]");
    rock.req = req;
    rock.props = NULL;
    rock.rows = 0;
    rock.mailbox = NULL;

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

    struct caldav_db *db = caldav_open_userid(req->userid);
    if (!db) {
        syslog(LOG_ERR, "caldav_open_mailbox failed for user %s", req->userid);
        r = IMAP_INTERNAL;
        goto done;
    }

    json_t *want = json_object_get(req->args, "ids");
    json_t *notfound = json_array();
    if (want) {
        int i;
        int size = json_array_size(want);
        for (i = 0; i < size; i++) {
            rock.rows = 0;
            const char *id = json_string_value(json_array_get(want, i));
            if (id && id[0] == '#') {
                id = hash_lookup(id + 1, &req->idmap->calendarevents);
            }
            if (!id) continue;
            r = caldav_get_events(db, NULL, id, &getcalendarevents_cb, &rock);
            if (r || !rock.rows) {
                json_array_append_new(notfound, json_string(id));
            }
        }
    } else {
        rock.rows = 0;
        r = caldav_get_events(db, NULL, NULL, &getcalendarevents_cb, &rock);
        if (r) goto done;
    }

    json_t *events = json_pack("{}");
    json_object_set_new(events, "state", jmap_getstate(MBTYPE_CALENDAR, req));

    json_incref(rock.array);
    json_object_set_new(events, "accountId", json_string(req->userid));
    json_object_set_new(events, "list", rock.array);
    if (json_array_size(notfound)) {
        json_object_set_new(events, "notFound", notfound);
    }
    else {
        json_decref(notfound);
        json_object_set_new(events, "notFound", json_null());
    }

    json_t *item = json_pack("[]");
    json_array_append_new(item, json_string("calendarEvents"));
    json_array_append_new(item, events);
    json_array_append_new(item, json_string(req->tag));

    json_array_append_new(req->response, item);

done:
    if (rock.props) {
        free_hash_table(rock.props, NULL);
        free(rock.props);
    }
    json_decref(rock.array);
    if (db) caldav_close(db);
    if (rock.mailbox) mailbox_close(&rock.mailbox);
    return r;
}

static int jmap_schedule_ical(struct jmap_req *req,
                              char **schedaddrp,
                              icalcomponent *oldical,
                              icalcomponent *ical,
                              int mode)
{
    /* Determine if any scheduling is required. */
    icalcomponent *src = mode&JMAP_DESTROY ? oldical : ical;
    icalcomponent *comp = icalcomponent_get_first_component(src, ICAL_VEVENT_COMPONENT);
    icalproperty *prop = icalcomponent_get_first_property(comp, ICAL_ORGANIZER_PROPERTY);
    if (!prop) return 0;
    const char *organizer = icalproperty_get_organizer(prop);
    if (!organizer) return 0;
    if (!strncasecmp(organizer, "mailto:", 7)) organizer += 7;

    if (!*schedaddrp) {
        const char **hdr = spool_getheader(req->txn->req_hdrs, "Schedule-Address");
        if (hdr) *schedaddrp = xstrdup(hdr[0]);
    }

    /* XXX - after legacy records are gone, we can strip this and just not send a
     * cancellation if deleting a record which was never replied to... */
    if (!*schedaddrp) {
        /* userid corresponding to target */
        *schedaddrp = xstrdup(req->userid);

        /* or overridden address-set for target user */
        const char *annotname = DAV_ANNOT_NS "<" XML_NS_CALDAV ">calendar-user-address-set";
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
        oldcomp = icalcomponent_get_first_component(oldical, ICAL_VEVENT_COMPONENT);
        if (oldcomp) prop = icalcomponent_get_first_property(oldcomp, ICAL_ORGANIZER_PROPERTY);
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

/* Create, update or destroy the JMAP calendar event. Mode must be one of
 * JMAP_CREATE, JMAP_UPDATE or JMAP_DESTROY. Return 0 for success and non-
 * fatal errors. */
static int jmap_write_calendarevent(json_t *event,
                                    struct caldav_db *db,
                                    const char *id,
                                    const char *uid,
                                    int mode,
                                    json_t *notWritten,
                                    struct jmap_req *req)
{
    int r, rights, pe;
    int needrights = DACL_RMRES|DACL_WRITE;

    struct caldav_data *cdata = NULL;
    mbentry_t mbentry;
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

    if (!(mode & JMAP_DESTROY)) {
        json_t *invalid = json_pack("[]");
        /* Look up the calendarId property. */
        pe = readprop(event, "calendarId", mode & JMAP_CREATE,  invalid, "s", &calendarId);
        if (pe > 0 && !strlen(calendarId)) {
            json_array_append_new(invalid, json_string("calendarId"));
        } else if (pe > 0 && *calendarId == '#') {
            const char *id = (const char *) hash_lookup(calendarId + 1, &req->idmap->calendars);
            if (id != NULL) {
                calendarId = id;
            } else {
                json_array_append_new(invalid, json_string("calendarId"));
            }
        }
        if (calendarId && jmap_calendar_ishidden(calendarId)) {
            json_t *err = json_pack("{s:s}", "type", "calendarNotFound");
            json_object_set_new(notWritten, id, err);
            r = 0; goto done;
        } else if (json_array_size(invalid)) {
            json_t *err = json_pack("{s:s, s:o}",
                    "type", "invalidProperties", "properties", invalid);
            json_object_set_new(notWritten, id, err);
            r = 0; goto done;
        }
        json_decref(invalid);
    }

    /* Handle any calendarId property errors and bail out. */

    /* Determine mailbox and resource name of calendar event. */
    if (mode & (JMAP_UPDATE|JMAP_DESTROY)) {
        r = caldav_lookup_uid(db, uid, &cdata);
        if (r && r != CYRUSDB_NOTFOUND) {
            syslog(LOG_ERR, "caldav_lookup_uid(%s) failed: %s",
                    uid, error_message(r));
            goto done;
        }
        if (r == CYRUSDB_NOTFOUND || !cdata->dav.alive ||
                !cdata->dav.rowid || !cdata->dav.imap_uid) {
            json_t *err = json_pack("{s:s}", "type", "notFound");
            json_object_set_new(notWritten, id, err);
            r = 0; goto done;
        }
        mboxname = xstrdup(cdata->dav.mailbox);
        resource = xstrdup(cdata->dav.resource);
    } else if (mode & JMAP_CREATE) {
        struct buf buf = BUF_INITIALIZER;
        mboxname = caldav_mboxname(req->userid, calendarId);
        buf_printf(&buf, "%s.ics", uid);
        resource = buf_newcstring(&buf);
        buf_free(&buf);
    }

    /* Open mailbox for writing */
    r = mailbox_open_iwl(mboxname, &mbox);
    if (r == IMAP_MAILBOX_NONEXISTENT) {
        json_t *err = json_pack("{s:s}", "type", "calendarNotFound");
        json_object_set_new(notWritten, id, err);
        r = 0; goto done;
    } else if (r) {
        syslog(LOG_ERR, "mailbox_open_iwl(%s) failed: %s",
                mboxname, error_message(r));
        goto done;
    }

    /* Check permissions. */
    mbentry.acl = mbox->acl;
    mbentry.mbtype = mbox->mbtype;
    rights = httpd_myrights(req->authstate, &mbentry);
    if (!(rights & needrights)) {
        /* Pretend this mailbox does not exist. */
        json_t *err = json_pack("{s:s}", "type", "notFound");
        json_object_set_new(notWritten, id, err);
        r = 0; goto done;
    }

    if (!(mode & JMAP_CREATE)) {
        /* Fetch index record for the resource */
        memset(&record, 0, sizeof(struct index_record));
        r = mailbox_find_index_record(mbox, cdata->dav.imap_uid, &record);
        if (r == IMAP_NOTFOUND) {
            json_t *err = json_pack("{s:s}", "type", "notFound");
            json_object_set_new(notWritten, id, err);
            r = 0; goto done;
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
    }

    if (!(mode & JMAP_DESTROY)) {
        /* Convert the JMAP calendar event to ical. */
        jmapical_err_t err;
        memset(&err, 0, sizeof(jmapical_err_t));

        if (!json_object_get(event, "uid")) {
            json_object_set_new(event, "uid", json_string(uid));
        }
        ical = jmapical_toical(event, oldical, &err);

        if (err.code == JMAPICAL_ERROR_PROPS) {
            /* Handle any property errors and bail out. */
            json_t *jerr = json_pack("{s:s, s:o}",
                    "type", "invalidProperties", "properties", err.props);
            json_object_set_new(notWritten, id, jerr);
            r = 0; goto done;
        } else if (err.code) {
            syslog(LOG_ERR, "jmapical_toical: %s", jmapical_strerror(err.code));
            r = IMAP_INTERNAL;
            goto done;
        }
    }

    if ((mode & JMAP_UPDATE) && calendarId) {
        /* Check, if we need to move the event. */
        dstmboxname = caldav_mboxname(req->userid, calendarId);
        if (strcmp(mbox->name, dstmboxname)) {
            /* Open destination mailbox for writing. */
            r = mailbox_open_iwl(dstmboxname, &dstmbox);
            if (r == IMAP_MAILBOX_NONEXISTENT) {
                json_t *err = json_pack("{s:s}", "type", "calendarNotFound");
                json_object_set_new(notWritten, id, err);
                r = 0; goto done;
            } else if (r) {
                syslog(LOG_ERR, "mailbox_open_iwl(%s) failed: %s",
                        dstmboxname, error_message(r));
                goto done;
            }
            /* Check permissions. */
            mbentry.acl = dstmbox->acl;
            mbentry.mbtype = dstmbox->mbtype;
            rights = httpd_myrights(req->authstate, &mbentry);
            if (!(rights & (DACL_WRITE))) {
                json_t *err = json_pack("{s:s}", "type", "calendarNotFound");
                json_object_set_new(notWritten, id, err);
                r = 0; goto done;
            }
        }
    }

    /* Handle scheduling. */
    r = jmap_schedule_ical(req, &schedule_address, oldical, ical, mode);
    if (r) goto done;


    if (mode & JMAP_DESTROY || ((mode & JMAP_UPDATE) && dstmbox)) {
        /* Expunge the resource from mailbox. */
        record.system_flags |= FLAG_EXPUNGED;
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
        mboxevent_set_access(mboxevent, NULL, NULL, req->userid, cdata->dav.mailbox, 0);
        mailbox_close(&mbox);
        mboxevent_notify(&mboxevent);
        mboxevent_free(&mboxevent);

        if (mode & JMAP_DESTROY) {
            /* Keep the VEVENT in the database but set alive to 0, to report
             * with getCalendarEventUpdates. */
            cdata->dav.alive = 0;
            cdata->dav.modseq = record.modseq;
            cdata->dav.imap_uid = record.uid;
            r = caldav_write(db, cdata);
            goto done;
        } else {
            /* Close the mailbox we moved the event from. */
            mailbox_close(&mbox);
            mbox = dstmbox;
            dstmbox = NULL;
            free(mboxname);
            mboxname = dstmboxname;
            dstmboxname = NULL;
        }
    }

    if (mode & (JMAP_CREATE|JMAP_UPDATE)) {
        /* Store the updated VEVENT. */
        struct transaction_t txn;
        memset(&txn, 0, sizeof(struct transaction_t));
        txn.req_hdrs = spool_new_hdrcache();
        /* XXX - fix userid */
        r = caldav_store_resource(&txn, ical, mbox, resource, db, 0, schedule_address);
        spool_free_hdrcache(txn.req_hdrs);
        buf_free(&txn.buf);
        if (r && r != HTTP_CREATED && r != HTTP_NO_CONTENT) {
            json_t *err = json_pack("{s:s}", "type", "unknownError");
            json_object_set_new(notWritten, id, err);
            goto done;
        }
        r = 0;
    }

done:
    if (mbox) mailbox_close(&mbox);
    if (mboxname) free(mboxname);
    if (dstmbox) mailbox_close(&dstmbox);
    if (dstmboxname) free(dstmboxname);
    if (resource) free(resource);
    if (ical) icalcomponent_free(ical);
    if (oldical) icalcomponent_free(oldical);
    free(schedule_address);
    return r;
}

static int setCalendarEvents(struct jmap_req *req)
{
    struct caldav_db *db = NULL;
    json_t *set = NULL;
    int r = 0;

    json_t *state = json_object_get(req->args, "ifInState");
    if (state && jmap_checkstate(state, MBTYPE_CALENDAR, req)) {
        json_array_append_new(req->response, json_pack("[s, {s:s}, s]",
                    "error", "type", "stateMismatch", req->tag));
        goto done;
    }

    set = json_pack("{s:s}", "accountId", req->userid);
    json_object_set_new(set, "oldState", jmap_getstate(MBTYPE_CALENDAR, req));

    r = caldav_create_defaultcalendars(req->userid);
    if (r == IMAP_MAILBOX_NONEXISTENT) {
        /* The account exists but does not have a root mailbox. */
        json_t *err = json_pack("{s:s}", "type", "accountNoCalendars");
        json_array_append_new(req->response, json_pack("[s,o,s]",
                    "error", err, req->tag));
        return 0;
    } else if (r) return r;

    db = caldav_open_userid(req->userid);
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

            if ((uid = (char *) json_string_value(json_object_get(arg, "uid")))) {
                /* Use custom iCalendar UID from request object */
                uid = xstrdup(uid);
            }  else {
                /* Create a iCalendar UID */
                uid = xstrdup(makeuuid());
            }

            /* Create the calendar event. */
            size_t error_count = json_object_size(notCreated);
            r = jmap_write_calendarevent(arg, db, key, uid, JMAP_CREATE, notCreated, req);
            if (r) {
                free(uid);
                goto done;
            }
            if (error_count != json_object_size(notCreated)) {
                /* Bail out for any setErrors. */
                free(uid);
                continue;
            }

            /* Report calendar event as created. */
            json_object_set_new(created, key, json_pack("{s:s}", "id", uid));
            hash_insert(key, uid, &req->idmap->calendarevents);
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
                const char *newuid = hash_lookup(uid + 1, &req->idmap->calendarevents);
                if (!newuid) {
                    json_t *err = json_pack("{s:s}", "type", "notFound");
                    json_object_set_new(notUpdated, uid, err);
                    continue;
                }
                uid = newuid;
            }

            if ((val = (char *) json_string_value(json_object_get(arg, "uid")))) {
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
            size_t error_count = json_object_size(notUpdated);
            r = jmap_write_calendarevent(arg, db, uid, uid, JMAP_UPDATE, notUpdated, req);
            if (r) goto done;
            if (error_count != json_object_size(notUpdated)) {
                /* Bail out for any setErrors. */
                continue;
            }

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
            size_t error_count;
            /* Validate uid. */
            const char *uid = json_string_value(juid);
            if (!uid) {
                continue;
            }
            if (uid && uid[0] == '#') {
                const char *newuid = hash_lookup(uid + 1, &req->idmap->calendarevents);
                if (!newuid) {
                    json_t *err = json_pack("{s:s}", "type", "notFound");
                    json_object_set_new(notDestroyed, uid, err);
                    continue;
                }
                uid = newuid;
            }

            /* Destroy the calendar event. */
            error_count = json_object_size(notDestroyed);
            r = jmap_write_calendarevent(NULL, db, uid, uid, JMAP_DESTROY, notDestroyed, req);
            if (r) goto done;
            if (error_count != json_object_size(notDestroyed)) {
                /* Bail out for any setErrors. */
                continue;
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

        r = jmap_bumpstate(MBTYPE_CALENDAR, req);
        if (r) goto done;
    }
    json_object_set_new(set, "newState", jmap_getstate(MBTYPE_CALENDAR, req));

    json_incref(set);
    json_t *item = json_pack("[]");
    json_array_append_new(item, json_string("calendarEventsSet"));
    json_array_append_new(item, set);
    json_array_append_new(item, json_string(req->tag));
    json_array_append_new(req->response, item);

done:
    if (db) caldav_close(db);
    if (set) json_decref(set);
    return r;
}

static int geteventupdates_cb(void *rock, struct caldav_data *cdata)
{
    struct updates_rock *urock = (struct updates_rock *) rock;
    updates_rock_update(urock, cdata->dav, cdata->ical_uid);
    return 0;
}

static int getCalendarEventUpdates(struct jmap_req *req)
{
    int r, pe;
    json_t *invalid;
    struct caldav_db *db;
    const char *since;
    modseq_t oldmodseq = 0;
    json_int_t maxChanges = 0;
    int dofetch = 0;
    struct updates_rock rock;
    struct buf buf = BUF_INITIALIZER;

    /* Initialize rock. */
    memset(&rock, 0, sizeof(struct updates_rock));

    db = caldav_open_userid(req->userid);
    if (!db) {
        syslog(LOG_ERR, "caldav_open_mailbox failed for user %s", req->userid);
        r = IMAP_INTERNAL;
        goto done;
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
    pe = readprop(req->args, "maxChanges", 0 /*mandatory*/, invalid, "i", &maxChanges);
    if (pe > 0) {
        if (maxChanges <= 0) {
            json_array_append_new(invalid, json_string("maxChanges"));
        }
    }
    readprop(req->args, "fetchRecords", 0 /*mandatory*/, invalid, "b", &dofetch);
    if (json_array_size(invalid)) {
        json_t *err = json_pack("{s:s, s:o}", "type", "invalidArguments", "arguments", invalid);
        json_array_append_new(req->response, json_pack("[s,o,s]", "error", err, req->tag));
        r = 0;
        goto done;
    }
    json_decref(invalid);

    /* Lookup updates. */
    rock.fetchmodseq = 1;
    rock.changed = json_array();
    rock.removed = json_array();
    rock.max_records = maxChanges;
    r = caldav_get_updates(db, oldmodseq, NULL /*mboxname*/, CAL_COMP_VEVENT, 
            maxChanges ? maxChanges + 1 : -1, &geteventupdates_cb, &rock);
    mailbox_close(&rock.mailbox);
    if (r) goto done;
    strip_spurious_deletes(&rock);

    /* Determine new state. */
    modseq_t newstate;
    int more = rock.max_records ? rock.seen_records > rock.max_records : 0;
    if (more) {
        newstate = rock.highestmodseq;
    } else {
        newstate = req->counters.caldavmodseq;
    }

    /* Create response. */
    json_t *eventUpdates = json_pack("{}");
    json_object_set_new(eventUpdates, "accountId", json_string(req->userid));
    json_object_set_new(eventUpdates, "oldState", json_string(since));

    buf_printf(&buf, MODSEQ_FMT, newstate);
    json_object_set_new(eventUpdates, "newState", json_string(buf_cstring(&buf)));
    buf_reset(&buf);

    json_object_set_new(eventUpdates, "hasMoreUpdates", json_boolean(more));
    json_object_set(eventUpdates, "changed", rock.changed);
    json_object_set(eventUpdates, "removed", rock.removed);

    json_t *item = json_pack("[]");
    json_array_append_new(item, json_string("calendarEventUpdates"));
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
    if (rock.removed) json_decref(rock.removed);
    if (db) caldav_close(db);
    return r;
}

typedef struct calevent_filter {
    hash_table *calendars;
    icaltimetype after;
    icaltimetype before;
    const char *text;
    const char *summary;
    const char *description;
    const char *location;
    const char *owner;
    const char *attendee;
} calevent_filter;

static int calevent_filter_match_textprop_value(icalproperty *prop,
                                                const char *text)
{
    const char *val = icalproperty_get_value_as_string(prop);
    /* XXX better text matching than stristr */
    if (val && stristr(val, text) != NULL) {
        return 1;
    }
    return 0;
}

static int calevent_filter_match_textprop_x(icalcomponent *comp,
                                           const char *text,
                                           const char *name)
{
    icalproperty *prop;
    icalcomponent *ical;

    if (icalcomponent_isa(comp) != ICAL_VEVENT_COMPONENT) {
        return 0;
    }

    ical = icalcomponent_get_parent(comp);
    if (!ical || icalcomponent_isa(ical) != ICAL_VCALENDAR_COMPONENT) {
        return 0;
    }

    /* Look for text in any VEVENT of comp. */
    for (comp = icalcomponent_get_first_component(ical, ICAL_VEVENT_COMPONENT);
         comp;
         comp = icalcomponent_get_next_component(ical, ICAL_VEVENT_COMPONENT)) {

        for (prop = icalcomponent_get_first_property(comp, ICAL_X_PROPERTY);
             prop;
             prop = icalcomponent_get_next_property(comp, ICAL_X_PROPERTY)) {

            if (strcmp(icalproperty_get_x_name(prop), name)) {
                continue;
            }
            if (calevent_filter_match_textprop_value(prop, text)) {
                return 1;
            }
        }
    }

    return 0;
}

/* Match text with icalproperty kind in VEVENT comp and its recurrences. */
static int calevent_filter_match_textprop(icalcomponent *comp,
                                          const char *text,
                                          icalproperty_kind kind)
{
    icalproperty *prop;
    icalcomponent *ical;

    if (icalcomponent_isa(comp) != ICAL_VEVENT_COMPONENT) {
        return 0;
    }

    ical = icalcomponent_get_parent(comp);
    if (!ical || icalcomponent_isa(ical) != ICAL_VCALENDAR_COMPONENT) {
        return 0;
    }

    /* Look for text in any VEVENT of comp. */
    for (comp = icalcomponent_get_first_component(ical, ICAL_VEVENT_COMPONENT);
         comp;
         comp = icalcomponent_get_next_component(ical, ICAL_VEVENT_COMPONENT)) {

        for (prop = icalcomponent_get_first_property(comp, kind);
             prop;
             prop = icalcomponent_get_next_property(comp, kind)) {

            if (calevent_filter_match_textprop_value(prop, text)) {
                return 1;
            }
        }
    }

    return 0;
}

typedef struct calevent_filter_rock {
    icalcomponent *ical;
    struct caldav_data *cdata;
} calevent_filter_rock;

/* Match the VEVENTs contained in VCALENDAR component ical against filter. */
static int calevent_filter_match(void *vf, void *rock)
{
    calevent_filter *f = (calevent_filter *) vf;
    calevent_filter_rock *cfrock = (calevent_filter_rock*) rock;

    icalcomponent *ical = cfrock->ical;
    struct caldav_data *cdata = cfrock->cdata;
    icaltimezone *utc = icaltimezone_get_utc_timezone();

    /* Locate main VEVENT. */
    icalcomponent *comp;
    for (comp = icalcomponent_get_first_component(ical, ICAL_VEVENT_COMPONENT);
         comp;
         comp = icalcomponent_get_next_component(ical, ICAL_VEVENT_COMPONENT)) {
        if (!icalcomponent_get_first_property(comp, ICAL_RECURRENCEID_PROPERTY)) {
            break;
        }
    }
    if (!comp) {
        return 0;
    }

    /* calendars */
    if (f->calendars && !hash_lookup(cdata->dav.mailbox, f->calendars)) {
        return 0;
    }
    /* after */
    if (icaltime_as_timet_with_zone(f->after, utc) != caldav_epoch) {
        /* String compare to match caldav_foreach_timerange */
        if (strcmp(cdata->dtend, icaltime_as_ical_string(f->after)) <= 0) {
            return 0;
        }
    }
    /* before */
    if (icaltime_as_timet_with_zone(f->before, utc) != caldav_eternity) {
        /* String compare to match caldav_foreach_timerange */
        if (strcmp(cdata->dtstart, icaltime_as_ical_string(f->before)) >= 0) {
            return 0;
        }
    }
    /* text */
    if (f->text) {
        int m = calevent_filter_match_textprop(comp, f->text, ICAL_SUMMARY_PROPERTY);
        if (!m) m = calevent_filter_match_textprop(comp, f->text, ICAL_DESCRIPTION_PROPERTY);
        if (!m) m = calevent_filter_match_textprop(comp, f->text, ICAL_LOCATION_PROPERTY);
        if (!m) m = calevent_filter_match_textprop(comp, f->text, ICAL_ORGANIZER_PROPERTY);
        if (!m) m = calevent_filter_match_textprop(comp, f->text, ICAL_ATTENDEE_PROPERTY);

        if (!m) m = calevent_filter_match_textprop_x(comp, f->text, JMAPICAL_XPROP_LOCATION);
        if (!m) m = calevent_filter_match_textprop_x(comp, f->text, "X-APPLE-STRUCTURED-LOCATION");

        if (!m) {
            return 0;
        }
    }
    if ((f->summary && !calevent_filter_match_textprop(comp, f->summary, ICAL_SUMMARY_PROPERTY)) ||
        (f->description && !calevent_filter_match_textprop(comp, f->description, ICAL_DESCRIPTION_PROPERTY)) ||
        (f->location && !calevent_filter_match_textprop(comp, f->location, ICAL_LOCATION_PROPERTY)) ||
        (f->owner && !calevent_filter_match_textprop(comp, f->owner, ICAL_ORGANIZER_PROPERTY)) ||
        (f->attendee && !calevent_filter_match_textprop(comp, f->attendee, ICAL_ATTENDEE_PROPERTY)
                     && !calevent_filter_match_textprop(comp, f->attendee, ICAL_ORGANIZER_PROPERTY))) {
        return 0;
    }

    /* All matched. */
    return 1;
}

/* Free the memory allocated by this calendar event filter. */
static void calevent_filter_free(void *vf)
{
    calevent_filter *f = (calevent_filter*) vf;
    if (f->calendars) {
        free_hash_table(f->calendars, NULL);
        free(f->calendars);
    }
    free(f);
}

static void
calevent_filter_gettimerange(jmap_filter *f, time_t *before, time_t *after)
{
    if (!f) return;

    if (f->kind == JMAP_FILTER_KIND_OPER) {
        size_t i;
        time_t bf, af;

        for (i = 0; i < f->n_conditions; i++) {
            bf = caldav_eternity;
            af = caldav_epoch;

            calevent_filter_gettimerange(f->conditions[i], &bf, &af);

            if (bf != caldav_eternity) {
                switch (f->op) {
                    case JMAP_FILTER_OP_OR:
                        if (*before == caldav_eternity || *before < bf)
                            *before = bf;
                        break;
                    case JMAP_FILTER_OP_AND:
                        if (*before == caldav_eternity || *before > bf)
                            *before = bf;
                        break;
                    case JMAP_FILTER_OP_NOT:
                        if (*after == caldav_epoch || *after < bf)
                            *after = bf;
                        break;
                    default: /* unknown operator */ ;
                }
            }

            if (af != caldav_epoch) {
                switch (f->op) {
                    case JMAP_FILTER_OP_OR:
                        if (*after == caldav_epoch || *after > af)
                            *after = af;
                        break;
                    case JMAP_FILTER_OP_AND:
                        if (*after == caldav_epoch || *after < af)
                            *after = af;
                        break;
                    case JMAP_FILTER_OP_NOT:
                        if (*before == caldav_eternity || *before < af)
                            *before = af;
                        break;
                    default: /* unknown operator */ ;
                }
            }
        }
    } else {
        calevent_filter *cond = (calevent_filter *) f->cond;
        icaltimezone *utc = icaltimezone_get_utc_timezone();

        *before = icaltime_as_timet_with_zone(cond->before, utc);
        *after = icaltime_as_timet_with_zone(cond->after, utc);
    }
}


/* Parse the JMAP calendar event FilterOperator or FilterCondition in arg.
 * Report any invalid properties in invalid, prefixed by prefix.
 * Return NULL on error. */
static void *calevent_filter_parse(json_t *arg,
                                   const char *prefix,
                                   json_t *invalid)
{
    calevent_filter *f = (calevent_filter *) xzmalloc(sizeof(struct calevent_filter));
    int pe;
    const char *val;
    struct buf buf = BUF_INITIALIZER;
    icaltimezone *utc = icaltimezone_get_utc_timezone();

    /* inCalendars */
    json_t *cals = json_object_get(arg, "inCalendars");
    if (cals && json_array_size(cals)) {
        f->calendars = xmalloc(sizeof(hash_table));
        construct_hash_table(f->calendars, json_array_size(cals), 0);
        size_t i;
        json_t *uid;
        json_array_foreach(cals, i, uid) {
            const char *id = json_string_value(uid);
            if (id && strlen(id) && (*id != '#')) {
                hash_insert(id, (void *)1, f->calendars);
            } else {
                buf_printf(&buf, "%s.calendars[%zu]", prefix, i);
                json_array_append_new(invalid, json_string(buf_cstring(&buf)));
                buf_reset(&buf);
            }
        }
    } else if (JNOTNULL(cals)) {
        buf_printf(&buf, "%s.%s", prefix, "inCalendars");
        json_array_append_new(invalid, json_string(buf_cstring(&buf)));
        buf_reset(&buf);
    }

    /* after */
    if (JNOTNULL(json_object_get(arg, "after"))) {
        pe = readprop_full(arg, prefix, "after", 1, invalid, "s", &val);
        if (pe > 0) {
            if (!utcdate_to_icaltime(val, &f->after)) {
                buf_printf(&buf, "%s.%s", prefix, "after");
                json_array_append_new(invalid, json_string(buf_cstring(&buf)));
                buf_reset(&buf);
            }
        }
    } else {
        f->after = icaltime_from_timet_with_zone(caldav_epoch, 0, utc);
    }

    /* before */
    if (JNOTNULL(json_object_get(arg, "before"))) {
        pe = readprop_full(arg, prefix, "before", 1, invalid, "s", &val);
        if (pe > 0) {
            if (!utcdate_to_icaltime(val, &f->before)) {
                buf_printf(&buf, "%s.%s", prefix, "before");
                json_array_append_new(invalid, json_string(buf_cstring(&buf)));
                buf_reset(&buf);
            }
        }
    } else {
        f->before = icaltime_from_timet_with_zone(caldav_eternity, 0, utc);
    }

    /* text */
    if (JNOTNULL(json_object_get(arg, "text"))) {
        pe = readprop_full(arg, prefix, "text", 0, invalid, "s", &f->text);
    }

    /* summary */
    if (JNOTNULL(json_object_get(arg, "summary"))) {
        pe = readprop_full(arg, prefix, "summary", 0, invalid, "s", &f->summary);
    }

    /* description */
    if (JNOTNULL(json_object_get(arg, "description"))) {
        pe = readprop_full(arg, prefix, "description", 0, invalid, "s", &f->description);
    }

    /* location */
    if (JNOTNULL(json_object_get(arg, "location"))) {
        pe = readprop_full(arg, prefix, "location", 0, invalid, "s", &f->location);
    }

    /* owner */
    if (JNOTNULL(json_object_get(arg, "owner"))) {
        pe = readprop_full(arg, prefix, "owner", 0, invalid, "s", &f->owner);
    }

    /* attendee */
    if (JNOTNULL(json_object_get(arg, "attendee"))) {
        pe = readprop_full(arg, prefix, "attendee", 0, invalid, "s", &f->attendee);
    }

    buf_free(&buf);

    return f;
}

struct caleventlist_rock {
    jmap_filter *filter;
    size_t position;
    size_t limit;
    size_t total;
    json_t *events;

    struct mailbox *mailbox;
};

static int getcalendareventlist_cb(void *rock, struct caldav_data *cdata) {
    struct caleventlist_rock *crock = (struct caleventlist_rock*) rock;
    struct index_record record;
    icalcomponent *ical = NULL;
    int r = 0;

    if (!cdata->dav.alive || !cdata->dav.rowid || !cdata->dav.imap_uid) {
        return 0;
    }

    /* Open mailbox. */
    if (!crock->mailbox || strcmp(crock->mailbox->name, cdata->dav.mailbox)) {
        mailbox_close(&crock->mailbox);
        r = mailbox_open_irl(cdata->dav.mailbox, &crock->mailbox);
        if (r) goto done;
    }

    /* Load record. */
    r = mailbox_find_index_record(crock->mailbox, cdata->dav.imap_uid, &record);
    if (r) goto done;

    /* Load VEVENT from record. */
    ical = record_to_ical(crock->mailbox, &record, NULL);
    if (!ical) {
        syslog(LOG_ERR, "record_to_ical failed for record %u:%s",
                cdata->dav.imap_uid, crock->mailbox->name);
        r = IMAP_INTERNAL;
        goto done;
    }

    /* Match the event against the filter and update statistics. */
    struct calevent_filter_rock cfrock;
    cfrock.cdata = cdata;
    cfrock.ical = ical;
    if (crock->filter && !jmap_filter_match(crock->filter,
                                            &calevent_filter_match,
                                            &cfrock)) {
        goto done;
    }
    crock->total++;
    if (crock->position > crock->total) {
        goto done;
    }
    if (crock->limit && crock->limit >= json_array_size(crock->events)) {
        goto done;
    }

    /* All done. Add the event identifier. */
    json_array_append_new(crock->events, json_string(cdata->ical_uid));

done:
    if (ical) icalcomponent_free(ical);
    return r;
}

static int getCalendarEventList(struct jmap_req *req)
{
    int r = 0, pe;
    json_t *invalid;
    int dofetch = 0;
    json_t *filter;
    struct caleventlist_rock rock;
    struct caldav_db *db;
    time_t before, after;

    memset(&rock, 0, sizeof(struct caleventlist_rock));

    db = caldav_open_userid(req->userid);
    if (!db) {
        syslog(LOG_ERR, "caldav_open_mailbox failed for user %s", req->userid);
        r = IMAP_INTERNAL;
        goto done;
    }

    /* Parse and validate arguments. */
    invalid = json_pack("[]");

    /* filter */
    filter = json_object_get(req->args, "filter");
    if (JNOTNULL(filter)) {
        rock.filter = jmap_filter_parse(filter, "filter", invalid, calevent_filter_parse);
    }

    /* position */
    json_int_t pos = 0;
    if (JNOTNULL(json_object_get(req->args, "position"))) {
        pe = readprop(req->args, "position", 0 /*mandatory*/, invalid, "i", &pos);
        if (pe > 0 && pos < 0) {
            json_array_append_new(invalid, json_string("position"));
        }
    }
    rock.position = pos;

    /* limit */
    json_int_t limit = 0;
    if (JNOTNULL(json_object_get(req->args, "limit"))) {
        pe = readprop(req->args, "limit", 0 /*mandatory*/, invalid, "i", &limit);
        if (pe > 0 && limit < 0) {
            json_array_append_new(invalid, json_string("limit"));
        }
    }
    rock.limit = limit;

    /* fetchCalendarEvents */
    if (JNOTNULL(json_object_get(req->args, "fetchCalendarEvents"))) {
        readprop(req->args, "fetchCalendarEvents", 0 /*mandatory*/, invalid, "b", &dofetch);
    }

    if (json_array_size(invalid)) {
        json_t *err = json_pack("{s:s, s:o}", "type", "invalidArguments", "arguments", invalid);
        json_array_append_new(req->response, json_pack("[s,o,s]", "error", err, req->tag));
        r = 0;
        goto done;
    }
    json_decref(invalid);

    rock.events = json_pack("[]");
    before = caldav_eternity;
    after = caldav_epoch;
    calevent_filter_gettimerange(rock.filter, &before, &after);

    if (before != caldav_eternity || after != caldav_epoch) {
        /* Fast path. Filter by timerange. */
        r = caldav_foreach_timerange(db, NULL, after, before,
                getcalendareventlist_cb, &rock);
    } else {
        /* Inspect every entry in this accounts mailboxes. */
        r = caldav_foreach(db, NULL, getcalendareventlist_cb, &rock);
    }
    if (rock.mailbox) mailbox_close(&rock.mailbox);
    if (r) goto done;

    /* Prepare response. */
    json_t *eventList = json_pack("{}");
    json_object_set_new(eventList, "accountId", json_string(req->userid));
    json_object_set_new(eventList, "state", jmap_getstate(MBTYPE_CALENDAR, req));
    json_object_set_new(eventList, "position", json_integer(rock.position));
    json_object_set_new(eventList, "total", json_integer(rock.total));
    json_object_set(eventList, "calendarEventIds", rock.events);
    if (filter) json_object_set(eventList, "filter", filter);

    json_t *item = json_pack("[]");
    json_array_append_new(item, json_string("calendarEventList"));
    json_array_append_new(item, eventList);
    json_array_append_new(item, json_string(req->tag));
    json_array_append_new(req->response, item);

    /* Fetch updated records, if requested. */
    if (dofetch) {
        struct jmap_req subreq = *req;
        subreq.args = json_pack("{}");
        json_object_set(subreq.args, "ids", rock.events);
        r = getCalendarEvents(&subreq);
        json_decref(subreq.args);
    }

done:
    if (rock.filter) jmap_filter_free(rock.filter, calevent_filter_free);
    if (rock.events) json_decref(rock.events);
    if (db) caldav_close(db);
    return r;
}

static int getCalendarPreferences(struct jmap_req *req)
{
    /* Just a dummy implementation to make the JMAP web client happy. */
    json_t *item = json_pack("[]");
    json_array_append_new(item, json_string("calendarPreferences"));
    json_array_append_new(item, json_pack("{}"));
    json_array_append_new(item, json_string(req->tag));
    json_array_append_new(req->response, item);
    return 0;
}
