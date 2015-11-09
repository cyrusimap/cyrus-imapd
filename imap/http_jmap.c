/* http_jmap.c -- Routines for handling JMAP requests in httpd
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

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <ctype.h>
#include <string.h>
#include <syslog.h>
#include <assert.h>
#include <jansson.h>

#include "acl.h"
#include "annotate.h"
#include "append.h"
#include "caldav_db.h"
#include "carddav_db.h"
#include "global.h"
#include "hash.h"
#include "httpd.h"
#include "http_caldav.h"
#include "http_caldav_sched.h"
#include "http_dav.h"
#include "http_proxy.h"
#include "ical_support.h"
#include "imap_err.h"
#include "mailbox.h"
#include "mboxlist.h"
#include "mboxname.h"
#include "statuscache.h"
#include "stristr.h"
#include "times.h"
#include "util.h"
#include "version.h"
#include "xmalloc.h"
#include "xstrlcat.h"
#include "xstrlcpy.h"
#include "zoneinfo_db.h"

/* generated headers are not necessarily in current directory */
#include "imap/http_err.h"

struct jmap_req {
    const char *userid;
    struct auth_state *authstate;
    struct hash_table *idmap;
    json_t *args;
    json_t *response;
    const char *state; // if changing things, this is pre-change state
    struct mboxname_counters counters;
    const char *tag;
    struct transaction_t *txn;
};

struct namespace jmap_namespace;

static time_t compile_time;
static void jmap_init(struct buf *serverinfo);
static void jmap_auth(const char *userid);
static int jmap_get(struct transaction_t *txn, void *params);
static int jmap_post(struct transaction_t *txn, void *params);
static int getMailboxes(struct jmap_req *req);
static int getContactGroups(struct jmap_req *req);
static int getContactGroupUpdates(struct jmap_req *req);
static int setContactGroups(struct jmap_req *req);
static int getContacts(struct jmap_req *req);
static int getContactUpdates(struct jmap_req *req);
static int setContacts(struct jmap_req *req);

static int getCalendars(struct jmap_req *req);
static int getCalendarUpdates(struct jmap_req *req);
static int setCalendars(struct jmap_req *req);
static int getCalendarEvents(struct jmap_req *req);
static int getCalendarEventUpdates(struct jmap_req *req);
static int getCalendarEventList(struct jmap_req *req);
static int setCalendarEvents(struct jmap_req *req);

/* JMAP methods not defined in the spec. */
static int getCalendarPreferences(struct jmap_req *req);
static int getPersonalities(struct jmap_req *req);
static int getPreferences(struct jmap_req *req);

static const struct message_t {
    const char *name;
    int (*proc)(struct jmap_req *req);
} messages[] = {
    { "getMailboxes",   &getMailboxes },
    { "getContactGroups",       &getContactGroups },
    { "getContactGroupUpdates", &getContactGroupUpdates },
    { "setContactGroups",       &setContactGroups },
    { "getContacts",            &getContacts },
    { "getContactUpdates",      &getContactUpdates },
    { "setContacts",            &setContacts },
    { "getCalendars",           &getCalendars },
    { "getCalendarUpdates",     &getCalendarUpdates },
    { "setCalendars",           &setCalendars },
    { "getCalendarEvents",      &getCalendarEvents },
    { "getCalendarEventUpdates",&getCalendarEventUpdates },
    { "getCalendarEventList",   &getCalendarEventList },
    { "setCalendarEvents",      &setCalendarEvents },
    { "getCalendarPreferences", &getCalendarPreferences },
    { "getPersonalities",       &getPersonalities },
    { "getPreferences",         &getPreferences },
    { NULL,             NULL}
};


/* Namespace for JMAP */
struct namespace_t namespace_jmap = {
    URL_NS_JMAP, 0, "/jmap", "/.well-known/jmap", 1 /* auth */,
    /*mbtype*/0, 
    (ALLOW_READ | ALLOW_POST),
    &jmap_init, &jmap_auth, NULL, NULL,
    {
        { NULL,                 NULL },                 /* ACL          */
        { NULL,                 NULL },                 /* COPY         */
        { NULL,                 NULL },                 /* DELETE       */
        { &jmap_get,            NULL },                 /* GET          */
        { &jmap_get,            NULL },                 /* HEAD         */
        { NULL,                 NULL },                 /* LOCK         */
        { NULL,                 NULL },                 /* MKCALENDAR   */
        { NULL,                 NULL },                 /* MKCOL        */
        { NULL,                 NULL },                 /* MOVE         */
        { &meth_options,        NULL },                 /* OPTIONS      */
        { &jmap_post,           NULL },                 /* POST */
        { NULL,                 NULL },                 /* PROPFIND     */
        { NULL,                 NULL },                 /* PROPPATCH    */
        { NULL,                 NULL },                 /* PUT          */
        { NULL,                 NULL },                 /* REPORT       */
        { &meth_trace,          NULL },                 /* TRACE        */
        { NULL,                 NULL }                  /* UNLOCK       */
    }
};

static void jmap_init(struct buf *serverinfo __attribute__((unused)))
{
    namespace_jmap.enabled =
        config_httpmodules & IMAP_ENUM_HTTPMODULES_JMAP;

    if (!namespace_jmap.enabled) return;

    compile_time = calc_compile_time(__TIME__, __DATE__);
}


static void jmap_auth(const char *userid __attribute__((unused)))
{
    /* Set namespace */
    mboxname_init_namespace(&jmap_namespace,
                            httpd_userisadmin || httpd_userisproxyadmin);
}


/* Perform a GET/HEAD request */
static int jmap_get(struct transaction_t *txn __attribute__((unused)),
                     void *params __attribute__((unused)))
{
    return HTTP_NO_CONTENT;
}

/* Perform a POST request */
static int jmap_post(struct transaction_t *txn,
                     void *params __attribute__((unused)))
{
    const char **hdr;
    json_t *req, *resp = NULL;
    json_error_t jerr;
    const struct message_t *mp = NULL;
    struct mailbox *mailbox = NULL;
    struct hash_table idmap;
    size_t i, flags = JSON_PRESERVE_ORDER;
    int ret;
    char *buf, *inboxname = NULL;

    /* Read body */
    txn->req_body.flags |= BODY_DECODE;
    ret = http_read_body(httpd_in, httpd_out,
                       txn->req_hdrs, &txn->req_body, &txn->error.desc);

    if (ret) {
        txn->flags.conn = CONN_CLOSE;
        return ret;
    }

    if (!buf_len(&txn->req_body.payload)) return HTTP_BAD_REQUEST;

    /* Check Content-Type */
    if (!(hdr = spool_getheader(txn->req_hdrs, "Content-Type")) ||
        !is_mediatype("application/json", hdr[0])) {
        txn->error.desc = "This method requires a JSON request body\r\n";
        return HTTP_BAD_MEDIATYPE;
    }

    /* Allocate map to store uids */
    construct_hash_table(&idmap, 1024, 0);

    /* Parse the JSON request */
    req = json_loads(buf_cstring(&txn->req_body.payload), 0, &jerr);
    if (!req || !json_is_array(req)) {
        txn->error.desc = "Unable to parse JSON request body\r\n";
        ret = HTTP_BAD_REQUEST;
        goto done;
    }

    /* Start JSON response */
    resp = json_array();
    if (!resp) {
        txn->error.desc = "Unable to create JSON response body\r\n";
        ret = HTTP_SERVER_ERROR;
        goto done;
    }

    inboxname = mboxname_user_mbox(httpd_userid, NULL);

    /* we lock the user's INBOX before we start any operation, because that way we
     * guarantee (via conversations magic) that nothing changes the modseqs except
     * our operations */
    int r = mailbox_open_iwl(inboxname, &mailbox);
    if (r) {
        txn->error.desc = error_message(r);
        ret = HTTP_SERVER_ERROR;
        goto done;
    }

    /* Process each message in the request */
    for (i = 0; i < json_array_size(req); i++) {
        json_t *msg = json_array_get(req, i);
        const char *name = json_string_value(json_array_get(msg, 0));
        json_t *args = json_array_get(msg, 1);
        json_t *id = json_array_get(msg, 2);
        /* XXX - better error reporting */
        if (!id) continue;
        const char *tag = json_string_value(id);
        int r = 0;

        /* Find the message processor */
        for (mp = messages; mp->name && strcmp(name, mp->name); mp++);

        if (!mp || !mp->name) {
            json_array_append(resp, json_pack("[s {s:s} s]", "error", "type", "unknownMethod", tag));
            continue;
        }

        struct jmap_req req;
        req.userid = httpd_userid;
        req.authstate = httpd_authstate;
        req.args = args;
        req.response = resp;
        req.tag = tag;
        req.idmap = &idmap;
        req.txn = txn;

        /* Read the modseq counters again, just in case something changed. */
        r = mboxname_read_counters(inboxname, &req.counters);
        if (r) goto done;

        /* XXX - Make also contacts use counters. */
        struct buf buf = BUF_INITIALIZER;
        buf_printf(&buf, "%llu", req.counters.highestmodseq);
        req.state = buf_cstring(&buf);

        r = mp->proc(&req);

        buf_free(&buf);

        if (r) {
            txn->error.desc = error_message(r);
            ret = HTTP_SERVER_ERROR;
            goto done;
        }
    }

    /* unlock here so that we don't block on writing */
    mailbox_unlock_index(mailbox, NULL);

    /* Dump JSON object into a text buffer */
    flags |= (config_httpprettytelemetry ? JSON_INDENT(2) : JSON_COMPACT);
    buf = json_dumps(resp, flags);

    if (!buf) {
        txn->error.desc = "Error dumping JSON response object";
        ret = HTTP_SERVER_ERROR;
        goto done;
    }

    /* Output the JSON object */
    txn->resp_body.type = "application/json; charset=utf-8";
    write_body(HTTP_OK, txn, buf, strlen(buf));
    free(buf);

  done:
    free_hash_table(&idmap, free);
    mailbox_close(&mailbox);
    free(inboxname);
    if (req) json_decref(req);
    if (resp) json_decref(resp);

    return ret;
}


/* mboxlist_findall() callback to list mailboxes */
int getMailboxes_cb(const char *mboxname, int matchlen __attribute__((unused)),
                    int maycreate __attribute__((unused)),
                    void *rock)
{
    json_t *list = (json_t *) rock, *mbox;
    struct mboxlist_entry *mbentry = NULL;
    struct mailbox *mailbox = NULL;
    int r = 0, rights;
    unsigned statusitems = STATUS_MESSAGES | STATUS_UNSEEN;
    struct statusdata sdata;

    /* Check ACL on mailbox for current user */
    if ((r = mboxlist_lookup(mboxname, &mbentry, NULL))) {
        syslog(LOG_INFO, "mboxlist_lookup(%s) failed: %s",
               mboxname, error_message(r));
        goto done;
    }

    rights = mbentry->acl ? cyrus_acl_myrights(httpd_authstate, mbentry->acl) : 0;
    if ((rights & (ACL_LOOKUP | ACL_READ)) != (ACL_LOOKUP | ACL_READ)) {
        goto done;
    }

    /* Open mailbox to get uniqueid */
    if ((r = mailbox_open_irl(mboxname, &mailbox))) {
        syslog(LOG_INFO, "mailbox_open_irl(%s) failed: %s",
               mboxname, error_message(r));
        goto done;
    }
    mailbox_unlock_index(mailbox, NULL);

    r = status_lookup(mboxname, httpd_userid, statusitems, &sdata);

    mbox = json_pack("{s:s s:s s:n s:n s:b s:b s:b s:b s:i s:i}",
                     "id", mailbox->uniqueid,
                     "name", mboxname,
                     "parentId",
                     "role",
                     "mayAddMessages", rights & ACL_INSERT,
                     "mayRemoveMessages", rights & ACL_DELETEMSG,
                     "mayCreateChild", rights & ACL_CREATE,
                     "mayDeleteMailbox", rights & ACL_DELETEMBOX,
                     "totalMessages", sdata.messages,
                     "unreadMessages", sdata.unseen);
    json_array_append_new(list, mbox);

    mailbox_close(&mailbox);

  done:

    return 0;
}


/* Execute a getMailboxes message */
static int getMailboxes(struct jmap_req *req)
{
    json_t *item, *mailboxes, *list;

    /* Start constructing our response */
    item = json_pack("[s {s:s s:s} s]", "mailboxes",
                     "accountId", req->userid,
                     "state", req->state,
                     req->tag);

    list = json_array();

    /* Generate list of mailboxes */
    int isadmin = httpd_userisadmin||httpd_userisproxyadmin;
    mboxlist_findall(&jmap_namespace, "*", isadmin, httpd_userid,
                     httpd_authstate, &getMailboxes_cb, list);

    mailboxes = json_array_get(item, 1);
    json_object_set_new(mailboxes, "list", list);

    /* xxx - args */
    json_object_set_new(mailboxes, "notFound", json_null());

    json_array_append_new(req->response, item);

    return 0;
}

static void _add_xhref(json_t *obj, const char *mboxname, const char *resource)
{
    /* XXX - look up root path from namespace? */
    struct buf buf = BUF_INITIALIZER;
    char *userid = mboxname_to_userid(mboxname);

    const char *prefix = NULL;
    if (mboxname_isaddressbookmailbox(mboxname, 0)) {
        prefix = namespace_addressbook.prefix;
    }
    else if (mboxname_iscalendarmailbox(mboxname, 0)) {
        prefix = namespace_calendar.prefix;
    }

    if (strchr(userid, '@') || !httpd_extradomain) {
        buf_printf(&buf, "%s/user/%s/%s",
                   prefix, userid, strrchr(mboxname, '.')+1);
    }
    else {
        buf_printf(&buf, "%s/user/%s@%s/%s",
                   prefix, userid, httpd_extradomain, strrchr(mboxname, '.')+1);
    }
    if (resource)
        buf_printf(&buf, "/%s", resource);

    json_object_set_new(obj, "x-href", json_string(buf_cstring(&buf)));
    free(userid);
    buf_free(&buf);
}

struct cards_rock {
    struct jmap_req *req;
    json_t *array;
    struct hash_table *props;
    struct mailbox *mailbox;
    int rows;
};

static int getgroups_cb(void *rock, struct carddav_data *cdata)
{
    struct cards_rock *crock = (struct cards_rock *) rock;
    struct index_record record;
    int r;

    if (!crock->mailbox || strcmp(crock->mailbox->name, cdata->dav.mailbox)) {
        mailbox_close(&crock->mailbox);
        r = mailbox_open_irl(cdata->dav.mailbox, &crock->mailbox);
        if (r) return r;
    }

    r = mailbox_find_index_record(crock->mailbox, cdata->dav.imap_uid, &record);
    if (r) return r;

    crock->rows++;

    /* XXX - this could definitely be refactored from here and mailbox.c */
    struct buf msg_buf = BUF_INITIALIZER;
    struct vparse_state vparser;
    struct vparse_entry *ventry = NULL;

    /* Load message containing the resource and parse vcard data */
    r = mailbox_map_record(crock->mailbox, &record, &msg_buf);
    if (r) return r;

    memset(&vparser, 0, sizeof(struct vparse_state));
    vparser.base = buf_cstring(&msg_buf) + record.header_size;
    r = vparse_parse(&vparser, 0);
    buf_free(&msg_buf);
    if (r) return r;
    if (!vparser.card || !vparser.card->objects) {
        vparse_free(&vparser);
        return r;
    }
    struct vparse_card *vcard = vparser.card->objects;

    json_t *obj = json_pack("{}");

    json_object_set_new(obj, "id", json_string(cdata->vcard_uid));

    json_object_set_new(obj, "addressbookId",
                        json_string(strrchr(cdata->dav.mailbox, '.')+1));

    json_t *contactids = json_pack("[]");
    json_t *otherids = json_pack("{}");

    _add_xhref(obj, cdata->dav.mailbox, cdata->dav.resource);

    for (ventry = vcard->properties; ventry; ventry = ventry->next) {
        const char *name = ventry->name;
        const char *propval = ventry->v.value;

        if (!name) continue;
        if (!propval) continue;

        if (!strcmp(name, "fn")) {
            json_object_set_new(obj, "name", json_string(propval));
        }

        else if (!strcmp(name, "x-addressbookserver-member")) {
            if (strncmp(propval, "urn:uuid:", 9)) continue;
            json_array_append_new(contactids, json_string(propval+9));
        }

        else if (!strcmp(name, "x-fm-otheraccount-member")) {
            if (strncmp(propval, "urn:uuid:", 9)) continue;
            struct vparse_param *param = vparse_get_param(ventry, "userid");
            if (!param) continue;
            json_t *object = json_object_get(otherids, param->value);
            if (!object) {
                object = json_array();
                json_object_set_new(otherids, param->value, object);
            }
            json_array_append_new(object, json_string(propval+9));
        }
    }
    json_object_set_new(obj, "contactIds", contactids);
    json_object_set_new(obj, "otherAccountContactIds", otherids);

    json_array_append_new(crock->array, obj);

    return 0;
}

static int jmap_contacts_get(struct jmap_req *req, carddav_cb_t *cb,
                             int kind, const char *resname)
{
    struct carddav_db *db = carddav_open_userid(req->userid);
    if (!db) return -1;

    char *mboxname = NULL;
    json_t *abookid = json_object_get(req->args, "addressbookId");
    if (abookid && json_string_value(abookid)) {
        /* XXX - invalid arguments */
        const char *addressbookId = json_string_value(abookid);
        mboxname = carddav_mboxname(req->userid, addressbookId);
    }

    struct cards_rock rock;
    int r = 0;

    rock.array = json_pack("[]");
    rock.props = NULL;
    rock.mailbox = NULL;

    json_t *want = json_object_get(req->args, "ids");
    json_t *notFound = json_array();
    if (want) {
        int i;
        int size = json_array_size(want);
        for (i = 0; i < size; i++) {
            rock.rows = 0;
            const char *id = json_string_value(json_array_get(want, i));
            if (!id) continue;
            r = carddav_get_cards(db, mboxname, id, kind, cb, &rock);
            if (r || !rock.rows) {
                json_array_append_new(notFound, json_string(id));
            }
        }
    }
    else {
        rock.rows = 0;
        r = carddav_get_cards(db, mboxname, NULL, kind, cb, &rock);
    }
    if (r) goto done;

    json_t *toplevel = json_pack("{}");
    json_object_set_new(toplevel, "accountId", json_string(req->userid));
    json_object_set_new(toplevel, "state", json_string(req->state));
    json_object_set_new(toplevel, "list", rock.array);
    if (json_array_size(notFound)) {
        json_object_set_new(toplevel, "notFound", notFound);
    }
    else {
        json_decref(notFound);
        json_object_set_new(toplevel, "notFound", json_null());
    }

    json_t *item = json_pack("[]");
    json_array_append_new(item, json_string(resname));
    json_array_append_new(item, toplevel);
    json_array_append_new(item, json_string(req->tag));

    json_array_append_new(req->response, item);

  done:
    free(mboxname);
    mailbox_close(&rock.mailbox);
    carddav_close(db);
    return r;
}

static int getContactGroups(struct jmap_req *req)
{
    return jmap_contacts_get(req, &getgroups_cb, CARDDAV_KIND_GROUP, "contactGroups");
}

static const char *_json_object_get_string(const json_t *obj, const char *key)
{
    const json_t *jval = json_object_get(obj, key);
    if (!jval) return NULL;
    const char *val = json_string_value(jval);
    return val;
}

static const char *_json_array_get_string(const json_t *obj, size_t index)
{
    const json_t *jval = json_array_get(obj, index);
    if (!jval) return NULL;
    const char *val = json_string_value(jval);
    return val;
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
    }
    else {
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

static int getcontactupdates_cb(void *rock, struct carddav_data *cdata)
{
    struct updates_rock *urock = (struct updates_rock *) rock;
    updates_rock_update(urock, cdata->dav, cdata->vcard_uid);
    return 0;
}

static int geteventupdates_cb(void *rock, struct caldav_data *cdata)
{
    struct updates_rock *urock = (struct updates_rock *) rock;
    updates_rock_update(urock, cdata->dav, cdata->ical_uid);
    return 0;
}

static int getContactGroupUpdates(struct jmap_req *req)
{
    struct carddav_db *db = carddav_open_userid(req->userid);
    if (!db) return -1;

    int r = -1;
    const char *since = _json_object_get_string(req->args, "sinceState");
    if (!since) goto done;
    modseq_t oldmodseq = str2uint64(since);

    char *mboxname = NULL;
    json_t *abookid = json_object_get(req->args, "addressbookId");
    if (abookid && json_string_value(abookid)) {
        /* XXX - invalid arguments */
        const char *addressbookId = json_string_value(abookid);
        mboxname = carddav_mboxname(req->userid, addressbookId);
    }

    struct updates_rock rock;
    rock.changed = json_array();
    rock.removed = json_array();

    r = carddav_get_updates(db, oldmodseq, mboxname, CARDDAV_KIND_GROUP,
                            &getcontactupdates_cb, &rock);
    if (r) goto done;

    strip_spurious_deletes(&rock);

    json_t *contactGroupUpdates = json_pack("{}");
    json_object_set_new(contactGroupUpdates, "accountId",
                        json_string(req->userid));
    json_object_set_new(contactGroupUpdates, "oldState",
                        json_string(since)); // XXX - just use refcounted
    json_object_set_new(contactGroupUpdates, "newState",
                        json_string(req->state));
    json_object_set(contactGroupUpdates, "changed", rock.changed);
    json_object_set(contactGroupUpdates, "removed", rock.removed);

    json_t *item = json_pack("[]");
    json_array_append_new(item, json_string("contactGroupUpdates"));
    json_array_append_new(item, contactGroupUpdates);
    json_array_append_new(item, json_string(req->tag));

    json_array_append_new(req->response, item);

    json_t *dofetch = json_object_get(req->args, "fetchContactGroups");
    if (dofetch && json_is_true(dofetch) && json_array_size(rock.changed)) {
        struct jmap_req subreq = *req; // struct copy, woot
        subreq.args = json_pack("{}");
        json_object_set(subreq.args, "ids", rock.changed);
        if (abookid) {
            json_object_set(subreq.args, "addressbookId", abookid);
        }
        r = getContactGroups(&subreq);
        json_decref(subreq.args);
    }

    json_decref(rock.changed);
    json_decref(rock.removed);

  done:
    carddav_close(db);
    return r;
}

static const char *_resolveid(struct jmap_req *req, const char *id)
{
    const char *newid = hash_lookup(id, req->idmap);
    if (newid) return newid;
    return id;
}

static int _add_group_entries(struct jmap_req *req,
                              struct vparse_card *card, json_t *members)
{
    vparse_delete_entries(card, NULL, "X-ADDRESSBOOKSERVER-MEMBER");
    int r = 0;
    size_t index;
    struct buf buf = BUF_INITIALIZER;

    for (index = 0; index < json_array_size(members); index++) {
        const char *item = _json_array_get_string(members, index);
        if (!item) continue;
        const char *uid = _resolveid(req, item);
        buf_setcstr(&buf, "urn:uuid:");
        buf_appendcstr(&buf, uid);
        vparse_add_entry(card, NULL,
                         "X-ADDRESSBOOKSERVER-MEMBER", buf_cstring(&buf));
    }

    buf_free(&buf);
    return r;
}

static int _add_othergroup_entries(struct jmap_req *req,
                                   struct vparse_card *card, json_t *members)
{
    vparse_delete_entries(card, NULL, "X-FM-OTHERACCOUNT-MEMBER");
    int r = 0;
    struct buf buf = BUF_INITIALIZER;
    const char *key;
    json_t *arg;
    json_object_foreach(members, key, arg) {
        unsigned i;
        for (i = 0; i < json_array_size(arg); i++) {
            const char *item = json_string_value(json_array_get(arg, i));
            if (!item)
                return -1;
            const char *uid = _resolveid(req, item);
            buf_setcstr(&buf, "urn:uuid:");
            buf_appendcstr(&buf, uid);
            struct vparse_entry *entry =
                vparse_add_entry(card, NULL,
                                 "X-FM-OTHERACCOUNT-MEMBER", buf_cstring(&buf));
            vparse_add_param(entry, "userid", key);
        }
    }
    buf_free(&buf);
    return r;
}

static int setContactGroups(struct jmap_req *req)
{
    struct mailbox *mailbox = NULL;
    struct mailbox *newmailbox = NULL;
    struct carddav_db *db = carddav_open_userid(req->userid);
    if (!db) return -1;

    int r = 0;
    json_t *jcheckState = json_object_get(req->args, "ifInState");
    if (jcheckState) {
        const char *checkState = json_string_value(jcheckState);
        if (!checkState ||strcmp(req->state, checkState)) {
            json_t *item = json_pack("[s, {s:s}, s]",
                                     "error", "type", "stateMismatch", req->tag);
            json_array_append_new(req->response, item);
            goto done;
        }
    }
    json_t *set = json_pack("{s:s,s:s}",
                            "oldState", req->state,
                            "accountId", req->userid);

    json_t *create = json_object_get(req->args, "create");
    if (create) {
        json_t *created = json_pack("{}");
        json_t *notCreated = json_pack("{}");
        json_t *record;

        const char *key;
        json_t *arg;
        json_object_foreach(create, key, arg) {
            const char *uid = makeuuid();
            json_t *jname = json_object_get(arg, "name");
            if (!jname) {
                /* XXX - missingParameters should be an invalidProperties
                 * error. Fix this when the contacts error handling code gets
                 * merged with the calendar codebase. */
                json_t *err = json_pack("{s:s}", "type", "missingParameters");
                json_object_set_new(notCreated, key, err);
                continue;
            }
            const char *name = json_string_value(jname);
            if (!name) {
                json_t *err = json_pack("{s:s}", "type", "invalidArguments");
                json_object_set_new(notCreated, key, err);
                continue;
            }
            // XXX - no name => notCreated
            struct vparse_card *card = vparse_new_card("VCARD");
            vparse_add_entry(card, NULL, "VERSION", "3.0");
            vparse_add_entry(card, NULL, "FN", name);
            vparse_add_entry(card, NULL, "UID", uid);
            vparse_add_entry(card, NULL, "X-ADDRESSBOOKSERVER-KIND", "group");

            /* it's legal to create an empty group */
            json_t *members = json_object_get(arg, "contactIds");
            if (members) {
                r = _add_group_entries(req, card, members);
                if (r) {
                    /* this one is legit -
                       it just means we'll be adding an error instead */
                    r = 0;
                    json_t *err = json_pack("{s:s}",
                                            "type", "invalidContactId");
                    json_object_set_new(notCreated, key, err);
                    vparse_free_card(card);
                    continue;
                }
            }

            /* it's legal to create an empty group */
            json_t *others = json_object_get(arg, "otherAccountContactIds");
            if (others) {
                r = _add_othergroup_entries(req, card, others);
                if (r) {
                    /* this one is legit -
                       it just means we'll be adding an error instead */
                    r = 0;
                    json_t *err = json_pack("{s:s}",
                                            "type", "invalidContactId");
                    json_object_set_new(notCreated, key, err);
                    vparse_free_card(card);
                    continue;
                }
            }

            const char *addressbookId = "Default";
            json_t *abookid = json_object_get(arg, "addressbookId");
            if (abookid && json_string_value(abookid)) {
                /* XXX - invalid arguments */
                addressbookId = json_string_value(abookid);
            }
            const char *mboxname = mboxname_abook(req->userid, addressbookId);
            json_object_del(arg, "addressbookId");
            addressbookId = NULL;

            /* we need to create and append a record */
            if (!mailbox || strcmp(mailbox->name, mboxname)) {
                mailbox_close(&mailbox);
                r = mailbox_open_iwl(mboxname, &mailbox);
            }

            syslog(LOG_NOTICE, "jmap: create group %s/%s/%s (%s)",
                   req->userid, mboxname, uid, name);

            if (!r) r = carddav_store(mailbox, card, NULL, NULL, NULL,
                                      req->userid, req->authstate, ignorequota);

            vparse_free_card(card);

            if (r) {
                /* these are real "should never happen" errors */
                goto done;
            }

            record = json_pack("{s:s}", "id", uid);
            json_object_set_new(created, key, record);

            /* hash_insert takes ownership of uid here, skanky I know */
            hash_insert(key, xstrdup(uid), req->idmap);
        }

        if (json_object_size(created))
            json_object_set(set, "created", created);
        json_decref(created);
        if (json_object_size(notCreated))
            json_object_set(set, "notCreated", notCreated);
        json_decref(notCreated);
    }

    json_t *update = json_object_get(req->args, "update");
    if (update) {
        json_t *updated = json_pack("[]");
        json_t *notUpdated = json_pack("{}");

        const char *uid;
        json_t *arg;
        json_object_foreach(update, uid, arg) {
            struct carddav_data *cdata = NULL;
            r = carddav_lookup_uid(db, uid, &cdata);
            uint32_t olduid;
            char *resource = NULL;

            /* is it a valid group? */
            if (r || !cdata || !cdata->dav.imap_uid || !cdata->dav.resource
                  || cdata->kind != CARDDAV_KIND_GROUP) {
                r = 0;
                json_t *err = json_pack("{s:s}", "type", "notFound");
                json_object_set_new(notUpdated, uid, err);
                continue;
            }
            olduid = cdata->dav.imap_uid;
            resource = xstrdup(cdata->dav.resource);

            if (!mailbox || strcmp(mailbox->name, cdata->dav.mailbox)) {
                mailbox_close(&mailbox);
                r = mailbox_open_iwl(cdata->dav.mailbox, &mailbox);
                if (r) {
                    syslog(LOG_ERR, "IOERROR: failed to open %s",
                           cdata->dav.mailbox);
                    goto done;
                }
            }

            json_t *abookid = json_object_get(arg, "addressbookId");
            if (abookid && json_string_value(abookid)) {
                const char *mboxname =
                    mboxname_abook(req->userid, json_string_value(abookid));
                if (strcmp(mboxname, cdata->dav.mailbox)) {
                    /* move */
                    r = mailbox_open_iwl(mboxname, &newmailbox);
                    if (r) {
                        syslog(LOG_ERR, "IOERROR: failed to open %s", mboxname);
                        goto done;
                    }
                }
                json_object_del(arg, "addressbookId");
            }

            /* XXX - this could definitely be refactored from here and mailbox.c */
            struct buf msg_buf = BUF_INITIALIZER;
            struct vparse_state vparser;
            struct index_record record;

            r = mailbox_find_index_record(mailbox,
                                          cdata->dav.imap_uid, &record);
            if (r) goto done;

            /* Load message containing the resource and parse vcard data */
            r = mailbox_map_record(mailbox, &record, &msg_buf);
            if (r) goto done;

            memset(&vparser, 0, sizeof(struct vparse_state));
            vparser.base = buf_cstring(&msg_buf) + record.header_size;
            vparse_set_multival(&vparser, "adr");
            vparse_set_multival(&vparser, "org");
            vparse_set_multival(&vparser, "n");
            r = vparse_parse(&vparser, 0);
            buf_free(&msg_buf);
            if (r || !vparser.card || !vparser.card->objects) {
                json_t *err = json_pack("{s:s}", "type", "parseError");
                json_object_set_new(notUpdated, uid, err);
                vparse_free(&vparser);
                mailbox_close(&newmailbox);
                continue;
            }
            struct vparse_card *card = vparser.card->objects;

            json_t *namep = json_object_get(arg, "name");
            if (namep) {
                const char *name = json_string_value(namep);
                if (!name) {
                    json_t *err = json_pack("{s:s}",
                                            "type", "invalidArguments");
                    json_object_set_new(notUpdated, uid, err);
                    vparse_free(&vparser);
                    mailbox_close(&newmailbox);
                    continue;
                }
                struct vparse_entry *entry = vparse_get_entry(card, NULL, "FN");
                if (entry) {
                    free(entry->v.value);
                    entry->v.value = xstrdup(name);
                }
                else {
                    vparse_add_entry(card, NULL, "FN", name);
                }
            }

            json_t *members = json_object_get(arg, "contactIds");
            if (members) {
                r = _add_group_entries(req, card, members);
                if (r) {
                    /* this one is legit -
                       it just means we'll be adding an error instead */
                    r = 0;
                    json_t *err = json_pack("{s:s}",
                                            "type", "invalidContactId");
                    json_object_set_new(notUpdated, uid, err);
                    vparse_free(&vparser);
                    mailbox_close(&newmailbox);
                    continue;
                }
            }

            json_t *others = json_object_get(arg, "otherAccountContactIds");
            if (others) {
                r = _add_othergroup_entries(req, card, others);
                if (r) {
                    /* this one is legit -
                       it just means we'll be adding an error instead */
                    r = 0;
                    json_t *err = json_pack("{s:s}",
                                            "type", "invalidContactId");
                    json_object_set_new(notUpdated, uid, err);
                    vparse_free(&vparser);
                    mailbox_close(&newmailbox);
                    continue;
                }
            }

            syslog(LOG_NOTICE, "jmap: update group %s/%s",
                   req->userid, resource);

            r = carddav_store(newmailbox ? newmailbox : mailbox, card, resource,
                              NULL, NULL, req->userid, req->authstate, ignorequota);
            if (!r)
                r = carddav_remove(mailbox, olduid, /*isreplace*/!newmailbox);
            mailbox_close(&newmailbox);

            vparse_free(&vparser);
            free(resource);
            if (r) goto done;

            json_array_append_new(updated, json_string(uid));
        }

        if (json_array_size(updated))
            json_object_set(set, "updated", updated);
        json_decref(updated);
        if (json_object_size(notUpdated))
            json_object_set(set, "notUpdated", notUpdated);
        json_decref(notUpdated);
    }

    json_t *destroy = json_object_get(req->args, "destroy");
    if (destroy) {
        json_t *destroyed = json_pack("[]");
        json_t *notDestroyed = json_pack("{}");

        size_t index;
        for (index = 0; index < json_array_size(destroy); index++) {
            const char *uid = _json_array_get_string(destroy, index);
            if (!uid) {
                json_t *err = json_pack("{s:s}", "type", "invalidArguments");
                json_object_set_new(notDestroyed, uid, err);
                continue;
            }
            struct carddav_data *cdata = NULL;
            uint32_t olduid;
            r = carddav_lookup_uid(db, uid, &cdata);

            /* is it a valid group? */
            if (r || !cdata ||
                !cdata->dav.imap_uid || cdata->kind != CARDDAV_KIND_GROUP) {
                r = 0;
                json_t *err = json_pack("{s:s}", "type", "notFound");
                json_object_set_new(notDestroyed, uid, err);
                continue;
            }
            olduid = cdata->dav.imap_uid;

            if (!mailbox || strcmp(mailbox->name, cdata->dav.mailbox)) {
                mailbox_close(&mailbox);
                r = mailbox_open_iwl(cdata->dav.mailbox, &mailbox);
                if (r) goto done;
            }

            /* XXX - alive check */

            syslog(LOG_NOTICE, "jmap: destroy group %s (%s)", req->userid, uid);
            r = carddav_remove(mailbox, olduid, /*isreplace*/0);
            if (r) {
                syslog(LOG_ERR,
                       "IOERROR: setContactGroups remove failed for %s %u",
                       mailbox->name, cdata->dav.imap_uid);
                goto done;
            }

            json_array_append_new(destroyed, json_string(uid));
        }

        if (json_array_size(destroyed))
            json_object_set(set, "destroyed", destroyed);
        json_decref(destroyed);
        if (json_object_size(notDestroyed))
            json_object_set(set, "notDestroyed", notDestroyed);
        json_decref(notDestroyed);
    }

    /* force modseq to stable */
    if (mailbox) mailbox_unlock_index(mailbox, NULL);

    /* read the modseq again every time, just in case something changed it
     * in our actions */
    struct buf buf = BUF_INITIALIZER;
    const char *inboxname = mboxname_user_mbox(req->userid, NULL);
    modseq_t modseq = mboxname_readmodseq(inboxname);
    buf_printf(&buf, "%llu", modseq);
    json_object_set_new(set, "newState", json_string(buf_cstring(&buf)));
    buf_free(&buf);

    json_t *item = json_pack("[]");
    json_array_append_new(item, json_string("contactGroupsSet"));
    json_array_append_new(item, set);
    json_array_append_new(item, json_string(req->tag));

    json_array_append_new(req->response, item);

done:
    mailbox_close(&newmailbox);
    mailbox_close(&mailbox);

    carddav_close(db);
    return r;
}

static int _wantprop(hash_table *props, const char *name)
{
    if (!props) return 1;
    if (hash_lookup(name, props)) return 1;
    return 0;
}

/* convert YYYY-MM-DD to separate y,m,d */
static int _parse_date(const char *date, unsigned *y, unsigned *m, unsigned *d)
{
    /* there isn't a convenient libc function that will let us convert parts of
     * a string to integer and only take digit characters, so we just pull it
     * apart ourselves */

    /* format check. no need to strlen() beforehand, it will fall out of this */
    if (date[0] < '0' || date[0] > '9' ||
        date[1] < '0' || date[1] > '9' ||
        date[2] < '0' || date[2] > '9' ||
        date[3] < '0' || date[3] > '9' ||
        date[4] != '-' ||
        date[5] < '0' || date[5] > '9' ||
        date[6] < '0' || date[6] > '9' ||
        date[7] != '-' ||
        date[8] < '0' || date[8] > '9' ||
        date[9] < '0' || date[9] > '9' ||
        date[10] != '\0')

        return -1;

    /* convert to integer. ascii digits are 0x30-0x37, so we can take bottom
     * four bits and multiply */
    *y =
        (date[0] & 0xf) * 1000 +
        (date[1] & 0xf) * 100 +
        (date[2] & 0xf) * 10 +
        (date[3] & 0xf);

    *m =
        (date[5] & 0xf) * 10 +
        (date[6] & 0xf);

    *d =
        (date[8] & 0xf) * 10 +
        (date[9] & 0xf);

    return 0;
}

static void _date_to_jmap(struct vparse_entry *entry, struct buf *buf)
{
    if (!entry)
        goto no_date;

    unsigned y, m, d;
    if (_parse_date(entry->v.value, &y, &m, &d))
        goto no_date;

    if (y < 1604 || m > 12 || d > 31)
        goto no_date;

    const struct vparse_param *param;
    for (param = entry->params; param; param = param->next) {
        if (!strcasecmp(param->name, "x-apple-omit-year"))
            /* XXX compare value with actual year? */
            y = 0;
        if (!strcasecmp(param->name, "x-fm-no-month"))
            m = 0;
        if (!strcasecmp(param->name, "x-fm-no-day"))
            d = 0;
    }

    /* sigh, magic year 1604 has been seen without X-APPLE-OMIT-YEAR, making
     * me wonder what the bloody point is */
    if (y == 1604)
        y = 0;

    buf_reset(buf);
    buf_printf(buf, "%04d-%02d-%02d", y, m, d);
    return;

no_date:
    buf_setcstr(buf, "0000-00-00");
}

static const char *_servicetype(const char *type)
{
    /* add new services here */
    if (!strcasecmp(type, "aim")) return "AIM";
    if (!strcasecmp(type, "facebook")) return "Facebook";
    if (!strcasecmp(type, "flickr")) return "Flickr";
    if (!strcasecmp(type, "gadugadu")) return "GaduGadu";
    if (!strcasecmp(type, "github")) return "GitHub";
    if (!strcasecmp(type, "googletalk")) return "GoogleTalk";
    if (!strcasecmp(type, "icq")) return "ICQ";
    if (!strcasecmp(type, "jabber")) return "Jabber";
    if (!strcasecmp(type, "linkedin")) return "LinkedIn";
    if (!strcasecmp(type, "msn")) return "MSN";
    if (!strcasecmp(type, "myspace")) return "MySpace";
    if (!strcasecmp(type, "qq")) return "QQ";
    if (!strcasecmp(type, "skype")) return "Skype";
    if (!strcasecmp(type, "twitter")) return "Twitter";
    if (!strcasecmp(type, "yahoo")) return "Yahoo";

    syslog(LOG_NOTICE, "unknown service type %s", type);
    return type;
}

static int getcontacts_cb(void *rock, struct carddav_data *cdata)
{
    struct cards_rock *crock = (struct cards_rock *) rock;
    struct index_record record;
    strarray_t *empty = NULL;
    int r = 0;

    if (!crock->mailbox || strcmp(crock->mailbox->name, cdata->dav.mailbox)) {
        mailbox_close(&crock->mailbox);
        r = mailbox_open_irl(cdata->dav.mailbox, &crock->mailbox);
        if (r) return r;
    }

    r = mailbox_find_index_record(crock->mailbox, cdata->dav.imap_uid, &record);
    if (r) return r;

    crock->rows++;

    /* XXX - this could definitely be refactored from here and mailbox.c */
    struct buf msg_buf = BUF_INITIALIZER;
    struct vparse_state vparser;

    /* Load message containing the resource and parse vcard data */
    r = mailbox_map_record(crock->mailbox, &record, &msg_buf);
    if (r) return r;

    memset(&vparser, 0, sizeof(struct vparse_state));
    vparser.base = buf_cstring(&msg_buf) + record.header_size;
    vparse_set_multival(&vparser, "adr");
    vparse_set_multival(&vparser, "org");
    vparse_set_multival(&vparser, "n");
    r = vparse_parse(&vparser, 0);
    buf_free(&msg_buf);
    if (r || !vparser.card || !vparser.card->objects) {
        vparse_free(&vparser);
        return r;
    }
    struct vparse_card *card = vparser.card->objects;

    json_t *obj = json_pack("{}");

    json_object_set_new(obj, "id", json_string(cdata->vcard_uid));

    json_object_set_new(obj, "addressbookId",
                        json_string(strrchr(cdata->dav.mailbox, '.')+1));

    if (_wantprop(crock->props, "isFlagged")) {
        json_object_set_new(obj, "isFlagged",
                            record.system_flags & FLAG_FLAGGED ? json_true() :
                            json_false());
    }

    struct buf buf = BUF_INITIALIZER;

    if (_wantprop(crock->props, "x-href")) {
        _add_xhref(obj, cdata->dav.mailbox, cdata->dav.resource);
    }

    if (_wantprop(crock->props, "x-importance")) {
        double val = 0;
        const char *ns = DAV_ANNOT_NS "<" XML_NS_CYRUS ">importance";

        buf_reset(&buf);
        annotatemore_msg_lookup(crock->mailbox->name, record.uid,
                                ns, "", &buf);
        if (buf.len)
            val = strtod(buf_cstring(&buf), NULL);

        json_object_set_new(obj, "x-importance", json_real(val));
    }

    const strarray_t *n = vparse_multival(card, "n");
    const strarray_t *org = vparse_multival(card, "org");
    if (!n) n = empty ? empty : (empty = strarray_new());
    if (!org) org = empty ? empty : (empty = strarray_new());

    /* name fields: Family; Given; Middle; Prefix; Suffix. */

    if (_wantprop(crock->props, "lastName")) {
        const char *family = strarray_safenth(n, 0);
        const char *suffix = strarray_safenth(n, 4);
        buf_setcstr(&buf, family);
        if (*suffix) {
            buf_putc(&buf, ' ');
            buf_appendcstr(&buf, suffix);
        }
        json_object_set_new(obj, "lastName", json_string(buf_cstring(&buf)));
    }

    if (_wantprop(crock->props, "firstName")) {
        const char *given = strarray_safenth(n, 1);
        const char *middle = strarray_safenth(n, 2);
        buf_setcstr(&buf, given);
        if (*middle) {
            buf_putc(&buf, ' ');
            buf_appendcstr(&buf, middle);
        }
        json_object_set_new(obj, "firstName", json_string(buf_cstring(&buf)));
    }
    if (_wantprop(crock->props, "prefix")) {
        const char *prefix = strarray_safenth(n, 3);
        json_object_set_new(obj, "prefix",
                            json_string(prefix)); /* just prefix */
    }

    /* org fields */
    if (_wantprop(crock->props, "company"))
        json_object_set_new(obj, "company",
                            json_string(strarray_safenth(org, 0)));
    if (_wantprop(crock->props, "department"))
        json_object_set_new(obj, "department",
                            json_string(strarray_safenth(org, 1)));
    if (_wantprop(crock->props, "jobTitle"))
        json_object_set_new(obj, "jobTitle",
                            json_string(strarray_safenth(org, 2)));
    /* XXX - position? */

    /* address - we need to open code this, because it's repeated */
    if (_wantprop(crock->props, "addresses")) {
        json_t *adr = json_array();

        struct vparse_entry *entry;
        for (entry = card->properties; entry; entry = entry->next) {
            if (strcasecmp(entry->name, "adr")) continue;
            json_t *item = json_pack("{}");

            /* XXX - type and label */
            const strarray_t *a = entry->v.values;

            const struct vparse_param *param;
            const char *type = "other";
            const char *label = NULL;
            for (param = entry->params; param; param = param->next) {
                if (!strcasecmp(param->name, "type")) {
                    if (!strcasecmp(param->value, "home")) {
                        type = "home";
                    }
                    else if (!strcasecmp(param->value, "work")) {
                        type = "work";
                    }
                    else if (!strcasecmp(param->value, "billing")) {
                        type = "billing";
                    }
                    else if (!strcasecmp(param->value, "postal")) {
                        type = "postal";
                    }
                }
                else if (!strcasecmp(param->name, "label")) {
                    label = param->value;
                }
            }
            json_object_set_new(item, "type", json_string(type));
            if (label) json_object_set_new(item, "label", json_string(label));

            const char *pobox = strarray_safenth(a, 0);
            const char *extended = strarray_safenth(a, 1);
            const char *street = strarray_safenth(a, 2);
            buf_reset(&buf);
            if (*pobox) {
                buf_appendcstr(&buf, pobox);
                if (extended || street) buf_putc(&buf, '\n');
            }
            if (*extended) {
                buf_appendcstr(&buf, extended);
                if (street) buf_putc(&buf, '\n');
            }
            if (*street) {
                buf_appendcstr(&buf, street);
            }

            json_object_set_new(item, "street",
                                json_string(buf_cstring(&buf)));
            json_object_set_new(item, "locality",
                                json_string(strarray_safenth(a, 3)));
            json_object_set_new(item, "region",
                                json_string(strarray_safenth(a, 4)));
            json_object_set_new(item, "postcode",
                                json_string(strarray_safenth(a, 5)));
            json_object_set_new(item, "country",
                                json_string(strarray_safenth(a, 6)));

            json_array_append_new(adr, item);
        }

        json_object_set_new(obj, "addresses", adr);
    }

    /* address - we need to open code this, because it's repeated */
    if (_wantprop(crock->props, "emails")) {
        json_t *emails = json_array();

        struct vparse_entry *entry;
        int defaultIndex = -1;
        int i = 0;
        for (entry = card->properties; entry; entry = entry->next) {
            if (strcasecmp(entry->name, "email")) continue;
            json_t *item = json_pack("{}");
            const struct vparse_param *param;
            const char *type = "other";
            const char *label = NULL;
            for (param = entry->params; param; param = param->next) {
                if (!strcasecmp(param->name, "type")) {
                    if (!strcasecmp(param->value, "home")) {
                        type = "personal";
                    }
                    else if (!strcasecmp(param->value, "work")) {
                        type = "work";
                    }
                    else if (!strcasecmp(param->value, "pref")) {
                        if (defaultIndex < 0)
                            defaultIndex = i;
                    }
                }
                else if (!strcasecmp(param->name, "label")) {
                    label = param->value;
                }
            }
            json_object_set_new(item, "type", json_string(type));
            if (label) json_object_set_new(item, "label", json_string(label));

            json_object_set_new(item, "value", json_string(entry->v.value));

            json_array_append_new(emails, item);
            i++;
        }

        if (defaultIndex < 0)
            defaultIndex = 0;
        int size = json_array_size(emails);
        for (i = 0; i < size; i++) {
            json_t *item = json_array_get(emails, i);
            json_object_set_new(item, "isDefault",
                                i == defaultIndex ? json_true() : json_false());
        }

        json_object_set_new(obj, "emails", emails);
    }

    /* address - we need to open code this, because it's repeated */
    if (_wantprop(crock->props, "phones")) {
        json_t *phones = json_array();

        struct vparse_entry *entry;
        for (entry = card->properties; entry; entry = entry->next) {
            if (strcasecmp(entry->name, "tel")) continue;
            json_t *item = json_pack("{}");
            const struct vparse_param *param;
            const char *type = "other";
            const char *label = NULL;
            for (param = entry->params; param; param = param->next) {
                if (!strcasecmp(param->name, "type")) {
                    if (!strcasecmp(param->value, "home")) {
                        type = "home";
                    }
                    else if (!strcasecmp(param->value, "work")) {
                        type = "work";
                    }
                    else if (!strcasecmp(param->value, "cell")) {
                        type = "mobile";
                    }
                    else if (!strcasecmp(param->value, "mobile")) {
                        type = "mobile";
                    }
                    else if (!strcasecmp(param->value, "fax")) {
                        type = "fax";
                    }
                    else if (!strcasecmp(param->value, "pager")) {
                        type = "pager";
                    }
                }
                else if (!strcasecmp(param->name, "label")) {
                    label = param->value;
                }
            }
            json_object_set_new(item, "type", json_string(type));
            if (label) json_object_set_new(item, "label", json_string(label));

            json_object_set_new(item, "value", json_string(entry->v.value));

            json_array_append_new(phones, item);
        }

        json_object_set_new(obj, "phones", phones);
    }

    /* address - we need to open code this, because it's repeated */
    if (_wantprop(crock->props, "online")) {
        json_t *online = json_array();

        struct vparse_entry *entry;
        for (entry = card->properties; entry; entry = entry->next) {
            if (!strcasecmp(entry->name, "url")) {
                json_t *item = json_pack("{}");
                const struct vparse_param *param;
                const char *label = NULL;
                for (param = entry->params; param; param = param->next) {
                    if (!strcasecmp(param->name, "label")) {
                        label = param->value;
                    }
                }
                json_object_set_new(item, "type", json_string("uri"));
                if (label) json_object_set_new(item, "label", json_string(label));
                json_object_set_new(item, "value", json_string(entry->v.value));
                json_array_append_new(online, item);
            }
            if (!strcasecmp(entry->name, "impp")) {
                json_t *item = json_pack("{}");
                const struct vparse_param *param;
                const char *label = NULL;
                for (param = entry->params; param; param = param->next) {
                    if (!strcasecmp(param->name, "x-service-type")) {
                        label = _servicetype(param->value);
                    }
                }
                json_object_set_new(item, "type", json_string("username"));
                if (label) json_object_set_new(item, "label", json_string(label));
                json_object_set_new(item, "value", json_string(entry->v.value));
                json_array_append_new(online, item);
            }
            if (!strcasecmp(entry->name, "x-social-profile")) {
                json_t *item = json_pack("{}");
                const struct vparse_param *param;
                const char *label = NULL;
                const char *value = NULL;
                for (param = entry->params; param; param = param->next) {
                    if (!strcasecmp(param->name, "type")) {
                        label = _servicetype(param->value);
                    }
                    if (!strcasecmp(param->name, "x-user")) {
                        value = param->value;
                    }
                }
                json_object_set_new(item, "type", json_string("username"));
                if (label) json_object_set_new(item, "label", json_string(label));
                json_object_set_new(item, "value",
                                    json_string(value ? value : entry->v.value));
                json_array_append_new(online, item);
            }
            if (!strcasecmp(entry->name, "x-fm-online-other")) {
                json_t *item = json_pack("{}");
                const struct vparse_param *param;
                const char *label = NULL;
                for (param = entry->params; param; param = param->next) {
                    if (!strcasecmp(param->name, "label")) {
                        label = param->value;
                    }
                }
                json_object_set_new(item, "type", json_string("other"));
                if (label) json_object_set_new(item, "label", json_string(label));
                json_object_set_new(item, "value", json_string(entry->v.value));
                json_array_append_new(online, item);
            }
        }

        json_object_set_new(obj, "online", online);
    }

    if (_wantprop(crock->props, "nickname")) {
        const char *item = vparse_stringval(card, "nickname");
        json_object_set_new(obj, "nickname", json_string(item ? item : ""));
    }

    if (_wantprop(crock->props, "birthday")) {
        struct vparse_entry *entry = vparse_get_entry(card, NULL, "bday");
        _date_to_jmap(entry, &buf);
        json_object_set_new(obj, "birthday", json_string(buf_cstring(&buf)));
    }

    if (_wantprop(crock->props, "notes")) {
        const char *item = vparse_stringval(card, "note");
        json_object_set_new(obj, "notes", json_string(item ? item : ""));
    }

    if (_wantprop(crock->props, "x-hasPhoto")) {
        const char *item = vparse_stringval(card, "photo");
        json_object_set_new(obj, "x-hasPhoto",
                            item ? json_true() : json_false());
    }

    /* XXX - other fields */

    json_array_append_new(crock->array, obj);

    if (empty) strarray_free(empty);

    vparse_free(&vparser);
    buf_free(&buf);

    return 0;
}

static int getContacts(struct jmap_req *req)
{
    return jmap_contacts_get(req, &getcontacts_cb, CARDDAV_KIND_CONTACT, "contacts");
}

static int getContactUpdates(struct jmap_req *req)
{
    struct carddav_db *db = carddav_open_userid(req->userid);
    if (!db) return -1;

    int r = -1;
    const char *since = _json_object_get_string(req->args, "sinceState");
    if (!since) goto done;
    modseq_t oldmodseq = str2uint64(since);

    char *mboxname = NULL;
    json_t *abookid = json_object_get(req->args, "addressbookId");
    if (abookid && json_string_value(abookid)) {
        /* XXX - invalid arguments */
        const char *addressbookId = json_string_value(abookid);
        mboxname = carddav_mboxname(req->userid, addressbookId);
    }

    struct updates_rock rock;
    rock.changed = json_array();
    rock.removed = json_array();

    r = carddav_get_updates(db, oldmodseq, mboxname, CARDDAV_KIND_CONTACT,
                            &getcontactupdates_cb, &rock);
    if (r) goto done;

    strip_spurious_deletes(&rock);

    json_t *contactUpdates = json_pack("{}");
    json_object_set_new(contactUpdates, "accountId", json_string(req->userid));
    json_object_set_new(contactUpdates, "oldState", json_string(since));
    json_object_set_new(contactUpdates, "newState", json_string(req->state));
    json_object_set(contactUpdates, "changed", rock.changed);
    json_object_set(contactUpdates, "removed", rock.removed);

    json_t *item = json_pack("[]");
    json_array_append_new(item, json_string("contactUpdates"));
    json_array_append_new(item, contactUpdates);
    json_array_append_new(item, json_string(req->tag));

    json_array_append_new(req->response, item);

    json_t *dofetch = json_object_get(req->args, "fetchContacts");
    json_t *doprops = json_object_get(req->args, "fetchContactProperties");
    if (dofetch && json_is_true(dofetch) && json_array_size(rock.changed)) {
        struct jmap_req subreq = *req;
        subreq.args = json_pack("{}");
        json_object_set(subreq.args, "ids", rock.changed);
        if (doprops) json_object_set(subreq.args, "properties", doprops);
        if (abookid) {
            json_object_set(subreq.args, "addressbookId", abookid);
        }
        r = getContacts(&subreq);
        json_decref(subreq.args);
    }

    json_decref(rock.changed);
    json_decref(rock.removed);

  done:
    carddav_close(db);
    return r;
}

static struct vparse_entry *_card_multi(struct vparse_card *card,
                                        const char *name)
{
    struct vparse_entry *res = vparse_get_entry(card, NULL, name);
    if (!res) {
        res = vparse_add_entry(card, NULL, name, NULL);
        res->multivalue = 1;
        res->v.values = strarray_new();
    }
    return res;
}

static int _emails_to_card(struct vparse_card *card, json_t *arg)
{
    vparse_delete_entries(card, NULL, "email");

    int i;
    int size = json_array_size(arg);
    for (i = 0; i < size; i++) {
        json_t *item = json_array_get(arg, i);

        const char *type = _json_object_get_string(item, "type");
        if (!type) return -1;
        /*optional*/
        const char *label = _json_object_get_string(item, "label");
        const char *value = _json_object_get_string(item, "value");
        if (!value) return -1;
        json_t *jisDefault = json_object_get(item, "isDefault");

        struct vparse_entry *entry =
            vparse_add_entry(card, NULL, "email", value);

        if (!strcmpsafe(type, "personal"))
            type = "home";
        if (strcmpsafe(type, "other"))
            vparse_add_param(entry, "type", type);

        if (label)
            vparse_add_param(entry, "label", label);

        if (jisDefault && json_is_true(jisDefault))
            vparse_add_param(entry, "type", "pref");
    }
    return 0;
}

static int _phones_to_card(struct vparse_card *card, json_t *arg)
{
    vparse_delete_entries(card, NULL, "tel");

    int i;
    int size = json_array_size(arg);
    for (i = 0; i < size; i++) {
        json_t *item = json_array_get(arg, i);
        const char *type = _json_object_get_string(item, "type");
        if (!type) return -1;
        /* optional */
        const char *label = _json_object_get_string(item, "label");
        const char *value = _json_object_get_string(item, "value");
        if (!value) return -1;

        struct vparse_entry *entry = vparse_add_entry(card, NULL, "tel", value);

        if (!strcmp(type, "mobile"))
            vparse_add_param(entry, "type", "cell");
        else if (strcmp(type, "other"))
            vparse_add_param(entry, "type", type);

        if (label)
            vparse_add_param(entry, "label", label);
    }
    return 0;
}

static int _is_im(const char *type)
{
    /* add new services here */
    if (!strcasecmp(type, "aim")) return 1;
    if (!strcasecmp(type, "facebook")) return 1;
    if (!strcasecmp(type, "gadugadu")) return 1;
    if (!strcasecmp(type, "googletalk")) return 1;
    if (!strcasecmp(type, "icq")) return 1;
    if (!strcasecmp(type, "jabber")) return 1;
    if (!strcasecmp(type, "msn")) return 1;
    if (!strcasecmp(type, "qq")) return 1;
    if (!strcasecmp(type, "skype")) return 1;
    if (!strcasecmp(type, "twitter")) return 1;
    if (!strcasecmp(type, "yahoo")) return 1;

    return 0;
}

static int _online_to_card(struct vparse_card *card, json_t *arg)
{
    vparse_delete_entries(card, NULL, "url");
    vparse_delete_entries(card, NULL, "impp");
    vparse_delete_entries(card, NULL, "x-social-profile");
    vparse_delete_entries(card, NULL, "x-fm-online-other");

    int i;
    int size = json_array_size(arg);
    for (i = 0; i < size; i++) {
        json_t *item = json_array_get(arg, i);
        const char *value = _json_object_get_string(item, "value");
        if (!value) return -1;
        const char *type = _json_object_get_string(item, "type");
        if (!type) return -1;
        const char *label = _json_object_get_string(item, "label");

        if (!strcmp(type, "uri")) {
            struct vparse_entry *entry =
                vparse_add_entry(card, NULL, "url", value);
            if (label)
                vparse_add_param(entry, "label", label);
        }
        else if (!strcmp(type, "username")) {
            if (label && _is_im(label)) {
                struct vparse_entry *entry =
                    vparse_add_entry(card, NULL, "impp", value);
                vparse_add_param(entry, "x-service-type", label);
            }
            else {
                struct vparse_entry *entry =
                    vparse_add_entry(card, NULL, "x-social-profile", ""); // XXX - URL calculated, ick
                if (label)
                    vparse_add_param(entry, "type", label);
                vparse_add_param(entry, "x-user", value);
            }
        }
        else if (!strcmp(type, "other")) {
            struct vparse_entry *entry = vparse_add_entry(card, NULL, "x-fm-online-other", value);
            if (label)
                vparse_add_param(entry, "label", label);
        }
    }
    return 0;
}

static int _addresses_to_card(struct vparse_card *card, json_t *arg)
{
    vparse_delete_entries(card, NULL, "adr");

    int i;
    int size = json_array_size(arg);
    for (i = 0; i < size; i++) {
        json_t *item = json_array_get(arg, i);

        const char *type = _json_object_get_string(item, "type");
        if (!type) return -1;
        /* optional */
        const char *label = _json_object_get_string(item, "label");
        const char *street = _json_object_get_string(item, "street");
        if (!street) return -1;
        const char *locality = _json_object_get_string(item, "locality");
        if (!locality) return -1;
        const char *region = _json_object_get_string(item, "region");
        if (!region) return -1;
        const char *postcode = _json_object_get_string(item, "postcode");
        if (!postcode) return -1;
        const char *country = _json_object_get_string(item, "country");
        if (!country) return -1;

        struct vparse_entry *entry = vparse_add_entry(card, NULL, "adr", NULL);

        if (strcmpsafe(type, "other"))
            vparse_add_param(entry, "type", type);

        if (label)
            vparse_add_param(entry, "label", label);

        entry->multivalue = 1;
        entry->v.values = strarray_new();
        strarray_append(entry->v.values, ""); // PO Box
        strarray_append(entry->v.values, ""); // Extended Address
        strarray_append(entry->v.values, street);
        strarray_append(entry->v.values, locality);
        strarray_append(entry->v.values, region);
        strarray_append(entry->v.values, postcode);
        strarray_append(entry->v.values, country);
    }

    return 0;
}

static int _date_to_card(struct vparse_card *card,
                         const char *key, json_t *jval)
{
    if (!jval)
        return -1;
    const char *val = json_string_value(jval);
    if (!val)
        return -1;

    /* JMAP dates are always YYYY-MM-DD */
    unsigned y, m, d;
    if (_parse_date(val, &y, &m, &d))
        return -1;

    /* range checks. month and day just get basic sanity checks because we're
     * not carrying a full calendar implementation here. JMAP says zero is valid
     * so we'll allow that and deal with it later on */
    if (m > 12 || d > 31)
        return -1;

    /* all years are valid in JMAP, but ISO8601 only allows Gregorian ie >= 1583.
     * moreover, iOS uses 1604 as a magic number for "unknown", so we'll say 1605
     * is the minimum */
    if (y > 0 && y < 1605)
        return -1;

    /* everything in range. now comes the fun bit. vCard v3 says BDAY is
     * YYYY-MM-DD. It doesn't reference ISO8601 (vCard v4 does) and make no
     * provision for "unknown" date components, so there's no way to represent
     * JMAP's "unknown" values. Apple worked around this for year by using the
     * year 1604 and adding the parameter X-APPLE-OMIT-YEAR=1604 (value
     * apparently ignored). We will use a similar hack for month and day so we
     * can convert it back into a JMAP date */

    int no_year = 0;
    if (y == 0) {
        no_year = 1;
        y = 1604;
    }

    int no_month = 0;
    if (m == 0) {
        no_month = 1;
        m = 1;
    }

    int no_day = 0;
    if (d == 0) {
        no_day = 1;
        d = 1;
    }

    vparse_delete_entries(card, NULL, key);

    /* no values, we're done! */
    if (no_year && no_month && no_day)
        return 0;

    /* build the value */
    static char buf[11];
    snprintf(buf, sizeof(buf), "%04d-%02d-%02d", y, m, d);
    struct vparse_entry *entry = vparse_add_entry(card, NULL, key, buf);

    /* set all the round-trip flags, sigh */
    if (no_year)
        vparse_add_param(entry, "x-apple-omit-year", "1604");
    if (no_month)
        vparse_add_param(entry, "x-fm-no-month", "1");
    if (no_day)
        vparse_add_param(entry, "x-fm-no-day", "1");

    return 0;
}

static int _kv_to_card(struct vparse_card *card, const char *key, json_t *jval)
{
    if (!jval)
        return -1;
    const char *val = json_string_value(jval);
    if (!val)
        return -1;
    vparse_replace_entry(card, NULL, key, val);
    return 0;
}

static void _make_fn(struct vparse_card *card)
{
    struct vparse_entry *n = vparse_get_entry(card, NULL, "n");
    strarray_t *name = strarray_new();
    const char *v;

    if (n) {
        v = strarray_safenth(n->v.values, 3); // prefix
        if (*v) strarray_append(name, v);

        v = strarray_safenth(n->v.values, 1); // first
        if (*v) strarray_append(name, v);

        v = strarray_safenth(n->v.values, 2); // middle
        if (*v) strarray_append(name, v);

        v = strarray_safenth(n->v.values, 0); // last
        if (*v) strarray_append(name, v);

        v = strarray_safenth(n->v.values, 4); // suffix
        if (*v) strarray_append(name, v);
    }

    if (!strarray_size(name)) {
        v = vparse_stringval(card, "nickname");
        if (v && v[0]) strarray_append(name, v);
    }

    char *fn = NULL;
    if (strarray_size(name))
        fn = strarray_join(name, " ");
    else
        fn = xstrdup(" ");

    strarray_free(name);
    vparse_replace_entry(card, NULL, "fn", fn);
    free(fn);
}

static int _json_to_card(struct vparse_card *card,
                         json_t *arg, strarray_t *flags,
                         struct entryattlist **annotsp)
{
    const char *key;
    json_t *jval;
    struct vparse_entry *fn = vparse_get_entry(card, NULL, "fn");
    int name_is_dirty = 0;
    int record_is_dirty = 0;
    /* we'll be updating you later anyway... create early so that it's
     * at the top of the card */
    if (!fn) {
        fn = vparse_add_entry(card, NULL, "fn", "No Name");
        name_is_dirty = 1;
    }

    json_object_foreach(arg, key, jval) {
        if (!strcmp(key, "isFlagged")) {
            if (json_is_true(jval)) {
                strarray_add_case(flags, "\\Flagged");
            }
            else {
                strarray_remove_all_case(flags, "\\Flagged");
            }
        }
        else if (!strcmp(key, "x-importance")) {
            double dval = json_number_value(jval);
            const char *ns = DAV_ANNOT_NS "<" XML_NS_CYRUS ">importance";
            const char *attrib = "value.shared";
            struct buf buf = BUF_INITIALIZER;
            if (dval) {
                buf_printf(&buf, "%e", dval);
            }
            setentryatt(annotsp, ns, attrib, &buf);
            buf_free(&buf);
        }
        else if (!strcmp(key, "avatar")) {
            /* XXX - file handling */
        }
        else if (!strcmp(key, "prefix")) {
            const char *val = json_string_value(jval);
            if (!val)
                return -1;
            name_is_dirty = 1;
            struct vparse_entry *n = _card_multi(card, "n");
            strarray_set(n->v.values, 3, val);
        }
        else if (!strcmp(key, "firstName")) {
            const char *val = json_string_value(jval);
            if (!val)
                return -1;
            name_is_dirty = 1;
            struct vparse_entry *n = _card_multi(card, "n");
            strarray_set(n->v.values, 1, val);
        }
        else if (!strcmp(key, "lastName")) {
            const char *val = json_string_value(jval);
            if (!val)
                return -1;
            name_is_dirty = 1;
            struct vparse_entry *n = _card_multi(card, "n");
            strarray_set(n->v.values, 0, val);
        }
        else if (!strcmp(key, "suffix")) {
            const char *val = json_string_value(jval);
            if (!val)
                return -1;
            name_is_dirty = 1;
            struct vparse_entry *n = _card_multi(card, "n");
            strarray_set(n->v.values, 4, val);
        }
        else if (!strcmp(key, "nickname")) {
            int r = _kv_to_card(card, "nickname", jval);
            if (r) return r;
            record_is_dirty = 1;
        }
        else if (!strcmp(key, "birthday")) {
            int r = _date_to_card(card, "bday", jval);
            if (r) return r;
            record_is_dirty = 1;
        }
        else if (!strcmp(key, "anniversary")) {
            int r = _kv_to_card(card, "anniversary", jval);
            if (r) return r;
            record_is_dirty = 1;
        }
        else if (!strcmp(key, "company")) {
            const char *val = json_string_value(jval);
            if (!val)
                return -1;
            struct vparse_entry *org = _card_multi(card, "org");
            strarray_set(org->v.values, 0, val);
            record_is_dirty = 1;
        }
        else if (!strcmp(key, "department")) {
            const char *val = json_string_value(jval);
            if (!val)
                return -1;
            struct vparse_entry *org = _card_multi(card, "org");
            strarray_set(org->v.values, 1, val);
            record_is_dirty = 1;
        }
        else if (!strcmp(key, "jobTitle")) {
            const char *val = json_string_value(jval);
            if (!val)
                return -1;
            struct vparse_entry *org = _card_multi(card, "org");
            strarray_set(org->v.values, 2, val);
            record_is_dirty = 1;
        }
        else if (!strcmp(key, "emails")) {
            int r = _emails_to_card(card, jval);
            if (r) return r;
            record_is_dirty = 1;
        }
        else if (!strcmp(key, "phones")) {
            int r = _phones_to_card(card, jval);
            if (r) return r;
            record_is_dirty = 1;
        }
        else if (!strcmp(key, "online")) {
            int r = _online_to_card(card, jval);
            if (r) return r;
            record_is_dirty = 1;
        }
        else if (!strcmp(key, "addresses")) {
            int r = _addresses_to_card(card, jval);
            if (r) return r;
            record_is_dirty = 1;
        }
        else if (!strcmp(key, "notes")) {
            int r = _kv_to_card(card, "note", jval);
            if (r) return r;
            record_is_dirty = 1;
        }

        else {
            /* INVALID PARAM */
            return -1; /* XXX - need codes */
        }
    }

    if (name_is_dirty) {
        _make_fn(card);
        record_is_dirty = 1;
    }

    if (!record_is_dirty)
        return 204;  /* no content */

    return 0;
}

static int setContacts(struct jmap_req *req)
{
    struct carddav_db *db = carddav_open_userid(req->userid);
    if (!db) return -1;

    struct mailbox *mailbox = NULL;
    struct mailbox *newmailbox = NULL;

    int r = 0;
    json_t *jcheckState = json_object_get(req->args, "ifInState");
    if (jcheckState) {
        const char *checkState = json_string_value(jcheckState);
        if (!checkState ||strcmp(req->state, checkState)) {
            json_t *item = json_pack("[s, {s:s}, s]",
                                     "error", "type", "stateMismatch",
                                     req->tag);
            json_array_append_new(req->response, item);
            goto done;
        }
    }
    json_t *set = json_pack("{s:s,s:s}",
                            "oldState", req->state,
                            "accountId", req->userid);

    json_t *create = json_object_get(req->args, "create");
    if (create) {
        json_t *created = json_pack("{}");
        json_t *notCreated = json_pack("{}");
        json_t *record;

        const char *key;
        json_t *arg;
        json_object_foreach(create, key, arg) {
            const char *uid = makeuuid();
            strarray_t *flags = strarray_new();
            struct entryattlist *annots = NULL;

            const char *addressbookId = "Default";
            json_t *abookid = json_object_get(arg, "addressbookId");
            if (abookid && json_string_value(abookid)) {
                /* XXX - invalid arguments */
                addressbookId = json_string_value(abookid);
            }
            char *mboxname = mboxname_abook(req->userid, addressbookId);
            json_object_del(arg, "addressbookId");
            addressbookId = NULL;

            struct vparse_card *card = vparse_new_card("VCARD");
            vparse_add_entry(card, NULL, "VERSION", "3.0");
            vparse_add_entry(card, NULL, "UID", uid);

            /* we need to create and append a record */
            if (!mailbox || strcmp(mailbox->name, mboxname)) {
                mailbox_close(&mailbox);
                r = mailbox_open_iwl(mboxname, &mailbox);
                if (r) {
                    free(mboxname);
                    vparse_free_card(card);
                    goto done;
                }
            }

            r = _json_to_card(card, arg, flags, &annots);
            if (r) {
                /* this is just a failure */
                r = 0;
                json_t *err = json_pack("{s:s}", "type", "invalidParameters");
                json_object_set_new(notCreated, key, err);
                strarray_free(flags);
                freeentryatts(annots);
                vparse_free_card(card);
                continue;
            }

            syslog(LOG_NOTICE, "jmap: create contact %s/%s (%s)",
                   req->userid, mboxname, uid);
            r = carddav_store(mailbox, card, NULL,
                              flags, annots, req->userid, req->authstate, ignorequota);
            vparse_free_card(card);
            free(mboxname);
            strarray_free(flags);
            freeentryatts(annots);

            if (r) {
                goto done;
            }

            record = json_pack("{s:s}", "id", uid);
            json_object_set_new(created, key, record);

            /* hash_insert takes ownership of uid here, skanky I know */
            hash_insert(key, xstrdup(uid), req->idmap);
        }

        if (json_object_size(created))
            json_object_set(set, "created", created);
        json_decref(created);
        if (json_object_size(notCreated))
            json_object_set(set, "notCreated", notCreated);
        json_decref(notCreated);
    }

    json_t *update = json_object_get(req->args, "update");
    if (update) {
        json_t *updated = json_pack("[]");
        json_t *notUpdated = json_pack("{}");

        const char *uid;
        json_t *arg;
        json_object_foreach(update, uid, arg) {
            struct carddav_data *cdata = NULL;
            r = carddav_lookup_uid(db, uid, &cdata);
            uint32_t olduid;
            char *resource = NULL;

            if (r || !cdata || !cdata->dav.imap_uid
                  || cdata->kind != CARDDAV_KIND_CONTACT) {
                r = 0;
                json_t *err = json_pack("{s:s}", "type", "notFound");
                json_object_set_new(notUpdated, uid, err);
                continue;
            }
            olduid = cdata->dav.imap_uid;
            resource = xstrdup(cdata->dav.resource);

            if (!mailbox || strcmp(mailbox->name, cdata->dav.mailbox)) {
                mailbox_close(&mailbox);
                r = mailbox_open_iwl(cdata->dav.mailbox, &mailbox);
                if (r) {
                    syslog(LOG_ERR, "IOERROR: failed to open %s",
                           cdata->dav.mailbox);
                    goto done;
                }
            }

            json_t *abookid = json_object_get(arg, "addressbookId");
            if (abookid && json_string_value(abookid)) {
                const char *mboxname =
                    mboxname_abook(req->userid, json_string_value(abookid));
                if (strcmp(mboxname, cdata->dav.mailbox)) {
                    /* move */
                    r = mailbox_open_iwl(mboxname, &newmailbox);
                    if (r) {
                        syslog(LOG_ERR, "IOERROR: failed to open %s", mboxname);
                        goto done;
                    }
                }
                json_object_del(arg, "addressbookId");
            }

            /* XXX - this could definitely be refactored from here and mailbox.c */
            struct buf msg_buf = BUF_INITIALIZER;
            struct vparse_state vparser;
            struct index_record record;

            r = mailbox_find_index_record(mailbox, cdata->dav.imap_uid, &record);
            if (r) goto done;

            /* Load message containing the resource and parse vcard data */
            r = mailbox_map_record(mailbox, &record, &msg_buf);
            if (r) goto done;

            strarray_t *flags =
                mailbox_extract_flags(mailbox, &record, req->userid);
            struct entryattlist *annots =
                mailbox_extract_annots(mailbox, &record);

            memset(&vparser, 0, sizeof(struct vparse_state));
            vparser.base = buf_cstring(&msg_buf) + record.header_size;
            vparse_set_multival(&vparser, "adr");
            vparse_set_multival(&vparser, "org");
            vparse_set_multival(&vparser, "n");
            r = vparse_parse(&vparser, 0);
            buf_free(&msg_buf);
            if (r || !vparser.card || !vparser.card->objects) {
                r = 0;
                json_t *err = json_pack("{s:s}", "type", "parseError");
                json_object_set_new(notUpdated, uid, err);
                vparse_free(&vparser);
                strarray_free(flags);
                freeentryatts(annots);
                mailbox_close(&newmailbox);
                free(resource);
                continue;
            }
            struct vparse_card *card = vparser.card->objects;

            r = _json_to_card(card, arg, flags, &annots);
            if (r == 204) {
                r = 0;
                if (!newmailbox) {
                    /* just bump the modseq
                       if in the same mailbox and no data change */
                    syslog(LOG_NOTICE, "jmap: touch contact %s/%s",
                           req->userid, resource);
                    if (strarray_find_case(flags, "\\Flagged", 0) >= 0)
                        record.system_flags |= FLAG_FLAGGED;
                    else
                        record.system_flags &= ~FLAG_FLAGGED;
                    annotate_state_t *state = NULL;
                    r = mailbox_get_annotate_state(mailbox, record.uid, &state);
                    annotate_state_set_auth(state, 0,
                                            req->userid, req->authstate);
                    if (!r) r = annotate_state_store(state, annots);
                    if (!r) r = mailbox_rewrite_index_record(mailbox, &record);
                    goto finish;
                }
            }
            if (r) {
                /* this is just a failure to create the JSON, not an error */
                r = 0;
                json_t *err = json_pack("{s:s}", "type", "invalidParameters");
                json_object_set_new(notUpdated, uid, err);
                vparse_free(&vparser);
                strarray_free(flags);
                freeentryatts(annots);
                mailbox_close(&newmailbox);
                free(resource);
                continue;
            }

            syslog(LOG_NOTICE, "jmap: update contact %s/%s",
                   req->userid, resource);
            r = carddav_store(newmailbox ? newmailbox : mailbox, card, resource,
                              flags, annots, req->userid, req->authstate, ignorequota);
            if (!r)
                r = carddav_remove(mailbox, olduid, /*isreplace*/!newmailbox);

         finish:
            mailbox_close(&newmailbox);
            strarray_free(flags);
            freeentryatts(annots);

            vparse_free(&vparser);
            free(resource);

            if (r) goto done;

            json_array_append_new(updated, json_string(uid));
        }

        if (json_array_size(updated))
            json_object_set(set, "updated", updated);
        json_decref(updated);
        if (json_object_size(notUpdated))
            json_object_set(set, "notUpdated", notUpdated);
        json_decref(notUpdated);
    }

    json_t *destroy = json_object_get(req->args, "destroy");
    if (destroy) {
        json_t *destroyed = json_pack("[]");
        json_t *notDestroyed = json_pack("{}");

        size_t index;
        for (index = 0; index < json_array_size(destroy); index++) {
            const char *uid = _json_array_get_string(destroy, index);
            if (!uid) {
                json_t *err = json_pack("{s:s}", "type", "invalidArguments");
                json_object_set_new(notDestroyed, uid, err);
                continue;
            }
            struct carddav_data *cdata = NULL;
            uint32_t olduid;
            r = carddav_lookup_uid(db, uid, &cdata);

            if (r || !cdata || !cdata->dav.imap_uid
                  || cdata->kind != CARDDAV_KIND_CONTACT) {
                r = 0;
                json_t *err = json_pack("{s:s}", "type", "notFound");
                json_object_set_new(notDestroyed, uid, err);
                continue;
            }
            olduid = cdata->dav.imap_uid;

            if (!mailbox || strcmp(mailbox->name, cdata->dav.mailbox)) {
                mailbox_close(&mailbox);
                r = mailbox_open_iwl(cdata->dav.mailbox, &mailbox);
                if (r) goto done;
            }

            /* XXX - fricking mboxevent */

            syslog(LOG_NOTICE, "jmap: remove contact %s/%s", req->userid, uid);
            r = carddav_remove(mailbox, olduid, /*isreplace*/0);
            if (r) {
                syslog(LOG_ERR, "IOERROR: setContacts remove failed for %s %u",
                       mailbox->name, olduid);
                goto done;
            }

            json_array_append_new(destroyed, json_string(uid));
        }

        if (json_array_size(destroyed))
            json_object_set(set, "destroyed", destroyed);
        json_decref(destroyed);
        if (json_object_size(notDestroyed))
            json_object_set(set, "notDestroyed", notDestroyed);
        json_decref(notDestroyed);
    }

    /* force modseq to stable */
    if (mailbox) mailbox_unlock_index(mailbox, NULL);

    /* read the modseq again every time, just in case something changed it
     * in our actions */
    struct buf buf = BUF_INITIALIZER;
    char *inboxname = mboxname_user_mbox(req->userid, NULL);
    modseq_t modseq = mboxname_readmodseq(inboxname);
    free(inboxname);
    buf_printf(&buf, "%llu", modseq);
    json_object_set_new(set, "newState", json_string(buf_cstring(&buf)));
    buf_free(&buf);

    json_t *item = json_pack("[]");
    json_array_append_new(item, json_string("contactsSet"));
    json_array_append_new(item, set);
    json_array_append_new(item, json_string(req->tag));

    json_array_append_new(req->response, item);

done:
    mailbox_close(&newmailbox);
    mailbox_close(&mailbox);

    carddav_close(db);
    return r;
}

/*********************** CALENDARS **********************/

/* Helper flags for setCalendarEvents */
#define JMAP_CREATE     (1<<0) /* Current request is a create. */
#define JMAP_UPDATE     (1<<1) /* Current request is an update. */
#define JMAP_DESTROY    (1<<2) /* Current request is a destroy. */
#define JMAP_EXC        (1<<8) /* Current component is a VEVENT exception .*/

typedef struct calevent_rock {
    struct jmap_req *req;    /* The current JMAP request. */
    int flags;               /* Flags indicating the request context. */
    const char *uid;         /* The iCalendar UID of this event. */
    const char *recurid;     /* The LocalDate recurrence id of this event. */
    int isAllDay;            /* This event is a whole-day event. */

    json_t *invalid;         /* A JSON array of any invalid properties. */

    icalcomponent *comp;     /* The current main event of an exception. */
    icalcomponent *oldcomp;  /* The former main event of an exception */

    icaltimetype dtstart;      /* The start of this or the main event. */
    icaltimetype dtend;        /* The end of this or the main event. */
    icaltimezone *tzstart_old; /* The former startTimeZone. */
    icaltimezone *tzstart;     /* The current startTimeZone. */
    icaltimezone *tzend_old;   /* The former endTimeZone. */
    icaltimezone *tzend;       /* The current endTimeZone. */

    icaltimezone **tzs;      /* Timezones required as VTIMEZONEs. */
    size_t n_tzs;            /* The count of timezones. */
    size_t s_tzs;            /* The size of the timezone array. */
} calevent_rock;

/* Update the VEVENT comp with the properties of the JMAP calendar event.
 * The VEVENT must have a VCALENDAR as parent and its timezones might get
 * rewritten. If uid is non-zero, set the VEVENT uid and any recurrence
 * exceptions to this UID. */
static void jmap_calendarevent_to_ical(icalcomponent *comp,
                                       json_t *event,
                                       calevent_rock *rock);

/* Return a non-zero value if uid maps to a special-purpose calendar mailbox,
 * that may not be read or modified by the user. */
static int jmap_calendar_ishidden(const char *uid) {
    /* XXX - brong wrote to "check the specialuse magic on these instead" */
    if (!strcmp(uid, "#calendars")) return 1;
    /* XXX - could also check the schedule-inbox and outbox annotations,
     * instead. But as long as these names  are hardcoded in http_dav... */
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

/* Set is_cal, if the userid's calendar mailbox named mboxname is able to store
 * VEVENTs. Return non-zero on error. */
/* XXX Also make sure to check for this in getCalendarUpdates. Might want to
 * check this also in the other calendar and calendar event methods. */
static int jmap_mboxname_is_calendar(const char *mboxname, const char *userid, int *is_cal)
{
    struct buf attrib = BUF_INITIALIZER;
    static const char *calcompset_annot =
        DAV_ANNOT_NS "<" XML_NS_CALDAV ">supported-calendar-component-set";
    unsigned long types = -1; /* ALL component types by default. */

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
    int rights = httpd_myrights(crock->req->authstate, mbentry->acl);
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

    /* OK, we want this one */
    const char *collection = strrchr(mbentry->name, '.') + 1;

    /* unless it's one of the special names... XXX - check
     * the specialuse magic on these instead */
    if (jmap_calendar_ishidden(collection)) return 0;
    if (!strcmp(collection, "#calendars")) return 0;
    if (!strcmp(collection, "Inbox")) return 0;
    if (!strcmp(collection, "Outbox")) return 0;

    crock->rows++;

    json_t *obj = json_pack("{}");

    json_object_set_new(obj, "id", json_string(collection));

    if (_wantprop(crock->props, "x-href")) {
        _add_xhref(obj, mbentry->name, NULL);
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
        int bool = rights & DACL_RMRSRC;
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

/* Check if ifInState matches the current mailbox state for mailbox type
 * mbtype, if so return zero. Otherwise, append a stateMismatch error to the
 * JMAP response. */
static int jmap_checkstate(struct jmap_req *req, int mbtype) {
    json_t *jIfInState = json_object_get(req->args, "ifInState");
    if (jIfInState) {
        const char *ifInState = json_string_value(jIfInState);
        if (!ifInState) {
            return -1;
        }

        modseq_t clientState = str2uint64(ifInState);

        if (mbtype == MBTYPE_CALENDAR && clientState == req->counters.caldavmodseq) {
            return 0;
        } else if (mbtype == MBTYPE_ADDRESSBOOK && clientState == req->counters.carddavmodseq) {
            return 0;
        } else if (clientState == req->counters.mailmodseq) {
            /* XXX - What about notesmodseq? */
            return 0;
        } else {
            json_t *item = json_pack("[s, {s:s}, s]",
                                     "error", "type", "stateMismatch",
                                     req->tag);
            json_array_append_new(req->response, item);
            return -3;
        }
    }
    return 0;
}

/* Set the state token named name for the JMAP type mbtype in response res.
 * If refresh is true, refresh the current mailbox counters in req
 * If bump is true, update the state of this JMAP type before setting name. */
static int jmap_setstate(struct jmap_req *req,
                         json_t *res,
                         const char *name,
                         int mbtype,
                         int refresh,
                         int bump) {
    struct buf buf = BUF_INITIALIZER;
    char *mboxname;
    int r = 0;
    modseq_t modseq;

    mboxname = mboxname_user_mbox(req->userid, NULL);

    /* Read counters. */
    if (refresh) {
        r = mboxname_read_counters(mboxname, &req->counters);
        if (r) goto done;
    }

    /* Determine current counter by mailbox type. */
    switch (mbtype) {
        case MBTYPE_CALENDAR:
            modseq = req->counters.caldavmodseq;
            break;
        case MBTYPE_ADDRESSBOOK:
            modseq = req->counters.carddavmodseq;
            break;
        default:
            /* XXX - What about notesmodseq? */
            modseq = req->counters.highestmodseq;
    }

    /* Bump current counter. */
    if (bump) {
        modseq = mboxname_nextmodseq(mboxname, modseq, mbtype);
    }

    /* Set newState field. */
    buf_printf(&buf, "%llu", modseq);
    json_object_set_new(res, name, json_string(buf_cstring(&buf)));
    buf_free(&buf);

done:
    free(mboxname);
    return r;
}



/* Read the property named name into dst, formatted according to the json
 * unpack format fmt. If unpacking failed, or name is mandatory and not found
 * in root, append name (prefixed by any non-NULL prefix) to invalid.
 *
 * Return a negative value for a missing or invalid property.
 * Return a positive value if a property was read, zero otherwise. */
static int jmap_readprop_full(json_t *root,
                              const char *prefix,
                              const char *name,
                              int mandatory,
                              json_t *invalid,
                              const char *fmt,
                              void *dst)
{
    json_t *jval = json_object_get(root, name);
    if (!jval && mandatory) {
        json_array_append_new(invalid, json_string(name));
        return -1;
    }
    if (jval) {
        json_error_t err;
        if (json_unpack_ex(jval, &err, 0, fmt, dst)) {
            if (prefix) {
                struct buf buf = BUF_INITIALIZER;
                buf_printf(&buf, "%s.%s", prefix, name);
                json_array_append_new(invalid, json_string(buf_cstring(&buf)));
                buf_free(&buf);
            } else {
                json_array_append_new(invalid, json_string(name));
            }
            return -2;
        }
        return 1;
    }
    return 0;
}

static int jmap_readprop(json_t *root, const char *name, int mandatory,
                         json_t *invalid, const char *fmt, void *dst) {
    return jmap_readprop_full(root, NULL, name, mandatory, invalid, fmt, dst);
}

/* Compare the value of the first occurences of property kind in components
 * a and b. Return 0 if they match or if both do not contain kind. Note that
 * this function does not define an order on property values, so it can't be
 * used for sorting. */
static int jmap_compare_icalprop(icalcomponent *a, icalcomponent *b,
                                 icalproperty_kind kind) {
    icalproperty *pa, *pb;
    icalvalue *va, *vb;

    pa = icalcomponent_get_first_property(a, kind);
    pb = icalcomponent_get_first_property(b, kind);
    if (!pa && !pb) {
        return 0;
    }

    va = icalproperty_get_value(pa);
    vb = icalproperty_get_value(pb);
    enum icalparameter_xliccomparetype cmp = icalvalue_compare(va, vb);
    return cmp != ICAL_XLICCOMPARETYPE_EQUAL;
}

/* Compare the VALARM components in VEVENTs a and b. Return 0 if they both
 * contain the same number of VALARMs with the same TRIGGERS of type duration.
 * Ignore any VALARMs of type DATETIME.
 * Return 0 if all alarms match or both do not define alarms. */
static int jmap_compare_alerts(icalcomponent *a, icalcomponent *b) {
    icalcomponent *a_alarm, *b_alarm;
    icalproperty *prop;
    struct buf buf = BUF_INITIALIZER;
    int a_total = 0;
    int b_total = 0;
    int matches = 0;
    hash_table ha;
    construct_hash_table(&ha, 8, 0);

    /* Collect VALARMs from event a. */
    for (a_alarm = icalcomponent_get_first_component(a, ICAL_VALARM_COMPONENT);
         a_alarm;
         a_alarm = icalcomponent_get_next_component(a, ICAL_VALARM_COMPONENT)) {

        const char *action, *trigger;

        prop = icalcomponent_get_first_property(a_alarm, ICAL_ACTION_PROPERTY);
        if (!prop) continue;
        action = icalvalue_as_ical_string(icalproperty_get_value(prop));

        prop = icalcomponent_get_first_property(a_alarm, ICAL_TRIGGER_PROPERTY);
        if (!prop) continue;
        trigger = icalvalue_as_ical_string(icalproperty_get_value(prop));

        /* Ignore TIME triggers. */
        struct icaltriggertype t = icalproperty_get_trigger(prop);
        if (!icaltime_is_null_time(t.time)) {
            continue;
        }

        buf_printf(&buf, "%s:%s", action, trigger);
        hash_insert(buf_cstring(&buf), a_alarm, &ha);
        buf_reset(&buf);

        a_total++;
    }

    /* Check if the alarms in b match the ones a. */
    for (b_alarm = icalcomponent_get_first_component(b, ICAL_VALARM_COMPONENT);
         b_alarm;
         b_alarm = icalcomponent_get_next_component(b, ICAL_VALARM_COMPONENT)) {

        b_total++;

        const char *action, *trigger;

        prop = icalcomponent_get_first_property(b_alarm, ICAL_ACTION_PROPERTY);
        if (!prop) continue;
        action = icalvalue_as_ical_string(icalproperty_get_value(prop));

        prop = icalcomponent_get_first_property(b_alarm, ICAL_TRIGGER_PROPERTY);
        if (!prop) continue;
        trigger = icalvalue_as_ical_string(icalproperty_get_value(prop));

        /* Ignore TIME triggers. */
        struct icaltriggertype t = icalproperty_get_trigger(prop);
        if (!icaltime_is_null_time(t.time)) {
            continue;
        }

        buf_printf(&buf, "%s:%s", action, trigger);
        icalcomponent *a_alarm = hash_lookup(buf_cstring(&buf), &ha);
        buf_reset(&buf);
        if (!a_alarm) {
            continue;
        }

        matches++;
    }

    buf_free(&buf);
    free_hash_table(&ha, NULL);

    return a_total != b_total || b_total != matches;
}

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
    rights = mbox->acl ? cyrus_acl_myrights(req->authstate, mbox->acl) : 0;
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
        buf_printf(&val, "%s", name);
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
        buf_printf(&val, "%s", color);
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
        buf_printf(&val, "%s", isVisible ? "true" : "false");
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
    int r;

    r = mailbox_open_irl(mboxname, &mbox);
    if (r) {
        syslog(LOG_ERR, "mailbox_open_irl(%s) failed: %s",
                mboxname, error_message(r));
        return r;
    }
    int rights = mbox->acl ? cyrus_acl_myrights(req->authstate, mbox->acl) : 0;

    mailbox_close(&mbox);
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
    if (properties) {
        rock.props = xzmalloc(sizeof(struct hash_table));
        construct_hash_table(rock.props, 1024, 0);
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
    r = jmap_setstate(req, calendars, "state", MBTYPE_CALENDAR, 1 /*refresh*/, 0 /*bump*/);
    if (r) goto done;

    json_incref(rock.array);
    json_object_set_new(calendars, "accountId", json_string(req->userid));
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

static int getCalendarUpdates(struct jmap_req *req)
{
    int r, pe;
    json_t *invalid;
    struct caldav_db *db;
    const char *since = NULL;
    int dofetch = 0;
    struct buf buf = BUF_INITIALIZER;
    modseq_t oldmodseq;

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
    pe = jmap_readprop(req->args, "sinceState", 1 /*mandatory*/, invalid, "s", &since);
    if (pe > 0) {
        oldmodseq = str2uint64(since);
        if (!oldmodseq) {
            json_array_append_new(invalid, json_string("sinceState"));
        }
    }
    jmap_readprop(req->args, "fetchRecords", 0 /*mandatory*/, invalid, "b", &dofetch);
    if (json_array_size(invalid)) {
        json_t *err = json_pack("{s:s, s:o}", "type", "invalidArguments", "arguments", invalid);
        json_array_append_new(req->response, json_pack("[s,o,s]", "error", err, req->tag));
        r = 0;
        goto done;
    }
    json_decref(invalid);

    if (oldmodseq != req->counters.caldavmodseq) {
        /* XXX - This is where we would report calendar changes. But since it's
         * not clear yet, how to report purged mailboxes as removed, let's force
         * the client to flush its cache. */
        json_t *err = json_pack("{s:s}", "type", "cannotCalculateChanges");
        json_array_append_new(req->response, json_pack("[s,o,s]", "error", err, req->tag));
    } else {
        /* Create response without any updates. */
        json_t *eventUpdates = json_pack("{}");
        json_object_set_new(eventUpdates, "accountId", json_string(req->userid));
        json_object_set_new(eventUpdates, "oldState", json_string(since));
        json_object_set_new(eventUpdates, "newState", json_string(since));

        json_object_set_new(eventUpdates, "hasMoreUpdates", json_false());
        json_object_set_new(eventUpdates, "changed", json_pack("[]"));
        json_object_set_new(eventUpdates, "removed", json_pack("[]"));

        json_t *item = json_pack("[]");
        json_array_append_new(item, json_string("calendarUpdates"));
        json_array_append_new(item, eventUpdates);
        json_array_append_new(item, json_string(req->tag));
        json_array_append_new(req->response, item);
    }

  done:
    buf_free(&buf);
    if (db) caldav_close(db);
    return r;
}

static int setCalendars(struct jmap_req *req)
{
    int r = jmap_checkstate(req, MBTYPE_CALENDAR);
    if (r) return 0;

    json_t *set = json_pack("{s:s}", "accountId", req->userid);
    r = jmap_setstate(req, set, "oldState", MBTYPE_CALENDAR, 0 /*refresh*/, 0 /*bump*/);
    if (r) goto done;

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
            pe = jmap_readprop(arg, "name", 1,  invalid, "s", &name);
            if (pe > 0 && strnlen(name, 256) == 256) {
                json_array_append_new(invalid, json_string("name"));
            }

            /* XXX - wait for CalConnect/Neil feedback on how to validate */
            jmap_readprop(arg, "color", 1,  invalid, "s", &color);

            pe = jmap_readprop(arg, "sortOrder", 1,  invalid, "i", &sortOrder);
            if (pe > 0 && sortOrder < 0) {
                json_array_append_new(invalid, json_string("sortOrder"));
            }
            pe = jmap_readprop(arg, "isVisible", 1,  invalid, "b", &isVisible);
            if (pe > 0 && !isVisible) {
                json_array_append_new(invalid, json_string("isVisible"));
            }
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
                int rr = mboxlist_delete(mboxname, 1 /* force */);
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
            hash_insert(key, uid, req->idmap);
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
        json_t *updated = json_pack("[]");
        json_t *notUpdated = json_pack("{}");

        const char *uid;
        json_t *arg;
        json_object_foreach(update, uid, arg) {

            /* Validate uid */
            if (!strlen(uid)) {
                json_t *err= json_pack("{s:s}", "type", "invalidArguments");
                json_object_set_new(notUpdated, uid, err);
                continue;
            }
            if (*uid == '#') {
                const char *t = hash_lookup(uid, req->idmap);
                if (!t) {
                    json_t *err = json_pack("{s:s}", "type", "invalidArguments");
                    json_object_set_new(notUpdated, uid, err);
                    continue;
                }
                uid = t;
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
            pe = jmap_readprop(arg, "name", 0,  invalid, "s", &name);
            if (pe > 0 && strnlen(name, 256) == 256) {
                json_array_append_new(invalid, json_string("name"));
            }
            pe = jmap_readprop(arg, "color", 0,  invalid, "s", &color);
            if (pe > 0) {
                /* XXX - wait for CalConnect/Neil feedback on how to validate */
            }
            pe = jmap_readprop(arg, "sortOrder", 0,  invalid, "i", &sortOrder);
            if (pe > 0 && sortOrder < 0) {
                json_array_append_new(invalid, json_string("sortOrder"));
            }
            jmap_readprop(arg, "isVisible", 0,  invalid, "b", &isVisible);

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
                continue;
            }
            else if (r == IMAP_PERMISSION_DENIED) {
                json_t *err = json_pack("{s:s}", "type", "accountReadOnly");
                json_object_set_new(notUpdated, uid, err);
                continue;
            }

            /* Report calendar as updated. */
            json_array_append_new(updated, json_string(uid));
        }

        if (json_array_size(updated)) {
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

            /* Validate uid. JMAP destroy does not allow reference uids. */
            const char *uid = json_string_value(juid);
            if (!strlen(uid) || *uid == '#' || jmap_calendar_ishidden(uid)) {
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
                continue;
            } else if (r == IMAP_PERMISSION_DENIED) {
                json_t *err = json_pack("{s:s}", "type", "accountReadOnly");
                json_object_set_new(notDestroyed, uid, err);
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
    r = jmap_setstate(req, set, "newState", MBTYPE_CALENDAR,
            1 /*refresh*/,
            json_object_get(set, "created") ||
            json_object_get(set, "updated") ||
            json_object_get(set, "destroyed"));
    if (r) goto done;

    json_incref(set);
    json_t *item = json_pack("[]");
    json_array_append_new(item, json_string("calendarsSet"));
    json_array_append_new(item, set);
    json_array_append_new(item, json_string(req->tag));
    json_array_append_new(req->response, item);

done:
    json_decref(set);
    return r;
}

/* Convert time to a RFC3339 formatted localdate string. Return the number
 * of bytes written to buf sized size, excluding the terminating null byte. */
static int jmap_timet_to_localdate(time_t t, char* buf, size_t size) {
    int n = time_to_rfc3339(t, buf, size);
    if (n && buf[n-1] == 'Z') {
        buf[n-1] = '\0';
        n--;
    }
    return n;
}

/* Convert the JMAP datetime in buf to tm time. Return 0 on success. */
static int jmap_date_to_tm(const char *buf, struct tm *tm) {
    /* Initialize tm. We don't know about daylight savings time here. */
    memset(tm, 0, sizeof(struct tm));
    tm->tm_isdst = -1;

    /* Parse UTC date. */
    const char *p = strptime(buf, "%Y-%m-%dT%H:%M:%SZ", tm);
    if (!p || *p) {
        return -1;
    }
    return 0;
}

/* Convert the JMAP datetime formatted buf into ical datetime dt.
 * Return 0 on success. */
static int jmap_date_to_icaltime(const char *buf,
                                 icaltimetype *dt,
                                 int isAllDay) {
    struct tm tm;
    int r;
    icaltimetype tmp;

    r = jmap_date_to_tm(buf, &tm);
    if (r) return r;

    if (isAllDay && (tm.tm_sec || tm.tm_min || tm.tm_hour)) {
        return 1;
    }

    tmp = icaltime_from_timet_with_zone(mktime(&tm), 0, icaltimezone_get_utc_timezone());
    tmp.is_date = isAllDay;
    *dt = tmp;
    return 0;
}

/* Convert the JMAP local datetime in buf to tm time. Return 0 on success. */
static int jmap_localdate_to_tm(const char *buf, struct tm *tm) {
    /* Initialize tm. We don't know about daylight savings time here. */
    memset(tm, 0, sizeof(struct tm));
    tm->tm_isdst = -1;

    /* Parse LocalDate. */
    const char *p = strptime(buf, "%Y-%m-%dT%H:%M:%S", tm);
    if (!p || *p) {
        return -1;
    }
    return 0;
}

/* Convert the JMAP local datetime formatted buf into ical datetime dt
 * using timezone tz. Return 0 on success. */
static int jmap_localdate_to_icaltime(const char *buf,
                                      icaltimetype *dt,
                                      icaltimezone *tz,
                                      int isAllDay) {
    struct tm tm;
    int r;
    char *s = NULL;
    icaltimetype tmp;

    r = jmap_localdate_to_tm(buf, &tm);
    if (r) return r;

    if (isAllDay && (tm.tm_sec || tm.tm_min || tm.tm_hour)) {
        return 1;
    }

    /* Can't use icaltime_from_timet_with_zone since it tries to convert
     * t from UTC into tz. Let's feed ical a DATETIME string, instead. */
    s = xzmalloc(16);
    strftime(s, 16, "%Y%m%dT%H%M%S", &tm);
    tmp = icaltime_from_string(s);
    free(s);
    if (icaltime_is_null_time(tmp)) {
        return -1;
    }
    tmp.zone = tz;
    tmp.is_date = isAllDay;
    *dt = tmp;
    return 0;
}

/* Convert icaltime to a RFC3339 formatted localdate string. The returned
 * string is owned by the caller. Return NULL on error. */
static char* jmap_icaltime_to_localdate_r(icaltimetype icaltime) {
    char *s;
    time_t t;

    s = xmalloc(RFC3339_DATETIME_MAX);
    t = icaltime_as_timet(icaltime);
    if (!jmap_timet_to_localdate(t, s, RFC3339_DATETIME_MAX)) {
        return NULL;
    }
    return s;
}

/* Compare int in ascending order. */
static int jmap_intcmp(const void *aa, const void *bb)
{
    const int *a = aa, *b = bb;
    return (*a < *b) ? -1 : (*a > *b);
}

/* Compare time_t in ascending order. */
static int jmap_timetcmp(const void *aa, const void *bb)
{
    const time_t *a = aa, *b = bb;
    return (*a < *b) ? -1 : (*a > *b);
}

/* Return the identity of i. This is a helper for recur_byX. */
static int jmap_intident(int i) {
    return i;
}

/*  Convert libicals internal by_day encoding to JMAP byday. */
static int jmap_icalbyday_to_byday(int i) {
    int w = icalrecurrencetype_day_position(i);
    int d = icalrecurrencetype_day_day_of_week(i);
    if (d) {
        /* We could encounter libical's special ANY day here. But they don't
         * care about it in the pos*7+dow computation. See more in the inline
         * doc for icalrecurrencetype_day_day_of_week in icalrecur.c */
        d--;
    }
    return d + 7*w;
}

/*  Convert libicals internal by_month encoding to JMAP byday. */
static int jmap_icalbymonth_to_bymonth(int i) {
    return i-1;
}

/* Convert at most nmemb entries in the ical recurrence byDay/Month/etc array
 * named byX using conv. Return a new JSON array, sorted in ascending order. */
static json_t* jmap_recurrence_byX_from_ical(short byX[], size_t nmemb, int (*conv)(int)) {
    json_t *jbd = json_pack("[]");

    size_t i;
    int tmp[nmemb];
    for (i = 0; i < nmemb && byX[i] != ICAL_RECURRENCE_ARRAY_MAX; i++) {
        tmp[i] = conv(byX[i]);
    }

    size_t n = i;
    qsort(tmp, n, sizeof(int), jmap_intcmp);
    for (i = 0; i < n; i++) {
        json_array_append_new(jbd, json_pack("i", tmp[i]));
    }

    return jbd;
}

/* Convert the ical recurrence recur to a JMAP structure encoded in JSON using
 * timezone id tzid for localdate conversions. */
static json_t* jmap_recurrence_from_ical(struct icalrecurrencetype recur, const char *tzid) {
    json_t *jrecur = json_pack("{}");

    /* frequency */
    /* XXX - icalrecur depends on a recent change to libical. Might need to
     * add support for this to Cyrus imap/ical_support.h for backward
     * compatibility. */
    char *s = xstrdup(icalrecur_freq_to_string(recur.freq));
    char *p = s; for ( ; *p; ++p) *p = tolower(*p);
    json_object_set_new(jrecur, "frequency", json_string(s));
    free(s);

    if (recur.interval > 1) {
        json_object_set_new(jrecur, "interval", json_pack("i", recur.interval));
    }

    /* firstDayOfWeek */
    short day = recur.week_start - 1;
    if (day >= 0 && day != 1) {
        json_object_set_new(jrecur, "firstDayOfWeek", json_pack("i", day));
    }

    if (recur.by_day[0] != ICAL_RECURRENCE_ARRAY_MAX) {
        json_object_set_new(jrecur, "byDay",
                jmap_recurrence_byX_from_ical(recur.by_day,
                    ICAL_BY_DAY_SIZE, &jmap_icalbyday_to_byday));
    }
    if (recur.by_month_day[0] != ICAL_RECURRENCE_ARRAY_MAX) {
        json_object_set_new(jrecur, "byDate",
                jmap_recurrence_byX_from_ical(recur.by_month_day,
                    ICAL_BY_MONTHDAY_SIZE, &jmap_intident));
    }
    if (recur.by_month[0] != ICAL_RECURRENCE_ARRAY_MAX) {
        json_object_set_new(jrecur, "byMonth",
                jmap_recurrence_byX_from_ical(recur.by_month,
                    ICAL_BY_MONTH_SIZE, &jmap_icalbymonth_to_bymonth));
    }
    if (recur.by_year_day[0] != ICAL_RECURRENCE_ARRAY_MAX) {
        json_object_set_new(jrecur, "byYearDay",
                jmap_recurrence_byX_from_ical(recur.by_year_day,
                    ICAL_BY_YEARDAY_SIZE, &jmap_intident));
    }
    if (recur.by_month[0] != ICAL_RECURRENCE_ARRAY_MAX) {
        json_object_set_new(jrecur, "byWeekNo",
                jmap_recurrence_byX_from_ical(recur.by_month,
                    ICAL_BY_MONTH_SIZE, &jmap_intident));
    }
    if (recur.by_hour[0] != ICAL_RECURRENCE_ARRAY_MAX) {
        json_object_set_new(jrecur, "byHour",
                jmap_recurrence_byX_from_ical(recur.by_hour,
                    ICAL_BY_HOUR_SIZE, &jmap_intident));
    }
    if (recur.by_minute[0] != ICAL_RECURRENCE_ARRAY_MAX) {
        json_object_set_new(jrecur, "byMinute",
                jmap_recurrence_byX_from_ical(recur.by_minute,
                    ICAL_BY_MINUTE_SIZE, &jmap_intident));
    }
    if (recur.by_second[0] != ICAL_RECURRENCE_ARRAY_MAX) {
        json_object_set_new(jrecur, "bySecond",
                jmap_recurrence_byX_from_ical(recur.by_second,
                    ICAL_BY_SECOND_SIZE, &jmap_intident));
    }
    if (recur.by_set_pos[0] != ICAL_RECURRENCE_ARRAY_MAX) {
        json_object_set_new(jrecur, "bySetPosition",
                jmap_recurrence_byX_from_ical(recur.by_set_pos,
                    ICAL_BY_SETPOS_SIZE, &jmap_intident));
    }

    if (recur.count != 0) {
        /* Recur count takes precedence over until. */
        json_object_set_new(jrecur, "count", json_pack("i", recur.count));
    } else if (!icaltime_is_null_time(recur.until)) {
        icaltimezone *tz = icaltimezone_get_builtin_timezone(tzid);
        icaltimetype dtloc = icaltime_convert_to_zone(recur.until, tz);
        char *until = jmap_icaltime_to_localdate_r(dtloc);
        json_object_set_new(jrecur, "until", json_string(until));
        free(until);
    }

    return jrecur;
}

/* Convert a VEVENT ical component to CalendarEvent attachments. */
static json_t* jmap_attachments_from_ical(icalcomponent *comp) {
    icalproperty* prop;
    json_t *ret = json_pack("[]");

    for (prop = icalcomponent_get_first_property(comp, ICAL_ATTACH_PROPERTY);
         prop;
         prop = icalcomponent_get_next_property(comp, ICAL_ATTACH_PROPERTY)) {

        icalattach *attach = icalproperty_get_attach(prop);
        icalparameter *param = NULL;
        json_t *file = NULL;

        /* Ignore ATTACH properties with value BINARY. */
        if (!attach || !icalattach_get_is_url(attach)) {
            continue;
        }

        /* blobId */
        /* XXX Bron: for now the blobId is the attachment URL. */
        const char *url = icalattach_get_url(attach);
        if (!url || !strlen(url)) {
            continue;
        }

        file = json_pack("{s:s}", "blobId", url);

        /* type */
        param = icalproperty_get_first_parameter(prop, ICAL_FMTTYPE_PARAMETER);
        if (param) {
            const char *type = icalparameter_get_fmttype(param);
            json_object_set_new(file, "type",
                    type && strlen(type) ? json_string(type) : json_null());
        }

        /* name */
        /* XXX ALways null. */
        json_object_set_new(file, "name", json_null());

        /* size */
        json_int_t size = -1;
        param = icalproperty_get_first_parameter(prop, ICAL_SIZE_PARAMETER);
        if (param) {
            const char *s = icalparameter_get_size(param);
            if (s) {
                char *ptr;
                size = strtol(s, &ptr, 10);
                json_object_set_new(file, "size",
                        ptr && *ptr == '\0' ? json_integer(size) : json_null());
            }
        }

        json_array_append_new(ret, file);
    }

    if (!json_array_size(ret)) {
        json_decref(ret);
        ret = json_null();
    }

    return ret;
}


/* Convert a VEVENT ical component to CalendarEvent inclusions. */
static json_t* jmap_inclusions_from_ical(icalcomponent *comp) {
    icalproperty* prop;
    size_t sincl = 8;
    size_t nincl = 0;
    time_t *incl = xmalloc(sincl * sizeof(time_t));
    json_t *ret;
    size_t i;
    char timebuf[RFC3339_DATETIME_MAX];

    /* Collect all RDATE occurrences as datetimes into incl. */
    for(prop = icalcomponent_get_first_property(comp, ICAL_RDATE_PROPERTY);
        prop;
        prop = icalcomponent_get_next_property(comp, ICAL_RDATE_PROPERTY)) {

        struct icaldatetimeperiodtype rdate;
        time_t t;

        rdate = icalproperty_get_rdate(prop);
        if (!icalperiodtype_is_null_period(rdate.period)) {
            continue;
        }
        if (icaltime_is_null_time(rdate.time)) {
            continue;
        }
        t = icaltime_as_timet_with_zone(rdate.time, rdate.time.zone ?
                rdate.time.zone : icaltimezone_get_utc_timezone());
        if (nincl == sincl) {
            sincl <<= 1;
            incl = xrealloc(incl, sincl * sizeof(time_t));
        }
        incl[nincl++] = t;
    }
    if (!nincl) {
        ret = json_null();
        goto done;
    }

    /* Sort ascending. */
    qsort(incl, nincl, sizeof(time_t), &jmap_timetcmp);

    /* Convert incl to JMAP LocalDate. */
    ret = json_pack("[]");
    for (i = 0; i < nincl; ++i) {
        int n = jmap_timet_to_localdate(incl[i], timebuf, RFC3339_DATETIME_MAX);
        if (!n) continue;
        json_array_append_new(ret, json_string(timebuf));
    }

done:
    free(incl);
    return ret;
}

/* Convert the VALARMS in the VEVENT comp to CalendarEvent alerts. */
static json_t* jmap_alerts_from_ical(icalcomponent *comp) {
    json_t* ret = json_pack("[]");
    icalcomponent* alarm;

    for (alarm = icalcomponent_get_first_component(comp, ICAL_VALARM_COMPONENT);
         alarm;
         alarm = icalcomponent_get_next_component(comp, ICAL_VALARM_COMPONENT)) {

        icalproperty* prop;
        icalvalue* val;
        const char *type;
        struct icaltriggertype trigger;
        json_int_t diff;

        /* type */
        prop = icalcomponent_get_first_property(alarm, ICAL_ACTION_PROPERTY);
        if (!prop) {
            continue;
        }
        val = icalproperty_get_value(prop);
        if (!val) {
            continue;
        }
        enum icalproperty_action action = icalvalue_get_action(val);
        if (action == ICAL_ACTION_EMAIL) {
            type = "email";
        } else {
            type = "alert";
        }

        /* minutesBefore */
        prop = icalcomponent_get_first_property(alarm, ICAL_TRIGGER_PROPERTY);
        if (!prop) {
            continue;
        }
        trigger = icalproperty_get_trigger(prop);
        if (!icaldurationtype_is_null_duration(trigger.duration)) {
            diff = icaldurationtype_as_int(trigger.duration) / -60;
        } else {
            icaltimetype tgtime = icaltime_convert_to_zone(trigger.time,
                    icaltimezone_get_utc_timezone());
            time_t tg = icaltime_as_timet(tgtime);
            icaltimetype dtstart = icaltime_convert_to_zone(
                    icalcomponent_get_dtstart(comp),
                    icaltimezone_get_utc_timezone());
            time_t dt = icaltime_as_timet(dtstart);
            diff = difftime(dt, tg) / (json_int_t) 60;
        }

        json_array_append_new(ret, json_pack("{s:s, s:i}",
                    "type", type, "minutesBefore", diff));
    }

    if (!json_array_size(ret)) {
        json_decref(ret);
        ret = json_null();
    }
    return ret;
}

/* Set isyou if userid matches the user looked up by caladdr. Return 0 on
 * success or a Cyrus error on failure. */
static int jmap_isyou(const char *caladdr, const char *userid, short *isyou) {
    struct sched_param sparam;

    if (userid) {
        sparam.userid = NULL;
        int r = caladdress_lookup(caladdr, &sparam, userid);
        if (r && r != HTTP_NOT_FOUND) {
            syslog(LOG_ERR, "caladdress_lookup: failed to lookup caladdr %s: %s",
                    caladdr, error_message(r));
            return r;
        }
        if (r != HTTP_NOT_FOUND && sparam.userid) {
            *isyou = !strcmp(userid, sparam.userid) ;
        } else {
            *isyou = 0;
        }
        sched_param_free(&sparam);
    }
    return 0;
}

/* Convert the ical ORGANIZER/ATTENDEEs in comp to CalendarEvent
 * participants, and store them in the pointers pointed to by
 * organizer and attendees, or NULL. The participant isYou field
 * is set, if this participant's caladdress belongs to userid. */
static void jmap_participants_from_ical(icalcomponent *comp,
                                        json_t **organizer,
                                        json_t **attendees,
                                        const char *userid) {
    icalproperty *prop;
    icalparameter *param;
    json_t *org = NULL;
    json_t *atts = NULL;
    const char *email;
    short isYou;
    struct hash_table *hatts = NULL;
    int r;

    /* Lookup ORGANIZER. */
    prop = icalcomponent_get_first_property(comp, ICAL_ORGANIZER_PROPERTY);
    if (!prop) {
        goto done;
    }
    org = json_pack("{}");

    /* name */
    param = icalproperty_get_first_parameter(prop, ICAL_CN_PARAMETER);
    json_object_set_new(org, "name",
            param ? json_string(icalparameter_get_cn(param)) : json_null());

    /* email */
    email = icalproperty_get_value_as_string(prop);
    if (!strncmp(email, "mailto:", 7)) email += 7;
    json_object_set_new(org, "email", json_string(email));

    /* isYou */
    r = jmap_isyou(email, userid, &isYou);
    if (r) goto done;
    json_object_set_new(org, "isYou", json_boolean(isYou));

    /* Collect all attendees in a map so we can lookup delegates. */
    hatts = xzmalloc(sizeof(struct hash_table));
    construct_hash_table(hatts, 32, 0);

    for (prop = icalcomponent_get_first_property(comp, ICAL_ATTENDEE_PROPERTY);
         prop;
         prop = icalcomponent_get_next_property(comp, ICAL_ATTENDEE_PROPERTY)) {

        hash_insert(icalproperty_get_value_as_string(prop), prop, hatts);
    }
    if (!hash_numrecords(hatts)) {
        goto done;
    }

    /* Convert all ATTENDEES. */
    atts = json_pack("[]");
    for (prop = icalcomponent_get_first_property(comp, ICAL_ATTENDEE_PROPERTY);
         prop;
         prop = icalcomponent_get_next_property(comp, ICAL_ATTENDEE_PROPERTY)) {

        json_t *att = json_pack("{}");

        /* name */
        param = icalproperty_get_first_parameter(prop, ICAL_CN_PARAMETER);
        json_object_set_new(att, "name",
                param ? json_string(icalparameter_get_cn(param)) : json_null());

        /* email */
        email = icalproperty_get_value_as_string(prop);
        if (!strncmp(email, "mailto:", 7)) email += 7;
        json_object_set_new(att, "email", json_string(email));

        /* rsvp */
        const char *rsvp = NULL;
        short depth = 0;
        while (!rsvp) {
            param = icalproperty_get_first_parameter(prop, ICAL_PARTSTAT_PARAMETER);
            icalparameter_partstat pst = icalparameter_get_partstat(param);
            switch (pst) {
                case ICAL_PARTSTAT_ACCEPTED:
                    rsvp = "yes";
                    break;
                case ICAL_PARTSTAT_DECLINED:
                    rsvp = "no";
                    break;
                case ICAL_PARTSTAT_TENTATIVE:
                    rsvp = "maybe";
                    break;
                case ICAL_PARTSTAT_DELEGATED:
                    param = icalproperty_get_first_parameter(prop, ICAL_DELEGATEDTO_PARAMETER);
                    if (param) {
                        const char *to = icalparameter_get_delegatedto(param);
                        prop = hash_lookup(to, hatts);
                        if (prop) {
                            /* Determine PARTSTAT from delegate. */
                            if (++depth > 64) {
                                /* This is a pathological case: libical does
                                 * not check for inifite DELEGATE chains, so we
                                 * make sure not to fall in an endless loop. */
                                syslog(LOG_ERR, "delegates exceed maximum recursion depth, ignoring rsvp");
                                rsvp = "";
                            }
                            continue;
                        }
                    }
                    /* fallthrough */
                default:
                    rsvp = "";
            }
        }
        json_object_set_new(att, "rsvp", json_string(rsvp));

        /* isYou */
        r = jmap_isyou(email, userid, &isYou);
        if (r) goto done;
        json_object_set_new(att, "isYou", json_boolean(isYou));

        if (json_object_size(att)) {
            json_array_append(atts, att);
        }
        json_decref(att);
    }

done:
    if (hatts) {
        free_hash_table(hatts, NULL);
        free(hatts);
    }
    if (org && atts) {
        *organizer = org;
        *attendees = atts;
        json_incref(org);
        json_incref(atts);
    } else {
        *organizer = json_null();
        *attendees = json_null();
    }
    if (org) json_decref(org);
    if (atts) json_decref(atts);
}

/* Determine the Olson TZID, if any, of the ical property prop. */
static const char *jmap_tzid_from_icalprop(icalproperty *prop, int guess) {
    const char *tzid = NULL;
    icalparameter *param = NULL;

    if (prop) param = icalproperty_get_first_parameter(prop, ICAL_TZID_PARAMETER);
    if (param) tzid = icalparameter_get_tzid(param);
    /* Check if the tzid already corresponds to an Olson name. */
    if (tzid) {
        icaltimezone *tz = icaltimezone_get_builtin_timezone(tzid);
        if (!tz && guess) {
            /* Try to guess the timezone. */
            icalvalue *val = icalproperty_get_value(prop);
            icaltimetype dt = icalvalue_get_datetime(val);
            tzid = dt.zone ? icaltimezone_get_location((icaltimezone*) dt.zone) : NULL;
            tzid = tzid && icaltimezone_get_builtin_timezone(tzid) ? tzid : NULL;
        }
    }
    return tzid;
}

/* Determine the Olson TZID, if any, of the ical property kind in component comp. */
static const char *jmap_tzid_from_ical(icalcomponent *comp,
                                       icalproperty_kind kind) {
    icalproperty *prop = icalcomponent_get_first_property(comp, kind);
    if (!prop) {
        return NULL;
    }
    return jmap_tzid_from_icalprop(prop, 1/*guess*/);
}

/* Convert the libical VEVENT comp to a CalendarEvent, excluding the
 * exceptions property. If parent is not NULL, treat comp as a VEVENT
 * exception and only convert properties that are valid for exceptions.
 * If userid is not NULL it will be used to identify participants.
 * In any case, only convert the properties named in props. */
static json_t* jmap_calendarevent_from_ical(icalcomponent *comp,
                                            icalcomponent *parent,
                                            struct hash_table *props,
                                            const char *userid) {
    icalproperty* prop;
    json_t *obj;
    short exc = parent != NULL;

    obj = json_pack("{}");

    /* Always determine isAllDay to set start, end and timezone fields. */
    int isAllDay = icaltime_is_date(icalcomponent_get_dtstart(comp));
    if (_wantprop(props, "isAllDay") && !exc) {
        json_object_set_new(obj, "isAllDay", json_boolean(isAllDay));
    }

    /* Convert properties. */

    /* summary */
    if (_wantprop(props, "summary")) {
        prop = icalcomponent_get_first_property(comp, ICAL_SUMMARY_PROPERTY);
        if (prop && exc && !jmap_compare_icalprop(comp, parent, ICAL_SUMMARY_PROPERTY)) {
            /* Don't return the exception SUMMARY if it matches the main event. */
            prop = NULL;
        }
        if (prop || !exc) {
            json_object_set_new(obj, "summary",
                    prop ? json_string(icalproperty_get_value_as_string(prop)) : json_string(""));
        }
    }

    /* description */
    if (_wantprop(props, "description")) {
        prop = icalcomponent_get_first_property(comp, ICAL_DESCRIPTION_PROPERTY);
        if (prop && exc && !jmap_compare_icalprop(comp, parent, ICAL_DESCRIPTION_PROPERTY)) {
            /* Don't return the exception DESCRIPTION if it matches the main event. */
            prop = NULL;
        }
        if (prop || !exc) {
            json_object_set_new(obj, "description",
                    prop ? json_string(icalproperty_get_value_as_string(prop)) : json_string(""));
        }
    }

    /* location */
    if (_wantprop(props, "location")) {
        prop = icalcomponent_get_first_property(comp, ICAL_LOCATION_PROPERTY);
        if (prop && exc && !jmap_compare_icalprop(comp, parent, ICAL_LOCATION_PROPERTY)) {
            /* Don't return the exception LOCATION if it matches the main event. */
            prop = NULL;
        }
        if (prop || !exc) {
            json_object_set_new(obj, "location",
                    prop ? json_string(icalproperty_get_value_as_string(prop)) : json_string(""));
        }
    }

    /* showAsFree */
    if (_wantprop(props, "showAsFree")) {
        prop = icalcomponent_get_first_property(comp, ICAL_TRANSP_PROPERTY);
        if (prop && exc && !jmap_compare_icalprop(comp, parent, ICAL_TRANSP_PROPERTY)) {
            /* Don't return the exception TRANSP if it matches the main event. */
            prop = NULL;
        }
        if (prop || !exc) {
            json_object_set_new(obj, "showAsFree",
                    json_boolean(prop &&
                        !strcmp(icalproperty_get_value_as_string(prop), "TRANSPARENT")));
        }
    }

    /* start */
    if (_wantprop(props, "start")) {
        struct icaltimetype dt = icalcomponent_get_dtstart(comp);
        char *s = jmap_icaltime_to_localdate_r(dt);
        json_object_set_new(obj, "start", json_string(s));
        free(s);
    }

    /* end */
    if (_wantprop(props, "end")) {
        struct icaltimetype dt = icalcomponent_get_dtend(comp);
        if (icaltime_is_null_time(dt) && !exc) {
            dt = icalcomponent_get_dtstart(comp);
        }
        if (!icaltime_is_null_time(dt)) {
            char *s = jmap_icaltime_to_localdate_r(dt);
            json_object_set_new(obj, "end", json_string(s));
            free(s);
        }
    }

    /* Always determine the event's start timezone. */
    const char *tzidstart = jmap_tzid_from_ical(comp, ICAL_DTSTART_PROPERTY);

    /* startTimeZone */
    if (_wantprop(props, "startTimeZone")) {
        json_object_set_new(obj, "startTimeZone",
                tzidstart && !isAllDay ? json_string(tzidstart) : json_null());
    }

    /* endTimeZone */
    if (_wantprop(props, "endTimeZone")) {
        const char *tzidend = jmap_tzid_from_ical(comp, ICAL_DTEND_PROPERTY);
        if (!tzidend) {
            tzidend = tzidstart;
        }
        json_object_set_new(obj, "endTimeZone",
                tzidend && !isAllDay ? json_string(tzidend) : json_null());
    }

    /* recurrence */
    if (_wantprop(props, "recurrence") && !exc) {
        json_t *recur = NULL;
        prop = icalcomponent_get_first_property(comp, ICAL_RRULE_PROPERTY);
        if (prop) {
            recur = jmap_recurrence_from_ical(icalproperty_get_rrule(prop), tzidstart);
        }
        json_object_set_new(obj, "recurrence", recur ? recur : json_null());
    }

    /* inclusions */
    if (_wantprop(props, "inclusions") && !exc) {
        json_object_set_new(obj, "inclusions", jmap_inclusions_from_ical(comp));
    }

    /* Do not convert exceptions. */

    /* alerts */
    if (_wantprop(props, "alerts") && (!exc || jmap_compare_alerts(comp, parent))) {
        json_t *alerts = jmap_alerts_from_ical(comp);
        if (alerts != json_null() || !exc) {
            json_object_set_new(obj, "alerts", alerts);
        }
    }

    /* organizer and attendees */
    if (_wantprop(props, "organizer") || _wantprop(props, "attendees")) {
        json_t *organizer, *attendees;
        jmap_participants_from_ical(comp, &organizer, &attendees, userid);
        if (organizer && _wantprop(props, "organizer") && (organizer != json_null() || !exc)) {
            json_object_set_new(obj, "organizer", organizer);
        }
        if (attendees && _wantprop(props, "attendees") && (attendees != json_null() || !exc)) {
            json_object_set_new(obj, "attendees", attendees);
        }
    }

    /* attachments */
    if (_wantprop(props, "attachments") && !exc) {
        json_object_set_new(obj, "attachments", jmap_attachments_from_ical(comp));
    }

    return obj;
}

static int getcalendarevents_cb(void *rock, struct caldav_data *cdata)
{
    struct calendars_rock *crock = (struct calendars_rock *)rock;
    struct index_record record;
    int r = 0;
    icalcomponent* ical = NULL;
    icalcomponent* comp;
    icalproperty* prop;
    const char *userid = crock->req->userid;
    json_t *obj;

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
    ical = record_to_ical(crock->mailbox, &record);
    if (!ical) {
        syslog(LOG_ERR, "record_to_ical failed for record %u:%s",
                cdata->dav.imap_uid, crock->mailbox->name);
        r = IMAP_INTERNAL;
        goto done;
    }

    /* Locate the main VEVENT. */
    for (comp = icalcomponent_get_first_component(ical, ICAL_VEVENT_COMPONENT);
         comp;
         comp = icalcomponent_get_next_component(ical, ICAL_VEVENT_COMPONENT)) {
        if (!icalcomponent_get_first_property(comp, ICAL_RECURRENCEID_PROPERTY)) {
            break;
        }
    }
    if (!comp) {
        syslog(LOG_ERR, "no VEVENT in record %u:%s",
                cdata->dav.imap_uid, crock->mailbox->name);
        r = IMAP_INTERNAL;
        goto done;
    }

    /* Convert main VEVENT to JMAP. */
    obj = jmap_calendarevent_from_ical(comp, NULL, crock->props, userid);
    if (!obj) goto done;
    json_object_set_new(obj, "id", json_string(cdata->ical_uid));

    /* Add optional exceptions. */
    if (_wantprop(crock->props, "exceptions")) {
        json_t* excobj = json_pack("{}");
        icalcomponent *excomp;

        /* Add all EXDATEs as null value. */
        for (prop = icalcomponent_get_first_property(comp, ICAL_EXDATE_PROPERTY);
             prop;
             prop = icalcomponent_get_next_property(comp, ICAL_EXDATE_PROPERTY)) {

            struct icaltimetype exdate = icalproperty_get_exdate(prop);
            if (icaltime_is_null_time(exdate)) {
                continue;
            }
            char *s = jmap_icaltime_to_localdate_r(exdate);
            json_object_set_new(excobj, s, json_null());
            free(s);
        }

        /* Add VEVENTs with RECURRENCE-ID. */
        for (excomp = icalcomponent_get_first_component(ical, ICAL_VEVENT_COMPONENT);
             excomp;
             excomp = icalcomponent_get_next_component(ical, ICAL_VEVENT_COMPONENT)) {

            if (!icalcomponent_get_first_property(excomp, ICAL_RECURRENCEID_PROPERTY)) {
                continue;
            }

            json_t *exc = jmap_calendarevent_from_ical(excomp, comp, crock->props, userid);
            if (!exc) {
                continue;
            }
            struct icaltimetype recurid = icalcomponent_get_recurrenceid(excomp);
            char *s = jmap_icaltime_to_localdate_r(recurid);
            json_object_set_new(excobj, s, exc);
            free(s);
        }
        json_object_set(obj, "exceptions",
                json_object_size(excobj) ? excobj : json_null());
        json_decref(excobj);
    }

    /* Add JMAP-only fields. */
    if (_wantprop(crock->props, "x-href")) {
        _add_xhref(obj, cdata->dav.mailbox, cdata->dav.resource);
    }
    if (_wantprop(crock->props, "calendarId")) {
        json_object_set_new(obj, "calendarId", json_string(strrchr(cdata->dav.mailbox, '.')+1));
    }

    json_array_append_new(crock->array, obj);

done:
    if (ical) icalcomponent_free(ical);
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
    if (properties) {
        rock.props = xzmalloc(sizeof(struct hash_table));
        construct_hash_table(rock.props, 1024, 0);
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
    r = jmap_setstate(req, events, "state", MBTYPE_CALENDAR, 1 /* refresh */, 0 /* bump */);
    if (r) goto done;

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

/* Add tz to the rocks timezone cache, only if it doesn't point to a previously
 * cached timezone. Compare by pointers, which works for builtin timezones. */
static void calevent_rock_add_tz(calevent_rock *rock, icaltimezone *tz) {
    /* Yes, we could use a map here, but we don't expect the number of
     * timezones per VEVENT to be more than a handful. */
    size_t i;
    for (i = 0; i < rock->n_tzs; i++) {
        if (rock->tzs[i] == tz) {
            return;
        }
    }
    if (rock->n_tzs == rock->s_tzs) {
        rock->s_tzs = rock->s_tzs ? rock->s_tzs * 2 : 1;
        rock->tzs = xrealloc(rock->tzs, sizeof(icaltimezone*) * rock->s_tzs);
    }
    rock->tzs[rock->n_tzs++] = tz;
}

static void calevent_rock_free(struct calevent_rock *rock) {
    /* All other fields are  allocated outside our scope. */
    free(rock->tzs);
}

/* Remove and deallocate any properties of kind in VEVENT comp. */
static void jmap_remove_icalproperty(icalcomponent *comp, icalproperty_kind kind) {
    icalproperty *prop, *next;

    for (prop = icalcomponent_get_first_property(comp, kind);
         prop;
         prop = next) {

        next = icalcomponent_get_next_property(comp, kind);
        icalcomponent_remove_property(comp, prop);
        icalproperty_free(prop);
    }
}

/* Add or overwrite the datetime property kind in comp. If tz is not NULL, set
 * the TZID parameter on the property. */
static void jmap_update_dtprop_bykind(icalcomponent *comp,
                               icaltimetype dt,
                               icaltimezone *tz,
                               int purge,
                               enum icalproperty_kind kind) {
    icalproperty *prop;
    if (purge) {
        /* Purge the existing property. */
        prop = icalcomponent_get_first_property(comp, kind);
        if (prop) icalcomponent_remove_property(comp, prop);
        icalproperty_free(prop);
    }

    /* Set the new property. */
    prop = icalproperty_new(kind);
    icalproperty_set_value(prop, icalvalue_new_datetime(dt));
    if (tz) {
        icalparameter *param = icalproperty_get_first_parameter(prop, ICAL_TZID_PARAMETER);
        const char *tzid = icaltimezone_get_location(tz);
        if (param) {
            icalparameter_set_tzid(param, tzid);
        } else {
            icalproperty_add_parameter(prop,icalparameter_new_tzid(tzid));
        }
    }
    icalcomponent_add_property(comp, prop);
}

/* Return non-zero if the ical property TZID parameter matches the
 * location of tz, or if both are in floating time. */
static int jmap_dtprop_is_in_timezone(icalproperty *prop, icaltimezone *tz) {

    icalparameter *param = icalproperty_get_first_parameter(prop, ICAL_TZID_PARAMETER);
    const char *tzid = param ? icalparameter_get_tzid(param) : NULL;
    if (!tz && !tzid) {
        /* Check if the DATETIME value is in UTC. */
        icalvalue *val = icalproperty_get_value(prop);
        if (!val) {
            return 0;
        }
        icaltimetype dt = icalvalue_get_datetime(val);
        if (icaltime_is_null_time(dt)) {
            return 0;
        }
        /* Return true for floating time. */
        return dt.zone == NULL;
    }
    if (tz && tzid) {
        /* Check if they both match the same singleton builtin timezone. */
        icaltimezone *a = icaltimezone_get_builtin_timezone(tzid);
        icaltimezone *b = icaltimezone_get_builtin_timezone(icaltimezone_get_location(tz));
        return a == b;
    }
    return 0;
}

/* Update the TZID parameter of prop to the TZID of tz, or remove any TZID
 * parameter from prop if tz is NULL. */
static void jmap_dtprop_update_tzid(icalproperty *prop, icaltimezone *tz) {
    const char *tzid = tz ? icaltimezone_get_location(tz) : NULL;

    icalparameter *param = icalproperty_get_first_parameter(prop, ICAL_TZID_PARAMETER);
    if (param) {
        icalproperty_remove_parameter_by_ref(prop, param);
    }
    if (tzid) {
        param = icalparameter_new_tzid(tzid);
        icalproperty_add_parameter(prop, param);
    }
}

/* Create or update the ORGANIZER/ATTENDEEs in the VEVENT component comp as
 * defined by the JMAP organizer and attendees. Purge any participants that
 * are not updated. */
static void jmap_participants_to_ical(icalcomponent *comp,
                                      json_t *organizer,
                                      json_t *attendees,
                                      calevent_rock *rock) {
    int create = rock->flags & JMAP_CREATE;
    json_t *invalid = rock->invalid;
    const char *name = NULL;
    const char *email = NULL;
    const char *rsvp = NULL;
    struct buf buf = BUF_INITIALIZER;
    size_t i;
    icalproperty *prop, *next;
    json_t *att;
    hash_table cache;

    /* XXX - Integrate iTIP, once all the semantics JMAP<->iTIP are agreed. */

    /* Purge existing ORGANIZER and ATTENDEEs only if instructed to do so. */
    if (organizer == json_null() && attendees == json_null()) {
        prop = icalcomponent_get_first_property(comp, ICAL_ORGANIZER_PROPERTY);
        icalcomponent_remove_property(comp, prop);
        icalproperty_free(prop);
        for (prop = icalcomponent_get_first_property(comp, ICAL_ATTENDEE_PROPERTY);
             prop;
             prop = next) {
            next = icalcomponent_get_next_property(comp, ICAL_ATTENDEE_PROPERTY);
            icalcomponent_remove_property(comp, prop);
            icalproperty_free(prop);
        }
        return;
    }

    /* organizer */
    jmap_readprop_full(organizer, "organizer", "name", create, invalid, "s", &name);
    jmap_readprop_full(organizer, "organizer", "email", create, invalid, "s", &email);

    if (name && email) {
        prop = icalcomponent_get_first_property(comp, ICAL_ORGANIZER_PROPERTY);
        if (prop) {
            /* Remove but keep property to preserve ical parameters. */
            icalcomponent_remove_property(comp, prop);
            buf_printf(&buf, "mailto:%s", email);
            icalproperty_set_value_from_string(prop, buf_cstring(&buf), "NO");
            buf_reset(&buf);
        } else {
            prop = icalproperty_new_organizer(email);
        }
        icalparameter *param = icalproperty_get_first_parameter(prop, ICAL_CN_PARAMETER);
        if (param) {
            icalproperty_remove_parameter_by_ref(prop, param);
        }
        param = icalparameter_new_cn(name);
        icalproperty_add_parameter(prop, param);
        icalcomponent_add_property(comp, prop);
    }

    if (!json_array_size(attendees)) {
        return;
    }

    /* Move all current ATTENDEEs with a mailto caladdr to the cache. */
    construct_hash_table(&cache, json_array_size(attendees), 0);
    for (prop = icalcomponent_get_first_property(comp, ICAL_ATTENDEE_PROPERTY);
         prop;
         prop = next) {

        next = icalcomponent_get_next_property(comp, ICAL_ATTENDEE_PROPERTY);

        const char *val = icalproperty_get_value_as_string(prop);
        if (!val) {
            continue;
        }
        if (strncasecmp(val, "mailto:", 7)) {
            continue;
        }
        val += 7;
        if (!*val) {
            continue;
        }
        icalcomponent_remove_property(comp, prop);
        hash_insert(val, prop, &cache);
    }

    /* Iterate the JMAP attendees to create or update the iCalendar ATTENDEES. */
    json_array_foreach(attendees, i, att) {
        char *prefix;
        icalparameter_partstat pst = ICAL_PARTSTAT_NONE;
        name = NULL; email = NULL;
        rsvp = NULL;

        buf_printf(&buf, "attendees[%llu]", (long long unsigned) i);
        prefix = buf_newcstring(&buf);
        buf_reset(&buf);

        jmap_readprop_full(att, prefix, "name", create, invalid, "s", &name);
        jmap_readprop_full(att, prefix, "email", create, invalid, "s", &email);
        jmap_readprop_full(att, prefix, "rsvp", create, invalid, "s", &rsvp);
        if (rsvp) {
            if (!strcmp(rsvp, "")) {
                pst = ICAL_PARTSTAT_NEEDSACTION;
            } else if (!strcmp(rsvp, "yes")) {
                pst = ICAL_PARTSTAT_ACCEPTED;
            } else if (!strcmp(rsvp, "maybe")) {
                pst = ICAL_PARTSTAT_TENTATIVE;
            } else if (!strcmp(rsvp, "no")) {
                pst = ICAL_PARTSTAT_DECLINED;
            } else {
                buf_printf(&buf, "%s.%s", prefix, "rsvp");
                json_array_append_new(invalid, json_string(buf_cstring(&buf)));
                buf_reset(&buf);
            }
        }

        if (name && email && pst != ICAL_PARTSTAT_NONE) {
            /* Move the attendee either from the cache or create a new one. */
            prop = (icalproperty*) hash_lookup(email, &cache);
            if (prop) hash_del(email, &cache);
            if (!prop) {
                buf_printf(&buf, "mailto:%s", email);
                prop = icalproperty_new_attendee(buf_cstring(&buf));
                buf_reset(&buf);
            }

            icalparameter *param;

            /* name */
            param = icalproperty_get_first_parameter(prop, ICAL_CN_PARAMETER);
            if (param) {
                icalproperty_remove_parameter_by_ref(prop, param);
            }
            param = icalparameter_new_cn(name);
            icalproperty_add_parameter(prop, param);

            /* partstat */
            param = icalproperty_get_first_parameter(prop, ICAL_PARTSTAT_PARAMETER);
            if (param) {
                icalproperty_remove_parameter_by_ref(prop, param);
            }
            param = icalparameter_new_partstat(pst);
            icalproperty_add_parameter(prop, param);

            icalcomponent_add_property(comp, prop);
        }

        free(prefix);
    }

    free_hash_table(&cache, (void(*)(void*)) icalproperty_free);
    buf_free(&buf);
}

static void jmap_byday_to_ical(struct buf *buf, int val) {
    int day = 0;
    int week = 0;
    if (val >= 0) {
        day = val % 7;
        week = val / 7;
    } else {
        day = (7 + (val % 7)) % 7;
        week = (val - 6) / 7;
    }
    if (week) {
        buf_printf(buf, "%+d", week);
    }
    buf_printf(buf, icalrecur_weekday_to_string(day+1));
}


static void jmap_month_to_ical(struct buf *buf, int val) {
    buf_printf(buf, "%d", val+1);
}

static void jmap_int_to_ical(struct buf *buf, int val) {
    buf_printf(buf, "%d", val);
}

/* Convert and print the JMAP byX recurrence value to ical into buf, otherwise
 * report the erroneous fieldName as invalid. If lower or upper is not NULL,
 * make sure that every byX value is within these bounds. */
static void jmap_recurrence_byX_to_ical(json_t *byX,
                                        struct buf *buf,
                                        const char *tag,
                                        int *lower,
                                        int *upper,
                                        int allowZero,
                                        const char *fieldName,
                                        json_t *invalid,
                                        void(*conv)(struct buf*, int)) {

    /* Make sure there is at least on entry. */
    if (!json_array_size(byX)) {
        json_array_append_new(invalid, json_string(fieldName));
        return;
    }

    /* Convert the array. */
    buf_printf(buf, ";%s=", tag);
    size_t i;
    for (i = 0; i < json_array_size(byX); i++) {
        int val;
        int err = json_unpack(json_array_get(byX, i), "i", &val);
        if (!err && !allowZero && !val) {
            err = 1;
        }
        if (!err && ((lower && val < *lower) || (upper && val > *upper))) {
            err = 2;
        }
        if (err) {
            struct buf b = BUF_INITIALIZER;
            buf_printf(&b, "%s[%llu]", fieldName, (long long unsigned) i);
            json_array_append_new(invalid, json_string(buf_cstring(&b)));
            buf_free(&b);
            continue;
        }
        /* Prepend leading comma, if not first parameter value. */
        if (i) {
            buf_printf(buf, "%c", ',');
        }
        /* Convert the byX value to ical. */
        conv(buf, val);
    }
}

/* Update the TZID parameters of VEVENT comp's EXDATEs and any ot its
 * exceptions. */
static void jmap_exceptions_update_tz(icalcomponent *comp,
                                      calevent_rock *rock) {

    const char *tzid;
    icaltimezone *tz;

    /* Change the TZID of all EXDATEs that are in the former startTimezone. */
    icalproperty *prop;
    for (prop = icalcomponent_get_first_property(comp, ICAL_EXDATE_PROPERTY);
         prop;
         prop = icalcomponent_get_next_property(comp, ICAL_EXDATE_PROPERTY)) {

        if (jmap_dtprop_is_in_timezone(prop, rock->tzstart_old)) {
            jmap_dtprop_update_tzid(prop, rock->tzstart);
        } else {
            tzid = jmap_tzid_from_icalprop(prop, 1 /*guess*/);
            if (tzid) tz = icaltimezone_get_builtin_timezone(tzid);
            if (tz) calevent_rock_add_tz(rock, tz);
        }
    }

    /* Update the TZIDs of each VEVENT with RECURRENCE-ID. */
    icalcomponent *excomp;
    icalcomponent *ical = icalcomponent_get_parent(comp);
    for (excomp = icalcomponent_get_first_component(ical, ICAL_VEVENT_COMPONENT);
         excomp;
         excomp = icalcomponent_get_next_component(ical, ICAL_VEVENT_COMPONENT)) {

        prop = icalcomponent_get_first_property(excomp, ICAL_RECURRENCEID_PROPERTY);
        if (!prop) continue;

        /* Rewrite TZID of RECURRENCE-ID. */
        if (jmap_dtprop_is_in_timezone(prop, rock->tzstart_old)) {
            jmap_dtprop_update_tzid(prop, rock->tzstart);
        } else {
            tzid = jmap_tzid_from_icalprop(prop, 1 /*guess*/);
            if (tzid) tz = icaltimezone_get_builtin_timezone(tzid);
            if (tz) calevent_rock_add_tz(rock, tz);
        }

        /* Rewrite TZID of DTSTART. */
        if ((prop = icalcomponent_get_first_property(excomp, ICAL_DTSTART_PROPERTY))) {
            if (jmap_dtprop_is_in_timezone(prop, rock->tzstart_old)) {
                jmap_dtprop_update_tzid(prop, rock->tzstart);
            } else {
                tzid = jmap_tzid_from_icalprop(prop, 1 /*guess*/);
                if (tzid) tz = icaltimezone_get_builtin_timezone(tzid);
                if (tz) calevent_rock_add_tz(rock, tz);
            }
        }

        /* Rewrite TZID of DTEND. */
        if ((prop = icalcomponent_get_first_property(excomp, ICAL_DTEND_PROPERTY))) {
            if (jmap_dtprop_is_in_timezone(prop, rock->tzend_old)) {
                jmap_dtprop_update_tzid(prop, rock->tzend);
            } else {
                tzid = jmap_tzid_from_icalprop(prop, 1 /*guess*/);
                if (tzid) tz = icaltimezone_get_builtin_timezone(tzid);
                if (tz) calevent_rock_add_tz(rock, tz);
            }
        }
    }
}


/* Create or overwrite the VEVENT exceptions for VEVENT component comp as
 * defined by the JMAP exceptions. */
static void jmap_exceptions_to_ical(icalcomponent *comp,
                                    json_t *exceptions,
                                    calevent_rock *rock) {

    json_t *invalid = rock->invalid;

    /* Purge existing EXDATEs. */
    jmap_remove_icalproperty(comp, ICAL_EXDATE_PROPERTY);

    const char *key;
    json_t *exc;
    struct buf buf = BUF_INITIALIZER;
    icalcomponent *ical = icalcomponent_get_parent(comp);
    icalcomponent *excomp, *excomp_next;
    hash_table excs;
    icalproperty *prop;

    /* Move VEVENT exceptions to a temporary cache, keyed by recurrence id. */
    construct_hash_table(&excs, json_object_size(exceptions) + 1, 0);
    for (excomp = icalcomponent_get_first_component(ical, ICAL_VEVENT_COMPONENT);
         excomp;
         excomp = excomp_next) {
        excomp_next = icalcomponent_get_next_component(ical, ICAL_VEVENT_COMPONENT);

        prop = icalcomponent_get_first_property(excomp, ICAL_RECURRENCEID_PROPERTY);
        if (!prop) {
            continue;
        }
        /* Key by LocalDate (instead of LocalDate+TZID), since this
         * RECURRENCEID must be denoted in the original timezone. */
        const char *val = icalproperty_get_value_as_string(prop);
        if (val) {
#if 0
            hash_insert(val, excomp, &excs);
#endif
        }
        icalcomponent_remove_component(ical, excomp);
    }

    /* Add updated or new exceptions back to the VCALENDAR component. */
    json_object_foreach(exceptions, key, exc) {
        char *prefix;

        buf_printf(&buf, "exceptions[%s]", key);
        prefix = xstrdup(buf_cstring(&buf));
        buf_reset(&buf);

        /* Parse key as LocalDate. */
        icaltimetype dt;
        if (jmap_localdate_to_icaltime(key, &dt, rock->tzstart, rock->isAllDay)) {
            json_array_append_new(invalid, json_string(prefix));
            free(prefix);
            continue;
        }

        if (exc != json_null()) {
            json_t *invalidexc = json_pack("[]");
            size_t i;
            json_t *v;
            excomp = NULL;

            /* Check if the cache already contains this recurrence id. */
            const char *val = icaltime_as_ical_string(dt);
            excomp = (icalcomponent*) hash_lookup(val, &excs);
            if (excomp) hash_del(val, &excs);

            /* If not found, create a new clone of the main event. */
            if (!excomp) {
                excomp = icalcomponent_new_clone(comp);
                /* Remove any properties that we do not allow in exceptions. */
                jmap_remove_icalproperty(excomp, ICAL_RDATE_PROPERTY);
                jmap_remove_icalproperty(excomp, ICAL_EXDATE_PROPERTY);
                jmap_remove_icalproperty(excomp, ICAL_RRULE_PROPERTY);
                jmap_remove_icalproperty(excomp, ICAL_ORGANIZER_PROPERTY);
                jmap_remove_icalproperty(excomp, ICAL_ATTENDEE_PROPERTY);
                /* XXX ATTACH? */
            }

            /* Add RECURRENCEID property. */
            jmap_update_dtprop_bykind(excomp, dt, rock->tzstart, 1 /*purge*/, ICAL_RECURRENCEID_PROPERTY);

            /* Add exceptional VEVENT component to the VCALENDAR. */
            icalcomponent_add_component(ical, excomp);

            /* Make sure not to overwrite the main timezone rock. Since an
             * exception must not contain other exceptions, there can't
             * be any timezones added (and hence realloced) to the rock. */
            calevent_rock myrock = *rock;
            myrock.flags = JMAP_EXC;
            myrock.recurid = key;
            myrock.comp = comp;
            jmap_calendarevent_to_ical(excomp, exc, &myrock);
            /* XXX - that's ugly. Need to make sure that the rocks timezone
             * array still points to latest realloced memory block. */
            rock->tzs = myrock.tzs;
            rock->n_tzs = myrock.n_tzs;
            rock->s_tzs = myrock.s_tzs;

            /* Prepend prefix to any invalid properties. */
            json_array_foreach(invalidexc, i, v) {
                buf_printf(&buf, "%s.%s", prefix, json_string_value(v));
                json_array_append_new(invalid, json_string(buf_cstring(&buf)));
                buf_reset(&buf);
            }
            json_decref(invalidexc);
        } else {
            /* Add EXDATE to the VEVENT. */
            /* iCalendar allows to set multiple EXDATEs. */
            jmap_update_dtprop_bykind(comp, dt, rock->tzstart, 0 /*purge*/, ICAL_EXDATE_PROPERTY);
        }

        free(prefix);
    }

    /* Purge any remaining VEVENTs from the cache. */
    free_hash_table(&excs, (void(*)(void*)) icalcomponent_free);

    buf_free(&buf);

}

/* Set the TZID parameters for all RDATE properties. */
static void jmap_inclusions_update_tz(icalcomponent *comp,
                                      calevent_rock *rock) {
    icalproperty *prop;

    for (prop = icalcomponent_get_first_property(comp, ICAL_RDATE_PROPERTY);
         prop;
         prop = icalcomponent_get_next_property(comp, ICAL_RDATE_PROPERTY)) {
        icalparameter *param = icalproperty_get_first_parameter(prop, ICAL_TZID_PARAMETER);
        if (param) {
            if (rock->tzstart) {
                const char *tzid = icaltimezone_get_location(rock->tzstart);
                if (tzid) {
                    icalparameter_set_tzid(param, tzid);
                }
            } else {
                icalproperty_remove_parameter(prop, ICAL_TZID_PARAMETER);
            }
        }
    }
}

/* Create or overwrite the RDATEs in the VEVENT component comp as defined by the
 * JMAP recurrence. Use tz as timezone for LocalDate conversions. */
static void jmap_inclusions_to_ical(icalcomponent *comp,
                                    json_t *inclusions,
                                    calevent_rock *rock) {

    size_t i;
    json_t *incl;
    struct buf buf = BUF_INITIALIZER;
    json_t *invalid = rock->invalid;

    /* Purge existing RDATEs. */
    jmap_remove_icalproperty(comp, ICAL_RDATE_PROPERTY);

    if (!inclusions || inclusions == json_null()) {
        return;
    }

    /* Add RDATEs.*/
    json_array_foreach(inclusions, i, incl) {
        icaltimetype dt;

        /* Parse incl as LocalDate. */
        if (jmap_localdate_to_icaltime(json_string_value(incl), &dt, rock->tzstart, rock->isAllDay)) {
            buf_printf(&buf, "inclusions[%llu]", (long long unsigned) i);
            json_array_append_new(invalid, json_string(buf_cstring(&buf)));
            buf_reset(&buf);
            continue;
        } 

        /* Create and add RDATE property. */
        jmap_update_dtprop_bykind(comp, dt, rock->tzstart, 0 /*purge*/, ICAL_RDATE_PROPERTY);
    }

    buf_free(&buf);
}


/* Create or overwrite the VEVENT attachments for VEVENT component comp as
 * defined by the JMAP exceptions. */
static void jmap_attachments_to_ical(icalcomponent *comp,
                                     json_t *attachments,
                                     calevent_rock *rock) {

    hash_table atts;
    icalproperty *prop, *next;
    struct buf buf = BUF_INITIALIZER;
    json_t *invalid = rock->invalid;

    /* Move existing URL attachments to a temporary cache. */
    construct_hash_table(&atts, json_array_size(attachments) + 1, 0);
    for (prop = icalcomponent_get_first_property(comp, ICAL_ATTACH_PROPERTY);
         prop;
         prop = next) {

        next = icalcomponent_get_next_property(comp, ICAL_ATTACH_PROPERTY);
        icalattach *attach = icalproperty_get_attach(prop);

        /* Ignore binary attachments. */
        if (!attach || !icalattach_get_is_url(attach)) {
            continue;
        }

        /* Ignore malformed URLs. */
        const char *url = icalattach_get_url(attach);
        if (!url || !strlen(url)) {
            continue;
        }

        icalcomponent_remove_property(comp, prop);
        hash_insert(url, prop, &atts);
    }


    /* Create or update attachments. */
    size_t i;
    json_t *attachment;
    json_array_foreach(attachments, i, attachment) {

        int pe;
        const char *blobId = NULL;
        const char *type = NULL;
        const char *name = NULL;
        json_int_t size = -1;
        char *prefix;

        buf_printf(&buf, "attachments[%llu]", (long long unsigned) i);
        prefix = buf_newcstring(&buf);
        buf_reset(&buf);

        /* Parse and validate JMAP File object. */
        pe = jmap_readprop_full(attachment, prefix, "blobId", 1, invalid, "s", &blobId);
        if (pe > 0) {
            if (!strlen(blobId)) {
                buf_printf(&buf, "%s.%s", prefix, "blobId");
                json_array_append_new(invalid, json_string(buf_cstring(&buf)));
                buf_reset(&buf);
                blobId = NULL;
            }
        }
        if (json_object_get(attachment, "type") != json_null()) {
            jmap_readprop_full(attachment, prefix, "type", 0, invalid, "s", &type);
        }
        if (json_object_get(attachment, "name") != json_null()) {
            jmap_readprop_full(attachment, prefix, "name", 0, invalid, "s", &name);
        }
        if (json_object_get(attachment, "size") != json_null()) {
            pe = jmap_readprop_full(attachment, prefix, "size", 0, invalid, "I", &size);
            if (pe > 0 && size < 0) {
                buf_printf(&buf, "%s.%s", prefix, "size");
                json_array_append_new(invalid, json_string(buf_cstring(&buf)));
                buf_reset(&buf);
            }
        }

        if (blobId && !json_array_size(invalid)) {

            /* blobId */
            prop = (icalproperty*) hash_lookup(blobId, &atts);
            if (prop) {
                hash_del(blobId, &atts);
            } else {
                icalattach *icalatt = icalattach_new_from_url(blobId);
                prop = icalproperty_new_attach(icalatt);
                icalattach_unref(icalatt);
            }

            /* type */
            icalparameter *param = icalproperty_get_first_parameter(prop, ICAL_FMTTYPE_PARAMETER);
            if (param) icalproperty_remove_parameter_by_ref(prop, param);
            if (type) {
                icalproperty_add_parameter(prop, icalparameter_new_fmttype(type));
            }

            /* name */
            /* XXX Could use Microsoft's X-FILENAME parameter to store name,
             * but that's only for binary attachments. For now, ignore name. */

            /* size */
            param = icalproperty_get_first_parameter(prop, ICAL_SIZE_PARAMETER);
            if (param) icalproperty_remove_parameter_by_ref(prop, param);
            if (size >= 0) {
                buf_printf(&buf, "%lld", (long long) size);
                icalproperty_add_parameter(prop, icalparameter_new_size(buf_cstring(&buf)));
                buf_reset(&buf);
            }

            /* Add ATTACH property. */
            icalcomponent_add_property(comp, prop);
        }

        free(prefix);
        buf_free(&buf);
    }

    /* Purge any remaining URL attachments from the cache. */
    free_hash_table(&atts, (void(*)(void*)) icalproperty_free);

}

/* Rewrite the UTC-formatted UNTIL dates in the RRULE of VEVENT comp. */
static void jmap_recurrence_update_tz(icalcomponent *comp,
                                      calevent_rock *rock) {

    icalproperty *prop = icalcomponent_get_first_property(comp, ICAL_RRULE_PROPERTY);
    if (!prop) {
        return;
    }
    struct icalrecurrencetype rrule = icalproperty_get_rrule(prop);
    if (icaltime_is_null_time(rrule.until)) {
        return;
    }
    icaltimezone *utc = icaltimezone_get_utc_timezone();
    icaltimetype dt = icaltime_convert_to_zone(rrule.until, rock->tzstart_old);
    dt.zone = rock->tzstart;
    rrule.until = icaltime_convert_to_zone(dt, utc);
    icalproperty_set_rrule(prop, rrule);
}

/* Create or overwrite the RRULE in the VEVENT component comp as defined by the
 * JMAP recurrence. */
static void jmap_recurrence_to_ical(icalcomponent *comp,
                                    json_t *recur,
                                    calevent_rock *rock) {

    const char *prefix = "recurrence";
    const char *freq = NULL;
    struct buf buf = BUF_INITIALIZER;
    int pe;
    icalproperty *prop, *next;
    json_t *invalid = rock->invalid;

    /* Purge existing RRULE. */
    for (prop = icalcomponent_get_first_property(comp, ICAL_RRULE_PROPERTY);
         prop;
         prop = next) {
        next = icalcomponent_get_next_property(comp, ICAL_RRULE_PROPERTY);
        icalcomponent_remove_property(comp, prop);
        icalproperty_free(prop);
    }

    if (!recur || recur == json_null()) {
        return;
    }

    /* frequency */
    pe = jmap_readprop_full(recur, prefix, "frequency", 1, invalid, "s", &freq);
    if (pe > 0) {
        char *s = xstrndup(freq, 64);
        char *p = s; for ( ; *p; ++p) *p = toupper(*p);
        buf_printf(&buf, "FREQ=%s", s);
        free(s);
    }

    /* interval */
    int interval = 1;
    pe = jmap_readprop_full(recur, prefix, "interval", 0, invalid, "i", &interval);
    if (pe > 0) {
        if (interval > 1) {
            buf_printf(&buf, ";INTERVAL=%d", interval);
        } else {
            json_array_append_new(invalid, json_string("recurrence.interval"));
        }
    }

    /* firstDayOfWeek */
    int day = 1;
    pe = jmap_readprop_full(recur, prefix, "firstDayOfWeek", 0, invalid, "i", &day);
    if (pe > 0) {
        if (day == 0) {
            buf_printf(&buf, ";WKST=SU");
        } else if (day > 1 && day <= 6) {
            buf_printf(&buf, ";WKST=%s", icalrecur_weekday_to_string(day+1));
        } else {
            json_array_append_new(invalid, json_string("recurrence.firstDayOfWeek"));
        }
    }

    /* byDay */
    int lower, upper;
    json_t *byday = NULL;
    pe = jmap_readprop_full(recur, prefix, "byDay", 0, invalid, "o", &byday);
    if (pe > 0) {
        jmap_recurrence_byX_to_ical(byday, &buf, "BYDAY",
                NULL /* lower */, NULL /* upper */, 1 /* allowZero */,
                "recurrence.byDay", invalid, jmap_byday_to_ical);
    }

    /* byDate */
    json_t *bydate = NULL;
    lower = -31;
    upper = 31;
    pe = jmap_readprop_full(recur, prefix, "byDate", 0, invalid, "o", &bydate);
    if (pe > 0) {
        jmap_recurrence_byX_to_ical(bydate, &buf, "BYDATE",
                &lower, &upper, 0 /* allowZero */,
                "recurrence.byDate", invalid, jmap_int_to_ical);
    }

    /* byMonth */
    json_t *bymonth = NULL;
    lower = 0;
    upper = 11;
    pe = jmap_readprop_full(recur, prefix, "byMonth", 0, invalid, "o", &bymonth);
    if (pe > 0) {
        jmap_recurrence_byX_to_ical(bymonth, &buf, "BYMONTH",
                &lower, &upper, 0 /* allowZero */,
                "recurrence.byMonth", invalid, jmap_month_to_ical);
    }

    /* byYearDay */
    json_t *byyearday = NULL;
    lower = -366;
    upper = 366;
    pe = jmap_readprop_full(recur, prefix, "byYearDay", 0, invalid, "o", &byyearday);
    if (pe > 0) {
        jmap_recurrence_byX_to_ical(byyearday, &buf, "BYYEARDAY",
                &lower, &upper, 0 /* allowZero */,
                "recurrence.byYearDay", invalid, jmap_int_to_ical);
    }


    /* byWeekNo */
    json_t *byweekno = NULL;
    lower = -53;
    upper = 53;
    pe = jmap_readprop_full(recur, prefix, "byWeekNo", 0, invalid, "o", &byweekno);
    if (pe > 0) {
        jmap_recurrence_byX_to_ical(byweekno, &buf, "BYWEEKNO",
                &lower, &upper, 0 /* allowZero */,
                "recurrence.byWeekNo", invalid, jmap_int_to_ical);
    }

    /* byHour */
    json_t *byhour = NULL;
    lower = 0;
    upper = 23;
    pe = jmap_readprop_full(recur, prefix, "byHour", 0, invalid, "o", &byhour);
    if (pe > 0) {
        jmap_recurrence_byX_to_ical(byhour, &buf, "BYHOUR",
                &lower, &upper, 1 /* allowZero */,
                "recurrence.byHour", invalid, jmap_int_to_ical);
    }

    /* byMinute */
    json_t *byminute = NULL;
    lower = 0;
    upper = 59;
    pe = jmap_readprop_full(recur, prefix, "byMinute", 0, invalid, "o", &byminute);
    if (pe > 0) {
        jmap_recurrence_byX_to_ical(byminute, &buf, "BYMINUTE",
                &lower, &upper, 1 /* allowZero */,
                "recurrence.byMinute", invalid, jmap_int_to_ical);
    }

    /* bySecond */
    json_t *bysecond = NULL;
    lower = 0;
    upper = 59;
    pe = jmap_readprop_full(recur, prefix, "bySecond", 0, invalid, "o", &bysecond);
    if (pe > 0) {
        jmap_recurrence_byX_to_ical(bysecond, &buf, "BYSECOND",
                &lower, &upper, 1 /* allowZero */,
                "recurrence.bySecond", invalid, jmap_int_to_ical);
    }

    /* bySetPos */
    json_t *bysetpos = NULL;
    lower = 0;
    upper = 59;
    pe = jmap_readprop_full(recur, prefix, "bySetPos", 0, invalid, "o", &bysetpos);
    if (pe > 0) {
        jmap_recurrence_byX_to_ical(bysetpos, &buf, "BYSETPOS",
                &lower, &upper, 1 /* allowZero */,
                "recurrence.bySetPos", invalid, jmap_int_to_ical);
    }

    if (json_object_get(recur, "count") && json_object_get(recur, "until")) {
        json_array_append_new(invalid, json_string("recurrence.count"));
        json_array_append_new(invalid, json_string("recurrence.until"));
    }

    /* count */
    int count;
    pe = jmap_readprop_full(recur, prefix, "count", 0, invalid, "i", &count);
    if (pe > 0) {
        if (count > 0) {
            buf_printf(&buf, ";COUNT=%d", count);
        } else {
            json_array_append_new(invalid, json_string("recurrence.count"));
        }
    }

    /* until */
    const char *until;
    pe = jmap_readprop_full(recur, prefix, "until", 0, invalid, "s", &until);
    if (pe > 0) {
        icaltimetype dtloc;

        if (!jmap_localdate_to_icaltime(until, &dtloc, rock->tzstart, rock->isAllDay)) {
            icaltimezone *utc = icaltimezone_get_utc_timezone();
            icaltimetype dt = icaltime_convert_to_zone(dtloc, utc);
            buf_printf(&buf, ";UNTIL=%s", icaltime_as_ical_string(dt));
        } else {
            json_array_append_new(invalid, json_string("until"));
        }
    }

    if (json_array_size(invalid)) {
        buf_free(&buf);
        return;
    }

    /* Parse buf to make sure is valid. */
    struct icalrecurrencetype rt = icalrecurrencetype_from_string(buf_cstring(&buf));
    if (rt.freq == ICAL_NO_RECURRENCE) {
        /* We somehow broke the RRULE value. Report the recurrence as invalid
         * so we won't save it, but most probably the error is on our side. */
        syslog(LOG_ERR, "Could not parse RRULE %s: %s",
                buf_cstring(&buf), icalerror_strerror(icalerrno));
        json_array_append_new(invalid, json_string("recurrence"));
        buf_free(&buf);
        return;
    }

    /* Add RRULE property to comp. */
    icalcomponent_add_property(comp, icalproperty_new_rrule(rt));

    buf_free(&buf);
}

/* Create or update the VALARMs in the VEVENT component comp as defined by the
 * JMAP alerts. */
static void jmap_alerts_to_ical(icalcomponent *comp,
                                json_t *alerts,
                                calevent_rock *rock) {
    size_t i;
    json_t *alert;
    struct buf buf = BUF_INITIALIZER;
    json_t *invalid = rock->invalid;

    /* Purge all VALARMs. */
    icalcomponent *alarm, *next;
    for (alarm = icalcomponent_get_first_component(comp, ICAL_VALARM_COMPONENT);
         alarm;
         alarm = next) {
        next = icalcomponent_get_next_component(comp, ICAL_VALARM_COMPONENT);
        icalcomponent_remove_component(comp, alarm);
        icalcomponent_free(alarm);
    }

    if (alerts == json_null()) {
        return;
    }

    json_array_foreach(alerts, i, alert) {
        enum icalproperty_action action = ICAL_ACTION_NONE;
        const char *type = NULL;
        int diff = 0;
        char *prefix;
        int pe;

        buf_reset(&buf);
        buf_printf(&buf, "alerts[%llu]", (long long unsigned) i);
        prefix = buf_newcstring(&buf);
        buf_reset(&buf);

        /* type */
        pe = jmap_readprop_full(alert, prefix, "type", 1, invalid, "s", &type);
        if (pe > 0) {
            if (!strncmp(type, "email", 6)) {
                action = ICAL_ACTION_EMAIL;
            } else if (!strncmp(type, "alert", 6)) {
                action = ICAL_ACTION_DISPLAY;
            } else {
                buf_printf(&buf, "%s.type", prefix);
                json_array_append(invalid, json_string(buf_cstring(&buf)));
                buf_reset(&buf);
            }
        }

        /* minutesBefore */
        pe = jmap_readprop_full(alert, prefix, "minutesBefore", 1, invalid, "i", &diff);
        if (pe > 0 && action != ICAL_ACTION_NONE) {
            struct icaltriggertype trigger = icaltriggertype_from_int(diff * -60);
            icalcomponent *alarm = icalcomponent_new_valarm();
            icalproperty *prop;

            /* action */
            prop = icalproperty_new_action(action);
            icalcomponent_add_property(alarm, prop);

            /* trigger */
            prop = icalproperty_new_trigger(trigger);
            icalcomponent_add_property(alarm, prop);

            /* alert contents */
            if (action == ICAL_ACTION_EMAIL) {
                const char *s = icalcomponent_get_description(comp);
                prop = icalproperty_new_description(s ? s : "");
                icalcomponent_add_property(alarm, prop);

                s = icalcomponent_get_summary(comp);
                prop = icalproperty_new_summary(s ? s : "");
                icalcomponent_add_property(alarm, prop);

                buf_printf(&buf, "MAILTO:%s", rock->req->userid);
                prop = icalproperty_new_attendee(buf_cstring(&buf));
                buf_reset(&buf);
                icalcomponent_add_property(alarm, prop);
            } else {
                const char *s = icalcomponent_get_summary(comp);
                prop = icalproperty_new_description(s ? s : "");
                icalcomponent_add_property(alarm, prop);
            }

            /* Add VALARM to VEVENT. */
            icalcomponent_add_component(comp, alarm);
        }
        free(prefix);
    }

    buf_free(&buf);
}

/* Merge any changes of the basic properties of JMAP main event into
 * any exception VEVENTs of comp. */
static void jmap_exceptions_merge(icalcomponent *comp,
                                          json_t *event,
                                          calevent_rock *rock) {

    icalcomponent *excomp, *ical;
    icalcomponent *oldcomp = rock->oldcomp;
    icalproperty *prop;
    const char *val;
    json_t *invalid = json_pack("[]");

    ical = icalcomponent_get_parent(comp);

    for (excomp = icalcomponent_get_first_component(ical, ICAL_VEVENT_COMPONENT);
         excomp;
         excomp = icalcomponent_get_next_component(ical, ICAL_VEVENT_COMPONENT)) {

        prop = icalcomponent_get_first_property(excomp, ICAL_RECURRENCEID_PROPERTY);
        if (!prop) {
            continue;
        }

        /* summary */
        if (jmap_readprop(event, "summary", 0, invalid, "s", &val) > 0) {
            if (!jmap_compare_icalprop(excomp, oldcomp, ICAL_SUMMARY_PROPERTY)) {
                icalcomponent_set_summary(excomp, val);
            }
        }

        /* description */
        if (jmap_readprop(event, "description", 0, invalid, "s", &val) > 0) {
            if (!jmap_compare_icalprop(excomp, oldcomp, ICAL_DESCRIPTION_PROPERTY)) {
                icalcomponent_set_description(excomp, val);
            }
        }

        /* location */
        if (jmap_readprop(event, "location", 0, invalid, "s", &val) > 0) {
            if (!jmap_compare_icalprop(excomp, oldcomp, ICAL_LOCATION_PROPERTY)) {
                icalcomponent_set_location(excomp, val);
            }
        }

        /* showAsFree */
        int showAsFree;
        if (jmap_readprop(event, "showAsFree", 0, invalid, "s", &showAsFree) > 0) {
            if (!jmap_compare_icalprop(excomp, oldcomp, ICAL_TRANSP_PROPERTY)) {
                enum icalproperty_transp v = showAsFree ? ICAL_TRANSP_TRANSPARENT : ICAL_TRANSP_OPAQUE;
                prop = icalcomponent_get_first_property(comp, ICAL_TRANSP_PROPERTY);
                if (prop) {
                    icalproperty_set_transp(prop, v);
                } else {
                    icalcomponent_add_property(comp, icalproperty_new_transp(v));
                }
            }
        }

        /* alerts */
        json_t *alerts;
        if (jmap_readprop(event, "alerts", 0, invalid, "o", &alerts) > 0 &&
                !jmap_compare_alerts(oldcomp, excomp)) {

                /* Don't care about any parse errors hre. */
                json_t *oldinvalid = rock->invalid;
                rock->invalid = invalid;
                jmap_alerts_to_ical(excomp, alerts, rock);
                rock->invalid = oldinvalid;
            }
    }

    /* Don't care about any parse errors here. */
    json_decref(invalid);
}

static void jmap_timezones_to_ical_cb(icalcomponent *comp,
                                      struct icaltime_span *span,
                                      void *periodrock) {
    struct icalperiodtype *period = (struct icalperiodtype *) periodrock;
    int is_date = icaltime_is_date(icalcomponent_get_dtstart(comp));
    icaltimezone *utc = icaltimezone_get_utc_timezone();
    struct icaltimetype start =
        icaltime_from_timet_with_zone(span->start, is_date, utc);
    struct icaltimetype end =
        icaltime_from_timet_with_zone(span->end, is_date, utc);

    if (icaltime_compare(start, period->start) < 0)
        memcpy(&period->start, &start, sizeof(struct icaltimetype));

    if (icaltime_compare(end, period->end) > 0)
        memcpy(&period->end, &end, sizeof(struct icaltimetype));
}

/* Determine the UTC time span of all components within ical of type kind. */
static struct icalperiodtype jmap_get_utc_timespan(icalcomponent *ical,
                                                   icalcomponent_kind kind) {

    /* XXX This is almost identical to what's done in caldav_db's writeentry
     * function. But here, we want to collect also the timezone IDs in our
     * custom timezone rock. This might warrant some recfactoring, but let's
     * keep them separated for now. */

    struct icalperiodtype span;
    icalcomponent *comp = icalcomponent_get_first_component(ical, kind);
    int recurring = 0;

    /* Initialize span to be nothing */
    span.start = icaltime_from_timet_with_zone(caldav_eternity, 0, NULL);
    span.end = icaltime_from_timet_with_zone(caldav_epoch, 0, NULL);
    span.duration = icaldurationtype_null_duration();

    do {
        struct icalperiodtype period;
        icalproperty *rrule;
        icalproperty *purged_rrule = NULL;

        /* Get base dtstart and dtend */
        caldav_get_period(comp, kind, &period);

        /* See if its a recurring event */
        rrule = icalcomponent_get_first_property(comp, ICAL_RRULE_PROPERTY);
        if (rrule ||
                icalcomponent_get_first_property(comp, ICAL_RDATE_PROPERTY) ||
                icalcomponent_get_first_property(comp, ICAL_EXDATE_PROPERTY)) {
            /* Recurring - find widest time range that includes events */
            int expand = recurring = 1;

            if (rrule) {
                struct icalrecurrencetype recur = icalproperty_get_rrule(rrule);

                if (!icaltime_is_null_time(recur.until)) {
                    /* Recurrence ends - calculate dtend of last recurrence */
                    struct icaldurationtype duration;
                    icaltimezone *utc = icaltimezone_get_utc_timezone();

                    duration = icaltime_subtract(period.end, period.start);
                    period.end =
                        icaltime_add(icaltime_convert_to_zone(recur.until, utc),
                                duration);

                    /* Do RDATE expansion only */
                    /* Temporarily remove RRULE to allow for expansion of
                     * remaining recurrences. */
                    icalcomponent_remove_property(comp, rrule);
                    purged_rrule = rrule;
                }
                else if (!recur.count) {
                    /* Recurrence never ends - set end of span to eternity */
                    span.end =
                        icaltime_from_timet_with_zone(caldav_eternity, 0, NULL);

                    /* Skip RRULE & RDATE expansion */
                    expand = 0;
                }
            }

            /* Expand (remaining) recurrences */
            if (expand) {
                icalcomponent_foreach_recurrence(
                        comp,
                        icaltime_from_timet_with_zone(caldav_epoch, 0, NULL),
                        icaltime_from_timet_with_zone(caldav_eternity, 0, NULL),
                        jmap_timezones_to_ical_cb, &span);
            }

            /* Add RRULE again, if we had removed it before. */
            if (purged_rrule) {
                icalcomponent_add_property(comp, purged_rrule);
            }
        }

        /* Check our dtstart and dtend against span */
        if (icaltime_compare(period.start, span.start) < 0)
            memcpy(&span.start, &period.start, sizeof(struct icaltimetype));

        if (icaltime_compare(period.end, span.end) > 0)
            memcpy(&span.end, &period.end, sizeof(struct icaltimetype));

    } while ((comp = icalcomponent_get_next_component(ical, kind)));

    return span;
}

/* Convert the calendar event rocks timezones to VTIMEZONEs in the
 * VCALENDAR component ical. */
static void jmap_timezones_to_ical(icalcomponent *ical,
                                   calevent_rock *tzrock) {
    icalcomponent *tzcomp, *next;
    icalproperty *prop;
    struct icalperiodtype span;

    /* Determine recurrence span. */
    span = jmap_get_utc_timespan(ical, ICAL_VEVENT_COMPONENT);

    /* Remove all VTIMEZONE components for known TZIDs. This operation is
     * a bit hairy: we could expunge a timezone which is in use by an ical
     * property that is unknown to us. But since we don't know what to
     * look for, we can't make sure to preserve these timezones. */
    for (tzcomp = icalcomponent_get_first_component(ical, ICAL_VTIMEZONE_COMPONENT);
         tzcomp;
         tzcomp = next) {

        next = icalcomponent_get_next_component(ical,
                ICAL_VTIMEZONE_COMPONENT);

        prop = icalcomponent_get_first_property(tzcomp, ICAL_TZID_PROPERTY);
        if (prop) {
            const char *tzid = icalproperty_get_tzid(prop);
            if (icaltimezone_get_builtin_timezone(tzid)) {
                icalcomponent_remove_component(ical, tzcomp);
                icalcomponent_free(tzcomp);
            }
        }
    }

    /* Add the start and end timezones to the rock. */
    if (tzrock->tzstart) {
        calevent_rock_add_tz(tzrock, tzrock->tzstart);
    }
    if (tzrock->tzend) {
        calevent_rock_add_tz(tzrock, tzrock->tzend);
    }

    /* Now add each timezone in the rock, truncated by this events span. */
    size_t i;
    for (i = 0; i < tzrock->n_tzs; i++) {
        icaltimezone *tz = tzrock->tzs[i];

        /* Clone tz to overwrite its TZID property. */
        icalcomponent *tzcomp = icalcomponent_new_clone(icaltimezone_get_component(tz));
        icalproperty *tzprop = icalcomponent_get_first_property(tzcomp, ICAL_TZID_PROPERTY);
        icalproperty_set_tzid(tzprop, icaltimezone_get_location(tz));

        /* Truncate the timezone to the events timespan. */
        icaltimetype tzdtstart = icaltime_convert_to_zone(span.start, tz);
        icaltimetype tzdtend = icaltime_convert_to_zone(span.end, tz);
        tzdist_truncate_vtimezone(tzcomp, &tzdtstart, &tzdtend);

        /* Add the truncated timezone. */
        icalcomponent_add_component(ical, tzcomp);
    }
}

/* Update the start and end properties of VEVENT comp, as defined by
 * the JMAP calendarevent event. */
static void jmap_calendarevent_dt_to_ical(icalcomponent *comp,
                                          json_t *event,
                                          calevent_rock *rock) {
    const char *tzid;
    int pe;
    const char *val = NULL;
    struct icaltimetype dtstart = icaltime_null_time();
    struct icaltimetype dtend = icaltime_null_time();
    int create = rock->flags & JMAP_CREATE;
    int exc = rock->flags & JMAP_EXC;
    json_t *invalid = rock->invalid;

    /* startTimeZone */
    /* Determine the current timezone, if any. */
    tzid = jmap_tzid_from_ical(comp, ICAL_DTSTART_PROPERTY);
    if (tzid) rock->tzstart_old = icaltimezone_get_builtin_timezone(tzid);
    /* Read the new timezone, if any. */
    if (json_object_get(event, "startTimeZone") != json_null()) {
        pe = jmap_readprop(event, "startTimeZone", create&&!exc, invalid, "s", &val);
        if (pe > 0) {
            /* Lookup the new timezone. */
            rock->tzstart = icaltimezone_get_builtin_timezone(val);
            if (!rock->tzstart) {
                json_array_append_new(invalid, json_string("startTimeZone"));
            }
        } else if (!pe) {
             /* Keep the current timezone. */
            rock->tzstart = rock->tzstart_old;
        }
    } else {
        /* The startTimeZone is explicitly set to null. */
        rock->tzstart = NULL;
    }
    if (create) {
        /* If this is a create, then initialize also the old timezone to this
         * new event's timezone. Some conversion routines will look at it. */
        rock->tzstart_old = rock->tzstart;
    }
    if (rock->isAllDay && rock->tzstart) {
        /* Validate that if isAllDay is set, no timezone must be set. */
        json_array_append_new(invalid, json_string("startTimeZone"));
    }

    /* endTimeZone */
    tzid = jmap_tzid_from_ical(comp, ICAL_DTEND_PROPERTY);
    if (!tzid) tzid = jmap_tzid_from_ical(comp, ICAL_DTSTART_PROPERTY);
    if (tzid) rock->tzend_old = icaltimezone_get_builtin_timezone(tzid);
    if (json_object_get(event, "endTimeZone") != json_null()) {
        pe = jmap_readprop(event, "endTimeZone", create&&!exc, invalid, "s", &val);
        if (pe > 0) {
            rock->tzend = icaltimezone_get_builtin_timezone(val);
            if (!rock->tzend) {
                json_array_append_new(invalid, json_string("endTimeZone"));
            }
        } else if (!pe) {
            /* Keep the current timezone. */
            rock->tzend = rock->tzend_old;
        }
    } else {
        rock->tzend = NULL;
    }
    if (create) {
        rock->tzend_old = rock->tzend;
    }
    if (rock->isAllDay && rock->tzend) {
        json_array_append_new(invalid, json_string("endTimeZone"));
    }

    /* start */
    pe = jmap_readprop(event, "start", create&&!exc, invalid, "s", &val);
    if (pe > 0) {
        if (!jmap_localdate_to_icaltime(val, &dtstart, rock->tzstart, rock->isAllDay)) {
            jmap_update_dtprop_bykind(comp, dtstart, rock->tzstart, 1 /*purge*/, ICAL_DTSTART_PROPERTY);
        } else {
            json_array_append_new(invalid, json_string("start"));
        }
    } else if (!pe && !create && rock->tzstart_old != rock->tzstart) {
        /* The client changed the startTimeZone but not the start time. */
        icaltimetype dt = icalcomponent_get_dtstart(comp);
        if (!icaltime_is_null_time(dt)) {
            dt.zone = rock->tzstart;
            jmap_update_dtprop_bykind(comp, dt, rock->tzstart, 1 /*purge*/, ICAL_DTSTART_PROPERTY);
        }
    }

    /* end */
    pe = jmap_readprop(event, "end", create&&!exc, invalid, "s", &val);
    if (pe > 0) {
        if (!jmap_localdate_to_icaltime(val, &dtend, rock->tzend, rock->isAllDay)) {
            jmap_update_dtprop_bykind(comp, dtend, rock->tzend, 1 /*purge*/, ICAL_DTEND_PROPERTY);
        } else {
            json_array_append_new(invalid, json_string("end"));
        }
    } else if (!pe && !create && rock->tzend_old != rock->tzend) {
        /* The client changed the endTimeZone but not the end time. */
        icaltimetype dt = icalcomponent_get_dtend(comp);
        if (!icaltime_is_null_time(dt)) {
            dt.zone = rock->tzend;
            jmap_update_dtprop_bykind(comp, dt, rock->tzend, 1 /*purge*/, ICAL_DTEND_PROPERTY);
        }
    }

    /* The end date MUST be equal to or after the start date when both are
     * converted to UTC time. */
    dtstart = icalcomponent_get_dtstart(comp);
    dtstart.zone = rock->tzstart;
    if (!icaltime_is_null_time(dtstart)) rock->dtstart = dtstart;

    dtend = icalcomponent_get_dtend(comp);
    dtend.zone = rock->tzend;
    if (!icaltime_is_null_time(dtend)) rock->dtend = dtend;

    /* Make sure dtend follows dtstart. */
    if (icaltime_is_null_time(dtend)) dtend = dtstart;
    if (icaltime_compare(dtstart, dtend) > 0) {
        json_array_append_new(invalid, json_string("end"));
    }

}

/* Create or overwrite the iCalendar properties in VEVENT comp based on the
 * properties the JMAP calendar event. Collect all required timezone ids in
 * rock. */
static void jmap_calendarevent_to_ical(icalcomponent *comp,
                                       json_t *event,
                                       calevent_rock *rock) {
    int pe; /* parse error */
    const char *val = NULL;
    int showAsFree = 0;
    icalproperty *prop = NULL;
    int create = rock->flags & JMAP_CREATE;
    int exc = rock->flags & JMAP_EXC;
    json_t *invalid = rock->invalid;

    /* uid */
    icalcomponent_set_uid(comp, rock->uid);

    /* summary */
    pe = jmap_readprop(event, "summary", create&&!exc, invalid, "s", &val);
    if (pe > 0) {
        icalcomponent_set_summary(comp, val);
    }

    /* description */
    pe = jmap_readprop(event, "description", create&&!exc, invalid, "s", &val);
    if (pe > 0) {
        icalcomponent_set_description(comp, val);
    }

    /* location */
    pe = jmap_readprop(event, "location", create&&!exc, invalid, "s", &val);
    if (pe > 0) {
        icalcomponent_set_location(comp, val);
    }

    /* showAsFree */
    pe = jmap_readprop(event, "showAsFree", create&&!exc, invalid, "b", &showAsFree);
    if (pe > 0) {
        enum icalproperty_transp v = showAsFree ? ICAL_TRANSP_TRANSPARENT : ICAL_TRANSP_OPAQUE;
        prop = icalcomponent_get_first_property(comp, ICAL_TRANSP_PROPERTY);
        if (prop) {
            icalproperty_set_transp(prop, v);
        } else {
            icalcomponent_add_property(comp, icalproperty_new_transp(v));
        }
    }

    /* isAllDay */
    jmap_readprop(event, "isAllDay", create&&!exc, invalid, "b", &rock->isAllDay);

    /* start */
    /* end */
    /* startTimeZone */
    /* endTimeZone */
    jmap_calendarevent_dt_to_ical(comp, event, rock);

    /* organizer and attendees */
    json_t *organizer = NULL;
    json_t *attendees = NULL;

    jmap_readprop(event, "organizer", 0, invalid, "o", &organizer);
    jmap_readprop(event, "attendees", 0, invalid, "o", &attendees);
    if (organizer == json_null() && attendees == json_null()) {
        /* Remove both organizer and attendees from event. */
        jmap_participants_to_ical(comp, organizer, attendees, rock);
    } else if (organizer && attendees && json_array_size(attendees)) {
        /* Add or update both organizer and attendees. */
        jmap_participants_to_ical(comp, organizer, attendees, rock);
    } else if (organizer || attendees) {
        /* Any other combination is an error. */
        json_array_append_new(invalid, json_string("attendees"));
    }

    /* alerts */
    json_t *alerts = NULL;
    pe = jmap_readprop(event, "alerts", 0, invalid, "o", &alerts);
    if (pe > 0) {
        if (alerts == json_null() || json_array_size(alerts)) {
            jmap_alerts_to_ical(comp, alerts, rock);
        } else {
            json_array_append_new(invalid, json_string("alerts"));
        }
    } else if (!pe && !create && rock->tzstart_old != rock->tzstart) {
        /* The start timezone has changed but none of the alerts. */
        /* This is where we would like to update the timezones of any VALARMs
         * that have a TRIGGER value type of DATETIME (instead of the usual
         * DURATION type). Unfortunately, these DATETIMEs are stored in UTC.
         * Hence we can't tell, if the event owner really wants to wake up
         * at e.g. 1am UTC or if it just was close to a local datetime during
         * creation of the iCalendar file. For now, do nothing about that. */
    }

    /* recurrence */
    json_t *recurrence = NULL;
    pe = jmap_readprop(event, "recurrence", 0, invalid, "o", &recurrence);
    if (pe > 0) {
        if (!exc) {
            jmap_recurrence_to_ical(comp, recurrence, rock);
        } else {
            json_array_append_new(invalid, json_string("recurrence"));
        }
    } else if (!pe && !exc && !create && rock->tzstart_old != rock->tzstart) {
        /* The start timezone has changed but none of the recurrences. */
        jmap_recurrence_update_tz(comp, rock);
    }

    /* inclusions */
    json_t *inclusions = NULL;
    pe = jmap_readprop(event, "inclusions", 0, invalid, "o", &inclusions);
    if (pe > 0) {
        if (!exc && (inclusions == json_null() || json_array_size(inclusions))) {
            jmap_inclusions_to_ical(comp, inclusions, rock);
        } else {
            json_array_append_new(invalid, json_string("inclusions"));
        }
    } else if (!pe && !exc && !create && rock->tzstart_old != rock->tzstart) {
        /* The start timezone has changed but none of the inclusions. */
        jmap_inclusions_update_tz(comp, rock);
    }

    /* exceptions */
    json_t *exceptions = NULL;
    pe = jmap_readprop(event, "exceptions", 0, invalid, "o", &exceptions);
    if (pe > 0) {
        if (!exc && (exceptions == json_null() || json_object_size(exceptions))) {
            jmap_exceptions_to_ical(comp, exceptions, rock);
        } else {
            json_array_append_new(invalid, json_string("exceptions"));
        }
    } else if (!pe && !exc && !create) {
        if (rock->tzstart_old != rock->tzstart || rock->tzend_old != rock->tzend) {
            /* The start or end timezone has changed but none of the exceptions. */
            jmap_exceptions_update_tz(comp, rock);
        }
        /* Merge any other changes in the main event into the exceptions. */
        jmap_exceptions_merge(comp, event, rock);
    }

    /* attachments */
    json_t *attachments = NULL;
    pe = jmap_readprop(event, "attachments", 0, invalid, "o", &attachments);
    if (pe > 0) {
        if (!exc && (attachments == json_null() || json_array_size(attachments))) {
            jmap_attachments_to_ical(comp, attachments, rock);
        } else {
            json_array_append_new(invalid, json_string("attachments"));
        }
    }

    if (json_array_size(invalid)) {
        return;
    }

    /* Check JMAP specification conditions on the generated iCalendar file, so 
     * this also doubles as a sanity check. Note that we *could* report a
     * property here as invalid, which had only been set by the client in a
     * previous request. */

    /* If recurrence is null, inclusions and exceptions MUST also be null. */
    if (!exc && !icalcomponent_get_first_property(comp, ICAL_RRULE_PROPERTY)) {
        if (icalcomponent_get_first_property(comp, ICAL_RDATE_PROPERTY)) {
            json_array_append_new(invalid, json_string("inclusions"));
        }
        if (icalcomponent_get_first_property(comp, ICAL_EXDATE_PROPERTY)) {
            json_array_append_new(invalid, json_string("exceptions"));
        }
        if (!json_array_size(invalid)) {
            icalcomponent *ical = icalcomponent_get_parent(comp);
            icalcomponent *iter;
            for (iter = icalcomponent_get_first_component(ical, ICAL_VEVENT_COMPONENT);
                 iter;
                 iter = icalcomponent_get_next_component(ical, ICAL_VEVENT_COMPONENT)) {
                if (icalcomponent_get_first_property(iter, ICAL_RECURRENCEID_PROPERTY)) {
                    json_array_append_new(invalid, json_string("exceptions"));
                    break;
                }
            }
        }
    }

    /* Either both organizer and attendees are null, or neither are. */
    if ((icalcomponent_get_first_property(comp, ICAL_ORGANIZER_PROPERTY) == NULL) !=
        (icalcomponent_get_first_property(comp, ICAL_ATTENDEE_PROPERTY) == NULL)) {
        json_array_append_new(invalid, json_string("organizer"));
        json_array_append_new(invalid, json_string("attendees"));
    }
}

static int jmap_schedule_ical(const char *userid,
                              icalcomponent *oldical,
                              icalcomponent *ical,
                              int mode)
{
    struct sched_param sparam;
    int r;
    const char *organizer = NULL;
    icalcomponent *comp = NULL;

    /* Determine if any scheduling is required. */
    icalcomponent *src = mode&JMAP_DESTROY ? oldical : ical;
    comp = icalcomponent_get_first_component(src, ICAL_VEVENT_COMPONENT);
    icalproperty *prop = icalcomponent_get_first_property(comp, ICAL_ORGANIZER_PROPERTY);
    if (prop) organizer = icalproperty_get_organizer(prop);
    if (!organizer) {
        r = 0;
        goto done;
    }

    /* Lookup the organizer. */
    memset(&sparam, 0, sizeof(struct sched_param));
    r = caladdress_lookup(organizer, &sparam, userid);
    if (r == HTTP_NOT_FOUND) {
        r = 0; /* Skip non-local organizer. */ /* XXX need to handle non-local organizers? */
        goto done;
    } else if (r) {
        syslog(LOG_ERR, "failed to process scheduling message (org=%s)",
                organizer);
        goto done;
    }

    /* Validate create/update. */
    if (mode & (JMAP_CREATE|JMAP_UPDATE)) {
        /* Don't allow ORGANIZER to be changed */
        const char *oldorganizer = NULL;

        if (oldical) {
            icalcomponent *oldcomp = NULL;
            icalproperty *prop = NULL;
            oldcomp = icalcomponent_get_first_component(oldical, ICAL_VEVENT_COMPONENT);
            if (oldcomp) prop = icalcomponent_get_first_property(oldcomp, ICAL_ORGANIZER_PROPERTY);
            if (prop) oldorganizer = icalproperty_get_organizer(prop);
        }
        if (oldorganizer) {
            const char *p = organizer;
            if (!strncasecmp(p, "mailto:", 7)) p += 7;
            if (strcmp(oldorganizer, p)) {
                /* XXX This should become a set error. */
                r = IMAP_INTERNAL;
                goto done;
            }
        }
    }

    if (organizer && /* XXX Hack for Outlook */
            icalcomponent_get_first_invitee(comp)) {
        /* Send scheduling message. */
        if (!strcmpsafe(sparam.userid, userid)) {
            /* Organizer scheduling object resource */
            sched_request(userid, organizer, &sparam, oldical, ical, 0);
        } else {
            /* Attendee scheduling object resource */
            sched_reply(userid, oldical, ical);
        }
    }

done:
    sched_param_free(&sparam);
    return r;
}

/* Create, update or destroy the JMAP calendar event. Mode must be one of
 * JMAP_CREATE, JMAP_UPDATE or JMAP_DESTROY. Return 0 for success and non-
 * fatal errors. */
static int jmap_write_calendarevent(json_t *event,
                                    struct caldav_db *db,
                                    const char *uid,
                                    int mode,
                                    json_t *notWritten,
                                    struct jmap_req *req)
{
    int create = mode & JMAP_CREATE;
    int update = mode & JMAP_UPDATE;
    int destroy = mode & JMAP_DESTROY;
    int r, rights, pe;
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
    icalcomponent *comp;
    struct index_record record;
    struct calevent_rock rock;
    json_t *invalid = json_pack("[]");
    const char *calendarId = NULL;

    if (!destroy) {
        /* Look up the calendarId property. */
        pe = jmap_readprop(event, "calendarId", create /*mandatory*/,  invalid, "s", &calendarId);
        if (pe > 0 && !strlen(calendarId)) {
            json_array_append_new(invalid, json_string("calendarId"));
        } else if (pe > 0 && *calendarId == '#') {
            const char *id = (const char *) hash_lookup(calendarId, req->idmap);
            if (id != NULL) {
                calendarId = id;
            } else {
                json_array_append_new(invalid, json_string("calendarId"));
            }
        }
        if (calendarId && jmap_calendar_ishidden(calendarId)) {
            json_t *err = json_pack("{s:s}", "type", "calendarNotFound");
            json_object_set_new(notWritten, uid, err);
            r = 0; goto done;
        }

    }

    /* Handle any calendarId property errors and bail out. */
    if (json_array_size(invalid)) {
        json_t *err = json_pack("{s:s, s:O}",
                "type", "invalidProperties", "properties", invalid);
        json_object_set_new(notWritten, uid, err);
        r = 0; goto done;
    }

    /* Determine mailbox and resource name of calendar event. */
    if (update || destroy) {
        r = caldav_lookup_uid(db, uid, &cdata);
        if (r && r != CYRUSDB_NOTFOUND) {
            syslog(LOG_ERR, "caldav_lookup_uid(%s) failed: %s",
                    uid, error_message(r));
            goto done;
        }
        if (r == CYRUSDB_NOTFOUND || !cdata->dav.alive ||
                !cdata->dav.rowid || !cdata->dav.imap_uid) {
            json_t *err = json_pack("{s:s}", "type", "notFound");
            json_object_set_new(notWritten, uid, err);
            r = 0; goto done;
        }
        mboxname = xstrdup(cdata->dav.mailbox);
        resource = xstrdup(cdata->dav.resource);
    } else if (create) {
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
        json_object_set_new(notWritten, uid, err);
        r = 0; goto done;
    } else if (r) {
        syslog(LOG_ERR, "mailbox_open_iwl(%s) failed: %s",
                mboxname, error_message(r));
        goto done;
    }

    /* Check permissions. */
    rights = httpd_myrights(req->authstate, mbox->acl);
    if (!(rights & needrights)) {
        /* Pretend this mailbox does not exist. */
        json_t *err = json_pack("{s:s}", "type", "notFound");
        json_object_set_new(notWritten, uid, err);
        r = 0; goto done;
    }

    if (!create) {
        /* Fetch index record for the resource */
        memset(&record, 0, sizeof(struct index_record));
        r = mailbox_find_index_record(mbox, cdata->dav.imap_uid, &record);
        if (r == IMAP_NOTFOUND) {
            json_t *err = json_pack("{s:s}", "type", "notFound");
            json_object_set_new(notWritten, uid, err);
            r = 0; goto done;
        } else if (r) {
            syslog(LOG_ERR, "mailbox_index_record(0x%x) failed: %s",
                    cdata->dav.imap_uid, error_message(r));
            goto done;
        }
    }

    if (!create) {
        /* Load VEVENT from record. */
        ical = record_to_ical(mbox, &record);
        if (!ical) {
            syslog(LOG_ERR, "record_to_ical failed for record %u:%s",
                    cdata->dav.imap_uid, mbox->name);
            r = IMAP_INTERNAL;
            goto done;
        }
        /* Locate the main VEVENT. */
        for (comp = icalcomponent_get_first_component(ical, ICAL_VEVENT_COMPONENT);
                comp;
                comp = icalcomponent_get_next_component(ical, ICAL_VEVENT_COMPONENT)) {
            if (!icalcomponent_get_first_property(comp, ICAL_RECURRENCEID_PROPERTY)) {
                break;
            }
        }
        if (!comp) {
            syslog(LOG_ERR, "no VEVENT in record %u:%s",
                    cdata->dav.imap_uid, mbox->name);
            r = IMAP_INTERNAL;
            goto done;
        }
        if (update) {
            oldical = icalcomponent_new_clone(ical);
        } else if (destroy) {
            oldical = ical;
            ical = NULL;
        }
    } else {
        /* Create a new VCALENDAR and its VEVENT. */
        ical = icalcomponent_new_vcalendar();
        icalcomponent_add_property(ical, icalproperty_new_version("2.0"));
        icalcomponent_add_property(ical, icalproperty_new_calscale("GREGORIAN"));
        comp = icalcomponent_new_vevent();
        icalcomponent_add_component(ical, comp);
    }

    if (!destroy) {
        /* Convert the JMAP calendar event to ical. */
        memset(&rock, 0, sizeof(struct calevent_rock));
        rock.flags = create ? JMAP_CREATE : JMAP_UPDATE;
        rock.req = req;
        rock.invalid = invalid;
        rock.uid = uid;
        rock.comp = comp;
        if (update) {
            rock.oldcomp = icalcomponent_new_clone(comp);
        }
        jmap_calendarevent_to_ical(comp, event, &rock);
        jmap_timezones_to_ical(ical, &rock);
        calevent_rock_free(&rock);

        /* Handle any property errors and bail out. */
        if (json_array_size(invalid)) {
            json_t *err = json_pack("{s:s, s:O}",
                    "type", "invalidProperties", "properties", invalid);
            json_object_set_new(notWritten, uid, err);
            r = 0; goto done;
        }
    }

    if (update && calendarId) {
        /* Check, if we need to move the event. */
        dstmboxname = caldav_mboxname(req->userid, calendarId);
        if (strcmp(mbox->name, dstmboxname)) {
            /* Open destination mailbox for writing. */
            r = mailbox_open_iwl(dstmboxname, &dstmbox);
            if (r == IMAP_MAILBOX_NONEXISTENT) {
                json_t *err = json_pack("{s:s}", "type", "calendarNotFound");
                json_object_set_new(notWritten, uid, err);
                r = 0; goto done;
            } else if (r) {
                syslog(LOG_ERR, "mailbox_open_iwl(%s) failed: %s",
                        dstmboxname, error_message(r));
                goto done;
            }
            /* Check permissions. */
            rights = httpd_myrights(req->authstate, dstmbox->acl);
            if (!(rights & (DACL_WRITE))) {
                json_t *err = json_pack("{s:s}", "type", "calendarNotFound");
                json_object_set_new(notWritten, uid, err);
                r = 0; goto done;
            }
        }
    }

    /* Handle scheduling. */
    if (0) {
        /* XXX This currently segfaults in Cassandane tests when trying to call
         * sendmail. */
        r = jmap_schedule_ical(req->userid, oldical, ical, mode);
        if (r) goto done;
    }

    if (destroy || (update && dstmbox)) {
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
        mboxevent_notify(mboxevent);
        mboxevent_free(&mboxevent);

        if (destroy) {
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

    if (!destroy) {
        /* Store the updated VEVENT. */
        struct transaction_t txn;
        memset(&txn, 0, sizeof(struct transaction_t));
        txn.req_hdrs = spool_new_hdrcache();
        r = caldav_store_resource(&txn, ical, mbox, resource, db, 0);
        spool_free_hdrcache(txn.req_hdrs);
        buf_free(&txn.buf);
        if (r && r != HTTP_CREATED && r != HTTP_NO_CONTENT) {
            json_t *err = json_pack("{s:s}", "type", "unknownError");
            json_object_set_new(notWritten, uid, err);
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
    json_decref(invalid);
    return r;
}

static int setCalendarEvents(struct jmap_req *req)
{
    struct caldav_db *db = NULL;
    int r;

    r = jmap_checkstate(req, MBTYPE_CALENDAR);
    if (r) return 0;

    json_t *set = json_pack("{s:s}", "accountId", req->userid);
    r = jmap_setstate(req, set, "oldState", MBTYPE_CALENDAR, 0 /*refresh*/, 0 /*bump*/);
    if (r) goto done;

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
            uid = xstrdup(makeuuid());

            /* Create the calendar event. */
            size_t error_count = json_object_size(notCreated);
            r = jmap_write_calendarevent(arg, db, uid, JMAP_CREATE, notCreated, req);
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
            hash_insert(key, uid, req->idmap);
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
        json_t *updated = json_pack("[]");
        json_t *notUpdated = json_pack("{}");

        const char *uid;
        json_t *arg;

        json_object_foreach(update, uid, arg) {
            /* Validate uid. JMAP update does not allow creation uids here. */
            if (!strlen(uid) || *uid == '#') {
                json_t *err = json_pack("{s:s}", "type", "notFound");
                json_object_set_new(notUpdated, uid, err);
                continue;
            }

            /* Update the calendar event. */
            size_t error_count = json_object_size(notUpdated);
            r = jmap_write_calendarevent(arg, db, uid, JMAP_UPDATE, notUpdated, req);
            if (r) goto done;
            if (error_count != json_object_size(notUpdated)) {
                /* Bail out for any setErrors. */
                continue;
            }

            /* Report calendar event as updated. */
            json_array_append_new(updated, json_string(uid));
        }

        if (json_array_size(updated)) {
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
            /* Validate uid. JMAP destroy does not allow reference uids. */
            const char *uid = json_string_value(juid);
            if (!strlen(uid) || *uid == '#') {
                json_t *err = json_pack("{s:s}", "type", "notFound");
                json_object_set_new(notDestroyed, uid, err);
                continue;
            }

            /* Destroy the calendar event. */
            error_count = json_object_size(notDestroyed);
            r = jmap_write_calendarevent(NULL, db, uid, JMAP_DESTROY, notDestroyed, req);
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
    r = jmap_setstate(req, set, "newState", MBTYPE_CALENDAR,
            1 /*refresh*/,
            json_object_get(set, "created") ||
            json_object_get(set, "updated") ||
            json_object_get(set, "destroyed"));
    if (r) goto done;

    json_incref(set);
    json_t *item = json_pack("[]");
    json_array_append_new(item, json_string("calendarEventsSet"));
    json_array_append_new(item, set);
    json_array_append_new(item, json_string(req->tag));
    json_array_append_new(req->response, item);

done:
    if (db) caldav_close(db);
    json_decref(set);
    return r;
}

static int getCalendarEventUpdates(struct jmap_req *req)
{
    int r, pe;
    json_t *invalid;
    struct caldav_db *db;
    const char *since;
    modseq_t oldmodseq;
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
    pe = jmap_readprop(req->args, "sinceState", 1 /*mandatory*/, invalid, "s", &since);
    if (pe > 0) {
        oldmodseq = str2uint64(since);
        if (!oldmodseq) {
            json_array_append_new(invalid, json_string("sinceState"));
        }
    }
    pe = jmap_readprop(req->args, "maxChanges", 0 /*mandatory*/, invalid, "i", &maxChanges);
    if (pe > 0) {
        if (maxChanges <= 0) {
            json_array_append_new(invalid, json_string("maxChanges"));
        }
    }
    jmap_readprop(req->args, "fetchRecords", 0 /*mandatory*/, invalid, "b", &dofetch);
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

    buf_printf(&buf, "%llu", newstate);
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
    if (dofetch && json_array_size(rock.changed)) {
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

enum calevent_filter_kind {
    JMAP_CALFILTER_KIND_COND = 0,
    JMAP_CALFILTER_KIND_OPER
};
enum calevent_filter_op   {
    JMAP_CALFILTER_OP_NONE = 0,
    JMAP_CALFILTER_OP_AND,
    JMAP_CALFILTER_OP_OR,
    JMAP_CALFILTER_OP_NOT
};

typedef struct calevent_filter {
    enum calevent_filter_kind kind;
    enum calevent_filter_op op;

    struct calevent_filter **conditions;
    size_t n_conditions;

    hash_table *calendars;
    icaltimetype after;
    icaltimetype before;
    const char *text;
    const char *summary;
    const char *description;
    const char *location;
    const char *organizer;
    const char *attendee;
} calevent_filter;

/* Match text with icalproperty kind in VEVENT comp and its recurrences. */
static int calevent_filter_matchprop(icalcomponent *comp,
                                     const char *text,
                                     icalproperty_kind kind) {
    icalproperty *prop;
    icalcomponent *ical;

    if (icalcomponent_isa(comp) != ICAL_VEVENT_COMPONENT) {
        return 0;
    }

    /* Look for text in comp. */
    for (prop = icalcomponent_get_first_property(comp, kind);
         prop;
         prop = icalcomponent_get_next_property(comp, kind)) {
        const char *val = icalproperty_get_value_as_string(prop);
        /* XXX This isn't really according the JMAP spec, which requires phrase
         * matching and some other magic. Besides, it's really not efficient.
         * Check what other options we have to search text. */
        if (val && stristr(val, text)) {
            return 1;
        }
    }

    ical = icalcomponent_get_parent(comp);
    if (!ical || icalcomponent_isa(ical) != ICAL_VCALENDAR_COMPONENT) {
        return 0;
    }

    /* Look for text in any recurrence of comp. */
    for (comp = icalcomponent_get_first_component(ical, ICAL_VEVENT_COMPONENT);
         comp;
         comp = icalcomponent_get_next_component(ical, ICAL_VEVENT_COMPONENT)) {
        if (!icalcomponent_get_first_property(comp, ICAL_RECURRENCEID_PROPERTY)) {
            continue;
        }
        for (prop = icalcomponent_get_first_property(comp, kind);
                prop;
                prop = icalcomponent_get_next_property(comp, kind)) {
            const char *val = icalproperty_get_value_as_string(prop);
            /* XXX string matching */
            if (val && stristr(val, text)) {
                return 1;
            }
        }
    }

    return 0;
}

/* Match the VEVENTs contained in VCALENDAR component ical against filter. */
static int calevent_filter_matches(calevent_filter *f,
                                   struct caldav_data *cdata,
                                   icalcomponent *ical)
{
    if (f->kind == JMAP_CALFILTER_KIND_OPER) {
        size_t i;
        for (i = 0; i < f->n_conditions; i++) {
            int m = calevent_filter_matches(f->conditions[i], cdata, ical);
            if (m && f->op == JMAP_CALFILTER_OP_OR) {
                return 1;
            } else if (m && f->op == JMAP_CALFILTER_OP_NOT) {
                return 0;
            } else if (!m && f->op == JMAP_CALFILTER_OP_AND) {
                return 0;
            }
        }
        return f->op == JMAP_CALFILTER_OP_AND || f->op == JMAP_CALFILTER_OP_NOT;
    } else {
        /* Locate main VEVENT. */
        /* XXX Might save comp and dtend, dtstart in the rock to avoid
         * recalculating them. First wait for the decision if we want to
         * optimize here or move filtering to the SQL layer. */
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
        if (!icaltime_is_null_time(f->after)) {
            icaltimetype dtend = icaltime_from_string(cdata->dtend);
            if (icaltime_compare(dtend, f->after) <= 0) {
                return 0;
            }
        }
        /* before */
        if (!icaltime_is_null_time(f->before)) {
            icaltimetype dtstart = icaltime_from_string(cdata->dtstart);
            if (icaltime_compare(dtstart, f->before) >= 0) {
                return 0;
            }
        }
        /* text */
        if (f->text) {
            int m = calevent_filter_matchprop(comp, f->text, ICAL_SUMMARY_PROPERTY);
            if (!m) calevent_filter_matchprop(comp, f->text, ICAL_DESCRIPTION_PROPERTY);
            if (!m) calevent_filter_matchprop(comp, f->text, ICAL_LOCATION_PROPERTY);
            if (!m) calevent_filter_matchprop(comp, f->text, ICAL_ORGANIZER_PROPERTY);
            if (!m) calevent_filter_matchprop(comp, f->text, ICAL_ATTENDEE_PROPERTY);
            if (!m) {
                return 0;
            }
        }
        if ((f->summary && !calevent_filter_matchprop(comp, f->summary, ICAL_SUMMARY_PROPERTY)) ||
            (f->description && !calevent_filter_matchprop(comp, f->description, ICAL_DESCRIPTION_PROPERTY)) ||
            (f->location && !calevent_filter_matchprop(comp, f->location, ICAL_LOCATION_PROPERTY)) ||
            (f->organizer && !calevent_filter_matchprop(comp, f->organizer, ICAL_ORGANIZER_PROPERTY)) ||
            (f->attendee && !calevent_filter_matchprop(comp, f->attendee, ICAL_ATTENDEE_PROPERTY))) {
            return 0;
        }

        /* All matched. */
        return 1;
    }
}

/* Free the memory allocated by this calendar event filter. */
static void calevent_filter_free(calevent_filter **ff)
{
    size_t i;
    calevent_filter *f = *ff;
    for (i = 0; i < f->n_conditions; i++) {
        calevent_filter_free(&f->conditions[i]);
    }
    if (f->conditions) free(f->conditions);
    if (f->calendars) {
        free_hash_table(f->calendars, NULL);
        free(f->calendars);
    }
    free(f);
    *ff = NULL;
}

/* Parse the JMAP calendar event FilterOperator or FilterCondition in arg.
 * Report any invalid properties in invalid, prefixed by prefix.
 * Return NULL on error. */
static calevent_filter *calevent_filter_parse(json_t *arg,
                                              const char *prefix,
                                              json_t *invalid)
{
    calevent_filter *f = (calevent_filter *) xzmalloc(sizeof(struct calevent_filter));
    int pe;
    const char *val;
    struct buf buf = BUF_INITIALIZER;
    int iscond = 1;

    /* operator */
    pe = jmap_readprop_full(arg, prefix, "operator", 0 /*mandatory*/, invalid, "s", &val);
    if (pe > 0) {
        f->kind = JMAP_CALFILTER_KIND_OPER;
        if (!strncmp("AND", val, 3)) {
            f->op = JMAP_CALFILTER_OP_AND;
        } else if (!strncmp("OR", val, 2)) {
            f->op = JMAP_CALFILTER_OP_OR;
        } else if (!strncmp("NOT", val, 3)) {
            f->op = JMAP_CALFILTER_OP_NOT;
        } else {
            buf_printf(&buf, "%s.%s", prefix, "operator");
            json_array_append_new(invalid, json_string(buf_cstring(&buf)));
            buf_reset(&buf);
        }
    }
    iscond = f->kind == JMAP_CALFILTER_KIND_COND;

    /* conditions */
    json_t *conds = json_object_get(arg, "conditions");
    if (conds && !iscond && json_array_size(conds)) {
        f->n_conditions = json_array_size(conds);
        f->conditions = xmalloc(sizeof(struct calevent_filter*) * f->n_conditions);
        size_t i;
        for (i = 0; i < f->n_conditions; i++) {
            json_t *cond = json_array_get(conds, i);
            buf_printf(&buf, "%s.conditions[%zu]", prefix, i);
            f->conditions[i] = calevent_filter_parse(cond, buf_cstring(&buf), invalid);
            buf_reset(&buf);
        }
    } else if (conds && conds != json_null()) {
        buf_printf(&buf, "%s.%s", prefix, "conditions");
        json_array_append_new(invalid, json_string(buf_cstring(&buf)));
        buf_reset(&buf);
    }

    /* inCalendars */
    json_t *cals = json_object_get(arg, "inCalendars");
    if (cals && iscond && json_array_size(cals)) {
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
    } else if (cals && cals != json_null()) {
        buf_printf(&buf, "%s.%s", prefix, "inCalendars");
        json_array_append_new(invalid, json_string(buf_cstring(&buf)));
        buf_reset(&buf);
    }

    /* after */
    if (json_object_get(arg, "after") != json_null()) {
        pe = jmap_readprop_full(arg, prefix, "after", 0 /*mandatory*/, invalid, "s", &val);
        if (pe > 0) {
            if (jmap_date_to_icaltime(val, &f->after, 0 /*isAllDay*/) || !iscond) {
                buf_printf(&buf, "%s.%s", prefix, "after");
                json_array_append_new(invalid, json_string(buf_cstring(&buf)));
                buf_reset(&buf);
            }
        }
    }

    /* before */
    if (json_object_get(arg, "before") != json_null()) {
        pe = jmap_readprop_full(arg, prefix, "before", 0 /*mandatory*/, invalid, "s", &val);
        if (pe > 0) {
            if (jmap_date_to_icaltime(val, &f->before, 0 /*isAllDay*/) || !iscond) {
                buf_printf(&buf, "%s.%s", prefix, "before");
                json_array_append_new(invalid, json_string(buf_cstring(&buf)));
                buf_reset(&buf);
            }
        }
    }

    /* text */
    if (json_object_get(arg, "text") != json_null()) {
        pe = jmap_readprop_full(arg, prefix, "text", 0 /*mandatory */, invalid, "s", &f->text);
        if (pe > 0 && !iscond) {
            buf_printf(&buf, "%s.%s", prefix, "text");
            json_array_append_new(invalid, json_string(buf_cstring(&buf)));
            buf_reset(&buf);
        }
    }

    /* summary */
    if (json_object_get(arg, "summary") != json_null()) {
        pe = jmap_readprop_full(arg, prefix, "summary", 0 /*mandatory */, invalid, "s", &f->summary);
        if (pe > 0 && !iscond) {
            buf_printf(&buf, "%s.%s", prefix, "summary");
            json_array_append_new(invalid, json_string(buf_cstring(&buf)));
            buf_reset(&buf);
        }
    }

    /* description */
    if (json_object_get(arg, "description") != json_null()) {
        pe = jmap_readprop_full(arg, prefix, "description", 0 /*mandatory */, invalid, "s", &f->description);
        if (pe > 0 && !iscond) {
            buf_printf(&buf, "%s.%s", prefix, "description");
            json_array_append_new(invalid, json_string(buf_cstring(&buf)));
            buf_reset(&buf);
        }
    }

    /* location */
    if (json_object_get(arg, "location") != json_null()) {
        pe = jmap_readprop_full(arg, prefix, "location", 0 /*mandatory */, invalid, "s", &f->location);
        if (pe > 0 && !iscond) {
            buf_printf(&buf, "%s.%s", prefix, "location");
            json_array_append_new(invalid, json_string(buf_cstring(&buf)));
            buf_reset(&buf);
        }
    }

    /* organizer */
    if (json_object_get(arg, "organizer") != json_null()) {
        pe = jmap_readprop_full(arg, prefix, "organizer", 0 /*mandatory */, invalid, "s", &f->organizer);
        if (pe > 0 && !iscond) {
            buf_printf(&buf, "%s.%s", prefix, "organizer");
            json_array_append_new(invalid, json_string(buf_cstring(&buf)));
            buf_reset(&buf);
        }
    }

    /* attendee */
    if (json_object_get(arg, "attendee") != json_null()) {
        pe = jmap_readprop_full(arg, prefix, "attendee", 0 /*mandatory */, invalid, "s", &f->attendee);
        if (pe > 0 && !iscond) {
            buf_printf(&buf, "%s.%s", prefix, "attendee");
            json_array_append_new(invalid, json_string(buf_cstring(&buf)));
            buf_reset(&buf);
        }
    }

    if (json_array_size(invalid)) {
        calevent_filter_free(&f);
    }

    buf_free(&buf);

    return f;
}

struct caleventlist_rock {
    calevent_filter *filter;
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
    ical = record_to_ical(crock->mailbox, &record);
    if (!ical) {
        syslog(LOG_ERR, "record_to_ical failed for record %u:%s",
                cdata->dav.imap_uid, crock->mailbox->name);
        r = IMAP_INTERNAL;
        goto done;
    }

    /* Match the event against the filter and update statistics. */
    if (crock->filter && !calevent_filter_matches(crock->filter, cdata, ical)) {
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
    if (filter && filter != json_null()) {
        rock.filter = calevent_filter_parse(filter, "filter", invalid);
    }

    /* position */
    json_int_t pos = 0;
    if (json_object_get(req->args, "position") != json_null()) {
        pe = jmap_readprop(req->args, "position", 0 /*mandatory*/, invalid, "i", &pos);
        if (pe > 0 && pos < 0) {
            json_array_append_new(invalid, json_string("position"));
        }
    }
    rock.position = pos;

    /* limit */
    json_int_t limit = 0;
    if (json_object_get(req->args, "limit") != json_null()) {
        pe = jmap_readprop(req->args, "limit", 0 /*mandatory*/, invalid, "i", &limit);
        if (pe > 0 && limit < 0) {
            json_array_append_new(invalid, json_string("limit"));
        }
    }
    rock.limit = limit;

    /* fetchCalendarEvents */
    if (json_object_get(req->args, "fetchCalendarEvents") != json_null()) {
        jmap_readprop(req->args, "fetchCalendarEvents", 0 /*mandatory*/, invalid, "b", &dofetch);
    }

    if (json_array_size(invalid)) {
        json_t *err = json_pack("{s:s, s:o}", "type", "invalidArguments", "arguments", invalid);
        json_array_append_new(req->response, json_pack("[s,o,s]", "error", err, req->tag));
        r = 0;
        goto done;
    }
    json_decref(invalid);

    /* Inspect every entry in this accounts mailbox. */
    rock.events = json_pack("[]");
    r = caldav_foreach(db, NULL, getcalendareventlist_cb, &rock);
    if (rock.mailbox) mailbox_close(&rock.mailbox);
    if (r) goto done;

    /* Prepare response. */
    json_t *eventList = json_pack("{}");
    json_object_set_new(eventList, "accountId", json_string(req->userid));
    json_object_set_new(eventList, "state", json_string(req->state));
    json_object_set_new(eventList, "position", json_integer(rock.position));
    json_object_set_new(eventList, "total", json_integer(rock.total));
    json_object_set(eventList, "calendarEventIds", rock.events);

    json_t *item = json_pack("[]");
    json_array_append_new(item, json_string("calendarEventList"));
    json_array_append_new(item, eventList);
    json_array_append_new(item, json_string(req->tag));
    json_array_append_new(req->response, item);

    /* Fetch updated records, if requested. */
    if (dofetch && json_array_size(rock.events)) {
        struct jmap_req subreq = *req;
        subreq.args = json_pack("{}");
        json_object_set(subreq.args, "ids", rock.events);
        r = getCalendarEvents(&subreq);
        json_decref(subreq.args);
    }

done:
    if (rock.filter) calevent_filter_free(&rock.filter);
    if (rock.events) json_decref(rock.events);
    if (db) caldav_close(db);
    return r;
}

/* XXX The following JMAP methods are not defined in the spec. */

static int getCalendarPreferences(struct jmap_req *req)
{
    /* XXX Just a dummy implementation to make the JMAP web client happy while
     * testing. */
    json_t *item = json_pack("[]");
    json_array_append_new(item, json_string("calendarPreferences"));
    json_array_append_new(item, json_pack("{}"));
    json_array_append_new(item, json_string(req->tag));
    json_array_append_new(req->response, item);
    return 0;
}

static int getPersonalities(struct jmap_req *req)
{
    /* XXX Just a dummy implementation to make the JMAP web client happy while
     * testing. */
    json_t *item = json_pack("[]");
    json_array_append_new(item, json_string("personalities"));

    json_t *obj = json_pack("{}");
    json_object_set_new(obj, "id", json_string("1"));
    json_array_append_new(item, json_pack("{s:o}", "list", json_pack("[o]", obj)));

    /* Echo back the currently authenticated user's personality. */
    char *id = xstrdup(req->userid);
    char *p = strchr(id, '@'); if (p) { *p = 0; }
    json_object_set_new(obj, "name", json_string(id));
    free(id);
    json_object_set_new(obj, "email", json_string(req->userid));

    json_array_append_new(item, json_string(req->tag));
    json_array_append_new(req->response, item);
    return 0;
}

static int getPreferences(struct jmap_req *req)
{
    /* XXX Just a dummy implementation to make the JMAP web client happy while
     * testing. */
    json_t *item = json_pack("[]");
    json_array_append_new(item, json_string("preferences"));
    json_array_append_new(item, json_pack("{s:s}", "defaultPersonalityId", "1"));
    json_array_append_new(item, json_string(req->tag));
    json_array_append_new(req->response, item);
    return 0;
}
