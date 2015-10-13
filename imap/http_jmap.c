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
static int setCalendars(struct jmap_req *req);
static int getCalendarEvents(struct jmap_req *req);
static int setCalendarEvents(struct jmap_req *req);

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
    { "setCalendars",           &setCalendars },
    { "getCalendarEvents",      &getCalendarEvents },
    { "setCalendarEvents",      &setCalendarEvents },
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

static int getupdates_cb(void *rock, struct carddav_data *cdata)
{
    struct updates_rock *urock = (struct updates_rock *) rock;

    if (cdata->dav.alive) {
        json_array_append_new(urock->changed, json_string(cdata->vcard_uid));
    }
    else {
        json_array_append_new(urock->removed, json_string(cdata->vcard_uid));
    }

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
                            &getupdates_cb, &rock);
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
                            &getupdates_cb, &rock);
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

/* Return a non-zero value if uid maps to a special-purpose calendar mailbox,
 * that may not be read or modified by the user. */
static int _jmap_calendar_ishidden(const char *uid) {
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

/*
    id: String The id of the calendar. This property is immutable.
    name: String The user-visible name of the calendar. This may be any UTF-8 string of at least 1 character in length and maximum 256 bytes in size.
    color: String Any valid CSS color value. The color to be used when displaying events associated with the calendar. The color SHOULD have sufficient contrast to be used as text on a white background.
    sortOrder: Number Defines the sort order of calendars when presented in the UI, so it is consistent between devices. The number MUST be an integer in the range 0 <= sortOrder < 2^31.
    isVisible: Boolean Should the calendar’s events be displayed to the user at the moment?
    mayReadFreeBusy: Boolean The user may read the free-busy information for this calendar. In JMAP terms, this means the user may use this calendar as part of a filter in a getCalendarEventList call, however unless mayRead == true, the events returned for this calendar will only contain free-busy information, and be stripped of any other data. This property MUST be true if mayRead is true.
    mayReadItems: Boolean The user may fetch the events in this calendar. In JMAP terms, this means the user may use this calendar as part of a filter in a getCalendarEventList call
    mayAddItems: Boolean The user may add events to this calendar. In JMAP terms, this means the user may call setCalendarEvents to create new events in this calendar or move existing events into this calendar from another calenadr. This property MUST be false if the account to which this calendar belongs has the isReadOnly property set to true.
    mayModifyItems: Boolean The user may edit events in this calendar by calling setCalendarEvents with the update argument referencing events in this collection. This property MUST be false if the account to which this calendar belongs has the isReadOnly property set to true.
    mayRemoveItems: Boolean The user may remove events from this calendar by calling setCalendarEvents with the destroy argument referencing events in this collection, or by updating their calendarId property to a different calendar. This property MUST be false if the account to which this calendar belongs has the isReadOnly property set to true.
    mayRename: Boolean The user may rename the calendar. This property MUST be false if the account to which this calendar belongs has the isReadOnly property set to true.
    mayDelete: Boolean The user may delete the calendar itself. This property MUST be false if the account to which this calendar belongs has the isReadOnly property set to true.
*/

static int getcalendars_cb(const mbentry_t *mbentry, void *rock)
{
    struct calendars_rock *crock = (struct calendars_rock *)rock;

    /* only calendars... */
    if (!(mbentry->mbtype & MBTYPE_CALENDAR)) return 0;

    /* ...which are at least readable or visible */
    int rights = httpd_myrights(crock->req->authstate, mbentry->acl);
    /* XXX - What if just READFB is set? */
    if (!(rights & (DACL_READ|DACL_READFB))) {
        return 0;
    }

    /* OK, we want this one */
    const char *collection = strrchr(mbentry->name, '.') + 1;

    /* unless it's one of the special names... XXX - check
     * the specialuse magic on these instead */
    if (_jmap_calendar_ishidden(collection)) return 0;
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
        static const char *displayname_annot =
            DAV_ANNOT_NS "<" XML_NS_DAV ">displayname";
        struct buf attrib = BUF_INITIALIZER;
        int r = annotatemore_lookupmask(mbentry->name, displayname_annot, httpd_userid, &attrib);
        /* fall back to last part of mailbox name */
        if (r || !attrib.len) buf_setcstr(&attrib, collection);
        json_object_set_new(obj, "name", json_string(buf_cstring(&attrib)));
        buf_free(&attrib);
    }

    if (_wantprop(crock->props, "color")) {
        static const char *color_annot =
            DAV_ANNOT_NS "<" XML_NS_APPLE ">calendar-color";
        struct buf attrib = BUF_INITIALIZER;
        int r = annotatemore_lookupmask(mbentry->name, color_annot, httpd_userid, &attrib);
        if (!r && attrib.len)
            json_object_set_new(obj, "color", json_string(buf_cstring(&attrib)));
        buf_free(&attrib);
    }

    if (_wantprop(crock->props, "sortOrder")) {
        static const char *order_annot =
            DAV_ANNOT_NS "<" XML_NS_APPLE ">calendar-order";
        struct buf attrib = BUF_INITIALIZER;
        int r = annotatemore_lookupmask(mbentry->name, order_annot, httpd_userid, &attrib);
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
        static const char *color_annot =
            DAV_ANNOT_NS "<" XML_NS_CALDAV ">X-FM-isVisible";
        struct buf attrib = BUF_INITIALIZER;
        int r = annotatemore_lookupmask(mbentry->name, color_annot, httpd_userid, &attrib);
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

    return 0;
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
        char *ptr;
        modseq_t clientState = strtoull(ifInState, &ptr, 10);
        if (!ptr || *ptr != '\0') {
            json_t *item = json_pack("[s, {s:s}, s]",
                                     "error", "type", "stateMismatch",
                                     req->tag);
            json_array_append_new(req->response, item);
            return -2;
        }
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
    if (r) return r;

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

static int setCalendars(struct jmap_req *req)
{
    int r = jmap_checkstate(req, MBTYPE_CALENDAR);
    if (r) return 0;

    json_t *set = json_pack("{s:s}", "accountId", req->userid);
    r = jmap_setstate(req, set, "oldState", MBTYPE_CALENDAR, 0 /*refresh*/, 0 /*bump*/);
    if (r) goto done;

    r = caldav_create_defaultcalendars(req->userid);
    if (r) goto done;

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
            if (_jmap_calendar_ishidden(uid)) {
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
            if (!strlen(uid) || *uid == '#' || _jmap_calendar_ishidden(uid)) {
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
static int _jmap_timet_to_localdate(time_t t, char* buf, size_t size) {
    int n = time_to_rfc3339(t, buf, size);
    if (n && buf[n-1] == 'Z') {
        buf[n-1] = '\0';
        n--;
    }
    return n;
}

/* Convert the JMAP local datetime in buf to a type tm. Return 0 on success. */
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

/* Convert the JMAP local datetime in buf to ical. Return 0 on success. */
static int jmap_localdate_to_icaltime_with_zone(const char *buf,
                                                icaltimetype *tgdt,
                                                icaltimezone *tz) {
    struct tm tm;
    int r;
    char *s = NULL;
    icaltimetype dt;

    r = jmap_localdate_to_tm(buf, &tm);
    if (r) return r;

    /* Can't use icaltime_from_timet_with_zone since it tries to convert
     * t from UTC into tz. Let's feed ical a DATETIME string, instead. */
    s = xzmalloc(16);
    strftime(s, 16, "%Y%m%dT%H%M%S", &tm);
    dt = icaltime_from_string(s);
    free(s);
    if (icaltime_is_null_time(dt)) {
        return -1;
    }
    dt.zone = tz;
    *tgdt = dt;
    return 0;
}

/* Convert icaltime to a RFC3339 formatted localdate string. The returned
 * string is owned by the caller. Return NULL on error. */
static char* jmap_icaltime_to_localdate_r(icaltimetype icaltime) {
    char *s;
    time_t t;

    s = xmalloc(RFC3339_DATETIME_MAX);
    t = icaltime_as_timet(icaltime);
    if (!_jmap_timet_to_localdate(t, s, RFC3339_DATETIME_MAX)) {
        return NULL;
    }
    return s;
}

/* Compare int in ascending order. */
static int _jmap_intcmp(const void *aa, const void *bb)
{
    const int *a = aa, *b = bb;
    return (*a < *b) ? -1 : (*a > *b);
}

/* Compare time_t in ascending order. */
static int _jmap_timetcmp(const void *aa, const void *bb)
{
    const time_t *a = aa, *b = bb;
    return (*a < *b) ? -1 : (*a > *b);
}

/* Return the identity of i. This is a helper for recur_byX. */
static int _jmap_intident(int i) {
    return i;
}

/*  Convert libicals internal by_day encoding to JMAP byday. */
static int _jmap_icalbyday_to_byday(int i) {
    int w = icalrecurrencetype_day_position(i);
    int d = icalrecurrencetype_day_day_of_week(i);
    if (d) {
        /* XXX - for now, we treat libical's ANY day as SU. */
        d--;
    }
    return d + 7*w;
}

/*  Convert libicals internal by_month encoding to JMAP byday. */
static int _jmap_icalbymonth_to_bymonth(int i) {
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
    qsort(tmp, n, sizeof(int), _jmap_intcmp);
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
                    ICAL_BY_DAY_SIZE, &_jmap_icalbyday_to_byday));
    }
    if (recur.by_month_day[0] != ICAL_RECURRENCE_ARRAY_MAX) {
        json_object_set_new(jrecur, "byDate",
                jmap_recurrence_byX_from_ical(recur.by_month_day,
                    ICAL_BY_MONTHDAY_SIZE, &_jmap_intident));
    }
    if (recur.by_month[0] != ICAL_RECURRENCE_ARRAY_MAX) {
        json_object_set_new(jrecur, "byMonth",
                jmap_recurrence_byX_from_ical(recur.by_month,
                    ICAL_BY_MONTH_SIZE, &_jmap_icalbymonth_to_bymonth));
    }
    if (recur.by_year_day[0] != ICAL_RECURRENCE_ARRAY_MAX) {
        json_object_set_new(jrecur, "byYearDay",
                jmap_recurrence_byX_from_ical(recur.by_year_day,
                    ICAL_BY_YEARDAY_SIZE, &_jmap_intident));
    }
    if (recur.by_month[0] != ICAL_RECURRENCE_ARRAY_MAX) {
        json_object_set_new(jrecur, "byWeekNo",
                jmap_recurrence_byX_from_ical(recur.by_month,
                    ICAL_BY_MONTH_SIZE, &_jmap_intident));
    }
    if (recur.by_hour[0] != ICAL_RECURRENCE_ARRAY_MAX) {
        json_object_set_new(jrecur, "byHour",
                jmap_recurrence_byX_from_ical(recur.by_hour,
                    ICAL_BY_HOUR_SIZE, &_jmap_intident));
    }
    if (recur.by_minute[0] != ICAL_RECURRENCE_ARRAY_MAX) {
        json_object_set_new(jrecur, "byMinute",
                jmap_recurrence_byX_from_ical(recur.by_minute,
                    ICAL_BY_MINUTE_SIZE, &_jmap_intident));
    }
    if (recur.by_second[0] != ICAL_RECURRENCE_ARRAY_MAX) {
        json_object_set_new(jrecur, "bySecond",
                jmap_recurrence_byX_from_ical(recur.by_second,
                    ICAL_BY_SECOND_SIZE, &_jmap_intident));
    }
    if (recur.by_set_pos[0] != ICAL_RECURRENCE_ARRAY_MAX) {
        json_object_set_new(jrecur, "bySetPosition",
                jmap_recurrence_byX_from_ical(recur.by_set_pos,
                    ICAL_BY_SETPOS_SIZE, &_jmap_intident));
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
    qsort(incl, nincl, sizeof(time_t), &_jmap_timetcmp);

    /* Convert incl to JMAP LocalDate. */
    ret = json_pack("[]");
    for (i = 0; i < nincl; ++i) {
        int n = _jmap_timet_to_localdate(incl[i], timebuf, RFC3339_DATETIME_MAX);
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
        if (sparam.userid) {
            /* XXX - caladdress_lookup leaks. Once
             * caldav_fix_schedparam_memleak is merged, call
             * sched_param_free here. */
            free(sparam.userid);
        }
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
        *organizer = NULL;
        *attendees = NULL;
    }
    if (org) json_decref(org);
    if (atts) json_decref(atts);
}

static const char *jmap_tzid_from_ical(icalcomponent *comp, icalproperty_kind kind) {
    const char *tzid = NULL;
    icalproperty *prop;
    icalparameter *param;

    prop = icalcomponent_get_first_property(comp, ICAL_DTSTART_PROPERTY);
    if (prop) param = icalproperty_get_first_parameter(prop, ICAL_TZID_PARAMETER);
    if (param) tzid = icalparameter_get_tzid(param);
    /* Check if the tzid already corresponds to an Olson name. */
    if (tzid) {
        icaltimezone *tz = icaltimezone_get_builtin_timezone(tzid);
        if (!tz) {
            /* Try to guess the timezone. */
            icalvalue *val = icalproperty_get_value(prop);
            icaltimetype dt = icalvalue_get_datetime(val);
            tzid = dt.zone ? icaltimezone_get_location((icaltimezone*) dt.zone) : NULL;
            tzid = tzid && icaltimezone_get_builtin_timezone(tzid) ? tzid : NULL;
        }
    }
    return tzid;
}

/* Convert the libical VEVENT comp to a CalendarEvent, excluding the
 * exceptions property. If exc is true, only convert properties that are
 * valid for exceptions. If userid is not NULL it will be used to identify
 * participants.
 * Only convert the properties named in props. */
static json_t* jmap_vevent_to_calendarevent(icalcomponent *comp,
                                            struct hash_table *props,
                                            short exc,
                                            const char *userid) {
    icalproperty* prop;
    json_t *obj;

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
        json_object_set_new(obj, "summary",
                prop ? json_string(icalproperty_get_value_as_string(prop)) : json_string(""));
    }

    /* description */
    if (_wantprop(props, "description")) {
        prop = icalcomponent_get_first_property(comp, ICAL_DESCRIPTION_PROPERTY);
        json_object_set_new(obj, "description",
            prop ? json_string(icalproperty_get_value_as_string(prop)) : json_string(""));
    }

    /* location */
    if (_wantprop(props, "location")) {
        prop = icalcomponent_get_first_property(comp, ICAL_LOCATION_PROPERTY);
        json_object_set_new(obj, "location",
            prop ? json_string(icalproperty_get_value_as_string(prop)) : json_string(""));
    }

    /* showAsFree */
    if (_wantprop(props, "showAsFree")) {
        prop = icalcomponent_get_first_property(comp, ICAL_TRANSP_PROPERTY);
        json_object_set_new(obj, "showAsFree",
                json_boolean(prop &&
                    !strcmp(icalproperty_get_value_as_string(prop), "TRANSPARENT")));
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
        char *s = jmap_icaltime_to_localdate_r(dt);
        json_object_set_new(obj, "end", json_string(s));
        free(s);
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
        if (!tzidend) tzidend = tzidstart;
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
    if (_wantprop(props, "alerts")) {
        json_object_set_new(obj, "alerts", jmap_alerts_from_ical(comp));
    }

    /* organizer and attendees */
    if (_wantprop(props, "organizer") || _wantprop(props, "attendees")) {
        json_t *organizer, *attendees;
        jmap_participants_from_ical(comp, &organizer, &attendees, userid);
        if (organizer && _wantprop(props, "organizer")) {
            json_object_set_new(obj, "organizer", organizer);
        }
        if (attendees && _wantprop(props, "attendees")) {
            json_object_set_new(obj, "attendees", attendees);
        }
    }

    /* attachments */
    if (_wantprop(props, "attachments") && !exc) {
        /* XXX - Implement this */
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
    obj = jmap_vevent_to_calendarevent(comp, crock->props, 0 /* exc */, userid);
    if (!obj) goto done;
    json_object_set_new(obj, "id", json_string(cdata->ical_uid));

    /* Add optional exceptions. */
    if (_wantprop(crock->props, "exceptions")) {
        json_t* excobj = json_pack("{}");

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
        for (comp = icalcomponent_get_first_component(ical, ICAL_VEVENT_COMPONENT);
             comp;
             comp = icalcomponent_get_next_component(ical, ICAL_VEVENT_COMPONENT)) {

            if (!icalcomponent_get_first_property(comp, ICAL_RECURRENCEID_PROPERTY)) {
                continue;
            }

            json_t *exc = jmap_vevent_to_calendarevent(comp, crock->props, 1 /* exc */, userid);
            if (!exc) {
                continue;
            }
            struct icaltimetype dtstart = icalcomponent_get_dtstart(comp);
            char *s = jmap_icaltime_to_localdate_r(dtstart);
            json_object_set_new(excobj, s, exc);
            free(s);
        }
        if (json_object_size(excobj)) {
            json_object_set(obj, "exceptions", excobj);
        }
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
    if (r) return r;

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

/* XXX - sanitize forward declarations. */

/* Create or update the VEVENT comp with the properties of the JMAP calendar
 * event. The VEVENT must have a VCALENDAR as parent and its timezones might
 * get rewritten. If uid is non-zero, set the VEVENT uid and any recurrence
 * exceptions to this UID. */
static void jmap_calendarevent_to_ical(icalcomponent *comp,
                                       json_t *event,
                                       int flags,
                                       const char *uid,
                                       json_t *invalid,
                                       struct jmap_req *req);

/* Helper flags for setCalendarEvents */
#define JMAP_CREATE (1<<0)
#define JMAP_EXC    (1<<1)

/* Replace the datetime property kind in comp. If tz is not NULL, set
 * the TZID parameter on the property. */
static void jmap_update_ical_dtprop(icalcomponent *comp,
                               icaltimetype dt,
                               icaltimezone *tz,
                               enum icalproperty_kind kind) {
    /* Purge the existing property. */
    icalproperty *prop = icalcomponent_get_first_property(comp, kind);
    if (prop) icalcomponent_remove_property(comp, prop);

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

/* Create or update the ORGANIZER/ATTENDEEs in the VEVENT component comp as
 * defined by the JMAP organizer and attendees. If create is not set, purge
 * any participants that are not updated. */
static void jmap_participants_to_ical(icalcomponent *comp,
                                      json_t *organizer,
                                      json_t *attendees,
                                      short create,
                                      json_t *invalid,
                                      struct jmap_req *req) {
    if (!create) {
        /* XXX - Purge existing participants. */
    }

    const char *name = NULL;
    const char *email = NULL;
    const char *rsvp = NULL;

    jmap_readprop_full(organizer, "organizer", "name", create, invalid, "s", &name);
    jmap_readprop_full(organizer, "organizer", "email", create, invalid, "s", &email);

    if (name && email) {
        icalproperty *prop = icalproperty_new_organizer(email);
        icalparameter *param = icalparameter_new_cn(name);
        icalproperty_add_parameter(prop, param);
        icalcomponent_add_property(comp, prop);
    }

    size_t i;
    json_t *att;
    struct buf buf = BUF_INITIALIZER;

    json_array_foreach(attendees, i, att) {
        char *prefix;
        icalparameter_partstat pst = ICAL_PARTSTAT_NONE;
        name = NULL;
        email = NULL;
        rsvp = NULL;

        buf_reset(&buf);
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

        /* XXX - Check attendee email for uniqueness. */

        if (name && email && pst != ICAL_PARTSTAT_NONE) {
            /* email */
            icalproperty *prop = icalproperty_new_attendee(email);
            icalparameter *param;

            /* name */
            param = icalparameter_new_cn(name);
            icalproperty_add_parameter(prop, param);

            /* partstat */
            param = icalparameter_new_partstat(pst);
            icalproperty_add_parameter(prop, param);

            icalcomponent_add_property(comp, prop);
        }

        free(prefix);
    }

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


/* Create or overwrite the VEVENT exceptions for VEVENT component comp as
 * defined by the JMAP exceptions. Use tz as timezone for LocalDate
 * conversions and uid as the recurrence ID. */
static void jmap_exceptions_to_ical(icalcomponent *comp,
                                    json_t *exceptions,
                                    int flags,
                                    json_t *invalid,
                                    const char *uid,
                                    icaltimezone *tz,
                                    struct jmap_req *req) {
    if (!(flags&JMAP_CREATE)) {
        /* XXX - Purge existing exceptions (that are not updated). */
        /* XXX - Purge existing EXDATEs. */
    }

    const char *key;
    json_t *exc;
    struct buf buf = BUF_INITIALIZER;
    icalcomponent *ical = icalcomponent_get_parent(comp);

    json_object_foreach(exceptions, key, exc) {
        char *prefix;

        buf_printf(&buf, "exceptions[%s]", key);
        prefix = xstrdup(buf_cstring(&buf));
        buf_reset(&buf);

        /* Parse key as LocalDate. */
        icaltimetype dt;
        if (jmap_localdate_to_icaltime_with_zone(key, &dt, tz)) {
            json_array_append_new(invalid, json_string(prefix));
            free(prefix);
            continue;
        }

        if (exc != json_null()) {
            json_t *invalidexc = json_pack("[]");
            size_t i;
            json_t *v;

            /* Add exceptional VEVENT component to the VCALENDAR. */
            icalcomponent *excomp = icalcomponent_new_vevent();
            icalcomponent_add_component(ical, excomp);
            jmap_calendarevent_to_ical(excomp, exc, JMAP_CREATE|JMAP_EXC, uid, invalidexc, req);

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
            jmap_update_ical_dtprop(comp, dt, tz, ICAL_EXDATE_PROPERTY);
        }

        free(prefix);
    }

    buf_free(&buf);
}

/* Create or overwrite the RDATEs in the VEVENT component comp as defined by the
 * JMAP recurrence. Use tz as timezone for LocalDate conversions. */
static void jmap_inclusions_to_ical(icalcomponent *comp,
                                    json_t *inclusions,
                                    short create,
                                    json_t *invalid,
                                    icaltimezone *tz) {

    if (!create) {
        /* XXX - Purge existing RDATEs. */
    }

    size_t i;
    json_t *incl;
    struct buf buf = BUF_INITIALIZER;

    json_array_foreach(inclusions, i, incl) {
        icaltimetype dt;

        /* Parse incl as LocalDate. */
        if (jmap_localdate_to_icaltime_with_zone(json_string_value(incl), &dt, tz)) {
            buf_printf(&buf, "inclusions[%llu]", (long long unsigned) i);
            json_array_append_new(invalid, json_string(buf_cstring(&buf)));
            buf_reset(&buf);
            continue;
        } 

        /* Create and add RDATE property. */
        jmap_update_ical_dtprop(comp, dt, tz, ICAL_RDATE_PROPERTY);
    }

    buf_free(&buf);
}

/* Create or overwrite the RRULE in the VEVENT component comp as defined by the
 * JMAP recurrence. Use tz as timezone for LocalDate conversions. */
static void jmap_recurrence_to_ical(icalcomponent *comp,
                                    json_t *recur,
                                    short create,
                                    json_t *invalid,
                                    icaltimezone *tz) {

    if (!create) {
        /* XXX - Purge existing RRULE. */
    }

    const char *prefix = "recurrence";
    const char *freq = NULL;
    struct buf buf = BUF_INITIALIZER;
    int pe;

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

        if (!jmap_localdate_to_icaltime_with_zone(until, &dtloc, tz)) {
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
 * JMAP alerts. If create is not set, purge any alerts that are not updated. */
static void jmap_alerts_to_ical(icalcomponent *comp,
                                json_t *alerts,
                                short create,
                                json_t *invalid,
                                struct jmap_req *req) {
    if (!create) {
        /* XXX - Purge existing alarms which do not match the new alerts. */
    }

    size_t i;
    json_t *alert;
    struct buf buf = BUF_INITIALIZER;

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
        pe = jmap_readprop_full(alert, prefix, "type", create, invalid, "s", &type);
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
        pe = jmap_readprop_full(alert, prefix, "minutesBefore", create, invalid, "i", &diff);
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
            /* XXX - how to determine these properties? */
            if (action == ICAL_ACTION_EMAIL) {
                prop = icalproperty_new_description("the body of an email alert");
                icalcomponent_add_property(alarm, prop);

                prop = icalproperty_new_summary("the subject of an email alert");
                icalcomponent_add_property(alarm, prop);

                buf_printf(&buf, "MAILTO:%s", req->userid);
                prop = icalproperty_new_attendee(buf_cstring(&buf));
                buf_reset(&buf);
                icalcomponent_add_property(alarm, prop);
            } else {
                prop = icalproperty_new_description("a display alert");
                icalcomponent_add_property(alarm, prop);
            }

            /* Add VALARM to VEVENT. */
            icalcomponent_add_component(comp, alarm);
        }
        free(prefix);
    }

    buf_free(&buf);
}

static void jmap_calendarevent_to_ical(icalcomponent *comp,
                                       json_t *event,
                                       int flags,
                                       const char *uid,
                                       json_t *invalid,
                                       struct jmap_req *req) {
    int pe; /* parse error */
    const char *val = NULL;
    int showAsFree = 0;
    int isAllDay = 0;
    struct icaltimetype dtstart = icaltime_null_time();
    struct icaltimetype dtend = icaltime_null_time();
    icaltimezone *tzdtstart = NULL;
    icaltimezone *tzdtend = NULL;
    icalproperty *prop = NULL;
    int create = flags & JMAP_CREATE;
    icalcomponent *ical = icalcomponent_get_parent(comp);

    /* uid */
    if (uid) {
        icalcomponent_set_uid(comp, uid);
    }

    /* summary */
    pe = jmap_readprop(event, "summary", 1, invalid, "s", &val);
    if (pe > 0) {
        icalcomponent_set_summary(comp, val);
    }

    /* description */
    pe = jmap_readprop(event, "description", 1, invalid, "s", &val);
    if (pe > 0) {
        icalcomponent_set_description(comp, val);
    } 

    /* location */
    pe = jmap_readprop(event, "location", 1, invalid, "s", &val);
    if (pe > 0) {
        icalcomponent_set_location(comp, val);
    } 

    /* showAsFree */
    pe = jmap_readprop(event, "showAsFree", 1, invalid, "b", &showAsFree);
    if (pe > 0) {
        enum icalproperty_transp v = showAsFree ? ICAL_TRANSP_TRANSPARENT : ICAL_TRANSP_OPAQUE;
        prop = icalcomponent_get_first_property(comp, ICAL_TRANSP_PROPERTY);
        if (prop) {
            icalproperty_set_transp(prop, v);
        } else {
            icalcomponent_add_property(comp, icalproperty_new_transp(v));
        }
    }

    /* startTimeZone */
    pe = jmap_readprop(event, "startTimeZone", 0, invalid, "s", &val);
    if (pe > 0) {
        tzdtstart = icaltimezone_get_builtin_timezone(val);
        if (!tzdtstart) {
            json_array_append_new(invalid, json_string("startTimeZone"));
        }
    }

    /* endTimeZone */
    pe = jmap_readprop(event, "endTimeZone", 0, invalid, "s", &val);
    if (pe > 0) {
        tzdtend = icaltimezone_get_builtin_timezone(val);
        if (!tzdtend) {
            json_array_append_new(invalid, json_string("endTimeZone"));
        }
    }

    /* start */
    pe = jmap_readprop(event, "start", 1, invalid, "s", &val);
    if (pe > 0) {
        if (!jmap_localdate_to_icaltime_with_zone(val, &dtstart, tzdtstart)) {
            jmap_update_ical_dtprop(comp, dtstart, tzdtstart, ICAL_DTSTART_PROPERTY);
            if (flags & JMAP_EXC) {
                jmap_update_ical_dtprop(comp, dtstart, tzdtstart, ICAL_RECURRENCEID_PROPERTY);
            }
        } else {
            json_array_append_new(invalid, json_string("start"));
        }
    }

    /* end */
    pe = jmap_readprop(event, "end", 1, invalid, "s", &val);
    if (pe > 0) {
        if (!jmap_localdate_to_icaltime_with_zone(val, &dtend, tzdtend)) {
            jmap_update_ical_dtprop(comp, dtend, tzdtend, ICAL_DTEND_PROPERTY);
        } else {
            json_array_append_new(invalid, json_string("end"));
        }
    }

    /* isAllDay */
    jmap_readprop(event, "isAllDay", 1, invalid, "b", &isAllDay);
    if (pe > 0 && !create) {
        /* XXX Validate that start/end meet the criteria of isAllDay. */
    }

    /* organizer and attendees */
    json_t *organizer = NULL;
    json_t *attendees = NULL;

    jmap_readprop(event, "organizer", 0, invalid, "o", &organizer);
    jmap_readprop(event, "attendees", 0, invalid, "o", &attendees);
    if (organizer && attendees && !json_array_size(attendees)) {
        json_array_append_new(invalid, json_string("attendees"));
        attendees = NULL;
    }
    if ((create && organizer && attendees) || (!create && (organizer || attendees))) {
        jmap_participants_to_ical(comp, organizer, attendees, create, invalid, req);
    }

    /* alerts */
    json_t *alerts = NULL;
    pe = jmap_readprop(event, "alerts", 0, invalid, "o", &alerts);
    if (pe > 0) {
        if (json_array_size(alerts)) {
            jmap_alerts_to_ical(comp, alerts, create, invalid, req);
        } else {
            json_array_append_new(invalid, json_string("alerts"));
        }
    }

    /* recurrence */
    json_t *recurrence = NULL;
    pe = jmap_readprop(event, "recurrence", 0, invalid, "o", &recurrence);
    if (pe > 0) {
        if (!(flags&JMAP_EXC)) {
            jmap_recurrence_to_ical(comp, recurrence, create, invalid, tzdtstart);
        } else {
            json_array_append_new(invalid, json_string("recurrence"));
        }
    }

    /* inclusions */
    json_t *inclusions = NULL;
    pe = jmap_readprop(event, "inclusions", 0, invalid, "o", &inclusions);
    if (pe > 0) {
        if (!(flags&JMAP_EXC) && json_array_size(inclusions)) {
            jmap_inclusions_to_ical(comp, inclusions, create, invalid, tzdtstart);
        } else {
            json_array_append_new(invalid, json_string("inclusions"));
        }
    }

    /* exceptions */
    json_t *exceptions = NULL;
    pe = jmap_readprop(event, "exceptions", 0, invalid, "o", &exceptions);
    if (pe > 0) {
        if (!(flags&JMAP_EXC) && json_object_size(exceptions)) {
            jmap_exceptions_to_ical(comp, exceptions, flags, invalid, uid, tzdtstart, req);
        } else {
            json_array_append_new(invalid, json_string("exceptions"));
        }
    }

    /* XXX - attachments */

    if (json_array_size(invalid)) {
        return;
    }

    if (!(flags&JMAP_EXC)) {
        /* XXX - purge unused and add new VTIMEZONEs (if any). */
        icaltimezone *tz = tzdtstart;
        if (tz) {
            icalcomponent *tzcomp = icalcomponent_new_clone(icaltimezone_get_component(tz));
            icalproperty *tzprop = icalcomponent_get_first_property(tzcomp, ICAL_TZID_PROPERTY);
            icalproperty_set_tzid(tzprop, icaltimezone_get_location(tz));
            /* XXX - truncation using dtend might not work for recurrences. */
            tzdist_truncate_vtimezone(tzcomp, &dtstart, &dtend);
            icalcomponent_add_component(ical, tzcomp);
        }
    }
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
    if (r) goto done;

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
            json_t *invalid = json_pack("[]");
            const char *calId = NULL;
            const char *id = NULL;
            char *uid = NULL;

            /* Validate calendar event id. */
            if (!strlen(key)) {
                json_t *err= json_pack("{s:s}", "type", "invalidArguments");
                json_object_set_new(notCreated, key, err);
                continue;
            }

            /* XXX - Clean this up after update is implemented. */

            /* Convert the calendar event to ical. */
            uid = xstrdup(makeuuid());
            jmap_readprop(arg, "calendarId", 1,  invalid, "s", &calId);
            if (calId && strlen(calId) == 0) {
                json_array_append_new(invalid, json_string("calendarId"));
            }
            jmap_readprop(arg, "id", 0, invalid, "s", &id);
            if (id != NULL) {
                json_array_append_new(invalid, json_string("id"));
            }

            /* Create the VCALENDAR component. */
            icalcomponent *ical = icalcomponent_new_vcalendar();
            icalproperty *prop;
            prop = icalproperty_new_version("2.0");
            icalcomponent_add_property(ical, prop);
            prop = icalproperty_new_calscale("GREGORIAN");
            icalcomponent_add_property(ical, prop);

            /* Convert the calendar event to a VEVENT and add to ical. */
            icalcomponent *comp = icalcomponent_new_vevent();
            icalcomponent_add_component(ical, comp);
            jmap_calendarevent_to_ical(comp, arg, 1 /* create */, uid, invalid, req);

            /* Handle any property errors and bail out. */
            if (json_array_size(invalid)) {
                json_t *err = json_pack("{s:s, s:o}",
                        "type", "invalidProperties", "properties", invalid);
                json_object_set_new(notCreated, key, err);
                icalcomponent_free(ical);
                free(uid);
                continue;
            }
            json_decref(invalid);

            /* Store the ical component in the mailbox. */
            struct mailbox *mbox = NULL;
            char *mboxname;

            if (_jmap_calendar_ishidden(calId)) {
                /* XXX - calendarNotFound is not defined in the spec */
                json_t *err = json_pack("{s:s}", "type", "calendarNotFound");
                json_object_set_new(notCreated, key, err);
                free(uid);
                continue;
            }
            mboxname = caldav_mboxname(req->userid, calId);
            r = mailbox_open_iwl(mboxname, &mbox);

            if (r == IMAP_MAILBOX_NONEXISTENT || r == IMAP_PERMISSION_DENIED) {
                json_t *err = json_pack("{s:s}", "type", "calendarNotFound");
                json_object_set_new(notCreated, key, err);
                free(uid);
                free(mboxname);
                continue;
            } else if (r) {
                syslog(LOG_ERR, "mailbox_open_iwl(%s) failed: %s", mboxname, error_message(r));
                free(uid);
                free(mboxname);
                goto done;
            }
            free(mboxname);

            struct transaction_t txn;
            memset(&txn, 0, sizeof(struct transaction_t));
            txn.req_hdrs = spool_new_hdrcache();
            /* XXX Can we trigger invitations by setting a flag here? */
            r = caldav_store_resource(&txn, ical, mbox, uid, db, 0);
            spool_free_hdrcache(txn.req_hdrs);
            icalcomponent_free(ical);
            buf_free(&txn.buf);

            mailbox_close(&mbox);
            if (r != HTTP_CREATED && r != HTTP_NO_CONTENT) {
                /* XXX - invalidProperties is probably not the right set error,
                 * but what went wrong in caldav_store_resource? */
                json_t *err = json_pack("{s:s}", "type", "invalidProperties");
                json_object_set_new(notCreated, key, err);
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

        /* XXX - This could be refactored with create and destroy. */

        const char *uid;
        json_t *arg;

        json_object_foreach(update, uid, arg) {
            struct caldav_data *cdata = NULL;
            struct mailbox *mbox = NULL;
            struct index_record record;
            icalcomponent *ical = NULL;
            icalcomponent *comp = NULL;
            json_t *invalid = NULL;
            const char *calId = NULL;
            int pe;
            int rights;

            /* Validate uid. JMAP update does not allow creation uids here. */
            if (!strlen(uid) || *uid == '#') {
                json_t *err = json_pack("{s:s}", "type", "notFound");
                json_object_set_new(notUpdated, uid, err);
                continue;
            }

            /* Lookup calendar event uid in DB. */
            r = caldav_lookup_uid(db, uid, &cdata);
            if (r) {
                syslog(LOG_ERR, "caldav_lookup_uid(%s) failed: %s",
                        uid, error_message(r));
                goto done;
            }
            if (!cdata->dav.rowid || !cdata->dav.imap_uid) {
                json_t *err = json_pack("{s:s}", "type", "notFound");
                json_object_set_new(notUpdated, uid, err);
                continue;
            }

            /* Open mailbox for writing */
            r = mailbox_open_iwl(cdata->dav.mailbox, &mbox);
            if (r) {
                if (r == IMAP_MAILBOX_NONEXISTENT) {
                    /* XXX - calendarNotFound setError is not specified. */
                    json_t *err = json_pack("{s:s}", "type", "calendarNotFound");
                    json_object_set_new(notUpdated, uid, err);
                    continue;
                } else {
                    syslog(LOG_ERR, "mailbox_open_iwl(%s) failed: %s",
                            cdata->dav.mailbox, error_message(r));
                    goto done;
                }
            }

            /* Check permissions. */
            rights = httpd_myrights(req->authstate, mbox->acl);
            if (!(rights & (DACL_WRITE))) {
                /* Pretend this mailbox does not exist. jmap_post should have
                 * checked already for an accountReadOnly error. */
                /* XXX But jmap_post does not seem to take care of that yet. */
                mailbox_close(&mbox);
                json_t *err = json_pack("{s:s}", "type", "notFound");
                json_object_set_new(notUpdated, uid, err);
                continue;
            }

            /* - Fetch index record for the resource */
            memset(&record, 0, sizeof(struct index_record));
            r = mailbox_find_index_record(mbox, cdata->dav.imap_uid, &record);
            if (r) {
                mailbox_close(&mbox);
                if (r == IMAP_NOTFOUND) {
                    json_t *err = json_pack("{s:s}", "type", "notFound");
                    json_object_set_new(notUpdated, uid, err);
                    continue;
                } else {
                    syslog(LOG_ERR, "mailbox_index_record(0x%x) failed: %s",
                            cdata->dav.imap_uid, error_message(r));
                    goto done;
                }
            }

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

            /* Look up the calendarId property. If it is set and differs from
             * the calendar mailbox name, we need to move the event. */
            invalid = json_pack("[]");

            pe = jmap_readprop(arg, "calendarId", 0,  invalid, "s", &calId);
            if (pe > 0) {
                if (strlen(calId) == 0) {
                    json_array_append_new(invalid, json_string("calendarId"));
                    /* XXX error */
                }
                if (*calId == '#') {
                    const char *id = (const char *) hash_lookup(calId, req->idmap);
                    if (id != NULL) {
                        calId = id;
                    }
                }
            }

            /* Update the VEVENT. */
            jmap_calendarevent_to_ical(comp, arg, 0 /* create */, uid, invalid, req);

            /* Handle any property errors and bail out. */
            if (json_array_size(invalid)) {
                json_t *err = json_pack("{s:s, s:o}",
                        "type", "invalidProperties", "properties", invalid);
                json_object_set_new(notUpdated, uid, err);
                icalcomponent_free(ical);
                mailbox_close(&mbox);
                continue;
            }
            json_decref(invalid);

            /* Store the updated VEVENT. */
            /* XXX - Handle move here. */
            struct transaction_t txn;
            memset(&txn, 0, sizeof(struct transaction_t));
            txn.req_hdrs = spool_new_hdrcache();
            /* XXX Can we trigger invitations by setting a flag here? */
            r = caldav_store_resource(&txn, ical, mbox, uid, db, 0);
            spool_free_hdrcache(txn.req_hdrs);
            icalcomponent_free(ical);
            buf_free(&txn.buf);
            mailbox_close(&mbox);
            if (r != HTTP_CREATED && r != HTTP_NO_CONTENT) {
                /* XXX - invalidProperties is probably not the right set error,
                 * but what went wrong in caldav_store_resource? */
                json_t *err = json_pack("{s:s}", "type", "invalidProperties");
                json_object_set_new(notUpdated, uid, err);
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
            struct mboxevent *mboxevent = NULL;
            struct caldav_data *cdata = NULL;
            struct mailbox *mbox = NULL;
            struct index_record record;
            int rights;

            /* Validate uid. JMAP destroy does not allow reference uids. */
            const char *uid = json_string_value(juid);
            if (!strlen(uid) || *uid == '#') {
                json_t *err = json_pack("{s:s}", "type", "notFound");
                json_object_set_new(notDestroyed, uid, err);
                continue;
            }

            /* Lookup calendar event uid in DB. */
            r = caldav_lookup_uid(db, uid, &cdata);
            if (r) {
                syslog(LOG_ERR, "caldav_lookup_uid(%s) failed: %s",
                        uid, error_message(r));
                goto done;
            }
            if (!cdata->dav.rowid || !cdata->dav.imap_uid) {
                json_t *err = json_pack("{s:s}", "type", "notFound");
                json_object_set_new(notDestroyed, uid, err);
                continue;
            }

            /* Open mailbox for writing */
            r = mailbox_open_iwl(cdata->dav.mailbox, &mbox);
            if (r) {
                if (r == IMAP_MAILBOX_NONEXISTENT) {
                    /* XXX - calendarNotFound setError is not specified. */
                    json_t *err = json_pack("{s:s}", "type", "calendarNotFound");
                    json_object_set_new(notDestroyed, uid, err);
                    continue;
                } else {
                    syslog(LOG_ERR, "mailbox_open_iwl(%s) failed: %s",
                            cdata->dav.mailbox, error_message(r));
                    goto done;
                }
            }

            /* Check permissions. */
            rights = httpd_myrights(req->authstate, mbox->acl);
            if (!(rights & (DACL_RMRSRC))) {
                /* Pretend this mailbox does not exist. jmap_post should have
                 * checked already for an accountReadOnly error. */
                /* XXX But jmap_post does not seem to take care of that yet. */
                mailbox_close(&mbox);
                json_t *err = json_pack("{s:s}", "type", "notFound");
                json_object_set_new(notDestroyed, uid, err);
                continue;
            }
            /* - Fetch index record for the resource */
            memset(&record, 0, sizeof(struct index_record));
            r = mailbox_find_index_record(mbox, cdata->dav.imap_uid, &record);
            if (r) {
                mailbox_close(&mbox);
                if (r == IMAP_NOTFOUND) {
                    json_t *err = json_pack("{s:s}", "type", "notFound");
                    json_object_set_new(notDestroyed, uid, err);
                    continue;
                } else {
                    syslog(LOG_ERR, "mailbox_index_record(0x%x) failed: %s",
                            cdata->dav.imap_uid, error_message(r));
                    goto done;
                }
            }

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

            /* Remove from CalDAV DB. */
            caldav_delete(db, cdata->dav.rowid);

            mboxevent_notify(mboxevent);
            mboxevent_free(&mboxevent);

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
    json_array_append_new(item, json_string("calendarsEventsSet"));
    json_array_append_new(item, set);
    json_array_append_new(item, json_string(req->tag));
    json_array_append_new(req->response, item);

done:
    if (db) caldav_close(db);
    json_decref(set);
    return r;
}
