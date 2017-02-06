/* jmap_contact.c -- Routines for handling JMAP contact messages
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

#include "annotate.h"
#include "carddav_db.h"
#include "global.h"
#include "hash.h"
#include "http_carddav.h"
#include "http_dav.h"
#include "imap_err.h"
#include "mailbox.h"
#include "mboxname.h"
#include "stristr.h"
#include "util.h"
#include "vcard_support.h"
#include "xmalloc.h"

#include "jmap_common.h"

/* generated headers are not necessarily in current directory */
#include "imap/http_err.h"

static int getContactGroups(struct jmap_req *req);
static int getContactGroupUpdates(struct jmap_req *req);
static int setContactGroups(struct jmap_req *req);
static int getContacts(struct jmap_req *req);
static int getContactUpdates(struct jmap_req *req);
static int getContactList(struct jmap_req *req);
static int setContacts(struct jmap_req *req);

jmap_msg_t jmap_contact_messages[] = {
    { "getContactGroups",       &getContactGroups },
    { "getContactGroupUpdates", &getContactGroupUpdates },
    { "setContactGroups",       &setContactGroups },
    { "getContacts",            &getContacts },
    { "getContactUpdates",      &getContactUpdates },
    { "getContactList",         &getContactList },
    { "setContacts",            &setContacts },
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

static int _match_text(const char *haystack, const char *needle) {
    /* XXX This is just a very crude text matcher. */
    return stristr(haystack, needle) != NULL;
}

/* Return true if text matches the value of arg's property named name. If 
 * name is NULL, match text to any JSON string property of arg or those of
 * its enclosed JSON objects and arrays. */
static int jmap_match_jsonprop(json_t *arg, const char *name, const char *text) {
    if (name) {
        json_t *val = json_object_get(arg, name);
        if (json_typeof(val) != JSON_STRING) {
            return 0;
        }
        return _match_text(json_string_value(val), text);
    } else {
        const char *key;
        json_t *val;
        int m = 0;
        size_t i;
        json_t *entry;

        json_object_foreach(arg, key, val) {
            switch json_typeof(val) {
                case JSON_STRING:
                    m = _match_text(json_string_value(val), text);
                    break;
                case JSON_OBJECT:
                    m = jmap_match_jsonprop(val, NULL, text);
                    break;
                case JSON_ARRAY:
                    json_array_foreach(val, i, entry) {
                        switch json_typeof(entry) {
                            case JSON_STRING:
                                m = _match_text(json_string_value(entry), text);
                                break;
                            case JSON_OBJECT:
                                m = jmap_match_jsonprop(entry, NULL, text);
                                break;
                            default:
                                /* do nothing */
                                ;
                        }
                        if (m) break;
                    }
                default:
                    /* do nothing */
                    ;
            }
            if (m) return m;
        }
    }
    return 0;
}

/* FIXME DUPLICATE END */
/*****************************************************************************
 * JMAP Contacts API
 ****************************************************************************/

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
    char *xhref;
    int r;

    if (!crock->mailbox || strcmp(crock->mailbox->name, cdata->dav.mailbox)) {
        mailbox_close(&crock->mailbox);
        r = mailbox_open_irl(cdata->dav.mailbox, &crock->mailbox);
        if (r) return r;
    }

    r = mailbox_find_index_record(crock->mailbox, cdata->dav.imap_uid, &record);
    if (r) return r;

    crock->rows++;

    struct vparse_entry *ventry = NULL;

    /* Load message containing the resource and parse vcard data */
    struct vparse_card *vcard = record_to_vcard(crock->mailbox, &record);
    if (!vcard || !vcard->objects) {
        syslog(LOG_ERR, "record_to_vcard failed for record %u:%s",
                cdata->dav.imap_uid, crock->mailbox->name);
        vparse_free_card(vcard);
        return IMAP_INTERNAL;
    }

    json_t *obj = json_pack("{}");

    json_object_set_new(obj, "id", json_string(cdata->vcard_uid));

    json_object_set_new(obj, "addressbookId",
                        json_string(strrchr(cdata->dav.mailbox, '.')+1));

    json_t *contactids = json_pack("[]");
    json_t *otherids = json_pack("{}");

    xhref = jmap_xhref(cdata->dav.mailbox, cdata->dav.resource);
    json_object_set_new(obj, "x-href", json_string(xhref));
    free(xhref);

    for (ventry = vcard->objects->properties; ventry; ventry = ventry->next) {
        const char *name = ventry->name;
        const char *propval = ventry->v.value;

        if (!name) continue;
        if (!propval) continue;

        if (!strcasecmp(name, "fn")) {
            json_object_set_new(obj, "name", json_string(propval));
        }

        else if (!strcasecmp(name, "x-addressbookserver-member")) {
            if (strncmp(propval, "urn:uuid:", 9)) continue;
            json_array_append_new(contactids, json_string(propval+9));
        }

        else if (!strcasecmp(name, "x-fm-otheraccount-member")) {
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

    vparse_free_card(vcard);

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

    rock.mailbox = NULL;

    r = carddav_create_defaultaddressbook(req->userid);
    if (r) goto done;

    rock.array = json_pack("[]");
    rock.props = NULL;

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
    json_t *notFound = json_array();
    if (want) {
        int i;
        int size = json_array_size(want);
        for (i = 0; i < size; i++) {
            rock.rows = 0;
            const char *id = json_string_value(json_array_get(want, i));
            if (!id) continue;
            if (id[0] == '#') {
                const char *newid;
                if (kind == CARDDAV_KIND_GROUP) {
                    newid = hash_lookup(id + 1, &req->idmap->contactgroups);
                }
                else {
                    newid = hash_lookup(id + 1, &req->idmap->contacts);
                }
                if (newid) id = newid;
            }
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
    if (rock.props) {
        free_hash_table(rock.props, NULL);
        free(rock.props);
    }
    if (r) goto done;

    json_t *toplevel = json_pack("{}");
    json_object_set_new(toplevel, "accountId", json_string(req->userid));
    json_object_set_new(toplevel, "state", jmap_getstate(MBTYPE_ADDRESSBOOK, req));
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


static int getcontactupdates_cb(void *rock, struct carddav_data *cdata)
{
    struct updates_rock *urock = (struct updates_rock *) rock;
    updates_rock_update(urock, cdata->dav, cdata->vcard_uid);
    return 0;
}

static int getContactGroupUpdates(struct jmap_req *req)
{
    struct carddav_db *db = carddav_open_userid(req->userid);
    if (!db) return -1;
    struct buf buf = BUF_INITIALIZER;
    int r = -1;
    int pe; /* property parse error */
    modseq_t oldmodseq = 0;
    int dofetch = 0;

    /* Parse and validate arguments. */
    json_t *invalid = json_pack("[]");

    json_int_t max_records = 0;
    pe = readprop(req->args, "maxChanges", 0 /*mandatory*/, invalid, "i", &max_records);
    if (pe > 0) {
        if (max_records <= 0) {
            json_array_append_new(invalid, json_string("maxChanges"));
        }
    }

    const char *since = NULL;
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

    /* Non-JMAP spec addressbookId argument */
    char *mboxname = NULL;
    json_t *abookid = json_object_get(req->args, "addressbookId");
    if (abookid && json_string_value(abookid)) {
        const char *addressbookId = json_string_value(abookid);
        mboxname = carddav_mboxname(req->userid, addressbookId);
    }

    r = carddav_create_defaultaddressbook(req->userid);
    if (r) goto done;

    /* Lookup updates. */
    struct updates_rock rock;
    memset(&rock, 0, sizeof(struct updates_rock));
    rock.changed = json_array();
    rock.removed = json_array();
    rock.max_records = max_records;
    rock.fetchmodseq = 1;

    r = carddav_get_updates(db, oldmodseq, mboxname, CARDDAV_KIND_GROUP,
                            &getcontactupdates_cb, &rock);
    mailbox_close(&rock.mailbox);
    if (r) goto done;

    strip_spurious_deletes(&rock);

    /* Determine new state. */
    modseq_t newstate;
    int more = rock.max_records ? rock.seen_records > rock.max_records : 0;
    if (more) {
        newstate = rock.highestmodseq;
    } else {
        newstate = req->counters.carddavmodseq;
    }

    json_t *contactGroupUpdates = json_pack("{}");
    buf_printf(&buf, MODSEQ_FMT, newstate);
    json_object_set_new(contactGroupUpdates, "newState", json_string(buf_cstring(&buf)));
    buf_reset(&buf);

    json_object_set_new(contactGroupUpdates, "accountId", json_string(req->userid));
    json_object_set_new(contactGroupUpdates, "oldState", json_string(since));
    json_object_set_new(contactGroupUpdates, "hasMoreUpdates", json_boolean(more));
    json_object_set(contactGroupUpdates, "changed", rock.changed);
    json_object_set(contactGroupUpdates, "removed", rock.removed);

    json_t *item = json_pack("[]");
    json_array_append_new(item, json_string("contactGroupUpdates"));
    json_array_append_new(item, contactGroupUpdates);
    json_array_append_new(item, json_string(req->tag));

    json_array_append_new(req->response, item);

    if (dofetch) {
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
    buf_free(&buf);
    carddav_close(db);
    return r;
}

static const char *_resolve_contactid(struct jmap_req *req, const char *id)
{
    if (id && *id == '#') {
        const char *newid = hash_lookup(id + 1, &req->idmap->contacts);
        if (newid) return newid;
    }
    return id;
}

static int _add_group_entries(struct jmap_req *req,
                              struct vparse_card *card, json_t *members,
                              json_t *invalid)
{
    vparse_delete_entries(card, NULL, "X-ADDRESSBOOKSERVER-MEMBER");
    int r = 0;
    size_t index;
    struct buf buf = BUF_INITIALIZER;

    for (index = 0; index < json_array_size(members); index++) {
        const char *item = _json_array_get_string(members, index);
        if (!item) {
            buf_printf(&buf, "contactIds[%zu]", index);
            json_array_append_new(invalid, json_string(buf_cstring(&buf)));
            buf_reset(&buf);
            continue;
        }
        const char *uid = _resolve_contactid(req, item);
        buf_setcstr(&buf, "urn:uuid:");
        buf_appendcstr(&buf, uid);
        vparse_add_entry(card, NULL,
                         "X-ADDRESSBOOKSERVER-MEMBER", buf_cstring(&buf));
        buf_reset(&buf);
    }

    buf_free(&buf);
    return r;
}

static int _add_othergroup_entries(struct jmap_req *req,
                                   struct vparse_card *card, json_t *members,
                                   json_t *invalid)
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
            if (!item) {
                buf_printf(&buf, "otherContactIds[%s]", key);
                json_array_append_new(invalid, json_string(buf_cstring(&buf)));
                buf_reset(&buf);
                continue;
            }
            const char *uid = _resolve_contactid(req, item);
            buf_setcstr(&buf, "urn:uuid:");
            buf_appendcstr(&buf, uid);
            struct vparse_entry *entry =
                vparse_add_entry(card, NULL,
                                 "X-FM-OTHERACCOUNT-MEMBER", buf_cstring(&buf));
            vparse_add_param(entry, "userid", key);
            buf_reset(&buf);
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
    if (jcheckState && jmap_checkstate(jcheckState, MBTYPE_ADDRESSBOOK, req)) {
        json_t *item = json_pack("[s, {s:s}, s]",
                "error", "type", "stateMismatch", req->tag);
        json_array_append_new(req->response, item);
        goto done;
    }

    json_t *set = json_pack("{s:o,s:s}",
                            "oldState", jmap_getstate(MBTYPE_ADDRESSBOOK, req),
                            "accountId", req->userid);

    r = carddav_create_defaultaddressbook(req->userid);
    if (r) goto done;

    json_t *create = json_object_get(req->args, "create");
    if (create) {
        json_t *created = json_pack("{}");
        json_t *notCreated = json_pack("{}");
        json_t *record;

        const char *key;
        json_t *arg;
        json_object_foreach(create, key, arg) {
            char *uid = xstrdup(makeuuid());
            const char *name = NULL;
            json_t *invalid = json_pack("[]");

            readprop(arg, "name", 1, invalid, "s", &name);

            struct vparse_card *card = vparse_new_card("VCARD");
            vparse_add_entry(card, NULL, "VERSION", "3.0");
            vparse_add_entry(card, NULL, "N", name);
            vparse_add_entry(card, NULL, "FN", name);
            vparse_add_entry(card, NULL, "UID", uid);
            vparse_add_entry(card, NULL, "X-ADDRESSBOOKSERVER-KIND", "group");

            /* it's legal to create an empty group */
            json_t *members = json_object_get(arg, "contactIds");
            if (members) {
                _add_group_entries(req, card, members, invalid);
            }

            /* it's legal to create an empty group */
            json_t *others = json_object_get(arg, "otherAccountContactIds");
            if (others) {
                _add_othergroup_entries(req, card, others, invalid);
            }

            if (json_array_size(invalid)) {
                json_t *err = json_pack("{s:s, s:o}",
                        "type", "invalidProperties", "properties", invalid);
                json_object_set_new(notCreated, key, err);
                vparse_free_card(card);
                free(uid);
                continue;
            }
            json_decref(invalid);

            const char *addressbookId = "Default";
            json_t *abookid = json_object_get(arg, "addressbookId");
            if (abookid && json_string_value(abookid)) {
                /* XXX - invalid arguments */
                addressbookId = json_string_value(abookid);
            }
            char *mboxname = mboxname_abook(req->userid, addressbookId);
            json_object_del(arg, "addressbookId");
            addressbookId = NULL;

            /* we need to create and append a record */
            if (!mailbox || strcmp(mailbox->name, mboxname)) {
                mailbox_close(&mailbox);
                r = mailbox_open_iwl(mboxname, &mailbox);
            }

            syslog(LOG_NOTICE, "jmap: create group %s/%s/%s (%s)",
                   req->userid, mboxname, uid, name);
            free(mboxname);

            if (!r) r = carddav_store(mailbox, card, NULL, NULL, NULL,
                                      req->userid, req->authstate, ignorequota);
            vparse_free_card(card);

            if (r) {
                /* these are real "should never happen" errors */
                free(uid);
                goto done;
            }

            record = json_pack("{s:s}", "id", uid);
            json_object_set_new(created, key, record);

            /* hash_insert takes ownership of uid here, skanky I know */
            hash_insert(key, uid, &req->idmap->contactgroups);
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
        json_t *updated = json_pack("{}");
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
                    free(resource);
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
                        free(resource);
                        goto done;
                    }
                }
                json_object_del(arg, "addressbookId");
            }

            struct index_record record;

            r = mailbox_find_index_record(mailbox,
                                          cdata->dav.imap_uid, &record);
            if (r) {
                free(resource);
                goto done;
            }

            /* Load message containing the resource and parse vcard data */
            struct vparse_card *vcard = record_to_vcard(mailbox, &record);
            if (!vcard || !vcard->objects) {
                syslog(LOG_ERR, "record_to_vcard failed for record %u:%s",
                       cdata->dav.imap_uid, mailbox->name);
                json_t *err = json_pack("{s:s}", "type", "parseError");
                json_object_set_new(notUpdated, uid, err);
                vparse_free_card(vcard);
                mailbox_close(&newmailbox);
                free(resource);
                continue;
            }
            struct vparse_card *card = vcard->objects;

            json_t *namep = json_object_get(arg, "name");
            if (namep) {
                const char *name = json_string_value(namep);
                if (!name) {
                    json_t *err = json_pack("{s:s}",
                                            "type", "invalidArguments");
                    json_object_set_new(notUpdated, uid, err);
                    vparse_free_card(vcard);
                    mailbox_close(&newmailbox);
                    free(resource);
                    continue;
                }
                /* both N and FN get the name */
                struct vparse_entry *entry = vparse_get_entry(card, NULL, "N");
                if (entry) {
                    if (entry->multivalue) {
                        strarray_free(entry->v.values);
                        entry->v.values = NULL;
                    } else {
                        free(entry->v.value);
                    }
                    entry->v.value = xstrdup(name);
                    entry->multivalue = 0;
                }
                else {
                    vparse_add_entry(card, NULL, "N", name);
                }
                entry = vparse_get_entry(card, NULL, "FN");
                if (entry) {
                    if (entry->multivalue) {
                        /* FN isn't allowed to be a multi-value, but let's
                         * rather check than deal with corrupt memory */
                        strarray_free(entry->v.values);
                        entry->v.values = NULL;
                    } else {
                        free(entry->v.value);
                    }
                    entry->v.value = xstrdup(name);
                    entry->multivalue = 0;
                }
                else {
                    vparse_add_entry(card, NULL, "FN", name);
                }
            }

            json_t *invalid = json_pack("[]");
            json_t *members = json_object_get(arg, "contactIds");
            if (members) {
                _add_group_entries(req, card, members, invalid);
            }

            json_t *others = json_object_get(arg, "otherAccountContactIds");
            if (others) {
                _add_othergroup_entries(req, card, others, invalid);
            }
            if (json_array_size(invalid)) {
                json_t *err = json_pack("{s:s, s:o}",
                        "type", "invalidProperties", "properties", invalid);
                json_object_set_new(notUpdated, uid, err);
                vparse_free_card(vcard);
                mailbox_close(&newmailbox);
                free(resource);
                continue;
            }
            json_decref(invalid);

            syslog(LOG_NOTICE, "jmap: update group %s/%s",
                   req->userid, resource);

            r = carddav_store(newmailbox ? newmailbox : mailbox, card, resource,
                              NULL, NULL, req->userid, req->authstate, ignorequota);
            if (!r)
                r = carddav_remove(mailbox, olduid, /*isreplace*/!newmailbox, req->userid);
            mailbox_close(&newmailbox);

            vparse_free_card(vcard);
            free(resource);
            if (r) goto done;

            json_object_set_new(updated, uid, json_null());
        }

        if (json_object_size(updated))
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
            r = carddav_remove(mailbox, olduid, /*isreplace*/0, req->userid);
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

    if (json_object_get(set, "created") ||
        json_object_get(set, "updated") ||
        json_object_get(set, "destroyed")) {

        r = jmap_bumpstate(MBTYPE_ADDRESSBOOK, req);
        if (r) goto done;
    }
    json_object_set_new(set, "newState", jmap_getstate(MBTYPE_ADDRESSBOOK, req));

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

/* Extract separate y,m,d from YYYY-MM-DD or (with ignore_hyphens) YYYYMMDD
 *
 * This handles birthday/anniversary and BDAY/ANNIVERSARY for JMAP and vCard
 *
 * JMAP dates are _always_ YYYY-MM-DD, so use require_hyphens = 1
 *
 * For vCard, this handles "date-value" from RFC2426 (which is "date" from
 * RFC2425), used by BDAY (ANNIVERSARY isn't in vCard 3). vCard 4 says BDAY and
 * ANNIVERSARY is date-and-or-time, which is far more complicated. I haven't
 * seen that in the wild yet and hope I never do.
 */
static int _parse_date(const char *date, unsigned *y, unsigned *m, unsigned *d, int require_hyphens)
{
    /* there isn't a convenient libc function that will let us convert parts of
     * a string to integer and only take digit characters, so we just pull it
     * apart ourselves */

    const char *yp = NULL, *mp = NULL, *dp = NULL;

    /* getting pointers to the ymd components, skipping hyphens if necessary.
     * format checking as we go. no need to strlen() beforehand, it will fall
     * out of the range checks. */
    yp = date;
    if (yp[0] < '0' || yp[0] > '9' ||
        yp[1] < '0' || yp[1] > '9' ||
        yp[2] < '0' || yp[2] > '9' ||
        yp[3] < '0' || yp[3] > '9') return -1;

    mp = &yp[4];

    if (*mp == '-') mp++;
    else if (require_hyphens) return -1;

    if (mp[0] < '0' || mp[0] > '9' ||
        mp[1] < '0' || mp[1] > '9') return -1;

    dp = &mp[2];

    if (*dp == '-') dp++;
    else if (require_hyphens) return -1;

    if (dp[0] < '0' || dp[0] > '9' ||
        dp[1] < '0' || dp[1] > '9') return -1;

    if (dp[2] != '\0') return -1;

    /* convert to integer. ascii digits are 0x30-0x37, so we can take bottom
     * four bits and multiply */
    *y =
        (yp[0] & 0xf) * 1000 +
        (yp[1] & 0xf) * 100 +
        (yp[2] & 0xf) * 10 +
        (yp[3] & 0xf);

    *m =
        (mp[0] & 0xf) * 10 +
        (mp[1] & 0xf);

    *d =
        (dp[0] & 0xf) * 10 +
        (dp[1] & 0xf);

    return 0;
}

static void _date_to_jmap(struct vparse_entry *entry, struct buf *buf)
{
    if (!entry)
        goto no_date;

    unsigned y, m, d;
    if (_parse_date(entry->v.value, &y, &m, &d, 0))
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

/* Convert the VCARD card, contained in record and cdata and mailbox 
 * mboxname. If props is not NULL, only convert properties in props. */
static json_t *jmap_contact_from_vcard(struct vparse_card *card,
                                       struct carddav_data *cdata,
                                       struct index_record *record,
                                       hash_table *props,
                                       const char *mboxname)
{
    strarray_t *empty = NULL;
    json_t *obj = json_pack("{}");
    struct buf buf = BUF_INITIALIZER;

    json_object_set_new(obj, "id", json_string(cdata->vcard_uid));

    json_object_set_new(obj, "addressbookId",
                        json_string(strrchr(cdata->dav.mailbox, '.')+1));

    if (_wantprop(props, "isFlagged")) {
        json_object_set_new(obj, "isFlagged",
                            record->system_flags & FLAG_FLAGGED ? json_true() :
                            json_false());
    }

    if (_wantprop(props, "x-href")) {
        char *xhref = jmap_xhref(cdata->dav.mailbox, cdata->dav.resource);
        json_object_set_new(obj, "x-href", json_string(xhref));
        free(xhref);
    }

    if (_wantprop(props, "x-importance")) {
        double val = 0;
        const char *ns = DAV_ANNOT_NS "<" XML_NS_CYRUS ">importance";

        buf_reset(&buf);
        annotatemore_msg_lookup(mboxname, record->uid,
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

    if (_wantprop(props, "lastName")) {
        const char *family = strarray_safenth(n, 0);
        json_object_set_new(obj, "lastName", json_string(family));
    }

    if (_wantprop(props, "firstName")) {
        /* JMAP doesn't have a separate field for Middle (aka "Additional
         * Names"), so we just mash them into firstName. See reverse of this in
         * _json_to_card */
        const char *given = strarray_safenth(n, 1);
        const char *middle = strarray_safenth(n, 2);
        buf_setcstr(&buf, given);
        if (*middle) {
            buf_putc(&buf, ' ');
            buf_appendcstr(&buf, middle);
        }
        json_object_set_new(obj, "firstName", json_string(buf_cstring(&buf)));
    }
    if (_wantprop(props, "prefix")) {
        const char *prefix = strarray_safenth(n, 3);
        json_object_set_new(obj, "prefix",
                            json_string(prefix)); /* just prefix */
    }
    if (_wantprop(props, "suffix")) {
        const char *suffix = strarray_safenth(n, 4);
        json_object_set_new(obj, "suffix",
                            json_string(suffix)); /* just suffix */
    }

    /* org fields */
    if (_wantprop(props, "company"))
        json_object_set_new(obj, "company",
                            json_string(strarray_safenth(org, 0)));
    if (_wantprop(props, "department"))
        json_object_set_new(obj, "department",
                            json_string(strarray_safenth(org, 1)));
    if (_wantprop(props, "jobTitle")) {
        /* we used to store jobTitle in ORG[2] instead of TITLE, which confused
         * CardDAV clients. that's fixed, but there's now lots of cards with it
         * stored in the wrong place, so check both */
        const char *item = vparse_stringval(card, "title");
        if (!item)
            item = strarray_safenth(org, 2);
        json_object_set_new(obj, "jobTitle", json_string(item));
    }

    /* address - we need to open code this, because it's repeated */
    if (_wantprop(props, "addresses")) {
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
    if (_wantprop(props, "emails")) {
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
    if (_wantprop(props, "phones")) {
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
    if (_wantprop(props, "online")) {
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

    if (_wantprop(props, "nickname")) {
        const char *item = vparse_stringval(card, "nickname");
        json_object_set_new(obj, "nickname", json_string(item ? item : ""));
    }

    if (_wantprop(props, "anniversary")) {
        struct vparse_entry *entry = vparse_get_entry(card, NULL, "anniversary");
        _date_to_jmap(entry, &buf);
        json_object_set_new(obj, "anniversary", json_string(buf_cstring(&buf)));
    }

    if (_wantprop(props, "birthday")) {
        struct vparse_entry *entry = vparse_get_entry(card, NULL, "bday");
        _date_to_jmap(entry, &buf);
        json_object_set_new(obj, "birthday", json_string(buf_cstring(&buf)));
    }

    if (_wantprop(props, "notes")) {
        const char *item = vparse_stringval(card, "note");
        json_object_set_new(obj, "notes", json_string(item ? item : ""));
    }

    if (_wantprop(props, "x-hasPhoto")) {
        const char *item = vparse_stringval(card, "photo");
        json_object_set_new(obj, "x-hasPhoto",
                            item ? json_true() : json_false());
    }

    /* XXX - other fields */

    buf_free(&buf);
    if (empty) strarray_free(empty);
    return obj;
}

static int getcontacts_cb(void *rock, struct carddav_data *cdata)
{
    struct cards_rock *crock = (struct cards_rock *) rock;
    struct index_record record;
    int r = 0;

    if (!crock->mailbox || strcmp(crock->mailbox->name, cdata->dav.mailbox)) {
        mailbox_close(&crock->mailbox);
        r = mailbox_open_irl(cdata->dav.mailbox, &crock->mailbox);
        if (r) return r;
    }

    r = mailbox_find_index_record(crock->mailbox, cdata->dav.imap_uid, &record);
    if (r) return r;

    crock->rows++;

    /* Load message containing the resource and parse vcard data */
    struct vparse_card *vcard = record_to_vcard(crock->mailbox, &record);
    if (!vcard || !vcard->objects) {
        syslog(LOG_ERR, "record_to_vcard failed for record %u:%s",
                cdata->dav.imap_uid, crock->mailbox->name);
        vparse_free_card(vcard);
        return IMAP_INTERNAL;
    }

    /* Convert the VCARD to a JMAP contact. */
    json_t *obj = jmap_contact_from_vcard(vcard->objects, cdata, &record,
                                          crock->props, crock->mailbox->name);
    json_array_append_new(crock->array, obj);

    vparse_free_card(vcard);

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
    struct buf buf = BUF_INITIALIZER;
    int r = -1;
    json_t *invalid = NULL; /* invalid property array */
    int pe; /* property parse error */

    /* Parse and validate arguments. */
    invalid = json_pack("[]");

    json_int_t max_records = 0;
    pe = readprop(req->args, "maxChanges", 0 /*mandatory*/, invalid, "i", &max_records);
    if (pe > 0) {
        if (max_records <= 0) {
            json_array_append_new(invalid, json_string("maxChanges"));
        }
    }

    if (json_array_size(invalid)) {
        json_t *err = json_pack("{s:s, s:o}", "type", "invalidArguments", "arguments", invalid);
        json_array_append_new(req->response, json_pack("[s,o,s]", "error", err, req->tag));
        r = 0;
        goto done;
    }
    json_decref(invalid);

    const char *since = _json_object_get_string(req->args, "sinceState");
    if (!since) goto done;
    modseq_t oldmodseq = atomodseq_t(since);

    char *mboxname = NULL;
    json_t *abookid = json_object_get(req->args, "addressbookId");
    if (abookid && json_string_value(abookid)) {
        /* XXX - invalid arguments */
        const char *addressbookId = json_string_value(abookid);
        mboxname = carddav_mboxname(req->userid, addressbookId);
    }

    r = carddav_create_defaultaddressbook(req->userid);
    if (r) goto done;

    /* Lookup updates. */
    struct updates_rock rock;
    memset(&rock, 0, sizeof(struct updates_rock));
    rock.changed = json_array();
    rock.removed = json_array();
    rock.fetchmodseq = 1;
    rock.max_records = max_records;

    r = carddav_get_updates(db, oldmodseq, mboxname, CARDDAV_KIND_CONTACT,
                            &getcontactupdates_cb, &rock);
    mailbox_close(&rock.mailbox);
    if (r) goto done;

    strip_spurious_deletes(&rock);

    /* Determine new state. */
    modseq_t newstate;
    int more = rock.max_records ? rock.seen_records > rock.max_records : 0;
    if (more) {
        newstate = rock.highestmodseq;
    } else {
        newstate = req->counters.carddavmodseq;
    }

    json_t *contactUpdates = json_pack("{}");
    buf_printf(&buf, MODSEQ_FMT, newstate);
    json_object_set_new(contactUpdates, "newState", json_string(buf_cstring(&buf)));
    buf_reset(&buf);
    json_object_set_new(contactUpdates, "accountId", json_string(req->userid));
    json_object_set_new(contactUpdates, "oldState", json_string(since));
    json_object_set_new(contactUpdates, "hasMoreUpdates", json_boolean(more));
    json_object_set(contactUpdates, "changed", rock.changed);
    json_object_set(contactUpdates, "removed", rock.removed);

    json_t *item = json_pack("[]");
    json_array_append_new(item, json_string("contactUpdates"));
    json_array_append_new(item, contactUpdates);
    json_array_append_new(item, json_string(req->tag));

    json_array_append_new(req->response, item);

    json_t *dofetch = json_object_get(req->args, "fetchRecords");
    json_t *doprops = json_object_get(req->args, "fetchRecordProperties");
    if (dofetch && json_is_true(dofetch)) {
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
    buf_free(&buf);
    return r;
}

typedef struct contact_filter {
    hash_table *inContactGroup;
    json_t *isFlagged;
    const char *text;
    const char *prefix;
    const char *firstName;
    const char *lastName;
    const char *suffix;
    const char *nickname;
    const char *company;
    const char *department;
    const char *jobTitle;
    const char *email;
    const char *phone;
    const char *online;
    const char *address;
    const char *notes;
} contact_filter;

typedef struct contact_filter_rock {
    struct carddav_db *carddavdb;
    struct carddav_data *cdata;
    json_t *contact;
} contact_filter_rock;

/* Match the contact in rock against filter. */
static int contact_filter_match(void *vf, void *rock)
{
    contact_filter *f = (contact_filter *) vf;
    contact_filter_rock *cfrock = (contact_filter_rock*) rock;
    json_t *contact = cfrock->contact;
    struct carddav_data *cdata = cfrock->cdata;
    struct carddav_db *db = cfrock->carddavdb;

    /* isFlagged */
    if (JNOTNULL(f->isFlagged)) {
        json_t *isFlagged = json_object_get(contact, "isFlagged");
        if (f->isFlagged != isFlagged) {
            return 0;
        }
    }
    /* text */
    if (f->text && !jmap_match_jsonprop(contact, NULL, f->text)) {
        return 0;
    }
    /*  prefix */
    if (f->prefix && !jmap_match_jsonprop(contact, "prefix", f->prefix)) {
        return 0;
    }
    /* firstName */
    if (f->firstName && !jmap_match_jsonprop(contact, "firstName", f->firstName)) {
        return 0;
    }
    /* lastName */
    if (f->lastName && !jmap_match_jsonprop(contact, "lastName", f->lastName)) {
        return 0;
    }
    /*  suffix */
    if (f->suffix && !jmap_match_jsonprop(contact, "suffix", f->suffix)) {
        return 0;
    }
    /*  nickname */
    if (f->nickname && !jmap_match_jsonprop(contact, "nickname", f->nickname)) {
        return 0;
    }
    /*  company */
    if (f->company && !jmap_match_jsonprop(contact, "company", f->company)) {
        return 0;
    }
    /*  department */
    if (f->department && !jmap_match_jsonprop(contact, "department", f->department)) {
        return 0;
    }
    /*  jobTitle */
    if (f->jobTitle && !jmap_match_jsonprop(contact, "jobTitle", f->jobTitle)) {
        return 0;
    }
    /* email */
    if (f->email && json_object_get(contact, "emails")) {
        size_t i;
        json_t *email;
        int m = 0;
        json_array_foreach(json_object_get(contact, "emails"), i, email) {
            m = jmap_match_jsonprop(email, NULL, f->email);
            if (m) break;
        }
        if (!m) return 0;
    }
    /*  phone */
    if (f->phone && json_object_get(contact, "phones")) {
        size_t i;
        json_t *phone;
        int m = 0;
        json_array_foreach(json_object_get(contact, "phones"), i, phone) {
            m = jmap_match_jsonprop(phone, NULL, f->phone);
            if (m) break;
        }
        if (!m) return 0;
    }
    /*  online */
    if (f->online && json_object_get(contact, "online")) {
        size_t i;
        json_t *online;
        int m = 0;
        json_array_foreach(json_object_get(contact, "online"), i, online) {
            m = jmap_match_jsonprop(online, NULL, f->online);
            if (m) break;
        }
        if (!m) return 0;
    }
    /* address */
    if (f->address && json_object_get(contact, "addresses")) {
        size_t i;
        json_t *address;
        int m = 0;
        json_array_foreach(json_object_get(contact, "addresses"), i, address) {
            m = jmap_match_jsonprop(address, NULL, f->address);
            if (m) break;
        }
        if (!m) return 0;
    }
    /*  notes */
    if (f->notes && !jmap_match_jsonprop(contact, "notes", f->notes)) {
        return 0;
    }
    /* inContactGroup */
    if (f->inContactGroup) {
        /* XXX Calling carddav_db for every contact isn't really efficient. If
         * this turns out to be a performance issue, the carddav_db API might
         * support lookup contacts by group ids. */
        strarray_t *gids = carddav_getuid_groups(db, cdata->vcard_uid);
        if (!gids) {
            syslog(LOG_INFO, "carddav_getuid_groups(%s) returned NULL group array",
                    cdata->vcard_uid);
            return 0;
        }
        int i, m = 0;
        for (i = 0; i < gids->count; i++) {
            if (hash_lookup(strarray_nth(gids, i), f->inContactGroup)) {
                m = 1;
                break;
            }
        }
        strarray_free(gids);
        if (!m) return 0;
    }

    /* All matched. */
    return 1;
}

/* Free the memory allocated by this contact filter. */
static void contact_filter_free(void *vf)
{
    contact_filter *f = (contact_filter*) vf;
    if (f->inContactGroup) {
        free_hash_table(f->inContactGroup, NULL);
        free(f->inContactGroup);
    }
    free(f);
}

/* Parse the JMAP Contact FilterCondition in arg.
 * Report any invalid properties in invalid, prefixed by prefix.
 * Return NULL on error. */
static void *contact_filter_parse(json_t *arg,
                                   const char *prefix,
                                   json_t *invalid)
{
    contact_filter *f = (contact_filter *) xzmalloc(sizeof(struct contact_filter));
    struct buf buf = BUF_INITIALIZER;

    /* inContactGroup */
    json_t *inContactGroup = json_object_get(arg, "inContactGroup");
    if (inContactGroup && json_typeof(inContactGroup) != JSON_ARRAY) {
        buf_printf(&buf, "%s.inContactGroup", prefix);
        json_array_append_new(invalid, json_string(buf_cstring(&buf)));
        buf_reset(&buf);
    } else if (inContactGroup) {
        f->inContactGroup = xmalloc(sizeof(struct hash_table));
        construct_hash_table(f->inContactGroup, json_array_size(inContactGroup)+1, 0);
        size_t i;
        json_t *val;
        json_array_foreach(inContactGroup, i, val) {
            buf_printf(&buf, "%s.inContactGroup[%zu]", prefix, i);
            const char *id;
            if (json_unpack(val, "s", &id) != -1) {
                hash_insert(id, (void*)1, f->inContactGroup);
            } else {
                json_array_append_new(invalid, json_string(buf_cstring(&buf)));
            }
            buf_reset(&buf);
        }
    }

    /* isFlagged */
    f->isFlagged = json_object_get(arg, "isFlagged");

    /* text */
    if (JNOTNULL(json_object_get(arg, "text"))) {
        readprop_full(arg, prefix, "text", 0, invalid, "s", &f->text);
    }
    /* prefix */
    if (JNOTNULL(json_object_get(arg, "prefix"))) {
        readprop_full(arg, prefix, "prefix", 0, invalid, "s", &f->prefix);
    }
    /* firstName */
    if (JNOTNULL(json_object_get(arg, "firstName"))) {
        readprop_full(arg, prefix, "firstName", 0, invalid, "s", &f->firstName);
    }
    /* lastName */
    if (JNOTNULL(json_object_get(arg, "lastName"))) {
        readprop_full(arg, prefix, "lastName", 0, invalid, "s", &f->lastName);
    }
    /* suffix */
    if (JNOTNULL(json_object_get(arg, "suffix"))) {
        readprop_full(arg, prefix, "suffix", 0, invalid, "s", &f->suffix);
    }
    /* nickname */
    if (JNOTNULL(json_object_get(arg, "nickname"))) {
        readprop_full(arg, prefix, "nickname", 0, invalid, "s", &f->nickname);
    }
    /* company */
    if (JNOTNULL(json_object_get(arg, "company"))) {
        readprop_full(arg, prefix, "company", 0, invalid, "s", &f->company);
    }
    /* department */
    if (JNOTNULL(json_object_get(arg, "department"))) {
        readprop_full(arg, prefix, "department", 0, invalid, "s", &f->department);
    }
    /* jobTitle */
    if (JNOTNULL(json_object_get(arg, "jobTitle"))) {
        readprop_full(arg, prefix, "jobTitle", 0, invalid, "s", &f->jobTitle);
    }
    /* email */
    if (JNOTNULL(json_object_get(arg, "email"))) {
        readprop_full(arg, prefix, "email", 0, invalid, "s", &f->email);
    }
    /* phone */
    if (JNOTNULL(json_object_get(arg, "phone"))) {
        readprop_full(arg, prefix, "phone", 0, invalid, "s", &f->phone);
    }
    /* online */
    if (JNOTNULL(json_object_get(arg, "online"))) {
        readprop_full(arg, prefix, "online", 0, invalid, "s", &f->online);
    }
    /* address */
    if (JNOTNULL(json_object_get(arg, "address"))) {
        readprop_full(arg, prefix, "address", 0, invalid, "s", &f->address);
    }
    /* notes */
    if (JNOTNULL(json_object_get(arg, "notes"))) {
        readprop_full(arg, prefix, "notes", 0, invalid, "s", &f->notes);
    }

    buf_free(&buf);

    return f;
}

struct contactlist_rock {
    jmap_filter *filter;
    size_t position;
    size_t limit;
    size_t total;
    json_t *contacts;

    struct mailbox *mailbox;
    struct carddav_db *carddavdb;
};

static int getcontactlist_cb(void *rock, struct carddav_data *cdata) {
    struct contactlist_rock *crock = (struct contactlist_rock*) rock;
    struct index_record record;
    json_t *contact = NULL;
    int r = 0;

    if (!cdata->dav.alive || !cdata->dav.rowid || !cdata->dav.imap_uid) {
        return 0;
    }

    /* Ignore anything but contacts. */
    if (cdata->kind != CARDDAV_KIND_CONTACT) {
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

    /* Load contact from record. */
    struct vparse_card *vcard = record_to_vcard(crock->mailbox, &record);
    if (!vcard || !vcard->objects) {
        syslog(LOG_ERR, "record_to_vcard failed for record %u:%s",
                cdata->dav.imap_uid, crock->mailbox->name);
        vparse_free_card(vcard);
        r = IMAP_INTERNAL;
        goto done;
    }

    /* Convert the VCARD to a JMAP contact. */
    /* XXX If this conversion turns out to waste too many cycles, then first
     * initialize props with any non-NULL field in filter f or its subconditions. */
    contact = jmap_contact_from_vcard(vcard->objects, cdata, &record,
                                      NULL /* props */, crock->mailbox->name);
    vparse_free_card(vcard);

    /* Match the contact against the filter and update statistics. */
    struct contact_filter_rock cfrock;
    cfrock.carddavdb = crock->carddavdb;
    cfrock.cdata = cdata;
    cfrock.contact = contact;
    if (crock->filter && !jmap_filter_match(crock->filter, &contact_filter_match, &cfrock)) {
        goto done;
    }
    crock->total++;
    if (crock->position > crock->total) {
        goto done;
    }
    if (crock->limit && crock->limit >= json_array_size(crock->contacts)) {
        goto done;
    }

    /* All done. Add the contact identifier. */
    json_array_append_new(crock->contacts, json_string(cdata->vcard_uid));

done:
    if (contact) json_decref(contact);
    return r;
}

static int getContactList(struct jmap_req *req)
{
    int r = 0, pe;
    json_t *invalid;
    int dofetch = 0;
    json_t *filter;
    struct contactlist_rock rock;
    struct carddav_db *db;

    memset(&rock, 0, sizeof(struct contactlist_rock));

    db = carddav_open_userid(req->userid);
    if (!db) {
        syslog(LOG_ERR, "carddav_open_userid failed for user %s", req->userid);
        r = IMAP_INTERNAL;
        goto done;
    }

    /* Parse and validate arguments. */
    invalid = json_pack("[]");

    /* filter */
    filter = json_object_get(req->args, "filter");
    if (JNOTNULL(filter)) {
        rock.filter = jmap_filter_parse(filter, "filter", invalid, contact_filter_parse);
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

    /* fetchRecords */
    if (JNOTNULL(json_object_get(req->args, "fetchRecords"))) {
        readprop(req->args, "fetchRecords", 0 /*mandatory*/, invalid, "b", &dofetch);
    }

    if (json_array_size(invalid)) {
        json_t *err = json_pack("{s:s, s:o}", "type", "invalidArguments", "arguments", invalid);
        json_array_append_new(req->response, json_pack("[s,o,s]", "error", err, req->tag));
        r = 0;
        goto done;
    }
    json_decref(invalid);

    /* Inspect every entry in this accounts addressbok mailboxes. */
    rock.contacts = json_pack("[]");
    rock.carddavdb = db;
    r = carddav_foreach(db, NULL, getcontactlist_cb, &rock);
    if (rock.mailbox) mailbox_close(&rock.mailbox);
    if (r) goto done;

    /* Prepare response. */
    json_t *contactList = json_pack("{}");
    json_object_set_new(contactList, "accountId", json_string(req->userid));
    json_object_set_new(contactList, "state", jmap_getstate(MBTYPE_CALENDAR, req));
    json_object_set_new(contactList, "position", json_integer(rock.position));
    json_object_set_new(contactList, "total", json_integer(rock.total));
    json_object_set(contactList, "contactIds", rock.contacts);
    if (filter) json_object_set(contactList, "filter", filter);

    json_t *item = json_pack("[]");
    json_array_append_new(item, json_string("contactList"));
    json_array_append_new(item, contactList);
    json_array_append_new(item, json_string(req->tag));
    json_array_append_new(req->response, item);

    /* Fetch updated records, if requested. */
    if (dofetch && json_array_size(rock.contacts)) {
        struct jmap_req subreq = *req;
        subreq.args = json_pack("{}");
        json_object_set(subreq.args, "ids", rock.contacts);
        r = getContacts(&subreq);
        json_decref(subreq.args);
    }

done:
    if (rock.filter) jmap_filter_free(rock.filter, contact_filter_free);
    if (rock.contacts) json_decref(rock.contacts);
    if (db) carddav_close(db);
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

static int _emails_to_card(struct vparse_card *card, json_t *arg, json_t *invalid)
{
    vparse_delete_entries(card, NULL, "email");

    int i;
    int size = json_array_size(arg);
    struct buf buf = BUF_INITIALIZER;
    for (i = 0; i < size; i++) {
        json_t *item = json_array_get(arg, i);

        buf_printf(&buf, "emails[%d]", i);
        const char *prefix = buf_cstring(&buf);

        /* Parse properties. */
        const char *type = NULL;
        const char *label = NULL;
        const char *value = NULL;
        int pe; /* parse error */

        pe = readprop_full(item, prefix, "type", 1, invalid, "s", &type);
        pe = readprop_full(item, prefix, "value", 1, invalid, "s", &value);
        pe = readprop_full(item, prefix, "label", 0, invalid, "s", &label);
        json_t *jisDefault = json_object_get(item, "isDefault");

        /* Bail out for any property errors. */
        if (!type || !value || pe < 0) {
            buf_free(&buf);
            return -1;
        }

        /* Update card. */
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

        buf_reset(&buf);
    }
    buf_free(&buf);
    return 0;
}

static int _phones_to_card(struct vparse_card *card, json_t *arg, json_t *invalid)
{
    vparse_delete_entries(card, NULL, "tel");

    int i;
    int size = json_array_size(arg);
    struct buf buf = BUF_INITIALIZER;
    for (i = 0; i < size; i++) {
        json_t *item = json_array_get(arg, i);

        buf_printf(&buf, "phones[%d]", i);
        const char *prefix = buf_cstring(&buf);

        /* Parse properties. */
        const char *type = NULL;
        const char *label = NULL;
        const char *value = NULL;
        int pe; /* parse error */

        pe = readprop_full(item, prefix, "type", 1, invalid, "s", &type);
        pe = readprop_full(item, prefix, "value", 1, invalid, "s", &value);
        if (JNOTNULL(json_object_get(item, "label"))) {
            pe = readprop_full(item, prefix, "label", 0, invalid, "s", &label);
        }

        /* Bail out for any property errors. */
        if (!type || !value || pe < 0) {
            buf_free(&buf);
            return -1;
        }

        /* Update card. */
        struct vparse_entry *entry = vparse_add_entry(card, NULL, "tel", value);

        if (!strcmp(type, "mobile"))
            vparse_add_param(entry, "type", "cell");
        else if (strcmp(type, "other"))
            vparse_add_param(entry, "type", type);

        if (label)
            vparse_add_param(entry, "label", label);

        buf_reset(&buf);
    }
    buf_free(&buf);
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

static int _online_to_card(struct vparse_card *card, json_t *arg, json_t *invalid)
{
    vparse_delete_entries(card, NULL, "url");
    vparse_delete_entries(card, NULL, "impp");
    vparse_delete_entries(card, NULL, "x-social-profile");
    vparse_delete_entries(card, NULL, "x-fm-online-other");

    int i;
    int size = json_array_size(arg);
    struct buf buf = BUF_INITIALIZER;
    for (i = 0; i < size; i++) {
        json_t *item = json_array_get(arg, i);

        buf_printf(&buf, "online[%d]", i);
        const char *prefix = buf_cstring(&buf);

        /* Parse properties. */
        const char *type = NULL;
        const char *label = NULL;
        const char *value = NULL;
        int pe; /* parse error */

        pe = readprop_full(item, prefix, "type", 1, invalid, "s", &type);
        pe = readprop_full(item, prefix, "value", 1, invalid, "s", &value);
        if (JNOTNULL(json_object_get(item, "label"))) {
            pe = readprop_full(item, prefix, "label", 0, invalid, "s", &label);
        }

        /* Bail out for any property errors. */
        if (!type || !value || pe < 0) {
            buf_free(&buf);
            return -1;
        }

        /* Update card. */
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
    buf_free(&buf);
    return 0;
}

static int _addresses_to_card(struct vparse_card *card, json_t *arg, json_t *invalid)
{
    vparse_delete_entries(card, NULL, "adr");

    int i;
    int size = json_array_size(arg);
    struct buf buf = BUF_INITIALIZER;
    for (i = 0; i < size; i++) {
        json_t *item = json_array_get(arg, i);

        buf_printf(&buf, "addresses[%d]", i);
        const char *prefix = buf_cstring(&buf);

        /* Parse properties. */
        const char *type = NULL;
        const char *label = NULL;
        const char *street = NULL;
        const char *locality = NULL;
        const char *region = NULL;
        const char *postcode = NULL;
        const char *country = NULL;
        int pe; /* parse error */

        /* Mandatory */
        pe = readprop_full(item, prefix, "type", 1, invalid, "s", &type);
        pe = readprop_full(item, prefix, "street", 1, invalid, "s", &street);
        pe = readprop_full(item, prefix, "locality", 1, invalid, "s", &locality);
        pe = readprop_full(item, prefix, "region", 1, invalid, "s", &region);
        pe = readprop_full(item, prefix, "postcode", 1, invalid, "s", &postcode);
        pe = readprop_full(item, prefix, "country", 1, invalid, "s", &country);

        /* Optional */
        if (JNOTNULL(json_object_get(item, "label"))) {
            pe = readprop_full(item, prefix, "label", 0, invalid, "s", &label);
        }

        /* Bail out for any property errors. */
        if (!type || !street || !locality || !region || !postcode || !country || pe < 0) {
            buf_free(&buf);
            return -1;
        }

        /* Update card. */
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

        buf_reset(&buf);
    }

    buf_free(&buf);
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
    if (_parse_date(val, &y, &m, &d, 1))
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

static int _json_to_card(const char *uid,
                         struct vparse_card *card,
                         json_t *arg, strarray_t *flags,
                         struct entryattlist **annotsp,
                         json_t *invalid)
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
            } else if (json_is_false(jval)) {
                strarray_remove_all_case(flags, "\\Flagged");
            } else {
                json_array_append_new(invalid, json_string("isFlagged"));
                return -1;
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
            if (!val) {
                json_array_append_new(invalid, json_string("prefix"));
                return -1;
            }
            name_is_dirty = 1;
            struct vparse_entry *n = _card_multi(card, "n");
            strarray_set(n->v.values, 3, val);
        }
        else if (!strcmp(key, "firstName")) {
            const char *val = json_string_value(jval);
            if (!val) {
                json_array_append_new(invalid, json_string("firstName"));
                return -1;
            }
            name_is_dirty = 1;
            /* JMAP doesn't have a separate field for Middle (aka "Additional
             * Names"), so any extra names are probably in firstName, and we
             * should split them out. See reverse of this in getcontacts_cb */
            struct vparse_entry *n = _card_multi(card, "n");
            const char *middle = strchr(val, ' ');
            if (middle) {
                /* multiple worlds, first to First, rest to Middle */
                strarray_setm(n->v.values, 1, xstrndup(val, middle-val));
                strarray_set(n->v.values, 2, ++middle);
            }
            else {
                /* single word, set First, clear Middle */
                strarray_set(n->v.values, 1, val);
                strarray_set(n->v.values, 2, "");
            }
        }
        else if (!strcmp(key, "lastName")) {
            const char *val = json_string_value(jval);
            if (!val) {
                json_array_append_new(invalid, json_string("lastName"));
                return -1;
            }
            name_is_dirty = 1;
            struct vparse_entry *n = _card_multi(card, "n");
            strarray_set(n->v.values, 0, val);
        }
        else if (!strcmp(key, "suffix")) {
            const char *val = json_string_value(jval);
            if (!val) {
                json_array_append_new(invalid, json_string("suffix"));
                return -1;
            }
            name_is_dirty = 1;
            struct vparse_entry *n = _card_multi(card, "n");
            strarray_set(n->v.values, 4, val);
        }
        else if (!strcmp(key, "nickname")) {
            int r = _kv_to_card(card, "nickname", jval);
            if (r) {
                json_array_append_new(invalid, json_string("nickname"));
                return r;
            }
            record_is_dirty = 1;
        }
        else if (!strcmp(key, "birthday")) {
            int r = _date_to_card(card, "bday", jval);
            if (r) {
                json_array_append_new(invalid, json_string("birthday"));
                return r;
            }
            record_is_dirty = 1;
        }
        else if (!strcmp(key, "anniversary")) {
            int r = _date_to_card(card, "anniversary", jval);
            if (r) {
                json_array_append_new(invalid, json_string("anniversary"));
                return r;
            }
            record_is_dirty = 1;
        }
        else if (!strcmp(key, "jobTitle")) {
            int r = _kv_to_card(card, "title", jval);
            if (r) {
                json_array_append_new(invalid, json_string("jobTitle"));
                return r;
            }
            record_is_dirty = 1;
        }
        else if (!strcmp(key, "company")) {
            const char *val = json_string_value(jval);
            if (!val) {
                json_array_append_new(invalid, json_string("company"));
                return -1;
            }
            struct vparse_entry *org = _card_multi(card, "org");
            strarray_set(org->v.values, 0, val);
            record_is_dirty = 1;
        }
        else if (!strcmp(key, "department")) {
            const char *val = json_string_value(jval);
            if (!val) {
                json_array_append_new(invalid, json_string("department"));
                return -1;
            }
            struct vparse_entry *org = _card_multi(card, "org");
            strarray_set(org->v.values, 1, val);
            record_is_dirty = 1;
        }
        else if (!strcmp(key, "emails")) {
            int r = _emails_to_card(card, jval, invalid);
            if (r) return r;
            record_is_dirty = 1;
        }
        else if (!strcmp(key, "phones")) {
            int r = _phones_to_card(card, jval, invalid);
            if (r) return r;
            record_is_dirty = 1;
        }
        else if (!strcmp(key, "online")) {
            int r = _online_to_card(card, jval, invalid);
            if (r) return r;
            record_is_dirty = 1;
        }
        else if (!strcmp(key, "addresses")) {
            int r = _addresses_to_card(card, jval, invalid);
            if (r) return r;
            record_is_dirty = 1;
        }
        else if (!strcmp(key, "notes")) {
            int r = _kv_to_card(card, "note", jval);
            if (r) {
                json_array_append_new(invalid, json_string("notes"));
                return r;
            }
            record_is_dirty = 1;
        } if (!strcmp(key, "id")) {
            const char *val = json_string_value(jval);
            if (!val || (uid && strcmp(uid, val))) {
                json_array_append_new(invalid, json_string("id"));
                return -1;
            }
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
    if (jcheckState && jmap_checkstate(jcheckState, MBTYPE_ADDRESSBOOK, req)) {
        json_t *item = json_pack("[s, {s:s}, s]",
                "error", "type", "stateMismatch",
                req->tag);
        json_array_append_new(req->response, item);
        goto done;
    }
    json_t *set = json_pack("{s:o,s:s}",
                            "oldState", jmap_getstate(MBTYPE_ADDRESSBOOK, req),
                            "accountId", req->userid);

    r = carddav_create_defaultaddressbook(req->userid);
    if (r) goto done;

    json_t *create = json_object_get(req->args, "create");
    if (create) {
        json_t *created = json_pack("{}");
        json_t *notCreated = json_pack("{}");
        json_t *record;

        const char *key;
        json_t *arg;
        json_object_foreach(create, key, arg) {
            const char *uid = makeuuid();
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

            strarray_t *flags = strarray_new();
            json_t *invalid = json_pack("[]");
            r = _json_to_card(uid, card, arg, flags, &annots, invalid);
            if (r || json_array_size(invalid)) {
                /* this is just a failure */
                r = 0;
                json_t *err = json_pack("{s:s}", "type", "invalidProperties");
                if (json_array_size(invalid)) {
                    json_object_set(err, "properties", invalid);
                }
                json_decref(invalid);
                json_object_set_new(notCreated, key, err);
                strarray_free(flags);
                freeentryatts(annots);
                vparse_free_card(card);
                continue;
            }
            json_decref(invalid);

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
            hash_insert(key, xstrdup(uid), &req->idmap->contacts);
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
        json_t *updated = json_pack("{}");
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

            struct index_record record;

            r = mailbox_find_index_record(mailbox, cdata->dav.imap_uid, &record);
            if (r) goto done;

            olduid = cdata->dav.imap_uid;
            resource = xstrdup(cdata->dav.resource);

            strarray_t *flags =
                mailbox_extract_flags(mailbox, &record, req->userid);
            struct entryattlist *annots =
                mailbox_extract_annots(mailbox, &record);

            /* Load message containing the resource and parse vcard data */
            struct vparse_card *vcard = record_to_vcard(mailbox, &record);
            if (!vcard || !vcard->objects) {
                syslog(LOG_ERR, "record_to_vcard failed for record %u:%s",
                       cdata->dav.imap_uid, mailbox->name);
                r = 0;
                json_t *err = json_pack("{s:s}", "type", "parseError");
                json_object_set_new(notUpdated, uid, err);
                vparse_free_card(vcard);
                strarray_free(flags);
                freeentryatts(annots);
                mailbox_close(&newmailbox);
                free(resource);
                continue;
            }
            struct vparse_card *card = vcard->objects;

            json_t *invalid = json_pack("[]");

            r = _json_to_card(uid, card, arg, flags, &annots, invalid);
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
                    json_decref(invalid);
                    goto finish;
                }
            }
            if (r || json_array_size(invalid)) {
                /* this is just a failure to create the JSON, not an error */
                r = 0;
                json_t *err = json_pack("{s:s}", "type", "invalidProperties");
                if (json_array_size(invalid)) {
                    json_object_set(err, "properties", invalid);
                }
                json_decref(invalid);
                json_object_set_new(notUpdated, uid, err);
                vparse_free_card(vcard);
                strarray_free(flags);
                freeentryatts(annots);
                mailbox_close(&newmailbox);
                free(resource);
                continue;
            }
            json_decref(invalid);

            syslog(LOG_NOTICE, "jmap: update contact %s/%s",
                   req->userid, resource);
            r = carddav_store(newmailbox ? newmailbox : mailbox, card, resource,
                              flags, annots, req->userid, req->authstate, ignorequota);
            if (!r)
                r = carddav_remove(mailbox, olduid, /*isreplace*/!newmailbox, req->userid);

         finish:
            mailbox_close(&newmailbox);
            strarray_free(flags);
            freeentryatts(annots);

            vparse_free_card(vcard);
            free(resource);

            if (r) goto done;

            json_object_set_new(updated, uid, json_null());
        }

        if (json_object_size(updated))
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

            syslog(LOG_NOTICE, "jmap: remove contact %s/%s", req->userid, uid);
            r = carddav_remove(mailbox, olduid, /*isreplace*/0, req->userid);
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
    if (json_object_get(set, "created") ||
        json_object_get(set, "updated") ||
        json_object_get(set, "destroyed")) {

        r = jmap_bumpstate(MBTYPE_ADDRESSBOOK, req);
        if (r) goto done;
    }
    json_object_set_new(set, "newState", jmap_getstate(MBTYPE_ADDRESSBOOK, req));

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

