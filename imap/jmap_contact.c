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

#include "annotate.h"
#include "carddav_db.h"
#include "global.h"
#include "hash.h"
#include "http_carddav.h"
#include "http_dav.h"
#include "http_jmap.h"
#include "json_support.h"
#include "mailbox.h"
#include "mboxname.h"
#include "stristr.h"
#include "times.h"
#include "util.h"
#include "vcard_support.h"
#include "xmalloc.h"

/* generated headers are not necessarily in current directory */
#include "imap/http_err.h"
#include "imap/imap_err.h"

static int getContactGroups(struct jmap_req *req);
static int getContactsGroupUpdates(struct jmap_req *req);
static int setContactGroups(struct jmap_req *req);
static int getContacts(struct jmap_req *req);
static int getContactsUpdates(struct jmap_req *req);
static int getContactsList(struct jmap_req *req);
static int setContacts(struct jmap_req *req);

jmap_method_t jmap_contact_methods[] = {
    { "ContactGroup/get",        &getContactGroups },
    { "ContactGroup/changes",    &getContactsGroupUpdates },
    { "ContactGroup/set",        &setContactGroups },
    { "Contact/get",             &getContacts },
    { "Contact/changes",         &getContactsUpdates },
    { "Contact/query",           &getContactsList },
    { "Contact/set",             &setContacts },
    { NULL,                      NULL}
};

int jmap_contact_init(hash_table *methods, json_t *capabilities __attribute__((unused)))
{
    jmap_method_t *mp;
    for (mp = jmap_contact_methods; mp->name; mp++) {
        hash_insert(mp->name, mp, methods);
    }
    return 0;
}

struct updates_rock {
    jmap_req_t *req;
    struct jmap_changes *changes;
    size_t seen_records;
    modseq_t highestmodseq;
};

static void strip_spurious_deletes(struct updates_rock *urock)
{
    /* if something is mentioned in both DELETEs and UPDATEs, it's probably
     * a move.  O(N*M) algorithm, but there are rarely many, and the alternative
     * of a hash will cost more */
    unsigned i, j;

    for (i = 0; i < json_array_size(urock->changes->destroyed); i++) {
        const char *del =
            json_string_value(json_array_get(urock->changes->destroyed, i));

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
static int jmap_match_jsonprop(json_t *arg, const char *name, const char *text)
{
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

/*
 * FIXME Refactored JMAP filter into contacts, since we don't
 * need it anymore for calendar events. You are next, contacts!
 */

enum jmap_filter_op   {
    JMAP_FILTER_OP_NONE = 0,
    JMAP_FILTER_OP_AND,
    JMAP_FILTER_OP_OR,
    JMAP_FILTER_OP_NOT
};

typedef struct jmap_filter {
    enum jmap_filter_op op;
    ptrarray_t conditions;
} jmap_filter;

typedef void* jmap_filterparse_cb(json_t* arg);
typedef int   jmap_filtermatch_cb(void* cond, void* rock);
typedef void  jmap_filterfree_cb(void* cond);

static int jmap_filter_match(jmap_filter *f,
                             jmap_filtermatch_cb *match, void *rock)
{
    if (f->op == JMAP_FILTER_OP_NONE) {
        return match(ptrarray_head(&f->conditions), rock);
    } else {
        int i;
        for (i = 0; i < ptrarray_size(&f->conditions); i++) {
            int m = jmap_filter_match(ptrarray_nth(&f->conditions, i), match, rock);
            if (m && f->op == JMAP_FILTER_OP_OR) {
                return 1;
            } else if (m && f->op == JMAP_FILTER_OP_NOT) {
                return 0;
            } else if (!m && f->op == JMAP_FILTER_OP_AND) {
                return 0;
            }
        }
        return f->op == JMAP_FILTER_OP_AND || f->op == JMAP_FILTER_OP_NOT;
    }
}

static void jmap_filter_free(jmap_filter *f, jmap_filterfree_cb *freecond)
{
    void *cond;

    while ((cond = ptrarray_pop(&f->conditions))) {
        if (freecond) freecond(cond);
    }
    ptrarray_fini(&f->conditions);
    free(f);
}

static jmap_filter *buildfilter(json_t *arg, jmap_filterparse_cb *parse)
{
    jmap_filter *f = (jmap_filter *) xzmalloc(sizeof(struct jmap_filter));
    int pe;
    const char *val;
    int iscond = 1;

    /* operator */
    pe = readprop_full(arg, NULL, "operator",
                       0 /*mandatory*/, NULL, "s", &val);
    if (pe > 0) {
        if (!strncmp("AND", val, 3)) {
            f->op = JMAP_FILTER_OP_AND;
        } else if (!strncmp("OR", val, 2)) {
            f->op = JMAP_FILTER_OP_OR;
        } else if (!strncmp("NOT", val, 3)) {
            f->op = JMAP_FILTER_OP_NOT;
        }
    }
    iscond = f->op == JMAP_FILTER_OP_NONE;

    /* conditions */
    json_t *conds = json_object_get(arg, "conditions");
    if (conds && !iscond && json_array_size(conds)) {
        size_t i, n_conditions = json_array_size(conds);
        for (i = 0; i < n_conditions; i++) {
            json_t *cond = json_array_get(conds, i);
            ptrarray_push(&f->conditions, buildfilter(cond, parse));
        }
    }

    if (iscond) {
        ptrarray_push(&f->conditions, parse(arg));
    }

    return f;
}

/*****************************************************************************
 * JMAP Contacts API
 ****************************************************************************/

struct cards_rock {
    struct jmap_req *req;
    struct jmap_get *get;
    struct mailbox *mailbox;
    int rows;
};

static int getgroups_cb(void *rock, struct carddav_data *cdata)
{
    struct cards_rock *crock = (struct cards_rock *) rock;
    struct index_record record;
    jmap_req_t *req = crock->req;
    char *xhref;
    int r;

    int rights = jmap_myrights_byname(req, cdata->dav.mailbox);
    if (!(rights & DACL_READ)) return 0;

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

    json_array_append_new(crock->get->list, obj);

    vparse_free_card(vcard);

    return 0;
}

static const jmap_property_t contact_props[] = {
    { "id",          JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE },
    { "isFlagged",   0 },
    { "avatar",      0 },
    { "prefix",      0 },
    { "firstName",   0 },
    { "lastName",    0 },
    { "suffix",      0 },
    { "nickname",    0 },
    { "birthday",    0 },
    { "anniversary", 0 },
    { "company",     0 },
    { "department",  0 },
    { "jobTitle",    0 },
    { "emails",      0 },
    { "phones",      0 },
    { "online",      0 },
    { "addresses",   0 },
    { "notes",       0 },

    /* FM extensions */
    { "x-href",      JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE }, // AJAXUI only
    { "x-hasPhoto",  JMAP_PROP_SERVER_SET }, // AJAXUI only
    { "x-importance",0 },  // AJAXUI only
    { "importance",  0 },  // JMAPUI only

    { NULL,          0 }
};

static const jmap_property_t group_props[] = {
    { "id",          JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE },
    { "name",        0 },
    { "contactIds",  0 },

    // FM extensions */
    { "otherAccountContactIds", 0}, // Both AJAXUI and JMAPUI

    { NULL,          0 }
};

static int jmap_contacts_get(struct jmap_req *req, carddav_cb_t *cb, int kind)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_get get;
    json_t *err = NULL;
    int r = 0;

    r = carddav_create_defaultaddressbook(req->accountid);
    if (r == IMAP_MAILBOX_NONEXISTENT) {
        /* The account exists but does not have a root mailbox. */
        jmap_error(req, json_pack("{s:s}", "type", "accountNoAddressbooks"));
        return 0;
    } else if (r) return r;

    struct carddav_db *db = carddav_open_userid(req->accountid);
    if (!db) {
        syslog(LOG_ERR,
               "caldav_open_mailbox failed for user %s", req->accountid);
        return IMAP_INTERNAL;
    }

    char *mboxname = NULL;
    json_t *abookid = json_object_get(req->args, "addressbookId");
    if (abookid && json_string_value(abookid)) {
        /* XXX - invalid arguments */
        const char *addressbookId = json_string_value(abookid);
        mboxname = carddav_mboxname(req->accountid, addressbookId);
    }

    /* Build callback data */
    struct cards_rock rock = { req, &get, NULL /*mailbox*/, 0 /*rows */ };

    /* Parse request */
    jmap_get_parse(req->args, &parser, req,
                   kind == CARDDAV_KIND_GROUP ? group_props : contact_props,
                   NULL, NULL, &get, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    /* Does the client request specific events? */
    if (JNOTNULL(get.ids)) {
        size_t i;
        json_t *jval;
        json_array_foreach(get.ids, i, jval) {
            rock.rows = 0;
            const char *id = json_string_value(jval);

            r = carddav_get_cards(db, mboxname, id, kind, cb, &rock);
            if (r || !rock.rows) {
                json_array_append(get.not_found, jval);
            }
        }
    }
    else {
        rock.rows = 0;
        r = carddav_get_cards(db, mboxname, NULL, kind, cb, &rock);
    }

    /* Build response */
    json_t *jstate = jmap_getstate(req, MBTYPE_ADDRESSBOOK, /*refresh*/0);
    get.state = xstrdup(json_string_value(jstate));
    json_decref(jstate);
    jmap_ok(req, jmap_get_reply(&get));

  done:
    jmap_parser_fini(&parser);
    jmap_get_fini(&get);
    free(mboxname);
    mailbox_close(&rock.mailbox);
    carddav_close(db);
    return r;
}

static int getContactGroups(struct jmap_req *req)
{
    return jmap_contacts_get(req, &getgroups_cb, CARDDAV_KIND_GROUP);
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
    struct dav_data dav = cdata->dav;
    const char *uid = cdata->vcard_uid;
    int rights = jmap_myrights_byname(urock->req, dav.mailbox);
    if (!(rights & DACL_READ)) return 0;

    /* Count, but don't process items that exceed the maximum record count. */
    if (urock->changes->max_changes &&
        ++(urock->seen_records) > urock->changes->max_changes) {
        urock->changes->has_more_changes = 1;
        return 0;
    }

    /* Report item as updated or destroyed. */
    if (dav.alive) {
        if (dav.createdmodseq <= urock->changes->since_modseq)
            json_array_append_new(urock->changes->updated, json_string(uid));
        else
            json_array_append_new(urock->changes->created, json_string(uid));
    } else {
        if (dav.createdmodseq <= urock->changes->since_modseq)
            json_array_append_new(urock->changes->destroyed, json_string(uid));
    }

    /* Fetch record to determine modseq. */
    if (dav.modseq > urock->highestmodseq) {
        urock->highestmodseq = dav.modseq;
    }

    return 0;
}

static int jmap_contacts_updates(struct jmap_req *req, int kind)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_changes changes;
    json_t *err = NULL;
    struct carddav_db *db = carddav_open_userid(req->accountid);
    if (!db) return -1;
    int r = -1;

    /* Parse request */
    jmap_changes_parse(req->args, &parser, &changes, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    /* Non-JMAP spec addressbookId argument */
    char *mboxname = NULL;
    json_t *abookid = json_object_get(req->args, "addressbookId");
    if (abookid && json_string_value(abookid)) {
        const char *addressbookId = json_string_value(abookid);
        mboxname = carddav_mboxname(req->accountid, addressbookId);
    }

    r = carddav_create_defaultaddressbook(req->accountid);
    if (r) goto done;

    /* Lookup updates. */
    struct updates_rock rock = { req, &changes, 0 /*seen_records*/, 0 /*highestmodseq*/};
    r = carddav_get_updates(db, changes.since_modseq, mboxname, kind,
                            -1 /*max_records*/, &getcontactupdates_cb, &rock);
    if (r) goto done;

    strip_spurious_deletes(&rock);

    /* Determine new state. */
    changes.new_modseq = changes.has_more_changes ?
        rock.highestmodseq : jmap_highestmodseq(req, MBTYPE_ADDRESSBOOK);

    /* Build response */
    jmap_ok(req, jmap_changes_reply(&changes));

  done:
    jmap_changes_fini(&changes);
    jmap_parser_fini(&parser);
    carddav_close(db);

    return r;
}

static int getContactsGroupUpdates(struct jmap_req *req)
{
    return jmap_contacts_updates(req, CARDDAV_KIND_GROUP);
}

static const char *_resolve_contactid(struct jmap_req *req, const char *id)
{
    if (id && *id == '#') {
        return jmap_lookup_id(req, id + 1);
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
        const char *uid = _resolve_contactid(req, item);
        if (!item || !uid) {
            buf_printf(&buf, "contactIds[%zu]", index);
            json_array_append_new(invalid, json_string(buf_cstring(&buf)));
            buf_reset(&buf);
            continue;
        }
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
            const char *uid = _resolve_contactid(req, item);
            if (!item || !uid) {
                buf_printf(&buf, "otherContactIds[%s]", key);
                json_array_append_new(invalid, json_string(buf_cstring(&buf)));
                buf_reset(&buf);
                continue;
            }
            buf_setcstr(&buf, "urn:uuid:");
            buf_appendcstr(&buf, uid);
            struct vparse_entry *entry =
                vparse_add_entry(card, NULL,
                                 "X-FM-OTHERACCOUNT-MEMBER", buf_cstring(&buf));
            vparse_add_param(entry, "USERID", key);
            buf_reset(&buf);
        }
    }
    buf_free(&buf);
    return r;
}

static int setContactGroups(struct jmap_req *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_set set;
    json_t *err = NULL;
    int r = 0;

    struct mailbox *mailbox = NULL;
    struct mailbox *newmailbox = NULL;

    struct carddav_db *db = carddav_open_userid(req->accountid);
    if (!db) return -1;

    /* Parse arguments */
    jmap_set_parse(req->args, &parser, &set, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    if (set.if_in_state) {
        /* TODO rewrite state function to use char* not json_t* */
        json_t *jstate = json_string(set.if_in_state);
        if (jmap_cmpstate(req, jstate, MBTYPE_ADDRESSBOOK)) {
            jmap_error(req, json_pack("{s:s}", "type", "stateMismatch"));
            goto done;
        }
        json_decref(jstate);
        set.old_state = xstrdup(set.if_in_state);
    }
    else {
        json_t *jstate = jmap_getstate(req, MBTYPE_ADDRESSBOOK, /*refresh*/0);
        set.old_state = xstrdup(json_string_value(jstate));
        json_decref(jstate);
    }

    r = carddav_create_defaultaddressbook(req->accountid);
    if (r) goto done;

    /* create */
    const char *key;
    json_t *arg, *record;
    json_object_foreach(set.create, key, arg) {
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
                                    "type", "invalidProperties",
                                    "properties", invalid);
            json_object_set_new(set.not_created, key, err);
            vparse_free_card(card);
            free(uid);
            continue;
        }

        const char *addressbookId = "Default";
        json_t *abookid = json_object_get(arg, "addressbookId");
        if (abookid && json_string_value(abookid)) {
            /* XXX - invalid arguments */
            addressbookId = json_string_value(abookid);
        }
        char *mboxname = mboxname_abook(req->accountid, addressbookId);
        json_object_del(arg, "addressbookId");
        addressbookId = NULL;

        int rights = jmap_myrights_byname(req, mboxname);
        if (!(rights & DACL_WRITE)) {
            json_array_append_new(invalid, json_string("addressbookId"));
            json_t *err = json_pack("{s:s, s:o}",
                                    "type", "invalidProperties",
                                    "properties", invalid);
            json_object_set_new(set.not_created, key, err);
            vparse_free_card(card);
            free(uid);
            continue;
        }
        json_decref(invalid);

        /* we need to create and append a record */
        if (!mailbox || strcmp(mailbox->name, mboxname)) {
            mailbox_close(&mailbox);
            r = mailbox_open_iwl(mboxname, &mailbox);
        }

        syslog(LOG_NOTICE, "jmap: create group %s/%s/%s (%s)",
               req->accountid, mboxname, uid, name);
        free(mboxname);

        if (!r) r = carddav_store(mailbox, card, NULL, 0, NULL, NULL,
                                  req->accountid, req->authstate, ignorequota);
        vparse_free_card(card);

        if (r) {
            /* these are real "should never happen" errors */
            free(uid);
            goto done;
        }

        record = json_pack("{s:s}", "id", uid);
        json_object_set_new(set.created, key, record);

        /* Register creation id */
        jmap_add_id(req, key, uid);
        free(uid);
    }

    /* update */
    const char *uid;
    json_object_foreach(set.update, uid, arg) {
        struct carddav_data *cdata = NULL;
        r = carddav_lookup_uid(db, uid, &cdata);
        uint32_t olduid;
        char *resource = NULL;

        /* is it a valid group? */
        if (r || !cdata || !cdata->dav.imap_uid || !cdata->dav.resource
            || cdata->kind != CARDDAV_KIND_GROUP) {
            r = 0;
            json_t *err = json_pack("{s:s}", "type", "notFound");
            json_object_set_new(set.not_updated, uid, err);
            continue;
        }
        olduid = cdata->dav.imap_uid;
        resource = xstrdup(cdata->dav.resource);

        int rights = jmap_myrights_byname(req, cdata->dav.mailbox);
        if (!(rights & DACL_WRITE)) {
            json_t *err = json_pack("{s:s}", "type",
                                    rights & ACL_READ ?
                                    "accountReadOnly" : "notFound");
            json_object_set_new(set.not_updated, uid, err);
            free(resource);
            continue;
        }

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
                mboxname_abook(req->accountid, json_string_value(abookid));
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

        r = mailbox_find_index_record(mailbox, cdata->dav.imap_uid, &record);
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
            json_object_set_new(set.not_updated, uid, err);
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
                json_object_set_new(set.not_updated, uid, err);
                vparse_free_card(vcard);
                mailbox_close(&newmailbox);
                free(resource);
                continue;
            }

            vparse_replace_entry(card, NULL, "FN", name);
            vparse_replace_entry(card, NULL, "N", name);
        }
        else if (!vparse_get_entry(card, NULL, "N")) {
            struct vparse_entry *entry = vparse_get_entry(card, NULL, "FN");
            if (entry) vparse_replace_entry(card, NULL, "N", entry->v.value);
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
                                    "type", "invalidProperties",
                                    "properties", invalid);
            json_object_set_new(set.not_updated, uid, err);
            vparse_free_card(vcard);
            mailbox_close(&newmailbox);
            free(resource);
            continue;
        }
        json_decref(invalid);

        syslog(LOG_NOTICE, "jmap: update group %s/%s",
               req->accountid, resource);

        r = carddav_store(newmailbox ? newmailbox : mailbox, card, resource,
                          record.createdmodseq, NULL, NULL, req->accountid,
                          req->authstate, ignorequota);
        if (!r)
            r = carddav_remove(mailbox, olduid,
                               /*isreplace*/!newmailbox, req->accountid);
        mailbox_close(&newmailbox);

        vparse_free_card(vcard);
        free(resource);
        if (r) goto done;

        json_object_set_new(set.updated, uid, json_null());
    }


    /* destroy */
    size_t index;
    for (index = 0; index < json_array_size(set.destroy); index++) {
        const char *uid = _json_array_get_string(set.destroy, index);
        if (!uid) {
            json_t *err = json_pack("{s:s}", "type", "invalidArguments");
            json_object_set_new(set.not_destroyed, uid, err);
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
            json_object_set_new(set.not_destroyed, uid, err);
            continue;
        }
        olduid = cdata->dav.imap_uid;

        int rights = jmap_myrights_byname(req, cdata->dav.mailbox);
        if (!(rights & DACL_WRITE)) {
            json_t *err = json_pack("{s:s}", "type",
                                    rights & ACL_READ ?
                                    "accountReadOnly" : "notFound");
            json_object_set_new(set.not_destroyed, uid, err);
            continue;
        }

        if (!mailbox || strcmp(mailbox->name, cdata->dav.mailbox)) {
            mailbox_close(&mailbox);
            r = mailbox_open_iwl(cdata->dav.mailbox, &mailbox);
            if (r) goto done;
        }

        /* XXX - alive check */

        syslog(LOG_NOTICE,
               "jmap: destroy group %s (%s)", req->accountid, uid);
        r = carddav_remove(mailbox, olduid, /*isreplace*/0, req->accountid);
        if (r) {
            syslog(LOG_ERR,
                   "IOERROR: setContactGroups remove failed for %s %u",
                   mailbox->name, cdata->dav.imap_uid);
            goto done;
        }

        json_array_append_new(set.destroyed, json_string(uid));
    }

    /* force modseq to stable */
    if (mailbox) mailbox_unlock_index(mailbox, NULL);

    // TODO refactor jmap_getstate to return a string, once
    // all code has been migrated to the new JMAP parser.
    json_t *jstate = jmap_getstate(req, MBTYPE_ADDRESSBOOK, /*refresh*/1);
    set.new_state = xstrdup(json_string_value(jstate));
    json_decref(jstate);

    jmap_ok(req, jmap_set_reply(&set));

done:
    jmap_parser_fini(&parser);
    jmap_set_fini(&set);
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
static int _parse_date(const char *date, unsigned *y,
                       unsigned *m, unsigned *d, int require_hyphens)
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

    // need to keep the x- version while AJAXUI is around
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

    // also fetchable without the x- for JMAPUI
    if (_wantprop(props, "importance")) {
        double val = 0;
        const char *ns = DAV_ANNOT_NS "<" XML_NS_CYRUS ">importance";

        buf_reset(&buf);
        annotatemore_msg_lookup(mboxname, record->uid,
                                ns, "", &buf);
        if (buf.len)
            val = strtod(buf_cstring(&buf), NULL);

        json_object_set_new(obj, "importance", json_real(val));
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

    if (_wantprop(props, "avatar")) {
        struct vparse_entry *photo = vparse_get_entry(card, NULL, "photo");
        struct message_guid guid;
        char *type = NULL;
        unsigned size;
        json_t *file;

        if (photo &&
            (size = vcard_prop_decode_value(photo, NULL, &type, &guid))) {
            char blob_id[42];
            jmap_set_blobid(&guid, blob_id);

            file = json_pack("{s:s s:i s:s? s:n}",
                             "blobId", blob_id, "size", size,
                             "type", type, "name");
        }
        else file = json_null();

        json_object_set_new(obj, "avatar", file);
        free(type);
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

    int rights = jmap_myrights_byname(crock->req, cdata->dav.mailbox);
    if (!(rights & DACL_READ)) return 0;

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
                                          crock->get->props, crock->mailbox->name);
    json_array_append_new(crock->get->list, obj);

    vparse_free_card(vcard);

    return 0;
}

static int getContacts(struct jmap_req *req)
{
    return jmap_contacts_get(req, &getcontacts_cb, CARDDAV_KIND_CONTACT);
}

static int getContactsUpdates(struct jmap_req *req)
{
    return jmap_contacts_updates(req, CARDDAV_KIND_CONTACT);
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
    if (f->firstName &&
        !jmap_match_jsonprop(contact, "firstName", f->firstName)) {
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
    if (f->department &&
        !jmap_match_jsonprop(contact, "department", f->department)) {
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
            syslog(LOG_INFO,
                   "carddav_getuid_groups(%s) returned NULL group array",
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
static void *contact_filter_parse(json_t *arg)
{
    contact_filter *f =
        (contact_filter *) xzmalloc(sizeof(struct contact_filter));

    /* inContactGroup */
    json_t *inContactGroup = json_object_get(arg, "inContactGroup");
    if (inContactGroup) {
        f->inContactGroup = xmalloc(sizeof(struct hash_table));
        construct_hash_table(f->inContactGroup,
                             json_array_size(inContactGroup)+1, 0);
        size_t i;
        json_t *val;
        json_array_foreach(inContactGroup, i, val) {
            const char *id;
            if (json_unpack(val, "s", &id) != -1) {
                hash_insert(id, (void*)1, f->inContactGroup);
            }
        }
    }

    /* isFlagged */
    f->isFlagged = json_object_get(arg, "isFlagged");

    /* text */
    if (JNOTNULL(json_object_get(arg, "text"))) {
        readprop_full(arg, NULL, "text", 0, NULL, "s", &f->text);
    }
    /* prefix */
    if (JNOTNULL(json_object_get(arg, "prefix"))) {
        readprop_full(arg, NULL, "prefix", 0, NULL, "s", &f->prefix);
    }
    /* firstName */
    if (JNOTNULL(json_object_get(arg, "firstName"))) {
        readprop_full(arg, NULL, "firstName", 0, NULL, "s", &f->firstName);
    }
    /* lastName */
    if (JNOTNULL(json_object_get(arg, "lastName"))) {
        readprop_full(arg, NULL, "lastName", 0, NULL, "s", &f->lastName);
    }
    /* suffix */
    if (JNOTNULL(json_object_get(arg, "suffix"))) {
        readprop_full(arg, NULL, "suffix", 0, NULL, "s", &f->suffix);
    }
    /* nickname */
    if (JNOTNULL(json_object_get(arg, "nickname"))) {
        readprop_full(arg, NULL, "nickname", 0, NULL, "s", &f->nickname);
    }
    /* company */
    if (JNOTNULL(json_object_get(arg, "company"))) {
        readprop_full(arg, NULL, "company", 0, NULL, "s", &f->company);
    }
    /* department */
    if (JNOTNULL(json_object_get(arg, "department"))) {
        readprop_full(arg, NULL, "department", 0, NULL, "s", &f->department);
    }
    /* jobTitle */
    if (JNOTNULL(json_object_get(arg, "jobTitle"))) {
        readprop_full(arg, NULL, "jobTitle", 0, NULL, "s", &f->jobTitle);
    }
    /* email */
    if (JNOTNULL(json_object_get(arg, "email"))) {
        readprop_full(arg, NULL, "email", 0, NULL, "s", &f->email);
    }
    /* phone */
    if (JNOTNULL(json_object_get(arg, "phone"))) {
        readprop_full(arg, NULL, "phone", 0, NULL, "s", &f->phone);
    }
    /* online */
    if (JNOTNULL(json_object_get(arg, "online"))) {
        readprop_full(arg, NULL, "online", 0, NULL, "s", &f->online);
    }
    /* address */
    if (JNOTNULL(json_object_get(arg, "address"))) {
        readprop_full(arg, NULL, "address", 0, NULL, "s", &f->address);
    }
    /* notes */
    if (JNOTNULL(json_object_get(arg, "notes"))) {
        readprop_full(arg, NULL, "notes", 0, NULL, "s", &f->notes);
    }

    return f;
}

static void validatefilter(json_t *filter, struct jmap_parser *parser,
                           json_t *unsupported __attribute__((unused)),
                           void *rock __attribute__((unused)))
{
    struct buf buf = BUF_INITIALIZER;
    const char *s;

    if (!JNOTNULL(filter) || json_typeof(filter) != JSON_OBJECT) {
        jmap_parser_invalid(parser, NULL);
        return;
    }

    /* inContactGroup */
    json_t *inContactGroup = json_object_get(filter, "inContactGroup");
    if (inContactGroup && json_typeof(inContactGroup) != JSON_ARRAY) {
        jmap_parser_invalid(parser, "inContactGroup");
    } else if (inContactGroup) {
        size_t i;
        json_t *val;
        json_array_foreach(inContactGroup, i, val) {
            const char *id;
            if (json_unpack(val, "s", &id) == -1) {
                buf_printf(&buf, "inContactGroup[%zu]", i);
                jmap_parser_invalid(parser, buf_cstring(&buf));
                buf_reset(&buf);
            }
        }
    }

    /* text */
    if (JNOTNULL(json_object_get(filter, "text"))) {
        readprop_full(filter, NULL, "text", 0, parser->invalid, "s", &s);
    }
    /* prefix */
    if (JNOTNULL(json_object_get(filter, "prefix"))) {
        readprop_full(filter, NULL, "prefix", 0, parser->invalid, "s", &s);
    }
    /* firstName */
    if (JNOTNULL(json_object_get(filter, "firstName"))) {
        readprop_full(filter, NULL, "firstName", 0, parser->invalid, "s", &s);
    }
    /* lastName */
    if (JNOTNULL(json_object_get(filter, "lastName"))) {
        readprop_full(filter, NULL, "lastName", 0, parser->invalid, "s", &s);
    }
    /* suffix */
    if (JNOTNULL(json_object_get(filter, "suffix"))) {
        readprop_full(filter, NULL, "suffix", 0, parser->invalid, "s", &s);
    }
    /* nickname */
    if (JNOTNULL(json_object_get(filter, "nickname"))) {
        readprop_full(filter, NULL, "nickname", 0, parser->invalid, "s", &s);
    }
    /* company */
    if (JNOTNULL(json_object_get(filter, "company"))) {
        readprop_full(filter, NULL, "company", 0, parser->invalid, "s", &s);
    }
    /* department */
    if (JNOTNULL(json_object_get(filter, "department"))) {
        readprop_full(filter, NULL, "department", 0, parser->invalid, "s", &s);
    }
    /* jobTitle */
    if (JNOTNULL(json_object_get(filter, "jobTitle"))) {
        readprop_full(filter, NULL, "jobTitle", 0, parser->invalid, "s", &s);
    }
    /* email */
    if (JNOTNULL(json_object_get(filter, "email"))) {
        readprop_full(filter, NULL, "email", 0, parser->invalid, "s", &s);
    }
    /* phone */
    if (JNOTNULL(json_object_get(filter, "phone"))) {
        readprop_full(filter, NULL, "phone", 0, parser->invalid, "s", &s);
    }
    /* online */
    if (JNOTNULL(json_object_get(filter, "online"))) {
        readprop_full(filter, NULL, "online", 0, parser->invalid, "s", &s);
    }
    /* address */
    if (JNOTNULL(json_object_get(filter, "address"))) {
        readprop_full(filter, NULL, "address", 0, parser->invalid, "s", &s);
    }
    /* notes */
    if (JNOTNULL(json_object_get(filter, "notes"))) {
        readprop_full(filter, NULL, "notes", 0, parser->invalid, "s", &s);
    }

    buf_free(&buf);
}

static int validatecomparator(struct jmap_comparator *comp,
                              void *rock __attribute__((unused)))
{
    /* Reject any collation */
    if (comp->collation) {
        return 0;
    }
    if (!strcmp(comp->property, "isFlagged") ||
        !strcmp(comp->property, "firstName") ||
        !strcmp(comp->property, "lastName") ||
        !strcmp(comp->property, "nickname") ||
        !strcmp(comp->property, "company")) {
        return 1;
    }
    return 0;
}

struct contactlist_rock {
    jmap_req_t *req;
    struct jmap_query *query;
    jmap_filter *filter;

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

    int rights = jmap_myrights_byname(crock->req, cdata->dav.mailbox);
    if (!(rights & DACL_READ)) return 0;

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
     * initialize props with any non-NULL field in filter f or its subconditions.
     */
    contact = jmap_contact_from_vcard(vcard->objects, cdata, &record,
                                      NULL /* props */, crock->mailbox->name);
    vparse_free_card(vcard);

    /* Match the contact against the filter and update statistics. */
    struct contact_filter_rock cfrock;
    cfrock.carddavdb = crock->carddavdb;
    cfrock.cdata = cdata;
    cfrock.contact = contact;
    if (crock->filter &&
        !jmap_filter_match(crock->filter, &contact_filter_match, &cfrock)) {
        goto done;
    }
    crock->query->total++;
    if (crock->query->position > (ssize_t) crock->query->total) {
        goto done;
    }
    if (crock->query->limit &&
        crock->query->limit >= json_array_size(crock->query->ids)) {
        goto done;
    }

    /* All done. Add the contact identifier. */
    json_array_append_new(crock->query->ids, json_string(cdata->vcard_uid));

done:
    if (contact) json_decref(contact);
    return r;
}

static int getContactsList(struct jmap_req *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_query query;
    struct carddav_db *db;
    jmap_filter *parsed_filter = NULL;
    int r = 0;

    db = carddav_open_userid(req->accountid);
    if (!db) {
        syslog(LOG_ERR,
               "carddav_open_userid failed for user %s", req->accountid);
        r = IMAP_INTERNAL;
        goto done;
    }

    /* Parse request */
    json_t *err = NULL;
    jmap_query_parse(req->args, &parser,
            validatefilter, NULL,
            validatecomparator, NULL,
            &query, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }
    if (query.position < 0) {
        /* we currently don't support negative positions */
        jmap_parser_invalid(&parser, "position");
    }
    if (json_array_size(parser.invalid)) {
        err = json_pack("{s:s}", "type", "invalidArguments");
        json_object_set(err, "arguments", parser.invalid);
        jmap_error(req, err);
        goto done;
    }

    /* Build filter */
    json_t *filter = json_object_get(req->args, "filter");
    if (JNOTNULL(filter)) {
        parsed_filter = buildfilter(filter, contact_filter_parse);
    }

    /* Inspect every entry in this accounts addressbook mailboxes. */
    struct contactlist_rock rock = {
        req, &query, parsed_filter, NULL, db
    };
    r = carddav_foreach(db, NULL, getcontactlist_cb, &rock);
    if (rock.mailbox) mailbox_close(&rock.mailbox);
    if (r) {
        err = jmap_server_error(r);
        jmap_error(req, err);
        goto done;
    }

    /* Build response */
    json_t *jstate = jmap_getstate(req, MBTYPE_ADDRESSBOOK, /*refresh*/0);
    query.query_state = xstrdup(json_string_value(jstate));
    json_decref(jstate);

    json_t *res = jmap_query_reply(&query);
    jmap_ok(req, res);

done:
    jmap_query_fini(&query);
    jmap_parser_fini(&parser);
    if (rock.filter) jmap_filter_free(rock.filter, contact_filter_free);
    if (db) carddav_close(db);
    return 0;
}

static struct vparse_entry *_card_multi(struct vparse_card *card,
                                        const char *name, char sepchar)
{
    struct vparse_entry *res = vparse_get_entry(card, NULL, name);
    if (!res) {
        res = vparse_add_entry(card, NULL, name, NULL);
        res->multivaluesep = sepchar;
        res->v.values = strarray_new();
    }
    return res;
}

static int _emails_to_card(struct vparse_card *card,
                           json_t *arg, json_t *invalid)
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

        readprop_full(item, prefix, "type", 1, invalid, "s", &type);
        readprop_full(item, prefix, "value", 1, invalid, "s", &value);
        if (JNOTNULL(json_object_get(item, "label"))) {
            readprop_full(item, prefix, "label", 1, invalid, "s", &label);
        }
        json_t *jisDefault = json_object_get(item, "isDefault");

        /* Bail out for any property errors. */
        if (!type || !value || json_array_size(invalid)) {
            buf_free(&buf);
            return -1;
        }

        /* Update card. */
        struct vparse_entry *entry =
            vparse_add_entry(card, NULL, "EMAIL", value);

        if (!strcmpsafe(type, "personal"))
            type = "home";
        if (strcmpsafe(type, "other"))
            vparse_add_param(entry, "TYPE", type);

        if (label)
            vparse_add_param(entry, "LABEL", label);

        if (jisDefault && json_is_true(jisDefault))
            vparse_add_param(entry, "TYPE", "pref");

        buf_reset(&buf);
    }
    buf_free(&buf);
    return 0;
}

static int _phones_to_card(struct vparse_card *card,
                           json_t *arg, json_t *invalid)
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

        readprop_full(item, prefix, "type", 1, invalid, "s", &type);
        readprop_full(item, prefix, "value", 1, invalid, "s", &value);
        if (JNOTNULL(json_object_get(item, "label"))) {
            readprop_full(item, prefix, "label", 1, invalid, "s", &label);
        }

        /* Bail out for any property errors. */
        if (!type || !value || json_array_size(invalid)) {
            buf_free(&buf);
            return -1;
        }

        /* Update card. */
        struct vparse_entry *entry = vparse_add_entry(card, NULL, "TEL", value);

        if (!strcmp(type, "mobile"))
            vparse_add_param(entry, "TYPE", "CELL");
        else if (strcmp(type, "other"))
            vparse_add_param(entry, "TYPE", type);

        if (label)
            vparse_add_param(entry, "LABEL", label);

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

static int _online_to_card(struct vparse_card *card,
                           json_t *arg, json_t *invalid)
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

        readprop_full(item, prefix, "type", 1, invalid, "s", &type);
        readprop_full(item, prefix, "value", 1, invalid, "s", &value);
        if (JNOTNULL(json_object_get(item, "label"))) {
            readprop_full(item, prefix, "label", 1, invalid, "s", &label);
        }

        /* Bail out for any property errors. */
        if (!type || !value || json_array_size(invalid)) {
            buf_free(&buf);
            return -1;
        }

        /* Update card. */
        if (!strcmp(type, "uri")) {
            struct vparse_entry *entry =
                vparse_add_entry(card, NULL, "URL", value);
            if (label)
                vparse_add_param(entry, "LABEL", label);
        }
        else if (!strcmp(type, "username")) {
            if (label && _is_im(label)) {
                struct vparse_entry *entry =
                    vparse_add_entry(card, NULL, "IMPP", value);
                vparse_add_param(entry, "X-SERVICE-TYPE", label);
            }
            else {
                struct vparse_entry *entry =
                    vparse_add_entry(card, NULL, "X-SOCIAL-PROFILE", ""); // XXX - URL calculated, ick
                if (label)
                    vparse_add_param(entry, "TYPE", label);
                vparse_add_param(entry, "X-USER", value);
            }
        }
        else if (!strcmp(type, "other")) {
            struct vparse_entry *entry =
                vparse_add_entry(card, NULL, "X-FM-ONLINE-OTHER", value);
            if (label)
                vparse_add_param(entry, "LABEL", label);
        }
    }
    buf_free(&buf);
    return 0;
}

static int _addresses_to_card(struct vparse_card *card,
                              json_t *arg, json_t *invalid)
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
        if (!type || !street || !locality ||
            !region || !postcode || !country || pe < 0) {
            buf_free(&buf);
            return -1;
        }

        /* Update card. */
        struct vparse_entry *entry = vparse_add_entry(card, NULL, "ADR", NULL);

        if (strcmpsafe(type, "other"))
            vparse_add_param(entry, "TYPE", type);

        if (label)
            vparse_add_param(entry, "LABEL", label);

        entry->multivaluesep = ';';
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
        vparse_add_param(entry, "X-APPLE-OMIT-YEAR", "1604");
    if (no_month)
        vparse_add_param(entry, "X-FM-NO-MONTH", "1");
    if (no_day)
        vparse_add_param(entry, "X-FM-NO-DAY", "1");

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

static int _blob_to_card(struct jmap_req *req,
                         struct vparse_card *card, const char *key, json_t *file)
{
    struct buf blob_buf = BUF_INITIALIZER;
    msgrecord_t *mr = NULL;
    struct mailbox *mbox = NULL;
    struct body *body = NULL;
    const struct body *part = NULL;
    const char *blobid = NULL;
    json_t *val;
    int r;

    if (!file) return -1;

    /* Extract blobId */
    val = json_object_get(file, "blobId");
    if (val) blobid = json_string_value(val);
    if (!blobid) return -1;

    /* Find body part containing blob */
    r = jmap_findblob(req, blobid, &mbox, &mr, &body, &part, &blob_buf);
    if (r) goto done;

    if (!buf_base(&blob_buf)) {
        /* Map the blob into memory */
        r = msgrecord_get_body(mr, &blob_buf);
        if (r) goto done;
    }

    /* Fetch blob contents and decode */
    const char *base = buf_base(&blob_buf);
    size_t len = buf_len(&blob_buf);

    char *decbuf = NULL;
    if (part) {
        /* Map into body part */
        base += part->content_offset;
        len = part->content_size;

        /* Determine encoding */
        int encoding = part->charset_enc & 0xff;
        base = charset_decode_mimebody(base, len, encoding, &decbuf, &len);
    }

    /* Pre-flight base64 encoder to determine length */
    size_t len64 = 0;
    charset_encode_mimebody(NULL, len, NULL, &len64, NULL, 0 /* no wrap */);

    /* Now encode the blob */
    char *encbuf = xmalloc(len64+1);
    charset_encode_mimebody(base, len, encbuf, &len64, NULL, 0 /* no wrap */);
    encbuf[len64] = '\0';
    base = encbuf;

    /* (Re)write vCard property */
    vparse_delete_entries(card, NULL, key);

    struct vparse_entry *entry = vparse_add_entry(card, NULL, key, base);

    vparse_add_param(entry, "ENCODING", "b");

    val = json_object_get(file, "type");
    if (val) {
        const char *type = json_string_value(val);
        char *subtype = xstrdup(strchr(type, '/'));

        vparse_add_param(entry, "TYPE", ucase(subtype+1));
        free(subtype);
    }

    free(decbuf);
    free(encbuf);
    r = 0;

  done:
    if (body) {
        message_free_body(body);
        free(body);
    }
    msgrecord_unref(&mr);
    jmap_closembox(req, &mbox);
    buf_free(&blob_buf);

    return r;
}

static void _make_fn(struct vparse_card *card)
{
    struct vparse_entry *n = vparse_get_entry(card, NULL, "N");
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
        v = vparse_stringval(card, "NICKNAME");
        if (v && v[0]) strarray_append(name, v);
    }

    char *fn = NULL;
    if (strarray_size(name))
        fn = strarray_join(name, " ");
    else
        fn = xstrdup(" ");

    strarray_free(name);
    vparse_replace_entry(card, NULL, "FN", fn);
    free(fn);
}

static int _json_to_card(struct jmap_req *req,
                         struct carddav_data *cdata,
                         struct vparse_card *card,
                         json_t *arg, strarray_t *flags,
                         struct entryattlist **annotsp,
                         json_t *invalid)
{
    const char *key;
    json_t *jval;
    struct vparse_entry *n = vparse_get_entry(card, NULL, "N");
    int name_is_dirty = 0;
    int has_noncontent = 0;
    int record_is_dirty = 0;

    /* we'll be updating you later anyway... create early so that it's
     * at the top of the card */
    if (!n) {
        /* _card_multi repeats some work, but we don't care */
        n = _card_multi(card, "N", ';');
        record_is_dirty = 1;
    }

    if (!vparse_get_entry(card, NULL, "FN")) {
        /* adding first to get position near the top */
        vparse_add_entry(card, NULL, "FN", "No Name");
        name_is_dirty = 1;
    }

    json_object_foreach(arg, key, jval) {
        if (cdata) {
            if (!strcmp(key, "id")) {
                if (strcmpnull(cdata->vcard_uid, json_string_value(jval))) {
                    json_array_append_new(invalid, json_string("id"));
                }
                continue;
            }
            else if (!strcmp(key, "x-href")) {
                if (strcmpnull(json_string_value(jval),
                               jmap_xhref(cdata->dav.mailbox,
                                          cdata->dav.resource))) {
                    json_array_append_new(invalid, json_string("x-href"));
                }
                continue;
            }
            else if (!strcmp(key, "x-hasPhoto")) {
                if ((vparse_stringval(card, "photo") && !json_is_true(jval)) ||
                    !json_is_false(jval)) {
                    json_array_append_new(invalid, json_string("x-hasPhoto"));
                }
                continue;
            }
        }

        if (!strcmp(key, "isFlagged")) {
            has_noncontent = 1;
            if (json_is_true(jval)) {
                strarray_add_case(flags, "\\Flagged");
            } else if (json_is_false(jval)) {
                strarray_remove_all_case(flags, "\\Flagged");
            } else {
                json_array_append_new(invalid, json_string("isFlagged"));
            }
        }
        // need to support x-importance while AJAXUI is around
        else if (!strcmp(key, "x-importance") || !strcmp(key, "importance")) {
            has_noncontent = 1;
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
            if (!json_is_null(jval)) {
                int r = _blob_to_card(req, card, "PHOTO", jval);
                if (r) {
                    json_array_append_new(invalid, json_string("avatar"));
                    continue;
                }
                record_is_dirty = 1;
            }
        }
        else if (!strcmp(key, "prefix")) {
            const char *val = json_string_value(jval);
            if (!val) {
                json_array_append_new(invalid, json_string("prefix"));
                continue;
            }

            name_is_dirty = 1;
            strarray_set(n->v.values, 3, val);
        }
        else if (!strcmp(key, "firstName")) {
            const char *val = json_string_value(jval);
            if (!val) {
                json_array_append_new(invalid, json_string("firstName"));
                continue;
            }
            name_is_dirty = 1;
            /* JMAP doesn't have a separate field for Middle (aka "Additional
             * Names"), so any extra names are probably in firstName, and we
             * should split them out. See reverse of this in getcontacts_cb */
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
                continue;
            }
            name_is_dirty = 1;
            strarray_set(n->v.values, 0, val);
        }
        else if (!strcmp(key, "suffix")) {
            const char *val = json_string_value(jval);
            if (!val) {
                json_array_append_new(invalid, json_string("suffix"));
                continue;
            }
            name_is_dirty = 1;
            strarray_set(n->v.values, 4, val);
        }
        else if (!strcmp(key, "nickname")) {
            const char *val = json_string_value(jval);
            if (!val) {
                json_array_append_new(invalid, json_string("nickname"));
                continue;
            }
            struct vparse_entry *nick = _card_multi(card, "NICKNAME", ',');
            strarray_truncate(nick->v.values, 0);
            if (*val) strarray_set(nick->v.values, 0, val);
            record_is_dirty = 1;
        }
        else if (!strcmp(key, "birthday")) {
            int r = _date_to_card(card, "BDAY", jval);
            if (r) {
                json_array_append_new(invalid, json_string("birthday"));
                continue;
            }
            record_is_dirty = 1;
        }
        else if (!strcmp(key, "anniversary")) {
            int r = _date_to_card(card, "ANNIVERSARY", jval);
            if (r) {
                json_array_append_new(invalid, json_string("anniversary"));
                continue;
            }
            record_is_dirty = 1;
        }
        else if (!strcmp(key, "jobTitle")) {
            int r = _kv_to_card(card, "TITLE", jval);
            if (r) {
                json_array_append_new(invalid, json_string("jobTitle"));
                continue;
            }
            record_is_dirty = 1;
        }
        else if (!strcmp(key, "company")) {
            const char *val = json_string_value(jval);
            if (!val) {
                json_array_append_new(invalid, json_string("company"));
                continue;
            }
            struct vparse_entry *org = _card_multi(card, "ORG", ';');
            strarray_set(org->v.values, 0, val);
            record_is_dirty = 1;
        }
        else if (!strcmp(key, "department")) {
            const char *val = json_string_value(jval);
            if (!val) {
                json_array_append_new(invalid, json_string("department"));
                continue;
            }
            struct vparse_entry *org = _card_multi(card, "ORG", ';');
            strarray_set(org->v.values, 1, val);
            record_is_dirty = 1;
        }
        else if (!strcmp(key, "emails")) {
            int r = _emails_to_card(card, jval, invalid);
            if (r) continue;
            record_is_dirty = 1;
        }
        else if (!strcmp(key, "phones")) {
            int r = _phones_to_card(card, jval, invalid);
            if (r) continue;
            record_is_dirty = 1;
        }
        else if (!strcmp(key, "online")) {
            int r = _online_to_card(card, jval, invalid);
            if (r) continue;
            record_is_dirty = 1;
        }
        else if (!strcmp(key, "addresses")) {
            int r = _addresses_to_card(card, jval, invalid);
            if (r) continue;
            record_is_dirty = 1;
        }
        else if (!strcmp(key, "notes")) {
            int r = _kv_to_card(card, "NOTE", jval);
            if (r) {
                json_array_append_new(invalid, json_string("notes"));
                continue;
            }
            record_is_dirty = 1;
        }
        else {
            json_array_append_new(invalid, json_string(key));
        }
    }

    if (json_array_size(invalid)) return -1;

    if (name_is_dirty) {
        _make_fn(card);
        record_is_dirty = 1;
    }

    if (!record_is_dirty && has_noncontent)
        return HTTP_NO_CONTENT;  /* no content */

    return 0;
}

static int setContacts(struct jmap_req *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_set set;
    json_t *err = NULL;
    int r = 0;

    struct mailbox *mailbox = NULL;
    struct mailbox *newmailbox = NULL;

    struct carddav_db *db = carddav_open_userid(req->accountid);
    if (!db) return -1;

    /* Parse arguments */
    jmap_set_parse(req->args, &parser, &set, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    if (set.if_in_state) {
        /* TODO rewrite state function to use char* not json_t* */
        json_t *jstate = json_string(set.if_in_state);
        if (jmap_cmpstate(req, jstate, MBTYPE_ADDRESSBOOK)) {
            jmap_error(req, json_pack("{s:s}", "type", "stateMismatch"));
            goto done;
        }
        json_decref(jstate);
        set.old_state = xstrdup(set.if_in_state);
    }
    else {
        json_t *jstate = jmap_getstate(req, MBTYPE_ADDRESSBOOK, /*refresh*/0);
        set.old_state = xstrdup(json_string_value(jstate));
        json_decref(jstate);
    }

    /* Initialize PRODID value */
    static char *_prodid = NULL;
    if (!_prodid) {
        /* XXX - OS X 10.11.6 Contacts is not unfolding PRODID lines, so make
         * sure that PRODID never exceeds the 75 octet limit without CRLF */
        struct buf prodidbuf = BUF_INITIALIZER;
        size_t max_len = 68; /* 75 - strlen("PRODID:") */
        buf_printf(&prodidbuf, "-//CyrusIMAP.org//Cyrus %s//EN", CYRUS_VERSION);
        if (buf_len(&prodidbuf) > max_len) {
            buf_truncate(&prodidbuf, max_len - 6);
            buf_appendcstr(&prodidbuf, "..//EN");
        }
        _prodid = buf_release(&prodidbuf);
    }

    r = carddav_create_defaultaddressbook(req->accountid);
    if (r) goto done;

    /* create */
    json_t *record;
    const char *key;
    json_t *arg;
    json_object_foreach(set.create, key, arg) {
        char *uid = xstrdup(makeuuid());
        struct entryattlist *annots = NULL;

        const char *addressbookId = "Default";
        json_t *abookid = json_object_get(arg, "addressbookId");
        if (abookid && json_string_value(abookid)) {
            /* XXX - invalid arguments */
            addressbookId = json_string_value(abookid);
        }
        char *mboxname = mboxname_abook(req->accountid, addressbookId);
        json_object_del(arg, "addressbookId");
        addressbookId = NULL;

        int rights = jmap_myrights_byname(req, mboxname);
        if (!(rights & DACL_WRITE)) {
            json_t *err = json_pack("{s:s s:[s]}",
                                    "type", "invalidProperties",
                                    "properties", "addressbookId");
            json_object_set_new(set.not_created, key, err);
            free(mboxname);
            continue;
        }

        struct vparse_card *card = vparse_new_card("VCARD");
        vparse_add_entry(card, NULL, "PRODID", _prodid);
        vparse_add_entry(card, NULL, "VERSION", "3.0");
        vparse_add_entry(card, NULL, "UID", uid);

        /* we need to create and append a record */
        if (!mailbox || strcmp(mailbox->name, mboxname)) {
            jmap_closembox(req, &mailbox);
            r = jmap_openmbox(req, mboxname, &mailbox, 1);
            if (r) {
                free(mboxname);
                vparse_free_card(card);
                goto done;
            }
        }

        strarray_t *flags = strarray_new();
        json_t *invalid = json_pack("[]");
        r = _json_to_card(req, NULL, card, arg, flags, &annots, invalid);
        if (r || json_array_size(invalid)) {
            /* this is just a failure */
            r = 0;
            json_t *err = json_pack("{s:s}", "type", "invalidProperties");
            if (json_array_size(invalid)) {
                json_object_set(err, "properties", invalid);
            }
            json_decref(invalid);
            json_object_set_new(set.not_created, key, err);
            strarray_free(flags);
            freeentryatts(annots);
            vparse_free_card(card);
            continue;
        }
        json_decref(invalid);

        syslog(LOG_NOTICE, "jmap: create contact %s/%s (%s)",
               req->accountid, mboxname, uid);
        r = carddav_store(mailbox, card, NULL, 0, flags, annots,
                          req->accountid, req->authstate, ignorequota);
        vparse_free_card(card);
        free(mboxname);
        strarray_free(flags);
        freeentryatts(annots);

        if (r) {
            goto done;
        }

        record = json_pack("{s:s}", "id", uid);
        json_object_set_new(set.created, key, record);

        /* Register creation id */
        jmap_add_id(req, key, uid);
        free(uid);
    }


    /* update */
    const char *uid;
    json_object_foreach(set.update, uid, arg) {
        struct carddav_data *cdata = NULL;
        r = carddav_lookup_uid(db, uid, &cdata);
        uint32_t olduid;
        char *resource = NULL;

        if (r || !cdata || !cdata->dav.imap_uid
            || cdata->kind != CARDDAV_KIND_CONTACT) {
            r = 0;
            json_t *err = json_pack("{s:s}", "type", "notFound");
            json_object_set_new(set.not_updated, uid, err);
            continue;
        }

        int rights = jmap_myrights_byname(req, cdata->dav.mailbox);
        if (!(rights & DACL_WRITE)) {
            json_t *err = json_pack("{s:s s:[s]}",
                                    "type", "invalidProperties",
                                    "properties", "addressbookId");
            json_object_set_new(set.not_updated, uid, err);
            continue;
        }

        if (!mailbox || strcmp(mailbox->name, cdata->dav.mailbox)) {
            jmap_closembox(req, &mailbox);
            r = jmap_openmbox(req, cdata->dav.mailbox, &mailbox, 1);
            if (r) {
                syslog(LOG_ERR, "IOERROR: failed to open %s",
                       cdata->dav.mailbox);
                goto done;
            }
        }

        json_t *abookid = json_object_get(arg, "addressbookId");
        if (abookid && json_string_value(abookid)) {
            const char *mboxname =
                mboxname_abook(req->accountid, json_string_value(abookid));
            if (strcmp(mboxname, cdata->dav.mailbox)) {
                /* move */
                int dstrights = jmap_myrights_byname(req, mboxname);
                if (!(dstrights & DACL_WRITE)) {
                    json_t *err = json_pack("{s:s s:[s]}",
                                            "type", "invalidProperties",
                                            "properties", "addressbookId");
                    json_object_set_new(set.not_updated, uid, err);
                    jmap_closembox(req, &mailbox);
                    continue;
                }
                r = jmap_openmbox(req, mboxname, &newmailbox, 1);
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
            mailbox_extract_flags(mailbox, &record, req->accountid);
        struct entryattlist *annots =
            mailbox_extract_annots(mailbox, &record);

        /* Load message containing the resource and parse vcard data */
        struct vparse_card *vcard = record_to_vcard(mailbox, &record);
        if (!vcard || !vcard->objects) {
            syslog(LOG_ERR, "record_to_vcard failed for record %u:%s",
                   cdata->dav.imap_uid, mailbox->name);
            r = 0;
            json_t *err = json_pack("{s:s}", "type", "parseError");
            json_object_set_new(set.not_updated, uid, err);
            vparse_free_card(vcard);
            strarray_free(flags);
            freeentryatts(annots);
            jmap_closembox(req, &newmailbox);
            free(resource);
            continue;
        }
        struct vparse_card *card = vcard->objects;
        vparse_replace_entry(card, NULL, "VERSION", "3.0");
        vparse_replace_entry(card, NULL, "PRODID", _prodid);

        json_t *invalid = json_pack("[]");

        r = _json_to_card(req, cdata, card, arg, flags, &annots, invalid);
        if (r == HTTP_NO_CONTENT) {
            r = 0;
            if (!newmailbox) {
                /* just bump the modseq
                   if in the same mailbox and no data change */
                syslog(LOG_NOTICE, "jmap: touch contact %s/%s",
                       req->accountid, resource);
                if (strarray_find_case(flags, "\\Flagged", 0) >= 0)
                    record.system_flags |= FLAG_FLAGGED;
                else
                    record.system_flags &= ~FLAG_FLAGGED;
                annotate_state_t *state = NULL;
                r = mailbox_get_annotate_state(mailbox, record.uid, &state);
                annotate_state_set_auth(state, 0,
                                        req->accountid, req->authstate);
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
            json_object_set_new(set.not_updated, uid, err);
            vparse_free_card(vcard);
            strarray_free(flags);
            freeentryatts(annots);
            jmap_closembox(req, &newmailbox);
            free(resource);
            continue;
        }
        json_decref(invalid);

        syslog(LOG_NOTICE, "jmap: update contact %s/%s",
               req->accountid, resource);
        r = carddav_store(newmailbox ? newmailbox : mailbox, card, resource,
                          record.createdmodseq, flags, annots, req->accountid,
                          req->authstate, ignorequota);
        if (!r)
            r = carddav_remove(mailbox, olduid,
                               /*isreplace*/!newmailbox, req->accountid);

      finish:
        jmap_closembox(req, &newmailbox);
        strarray_free(flags);
        freeentryatts(annots);

        vparse_free_card(vcard);
        free(resource);

        if (r) goto done;

        json_object_set_new(set.updated, uid, json_null());
    }


    /* destroy */
    size_t index;
    for (index = 0; index < json_array_size(set.destroy); index++) {
        const char *uid = _json_array_get_string(set.destroy, index);
        if (!uid) {
            json_t *err = json_pack("{s:s}", "type", "invalidArguments");
            json_object_set_new(set.not_destroyed, uid, err);
            continue;
        }
        struct carddav_data *cdata = NULL;
        uint32_t olduid;
        r = carddav_lookup_uid(db, uid, &cdata);

        if (r || !cdata || !cdata->dav.imap_uid
            || cdata->kind != CARDDAV_KIND_CONTACT) {
            r = 0;
            json_t *err = json_pack("{s:s}", "type", "notFound");
            json_object_set_new(set.not_destroyed, uid, err);
            continue;
        }
        olduid = cdata->dav.imap_uid;

        int rights = jmap_myrights_byname(req, cdata->dav.mailbox);
        if (!(rights & DACL_WRITE)) {
            json_t *err = json_pack("{s:s}", "type",
                                    rights & ACL_READ ?
                                    "accountReadOnly" : "notFound");
            json_object_set_new(set.not_destroyed, uid, err);
            continue;
        }

        if (!mailbox || strcmp(mailbox->name, cdata->dav.mailbox)) {
            jmap_closembox(req, &mailbox);
            r = jmap_openmbox(req, cdata->dav.mailbox, &mailbox, 1);
            if (r) goto done;
        }

        syslog(LOG_NOTICE,
               "jmap: remove contact %s/%s", req->accountid, uid);
        r = carddav_remove(mailbox, olduid, /*isreplace*/0, req->accountid);
        if (r) {
            syslog(LOG_ERR, "IOERROR: setContacts remove failed for %s %u",
                   mailbox->name, olduid);
            goto done;
        }

        json_array_append_new(set.destroyed, json_string(uid));
    }

    /* force modseq to stable */
    if (mailbox) mailbox_unlock_index(mailbox, NULL);

    // TODO refactor jmap_getstate to return a string, once
    // all code has been migrated to the new JMAP parser.
    json_t *jstate = jmap_getstate(req, MBTYPE_ADDRESSBOOK, /*refresh*/1);
    set.new_state = xstrdup(json_string_value(jstate));
    json_decref(jstate);

    jmap_ok(req, jmap_set_reply(&set));

done:
    jmap_parser_fini(&parser);
    jmap_set_fini(&set);
    jmap_closembox(req, &newmailbox);
    jmap_closembox(req, &mailbox);

    carddav_close(db);
    return r;
}

const struct body *jmap_contact_findblob(struct message_guid *content_guid,
                                         const char *part_id,
                                         struct mailbox *mbox,
                                         msgrecord_t *mr,
                                         struct buf *blob)
{
    const struct body *ret = NULL;
    struct index_record record;
    struct vparse_card *vcard;
    const char *proppath = strstr(part_id, "/VCARD#");

    if (!proppath) return NULL;

    msgrecord_get_index_record(mr, &record);
    vcard = record_to_vcard(mbox, &record);

    if (vcard) {
        static struct body subpart;
        struct buf propval = BUF_INITIALIZER;
        char *type = NULL;
        struct vparse_entry *entry =
            vparse_get_entry(vcard->objects, NULL, proppath+7);

        memset(&subpart, 0, sizeof(struct body));

        if (entry && vcard_prop_decode_value(entry, &propval,
                                             &type, &subpart.content_guid) &&
            !message_guid_cmp(content_guid, &subpart.content_guid)) {
            /* Build a body part for the property */
            subpart.charset_enc = ENCODING_NONE;
            subpart.encoding = "BINARY";
            subpart.header_offset = 0;
            subpart.content_size = buf_len(&propval);
            ret = &subpart;

            buf_reset(blob);
            buf_printf(blob, "User-Agent: Cyrus-JMAP/%s\r\n", CYRUS_VERSION);

            struct buf from = BUF_INITIALIZER;
            if (strchr(httpd_userid, '@')) {
                /* XXX  This needs to be done via an LDAP/DB lookup */
                buf_printf(&from, "<%s>", httpd_userid);
            }
            else {
                buf_printf(&from, "<%s@%s>", httpd_userid, config_servername);
            }
            
            char *mimehdr = charset_encode_mimeheader(buf_cstring(&from),
                                                      buf_len(&from), 0);

            buf_printf(blob, "From: %s\r\n", mimehdr);
            free(mimehdr);
            buf_free(&from);

            char datestr[80];
            time_to_rfc5322(time(NULL), datestr, sizeof(datestr));
            buf_printf(blob, "Date: %s\r\n", datestr);

            if (!type) type = xstrdup("application/octet-stream");
            buf_printf(blob, "Content-Type: %s\r\n", type);

            buf_printf(blob, "Content-Transfer-Encoding: %s\r\n",
                       subpart.encoding);

            buf_printf(blob, "Content-Length: %u\r\n", subpart.content_size);

            buf_appendcstr(blob, "MIME-Version: 1.0\r\n\r\n");

            subpart.content_offset = subpart.header_size = buf_len(blob);

            buf_append(blob, &propval);
            buf_free(&propval);
        }
        else buf_free(&propval);

        free(type);
        vparse_free_card(vcard);
    }

    return ret;
}
