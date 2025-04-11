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
#include <errno.h>

#include "annotate.h"
#include "carddav_db.h"
#include "cyr_qsort_r.h"
#include "global.h"
#include "hash.h"
#include "http_carddav.h"
#include "http_dav.h"
#include "http_dav_sharing.h"
#include "http_jmap.h"
#include "json_support.h"
#include "mailbox.h"
#include "mboxname.h"
#include "mkgmtime.h"
#include "stristr.h"
#include "times.h"
#include "user.h"
#include "util.h"
#include "vcard_support.h"
#include "xapian_wrap.h"
#include "xmalloc.h"

/* generated headers are not necessarily in current directory */
#include "imap/http_err.h"
#include "imap/imap_err.h"

#ifdef HAVE_LIBICALVCARD
static int jmap_addressbook_get(struct jmap_req *req);
static int jmap_addressbook_changes(struct jmap_req *req);
static int jmap_addressbook_set(struct jmap_req *req);
static int jmap_card_get(struct jmap_req *req);
static int jmap_card_changes(struct jmap_req *req);
static int jmap_card_query(struct jmap_req *req);
static int jmap_card_querychanges(struct jmap_req *req);
static int jmap_card_set(struct jmap_req *req);
static int jmap_card_copy(struct jmap_req *req);
static int jmap_card_parse(jmap_req_t *req);
#endif /* HAVE_LIBICALVCARD */

static int jmap_contactgroup_get(struct jmap_req *req);
static int jmap_contactgroup_changes(struct jmap_req *req);
static int jmap_contactgroup_set(struct jmap_req *req);
static int jmap_contactgroup_query(struct jmap_req *req);
static int jmap_contact_get(struct jmap_req *req);
static int jmap_contact_changes(struct jmap_req *req);
static int jmap_contact_query(struct jmap_req *req);
static int jmap_contact_set(struct jmap_req *req);
static int jmap_contact_copy(struct jmap_req *req);

typedef struct {
    json_t *invalid;
    json_t *blobNotFound;
} jmap_contact_errors_t;

static int _contact_set_create(jmap_req_t *req, unsigned kind, json_t *jcard,
                               struct mailbox **mailbox, json_t *item,
                               jmap_contact_errors_t *errors);
static int _contact_set_update(jmap_req_t *req, unsigned kind,
                               const char *uid, json_t *jcard,
                               struct carddav_db *db, struct mailbox **mailbox,
                               json_t **item, jmap_contact_errors_t *errors);
static int required_set_rights(json_t *props);
static int _json_to_card(struct jmap_req *req,
                         struct carddav_data *cdata,
                         const char *mboxname,
                         struct vparse_card *card,
                         json_t *arg, strarray_t *flags,
                         struct entryattlist **annotsp,
                         ptrarray_t *blobs,
                         jmap_contact_errors_t *errors);

static int jmap_contact_getblob(jmap_req_t *req, jmap_getblob_context_t *ctx);

#define JMAPCACHE_CARDVERSION 1

// clang-format off
static jmap_method_t jmap_contact_methods_standard[] = {
#ifdef HAVE_LIBICALVCARD
    {
        "AddressBook/get",
        JMAP_URN_CONTACTS,
        &jmap_addressbook_get,
        JMAP_NEED_CSTATE
    },
    {
        "AddressBook/changes",
        JMAP_URN_CONTACTS,
        &jmap_addressbook_changes,
        JMAP_NEED_CSTATE
    },
    {
        "AddressBook/set",
        JMAP_URN_CONTACTS,
        &jmap_addressbook_set,
        JMAP_NEED_CSTATE | JMAP_READ_WRITE
    },
    {
        "ContactCard/get",
        JMAP_URN_CONTACTS,
        &jmap_card_get,
        JMAP_NEED_CSTATE
    },
    {
        "ContactCard/changes",
        JMAP_URN_CONTACTS,
        &jmap_card_changes,
        JMAP_NEED_CSTATE
    },
    {
        "ContactCard/query",
        JMAP_URN_CONTACTS,
        &jmap_card_query,
        JMAP_NEED_CSTATE
    },
    {
        "ContactCard/queryChanges",
        JMAP_URN_CONTACTS,
        &jmap_card_querychanges,
        JMAP_NEED_CSTATE
    },
    {
        "ContactCard/set",
        JMAP_URN_CONTACTS,
        &jmap_card_set,
        JMAP_NEED_CSTATE | JMAP_READ_WRITE
    },
    {
        "ContactCard/copy",
        JMAP_URN_CONTACTS,
        &jmap_card_copy,
        JMAP_READ_WRITE // need to do lock ordering before opening conversations
    },
    {
        "ContactCard/parse",
        JMAP_CONTACTS_EXTENSION,
        &jmap_card_parse,
        JMAP_NEED_CSTATE
    },
#endif /* HAVE_LIBICALVCARD */
    { NULL, NULL, NULL, 0}
};
// clang-format on

// clang-format off
static jmap_method_t jmap_contact_methods_nonstandard[] = {
    {
        "ContactGroup/get",
        JMAP_CONTACTS_EXTENSION,
        &jmap_contactgroup_get,
        JMAP_NEED_CSTATE
    },
    {
        "ContactGroup/changes",
        JMAP_CONTACTS_EXTENSION,
        &jmap_contactgroup_changes,
        JMAP_NEED_CSTATE
    },
    {
        "ContactGroup/set",
        JMAP_CONTACTS_EXTENSION,
        &jmap_contactgroup_set,
        JMAP_NEED_CSTATE | JMAP_READ_WRITE
    },
    {
        "ContactGroup/query",
        JMAP_CONTACTS_EXTENSION,
        &jmap_contactgroup_query,
        JMAP_NEED_CSTATE
    },
    {
        "Contact/get",
        JMAP_CONTACTS_EXTENSION,
        &jmap_contact_get,
        JMAP_NEED_CSTATE
    },
    {
        "Contact/changes",
        JMAP_CONTACTS_EXTENSION,
        &jmap_contact_changes,
        JMAP_NEED_CSTATE
    },
    {
        "Contact/query",
        JMAP_CONTACTS_EXTENSION,
        &jmap_contact_query,
        JMAP_NEED_CSTATE
    },
    {
        "Contact/set",
        JMAP_CONTACTS_EXTENSION,
        &jmap_contact_set,
        JMAP_NEED_CSTATE | JMAP_READ_WRITE
    },
    {
        "Contact/copy",
        JMAP_CONTACTS_EXTENSION,
        &jmap_contact_copy,
        JMAP_READ_WRITE // can't open conversations until we get locks ordered
    },
    { NULL, NULL, NULL, 0}
};
// clang-format on

static char *_prodid = NULL;

HIDDEN void jmap_contact_init(jmap_settings_t *settings)
{
    jmap_add_methods(jmap_contact_methods_standard, settings);

#ifdef HAVE_LIBICALVCARD
    json_object_set_new(settings->server_capabilities,
            JMAP_URN_CONTACTS, json_object());
#endif

    if (config_getswitch(IMAPOPT_JMAP_NONSTANDARD_EXTENSIONS)) {
        json_object_set_new(settings->server_capabilities,
                JMAP_CONTACTS_EXTENSION, json_object());

        jmap_add_methods(jmap_contact_methods_nonstandard, settings);
    }

    ptrarray_append(&settings->getblob_handlers, jmap_contact_getblob);

    /* Initialize PRODID value
     *
     * XXX - OS X 10.11.6 Contacts is not unfolding PRODID lines, so make
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

HIDDEN void jmap_contact_capabilities(json_t *account_capabilities,
#ifdef HAVE_LIBICALVCARD
                                      struct auth_state *authstate,
                                      const char *authuserid,
#else
                                      struct auth_state *authstate __attribute__((unused)),
                                      const char *authuserid __attribute__((unused)),
#endif
                                      const char *accountid)
{
    char *cardhomename = carddav_mboxname(accountid, NULL);
    mbentry_t *mbentry = NULL;
    int r = mboxlist_lookup(cardhomename, &mbentry, NULL);
    if (r) {
        xsyslog(LOG_ERR, "can't lookup addressbook home",
                "cardhomename=%s error=%s",
                cardhomename, error_message(r));
        goto done;
    }

#ifdef HAVE_LIBICALVCARD
    int rights = httpd_myrights(authstate, mbentry);
    int is_main_account = !strcmpsafe(authuserid, accountid);

    json_object_set_new(account_capabilities, JMAP_URN_CONTACTS,
                        json_pack("{s:b}", "mayCreateAddressBook",
                                  is_main_account || (rights & JACL_CREATECHILD)));
#endif

    if (config_getswitch(IMAPOPT_JMAP_NONSTANDARD_EXTENSIONS)) {
        json_object_set_new(account_capabilities, JMAP_CONTACTS_EXTENSION, json_object());
    }

 done:
    free(cardhomename);
    mboxlist_entry_free(&mbentry);
}

struct changes_rock {
    jmap_req_t *req;
    struct jmap_changes *changes;
    size_t seen_records;
    modseq_t highestmodseq;
};

static void strip_spurious_deletes(struct changes_rock *urock)
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

static json_t *jmap_utf8string(const char *s)
{
    struct buf buf = BUF_INITIALIZER;
    jmap_decode_to_utf8("utf-8", ENCODING_NONE, s, strlen(s), 1.0, &buf, NULL);
    json_t *jval = json_string(buf_cstring(&buf));
    buf_free(&buf);
    return jval;
}

/*****************************************************************************
 * JMAP Contacts API
 ****************************************************************************/

struct contact_getargs {
    const char *addressbook_id;
    int disable_uri_as_blobid;
};

static int _contact_getargs_parse(jmap_req_t *req __attribute__((unused)),
                                  struct jmap_parser *parser __attribute__((unused)),
                                  const char *key,
                                  json_t *arg,
                                  void *rock)
{
    struct contact_getargs *args = rock;
    int r = 0;

    /* Non-JMAP spec addressbookId argument */
    if (!strcmp(key, "addressbookId") && json_is_string(arg)) {
        args->addressbook_id = json_string_value(arg);
        r = 1;
    }
    else if (!strcmp(key, "disableUriAsBlobId") && json_is_boolean(arg)) {
        args->disable_uri_as_blobid = json_boolean_value(arg);
        r = 1;
    }

    return r;
}

struct cards_rock {
    struct carddav_db *db;
    struct jmap_req *req;
    struct jmap_get *get;
    struct mailbox *mailbox;
    mbentry_t *mbentry;
    hashu64_table jmapcache;
    int rows;
    struct contact_getargs args;
};

static json_t *jmap_group_from_vcard(struct vparse_card *vcard)
{
    struct vparse_entry *ventry = NULL;
    json_t *obj = json_object();

    // Deduplicate member ids
    json_t *contactids_set = json_object();
    json_t *otherids_sets = json_object();

    for (ventry = vcard->properties; ventry; ventry = ventry->next) {
        const char *name = ventry->name;
        const char *propval = ventry->v.value;

        if (!name) continue;
        if (!propval) continue;

        if (!strcasecmp(name, "fn")) {
            json_object_set_new(obj, "name", jmap_utf8string(propval));
        }

        else if (!strcasecmp(name, "member") ||
                 !strcasecmp(name, "x-addressbookserver-member")) {
            if (strncmp(propval, "urn:uuid:", 9)) continue;
            json_object_set_new(contactids_set, propval+9, json_true());
        }

        else if (!strcasecmp(name, "x-fm-otheraccount-member")) {
            if (strncmp(propval, "urn:uuid:", 9)) continue;
            struct vparse_param *param = vparse_get_param(ventry, "userid");
            if (!param) continue;
            json_t *object = json_object_get(otherids_sets, param->value);
            if (!object) {
                object = json_object();
                json_object_set_new(otherids_sets, param->value, object);
            }
            json_object_set_new(object, propval+9, json_true());
        }
    }

    // Convert contact ids set to array
    json_t *contactids = json_array();
    const char *contactid;
    json_t *jval;
    json_object_foreach(contactids_set, contactid, jval) {
        json_array_append_new(contactids, json_string(contactid));
    }
    json_object_set_new(obj, "contactIds", contactids);

    // Convert otherids set to array
    json_t *otherids = json_object();
    const char *userid;
    json_t *jaccountids;
    json_object_foreach(otherids_sets, userid, jaccountids) {
        json_t *account_contactids = json_array();
        json_object_foreach(jaccountids, contactid, jval) {
            json_array_append_new(account_contactids, json_string(contactid));
        }
        json_object_set_new(otherids, userid, account_contactids);
    }
    json_object_set_new(obj, "otherAccountContactIds", otherids);

    json_decref(contactids_set);
    json_decref(otherids_sets);

    return obj;
}

static int getgroups_cb(void *rock, struct carddav_data *cdata)
{
    struct cards_rock *crock = (struct cards_rock *) rock;
    struct index_record record;
    jmap_req_t *req = crock->req;
    json_t *obj = NULL;
    mbentry_t *mbentry = NULL;
    char *xhref;
    int r = 0;

    mbentry = jmap_mbentry_from_dav(req, &cdata->dav);

    if (!mbentry || !jmap_hasrights_mbentry(req, mbentry, JACL_READITEMS)) {
        mboxlist_entry_free(&mbentry);
        return 0;
    }

    if (!crock->mailbox || strcmp(mailbox_uniqueid(crock->mailbox), cdata->dav.mailbox)) {
        mailbox_close(&crock->mailbox);
        r = mailbox_open_irl(mbentry->name, &crock->mailbox);
    }
    if (r) goto done;

    r = mailbox_find_index_record(crock->mailbox, cdata->dav.imap_uid, &record);
    if (r) goto done;

    /* Load message containing the resource and parse vcard data */
    struct vparse_card *vcard = record_to_vcard(crock->mailbox, &record);
    if (!vcard || !vcard->objects) {
        syslog(LOG_ERR, "record_to_vcard failed for record %u:%s",
                cdata->dav.imap_uid, mailbox_name(crock->mailbox));
        vparse_free_card(vcard);
        r = IMAP_INTERNAL;
        goto done;
    }

    obj = jmap_group_from_vcard(vcard->objects);

    vparse_free_card(vcard);

    json_object_set_new(obj, "id", json_string(cdata->vcard_uid));
    json_object_set_new(obj, "uid", json_string(cdata->vcard_uid));

    json_object_set_new(obj, "addressbookId",
                        json_string(strrchr(mbentry->name, '.')+1));

    xhref = jmap_xhref(mbentry->name, cdata->dav.resource);
    json_object_set_new(obj, "x-href", json_string(xhref));
    free(xhref);

    json_array_append_new(crock->get->list, obj);

    crock->rows++;

 done:
    mboxlist_entry_free(&mbentry);

    return r;
}

// clang-format off
static const jmap_property_t contact_props[] = {
    {
        "id",
        NULL,
        JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE | JMAP_PROP_ALWAYS_GET
    },
    {
        "uid",
        NULL,
        JMAP_PROP_IMMUTABLE
    },
    {
        "isFlagged",
        NULL,
        0
    },
    {
        "avatar",
        NULL,
        0
    },
    {
        "prefix",
        NULL,
        0
    },
    {
        "firstName",
        NULL,
        0
    },
    {
        "lastName",
        NULL,
        0
    },
    {
        "suffix",
        NULL,
        0
    },
    {
        "nickname",
        NULL,
        0
    },
    {
        "birthday",
        NULL,
        0
    },
    {
        "anniversary",
        NULL,
        0
    },
    {
        "company",
        NULL,
        0
    },
    {
        "department",
        NULL,
        0
    },
    {
        "jobTitle",
        NULL,
        0
    },
    {
        "emails",
        NULL,
        0
    },
    {
        "phones",
        NULL,
        0
    },
    {
        "online",
        NULL,
        0
    },
    {
        "addresses",
        NULL,
        0
    },
    {
        "notes",
        NULL,
        0
    },
    {
        "vCardProps",
        NULL,
        JMAP_PROP_REJECT_GET | JMAP_PROP_REJECT_SET | JMAP_PROP_SKIP_GET
    },

    /* FM extensions */
    {
        "addressbookId",
        JMAP_CONTACTS_EXTENSION,
        0
    },
    {
        "x-href",
        JMAP_CONTACTS_EXTENSION,
        JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE
    }, // AJAXUI only
    {
        "x-hasPhoto",
        JMAP_CONTACTS_EXTENSION,
        JMAP_PROP_SERVER_SET
    }, // AJAXUI only
    {
        "importance",
        JMAP_CONTACTS_EXTENSION,
        0
    },  // JMAPUI only
    {
        "blobId",
        JMAP_CONTACTS_EXTENSION,
        JMAP_PROP_SERVER_SET
    },
    {
        "size",
        JMAP_CONTACTS_EXTENSION,
        JMAP_PROP_SERVER_SET
    },

    { NULL, NULL, 0 }
};
// clang-format on

// clang-format off
static const jmap_property_t group_props[] = {
    {
        "id",
        NULL,
        JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE | JMAP_PROP_ALWAYS_GET
    },
    {
        "uid",
        NULL,
        JMAP_PROP_IMMUTABLE
    },
    {
        "name",
        NULL,
        0
    },
    {
        "contactIds",
        NULL,
        0
    },

    // FM extensions */
    {
        "addressbookId",
        JMAP_CONTACTS_EXTENSION,
        0
    },
    {
        "x-href",
        JMAP_CONTACTS_EXTENSION,
        JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE
    }, // AJAXUI only
    {
        "otherAccountContactIds",
        JMAP_CONTACTS_EXTENSION,
        0
    }, // Both AJAXUI and JMAPUI

    { NULL, NULL, 0 }
};
// clang-format on

static void cachecards_cb(uint64_t rowid, void *payload, void *vrock)
{
    const char *jscard = payload;
    struct cards_rock *rock = vrock;

    // there's no way to return errors, but luckily it doesn't matter if we
    // fail to cache
    carddav_write_jscardcache(rock->db, rowid,
                              rock->req->userid, JMAPCACHE_CARDVERSION, jscard);
}

static int has_addressbooks_cb(const mbentry_t *mbentry, void *rock)
{
    jmap_req_t *req = rock;
    if (mbtype_isa(mbentry->mbtype) == MBTYPE_ADDRESSBOOK &&
            jmap_hasrights_mbentry(req, mbentry, JACL_READITEMS)) {
        return CYRUSDB_DONE;
    }
    return 0;
}

static int has_addressbooks(jmap_req_t *req)
{
    mbname_t *mbname = mbname_from_userid(req->accountid);
    mbname_push_boxes(mbname, config_getstring(IMAPOPT_ADDRESSBOOKPREFIX));
    int r = mboxlist_mboxtree(mbname_intname(mbname), has_addressbooks_cb,
                              req, MBOXTREE_SKIP_ROOT);
    mbname_free(&mbname);
    return r == CYRUSDB_DONE;
}

static int _contacts_get(struct jmap_req *req, carddav_cb_t *cb, int kind,
                         const jmap_property_t *props)
{
    if (!has_addressbooks(req)) {
        jmap_error(req, json_pack("{s:s}", "type", "accountNoAddressbooks"));
        return 0;
    }

    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_get get;
    json_t *err = NULL;
    struct carddav_db *db = NULL;
    mbentry_t *mbentry = NULL;
    int r = 0;

    /* Build callback data */
    struct cards_rock rock = {
        .req = req,
        .get = &get,
        .jmapcache = HASHU64_TABLE_INITIALIZER,
    };

    construct_hashu64_table(&rock.jmapcache, 512, 0);

    /* Parse request */
    jmap_get_parse(req, &parser, props, /* allow_null_ids */ 1,
                   &_contact_getargs_parse, &rock.args, &get, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    /* Does the client request specific events? */
    rock.db = db = carddav_open_userid(req->accountid);
    if (!db) {
        syslog(LOG_ERR,
               "carddav_open_mailbox failed for user %s", req->accountid);
        r = IMAP_INTERNAL;
        goto done;
    }

    if (rock.args.addressbook_id) {
        if (kind == CARDDAV_KIND_ANY) {
            jmap_parser_invalid(&parser, "addressbookId");
            err = json_pack("{s:s}", "type", "invalidArguments");
            json_object_set(err, "arguments", parser.invalid);
            jmap_error(req, err);
            goto done;
        }

        char *mboxname = carddav_mboxname(req->accountid, rock.args.addressbook_id);
        mboxlist_lookup_allow_all(mboxname, &mbentry, NULL);
        free(mboxname);
        /* XXX  invalidArgument? */
    }

    if (JNOTNULL(get.ids)) {
        size_t i;
        json_t *jval;
        json_array_foreach(get.ids, i, jval) {
            rock.rows = 0;
            const char *id = json_string_value(jval);

            r = carddav_get_cards(db, mbentry, req->userid, id, kind, cb, &rock);
            if (r || !rock.rows) {
                json_array_append(get.not_found, jval);
            }
            r = 0; // we don't ever fail the whole request from this
        }
    }
    else {
        rock.rows = 0;
        r = carddav_get_cards(db, mbentry, req->userid, NULL, kind, cb, &rock);
        if (r) goto done;
    }

    if (hashu64_count(&rock.jmapcache)) {
        r = carddav_begin(db);
        if (!r) hashu64_enumerate(&rock.jmapcache, cachecards_cb, &rock);
        if (r) carddav_abort(db);
        else r = carddav_commit(db);
        if (r) goto done;
    }

    /* Build response */
    get.state = modseqtoa(jmap_modseq(req, MBTYPE_ADDRESSBOOK, 0));
    jmap_ok(req, jmap_get_reply(&get));

  done:
    jmap_parser_fini(&parser);
    jmap_get_fini(&get);
    mboxlist_entry_free(&mbentry);
    mailbox_close(&rock.mailbox);
    mboxlist_entry_free(&rock.mbentry);
    free_hashu64_table(&rock.jmapcache, free);
    if (db) carddav_close(db);
    return r;
}

static int jmap_contactgroup_get(struct jmap_req *req)
{
    return _contacts_get(req, &getgroups_cb, CARDDAV_KIND_GROUP, group_props);
}

static const char *_json_array_get_string(const json_t *obj, size_t index)
{
    const json_t *jval = json_array_get(obj, index);
    if (!jval) return NULL;
    const char *val = json_string_value(jval);
    return val;
}


static int getchanges_cb(void *rock, struct carddav_data *cdata)
{
    struct changes_rock *urock = (struct changes_rock *) rock;
    struct dav_data dav = cdata->dav;
    const char *uid = cdata->vcard_uid;
    mbentry_t *mbentry = jmap_mbentry_from_dav(urock->req, &dav);

    int rights =
        mbentry && jmap_hasrights_mbentry(urock->req, mbentry, JACL_READITEMS);
    mboxlist_entry_free(&mbentry);
    if (!rights)
        return 0;

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

static int _contacts_changes(struct jmap_req *req, int kind)
{
    if (!has_addressbooks(req)) {
        jmap_error(req, json_pack("{s:s}", "type", "accountNoAddressbooks"));
        return 0;
    }

    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_changes changes = JMAP_CHANGES_INITIALIZER;
    json_t *err = NULL;
    struct carddav_db *db = NULL;
    mbentry_t *mbentry = NULL;
    int r = 0;

    /* Parse request */
    struct contact_getargs args = {0};
    jmap_changes_parse(req, &parser, req->counters.carddavdeletedmodseq,
                       &_contact_getargs_parse, &args, &changes, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    if (args.addressbook_id) {
        char *mboxname = carddav_mboxname(req->accountid, args.addressbook_id);
        mboxlist_lookup_allow_all(mboxname, &mbentry, NULL);
        free(mboxname);
        /* XXX  invalidArgument? */
    }

    /* Lookup updates. */
    db = carddav_open_userid(req->accountid);
    if (!db) {
        syslog(LOG_ERR,
               "carddav_open_userid failed for user %s", req->accountid);
        r = IMAP_INTERNAL;
        goto done;
    }
    struct changes_rock rock = { req, &changes, 0 /*seen_records*/, 0 /*highestmodseq*/};
    r = carddav_get_updates(db, changes.since_modseq, mbentry, kind,
                            -1 /*max_records*/, &getchanges_cb, &rock);
    if (r) goto done;

    strip_spurious_deletes(&rock);

    /* Determine new state. */
    changes.new_modseq = changes.has_more_changes ?
        rock.highestmodseq : jmap_modseq(req, MBTYPE_ADDRESSBOOK, 0);

    /* Build response */
    jmap_ok(req, jmap_changes_reply(&changes));

  done:
    if (r) jmap_error(req, jmap_server_error(r));
    jmap_changes_fini(&changes);
    jmap_parser_fini(&parser);
    carddav_close(db);
    mboxlist_entry_free(&mbentry);

    return 0;
}

static int jmap_contactgroup_changes(struct jmap_req *req)
{
    return _contacts_changes(req, CARDDAV_KIND_GROUP);
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
    const char *group_propname = "X-ADDRESSBOOKSERVER-MEMBER";
    struct vparse_entry *ventry = vparse_get_entry(card, NULL, "VERSION");
    int r = 0;
    size_t index;
    struct buf buf = BUF_INITIALIZER;

    if (ventry && atof(ventry->v.value) >= 4.0) group_propname =  "MEMBER";

    vparse_delete_entries(card, NULL, group_propname);

    for (index = 0; index < json_array_size(members); index++) {
        const char *item = _json_array_get_string(members, index);
        const char *uid = _resolve_contactid(req, item);
        if (!item || !uid) {
            buf_printf(&buf, "contactIds[%zu]", index);
            json_array_append_new(invalid, json_string(buf_cstring(&buf)));
            buf_reset(&buf);
            continue;
        }

        buf_reset(&buf);
        if (strncmpsafe("urn:uuid:", uid, 9)) {
            buf_setcstr(&buf, "urn:uuid:");
        }

        buf_appendcstr(&buf, uid);
        vparse_add_entry(card, NULL, group_propname, buf_cstring(&buf));
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
                buf_printf(&buf, "otherAccountContactIds[%s]", key);
                json_array_append_new(invalid, json_string(buf_cstring(&buf)));
                buf_reset(&buf);
                continue;
            }

            buf_reset(&buf);
            if (strncmpsafe("urn:uuid:", uid, 9)) {
                buf_setcstr(&buf, "urn:uuid:");
            }

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

typedef struct {
    char *key;
    char *prop;
    char *type;
    size_t size;
    struct message_guid guid;
} property_blob_t;

static property_blob_t *property_blob_new(const char *key, const char *prop,
                                          const char *type, struct buf *data)
{
    property_blob_t *blob = xzmalloc(sizeof(property_blob_t));

    blob->key = xstrdup(key);
    blob->prop = xstrdup(prop);
    blob->type = xstrdupnull(type);
    blob->size = buf_len(data);
    message_guid_generate(&blob->guid, buf_base(data), buf_len(data));

    return blob;
}

static void property_blob_free(property_blob_t **blob)
{
    property_blob_t *freeme = *blob;

    free(freeme->key);
    free(freeme->prop);
    free(freeme->type);
    free(freeme);
    *blob = NULL;
}

static void _contacts_set(struct jmap_req *req, unsigned kind,
                          const jmap_property_t *props,
                          int (*_set_create)(jmap_req_t *req,
                                             unsigned kind,
                                             json_t *jcard,
                                             struct mailbox **mailbox,
                                             json_t *item,
                                             jmap_contact_errors_t *errors),
                          int (*_set_update)(jmap_req_t *req,
                                             unsigned kind,
                                             const char *uid,
                                             json_t *jcard,
                                             struct carddav_db *db,
                                             struct mailbox **mailbox,
                                             json_t **item,
                                             jmap_contact_errors_t *errors))
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_set set;
    json_t *err = NULL;
    int r = 0;

    struct mailbox *mailbox = NULL;
    struct mailbox *newmailbox = NULL;

    struct carddav_db *db = carddav_open_userid(req->accountid);
    if (!db) {
        xsyslog(LOG_ERR, "can not open carddav db", "accountid=<%s>",
                req->accountid);
        r = IMAP_INTERNAL;
        goto done;
    }

    /* Parse arguments */
    jmap_set_parse(req, &parser, props, NULL, NULL, &set, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    if (set.if_in_state) {
        if (atomodseq_t(set.if_in_state) != jmap_modseq(req, MBTYPE_ADDRESSBOOK, 0)) {
            jmap_error(req, json_pack("{s:s}", "type", "stateMismatch"));
            goto done;
        }
        set.old_state = xstrdup(set.if_in_state);
    }
    else {
        set.old_state = modseqtoa(jmap_modseq(req, MBTYPE_ADDRESSBOOK, 0));
    }

    r = carddav_create_defaultaddressbook(req->accountid);
    if (r) goto done;

    /* create */
    const char *key;
    json_t *arg;
    json_object_foreach(set.create, key, arg) {
        json_t *invalid = json_array();
        jmap_contact_errors_t errors = { invalid, NULL };
        json_t *item = json_object();
        r = _set_create(req, kind, arg, &mailbox, item, &errors);
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
                case IMAP_MESSAGE_TOO_LARGE:
                    err = json_pack("{s:s}", "type", "tooLarge");
                    break;
                default:
                    err = jmap_server_error(r);
            }
            json_object_set_new(set.not_created, key, err);
            r = 0;
            json_decref(item);
            json_decref(invalid);
            continue;
        }
        if (json_array_size(invalid)) {
            json_t *err = json_pack("{s:s s:o}",
                                    "type", "invalidProperties",
                                    "properties", invalid);
            json_object_set_new(set.not_created, key, err);
            json_decref(errors.blobNotFound);
            json_decref(item);
            continue;
        }
        json_decref(invalid);

        if (errors.blobNotFound) {
            json_t *err = json_pack("{s:s s:o}",
                                    "type", "blobNotFound",
                                    "notFound", errors.blobNotFound);
            json_object_set_new(set.not_created, key, err);
            json_decref(item);
            continue;
        }

        /* Report contact as created. */
        json_object_set_new(set.created, key, item);

        /* Register creation id */
        jmap_add_id(req, key, json_string_value(json_object_get(item, "id")));
    }

    /* update */
    const char *uid;
    json_object_foreach(set.update, uid, arg) {
        json_t *invalid = json_array();
        jmap_contact_errors_t errors = { invalid, NULL };
        json_t *item = NULL;
        r = _set_update(req, kind, uid, arg, db, &mailbox, &item, &errors);
        if (r) {
            json_t *err;
            switch (r) {
            case HTTP_NOT_FOUND:
                err = json_pack("{s:s}", "type", "notFound");
                break;
            case HTTP_NOT_ALLOWED:
                err = json_pack("{s:s}", "type", "accountReadOnly");
                break;
            case HTTP_BAD_REQUEST:
                err = json_pack("{s:s}", "type", "invalidPatch");
                break;
            case HTTP_UNPROCESSABLE:
                err = json_pack("{s:s s:s}", "type", "serverFail",
                                "description", "invalid current card");
                break;
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
            json_object_set_new(set.not_updated, uid, err);
            r = 0;
            json_decref(item);
            json_decref(invalid);
            continue;
        }
        if (json_array_size(invalid)) {
            json_t *err = json_pack("{s:s s:o}",
                                    "type", "invalidProperties",
                                    "properties", invalid);
            json_object_set_new(set.not_updated, uid, err);
            json_decref(errors.blobNotFound);
            json_decref(item);
            continue;
        }
        json_decref(invalid);

        if (errors.blobNotFound) {
            json_t *err = json_pack("{s:s s:o}",
                                    "type", "blobNotFound",
                                    "notFound", errors.blobNotFound);
            json_object_set_new(set.not_updated, uid, err);
            json_decref(item);
            continue;
        }

        /* Report contact as updated. */
        json_object_set_new(set.updated, uid, item);
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
        mbentry_t *mbentry = NULL;
        struct carddav_data *cdata = NULL;
        uint32_t olduid;
        r = carddav_lookup_uid(db, uid, &cdata);

        /* is it a valid contact? */
        if (r || !cdata || !cdata->dav.imap_uid ||
            (cdata->kind != kind && kind != CARDDAV_KIND_ANY)) {
            r = 0;
            json_t *err = json_pack("{s:s}", "type", "notFound");
            json_object_set_new(set.not_destroyed, uid, err);
            continue;
        }
        olduid = cdata->dav.imap_uid;

        mbentry = jmap_mbentry_from_dav(req, &cdata->dav);

        if (!mbentry || !jmap_hasrights_mbentry(req, mbentry, JACL_REMOVEITEMS)) {
            int rights = mbentry ? jmap_myrights_mbentry(req, mbentry) : 0;
            json_t *err = json_pack("{s:s}", "type",
                                    rights & JACL_READITEMS ?
                                    "accountReadOnly" : "notFound");
            json_object_set_new(set.not_destroyed, uid, err);
            mboxlist_entry_free(&mbentry);
            continue;
        }

        if (!mailbox || strcmp(mailbox_name(mailbox), mbentry->name)) {
            mailbox_close(&mailbox);
            r = mailbox_open_iwl(mbentry->name, &mailbox);
        }
        mboxlist_entry_free(&mbentry);
        if (r) goto done;

        syslog(LOG_NOTICE,
               "jmap: remove %s %s/%s",
               kind == CARDDAV_KIND_GROUP ? "group" : "contact",
               req->accountid, uid);
        r = carddav_remove(mailbox, olduid, /*isreplace*/0, req->userid);
        if (r) {
            xsyslog(LOG_ERR, "IOERROR: carddav remove failed",
                             "kind=<%s> mailbox=<%s> olduid=<%u>",
                             kind == CARDDAV_KIND_GROUP ? "group" : "contact",
                             mailbox_name(mailbox), olduid);
            goto done;
        }

        json_array_append_new(set.destroyed, json_string(uid));
    }

    /* force modseq to stable */
    if (mailbox) mailbox_unlock_index(mailbox, NULL);

    set.new_state = modseqtoa(jmap_modseq(req, MBTYPE_ADDRESSBOOK, JMAP_MODSEQ_RELOAD));

    jmap_ok(req, jmap_set_reply(&set));
    r = 0;

done:
    if (r) jmap_error(req, jmap_server_error(r));
    jmap_parser_fini(&parser);
    jmap_set_fini(&set);
    mailbox_close(&newmailbox);
    mailbox_close(&mailbox);

    carddav_close(db);
}

static int jmap_contactgroup_set(struct jmap_req *req)
{
    _contacts_set(req, CARDDAV_KIND_GROUP, group_props,
                  &_contact_set_create, &_contact_set_update);
    return 0;
}

/* Extract separate y,m,d from YYYY-MM-DD or (with ignore_hyphens) YYYYMMDD
 *
 * This handles birthday/anniversary and BDAY/ANNIVERSARY for JMAP and vCard
 *
 * JMAP dates are _always_ YYYY-MM-DD, so use require_hyphens = 1
 *
 * For vCard, this handles "date-value" from RFC 2426 (which is "date" from
 * RFC 2425), used by BDAY (ANNIVERSARY isn't in vCard 3). vCard 4 says BDAY and
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

static json_t *vcardprop_from_vcard_entry(struct vparse_entry *entry)
{
    struct buf buf = BUF_INITIALIZER;

    // Make jCard property.
    json_t *vprop = json_array();

    // Element 1: Property name.
    buf_setcstr(&buf, entry->name);
    json_array_append_new(vprop, json_string(buf_lcase(&buf)));

    // Element 2: Parameters.
    json_t *vparams = json_object();
    for (struct vparse_param *param = entry->params; param;
         param = param->next) {
        if (strcasecmp(param->name, "value") && param->value) {
            buf_setcstr(&buf, param->name);
            json_object_set_new(vparams, buf_lcase(&buf),
                                json_string(param->value));
        }
    }

    if (entry->group) {
        // Set this after arbitrary parameters so that we overwrite
        // any bogus GROUP parameter set in the vCard property.
        buf_setcstr(&buf, entry->group);
        json_object_set_new(vparams, "group", json_string(buf_lcase(&buf)));
    }
    json_array_append_new(vprop, vparams);

    // Element 3: Value type.
    const char *value = NULL;
    for (struct vparse_param *param = entry->params; param;
         param = param->next) {
        if (!strcasecmp(param->name, "value")) {
            value = param->value;
            break;
        }
    }
    json_array_append_new(vprop, json_string(value ? value : "unknown"));

    // Element 4 and more: Property value.
    if (entry->multivaluesep) {
        // It's highly unlikely we'll encounter an unknown x-property
        // for which we do know the multi-value separator. But even if
        // we do, we can't rely on knowing it when we convert that
        // jCard property value back to vCard.
        // Instead, we'll join the multiple values by their separator
        // and set a single string value in jCard, as these vCardProps
        // are for internal use anyway.
        buf_reset(&buf);
        for (int i = 0; i < strarray_size(entry->v.values); i++) {
            if (i)
                buf_putc(&buf, entry->multivaluesep);
            buf_appendcstr(&buf, strarray_nth(entry->v.values, i));
        }
        json_array_append_new(vprop, json_string(buf_cstring(&buf)));
    }
    else if (entry->v.value) {
        json_array_append_new(vprop, json_string(entry->v.value));
    }
    if (json_array_size(vprop) == 3) {
        json_array_append_new(vprop, json_string(""));
    }

    buf_free(&buf);
    return vprop;
}

/* Convert the VCARD card to jmap properties */
static json_t *jmap_contact_from_vcard(const char *userid,
                                       struct vparse_card *card,
                                       struct mailbox *mailbox,
                                       struct index_record *record)
{
    strarray_t *empty = NULL;
    json_t *obj = json_object();
    struct buf buf = BUF_INITIALIZER;
    struct vparse_entry *entry;

    /* Fetch any Apple-style labels */
    hash_table labels = HASH_TABLE_INITIALIZER;
    size_t nprops = 0;
    for (entry = card->properties; entry; entry = entry->next) {
        nprops++;
    }
    construct_hash_table(&labels, nprops + 1, 0);
    for (entry = card->properties; entry; entry = entry->next) {
        if (entry->group &&
            !strcasecmpsafe(entry->name, VCARD_APPLE_LABEL_PROPERTY)) {
            hash_insert(entry->group, entry->v.value, &labels);
        }
    }

    const strarray_t *n = vparse_multival(card, "n");
    const strarray_t *org = vparse_multival(card, "org");
    if (!n) n = empty ? empty : (empty = strarray_new());
    if (!org) org = empty ? empty : (empty = strarray_new());

    /* name fields: Family; Given; Middle; Prefix; Suffix. */

    const char *family = strarray_safenth(n, 0);
    json_object_set_new(obj, "lastName", jmap_utf8string(family));

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
    json_object_set_new(obj, "firstName", jmap_utf8string(buf_cstring(&buf)));

    const char *prefix = strarray_safenth(n, 3);
    json_object_set_new(obj, "prefix",
                        jmap_utf8string(prefix)); /* just prefix */

    const char *suffix = strarray_safenth(n, 4);
    json_object_set_new(obj, "suffix",
                        jmap_utf8string(suffix)); /* just suffix */

    json_object_set_new(obj, "company",
                        jmap_utf8string(strarray_safenth(org, 0)));
    json_object_set_new(obj, "department",
                        jmap_utf8string(strarray_safenth(org, 1)));

    /* we used to store jobTitle in ORG[2] instead of TITLE, which confused
     * CardDAV clients. that's fixed, but there's now lots of cards with it
     * stored in the wrong place, so check both */
    const char *item = vparse_stringval(card, "title");
    if (!item)
        item = strarray_safenth(org, 2);
    json_object_set_new(obj, "jobTitle", jmap_utf8string(item));

    json_t *adr = json_array();
    json_t *emails = json_array();
    json_t *phones = json_array();
    json_t *online = json_array();
    int emailIndex = 0, defaultEmailIndex = -1;

    // Generate lookup table for Apple's X-ABADR property values.
    hash_table abadr_by_group = HASH_TABLE_INITIALIZER;
    size_t nabadr = 0;
    for (struct vparse_entry *it = card->properties; it; it = it->next) {
        if (!strcasecmp(it->name, VCARD_APPLE_ABADR_PROPERTY))
            nabadr++;
    }
    construct_hash_table(&abadr_by_group, nabadr + 1, 0);
    for (struct vparse_entry *it = card->properties; it; it = it->next) {
        if (!strcasecmp(it->name, VCARD_APPLE_ABADR_PROPERTY)) {
            if (it->group && it->v.value) {
                buf_setcstr(&buf, it->group);
                hash_insert(
                    buf_ucase(&buf), xstrdup(it->v.value), &abadr_by_group);
            }
        }
    }

    for (entry = card->properties; entry; entry = entry->next) {
        const struct vparse_param *param;
        const char *label = NULL;
        size_t label_len = 0;

        /* Apple label */
        if (entry->group) {
            label = hash_lookup(entry->group, &labels);
            if (label) {
                label_len = strlen(label);

                /* Check and adjust for weird (localized?) labels */
                if (label_len > 8 && !strncmp(label, "_$!<", 4)) {
                    label += 4;      // skip "_$!<" prefix
                    label_len -= 8;  // and trim ">!$_" suffix
                }
            }
        }

        if (!strcasecmp(entry->name, "adr")) {
            json_t *item = json_object();
            const char *type = "other";

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
                    if (label) label_len = strlen(label);
                }
            }
            json_object_set_new(item, "type", json_string(type));
            json_object_set_new(item, "label",
                                label ? json_stringn(label, label_len) : json_null());

            const strarray_t *a = entry->v.values;
            const char *pobox = strarray_safenth(a, 0);
            const char *extended = strarray_safenth(a, 1);
            const char *street = strarray_safenth(a, 2);
            unsigned newline = 0;

            buf_reset(&buf);
            if (*pobox) {
                buf_appendcstr(&buf, pobox);
                newline++;
            }
            if (*extended) {
                if (newline++) buf_putc(&buf, '\n');
                buf_appendcstr(&buf, extended);
            }
            if (*street) {
                if (newline) buf_putc(&buf, '\n');
                buf_appendcstr(&buf, street);
            }

            /* Read countryCode from same-grouped ABADR property, if any */
            const char *countrycode = NULL;
            if (entry->group) {
                buf_setcstr(&buf, entry->group);
                countrycode = hash_lookup(buf_ucase(&buf), &abadr_by_group);
            }

            json_object_set_new(item, "street",
                                jmap_utf8string(buf_cstring(&buf)));
            json_object_set_new(item, "locality",
                                jmap_utf8string(strarray_safenth(a, 3)));
            json_object_set_new(item, "region",
                                jmap_utf8string(strarray_safenth(a, 4)));
            json_object_set_new(item, "postcode",
                                jmap_utf8string(strarray_safenth(a, 5)));
            json_object_set_new(item, "country",
                                jmap_utf8string(strarray_safenth(a, 6)));
            if (countrycode) {
                buf_setcstr(&buf, countrycode);
                buf_lcase(&buf);
                json_object_set_new(item, "countryCode",
                        jmap_utf8string(buf_cstring(&buf)));
            }

            json_array_append_new(adr, item);
        }
        else if (!strcasecmp(entry->name, "email")) {
            json_t *item = json_object();
            const char *type = "other";
            for (param = entry->params; param; param = param->next) {
                if (!strcasecmp(param->name, "type")) {
                    if (!strcasecmp(param->value, "home")) {
                        type = "personal";
                    }
                    else if (!strcasecmp(param->value, "work")) {
                        type = "work";
                    }
                    else if (!strcasecmp(param->value, "pref")) {
                        if (defaultEmailIndex < 0)
                            defaultEmailIndex = emailIndex;
                    }
                }
                else if (!strcasecmp(param->name, "label")) {
                    label = param->value;
                    if (label) label_len = strlen(label);
                }
            }
            json_object_set_new(item, "type", json_string(type));
            json_object_set_new(item, "isDefault", json_false());
            if (label) {
                json_object_set_new(item, "label", json_stringn(label, label_len));
            }

            json_object_set_new(item, "value", jmap_utf8string(entry->v.value));

            json_array_append_new(emails, item);
            emailIndex++;
        }
        else if (!strcasecmp(entry->name, "tel")) {
            json_t *item = json_object();
            const char *type = "other";
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
                    if (label) label_len = strlen(label);
                }
            }
            json_object_set_new(item, "type", json_string(type));
            if (label) {
                json_object_set_new(item, "label", json_stringn(label, label_len));
            }

            json_object_set_new(item, "value", jmap_utf8string(entry->v.value));

            json_array_append_new(phones, item);
        }
        else if (!strcasecmp(entry->name, "url")) {
            json_t *item = json_object();
            for (param = entry->params; param; param = param->next) {
                if (!strcasecmp(param->name, "label")) {
                    label = param->value;
                    if (label) label_len = strlen(label);
                }
            }
            json_object_set_new(item, "type", json_string("uri"));
            if (label) json_object_set_new(item, "label", json_stringn(label, label_len));
            json_object_set_new(item, "value", json_string(entry->v.value));
            json_array_append_new(online, item);
        }
        else if (!strcasecmp(entry->name, "impp")) {
            json_t *item = json_object();
            for (param = entry->params; param; param = param->next) {
                if (!strcasecmp(param->name, "x-service-type")) {
                    label = _servicetype(param->value);
                }
            }
            json_object_set_new(item, "type", json_string("username"));
            if (label) json_object_set_new(item, "label", json_string(label));
            json_object_set_new(item, "value", jmap_utf8string(entry->v.value));
            json_array_append_new(online, item);
        }
        else if (!strcasecmp(entry->name, "x-social-profile")) {
            json_t *item = json_object();
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
                                jmap_utf8string(value ? value : entry->v.value));
            json_array_append_new(online, item);
        }
        else if (!strcasecmp(entry->name, "x-fm-online-other")) {
            json_t *item = json_object();
            for (param = entry->params; param; param = param->next) {
                if (!strcasecmp(param->name, "label")) {
                    label = param->value;
                }
            }
            json_object_set_new(item, "type", json_string("other"));
            if (label) json_object_set_new(item, "label", json_string(label));
            json_object_set_new(item, "value", jmap_utf8string(entry->v.value));
            json_array_append_new(online, item);
        }
        else if (!strncasecmp(entry->name, "x-", 2)) {
            // Preserve unknown x-properties as RFC 7095 jCard.
            json_t *vcardprops = json_object_get(obj, "vCardProps");
            if (!vcardprops) {
                vcardprops = json_array();
                json_object_set_new(obj, "vCardProps", vcardprops);
            }

            json_t *vprop = vcardprop_from_vcard_entry(entry);
            if (vprop) {
                json_array_append_new(vcardprops, vprop);
            }
            else if (!json_array_size(vcardprops)) {
                json_object_del(obj, "vCardProps");
            }
        }
    }

    if (defaultEmailIndex < 0)
        defaultEmailIndex = 0;
    json_object_set_new(json_array_get(emails, defaultEmailIndex),
                        "isDefault", json_true());

    json_object_set_new(obj, "addresses", adr);
    json_object_set_new(obj, "emails", emails);
    json_object_set_new(obj, "phones", phones);
    json_object_set_new(obj, "online", online);

    item = vparse_stringval(card, "nickname");
    json_object_set_new(obj, "nickname", jmap_utf8string(item ? item : ""));

    entry = vparse_get_entry(card, NULL, "anniversary");
    _date_to_jmap(entry, &buf);
    json_object_set_new(obj, "anniversary", jmap_utf8string(buf_cstring(&buf)));

    entry = vparse_get_entry(card, NULL, "bday");
    _date_to_jmap(entry, &buf);
    json_object_set_new(obj, "birthday", jmap_utf8string(buf_cstring(&buf)));

    item = vparse_stringval(card, "note");
    json_object_set_new(obj, "notes", jmap_utf8string(item ? item : ""));

    item = vparse_stringval(card, "photo");
    json_object_set_new(obj, "x-hasPhoto",
                        item ? json_true() : json_false());

    struct vparse_entry *photo = vparse_get_entry(card, NULL, "photo");
    struct message_guid guid;
    char *type = NULL;
    json_t *file = NULL;
    size_t size;

    if (photo &&
        (size = vcard_prop_decode_value(photo, NULL, &type, &guid))) {
        struct buf blobid = BUF_INITIALIZER;
        if (jmap_encode_rawdata_blobid('V', mailbox_uniqueid(mailbox), record->uid,
                                       NULL, NULL, "PHOTO", &guid, &blobid)) {
            file = json_pack("{s:s s:i s:s s:n}",
                             "blobId", buf_cstring(&blobid), "size", size,
                             "type", type ? type : "application/octet-stream",
                             "name");
        }
        buf_free(&blobid);
    }
    if (!file) file = json_null();

    json_object_set_new(obj, "avatar", file);
    free(type);

    // record properties

    json_object_set_new(obj, "isFlagged",
                        record->system_flags & FLAG_FLAGGED ? json_true() :
                        json_false());

    const char *annot = DAV_ANNOT_NS "<" XML_NS_CYRUS ">importance";
    // NOTE: using buf_free here because annotatemore_msg_lookup uses
    // buf_init_ro on the buffer, which blats the base pointer.
    buf_free(&buf);
    annotatemore_msg_lookupmask(mailbox, record->uid, annot, userid, &buf);
    double val = 0;
    if (buf.len) val = strtod(buf_cstring(&buf), NULL);

    // need to keep the x- version while AJAXUI is around
    json_object_set_new(obj, "importance", json_real(val));

    /* XXX - other fields */

    buf_free(&buf);
    if (empty) strarray_free(empty);

    free_hash_table(&labels, NULL);
    free_hash_table(&abadr_by_group, free);

    return obj;
}

static int getcontacts_cb(void *rock, struct carddav_data *cdata)
{
    struct cards_rock *crock = (struct cards_rock *) rock;
    struct index_record record;
    json_t *obj = NULL;
    int r = 0;

    mbentry_t *mbentry = jmap_mbentry_from_dav(crock->req, &cdata->dav);

    if (!mbentry || !jmap_hasrights_mbentry(crock->req, mbentry, JACL_READITEMS)) {
        mboxlist_entry_free(&mbentry);
        return 0;
    }

    if (!crock->mailbox || strcmp(mailbox_name(crock->mailbox), mbentry->name)) {
        mailbox_close(&crock->mailbox);
        r = mailbox_open_irl(mbentry->name, &crock->mailbox);
    }
    if (r) goto done;

    r = mailbox_find_index_record(crock->mailbox, cdata->dav.imap_uid, &record);
    if (r) goto done;

    /* Load message containing the resource and parse vcard data */
    struct vparse_card *vcard = record_to_vcard(crock->mailbox, &record);
    if (!vcard || !vcard->objects) {
        syslog(LOG_ERR, "record_to_vcard failed for record %u:%s",
                cdata->dav.imap_uid, mailbox_name(crock->mailbox));
        vparse_free_card(vcard);
        r = IMAP_INTERNAL;
        goto done;
    }

    /* Convert the VCARD to a JMAP contact. */
    obj = jmap_contact_from_vcard(crock->req->userid, vcard->objects,
                                  crock->mailbox, &record);
    vparse_free_card(vcard);

    jmap_filterprops(obj, crock->get->props);

    if (jmap_wantprop(crock->get->props, "x-href")) {
        char *xhref = jmap_xhref(mbentry->name, cdata->dav.resource);
        json_object_set_new(obj, "x-href", json_string(xhref));
        free(xhref);
    }
    if (jmap_wantprop(crock->get->props, "blobId")) {
        json_t *jblobid = json_null();
        struct buf blobid = BUF_INITIALIZER;
        const char *uniqueid = NULL;

        /* Get uniqueid of calendar mailbox */
        if (!crock->mailbox || strcmp(mailbox_uniqueid(crock->mailbox), cdata->dav.mailbox)) {
            if (!crock->mbentry || strcmp(crock->mbentry->uniqueid, cdata->dav.mailbox)) {
                mboxlist_entry_free(&crock->mbentry);
                crock->mbentry = jmap_mbentry_from_dav(crock->req, &cdata->dav);
            }
            if (crock->mbentry &&
                jmap_hasrights_mbentry(crock->req, crock->mbentry, JACL_READITEMS)) {
                uniqueid = crock->mbentry->uniqueid;
            }
        }
        else {
            uniqueid = mailbox_uniqueid(crock->mailbox);
        }

        if (uniqueid &&
            jmap_encode_rawdata_blobid('V', uniqueid, record.uid,
                                       NULL, NULL, NULL, NULL, &blobid)) {
            jblobid = json_string(buf_cstring(&blobid));
        }
        buf_free(&blobid);
        json_object_set_new(obj, "blobId", jblobid);
    }
    if (jmap_wantprop(crock->get->props, "size")) {
        json_object_set_new(obj, "size",
                            json_integer(record.size - record.header_size));
    }

    json_object_set_new(obj, "id", json_string(cdata->vcard_uid));
    json_object_set_new(obj, "uid", json_string(cdata->vcard_uid));

    json_object_set_new(obj, "addressbookId",
                        json_string(strrchr(mbentry->name, '.')+1));

    json_array_append_new(crock->get->list, obj);
    crock->rows++;

 done:
    mboxlist_entry_free(&mbentry);

    return 0;
}

static int jmap_contact_get(struct jmap_req *req)
{
    return _contacts_get(req, &getcontacts_cb, CARDDAV_KIND_CONTACT, contact_props);
}

static int jmap_contact_changes(struct jmap_req *req)
{
    return _contacts_changes(req, CARDDAV_KIND_CONTACT);
}

struct contact_textfilter {
    strarray_t terms;
    bitvector_t matched_terms;
    strarray_t phrases;
    bitvector_t matched_phrases;
    int is_any;
};

static int contact_textfilter_add_to_termset(const char *term, void *termset)
{
    hash_insert(term, (void*)1, (hash_table*)termset);
    return 0;
}

static int contact_textfilter_add_to_strarray(const char *term, void *sa)
{
    strarray_append((strarray_t*)sa, term);
    return 0;
}

static struct contact_textfilter *contact_textfilter_new(const char *query)
{
    struct contact_textfilter *f = xzmalloc(sizeof(struct contact_textfilter));
    struct buf buf = BUF_INITIALIZER;
    const char *p, *q;
    int in_phrase = 0;
    xapian_doc_t *doc = xapian_doc_new();

    /* Parse query string into loose terms and phrases */
    for (p = query, q = query; *p; p++) {
        if (in_phrase) {
            if (*p == '\'' || *(p+1) == '\0') {
                // end of phrase
                if (*p != '\'') {
                    buf_putc(&buf, *p);
                }
                if (buf_len(&buf)) {
                    strarray_append(&f->phrases, buf_cstring(&buf));
                    buf_reset(&buf);
                }
                in_phrase = 0;
            }
            else if (*p == '\\') {
                // escape character within phrase
                switch (*(p+1)) {
                    case '"':
                    case '\'':
                    case '\\':
                        buf_putc(&buf, *(p+1));
                        p++;
                        break;
                    default:
                        buf_putc(&buf, *p);
                }
            }
            else buf_putc(&buf, *p);
        }
        else {
            if (*p == '\'' || *(p+1) == '\0') {
                // end of loose terms
                if (q) {
                    const char *end = *p == '\'' ? p : p + 1;
                    xapian_doc_index_text(doc, q, end - q);
                }
                if (*p == '\'') {
                    //start of phrase
                    in_phrase = 1;
                }
                q = NULL;
            }
            else if (!q) {
                // start of loose terms
                q = p;
            }
        }
    }

    /* Add loose terms to matcher */
    xapian_doc_foreach_term(doc, contact_textfilter_add_to_strarray, &f->terms);

    /* Initialize state */
    bv_init(&f->matched_phrases);
    bv_init(&f->matched_terms);
    bv_setsize(&f->matched_phrases, (unsigned) strarray_size(&f->phrases));
    bv_setsize(&f->matched_terms, (unsigned) strarray_size(&f->terms));

    xapian_doc_close(doc);
    buf_free(&buf);
    return f;
}

static int contact_textfilter_match(struct contact_textfilter *f, const char *text, hash_table *termset)
{
    int matches = 0;

    if (!f->is_any) {
        bv_clearall(&f->matched_phrases);
        bv_clearall(&f->matched_terms);
    }

    /* Validate phrase search */
    int i;
    for (i = 0; i < strarray_size(&f->phrases); i++) {
        const char *phrase = strarray_nth(&f->phrases, i);
        if (stristr(text, phrase)) {
            bv_set(&f->matched_phrases, i);
            if (f->is_any) {
                matches = 1;
                goto done;
            }
        }
        else if (!f->is_any) goto done;
    }

    /* Validate loose term search */
    if (!termset->size) {
        /* Extract terms from text and store result in termset */
        xapian_doc_t *doc = xapian_doc_new();
        xapian_doc_index_text(doc, text, strlen(text));
        if (!xapian_doc_termcount(doc)) {
            xapian_doc_close(doc);
            goto done;
        }
        construct_hash_table(termset, xapian_doc_termcount(doc), 0);
        xapian_doc_foreach_term(doc, contact_textfilter_add_to_termset, termset);
        xapian_doc_close(doc);
    }
    for (i = 0; i < strarray_size(&f->terms); i++) {
        const char *term = strarray_nth(&f->terms, i);
        if (hash_lookup(term, termset)) {
            bv_set(&f->matched_terms, i);
            if (f->is_any) {
                matches = 1;
                goto done;
            }
        }
        else if (!f->is_any) goto done;
    }

    /* All loose terms and phrases matched */
    matches = 1;

done:
    return matches;
}

static void contact_textfilter_reset(struct contact_textfilter *f)
{
    bv_clearall(&f->matched_phrases);
    bv_clearall(&f->matched_terms);
}


static void contact_textfilter_free(struct contact_textfilter *f)
{
    if (f) {
        strarray_fini(&f->terms);
        bv_fini(&f->matched_terms);
        strarray_fini(&f->phrases);
        bv_fini(&f->matched_phrases);
        free(f);
    }
}

static int contact_textfilter_matched_all(struct contact_textfilter *f)
{
    return bv_count(&f->matched_terms) == (unsigned) strarray_size(&f->terms) &&
           bv_count(&f->matched_phrases) == (unsigned) strarray_size(&f->phrases);
}

struct named_termset {
    const char *propname;
    hash_table termset;
};

struct contactsquery_filter_rock {
    struct carddav_db *carddavdb;
    struct carddav_data *cdata;
    json_t *entry;
    ptrarray_t cached_termsets; // list of named_termset
};

struct contact_filter {
    hash_table *inContactGroup;
    json_t *isFlagged;
    const char *uid;
    struct contact_textfilter *prefix;
    struct contact_textfilter *firstName;
    struct contact_textfilter *lastName;
    struct contact_textfilter *suffix;
    struct contact_textfilter *nickname;
    struct contact_textfilter *company;
    struct contact_textfilter *department;
    struct contact_textfilter *jobTitle;
    struct contact_textfilter *email;
    struct contact_textfilter *phone;
    struct contact_textfilter *online;
    struct contact_textfilter *address;
    struct contact_textfilter *notes;
    struct contact_textfilter *text;
};

static int contact_filter_match_textval(const char *val,
                                        struct contact_textfilter *propfilter,
                                        struct contact_textfilter *textfilter,
                                        hash_table *termset)
{
    if (propfilter) {
        /* Fail early if propfilter does not match */
        if (val && !contact_textfilter_match(propfilter, val, termset)) {
            return 0;
        }
    }
    if (textfilter) {
        /* Don't care if textfilter matches */
        if (val && !contact_textfilter_matched_all(textfilter)) {
            contact_textfilter_match(textfilter, val, termset);
        }
    }

    return 1;
}

static hash_table *getorset_termset(ptrarray_t *cached_termsets, const char *propname)
{
    int i;
    for (i = 0; i < ptrarray_size(cached_termsets); i++) {
        struct named_termset *nts = ptrarray_nth(cached_termsets, i);
        if (!strcmp(nts->propname, propname)) return &nts->termset;
    }
    struct named_termset *nts = xzmalloc(sizeof(struct named_termset));
    nts->propname = propname;
    ptrarray_append(cached_termsets, nts);
    return &nts->termset;
}

static int contact_filter_match_textprop(json_t *jentry, const char *propname,
                                         struct contact_textfilter *propfilter,
                                         struct contact_textfilter *textfilter,
                                         ptrarray_t *cached_termsets)
{

    /* Skip matching if possible */
    if (!propfilter && (!textfilter || contact_textfilter_matched_all(textfilter)))
        return 1;

    /* Evaluate search on text value */
    hash_table *termset = getorset_termset(cached_termsets, propname);
    const char *val = json_string_value(json_object_get(jentry, propname));
    return contact_filter_match_textval(val, propfilter, textfilter, termset);
}

static int contact_filter_match_contactinfo(json_t *jentry, const char *propname,
                                            struct contact_textfilter *propfilter,
                                            struct contact_textfilter *textfilter,
                                            ptrarray_t *cached_termsets)
{
    /* Skip matching if possible */
    if (!propfilter && (!textfilter || contact_textfilter_matched_all(textfilter)))
        return 1;

    /* Combine values into text buffer */
    json_t *jlist = json_object_get(jentry, propname);
    struct buf buf = BUF_INITIALIZER;
    json_t *jinfo;
    size_t i;
    json_array_foreach(jlist, i, jinfo) {
        const char *val = json_string_value(json_object_get(jinfo, "value"));
        if (!val) continue;
        if (i) buf_putc(&buf, ' ');
        buf_appendcstr(&buf, val);
    }
    if (propfilter && !buf_len(&buf))
        return 0;

    /* Evaluate search on text buffer */
    hash_table *termset = getorset_termset(cached_termsets, propname);
    int ret = contact_filter_match_textval(buf_cstring(&buf), propfilter, textfilter, termset);
    buf_free(&buf);
    return ret;
}

static int contact_filter_match_addresses(json_t *jentry, const char *propname,
                                          struct contact_textfilter *propfilter,
                                          struct contact_textfilter *textfilter,
                                          ptrarray_t *cached_termsets)
{
    /* Skip matching if possible */
    if (!propfilter && (!textfilter || contact_textfilter_matched_all(textfilter)))
        return 1;

    /* Combine values into text buffer */
    json_t *jlist = json_object_get(jentry, propname);
    struct buf buf = BUF_INITIALIZER;
    json_t *jaddr;
    size_t i;
    json_array_foreach(jlist, i, jaddr) {
        const char *val;
        if ((val = json_string_value(json_object_get(jaddr, "street")))) {
            buf_putc(&buf, ' ');
            buf_appendcstr(&buf, val);
        }
        if ((val = json_string_value(json_object_get(jaddr, "locality")))) {
            buf_putc(&buf, ' ');
            buf_appendcstr(&buf, val);
        }
        if ((val = json_string_value(json_object_get(jaddr, "region")))) {
            buf_putc(&buf, ' ');
            buf_appendcstr(&buf, val);
        }
        if ((val = json_string_value(json_object_get(jaddr, "postcode")))) {
            buf_putc(&buf, ' ');
            buf_appendcstr(&buf, val);
        }
        if ((val = json_string_value(json_object_get(jaddr, "country")))) {
            buf_putc(&buf, ' ');
            buf_appendcstr(&buf, val);
        }
    }
    if (propfilter && !buf_len(&buf))
        return 0;

    /* Evaluate search on text buffer */
    hash_table *termset = getorset_termset(cached_termsets, propname);
    int ret = contact_filter_match_textval(buf_cstring(&buf), propfilter, textfilter, termset);
    buf_free(&buf);
    return ret;
}

/* Match the contact in rock against filter. */
static int contact_filter_match(void *vf, void *rock)
{
    struct contact_filter *f = (struct contact_filter *) vf;
    struct contactsquery_filter_rock *cfrock = (struct contactsquery_filter_rock*) rock;
    json_t *contact = cfrock->entry;
    struct carddav_data *cdata = cfrock->cdata;
    struct carddav_db *db = cfrock->carddavdb;

    /* uid */
    if (f->uid && strcmpsafe(cdata->vcard_uid, f->uid)) {
        return 0;
    }

    /* isFlagged */
    if (JNOTNULL(f->isFlagged)) {
        json_t *isFlagged = json_object_get(contact, "isFlagged");
        if (f->isFlagged != isFlagged) {
            return 0;
        }
    }

    /* Match text filters */
    if (f->text) contact_textfilter_reset(f->text);
    if (!contact_filter_match_textprop(contact, "prefix", f->prefix, f->text, &cfrock->cached_termsets) ||
        !contact_filter_match_textprop(contact, "firstName", f->firstName, f->text, &cfrock->cached_termsets) ||
        !contact_filter_match_textprop(contact, "lastName", f->lastName, f->text, &cfrock->cached_termsets) ||
        !contact_filter_match_textprop(contact, "suffix", f->suffix, f->text, &cfrock->cached_termsets) ||
        !contact_filter_match_textprop(contact, "nickname", f->nickname, f->text, &cfrock->cached_termsets) ||
        !contact_filter_match_textprop(contact, "company", f->company, f->text, &cfrock->cached_termsets) ||
        !contact_filter_match_textprop(contact, "department", f->department, f->text, &cfrock->cached_termsets) ||
        !contact_filter_match_textprop(contact, "jobTitle", f->jobTitle, f->text, &cfrock->cached_termsets) ||
        !contact_filter_match_textprop(contact, "notes", f->notes, f->text, &cfrock->cached_termsets) ||
        !contact_filter_match_contactinfo(contact, "emails", f->email, f->text, &cfrock->cached_termsets) ||
        !contact_filter_match_contactinfo(contact, "phones", f->phone, f->text, &cfrock->cached_termsets) ||
        !contact_filter_match_contactinfo(contact, "online", f->online, f->text, &cfrock->cached_termsets) ||
        !contact_filter_match_addresses(contact, "addresses", f->address, f->text, &cfrock->cached_termsets)) {
        return 0;
    }

    if (f->text && !contact_textfilter_matched_all(f->text)) return 0;

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
    struct contact_filter *f = (struct contact_filter*) vf;
    if (f->inContactGroup) {
        free_hash_table(f->inContactGroup, NULL);
        free(f->inContactGroup);
    }
    contact_textfilter_free(f->prefix);
    contact_textfilter_free(f->firstName);
    contact_textfilter_free(f->lastName);
    contact_textfilter_free(f->suffix);
    contact_textfilter_free(f->nickname);
    contact_textfilter_free(f->company);
    contact_textfilter_free(f->department);
    contact_textfilter_free(f->jobTitle);
    contact_textfilter_free(f->email);
    contact_textfilter_free(f->phone);
    contact_textfilter_free(f->online);
    contact_textfilter_free(f->address);
    contact_textfilter_free(f->notes);
    contact_textfilter_free(f->text);
    free(f);
}

/* Parse the JMAP Contact FilterCondition in arg.
 * Report any invalid properties in invalid, prefixed by prefix.
 * Return NULL on error. */
static void *contact_filter_parse(json_t *arg)
{
    struct contact_filter *f =
        (struct contact_filter *) xzmalloc(sizeof(struct contact_filter));

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

    /* prefix */
    if (JNOTNULL(json_object_get(arg, "prefix"))) {
        const char *s = NULL;
        if (jmap_readprop(arg, "prefix", 0, NULL, "s", &s) > 0) {
            f->prefix = contact_textfilter_new(s);
        }
    }
    /* firstName */
    if (JNOTNULL(json_object_get(arg, "firstName"))) {
        const char *s = NULL;
        if (jmap_readprop(arg, "firstName", 0, NULL, "s", &s) > 0) {
            f->firstName = contact_textfilter_new(s);
        }
    }
    /* lastName */
    if (JNOTNULL(json_object_get(arg, "lastName"))) {
        const char *s = NULL;
        if (jmap_readprop(arg, "lastName", 0, NULL, "s", &s) > 0) {
            f->lastName = contact_textfilter_new(s);
        }
    }
    /* suffix */
    if (JNOTNULL(json_object_get(arg, "suffix"))) {
        const char *s = NULL;
        if (jmap_readprop(arg, "suffix", 0, NULL, "s", &s) > 0) {
            f->suffix = contact_textfilter_new(s);
        }
    }
    /* nickname */
    if (JNOTNULL(json_object_get(arg, "nickname"))) {
        const char *s = NULL;
        if (jmap_readprop(arg, "nickname", 0, NULL, "s", &s) > 0) {
            f->nickname = contact_textfilter_new(s);
        }
    }
    /* company */
    if (JNOTNULL(json_object_get(arg, "company"))) {
        const char *s = NULL;
        if (jmap_readprop(arg, "company", 0, NULL, "s", &s) > 0) {
            f->company = contact_textfilter_new(s);
        }
    }
    /* department */
    if (JNOTNULL(json_object_get(arg, "department"))) {
        const char *s = NULL;
        if (jmap_readprop(arg, "department", 0, NULL, "s", &s) > 0) {
            f->department = contact_textfilter_new(s);
        }
    }
    /* jobTitle */
    if (JNOTNULL(json_object_get(arg, "jobTitle"))) {
        const char *s = NULL;
        if (jmap_readprop(arg, "jobTitle", 0, NULL, "s", &s) > 0) {
            f->jobTitle = contact_textfilter_new(s);
        }
    }
    /* email */
    if (JNOTNULL(json_object_get(arg, "email"))) {
        const char *s = NULL;
        if (jmap_readprop(arg, "email", 0, NULL, "s", &s) > 0) {
            f->email = contact_textfilter_new(s);
        }
    }
    /* phone */
    if (JNOTNULL(json_object_get(arg, "phone"))) {
        const char *s = NULL;
        if (jmap_readprop(arg, "phone", 0, NULL, "s", &s) > 0) {
            f->phone = contact_textfilter_new(s);
        }
    }
    /* online */
    if (JNOTNULL(json_object_get(arg, "online"))) {
        const char *s = NULL;
        if (jmap_readprop(arg, "online", 0, NULL, "s", &s) > 0) {
            f->online = contact_textfilter_new(s);
        }
    }
    /* address */
    if (JNOTNULL(json_object_get(arg, "address"))) {
        const char *s = NULL;
        if (jmap_readprop(arg, "address", 0, NULL, "s", &s) > 0) {
            f->address = contact_textfilter_new(s);
        }
    }
    /* notes */
    if (JNOTNULL(json_object_get(arg, "notes"))) {
        const char *s = NULL;
        if (jmap_readprop(arg, "notes", 0, NULL, "s", &s) > 0) {
            f->notes = contact_textfilter_new(s);
        }
    }
    /* text */
    if (JNOTNULL(json_object_get(arg, "text"))) {
        const char *s = NULL;
        if (jmap_readprop(arg, "text", 0, NULL, "s", &s) > 0) {
            f->text = contact_textfilter_new(s);
        }
    }
    /* uid */
    if (JNOTNULL(json_object_get(arg, "uid"))) {
        jmap_readprop(arg, "uid", 0, NULL, "s", &f->uid);
    }

    return f;
}

static void contact_filter_validate(jmap_req_t *req __attribute__((unused)),
                                    struct jmap_parser *parser,
                                    json_t *filter,
                                    json_t *unsupported __attribute__((unused)),
                                    void *rock __attribute__((unused)),
                                    json_t **err __attribute__((unused)))
{
    const char *field;
    json_t *arg;

    json_object_foreach(filter, field, arg) {
        if (!strcmp(field, "inContactGroup")) {
            if (!json_is_array(arg)) {
                jmap_parser_invalid(parser, field);
            }
            else {
                jmap_parse_strings(arg, parser, field);
            }
        }
        else if (!strcmp(field, "isFlagged")) {
            if (!json_is_boolean(arg)) {
                jmap_parser_invalid(parser, field);
            }
        }
        else if (!strcmp(field, "text") ||
                 !strcmp(field, "prefix") ||
                 !strcmp(field, "firstName") ||
                 !strcmp(field, "lastName") ||
                 !strcmp(field, "suffix") ||
                 !strcmp(field, "nickname") ||
                 !strcmp(field, "company") ||
                 !strcmp(field, "department") ||
                 !strcmp(field, "jobTitle") ||
                 !strcmp(field, "email") ||
                 !strcmp(field, "phone") ||
                 !strcmp(field, "online") ||
                 !strcmp(field, "address") ||
                 !strcmp(field, "uid") ||
                 !strcmp(field, "notes")) {
            if (!json_is_string(arg)) {
                jmap_parser_invalid(parser, field);
            }
        }
        else {
            jmap_parser_invalid(parser, field);
        }
    }
}

static int contact_comparator_validate(jmap_req_t *req __attribute__((unused)),
                              struct jmap_comparator *comp,
                              void *rock __attribute__((unused)),
                              json_t **err __attribute__((unused)))
{
    /* Reject any collation */
    if (comp->collation) {
        return 0;
    }
    if (!strcmp(comp->property, "isFlagged") ||
        !strcmp(comp->property, "firstName") ||
        !strcmp(comp->property, "lastName") ||
        !strcmp(comp->property, "nickname") ||
        !strcmp(comp->property, "company") ||
        !strcmp(comp->property, "uid")) {
        return 1;
    }
    return 0;
}

struct contactgroup_filter {
    const char *uid;
    struct contact_textfilter *name;
    struct contact_textfilter *text;
};

/* Match the contact in rock against filter. */
static int contactgroup_filter_match(void *vf, void *rock)
{
    struct contactgroup_filter *f = (struct contactgroup_filter *) vf;
    struct contactsquery_filter_rock *cfrock = (struct contactsquery_filter_rock*) rock;
    struct carddav_data *cdata = cfrock->cdata;
    json_t *group = cfrock->entry;

    /* uid */
    if (f->uid && strcmpsafe(cdata->vcard_uid, f->uid)) {
        return 0;
    }
    /* Match text filters */
    if (f->text) {
        contact_textfilter_reset(f->text);
    }
    if (!contact_filter_match_textprop(group, "name", f->name, f->text, &cfrock->cached_termsets)) {
        return 0;
    }
    if (f->text && !contact_textfilter_matched_all(f->text)) {
        return 0;
    }

    /* All matched. */
    return 1;
}

/* Free the memory allocated by this contact filter. */
static void contactgroup_filter_free(void *vf)
{
    struct contactgroup_filter *f = vf;
    contact_textfilter_free(f->name);
    contact_textfilter_free(f->text);
    free(vf);
}

static void *contactgroup_filter_parse(json_t *arg)
{
    struct contactgroup_filter *f =
        (struct contactgroup_filter *) xzmalloc(sizeof(struct contactgroup_filter));

    /* uid */
    if (JNOTNULL(json_object_get(arg, "uid"))) {
        jmap_readprop(arg, "uid", 0, NULL, "s", &f->uid);
    }
    /* text */
    if (JNOTNULL(json_object_get(arg, "text"))) {
        const char *s = NULL;
        if (jmap_readprop(arg, "text", 0, NULL, "s", &s) > 0) {
            f->text = contact_textfilter_new(s);
        }
    }
    /* name */
    if (JNOTNULL(json_object_get(arg, "name"))) {
        const char *s = NULL;
        if (jmap_readprop(arg, "name", 0, NULL, "s", &s) > 0) {
            f->name = contact_textfilter_new(s);
        }
    }

    return f;
}

static void contactgroup_filter_validate(jmap_req_t *req __attribute__((unused)),
                                         struct jmap_parser *parser,
                                         json_t *filter,
                                         json_t *unsupported __attribute__((unused)),
                                         void *rock __attribute__((unused)),
                                         json_t **err __attribute__((unused)))
{
    const char *field;
    json_t *arg;

    json_object_foreach(filter, field, arg) {
        if (!strcmp(field, "uid") ||
            !strcmp(field, "text") ||
            !strcmp(field, "name")) {
            if (!json_is_string(arg)) {
                jmap_parser_invalid(parser, field);
            }
        }
        else {
            jmap_parser_invalid(parser, field);
        }
    }
}

static int contactgroup_comparator_validate(jmap_req_t *req __attribute__((unused)),
                              struct jmap_comparator *comp,
                              void *rock __attribute__((unused)),
                              json_t **err __attribute__((unused)))
{
    /* Reject any collation */
    if (comp->collation) {
        return 0;
    }
    if (!strcmp(comp->property, "uid")) {
        return 1;
    }
    return 0;
}

struct contactsquery_rock {
    jmap_req_t *req;
    struct jmap_query *query;
    jmap_filter *filter;

    struct mailbox *mailbox;
    struct carddav_db *carddavdb;
    unsigned kind;
    int build_response;
    ptrarray_t entries;
};

static int _contactsquery_cb(void *rock, struct carddav_data *cdata)
{
    struct contactsquery_rock *crock = (struct contactsquery_rock*) rock;
    struct index_record record;
    json_t *entry = NULL;
    int r = 0;

    if (!cdata->dav.alive || !cdata->dav.rowid || !cdata->dav.imap_uid) {
        return 0;
    }

    /* Ignore anything but the requested kind. */
    if (cdata->kind != crock->kind) {
        return 0;
    }

    mbentry_t *mbentry = jmap_mbentry_from_dav(crock->req, &cdata->dav);

    if (!mbentry || !jmap_hasrights_mbentry(crock->req, mbentry, JACL_READITEMS)) {
        mboxlist_entry_free(&mbentry);
        return 0;
    }

    /* Open mailbox. */
    if (!crock->mailbox || strcmp(mailbox_name(crock->mailbox), mbentry->name)) {
        mailbox_close(&crock->mailbox);
        r = mailbox_open_irl(mbentry->name, &crock->mailbox);
    }
    mboxlist_entry_free(&mbentry);
    if (r) return r;

    /* Load record. */
    r = mailbox_find_index_record(crock->mailbox, cdata->dav.imap_uid, &record);
    if (r) goto done;

    /* Load contact from record. */
    struct vparse_card *vcard = record_to_vcard(crock->mailbox, &record);
    if (!vcard || !vcard->objects) {
        syslog(LOG_ERR, "record_to_vcard failed for record %u:%s",
                cdata->dav.imap_uid, mailbox_name(crock->mailbox));
        vparse_free_card(vcard);
        r = IMAP_INTERNAL;
        goto done;
    }

    /* Convert the VCARD to a JMAP contact. */
    /* XXX If this conversion turns out to waste too many cycles, then first
     * initialize props with any non-NULL field in filter f or its subconditions.
     */
    entry = crock->kind == CARDDAV_KIND_GROUP ?
        jmap_group_from_vcard(vcard->objects) :
        jmap_contact_from_vcard(crock->req->userid, vcard->objects,
                                crock->mailbox, &record);
    vparse_free_card(vcard);

    if (crock->filter) {
        /* Match the contact against the filter */
        struct contactsquery_filter_rock cfrock = {
            crock->carddavdb, cdata, entry, PTRARRAY_INITIALIZER
        };
        /* Match filter */
        jmap_filtermatch_cb *matcher = crock->kind == CARDDAV_KIND_GROUP ?
            contactgroup_filter_match : contact_filter_match;
        int matches = jmap_filter_match(crock->filter, matcher, &cfrock);
        /* Free text search cached_termsets */
        int i;
        for (i = 0; i < ptrarray_size(&cfrock.cached_termsets); i++) {
            struct named_termset *nts = ptrarray_nth(&cfrock.cached_termsets, i);
            free_hash_table(&nts->termset, NULL);
            free(nts);
        }
        ptrarray_fini(&cfrock.cached_termsets);
        /* Skip non-matching entries */
        if (!matches) goto done;
    }

    /* Update statistics */
    crock->query->total++;

    if (crock->build_response) {
        struct jmap_query *query = crock->query;
        /* Apply windowing and build response ids */
        if (query->position > 0 && query->position > (ssize_t) query->total - 1) {
            goto done;
        }
        if (query->limit && json_array_size(query->ids) >= query->limit) {
            goto done;
        }
        if (!json_array_size(query->ids)) {
            query->result_position = query->total - 1;
        }
        json_array_append_new(query->ids, json_string(cdata->vcard_uid));
    }
    else {
        /* Keep matching entries for post-processing */
        json_object_set_new(entry, "id", json_string(cdata->vcard_uid));
        json_object_set_new(entry, "uid", json_string(cdata->vcard_uid));
        ptrarray_append(&crock->entries, entry);
        entry = NULL;
    }

done:
    if (entry) json_decref(entry);
    return r;
}

enum contactsquery_sort {
    CONTACTS_SORT_NONE = 0,
    CONTACTS_SORT_UID,
    /* Comparators for Contact */
    CONTACTS_SORT_ISFLAGGED,
    CONTACTS_SORT_FIRSTNAME,
    CONTACTS_SORT_LASTNAME,
    CONTACTS_SORT_NICKNAME,
    CONTACTS_SORT_COMPANY,
    /* Comparators for ContactGroup */
    CONTACTS_SORT_NAME,
    /* Flag for descencding sort */
    CONTACTS_SORT_DESC = 0x80,
};

static enum contactsquery_sort *contactsquery_buildsort(json_t *jsort)
{
    enum contactsquery_sort *sort =
        xzmalloc((json_array_size(jsort) + 1) * sizeof(enum contactsquery_sort));

    size_t i;
    json_t *jcomp;
    json_array_foreach(jsort, i, jcomp) {
        const char *prop = json_string_value(json_object_get(jcomp, "property"));
        if (!strcmp(prop, "uid"))
            sort[i] = CONTACTS_SORT_UID;
        /* Comparators for Contact */
        else if (!strcmp(prop, "isFlagged"))
            sort[i] = CONTACTS_SORT_ISFLAGGED;
        else if (!strcmp(prop, "firstName"))
            sort[i] = CONTACTS_SORT_FIRSTNAME;
        else if (!strcmp(prop, "lastName"))
            sort[i] = CONTACTS_SORT_LASTNAME;
        else if (!strcmp(prop, "nickname"))
            sort[i] = CONTACTS_SORT_NICKNAME;
        else if (!strcmp(prop, "company"))
            sort[i] = CONTACTS_SORT_COMPANY;
        /* Comparators for ContactGroup */
        else if (!strcmp(prop, "name"))
            sort[i] = CONTACTS_SORT_NAME;

        if (json_object_get(jcomp, "isAscending") == json_false())
            sort[i] |= CONTACTS_SORT_DESC;
    }

    return sort;
}

static int contactsquery_cmp QSORT_R_COMPAR_ARGS(const void *va,
                                                 const void *vb,
                                                 void *rock)
{
    enum contactsquery_sort *sort = rock;
    json_t *ja = (json_t*) *(void**)va;
    json_t *jb = (json_t*) *(void**)vb;

    enum contactsquery_sort *comp;
    for (comp = sort; *comp != CONTACTS_SORT_NONE; comp++) {
        int ret = 0;
        switch (*comp & ~CONTACTS_SORT_DESC) {
            case CONTACTS_SORT_UID:
                ret = strcmpsafe(json_string_value(json_object_get(ja, "uid")),
                                 json_string_value(json_object_get(jb, "uid")));
                break;
            case CONTACTS_SORT_FIRSTNAME:
                ret = strcmpsafe(json_string_value(json_object_get(ja, "firstName")),
                                 json_string_value(json_object_get(jb, "firstName")));
                break;
            case CONTACTS_SORT_LASTNAME:
                ret = strcmpsafe(json_string_value(json_object_get(ja, "lastName")),
                                 json_string_value(json_object_get(jb, "lastName")));
                break;
            case CONTACTS_SORT_NICKNAME:
                ret = strcmpsafe(json_string_value(json_object_get(ja, "nickname")),
                                 json_string_value(json_object_get(jb, "nickname")));
                break;
            case CONTACTS_SORT_COMPANY:
                ret = strcmpsafe(json_string_value(json_object_get(ja, "company")),
                                 json_string_value(json_object_get(jb, "company")));
                break;
            case CONTACTS_SORT_NAME:
                ret = strcmpsafe(json_string_value(json_object_get(ja, "name")),
                                 json_string_value(json_object_get(jb, "name")));
                break;
            case CONTACTS_SORT_ISFLAGGED:
                ret = json_boolean_value(json_object_get(ja, "isFlagged")) -
                      json_boolean_value(json_object_get(jb, "isFlagged"));
                break;
        }
        if (ret)
            return (*comp & CONTACTS_SORT_DESC) ? -ret : ret;
    }

    return 0;
}

static int _contactsquery(struct jmap_req *req, unsigned kind,
                          void *(*_filter_parse)(json_t *arg),
                          void (*_filter_free)(void *vf),
                          void (*_filter_validate)(jmap_req_t *req,
                                                   struct jmap_parser *parser,
                                                   json_t *filter,
                                                   json_t *unsupported,
                                                   void *rock,
                                                   json_t **err),
                          int (*_comparator_validate)(jmap_req_t *req,
                                                      struct jmap_comparator *comp,
                                                      void *rock,
                                                      json_t **err),
                          int (*_query_cb)(void *rock,
                                           struct carddav_data *cdata),
                          enum contactsquery_sort *(*_buildsort)(json_t *jsort),
                          int (*_sort_cmp) QSORT_R_COMPAR_ARGS(const void *va,
                                                               const void *vb,
                                                               void *rock))
{
    if (!has_addressbooks(req)) {
        jmap_error(req, json_pack("{s:s}", "type", "accountNoAddressbooks"));
        return 0;
    }

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
    jmap_query_parse(req, &parser, NULL, NULL,
                     _filter_validate, &kind,
                     _comparator_validate, NULL,
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

    /* Build filter */
    json_t *filter = json_object_get(req->args, "filter");
    const char *wantuid = NULL;
    if (JNOTNULL(filter)) {
        parsed_filter = jmap_buildfilter(filter, _filter_parse);
        wantuid = json_string_value(json_object_get(filter, "uid"));
    }

    /* Does this query have a complex sort? */
    int is_complexsort;
    if (json_array_size(query.sort) == 1) {
        json_t *jcomp = json_array_get(query.sort, 0);
        const char *prop = json_string_value(json_object_get(jcomp, "property"));
        is_complexsort = strcmpsafe("uid", prop);
    }
    else is_complexsort = json_array_size(query.sort) > 0;

    /* Inspect every entry in this accounts addressbook mailboxes. */
    struct contactsquery_rock rock = {
        req,
        &query,
        parsed_filter,
        NULL /*mailbox*/,
        db,
        kind,
        1 /*build_result*/,
        PTRARRAY_INITIALIZER
    };
    if (wantuid) {
        /* Fast-path single filter condition by UID */
        struct carddav_data *cdata = NULL;
        r = carddav_lookup_uid(db, wantuid, &cdata);
        if (!r) _query_cb(&rock, cdata);
        if (r == CYRUSDB_NOTFOUND) r = 0;
    }
    else if (!is_complexsort && query.position >= 0 && !query.anchor) {
        /* Fast-path simple query with carddav db */
        enum carddav_sort sort = CARD_SORT_UID; /* ignored if nsort == 0 */
        size_t nsort = 0;
        if (json_array_size(query.sort)) {
            json_t *jcomp = json_array_get(query.sort, 0);
            if (json_object_get(jcomp, "isAscending") == json_false()) {
                sort |= CARD_SORT_DESC;
            }
            nsort = 1;
        }
        r = carddav_foreach_sort(db, NULL, &sort, nsort, _query_cb, &rock);
    }
    else {
        /* Run carddav db query and apply custom sort */
        rock.build_response = 0;
        r = carddav_foreach(db, NULL, _query_cb, &rock);
        if (!r) {
            /* Sort entries */
            enum contactsquery_sort *sort = _buildsort(query.sort);
            cyr_qsort_r(rock.entries.data, rock.entries.count, sizeof(void*),
                        _sort_cmp, sort);
            free(sort);
            /* Build result ids */
            int i;
            for (i = 0; i < ptrarray_size(&rock.entries); i++) {
                json_t *entry = ptrarray_nth(&rock.entries, i);
                json_array_append(query.ids, json_object_get(entry, "uid"));
                json_decref(entry);
            }
            /* Determine start position of result window */
            size_t startpos = 0;
            if (query.anchor) {
                /* Look for anchor in result ids */
                size_t anchor_pos = 0;
                for ( ; anchor_pos < json_array_size(query.ids); anchor_pos++) {
                    json_t *jid = json_array_get(query.ids, anchor_pos);
                    if (!strcmpsafe(query.anchor, json_string_value(jid))) break;
                }
                /* Determine start of windowed result ids */
                if (anchor_pos < json_array_size(query.ids)) {
                    if (query.anchor_offset < 0) {
                        startpos = (size_t) -query.anchor_offset > anchor_pos ?
                            0 : anchor_pos + query.anchor_offset;
                    }
                    else {
                        startpos = anchor_pos + query.anchor_offset;
                    }
                }
                else err = json_pack("{s:s}", "type", "anchorNotFound");
            }
            else if (query.position < 0) {
                startpos = (size_t) -query.position > json_array_size(query.ids) ?
                    0 : json_array_size(query.ids) + query.position;
            }
            else startpos = query.position;
            /* Apply window to result list */
            if (startpos < json_array_size(query.ids)) {
                json_t *windowed_ids = json_array();
                size_t j;
                for (j = startpos; j < json_array_size(query.ids); j++) {
                    if (!query.limit || json_array_size(windowed_ids) < query.limit) {
                        json_array_append(windowed_ids, json_array_get(query.ids, j));
                    }
                    else break;
                }
                json_decref(query.ids);
                query.ids = windowed_ids;
                query.result_position = startpos;
            }
            else {
                json_decref(query.ids);
                query.ids = json_array();
            }
            ptrarray_fini(&rock.entries);
        }
    }
    /* Clean up callback state */
    if (rock.mailbox) mailbox_close(&rock.mailbox);
    /* Handle callback errors */
    if (r || err) {
        if (!err) err = jmap_server_error(r);
        jmap_error(req, err);
        goto done;
    }

    /* Build response */
    query.query_state = modseqtoa(jmap_modseq(req, MBTYPE_ADDRESSBOOK, 0));

    json_t *res = jmap_query_reply(&query);
    jmap_ok(req, res);

done:
    jmap_query_fini(&query);
    jmap_parser_fini(&parser);
    if (parsed_filter) {
        jmap_filter_free(parsed_filter, _filter_free);
    }
    if (db) carddav_close(db);
    return 0;
}

static int jmap_contact_query(struct jmap_req *req)
{
    return _contactsquery(req, CARDDAV_KIND_CONTACT,
                          &contact_filter_parse, &contact_filter_free,
                          &contact_filter_validate,
                          &contact_comparator_validate, &_contactsquery_cb,
                          &contactsquery_buildsort, &contactsquery_cmp);
}

static int jmap_contactgroup_query(struct jmap_req *req)
{
    return _contactsquery(req, CARDDAV_KIND_GROUP,
                          &contactgroup_filter_parse, &contactgroup_filter_free,
                          &contactgroup_filter_validate,
                          &contactgroup_comparator_validate, &_contactsquery_cb,
                          &contactsquery_buildsort, &contactsquery_cmp);
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

        jmap_readprop_full(item, prefix, "type", 1, invalid, "s", &type);
        if (type) {
            if (strcmp(type, "personal") && strcmp(type, "work") && strcmp(type, "other")) {
                char *tmp = strconcat(prefix, ".type", NULL);
                json_array_append_new(invalid, json_string(tmp));
                free(tmp);
            }
        }
        jmap_readprop_full(item, prefix, "value", 1, invalid, "s", &value);
        if (JNOTNULL(json_object_get(item, "label"))) {
            jmap_readprop_full(item, prefix, "label", 1, invalid, "s", &label);
        }
        json_t *jisDefault = json_object_get(item, "isDefault");

        /* Bail out for any property errors. */
        if (!type || !value || json_array_size(invalid)) {
            buf_free(&buf);
            return -1;
        }

        /* Update card. */
        const char *group = NULL;
        if (label) {
            /* Add Apple-style label using property grouping */
            buf_reset(&buf);
            buf_printf(&buf, "email%d", i);
            group = buf_cstring(&buf);

            vparse_add_entry(card, group, VCARD_APPLE_LABEL_PROPERTY, label);
        }

        struct vparse_entry *entry = vparse_add_entry(card, group, "EMAIL", value);

        if (!strcmpsafe(type, "personal"))
            type = "home";
        if (strcmpsafe(type, "other"))
            vparse_add_param(entry, "TYPE", type);

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

        jmap_readprop_full(item, prefix, "type", 1, invalid, "s", &type);
        if (type) {
            if (strcmp(type, "home") && strcmp(type, "work") && strcmp(type, "mobile") &&
                strcmp(type, "fax") && strcmp(type, "pager") && strcmp(type, "other")) {
                char *tmp = strconcat(prefix, ".type", NULL);
                json_array_append_new(invalid, json_string(tmp));
                free(tmp);
            }
        }
        jmap_readprop_full(item, prefix, "value", 1, invalid, "s", &value);
        if (JNOTNULL(json_object_get(item, "label"))) {
            jmap_readprop_full(item, prefix, "label", 1, invalid, "s", &label);
        }

        /* Bail out for any property errors. */
        if (!type || !value || json_array_size(invalid)) {
            buf_free(&buf);
            return -1;
        }

        /* Update card. */
        const char *group = NULL;
        if (label) {
            /* Add Apple-style label using property grouping */
            buf_reset(&buf);
            buf_printf(&buf, "tel%d", i);
            group = buf_cstring(&buf);

            vparse_add_entry(card, group, VCARD_APPLE_LABEL_PROPERTY, label);
        }

        struct vparse_entry *entry = vparse_add_entry(card, group, "TEL", value);

        if (!strcmp(type, "mobile"))
            vparse_add_param(entry, "TYPE", "CELL");
        else if (strcmp(type, "other"))
            vparse_add_param(entry, "TYPE", type);

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

        jmap_readprop_full(item, prefix, "type", 1, invalid, "s", &type);
        if (type) {
            if (strcmp(type, "uri") && strcmp(type, "username") && strcmp(type, "other")) {
                char *tmp = strconcat(prefix, ".type", NULL);
                json_array_append_new(invalid, json_string(tmp));
                free(tmp);
            }
        }
        jmap_readprop_full(item, prefix, "value", 1, invalid, "s", &value);
        if (JNOTNULL(json_object_get(item, "label"))) {
            jmap_readprop_full(item, prefix, "label", 1, invalid, "s", &label);
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
        const char *countrycode = NULL;
        int pe; /* parse error */

        /* Mandatory */
        pe = jmap_readprop_full(item, prefix, "type", 1, invalid, "s", &type);
        if (type) {
            if (strcmp(type, "home") && strcmp(type, "work") && strcmp(type, "billing") &&
                strcmp(type, "postal") && strcmp(type, "other")) {
                char *tmp = strconcat(prefix, ".type", NULL);
                json_array_append_new(invalid, json_string(tmp));
                free(tmp);
            }
        }
        pe = jmap_readprop_full(item, prefix, "street", 1, invalid, "s", &street);
        pe = jmap_readprop_full(item, prefix, "locality", 1, invalid, "s", &locality);
        pe = jmap_readprop_full(item, prefix, "region", 1, invalid, "s", &region);
        pe = jmap_readprop_full(item, prefix, "postcode", 1, invalid, "s", &postcode);
        pe = jmap_readprop_full(item, prefix, "country", 1, invalid, "s", &country);

        /* Optional */
        if (JNOTNULL(json_object_get(item, "label"))) {
            pe = jmap_readprop_full(item, prefix, "label", 0, invalid, "s", &label);
        }
        if (JNOTNULL(json_object_get(item, "countryCode"))) {
            pe = jmap_readprop_full(item, prefix, "countryCode", 0, invalid, "s", &countrycode);
        }

        /* Bail out for any property errors. */
        if (!type || !street || !locality ||
            !region || !postcode || !country || pe < 0) {
            buf_free(&buf);
            return -1;
        }

        /* Update card. */
        const char *group = NULL;
        if (label || countrycode) {
            /* Add Apple-style label using property grouping */
            buf_reset(&buf);
            buf_printf(&buf, "adr%d", i);
            group = buf_cstring(&buf);

            if (label)
                vparse_add_entry(card, group, VCARD_APPLE_LABEL_PROPERTY, label);
            if (countrycode) {
                struct buf lcode = BUF_INITIALIZER;
                buf_setcstr(&lcode, countrycode);
                buf_lcase(&lcode);
                vparse_add_entry(card, group, VCARD_APPLE_ABADR_PROPERTY, buf_cstring(&lcode));
                buf_free(&lcode);
            }
        }

        struct vparse_entry *entry = vparse_add_entry(card, group, "ADR", NULL);

        if (strcmpsafe(type, "other"))
            vparse_add_param(entry, "TYPE", type);

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
                         const char *key, json_t *file,
                         struct vparse_card *card, const char *prop,
                         ptrarray_t *blobs, jmap_contact_errors_t *errors)
{
    const char *blobid = NULL;
    const char *accountid = NULL;
    const char *accept_mime = NULL;
    char *encbuf = NULL;
    char *decbuf = NULL;
    json_t *jblobId;
    int r = 0;
    const char *base = NULL;
    size_t len = 0;
    struct buf buf = BUF_INITIALIZER;

    if (!file) {
        json_array_append_new(errors->invalid, json_string(key));
        return HTTP_BAD_REQUEST;
    }

    /* Extract blobId */
    jblobId = json_object_get(file, "blobId");
    if (!json_is_string(jblobId)) {
        buf_printf(&buf, "%s/blobId", key);
        json_array_append_new(errors->invalid, json_string(buf_cstring(&buf)));
        buf_free(&buf);
        return HTTP_BAD_REQUEST;
    }
    
    blobid = jmap_id_string_value(req, jblobId);

    accountid = json_string_value(json_object_get(file, "accountId"));
    accept_mime = json_string_value(json_object_get(file, "type"));

    /* Find blob */
    jmap_getblob_context_t ctx;
    jmap_getblob_ctx_init(&ctx, accountid, blobid, accept_mime, 1);
    r = jmap_getblob(req, &ctx);

    switch (r) {
    case 0:
        if (!buf_len(&ctx.content_type) ||
                strchr(buf_cstring(&ctx.content_type), '/')) break;

        /* Fall through */
        GCC_FALLTHROUGH

    case HTTP_NOT_ACCEPTABLE:
        buf_printf(&buf, "%s/type", key);
        json_array_append_new(errors->invalid, json_string(buf_cstring(&buf)));
        buf_free(&buf);
        r = HTTP_NOT_ACCEPTABLE;
        goto done;

    default:
        /* Not found, or system error */
        if (!errors->blobNotFound) errors->blobNotFound = json_array();
        json_array_append(errors->blobNotFound, jblobId);
        goto done;
    }

    /* (Re)write vCard property */
    vparse_delete_entries(card, NULL, prop);

    base = buf_base(&ctx.blob);
    len = buf_len(&ctx.blob);

    /* Pre-flight base64 encoder to determine length */
    size_t len64 = 0;
    charset_b64encode_mimebody(NULL, len, NULL, &len64, NULL, 0 /* no wrap */);

    /* Now create the property */
    char *version = vparse_get_value(vparse_get_entry(card, NULL, "VERSION"));
    if (!strcmpsafe("4.0", version)) {
        // Create version 4.0 data: URI property
        buf_setcstr(&buf, "data:");
        if (buf_len(&ctx.content_type)) {
            buf_append(&buf, &ctx.content_type);
        }
        buf_appendcstr(&buf, ";base64,");
        encbuf = xzmalloc(buf_len(&buf) + len64 + 1);
        memcpy(encbuf, buf_base(&buf), buf_len(&buf));
        charset_b64encode_mimebody(
            base, len, encbuf + buf_len(&buf), &len64, NULL, 0 /* no wrap */);
        vparse_add_entry(card, NULL, prop, encbuf);
    }
    else {
        // Create version 3.0 binary property
        encbuf = xzmalloc(len64 + 1);
        charset_b64encode_mimebody(
            base, len, encbuf, &len64, NULL, 0 /* no wrap */);

        struct vparse_entry *entry = vparse_add_entry(card, NULL, prop, encbuf);
        vparse_add_param(entry, "ENCODING", "b");

        if (buf_len(&ctx.content_type)) {
            char *subtype =
                xstrdupnull(strchr(buf_cstring(&ctx.content_type), '/'));
            vparse_add_param(entry, "TYPE", ucase(subtype + 1));
            free(subtype);
        }
    }
    xzfree(version);

    /* Add this blob to our list */
    property_blob_t *blob = property_blob_new(key, prop,
                                              buf_cstring(&ctx.content_type),
                                              &ctx.blob);
    ptrarray_append(blobs, blob);

  done:
    free(decbuf);
    free(encbuf);
    buf_free(&buf);
    jmap_getblob_ctx_fini(&ctx);

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

static int vcardprop_to_vcard(json_t *vprop, struct vparse_card *card, int reject_iana)
{
    // Validate that it's a sane jCard value.
    int is_valid = json_array_size(vprop) == 4 &&
                   json_is_string(json_array_get(vprop, 0)) &&
                   json_is_object(json_array_get(vprop, 1)) &&
                   json_is_string(json_array_get(vprop, 2)) &&
                   json_is_string(json_array_get(vprop, 3));

    if (!is_valid)
        return -1;


    // Check if this is a X-property or IANA name.
    if (reject_iana &&
        strncasecmp("X-", json_string_value(json_array_get(vprop, 0)), 2))
        return -1;

    // Validate parameter object.
    const char *group = NULL;
    const char *pname;
    json_t *pval;
    json_object_foreach(json_array_get(vprop, 1), pname, pval) {
        if (!json_is_string(pval)) {
            return -1;
        }
        if (!strcasecmp(pname, "group"))
            group = json_string_value(pval);
    }

    // Set vCard property.
    struct buf buf = BUF_INITIALIZER;

    buf_setcstr(&buf, json_string_value(json_array_get(vprop, 0)));
    buf_ucase(&buf);
    struct vparse_entry *entry =
        vparse_add_entry(card, group, buf_cstring(&buf),
                         json_string_value(json_array_get(vprop, 3)));

    json_object_foreach(json_array_get(vprop, 1), pname, pval) {
        if (strcasecmp(pname, "group")) {
            buf_setcstr(&buf, pname);
            buf_ucase(&buf);
            vparse_add_param(entry, buf_cstring(&buf), json_string_value(pval));
        }
    }

    buf_free(&buf);
    return 0;
}

static int _json_to_card(struct jmap_req *req,
                         struct carddav_data *cdata,
                         const char *mboxname,
                         struct vparse_card *card,
                         json_t *arg, strarray_t *flags,
                         struct entryattlist **annotsp,
                         ptrarray_t *blobs,
                         jmap_contact_errors_t *errors)
{
    json_t *invalid = errors->invalid;
    const char *key;
    json_t *jval;
    struct vparse_entry *n = vparse_get_entry(card, NULL, "N");
    int name_is_dirty = 0;
    int has_noncontent = 0;
    int record_is_dirty = 0;
    struct buf buf = BUF_INITIALIZER;

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
            if (!strcmp(key, "uid")) {
                if (strcmpnull(cdata->vcard_uid, json_string_value(jval))) {
                    json_array_append_new(invalid, json_string("uid"));
                }
                continue;
            }
            else if (!strcmp(key, "x-href")) {
                char *xhref = jmap_xhref(mboxname, cdata->dav.resource);
                if (strcmpnull(json_string_value(jval), xhref)) {
                    json_array_append_new(invalid, json_string("x-href"));
                }
                free(xhref);
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

        if (!strcmp(key, "uid")) {
            if (!json_is_string(jval)) {
                json_array_append_new(invalid, json_string("uid"));
            }
        }
        else if (!strcmp(key, "isFlagged")) {
            has_noncontent = 1;
            if (json_is_true(jval)) {
                strarray_add_case(flags, "\\Flagged");
            } else if (json_is_false(jval)) {
                strarray_remove_all_case(flags, "\\Flagged");
            } else {
                json_array_append_new(invalid, json_string("isFlagged"));
            }
        }
        else if (!strcmp(key, "importance")) {
            has_noncontent = 1;
            double dval = json_number_value(jval);
            const char *ns = DAV_ANNOT_NS "<" XML_NS_CYRUS ">importance";
            const char *attrib = mboxname_userownsmailbox(req->userid, mboxname) ?
                "value.shared" : "value.priv";
            struct buf buf = BUF_INITIALIZER;
            if (dval) {
                buf_printf(&buf, "%.17g", dval);
            }
            setentryatt(annotsp, ns, attrib, &buf);
            buf_free(&buf);
        }
        else if (!strcmp(key, "avatar")) {
            if (!json_is_null(jval)) {
                int r = _blob_to_card(req, key, jval, card, "PHOTO", blobs, errors);
                if (r) {
                    continue;
                }
                record_is_dirty = 1;
            }
            else if (vparse_get_entry(card, NULL, "PHOTO")) {
                vparse_delete_entries(card, NULL, "PHOTO");
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
        else if (!strcmp(key, "vCardProps")) {
            if (json_is_array(jval)) {
                size_t i;
                json_t *vprop;
                json_array_foreach(jval, i, vprop) {
                    if (vcardprop_to_vcard(vprop, card, /*reject_iana*/1) < 0) {
                        // Report erroneous jCard property.
                        buf_reset(&buf);
                        buf_printf(&buf, "%s/%zu", key, i);
                        json_array_append_new(invalid,
                                              json_string(buf_cstring(&buf)));
                    }
                }
            }
            else {
                json_array_append_new(invalid, json_string(key));
            }
        }
        else {
            json_array_append_new(invalid, json_string(key));
        }
    }

    if (json_array_size(invalid) || errors->blobNotFound) return 0;

    if (name_is_dirty) {
        _make_fn(card);
        record_is_dirty = 1;
    }

    if (!record_is_dirty && has_noncontent)
        return HTTP_NO_CONTENT;  /* no content */

    buf_free(&buf);
    return 0;
}

static int required_set_rights(json_t *props)
{
    int needrights = 0;
    const char *name;
    json_t *val;

    json_object_foreach(props, name, val) {
        const char *myname = name;

        if (!strcmp(myname, "id") ||
            !strcmp(myname, "x-href") ||
            !strcmp(myname, "x-hasPhoto") ||
            !strcmp(myname, "addressbookId")) {
            /* immutable */
        }
        else if (!strcmp(myname, "addressBookId") ||
                 (!strncmp(myname, "cyrusimap.org:", 14) && (myname += 14) &&
                  (!strcmp(myname, "href") ||
                   !strcmp(myname, "hasPhoto")))) {
            /* immutable */
        }
        else if (!strcmp(myname, "importance")) {
            /* writing shared meta-data (per RFC 5257) */
            needrights |= JACL_SETPROPERTIES;
        }
        else if (!strcmp(myname, "isFlagged")) {
            /* writing private meta-data */
            needrights |= JACL_SETKEYWORDS;
        }
        else {
            /* writing vCard data */
            needrights |= JACL_UPDATEITEMS;
        }
    }

    return needrights;
}

static int _contact_set_create(jmap_req_t *req, unsigned kind, json_t *jcard,
                               struct mailbox **mailbox, json_t *item,
                               jmap_contact_errors_t *errors)
{
    json_t *invalid = errors->invalid;
    struct entryattlist *annots = NULL;
    strarray_t *flags = NULL;
    struct vparse_card *card = NULL;
    char *uid = NULL;
    int r = 0;
    char *resourcename = NULL;
    struct buf buf = BUF_INITIALIZER;
    ptrarray_t blobs = PTRARRAY_INITIALIZER;
    property_blob_t *blob;
    char *mboxname = NULL;

    /* Validate uid */
    struct carddav_db *db = carddav_open_userid(req->accountid);
    if (!db) {
        xsyslog(LOG_ERR, "can not open carddav db", "accountid=<%s>",
                req->accountid);
        r = IMAP_INTERNAL;
    }
    if (!r) {
        struct carddav_data *mycdata = NULL;
        if ((uid = (char *) json_string_value(json_object_get(jcard, "uid")))) {
            /* Use custom vCard UID from request object */
            uid = xstrdup(uid);
            r = carddav_lookup_uid(db, uid, &mycdata);
            if (r == CYRUSDB_NOTFOUND) {
                r = 0;
            }
            else if (!r) {
                json_array_append_new(invalid, json_string("uid"));
            }
        }  else {
            /* Create a vCard UID */
            static int maxattempts = 3;
            int i;
            for (i = 0; i < maxattempts; i++) {
                free(uid);
                uid = xstrdup(makeuuid());
                r = carddav_lookup_uid(db, uid, &mycdata);
                if (r == CYRUSDB_NOTFOUND) {
                    json_object_set_new(item, "uid", json_string(uid));
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
    }
    carddav_close(db);
    if (r) goto done;

    /* Determine mailbox and resource name of card.
     * We attempt to reuse the UID as DAV resource name; but
     * only if it looks like a reasonable URL path segment. */
    const char *p;
    for (p = uid; *p; p++) {
        if ((*p >= '0' && *p <= '9') ||
            (*p >= 'a' && *p <= 'z') ||
            (*p >= 'A' && *p <= 'Z') ||
            (p > uid &&
                (*p == '@' || *p == '.' ||
                 *p == '_' || *p == '-'))) {
            continue;
        }
        break;
    }
    if (*p == '\0' && p - uid >= 16 && p - uid <= 200) {
        buf_setcstr(&buf, uid);
    } else {
        buf_setcstr(&buf, makeuuid());
    }
    buf_appendcstr(&buf, ".vcf");
    resourcename = buf_newcstring(&buf);

    const char *addressbookId = "Default";
    json_t *abookid = json_object_get(jcard, "addressbookId");
    if (abookid && json_string_value(abookid)) {
        /* XXX - invalid arguments */
        addressbookId = json_string_value(abookid);
    }
    else {
        json_object_set_new(item, "addressbookId", json_string(addressbookId));
    }
    mboxname = mboxname_abook(req->accountid, addressbookId);
    json_object_del(jcard, "addressbookId");
    addressbookId = NULL;

    int needrights = required_set_rights(jcard);

    /* Check permissions. */
    if (!jmap_hasrights(req, mboxname, needrights)) {
        json_array_append_new(invalid, json_string("addressbookId"));
        goto done;
    }

    card = vparse_new_card("VCARD");
    vparse_add_entry(card, NULL, "PRODID", _prodid);
    vparse_add_entry(card, NULL, "VERSION", "3.0");
    vparse_add_entry(card, NULL, "UID", uid);

    /* we need to create and append a record */
    if (!*mailbox || strcmp(mailbox_name(*mailbox), mboxname)) {
        mailbox_close(mailbox);
        r = mailbox_open_iwl(mboxname, mailbox);
        if (r == IMAP_MAILBOX_NONEXISTENT) {
            json_array_append_new(invalid, json_string("addressbookId"));
            r = 0;
            goto done;
        }
        else if (r) goto done;
    }

    const char *name = NULL;
    const char *logfmt = NULL;

    if (kind == CARDDAV_KIND_GROUP) {
        jmap_readprop(jcard, "name", 1, invalid, "s", &name);

        vparse_add_entry(card, NULL, "N", name);
        vparse_add_entry(card, NULL, "FN", name);
        vparse_add_entry(card, NULL, "X-ADDRESSBOOKSERVER-KIND", "group");

        /* it's legal to create an empty group */
        json_t *members = json_object_get(jcard, "contactIds");
        if (members) {
            _add_group_entries(req, card, members, invalid);
        }

        /* it's legal to create an empty group */
        json_t *others = json_object_get(jcard, "otherAccountContactIds");
        if (others) {
            _add_othergroup_entries(req, card, others, invalid);
        }

        logfmt = "jmap: create group %s/%s/%s (%s)";
    }
    else {
        flags = strarray_new();
        r = _json_to_card(req, NULL, mboxname, card,
                          jcard, flags, &annots, &blobs, errors);

        logfmt = "jmap: create contact %s/%s (%s)";
    }

    if (json_array_size(invalid) || errors->blobNotFound) {
        goto done;
    }

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
    /* format string chosen above */
    syslog(LOG_NOTICE, logfmt, req->accountid, mboxname, uid, name);
#pragma GCC diagnostic pop

    r = carddav_store(*mailbox, card, resourcename, 0, flags, &annots,
                      req->userid, req->authstate, ignorequota, /*oldsize*/ 0);
    if (r && r != HTTP_CREATED && r != HTTP_NO_CONTENT) {
        syslog(LOG_ERR, "carddav_store failed for user %s: %s",
               req->userid, error_message(r));
        goto done;
    }
    r = 0;

    json_object_set_new(item, "id", json_string(uid));

    struct index_record record;
    mailbox_find_index_record(*mailbox, (*mailbox)->i.last_uid, &record);

    jmap_encode_rawdata_blobid('V', mailbox_uniqueid(*mailbox), record.uid,
                               NULL, NULL, NULL, NULL, &buf);
    json_object_set_new(item, "blobId", json_string(buf_cstring(&buf)));

    json_object_set_new(item, "size",
                        json_integer(record.size - record.header_size));

    while ((blob = ptrarray_pop(&blobs))) {
        jmap_encode_rawdata_blobid('V', mailbox_uniqueid(*mailbox), record.uid,
                                   NULL, NULL, blob->prop, &blob->guid, &buf);
        json_object_set_new(item, blob->key,
                            json_pack("{s:s s:i s:s? s:n}",
                                      "blobId", buf_cstring(&buf),
                                      "size", blob->size,
                                      "type", blob->type, "name"));
        property_blob_free(&blob);
    }

done:
    vparse_free_card(card);
    free(mboxname);
    free(resourcename);
    strarray_free(flags);
    freeentryatts(annots);
    free(uid);
    buf_free(&buf);
    while ((blob = ptrarray_pop(&blobs))) {
        property_blob_free(&blob);
    }
    ptrarray_fini(&blobs);

    return r;
}

static int _contact_set_update(jmap_req_t *req, unsigned kind,
                               const char *uid, json_t *jcard,
                               struct carddav_db *db, struct mailbox **mailbox,
                               json_t **item, jmap_contact_errors_t *errors)
{
    json_t *invalid = errors->invalid;
    struct mailbox *newmailbox = NULL;
    struct carddav_data *cdata = NULL;
    struct buf buf = BUF_INITIALIZER;
    mbentry_t *mbentry = NULL;
    uint32_t olduid;
    char *resource = NULL;
    int do_move = 0;
    json_t *jupdated = NULL;
    struct vparse_card *vcard = NULL;
    struct entryattlist *annots = NULL;
    strarray_t *flags = NULL;
    ptrarray_t blobs = PTRARRAY_INITIALIZER;
    property_blob_t *blob;
    int r;

    /* is it a valid contact? */
    r = carddav_lookup_uid(db, uid, &cdata);
    if (r || !cdata || !cdata->dav.imap_uid || cdata->kind != kind) {
        r = HTTP_NOT_FOUND;
        goto done;
    }

    mbentry = jmap_mbentry_from_dav(req, &cdata->dav);

    json_t *abookid = json_object_get(jcard, "addressbookId");
    if (abookid && json_string_value(abookid)) {
        char *mboxname = mboxname_abook(req->accountid, json_string_value(abookid));

        if (mbentry && strcmp(mboxname, mbentry->name)) {
            /* move */
            if (!jmap_hasrights(req, mboxname, JACL_ADDITEMS)) {
                json_array_append_new(invalid, json_string("addressbookId"));
                r = HTTP_FORBIDDEN;
            }
            else if ((r = mailbox_open_iwl(mboxname, &newmailbox))) {
                syslog(LOG_ERR, "IOERROR: failed to open %s", mboxname);
            }
            else {
                do_move = 1;
            }
        }
        json_object_del(jcard, "addressbookId");
        free(mboxname);

        if (r) goto done;
    }

    int needrights = do_move ? JACL_UPDATEITEMS : required_set_rights(jcard);

    if (!mbentry || !jmap_hasrights_mbentry(req, mbentry, needrights)) {
        int rights = mbentry ? jmap_myrights_mbentry(req, mbentry) : 0;
        r = (rights & JACL_READITEMS) ? HTTP_NOT_ALLOWED : HTTP_NOT_FOUND;
        goto done;
    }

    if (!*mailbox || strcmp(mailbox_name(*mailbox), mbentry->name)) {
        mailbox_close(mailbox);
        r = mailbox_open_iwl(mbentry->name, mailbox);
    }
    if (r) {
        syslog(LOG_ERR, "IOERROR: failed to open %s",
               mbentry->name);
        goto done;
    }

    struct index_record record;

    r = mailbox_find_index_record(*mailbox, cdata->dav.imap_uid, &record);
    if (r) goto done;

    olduid = cdata->dav.imap_uid;
    resource = xstrdup(cdata->dav.resource);

    /* Load message containing the resource and parse vcard data */
    vcard = record_to_vcard(*mailbox, &record);
    if (!vcard || !vcard->objects) {
        syslog(LOG_ERR, "record_to_vcard failed for record %u:%s",
               cdata->dav.imap_uid, mailbox_name(*mailbox));
        r = HTTP_UNPROCESSABLE;
        goto done;
    }

    struct vparse_card *card = vcard->objects;
    if (!vparse_get_entry(card, NULL, "VERSION"))
        vparse_replace_entry(card, NULL, "VERSION", "3.0");
    vparse_replace_entry(card, NULL, "PRODID", _prodid);

    *item = json_object();

    if (kind == CARDDAV_KIND_GROUP) {
        json_t *namep = NULL;
        json_t *members = NULL;
        json_t *others = NULL;
        json_t *jval;
        const char *key;

        json_object_foreach(jcard, key, jval) {
            if (!strcmp(key, "name")) {
                if (json_is_string(jval))
                    namep = jval;
                else json_array_append_new(invalid, json_string("name"));
            }
            else if (!strcmp(key, "contactIds")) {
                members = jval;
            }
            else if (!strcmp(key, "otherAccountContactIds")) {
                others = jval;
            }
            else if (!strncmp(key, "otherAccountContactIds/", 23)) {
                /* Read and apply patch to current card */
                json_t *jcurrent = jmap_group_from_vcard(card);
                if (!jcurrent) {
                    syslog(LOG_ERR, "can't read vcard %u:%s for update",
                           cdata->dav.imap_uid, mailbox_name(*mailbox));
                    r = HTTP_UNPROCESSABLE;
                    goto done;
                }
                jupdated = jmap_patchobject_apply(jcurrent, jcard, NULL, 0);
                json_decref(jcurrent);
                if (JNOTNULL(jupdated)) {
                    json_object_del(jupdated, "addressbookId");
                    /* Now read the updated property value */
                    others = json_object_get(jupdated, "otherAccountContactIds");
                }
            }
            else if (!strcmp(key, "id") || !strcmp(key, "uid")) {
                if (cdata && strcmpnull(cdata->vcard_uid, json_string_value(jval))) {
                    json_array_append_new(invalid, json_string(key));
                }
            }
        }

        if (namep) {
            const char *name = json_string_value(namep);
            if (name) {
                vparse_replace_entry(card, NULL, "FN", name);
                vparse_replace_entry(card, NULL, "N", name);
            }
        }
        else if (!vparse_get_entry(card, NULL, "N")) {
            struct vparse_entry *entry = vparse_get_entry(card, NULL, "FN");
            if (entry) vparse_replace_entry(card, NULL, "N", entry->v.value);
        }
        if (members) {
            _add_group_entries(req, card, members, invalid);
        }
        if (others) {
            _add_othergroup_entries(req, card, others, invalid);
        }
    }
    else {
        flags = mailbox_extract_flags(*mailbox, &record, req->userid);
        annots = mailbox_extract_annots(*mailbox, &record);

        r = _json_to_card(req, cdata, mailbox_name(*mailbox), card, jcard, flags,
                          &annots, &blobs, errors);
        if (r == HTTP_NO_CONTENT) {
            r = 0;
            if (!newmailbox) {
                /* just bump the modseq
                   if in the same mailbox and no data change */
                syslog(LOG_NOTICE, "jmap: touch contact %s/%s",
                       req->accountid, resource);
                if (strarray_contains_case(flags, "\\Flagged"))
                    record.system_flags |= FLAG_FLAGGED;
                else
                    record.system_flags &= ~FLAG_FLAGGED;
                annotate_state_t *state = NULL;
                r = mailbox_get_annotate_state(*mailbox, record.uid, &state);
                annotate_state_set_auth(state, 0,
                                        req->userid, req->authstate);
                if (!r) r = annotate_state_store(state, annots);
                if (!r) r = mailbox_rewrite_index_record(*mailbox, &record);
                if (!r) {
                    json_decref(*item);
                    *item = json_null();
                }
                goto done;
            }
        }
    }

    if (!json_array_size(invalid) && !errors->blobNotFound) {
        struct mailbox *this_mailbox = newmailbox ? newmailbox : *mailbox;

        syslog(LOG_NOTICE, "jmap: update %s %s/%s",
               kind == CARDDAV_KIND_GROUP ? "group" : "contact",
               req->accountid, resource);
        r = carddav_store(this_mailbox, card, resource,
                          record.createdmodseq, flags, &annots, req->userid,
                          req->authstate, ignorequota,
                          (record.size - record.header_size));
        if (!r) {
            struct index_record record;

            mailbox_find_index_record(this_mailbox,
                                      this_mailbox->i.last_uid, &record);

            jmap_encode_rawdata_blobid('V', mailbox_uniqueid(this_mailbox),
                                       record.uid, NULL, NULL, NULL, NULL, &buf);
            json_object_set_new(*item, "blobId",
                                json_string(buf_cstring(&buf)));

            json_object_set_new(*item, "size",
                                json_integer(record.size - record.header_size));

            while ((blob = ptrarray_pop(&blobs))) {
                jmap_encode_rawdata_blobid('V', mailbox_uniqueid(this_mailbox),
                                           record.uid, NULL, NULL, blob->prop,
                                           &blob->guid, &buf);
                json_object_set_new(*item, blob->key,
                                    json_pack("{s:s s:i s:s? s:n}",
                                              "blobId", buf_cstring(&buf),
                                              "size", blob->size,
                                              "type", blob->type, "name"));
                property_blob_free(&blob);
            }

            r = carddav_remove(*mailbox, olduid,
                               /*isreplace*/!newmailbox, req->userid);
        }
    }

  done:
    mboxlist_entry_free(&mbentry);
    mailbox_close(&newmailbox);
    strarray_free(flags);
    freeentryatts(annots);
    vparse_free_card(vcard);
    free(resource);
    json_decref(jupdated);
    while ((blob = ptrarray_pop(&blobs))) {
        property_blob_free(&blob);
    }
    ptrarray_fini(&blobs);
    buf_free(&buf);

    return r;
}

static int jmap_contact_set(struct jmap_req *req)
{
    _contacts_set(req, CARDDAV_KIND_CONTACT, contact_props,
                  &_contact_set_create, &_contact_set_update);

    return 0;
}

static void _contact_copy(jmap_req_t *req,
                          json_t *jcard,
                          struct carddav_db *src_db,
                          json_t *(*_from_record)(jmap_req_t *req,
                                                  struct carddav_db *db,
                                                  struct mailbox *mailbox,
                                                  struct index_record *record),
                          int (*_set_create)(jmap_req_t *req,
                                             unsigned kind,
                                             json_t *jcard,
                                             struct mailbox **mailbox,
                                             json_t *item,
                                             jmap_contact_errors_t *errors),
                          json_t **new_card,
                          json_t **set_err)
{
    struct jmap_parser myparser = JMAP_PARSER_INITIALIZER;
    json_t *src_card = NULL, *dst_card = NULL;
    struct mailbox *src_mbox = NULL;
    struct mailbox *dst_mbox = NULL;
    mbentry_t *mbentry = NULL;
    int r = 0;

    /* Read mandatory properties */
    const char *src_id = json_string_value(json_object_get(jcard, "id"));
    if (!src_id) {
        jmap_parser_invalid(&myparser, "id");
    }
    if (json_array_size(myparser.invalid)) {
        *set_err = json_pack("{s:s s:O}", "type", "invalidProperties",
                                          "properties", myparser.invalid);
        goto done;
    }

    /* Lookup event */
    struct carddav_data *cdata = NULL;
    r = carddav_lookup_uid(src_db, src_id, &cdata);
    if (r && r != CYRUSDB_NOTFOUND) {
        syslog(LOG_ERR, "carddav_lookup_uid(%s) failed: %s",
               src_id, error_message(r));
        goto done;
    }
    if (r == CYRUSDB_NOTFOUND || !cdata->dav.alive ||
        !cdata->dav.rowid || !cdata->dav.imap_uid) {
        *set_err = json_pack("{s:s}", "type", "notFound");
        goto done;
    }

    mbentry = jmap_mbentry_from_dav(req, &cdata->dav);
    if (!mbentry || !jmap_hasrights_mbentry(req, mbentry, JACL_READITEMS)) {
        *set_err = json_pack("{s:s}", "type", "notFound");
        goto done;
    }

    /* Read source event */
    r = mailbox_open_irl(mbentry->name, &src_mbox);
    if (r) goto done;

    struct index_record record;
    r = mailbox_find_index_record(src_mbox, cdata->dav.imap_uid, &record);
    if (!r) src_card = _from_record(req, src_db, src_mbox, &record);
    if (!src_card) {
        syslog(LOG_ERR, "contact_copy: can't convert %s to JMAP", src_id);
        r = IMAP_INTERNAL;
        goto done;
    }

    dst_card = jmap_patchobject_apply(src_card, jcard, NULL, 0);
    json_object_del(dst_card, "id");  // immutable and WILL change
    json_decref(src_card);

    /* Create vcard */
    json_t *invalid = json_array();
    jmap_contact_errors_t errors = { invalid, NULL };
    json_t *item = json_object();
    r = _set_create(req, CARDDAV_KIND_CONTACT, dst_card,
                    &dst_mbox, item, &errors);
    if (r || json_array_size(invalid) || errors.blobNotFound) {
        if (json_array_size(invalid)) {
            *set_err = json_pack("{s:s s:o}", "type", "invalidProperties",
                                              "properties", invalid);
            json_decref(errors.blobNotFound);
        }
        else {
            json_decref(invalid);

            if (errors.blobNotFound) {
                *set_err = json_pack("{s:s s:o}", "type", "blobNotFound",
                                     "notFound", errors.blobNotFound);
            }
            else *set_err = jmap_server_error(r);
        }
        json_decref(item);
        goto done;
    }
    json_decref(invalid);

    *new_card = item;

done:
    if (r && *set_err == NULL) {
        if (r == CYRUSDB_NOTFOUND)
            *set_err = json_pack("{s:s}", "type", "notFound");
        else
            *set_err = jmap_server_error(r);
    }
    mboxlist_entry_free(&mbentry);
    mailbox_close(&dst_mbox);
    mailbox_close(&src_mbox);
    json_decref(dst_card);
    jmap_parser_fini(&myparser);
}

static int _contacts_copy(struct jmap_req *req,
                          json_t *(*_from_record)(jmap_req_t *req,
                                                  struct carddav_db *db,
                                                  struct mailbox *mailbox,
                                                  struct index_record *record),
                          int (*_set_create)(jmap_req_t *req,
                                             unsigned kind,
                                             json_t *jcard,
                                             struct mailbox **mailbox,
                                             json_t *item,
                                             jmap_contact_errors_t *errors))
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_copy copy;
    json_t *err = NULL;
    struct carddav_db *src_db = NULL;
    json_t *destroy_cards = json_array();
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
        if (atomodseq_t(copy.if_from_in_state) != counters.carddavmodseq) {
            jmap_error(req, json_pack("{s:s}", "type", "stateMismatch"));
            goto done;
        }
    }

    if (copy.if_in_state) {
        if (atomodseq_t(copy.if_in_state) != jmap_modseq(req, MBTYPE_ADDRESSBOOK, 0)) {
            jmap_error(req, json_pack("{s:s}", "type", "stateMismatch"));
            goto done;
        }
        copy.old_state = xstrdup(copy.if_in_state);
    }
    else {
        copy.old_state = modseqtoa(jmap_modseq(req, MBTYPE_ADDRESSBOOK, 0));
    }

    // now we can open the cstate
    int r = conversations_open_user(req->accountid, 0, &req->cstate);
    if (r) {
        syslog(LOG_ERR, "jmap_email_copy: can't open converstaions: %s",
                        error_message(r));
        jmap_error(req, jmap_server_error(r));
        goto done;
    }

    src_db = carddav_open_userid(copy.from_account_id);
    if (!src_db) {
        jmap_error(req, json_pack("{s:s}", "type", "fromAccountNotFound"));
        goto done;
    }

    /* Process request */
    const char *creation_id;
    json_t *jcard;
    json_object_foreach(copy.create, creation_id, jcard) {
        /* Copy event */
        json_t *set_err = NULL;
        json_t *new_card = NULL;

        _contact_copy(req, jcard, src_db,
                      _from_record, _set_create, &new_card, &set_err);
        if (set_err) {
            json_object_set_new(copy.not_created, creation_id, set_err);
            continue;
        }

        // extract the id for later deletion
        json_array_append(destroy_cards, json_object_get(jcard, "id"));

        /* Report event as created */
        json_object_set_new(copy.created, creation_id, new_card);
        const char *card_id = json_string_value(json_object_get(new_card, "id"));
        jmap_add_id(req, creation_id, card_id);
    }

    /* Build response */
    copy.new_state = modseqtoa(jmap_modseq(req, MBTYPE_ADDRESSBOOK, JMAP_MODSEQ_RELOAD));
    jmap_ok(req, jmap_copy_reply(&copy));

    /* Destroy originals, if requested */
    if (copy.on_success_destroy_original && json_array_size(destroy_cards)) {
        const char *submethod = !strcmp(req->method, "Contact/copy") ?
            "Contact/set" : "ContactCard/set";
        json_t *subargs = json_object();
        json_object_set(subargs, "destroy", destroy_cards);
        json_object_set_new(subargs, "accountId", json_string(copy.from_account_id));
        if (copy.destroy_from_if_in_state) {
            json_object_set_new(subargs, "ifInState",
                                json_string(copy.destroy_from_if_in_state));
        }
        jmap_add_subreq(req, submethod, subargs, NULL);
    }

done:
    json_decref(destroy_cards);
    if (src_db) carddav_close(src_db);
    mboxname_release(&srcnamespacelock);
    mboxname_release(&dstnamespacelock);
    jmap_parser_fini(&parser);
    jmap_copy_fini(&copy);
    free(srcinbox);
    free(dstinbox);
    return 0;
}

static json_t *_contact_from_record(jmap_req_t *req,
                                    struct carddav_db *db __attribute__((unused)),
                                    struct mailbox *mailbox,
                                    struct index_record *record)
{
    struct vparse_card *vcard = record_to_vcard(mailbox, record);

    if (!vcard || !vcard->objects) {
        if (vcard) vparse_free_card(vcard);
        return NULL;
    }

    /* Patch JMAP event */
    json_t *contact = jmap_contact_from_vcard(req->userid, vcard->objects,
                                              mailbox, record);
    vparse_free_card(vcard);

    if (contact && strstr(req->method, "/copy")) {
        json_t *avatar = json_object_get(contact, "avatar");
        if (avatar) {
            /* _blob_to_card() needs to know in which account to find blob */
            json_object_set(avatar, "accountId",
                            json_object_get(req->args, "fromAccountId"));
        }
        json_object_del(contact, "x-href");      // immutable and WILL change
        json_object_del(contact, "x-hasPhoto");  // immutable and WILL change
    }

    return contact;
}

static int jmap_contact_copy(struct jmap_req *req)
{
    return _contacts_copy(req, &_contact_from_record, &_contact_set_create);
}


#ifdef HAVE_LIBICALVCARD

/*****************************************************************************
 * JMAP AddressBook API
 ****************************************************************************/

static json_t *addressbookrights_to_jmap(int rights)
{
    return json_pack("{s:b s:b s:b s:b}",
            "mayRead",
            (rights & JACL_READITEMS) == JACL_READITEMS,
            "mayWrite",
            (rights & JACL_WRITEALL) == JACL_WRITEALL,
            "mayDelete",
            (rights & JACL_DELETE) == JACL_DELETE,
            "mayAdmin",
            (rights & JACL_ADMIN_ADDRBOOK) == JACL_ADMIN_ADDRBOOK);
}

static int addressbook_sharewith_to_rights(int rights, json_t *jsharewith)
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
addressbook_sharewith_to_rights_iter:
    json_object_foreach(jsharewith, name, jval) {
        int mask;
        if (!strcmp("mayRead", name))
            mask = JACL_READITEMS;
        else if (!strcmp("mayWrite", name))
            mask = JACL_WRITEALL;
        else if (!strcmp("mayDelete", name))
            mask = JACL_DELETE;
        else if (!strcmp("mayAdmin", name))
            mask = JACL_ADMIN_ADDRBOOK;
        else
            continue;

        if (iteration == 1 && !json_boolean_value(jval))
            newrights &= ~mask;
        else if (iteration == 2 && json_boolean_value(jval))
            newrights |= mask;
    }
    if (++iteration == 2) goto addressbook_sharewith_to_rights_iter;

    /* Allow to set addressbook properties */
    if (newrights) {
        newrights |= ACL_WRITE;
    }

    return newrights;
}

struct getaddressbooks_rock {
    struct jmap_req *req;
    struct jmap_get *get;
    int skip_hidden;
};

static int getaddressbooks_cb(const mbentry_t *mbentry, void *vrock)
{
    struct getaddressbooks_rock *rock = vrock;
    jmap_req_t *req = rock->req;
    mbname_t *mbname = NULL;
    int r = 0;

    /* Only addressbooks... */
    if (mbtype_isa(mbentry->mbtype) != MBTYPE_ADDRESSBOOK) return 0;

    /* ...which are at least readable or visible... */
    if (!jmap_hasrights_mbentry(rock->req, mbentry, JACL_READITEMS))
        return rock->skip_hidden ? 0 : IMAP_PERMISSION_DENIED;

    // needed for some fields
    int rights = jmap_myrights_mbentry(rock->req, mbentry);

    /* OK, we want this one... */
    mbname = mbname_from_intname(mbentry->name);

    json_t *obj = json_object();

    const strarray_t *boxes = mbname_boxes(mbname);
    const char *id = strarray_nth(boxes, boxes->count-1);
    json_object_set_new(obj, "id", json_string(id));

    if (jmap_wantprop(rock->get->props, "cyrusimap.org:href")) {
        // XXX - should the x-ref for a shared addressbook point
        // to the authenticated user's addressbook home?
        char *xhref = jmap_xhref(mbentry->name, NULL);
        json_object_set_new(obj, "cyrusimap.org:href", json_string(xhref));
        free(xhref);
    }

    struct buf attrib = BUF_INITIALIZER;
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

    if (jmap_wantprop(rock->get->props, "isSubscribed")) {
        int is_subscribed;
        if (mboxname_userownsmailbox(req->userid, mbentry->name)) {
            /* Users always subscribe their own addressbooks */
            is_subscribed = 1;
        }
        else {
            /* Lookup mailbox subscriptions */
            is_subscribed = mboxlist_checksub(mbentry->name, req->userid) == 0;
        }
        json_object_set_new(obj, "isSubscribed", json_boolean(is_subscribed));
    }

    if (jmap_wantprop(rock->get->props, "myRights")) {
        json_object_set_new(obj, "myRights", addressbookrights_to_jmap(rights));
    }

    if (jmap_wantprop(rock->get->props, "shareWith")) {
        json_t *sharewith =
            jmap_get_sharewith(mbentry, addressbookrights_to_jmap);
        json_object_set_new(obj, "shareWith", sharewith);
    }

    json_array_append_new(rock->get->list, obj);

    buf_free(&attrib);
    mbname_free(&mbname);
    return r;
}

// clang-format off
static const jmap_property_t addressbook_props[] = {
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
        "isSubscribed",
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
        "cyrusimap.org:href",
        JMAP_DEBUG_EXTENSION,
        JMAP_PROP_SERVER_SET
    },

    { NULL, NULL, 0 }
};
// clang-format on

static int jmap_addressbook_get(struct jmap_req *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_get get;
    json_t *err = NULL;
    int r = 0;

    /* Parse request */
    jmap_get_parse(req, &parser, addressbook_props, /*allow_null_ids*/1,
                   NULL, NULL, &get, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    /* Build callback data */
    struct getaddressbooks_rock rock = { req, &get, 1 /*skiphidden*/ };

    /* Does the client request specific addressbooks? */
    if (JNOTNULL(get.ids)) {
        size_t i;
        json_t *jval;

        rock.skip_hidden = 0; /* complain about missing ACL rights */
        json_array_foreach(get.ids, i, jval) {
            const char *id = json_string_value(jval);
            char *mboxname = carddav_mboxname(req->accountid, id);
            mbentry_t *mbentry = NULL;

            r = mboxlist_lookup(mboxname, &mbentry, NULL);
            if (r == IMAP_NOTFOUND || !mbentry) {
                json_array_append(get.not_found, jval);
                r = 0;
            }
            else {
                r = getaddressbooks_cb(mbentry, &rock);
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
        char *cardhomename = carddav_mboxname(req->accountid, NULL);
        r = mboxlist_mboxtree(cardhomename,
                              &getaddressbooks_cb, &rock, MBOXTREE_SKIP_ROOT);
        free(cardhomename);
        if (r) goto done;
    }

    /* Build response */
    get.state = modseqtoa(jmap_modseq(req, MBTYPE_ADDRESSBOOK, 0));
    jmap_ok(req, jmap_get_reply(&get));

done:
    jmap_parser_fini(&parser);
    jmap_get_fini(&get);
    return r;
}

struct addressbookchanges_rock {
    jmap_req_t *req;
    struct jmap_changes *changes;
};

static int getaddressbookchanges_cb(const mbentry_t *mbentry, void *vrock)
{
    struct addressbookchanges_rock *rock = (struct addressbookchanges_rock *) vrock;
    mbname_t *mbname = NULL;
    jmap_req_t *req = rock->req;
    int r = 0;

    /* Ignore old changes. */
    if (mbentry->foldermodseq <= rock->changes->since_modseq) {
        goto done;
    }

    /* Ignore any mailboxes that aren't (possibly deleted) addressbooks. */
    if (!mboxname_isaddressbookmailbox(mbentry->name, mbentry->mbtype))
        return 0;

    /* Ignore mailboxes that are hidden from us. */
    /* XXX Deleted mailboxes loose their ACL so we can't determine
     * if they ever could be read by the authenticated user. We
     * need to leak these deleted entries to not mess up client state. */
    if (!(mbentry->mbtype & MBTYPE_DELETED) || strcmpsafe(mbentry->acl, "")) {
        if (!jmap_hasrights_mbentry(req, mbentry, JACL_READITEMS)) return 0;
    }

    mbname = mbname_from_intname(mbentry->name);
    const strarray_t *boxes = mbname_boxes(mbname);
    const char *id = strarray_nth(boxes, boxes->count-1);

    /* Report this addressbook as created, updated or destroyed. */
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

static int jmap_addressbook_changes(struct jmap_req *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_changes changes = JMAP_CHANGES_INITIALIZER;
    json_t *err = NULL;
    int r = 0;

    /* Parse request */
    jmap_changes_parse(req, &parser, req->counters.carddavfoldersdeletedmodseq,
                       NULL, NULL, &changes, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    /* Lookup any changes. */
    char *mboxname = carddav_mboxname(req->accountid, NULL);
    struct addressbookchanges_rock rock = { req, &changes };

    r = mboxlist_mboxtree(mboxname, getaddressbookchanges_cb, &rock,
                          MBOXTREE_TOMBSTONES|MBOXTREE_SKIP_ROOT);
    free(mboxname);
    if (r) {
        jmap_error(req, json_pack("{s:s}", "type", "cannotCalculateChanges"));
        r = 0;
        goto done;
    }

    /* Determine new state.  XXX  what about max_changes? */
    changes.new_modseq = /*changes.has_more_changes ? rock.highestmodseq :*/
        jmap_modseq(req, MBTYPE_ADDRESSBOOK, 0);

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

struct setaddressbook_props {
    const char *name;
    int isSubscribed;
    struct {
        json_t *With;
        int overwrite_acl;
    } share;
};

static void setaddressbook_readprops(jmap_req_t *req,
                                     struct jmap_parser *parser,
                                     struct setaddressbook_props *props,
                                     json_t *arg,
                                     const char *mboxname)
{
    int is_create = (mboxname == NULL);

    memset(props, 0, sizeof(struct setaddressbook_props));

    if (is_create) {
        props->isSubscribed = 1;
        props->share.overwrite_acl = 1;
    }
    else {
        props->isSubscribed = -1;
        props->share.overwrite_acl = 1;
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

    /* isSubscribed */
    jprop = json_object_get(arg, "isSubscribed");
    if (json_is_boolean(jprop)) {
        props->isSubscribed = json_boolean_value(jprop);
        if (!strcmp(req->accountid, req->userid)) {
            if (!props->isSubscribed) {
                /* unsubscribing own addressbook isn't supported */
                jmap_parser_invalid(parser, "isSubscribed");
            }
            else props->isSubscribed = -1; // ignore
        }
    }
    else if (JNOTNULL(jprop)) {
        jmap_parser_invalid(parser, "isSubscribed");
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
                            (strcmp(right, "mayRead") &&
                             strcmp(right, "mayWrite") &&
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

    /* myRights */
    jprop = json_object_get(arg, "myRights");
    if (JNOTNULL(jprop)) {
        /* The myRights property is server-set and MUST NOT be set. */
        jmap_parser_invalid(parser, "myRights");
    }
}

/* Write the addressbook properties in the addressbook mailbox named mboxname.
 * NULL values and negative integers are ignored. Return 0 on success. */
static int setaddressbook_writeprops(jmap_req_t *req,
                                     const char *mboxname,
                                     struct setaddressbook_props *props,
                                     int ignore_acl)
{
    struct mailbox *mbox = NULL;
    annotate_state_t *astate = NULL;
    struct buf val = BUF_INITIALIZER;
    int r;

    if (!jmap_hasrights(req, mboxname, JACL_READITEMS) && !ignore_acl)
        return IMAP_MAILBOX_NONEXISTENT;

    r = mailbox_open_iwl(mboxname, &mbox);
    if (r) return r;

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

    /* isSubscribed */
    if (!r && props->isSubscribed >= 0) {
        /* Update subscription database */
        r = mboxlist_changesub(mboxname, req->userid, req->authstate,
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

    /* shareWith */
    if (!r && props->share.With) {
        r = jmap_set_sharewith(mbox, props->share.With,
                props->share.overwrite_acl, addressbook_sharewith_to_rights);
    }

    buf_free(&val);
    if (mbox) {
        if (r) mailbox_abort(mbox);
        mailbox_close(&mbox);
    }
    return r;
}

static int _addressbook_hascards_cb(void *rock __attribute__((unused)),
                                    struct carddav_data *cdata __attribute__((unused)))
{
    /* Any alive event will do */
    return CYRUSDB_DONE;
}

/* Delete the addressbook mailbox named mboxname for the userid in req. */
static void setaddressbooks_destroy(jmap_req_t *req, const char *abookid,
                                    int destroy_contents, json_t **err)
{
    char *mboxname = NULL;
    mbentry_t *mbentry = NULL;
    struct carddav_db *db = NULL;
    int r = 0;

    /* XXX  Don't delete default addressbook ??? */
    if (!strcmp(abookid, DEFAULT_ADDRBOOK)) {
        *err = json_pack("{s:s}", "type", "forbidden");
        goto done;
    }

    mboxname = carddav_mboxname(req->accountid, abookid);
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

    db = carddav_open_userid(req->accountid);
    if (!db) {
        xsyslog(LOG_ERR, "carddav_open_mailbox failed", "accountid=<%s>",
                req->accountid);
        goto done;
    }

    /* Validate onDestroyRemoveContents */
    if (!destroy_contents) {
        r = carddav_foreach(db, mbentry, _addressbook_hascards_cb, NULL);
        if (r == CYRUSDB_DONE) {
            *err = json_pack("{s:s}", "type", "addressBookHasContents");
            goto done;
        }
        else if (r) {
            *err = jmap_server_error(r);
            goto done;
        }
    }

    /* Delete addressbook */
    r = carddav_delmbox(db, mbentry);
    if (r) {
        xsyslog(LOG_ERR, "failed to delete mailbox from carddav_db",
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

  done:
    if (db) {
        int rr = carddav_close(db);
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
    mboxlist_entry_free(&mbentry);
    free(mboxname);
}

static char *setaddressbooks_create_rewriteacl(jmap_req_t *req,
                                               const char *parentacl)
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
                syslog(LOG_ERR, "IOERROR: failed to set_acl for addressbook create (%s, %s) %s",
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

static void setaddressbooks_create(struct jmap_req *req,
                                   const char *creation_id,
                                   json_t *arg,
                                   json_t **record,
                                   json_t **err)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct setaddressbook_props props;
    mbentry_t *mbparent = NULL;
    char *parentname = carddav_mboxname(req->accountid, NULL);
    char *uid = xstrdup(makeuuid());
    char *mboxname = carddav_mboxname(req->accountid, uid);
    int r = 0;

    /* Parse and validate properties. */
    setaddressbook_readprops(req, &parser, &props, arg, /*is_create*/NULL);
    if (props.share.With) {
        if (!jmap_hasrights(req, parentname, ACL_ADMIN)) {
            jmap_parser_invalid(&parser, "shareWith");
        }
    }
    if (json_array_size(parser.invalid)) {
        *err = json_pack("{s:s, s:O}",
                "type", "invalidProperties",
                "properties", parser.invalid);
        goto done;
    }

    /* Make sure we are allowed to create the addressbook */
    mboxlist_lookup(parentname, &mbparent, NULL);
    if (!jmap_hasrights_mbentry(req, mbparent, JACL_CREATECHILD)) {
        *err = json_pack("{s:s}", "type", "accountReadOnly");
        goto done;
    }

    /* Create the addressbook */
    char *acl = setaddressbooks_create_rewriteacl(req, mbparent->acl);
    if (!acl || acl[0] == '\0') {
        r = IMAP_INTERNAL;
        free(acl);
        goto done;
    }
    mbentry_t mbentry = MBENTRY_INITIALIZER;
    mbentry.name = mboxname;
    mbentry.acl = acl;
    mbentry.mbtype = MBTYPE_ADDRESSBOOK;
    r = mboxlist_createmailbox(&mbentry, 0/*options*/, 0/*highestmodseq*/,
            0/*isadmin*/, req->userid, req->authstate,
            0/*flags*/, NULL/*mailboxptr*/);
    free(acl);
    if (r) {
        syslog(LOG_ERR, "IOERROR: failed to create %s (%s)",
                mboxname, error_message(r));
        goto done;
    }
    r = setaddressbook_writeprops(req, mboxname, &props, /*ignore_acl*/1);
    if (r) {
        int rr = mboxlist_deletemailbox(mboxname, 1, "", NULL, NULL, 0);
        if (rr) {
            syslog(LOG_ERR, "could not delete mailbox %s: %s",
                    mboxname, error_message(rr));
        }
        goto done;
    }

    /* Report addressbook as created. */
    *record = json_pack("{s:s s:o}", "id", uid,
                        "myRights",
                        addressbookrights_to_jmap(jmap_myrights_mbentry(req,
                                                                        &mbentry)));
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
    jmap_parser_fini(&parser);
    free(parentname);
    free(mboxname);
    free(uid);
}

static void setaddressbooks_update(jmap_req_t *req,
                                   const char *uid,
                                   json_t *arg,
                                   json_t **record,
                                   json_t **err)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    char *mboxname = carddav_mboxname(req->accountid, uid);
    mbname_t *mbname = mbname_from_intname(mboxname);

    /* Parse and validate properties. */
    struct setaddressbook_props props;
    setaddressbook_readprops(req, &parser, &props, arg, mboxname);
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

    /* Update the addressbook */
    int r = setaddressbook_writeprops(req, mboxname, &props, /*ignore_acl*/0);
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

    /* Report addressbook as updated. */
    *record = json_null();

done:
    jmap_parser_fini(&parser);
    mbname_free(&mbname);
    free(mboxname);
}

static int setaddressbooks_parse_args(jmap_req_t *req __attribute__((unused)),
                                      struct jmap_parser *parser __attribute__((unused)),
                                      const char *arg, json_t *val, void *rock)
{
    int *on_destroy_remove_contents = rock;
    *on_destroy_remove_contents = 0;

    if (!strcmp(arg, "onDestroyRemoveContents")) {
        if (json_is_boolean(val)) {
            *on_destroy_remove_contents = json_boolean_value(val);
            return 1;
        }
    }
    return 0;
}

static int jmap_addressbook_set(struct jmap_req *req)
{
    struct mboxlock *namespacelock = user_namespacelock(req->accountid);
    struct jmap_parser argparser = JMAP_PARSER_INITIALIZER;
    struct jmap_set set;
    int on_destroy_remove_contents = 0;
    json_t *err = NULL;
    int r = 0;

    /* Parse arguments */
    jmap_set_parse(req, &argparser, addressbook_props, setaddressbooks_parse_args,
                   &on_destroy_remove_contents, &set, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    if (set.if_in_state) {
        if (atomodseq_t(set.if_in_state) != jmap_modseq(req, MBTYPE_ADDRESSBOOK, 0)) {
            jmap_error(req, json_pack("{s:s}", "type", "stateMismatch"));
            goto done;
        }
        set.old_state = xstrdup(set.if_in_state);
    }
    else {
        set.old_state = modseqtoa(jmap_modseq(req, MBTYPE_ADDRESSBOOK, 0));
    }

    r = carddav_create_defaultaddressbook(req->accountid);
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
        setaddressbooks_create(req, key, arg, &record, &err);
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
        const char *abookid = id;
        if (abookid && abookid[0] == '#') {
            const char *newabookid = jmap_lookup_id(req, abookid + 1);
            if (!newabookid) {
                json_object_set_new(set.not_updated, id,
                        json_pack("{s:s}", "type", "notFound"));
                continue;
            }
            abookid = newabookid;
        }
        json_t *record = NULL, *err = NULL;
        setaddressbooks_update(req, abookid, arg, &record, &err);
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
        /* Resolve abookid */
        const char *abookid = id;
        if (abookid && abookid[0] == '#') {
            const char *newabookid = jmap_lookup_id(req, abookid + 1);
            if (!newabookid) {
                json_t *err = json_pack("{s:s}", "type", "notFound");
                json_object_set_new(set.not_destroyed, id, err);
                continue;
            }
            abookid = newabookid;
        }
        json_t *err = NULL;
        setaddressbooks_destroy(req, abookid, on_destroy_remove_contents, &err);
        if (!err) {
            json_array_append_new(set.destroyed, json_string(id));
        }
        else json_object_set_new(set.not_destroyed, id, err);
    }

    set.new_state = modseqtoa(jmap_modseq(req, MBTYPE_ADDRESSBOOK, JMAP_MODSEQ_RELOAD));

    jmap_ok(req, jmap_set_reply(&set));

done:
    mboxname_release(&namespacelock);
    jmap_parser_fini(&argparser);
    jmap_set_fini(&set);
    return r;
}


/*****************************************************************************
 * JMAP ContactCard API
 ****************************************************************************/

// clang-format off
static const jmap_property_t card_props[] = {
    {
        "id",
        NULL,
        JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE | JMAP_PROP_ALWAYS_GET
    },
    {
        "addressBookId",
        NULL,
        0
    },
    {
        "@type",
        NULL,
        0
    },
    {
        "version",
        NULL,
        0
    },
    {
        "created",
        NULL,
        0
    },
    {
        "kind",
        NULL,
        0
    },
    {
        "language",
        NULL,
        0
    },
    {
        "members",
        NULL,
        0
    },
    {
        "prodId",
        NULL,
        0
    },
    {
        "relatedTo",
        NULL,
        0
    },
    {
        "uid",
        NULL,
        JMAP_PROP_IMMUTABLE
    },
    {
        "updated",
        NULL,
        0
    },
    {
        "name",
        NULL,
        0
    },
    {
        "nicknames",
        NULL,
        0
    },
    {
        "organizations",
        NULL,
        0
    },
    {
        "speakToAs",
        NULL,
        0
    },
    {
        "titles",
        NULL,
        0
    },
    {
        "department",
        NULL,
        0
    },
    {
        "emails",
        NULL,
        0
    },
    {
        "onlineServices",
        NULL,
        0
    },
    {
        "phones",
        NULL,
        0
    },
    {
        "contactBy",
        NULL,
        0
    },
    {
        "preferredLanguages",
        NULL,
        0
    },
    {
        "calendars",
        NULL,
        0
    },
    {
        "schedulingAddresses",
        NULL,
        0
    },
    {
        "addresses",
        NULL,
        0
    },
    {
        "cryptoKeys",
        NULL,
        0
    },
    {
        "directories",
        NULL,
        0
    },
    {
        "links",
        NULL,
        0
    },
    {
        "media",
        NULL,
        0
    },
    {
        "localizations",
        NULL,
        0
    },
    {
        "anniversaries",
        NULL,
        0
    },
    {
        "keywords",
        NULL,
        0
    },
    {
        "notes",
        NULL,
        0
    },
    {
        "personalInfo",
        NULL,
        0
    },
    {
        "vCardProps",
        NULL,
        0
    },

    /* FM extensions */
    {
        "cyrusimap.org:importance",
        JMAP_CONTACTS_EXTENSION,
        0
    },
    {
        "cyrusimap.org:blobId",
        JMAP_CONTACTS_EXTENSION,
        JMAP_PROP_SERVER_SET
    },
    {
        "cyrusimap.org:size",
        JMAP_CONTACTS_EXTENSION,
        JMAP_PROP_SERVER_SET
    },
    {
        "cyrusimap.org:href", 
        JMAP_DEBUG_EXTENSION,
        JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE
    },

    /* Allow unknown properties */
    {
        "*",
        NULL,
        0
    },

    { NULL, NULL, 0 }
};
// clang-format on


/*
 * ContactCard/get
 */

struct comp_kind {
    unsigned idx;
    const char *name;
    unsigned flags;
    unsigned alt_idx; /* idx of alternate field dictated by flags */
};

#define FIELD_BWD  (1<<0)  /* Add value to backward-compatibility field    */
#define FIELD_EXT  (1<<1)  /* Ignore value if it appears in extended field */
#define FIELD_SKIP (1<<2)  /* Skip this field if extended field exists     */

/* JSContact Name components - ordered per vcard_n_field */
// clang-format off
static const struct comp_kind n_comp_kinds[] = {
    { VCARD_N_FAMILY,          "surname",       FIELD_EXT,  VCARD_N_SECONDARY  },
    { VCARD_N_GIVEN,           "given",         0,          0                  },
    { VCARD_N_ADDITIONAL,      "given2",        0,          0                  },
    { VCARD_N_PREFIX,          "title",         0,          0                  },
    { VCARD_N_SUFFIX,          "credential",    FIELD_EXT,  VCARD_N_GENERATION },
    /* Extended fields (RFC 9554) */
    { VCARD_N_SECONDARY,       "surname2",      FIELD_BWD,  VCARD_N_FAMILY     },
    { VCARD_N_GENERATION,      "generation",    FIELD_BWD,  VCARD_N_SUFFIX     },
    { 0,                       NULL,            0,          0                  }
};
// clang-format on

/* JSContact Address components - ordered per vcard_adr_field */
// clang-format off
static const struct comp_kind adr_comp_kinds[] = {
    { VCARD_ADR_PO_BOX,        "postOfficeBox", 0,          0                  },
    { VCARD_ADR_EXTENDED,      "apartment",     FIELD_SKIP, VCARD_ADR_ROOM     },
    { VCARD_ADR_STREET,        "name",          FIELD_SKIP, VCARD_ADR_ROOM     },
    { VCARD_ADR_LOCALITY,      "locality",      0,          0                  },
    { VCARD_ADR_REGION,        "region",        0,          0                  },
    { VCARD_ADR_POSTAL_CODE,   "postcode",      0,          0                  },
    { VCARD_ADR_COUNTRY,       "country",       0,          0                  },
    /* Extended fields (RFC 9554) */
    { VCARD_ADR_ROOM,          "room",          FIELD_BWD,  VCARD_ADR_EXTENDED },
    { VCARD_ADR_APARTMENT,     "apartment",     FIELD_BWD,  VCARD_ADR_EXTENDED },
    { VCARD_ADR_FLOOR,         "floor",         FIELD_BWD,  VCARD_ADR_EXTENDED },
    { VCARD_ADR_STREET_NUMBER, "number",        FIELD_BWD,  VCARD_ADR_STREET   },
    { VCARD_ADR_STREET_NAME,   "name",          FIELD_BWD,  VCARD_ADR_STREET   },
    { VCARD_ADR_BUILDING,      "building",      FIELD_BWD,  VCARD_ADR_EXTENDED },
    { VCARD_ADR_BLOCK,         "block",         FIELD_BWD,  VCARD_ADR_STREET   },
    { VCARD_ADR_SUBDISTRICT,   "subdistrict",   FIELD_BWD,  VCARD_ADR_STREET   },
    { VCARD_ADR_DISTRICT,      "district",      FIELD_BWD,  VCARD_ADR_STREET   },
    { VCARD_ADR_LANDMARK,      "landmark",      FIELD_BWD,  VCARD_ADR_STREET   },
    { VCARD_ADR_DIRECTION,     "direction",     FIELD_BWD,  VCARD_ADR_STREET   },
    { 0,                       NULL,            0,          0                  }
};
// clang-format on

#define ALLOW_CALSCALE_PARAM      (1<<0)
#define ALLOW_INDEX_PARAM         (1<<1)
#define ALLOW_LANGUAGE_PARAM      (1<<2)
#define ALLOW_LABEL_PARAM         (1<<3)
#define ALLOW_LEVEL_PARAM         (1<<4)
#define ALLOW_MEDIATYPE_PARAM     (1<<5)
#define ALLOW_PREF_PARAM          (1<<6)
#define ALLOW_SERVICETYPE_PARAM   (1<<7)
#define ALLOW_TYPE_PARAM          (1<<8)
#define ALLOW_USERNAME_PARAM      (1<<9)

static const char *_prop_id(vcardproperty *prop)
{
    static struct message_guid guid = MESSAGE_GUID_INITIALIZER;
    vcardparameter *param =
        vcardproperty_get_first_parameter(prop, VCARD_PROPID_PARAMETER);

    /* Use PROP-ID if we have it */
    if (param) {
        return vcardparameter_get_propid(param);
    }
    else {
        /* Otherwise, use hash of property value */
        const char *value = vcardproperty_get_value_as_string(prop);

        message_guid_generate(&guid, value, strlen(value));

        return message_guid_encode(&guid);
    }
}

static char *_value_to_uri_blobid(vcardproperty *prop,
                                  struct mailbox *mailbox,
                                  struct index_record *record,
                                  vcardproperty_version version,
                                  char **type, char **blobid)
{
    if (!blobid && version == VCARD_VERSION_40) {
        const char *uri = vcardvalue_get_uri(vcardproperty_get_value(prop));
        if (uri) return xstrdup(uri);
    }

    struct message_guid guid;
    size_t size = vcard_prop_decode_value_x(prop, NULL, type, &guid);

    if (size) {
        vcardparameter *param =
            vcardproperty_get_first_parameter(prop, VCARD_ENCODING_PARAMETER);
        struct buf buf = BUF_INITIALIZER;

        if (!*type) *type = xstrdup("application/octet-stream");

        if (param) {
            vcardproperty_remove_parameter_by_ref(prop, param);
            vcardproperty_remove_parameter_by_kind(prop, VCARD_TYPE_PARAMETER);
        }

        if (mailbox && record && blobid) {
            const char *prop_name = vcardproperty_get_property_name(prop);

            jmap_encode_rawdata_blobid('V', mailbox_uniqueid(mailbox),
                                       record->uid, NULL, NULL,
                                       prop_name, &guid, &buf);
            *blobid = buf_release(&buf);
            return NULL;
        }
        else if (param) {
            /* Build data: uri */
            buf_printf(&buf, "data:%s;base64,%s",
                       *type, vcardvalue_get_uri(vcardproperty_get_value(prop)));
            return buf_release(&buf);
        }
    }

    return xstrdup(vcardvalue_get_uri(vcardproperty_get_value(prop)));
}

static json_t *vcardtime_to_jmap_utcdate(vcardtimetype t)
{
    char datestr[ISO8601_DATETIME_MAX+1] = "";
    struct tm tm = { 0 };

    tm.tm_sec = t.second;
    tm.tm_min = t.minute;
    tm.tm_hour = t.hour;
    tm.tm_mday = t.day;
    tm.tm_mon = t.month - 1;
    tm.tm_year = t.year - 1900;
    tm.tm_isdst = -1;

    time_to_iso8601(mkgmtime(&tm) - (t.utcoffset * 60),
                    datestr, sizeof(datestr), 1);

    return json_string(datestr);
}

static json_t *_to_jmap_date(vcardproperty *prop)
{
    vcardtimetype date = vcardproperty_get_bday(prop);

    if (vcardtime_is_timestamp(date)) {
        return json_pack("{s:s s:o}",
                         "@type", "Timestamp",
                         "utc", vcardtime_to_jmap_utcdate(date));
    }

    int y = date.year, m = date.month, d = date.day;
    json_t *jdate = json_object();
    vcardparameter *param;

    for (param = vcardproperty_get_first_parameter(prop, VCARD_X_PARAMETER);
         param;
         param = vcardproperty_get_next_parameter(prop, VCARD_X_PARAMETER)) {
        const char *param_name = vcardparameter_get_xname(param);

        if (!strcasecmp(param_name, "X-APPLE-OMIT-YEAR")) {
            /* XXX compare value with actual year? */
            y = 0;
        }
        else if (!strncasecmp(param_name, "X-FM-NO-", 8)) {
            param_name += 8;

            if (!strcasecmp(param_name, "MONTH"))
                m = 0;
            else if (!strcasecmp(param_name, "DAY"))
                d = 0;
        }
    }

    /* sigh, magic year 1604 has been seen without X-APPLE-OMIT-YEAR, making
     * me wonder what the bloody point is */
    if (y > 0 && y != 1604) json_object_set_new(jdate, "year",  json_integer(y));
    if (m > 0) json_object_set_new(jdate, "month", json_integer(m));
    if (d > 0) json_object_set_new(jdate, "day",   json_integer(d));

    return jdate;
}

static void _unmapped_param(json_t *obj,
                            vcardparameter *param, char *param_value)
{
    vcardparameter_kind param_kind = vcardparameter_isa(param);
    json_t *params = json_object_get_vanew(obj, "vCardParams", "{}");
    struct buf buf = BUF_INITIALIZER;

    if (param_kind == VCARD_IANA_PARAMETER) {
        buf_setcstr(&buf, vcardparameter_get_iana_name(param));
    }
    else {
        buf_setcstr(&buf, vcardparameter_kind_to_string(param_kind));
    }

    json_object_set_new(params, buf_lcase(&buf), jmap_utf8string(param_value));

    buf_free(&buf);
}

static void _add_vcard_params(json_t *obj, vcardproperty *prop,
                              unsigned param_flags)
{
    vcardproperty_kind prop_kind = vcardproperty_isa(prop);
    struct buf buf = BUF_INITIALIZER;
    vcardparameter *param;

    for (param = vcardproperty_get_first_parameter(prop, VCARD_ANY_PARAMETER);
         param;
         param = vcardproperty_get_next_parameter(prop, VCARD_ANY_PARAMETER)) {
        vcardparameter_kind param_kind = vcardparameter_isa(param);
        char *param_str = vcardparameter_as_vcard_string(param);
        char *param_value = strchr(param_str, '=') + 1;
        const char *key = NULL;

        switch (param_kind) {
        case VCARD_ALTID_PARAMETER:
            /* Handled by localization code */
            continue;

        case VCARD_AUTHOR_PARAMETER:
            key = "uri";

            GCC_FALLTHROUGH

        case VCARD_AUTHORNAME_PARAMETER:
            if (!key) key = "name";

            if (prop_kind == VCARD_NOTE_PROPERTY) {
                json_t *author =
                    json_object_get_vanew(obj, "author", "{}");

                json_object_set_new(author, key,
                                    json_string(param_value));
                continue;
            }
            break;

        case VCARD_CALSCALE_PARAMETER:
            if (param_flags & ALLOW_CALSCALE_PARAM) {
                json_object_set_new(obj, "calendarScale",
                                    json_string(lcase(param_value)));
                continue;
            }
            break;

        case VCARD_CC_PARAMETER:
            if (prop_kind == VCARD_ADR_PROPERTY) {
                json_object_set_new(obj, "countryCode",
                                    json_string(lcase(param_value)));
                continue;
            }
            break;

        case VCARD_CREATED_PARAMETER:
            if (prop_kind == VCARD_NOTE_PROPERTY) {
                vcardtimetype time = vcardparameter_get_created(param);
                char datestr[ISO8601_DATETIME_MAX];

                sprintf(datestr, "%4d-%02d-%02dT%02d:%02d:%02d",
                        time.year, time.month, time.day,
                        time.hour, time.minute, time.second);
                if (time.utcoffset) {
                    sprintf(datestr + strlen(datestr), "%+03d:%02d",
                            time.utcoffset / 60, abs(time.utcoffset % 60));
                }
                else {
                    strcat(datestr, "Z");
                }

                json_object_set_new(obj, "created", json_string(datestr));
                continue;
            }
            break;

        case VCARD_GEO_PARAMETER:
            if (prop_kind == VCARD_ADR_PROPERTY) {
                json_object_set_new(obj, "coordinates",
                                    json_string(param_value));
                continue;
            }
            break;

        case VCARD_INDEX_PARAMETER:
            if (param_flags & ALLOW_INDEX_PARAM) {
                json_object_set_new(obj, "listAs",
                                    json_integer(vcardparameter_get_index(param)));
                continue;
            }
            break;

        case VCARD_LANGUAGE_PARAMETER:
            /* Handled by localization code */
            continue;

        case VCARD_LABEL_PARAMETER:
            /* Should be handled by the properties that use it */
            break;

        case VCARD_LEVEL_PARAMETER:
            if (param_flags & ALLOW_LEVEL_PARAM) {
                const char *level = NULL;

                switch (vcardparameter_get_level(param)) {
                case VCARD_LEVEL_LOW:
                case VCARD_LEVEL_BEGINNER:
                    level = "low";
                    break;

                case VCARD_LEVEL_MEDIUM:
                case VCARD_LEVEL_AVERAGE:
                    level = "medium";
                    break;

                case VCARD_LEVEL_HIGH:
                case VCARD_LEVEL_EXPERT:
                    level = "high";
                    break;

                default:
                    break;
                }

                if (level) {
                    json_object_set_new(obj, "level", json_string(level));
                    continue;
                }
            }
            break;

        case VCARD_MEDIATYPE_PARAMETER:
            if (param_flags & ALLOW_MEDIATYPE_PARAM) {
                json_object_set_new(obj, "mediaType",
                                    json_string(param_value));
                continue;
            }
            break;

        case VCARD_PREF_PARAMETER:
            if (param_flags & ALLOW_PREF_PARAM) {
                json_object_set_new(obj, "pref",
                                    json_integer(vcardparameter_get_pref(param)));
                continue;
            }
            break;

        case VCARD_PROPID_PARAMETER:
            /* Should be handled by the properties that use it */
            continue;

        servicetype:
        case VCARD_SERVICETYPE_PARAMETER:
            if (param_flags & ALLOW_SERVICETYPE_PARAM) {
                json_object_set_new(obj, "service", json_string(param_value));
                continue;
            }
            break;

        case VCARD_TYPE_PARAMETER:
            if (param_flags & ALLOW_TYPE_PARAM) {
                vcardenumarray *array = vcardparameter_get_type(param);

                for (size_t i = 0; i < vcardenumarray_size(array); i++) {
                    const vcardenumarray_element *e =
                        vcardenumarray_element_at(array, i);
                    const char *type = NULL, *val = NULL;

                    switch (e->val) {
                    case VCARD_TYPE_PREF:
                        if (param_flags & ALLOW_PREF_PARAM) {
                            /* v3 TYPE=PREF */
                            json_object_set_new(obj, "pref", json_integer(1));
                            continue;
                        }
                        break;

                    case VCARD_TYPE_HOME:
                        val = "private";

                        GCC_FALLTHROUGH

                    case VCARD_TYPE_WORK:
                        type = "contexts";
                        break;

                    case VCARD_TYPE_BILLING:
                    case VCARD_TYPE_DELIVERY:
                        if (prop_kind == VCARD_ADR_PROPERTY) {
                            type = "contexts";
                        }
                        break;

                    case VCARD_TYPE_CELL:
                        val = "mobile";

                        GCC_FALLTHROUGH

                    case VCARD_TYPE_TEXT:
                    case VCARD_TYPE_VOICE:
                    case VCARD_TYPE_FAX:
                    case VCARD_TYPE_VIDEO:
                    case VCARD_TYPE_PAGER:
                    case VCARD_TYPE_TEXTPHONE:
                    case VCARD_TYPE_MAINNUMBER:
                        if (prop_kind == VCARD_TEL_PROPERTY) {
                            type = "features";
                        }
                        break;

                    default:
                        if (prop_kind == VCARD_RELATED_PROPERTY) {
                            type = "relation";
                        }
                        else if (param_flags & ALLOW_SERVICETYPE_PARAM) {
                            goto servicetype;
                        }
                        break;
                    }

                    if (type) {
                        json_t *jprop = json_object_get_vanew(obj, type, "{}");

                        if (!val) {
                            if (e->xvalue) {
                                val = e->xvalue;
                            }
                            else {
                                buf_setcstr(&buf,
                                            vcardparameter_enum_to_string(e->val));
                                val = buf_lcase(&buf);
                            }
                        }

                        json_object_set_new(jprop, val, json_true());
                    }
                    else {
                        /* Unknown/unexpected TYPE */
                        _unmapped_param(obj, param, param_value);
                    }
                }
            }
            continue;

        case VCARD_TZ_PARAMETER:
            if (prop_kind == VCARD_ADR_PROPERTY) {
                /* XXX  TODO: Check for URI or UTC-OFFSET */
                json_object_set_new(obj, "timeZone",
                                    json_string(param_value));
                continue;
            }
            break;

        username:
        case VCARD_USERNAME_PARAMETER:
            if (param_flags & ALLOW_SERVICETYPE_PARAM) {
                json_object_set_new(obj, "user", jmap_utf8string(param_value));
                continue;
            }
            break;

        case VCARD_VALUE_PARAMETER:
            /* Should be handled by the properties that use it */
            continue;

        case VCARD_X_PARAMETER:
            if ((param_flags & ALLOW_SERVICETYPE_PARAM) &&
                !strcasecmp(vcardparameter_get_xname(param), "X-SERVICE-TYPE")) {
                goto servicetype;
            }
            else if ((param_flags & ALLOW_USERNAME_PARAM) &&
                !strcasecmp(vcardparameter_get_xname(param), "X-USER")) {
                goto username;
            }
            break;

        default:
            break;
        }

        /* Unknown/unexpected parameter [value]*/
        _unmapped_param(obj, param, param_value);
    }

    buf_free(&buf);
}

#define IGNORE_VCARD_VERSION  (1<<0)
#define IGNORE_DERIVED_PROPS  (1<<1)
#define DISABLE_URI_AS_BLOBID (1<<2)

struct card_rock {
    json_t *card;
    json_t *patch;
    const char *deflang;
    hash_table *labels;
    hash_table *adrs;
    hash_table *orgs;
    struct carddav_db *db;
    struct mailbox *mailbox;
    struct index_record *record;
    unsigned flags;
    struct buf *buf;
    vcardproperty_version version;
};

static void jscomps_from_vcard(json_t *obj, vcardproperty *prop,
                               vcardstructuredtype *st,
                               const struct comp_kind *comp_kinds)
{
    vcardparameter *param;
    vcardstrarray *sa;
    const char *val, *val_prop_name = "value";
    json_t *comps, *comp = NULL;
    size_t i, j = 0;

    param = vcardproperty_get_first_parameter(prop, VCARD_PHONETIC_PARAMETER);
    if (param) {
        vcardparameter_phonetic phonetic = vcardparameter_get_phonetic(param);
        struct buf buf = BUF_INITIALIZER;

        if (phonetic == VCARD_PHONETIC_X) {
            buf_setcstr(&buf, vcardparameter_get_xvalue(param));
        }
        else {
            buf_setcstr(&buf, vcardparameter_enum_to_string(phonetic));
            buf_lcase(&buf);
        }
        json_object_set_new(obj, "phoneticSystem",
                            json_string(buf_cstring(&buf)));
        buf_free(&buf);

        val_prop_name = "phonetic";

        /* Remove PHONETIC parameter */
        vcardproperty_remove_parameter_by_ref(prop, param);
    }

    param = vcardproperty_get_first_parameter(prop, VCARD_SCRIPT_PARAMETER);
    if (param) {
        json_object_set_new(obj, "phoneticScript",
                            json_string(vcardparameter_get_script(param)));

        /* Remove SCRIPT parameter */
        vcardproperty_remove_parameter_by_ref(prop, param);
    }

    param = vcardproperty_get_first_parameter(prop, VCARD_JSCOMPS_PARAMETER);
    if (param) {
        /* Order components per JSCOMPS */
        vcardstructuredtype *jscomps = vcardparameter_get_jscomps(param);

        json_object_set_new(obj, "isOrdered", json_true());

        sa = jscomps->field[0];
        if (sa) {
            /* add default separator, if not " " */
            val = vcardstrarray_element_at(sa, 1);
            if (strcmpsafe(" ", val)) {
                json_object_set_new(obj, "defaultSeparator", json_string(val));
            }
        }

        for (i = 1; i < jscomps->num_fields; i++) {
            const char *kind;

            sa = jscomps->field[i];
            val = vcardstrarray_element_at(sa, 0);
            if (*val == 's') {
                kind = "separator";
                val = vcardstrarray_element_at(sa, 1);
            }
            else {
                int field_idx = atoi(val);
                int val_idx = 0;

                if (field_idx >= (int) st->num_fields) continue;

                kind = comp_kinds[field_idx].name;

                if (vcardstrarray_size(sa) > 1)
                    val_idx = atoi(vcardstrarray_element_at(sa, 1));

                val = vcardstrarray_element_at(st->field[field_idx], val_idx);
            }

            if (*val) {
                /* This assumes that JSCOMPS are identical
                   for props paired by ALTID */
                comps = json_object_get_vanew(obj, "components", "[]");
                if (json_array_size(comps) > j) {
                    /* Grab the existing component by position */
                    comp = json_array_get(comps, j);
                }
                else {
                    comp = json_pack("{s:s}", "kind", kind);
                    json_array_append_new(comps, comp);
                }
                json_object_set_new(comp, val_prop_name, jmap_utf8string(val));
                j++;
            }
        }

        /* Remove JSCOMPS parameter */
        vcardproperty_remove_parameter_by_ref(prop, param);
        return;
    }

    /* Iterate through all components and values */
    for (const struct comp_kind *ckind = comp_kinds;
         ckind->name && ckind->idx < st->num_fields; ckind++) {
        if ((ckind->flags & FIELD_SKIP) && st->num_fields > ckind->alt_idx)
            continue;

        sa = st->field[ckind->idx];
        for (i = 0; sa && i < vcardstrarray_size(sa); i++) {
            val = vcardstrarray_element_at(sa, i);

            if (*val) {
                /* Skip values that appear in other fields */
                if (ckind->flags & FIELD_EXT) {
                    vcardstrarray *alt_sa = st->field[ckind->alt_idx];
                    if (alt_sa && vcardstrarray_find(alt_sa, val) >= 0)
                        continue;
                }

                comps = json_object_get_vanew(obj, "components", "[]");
                if (json_array_size(comps) > j) {
                    size_t k;

                    /* Find the existing component by name */
                    json_array_foreach(comps, k, comp) {
                        if (!strcmp(ckind->name,
                                    json_string_value(json_object_get(comp, "kind")))) {
                            break;
                        }
                    }
                    if (k > json_array_size(comps)) continue;
                }
                else {
                    comp = json_pack("{s:s}", "kind", ckind->name);
                    json_array_append_new(comps, comp);
                }
                json_object_set_new(comp, val_prop_name, jmap_utf8string(val));
                j++;
            }
        }
    }
}

static void jsprop_from_vcard(vcardproperty *prop, json_t *obj,
                              const char *prop_id, struct card_rock *crock)
{
    vcardparameter *param;

    if ((crock->flags & IGNORE_DERIVED_PROPS) &&
        (param = vcardproperty_get_first_parameter(prop,
                                                   VCARD_DERIVED_PARAMETER)) &&

        vcardparameter_get_derived(param) == VCARD_DERIVED_TRUE) {
        /* Don't convert this property */
        return;
    }

    vcardproperty_kind prop_kind = vcardproperty_isa(prop);
    const char *prop_group = vcardproperty_get_group(prop);
    vcardvalue *value = vcardproperty_get_value(prop);
    const char *prop_value;
    const char *label = prop_group ?  /* Apple label? */
        hash_lookup(prop_group, crock->labels) : NULL;
    unsigned param_flags = 0;
    const char *kind = NULL;
    json_t *jprop = NULL;
    struct {
        const char *key;
        json_t *val;
    } subprop = { 0 };

    switch (vcardvalue_isa(value)) {
    case VCARD_X_VALUE:
        prop_value = vcardvalue_get_x(value);
        break;

    case VCARD_TEXT_VALUE:
        prop_value = vcardvalue_get_text(value);
        break;

    default:
        prop_value = vcardvalue_as_vcard_string(value);
        break;
    }

    switch (prop_kind) {
        /* Apple Properties */
    case VCARD_X_PROPERTY: {
        const char *prop_name = vcardproperty_get_property_name(prop);

        if (!strcmp(prop_name, "X-ADDRESSBOOKSERVER-KIND")) {
            goto kind;
        }
        else if (!strcmp(prop_name, "X-ADDRESSBOOKSERVER-MEMBER")) {
            goto member;
        }
        else if (!strcmp(prop_name, "X-FM-OTHERACCOUNT-MEMBER")) {
            goto member;
        }
        else if (!strcasecmp(prop_name, "X-SOCIAL-PROFILE")) {
            kind = "x-social-profile";
            goto online;
        }
        else if (!strcasecmp(prop_name, "X-FM-ONLINE-OTHER")) {
            goto online;
        }
        else if (prop_group) {
            if (!strcasecmp(prop_name, VCARD_APPLE_ABADR_PROPERTY)) {
                kind = "countryCode";
                buf_setcstr(crock->buf, prop_value);
                prop_value = buf_lcase(crock->buf);
                goto grouped_geo;
            }
            else if (!strcasecmp(prop_name, VCARD_APPLE_LABEL_PROPERTY)) {
                /* Ignore -- handled elsewhere */
                return;
            }
        }

        goto unmapped;
    }

        /* General Properties */
    kind:
    case VCARD_KIND_PROPERTY:
        buf_setcstr(crock->buf, prop_value);
        json_object_set_new(obj, "kind", json_string(buf_lcase(crock->buf)));
        break;

    case VCARD_SOURCE_PROPERTY:
        kind = "entry";

    directories:
        {
            json_t *dirs = json_object_get_vanew(obj, "directories", "{}");

            param_flags = ALLOW_TYPE_PARAM | ALLOW_PREF_PARAM |
                ALLOW_LABEL_PARAM | ALLOW_MEDIATYPE_PARAM;

            jprop = json_pack("{s:s s:o}",
                              "kind", kind, "uri", jmap_utf8string(prop_value));

            json_object_set_new(dirs, prop_id, jprop);
        }
        break;

    case VCARD_XML_PROPERTY:
        goto unmapped;

        /* Identification Properties */
    case VCARD_BDAY_PROPERTY:
        kind = "birth";

        GCC_FALLTHROUGH

    case VCARD_DEATHDATE_PROPERTY:
        if (!kind) kind = "death";

        GCC_FALLTHROUGH

    case VCARD_ANNIVERSARY_PROPERTY:
        if (!kind) kind = "wedding";

        subprop.key = "date";
        subprop.val = _to_jmap_date(prop);

        param_flags = ALLOW_CALSCALE_PARAM;

    anniversaries:
        {
            json_t *annivs = json_object_get_vanew(obj, "anniversaries", "{}");

            jprop = json_object_get_vanew(annivs, prop_id, "{s:s}", "kind", kind);

            json_object_set_new(jprop, subprop.key, subprop.val);
        }
        break;

    case VCARD_BIRTHPLACE_PROPERTY:
        kind = "birth";

        GCC_FALLTHROUGH

    case VCARD_DEATHPLACE_PROPERTY: {
        if (!kind) kind = "death";

        const char *comp = "full";
            
        param = vcardproperty_get_first_parameter(prop, VCARD_VALUE_PARAMETER);
        if (param && vcardparameter_get_value(param) == VCARD_VALUE_URI) {
            if (!strncmp(prop_value, "geo", 4)) {
                comp = "coordinates";
            }
            else {
                goto unmapped;
            }
        }

        subprop.key = "place";
        subprop.val = json_pack("{s:o}", comp, jmap_utf8string(prop_value));

        goto anniversaries;
    }

    case VCARD_GRAMGENDER_PROPERTY: {
        json_t *speakto = json_object_get_vanew(obj, "speakToAs", "{}");

        buf_setcstr(crock->buf, prop_value);
        json_object_set_new(speakto, "grammaticalGender",
                            json_string(buf_lcase(crock->buf)));
        break;
    }

    case VCARD_PRONOUNS_PROPERTY: {
        json_t *speakto = json_object_get_vanew(obj, "speakToAs", "{}");
        json_t *pronouns = json_object_get_vanew(speakto, "pronouns", "{}");

        param_flags = ALLOW_TYPE_PARAM | ALLOW_PREF_PARAM;

        jprop = json_pack("{s:o}", "pronouns", jmap_utf8string(prop_value));

        json_object_set_new(pronouns, prop_id, jprop);
        break;
    }

    case VCARD_FN_PROPERTY:
        json_object_set_new(json_object_get_vanew(obj, "name", "{}"),
                            "full", jmap_utf8string(prop_value));
        break;

    case VCARD_N_PROPERTY: {
        vcardstructuredtype *n = vcardproperty_get_n(prop);

        jprop = json_object_get_vanew(obj, "name", "{}");

        jscomps_from_vcard(jprop, prop, n, n_comp_kinds);

        param = vcardproperty_get_first_parameter(prop, VCARD_SORTAS_PARAMETER);
        if (param) {
            vcardstrarray *sorts = vcardparameter_get_sortas(param);
            json_t *sortas = json_object();
            const struct comp_kind *ckind;

            for (ckind = n_comp_kinds; ckind->name; ckind++) {
                if (ckind->idx < vcardstrarray_size(sorts)) {
                    const char *val =
                        vcardstrarray_element_at(sorts, ckind->idx);

                    if (*val) {
                        json_object_set_new(sortas,
                                            ckind->name, jmap_utf8string(val));
                    }
                }
            }

            json_object_set_new(jprop, "sortAs", sortas);

            /* Remove SORT-AS parameter */
            vcardproperty_remove_parameter_by_ref(prop, param);
        }
        break;
    }

    case VCARD_NICKNAME_PROPERTY: {
        json_t *nicks = json_object_get_vanew(obj, "nicknames", "{}");
        vcardstrarray *names = vcardproperty_get_nickname(prop);
        size_t i;

        param_flags = ALLOW_TYPE_PARAM | ALLOW_PREF_PARAM;

        for (i = 0; i < vcardstrarray_size(names); i++) {
            const char *name = vcardstrarray_element_at(names, i);

            jprop = json_pack("{s:o}", "name", jmap_utf8string(name));

            json_object_set_new(nicks, prop_id, jprop);
        }
        break;
    }

    case VCARD_PHOTO_PROPERTY:
        kind = "photo";

    media:
        {
            json_t *media = json_object_get_vanew(obj, "media", "{}");
            char *uri = NULL, *type = NULL, *blobid = NULL;

            param_flags = ALLOW_TYPE_PARAM | ALLOW_PREF_PARAM |
                ALLOW_LABEL_PARAM | ALLOW_MEDIATYPE_PARAM;

            uri = _value_to_uri_blobid(prop,
                    crock->mailbox, crock->record, crock->version,
                    &type, crock->flags & DISABLE_URI_AS_BLOBID ? NULL : &blobid);

            jprop = json_pack("{s:s s:s* s:s* s:s*}",
                              "kind", kind, "mediaType", type,
                              "uri", uri, "blobId", blobid);

            json_object_set_new(media, prop_id, jprop);

            free(blobid);
            free(type);
            free(uri);
        }
        break;

        /* Delivery Addressing Properties */
    case VCARD_ADR_PROPERTY: {
        vcardstructuredtype *adr = vcardproperty_get_adr(prop);
        json_t *addrs = json_object_get_vanew(obj, "addresses", "{}");

        param_flags = ALLOW_TYPE_PARAM | ALLOW_PREF_PARAM | ALLOW_LABEL_PARAM;

        jprop = json_object_get_vanew(addrs, prop_id, "{}");

        param = vcardproperty_get_first_parameter(prop, VCARD_LABEL_PARAMETER);
        if (param) {
            json_object_set_new(jprop, "full",
                                jmap_utf8string(vcardparameter_get_label(param)));

            /* Remove LABEL parameter */
            vcardproperty_remove_parameter_by_ref(prop, param);
        }

        jscomps_from_vcard(jprop, prop, adr, adr_comp_kinds);
        break;
    }

        /* Communications Properties */
    case VCARD_EMAIL_PROPERTY: {
        json_t *emails = json_object_get_vanew(obj, "emails", "{}");

        param_flags = ALLOW_TYPE_PARAM |
            ALLOW_PREF_PARAM | ALLOW_LABEL_PARAM;

        jprop = json_pack("{s:o}", "address", jmap_utf8string(prop_value));

        json_object_set_new(emails, prop_id, jprop);
        break;
    }

    case VCARD_IMPP_PROPERTY:
        kind = "impp";

        goto online;

    case VCARD_SOCIALPROFILE_PROPERTY:
        kind = "socialprofile";

    online:
        {
            json_t *user = NULL, *uri = NULL;
            json_t *services = json_object_get_vanew(obj, "onlineServices", "{}");

            param_flags = ALLOW_TYPE_PARAM | ALLOW_PREF_PARAM |
                ALLOW_LABEL_PARAM | ALLOW_SERVICETYPE_PARAM;

            param = vcardproperty_get_first_parameter(prop, VCARD_VALUE_PARAMETER);
            if ((param && vcardparameter_get_value(param) == VCARD_VALUE_TEXT) ||
                (prop_value && *prop_value && !strchr(prop_value, ':'))) {
                user = jmap_utf8string(prop_value);
            }
            else {
                if (prop_value && *prop_value)
                    uri = jmap_utf8string(prop_value);

                param_flags |= ALLOW_USERNAME_PARAM;
            }

            jprop = json_pack("{s:o* s:o* s:s*}",
                              "user", user, "uri", uri, "vCardName", kind);

            json_object_set_new(services, prop_id, jprop);
        }
        break;

    case VCARD_LANG_PROPERTY: {
        json_t *langs = json_object_get_vanew(obj, "preferredLanguages", "{}");

        param_flags = ALLOW_TYPE_PARAM | ALLOW_PREF_PARAM;

        jprop = json_pack("{s:o}", "language", jmap_utf8string(prop_value));

        json_object_set_new(langs, prop_id, jprop);
        break;
    }

    case VCARD_LANGUAGE_PROPERTY:
        json_object_set_new(obj, "language", jmap_utf8string(prop_value));
        break;

    case VCARD_TEL_PROPERTY: {
        json_t *phones = json_object_get_vanew(obj, "phones", "{}");

        param_flags = ALLOW_TYPE_PARAM |
            ALLOW_PREF_PARAM | ALLOW_LABEL_PARAM;

        jprop = json_pack("{s:o}", "number", jmap_utf8string(prop_value));

        json_object_set_new(phones, prop_id, jprop);
        break;
    }

        /* Geographical Properties */
    case VCARD_GEO_PROPERTY: {
        vcardgeotype geo = vcardproperty_get_geo(prop);

        kind = "coordinates";

        if (geo.uri) {
            prop_value = geo.uri;
        }
        else {
            buf_reset(crock->buf);
            buf_printf(crock->buf, "geo:%s,%s", geo.coords.lat, geo.coords.lon);
            prop_value = buf_cstring(crock->buf);
        }

        GCC_FALLTHROUGH
    }

    case VCARD_TZ_PROPERTY:
        if (!kind) {
            vcardtztype tz = vcardproperty_get_tz(prop);

            kind = "timeZone";

            if (tz.uri) {
                goto unmapped;
            }
            else if (tz.tzid) {
                prop_value = tz.tzid;
            }
            else if (!tz.utcoffset) {
                prop_value = "Etc/UTC";
            }
            else {
                buf_reset(crock->buf);
                buf_printf(crock->buf, "Etc/GMT%+d", -tz.utcoffset / 3600);
                prop_value = buf_cstring(crock->buf);
            }
        }

    grouped_geo:
        {
            strarray_t *ids =
                hash_lookup(prop_group ? prop_group : "", crock->adrs);

            if (!ids) goto unmapped;

            for (int i = 0; i < strarray_size(ids); i++) {
                json_t *addrs = json_object_get_vanew(obj, "addresses", "{}");
                const char *prop_id = strarray_nth(ids, i);

                jprop = json_object_get_vanew(addrs, prop_id, "{}");

                json_object_set_new(jprop, kind, json_string(prop_value));
            }
        }
        break;

        /* Organizational Properties */
    case VCARD_CONTACTURI_PROPERTY:
        kind = "contact";

    links:
        {
            json_t *links = json_object_get_vanew(obj, "links", "{}");

            param_flags = ALLOW_TYPE_PARAM |
                ALLOW_PREF_PARAM | ALLOW_LABEL_PARAM;

            jprop = json_pack("{s:s* s:o}",
                              "kind", kind, "uri", jmap_utf8string(prop_value));

            json_object_set_new(links, prop_id, jprop);
        }
        break;

    case VCARD_LOGO_PROPERTY:
        kind = "logo";
        goto media;

    member:
    case VCARD_MEMBER_PROPERTY: {
        json_t *members = json_object_get_vanew(obj, "members", "{}");
        struct carddav_data *cdata = NULL;
        int r = carddav_lookup_uid(crock->db, prop_value, &cdata);

        if (r == CYRUSDB_NOTFOUND &&
            !strncmp(prop_value, "urn:uuid:", 9) &&
            !carddav_lookup_uid(crock->db, prop_value+9, &cdata)) {
            prop_value += 9;
        }

        json_object_set_new(members, prop_value, json_true());

        break;
    }

    case VCARD_ORG_PROPERTY: {
        json_t *orgs = json_object_get_vanew(obj, "organizations", "{}");
        vcardstrarray *org = vcardproperty_get_org(prop);
        const char *name = vcardstrarray_element_at(org, 0);
        size_t num_comp = vcardstrarray_size(org);
        json_t *units = num_comp > 1 ? json_array() : NULL;
        vcardstrarray *sortas = NULL;
        const char *sort = NULL;

        param = vcardproperty_get_first_parameter(prop, VCARD_SORTAS_PARAMETER);
        if (param) {
            sortas = vcardparameter_get_sortas(param);
            sort = vcardstrarray_element_at(sortas, 0);
            if (!*sort) sort = NULL;
        }

        jprop = json_pack("{s:o* s:o* s:s*}",
                          "name", *name ? jmap_utf8string(name) : NULL,
                          "units", units, "sortAs", sort);

        for (size_t i = 1; i < num_comp; i++) {
            name = vcardstrarray_element_at(org, i);
            if (sortas && i < vcardstrarray_size(sortas)) {
                sort = vcardstrarray_element_at(sortas, i);
                if (!*sort) sort = NULL;
            }
            else {
                sort = NULL;
            }
            json_array_append_new(units,
                                  json_pack("{s:o s:s*}",
                                            "name", jmap_utf8string(name),
                                            "sortAs", sort));
        }

        /* Remove SORT-AS parameter */
        if (param) {
            vcardproperty_remove_parameter_by_ref(prop, param);
        }

        json_object_set_new(orgs, prop_id, jprop);
        break;
    }

    case VCARD_RELATED_PROPERTY: {
        json_t *relatedto = json_object_get_vanew(obj, "relatedTo", "{}");

        param_flags = ALLOW_TYPE_PARAM;

        jprop = json_pack("{s:{}}", "relation");

        json_object_set_new(relatedto, prop_value, jprop);
        break;
    }

    case VCARD_ROLE_PROPERTY:
        kind = "role";

        GCC_FALLTHROUGH

    case VCARD_TITLE_PROPERTY: {
        json_t *titles = json_object_get_vanew(obj, "titles", "{}");
        const char *org = NULL;

        if (prop_group) {
            org = hash_lookup(prop_group, crock->orgs);
        }

        json_object_set_new(titles, prop_id,
                            json_pack("{s:s* s:o s:s*}",
                                      "kind", kind,
                                      "name", jmap_utf8string(prop_value),
                                      "organizationId", org));
        break;
    }

        /* Personal Information Properties */
    case VCARD_EXPERTISE_PROPERTY:
    case VCARD_HOBBY_PROPERTY:
    case VCARD_INTEREST_PROPERTY: {
        json_t *personal = json_object_get_vanew(obj, "personalInfo", "{}");

        param_flags = ALLOW_INDEX_PARAM | ALLOW_LEVEL_PARAM;

        buf_setcstr(crock->buf, vcardproperty_get_property_name(prop));

        jprop = json_object_get_vanew(personal, prop_id,
                                      "{s:s s:s}",
                                      "kind", buf_lcase(crock->buf),
                                      "value", prop_value);
        break;
    }

    case VCARD_ORGDIRECTORY_PROPERTY:
        kind = "directory";
        goto directories;

        /* Explanatory Properties */
    case VCARD_CATEGORIES_PROPERTY: {
        json_t *keywords = json_object_get_vanew(obj, "keywords", "{}");
        vcardstrarray *cat = vcardproperty_get_categories(prop);
        size_t i;

        for (i = 0; i < vcardstrarray_size(cat); i++) {
            json_object_set_new(keywords,
                                vcardstrarray_element_at(cat, i), json_true());
        }
        break;
    }

    case VCARD_CLIENTPIDMAP_PROPERTY:
        goto unmapped;

    case VCARD_CREATED_PROPERTY:
        json_object_set_new(obj, "created",
                            vcardtime_to_jmap_utcdate(vcardproperty_get_created(prop)));
        break;

    case VCARD_NOTE_PROPERTY: {
        json_t *notes = json_object_get_vanew(obj, "notes", "{}");

        jprop = json_pack("{s:o}", "note", jmap_utf8string(prop_value));

        json_object_set_new(notes, prop_id, jprop);
        break;
    }

    case VCARD_PRODID_PROPERTY:
        json_object_set_new(obj, "prodId", jmap_utf8string(prop_value));
        break;

    case VCARD_REV_PROPERTY:
        json_object_set_new(obj, "updated",
                            vcardtime_to_jmap_utcdate(vcardproperty_get_rev(prop)));
        break;

    case VCARD_SOUND_PROPERTY:
        kind = "sound";
        goto media;

    case VCARD_UID_PROPERTY:
        json_object_set_new(obj, "uid", jmap_utf8string(prop_value));
        break;

    case VCARD_URL_PROPERTY:
        goto links;

    case VCARD_VERSION_PROPERTY:
        if (crock->flags & IGNORE_VCARD_VERSION) break;
        else goto unmapped;

        /* Security Properties */
    case VCARD_KEY_PROPERTY: {
        json_t *keys = json_object_get_vanew(obj, "cryptoKeys", "{}");
        char *uri = NULL, *type = NULL, *blobid = NULL;

        param_flags = ALLOW_TYPE_PARAM | ALLOW_PREF_PARAM |
            ALLOW_LABEL_PARAM | ALLOW_MEDIATYPE_PARAM;

        uri = _value_to_uri_blobid(prop,
                crock->mailbox, crock->record, crock->version,
                &type, crock->flags & DISABLE_URI_AS_BLOBID ? NULL : &blobid);

        jprop = json_pack("{s:s* s:s* s:s*}",
                          "mediaType", type, "uri", uri, "blobId", blobid);

        json_object_set_new(keys, prop_id, jprop);

        free(blobid);
        free(type);
        free(uri);
        break;
    }

        /* Calendar Properties */
    case VCARD_CALADRURI_PROPERTY: {
        json_t *addrs = json_object_get_vanew(obj, "schedulingAddresses", "{}");

        param_flags = ALLOW_TYPE_PARAM | ALLOW_PREF_PARAM | ALLOW_LABEL_PARAM;

        jprop = json_pack("{s:s}", "uri", prop_value);

        json_object_set_new(addrs, prop_id, jprop);
        break;
    }

    case VCARD_CALURI_PROPERTY:
        kind = "calendar";

        GCC_FALLTHROUGH

    case VCARD_FBURL_PROPERTY: {
        json_t *cals = json_object_get_vanew(obj, "calendars", "{}");

        if (!kind) kind = "freeBusy";

        param_flags = ALLOW_TYPE_PARAM | ALLOW_PREF_PARAM |
            ALLOW_LABEL_PARAM | ALLOW_MEDIATYPE_PARAM;

        jprop = json_pack("{s:s s:s}", "kind", kind, "uri", prop_value);

        json_object_set_new(cals, prop_id, jprop);
        break;
    }

        /* Custom JSContact Properties */
    case VCARD_JSPROP_PROPERTY: {
        json_t *val = json_loads(vcardproperty_get_jsprop(prop),
                                 JSON_DECODE_ANY, NULL);
        if (val) {
            param = vcardproperty_get_first_parameter(prop,
                                                      VCARD_JSPTR_PARAMETER);

            if (!crock->patch) crock->patch = json_object();
            json_object_set_new(crock->patch,
                                vcardparameter_get_jsptr(param), val);
        }
        break;
    }

        /* Unmapped Properties (jCard-encoded) */
    unmapped:
    default: {
        json_t *props = json_object_get_vanew(obj, "vCardProps", "[]");
        json_t *jtype, *jparams = json_object();
        const char *type = NULL;
        vcardvalue_kind vkind;

        for (param = vcardproperty_get_first_parameter(prop,
                                                       VCARD_ANY_PARAMETER);
             param;
             param = vcardproperty_get_next_parameter(prop,
                                                      VCARD_ANY_PARAMETER)) {
            vcardparameter_kind param_kind = vcardparameter_isa(param);
            char *param_str = vcardparameter_as_vcard_string(param);
            char *param_value = strchr(param_str, '=') + 1;

            buf_setcstr(crock->buf, vcardparameter_kind_to_string(param_kind));

            if (param_kind == VCARD_VALUE_PARAMETER) {
                type = lcase(param_value);
            }
            else {
                int is_multivalued = 0;  /* XXX  Create JSON array? */
                json_t *val;

                vkind = vcardparameter_kind_value_kind(param_kind, &is_multivalued);

                switch (vkind) {
                case VCARD_INTEGER_VALUE:
                    val = json_integer(vcardparameter_get_index(param));
                    break;

                case VCARD_BOOLEAN_VALUE:
                    val = json_boolean(VCARD_DERIVED_TRUE ==
                                       vcardparameter_get_derived(param));
                    break;

                default:
                    val = jmap_utf8string(param_value);
                    break;
                }

                json_object_set_new(jparams, buf_lcase(crock->buf), val);
            }
        }

        if (!type) {
            vkind = vcardproperty_kind_to_value_kind(prop_kind);

            switch (vkind) {
            case VCARD_X_VALUE:
            case VCARD_NO_VALUE:
                type = "unknown";
                break;
                    
            case VCARD_TZ_VALUE:
            case VCARD_GEO_VALUE:
            case VCARD_KIND_VALUE:
            case VCARD_TEXT_VALUE:
            case VCARD_VERSION_VALUE:
            case VCARD_TEXTLIST_VALUE:
            case VCARD_GRAMGENDER_VALUE:
            case VCARD_STRUCTURED_VALUE:
                type = "text";
                break;

            default:
                buf_setcstr(crock->buf, vcardvalue_kind_to_string(vkind));
                type = buf_lcase(crock->buf);
                break;
            }
        }

        jtype = json_string(type);

        if (prop_group) {
            json_object_set_new(jparams, "group", jmap_utf8string(prop_group));

            if (label) {
                /* Apple label */
                buf_setcstr(crock->buf, VCARD_APPLE_LABEL_PROPERTY);
                json_array_append_new(props,
                                      json_pack("[s {s:o} s o]",
                                                buf_lcase(crock->buf),
                                                "group",
                                                jmap_utf8string(prop_group),
                                                "text",
                                                jmap_utf8string(label)));
            }
        }

        buf_setcstr(crock->buf, vcardproperty_get_property_name(prop));
        json_array_append_new(props,
                              json_pack("[s o o o]",
                                        buf_lcase(crock->buf), jparams, jtype,
                                        jmap_utf8string(prop_value)));
        return;
    }
    }

    if (jprop) {
        _add_vcard_params(jprop, prop, param_flags);

        if (label && (param_flags & ALLOW_LABEL_PARAM)) {
            /* Apple label */
            json_object_set_new(jprop, "label", jmap_utf8string(label));
        }
    }
}

static void free_props_by_altid(void *val)
{
    free_hash_table((hash_table *) val, (void (*)(void *)) &ptrarray_free);
    free(val);
}

static void props_by_altid_cb(const char *altid, void *val, void *rock)
{
    ptrarray_t *props = val;
    struct card_rock *crock = rock;
    const char *prop_id = NULL;
    int i;

    /* Look for property with default language and translate it into the Card */
    for (i = 0; i < ptrarray_size(props); i++) {
        vcardproperty *prop = ptrarray_nth(props, i);
        const char *lang = NULL;

        vcardparameter *param =
            vcardproperty_get_first_parameter(prop, VCARD_LANGUAGE_PARAMETER);
        if (param) {
            lang = vcardparameter_get_language(param);
        }

        if (!lang || !strcmpsafe(lang, crock->deflang)) {
            ptrarray_remove(props, i);
            prop_id = *altid ? altid : _prop_id(prop);
            jsprop_from_vcard(prop, crock->card, prop_id, crock);
            break;
        }
    }

    /* Process the remaining properties with non-default languages */
    for (i = 0; i < ptrarray_size(props); i++) {
        vcardproperty *prop = ptrarray_nth(props, i);
        vcardparameter *param =
            vcardproperty_get_first_parameter(prop, VCARD_LANGUAGE_PARAMETER);

        if (param) {
            /* Translate into the "localizations" property as a patch */
            const char *lang = vcardparameter_get_language(param);
            json_t *l10n =
                json_object_get_vanew(crock->card, "localizations", "{}");
            json_t *tmp = json_object();

            if (!prop_id) prop_id = *altid ? altid : _prop_id(prop);

            jsprop_from_vcard(prop, tmp, prop_id, crock);
            json_object_update_new(json_object_get_vanew(l10n, lang, "{}"),
                                   jmap_patchobject_create(crock->card, tmp,
                                                           PATCH_NO_REMOVE |
                                                           PATCH_ALLOW_ARRAY));
            json_decref(tmp);
        }
        else {
            /* No language - translate into the toplevel Card */
            jsprop_from_vcard(prop, crock->card, _prop_id(prop), crock);
        }
    }
}

static void props_by_name_cb(const char *name __attribute__((unused)),
                             void *val, void *rock)
{
    hash_enumerate((hash_table *) val, &props_by_altid_cb, rock);
}

/* Convert the vCard to JSContact Card properties */
static json_t *jmap_card_from_vcard(const char *userid,
                                    vcardcomponent *vcard,
                                    struct carddav_db *db,
                                    struct mailbox *mailbox,
                                    struct index_record *record,
                                    unsigned flags)
{
    /* Default to kind:individual for /query.
       Will be overwritten by KIND property if present. */
    json_t *jcard = json_pack("{s:s s:s s:s}",
                              "@type", "Card",
                              "version", "1.0",
                              "kind", "individual");
    hash_table props_by_name = HASH_TABLE_INITIALIZER;
    hash_table labels = HASH_TABLE_INITIALIZER;
    hash_table adrs = HASH_TABLE_INITIALIZER;
    hash_table orgs = HASH_TABLE_INITIALIZER;
    struct buf buf = BUF_INITIALIZER;
    struct card_rock crock = {
        jcard, NULL, NULL, &labels, &adrs, &orgs,
        db, mailbox, record, flags, &buf, VCARD_VERSION_NONE
    };
    vcardproperty *prop;
    vcardparameter *param;

    /* Iterate through the vCard properties:
       - Fetch VERSION for sanity checking
       - Fetch LANGUAGE for localizations
       - Fetch ADRs for combining with geographic properties
       - Fetch ORGs for pairing with grouped TITLE/ROLE
       - Fetch Apple-style labels for pairing with grouped properties
       - Sort them by name and then by altid for calculating localizations
    */
    size_t nprops = vcardcomponent_count_properties(vcard, VCARD_ANY_PROPERTY, 0);
    construct_hash_table(&props_by_name, nprops + 1, 0);
    construct_hash_table(&adrs, nprops + 1, 0);
    construct_hash_table(&orgs, nprops + 1, 0);
    construct_hash_table(&labels, nprops + 1, 0);
    for (prop = vcardcomponent_get_first_property(vcard, VCARD_ANY_PROPERTY);
         prop;
         prop = vcardcomponent_get_next_property(vcard, VCARD_ANY_PROPERTY)) {
        const char *prop_name = vcardproperty_get_property_name(prop);
        const char *group = vcardproperty_get_group(prop);
        const char *altid = "";
        hash_table *props_by_altid;
        ptrarray_t *props;
        int prop_idx = -1;  /* append */

        switch (vcardproperty_isa(prop)) {
        case VCARD_VERSION_PROPERTY:
            crock.version = vcardproperty_get_version(prop);
            break;

        case VCARD_LANGUAGE_PROPERTY:
            crock.deflang = vcardproperty_get_language(prop);
            break;

        case VCARD_ADR_PROPERTY: {
            strarray_t *ids = hash_lookup(group ? group : "", &adrs);

            if (!ids) {
                ids = strarray_new();
                hash_insert(group ? group : "", ids, &adrs);
            }
            strarray_append(ids, _prop_id(prop));

            /* Fall through */
            GCC_FALLTHROUGH
        }

        case VCARD_N_PROPERTY:
            if (vcardproperty_get_first_parameter(prop, VCARD_JSCOMPS_PARAMETER)) {
                /* Always place props with JSCOMPS at the head of the list
                   so the component order is set before handling any PHONETICS */
                prop_idx = 0;
            }
            break;

        case VCARD_ORG_PROPERTY:
            if (group) hash_insert(group, xstrdup(_prop_id(prop)), &orgs);
            break;

        case VCARD_X_PROPERTY:
            if (group && !strcasecmp(prop_name, VCARD_APPLE_LABEL_PROPERTY)) {
                const char *label = vcardproperty_get_value_as_string(prop);
                size_t label_len = strlen(label);

                /* Check and adjust for weird (localized?) labels */
                if (label_len > 8 && !strncmp(label, "_$!<", 4)) {
                    label += 4;      // skip "_$!<" prefix
                    label_len -= 8;  // and trim ">!$_" suffix
                }

                hash_insert(group, xstrndup(label, label_len), &labels);
            }
            break;

        default:
            break;
        }

        param = vcardproperty_get_first_parameter(prop, VCARD_ALTID_PARAMETER);
        if (param) {
            altid = vcardparameter_get_altid(param);
        }

        props_by_altid = hash_lookup(prop_name, &props_by_name);
        if (!props_by_altid) {
            props_by_altid = xzmalloc(sizeof(hash_table));
            construct_hash_table(props_by_altid, nprops + 1, 0);
            hash_insert(prop_name, props_by_altid, &props_by_name);
        }

        props = hash_lookup(altid, props_by_altid);
        if (!props) {
            props = ptrarray_new();
            hash_insert(altid, props, props_by_altid);
        }

        if (prop_idx < 0) {
            ptrarray_append(props, prop);
        }
        else {
            ptrarray_insert(props, prop_idx, prop);
        }
    }

    if (crock.version == VCARD_VERSION_NONE || crock.version == VCARD_VERSION_X)
        goto done;

    /* Don't combine geographical props unless at least one ADR has GROUP set */
    if (hash_numrecords(&adrs) == 1 && hash_lookup("", &adrs)) {
        strarray_free(hash_del("", &adrs));
    }

    /* Translate vCard props to JS props */
    hash_enumerate(&props_by_name, &props_by_name_cb, &crock);

    if (crock.patch) {
        json_t *patched = jmap_patchobject_apply(jcard, crock.patch, NULL, 0);

        json_decref(crock.patch);
        json_decref(jcard);
        jcard = patched;
    }

    /* Record properties */
    if (record) {
        const char *annot = DAV_ANNOT_NS "<" XML_NS_CYRUS ">importance";
        // NOTE: using buf_free here because annotatemore_msg_lookup uses
        // buf_init_ro on the buffer, which blats the base pointer.
        buf_free(&buf);
        annotatemore_msg_lookupmask(mailbox, record->uid, annot, userid, &buf);
        double val = 0;
        if (buf_len(&buf)) val = strtod(buf_cstring(&buf), NULL);

        json_object_set_new(jcard, "cyrusimap.org:importance", json_real(val));
    }

  done:
    buf_free(&buf);
    free_hash_table(&labels, &free);
    free_hash_table(&orgs, &free);
    free_hash_table(&adrs, (void (*)(void *)) &strarray_free);
    free_hash_table(&props_by_name, &free_props_by_altid);

    return jcard;
}

static int getcards_cb(void *rock, struct carddav_data *cdata)
{
    struct cards_rock *crock = (struct cards_rock *) rock;
    struct index_record record;
    json_t *obj = NULL;
    int r = 0;

    mbentry_t *mbentry = jmap_mbentry_from_dav(crock->req, &cdata->dav);

    if (!mbentry ||
        !jmap_hasrights_mbentry(crock->req, mbentry, JACL_READITEMS)) {
        mboxlist_entry_free(&mbentry);
        return 0;
    }

    if (!crock->mailbox || strcmp(mailbox_name(crock->mailbox), mbentry->name)) {
        mailbox_close(&crock->mailbox);
        r = mailbox_open_irl(mbentry->name, &crock->mailbox);
    }
    if (r) goto done;

    r = mailbox_find_index_record(crock->mailbox, cdata->dav.imap_uid, &record);
    if (r) goto done;

    if (!crock->args.disable_uri_as_blobid &&
        cdata->jmapversion == JMAPCACHE_CARDVERSION) {
        /* We only cache contacts with media as blobids */
        json_error_t jerr;
        obj = json_loads(cdata->jmapdata, 0, &jerr);
        if (obj) goto gotvalue;
    }

    /* Load message containing the resource and parse vcard data */
    vcardcomponent *vcard = record_to_vcard_x(crock->mailbox, &record);
    if (!vcard) {
        syslog(LOG_ERR, "record_to_vcard failed for record %u:%s",
                cdata->dav.imap_uid, mailbox_name(crock->mailbox));
        r = IMAP_INTERNAL;
        goto done;
    }

    /* Convert the vCard to a JSContact Card. */
    int from_vcard_flags = IGNORE_DERIVED_PROPS;
    if (crock->args.disable_uri_as_blobid)
        from_vcard_flags |= DISABLE_URI_AS_BLOBID;

    obj = jmap_card_from_vcard(crock->req->userid, vcard, crock->db,
                               crock->mailbox, &record, from_vcard_flags);
    vcardcomponent_free(vcard);

    if (!crock->args.disable_uri_as_blobid) {
        /* Only cache contacts with media as blobids */
        hashu64_insert(cdata->dav.rowid, json_dumps(obj, 0), &crock->jmapcache);
    }

  gotvalue:

    jmap_filterprops(obj, crock->get->props);

    if (jmap_wantprop(crock->get->props, "cyrusimap.org:href")) {
        char *xhref = jmap_xhref(mbentry->name, cdata->dav.resource);
        json_object_set_new(obj, "cyrusimap.org:href", json_string(xhref));
        free(xhref);
    }
    if (jmap_wantprop(crock->get->props, "cyrusimap.org:blobId")) {
        json_t *jblobid = json_null();
        struct buf blobid = BUF_INITIALIZER;
        const char *uniqueid = NULL;

        /* Get uniqueid of calendar mailbox */
        if (!crock->mailbox ||
            strcmp(mailbox_uniqueid(crock->mailbox), cdata->dav.mailbox)) {
            if (!crock->mbentry ||
                strcmp(crock->mbentry->uniqueid, cdata->dav.mailbox)) {
                mboxlist_entry_free(&crock->mbentry);
                crock->mbentry = jmap_mbentry_from_dav(crock->req, &cdata->dav);
            }
            if (crock->mbentry &&
                jmap_hasrights_mbentry(crock->req,
                                       crock->mbentry, JACL_READITEMS)) {
                uniqueid = crock->mbentry->uniqueid;
            }
        }
        else {
            uniqueid = mailbox_uniqueid(crock->mailbox);
        }

        if (uniqueid &&
            jmap_encode_rawdata_blobid('V', uniqueid, record.uid,
                                       NULL, NULL, NULL, NULL, &blobid)) {
            jblobid = json_string(buf_cstring(&blobid));
        }
        buf_free(&blobid);
        json_object_set_new(obj, "cyrusimap.org:blobId", jblobid);
    }
    if (jmap_wantprop(crock->get->props, "cyrusimap.org:size")) {
        json_object_set_new(obj, "cyrusimap.org:size",
                            json_integer(record.size - record.header_size));
    }

    json_object_set_new(obj, "id", json_string(cdata->vcard_uid));
    json_object_set_new(obj, "addressBookIds",
                             json_pack("{s:b}", strrchr(mbentry->name, '.')+1, 1));

    json_array_append_new(crock->get->list, obj);
    crock->rows++;

 done:
    mboxlist_entry_free(&mbentry);

    return 0;
}

/*
 * ContactCard/query
 */

#define card_filter_match_textval   contact_filter_match_textval
#define card_filter_match_textprop  contact_filter_match_textprop

struct card_filter {
    const char *uid;
    hash_table *inCardGroup;
    struct contact_textfilter *fullName;
    struct contact_textfilter *prefix;
    struct contact_textfilter *given;
    struct contact_textfilter *middle;
    struct contact_textfilter *surname;
    struct contact_textfilter *suffix;
    struct contact_textfilter *nickName;
    struct contact_textfilter *organization;
    struct contact_textfilter *title;
    struct contact_textfilter *role;
    struct contact_textfilter *email;
    struct contact_textfilter *phone;
    struct contact_textfilter *online;
    struct contact_textfilter *address;
    struct contact_textfilter *expertise;
    struct contact_textfilter *hobby;
    struct contact_textfilter *interest;
    struct contact_textfilter *note;
    struct contact_textfilter *text;
    struct contact_textfilter *member;
    struct contact_textfilter *kind;
};

/* Free the memory allocated by this card filter. */
static void card_filter_free(void *vf)
{
    struct card_filter *f = (struct card_filter *) vf;

    if (f->inCardGroup) {
        free_hash_table(f->inCardGroup, NULL);
        free(f->inCardGroup);
    }
    contact_textfilter_free(f->fullName);
    contact_textfilter_free(f->prefix);
    contact_textfilter_free(f->given);
    contact_textfilter_free(f->middle);
    contact_textfilter_free(f->surname);
    contact_textfilter_free(f->suffix);
    contact_textfilter_free(f->nickName);
    contact_textfilter_free(f->organization);
    contact_textfilter_free(f->title);
    contact_textfilter_free(f->role);
    contact_textfilter_free(f->email);
    contact_textfilter_free(f->phone);
    contact_textfilter_free(f->online);
    contact_textfilter_free(f->address);
    contact_textfilter_free(f->expertise);
    contact_textfilter_free(f->hobby);
    contact_textfilter_free(f->interest);
    contact_textfilter_free(f->note);
    contact_textfilter_free(f->text);
    contact_textfilter_free(f->member);
    contact_textfilter_free(f->kind);
    free(f);
}

/* Parse the JMAP ContactCard FilterCondition in arg.
 * Report any invalid properties in invalid, prefixed by prefix.
 * Return NULL on error. */
static void *card_filter_parse(json_t *arg)
{
    struct card_filter *f =
        (struct card_filter *) xzmalloc(sizeof(struct card_filter));

    /* inCardGroup */
    json_t *inCardGroup = json_object_get(arg, "inCardGroup");
    if (inCardGroup) {
        f->inCardGroup = xmalloc(sizeof(struct hash_table));
        construct_hash_table(f->inCardGroup,
                             json_array_size(inCardGroup)+1, 0);
        size_t i;
        json_t *val;
        json_array_foreach(inCardGroup, i, val) {
            const char *id;
            if (json_unpack(val, "s", &id) != -1) {
                hash_insert(id, (void*)1, f->inCardGroup);
            }
        }
    }

    /* fullName */
    if (JNOTNULL(json_object_get(arg, "name"))) {
        const char *s = NULL;
        if (jmap_readprop(arg, "name", 0, NULL, "s", &s) > 0) {
            f->fullName = contact_textfilter_new(s);
        }
    }
    /* prefix */
    if (JNOTNULL(json_object_get(arg, "name/prefix"))) {
        const char *s = NULL;
        if (jmap_readprop(arg, "name/prefix", 0, NULL, "s", &s) > 0) {
            f->prefix = contact_textfilter_new(s);
        }
    }
    /* given */
    if (JNOTNULL(json_object_get(arg, "name/given"))) {
        const char *s = NULL;
        if (jmap_readprop(arg, "name/given", 0, NULL, "s", &s) > 0) {
            f->given = contact_textfilter_new(s);
        }
    }
    /* middle */
    if (JNOTNULL(json_object_get(arg, "name/middle"))) {
        const char *s = NULL;
        if (jmap_readprop(arg, "name/middle", 0, NULL, "s", &s) > 0) {
            f->middle = contact_textfilter_new(s);
        }
    }
    /* surname */
    if (JNOTNULL(json_object_get(arg, "name/surname"))) {
        const char *s = NULL;
        if (jmap_readprop(arg, "name/surname", 0, NULL, "s", &s) > 0) {
            f->surname = contact_textfilter_new(s);
        }
    }
    /* suffix */
    if (JNOTNULL(json_object_get(arg, "name/suffix"))) {
        const char *s = NULL;
        if (jmap_readprop(arg, "name/suffix", 0, NULL, "s", &s) > 0) {
            f->suffix = contact_textfilter_new(s);
        }
    }
    /* nickName */
    if (JNOTNULL(json_object_get(arg, "nickName"))) {
        const char *s = NULL;
        if (jmap_readprop(arg, "nickName", 0, NULL, "s", &s) > 0) {
            f->nickName = contact_textfilter_new(s);
        }
    }
    /* organization */
    if (JNOTNULL(json_object_get(arg, "organization"))) {
        const char *s = NULL;
        if (jmap_readprop(arg, "organization", 0, NULL, "s", &s) > 0) {
            f->organization = contact_textfilter_new(s);
        }
    }
    /* title */
    if (JNOTNULL(json_object_get(arg, "title"))) {
        const char *s = NULL;
        if (jmap_readprop(arg, "title", 0, NULL, "s", &s) > 0) {
            f->nickName = contact_textfilter_new(s);
        }
    }
    /* role */
    if (JNOTNULL(json_object_get(arg, "role"))) {
        const char *s = NULL;
        if (jmap_readprop(arg, "role", 0, NULL, "s", &s) > 0) {
            f->role = contact_textfilter_new(s);
        }
    }
    /* email */
    if (JNOTNULL(json_object_get(arg, "email"))) {
        const char *s = NULL;
        if (jmap_readprop(arg, "email", 0, NULL, "s", &s) > 0) {
            f->email = contact_textfilter_new(s);
        }
    }
    /* phone */
    if (JNOTNULL(json_object_get(arg, "phone"))) {
        const char *s = NULL;
        if (jmap_readprop(arg, "phone", 0, NULL, "s", &s) > 0) {
            f->phone = contact_textfilter_new(s);
        }
    }
    /* onlineServices */
    if (JNOTNULL(json_object_get(arg, "onlineService"))) {
        const char *s = NULL;
        if (jmap_readprop(arg, "onlineService", 0, NULL, "s", &s) > 0) {
            f->online = contact_textfilter_new(s);
        }
    }
    /* address */
    if (JNOTNULL(json_object_get(arg, "address"))) {
        const char *s = NULL;
        if (jmap_readprop(arg, "address", 0, NULL, "s", &s) > 0) {
            f->address = contact_textfilter_new(s);
        }
    }
    /* expertise */
    if (JNOTNULL(json_object_get(arg, "expertise"))) {
        const char *s = NULL;
        if (jmap_readprop(arg, "expertise", 0, NULL, "s", &s) > 0) {
            f->expertise = contact_textfilter_new(s);
        }
    }
    /* hobby */
    if (JNOTNULL(json_object_get(arg, "hobby"))) {
        const char *s = NULL;
        if (jmap_readprop(arg, "hobby", 0, NULL, "s", &s) > 0) {
            f->hobby = contact_textfilter_new(s);
        }
    }
    /* interest */
    if (JNOTNULL(json_object_get(arg, "interest"))) {
        const char *s = NULL;
        if (jmap_readprop(arg, "interest", 0, NULL, "s", &s) > 0) {
            f->interest = contact_textfilter_new(s);
        }
    }
    /* note */
    if (JNOTNULL(json_object_get(arg, "note"))) {
        const char *s = NULL;
        if (jmap_readprop(arg, "note", 0, NULL, "s", &s) > 0) {
            f->note = contact_textfilter_new(s);
        }
    }
    /* text */
    if (JNOTNULL(json_object_get(arg, "text"))) {
        const char *s = NULL;
        if (jmap_readprop(arg, "text", 0, NULL, "s", &s) > 0) {
            f->text = contact_textfilter_new(s);
        }
    }
    /* hasMember */
    if (JNOTNULL(json_object_get(arg, "hasMember"))) {
        const char *s = NULL;
        if (jmap_readprop(arg, "hasMember", 0, NULL, "s", &s) > 0) {
            f->member = contact_textfilter_new(s);
        }
    }
    /* kind */
    if (JNOTNULL(json_object_get(arg, "kind"))) {
        const char *s = NULL;
        if (jmap_readprop(arg, "kind", 0, NULL, "s", &s) > 0) {
            f->kind = contact_textfilter_new(s);
        }
    }
    /* uid */
    if (JNOTNULL(json_object_get(arg, "uid"))) {
        jmap_readprop(arg, "uid", 0, NULL, "s", &f->uid);
    }

    return f;
}

static void card_filter_validate(jmap_req_t *req __attribute__((unused)),
                                 struct jmap_parser *parser,
                                 json_t *filter,
                                 json_t *unsupported __attribute__((unused)),
                                 void *rock,
                                 json_t **err __attribute__((unused)))
{
    const char *field;
    json_t *arg;
    void *tmp;

    json_object_foreach_safe(filter, tmp, field, arg) {
        if (!strcmp(field, "name") ||
            !strcmp(field, "name/prefix") ||
            !strcmp(field, "name/given") ||
            !strcmp(field, "name/middle") ||
            !strcmp(field, "name/surname") ||
            !strcmp(field, "name/suffix") ||
            !strcmp(field, "nickName") ||
            !strcmp(field, "organization") ||
            !strcmp(field, "title") ||
            !strcmp(field, "role") ||
            !strcmp(field, "email") ||
            !strcmp(field, "phone") ||
            !strcmp(field, "onlineService") ||
            !strcmp(field, "address") ||
            !strcmp(field, "expertise") ||
            !strcmp(field, "hobby") ||
            !strcmp(field, "interest") ||
            !strcmp(field, "note") ||
            !strcmp(field, "text") ||
            !strcmp(field, "kind") ||
            !strcmp(field, "hasMember") ||
            !strcmp(field, "uid")) {
            if (!json_is_string(arg)) {
                jmap_parser_invalid(parser, field);
            }

            if (*field == 'k') {
                int *kind = (int *) rock;

                if (!strcmp("group", json_string_value(arg))) {
                    *kind = CARDDAV_KIND_GROUP;

                    /* Group vs non-group is filtered by a flag in carddav.db.
                       Remove property so we don't text match against it. */
                    json_object_del(filter, "kind");
                }
                else {
                    *kind = CARDDAV_KIND_CONTACT;
                }
            }
        }
        else if (!strcmp(field, "inCardGroup")) {
            if (!json_is_array(arg)) {
                jmap_parser_invalid(parser, field);
            }
            else {
                jmap_parse_strings(arg, parser, field);
            }
        }
        else {
            jmap_parser_invalid(parser, field);
        }
    }
}

static int card_comparator_validate(jmap_req_t *req __attribute__((unused)),
                                    struct jmap_comparator *comp,
                                    void *rock __attribute__((unused)),
                                    json_t **err __attribute__((unused)))
{
    /* Reject any collation */
    if (comp->collation) {
        return 0;
    }
    if (!strcmp(comp->property, "uid") ||
        !strcmp(comp->property, "name") ||
        !strcmp(comp->property, "name/given") ||
        !strcmp(comp->property, "name/surname") ||
        !strcmp(comp->property, "nickName") ||
        !strcmp(comp->property, "organization")) {
        return 1;
    }
    return 0;
}

static int card_filter_match_listprop(json_t *jentry, const char *propname,
                                      const char *kind, const char *val_keys[],
                                      struct contact_textfilter *propfilter,
                                      struct contact_textfilter *textfilter,
                                      ptrarray_t *cached_termsets)
{
    /* Skip matching if possible */
    if (!propfilter &&
        (!textfilter || contact_textfilter_matched_all(textfilter))) {
        return 1;
    }

    /* Combine values into text buffer */
    json_t *jlist = json_object_get(jentry, propname);
    struct buf buf = BUF_INITIALIZER;
    const char *id;
    json_t *jinfo;

    json_object_foreach(jlist, id, jinfo) {

        if (!val_keys) {
            if (buf_len(&buf)) buf_putc(&buf, ' ');
            buf_appendcstr(&buf, id);
        }
        else {
            const char *key;

            if (kind &&
                strcmpnull(kind,
                           json_string_value(json_object_get(jinfo, "kind")))) {
                continue;
            }

            for (key = *val_keys; *key; key++) {
                const char *val =
                    json_string_value(json_object_get(jinfo, key));
                if (!val) continue;
                if (buf_len(&buf)) buf_putc(&buf, ' ');
                buf_appendcstr(&buf, val);
            }
        }
    }
    if (propfilter && !buf_len(&buf)) return 0;

    /* Evaluate search on text buffer */
    hash_table *termset = getorset_termset(cached_termsets, propname);
    int ret = card_filter_match_textval(buf_cstring(&buf),
                                        propfilter, textfilter, termset);
    buf_free(&buf);

    return ret;
}

static const char *jsname_comp(json_t *name, const char *compname,
                               struct buf *buf)
{
    json_t *comps = json_object_get(name, "components");
    const char *sep,
        *defsep = json_string_value(json_object_get(name, "defaultSeparator"));
    size_t i;
    json_t *jinfo;

    if (!defsep) defsep = " ";
    sep = defsep;

    buf_reset(buf);

    json_array_foreach(comps, i, jinfo) {
        const char *kind = json_string_value(json_object_get(jinfo, "kind"));
        const char *val = json_string_value(json_object_get(jinfo, "value"));

        if (!strcmp("separator", kind)) {
            sep = val;
            continue;
        }

        if (!strcmp(compname, kind)) {
            if (buf_len(buf)) buf_appendcstr(buf, sep);
            buf_appendcstr(buf, val);
        }

        sep = defsep;
    }

    return buf_cstringnull_ifempty(buf);
}

static int card_filter_match_fullname(json_t *jentry,
                                      struct contact_textfilter *propfilter,
                                      struct contact_textfilter *textfilter,
                                      ptrarray_t *cached_termsets)
{
    /* Skip matching if possible */
    if (!propfilter &&
        (!textfilter || contact_textfilter_matched_all(textfilter))) {
        return 1;
    }

    /* Combine name component values into text buffer */
    json_t *name = json_object_get(jentry, "name");
    const char *val = json_string_value(json_object_get(name, "full"));
    if (propfilter && !val) return 0;

    /* Evaluate search on text buffer */
    hash_table *termset = getorset_termset(cached_termsets, "name");
    int ret = card_filter_match_textval(val, propfilter, textfilter, termset);

    return ret;
}

static int card_filter_match_namecomp(json_t *jentry, const char *compname,
                                      struct contact_textfilter *propfilter,
                                      struct contact_textfilter *textfilter,
                                      ptrarray_t *cached_termsets)
{
    /* Skip matching if possible */
    if (!propfilter &&
        (!textfilter || contact_textfilter_matched_all(textfilter))) {
        return 1;
    }

    /* Combine name component values into text buffer */
    json_t *name = json_object_get(jentry, "name");
    struct buf buf = BUF_INITIALIZER;
    const char *val = jsname_comp(name, compname, &buf);
    if (propfilter && !val) return 0;

    /* Evaluate search on text buffer */
    hash_table *termset = getorset_termset(cached_termsets, compname);
    int ret = card_filter_match_textval(buf_cstring(&buf),
                                        propfilter, textfilter, termset);
    buf_free(&buf);

    return ret;
}

static int card_filter_match_address(json_t *jentry,
                                     struct contact_textfilter *propfilter,
                                     struct contact_textfilter *textfilter,
                                     ptrarray_t *cached_termsets)
{
    /* Skip matching if possible */
    if (!propfilter &&
        (!textfilter || contact_textfilter_matched_all(textfilter))) {
        return 1;
    }

    /* Combine values into text buffer */
    json_t *jlist = json_object_get(jentry, "addresses");
    struct buf buf = BUF_INITIALIZER;
    const char *id;
    json_t *jinfo;

    json_object_foreach(jlist, id, jinfo) {
        const char *val;

        val = json_string_value(json_object_get(jinfo, "full"));
        if (val) {
            if (buf_len(&buf)) buf_putc(&buf, ' ');
            buf_appendcstr(&buf, val);
            continue;
        }

        json_t *jcomp, *jcomps = json_object_get(jinfo, "components");
        size_t i;
        json_array_foreach(jcomps, i, jcomp) {
            val = json_string_value(json_object_get(jcomp, "value"));
            if (val) {
                if (buf_len(&buf)) buf_putc(&buf, ' ');
                buf_appendcstr(&buf, val);
            }
        }
    }
    if (propfilter && !buf_len(&buf)) return 0;

    /* Evaluate search on text buffer */
    hash_table *termset = getorset_termset(cached_termsets, "address");
    int ret = card_filter_match_textval(buf_cstring(&buf),
                                        propfilter, textfilter, termset);
    buf_free(&buf);

    return ret;
}

static const char *name_vals[] =     { "name", NULL };
static const char *email_vals[] =    { "address", "label", NULL };
static const char *phone_vals[] =    { "number", "label", NULL };
static const char *online_vals[] =   { "service", "uri", "user", "label", NULL };
static const char *personal_vals[] = { "value", NULL };
static const char *note_vals[] =     { "note", NULL };

/* Match the card in rock against filter. */
static int card_filter_match(void *vf, void *rock)
{
    struct card_filter *f = (struct card_filter *) vf;
    struct contactsquery_filter_rock *cfrock = (struct contactsquery_filter_rock*) rock;
    json_t *card = cfrock->entry;
    struct carddav_data *cdata = cfrock->cdata;
    struct carddav_db *db = cfrock->carddavdb;

    /* uid */
    if (f->uid && strcmpsafe(cdata->vcard_uid, f->uid)) {
        return 0;
    }

    /* Match text filters */
    if (f->text) contact_textfilter_reset(f->text);
    if (!card_filter_match_fullname(card, f->fullName,
                                    f->text, &cfrock->cached_termsets) ||
        !card_filter_match_namecomp(card, "prefix", f->prefix,
                                    f->text, &cfrock->cached_termsets) ||
        !card_filter_match_namecomp(card, "given", f->given,
                                    f->text, &cfrock->cached_termsets) ||
        !card_filter_match_namecomp(card, "given2", f->middle,
                                    f->text, &cfrock->cached_termsets) ||
        !card_filter_match_namecomp(card, "surname", f->surname,
                                    f->text, &cfrock->cached_termsets) ||
        !card_filter_match_namecomp(card, "suffix", f->suffix,
                                    f->text, &cfrock->cached_termsets) ||
        !card_filter_match_listprop(card, "nicknames", NULL,
                                    name_vals, f->nickName,
                                    f->text, &cfrock->cached_termsets) ||
        !card_filter_match_listprop(card, "titles", "title",
                                    name_vals, f->title,
                                    f->text, &cfrock->cached_termsets) ||
        !card_filter_match_listprop(card, "organizations", NULL,
                                    name_vals, f->organization,
                                    f->text, &cfrock->cached_termsets) ||
        !card_filter_match_listprop(card, "titles", "role",
                                    name_vals, f->role,
                                    f->text, &cfrock->cached_termsets) ||
        !card_filter_match_listprop(card, "emails", NULL,
                                    email_vals, f->email,
                                    f->text, &cfrock->cached_termsets) ||
        !card_filter_match_listprop(card, "phones", NULL,
                                    phone_vals, f->phone,
                                    f->text, &cfrock->cached_termsets) ||
        !card_filter_match_listprop(card, "onlineServices", NULL,
                                    online_vals, f->online,
                                    f->text, &cfrock->cached_termsets) ||
        !card_filter_match_listprop(card, "personalInfo", "expertise",
                                    personal_vals, f->expertise,
                                    f->text, &cfrock->cached_termsets) ||
        !card_filter_match_listprop(card, "personalInfo", "hobby",
                                    personal_vals, f->hobby,
                                    f->text, &cfrock->cached_termsets) ||
        !card_filter_match_listprop(card, "personalInfo", "interest",
                                    personal_vals, f->interest,
                                    f->text, &cfrock->cached_termsets) ||
        !card_filter_match_listprop(card, "notes", NULL,
                                    note_vals, f->note,
                                    f->text, &cfrock->cached_termsets) ||
        !card_filter_match_listprop(card, "members", NULL,
                                    NULL, f->member,
                                    f->text, &cfrock->cached_termsets) ||
        !card_filter_match_textprop(card, "kind", f->kind,
                                    f->text, &cfrock->cached_termsets) ||
        !card_filter_match_address(card, f->address,
                                   f->text, &cfrock->cached_termsets)) {
        return 0;
    }

    if (f->text && !contact_textfilter_matched_all(f->text)) return 0;

    /* inCardGroup */
    if (f->inCardGroup) {
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
            if (hash_lookup(strarray_nth(gids, i), f->inCardGroup)) {
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

static json_t *_card_from_record(jmap_req_t *req,
                                 struct carddav_db *db,
                                 struct mailbox *mailbox,
                                 struct index_record *record);

static int _cardquery_cb(void *rock, struct carddav_data *cdata)
{
    struct contactsquery_rock *crock = (struct contactsquery_rock*) rock;
    struct index_record record;
    json_t *entry = NULL;
    int r = 0;

    if (!cdata->dav.alive || !cdata->dav.rowid || !cdata->dav.imap_uid) {
        return 0;
    }

    /* Ignore anything but the requested kind. */
    if (cdata->kind != crock->kind && crock->kind != CARDDAV_KIND_ANY) {
        return 0;
    }

    mbentry_t *mbentry = jmap_mbentry_from_dav(crock->req, &cdata->dav);

    if (!mbentry || !jmap_hasrights_mbentry(crock->req, mbentry, JACL_READITEMS)) {
        mboxlist_entry_free(&mbentry);
        return 0;
    }

    if (cdata->jmapversion == JMAPCACHE_CARDVERSION) {
        json_error_t jerr;
        entry = json_loads(cdata->jmapdata, 0, &jerr);
        if (entry) goto gotvalue;
    }

    /* Open mailbox. */
    if (!crock->mailbox || strcmp(mailbox_name(crock->mailbox), mbentry->name)) {
        mailbox_close(&crock->mailbox);
        r = mailbox_open_irl(mbentry->name, &crock->mailbox);
    }
    mboxlist_entry_free(&mbentry);
    if (r) return r;

    /* Load record. */
    r = mailbox_find_index_record(crock->mailbox, cdata->dav.imap_uid, &record);
    if (r) goto done;

    /* Load contact from record. */
    entry = _card_from_record(crock->req, crock->carddavdb,
                              crock->mailbox, &record);
    if (!entry) {
        syslog(LOG_ERR, "_card_from_record failed for record %u:%s",
                cdata->dav.imap_uid, mailbox_name(crock->mailbox));
        r = IMAP_INTERNAL;
        goto done;
    }

  gotvalue:

    if (crock->filter) {
        /* Match the contact against the filter */
        struct contactsquery_filter_rock cfrock = {
            crock->carddavdb, cdata, entry, PTRARRAY_INITIALIZER
        };
        /* Match filter */
        int matches =
            jmap_filter_match(crock->filter, &card_filter_match, &cfrock);
        /* Free text search cached_termsets */
        int i;
        for (i = 0; i < ptrarray_size(&cfrock.cached_termsets); i++) {
            struct named_termset *nts = ptrarray_nth(&cfrock.cached_termsets, i);
            free_hash_table(&nts->termset, NULL);
            free(nts);
        }
        ptrarray_fini(&cfrock.cached_termsets);
        /* Skip non-matching entries */
        if (!matches) goto done;
    }

    /* Update statistics */
    crock->query->total++;

    if (crock->build_response) {
        struct jmap_query *query = crock->query;
        /* Apply windowing and build response ids */
        if (query->position > 0 && query->position > (ssize_t) query->total - 1) {
            goto done;
        }
        if (query->limit && json_array_size(query->ids) >= query->limit) {
            goto done;
        }
        if (!json_array_size(query->ids)) {
            query->result_position = query->total - 1;
        }
        json_array_append_new(query->ids, json_string(cdata->vcard_uid));
    }
    else {
        /* Keep matching entries for post-processing */
        json_object_set_new(entry, "id", json_string(cdata->vcard_uid));
        json_object_set_new(entry, "uid", json_string(cdata->vcard_uid));
        ptrarray_append(&crock->entries, entry);
        entry = NULL;
    }

done:
    if (entry) json_decref(entry);
    return r;
}

static enum contactsquery_sort *cardquery_buildsort(json_t *jsort)
{
    enum contactsquery_sort *sort =
        xzmalloc((json_array_size(jsort) + 1) * sizeof(enum contactsquery_sort));

    size_t i;
    json_t *jcomp;
    json_array_foreach(jsort, i, jcomp) {
        const char *prop = json_string_value(json_object_get(jcomp, "property"));
        if (!strcmp(prop, "uid"))
            sort[i] = CONTACTS_SORT_UID;
        /* Comparators for Card */
        else if (!strcmp(prop, "name/given"))
            sort[i] = CONTACTS_SORT_FIRSTNAME;
        else if (!strcmp(prop, "name/surname"))
            sort[i] = CONTACTS_SORT_LASTNAME;
        else if (!strcmp(prop, "nickName"))
            sort[i] = CONTACTS_SORT_NICKNAME;
        else if (!strcmp(prop, "organization"))
            sort[i] = CONTACTS_SORT_COMPANY;
        /* Comparators for CardGroup */
        else if (!strcmp(prop, "name"))
            sort[i] = CONTACTS_SORT_NAME;

        if (json_object_get(jcomp, "isAscending") == json_false())
            sort[i] |= CONTACTS_SORT_DESC;
    }

    return sort;
}

static const char *jsname_sortas(json_t *card, const char *comp, struct buf *buf)
{
    json_t *name = json_object_get(card, "name");
    const char *val = NULL;

    if (name) {
        json_t *sortas = json_object_get(name, "sortAs");

        if (sortas) val = json_string_value(json_object_get(sortas, comp));
        if (!val) val = jsname_comp(name, comp, buf);
    }

    return val;
}

static const char *jsorg_sortas(json_t *card, struct buf *buf)
{
    json_t *orgs = json_object_get(card, "organizations");
    const char *val = NULL;

    buf_reset(buf);

    if (orgs) {
        const char *id;
        json_t *org;

        json_object_foreach(orgs, id, org) {
            val = json_string_value(json_object_get(org, "sortAs"));
            if (!val) val = json_string_value(json_object_get(org, "name"));

            if (buf_len(buf)) buf_putc(buf, ' ');
            buf_appendcstr(buf, val);
        }
    }

    return val;
}

static int cardquery_cmp QSORT_R_COMPAR_ARGS(const void *va,
                                             const void *vb,
                                             void *rock)
{
    enum contactsquery_sort *sort = rock;
    enum contactsquery_sort *comp;
    json_t *ja = (json_t*) *(void**)va;
    json_t *jb = (json_t*) *(void**)vb;
    struct buf bufa = BUF_INITIALIZER;
    struct buf bufb = BUF_INITIALIZER;
    int ret = 0;

    for (comp = sort; *comp != CONTACTS_SORT_NONE; comp++) {
        const char *vala = NULL, *valb = NULL;

        switch (*comp & ~CONTACTS_SORT_DESC) {
            case CONTACTS_SORT_UID:
                vala = json_string_value(json_object_get(ja, "uid"));
                valb = json_string_value(json_object_get(jb, "uid"));
                break;
            case CONTACTS_SORT_FIRSTNAME:
                vala = jsname_sortas(ja, "given", &bufa);
                valb = jsname_sortas(jb, "given", &bufb);
                break;
            case CONTACTS_SORT_LASTNAME:
                vala = jsname_sortas(ja, "surname", &bufa);
                valb = jsname_sortas(jb, "surname", &bufb);
                break;
            case CONTACTS_SORT_NICKNAME:
                vala = json_string_value(json_object_get(ja, "nickName"));
                valb = json_string_value(json_object_get(jb, "nickName"));
                break;
            case CONTACTS_SORT_COMPANY:
                vala = jsorg_sortas(ja, &bufa);
                valb = jsorg_sortas(jb, &bufb);
                break;
            case CONTACTS_SORT_NAME:
                vala = json_string_value(json_object_get(json_object_get(ja, "name"), "full"));
                valb = json_string_value(json_object_get(json_object_get(jb, "name"), "full"));
                break;
        }

        ret = strcmpsafe(vala, valb);
        if (ret) {
            if (*comp & CONTACTS_SORT_DESC) ret = -ret;
            break;
        }
    }

    buf_free(&bufa);
    buf_free(&bufb);

    return ret;
}

/*
 * ContactCard/set
 */

struct l10n_by_id_t {
    const char *deflang;
    const char *lang;
    hash_table *patches;
};

static void _jsunknown_to_vcard(struct jmap_parser *parser,
                                const char *key, json_t *jval,
                                const char *known_props[],
                                vcardcomponent *card)
{
    if (key) {
        for (int i = 0; known_props && known_props[i]; i++) {
            if (!strcasecmp(key, known_props[i])) {
                jmap_parser_invalid(parser, key);
                return;
            }
        }

        jmap_parser_push(parser, key);
    }

    const char *ptr = jmap_parser_path(parser, &parser->buf);
    char *val = json_dumps(jval, JSON_COMPACT|JSON_ENCODE_ANY);
    vcardproperty *prop =
        vcardproperty_vanew_jsprop(val,
                                   vcardparameter_new_jsptr(ptr),
                                   NULL);

    vcardcomponent_add_property(card, prop);
    
    if (key) jmap_parser_pop(parser);
    free(val);
}

static unsigned jssimple_to_vcard(struct jmap_parser *parser,
                                  const char *key, const char *lang,
                                  json_t *jval, vcardcomponent *card,
                                  vcardproperty_kind pkind,
                                  vcardvalue_kind vkind)
{
    vcardproperty *prop = NULL;
    vcardvalue *val = NULL;

    switch (vkind) {
    case VCARD_KIND_VALUE:
    case VCARD_TEXT_VALUE:
    case VCARD_GRAMGENDER_VALUE:
        if (!json_is_string(jval)) {
            jmap_parser_invalid(parser, key);
            return 0;
        }
        else {
            val = vcardvalue_new_from_string(vkind, json_string_value(jval));
        }
        break;

    case VCARD_TIMESTAMP_VALUE:
        if (!json_is_utcdate(jval)) {
            jmap_parser_invalid(parser, key);
            return 0;
        }
        else {
            vcardtimetype tt = vcardtime_from_string(json_string_value(jval), 0);
            val = vcardvalue_new_timestamp(tt);
        }
        break;

    default:
        jmap_parser_invalid(parser, key);
        return 0;
    }

    prop = vcardproperty_new(pkind);
    vcardproperty_set_value(prop, val);
    vcardcomponent_add_property(card, prop);

    if (lang && *lang) {
        vcardproperty_add_parameter(prop, vcardparameter_new_language(lang));
    }

    return 1;
}
static unsigned _jsmultikey_to_card(struct jmap_parser *parser, json_t *jval,
                                    const char *key, vcardcomponent *card,
                                    vcardproperty_kind pkind)
{
    struct buf buf = BUF_INITIALIZER;
    vcardstrarray *text = NULL;
    const char *id;
    json_t *obj;
    int r = 0;

    if (!json_is_object(jval)) {
        jmap_parser_invalid(parser, key);
        return 0;
    }

    jmap_parser_push(parser, key);

    json_object_foreach(jval, id, obj) {

        jmap_parser_push(parser, id);

        if (!json_is_true(obj)) {
            jmap_parser_invalid(parser, id);
        }
        else if (vcardproperty_is_multivalued(pkind)) {
            if (!text) text = vcardstrarray_new(1);
            vcardstrarray_append(text, id);
        }
        else {
            vcardproperty *prop = vcardproperty_new(pkind);

            buf_reset(&buf);

            if (pkind == VCARD_MEMBER_PROPERTY &&
                strncmpsafe("urn:uuid:", id, 9)) {
                buf_setcstr(&buf, "urn:uuid:");
            }

            buf_appendcstr(&buf, id);
            vcardproperty_set_value_from_string(prop, buf_cstring(&buf), "NO");

            vcardcomponent_add_property(card, prop);
            r = 1;
        }

        jmap_parser_pop(parser);
    }

    if (text) {
        vcardproperty *prop = vcardproperty_new(pkind);

        vcardproperty_set_value(prop, vcardvalue_new_textlist(text));
        vcardcomponent_add_property(card, prop);
        r = 1;
    }

    jmap_parser_pop(parser);
    buf_free(&buf);

    return r;
}

static void _jsparam_to_vcard(struct jmap_parser *parser,
                              const char *key, json_t *jval,
                              vcardproperty *prop,
                              vcardparameter_kind pkind,
                              unsigned *groupnum)
{
    json_t *jprop = json_object_get(jval, key);
    vcardparameter *new = NULL, *param = NULL;
    static struct buf buf = BUF_INITIALIZER;

    if (!jprop) return;

    switch (pkind) {
    case VCARD_TYPE_PARAMETER:
        if (json_is_object(jprop)) {
            const char *type;
            json_t *set;

            param = vcardproperty_get_first_parameter(prop, pkind);
            if (!param) param = new = vcardparameter_new(pkind);

            json_object_foreach(jprop, type, set) {
                const char *mytype;

                if (!strcasecmp("private", type))
                    mytype = "home";
                else if (!strcasecmp("mobile", type))
                    mytype = "cell";
                else
                    mytype = type;

                vcardparameter_add_value_from_string(param, mytype);
            }
        }
        break;

    case VCARD_PREF_PARAMETER:
    case VCARD_INDEX_PARAMETER:
        if (json_is_integer(jprop)) {
            param = new = vcardparameter_new(pkind);
            vcardparameter_set_pref(param, json_integer_value(jprop));
        }
        break;

    case VCARD_CREATED_PARAMETER:
        if (json_is_utcdate(jprop)) {
            vcardtimetype tt = vcardtime_from_string(json_string_value(jprop), 0);

            param = new = vcardparameter_new_created(tt);
        }
        break;

    case VCARD_LEVEL_PARAMETER:
        if (json_is_string(jprop)) {
            const char *val = json_string_value(jprop);

            if (vcardproperty_isa(prop) == VCARD_EXPERTISE_PROPERTY) {
                if (!strcasecmp("low", val)) {
                    val = "beginner";
                }
                else if (!strcasecmp("medium", val)) {
                    val = "average";
                }
                else if (!strcasecmp("high", val)) {
                    val = "expert";
                }
            }

            param = new = vcardparameter_new(VCARD_LEVEL_PARAMETER);
            vcardparameter_set_value_from_string(param, val);
        }
        break;

    case VCARD_X_PARAMETER:
        /* label translates to a grouped X-ABLabel property */
        if (json_is_string(jprop)) {
            vcardproperty *label = vcardproperty_new_x(json_string_value(jprop));
            const char *group;

            vcardproperty_set_x_name(label, VCARD_APPLE_LABEL_PROPERTY);
            vcardcomponent_add_property(vcardproperty_get_parent(prop), label);

            buf_setcstr(&buf, vcardproperty_get_property_name(prop));
            buf_truncate(&buf, MIN(5, buf_len(&buf)));
            buf_printf(&buf, "%u", (*groupnum)++);
            group = buf_lcase(&buf);

            vcardproperty_set_group(label, group);
            vcardproperty_set_group(prop, group);
            jprop = NULL;
        }
        break;

    default:
        if (json_is_string(jprop)) {
            param = new = vcardparameter_new(pkind);
            vcardparameter_set_value_from_string(param,
                                                 json_string_value(jprop));
        }
        break;
    }

    if (param) {
        if (new) vcardproperty_add_parameter(prop, param);
    }
    else if (jprop) {
        jmap_parser_invalid(parser, key);
    }

    json_object_del(jval, key);
}

struct param_prop_t {
    const char *key;
    vcardparameter_kind kind;
};

// clang-format off
struct param_prop_t phone_param_props[] = {
    { "features", VCARD_TYPE_PARAMETER  },
    { "label",    VCARD_X_PARAMETER     },
    { "pref",     VCARD_PREF_PARAMETER  },
    { "contexts", VCARD_TYPE_PARAMETER  },
    { NULL,       0                     }
};
// clang-format on

#define comm_param_props    (phone_param_props+1)  // label, context & pref
#define pref_param_props    (phone_param_props+2)  // context & pref
#define context_param_props (phone_param_props+3)  // context

// clang-format off
struct param_prop_t directories_param_props[] = {
    { "listAs",    VCARD_INDEX_PARAMETER     },
    { "mediaType", VCARD_MEDIATYPE_PARAMETER },
    { "label",     VCARD_X_PARAMETER         },
    { "pref",      VCARD_PREF_PARAMETER      },
    { "contexts",  VCARD_TYPE_PARAMETER      },
    { NULL,       0                          }
};
// clang-format on

#define resource_param_props (directories_param_props+1)  // no listAs

#define WANT_PROPID_FLAG (1<<0)
#define WANT_ALTID_FLAG  (1<<1)

typedef vcardproperty* (*prop_cb_t)(struct jmap_parser *parser, json_t *obj,
                                    const char *id, vcardcomponent *card,
                                    void *rock);

static void _vcardparams_to_prop(json_t *jparams, vcardproperty *prop)
{
    const char *name;
    json_t *jval;

    json_object_foreach(jparams, name, jval) {
        vcardparameter *param;

        if (!strcmp(name, "group")) {
            vcardproperty_set_group(prop, json_string_value(jval));
            continue;
        }

        vcardparameter_kind kind = vcardparameter_string_to_kind(name);
        switch (kind) {
        case VCARD_X_PARAMETER:
        case VCARD_NO_PARAMETER:
        case VCARD_IANA_PARAMETER:
            param = vcardparameter_new(VCARD_IANA_PARAMETER);
            vcardparameter_set_iana_name(param, name);
            break;

        default:
            param = vcardparameter_new(kind);
            break;
        }

        if (json_is_string(jval)) {
            vcardparameter_set_value_from_string(param, json_string_value(jval));
        }
        else if (json_is_boolean(jval)) {
            vcardparameter_set_derived(param, json_boolean_value(jval) ?
                                       VCARD_DERIVED_TRUE : VCARD_DERIVED_FALSE);
        }
        else if (json_is_integer(jval)) {
            vcardparameter_set_index(param, json_integer_value(jval));
        }
        else {
            char *val = json_dumps(jval, JSON_COMPACT);
            param = vcardparameter_new_iana(val);
            free(val);
        }

        vcardproperty_add_parameter(prop, param);
    }
}

static unsigned _jsobject_to_card(struct jmap_parser *parser, json_t *obj,
                                  const char *id, const char *type, prop_cb_t cb,
                                  struct param_prop_t param_props[],
                                  unsigned flags, const char *lang,
                                  vcardcomponent *card, void *rock,
                                  unsigned *groupnum)
{
    vcardproperty *prop = NULL;
    const char *myprops[] = { "@type", NULL };
    const char *key;
    json_t *jprop;
    int r = 0;

    jprop = json_object_get(obj, "@type");
    if (jprop && strcmpsafe(type, json_string_value(jprop))) {
        jmap_parser_invalid(parser, "@type");
        return 0;
    }
    json_object_del(obj, "@type");

    prop = cb(parser, obj, id, card, rock);

    if (prop) {
        struct param_prop_t *pprop;
        json_t *jprop;

        vcardcomponent_add_property(card, prop);

        if (flags & WANT_PROPID_FLAG) {
            vcardproperty_add_parameter(prop, vcardparameter_new_propid(id));
        }
        if (flags & WANT_ALTID_FLAG) {
            vcardproperty_add_parameter(prop, vcardparameter_new_altid(id));
        }
        if (lang && *lang) {
            vcardproperty_add_parameter(prop, vcardparameter_new_language(lang));
        }

        for (pprop = param_props; pprop && pprop->key; pprop++) {
            _jsparam_to_vcard(parser, pprop->key, obj, prop, pprop->kind, groupnum);
        }

        jprop = json_object_get(obj, "vCardParams");
        if (json_is_object(jprop)) {
            _vcardparams_to_prop(jprop, prop);

            json_object_del(obj, "vCardParams");
        }

        r = 1;
    }

    /* Add unknown properties */
    json_object_foreach(obj, key, jprop) {
        _jsunknown_to_vcard(parser, key, jprop, myprops, card);
    }

    return r;
}

struct l10n_rock {
    unsigned is_multi: 1;
    unsigned *groupnum;
    union {
        unsigned (*prop_cb)(struct jmap_parser *, json_t *,
                            struct l10n_by_id_t *, vcardcomponent *);
        struct {
            const char *type;
            prop_cb_t prop_cb;
            struct param_prop_t *param_props;
            void *rock;
        } multi;
    } u;
};

static unsigned _jsl10n_to_vcard(struct jmap_parser *parser, json_t *obj,
                                 const char *key, const char *id,
                                 struct l10n_by_id_t *l10n,
                                 vcardcomponent *card, struct l10n_rock *rock)
{
    json_t *patches =
        l10n->patches ? hash_del(id ? id : "", l10n->patches) : NULL;
    int r = 0;

    if (patches) {
        /* Apply localization patches and add new objects to Card */
        struct buf buf = BUF_INITIALIZER;
        const char *lang;
        json_t *jpatch;
        
        json_object_foreach(patches, lang, jpatch) {
            json_t *altobj = json_object_get(jpatch, "");
            json_t *invalid = NULL, *patched = NULL;

            if (!altobj) {
                invalid = json_array();
                altobj = patched = jmap_patchobject_apply(obj, jpatch, invalid,
                                                          PATCH_ALLOW_ARRAY);
            }

            if (altobj) {
                if (rock->is_multi) {
                    const char *this_lang =
                        strcasecmpsafe(l10n->deflang, lang) ? lang : NULL;

                    r |= _jsobject_to_card(parser, altobj, id,
                                           rock->u.multi.type,
                                           rock->u.multi.prop_cb,
                                           rock->u.multi.param_props,
                                           WANT_PROPID_FLAG | WANT_ALTID_FLAG,
                                           this_lang, card,
                                           rock->u.multi.rock,
                                           rock->groupnum);
                }
                else {
                    struct l10n_by_id_t my_l10n = { l10n->deflang, lang, NULL };

                    r |= rock->u.prop_cb(parser, altobj, &my_l10n, card);
                }

                if (patched) json_decref(patched);
            }
            else {
                json_t *path;
                size_t len, i;

                buf_printf(&buf, "localizations/%s/", lang);
                if (id) buf_printf(&buf, "%s/", id);
                buf_printf(&buf, "%s/", key);
                len = buf_len(&buf);

                json_array_foreach(invalid, i, path) {
                    buf_appendcstr(&buf, json_string_value(path));
                    jmap_parser_invalid_path(parser, buf_cstring(&buf));
                    buf_truncate(&buf, len);
                }
                buf_reset(&buf);
            }

            if (invalid) json_decref(invalid);
        }

        json_decref(patches);
        buf_free(&buf);
    }

    return r;
}

static unsigned _jsmultiobject_to_card(struct jmap_parser *parser, json_t *jval,
                                       const char *key, const char *type,
                                       prop_cb_t prop_cb, unsigned flags,
                                       struct param_prop_t param_props[],
                                       struct l10n_by_id_t *l10n,
                                       vcardcomponent *card, void *rock)
{
    unsigned groupnum = 0;
    struct l10n_rock lrock =
        { 1, &groupnum, { .multi = { type, prop_cb, param_props, rock}} };
    const char *id;
    json_t *obj;
    void *tmp;
    int r = 0;

    if (!json_is_object(jval)) {
        jmap_parser_invalid(parser, key);
        return 0;
    }

    jmap_parser_push(parser, key);

    json_object_foreach_safe(jval, tmp, id, obj) {
        int r1;

        jmap_parser_push(parser, id);

        r |= _jsl10n_to_vcard(parser, obj, key, id, l10n, card, &lrock);

        if (l10n->lang) {
            flags |= WANT_ALTID_FLAG;
        }

        /* Add base object to Card */
        r |= (r1 = _jsobject_to_card(parser, obj, id, type, prop_cb,
                                     param_props, flags, l10n->lang,
                                     card, rock, &groupnum));

        json_object_del(jval, id);
        jmap_parser_pop(parser);

        if (!r1) break;
    }

    jmap_parser_pop(parser);

    return r;
}

static vcardproperty *_jsrelation_to_vcard(struct jmap_parser *parser,
                                           json_t *obj, const char *id,
                                           vcardcomponent *card __attribute__((unused)),
                                           void *rock __attribute__((unused)))
{
    json_t *jprop = jprop = json_object_get(obj, "relation");
    vcardproperty *prop = NULL;

    if (!jprop || !json_is_object(jprop)) {
        jmap_parser_invalid(parser, "relation");
    }
    else {
        const char *valkind = "URI";
        size_t i, len = strlen(id);
        int have_scheme = 0;

        for (i = 0; i < len; i++) {
            if (!isascii(id[i]) || !isprint(id[i]) || isspace(id[i])) {
                break;
            }
            else if (i && id[i] == ':') {
                have_scheme = 1;
            }
        }
        if (!have_scheme || i < len) {
            valkind = "TEXT";
        }

        prop = vcardproperty_new(VCARD_RELATED_PROPERTY);
        vcardproperty_set_value_from_string(prop, id, valkind);
    }

    return prop;
}

static const struct comp_kind *_field_name_to_kind(const char *name,
                                                   const struct comp_kind *comps)
{
    const struct comp_kind *comp;

    for (comp = comps; comp->name; comp++) {
        if (!(comp->flags & FIELD_SKIP) && !strcmpsafe(name, comp->name)) {
            return comp;
        }
    }

    return NULL;
}

struct jscomps_args {
    vcardproperty *(*vanew_prop)(vcardstructuredtype*, ...);
    unsigned num_comps;
    const char *id;
    const char *comp_type;
    const struct comp_kind *comp_kinds;
    struct buf *derived;
};

static vcardproperty *_jscomps_to_vcard(struct jmap_parser *parser, json_t *obj,
                                        vcardcomponent *card,
                                        struct jscomps_args *args)
{
    json_t *comps = json_object_get(obj, "components");

    if (!comps) return NULL;

    if (!json_array_size(comps)) {
        jmap_parser_invalid(parser, "components");
        return 0;
    }

    vcardstructuredtype vals = { args->num_comps, { 0 } };
    vcardstructuredtype ph = { args->num_comps, { 0 } };
    size_t i, size = json_array_size(comps);
    vcardstructuredtype *jscomps = NULL;
    vcardproperty *prop = NULL;
    const char *defsep = " ", *sep = NULL, *ph_system = NULL;;
    struct buf buf = BUF_INITIALIZER;
    vcardstrarray *entry;
    json_t *jprop;
    int isordered = 0;

    jprop = json_object_get(obj, "phoneticSystem");
    if (json_is_string(jprop)) {
        ph_system = json_string_value(jprop);
    }
    else if (jprop) {
        jmap_parser_invalid(parser, "phoneticSystem");
        goto fail;
    }

    jprop = json_object_get(obj, "isOrdered");
    if (jprop) {
        if (!json_is_boolean(jprop)) {
            jmap_parser_invalid(parser, "isOrdered");
            goto fail;
        }

        isordered = json_boolean_value(jprop);
    }

    if (isordered) {
        jscomps = xzmalloc(sizeof(vcardstructuredtype));

        jscomps->num_fields = 1; // for separator, regardless if specified

        jprop = json_object_get(obj, "defaultSeparator");
        if (json_is_string(jprop)) {
            defsep = json_string_value(jprop);

            /* Add default separator entry to JSCOMPS (if not SP) */
            if (strcmp(defsep, " ")) {
                entry = vcardstrarray_new(2);
                vcardstrarray_append(entry, "s");
                vcardstrarray_append(entry, defsep);
                jscomps->field[0] = entry;
            }
        }
        else if (jprop) {
            jmap_parser_invalid(parser, "defaultSeparator");
            goto fail;
        }
    }

    for (i = 0; i < size; i++) {
        json_t *comp = json_array_get(comps, i);
        const char *key, *kind = NULL, *val = NULL, *phonetic = NULL;
        const char *myprops[] = { "@type", "kind", "value", "phonetic", NULL };
        json_t *jsubprop;

        jmap_parser_push_index(parser, "components", i, NULL);

        json_object_foreach(comp, key, jsubprop) {
            if (!strcmp("@type", key)) {
                if (strcmpsafe(args->comp_type, json_string_value(jsubprop))) {
                    jmap_parser_invalid(parser, "@type");
                    break;
                }
            }
            else if (!strcmp("kind", key)) {
                kind = json_string_value(jsubprop);
            }
            else if (!strcmp("value", key)) {
                val = json_string_value(jsubprop);
            }
            else if (!strcmp("phonetic", key)) {
                if (!ph_system || !json_is_string(jsubprop)) {
                    jmap_parser_invalid(parser, "phonetic");
                    break;
                }

                phonetic = json_string_value(jsubprop);
            }
            else {
                jmap_parser_pop(parser);
                _jsunknown_to_vcard(parser, "components", comps, myprops, card);
                goto fail;
            }
        }

        if (!val) {
            jmap_parser_invalid(parser, "value");
            break;
        }

        if (!kind) {
            jmap_parser_invalid(parser, "kind");
            break;
        }
        else if (!strcmp(kind, "separator")) {
            if (isordered) {
                /* Add separator entry to JSCOMPS */
                sep = val;
                buf_setcstr(&buf, sep);
                entry = vcardstrarray_new(2);
                vcardstrarray_append(entry, "s");
                vcardstrarray_append(entry, buf_cstring(&buf));
                jscomps->field[jscomps->num_fields++] = entry;
            }
            else {
                jmap_parser_invalid(parser, "kind");
                break;
            }
        }
        else {
            const struct comp_kind *ckind =
                _field_name_to_kind(kind, args->comp_kinds);
            vcardstrarray **field;

            if (!ckind) {
                jmap_parser_pop(parser);
                _jsunknown_to_vcard(parser, "components", comps, myprops, card);
                goto fail;
            }

            /* Add phonetic to proper field */
            if (phonetic) {
                field = &ph.field[ckind->idx];
                if (!*field) *field = vcardstrarray_new(1);
                vcardstrarray_append(*field, phonetic);
            }

            /* Add value to proper field */
            field = &vals.field[ckind->idx];
            if (!*field) *field = vcardstrarray_new(1);
            vcardstrarray_append(*field, val);

            if (isordered) {
                /* Add positional entry (field idx [value idx]) to JSCOMPS */
                entry = vcardstrarray_new(2);
                buf_reset(&buf);
                buf_printf(&buf, "%d", ckind->idx);
                vcardstrarray_append(entry, buf_cstring(&buf));
                if (vcardstrarray_size(*field) > 1) {
                    buf_reset(&buf);
                    buf_printf(&buf, "%lu", vcardstrarray_size(*field) - 1);
                    vcardstrarray_append(entry, buf_cstring(&buf));
                }
                jscomps->field[jscomps->num_fields++] = entry;
            }

            if (args->derived) {
                /* Create derived value from fields */
                if (i) buf_appendcstr(args->derived, sep ? sep : defsep);
                buf_appendcstr(args->derived, val);
                sep = NULL;
            }

            /* Also add values from ext fields to backward-compat fields */
            if (ckind->flags & FIELD_BWD) {
                field = &vals.field[ckind->alt_idx];
                if (!*field) *field = vcardstrarray_new(1);
                vcardstrarray_append(*field, val);
            }
        }

        jmap_parser_pop(parser);
    }

    if (i != size) {
        jmap_parser_pop(parser);
        goto fail;
    }

    prop = args->vanew_prop(&vals,
                            jscomps ? vcardparameter_new_jscomps(jscomps) : NULL,
                            NULL);

    if (ph_system) {
        vcardproperty_add_parameter(prop, vcardparameter_new_altid(args->id));

        /* Add alternate property */
        vcardparameter *param = vcardparameter_new(VCARD_PHONETIC_PARAMETER);

        vcardparameter_set_value_from_string(param, ph_system);
        vcardcomponent_add_property(card,
                                    args->vanew_prop(&ph,
                                                     vcardparameter_new_altid(args->id),
                                                     param,
                                                     NULL));
    }

    json_object_del(obj, "components");
    json_object_del(obj, "isOrdered");
    json_object_del(obj, "phoneticSystem");
    json_object_del(obj, "defaultSeparator");

    buf_free(&buf);

    return prop;

  fail:
    for (unsigned i = 0; i < vals.num_fields; i++) {
        vcardstrarray *sa = vals.field[i];

        if (sa) vcardstrarray_free(sa);
    }
    if (ph_system) {
        for (unsigned i = 0; i < ph.num_fields; i++) {
            vcardstrarray *sa = ph.field[i];

            if (sa) vcardstrarray_free(sa);
        }
    }
    if (jscomps) {
        for (unsigned i = 0; i < jscomps->num_fields; i++) {
            vcardstrarray *sa = jscomps->field[i];

            if (sa) vcardstrarray_free(sa);
        }
        free(jscomps);
    }
    if (args->derived) {
        buf_reset(args->derived);
    }
    buf_free(&buf);

    json_object_del(obj, "components");
    json_object_del(obj, "isOrdered");
    json_object_del(obj, "phoneticSystem");
    json_object_del(obj, "defaultSeparator");

    return NULL;
}

static unsigned _jsname_to_vcard(struct jmap_parser *parser, json_t *jval,
                                 struct l10n_by_id_t *l10n,
                                 vcardcomponent *card)
{
    struct l10n_rock lrock = { 0, NULL, { .prop_cb = &_jsname_to_vcard } };
    struct jscomps_args args = {
        &vcardproperty_vanew_n, VCARD_NUM_N_FIELDS,
        "n1", "Name", n_comp_kinds, NULL
    };
    const char *myprops[] = {
        "@type", "full", "sortAs",
        "phoneticSystem", "isOrdered", "defaultSeparator", "components", NULL
    };
    vcardstrarray *sortas = NULL;
    vcardproperty *prop = NULL;
    const char *key, *fullName = NULL;
    struct buf buf = BUF_INITIALIZER;
    json_t *jprop, *jsubprop;
    size_t i;
    int r = 0;

    if (!json_is_object(jval)) {
        jmap_parser_invalid(parser, "name");
        return 0;
    }

    _jsl10n_to_vcard(parser, jval, "name", NULL, l10n, card, &lrock);

    jmap_parser_push(parser, "name");

    /* Add base object to Card */
    jprop = json_object_get(jval, "@type");
    if (jprop && strcmpsafe("Name", json_string_value(jprop))) {
        jmap_parser_invalid(parser, "@type");
        goto done;
    }

    jprop = json_object_get(jval, "full");
    if (json_is_string(jprop)) {
        buf_setcstr(&buf, json_string_value(jprop));
        fullName = buf_cstring(&buf);
    }
    else if (jprop || !json_object_get(jval, "components")) {
        jmap_parser_invalid(parser, "full");
        goto done;
    }

    if (json_object_get(jval, "sortAs") &&
        !json_object_get(jval, "components")) {
        jmap_parser_invalid(parser, "sortAs");
        goto done;
    }

    if (!fullName) args.derived = &buf;

    prop = _jscomps_to_vcard(parser, jval, card, &args);

    if (prop) {
        vcardcomponent_add_property(card, prop);

        if (l10n->lang) {
            vcardproperty_add_parameter(prop, vcardparameter_new_altid("n1"));

            if (*l10n->lang) {
                vcardproperty_add_parameter(prop,
                                            vcardparameter_new_language(l10n->lang));
            }
        }

        jprop = json_object_get(jval, "sortAs");
        if (jprop) {
            const char *fields[VCARD_NUM_N_FIELDS] = { 0 };
            unsigned last_field = 0;
            void *tmp;

            if (!json_is_object(jprop)) {
                jmap_parser_invalid(parser, "sortAs");
                goto done;
            }

            jmap_parser_push(parser, "sortAs");

            json_object_foreach_safe(jprop, tmp, key, jsubprop) {
                const struct comp_kind *ckind =
                    _field_name_to_kind(key, n_comp_kinds);

                if (!ckind) {
                    _jsunknown_to_vcard(parser, key, jsubprop, myprops, card);
                }

                fields[ckind->idx] = json_string_value(jsubprop);
                last_field = MAX(last_field, ckind->idx);
            }

            sortas = vcardstrarray_new(1);

            for (i = 0; i <= (size_t) last_field; i++) {
                vcardstrarray_append(sortas, fields[i] ? fields[i] : "");
            }

            /* Add SORT-AS parameter */
            vcardproperty_add_parameter(prop, vcardparameter_new_sortas(sortas));

            jmap_parser_pop(parser);
        }
    }

    if (buf_len(&buf)) {
        /* Add FN property */
        prop = vcardproperty_vanew_fn(
            buf_cstring(&buf),
            !fullName ? vcardparameter_new_derived(VCARD_DERIVED_TRUE) : 0,
            NULL);
        vcardcomponent_add_property(card, prop);

        if (l10n->lang && *l10n->lang) {
            vcardproperty_add_parameter(prop,
                                        vcardparameter_new_language(l10n->lang));
        }
    }

    json_object_del(jval, "@type");
    json_object_del(jval, "full");
    json_object_del(jval, "sortAs");

    /* Add unknown properties */
    json_object_foreach(jval, key, jprop) {
        _jsunknown_to_vcard(parser, key, jprop, myprops, card);
    }

    r = 1;

  done:
    jmap_parser_pop(parser);
    buf_free(&buf);
    return r;
}

static vcardproperty *_jsnickname_to_vcard(struct jmap_parser *parser,
                                           json_t *obj,
                                           const char *id __attribute__((unused)),
                                           vcardcomponent *card __attribute__((unused)),
                                           void *rock __attribute__((unused)))
{
    const char *val = json_string_value(json_object_get(obj, "name"));
    vcardproperty *prop = NULL;

    if (!val) {
        jmap_parser_invalid(parser, "name");
    }
    else {
        vcardstrarray *sa = vcardstrarray_new(1);

        vcardstrarray_append(sa, val);

        prop = vcardproperty_new_nickname(sa);

        json_object_del(obj, "name");
    }

    return prop;
}

static vcardproperty *_jsorg_to_vcard(struct jmap_parser *parser, json_t *obj,
                                      const char *id, vcardcomponent *card,
                                      void *rock)
{
    hash_table *groups = rock;
    vcardstrarray *units = NULL, *sortas = NULL;
    vcardproperty *prop = NULL;
    json_t *jprop;

    jprop = json_object_get(obj, "name");
    if (json_is_string(jprop)) {
        units = vcardstrarray_new(1);
        vcardstrarray_append(units, json_string_value(jprop));
    }
    else if (jprop) {
        jmap_parser_invalid(parser, "name");
        return NULL;
    }

    jprop = json_object_get(obj, "sortAs");
    if (json_is_string(jprop)) {
        sortas = vcardstrarray_new(1);
        vcardstrarray_append(sortas, json_string_value(jprop));
    }
    else if (jprop) {
        jmap_parser_invalid(parser, "sortAs");
        if (units) vcardstrarray_free(units);
        return NULL;
    }

    jprop = json_object_get(obj, "units");
    if (json_is_array(jprop)) {
        size_t i, size = json_array_size(jprop);

        if (!units) {
            units = vcardstrarray_new(1);
            vcardstrarray_append(units, "");
        }

        for (i = 0; i < size; i++) { 
            const char *myprops[] = { "@type", "name", "sortAs", NULL };
           json_t *unit = json_array_get(jprop, i);
            const char *key, *val;
            json_t *jsubprop;

            jmap_parser_push_index(parser, "units", i, NULL);

            jsubprop = json_object_get(unit, "@type");
            if (jsubprop && strcmpsafe("OrgUnit", json_string_value(jsubprop))) {
                jmap_parser_invalid(parser, "@type");
                break;
            }

            val = json_string_value(json_object_get(unit, "name"));
            if (val) {
                vcardstrarray_append(units, val);
            }
            else {
                jmap_parser_invalid(parser, "name");
                break;
            }

            jsubprop = json_object_get(unit, "sortAs");
            if (json_is_string(jsubprop)) {
                size_t num_empty;

                if (!sortas) {
                    sortas = vcardstrarray_new(1);
                }

                num_empty = i - vcardstrarray_size(sortas) + 1;
                while (num_empty--) {
                    vcardstrarray_append(sortas, "");
                }

                vcardstrarray_append(sortas, json_string_value(jsubprop));
            }
            else if (jsubprop) {
                jmap_parser_invalid(parser, "sortAs");
            }

            json_object_del(unit, "@type");
            json_object_del(unit, "name");
            json_object_del(unit, "sortAs");

            /* Add unknown properties */
            json_object_foreach(unit, key, jsubprop) {
                _jsunknown_to_vcard(parser, key, jsubprop, myprops, card);
            }

            jmap_parser_pop(parser);
        }

        if (i != size) {
            jmap_parser_pop(parser);
            vcardstrarray_free(units);
            units = NULL;
        }
    }
    else if (jprop) {
        jmap_parser_invalid(parser, "units");
    }

    if (units) {
        ptrarray_t *props = hash_lookup(id, groups);

        prop =  vcardproperty_new_org(units);
        if (sortas) {
            vcardproperty_add_parameter(prop, vcardparameter_new_sortas(sortas));
        }

        if (!props) {
            props = ptrarray_new();
            hash_insert(id, props, groups);
        }
        ptrarray_append(props, prop);
    }
    else if (sortas) {
        vcardstrarray_free(sortas);
    }

    json_object_del(obj, "name");
    json_object_del(obj, "units");
    json_object_del(obj, "sortAs");

    return prop;
}

static vcardproperty *_jspronoun_to_vcard(struct jmap_parser *parser, json_t *obj,
                                          const char *id __attribute__((unused)),
                                          vcardcomponent *card __attribute__((unused)),
                                          void *rock __attribute__((unused)))
{
    const char *val = json_string_value(json_object_get(obj, "pronouns"));
    vcardproperty *prop = NULL;

    if (!val) {
        jmap_parser_invalid(parser, "pronouns");
    }
    else {
        prop = vcardproperty_new_pronouns(val);

        json_object_del(obj, "pronouns");
    }

    return prop;
}

static unsigned _jsspeak_to_vcard(struct jmap_parser *parser,
                                  json_t *jval, struct l10n_by_id_t *l10n,
                                  vcardcomponent *card)
{
    struct l10n_rock lrock = { 0, NULL, { .prop_cb = &_jsspeak_to_vcard } };
    const char *myprops[] = { "@type", "grammaticalGender", "pronouns", NULL };
    json_t *jprop;
    const char *key;
    int r = 0;

    if (!json_is_object(jval)) {
        jmap_parser_invalid(parser, "speakToAs");
        return 0;
    }

    r = _jsl10n_to_vcard(parser, jval, "speakToAs", NULL, l10n, card, &lrock);
    jmap_parser_push(parser, "speakToAs");

    /* Add base object to Card */
    jprop = json_object_get(jval, "@type");
    if (jprop && strcmpsafe("SpeakToAs", json_string_value(jprop))) {
        jmap_parser_invalid(parser, "@type");
        goto done;
    }

    jprop = json_object_get(jval, "grammaticalGender");
    if (jprop) {
        if (jssimple_to_vcard(parser, "grammaticalGender", l10n->lang, jprop,
                              card, VCARD_GRAMGENDER_PROPERTY,
                              VCARD_GRAMGENDER_VALUE)) {
            r |= 1;
        }
        else {
            goto done;
        }
    }

    jprop = json_object_get(jval, "pronouns");
    if (jprop) {
        r |= _jsmultiobject_to_card(parser, jprop, "pronouns", "Pronouns",
                                    &_jspronoun_to_vcard, WANT_PROPID_FLAG,
                                    pref_param_props, l10n, card, NULL);
    }

    json_object_del(jval, "@type");
    json_object_del(jval, "grammaticalGender");
    json_object_del(jval, "pronouns");

    /* Add unknown properties */
    json_object_foreach(jval, key, jprop) {
        _jsunknown_to_vcard(parser, key, jprop, myprops, card);
    }

  done:
    jmap_parser_pop(parser);

    return r;
}

static vcardproperty *_jstitle_to_vcard(struct jmap_parser *parser, json_t *obj,
                                        const char *id __attribute__((unused)),
                                        vcardcomponent *card __attribute__((unused)),
                                        void *rock)
{
    hash_table *groups = rock;
    vcardproperty_kind kind = VCARD_NO_PROPERTY;
    vcardproperty *prop = NULL;
    json_t *jprop;
    const char *val;

    jprop = json_object_get(obj, "kind");
    if (json_is_string(jprop)) {
        val = json_string_value(jprop);

        if (!strcmp("title", val)) {
            kind = VCARD_TITLE_PROPERTY;
        }
        else if (!strcmp("role", val)) {
            kind = VCARD_ROLE_PROPERTY;
        }
        else {
            jmap_parser_invalid(parser, "kind");
        }
    }
    else if (jprop) {
        jmap_parser_invalid(parser, "kind");
    }
    else {
        kind = VCARD_TITLE_PROPERTY;
    }

    if (kind != VCARD_NO_PROPERTY) {
        val = json_string_value(json_object_get(obj, "name"));
        if (!val) {
            jmap_parser_invalid(parser, "name");
        }
        else {
            json_t *jprop = json_object_get(obj, "organizationId");

            prop = vcardproperty_new(kind);
            vcardproperty_set_value_from_string(prop, val, "TEXT");

            if (json_is_string(jprop)) {
                const char *group = json_string_value(jprop);
                ptrarray_t *props = hash_lookup(group, groups);

                if (!props) {
                    props = ptrarray_new();
                    hash_insert(group, props, groups);
                }
                ptrarray_append(props, prop);

                json_object_del(obj, "organizationId");
            }
            else if (jprop) {
                jmap_parser_invalid(parser, "organizationId");
            }

            json_object_del(obj, "kind");
            json_object_del(obj, "name");
        }
    }

    return prop;
}

struct comm_rock {
    const char *val_key;
    vcardproperty_kind kind;
};

static vcardproperty *_jscomm_to_vcard(struct jmap_parser *parser, json_t *obj,
                                       const char *id __attribute__((unused)),
                                       vcardcomponent *card __attribute__((unused)),
                                       void *rock)
{
    struct comm_rock *crock = rock;
    vcardproperty *prop = NULL;
    const char *val = json_string_value(json_object_get(obj, crock->val_key));
    const char *val_kind = "URI";

    if (!val) {
        jmap_parser_invalid(parser, crock->val_key);
    }
    else {
        size_t i, len = strlen(val), have_scheme = 0;

        for (i = 0; i < len; i++) {
            if (!isascii(val[i]) || !isprint(val[i]) || isspace(val[i]))
                break;
            else if (i && val[i] == ':')
                have_scheme = 1;
        }

        if (!have_scheme || i < len) val_kind = "TEXT";

        prop = vcardproperty_new(crock->kind);
        vcardproperty_set_value_from_string(prop, val, val_kind);

        json_object_del(obj, crock->val_key);
    }

    return prop;
}

static vcardproperty *_jsonline_to_vcard(struct jmap_parser *parser, json_t *obj,
                                         const char *id __attribute__((unused)),
                                         vcardcomponent *card __attribute__((unused)),
                                         void *rock __attribute__((unused)))
{
    const char *service = NULL, *user = NULL, *val = NULL, *val_kind = "TEXT";
    vcardproperty_kind kind = VCARD_SOCIALPROFILE_PROPERTY;
    vcardproperty *prop = NULL;
    json_t *jprop;

    jprop = json_object_get(obj, "service");
    if (json_is_string(jprop)) {
        service = json_string_value(jprop);
    }
    else if (jprop) {
        jmap_parser_invalid(parser, "service");
    }

    jprop = json_object_get(obj, "user");
    if (json_is_string(jprop)) {
        user = json_string_value(jprop);
    }
    else if (jprop) {
        jmap_parser_invalid(parser, "user");
    }

    jprop = json_object_get(obj, "uri");
    if (json_is_string(jprop)) {
        val_kind = "URI";
        val = json_string_value(jprop);

        if (!strncasecmp("xmpp:", val, 5)) {
            kind = VCARD_IMPP_PROPERTY;
        }
    }
    else if (jprop || !user) {
        jmap_parser_invalid(parser, "uri");
    }
    else {
        val = user;
        user = NULL;
    }

    jprop = json_object_get(obj, "vCardName");
    if (json_is_string(jprop)) {
        kind = vcardproperty_string_to_kind(json_string_value(jprop));

        if (kind == VCARD_NO_PROPERTY) {
            jmap_parser_invalid(parser, "vCardName");
        }
    }
    else if (jprop) {
        jmap_parser_invalid(parser, "vCardName");
    }

    if (val) {
        prop = vcardproperty_new(kind);
        vcardproperty_set_value_from_string(prop, val, val_kind);
            
        if (service) {
            vcardproperty_add_parameter(prop,
                                        vcardparameter_new_servicetype(service));
        }
        if (user) {
            vcardproperty_add_parameter(prop, vcardparameter_new_username(user));
        }
    }

    json_object_del(obj, "service");
    json_object_del(obj, "user");
    json_object_del(obj, "uri");
    json_object_del(obj, "vCardName");

    return prop;
}

static vcardproperty *_jspreflang_to_vcard(struct jmap_parser *parser,
                                           json_t *obj,
                                           const char *id __attribute__((unused)),
                                           vcardcomponent *card __attribute__((unused)),
                                           void *rock __attribute__((unused)))
{
    const char *lang = json_string_value(json_object_get(obj, "language"));
    vcardproperty *prop = NULL;

    if (!lang) {
        jmap_parser_invalid(parser, "language");
    }
    else {
        prop = vcardproperty_new_lang(lang);

        json_object_del(obj, "language");
    }

    return prop;
}

struct resource_map {
    const char *kind;
    vcardproperty_kind pkind;
    unsigned supports_blobid : 1;
};

struct resource_rock {
    struct jmap_req *req;
    struct resource_map *map;
    ptrarray_t *blobs;
    jmap_contact_errors_t *errors;
};

static vcardproperty *_jsresource_to_vcard(struct jmap_parser *parser, json_t *obj,
                                           const char *id,
                                           vcardcomponent *card __attribute__((unused)),
                                           void *rock)
{
    struct resource_rock *rrock = rock;
    struct resource_map *m;
    vcardproperty_kind pkind;
    const char *mkind, *uri = NULL;
    struct buf buf = BUF_INITIALIZER;
    char *media_type;
    json_t *jprop;

    mkind = json_string_value(json_object_get(obj, "kind"));
    for (m = rrock->map; m->kind; m++) {
        if (!strcmpnull(m->kind, mkind)) {
            break;
        }
    }
    pkind = m->pkind;

    if (pkind == VCARD_NO_PROPERTY) {
        jmap_parser_invalid(parser, "kind");
        return NULL;
    }

    jprop = json_object_get(obj, "uri");
    if (json_is_string(jprop)) {
        uri = json_string_value(jprop);
    }
    else if (jprop) {
        jmap_parser_invalid(parser, "uri");
        return NULL;
    }

    media_type =
        xstrdupnull(json_string_value(json_object_get(obj, "mediaType")));

    if (m->supports_blobid) {
        jmap_getblob_context_t ctx = { 0 };
        struct buf *blob = NULL;

        /* blobId supersedes uri */
        jprop = json_object_get(obj, "blobId");
        if (jprop) {
            /* Extract blobId */
            if (!json_is_string(jprop)) {
                jmap_parser_invalid(parser, "blobId");
                return NULL;
            }

            const char *blobid = jmap_id_string_value(rrock->req, jprop);
            const char *accountid =
                json_string_value(json_object_get(obj, "accountId"));

            /* Find blob */
            jmap_getblob_ctx_init(&ctx, accountid, blobid, media_type, 1);

            int r = jmap_getblob(rrock->req, &ctx);

            switch (r) {
            case 0:
                if (!buf_len(&ctx.content_type) ||
                    strchr(buf_cstring(&ctx.content_type), '/')) break;

                /* Fall through */
                GCC_FALLTHROUGH

            case HTTP_NOT_ACCEPTABLE:
                jmap_parser_invalid(parser, "mediaType");
                return NULL;

            default:
                /* Not found, or system error */
                if (!rrock->errors->blobNotFound)
                    rrock->errors->blobNotFound = json_array();
                json_array_append(rrock->errors->blobNotFound, jprop);
                return NULL;
            }

            buf_printf(&buf, "data:%s;base64,", buf_lcase(&ctx.content_type));

            const char *base = buf_base(&ctx.blob);
            size_t len = buf_len(&ctx.blob);

            /* Pre-flight base64 encoder to determine length */
            size_t len64 = 0;
            charset_b64encode_mimebody(NULL, len, NULL,
                                    &len64, NULL, 0 /* no wrap */);

            /* Now encode the blob */
            buf_ensure(&buf, len64+1);
            charset_b64encode_mimebody(base, len,
                                    (char *) buf_base(&buf) + buf_len(&buf),
                                    &len64, NULL, 0 /* no wrap */);
            buf_truncate(&buf, buf_len(&buf) + len64);
            uri = buf_cstring(&buf);

            if (!media_type) media_type = buf_release(&ctx.content_type);
            blob = &ctx.blob;

            json_object_del(obj, "blobId");
            json_object_del(obj, "accountId");
        }
        else if (uri && !strncmp(uri, "data:", 5)) {
            const char *data = strchr(uri, ',') + 1;
            char *decbuf = NULL;
            size_t size = 0;

            if (!media_type) {
                const char *mt = uri + 5;

                size = strcspn(mt, ";,");
                if (size) {
                    media_type = xstrndup(mt, size);
                }
            }

            /* Decode property value */
            charset_decode_mimebody(data, strlen(data),
                                    ENCODING_BASE64, &decbuf, &size);
            buf_initm(&buf, decbuf, size);
            blob = &buf;
        }

        if (blob) {
            /* Add this blob to our list */
            const char *prop_name = vcardproperty_kind_to_string(pkind);

            ptrarray_append(rrock->blobs,
                            property_blob_new(id, prop_name, media_type, blob));

            json_object_del(obj, "mediaType");
        }

        jmap_getblob_ctx_fini(&ctx);
    }

    free(media_type);

    if (!uri) {
        jmap_parser_invalid(parser, "uri");
        return NULL;
    }

    vcardproperty *prop = vcardproperty_new(pkind);
    vcardproperty_set_value_from_string(prop, uri, "URI");

    json_object_del(obj, "kind");
    json_object_del(obj, "uri");

    buf_free(&buf);

    return prop;
}

static vcardproperty *_jsaddr_to_vcard(struct jmap_parser *parser, json_t *obj,
                                       const char *id, vcardcomponent *card,
                                       void *rock __attribute__((unused)))
{
    struct jscomps_args args = {
        &vcardproperty_vanew_adr, VCARD_NUM_ADR_FIELDS,
        id, "Address", adr_comp_kinds, NULL
    };
    json_t *comps = json_object_get(obj, "components");

    if (comps && !json_boolean_value(json_object_get(obj, "isOrdered"))) {
        /* Bubble sort the components by kind
           (for building extended/street fields) */
        size_t i, j, size = json_array_size(comps);

        for (i = 0; i < size - 1; i++) {
            int swap = 0;

            for (j = 0; j < size - i - 1; j++) {
                json_t *comp1 = json_array_get(comps, j);
                json_t *comp2 = json_array_get(comps, j+1);
                const char *kind1 =
                    json_string_value(json_object_get(comp1, "kind"));
                const char *kind2 =
                    json_string_value(json_object_get(comp2, "kind"));
                const struct comp_kind *ckind1 =
                    kind1 ? _field_name_to_kind(kind1, adr_comp_kinds) : NULL;
                const struct comp_kind *ckind2 =
                    kind2 ? _field_name_to_kind(kind2, adr_comp_kinds) : NULL;

                if (!ckind1 || !ckind2) break;

                if (ckind1 > ckind2) {
                    json_t *tmp = json_copy(comp1);
                    json_array_set(comps, j, comp2);
                    json_array_set_new(comps, j+1, tmp);
                    swap = 1;
                }
            }

            if (!swap) break;
        }
    }

    return _jscomps_to_vcard(parser, obj, card, &args);
}

static vcardproperty *_jsanniv_to_vcard(struct jmap_parser *parser,
                                        json_t *anniv, const char *id,
                                        vcardcomponent *card,
                                        void *rock __attribute__((unused)))
{
    vcardproperty_kind date_kind, place_kind = VCARD_NO_PROPERTY;
    vcardproperty *prop = NULL;
    json_t *jprop, *jsubprop;
    const char *key, *val;

    val = json_string_value(json_object_get(anniv, "kind"));
    if (!strcmpsafe("birth", val)) {
        date_kind = VCARD_BDAY_PROPERTY;
        place_kind = VCARD_BIRTHPLACE_PROPERTY;
    }
    else if (!strcmpsafe("death", val)) {
        date_kind = VCARD_DEATHDATE_PROPERTY;
        place_kind = VCARD_DEATHPLACE_PROPERTY;
    }
    else if (!strcmpsafe("wedding", val)) {
        date_kind = VCARD_ANNIVERSARY_PROPERTY;
    }
    else {
        _jsunknown_to_vcard(parser, NULL, anniv, NULL, card);
        return NULL;
    }

    json_object_del(anniv, "kind");

    jprop = json_object_get(anniv, "date");
    if (json_is_object(jprop)) {
        const char *myprops[] = {
            "@type", "year", "month", "day", "calendarScale", "utc", NULL
        };
        const char *calscale = NULL;
        vcardvalue *value = NULL;
        vcardtimetype tt;

        jmap_parser_push(parser, "date");

        jsubprop = json_object_get(jprop, "@type");
        if (!jsubprop ||  // defaultType
            !strcmpsafe("PartialDate", json_string_value(jsubprop))) {

            json_object_del(jprop, "@type");

            tt = vcardtime_null_date();

            jsubprop = json_object_get(jprop, "year");
            if (json_is_integer(jsubprop)) {
                tt.year = json_integer_value(jsubprop);
                json_object_del(jprop, "year");
            }
            else if (jsubprop) {
                jmap_parser_invalid(parser, "year");
            }

            jsubprop = json_object_get(jprop, "month");
            if (json_is_integer(jsubprop)) {
                tt.month = json_integer_value(jsubprop);
                json_object_del(jprop, "month");
            }
            else if (jsubprop) {
                jmap_parser_invalid(parser, "month");
            }

            jsubprop = json_object_get(jprop, "day");
            if (json_is_integer(jsubprop)) {
                tt.day = json_integer_value(jsubprop);
                json_object_del(jprop, "day");
            }
            else if (jsubprop) {
                jmap_parser_invalid(parser, "day");
            }

            jsubprop = json_object_get(jprop, "calendarScale");
            if (json_is_string(jsubprop)) {
                calscale = json_string_value(jsubprop);
            }
            else if (jsubprop) {
                jmap_parser_invalid(parser, "calendarScale");
            }

            if (!vcardtime_is_null_datetime(tt)) {
                value = vcardvalue_new_date(tt);
            }
        }
        else if (!strcmpsafe("Timestamp", json_string_value(jsubprop))) {
            jsubprop = json_object_get(jprop, "utc");
            if (!json_is_utcdate(jsubprop)) {
                jmap_parser_invalid(parser, "utc");
            }
            else {
                tt = vcardtime_from_string(json_string_value(jsubprop), 0);
                value = vcardvalue_new_timestamp(tt);
                json_object_del(jprop, "utc");
            }
        }
        else {
            jmap_parser_invalid(parser, "@type");
        }

        if (value) {
            prop = vcardproperty_new(date_kind);
            vcardproperty_set_value(prop, value);

            if (calscale) {
                vcardparameter *param =
                    vcardparameter_new_from_value_string(VCARD_CALSCALE_PARAMETER,
                                                         calscale);
                vcardproperty_add_parameter(prop, param);
            }

            json_object_del(jprop, "@type");
            json_object_del(jprop, "calendarScale");
        }

        /* Add unknown properties */
        json_object_foreach(jprop, key, jsubprop) {
            _jsunknown_to_vcard(parser, key, jsubprop, myprops, card);
        }

        json_object_del(anniv, "date");

        jmap_parser_pop(parser);
    }
    else if (jprop) {
        jmap_parser_invalid(parser, "date");
        return NULL;
    }

    jprop = json_object_get(anniv, "place");
    if (json_is_object(jprop)) {
        if (place_kind != VCARD_NO_PROPERTY) {
            const char *myprops[] = { "@type", "full", "coordinates", NULL };

            jmap_parser_push(parser, "place");

            jsubprop = json_object_get(jprop, "@type");
            if (jsubprop && strcmpsafe("Address", json_string_value(jsubprop))) {
                jmap_parser_invalid(parser, "@type");
            }
            else {
                const char *val_kind = NULL;

                if ((val =
                     json_string_value(json_object_get(jprop, "full")))) {
                    val_kind = "TEXT";
                }
                else if ((val =
                          json_string_value(json_object_get(jprop,
                                                            "coordinates")))) {
                    val_kind = "URI";
                }

                if (val_kind) {
                    vcardproperty *myprop = vcardproperty_new(place_kind);

                    vcardproperty_set_value_from_string(myprop, val, val_kind);

                    if (!prop) {
                        prop = myprop;
                    }
                    else {
                        vcardproperty_add_parameter(myprop,
                                                    vcardparameter_new_propid(id));
                        vcardcomponent_add_property(card, myprop);
                    }
                }

                json_object_del(jprop, "@type");
                json_object_del(jprop, "full");
                json_object_del(jprop, "coordinates");

                /* Add unknown properties */
                json_object_foreach(jprop, key, jsubprop) {
                    _jsunknown_to_vcard(parser, key, jsubprop, myprops, card);
                }
            }

            jmap_parser_pop(parser);
        }
        else {
            _jsunknown_to_vcard(parser, "place", jprop, NULL, card);
        }

        json_object_del(anniv, "place");
    }
    else if (jprop) {
        jmap_parser_invalid(parser, "place");
        return NULL;
    }

    return prop;
}

static vcardproperty *_jsnote_to_vcard(struct jmap_parser *parser,
                                       json_t *obj,
                                       const char *id __attribute__((unused)),
                                       vcardcomponent *card __attribute__((unused)),
                                       void *rock __attribute__((unused)))
{
    vcardproperty *prop = NULL;
    json_t *jprop;
    const char *val;

    val = json_string_value(json_object_get(obj, "note"));
    if (!val) {
        jmap_parser_invalid(parser, "note");
        return NULL;
    }

    prop = vcardproperty_new_note(val);

    jprop = json_object_get(obj, "author");
    if (json_is_object(jprop)) {
        const char *myprops[] = { "@type", "name", "uri", NULL };
        json_t *jsubprop;
        const char *key;

        jmap_parser_push(parser, "author");

        jsubprop = json_object_get(jprop, "@type");
        if (jsubprop && strcmpsafe("Author", json_string_value(jsubprop))) {
            jmap_parser_invalid(parser, "@type");
        }
        else {
            jsubprop = json_object_get(jprop, "name");
            if (json_is_string(jsubprop)) {
                val = json_string_value(jsubprop);
                vcardproperty_add_parameter(prop,
                                            vcardparameter_new_authorname(val));

                json_object_del(jprop, "name");
            }
            else if (jsubprop) {
                jmap_parser_invalid(parser, "name");
            }

            jsubprop = json_object_get(jprop, "uri");
            if (json_is_string(jsubprop)) {
                val = json_string_value(jsubprop);
                vcardproperty_add_parameter(prop, vcardparameter_new_author(val));

                json_object_del(jprop, "uri");
            }
            else if (jsubprop) {
                jmap_parser_invalid(parser, "uri");
            }
        }

        json_object_del(jprop, "@type");

        /* Add unknown properties */
        json_object_foreach(jprop, key, jsubprop) {
            _jsunknown_to_vcard(parser, key, jsubprop, myprops, card);
        }

        json_object_del(obj, "author");

        jmap_parser_pop(parser);
    }
    else if (jprop) {
        jmap_parser_invalid(parser, "author");
    }

    json_object_del(obj, "note");

    return prop;
}

static vcardproperty *_jspersonal_to_vcard(struct jmap_parser *parser,
                                           json_t *obj,
                                           const char *id __attribute__((unused)),
                                           vcardcomponent *card __attribute__((unused)),
                                           void *rock __attribute__((unused)))
{
    vcardproperty_kind pkind;
    vcardproperty *prop = NULL;
    const char *val;

    val = json_string_value(json_object_get(obj, "kind"));
    if (!strcmpsafe("expertise", val)) {
        pkind = VCARD_EXPERTISE_PROPERTY;
    }
    else if (!strcmpsafe("hobby", val)) {
        pkind = VCARD_HOBBY_PROPERTY;
    }
    else if (!strcmpsafe("interest", val)) {
        pkind = VCARD_INTEREST_PROPERTY;
    }
    else {
        jmap_parser_invalid(parser, "kind");
        return NULL;
    }

    val = json_string_value(json_object_get(obj, "value"));
    if (!val) {
        jmap_parser_invalid(parser, "value");
        return NULL;
    }

    prop = vcardproperty_new(pkind);
    vcardproperty_set_value_from_string(prop, val, "TEXT");

    json_object_del(obj, "kind");
    json_object_del(obj, "value");

    return prop;
}

static void _set_groups(const char *key, void *val,
                        void *rock __attribute__((unused)))
{
    ptrarray_t *props = val;
    int i;

    for (i = 0; i < ptrarray_size(props); i++) {
        vcardproperty *prop = ptrarray_nth(props, i);

        vcardproperty_set_group(prop, key);
    }
}

struct bad_patch_rock {
    struct jmap_parser *parser;
    const char *key;
};

static void _invalid_l10n_patches_by_id(const char *id, void *val, void *rock)
{
    struct bad_patch_rock *brock = rock;
    json_t *patches = val, *jpatch;
    const char *lang;

    json_object_foreach(patches, lang, jpatch) {
        jmap_parser_push(brock->parser, lang);
        jmap_parser_push(brock->parser, brock->key);

        if (json_object_size(jpatch)) {
            struct buf buf = BUF_INITIALIZER;
            const char *path;
            int len;

            jmap_parser_push(brock->parser, id);
            jmap_parser_path(brock->parser, &buf);
            len = buf_len(&buf);

            json_object_foreach(jpatch, path, val) {
                if (*path) {
                    buf_putc(&buf, '/');
                    buf_appendcstr(&buf, path);
                }
                jmap_parser_invalid_path(brock->parser, buf_cstring(&buf));
                buf_truncate(&buf, len);
            }

            jmap_parser_pop(brock->parser);
            buf_free(&buf);
        }
        else {
            jmap_parser_invalid(brock->parser, id);
        }

        jmap_parser_pop(brock->parser);
        jmap_parser_pop(brock->parser);
    }

    json_decref(patches);
}

static void _invalid_l10n_patches_by_key(const char *key, void *val, void *rock)
{
    struct bad_patch_rock brock = { rock /* parser */, key };
    hash_table *patches_by_id = val;

    hash_enumerate(patches_by_id, &_invalid_l10n_patches_by_id, &brock);
    free_hash_table(patches_by_id, NULL);
    free(patches_by_id);
}

static void _jscard_set_importance(struct jmap_req *req,
                                   const char *mboxname,
                                   const char *key, json_t *arg,
                                   struct entryattlist **annotsp,
                                   jmap_contact_errors_t *errors)
{
    if (json_is_number(arg)) {
        const char *ns = DAV_ANNOT_NS "<" XML_NS_CYRUS ">importance";
        const char *attrib = mboxname_userownsmailbox(req->userid, mboxname) ?
            "value.shared" : "value.priv";
        struct buf buf = BUF_INITIALIZER;

        buf_printf(&buf, "%.17g", json_number_value(arg));

        setentryatt(annotsp, ns, attrib, &buf);
        buf_free(&buf);
    } else {
        json_array_append_new(errors->invalid, json_string(key));
    }
}

static unsigned _vcardprops_to_card(struct jmap_parser *parser, json_t *jval,
                                    vcardcomponent *card)
{
    size_t i;
    json_t *jcard;
    struct buf buf = BUF_INITIALIZER;
    int r = 0;

    if (!json_is_array(jval)) {
        jmap_parser_invalid(parser, "vCardProps");
        return 0;
    }

    jmap_parser_push(parser, "vCardProps");

    json_array_foreach(jval, i, jcard) {
        const char *name, *val_type, *val;
        json_t *params;
        vcardproperty *prop;

        if (json_array_size(jcard) != 4) {
            buf_reset(&buf);
            buf_printf(&buf, "%zu", i);
            jmap_parser_invalid(parser, buf_cstring(&buf));
            break;
        }

        name = json_string_value(json_array_get(jcard, 0));
        params = json_array_get(jcard, 1);
        val_type = json_string_value(json_array_get(jcard, 2));
        val = json_string_value(json_array_get(jcard, 3));
        prop = vcardproperty_new_x(val);

        buf_setcstr(&buf, name);
        vcardproperty_set_x_name(prop, buf_ucase(&buf));
        vcardcomponent_add_property(card, prop);

        if (strcmp(val_type, "unknown")) {
            vcardparameter_value type = vcardparameter_string_to_enum(val_type);;

            vcardproperty_add_parameter(prop, vcardparameter_new_value(type));
        }

        _vcardparams_to_prop(params, prop);

        r = 1;
    }

    jmap_parser_pop(parser);
    buf_free(&buf);

    return r;
}

#define PROP_LANG_TAG_PREFIX      "cyrusimap.org:lang:"
#define PROP_LANG_TAG_PREFIX_LEN  19

static void reject_reserved_props(json_t *jsobj, struct jmap_parser *parser)
{
    if (JNULL(jsobj)) return;

    const char *key;
    json_t *jval;
    json_object_foreach(jsobj, key, jval) {
        if (!strcasecmp(key, "extra")) {
            jmap_parser_invalid(parser, key);
        }
        else if (strchr(key, '/')) {
            strarray_t *segs = strarray_split(key, "/", STRARRAY_LCASE);
            for (int i = 0; i < strarray_size(segs); i++) {
                if (!strcmp(strarray_nth(segs, i), "extra")) {
                    jmap_parser_invalid(parser, key);
                    break;
                }
            }
            strarray_free(segs);
        }

        for (size_t i = 0; i < json_array_size(jval); i++) {
            jmap_parser_push_index(parser, key, i, NULL);
            reject_reserved_props(json_array_get(jval, i), parser);
            jmap_parser_pop(parser);
        }

        if (json_object_size(jval)) {
            jmap_parser_push(parser, key);
            reject_reserved_props(jval, parser);
            jmap_parser_pop(parser);
        }
    }
}

static int _jscard_to_vcard(struct jmap_req *req,
                            struct carddav_data *cdata,
                            const char *mboxname,
                            vcardcomponent *card,
                            json_t *arg,
                            struct entryattlist **annotsp,
                            ptrarray_t *blobs,
                            jmap_contact_errors_t *errors)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    const char *key, *deflang = NULL, *lang, *p;
    json_t *jval;
    unsigned has_noncontent = 0;
    unsigned record_is_dirty = 0;
    hash_table groups = HASH_TABLE_INITIALIZER;
    hash_table l10n_by_key = HASH_TABLE_INITIALIZER;
    struct buf buf = BUF_INITIALIZER;
    unsigned has_localized_name = 0;
    int r = 0;

    json_decref(parser.invalid);
    parser.invalid = errors->invalid;

    /* Using reserved props is invalid */
    reject_reserved_props(arg, &parser);

    /* Estimate upper bound for required vCard groups */
    size_t ngroups = 0;
    json_object_foreach(arg, key, jval) {
        ngroups += json_object_size(jval);
    }
    construct_hash_table(&groups, ngroups + 1, 0);

    /* Estimate upper bound for localized property count */
    size_t nl10n = 0;
    json_object_foreach(json_object_get(arg, "localizations"), lang, jval) {
        nl10n++;
    }
    construct_hash_table(&l10n_by_key, nl10n + 1, 0);

    deflang = json_string_value(json_object_get(arg, "language"));
    json_object_foreach(json_object_get(arg, "localizations"), lang, jval) {
        json_t *jsubval;

        json_object_foreach(jval, key, jsubval) {
            p = strchr(key, '/');

            if (p) {
                /* Localization patch:
                 *
                 * Patches are stored in a hash table (by property key)
                 * of hash tables (by object id) of JSON patches (by lang).
                 */
                hash_table *patches_by_id;
                const char *prop_key, *id = p+1, *path = "";
                json_t *patches_by_lang, *patch;

                buf_setmap(&buf, key, p - key);
                prop_key = buf_cstring(&buf);
                patches_by_id = hash_lookup(prop_key, &l10n_by_key);
                if (!patches_by_id) {
                    patches_by_id = xzmalloc(sizeof(hash_table));
                    construct_hash_table(patches_by_id, ngroups + 1, 0);
                    hash_insert(prop_key, patches_by_id, &l10n_by_key);
                }

                if (!strcmp(prop_key, "name") ||
                    !strcmp(prop_key, "speakToAs")) {
                    path = id;
                    id = "";
                }
                else {
                    p = strchr(id, '/');
                    if (p) {
                        buf_setmap(&buf, id, p - id);
                        id = buf_cstring(&buf);
                        path = ++p;
                    }
                }

                patches_by_lang = hash_lookup(id, patches_by_id);
                if (!patches_by_lang) {
                    patches_by_lang = json_object();
                    hash_insert(id, patches_by_lang, patches_by_id);
                }

                patch = json_object_get(patches_by_lang, lang);
                if (!patch) {
                    patch = json_object();
                    json_object_set_new(patches_by_lang, lang, patch);
                }

                json_object_set(patch, path, jsubval);
            }
            else {
                /* Localization object:
                 *
                 * Prefix the property key with vendor + language tags
                 * and add the object to the Card for normal processing.
                 */
                if (!strcmp("name", key)) {
                    has_localized_name = 1;
                }

                buf_reset(&buf);
                buf_printf(&buf, "%s%s:%s", PROP_LANG_TAG_PREFIX, lang, key);
                json_object_set(arg, buf_cstring(&buf), jsubval);
            }
        }
    }

    json_object_foreach(arg, key, jval) {
        struct l10n_by_id_t l10n = { deflang, NULL, NULL };
        const char *mykey;

        if (cdata) {
            if (!strcmp(key, "id")) {
                if (strcmpnull(cdata->vcard_uid, json_string_value(jval))) {
                    jmap_parser_invalid(&parser, "id");
                }
                continue;
            }
            if (!strcmp(key, "uid")) {
                if (strcmpnull(cdata->vcard_uid, json_string_value(jval))) {
                    jmap_parser_invalid(&parser, "uid");
                }
                continue;
            }
            else if (!strcmp(key, "cyrusimap.org:href")) {
                char *xhref = jmap_xhref(mboxname, cdata->dav.resource);
                if (strcmpnull(json_string_value(jval), xhref)) {
                    jmap_parser_invalid(&parser, "cyrusimap.org:href");
                }
                free(xhref);
                continue;
            }
        }

        /* Localization property? */
        if (!strncmp(PROP_LANG_TAG_PREFIX, key, PROP_LANG_TAG_PREFIX_LEN)) {
            /* Strip prefix and get language tag */
            lang = key + PROP_LANG_TAG_PREFIX_LEN;
            p = strchr(lang, ':');

            buf_setmap(&buf, lang, p - lang);
            lang = buf_cstring(&buf);
            mykey = ++p;

            /* If language tag == deflang,
               don't add LANGUAGE parameter, but still force ALTID parameter */
            l10n.lang = strcasecmpsafe(lang, l10n.deflang) ? lang : "";

            jmap_parser_push(&parser, "localizations");
            jmap_parser_push(&parser, lang);
        }
        else {
            /* Fetch any localization patches for this property */
            l10n.patches = hash_lookup(key, &l10n_by_key);
            if (l10n.patches) {
                /* Force ALTID parameter */
                l10n.lang = "";
            }
            mykey = key;
        }

        /* Metadata properties */
        if (!strcmp(mykey, "@type")) {
            if (strcmpsafe("Card", json_string_value(jval))) {
                jmap_parser_invalid(&parser, "@type");
            }
        }
        else if (!strcmp(mykey, "version")) {
            if (strcmpsafe("1.0", json_string_value(jval))) {
                jmap_parser_invalid(&parser, "version");
            }
        }
        else if (!strcmp(mykey, "created")) {
            record_is_dirty |= jssimple_to_vcard(&parser, mykey, l10n.lang,
                                                 jval, card,
                                                 VCARD_CREATED_PROPERTY,
                                                 VCARD_TIMESTAMP_VALUE);
        }
        else if (!strcmp(mykey, "kind")) {
            record_is_dirty |= jssimple_to_vcard(&parser, mykey, l10n.lang,
                                                 jval, card,
                                                 VCARD_KIND_PROPERTY,
                                                 VCARD_KIND_VALUE);
        }
        else if (!strcmp(mykey, "language")) {
            record_is_dirty |= jssimple_to_vcard(&parser, mykey, l10n.lang,
                                                 jval, card,
                                                 VCARD_LANGUAGE_PROPERTY,
                                                 VCARD_TEXT_VALUE);
        }
        else if (!strcmp(mykey, "members")) {
            record_is_dirty |= _jsmultikey_to_card(&parser, jval, mykey, card,
                                                   VCARD_MEMBER_PROPERTY);
        }
        else if (!strcmp(mykey, "prodId")) {
            record_is_dirty |= jssimple_to_vcard(&parser, mykey, l10n.lang,
                                                 jval, card,
                                                 VCARD_PRODID_PROPERTY,
                                                 VCARD_TEXT_VALUE);
        }
        else if (!strcmp(mykey, "relatedTo")) {
            struct param_prop_t relation_props[] = {
                { "relation", VCARD_TYPE_PARAMETER  },
                { NULL,       0                     }
            };

            record_is_dirty |= _jsmultiobject_to_card(&parser, jval,
                                                      mykey, "Relation",
                                                      &_jsrelation_to_vcard,
                                                      0 /* no flags */,
                                                      relation_props, &l10n,
                                                      card, NULL);
        }
        else if (!strcmp(mykey, "uid")) {
            if (!json_is_string(jval)) {
                jmap_parser_invalid(&parser, "uid");
                break;
            }
        }
        else if (!strcmp(mykey, "updated")) {
            record_is_dirty |= jssimple_to_vcard(&parser, mykey, l10n.lang,
                                                 jval, card,
                                                 VCARD_REV_PROPERTY,
                                                 VCARD_TIMESTAMP_VALUE);
        }

        /* Name and Organization properties */
        else if (!strcmp(mykey, "name")) {
            if (!l10n.lang && has_localized_name) {
                l10n.lang = "";
            }
            record_is_dirty |= _jsname_to_vcard(&parser, jval, &l10n, card);
        }
        else if (!strcmp(mykey, "nicknames")) {
            record_is_dirty |= _jsmultiobject_to_card(&parser, jval,
                                                      mykey, "Nickname",
                                                      &_jsnickname_to_vcard,
                                                      WANT_PROPID_FLAG,
                                                      pref_param_props, &l10n,
                                                      card, NULL);
        }
        else if (!strcmp(mykey, "organizations")) {
            record_is_dirty |= _jsmultiobject_to_card(&parser, jval,
                                                      mykey, "Organization",
                                                      &_jsorg_to_vcard,
                                                      WANT_PROPID_FLAG,
                                                      context_param_props, &l10n,
                                                      card, &groups);
        }
        else if (!strcmp(mykey, "speakToAs")) {
            record_is_dirty |= _jsspeak_to_vcard(&parser, jval, &l10n, card);
        }
        else if (!strcmp(mykey, "titles")) {
            record_is_dirty |= _jsmultiobject_to_card(&parser, jval,
                                                      mykey, "Title",
                                                      &_jstitle_to_vcard,
                                                      WANT_PROPID_FLAG,
                                                      NULL, &l10n,
                                                      card, &groups);
        }

        /* Contact properties */
        else if (!strcmp(mykey, "emails")) {
            struct comm_rock crock = { "address", VCARD_EMAIL_PROPERTY };

            record_is_dirty |= _jsmultiobject_to_card(&parser, jval,
                                                      mykey, "EmailAddress",
                                                      &_jscomm_to_vcard,
                                                      WANT_PROPID_FLAG,
                                                      comm_param_props, &l10n,
                                                      card, &crock);
        }
        else if (!strcmp(mykey, "onlineServices")) {
            record_is_dirty |= _jsmultiobject_to_card(&parser, jval,
                                                      mykey, "OnlineService",
                                                      &_jsonline_to_vcard,
                                                      WANT_PROPID_FLAG,
                                                      comm_param_props, &l10n,
                                                      card, NULL);
        }
        else if (!strcmp(mykey, "phones")) {
            struct comm_rock crock = { "number", VCARD_TEL_PROPERTY };

            record_is_dirty |= _jsmultiobject_to_card(&parser, jval,
                                                      mykey, "Phone",
                                                      &_jscomm_to_vcard,
                                                      WANT_PROPID_FLAG,
                                                      phone_param_props, &l10n,
                                                      card, &crock);
        }
        else if (!strcmp(mykey, "preferredLanguages")) {
            record_is_dirty |= _jsmultiobject_to_card(&parser, jval,
                                                      mykey, "LanguagePref",
                                                      &_jspreflang_to_vcard,
                                                      WANT_PROPID_FLAG,
                                                      pref_param_props, &l10n,
                                                      card, NULL);
        }

        /* Calendaring and Scheduling properties*/
        else if (!strcmp(mykey, "calendars")) {
            struct resource_map map[] = {
                { "calendar", VCARD_CALURI_PROPERTY, 0 },
                { "freeBusy", VCARD_FBURL_PROPERTY,  0 },
                { NULL,       VCARD_NO_PROPERTY,     0 }
            };
            struct resource_rock rrock = { req, map, blobs, errors };

            record_is_dirty |= _jsmultiobject_to_card(&parser, jval,
                                                      mykey, "CalendarResource",
                                                      &_jsresource_to_vcard,
                                                      WANT_PROPID_FLAG,
                                                      resource_param_props,
                                                      &l10n, card, &rrock);
        }
        else if (!strcmp(mykey, "schedulingAddresses")) {
            struct comm_rock crock = { "uri", VCARD_CALADRURI_PROPERTY };

            record_is_dirty |= _jsmultiobject_to_card(&parser, jval,
                                                      mykey, "SchedulingAddress",
                                                      &_jscomm_to_vcard,
                                                      WANT_PROPID_FLAG,
                                                      comm_param_props, &l10n,
                                                      card, &crock);
        }

        /* Address and Location properties */
        else if (!strcmp(mykey, "addresses")) {
            struct param_prop_t addr_props[] = {
                { "pref",        VCARD_PREF_PARAMETER  },
                { "contexts",    VCARD_TYPE_PARAMETER  },
                { "timeZone",    VCARD_TZ_PARAMETER    },
                { "countryCode", VCARD_CC_PARAMETER    },
                { "coordinates", VCARD_GEO_PARAMETER   },
                { "full",        VCARD_LABEL_PARAMETER },
                { NULL,          0                     }
            };

            record_is_dirty |= _jsmultiobject_to_card(&parser, jval,
                                                      mykey, "Address",
                                                      &_jsaddr_to_vcard,
                                                      WANT_PROPID_FLAG,
                                                      addr_props, &l10n,
                                                      card, NULL);
        }

        /* Resource properties */
        else if (!strcmp(mykey, "cryptoKeys")) {
            struct resource_map map[] = {
                { NULL, VCARD_KEY_PROPERTY, 1 }
            };
            struct resource_rock rrock = { req, map, blobs, errors };

            record_is_dirty |= _jsmultiobject_to_card(&parser, jval,
                                                      mykey, "CryptoResource",
                                                      &_jsresource_to_vcard,
                                                      WANT_PROPID_FLAG,
                                                      resource_param_props,
                                                      &l10n, card, &rrock);
        }
        else if (!strcmp(mykey, "directories")) {
            struct resource_map map[] = {
                { "directory", VCARD_ORGDIRECTORY_PROPERTY, 0 },
                { "entry",     VCARD_SOURCE_PROPERTY,       0 },
                { NULL,        VCARD_NO_PROPERTY,           0 }
            };
            struct resource_rock rrock = { req, map, blobs, errors };

            record_is_dirty |= _jsmultiobject_to_card(&parser, jval,
                                                      mykey, "DirectoryResource",
                                                      &_jsresource_to_vcard,
                                                      WANT_PROPID_FLAG,
                                                      directories_param_props,
                                                      &l10n, card, &rrock);
        }
        else if (!strcmp(mykey, "links")) {
            struct resource_map map[] = {
                { "contact", VCARD_CONTACTURI_PROPERTY, 0 },
                { NULL,      VCARD_URL_PROPERTY,        0 }
            };
            struct resource_rock rrock = { req, map, blobs, errors };

            record_is_dirty |= _jsmultiobject_to_card(&parser, jval,
                                                      mykey, "LinkResource",
                                                      &_jsresource_to_vcard,
                                                      WANT_PROPID_FLAG,
                                                      resource_param_props,
                                                      &l10n, card, &rrock);
        }
        else if (!strcmp(mykey, "media")) {
            struct resource_map map[] = {
                { "photo", VCARD_PHOTO_PROPERTY, 1 },
                { "sound", VCARD_SOUND_PROPERTY, 1 },
                { "logo",  VCARD_LOGO_PROPERTY,  1 },
                { NULL,    VCARD_NO_PROPERTY,    0 }
            };
            struct resource_rock rrock = { req, map, blobs, errors };

            record_is_dirty |= _jsmultiobject_to_card(&parser, jval,
                                                      mykey, "MediaResource",
                                                      &_jsresource_to_vcard,
                                                      WANT_PROPID_FLAG,
                                                      resource_param_props,
                                                      &l10n, card, &rrock);
        }

        /* Multilingual properties */
        else if (!strcmp(mykey, "localizations")) {
            /* Handled elsewhere */
        }

        /* Additional properties */
        else if (!strcmp(mykey, "anniversaries")) {
            record_is_dirty |= _jsmultiobject_to_card(&parser, jval,
                                                      mykey, "Anniversary",
                                                      &_jsanniv_to_vcard,
                                                      WANT_PROPID_FLAG,
                                                      NULL, &l10n, card, NULL);
        }
        else if (!strcmp(mykey, "keywords")) {
            record_is_dirty |= _jsmultikey_to_card(&parser, jval, mykey, card,
                                                   VCARD_CATEGORIES_PROPERTY);
        }
        else if (!strcmp(mykey, "notes")) {
            struct param_prop_t note_props[] = {
                { "created", VCARD_CREATED_PARAMETER },
                { NULL,      0                       }
            };

            record_is_dirty |= _jsmultiobject_to_card(&parser, jval,
                                                      mykey, "Note",
                                                      &_jsnote_to_vcard,
                                                      WANT_PROPID_FLAG,
                                                      note_props, &l10n,
                                                      card, NULL);
        }
        else if (!strcmp(mykey, "personalInfo")) {
            struct param_prop_t personal_props[] = {
                { "label",  VCARD_X_PARAMETER     },
                { "level",  VCARD_LEVEL_PARAMETER },
                { "listAs", VCARD_INDEX_PARAMETER },
                { NULL,     0                     }
            };

            record_is_dirty |= _jsmultiobject_to_card(&parser, jval,
                                                      mykey, "PersonalInfo",
                                                      &_jspersonal_to_vcard,
                                                      WANT_PROPID_FLAG,
                                                      personal_props, &l10n,
                                                      card, NULL);
        }

        /* Unmapped vCard properties */
        else if (!strcmp(mykey, "vCardProps")) {
            record_is_dirty |= _vcardprops_to_card(&parser, jval, card);
        }

        /* Cyrus-specific properties */
        else if (!strcmp(mykey, "cyrusimap.org:importance")) {
            has_noncontent = 1;
            _jscard_set_importance(req, mboxname, mykey, jval, annotsp, errors);
        }

        else {
            int i;

            /* Known property with wrong case is invalid */
            for (i = 0; card_props[i].name; i++) {
                if (!strcasecmp(mykey, card_props[i].name)) {
                    jmap_parser_invalid(&parser, mykey);
                }
            }

            if (!card_props[i].name) {
                _jsunknown_to_vcard(&parser, mykey, jval, NULL, card);
            }
        }

        if (l10n.lang) {
            jmap_parser_pop(&parser);
            jmap_parser_pop(&parser);
        }
    }

    /* Report and free and invalid localization patches */
    jmap_parser_push(&parser, "localizations");
    hash_enumerate(&l10n_by_key, &_invalid_l10n_patches_by_key, &parser);
    free_hash_table(&l10n_by_key, NULL);
    jmap_parser_pop(&parser);

    parser.invalid = NULL;

    if (json_array_size(errors->invalid) || errors->blobNotFound) goto done;

    /* Set group label on grouped properties */
    hash_enumerate(&groups, &_set_groups, NULL);

    if (!vcardcomponent_get_first_property(card, VCARD_FN_PROPERTY)) {
        /* Need to construct an FN property */
        vcardproperty *prop =
            vcardproperty_vanew_fn("No Name",
                                   vcardparameter_new_derived(VCARD_DERIVED_TRUE),
                                   NULL);
        vcardcomponent_add_property(card, prop);
        record_is_dirty = 1;
    }

    if (!record_is_dirty && has_noncontent)
        r = HTTP_NO_CONTENT;  /* no content */

  done:
    free_hash_table(&groups, (void (*)(void *)) &ptrarray_free);
    free_hash_table(&l10n_by_key, NULL);
    buf_free(&buf);
    jmap_parser_fini(&parser);

    return r;
}

static int _card_set_create(jmap_req_t *req,
                            unsigned kind __attribute__((unused)),
                            json_t *jcard, struct mailbox **mailbox,
                            json_t *item, jmap_contact_errors_t *errors)
{
    json_t *invalid = errors->invalid;
    struct entryattlist *annots = NULL;
    vcardcomponent *card = NULL;
    char *uid = NULL;
    int r = 0;
    char *resourcename = NULL;
    struct buf buf = BUF_INITIALIZER;
    ptrarray_t blobs = PTRARRAY_INITIALIZER;
    property_blob_t *blob;
    char *mboxname = NULL;
    json_t *media = NULL, *keys = NULL;

    /* Validate uid */
    struct carddav_db *db = carddav_open_userid(req->accountid);
    if (!db) {
        xsyslog(LOG_ERR, "can not open carddav db", "accountid=<%s>",
                req->accountid);
        r = IMAP_INTERNAL;
    }
    if (!r) {
        struct carddav_data *mycdata = NULL;
        if ((uid = (char *) json_string_value(json_object_get(jcard, "uid")))) {
            /* Use custom vCard UID from request object */
            uid = xstrdup(uid);
            r = carddav_lookup_uid(db, uid, &mycdata);
            if (r == CYRUSDB_NOTFOUND) {
                r = 0;
            }
            else if (!r) {
                json_array_append_new(invalid, json_string("uid"));
            }
        }  else {
            /* Create a vCard UID */
            static int maxattempts = 3;
            int i;
            for (i = 0; i < maxattempts; i++) {
                free(uid);
                uid = xstrdup(makeuuid());
                r = carddav_lookup_uid(db, uid, &mycdata);
                if (r == CYRUSDB_NOTFOUND) {
                    json_object_set_new(item, "uid", json_string(uid));
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
    }
    carddav_close(db);
    if (r) goto done;

    /* Determine mailbox and resource name of card.
     * We attempt to reuse the UID as DAV resource name; but
     * only if it looks like a reasonable URL path segment. */
    const char *p;
    for (p = uid; *p; p++) {
        if ((*p >= '0' && *p <= '9') ||
            (*p >= 'a' && *p <= 'z') ||
            (*p >= 'A' && *p <= 'Z') ||
            (p > uid &&
                (*p == '@' || *p == '.' ||
                 *p == '_' || *p == '-'))) {
            continue;
        }
        break;
    }
    if (*p == '\0' && p - uid >= 16 && p - uid <= 200) {
        buf_setcstr(&buf, uid);
    } else {
        buf_setcstr(&buf, makeuuid());
    }
    buf_appendcstr(&buf, ".vcf");
    resourcename = buf_newcstring(&buf);

    const char *addressbookId = NULL;
    json_t *jval = json_object_get(jcard, "addressBookIds");
    if (jval) {
        if (json_object_size(jval) != 1) {
            // multiple address book ids are not supported
            json_array_append_new(invalid, json_string("addressBookIds"));
            goto done;
        }

        void *iter = json_object_iter(jval);
        if (json_object_iter_value(iter) == json_true()) {
            addressbookId = json_object_iter_key(iter);
        }
        if (addressbookId && *addressbookId == '#') {
            addressbookId = jmap_lookup_id(req, addressbookId + 1);
        }

        if (!addressbookId) {
            json_array_append_new(invalid, json_string("addressBookIds"));
            goto done;
        }
    }

    if (! addressbookId) {
        json_object_set_new(item, "addressBookIds", json_pack("{s:b}",
                                                              "Default", 1));
        addressbookId = "Default";
    }
    mboxname = mboxname_abook(req->accountid, addressbookId);
    json_object_del(jcard, "addressBookIds");
    addressbookId = NULL;

    int needrights = required_set_rights(jcard);

    /* Check permissions. */
    if (!jmap_hasrights(req, mboxname, needrights)) {
        json_array_append_new(invalid, json_string("addressBookIds"));
        goto done;
    }

    // Create vCard component
    card = vcardcomponent_vanew(VCARD_VCARD_COMPONENT,
                                vcardproperty_new_version(VCARD_VERSION_40),
                                NULL);

    // Add UID property
    vcardproperty *uidprop = vcardproperty_new_uid(uid);
    xmlURIPtr xuri = xmlParseURI(uid);
    if (!xuri || !xuri->scheme) {
        vcardproperty_set_value(uidprop, vcardvalue_new_text(uid));
    }
    xmlFreeURI(xuri);
    vcardcomponent_add_property(card, uidprop);

    /* we need to create and append a record */
    if (!*mailbox || strcmp(mailbox_name(*mailbox), mboxname)) {
        mailbox_close(mailbox);
        r = mailbox_open_iwl(mboxname, mailbox);
        if (r == IMAP_MAILBOX_NONEXISTENT) {
            json_array_append_new(invalid, json_string("addressbookIds"));
            r = 0;
            goto done;
        }
        else if (r) goto done;
    }

    /* Make copies of media/cryptoKeys properties
       in case we need to report updated blobIds */
    media = json_deep_copy(json_object_get(jcard, "media"));
    keys = json_deep_copy(json_object_get(jcard, "cryptoKeys"));

    if (!json_object_get(jcard, "created")) {
        /* set the CREATED time */
        char datestr[ISO8601_DATETIME_MAX+1] = "";
        time_t now = time(NULL);

        time_to_iso8601(now, datestr, sizeof(datestr), 1);

        json_object_set_new(jcard, "created", json_string(datestr));
        json_object_set_new(item, "created", json_string(datestr));
    }

    const char *name = NULL;
    jmap_readprop(json_object_get(jcard, "name"),
                  "full", 0, invalid, "s", &name);

    syslog(LOG_NOTICE, "jmap: create card %s/%s/%s (%s)",
           req->accountid, mboxname, uid, name ? name : "");

    r = _jscard_to_vcard(req, NULL, mboxname, card,
                         jcard, &annots, &blobs, errors);

    if (json_array_size(invalid) || errors->blobNotFound) {
        goto done;
    }

    r = carddav_store_x(*mailbox, card, resourcename, 0, &annots,
                        req->userid, req->authstate, ignorequota, /*oldsize*/ 0);
    if (r && r != HTTP_CREATED && r != HTTP_NO_CONTENT) {
        syslog(LOG_ERR, "carddav_store failed for user %s: %s",
               req->userid, error_message(r));
        goto done;
    }
    r = 0;

    json_object_set_new(item, "id", json_string(uid));

    struct index_record record;
    mailbox_find_index_record(*mailbox, (*mailbox)->i.last_uid, &record);

    while ((blob = ptrarray_pop(&blobs))) {
        json_t *obj;

        // blob->key is id of the subobj
        if (*blob->prop == 'K') {
            json_object_set(item, "cryptoKeys", keys);
            obj = json_object_get(keys, blob->key);
        }
        else {
            json_object_set(item, "media", media);
            obj = json_object_get(media, blob->key);
        }

        jmap_encode_rawdata_blobid('V', mailbox_uniqueid(*mailbox),
                                   record.uid, NULL, NULL,
                                   blob->prop, &blob->guid, &buf);

        json_object_set_new(obj, "blobId", json_string(buf_cstring(&buf)));
        if (blob->type) {
            json_object_set_new(obj, "mediaType", json_string(blob->type));
        }
        json_object_del(obj, "uri");

        property_blob_free(&blob);
    }

    if (jmap_is_using(req, JMAP_CONTACTS_EXTENSION)) {
        jmap_encode_rawdata_blobid('V', mailbox_uniqueid(*mailbox), record.uid,
                                   NULL, NULL, NULL, NULL, &buf);
        json_object_set_new(item, "cyrusimap.org:blobId",
                            json_string(buf_cstring(&buf)));

        json_object_set_new(item, "cyrusimap.org:size",
                            json_integer(record.size - record.header_size));

        char *xhref = jmap_xhref(mboxname, resourcename);
        json_object_set_new(item, "cyrusimap.org:href", json_string(xhref));
        free(xhref);
    }

done:
    vcardcomponent_free(card);
    free(mboxname);
    free(resourcename);
    freeentryatts(annots);
    free(uid);
    buf_free(&buf);
    while ((blob = ptrarray_pop(&blobs))) {
        property_blob_free(&blob);
    }
    ptrarray_fini(&blobs);
    json_decref(media);
    json_decref(keys);

    return r;
}

static int _card_set_update(jmap_req_t *req, unsigned kind,
                            const char *uid, json_t *jcard,
                            struct carddav_db *db, struct mailbox **mailbox,
                            json_t **item, jmap_contact_errors_t *errors)
{
    json_t *invalid = errors->invalid;
    struct mailbox *newmailbox = NULL;
    struct carddav_data *cdata = NULL, mycdata;
    struct buf buf = BUF_INITIALIZER;
    mbentry_t *mbentry = NULL;
    uint32_t olduid;
    char *resource = NULL;
    int do_move = 0;
    json_t *jupdated = NULL;
    vcardcomponent *vcard = NULL;
    struct entryattlist *annots = NULL;
    ptrarray_t blobs = PTRARRAY_INITIALIZER;
    property_blob_t *blob;
    json_t *media = NULL, *keys = NULL;
    int r = 0;

    /* is it a valid contact? */
    r = carddav_lookup_uid(db, uid, &cdata);
    if (r || !cdata || !cdata->dav.imap_uid) {
        r = HTTP_NOT_FOUND;
        goto done;
    }

    /* make a working copy of cdata -
     * conversion of vCard to JSContact might do group member lookups
     * and thus overwrite our cdata
     */
    cdata = memcpy(&mycdata, cdata, sizeof(mycdata));
    cdata->vcard_uid = uid;
    cdata->dav.resource = resource = xstrdup(cdata->dav.resource);

    json_t *jkind = json_object_get(jcard, "kind");
    if (jkind) {
        kind = !strcmpsafe("group", json_string_value(jkind)) ?
            CARDDAV_KIND_GROUP : CARDDAV_KIND_CONTACT;

        if (cdata->kind != kind) {
            json_array_append_new(invalid, json_string("kind"));
            goto done;
        }
    }

    mbentry = jmap_mbentry_from_dav(req, &cdata->dav);

    const char *addressbookId = NULL;
    json_t *jval = json_object_get(jcard, "addressBookIds");
    if (jval) {
        if (json_object_size(jval) != 1) {
            // multiple address book ids are not supported
            json_array_append_new(invalid, json_string("addressBookIds"));
            goto done;
        }

        void *iter = json_object_iter(jval);
        if (json_object_iter_value(iter) == json_true()) {
            addressbookId = json_object_iter_key(iter);
        }
        if (addressbookId && *addressbookId == '#') {
            addressbookId = jmap_lookup_id(req, addressbookId + 1);
        }

        if (!addressbookId) {
            json_array_append_new(invalid, json_string("addressBookIds"));
            goto done;
        }
    }

    if (addressbookId) {
        char *mboxname = mboxname_abook(req->accountid, addressbookId);

        if (mbentry && strcmp(mboxname, mbentry->name)) {
            /* move */
            if (!jmap_hasrights(req, mboxname, JACL_ADDITEMS)) {
                json_array_append_new(invalid, json_string("addressBookIds"));
                r = HTTP_FORBIDDEN;
            }
            else if ((r = mailbox_open_iwl(mboxname, &newmailbox))) {
                syslog(LOG_ERR, "IOERROR: failed to open %s", mboxname);
            }
            else {
                do_move = 1;
            }
        }
        json_object_del(jcard, "addressBookIds");
        free(mboxname);

        if (r) goto done;
    }

    int needrights = do_move ? JACL_UPDATEITEMS : required_set_rights(jcard);

    if (!mbentry || !jmap_hasrights_mbentry(req, mbentry, needrights)) {
        int rights = mbentry ? jmap_myrights_mbentry(req, mbentry) : 0;
        r = (rights & JACL_READITEMS) ? HTTP_NOT_ALLOWED : HTTP_NOT_FOUND;
        goto done;
    }

    if (!*mailbox || strcmp(mailbox_name(*mailbox), mbentry->name)) {
        mailbox_close(mailbox);
        r = mailbox_open_iwl(mbentry->name, mailbox);
    }
    if (r) {
        syslog(LOG_ERR, "IOERROR: failed to open %s",
               mbentry->name);
        goto done;
    }

    struct index_record record;

    r = mailbox_find_index_record(*mailbox, cdata->dav.imap_uid, &record);
    if (r) goto done;

    olduid = cdata->dav.imap_uid;

    annots = mailbox_extract_annots(*mailbox, &record);

    if (!newmailbox) {
        size_t num_props = json_object_size(jcard);
        const char *key = "cyrusimap.org:importance";
        json_t *jval;

        if (num_props &&
            (jval = json_object_get(jcard, key))) {
            _jscard_set_importance(req, mailbox_name(*mailbox),
                                   key, jval, &annots, errors);
            num_props--;
        }

        if (!num_props) {
            /* just bump the modseq
               if in the same mailbox and no data change */
            annotate_state_t *state = NULL;

            syslog(LOG_NOTICE, "jmap: touch contact %s/%s",
                   req->accountid, resource);
            r = mailbox_get_annotate_state(*mailbox, record.uid, &state);
            annotate_state_set_auth(state, 0,
                                    req->userid, req->authstate);
            if (!r) r = annotate_state_store(state, annots);
            if (!r) r = mailbox_rewrite_index_record(*mailbox, &record);
            if (!r) {
                *item = json_null();

                /* flush cached JSContactCard for this user */
                carddav_write_jscardcache(db, cdata->dav.rowid,
                                          req->userid, 0, NULL);
            }
            goto done;
        }
    }

    /* Load message containing the resource and parse vcard data */
    vcard = record_to_vcard_x(*mailbox, &record);
    if (!vcard) {
        syslog(LOG_ERR, "record_to_vcard failed for record %u:%s",
               cdata->dav.imap_uid, mailbox_name(*mailbox));
        r = HTTP_UNPROCESSABLE;
        goto done;
    }

    /* Convert the vCard to a JSContact Card. */
    json_t *old_obj = jmap_card_from_vcard(req->userid, vcard,
                                           db, *mailbox, &record,
                                           IGNORE_VCARD_VERSION | IGNORE_DERIVED_PROPS);
    vcardcomponent_free(vcard);

    /* Remove old "updated" */
    json_object_del(old_obj, "updated");

    /* Apply the patch as provided */
    json_t *new_obj = jmap_patchobject_apply(old_obj, jcard, invalid, 0);

    json_decref(old_obj);
    if (!new_obj) {
        r = HTTP_BAD_REQUEST;
        goto done;
    }

    /* Make copies of patched media/cryptoKeys properties
       in case we need to report updated blobIds */
    media = json_deep_copy(json_object_get(new_obj, "media"));
    keys = json_deep_copy(json_object_get(new_obj, "cryptoKeys"));

    vcard = vcardcomponent_vanew(VCARD_VCARD_COMPONENT,
                                 vcardproperty_new_version(VCARD_VERSION_40),
                                 vcardproperty_new_uid(uid),
                                 NULL);

    *item = json_object();

    if (!json_object_get(new_obj, "updated")) {
        /* set the REVision time */
        char datestr[ISO8601_DATETIME_MAX+1] = "";
        time_t now = time(NULL);

        time_to_iso8601(now, datestr, sizeof(datestr), 1);

        json_object_set_new(new_obj, "updated", json_string(datestr));
        json_object_set_new(*item, "updated", json_string(datestr));
    }

    r = _jscard_to_vcard(req, cdata, mailbox_name(*mailbox), vcard,
                         new_obj, &annots, &blobs, errors);
    json_decref(new_obj);

    if (!json_array_size(invalid) && !errors->blobNotFound) {
        struct mailbox *this_mailbox = newmailbox ? newmailbox : *mailbox;

        syslog(LOG_NOTICE, "jmap: update %s %s/%s",
               kind == CARDDAV_KIND_GROUP ? "group" : "contact",
               req->accountid, resource);
        r = carddav_store_x(this_mailbox, vcard, resource,
                            record.createdmodseq, &annots, req->userid,
                            req->authstate, ignorequota,
                            (record.size - record.header_size));
        if (!r) {
            struct index_record record;

            mailbox_find_index_record(this_mailbox,
                                      this_mailbox->i.last_uid, &record);

            jmap_encode_rawdata_blobid('V', mailbox_uniqueid(this_mailbox),
                                       record.uid, NULL, NULL, NULL, NULL, &buf);
            json_object_set_new(*item, "cyrusimap.org:blobId",
                                json_string(buf_cstring(&buf)));

            json_object_set_new(*item, "cyrusimap.org:size",
                                json_integer(record.size - record.header_size));

            while ((blob = ptrarray_pop(&blobs))) {
                json_t *obj;

                // blob->key is id of the subobj
                if (*blob->prop == 'K') {
                    json_object_set(*item, "cryptoKeys", keys);
                    obj = json_object_get(keys, blob->key);
                }
                else {
                    json_object_set(*item, "media", media);
                    obj = json_object_get(media, blob->key);
                }

                jmap_encode_rawdata_blobid('V',
                                           mailbox_uniqueid(this_mailbox),
                                           record.uid, NULL, NULL,
                                           blob->prop, &blob->guid, &buf);

                json_object_set_new(obj, "blobId",
                                    json_string(buf_cstring(&buf)));
                if (blob->type) {
                    json_object_set_new(obj, "mediaType",
                                        json_string(blob->type));
                }
                json_object_del(obj, "uri");

                property_blob_free(&blob);
            }

            r = carddav_remove(*mailbox, olduid,
                               /*isreplace*/!newmailbox, req->userid);
        }
    }

  done:
    mboxlist_entry_free(&mbentry);
    mailbox_close(&newmailbox);
    freeentryatts(annots);
    vcardcomponent_free(vcard);
    free(resource);
    json_decref(jupdated);
    buf_free(&buf);
    while ((blob = ptrarray_pop(&blobs))) {
        property_blob_free(&blob);
    }
    ptrarray_fini(&blobs);
    json_decref(media);
    json_decref(keys);

    return r;
}

static json_t *_card_from_record(jmap_req_t *req,
                                 struct carddav_db *db,
                                 struct mailbox *mailbox,
                                 struct index_record *record)
{
    vcardcomponent *vcard = record_to_vcard_x(mailbox, record);

    if (!vcard) return NULL;

    /* Patch JMAP event */
    json_t *jcard = jmap_card_from_vcard(req->userid, vcard, db, mailbox, record,
                                         IGNORE_VCARD_VERSION);
    vcardcomponent_free(vcard);

    if (jcard && strstr(req->method, "/copy")) {
        json_t *media = json_object_get(jcard, "media");
        if (media) {
            /* _blob_to_card() needs to know in which account to find blobs */
            json_object_set(media, "accountId",
                            json_object_get(req->args, "fromAccountId"));
        }

        // immutable and WILL change
        json_object_del(jcard, "cyrusimap.org:href");
    }

    return jcard;
}

static int jmap_card_get(struct jmap_req *req)
{
    return _contacts_get(req, &getcards_cb, CARDDAV_KIND_ANY, card_props);
}

static int jmap_card_changes(struct jmap_req *req)
{
    return _contacts_changes(req, CARDDAV_KIND_ANY);
}

static int jmap_card_query(struct jmap_req *req)
{
    return _contactsquery(req, CARDDAV_KIND_ANY,
                          &card_filter_parse, &card_filter_free,
                          &card_filter_validate,
                          &card_comparator_validate, &_cardquery_cb,
                          &cardquery_buildsort, &cardquery_cmp);
}

static int jmap_card_querychanges(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_querychanges query;

    json_t *err = NULL;
    jmap_querychanges_parse(req, &parser, NULL, NULL,
                            &card_filter_validate, NULL,
                            &card_comparator_validate, NULL,
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

static int jmap_card_set(struct jmap_req *req)
{
    _contacts_set(req, CARDDAV_KIND_ANY, card_props,
                  &_card_set_create, &_card_set_update);

    return 0;
}

static int jmap_card_copy(struct jmap_req *req)
{
    return _contacts_copy(req, &_card_from_record, &_card_set_create);
}

struct card_parseargs {
    hash_table *props;
    int disable_uri_as_blobid;
};

static int _card_parseargs_parse(jmap_req_t *req __attribute__((unused)),
                                 struct jmap_parser *parser,
                                 const char *key,
                                 json_t *arg,
                                 void *rock)
{
    struct card_parseargs *args = rock;
    int r = 0;

    if (!strcmp(key, "properties") && json_is_array(arg)) {
        size_t i;
        json_t *val;

        args->props = xzmalloc(sizeof(hash_table));
        construct_hash_table(args->props, json_array_size(arg) + 1, 0);
        json_array_foreach(arg, i, val) {
            const char *s = json_string_value(val);
            if (!s) {
                jmap_parser_push_index(parser, "properties", i, s);
                jmap_parser_invalid(parser, NULL);
                jmap_parser_pop(parser);
                continue;
            }
            hash_insert(s, (void*)1, args->props);
        }
        r = 1;
    }
    else if (!strcmp(key, "disableUriAsBlobId") && json_is_boolean(arg)) {
        args->disable_uri_as_blobid = json_boolean_value(arg);
        r = 1;
    }

    return r;
}

static int jmap_card_parse(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_parse parse;
    struct card_parseargs args = {0};
    struct carddav_db *db = NULL;
    json_t *err = NULL;

    /* Parse request */
    jmap_parse_parse(req, &parser, &_card_parseargs_parse, &args, &parse, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    db = carddav_open_userid(req->accountid);
    if (!db) {
        syslog(LOG_ERR,
               "carddav_open_mailbox failed for user %s", req->accountid);
        goto done;
    }

    /* Process request */
    jmap_getblob_context_t blob_ctx;
    jmap_getblob_ctx_init(&blob_ctx, NULL, NULL, "text/vcard", 1);

    json_t *jval;
    size_t i;
    json_array_foreach(parse.blob_ids, i, jval) {
        const char *blobid = json_string_value(jval);
        vcardcomponent *vcard = NULL;
        struct mailbox *mailbox = NULL;
        struct index_record record;
        json_t *jcard = NULL;
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

        blob_ctx.mboxp = &mailbox;
        blob_ctx.recordp = &record;
        buf_reset(&blob_ctx.blob);
        r = jmap_getblob(req, &blob_ctx);
        if (r) {
            json_array_append_new(parse.not_found, json_string(blobid));
            continue;
        }

        vcard = vcard_parse_buf_x(&blob_ctx.blob);
        if (vcard) {
            int from_vcard_flags = IGNORE_DERIVED_PROPS;
            if (args.disable_uri_as_blobid)
                from_vcard_flags |= DISABLE_URI_AS_BLOBID;

            jcard = jmap_card_from_vcard(req->userid, vcard, db,
                                         mailbox, &record, from_vcard_flags);
            vcardcomponent_free(vcard);
        }

        if (jcard) {
            jmap_filterprops(jcard, args.props);
            json_object_set_new(parse.parsed, blobid, jcard);
        }
        else {
            json_array_append_new(parse.not_parsable, json_string(blobid));
        }

        mailbox_close(&mailbox);
    }

    jmap_getblob_ctx_fini(&blob_ctx);

    /* Build response */
    jmap_ok(req, jmap_parse_reply(&parse));

done:
    jmap_parser_fini(&parser);
    jmap_parse_fini(&parse);
    if (db) carddav_close(db);
    free_hash_table(args.props, NULL);
    free(args.props);
    return 0;
}

static int jmap_contact_getblob(jmap_req_t *req, jmap_getblob_context_t *ctx)
{
    struct mailbox *mailbox = NULL;
    vcardcomponent *vcard = NULL;
    char *mboxid = NULL, *propname = NULL, *mediatype = NULL;
    uint32_t uid;
    struct message_guid guid = MESSAGE_GUID_INITIALIZER;
    int res = HTTP_OK;
    mbentry_t *freeme = NULL;
    int r;

    if (ctx->blobid[0] != 'V') return 0;

    if (!jmap_decode_rawdata_blobid(ctx->blobid, &mboxid, &uid,
                                    NULL, NULL, &propname, &guid)) {
        res = HTTP_BAD_REQUEST;
        goto done;
    }

    if (!propname && ctx->accept_mime) {
        /* Make sure client can handle blob type. */
        if (strcmp(ctx->accept_mime, "application/octet-stream") &&
            strcmp(ctx->accept_mime, "text/vcard")) {
            res = HTTP_NOT_ACCEPTABLE;
            goto done;
        }
        buf_setcstr(&ctx->content_type, ctx->accept_mime);
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

    /* Fetch index record */
    struct index_record record;
    r = mailbox_find_index_record(mailbox, uid, &record);
    if (r) {
        if (r == IMAP_NOTFOUND) {
            res = HTTP_NOT_FOUND;
        }
        else {
            ctx->errstr = "failed to load record";
            res = HTTP_SERVER_ERROR;
        }
        goto done;
    }

    if (propname) {
        /* Fetching a particular property as a blob */

        /* Load vCard data */
        vcard = record_to_vcard_x(mailbox, &record);
        if (!vcard) {
            ctx->errstr = "failed to parse vCard";
            res = HTTP_SERVER_ERROR;
            goto done;
        }

        vcardproperty_kind kind = vcardproperty_string_to_kind(propname);
        vcardproperty *prop = vcardcomponent_get_first_property(vcard, kind);
        struct message_guid prop_guid = MESSAGE_GUID_INITIALIZER;

        if (!prop ||
            !vcard_prop_decode_value_x(prop, &ctx->blob, &mediatype, &prop_guid) ||
            message_guid_cmp(&guid, &prop_guid)) {
            res = HTTP_NOT_FOUND;
            goto done;
        }
        else if (ctx->accept_mime) {
            if (strcmp(ctx->accept_mime, "application/octet-stream") &&
                strcmp(ctx->accept_mime, mediatype)) {
                res = HTTP_NOT_ACCEPTABLE;
                goto done;
            }
            buf_setcstr(&ctx->content_type, ctx->accept_mime);
        }
        else if (mediatype) {
            buf_setcstr(&ctx->content_type, mediatype);
        }
        else buf_reset(&ctx->content_type);

        buf_setcstr(&ctx->encoding, "BINARY");
    }
    else {
        /* Load message containing the resource */
        struct buf buf = BUF_INITIALIZER;

        if (mailbox_map_record(mailbox, &record, &buf)) {
            ctx->errstr = "failed to load vCard";
            res = HTTP_SERVER_ERROR;
            goto done;
        }

        if (!ctx->accept_mime || !strcmp(ctx->accept_mime, "text/vcard")) {
            struct carddav_db *db = carddav_open_mailbox(mailbox);
            struct carddav_data *cdata = NULL;

            buf_setcstr(&ctx->content_type, "text/vcard");

            if (db &&
                !carddav_lookup_imapuid(db, mbentry, uid, &cdata, 0) && cdata) {
                buf_printf(&ctx->content_type, "; version=%u.0", cdata->version);
            }

            carddav_close(db);
        }

        buf_setcstr(&ctx->encoding, "8BIT");
        buf_setmap(&ctx->blob, buf_base(&buf) + record.header_size,
                   record.size - record.header_size);
        buf_free(&buf);
    }

done:
    if (res != HTTP_OK && !ctx->errstr) {
        const char *desc = NULL;
        switch (res) {
            case HTTP_BAD_REQUEST:
                desc = "invalid contact blobid";
                break;
            case HTTP_NOT_FOUND:
                desc = "failed to find blob by contact blobid";
                break;
            default:
                desc = error_message(res);
        }
        ctx->errstr = desc;
    }
    if (vcard) vcardcomponent_free(vcard);
    mailbox_close(&mailbox);
    mboxlist_entry_free(&freeme);
    free(mboxid);
    free(propname);
    free(mediatype);
    return res;
}

#else /* !HAVE_LIBICALVCARD */

static int jmap_contact_getblob(jmap_req_t *req, jmap_getblob_context_t *ctx)
{
    struct mailbox *mailbox = NULL;
    struct vparse_card *vcard = NULL;
    char *mboxid = NULL, *prop = NULL, *mediatype = NULL;
    uint32_t uid;
    struct message_guid guid = MESSAGE_GUID_INITIALIZER;
    int res = HTTP_OK;
    mbentry_t *freeme = NULL;
    int r;

    if (ctx->blobid[0] != 'V') return 0;

    if (!jmap_decode_rawdata_blobid(ctx->blobid, &mboxid, &uid,
                                    NULL, NULL, &prop, &guid)) {
        res = HTTP_BAD_REQUEST;
        goto done;
    }

    if (!prop && ctx->accept_mime) {
        /* Make sure client can handle blob type. */
        if (strcmp(ctx->accept_mime, "application/octet-stream") &&
            strcmp(ctx->accept_mime, "text/vcard")) {
            res = HTTP_NOT_ACCEPTABLE;
            goto done;
        }
        buf_setcstr(&ctx->content_type, ctx->accept_mime);
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

    /* Load vCard data */
    struct index_record record;
    r = mailbox_find_index_record(mailbox, uid, &record);
    if (r == IMAP_NOTFOUND) {
        res = HTTP_NOT_FOUND;
        goto done;
    }

    if (!r) {
        vcard = record_to_vcard(mailbox, &record);
    }
    if (!vcard) {
        ctx->errstr = "failed to load record";
        res = HTTP_SERVER_ERROR;
        goto done;
    }

    if (prop) {
        /* Fetching a particular property as a blob */
        struct vparse_entry *entry = vparse_get_entry(vcard->objects, NULL, prop);
        struct message_guid prop_guid = MESSAGE_GUID_INITIALIZER;

        if (!entry ||
            !vcard_prop_decode_value(entry, &ctx->blob, &mediatype, &prop_guid) ||
            message_guid_cmp(&guid, &prop_guid)) {
            res = HTTP_NOT_FOUND;
            goto done;
        }
        else if (ctx->accept_mime) {
            if (strcmp(ctx->accept_mime, "application/octet-stream") &&
                strcmp(ctx->accept_mime, mediatype)) {
                res = HTTP_NOT_ACCEPTABLE;
                goto done;
            }
            buf_setcstr(&ctx->content_type, ctx->accept_mime);
        }
        else if (mediatype) {
            buf_setcstr(&ctx->content_type, mediatype);
        }
        else buf_reset(&ctx->content_type);

        buf_setcstr(&ctx->encoding, "BINARY");
    }
    else {
        if (!ctx->accept_mime || !strcmp(ctx->accept_mime, "text/vcard")) {
            struct vparse_entry *entry =
                vparse_get_entry(vcard->objects, NULL, "VERSION");

            buf_setcstr(&ctx->content_type, "text/vcard");
            if (entry)
                buf_printf(&ctx->content_type, "; version=%s", entry->v.value);
        }

        buf_setcstr(&ctx->encoding, "8BIT");
        vparse_tobuf(vcard, &ctx->blob);
    }

done:
    if (res != HTTP_OK && !ctx->errstr) {
        const char *desc = NULL;
        switch (res) {
            case HTTP_BAD_REQUEST:
                desc = "invalid contact blobid";
                break;
            case HTTP_NOT_FOUND:
                desc = "failed to find blob by contact blobid";
                break;
            default:
                desc = error_message(res);
        }
        ctx->errstr = desc;
    }
    if (vcard) vparse_free_card(vcard);
    mailbox_close(&mailbox);
    mboxlist_entry_free(&freeme);
    free(mboxid);
    free(prop);
    free(mediatype);
    return res;
}

#endif /* HAVE_LIBICALVCARD */
