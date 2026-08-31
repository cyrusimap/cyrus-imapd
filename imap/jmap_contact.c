/* jmap_contact.c - Routines for handling JMAP contact messages */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>

#include <cyrus/assert.h>
#include <cyrus/hash.h>
#include <cyrus/xmalloc.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <string.h>
#include <syslog.h>
#include <errno.h>

#include "annotate.h"
#include "carddav_db.h"
#include "cyr_qsort_r.h"
#include "global.h"
#include "http_carddav.h"
#include "http_dav.h"
#include "http_dav_sharing.h"
#include "http_jmap.h"
#include "jscontact.h"
#include "json_support.h"
#include "mailbox.h"
#include "mboxname.h"
#include "stristr.h"
#include "times.h"
#include "user.h"
#include "util.h"
#include "vcard_support.h"
#include "xapian_wrap.h"
#include "xstrlcpy.h"

/* generated headers are not necessarily in current directory */
#include "imap/http_err.h"
#include "imap/imap_err.h"
#include "imap/jmap_props/addressbook.h"
#include "imap/jmap_props/contact_card.h"

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

typedef struct {
    json_t *invalid;
    json_t *blobNotFound;
} jmap_contact_errors_t;

/** Defines an addresbook membership change for a Card */
enum addrbook_change {
    ADDRBOOK_CHANGE_NONE = 0,  /* does not change addressbook membership */
    ADDRBOOK_CHANGE_CREATE,    /* creates a Card in the addressbook */
    ADDRBOOK_CHANGE_MOVE,      /* moves a Card out of its addressbook */
};

static int required_set_rights(json_t *props, enum addrbook_change change);

static int jmap_contact_getblob(jmap_req_t *req, jmap_getblob_context_t *ctx);

#define JMAPCACHE_CARDVERSION 2

// clang-format off
static jmap_method_t jmap_contact_methods_standard[] = {
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
        JMAP_NEED_CSTATE | JMAP_READ_WRITE
    },
    { NULL, NULL, NULL, 0}
};
// clang-format on

// clang-format off
static jmap_method_t jmap_contact_methods_nonstandard[] = {
    {
        "ContactCard/parse",
        JMAP_CONTACTS_EXTENSION,
        &jmap_card_parse,
        JMAP_NEED_CSTATE
    },
    { NULL, NULL, NULL, 0}
};
// clang-format on

static char *_prodid = NULL;

HIDDEN void jmap_contact_init(jmap_settings_t *settings)
{
    jmap_add_methods(jmap_contact_methods_standard, settings);

    json_object_set_new(settings->server_capabilities,
            JMAP_URN_CONTACTS, json_object());

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
                                      struct auth_state *authstate,
                                      const char *authuserid,
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

    int rights = httpd_myrights(authstate, mbentry);
    int is_main_account = !strcmpsafe(authuserid, accountid);

    json_object_set_new(account_capabilities, JMAP_URN_CONTACTS,
                        json_pack("{s:i s:b}",
                                  "maxAddressBooksPerCard", 1,
                                  "mayCreateAddressBook",
                                  is_main_account || (rights & JACL_CREATECHILD)));

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
    struct buf *cid;        // buffer for constructing ContactCard ids
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


/*****************************************************************************
 * JMAP Contacts API
 ****************************************************************************/

struct cards_rock {
    struct carddav_db *db;
    struct jmap_req *req;
    struct jmap_get *get;
    struct mailbox *mailbox;
    mbentry_t *mbentry;
    hashu64_table jmapcache;
    struct buf cid;          // buffer for constructing ContactCard ids
    int rows;
};

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

static int getcards_cb(void *rock, struct carddav_data *cdata);

static int jmap_card_get(struct jmap_req *req)
{
    if (!has_addressbooks(req)) {
        jmap_error(req, json_pack("{s:s}", "type", "accountNoAddressbooks"));
        return 0;
    }

    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_get get = JMAP_GET_INITIALIZER;
    json_t *err = NULL;
    struct carddav_db *db = NULL;
    mbentry_t *mbentry = NULL;
    int r = 0;

    /* Build callback data */
    struct cards_rock rock = {
        .req = req,
        .get = &get,
        .jmapcache = HASHU64_TABLE_INITIALIZER,
        .cid = BUF_INITIALIZER
    };

    construct_hashu64_table(&rock.jmapcache, 512, 0);

    /* Parse request */
    jmap_get_parse(req, &parser, &card_props, /* allow_null_ids */ 1,
                   NULL, NULL, &get, &err);
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

    if (JNOTNULL(get.ids)) {
        size_t i;
        json_t *jval;
        json_array_foreach(get.ids, i, jval) {
            rock.rows = 0;
            const char *id = json_string_value(jval);

            if (USER_COMPACT_EMAILIDS(req->cstate)) {
                if (id[0] == JMAP_CONTACTID_PREFIX &&
                    strlen(id) < JMAP_CONTACTID_SIZE) {
                    struct carddav_data *cdata = NULL;

                    r = carddav_lookup_jmapid(db, id+1, &cdata);  // strip prefix
                    if (!r && cdata) {
                        r = getcards_cb(&rock, cdata);
                    }
                }
            }
            else {
                r = carddav_get_cards(db, mbentry, req->userid,
                                      id, CARDDAV_KIND_ANY, &getcards_cb, &rock);
            }
            if (r || !rock.rows) {
                json_array_append(get.not_found, jval);
            }
            r = 0; // we don't ever fail the whole request from this
        }
    }
    else {
        rock.rows = 0;
        r = carddav_get_cards(db, mbentry, req->userid,
                              NULL, CARDDAV_KIND_ANY, &getcards_cb, &rock);
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
    buf_free(&rock.cid);
    free_hashu64_table(&rock.jmapcache, free);
    if (db) carddav_close(db);
    return r;
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
    const char *id = cdata->vcard_uid;
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

    if (urock->cid) {
        jmap_set_contactid(urock->req->cstate, cdata, urock->cid);
        id = buf_cstring(urock->cid);
    }

    /* Report item as updated or destroyed. */
    if (dav.alive) {
        if (dav.createdmodseq <= urock->changes->since_modseq)
            json_array_append_new(urock->changes->updated, json_string(id));
        else
            json_array_append_new(urock->changes->created, json_string(id));
    } else {
        if (dav.createdmodseq <= urock->changes->since_modseq)
            json_array_append_new(urock->changes->destroyed, json_string(id));
    }

    /* Fetch record to determine modseq. */
    if (dav.modseq > urock->highestmodseq) {
        urock->highestmodseq = dav.modseq;
    }

    return 0;
}

static int jmap_card_changes(struct jmap_req *req)
{
    if (!has_addressbooks(req)) {
        jmap_error(req, json_pack("{s:s}", "type", "accountNoAddressbooks"));
        return 0;
    }

    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_changes changes = JMAP_CHANGES_INITIALIZER;
    json_t *err = NULL;
    struct carddav_db *db = NULL;
    int r = 0;

    /* Parse request */
    jmap_changes_parse(req, &parser, req->counters.carddavdeletedmodseq,
                       NULL, NULL, &changes, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    /* Lookup updates. */
    db = carddav_open_userid(req->accountid);
    if (!db) {
        syslog(LOG_ERR,
               "carddav_open_userid failed for user %s", req->accountid);
        r = IMAP_INTERNAL;
        goto done;
    }
    struct buf cid = BUF_INITIALIZER;
    struct changes_rock rock = { req, &changes, 0 /*seen_records*/,
                                 0 /*highestmodseq*/, &cid };
    r = carddav_get_updates(db, changes.since_modseq, NULL, CARDDAV_KIND_ANY,
                            -1 /*max_records*/, &getchanges_cb, &rock);
    buf_free(&cid);
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

    return 0;
}

typedef struct {
    char *key;
    char *prop;
    char *type;
    size_t size;
    struct message_guid guid;
} property_blob_t;

static property_blob_t *property_blob_new(const char *key, const char *prop,
                                          const char *type,
                                          const struct buf *data)
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

/* cyrusimap.org:importance is a JMAP-only property backed by an annotation,
 * so it is stored and read here rather than by the JSContact conversion. */
static void _card_store_importance_annot(jmap_req_t *req, const char *mboxname,
                                         const char *key, json_t *arg,
                                         struct entryattlist **annotsp,
                                         json_t *invalid)
{
    if (!json_is_number(arg)) {
        json_array_append_new(invalid, json_string(key));
        return;
    }

    const char *ns = DAV_ANNOT_NS "<" XML_NS_CYRUS ">importance";
    const char *attrib = mboxname_userownsmailbox(req->userid, mboxname) ?
        "value.shared" : "value.priv";
    struct buf buf = BUF_INITIALIZER;

    buf_printf(&buf, "%.17g", json_number_value(arg));

    setentryatt(annotsp, ns, attrib, &buf);
    buf_free(&buf);
}

/* Convert a vCard record to a Card, including the Cyrus-specific properties
   that are not part of JSContact */
static json_t *_card_from_vcard(jmap_req_t *req, jscontact_ctx_t *ctx,
                                vcardcomponent *vcard)
{
    json_t *jcard = jscontact_from_vcard(ctx, vcard);

    if (jcard && ctx->record &&
        ctx->version != VCARD_VERSION_NONE && ctx->version != VCARD_VERSION_X) {
        const char *annot = DAV_ANNOT_NS "<" XML_NS_CYRUS ">importance";
        struct buf buf = BUF_INITIALIZER;

        annotatemore_msg_lookupmask(ctx->mailbox, ctx->record->uid, annot,
                                    req->userid, &buf);
        double val = 0;
        if (buf_len(&buf)) val = strtod(buf_cstring(&buf), NULL);

        json_object_set_new(jcard, "cyrusimap.org:importance", json_real(val));
        buf_free(&buf);
    }

    return jcard;
}

/* Callback data for the JSContact to vCard blob callbacks */
struct card_blob_rock {
    jmap_req_t *req;
    ptrarray_t *blobs;
    jmap_contact_errors_t *errors;
};

static int _card_getblob(void *rock, const char *accountid, const char *blobid,
                         const char *mediatype, struct buf *data,
                         struct buf *type)
{
    struct card_blob_rock *brock = rock;
    jmap_getblob_context_t ctx = { 0 };
    const char *id = blobid;

    if (id && *id == '#') id = jmap_lookup_id(brock->req, id + 1);

    jmap_getblob_ctx_init(&ctx, accountid, id, mediatype, 1);

    int r = jmap_getblob(brock->req, &ctx);
    if (!r) {
        buf_move(data, &ctx.blob);
        buf_move(type, &ctx.content_type);
    }
    else if (r != HTTP_NOT_ACCEPTABLE) {
        /* Not found, or system error */
        if (!brock->errors->blobNotFound)
            brock->errors->blobNotFound = json_array();
        json_array_append_new(brock->errors->blobNotFound,
                              json_string(blobid));
    }

    jmap_getblob_ctx_fini(&ctx);

    return r;
}

static void _card_addblob(void *rock, const char *id, const char *propname,
                          const char *mediatype, const struct buf *data)
{
    struct card_blob_rock *brock = rock;

    ptrarray_append(brock->blobs,
                    property_blob_new(id, propname, mediatype, data));
}

static void reject_or_remove_convprops_internal(struct jmap_parser *parser,
                                                struct buf *buf,
                                                json_t *jpatch,
                                                json_t *invalid,
                                                bool remove)
{
    if (json_is_object(jpatch)) {
        const char *key;
        json_t *jval;
        void *tmp;
        json_object_foreach_safe(jpatch, tmp, key, jval)
        {
            if (strchr(key, '/'))
                jmap_parser_push_path(parser, key);
            else
                jmap_parser_push(parser, key);

            const char *subpath = key;
            bool found_convprop = false;
            while (subpath) {
                if (!strncasecmp(subpath, "vCard", 5)) {
                    found_convprop = true;
                    if (remove) {
                        json_object_del(jpatch, key);
                    }
                    else {
                        json_array_append_new(
                            invalid, json_string(jmap_parser_path(parser)));
                    }
                    break;
                }
                else {
                    subpath = strchr(subpath, '/');
                    if (subpath) subpath++;
                }
            }

            if (!found_convprop) {
                reject_or_remove_convprops_internal(parser, buf, jval,
                                                    invalid, remove);
            }

            jmap_parser_pop(parser);
        }
    }
    else if (json_is_array(jpatch)) {
        size_t i;
        json_t *jval;
        json_array_foreach(jpatch, i, jval) {
            buf_reset(buf);
            buf_printf(buf, "%zu", i);
            jmap_parser_push(parser, buf_cstring(buf));
            reject_or_remove_convprops_internal(parser, buf, jval,
                                                invalid, remove);
            jmap_parser_pop(parser);
        }
    }
}

/* Handle any JSON pointer containing a vCard-conversion property
 * in the PatchObject "jpatch". If "remove" is false, report the
 * full path of each such patch entry in "invalid". If "remove" is
 * true, silently delete the entry from "jpatch" instead.
 *
 * Any property starting with "vCard" is assumed to be
 * a conversion property, e.g. such as vCardProps, vCardName
 * et al defined in RFC 9555.
 */
static void reject_or_remove_convprops(json_t *jpatch, json_t *invalid,
                                       bool remove) {
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct buf buf = BUF_INITIALIZER;

    reject_or_remove_convprops_internal(&parser, &buf, jpatch, invalid, remove);

    buf_free(&buf);
    jmap_parser_fini(&parser);
}

static int _card_set_create(jmap_req_t *req,
                            json_t *jcard, struct mailbox **mailbox,
                            json_t *item, jmap_contact_errors_t *errors);

static int _card_set_update(jmap_req_t *req, bool apply_empty_updates,
                            const char *id, json_t *jcard,
                            struct carddav_db *db, struct mailbox **mailbox,
                            json_t **item, jmap_contact_errors_t *errors);

static int jmap_card_set(struct jmap_req *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_set set = JMAP_SET_INITIALIZER;
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
    jmap_set_parse(req, &parser, &card_props, NULL, NULL, &set, &err);
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

    if (!has_addressbooks(req)) {
        r = carddav_create_defaultaddressbook(req->accountid);
        if (r) goto done;
    }

    /* destroy */
    size_t index;
    for (index = 0; index < json_array_size(set.destroy); index++) {
        const char *id = _json_array_get_string(set.destroy, index);
        if (!id) {
            json_t *err = json_pack("{s:s}", "type", "invalidArguments");
            json_object_set_new(set.not_destroyed, id, err);
            continue;
        }
        mbentry_t *mbentry = NULL;
        struct carddav_data *cdata = NULL;
        uint32_t olduid;
        if (USER_COMPACT_EMAILIDS(req->cstate)) {
            if (id[0] == JMAP_CONTACTID_PREFIX &&
                strlen(id) < JMAP_CONTACTID_SIZE) {
                r = carddav_lookup_jmapid(db, id+1, &cdata);  // strip prefix
            }
        }
        else {
            r = carddav_lookup_uid(db, NULL, id, &cdata);
        }

        /* is it a valid contact? */
        if (r || !cdata || !cdata->dav.imap_uid) {
            r = 0;
            json_t *err = json_pack("{s:s}", "type", "notFound");
            json_object_set_new(set.not_destroyed, id, err);
            continue;
        }
        olduid = cdata->dav.imap_uid;

        mbentry = jmap_mbentry_from_dav(req, &cdata->dav);

        if (!mbentry || !jmap_hasrights_mbentry(req, mbentry, JACL_REMOVEITEMS)) {
            int rights = mbentry ? jmap_myrights_mbentry(req, mbentry) : 0;
            json_t *err = json_pack("{s:s}", "type",
                                    rights & JACL_READITEMS ?
                                    "accountReadOnly" : "notFound");
            json_object_set_new(set.not_destroyed, id, err);
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
               cdata->kind == CARDDAV_KIND_GROUP ? "group" : "contact",
               req->accountid, id);
        r = carddav_remove(mailbox, olduid, /*isreplace*/0, req->userid);
        if (r) {
            xsyslog(LOG_ERR, "IOERROR: carddav remove failed",
                             "kind=<%s> mailbox=<%s> olduid=<%u>",
                             cdata->kind == CARDDAV_KIND_GROUP ? "group" : "contact",
                             mailbox_name(mailbox), olduid);
            goto done;
        }

        json_array_append_new(set.destroyed, json_string(id));
    }

    /* create */
    const char *key;
    json_t *arg;
    json_object_foreach(set.create, key, arg) {
        json_t *invalid = json_array();
        jmap_contact_errors_t errors = { invalid, NULL };
        json_t *item = json_object();
        // XXX Silently remove conversion properties if extension
        // capability is used. This is because due to a bug
        // we had served Card objects with these properties
        // and now client requests trying to clone or update these
        // cards get rejected.
        reject_or_remove_convprops(arg, invalid,
                jmap_is_using(req, JMAP_CONTACTS_EXTENSION));
        r = _card_set_create(req, arg, &mailbox, item, &errors);
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
        // XXX Silently remove conversion properties if extension
        // capability is used. This is because due to a bug
        // we had served Card objects with these properties
        // and now client requests trying to clone or update these
        // cards get rejected.
        reject_or_remove_convprops(arg, invalid,
                jmap_is_using(req, JMAP_CONTACTS_EXTENSION));
        r = _card_set_update(req, set.apply_empty_updates,
                             uid, arg, db, &mailbox, &item, &errors);
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

    return 0;
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
    if (!hash_constructed(termset)) {
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

struct contactsquery_rock {
    jmap_req_t *req;
    struct jmap_query *query;
    jmap_filter *filter;

    struct mailbox *mailbox;
    struct carddav_db *carddavdb;
    unsigned kind;
    int build_response;
    ptrarray_t entries;
    struct buf cid;
};

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
    /* Comparators for ContactCard */
    CONTACTS_SORT_LASTNAME2,
    CONTACTS_SORT_CREATED,
    CONTACTS_SORT_UPDATED,
   /* Flag for descending sort */
    CONTACTS_SORT_DESC = 0x80,
};

struct filter_parse_rock {
    struct jmap_req *req;
    struct carddav_db *db;
};

static void *card_filter_parse(json_t *arg, void *rock);
static void card_filter_free(void *vf);
static void card_filter_validate(jmap_req_t *req __attribute__((unused)),
                                 struct jmap_parser *parser,
                                 json_t *filter,
                                 json_t *unsupported __attribute__((unused)),
                                 void *rock,
                                 json_t **err __attribute__((unused)));
static int card_comparator_validate(jmap_req_t *req __attribute__((unused)),
                                    struct jmap_comparator *comp,
                                    void *rock __attribute__((unused)),
                                    json_t **err __attribute__((unused)));
static int _cardquery_cb(void *rock, struct carddav_data *cdata);
static enum contactsquery_sort *cardquery_buildsort(json_t *jsort);
static int cardquery_cmp QSORT_R_COMPAR_ARGS(const void *va,
                                             const void *vb,
                                             void *rock);

static int jmap_card_query(struct jmap_req *req)
{
    if (!has_addressbooks(req)) {
        jmap_error(req, json_pack("{s:s}", "type", "accountNoAddressbooks"));
        return 0;
    }

    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_query query = JMAP_QUERY_INITIALIZER;
    unsigned kind = CARDDAV_KIND_ANY;
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
                     &card_filter_validate, &kind,
                     &card_comparator_validate, NULL,
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
        struct filter_parse_rock frock = { req, db };
        parsed_filter = jmap_buildfilter(filter, &card_filter_parse, &frock);
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
        PTRARRAY_INITIALIZER,
        BUF_INITIALIZER
    };
    if (wantuid) {
        /* Fast-path single filter condition by UID */
        struct carddav_data *cdata = NULL;
        r = carddav_lookup_uid(db, NULL, wantuid, &cdata);
        if (!r) _cardquery_cb(&rock, cdata);
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
        r = carddav_foreach_sort(db, NULL, &sort, nsort, &_cardquery_cb, &rock);
    }
    else {
        /* Run carddav db query and apply custom sort */
        rock.build_response = 0;
        r = carddav_foreach(db, NULL, &_cardquery_cb, &rock);
        if (!r) {
            /* Sort entries */
            enum contactsquery_sort *sort = cardquery_buildsort(query.sort);
            cyr_qsort_r(rock.entries.data, rock.entries.count, sizeof(void*),
                        &cardquery_cmp, sort);
            free(sort);
            /* Build result ids */
            int i;
            for (i = 0; i < ptrarray_size(&rock.entries); i++) {
                json_t *entry = ptrarray_nth(&rock.entries, i);
                json_array_append(query.ids, json_object_get(entry, "id"));
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
    buf_free(&rock.cid);
    /* Handle callback errors */
    if (r || err) {
        if (!err) err = jmap_server_error(r);
        jmap_error(req, err);
        goto done;
    }

    /* Build response */
    if (kind == CARDDAV_KIND_GROUP) {
        /* Replace kind => group filter */
        json_object_set_new(query.filter, "kind", json_string("group"));
    }
    query.query_state = modseqtoa(jmap_modseq(req, MBTYPE_ADDRESSBOOK, 0));

    json_t *res = jmap_query_reply(&query);
    jmap_ok(req, res);

done:
    jmap_query_fini(&query);
    jmap_parser_fini(&parser);
    if (parsed_filter) {
        jmap_filter_free(parsed_filter, &card_filter_free);
    }
    if (db) carddav_close(db);
    return 0;
}

static bool _card_prop_is_immutable(const char *name)
{
    if (!strcmp(name, "id")) {
        return true;
    }
    if (!strncmp(name, "cyrusimap.org:", 14)) {
        const char *sub = name + 14;
        return !strcmp(sub, "href") ||
               !strcmp(sub, "blobId") ||
               !strcmp(sub, "size");
    }
    return false;
}

static int required_set_rights(json_t *props, enum addrbook_change change)
{
    int needrights = 0;
    const char *name;
    json_t *val;

    json_object_foreach(props, name, val) {
        const char *myname = name;

        if (_card_prop_is_immutable(myname)) {
            /* immutable */
        }
        else if (!strcmp(myname, "addressBookIds")) {
            /* membership change; rights are determined by `change` below */
        }
        else {
            /* a "cyrusimap.org:" prefix denotes Cyrus-specific meta-data */
            if (!strncmp(myname, "cyrusimap.org:", 14)) myname += 14;

            if (!strcmp(myname, "importance")) {
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
    }

    switch (change) {
    case ADDRBOOK_CHANGE_CREATE:
        needrights |= JACL_ADDITEMS;
        break;
    case ADDRBOOK_CHANGE_MOVE:
        needrights |= JACL_REMOVEITEMS;
        break;
    case ADDRBOOK_CHANGE_NONE:
        break;
    }

    return needrights;
}

static json_t *_card_from_record(jmap_req_t *req,
                                 struct mailbox *mailbox,
                                 struct index_record *record);

static void _contact_copy(jmap_req_t *req,
                          json_t *jcard,
                          struct conversations_state *src_cstate,
                          struct carddav_db *src_db,
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
    if (USER_COMPACT_EMAILIDS(src_cstate)) {
        if (src_id[0] == JMAP_CONTACTID_PREFIX &&
            strlen(src_id) < JMAP_CONTACTID_SIZE) {
            r = carddav_lookup_jmapid(src_db, src_id+1, &cdata);  // strip prefix
        }
        else {
            r = CYRUSDB_NOTFOUND;
        }
    }
    else {
        r = carddav_lookup_uid(src_db, NULL, src_id, &cdata);
    }
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
    if (!r) src_card = _card_from_record(req, src_mbox, &record);
    if (!src_card) {
        syslog(LOG_ERR, "contact_copy: can't convert %s to JMAP", src_id);
        r = IMAP_INTERNAL;
        goto done;
    }

    // Apply patch.
    json_t *invalid = json_array();
    reject_or_remove_convprops(jcard, invalid, false);
    dst_card = jmap_patchobject_apply(src_card, jcard, NULL, 0);
    json_object_del(dst_card, "id");  // immutable and WILL change
    json_decref(src_card);

    /* Create vcard */
    jmap_contact_errors_t errors = { invalid, NULL };
    json_t *item = json_object();
    r = _card_set_create(req, dst_card, &dst_mbox, item, &errors);
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

static int jmap_card_copy(struct jmap_req *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_copy copy = JMAP_COPY_INITIALIZER;
    json_t *err = NULL;
    struct carddav_db *src_db = NULL;
    struct conversations_state *src_cstate = NULL;
    json_t *destroy_cards = json_array();

    /* Parse request */
    jmap_copy_parse(req, &parser, NULL, NULL, &copy, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    if (copy.if_from_in_state) {
        struct mboxname_counters counters;
        char *srcinbox = mboxname_user_mbox(copy.from_account_id, NULL);
        assert (!mboxname_read_counters(srcinbox, &counters));
        free(srcinbox);
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

    int r = 0;
    r = conversations_open_user(copy.from_account_id, 1/*shared*/, &src_cstate);
    if (!r) src_db = carddav_open_userid(copy.from_account_id);
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

        _contact_copy(req, jcard, src_cstate, src_db, &new_card, &set_err);
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
        json_t *subargs = json_object();
        json_object_set(subargs, "destroy", destroy_cards);
        json_object_set_new(subargs, "accountId", json_string(copy.from_account_id));
        if (copy.destroy_from_if_in_state) {
            json_object_set_new(subargs, "ifInState",
                                json_string(copy.destroy_from_if_in_state));
        }
        jmap_add_subreq(req, "ContactCard/set", subargs, NULL);
    }

done:
    json_decref(destroy_cards);
    if (src_db) carddav_close(src_db);
    if (src_cstate) conversations_abort(&src_cstate);
    jmap_parser_fini(&parser);
    jmap_copy_fini(&copy);
    return 0;
}


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
            "mayShare",
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
        else if (!strcmp("mayShare", name))
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

static void abookid_to_mbentry(jmap_req_t *req, const char *id,
                               mbentry_t **mbentry)
{
    const char *idtype;
    int r = IMAP_NOTFOUND;

    if (USER_COMPACT_EMAILIDS(req->cstate)) {
        idtype = "jmapid";
        if (id[0] == JMAP_ADDRBOOKID_PREFIX) {
            char jmapid[JMAP_ADDRBOOKID_SIZE];
            strlcpy(jmapid, id, JMAP_ADDRBOOKID_SIZE);
            jmapid[0] = JMAP_MAILBOXID_PREFIX;
            r = mboxlist_lookup_by_jmapid(req->accountid, jmapid, mbentry, NULL);
        }
    }
    else {
        char *mboxname = carddav_mboxname(req->accountid, id);
        idtype = "name";
        r = mboxlist_lookup(mboxname, mbentry, NULL);
        free(mboxname);
    }

    if (r) {
        if (r != IMAP_NOTFOUND) {
            syslog(LOG_ERR,
                   "Error reading mbentry for addressbook via %s %s: %s",
                   idtype, id, error_message(r));
        }

        *mbentry = NULL;
    }
    else if (((*mbentry)->mbtype & (MBTYPE_RESERVE | MBTYPE_DELETED)) ||
             mboxname_isdeletedmailbox((*mbentry)->name, NULL)) {
        /* Ignore "reserved" and "deleted" entries, like they aren't there */
        mboxlist_entry_free(mbentry);
        *mbentry = NULL;
    }
}

struct getaddressbooks_rock {
    struct jmap_req *req;
    struct jmap_get *get;
    const char *default_addrbookname;
    int skip_hidden;
};

static int getaddressbooks_cb(const mbentry_t *mbentry, void *vrock)
{
    struct getaddressbooks_rock *rock = vrock;
    jmap_req_t *req = rock->req;
    int r = 0;

    /* Only addressbooks... */
    if (mbtype_isa(mbentry->mbtype) != MBTYPE_ADDRESSBOOK) return 0;

    /* ...which are at least readable or visible... */
    if (!jmap_hasrights_mbentry(rock->req, mbentry, JACL_READITEMS))
        return rock->skip_hidden ? 0 : IMAP_PERMISSION_DENIED;

    // needed for some fields
    int rights = jmap_myrights_mbentry(rock->req, mbentry);

    /* OK, we want this one... */
    json_t *obj = json_object();

    char id[JMAP_MAX_ADDRBOOKID_SIZE];
    jmap_set_addrbookid(req->cstate, mbentry, id);
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
        if (r || !attrib.len) {
            mbname_t *mbname = mbname_from_intname(mbentry->name);
            const strarray_t *boxes = mbname_boxes(mbname);
            const char *id = strarray_nth(boxes, boxes->count-1);
            buf_setcstr(&attrib, id);
            mbname_free(&mbname);
        }
        json_object_set_new(obj, "name", json_string(buf_cstring(&attrib)));
        buf_free(&attrib);
    }

    if (jmap_wantprop(rock->get->props, "description")) {
        buf_reset(&attrib);
        static const char *description_annot =
            DAV_ANNOT_NS "<" XML_NS_DAV ">addressbook-description";
        r = annotatemore_lookupmask_mbe(mbentry, description_annot,
                                        req->userid, &attrib);
        json_object_set_new(obj, "description", buf_len(&attrib) ?
                            json_string(buf_cstring(&attrib)) : json_null());
        buf_free(&attrib);
    }

    if (jmap_wantprop(rock->get->props, "sortOrder")) {
        buf_reset(&attrib);
        static const char *sortorder_annot = IMAP_ANNOT_NS "sortorder";
        int sort_order = 0;
        r = annotatemore_lookupmask_mbe(mbentry, sortorder_annot,
                                        req->userid, &attrib);
        if (buf_len(&attrib)) {
            uint64_t t = str2uint64(buf_cstring(&attrib));
            if (t < INT_MAX) {
                sort_order = (int) t;
            } else {
                syslog(LOG_ERR, "%s: bogus sortorder annotation value for %s",
                       mbentry->name, httpd_userid);
            }
        }
        json_object_set_new(obj, "sortOrder", json_integer(sort_order));
        buf_free(&attrib);
    }

    if (jmap_wantprop(rock->get->props, "isDefault")) {
        bool is_default = !strcmp(rock->default_addrbookname, mbentry->name);
        json_object_set_new(obj, "isDefault", json_boolean(is_default));
    }

    if (jmap_wantprop(rock->get->props, "isSubscribed")) {
        int is_subscribed;
        if (mboxname_userownsmailbox(req->userid, mbentry->name)) {
            /* Users always subscribe their own addressbooks */
            is_subscribed = 1;
        }
        else if (rights & ACL_AUTOSUB) {
            /* ACL keeps this user subscribed */
            is_subscribed = 1;
        }
        else {
            /* Lookup mailbox subscriptions */
            is_subscribed = mboxlist_checksub(mbentry->name, req->userid) == 0;
        }
        json_object_set_new(obj, "isSubscribed", json_boolean(is_subscribed));
    }

    if (jmap_wantprop(rock->get->props, "myRights")) {
        if (!strcmp(rock->default_addrbookname, mbentry->name)) {
            /* We don't allow deleting the default addressbook */
            rights &= ~JACL_DELETE;
        }
        json_object_set_new(obj, "myRights", addressbookrights_to_jmap(rights));
    }

    if (jmap_wantprop(rock->get->props, "shareWith")) {
        json_t *sharewith =
            jmap_get_sharewith(mbentry, addressbookrights_to_jmap);
        json_object_set_new(obj, "shareWith", sharewith);
    }

    if (jmap_wantprop(rock->get->props, "mailboxUniqueId")) {
        json_object_set_new(obj, "mailboxUniqueId", json_string(mbentry->uniqueid));
    }

    json_array_append_new(rock->get->list, obj);

    buf_free(&attrib);
    return r;
}

static const char *default_addrbookname_annot =
    DAV_ANNOT_NS "<" XML_NS_CYRUS ">jmap-default-addressbook";

static char *lookup_default_addrbookname(char *cardhomename)
{
    struct buf buf = BUF_INITIALIZER;

    int r = annotatemore_lookupmask(cardhomename,
                                    default_addrbookname_annot, "", &buf);

    if (r || !buf.len) {
        /* fallback to specifically-named default created at provisioning */
        mbname_t *mbname = mbname_from_intname(cardhomename);

        mbname_push_boxes(mbname, DEFAULT_ADDRBOOK);
        buf_setcstr(&buf, mbname_intname(mbname));
        mbname_free(&mbname);
    }

    return buf_release(&buf);
}

static int jmap_addressbook_get(struct jmap_req *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_get get = JMAP_GET_INITIALIZER;
    char *cardhomename = NULL;
    char *default_addrbookname = NULL;
    json_t *err = NULL;
    int r = 0;

    /* Parse request */
    jmap_get_parse(req, &parser, &addressbook_props, /*allow_null_ids*/1,
                   NULL, NULL, &get, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    cardhomename = carddav_mboxname(req->accountid, NULL);
    default_addrbookname = lookup_default_addrbookname(cardhomename);

    /* Build callback data */
    struct getaddressbooks_rock rock =
        { req, &get, default_addrbookname, 1 /*skiphidden*/ };

    /* Does the client request specific addressbooks? */
    if (JNOTNULL(get.ids)) {
        size_t i;
        json_t *jval;

        rock.skip_hidden = 0; /* complain about missing ACL rights */
        json_array_foreach(get.ids, i, jval) {
            const char *id = json_string_value(jval);
            mbentry_t *mbentry = NULL;
            abookid_to_mbentry(req, id, &mbentry);
            if (!mbentry) {
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
            if (r) goto done;
        }
    }
    else {
        r = mboxlist_mboxtree(cardhomename,
                              &getaddressbooks_cb, &rock, MBOXTREE_SKIP_ROOT);
        if (r) goto done;
    }

    /* Build response */
    get.state = modseqtoa(jmap_modseq(req, MBTYPE_ADDRESSBOOK, 0));
    jmap_ok(req, jmap_get_reply(&get));

done:
    jmap_parser_fini(&parser);
    jmap_get_fini(&get);
    free(default_addrbookname);
    free(cardhomename);
    return r;
}

struct addressbookchanges_rock {
    jmap_req_t *req;
    struct jmap_changes *changes;
};

static int getaddressbookchanges_cb(const mbentry_t *mbentry, void *vrock)
{
    struct addressbookchanges_rock *rock = (struct addressbookchanges_rock *) vrock;
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

    char id[JMAP_MAX_ADDRBOOKID_SIZE];
    jmap_set_addrbookid(req->cstate, mbentry, id);

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
    const char *description;
    int sortOrder;
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

    /* description */
    jprop = json_object_get(arg, "description");
    if (json_is_string(jprop)) {
        props->description = json_string_value(jprop);
    }
    else if (JNOTNULL(jprop)) {
        jmap_parser_invalid(parser, "description");
    }

    /* sortOrder */
    jprop = json_object_get(arg, "sortOrder");
    if (json_is_integer(jprop)) {
        json_int_t t = json_integer_value(jprop);
        if (t < 0 || t >= INT_MAX) {
            jmap_parser_invalid(parser, "sortOrder");
        }
        else {
            props->sortOrder = t;
        }
    }
    else if (JNOTNULL(jprop)) {
        jmap_parser_invalid(parser, "sortOrder");
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
                             strcmp(right, "mayShare") &&
                             strcmp(right, "mayDelete"))) {

                        jmap_parser_push(parser, "shareWith");
                        jmap_parser_push(parser, sharee);
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

    /* description */
    if (!r && props->description) {
        buf_setcstr(&val, props->description);
        static const char *description_annot =
            DAV_ANNOT_NS "<" XML_NS_DAV ">addressbook-description";
        r = annotate_state_writemask(astate, description_annot, req->userid, &val);
        if (r) {
            syslog(LOG_ERR, "failed to write annotation %s: %s",
                   description_annot, error_message(r));
        }
        buf_reset(&val);
    }

    /* sortOrder */
    if (!r && props->sortOrder >= 0) {
        buf_reset(&val);
        buf_printf(&val, "%d", props->sortOrder);
        static const char *sortorder_annot = IMAP_ANNOT_NS "sortorder";
        r = annotatemore_writemask(mboxname, sortorder_annot, httpd_userid, &val);
        if (r) {
            syslog(LOG_ERR, "failed to write annotation %s: %s",
                    sortorder_annot, error_message(r));
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
                                    const char *default_addrbookname,
                                    int destroy_contents, json_t **err)
{
    mbentry_t *mbentry = NULL;
    struct carddav_db *db = NULL;
    int r = 0;

    abookid_to_mbentry(req, abookid, &mbentry);

    /* Check ACL */
    if (!mbentry || !jmap_hasrights_mbentry(req, mbentry, JACL_READITEMS)) {
        *err = json_pack("{s:s}", "type", "notFound");
        goto done;
    }
    else if (!jmap_hasrights_mbentry(req, mbentry, JACL_DELETE)) {
        *err = json_pack("{s:s}", "type", "accountReadOnly");
        goto done;
    }

    /* Don't delete default addressbook */
    if (!strcmp(mbentry->name, default_addrbookname)) {
        *err = json_pack("{s:s}", "type", "forbidden");
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

    jmap_myrights_delete(req, mbentry->name);

    /* Remove from subscriptions db */
    mboxlist_changesub(mbentry->name, req->userid, req->authstate, 0, 1, 0, 1);

    struct mboxevent *mboxevent = mboxevent_new(EVENT_MAILBOX_DELETE);
    if (mboxlist_delayed_delete_isenabled()) {
        r = mboxlist_delayed_deletemailbox(mbentry->name,
                httpd_userisadmin || httpd_userisproxyadmin,
                req->userid, req->authstate, mboxevent,
                MBOXLIST_DELETE_CHECKACL|MBOXLIST_DELETE_KEEP_INTERMEDIARIES);
    } else {
        r = mboxlist_deletemailbox(mbentry->name,
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

    /* Lookup the new mailbox id */
    mbentry_t *newmbentry = NULL;
    r = jmap_mboxlist_lookup(mboxname, &newmbentry, NULL);
    if (r) {
        syslog(LOG_ERR, "IOERROR: failed to lookup %s after create (%s)",
                mboxname, error_message(r));
        goto done;
    }

    /* Report addressbook as created. */
    char id[JMAP_MAX_ADDRBOOKID_SIZE];
    jmap_set_addrbookid(req->cstate, newmbentry, id);
    *record = json_pack("{s:s s:o}", "id", id,
                        "myRights",
                        addressbookrights_to_jmap(jmap_myrights_mbentry(req,
                                                                        newmbentry)));
    jmap_add_id(req, creation_id, id);

    if (jmap_is_using(req, JMAP_CONTACTS_EXTENSION)) {
        json_object_set_new(*record, "mailboxUniqueId",
                        json_string(newmbentry->uniqueid));
        char *xhref = jmap_xhref(mboxname, NULL);
        json_object_set_new(*record, "cyrusimap.org:href", json_string(xhref));
        free(xhref);
    }

    mboxlist_entry_free(&newmbentry);

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
                                   const char *abookid,
                                   json_t *arg,
                                   json_t **record,
                                   json_t **err)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    mbentry_t *mbentry = NULL;

    abookid_to_mbentry(req, abookid, &mbentry);

    if (!mbentry) {
        *err = json_pack("{s:s}", "type", "notFound");
        goto done;
    }

    /* Parse and validate properties. */
    struct setaddressbook_props props;
    setaddressbook_readprops(req, &parser, &props, arg, mbentry->name);
    if (props.share.With) {
        if (!jmap_hasrights(req, mbentry->name, ACL_ADMIN)) {
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
    int r = setaddressbook_writeprops(req, mbentry->name, &props, /*ignore_acl*/0);
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

    /* Report addressbook as updated. If the client asked to
     * unsubscribe but an auto-subscribe ACL keeps them subscribed,
     * report the effective value back as server-set. */
    if (props.isSubscribed == 0 &&
            (jmap_myrights(req, mbentry->name) & ACL_AUTOSUB)) {
        *record = json_pack("{s:b}", "isSubscribed", 1);
    }
    else {
        *record = json_null();
    }

done:
    mboxlist_entry_free(&mbentry);
    jmap_parser_fini(&parser);
}

struct addressbook_set_args {
    bool on_destroy_remove_contents;
    const char *on_success_set_is_default;
};

static int setaddressbooks_parse_args(jmap_req_t *req __attribute__((unused)),
                                      struct jmap_parser *parser __attribute__((unused)),
                                      const char *arg, json_t *val, void *rock)
{
    struct addressbook_set_args *setargs = (struct addressbook_set_args *) rock;

    if (!strcmp(arg, "onDestroyRemoveContents")) {
        if (json_is_boolean(val)) {
            setargs->on_destroy_remove_contents = json_boolean_value(val);
            return 1;
        }
    }

    else if (!strcmp(arg, "onSuccessSetIsDefault")) {
        if (json_is_string(val)) {
            setargs->on_success_set_is_default = json_string_value(val);
            return 1;
        }
    }

    return 0;
}

static int jmap_addressbook_set(struct jmap_req *req)
{
    struct jmap_parser argparser = JMAP_PARSER_INITIALIZER;
    struct jmap_set set = JMAP_SET_INITIALIZER;
    struct addressbook_set_args setargs = { 0 };
    char *cardhomename = NULL;
    char *default_addrbookname = NULL;
    json_t *err = NULL;
    int r = 0;

    /* Parse arguments */
    jmap_set_parse(req, &argparser, &addressbook_props,
                   setaddressbooks_parse_args, &setargs, &set, &err);
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

    cardhomename = carddav_mboxname(req->accountid, NULL);
    default_addrbookname = lookup_default_addrbookname(cardhomename);

    if (!has_addressbooks(req)) {
        r = carddav_create_defaultaddressbook(req->accountid);
        if (r) goto done;
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
        setaddressbooks_destroy(req, abookid, default_addrbookname,
                                setargs.on_destroy_remove_contents, &err);
        if (!err) {
            json_array_append_new(set.destroyed, json_string(id));
        }
        else json_object_set_new(set.not_destroyed, id, err);
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

    if (setargs.on_success_set_is_default &&
        /* No failures */
        !json_object_size(set.not_created) &&
        !json_object_size(set.not_updated) &&
        !json_object_size(set.not_destroyed)) {

        /* resolve new default addressbook id */
        const char *newid = setargs.on_success_set_is_default;
        if (*newid == '#') {
            json_t *jobj = json_object_get(set.created, newid+1);
            if (jobj) newid = json_string_value(json_object_get(jobj, "id"));
        }

        /* Make sure the new default addressbook exists, and that the caller
         * has admin rights on the addressbook home: for changing per-account
         * state, per-addressbook rights aren't enough. */
        mbentry_t *mbentry = NULL;
        abookid_to_mbentry(req, newid, &mbentry);
        if (mbentry &&
            jmap_hasrights(req, cardhomename, JACL_ADMIN_ADDRBOOK)) {
            /* set jmap-default-addressbook annotation */
            struct buf buf = BUF_INITIALIZER;
            buf_init_ro_cstr(&buf, mbentry->name);
            r = annotatemore_writemask(cardhomename, default_addrbookname_annot,
                                       req->accountid, &buf);
            buf_free(&buf);

            if (!r) {
                /* report that isDefault has been moved to new addressbook */
                jmap_report_isdefault(&set, mbentry->name,
                                      setargs.on_success_set_is_default, true);

                /* report that isDefault has been removed from old default */
                mboxlist_entry_free(&mbentry);
                mboxlist_lookup(default_addrbookname, &mbentry, NULL);
                if (mbentry) {
                    char oldid[JMAP_MAX_ADDRBOOKID_SIZE];

                    jmap_set_addrbookid(req->cstate, mbentry, oldid);
                    jmap_report_isdefault(&set, mbentry->name, oldid, false);
                }
            }
        }

        mboxlist_entry_free(&mbentry);
    }

    set.new_state =
        modseqtoa(jmap_modseq(req, MBTYPE_ADDRESSBOOK, JMAP_MODSEQ_RELOAD));

    jmap_ok(req, jmap_set_reply(&set));

done:
    jmap_parser_fini(&argparser);
    jmap_set_fini(&set);
    free(default_addrbookname);
    free(cardhomename);
    return r;
}


/*****************************************************************************
 * JMAP ContactCard API
 ****************************************************************************/

/*
 * ContactCard/get
 */


static int getcards_cb(void *rock, struct carddav_data *cdata)
{
    struct cards_rock *crock = (struct cards_rock *) rock;
    struct jmap_req *req = crock->req;
    struct index_record record;
    json_t *obj = NULL;
    char *href = NULL;
    int r = 0;

    mbentry_t *mbentry = jmap_mbentry_from_dav(req, &cdata->dav);

    if (!mbentry ||
        !jmap_hasrights_mbentry(req, mbentry, JACL_READITEMS)) {
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

    /* Calculate href if wanted. We need to do here since we need it for
     * a cached response. */
    if (jmap_wantprop(crock->get->props, "cyrusimap.org:href")) {
        href = jmap_xhref(mbentry->name, cdata->dav.resource);
    }

    if (cdata->jmapversion == JMAPCACHE_CARDVERSION) {
        /* We only cache contacts with media as blobids */
        json_error_t jerr;
        obj = json_loads(cdata->jmapdata, 0, &jerr);
        if (obj) goto gotvalue;
    }

    /* Load message containing the resource and parse vcard data */
    vcardcomponent *vcard = record_to_vcard(crock->mailbox, &record);
    if (!vcard) {
        syslog(LOG_ERR, "record_to_vcard failed for record %u:%s",
                cdata->dav.imap_uid, mailbox_name(crock->mailbox));
        r = IMAP_INTERNAL;
        goto done;
    }

    /* Always work with a v4 card so we have "clean" MEMBER properties */
    if (cdata->version == 3) {
        vcardcomponent_transform(vcard, VCARD_VERSION_40);
    }

    /* Convert the vCard to a JSContact Card. */
    jscontact_ctx_t ctx = {
        .mailbox = crock->mailbox,
        .record = &record,
        .ignore_derived_props = true,
    };

    obj = _card_from_vcard(req, &ctx, vcard);
    vcardcomponent_free(vcard);

    if (!obj) {
        syslog(LOG_ERR, "_card_from_vcard returned NULL for %u:%s",
                cdata->dav.imap_uid, mailbox_name(crock->mailbox));
        r = IMAP_INTERNAL;
        goto done;
    }

    /* Cache contact */
    hashu64_insert(cdata->dav.rowid, json_dumps(obj, 0), &crock->jmapcache);

    if (jmap_is_using(req, JMAP_DEBUG_EXTENSION)) {
        /* Set vCard version for debugging. */
        struct buf buf = BUF_INITIALIZER;
        buf_printf(&buf, "%d.0", cdata->version);
        json_object_set_new(obj, "cyrusimap.org:vCardVersion",
                json_string(buf_cstring(&buf)));
        buf_free(&buf);
    }

  gotvalue:

    jmap_filterprops(obj, crock->get->props);

    if (href) {
        json_object_set_new(obj, "cyrusimap.org:href", json_string(href));
    }
    if (jmap_wantprop(crock->get->props, "cyrusimap.org:blobId")) {
        struct buf blobid = BUF_INITIALIZER;

        jmap_encode_rawdata_blobid('V', mbentry->uniqueid, record.uid,
                                   NULL, NULL, "G", &record.guid, &blobid);
        json_object_set_new(obj, "cyrusimap.org:blobId",
                            json_string(buf_cstring(&blobid)));
        buf_free(&blobid);
    }
    if (jmap_wantprop(crock->get->props, "cyrusimap.org:size")) {
        json_object_set_new(obj, "cyrusimap.org:size",
                            json_integer(record.size - record.header_size));
    }

    jmap_set_contactid(req->cstate, cdata, &crock->cid);
    json_object_set_new(obj, "id", json_string(buf_cstring(&crock->cid)));

    char id[JMAP_MAX_ADDRBOOKID_SIZE];
    jmap_set_addrbookid(req->cstate, mbentry, id);
    json_object_set_new(obj, "addressBookIds", json_pack("{s:b}", id, true));

    json_array_append_new(crock->get->list, obj);
    crock->rows++;

 done:
    mboxlist_entry_free(&mbentry);
    free(href);

    return 0;
}

/*
 * ContactCard/query
 */

#define card_filter_match_textval   contact_filter_match_textval
#define card_filter_match_textprop  contact_filter_match_textprop

struct card_filter {
    const char *uid;
    const char *createdBefore;
    const char *createdAfter;
    const char *updatedBefore;
    const char *updatedAfter;
    mbentry_t *inAddressBook;
    hash_table *inCardGroup;
    struct contact_textfilter *fullName;
    struct contact_textfilter *given;
    struct contact_textfilter *surname;
    struct contact_textfilter *surname2;
    struct contact_textfilter *nickname;
    struct contact_textfilter *organization;
    struct contact_textfilter *email;
    struct contact_textfilter *phone;
    struct contact_textfilter *online;
    struct contact_textfilter *address;
    struct contact_textfilter *note;
    struct contact_textfilter *text;
    struct contact_textfilter *member;
    struct contact_textfilter *kind;
};

/* Free the memory allocated by this card filter. */
static void card_filter_free(void *vf)
{
    struct card_filter *f = (struct card_filter *) vf;

    mboxlist_entry_free(&f->inAddressBook);
    if (f->inCardGroup) {
        free_hash_table(f->inCardGroup, NULL);
        free(f->inCardGroup);
    }
    contact_textfilter_free(f->fullName);
    contact_textfilter_free(f->given);
    contact_textfilter_free(f->surname);
    contact_textfilter_free(f->surname2);
    contact_textfilter_free(f->nickname);
    contact_textfilter_free(f->organization);
    contact_textfilter_free(f->email);
    contact_textfilter_free(f->phone);
    contact_textfilter_free(f->online);
    contact_textfilter_free(f->address);
    contact_textfilter_free(f->note);
    contact_textfilter_free(f->text);
    contact_textfilter_free(f->member);
    contact_textfilter_free(f->kind);
    free(f);
}

/* Parse the JMAP ContactCard FilterCondition in arg.
 * Report any invalid properties in invalid, prefixed by prefix.
 * Return NULL on error. */
static void *card_filter_parse(json_t *arg, void *rock)
{
    struct filter_parse_rock *frock = (struct filter_parse_rock *) rock;
    struct card_filter *f =
        (struct card_filter *) xzmalloc(sizeof(struct card_filter));

    /* inAddressBook */
    if (JNOTNULL(json_object_get(arg, "inAddressBook"))) {
        const char *id = NULL;
        if (jmap_readprop(arg, "inAddressBook", 0, NULL, "s", &id) > 0) {
            abookid_to_mbentry(frock->req, id, &f->inAddressBook);
        }
    }

    /* inCardGroup */
    json_t *inCardGroup = json_object_get(arg, "inCardGroup");
    if (inCardGroup) {
        struct buf cid = BUF_INITIALIZER;
        f->inCardGroup = xmalloc(sizeof(struct hash_table));
        construct_hash_table(f->inCardGroup,
                             json_array_size(inCardGroup)+1, 0);
        size_t i;
        json_t *val;
        json_array_foreach(inCardGroup, i, val) {
            const char *id;
            if (json_unpack(val, "s", &id) != -1) {
                struct carddav_data *cdata = NULL;

                if (USER_COMPACT_EMAILIDS(frock->req->cstate)) {
                    if (id[0] == JMAP_CONTACTID_PREFIX &&
                        strlen(id) < JMAP_CONTACTID_SIZE) {
                        /* translate JMAP IDs to vCard UIDs */
                        int r = carddav_lookup_jmapid(frock->db, id+1, &cdata);
                        if (!r && cdata) id = cdata->vcard_uid;
                    }
                }

                hash_insert(id, (void*)1, f->inCardGroup);
            }
        }
        buf_free(&cid);
    }

    /* createdBefore */
    if (JNOTNULL(json_object_get(arg, "createdBefore"))) {
        jmap_readprop(arg, "createdBefore", 0, NULL, "s", &f->createdBefore);
    }
    /* createdAfter */
    if (JNOTNULL(json_object_get(arg, "createdAfter"))) {
        jmap_readprop(arg, "createdAfter", 0, NULL, "s", &f->createdAfter);
    }
    /* updatedBefore */
    if (JNOTNULL(json_object_get(arg, "updatedBefore"))) {
        jmap_readprop(arg, "updatedBefore", 0, NULL, "s", &f->updatedBefore);
    }
    /* updatedAfter */
    if (JNOTNULL(json_object_get(arg, "updatedAfter"))) {
        jmap_readprop(arg, "updatedAfter", 0, NULL, "s", &f->updatedAfter);
    }

    /* fullName */
    if (JNOTNULL(json_object_get(arg, "name"))) {
        const char *s = NULL;
        if (jmap_readprop(arg, "name", 0, NULL, "s", &s) > 0) {
            f->fullName = contact_textfilter_new(s);
        }
    }
    /* given */
    if (JNOTNULL(json_object_get(arg, "name/given"))) {
        const char *s = NULL;
        if (jmap_readprop(arg, "name/given", 0, NULL, "s", &s) > 0) {
            f->given = contact_textfilter_new(s);
        }
    }
    /* surname */
    if (JNOTNULL(json_object_get(arg, "name/surname"))) {
        const char *s = NULL;
        if (jmap_readprop(arg, "name/surname", 0, NULL, "s", &s) > 0) {
            f->surname = contact_textfilter_new(s);
        }
    }
    /* surname2 */
    if (JNOTNULL(json_object_get(arg, "name/surname2"))) {
        const char *s = NULL;
        if (jmap_readprop(arg, "name/surname2", 0, NULL, "s", &s) > 0) {
            f->surname2 = contact_textfilter_new(s);
        }
    }
    /* nickname */
    if (JNOTNULL(json_object_get(arg, "nickname"))) {
        const char *s = NULL;
        if (jmap_readprop(arg, "nickname", 0, NULL, "s", &s) > 0) {
            f->nickname = contact_textfilter_new(s);
        }
    }
    /* organization */
    if (JNOTNULL(json_object_get(arg, "organization"))) {
        const char *s = NULL;
        if (jmap_readprop(arg, "organization", 0, NULL, "s", &s) > 0) {
            f->organization = contact_textfilter_new(s);
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
            !strcmp(field, "name/given") ||
            !strcmp(field, "name/surname") ||
            !strcmp(field, "name/surname2") ||
            !strcmp(field, "nickname") ||
            !strcmp(field, "organization") ||
            !strcmp(field, "email") ||
            !strcmp(field, "phone") ||
            !strcmp(field, "onlineService") ||
            !strcmp(field, "address") ||
            !strcmp(field, "note") ||
            !strcmp(field, "text") ||
            !strcmp(field, "kind") ||
            !strcmp(field, "hasMember") ||
            !strcmp(field, "inAddressBook") ||
            !strcmp(field, "uid")) {
            if (!json_is_string(arg)) {
                jmap_parser_invalid(parser, field);
            }

           else if (!strcmp(field, "kind")) {
                int *kind = (int *) rock;

                if (!strcmp("group", json_string_value(arg))) {
                    *kind = CARDDAV_KIND_GROUP;

                    /* Group vs non-group is filtered by a flag in carddav.db.
                       Remove this property so we don't waste cycles
                       doing a text match against it.
                       We will replace it later for the response. */
                    json_object_del(filter, "kind");
                }
                else {
                    *kind = CARDDAV_KIND_CONTACT;
                }
            }
            else if (!strcmp(field, "inAddressBook")) {
                mbentry_t *mbentry = NULL;

                abookid_to_mbentry(req, json_string_value(arg), &mbentry);
                if (!mbentry) {
                    jmap_parser_invalid(parser, field);
                }
                mboxlist_entry_free(&mbentry);
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
        else if (!strcmp(field, "createdBefore") ||
                 !strcmp(field, "createdAfter")  ||
                 !strcmp(field, "updatedBefore") ||
                 !strcmp(field, "updatedAfter")) {
            if (!json_is_utcdate(arg)) {
                jmap_parser_invalid(parser, field);
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
        !strcmp(comp->property, "name/surname2") ||
        !strcmp(comp->property, "created") ||
        !strcmp(comp->property, "updated") ||
        !strcmp(comp->property, "nickname") ||
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

static int card_filter_match_timestamp(json_t *card, const char *propname,
                                       const char *filter, bool want_after)
{
    /* If we don't have a filter time, skip the test (pass) */
    if (!filter) return 1;

    const char *datestr = json_string_value(json_object_get(card, propname));

    /* If we don't have the specified time property, the test fails */
    if (!datestr) return 0;

    /* Compare the card time and filter time
       UTCDate strings: ASCII order == datetime order */
    int r = strcmp(datestr, filter);

    if (want_after) {
        /* If card time is before filter time, the fails */
        if (r < 0) return 0;
    }
    /* If card time is after filter time, the fails */
    else if (r >= 0) return 0;

    /* Otherwise, the test passes */
    return 1;
}

static const char *name_vals[] =     { "name", NULL };
static const char *email_vals[] =    { "address", "label", NULL };
static const char *phone_vals[] =    { "number", "label", NULL };
static const char *online_vals[] =   { "service", "uri", "user", "label", NULL };
static const char *note_vals[] =     { "note", NULL };

/* Match the card in rock against filter. */
static int card_filter_match(void *vf, void *rock)
{
    struct card_filter *f = (struct card_filter *) vf;
    struct contactsquery_filter_rock *cfrock = (struct contactsquery_filter_rock*) rock;
    json_t *card = cfrock->entry;
    struct carddav_data *cdata = cfrock->cdata;
    struct carddav_db *db = cfrock->carddavdb;

    /* inAddressBook */
    if (f->inAddressBook) {
        if (cdata->dav.mailbox_byname) {
            if (strcmpsafe(cdata->dav.mailbox, f->inAddressBook->name)) {
                return 0;
            }
        }
        else if (strcmpsafe(cdata->dav.mailbox, f->inAddressBook->uniqueid)) {
            return 0;
        }
    }

    /* uid */
    if (f->uid && strcmpsafe(cdata->vcard_uid, f->uid)) {
        return 0;
    }

    /* Match time filters */
    if (!card_filter_match_timestamp(card, "created", f->createdBefore, 0) ||
        !card_filter_match_timestamp(card, "created", f->createdAfter,  1) ||
        !card_filter_match_timestamp(card, "updated", f->updatedBefore, 0) ||
        !card_filter_match_timestamp(card, "updated", f->updatedAfter,  1)) {
        return 0;
    }

    /* Match text filters */
    if (f->text) contact_textfilter_reset(f->text);
    if (!card_filter_match_fullname(card, f->fullName,
                                    f->text, &cfrock->cached_termsets) ||
        !card_filter_match_namecomp(card, "given", f->given,
                                    f->text, &cfrock->cached_termsets) ||
        !card_filter_match_namecomp(card, "surname", f->surname,
                                    f->text, &cfrock->cached_termsets) ||
        !card_filter_match_namecomp(card, "surname2", f->surname2,
                                    f->text, &cfrock->cached_termsets) ||
        !card_filter_match_listprop(card, "nicknames", NULL,
                                    name_vals, f->nickname,
                                    f->text, &cfrock->cached_termsets) ||
        !card_filter_match_listprop(card, "organizations", NULL,
                                    name_vals, f->organization,
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

static int _cardquery_cb(void *rock, struct carddav_data *cdata)
{
    struct contactsquery_rock *crock = (struct contactsquery_rock*) rock;
    struct carddav_data mycdata = { 0 };
    struct index_record record;
    char *vcard_uid = NULL;
    char *mailbox = NULL;
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

    /* Copy critical values out of cdata
       because the carddav_db lookups below reuse its row buffer */
    mycdata.dav.imap_uid = cdata->dav.imap_uid;
    mycdata.dav.createdmodseq = cdata->dav.createdmodseq;
    mycdata.dav.mailbox_byname = cdata->dav.mailbox_byname;
    mycdata.dav.mailbox = mailbox = xstrdupnull(cdata->dav.mailbox);
    mycdata.vcard_uid = vcard_uid = xstrdupnull(cdata->vcard_uid);

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
    r = mailbox_find_index_record(crock->mailbox, mycdata.dav.imap_uid, &record);
    if (r) goto done;

    /* Load contact from record. */
    entry = _card_from_record(crock->req, crock->mailbox, &record);
    if (!entry) {
        syslog(LOG_ERR, "_card_from_record failed for record %u:%s",
                mycdata.dav.imap_uid, mailbox_name(crock->mailbox));
        r = IMAP_INTERNAL;
        goto done;
    }

  gotvalue:

    if (crock->filter) {
        /* Match the contact against the filter */
        struct contactsquery_filter_rock cfrock = {
            crock->carddavdb, &mycdata, entry, PTRARRAY_INITIALIZER
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

    jmap_set_contactid(crock->req->cstate, &mycdata, &crock->cid);

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
        json_array_append_new(query->ids, json_string(buf_cstring(&crock->cid)));
    }
    else {
        /* Keep matching entries for post-processing */
        json_object_set_new(entry, "id", json_string(buf_cstring(&crock->cid)));
        json_object_set_new(entry, "uid", json_string(mycdata.vcard_uid));
        ptrarray_append(&crock->entries, entry);
        entry = NULL;
    }

done:
    if (entry) json_decref(entry);
    free(mailbox);
    free(vcard_uid);
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
        else if (!strcmp(prop, "name/surname2"))
            sort[i] = CONTACTS_SORT_LASTNAME2;
        else if (!strcmp(prop, "created"))
            sort[i] = CONTACTS_SORT_CREATED;
        else if (!strcmp(prop, "updated"))
            sort[i] = CONTACTS_SORT_UPDATED;
        /* Non-standard comparators */
        else if (!strcmp(prop, "nickname"))
            sort[i] = CONTACTS_SORT_NICKNAME;
        else if (!strcmp(prop, "organization"))
            sort[i] = CONTACTS_SORT_COMPANY;
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
            case CONTACTS_SORT_LASTNAME2:
                vala = jsname_sortas(ja, "surname2", &bufa);
                valb = jsname_sortas(jb, "surname2", &bufb);
                break;
            case CONTACTS_SORT_CREATED:
                /* UTCDate strings: ASCII order == datetime order */
                vala = json_string_value(json_object_get(ja, "created"));
                valb = json_string_value(json_object_get(jb, "created"));
                break;
            case CONTACTS_SORT_UPDATED:
                /* UTCDate strings: ASCII order == datetime order */
                vala = json_string_value(json_object_get(ja, "updated"));
                valb = json_string_value(json_object_get(jb, "updated"));
                break;
            case CONTACTS_SORT_NICKNAME:
                vala = json_string_value(json_object_get(ja, "nickname"));
                valb = json_string_value(json_object_get(jb, "nickname"));
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


static int _card_set_create(jmap_req_t *req,
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
    mbentry_t *mbentry = NULL;
    json_t *media = NULL, *keys = NULL, *members = NULL;

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
            r = carddav_lookup_uid(db, NULL, uid, &mycdata);
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
                r = carddav_lookup_uid(db, NULL, uid, &mycdata);
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
        char *mboxname = mboxname_abook(req->accountid, DEFAULT_ADDRBOOK);

        if (jmap_mboxlist_lookup(mboxname, &mbentry, NULL)) {
            mboxlist_entry_free(&mbentry);
        }
        else {
            char id[JMAP_MAX_ADDRBOOKID_SIZE];
            jmap_set_addrbookid(req->cstate, mbentry, id);
            json_object_set_new(item, "addressBookIds",
                                json_pack("{s:b}", id, true));
        }
        free(mboxname);
    }
    else {
        abookid_to_mbentry(req, addressbookId, &mbentry);
        json_object_del(jcard, "addressBookIds");
    }

    int needrights = required_set_rights(jcard, ADDRBOOK_CHANGE_CREATE);

    /* Check permissions. */
    if (!mbentry || !jmap_hasrights_mbentry(req, mbentry, needrights)) {
        json_array_append_new(invalid, json_string("addressBookIds"));
        goto done;
    }

    /* we need to create and append a record */
    if (!*mailbox || strcmp(mailbox_name(*mailbox), mbentry->name)) {
        mailbox_close(mailbox);
        r = mailbox_open_iwl(mbentry->name, mailbox);
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

    /* Accept members => NULL by removing it and treating it as not present */
    members = json_object_get(jcard, "members");
    if (json_is_null(members)) {
        json_object_del(jcard, "members");
        members = NULL;
    }

    bool has_prodid = json_object_get(jcard, "prodId") != NULL;

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
           req->accountid, mbentry->name, uid, name ? name : "");

    /* Store cyrusimap.org:importance as an annotation. It is not a vCard
       property, so take it out before converting. */
    const char *importance_key = "cyrusimap.org:importance";
    json_t *jimportance = json_object_get(jcard, importance_key);

    if (jimportance) {
        _card_store_importance_annot(req, mbentry->name, importance_key,
                                     jimportance, &annots, invalid);
        json_object_del(jcard, importance_key);
    }

    struct card_blob_rock brock = { req, &blobs, errors };
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    jscontact_ctx_t ctx = {
        .uid = uid,
        .getblob = &_card_getblob,
        .addblob = &_card_addblob,
        .blob_rock = &brock,
    };

    json_decref(parser.invalid);
    parser.invalid = invalid;
    card = jscontact_to_vcard(&ctx, jcard, &parser);
    parser.invalid = NULL;
    jmap_parser_fini(&parser);

    if (!card) goto done;

    if (!has_prodid) {
        /* set the PRODID */
        vcardcomponent_add_property(card, vcardproperty_new_prodid(_prodid));
        json_object_set_new(item, "prodId", json_string(_prodid));
    }

    modseq_t cmodseq =
        mboxname_nextmodseq(mbentry->name, 0, MBTYPE_ADDRESSBOOK, 0);
    r = carddav_store(*mailbox, card, resourcename, cmodseq, &annots,
                      req->userid, req->authstate, ignorequota, /*oldsize*/ 0);
    if (r && r != HTTP_CREATED && r != HTTP_NO_CONTENT) {
        syslog(LOG_ERR, "carddav_store failed for user %s: %s",
               req->userid, error_message(r));
        goto done;
    }
    r = 0;

    /* If group members was not present, return {} */
    if (!members &&
        !strcasecmpsafe("group",
                        json_string_value(json_object_get(jcard, "kind")))) {
        json_object_set_new(item, "members", json_object());
    }

    struct index_record record;
    mailbox_find_index_record(*mailbox, (*mailbox)->i.last_uid, &record);

    struct carddav_data cdata = {
        .dav.createdmodseq = record.createdmodseq,
        .vcard_uid = uid
    };
    struct buf cid = BUF_INITIALIZER;

    jmap_set_contactid(req->cstate, &cdata, &cid);
    json_object_set_new(item, "id", json_string(buf_cstring(&cid)));
    buf_free(&cid);

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
                                   NULL, NULL, "G", &record.guid, &buf);
        json_object_set_new(item, "cyrusimap.org:blobId",
                            json_string(buf_cstring(&buf)));

        json_object_set_new(item, "cyrusimap.org:size",
                            json_integer(record.size - record.header_size));

        char *xhref = jmap_xhref(mbentry->name, resourcename);
        json_object_set_new(item, "cyrusimap.org:href", json_string(xhref));
        free(xhref);
    }

done:
    if (card) vcardcomponent_free(card);
    mboxlist_entry_free(&mbentry);
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

static int _card_set_update(jmap_req_t *req, bool apply_empty_updates,
                            const char *id, json_t *jcard,
                            struct carddav_db *db, struct mailbox **mailbox,
                            json_t **item, jmap_contact_errors_t *errors)
{
    json_t *invalid = errors->invalid;
    struct mailbox *newmailbox = NULL;
    struct carddav_data *cdata = NULL, mycdata;
    struct buf buf = BUF_INITIALIZER;
    mbentry_t *mbentry = NULL;
    uint32_t olduid;
    char *resource = NULL, *uid = NULL;
    json_t *jupdated = NULL;
    vcardcomponent *vcard = NULL;
    struct entryattlist *annots = NULL;
    ptrarray_t blobs = PTRARRAY_INITIALIZER;
    property_blob_t *blob;
    json_t *media = NULL, *keys = NULL;
    int r = 0;
    size_t num_props = json_object_size(jcard);
    json_t *new_obj = NULL;
    unsigned kind = CARDDAV_KIND_ANY;

    /* is it a valid contact? */
    if (USER_COMPACT_EMAILIDS(req->cstate)) {
        if (id[0] == JMAP_CONTACTID_PREFIX && strlen(id) < JMAP_CONTACTID_SIZE) {
            r = carddav_lookup_jmapid(db, id+1, &cdata);  // strip prefix
        }
        else {
            r = CYRUSDB_NOTFOUND;
        }
    }
    else {
        r = carddav_lookup_uid(db, NULL, id, &cdata);
    }
    if (r || !cdata || !cdata->dav.imap_uid) {
        r = HTTP_NOT_FOUND;
        goto done;
    }

    /* make a working copy of cdata -
     * conversion of vCard to JSContact might do group member lookups
     * and thus overwrite our cdata
     */
    cdata = memcpy(&mycdata, cdata, sizeof(mycdata));
    cdata->vcard_uid = uid = xstrdup(cdata->vcard_uid);
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

    /* Determine whether this set relocates the card to a different address
     * book. An addressBookIds naming the card's current book is a no-op (no
     * move, no rewrite); a different book is a move that requires rights. */
    bool is_move = false;
    json_t *jabookids = json_object_get(jcard, "addressBookIds");
    if (jabookids && json_object_size(jabookids) == 1) {
        void *iter = json_object_iter(jabookids);
        const char *abookid = json_object_iter_value(iter) == json_true() ?
            json_object_iter_key(iter) : NULL;
        if (abookid && *abookid == '#')
            abookid = jmap_lookup_id(req, abookid + 1);

        mbentry_t *tgtmbentry = NULL;
        if (abookid) abookid_to_mbentry(req, abookid, &tgtmbentry);
        if (tgtmbentry && mbentry) {
            if (!strcmpsafe(tgtmbentry->name, mbentry->name)) {
                /* sets the current address book: a no-op, not a move */
                num_props--;
            }
            else {
                /* sets a different address book: a move */
                is_move = true;
            }
        }
        mboxlist_entry_free(&tgtmbentry);
    }

    int needrights = required_set_rights(jcard,
        is_move ? ADDRBOOK_CHANGE_MOVE : ADDRBOOK_CHANGE_NONE);

    int rights = mbentry ? jmap_myrights_mbentry(req, mbentry) : 0;
    if (!mbentry || (rights & needrights) != needrights) {
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

    /* Check for changes on immutable id property */
    json_t *jid = json_object_get(jcard, "id");
    if (jid && strcmpsafe(json_string_value(jid), id)) {
        json_array_append_new(invalid, json_string("id"));
        goto done;
    }

    /* Check other immutable properties, ignore value changes. */
    {
        const char *pname;
        json_t *jval;
        json_object_foreach(jcard, pname, jval) {
            if (_card_prop_is_immutable(pname)) num_props--;
        }
    }

    const char *key = "cyrusimap.org:importance";
    json_t *jval;

    if (num_props == 1 &&
        (jval = json_object_get(jcard, key))) {
        _card_store_importance_annot(req, mailbox_name(*mailbox),
                                     key, jval, &annots, invalid);
        num_props--;
    }

    if (!num_props && !apply_empty_updates) {
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

    /* Load message containing the resource and parse vcard data */
    vcard = record_to_vcard(*mailbox, &record);
    if (!vcard) {
        syslog(LOG_ERR, "record_to_vcard failed for record %u:%s",
               cdata->dav.imap_uid, mailbox_name(*mailbox));
        r = HTTP_UNPROCESSABLE;
        goto done;
    }

    if (num_props) {
        /* Always work with a v4 card so we have "clean" MEMBER properties */
        if (cdata->version == 3) {
            vcardcomponent_transform(vcard, VCARD_VERSION_40);
        }

        /* Convert the vCard to a JSContact Card. */
        jscontact_ctx_t fromctx = {
            .mailbox = *mailbox,
            .record = &record,
            .ignore_derived_props = true,
            .set_vcard_convprops = true,
        };
        json_t *old_obj = _card_from_vcard(req, &fromctx, vcard);
        vcardcomponent_free(vcard);
        vcard = NULL;

        /* Add current addressBookId */
        char cur_abookid[JMAP_MAX_ADDRBOOKID_SIZE];
        jmap_set_addrbookid(req->cstate, mbentry, cur_abookid);
        json_object_set_new(old_obj, "addressBookIds",
                            json_pack("{s:b}", cur_abookid, true));

        /* Remove old "updated" */
        json_object_del(old_obj, "updated");

        /* Apply the patch as provided */
        new_obj = jmap_patchobject_apply(old_obj, jcard, invalid, 0);

        json_decref(old_obj);
        if (!new_obj) {
            r = HTTP_BAD_REQUEST;
            goto done;
        }

        /* Validate addressBookIds */
        const char *addressbookId = NULL;
        json_t *jval = json_object_get(new_obj, "addressBookIds");
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
        }

        if (!addressbookId) {
            json_array_append_new(invalid, json_string("addressBookIds"));
            goto done;
        }

        mbentry_t *newmbentry = NULL;
        abookid_to_mbentry(req, addressbookId, &newmbentry);

        if (!newmbentry || strcmp(newmbentry->name, mbentry->name)) {
            /* move */
            needrights |= JACL_ADDITEMS;
            if (!newmbentry ||
                !jmap_hasrights_mbentry(req, newmbentry, JACL_ADDITEMS)) {
                json_array_append_new(invalid, json_string("addressBookIds"));
                r = HTTP_FORBIDDEN;
            }
            else if (!(rights & JACL_REMOVEITEMS)) {
                r = HTTP_FORBIDDEN;
            }
            else if ((r = mailbox_open_iwl(newmbentry->name, &newmailbox))) {
                syslog(LOG_ERR, "IOERROR: failed to open %s", newmbentry->name);
            }
        }
        mboxlist_entry_free(&newmbentry);

        if (r) goto done;

        json_object_del(new_obj, "addressBookIds");

        /* Make copies of patched media/cryptoKeys properties
           in case we need to report updated blobIds */
        media = json_deep_copy(json_object_get(new_obj, "media"));
        keys = json_deep_copy(json_object_get(new_obj, "cryptoKeys"));

        *item = json_object();

        if (!json_object_get(new_obj, "updated")) {
            /* set the REVision time */
            char datestr[ISO8601_DATETIME_MAX+1] = "";
            time_t now = time(NULL);

            time_to_iso8601(now, datestr, sizeof(datestr), 1);

            json_object_set_new(new_obj, "updated", json_string(datestr));
            json_object_set_new(*item, "updated", json_string(datestr));
        }

        /* A client may echo back the immutable properties, but only with
           their current value. They convey no vCard content, so take them
           out before converting. */
        json_t *jid = json_object_get(new_obj, "id");

        if (jid) {
            struct buf cid = BUF_INITIALIZER;

            jmap_set_contactid(req->cstate, cdata, &cid);
            if (strcmpnull(buf_cstring(&cid), json_string_value(jid))) {
                json_array_append_new(invalid, json_string("id"));
            }
            buf_free(&cid);
            json_object_del(new_obj, "id");
        }

        json_t *jhref = json_object_get(new_obj, "cyrusimap.org:href");

        if (jhref) {
            char *xhref = jmap_xhref(mailbox_name(*mailbox),
                                     cdata->dav.resource);

            if (strcmpnull(json_string_value(jhref), xhref)) {
                json_array_append_new(invalid,
                                      json_string("cyrusimap.org:href"));
            }
            free(xhref);
            json_object_del(new_obj, "cyrusimap.org:href");
        }

        /* Likewise for cyrusimap.org:importance, which is an annotation */
        json_t *jimportance = json_object_get(new_obj, key);

        if (jimportance) {
            _card_store_importance_annot(req, mailbox_name(*mailbox), key,
                                         jimportance, &annots, invalid);
            json_object_del(new_obj, key);
        }

        struct card_blob_rock brock = { req, &blobs, errors };
        struct jmap_parser myparser = JMAP_PARSER_INITIALIZER;

        /* Only a newly created vCard needs its UID value type set */
        vcardproperty *uidprop = vcardproperty_new_uid(uid);

        jscontact_ctx_t ctx = {
            .uid = uid,
            .uid_prop = uidprop,
            .getblob = &_card_getblob,
            .addblob = &_card_addblob,
            .blob_rock = &brock,
        };

        json_decref(myparser.invalid);
        myparser.invalid = invalid;
        vcard = jscontact_to_vcard(&ctx, new_obj, &myparser);
        myparser.invalid = NULL;
        jmap_parser_fini(&myparser);
        vcardproperty_free(uidprop);

        if (!vcard) goto done;
    }
    else {
        *item = json_null();
    }

    if (!json_array_size(invalid) && !errors->blobNotFound) {
        struct mailbox *this_mailbox = newmailbox ? newmailbox : *mailbox;

        syslog(LOG_NOTICE, "jmap: update %s %s/%s",
               kind == CARDDAV_KIND_GROUP ? "group" : "contact",
               req->accountid, resource);
        r = carddav_store(this_mailbox, vcard, resource,
                          record.createdmodseq, &annots, req->userid,
                          req->authstate, ignorequota,
                          (record.size - record.header_size));
        if (!r) {
            struct index_record record;

            mailbox_find_index_record(this_mailbox,
                                      this_mailbox->i.last_uid, &record);

            jmap_encode_rawdata_blobid('V', mailbox_uniqueid(this_mailbox),
                                       record.uid, NULL, NULL, "G",
                                       &record.guid, &buf);
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

            /* If group members was set to null, return {} */
            if (cdata->kind == CARDDAV_KIND_GROUP &&
                json_is_null(json_object_get(jcard, "members"))) {
                json_object_set_new(*item, "members", json_object());
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
    free(uid);
    json_decref(jupdated);
    buf_free(&buf);
    while ((blob = ptrarray_pop(&blobs))) {
        property_blob_free(&blob);
    }
    ptrarray_fini(&blobs);
    json_decref(media);
    json_decref(keys);
    json_decref(new_obj);

    return r;
}

static json_t *_card_from_record(jmap_req_t *req,
                                 struct mailbox *mailbox,
                                 struct index_record *record)
{
    vcardcomponent *vcard = record_to_vcard(mailbox, record);

    if (!vcard) return NULL;

    jscontact_ctx_t ctx = {
        .mailbox = mailbox,
        .record = record,
        .set_vcard_convprops = true,
    };
    json_t *jcard = _card_from_vcard(req, &ctx, vcard);
    vcardcomponent_free(vcard);

    if (jcard && strstr(req->method, "/copy")) {
        /* jsresource_to_vcard() needs to know in which account to find blobs */
        static const char *types_with_blobid[] = { "media", "cryptoKeys", NULL };
        json_t *fromAccountId = json_object_get(req->args, "fromAccountId");

        for (const char **type = types_with_blobid; *type; type++) {
            const char *key;
            json_t *jval;

            json_object_foreach(json_object_get(jcard, *type), key, jval) {
                json_object_set(jval, "accountId", fromAccountId);
            }
        }

        // immutable and WILL change
        json_object_del(jcard, "cyrusimap.org:href");
    }

    return jcard;
}

static int jmap_card_querychanges(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_querychanges query = JMAP_QUERYCHANGES_INITIALIZER;

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

struct card_parseargs {
    hash_table *props;
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

    return r;
}

static int jmap_card_parse(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_parse parse = JMAP_QUERYCHANGES_INITIALIZER;
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

        vcard = vcard_parse_buf(&blob_ctx.blob);
        if (vcard) {
            jscontact_ctx_t ctx = {
                .mailbox = mailbox,
                .record = &record,
                .ignore_derived_props = true,
            };
            jcard = _card_from_vcard(req, &ctx, vcard);
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
    if (!strcmpsafe(propname, "G")) {
        // G subpart encodes the guid of the whole vCard blob
        xzfree(propname);
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
        vcard = record_to_vcard(mailbox, &record);
        if (!vcard) {
            ctx->errstr = "failed to parse vCard";
            res = HTTP_SERVER_ERROR;
            goto done;
        }

        vcardproperty_kind kind = vcardproperty_string_to_kind(propname);
        vcardproperty *prop = vcardcomponent_get_first_property(vcard, kind);
        struct message_guid prop_guid = MESSAGE_GUID_INITIALIZER;

        if (!prop ||
            !vcard_prop_decode_value(prop, &ctx->blob, &mediatype, &prop_guid) ||
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

        /* The blobId encodes the guid of the whole vCard resource */
        if (!message_guid_equal(&guid, &record.guid)) {
            res = HTTP_NOT_FOUND;
            goto done;
        }

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

