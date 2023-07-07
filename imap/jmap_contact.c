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
#include "http_jmap.h"
#include "json_support.h"
#include "mailbox.h"
#include "mboxname.h"
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

static int jmap_addressbook_get(struct jmap_req *req);
static int jmap_addressbook_changes(struct jmap_req *req);
static int jmap_addressbook_set(struct jmap_req *req);
static int jmap_card_changes(struct jmap_req *req);
static int jmap_cardgroup_changes(struct jmap_req *req);

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

static int _contact_set_create(jmap_req_t *req, unsigned kind,
                               json_t *jcard, struct carddav_data *cdata,
                               struct mailbox **mailbox, json_t *item,
                               jmap_contact_errors_t *errors);
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

#define JMAPCACHE_CONTACTVERSION 1

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
        "Card/changes",
        JMAP_URN_CONTACTS,
        &jmap_card_changes,
        JMAP_NEED_CSTATE
    },
    {
        "CardGroup/changes",
        JMAP_URN_CONTACTS,
        &jmap_cardgroup_changes,
        JMAP_NEED_CSTATE
    },
    { NULL, NULL, NULL, 0}
};

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
        JMAP_NEED_CSTATE | JMAP_READ_WRITE
    },
    { NULL, NULL, NULL, 0}
};

static char *_prodid = NULL;

HIDDEN void jmap_contact_init(jmap_settings_t *settings)
{
    jmap_method_t *mp;
    for (mp = jmap_contact_methods_standard; mp->name; mp++) {
        hash_insert(mp->name, mp, &settings->methods);
    }

    json_object_set_new(settings->server_capabilities,
            JMAP_URN_CONTACTS, json_object());

    if (config_getswitch(IMAPOPT_JMAP_NONSTANDARD_EXTENSIONS)) {
        json_object_set_new(settings->server_capabilities,
                JMAP_CONTACTS_EXTENSION, json_object());

        for (mp = jmap_contact_methods_nonstandard; mp->name; mp++) {
            hash_insert(mp->name, mp, &settings->methods);
        }
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
        return;
    }
    int rights = httpd_myrights(authstate, mbentry);
    int is_main_account = !strcmpsafe(authuserid, accountid);

    json_object_set_new(account_capabilities, JMAP_URN_CONTACTS,
                        json_pack("{s:b}", "mayCreateAddressBook",
                                  is_main_account || (rights & JACL_CREATECHILD)));

    if (config_getswitch(IMAPOPT_JMAP_NONSTANDARD_EXTENSIONS)) {
        json_object_set_new(account_capabilities, JMAP_CONTACTS_EXTENSION, json_object());
    }
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

    if (jmap_wantprop(rock->get->props, "x-href")) {
        // XXX - should the x-ref for a shared addressbook point
        // to the authenticated user's addressbook home?
        char *xhref = jmap_xhref(mbentry->name, NULL);
        json_object_set_new(obj, "x-href", json_string(xhref));
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
        "x-href",
        JMAP_DEBUG_EXTENSION,
        JMAP_PROP_SERVER_SET
    },

    { NULL, NULL, 0 }
};

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

            if (mbentry) mboxlist_entry_free(&mbentry);
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

    r = jmap_openmbox(req, mboxname, &mbox, 1);
    if (r) {
        syslog(LOG_ERR, "jmap_openmbox(req, %s) failed: %s",
                mboxname, error_message(r));
        return r;
    }

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
        r = jmap_set_sharewith(mbox, props->share.With,
                props->share.overwrite_acl, addressbook_sharewith_to_rights);
    }

    buf_free(&val);
    if (mbox) {
        if (r) mailbox_abort(mbox);
        jmap_closembox(req, &mbox);
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
    mboxlist_changesub(mboxname, req->userid, req->authstate, 0, 1, 0);

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
 * JMAP Contacts API
 ****************************************************************************/

struct cards_rock {
    struct carddav_db *db;
    struct jmap_req *req;
    struct jmap_get *get;
    struct mailbox *mailbox;
    mbentry_t *mbentry;
    hashu64_table jmapcache;
    int rows;
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

    if (cdata->jmapversion == JMAPCACHE_CONTACTVERSION) {
        json_error_t jerr;
        obj = json_loads(cdata->jmapdata, 0, &jerr);
        if (obj) goto gotvalue;
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

    hashu64_insert(cdata->dav.rowid, json_dumps(obj, 0), &crock->jmapcache);

gotvalue:

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

static int _contact_getargs_parse(jmap_req_t *req __attribute__((unused)),
                                  struct jmap_parser *parser __attribute__((unused)),
                                  const char *key,
                                  json_t *arg,
                                  void *rock)
{
    const char **addressbookId = (const char **) rock;
    int r = 1;

    /* Non-JMAP spec addressbookId argument */
    if (!strcmp(key, "addressbookId") && json_is_string(arg)) {
        *addressbookId = json_string_value(arg);
    }

    else r = 0;

    return r;
}

static void cachecards_cb(uint64_t rowid, void *payload, void *vrock)
{
    const char *eventrep = payload;
    struct cards_rock *rock = vrock;

    // there's no way to return errors, but luckily it doesn't matter if we
    // fail to cache
    carddav_write_jmapcache(rock->db, rowid,
                            JMAPCACHE_CONTACTVERSION, eventrep);
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
    struct cards_rock rock = { NULL, req, &get, NULL /*mailbox*/, NULL /*mbentry*/,
                               HASHU64_TABLE_INITIALIZER, 0 /*rows */ };

    construct_hashu64_table(&rock.jmapcache, 512, 0);

    /* Parse request */
    const char *addressbookId = NULL;
    jmap_get_parse(req, &parser, props, /* allow_null_ids */ 1,
                   &_contact_getargs_parse, &addressbookId, &get, &err);
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

    if (addressbookId) {
        char *mboxname = carddav_mboxname(req->accountid, addressbookId);
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

            r = carddav_get_cards(db, mbentry, id, kind, cb, &rock);
            if (r || !rock.rows) {
                json_array_append(get.not_found, jval);
            }
            r = 0; // we don't ever fail the whole request from this
        }
    }
    else {
        rock.rows = 0;
        r = carddav_get_cards(db, mbentry, NULL, kind, cb, &rock);
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
    const char *addressbookId = NULL;
    jmap_changes_parse(req, &parser, req->counters.carddavdeletedmodseq,
                       &_contact_getargs_parse, &addressbookId, &changes, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    if (addressbookId) {
        char *mboxname = carddav_mboxname(req->accountid, addressbookId);
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
        buf_setcstr(&buf, "urn:uuid:");
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

static void _contacts_set(struct jmap_req *req, unsigned kind)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_set set;
    json_t *err = NULL;
    int r = 0;

    struct mailbox *mailbox = NULL;
    struct mailbox *newmailbox = NULL;

    struct carddav_db *db = carddav_open_userid(req->accountid);
    if (!db) {
        r = IMAP_INTERNAL;
        goto done;
    }

    /* Parse arguments */
    jmap_set_parse(req, &parser,
                   kind == CARDDAV_KIND_GROUP ? group_props : contact_props,
                   NULL, NULL, &set, &err);
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
        r = _contact_set_create(req, kind, arg,
                                NULL, &mailbox, item, &errors);
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
    struct buf buf = BUF_INITIALIZER;
    const char *uid;
    json_object_foreach(set.update, uid, arg) {
        mbentry_t *mbentry = NULL;
        struct carddav_data *cdata = NULL;
        r = carddav_lookup_uid(db, uid, &cdata);
        uint32_t olduid;
        char *resource = NULL;
        int do_move = 0;
        json_t *jupdated = NULL;

        /* is it a valid contact? */
        if (r || !cdata || !cdata->dav.imap_uid || cdata->kind != kind) {
            r = 0;
            json_t *err = json_pack("{s:s}", "type", "notFound");
            json_object_set_new(set.not_updated, uid, err);
            continue;
        }

        mbentry = jmap_mbentry_from_dav(req, &cdata->dav);

        json_t *abookid = json_object_get(arg, "addressbookId");
        if (abookid && json_string_value(abookid)) {
            const char *mboxname =
                mboxname_abook(req->accountid, json_string_value(abookid));
            if (mbentry && strcmp(mboxname, mbentry->name)) {
                /* move */
                if (!jmap_hasrights(req, mboxname, JACL_ADDITEMS)) {
                    json_t *err = json_pack("{s:s s:[s]}",
                                            "type", "invalidProperties",
                                            "properties", "addressbookId");
                    json_object_set_new(set.not_updated, uid, err);
                    mboxlist_entry_free(&mbentry);
                    continue;
                }
                r = jmap_openmbox(req, mboxname, &newmailbox, 1);
                if (r) {
                    syslog(LOG_ERR, "IOERROR: failed to open %s", mboxname);
                    mboxlist_entry_free(&mbentry);
                    goto done;
                }
                do_move = 1;
            }
            json_object_del(arg, "addressbookId");
        }

        int needrights = do_move ? JACL_UPDATEITEMS : required_set_rights(arg);

        if (!mbentry || !jmap_hasrights_mbentry(req, mbentry, needrights)) {
            int rights = mbentry ? jmap_myrights_mbentry(req, mbentry) : 0;
            json_t *err = json_pack("{s:s}", "type",
                                    rights & JACL_READITEMS ?
                                    "accountReadOnly" : "notFound");
            json_object_set_new(set.not_updated, uid, err);
            mboxlist_entry_free(&mbentry);
            continue;
        }

        if (!mailbox || strcmp(mailbox_name(mailbox), mbentry->name)) {
            jmap_closembox(req, &mailbox);
            r = jmap_openmbox(req, mbentry->name, &mailbox, 1);
        }
        mboxlist_entry_free(&mbentry);
        if (r) {
            syslog(LOG_ERR, "IOERROR: failed to open %s",
                   mbentry->name);
            goto done;
        }

        struct index_record record;

        r = mailbox_find_index_record(mailbox, cdata->dav.imap_uid, &record);
        if (r) goto done;

        olduid = cdata->dav.imap_uid;
        resource = xstrdup(cdata->dav.resource);

        struct entryattlist *annots = NULL;
        strarray_t *flags = NULL;

        json_t *item = json_object();
        json_t *invalid = json_array();
        jmap_contact_errors_t errors = { invalid, NULL };
        ptrarray_t blobs = PTRARRAY_INITIALIZER;
        property_blob_t *blob;

        /* Load message containing the resource and parse vcard data */
        struct vparse_card *vcard = record_to_vcard(mailbox, &record);
        if (!vcard || !vcard->objects) {
            syslog(LOG_ERR, "record_to_vcard failed for record %u:%s",
                   cdata->dav.imap_uid, mailbox_name(mailbox));
            r = 0;
            json_t *err = json_pack("{s:s}", "type", "parseError");
            json_object_set_new(set.not_updated, uid, err);
            goto finish;
        }

        struct vparse_card *card = vcard->objects;
        if (!vparse_get_entry(card, NULL, "VERSION"))
            vparse_replace_entry(card, NULL, "VERSION", "3.0");
        vparse_replace_entry(card, NULL, "PRODID", _prodid);

        if (kind == CARDDAV_KIND_GROUP) {
            json_t *namep = NULL;
            json_t *members = NULL;
            json_t *others = NULL;
            json_t *jval;
            const char *key;

            json_object_foreach(arg, key, jval) {
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
                                cdata->dav.imap_uid, mailbox_name(mailbox));
                        r = 0;
                        json_t *err = json_pack("{s:s s:s}",
                                "type", "serverError", "description", "invalid current card");
                        json_object_set_new(set.not_updated, uid, err);
                        goto finish;
                    }
                    jupdated = jmap_patchobject_apply(jcurrent, arg, NULL);
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
            flags = mailbox_extract_flags(mailbox, &record, req->userid);
            annots = mailbox_extract_annots(mailbox, &record);

            r = _json_to_card(req, cdata, mailbox_name(mailbox), card, arg, flags,
                    &annots, &blobs, &errors);
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
                                            req->userid, req->authstate);
                    if (!r) r = annotate_state_store(state, annots);
                    if (!r) r = mailbox_rewrite_index_record(mailbox, &record);
                    if (!r) json_object_set_new(set.updated, uid, json_null());
                    goto finish;
                }
            }
        }

        if (!r && !json_array_size(invalid) && !errors.blobNotFound) {
            struct mailbox *this_mailbox = newmailbox ? newmailbox : mailbox;

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

                jmap_encode_rawdata_blobid('V', mailbox_uniqueid(this_mailbox), record.uid,
                                           NULL, NULL, NULL, NULL, &buf);
                json_object_set_new(item, "blobId",
                                    json_string(buf_cstring(&buf)));

                json_object_set_new(item, "size",
                                    json_integer(record.size - record.header_size));

                while ((blob = ptrarray_pop(&blobs))) {
                    jmap_encode_rawdata_blobid('V', mailbox_uniqueid(this_mailbox), record.uid,
                                               NULL, NULL, blob->prop, &blob->guid, &buf);
                    json_object_set_new(item, blob->key,
                                        json_pack("{s:s s:i s:s? s:n}",
                                                  "blobId", buf_cstring(&buf),
                                                  "size", blob->size,
                                                  "type", blob->type, "name"));
                    property_blob_free(&blob);
                }

                r = carddav_remove(mailbox, olduid,
                                   /*isreplace*/!newmailbox, req->userid);
            }
        }

        if (json_array_size(invalid)) {
            json_t *err = json_pack("{s:s s:O}",
                                    "type", "invalidProperties",
                                    "properties", invalid);
            json_object_set_new(set.not_updated, uid, err);
            goto finish;
        }
        else if (errors.blobNotFound) {
            json_t *err = json_pack("{s:s s:O}",
                                    "type", "blobNotFound",
                                    "notFound", errors.blobNotFound);
            json_object_set_new(set.not_updated, uid, err);
            goto finish;
        }
        else if (r) {
            json_t *err = NULL;
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
            json_object_set_new(set.not_updated, uid, err);
            goto finish;
        }
        else json_object_set(set.updated, uid, item);

      finish:
        strarray_free(flags);
        freeentryatts(annots);
        jmap_closembox(req, &newmailbox);
        vparse_free_card(vcard);
        free(resource);
        json_decref(jupdated);
        json_decref(invalid);
        json_decref(errors.blobNotFound);
        json_decref(item);
        while ((blob = ptrarray_pop(&blobs))) {
            property_blob_free(&blob);
        }
        ptrarray_fini(&blobs);
        r = 0;
    }
    buf_free(&buf);


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
        if (r || !cdata || !cdata->dav.imap_uid || cdata->kind != kind) {
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
            jmap_closembox(req, &mailbox);
            r = jmap_openmbox(req, mbentry->name, &mailbox, 1);
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
    jmap_closembox(req, &newmailbox);
    jmap_closembox(req, &mailbox);

    carddav_close(db);
}

static int jmap_contactgroup_set(struct jmap_req *req)
{
    _contacts_set(req, CARDDAV_KIND_GROUP);
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
    construct_hash_table(&labels, 10, 0);
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

            /* Read countryCode from same-grouped ABADR property, if any */
            const char *countrycode = NULL;
            if (entry->group) {
                // O(n^2) n is the (presumably small) count of VCARD props
                struct vparse_entry *iter;
                for (iter = card->properties; iter; iter = iter->next) {
                    if (!strcasecmpsafe(iter->group, entry->group) &&
                            !strcasecmp(iter->name, VCARD_APPLE_ABADR_PROPERTY)) {
                        countrycode = iter->v.value;
                        break;
                    }
                }
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

    return obj;
}

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
    if ((r = jmap_openmbox(req, mbentry->name, &mailbox, 0))) {
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
    if (mailbox) jmap_closembox(req, &mailbox);
    mboxlist_entry_free(&freeme);
    free(mboxid);
    free(prop);
    free(mediatype);
    return res;
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

    if (cdata->jmapversion == JMAPCACHE_CONTACTVERSION) {
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

gotvalue:


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

enum contactsquery_sort *buildsort(json_t *jsort)
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

static int _contactsquery_cmp QSORT_R_COMPAR_ARGS(const void *va,
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

static int _contactsquery(struct jmap_req *req, unsigned kind)
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
                     kind == CARDDAV_KIND_GROUP ?
                        contactgroup_filter_validate :
                        contact_filter_validate,
                     NULL,
                     kind == CARDDAV_KIND_GROUP ?
                        contactgroup_comparator_validate :
                        contact_comparator_validate,
                     NULL,
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
        parsed_filter = jmap_buildfilter(filter,
                kind == CARDDAV_KIND_GROUP ?
                    contactgroup_filter_parse : contact_filter_parse);
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
        if (!r) _contactsquery_cb(&rock, cdata);
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
        r = carddav_foreach_sort(db, NULL, &sort, nsort, _contactsquery_cb, &rock);
    }
    else {
        /* Run carddav db query and apply custom sort */
        rock.build_response = 0;
        r = carddav_foreach(db, NULL, _contactsquery_cb, &rock);
        if (!r) {
            /* Sort entries */
            enum contactsquery_sort *sort = buildsort(query.sort);
            cyr_qsort_r(rock.entries.data, rock.entries.count, sizeof(void*),
                        _contactsquery_cmp, sort);
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
        jmap_filter_free(parsed_filter, kind == CARDDAV_KIND_GROUP ?
            contactgroup_filter_free : contact_filter_free);
    }
    if (db) carddav_close(db);
    return 0;
}

static int jmap_contact_query(struct jmap_req *req)
{
    return _contactsquery(req, CARDDAV_KIND_CONTACT);
}

static int jmap_contactgroup_query(struct jmap_req *req)
{
    return _contactsquery(req, CARDDAV_KIND_GROUP);
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

    base = buf_base(&ctx.blob);
    len = buf_len(&ctx.blob);

    /* Pre-flight base64 encoder to determine length */
    size_t len64 = 0;
    charset_encode_mimebody(NULL, len, NULL, &len64, NULL, 0 /* no wrap */);

    /* Now encode the blob */
    encbuf = xzmalloc(len64+1);
    charset_encode_mimebody(base, len, encbuf, &len64, NULL, 0 /* no wrap */);
    base = encbuf;

    /* (Re)write vCard property */
    vparse_delete_entries(card, NULL, prop);

    struct vparse_entry *entry = vparse_add_entry(card, NULL, prop, base);

    vparse_add_param(entry, "ENCODING", "b");

    if (buf_len(&ctx.content_type)) {
        char *subtype = xstrdupnull(strchr(buf_cstring(&ctx.content_type), '/'));
        vparse_add_param(entry, "TYPE", ucase(subtype+1));
        free(subtype);
    }

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
        else {
            json_array_append_new(invalid, json_string(key));
        }
    }

    if (json_array_size(invalid) || errors->blobNotFound) return -1;

    if (name_is_dirty) {
        _make_fn(card);
        record_is_dirty = 1;
    }

    if (!record_is_dirty && has_noncontent)
        return HTTP_NO_CONTENT;  /* no content */

    return 0;
}

static int required_set_rights(json_t *props)
{
    int needrights = 0;
    const char *name;
    json_t *val;

    json_object_foreach(props, name, val) {
        if (!strcmp(name, "id") ||
            !strcmp(name, "x-href") ||
            !strcmp(name, "x-hasPhoto") ||
            !strcmp(name, "addressbookId")) {
            /* immutable */
        }
        else if (!strcmp(name, "importance")) {
            /* writing shared meta-data (per RFC 5257) */
            needrights |= JACL_SETPROPERTIES;
        }
        else if (!strcmp(name, "isFlagged")) {
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

static int _contact_set_create(jmap_req_t *req, unsigned kind,
                               json_t *jcard, struct carddav_data *cdata,
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
        jmap_closembox(req, mailbox);
        r = jmap_openmbox(req, mboxname, mailbox, 1);
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
        r = _json_to_card(req, cdata, mboxname, card, jcard, flags, &annots, &blobs, errors);

        logfmt = "jmap: create contact %s/%s (%s)";
    }

    if (r || json_array_size(invalid) || errors->blobNotFound) {
        r = 0;
        goto done;
    }

    syslog(LOG_NOTICE, logfmt, req->accountid, mboxname, uid, name);
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

static int jmap_contact_set(struct jmap_req *req)
{
    _contacts_set(req, CARDDAV_KIND_CONTACT);
    return 0;
}

static void _contact_copy(jmap_req_t *req,
                          json_t *jcard,
                          struct carddav_db *src_db,
                          json_t **new_card,
                          json_t **set_err)
{
    struct jmap_parser myparser = JMAP_PARSER_INITIALIZER;
    struct vparse_card *vcard = NULL;
    json_t *dst_card = NULL;
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
    r = jmap_openmbox(req, mbentry->name, &src_mbox, /*rw*/0);
    if (r) goto done;

    struct index_record record;
    r = mailbox_find_index_record(src_mbox, cdata->dav.imap_uid, &record);
    if (!r) vcard = record_to_vcard(src_mbox, &record);
    if (!vcard || !vcard->objects) {
        syslog(LOG_ERR, "contact_copy: can't convert %s to JMAP", src_id);
        r = IMAP_INTERNAL;
        goto done;
    }

    /* Patch JMAP event */
    json_t *src_card = jmap_contact_from_vcard(req->userid, vcard->objects,
                                               src_mbox, &record);
    if (src_card) {
        json_t *avatar = json_object_get(src_card, "avatar");
        if (avatar) {
            /* _blob_to_card() needs to know in which account to find blob */
            json_object_set(avatar, "accountId",
                            json_object_get(req->args, "fromAccountId"));
        }
        json_object_del(src_card, "x-href");  // immutable and WILL change
        json_object_del(src_card, "x-hasPhoto");  // immutable and WILL change
        dst_card = jmap_patchobject_apply(src_card, jcard, NULL);
        json_object_del(dst_card, "id");  // immutable and WILL change
    }
    json_decref(src_card);

    /* Create vcard */
    json_t *invalid = json_array();
    jmap_contact_errors_t errors = { invalid, NULL };
    json_t *item = json_object();
    r = _contact_set_create(req, CARDDAV_KIND_CONTACT, dst_card,
                            NULL, &dst_mbox, item, &errors);
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
    jmap_closembox(req, &dst_mbox);
    jmap_closembox(req, &src_mbox);
    if (vcard) vparse_free_card(vcard);
    json_decref(dst_card);
    jmap_parser_fini(&myparser);
}

static int jmap_contact_copy(struct jmap_req *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_copy copy;
    json_t *err = NULL;
    struct carddav_db *src_db = NULL;
    json_t *destroy_cards = json_array();

    /* Parse request */
    jmap_copy_parse(req, &parser, NULL, NULL, &copy, &err);
    if (err) {
        jmap_error(req, err);
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

        _contact_copy(req, jcard, src_db, /*dst_db,*/ &new_card, &set_err);
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
    jmap_ok(req, jmap_copy_reply(&copy));

    /* Destroy originals, if requested */
    if (copy.on_success_destroy_original && json_array_size(destroy_cards)) {
        json_t *subargs = json_object();
        json_object_set(subargs, "destroy", destroy_cards);
        json_object_set_new(subargs, "accountId", json_string(copy.from_account_id));
        jmap_add_subreq(req, "Contact/set", subargs, NULL);
    }

done:
    json_decref(destroy_cards);
    if (src_db) carddav_close(src_db);
    jmap_parser_fini(&parser);
    jmap_copy_fini(&copy);
    return 0;
}

static int jmap_card_changes(struct jmap_req *req)
{
    return _contacts_changes(req, CARDDAV_KIND_CONTACT);
}

static int jmap_cardgroup_changes(struct jmap_req *req)
{
    return _contacts_changes(req, CARDDAV_KIND_GROUP);
}
