/* http_dblookup.c -- Routines for dealing with HTTP based db lookups
 *
 * Copyright (c) 1994-2011 Carnegie Mellon University.  All rights reserved.
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


#include "carddav_db.h"
#include "http_dav.h"
#include "jmap_mail_query.h"
#include "json_support.h"
#include "spool.h"
#include "mboxlist.h"
#include "util.h"
#include "xstrlcpy.h"

/* generated headers are not necessarily in current directory */
#include "imap/http_err.h"

#include <jansson.h>

static int meth_get_db(struct transaction_t *txn, void *params);

/* Namespace for DB lookups */
// clang-format off
struct namespace_t namespace_dblookup = {
    URL_NS_DBLOOKUP, /*enabled*/1, "dblookup", "/dblookup", NULL,
    http_allow_noauth, /*authschemes*/0,
    /*mbtype*/0,
    ALLOW_READ,
    NULL, NULL, NULL, NULL, NULL,
    {
        { NULL,                 NULL },                 /* ACL          */
        { NULL,                 NULL },                 /* BIND         */
        { NULL,                 NULL },                 /* CONNECT      */
        { NULL,                 NULL },                 /* COPY         */
        { NULL,                 NULL },                 /* DELETE       */
        { &meth_get_db,         NULL },                 /* GET          */
        { NULL,                 NULL },                 /* HEAD         */
        { NULL,                 NULL },                 /* LOCK         */
        { NULL,                 NULL },                 /* MKCALENDAR   */
        { NULL,                 NULL },                 /* MKCOL        */
        { NULL,                 NULL },                 /* MOVE         */
        { NULL,                 NULL },                 /* OPTIONS      */
        { NULL,                 NULL },                 /* PATCH        */
        { NULL,                 NULL },                 /* POST         */
        { NULL,                 NULL },                 /* PROPFIND     */
        { NULL,                 NULL },                 /* PROPPATCH    */
        { NULL,                 NULL },                 /* PUT          */
        { NULL,                 NULL },                 /* REPORT       */
        { NULL,                 NULL },                 /* SEARCH       */
        { NULL,                 NULL },                 /* TRACE        */
        { NULL,                 NULL },                 /* UNBIND       */
        { NULL,                 NULL }                  /* UNLOCK       */
    }
};
// clang-format on

static int get_email(struct transaction_t *txn __attribute__((unused)),
                     const char *userid, const char *key)
{
    struct carddav_db *db = NULL;
    strarray_t *array = NULL;
    char *result = NULL;
    json_t *json;
    int ret = HTTP_NO_CONTENT;
    int i;

    /* XXX init just incase carddav not enabled? */
    db = carddav_open_userid(userid);
    if (!db) goto done;

    array = carddav_getemail_groups(db, key);
    if (!array) goto done;

    json = json_array();
    for (i = 0; i < strarray_size(array); i++) {
        json_array_append_new(json, json_string(strarray_nth(array, i)));
    }

    result = json_dumps(json, JSON_PRESERVE_ORDER|JSON_COMPACT);
    json_decref(json);

    txn->resp_body.type = "application/json";
    txn->resp_body.len = strlen(result);

    write_body(HTTP_OK, txn, result, txn->resp_body.len);
    ret = 0;

done:
    free(result);
    if (array) strarray_free(array);
    if (db) carddav_close(db);
    return ret;
}

static int get_email2uids(struct transaction_t *txn __attribute__((unused)),
                          const char *userid, const char *key)
{
    struct carddav_db *db = NULL;
    strarray_t *array = NULL;
    char *result = NULL;
    json_t *json;
    int ret = HTTP_NO_CONTENT;
    int i;
    char *mboxname = NULL;
    const char **mailboxhdrs;
    const char *mailbox = "Default";
    mbentry_t *mbentry = NULL;

    mailboxhdrs = spool_getheader(txn->req_hdrs, "Mailbox");
    if (mailboxhdrs) {
        mailbox = mailboxhdrs[0];
    }

    mboxname = mboxname_abook(userid, mailbox);
    if (!mboxname) goto done;

    mboxlist_lookup(mboxname, &mbentry, NULL);
    if (!mbentry) goto done;

    /* XXX init just incase carddav not enabled? */
    db = carddav_open_userid(userid);
    if (!db) goto done;

    array = carddav_getemail2details(db, key, mbentry, NULL);
    if (!array) goto done;

    json = json_array();
    for (i = 0; i < strarray_size(array); i++) {
        json_array_append_new(json, json_string(strarray_nth(array, i)));
    }

    result = json_dumps(json, JSON_PRESERVE_ORDER|JSON_COMPACT);
    json_decref(json);

    txn->resp_body.type = "application/json";
    txn->resp_body.len = strlen(result);

    write_body(HTTP_OK, txn, result, txn->resp_body.len);
    ret = 0;

done:
    free(mboxname);
    free(result);
    mboxlist_entry_free(&mbentry);
    if (array) strarray_free(array);
    if (db) carddav_close(db);
    return ret;
}

static int get_email2details(struct transaction_t *txn __attribute__((unused)),
                             const char *userid, const char *key)
{
    struct carddav_db *db = NULL;
    strarray_t *array = NULL;
    char *result = NULL;
    json_t *uids, *json;
    int ret = HTTP_NO_CONTENT;
    int i;
    char *mboxname = NULL;
    const char **mailboxhdrs;
    const char *mailbox = "Default";
    mbentry_t *mbentry = NULL;
    int ispinned = 0;

    mailboxhdrs = spool_getheader(txn->req_hdrs, "Mailbox");
    if (mailboxhdrs) {
        mailbox = mailboxhdrs[0];
    }

    mboxname = mboxname_abook(userid, mailbox);
    if (!mboxname) goto done;

    mboxlist_lookup(mboxname, &mbentry, NULL);
    if (!mbentry) goto done;

    /* XXX init just incase carddav not enabled? */
    db = carddav_open_userid(userid);
    if (!db) goto done;

    array = carddav_getemail2details(db, key, mbentry, &ispinned);
    if (!array) goto done;

    uids = json_array();
    for (i = 0; i < strarray_size(array); i++) {
        json_array_append_new(uids, json_string(strarray_nth(array, i)));
    }

    json = json_pack("{s:o s:b}", "uids", uids, "isPinned", ispinned);

    result = json_dumps(json, JSON_PRESERVE_ORDER|JSON_COMPACT);
    json_decref(json);

    txn->resp_body.type = "application/json";
    txn->resp_body.len = strlen(result);

    write_body(HTTP_OK, txn, result, txn->resp_body.len);
    ret = 0;

done:
    free(mboxname);
    free(result);
    mboxlist_entry_free(&mbentry);
    if (array) strarray_free(array);
    if (db) carddav_close(db);
    return ret;
}

static int get_uid2groups(struct transaction_t *txn,
                          const char *userid, const char *key)
{
    struct carddav_db *db = NULL;
    strarray_t *array = NULL;
    char *result = NULL;
    json_t *json;
    int ret = HTTP_NO_CONTENT;
    int i;
    char *mboxname = NULL;
    const char **otheruserhdrs;
    const char *otheruser = "";
    const char **mailboxhdrs;
    const char *mailbox = "Default";
    mbentry_t *mbentry = NULL;
    ptrarray_t *abook_sets = NULL;
    struct auth_state *authstate = auth_newstate(userid);

    if (!authstate) goto done;

    otheruserhdrs = spool_getheader(txn->req_hdrs, "OtherUser");
    if (otheruserhdrs) {
        otheruser = otheruserhdrs[0];
    }

    mailboxhdrs = spool_getheader(txn->req_hdrs, "Mailbox");
    if (mailboxhdrs) {
        mailbox = mailboxhdrs[0];
    }

    mboxname = mboxname_abook(userid, mailbox);
    if (!mboxname) goto done;

    mboxlist_lookup(mboxname, &mbentry, NULL);
    if (!mbentry) goto done;

    /* Open DAV DB for the specified user.
     * It will be assigned to an abook_set in jmap_get_accessible_addressbooks()
     * and closed in jmap_free_abook_sets().
     */
    db = carddav_open_userid(userid);
    if (!db) goto done;

    abook_sets = jmap_get_accessible_addressbooks(userid, authstate,
                                                  &httpd_namespace, db);
    struct abook_set *user_set = NULL;
    struct carddav_data *cdata = NULL;
    int is_accessible = 0;

    if (!*otheruser) {
        /* Addressbook set for User */
        user_set = ptrarray_nth(abook_sets, 0);
    }
    else {
        /* Find addressbook set for OtherUser */
        for (int i = 1; i < ptrarray_size(abook_sets); i++) {
            struct abook_set *set = ptrarray_nth(abook_sets, i);

            if (!strcmp(otheruser, set->userid)) {
                user_set = set;
                break;
            }
        }
    }

    /* Verify that the member UID exists in an accessible addressbook */
    if (user_set && user_set->carddavdb &&
        !carddav_lookup_uid(user_set->carddavdb, NULL, key, &cdata) &&
        cdata && cdata->dav.imap_uid) {
        for (int i = 0; i < ptrarray_size(&user_set->mbentrys); i++) {
            mbentry_t *mbentry = ptrarray_nth(&user_set->mbentrys, i);

            if (!mbentry ||  // ANY addressbook of User
                !strcmp(cdata->dav.mailbox, mbentry->uniqueid)) {
                is_accessible = 1;
                break;
            }
        }
    }

    if (is_accessible) {
        array = carddav_getuid2groups(db, key, mbentry, otheruser);
        if (!array) goto done;
    }

    json = json_object();
    for (i = 0; i < strarray_size(array); i += 2) {
        json_object_set_new(json, strarray_nth(array, i), json_string(strarray_nth(array, i+1)));
    }

    result = json_dumps(json, JSON_PRESERVE_ORDER|JSON_COMPACT);
    json_decref(json);

    txn->resp_body.type = "application/json";
    txn->resp_body.len = strlen(result);

    write_body(HTTP_OK, txn, result, txn->resp_body.len);
    ret = 0;

done:
    free(mboxname);
    free(result);
    mboxlist_entry_free(&mbentry);
    if (array) strarray_free(array);
    if (authstate) auth_freestate(authstate);
    if (abook_sets) jmap_free_abook_sets(abook_sets);
    return ret;
}

struct get_cards_rock {
    hash_table *cards_by_uid;
    const char *group_uid;
    strarray_t *member_uids;
    struct abook_set *abook_set;
};

static int _get_cards_cb(void *rock, struct carddav_data *cdata)
{
    struct get_cards_rock *grock = rock;

    if (!hash_lookup(cdata->vcard_uid, grock->cards_by_uid)) {
        hash_insert(cdata->vcard_uid, grock->abook_set, grock->cards_by_uid);
    }

    if (cdata->kind == CARDDAV_KIND_GROUP &&
        !strcmp(cdata->vcard_uid, grock->group_uid)) {

        if (!grock->member_uids) {
            carddav_getmembers(grock->abook_set->carddavdb, NULL,
                               grock->group_uid, &grock->member_uids);
        }
    }

    return 0;
}

static int get_expandcard(struct transaction_t *txn,
                          const char *userid, const char *uid)
{
    struct auth_state *authstate = auth_newstate(userid);
    hash_table uid_to_userid = HASH_TABLE_INITIALIZER;
    ptrarray_t *abook_sets = NULL;
    int ret = HTTP_NO_CONTENT;

    if (!authstate) goto done;

    /* Open DAV DB for the specified user.
     * It will be assigned to an abook_set in jmap_get_accessible_addressbooks()
     * and closed in jmap_free_abook_sets().
     */
    struct carddav_db *carddavdb = carddav_open_userid(userid);
    if (!carddavdb) goto done;

    abook_sets = jmap_get_accessible_addressbooks(userid, authstate,
                                                  &httpd_namespace, carddavdb);

    construct_hash_table(&uid_to_userid, 1024 * ptrarray_size(abook_sets), 0);

    struct get_cards_rock grock = { &uid_to_userid, uid, NULL, NULL };

    /* Fetch all cards from each addressbook in each set.
       Also, get members in the specified group card */
    for (int i = 0; i < ptrarray_size(abook_sets); i++) {
        struct abook_set *set = ptrarray_nth(abook_sets, i);

        if (set->carddavdb) {
            grock.abook_set = set;

            for (int j = 0; j < ptrarray_size(&set->mbentrys); j++) {
                mbentry_t *mbentry = ptrarray_nth(&set->mbentrys, j);

                carddav_foreach(set->carddavdb, mbentry, &_get_cards_cb, &grock);
            }
        }
    }

    struct abook_set *abook_set = hash_lookup(uid, &uid_to_userid);
    if (!abook_set) goto done;

    /* Lookup preferred email and build response */
    json_t *jres = json_object();
    json_t *uids = json_object_get_vanew(jres, abook_set->userid, "{}");
    strarray_t emails = STRARRAY_INITIALIZER;

    carddav_getemails_pref(abook_set->carddavdb, NULL,
                           uid, CARDDAV_KIND_ANY, &emails);

    json_object_set_new(uids, uid, json_pack("s?", strarray_nth(&emails, 0)));
    strarray_fini(&emails);

    /* Lookup group members and add preferred emails to response */
    for (int i = 0; i < strarray_size(grock.member_uids); i++) {
        const char *member = strarray_nth(grock.member_uids, i);

        abook_set = hash_lookup(member, &uid_to_userid);

        if (abook_set) {
            uids = json_object_get_vanew(jres, abook_set->userid, "{}");

            carddav_getemails_pref(abook_set->carddavdb, NULL,
                                   member, CARDDAV_KIND_ANY, &emails);

            json_object_set_new(uids, member,
                                json_pack("s?", strarray_nth(&emails, 0)));
            strarray_fini(&emails);
        }
    }

    strarray_free(grock.member_uids);

    char *res = json_dumps(jres, JSON_PRESERVE_ORDER|JSON_COMPACT);
    json_decref(jres);

    txn->resp_body.type = "application/json";
    txn->resp_body.len = strlen(res);

    write_body(HTTP_OK, txn, res, txn->resp_body.len);
    free(res);
    ret = 0;

done:
    if (authstate) auth_freestate(authstate);
    if (abook_sets) jmap_free_abook_sets(abook_sets);
    free_hash_table(&uid_to_userid, NULL);

    return ret;
}

static int get_mbpath(struct transaction_t *txn __attribute__((unused)),
                      const char *userid, const char *key)
{
    mbname_t *mbname = NULL;
    if (!strcasecmp(key, "mboxname")) {
        mbname = mbname_from_extname(userid, &httpd_namespace, "cyrus");
    }
    else {
        mbname = mbname_from_userid(userid);
    }
    if (!mbname) return HTTP_NOT_FOUND;

    mbentry_t *mbentry = NULL;
    int r = mboxlist_lookup(mbname_intname(mbname), &mbentry, NULL);
    mbname_free(&mbname);
    if (r) return HTTP_NOT_FOUND;

    json_t *jres = mbentry_paths_json(mbentry);
    mboxlist_entry_free(&mbentry);

    char *result = json_dumps(jres, JSON_INDENT(2)|JSON_SORT_KEYS);
    json_decref(jres);

    txn->resp_body.type = "application/json";
    txn->resp_body.len = strlen(result);
    write_body(HTTP_OK, txn, result, txn->resp_body.len);

    free(result);
    return 0;
}

static int meth_get_db(struct transaction_t *txn,
                       void *params __attribute__((unused)))
{
    const char **userhdrs;
    const char **keyhdrs;

    userhdrs = spool_getheader(txn->req_hdrs, "User");
    keyhdrs = spool_getheader(txn->req_hdrs, "Key");

    if (!userhdrs) return HTTP_BAD_REQUEST;
    if (!keyhdrs) return HTTP_BAD_REQUEST;

    if (userhdrs[1]) return HTTP_NOT_ALLOWED;
    if (keyhdrs[1]) return HTTP_NOT_ALLOWED;

    spool_cache_header(xstrdup(":dblookup"),
                      strconcat(userhdrs[0], "/", keyhdrs[0], (char *)NULL),
                      txn->req_hdrs);


    if (!strcmp(txn->req_uri->path, "/dblookup/email"))
        return get_email(txn, userhdrs[0], keyhdrs[0]);

    if (!strcmp(txn->req_uri->path, "/dblookup/email2uids"))
        return get_email2uids(txn, userhdrs[0], keyhdrs[0]);

    if (!strcmp(txn->req_uri->path, "/dblookup/email2details"))
        return get_email2details(txn, userhdrs[0], keyhdrs[0]);

    if (!strcmp(txn->req_uri->path, "/dblookup/uid2groups"))
        return get_uid2groups(txn, userhdrs[0], keyhdrs[0]);

    if (!strcmp(txn->req_uri->path, "/dblookup/expandcard"))
        return get_expandcard(txn, userhdrs[0], keyhdrs[0]);

    if (!strcmp(txn->req_uri->path, "/dblookup/mbpath"))
        return get_mbpath(txn, userhdrs[0], keyhdrs[0]);

    return HTTP_NOT_FOUND;
}
