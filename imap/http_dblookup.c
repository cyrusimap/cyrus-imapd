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
#include "pushsub_db.h"
#include "spool.h"
#include "util.h"
#include "xstrlcpy.h"

/* generated headers are not necessarily in current directory */
#include "imap/http_err.h"

#include <jansson.h>

static int meth_get_db(struct transaction_t *txn, void *params);

/* Namespace for DB lookups */
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

    array = carddav_getemail(db, key);
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

    /* XXX init just incase carddav not enabled? */
    db = carddav_open_userid(userid);
    if (!db) goto done;

    array = carddav_getuid2groups(db, key, mbentry, otheruser);
    if (!array) goto done;

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
    if (db) carddav_close(db);
    return ret;
}

static int get_pushsub(void *rock, struct pushsub_data *data)
{
    json_t *array = (json_t *) rock;
    json_t *obj;
    json_error_t jerr;

    obj = json_loads(data->subscription, 0, &jerr);
    json_object_set_new(obj, "isVerified", json_boolean(data->isverified));

    json_array_append_new(array, obj);

    return 0;
}

static int get_pushsubs(struct transaction_t *txn __attribute__((unused)),
                        const char *userid, const char *key __attribute__((unused)))
{
    struct pushsub_db *db = NULL;
    char *result = NULL;
    json_t *json;
    int ret = HTTP_NO_CONTENT;

    db = pushsubdb_open_userid(userid);
    if (!db) goto done;

    json = json_array();
    pushsubdb_foreach(db, &get_pushsub, json);
    result = json_dumps(json, JSON_PRESERVE_ORDER|JSON_COMPACT);
    json_decref(json);

    txn->resp_body.type = "application/json";
    txn->resp_body.len = strlen(result);

    write_body(HTTP_OK, txn, result, txn->resp_body.len);
    ret = 0;

done:
    free(result);
    if (db) pushsubdb_close(db);
    return ret;
}

struct lookup_type_t {
    const char *path;
    int (*cb)(struct transaction_t *txn, const char *userid, const char *key);
    unsigned key_required : 1;
};

static const struct lookup_type_t lookup_types[] = {
    { "/email",         &get_email,         1 },
    { "/email2uids",    &get_email2uids,    1 },
    { "/email2details", &get_email2details, 1 },
    { "/uid2groups",    &get_uid2groups,    1 },
    { "/pushsubs",      &get_pushsubs,      0 },
    { NULL,             NULL,               0 }
};

static int meth_get_db(struct transaction_t *txn,
                       void *params __attribute__((unused)))
{
    const char **userhdrs;
    const char **keyhdrs = NULL;
    const char *req_path = txn->req_uri->path + 9;
    const struct lookup_type_t *ltype;
    struct buf buf = BUF_INITIALIZER;

    /* Find our lookup type */
    for (ltype = lookup_types; ltype->cb && strcmp(req_path, ltype->path); ltype++);

    if (!ltype->cb) return HTTP_NOT_FOUND;

    userhdrs = spool_getheader(txn->req_hdrs, "User");

    if (!userhdrs) return HTTP_BAD_REQUEST;
    if (userhdrs[1]) return HTTP_NOT_ALLOWED;

    buf_setcstr(&buf, userhdrs[0]);

    if (ltype->key_required) {
        keyhdrs = spool_getheader(txn->req_hdrs, "Key");

        if (!keyhdrs) return HTTP_BAD_REQUEST;
        if (keyhdrs[1]) return HTTP_NOT_ALLOWED;

        buf_printf(&buf, "/%s", keyhdrs[0]);
    }

    spool_cache_header(xstrdup(":dblookup"), buf_release(&buf), txn->req_hdrs);

    return ltype->cb(txn, userhdrs[0], keyhdrs ? keyhdrs[0] : NULL);
}
