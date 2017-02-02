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
#include "util.h"
#include "xstrlcpy.h"

/* generated headers are not necessarily in current directory */
#include "imap/http_err.h"

#include <jansson.h>

static int meth_get_db(struct transaction_t *txn, void *params);

/* Namespace for DB lookups */
struct namespace_t namespace_dblookup = {
    URL_NS_DBLOOKUP, /*enabled*/1, "/dblookup", NULL,
    http_allow_noauth, /*authschemes*/0,
    /*mbtype*/0,
    ALLOW_READ,
    NULL, NULL, NULL, NULL, NULL,
    {
        { NULL,                 NULL },                 /* ACL          */
        { NULL,                 NULL },                 /* BIND         */
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
    const char *mboxname = NULL;
    const char **mailboxhdrs;
    const char *mailbox = "Default";

    mailboxhdrs = spool_getheader(txn->req_hdrs, "Mailbox");
    if (mailboxhdrs) {
        mailbox = mailboxhdrs[0];
    }

    mboxname = mboxname_abook(userid, mailbox);

    /* XXX init just incase carddav not enabled? */
    db = carddav_open_userid(userid);
    if (!db) goto done;

    array = carddav_getemail2uids(db, key, mboxname);
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

static int get_uid2groups(struct transaction_t *txn,
                          const char *userid, const char *key)
{
    struct carddav_db *db = NULL;
    strarray_t *array = NULL;
    char *result = NULL;
    json_t *json;
    int ret = HTTP_NO_CONTENT;
    int i;
    const char *mboxname = NULL;
    const char **otheruserhdrs;
    const char *otheruser = "";
    const char **mailboxhdrs;
    const char *mailbox = "Default";

    otheruserhdrs = spool_getheader(txn->req_hdrs, "OtherUser");
    if (otheruserhdrs) {
        otheruser = otheruserhdrs[0];
    }

    mailboxhdrs = spool_getheader(txn->req_hdrs, "Mailbox");
    if (mailboxhdrs) {
        mailbox = mailboxhdrs[0];
    }

    mboxname = mboxname_abook(userid, mailbox);

    /* XXX init just incase carddav not enabled? */
    db = carddav_open_userid(userid);
    if (!db) goto done;

    array = carddav_getuid2groups(db, key, mboxname, otheruser);
    if (!array) goto done;

    json = json_pack("{}");
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
    free(result);
    if (array) strarray_free(array);
    if (db) carddav_close(db);
    return ret;
}

static int get_group(struct transaction_t *txn, const char *userid, const char *mboxname, const char *group)
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

    array = carddav_getgroup(db, mboxname, group);
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

static int meth_get_db(struct transaction_t *txn,
                       void *params __attribute__((unused)))
{
    const char **userhdrs;
    const char **keyhdrs;
    char path[MAX_MAILBOX_PATH+1];
    char *p;
    mbname_t *mbname = NULL;

    userhdrs = spool_getheader(txn->req_hdrs, "User");
    keyhdrs = spool_getheader(txn->req_hdrs, "Key");

    if (!userhdrs) return HTTP_BAD_REQUEST;
    if (!keyhdrs) return HTTP_BAD_REQUEST;

    if (userhdrs[1]) return HTTP_NOT_ALLOWED;
    if (keyhdrs[1]) return HTTP_NOT_ALLOWED;

    if (!strcmp(txn->req_uri->path, "/dblookup/email"))
        return get_email(txn, userhdrs[0], keyhdrs[0]);

    if (!strcmp(txn->req_uri->path, "/dblookup/email2uids"))
        return get_email2uids(txn, userhdrs[0], keyhdrs[0]);

    if (!strcmp(txn->req_uri->path, "/dblookup/uid2groups"))
        return get_uid2groups(txn, userhdrs[0], keyhdrs[0]);

    strlcpy(path, keyhdrs[0], sizeof(path));
    p = path + strlen(path);
    while (p >= path && *p != '/') { p--; }
    if (p < path)
        return HTTP_BAD_REQUEST;
    *p++ = '\0';

    mbname = mbname_from_userid(userhdrs[0]);
    mbname_push_boxes(mbname, config_getstring(IMAPOPT_ADDRESSBOOKPREFIX));
    mbname_push_boxes(mbname, path);

    /* XXX - hack to allow @domain parts for non-domain-split users */
    if (httpd_extradomain) {
        /* not allowed to be cross domain */
        if (mbname_localpart(mbname) && strcmpsafe(mbname_domain(mbname), httpd_extradomain)) {
            mbname_free(&mbname);
            return HTTP_NOT_FOUND;
        }
        //free(parts.domain); - XXX fix when converting to real parts
        mbname_set_domain(mbname, NULL);
    }

    const char *mboxname = mbname_intname(mbname);

    int r;
    if (!strcmp(txn->req_uri->path, "/dblookup/group"))
        r = get_group(txn, userhdrs[0], mboxname, p);
    else
        r = HTTP_NOT_FOUND;

    mbname_free(&mbname);

    return r;
}
