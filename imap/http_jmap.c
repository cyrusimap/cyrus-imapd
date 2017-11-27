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

#include <sasl/sasl.h>
#include <sasl/saslutil.h>

#ifdef HAVE_SSL
#include <openssl/hmac.h>
#include <openssl/rand.h>
#endif /* HAVE_SSL */

#include "append.h"
#include "cyrusdb.h"
#include "hash.h"
#include "httpd.h"
#include "http_dav.h"
#include "http_proxy.h"
#include "mboxname.h"
#include "msgrecord.h"
#include "proxy.h"
#include "times.h"
#include "syslog.h"
#include "xstrlcpy.h"

/* generated headers are not necessarily in current directory */
#include "imap/http_err.h"
#include "imap/imap_err.h"

#include "http_jmap.h"

struct namespace jmap_namespace;

static time_t compile_time;

/* HTTP method handlers */
static int jmap_get(struct transaction_t *txn, void *params);
static int jmap_post(struct transaction_t *txn, void *params);
static int jmap_delete(struct transaction_t *txn, void *params);

/* Namespace callbacks */
static void jmap_init(struct buf *serverinfo);
static int  jmap_checkurl(struct transaction_t *txn);
static int  jmap_auth(const char *userid);
static int  jmap_bearer(const char *bearer, char *userbuf, size_t buflen);

/* Authentication handlers */
static int jmap_authreq(struct transaction_t *txn);
static int jmap_authdel(struct transaction_t *txn);
static int jmap_settings(struct transaction_t *txn);

static int  jmap_initreq(jmap_req_t *req);
static void jmap_finireq(jmap_req_t *req);

static int myrights(struct auth_state *authstate,
                    const mbentry_t *mbentry,
                    hash_table *mboxrights);

static int myrights_byname(struct auth_state *authstate,
                           const char *mboxname,
                           hash_table *mboxrights);

/* Namespace for JMAP */
struct namespace_t namespace_jmap = {
    URL_NS_JMAP, 0, "/jmap", "/.well-known/jmap",
    jmap_checkurl, AUTH_BEARER,
    /*mbtype*/0, 
    (ALLOW_READ | ALLOW_POST),
    &jmap_init, &jmap_auth, NULL, NULL, NULL, &jmap_bearer,
    {
        { NULL,                 NULL },                 /* ACL          */
        { NULL,                 NULL },                 /* BIND         */
        { NULL,                 NULL },                 /* COPY         */
        { &jmap_delete,         NULL },                 /* DELETE       */
        { &jmap_get,            NULL },                 /* GET          */
        { &jmap_get,            NULL },                 /* HEAD         */
        { NULL,                 NULL },                 /* LOCK         */
        { NULL,                 NULL },                 /* MKCALENDAR   */
        { NULL,                 NULL },                 /* MKCOL        */
        { NULL,                 NULL },                 /* MOVE         */
        { &meth_options,        NULL },                 /* OPTIONS      */
        { NULL,                 NULL },                 /* PATCH        */
        { &jmap_post,           NULL },                 /* POST         */
        { NULL,                 NULL },                 /* PROPFIND     */
        { NULL,                 NULL },                 /* PROPPATCH    */
        { NULL,                 NULL },                 /* PUT          */
        { NULL,                 NULL },                 /* REPORT       */
        { &meth_trace,          NULL },                 /* TRACE        */
        { NULL,                 NULL },                 /* UNBIND       */
        { NULL,                 NULL }                  /* UNLOCK       */
    }
};

static ptrarray_t messages = PTRARRAY_INITIALIZER;

static jmap_msg_t *find_message(const char *name)
{
    jmap_msg_t *mp = NULL;
    int i;

    for (i = 0; i < messages.count; i++) {
        mp = (jmap_msg_t*) ptrarray_nth(&messages, i);
        if (!strcmp(mp->name, name)) {
            break;
        }
    }
    if (i == messages.count) {
        mp = NULL;
    }

    return mp;
}

struct mymblist_rock {
    mboxlist_cb *proc;
    void *rock;
    struct auth_state *authstate;
    hash_table *mboxrights;
    int all;
};

static int mymblist_cb(const mbentry_t *mbentry, void *rock)
{
    struct mymblist_rock *myrock = rock;

    if (!myrock->all) {
        if (mbentry->mbtype & MBTYPE_DELETED)
            return 0;

        int rights = myrights(myrock->authstate, mbentry, myrock->mboxrights);
        if (!(rights & ACL_LOOKUP))
            return 0;
    }
    return myrock->proc(mbentry, myrock->rock);
}

static int mymblist(const char *userid,
                    const char *accountid,
                    struct auth_state *authstate,
                    hash_table *mboxrights,
                    mboxlist_cb *proc,
                    void *rock,
                    int all)
{
    if (!strcmp(userid, accountid)) {
        int flags = all ? (MBOXTREE_TOMBSTONES|MBOXTREE_DELETED) : 0;
        return mboxlist_usermboxtree(userid, proc, rock, flags);
    }

    /* Open the INBOX first */
    struct mymblist_rock myrock = { proc, rock, authstate, mboxrights, all };
    struct buf buf = BUF_INITIALIZER;
    buf_printf(&buf, "user%c%s", jmap_namespace.hier_sep, accountid);
    mbentry_t *mbentry = NULL;

    int r = mboxlist_lookup(buf_cstring(&buf), &mbentry, NULL);
    if (r) goto done;
    r = mymblist_cb(mbentry, &myrock);
    if (r) goto done;

    /* Visit any mailboxes underneath the INBOX */
    buf_putc(&buf, jmap_namespace.hier_sep);
    r = mboxlist_allmbox(buf_cstring(&buf), mymblist_cb, &myrock, all);

done:
    mboxlist_entry_free(&mbentry);
    buf_free(&buf);
    return r;
}

EXPORTED int jmap_mboxlist(jmap_req_t *req, mboxlist_cb *proc, void *rock)
{
    return mymblist(req->userid, req->accountid, req->authstate,
                    req->mboxrights, proc, rock, 0/*all*/);
}

EXPORTED int jmap_allmbox(jmap_req_t *req, mboxlist_cb *proc, void *rock)
{
    return mymblist(req->userid, req->accountid, req->authstate,
                    req->mboxrights, proc, rock, 1/*all*/);
}

static void jmap_init(struct buf *serverinfo __attribute__((unused)))
{
    namespace_jmap.enabled =
        config_httpmodules & IMAP_ENUM_HTTPMODULES_JMAP;

    jmapauth_init();

    if (config_jmapauth_allowsasl)
        namespace_jmap.auth_schemes = ~0;

    if (!namespace_jmap.enabled) return;

    compile_time = calc_compile_time(__TIME__, __DATE__);

    jmap_msg_t *mp;
    for (mp = jmap_mail_messages; mp->name; mp++) {
        ptrarray_append(&messages, mp);
    }
    for (mp = jmap_contact_messages; mp->name; mp++) {
        ptrarray_append(&messages, mp);
    }
    for (mp = jmap_calendar_messages; mp->name; mp++) {
        ptrarray_append(&messages, mp);
    }
}


static int jmap_auth(const char *userid __attribute__((unused)))
{
    /* Set namespace */
    mboxname_init_namespace(&jmap_namespace,
                            httpd_userisadmin || httpd_userisproxyadmin);
    return 0;
}

/* Perform a DELETE request */
static int jmap_delete(struct transaction_t *txn,
                       void *params __attribute__((unused)))
{
    if (!strcmp(txn->req_uri->path, "/jmap/auth/")) {
        return jmap_authdel(txn);
    }

    return HTTP_NOT_ALLOWED;
}

/* Perform a GET/HEAD request */
static int jmap_get(struct transaction_t *txn,
                    void *params __attribute__((unused)))
{
    if (!strncmp(txn->req_uri->path, "/jmap/download/", 15)) {
        return jmap_download(txn);
    }

    if (!strcmp(txn->req_uri->path, "/jmap/auth/")) {
        return jmap_settings(txn);
    }
    return HTTP_NOT_FOUND;
}

static int is_accessible(const mbentry_t *mbentry, void *rock __attribute__((unused)))
{
    if ((mbentry->mbtype & MBTYPE_DELETED) ||
        (mbentry->mbtype & MBTYPE_MOVING) ||
        (mbentry->mbtype & MBTYPE_REMOTE) ||
        (mbentry->mbtype & MBTYPE_RESERVE)) {
        return 0;
    }
    return IMAP_OK_COMPLETED;
}

static json_t *extract_value(json_t *from, const char *path, ptrarray_t *refs);

static json_t *extract_array_value(json_t *val, const char *idx, const char *path, ptrarray_t *pool)
{
    if (!strcmp(idx, "*")) {
        /* Build value from array traversal */
        json_t *newval = json_pack("[]");
        size_t i;
        json_t *v;
        json_array_foreach(val, i, v) {
            json_t *x = extract_value(v, path, pool);
            if (json_is_array(x)) {
                /* JMAP spec: "If the result of applying the rest
                 * of the pointer tokens to a value was itself an
                 * array, its items should be included individually
                 * in the output rather than including the array
                 * itself." */
                json_array_extend(newval, x);
            } else if (x) {
                json_array_append(newval, x);
            } else {
                json_decref(newval);
                newval = NULL;
            }
        }
        if (newval) {
            ptrarray_add(pool, newval);
        }
        return newval;
    }

    /* Lookup array value by index */
    const char *eot = NULL;
    bit64 num;
    if (parsenum(idx, &eot, 0, &num) || *eot) {
        return NULL;
    }
    val = json_array_get(val, num);
    if (!val) {
        return NULL;
    }
    return extract_value(val, path, pool);
}

/* Extract the JSON value at position path from val.
 *
 * Return NULL, if the the value does not exist or if
 * path is erroneous.
 */
static json_t *extract_value(json_t *val, const char *path, ptrarray_t *pool)
{
    /* Return value for empty path */
    if (*path == '\0') {
        return val;
    }

    /* Be lenient: root path '/' is optional */
    if (*path == '/') {
        path++;
    }

    /* Walk over path segments */
    while (val && *path) {
        const char *top = NULL;
        char *p = NULL;

        /* Extract next path segment */
        if (!(top = strchr(path, '/'))) {
            top = strchr(path, '\0');
        }
        p = json_pointer_decode(path, top - path);
        if (*p == '\0') {
            return NULL;
        }

        /* Extract array value */
        if (json_is_array(val)) {
            val = extract_array_value(val, p, top, pool);
            free(p);
            return val;
        }

        /* Value MUST be an object now */
        if (!json_is_object(val)) {
            free(p);
            return NULL;
        }
        /* Step down into object tree */
        val = json_object_get(val, p);
        free(p);
        path = *top ? top + 1 : top;
    }

    return val;
}

static int process_resultrefs(json_t *args, json_t *resp)
{
    json_t *ref;
    const char *arg;
    int ret = -1;

    void *tmp;
    json_object_foreach_safe(args, tmp, arg, ref) {
        if (*arg != '#' || *(arg+1) == '\0') {
            continue;
        }

        const char *of, *path;
        json_t *res = NULL;

        /* Parse result reference object */
        of = json_string_value(json_object_get(ref, "resultOf"));
        if (!of || *of == '\0') {
            goto fail;
        }
        path = json_string_value(json_object_get(ref, "path"));
        if (!path || *path == '\0') {
            goto fail;
        }

        /* Lookup referenced response */
        json_t *v;
        size_t i;
        json_array_foreach(resp, i, v) {
            const char *tag = json_string_value(json_array_get(v, 2));
            if (!tag || strcmp(tag, of)) {
                continue;
            }
            const char *typ = json_string_value(json_array_get(v, 0));
            if (!typ || !strcmp("error", typ)) {
                goto fail;
            }
            res = v;
            break;
        }
        if (!res) goto fail;

        /* Extract the reference argument value. */
        /* We maintain our own pool of newly created JSON objects, since
         * tracking reference counts across newly created JSON arrays is
         * a pain. Rule: If you incref an existing JSON value or create
         * an entirely new one, put it into the pool for cleanup. */
        ptrarray_t pool = PTRARRAY_INITIALIZER;
        json_t *val = extract_value(json_array_get(res, 1), path, &pool);
        if (!val) goto fail;

        /* XXX JMAP references are defined that: "If the type of the result
         * is X, and the expected type of the argument is an array of type X,
         * wrap the result in an array with a single item."...
         *
         * ...which basically requires us to keep a schema of JMAP requests.
         * In general, that shouldn't be too hard, but the getFooList filters
         * are polymorph (Condition vs Operator) and recursive.
         * For now, let's just go with a set of magic argument names that we
         * allow to promote to arrays (if they aren't already). */
        if (!json_is_array(val)) {
            if (!strcmp(arg+1, "ids") ||
                !strcmp(arg+1, "threadIds") ||
                !strcmp(arg+1, "mailboxIds")) {
                val = json_pack("[O]", val);
                ptrarray_add(&pool, val);
            }
        }

        /* Replace both key and value of the reference entry */
        json_object_set(args, arg + 1, val);
        json_object_del(args, arg);

        /* Clean up reference counts of pooled JSON objects */
        json_t *ref;
        while ((ref = ptrarray_pop(&pool))) {
            json_decref(ref);
        }
        ptrarray_fini(&pool);
    }

    return 0;

fail:
    return ret;
}

/* Perform a POST request */
static int jmap_post(struct transaction_t *txn,
                     void *params __attribute__((unused)))
{
    const char **hdr;
    json_t *req, *resp = NULL;
    json_error_t jerr;
    struct jmap_idmap idmap = {
        HASH_TABLE_INITIALIZER,
        HASH_TABLE_INITIALIZER,
        HASH_TABLE_INITIALIZER,
        HASH_TABLE_INITIALIZER,
        HASH_TABLE_INITIALIZER,
        HASH_TABLE_INITIALIZER
    };
    size_t i, flags = JSON_PRESERVE_ORDER;
    int ret;
    char *buf, *inboxname = NULL;
    hash_table accounts = HASH_TABLE_INITIALIZER;
    hash_table mboxrights = HASH_TABLE_INITIALIZER;

    /* Read body */
    txn->req_body.flags |= BODY_DECODE;
    ret = http_read_body(httpd_in, httpd_out,
                       txn->req_hdrs, &txn->req_body, &txn->error.desc);
    if (ret) {
        txn->flags.conn = CONN_CLOSE;
        return ret;
    }

    /* Handle uploads */
    if (!strncmp(txn->req_uri->path, "/jmap/upload/", 13)) {
        return jmap_upload(txn);
    }

    /* Handle POST to the authentication endpoint */
    if (!strcmp(txn->req_uri->path, "/jmap/auth/")) {
        return jmap_authreq(txn);
    }

    /* Must be a regular JMAP POST request */
    /* Canonicalize URL */
    if (!strcmp(txn->req_uri->path, "/jmap")) {
        txn->location = "/jmap/";
        return HTTP_MOVED;
    }
    if (strcmp(txn->req_uri->path, "/jmap/")) {
        return HTTP_NOT_FOUND;
    }

    /* Check Content-Type */
    if (!(hdr = spool_getheader(txn->req_hdrs, "Content-Type")) ||
        !is_mediatype("application/json", hdr[0])) {
        txn->error.desc = "This method requires a JSON request body";
        return HTTP_BAD_MEDIATYPE;
    }

    if (!buf_len(&txn->req_body.payload)) return HTTP_BAD_REQUEST;

    /* Allocate map to store uids */
    construct_hash_table(&idmap.mailboxes, 64, 0);
    construct_hash_table(&idmap.messages, 64, 0);
    construct_hash_table(&idmap.calendars, 64, 0);
    construct_hash_table(&idmap.calendarevents, 64, 0);
    construct_hash_table(&idmap.contactgroups, 64, 0);
    construct_hash_table(&idmap.contacts, 64, 0);


    /* Parse the JSON request */
    req = json_loads(buf_cstring(&txn->req_body.payload), 0, &jerr);
    if (!req || !json_is_array(req)) {
        txn->error.desc = "Unable to parse JSON request body";
        ret = HTTP_BAD_REQUEST;
        goto done;
    }

    /* Start JSON response */
    resp = json_array();
    if (!resp) {
        txn->error.desc = "Unable to create JSON response body";
        ret = HTTP_SERVER_ERROR;
        goto done;
    }

    construct_hash_table(&accounts, 8, 0);
    construct_hash_table(&mboxrights, 64, 0);

    /* Process each message in the request */
    for (i = 0; i < json_array_size(req); i++) {
        const jmap_msg_t *mp;
        json_t *msg = json_array_get(req, i);
        const char *tag, *name = json_string_value(json_array_get(msg, 0));
        json_t *args = json_array_get(msg, 1), *arg;
        json_t *id = json_array_get(msg, 2);
        int r = 0;

        /* XXX - better error reporting */
        if (!id) {
            txn->error.desc = "Missing id on request";
            ret = HTTP_BAD_REQUEST;
            goto done;
        }
        tag = json_string_value(id);

        /* Find the message processor */
        if (!(mp = find_message(name))) {
            json_array_append(resp, json_pack("[s {s:s} s]",
                        "error", "type", "unknownMethod", tag));
            continue;
        }

        /* Determine account */
        const char *accountid = httpd_userid;
        arg = json_object_get(json_array_get(msg, 1), "accountId");
        if (arg && arg != json_null()) {
            if ((accountid = json_string_value(arg)) == NULL) {
                json_t *err = json_pack("{s:s, s:[s]}",
                        "type", "invalidArguments", "arguments", "accountId");
                json_array_append(resp, json_pack("[s,o,s]", "error", err, tag));
                continue;
            }
            /* Check if any shared mailbox is accessible */
            if (!hash_lookup(accountid, &accounts)) {
                r = mymblist(httpd_userid, accountid, httpd_authstate, &mboxrights,
                             is_accessible, NULL, 0/*all*/);
                if (r != IMAP_OK_COMPLETED) {
                    json_t *err = json_pack("{s:s}", "type", "accountNotFound");
                    json_array_append_new(resp, json_pack("[s,o,s]", "error", err, tag));
                    continue;
                }
                hash_insert(accountid, (void*)1, &accounts);
            }
        }
        free(inboxname);
        inboxname = mboxname_user_mbox(accountid, NULL);

        /* Pre-process result references */
        if (process_resultrefs(args, resp)) {
            json_array_append_new(resp, json_pack("[s,{s:s},s]",
                        "error", "type", "resultReference", tag));
            continue;
        }

        struct conversations_state *cstate = NULL;
        r = conversations_open_user(accountid, &cstate);
        if (r) {
            txn->error.desc = error_message(r);
            ret = HTTP_SERVER_ERROR;
            goto done;
        }

        struct jmap_req req;
        req.userid = httpd_userid;
        req.accountid = accountid;
        req.inboxname = inboxname;
        req.cstate = cstate;
        req.authstate = httpd_authstate;
        req.args = args;
        req.response = resp;
        req.tag = tag;
        req.idmap = &idmap;
        req.txn = txn;
        req.mboxrights = &mboxrights;
        req.is_shared_account = strcmp(accountid, httpd_userid);

        /* Initialize request context */
        jmap_initreq(&req);

        /* Read the modseq counters again, just in case something changed. */
        r = mboxname_read_counters(inboxname, &req.counters);
        if (r) goto done;

        /* Call the message processor. */
        r = mp->proc(&req);

        /* Finalize request context */
        jmap_finireq(&req);

        if (r) {
            conversations_abort(&req.cstate);
            txn->error.desc = error_message(r);
            ret = HTTP_SERVER_ERROR;
            goto done;
        }
        conversations_commit(&req.cstate);
    }

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
    free_hash_table(&idmap.mailboxes, free);
    free_hash_table(&idmap.messages, free);
    free_hash_table(&idmap.calendars, free);
    free_hash_table(&idmap.calendarevents, free);
    free_hash_table(&idmap.contactgroups, free);
    free_hash_table(&idmap.contacts, free);
    free_hash_table(&accounts, NULL);
    free_hash_table(&mboxrights, free);
    free(inboxname);
    if (req) json_decref(req);
    if (resp) json_decref(resp);

    return ret;
}

struct _mboxcache_rec {
    struct mailbox *mbox;
    int refcount;
    int rw;
};

static int jmap_initreq(jmap_req_t *req)
{
    req->mboxes = ptrarray_new();
    return 0;
}

static void jmap_finireq(jmap_req_t *req)
{
    int i;

    for (i = 0; i < req->mboxes->count; i++) {
        struct _mboxcache_rec *rec = ptrarray_nth(req->mboxes, i);
        syslog(LOG_ERR, "jmap: force-closing mailbox %s (refcount=%d)",
                        rec->mbox->name, rec->refcount);
        mailbox_close(&rec->mbox);
        free(rec);
    }
    ptrarray_free(req->mboxes);
    req->mboxes = NULL;
}

EXPORTED int jmap_openmbox(jmap_req_t *req, const char *name, struct mailbox **mboxp, int rw)
{
    int i, r;
    struct _mboxcache_rec *rec;

    for (i = 0; i < req->mboxes->count; i++) {
        rec = (struct _mboxcache_rec*) ptrarray_nth(req->mboxes, i);
        if (!strcmp(name, rec->mbox->name)) {
            if (rw && !rec->rw) {
                /* Lock promotions are not supported */
                syslog(LOG_ERR, "jmapmbox: won't reopen mailbox %s", name);
                return IMAP_INTERNAL;
            }
            rec->refcount++;
            *mboxp = rec->mbox;
            return 0;
        }
    }

    r = rw ? mailbox_open_iwl(name, mboxp) : mailbox_open_irl(name, mboxp);
    if (r) {
        syslog(LOG_ERR, "jmap_openmbox(%s): %s", name, error_message(r));
        return r;
    }

    rec = xzmalloc(sizeof(struct _mboxcache_rec));
    rec->mbox = *mboxp;
    rec->refcount = 1;
    rec->rw = rw;
    ptrarray_add(req->mboxes, rec);

    return 0;
}

EXPORTED int jmap_isopenmbox(jmap_req_t *req, const char *name)
{

    int i;
    struct _mboxcache_rec *rec;

    for (i = 0; i < req->mboxes->count; i++) {
        rec = (struct _mboxcache_rec*) ptrarray_nth(req->mboxes, i);
        if (!strcmp(name, rec->mbox->name))
            return 1;
    }

    return 0;
}

EXPORTED void jmap_closembox(jmap_req_t *req, struct mailbox **mboxp)
{
    struct _mboxcache_rec *rec = NULL;
    int i;

    for (i = 0; i < req->mboxes->count; i++) {
        rec = (struct _mboxcache_rec*) ptrarray_nth(req->mboxes, i);
        if (rec->mbox == *mboxp)
            break;
    }
    if (i >= req->mboxes->count) {
        syslog(LOG_ERR, "jmap: ignore non-cached mailbox %s", (*mboxp)->name);
        return;
    }

    if (!(--rec->refcount)) {
        ptrarray_remove(req->mboxes, i);
        mailbox_close(&rec->mbox);
        free(rec);
    }
    *mboxp = NULL;
}

EXPORTED char *jmap_blobid(const struct message_guid *guid)
{
    char *blobid = xzmalloc(42);
    blobid[0] = 'G';
    memcpy(blobid+1, message_guid_encode(guid), 40);
    return blobid;
}


struct findblob_data {
    jmap_req_t *req;
    struct mailbox *mbox;
    msgrecord_t *mr;
    char *part_id;
};

static int findblob_cb(const conv_guidrec_t *rec, void *rock)
{
    struct findblob_data *d = (struct findblob_data*) rock;
    jmap_req_t *req = d->req;
    int r = 0;

    r = jmap_openmbox(req, rec->mboxname, &d->mbox, 0);
    if (r) return r;

    r = msgrecord_find(d->mbox, rec->uid, &d->mr);
    if (r) {
        jmap_closembox(req, &d->mbox);
        d->mr = NULL;
        return r;
    }

    d->part_id = rec->part ? xstrdup(rec->part) : NULL;
    return IMAP_OK_COMPLETED;
}


EXPORTED int jmap_findblob(jmap_req_t *req, const char *blobid,
                           struct mailbox **mbox, msgrecord_t **mr,
                           struct body **body, const struct body **part)
{
    struct findblob_data data = { req, NULL, NULL, NULL };
    struct body *mybody = NULL;
    const struct body *mypart = NULL;
    int i, r;

    if (blobid[0] != 'G')
        return IMAP_NOTFOUND;

    r = conversations_guid_foreach(req->cstate, blobid+1, findblob_cb, &data);
    if (r != IMAP_OK_COMPLETED) {
        if (!r) r = IMAP_NOTFOUND;
        goto done;
    }

    r = msgrecord_get_bodystructure(data.mr, &mybody);
    if (r) goto done;

    /* Find part containing the data */
    if (data.part_id) {
        ptrarray_t parts = PTRARRAY_INITIALIZER;
        struct message_guid content_guid;

        message_guid_decode(&content_guid, blobid+1);

        ptrarray_push(&parts, mybody);
        while ((mypart = ptrarray_shift(&parts))) {
            if (!message_guid_cmp(&content_guid, &mypart->content_guid)) {
                break;
            }
            if (!mypart->subpart) continue;
            ptrarray_push(&parts, mypart->subpart);
            for (i = 1; i < mypart->numparts; i++)
                ptrarray_push(&parts, mypart->subpart + i);
        }
        ptrarray_fini(&parts);

        if (!mypart) {
            r = IMAP_NOTFOUND;
            goto done;
        }
    }

    *mbox = data.mbox;
    *mr = data.mr;
    *part = mypart;
    *body = mybody;
    r = 0;

done:
    if (r) {
        if (data.mbox) jmap_closembox(req, &data.mbox);
        if (mybody) message_free_body(mybody);
    }
    if (data.part_id) free(data.part_id);
    return r;
}


EXPORTED int jmap_download(struct transaction_t *txn)
{
    if (strncmp(txn->req_uri->path, "/jmap/download/", 15))
        return HTTP_NOT_FOUND;

    const char *userid = txn->req_uri->path + 15;
    const char *slash = strchr(userid, '/');
    if (!slash) {
        /* XXX - error, needs AccountId */
        return HTTP_NOT_FOUND;
    }
#if 0
    size_t userlen = slash - userid;

    /* invalid user? */
    if (!strncmp(userid, httpd_userid, userlen)) {
        txn->error.desc = "failed to match userid";
        return HTTP_BAD_REQUEST;
    }
#endif

    const char *blobbase = slash + 1;
    slash = strchr(blobbase, '/');
    if (!slash) {
        /* XXX - error, needs blobid */
        txn->error.desc = "failed to find blobid";
        return HTTP_BAD_REQUEST;
    }
    size_t bloblen = slash - blobbase;

    if (*blobbase != 'G') {
        txn->error.desc = "invalid blobid (doesn't start with G)";
        return HTTP_BAD_REQUEST;
    }

    if (bloblen != 41) {
        /* incomplete or incorrect blobid */
        txn->error.desc = "invalid blobid (not 41 chars)";
        return HTTP_BAD_REQUEST;
    }

    const char *name = slash + 1;

    struct conversations_state *cstate = NULL;
    int r = conversations_open_user(httpd_userid, &cstate);
    if (r) {
        txn->error.desc = error_message(r);
        return HTTP_SERVER_ERROR;
    }

    /* now we're allocating memory, so don't return from here! */

    char *inboxname = mboxname_user_mbox(httpd_userid, NULL);

    struct jmap_req req;
    req.userid = httpd_userid;
    req.inboxname = inboxname;
    req.cstate = cstate;
    req.authstate = httpd_authstate;
    req.args = NULL;
    req.response = NULL;
    req.tag = NULL;
    req.idmap = NULL;
    req.txn = txn;

    jmap_initreq(&req);

    char *blobid = xstrndup(blobbase, bloblen);

    struct mailbox *mbox = NULL;
    msgrecord_t *mr = NULL;
    struct body *body = NULL;
    const struct body *part = NULL;
    struct buf msg_buf = BUF_INITIALIZER;
    char *decbuf = NULL;
    char *ctype = NULL;
    strarray_t headers = STRARRAY_INITIALIZER;
    int res = 0;

    /* Find part containing blob */
    r = jmap_findblob(&req, blobid, &mbox, &mr, &body, &part);
    if (r) {
        res = HTTP_NOT_FOUND; // XXX errors?
        txn->error.desc = "failed to find blob by id";
        goto done;
    }

    /* Map the message into memory */
    r = msgrecord_get_body(mr, &msg_buf);
    if (r) {
        res = HTTP_NOT_FOUND; // XXX errors?
        txn->error.desc = "failed to map record";
        goto done;
    }

    // default with no part is the whole message
    const char *base = msg_buf.s;
    size_t len = msg_buf.len;
    txn->resp_body.type = "message/rfc822";

    if (part) {
        // map into just this part
        txn->resp_body.type = "application/octet-stream";
        base += part->content_offset;
        len = part->content_size;

        // update content type header if present
        strarray_add(&headers, "Content-Type");
        ctype = xstrndup(msg_buf.s + part->header_offset, part->header_size);
        message_pruneheader(ctype, &headers, NULL);
        strarray_truncate(&headers, 0);
        if (ctype) {
            char *p = strchr(ctype, ':');
            if (p) {
                p++;
                while (*p == ' ') p++;
                char *end = strchr(p, '\n');
                if (end) *end = '\0';
                end = strchr(p, '\r');
                if (end) *end = '\0';
            }
            if (p && *p) txn->resp_body.type = p;
        }

        // binary decode if needed
        int encoding = part->charset_enc & 0xff;
        base = charset_decode_mimebody(base, len, encoding, &decbuf, &len);
    }

    txn->resp_body.len = len;
    txn->resp_body.fname = name;

    write_body(HTTP_OK, txn, base, len);

 done:
    free(decbuf);
    free(ctype);
    strarray_fini(&headers);
    if (mbox) jmap_closembox(&req, &mbox);
    conversations_commit(&cstate);
    if (body) {
        message_free_body(body);
        free(body);
    }
    if (mr) {
        msgrecord_unref(&mr);
    }
    buf_free(&msg_buf);
    free(blobid);
    jmap_finireq(&req);
    free(inboxname);
    return res;
}

static int lookup_upload_collection(const char *accountid, mbentry_t **mbentry)
{
    mbname_t *mbname;
    const char *uploadname;
    int r;

    /* Create notification mailbox name from the parsed path */
    mbname = mbname_from_userid(accountid);
    mbname_push_boxes(mbname, config_getstring(IMAPOPT_JMAPUPLOADFOLDER));

    /* XXX - hack to allow @domain parts for non-domain-split users */
    if (httpd_extradomain) {
        /* not allowed to be cross domain */
        if (mbname_localpart(mbname) &&
            strcmpsafe(mbname_domain(mbname), httpd_extradomain)) {
            r = HTTP_NOT_FOUND;
            goto done;
        }
        mbname_set_domain(mbname, NULL);
    }

    /* Locate the mailbox */
    uploadname = mbname_intname(mbname);
    r = http_mlookup(uploadname, mbentry, NULL);
    if (r == IMAP_MAILBOX_NONEXISTENT) {
        /* Find location of INBOX */
        char *inboxname = mboxname_user_mbox(accountid, NULL);

        int r1 = http_mlookup(inboxname, mbentry, NULL);
        free(inboxname);
        if (r1 == IMAP_MAILBOX_NONEXISTENT) {
            r = IMAP_INVALID_USER;
            goto done;
        }

        int rights = httpd_myrights(httpd_authstate, *mbentry);
        if (!(rights & ACL_CREATE)) {
            r = IMAP_PERMISSION_DENIED;
            goto done;
        }

        if (*mbentry) free((*mbentry)->name);
        else *mbentry = mboxlist_entry_create();
        (*mbentry)->name = xstrdup(uploadname);
    }
    else if (!r) {
        int rights = httpd_myrights(httpd_authstate, *mbentry);
        if (!(rights & ACL_INSERT)) {
            r = IMAP_PERMISSION_DENIED;
            goto done;
        }
    }

  done:
    mbname_free(&mbname);

    return r;
}


static int create_upload_collection(const char *accountid, struct mailbox **mailbox)
{
    /* notifications collection */
    mbentry_t *mbentry = NULL;
    int r = lookup_upload_collection(accountid, &mbentry);

    if (r == IMAP_INVALID_USER) {
        goto done;
    }
    else if (r == IMAP_PERMISSION_DENIED) {
        goto done;
    }
    else if (r == IMAP_MAILBOX_NONEXISTENT) {
        if (!mbentry) goto done;
        else if (mbentry->server) {
            proxy_findserver(mbentry->server, &http_protocol, httpd_userid,
                             &backend_cached, NULL, NULL, httpd_in);
            goto done;
        }

        r = mboxlist_createmailbox(mbentry->name, MBTYPE_COLLECTION,
                                   NULL, 1 /* admin */, accountid, NULL,
                                   0, 0, 0, 0, mailbox);
        /* we lost the race, that's OK */
        if (r == IMAP_MAILBOX_LOCKED) r = 0;
        if (r) syslog(LOG_ERR, "IOERROR: failed to create %s (%s)",
                      mbentry->name, error_message(r));
    }
    else if (mailbox) {
        /* Open mailbox for writing */
        r = mailbox_open_iwl(mbentry->name, mailbox);
        if (r) {
            syslog(LOG_ERR, "mailbox_open_iwl(%s) failed: %s",
                   mbentry->name, error_message(r));
        }
    }

 done:
    mboxlist_entry_free(&mbentry);
    return r;
}

/* Helper function to determine domain of data */
enum {
    DOMAIN_7BIT = 0,
    DOMAIN_8BIT,
    DOMAIN_BINARY
};

static int data_domain(const char *p, size_t n)
{
    int r = DOMAIN_7BIT;

    while (n--) {
        if (!*p) return DOMAIN_BINARY;
        if (*p & 0x80) r = DOMAIN_8BIT;
        p++;
    }

    return r;
}

EXPORTED int jmap_upload(struct transaction_t *txn)
{
    strarray_t flags = STRARRAY_INITIALIZER;
    strarray_append(&flags, "\\Deleted");
    strarray_append(&flags, "\\Expunged");  // custom flag to insta-expunge!

    struct body *body = NULL;
    const char *data = buf_base(&txn->req_body.payload);
    size_t datalen = buf_len(&txn->req_body.payload);

    int ret = HTTP_CREATED;
    hdrcache_t hdrcache = txn->req_hdrs;
    struct stagemsg *stage = NULL;
    FILE *f = NULL;
    const char **hdr;
    time_t now = time(NULL);
    struct appendstate as;

    struct mailbox *mailbox = NULL;
    int r = 0;
    const char *accountid = httpd_userid;
    if ((hdr = spool_getheader(hdrcache, "X-JMAP-AccountId"))) {
        accountid = hdr[0];
    }
    r = create_upload_collection(accountid, &mailbox);
    if (r) {
        syslog(LOG_ERR, "create_upload_collection: %s", error_message(r));
        ret = HTTP_BAD_REQUEST;
        goto done;
    }

    json_t *resp = json_pack("{s:s}", "accountId", accountid);

    /* Prepare to stage the message */
    if (!(f = append_newstage(mailbox->name, now, 0, &stage))) {
        syslog(LOG_ERR, "append_newstage(%s) failed", mailbox->name);
        txn->error.desc = "append_newstage() failed";
        ret = HTTP_SERVER_ERROR;
        goto done;
    }

    /* Create RFC 5322 header for resource */
    if ((hdr = spool_getheader(hdrcache, "User-Agent"))) {
        fprintf(f, "User-Agent: %s\r\n", hdr[0]);
    }

    if ((hdr = spool_getheader(hdrcache, "From"))) {
        fprintf(f, "From: %s\r\n", hdr[0]);
    }
    else {
        char *mimehdr;

        assert(!buf_len(&txn->buf));
        if (strchr(httpd_userid, '@')) {
            /* XXX  This needs to be done via an LDAP/DB lookup */
            buf_printf(&txn->buf, "<%s>", httpd_userid);
        }
        else {
            buf_printf(&txn->buf, "<%s@%s>", httpd_userid, config_servername);
        }

        mimehdr = charset_encode_mimeheader(buf_cstring(&txn->buf),
                                            buf_len(&txn->buf));
        fprintf(f, "From: %s\r\n", mimehdr);
        free(mimehdr);
        buf_reset(&txn->buf);
    }

    if ((hdr = spool_getheader(hdrcache, "Subject"))) {
        fprintf(f, "Subject: %s\r\n", hdr[0]);
    }

    if ((hdr = spool_getheader(hdrcache, "Date"))) {
        fprintf(f, "Date: %s\r\n", hdr[0]);
    }
    else {
        char datestr[80];
        time_to_rfc5322(now, datestr, sizeof(datestr));
        fprintf(f, "Date: %s\r\n", datestr);
    }

    if ((hdr = spool_getheader(hdrcache, "Message-ID"))) {
        fprintf(f, "Message-ID: %s\r\n", hdr[0]);
    }

    const char *type = "application/octet-stream";
    if ((hdr = spool_getheader(hdrcache, "Content-Type"))) {
        type = hdr[0];
    }
    fprintf(f, "Content-Type: %s\r\n", type);

    int domain = data_domain(data, datalen);
    switch (domain) {
        case DOMAIN_BINARY:
            fputs("Content-Transfer-Encoding: BINARY\r\n", f);
            break;
        case DOMAIN_8BIT:
            fputs("Content-Transfer-Encoding: 8BIT\r\n", f);
            break;
        default:
            break; // no CTE == 7bit
    }

    if ((hdr = spool_getheader(hdrcache, "Content-Disposition"))) {
        fprintf(f, "Content-Disposition: %s\r\n", hdr[0]);
    }

    if ((hdr = spool_getheader(hdrcache, "Content-Description"))) {
        fprintf(f, "Content-Description: %s\r\n", hdr[0]);
    }

    fprintf(f, "Content-Length: %u\r\n", (unsigned) datalen);

    fputs("MIME-Version: 1.0\r\n\r\n", f);

    /* Write the data to the file */
    fwrite(data, datalen, 1, f);
    fclose(f);

    /* Prepare to append the message to the mailbox */
    r = append_setup_mbox(&as, mailbox, httpd_userid, httpd_authstate,
                          0, /*quota*/NULL, 0, 0, /*event*/0);
    if (r) {
        syslog(LOG_ERR, "append_setup(%s) failed: %s",
               mailbox->name, error_message(r));
        ret = HTTP_SERVER_ERROR;
        txn->error.desc = "append_setup() failed";
        goto done;
    }

    /* Append the message to the mailbox */
    r = append_fromstage(&as, &body, stage, now, &flags, 0, /*annots*/NULL);

    if (r) {
        append_abort(&as);
        syslog(LOG_ERR, "append_fromstage(%s) failed: %s",
               mailbox->name, error_message(r));
        ret = HTTP_SERVER_ERROR;
        txn->error.desc = "append_fromstage() failed";
        goto done;
    }

    r = append_commit(&as);
    if (r) {
        syslog(LOG_ERR, "append_commit(%s) failed: %s",
               mailbox->name, error_message(r));
        ret = HTTP_SERVER_ERROR;
        txn->error.desc = "append_commit() failed";
        goto done;
    }

    char datestr[RFC3339_DATETIME_MAX];
    time_to_rfc3339(now + 86400, datestr, RFC3339_DATETIME_MAX);

    char *blobid = jmap_blobid(&body->content_guid);
    json_object_set_new(resp, "blobId", json_string(blobid));
    free(blobid);
    json_object_set_new(resp, "type", json_string(type));
    json_object_set_new(resp, "size", json_integer(datalen));
    json_object_set_new(resp, "expires", json_string(datestr));

    /* Dump JSON object into a text buffer */
    size_t jflags = JSON_PRESERVE_ORDER;
    jflags |= (config_httpprettytelemetry ? JSON_INDENT(2) : JSON_COMPACT);
    char *buf = json_dumps(resp, jflags);

    if (!buf) {
        txn->error.desc = "Error dumping JSON response object";
        ret = HTTP_SERVER_ERROR;
        goto done;
    }

    /* Output the JSON object */
    txn->resp_body.type = "application/json; charset=utf-8";
    write_body(HTTP_CREATED, txn, buf, strlen(buf));
    free(buf);
    ret = 0;

done:
    json_decref(resp);
    if (body) {
        message_free_body(body);
        free(body);
    }
    strarray_fini(&flags);
    append_removestage(stage);
    if (mailbox) {
        if (r) mailbox_abort(mailbox);
        else r = mailbox_commit(mailbox);
        mailbox_close(&mailbox);
    }

    return ret;
}

static int JNOTNULL(json_t *item)
{
   if (!item) return 0;
   if (json_is_null(item)) return 0;
   return 1;
}

EXPORTED int jmap_cmpstate(jmap_req_t* req, json_t *state, int mbtype) {
    if (JNOTNULL(state)) {
        const char *s = json_string_value(state);
        if (!s) {
            return -1;
        }
        modseq_t client_modseq = atomodseq_t(s);
        modseq_t server_modseq = 0;
        switch (mbtype) {
         case MBTYPE_CALENDAR:
             server_modseq = req->counters.caldavmodseq;
             break;
         case MBTYPE_ADDRESSBOOK:
             server_modseq = req->counters.carddavmodseq;
             break;
         default:
             server_modseq = req->counters.mailmodseq;
        }
        if (client_modseq < server_modseq)
            return -1;
        else if (client_modseq > server_modseq)
            return 1;
        else
            return 0;
    }
    return 0;
}

EXPORTED modseq_t jmap_highestmodseq(jmap_req_t *req, int mbtype) {
    modseq_t modseq;

    /* Determine current counter by mailbox type. */
    switch (mbtype) {
        case MBTYPE_CALENDAR:
            modseq = req->counters.caldavmodseq;
            break;
        case MBTYPE_ADDRESSBOOK:
            modseq = req->counters.carddavmodseq;
            break;
        case 0:
            modseq = req->counters.mailmodseq;
            break;
        default:
            modseq = req->counters.highestmodseq;
    }

    return modseq;
}

EXPORTED json_t* jmap_getstate(jmap_req_t *req, int mbtype) {
    struct buf buf = BUF_INITIALIZER;
    json_t *state = NULL;
    modseq_t modseq = jmap_highestmodseq(req, mbtype);

    buf_printf(&buf, MODSEQ_FMT, modseq);
    state = json_string(buf_cstring(&buf));
    buf_free(&buf);

    return state;
}

EXPORTED int jmap_bumpstate(jmap_req_t *req, int mbtype) {
    int r = 0;
    modseq_t modseq;
    char *mboxname = mboxname_user_mbox(req->accountid, NULL);

    /* Read counters. */
    r = mboxname_read_counters(mboxname, &req->counters);
    if (r) goto done;

    /* Determine current counter by mailbox type. */
    switch (mbtype) {
        case MBTYPE_CALENDAR:
            modseq = req->counters.caldavmodseq;
            break;
        case MBTYPE_ADDRESSBOOK:
            modseq = req->counters.carddavmodseq;
            break;
        case 0:
            modseq = req->counters.mailmodseq;
            break;
        default:
            modseq = req->counters.highestmodseq;
    }

    modseq = mboxname_nextmodseq(mboxname, modseq, mbtype, 1);
    r = mboxname_read_counters(mboxname, &req->counters);
    if (r) goto done;

done:
    free(mboxname);
    return r;
}

EXPORTED char *jmap_xhref(const char *mboxname, const char *resource)
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
        buf_printf(&buf, "%s/%s/%s/%s", prefix, USER_COLLECTION_PREFIX,
                   userid, strrchr(mboxname, '.')+1);
    }
    else {
        buf_printf(&buf, "%s/%s/%s@%s/%s", prefix, USER_COLLECTION_PREFIX,
                   userid, httpd_extradomain, strrchr(mboxname, '.')+1);
    }
    if (resource)
        buf_printf(&buf, "/%s", resource);
    free(userid);
    return buf_release(&buf);
}

static int jmap_checkurl(struct transaction_t *txn)
{
    if (!strcmp(txn->req_line.meth, "POST") &&
        !strncmp(txn->req_uri->path, "/jmap/auth/", 11)) {
        return 0;
    }
    return HTTP_UNAUTHORIZED;
}

static int check_password(const char *username, const char *password)
{
    assert(httpd_saslconn);

    int r = SASL_BADAUTH;
    char *user, *domain, *extra, *plus, *realuser;

    /* Taken straight out of httpd.c Basic auth */
    user = xstrdup(username);
    domain = strchr(user, '@');
    if (domain) *domain++ = '\0';
    extra = strchr(user, '%');
    if (extra) *extra++ = '\0';
    plus = strchr(user, '+');
    if (plus) *plus++ = '\0';
    /* Verify the password */
    realuser = domain ? strconcat(user, "@", domain, (char *)NULL) : xstrdup(user);
    r = sasl_checkpass(httpd_saslconn, realuser, strlen(realuser),
                       password, strlen(password));
    free(realuser);
    free(user);
    return r;
}

struct findaccounts_data {
    json_t *accounts;
    struct buf userid;
    int rw;
};

static void findaccounts_add(json_t *accounts, const char *userid, int rw)
{
    if (!userid || !strlen(userid)) {
        return;
    }

    json_object_set_new(accounts, userid, json_pack("{s:s s:b s:b}",
                "name", userid,
                "isPrimary", 0,
                "isReadOnly", !rw));
}

static int findaccounts_cb(struct findall_data *data, void *rock)
{
    if (!data || !data->mbentry)
        return 0;

    mbname_t *mbname = mbname_from_intname(data->mbentry->name);
    const char *userid = mbname_userid(mbname);
    struct findaccounts_data *ctx = rock;

    if (strcmp(buf_cstring(&ctx->userid), userid)) {
        /* We haven't yet seen this account */
        findaccounts_add(ctx->accounts, buf_cstring(&ctx->userid), ctx->rw);
        buf_setcstr(&ctx->userid, userid);
        ctx->rw = httpd_myrights(httpd_authstate, data->mbentry) & ACL_READ_WRITE;
    } else if (!ctx->rw) {
        /* Already seen this account, but it's read-only so far */
        ctx->rw = httpd_myrights(httpd_authstate, data->mbentry) & ACL_READ_WRITE;
    }

    mbname_free(&mbname);
    return 0;
}

static json_t *user_settings(const char *userid)
{
    json_t *accounts = json_pack("{s:{s:s s:b s:b}}",
            userid, "name", userid,
            "isPrimary", 1,
            "isReadOnly", 0); /* FIXME hasDataFor */

    /* Find all shared accounts */
    strarray_t patterns = STRARRAY_INITIALIZER;
    char *userpat = xstrdup("user.*");
    userpat[4] = jmap_namespace.hier_sep;
    strarray_append(&patterns, userpat);
    struct findaccounts_data ctx = { accounts, BUF_INITIALIZER, 0 };
    int r = mboxlist_findallmulti(&jmap_namespace, &patterns, 0, userid,
                                  httpd_authstate, findaccounts_cb, &ctx);
    free(userpat);
    strarray_fini(&patterns);
    if (r) {
        syslog(LOG_ERR, "Can't determine shared JMAP accounts for user %s: %s",
                userid, error_message(r));
    }
    findaccounts_add(ctx.accounts, buf_cstring(&ctx.userid), ctx.rw);
    buf_free(&ctx.userid);

    return json_pack("{s:s s:o s:o s:s s:s s:s}",
            "username", userid,
            "accounts", accounts,
            "capabilities", json_pack("{}"), /* TODO update with JMAP URIs */
            "apiUrl", "/jmap/",
            "downloadUrl", "/jmap/download/{accountId}/{blobId}/{name}",
            /* FIXME eventSourceUrl */
            "uploadUrl", "/jmap/upload/");
}

static int jmap_login(const char *login_id, const char *password,
                      struct jmapauth_token **tokptr)
{
    struct db *db = NULL;
    struct txn *tid = NULL;
    int r, ret = 0;
    struct jmapauth_token *login_tok = NULL;
    struct jmapauth_token *access_tok = NULL;
    char *data = NULL;
    size_t datalen = 0;

    /* Open the token database */
    login_tok = NULL;
    r = jmapauth_open(&db, CYRUSDB_CREATE | CYRUSDB_CONVERT, NULL);
    if (r) {
        ret = HTTP_GONE;
        goto done;
    }

    /* Fetch the token. This fails for corrupt MACs */
    r = jmapauth_fetch(db, login_id, &login_tok, JMAPAUTH_FETCH_LOCK, &tid);
    switch (r) {
        case CYRUSDB_OK:
            /* Hurray! */
            break;
        case CYRUSDB_NOTFOUND:
        case CYRUSDB_EXISTS:
            ret = HTTP_GONE;
            break;
        default:
            ret = HTTP_SERVER_ERROR;
    }
    if (ret) {
        goto done;
    }

    /* Check expiry time */
    if (jmapauth_is_expired(login_tok)) {
        ret = HTTP_GONE;
        goto done;
    }

    /* Check the password */
    if (check_password(login_tok->userid, password) != SASL_OK) {
        /* This *allows* enumeration of sessions! However, we'd rather
         * allow legit users distinguish if they have submitted an
         * invalid token or a wrong password. Rate-limit your servers. */
        ret = HTTP_FORBIDDEN;
        goto done;
    }

    /* Create and store the access token */
    data = xmalloc(login_tok->datalen);
    datalen = login_tok->datalen;
    memcpy(data, login_tok->data, login_tok->datalen);
    access_tok = jmapauth_token_new(login_tok->userid, JMAPAUTH_ACCESS_KIND,
                                    data, datalen);
    if (!access_tok) {
        syslog(LOG_ERR, "JMAP auth: cannot create access token");
        ret = HTTP_SERVER_ERROR;
        goto done;
    }
    r = jmapauth_store(db, access_tok, &tid);
    if (r) {
        syslog(LOG_ERR, "JMAP auth: cannot store access token: %s",
                cyrusdb_strerror(r));
        ret = HTTP_SERVER_ERROR;
        goto done;
    }

    /* Remove the login id */
    r = jmapauth_delete(db, login_id, &tid);
    if (r) {
        syslog(LOG_ERR, "JMAP auth: cannot delete login id: %s",
                cyrusdb_strerror(r));
        ret = HTTP_SERVER_ERROR;
        goto done;
    }

    /* All done */
    r = cyrusdb_commit(db, tid);
    if (r) {
        syslog(LOG_ERR, "JMAP auth: cannot commit access token: %s",
                cyrusdb_strerror(r));
        ret = HTTP_SERVER_ERROR;
        goto done;
    }
    tid = NULL;

done:
    if (tid) cyrusdb_abort(db, tid);
    r = jmapauth_close(db);
    if (r) {
        syslog(LOG_ERR, "JMAP auth: cannot close db: %s", cyrusdb_strerror(r));
        ret = HTTP_SERVER_ERROR;
    }
    if (!ret) {
        *tokptr = access_tok;
    } else {
        jmapauth_token_free(access_tok);
    }
    jmapauth_token_free(login_tok);
    free(data);
    return ret;
}

/* Handle a JMAP auth request */
static int jmap_authreq(struct transaction_t *txn)
{
    int ret = 0, r = 0;
    json_t *req = NULL;
    json_error_t jerr;
    const char **hdr;

    /* Check Content-Type */
    if (!(hdr = spool_getheader(txn->req_hdrs, "Content-Type")) ||
            !is_mediatype("application/json", hdr[0])) {
        txn->error.desc = "This method requires a JSON request body";
        return HTTP_BAD_MEDIATYPE;
    }

    /* Parse the JSON request */
    if (!buf_len(&txn->req_body.payload)) return HTTP_BAD_REQUEST;
    req = json_loads(buf_cstring(&txn->req_body.payload), 0, &jerr);
    if (!req || !json_is_object(req)) {
        txn->error.desc = "Unable to parse JSON request body";
        ret = HTTP_BAD_REQUEST;
        goto done;
    }

    if (json_object_get(req, "username")) {
        const char *userid = json_string_value(json_object_get(req, "username"));
        if (!userid || !strlen(userid)) {
            txn->error.desc = "Missing username property";
            ret = HTTP_BAD_REQUEST;
            goto done;
        }
        const char *client = json_string_value(json_object_get(req, "clientName"));
        if (!client || !strlen(client)) {
            txn->error.desc = "Missing clientName property";
            ret = HTTP_BAD_REQUEST;
            goto done;
        }
        const char *device = json_string_value(json_object_get(req, "deviceName"));
        if (!device || !strlen(device)) {
            txn->error.desc = "Missing deviceName property";
            ret = HTTP_BAD_REQUEST;
            goto done;
        }

        /* We'll store the payload so make sure it isn't excessive */
        if (txn->req_body.payload.len > 4096) {
            ret = HTTP_PAYLOAD_TOO_LARGE;
            goto done;
        }

        /* Create a loginId (also for unknown users) */
        struct jmapauth_token *login_tok = jmapauth_token_new(userid,
                JMAPAUTH_LOGINID_KIND,
                txn->req_body.payload.s,
                txn->req_body.payload.len);
        if (!login_tok) {
            syslog(LOG_ERR, "JMAP auth: cannot create login id");
            ret = HTTP_SERVER_ERROR;
            goto done;
        }

        /* Store the session (also for unknown users) */
        struct db *db = NULL;
        r = jmapauth_open(&db, CYRUSDB_CREATE | CYRUSDB_CONVERT, NULL);
        if (!r) {
            r = jmapauth_store(db, login_tok, NULL);
            if (r) {
                syslog(LOG_ERR, "JMAP auth: cannot store login id: %s",
                        cyrusdb_strerror(r));
                ret = HTTP_SERVER_ERROR;
                jmapauth_close(db);
                goto done;
            }
            r = jmapauth_close(db);
            db = NULL;
        }
        if (r) {
            syslog(LOG_ERR, "JMAP auth: cannot open/close db: %s",
                    cyrusdb_strerror(r));
            ret = HTTP_SERVER_ERROR;
            goto done;
        }

        /* Create the response object */
        char *login_id = jmapauth_tokenid(login_tok);
        json_t *res = json_pack("{s:s s:[{s:s}] s:n}",
                "loginId", login_id,
                "methods", "type", "password",
                "prompt");
        free(login_id);
        jmapauth_token_free(login_tok);

        /* Write the JSON response */
        char *sbuf = json_dumps(res, 0);
        if (!sbuf) {
            txn->error.desc = "Error dumping JSON response object";
            ret = HTTP_SERVER_ERROR;
            goto done;
        }
        txn->resp_body.type = "application/json; charset=utf-8";
        write_body(HTTP_OK, txn, sbuf, strlen(sbuf));
        free(sbuf);
        json_decref(res);
    }
    else if (json_object_get(req, "loginId")) {
        /* Validate request */
        txn->error.desc = NULL;
        const char *login_id = json_string_value(json_object_get(req, "loginId"));
        if (!login_id || !strlen(login_id)) {
            txn->error.desc = "Missing loginId property";
        }
        const char *password = json_string_value(json_object_get(req, "password"));
        if (!password || !strlen(password)) {
            txn->error.desc = "Missing password property";
        }
        const char *type = json_string_value(json_object_get(req, "type"));
        if (!type || !strlen(type)) {
            txn->error.desc = "Missing type property";
        }
        if (txn->error.desc) {
            ret = HTTP_BAD_REQUEST;
            goto done;
        }

        /* Reject all but password authentication requests */
        if (strcmp(type, "password")) {
            txn->error.desc = "Unsupported auth method";
            ret = HTTP_GONE;
            goto done;
        }

        /* Login user */
        struct jmapauth_token *access_tok;
        ret = jmap_login(login_id, password, &access_tok);
        if (ret) {
            txn->error.desc = "Invalid loginId or password";
            goto done;
        }

        /* Initialize the global namespace. Usually, that's done by
         * jmap_auth after a successful login, but we are out of the
         * regular authentication codepaths here. */
        mboxname_init_namespace(&jmap_namespace, 0/*isadmin*/);

        /* Create the response object */
        json_t *res = user_settings(access_tok->userid);
        if (!res) {
            syslog(LOG_ERR, "JMAP auth: cannot determine user settings for %s",
                    access_tok->userid);
            ret = HTTP_SERVER_ERROR;
            goto done;
        }
        char *access_id = jmapauth_tokenid(access_tok);
        json_object_set_new(res, "accessToken", json_string(access_id));

        /* Write the JSON response */
        char *sbuf = json_dumps(res, 0);
        if (!sbuf) {
            txn->error.desc = "Error dumping JSON response object";
            ret = HTTP_SERVER_ERROR;
            goto done;
        }
        txn->resp_body.type = "application/json; charset=utf-8";
        write_body(HTTP_CREATED, txn, sbuf, strlen(sbuf));

        jmapauth_token_free(access_tok);
        free(access_id);
        free(sbuf);
        json_decref(res);
    }
    else {
        txn->error.desc = "Unable to parse JSON request body";
        ret = HTTP_BAD_REQUEST;
    }

done:
    if (req) json_decref(req);
    return ret;
}

static int jmap_authdel(struct transaction_t *txn __attribute__((unused)))
{
    /* Get the access token. */
    const char **hdr = spool_getheader(txn->req_hdrs, "Authorization");
    if (!hdr || strncmp("Bearer ", hdr[0], 7)) {
        syslog(LOG_ERR, "JMAP auth: DELETE without Bearer token");
        /* Request was successfully authenticated with another auth scheme */
        txn->error.desc = "Need Bearer access token to revoke";
        return HTTP_FORBIDDEN;
    }
    const char *tokenid = hdr[0] + 7;

    /* Remove the token */
    struct db *db = NULL;
    int ret, r;

    r = jmapauth_open(&db, /*db_flags*/0, NULL);
    if (r || db == NULL) {
        syslog(LOG_ERR, "JMAP auth: cannot open db: %s", cyrusdb_strerror(r));
        ret = HTTP_SERVER_ERROR;
        goto done;
    }
    r = jmapauth_delete(db, tokenid, NULL);
    if (r && r != CYRUSDB_NOTFOUND) {
        syslog(LOG_ERR, "JMAP auth: cannot delete access token: %s",
                cyrusdb_strerror(r));
        ret = HTTP_SERVER_ERROR;
        goto done;
    }

    /* All done */
    ret = HTTP_NO_CONTENT;

done:
    r = jmapauth_close(db);
    if (r) {
        syslog(LOG_ERR, "JMAP auth: cannot close db: %s", cyrusdb_strerror(r));
        ret = HTTP_SERVER_ERROR;
        goto done;
    }
    return ret;
}


static int jmap_bearer(const char *bearer, char *userbuf, size_t userbuf_size)
{
    struct db *db = NULL;
    int ret = SASL_BADAUTH;
    time_t now = time(NULL);

    assert(userbuf);
    assert(userbuf_size);
    assert(bearer);

    /* Open the database */
    struct jmapauth_token *access_tok = NULL;
    int r = jmapauth_open(&db, /*db_flags*/0, NULL);
    if (r || db == NULL) {
        syslog(LOG_ERR, "JMAP auth: cannot open db: %s", cyrusdb_strerror(r));
        goto done;
    }

    /* Lookup the token. */
    r = jmapauth_fetch(db, bearer, &access_tok, 0, NULL);
    if (r) {
        syslog(LOG_INFO, "JMAP auth: access token lookup failed: %s",
                cyrusdb_strerror(r));
        goto done;
    }

    /* Cry loud for flagged tokens */
    if (access_tok->flags)  {
        /* FIXME httpd_remoteip might not be the one we're interested in */
        syslog(LOG_ERR, "JMAP auth: flagged token received from %s", httpd_remoteip);
        goto done;
    }

    /* Validate expiration time */
    if (jmapauth_is_expired(access_tok)) {
        syslog(LOG_INFO, "JMAP auth: access token is expired");
        r = jmapauth_delete(db, bearer, NULL);
        if (r) {
            syslog(LOG_ERR, "JMAP auth: cannot delete expired token: %s",
                    cyrusdb_strerror(r));
        }
        goto done;
    }

    /* Update last usage time if significant time has passed */
    if (now - access_tok->lastuse > JMAPAUTH_TOKEN_TTL_WINDOW) {
        access_tok->lastuse = now;
        r = jmapauth_store(db, access_tok, NULL);
        if (r) {
            syslog(LOG_ERR, "JMAP auth: cannot update token: %s",
                    cyrusdb_strerror(r));
            goto done;
        }
    }

    /* Copy username */
    size_t n = strlcpy(userbuf, access_tok->userid, userbuf_size - 1);
    if (n < strlen(access_tok->userid)) {
        syslog(LOG_ERR, "JMAP auth: excessively long username");
        goto done;
    }

    /* It's a legit bearer token */
    ret = SASL_OK;

done:
    r = jmapauth_close(db);
    if (r) {
        syslog(LOG_ERR, "JMAP auth: cannot close db: %s", cyrusdb_strerror(r));
        ret = SASL_BADAUTH;
        goto done;
    }
    jmapauth_token_free(access_tok);
    return ret;
}

/* Handle a GET on the auth endpoint */
static int jmap_settings(struct transaction_t *txn)
{
    assert(httpd_userid);

    /* Create the response object */
    json_t *res = user_settings(httpd_userid);
    if (!res) {
        syslog(LOG_ERR, "JMAP auth: cannot determine user settings for %s",
                httpd_userid);
        return HTTP_SERVER_ERROR;
    }

    /* Write the JSON response */
    char *sbuf = json_dumps(res, 0);
    if (!sbuf) {
        txn->error.desc = "Error dumping JSON response object";
        return HTTP_SERVER_ERROR;
    }
    txn->resp_body.type = "application/json; charset=utf-8";
    write_body(HTTP_CREATED, txn, sbuf, strlen(sbuf));

    free(sbuf);
    json_decref(res);
    return 0;
}

static int myrights(struct auth_state *authstate,
                    const mbentry_t *mbentry,
                    hash_table *mboxrights)
{
    int *rightsptr = hash_lookup(mbentry->name, mboxrights);
    if (!rightsptr) {
        rightsptr = xmalloc(sizeof(int));
        *rightsptr = httpd_myrights(authstate, mbentry);
        hash_insert(mbentry->name, rightsptr, mboxrights);
    }
    return *rightsptr;
}

static int myrights_byname(struct auth_state *authstate,
                           const char *mboxname,
                           hash_table *mboxrights)
{
    int *rightsptr = hash_lookup(mboxname, mboxrights);
    if (!rightsptr) {
        mbentry_t *mbentry = NULL;
        if (mboxlist_lookup(mboxname, &mbentry, NULL)) {
            return 0;
        }
        rightsptr = xmalloc(sizeof(int));
        *rightsptr = httpd_myrights(authstate, mbentry);
        mboxlist_entry_free(&mbentry);
        hash_insert(mboxname, rightsptr, mboxrights);
    }
    return *rightsptr;
}

EXPORTED int jmap_myrights(jmap_req_t *req, const mbentry_t *mbentry)
{
    if (!req->is_shared_account) {
        return -1;
    }
    return myrights(req->authstate, mbentry, req->mboxrights);
}

EXPORTED int jmap_myrights_byname(jmap_req_t *req, const char *mboxname)
{
    if (!req->is_shared_account) {
        return -1;
    }
    return myrights_byname(req->authstate, mboxname, req->mboxrights);
}


EXPORTED void jmap_myrights_delete(jmap_req_t *req, const char *mboxname)
{
    if (!req->is_shared_account) {
        return;
    }
    int *rightsptr = hash_del(mboxname, req->mboxrights);
    free(rightsptr);
}
