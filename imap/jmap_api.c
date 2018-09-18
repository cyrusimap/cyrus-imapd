/* jmap_api.c -- Routines for handling JMAP API requests
 *
 * Copyright (c) 1994-2018 Carnegie Mellon University.  All rights reserved.
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

#include <sys/time.h>
#include <sys/resource.h>

#include <errno.h>

#include "append.h"
#include "cyrusdb.h"
#include "hash.h"
#include "httpd.h"
#include "http_dav.h"
#include "http_jmap.h"
#include "mboxname.h"
#include "msgrecord.h"
#include "proxy.h"
#include "times.h"
#include "syslog.h"
#include "xstrlcpy.h"

/* generated headers are not necessarily in current directory */
#include "imap/http_err.h"
#include "imap/imap_err.h"
#include "imap/jmap_err.h"


struct mymblist_rock {
    mboxlist_cb *proc;
    void *rock;
    struct auth_state *authstate;
    hash_table *mboxrights;
    int all;
};

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
    int flags = all ? (MBOXTREE_TOMBSTONES|MBOXTREE_DELETED) : 0;

    /* skip ACL checks if account owner */
    if (!strcmp(userid, accountid))
        return mboxlist_usermboxtree(userid, authstate, proc, rock, flags);

    /* Open the INBOX first */
    struct mymblist_rock myrock = { proc, rock, authstate, mboxrights, all };
    return mboxlist_usermboxtree(accountid, authstate, mymblist_cb, &myrock, flags);
}

HIDDEN int jmap_mboxlist(jmap_req_t *req, mboxlist_cb *proc, void *rock)
{
    return mymblist(req->userid, req->accountid, req->authstate,
                    req->mboxrights, proc, rock, 0/*all*/);
}

HIDDEN int jmap_is_accessible(const mbentry_t *mbentry,
                              void *rock __attribute__((unused)))
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

static json_t *extract_array_value(json_t *val, const char *idx,
                                   const char *path, ptrarray_t *pool)
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

static int process_resultrefs(json_t *args, json_t *resp, json_t **err)
{
    json_t *ref;
    const char *arg;
    int ret = -1;

    void *tmp;
    json_object_foreach_safe(args, tmp, arg, ref) {
        if (*arg != '#' || *(arg+1) == '\0') {
            continue;
        }

        if (json_object_get(args, arg + 1)) {
            *err = json_pack("{s:s, s:[s]}",
                             "type", "invalidArguments", "arguments", arg);
            goto fail;
        }

        const char *of, *path, *name;
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
        name = json_string_value(json_object_get(ref, "name"));
        if (!name || *name == '\0') {
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
            const char *mname = json_string_value(json_array_get(v, 0));
            if (!mname || strcmp(name, mname)) {
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

static int parse_json_body(struct transaction_t *txn, json_t **req)
{
    const char **hdr;
    json_error_t jerr;
    int ret;

    /* Check Content-Type */
    if (!(hdr = spool_getheader(txn->req_hdrs, "Content-Type")) ||
        !is_mediatype("application/json", hdr[0])) {
        txn->error.desc = "This method requires a JSON request body";
        return HTTP_BAD_MEDIATYPE;
    }

    /* Read body */
    txn->req_body.flags |= BODY_DECODE;
    ret = http_read_req_body(txn);
    if (ret) {
        txn->flags.conn = CONN_CLOSE;
        return ret;
    }

    /* Parse the JSON request */
    *req = json_loads(buf_cstring(&txn->req_body.payload), 0, &jerr);
    if (!*req) {
        buf_reset(&txn->buf);
        buf_printf(&txn->buf,
                   "Unable to parse JSON request body: %s", jerr.text);
        txn->error.desc = buf_cstring(&txn->buf);
        return JMAP_NOT_JSON;
    }

    return 0;
}

static int validate_request(struct transaction_t *txn, json_t *req,
                            jmap_settings_t *settings, int *do_perf)
{
    json_t *using = json_object_get(req, "using");
    json_t *calls = json_object_get(req, "methodCalls");

    if (!json_is_array(using) || !json_is_array(calls)) {
        return JMAP_NOT_REQUEST;
    }

    /*
     * XXX the following maximums are not enforced:
     * maxConcurrentUpload
     * maxConcurrentRequests
     */

    if (buf_len(&txn->req_body.payload) >
        (size_t) settings->limits[MAX_SIZE_REQUEST]) {
        return JMAP_LIMIT_SIZE;
    }

    size_t i;
    json_t *val;
    json_array_foreach(calls, i, val) {
        if (json_array_size(val) != 3 ||
                !json_is_string(json_array_get(val, 0)) ||
                !json_is_object(json_array_get(val, 1)) ||
                !json_is_string(json_array_get(val, 2))) {
            return JMAP_NOT_REQUEST;
        }
        if (i >= (size_t) settings->limits[MAX_CALLS_IN_REQUEST]) {
            return JMAP_LIMIT_CALLS;
        }
        const char *mname = json_string_value(json_array_get(val, 0));
        mname = strchr(mname, '/');
        if (!mname) continue;

        if (!strcmp(mname, "get")) {
            json_t *ids = json_object_get(json_array_get(val, 1), "ids");
            if (json_array_size(ids) >
                (size_t) settings->limits[MAX_OBJECTS_IN_GET]) {
                return JMAP_LIMIT_OBJS_GET;
            }
        }
        else if (!strcmp(mname, "set")) {
            json_t *args = json_array_get(val, 1);
            size_t size = json_object_size(json_object_get(args, "create"));
            size += json_object_size(json_object_get(args, "update"));
            size += json_array_size(json_object_get(args, "destroy"));
            if (size > (size_t) settings->limits[MAX_OBJECTS_IN_SET]) {
                return JMAP_LIMIT_OBJS_SET;
            }
        }
    }

    json_array_foreach(using, i, val) {
        const char *s = json_string_value(val);
        if (!s) {
            return JMAP_NOT_REQUEST;
        }
        if (!strcmp(s, XML_NS_CYRUS "performance")) {
            *do_perf = 1;
        }
        else if (!strcmp(s, "ietf:jmap")) {
            syslog(LOG_DEBUG, "old capability %s used", s);
        }
        else if (!strcmp(s, "ietf:jmapmail")) {
            syslog(LOG_DEBUG, "old capability %s used", s);
        }
        else if (!json_object_get(settings->capabilities, s)) {
            return JMAP_UNKNOWN_CAPABILITY;
        }
    }

    return 0;
}

HIDDEN int jmap_is_valid_id(const char *id)
{
    if (!id || *id == '\0') return 0;
    const char *p;
    for (p = id; *p; p++) {
        if (('0' <= *p && *p <= '9'))
            continue;
        if (('a' <= *p && *p <= 'z') || ('A' <= *p && *p <= 'Z'))
            continue;
        if ((*p == '-') || (*p == '_'))
            continue;
        return 0;
    }
    return 1;
}

static void _make_created_ids(const char *creation_id, void *val, void *rock)
{
    json_t *jcreatedIds = rock;
    const char *id = val;
    json_object_set_new(jcreatedIds, creation_id, json_string(id));
}

static int json_error_response(struct transaction_t *txn,
                               long code, json_t **res)
{
    long http_code = HTTP_BAD_REQUEST;
    const char *type, *title, *limit = NULL;

    /* Error string is encoded as type NUL title [ NUL limit ] */
    type = error_message(code);
    title = type + strlen(type) + 1;

    switch (code) {
    case JMAP_NOT_JSON:
    case JMAP_NOT_REQUEST:
    case JMAP_UNKNOWN_CAPABILITY:
        break;

    case JMAP_LIMIT_SIZE:
        http_code = HTTP_PAYLOAD_TOO_LARGE;

        GCC_FALLTHROUGH

    case JMAP_LIMIT_CALLS:
    case JMAP_LIMIT_OBJS_GET:
    case JMAP_LIMIT_OBJS_SET:
        limit = title + strlen(title) + 1;
        break;

    default:
        /* Actually an HTTP code, not a JMAP error code */
        return code;
    }

    *res = json_pack("{s:s s:s s:i}", "type", type, "title", title,
                     "status", atoi(error_message(http_code)));
    if (!*res) {
        txn->error.desc = "Unable to create JSON response";
        return HTTP_SERVER_ERROR;
    }

    if (limit) {
        json_object_set_new(*res, "limit", json_string(limit));
    }

    if (txn->error.desc) {
        json_object_set_new(*res, "detail", json_string(txn->error.desc));
    }

    return 0;
}


HIDDEN int jmap_initreq(jmap_req_t *req)
{
    memset(req, 0, sizeof(struct jmap_req));
    req->mboxes = ptrarray_new();
    return 0;
}

struct _mboxcache_rec {
    struct mailbox *mbox;
    int refcount;
    int rw;
};

HIDDEN void jmap_finireq(jmap_req_t *req)
{
    int i;

    for (i = 0; i < req->mboxes->count; i++) {
        struct _mboxcache_rec *rec = ptrarray_nth(req->mboxes, i);
        syslog(LOG_ERR, "jmap: force-closing mailbox %s (refcount=%d)",
                        rec->mbox->name, rec->refcount);
        mailbox_close(&rec->mbox);
        free(rec);
    }
    /* Fail after cleaning up open mailboxes */
    assert(!req->mboxes->count);

    ptrarray_free(req->mboxes);
    req->mboxes = NULL;
}

static jmap_method_t *find_methodproc(const char *name, hash_table *jmap_methods)
{
    return hash_lookup(name, jmap_methods);
}

/* Perform an API request */
HIDDEN int jmap_api(struct transaction_t *txn, json_t **res,
                    jmap_settings_t *settings)
{
    json_t *jreq = NULL, *resp = NULL;
    size_t i;
    int ret, do_perf = 0;
    char *inboxname = NULL;
    hash_table *client_creation_ids = NULL;
    hash_table *new_creation_ids = NULL;
    hash_table accounts = HASH_TABLE_INITIALIZER;
    hash_table mboxrights = HASH_TABLE_INITIALIZER;
    strarray_t methods = STRARRAY_INITIALIZER;

    ret = parse_json_body(txn, &jreq);
    if (ret) return json_error_response(txn, ret, res);

    /* Validate Request object */
    if ((ret = validate_request(txn, jreq, settings, &do_perf))) {
        return json_error_response(txn, ret, res);
    }

    /* Start JSON response */
    resp = json_array();
    if (!resp) {
        txn->error.desc = "Unable to create JSON response body";
        ret = HTTP_SERVER_ERROR;
        goto done;
    }

    /* Set up request-internal state */
    construct_hash_table(&accounts, 8, 0);
    construct_hash_table(&mboxrights, 64, 0);

    /* Set up creation ids */
    long max_creation_ids = (settings->limits[MAX_CALLS_IN_REQUEST] + 1) *
    settings->limits[MAX_OBJECTS_IN_SET];
    new_creation_ids = xzmalloc(sizeof(hash_table));
    construct_hash_table(new_creation_ids, max_creation_ids, 0);

    /* Parse client-supplied creation ids */
    json_t *jcreatedIds = json_object_get(jreq, "createdIds");
    if (json_is_object(jcreatedIds)) {
        client_creation_ids = xzmalloc(sizeof(hash_table));
        construct_hash_table(client_creation_ids,
                             json_object_size(jcreatedIds)+1, 0);
        const char *creation_id;
        json_t *jval;
        json_object_foreach(jcreatedIds, creation_id, jval) {
            if (!json_is_string(jval)) {
                txn->error.desc = "Invalid createdIds argument";
                ret = HTTP_BAD_REQUEST;
                goto done;
            }
            const char *id = json_string_value(jval);
            if (!jmap_is_valid_id(creation_id) || !jmap_is_valid_id(id)) {
                txn->error.desc = "Invalid createdIds argument";
                ret = HTTP_BAD_REQUEST;
                goto done;
            }
            hash_insert(creation_id, xstrdup(id), client_creation_ids);
        }
    }
    else if (jcreatedIds && jcreatedIds != json_null()) {
        txn->error.desc = "Invalid createdIds argument";
        ret = HTTP_BAD_REQUEST;
        goto done;
    }

    /* Process each method call in the request */
    json_t *mc;
    json_array_foreach(json_object_get(jreq, "methodCalls"), i, mc) {
        const jmap_method_t *mp;
        const char *mname = json_string_value(json_array_get(mc, 0));
        json_t *args = json_array_get(mc, 1), *arg;
        const char *tag = json_string_value(json_array_get(mc, 2));
        json_t *err = NULL;
        int r = 0;

        strarray_append(&methods, mname);
        json_incref(args);

    redo:

        /* Find the message processor */
        if (!(mp = find_methodproc(mname, &settings->methods))) {
            json_array_append(resp, json_pack("[s {s:s} s]",
                        "error", "type", "unknownMethod", tag));
            json_decref(args);
            continue;
        }

        /* Determine account */
        const char *accountid = httpd_userid;
        arg = json_object_get(args, "accountId");
        if (arg && arg != json_null()) {
            if ((accountid = json_string_value(arg)) == NULL) {
                json_t *err = json_pack("{s:s, s:[s]}",
                        "type", "invalidArguments", "arguments", "accountId");
                json_array_append(resp, json_pack("[s,o,s]", "error", err, tag));
                json_decref(args);
                continue;
            }
            /* Check if any shared mailbox is accessible */
            if (!hash_lookup(accountid, &accounts)) {
                r = mymblist(httpd_userid, accountid, httpd_authstate,
                             &mboxrights, jmap_is_accessible, NULL, 0/*all*/);
                if (r != IMAP_OK_COMPLETED) {
                    json_t *err = json_pack("{s:s}", "type", "accountNotFound");
                    json_array_append_new(resp,
                                          json_pack("[s,o,s]", "error", err, tag));
                    json_decref(args);
                    continue;
                }
                hash_insert(accountid, (void*)1, &accounts);
            }
        }
        free(inboxname);
        inboxname = mboxname_user_mbox(accountid, NULL);

        /* Pre-process result references */
        if (process_resultrefs(args, resp, &err)) {
            if (!err) err = json_pack("{s:s}", "type", "resultReference");

            json_array_append_new(resp, json_pack("[s,o,s]", "error", err, tag));
            json_decref(args);
            continue;
        }

        struct conversations_state *cstate = NULL;
        r = conversations_open_user(accountid, &cstate);
        if (r) {
            txn->error.desc = error_message(r);
            ret = HTTP_SERVER_ERROR;
            json_decref(args);
            goto done;
        }

        /* Initialize request context */
        struct jmap_req req;
        jmap_initreq(&req);

        req.method = mname;
        req.userid = httpd_userid;
        req.accountid = accountid;
        req.inboxname = inboxname;
        req.cstate = cstate;
        req.authstate = httpd_authstate;
        req.args = args;
        req.response = resp;
        req.tag = tag;
        req.client_creation_ids = client_creation_ids;
        req.new_creation_ids = new_creation_ids;
        req.txn = txn;
        req.mboxrights = &mboxrights;

        if (do_perf) {
            struct rusage usage;

            getrusage(RUSAGE_SELF, &usage);
            req.user_start = timeval_get_double(&usage.ru_utime);
            req.sys_start = timeval_get_double(&usage.ru_stime);
            req.real_start = now_ms() / 1000.0;
            req.do_perf = 1;
        }

        /* Read the current state data in */
        r = mboxname_read_counters(inboxname, &req.counters);
        if (r) {
            jmap_finireq(&req);
            if (req.subargs) json_decref(req.subargs);
            json_decref(args);
            goto done;
        }

        /* Call the message processor. */
        r = mp->proc(&req);

        /* Finalize request context */
        jmap_finireq(&req);

        if (r) {
            conversations_abort(&req.cstate);
            txn->error.desc = error_message(r);
            ret = HTTP_SERVER_ERROR;
            if (req.subargs) json_decref(req.subargs);
            json_decref(args);
            goto done;
        }
        conversations_commit(&req.cstate);

        json_decref(args);

        if (req.subreq) {
            mname = req.subreq;
            args = req.subargs;
            goto redo;
        }
    }

    /* tell syslog which methods were called */
    spool_replace_header(xstrdup(":jmap"),
                         strarray_join(&methods, ","), txn->req_hdrs);


    /* Build responses */
    *res = json_pack("{s:O}", "methodResponses", resp);
    if (client_creation_ids) {
        json_t *jcreatedIds = json_object();
        hash_enumerate(new_creation_ids, _make_created_ids, jcreatedIds);
        json_object_set_new(*res, "createdIds", jcreatedIds);
    }

  done:
    free_hash_table(client_creation_ids, free);
    free(client_creation_ids);
    free_hash_table(new_creation_ids, free);
    free(new_creation_ids);
    free_hash_table(&accounts, NULL);
    free_hash_table(&mboxrights, free);
    free(inboxname);
    json_decref(jreq);
    json_decref(resp);
    strarray_fini(&methods);

    return ret;
}

const char *jmap_lookup_id(jmap_req_t *req, const char *creation_id)
{
    if (req->client_creation_ids) {
        const char *id = hash_lookup(creation_id, req->client_creation_ids);
        if (id) return id;
    }
    if (!req->new_creation_ids)
        return NULL;
    return hash_lookup(creation_id, req->new_creation_ids);
}

void jmap_add_id(jmap_req_t *req, const char *creation_id, const char *id)
{
    /* It's OK to overwrite existing ids, as per Foo/set:
     * "A client SHOULD NOT reuse a creation id anywhere in the same API
     * request. If a creation id is reused, the server MUST map the creation
     * id to the most recently created item with that id."
     */
    if (!req->new_creation_ids) {
        req->new_creation_ids = xzmalloc(sizeof(hash_table));
        construct_hash_table(req->new_creation_ids, 128, 0);
    }
    hash_insert(creation_id, xstrdup(id), req->new_creation_ids);
}

HIDDEN int jmap_openmbox(jmap_req_t *req, const char *name,
                         struct mailbox **mboxp, int rw)
{
    int i, r;
    struct _mboxcache_rec *rec;

    for (i = 0; i < req->mboxes->count; i++) {
        rec = (struct _mboxcache_rec*) ptrarray_nth(req->mboxes, i);
        if (!strcmp(name, rec->mbox->name)) {
            if (rw && !rec->rw) {
                /* Lock promotions are not supported */
                syslog(LOG_ERR, "jmapmbox: failed to grab write-lock"
                       " on cached read-only mailbox %s", name);
                return IMAP_INTERNAL;
            }
            /* Found a cached mailbox. Increment refcount. */
            rec->refcount++;
            *mboxp = rec->mbox;

            return 0;
        }
    }

    /* Add mailbox to cache */
    if (req->force_openmbox_rw)
        rw = 1;
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

HIDDEN int jmap_isopenmbox(jmap_req_t *req, const char *name)
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

HIDDEN void jmap_closembox(jmap_req_t *req, struct mailbox **mboxp)
{
    struct _mboxcache_rec *rec = NULL;
    int i;

    if (mboxp == NULL || *mboxp == NULL) return;

    for (i = 0; i < req->mboxes->count; i++) {
        rec = (struct _mboxcache_rec*) ptrarray_nth(req->mboxes, i);
        if (rec->mbox == *mboxp) {
            if (!(--rec->refcount)) {
                ptrarray_remove(req->mboxes, i);
                mailbox_close(&rec->mbox);
                free(rec);
            }
            *mboxp = NULL;
            return;
        }
    }
    syslog(LOG_INFO, "jmap: ignoring non-cached mailbox %s", (*mboxp)->name);
}

HIDDEN void jmap_set_blobid(const struct message_guid *guid, char *buf)
{
    buf[0] = 'G';
    memcpy(buf+1, message_guid_encode(guid), 40);
    buf[41] = '\0';
}


struct findblob_data {
    jmap_req_t *req;
    const char *accountid;
    int is_shared_account;
    struct mailbox *mbox;
    msgrecord_t *mr;
    char *part_id;
};

static int findblob_cb(const conv_guidrec_t *rec, void *rock)
{
    struct findblob_data *d = (struct findblob_data*) rock;
    jmap_req_t *req = d->req;
    int r = 0;

    /* Ignore blobs that don't belong to the current accountId */
    mbname_t *mbname = mbname_from_intname(rec->mboxname);
    int is_accountid_mbox =
        (mbname && !strcmp(mbname_userid(mbname), d->accountid));
    mbname_free(&mbname);
    if (!is_accountid_mbox)
        return 0;

    /* Check ACL */
    if (d->is_shared_account) {
        mbentry_t *mbentry = NULL;
        r = mboxlist_lookup(rec->mboxname, &mbentry, NULL);
        if (r) {
            syslog(LOG_ERR, "jmap_findblob: no mbentry for %s", rec->mboxname);
            return r;
        }
        int rights = jmap_myrights(req, mbentry);
        mboxlist_entry_free(&mbentry);
        if ((rights & (ACL_LOOKUP|ACL_READ)) != (ACL_LOOKUP|ACL_READ)) {
            return 0;
        }
    }

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

HIDDEN int jmap_findblob(jmap_req_t *req, const char *blobid,
                         struct mailbox **mbox, msgrecord_t **mr,
                         struct body **body, const struct body **part,
                         struct buf *blob)
{

    struct findblob_data data = {
        req, /* req */
        req->accountid, /* accountid */
        strcmp(req->userid, req->accountid), /* is_shared_account */
        NULL, /* mbox */
        NULL, /* mr */
        NULL  /* part_id */
    };
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
            if (!mypart->subpart) {
                if (data.mbox->mbtype == MBTYPE_ADDRESSBOOK &&
                    (mypart = jmap_contact_findblob(&content_guid, data.part_id,
                                                    data.mbox, data.mr, blob))) {
                    break;
                }
                continue;
            }
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


HIDDEN int jmap_cmpstate(jmap_req_t* req, json_t *state, int mbtype)
{
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

HIDDEN modseq_t jmap_highestmodseq(jmap_req_t *req, int mbtype)
{
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

HIDDEN json_t* jmap_getstate(jmap_req_t *req, int mbtype, int refresh)
{
    if (refresh)
        assert (!mboxname_read_counters(req->inboxname, &req->counters));
    struct buf buf = BUF_INITIALIZER;
    json_t *state = NULL;
    modseq_t modseq = jmap_highestmodseq(req, mbtype);

    buf_printf(&buf, MODSEQ_FMT, modseq);
    state = json_string(buf_cstring(&buf));
    buf_free(&buf);

    return state;
}


HIDDEN json_t *jmap_fmtstate(modseq_t modseq)
{
    struct buf buf = BUF_INITIALIZER;
    json_t *state = NULL;
    buf_printf(&buf, MODSEQ_FMT, modseq);
    state = json_string(buf_cstring(&buf));
    buf_free(&buf);
    return state;
}

HIDDEN char *jmap_xhref(const char *mboxname, const char *resource)
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

static int _rights_for_mbentry(jmap_req_t *req, const mbentry_t *mbentry)
{
    // for the mailbox owner, assume full rights
    int rights = -1;

    mbname_t *mbname = mbname_from_intname(mbentry->name);
    if (strcmp(mbname_userid(mbname), req->userid)) {
        if (mbentry->mbtype & MBTYPE_INTERMEDIATE) {
            // if it's an intermediate mailbox, we get rights from the parent
            mbentry_t *parententry = NULL;
            if (mboxlist_findparent(mbentry->name, &parententry))
                rights = 0;
            else
                rights = httpd_myrights(req->authstate, parententry);
            mboxlist_entry_free(&parententry);
        }
        else
            rights = httpd_myrights(req->authstate, mbentry);
    }
    mbname_free(&mbname);

    // intermediate mailboxes have limited rights, just see, create sub,
    // rename and delete:
    if (mbentry->mbtype & MBTYPE_INTERMEDIATE)
        rights &= ACL_LOOKUP | ACL_CREATE | ACL_DELETEMBOX;

    return rights;
}


HIDDEN int jmap_myrights(jmap_req_t *req, const mbentry_t *mbentry)
{
    int *rightsptr = hash_lookup(mbentry->name, req->mboxrights);

    if (!rightsptr) {
        rightsptr = xmalloc(sizeof(int));
        *rightsptr = _rights_for_mbentry(req, mbentry);
        hash_insert(mbentry->name, rightsptr, req->mboxrights);
    }

    return *rightsptr;
}

// gotta have them all
HIDDEN int jmap_hasrights(jmap_req_t *req, const mbentry_t *mbentry, int rights)
{
    int myrights = jmap_myrights(req, mbentry);
    if ((myrights & rights) == rights) return 1;
    return 0;
}

HIDDEN int jmap_myrights_byname(jmap_req_t *req, const char *mboxname)
{
    int *rightsptr = hash_lookup(mboxname, req->mboxrights);

    if (!rightsptr) {
        rightsptr = xmalloc(sizeof(int));

        // if unable to read, that means no rights
        int rights = 0;
        mbentry_t *mbentry = NULL;
        if (!mboxlist_lookup(mboxname, &mbentry, NULL)) {
            rights = _rights_for_mbentry(req, mbentry);
            mboxlist_entry_free(&mbentry);
        }

        *rightsptr = rights;
        hash_insert(mboxname, rightsptr, req->mboxrights);
    }

    return *rightsptr;
}

// gotta have them all
HIDDEN int jmap_hasrights_byname(jmap_req_t *req, const char *mboxname,
                                 int rights)
{
    int myrights = jmap_myrights_byname(req, mboxname);
    if ((myrights & rights) == rights) return 1;
    return 0;
}

HIDDEN void jmap_myrights_delete(jmap_req_t *req, const char *mboxname)
{
    int *rightsptr = hash_del(mboxname, req->mboxrights);
    free(rightsptr);
}

HIDDEN json_t* jmap_patchobject_apply(json_t *val, json_t *patch)
{
    const char *path;
    json_t *newval, *dst;

    dst = json_deep_copy(val);
    json_object_foreach(patch, path, newval) {
        /* Start traversal at root object */
        json_t *it = dst;
        const char *base = path, *top;
        /* Find path in object tree */
        while ((top = strchr(base, '/'))) {
            char *name = json_pointer_decode(base, top-base);
            it = json_object_get(it, name);
            free(name);
            base = top + 1;
        }
        if (!it) {
            /* No such path in 'val' */
            json_decref(dst);
            return NULL;
        }
        /* Replace value at path */
        char *name = json_pointer_decode(base, strlen(base));
        if (newval == json_null()) {
            json_object_del(it, name);
        } else {
            json_object_set(it, name, newval);
        }
        free(name);
    }

    return dst;
}

static void jmap_patchobject_diff(json_t *patch, struct buf *buf,
                                  json_t *a, json_t *b)
{
    const char *id;
    json_t *o;

    if (b == NULL || json_equal(a, b)) {
        return;
    }

    if (!a || json_is_null(a) || json_typeof(b) != JSON_OBJECT) {
        json_object_set(patch, buf_cstring(buf), b);
    }

    json_object_foreach(b, id, o) {
        char *encid = json_pointer_encode(id);
        size_t l = buf_len(buf);
        if (!l) {
            buf_setcstr(buf, encid);
        } else {
            buf_appendcstr(buf, "/");
            buf_appendcstr(buf, encid);
        }
        jmap_patchobject_diff(patch, buf, json_object_get(a, id), o);
        buf_truncate(buf, l);
        free(encid);
    }
}

HIDDEN json_t *jmap_patchobject_create(json_t *a, json_t *b)
{
    json_t *patch = json_object();
    struct buf buf = BUF_INITIALIZER;
    jmap_patchobject_diff(patch, &buf, a, b);
    buf_free(&buf);
    return patch;
}

/* Add performance stats to method response */
static void jmap_add_perf(jmap_req_t *req, json_t *res)
{
    if (req->do_perf) {
        struct rusage usage;

        getrusage(RUSAGE_SELF, &usage);

        json_t *perf = json_pack("{s:f s:f s:f}",
            "real", (now_ms() / 1000.0) - req->real_start,
            "user", timeval_get_double(&usage.ru_utime) - req->user_start,
            "sys", timeval_get_double(&usage.ru_stime) - req->sys_start);

        json_object_set_new(res, "performance", perf);
    }
}

HIDDEN void jmap_parser_fini(struct jmap_parser *parser)
{
    strarray_fini(&parser->path);
    json_decref(parser->invalid);
    buf_free(&parser->buf);
}

HIDDEN void jmap_parser_push(struct jmap_parser *parser, const char *prop)
{
    strarray_push(&parser->path, prop);
}

HIDDEN void jmap_parser_push_index(struct jmap_parser *parser, const char *prop,
                                   size_t index, const char *name)
{
    /* TODO make this more clever: won't need to printf most of the time */
    if (name) buf_printf(&parser->buf, "%s[%zu:%s]", prop, index, name);
    else buf_printf(&parser->buf, "%s[%zu]", prop, index);
    strarray_push(&parser->path, buf_cstring(&parser->buf));
    buf_reset(&parser->buf);
}

HIDDEN void jmap_parser_push_name(struct jmap_parser *parser,
                                  const char *prop, const char *name)
{
    /* TODO make this more clever: won't need to printf most of the time */
    buf_printf(&parser->buf, "%s{%s}", prop, name);
    strarray_push(&parser->path, buf_cstring(&parser->buf));
    buf_reset(&parser->buf);
}

HIDDEN void jmap_parser_pop(struct jmap_parser *parser)
{
    free(strarray_pop(&parser->path));
}

HIDDEN const char* jmap_parser_path(struct jmap_parser *parser, struct buf *buf)
{
    int i;
    buf_reset(buf);

    for (i = 0; i < parser->path.count; i++) {
        const char *p = strarray_nth(&parser->path, i);
        if (json_pointer_needsencode(p)) {
            char *tmp = json_pointer_encode(p);
            buf_appendcstr(buf, tmp);
            free(tmp);
        } else {
            buf_appendcstr(buf, p);
        }
        if ((i + 1) < parser->path.count) {
            buf_appendcstr(buf, "/");
        }
    }

    return buf_cstring(buf);
}

HIDDEN void jmap_parser_invalid(struct jmap_parser *parser, const char *prop)
{
    if (prop)
        jmap_parser_push(parser, prop);

    json_array_append_new(parser->invalid,
            json_string(jmap_parser_path(parser, &parser->buf)));

    if (prop)
        jmap_parser_pop(parser);
}

HIDDEN void jmap_ok(jmap_req_t *req, json_t *res)
{
    json_object_set_new(res, "accountId", json_string(req->accountid));

    json_t *item = json_pack("[]");
    json_array_append_new(item, json_string(req->method));
    json_array_append_new(item, res);
    json_array_append_new(item, json_string(req->tag));
    json_array_append_new(req->response, item);

    jmap_add_perf(req, res);
}

HIDDEN void jmap_error(jmap_req_t *req, json_t *err)
{
    json_array_append_new(req->response,
            json_pack("[s,o,s]", "error", err, req->tag));
}

HIDDEN json_t *jmap_server_error(int r)
{
    return json_pack("{s:s, s:s}",
                     "type", "serverError",
                     "description", error_message(r));
}


HIDDEN int jmap_parse_strings(json_t *arg,
                              struct jmap_parser *parser, const char *prop)
{
    if (!json_is_array(arg)) {
        jmap_parser_invalid(parser, prop);
        return 0;
    }
    int valid = 1;
    size_t i;
    json_t *val;
    json_array_foreach(arg, i, val) {
        if (!json_is_string(val)) {
            jmap_parser_push_index(parser, prop, i, NULL);
            jmap_parser_invalid(parser, NULL);
            jmap_parser_pop(parser);
            valid = 0;
        }
    }
    return valid;
}


HIDDEN const jmap_property_t *jmap_property_find(const char *name,
                                                 const jmap_property_t props[])
{
    const jmap_property_t *prop;

    for (prop = props; prop && prop->name; prop++) {
        if (!strcmp(name, prop->name)) return prop;
        else {
            size_t len = strlen(prop->name);
            if ((prop->name[len-1] == '*') && !strncmp(name, prop->name, len-1))
                return prop;
        }
    }

    return NULL;
}


/* Foo/get */

HIDDEN void jmap_get_parse(json_t *jargs,
                           struct jmap_parser *parser,
                           jmap_req_t *req,
                           const jmap_property_t valid_props[],
                           int (*args_parse)(const char *, json_t *,
                                             struct jmap_parser *, void *),
                           void *args_rock,
                           struct jmap_get *get,
                           int allow_null_ids,
                           json_t **err)
{
    const char *key;
    json_t *arg, *val;
    size_t i;

    memset(get, 0, sizeof(struct jmap_get));

    get->list = json_array();
    get->not_found = json_array();

    json_object_foreach(jargs, key, arg) {
        if (!strcmp(key, "accountId")) {
            /* already handled in jmap_api() */
        }

        else if (!strcmp(key, "ids")) {
            if (json_is_array(arg)) {
                get->ids = json_array();
                /* JMAP spec requires: "If an identical id is included
                 * more than once in the request, the server MUST only
                 * include it once in either the list or notFound
                 * argument of the response."
                 * So let's weed out duplicate ids here. */
                hash_table _dedup = HASH_TABLE_INITIALIZER;
                construct_hash_table(&_dedup, json_array_size(arg) + 1, 0);
                json_array_foreach(arg, i, val) {
                    const char *id = json_string_value(val);
                    if (!id) {
                        jmap_parser_push_index(parser, "ids", i, NULL);
                        jmap_parser_invalid(parser, NULL);
                        jmap_parser_pop(parser);
                        continue;
                    }
                    /* Weed out unknown creation ids and add the ids of known
                     * creation ids to the requested ids list. THis might
                     * cause a race if the Foo object pointed to by creation
                     * id is deleted between parsing the request and answering
                     * it. But re-checking creation ids for their existence
                     * later in the control flow just shifts the problem */
                    if (*id == '#') {
                        const char *id2 = jmap_lookup_id(req, id + 1);
                        if (!id2) {
                            json_array_append_new(get->not_found,
                                                  json_string(id));
                            continue;
                        }
                        id = id2;
                    }
                    if (hash_lookup(id, &_dedup)) {
                        continue;
                    }
                    json_array_append_new(get->ids, json_string(id));
                }
                free_hash_table(&_dedup, NULL);
            }
            else if (JNOTNULL(arg)) {
                jmap_parser_invalid(parser, "ids");
            }
        }

        else if (!strcmp(key, "properties")) {
            if (json_is_array(arg)) {
                get->props = xzmalloc(sizeof(hash_table));
                construct_hash_table(get->props, json_array_size(arg) + 1, 0);
                json_array_foreach(arg, i, val) {
                    const char *s = json_string_value(val);
                    if (!s || !jmap_property_find(s, valid_props)) {
                        jmap_parser_push_index(parser, "properties", i, s);
                        jmap_parser_invalid(parser, NULL);
                        jmap_parser_pop(parser);
                        continue;
                    }
                    hash_insert(s, (void*)1, get->props);
                }
            }
            else if (JNOTNULL(arg)) {
                jmap_parser_invalid(parser, "properties");
            }
        }

        else if (!args_parse || !args_parse(key, arg, parser, args_rock)) {
            jmap_parser_invalid(parser, key);
        }
    }

    if (json_array_size(parser->invalid)) {
        *err = json_pack("{s:s s:O}", "type", "invalidArguments",
                "arguments", parser->invalid);
        return;
    }

    if (!allow_null_ids && !JNOTNULL(get->ids)) {
        *err = json_pack("{s:s, s:s}", "type", "requestTooLarge",
                         "description", "ids must be specified");
        return;
    }

    /* Number of ids checked in validate_request() */ 
}

HIDDEN void jmap_get_fini(struct jmap_get *get)
{
    free_hash_table(get->props, NULL);
    free(get->props);
    free(get->state);
    json_decref(get->ids);
    json_decref(get->list);
    json_decref(get->not_found);
}

HIDDEN json_t *jmap_get_reply(struct jmap_get *get)
{
    json_t *res = json_object();
    json_object_set_new(res, "state", json_string(get->state));
    json_object_set(res, "list", get->list);
    json_object_set(res, "notFound", get->not_found);
    return res;
}


/* Foo/set */

HIDDEN void jmap_set_parse(json_t *jargs, struct jmap_parser *parser,
                           int (*args_parse)(const char *, json_t *,
                                             struct jmap_parser *, void *),
                           void *args_rock,
                           struct jmap_set *set, json_t **err)
{
    memset(set, 0, sizeof(struct jmap_set));
    set->create = json_object();
    set->update = json_object();
    set->destroy = json_array();
    set->created = json_object();
    set->updated = json_object();
    set->destroyed = json_array();
    set->not_created = json_object();
    set->not_updated = json_object();
    set->not_destroyed = json_object();

    const char *key;
    json_t *arg, *val;

    json_object_foreach(jargs, key, arg) {
        if (!strcmp(key, "accountId")) {
            /* already handled in jmap_api() */
        }

        /* ifInState */
        else  if (!strcmp(key, "ifInState")) {
            if (json_is_string(arg)) {
                set->if_in_state = json_string_value(arg);
            }
            else if (JNOTNULL(arg)) {
                jmap_parser_invalid(parser, "ifInState");
            }
        }

        /* create */
        else if (!strcmp(key, "create")) {
            if (json_is_object(arg)) {
                const char *id;
                json_object_foreach(arg, id, val) {
                    if (!json_is_object(val)) {
                        jmap_parser_push(parser, "create");
                        jmap_parser_invalid(parser, id);
                        jmap_parser_pop(parser);
                        continue;
                    }
                    json_object_set(set->create, id, val);
                }
            }
            else if (JNOTNULL(arg)) {
                jmap_parser_invalid(parser, "create");
            }
        }

        /* update */
        else if (!strcmp(key, "update")) {
            if (json_is_object(arg)) {
                const char *id;
                json_object_foreach(arg, id, val) {
                    if (!json_is_object(val)) {
                        jmap_parser_push(parser, "update");
                        jmap_parser_invalid(parser, id);
                        jmap_parser_pop(parser);
                        continue;
                    }
                    json_object_set(set->update, id, val);
                }
            }
            else if (JNOTNULL(arg)) {
                jmap_parser_invalid(parser, "update");
            }
        }

        /* destroy */
        else if (!strcmp(key, "destroy")) {
            if (JNOTNULL(arg)) {
                jmap_parse_strings(arg, parser, "destroy");
                if (!json_array_size(parser->invalid)) {
                    json_decref(set->destroy);
                    set->destroy = json_incref(arg);
                }
            }
        }

        else if (!args_parse || !args_parse(key, arg, parser, args_rock)) {
            jmap_parser_invalid(parser, key);
        }
    }

    // TODO We could report the following set errors here:
    // -invalidPatch
    // - willDestroy

    if (json_array_size(parser->invalid)) {
        *err = json_pack("{s:s s:O}", "type", "invalidArguments",
                "arguments", parser->invalid);
    }
}


HIDDEN void jmap_set_fini(struct jmap_set *set)
{
    free(set->old_state);
    free(set->new_state);
    json_decref(set->create);
    json_decref(set->update);
    json_decref(set->destroy);
    json_decref(set->created);
    json_decref(set->updated);
    json_decref(set->destroyed);
    json_decref(set->not_created);
    json_decref(set->not_updated);
    json_decref(set->not_destroyed);
}

HIDDEN json_t *jmap_set_reply(struct jmap_set *set)
{
    json_t *res = json_object();
    json_object_set_new(res, "oldState",
            set->old_state ? json_string(set->old_state) : json_null());
    json_object_set_new(res, "newState", json_string(set->new_state));
    json_object_set(res, "created", json_object_size(set->created) ?
            set->created : json_null());
    json_object_set(res, "updated", json_object_size(set->updated) ?
            set->updated : json_null());
    json_object_set(res, "destroyed", json_array_size(set->destroyed) ?
            set->destroyed : json_null());
    json_object_set(res, "notCreated", json_object_size(set->not_created) ?
            set->not_created : json_null());
    json_object_set(res, "notUpdated", json_object_size(set->not_updated) ?
            set->not_updated : json_null());
    json_object_set(res, "notDestroyed", json_object_size(set->not_destroyed) ?
            set->not_destroyed : json_null());
    return res;
}


/* Foo/changes */

HIDDEN void jmap_changes_parse(json_t *jargs,
                               struct jmap_parser *parser,
                               int (*args_parse)(const char *, json_t *,
                                                 struct jmap_parser *, void *),
                               void *args_rock,
                               struct jmap_changes *changes,
                               json_t **err)
{
    const char *key;
    json_t *arg;

    memset(changes, 0, sizeof(struct jmap_changes));
    changes->created = json_array();
    changes->updated = json_array();
    changes->destroyed = json_array();

    json_object_foreach(jargs, key, arg) {
        if (!strcmp(key, "accountId")) {
            /* already handled in jmap_api() */
        }

        /* sinceState */
        else if (!strcmp(key, "sinceState")) {
            if (json_is_string(arg)) {
                changes->since_modseq = atomodseq_t(json_string_value(arg));
            }
            if (!changes->since_modseq) {
                jmap_parser_invalid(parser, "sinceState");
            }
        }

        /* maxChanges */
        else if (!strcmp(key, "maxChanges")) {
            if (json_is_integer(arg) && json_integer_value(arg) > 0) {
                changes->max_changes = json_integer_value(arg);
            } else if (JNOTNULL(arg)) {
                jmap_parser_invalid(parser, "maxChanges");
            }
        }

        else if (!args_parse || !args_parse(key, arg, parser, args_rock)) {
            jmap_parser_invalid(parser, key);
        }
    }

    if (json_array_size(parser->invalid)) {
        *err = json_pack("{s:s s:O}", "type", "invalidArguments",
                "arguments", parser->invalid);
    }
}

HIDDEN void jmap_changes_fini(struct jmap_changes *changes)
{
    json_decref(changes->created);
    json_decref(changes->updated);
    json_decref(changes->destroyed);
}

HIDDEN json_t *jmap_changes_reply(struct jmap_changes *changes)
{
    json_t *res = json_object();
    json_object_set_new(res, "oldState", jmap_fmtstate(changes->since_modseq));
    json_object_set_new(res, "newState", jmap_fmtstate(changes->new_modseq));
    json_object_set_new(res, "hasMoreChanges",
            json_boolean(changes->has_more_changes));
    json_object_set(res, "created", changes->created);
    json_object_set(res, "updated", changes->updated);
    json_object_set(res, "destroyed", changes->destroyed);
    return res;
}


/* Foo/copy */

HIDDEN void jmap_copy_parse(json_t *jargs,
                            struct jmap_parser *parser, jmap_req_t *req,
                            void (*validate_props)(json_t *obj, json_t **err),
                            struct jmap_copy *copy, json_t **err)
{
    memset(copy, 0, sizeof(struct jmap_copy));
    copy->blob_copy = !strcmp(req->method, "Blob/copy");
    copy->create = copy->blob_copy ? json_array() : json_object();
    copy->created = json_object();
    copy->not_created = json_object();

    const char *key;
    json_t *arg;

    json_object_foreach(jargs, key, arg) {
        /* fromAccountId */
        if (!strcmp(key, "fromAccountId")) {
            if (json_is_string(arg)) {
                copy->from_account_id = json_string_value(arg);
            }
            else if (JNOTNULL(arg)) {
                jmap_parser_invalid(parser, "fromAccountId");
            }
        }

        /* toAccountId */
        else if (!strcmp(key, "toAccountId")) {
            if (json_is_string(arg)) {
                copy->to_account_id = json_string_value(arg);
            }
            else if (JNOTNULL(arg)) {
                jmap_parser_invalid(parser, "toAccountId");
            }
        }

        /* blobIds */
        else if (copy->blob_copy &&
                 !strcmp(key, "blobIds") && json_is_array(arg)) {
            struct buf buf = BUF_INITIALIZER;
            json_t *id;
            size_t i;
            json_array_foreach(arg, i, id) {
                if (!json_is_string(id)) {
                    buf_printf(&buf, "blobIds[%zu]", i);
                    jmap_parser_invalid(parser, buf_cstring(&buf));
                    buf_reset(&buf);
                }
                else json_array_append(copy->create, id);
            }
        }

        /* create */
        else if (!copy->blob_copy &&
                 !strcmp(key, "create") && json_is_object(arg)) {
            jmap_parser_push(parser, "create");
            const char *creation_id;
            json_t *obj;
            json_object_foreach(arg, creation_id, obj) {
                if (!json_is_object(obj)) {
                    jmap_parser_invalid(parser, creation_id);
                }
                else {
                    /* Validate properties */
                    json_t *myerr = NULL;
                    if (validate_props) validate_props(obj, &myerr);
                    if (myerr) {
                        json_object_set(copy->not_created, creation_id, myerr);
                    }
                    else {
                        json_object_set(copy->create, creation_id, obj);
                    }
                }
            }
            jmap_parser_pop(parser);
        }

        /* onSuccessDestroyOriginal */
        else if (!copy->blob_copy && !strcmp(key, "onSuccessDestroyOriginal") &&
                 json_is_boolean(arg)) {
            copy->on_success_destroy_original = json_boolean_value(arg);
        }

        else jmap_parser_invalid(parser, key);
    }

    if (json_array_size(parser->invalid)) {
        *err = json_pack("{s:s s:O}", "type", "invalidArguments",
                "arguments", parser->invalid);
    }

    if (!copy->from_account_id) {
        copy->from_account_id = req->accountid;
    }
    if (!copy->to_account_id) {
        copy->to_account_id = req->accountid;
    }
}


HIDDEN void jmap_copy_fini(struct jmap_copy *copy)
{
    json_decref(copy->create);
    json_decref(copy->created);
    json_decref(copy->not_created);
}

HIDDEN json_t *jmap_copy_reply(struct jmap_copy *copy)
{
    json_t *res = json_object();
    json_object_set_new(res, "fromAccountId",
                        json_string(copy->from_account_id));
    json_object_set_new(res, "toAccountId", json_string(copy->to_account_id));
    json_object_set(res, copy->blob_copy ? "copied" : "created",
                    json_object_size(copy->created) ?
                    copy->created : json_null());
    json_object_set(res, copy->blob_copy ? "notCopied" : "notCreated",
                    json_object_size(copy->not_created) ?
                    copy->not_created : json_null());
    return res;
}


/* Foo/query */

HIDDEN void jmap_filter_parse(json_t *filter, struct jmap_parser *parser,
                              jmap_filter_parse_cb parse_condition,
                              json_t *unsupported, void *rock)
{
    json_t *arg, *val;
    const char *s;
    size_t i;

    if (!JNOTNULL(filter) || json_typeof(filter) != JSON_OBJECT) {
        jmap_parser_invalid(parser, NULL);
        return;
    }
    arg = json_object_get(filter, "operator");
    if ((s = json_string_value(arg))) {
        if (strcmp("AND", s) && strcmp("OR", s) && strcmp("NOT", s)) {
            jmap_parser_invalid(parser, "operator");
        }
        arg = json_object_get(filter, "conditions");
        if (!json_array_size(arg)) {
            jmap_parser_invalid(parser, "conditions");
        }
        json_array_foreach(arg, i, val) {
            jmap_parser_push_index(parser, "conditions", i, NULL);
            jmap_filter_parse(val, parser, parse_condition, unsupported, rock);
            jmap_parser_pop(parser);
        }
    } else if (arg) {
        jmap_parser_invalid(parser, "operator");
    } else {
        parse_condition(filter, parser, unsupported, rock);
    }
}

HIDDEN void jmap_parse_comparator(json_t *jsort, struct jmap_parser *parser,
                                  jmap_comparator_parse_cb comp_cb,
                                  json_t *unsupported, void *rock)
{
    if (!json_is_object(jsort)) {
        jmap_parser_invalid(parser, NULL);
        return;
    }

    struct jmap_comparator comp = { NULL, 0, NULL };

    /* property */
    json_t *val = json_object_get(jsort, "property");
    comp.property = json_string_value(val);
    if (!comp.property) {
        jmap_parser_invalid(parser, "property");
    }

    /* isAscending */
    comp.is_ascending = 1;
    val = json_object_get(jsort, "isAscending");
    if (JNOTNULL(val)) {
        if (!json_is_boolean(val)) {
            jmap_parser_invalid(parser, "isAscending");
        }
        comp.is_ascending = json_boolean_value(val);
    }

    /* collation */
    val = json_object_get(jsort, "collation");
    if (JNOTNULL(val) && !json_is_string(val)) {
        jmap_parser_invalid(parser, "collation");
    }
    comp.collation = json_string_value(val);


    if (comp.property && !comp_cb(&comp, rock)) {
        struct buf buf = BUF_INITIALIZER;
        json_array_append_new(unsupported,
                json_string(jmap_parser_path(parser, &buf)));
        buf_free(&buf);
    }
}

HIDDEN void jmap_query_parse(json_t *jargs, struct jmap_parser *parser,
                             jmap_filter_parse_cb filter_cb, void *filter_rock,
                             jmap_comparator_parse_cb comp_cb, void *sort_rock,
                             int (*args_parse)(const char *, json_t *,
                                               struct jmap_parser *, void *),
                             void *args_rock,
                             struct jmap_query *query, json_t **err)
{
    const char *key;
    json_t *arg, *val;
    size_t i;

    memset(query, 0, sizeof(struct jmap_query));
    query->ids = json_array();

    json_t *unsupported_filter = json_array();
    json_t *unsupported_sort = json_array();

    json_object_foreach(jargs, key, arg) {
        if (!strcmp(key, "accountId")) {
            /* already handled in jmap_api() */
        }

        /* filter */
        else if (!strcmp(key, "filter")) {
            if (json_is_object(arg)) {
                jmap_parser_push(parser, "filter");
                jmap_filter_parse(arg, parser, filter_cb,
                                  unsupported_filter, filter_rock);
                jmap_parser_pop(parser);
                query->filter = arg;
            }
            else if (JNOTNULL(arg)) {
                jmap_parser_invalid(parser, "filter");
            }
        }

        /* sort */
        else if (!strcmp(key, "sort")) {
            if (json_is_array(arg)) {
                json_array_foreach(arg, i, val) {
                    jmap_parser_push_index(parser, "sort", i, NULL);
                    jmap_parse_comparator(val, parser,
                                          comp_cb, unsupported_sort, sort_rock);
                    jmap_parser_pop(parser);
                }
                if (json_array_size(arg)) {
                    query->sort = arg;
                }
            }
            else if (JNOTNULL(arg)) {
                jmap_parser_invalid(parser, "sort");
            }
        }

        else if (!strcmp(key, "position")) {
            if (json_is_integer(arg)) {
                query->position = json_integer_value(arg);
            }
            else if (arg) {
                jmap_parser_invalid(parser, "position");
            }
        }

        else if (!strcmp(key, "anchor")) {
            if (json_is_string(arg)) {
                query->anchor = json_string_value(arg);
            } else if (JNOTNULL(arg)) {
                jmap_parser_invalid(parser, "anchor");
            }
        }

        else if (!strcmp(key, "anchorOffset")) {
            if (json_is_integer(arg)) {
                query->anchor_offset = json_integer_value(arg);
            } else if (JNOTNULL(arg)) {
                jmap_parser_invalid(parser, "anchorOffset");
            }
        }

        else if (!strcmp(key, "limit")) {
            if (json_is_integer(arg) && json_integer_value(arg) >= 0) {
                query->limit = json_integer_value(arg);
                query->have_limit = 1;
            } else if (JNOTNULL(arg)) {
                jmap_parser_invalid(parser, "limit");
            }
        }

        else if (!strcmp(key, "calculateTotal")) {
            if (json_is_boolean(arg)) {
                query->calculate_total = json_boolean_value(arg);
            } else if (JNOTNULL(arg)) {
                jmap_parser_invalid(parser, "calculateTotal");
            }
        }

        else if (!args_parse || !args_parse(key, arg, parser, args_rock)) {
            jmap_parser_invalid(parser, key);
        }
    }

    if (json_array_size(parser->invalid)) {
        *err = json_pack("{s:s s:O}", "type", "invalidArguments",
                "arguments", parser->invalid);
    }
    else if (json_array_size(unsupported_filter)) {
        *err = json_pack("{s:s s:O}", "type", "unsupportedFilter",
                         "filters", unsupported_filter);
    }
    else if (json_array_size(unsupported_sort)) {
        *err = json_pack("{s:s s:O}", "type", "unsupportedSort",
                         "sort", unsupported_sort);
    }

    json_decref(unsupported_filter);
    json_decref(unsupported_sort);
}

HIDDEN void jmap_query_fini(struct jmap_query *query)
{
    free(query->query_state);
    json_decref(query->ids);
}

HIDDEN json_t *jmap_query_reply(struct jmap_query *query)
{

    json_t *res = json_object();
    json_object_set(res, "filter", query->filter);
    json_object_set(res, "sort", query->sort);
    json_object_set_new(res, "queryState", json_string(query->query_state));
    json_object_set_new(res, "canCalculateChanges",
                        json_boolean(query->can_calculate_changes));
    json_object_set_new(res, "position", json_integer(query->result_position));
    json_object_set_new(res, "total", json_integer(query->total));
    /* Special case total */
    if (query->position > 0 && query->total < SSIZE_MAX) {
        if (query->position > (ssize_t) query->total) {
            json_decref(query->ids);
            query->ids = json_array();
        }
    }
    /* Special case limit 0 */
    if (query->have_limit && query->limit == 0) {
        json_array_clear(query->ids);
    }

    json_object_set(res, "ids", query->ids);
    return res;
}


/* Foo/queryChanges */

HIDDEN void jmap_querychanges_parse(json_t *jargs,
                                    struct jmap_parser *parser,
                                    jmap_filter_parse_cb filter_cb,
                                    void *filter_rock,
                                    jmap_comparator_parse_cb comp_cb,
                                    void *sort_rock,
                                    int (*args_parse)(const char *, json_t *,
                                                      struct jmap_parser *,
                                                      void *),
                                    void *args_rock,
                                    struct jmap_querychanges *query,
                                    json_t **err)
{
    const char *key;
    json_t *arg, *val;
    size_t i;

    memset(query, 0, sizeof(struct jmap_querychanges));
    query->removed = json_array();
    query->added = json_array();

    json_t *unsupported_filter = json_array();
    json_t *unsupported_sort = json_array();

    json_object_foreach(jargs, key, arg) {
        if (!strcmp(key, "accountId")) {
            /* already handled in jmap_api() */
        }

        /* filter */
        else if (!strcmp(key, "filter")) {
            if (json_is_object(arg)) {
                jmap_parser_push(parser, "filter");
                jmap_filter_parse(arg, parser, filter_cb,
                                  unsupported_filter, filter_rock);
                jmap_parser_pop(parser);
                query->filter = arg;
            }
            else if (JNOTNULL(arg)) {
                jmap_parser_invalid(parser, "filter");
            }
        }

        /* sort */
        else if (!strcmp(key, "sort")) {
            if (json_is_array(arg)) {
                json_array_foreach(arg, i, val) {
                    jmap_parser_push_index(parser, "sort", i, NULL);
                    jmap_parse_comparator(val, parser, comp_cb,
                                          unsupported_sort, sort_rock);
                    jmap_parser_pop(parser);
                }
                if (json_array_size(arg)) {
                    query->sort = arg;
                }
            }
            else if (JNOTNULL(arg)) {
                jmap_parser_invalid(parser, "sort");
            }
        }

        /* sinceQueryState */
        else if (!strcmp(key, "sinceQueryState")) {
            if (json_is_string(arg)) {
                query->since_querystate = json_string_value(arg);
            } else {
                jmap_parser_invalid(parser, "sinceQueryState");
            }
        }

        /* maxChanges */
        else if (!strcmp(key, "maxChanges")) {
            if (json_is_integer(arg) && json_integer_value(arg) > 0) {
                query->max_changes = json_integer_value(arg);
            } else if (JNOTNULL(arg)) {
                jmap_parser_invalid(parser, "maxChanges");
            }
        }

        /* upToId */
        else if (!strcmp(key, "upToId")) {
            if (json_is_string(arg)) {
                query->up_to_id = json_string_value(arg);
            } else if (JNOTNULL(arg)) {
                jmap_parser_invalid(parser, "upToId");
            }
        }

        /* calculateTotal */
        else if (!strcmp(key, "calculateTotal")) {
            if (json_is_boolean(arg)) {
                query->calculate_total = json_boolean_value(arg);
            } else if (JNOTNULL(arg)) {
                jmap_parser_invalid(parser, "calculateTotal");
            }
        }

        else if (!args_parse || !args_parse(key, arg, parser, args_rock)) {
            jmap_parser_invalid(parser, key);
        }
    }

    if (query->since_querystate == NULL) {
        jmap_parser_invalid(parser, "sinceQueryState");
    }

    if (json_array_size(parser->invalid)) {
        *err = json_pack("{s:s s:O}", "type", "invalidArguments",
                         "arguments", parser->invalid);
    }
    else if (json_array_size(unsupported_filter)) {
        *err = json_pack("{s:s s:O}", "type", "unsupportedFilter",
                         "filters", unsupported_filter);
    }
    else if (json_array_size(unsupported_sort)) {
        *err = json_pack("{s:s s:O}", "type", "unsupportedSort",
                         "sort", unsupported_sort);
    }

    json_decref(unsupported_filter);
    json_decref(unsupported_sort);
}

HIDDEN void jmap_querychanges_fini(struct jmap_querychanges *query)
{
    free(query->new_querystate);
    json_decref(query->removed);
    json_decref(query->added);
}

HIDDEN json_t *jmap_querychanges_reply(struct jmap_querychanges *query)
{
    json_t *res = json_object();
    json_object_set(res, "filter", query->filter);
    json_object_set(res, "sort", query->sort);
    json_object_set_new(res, "oldQueryState",
                        json_string(query->since_querystate));
    json_object_set_new(res, "newQueryState",
                        json_string(query->new_querystate));
    json_object_set_new(res, "upToId", query->up_to_id ?
            json_string(query->up_to_id) : json_null());
    json_object_set(res, "removed", query->removed);
    json_object_set(res, "added", query->added);
    json_object_set_new(res, "total", json_integer(query->total));
    return res;
}
