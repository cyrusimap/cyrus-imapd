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

#include "hash.h"
#include "httpd.h"
#include "http_dav.h"

/* generated headers are not necessarily in current directory */
#include "imap/http_err.h"
#include "imap/imap_err.h"

#include "http_jmap.h"
#include "syslog.h"

struct namespace jmap_namespace;

static time_t compile_time;
static void jmap_init(struct buf *serverinfo);
static void jmap_auth(const char *userid);
static int jmap_get(struct transaction_t *txn, void *params);
static int jmap_post(struct transaction_t *txn, void *params);

/* Namespace for JMAP */
struct namespace_t namespace_jmap = {
    URL_NS_JMAP, 0, "/jmap", "/.well-known/jmap", 1 /* auth */,
    /*mbtype*/0, 
    (ALLOW_READ | ALLOW_POST),
    &jmap_init, &jmap_auth, NULL, NULL, NULL,
    {
        { NULL,                 NULL },                 /* ACL          */
        { NULL,                 NULL },                 /* BIND         */
        { NULL,                 NULL },                 /* COPY         */
        { NULL,                 NULL },                 /* DELETE       */
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

static void jmap_init(struct buf *serverinfo __attribute__((unused)))
{
    namespace_jmap.enabled =
        config_httpmodules & IMAP_ENUM_HTTPMODULES_JMAP;

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

    search_attr_init();
}


static void jmap_auth(const char *userid __attribute__((unused)))
{
    /* Set namespace */
    mboxname_init_namespace(&jmap_namespace,
                            httpd_userisadmin || httpd_userisproxyadmin);
}


/* Perform a GET/HEAD request */
static int jmap_get(struct transaction_t *txn,
                    void *params __attribute__((unused)))
{
    if (!strncmp(txn->req_uri->path, "/jmap/download/", 15))
        return jmap_download(txn);

    return HTTP_NOT_FOUND;
}

/* Perform a POST request */
static int jmap_post(struct transaction_t *txn,
                     void *params __attribute__((unused)))
{
    const char **hdr;
    json_t *req, *resp = NULL;
    json_error_t jerr;
    struct hash_table idmap;
    size_t i, flags = JSON_PRESERVE_ORDER;
    int ret;
    char *buf, *inboxname = NULL;

    /* Read body */
    txn->req_body.flags |= BODY_DECODE;
    ret = http_read_body(httpd_in, httpd_out,
                       txn->req_hdrs, &txn->req_body, &txn->error.desc);

    if (ret) {
        txn->flags.conn = CONN_CLOSE;
        return ret;
    }

    if (!strncmp(txn->req_uri->path, "/jmap/upload", 12)) {
        return jmap_upload(txn);
    }

    if (!buf_len(&txn->req_body.payload)) return HTTP_BAD_REQUEST;

    /* Check Content-Type */
    if (!(hdr = spool_getheader(txn->req_hdrs, "Content-Type")) ||
        !is_mediatype("application/json", hdr[0])) {
        txn->error.desc = "This method requires a JSON request body\r\n";
        return HTTP_BAD_MEDIATYPE;
    }

    /* Allocate map to store uids */
    construct_hash_table(&idmap, 1024, 0);

    /* Parse the JSON request */
    req = json_loads(buf_cstring(&txn->req_body.payload), 0, &jerr);
    if (!req || !json_is_array(req)) {
        txn->error.desc = "Unable to parse JSON request body\r\n";
        ret = HTTP_BAD_REQUEST;
        goto done;
    }

    /* Start JSON response */
    resp = json_array();
    if (!resp) {
        txn->error.desc = "Unable to create JSON response body\r\n";
        ret = HTTP_SERVER_ERROR;
        goto done;
    }

    inboxname = mboxname_user_mbox(httpd_userid, NULL);

    /* Process each message in the request */
    for (i = 0; i < json_array_size(req); i++) {
        const jmap_msg_t *mp;
        json_t *msg = json_array_get(req, i);
        const char *tag, *name = json_string_value(json_array_get(msg, 0));
        json_t *args = json_array_get(msg, 1);
        json_t *id = json_array_get(msg, 2);
        int r = 0;

        /* XXX - better error reporting */
        if (!id) {
            txn->error.desc = "Missing id on request\n";
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

        struct conversations_state *cstate = NULL;
        r = conversations_open_user(httpd_userid, &cstate);
        if (r) {
            txn->error.desc = error_message(r);
            ret = HTTP_SERVER_ERROR;
            goto done;
        }

        struct jmap_req req;
        req.userid = httpd_userid;
        req.inboxname = inboxname;
        req.cstate = cstate;
        req.authstate = httpd_authstate;
        req.args = args;
        req.response = resp;
        req.tag = tag;
        req.idmap = &idmap;
        req.txn = txn;

        /* Read the modseq counters again, just in case something changed. */
        r = mboxname_read_counters(inboxname, &req.counters);
        if (r) goto done;

        /* Call the message processor. */
        r = mp->proc(&req);

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
    free_hash_table(&idmap, free);
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

struct _req_context {
    ptrarray_t *cache;
};

EXPORTED int jmap_initreq(jmap_req_t *req)
{
    struct _req_context *ctx = xzmalloc(sizeof(struct _req_context));
    ctx->cache = ptrarray_new();
    req->rock = ctx;
    return 0;
}

EXPORTED void jmap_finireq(jmap_req_t *req)
{
    struct _req_context *ctx = (struct _req_context *) req->rock;

    if (!ctx) return;

    assert(ctx->cache->count == 0);
    ptrarray_free(ctx->cache);

    free(ctx);
    req->rock = NULL;
}

EXPORTED int jmap_openmbox(jmap_req_t *req, const char *name, struct mailbox **mboxp, int rw)
{
    int i, r;
    ptrarray_t* cache = ((struct _req_context*)req->rock)->cache;
    struct _mboxcache_rec *rec;

    for (i = 0; i < cache->count; i++) {
        rec = (struct _mboxcache_rec*) ptrarray_nth(cache, i);
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
    ptrarray_add(cache, rec);

    return 0;
}

EXPORTED int jmap_isopenmbox(jmap_req_t *req, const char *name)
{

    int i;
    ptrarray_t* cache = ((struct _req_context*)req->rock)->cache;
    struct _mboxcache_rec *rec;

    for (i = 0; i < cache->count; i++) {
        rec = (struct _mboxcache_rec*) ptrarray_nth(cache, i);
        if (!strcmp(name, rec->mbox->name))
            return 1;
    }

    return 0;
}

EXPORTED void jmap_closembox(jmap_req_t *req, struct mailbox **mboxp)
{
    ptrarray_t* cache = ((struct _req_context*)req->rock)->cache;
    struct _mboxcache_rec *rec = NULL;
    int i;

    for (i = 0; i < cache->count; i++) {
        rec = (struct _mboxcache_rec*) ptrarray_nth(cache, i);
        if (rec->mbox == *mboxp)
            break;
    }
    assert(i < cache->count);

    if (!(--rec->refcount)) {
        ptrarray_remove(cache, i);
        mailbox_close(&rec->mbox);
        free(rec);
    }
    *mboxp = NULL;
}
