/* http_jmap.c -- Routines for handling JMAP requests in httpd
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

#include <errno.h>

#include "acl.h"
#include "append.h"
#include "httpd.h"
#include "http_jmap.h"
#include "http_proxy.h"
#include "http_ws.h"
#include "mboxname.h"
#include "proxy.h"
#include "times.h"
#include "sync_support.h"
#include "syslog.h"
#include "user.h"
#include "xstrlcpy.h"

/* generated headers are not necessarily in current directory */
#include "imap/http_err.h"
#include "imap/imap_err.h"
#include "imap/jmap_err.h"


#define JMAP_ROOT          "/jmap"
#define JMAP_BASE_URL      JMAP_ROOT "/"
#define JMAP_WS_COL        "ws/"
#define JMAP_UPLOAD_COL    "upload/"
#define JMAP_UPLOAD_TPL    "{accountId}/"
#define JMAP_DOWNLOAD_COL  "download/"
#define JMAP_DOWNLOAD_TPL  "{accountId}/{blobId}/{name}?accept={type}"
#define JMAP_EVENTSOURCE_COL  "eventsource/"
#define JMAP_EVENTSOURCE_TPL  "?types={types}&closeafter={closeafter}&ping={ping}"

struct namespace jmap_namespace;

static time_t compile_time;


/* Namespace callbacks */
static void jmap_init(struct buf *serverinfo);
static int  jmap_need_auth(struct transaction_t *txn);
static int  jmap_auth(const char *userid);
static void jmap_reset(void);
static void jmap_shutdown(void);

/* HTTP method handlers */
static int meth_get(struct transaction_t *txn, void *params);
static int meth_options_jmap(struct transaction_t *txn, void *params);
static int meth_post(struct transaction_t *txn, void *params);

/* JMAP Requests */
static int jmap_get_session(struct transaction_t *txn);
static int jmap_download(struct transaction_t *txn);
static int jmap_upload(struct transaction_t *txn);
static int jmap_eventsource(struct transaction_t *txn);

/* WebSocket handler */
#define JMAP_WS_PROTOCOL   "jmap"

static ws_data_callback jmap_ws;

static struct connect_params ws_params = {
    JMAP_BASE_URL JMAP_WS_COL, JMAP_WS_PROTOCOL, &jmap_ws
};


/* Namespace for JMAP */
struct namespace_t namespace_jmap = {
    URL_NS_JMAP, 0, "jmap", JMAP_ROOT, "/.well-known/jmap",
    jmap_need_auth, /*authschemes*/0,
    /*mbtype*/0, 
    (ALLOW_READ | ALLOW_POST | ALLOW_READONLY),
    &jmap_init, &jmap_auth, &jmap_reset, &jmap_shutdown, NULL, /*bearer*/NULL,
    {
        { NULL,                 NULL },                 /* ACL          */
        { NULL,                 NULL },                 /* BIND         */
        { &meth_connect,        &ws_params },           /* CONNECT      */
        { NULL,                 NULL },                 /* COPY         */
        { NULL,                 NULL },                 /* DELETE       */
        { &meth_get,            NULL },                 /* GET          */
        { &meth_get,            NULL },                 /* HEAD         */
        { NULL,                 NULL },                 /* LOCK         */
        { NULL,                 NULL },                 /* MKCALENDAR   */
        { NULL,                 NULL },                 /* MKCOL        */
        { NULL,                 NULL },                 /* MOVE         */
        { &meth_options_jmap,   NULL },                 /* OPTIONS      */
        { NULL,                 NULL },                 /* PATCH        */
        { &meth_post,           NULL },                 /* POST         */
        { NULL,                 NULL },                 /* PROPFIND     */
        { NULL,                 NULL },                 /* PROPPATCH    */
        { NULL,                 NULL },                 /* PUT          */
        { NULL,                 NULL },                 /* REPORT       */
        { &meth_trace,          NULL },                 /* TRACE        */
        { NULL,                 NULL },                 /* UNBIND       */
        { NULL,                 NULL }                  /* UNLOCK       */
    }
};


/*
 * Namespace callbacks
 */

static jmap_settings_t my_jmap_settings = {
    HASH_TABLE_INITIALIZER,
    NULL,
    { 0 },
    PTRARRAY_INITIALIZER,
    PTRARRAY_INITIALIZER
};

static void jmap_init(struct buf *serverinfo)
{
#ifdef USE_XAPIAN
#include "xapian_wrap.h"
    buf_printf(serverinfo, " Xapian/%s", xapian_version_string());
#endif

    namespace_jmap.enabled =
        config_httpmodules & IMAP_ENUM_HTTPMODULES_JMAP;

    if (namespace_jmap.enabled && !config_getswitch(IMAPOPT_CONVERSATIONS)) {
        syslog(LOG_ERR,
               "ERROR: cannot enable %s module with conversations disabled",
               namespace_jmap.name);
        namespace_jmap.enabled = 0;
    }

    if (!namespace_jmap.enabled) return;

    compile_time = calc_compile_time(__TIME__, __DATE__);

    initialize_JMAP_error_table();

    construct_hash_table(&my_jmap_settings.methods, 128, 0);
    my_jmap_settings.server_capabilities = json_object();

    jmap_core_init(&my_jmap_settings);
    jmap_mail_init(&my_jmap_settings);
    jmap_mdn_init(&my_jmap_settings);
    jmap_contact_init(&my_jmap_settings);
    jmap_calendar_init(&my_jmap_settings);
    jmap_backup_init(&my_jmap_settings);
    jmap_notes_init(&my_jmap_settings);
#ifdef USE_SIEVE
    jmap_sieve_init(&my_jmap_settings);
#endif

    if (ws_enabled()) {
        json_object_set_new(my_jmap_settings.server_capabilities,
                JMAP_URN_WEBSOCKET,
                json_pack("{s:s s:b}",
                          "webSocketUrl", "wss:" JMAP_BASE_URL JMAP_WS_COL,
                          "supportsWebSocketPush", 0));
    }
}

static int jmap_auth(const char *userid __attribute__((unused)))
{
    /* Set namespace */
    mboxname_init_namespace(&jmap_namespace,
                            httpd_userisadmin || httpd_userisproxyadmin);
    return 0;
}

static int jmap_need_auth(struct transaction_t *txn __attribute__((unused)))
{
    /* All endpoints require authentication */
    return HTTP_UNAUTHORIZED;
}

static void jmap_reset(void)
{
    int i;
    for (i = 0; i < ptrarray_size(&my_jmap_settings.event_handlers); i++) {
        struct jmap_handler *h =
            ptrarray_nth(&my_jmap_settings.event_handlers, i);
        if (h->eventmask & JMAP_HANDLE_CLOSE_CONN) {
            h->handler(JMAP_HANDLE_CLOSE_CONN, NULL, h->rock);
        }
    }
}

static void jmap_shutdown(void)
{
    free_hash_table(&my_jmap_settings.methods, NULL);
    json_decref(my_jmap_settings.server_capabilities);
    ptrarray_fini(&my_jmap_settings.getblob_handlers);
    int i;
    for (i = 0; i < ptrarray_size(&my_jmap_settings.event_handlers); i++) {
        struct jmap_handler *h =
            ptrarray_nth(&my_jmap_settings.event_handlers, i);
        if (h->eventmask & JMAP_HANDLE_SHUTDOWN) {
            h->handler(JMAP_HANDLE_SHUTDOWN, NULL, h->rock);
        }
        free(h);
    }
    ptrarray_fini(&my_jmap_settings.event_handlers);
}   


/*
 * HTTP method handlers
 */

enum {
    JMAP_ENDPOINT_API,
    JMAP_ENDPOINT_WS,
    JMAP_ENDPOINT_UPLOAD,
    JMAP_ENDPOINT_DOWNLOAD,
    JMAP_ENDPOINT_EVENTSOURCE
};

static int jmap_parse_path(struct transaction_t *txn)
{
    struct request_target_t *tgt = &txn->req_tgt;
    size_t len;
    char *p;

    if (*tgt->path) return 0;  /* Already parsed */

    /* Make a working copy of target path */
    strlcpy(tgt->path, txn->req_uri->path, sizeof(tgt->path));
    p = tgt->path;

    /* Sanity check namespace */
    len = strlen(namespace_jmap.prefix);
    if (strlen(p) < len ||
        strncmp(namespace_jmap.prefix, p, len) ||
        (tgt->path[len] && tgt->path[len] != '/')) {
        txn->error.desc = "Namespace mismatch request target path";
        return HTTP_FORBIDDEN;
    }

    /* Skip namespace */
    p += len;
    if (!*p) {
        /* Canonicalize URL */
        txn->location = JMAP_BASE_URL;
        return HTTP_MOVED;
    }

    /* Check for path after prefix */
    if (*++p) {
        /* Get "collection" */
        tgt->collection = p;

        if (!strncmp(tgt->collection, JMAP_UPLOAD_COL,
                          strlen(JMAP_UPLOAD_COL))) {
            tgt->flags = JMAP_ENDPOINT_UPLOAD;
            tgt->allow = ALLOW_POST;

            /* Get "resource" which must be the accountId */
            tgt->resource = tgt->collection + strlen(JMAP_UPLOAD_COL);
        }
        else if (!strncmp(tgt->collection,
                          JMAP_DOWNLOAD_COL, strlen(JMAP_DOWNLOAD_COL))) {
            tgt->flags = JMAP_ENDPOINT_DOWNLOAD;
            tgt->allow = ALLOW_READ;

            /* Get "resource" */
            tgt->resource = tgt->collection + strlen(JMAP_DOWNLOAD_COL);
        }
        else if (ws_enabled() && !strcmp(tgt->collection, JMAP_WS_COL)) {
            tgt->flags = JMAP_ENDPOINT_WS;
            tgt->allow = (txn->flags.ver == VER_2) ? ALLOW_CONNECT : ALLOW_READ;
        }
        else if (!strncmp(tgt->collection,
                          JMAP_EVENTSOURCE_COL, strlen(JMAP_EVENTSOURCE_COL))) {
            tgt->flags = JMAP_ENDPOINT_EVENTSOURCE;
            tgt->allow = ALLOW_READ;
        }
        else {
            return HTTP_NOT_FOUND;
        }
    }
    else {
        tgt->flags = JMAP_ENDPOINT_API;
        tgt->allow = ALLOW_POST|ALLOW_READ;
    }

    return 0;
}

/* Perform a GET/HEAD request */
static int meth_get(struct transaction_t *txn,
                    void *params __attribute__((unused)))
{
    int r = jmap_parse_path(txn);

    if (!(txn->req_tgt.allow & ALLOW_READ)) {
        return HTTP_NOT_FOUND;
    }
    else if (r) return r;

    if (txn->req_tgt.flags == JMAP_ENDPOINT_API) {
        return jmap_get_session(txn);
    }
    else if (txn->req_tgt.flags == JMAP_ENDPOINT_DOWNLOAD) {
        return jmap_download(txn);
    }
    /* Upgrade to WebSockets over HTTP/1.1 on WS endpoint, if requested */
    else if ((txn->req_tgt.flags == JMAP_ENDPOINT_WS) &&
             (txn->flags.upgrade & UPGRADE_WS)) {
        return ws_start_channel(txn, JMAP_WS_PROTOCOL, &jmap_ws);
    }
    else if (txn->req_tgt.flags == JMAP_ENDPOINT_EVENTSOURCE) {
        return jmap_eventsource(txn);
    }

    return HTTP_NO_CONTENT;
}

static int parse_json_body(struct transaction_t *txn, json_t **req)
{
    json_error_t jerr;

    /* Parse the JSON request */
    *req = json_loadb(buf_base(&txn->req_body.payload),
                      buf_len(&txn->req_body.payload),
                      0, &jerr);
    if (!*req) {
        buf_reset(&txn->buf);
        buf_printf(&txn->buf,
                   "Unable to parse JSON request body: %s", jerr.text);
        txn->error.desc = buf_cstring(&txn->buf);
        return JMAP_NOT_JSON;
    }

    return 0;
}

static int json_response(int code, struct transaction_t *txn, json_t *root)
{
    size_t flags = JSON_PRESERVE_ORDER;
    char *buf;

    /* Dump JSON object into a text buffer */
    flags |= (config_httpprettytelemetry ? JSON_INDENT(2) : JSON_COMPACT);
    buf = json_dumps(root, flags);
    json_decref(root);

    if (!buf) {
        txn->error.desc = "Error dumping JSON object";
        return HTTP_SERVER_ERROR;
    }

    /* Output the JSON object */
    switch (code) {
    case 0:
        /* API request over WebSocket */
        buf_initm(&txn->resp_body.payload, buf, strlen(buf));
        return 0;

    case HTTP_OK:
    case HTTP_CREATED:
        txn->resp_body.type = "application/json; charset=utf-8";
        break;
    default:
        txn->resp_body.type = "application/problem+json; charset=utf-8";
        break;
    }

    write_body(code, txn, buf, strlen(buf));
    free(buf);

    return 0;
}

/* Perform a POST request */
static int meth_post(struct transaction_t *txn,
                     void *params __attribute__((unused)))
{
    int ret;
    json_t *req = NULL, *res = NULL;

    ret = jmap_parse_path(txn);

    if (ret) return ret;
    if (!(txn->req_tgt.allow & ALLOW_POST)) {
        return HTTP_NOT_ALLOWED;
    }

    /* Handle uploads */
    if (txn->req_tgt.flags == JMAP_ENDPOINT_UPLOAD) {
        return jmap_upload(txn);
    }

    /* Regular JMAP API request */
    txn->req_body.flags |= BODY_DECODE;

    /* Check Content-Type */
    const char **hdr = spool_getheader(txn->req_hdrs, "Content-Type");
    if (!hdr ||
        !is_mediatype("application/json", hdr[0])) {
        txn->error.desc = "This method requires a JSON request body";
        ret = HTTP_BAD_MEDIATYPE;
    }

    /* Read body */
    else if ((ret = http_read_req_body(txn))) {
        txn->flags.conn = CONN_CLOSE;
    }

    /* Parse the JSON request */
    else if (!(ret = parse_json_body(txn, &req))) {
        ret = jmap_api(txn, req, &res, &my_jmap_settings);
        json_decref(req);
    }

    if (ret) ret = jmap_error_response(txn, ret, &res);
        
    /* ensure we didn't leak anything! */
    assert(!open_mailboxes_exist());
    assert(!open_mboxlocks_exist());

    // checkpoint before we reply
    sync_checkpoint(httpd_in);

    if (res) {
        /* Output the JSON object */
        ret = json_response(ret ? ret : HTTP_OK, txn, res);
    }

    syslog(LOG_DEBUG, ">>>> jmap_post: Exit");
    return ret;
}

/* Perform an OPTIONS request */
static int meth_options_jmap(struct transaction_t *txn, void *params)
{
    /* Parse the path */
    int r = jmap_parse_path(txn);
    if (r) return r;

    return meth_options(txn, params);
}


/*
 * JMAP Requests
 */

static char *parse_accept_header(const char **hdr)
{
    char *val = NULL;
    struct accept *accept = parse_accept(hdr);
    if (accept) {
        char *type = NULL;
        char *subtype = NULL;
        struct param *params = NULL;
        message_parse_type(accept->token, &type, &subtype, &params);
        if (type && subtype && !strchr(type, '*') && !strchr(subtype, '*'))
            val = xstrdup(accept->token);
        free(type);
        free(subtype);
        param_free(&params);
        struct accept *tmp;
        for (tmp = accept; tmp && tmp->token; tmp++) {
            free(tmp->token);
        }
        free(accept);
    }
    return val;
}

static int jmap_getblob_default_handler(jmap_req_t *req,
                                        jmap_getblob_context_t *ctx)
{
    struct mailbox *mbox = NULL;
    msgrecord_t *mr = NULL;
    struct body *body = NULL;
    const struct body *part = NULL;
    int res = HTTP_OK;

    /* Find part containing blob */
    int r = jmap_findblob(req, ctx->from_accountid, ctx->blobid,
                          &mbox, &mr, &body, &part, &ctx->blob);
    if (r) {
        res = HTTP_NOT_FOUND; // XXX errors?
        ctx->errstr = "failed to find blob by id";
        goto done;
    }

    // default with no part is the whole message

    if (ctx->accept_mime) {
        /* XXX  Can we be smarter here and test against part->[sub]type ? */
        ctx->content_type = xstrdup(ctx->accept_mime);
    }

    if (part) {
        // map into just this part
        const char *base = buf_base(&ctx->blob) + part->content_offset;
        size_t len = part->content_size;
        char *decbuf = NULL;

        // binary decode if needed
        int encoding = part->charset_enc & 0xff;
        base = charset_decode_mimebody(base, len, encoding, &decbuf, &len);

        if (!base) {
            res = HTTP_NOT_FOUND; // XXX errors?
            ctx->errstr = "failed to decode blob";
            goto done;
        }
        else if (decbuf) {
            buf_initm(&ctx->blob, decbuf, len);
            ctx->encoding = xstrdup("BINARY");
        }
        else {
            /* Skip headers */
            buf_remove(&ctx->blob, 0, part->content_offset);
            buf_truncate(&ctx->blob, part->content_size);
            ctx->encoding = xstrdup(part->encoding);
        }
    }

 done:
    if (mbox) jmap_closembox(req, &mbox);
    if (body) {
        message_free_body(body);
        free(body);
    }
    if (mr) {
        msgrecord_unref(&mr);
    }
    return res;
}

HIDDEN int jmap_getblob(jmap_req_t *req, jmap_getblob_context_t *ctx)
{
    int res = 0;

    if (!ctx->blobid) return HTTP_NOT_FOUND;

    /* Call getblob handlers */
    int i;
    for (i = 0; i < ptrarray_size(&my_jmap_settings.getblob_handlers); i++) {
        jmap_getblob_handler *handler =
            ptrarray_nth(&my_jmap_settings.getblob_handlers, i);

        jmap_getblob_ctx_reset(ctx);
        res = handler(req, ctx);
        if (res) break;
    }

    if (!res) {
        /* Try default getblob handler */
        jmap_getblob_ctx_reset(ctx);
        res = jmap_getblob_default_handler(req, ctx);
    }

    if (res == HTTP_OK) return 0;

    return res;
}

/* Handle a GET on the download endpoint */
static int jmap_download(struct transaction_t *txn)
{
    const char *userid = txn->req_tgt.resource;
    const char *slash = strchr(userid, '/');
    if (!slash) {
        /* XXX - error, needs AccountId */
        return HTTP_NOT_FOUND;
    }

    const char *blobbase = slash + 1;
    slash = strchr(blobbase, '/');
    if (!slash) {
        /* XXX - error, needs blobid */
        txn->error.desc = "failed to find blobid";
        return HTTP_BAD_REQUEST;
    }
    size_t bloblen = slash - blobbase;
    const char *fname = slash + 1;

    /* now we're allocating memory, so don't return from here! */

    char *accountid = xstrndup(userid, strchr(userid, '/') - userid);
    int res = 0;

    struct conversations_state *cstate = NULL;
    int r = conversations_open_user(accountid, 1/*shared*/, &cstate);
    if (r) {
        txn->error.desc = error_message(r);
        res = (r == IMAP_MAILBOX_BADNAME) ? HTTP_NOT_FOUND : HTTP_SERVER_ERROR;
        free(accountid);
        return res;
    }

    char *blobid = NULL;
    char *accept_mime = NULL;

    /* Initialize request context */
    struct jmap_req req;
    jmap_initreq(&req);

    req.userid = httpd_userid;
    req.accountid = accountid;
    req.cstate = cstate;
    req.authstate = httpd_authstate;
    req.txn = txn;

    /* Initialize ACL mailbox cache for findblob */
    hash_table mbstates = HASH_TABLE_INITIALIZER;
    construct_hash_table(&mbstates, 64, 0);
    req.mbstates = &mbstates;

    blobid = xstrndup(blobbase, bloblen);

    struct strlist *param;
    if ((param = hash_lookup("accept", &txn->req_qparams))) {
        accept_mime = xstrdup(param->s);
    }

    const char **hdr;
    if (!accept_mime && (hdr = spool_getheader(txn->req_hdrs, "Accept"))) {
        accept_mime = parse_accept_header(hdr);
    }

    /* Call blob download handlers */
    jmap_getblob_context_t ctx;
    jmap_getblob_ctx_init(&ctx, accountid, blobid, accept_mime, 1);
    res = jmap_getblob(&req, &ctx);
    if (res) {
        txn->error.desc = ctx.errstr ? ctx.errstr : error_message(res);
    }
    else {
        /* Set Content-Disposition header */
        txn->resp_body.dispo.attach = fname != NULL;
        txn->resp_body.dispo.fname = fname;

        /* Set Cache-Control directives */
        txn->resp_body.maxage = 604800;  /* 7 days */
        txn->flags.cc |= CC_MAXAGE | CC_PRIVATE | CC_IMMUTABLE;

        /* Write body */
        txn->resp_body.type =
            ctx.content_type ? ctx.content_type : "application/octet-stream";
        txn->resp_body.len = buf_len(&ctx.blob);
        write_body(HTTP_OK, txn, buf_base(&ctx.blob), buf_len(&ctx.blob));
    }

    jmap_getblob_ctx_fini(&ctx);
    free_hash_table(&mbstates, free);
    conversations_commit(&cstate);
    free(accept_mime);
    free(accountid);
    free(blobid);
    jmap_finireq(&req);
    return res;
}

static int has_shared_rw_rights_cb(const mbentry_t *mbentry, void *vrock)
{
    int *rights = (int *) vrock;

    /* skip any special use folders */
    if (mbentry->mbtype &&
        !(mbentry->mbtype & (MBTYPE_CALENDAR | MBTYPE_ADDRESSBOOK))) {
        return 0;
    }

    *rights |= (httpd_myrights(httpd_authstate, mbentry) & JACL_ADDITEMS);

    if (*rights) {
        /* one writable mailbox is enough to short-circuit the search */
        return CYRUSDB_DONE;
    }
    
    return 0;
}

/* See if this account has shared any mailbox with the authenticated user */
static int has_shared_rw_rights(const char *accountid)
{
    int rights = 0;

    mboxlist_usermboxtree(accountid, NULL, &has_shared_rw_rights_cb, &rights, 0);

    return rights;
}

static int lookup_upload_collection(const char *accountid, mbentry_t **mbentry)
{
    mbname_t *mbname;
    const char *uploadname;
    int r;

    /* Create upload mailbox name from the parsed path */
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
    r = proxy_mlookup(uploadname, mbentry, NULL, NULL);
    if (r == IMAP_MAILBOX_NONEXISTENT) {
        /* Find location of INBOX */
        char *inboxname = mboxname_user_mbox(accountid, NULL);

        int r1 = proxy_mlookup(inboxname, mbentry, NULL, NULL);
        free(inboxname);
        if (r1 == IMAP_MAILBOX_NONEXISTENT) {
            r = IMAP_INVALID_USER;
            goto done;
        }

        if (!strcmp(accountid, httpd_userid)) {
            int rights = httpd_myrights(httpd_authstate, *mbentry);
            if (!(rights & ACL_CREATE)) {
                r = IMAP_PERMISSION_DENIED;
                goto done;
            }
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

static int _create_upload_collection(const char *accountid,
                                     struct mailbox **mailbox)
{
    /* upload collection */
    struct mboxlock *namespacelock = user_namespacelock(accountid);
    mbentry_t *mbentry = NULL;
    int r = lookup_upload_collection(accountid, &mbentry);

    if (r == IMAP_INVALID_USER) {
        goto done;
    }
    else if (r == IMAP_PERMISSION_DENIED) {
        if (has_shared_rw_rights(accountid)) {
            /* add rights for the sharee */
            char rightstr[100];
            cyrus_acl_masktostr(JACL_READITEMS | JACL_WRITE, rightstr);
            r = mboxlist_setacl(&jmap_namespace, mbentry->name, httpd_userid,
                                rightstr, 1, httpd_userid, httpd_authstate);
        }
        if (r) goto done;
    }
    else if (r == IMAP_MAILBOX_NONEXISTENT) {
        if (!mbentry) goto done;
        else if (mbentry->server) {
            proxy_findserver(mbentry->server, &http_protocol, httpd_userid,
                             &backend_cached, NULL, NULL, httpd_in);
            goto done;
        }

        int is_shared = 0;
        if (strcmp(accountid, httpd_userid)) {
            if (!(has_shared_rw_rights(accountid))) {
                r = IMAP_PERMISSION_DENIED;
                goto done;
            }

            is_shared = 1;
        }

        r = mboxlist_createmailbox(mbentry->name, MBTYPE_COLLECTION,
                                   NULL, 1 /* admin */, accountid,
                                   httpd_authstate, 0, 0, 0, 0, mailbox);
        /* we lost the race, that's OK */
        if (r == IMAP_MAILBOX_LOCKED) r = 0;
        else {
            if (r) {
                syslog(LOG_ERR, "IOERROR: failed to create %s (%s)",
                        mbentry->name, error_message(r));
            }
            else if (is_shared) {
                /* add rights for the sharee */
                char *newacl = xstrdup((*mailbox)->acl);

                cyrus_acl_set(&newacl, httpd_userid, ACL_MODE_SET,
                              JACL_READITEMS | JACL_WRITE, NULL, NULL);

                /* ok, change the mailboxes database */
                r = mboxlist_sync_setacls(mbentry->name, newacl,
                                          mailbox_modseq_dirty(*mailbox));
                if (r) {
                    syslog(LOG_ERR, "mboxlist_sync_setacls(%s) failed: %s",
                           mbentry->name, error_message(r));
                }
                else {
                    /* ok, change the backup in cyrus.header */
                    r = mailbox_set_acl(*mailbox, newacl);
                    if (r) {
                        syslog(LOG_ERR, "mailbox_set_acl(%s) failed: %s",
                               mbentry->name, error_message(r));
                    }
                }
                free(newacl);
            }
            goto done;
        }
    }
    else if (r) goto done;

    if (mailbox) {
        /* Open mailbox for writing */
        r = mailbox_open_iwl(mbentry->name, mailbox);
        if (r) {
            syslog(LOG_ERR, "mailbox_open_iwl(%s) failed: %s",
                   mbentry->name, error_message(r));
        }
    }

 done:
    mboxname_release(&namespacelock);
    mboxlist_entry_free(&mbentry);
    return r;
}

HIDDEN int jmap_open_upload_collection(const char *accountid,
                                       struct mailbox **mailbox)
{
    /* upload collection */
    mbentry_t *mbentry = NULL;
    int r = lookup_upload_collection(accountid, &mbentry);
    if (r) {
        mboxlist_entry_free(&mbentry);
        return _create_upload_collection(accountid, mailbox);
    }

    if (mailbox) {
        /* Open mailbox for writing */
        r = mailbox_open_iwl(mbentry->name, mailbox);
        if (r) {
            syslog(LOG_ERR, "mailbox_open_iwl(%s) failed: %s",
                   mbentry->name, error_message(r));
        }
    }

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

/* Handle a POST on the upload endpoint */
static int jmap_upload(struct transaction_t *txn)
{
    strarray_t flags = STRARRAY_INITIALIZER;

    struct body *body = NULL;

    int ret = HTTP_SERVER_ERROR;
    json_t *resp = NULL;
    hdrcache_t hdrcache = txn->req_hdrs;
    struct stagemsg *stage = NULL;
    FILE *f = NULL;
    const char **hdr;
    time_t now = time(NULL);
    struct appendstate as;
    char *normalisedtype = NULL;
    int rawmessage = 0;

    struct mailbox *mailbox = NULL;
    int r = 0;

    /* Read body */
    txn->req_body.flags |= BODY_DECODE;
    r = http_read_req_body(txn);
    if (r) {
        txn->flags.conn = CONN_CLOSE;
        return r;
    }

    const char *data = buf_base(&txn->req_body.payload);
    size_t datalen = buf_len(&txn->req_body.payload);

    if (datalen > (size_t) my_jmap_settings.limits[MAX_SIZE_UPLOAD]) {
        txn->error.desc = "JSON upload byte size exceeds maxSizeUpload";
        return HTTP_PAYLOAD_TOO_LARGE;
    }

    /* Resource must be {accountId}/ with no trailing path */
    char *accountid = xstrdup(txn->req_tgt.resource);
    char *slash = strchr(accountid, '/');
    if (!slash || *(slash + 1) != '\0') {
        ret = HTTP_NOT_FOUND;
        goto done;
    }
    *slash = '\0';

    r = jmap_open_upload_collection(accountid, &mailbox);
    if (r) {
        syslog(LOG_ERR, "jmap_upload: can't open upload collection for %s: %s",
               error_message(r), accountid);
        ret = HTTP_NOT_FOUND;
        goto done;
    }

    /* Prepare to stage the message */
    if (!(f = append_newstage(mailbox->name, now, 0, &stage))) {
        syslog(LOG_ERR, "append_newstage(%s) failed", mailbox->name);
        txn->error.desc = "append_newstage() failed";
        ret = HTTP_SERVER_ERROR;
        goto done;
    }

    const char *type = "application/octet-stream";
    if ((hdr = spool_getheader(hdrcache, "Content-Type"))) {
        type = hdr[0];
    }
    /* Remove CFWS and encodings from type */
    normalisedtype = charset_decode_mimeheader(type, CHARSET_KEEPCASE);

    if (!strcasecmp(normalisedtype, "message/rfc822")) {
        struct protstream *stream = prot_readmap(data, datalen);
        r = message_copy_strict(stream, f, datalen, 0);
        prot_free(stream);
        if (!r) {
            rawmessage = 1;
            goto wrotebody;
        }
        // otherwise we gotta clean up and make it an attachment
        ftruncate(fileno(f), 0L);
        fseek(f, 0L, SEEK_SET);
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
                                            buf_len(&txn->buf), 0);
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

wrotebody:

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
    strarray_append(&flags, "\\Deleted");
    strarray_append(&flags, "\\Expunged");  // custom flag to insta-expunge!
    r = append_fromstage(&as, &body, stage, now, 0, &flags, 0, /*annots*/NULL);

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

    char blob_id[JMAP_BLOBID_SIZE];
    jmap_set_blobid(rawmessage ? &body->guid : &body->content_guid, blob_id);

    /* Create response object */
    resp = json_pack("{s:s}", "accountId", accountid);
    json_object_set_new(resp, "blobId", json_string(blob_id));
    json_object_set_new(resp, "size", json_integer(datalen));
    json_object_set_new(resp, "expires", json_string(datestr));
    json_object_set_new(resp, "type", json_string(normalisedtype));

done:
    free(normalisedtype);
    free(accountid);
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

    /* ensure we didn't leak anything! */
    assert(!open_mailboxes_exist());
    assert(!open_mboxlocks_exist());

    // checkpoint before replying
    sync_checkpoint(httpd_in);

    /* Output the JSON object */
    if (resp)
        ret = json_response(HTTP_CREATED, txn, resp);

    return ret;
}

/* Handle a GET on the session endpoint */
static int jmap_get_session(struct transaction_t *txn)
{
    json_t *jsession = json_object();

    /* URLs */
    json_object_set_new(jsession, "username", json_string(httpd_userid));
    json_object_set_new(jsession, "apiUrl", json_string(JMAP_BASE_URL));
    json_object_set_new(jsession, "downloadUrl",
            json_string(JMAP_BASE_URL JMAP_DOWNLOAD_COL JMAP_DOWNLOAD_TPL));
    json_object_set_new(jsession, "uploadUrl",
            json_string(JMAP_BASE_URL JMAP_UPLOAD_COL JMAP_UPLOAD_TPL));
    json_object_set_new(jsession, "eventSourceUrl",
            json_string(JMAP_BASE_URL JMAP_EVENTSOURCE_COL JMAP_EVENTSOURCE_TPL));

    /* state */
    char *inboxname = mboxname_user_mbox(httpd_userid, NULL);
    struct buf state = BUF_INITIALIZER;
    buf_printf(&state, MODSEQ_FMT, mboxname_readraclmodseq(inboxname));
    json_object_set_new(jsession, "state", json_string(buf_cstring(&state)));
    free(inboxname);
    buf_free(&state);

    /* capabilities */
    json_object_set(jsession, "capabilities", my_jmap_settings.server_capabilities);
    json_t *accounts = json_object();
    json_t *primary_accounts = json_object();
    jmap_accounts(accounts, primary_accounts);
    json_object_set_new(jsession, "accounts", accounts);
    json_object_set_new(jsession, "primaryAccounts", primary_accounts);

    /* Response should not be cached */
    txn->flags.cc |= CC_NOCACHE | CC_NOSTORE | CC_REVALIDATE;

    /* Write the JSON response */
    return json_response(HTTP_OK, txn, jsession);
}


/*
 * WebSockets data callback ('jmap' sub-protocol): Process JMAP API request.
 *
 * Can be tested with:
 *   https://github.com/websockets/wscat
 *   https://chrome.google.com/webstore/detail/web-socket-client/lifhekgaodigcpmnakfhaaaboididbdn
 *
 * WebSockets over HTTP/2 currently only available in:
 *   https://www.google.com/chrome/browser/canary.html
 */
static int jmap_ws(enum wslay_opcode opcode,
                   struct buf *inbuf, struct buf *outbuf,
                   struct buf *logbuf, void **rock)
{
    struct transaction_t **txnp = (struct transaction_t **) rock;
    struct transaction_t *txn = *txnp;
    json_t *req = NULL, *res = NULL;
    int ret;

    if (!txn) {
        /* Create a transaction rock to use for API requests */
        txn = *txnp = xzmalloc(sizeof(struct transaction_t));

        /* Create header cache */
        txn->req_hdrs = spool_new_hdrcache();
        if (!txn->req_hdrs) {
            free(txn);
            return HTTP_SERVER_ERROR;
        }
    }
    else if (!inbuf) {
        /* Free transaction rock */
        transaction_free(txn);
        free(txn);
        return 0;
    }

    /* Only accept text frames */
    if (opcode != WSLAY_TEXT_FRAME) {
        return HTTP_NOT_ACCEPTABLE;
    }

    /* Set request payload */
    buf_init_ro(&txn->req_body.payload, buf_base(inbuf), buf_len(inbuf));

    /* Parse the JSON request */
    ret = parse_json_body(txn, &req);
    if (ret) {
        ret = jmap_error_response(txn, ret, &res);
    }
    else {
        const char *type = json_string_value(json_object_get(req, "@type"));

        if (!strcmpsafe(type, "Request")) {
            /* Process the API request */
            ret = jmap_api(txn, req, &res, &my_jmap_settings);
        }
        else if (!strcmpsafe(type, "WebSocketPushEnable")) {
            /* Log request */
            spool_replace_header(xstrdup(":jmap"),
                                 xstrdup("WebSocketPushEnable"), txn->req_hdrs);
            /* XXX  Do nothing until supported */
            ret = HTTP_NO_CONTENT;
        }
        else if (!strcmpsafe(type, "WebSocketPushDisable")) {
            /* Log request */
            spool_replace_header(xstrdup(":jmap"),
                                 xstrdup("WebSocketPushDisable"), txn->req_hdrs);
            /* XXX  Do nothing until supported */
            ret = HTTP_NO_CONTENT;
        }
        else {
            buf_reset(&txn->buf);
            buf_printf(&txn->buf,
                       "Unknown request @type: %s", type ? type : "null");
            txn->error.desc = buf_cstring(&txn->buf);

            ret = jmap_error_response(txn, JMAP_NOT_REQUEST, &res);
        }
    }

    /* ensure we didn't leak anything! */
    assert(!open_mailboxes_exist());
    assert(!open_mboxlocks_exist());

    // checkpoint before we reply
    sync_checkpoint(httpd_in);

    /* Free request payload */
    buf_free(&txn->req_body.payload);

    if (logbuf) {
        /* Log JMAP methods */
        const char **hdr = spool_getheader(txn->req_hdrs, ":jmap");

        if (hdr) buf_printf(logbuf, "; jmap=%s", hdr[0]);

        /* Add logheaders */
        if (strarray_size(httpd_log_headers)) {
            json_t *jlogHeaders = json_object_get(req, "logHeaders");
            const char *hdrname;
            json_t *jval;

            json_object_foreach(jlogHeaders, hdrname, jval) {
                const char *val = json_string_value(jval);

                if (val &&
                    strarray_find_case(httpd_log_headers, hdrname, 0) >= 0) {
                    buf_printf(logbuf, "; %s=\"%s\"", hdrname, val);
                }
            }
        }
    }

    if (res) {
        /* Add @type */
        json_object_set_new(res, "@type",
                            json_string(ret ? "RequestError" : "Response"));

        /* Add requestId */
        json_t *id = json_object_get(req, "id");
        if (id) {
            json_object_set(res, "requestId", id);
        }

        /* Return the JSON object */
        ret = json_response(0, txn, res);
        buf_move(outbuf, &txn->resp_body.payload);
    }

    json_decref(req);

    return ret;
}

/* Handle a GET on the eventsource endpoint */
static int jmap_eventsource(struct transaction_t *txn __attribute__((unused)))
{
    return HTTP_NO_CONTENT;
}
