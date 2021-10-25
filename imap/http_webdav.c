/* http_webdav.c -- Routines for handling WebDAV collections in httpd
 *
 * Copyright (c) 1994-2015 Carnegie Mellon University.  All rights reserved.
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

#include <string.h>
#include <sysexits.h>
#include <syslog.h>

#include "httpd.h"
#include "http_dav.h"
#include "http_proxy.h"
#include "mailbox.h"
#include "proxy.h"
#include "spool.h"
#include "tok.h"
#include "user.h"
#include "util.h"
#include "webdav_db.h"
#include "xstrlcpy.h"

/* generated headers are not necessarily in current directory */
#include "imap/http_err.h"
#include "imap/imap_err.h"

static void my_webdav_init(struct buf *serverinfo);
static int my_webdav_auth(const char *userid);
static void my_webdav_reset(void);
static void my_webdav_shutdown(void);

static unsigned long webdav_allow_cb(struct request_target_t *tgt);
static int webdav_parse_path(const char *path, struct request_target_t *tgt,
                             const char **resultstr);

static int webdav_get(struct transaction_t *txn, struct mailbox *mailbox,
                      struct index_record *record, void *data, void **obj);
static int webdav_put(struct transaction_t *txn, void *obj,
                      struct mailbox *mailbox, const char *resource,
                      void *davdb, unsigned flags);

static int propfind_restype(const xmlChar *name, xmlNsPtr ns,
                            struct propfind_ctx *fctx,
                            xmlNodePtr prop, xmlNodePtr resp,
                            struct propstat propstat[], void *rock);

static struct buf *from_buf(struct buf *buf)
{
    struct buf *ret = buf_new();

    buf_copy(ret, buf);

    return ret;
}

static const struct buf *to_buf(const struct buf *buf)
{
    return buf;
}

static struct mime_type_t webdav_mime_types[] = {
    /* First item MUST be the default type and storage format */
    { "*/*", NULL, NULL,
      (struct buf* (*)(void *)) &from_buf,
      (void * (*)(const struct buf*)) &to_buf,
      NULL, NULL, NULL
    },
    { NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL }
};

/* Array of supported REPORTs */
static const struct report_type_t webdav_reports[] = {

    /* WebDAV Versioning (RFC 3253) REPORTs */
    { "expand-property", NS_DAV, "multistatus", &report_expand_prop,
      DACL_READ, 0 },

    /* WebDAV ACL (RFC 3744) REPORTs */
    { "acl-principal-prop-set", NS_DAV, "multistatus", &report_acl_prin_prop,
      DACL_ADMIN, REPORT_NEED_MBOX | REPORT_NEED_PROPS | REPORT_DEPTH_ZERO },

    /* WebDAV Sync (RFC 6578) REPORTs */
    { "sync-collection", NS_DAV, "multistatus", &report_sync_col,
      DACL_READ, REPORT_NEED_MBOX | REPORT_NEED_PROPS },

    { NULL, 0, NULL, NULL, 0, 0 }
};

/* Array of known "live" properties */
static const struct prop_entry webdav_props[] = {

    /* WebDAV (RFC 4918) properties */
    { "creationdate", NS_DAV,
      PROP_ALLPROP | PROP_COLLECTION | PROP_RESOURCE,
      propfind_creationdate, NULL, NULL },
    { "displayname", NS_DAV,
      PROP_ALLPROP | PROP_COLLECTION | PROP_RESOURCE | PROP_PERUSER,
      propfind_collectionname, proppatch_todb, NULL },
    { "getcontentlanguage", NS_DAV,
      PROP_ALLPROP | PROP_RESOURCE,
      propfind_fromhdr, NULL, "Content-Language" },
    { "getcontentlength", NS_DAV,
      PROP_ALLPROP | PROP_COLLECTION | PROP_RESOURCE,
      propfind_getlength, NULL, NULL },
    { "getcontenttype", NS_DAV,
      PROP_ALLPROP | PROP_RESOURCE,
      propfind_fromhdr, NULL, "Content-Type" },
    { "getetag", NS_DAV,
      PROP_ALLPROP | PROP_COLLECTION | PROP_RESOURCE,
      propfind_getetag, NULL, NULL },
    { "getlastmodified", NS_DAV,
      PROP_ALLPROP | PROP_COLLECTION | PROP_RESOURCE,
      propfind_getlastmod, NULL, NULL },
    { "lockdiscovery", NS_DAV,
      PROP_ALLPROP | PROP_RESOURCE,
      propfind_lockdisc, NULL, NULL },
    { "resourcetype", NS_DAV,
      PROP_ALLPROP | PROP_COLLECTION | PROP_RESOURCE,
      propfind_restype, proppatch_restype, "addressbook" },
    { "supportedlock", NS_DAV,
      PROP_ALLPROP | PROP_RESOURCE,
      propfind_suplock, NULL, NULL },

    /* WebDAV Versioning (RFC 3253) properties */
    { "supported-report-set", NS_DAV,
      PROP_COLLECTION,
      propfind_reportset, NULL, (void *) webdav_reports },
    { "supported-method-set", NS_DAV,
      PROP_COLLECTION | PROP_RESOURCE,
      propfind_methodset, NULL, (void *) &webdav_allow_cb },

    /* WebDAV ACL (RFC 3744) properties */
    { "owner", NS_DAV,
      PROP_COLLECTION | PROP_RESOURCE,
      propfind_owner, NULL, NULL },
    { "group", NS_DAV,
      PROP_COLLECTION | PROP_RESOURCE,
      NULL, NULL, NULL },
    { "supported-privilege-set", NS_DAV,
      PROP_COLLECTION | PROP_RESOURCE | PROP_PRESCREEN,
      propfind_supprivset, NULL, NULL },
    { "current-user-privilege-set", NS_DAV,
      PROP_COLLECTION | PROP_RESOURCE | PROP_PRESCREEN,
      propfind_curprivset, NULL, NULL },
    { "acl", NS_DAV,
      PROP_COLLECTION | PROP_RESOURCE | PROP_PRESCREEN,
      propfind_acl, NULL, NULL },
    { "acl-restrictions", NS_DAV,
      PROP_COLLECTION | PROP_RESOURCE,
      propfind_aclrestrict, NULL, NULL },
    { "inherited-acl-set", NS_DAV,
      PROP_COLLECTION | PROP_RESOURCE,
      NULL, NULL, NULL },
    { "principal-collection-set", NS_DAV,
      PROP_COLLECTION | PROP_RESOURCE,
      propfind_princolset, NULL, NULL },

    /* WebDAV Quota (RFC 4331) properties */
    { "quota-available-bytes", NS_DAV,
      PROP_COLLECTION,
      propfind_quota, NULL, NULL },
    { "quota-used-bytes", NS_DAV,
      PROP_COLLECTION,
      propfind_quota, NULL, NULL },

    /* WebDAV Current Principal (RFC 5397) properties */
    { "current-user-principal", NS_DAV,
      PROP_COLLECTION | PROP_RESOURCE,
      propfind_curprin, NULL, NULL },

    /* WebDAV POST (RFC 5995) properties */
    { "add-member", NS_DAV,
      PROP_COLLECTION,
      NULL,  /* Until Apple Contacts is fixed */ NULL, NULL },

    /* WebDAV Sync (RFC 6578) properties */
    { "sync-token", NS_DAV,
      PROP_COLLECTION,
      propfind_sync_token, NULL, SYNC_TOKEN_URL_SCHEME },

    /* Apple Calendar Server properties */
    { "getctag", NS_CS,
      PROP_ALLPROP | PROP_COLLECTION,
      propfind_sync_token, NULL, "" },

    { NULL, 0, 0, NULL, NULL, NULL }
};

struct meth_params webdav_params = {
    webdav_mime_types,
    &webdav_parse_path,
    &dav_get_validators,
    &dav_get_modseq,
    &dav_check_precond,
    { (db_open_proc_t) &webdav_open_mailbox,
      (db_close_proc_t) &webdav_close,
      (db_proc_t) &webdav_begin,
      (db_proc_t) &webdav_commit,
      (db_proc_t) &webdav_abort,
      (db_lookup_proc_t) &webdav_lookup_resource,
      (db_imapuid_proc_t) &webdav_lookup_imapuid,
      (db_foreach_proc_t) &webdav_foreach,
      (db_updates_proc_t) &webdav_get_updates,
      (db_write_proc_t) &webdav_write,
      (db_delete_proc_t) &webdav_delete },
    NULL,                                       /* No ACL extensions */
    { 0, &webdav_put },                         /* Allow duplicate UIDs */
    NULL,                                       /* No special DELETE handling */
    &webdav_get,
    { 0, MBTYPE_COLLECTION, NULL },             /* Allow any location */
    NULL,                                       /* No PATCH handling */
    { POST_ADDMEMBER, NULL, { 0, NULL, NULL } },/* No special POST handling */
    { 0, &webdav_put },                         /* Allow any MIME type */
    { DAV_FINITE_DEPTH, webdav_props},
    webdav_reports
};


/* Namespace for Webdav collections */
struct namespace_t namespace_drive = {
    URL_NS_DRIVE, 0, "drive", "/dav/drive", NULL,
    http_allow_noauth_get, /*authschemes*/0,
    MBTYPE_COLLECTION,
    (ALLOW_READ | ALLOW_POST | ALLOW_WRITE | ALLOW_DELETE |
     ALLOW_DAV | ALLOW_PROPPATCH | ALLOW_MKCOL | ALLOW_ACL),
    &my_webdav_init, &my_webdav_auth, my_webdav_reset, &my_webdav_shutdown,
    &dav_premethod, /*bearer*/NULL,
    {
        { &meth_acl,            &webdav_params },      /* ACL          */
        { NULL,                 NULL },                /* BIND         */
        { NULL,                 NULL },                /* CONNECT      */
        { &meth_copy_move,      &webdav_params },      /* COPY         */
        { &meth_delete,         &webdav_params },      /* DELETE       */
        { &meth_get_head,       &webdav_params },      /* GET          */
        { &meth_get_head,       &webdav_params },      /* HEAD         */
        { &meth_lock,           &webdav_params },      /* LOCK         */
        { NULL,                 NULL },                /* MKCALENDAR   */
        { &meth_mkcol,          &webdav_params },      /* MKCOL        */
        { &meth_copy_move,      &webdav_params },      /* MOVE         */
        { &meth_options,        &webdav_parse_path },  /* OPTIONS      */
        { NULL,                 NULL },                /* PATCH        */
        { &meth_post,           &webdav_params },      /* POST         */
        { &meth_propfind,       &webdav_params },      /* PROPFIND     */
        { &meth_proppatch,      &webdav_params },      /* PROPPATCH    */
        { &meth_put,            &webdav_params },      /* PUT          */
        { &meth_report,         &webdav_params },      /* REPORT       */
        { &meth_trace,          &webdav_parse_path },  /* TRACE        */
        { NULL,                 NULL },                /* UNBIND       */
        { &meth_unlock,         &webdav_params }       /* UNLOCK       */
    }
};

static void my_webdav_init(struct buf *serverinfo __attribute__((unused)))
{
    namespace_drive.enabled =
        config_httpmodules & IMAP_ENUM_HTTPMODULES_WEBDAV;

    if (!namespace_drive.enabled) return;

    if (!config_getstring(IMAPOPT_DAVDRIVEPREFIX)) {
        fatal("Required 'davdriveprefix' option is not set", EX_CONFIG);
    }

    webdav_init();

    namespace_principal.enabled = 1;
}


static int my_webdav_auth(const char *userid)
{
    if (httpd_userisadmin || httpd_userisanonymous ||
        global_authisa(httpd_authstate, IMAPOPT_PROXYSERVERS)) {
        /* admin, anonymous, or proxy from frontend - won't have DAV database */
        return 0;
    }

    if (config_mupdate_server && !config_getstring(IMAPOPT_PROXYSERVERS)) {
        /* proxy-only server - won't have DAV databases */
        return 0;
    }

    /* Auto-provision toplevel DAV drive collection for 'userid' */
    mbname_t *mbname = mbname_from_userid(userid);
    mbname_push_boxes(mbname, config_getstring(IMAPOPT_DAVDRIVEPREFIX));
    int r = mboxlist_lookup(mbname_intname(mbname), NULL, NULL);
    if (r == IMAP_MAILBOX_NONEXISTENT) {
        struct mboxlock *namespacelock = user_namespacelock(userid);
        // did we lose the race?  Nothing to do!
        r = mboxlist_lookup(mbname_intname(mbname), NULL, NULL);
        if (r != IMAP_MAILBOX_NONEXISTENT) goto done;

        /* Find location of INBOX */
        char *inboxname = mboxname_user_mbox(userid, NULL);
        mbentry_t *mbentry = NULL;

        r = proxy_mlookup(inboxname, &mbentry, NULL, NULL);
        free(inboxname);
        if (r == IMAP_MAILBOX_NONEXISTENT) r = IMAP_INVALID_USER;
        if (!r && mbentry->server) {
            proxy_findserver(mbentry->server, &http_protocol, httpd_userid,
                             &backend_cached, NULL, NULL, httpd_in);
            mboxlist_entry_free(&mbentry);
            mboxname_release(&namespacelock);
            goto done;
        }
        mboxlist_entry_free(&mbentry);

        if (!r) {
            mbentry_t mbentry = MBENTRY_INITIALIZER;
            mbentry.name = (char *) mbname_intname(mbname);
            mbentry.mbtype = MBTYPE_COLLECTION;
            r = mboxlist_createmailbox(&mbentry, 0/*options*/, 0/*highestmodseq*/,
                                       httpd_userisadmin || httpd_userisproxyadmin,
                                       userid, httpd_authstate,
                                       0/*flags*/, NULL/*mailboxptr*/);
            if (r) syslog(LOG_ERR, "IOERROR: failed to create %s (%s)",
                          mbname_intname(mbname), error_message(r));
        }
        else {
            syslog(LOG_ERR, "could not autoprovision DAV drive for userid %s: %s",
                   userid, error_message(r));
        }

        mboxname_release(&namespacelock);
    }

 done:
    mbname_free(&mbname);
    return 0;
}


static void my_webdav_reset(void)
{
    // nothing
}


static void my_webdav_shutdown(void)
{
    my_webdav_reset();
    webdav_done();
}


/* Determine allowed methods in WebDAV namespace */
static unsigned long webdav_allow_cb(struct request_target_t *tgt)
{
    unsigned long allow = tgt->namespace->allow;

    if (!tgt->userid) {
        allow &= ALLOW_READ_MASK;
    }
    else if (tgt->resource) {
        allow &= ~(ALLOW_MKCOL | ALLOW_POST);
    }

    return allow;
}


/* Parse request-target path in WebDAV namespace
 *
 * For purposes of PROPFIND and REPORT, we never assign tgt->collection.
 * All collections are treated as though they are at the root so both
 * contained resources and collection are listed.
 */
static int webdav_parse_path(const char *path, struct request_target_t *tgt,
                             const char **resultstr)
{
    char *p, *last = NULL;
    size_t len, lastlen = 0;
    mbname_t *mbname = NULL;
    const char *mboxname = NULL;

    if (*tgt->path) return 0;  /* Already parsed */

    /* Make a working copy of target path */
    strlcpy(tgt->path, path, sizeof(tgt->path));
    tgt->tail = tgt->path + strlen(tgt->path);

    p = tgt->path;

    /* Sanity check namespace */
    len = strlen(namespace_drive.prefix);
    if (strlen(p) < len ||
        strncmp(namespace_drive.prefix, p, len) ||
        (path[len] && path[len] != '/')) {
        *resultstr = "Namespace mismatch request target path";
        return HTTP_FORBIDDEN;
    }

    tgt->mboxprefix = config_getstring(IMAPOPT_DAVDRIVEPREFIX);

    /* Default to bare-bones Allow bits */
    tgt->allow &= ALLOW_READ_MASK;

    /* Skip namespace */
    p += len;
    if (!*p || !*++p) {
        /* Make sure collection is terminated with '/' */
        if (p[-1] != '/') *p++ = '/';

        tgt->flags = TGT_DRIVE_ROOT;
    }

    /* Check if we're in user space */
    len = strcspn(p, "/");
    if (len && !strncmp(p, USER_COLLECTION_PREFIX, len)) {
        p += len;
        if (!*p || !*++p) {
            /* Make sure collection is terminated with '/' */
            if (p[-1] != '/') *p++ = '/';

            tgt->flags = TGT_DRIVE_USER;

            /* Create pseudo entry for /dav/drive/user */
            tgt->mbentry = mboxlist_entry_create();
            tgt->mbentry->name = xstrdup(USER_COLLECTION_PREFIX);
            tgt->userid = xstrdup("");
            tgt->mbentry->acl = xstrdup("anyone\tlr\t");
            tgt->mbentry->mbtype = MBTYPE_COLLECTION;
            return 0;
        }

        /* Get user id */
        len = strcspn(p, "/");
        tgt->userid = xstrndup(p, len);

        p += len;
        if (!*p || !*++p) {
            /* Make sure collection is terminated with '/' */
            if (p[-1] != '/') *p++ = '/';
        }

        len = strcspn(p, "/");
    }

    /* Create mailbox name from the parsed path */
    mbname = mbname_from_userid(tgt->userid);
    mbname_push_boxes(mbname, config_getstring(IMAPOPT_DAVDRIVEPREFIX));

    while (len) {
        /* Get collection(s) */
        char *val = xstrndup(p, len);
        mbname_push_boxes(mbname, val);
        free(val);

        /* Keep track of last segment in path */
        last = p;

        p += len;
        if (!*p || !*++p) {
            /* Make sure collection is terminated with '/' */
            if (p[-1] != '/') *p++ = '/';
            lastlen = strlen(last);
        }

        len = strcspn(p, "/");
    }

    /* XXX - hack to allow @domain parts for non-domain-split users */
    if (httpd_extradomain) {
        /* not allowed to be cross domain */
        if (mbname_localpart(mbname) &&
            strcmpsafe(mbname_domain(mbname), httpd_extradomain))
            return HTTP_NOT_FOUND;
        mbname_set_domain(mbname, NULL);
    }

    mboxname = mbname_intname(mbname);
    if (tgt->mbentry) {
        /* Just return the mboxname (MKCOL or dest of COPY/MOVE collection) */
        tgt->mbentry->name = xstrdup(mboxname);

        /* XXX  Hack to get around MKCOL/PROPPATCH check */
        tgt->collection = last;
    }
    else if (*mboxname) {
        /* Locate the mailbox */
        int r = proxy_mlookup(mboxname, &tgt->mbentry, NULL, NULL);

        if (r == IMAP_MAILBOX_NONEXISTENT && last) {
            /* Assume that the last segment of the path is a resource */
            tgt->resource = last;
            tgt->reslen = --lastlen;
            tgt->resource[lastlen] = '\0';  /* trim trailing '/' */

            /* Adjust collection */
            free(mbname_pop_boxes(mbname));

            r = proxy_mlookup(mbname_intname(mbname), &tgt->mbentry, NULL, NULL);
        }
        if (r) {
            syslog(LOG_ERR, "mlookup(%s) failed: %s",
                   mboxname, error_message(r));
            *resultstr = error_message(r);
            mbname_free(&mbname);

            switch (r) {
            case IMAP_PERMISSION_DENIED: return HTTP_FORBIDDEN;
            case IMAP_MAILBOX_NONEXISTENT: return HTTP_NOT_FOUND;
            default: return HTTP_SERVER_ERROR;
            }
        }
    }

    mbname_free(&mbname);

    /* Set proper Allow bits based on path components */
    tgt->allow |= ALLOW_ACL | ALLOW_PROPPATCH | ALLOW_WRITE | ALLOW_DELETE;

    if (!tgt->resource) tgt->allow |= ALLOW_POST | ALLOW_MKCOL;

    return 0;
}


/* Perform a GET/HEAD request on a WebDAV resource */
static int webdav_get(struct transaction_t *txn,
                      struct mailbox *mailbox __attribute__((unused)),
                      struct index_record *record, void *data,
                      void **obj __attribute__((unused)))
{
    if (record && record->uid) {
        /* GET on a resource */
        struct webdav_data *wdata = (struct webdav_data *) data;

        assert(!buf_len(&txn->buf));
        buf_printf(&txn->buf, "%s/%s", wdata->type, wdata->subtype);
        txn->resp_body.type = buf_cstring(&txn->buf);
        txn->resp_body.dispo.fname = wdata->filename;
        return HTTP_CONTINUE;
    }

    /* Get on a user/collection */
    struct buf *body = &txn->resp_body.payload;
    unsigned level = 0;

    /* Check ACL for current user */
    int rights = httpd_myrights(httpd_authstate, txn->req_tgt.mbentry);
    if ((rights & DACL_READ) != DACL_READ) {
        /* DAV:need-privileges */
        txn->error.precond = DAV_NEED_PRIVS;
        txn->error.resource = txn->req_tgt.path;
        txn->error.rights = DACL_READ;
        return HTTP_NO_PRIVS;
    }

    struct strlist *action = hash_lookup("action", &txn->req_qparams);
    if (!action) {
        /* Send HTML with davmount link */
        buf_reset(body);
        buf_printf_markup(body, level, HTML_DOCTYPE);
        buf_printf_markup(body, level++, "<html>");
        buf_printf_markup(body, level++, "<head>");
        buf_printf_markup(body, level, "<title>%s</title>", txn->req_tgt.path);
        buf_printf_markup(body, --level, "</head>");
        buf_printf_markup(body, level++, "<body>");
        buf_printf_markup(body, level, "<a href=?action=davmount>%s</a>",
                          "View this collection in your WebDAV client");
        buf_printf_markup(body, --level, "</body>");
        buf_printf_markup(body, --level, "</html>");

        txn->resp_body.type = "text/html; charset=utf-8";
    }
    else if (action->next || strcmp(action->s, "davmount")) {
        return HTTP_BAD_REQUEST;
    }
    else {
        /* Send WebDAV mount request XML */
        const char *proto = NULL;
        const char *host = NULL;

        buf_reset(body);
        buf_printf_markup(body, level, XML_DECLARATION);
        buf_printf_markup(body, level++,
                          "<mount xmlns=\"" XML_NS_DAVMOUNT "\">");
        http_proto_host(txn->req_hdrs, &proto, &host);
        buf_printf_markup(body, level, "<url>%s://%s%s</url>",
                          proto, host, txn->req_tgt.path);
        if (httpd_userid) {
            txn->flags.cc |= CC_PRIVATE;
            buf_printf_markup(body, level,
                              "<username>%s</username>", httpd_userid);
        }
        buf_printf_markup(body, --level, "</mount>");

        txn->resp_body.type = "application/davmount+xml; charset=utf-8";
    }

    write_body(HTTP_OK, txn, buf_cstring(body), buf_len(body));

    return 0;
}


/* Perform a PUT request on a WebDAV resource */
static int webdav_put(struct transaction_t *txn, void *obj,
                      struct mailbox *mailbox, const char *resource,
                      void *destdb, unsigned flags __attribute__((unused)))
{
    struct webdav_db *db = (struct webdav_db *)destdb;
    struct buf *buf = (struct buf *) obj;
    struct webdav_data *wdata;
    struct index_record *oldrecord = NULL, record;
    const char **hdr;
    char *filename = NULL;

    /* Validate the data */
    if (!buf) return HTTP_FORBIDDEN;

    /* Find message UID for the resource */
    /* XXX  We can't assume that txn->req_tgt.mbentry is our target,
       XXX  because we may have been called as part of a COPY/MOVE */
    const mbentry_t mbentry = { .name = (char *)mailbox_name(mailbox),
                                .uniqueid = (char *)mailbox_uniqueid(mailbox) };
    webdav_lookup_resource(db, &mbentry, resource, &wdata, 0);

    if (wdata->dav.imap_uid) {
        /* Fetch index record for the resource */
        int r = mailbox_find_index_record(mailbox, wdata->dav.imap_uid, &record);
        if (!r) {
            oldrecord = &record;
        }
        else {
            xsyslog(LOG_ERR,
                    "Couldn't find index record corresponding to WebDAV DB record",
                    "mailbox=<%s> record=<%u> error=<%s>",
                    mailbox_name(mailbox), wdata->dav.imap_uid, error_message(r));
        }
    }

    /* Get filename of attachment */
    if ((hdr = spool_getheader(txn->req_hdrs, "Content-Disposition"))) {
        char *dparam;
        tok_t tok;

        tok_initm(&tok, (char *) *hdr, ";", TOK_TRIMLEFT|TOK_TRIMRIGHT);
        while ((dparam = tok_next(&tok))) {
            if (!strncasecmp(dparam, "filename=", 9)) {
                filename = dparam+9;
                if (*filename == '"') {
                    filename++;
                    filename[strlen(filename)-1] = '\0';
                }
                break;
            }
        }
        tok_fini(&tok);
    }
    else filename = (char *) resource;

    /* Create and cache RFC 5322 header fields for resource */
    if (filename) {
        spool_replace_header(xstrdup("Subject"),
                             xstrdup(filename), txn->req_hdrs);
        spool_replace_header(xstrdup("Content-Description"),
                             xstrdup(filename), txn->req_hdrs);
    }

    assert(!buf_len(&txn->buf));
    buf_printf(&txn->buf, "<%s@%s>", resource, config_servername);
    spool_replace_header(xstrdup("Message-ID"),
                         buf_release(&txn->buf), txn->req_hdrs);

    buf_printf(&txn->buf, "attachment;\r\n\tfilename=\"%s\"", resource);
    spool_replace_header(xstrdup("Content-Disposition"),
                         buf_release(&txn->buf), txn->req_hdrs);

    /* Store the resource */
    return dav_store_resource(txn, buf_base(buf), buf_len(buf),
                              mailbox, oldrecord, wdata->dav.createdmodseq, NULL);
}


/* Callback to fetch DAV:resourcetype */
static int propfind_restype(const xmlChar *name, xmlNsPtr ns,
                            struct propfind_ctx *fctx,
                            xmlNodePtr prop __attribute__((unused)),
                            xmlNodePtr resp __attribute__((unused)),
                            struct propstat propstat[],
                            void *rock __attribute__((unused)))
{
    xmlNodePtr node = xml_add_prop(HTTP_OK, fctx->ns[NS_DAV],
                                   &propstat[PROPSTAT_OK], name, ns, NULL, 0);

    if (!fctx->req_tgt->resource)
        xmlNewChild(node, NULL, BAD_CAST "collection", NULL);

    return 0;
}
