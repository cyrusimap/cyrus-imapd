/* http_dav.c -- Routines for dealing with DAV properties in httpd
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

#include <sysexits.h>

#include "httpd.h"
#include "http_dav.h"
#include "http_dav_sharing.h"
#include "http_proxy.h"
#include "proxy.h"
#include "strhash.h"
#include "syslog.h"
#include "times.h"
#include "user.h"
#include "webdav_db.h"
#include "xstrlcpy.h"

/* generated headers are not necessarily in current directory */
#include "imap/http_err.h"
#include "imap/imap_err.h"

#define DAVNOTIFICATION_CONTENT_TYPE \
    "application/davnotification+xml; charset=utf-8"

static struct webdav_db *auth_webdavdb = NULL;

static void my_dav_init(struct buf *serverinfo);
static int my_dav_auth(const char *userid);
static void my_dav_reset(void);
static void my_dav_shutdown(void);

static unsigned long notify_allow_cb(struct request_target_t *tgt);

static int notify_parse_path(const char *path, struct request_target_t *tgt,
                             const char **resultstr);

static int notify_get(struct transaction_t *txn, struct mailbox *mailbox,
                      struct index_record *record, void *data, void **obj,
                      struct mime_type_t *mime);

static int propfind_restype(const xmlChar *name, xmlNsPtr ns,
                            struct propfind_ctx *fctx,
                            xmlNodePtr prop, xmlNodePtr resp,
                            struct propstat propstat[], void *rock);

static int propfind_notifytype(const xmlChar *name, xmlNsPtr ns,
                               struct propfind_ctx *fctx,
                               xmlNodePtr prop, xmlNodePtr resp,
                               struct propstat propstat[], void *rock);

static struct buf *from_xml(xmlDocPtr doc)
{
    struct buf *buf = buf_new();
    xmlChar *xml = NULL;
    int len = 0;

    /* Dump XML response tree into a text buffer */
    xmlDocDumpFormatMemoryEnc(doc, &xml, &len, "utf-8",
                              config_httpprettytelemetry);
    if (xml) buf_initm(buf, (char *) xml, len);

    return buf;
}

static xmlDocPtr to_xml(const struct buf *buf)
{
    xmlParserCtxtPtr ctxt;
    xmlDocPtr doc = NULL;

    ctxt = xmlNewParserCtxt();
    if (ctxt) {
        doc = xmlCtxtReadMemory(ctxt, buf_base(buf), buf_len(buf), NULL, NULL,
                                XML_PARSE_NOWARNING);
        xmlFreeParserCtxt(ctxt);
    }

    return doc;
}

static struct mime_type_t notify_mime_types[] = {
    /* First item MUST be the default type and storage format */
    { DAVNOTIFICATION_CONTENT_TYPE, NULL, "xml",
      (struct buf* (*)(void *)) &from_xml,
      (void * (*)(const struct buf*)) &to_xml,
      (void (*)(void *)) &xmlFreeDoc, NULL, NULL
    },
    { NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL }
};

/* Array of supported REPORTs */
static const struct report_type_t notify_reports[] = {

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
static const struct prop_entry notify_props[] = {

    /* WebDAV (RFC 4918) properties */
    { "creationdate", NS_DAV,
      PROP_ALLPROP | PROP_COLLECTION | PROP_RESOURCE,
      propfind_creationdate, NULL, NULL },
    { "displayname", NS_DAV,
      PROP_ALLPROP | PROP_COLLECTION | PROP_RESOURCE | PROP_PERUSER,
      propfind_fromdb, proppatch_todb, NULL },
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
    { "resourcetype", NS_DAV,
      PROP_ALLPROP | PROP_COLLECTION | PROP_RESOURCE,
      propfind_restype, NULL, NULL },

    /* WebDAV Versioning (RFC 3253) properties */
    { "supported-report-set", NS_DAV,
      PROP_COLLECTION,
      propfind_reportset, NULL, (void *) notify_reports },
    { "supported-method-set", NS_DAV,
      PROP_COLLECTION | PROP_RESOURCE,
      propfind_methodset, NULL, (void *) &notify_allow_cb },

    /* WebDAV ACL (RFC 3744) properties */
    { "owner", NS_DAV,
      PROP_COLLECTION | PROP_RESOURCE,
      propfind_owner, NULL, NULL },
    { "group", NS_DAV,
      PROP_COLLECTION | PROP_RESOURCE,
      NULL, NULL, NULL },
    { "supported-privilege-set", NS_DAV,
      PROP_COLLECTION | PROP_RESOURCE,
      propfind_supprivset, NULL, NULL },
    { "current-user-privilege-set", NS_DAV,
      PROP_COLLECTION | PROP_RESOURCE,
      propfind_curprivset, NULL, NULL },
    { "acl", NS_DAV,
      PROP_COLLECTION | PROP_RESOURCE,
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

    /* WebDAV Current Principal (RFC 5397) properties */
    { "current-user-principal", NS_DAV,
      PROP_COLLECTION | PROP_RESOURCE,
      propfind_curprin, NULL, NULL },

    /* WebDAV Sync (RFC 6578) properties */
    { "sync-token", NS_DAV,
      PROP_COLLECTION,
      propfind_sync_token, NULL, SYNC_TOKEN_URL_SCHEME },

    /* WebDAV Notifications (draft-pot-webdav-notifications) properties */
    { "notificationtype", NS_DAV,
      PROP_RESOURCE,
      propfind_notifytype, NULL, NULL },

    /* Backwards compatibility with Apple notifications clients */
    { "notificationtype", NS_CS,
      PROP_RESOURCE,
      propfind_notifytype, NULL, "calendarserver-sharing" },

    /* Apple Calendar Server properties */
    { "getctag", NS_CS,
      PROP_ALLPROP | PROP_COLLECTION,
      propfind_sync_token, NULL, "" },

    { NULL, 0, 0, NULL, NULL, NULL }
};

static struct meth_params notify_params = {
    notify_mime_types,
    &notify_parse_path,
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
    { 0, NULL },
    NULL,                                       /* No special DELETE handling */
    &notify_get,
    { 0, 0, NULL },                             /* No MKCOL handling */
    NULL,                                       /* No PATCH handling */
    { 0, &notify_post, { 0, NULL, NULL } },     /* No generic POST handling */
    { 0, NULL },
    { DAV_FINITE_DEPTH, notify_props},
    notify_reports
};


/* Namespace for WebDAV notification collections */
struct namespace_t namespace_notify = {
    URL_NS_NOTIFY, 0, "notify", "/dav/notifications", NULL,
    http_allow_noauth_get, /*authschemes*/0,
    MBTYPE_COLLECTION,
    (ALLOW_READ | ALLOW_POST | ALLOW_DELETE |
     ALLOW_DAV | ALLOW_PROPPATCH | ALLOW_ACL),
    &my_dav_init, &my_dav_auth, &my_dav_reset, &my_dav_shutdown,
    &dav_premethod,
    {
        { &meth_acl,            &notify_params },      /* ACL          */
        { NULL,                 NULL },                /* BIND         */
        { NULL,                 NULL },                /* CONNECT      */
        { NULL,                 NULL },                /* COPY         */
        { &meth_delete,         &notify_params },      /* DELETE       */
        { &meth_get_head,       &notify_params },      /* GET          */
        { &meth_get_head,       &notify_params },      /* HEAD         */
        { NULL,                 NULL },                /* LOCK         */
        { NULL,                 NULL },                /* MKCALENDAR   */
        { NULL,                 NULL },                /* MKCOL        */
        { NULL,                 NULL },                /* MOVE         */
        { &meth_options,        &notify_parse_path },  /* OPTIONS      */
        { NULL,                 NULL },                /* PATCH        */
        { &meth_post,           &notify_params },      /* POST         */
        { &meth_propfind,       &notify_params },      /* PROPFIND     */
        { NULL,                 NULL },                /* PROPPATCH    */
        { NULL,                 NULL },                /* PUT          */
        { &meth_report,         &notify_params },      /* REPORT       */
        { &meth_trace,          &notify_parse_path },  /* TRACE        */
        { NULL,                 NULL },                /* UNBIND       */
        { NULL,                 NULL },                /* UNLOCK       */
    }
};


static void my_dav_init(struct buf *serverinfo __attribute__((unused)))
{
    if (!namespace_principal.enabled) return;

    if (!config_getstring(IMAPOPT_DAVNOTIFICATIONSPREFIX)) {
        fatal("Required 'davnotificationsprefix' option is not set", EX_CONFIG);
    }

    namespace_notify.enabled = 1;

    webdav_init();
}


int dav_lookup_notify_collection(const char *userid, mbentry_t **mbentry)
{
    mbname_t *mbname;
    const char *notifyname;
    int r;

    /* Create notification mailbox name from the parsed path */
    mbname = mbname_from_userid(userid);
    mbname_push_boxes(mbname, config_getstring(IMAPOPT_DAVNOTIFICATIONSPREFIX));

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
    notifyname = mbname_intname(mbname);
    r = proxy_mlookup(notifyname, mbentry, NULL, NULL);
    if (r == IMAP_MAILBOX_NONEXISTENT) {
        /* Find location of INBOX */
        char *inboxname = mboxname_user_mbox(userid, NULL);

        int r1 = proxy_mlookup(inboxname, mbentry, NULL, NULL);
        free(inboxname);
        if (r1 == IMAP_MAILBOX_NONEXISTENT) {
            r = IMAP_INVALID_USER;
            goto done;
        }

        mboxlist_entry_free(mbentry);
        *mbentry = mboxlist_entry_create();
        (*mbentry)->name = xstrdup(notifyname);
        (*mbentry)->mbtype = MBTYPE_COLLECTION;
    }

  done:
    mbname_free(&mbname);

    return r;
}

static int _create_notify_collection(const char *userid, struct mailbox **mailbox)
{
    /* lock the namespace lock and try again */
    struct mboxlock *namespacelock = user_namespacelock(userid);

    mbentry_t *mbentry = NULL;
    int r = dav_lookup_notify_collection(userid, &mbentry);

    if (r == IMAP_MAILBOX_NONEXISTENT) {
        if (!mbentry) goto done;
        else if (mbentry->server) {
            proxy_findserver(mbentry->server, &http_protocol, httpd_userid,
                             &backend_cached, NULL, NULL, httpd_in);
            goto done;
        }

        r = mboxlist_createmailbox(mbentry, 0/*options*/, 0/*highestmodseq*/,
                                   1/*isadmin*/, userid, NULL/*authstate*/,
                                   0/*flags*/, mailbox);
        /* we lost the race, that's OK */
        if (r == IMAP_MAILBOX_LOCKED) r = 0;
        if (r) syslog(LOG_ERR, "IOERROR: failed to create %s (%s)",
                      mbentry->name, error_message(r));
    }
    else if (!r && mailbox) {
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

static int create_notify_collection(const char *userid, struct mailbox **mailbox)
{
    /* notifications collection */
    mbentry_t *mbentry = NULL;
    int r = dav_lookup_notify_collection(userid, &mbentry);
    if (r) {
        mboxlist_entry_free(&mbentry);
        return _create_notify_collection(userid, mailbox);
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

static int my_dav_auth(const char *userid)
{
    if (httpd_userisadmin || httpd_userisanonymous ||
        global_authisa(httpd_authstate, IMAPOPT_PROXYSERVERS)) {
        /* admin, anonymous, or proxy from frontend - won't have DAV database */
        return 0;
    }
    else if (config_mupdate_server && !config_getstring(IMAPOPT_PROXYSERVERS)) {
        /* proxy-only server - won't have DAV databases */
        return 0;
    }
    else {
        /* Open WebDAV DB for 'userid' */
        my_dav_reset();
        auth_webdavdb = webdav_open_userid(userid);
        if (!auth_webdavdb) {
            syslog(LOG_ERR, "Unable to open WebDAV DB for userid: %s", userid);
            return HTTP_UNAVAILABLE;
        }
    }

    /* Auto-provision a notifications collection for 'userid' */
    create_notify_collection(userid, NULL);

    return 0;
}


static void my_dav_reset(void)
{
    if (auth_webdavdb) webdav_close(auth_webdavdb);
    auth_webdavdb = NULL;
}


static void my_dav_shutdown(void)
{
    my_dav_reset();
    webdav_done();
}


/* Perform a GET/HEAD request on a WebDAV notification resource */
static int notify_get(struct transaction_t *txn, struct mailbox *mailbox,
                      struct index_record *record, void *data,
                      void **obj __attribute__((unused)),
                      struct mime_type_t *mime __attribute__((unused)))
{
    const char **hdr;
    struct webdav_data *wdata = (struct webdav_data *) data;
    struct dlist *dl = NULL, *al;
    const char *type_str;
    struct buf msg_buf = BUF_INITIALIZER;
    struct buf inbuf = BUF_INITIALIZER, *outbuf = NULL;
    xmlDocPtr indoc = NULL, outdoc;
    xmlNodePtr notify = NULL, root, node, type;
    xmlNodePtr resp = NULL, sharedurl = NULL, node2;
    xmlNsPtr ns[NUM_NAMESPACE];
    xmlChar *dtstamp = NULL, *comment = NULL;
    char datestr[RFC3339_DATETIME_MAX];
    time_t t;
    enum {
        SYSTEM_STATUS,
        SHARE_INVITE,
        SHARE_REPLY
    } notify_type;
    int r, ret = 0;

    if (!record || !record->uid) return HTTP_NO_CONTENT;

    if ((hdr = spool_getheader(txn->req_hdrs, "Accept")) &&
        is_mediatype(DAVSHARING_CONTENT_TYPE, hdr[0])) {
        return HTTP_CONTINUE;
    }

    /* If no Accept header is given or its not application/davsharing+xml,
       assume its a legacy notification client and do a mime type translation
       from application/davnotification+xml to application/xml */

    /* Parse dlist representing notification type, and data */
    dlist_parsemap(&dl, 1, 0, wdata->filename, strlen(wdata->filename));
    dlist_getatom(dl, "T", &type_str);
    dlist_getlist(dl, "D", &al);

    if (!strcmp(type_str, SYSTEM_STATUS_NOTIFICATION)) {
        notify_type = SYSTEM_STATUS;
    }
    else if (!strcmp(type_str, SHARE_INVITE_NOTIFICATION)) {
        notify_type = SHARE_INVITE;
    }
    else if (!strcmp(type_str, SHARE_REPLY_NOTIFICATION)) {
        notify_type = SHARE_REPLY;
    }
    else {
        ret = HTTP_NOT_ACCEPTABLE;
        goto done;
    }

    txn->resp_body.type = "application/xml";

    if (txn->meth == METH_HEAD) {
        ret = HTTP_CONTINUE;
        goto done;
    }


    /* Load message containing the resource */
    r = mailbox_map_record(mailbox, record, &msg_buf);
    if (r) {
        txn->error.desc = error_message(r);
        return HTTP_SERVER_ERROR;
    }

    /* Parse message body into XML tree */
    buf_init_ro(&inbuf, buf_base(&msg_buf) + record->header_size,
                record->size - record->header_size);
    indoc = to_xml(&inbuf);
    buf_free(&inbuf);
    buf_free(&msg_buf);

    root = xmlDocGetRootElement(indoc);
    node = xmlFirstElementChild(root);
    dtstamp = xmlNodeGetContent(node);
    type = xmlNextElementSibling(node);

    /* Translate DAV notification into CS notification */
    notify = init_xml_response("notification", NS_CS, NULL, ns);
    outdoc = notify->doc;

    /* Calendar.app doesn't like separators in date-time */
    time_from_iso8601((const char *) dtstamp, &t);
    time_to_iso8601(t, datestr, RFC3339_DATETIME_MAX, 0);
    xmlNewChild(notify, NULL, BAD_CAST "dtstamp", BAD_CAST datestr);

    if (notify_type == SYSTEM_STATUS) {
    }
    else if (notify_type == SHARE_INVITE) {
        xmlNodePtr invite, sharer = NULL, access = NULL, calcompset = NULL;
        xmlChar *name = NULL;
        struct buf buf = BUF_INITIALIZER;

        /* Grab DAV elements that we need to construct CS notification */
        for (node = xmlFirstElementChild(type); node;
             node = xmlNextElementSibling(node)) {
            if (!xmlStrncmp(node->name, BAD_CAST "invite-", 7)) {
                resp = node;
            }
            else if (!xmlStrcmp(node->name, BAD_CAST "sharer-resource-uri")) {
                sharedurl = xmlFirstElementChild(node);
            }
            else if (!xmlStrcmp(node->name, BAD_CAST "principal")) {
                sharer = xmlFirstElementChild(node);
                node2 = xmlNextElementSibling(sharer);
                if (!xmlStrcmp(node2->name, BAD_CAST "prop")) {
                    for (node2 = xmlFirstElementChild(node2); node2;
                         node2 = xmlNextElementSibling(node2)) {
                        if (!xmlStrcmp(node2->name, BAD_CAST "displayname")) {
                            name = xmlNodeGetContent(node2);
                        }
                    }
                }
            }
            else if (!xmlStrcmp(node->name, BAD_CAST "share-access")) {
                access = xmlFirstElementChild(node);
            }
            else if (!xmlStrcmp(node->name, BAD_CAST "comment")) {
                comment = xmlNodeGetContent(node);
            }
            else if (!xmlStrcmp(node->name, BAD_CAST "prop")) {
                for (node2 = xmlFirstElementChild(node); node2;
                     node2 = xmlNextElementSibling(node2)) {
                    if (!xmlStrcmp(node2->name,
                                   BAD_CAST "supported-calendar-component-set")) {
                        calcompset = node2;
                    }
                }
            }
        }

        invite = xmlNewChild(notify, NULL, BAD_CAST "invite-notification", NULL);

        xmlNewChild(invite, NULL, BAD_CAST "uid", BAD_CAST wdata->dav.resource);

        /* Sharee href */
        buf_reset(&buf);
        buf_printf(&buf, "%s/%s/%s/", namespace_principal.prefix,
                   USER_COLLECTION_PREFIX, txn->req_tgt.userid);
        node = xml_add_href(invite, NULL, buf_cstring(&buf));
        ensure_ns(ns, NS_DAV, node, XML_NS_DAV, "D");
        xmlSetNs(node, ns[NS_DAV]);

#if 0  /* XXX  Apple clients seem to always want "noresponse" */
        xmlNewChild(invite, NULL, resp->name, NULL);
#else
        xmlNewChild(invite, NULL, BAD_CAST "invite-noresponse", NULL);
#endif

        node = xmlNewChild(invite, NULL, BAD_CAST "access", NULL);
        xmlNewChild(node, NULL, access->name, NULL);
        node = xmlNewChild(invite, NULL, BAD_CAST "hosturl", NULL);
        xmlAddChild(node, xmlCopyNode(sharedurl, 1));
        node = xmlNewChild(invite, NULL, BAD_CAST "organizer", NULL);
        xmlAddChild(node, xmlCopyNode(sharer, 1));
        if (name) {
            xmlNewChild(node, NULL, BAD_CAST "common-name", name);
            xmlFree(name);
        }

        if (comment) {
            xmlNewChild(invite, NULL, BAD_CAST "summary", comment);
            xmlFree(comment);
        }
        if (calcompset) {
            xmlAddChild(invite, xmlCopyNode(calcompset, 1));
        }

        buf_free(&buf);
    }
    else if (notify_type == SHARE_REPLY) {
        xmlNodePtr reply, sharee = NULL;

        /* Grab DAV elements that we need to construct CS notification */
        for (node = xmlFirstElementChild(type); node;
             node = xmlNextElementSibling(node)) {
            if (!xmlStrcmp(node->name, BAD_CAST "sharee")) {
                for (node2 = xmlFirstElementChild(node); node2;
                     node2 = xmlNextElementSibling(node2)) {
                    if (!xmlStrcmp(node2->name, BAD_CAST "href")) {
                        sharee = node2;
                    }
                    else if (!xmlStrncmp(node2->name, BAD_CAST "invite-", 7)) {
                        resp = node2;
                    }
                }
            }
            else if (!xmlStrcmp(node->name, BAD_CAST "href")) {
                sharedurl = node;
            }
            else if (!xmlStrcmp(node->name, BAD_CAST "comment")) {
                comment = xmlNodeGetContent(node);
            }
        }

        reply = xmlNewChild(notify, NULL, BAD_CAST "invite-reply", NULL);

        xmlAddChild(reply, xmlCopyNode(sharee, 1));
        xmlNewChild(reply, NULL, resp->name, NULL);
        node = xmlNewChild(reply, NULL, BAD_CAST "hosturl", NULL);
        xmlAddChild(node, xmlCopyNode(sharedurl, 1));

        xmlNewChild(reply, NULL,
                    BAD_CAST "in-reply-to", BAD_CAST wdata->dav.resource);

        if (comment) {
            xmlNewChild(reply, NULL, BAD_CAST "summary", comment);
            xmlFree(comment);
        }
    }
    else {
        /* Unknown type - return as-is */
        xmlFreeDoc(notify->doc);
        notify = NULL;
        outdoc = indoc;
    }

    /* Dump XML tree into a text buffer */
    outbuf = from_xml(outdoc);

    write_body(HTTP_OK, txn, buf_cstring(outbuf), buf_len(outbuf));

  done:
    if (dtstamp) xmlFree(dtstamp);
    if (notify) xmlFreeDoc(notify->doc);
    if (indoc) xmlFreeDoc(indoc);
    buf_destroy(outbuf);
    dlist_free(&dl);

    return ret;
}

static struct dlist *notify_extract_dl(xmlDocPtr doc)
{
    xmlNodePtr root, dtstamp, type = NULL;

    /* Get type of notification */
    if ((root = xmlDocGetRootElement(doc)) &&
        (dtstamp = xmlFirstElementChild(root))) {
        type = xmlNextElementSibling(dtstamp);
    }

    /* Create and cache RFC 5322 header fields for resource */
    if (!type) {
        return NULL;
    }

    /* Create a dlist representing type, namespace, and attribute(s) */
    time_t t;
    xmlChar *value = xmlNodeGetContent(dtstamp);
    time_from_iso8601((const char *) value, &t);
    xmlFree(value);

    struct dlist *dl = dlist_newkvlist(NULL, "N");
    dlist_setdate(dl, "S", t);
    dlist_setatom(dl, "NS", (char *) type->ns->href);
    dlist_setatom(dl, "T", (char *) type->name);

    /* Add any attributes */
    xmlAttrPtr attr;
    struct dlist *al = dlist_newkvlist(dl, "A");
    for (attr = type->properties; attr; attr = attr->next) {
        value = xmlNodeGetContent((xmlNodePtr) attr);
        dlist_setmap(al, (char *) attr->name,
                (char *) value, xmlStrlen(value));
        xmlFree(value);
    }

    /* Add any additional data */
    al = dlist_newkvlist(dl, "D");
    if (!xmlStrcmp(type->name, BAD_CAST SHARE_INVITE_NOTIFICATION)) {
        xmlNodePtr node;
        for (node = xmlFirstElementChild(type); node;
                node = xmlNextElementSibling(node)) {
            if (!xmlStrcmp(node->name, BAD_CAST "sharer-resource-uri")) {
                struct request_target_t tgt;
                struct meth_params *pparams;
                const char *path, *errstr;
                int i;

                value = xmlNodeGetContent(xmlFirstElementChild(node));
                path = (const char *) value;

                /* Find the namespace of the requested resource */
                for (i = 0; http_namespaces[i]; i++) {
                    size_t len;

                    /* Skip disabled namespaces */
                    if (!http_namespaces[i]->enabled) continue;

                    /* See if the prefix matches - terminated with NUL or '/' */
                    len = strlen(http_namespaces[i]->prefix);
                    if (!strncmp(path, http_namespaces[i]->prefix, len) &&
                            (!path[len] || (path[len] == '/') || !strcmp(path, "*"))) {
                        break;
                    }
                }

                memset(&tgt, 0, sizeof(struct request_target_t));
                tgt.namespace = http_namespaces[i];
                pparams =
                    (struct meth_params *) tgt.namespace->methods[METH_PUT].params;
                tgt.flags = TGT_DAV_SHARED;  // prevent old-style sharing redirect
                pparams->parse_path(path, &tgt, &errstr);
                xmlFree(value);
                free(tgt.userid);

                dlist_setatom(al, "M", tgt.mbentry->name);

                mboxlist_entry_free(&tgt.mbentry);
                break;
            }
        }
    }

    return dl;
}

static int dav_store_notification(struct transaction_t *txn,
                                  xmlDocPtr doc, struct dlist *extradata,
                                  struct mailbox *mailbox, const char *resource,
                                  struct webdav_db *db)
{
    struct webdav_data *wdata;
    struct index_record *oldrecord = NULL, record;
    struct buf *xmlbuf = NULL;
    int r;

    mbentry_t *mbentry = NULL;
    r = mboxlist_lookup_by_uniqueid(mailbox_uniqueid(mailbox), &mbentry, NULL);
    if (r) goto done;

    /* Find message UID for the resource */
    webdav_lookup_resource(db, mbentry, resource, &wdata, 0);

    if (wdata->dav.imap_uid) {
        /* Fetch index record for the resource */
        oldrecord = &record;
        mailbox_find_index_record(mailbox, wdata->dav.imap_uid, oldrecord);
    }

    struct dlist *dl = notify_extract_dl(doc);
    if (!dl) {
        r = HTTP_FORBIDDEN;
        goto done;
    }

    if (extradata) {
        struct dlist *md = dlist_newkvlist(dl, "X");
        dlist_stitch(md, extradata); // XXX takes ownership
    }

    const char *type;
    if (dlist_getatom(dl, "T", &type)) {
        spool_replace_header(xstrdup("Subject"),
                             xstrdup((char *) type), txn->req_hdrs);

        struct buf buf = BUF_INITIALIZER;
        dlist_printbuf(dl, 1, &buf);
        dlist_free(&dl);
        spool_replace_header(xstrdup("Content-Description"),
                buf_release(&buf), txn->req_hdrs);
    }

    buf_reset(&txn->buf);
    buf_printf(&txn->buf, "<%s-%ld@%s>", resource, time(0), config_servername);
    spool_replace_header(xstrdup("Message-ID"),
                         buf_release(&txn->buf), txn->req_hdrs);

    buf_printf(&txn->buf, "attachment;\r\n\tfilename=\"%s\"", resource);
    spool_replace_header(xstrdup("Content-Disposition"),
                         buf_release(&txn->buf), txn->req_hdrs);

    /* Dump XML response tree into a text buffer */
    xmlbuf = from_xml(doc);
    if (!buf_len(xmlbuf)) r = HTTP_SERVER_ERROR;
    else {
        /* Store the resource */
        r = dav_store_resource(txn, buf_cstring(xmlbuf), buf_len(xmlbuf),
                               mailbox, oldrecord, wdata->dav.createdmodseq,
                               NULL, NULL);
    }

done:
    buf_destroy(xmlbuf);
    mboxlist_entry_free(&mbentry);
    return r;
}

HIDDEN int dav_send_notification(xmlDocPtr doc, struct dlist *extradata,
                                 const char *userid, const char *resource)
{
    struct mailbox *mailbox = NULL;
    struct webdav_db *webdavdb = NULL;
    struct transaction_t txn;
    mbentry_t mbentry;
    int r;

    /* XXX  Need to find location of user.
       If remote need to do a PUT or possibly email */

    /* Open notifications collection for writing */
    r = create_notify_collection(userid, &mailbox);
    if (r == IMAP_INVALID_USER) {
        syslog(LOG_NOTICE,
               "dav_send_notification(%s) failed: %s", userid, error_message(r));
        return 0;
    }
    else if (r) {
        syslog(LOG_ERR,
               "dav_send_notification: create_notify_collection(%s) failed: %s",
               userid, error_message(r));
        return r;
    }

    /* Open the WebDAV DB corresponding to collection */
    webdavdb = webdav_open_mailbox(mailbox);
    if (!webdavdb) {
        syslog(LOG_ERR, "dav_send_notification: unable to open WebDAV DB (%s)",
               mailbox_name(mailbox));
        r = HTTP_SERVER_ERROR;
        goto done;
    }

    /* Start with an empty (clean) transaction */
    memset(&txn, 0, sizeof(struct transaction_t));
    txn.userid = httpd_userid;
    txn.authstate = httpd_authstate;

    /* Create minimal mbentry for request target from mailbox */
    memset(&mbentry, 0, sizeof(mbentry_t));
    mbentry.name = (char *)mailbox_name(mailbox);
    mbentry.uniqueid = (char *)mailbox_uniqueid(mailbox);
    txn.req_tgt.mbentry = &mbentry;

    /* Create header cache */
    if (!(txn.req_hdrs = spool_new_hdrcache())) {
        syslog(LOG_ERR, "dav_send_notification: unable to create header cache");
        r = HTTP_SERVER_ERROR;
        goto done;
    }

    spool_cache_header(xstrdup("Content-Type"),
                       xstrdup(DAVNOTIFICATION_CONTENT_TYPE), txn.req_hdrs);

    r = dav_store_notification(&txn, doc, extradata,
                               mailbox, resource, webdavdb);
    if (r != HTTP_CREATED && r != HTTP_NO_CONTENT) {
        xsyslog(LOG_ERR, "can not store notification",
                "mboxname=<%s> resource=<%s> err=<%s>",
                mailbox_name(mailbox), resource, error_message(r));
    }

  done:
    spool_free_hdrcache(txn.req_hdrs);
    buf_free(&txn.buf);
    webdav_close(webdavdb);
    mailbox_close(&mailbox);

    return r;
}


/* Perform a POST request on a WebDAV notification resource */
HIDDEN int notify_post(struct transaction_t *txn)
{
    xmlNodePtr root = NULL, node, resp = NULL;
    int rights, ret, r, legacy = 0, add = 0;
    struct mailbox *shared = NULL;
    struct webdav_db *webdavdb = NULL;
    struct webdav_data *wdata;
    struct dlist *dl = NULL, *data;
    const char *type_str, *mboxname, *url_prefix;
    char dtstamp[RFC3339_DATETIME_MAX], *resource = NULL;
    xmlNodePtr notify = NULL, type, sharee;
    xmlNsPtr ns[NUM_NAMESPACE];
    xmlChar *comment = NULL, *freeme = NULL;
    mbname_t *mbname = NULL;

    /* Check ACL for current user */
    rights = httpd_myrights(httpd_authstate, txn->req_tgt.mbentry);
    if (!(rights & DACL_ADMIN)) {
        /* DAV:need-privileges */
        txn->error.precond = DAV_NEED_PRIVS;
        txn->error.resource = txn->req_tgt.path;
        txn->error.rights = DACL_ADMIN;
        return HTTP_NO_PRIVS;
    }

    if (txn->req_tgt.mbentry->server) {
        /* Remote mailbox */
        struct backend *be;

        be = proxy_findserver(txn->req_tgt.mbentry->server,
                              &http_protocol, httpd_userid,
                              &backend_cached, NULL, NULL, httpd_in);
        if (!be) return HTTP_UNAVAILABLE;

        return http_pipe_req_resp(be, txn);
    }

    /* Local Mailbox */

    /* Read body */
    ret = parse_xml_body(txn, &root, DAVSHARING_CONTENT_TYPE);
    if (!ret && !root) {
        txn->error.desc = "Missing request body";
        ret = HTTP_BAD_REQUEST;
    }
    if (ret) goto done;

    /* Make sure its a invite-reply element */
    if (xmlStrcmp(root->name, BAD_CAST "invite-reply")) {
        txn->error.desc =
            "Missing invite-reply element in POST request";
        ret = HTTP_BAD_REQUEST;
        goto done;
    }

    resource = txn->req_tgt.resource;
    if (!resource) legacy = 1;

    /* Fetch needed elements */
    for (node = xmlFirstElementChild(root); node;
         node = xmlNextElementSibling(node)) {
        if (!xmlStrncmp(node->name, BAD_CAST "invite-", 7)) {
            if (!xmlStrcmp(node->name, BAD_CAST "invite-accepted")) add = 1;
            resp = node;
        }
        else if (legacy) {
            if (!xmlStrcmp(node->name, BAD_CAST "in-reply-to")) {
                freeme = xmlNodeGetContent(node);
                resource = (char *) freeme;
            }
            else if (!xmlStrcmp(node->name, BAD_CAST "summary")) {
                comment = xmlNodeGetContent(node);
            }
        }
        else if (!xmlStrcmp(node->name, BAD_CAST "comment")) {
            comment = xmlNodeGetContent(node);
        }
    }

    if (!resp) {
        txn->error.desc = "Missing invite response element in POST request";
        ret = HTTP_BAD_REQUEST;
        goto done;
    }
    if (!resource) {
        txn->error.desc = "Missing in-reply-to element in POST request";
        ret = HTTP_BAD_REQUEST;
        goto done;
    }

    if (legacy) {
        /* Locate notification mailbox for target user */
        mboxlist_entry_free(&txn->req_tgt.mbentry);
        txn->req_tgt.mbentry = NULL;
        r = dav_lookup_notify_collection(txn->req_tgt.userid, &txn->req_tgt.mbentry);
        if (r) {
            syslog(LOG_ERR, "lookup_notify_collection(%s) failed: %s",
                   txn->req_tgt.userid, error_message(r));
            txn->error.desc = error_message(r);
            ret = HTTP_SERVER_ERROR;
            goto done;
        }
    }

    /* Open the WebDAV DB corresponding to the mailbox */
    webdavdb = webdav_open_userid(txn->req_tgt.userid);

    /* Find message UID for the resource */
    webdav_lookup_resource(webdavdb, txn->req_tgt.mbentry,
                           resource, &wdata, 0);
    if (!wdata->dav.imap_uid) {
        ret = HTTP_NOT_FOUND;
        goto done;
    }

    /* Parse dlist representing notification type, and data */
    dlist_parsemap(&dl, 1, 0, wdata->filename, strlen(wdata->filename));
    dlist_getatom(dl, "T", &type_str);
    if (strcmp(type_str, SHARE_INVITE_NOTIFICATION)) {
        ret = HTTP_NOT_ALLOWED;
        goto done;
    }

    dlist_getlist(dl, "D", &data);
    dlist_getatom(data, "M", &mboxname);

    /* [Un]subscribe */
    r = mboxlist_changesub(mboxname, txn->req_tgt.userid,
                           httpd_authstate, add, 0, 0);
    if (r) {
        syslog(LOG_ERR, "mboxlist_changesub(%s, %s) failed: %s",
               mboxname, txn->req_tgt.userid, error_message(r));
        txn->error.desc = error_message(r);
        ret = HTTP_SERVER_ERROR;
        goto done;
    }

    /* Set invite status */
    r = mailbox_open_iwl(mboxname, &shared);
    if (r) {
        xsyslog(LOG_ERR, "IOERROR: failed to open mailbox for share reply",
                         "mailbox=<%s>", mboxname);
    }
    else {
        annotate_state_t *astate = NULL;

        r = mailbox_get_annotate_state(shared, 0, &astate);
        if (!r) {
            const char *annot = DAV_ANNOT_NS "<" XML_NS_DAV ">invite-status";
            struct buf value = BUF_INITIALIZER;

            buf_init_ro_cstr(&value, (char *) resp->name);
            r = annotate_state_writemask(astate, annot,
                                         txn->req_tgt.userid, &value);

            if (mbtype_isa(mailbox_mbtype(shared)) == MBTYPE_CALENDAR) {
                /* Sharee's copy of calendar SHOULD default to transparent */
                annot =
                    DAV_ANNOT_NS "<" XML_NS_CALDAV ">schedule-calendar-transp";
                buf_init_ro_cstr(&value, "transparent");
                r = annotate_state_writemask(astate, annot,
                                             txn->req_tgt.userid, &value);
            }
        }

        mailbox_close(&shared);
    }

    /* Create share-reply-notification */
    notify = init_xml_response("notification", NS_DAV, NULL, ns);

    time_to_rfc3339(time(0), dtstamp, RFC3339_DATETIME_MAX);
    xmlNewChild(notify, NULL, BAD_CAST "dtstamp", BAD_CAST dtstamp);

    type = xmlNewChild(notify, NULL, BAD_CAST SHARE_REPLY_NOTIFICATION, NULL);

    sharee = xmlNewChild(type, NULL, BAD_CAST "sharee", NULL);
    buf_reset(&txn->buf);
    buf_printf(&txn->buf, "%s/%s/%s/", namespace_principal.prefix,
               USER_COLLECTION_PREFIX, txn->req_tgt.userid);
    xml_add_href(sharee, NULL, buf_cstring(&txn->buf));

    node = xmlNewChild(sharee, NULL, resp->name, NULL);

    /* shared-url */
    url_prefix = strstr(mboxname, config_getstring(IMAPOPT_CALENDARPREFIX)) ?
        namespace_calendar.prefix : namespace_addressbook.prefix;

    mbname = mbname_from_intname(mboxname);
    if (!mbname_domain(mbname)) mbname_set_domain(mbname, httpd_extradomain);

    make_collection_url(&txn->buf, url_prefix, /*haszzzz*/0, mbname, "");

    xml_add_href(type, NULL, buf_cstring(&txn->buf));

    if (comment) {
        xmlNewChild(type, NULL, BAD_CAST "comment", comment);
        xmlFree(comment);
    }

    /* Create a resource name for the notifications -
       We use a consistent naming scheme so that multiple notifications
       of the same type for the same resource are coalesced (overwritten) */
    buf_reset(&txn->buf);
    buf_printf(&txn->buf, "%x-%x-%x-%x.xml",
               strhash(XML_NS_DAV), strhash(SHARE_REPLY_NOTIFICATION),
               strhash(mboxname), strhash(txn->req_tgt.userid));

    r = dav_send_notification(notify->doc, NULL, mbname_userid(mbname),
                              buf_cstring(&txn->buf));


    if (add) {
        /* Accepted - create URL of sharee's new collection */
        make_collection_url(&txn->buf, url_prefix, /*haszzzz*/0,
                            mbname, txn->req_tgt.userid);

        if (legacy) {
            /* Create CS:shared-as XML body */
            xmlNodePtr shared_as = init_xml_response("shared-as", NS_CS, NULL, ns);
            if (!shared_as) {
                ret = HTTP_SERVER_ERROR;
                goto done;
            }

            node = xml_add_href(shared_as, NULL, buf_cstring(&txn->buf));
            ensure_ns(ns, NS_DAV, node, XML_NS_DAV, "D");
            xmlSetNs(node, ns[NS_DAV]);
            xml_response(HTTP_OK, txn, shared_as->doc);
            xmlFreeDoc(shared_as->doc);
            ret = 0;
        }
        else {
            /* Add Location header */
            txn->location = buf_cstring(&txn->buf);
            ret = HTTP_CREATED;
        }
    }
    else {
        /* Declined */
        ret = HTTP_NO_CONTENT;
    }

  done:
    if (freeme) xmlFree(freeme);
    if (root) xmlFreeDoc(root->doc);
    if (notify) xmlFreeDoc(notify->doc);
    webdav_close(webdavdb);
    mbname_free(&mbname);
    dlist_free(&dl);

    return ret;
}

/* Determine allowed methods in notify namespace */
static unsigned long notify_allow_cb(struct request_target_t *tgt)
{
    unsigned long allow = tgt->namespace->allow;

    if (!tgt->resource) {
        allow &= ~(ALLOW_DELETE | ALLOW_POST);
    }

    return allow;
}


/* Parse request-target path in DAV notifications namespace */
static int notify_parse_path(const char *path, struct request_target_t *tgt,
                             const char **resultstr)
{
    char *p;
    size_t len;
    mbname_t *mbname = NULL;

    /* Make a working copy of target path */
    strlcpy(tgt->path, path, sizeof(tgt->path));
    tgt->tail = tgt->path + strlen(tgt->path);

    p = tgt->path;

    /* Sanity check namespace */
    len = strlen(namespace_notify.prefix);
    if (strlen(p) < len ||
        strncmp(namespace_notify.prefix, p, len) ||
        (path[len] && path[len] != '/')) {
        *resultstr = "Namespace mismatch request target path";
        return HTTP_FORBIDDEN;
    }

    tgt->mboxprefix = config_getstring(IMAPOPT_DAVNOTIFICATIONSPREFIX);

    /* Default to bare-bones Allow bits */
    tgt->allow &= ALLOW_READ_MASK;

    /* Skip namespace */
    p += len;
    if (!*p || !*++p) return 0;

    /* Check if we're in user space */
    len = strcspn(p, "/");
    if (!strncmp(p, USER_COLLECTION_PREFIX, len)) {
        p += len;
        if (!*p || !*++p) return 0;

        /* Get user id */
        len = strcspn(p, "/");
        tgt->userid = xstrndup(p, len);

        if (httpd_extradomain) {
            char *at = strchr(tgt->userid, '@');
            if (at && !strcmp(at+1, httpd_extradomain))
                *at = 0;
        }

        p += len;
        if (!*p || !*++p) goto done;
    }
    else return HTTP_NOT_FOUND;  /* need to specify a userid */


    /* Get resource */
    len = strcspn(p, "/");
    tgt->resource = p;
    tgt->reslen = len;

    p += len;

    if (*p) {
//      *resultstr = "Too many segments in request target path";
        return HTTP_NOT_FOUND;
    }

  done:
    /* Create mailbox name from the parsed path */

    mbname = mbname_from_userid(tgt->userid);
    mbname_push_boxes(mbname, config_getstring(IMAPOPT_DAVNOTIFICATIONSPREFIX));

    /* XXX - hack to allow @domain parts for non-domain-split users */
    if (httpd_extradomain) {
        /* not allowed to be cross domain */
        if (mbname_localpart(mbname) &&
            strcmpsafe(mbname_domain(mbname), httpd_extradomain))
            return HTTP_NOT_FOUND;
        mbname_set_domain(mbname, NULL);
    }

    const char *mboxname = mbname_intname(mbname);

    if (*mboxname) {
        /* Locate the mailbox */
        int r = proxy_mlookup(mboxname, &tgt->mbentry, NULL, NULL);
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
    tgt->allow |= ALLOW_ACL;

    if (tgt->resource) tgt->allow |= ALLOW_POST | ALLOW_DELETE;

    return 0;
}


struct userid_rights {
    long positive;
    long negative;
};

static void parse_acl(hash_table *table, const char *origacl)
{
    char *acl = xstrdupsafe(origacl);
    char *thisid, *rights, *nextid;

    for (thisid = acl; *thisid; thisid = nextid) {
        struct userid_rights *id_rights;
        int is_negative = 0;
        int mask;

        rights = strchr(thisid, '\t');
        if (!rights) {
            break;
        }
        *rights++ = '\0';

        nextid = strchr(rights, '\t');
        if (!nextid) {
            rights[-1] = '\t';
            break;
        }
        *nextid++ = '\0';

        if (*thisid == '-') {
            is_negative = 1;
            thisid++;
        }

        id_rights = hash_lookup(thisid, table);
        if (!id_rights) {
            id_rights = xzmalloc(sizeof(struct userid_rights));
            hash_insert(thisid, id_rights, table);
        }

        cyrus_acl_strtomask(rights, &mask);
        /* XXX and if strtomask fails? */
        if (is_negative) id_rights->negative |= mask;
        else id_rights->positive |= mask;
    }

    free(acl);
}

struct invite_rock {
    const char *owner;
    int is_shared;
    struct propfind_ctx *fctx;
    xmlNodePtr node;
    int legacy;
};

static void xml_add_sharee(const char *userid, void *data, void *rock)
{
    struct userid_rights *id_rights = (struct userid_rights *) data;
    struct invite_rock *irock = (struct invite_rock *) rock;
    int rights = id_rights->positive & ~id_rights->negative;
    struct auth_state *authstate;
    int isadmin;

    if ((rights & DACL_SHARE) != DACL_SHARE) return;  /* not shared */
    if (!strcmp(userid, irock->owner)) return;  /* user is owner */

    authstate = auth_newstate(userid);
    isadmin = global_authisa(authstate, IMAPOPT_ADMINS);
    auth_freestate(authstate);
    if (isadmin) return;  /* user is an admin */


    irock->is_shared = 1;

    if (irock->node) {
        xmlNodePtr sharee, access;
        const char *annot = DAV_ANNOT_NS "<" XML_NS_DAV ">invite-status";
        const char *resp = "invite-noresponse";
        struct buf value = BUF_INITIALIZER;
        int r;

        sharee = xmlNewChild(irock->node, NULL,
                             BAD_CAST (irock->legacy ? "user" : "sharee"), NULL);

        buf_reset(&irock->fctx->buf);
        if (strchr(userid, '@')) {
            buf_printf(&irock->fctx->buf, "mailto:%s", userid);
        }
        else {
            const char *domain = httpd_extradomain;
            if (!domain) domain = config_defdomain;
            if (!domain) domain = config_servername;

            buf_printf(&irock->fctx->buf, "mailto:%s@%s", userid, domain);
        }
        xml_add_href(sharee, irock->fctx->ns[NS_DAV],
                     buf_cstring(&irock->fctx->buf));

        /* Lookup invite status */
        r = annotatemore_lookupmask(irock->fctx->mbentry->name,
                                    annot, userid, &value);
        if (!r && buf_len(&value)) resp = buf_cstring(&value);
        xmlNewChild(sharee, NULL, BAD_CAST resp, NULL);
        buf_free(&value);

        access = xmlNewChild(sharee, NULL,
                             BAD_CAST (irock->legacy ? "access" :
                                       "share-access"), NULL);
        if ((rights & DACL_SHARERW) == DACL_SHARERW)
            xmlNewChild(access, NULL, BAD_CAST "read-write", NULL);
        else xmlNewChild(access, NULL, BAD_CAST "read", NULL);
    }
}


HIDDEN void xml_add_shareaccess(struct propfind_ctx *fctx,
                                xmlNodePtr resp, xmlNodePtr node, int legacy)
{
    if (mboxname_userownsmailbox(fctx->req_tgt->userid, fctx->mbentry->name)) {
        hash_table table;
        struct invite_rock irock = { fctx->req_tgt->userid, 0, NULL, NULL, 0 };

        construct_hash_table(&table, 10, 1);
        parse_acl(&table, fctx->mbentry->acl);
        hash_enumerate(&table, &xml_add_sharee, &irock);

        if (irock.is_shared) {
            xmlNsPtr ns = fctx->ns[NS_DAV];

            if (legacy) {
                ensure_ns(fctx->ns, NS_CS, resp->parent, XML_NS_CS, "CS");
                ns = fctx->ns[NS_CS];
            }
            xmlNewChild(node, ns, BAD_CAST "shared-owner", NULL);
        }
        else if (!legacy)
            xmlNewChild(node, NULL, BAD_CAST "not-shared", NULL);

        free_hash_table(&table, &free);
    }
    else if (legacy) {
        ensure_ns(fctx->ns, NS_CS, resp->parent, XML_NS_CS, "CS");
        xmlNewChild(node, fctx->ns[NS_CS], BAD_CAST "shared", NULL);
    }
    else {
        int rights = httpd_myrights(httpd_authstate, fctx->mbentry);

        if ((rights & DACL_SHARERW) == DACL_SHARERW)
            xmlNewChild(node, NULL, BAD_CAST "read-write", NULL);
        else
            xmlNewChild(node, NULL, BAD_CAST "read", NULL);
    }
}


/* Callback to fetch DAV:share-access */
HIDDEN int propfind_shareaccess(const xmlChar *name, xmlNsPtr ns,
                                struct propfind_ctx *fctx,
                                xmlNodePtr prop __attribute__((unused)),
                                xmlNodePtr resp,
                                struct propstat propstat[],
                                void *rock __attribute__((unused)))
{
    xmlNodePtr node;

    if (!fctx->mbentry) return HTTP_NOT_FOUND;

    node = xml_add_prop(HTTP_OK, fctx->ns[NS_DAV],
                        &propstat[PROPSTAT_OK], name, ns, NULL, 0);

    xml_add_shareaccess(fctx, resp, node, 0 /* legacy */);

    return 0;
}


/* Callback to fetch DAV:invite and CS:invite */
HIDDEN int propfind_invite(const xmlChar *name, xmlNsPtr ns,
                           struct propfind_ctx *fctx,
                           xmlNodePtr prop __attribute__((unused)),
                           xmlNodePtr resp __attribute__((unused)),
                           struct propstat propstat[], void *rock)
{
    struct invite_rock irock = { fctx->req_tgt->userid, 0 /* is_shared */,
                                 fctx, NULL, rock != 0 /* legacy */ };
    xmlNodePtr node;

    fctx->flags.cs_sharing = (rock != 0);

    if (!fctx->mbentry) return HTTP_NOT_FOUND;

    node = xml_add_prop(HTTP_OK, fctx->ns[NS_DAV],
                        &propstat[PROPSTAT_OK], name, ns, NULL, 0);
    irock.node = node;

    if (mboxname_userownsmailbox(fctx->req_tgt->userid, fctx->mbentry->name)) {
        hash_table table;

        construct_hash_table(&table, 10, 1);

        parse_acl(&table, fctx->mbentry->acl);
        hash_enumerate(&table, &xml_add_sharee, &irock);

        free_hash_table(&table, &free);
    }
    else {
        struct userid_rights id_rights = 
            { httpd_myrights(httpd_authstate, fctx->mbentry), 0 /* neg */};

        irock.owner = "";
        xml_add_sharee(fctx->req_tgt->userid, &id_rights, &irock);
    }

    return 0;
}


/* Callback to fetch DAV:sharer-resource-uri and CS:shared-url */
HIDDEN int propfind_sharedurl(const xmlChar *name, xmlNsPtr ns,
                              struct propfind_ctx *fctx,
                              xmlNodePtr prop __attribute__((unused)),
                              xmlNodePtr resp __attribute__((unused)),
                              struct propstat propstat[], void *rock)
{
    mbname_t *mbname;
    const strarray_t *boxes;
    int n, size;
    xmlNodePtr node;

    fctx->flags.cs_sharing = (rock != 0);

    mbname = mbname_from_intname(mailbox_name(fctx->mailbox));

    if (!strcmpsafe(mbname_userid(mbname), fctx->req_tgt->userid)) {
        mbname_free(&mbname);
        return HTTP_NOT_FOUND;
    }

    buf_setcstr(&fctx->buf, fctx->req_tgt->namespace->prefix);

    if (mbname_localpart(mbname)) {
        const char *domain =
            mbname_domain(mbname) ? mbname_domain(mbname) : httpd_extradomain;

        buf_printf(&fctx->buf, "/%s/%s",
                   USER_COLLECTION_PREFIX, mbname_localpart(mbname));
        if (domain) buf_printf(&fctx->buf, "@%s", domain);
    }
    buf_putc(&fctx->buf, '/');

    boxes = mbname_boxes(mbname);
    size = strarray_size(boxes);
    for (n = 1; n < size; n++) {
        buf_appendcstr(&fctx->buf, strarray_nth(boxes, n));
        buf_putc(&fctx->buf, '/');
    }

    node = xml_add_prop(HTTP_OK, fctx->ns[NS_DAV],
                        &propstat[PROPSTAT_OK], name, ns, NULL, 0);

    xml_add_href(node, fctx->ns[NS_DAV], buf_cstring(&fctx->buf));

    mbname_free(&mbname);

    return 0;
}


/* Callback to fetch DAV:notification-URL and CS:notification-URL */
HIDDEN int propfind_notifyurl(const xmlChar *name, xmlNsPtr ns,
                              struct propfind_ctx *fctx,
                              xmlNodePtr prop,
                              xmlNodePtr resp __attribute__((unused)),
                              struct propstat propstat[],
                              void *rock __attribute__((unused)))
{
    xmlNodePtr node;

    if (!(namespace_principal.enabled && fctx->req_tgt->userid))
        return HTTP_NOT_FOUND;

    node = xml_add_prop(HTTP_OK, fctx->ns[NS_DAV], &propstat[PROPSTAT_OK],
                        name, ns, NULL, 0);

    buf_reset(&fctx->buf);
    buf_printf(&fctx->buf, "%s/%s/%s/", namespace_notify.prefix,
               USER_COLLECTION_PREFIX, fctx->req_tgt->userid);

    if ((fctx->mode == PROPFIND_EXPAND) && xmlFirstElementChild(prop)) {
        /* Return properties for this URL */
        expand_property(prop, fctx, &namespace_notify, buf_cstring(&fctx->buf),
                        &notify_parse_path, notify_props, node, 0);

    }
    else {
        /* Return just the URL */
        xml_add_href(node, fctx->ns[NS_DAV], buf_cstring(&fctx->buf));
    }

    return 0;
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

    if (!fctx->record) {
        xmlNewChild(node, NULL, BAD_CAST "collection", NULL);

        if (fctx->req_tgt->userid) {
            xmlNewChild(node, NULL, BAD_CAST "notifications", NULL);

            ensure_ns(fctx->ns, NS_CS, resp->parent, XML_NS_CS, "CS");
            xmlNewChild(node, fctx->ns[NS_CS], BAD_CAST "notification", NULL);
        }
    }

    return 0;
}


/* Callback to fetch DAV:notificationtype */
static int propfind_notifytype(const xmlChar *name, xmlNsPtr ns,
                               struct propfind_ctx *fctx,
                               xmlNodePtr prop __attribute__((unused)),
                               xmlNodePtr resp __attribute__((unused)),
                               struct propstat propstat[], void *rock)
{
    struct webdav_data *wdata = (struct webdav_data *) fctx->data;
    xmlNodePtr node;
    xmlNsPtr type_ns = NULL;
    struct dlist *dl = NULL, *al, *item;
    const char *ns_href, *type;
    int i;

    if (!wdata->filename) return HTTP_NOT_FOUND;

    node = xml_add_prop(HTTP_OK, fctx->ns[NS_DAV], &propstat[PROPSTAT_OK],
                        name, ns, NULL, 0);

    /* Parse dlist representing notification type, namespace, and attributes */
    dlist_parsemap(&dl, 1, 0, wdata->filename, strlen(wdata->filename));
    dlist_getatom(dl, "T", &type);
    dlist_getatom(dl, "NS", &ns_href);
    dlist_getlist(dl, "A", &al);

    if (rock /* calendarserver-sharing */) {
        if (!strcmp(type, SHARE_INVITE_NOTIFICATION))
            type = "invite-notification";
        else if (!strcmp(type, SHARE_REPLY_NOTIFICATION))
            type = "invite-reply";
    }
    else {
        /* Check if we already have this ns-href, otherwise create a new one */
        type_ns = xmlSearchNsByHref(node->doc, node, BAD_CAST ns_href);
        if (!type_ns) {
            char prefix[20];
            snprintf(prefix, sizeof(prefix), "X%X", strhash(ns_href) & 0xffff);
            type_ns = xmlNewNs(node, BAD_CAST ns_href, BAD_CAST prefix);
        }
    }

    /* Create node for type */
    node = xmlNewChild(node, type_ns, BAD_CAST type, NULL);

    /* Add attributes */
    for (i = 0; (item = dlist_getchildn(al, i)); i++) {
        xmlNewProp(node, BAD_CAST item->name, BAD_CAST dlist_cstring(item));
    }

    dlist_free(&dl);

    return 0;
}


HIDDEN int propfind_csnotify_collection(struct propfind_ctx *fctx,
                                        xmlNodePtr props)
{
    struct propfind_ctx my_fctx;
    struct request_target_t tgt;
    const char *err = NULL;

    /* Populate our propfind context for notification collection */
    memset(&my_fctx, 0, sizeof(struct propfind_ctx));

    buf_printf(&my_fctx.buf, "%s/%s/%s/", namespace_notify.prefix,
               USER_COLLECTION_PREFIX, fctx->req_tgt->userid);

    memset(&tgt, 0, sizeof(struct request_target_t));
    tgt.namespace = &namespace_notify;
    notify_parse_path(buf_cstring(&my_fctx.buf), &tgt, &err);

    my_fctx.txn = fctx->txn;
    my_fctx.req_tgt = &tgt;
    my_fctx.mode = fctx->mode;
    my_fctx.depth = fctx->depth;
    my_fctx.prefer = fctx->prefer & PREFER_MIN;
    my_fctx.userid = httpd_userid;
    my_fctx.userisadmin = httpd_userisadmin;
    my_fctx.authstate = httpd_authstate;
    my_fctx.mbentry = NULL;
    my_fctx.mailbox = NULL;
    my_fctx.record = NULL;
    my_fctx.reqd_privs = DACL_READ;
    my_fctx.filter = NULL;
    my_fctx.filter_crit = NULL;
    my_fctx.open_db = notify_params.davdb.open_db;
    my_fctx.close_db = notify_params.davdb.close_db;
    my_fctx.lookup_resource = notify_params.davdb.lookup_resource;
    my_fctx.foreach_resource = notify_params.davdb.foreach_resource;
    my_fctx.proc_by_resource = &propfind_by_resource;
    my_fctx.elist = NULL;
    my_fctx.lprops = notify_params.propfind.lprops;
    my_fctx.root = fctx->root;
    my_fctx.ns = fctx->ns;
    my_fctx.ns_table = fctx->ns_table;
    my_fctx.ret = fctx->ret;
    my_fctx.xmlbuf = fctx->xmlbuf;

    /* Parse the list of properties and build a list of callbacks */
    preload_proplist(props, &my_fctx);

    /* Add response for target collection */
    propfind_by_collection(tgt.mbentry, &my_fctx);

    free(tgt.userid);
    mboxlist_entry_free(&tgt.mbentry);

    /* Free the entry list */
    free_entry_list(my_fctx.elist);

    buf_free(&my_fctx.buf);

    return 0;
}


static const char *access_types[] = { "no-access", "read", "read-write" };

static int set_share_access(const char *mboxname,
                            const char *userid, int access)
{
    char r, rightstr[100];

    /* Set access rights */
    rightstr[0] = (access == SHARE_READWRITE) ? '+' : '-';

    cyrus_acl_masktostr(DACL_SHARERW, rightstr+1);
    r = mboxlist_setacl(&httpd_namespace, mboxname, userid, rightstr,
                        httpd_userisadmin || httpd_userisproxyadmin,
                        httpd_userid, httpd_authstate);
    if (!r && access == SHARE_READONLY) {
        rightstr[0] = '+';
        cyrus_acl_masktostr(DACL_SHARE, rightstr+1);
        r = mboxlist_setacl(&httpd_namespace, mboxname, userid, rightstr,
                            httpd_userisadmin || httpd_userisproxyadmin,
                            httpd_userid, httpd_authstate);
    }

    return r;
}


static xmlNodePtr get_props(struct request_target_t *req_tgt,
                            const char *prop_names[],
                            xmlNodePtr root, xmlNsPtr ns[],
                            const struct prop_entry prop_list[])
{
    struct propstat propstat = { NULL, 0, 0 };
    struct propfind_ctx fctx;
    const struct prop_entry *prop;
    const char **name;
    xmlNodePtr node;

    memset(&fctx, 0, sizeof(struct propfind_ctx));
    fctx.req_tgt = req_tgt;
    fctx.mbentry = req_tgt->mbentry;
    fctx.root = root;
    fctx.ns = ns;

    for (prop = prop_list; prop->name; prop++) {
        for (name = prop_names; *name; name++) {
            if (!strcmp(*name, prop->name)) {
                prop->get(BAD_CAST prop->name, ns[NS_DAV],
                          &fctx, NULL, NULL, &propstat, NULL);
            }
        }
    }

    buf_free(&fctx.buf);

    node = propstat.root->children;
    xmlUnlinkNode(node);
    xmlFreeNode(propstat.root);

    return node;
}


HIDDEN int dav_create_invite(xmlNodePtr *notify, xmlNsPtr *ns,
                             struct request_target_t *tgt,
                             const struct prop_entry *live_props,
                             const char *sharee, int access,
                             xmlChar *content)
{
    static xmlNodePtr resp, share, comment, node;
    struct buf buf = BUF_INITIALIZER;
    const char *invite_principal_props[] = { "displayname", NULL };
    const char *invite_collection_props[] = { "displayname", "resourcetype",
                                              "supported-calendar-component-set",
                                              NULL };
    const char *annot = DAV_ANNOT_NS "<" XML_NS_DAV ">invite-status";
    const char *response = "invite-noresponse";
    int r;

    if (!*notify) {
        /* Create share-invite-notification -
           response and share-access will be replaced for each sharee */
        char dtstamp[RFC3339_DATETIME_MAX];
        xmlNodePtr type, princ;

        *notify = init_xml_response("notification", NS_DAV, NULL, ns);
        if (!*notify) return HTTP_SERVER_ERROR;

        time_to_rfc3339(time(0), dtstamp, RFC3339_DATETIME_MAX);
        xmlNewChild(*notify, NULL, BAD_CAST "dtstamp", BAD_CAST dtstamp);

        type = xmlNewChild(*notify, NULL,
                           BAD_CAST SHARE_INVITE_NOTIFICATION, NULL);

        princ = xmlNewChild(type, NULL, BAD_CAST "principal", NULL);
        buf_printf(&buf, "%s/%s/%s/", namespace_principal.prefix,
                   USER_COLLECTION_PREFIX, tgt->userid);
        xml_add_href(princ, NULL, buf_cstring(&buf));
        buf_free(&buf);

        node = get_props(tgt, invite_principal_props,
                         *notify, ns, princ_params.propfind.lprops);
        xmlAddChild(princ, node);

        resp = xmlNewChild(type, NULL, BAD_CAST "invite-noresponse", NULL);

        node = xmlNewChild(type, NULL, BAD_CAST "sharer-resource-uri", NULL);
        xml_add_href(node, NULL, tgt->path);

        node = xmlNewChild(type, NULL, BAD_CAST "share-access", NULL);
        share = xmlNewChild(node, NULL, BAD_CAST "no-access", NULL);

        node = get_props(tgt, invite_collection_props,
                         *notify, ns, live_props);
        xmlAddChild(type, node);

        comment = xmlNewChild(type, NULL, BAD_CAST "comment", NULL);
    }

    /* Lookup invite status */
    r = annotatemore_lookupmask(tgt->mbentry->name,
                                annot, sharee, &buf);
    if (!r && buf_len(&buf)) response = buf_cstring(&buf);

    /* Patch in response and share-access */
    node = xmlNewNode(ns[NS_DAV], BAD_CAST response);
    buf_free(&buf);
    xmlReplaceNode(resp, node);
    xmlFreeNode(resp);
    resp = node;

    node = xmlNewNode(ns[NS_DAV], BAD_CAST access_types[access]);
    xmlReplaceNode(share, node);
    xmlFreeNode(share);
    share = node;

    xmlNodeSetContent(comment, content ? content : BAD_CAST "");

    return 0;
}


HIDDEN int dav_post_share(struct transaction_t *txn, struct meth_params *pparams)
{
    xmlNodePtr root = NULL, node, sharee;
    int oldrights, ret, legacy = 0;
    struct buf resource = BUF_INITIALIZER;
    xmlNodePtr notify = NULL;
    xmlNsPtr ns[NUM_NAMESPACE];

    /* Check ACL for current user */
    oldrights = httpd_myrights(httpd_authstate, txn->req_tgt.mbentry);
    if (!(oldrights & DACL_ADMIN)) {
        /* DAV:need-privileges */
        txn->error.precond = DAV_NEED_PRIVS;
        txn->error.resource = txn->req_tgt.path;
        txn->error.rights = DACL_ADMIN;
        return HTTP_NO_PRIVS;
    }

    if (txn->req_tgt.mbentry->server) {
        /* Remote mailbox */
        struct backend *be;

        be = proxy_findserver(txn->req_tgt.mbentry->server,
                              &http_protocol, httpd_userid,
                              &backend_cached, NULL, NULL, httpd_in);
        if (!be) return HTTP_UNAVAILABLE;

        return http_pipe_req_resp(be, txn);
    }

    /* Local mailbox */
    struct mboxlock *namespacelock = mboxname_usernamespacelock(txn->req_tgt.mbentry->name);

    /* Read body */
    ret = parse_xml_body(txn, &root, DAVSHARING_CONTENT_TYPE);
    if (!ret && !root) {
        txn->error.desc = "Missing request body";
        ret = HTTP_BAD_REQUEST;
    }
    if (ret) goto done;

    /* Make sure its a share-resource element */
    if (!xmlStrcmp(root->name, BAD_CAST "share")) legacy = 1;
    else if (xmlStrcmp(root->name, BAD_CAST "share-resource")) {
        txn->error.desc =
            "Missing share-resource element in POST request";
        ret = HTTP_BAD_REQUEST;
        goto done;
    }

    /* Process each sharee */
    for (sharee = xmlFirstElementChild(root); sharee;
         sharee = xmlNextElementSibling(sharee)) {
        xmlChar *href = NULL, *content = NULL;
        int access = SHARE_READONLY;

        if (legacy) {
            if (!xmlStrcmp(sharee->name, BAD_CAST "remove")) {
                access = SHARE_NONE;
            }
            else if (xmlStrcmp(sharee->name, BAD_CAST "set")) continue;
        }
        else if (xmlStrcmp(sharee->name, BAD_CAST "sharee")) continue;

        for (node = xmlFirstElementChild(sharee); node;
             node = xmlNextElementSibling(node)) {
            if (!xmlStrcmp(node->name, BAD_CAST "href")) {
                href = xmlNodeGetContent(node);
                if (access == SHARE_NONE) break;
            }

            if (legacy) {
                if (!xmlStrcmp(node->name, BAD_CAST "read-write")) {
                    access = SHARE_READWRITE;
                }
                else if (!xmlStrcmp(node->name, BAD_CAST "summary")) {
                    content = xmlNodeGetContent(node);
                }
            }
            else if (!xmlStrcmp(node->name, BAD_CAST "share-access")) {
                xmlNodePtr share = xmlFirstElementChild(node);

                if (!xmlStrcmp(share->name, BAD_CAST "no-access")) {
                    access = SHARE_NONE;
                }
                else if (!xmlStrcmp(share->name, BAD_CAST "read-write")) {
                    access = SHARE_READWRITE;
                }
            }
            else if (!xmlStrcmp(node->name, BAD_CAST "comment")) {
                content = xmlNodeGetContent(node);
            }
        }

        if (href) {
            char *userid = NULL, *at;
            int r;

            if (!xmlStrncasecmp(href, BAD_CAST "mailto:", 7)) {
                userid = xstrdup((char *) href + 7);
                if ((at = strchr(userid, '@'))) {
                    if (!config_virtdomains || !strcmp(at+1, config_defdomain)){
                        *at = '\0';
                    }
                }
            }
            else if (!xmlStrncmp(href, BAD_CAST "DAV:", 4)) {
                if (!xmlStrcmp(href + 4, BAD_CAST "all")) {
                    userid = xstrdup("anyone");
                }
                else if (!xmlStrcmp(href + 4, BAD_CAST "unauthenticated")) {
                    userid = xstrdup("anonymous");
                }
                else if (!xmlStrcmp(href + 4, BAD_CAST "authenticated")) {
                    /* This needs to be done as anyone - anonymous */
                    r = set_share_access(txn->req_tgt.mbentry->name,
                                         "anyone", access);
                    if (r) {
                        syslog(LOG_NOTICE,
                               "failed to set share access for"
                               " 'anyone' on '%s': %s",
                               txn->req_tgt.mbentry->name, error_message(r));
                    }
                    else userid = xstrdup("-anonymous");
                }
            }
            else {
                const char *errstr = NULL;
                xmlURIPtr uri = parse_uri(METH_UNKNOWN,
                                          (const char *) href, 1, &errstr);

                if (uri) {
                    struct request_target_t principal;

                    memset(&principal, 0, sizeof(struct request_target_t));
                    r = princ_params.parse_path((const char *) uri->path,
                                                &principal, &errstr);
                    if (!r && principal.userid) userid = principal.userid;
                    else if (principal.userid) free(principal.userid);

                    xmlFreeURI(uri);
                }
            }

            if (!userid) {
                /* XXX  set invite-invalid ? */
                syslog(LOG_NOTICE, "could not parse userid from sharing href");
            }
            else {
                /* Set access rights */
                r = set_share_access(txn->req_tgt.mbentry->name,
                                     userid, access);
                if (r) {
                    syslog(LOG_NOTICE,
                           "failed to set share access for '%s' on '%s': %s",
                           userid, txn->req_tgt.mbentry->name,
                           error_message(r));
                }
                else {
                    /* Notify sharee */
                    r = dav_create_invite(&notify, ns, &txn->req_tgt,
                                          pparams->propfind.lprops,
                                          userid, access, content);

                    int newrights = httpd_myrights(httpd_authstate, txn->req_tgt.mbentry);
                    struct dlist *extradata = dlist_newkvlist(NULL, "ACL");
                    char rights[100];
                    cyrus_acl_masktostr(oldrights, rights);
                    dlist_setatom(extradata, "OLD", rights);
                    cyrus_acl_masktostr(newrights, rights);
                    dlist_setatom(extradata, "NEW", rights);

                    /* Create a resource name for the notifications -
                       We use a consistent naming scheme so that multiple
                       notifications of the same type for the same resource
                       are coalesced (overwritten) */
                    buf_reset(&resource);
                    buf_printf(&resource, "%x-%x-%x-%x.xml",
                               strhash(XML_NS_DAV),
                               strhash(SHARE_INVITE_NOTIFICATION),
                               strhash(txn->req_tgt.mbentry->name),
                               strhash(userid));

                    r = dav_send_notification(notify->doc, extradata,
                                              userid, buf_cstring(&resource));
                }

                free(userid);
            }

            xmlFree(href);
        }
        if (content) xmlFree(content);

        ret = HTTP_NO_CONTENT;
    }

  done:
    if (root) xmlFreeDoc(root->doc);
    if (notify) xmlFreeDoc(notify->doc);
    buf_free(&resource);
    mboxname_release(&namespacelock);

    return ret;
}
