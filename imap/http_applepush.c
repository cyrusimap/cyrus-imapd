/* http_applepush.c -- Apple push service endpoints for DAV push
 *
 * Copyright (c) 1994-2016 Carnegie Mellon University.  All rights reserved.
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

#include "config.h"

#include "acl.h"
#include "httpd.h"
#include "http_dav.h"
#include "util.h"
#include <syslog.h>

/* generated headers are not necessarily in current directory */
#include "imap/http_err.h"

static void applepush_init(struct buf *serverinfo);

static int meth_get_applepush(struct transaction_t *txn, void *params);
static int meth_post_applepush(struct transaction_t *txn, void *params);

struct namespace_t namespace_applepush = {
    URL_NS_APPLEPUSH, /*enabled*/0, "applepush", "/applepush/subscribe", NULL,
    http_allow_noauth_get, /*authschemes*/0,
    /*mbtype*/0,
    ALLOW_READ|ALLOW_POST,
    &applepush_init, NULL, NULL, NULL, NULL, NULL,
    {
        { NULL,                 NULL },                 /* ACL          */
        { NULL,                 NULL },                 /* BIND         */
        { NULL,                 NULL },                 /* CONNECT      */
        { NULL,                 NULL },                 /* COPY         */
        { NULL,                 NULL },                 /* DELETE       */
        { &meth_get_applepush,  NULL },                 /* GET          */
        { NULL,                 NULL },                 /* HEAD         */
        { NULL,                 NULL },                 /* LOCK         */
        { NULL,                 NULL },                 /* MKCALENDAR   */
        { NULL,                 NULL },                 /* MKCOL        */
        { NULL,                 NULL },                 /* MOVE         */
        { NULL,                 NULL },                 /* OPTIONS      */
        { NULL,                 NULL },                 /* PATCH        */
        { &meth_post_applepush, NULL },                 /* POST         */
        { NULL,                 NULL },                 /* PROPFIND     */
        { NULL,                 NULL },                 /* PROPPATCH    */
        { NULL,                 NULL },                 /* PUT          */
        { NULL,                 NULL },                 /* REPORT       */
        { NULL,                 NULL },                 /* TRACE        */
        { NULL,                 NULL },                 /* UNBIND       */
        { NULL,                 NULL }                  /* UNLOCK       */
    }
};

static void applepush_init(struct buf *serverinfo __attribute__((unused)))
{
    namespace_applepush.enabled = apns_enabled &&
        ((namespace_calendar.enabled && config_getstring(IMAPOPT_APS_TOPIC_CALDAV)) ||
         (namespace_addressbook.enabled && config_getstring(IMAPOPT_APS_TOPIC_CARDDAV)));
}

static int meth_get_applepush(struct transaction_t *txn,
                              void *params __attribute__((unused)))
{
    int rc = HTTP_BAD_REQUEST, r = 0;
    struct strlist *vals = NULL;
    const char *token = NULL, *key = NULL, *aps_topic = NULL;
    const char *mailbox_userid = NULL, *mailbox_uniqueid = NULL;
    strarray_t *keyparts = NULL;
    char *mboxname = NULL;
    struct mboxlist_entry *mbentry = NULL;
    int mbtype = 0;

    /* unpack query params */
    vals = hash_lookup("token", &txn->req_qparams);
    if (!vals) goto done;
    token = vals->s;

    vals = hash_lookup("key", &txn->req_qparams);
    if (!vals) goto done;
    key = vals->s;

    /* decompose key to userid + mailbox uniqueid */
    keyparts = strarray_split(key, "/", 0);
    if (strarray_size(keyparts) != 2)
        goto done;
    mailbox_userid = strarray_nth(keyparts, 0);
    mailbox_uniqueid = strarray_nth(keyparts, 1);

    /* lookup mailbox */
    mboxname = mboxlist_find_uniqueid(mailbox_uniqueid, mailbox_userid,
                                      httpd_authstate);
    if (!mboxname) {
        syslog(LOG_ERR,
               "meth_get_applepush: mboxlist_find_uniqueid(%s, %s) not found",
               mailbox_uniqueid, mailbox_userid);
        goto done;
    }

    r = mboxlist_lookup(mboxname, &mbentry, NULL);
    if (r || !mbentry) {
        syslog(LOG_ERR, "meth_get_applepush: mboxlist_lookup(%s): %s",
               mboxname, error_message(r));
        goto done;
    }

    /* mailbox must be calendar or addressbook */
    mbtype = mbtype_isa(mbentry->mbtype);
    if (mbtype != MBTYPE_CALENDAR && mbtype != MBTYPE_ADDRESSBOOK)
        goto done;

    /* check if auth user has access to mailbox */
    int myrights = httpd_myrights(httpd_authstate, mbentry);
    if (!(myrights & ACL_READ)) {
        syslog(LOG_ERR, "meth_get_applepush: no read access to %s for %s (%s)",
               mboxname, httpd_userid, mbentry->acl);
        goto done;
    }

    aps_topic = config_getstring(mbtype_isa(mbtype) == MBTYPE_CALENDAR ?
                                 IMAPOPT_APS_TOPIC_CALDAV :
                                 IMAPOPT_APS_TOPIC_CARDDAV);
    if (!aps_topic) {
        syslog(LOG_ERR, "aps_topic_%s not configured, can't subscribe",
               mbtype_isa(mbtype) == MBTYPE_CALENDAR ? "caldav" : "carddav");
        goto done;
    }

    mboxlist_entry_free(&mbentry);

    /* notify! */
    struct mboxevent *mboxevent = mboxevent_new(EVENT_APPLEPUSHSERVICE_DAV);
    mboxevent_set_applepushservice_dav(mboxevent, aps_topic, token, httpd_userid,
                                       mailbox_userid, mailbox_uniqueid, mbtype,
                                       86400); // XXX interval from config
    mboxevent_notify(&mboxevent);
    mboxevent_free(&mboxevent);

    rc = HTTP_OK;

done:
    mboxlist_entry_free(&mbentry);
    if (mboxname) free(mboxname);
    if (keyparts) strarray_free(keyparts);

    return rc;
}

static int meth_post_applepush(struct transaction_t *txn, void *params)
{
    /* Check Content-Type */
    const char **hdr = spool_getheader(txn->req_hdrs, "Content-Type");

    if (hdr && is_mediatype("application/x-www-form-urlencoded", hdr[0])) {
        /* Read body */
        txn->req_body.flags |= BODY_DECODE;

        int r = http_read_req_body(txn);
        if (r) {
            txn->flags.conn = CONN_CLOSE;
            return r;
        }

        /* x-www-form-urlencoded is essentially a URI query component
           with SP replaced with '+' */
        buf_replace_char(&txn->req_body.payload, '+', ' ');
        parse_query_params(txn, buf_cstring(&txn->req_body.payload));
    }
    else {
        /* POST has been seen with URL params,
           so for now we just call the GET handler */
    }

    return meth_get_applepush(txn, params);
}


/* Apple push notifications
   https://github.com/apple/ccs-calendarserver/blob/master/doc/Extensions/caldav-pubsubdiscovery.txt
*/
int propfind_push_transports(const xmlChar *name, xmlNsPtr ns,
                             struct propfind_ctx *fctx,
                             xmlNodePtr prop __attribute__((unused)),
                             xmlNodePtr resp,
                             struct propstat propstat[],
                             void *rock __attribute__((unused)))
{
    xmlNodePtr node, transport, subscription_url;

    assert(fctx->req_tgt->namespace->id == URL_NS_CALENDAR ||
           fctx->req_tgt->namespace->id == URL_NS_ADDRESSBOOK);

    if (!namespace_applepush.enabled) return HTTP_NOT_FOUND;

    /* Only on home sets */
    if (fctx->req_tgt->collection) return HTTP_NOT_FOUND;

    if (!propstat) {
        /* Prescreen "property" request - add namespace for environment */
        ensure_ns(fctx->ns, NS_MOBME, fctx->root, XML_NS_MOBME, "MM");
        return 0;
    }

    const char *aps_topic =
        config_getstring(fctx->req_tgt->namespace->id == URL_NS_CALENDAR ?
                         IMAPOPT_APS_TOPIC_CALDAV : IMAPOPT_APS_TOPIC_CARDDAV);
    if (!aps_topic) {
        syslog(LOG_DEBUG, "aps_topic_%s not configured,"
               " can't build CS:push-transports response",
               fctx->req_tgt->namespace->id == URL_NS_CALENDAR ?
               "caldav" : "carddav");
        return HTTP_NOT_FOUND;
    }

    node = xml_add_prop(HTTP_OK, fctx->ns[NS_CS], &propstat[PROPSTAT_OK],
                        name, ns, NULL, 0);

    transport = xmlNewChild(node, NULL, BAD_CAST "transport", NULL);
    xmlNewProp(transport, BAD_CAST "type", BAD_CAST "APSD");

    subscription_url =
        xmlNewChild(transport, NULL, BAD_CAST "subscription-url", NULL);
    xml_add_href(subscription_url, fctx->ns[NS_DAV], namespace_applepush.prefix);

    xmlNewChild(transport, NULL, BAD_CAST "apsbundleid", BAD_CAST aps_topic);

    // XXX from config, I think?
    ensure_ns(fctx->ns, NS_MOBME, resp->parent, XML_NS_MOBME, "MM");
    xmlNewChild(transport, fctx->ns[NS_MOBME],
                BAD_CAST "env", BAD_CAST "PRODUCTION");

    // XXX from config
    xmlNewChild(transport, NULL,
                BAD_CAST "refresh-interval", BAD_CAST "86400");

    return 0;
}

int propfind_pushkey(const xmlChar *name, xmlNsPtr ns,
                     struct propfind_ctx *fctx,
                     xmlNodePtr prop __attribute__((unused)),
                     xmlNodePtr resp __attribute__((unused)),
                     struct propstat propstat[],
                     void *rock __attribute__((unused)))
{
    if (!namespace_applepush.enabled) return HTTP_NOT_FOUND;

    /* Only on collections */
    if (!fctx->req_tgt->collection) return HTTP_NOT_FOUND;

    /* key is userid and mailbox uniqueid */
    buf_reset(&fctx->buf);
    buf_printf(&fctx->buf, "%s/%s",
               fctx->req_tgt->userid, fctx->mailbox->uniqueid);
    xml_add_prop(HTTP_OK, fctx->ns[NS_DAV], &propstat[PROPSTAT_OK],
                 name, ns, BAD_CAST buf_cstring(&fctx->buf), 0);

    return 0;
}
