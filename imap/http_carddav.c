/* http_carddav.c -- Routines for handling CardDAV collections in httpd
 *
 * Copyright (c) 1994-2013 Carnegie Mellon University.  All rights reserved.
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
/*
 * TODO:
 *   Support <filter> for addressbook-query Report
 *
 */

#include <config.h>

#include <syslog.h>

#include <libxml/tree.h>
#include <libxml/uri.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "acl.h"
#include "append.h"
#include "carddav_db.h"
#include "exitcodes.h"
#include "global.h"
#include "hash.h"
#include "httpd.h"
#include "http_dav.h"
#include "http_proxy.h"
#include "index.h"
#include "mailbox.h"
#include "mboxlist.h"
#include "message.h"
#include "message_guid.h"
#include "proxy.h"
#include "smtpclient.h"
#include "spool.h"
#include "stristr.h"
#include "times.h"
#include "util.h"
#include "vcard_support.h"
#include "version.h"
#include "vparse.h"
#include "xmalloc.h"
#include "xml_support.h"
#include "xstrlcat.h"
#include "xstrlcpy.h"

/* generated headers are not necessarily in current directory */
#include "imap/http_err.h"
#include "imap/imap_err.h"

static struct carddav_db *auth_carddavdb = NULL;

static void my_carddav_init(struct buf *serverinfo);
static void my_carddav_auth(const char *userid);
static void my_carddav_reset(void);
static void my_carddav_shutdown(void);

static strarray_t partial_addrdata;

static int carddav_parse_path(const char *path,
                              struct request_target_t *tgt, const char **errstr);

static int carddav_copy(struct transaction_t *txn, void *obj,
                        struct mailbox *mailbox, const char *resource,
                        void *destdb, unsigned flags);

static int carddav_put(struct transaction_t *txn, void *obj,
                       struct mailbox *mailbox, const char *resource,
                       void *destdb, unsigned flags);

static int propfind_getcontenttype(const xmlChar *name, xmlNsPtr ns,
                                   struct propfind_ctx *fctx,
                                   xmlNodePtr prop, xmlNodePtr resp,
                                   struct propstat propstat[], void *rock);
static int propfind_restype(const xmlChar *name, xmlNsPtr ns,
                            struct propfind_ctx *fctx,
                            xmlNodePtr prop, xmlNodePtr resp,
                            struct propstat propstat[], void *rock);
static int propfind_addrdata(const xmlChar *name, xmlNsPtr ns,
                             struct propfind_ctx *fctx,
                             xmlNodePtr prop, xmlNodePtr resp,
                             struct propstat propstat[], void *rock);
static int propfind_suppaddrdata(const xmlChar *name, xmlNsPtr ns,
                                 struct propfind_ctx *fctx,
                                 xmlNodePtr prop, xmlNodePtr resp,
                                 struct propstat propstat[], void *rock);
static int propfind_addrgroups(const xmlChar *name, xmlNsPtr ns,
                               struct propfind_ctx *fctx,
                               xmlNodePtr prop, xmlNodePtr resp,
                               struct propstat propstat[], void *rock);

static int report_card_query(struct transaction_t *txn,
                             struct meth_params *rparams,
                             xmlNodePtr inroot, struct propfind_ctx *fctx);

static struct mime_type_t carddav_mime_types[] = {
    /* First item MUST be the default type and storage format */
    { "text/vcard; charset=utf-8", "3.0", "vcf",
      (struct buf* (*)(void *)) &vcard_as_buf,
      (void * (*)(const struct buf*)) &vcard_parse_buf,
      (void (*)(void *)) &vparse_free_card, NULL, NULL
    },
    { NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL }
};

/* Array of supported REPORTs */
static const struct report_type_t carddav_reports[] = {

    /* WebDAV Versioning (RFC 3253) REPORTs */
    { "expand-property", NS_DAV, "multistatus", &report_expand_prop,
      DACL_READ, 0 },

    /* WebDAV ACL (RFC 3744) REPORTs */
    { "acl-principal-prop-set", NS_DAV, "multistatus", &report_acl_prin_prop,
      DACL_ADMIN, REPORT_NEED_MBOX | REPORT_DEPTH_ZERO },

    /* WebDAV Sync (RFC 6578) REPORTs */
    { "sync-collection", NS_DAV, "multistatus", &report_sync_col,
      DACL_READ, REPORT_NEED_MBOX | REPORT_NEED_PROPS },

    /* CardDAV (RFC 6352) REPORTs */
    { "addressbook-query", NS_CARDDAV, "multistatus", &report_card_query,
      DACL_READ, REPORT_NEED_MBOX | REPORT_ALLOW_PROPS },
    { "addressbook-multiget", NS_CARDDAV, "multistatus", &report_multiget,
      DACL_READ, REPORT_NEED_MBOX | REPORT_ALLOW_PROPS },

    { NULL, 0, NULL, NULL, 0, 0 }
};

/* Array of known "live" properties */
static const struct prop_entry carddav_props[] = {

    /* WebDAV (RFC 4918) properties */
    { "creationdate", NS_DAV,
      PROP_ALLPROP | PROP_COLLECTION | PROP_RESOURCE,
      propfind_creationdate, NULL, NULL },
    { "displayname", NS_DAV,
      PROP_ALLPROP | PROP_COLLECTION | PROP_RESOURCE,
      propfind_fromdb, proppatch_todb, NULL },
    { "getcontentlanguage", NS_DAV, PROP_ALLPROP | PROP_RESOURCE,
      propfind_fromhdr, NULL, "Content-Language" },
    { "getcontentlength", NS_DAV,
      PROP_ALLPROP | PROP_COLLECTION | PROP_RESOURCE,
      propfind_getlength, NULL, NULL },
    { "getcontenttype", NS_DAV,
      PROP_ALLPROP | PROP_COLLECTION | PROP_RESOURCE,
      propfind_getcontenttype, NULL, "Content-Type" },
    { "getetag", NS_DAV, PROP_ALLPROP | PROP_COLLECTION | PROP_RESOURCE,
      propfind_getetag, NULL, NULL },
    { "getlastmodified", NS_DAV,
      PROP_ALLPROP | PROP_COLLECTION | PROP_RESOURCE,
      propfind_getlastmod, NULL, NULL },
    { "lockdiscovery", NS_DAV, PROP_ALLPROP | PROP_RESOURCE,
      propfind_lockdisc, NULL, NULL },
    { "resourcetype", NS_DAV,
      PROP_ALLPROP | PROP_COLLECTION | PROP_RESOURCE,
      propfind_restype, proppatch_restype, "addressbook" },
    { "supportedlock", NS_DAV, PROP_ALLPROP | PROP_RESOURCE,
      propfind_suplock, NULL, NULL },

    /* WebDAV Versioning (RFC 3253) properties */
    { "supported-report-set", NS_DAV, PROP_COLLECTION,
      propfind_reportset, NULL, (void *) carddav_reports },

    /* WebDAV ACL (RFC 3744) properties */
    { "owner", NS_DAV, PROP_COLLECTION | PROP_RESOURCE,
      propfind_owner, NULL, NULL },
    { "group", NS_DAV, 0, NULL, NULL, NULL },
    { "supported-privilege-set", NS_DAV, PROP_COLLECTION | PROP_RESOURCE,
      propfind_supprivset, NULL, NULL },
    { "current-user-privilege-set", NS_DAV, PROP_COLLECTION | PROP_RESOURCE,
      propfind_curprivset, NULL, NULL },
    { "acl", NS_DAV, PROP_COLLECTION | PROP_RESOURCE,
      propfind_acl, NULL, NULL },
    { "acl-restrictions", NS_DAV, PROP_COLLECTION | PROP_RESOURCE,
      propfind_aclrestrict, NULL, NULL },
    { "inherited-acl-set", NS_DAV, 0, NULL, NULL, NULL },
    { "principal-collection-set", NS_DAV, PROP_COLLECTION | PROP_RESOURCE,
      propfind_princolset, NULL, NULL },

    /* WebDAV Quota (RFC 4331) properties */
    { "quota-available-bytes", NS_DAV, PROP_COLLECTION,
      propfind_quota, NULL, NULL },
    { "quota-used-bytes", NS_DAV, PROP_COLLECTION,
      propfind_quota, NULL, NULL },

    /* WebDAV Current Principal (RFC 5397) properties */
    { "current-user-principal", NS_DAV,
      PROP_COLLECTION | PROP_RESOURCE,
      propfind_curprin, NULL, NULL },

    /* WebDAV POST (RFC 5995) properties */
    { "add-member", NS_DAV, PROP_COLLECTION,
      NULL /* add-member broken at FM */, NULL, NULL },

    /* WebDAV Sync (RFC 6578) properties */
    { "sync-token", NS_DAV, PROP_COLLECTION,
      propfind_sync_token, NULL, SYNC_TOKEN_URL_SCHEME },

    /* WebDAV Sharing (draft-pot-webdav-resource-sharing) properties */
    { "share-access", NS_DAV, PROP_COLLECTION,
      propfind_shareaccess, NULL, NULL },
    { "invite", NS_DAV, PROP_COLLECTION,
      propfind_invite, NULL, NULL },
    { "sharer-resource-uri", NS_DAV, PROP_COLLECTION,
      propfind_sharedurl, NULL, NULL },

    /* CardDAV (RFC 6352) properties */
    { "address-data", NS_CARDDAV, PROP_RESOURCE | PROP_PRESCREEN | PROP_CLEANUP,
      propfind_addrdata, NULL, &partial_addrdata },
    { "addressbook-description", NS_CARDDAV, PROP_COLLECTION,
      propfind_fromdb, proppatch_todb, NULL },
    { "supported-address-data", NS_CARDDAV, PROP_COLLECTION,
      propfind_suppaddrdata, NULL, NULL },
    { "supported-collation-set", NS_CARDDAV, PROP_COLLECTION,
      propfind_collationset, NULL, NULL },
    { "max-resource-size", NS_CARDDAV, 0, NULL, NULL, NULL },

    /* Apple Calendar Server properties */
    { "getctag", NS_CS, PROP_ALLPROP | PROP_COLLECTION,
      propfind_sync_token, NULL, "" },

    /* Apple Push Notifications Service properties */
    { "push-transports", NS_CS, PROP_COLLECTION,
      propfind_push_transports, NULL, (void *) MBTYPE_ADDRESSBOOK },
    { "pushkey", NS_CS, PROP_COLLECTION,
      propfind_pushkey, NULL, NULL },

    /* Cyrus properties */
    { "address-groups", NS_CYRUS, PROP_RESOURCE,
      propfind_addrgroups, NULL, NULL },

    { NULL, 0, 0, NULL, NULL, NULL }
};

static struct meth_params carddav_params = {
    carddav_mime_types,
    &carddav_parse_path,
    &dav_check_precond,
    { (db_open_proc_t) &carddav_open_mailbox,
      (db_close_proc_t) &carddav_close,
      (db_proc_t) &carddav_begin,
      (db_proc_t) &carddav_commit,
      (db_proc_t) &carddav_abort,
      (db_lookup_proc_t) &carddav_lookup_resource,
      (db_foreach_proc_t) &carddav_foreach,
      (db_write_proc_t) &carddav_write,
      (db_delete_proc_t) &carddav_delete },
    NULL,                                       /* No ACL extensions */
    { CARDDAV_UID_CONFLICT, &carddav_copy },
    NULL,                                       /* No special DELETE handling */
    NULL,                                       /* No special GET handling */
    { CARDDAV_LOCATION_OK, MBTYPE_ADDRESSBOOK },
    NULL,                                       /* No PATCH handling */
    { POST_SHARE, NULL, NULL },                 /* No special POST handling */
    { CARDDAV_SUPP_DATA, &carddav_put },
    { DAV_FINITE_DEPTH, carddav_props },        /* Disable infinite depth */
    carddav_reports
};


/* Namespace for Carddav collections */
struct namespace_t namespace_addressbook = {
    URL_NS_ADDRESSBOOK, 0, "/dav/addressbooks", "/.well-known/carddav", 1 /* auth */,
    MBTYPE_ADDRESSBOOK,
    (ALLOW_READ | ALLOW_POST | ALLOW_WRITE | ALLOW_DELETE |
     ALLOW_DAV | ALLOW_PROPPATCH | ALLOW_MKCOL | ALLOW_ACL | ALLOW_CARD),
    &my_carddav_init, &my_carddav_auth, my_carddav_reset, &my_carddav_shutdown,
    &dav_premethod,
    {
        { &meth_acl,            &carddav_params },      /* ACL          */
        { NULL,                 NULL },                 /* BIND         */
        { &meth_copy_move,      &carddav_params },      /* COPY         */
        { &meth_delete,         &carddav_params },      /* DELETE       */
        { &meth_get_head,       &carddav_params },      /* GET          */
        { &meth_get_head,       &carddav_params },      /* HEAD         */
        { &meth_lock,           &carddav_params },      /* LOCK         */
        { NULL,                 NULL },                 /* MKCALENDAR   */
        { &meth_mkcol,          &carddav_params },      /* MKCOL        */
        { &meth_copy_move,      &carddav_params },      /* MOVE         */
        { &meth_options,        &carddav_parse_path },  /* OPTIONS      */
        { NULL,                 NULL },                 /* PATCH        */
        { &meth_post,           &carddav_params },      /* POST         */
        { &meth_propfind,       &carddav_params },      /* PROPFIND     */
        { &meth_proppatch,      &carddav_params },      /* PROPPATCH    */
        { &meth_put,            &carddav_params },      /* PUT          */
        { &meth_report,         &carddav_params },      /* REPORT       */
        { &meth_trace,          &carddav_parse_path },  /* TRACE        */
        { NULL,                 NULL },                 /* UNBIND       */
        { &meth_unlock,         &carddav_params }       /* UNLOCK       */
    }
};

static void my_carddav_init(struct buf *serverinfo __attribute__((unused)))
{
    namespace_addressbook.enabled =
        config_httpmodules & IMAP_ENUM_HTTPMODULES_CARDDAV;

    if (!namespace_addressbook.enabled) return;

    if (!config_getstring(IMAPOPT_ADDRESSBOOKPREFIX)) {
        fatal("Required 'addressbookprefix' option is not set", EC_CONFIG);
    }

    carddav_init();

    namespace_principal.enabled = 1;
    /* Apple clients check principal resources for these DAV tokens */
    namespace_principal.allow |= ALLOW_CARD;
}


#define DEFAULT_ADDRBOOK "Default"

EXPORTED int carddav_create_defaultaddressbook(const char *userid) {
    /* addressbook-home-set */
    mbname_t *mbname = mbname_from_userid(userid);
    mbname_push_boxes(mbname, config_getstring(IMAPOPT_ADDRESSBOOKPREFIX));
    int r = mboxlist_lookup(mbname_intname(mbname), NULL, NULL);
    if (r == IMAP_MAILBOX_NONEXISTENT) {
        /* Find location of INBOX */
        char *inboxname = mboxname_user_mbox(userid, NULL);
        mbentry_t *mbentry = NULL;

        r = http_mlookup(inboxname, &mbentry, NULL);
        free(inboxname);
        if (r == IMAP_MAILBOX_NONEXISTENT) r = IMAP_INVALID_USER;
        if (!r && mbentry->server) {
            proxy_findserver(mbentry->server, &http_protocol, httpd_userid,
                             &backend_cached, NULL, NULL, httpd_in);
            mboxlist_entry_free(&mbentry);
            goto done;
        }
        mboxlist_entry_free(&mbentry);

        if (!r) {
            r = mboxlist_createmailbox(mbname_intname(mbname),
                                       MBTYPE_ADDRESSBOOK,
                                       NULL, 0,
                                       userid, httpd_authstate,
                                       0, 0, 0, 0, NULL);
            if (r) syslog(LOG_ERR, "IOERROR: failed to create %s (%s)",
                          mbname_intname(mbname), error_message(r));
        }
    }
    if (r) goto done;

    /* Default addressbook */
    mbname_push_boxes(mbname, DEFAULT_ADDRBOOK);
    r = mboxlist_lookup(mbname_intname(mbname), NULL, NULL);
    if (r == IMAP_MAILBOX_NONEXISTENT) {
        struct mailbox *mailbox = NULL;

        r = mboxlist_createmailbox(mbname_intname(mbname), MBTYPE_ADDRESSBOOK,
                                   NULL, 0,
                                   userid, httpd_authstate,
                                   0, 0, 0, 0, &mailbox);
        if (r) syslog(LOG_ERR, "IOERROR: failed to create %s (%s)",
                      mbname_intname(mbname), error_message(r));
        else {
            annotate_state_t *astate = NULL;

            r = mailbox_get_annotate_state(mailbox, 0, &astate);
            if (!r) {
                const char *annot = DAV_ANNOT_NS "<" XML_NS_DAV ">displayname";
                struct buf value = BUF_INITIALIZER;

                buf_init_ro_cstr(&value, "personal");
                r = annotate_state_writemask(astate, annot, userid, &value);
            }

            mailbox_close(&mailbox);
        }
    }

 done:
    mbname_free(&mbname);
    return r;
}

static void my_carddav_auth(const char *userid)
{
    int r;

    if (httpd_userisadmin || httpd_userisanonymous ||
        global_authisa(httpd_authstate, IMAPOPT_PROXYSERVERS)) {
        /* admin, anonymous, or proxy from frontend - won't have DAV database */
        return;
    }
    else if (config_mupdate_server && !config_getstring(IMAPOPT_PROXYSERVERS)) {
        /* proxy-only server - won't have DAV databases */
    }
    else {
        /* Open CardDAV DB for 'userid' */
        my_carddav_reset();
        auth_carddavdb = carddav_open_userid(userid);
        if (!auth_carddavdb) fatal("Unable to open CardDAV DB", EC_IOERR);
    }

    /* Auto-provision an addressbook for 'userid' */
    r = carddav_create_defaultaddressbook(userid);
    if (r) {
        syslog(LOG_ERR, "could not autoprovision addressbook for userid %s: %s",
                userid, error_message(r));
    }
}


static void my_carddav_reset(void)
{
    if (auth_carddavdb) carddav_close(auth_carddavdb);
    auth_carddavdb = NULL;
}


static void my_carddav_shutdown(void)
{
    my_carddav_reset();
    carddav_done();
}


/* Parse request-target path in CardDAV namespace */
static int carddav_parse_path(const char *path,
                              struct request_target_t *tgt, const char **errstr)
{
    return calcarddav_parse_path(path, tgt,
                                 config_getstring(IMAPOPT_ADDRESSBOOKPREFIX),
                                 errstr);
}

/* Perform a COPY/MOVE/PUT request
 *
 * preconditions:
 *   CARDDAV:valid-address-data
 *   CARDDAV:no-uid-conflict (DAV:href)
 *   CARDDAV:max-resource-size
 */
static int store_resource(struct transaction_t *txn,
                          struct vparse_card *vcard,
                          struct mailbox *mailbox, const char *resource,
                          struct carddav_db *davdb, int dupcheck)
{
    struct vparse_entry *ventry;
    struct carddav_data *cdata;
    const char *version = NULL, *uid = NULL, *fullname = NULL;
    struct index_record *oldrecord = NULL, record;
    char *mimehdr;

    /* Validate the vCard data */
    if (!vcard ||
        !vcard->objects ||
        !vcard->objects->type ||
        strcasecmp(vcard->objects->type, "vcard")) {
        txn->error.precond = CARDDAV_VALID_DATA;
        return HTTP_FORBIDDEN;
    }

    /* Fetch some important properties */
    for (ventry = vcard->objects->properties; ventry; ventry = ventry->next) {
        const char *name = ventry->name;
        const char *propval = ventry->v.value;

        if (!name) continue;
        if (!propval) continue;

        if (!strcasecmp(name, "version")) {
            version = propval;
            if (strcmp(version, "3.0")) {
                txn->error.precond = CARDDAV_SUPP_DATA;
                return HTTP_FORBIDDEN;
            }
        }

        else if (!strcasecmp(name, "uid"))
            uid = propval;

        else if (!strcasecmp(name, "fn"))
            fullname = propval;
    }

    /* Sanity check data */
    if (!version || !uid || !fullname) {
        txn->error.precond = CARDDAV_VALID_DATA;
        return HTTP_FORBIDDEN;
    }

    /* Check for changed UID on existing resource */
    carddav_lookup_resource(davdb, mailbox->name, resource, &cdata, 0);
    if (cdata->dav.imap_uid && strcmpsafe(cdata->vcard_uid, uid)) {
        char *owner = mboxname_to_userid(cdata->dav.mailbox);

        txn->error.precond = CARDDAV_UID_CONFLICT;
        assert(!buf_len(&txn->buf));
        buf_printf(&txn->buf, "%s/%s/%s/%s/%s",
                   namespace_addressbook.prefix,
                   USER_COLLECTION_PREFIX, owner,
                   strrchr(cdata->dav.mailbox, '.')+1,
                   cdata->dav.resource);
        txn->error.resource = buf_cstring(&txn->buf);
        free(owner);
        return HTTP_FORBIDDEN;
    }

    if (dupcheck) {
        /* Check for different resource with same UID */
        carddav_lookup_uid(davdb, uid, &cdata);
        if (cdata->dav.imap_uid && (strcmp(cdata->dav.mailbox, mailbox->name) ||
                                    strcmp(cdata->dav.resource, resource))) {
            /* CARDDAV:no-uid-conflict */
            char *owner = mboxname_to_userid(cdata->dav.mailbox);

            txn->error.precond = CARDDAV_UID_CONFLICT;
            assert(!buf_len(&txn->buf));
            buf_printf(&txn->buf, "%s/%s/%s/%s/%s",
                       namespace_addressbook.prefix,
                       USER_COLLECTION_PREFIX, owner,
                       strrchr(cdata->dav.mailbox, '.')+1,
                       cdata->dav.resource);
            txn->error.resource = buf_cstring(&txn->buf);
            free(owner);
            return HTTP_FORBIDDEN;
        }
    }

    if (cdata->dav.imap_uid) {
        /* Fetch index record for the resource */
        oldrecord = &record;
        mailbox_find_index_record(mailbox, cdata->dav.imap_uid, oldrecord);
    }

    /* Create and cache RFC 5322 header fields for resource */
    mimehdr = charset_encode_mimeheader(fullname, 0);
    spool_replace_header(xstrdup("Subject"), mimehdr, txn->req_hdrs);

    /* XXX - validate uid for mime safety? */
    if (strchr(uid, '@')) {
        spool_replace_header(xstrdup("Message-ID"),
                             xstrdup(uid), txn->req_hdrs);
    }
    else {
        assert(!buf_len(&txn->buf));
        buf_printf(&txn->buf, "<%s@%s>", uid, config_servername);
        spool_replace_header(xstrdup("Message-ID"),
                             buf_release(&txn->buf), txn->req_hdrs);
    }

    assert(!buf_len(&txn->buf));
    buf_printf(&txn->buf, "text/vcard; version=%s; charset=utf-8", version);
    spool_replace_header(xstrdup("Content-Type"),
                         buf_release(&txn->buf), txn->req_hdrs);

    buf_printf(&txn->buf, "attachment;\r\n\tfilename=\"%s\"", resource);
    spool_replace_header(xstrdup("Content-Disposition"),
                         buf_release(&txn->buf), txn->req_hdrs);

    spool_remove_header(xstrdup("Content-Description"), txn->req_hdrs);

    /* Store the resource */
    struct buf *buf = vcard_as_buf(vcard);
    int r = dav_store_resource(txn, buf_cstring(buf), 0,
                              mailbox, oldrecord, NULL);
    buf_destroy(buf);
    return r;
}

static int carddav_copy(struct transaction_t *txn, void *obj,
                        struct mailbox *mailbox, const char *resource,
                        void *destdb, unsigned flags __attribute__((unused)))
{
    struct carddav_db *db = (struct carddav_db *)destdb;
    struct vparse_card *vcard = (struct vparse_card *)obj;
    return store_resource(txn, vcard, mailbox, resource, db, /*dupcheck*/0);
}

static int carddav_put(struct transaction_t *txn, void *obj,
                       struct mailbox *mailbox, const char *resource,
                       void *destdb, unsigned flags __attribute__((unused)))
{
    struct carddav_db *db = (struct carddav_db *)destdb;
    struct vparse_card *vcard = (struct vparse_card *)obj;
    return store_resource(txn, vcard, mailbox, resource, db, /*dupcheck*/1);
}


/* Callback to fetch DAV:getcontenttype */
static int propfind_getcontenttype(const xmlChar *name, xmlNsPtr ns,
                                   struct propfind_ctx *fctx,
                                   xmlNodePtr prop __attribute__((unused)),
                                   xmlNodePtr resp __attribute__((unused)),
                                   struct propstat propstat[],
                                   void *rock __attribute__((unused)))
{
    buf_setcstr(&fctx->buf, "text/vcard; charset=utf-8");

    xml_add_prop(HTTP_OK, fctx->ns[NS_DAV], &propstat[PROPSTAT_OK],
                 name, ns, BAD_CAST buf_cstring(&fctx->buf), 0);

    return 0;
}


/* Callback to fetch DAV:resourcetype */
static int propfind_restype(const xmlChar *name, xmlNsPtr ns,
                            struct propfind_ctx *fctx,
                            xmlNodePtr prop __attribute__((unused)),
                            xmlNodePtr resp,
                            struct propstat propstat[],
                            void *rock __attribute__((unused)))
{
    xmlNodePtr node = xml_add_prop(HTTP_OK, fctx->ns[NS_DAV],
                                   &propstat[PROPSTAT_OK], name, ns, NULL, 0);

    if (!fctx->record) {
        xmlNewChild(node, NULL, BAD_CAST "collection", NULL);

        if (fctx->req_tgt->collection) {
            ensure_ns(fctx->ns, NS_CARDDAV,
                      resp ? resp->parent: node, XML_NS_CARDDAV, "C");
            xmlNewChild(node, fctx->ns[NS_CARDDAV],
                        BAD_CAST "addressbook", NULL);
        }
    }

    return 0;
}


static void prune_properties(struct vparse_card *vcard, strarray_t *partial)
{
    struct vparse_entry **entryp = &vcard->properties;

    while (*entryp) {
        struct vparse_entry *entry = *entryp;

        if (strarray_find_case(partial, entry->name, 0) < 0) {
            *entryp = entry->next;
            entry->next = NULL; /* so free doesn't walk the chain */
            vparse_free_entry(entry);
        }
        else {
            entryp = &((*entryp)->next);
        }
    }
}

/* Callback to prescreen/fetch CARDDAV:address-data */
static int propfind_addrdata(const xmlChar *name, xmlNsPtr ns,
                             struct propfind_ctx *fctx,
                             xmlNodePtr prop,
                             xmlNodePtr resp __attribute__((unused)),
                             struct propstat propstat[],
                             void *rock)
{
    strarray_t *partial = (strarray_t *) rock;
    const char *data = NULL;
    size_t datalen = 0;

    if (propstat) {
        if (!fctx->record) return HTTP_NOT_FOUND;

        if (!fctx->msg_buf.len)
            mailbox_map_record(fctx->mailbox, fctx->record, &fctx->msg_buf);
        if (!fctx->msg_buf.len) return HTTP_SERVER_ERROR;

        data = fctx->msg_buf.s + fctx->record->header_size;
        datalen = fctx->record->size - fctx->record->header_size;

        if (strarray_size(partial)) {
            /* Limit returned properties */
            struct vparse_card *vcard = fctx->obj;

            if (!vcard) vcard = fctx->obj = vcard_parse_string(data, 1);
            prune_properties(vcard->objects, partial);

            /* Create vCard data from new vcard component */
            buf_reset(&fctx->msg_buf);
            vparse_tobuf(vcard, &fctx->msg_buf);
            data = buf_cstring(&fctx->msg_buf);
            datalen = buf_len(&fctx->msg_buf);
        }
    }
    else if (prop) {
        /* Prescreen "property" request - read partial properties */
        xmlNodePtr node;

        /* Initialize partial property array to be empty */
        strarray_init(partial);

        /* Check for and parse child elements of CARDDAV:address-data */
        for (node = xmlFirstElementChild(prop); node;
             node = xmlNextElementSibling(node)) {

            if (!xmlStrcmp(node->name, BAD_CAST "prop")) {
                xmlChar *name = xmlGetProp(node, BAD_CAST "name");
                if (name) {
                    strarray_add_case(partial, (const char *) name);
                    xmlFree(name);
                }
            }
        }
    }
    else {
        /* Cleanup "property" request - free partial property array */
        strarray_fini(partial);

        return 0;
    }

    return propfind_getdata(name, ns, fctx, prop, propstat, carddav_mime_types,
                            CARDDAV_SUPP_DATA, data, datalen);
}


/* Callback to fetch CARDDAV:addressbook-home-set */
int propfind_abookhome(const xmlChar *name, xmlNsPtr ns,
                       struct propfind_ctx *fctx,
                       xmlNodePtr prop,
                       xmlNodePtr resp __attribute__((unused)),
                       struct propstat propstat[],
                       void *rock __attribute__((unused)))
{
    xmlNodePtr node;
    // XXX - should we be using httpd_userid here?
    const char *userid = fctx->req_tgt->userid;

    if (!(namespace_addressbook.enabled && userid))
        return HTTP_NOT_FOUND;

    node = xml_add_prop(HTTP_OK, fctx->ns[NS_DAV], &propstat[PROPSTAT_OK],
                        name, ns, NULL, 0);

    buf_reset(&fctx->buf);
    if (strchr(userid, '@') || !httpd_extradomain) {
        buf_printf(&fctx->buf, "%s/%s/%s/", namespace_addressbook.prefix,
                   USER_COLLECTION_PREFIX, userid);
    }
    else {
        buf_printf(&fctx->buf, "%s/%s/%s@%s/", namespace_addressbook.prefix,
                   USER_COLLECTION_PREFIX, userid, httpd_extradomain);
    }

    if ((fctx->mode == PROPFIND_EXPAND) && xmlFirstElementChild(prop)) {
        /* Return properties for this URL */
        expand_property(prop, fctx, &namespace_addressbook, buf_cstring(&fctx->buf),
                        &carddav_parse_path, carddav_props, node, 0);

    }
    else {
        /* Return just the URL */
        xml_add_href(node, fctx->ns[NS_DAV], buf_cstring(&fctx->buf));
    }

    return 0;
}


/* Callback to fetch CARDDAV:supported-address-data */
static int propfind_suppaddrdata(const xmlChar *name, xmlNsPtr ns,
                                 struct propfind_ctx *fctx,
                                 xmlNodePtr prop __attribute__((unused)),
                                 xmlNodePtr resp __attribute__((unused)),
                                 struct propstat propstat[],
                                 void *rock __attribute__((unused)))
{
    xmlNodePtr node;
    struct mime_type_t *mime;

    if (!fctx->req_tgt->collection) return HTTP_NOT_FOUND;

    node = xml_add_prop(HTTP_OK, fctx->ns[NS_DAV], &propstat[PROPSTAT_OK],
                        name, ns, NULL, 0);

    for (mime = carddav_mime_types; mime->content_type; mime++) {
        xmlNodePtr type = xmlNewChild(node, fctx->ns[NS_CARDDAV],
                                      BAD_CAST "address-data-type", NULL);

        /* Trim any charset from content-type */
        buf_reset(&fctx->buf);
        buf_printf(&fctx->buf, "%.*s",
                   (int) strcspn(mime->content_type, ";"), mime->content_type);

        xmlNewProp(type, BAD_CAST "content-type",
                   BAD_CAST buf_cstring(&fctx->buf));

        if (mime->version)
            xmlNewProp(type, BAD_CAST "version", BAD_CAST mime->version);
    }

    buf_reset(&fctx->buf);

    return 0;
}

/* Callback to fetch CY:address-groups */
int propfind_addrgroups(const xmlChar *name, xmlNsPtr ns,
                        struct propfind_ctx *fctx,
                        xmlNodePtr prop __attribute__((unused)),
                        xmlNodePtr resp __attribute__((unused)),
                        struct propstat propstat[],
                        void *rock __attribute__((unused)))
{
    int r = 0;
    struct carddav_db *davdb = NULL;
    struct carddav_data *cdata = NULL;
    strarray_t *groups;
    xmlNodePtr node;
    int i;

    if (!fctx->req_tgt->collection) return HTTP_NOT_FOUND;

    /* If we're here via report_sync_col then we don't have a db handle yet, so
     * lets just manage this ourselves */
    davdb = carddav_open_mailbox(fctx->mailbox);
    if (davdb == NULL) {
        r = HTTP_SERVER_ERROR;
        goto done;
    }

    r = carddav_lookup_resource(davdb, fctx->req_tgt->mbentry->name,
                                fctx->req_tgt->resource, &cdata, 0);
    if (r)
        goto done;

    node = xml_add_prop(HTTP_OK, fctx->ns[NS_CYRUS], &propstat[PROPSTAT_OK],
                        name, ns, NULL, 0);

    groups = carddav_getuid_groups(davdb, cdata->vcard_uid);
    if (groups == NULL)
        goto done;

    for (i = 0; i < strarray_size(groups); i++) {
        const char *group_uid = strarray_nth(groups, i);

        xmlNodePtr group = xmlNewChild(node, fctx->ns[NS_CYRUS],
                                       BAD_CAST "address-group", NULL);
        xmlAddChild(group,
                    xmlNewCDataBlock(fctx->root->doc,
                                     BAD_CAST group_uid, strlen(group_uid)));
    }

    strarray_free(groups);

done:
    carddav_close(davdb);
    return r;
}


typedef enum vcardproperty_kind {
    VCARD_ANY_PROPERTY = 0,
    VCARD_FN_PROPERTY = 1,
    VCARD_N_PROPERTY = 2,
    VCARD_NICKNAME_PROPERTY = 3,
    VCARD_UID_PROPERTY = 4,
    VCARD_NO_PROPERTY = 1000
} vcardproperty_kind;

struct cardquery_filter {
    unsigned allof : 1;
    struct prop_filter *prop;
};

static unsigned vcardproperty_string_to_kind(const char *str)
{
    if (!strcasecmp(str, "FN")) return VCARD_FN_PROPERTY;
    else if (!strcasecmp(str, "N")) return VCARD_N_PROPERTY;
    else if (!strcasecmp(str, "NICKNAME")) return VCARD_NICKNAME_PROPERTY;
    else if (!strcasecmp(str, "UID")) return VCARD_UID_PROPERTY;
    else return VCARD_ANY_PROPERTY;
}

static int parse_cardfilter(xmlNodePtr root, struct cardquery_filter *filter,
                            struct error_t *error)
{
    xmlChar *attr;
    xmlNodePtr node;
    struct filter_profile_t profile =
        { 0 /* anyof */, COLLATION_UNICODE,
          CARDDAV_SUPP_FILTER, CARDDAV_SUPP_COLLATION,
          vcardproperty_string_to_kind, VCARD_NO_PROPERTY,
          NULL /* param_string_to_kind */, 0 /* no_param_value */,
          NULL /* parse_propfilter */ };

    /* Parse elements of filter */
    attr = xmlGetProp(root, BAD_CAST "test");
    if (attr) {
        if (!xmlStrcmp(attr, BAD_CAST "allof")) filter->allof = 1;
        else if (xmlStrcmp(attr, BAD_CAST "anyof")) {
            error->precond = CARDDAV_SUPP_FILTER;
            error->desc = "Unsupported test";
            error->node = xmlCopyNode(root, 2);
        }
        xmlFree(attr);
    }

    for (node = xmlFirstElementChild(root); node && !error->precond;
         node = xmlNextElementSibling(node)) {

        if (!xmlStrcmp(node->name, BAD_CAST "prop-filter")) {
            struct prop_filter *prop = NULL;

            dav_parse_propfilter(node, &prop, &profile, error);
            if (prop) {
                if (filter->prop) prop->next = filter->prop;
                filter->prop = prop;
            }
        }
        else {
            error->precond = CARDDAV_SUPP_FILTER;
            error->desc = "Unsupported element in filter";
            error->node = xmlCopyNode(root, 1);
        }
    }

    return error->precond ? HTTP_FORBIDDEN : 0;
}


static int apply_paramfilter(struct param_filter *paramfilter,
                             struct vparse_entry *prop)
{
    struct vparse_param *param =
        vparse_get_param(prop, (char *) paramfilter->name);

    if (!param) return paramfilter->not_defined;
    if (paramfilter->not_defined) return 0;
    if (!paramfilter->match) return 1;

    return dav_apply_textmatch(BAD_CAST param->value, paramfilter->match);
}

static int apply_propfilter(struct prop_filter *propfilter,
                            struct carddav_data *cdata,
                            struct propfind_ctx *fctx)
{
    int pass = 1;
    struct vparse_card *vcard = fctx->obj;
    struct vparse_entry myprop, *prop = NULL;

    memset(&myprop, 0, sizeof(struct vparse_entry));

    if (!propfilter->param) {
        switch (propfilter->kind) {
        case VCARD_FN_PROPERTY:
            if (cdata->fullname) myprop.v.value = (char *) cdata->fullname;
            break;

        case VCARD_N_PROPERTY:
            if (cdata->name) myprop.v.value = (char *) cdata->name;
            break;

        case VCARD_NICKNAME_PROPERTY:
            if (cdata->nickname) {
                if (propfilter->match) {
                    myprop.multivalue = 1;
                    myprop.v.values =
                        strarray_split(cdata->nickname, ",", STRARRAY_TRIM);
                }
                else myprop.v.value = (char *) cdata->nickname;
            }
            break;

        case VCARD_UID_PROPERTY:
            if (cdata->vcard_uid) myprop.v.value = (char *) cdata->vcard_uid;
            break;

        default:
            break;
        }

        if (myprop.v.value) prop = &myprop;
    }

    if (propfilter->param || (propfilter->kind == VCARD_ANY_PROPERTY)) {
        /* Load message containing the resource and parse vcard data */
        if (!vcard) {
            if (!fctx->msg_buf.len) {
                mailbox_map_record(fctx->mailbox, fctx->record, &fctx->msg_buf);
            }
            if (fctx->msg_buf.len) {
                vcard = fctx->obj =
                    vcard_parse_string(buf_cstring(&fctx->msg_buf) +
                                       fctx->record->header_size, 1);
            }
            if (!vcard) return 0;
        }

        prop = vparse_get_entry(vcard->objects, NULL, (char *) propfilter->name);
    }

    if (!prop) return propfilter->not_defined;
    if (propfilter->not_defined) return 0;
    if (!(propfilter->match || propfilter->param)) return 1;

    /* Test each instance of this property (logical OR) */
    do {
        struct text_match_t *match;
        struct param_filter *paramfilter;

        if (!pass && strcasecmpsafe(prop->name, (char *) propfilter->name)) {
            /* Skip property if name doesn't match */
            continue;
        }
    
        pass = propfilter->allof;

        /* Apply each text-match, breaking if allof fails or anyof succeeds */
        for (match = propfilter->match;
             match && (pass == propfilter->allof);
             match = match->next) {

            int n = 0;
            const char *text = prop->multivalue ?
                strarray_nth(prop->v.values, n) : prop->v.value;

            /* Test each value of this property (logical OR) */
            do {
                pass = dav_apply_textmatch(BAD_CAST text, match);

            } while (!pass && prop->multivalue &&
                     (text = strarray_nth(prop->v.values, ++n)));
        }

        /* Apply each param-filter, breaking if allof fails or anyof succeeds */
        for (paramfilter = propfilter->param;
             paramfilter && (pass == propfilter->allof);
             paramfilter = paramfilter->next) {

            pass = apply_paramfilter(paramfilter, prop);
        }

    } while (!pass && (prop = prop->next));  /* XXX  No API to fetch next prop */

    if (myprop.multivalue) strarray_free(myprop.v.values);

    return pass;
}

/* See if the current resource matches the specified filter.
 * Returns 1 if match, 0 otherwise.
 */
static int apply_cardfilter(struct propfind_ctx *fctx, void *data)
{
    struct cardquery_filter *cardfilter =
        (struct cardquery_filter *) fctx->filter_crit;
    struct carddav_data *cdata = (struct carddav_data *) data;
    struct prop_filter *propfilter;
    int pass = 1;

    for (propfilter = cardfilter->prop; propfilter;
         propfilter = propfilter->next) {

        pass = apply_propfilter(propfilter, cdata, fctx);
        /* If allof fails or anyof succeeds, we're done */
        if (pass != cardfilter->allof) break;
    }

    return pass;
}

static void free_cardfilter(struct cardquery_filter *cardfilter)
{
    struct prop_filter *prop, *next;

    for (prop = cardfilter->prop; prop; prop = next) {
        next = prop->next;

        dav_free_propfilter(prop);
    }
}

static int report_card_query(struct transaction_t *txn,
                             struct meth_params *rparams __attribute__((unused)),
                             xmlNodePtr inroot, struct propfind_ctx *fctx)
{
    int ret = 0;
    xmlNodePtr node;
    struct cardquery_filter cardfilter;

    memset(&cardfilter, 0, sizeof(struct cardquery_filter));

    fctx->filter_crit = &cardfilter;
    fctx->open_db = (db_open_proc_t) &carddav_open_mailbox;
    fctx->close_db = (db_close_proc_t) &carddav_close;
    fctx->lookup_resource = (db_lookup_proc_t) &carddav_lookup_resource;
    fctx->foreach_resource = (db_foreach_proc_t) &carddav_foreach;
    fctx->proc_by_resource = &propfind_by_resource;
    fctx->davdb = NULL;

    /* Parse children element of report */
    for (node = inroot->children; node; node = node->next) {
        if (node->type == XML_ELEMENT_NODE) {
            if (!xmlStrcmp(node->name, BAD_CAST "filter")) {
                ret = parse_cardfilter(node, &cardfilter, &txn->error);
                if (ret) goto done;
                else fctx->filter = apply_cardfilter;
            }
        }
    }

    if (fctx->depth++ > 0) {
        /* Addressbook collection(s) */
        if (txn->req_tgt.collection) {
            /* Add response for target addressbook collection */
            propfind_by_collection(txn->req_tgt.mbentry, fctx);
        }
        else {
            /* Add responses for all contained addressbook collections */
            mboxlist_mboxtree(txn->req_tgt.mbentry->name,
                              propfind_by_collection, fctx,
                              MBOXTREE_SKIP_ROOT);

            /* Add responses for all shared addressbook collections */
            mboxlist_usersubs(txn->req_tgt.userid,
                              propfind_by_collection, fctx,
                              MBOXTREE_SKIP_PERSONAL);
        }

        ret = *fctx->ret;
    }

  done:
    /* Free filter structure */
    free_cardfilter(&cardfilter);

    if (fctx->davdb) {
        fctx->close_db(fctx->davdb);
        fctx->davdb = NULL;
    }

    return (ret ? ret : HTTP_MULTI_STATUS);
}
