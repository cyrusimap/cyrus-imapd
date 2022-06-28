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

#include <sysexits.h>
#include <syslog.h>

#include <libxml/tree.h>
#include <libxml/uri.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "acl.h"
#include "append.h"
#include "carddav_db.h"
#include "global.h"
#include "hash.h"
#include "httpd.h"
#include "http_dav.h"
#include "http_dav_sharing.h"
#include "http_proxy.h"
#include "index.h"
#include "mailbox.h"
#include "mboxlist.h"
#include "message.h"
#include "message_guid.h"
#include "proxy.h"
#include "smtpclient.h"
#include "spool.h"
#include "strhash.h"
#include "times.h"
#include "user.h"
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

static time_t compile_time;
static int vcard_max_size;

static void my_carddav_init(struct buf *serverinfo);
static int my_carddav_auth(const char *userid);
static void my_carddav_reset(void);
static void my_carddav_shutdown(void);

static int carddav_parse_path(const char *path, struct request_target_t *tgt,
                              const char **resultstr);

static int carddav_copy(struct transaction_t *txn, void *obj,
                        struct mailbox *mailbox, const char *resource,
                        void *destdb, unsigned flags);

static int carddav_get(struct transaction_t *txn, struct mailbox *mailbox,
                       struct index_record *record, void *data, void **obj,
                       struct mime_type_t *mime);

static int carddav_put(struct transaction_t *txn, void *obj,
                       struct mailbox *mailbox, const char *resource,
                       void *destdb, unsigned flags);

static int carddav_import(struct transaction_t *txn, void *obj,
                          struct mailbox *mailbox, void *destdb,
                          xmlNodePtr root, xmlNsPtr *ns, unsigned flags);

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
static int propfind_maxsize(const xmlChar *name, xmlNsPtr ns,
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
    { "text/directory; charset=utf-8", "3.0", "vcf",
      (struct buf* (*)(void *)) &vcard_as_buf,
      (void * (*)(const struct buf*)) &vcard_parse_buf,
      (void (*)(void *)) &vparse_free_card, NULL, NULL
    },
    { "text/vcard", "4.0", "vcf",
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
      DACL_ADMIN, REPORT_NEED_MBOX | REPORT_NEED_PROPS | REPORT_DEPTH_ZERO },

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
      PROP_ALLPROP | PROP_COLLECTION | PROP_RESOURCE | PROP_PERUSER,
      propfind_collectionname, proppatch_todb, NULL },
    { "getcontentlanguage", NS_DAV,
      PROP_ALLPROP | PROP_RESOURCE,
      propfind_fromhdr, NULL, "Content-Language" },
    { "getcontentlength", NS_DAV,
      PROP_ALLPROP | PROP_COLLECTION | PROP_RESOURCE,
      propfind_getlength, NULL, NULL },
    { "getcontenttype", NS_DAV,
      PROP_ALLPROP | PROP_COLLECTION | PROP_RESOURCE,
      propfind_getcontenttype, NULL, "Content-Type" },
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
      PROP_ALLPROP | PROP_COLLECTION | PROP_RESOURCE | PROP_PRESCREEN,
      propfind_restype, proppatch_restype, "addressbook" },
    { "supportedlock", NS_DAV,
      PROP_ALLPROP | PROP_RESOURCE,
      propfind_suplock, NULL, NULL },

    /* WebDAV Versioning (RFC 3253) properties */
    { "supported-report-set", NS_DAV,
      PROP_COLLECTION | PROP_PRESCREEN,
      propfind_reportset, NULL, (void *) carddav_reports },
    { "supported-method-set", NS_DAV,
      PROP_COLLECTION | PROP_RESOURCE,
      propfind_methodset, NULL, (void *) &calcarddav_allow_cb },

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
      propfind_addmember, NULL, NULL },

    /* WebDAV Sync (RFC 6578) properties */
    { "sync-token", NS_DAV,
      PROP_COLLECTION,
      propfind_sync_token, NULL, SYNC_TOKEN_URL_SCHEME },

    /* WebDAV Sharing (draft-pot-webdav-resource-sharing) properties */
    { "share-access", NS_DAV,
      PROP_COLLECTION,
      propfind_shareaccess, NULL, NULL },
    { "invite", NS_DAV,
      PROP_COLLECTION,
      propfind_invite, NULL, NULL },
    { "sharer-resource-uri", NS_DAV,
      PROP_COLLECTION,
      propfind_sharedurl, NULL, NULL },

    /* CardDAV (RFC 6352) properties */
    { "address-data", NS_CARDDAV,
      PROP_RESOURCE | PROP_PRESCREEN | PROP_CLEANUP,
      propfind_addrdata, NULL, (void *) CARDDAV_SUPP_DATA },
    { "addressbook-description", NS_CARDDAV,
      PROP_COLLECTION | PROP_PERUSER,
      propfind_fromdb, proppatch_todb, NULL },
    { "supported-address-data", NS_CARDDAV,
      PROP_COLLECTION,
      propfind_suppaddrdata, NULL, NULL },
    { "supported-collation-set", NS_CARDDAV,
      PROP_COLLECTION,
      propfind_collationset, NULL, NULL },
    { "max-resource-size", NS_CARDDAV,
      PROP_COLLECTION,
      propfind_maxsize, NULL, NULL },

    /* Apple Calendar Server properties */
    { "getctag", NS_CS,
      PROP_ALLPROP | PROP_COLLECTION,
      propfind_sync_token, NULL, "" },

    /* Apple Push Notifications Service properties */
    { "push-transports", NS_CS,
      PROP_COLLECTION | PROP_PRESCREEN,
      propfind_push_transports, NULL, (void *) MBTYPE_ADDRESSBOOK },
    { "pushkey", NS_CS,
      PROP_COLLECTION,
      propfind_pushkey, NULL, NULL },

    /* Cyrus properties */
    { "address-groups", NS_CYRUS,
      PROP_RESOURCE,
      propfind_addrgroups, NULL, NULL },

    { NULL, 0, 0, NULL, NULL, NULL }
};

static struct meth_params carddav_params = {
    carddav_mime_types,
    &carddav_parse_path,
    &dav_get_validators,
    &dav_get_modseq,
    &dav_check_precond,
    { (db_open_proc_t) &carddav_open_mailbox,
      (db_close_proc_t) &carddav_close,
      (db_proc_t) &carddav_begin,
      (db_proc_t) &carddav_commit,
      (db_proc_t) &carddav_abort,
      (db_lookup_proc_t) &carddav_lookup_resource,
      (db_imapuid_proc_t) &carddav_lookup_imapuid,
      (db_foreach_proc_t) &carddav_foreach,
      (db_updates_proc_t) &carddav_get_updates,
      (db_write_proc_t) &carddav_write,
      (db_delete_proc_t) &carddav_delete },
    NULL,                                       /* No ACL extensions */
    { CARDDAV_UID_CONFLICT, &carddav_copy },
    NULL,                                       /* No special DELETE handling */
    &carddav_get,
    { CARDDAV_LOCATION_OK, MBTYPE_ADDRESSBOOK, NULL },
    NULL,                                       /* No PATCH handling */
    { POST_ADDMEMBER | POST_SHARE, NULL,        /* No special POST handling */
      { NS_CARDDAV, "addressbook-data", &carddav_import } },
    { CARDDAV_SUPP_DATA, &carddav_put },
    { DAV_FINITE_DEPTH, carddav_props },        /* Disable infinite depth */
    carddav_reports
};


/* Namespace for Carddav collections */
struct namespace_t namespace_addressbook = {
    URL_NS_ADDRESSBOOK, 0, "addressbook", "/dav/addressbooks", "/.well-known/carddav",
    http_allow_noauth_get, /*authschemes*/0,
    MBTYPE_ADDRESSBOOK,
    (ALLOW_READ | ALLOW_POST | ALLOW_WRITE | ALLOW_DELETE |
     ALLOW_DAV | ALLOW_PROPPATCH | ALLOW_MKCOL | ALLOW_ACL | ALLOW_CARD),
    &my_carddav_init, &my_carddav_auth, my_carddav_reset, &my_carddav_shutdown,
    &dav_premethod,
    {
        { &meth_acl,            &carddav_params },      /* ACL          */
        { NULL,                 NULL },                 /* BIND         */
        { NULL,                 NULL },                 /* CONNECT      */
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
        fatal("Required 'addressbookprefix' option is not set", EX_CONFIG);
    }

    carddav_init();

    namespace_principal.enabled = 1;
    /* Apple clients check principal resources for these DAV tokens */
    namespace_principal.allow |= ALLOW_CARD;

    compile_time = calc_compile_time(__TIME__, __DATE__);

    vcard_max_size = config_getint(IMAPOPT_VCARD_MAX_SIZE);
    if (vcard_max_size <= 0) vcard_max_size = INT_MAX;
}


#define DEFAULT_ADDRBOOK "Default"

static int _create_mailbox(const char *userid, const char *mailboxname, int type,
                           const char *displayname, struct mboxlock **namespacelockp)
{
    struct mailbox *mailbox = NULL;

    int r = mboxlist_lookup(mailboxname, NULL, NULL);
    if (r != IMAP_MAILBOX_NONEXISTENT) return r;

    if (!*namespacelockp) {
        *namespacelockp = mboxname_usernamespacelock(mailboxname);
        // maybe we lost the race on this one
        r = mboxlist_lookup(mailboxname, NULL, NULL);
        if (r != IMAP_MAILBOX_NONEXISTENT) return r;
    }

    /* Create locally */
    mbentry_t mbentry = MBENTRY_INITIALIZER;
    mbentry.name = (char *) mailboxname;
    mbentry.mbtype = type;
    r = mboxlist_createmailbox(&mbentry, 0/*options*/, 0/*highestmodseq*/,
                               0/*isadmin*/, userid, httpd_authstate,
                               0/*flags*/, displayname ? &mailbox : NULL);

    if (!r && displayname) {
        annotate_state_t *astate = NULL;

        r = mailbox_get_annotate_state(mailbox, 0, &astate);
        if (!r) {
            const char *disp_annot = DAV_ANNOT_NS "<" XML_NS_DAV ">displayname";
            struct buf value = BUF_INITIALIZER;

            buf_init_ro_cstr(&value, displayname);
            r = annotate_state_writemask(astate, disp_annot, userid, &value);
            buf_free(&value);
        }

        mailbox_close(&mailbox);
    }

    if (r) syslog(LOG_ERR, "IOERROR: failed to create %s (%s)",
                  mailboxname, error_message(r));

    return r;
}



EXPORTED int carddav_create_defaultaddressbook(const char *userid) {
    struct mboxlock *namespacelock = NULL;

    /* addressbook-home-set */
    mbname_t *mbname = mbname_from_userid(userid);
    mbname_push_boxes(mbname, config_getstring(IMAPOPT_ADDRESSBOOKPREFIX));
    int r = mboxlist_lookup(mbname_intname(mbname), NULL, NULL);
    if (r == IMAP_MAILBOX_NONEXISTENT) {
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
            goto done;
        }
        mboxlist_entry_free(&mbentry);

        if (!r) r = _create_mailbox(userid, mbname_intname(mbname),
                                    MBTYPE_ADDRESSBOOK, NULL,
                                    &namespacelock);
    }
    if (r) goto done;

    /* Default addressbook */
    mbname_push_boxes(mbname, DEFAULT_ADDRBOOK);
    r = mboxlist_lookup(mbname_intname(mbname), NULL, NULL);
    if (r == IMAP_MAILBOX_NONEXISTENT) {
        r = _create_mailbox(userid, mbname_intname(mbname),
                            MBTYPE_ADDRESSBOOK, "personal",
                            &namespacelock);
    }

 done:
    mboxname_release(&namespacelock);
    mbname_free(&mbname);
    return r;
}

static int my_carddav_auth(const char *userid)
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

    /* Auto-provision an addressbook for 'userid' */
    int r = carddav_create_defaultaddressbook(userid);
    if (r) {
        syslog(LOG_ERR, "could not autoprovision addressbook for userid %s: %s",
                userid, error_message(r));
        return HTTP_SERVER_ERROR;
    }
    return 0;
}


static void my_carddav_reset(void)
{
    // nothing
}


static void my_carddav_shutdown(void)
{
    my_carddav_reset();
    carddav_done();
}


/* Parse request-target path in CardDAV namespace */
static int carddav_parse_path(const char *path, struct request_target_t *tgt,
                              const char **resultstr)
{
    return calcarddav_parse_path(path, tgt,
                                 config_getstring(IMAPOPT_ADDRESSBOOKPREFIX),
                                 resultstr);
}

/* Store the vCard data in the specified addressbook/resource */
static int carddav_store_resource(struct transaction_t *txn,
                                  struct vparse_card *vcard,
                                  struct mailbox *mailbox, const char *resource,
                                  struct carddav_db *davdb)
{
    struct vparse_entry *ventry;
    struct carddav_data *cdata;
    const char *version = NULL, *uid = NULL, *fullname = NULL;
    struct index_record *oldrecord = NULL, record;
    char *mimehdr;

    /* Validate the vCard data */
    if (!vcard) {
        txn->error.precond = CARDDAV_VALID_DATA;
        return HTTP_FORBIDDEN;
    }

    /* Fetch some important properties */
    for (ventry = vcard->objects->properties; ventry; ventry = ventry->next) {
        const char *name = ventry->name;
        const char *propval = ventry->v.value;

        if (!name) continue;
        if (!propval) continue;

        if (!strcasecmp(name, "version"))
            version = propval;

        else if (!strcasecmp(name, "uid"))
            uid = propval;

        else if (!strcasecmp(name, "fn"))
            fullname = propval;
    }

    /* Check for an existing resource */
    /* XXX  We can't assume that txn->req_tgt.mbentry is our target,
       XXX  because we may have been called as part of a COPY/MOVE */
    const mbentry_t mbentry = { .name = (char *)mailbox_name(mailbox),
                                .uniqueid = (char *)mailbox_uniqueid(mailbox) };
    carddav_lookup_resource(davdb, &mbentry, resource, &cdata, 0);

    if (cdata->dav.imap_uid) {
        /* Fetch index record for the resource */
        int r = mailbox_find_index_record(mailbox, cdata->dav.imap_uid, &record);
        if (!r) {
            oldrecord = &record;
        }
        else {
            xsyslog(LOG_ERR,
                    "Couldn't find index record corresponding to CardDAV DB record",
                    "mailbox=<%s> record=<%u> error=<%s>",
                    mailbox_name(mailbox), cdata->dav.imap_uid, error_message(r));
        }
    }

    /* Check size of vCard (allow existing oversized cards to be updated) */
    struct buf *buf = vcard_as_buf(vcard);
    if ((buf_len(buf) > (size_t) vcard_max_size) &&
        (!oldrecord || (oldrecord->size - oldrecord->header_size) <= (size_t) vcard_max_size)) {
        buf_destroy(buf);
        txn->error.precond = CARDDAV_MAX_SIZE;
        return HTTP_FORBIDDEN;
    }

    /* Create and cache RFC 5322 header fields for resource */
    mimehdr = charset_encode_mimeheader(fullname, 0, 0);
    spool_replace_header(xstrdup("Subject"), mimehdr, txn->req_hdrs);

    /* Use SHA1(uid)@servername as Message-ID */
    struct message_guid uuid;
    message_guid_generate(&uuid, uid, strlen(uid));
    assert(!buf_len(&txn->buf));
    buf_printf(&txn->buf, "<%s@%s>",
               message_guid_encode(&uuid), config_servername);
    spool_replace_header(xstrdup("Message-ID"),
                         buf_release(&txn->buf), txn->req_hdrs);

    assert(!buf_len(&txn->buf));
    buf_printf(&txn->buf, "text/vcard; version=%s; charset=utf-8", version);
    spool_replace_header(xstrdup("Content-Type"),
                         buf_release(&txn->buf), txn->req_hdrs);

    buf_printf(&txn->buf, "attachment;\r\n\tfilename=\"%s\"", resource);
    spool_replace_header(xstrdup("Content-Disposition"),
                         buf_release(&txn->buf), txn->req_hdrs);

    spool_remove_header(xstrdup("Content-Description"), txn->req_hdrs);

    /* Store the resource */
    int r = dav_store_resource(txn, buf_cstring(buf), 0,
                              mailbox, oldrecord, cdata->dav.createdmodseq,
                              NULL, NULL);
    buf_destroy(buf);
    return r;
}

static int carddav_copy(struct transaction_t *txn, void *obj,
                        struct mailbox *mailbox, const char *resource,
                        void *destdb, unsigned flags __attribute__((unused)))
{
    struct carddav_db *db = (struct carddav_db *)destdb;
    struct vparse_card *vcard = (struct vparse_card *)obj;

    return carddav_store_resource(txn, vcard, mailbox, resource, db);
}


static int export_addressbook(struct transaction_t *txn,
                              struct mime_type_t *mime)
{
    int ret = 0, r, precond;
    struct resp_body_t *resp_body = &txn->resp_body;
    struct buf *buf = &resp_body->payload;
    struct mailbox *mailbox = NULL;
    static char etag[33];
    static const char *displayname_annot =
        DAV_ANNOT_NS "<" XML_NS_DAV ">displayname";
    struct buf attrib = BUF_INITIALIZER;
    const char *sep = "";

    if (!mime) return HTTP_NOT_ACCEPTABLE;

    /* Open mailbox for reading */
    r = mailbox_open_irl(txn->req_tgt.mbentry->name, &mailbox);
    if (r) {
        syslog(LOG_ERR, "http_mailbox_open(%s) failed: %s",
               txn->req_tgt.mbentry->name, error_message(r));
        txn->error.desc = error_message(r);
        ret = HTTP_SERVER_ERROR;
        goto done;
    }

    /* Check any preconditions */
    sprintf(etag, "%u-%u-%u",
            mailbox->i.uidvalidity, mailbox->i.last_uid, mailbox->i.exists);
    precond = check_precond(txn, etag, mailbox->index_mtime);

    switch (precond) {
    case HTTP_OK:
    case HTTP_NOT_MODIFIED:
        /* Fill in ETag, Last-Modified, Expires, and Cache-Control */
        txn->resp_body.etag = etag;
        txn->resp_body.lastmod = mailbox->index_mtime;
        txn->resp_body.maxage = 3600;  /* 1 hr */
        txn->flags.cc |= CC_MAXAGE | CC_REVALIDATE;  /* don't use stale data */
        if (httpd_userid) txn->flags.cc |= CC_PRIVATE;

        if (precond != HTTP_NOT_MODIFIED) break;

        GCC_FALLTHROUGH

    default:
        /* We failed a precondition - don't perform the request */
        ret = precond;
        goto done;
    }

    /* Setup for chunked response */
    txn->flags.te |= TE_CHUNKED;
    txn->flags.vary |= VARY_ACCEPT;
    txn->resp_body.type = mime->content_type;

    /* Set filename of resource */
    r = annotatemore_lookupmask_mbox(mailbox, displayname_annot,
                                     httpd_userid, &attrib);
    /* fall back to last part of mailbox name */
    if (r || !attrib.len) buf_setcstr(&attrib, strrchr(mailbox_name(mailbox), '.') + 1);

    buf_reset(&txn->buf);
    buf_printf(&txn->buf, "%s.%s", buf_cstring(&attrib), mime->file_ext);
    txn->resp_body.dispo.fname = buf_cstring(&txn->buf);

    /* Short-circuit for HEAD request */
    if (txn->meth == METH_HEAD) {
        response_header(HTTP_OK, txn);
        ret = 0;
        goto done;
    }

    /* vCard data in response should not be transformed */
    txn->flags.cc |= CC_NOTRANSFORM;

    /* Begin (converted) vCard stream */
    if (mime->begin_stream)
        sep = mime->begin_stream(buf, mailbox, NULL, NULL, NULL, NULL);
    else buf_reset(buf);
    write_body(HTTP_OK, txn, buf_cstring(buf), buf_len(buf));

    unsigned want_ver = (mime->version[0] == '4') ? 4 : 3;
    struct mailbox_iter *iter =
        mailbox_iter_init(mailbox, 0, ITER_SKIP_EXPUNGED|ITER_SKIP_DELETED);

    const message_t *msg;
    while ((msg = mailbox_iter_step(iter))) {
        const struct index_record *record = msg_record(msg);
        struct vparse_card *vcard;

        /* Map and parse existing vCard resource */
        vcard = record_to_vcard(mailbox, record);

        if (vcard) {
            struct vparse_entry *ventry =
                vparse_get_entry(vcard, NULL, "version");
            unsigned version = (ventry && ventry->v.value[0] == '4') ? 4 : 3;

            if (version != want_ver) {
                if (want_ver == 4) vcard_to_v4(vcard);
                else vcard_to_v3(vcard);
            }

            if (r++ && *sep) {
                /* Add separator, if necessary */
                buf_reset(buf);
                buf_printf_markup(buf, 0, "%s", sep);
                write_body(0, txn, buf_cstring(buf), buf_len(buf));
            }

            struct buf *card_str = mime->from_object(vcard);
            write_body(0, txn, buf_base(card_str), buf_len(card_str));
            buf_destroy(card_str);

            vparse_free_card(vcard);
        }
    }

    mailbox_iter_done(&iter);

    /* End (converted) vCard stream */
    if (mime->end_stream) {
        mime->end_stream(buf);
        write_body(0, txn, buf_cstring(buf), buf_len(buf));
    }

    /* End of output */
    write_body(0, txn, NULL, 0);

  done:
    buf_free(&attrib);
    mailbox_close(&mailbox);

    return ret;
}


/*
 * mboxlist_findall() callback function to list addressbooks
 */

struct addr_info {
    char shortname[MAX_MAILBOX_NAME];
    char displayname[MAX_MAILBOX_NAME];
    unsigned flags;
};

enum {
    ADDR_IS_DEFAULT =    (1<<0),
    ADDR_CAN_DELETE =    (1<<1),
    ADDR_CAN_ADMIN =     (1<<2),
    ADDR_IS_PUBLIC =     (1<<3)
};

struct list_addr_rock {
    struct addr_info *addr;
    unsigned len;
    unsigned alloc;
};

static int list_addr_cb(const mbentry_t *mbentry, void *rock)
{
    struct list_addr_rock *lrock = (struct list_addr_rock *) rock;
    struct addr_info *addr;
    static size_t defaultlen = 0;
    char *shortname;
    size_t len;
    int r, rights, any_rights = 0;
    static const char *displayname_annot =
        DAV_ANNOT_NS "<" XML_NS_DAV ">displayname";
    struct buf displayname = BUF_INITIALIZER;

    if (!defaultlen) defaultlen = strlen(DEFAULT_ADDRBOOK);

    /* Make sure its a addrendar */
    if (mbtype_isa(mbentry->mbtype) != MBTYPE_ADDRESSBOOK) goto done;

    /* Make sure its readable */
    rights = httpd_myrights(httpd_authstate, mbentry);
    if ((rights & DACL_READ) != DACL_READ) goto done;

    shortname = strrchr(mbentry->name, '.') + 1;
    len = strlen(shortname);

    /* Lookup DAV:displayname */
    r = annotatemore_lookupmask_mbe(mbentry, displayname_annot,
                                    httpd_userid, &displayname);
    /* fall back to the last part of the mailbox name */
    if (r || !displayname.len) buf_setcstr(&displayname, shortname);

    /* Make sure we have room in our array */
    if (lrock->len == lrock->alloc) {
        lrock->alloc += 100;
        lrock->addr = xrealloc(lrock->addr,
                              lrock->alloc * sizeof(struct addr_info));
    }

    /* Add our addressbook to the array */
    addr = &lrock->addr[lrock->len];
    strlcpy(addr->shortname, shortname, MAX_MAILBOX_NAME);
    strlcpy(addr->displayname, buf_cstring(&displayname), MAX_MAILBOX_NAME);
    addr->flags = 0;

    /* Is this the default addressbook? */
    if (len == defaultlen && !strncmp(shortname, SCHED_DEFAULT, defaultlen)) {
        addr->flags |= ADDR_IS_DEFAULT;
    }

    /* Can we delete this addrendar? */
    else if (rights & DACL_RMCOL) {
        addr->flags |= ADDR_CAN_DELETE;
    }

    /* Can we admin this addressbook? */
    if (rights & DACL_ADMIN) {
        addr->flags |= ADDR_CAN_ADMIN;
    }

    /* Is this addressbook public? */
    if (mbentry->acl) {
        struct auth_state *auth_anyone = auth_newstate("anyone");

        any_rights = cyrus_acl_myrights(auth_anyone, mbentry->acl);
        auth_freestate(auth_anyone);
    }
    if ((any_rights & DACL_READ) == DACL_READ) {
        addr->flags |= ADDR_IS_PUBLIC;
    }

    lrock->len++;

done:
    buf_free(&displayname);

    return 0;
}

static int addr_compare(const void *a, const void *b)
{
    struct addr_info *c1 = (struct addr_info *) a;
    struct addr_info *c2 = (struct addr_info *) b;

    return strcmp(c1->displayname, c2->displayname);
}


/* Create a HTML document listing all addressbooks available to the user */
static int list_addressbooks(struct transaction_t *txn)
{
    int ret = 0, precond, rights;
    char mboxlist[MAX_MAILBOX_PATH+1];
    struct stat sbuf;
    time_t lastmod;
    const char *etag, *base_path = txn->req_tgt.path;
    unsigned level = 0, i;
    struct buf *body = &txn->resp_body.payload;
    struct list_addr_rock lrock;
    const char *proto = NULL;
    const char *host = NULL;
#include "imap/http_carddav_js.h"

    /* stat() mailboxes.db for Last-Modified and ETag */
    snprintf(mboxlist, MAX_MAILBOX_PATH, "%s%s", config_dir, FNAME_MBOXLIST);
    stat(mboxlist, &sbuf);
    lastmod = MAX(compile_time, sbuf.st_mtime);
    assert(!buf_len(&txn->buf));
    buf_printf(&txn->buf, TIME_T_FMT "-" TIME_T_FMT "-" OFF_T_FMT,
               compile_time, sbuf.st_mtime, sbuf.st_size);

    /* stat() config file for Last-Modified and ETag */
    stat(config_filename, &sbuf);
    lastmod = MAX(lastmod, sbuf.st_mtime);
    buf_printf(&txn->buf, "-" TIME_T_FMT "-" OFF_T_FMT, sbuf.st_mtime, sbuf.st_size);
    etag = buf_cstring(&txn->buf);

    /* Check any preconditions */
    precond = check_precond(txn, etag, lastmod);

    switch (precond) {
    case HTTP_OK:
    case HTTP_NOT_MODIFIED:
        /* Fill in ETag, Last-Modified, and Expires */
        txn->resp_body.etag = etag;
        txn->resp_body.lastmod = lastmod;
        txn->flags.cc |= CC_REVALIDATE;

        if (precond != HTTP_NOT_MODIFIED) break;

        GCC_FALLTHROUGH

    default:
        /* We failed a precondition - don't perform the request */
        ret = precond;
        goto done;
    }

    /* Setup for chunked response */
    txn->flags.te |= TE_CHUNKED;
    txn->resp_body.type = "text/html; charset=utf-8";

    /* Short-circuit for HEAD request */
    if (txn->meth == METH_HEAD) {
        response_header(HTTP_OK, txn);
        goto done;
    }

    /* Send HTML header */
    buf_reset(body);
    buf_printf_markup(body, level, HTML_DOCTYPE);
    buf_printf_markup(body, level++, "<html>");
    buf_printf_markup(body, level++, "<head>");
    buf_printf_markup(body, level, "<title>%s</title>", "Available Addressbooks");
    buf_printf_markup(body, level++, "<script type=\"text/javascript\">");
    buf_appendcstr(body, "//<![CDATA[\n");
    buf_printf(body, (const char *) http_carddav_js,
               CYRUS_VERSION, http_carddav_js_len);
    buf_appendcstr(body, "//]]>\n");
    buf_printf_markup(body, --level, "</script>");
    buf_printf_markup(body, level++, "<noscript>");
    buf_printf_markup(body, level, "<i>*** %s ***</i>",
                      "JavaScript required to create/modify/delete addressbooks");
    buf_printf_markup(body, --level, "</noscript>");
    buf_printf_markup(body, --level, "</head>");
    buf_printf_markup(body, level++, "<body>");

    write_body(HTTP_OK, txn, buf_cstring(body), buf_len(body));
    buf_reset(body);

    /* Check ACL for current user */
    rights = httpd_myrights(httpd_authstate, txn->req_tgt.mbentry);

    if (rights & DACL_MKCOL) {
        /* Add "create" form */
        buf_printf_markup(body, level, "<h2>%s</h2>", "Create New Addressbook");
        buf_printf_markup(body, level++, "<form name='create'>");
        buf_printf_markup(body, level++, "<table cellpadding=5>");
        buf_printf_markup(body, level++, "<tr>");
        buf_printf_markup(body, level, "<td align=right>Name:</td>");
        buf_printf_markup(body, level,
                          "<td><input name=name size=30 maxlength=40></td>");
        buf_printf_markup(body, --level, "</tr>");

        buf_printf_markup(body, level++, "<tr>");
        buf_printf_markup(body, level, "<td align=right>Description:</td>");
        buf_printf_markup(body, level,
                          "<td><input name=desc size=75 maxlength=120></td>");
        buf_printf_markup(body, --level, "</tr>");

        buf_printf_markup(body, level++, "<tr>");
        buf_printf_markup(body, level, "<td></td>");
        buf_printf_markup(body, level,
                          "<td><br><input type=button value='Create'"
                          " onclick=\"createAddressbook('%s')\">"
                          " <input type=reset></td>",
                          base_path);
        buf_printf_markup(body, --level, "</tr>");

        buf_printf_markup(body, --level, "</table>");
        buf_printf_markup(body, --level, "</form>");

        buf_printf_markup(body, level, "<br><hr><br>");

        write_body(0, txn, buf_cstring(body), buf_len(body));
        buf_reset(body);
    }

    buf_printf_markup(body, level, "<h2>%s</h2>", "Available Addressbooks");
    buf_printf_markup(body, level++, "<table border cellpadding=5>");

    /* Create base URL for addressbooks */
    http_proto_host(txn->req_hdrs, &proto, &host);
    buf_reset(&txn->buf);
    buf_printf(&txn->buf, "%s://%s%s", proto, host, txn->req_tgt.path);

    memset(&lrock, 0, sizeof(struct list_addr_rock));
    mboxlist_mboxtree(txn->req_tgt.mbentry->name,
                      list_addr_cb, &lrock, MBOXTREE_SKIP_ROOT);

    /* Sort addressbooks by displayname */
    qsort(lrock.addr, lrock.len, sizeof(struct addr_info), &addr_compare);

    /* Add available addressbooks with action items */
    for (i = 0; i < lrock.len; i++) {
        struct addr_info *addr = &lrock.addr[i];

        /* Send a body chunk once in a while */
        if (buf_len(body) > PROT_BUFSIZE) {
            write_body(0, txn, buf_cstring(body), buf_len(body));
            buf_reset(body);
        }

        /* Addressbook name */
        buf_printf_markup(body, level++, "<tr>");
        buf_printf_markup(body, level, "<td>%s%s%s",
                          (addr->flags & ADDR_IS_DEFAULT) ? "<b>" : "",
                          addr->displayname,
                          (addr->flags & ADDR_IS_DEFAULT) ? "</b>" : "");

        /* Download link */
        buf_printf_markup(body, level, "<td><a href=\"%s%s\">Download</a></td>",
                          base_path, addr->shortname);

        /* Delete button */
        buf_printf_markup(body, level,
                          "<td><input type=button%s value='Delete'"
                          " onclick=\"deleteAddressbook('%s%s', '%s')\"></td>",
                          !(addr->flags & ADDR_CAN_DELETE) ? " disabled" : "",
                          base_path, addr->shortname, addr->displayname);

        /* Public (shared) checkbox */
        buf_printf_markup(body, level,
                          "<td><input type=checkbox%s%s name=share"
                          " onclick=\"shareAddressbook('%s%s', this.checked)\">"
                          "Public</td>",
                          !(addr->flags & ADDR_CAN_ADMIN) ? " disabled" : "",
                          (addr->flags & ADDR_IS_PUBLIC) ? " checked" : "",
                          base_path, addr->shortname);

        buf_printf_markup(body, --level, "</tr>");
    }

    free(lrock.addr);

    /* Finish list */
    buf_printf_markup(body, --level, "</table>");

    /* Finish HTML */
    buf_printf_markup(body, --level, "</body>");
    buf_printf_markup(body, --level, "</html>");
    write_body(0, txn, buf_cstring(body), buf_len(body));

    /* End of output */
    write_body(0, txn, NULL, 0);

  done:
    return ret;
}


/* Perform a GET/HEAD request on a CardDAV resource */
static int carddav_get(struct transaction_t *txn, struct mailbox *mailbox,
                       struct index_record *record, void *data, void **obj,
                       struct mime_type_t *mime)
{
    if (!(txn->req_tgt.collection || txn->req_tgt.userid))
        return HTTP_NO_CONTENT;

    if (record && record->uid) {
        /* GET on a resource */
        struct carddav_data *cdata = (struct carddav_data *) data;
        unsigned want_ver = (mime && mime->version[0] == '4') ? 4 : 3;

        if (cdata->version != want_ver) {
            /* Translate between vCard versions */
            *obj = record_to_vcard(mailbox, record);
            if (want_ver == 4) vcard_to_v4(*obj);
            else vcard_to_v3(*obj);
        }

        return HTTP_CONTINUE;
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

    if (txn->req_tgt.collection) {
        /* Download an entire addressbook collection */
        return export_addressbook(txn, mime);
    }
    else if (txn->req_tgt.userid &&
             config_getswitch(IMAPOPT_CARDDAV_ALLOWADDRESSBOOKADMIN)) {
        /* GET a list of addressbook under addressbook-home-set */
        return list_addressbooks(txn);
    }

    /* Unknown action */
    return HTTP_NO_CONTENT;
}


/* Perform a COPY/MOVE/PUT request
 *
 * preconditions:
 *   CARDDAV:valid-address-data
 *   CARDDAV:no-uid-conflict (DAV:href)
 *   CARDDAV:max-resource-size
 */
static int carddav_put(struct transaction_t *txn, void *obj,
                       struct mailbox *mailbox, const char *resource,
                       void *destdb, unsigned flags __attribute__((unused)))
{
    struct carddav_db *db = (struct carddav_db *)destdb;
    struct vparse_card *vcard = (struct vparse_card *)obj;
    char *type = NULL, *subtype = NULL;
    struct param *params = NULL;
    const char *want_ver = NULL;

    /* Sanity check Content-Type */
    const char **hdr = spool_getheader(txn->req_hdrs, "Content-Type");
    if (hdr && hdr[0]) {
        const char *profile = NULL;
        struct param *param;

        message_parse_type(hdr[0], &type, &subtype, &params);

        for (param = params; param; param = param->next) {
            if (!strcasecmp(param->attribute, "version")) {
                want_ver = param->value;

                if (strcmp(want_ver, "3.0") &&
                    strcmp(want_ver, "4.0")) {
                    txn->error.precond = CARDDAV_SUPP_DATA;
                    txn->error.desc =
                        "Unsupported version= specified in Content-Type";
                    goto done;
                }
            }
            else if (!strcasecmp(param->attribute, "charset")) {
                charset_t charset = charset_lookupname(param->value);

                if (charset == CHARSET_UNKNOWN_CHARSET) {
                    txn->error.precond = CARDDAV_SUPP_DATA;
                    txn->error.desc =
                        "Unknown charset= specified in Content-Type";
                    goto done;
                }
                if (strcmp(charset_canon_name(charset), "utf-8")) {
                    txn->error.precond = CARDDAV_SUPP_DATA;
                    txn->error.desc =
                        "Server only accepts Content-type charset=utf-8";
                    goto done;
                }
            }
            else if (!strcasecmp(param->attribute, "profile")) {
                profile = param->value;
            }
        }

        if (!strcasecmp(subtype, "directory")) {
            if (profile && strcasecmp(profile, "vcard")) {
                txn->error.precond = CARDDAV_SUPP_DATA;
                txn->error.desc = "Only profile=vcard is accepted"
                    " for Content-type 'text/directory'";
                goto done;
            }

            if (!want_ver) {
                want_ver = "3.0";
            }
            else if (want_ver[0] != 3) {
                txn->error.precond = CARDDAV_VALID_DATA;
                txn->error.desc =
                    "Content-Type 'text/directory' MUST use version=3.0";
                goto done;
            }
        }
    }

    /* Validate the vCard data */
    if (!vcard ||
        !vcard->objects ||
        !vcard->objects->type ||
        strcasecmp(vcard->objects->type, "vcard")) {
        txn->error.precond = CARDDAV_VALID_DATA;
        txn->error.desc = "Resource is not a vCard object";
        goto done;
    }

    if (!vparse_restriction_check(vcard->objects)) {
        txn->error.precond = CARDDAV_VALID_DATA;
        txn->error.desc = "Failed restriction checks";
        goto done;
    }

    /* Sanity check vCard data */
    struct vparse_entry *ventry;
    const char *uid = NULL, *fullname = NULL;
    for (ventry = vcard->objects->properties; ventry; ventry = ventry->next) {
        const char *name = ventry->name;
        const char *propval = ventry->v.value;

        if (!name) continue;
        if (!propval) continue;

        if (!strcasecmp(name, "version")) {
            if (strcmp(ventry->v.value, "3.0") &&
                strcmp(ventry->v.value, "4.0")) {
                txn->error.precond = CARDDAV_SUPP_DATA;
                txn->error.desc = "Unsupported vCard version";
                goto done;
            }
            if (want_ver && (want_ver[0] != ventry->v.value[0])) {
                txn->error.precond = CARDDAV_VALID_DATA;
                txn->error.desc =
                    "Content-Type version= and vCard VERSION mismatch";
                goto done;
            }
        }

        else if (!strcasecmp(name, "uid"))
            uid = propval;

        else if (!strcasecmp(name, "fn"))
            fullname = propval;
    }

    if (!uid) {
        txn->error.precond = CARDDAV_VALID_DATA;
        txn->error.desc = "Missing mandatory UID property";
        goto done;
    }
    if (!fullname) {
        txn->error.precond = CARDDAV_VALID_DATA;
        txn->error.desc = "Missing mandatory FN property";
        goto done;
    }

    /* Check for changed UID -- Allow for text uuid <-> urn:uuid */
    struct carddav_data *cdata;
    carddav_lookup_resource(db, txn->req_tgt.mbentry, resource, &cdata, 0);
    
    const char *olduid = cdata->vcard_uid;
    if (!strncmp(uid, "urn:uuid:", 9)) uid += 9;
    if (!strncmpsafe(olduid, "urn:uuid:", 9)) olduid += 9;
    if (cdata->dav.imap_uid && strcmpsafe(olduid, uid)) {
        /* CARDDAV:no-uid-conflict */
        char *owner;
        const char *mboxname;
        mbentry_t *mbentry = NULL;

        if (cdata->dav.mailbox_byname)
            mboxname = cdata->dav.mailbox;
        else {
            mboxlist_lookup_by_uniqueid(cdata->dav.mailbox, &mbentry, NULL);
            mboxname = mbentry->name;
        }
        owner = mboxname_to_userid(mboxname);

        assert(!buf_len(&txn->buf));
        buf_printf(&txn->buf, "%s/%s/%s/%s/%s",
                   namespace_addressbook.prefix, USER_COLLECTION_PREFIX, owner,
                   strrchr(mboxname, '.') + 1, cdata->dav.resource);
        txn->error.resource = buf_cstring(&txn->buf);
        mboxlist_entry_free(&mbentry);
        free(owner);

        txn->error.precond = CARDDAV_UID_CONFLICT;
        goto done;
    }

  done:
    param_free(&params);
    free(subtype);
    free(type);

    if (txn->error.precond) return HTTP_FORBIDDEN;

    return carddav_store_resource(txn, vcard, mailbox, resource, db);
}


/* Perform a bulk import */
static int carddav_import(struct transaction_t *txn, void *obj,
                          struct mailbox *mailbox, void *destdb,
                          xmlNodePtr root, xmlNsPtr *ns, unsigned flags)
{
    struct vparse_card *vcard = obj;
    xmlBufferPtr xmlbuf = NULL;
    size_t baselen;

    if (!root) {
        /* Validate the vCard data */
        if (!vcard ||
            !vcard->objects ||
            !vcard->objects->type ||
            strcasecmp(vcard->objects->type, "vcard")) {
            txn->error.precond = CARDDAV_VALID_DATA;
            return HTTP_FORBIDDEN;
        }

        return 0;
    }


    /* Setup for appending resource name to request path */
    baselen = strlen(txn->req_tgt.path);
    txn->req_tgt.resource = txn->req_tgt.path + baselen;

    /* Import vCards */
    while (vcard->objects) {
        struct vparse_card *this, *next;
        xmlNodePtr resp, node;
        struct vparse_entry *entry;
        const char *resource = makeuuid(), *uid, *myuid = NULL;
        int r;

        /* Create DAV:response element */
        resp = xmlNewChild(root, ns[NS_DAV], BAD_CAST "response", NULL);
        if (!resp) {
            syslog(LOG_ERR,
                   "import_resource()): Unable to add response XML element");
            fatal("import_resource()): Unable to add response XML element",
                  EX_SOFTWARE);
        }

        /* Isolate this card */
        this = vcard->objects;
        next = this->next;
        this->next = NULL;

        /* Get/create UID property */
        entry = vparse_get_entry(this, NULL, "UID");
        if (entry) {
            uid = entry->v.value;
        }
        else {
            myuid = uid = resource;
            vparse_add_entry(this, NULL, "UID", uid);
        }

        /* Append a unique resource name to URL and perform a PUT */
        txn->req_tgt.reslen =
            snprintf(txn->req_tgt.resource, MAX_MAILBOX_PATH - baselen,
                     "%s.vcf", resource);

        r = carddav_put(txn, vcard, mailbox,
                       txn->req_tgt.resource, destdb, flags);

        switch (r) {
        case HTTP_OK:
        case HTTP_CREATED:
        case HTTP_NO_CONTENT:
            /* Success: Add DAV:href and DAV:propstat elements */
            xml_add_href(resp, NULL, txn->req_tgt.path);

            node = xmlNewChild(resp, ns[NS_DAV], BAD_CAST "propstat", NULL);
            xmlNewChild(node, ns[NS_DAV], BAD_CAST "status",
                        BAD_CAST http_statusline(VER_1_1, HTTP_OK));

            node = xmlNewChild(node, ns[NS_DAV], BAD_CAST "prop", NULL);

            if (txn->resp_body.etag) {
                /* Add DAV:getetag property */
                xmlNewTextChild(node, ns[NS_DAV], BAD_CAST "getetag",
                                BAD_CAST txn->resp_body.etag);
            }

            if ((flags & PREFER_REP) && myuid /* we added a UID */) {
                /* Add CARDDAV:addressbook-data property */
                struct buf *vcardbuf = vcard_as_buf(this);
                xmlNodePtr cdata = xmlNewChild(node, ns[NS_CARDDAV],
                                               BAD_CAST "addressbook-data", NULL);

                xmlAddChild(cdata, xmlNewCDataBlock(root->doc,
                                                    BAD_CAST buf_cstring(vcardbuf),
                                                    buf_len(vcardbuf)));
                buf_free(vcardbuf);
            }

            break;

        default:
            /* Failure: Add DAV:href, DAV:status, and DAV:error elements */
            xml_add_href(resp, NULL, NULL);

            xmlNewChild(resp, ns[NS_DAV], BAD_CAST "status",
                        BAD_CAST http_statusline(VER_1_1, r));

            node = xml_add_error(resp, &txn->error, ns);
            break;
        }

        /* Add CS:uid property */
        xmlNewTextChild(node, ns[NS_CS], BAD_CAST "uid", BAD_CAST uid);

        /* Add DAV:response element for this resource to output buffer.
           Only output the xmlBuffer every PROT_BUFSIZE bytes */
        xml_partial_response((xmlBufferLength(xmlbuf) > PROT_BUFSIZE) ? txn : NULL,
                             root->doc, resp, 1, &xmlbuf);

        /* Remove DAV:response element from root (no need to keep in memory) */
        xmlReplaceNode(resp, NULL);
        xmlFreeNode(resp);

        /* Remove this vcard from the head of the list */
        vparse_free_card(this);
        vcard->objects = next;

        /* Clear the buffer used for constructing href */
        buf_reset(&txn->buf);
    }

    /* End XML response */
    xml_partial_response(txn, root->doc, NULL /* end */, 0, &xmlbuf);
    xmlBufferFree(xmlbuf);

    return 0;
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
    if (!propstat) {
        /* Prescreen "property" request */
        if (fctx->req_tgt->collection ||
            (fctx->req_tgt->userid && fctx->depth >= 1) || fctx->depth >= 2) {
            /* Add namespaces for possible resource types */
            ensure_ns(fctx->ns, NS_CARDDAV, fctx->root, XML_NS_CARDDAV, "C");
        }

        return 0;
    }

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
                             void *rock __attribute__((unused)))
{
    static struct mime_type_t *out_type = carddav_mime_types;
    static strarray_t partial_addrdata = STRARRAY_INITIALIZER;
    strarray_t *partial = &partial_addrdata;
    const char *data = NULL;
    size_t datalen = 0;

    if (!fctx) {
        /* Cleanup "property" request - free partial property array */
        strarray_fini(partial);

        return 0;
    }

    if (!propstat) {
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
        struct carddav_data *cdata = (struct carddav_data *) fctx->data;
        struct vparse_card *vcard = NULL;
        unsigned want_ver;

        if (fctx->txn->meth != METH_REPORT) return HTTP_FORBIDDEN;

        if (!out_type->content_type) return HTTP_BAD_MEDIATYPE;

        if (!fctx->record) return HTTP_NOT_FOUND;

        if (!fctx->msg_buf.len)
            mailbox_map_record(fctx->mailbox, fctx->record, &fctx->msg_buf);
        if (!fctx->msg_buf.len) return HTTP_SERVER_ERROR;

        data = buf_cstring(&fctx->msg_buf) + fctx->record->header_size;
        datalen = fctx->record->size - fctx->record->header_size;

        want_ver = (out_type->version[0] == '4') ? 4 : 3;

        if (cdata->version != want_ver) {
            /* Translate between vCard versions */
            vcard = fctx->obj;

            if (!vcard) vcard = fctx->obj = vcard_parse_string(data);

            if (want_ver == 4) vcard_to_v4(vcard);
            else vcard_to_v3(vcard);
        }

        if (strarray_size(partial)) {
            /* Limit returned properties */
            vcard = fctx->obj;

            if (!vcard) vcard = fctx->obj = vcard_parse_string(data);
            prune_properties(vcard->objects, partial);
        }

        if (vcard) {
            /* Create vCard data from new vCard component */
            buf_reset(&fctx->msg_buf);
            vparse_tobuf(vcard, &fctx->msg_buf);
            data = buf_cstring(&fctx->msg_buf);
            datalen = buf_len(&fctx->msg_buf);
        }
    }

    return propfind_getdata(name, ns, fctx, prop, propstat, carddav_mime_types,
                            &out_type, data, datalen);
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

/* Callback to fetch CARDDAV:max-resource-size */
static int propfind_maxsize(const xmlChar *name, xmlNsPtr ns,
                            struct propfind_ctx *fctx,
                            xmlNodePtr prop __attribute__((unused)),
                            xmlNodePtr resp __attribute__((unused)),
                            struct propstat propstat[],
                            void *rock __attribute__((unused)))
{
    if (!fctx->req_tgt->collection) return HTTP_NOT_FOUND;

    buf_reset(&fctx->buf);
    buf_printf(&fctx->buf, "%d", vcard_max_size);
    xml_add_prop(HTTP_OK, fctx->ns[NS_DAV], &propstat[PROPSTAT_OK],
                 name, ns, BAD_CAST buf_cstring(&fctx->buf), 0);

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

    r = carddav_lookup_resource(davdb, fctx->req_tgt->mbentry,
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
                    myprop.multivaluesep = ',';
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
                                       fctx->record->header_size);
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
            const char *text = prop->multivaluesep ?
                strarray_nth(prop->v.values, n) : prop->v.value;

            /* Test each value of this property (logical OR) */
            do {
                pass = dav_apply_textmatch(BAD_CAST text, match);

            } while (!pass && prop->multivaluesep &&
                     (text = strarray_nth(prop->v.values, ++n)));
        }

        /* Apply each param-filter, breaking if allof fails or anyof succeeds */
        for (paramfilter = propfilter->param;
             paramfilter && (pass == propfilter->allof);
             paramfilter = paramfilter->next) {

            pass = apply_paramfilter(paramfilter, prop);
        }

    } while (!pass && (prop = prop->next));  /* XXX  No API to fetch next prop */

    if (myprop.multivaluesep) strarray_free(myprop.v.values);

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

    /* Setup for chunked response */
    txn->flags.te |= TE_CHUNKED;

    /* Begin XML response */
    xml_response(HTTP_MULTI_STATUS, txn, fctx->root->doc);

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
    }

    /* End XML response */
    xml_partial_response(txn, fctx->root->doc, NULL /* end */, 0, &fctx->xmlbuf);
    xmlBufferFree(fctx->xmlbuf);

    /* End of output */
    write_body(0, txn, NULL, 0);

  done:
    /* Free filter structure */
    free_cardfilter(&cardfilter);

    if (fctx->davdb) {
        fctx->close_db(fctx->davdb);
        fctx->davdb = NULL;
    }

    return ret;
}
