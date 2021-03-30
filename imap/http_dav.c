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
/*
 * TODO:
 *
 *   - CALDAV:supported-calendar-component-set should be a bitmask in
 *     cyrus.index header Mailbox Options field
 *
 *   - CALDAV:schedule-calendar-transp should be a flag in
 *     cyrus.index header (Mailbox Options)
 *
 *   - DAV:creationdate should be added to cyrus.header since it only
 *     gets set at creation time
 *
 *   - Should add a last_metadata_update field to cyrus.index header
 *     for use in PROPFIND, PROPPATCH, and possibly REPORT.
 *     This would get updated any time a mailbox annotation, mailbox
 *     acl, or quota root limit is changed
 *
 *   - Should we use cyrus.index header Format field to indicate
 *     CalDAV mailbox?
 *
 */

#include <sysexits.h>

#include "annotate.h"
#include "acl.h"
#include "append.h"
#include "caldav_db.h"
#include "dlist.h"
#include "global.h"
#include "http_dav.h"
#include "http_dav_sharing.h"
#include "http_proxy.h"
#include "index.h"
#include "proxy.h"
#include "times.h"
#include "syslog.h"
#include "strhash.h"
#include "sync_support.h"
#include "tok.h"
#include "user.h"
#include "util.h"
#include "version.h"
#include "xmalloc.h"
#include "xml_support.h"
#include "xstrlcat.h"
#include "xstrlcpy.h"
#include "xstrnchr.h"

/* generated headers are not necessarily in current directory */
#include "imap/http_err.h"
#include "imap/imap_err.h"

#include <errno.h>
#include <libxml/uri.h>

static const struct dav_namespace_t {
    const char *href;
    const char *prefix;
} known_namespaces[] = {
    { XML_NS_DAV, "D" },
    { XML_NS_CALDAV, "C" },
    { XML_NS_CARDDAV, "C" },
    { XML_NS_ISCHED, NULL },
    { XML_NS_CS, "CS" },
    { XML_NS_MECOM, "MC" },
    { XML_NS_MOBME, "MM" },
    { XML_NS_CYRUS, "CY" },
    { XML_NS_USERFLAG, "UF" },
    { XML_NS_SYSFLAG, "SF" },
};

const struct match_type_t dav_match_types[] = {
    { "contains", MATCH_TYPE_CONTAINS },
    { "equals", MATCH_TYPE_EQUALS },
    { "starts-with", MATCH_TYPE_PREFIX },
    { "ends-with", MATCH_TYPE_SUFFIX },
    { NULL, 0 }
};

const struct collation_t dav_collations[] = {
    { "i;unicode-casemap", COLLATION_UNICODE },
    { "i;ascii-casemap", COLLATION_ASCII },
    { "i;octet", COLLATION_OCTET },
    { NULL, 0 }
};

static xmlChar *server_info = NULL;
static int server_info_size = 0;
static time_t server_info_lastmod = 0;
static struct buf server_info_token = BUF_INITIALIZER;
static struct buf server_info_link = BUF_INITIALIZER;

static void my_dav_init(struct buf *serverinfo);
static void my_dav_shutdown(void);

static int get_server_info(struct transaction_t *txn);

static unsigned long principal_allow_cb(struct request_target_t *tgt);
static int principal_parse_path(const char *path, struct request_target_t *tgt,
                                const char **resultstr);
static int propfind_principalname(const xmlChar *name, xmlNsPtr ns,
                                  struct propfind_ctx *fctx,
                                  xmlNodePtr prop, xmlNodePtr resp,
                                  struct propstat propstat[], void *rock);
static int proppatch_principalname(xmlNodePtr prop, unsigned set,
                                   struct proppatch_ctx *pctx,
                                   struct propstat propstat[],
                                   void *rock);
static int propfind_restype(const xmlChar *name, xmlNsPtr ns,
                            struct propfind_ctx *fctx,
                            xmlNodePtr prop, xmlNodePtr resp,
                            struct propstat propstat[], void *rock);
static int propfind_alturiset(const xmlChar *name, xmlNsPtr ns,
                              struct propfind_ctx *fctx,
                              xmlNodePtr prop, xmlNodePtr resp,
                              struct propstat propstat[], void *rock);

static int principal_search(const char *userid, void *rock);
static int report_prin_prop_search(struct transaction_t *txn,
                                   struct meth_params *rparams,
                                   xmlNodePtr inroot,
                                   struct propfind_ctx *fctx);
static int report_prin_search_prop_set(struct transaction_t *txn,
                                       struct meth_params *rparams,
                                       xmlNodePtr inroot,
                                       struct propfind_ctx *fctx);

static int allprop_cb(const char *mailbox __attribute__((unused)),
                      uint32_t uid __attribute__((unused)),
                      const char *entry,
                      const char *userid, const struct buf *attrib,
                      const struct annotate_metadata *mdata __attribute__((unused)),
                      void *rock);

/* Array of supported REPORTs */
static const struct report_type_t principal_reports[] = {

    /* WebDAV Versioning (RFC 3253) REPORTs */
    { "expand-property", NS_DAV, "multistatus", &report_expand_prop,
      DACL_READ, 0 },

    /* WebDAV ACL (RFC 3744) REPORTs */
    { "principal-property-search", NS_DAV, "multistatus",
      &report_prin_prop_search, 0, REPORT_ALLOW_PROPS | REPORT_DEPTH_ZERO },
    { "principal-search-property-set", NS_DAV, "principal-search-property-set",
      &report_prin_search_prop_set, 0, REPORT_DEPTH_ZERO },

    { NULL, 0, NULL, NULL, 0, 0 }
};

/* Array of known "live" properties */
static const struct prop_entry principal_props[] = {

    /* WebDAV (RFC 4918) properties */
    { "creationdate", NS_DAV,
      PROP_ALLPROP, NULL, NULL, NULL },
    { "displayname", NS_DAV,
      PROP_ALLPROP | PROP_COLLECTION,
      propfind_principalname, proppatch_principalname, NULL },
    { "getcontentlanguage", NS_DAV,
      PROP_ALLPROP, NULL, NULL, NULL },
    { "getcontentlength", NS_DAV,
      PROP_ALLPROP | PROP_COLLECTION,
      propfind_getlength, NULL, NULL },
    { "getcontenttype", NS_DAV,
      PROP_ALLPROP, NULL, NULL, NULL },
    { "getetag", NS_DAV,
      PROP_ALLPROP, NULL, NULL, NULL },
    { "getlastmodified", NS_DAV,
      PROP_ALLPROP, NULL, NULL, NULL },
    { "lockdiscovery", NS_DAV,
      PROP_ALLPROP | PROP_COLLECTION,
      propfind_lockdisc, NULL, NULL },
    { "resourcetype", NS_DAV,
      PROP_ALLPROP | PROP_COLLECTION,
      propfind_restype, NULL, NULL },
    { "supportedlock", NS_DAV,
      PROP_ALLPROP | PROP_COLLECTION,
      propfind_suplock, NULL, NULL },

    /* WebDAV Versioning (RFC 3253) properties */
    { "supported-report-set", NS_DAV,
      PROP_COLLECTION,
      propfind_reportset, NULL, (void *) principal_reports },
    { "supported-method-set", NS_DAV,
      PROP_COLLECTION,
      propfind_methodset, NULL, (void *) &principal_allow_cb },

    /* WebDAV ACL (RFC 3744) properties */
    { "alternate-URI-set", NS_DAV,
      PROP_COLLECTION,
      propfind_alturiset, NULL, NULL },
    { "principal-URL", NS_DAV,
      PROP_COLLECTION,
      propfind_principalurl, NULL, NULL },
    { "group-member-set", NS_DAV,
      PROP_COLLECTION,
      NULL, NULL, NULL },
    { "group-membership", NS_DAV,
      PROP_COLLECTION,
      NULL, NULL, NULL },
    { "principal-collection-set", NS_DAV,
      PROP_COLLECTION,
      propfind_princolset, NULL, NULL },

    /* WebDAV Current Principal (RFC 5397) properties */
    { "current-user-principal", NS_DAV,
      PROP_COLLECTION,
      propfind_curprin, NULL, NULL },

    /* CalDAV (RFC 4791) properties */
    { "calendar-home-set", NS_CALDAV,
      PROP_COLLECTION,
      propfind_calurl, NULL, NULL },

    /* CalDAV Scheduling (RFC 6638) properties */
    { "schedule-inbox-URL", NS_CALDAV,
      PROP_COLLECTION,
      propfind_calurl, NULL, SCHED_INBOX },
    { "schedule-outbox-URL", NS_CALDAV,
      PROP_COLLECTION,
      propfind_calurl, NULL, SCHED_OUTBOX },
    { "calendar-user-address-set", NS_CALDAV,
      PROP_COLLECTION,
      propfind_caluseraddr, proppatch_caluseraddr, NULL },
    { "calendar-user-type", NS_CALDAV,
      PROP_COLLECTION,
      propfind_calusertype, NULL, NULL },

    /* CardDAV (RFC 6352) properties */
    { "addressbook-home-set", NS_CARDDAV,
      PROP_COLLECTION,
      propfind_abookhome, NULL, NULL },

    /* WebDAV Notifications (draft-pot-webdav-notifications) properties */
    { "notification-URL", NS_DAV,
      PROP_COLLECTION,
      propfind_notifyurl, NULL, NULL },

    /* Backwards compatibility with Apple notifications clients */
    { "notification-URL", NS_CS,
      PROP_COLLECTION,
      propfind_notifyurl, NULL, NULL },
    { "email-address-set", NS_CS,
      PROP_COLLECTION,
      propfind_caluseremail, NULL, NULL },

    { NULL, 0, 0, NULL, NULL, NULL }
};


struct meth_params princ_params = {
    .parse_path = &principal_parse_path,
    .propfind = { 0, principal_props },
    .reports = principal_reports
};

/* Namespace for WebDAV principals */
struct namespace_t namespace_principal = {
    URL_NS_PRINCIPAL, 0, "principal", "/dav/principals", NULL,
    http_allow_noauth_get, /*authschemes*/0,
    /*mbtype */ 0,
    ALLOW_READ | ALLOW_DAV | ALLOW_PROPPATCH,
    &my_dav_init, NULL, NULL, &my_dav_shutdown, &dav_premethod,
    /*bearer*/NULL,
    {
        { NULL,                 NULL },                 /* ACL          */
        { NULL,                 NULL },                 /* BIND         */
        { NULL,                 NULL },                 /* CONNECT      */
        { NULL,                 NULL },                 /* COPY         */
        { NULL,                 NULL },                 /* DELETE       */
        { &meth_get_head,       &princ_params },        /* GET          */
        { &meth_get_head,       &princ_params },        /* HEAD         */
        { NULL,                 NULL },                 /* LOCK         */
        { NULL,                 NULL },                 /* MKCALENDAR   */
        { NULL,                 NULL },                 /* MKCOL        */
        { NULL,                 NULL },                 /* MOVE         */
        { &meth_options,        NULL },                 /* OPTIONS      */
        { NULL,                 NULL },                 /* PATCH        */
        { NULL,                 NULL },                 /* POST         */
        { &meth_propfind,       &princ_params },        /* PROPFIND     */
        { &meth_proppatch,      &princ_params },        /* PROPPATCH    */
        { NULL,                 NULL },                 /* PUT          */
        { &meth_report,         &princ_params },        /* REPORT       */
        { &meth_trace,          NULL },                 /* TRACE        */
        { NULL,                 NULL },                 /* UNBIND       */
        { NULL,                 NULL }                  /* UNLOCK       */
    }
};


/* Linked-list of properties for fetching */
struct propfind_entry_list {
    xmlChar *name;                      /* Property name (needs to be freed) */
    xmlNsPtr ns;                        /* Property namespace */
    unsigned char flags;                /* Flags for how/where prop apply */
    int (*get)(const xmlChar *name,     /* Callback to fetch property */
               xmlNsPtr ns, struct propfind_ctx *fctx, xmlNodePtr prop,
               xmlNodePtr resp, struct propstat propstat[], void *rock);
    xmlNodePtr prop;                    /* Property node from request */
    void *rock;                         /* Add'l data to pass to callback */
    struct propfind_entry_list *next;
};


/* Bitmask of privilege flags */
enum {
    PRIV_IMPLICIT =             (1<<0),
    PRIV_INBOX =                (1<<1),
    PRIV_OUTBOX =               (1<<2),
    PRIV_CONTAINED =            (1<<3)
};


/* Array of precondition/postcondition errors */
static const struct precond_t {
    const char *name;                   /* Property name */
    unsigned ns;                        /* Index into known namespace array */
} preconds[] = {
    /* Placeholder for zero (no) precondition code */
    { NULL, 0 },

    /* WebDAV (RFC 4918) preconditions */
    { "cannot-modify-protected-property", NS_DAV },
    { "lock-token-matches-request-uri", NS_DAV },
    { "lock-token-submitted", NS_DAV },
    { "no-conflicting-lock", NS_DAV },
    { "propfind-finite-depth", NS_DAV },

    /* WebDAV Versioning (RFC 3253) preconditions */
    { "supported-report", NS_DAV },
    { "resource-must-be-null", NS_DAV },

    /* WebDAV ACL (RFC 3744) preconditions */
    { "need-privileges", NS_DAV },
    { "no-invert", NS_DAV },
    { "no-abstract", NS_DAV },
    { "not-supported-privilege", NS_DAV },
    { "recognized-principal", NS_DAV },
    { "allowed-principal", NS_DAV },
    { "grant-only", NS_DAV },

    /* WebDAV Quota (RFC 4331) preconditions */
    { "quota-not-exceeded", NS_DAV },
    { "sufficient-disk-space", NS_DAV },

    /* WebDAV Extended MKCOL (RFC 5689) preconditions */
    { "valid-resourcetype", NS_DAV },

    /* WebDAV Sync (RFC 6578) preconditions */
    { "valid-sync-token", NS_DAV },
    { "number-of-matches-within-limits", NS_DAV },

    /* CalDAV (RFC 4791) preconditions */
    { "supported-calendar-data", NS_CALDAV },
    { "valid-calendar-data", NS_CALDAV },
    { "valid-calendar-object-resource", NS_CALDAV },
    { "supported-calendar-component", NS_CALDAV },
    { "calendar-collection-location-ok", NS_CALDAV },
    { "no-uid-conflict", NS_CALDAV },
    { "supported-filter", NS_CALDAV },
    { "valid-filter", NS_CALDAV },
    { "supported-collation", NS_CALDAV },

    /* RSCALE (RFC 7529) preconditions */
    { "supported-rscale", NS_CALDAV },

    /* Time Zones by Reference (RFC 7809) preconditions */
    { "valid-timezone", NS_CALDAV },

    /* Managed Attachments (draft-ietf-calext-caldav-attachments) preconditions */
    { "valid-managed-id", NS_CALDAV },

    /* Bulk Change (draft-daboo-calendarserver-bulk-change) preconditions */
    { "ctag-ok", NS_MECOM },

    /* CalDAV Scheduling (RFC 6638) preconditions */
    { "valid-scheduling-message", NS_CALDAV },
    { "valid-organizer", NS_CALDAV },
    { "unique-scheduling-object-resource", NS_CALDAV },
    { "same-organizer-in-all-components", NS_CALDAV },
    { "allowed-organizer-scheduling-object-change", NS_CALDAV },
    { "allowed-attendee-scheduling-object-change", NS_CALDAV },
    { "default-calendar-needed", NS_CALDAV },
    { "valid-schedule-default-calendar-URL", NS_CALDAV },

    /* iSchedule (draft-desruisseaux-ischedule) preconditions */
    { "version-not-supported", NS_ISCHED },
    { "invalid-calendar-data-type", NS_ISCHED },
    { "invalid-calendar-data", NS_ISCHED },
    { "invalid-scheduling-message", NS_ISCHED },
    { "originator-missing", NS_ISCHED },
    { "too-many-originators", NS_ISCHED },
    { "originator-invalid", NS_ISCHED },
    { "originator-denied", NS_ISCHED },
    { "recipient-missing", NS_ISCHED },
    { "recipient-mismatch", NS_ISCHED },
    { "verification-failed", NS_ISCHED },

    /* CardDAV (RFC 6352) preconditions */
    { "supported-address-data", NS_CARDDAV },
    { "valid-address-data", NS_CARDDAV },
    { "no-uid-conflict", NS_CARDDAV },
    { "addressbook-collection-location-ok", NS_CARDDAV },
    { "supported-filter", NS_CARDDAV },
    { "supported-collation", NS_CARDDAV }
};


/* Check ACL on userid's principal (Inbox): ACL_LOOKUP right gives access */
static int principal_acl_check(const char *userid, struct auth_state *authstate)
{
    int r = 0;

    if (!httpd_userisadmin) {
        char *mboxname = caldav_mboxname(userid, NULL);
        mbentry_t *mbentry = NULL;

        r = proxy_mlookup(mboxname, &mbentry, NULL, NULL);
        if (r) {
            syslog(LOG_ERR, "mlookup(%s) failed: %s",
                   mboxname, error_message(r));
            r = HTTP_NOT_FOUND;
        }
        else if (!(httpd_myrights(authstate, mbentry) & ACL_LOOKUP)) {
            // allow READ (for owner) or USER6 (to grant access generally without anything else)
            r = HTTP_NOT_FOUND;
        }

        mboxlist_entry_free(&mbentry);
        free(mboxname);
    }

    return r;
}


/* Determine allowed methods in DAV principals namespace */
static unsigned long principal_allow_cb(struct request_target_t *tgt)
{
    return tgt->namespace->allow;
}


/* Parse request-target path in DAV principals namespace */
static int principal_parse_path(const char *path, struct request_target_t *tgt,
                                const char **resultstr)
{
    char *p;
    size_t len;

    /* Make a working copy of target path */
    strlcpy(tgt->path, path, sizeof(tgt->path));
    tgt->tail = tgt->path + strlen(tgt->path);

    p = tgt->path;

    /* Sanity check namespace */
    len = strlen(namespace_principal.prefix);
    if (strlen(p) < len ||
        strncmp(namespace_principal.prefix, p, len) ||
        (path[len] && path[len] != '/')) {
        *resultstr = "Namespace mismatch request target path";
        return HTTP_FORBIDDEN;
    }

    /* Skip past namespace (and any extra '/') */
    for (p += len; p[1] == '/'; p++);
    if (!*p || !*++p) {
        /* Make sure collection is terminated with '/' */
        if (p[-1] != '/') *p++ = '/';
        return 0;
    }

    /* Check if we're in user space */
    len = strcspn(p, "/");
    if (!strncmp(p, USER_COLLECTION_PREFIX, len)) {
        /* Skip past user prefix (and any extra '/') */
        for (p += len; p[1] == '/'; p++);
        if (!*p || !*++p) {
            /* Make sure collection is terminated with '/' */
            if (p[-1] != '/') *p++ = '/';
            return 0;
        }

        /* Get user id */
        len = strcspn(p, "/");
        tgt->userid = xstrndup(p, len);

        if (httpd_extradomain) {
            char *at = strchr(tgt->userid, '@');
            if (at && !strcmp(at+1, httpd_extradomain))
                *at = 0;
        }

        /* Skip past userid (and any extra '/') */
        for (p += len; p[1] == '/'; p++);
        if (!*p || !*++p) goto mailbox;
    }
    else if (!strncmp(p, SERVER_INFO, len)) {
        p += len;
        if (!*p || !*++p) {
            tgt->flags = TGT_SERVER_INFO;
            return 0;
        }
    }
    else return HTTP_NOT_FOUND;  /* need to specify a userid */

    if (*p) {
//      *resultstr = "Too many segments in request target path";
        return HTTP_NOT_FOUND;
    }

  mailbox:
    /* Create mailbox name from the parsed path */

    if (tgt->userid) {
        /* Locate the mailbox */
        char *mboxname = caldav_mboxname(tgt->userid, NULL);
        int r = proxy_mlookup(mboxname, &tgt->mbentry, NULL, NULL);

        if (r) {
            *resultstr = error_message(r);
            syslog(LOG_ERR, "mlookup(%s) failed: %s", mboxname, *resultstr);
        }
        free(mboxname);

        switch (r) {
        case 0:
            break;

        case IMAP_PERMISSION_DENIED:
            return HTTP_FORBIDDEN;

        case IMAP_MAILBOX_NONEXISTENT:
            return HTTP_NOT_FOUND;

        default:
            return HTTP_SERVER_ERROR;
        }
    }

    return 0;
}


/* Determine allowed methods in Cal/CardDAV namespace */
HIDDEN unsigned long calcarddav_allow_cb(struct request_target_t *tgt)
{
    unsigned long allow = tgt->namespace->allow;

    if (!tgt->userid) {
        allow &= ALLOW_READ_MASK;
    }
    else if (!tgt->collection) {
        allow &= ~(ALLOW_DELETE | ALLOW_PATCH | ALLOW_POST | ALLOW_WRITE);
    }
    else if (!tgt->resource) {
        allow &= ~(ALLOW_MKCOL | ALLOW_PATCH);
    }
    else {
        allow &= ~(ALLOW_MKCOL | ALLOW_POST);
    }

    return allow;
}


/* Parse request-target path in *DAV namespace */
EXPORTED int dav_parse_req_target(struct transaction_t *txn,
                                  struct meth_params *params)
{
    const char *resultstr = NULL;
    int r;

    r = params->parse_path(txn->req_uri->path, &txn->req_tgt, &resultstr);
    if (r) {
        if (r == HTTP_MOVED) txn->location = resultstr;
        else txn->error.desc = resultstr;
    }

    return r;
}


/* Parse a path in Cal/CardDAV namespace */
HIDDEN int calcarddav_parse_path(const char *path,
                                   struct request_target_t *tgt,
                                   const char *mboxprefix,
                                   const char **resultstr)
{
    char *p, *owner = NULL, *collection = NULL, *freeme = NULL;
    size_t len;
    const char *mboxname;
    mbname_t *mbname = NULL;
    int ret = 0;
    static struct buf redirect_buf = BUF_INITIALIZER;

    if (*tgt->path) return 0;  /* Already parsed */

    /* Make a working copy of target path */
    strlcpy(tgt->path, path, sizeof(tgt->path));
    tgt->tail = tgt->path + strlen(tgt->path);

    p = tgt->path;

    /* Sanity check namespace */
    len = strlen(tgt->namespace->prefix);
    if (strlen(p) < len ||
        strncmp(tgt->namespace->prefix, p, len) || (path[len] && path[len] != '/')) {
        *resultstr = "Namespace mismatch request target path";
        return HTTP_FORBIDDEN;
    }

    tgt->mboxprefix = mboxprefix;

    /* Default to bare-bones Allow bits */
    tgt->allow &= ALLOW_READ_MASK;

    /* Skip past namespace (and any extra '/') */
    for (p += len; p[1] == '/'; p++);
    if (!*p || !*++p) return 0;

    /* Check if we're in user space */
    len = strcspn(p, "/");
    /* zzzz is part of the FastMail sorting hack to make shared collections
     * always appear later */
    if (!strncmp(p, USER_COLLECTION_PREFIX, len) || !strncmp(p, "zzzz", len)) {
        if (!strncmp(p, "zzzz", len))
            tgt->flags |= TGT_USER_ZZZZ;

        /* Skip past user prefix (and any extra '/') */
        for (p += len; p[1] == '/'; p++);
        if (!*p || !*++p) return 0;

        /* Get user id */
        len = strcspn(p, "/");
        tgt->userid = xstrndup(p, len);

        /* Skip past userid (and any extra '/') */
        for (p += len; p[1] == '/'; p++);
        if (!*p || !*++p) {
            /* Make sure home-set is terminated with '/' */
            if (p[-1] != '/') *p++ = '/';
            goto mailbox;
        }

        len = strcspn(p, "/");
    }

    /* Get collection */
    tgt->collection = p;
    tgt->collen = len;

    /* Skip past collection (and any extra '/') */
    for (p += len; p[1] == '/'; p++);
    if (!*p || !*++p) {
        /* Make sure collection is terminated with '/' */
        if (p[-1] != '/') *p++ = '/';
        goto mailbox;
    }

    /* Get resource */
    len = strcspn(p, "/");
    tgt->resource = p;
    tgt->reslen = len;

    p += len;

    if (*p) {
//      *resultstr = "Too many segments in request target path";
        return HTTP_NOT_FOUND;
    }

  mailbox:
    /* Create mailbox name from the parsed path */

    owner = tgt->userid;
    if (tgt->collen) {
        collection = freeme = xstrndup(tgt->collection, tgt->collen);

        p = strrchr(collection, SHARED_COLLECTION_DELIM);
        if (p) {
            if (tgt->mbentry) { /* MKCOL or COPY/MOVE destination */
                *resultstr = "Invalid characters in collection name";
                ret = HTTP_FORBIDDEN;
                goto done;
            }
            else {
                /* Shared collection encoded as: <owner> "." <mboxname> */
                owner = collection;
                *p++ = '\0';
                collection = p;

                tgt->flags = TGT_DAV_SHARED;
                tgt->allow |= ALLOW_DELETE;
            }
        }
    }

    mbname = mbname_from_userid(owner);

    mbname_push_boxes(mbname, mboxprefix);
    if (collection) {
        mbname_push_boxes(mbname, collection);
    }

    /* XXX - hack to allow @domain parts for non-domain-split users */
    if (httpd_extradomain) {
        /* not allowed to be cross domain */
        if (mbname_localpart(mbname) &&
            strcmpsafe(mbname_domain(mbname), httpd_extradomain)) {
            ret = HTTP_NOT_FOUND;
            goto done;
        }
        mbname_set_domain(mbname, NULL);
    }

    mboxname = mbname_intname(mbname);

    /* Check for FastMail legacy sharing URLs and redirect */
    if (httpd_userid && !config_getswitch(IMAPOPT_FASTMAILSHARING) &&
        tgt->flags != TGT_DAV_SHARED &&
        !mboxname_userownsmailbox(httpd_userid, mboxname)) {
        buf_reset(&redirect_buf);
        buf_printf(&redirect_buf, "%s/%s/%s/%s%c%s",
                 tgt->namespace->prefix, USER_COLLECTION_PREFIX,
                 httpd_userid, tgt->userid, SHARED_COLLECTION_DELIM,
                 tgt->collection);
        *resultstr = buf_cstring(&redirect_buf);

        ret = HTTP_MOVED;
        goto done;
    }

    if (tgt->mbentry) {
        /* Just return the mboxname (MKCOL or COPY/MOVE destination) */
        tgt->mbentry->name = xstrdup(mboxname);

        ret = mboxlist_createmailboxcheck(mboxname, 0, NULL, httpd_userisadmin,
                                          httpd_userid, httpd_authstate,
                                          NULL, NULL, 0 /* force */);
        if (ret) {
            if (ret == IMAP_MAILBOX_BADNAME)
                *resultstr = "Invalid name.  Percent encoded HTTP URLs are in theory valid, but in practice not supported.";
            goto done;
	}

        tgt->allow |= ALLOW_MKCOL;
    }
    else if (*mboxname) {
        /* Locate the mailbox */
        int r = proxy_mlookup(mboxname, &tgt->mbentry, NULL, NULL);

        if (r) {
            *resultstr = error_message(r);
            syslog(LOG_ERR, "mlookup(%s) failed: %s", mboxname, *resultstr);

            switch (r) {
            case IMAP_PERMISSION_DENIED:
                ret = HTTP_FORBIDDEN;
                break;

            case IMAP_MAILBOX_NONEXISTENT:
                ret = HTTP_NOT_FOUND;
                break;

            default:
                ret = HTTP_SERVER_ERROR;
                break;
            }

            goto done;
        }
    }

    /* Set generic Allow bits based on path components */
    tgt->allow |= ALLOW_ACL | ALLOW_PROPPATCH;

    if (tgt->collection) {
        tgt->allow |= ALLOW_WRITE | ALLOW_DELETE;

        if (!tgt->resource) tgt->allow |= ALLOW_POST;
    }
    else if (tgt->userid) tgt->allow |= ALLOW_MKCOL;

  done:
    mbname_free(&mbname);
    free(freeme);

    return ret;
}


EXPORTED int dav_get_validators(struct mailbox *mailbox, void *data,
                                const char *userid __attribute__((unused)),
                                struct index_record *record,
                                const char **etag, time_t *lastmod)
{
    const struct dav_data *ddata = (const struct dav_data *) data;

    memset(record, 0, sizeof(struct index_record));

    if (!ddata->alive) {
        /* New resource */
        if (etag) *etag = NULL;
        if (lastmod) *lastmod = 0;
    }
    else if (ddata->imap_uid) {
        /* Mapped URL */
        int r;

        /* Fetch index record for the resource */
        r = mailbox_find_index_record(mailbox, ddata->imap_uid, record);
        if (r) {
            syslog(LOG_ERR, "mailbox_find_index_record(%s, %u) failed: %s",
                   mailbox->name, ddata->imap_uid, error_message(r));
            return r;
        }

        if (etag) *etag = message_guid_encode(&record->guid);
        if (lastmod) *lastmod = record->internaldate;
    }
    else {
        /* Unmapped URL (empty resource) */
        if (etag) *etag = NULL;
        if (lastmod) *lastmod = ddata->creationdate;
    }

    return 0;
}


EXPORTED modseq_t dav_get_modseq(struct mailbox *mailbox __attribute__((unused)),
                                 void *data,
                                 const char *userid __attribute__((unused)))
{
    return ((struct dav_data *) data)->modseq;
}


/* Evaluate If header.  Note that we can't short-circuit any of the tests
   because we need to check for a lock-token anywhere in the header */
static int eval_list(char *list, struct mailbox *mailbox, const char *etag,
                     const char *lock_token, unsigned *locked)
{
    unsigned ret = 1;
    tok_t tok;
    char *cond;

    /* Process each condition, ANDing the results */
    tok_initm(&tok, list+1, "]>", TOK_TRIMLEFT|TOK_TRIMRIGHT);
    while ((cond = tok_next(&tok))) {
        unsigned r = 0, not = 0;

        if (!strncmp(cond, "Not", 3)) {
            not = 1;
            cond += 3;
            while (*cond == ' ') cond++;
        }
        if (*cond++ == '[') {
            /* ETag */
            r = !etagcmp(cond, etag);
        }
        else {
            /* State Token */
            r = !strcmpnull(cond, lock_token);
            if (r) {
                /* Correct lock-token has been provided */
                (*locked)--;
            }
            else if (mailbox) {
                struct buf buf = BUF_INITIALIZER;

                dav_get_synctoken(mailbox, &buf, SYNC_TOKEN_URL_SCHEME);
                r = !strcmp(cond, buf_cstring(&buf));
                if (!r) {
                    dav_get_synctoken(mailbox, &buf, XML_NS_MECOM "ctag/");
                    r = !strcmp(cond, buf_cstring(&buf));
                }
                buf_free(&buf);
            }
        }

        ret &= (not ? !r : r);
    }

    tok_fini(&tok);

    return ret;
}

static int eval_if(const char *hdr, struct meth_params *params,
                   const struct namespace_t *namespace,
                   struct mailbox *tgt_mailbox, const char *tgt_resource,
                   const char *tgt_etag, const char *tgt_lock_token,
                   unsigned *locked)
{
    unsigned ret = 0;
    tok_t tok;
    char *list;

    /* Process each list, ORing the results */
    tok_init(&tok, hdr, ")", TOK_TRIMLEFT|TOK_TRIMRIGHT);
    while ((list = tok_next(&tok))) {
        struct mailbox *mailbox, *my_mailbox = NULL;
        const char *etag, *lock_token;
        struct buf buf = BUF_INITIALIZER;
        struct index_record record;
        struct dav_data *ddata;
        void *davdb = NULL;

        if (*list == '<') {
            /* Tagged-list */
            const char *tag, *err;
            xmlURIPtr uri;

            tag = ++list;
            list = strchr(tag, '>');
            *list++ = '\0';

            mailbox = NULL;
            etag = lock_token = NULL;

            /* Parse the URL and assign mailbox, etag, and lock_token */
            if (params && (uri = parse_uri(METH_UNKNOWN, tag, 1, &err))) {
                struct request_target_t tag_tgt;
                int r;

                memset(&tag_tgt, 0, sizeof(struct request_target_t));
                tag_tgt.namespace = namespace;

                if (!params->parse_path(uri->path, &tag_tgt, &err)) {
                    if (tag_tgt.mbentry && !tag_tgt.mbentry->server) {
                        if (tgt_mailbox &&
                            !strcmp(tgt_mailbox->name, tag_tgt.mbentry->name)) {
                            /* Use target mailbox */
                            mailbox = tgt_mailbox;
                        }
                        else {
                            /* Open new mailbox */
                            r = mailbox_open_irl(tag_tgt.mbentry->name,
                                                 &my_mailbox);
                            if (r) {
                                syslog(LOG_NOTICE,
                                       "failed to open mailbox '%s'"
                                       " in tagged If header: %s",
                                       tag_tgt.mbentry->name, error_message(r));
                            }
                            mailbox = my_mailbox;
                        }
                        if (mailbox) {
                            if (!strcmpnull(tgt_resource, tag_tgt.resource)) {
                                /* Tag IS target resource */
                                etag = tgt_etag;
                                lock_token = tgt_lock_token;
                            }
                            else if (tag_tgt.resource) {
                                /* Open DAV DB corresponding to the mailbox */
                                davdb = params->davdb.open_db(mailbox);

                                /* Find message UID for the resource */
                                params->davdb.lookup_resource(davdb,
                                                              mailbox->name,
                                                              tag_tgt.resource,
                                                              (void **) &ddata,
                                                              0);
                                if (ddata->rowid) {
                                    if (ddata->lock_expire > time(NULL)) {
                                        lock_token = ddata->lock_token;
                                        (*locked)++;
                                    }

                                    memset(&record, 0,
                                           sizeof(struct index_record));
                                    if (ddata->imap_uid) {
                                        /* Mapped URL - Fetch index record */
                                        r = mailbox_find_index_record(mailbox,
                                                                      ddata->imap_uid,
                                                                      &record);
                                        if (r) {
                                            syslog(LOG_NOTICE,
                                                   "failed to fetch record for"
                                                   " '%s':%u in tagged"
                                                   " If header: %s",
                                                   mailbox->name,
                                                   ddata->imap_uid,
                                                   error_message(r));
                                        }
                                        else {
                                            etag =
                                                message_guid_encode(&record.guid);
                                        }
                                    }
                                    else {
                                        /* Unmapped URL (empty resource) */
                                        etag = NULL;
                                    }
                                }
                            }
                            else {
                                /* Collection */
                                buf_printf(&buf, "%u-%u-%u",
                                           mailbox->i.uidvalidity,
                                           mailbox->i.last_uid,
                                           mailbox->i.exists);
                                etag = buf_cstring(&buf);
                            }
                        }
                    }

                    mboxlist_entry_free(&tag_tgt.mbentry);
                    free(tag_tgt.userid);
                }

                xmlFreeURI(uri);
            }
        }
        else {
            /* No-tag-list */
            mailbox = tgt_mailbox;
            etag = tgt_etag;
            lock_token = tgt_lock_token;
        }

        list = strchr(list, '(');

        ret |= eval_list(list, mailbox, etag, lock_token, locked);

        if (davdb) params->davdb.close_db(davdb);
        mailbox_close(&my_mailbox);
        buf_free(&buf);
    }

    tok_fini(&tok);

    return (ret || *locked);
}


/* Check headers for any preconditions */
EXPORTED int dav_check_precond(struct transaction_t *txn,
                               struct meth_params *params,
                               struct mailbox *mailbox, const void *data,
                               const char *etag, time_t lastmod)
{
    const struct dav_data *ddata = (const struct dav_data *) data;
    hdrcache_t hdrcache = txn->req_hdrs;
    const char **hdr;
    const char *lock_token = NULL;
    unsigned locked = 0;

    /* Check for a write-lock on the source */
    if (ddata && ddata->lock_expire > time(NULL)) {
        lock_token = ddata->lock_token;

        switch (txn->meth) {
        case METH_DELETE:
        case METH_LOCK:
        case METH_MOVE:
        case METH_PATCH:
        case METH_POST:
        case METH_PUT:
            /* State-changing method: Only the lock owner can execute
               and MUST provide the correct lock-token in an If header */
            if (strcmp(ddata->lock_ownerid, httpd_userid)) return HTTP_LOCKED;

            locked = 1;
            break;

        case METH_UNLOCK:
            /* State-changing method: Authorized in meth_unlock() */
            break;

        case METH_ACL:
        case METH_MKCALENDAR:
        case METH_MKCOL:
        case METH_PROPPATCH:
            /* State-changing method: Locks on collections unsupported */
            break;

        default:
            /* Non-state-changing method: Always allowed */
            break;
        }
    }

    /* Per RFC 4918, If is similar to If-Match, but with lock-token submission.
       Per RFC 7232, LOCK errors supercede preconditions */
    if ((hdr = spool_getheader(hdrcache, "If"))) {
        /* State tokens (sync-token, lock-token) and Etags */
        if (!eval_if(hdr[0], params, txn->req_tgt.namespace,
                     mailbox, txn->req_tgt.resource,
                     etag, lock_token, &locked))
            return HTTP_PRECOND_FAILED;
    }

    if (locked) {
        /* Correct lock-token was not provided in If header */
        return HTTP_LOCKED;
    }


    /* Do normal HTTP checks */
    return check_precond(txn, etag, lastmod);
}


EXPORTED int dav_premethod(struct transaction_t *txn)
{
    if (buf_len(&server_info_link)) {
        /* Check for Server-Info-Token header */
        const char **hdr = spool_getheader(txn->req_hdrs, "Server-Info-Token");

        if ((hdr && strcmp(hdr[0], buf_cstring(&server_info_token))) ||
            (!hdr && txn->meth == METH_OPTIONS)) {
            strarray_append(&txn->resp_body.links,
                            buf_cstring(&server_info_link));
        }
    }

    return 0;
}


EXPORTED unsigned get_preferences(struct transaction_t *txn)
{
    unsigned mask = 0, prefs = 0;
    const char **hdr;

    /* Create a mask for preferences honored by method */
    switch (txn->meth) {
    case METH_COPY:
    case METH_MOVE:
    case METH_PATCH:
    case METH_POST:
    case METH_PUT:
        mask = PREFER_REP;
        break;

    case METH_GET:
    case METH_MKCALENDAR:
    case METH_MKCOL:
    case METH_PROPPATCH:
        mask = PREFER_MIN;
        break;

    case METH_PROPFIND:
    case METH_REPORT:
        mask = (PREFER_MIN | PREFER_NOROOT);
        break;
    }

    if (!mask) return 0;
    else {
        txn->flags.vary |= VARY_PREFER;
        if (mask & PREFER_MIN) txn->flags.vary |= VARY_BRIEF;
    }

    /* Check for Prefer header(s) */
    if ((hdr = spool_getheader(txn->req_hdrs, "Prefer"))) {
        int i;
        for (i = 0; hdr[i]; i++) {
            tok_t tok;
            char *token;

            tok_init(&tok, hdr[i], ",\r\n", TOK_TRIMLEFT|TOK_TRIMRIGHT);
            while ((token = tok_next(&tok))) {
                if ((mask & PREFER_MIN) &&
                    !strcmp(token, "return=minimal"))
                    prefs |= PREFER_MIN;
                else if ((mask & PREFER_REP) &&
                         !strcmp(token, "return=representation"))
                    prefs |= PREFER_REP;
                else if ((mask & PREFER_NOROOT) &&
                         !strcmp(token, "depth-noroot"))
                    prefs |= PREFER_NOROOT;
            }
            tok_fini(&tok);
        }

        txn->resp_body.prefs = prefs;
    }

    /* Check for Brief header */
    if ((mask & PREFER_MIN) &&
        (hdr = spool_getheader(txn->req_hdrs, "Brief")) &&
        !strcasecmp(hdr[0], "t")) {
        prefs |= PREFER_MIN;
    }

    /* Check for X-MobileMe-DAV-Options header */
    if ((mask & PREFER_REP) &&
        (hdr = spool_getheader(txn->req_hdrs, "X-MobileMe-DAV-Options")) &&
        !strcasecmp(hdr[0], "return-changed-data")) {
        prefs |= PREFER_REP;
    }

    return prefs;
}


/* Check requested MIME type */
struct mime_type_t *get_accept_type(const char **hdr, struct mime_type_t *types)
{
    struct mime_type_t *ret = NULL;
    struct accept *e, *enc = parse_accept(hdr);

    for (e = enc; e && e->token; e++) {
        if (!ret && e->qual > 0.0) {
            struct mime_type_t *m;

            for (m = types; !ret && m->content_type; m++) {
                if (is_mediatype(e->token, m->content_type)) ret = m;
            }
        }

        free(e->token);
    }
    if (enc) free(enc);

    return ret;
}


static void add_privs(int rights, unsigned flags,
                      xmlNodePtr parent, xmlNodePtr root, xmlNsPtr *ns);


/* Ensure that we have a given namespace.  If it doesn't exist in what we
 * parsed in the request, create it and attach to 'node'.
 */
int ensure_ns(xmlNsPtr *respNs, int ns, xmlNodePtr node,
              const char *url, const char *prefix)
{
    if (!respNs[ns]) {
        xmlNsPtr nsDef;
        char myprefix[20];

        /* Search for existing namespace using our prefix */
        for (nsDef = node->nsDef; nsDef; nsDef = nsDef->next) {
            if ((!nsDef->prefix && !prefix) ||
                (nsDef->prefix && prefix &&
                 !strcmp((const char *) nsDef->prefix, prefix))) break;
        }

        if (nsDef) {
            /* Prefix is already used - generate a new one */
            snprintf(myprefix, sizeof(myprefix), "X%X", strhash(url) & 0xffff);
            prefix = myprefix;
        }

        respNs[ns] = xmlNewNs(node, BAD_CAST url, BAD_CAST prefix);
    }

    /* XXX  check for errors */
    return 0;
}


/* Add namespaces declared in the request to our root node and Ns array */
static int xml_add_ns(xmlNodePtr req, xmlNsPtr *respNs, xmlNodePtr root)
{
    for (; req; req = req->next) {
        if (req->type == XML_ELEMENT_NODE) {
            xmlNsPtr nsDef;

            for (nsDef = req->nsDef; nsDef; nsDef = nsDef->next) {
                if (!xmlStrcmp(nsDef->href, BAD_CAST XML_NS_DAV))
                    ensure_ns(respNs, NS_DAV, root,
                              (const char *) nsDef->href,
                              (const char *) nsDef->prefix);
                else if (!xmlStrcmp(nsDef->href, BAD_CAST XML_NS_CALDAV))
                    ensure_ns(respNs, NS_CALDAV, root,
                              (const char *) nsDef->href,
                              (const char *) nsDef->prefix);
                else if (!xmlStrcmp(nsDef->href, BAD_CAST XML_NS_CARDDAV))
                    ensure_ns(respNs, NS_CARDDAV, root,
                              (const char *) nsDef->href,
                              (const char *) nsDef->prefix);
                else if (!xmlStrcmp(nsDef->href, BAD_CAST XML_NS_CS))
                    ensure_ns(respNs, NS_CS, root,
                              (const char *) nsDef->href,
                              (const char *) nsDef->prefix);
                else if (!xmlStrcmp(nsDef->href, BAD_CAST XML_NS_MECOM))
                    ensure_ns(respNs, NS_MECOM, root,
                              (const char *) nsDef->href,
                              (const char *) nsDef->prefix);
                else if (!xmlStrcmp(nsDef->href, BAD_CAST XML_NS_MOBME))
                    ensure_ns(respNs, NS_MOBME, root,
                              (const char *) nsDef->href,
                              (const char *) nsDef->prefix);
                else if (!xmlStrcmp(nsDef->href, BAD_CAST XML_NS_CYRUS))
                    ensure_ns(respNs, NS_CYRUS, root,
                              (const char *) nsDef->href,
                              (const char *) nsDef->prefix);
                else
                    xmlNewNs(root, nsDef->href, nsDef->prefix);
            }
        }

        xml_add_ns(req->children, respNs, root);
    }

    /* XXX  check for errors */
    return 0;
}


/* Initialize an XML tree for a property response */
xmlNodePtr init_xml_response(const char *resp, int ns,
                             xmlNodePtr req, xmlNsPtr *respNs)
{
    /* Start construction of our XML response tree */
    xmlDocPtr doc = xmlNewDoc(BAD_CAST "1.0");
    xmlNodePtr root = NULL;

    if (!doc) return NULL;
    if (!(root = xmlNewNode(NULL, BAD_CAST resp))) {
        xmlFreeDoc(doc);
        return NULL;
    }

    xmlDocSetRootElement(doc, root);

    /* Add namespaces from request to our response,
     * creating array of known namespaces that we can reference later.
     */
    memset(respNs, 0, NUM_NAMESPACE * sizeof(xmlNsPtr));
    xml_add_ns(req, respNs, root);

    /* Set namespace of root node */
    if (ns == NS_REQ_ROOT) xmlSetNs(root, req->ns);
    else {
        ensure_ns(respNs, ns, root,
                  known_namespaces[ns].href, known_namespaces[ns].prefix);
        xmlSetNs(root, respNs[ns]);
    }

    return root;
}

xmlNodePtr xml_add_href(xmlNodePtr parent, xmlNsPtr ns, const char *href)
{
    xmlChar *uri = xmlURIEscapeStr(BAD_CAST href, BAD_CAST ":/?=");
    xmlNodePtr node = xmlNewChild(parent, ns, BAD_CAST "href", uri);

    free(uri);
    return node;
}

xmlNodePtr xml_add_error(xmlNodePtr root, struct error_t *err,
                         xmlNsPtr *avail_ns)
{
    xmlNsPtr ns[NUM_NAMESPACE];
    xmlNodePtr error, node;
    const struct precond_t *precond = &preconds[err->precond];
    unsigned err_ns = NS_DAV;
    const char *resp_desc = "responsedescription";

    if (precond->ns == NS_ISCHED) {
        err_ns = NS_ISCHED;
        resp_desc = "response-description";
    }

    if (!root) {
        error = root = init_xml_response("error", err_ns, NULL, ns);
        avail_ns = ns;
    }
    else error = xmlNewChild(root, NULL, BAD_CAST "error", NULL);

    ensure_ns(avail_ns, precond->ns, root, known_namespaces[precond->ns].href,
              known_namespaces[precond->ns].prefix);
    node = xmlNewChild(error, avail_ns[precond->ns],
                       BAD_CAST precond->name, NULL);

    switch (err->precond) {
    case DAV_NEED_PRIVS:
        if (err->resource && err->rights) {
            unsigned flags = 0;
            size_t rlen = strlen(err->resource);
            const char *p = err->resource + rlen;

            node = xmlNewChild(node, NULL, BAD_CAST "resource", NULL);
            xml_add_href(node, NULL, err->resource);

            if (rlen > 6 && !strcmp(p-6, SCHED_INBOX))
                flags = PRIV_INBOX;
            else if (rlen > 7 && !strcmp(p-7, SCHED_OUTBOX))
                flags = PRIV_OUTBOX;

            add_privs(err->rights, flags, node, root, avail_ns);
        }
        break;

    default:
        if (err->node) xmlAddChild(node, err->node);
        if (err->resource) xml_add_href(node, avail_ns[NS_DAV], err->resource);
        break;
    }

    if (err->desc) {
        xmlNewTextChild(error, NULL, BAD_CAST resp_desc, BAD_CAST err->desc);
    }

    return error;
}


void xml_add_lockdisc(xmlNodePtr node, const char *root, struct dav_data *data)
{
    time_t now = time(NULL);

    if (data->lock_expire > now) {
        xmlNodePtr active, node1;
        char tbuf[30]; /* "Second-" + long int + NUL */

        active = xmlNewChild(node, NULL, BAD_CAST "activelock", NULL);
        node1 = xmlNewChild(active, NULL, BAD_CAST "lockscope", NULL);
        xmlNewChild(node1, NULL, BAD_CAST "exclusive", NULL);

        node1 = xmlNewChild(active, NULL, BAD_CAST "locktype", NULL);
        xmlNewChild(node1, NULL, BAD_CAST "write", NULL);

        xmlNewChild(active, NULL, BAD_CAST "depth", BAD_CAST "0");

        if (data->lock_owner) {
            if (!strncmp(data->lock_owner, "<DAV:href>", 10)) {
                node1 = xmlNewChild(active, NULL, BAD_CAST "owner", NULL);
                xml_add_href(node1, NULL, data->lock_owner + 10);
            }
            else {
                xmlNewTextChild(active, NULL, BAD_CAST "owner",
                                BAD_CAST data->lock_owner);
            }
        }

        snprintf(tbuf, sizeof(tbuf), "Second-" TIME_T_FMT, data->lock_expire - now);
        xmlNewChild(active, NULL, BAD_CAST "timeout", BAD_CAST tbuf);

        node1 = xmlNewChild(active, NULL, BAD_CAST "locktoken", NULL);
        xml_add_href(node1, NULL, data->lock_token);

        node1 = xmlNewChild(active, NULL, BAD_CAST "lockroot", NULL);
        xml_add_href(node1, NULL, root);
    }
}


/* Add a property 'name', of namespace 'ns', with content 'content',
 * and status code/string 'status' to propstat element 'stat'.
 * 'stat' will be created as necessary.
 */
xmlNodePtr xml_add_prop(long status, xmlNsPtr davns,
                        struct propstat *propstat,
                        const xmlChar *name, xmlNsPtr ns,
                        xmlChar *content,
                        unsigned precond)
{
    xmlNodePtr newprop = NULL;

    if (!propstat->root) {
        propstat->root = xmlNewNode(davns, BAD_CAST "propstat");
        xmlNewChild(propstat->root, NULL, BAD_CAST "prop", NULL);
    }

    if (name) newprop = xmlNewTextChild(propstat->root->children,
                                        ns, name, content);
    propstat->status = status;
    propstat->precond = precond;

    return newprop;
}


struct allprop_rock {
    struct propfind_ctx *fctx;
    struct propstat *propstat;
};

/* Add a response tree to 'root' for the specified href and
   either error code or property list */
int xml_add_response(struct propfind_ctx *fctx, long code, unsigned precond,
                     const char *desc, const char *location)
{
    xmlNodePtr resp;

    resp = xmlNewChild(fctx->root, fctx->ns[NS_DAV], BAD_CAST "response", NULL);
    if (!resp) {
        fctx->txn->error.desc = "Unable to add response XML element";
        *fctx->ret = HTTP_SERVER_ERROR;
        return HTTP_SERVER_ERROR;
    }
    xml_add_href(resp, NULL, fctx->req_tgt->path);

    if (code) {
        xmlNewChild(resp, NULL, BAD_CAST "status",
                    BAD_CAST http_statusline(VER_1_1, code));

        if (precond) {
            xmlNodePtr error = xmlNewChild(resp, NULL, BAD_CAST "error", NULL);

            xmlNewChild(error, NULL, BAD_CAST preconds[precond].name, NULL);
        }
        if (desc) {
            xmlNewTextChild(resp, NULL,
                            BAD_CAST "errordescription", BAD_CAST desc);
        }
        if (location) {
            xmlNodePtr node = xmlNewChild(resp, NULL, BAD_CAST "location", NULL);

            xml_add_href(node, NULL, location);
        }
    }
    else {
        struct propstat propstat[NUM_PROPSTAT], *stat;
        struct propfind_entry_list *e;
        int i;

        memset(propstat, 0, NUM_PROPSTAT * sizeof(struct propstat));

        /* Process each property in the linked list */
        for (e = fctx->elist; e; e = e->next) {
            int r = HTTP_NOT_FOUND;

            if (e->get) {
                r = 0;

                /* Pre-screen request based on prop flags */
                if (fctx->req_tgt->resource) {
                    if (!(e->flags & PROP_RESOURCE)) r = HTTP_NOT_FOUND;
                }
                else if (!(e->flags & PROP_COLLECTION)) r = HTTP_NOT_FOUND;

                if (!r) {
                    if (fctx->mode == PROPFIND_NAME) {
                        xml_add_prop(HTTP_OK, fctx->ns[NS_DAV],
                                     &propstat[PROPSTAT_OK],
                                     e->name, e->ns, NULL, 0);
                    }
                    else {
                        r = e->get(e->name, e->ns, fctx,
                                   e->prop, resp, propstat, e->rock);
                    }
                }
            }

            switch (r) {
            case 0:
            case HTTP_OK:
                /* Nothing to do - property handled in callback */
                break;

            case HTTP_UNAUTHORIZED:
                xml_add_prop(HTTP_UNAUTHORIZED, fctx->ns[NS_DAV],
                             &propstat[PROPSTAT_UNAUTH],
                             e->name, e->ns, NULL, 0);
                break;

            case HTTP_FORBIDDEN:
                xml_add_prop(HTTP_FORBIDDEN, fctx->ns[NS_DAV],
                             &propstat[PROPSTAT_FORBID],
                             e->name, e->ns, NULL, 0);
                break;

            case HTTP_NOT_FOUND:
                if (!(fctx->prefer & PREFER_MIN)) {
                    xml_add_prop(HTTP_NOT_FOUND, fctx->ns[NS_DAV],
                                 &propstat[PROPSTAT_NOTFOUND],
                                 e->name, e->ns, NULL, 0);
                }
                break;

            case HTTP_BAD_MEDIATYPE:
                /* CALDAV:calendar-data/timezone/availability and
                   CARDDAV:address-data ONLY.
                   'e->rock' contains supported data precondition code.
                */
                xml_add_prop(HTTP_FORBIDDEN, fctx->ns[NS_DAV],
                             &propstat[PROPSTAT_FORBID],
                             e->name, e->ns, NULL, (uintptr_t) e->rock);
                break;

            default:
                xml_add_prop(r, fctx->ns[NS_DAV], &propstat[PROPSTAT_ERROR],
                             e->name, e->ns, NULL, 0);
                break;

            }
        }

        /* Process dead properties for allprop/propname */
        if (fctx->mailbox && !fctx->req_tgt->resource &&
            (fctx->mode == PROPFIND_ALL || fctx->mode == PROPFIND_NAME)) {
            struct allprop_rock arock = { fctx, propstat };

            annotatemore_findall(fctx->mailbox->name, 0, "*", /*modseq*/0,
                                 allprop_cb, &arock, /*flags*/0);
        }

        /* Check if we have any propstat elements */
        for (i = 0; i < NUM_PROPSTAT && !propstat[i].root; i++);
        if (i == NUM_PROPSTAT) {
            /* Add an empty propstat 200 */
            xml_add_prop(HTTP_OK, fctx->ns[NS_DAV],
                         &propstat[PROPSTAT_OK], NULL, NULL, NULL, 0);
        }

        /* Add status and optional error to the propstat elements
           and then add them to response element */
        for (i = 0; i < NUM_PROPSTAT; i++) {
            stat = &propstat[i];

            if (stat->root) {
                xmlNewChild(stat->root, NULL, BAD_CAST "status",
                            BAD_CAST http_statusline(VER_1_1, stat->status));
                if (stat->precond) {
                    struct error_t error = { NULL, stat->precond, NULL, NULL, 0 };
                    xml_add_error(stat->root, &error, fctx->ns);
                }

                xmlAddChild(resp, stat->root);
            }
        }
    }

    fctx->record = NULL;

    if (fctx->txn->flags.te & TE_CHUNKED) {
        /* Add <response> element for this resource to output buffer.
           Only output the xmlBuffer every PROT_BUFSIZE bytes */
        xml_partial_response((xmlBufferLength(fctx->xmlbuf) > PROT_BUFSIZE) ?
                             fctx->txn : NULL,
                             fctx->root->doc, resp, 1, &fctx->xmlbuf);

        /* Remove <response> element from root (no need to keep in memory) */
        xmlReplaceNode(resp, NULL);
        xmlFreeNode(resp);
    }

    return 0;
}


/* Helper function to prescreen/fetch resource data */
int propfind_getdata(const xmlChar *name, xmlNsPtr ns,
                     struct propfind_ctx *fctx,
                     xmlNodePtr prop, struct propstat propstat[],
                     struct mime_type_t *mime_types,
                     struct mime_type_t **out_type,
                     const char *data, unsigned long datalen)
{
    int ret = 0;

    if (!propstat) {
        /* Prescreen "property" request */
        xmlChar *type, *ver = NULL;
        struct mime_type_t *mime;

        type = xmlGetProp(prop, BAD_CAST "content-type");
        if (type) ver = xmlGetProp(prop, BAD_CAST "version");

        /* Check/find requested MIME type */
        for (mime = mime_types; type && mime->content_type; mime++) {
            if (is_mediatype((const char *) type, mime->content_type)) {
                if (ver &&
                    (!mime->version || xmlStrcmp(ver, BAD_CAST mime->version))) {
                    continue;
                }
                break;
            }
        }

        if (type) xmlFree(type);
        if (ver) xmlFree(ver);

        *out_type = mime;
    }
    else {
        /* Add "property" */
        struct mime_type_t *mime = *out_type;
        char *freeme = NULL;

        prop = xml_add_prop(HTTP_OK, fctx->ns[NS_DAV],
                            &propstat[PROPSTAT_OK], name, ns, NULL, 0);

        if (mime != mime_types) {
            /* Not the storage format - convert into requested MIME type */
            struct buf inbuf = BUF_INITIALIZER;

            if (!fctx->obj) {
                buf_init_ro(&inbuf, data, datalen);
                fctx->obj = mime_types->to_object(&inbuf);
                buf_free(&inbuf);
            }

            struct buf *outbuf = mime->from_object(fctx->obj);
            datalen = buf_len(outbuf);
            data = freeme = buf_release(outbuf);
            buf_destroy(outbuf);

            xmlSetProp(prop,
                       BAD_CAST "content-type", BAD_CAST mime->content_type);
            if (mime->version)
                xmlSetProp(prop, BAD_CAST "version", BAD_CAST mime->version);
        }

        xmlAddChild(prop,
                    xmlNewCDataBlock(fctx->root->doc, BAD_CAST data, datalen));

        fctx->flags.fetcheddata = 1;

        if (freeme) free(freeme);
    }

    return ret;
}


/* Callback to fetch DAV:creationdate */
int propfind_creationdate(const xmlChar *name, xmlNsPtr ns,
                          struct propfind_ctx *fctx,
                          xmlNodePtr prop __attribute__((unused)),
                          xmlNodePtr resp __attribute__((unused)),
                          struct propstat propstat[],
                          void *rock __attribute__((unused)))
{
    time_t t = 0;
    char datestr[RFC3339_DATETIME_MAX];

    if (fctx->data) {
        struct dav_data *ddata = (struct dav_data *) fctx->data;

        t = ddata->creationdate;
    }
    else if (fctx->mailbox) {
        struct stat sbuf;

        fstat(fctx->mailbox->header_fd, &sbuf);

        t = sbuf.st_ctime;
    }

    if (!t) return HTTP_NOT_FOUND;

    time_to_rfc3339(t, datestr, RFC3339_DATETIME_MAX);

    xml_add_prop(HTTP_OK, fctx->ns[NS_DAV], &propstat[PROPSTAT_OK],
                 name, ns, BAD_CAST datestr, 0);

    return 0;
}

/* Callback to write DAV:displayname for the principal */
int proppatch_principalname(xmlNodePtr prop, unsigned set,
                          struct proppatch_ctx *pctx,
                          struct propstat propstat[],
                          void *rock __attribute__((unused)))
{
    struct mailbox *mailbox = pctx->mailbox;
    struct mailbox *calhomeset = NULL;

    if (pctx->txn->req_tgt.namespace->id == URL_NS_PRINCIPAL) {
        /* We have been storing CUAS on cal-home-set, NOT INBOX */
        char *mboxname = caldav_mboxname(pctx->txn->req_tgt.userid, NULL);
        int r = 0;

        if (!mailbox || strcmp(mboxname, mailbox->name)) {
            r = mailbox_open_iwl(mboxname, &calhomeset);
            if (!r) pctx->mailbox = calhomeset;
        }
        free(mboxname);

        if (r) {
            xml_add_prop(HTTP_SERVER_ERROR, pctx->ns[NS_DAV],
                         &propstat[PROPSTAT_ERROR],
                         prop->name, prop->ns, NULL, 0);
            *pctx->ret = HTTP_SERVER_ERROR;
            return 0;
        }
    }
    else {
        /* shouldn't happen!  Internal server error 'r' us */
        *pctx->ret = HTTP_SERVER_ERROR;
        return 0;
    }

    /* Make sure this is on a collection and the user has admin rights */
    if (pctx->txn->req_tgt.resource ||
        !(cyrus_acl_myrights(httpd_authstate, pctx->mailbox->acl) & DACL_ADMIN)) {
        xml_add_prop(HTTP_FORBIDDEN, pctx->ns[NS_DAV],
                     &propstat[PROPSTAT_FORBID],
                     prop->name, prop->ns, NULL, 0);

        *pctx->ret = HTTP_FORBIDDEN;
    }
    else {
        char *value = NULL;

        if (set) {
            value = (char *) xmlNodeGetContent(prop);
        }

        proppatch_todb(prop, set, pctx, propstat, (void *) value);
        free(value);
    }

    if (calhomeset) {
        mailbox_close(&calhomeset);
        pctx->mailbox = mailbox;
    }

    return 0;
}

/* Callback to fetch DAV:displayname for principals */
static int propfind_principalname(const xmlChar *name, xmlNsPtr ns,
                                  struct propfind_ctx *fctx,
                                  xmlNodePtr prop __attribute__((unused)),
                                  xmlNodePtr resp __attribute__((unused)),
                                  struct propstat propstat[],
                                  void *rock __attribute__((unused)))
{
    /* XXX  Do LDAP/SQL lookup here */
    buf_reset(&fctx->buf);

    if (fctx->req_tgt->userid) {
        const char *annotname = DAV_ANNOT_NS "<" XML_NS_DAV ">displayname";
        char *mailboxname = caldav_mboxname(fctx->req_tgt->userid, NULL);
        int r = annotatemore_lookupmask(mailboxname, annotname,
                                        fctx->req_tgt->userid, &fctx->buf);
        free(mailboxname);
        if (r || !buf_len(&fctx->buf)) {
            buf_printf(&fctx->buf, "%s", fctx->req_tgt->userid);
        }
    }
    else {
        buf_printf(&fctx->buf, "no userid");
    }

    xml_add_prop(HTTP_OK, fctx->ns[NS_DAV], &propstat[PROPSTAT_OK],
                 name, ns, BAD_CAST buf_cstring(&fctx->buf), 0);

    return 0;
}


/* Callback to fetch DAV:displayname for collections */
int propfind_collectionname(const xmlChar *name, xmlNsPtr ns,
                            struct propfind_ctx *fctx,
                            xmlNodePtr prop, xmlNodePtr resp,
                            struct propstat propstat[], void *rock)
{
    int r = propfind_fromdb(name, ns, fctx, prop, resp, propstat, rock);

    if (r && fctx->mbentry && !fctx->req_tgt->resource) {
        /* Special case empty displayname -- use last segment of path */
        char *p = strrchr(fctx->mbentry->name, '.');
        xmlNodePtr node = xml_add_prop(HTTP_OK, fctx->ns[NS_DAV],
                                       &propstat[PROPSTAT_OK], name, ns, NULL, 0);
        buf_setcstr(&fctx->buf, (p ? p + 1 : fctx->mbentry->name));
        xmlAddChild(node, xmlNewCDataBlock(fctx->root->doc,
                                           BAD_CAST buf_cstring(&fctx->buf),
                                           buf_len(&fctx->buf)));
        return 0;
    }

    return r;
}


/* Callback to fetch DAV:getcontentlength */
int propfind_getlength(const xmlChar *name, xmlNsPtr ns,
                       struct propfind_ctx *fctx,
                       xmlNodePtr prop __attribute__((unused)),
                       xmlNodePtr resp __attribute__((unused)),
                       struct propstat propstat[],
                       void *rock __attribute__((unused)))
{
    buf_reset(&fctx->buf);

    if (fctx->record) {
        buf_printf(&fctx->buf, "%u",
                   fctx->record->size - fctx->record->header_size);
    }

    xml_add_prop(HTTP_OK, fctx->ns[NS_DAV], &propstat[PROPSTAT_OK],
                 name, ns, BAD_CAST buf_cstring(&fctx->buf), 0);

    return 0;
}


/* Callback to fetch DAV:getetag */
int propfind_getetag(const xmlChar *name, xmlNsPtr ns,
                     struct propfind_ctx *fctx,
                     xmlNodePtr prop __attribute__((unused)),
                     xmlNodePtr resp __attribute__((unused)),
                     struct propstat propstat[],
                     void *rock __attribute__((unused)))
{
    if (fctx->req_tgt->resource && !fctx->record) return HTTP_NOT_FOUND;
    if (!fctx->mailbox) return HTTP_NOT_FOUND;

    buf_reset(&fctx->buf);

    if (fctx->record) {
        const char *etag;

        fctx->get_validators(fctx->mailbox, fctx->data, fctx->userid,
                             fctx->record, &etag, NULL);
        /* add DQUOTEs */
        buf_printf(&fctx->buf, "\"%s\"", etag);
    }
    else {
        buf_printf(&fctx->buf, "\"%u-%u-%u\"", fctx->mailbox->i.uidvalidity,
                   fctx->mailbox->i.last_uid, fctx->mailbox->i.exists);
    }

    xml_add_prop(HTTP_OK, fctx->ns[NS_DAV], &propstat[PROPSTAT_OK],
                 name, ns, BAD_CAST buf_cstring(&fctx->buf), 0);

    return 0;
}


/* Callback to fetch DAV:getlastmodified */
int propfind_getlastmod(const xmlChar *name, xmlNsPtr ns,
                        struct propfind_ctx *fctx,
                        xmlNodePtr prop __attribute__((unused)),
                        xmlNodePtr resp __attribute__((unused)),
                        struct propstat propstat[],
                        void *rock __attribute__((unused)))
{
    time_t lastmod;

    if (!fctx->mailbox ||
        (fctx->req_tgt->resource && !fctx->record)) return HTTP_NOT_FOUND;

    if (fctx->record) {
        fctx->get_validators(fctx->mailbox, fctx->data, fctx->userid,
                             fctx->record, NULL, &lastmod);
    }
    else {
        lastmod = fctx->mailbox->index_mtime;
    }

    buf_ensure(&fctx->buf, 30);
    httpdate_gen(fctx->buf.s, fctx->buf.alloc, lastmod);

    xml_add_prop(HTTP_OK, fctx->ns[NS_DAV], &propstat[PROPSTAT_OK],
                 name, ns, BAD_CAST fctx->buf.s, 0);

    return 0;
}


/* Callback to fetch DAV:lockdiscovery */
int propfind_lockdisc(const xmlChar *name, xmlNsPtr ns,
                      struct propfind_ctx *fctx,
                      xmlNodePtr prop __attribute__((unused)),
                      xmlNodePtr resp __attribute__((unused)),
                      struct propstat propstat[],
                      void *rock __attribute__((unused)))
{
    xmlNodePtr node = xml_add_prop(HTTP_OK, fctx->ns[NS_DAV],
                                   &propstat[PROPSTAT_OK], name, ns, NULL, 0);

    if (fctx->data) {
        struct dav_data *ddata = (struct dav_data *) fctx->data;

        xml_add_lockdisc(node, fctx->req_tgt->path, ddata);
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

    if (fctx->req_tgt->namespace->id == URL_NS_PRINCIPAL) {
        if (fctx->req_tgt->userid)
            xmlNewChild(node, NULL, BAD_CAST "principal", NULL);
        else
            xmlNewChild(node, NULL, BAD_CAST "collection", NULL);
    }
    else if (!fctx->record) {
        xmlNewChild(node, NULL, BAD_CAST "collection", NULL);

        if (fctx->req_tgt->userid) {
            xmlNewChild(node, NULL, BAD_CAST "notifications", NULL);

            ensure_ns(fctx->ns, NS_CS, resp->parent, XML_NS_CS, "CS");
            xmlNewChild(node, fctx->ns[NS_CS], BAD_CAST "notification", NULL);
        }
    }

    return 0;
}


/* Callback to "write" resourcetype property */
int proppatch_restype(xmlNodePtr prop, unsigned set,
                      struct proppatch_ctx *pctx,
                      struct propstat propstat[],
                      void *rock)
{
    const char *coltype = (const char *) rock;
    unsigned precond = 0;

    if (set && (pctx->txn->meth != METH_PROPPATCH)) {
        /* "Writeable" for MKCOL/MKCALENDAR only */
        xmlNodePtr cur;

        for (cur = prop->children; cur; cur = cur->next) {
            if (cur->type != XML_ELEMENT_NODE) continue;
            /* Make sure we have valid resourcetypes for the collection */
            if (xmlStrcmp(cur->name, BAD_CAST "collection") &&
                (!coltype || xmlStrcmp(cur->name, BAD_CAST coltype))) break;
        }

        if (!cur) {
            /* All resourcetypes are valid */
            xml_add_prop(HTTP_OK, pctx->ns[NS_DAV], &propstat[PROPSTAT_OK],
                         prop->name, prop->ns, NULL, 0);

            return 0;
        }

        /* Invalid resourcetype */
        precond = DAV_VALID_RESTYPE;
    }
    else {
        /* Protected property */
        precond = DAV_PROT_PROP;
    }

    xml_add_prop(HTTP_FORBIDDEN, pctx->ns[NS_DAV], &propstat[PROPSTAT_FORBID],
                 prop->name, prop->ns, NULL, precond);

    *pctx->ret = HTTP_FORBIDDEN;

    return 0;
}


/* Callback to fetch DAV:supportedlock */
int propfind_suplock(const xmlChar *name, xmlNsPtr ns,
                     struct propfind_ctx *fctx,
                     xmlNodePtr prop __attribute__((unused)),
                     xmlNodePtr resp __attribute__((unused)),
                     struct propstat propstat[],
                     void *rock __attribute__((unused)))
{
    xmlNodePtr node = xml_add_prop(HTTP_OK, fctx->ns[NS_DAV],
                                   &propstat[PROPSTAT_OK], name, ns, NULL, 0);

    if (fctx->mailbox && fctx->record) {
        xmlNodePtr entry = xmlNewChild(node, NULL, BAD_CAST "lockentry", NULL);
        xmlNodePtr scope = xmlNewChild(entry, NULL, BAD_CAST "lockscope", NULL);
        xmlNodePtr type = xmlNewChild(entry, NULL, BAD_CAST "locktype", NULL);

        xmlNewChild(scope, NULL, BAD_CAST "exclusive", NULL);
        xmlNewChild(type, NULL, BAD_CAST "write", NULL);
    }

    return 0;
}


/* Callback to fetch DAV:supported-report-set */
int propfind_reportset(const xmlChar *name, xmlNsPtr ns,
                       struct propfind_ctx *fctx,
                       xmlNodePtr prop __attribute__((unused)),
                       xmlNodePtr resp __attribute__((unused)),
                       struct propstat propstat[],
                       void *rock)
{
    xmlNodePtr top, node;
    const struct report_type_t *report;

    if (!propstat) {
        /* Prescreen "property" request */
        for (report = (const struct report_type_t *) rock;
             report && report->name; report++) {
            /* Add namespaces for possible reports */
            ensure_ns(fctx->ns, report->ns, fctx->root,
                      known_namespaces[report->ns].href,
                      known_namespaces[report->ns].prefix);
        }

        return 0;
    }

    top = xml_add_prop(HTTP_OK, fctx->ns[NS_DAV], &propstat[PROPSTAT_OK],
                       name, ns, NULL, 0);

    for (report = (const struct report_type_t *) rock;
         report && report->name; report++) {
        node = xmlNewChild(top, NULL, BAD_CAST "supported-report", NULL);
        node = xmlNewChild(node, NULL, BAD_CAST "report", NULL);

        ensure_ns(fctx->ns, report->ns, resp->parent,
                  known_namespaces[report->ns].href,
                  known_namespaces[report->ns].prefix);
        xmlNewChild(node, fctx->ns[report->ns], BAD_CAST report->name, NULL);
    }

    return 0;
}


/* Callback to fetch DAV:supported-method-set */
int propfind_methodset(const xmlChar *name, xmlNsPtr ns,
                       struct propfind_ctx *fctx,
                       xmlNodePtr prop __attribute__((unused)),
                       xmlNodePtr resp __attribute__((unused)),
                       struct propstat propstat[],
                       void *rock)
{
    unsigned long (*allow_cb)(struct request_target_t *) =
        (unsigned long (*)(struct request_target_t *)) rock;
    unsigned long allow = allow_cb(fctx->req_tgt);
    xmlNodePtr top, node;

    top = xml_add_prop(HTTP_OK, fctx->ns[NS_DAV], &propstat[PROPSTAT_OK],
                       name, ns, NULL, 0);

    if (allow & ALLOW_ACL) {
        node = xmlNewChild(top, NULL, BAD_CAST "supported-method", NULL);
        xmlSetProp(node, BAD_CAST "name", BAD_CAST "ACL");
    }
    if (allow & ALLOW_READ) {
        node = xmlNewChild(top, NULL, BAD_CAST "supported-method", NULL);
        xmlSetProp(node, BAD_CAST "name", BAD_CAST "COPY");
    }
    if (allow & ALLOW_DELETE) {
        node = xmlNewChild(top, NULL, BAD_CAST "supported-method", NULL);
        xmlSetProp(node, BAD_CAST "name", BAD_CAST "DELETE");
    }
    if (allow & ALLOW_READ) {
        node = xmlNewChild(top, NULL, BAD_CAST "supported-method", NULL);
        xmlSetProp(node, BAD_CAST "name", BAD_CAST "GET");
        node = xmlNewChild(top, NULL, BAD_CAST "supported-method", NULL);
        xmlSetProp(node, BAD_CAST "name", BAD_CAST "HEAD");
    }
    if (allow & ALLOW_WRITE) {
        node = xmlNewChild(top, NULL, BAD_CAST "supported-method", NULL);
        xmlSetProp(node, BAD_CAST "name", BAD_CAST "LOCK");
    }
    if (allow & ALLOW_MKCOL) {
        if (allow & ALLOW_CAL) {
            node = xmlNewChild(top, NULL, BAD_CAST "supported-method", NULL);
            xmlSetProp(node, BAD_CAST "name", BAD_CAST "MKCALENDAR");
        }
        node = xmlNewChild(top, NULL, BAD_CAST "supported-method", NULL);
        xmlSetProp(node, BAD_CAST "name", BAD_CAST "MKCOL");
    }
    if (allow & ALLOW_DELETE) {
        node = xmlNewChild(top, NULL, BAD_CAST "supported-method", NULL);
        xmlSetProp(node, BAD_CAST "name", BAD_CAST "MOVE");
    }
    if (allow & ALLOW_READ) {
        node = xmlNewChild(top, NULL, BAD_CAST "supported-method", NULL);
        xmlSetProp(node, BAD_CAST "name", BAD_CAST "OPTIONS");
    }
    if (allow & ALLOW_PATCH) {
        node = xmlNewChild(top, NULL, BAD_CAST "supported-method", NULL);
        xmlSetProp(node, BAD_CAST "name", BAD_CAST "PATCH");
    }
    if (allow & ALLOW_POST) {
        node = xmlNewChild(top, NULL, BAD_CAST "supported-method", NULL);
        xmlSetProp(node, BAD_CAST "name", BAD_CAST "POST");
    }
    if (allow & ALLOW_READ) {
        node = xmlNewChild(top, NULL, BAD_CAST "supported-method", NULL);
        xmlSetProp(node, BAD_CAST "name", BAD_CAST "PROPFIND");
    }
    if (allow & ALLOW_PROPPATCH) {
        node = xmlNewChild(top, NULL, BAD_CAST "supported-method", NULL);
        xmlSetProp(node, BAD_CAST "name", BAD_CAST "PROPPATCH");
    }
    if (allow & ALLOW_WRITE) {
        node = xmlNewChild(top, NULL, BAD_CAST "supported-method", NULL);
        xmlSetProp(node, BAD_CAST "name", BAD_CAST "PUT");
    }
    if (allow & ALLOW_READ) {
        node = xmlNewChild(top, NULL, BAD_CAST "supported-method", NULL);
        xmlSetProp(node, BAD_CAST "name", BAD_CAST "REPORT");
    }
    if (allow & ALLOW_TRACE) {
        node = xmlNewChild(top, NULL, BAD_CAST "supported-method", NULL);
        xmlSetProp(node, BAD_CAST "name", BAD_CAST "TRACE");
    }
    if (allow & ALLOW_WRITE) {
        node = xmlNewChild(top, NULL, BAD_CAST "supported-method", NULL);
        xmlSetProp(node, BAD_CAST "name", BAD_CAST "UNLOCK");
    }

    return 0;
}


/* Callback to fetch *DAV:supported-collation-set */
int propfind_collationset(const xmlChar *name, xmlNsPtr ns,
                          struct propfind_ctx *fctx,
                          xmlNodePtr prop __attribute__((unused)),
                          xmlNodePtr resp __attribute__((unused)),
                          struct propstat propstat[],
                          void *rock __attribute__((unused)))
{
    xmlNodePtr top;
    const struct collation_t *col;

    top = xml_add_prop(HTTP_OK, fctx->ns[NS_DAV], &propstat[PROPSTAT_OK],
                       name, ns, NULL, 0);

    for (col = dav_collations; col->name; col++) {
        xmlNewChild(top, NULL, BAD_CAST "supported-collation", BAD_CAST col->name);
    }

    return 0;
}


/* Callback to fetch DAV:alternate-URI-set */
static int propfind_alturiset(const xmlChar *name, xmlNsPtr ns,
                              struct propfind_ctx *fctx,
                              xmlNodePtr prop __attribute__((unused)),
                              xmlNodePtr resp __attribute__((unused)),
                              struct propstat propstat[],
                              void *rock __attribute__((unused)))
{
    xml_add_prop(HTTP_OK, fctx->ns[NS_DAV],
                 &propstat[PROPSTAT_OK], name, ns, NULL, 0);

    return 0;
}


/* Callback to fetch DAV:principal-URL */
int propfind_principalurl(const xmlChar *name, xmlNsPtr ns,
                          struct propfind_ctx *fctx,
                          xmlNodePtr prop,
                          xmlNodePtr resp __attribute__((unused)),
                          struct propstat propstat[],
                          void *rock)
{
    xmlNodePtr node = xml_add_prop(HTTP_OK, fctx->ns[NS_DAV],
                                   &propstat[PROPSTAT_OK], name, ns, NULL, 0);
    const char *userid = rock ? (const char *) rock : fctx->req_tgt->userid;

    if (userid) {
        buf_reset(&fctx->buf);

        if (strchr(userid, '@') || !httpd_extradomain) {
            buf_printf(&fctx->buf, "%s/%s/%s/", namespace_principal.prefix,
                       USER_COLLECTION_PREFIX, userid);
        }
        else {
            buf_printf(&fctx->buf, "%s/%s/%s@%s/", namespace_principal.prefix,
                       USER_COLLECTION_PREFIX, userid, httpd_extradomain);
        }

        if ((fctx->mode == PROPFIND_EXPAND) && xmlFirstElementChild(prop)) {
            /* Return properties for this URL */
            expand_property(prop, fctx, &namespace_principal, buf_cstring(&fctx->buf),
                            &principal_parse_path, principal_props, node, 0);
        }
        else {
            /* Return just the URL */
            xml_add_href(node, NULL, buf_cstring(&fctx->buf));
        }
    }

    return 0;
}


/* Callback to fetch DAV:owner */
int propfind_owner(const xmlChar *name, xmlNsPtr ns,
                   struct propfind_ctx *fctx,
                   xmlNodePtr prop,
                   xmlNodePtr resp __attribute__((unused)),
                   struct propstat propstat[],
                   void *rock __attribute__((unused)))
{
    mbname_t *mbname;
    const char *owner;
    int r;

    if (!fctx->mbentry) return HTTP_NOT_FOUND;

    mbname = mbname_from_intname(fctx->mbentry->name);
    owner = mbname_userid(mbname);
    if (!owner) {
        static strarray_t *admins = NULL;

        if (!admins) admins = strarray_split(config_getstring(IMAPOPT_ADMINS),
                                             NULL, STRARRAY_TRIM);

        owner = strarray_nth(admins, 0);
    }

    r = propfind_principalurl(name, ns, fctx,
                              prop, resp, propstat, (void *) owner);

    mbname_free(&mbname);

    return r;
}


/* Add possibly 'abstract' supported-privilege 'priv_name', of namespace 'ns',
 * with description 'desc_str' to node 'root'.  For now, we assume all
 * descriptions are English.
 */
static xmlNodePtr add_suppriv(xmlNodePtr root, const char *priv_name,
                              xmlNsPtr ns, int abstract, const char *desc_str)
{
    xmlNodePtr supp, priv, desc;

    supp = xmlNewChild(root, NULL, BAD_CAST "supported-privilege", NULL);
    priv = xmlNewChild(supp, NULL, BAD_CAST "privilege", NULL);
    xmlNewChild(priv, ns, BAD_CAST priv_name, NULL);
    if (abstract) xmlNewChild(supp, NULL, BAD_CAST "abstract", NULL);
    desc = xmlNewChild(supp, NULL, BAD_CAST "description", BAD_CAST desc_str);
    xmlNodeSetLang(desc, BAD_CAST "en");

    return supp;
}


/* Callback to fetch DAV:supported-privilege-set */
int propfind_supprivset(const xmlChar *name, xmlNsPtr ns,
                        struct propfind_ctx *fctx,
                        xmlNodePtr prop __attribute__((unused)),
                        xmlNodePtr resp,
                        struct propstat propstat[],
                        void *rock __attribute__((unused)))
{
    xmlNodePtr set, all, agg, write;
    unsigned tgt_flags = 0;

    if (!propstat) {
        /* Prescreen "property" request */
        if (fctx->req_tgt->collection ||
            (fctx->req_tgt->userid && fctx->depth >= 1) || fctx->depth >= 2) {
            /* Add namespaces for possible privileges */
            ensure_ns(fctx->ns, NS_CYRUS, fctx->root, XML_NS_CYRUS, "CY");
            if (fctx->req_tgt->namespace->id == URL_NS_CALENDAR) {
                ensure_ns(fctx->ns, NS_CALDAV, fctx->root, XML_NS_CALDAV, "C");
            }
        }

        return 0;
    }

    set = xml_add_prop(HTTP_OK, fctx->ns[NS_DAV], &propstat[PROPSTAT_OK],
                       name, ns, NULL, 0);

    all = add_suppriv(set, "all", NULL, 0, "Any operation");

    agg = add_suppriv(all, "read", NULL, 0, "Read any object");
    add_suppriv(agg, "read-current-user-privilege-set", NULL, 1,
                "Read current user privilege set");

    if (fctx->req_tgt->namespace->id == URL_NS_CALENDAR) {
        if (fctx->req_tgt->collection) {
            ensure_ns(fctx->ns, NS_CALDAV, resp->parent, XML_NS_CALDAV, "C");

            if (!strcmp(fctx->req_tgt->collection, SCHED_INBOX))
                tgt_flags = TGT_SCHED_INBOX;
            else if (!strcmp(fctx->req_tgt->collection, SCHED_OUTBOX))
                tgt_flags = TGT_SCHED_OUTBOX;
            else {
                add_suppriv(agg, "read-free-busy", fctx->ns[NS_CALDAV], 0,
                            "Read free/busy time");
            }
        }
    }

    write = add_suppriv(all, "write", NULL, 0, "Write any object");
    add_suppriv(write, "write-content", NULL, 0, "Write resource content");

    agg = add_suppriv(write, "write-properties", NULL, 0, "Write properties");
    ensure_ns(fctx->ns, NS_CYRUS, resp->parent, XML_NS_CYRUS, "CY");
    add_suppriv(agg, "write-properties-collection", fctx->ns[NS_CYRUS], 0,
                "Write properties on a collection");
    add_suppriv(agg, "write-properties-resource", fctx->ns[NS_CYRUS], 0,
                "Write properties on a resource");

    agg = add_suppriv(write, "bind", NULL, 0, "Add new member to collection");
    add_suppriv(agg, "make-collection", fctx->ns[NS_CYRUS], 0,
                "Make new collection");
    add_suppriv(agg, "add-resource", fctx->ns[NS_CYRUS], 0,
                "Add new resource");

    agg = add_suppriv(write, "unbind", NULL, 0,
                         "Remove member from collection");
    add_suppriv(agg, "remove-collection", fctx->ns[NS_CYRUS], 0,
                "Remove collection");
    add_suppriv(agg, "remove-resource", fctx->ns[NS_CYRUS], 0,
                "Remove resource");

    agg = add_suppriv(all, "admin", fctx->ns[NS_CYRUS], 0,
                        "Perform administrative operations");
    add_suppriv(agg, "read-acl", NULL, 1, "Read ACL");
    add_suppriv(agg, "write-acl", NULL, 1, "Write ACL");
    add_suppriv(agg, "unlock", NULL, 1, "Unlock resource");
    add_suppriv(agg, "share", NULL, 1, "Share resource");

    if (tgt_flags == TGT_SCHED_INBOX) {
        agg = add_suppriv(all, "schedule-deliver", fctx->ns[NS_CALDAV], 0,
                          "Deliver scheduling messages");
        add_suppriv(agg, "schedule-deliver-invite", fctx->ns[NS_CALDAV], 0,
                    "Deliver scheduling messages from Organizers");
        add_suppriv(agg, "schedule-deliver-reply", fctx->ns[NS_CALDAV], 0,
                    "Deliver scheduling messages from Attendees");
        add_suppriv(agg, "schedule-query-freebusy", fctx->ns[NS_CALDAV], 0,
                    "Accept free/busy requests");
    }
    else if (tgt_flags == TGT_SCHED_OUTBOX) {
        agg = add_suppriv(all, "schedule-send", fctx->ns[NS_CALDAV], 0,
                          "Send scheduling messages");
        add_suppriv(agg, "schedule-send-invite", fctx->ns[NS_CALDAV], 0,
                    "Send scheduling messages by Organizers");
        add_suppriv(agg, "schedule-send-reply", fctx->ns[NS_CALDAV], 0,
                    "Send scheduling messages by Attendees");
        add_suppriv(agg, "schedule-send-freebusy", fctx->ns[NS_CALDAV], 0,
                    "Submit free/busy requests");
    }

    return 0;
}


static void add_privs(int rights, unsigned flags,
                      xmlNodePtr parent, xmlNodePtr root, xmlNsPtr *ns)
{
    xmlNodePtr priv;
    int do_contained;

    /* DAV:all */
    if ((rights & DACL_ALL) == DACL_ALL &&
        /* DAV:all on CALDAV:schedule-in/outbox MUST include CALDAV:schedule */
        (!(flags & (PRIV_INBOX|PRIV_OUTBOX)) ||
         (rights & DACL_SCHED) == DACL_SCHED)) {
        priv = xmlNewChild(parent, NULL, BAD_CAST "privilege", NULL);
        xmlNewChild(priv, NULL, BAD_CAST "all", NULL);

        if (!(flags & PRIV_CONTAINED)) return;
    }

    /* DAV:read */
    if ((rights & DACL_READ) == DACL_READ) {
        priv = xmlNewChild(parent, NULL, BAD_CAST "privilege", NULL);
        xmlNewChild(priv, NULL, BAD_CAST "read", NULL);
        if (flags & PRIV_IMPLICIT) rights |= DACL_READFB;

        do_contained = (flags & PRIV_CONTAINED);
    }
    else do_contained = 1;

    if (do_contained) {
        if ((rights & DACL_READFB) &&
            /* CALDAV:read-free-busy doesn't apply to CALDAV:sched-in/outbox */
            !(flags & (PRIV_INBOX|PRIV_OUTBOX))) {
            priv = xmlNewChild(parent, NULL, BAD_CAST "privilege", NULL);
            ensure_ns(ns, NS_CALDAV, root, XML_NS_CALDAV, "C");
            xmlNewChild(priv, ns[NS_CALDAV], BAD_CAST  "read-free-busy", NULL);
        }
    }

    /* DAV:write */
    if ((rights & DACL_WRITE) == DACL_WRITE) {
        priv = xmlNewChild(parent, NULL, BAD_CAST "privilege", NULL);
        xmlNewChild(priv, NULL, BAD_CAST "write", NULL);

        do_contained = (flags & PRIV_CONTAINED);
    }
    else do_contained = 1;

    if (do_contained) {
        if (rights & DACL_WRITECONT) {
            priv = xmlNewChild(parent, NULL, BAD_CAST "privilege", NULL);
            xmlNewChild(priv, NULL, BAD_CAST "write-content", NULL);
        }

        if (rights & (DACL_WRITEPROPS|DACL_BIND|DACL_UNBIND)) {
            ensure_ns(ns, NS_CYRUS, root, XML_NS_CYRUS, "CY");

            /* DAV:write-properties */
            if ((rights & DACL_WRITEPROPS) == DACL_WRITEPROPS) {
                priv = xmlNewChild(parent, NULL, BAD_CAST "privilege", NULL);
                xmlNewChild(priv, NULL, BAD_CAST "write-properties", NULL);

                do_contained = (flags & PRIV_CONTAINED);
            }
            else do_contained = 1;

            if (do_contained) {
                if (rights & DACL_PROPCOL) {
                    priv = xmlNewChild(parent, NULL,
                                       BAD_CAST "privilege", NULL);
                    xmlNewChild(priv, ns[NS_CYRUS],
                                BAD_CAST "write-properties-collection", NULL);
                }
                if (rights & DACL_PROPRSRC) {
                    priv = xmlNewChild(parent, NULL,
                                       BAD_CAST "privilege", NULL);
                    xmlNewChild(priv, ns[NS_CYRUS],
                                BAD_CAST "write-properties-resource", NULL);
                }
            }

            /* DAV:bind */
            if ((rights & DACL_BIND) == DACL_BIND) {
                priv = xmlNewChild(parent, NULL, BAD_CAST "privilege", NULL);
                xmlNewChild(priv, NULL, BAD_CAST "bind", NULL);

                do_contained = (flags & PRIV_CONTAINED);
            }
            else do_contained = 1;

            if (do_contained) {
                if (rights & DACL_MKCOL) {
                    priv = xmlNewChild(parent, NULL,
                                       BAD_CAST "privilege", NULL);
                    xmlNewChild(priv, ns[NS_CYRUS],
                                BAD_CAST "make-collection", NULL);
                }
                if (rights & DACL_ADDRSRC) {
                    priv = xmlNewChild(parent, NULL,
                                       BAD_CAST "privilege", NULL);
                    xmlNewChild(priv, ns[NS_CYRUS],
                                BAD_CAST "add-resource", NULL);
                }
            }

            /* DAV:unbind */
            if ((rights & DACL_UNBIND) == DACL_UNBIND) {
                priv = xmlNewChild(parent, NULL, BAD_CAST "privilege", NULL);
                xmlNewChild(priv, NULL, BAD_CAST "unbind", NULL);

                do_contained = (flags & PRIV_CONTAINED);
            }
            else do_contained = 1;

            if (do_contained) {
                if (rights & DACL_RMCOL) {
                    priv = xmlNewChild(parent, NULL,
                                       BAD_CAST "privilege", NULL);
                    xmlNewChild(priv, ns[NS_CYRUS],
                                BAD_CAST "remove-collection", NULL);
                }
                if ((rights & DACL_RMRSRC) == DACL_RMRSRC) {
                    priv = xmlNewChild(parent, NULL,
                                       BAD_CAST "privilege", NULL);
                    xmlNewChild(priv, ns[NS_CYRUS],
                                BAD_CAST "remove-resource", NULL);
                }
            }
        }
    }

    /* CYRUS:admin */
    if (rights & DACL_ADMIN) {
        ensure_ns(ns, NS_CYRUS, root, XML_NS_CYRUS, "CY");
        priv = xmlNewChild(parent, NULL, BAD_CAST "privilege", NULL);
        xmlNewChild(priv, ns[NS_CYRUS], BAD_CAST  "admin", NULL);
    }

    if ((rights & DACL_SCHED) && (flags & (PRIV_INBOX|PRIV_OUTBOX))) {
        struct buf buf = BUF_INITIALIZER;
        size_t len;

        if (flags & PRIV_INBOX) buf_setcstr(&buf, "schedule-deliver");
        else buf_setcstr(&buf, "schedule-send");
        len = buf_len(&buf);

        ensure_ns(ns, NS_CALDAV, root, XML_NS_CALDAV, "C");

        /* CALDAV:schedule */
        if ((rights & DACL_SCHED) == DACL_SCHED) {
            priv = xmlNewChild(parent, NULL, BAD_CAST "privilege", NULL);
            xmlNewChild(priv, ns[NS_CALDAV], BAD_CAST buf_cstring(&buf), NULL);
            
            do_contained = (flags & PRIV_CONTAINED);
        }
        else do_contained = 1;

        if (do_contained) {
            if (rights & DACL_INVITE) {
                buf_truncate(&buf, len);
                buf_appendcstr(&buf, "-invite");
                priv = xmlNewChild(parent, NULL, BAD_CAST "privilege", NULL);
                xmlNewChild(priv, ns[NS_CALDAV],
                            BAD_CAST buf_cstring(&buf), NULL);
            }
            if (rights & DACL_REPLY) {
                buf_truncate(&buf, len);
                buf_appendcstr(&buf, "-reply");
                priv = xmlNewChild(parent, NULL, BAD_CAST "privilege", NULL);
                xmlNewChild(priv, ns[NS_CALDAV],
                            BAD_CAST buf_cstring(&buf), NULL);
            }
            if (rights & DACL_SCHEDFB) {
                if (flags & PRIV_INBOX) buf_setcstr(&buf, "schedule-query");
                else buf_truncate(&buf, len);
                buf_appendcstr(&buf, "-freebusy");
                priv = xmlNewChild(parent, NULL, BAD_CAST "privilege", NULL);
                xmlNewChild(priv, ns[NS_CALDAV],
                            BAD_CAST buf_cstring(&buf), NULL);
            }
        }
        buf_free(&buf);
    }
}


/* Callback to fetch DAV:current-user-privilege-set */
int propfind_curprivset(const xmlChar *name, xmlNsPtr ns,
                        struct propfind_ctx *fctx,
                        xmlNodePtr prop __attribute__((unused)),
                        xmlNodePtr resp,
                        struct propstat propstat[],
                        void *rock __attribute__((unused)))
{
    int rights;
    unsigned flags = 0;
    xmlNodePtr set;

    if (!propstat) {
        /* Prescreen "property" request */
        if (fctx->req_tgt->collection ||
            (fctx->req_tgt->userid && fctx->depth >= 1) || fctx->depth >= 2) {
            /* Add namespaces for possible privileges */
            ensure_ns(fctx->ns, NS_CYRUS, fctx->root, XML_NS_CYRUS, "CY");
            if (fctx->req_tgt->namespace->id == URL_NS_CALENDAR) {
                ensure_ns(fctx->ns, NS_CALDAV, fctx->root, XML_NS_CALDAV, "C");
            }
        }

        return 0;
    }

    if (!fctx->mailbox) return HTTP_NOT_FOUND;
    rights = httpd_myrights(fctx->authstate, fctx->mbentry);
    if ((rights & DACL_READ) != DACL_READ) {
        return HTTP_UNAUTHORIZED;
    }

    /* Add in implicit rights */
    if (fctx->userisadmin) {
        rights |= DACL_ADMIN;
    }
    else if (mboxname_userownsmailbox(httpd_userid, fctx->mailbox->name)) {
        rights |= config_implicitrights;
        /* we always allow admin by the owner in DAV */
        rights |= DACL_ADMIN;
    }

    /* Build the rest of the XML response */
    set = xml_add_prop(HTTP_OK, fctx->ns[NS_DAV], &propstat[PROPSTAT_OK],
                       name, ns, NULL, 0);

    if (!fctx->req_tgt->resource) {
        if (fctx->req_tgt->namespace->id == URL_NS_CALENDAR) {
            flags = PRIV_IMPLICIT;

            if (fctx->req_tgt->collection) {
                if (!strcmp(fctx->req_tgt->collection, SCHED_INBOX))
                    flags = PRIV_INBOX;
                else if (!strcmp(fctx->req_tgt->collection, SCHED_OUTBOX))
                    flags = PRIV_OUTBOX;
            }
        }

        flags += PRIV_CONTAINED;

        add_privs(rights, flags, set, resp->parent, fctx->ns);
    }

    return 0;
}


/* Callback to fetch DAV:acl */
int propfind_acl(const xmlChar *name, xmlNsPtr ns,
                 struct propfind_ctx *fctx,
                 xmlNodePtr prop __attribute__((unused)),
                 xmlNodePtr resp,
                 struct propstat propstat[],
                 void *rock __attribute__((unused)))
{
    xmlNodePtr acl;
    char *aclstr, *userid;
    unsigned flags = 0;

    if (!propstat) {
        /* Prescreen "property" request */
        if (fctx->req_tgt->namespace->id == URL_NS_CALENDAR &&
            (fctx->req_tgt->collection ||
             (fctx->req_tgt->userid && fctx->depth >= 1) || fctx->depth >= 2)) {
            /* Add namespaces for possible privileges */
            ensure_ns(fctx->ns, NS_CALDAV, fctx->root, XML_NS_CALDAV, "C");
        }

        return 0;
    }

    if (!fctx->mailbox) return HTTP_NOT_FOUND;

    /* owner has implicit admin rights */
    if (!mboxname_userownsmailbox(httpd_userid, fctx->mailbox->name)) {
        int rights = httpd_myrights(fctx->authstate, fctx->mbentry);
        if (!(rights & DACL_ADMIN))
            return HTTP_UNAUTHORIZED;
    }

    if (fctx->req_tgt->namespace->id == URL_NS_CALENDAR) {
        flags = PRIV_IMPLICIT;

        if (fctx->req_tgt->collection) {
            if (!strcmp(fctx->req_tgt->collection, SCHED_INBOX))
                flags = PRIV_INBOX;
            else if (!strcmp(fctx->req_tgt->collection, SCHED_OUTBOX))
                flags = PRIV_OUTBOX;
        }
    }

    /* Start the acl XML response */
    acl = xml_add_prop(HTTP_OK, fctx->ns[NS_DAV], &propstat[PROPSTAT_OK],
                       name, ns, NULL, 0);

    /* Parse the ACL string (userid/rights pairs) */
    userid = aclstr = xstrdup(fctx->mailbox->acl);

    while (userid) {
        int rights;
        char *rightstr, *nextid;
        xmlNodePtr ace, node;
        int deny = 0;

        rightstr = strchr(userid, '\t');
        if (!rightstr) break;
        *rightstr++ = '\0';

        nextid = strchr(rightstr, '\t');
        if (!nextid) break;
        *nextid++ = '\0';

        /* Check for negative rights */
        if (*userid == '-') {
            deny = 1;
            userid++;
        }

        cyrus_acl_strtomask(rightstr, &rights);
        /* XXX and if strtomask fails? */

        /* Add ace XML element for this userid/right pair */
        ace = xmlNewChild(acl, NULL, BAD_CAST "ace", NULL);

        node = xmlNewChild(ace, NULL, BAD_CAST "principal", NULL);
        if (!strcmp(userid, fctx->userid))
            xmlNewChild(node, NULL, BAD_CAST "self", NULL);
        else if (mboxname_userownsmailbox(userid, fctx->mailbox->name)) {
            xmlNewChild(node, NULL, BAD_CAST "owner", NULL);
            /* we always allow admin by the owner in DAV */
            rights |= DACL_ADMIN;
        }
        else if (!strcmp(userid, "anyone"))
            xmlNewChild(node, NULL, BAD_CAST "all", NULL);
        else if (!strcmp(userid, "anonymous"))
            xmlNewChild(node, NULL, BAD_CAST "unauthenticated", NULL);
        else if (!strncmp(userid, "group:", 6)) {
            buf_reset(&fctx->buf);
            buf_printf(&fctx->buf, "%s/%s/%s/", namespace_principal.prefix,
                       GROUP_COLLECTION_PREFIX, userid+6);
            xml_add_href(node, NULL, buf_cstring(&fctx->buf));
        }
        else {
            buf_reset(&fctx->buf);
            buf_printf(&fctx->buf, "%s/%s/%s/", namespace_principal.prefix,
                       USER_COLLECTION_PREFIX, userid);
            xml_add_href(node, NULL, buf_cstring(&fctx->buf));
        }

        node = xmlNewChild(ace, NULL, BAD_CAST (deny ? "deny" : "grant"), NULL);
        add_privs(rights, flags, node, resp->parent, fctx->ns);

        if (fctx->req_tgt->resource) {
            node = xmlNewChild(ace, NULL, BAD_CAST "inherited", NULL);
            buf_reset(&fctx->buf);
            buf_printf(&fctx->buf, "%.*s",
                       (int)(fctx->req_tgt->resource - fctx->req_tgt->path),
                       fctx->req_tgt->path);
            xml_add_href(node, NULL, buf_cstring(&fctx->buf));
        }

        userid = nextid;
    }

    if (aclstr) free(aclstr);

    return 0;
}


/* Callback to fetch DAV:acl-restrictions */
int propfind_aclrestrict(const xmlChar *name, xmlNsPtr ns,
                         struct propfind_ctx *fctx,
                         xmlNodePtr prop __attribute__((unused)),
                         xmlNodePtr resp __attribute__((unused)),
                         struct propstat propstat[],
                         void *rock __attribute__((unused)))
{
    xmlNodePtr node = xml_add_prop(HTTP_OK, fctx->ns[NS_DAV],
                                   &propstat[PROPSTAT_OK], name, ns, NULL, 0);

    xmlNewChild(node, NULL, BAD_CAST "no-invert", NULL);

    return 0;
}


/* Callback to fetch DAV:principal-collection-set */
EXPORTED int propfind_princolset(const xmlChar *name, xmlNsPtr ns,
                                 struct propfind_ctx *fctx,
                                 xmlNodePtr prop __attribute__((unused)),
                                 xmlNodePtr resp __attribute__((unused)),
                                 struct propstat propstat[],
                                 void *rock __attribute__((unused)))
{
    xmlNodePtr node = xml_add_prop(HTTP_OK, fctx->ns[NS_DAV],
                                   &propstat[PROPSTAT_OK], name, ns, NULL, 0);

    buf_reset(&fctx->buf);
    buf_printf(&fctx->buf, "%s/%s/",
               namespace_principal.prefix, USER_COLLECTION_PREFIX);
    xml_add_href(node, NULL, buf_cstring(&fctx->buf));

    return 0;
}


/* Callback to fetch DAV:quota-available-bytes and DAV:quota-used-bytes */
EXPORTED int propfind_quota(const xmlChar *name, xmlNsPtr ns,
                            struct propfind_ctx *fctx,
                            xmlNodePtr prop __attribute__((unused)),
                            xmlNodePtr resp __attribute__((unused)),
                            struct propstat propstat[],
                            void *rock __attribute__((unused)))
{
    static char prevroot[MAX_MAILBOX_BUFFER];
    char foundroot[MAX_MAILBOX_BUFFER], *qr = NULL;

    if (fctx->mailbox) {
        /* Use the quotaroot as specified in mailbox header */
        qr = fctx->mailbox->quotaroot;
    }
    else if (fctx->req_tgt->mbentry) {
        /* Find the quotaroot governing this hierarchy */
        if (quota_findroot(foundroot, sizeof(foundroot),
                           fctx->req_tgt->mbentry->name)) {
            qr = foundroot;
        }
    }

    if (!qr) return HTTP_NOT_FOUND;

    if (!fctx->quota.root ||
        strcmp(fctx->quota.root, qr)) {
        /* Different quotaroot - read it */

        syslog(LOG_DEBUG, "reading quota for '%s'", qr);

        fctx->quota.root = strcpy(prevroot, qr);

        quota_read_withconversations(&fctx->quota);
    }

    buf_reset(&fctx->buf);
    if (!xmlStrcmp(name, BAD_CAST "quota-available-bytes")) {
        /* Calculate limit in bytes and subtract usage */
        quota_t limit =
            fctx->quota.limits[QUOTA_STORAGE] * quota_units[QUOTA_STORAGE];

        buf_printf(&fctx->buf, QUOTA_T_FMT,
                   limit - fctx->quota.useds[QUOTA_STORAGE]);
    }
    else if (fctx->record) {
        /* Bytes used by resource */
        buf_printf(&fctx->buf, "%u", fctx->record->size);
    }
    else if (fctx->mailbox) {
        /* Bytes used by calendar collection */
        buf_printf(&fctx->buf, QUOTA_T_FMT,
                   fctx->mailbox->i.quota_mailbox_used);
    }
    else {
        /* Bytes used by entire hierarchy */
        buf_printf(&fctx->buf, QUOTA_T_FMT, fctx->quota.useds[QUOTA_STORAGE]);
    }

    xml_add_prop(HTTP_OK, fctx->ns[NS_DAV], &propstat[PROPSTAT_OK],
                 name, ns, BAD_CAST buf_cstring(&fctx->buf), 0);

    return 0;
}


/* Callback to fetch DAV:current-user-principal */
EXPORTED int propfind_curprin(const xmlChar *name, xmlNsPtr ns,
                              struct propfind_ctx *fctx,
                              xmlNodePtr prop,
                              xmlNodePtr resp,
                              struct propstat propstat[],
                              void *rock __attribute__((unused)))
{
    if (httpd_userid) {
        propfind_principalurl(name, ns, fctx,
                              prop, resp, propstat, httpd_userid);
    }
    else {
        xmlNodePtr node =
            xml_add_prop(HTTP_OK, fctx->ns[NS_DAV],
                         &propstat[PROPSTAT_OK], name, ns, NULL, 0);

        xmlNewChild(node, NULL, BAD_CAST "unauthenticated", NULL);
    }

    return 0;
}


/* Callback to fetch DAV:add-member */
int propfind_addmember(const xmlChar *name, xmlNsPtr ns,
                       struct propfind_ctx *fctx,
                       xmlNodePtr prop __attribute__((unused)),
                       xmlNodePtr resp __attribute__((unused)),
                       struct propstat propstat[],
                       void *rock __attribute__((unused)))
{
    xmlNodePtr node;
    int len;

    if (!fctx->req_tgt->collection ||
        !strcmp(fctx->req_tgt->collection, SCHED_INBOX) ||
        !strcmp(fctx->req_tgt->collection, SCHED_OUTBOX) ||
        (fctx->req_tgt->namespace->id == URL_NS_ADDRESSBOOK &&
         !config_getswitch(IMAPOPT_CARDDAV_ALLOWADDMEMBER))) {
        /* Only allowed on non-scheduling collections */
        return HTTP_NOT_FOUND;
    }

    node = xml_add_prop(HTTP_OK, fctx->ns[NS_DAV], &propstat[PROPSTAT_OK],
                        name, ns, NULL, 0);

    len = fctx->req_tgt->resource ?
        (size_t) (fctx->req_tgt->resource - fctx->req_tgt->path) :
        strlen(fctx->req_tgt->path);
    buf_reset(&fctx->buf);
    buf_printf(&fctx->buf, "%.*s?action=add-member", len, fctx->req_tgt->path);

    xml_add_href(node, NULL, buf_cstring(&fctx->buf));

    return 0;
}


void dav_get_synctoken(struct mailbox *mailbox,
                       struct buf *buf, const char *prefix)
{
    buf_reset(buf);
    buf_printf(buf, "%s%u-" MODSEQ_FMT,
               prefix, mailbox->i.uidvalidity, mailbox->i.highestmodseq);
}

/* Callback to fetch DAV:sync-token and CS:getctag */
int propfind_sync_token(const xmlChar *name, xmlNsPtr ns,
                        struct propfind_ctx *fctx,
                        xmlNodePtr prop __attribute__((unused)),
                        xmlNodePtr resp __attribute__((unused)),
                        struct propstat propstat[],
                        void *rock)
{
    const char *prefix = (const char *) rock;

    if (!fctx->req_tgt->collection || /* until we support sync on cal-home */
        !fctx->mailbox || fctx->record) return HTTP_NOT_FOUND;

    /* not defined on the top-level collection either (aka #calendars) */
    if (!fctx->req_tgt->collection) return HTTP_NOT_FOUND;

    dav_get_synctoken(fctx->mailbox, &fctx->buf, prefix);

    xml_add_prop(HTTP_OK, fctx->ns[NS_DAV], &propstat[PROPSTAT_OK],
                 name, ns, BAD_CAST buf_cstring(&fctx->buf), 0);

    return 0;
}


/* Callback to fetch MC:bulk-requests */
int propfind_bulkrequests(const xmlChar *name, xmlNsPtr ns,
                          struct propfind_ctx *fctx,
                          xmlNodePtr prop __attribute__((unused)),
                          xmlNodePtr resp __attribute__((unused)),
                          struct propstat propstat[],
                          void *rock __attribute__((unused)))
{
    xmlNodePtr node = xml_add_prop(HTTP_OK, fctx->ns[NS_DAV],
                                   &propstat[PROPSTAT_OK], name, ns, NULL, 0);

    if (fctx->req_tgt->collection && !fctx->req_tgt->flags &&
        !fctx->req_tgt->resource) {
        xmlNodePtr type = xmlNewChild(node, NULL, BAD_CAST "simple", NULL);
        xmlNewChild(type, NULL, BAD_CAST "max-resources", NULL);
        xmlNewChild(type, NULL, BAD_CAST "max-bytes", NULL);
#if 0
        type = xmlNewChild(node, NULL, BAD_CAST "crud", NULL);
        xmlNewChild(type, NULL, BAD_CAST "max-resources", NULL);
        xmlNewChild(type, NULL, BAD_CAST "max-bytes", NULL);
#endif
    }

    return 0;
}


/* Callback to fetch properties from resource header */
int propfind_fromhdr(const xmlChar *name, xmlNsPtr ns,
                     struct propfind_ctx *fctx,
                     xmlNodePtr prop __attribute__((unused)),
                     xmlNodePtr resp __attribute__((unused)),
                     struct propstat propstat[],
                     void *rock)
{
    const char *hdrname = (const char *) rock;
    int r = HTTP_NOT_FOUND;

    if (fctx->record &&
        (mailbox_cached_header(hdrname) != BIT32_MAX) &&
        !mailbox_cacherecord(fctx->mailbox, fctx->record)) {
        unsigned size;
        struct protstream *stream;
        hdrcache_t hdrs = NULL;
        const char **hdr;

        size = cacheitem_size(fctx->record, CACHE_HEADERS);
        stream = prot_readmap(cacheitem_base(fctx->record,
                                             CACHE_HEADERS), size);
        hdrs = spool_new_hdrcache();
        spool_fill_hdrcache(stream, NULL, hdrs, NULL);
        prot_free(stream);

        if ((hdr = spool_getheader(hdrs, (const char *) hdrname))) {
            xml_add_prop(HTTP_OK, fctx->ns[NS_DAV], &propstat[PROPSTAT_OK],
                         name, ns, BAD_CAST hdr[0], 0);
            r = 0;
        }

        spool_free_hdrcache(hdrs);
    }

    return r;
}

static struct flaggedresources {
    const char *name;
    int flag;
} fres[] = {
    { "answered", FLAG_ANSWERED },
    { "flagged", FLAG_FLAGGED },
    { "seen", FLAG_SEEN },
    { NULL, 0 } /* last is always NULL */
};

/* Callback to write a property to annotation DB */
static int proppatch_toresource(xmlNodePtr prop, unsigned set,
                         struct proppatch_ctx *pctx,
                         struct propstat propstat[],
                         void *rock __attribute__((unused)))
{
    xmlChar *freeme = NULL;
    annotate_state_t *astate = NULL;
    struct buf value = BUF_INITIALIZER;
    int r = 1; /* default to error */

    /* flags only store "exists" */

    if (!strcmp((const char *)prop->ns->href, XML_NS_SYSFLAG)) {
        struct flaggedresources *frp;
        int isset;
        for (frp = fres; frp->name; frp++) {
            if (strcasecmp((const char *)prop->name, frp->name)) continue;
            r = 0; /* ok to do nothing */
            isset = pctx->record->system_flags & frp->flag;
            if (set) {
                if (isset) goto done;
                pctx->record->system_flags |= frp->flag;
            }
            else {
                if (!isset) goto done;
                pctx->record->system_flags &= ~frp->flag;
            }
            r = mailbox_rewrite_index_record(pctx->mailbox, pctx->record);
            goto done;
        }
        goto done;
    }

    if (!strcmp((const char *)prop->ns->href, XML_NS_USERFLAG)) {
        int userflag = 0;
        int isset;
        r = mailbox_user_flag(pctx->mailbox, (const char *)prop->name, &userflag, 1);
        if (r) goto done;
        isset = pctx->record->user_flags[userflag/32] & (1<<userflag%31);
        if (set) {
            if (isset) goto done;
            pctx->record->user_flags[userflag/32] |= (1<<userflag%31);
        }
        else {
            if (!isset) goto done;
            pctx->record->user_flags[userflag/32] &= ~(1<<userflag%31);
        }
        r = mailbox_rewrite_index_record(pctx->mailbox, pctx->record);
        goto done;
    }

    /* otherwise it's a database annotation */

    buf_reset(&pctx->buf);
    buf_printf(&pctx->buf, DAV_ANNOT_NS "<%s>%s",
               (const char *) prop->ns->href, prop->name);

    if (set) {
        freeme = xmlNodeGetContent(prop);
        buf_init_ro_cstr(&value, (const char *)freeme);
    }

    r = mailbox_get_annotate_state(pctx->mailbox, pctx->record->uid, &astate);
    if (!r) r = annotate_state_writemask(astate, buf_cstring(&pctx->buf),
                                         httpd_userid, &value);
    /* we need to rewrite the record to update the modseq because the layering
     * of annotations and mailboxes is broken */
    if (!r) r = mailbox_rewrite_index_record(pctx->mailbox, pctx->record);

 done:

    if (!r) {
        xml_add_prop(HTTP_OK, pctx->ns[NS_DAV], &propstat[PROPSTAT_OK],
                     prop->name, prop->ns, NULL, 0);
    }
    else {
        xml_add_prop(HTTP_SERVER_ERROR, pctx->ns[NS_DAV],
                     &propstat[PROPSTAT_ERROR], prop->name, prop->ns, NULL, 0);
    }

    buf_free(&value);
    if (freeme) xmlFree(freeme);

    return 0;
}


/* Callback to read a property from annotation DB */
static int propfind_fromresource(const xmlChar *name, xmlNsPtr ns,
                                 struct propfind_ctx *fctx,
                                 xmlNodePtr prop __attribute__((unused)),
                                 xmlNodePtr resp __attribute__((unused)),
                                 struct propstat propstat[],
                                 void *rock __attribute__((unused)))
{
    struct buf attrib = BUF_INITIALIZER;
    xmlNodePtr node;
    int r = 0; /* default no error */

    if (!strcmp((const char *)ns->href, XML_NS_SYSFLAG)) {
        struct flaggedresources *frp;
        int isset;
        for (frp = fres; frp->name; frp++) {
            if (strcasecmp((const char *)name, frp->name)) continue;
            isset = fctx->record->system_flags & frp->flag;
            if (isset)
                buf_setcstr(&attrib, "1");
            goto done;
        }
        goto done;
    }

    if (!strcmp((const char *)ns->href, XML_NS_USERFLAG)) {
        int userflag = 0;
        int isset;
        r = mailbox_user_flag(fctx->mailbox, (const char *)name, &userflag, 0);
        if (r) goto done;
        isset = fctx->record->user_flags[userflag/32] & (1<<userflag%31);
        if (isset)
            buf_setcstr(&attrib, "1");
        goto done;
    }

    /* otherwise it's a DB annotation */

    buf_reset(&fctx->buf);
    buf_printf(&fctx->buf, DAV_ANNOT_NS "<%s>%s",
               (const char *) ns->href, name);

    r = annotatemore_msg_lookup(fctx->mailbox->name, fctx->record->uid,
                                buf_cstring(&fctx->buf), NULL, &attrib);

done:
    if (r) r = HTTP_SERVER_ERROR;
    else if (!buf_len(&attrib)) r = HTTP_NOT_FOUND;

    if (!r) {
        node = xml_add_prop(HTTP_OK, fctx->ns[NS_DAV], &propstat[PROPSTAT_OK],
                            name, ns, NULL, 0);
        xmlAddChild(node, xmlNewCDataBlock(fctx->root->doc,
                                           BAD_CAST buf_cstring(&attrib),
                                           buf_len(&attrib)));
    }

    buf_free(&attrib);

    return r;
}


/* Callback to read a property from annotation DB */
int propfind_fromdb(const xmlChar *name, xmlNsPtr ns,
                    struct propfind_ctx *fctx,
                    xmlNodePtr prop, xmlNodePtr resp,
                    struct propstat propstat[], void *rock)
{
    struct buf attrib = BUF_INITIALIZER;
    xmlNodePtr node;
    int r = 0;

    if (fctx->req_tgt->resource) {
        if (!fctx->record) return HTTP_NOT_FOUND;
        return propfind_fromresource(name, ns, fctx, prop, resp, propstat, rock);
    }

    buf_reset(&fctx->buf);
    buf_printf(&fctx->buf, DAV_ANNOT_NS "<%s>%s",
               (const char *) ns->href, name);

    if (fctx->mbentry && !fctx->record) {
        r = annotatemore_lookupmask(fctx->mbentry->name,
                                    buf_cstring(&fctx->buf),
                                    httpd_userid, &attrib);
    }

    if (r) return HTTP_SERVER_ERROR;
    if (!buf_len(&attrib)) return HTTP_NOT_FOUND;

    node = xml_add_prop(HTTP_OK, fctx->ns[NS_DAV], &propstat[PROPSTAT_OK],
                        name, ns, NULL, 0);
    xmlAddChild(node, xmlNewCDataBlock(fctx->root->doc,
                                       BAD_CAST buf_cstring(&attrib),
                                       buf_len(&attrib)));

    buf_free(&attrib);

    return 0;
}

/* Callback to write a property to annotation DB */
int proppatch_todb(xmlNodePtr prop, unsigned set,
                   struct proppatch_ctx *pctx,
                   struct propstat propstat[],
                   void *rock)
{
    xmlChar *freeme = NULL;
    annotate_state_t *astate = NULL;
    struct buf value = BUF_INITIALIZER;
    int r;

    if (pctx->txn->req_tgt.resource)
        return proppatch_toresource(prop, set, pctx, propstat, NULL);

    buf_reset(&pctx->buf);
    buf_printf(&pctx->buf, DAV_ANNOT_NS "<%s>%s",
               (const char *) prop->ns->href, prop->name);

    if (set) {
        if (rock) {
            buf_init_ro_cstr(&value, (const char *)rock);
        }
        else {
            freeme = xmlNodeGetContent(prop);
            buf_init_ro_cstr(&value, (const char *)freeme);
        }
    }

    r = mailbox_get_annotate_state(pctx->mailbox, 0, &astate);
    if (!r) r = annotate_state_writemask(astate, buf_cstring(&pctx->buf),
                                         httpd_userid, &value);

    if (!r) {
        xml_add_prop(HTTP_OK, pctx->ns[NS_DAV], &propstat[PROPSTAT_OK],
                     prop->name, prop->ns, NULL, 0);
    }
    else {
        xml_add_prop(HTTP_SERVER_ERROR, pctx->ns[NS_DAV],
                     &propstat[PROPSTAT_ERROR], prop->name, prop->ns, NULL, 0);
    }

    buf_free(&value);
    if (freeme) xmlFree(freeme);

    return 0;
}

/* annotatemore_findall callback for adding dead properties (allprop/propname) */
static int allprop_cb(const char *mailbox __attribute__((unused)),
                      uint32_t uid __attribute__((unused)),
                      const char *entry,
                      const char *userid, const struct buf *attrib,
                      const struct annotate_metadata *mdata __attribute__((unused)),
                      void *rock)
{
    struct allprop_rock *arock = (struct allprop_rock *) rock;
    const struct prop_entry *pentry;
    char *href, *name;
    xmlNsPtr ns;
    xmlNodePtr node;

    /* Make sure its a shared entry or the user's private one */
    if (userid && *userid && strcmp(userid, arock->fctx->userid)) return 0;

    /* Split entry into namespace href and name ( <href>name ) */
    buf_setcstr(&arock->fctx->buf, entry + strlen(DAV_ANNOT_NS) + 1);
    href = (char *) buf_cstring(&arock->fctx->buf);
    if ((name = strchr(href, '>'))) *name++ = '\0';
    else if ((name = strchr(href, ':'))) *name++ = '\0';

    /* Look for a match against live properties */
    for (pentry = arock->fctx->lprops;
         pentry->name &&
             (strcmp(name, pentry->name) ||
              strcmp(href, known_namespaces[pentry->ns].href));
         pentry++);

    if (pentry->name &&
        (arock->fctx->mode == PROPFIND_ALL    /* Skip all live properties */
         || (pentry->flags & PROP_ALLPROP)))  /* Skip those already included */
        return 0;

    /* Look for an instance of this namespace in our response */
    ns = hash_lookup(href, arock->fctx->ns_table);

    /* XXX - can return the same property multiple times with annotate masks! */

    /* Add the dead property to the response */
    node = xml_add_prop(HTTP_OK, arock->fctx->ns[NS_DAV],
                        &arock->propstat[PROPSTAT_OK],
                        BAD_CAST name, ns, NULL, 0);
    if (!ns) {
        /* Add the namespace directly to the property -
           its too late to add it to the root when chunking the responses */
        char prefix[9];
        snprintf(prefix, sizeof(prefix), "X%X", strhash(href));
        xmlSetNs(node, xmlNewNs(node, BAD_CAST href, BAD_CAST prefix));
    }

    if (arock->fctx->mode == PROPFIND_ALL) {
        xmlAddChild(node, xmlNewCDataBlock(arock->fctx->root->doc,
                                           BAD_CAST attrib->s, attrib->len));
    }

    return 0;
}


static int prescreen_prop(const struct prop_entry *entry,
                          xmlNodePtr prop,
                          struct propfind_ctx *fctx)
{
    unsigned allowed = 1;

    if (fctx->req_tgt->resource && !(entry->flags & PROP_RESOURCE)) allowed = 0;
    else if (entry->flags & PROP_PRESCREEN) {
        allowed = !entry->get(BAD_CAST entry->name, NULL, fctx,
                              prop, NULL, NULL, entry->rock);
    }

    return allowed;
}


/* Parse the requested properties and create a linked list of fetch callbacks.
 * The list gets reused for each href if Depth > 0
 */
HIDDEN int preload_proplist(xmlNodePtr proplist, struct propfind_ctx *fctx)
{
    int ret = 0;
    xmlNodePtr prop;
    const struct prop_entry *entry;
    struct propfind_entry_list *tail = NULL;

    switch (fctx->mode) {
    case PROPFIND_ALL:
    case PROPFIND_NAME:
        /* Add live properties for allprop/propname */
        for (entry = fctx->lprops; entry->name; entry++) {
            if (entry->flags & PROP_ALLPROP) {
                /* Pre-screen request based on prop flags */
                int allowed = prescreen_prop(entry, NULL, fctx);

                if (allowed || fctx->mode == PROPFIND_ALL) {
                    struct propfind_entry_list *nentry =
                        xzmalloc(sizeof(struct propfind_entry_list));

                    ensure_ns(fctx->ns, entry->ns, fctx->root,
                              known_namespaces[entry->ns].href,
                              known_namespaces[entry->ns].prefix);

                    nentry->name = xmlStrdup(BAD_CAST entry->name);
                    nentry->ns = fctx->ns[entry->ns];
                    if (allowed) {
                        nentry->flags = entry->flags;
                        nentry->get = entry->get;
                        nentry->prop = NULL;
                        nentry->rock = entry->rock;
                    }

                    /* Append new entry to linked list */
                    if (tail) {
                        tail->next = nentry;
                        tail = nentry;
                    }
                    else tail = fctx->elist = nentry;
                }
            }
        }
        /* Fall through and build hash table of namespaces */
        GCC_FALLTHROUGH

    case PROPFIND_EXPAND:
        /* Add all namespaces attached to the response to our hash table */
        if (!fctx->ns_table->size) {
            xmlNsPtr nsDef;

            construct_hash_table(fctx->ns_table, 10, 1);

            for (nsDef = fctx->root->nsDef; nsDef; nsDef = nsDef->next) {
                hash_insert((const char *) nsDef->href, nsDef, fctx->ns_table);
            }
        }
    }

    /* Iterate through requested properties */
    for (prop = proplist; !*fctx->ret && prop; prop = prop->next) {
        if (prop->type == XML_ELEMENT_NODE) {
            struct propfind_entry_list *nentry;
            xmlChar *name, *namespace = NULL;
            xmlNsPtr ns;
            const char *ns_href;
            unsigned i;

            if (!prop->ns) return HTTP_BAD_REQUEST;

            ns = prop->ns;
            ns_href = (const char *) ns->href;

            if (fctx->mode == PROPFIND_EXPAND) {
                /* Get name/namespace from <property> */
                name = xmlGetProp(prop, BAD_CAST "name");
                namespace = xmlGetProp(prop, BAD_CAST "namespace");

                if (namespace) {
                    ns_href = (const char *) namespace;
                    ns = NULL;
                }
            }
            else {
                /* node IS the property */
                name = xmlStrdup(prop->name);
            }

            /* Look for this namespace in our known array */
            for (i = 0; i < NUM_NAMESPACE; i++) {
                if (!strcmp(ns_href, known_namespaces[i].href)) {
                    ensure_ns(fctx->ns, i, fctx->root,
                              known_namespaces[i].href,
                              known_namespaces[i].prefix);
                    ns = fctx->ns[i];
                    break;
                }
            }

            if (namespace) {
                if (!ns) {
                    /* Look for namespace in hash table */
                    ns = hash_lookup(ns_href, fctx->ns_table);
                    if (!ns) {
                        char prefix[6];
                        snprintf(prefix, sizeof(prefix),
                                 "X%X", strhash(ns_href) & 0xffff);
                        ns = xmlNewNs(fctx->root,
                                      BAD_CAST ns_href, BAD_CAST prefix);
                        hash_insert(ns_href, ns, fctx->ns_table);
                    }
                }
                xmlFree(namespace);
            }

            /* Look for a match against our known properties */
            for (entry = fctx->lprops;
                 entry->name &&
                     (strcmp((const char *) name, entry->name) ||
                      strcmp((const char *) ns->href,
                             known_namespaces[entry->ns].href));
                 entry++);

            /* Skip properties already included by allprop */
            if (fctx->mode == PROPFIND_ALL && (entry->flags & PROP_ALLPROP)) {
                xmlFree(name);
                continue;
            }

            nentry = xzmalloc(sizeof(struct propfind_entry_list));
            nentry->name = name;
            nentry->ns = ns;
            if (entry->name) {
                /* Found a match - Pre-screen request based on prop flags */
                if (prescreen_prop(entry, prop, fctx)) {
                    nentry->flags = entry->flags;
                    nentry->get = entry->get;
                    nentry->prop = prop;
                    nentry->rock = entry->rock;
                }
                ret = *fctx->ret;
            }
            else {
                /* No match, treat as a dead property.
                   Need to look at both collections and resources */
                nentry->flags = PROP_COLLECTION | PROP_RESOURCE;
                nentry->get = propfind_fromdb;
                nentry->prop = NULL;
                nentry->rock = NULL;
            }

            /* Append new entry to linked list */
            if (tail) {
                tail->next = nentry;
                tail = nentry;
            }
            else tail = fctx->elist = nentry;
        }
    }

    return ret;
}


/* Execute the given property patch instructions */
static int do_proppatch(struct proppatch_ctx *pctx, xmlNodePtr instr)
{
    struct propstat propstat[NUM_PROPSTAT];
    int i;

    memset(propstat, 0, NUM_PROPSTAT * sizeof(struct propstat));

    /* Iterate through propertyupdate children */
    for (; instr; instr = instr->next) {
        if (instr->type == XML_ELEMENT_NODE) {
            xmlNodePtr prop;
            unsigned set = 0;

            if (!xmlStrcmp(instr->name, BAD_CAST "set")) set = 1;
            else if ((pctx->txn->meth == METH_PROPPATCH) &&
                     !xmlStrcmp(instr->name, BAD_CAST "remove")) set = 0;
            else {
                syslog(LOG_INFO, "Unknown PROPPATCH instruction");
                pctx->txn->error.desc = "Unknown PROPPATCH instruction";
                return HTTP_BAD_REQUEST;
            }

            /* Find child element */
            for (prop = instr->children;
                 prop && prop->type != XML_ELEMENT_NODE; prop = prop->next);
            if (!prop || xmlStrcmp(prop->name, BAD_CAST "prop")) {
                pctx->txn->error.desc = "Missing prop element";
                return HTTP_BAD_REQUEST;
            }

            /* Iterate through requested properties */
            for (prop = prop->children; prop; prop = prop->next) {
                if (prop->type == XML_ELEMENT_NODE) {
                    const struct prop_entry *entry;

                    /* Look for a match against our known properties */
                    for (entry = pctx->lprops;
                         entry->name &&
                             (strcmp((const char *) prop->name, entry->name) ||
                              !prop->ns ||
                              strcmp((const char *) prop->ns->href,
                                     known_namespaces[entry->ns].href));
                         entry++);

                    if (entry->name) {
                        int rights = httpd_myrights(httpd_authstate,
                                                    pctx->txn->req_tgt.mbentry);
                        if (!entry->put) {
                            /* Protected property */
                            xml_add_prop(HTTP_FORBIDDEN, pctx->ns[NS_DAV],
                                         &propstat[PROPSTAT_FORBID],
                                         prop->name, prop->ns, NULL,
                                         DAV_PROT_PROP);
                            *pctx->ret = HTTP_FORBIDDEN;
                        }
                        else if ((pctx->txn->meth == METH_PROPPATCH) &&
                                 !(rights & ((entry->flags & PROP_PERUSER) ?
                                             DACL_READ : DACL_PROPCOL))) {
                            /* DAV:need-privileges */
                            xml_add_prop(HTTP_FORBIDDEN, pctx->ns[NS_DAV],
                                         &propstat[PROPSTAT_FORBID],
                                         prop->name, prop->ns, NULL,
                                         DAV_NEED_PRIVS);
                            *pctx->ret = HTTP_FORBIDDEN;
                        }
                        else {
                            /* Write "live" property */
                            entry->put(prop, set, pctx, propstat, entry->rock);
                        }
                    }
                    else if (!prop->ns) {
                        /* Property with no namespace */
                        xmlNodePtr newprop =
                            xml_add_prop(HTTP_FORBIDDEN, pctx->ns[NS_DAV],
                                         &propstat[PROPSTAT_FORBID],
                                         prop->name, NULL, NULL, 0);
                        xmlSetNs(newprop, NULL);
                        *pctx->ret = HTTP_FORBIDDEN;
                    }
                    else if (pctx->txn->req_tgt.namespace->id != URL_NS_PRINCIPAL) {
                        /* Write "dead" property */
                        proppatch_todb(prop, set, pctx, propstat, NULL);
                    }
                }
            }
        }
    }

    /* One or more of the properties failed */
    if (*pctx->ret && propstat[PROPSTAT_OK].root) {
        /* 200 status must become 424 */
        propstat[PROPSTAT_FAILEDDEP].root = propstat[PROPSTAT_OK].root;
        propstat[PROPSTAT_FAILEDDEP].status = HTTP_FAILED_DEP;
        propstat[PROPSTAT_OK].root = NULL;
    }

    /* Add status and optional error to the propstat elements
       and then add them to the response element */
    for (i = 0; i < NUM_PROPSTAT; i++) {
        struct propstat *stat = &propstat[i];

        if (stat->root) {
            xmlNewChild(stat->root, NULL, BAD_CAST "status",
                        BAD_CAST http_statusline(VER_1_1, stat->status));
            if (stat->precond) {
                struct error_t error = { NULL, stat->precond, NULL, NULL, 0 };
                xml_add_error(stat->root, &error, pctx->ns);
            }

            xmlAddChild(pctx->root, stat->root);
        }
    }

    return 0;
}


/* Parse an XML body into a tree */
int parse_xml_body(struct transaction_t *txn, xmlNodePtr *root,
                   const char *spec_type)
{
    const char **hdr;
    xmlDocPtr doc = NULL;
    int r = 0;

    *root = NULL;

    /* Read body */
    txn->req_body.flags |= BODY_DECODE;
    r = http_read_req_body(txn);
    if (r) {
        txn->flags.conn = CONN_CLOSE;
        return r;
    }

    if (!buf_len(&txn->req_body.payload)) return 0;

    /* Check Content-Type */
    if (!(hdr = spool_getheader(txn->req_hdrs, "Content-Type")) ||
        (!is_mediatype("text/xml", hdr[0]) &&
         !is_mediatype("application/xml", hdr[0]) &&
         !(spec_type && is_mediatype(spec_type, hdr[0])))) {
        txn->error.desc = "This method requires an XML body";
        return HTTP_BAD_MEDIATYPE;
    }

    /* Parse the XML request */
    doc = xmlCtxtReadMemory(txn->conn->xml, buf_cstring(&txn->req_body.payload),
                            buf_len(&txn->req_body.payload), NULL, NULL,
                            XML_PARSE_NOERROR | XML_PARSE_NOWARNING);
    if (!doc) {
        txn->error.desc = "Unable to parse XML body";
        return HTTP_BAD_REQUEST;
    }
    else {
        xmlErrorPtr err = xmlCtxtGetLastError(txn->conn->xml);
        if (err) {
            xmlFreeDoc(doc);
            txn->error.desc = err->message;
            return HTTP_BAD_REQUEST;
        }
    }

    /* Get the root element of the XML request */
    if (!(*root = xmlDocGetRootElement(doc))) {
        xmlFreeDoc(doc);
        txn->error.desc = "Missing root element in request";
        return HTTP_BAD_REQUEST;
    }

    return 0;
}

/* Perform an ACL request
 *
 * preconditions:
 *   DAV:no-ace-conflict
 *   DAV:no-protected-ace-conflict
 *   DAV:no-inherited-ace-conflict
 *   DAV:limited-number-of-aces
 *   DAV:deny-before-grant
 *   DAV:grant-only
 *   DAV:no-invert
 *   DAV:no-abstract
 *   DAV:not-supported-privilege
 *   DAV:missing-required-principal
 *   DAV:recognized-principal
 *   DAV:allowed-principal
 *
 * The standard behavior of the ACL method is to completely replace the existing
 * ACL with the one in the request.  We treat the <deny> element as providing
 * "negative" rights (-identifier) in IMAP-speak.  Additionally, we treat
 * the special DAV identifiers as follows:
 *
 *   <all> == IMAP "anyone"
 *   <unauthenticated> == IMAP "anonymous"
 *   <authenticated> == IMAP "anyone -anonymous"
 */
int meth_acl(struct transaction_t *txn, void *params)
{
    struct meth_params *aparams = (struct meth_params *) params;
    int ret = 0, r, rights;
    xmlDocPtr indoc = NULL;
    xmlNodePtr root, ace;
    struct mailbox *mailbox = NULL;
    struct buf acl = BUF_INITIALIZER;

    /* Response should not be cached */
    txn->flags.cc |= CC_NOCACHE;

    /* Parse the path */
    r = dav_parse_req_target(txn, aparams);
    if (r) return r;

    /* Make sure method is allowed (only allowed on collections) */
    if (!(txn->req_tgt.allow & ALLOW_ACL)) {
        txn->error.desc = "ACLs can only be set on collections";
        syslog(LOG_DEBUG, "Tried to set ACL on non-collection");
        return HTTP_NOT_ALLOWED;
    }

    if (!mboxname_userownsmailbox(httpd_userid, txn->req_tgt.mbentry->name)) {
        /* Check ACL for current user */
        rights = httpd_myrights(httpd_authstate, txn->req_tgt.mbentry);
        if (!(rights & DACL_ADMIN)) {
            /* DAV:need-privileges */
            txn->error.precond = DAV_NEED_PRIVS;
            txn->error.resource = txn->req_tgt.path;
            txn->error.rights = DACL_ADMIN;
            return HTTP_NO_PRIVS;
        }
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

    /* Parse the ACL body */
    ret = parse_xml_body(txn, &root, NULL);
    if (!ret && !root) {
        txn->error.desc = "Missing request body";
        ret = HTTP_BAD_REQUEST;
    }
    if (ret) goto done;

    indoc = root->doc;

    /* Make sure its an DAV:acl element */
    if (!root->ns || xmlStrcmp(root->ns->href, BAD_CAST XML_NS_DAV) ||
        xmlStrcmp(root->name, BAD_CAST "acl")) {
        txn->error.desc = "Missing DAV:acl element in ACL request";
        ret = HTTP_BAD_REQUEST;
        goto done;
    }

    /* Open mailbox for writing */
    r = mailbox_open_iwl(txn->req_tgt.mbentry->name, &mailbox);
    if (r) {
        syslog(LOG_ERR, "http_mailbox_open(%s) failed: %s",
               txn->req_tgt.mbentry->name, error_message(r));
        txn->error.desc = error_message(r);
        ret = HTTP_SERVER_ERROR;
        goto done;
    }

    /* Parse the DAV:ace elements */
    for (ace = root->children; ace; ace = ace->next) {
        if (ace->type == XML_ELEMENT_NODE) {
            xmlNodePtr child = NULL, prin = NULL, privs = NULL;
            const char *userid = NULL;
            int deny = 0, rights = 0;
            char *freeme = NULL;
            char rightstr[100];
            struct request_target_t tgt;

            for (child = ace->children; child; child = child->next) {
                if (child->type == XML_ELEMENT_NODE) {
                    if (!xmlStrcmp(child->name, BAD_CAST "principal")) {
                        if (prin) {
                            txn->error.desc = "Multiple principals in ACE";
                            ret = HTTP_BAD_REQUEST;
                            goto done;
                        }

                        for (prin = child->children; prin &&
                             prin->type != XML_ELEMENT_NODE; prin = prin->next);
                        if (!prin) {
                            txn->error.desc = "Empty principal in ACE";
                            ret = HTTP_BAD_REQUEST;
                            goto done;
                        }
                    }
                    else if (!xmlStrcmp(child->name, BAD_CAST "grant")) {
                        if (privs) {
                            txn->error.desc = "Multiple grant|deny in ACE";
                            ret = HTTP_BAD_REQUEST;
                            goto done;
                        }

                        for (privs = child->children; privs &&
                             privs->type != XML_ELEMENT_NODE; privs = privs->next);
                    }
                    else if (!xmlStrcmp(child->name, BAD_CAST "deny")) {
                        if (privs) {
                            txn->error.desc = "Multiple grant|deny in ACE";
                            ret = HTTP_BAD_REQUEST;
                            goto done;
                        }

                        for (privs = child->children; privs &&
                             privs->type != XML_ELEMENT_NODE; privs = privs->next);
                        deny = 1;
                    }
                    else if (!xmlStrcmp(child->name, BAD_CAST "invert")) {
                        /* DAV:no-invert */
                        txn->error.precond = DAV_NO_INVERT;
                        ret = HTTP_FORBIDDEN;
                        goto done;
                    }
                    else {
                        txn->error.desc = "Unknown element in ACE";
                        ret = HTTP_BAD_REQUEST;
                        goto done;
                    }
                }
            }

            if (!xmlStrcmp(prin->name, BAD_CAST "self")) {
                userid = httpd_userid;
            }
            else if (!xmlStrcmp(prin->name, BAD_CAST "owner")) {
                userid = freeme = mboxname_to_userid(txn->req_tgt.mbentry->name);
            }
            else if (!xmlStrcmp(prin->name, BAD_CAST "all")) {
                userid = "anyone";
            }
            else if (!xmlStrcmp(prin->name, BAD_CAST "authenticated")) {
                if (deny) {
                    /* DAV:grant-only */
                    txn->error.precond = DAV_GRANT_ONLY;
                    ret = HTTP_FORBIDDEN;
                    goto done;
                }
                userid = "\a"; /* flagged for use below */
            }
            else if (!xmlStrcmp(prin->name, BAD_CAST "unauthenticated")) {
                userid = "anonymous";
            }
            else if (!xmlStrcmp(prin->name, BAD_CAST "href")) {
                xmlChar *href = xmlNodeGetContent(prin);
                xmlURIPtr uri;
                const char *errstr = NULL;
                size_t plen = strlen(namespace_principal.prefix);

                uri = parse_uri(METH_UNKNOWN, (const char *) href, 1, &errstr);
                if (uri &&
                    !strncmp(namespace_principal.prefix, uri->path, plen) &&
                    uri->path[plen] == '/') {
                    memset(&tgt, 0, sizeof(struct request_target_t));
                    tgt.namespace = &namespace_principal;
                    /* XXX: there is no doubt that this leaks memory */
                    r = principal_parse_path(uri->path, &tgt, &errstr);
                    if (!r && tgt.userid) userid = tgt.userid;
                }
                if (uri) xmlFreeURI(uri);
                xmlFree(href);
            }

            if (!userid) {
                /* DAV:recognized-principal */
                txn->error.precond = DAV_RECOG_PRINC;
                ret = HTTP_FORBIDDEN;
                free(freeme);
                goto done;
            }

            for (; privs; privs = privs->next) {
                if (privs->type == XML_ELEMENT_NODE) {
                    xmlNodePtr priv = privs->children;
                    for (; priv->type != XML_ELEMENT_NODE; priv = priv->next);

                    if (aparams->acl_ext &&
                        aparams->acl_ext(txn, priv, &rights)) {
                        /* Extension (CalDAV) privileges */
                        if (txn->error.precond) {
                            ret = HTTP_FORBIDDEN;
                            free(freeme);
                            goto done;
                        }
                    }
                    else if (!xmlStrcmp(priv->ns->href,
                                        BAD_CAST XML_NS_DAV)) {
                        /* WebDAV privileges */
                        if (!xmlStrcmp(priv->name,
                                       BAD_CAST "all")) {
                            if (deny)
                                rights |= ACL_FULL; /* wipe EVERYTHING */
                            else
                                rights |= DACL_ALL;
                        }
                        else if (!xmlStrcmp(priv->name,
                                            BAD_CAST "read"))
                            rights |= DACL_READ;
                        else if (!xmlStrcmp(priv->name,
                                            BAD_CAST "write"))
                            rights |= DACL_WRITE;
                        else if (!xmlStrcmp(priv->name,
                                            BAD_CAST "write-content"))
                            rights |= DACL_WRITECONT;
                        else if (!xmlStrcmp(priv->name,
                                            BAD_CAST "write-properties"))
                            rights |= DACL_WRITEPROPS;
                        else if (!xmlStrcmp(priv->name,
                                            BAD_CAST "bind"))
                            rights |= DACL_BIND;
                        else if (!xmlStrcmp(priv->name,
                                            BAD_CAST "unbind"))
                            rights |= DACL_UNBIND;
                        else if (!xmlStrcmp(priv->name,
                                            BAD_CAST "read-current-user-privilege-set")
                                 || !xmlStrcmp(priv->name,
                                               BAD_CAST "read-acl")
                                 || !xmlStrcmp(priv->name,
                                               BAD_CAST "write-acl")
                                 || !xmlStrcmp(priv->name,
                                               BAD_CAST "unlock")
                                 || !xmlStrcmp(priv->name,
                                               BAD_CAST "share")) {
                            /* DAV:no-abstract */
                            txn->error.precond = DAV_NO_ABSTRACT;
                            ret = HTTP_FORBIDDEN;
                            free(freeme);
                            goto done;
                        }
                        else {
                            /* DAV:not-supported-privilege */
                            txn->error.precond = DAV_SUPP_PRIV;
                            ret = HTTP_FORBIDDEN;
                            free(freeme);
                            goto done;
                        }
                    }
                    else if (!xmlStrcmp(priv->ns->href,
                                   BAD_CAST XML_NS_CALDAV)) {
                        if (!xmlStrcmp(priv->name,
                                       BAD_CAST "read-free-busy"))
                            rights |= DACL_READFB;
                        else {
                            /* DAV:not-supported-privilege */
                            txn->error.precond = DAV_SUPP_PRIV;
                            ret = HTTP_FORBIDDEN;
                            free(freeme);
                            goto done;
                        }
                    }
                    else if (!xmlStrcmp(priv->ns->href,
                                   BAD_CAST XML_NS_CYRUS)) {
                        /* Cyrus-specific privileges */
                        if (!xmlStrcmp(priv->name,
                                       BAD_CAST "write-properties-collection"))
                            rights |= DACL_PROPCOL;
                        else if (!xmlStrcmp(priv->name,
                                       BAD_CAST "write-properties-resource"))
                            rights |= DACL_PROPRSRC;
                        else if (!xmlStrcmp(priv->name,
                                       BAD_CAST "make-collection"))
                            rights |= DACL_MKCOL;
                        else if (!xmlStrcmp(priv->name,
                                       BAD_CAST "remove-collection"))
                            rights |= DACL_RMCOL;
                        else if (!xmlStrcmp(priv->name,
                                       BAD_CAST "add-resource"))
                            rights |= DACL_ADDRSRC;
                        else if (!xmlStrcmp(priv->name,
                                       BAD_CAST "remove-resource"))
                            rights |= DACL_RMRSRC;
                        else if (!xmlStrcmp(priv->name,
                                       BAD_CAST "admin"))
                            rights |= DACL_ADMIN;
                        else {
                            /* DAV:not-supported-privilege */
                            txn->error.precond = DAV_SUPP_PRIV;
                            ret = HTTP_FORBIDDEN;
                            free(freeme);
                            goto done;
                        }
                    }
                    else {
                        /* DAV:not-supported-privilege */
                        txn->error.precond = DAV_SUPP_PRIV;
                        ret = HTTP_FORBIDDEN;
                        free(freeme);
                        goto done;
                    }
                }
            }

            /* gotta have something to do! */
            if (rights) {
                cyrus_acl_masktostr(rights, rightstr);

                if (*userid == '\a') {
                    /* authenticated = "anyone -anonymous" */
                    buf_printf(&acl, "anyone\t%s\t-anonymous\t%s\t",
                               rightstr, rightstr);
                }
                else {
                    buf_printf(&acl, "%s%s\t%s\t",
                               deny ? "-" : "", userid, rightstr);
                }
            }

            free(freeme);
        }
    }

    r = mboxlist_sync_setacls(txn->req_tgt.mbentry->name, buf_cstring(&acl), mailbox_modseq_dirty(mailbox));
    if (!r) r = mailbox_set_acl(mailbox, buf_cstring(&acl));
    if (!r) {
        char *userid = mboxname_to_userid(txn->req_tgt.mbentry->name);
        r = caldav_update_shareacls(userid);
        free(userid);
    }
    if (r) {
        syslog(LOG_ERR, "mboxlist_sync_setacls(%s) failed: %s",
               txn->req_tgt.mbentry->name, error_message(r));
        txn->error.desc = error_message(r);
        ret = HTTP_SERVER_ERROR;
        goto done;
    }

    response_header(HTTP_OK, txn);

  done:
    buf_free(&acl);
    if (indoc) xmlFreeDoc(indoc);
    mailbox_close(&mailbox);
    return ret;
}


struct move_rock {
    int omlen;
    int nmlen;
    struct buf newname;
    const char *urlprefix;
    xmlNodePtr root;
    xmlNsPtr ns[NUM_NAMESPACE];
};

/* Callback for use by dav_move_collection() to move single collection */
static int move_collection(const mbentry_t *mbentry, void *rock)
{
    struct move_rock *mrock = (struct move_rock *) rock;
    int r = 0;

    buf_truncate(&mrock->newname, mrock->nmlen);
    buf_appendcstr(&mrock->newname, mbentry->name + mrock->omlen);

    if (buf_len(&mrock->newname) >= MAX_MAILBOX_NAME) {
        r = IMAP_MAILBOX_BADNAME;
    }
    else {
        /* Rename mailbox -
           Pretend we're an admin since we already renamed the parent */
        r = mboxlist_renamemailbox(mbentry, buf_cstring(&mrock->newname),
                                   NULL /* partition */, 0 /* uidvalidity */,
                                   1 /* admin */, httpd_userid, httpd_authstate,
                                   NULL, 0, 0, 1 /* ignorequota */, 0, 0, 0);
    }

    if (r) {
        struct error_t err = { error_message(r), 0, NULL, NULL, 0 };
        struct buf href = BUF_INITIALIZER;
        xmlNodePtr resp;
        mbname_t *mbname;
        const strarray_t *boxes;
        int n, size, code;

        if (!mrock->root) {
            /* Create new <multistatus> */
            mrock->root =
                init_xml_response("multistatus", NS_DAV, NULL, mrock->ns);
            if (!mrock->root) return HTTP_SERVER_ERROR;
        }

        /* Add new <response> element */
        resp = xmlNewChild(mrock->root, mrock->ns[NS_DAV],
                           BAD_CAST "response", NULL);
        if (!resp) return HTTP_SERVER_ERROR;

        /* Generate href for destination collection */
        mbname = mbname_from_intname(buf_cstring(&mrock->newname));

        buf_setcstr(&href, mrock->urlprefix);

        if (mbname_localpart(mbname)) {
            const char *domain =
                mbname_domain(mbname) ? mbname_domain(mbname) :
                httpd_extradomain;

            buf_printf(&href, "/%s/%s",
                       USER_COLLECTION_PREFIX, mbname_localpart(mbname));
            if (domain) buf_printf(&href, "@%s", domain);
        }
        buf_putc(&href, '/');

        boxes = mbname_boxes(mbname);
        size = strarray_size(boxes);
        for (n = 1; n < size; n++) {
            buf_appendcstr(&href, strarray_nth(boxes, n));
            buf_putc(&href, '/');
        }
        mbname_free(&mbname);

        /* Add <href> element */
        xml_add_href(resp, NULL, buf_cstring(&href));

        /* Determine HTTP response code */
        switch (r) {
        case IMAP_MAILBOX_BADNAME:
            code = HTTP_FORBIDDEN;
            break;

        case IMAP_MAILBOX_EXISTS:
            code = HTTP_PRECOND_FAILED;
            break;

        case IMAP_PERMISSION_DENIED:
            code = HTTP_FORBIDDEN;
            err.precond = DAV_NEED_PRIVS;
            err.rights = DACL_UNBIND;
            err.resource = buf_cstring(&href);
            break;

        default:
            code = HTTP_SERVER_ERROR;
            break;
        }

        /* Add <status> element */
        xmlNewChild(resp, NULL, BAD_CAST "status",
                    BAD_CAST http_statusline(VER_1_1, code));

        /* Add <error> element */
        xml_add_error(resp, &err, mrock->ns);

        buf_free(&href);

        /* XXX  Per RFC 4918, we SHOULD continue to move non-children */
    }

    return r;
}

/* Callback for use by dav_move_collection() ro remove a single collection */
static int remove_collection(const mbentry_t *mbentry,
                             void *rock __attribute__((unused)))
{
    int r;

    /* Delete mailbox -
       Pretend we're an admin since we already deleted the parent */
    if (mboxlist_delayed_delete_isenabled()) {
        r = mboxlist_delayed_deletemailbox(mbentry->name, 1, /* admin */
                                           httpd_userid, httpd_authstate,
                                           NULL, MBOXLIST_DELETE_CHECKACL);

    }
    else {
        r = mboxlist_deletemailbox(mbentry->name, 1, /* admin */
                                   httpd_userid, httpd_authstate,
                                   NULL, MBOXLIST_DELETE_CHECKACL);
    }

    return r;
}

static int dav_move_collection(struct transaction_t *txn,
                               struct request_target_t *dest_tgt,
                               int overwrite)
{
    int r = 0, recursive = 1, rights;
    int omlen, nmlen;
    char *oldmailboxname = txn->req_tgt.mbentry->name;
    char *newmailboxname = dest_tgt->mbentry->name;
    struct mboxevent *mboxevent = NULL;

    /* Make sure we're moving within the same user */
    if (!mboxname_same_userid(newmailboxname, oldmailboxname)) {
        txn->error.desc = "Can only move within same user";
        return HTTP_FORBIDDEN;
    }

    /* Check ACL for current user on source mailbox */
    rights = httpd_myrights(httpd_authstate, txn->req_tgt.mbentry);
    if ((rights & DACL_UNBIND) != DACL_UNBIND) {
        /* DAV:need-privileges */
        txn->error.precond = DAV_NEED_PRIVS;
        txn->error.resource = txn->req_tgt.path;
        txn->error.rights = DACL_UNBIND;
        return HTTP_NO_PRIVS;
    }

    if (txn->req_tgt.mbentry->server) {
        /* Remote source mailbox */
        struct backend *be;

        be = proxy_findserver(txn->req_tgt.mbentry->server,
                              &http_protocol, httpd_userid,
                              &backend_cached, NULL, NULL, httpd_in);
        if (!be) return HTTP_UNAVAILABLE;

        return http_pipe_req_resp(be, txn);
    }

    /* Local source mailbox */

    /* If we're renaming something inside of something else,
       don't recursively rename */
    omlen = strlen(oldmailboxname);
    nmlen = strlen(newmailboxname);
    if (omlen < nmlen) {
        if (!strncmp(oldmailboxname, newmailboxname, omlen) &&
            newmailboxname[omlen] == '.') {
            recursive = 0;
        }
    } else {
        if (!strncmp(oldmailboxname, newmailboxname, nmlen) &&
            oldmailboxname[nmlen] == '.') {
            recursive = 0;
        }
    }

    struct mboxlock *namespacelock = mboxname_usernamespacelock(newmailboxname);

    r = mboxlist_createmailboxcheck(newmailboxname, 0, NULL, httpd_userisadmin,
                                    httpd_userid, httpd_authstate,
                                    NULL, NULL, 0 /* force */);

    if (r == IMAP_MAILBOX_EXISTS && overwrite) {
        /* Attempt to delete existing base mailbox */
        overwrite = -1;

        mboxevent = mboxevent_new(EVENT_MAILBOX_DELETE);

        if (mboxlist_delayed_delete_isenabled()) {
            r = mboxlist_delayed_deletemailbox(newmailboxname,
                                               httpd_userisadmin,
                                               httpd_userid, httpd_authstate,
                                               mboxevent, MBOXLIST_DELETE_CHECKACL);

        }
        else {
            r = mboxlist_deletemailbox(newmailboxname,
                                       httpd_userisadmin,
                                       httpd_userid, httpd_authstate,
                                       mboxevent, MBOXLIST_DELETE_CHECKACL);
        }

        if (!r) mboxevent_notify(&mboxevent);
        mboxevent_free(&mboxevent);

        /* Attempt to delete all existing submailboxes */
        if (!r && recursive) {
            char nmbn[MAX_MAILBOX_BUFFER];

            strcpy(nmbn, newmailboxname);
            strcat(nmbn, ".");

            r = mboxlist_allmbox(nmbn, remove_collection, NULL, 0);
        }
    }
    if (r) goto done;

    /* Attempt to rename the base mailbox */
    mboxevent = mboxevent_new(EVENT_MAILBOX_RENAME);

    r = mboxlist_renamemailbox(txn->req_tgt.mbentry, newmailboxname,
                               NULL /* partition */, 0 /* uidvalidity */,
                               httpd_userisadmin, httpd_userid, httpd_authstate,
                               mboxevent, 0, 0, 1 /* ignorequota */, 0, 0, 0);

    if (!r) mboxevent_notify(&mboxevent);
    mboxevent_free(&mboxevent);

    /* Attempt to rename all submailboxes */
    if (!r && recursive) {
        char ombn[MAX_MAILBOX_BUFFER];
        struct move_rock mrock = { ++omlen, ++nmlen, BUF_INITIALIZER,
                                   dest_tgt->namespace->prefix, NULL, {0} };

        strcpy(ombn, oldmailboxname);
        strcat(ombn, ".");

        /* Setup the rock */
        buf_setcstr(&mrock.newname, newmailboxname);
        buf_putc(&mrock.newname, '.');

        r = mboxlist_allmbox(ombn, move_collection, &mrock, 0);
        buf_free(&mrock.newname);

        if (mrock.root) {
            mboxname_release(&namespacelock);
            sync_checkpoint(txn->conn->pin);
            xml_response(HTTP_MULTI_STATUS, txn, mrock.root->doc);
            xmlFreeDoc(mrock.root->doc);
            return 0;
        }
    }

  done:
    mboxname_release(&namespacelock);
    switch (r) {
    case 0:
        sync_checkpoint(txn->conn->pin);
        return (overwrite < 0) ? HTTP_NO_CONTENT : HTTP_CREATED;

    case IMAP_MAILBOX_EXISTS:
        return HTTP_PRECOND_FAILED;

    case IMAP_PERMISSION_DENIED:
        /* DAV:need-privileges */
        txn->error.precond = DAV_NEED_PRIVS;
        txn->error.resource = dest_tgt->path;
        txn->error.rights = (overwrite < 0) ? DACL_UNBIND : DACL_BIND;
        return HTTP_NO_PRIVS;

    default:
        txn->error.desc = error_message(r);
        return HTTP_SERVER_ERROR;
    }
}



/* Perform a COPY/MOVE request
 *
 * preconditions:
 *   *DAV:need-privileges
 */
int meth_copy_move(struct transaction_t *txn, void *params)
{
    struct meth_params *cparams = (struct meth_params *) params;
    int ret = HTTP_CREATED, overwrite = 1, r, precond, rights;
    const char **hdr;
    xmlURIPtr dest_uri;
    static struct request_target_t dest_tgt;  /* Parsed destination URL -
                                                 static for Location resp hdr */
    struct backend *src_be = NULL, *dest_be = NULL;
    struct mailbox *src_mbox = NULL, *dest_mbox = NULL;
    struct dav_data *ddata;
    struct index_record src_rec;
    const char *etag = NULL;
    time_t lastmod = 0;
    unsigned meth_move = (txn->meth == METH_MOVE);
    void *src_davdb = NULL, *dest_davdb = NULL, *obj = NULL;
    struct buf msg_buf = BUF_INITIALIZER;
    struct buf body_buf = BUF_INITIALIZER;

    memset(&dest_tgt, 0, sizeof(struct request_target_t));

    /* Response should not be cached */
    txn->flags.cc |= CC_NOCACHE;

    /* Parse the source path */
    r = dav_parse_req_target(txn, cparams);
    if (r) return r;

    /* Make sure method is allowed (not allowed on collections yet) */
    if (!(txn->req_tgt.allow & ALLOW_WRITE)) return HTTP_NOT_ALLOWED;

    /* Check for mandatory Destination header */
    if (!(hdr = spool_getheader(txn->req_hdrs, "Destination"))) {
        txn->error.desc = "Missing Destination header";
        return HTTP_BAD_REQUEST;
    }

    /* Parse destination URI */
    if (!(dest_uri = parse_uri(METH_UNKNOWN, hdr[0], 1, &txn->error.desc))) {
        txn->error.desc = "Illegal Destination target URI";
        return HTTP_BAD_REQUEST;
    }

    /* Make sure source and dest resources are NOT the same */
    if (!strcmp(txn->req_uri->path, dest_uri->path)) {
        txn->error.desc = "Source and destination resources are the same";
        ret = HTTP_FORBIDDEN;
        goto done;
    }

    /* Check for COPY/MOVE on collection */
    if (!txn->req_tgt.resource) {
        if (meth_move) {
            /* Use our own entry for dest to suppress lookup in parse_path() */
            dest_tgt.mbentry = mboxlist_entry_create();
        }
        else {
            /* We don't yet handle COPY on collections */
            ret = HTTP_NOT_ALLOWED;
            goto done;
        }
    }

    /* Parse the destination path */
    dest_tgt.namespace = txn->req_tgt.namespace;
    r = cparams->parse_path(dest_uri->path, &dest_tgt, &txn->error.desc);
    if (r) {
        ret = (r == HTTP_MOVED) ? HTTP_FORBIDDEN : r;
        goto done;
    }

    /* Replace cached Destination header with just the absolute path */
    spool_replace_header(xstrdup("Destination"),
                         xstrdup(dest_tgt.path), txn->req_hdrs);

    /* Check for optional Overwrite header */
    if ((hdr = spool_getheader(txn->req_hdrs, "Overwrite")) &&
        !strcmp(hdr[0], "F")) {
        overwrite = 0;
    }

    /* Handle MOVE on collection */
    if (!txn->req_tgt.resource) {
        ret = dav_move_collection(txn, &dest_tgt, overwrite);
        goto done;
    }

    /* Make sure we have a dest resource */
    if (!dest_tgt.resource) {
        txn->error.desc = "No destination resource specified";
        ret = HTTP_BAD_REQUEST;
        goto done;
    }

    /* Check ACL for current user on source mailbox */
    rights = httpd_myrights(httpd_authstate, txn->req_tgt.mbentry);
    if (((rights & DACL_READ) != DACL_READ) ||
        (meth_move && !(rights & DACL_RMRSRC))) {
        /* DAV:need-privileges */
        txn->error.precond = DAV_NEED_PRIVS;
        txn->error.resource = txn->req_tgt.path;
        txn->error.rights =
            (rights & DACL_READ) != DACL_READ ? DACL_READ : DACL_RMRSRC;
        ret = HTTP_NO_PRIVS;
        goto done;
    }

    /* Check ACL for current user on destination */
    rights = httpd_myrights(httpd_authstate, dest_tgt.mbentry);
    if (!(rights & DACL_ADDRSRC) || !(rights & DACL_WRITECONT)) {
        /* DAV:need-privileges */
        txn->error.precond = DAV_NEED_PRIVS;
        txn->error.resource = dest_tgt.path;
        txn->error.rights =
            !(rights & DACL_ADDRSRC) ? DACL_ADDRSRC : DACL_WRITECONT;
        ret = HTTP_NO_PRIVS;
        goto done;
    }

    /* Check we're not copying within the same user */
    if (!meth_move && cparams->copy.uid_conf_precond &&
        mboxname_same_userid(dest_tgt.mbentry->name,
                             txn->req_tgt.mbentry->name)) {
        txn->error.precond = cparams->copy.uid_conf_precond;
        txn->error.desc = "Can not copy resources within same user";
        ret = HTTP_NOT_ALLOWED;
        goto done;
    }

    if (txn->req_tgt.mbentry->server) {
        /* Remote source mailbox */

        if (!dest_tgt.mbentry->server) {
            /* Local destination mailbox */

            /* XXX  Currently only supports standard Murder */
            txn->error.desc = "COPY/MOVE only supported in a standard Murder";
            ret = HTTP_NOT_ALLOWED;
        }
        else if (!(src_be = proxy_findserver(txn->req_tgt.mbentry->server,
                                             &http_protocol, httpd_userid,
                                             &backend_cached, NULL, NULL,
                                             httpd_in))) {
            txn->error.desc = "Unable to connect to source backend";
            ret = HTTP_UNAVAILABLE;
        }
        else if (!(dest_be = proxy_findserver(dest_tgt.mbentry->server,
                                              &http_protocol, httpd_userid,
                                              &backend_cached, NULL, NULL,
                                              httpd_in))) {
            txn->error.desc = "Unable to connect to destination backend";
            ret = HTTP_UNAVAILABLE;
        }
        else if (src_be == dest_be) {
            /* Simply send the COPY to the backend */
            ret = http_pipe_req_resp(src_be, txn);
        }
        else {
            /* This is the harder case: GET from source and PUT on dest */
            ret = http_proxy_copy(src_be, dest_be, txn);
        }

        goto done;
    }
    else if (dest_tgt.mbentry->server) {
        /* Local source and remote destination mailbox */

        /* XXX  Currently only supports standard Murder */
        txn->error.desc = "COPY/MOVE only supported in a standard Murder";
        ret = HTTP_NOT_ALLOWED;
        goto done;
    }

    /* Local source and destination mailboxes */

    if (!strcmp(txn->req_tgt.mbentry->name, dest_tgt.mbentry->name)) {
        /* Same source and destination - Open source mailbox for writing */
        r = mailbox_open_iwl(txn->req_tgt.mbentry->name, &src_mbox);
        dest_mbox = src_mbox;
    }
    else if (meth_move) {
        /* Open source mailbox for writing */
        r = mailbox_open_iwl(txn->req_tgt.mbentry->name, &src_mbox);
    }
    else {
        /* Open source mailbox for reading */
        r = mailbox_open_irl(txn->req_tgt.mbentry->name, &src_mbox);
    }
    if (r) {
        syslog(LOG_ERR, "mailbox_open_i%cl(%s) failed: %s",
               (meth_move ||
                !strcmp(txn->req_tgt.mbentry->name, dest_tgt.mbentry->name)) ?
               'w' : 'r',
               txn->req_tgt.mbentry->name, error_message(r));
        txn->error.desc = error_message(r);
        ret = HTTP_SERVER_ERROR;
        goto done;
    }

    /* Open the DAV DB corresponding to the src mailbox */
    src_davdb = cparams->davdb.open_db(src_mbox);

    /* Find message UID for the source resource */
    cparams->davdb.lookup_resource(src_davdb, txn->req_tgt.mbentry->name,
                                   txn->req_tgt.resource,
                                   (void **) &ddata, 0);
    if (!ddata->rowid) {
        ret = HTTP_NOT_FOUND;
        goto done;
    }

    /* Fetch resource validators */
    r = cparams->get_validators(src_mbox, (void *) ddata, httpd_userid,
                                &src_rec, &etag, &lastmod);
    if (r) {
        txn->error.desc = error_message(r);
        ret = HTTP_SERVER_ERROR;
        goto done;
    }

    /* Check any preconditions on source */
    precond = cparams->check_precond(txn, params, src_mbox,
                                     (void *) ddata, etag, lastmod);

    switch (precond) {
    case HTTP_OK:
        break;

    case HTTP_LOCKED:
        txn->error.precond = DAV_NEED_LOCK_TOKEN;
        txn->error.resource = txn->req_tgt.path;

        GCC_FALLTHROUGH

    default:
        /* We failed a precondition - don't perform the request */
        ret = precond;
        goto done;
    }

    if (src_rec.uid) {
        /* Mapped URL - Load message containing the resource and parse data */
        mailbox_map_record(src_mbox, &src_rec, &msg_buf);
        buf_init_ro(&body_buf, buf_base(&msg_buf) + src_rec.header_size,
                    buf_len(&msg_buf) - src_rec.header_size);
        obj = cparams->mime_types[0].to_object(&body_buf);
    }
    else {
        /* Unmapped URL (empty resource) */
        buf_init_ro_cstr(&body_buf, "");
        obj = &body_buf;
        src_rec.recno = ddata->rowid; /* For deleting DAV record */
    }

    if (dest_mbox != src_mbox) {
        if (!meth_move) {
            /* Done with source mailbox */
            mailbox_unlock_index(src_mbox, NULL);
        }

        /* Open dest mailbox for writing */
        r = mailbox_open_iwl(dest_tgt.mbentry->name, &dest_mbox);
        if (r) {
            syslog(LOG_ERR, "mailbox_open_iwl(%s) failed: %s",
                   dest_tgt.mbentry->name, error_message(r));
            txn->error.desc = error_message(r);
            ret = HTTP_SERVER_ERROR;
            goto done;
        }

        /* Open the DAV DB corresponding to the dest mailbox */
        dest_davdb = cparams->davdb.open_db(dest_mbox);
    }
    else {
        dest_davdb = src_davdb;
    }

    /* Find message UID for the dest resource, if exists */
    cparams->davdb.lookup_resource(dest_davdb, dest_tgt.mbentry->name,
                                   dest_tgt.resource, (void **) &ddata, 0);
    /* XXX  Check errors */

    /* Check any preconditions on destination */
    if (ddata->rowid && !overwrite) {
        /* Don't overwrite the destination resource */
        ret = HTTP_PRECOND_FAILED;
        goto done;
    }

    /* Store the resource at destination */
    ret = cparams->copy.proc(txn, obj,
                             dest_mbox, dest_tgt.resource, dest_davdb, 0);

    if (dest_mbox != src_mbox) {
        /* Done with destination mailbox */
        mailbox_unlock_index(dest_mbox, NULL);
    }

    switch (ret) {
    case HTTP_CREATED:
    case HTTP_NO_CONTENT:
        if (meth_move) {
            /* Expunge the source message */
            if (src_rec.uid) {
                /* Mapped URL */
                src_rec.internal_flags |= FLAG_INTERNAL_EXPUNGED;
                if ((r = mailbox_rewrite_index_record(src_mbox, &src_rec))) {
                    syslog(LOG_ERR, "expunging src record (%s) failed: %s",
                           txn->req_tgt.mbentry->name, error_message(r));
                    txn->error.desc = error_message(r);
                    ret = HTTP_SERVER_ERROR;
                    goto done;
                }
            }
            else {
                /* Unmapped URL (empty resource) */
                cparams->davdb.delete_resourceLOCKONLY(src_davdb, src_rec.recno);
            }
        }
    }

  done:
    if (ret == HTTP_CREATED) {
        /* Tell client where to find the new resource */
        txn->location = dest_tgt.path;
    }
    else {
        /* Don't confuse client by providing ETag of Destination resource */
        txn->resp_body.etag = NULL;
    }

    if (obj && cparams->mime_types[0].free) cparams->mime_types[0].free(obj);
    if (dest_mbox != src_mbox) {
        if (dest_davdb) cparams->davdb.close_db(dest_davdb);
        if (dest_mbox) mailbox_close(&dest_mbox);
    }
    if (src_davdb) cparams->davdb.close_db(src_davdb);
    if (src_mbox) mailbox_close(&src_mbox);

    buf_free(&msg_buf);
    buf_free(&body_buf);
    xmlFreeURI(dest_uri);
    free(dest_tgt.userid);
    mboxlist_entry_free(&dest_tgt.mbentry);

    return ret;
}


struct delete_rock {
    struct transaction_t *txn;
    struct mailbox *mailbox;
    delete_proc_t deletep;
};

static int delete_cb(void *rock, void *data)
{
    struct delete_rock *drock = (struct delete_rock *) rock;
    struct dav_data *ddata = (struct dav_data *) data;
    struct index_record record;
    int r;

    if (!ddata->imap_uid) {
        /* Unmapped URL (empty resource) */
        return 0;
    }

    /* Fetch index record for the resource */
    r = mailbox_find_index_record(drock->mailbox, ddata->imap_uid, &record);
    if (r) {
        drock->txn->error.desc = error_message(r);
        return HTTP_SERVER_ERROR;
    }

    r = drock->deletep(drock->txn, drock->mailbox, &record, data);

    return r;
}

/* DELETE collection */
static int meth_delete_collection(struct transaction_t *txn,
                                  struct meth_params *dparams)
{
    int ret = HTTP_NO_CONTENT, r = 0, precond, rights, needrights;
    struct mailbox *mailbox = NULL;

    /* if FastMail sharing, we need to remove ACLs */
    if (config_getswitch(IMAPOPT_FASTMAILSHARING) &&
        !mboxname_userownsmailbox(httpd_userid, txn->req_tgt.mbentry->name)) {
        r = mboxlist_setacl(&httpd_namespace, txn->req_tgt.mbentry->name,
                            httpd_userid, /*rights*/NULL, /*isadmin*/1,
                            httpd_userid, httpd_authstate);
        if (r) {
            syslog(LOG_ERR, "meth_delete(%s) failed to remove acl: %s",
                   txn->req_tgt.mbentry->name, error_message(r));
            txn->error.desc = error_message(r);
            return HTTP_SERVER_ERROR;
        }
        sync_checkpoint(txn->conn->pin);
        return HTTP_OK;
    }

    /* Special case of deleting a shared collection */
    if (txn->req_tgt.flags == TGT_DAV_SHARED) {
        char *inboxname = mboxname_user_mbox(txn->req_tgt.userid, NULL);
        mbentry_t *mbentry = NULL;

        r = proxy_mlookup(inboxname, &mbentry, NULL, NULL);
        if (r) {
            syslog(LOG_ERR, "mlookup(%s) failed: %s",
                   inboxname, error_message(r));
            ret = HTTP_NOT_FOUND;
        }
        else if (mbentry->server) {
            /* Remote mailbox */
            struct backend *be;

            be = proxy_findserver(mbentry->server, &http_protocol, httpd_userid,
                                  &backend_cached, NULL, NULL, httpd_in);
            if (!be) ret = HTTP_UNAVAILABLE;
            else ret = http_pipe_req_resp(be, txn);
        }
        else {
            /* Local Mailbox */
            struct mailbox *mailbox = NULL;

            /* Unsubscribe */
            r = mboxlist_changesub(txn->req_tgt.mbentry->name,
                                   txn->req_tgt.userid,
                                   httpd_authstate, 0 /* remove */, 0, 0);
            if (r) {
                syslog(LOG_ERR, "mboxlist_changesub(%s, %s) failed: %s",
                       txn->req_tgt.mbentry->name, txn->req_tgt.userid,
                       error_message(r));
                txn->error.desc = error_message(r);
                ret = HTTP_SERVER_ERROR;
            }
            else ret = HTTP_NO_CONTENT;

            /* Set invite status to declined */
            r = mailbox_open_iwl(txn->req_tgt.mbentry->name, &mailbox);
            if (r) {
                syslog(LOG_ERR,
                       "IOERROR: failed to open mailbox %s for DELETE share",
                       txn->req_tgt.mbentry->name);
            }
            else {
                annotate_state_t *astate = NULL;

                r = mailbox_get_annotate_state(mailbox, 0, &astate);
                if (!r) {
                    const char *annot =
                        DAV_ANNOT_NS "<" XML_NS_DAV ">invite-status";
                    struct buf value = BUF_INITIALIZER;

                    buf_init_ro_cstr(&value, "invite-declined");
                    r = annotate_state_writemask(astate, annot,
                                                 txn->req_tgt.userid, &value);
                }

                mailbox_close(&mailbox);
            }
        }

        mboxlist_entry_free(&mbentry);
        free(inboxname);

        sync_checkpoint(txn->conn->pin);

        return ret;
    }

    /* Check ACL for current user */
    rights = httpd_myrights(httpd_authstate, txn->req_tgt.mbentry);
    needrights = DACL_RMCOL;
    if (!(rights & needrights)) {
        /* DAV:need-privileges */
        txn->error.precond = DAV_NEED_PRIVS;
        txn->error.resource = txn->req_tgt.path;
        txn->error.rights = needrights;
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

    /* Open mailbox for reading */
    r = mailbox_open_irl(txn->req_tgt.mbentry->name, &mailbox);
    if (r) {
        syslog(LOG_ERR, "http_mailbox_open(%s) failed: %s",
               txn->req_tgt.mbentry->name, error_message(r));
        txn->error.desc = error_message(r);
        return HTTP_SERVER_ERROR;
    }

    /* Check any preconditions */
    precond = dparams->check_precond(txn, dparams, mailbox, NULL, NULL, 0);

    switch (precond) {
    case HTTP_OK:
        break;

    case HTTP_LOCKED:
        txn->error.precond = DAV_NEED_LOCK_TOKEN;
        txn->error.resource = txn->req_tgt.path;
        GCC_FALLTHROUGH

    default:
        /* We failed a precondition - don't perform the request */
        ret = precond;
        goto done;
    }

    if (dparams->delete) {
        /* Do special processing on all resources */
        struct delete_rock drock = { txn, NULL, dparams->delete };

        /* Open the DAV DB corresponding to the mailbox */
        void *davdb = dparams->davdb.open_db(mailbox);

        drock.mailbox = mailbox;
        r = dparams->davdb.foreach_resource(davdb, mailbox->name,
                                            &delete_cb, &drock);
        dparams->davdb.close_db(davdb);

        if (r) {
            txn->error.desc = error_message(r);
            ret = HTTP_SERVER_ERROR;
            goto done;
        }
    }

    /* we need the mailbox closed before we delete it */
    mailbox_close(&mailbox);

    mbname_t *mbname = mbname_from_intname(txn->req_tgt.mbentry->name);
    struct mboxlock *namespacelock = user_namespacelock(mbname_userid(mbname));
    struct mboxevent *mboxevent = mboxevent_new(EVENT_MAILBOX_DELETE);

    if (mboxlist_delayed_delete_isenabled()) {
        r = mboxlist_delayed_deletemailbox(txn->req_tgt.mbentry->name,
                                           httpd_userisadmin || httpd_userisproxyadmin,
                                           httpd_userid, httpd_authstate,
                                           mboxevent, MBOXLIST_DELETE_CHECKACL);
    }
    else {
        r = mboxlist_deletemailbox(txn->req_tgt.mbentry->name,
                                   httpd_userisadmin || httpd_userisproxyadmin,
                                   httpd_userid, httpd_authstate, mboxevent,
                                   MBOXLIST_DELETE_CHECKACL);
    }
    if (!r) {
        r = caldav_update_shareacls(mbname_userid(mbname));
    }
    if (r == IMAP_PERMISSION_DENIED) ret = HTTP_FORBIDDEN;
    else if (r == IMAP_MAILBOX_NONEXISTENT) ret = HTTP_NOT_FOUND;
    else if (r) ret = HTTP_SERVER_ERROR;
    else mboxevent_notify(&mboxevent);

    mboxevent_free(&mboxevent);
    mboxname_release(&namespacelock);
    mbname_free(&mbname);

  done:
    mailbox_close(&mailbox);

    sync_checkpoint(txn->conn->pin);

    return ret;
}

/* DELETE resource */
static int meth_delete_resource(struct transaction_t *txn,
                                struct meth_params *dparams)
{
    int ret = HTTP_NO_CONTENT, r = 0, precond, rights, needrights;
    struct mboxevent *mboxevent = NULL;
    struct mailbox *mailbox = NULL;
    struct dav_data *ddata;
    struct index_record record;
    const char *etag = NULL;
    time_t lastmod = 0;
    void *davdb = NULL;

    /* Check ACL for current user */
    rights = httpd_myrights(httpd_authstate, txn->req_tgt.mbentry);
    needrights = DACL_RMRSRC;
    if (!(rights & needrights)) {
        /* DAV:need-privileges */
        txn->error.precond = DAV_NEED_PRIVS;
        txn->error.resource = txn->req_tgt.path;
        txn->error.rights = needrights;
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

    /* Open mailbox for writing */
    r = mailbox_open_iwl(txn->req_tgt.mbentry->name, &mailbox);
    if (r) {
        syslog(LOG_ERR, "http_mailbox_open(%s) failed: %s",
               txn->req_tgt.mbentry->name, error_message(r));
        txn->error.desc = error_message(r);
        return HTTP_SERVER_ERROR;
    }

    /* Open the DAV DB corresponding to the mailbox */
    davdb = dparams->davdb.open_db(mailbox);

    /* Find message UID for the resource, if exists */
    dparams->davdb.lookup_resource(davdb, txn->req_tgt.mbentry->name,
                                   txn->req_tgt.resource, (void **) &ddata, 0);
    if (!ddata->rowid) {
        ret = HTTP_NOT_FOUND;
        goto done;
    }

    /* Fetch resource validators */
    r = dparams->get_validators(mailbox, (void *) ddata, httpd_userid,
                                &record, &etag, &lastmod);
    if (r) {
        txn->error.desc = error_message(r);
        ret = HTTP_SERVER_ERROR;
        goto done;
    }

    /* Check any preconditions */
    precond = dparams->check_precond(txn, dparams, mailbox,
                                     (void *) ddata, etag, lastmod);

    switch (precond) {
    case HTTP_OK:
        break;

    case HTTP_LOCKED:
        txn->error.precond = DAV_NEED_LOCK_TOKEN;
        txn->error.resource = txn->req_tgt.path;

        GCC_FALLTHROUGH

    default:
        /* We failed a precondition - don't perform the request */
        ret = precond;
        goto done;
    }

    if (record.uid) {
        /* Do any special processing */
        if (dparams->delete) dparams->delete(txn, mailbox, &record, ddata);

        /* Expunge the resource */
        record.internal_flags |= FLAG_INTERNAL_EXPUNGED;

        mboxevent = mboxevent_new(EVENT_MESSAGE_EXPUNGE);

        r = mailbox_rewrite_index_record(mailbox, &record);

        if (r) {
            syslog(LOG_ERR, "expunging record (%s) failed: %s",
                   txn->req_tgt.mbentry->name, error_message(r));
            txn->error.desc = error_message(r);
            ret = HTTP_SERVER_ERROR;
        }
        else {
            mboxevent_extract_record(mboxevent, mailbox, &record);
            mboxevent_extract_mailbox(mboxevent, mailbox);
            mboxevent_set_numunseen(mboxevent, mailbox, -1);
            mboxevent_set_access(mboxevent, NULL, NULL, httpd_userid,
                                 txn->req_tgt.mbentry->name, 0);
            mboxevent_notify(&mboxevent);
        }

        mboxevent_free(&mboxevent);
    }

  done:
    if (davdb) dparams->davdb.close_db(davdb);
    mailbox_close(&mailbox);

    sync_checkpoint(txn->conn->pin);

    return ret;
}

/* Perform a DELETE request */
int meth_delete(struct transaction_t *txn, void *params)
{
    struct meth_params *dparams = (struct meth_params *) params;

    /* Response should not be cached */
    txn->flags.cc |= CC_NOCACHE;

    /* Parse the path */
    int r = dav_parse_req_target(txn, dparams);
    if (r) return r;

    /* Make sure method is allowed */
    if (!(txn->req_tgt.allow & ALLOW_DELETE)) return HTTP_NOT_ALLOWED;

    if (txn->req_tgt.resource) return meth_delete_resource(txn, dparams);

    return meth_delete_collection(txn, dparams);
}


/* Perform a GET/HEAD request on a DAV resource */
int meth_get_head(struct transaction_t *txn, void *params)
{
    struct meth_params *gparams = (struct meth_params *) params;
    const char **hdr;
    struct mime_type_t *mime = NULL;
    int ret = 0, r = 0, precond, rights;
    const char *data = NULL;
    unsigned long datalen = 0, offset = 0;
    struct buf msg_buf = BUF_INITIALIZER;
    struct resp_body_t *resp_body = &txn->resp_body;
    struct mailbox *mailbox = NULL;
    struct dav_data *ddata;
    struct index_record record;
    const char *etag = NULL;
    time_t lastmod = 0;
    void *davdb = NULL, *obj = NULL;
    char *freeme = NULL;

    /* Parse the path */
    r = dav_parse_req_target(txn, gparams);
    if (r) return r;

    if (txn->req_tgt.namespace->id == URL_NS_PRINCIPAL) {
        /* Special "principal" */
        if (txn->req_tgt.flags == TGT_SERVER_INFO) return get_server_info(txn);

        /* No content for principals (yet) */
        return HTTP_NO_CONTENT;
    }

    if (!txn->req_tgt.resource) {
        /* Do any collection processing */
        if (gparams->get) return gparams->get(txn, NULL, NULL, NULL, NULL);

        /* We don't handle GET on a collection */
        return HTTP_NO_CONTENT;
    }

    /* Check ACL for current user */
    rights = httpd_myrights(httpd_authstate, txn->req_tgt.mbentry);
    if ((rights & DACL_READ) != DACL_READ) {
        /* DAV:need-privileges */
        txn->error.precond = DAV_NEED_PRIVS;
        txn->error.resource = txn->req_tgt.path;
        txn->error.rights = DACL_READ;
        return HTTP_NO_PRIVS;
    }

    if (gparams->mime_types) {
        /* Check requested MIME type:
           1st entry in gparams->mime_types array MUST be default MIME type */
        if ((hdr = spool_getheader(txn->req_hdrs, "Accept")))
            mime = get_accept_type(hdr, gparams->mime_types);
        else mime = gparams->mime_types;
        if (!mime) return HTTP_NOT_ACCEPTABLE;
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

    /* Open mailbox for reading */
    r = mailbox_open_irl(txn->req_tgt.mbentry->name, &mailbox);
    if (r) {
        syslog(LOG_ERR, "http_mailbox_open(%s) failed: %s",
               txn->req_tgt.mbentry->name, error_message(r));
        goto done;
    }

    /* Open the DAV DB corresponding to the mailbox */
    davdb = gparams->davdb.open_db(mailbox);

    /* Find message UID for the resource */
    gparams->davdb.lookup_resource(davdb, txn->req_tgt.mbentry->name,
                                   txn->req_tgt.resource, (void **) &ddata, 0);
    if (!ddata->rowid) {
        ret = HTTP_NOT_FOUND;
        goto done;
    }

    /* Fetch resource validators */
    r = gparams->get_validators(mailbox, (void *) ddata, httpd_userid,
                                &record, &etag, &lastmod);
    if (r) {
        txn->error.desc = error_message(r);
        ret = HTTP_SERVER_ERROR;
        goto done;
    }

    txn->flags.ranges = (ddata->imap_uid != 0);

    /* Check any preconditions, including range request */
    precond = gparams->check_precond(txn, params, mailbox,
                                     (void *) ddata, etag, lastmod);

    switch (precond) {
    case HTTP_OK:
    case HTTP_PARTIAL:
    case HTTP_NOT_MODIFIED:
        /* Fill in ETag, Last-Modified, Expires, and Cache-Control */
        resp_body->etag = etag;
        resp_body->lastmod = lastmod;
        resp_body->maxage = 3600;       /* 1 hr */
        txn->flags.cc |= CC_MAXAGE | CC_REVALIDATE;  /* don't use stale data */
        if (httpd_userid) txn->flags.cc |= CC_PRIVATE;

        if (precond != HTTP_NOT_MODIFIED && record.uid) break;

        GCC_FALLTHROUGH

    default:
        /* We failed a precondition - don't perform the request */
        ret = precond;
        goto done;
    }

    /* Do any special processing */
    if (gparams->get) {
        ret = gparams->get(txn, mailbox, &record, ddata, &obj);
        if (ret != HTTP_CONTINUE) goto done;

        ret = 0;
    }

    if (mime && !resp_body->type) {
        txn->flags.vary |= VARY_ACCEPT;
        resp_body->type = mime->content_type;
    }

    if (!obj) {
        /* Raw resource - length doesn't include RFC 5322 header */
        offset = record.header_size;
        datalen = record.size - offset;

        if (txn->meth == METH_GET) {
            /* Load message containing the resource */
            r = mailbox_map_record(mailbox, &record, &msg_buf);
            if (r) goto done;

            data = buf_base(&msg_buf) + offset;

            if (mime != gparams->mime_types) {
                /* Not the storage format - create resource object */
                struct buf inbuf = BUF_INITIALIZER;
                buf_init_ro(&inbuf, data, datalen);
                obj = gparams->mime_types[0].to_object(&inbuf);
                buf_free(&inbuf);
            }
        }
    }

    if (obj) {
        /* Convert object into requested MIME type */
        struct buf *outbuf = mime->from_object(obj);

        datalen = buf_len(outbuf);
        if (txn->meth == METH_GET) data = freeme = buf_release(outbuf);
        buf_destroy(outbuf);

        if (gparams->mime_types[0].free) gparams->mime_types[0].free(obj);
    }

    write_body(precond, txn, data, datalen);

    buf_free(&msg_buf);
    free(freeme);

  done:
    if (davdb) gparams->davdb.close_db(davdb);
    if (r) {
        txn->error.desc = error_message(r);
        ret = HTTP_SERVER_ERROR;
    }
    mailbox_close(&mailbox);

    return ret;
}


/* Perform a LOCK request
 *
 * preconditions:
 *   DAV:need-privileges
 *   DAV:no-conflicting-lock
 *   DAV:lock-token-submitted
 */
int meth_lock(struct transaction_t *txn, void *params)
{
    struct meth_params *lparams = (struct meth_params *) params;
    int ret = HTTP_OK, r, precond, rights;
    struct mailbox *mailbox = NULL;
    struct dav_data *ddata;
    struct index_record oldrecord;
    const char *etag;
    time_t lastmod;
    xmlDocPtr indoc = NULL, outdoc = NULL;
    xmlNodePtr root = NULL;
    xmlNsPtr ns[NUM_NAMESPACE];
    xmlBufferPtr owner = NULL;
    time_t now = time(NULL);
    void *davdb = NULL;

    /* XXX  We ignore Depth and Timeout header fields */

    /* Response should not be cached */
    txn->flags.cc |= CC_NOCACHE;

    /* Parse the path */
    r = dav_parse_req_target(txn, lparams);
    if (r) return r;

    /* Make sure method is allowed (only allowed on resources) */
    if (!(txn->req_tgt.allow & ALLOW_WRITE)) return HTTP_NOT_ALLOWED;

    /* Check ACL for current user */
    rights = httpd_myrights(httpd_authstate, txn->req_tgt.mbentry);
    if (!(rights & DACL_WRITECONT) || !(rights & DACL_ADDRSRC)) {
        /* DAV:need-privileges */
        txn->error.precond = DAV_NEED_PRIVS;
        txn->error.resource = txn->req_tgt.path;
        txn->error.rights =
            !(rights & DACL_WRITECONT) ? DACL_WRITECONT : DACL_ADDRSRC;
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

    /* Open mailbox for reading */
    r = mailbox_open_irl(txn->req_tgt.mbentry->name, &mailbox);
    if (r) {
        syslog(LOG_ERR, "http_mailbox_open(%s) failed: %s",
               txn->req_tgt.mbentry->name, error_message(r));
        txn->error.desc = error_message(r);
        ret = HTTP_SERVER_ERROR;
        goto done;
    }

    /* Open the DAV DB corresponding to the mailbox */
    davdb = lparams->davdb.open_db(mailbox);
    lparams->davdb.begin_transaction(davdb);

    /* Find message UID for the resource, if exists */
    lparams->davdb.lookup_resource(davdb, txn->req_tgt.mbentry->name,
                                   txn->req_tgt.resource, (void *) &ddata, 1);

    /* Fetch resource validators */
    r = lparams->get_validators(mailbox, (void *) ddata, httpd_userid,
                                &oldrecord, &etag, &lastmod);
    if (r) {
        txn->error.desc = error_message(r);
        ret = HTTP_SERVER_ERROR;
        goto done;
    }

    if (!ddata->alive) {
        /* New resource */
        ddata->creationdate = now;
        ddata->mailbox = mailbox->name;
        ddata->resource = txn->req_tgt.resource;
        ddata->imap_uid = 0;
        ddata->lock_expire = 0;
        ddata->alive = 1;
    }

    /* Check any preconditions */
    precond = lparams->check_precond(txn, params, mailbox,
                                     (void *) ddata, etag, lastmod);

    switch (precond) {
    case HTTP_OK:
        break;

    case HTTP_LOCKED:
        if (strcmp(ddata->lock_ownerid, httpd_userid))
            txn->error.precond = DAV_LOCKED;
        else
            txn->error.precond = DAV_NEED_LOCK_TOKEN;
        txn->error.resource = txn->req_tgt.path;

        GCC_FALLTHROUGH

    default:
        /* We failed a precondition - don't perform the request */
        ret = precond;
        goto done;
    }

    if (ddata->lock_expire <= now) {
        /* Create new lock */
        xmlNodePtr node, sub;

        /* Parse the required body */
        ret = parse_xml_body(txn, &root, NULL);
        if (!ret && !root) {
            txn->error.desc = "Missing request body";
            ret = HTTP_BAD_REQUEST;
        }
        if (ret) goto done;

        /* Make sure its a DAV:lockinfo element */
        indoc = root->doc;
        if (!root->ns || xmlStrcmp(root->ns->href, BAD_CAST XML_NS_DAV) ||
            xmlStrcmp(root->name, BAD_CAST "lockinfo")) {
            txn->error.desc = "Missing DAV:lockinfo element in LOCK request";
            ret = HTTP_BAD_MEDIATYPE;
            goto done;
        }

        /* Parse elements of lockinfo */
        for (node = root->children; node; node = node->next) {
            if (node->type != XML_ELEMENT_NODE) continue;

            if (!xmlStrcmp(node->name, BAD_CAST "lockscope")) {
                /* Find child element of lockscope */
                for (sub = node->children;
                     sub && sub->type != XML_ELEMENT_NODE; sub = sub->next);
                /* Make sure its an exclusive element */
                if (!sub || xmlStrcmp(sub->name, BAD_CAST "exclusive")) {
                    txn->error.desc = "Only exclusive locks are supported";
                    ret = HTTP_BAD_REQUEST;
                    goto done;
                }
            }
            else if (!xmlStrcmp(node->name, BAD_CAST "locktype")) {
                /* Find child element of locktype */
                for (sub = node->children;
                     sub && sub->type != XML_ELEMENT_NODE; sub = sub->next);
                /* Make sure its a write element */
                if (!sub || xmlStrcmp(sub->name, BAD_CAST "write")) {
                    txn->error.desc = "Only write locks are supported";
                    ret = HTTP_BAD_REQUEST;
                    goto done;
                }
            }
            else if (!xmlStrcmp(node->name, BAD_CAST "owner")) {
                /* Find child element of owner */
                owner = xmlBufferCreate();
                for (sub = node->children;
                     sub && sub->type != XML_ELEMENT_NODE; sub = sub->next);
                if (!sub) {
                    xmlNodeBufGetContent(owner, node);
                }
                /* Make sure its a href element */
                else if (xmlStrcmp(sub->name, BAD_CAST "href")) {
                    ret = HTTP_BAD_REQUEST;
                    goto done;
                }
                else {
                    xmlNodeBufGetContent(owner, sub);
                    xmlBufferAddHead(owner, BAD_CAST "<DAV:href>", 10);
                }
            }
        }

        ddata->lock_ownerid = httpd_userid;
        if (owner) ddata->lock_owner = (const char *) xmlBufferContent(owner);

        /* Construct lock-token */
        assert(!buf_len(&txn->buf));
        buf_printf(&txn->buf, LOCK_TOKEN_URL_SCHEME "%s", makeuuid());

        ddata->lock_token = buf_cstring(&txn->buf);
    }

    /* Update lock expiration */
    ddata->lock_expire = now + 300;  /* 5 min */

    /* Start construction of our prop response */
    if (!(root = init_xml_response("prop", NS_DAV, root, ns))) {
        ret = HTTP_SERVER_ERROR;
        txn->error.desc = "Unable to create XML response";
        goto done;
    }

    outdoc = root->doc;
    root = xmlNewChild(root, NULL, BAD_CAST "lockdiscovery", NULL);
    xml_add_lockdisc(root, txn->req_tgt.path, (struct dav_data *) ddata);

    r = lparams->davdb.write_resourceLOCKONLY(davdb, ddata);
    if (r) {
        syslog(LOG_ERR, "Unable to write lock record to DAV DB: %s",
               error_message(r));
        ret = HTTP_SERVER_ERROR;
        txn->error.desc = "Unable to create locked resource";
        goto done;
    }

    txn->resp_body.lock = ddata->lock_token;

    if (!ddata->rowid) {
        ret = HTTP_CREATED;

        /* Tell client where to find the new resource */
        txn->location = txn->req_tgt.path;
    }
    else ret = HTTP_OK;

    xml_response(ret, txn, outdoc);
    ret = 0;

  done:
    if (davdb) {
        /* XXX - error handling/abort */
        lparams->davdb.commit_transaction(davdb);
        lparams->davdb.close_db(davdb);
    }
    mailbox_close(&mailbox);
    if (outdoc) xmlFreeDoc(outdoc);
    if (indoc) xmlFreeDoc(indoc);
    if (owner) xmlBufferFree(owner);

    return ret;
}


/* Perform a MKCOL/MKCALENDAR request */
/*
 * preconditions:
 *   DAV:resource-must-be-null
 *   DAV:need-privileges
 *   DAV:valid-resourcetype
 *   CALDAV:calendar-collection-location-ok
 *   CALDAV:valid-calendar-data (CALDAV:calendar-timezone)
 */
int meth_mkcol(struct transaction_t *txn, void *params)
{
    struct meth_params *mparams = (struct meth_params *) params;
    int ret = 0, r = 0;
    xmlDocPtr indoc = NULL, outdoc = NULL;
    xmlNodePtr root = NULL, instr = NULL;
    xmlNsPtr ns[NUM_NAMESPACE];
    char *partition = NULL;
    struct proppatch_ctx pctx;
    struct mailbox *mailbox = NULL;

    memset(&pctx, 0, sizeof(struct proppatch_ctx));

    /* Response should not be cached */
    txn->flags.cc |= CC_NOCACHE;

    /* Parse the path (use our own entry to suppress lookup) */
    txn->req_tgt.mbentry = mboxlist_entry_create();
    r = mparams->parse_path(txn->req_uri->path, &txn->req_tgt, &txn->error.desc);

    /* Make sure method is allowed (only allowed on child of home-set) */
    if (!txn->req_tgt.collection || txn->req_tgt.resource) {
        txn->error.precond = mparams->mkcol.location_precond;
        return HTTP_FORBIDDEN;
    }
    else if (r) {
        switch (r) {
        case IMAP_MAILBOX_EXISTS:
            txn->error.precond = DAV_RES_EXISTS;
            break;

        case IMAP_PERMISSION_DENIED:
            txn->error.precond = DAV_NEED_PRIVS;
            txn->error.rights = DACL_BIND;
            buf_reset(&txn->buf);
            buf_printf(&txn->buf, "%s/%s/%s",
                       txn->req_tgt.namespace->prefix, USER_COLLECTION_PREFIX,
                       txn->req_tgt.userid);
            txn->error.resource = buf_cstring(&txn->buf);
            break;

        default:
            txn->error.precond = mparams->mkcol.location_precond;
            break;
        }

        return HTTP_FORBIDDEN;
    }

    if (config_mupdate_server && !config_getstring(IMAPOPT_PROXYSERVERS)) {
        /* Remote mailbox - find the parent */
        mbentry_t *parent = NULL;
        struct backend *be;

        r = mboxlist_findparent(txn->req_tgt.mbentry->name, &parent);
        if (r) {
            txn->error.precond = mparams->mkcol.location_precond;
            ret = HTTP_FORBIDDEN;
            goto done;
	}

        be = proxy_findserver(parent->server, &http_protocol, httpd_userid,
                              &backend_cached, NULL, NULL, httpd_in);

        if (!be) ret = HTTP_UNAVAILABLE;
        else ret = http_pipe_req_resp(be, txn);

        goto done;
    }

    /* Local Mailbox */

    /* Parse the MKCOL/MKCALENDAR body, if exists */
    ret = parse_xml_body(txn, &root, NULL);
    if (ret) goto done;

    if (root) {
        /* Check for correct root element (lowercase method name ) */
        const char *ns_href;

        indoc = root->doc;

        buf_setcstr(&txn->buf, http_methods[txn->meth].name);
        ns_href = buf_len(&txn->buf) > 5 ? XML_NS_CALDAV : XML_NS_DAV;
        if (!root->ns || xmlStrcmp(root->ns->href, BAD_CAST ns_href) ||
            xmlStrcmp(root->name, BAD_CAST buf_lcase(&txn->buf))) {
            txn->error.desc =
                "Incorrect root element in MKCOL/MKCALENDAR request";
            ret = HTTP_BAD_REQUEST;
            goto done;
        }

        instr = root->children;
    }

    struct mboxlock *namespacelock = mboxname_usernamespacelock(txn->req_tgt.mbentry->name);

    /* Create the mailbox */
    r = mboxlist_createmailbox(txn->req_tgt.mbentry->name,
                               mparams->mkcol.mbtype, partition,
                               httpd_userisadmin || httpd_userisproxyadmin,
                               httpd_userid, httpd_authstate,
                               /*localonly*/0, /*forceuser*/0,
                               /*dbonly*/0, /*notify*/0,
                               &mailbox);

    if (instr && !r) {
        /* Start construction of our mkcol/mkcalendar response */
        buf_appendcstr(&txn->buf, "-response");
        root = init_xml_response(buf_cstring(&txn->buf), NS_REQ_ROOT, root, ns);
        buf_reset(&txn->buf);
        if (!root) {
            ret = HTTP_SERVER_ERROR;
            txn->error.desc = "Unable to create XML response";
            mboxname_release(&namespacelock);
            goto done;
        }

        outdoc = root->doc;

        /* Populate our proppatch context */
        pctx.txn = txn;
        pctx.mailbox = mailbox;
        pctx.lprops = mparams->propfind.lprops;
        pctx.root = root;
        pctx.ns = ns;
        pctx.tid = NULL;
        pctx.ret = &r;

        /* Execute the property patch instructions */
        ret = do_proppatch(&pctx, instr);

        if (ret || r) {
            /* Setting properties failed - delete mailbox */
            mailbox_abort(mailbox);
            mailbox_close(&mailbox);
            mboxlist_deletemailbox(txn->req_tgt.mbentry->name,
                                   /*isadmin*/1, NULL, NULL, NULL,
                                   MBOXLIST_DELETE_FORCE);

            if (!ret) {
                /* Output the XML response */
                if (txn->meth == METH_MKCALENDAR) {
                    /* MKCALENDAR failure response MUST be 207 (Multi-Status) */
                    xmlNodeSetName(root, BAD_CAST "multistatus");
                    xmlSetNs(root, ns[NS_DAV]);
                    r = HTTP_MULTI_STATUS;
                }
                xml_response(r, txn, outdoc);
            }

            mboxname_release(&namespacelock);
            goto done;
        }
    }
    mboxname_release(&namespacelock);

    if (!r) {
        if (mparams->mkcol.proc) r = mparams->mkcol.proc(mailbox);

        assert(!buf_len(&txn->buf));
        dav_get_synctoken(mailbox, &txn->buf, "");
        txn->resp_body.ctag = buf_cstring(&txn->buf);
        ret = HTTP_CREATED;
    }
    else if (r == IMAP_PERMISSION_DENIED) ret = HTTP_NO_PRIVS;
    else if (r == IMAP_MAILBOX_EXISTS) {
        txn->error.precond = DAV_RES_EXISTS;
        ret = HTTP_FORBIDDEN;
    }
    else {
        txn->error.desc = error_message(r);
        ret = HTTP_SERVER_ERROR;
    }

  done:
    buf_free(&pctx.buf);
    mailbox_close(&mailbox);

    sync_checkpoint(txn->conn->pin);

    if (partition) free(partition);
    if (outdoc) xmlFreeDoc(outdoc);
    if (indoc) xmlFreeDoc(indoc);

    return ret;
}


/* dav_foreach() callback to find props on a resource */
int propfind_by_resource(void *rock, void *data)
{
    struct propfind_ctx *fctx = (struct propfind_ctx *) rock;
    struct dav_data *ddata = (struct dav_data *) data;
    struct index_record record;
    char *p;
    size_t len;
    int r = 0, ret = 0;

    keepalive_response(fctx->txn);

    /* Append resource name to URL path */
    if (!fctx->req_tgt->resource) {
        len = strlen(fctx->req_tgt->path);
        p = fctx->req_tgt->path + len;
    }
    else {
        p = fctx->req_tgt->resource;
        len = p - fctx->req_tgt->path;
    }

    if (p[-1] != '/') {
        *p++ = '/';
        len++;
    }
    strlcpy(p, ddata->resource, MAX_MAILBOX_PATH - len);
    fctx->req_tgt->resource = p;
    fctx->req_tgt->reslen = strlen(p);

    fctx->data = data;
    if (ddata->imap_uid && !fctx->record) {
        /* Fetch index record for the resource */
        r = mailbox_find_index_record(fctx->mailbox, ddata->imap_uid, &record);

        fctx->record = r ? NULL : &record;
    }

    if (r || (!ddata->imap_uid && ddata->lock_expire <= time(NULL))) {
        /* Add response for missing target */
        ret = xml_add_response(fctx, HTTP_NOT_FOUND, 0, NULL, NULL);
    }
    else if (!fctx->filter || fctx->filter(fctx, data)) {
        /* Add response for target */
        ret = xml_add_response(fctx, 0, 0, NULL, NULL);
    }

    buf_free(&fctx->msg_buf);
    if (fctx->obj) {
        fctx->free_obj(fctx->obj);
        fctx->obj = NULL;
    }
    fctx->record = NULL;
    fctx->data = NULL;

    return ret;
}


static int propfind_by_resources(struct propfind_ctx *fctx)
{
    int r = 0;
    sqlite3 *newdb;

    if (!fctx->mailbox) return 0;

    /* Open the DAV DB corresponding to the mailbox.
     *
     * Note we open the new one first before closing the old one, so we
     * get refcounted retaining of the open database within a single user */
    newdb = fctx->open_db(fctx->mailbox);
    if (fctx->davdb) fctx->close_db(fctx->davdb);
    fctx->davdb = newdb;

    if (fctx->req_tgt->resource) {
        /* Add response for target resource */
        struct dav_data *ddata;

        /* Find message UID for the resource */
        fctx->lookup_resource(fctx->davdb, fctx->mailbox->name,
                              fctx->req_tgt->resource, (void **) &ddata, 0);
        if (!ddata->rowid) {
            /* Add response for missing target */
            xml_add_response(fctx, HTTP_NOT_FOUND, 0, NULL, NULL);
            return HTTP_NOT_FOUND;
        }
        r = fctx->proc_by_resource(fctx, ddata);
    }
    else {
        /* Add responses for all contained resources */
        fctx->foreach_resource(fctx->davdb, fctx->mailbox->name,
                               fctx->proc_by_resource, fctx);

        /* Started with NULL resource, end with NULL resource */
        fctx->req_tgt->resource = NULL;
        fctx->req_tgt->reslen = 0;
    }

    return r;
}


HIDDEN size_t make_collection_url(struct buf *buf, const char *urlprefix, int haszzzz,
                                  const mbname_t *mbname, const char *userid)
{
    const strarray_t *boxes;
    int n, size;
    size_t len;

    buf_reset(buf);
    buf_printf(buf, "%s/", urlprefix);

    if (userid) {
        const char *owner = mbname_userid(mbname);
        if (!owner) owner = "";

        if (config_getswitch(IMAPOPT_FASTMAILSHARING)) {
            buf_printf(buf, "%s/%s/", haszzzz ? "zzzz" : USER_COLLECTION_PREFIX, owner);
        }
        else {
            buf_printf(buf, "%s/", USER_COLLECTION_PREFIX);

            if (*userid) {
                buf_printf(buf, "%s/", userid);

                if (strcmp(owner, userid)) {
                    /* Encode shared collection as: <owner> "." <mboxname> */
                    buf_printf(buf, "%s%c", owner, SHARED_COLLECTION_DELIM);
                }
            }
            else buf_printf(buf, "%s/", owner);
        }
    }

    len = buf_len(buf);

    /* add collection(s) to path */
    boxes = mbname_boxes(mbname);
    size = strarray_size(boxes);
    for (n = 1; n < size; n++) {
        buf_appendcstr(buf, strarray_nth(boxes, n));
        buf_putc(buf, '/');
    }

    return len;
}


/* mboxlist_findall() callback to find props on a collection */
int propfind_by_collection(const mbentry_t *mbentry, void *rock)
{
    struct propfind_ctx *fctx = (struct propfind_ctx *) rock;
    const char *mboxname = mbentry->name;
    struct buf writebuf = BUF_INITIALIZER;
    struct mailbox *mailbox = NULL;
    char *p;
    size_t len;
    int r = 0, rights = 0;

    /* skip deleted items */
    if (mboxname_isdeletedmailbox(mbentry->name, 0) ||
        (mbentry->mbtype & MBTYPE_DELETED)) {
        goto done;
    }

    /* Check ACL on mailbox for current user */
    rights = httpd_myrights(httpd_authstate, mbentry);
    if ((rights & fctx->reqd_privs) != fctx->reqd_privs) goto done;

    /* We only match known types */
    if (!(mbentry->mbtype & fctx->req_tgt->namespace->mboxtype)) goto done;

    p = strrchr(mboxname, '.');
    if (!p) goto done;
    p++; /* skip dot */

    switch (fctx->req_tgt->namespace->id) {
    case URL_NS_DRIVE:
        if (fctx->req_tgt->flags == TGT_DRIVE_USER) {
            /* Special case of listing users with DAV #drives */
            p = strchr(mboxname+5, '.') + 1;  /* skip "user.XXX." */
            if (strcmp(p, fctx->req_tgt->mboxprefix)) goto done;
        }
        else if (p - mboxname > 1 + (int) strlen(fctx->req_tgt->mbentry->name)) {
            /* Reject folders that are more than one level deep */
            goto done;
        }
        break;

    default:
        /* Magic folder filter */
        if (httpd_extrafolder && strcasecmp(p, httpd_extrafolder)) goto done;
        break;
    }

    /* skip toplevels */
    if (config_getswitch(IMAPOPT_FASTMAILSHARING) && *p == '#')
        goto done;


    /* Open mailbox for reading */
    if ((r = mailbox_open_irl(mboxname, &mailbox))) {
        syslog(LOG_INFO, "mailbox_open_irl(%s) failed: %s",
               mboxname, error_message(r));
    }

    fctx->mbentry = mbentry;
    fctx->mailbox = mailbox;
    fctx->record = NULL;

    if (!fctx->req_tgt->resource) {
        /* we always have zzzz if it's already in the URL */
        int haszzzz = fctx->req_tgt->flags & TGT_USER_ZZZZ;

        mbname_t *mbname = mbname_from_intname(mboxname);
        if (!mbname_domain(mbname))
            mbname_set_domain(mbname, httpd_extradomain);

        /* we also need to deal with the discovery case,
         * where mboxname doesn't match request path */
        if (fctx->req_tgt->userid &&
            strcmpsafe(mbname_userid(mbname), fctx->req_tgt->userid)) {
            haszzzz = 1;
        }

        len = make_collection_url(&writebuf, fctx->req_tgt->namespace->prefix,
                                  haszzzz, mbname, fctx->req_tgt->userid);

        mbname_free(&mbname);

        /* copy it all back into place... in theory we should check against
         * 'last' and make sure it doesn't change from the original request.
         * yay for micro-optimised memory usage... */
        strlcpy(fctx->req_tgt->path, buf_cstring(&writebuf), MAX_MAILBOX_PATH);
        p = fctx->req_tgt->path + len;
        fctx->req_tgt->collection = p;
        fctx->req_tgt->collen = strlen(p);

        /* If not filtering by calendar resource, and not excluding root,
           add response for collection */
        if (!r && !fctx->filter_crit && !(fctx->prefer & PREFER_NOROOT) &&
            (r = xml_add_response(fctx, 0, 0, NULL, NULL))) goto done;
    }

    if (r) {
        xml_add_response(fctx, HTTP_SERVER_ERROR, 0, error_message(r), NULL);
        goto done;
    }

    if (fctx->depth > 1 && fctx->open_db) { // can't do davdb searches if no dav db
        /* Resource(s) */
        r = propfind_by_resources(fctx);
    }

  done:
    buf_free(&writebuf);
    if (mailbox) mailbox_close(&mailbox);

    return 0;
}

/* Free an entry list */
HIDDEN void free_entry_list(struct propfind_entry_list *elist)
{
    while (elist) {
        struct propfind_entry_list *freeme = elist;

        elist = elist->next;
        if (freeme->flags & PROP_CLEANUP) {
            freeme->get(freeme->name, NULL, NULL,
                        NULL, NULL, NULL, freeme->rock);
        }

        xmlFree(freeme->name);
        free(freeme);
    }
}

/* Perform a PROPFIND request */
EXPORTED int meth_propfind(struct transaction_t *txn, void *params)
{
    struct meth_params *fparams = (struct meth_params *) params;
    int ret = 0, r;
    const char **hdr;
    unsigned depth;
    xmlDocPtr indoc = NULL, outdoc = NULL;
    xmlNodePtr root, cur = NULL, props = NULL;
    xmlNsPtr ns[NUM_NAMESPACE];
    struct hash_table ns_table = { 0, NULL, NULL };
    struct propfind_ctx fctx;

    memset(&fctx, 0, sizeof(struct propfind_ctx));

    /* Parse the path */
    if (fparams->parse_path) {
        r = dav_parse_req_target(txn, fparams);
        if (r) return r;
    }

    /* Make sure method is allowed */
    if (!(txn->req_tgt.allow & ALLOW_DAV)) return HTTP_NOT_ALLOWED;

    /* Check Depth */
    hdr = spool_getheader(txn->req_hdrs, "Depth");
    if (!hdr || !strcmp(hdr[0], "infinity")) {
        depth = 3;

        if ((txn->error.precond = fparams->propfind.finite_depth_precond)) {
            ret = HTTP_FORBIDDEN;
            goto done;
        }
    }
    else if (!strcmp(hdr[0], "1")) {
        depth = 1;
    }
    else if (!strcmp(hdr[0], "0")) {
        depth = 0;
    }
    else {
        txn->error.desc = "Illegal Depth value";
        return HTTP_BAD_REQUEST;
    }

    if (txn->req_tgt.mbentry) {
        int rights;

        /* Check ACL for current user */
        rights = httpd_myrights(httpd_authstate, txn->req_tgt.mbentry);
        if ((rights & DACL_READ) != DACL_READ) {
            /* DAV:need-privileges */
            txn->error.precond = DAV_NEED_PRIVS;
            txn->error.resource = txn->req_tgt.path;
            txn->error.rights = DACL_READ;
            ret = HTTP_NO_PRIVS;
            goto done;
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
    }

    /* Principal or Local Mailbox */

    /* Parse the PROPFIND body, if exists */
    ret = parse_xml_body(txn, &root, NULL);
    if (ret) goto done;

    if (!root) {
        /* Empty request */
        fctx.mode = PROPFIND_ALL;
    }
    else {
        indoc = root->doc;

        /* Make sure its a DAV:propfind element */
        if (!root->ns || xmlStrcmp(root->ns->href, BAD_CAST XML_NS_DAV) ||
            xmlStrcmp(root->name, BAD_CAST "propfind")) {
            txn->error.desc = "Missing DAV:propfind element in PROPFIND request";
            ret = HTTP_BAD_REQUEST;
            goto done;
        }

        /* Find child element of propfind */
        for (cur = root->children;
             cur && cur->type != XML_ELEMENT_NODE; cur = cur->next);

        if (!cur) {
            txn->error.desc = "Missing child node element in PROPFIND request";
            ret = HTTP_BAD_REQUEST;
            goto done;
        }

        /* Add propfind type to our header cache */
        spool_cache_header(xstrdup(":type"), xstrdup((const char *) cur->name),
                           txn->req_hdrs);

        /* Make sure its a known element */
        if (!xmlStrcmp(cur->name, BAD_CAST "allprop")) {
            fctx.mode = PROPFIND_ALL;
        }
        else if (!xmlStrcmp(cur->name, BAD_CAST "propname")) {
            fctx.mode = PROPFIND_NAME;
            fctx.prefer = PREFER_MIN;  /* Don't want 404 (Not Found) */
        }
        else if (!xmlStrcmp(cur->name, BAD_CAST "prop")) {
            fctx.mode = PROPFIND_PROP;
            props = cur->children;
        }
        else {
            ret = HTTP_BAD_REQUEST;
            goto done;
        }

        /* Check for extra elements */
        for (cur = cur->next; cur; cur = cur->next) {
            if (cur->type == XML_ELEMENT_NODE) {
                if ((fctx.mode == PROPFIND_ALL) && !props &&
                    /* Check for 'include' element */
                    !xmlStrcmp(cur->name, BAD_CAST "include")) {
                    props = cur->children;
                }
                else {
                    ret = HTTP_BAD_REQUEST;
                    goto done;
                }
            }
        }
    }

    /* Start construction of our multistatus response */
    root = init_xml_response("multistatus", NS_DAV, root, ns);
    if (!root) {
        ret = HTTP_SERVER_ERROR;
        txn->error.desc = "Unable to create XML response";
        goto done;
    }

    outdoc = root->doc;

    /* Populate our propfind context */
    fctx.txn = txn;
    fctx.req_tgt = &txn->req_tgt;
    fctx.depth = depth;
    fctx.prefer |= get_preferences(txn);
    fctx.userid = httpd_userid;
    fctx.userisadmin = httpd_userisadmin;
    fctx.authstate = httpd_authstate;
    fctx.mbentry = NULL;
    fctx.mailbox = NULL;
    fctx.record = NULL;
    fctx.get_validators = fparams->get_validators;
    fctx.reqd_privs = DACL_READ;
    fctx.filter = NULL;
    fctx.filter_crit = NULL;
    if (fparams->mime_types) fctx.free_obj = fparams->mime_types[0].free;
    fctx.open_db = fparams->davdb.open_db;
    fctx.close_db = fparams->davdb.close_db;
    fctx.lookup_resource = fparams->davdb.lookup_resource;
    fctx.foreach_resource = fparams->davdb.foreach_resource;
    fctx.proc_by_resource = &propfind_by_resource;
    fctx.elist = NULL;
    fctx.lprops = fparams->propfind.lprops;
    fctx.root = root;
    fctx.ns = ns;
    fctx.ns_table = &ns_table;
    fctx.ret = &ret;

    /* Parse the list of properties and build a list of callbacks */
    ret = preload_proplist(props, &fctx);
    if (ret) goto done;

    /* iCalendar/vCard data in response should not be transformed */
    if (fctx.flags.fetcheddata) txn->flags.cc |= CC_NOTRANSFORM;

    /* Setup for chunked response */
    txn->flags.te |= TE_CHUNKED;

    /* Begin XML response */
    xml_response(HTTP_MULTI_STATUS, txn, fctx.root->doc);

    /* Generate responses */
    if (txn->req_tgt.namespace->id == URL_NS_PRINCIPAL) {
        if (!depth || !(fctx.prefer & PREFER_NOROOT)) {
            /* Add response for target URL */
            xml_add_response(&fctx, 0, 0, NULL, NULL);
        }

        if (depth > 0 && !txn->req_tgt.userid) {
            size_t len = strlen(namespace_principal.prefix);
            char *p = txn->req_tgt.path + len;

            if (!strcmp(p, "/" USER_COLLECTION_PREFIX "/")) {
                /* Normalize depth so that:
                 * 0 = prin-set, 1+ = collection, 2+ = principal, 3+ = infinity!
                 */
                depth++;
            }
            else {
                /* Add a response for 'user' collection */
                snprintf(p, MAX_MAILBOX_PATH - len,
                         "/%s/", USER_COLLECTION_PREFIX);
                xml_add_response(&fctx, 0, 0, NULL, NULL);
            }

            if (depth >= 2) {
                /* Add responses for all user principals */
                ret = mboxlist_alluser(principal_search, &fctx);
            }
        }
    }
    else {
        /* Normalize depth so that:
         * 0 = home-set, 1+ = collection, 2+ = resource, 3+ = infinity!
         */
        if (txn->req_tgt.collection) depth++;
        if (txn->req_tgt.resource) depth++;

        fctx.depth = depth;

        if (!txn->req_tgt.collection &&
            (!depth || !(fctx.prefer & PREFER_NOROOT))) {
            /* Add response for home-set collection */
            if (txn->req_tgt.mbentry) {
                /* Open mailbox for reading */
                if ((r = mailbox_open_irl(txn->req_tgt.mbentry->name,
                                          &fctx.mailbox))
                    && r != IMAP_MAILBOX_NONEXISTENT) {
                    syslog(LOG_INFO, "mailbox_open_irl(%s) failed: %s",
                           txn->req_tgt.mbentry->name, error_message(r));
                    txn->error.desc = error_message(r);
                    ret = HTTP_SERVER_ERROR;
                    goto done;
                }

                fctx.mbentry = txn->req_tgt.mbentry;
            }

            if (!fctx.req_tgt->resource)
                xml_add_response(&fctx, 0, 0, NULL, NULL);

            /* Resource(s) */
            r = propfind_by_resources(&fctx);
            if (r) ret = r;

            mailbox_close(&fctx.mailbox);
        }

        if (depth > 0) {
            /* Collection(s) */

            if (txn->req_tgt.collection) {
                /* Add response for target collection */
                propfind_by_collection(txn->req_tgt.mbentry, &fctx);
            }
            else if (config_getswitch(IMAPOPT_FASTMAILSHARING)) {
                /* Add responses for all visible collections */
                mboxlist_usermboxtree(httpd_userid, httpd_authstate,
                                      propfind_by_collection,
                                      &fctx, MBOXTREE_PLUS_RACL);
            }
            else if (txn->req_tgt.mbentry) {
                /* Add responses for all contained collections */
                fctx.prefer &= ~PREFER_NOROOT;
                mboxlist_mboxtree(txn->req_tgt.mbentry->name,
                                  propfind_by_collection, &fctx,
                                  MBOXTREE_SKIP_ROOT);

                switch (txn->req_tgt.namespace->id) {
                case URL_NS_DRIVE:
                    if (txn->req_tgt.flags == TGT_DRIVE_ROOT) {
                        /* Add a response for 'user' hierarchy */
                        buf_setcstr(&fctx.buf, txn->req_tgt.namespace->prefix);
                        buf_printf(&fctx.buf, "/%s/", USER_COLLECTION_PREFIX);
                        strlcpy(fctx.req_tgt->path,
                                buf_cstring(&fctx.buf), MAX_MAILBOX_PATH);
                        fctx.mbentry = NULL;
                        fctx.mailbox = NULL;
                        r = xml_add_response(&fctx, 0, 0, NULL, NULL);
                    }
                    break;

                case URL_NS_CALENDAR:
                    if (fctx.flags.cs_sharing) {
                        /* Add response for notification collection */
                        r = propfind_csnotify_collection(&fctx, props);
                    }
                    /* Fall through */

                case URL_NS_ADDRESSBOOK:
                    /* Add responses for shared collections */
                    mboxlist_usersubs(txn->req_tgt.userid,
                                      propfind_by_collection, &fctx,
                                      MBOXTREE_SKIP_PERSONAL);
                    break;
                }
            }

            ret = *fctx.ret;
        }
    }

    if (fctx.davdb) fctx.close_db(fctx.davdb);

    /* End XML response */
    xml_partial_response(txn, fctx.root->doc, NULL /* end */, 0, &fctx.xmlbuf);
    xmlBufferFree(fctx.xmlbuf);

    // might have made a change!
    sync_checkpoint(txn->conn->pin);

    /* End of output */
    write_body(0, txn, NULL, 0);
    ret = 0;

  done:
    /* Free the entry list */
    free_entry_list(fctx.elist);

    buf_free(&fctx.buf);

    free_hash_table(&ns_table, NULL);

    if (outdoc) xmlFreeDoc(outdoc);
    if (indoc) xmlFreeDoc(indoc);

    return ret;
}


/* Perform a PROPPATCH request
 *
 * preconditions:
 *   DAV:cannot-modify-protected-property
 *   CALDAV:valid-calendar-data (CALDAV:calendar-timezone)
 */
int meth_proppatch(struct transaction_t *txn, void *params)
{
    struct meth_params *pparams = (struct meth_params *) params;
    int ret = 0, r = 0;
    xmlDocPtr indoc = NULL, outdoc = NULL;
    xmlNodePtr root, instr, resp;
    xmlNsPtr ns[NUM_NAMESPACE];
    struct mailbox *mailbox = NULL;
    struct proppatch_ctx pctx;
    struct index_record record;
    void *davdb = NULL;

    memset(&pctx, 0, sizeof(struct proppatch_ctx));

    /* Response should not be cached */
    txn->flags.cc |= CC_NOCACHE;

    /* Parse the path */
    r = dav_parse_req_target(txn, pparams);
    if (r) return r;

    if (!txn->req_tgt.collection && !txn->req_tgt.userid) {
        txn->error.desc = "PROPPATCH requires a collection";
        return HTTP_NOT_ALLOWED;
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

    r = mailbox_open_iwl(txn->req_tgt.mbentry->name, &mailbox);
    if (r) {
        syslog(LOG_ERR, "IOERROR: failed to open mailbox %s for proppatch",
               txn->req_tgt.mbentry->name);
        return HTTP_SERVER_ERROR;
    }

    /* Parse the PROPPATCH body */
    ret = parse_xml_body(txn, &root, NULL);
    if (!ret && !root) {
        txn->error.desc = "Missing request body";
        ret = HTTP_BAD_REQUEST;
    }
    if (ret) goto done;

    indoc = root->doc;

    /* Make sure its a DAV:propertyupdate element */
    if (!root->ns || xmlStrcmp(root->ns->href, BAD_CAST XML_NS_DAV) ||
        xmlStrcmp(root->name, BAD_CAST "propertyupdate")) {
        txn->error.desc =
            "Missing DAV:propertyupdate element in PROPPATCH request";
        ret = HTTP_BAD_REQUEST;
        goto done;
    }
    instr = root->children;

    /* Start construction of our multistatus response */
    if (!(root = init_xml_response("multistatus", NS_DAV, root, ns))) {
        txn->error.desc = "Unable to create XML response";
        ret = HTTP_SERVER_ERROR;
        goto done;
    }

    outdoc = root->doc;

    /* Add a response tree to 'root' for the specified href */
    resp = xmlNewChild(root, NULL, BAD_CAST "response", NULL);
    if (!resp) syslog(LOG_ERR, "new child response failed");
    xmlNewChild(resp, NULL, BAD_CAST "href", BAD_CAST txn->req_tgt.path);

    /* Populate our proppatch context */
    pctx.txn = txn;
    pctx.mailbox = mailbox;
    pctx.record = NULL;
    pctx.lprops = pparams->propfind.lprops;
    pctx.root = resp;
    pctx.ns = ns;
    pctx.tid = NULL;
    pctx.ret = &r;

    if (txn->req_tgt.resource) {
        struct dav_data *ddata;
        /* gotta find the resource */
        /* Open the DAV DB corresponding to the mailbox */
        davdb = pparams->davdb.open_db(mailbox);

        /* Find message UID for the resource */
        pparams->davdb.lookup_resource(davdb, txn->req_tgt.mbentry->name,
                                       txn->req_tgt.resource, (void **) &ddata, 0);
        if (!ddata->imap_uid) {
            ret = HTTP_NOT_FOUND;
            goto done;
        }

        memset(&record, 0, sizeof(struct index_record));
        /* Mapped URL - Fetch index record for the resource */
        r = mailbox_find_index_record(mailbox, ddata->imap_uid, &record);
        if (r) {
            ret = HTTP_NOT_FOUND;
            goto done;
        }

        pctx.record = &record;
    }

    /* Execute the property patch instructions */
    ret = do_proppatch(&pctx, instr);

  done:
    if (r) mailbox_abort(mailbox);
    mailbox_close(&mailbox);
    if (davdb) pparams->davdb.close_db(davdb);

    sync_checkpoint(txn->conn->pin);

    if (!ret) {
        /* Output the XML response if wanted */
        if (get_preferences(txn) & PREFER_MIN)
            ret = HTTP_OK;
        else
            xml_response(HTTP_MULTI_STATUS, txn, outdoc);
    }

    buf_free(&pctx.buf);
    if (outdoc) xmlFreeDoc(outdoc);
    if (indoc) xmlFreeDoc(indoc);

    return ret;
}


static int dav_post_import(struct transaction_t *txn,
                          struct meth_params *pparams)
{
    int ret = 0, r, precond = HTTP_OK, rights;
    const char **hdr;
    struct mime_type_t *mime = NULL;
    struct mailbox *mailbox = NULL;
    quota_t qdiffs[QUOTA_NUMRESOURCES] = QUOTA_DIFFS_DONTCARE_INITIALIZER;
    void *davdb = NULL, *obj = NULL;
    xmlDocPtr outdoc = NULL;
    xmlNodePtr root;
    xmlNsPtr ns[NUM_NAMESPACE];
    unsigned data_ns = pparams->post.bulk.data_ns;

    /* Check Content-Type */
    mime = pparams->mime_types;
    if ((hdr = spool_getheader(txn->req_hdrs, "Content-Type"))) {
        for (; mime->content_type; mime++) {
            if (is_mediatype(mime->content_type, hdr[0])) break;
        }
        if (!mime->content_type) {
            txn->error.precond = pparams->put.supp_data_precond;
            return HTTP_FORBIDDEN;
        }
    }

    /* Check ACL for current user */
    rights = httpd_myrights(httpd_authstate, txn->req_tgt.mbentry);
    if (!(rights & DACL_WRITECONT) || !(rights & DACL_ADDRSRC)) {
        /* DAV:need-privileges */
        txn->error.precond = DAV_NEED_PRIVS;
        txn->error.resource = txn->req_tgt.path;
        txn->error.rights =
            !(rights & DACL_WRITECONT) ? DACL_WRITECONT : DACL_ADDRSRC;
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

    /* Read body */
    txn->req_body.flags |= BODY_DECODE;
    r = http_read_req_body(txn);
    if (r) {
        txn->flags.conn = CONN_CLOSE;
        return r;
    }

    /* Check if we can append a new message to mailbox */
    qdiffs[QUOTA_STORAGE] = buf_len(&txn->req_body.payload);
    qdiffs[QUOTA_MESSAGE] = 1;
    if ((r = append_check(txn->req_tgt.mbentry->name, httpd_authstate,
                          ACL_INSERT, ignorequota ? NULL : qdiffs))) {
        syslog(LOG_ERR, "append_check(%s) failed: %s",
               txn->req_tgt.mbentry->name, error_message(r));
        txn->error.desc = error_message(r);
        return HTTP_SERVER_ERROR;
    }

    /* Open mailbox for writing */
    r = mailbox_open_iwl(txn->req_tgt.mbentry->name, &mailbox);
    if (r) {
        syslog(LOG_ERR, "http_mailbox_open(%s) failed: %s",
               txn->req_tgt.mbentry->name, error_message(r));
        txn->error.desc = error_message(r);
        return HTTP_SERVER_ERROR;
    }

    /* Open the DAV DB corresponding to the mailbox */
    davdb = pparams->davdb.open_db(mailbox);

    /* Check any preconditions */
    assert(!buf_len(&txn->buf));
    buf_printf(&txn->buf, "%u-%u-%u", mailbox->i.uidvalidity,
               mailbox->i.last_uid, mailbox->i.exists);
    ret = precond = pparams->check_precond(txn, pparams, mailbox, NULL,
                                           buf_cstring(&txn->buf),
                                           mailbox->index_mtime);
    buf_reset(&txn->buf);

    switch (precond) {
    case HTTP_OK:
        break;

    case HTTP_LOCKED:
        txn->error.precond = DAV_NEED_LOCK_TOKEN;
        txn->error.resource = txn->req_tgt.path;

        GCC_FALLTHROUGH

    case HTTP_PRECOND_FAILED:
    default:
        /* We failed a precondition */
        ret = precond;
        goto done;
    }

    /* Parse and validate the resources */
    obj = mime->to_object(&txn->req_body.payload);
    ret = pparams->post.bulk.import(txn, obj, NULL, NULL, NULL, NULL, 0);
    if (ret) goto done;

    /* Start construction of our multistatus response */
    root = init_xml_response("multistatus", NS_DAV, NULL, ns);
    if (!root) {
        ret = HTTP_SERVER_ERROR;
        txn->error.desc = "Unable to create XML response";
        goto done;
    }
    ensure_ns(ns, NS_CS, root, XML_NS_CS, "CS");
    ensure_ns(ns, data_ns, root, known_namespaces[data_ns].href,
              known_namespaces[data_ns].prefix);

    outdoc = root->doc;

    /* Setup for chunked response */
    txn->flags.te |= TE_CHUNKED;

    /* Include CTag in trailer */
    txn->flags.trailer |= TRAILER_CTAG;

    /* Begin XML response */
    xml_response(HTTP_MULTI_STATUS, txn, outdoc);

    /* Store the resources */
    ret = pparams->post.bulk.import(txn, obj, mailbox, davdb,
                                    root, ns, get_preferences(txn));

    /* Validators */
    dav_get_synctoken(mailbox, &txn->buf, "");
    txn->resp_body.ctag = buf_cstring(&txn->buf);

    sync_checkpoint(txn->conn->pin);

    /* End of output */
    write_body(0, txn, NULL, 0);
    ret = 0;

  done:
    if (outdoc) xmlFreeDoc(outdoc);
    if (obj) {
        if (pparams->mime_types[0].free) pparams->mime_types[0].free(obj);
    }
    if (davdb) pparams->davdb.close_db(davdb);
    mailbox_close(&mailbox);

    return ret;
}


/* Perform a POST request */
int meth_post(struct transaction_t *txn, void *params)
{
    struct meth_params *pparams = (struct meth_params *) params;
    struct strlist *action;
    int r, ret;
    size_t len;

    /* Response should not be cached */
    txn->flags.cc |= CC_NOCACHE;
    if (httpd_userid) txn->flags.cc |= CC_PRIVATE;

    /* Parse the path */
    r = dav_parse_req_target(txn, pparams);
    if (r) return r;

    /* Make sure method is allowed (only allowed on certain collections) */
    if (!(txn->req_tgt.allow & ALLOW_POST)) return HTTP_NOT_ALLOWED;

    /* Do any special processing */
    if (pparams->post.proc) {
        ret = pparams->post.proc(txn);
        if (ret != HTTP_CONTINUE) return ret;
    }

    /* Check for query params */
    action = hash_lookup("action", &txn->req_qparams);

    if (!action) {
        /* Check Content-Type */
        const char **hdr = spool_getheader(txn->req_hdrs, "Content-Type");

        if ((pparams->post.allowed & POST_SHARE) && hdr &&
            (is_mediatype(hdr[0], DAVSHARING_CONTENT_TYPE) ||
             is_mediatype(hdr[0], "text/xml"))) {
            /* Sharing request */
            return dav_post_share(txn, pparams);
        }
        else if (pparams->post.bulk.data_prop && hdr &&
                 is_mediatype(hdr[0], "application/xml")) {
            /* Bulk CRUD */
            return HTTP_FORBIDDEN;
        }
        else if (pparams->post.bulk.import && hdr) {
            /* Bulk import */
            return dav_post_import(txn, pparams);
        }
        else return HTTP_BAD_REQUEST;
    }

    if (!(pparams->post.allowed & POST_ADDMEMBER) ||
        !action || action->next || strcmp(action->s, "add-member")) {
        return HTTP_BAD_REQUEST;
    }

    /* POST add-member to regular collection */

    /* Append a unique resource name to URL path and perform a PUT */
    len = strlen(txn->req_tgt.path);
    txn->req_tgt.resource = txn->req_tgt.path + len;
    txn->req_tgt.reslen =
        snprintf(txn->req_tgt.resource, MAX_MAILBOX_PATH - len,
                 "%s.%s", makeuuid(), pparams->mime_types[0].file_ext ?
                 pparams->mime_types[0].file_ext : "");

    /* Tell client where to find the new resource */
    txn->location = txn->req_tgt.path;

    ret = meth_put(txn, params);

    if (ret != HTTP_CREATED) txn->location = NULL;

    return ret;
}


/* Perform a PATCH request
 *
 * preconditions:
 */
int meth_patch(struct transaction_t *txn, void *params)
{
    struct meth_params *pparams = (struct meth_params *) params;
    int ret, r, precond, rights;
    const char **hdr, *etag;
    struct patch_doc_t *patch_doc = NULL;
    struct mailbox *mailbox = NULL;
    struct dav_data *ddata;
    struct index_record oldrecord;
    time_t lastmod;
    unsigned flags = 0;
    void *davdb = NULL, *obj = NULL;
    struct buf msg_buf = BUF_INITIALIZER;

    /* Response should not be cached */
    txn->flags.cc |= CC_NOCACHE;

    /* Parse the path */
    r = dav_parse_req_target(txn, pparams);
    if (r) return r;

    /* Make sure method is allowed (only allowed on resources) */
    if (!(txn->req_tgt.allow & ALLOW_PATCH)) return HTTP_NOT_ALLOWED;

    /* Check Content-Type */
    if ((hdr = spool_getheader(txn->req_hdrs, "Content-Type"))) {
        for (patch_doc = pparams->patch_docs; patch_doc->format; patch_doc++) {
            if (is_mediatype(patch_doc->format, hdr[0])) break;
        }
    }
    if (!patch_doc || !patch_doc->format) {
        txn->resp_body.patch = pparams->patch_docs;
        return HTTP_BAD_MEDIATYPE;
    }

    /* Check ACL for current user */
    rights = httpd_myrights(httpd_authstate, txn->req_tgt.mbentry);
    if (!(rights & DACL_WRITECONT)) {
        /* DAV:need-privileges */
        txn->error.precond = DAV_NEED_PRIVS;
        txn->error.resource = txn->req_tgt.path;
        txn->error.rights = DACL_WRITECONT;
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
    txn->req_body.flags |= BODY_DECODE;
    ret = http_read_req_body(txn);
    if (ret) {
        txn->flags.conn = CONN_CLOSE;
        return ret;
    }

    /* Check if we can append a new message to mailbox */
    /* XXX  Can we guess-timate the size difference? */
    if ((r = append_check(txn->req_tgt.mbentry->name, httpd_authstate,
                          ACL_INSERT, NULL))) {
        syslog(LOG_ERR, "append_check(%s) failed: %s",
               txn->req_tgt.mbentry->name, error_message(r));
        txn->error.desc = error_message(r);
        return HTTP_SERVER_ERROR;
    }

    /* Open mailbox for writing */
    r = mailbox_open_iwl(txn->req_tgt.mbentry->name, &mailbox);
    if (r) {
        syslog(LOG_ERR, "http_mailbox_open(%s) failed: %s",
               txn->req_tgt.mbentry->name, error_message(r));
        txn->error.desc = error_message(r);
        return HTTP_SERVER_ERROR;
    }

    /* Open the DAV DB corresponding to the mailbox */
    davdb = pparams->davdb.open_db(mailbox);

    /* Find message UID for the resource */
    pparams->davdb.lookup_resource(davdb, txn->req_tgt.mbentry->name,
                                   txn->req_tgt.resource, (void *) &ddata, 0);
    if (!ddata->imap_uid) {
        ret = HTTP_NOT_FOUND;
        goto done;
    }

    /* Fetch resource validators */
    r = pparams->get_validators(mailbox, (void *) ddata, httpd_userid,
                                &oldrecord, &etag, &lastmod);
    if (r) {
        txn->error.desc = error_message(r);
        ret = HTTP_SERVER_ERROR;
        goto done;
    }

    /* Check any preferences */
    flags = get_preferences(txn);

    /* Check any preconditions */
    ret = precond = pparams->check_precond(txn, params, mailbox,
                                           (void *) ddata, etag, lastmod);

    switch (precond) {
    case HTTP_PRECOND_FAILED:
        if (!(flags & PREFER_REP)) goto done;

        /* Fill in ETag and Last-Modified */
        txn->resp_body.etag = etag;
        txn->resp_body.lastmod = lastmod;

        /* Fall through and load message */
        GCC_FALLTHROUGH

    case HTTP_OK: {
        unsigned offset;
        struct buf buf = BUF_INITIALIZER;

        /* Load message containing the resource */
        mailbox_map_record(mailbox, &oldrecord, &msg_buf);

        /* Resource length doesn't include RFC 5322 header */
        offset = oldrecord.header_size;

        /* Parse existing resource */
        buf_init_ro(&buf, buf_base(&msg_buf) + offset,
                    buf_len(&msg_buf) - offset);
        obj = pparams->mime_types[0].to_object(&buf);
        buf_free(&buf);

        if (precond == HTTP_OK) {
            /* Parse, validate, and apply the patch document to the resource */
            ret = patch_doc->proc(txn, obj);
            if (!ret) {
                ret = pparams->put.proc(txn, obj, mailbox,
                                        txn->req_tgt.resource, davdb, flags);
                if (ret == HTTP_FORBIDDEN) ret = HTTP_UNPROCESSABLE;
            }
        }

        break;
    }

    case HTTP_LOCKED:
        txn->error.precond = DAV_NEED_LOCK_TOKEN;
        txn->error.resource = txn->req_tgt.path;

    default:
        /* We failed a precondition */
        goto done;
    }

    if (flags & PREFER_REP) {
        struct resp_body_t *resp_body = &txn->resp_body;
        struct mime_type_t *mime = pparams->mime_types;
        struct buf *data;

        if ((hdr = spool_getheader(txn->req_hdrs, "Accept"))) {
            mime = get_accept_type(hdr, pparams->mime_types);
            if (!mime) goto done;
        }

        switch (ret) {
        case HTTP_NO_CONTENT:
            ret = HTTP_OK;

            GCC_FALLTHROUGH

        case HTTP_CREATED:
        case HTTP_PRECOND_FAILED:
            /* Convert into requested MIME type */
            data = mime->from_object(obj);

            /* Fill in Content-Type, Content-Length */
            resp_body->type = mime->content_type;
            resp_body->len = buf_len(data);

            /* Fill in Content-Location */
            resp_body->loc = txn->req_tgt.path;

            /* Fill in Expires and Cache-Control */
            resp_body->maxage = 3600;   /* 1 hr */
            txn->flags.cc = CC_MAXAGE
                | CC_REVALIDATE         /* don't use stale data */
                | CC_NOTRANSFORM;       /* don't alter iCal data */

            /* Output current representation */
            write_body(ret, txn, buf_base(data), buf_len(data));

            buf_destroy(data);
            ret = 0;
            break;

        default:
            /* failure - do nothing */
            break;
        }
    }

  done:
    if (obj) {
        if (pparams->mime_types[0].free) pparams->mime_types[0].free(obj);
        buf_free(&msg_buf);
    }
    if (davdb) pparams->davdb.close_db(davdb);
    mailbox_close(&mailbox);

    return ret;
}


/* Perform a PUT request
 *
 * preconditions:
 *   *DAV:supported-address-data
 */
int meth_put(struct transaction_t *txn, void *params)
{
    struct meth_params *pparams = (struct meth_params *) params;
    int ret, r, precond, rights, reqd_rights;
    const char **hdr, *etag;
    struct mime_type_t *mime = NULL;
    struct mailbox *mailbox = NULL;
    struct dav_data *ddata;
    struct index_record oldrecord;
    quota_t qdiffs[QUOTA_NUMRESOURCES] = QUOTA_DIFFS_DONTCARE_INITIALIZER;
    time_t lastmod;
    unsigned flags = 0;
    void *davdb = NULL, *obj = NULL;
    struct buf msg_buf = BUF_INITIALIZER;

    if (txn->meth == METH_POST) {
        reqd_rights = DACL_ADDRSRC;
    }
    else {
        /* Response should not be cached */
        txn->flags.cc |= CC_NOCACHE;

        /* Parse the path */
        r = dav_parse_req_target(txn, pparams);
        if (r) {
            switch (r){
            case HTTP_MOVED:
            case HTTP_SERVER_ERROR: return r;
            default: return HTTP_FORBIDDEN;
            }
        }

        /* Make sure method is allowed (only allowed on resources) */
        if (!((txn->req_tgt.allow & ALLOW_WRITE) && txn->req_tgt.resource))
            return HTTP_NOT_ALLOWED;

        reqd_rights = DACL_WRITECONT;

        if (txn->req_tgt.allow & ALLOW_USERDATA) reqd_rights |= DACL_PROPRSRC;
    }

    /* Make sure mailbox type is correct */
    if (txn->req_tgt.mbentry->mbtype != txn->req_tgt.namespace->mboxtype)
        return HTTP_FORBIDDEN;

    /* Make sure Content-Range isn't specified */
    if (spool_getheader(txn->req_hdrs, "Content-Range"))
        return HTTP_BAD_REQUEST;

    /* Check Content-Type */
    mime = pparams->mime_types;
    if ((hdr = spool_getheader(txn->req_hdrs, "Content-Type"))) {
        for (; mime->content_type; mime++) {
            if (is_mediatype(mime->content_type, hdr[0])) break;
        }
        if (!mime->content_type) {
            txn->error.precond = pparams->put.supp_data_precond;
            return HTTP_FORBIDDEN;
        }
    }

    /* Check ACL for current user */
    rights = httpd_myrights(httpd_authstate, txn->req_tgt.mbentry);
    if (!(rights & reqd_rights)) {
        /* DAV:need-privileges */
        txn->error.precond = DAV_NEED_PRIVS;
        txn->error.resource = txn->req_tgt.path;
        txn->error.rights = reqd_rights;
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
    txn->req_body.flags |= BODY_DECODE;
    ret = http_read_req_body(txn);
    if (ret) {
        txn->flags.conn = CONN_CLOSE;
        return ret;
    }

    if (rights & DACL_WRITECONT) {
        /* Check if we can append a new message to mailbox */
        qdiffs[QUOTA_STORAGE] = buf_len(&txn->req_body.payload);
        qdiffs[QUOTA_MESSAGE] = 1;
        if ((r = append_check(txn->req_tgt.mbentry->name, httpd_authstate,
                              ACL_INSERT, ignorequota ? NULL : qdiffs))) {
            syslog(LOG_ERR, "append_check(%s) failed: %s",
                   txn->req_tgt.mbentry->name, error_message(r));
            txn->error.desc = error_message(r);
            return HTTP_SERVER_ERROR;
        }
    }

    /* Open mailbox for writing */
    r = mailbox_open_iwl(txn->req_tgt.mbentry->name, &mailbox);
    if (r) {
        syslog(LOG_ERR, "http_mailbox_open(%s) failed: %s",
               txn->req_tgt.mbentry->name, error_message(r));
        txn->error.desc = error_message(r);
        return HTTP_SERVER_ERROR;
    }

    /* Open the DAV DB corresponding to the mailbox */
    davdb = pparams->davdb.open_db(mailbox);

    /* Find message UID for the resource, if exists */
    pparams->davdb.lookup_resource(davdb, txn->req_tgt.mbentry->name,
                                   txn->req_tgt.resource, (void *) &ddata, 0);
    /* XXX  Check errors */

    /* Fetch resource validators */
    r = pparams->get_validators(mailbox, (void *) ddata, httpd_userid,
                                &oldrecord, &etag, &lastmod);
    if (r) {
        txn->error.desc = error_message(r);
        ret = HTTP_SERVER_ERROR;
        goto done;
    }

    /* Check any preferences */
    flags = get_preferences(txn);

    /* Check any preconditions */
    if (txn->meth == METH_POST) {
        assert(!buf_len(&txn->buf));
        buf_printf(&txn->buf, "%u-%u-%u", mailbox->i.uidvalidity,
                   mailbox->i.last_uid, mailbox->i.exists);
        ret = precond = pparams->check_precond(txn, params, mailbox, NULL,
                                               buf_cstring(&txn->buf),
                                               mailbox->index_mtime);
        buf_reset(&txn->buf);
    }
    else {
        ret = precond = pparams->check_precond(txn, params, mailbox,
                                               (void *) ddata, etag, lastmod);
    }

    switch (precond) {
    case HTTP_OK:
        /* Parse, validate, and store the resource */
        obj = mime->to_object(&txn->req_body.payload);
        ret = pparams->put.proc(txn, obj, mailbox,
                                txn->req_tgt.resource, davdb, flags);
        break;

    case HTTP_PRECOND_FAILED:
        if ((flags & PREFER_REP) && ((rights & DACL_READ) == DACL_READ)) {
            /* Fill in ETag and Last-Modified */
            txn->resp_body.etag = etag;
            txn->resp_body.lastmod = lastmod;

            if (pparams->get) {
                r = pparams->get(txn, mailbox, &oldrecord, (void *) ddata, &obj);
                if (r != HTTP_CONTINUE) flags &= ~PREFER_REP;
            }
            else {
                unsigned offset;
                struct buf buf = BUF_INITIALIZER;

                /* Load message containing the resource */
                mailbox_map_record(mailbox, &oldrecord, &msg_buf);

                /* Resource length doesn't include RFC 5322 header */
                offset = oldrecord.header_size;

                /* Parse existing resource */
                buf_init_ro(&buf, buf_base(&msg_buf) + offset,
                            buf_len(&msg_buf) - offset);
                obj = pparams->mime_types[0].to_object(&buf);
                buf_free(&buf);
            }
        }
        break;

    case HTTP_LOCKED:
        txn->error.precond = DAV_NEED_LOCK_TOKEN;
        txn->error.resource = txn->req_tgt.path;

    default:
        /* We failed a precondition */
        goto done;
    }

    if (txn->req_tgt.allow & ALLOW_PATCH) {
        /* Add Accept-Patch formats to response */
        txn->resp_body.patch = pparams->patch_docs;
    }

    if (flags & PREFER_REP) {
        struct resp_body_t *resp_body = &txn->resp_body;
        const char **hdr;
        struct buf *data;

        if ((hdr = spool_getheader(txn->req_hdrs, "Accept"))) {
            mime = get_accept_type(hdr, pparams->mime_types);
            if (!mime) goto done;
        }

        switch (ret) {
        case HTTP_NO_CONTENT:
            ret = HTTP_OK;

            GCC_FALLTHROUGH

        case HTTP_CREATED:
        case HTTP_PRECOND_FAILED:
            /* Convert into requested MIME type */
            data = mime->from_object(obj);

            /* Fill in Content-Type, Content-Length */
            resp_body->type = mime->content_type;
            resp_body->len = buf_len(data);

            /* Fill in Content-Location */
            resp_body->loc = txn->req_tgt.path;

            /* Fill in Expires and Cache-Control */
            resp_body->maxage = 3600;   /* 1 hr */
            txn->flags.cc = CC_MAXAGE
                | CC_REVALIDATE         /* don't use stale data */
                | CC_NOTRANSFORM;       /* don't alter iCal data */
            if (httpd_userid) txn->flags.cc |= CC_PRIVATE;

            /* Output current representation */
            write_body(ret, txn, buf_base(data), buf_len(data));

            buf_destroy(data);
            ret = 0;
            break;

        default:
            /* failure - do nothing */
            break;
        }
    }

  done:
    if (obj && pparams->mime_types[0].free)
        pparams->mime_types[0].free(obj);
    buf_free(&msg_buf);
    if (davdb) pparams->davdb.close_db(davdb);
    mailbox_close(&mailbox);

    // XXX - this is AFTER the response has been sent, we need to
    // refactor this for total safety
    sync_checkpoint(txn->conn->pin);

    return ret;
}


/* CALDAV:calendar-multiget/CARDDAV:addressbook-multiget REPORT */
int report_multiget(struct transaction_t *txn, struct meth_params *rparams,
                    xmlNodePtr inroot, struct propfind_ctx *fctx)
{
    int r, ret = 0;
    struct mailbox *mailbox = NULL;
    xmlNodePtr node;

    /* Setup for chunked response */
    txn->flags.te |= TE_CHUNKED;

    /* Begin XML response */
    xml_response(HTTP_MULTI_STATUS, txn, fctx->root->doc);

    /* Get props for each href */
    for (node = inroot->children; node; node = node->next) {
        if ((node->type == XML_ELEMENT_NODE) &&
            !xmlStrcmp(node->name, BAD_CAST "href")) {
            xmlChar *href = xmlNodeListGetString(inroot->doc, node->children, 1);
            xmlURIPtr uri;
            struct request_target_t tgt;
            struct dav_data *ddata;
            const char *resultstr = NULL;

            memset(&tgt, 0, sizeof(struct request_target_t));

            /* Parse the URI */
            uri = parse_uri(METH_REPORT, (const char *) href,
                            1 /* path required */, &resultstr);
            xmlFree(href);
            if (!uri) {
                r = HTTP_FORBIDDEN;
            }
            else {
                /* Parse the path */
                tgt.namespace = txn->req_tgt.namespace;

                r = rparams->parse_path(uri->path, &tgt, &resultstr);
                xmlFreeURI(uri);
            }
            if (r) {
                if (r == HTTP_MOVED)
                    xml_add_response(fctx, HTTP_MOVED, 0, NULL, resultstr);
                else
                    xml_add_response(fctx, r, 0, resultstr, NULL);
                goto next;
            }

            fctx->req_tgt = &tgt;
            fctx->mbentry = tgt.mbentry;

            /* Check if we already have this mailbox open */
            if (!mailbox || strcmp(mailbox->name, tgt.mbentry->name)) {
                if (mailbox) mailbox_close(&mailbox);

                /* Open mailbox for reading */
                r = mailbox_open_irl(tgt.mbentry->name, &mailbox);
                if (r && r != IMAP_MAILBOX_NONEXISTENT) {
                    syslog(LOG_ERR, "http_mailbox_open(%s) failed: %s",
                           tgt.mbentry->name, error_message(r));
                    xml_add_response(fctx, HTTP_SERVER_ERROR,
                                     0, error_message(r), NULL);
                    goto next;
                }

                fctx->mailbox = mailbox;
            }

            if (!fctx->mailbox || !tgt.resource) {
                /* Add response for missing target */
                xml_add_response(fctx, HTTP_NOT_FOUND, 0, NULL, NULL);
                goto next;
            }

            /* Open the DAV DB corresponding to the mailbox */
            fctx->davdb = rparams->davdb.open_db(fctx->mailbox);

            /* Find message UID for the resource */
            rparams->davdb.lookup_resource(fctx->davdb, tgt.mbentry->name,
                                           tgt.resource, (void **) &ddata, 0);
            ddata->resource = tgt.resource;
            /* XXX  Check errors */

            fctx->proc_by_resource(fctx, ddata);

            rparams->davdb.close_db(fctx->davdb);

        next:
            /* XXX - split this into a req_tgt cleanup */
            free(tgt.userid);
            mboxlist_entry_free(&tgt.mbentry);
        }
    }

    /* End XML response */
    xml_partial_response(txn, fctx->root->doc, NULL /* end */, 0, &fctx->xmlbuf);
    xmlBufferFree(fctx->xmlbuf);

    /* End of output */
    write_body(0, txn, NULL, 0);

    mailbox_close(&mailbox);

    return ret;
}


struct updates_rock {
    struct propfind_ctx *fctx;
    get_modseq_t get_modseq;
    uint32_t limit;
    modseq_t syncmodseq;
    modseq_t basemodseq;
    modseq_t *respmodseq;
    uint32_t *nresp;
};

static int updates_cb(void *rock, void *data)
{
    struct dav_data *ddata = (struct dav_data *) data;
    struct updates_rock *urock = (struct updates_rock *) rock;
    struct propfind_ctx *fctx = urock->fctx;
    modseq_t modseq = urock->get_modseq(fctx->mailbox, data, fctx->userid);

    if (!ddata->alive) {
        if (modseq <= urock->basemodseq) {
            /* Initial sync - ignore unmapped resources */
            return 0;
        }

        /* Report resource as NOT FOUND
           IMAP UID of 0 will cause index record to be ignored
           propfind_by_resource() will append our resource name */
        ddata->imap_uid = 0;
    }
    else if (modseq <= urock->syncmodseq) {
        /* Per-user modseq hasn't changed */
        return 0;
    }


    if (*urock->nresp >= urock->limit) {
        /* Number of responses has reached client-specified limit */
        return HTTP_NO_STORAGE;
    }
    else {
        /* Bump response count */
        *urock->nresp += 1;
    }

    /* respmodseq will be highest modseq of the resources we return */
    *(urock->respmodseq) = MAX(modseq, *(urock->respmodseq));

    /* Add <response> element for this resource to root */
    fctx->proc_by_resource(fctx, ddata);
    fctx->record = NULL;

    return 0;
}


/* DAV:sync-collection REPORT */
int report_sync_col(struct transaction_t *txn, struct meth_params *rparams,
                    xmlNodePtr inroot, struct propfind_ctx *fctx)
{
    int ret = 0, r;
    struct mailbox *mailbox = NULL;
    uint32_t uidvalidity = 0;
    modseq_t syncmodseq = 0;
    modseq_t basemodseq = 0;
    modseq_t highestmodseq = 0;
    modseq_t respmodseq = 0;
    uint32_t limit = UINT32_MAX - 1;
    uint32_t nresp = 0;
    xmlNodePtr node;
    char tokenuri[MAX_MAILBOX_PATH+1];

    /* XXX  Handle Depth (cal-home-set at toplevel) */

    /* Open mailbox for reading */
    r = mailbox_open_irl(txn->req_tgt.mbentry->name, &mailbox);
    if (r) {
        syslog(LOG_ERR, "http_mailbox_open(%s) failed: %s",
               txn->req_tgt.mbentry->name, error_message(r));
        txn->error.desc = error_message(r);
        ret = HTTP_SERVER_ERROR;
        goto done;
    }

    fctx->mbentry = txn->req_tgt.mbentry;
    fctx->mailbox = mailbox;

    highestmodseq = mailbox->i.highestmodseq;

    /* Parse children element of report */
    for (node = inroot->children; node; node = node->next) {
        xmlNodePtr node2;
        xmlChar *str = NULL;
        if (node->type == XML_ELEMENT_NODE) {
            if (!xmlStrcmp(node->name, BAD_CAST "sync-token") &&
                (str = xmlNodeListGetString(inroot->doc, node->children, 1))) {
                /* Add sync-token to our header cache */
                spool_cache_header(xstrdup(":token"),
                                   xstrdup((const char *) str), txn->req_hdrs);

                /* Parse sync-token */
                r = sscanf((char *) str, SYNC_TOKEN_URL_SCHEME
                           "%u-" MODSEQ_FMT "-" MODSEQ_FMT "%1s",
                           &uidvalidity, &syncmodseq, &basemodseq,
                           tokenuri /* test for trailing junk */);

                syslog(LOG_DEBUG, "scanned token %s to %d %u %llu %llu",
                       str, r, uidvalidity, syncmodseq, basemodseq);
                /* Sanity check the token components */
                if (r < 2 || r > 3 ||
                    (uidvalidity != mailbox->i.uidvalidity) ||
                    (syncmodseq > highestmodseq)) {
                    fctx->txn->error.desc = "Invalid sync-token";
                }
                else if (r == 3) {
                    /* Previous partial read token */
                    if (basemodseq > highestmodseq) {
                        fctx->txn->error.desc = "Invalid sync-token";
                    }
                    else if (basemodseq < mailbox->i.deletedmodseq) {
                        fctx->txn->error.desc = "Stale sync-token";
                    }
                }
                else {
                    /* Regular token */
                    if (syncmodseq < mailbox->i.deletedmodseq) {
                        fctx->txn->error.desc = "Stale sync-token";
                    }
                }

                if (fctx->txn->error.desc) {
                    /* DAV:valid-sync-token */
                    txn->error.precond = DAV_SYNC_TOKEN;
                    ret = HTTP_FORBIDDEN;
                }
            }
            else if (!xmlStrcmp(node->name, BAD_CAST "sync-level") &&
                (str = xmlNodeListGetString(inroot->doc, node->children, 1))) {
                if (!strcmp((char *) str, "infinity")) {
                    fctx->txn->error.desc =
                        "This server DOES NOT support infinite depth requests";
                    ret = HTTP_SERVER_ERROR;
                }
                else if ((sscanf((char *) str, "%u", &fctx->depth) != 1) ||
                         (fctx->depth != 1)) {
                    fctx->txn->error.desc = "Illegal sync-level";
                    ret = HTTP_BAD_REQUEST;
                }
            }
            else if (!xmlStrcmp(node->name, BAD_CAST "limit")) {
                errno = 0;

                for (node2 = node->children; node2; node2 = node2->next) {
                    if ((node2->type == XML_ELEMENT_NODE) &&
                        !xmlStrcmp(node2->name, BAD_CAST "nresults") &&
                        (!(str = xmlNodeListGetString(inroot->doc,
                                                      node2->children, 1)) ||
                         (sscanf((char *) str, "%u", &limit) != 1) ||
                         (errno != 0) || (limit >= UINT32_MAX))) {
                        txn->error.precond = DAV_OVER_LIMIT;
                        ret = HTTP_FORBIDDEN;
                    }
                }
            }

            if (str) xmlFree(str);
            if (ret) goto done;
        }
    }

    /* Check Depth */
    if (!fctx->depth) {
        fctx->txn->error.desc = "Illegal sync-level";
        ret = HTTP_BAD_REQUEST;
        goto done;
    }

    if (!syncmodseq) {
        /* Initial sync - set basemodseq in case client limits results */
        basemodseq = highestmodseq;
    }

    /* Open the DAV DB corresponding to the mailbox */
    fctx->davdb = rparams->davdb.open_db(fctx->mailbox);

    /* Setup for chunked response */
    txn->flags.te |= TE_CHUNKED;

    /* Begin XML response */
    xml_response(HTTP_MULTI_STATUS, txn, fctx->root->doc);

    /* Report the resources within the client requested limit (if any) */
    struct updates_rock rock = { fctx, rparams->get_modseq, limit,
                                 syncmodseq, basemodseq, &respmodseq, &nresp };

    r = rparams->davdb.foreach_update(fctx->davdb, syncmodseq, mailbox->name,
                                      -1 /* ALL kinds of resources */,
                                      (syncmodseq && basemodseq) ? 0 : limit + 1,
                                      &updates_cb, &rock);
    if (r) {
        /* Tell client we truncated the responses */
        if (fctx->req_tgt->resource) *(fctx->req_tgt->resource) = '\0';
        xml_add_response(fctx, HTTP_NO_STORAGE, DAV_OVER_LIMIT, NULL, NULL);
    }
    else {
        /* Full response - respmodseq will be highestmodseq of mailbox */
        respmodseq = highestmodseq;
    }

    if (fctx->davdb) rparams->davdb.close_db(fctx->davdb);

    /* Add sync-token element to root */
    if (respmodseq < basemodseq) {
        /* Client limited results of initial sync - include basemodseq */
        snprintf(tokenuri, MAX_MAILBOX_PATH,
                 SYNC_TOKEN_URL_SCHEME "%u-" MODSEQ_FMT "-" MODSEQ_FMT,
                 mailbox->i.uidvalidity, respmodseq, basemodseq);
    }
    else {
        snprintf(tokenuri, MAX_MAILBOX_PATH,
                 SYNC_TOKEN_URL_SCHEME "%u-" MODSEQ_FMT,
                 mailbox->i.uidvalidity, respmodseq);
    }
    node =
        xmlNewChild(fctx->root, NULL, BAD_CAST "sync-token", BAD_CAST tokenuri);

    /* Add sync-token element to output buffer */
    xml_partial_response(NULL /* !output */,
                         fctx->root->doc, node, 1, &fctx->xmlbuf);

    /* End XML response */
    xml_partial_response(txn, fctx->root->doc, NULL /* end */, 0, &fctx->xmlbuf);
    xmlBufferFree(fctx->xmlbuf);

    /* End of output */
    write_body(0, txn, NULL, 0);

  done:
    mailbox_close(&mailbox);

    return ret;
}


int expand_property(xmlNodePtr inroot, struct propfind_ctx *fctx,
                    struct namespace_t *namespace, const char *href,
                    parse_path_t parse_path, const struct prop_entry *lprops,
                    xmlNodePtr root, int depth)
{
    int ret = 0, r;
    struct propfind_ctx prev_ctx;
    struct request_target_t req_tgt;

    memcpy(&prev_ctx, fctx, sizeof(struct propfind_ctx));
    memset(&req_tgt, 0, sizeof(struct request_target_t));

    fctx->mode = PROPFIND_EXPAND;
    fctx->prefer &= ~PREFER_NOROOT;
    if (href) {
        /* Parse the URL */
        req_tgt.namespace = namespace;
        parse_path(href, &req_tgt, &fctx->txn->error.desc);

        fctx->req_tgt = &req_tgt;
    }
    fctx->lprops = lprops;
    fctx->elist = NULL;
    fctx->root = root;
    fctx->depth = depth;
    fctx->mbentry = NULL;
    fctx->mailbox = NULL;

    ret = preload_proplist(inroot->children, fctx);
    if (ret) goto done;

    if (!fctx->req_tgt->collection && !fctx->depth) {
        /* Add response for principal or home-set collection */
        struct mailbox *mailbox = NULL;

        if (fctx->req_tgt->mbentry) {
            /* Open mailbox for reading */
            if ((r = mailbox_open_irl(fctx->req_tgt->mbentry->name, &mailbox))) {
                syslog(LOG_INFO, "mailbox_open_irl(%s) failed: %s",
                       fctx->req_tgt->mbentry->name, error_message(r));
                fctx->txn->error.desc = error_message(r);
                ret = HTTP_SERVER_ERROR;
                goto done;
            }
            fctx->mbentry = fctx->req_tgt->mbentry;
            fctx->mailbox = mailbox;
        }

        xml_add_response(fctx, 0, 0, NULL, NULL);

        mailbox_close(&mailbox);
    }

    if (fctx->depth > 0) {
        /* Collection(s) */

        if (fctx->req_tgt->collection) {
            /* Add response for target collection */
            propfind_by_collection(fctx->req_tgt->mbentry, fctx);
        }
        else {
            /* Add responses for all contained collections */
            mboxlist_mboxtree(fctx->req_tgt->mbentry->name,
                              propfind_by_collection, fctx,
                              MBOXTREE_SKIP_ROOT);

            switch (fctx->req_tgt->namespace->id) {
            case URL_NS_CALENDAR:
            case URL_NS_ADDRESSBOOK:
                /* Add responses for shared collections */
                mboxlist_usersubs(fctx->req_tgt->userid,
                                  propfind_by_collection, fctx,
                                  MBOXTREE_SKIP_PERSONAL);
                break;
            }
        }

        if (fctx->davdb) fctx->close_db(fctx->davdb);

        ret = *fctx->ret;
    }

  done:
    /* Free the entry list */
    free_entry_list(fctx->elist);

    free(req_tgt.userid);

    fctx->mbentry = prev_ctx.mbentry;
    fctx->mailbox = prev_ctx.mailbox;
    fctx->depth = prev_ctx.depth;
    fctx->root = prev_ctx.root;
    fctx->elist = prev_ctx.elist;
    fctx->lprops = prev_ctx.lprops;
    fctx->req_tgt = prev_ctx.req_tgt;
    fctx->prefer = prev_ctx.prefer;

    if (root != fctx->root) {
        /* Move any defined namespaces up to the previous parent */
        xmlNsPtr nsDef;

        if (fctx->root->nsDef) {
            /* Find last nsDef in list */
            for (nsDef = fctx->root->nsDef; nsDef->next; nsDef = nsDef->next);
            nsDef->next = root->nsDef;
        }
        else fctx->root->nsDef = root->nsDef;
        root->nsDef = NULL;
    }

    return ret;
}



/* DAV:expand-property REPORT */
int report_expand_prop(struct transaction_t *txn __attribute__((unused)),
                       struct meth_params *rparams __attribute__((unused)),
                       xmlNodePtr inroot, struct propfind_ctx *fctx)
{
    int ret = expand_property(inroot, fctx, NULL, NULL, NULL,
                              fctx->lprops, fctx->root, fctx->depth);

    return (ret ? ret : HTTP_MULTI_STATUS);
}


/* DAV:acl-principal-prop-set REPORT */
int report_acl_prin_prop(struct transaction_t *txn __attribute__((unused)),
                         struct meth_params *rparams __attribute__((unused)),
                         xmlNodePtr inroot __attribute__((unused)),
                         struct propfind_ctx *fctx)
{
    int ret = 0;
    struct request_target_t req_tgt;
    mbentry_t *mbentry = fctx->req_tgt->mbentry;
    char *userid, *nextid;

    /* Generate URL for user principal collection */
    buf_reset(&fctx->buf);
    buf_printf(&fctx->buf, "%s/%s/",
               namespace_principal.prefix, USER_COLLECTION_PREFIX);

    /* Allowed properties are for principals, NOT the request URL */
    memset(&req_tgt, 0, sizeof(struct request_target_t));
    principal_parse_path(buf_cstring(&fctx->buf), &req_tgt,
                         &fctx->txn->error.desc);
    fctx->req_tgt = &req_tgt;
    fctx->lprops = principal_props;
    fctx->proc_by_resource = &propfind_by_resource;

    /* Parse the ACL string (userid/rights pairs) */
    for (userid = mbentry->acl; userid; userid = nextid) {
        char *rightstr;

        rightstr = strchr(userid, '\t');
        if (!rightstr) break;
        *rightstr++ = '\0';

        nextid = strchr(rightstr, '\t');
        if (!nextid) break;
        *nextid++ = '\0';

        if (strcmp(userid, "anyone") && strcmp(userid, "anonymous")) {
            /* Add userid to principal URL */
            strcpy(req_tgt.tail, userid);
            req_tgt.userid = xstrdup(userid);

            /* Add response for URL */
            xml_add_response(fctx, 0, 0, NULL, NULL);

            free(req_tgt.userid);
        }
    }

    return (ret ? ret : HTTP_MULTI_STATUS);
}


struct search_crit {
    struct strlist *props;
    xmlChar *match;
    struct search_crit *next;
};


/* mboxlist_alluser() callback to find user principals (has Inbox) */
static int principal_search(const char *userid, void *rock)
{
    struct propfind_ctx *fctx = (struct propfind_ctx *) rock;
    struct search_crit *search_crit;
    size_t len;
    char *p;

    /* XXX - this function needs extradomain and virtdomains support */

    /* Check ACL for current user */
    if (principal_acl_check(userid, httpd_authstate)) return 0;

    /* Check against search criteria */
    for (search_crit = (struct search_crit *) fctx->filter_crit;
         search_crit; search_crit = search_crit->next) {
        struct strlist *prop;

        for (prop = search_crit->props; prop; prop = prop->next) {
            if (!strcmp(prop->s, "displayname")) {
                if (!xmlStrcasestr(BAD_CAST userid,
                                   search_crit->match)) return 0;
            }
            else if (!strcmp(prop->s, "calendar-user-address-set")) {
                char email[MAX_MAILBOX_NAME+1];

                snprintf(email, MAX_MAILBOX_NAME, "%s@%s",
                         userid, config_servername);
                if (!xmlStrcasestr(BAD_CAST email,
                                   search_crit->match)) return 0;
            }
            else if (!strcmp(prop->s, "calendar-user-type")) {
                if (!xmlStrcasestr(BAD_CAST "INDIVIDUAL",
                                   search_crit->match)) return 0;
            }
        }
    }

    /* Append principal name to URL path */
    len = strlen(namespace_principal.prefix);
    p = fctx->req_tgt->path + len;
    snprintf(p, MAX_MAILBOX_PATH - len, "/%s/%s/",
             USER_COLLECTION_PREFIX, userid);

    free(fctx->req_tgt->userid);
    fctx->req_tgt->userid = xstrdup(userid);

    return xml_add_response(fctx, 0, 0, NULL, NULL);
}


static const struct prop_entry prin_search_props[] = {

    /* WebDAV (RFC 4918) properties */
    { "displayname", NS_DAV, 0, NULL, NULL, NULL },

    /* CalDAV Scheduling (RFC 6638) properties */
    { "calendar-user-address-set", NS_CALDAV, 0, NULL, NULL, NULL },
    { "calendar-user-type", NS_CALDAV, 0, NULL, NULL, NULL },

    { NULL, 0, 0, NULL, NULL, NULL }
};


/* DAV:principal-property-search REPORT */
static int report_prin_prop_search(struct transaction_t *txn,
                                   struct meth_params *rparams __attribute__((unused)),
                                   xmlNodePtr inroot,
                                   struct propfind_ctx *fctx)
{
    int ret = 0;
    xmlNodePtr node;
    struct search_crit *search_crit, *next;
    unsigned apply_prin_set = 0;

    /* Parse children element of report */
    fctx->filter_crit = NULL;
    for (node = inroot->children; node; node = node->next) {
        if (node->type == XML_ELEMENT_NODE) {
            if (!xmlStrcmp(node->name, BAD_CAST "property-search")) {
                xmlNodePtr search;

                search_crit = xzmalloc(sizeof(struct search_crit));
                search_crit->next = fctx->filter_crit;
                fctx->filter_crit = search_crit;

                for (search = node->children; search; search = search->next) {
                    if (search->type == XML_ELEMENT_NODE) {
                        if (!xmlStrcmp(search->name, BAD_CAST "prop")) {
                            xmlNodePtr prop;

                            for (prop = search->children;
                                 prop; prop = prop->next) {
                                if (prop->type == XML_ELEMENT_NODE) {
                                    const struct prop_entry *entry;

                                    for (entry = prin_search_props;
                                         entry->name &&
                                             xmlStrcmp(prop->name,
                                                       BAD_CAST entry->name);
                                         entry++);

                                    if (!entry->name) {
                                        txn->error.desc =
                                            "Unsupported XML search prop";
                                        ret = HTTP_BAD_REQUEST;
                                        goto done;
                                    }
                                    else {
                                        appendstrlist(&search_crit->props,
                                                      (char *) entry->name);
                                    }
                                }
                            }
                        }
                        else if (!xmlStrcmp(search->name, BAD_CAST "match")) {
                            if (search_crit->match) {
                                txn->error.desc =
                                    "Too many DAV:match XML elements";
                                ret = HTTP_BAD_REQUEST;
                                goto done;
                            }

                            search_crit->match =
                                xmlNodeListGetString(inroot->doc,
                                                     search->children, 1);
                        }
                        else {
                            txn->error.desc = "Unknown XML element";
                            ret = HTTP_BAD_REQUEST;
                            goto done;
                        }
                    }
                }

                if (!search_crit->props) {
                    txn->error.desc = "Missing DAV:prop XML element";
                    ret = HTTP_BAD_REQUEST;
                    goto done;
                }
                if (!search_crit->match) {
                    txn->error.desc = "Missing DAV:match XML element";
                    ret = HTTP_BAD_REQUEST;
                    goto done;
                }
            }
            else if (!xmlStrcmp(node->name, BAD_CAST "prop")) {
                /* Already parsed in meth_report() */
            }
            else if (!xmlStrcmp(node->name,
                                BAD_CAST "apply-to-principal-collection-set")) {
                apply_prin_set = 1;
            }
            else {
                txn->error.desc = "Unknown XML element";
                ret = HTTP_BAD_REQUEST;
                goto done;
            }
        }
    }

    if (!fctx->filter_crit) {
        txn->error.desc = "Missing DAV:property-search XML element";
        ret = HTTP_BAD_REQUEST;
        goto done;
    }

    /* Only search DAV:principal-collection-set */
    if (apply_prin_set || !fctx->req_tgt->userid) {
        /* XXX  Do LDAP/SQL lookup of CN/email-address(es) here */

        ret = mboxlist_alluser(principal_search, fctx);
    }

  done:
    for (search_crit = fctx->filter_crit; search_crit; search_crit = next) {
        next = search_crit->next;

        if (search_crit->match) xmlFree(search_crit->match);
        freestrlist(search_crit->props);
        free(search_crit);
    }

    return (ret ? ret : HTTP_MULTI_STATUS);
}


/* DAV:principal-search-property-set REPORT */
static int report_prin_search_prop_set(struct transaction_t *txn,
                                       struct meth_params *rparams __attribute__((unused)),
                                       xmlNodePtr inroot,
                                       struct propfind_ctx *fctx)
{
    xmlNodePtr node;
    const struct prop_entry *entry;

    /* Look for child elements in request */
    for (node = inroot->children; node; node = node->next) {
        if (node->type == XML_ELEMENT_NODE) {
            txn->error.desc =
                "DAV:principal-search-property-set XML element MUST be empty";
            return HTTP_BAD_REQUEST;
        }
    }

    for (entry = prin_search_props; entry->name; entry++) {
        node = xmlNewChild(fctx->root, NULL,
                           BAD_CAST "principal-search-property", NULL);
        node = xmlNewChild(node, NULL, BAD_CAST "prop", NULL);
        ensure_ns(fctx->ns, entry->ns, fctx->root,
                  known_namespaces[entry->ns].href,
                  known_namespaces[entry->ns].prefix);
        xmlNewChild(node, fctx->ns[entry->ns], BAD_CAST entry->name, NULL);
    }

    return HTTP_OK;
}


/* Perform a REPORT request */
int meth_report(struct transaction_t *txn, void *params)
{
    struct meth_params *rparams = (struct meth_params *) params;
    int ret = 0, r;
    const char **hdr;
    unsigned depth = 0;
    xmlNodePtr inroot = NULL, outroot = NULL, cur, prop = NULL, props = NULL;
    const struct report_type_t *report = NULL;
    xmlNsPtr ns[NUM_NAMESPACE];
    struct hash_table ns_table = { 0, NULL, NULL };
    struct propfind_ctx fctx;

    memset(&fctx, 0, sizeof(struct propfind_ctx));

    /* Parse the path */
    r = dav_parse_req_target(txn, rparams);
    if (r) return r;

    /* Make sure method is allowed */
    if (!(txn->req_tgt.allow & ALLOW_DAV)) return HTTP_NOT_ALLOWED;

    /* Check Depth */
    if ((hdr = spool_getheader(txn->req_hdrs, "Depth"))) {
        if (!strcmp(hdr[0], "infinity")) {
            depth = 2;
        }
        else if ((sscanf(hdr[0], "%u", &depth) != 1) || (depth > 1)) {
            txn->error.desc = "Illegal Depth value";
            return HTTP_BAD_REQUEST;
        }
    }

    /* Parse the REPORT body */
    ret = parse_xml_body(txn, &inroot, NULL);
    if (!ret && !inroot) {
        txn->error.desc = "Missing request body";
        return HTTP_BAD_REQUEST;
    }
    if (ret) goto done;

    /* Add report type to our header cache */
    spool_cache_header(xstrdup(":type"), xstrdup((const char *) inroot->name),
                       txn->req_hdrs);

    /* Check the report type against our supported list */
    for (report = rparams->reports; report && report->name; report++) {
        if (inroot->ns &&
            !xmlStrcmp(inroot->ns->href,
                       BAD_CAST known_namespaces[report->ns].href) &&
            !xmlStrcmp(inroot->name, BAD_CAST report->name)) break;
    }
    if (!report || !report->name) {
        syslog(LOG_WARNING, "REPORT %s", inroot->name);
        /* DAV:supported-report */
        txn->error.precond = DAV_SUPP_REPORT;
        ret = HTTP_FORBIDDEN;
        goto done;
    }

    /* Check any depth limit */
    if (depth && (report->flags & REPORT_DEPTH_ZERO)) {
        txn->error.desc = "Depth header field MUST have value zero (0)";
        ret = HTTP_BAD_REQUEST;
        goto done;
    }

    /* Normalize depth so that:
     * 0 = home-set collection, 1+ = calendar collection, 2+ = calendar resource
     */
    if (txn->req_tgt.collection) depth++;
    if (txn->req_tgt.resource) depth++;

    /* Check ACL and location of mailbox */
    if (report->flags & REPORT_NEED_MBOX) {
        int rights;

        /* Check ACL for current user */
        rights = httpd_myrights(httpd_authstate, txn->req_tgt.mbentry);
        if ((rights & report->reqd_privs) != report->reqd_privs) {
            if (report->reqd_privs == DACL_READFB) ret = HTTP_NOT_FOUND;
            else {
                /* DAV:need-privileges */
                txn->error.precond = DAV_NEED_PRIVS;
                txn->error.resource = txn->req_tgt.path;
                txn->error.rights = report->reqd_privs;
                ret = HTTP_NO_PRIVS;
            }
            goto done;
        }

        if (txn->req_tgt.mbentry->server) {
            /* Remote mailbox */
            struct backend *be;

            be = proxy_findserver(txn->req_tgt.mbentry->server,
                                  &http_protocol, httpd_userid,
                                  &backend_cached, NULL, NULL, httpd_in);
            if (!be) ret = HTTP_UNAVAILABLE;
            else ret = http_pipe_req_resp(be, txn);
            goto done;
        }

        /* Local Mailbox */
    }

    /* Principal or Local Mailbox */

    if (report->flags & (REPORT_NEED_PROPS | REPORT_ALLOW_PROPS)) {
        /* Parse children element of report */
        for (cur = inroot->children; cur; cur = cur->next) {
            unsigned mode = PROPFIND_NONE;

            if (cur->type == XML_ELEMENT_NODE) {
                if (!xmlStrcmp(cur->name, BAD_CAST "allprop")) {
                    mode = PROPFIND_ALL;
                    prop = cur;
                }
                else if (!xmlStrcmp(cur->name, BAD_CAST "propname")) {
                    mode = PROPFIND_NAME;
                    fctx.prefer = PREFER_MIN;  /* Don't want 404 (Not Found) */
                    prop = cur;
                }
                else if (!xmlStrcmp(cur->name, BAD_CAST "prop")) {
                    mode = PROPFIND_PROP;
                    prop = cur;
                    props = cur->children;
                }
            }

            if (mode != PROPFIND_NONE) {
                if (fctx.mode != PROPFIND_NONE) {
                    txn->error.desc = "Multiple <*prop*> elements in REPORT";
                    ret = HTTP_BAD_REQUEST;
                    goto done;
                }

                fctx.mode = mode;
            }
        }

        if (!prop && (report->flags & REPORT_NEED_PROPS)) {
            txn->error.desc = "Missing <prop> element in REPORT";
            ret = HTTP_BAD_REQUEST;
            goto done;
        }
    }

    /* Start construction of our multistatus response */
    if (report->resp_root &&
        !(outroot = init_xml_response(report->resp_root, NS_DAV, inroot, ns))) {
        txn->error.desc = "Unable to create XML response";
        ret = HTTP_SERVER_ERROR;
        goto done;
    }

    /* Populate our propfind context */
    fctx.txn = txn;
    fctx.req_tgt = &txn->req_tgt;
    fctx.depth = depth;
    fctx.prefer |= get_preferences(txn);
    fctx.userid = httpd_userid;
    fctx.userisadmin = httpd_userisadmin;
    fctx.authstate = httpd_authstate;
    fctx.mbentry = NULL;
    fctx.mailbox = NULL;
    fctx.record = NULL;
    fctx.get_validators = rparams->get_validators;
    fctx.reqd_privs = report->reqd_privs;
    if (rparams->mime_types) fctx.free_obj = rparams->mime_types[0].free;
    fctx.proc_by_resource = &propfind_by_resource;
    fctx.elist = NULL;
    fctx.lprops = rparams->propfind.lprops;
    fctx.root = outroot;
    fctx.ns = ns;
    fctx.ns_table = &ns_table;
    fctx.ret = &ret;

    /* Parse the list of properties and build a list of callbacks */
    if (fctx.mode) {
        ret = preload_proplist(props, &fctx);

        /* iCalendar/vCard data in response should not be transformed */
        if (fctx.flags.fetcheddata) txn->flags.cc |= CC_NOTRANSFORM;
    }

    /* Process the requested report */
    if (!ret) ret = (*report->proc)(txn, rparams, inroot, &fctx);

    // might have made a change!
    sync_checkpoint(txn->conn->pin);

    /* Output the XML response */
    if (outroot) {
        switch (ret) {
        case HTTP_OK:
        case HTTP_MULTI_STATUS:
            /* iCalendar/vCard data in response should not be transformed */
            if (fctx.flags.fetcheddata) txn->flags.cc |= CC_NOTRANSFORM;

            xml_response(ret, txn, outroot->doc);

            ret = 0;
            break;

        default:
            break;
        }
    }

  done:
    /* Free the entry list */
    free_entry_list(fctx.elist);

    buf_free(&fctx.buf);

    free_hash_table(&ns_table, NULL);

    if (inroot) xmlFreeDoc(inroot->doc);
    if (outroot) xmlFreeDoc(outroot->doc);

    return ret;
}


/* Perform a UNLOCK request
 *
 * preconditions:
 *   DAV:need-privileges
 *   DAV:lock-token-matches-request-uri
 */
int meth_unlock(struct transaction_t *txn, void *params)
{
    struct meth_params *lparams = (struct meth_params *) params;
    int ret = HTTP_NO_CONTENT, r, precond;
    const char **hdr, *token;
    struct mailbox *mailbox = NULL;
    struct dav_data *ddata;
    struct index_record record;
    const char *etag;
    time_t lastmod;
    size_t len;
    void *davdb = NULL;

    /* Response should not be cached */
    txn->flags.cc |= CC_NOCACHE;

    /* Parse the path */
    r = dav_parse_req_target(txn, lparams);
    if (r) return r;

    /* Make sure method is allowed (only allowed on resources) */
    if (!(txn->req_tgt.allow & ALLOW_WRITE)) return HTTP_NOT_ALLOWED;

    /* Check for mandatory Lock-Token header */
    if (!(hdr = spool_getheader(txn->req_hdrs, "Lock-Token"))) {
        txn->error.desc = "Missing Lock-Token header";
        return HTTP_BAD_REQUEST;
    }
    token = hdr[0];

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

    /* Open mailbox for reading */
    r = mailbox_open_irl(txn->req_tgt.mbentry->name, &mailbox);
    if (r) {
        syslog(LOG_ERR, "http_mailbox_open(%s) failed: %s",
               txn->req_tgt.mbentry->name, error_message(r));
        txn->error.desc = error_message(r);
        ret = HTTP_SERVER_ERROR;
        goto done;
    }

    /* Open the DAV DB corresponding to the mailbox */
    davdb = lparams->davdb.open_db(mailbox);
    lparams->davdb.begin_transaction(davdb);

    /* Find message UID for the resource, if exists */
    lparams->davdb.lookup_resource(davdb, txn->req_tgt.mbentry->name,
                                   txn->req_tgt.resource, (void **) &ddata, 0);
    if (!ddata->rowid) {
        ret = HTTP_NOT_FOUND;
        goto done;
    }

    /* Check if resource is locked */
    if (ddata->lock_expire <= time(NULL)) {
        /* DAV:lock-token-matches-request-uri */
        txn->error.precond = DAV_BAD_LOCK_TOKEN;
        ret = HTTP_CONFLICT;
        goto done;
    }

    /* Check if current user owns the lock */
    if (strcmp(ddata->lock_ownerid, httpd_userid)) {
        /* Check ACL for current user */
        int rights = httpd_myrights(httpd_authstate, txn->req_tgt.mbentry);

        if (!(rights & DACL_ADMIN)) {
            /* DAV:need-privileges */
            txn->error.precond = DAV_NEED_PRIVS;
            txn->error.resource = txn->req_tgt.path;
            txn->error.rights = DACL_ADMIN;
            ret = HTTP_NO_PRIVS;
            goto done;
        }
    }

    /* Check if lock token matches */
    len = strlen(ddata->lock_token);
    if (token[0] != '<' || strlen(token) != len+2 || token[len+1] != '>' ||
        strncmp(token+1, ddata->lock_token, len)) {
        /* DAV:lock-token-matches-request-uri */
        txn->error.precond = DAV_BAD_LOCK_TOKEN;
        ret = HTTP_CONFLICT;
        goto done;
    }

    /* Fetch resource validators */
    r = lparams->get_validators(mailbox, (void *) ddata, httpd_userid,
                                &record, &etag, &lastmod);
    if (r) {
        txn->error.desc = error_message(r);
        ret = HTTP_SERVER_ERROR;
        goto done;
    }

    /* Check any preconditions */
    precond = lparams->check_precond(txn, params, mailbox,
                                     (void *) ddata, etag, lastmod);

    if (precond != HTTP_OK) {
        /* We failed a precondition - don't perform the request */
        ret = precond;
        goto done;
    }

    if (ddata->imap_uid) {
        /* Mapped URL - Remove the lock */
        ddata->lock_token = NULL;
        ddata->lock_owner = NULL;
        ddata->lock_ownerid = NULL;
        ddata->lock_expire = 0;

        lparams->davdb.write_resourceLOCKONLY(davdb, ddata);
    }
    else {
        /* Unmapped URL - Treat as lock-null and delete mapping entry */
        lparams->davdb.delete_resourceLOCKONLY(davdb, ddata->rowid);
    }

  done:
    if (davdb) {
        /* XXX error handling abort */
        lparams->davdb.commit_transaction(davdb);
        lparams->davdb.close_db(davdb);
    }
    mailbox_close(&mailbox);

    return ret;
}


int dav_store_resource(struct transaction_t *txn,
                       const char *data, size_t datalen,
                       struct mailbox *mailbox, struct index_record *oldrecord,
                       modseq_t createdmodseq, strarray_t *imapflags)
{
    int ret = HTTP_CREATED, r;
    hdrcache_t hdrcache = txn->req_hdrs;
    struct stagemsg *stage;
    FILE *f = NULL;
    const char **hdr, *cte;
    quota_t qdiffs[QUOTA_NUMRESOURCES] = QUOTA_DIFFS_DONTCARE_INITIALIZER;
    time_t now = time(NULL);
    struct appendstate as;

    /* Prepare to stage the message */
    if (!(f = append_newstage(mailbox->name, now, 0, &stage))) {
        syslog(LOG_ERR, "append_newstage(%s) failed", mailbox->name);
        txn->error.desc = "append_newstage() failed";
        return HTTP_SERVER_ERROR;
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
        char datestr[80];       /* XXX: Why do we need 80 character buffer? */
        time_to_rfc5322(now, datestr, sizeof(datestr));
        fprintf(f, "Date: %s\r\n", datestr);
    }

    if ((hdr = spool_getheader(hdrcache, "Message-ID"))) {
        fprintf(f, "Message-ID: %s\r\n", hdr[0]);
    }

    if ((hdr = spool_getheader(hdrcache, "X-Schedule-User-Address"))) {
        fprintf(f, "X-Schedule-User-Address: %s\r\n", hdr[0]);
    }

    if ((hdr = spool_getheader(hdrcache, "Content-Type"))) {
        fprintf(f, "Content-Type: %s\r\n", hdr[0]);
    }
    else fputs("Content-Type: application/octet-stream\r\n", f);

    if (!datalen) {
        datalen = strlen(data);
        cte = "8bit";
    }
    else {
        cte = strnchr(data, '\0', datalen) ? "binary" : "8bit";
    }
    fprintf(f, "Content-Transfer-Encoding: %s\r\n", cte);

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
    qdiffs[QUOTA_STORAGE] = ftell(f);

    fclose(f);

    qdiffs[QUOTA_MESSAGE] = 1;

    /* Prepare to append the message to the mailbox */
    if ((r = append_setup_mbox(&as, mailbox, httpd_userid, httpd_authstate,
                          0, qdiffs, 0, 0, EVENT_MESSAGE_NEW|EVENT_CALENDAR))) {
        syslog(LOG_ERR, "append_setup(%s) failed: %s",
               mailbox->name, error_message(r));
        if (r == IMAP_QUOTA_EXCEEDED) {
            /* DAV:quota-not-exceeded */
            txn->error.precond = DAV_OVER_QUOTA;
            ret = HTTP_NO_STORAGE;
        } else {
            ret = HTTP_SERVER_ERROR;
        }
        txn->error.desc = "append_setup() failed";
    }
    else {
        struct body *body = NULL;

        strarray_t *flaglist = NULL;
        struct entryattlist *annots = NULL;

        if (oldrecord) {
            flaglist = mailbox_extract_flags(mailbox, oldrecord, httpd_userid);
            mailbox_get_annotate_state(mailbox, oldrecord->uid, NULL);
            annots = mailbox_extract_annots(mailbox, oldrecord);
        }

        /* XXX - casemerge?  Doesn't matter with flags */
        if (imapflags) {
            if (flaglist)
                strarray_cat(flaglist, imapflags);
            else
                flaglist = strarray_dup(imapflags);
        }

        /* Append the message to the mailbox */
        if ((r = append_fromstage(&as, &body, stage, now, createdmodseq, flaglist, 0, &annots))) {
            syslog(LOG_ERR, "append_fromstage(%s) failed: %s",
                   mailbox->name, error_message(r));
            ret = HTTP_SERVER_ERROR;
            txn->error.desc = "append_fromstage() failed";
        }
        if (body) {
            message_free_body(body);
            free(body);
        }
        strarray_free(flaglist);
        freeentryatts(annots);

        if (r) append_abort(&as);
        else {
            /* Commit the append to the mailbox */
            if ((r = append_commit(&as))) {
                syslog(LOG_ERR, "append_commit(%s) failed: %s",
                       mailbox->name, error_message(r));
                ret = HTTP_SERVER_ERROR;
                txn->error.desc = "append_commit() failed";
            }
            else {
                if (oldrecord) {
                    /* Now that we have the replacement message in place
                       expunge the old one. */
                    int userflag;

                    ret = HTTP_NO_CONTENT;

                    /* Perform the actual expunge */
                    r = mailbox_user_flag(mailbox, DFLAG_UNBIND, &userflag, 1);
                    if (!r) {
                        oldrecord->user_flags[userflag/32] |= 1 << (userflag & 31);
                        oldrecord->internal_flags |= FLAG_INTERNAL_EXPUNGED;
                        r = mailbox_rewrite_index_record(mailbox, oldrecord);
                    }
                    if (r) {
                        syslog(LOG_ERR, "expunging record (%s) failed: %s",
                               mailbox->name, error_message(r));
                        txn->error.desc = error_message(r);
                        ret = HTTP_SERVER_ERROR;
                    }
                }

                if (!r) {
                    /* Read index record for new message (always the last one) */
                    struct index_record newrecord;
                    struct dav_data ddata;
                    static char etagbuf[256];
                    const char *etag;

                    ddata.alive = 1;
                    ddata.imap_uid = mailbox->i.last_uid;
                    dav_get_validators(mailbox, &ddata, httpd_userid, &newrecord,
                                       &etag, &txn->resp_body.lastmod);
                    strncpy(etagbuf, etag, 255);
                    etagbuf[255] = 0;
                    txn->resp_body.etag = etagbuf;
                }
            }
        }
    }

    append_removestage(stage);

    return ret;
}


static void my_dav_init(struct buf *serverinfo)
{
    time_t compile_time = calc_compile_time(__TIME__, __DATE__);
    struct stat sbuf;
    struct message_guid guid;
    xmlNodePtr root, node, apps, app;
    xmlNsPtr ns[NUM_NAMESPACE];

    buf_printf(serverinfo, " SQLite/%s", sqlite3_libversion());

    /* Generate token based on compile date/time of this source file,
       the number of available RSCALEs and the config file size/mtime */
    stat(config_filename, &sbuf);
    server_info_lastmod = MAX(compile_time, sbuf.st_mtime);

    buf_printf(&server_info_token, TIME_T_FMT "-" TIME_T_FMT "-" OFF_T_FMT, compile_time,
               sbuf.st_mtime, sbuf.st_size);
    message_guid_generate(&guid, buf_cstring(&server_info_token),
                          buf_len(&server_info_token));
    buf_setcstr(&server_info_token, message_guid_encode(&guid));

    /* Generate link header contents */
    buf_printf(&server_info_link,
               "<%s/%s>; rel=\"server-info\"; token=\"%s\"",
               namespace_principal.prefix, SERVER_INFO,
               buf_cstring(&server_info_token));

    /* Start construction of our server-info */
    if (!(root = init_xml_response("server-info", NS_DAV, NULL, ns))) {
        syslog(LOG_ERR, "Unable to create server-info XML");
        return;
    }

    /* Add token */
    xmlNewTextChild(root, ns[NS_DAV], BAD_CAST "token",
                    BAD_CAST buf_cstring(&server_info_token));

    /* Add server */
    if (config_serverinfo == IMAP_ENUM_SERVERINFO_ON) {
        node = xmlNewChild(root, NULL, BAD_CAST "server", NULL);
        xmlNewChild(node, ns[NS_DAV],
                    BAD_CAST "name", BAD_CAST "Cyrus-HTTP");
        xmlNewTextChild(node, ns[NS_DAV],
                        BAD_CAST "version", BAD_CAST CYRUS_VERSION);
    }

    /* Add global DAV features */
    node = xmlNewChild(root, NULL, BAD_CAST "features", NULL);
    xmlNewChild(node, ns[NS_DAV], BAD_CAST "class-1", NULL);
    xmlNewChild(node, ns[NS_DAV], BAD_CAST "class-2", NULL);
    xmlNewChild(node, ns[NS_DAV], BAD_CAST "class-3", NULL);
    xmlNewChild(node, ns[NS_DAV], BAD_CAST "access-control", NULL);
    xmlNewChild(node, ns[NS_DAV], BAD_CAST "extended-mkcol", NULL);
    xmlNewChild(node, ns[NS_DAV], BAD_CAST "quota", NULL);
    xmlNewChild(node, ns[NS_DAV], BAD_CAST "sync-collection", NULL);
    xmlNewChild(node, ns[NS_DAV], BAD_CAST "add-member", NULL);

    apps = xmlNewChild(root, NULL, BAD_CAST "applications", NULL);

    if (namespace_calendar.enabled) {
        app = xmlNewChild(apps, NULL, BAD_CAST "application", NULL);
        ensure_ns(ns, NS_CALDAV, app, XML_NS_CALDAV, "C");
        xmlNewChild(app, NULL, BAD_CAST "name", BAD_CAST "caldav");

        /* Add CalDAV features */
        node = xmlNewChild(app, NULL, BAD_CAST "features", NULL);
        xmlNewChild(node, ns[NS_CALDAV],
                    BAD_CAST "calendar-access", NULL);
        if (namespace_calendar.allow & ALLOW_CAL_SCHED)
            xmlNewChild(node, ns[NS_CALDAV],
                        BAD_CAST "calendar-auto-schedule", NULL);
        if (namespace_calendar.allow & ALLOW_CAL_NOTZ)
            xmlNewChild(node, ns[NS_CALDAV],
                        BAD_CAST "calendar-no-timezone", NULL);
        if (namespace_calendar.allow & ALLOW_CAL_AVAIL)
            xmlNewChild(node, ns[NS_CALDAV],
                        BAD_CAST "calendar-availability", NULL);
        if (namespace_calendar.allow & ALLOW_CAL_ATTACH) {
            xmlNewChild(node, ns[NS_CALDAV],
                        BAD_CAST "calendar-managed-attachments", NULL);
            xmlNewChild(node, ns[NS_CALDAV],
                        BAD_CAST "calendar-managed-attachments-no-recurrence",
                        NULL);
        }
    }

    if (namespace_addressbook.enabled) {
        app = xmlNewChild(apps, NULL, BAD_CAST "application", NULL);
        ensure_ns(ns, NS_CARDDAV, app, XML_NS_CARDDAV, "A");
        xmlNewChild(app, NULL, BAD_CAST "name", BAD_CAST "carddav");

        /* Add CardDAV features */
        node = xmlNewChild(app, NULL, BAD_CAST "features", NULL);
        xmlNewChild(node, ns[NS_CARDDAV], BAD_CAST "addressbook", NULL);
    }

    /* Dump XML response tree into a text buffer */
    xmlDocDumpFormatMemoryEnc(root->doc,
                                  &server_info, &server_info_size, "utf-8", 1);
    xmlFreeDoc(root->doc);

    if (!server_info) {
        syslog(LOG_ERR, "Unable to dump server-info XML tree");
    }

    return;
}


static void my_dav_shutdown(void)
{
    if (server_info) xmlFree(server_info);
    buf_free(&server_info_token);
    buf_free(&server_info_link);
}


static int get_server_info(struct transaction_t *txn)
{
    int precond;
    const char **hdr, *etag;

    if (!server_info) return HTTP_NOT_FOUND;

    if (!httpd_userid) return HTTP_UNAUTHORIZED;

    if ((hdr = spool_getheader(txn->req_hdrs, "Accept")) &&
        strcmp(hdr[0], "application/server-info+xml"))
        return HTTP_NOT_ACCEPTABLE;

    /* Check any preconditions, including range request */
    txn->flags.ranges = 1;
    etag = buf_cstring(&server_info_token);
    precond = check_precond(txn, etag, server_info_lastmod);

    switch (precond) {
    case HTTP_OK:
    case HTTP_PARTIAL:
    case HTTP_NOT_MODIFIED:
        /* Fill in Etag,  Last-Modified, and Expires */
        txn->resp_body.etag = etag;
        txn->resp_body.lastmod = server_info_lastmod;
        txn->resp_body.maxage = 86400;  /* 24 hrs */
        txn->flags.cc |= CC_MAXAGE;

        if (precond != HTTP_NOT_MODIFIED) break;

        GCC_FALLTHROUGH

    default:
        /* We failed a precondition - don't perform the request */
        return precond;
    }

    /* Output the XML response */
    txn->resp_body.type = "application/server-info+xml; charset=utf-8";
    write_body(precond, txn, (char *) server_info, server_info_size);

    return 0;
}

static void dav_parse_textmatch(xmlNodePtr node, struct text_match_t **match,
                                struct filter_profile_t *profile,
                                struct error_t *error)
{
    unsigned negate = 0;
    unsigned type = MATCH_TYPE_CONTAINS;
    unsigned collation = profile->collation;
    xmlChar *attr;

    *match = NULL;

    attr = xmlGetProp(node, BAD_CAST "negate-condition");
    if (attr) {
        if (!xmlStrcmp(attr, BAD_CAST "yes")) negate = 1;
        else if (xmlStrcmp(attr, BAD_CAST "no")) {
            error->precond = profile->filter_precond;
            error->desc = "negate-condition is a yes/no option";
            error->node = xmlCopyNode(node->parent, 1);
        }
        xmlFree(attr);
    }

    if (!error->precond) {
        attr = xmlGetProp(node, BAD_CAST "match-type");
        if (attr) {
            const struct match_type_t *match;

            for (match = dav_match_types; match->name; match++) {
                if (!xmlStrcmp(attr, BAD_CAST match->name)) break;
            }
            if (match->name) type = match->value;
            else {
                error->precond = profile->filter_precond;
                error->desc = "Unsupported match-type";
                error->node = xmlCopyNode(node->parent, 1);
            }
            xmlFree(attr);
        }
    }

    if (!error->precond) {
        attr = xmlGetProp(node, BAD_CAST "collation");
        if (attr) {
            if (xmlStrcmp(attr, BAD_CAST "default")) {
                const struct collation_t *col;

                for (col = dav_collations; col->name; col++) {
                    if (!xmlStrcmp(attr, BAD_CAST col->name)) break;
                }
                if (col->name) collation = col->value;
                else error->precond = profile->collation_precond;
            }
            xmlFree(attr);
        }
    }

    if (!error->precond) {
        *match = xzmalloc(sizeof(struct text_match_t));
        (*match)->text = xmlNodeGetContent(node);
        (*match)->negate = negate;
        (*match)->type = type;
        (*match)->collation = collation;
    }
}

static void dav_parse_paramfilter(xmlNodePtr root, struct param_filter **param,
                                  struct filter_profile_t *profile,
                                  struct error_t *error)
{
    xmlChar *attr;
    xmlNodePtr node;

    attr = xmlGetProp(root, BAD_CAST "name");
    if (!attr) {
        error->precond = profile->filter_precond;
        error->desc = "Missing 'name' attribute";
        error->node = xmlCopyNode(root, 2);
    }
    else {
        *param = xzmalloc(sizeof(struct param_filter));
        (*param)->name = attr;

        if (profile->param_string_to_kind) {
            (*param)->kind = profile->param_string_to_kind((const char *) attr);
        
            if ((*param)->kind == profile->no_param_value) {
                error->precond = profile->filter_precond;
                error->desc = "Unsupported parameter";
                error->node = xmlCopyNode(root, 2);
            }
        }
    }

    for (node = xmlFirstElementChild(root); node && !error->precond;
         node = xmlNextElementSibling(node)) {

        if ((*param)->not_defined) {
            error->precond = profile->filter_precond;
            error->desc = DAV_FILTER_ISNOTDEF_ERR;
            error->node = xmlCopyNode(root, 1);
        }
        else if (!xmlStrcmp(node->name, BAD_CAST "is-not-defined")) {
            if ((*param)->match) {
                error->precond = profile->filter_precond;
                error->desc = DAV_FILTER_ISNOTDEF_ERR;
                error->node = xmlCopyNode(root, 1);
            }
            else (*param)->not_defined = 1;
        }
        else if (!xmlStrcmp(node->name, BAD_CAST "text-match")) {
            if ((*param)->match) {
                error->precond = profile->filter_precond;
                error->desc = "Multiple text-match";
                error->node = xmlCopyNode(root, 1);
            }
            else {
                struct text_match_t *match = NULL;

                dav_parse_textmatch(node, &match, profile, error);
                (*param)->match = match;
            }
        }
        else {
            error->precond = profile->filter_precond;
            error->desc =
                "Unsupported element in param-filter";
            error->node = xmlCopyNode(root, 1);
        }
    }
}

void dav_parse_propfilter(xmlNodePtr root, struct prop_filter **prop,
                          struct filter_profile_t *profile,
                          struct error_t *error)
{
    xmlChar *attr;
    xmlNodePtr node;

    attr = xmlGetProp(root, BAD_CAST "name");
    if (!attr) {
        error->precond = profile->filter_precond;
        error->desc = "Missing 'name' attribute";
        error->node = xmlCopyNode(root, 2);
    }
    else {
        *prop = xzmalloc(sizeof(struct prop_filter));
        (*prop)->name = attr;
        (*prop)->allof = profile->allof;

        if (profile->prop_string_to_kind) {
            (*prop)->kind = profile->prop_string_to_kind((const char *) attr);

            if ((*prop)->kind == profile->no_prop_value) {
                error->precond = profile->filter_precond;
                error->desc = "Unsupported property";
                error->node = xmlCopyNode(root, 2);
            }
        }

        if (!error->precond) {
            attr = xmlGetProp(root, BAD_CAST "test");
            if (attr) {
                if (!xmlStrcmp(attr, BAD_CAST "allof")) (*prop)->allof = 1;
                else if (!xmlStrcmp(attr, BAD_CAST "anyof")) (*prop)->allof = 0;
                else {
                    error->precond = profile->filter_precond;
                    error->desc = "Unsupported test";
                    error->node = xmlCopyNode(root, 2);
                }
                xmlFree(attr);
            }
        }
    }

    for (node = xmlFirstElementChild(root); node && !error->precond;
         node = xmlNextElementSibling(node)) {

        if ((*prop)->not_defined) {
            error->precond = profile->filter_precond;
            error->desc = DAV_FILTER_ISNOTDEF_ERR;
            error->node = xmlCopyNode(root, 1);
        }
        else if (!xmlStrcmp(node->name, BAD_CAST "is-not-defined")) {
            if ((*prop)->other || (*prop)->match || (*prop)->param) {
                error->precond = profile->filter_precond;
                error->desc = DAV_FILTER_ISNOTDEF_ERR;
                error->node = xmlCopyNode(root, 1);
            }
            else (*prop)->not_defined = 1;
        }
        else if (!xmlStrcmp(node->name, BAD_CAST "text-match")) {
            struct text_match_t *match = NULL;

            dav_parse_textmatch(node, &match, profile, error);
            if (match) {
                if ((*prop)->match) match->next = (*prop)->match;
                (*prop)->match = match;
            }
        }
        else if (!xmlStrcmp(node->name, BAD_CAST "param-filter")) {
            struct param_filter *param = NULL;

            dav_parse_paramfilter(node, &param, profile, error);
            if (param) {
                if ((*prop)->param) param->next = (*prop)->param;
                (*prop)->param = param;
            }
        }
        else if (profile->parse_propfilter) {
            profile->parse_propfilter(node, *prop, error);
        }
        else {
            error->precond = profile->filter_precond;
            error->desc = "Unsupported element in prop-filter";
            error->node = xmlCopyNode(root, 1);
        }
    }
}

void dav_free_propfilter(struct prop_filter *prop)
{
    struct param_filter *param, *next;

    xmlFree(prop->name);
    if (prop->match) {
        xmlFree(prop->match->text);
        free(prop->match);
    }
    for (param = prop->param; param; param = next) {
        next = param->next;

        xmlFree(param->name);
        if (param->match) {
            xmlFree(param->match->text);
            free(param->match);
        }
        free(param);
    }
    free(prop);
}

int dav_apply_textmatch(xmlChar *text, struct text_match_t *match)
{
    const xmlChar *cp = NULL;
    int textlen, matchlen;
    int r = 0;

    switch (match->type) {
    case MATCH_TYPE_CONTAINS:
        switch (match->collation) {
        case COLLATION_UNICODE:
            /* XXX  how to do this? */
        case COLLATION_ASCII:
            cp = xmlStrcasestr(text, match->text);
            break;
        case COLLATION_OCTET:
            cp = xmlStrstr(text, match->text);
            break;
        }

        r = (cp != NULL);
        break;
    case MATCH_TYPE_EQUALS:
        switch (match->collation) {
        case COLLATION_UNICODE:
            /* XXX  how to do this? */
        case COLLATION_ASCII:
            r = !xmlStrcasecmp(text, match->text);
            break;
        case COLLATION_OCTET:
            r = xmlStrEqual(text, match->text);
            break;
        }
        break;
    case MATCH_TYPE_PREFIX:
        matchlen = xmlStrlen(match->text);

        switch (match->collation) {
        case COLLATION_UNICODE:
            /* XXX  how to do this? */
        case COLLATION_ASCII:
            r = !xmlStrncasecmp(text, match->text, matchlen);
            break;
        case COLLATION_OCTET:
            r = !xmlStrncmp(text, match->text, matchlen);
            break;
        }
        break;
    case MATCH_TYPE_SUFFIX:
        textlen = xmlStrlen(text);
        matchlen = xmlStrlen(match->text);

        if (textlen < matchlen) r = 0;
        else {
            cp = text += (textlen - matchlen);

            switch (match->collation) {
            case COLLATION_UNICODE:
                /* XXX  how to do this? */
            case COLLATION_ASCII:
                r = !xmlStrcasecmp(cp, match->text);
                break;
            case COLLATION_OCTET:
                r = xmlStrEqual(cp, match->text);
                break;
            }
        }
        break;
    }

    if (match->negate) r = !r;

    return r;
}
