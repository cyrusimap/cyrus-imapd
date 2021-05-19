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
 *   - DAV:creationdate sould be added to cyrus.header since it only
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

#include "http_dav.h"
#include "annotate.h"
#include "acl.h"
#include "append.h"
#include "caldav_db.h"
#include "dlist.h"
#include "exitcodes.h"
#include "global.h"
#include "http_proxy.h"
#include "index.h"
#include "proxy.h"
#include "times.h"
#include "syslog.h"
#include "strhash.h"
#include "tok.h"
#include "util.h"
#include "version.h"
#include "webdav_db.h"
#include "xmalloc.h"
#include "xml_support.h"
#include "xstrlcat.h"
#include "xstrlcpy.h"
#include "xstrnchr.h"

/* generated headers are not necessarily in current directory */
#include "imap/http_err.h"
#include "imap/imap_err.h"

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
static struct webdav_db *auth_webdavdb = NULL;

static void my_dav_init(struct buf *serverinfo);
static void my_dav_auth(const char *userid);
static void my_dav_reset(void);
static void my_dav_shutdown(void);

static int get_server_info(struct transaction_t *txn);
static void get_synctoken(struct mailbox *mailbox,
                          struct buf *buf, const char *prefix);

static int principal_parse_path(const char *path, struct request_target_t *tgt,
                                const char **errstr);
static int propfind_displayname(const xmlChar *name, xmlNsPtr ns,
                                struct propfind_ctx *fctx,
                                xmlNodePtr prop, xmlNodePtr resp,
                                struct propstat propstat[], void *rock);
static int propfind_restype(const xmlChar *name, xmlNsPtr ns,
                            struct propfind_ctx *fctx,
                            xmlNodePtr prop, xmlNodePtr resp,
                            struct propstat propstat[], void *rock);
static int propfind_alturiset(const xmlChar *name, xmlNsPtr ns,
                              struct propfind_ctx *fctx,
                              xmlNodePtr prop, xmlNodePtr resp,
                              struct propstat propstat[], void *rock);
static int propfind_notifyurl(const xmlChar *name, xmlNsPtr ns,
                              struct propfind_ctx *fctx,
                              xmlNodePtr prop, xmlNodePtr resp,
                              struct propstat propstat[], void *rock);


static int propfind_csnotify_collection(struct propfind_ctx *fctx,
                                        xmlNodePtr props);

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
    { "creationdate", NS_DAV, PROP_ALLPROP, NULL, NULL, NULL },
    { "displayname", NS_DAV, PROP_ALLPROP | PROP_COLLECTION,
      propfind_displayname, NULL, NULL },
    { "getcontentlanguage", NS_DAV, PROP_ALLPROP, NULL, NULL, NULL },
    { "getcontentlength", NS_DAV, PROP_ALLPROP | PROP_COLLECTION,
      propfind_getlength, NULL, NULL },
    { "getcontenttype", NS_DAV, PROP_ALLPROP, NULL, NULL, NULL },
    { "getetag", NS_DAV, PROP_ALLPROP, NULL, NULL, NULL },
    { "getlastmodified", NS_DAV, PROP_ALLPROP, NULL, NULL, NULL },
    { "lockdiscovery", NS_DAV, PROP_ALLPROP | PROP_COLLECTION,
      propfind_lockdisc, NULL, NULL },
    { "resourcetype", NS_DAV, PROP_ALLPROP | PROP_COLLECTION,
      propfind_restype, NULL, NULL },
    { "supportedlock", NS_DAV, PROP_ALLPROP | PROP_COLLECTION,
      propfind_suplock, NULL, NULL },

    /* WebDAV Versioning (RFC 3253) properties */
    { "supported-report-set", NS_DAV, PROP_COLLECTION,
      propfind_reportset, NULL, (void *) principal_reports },

    /* WebDAV ACL (RFC 3744) properties */
    { "alternate-URI-set", NS_DAV, PROP_COLLECTION,
      propfind_alturiset, NULL, NULL },
    { "principal-URL", NS_DAV, PROP_COLLECTION,
      propfind_principalurl, NULL, NULL },
    { "group-member-set", NS_DAV, 0, NULL, NULL, NULL },
    { "group-membership", NS_DAV, 0, NULL, NULL, NULL },
    { "principal-collection-set", NS_DAV, PROP_COLLECTION,
      propfind_princolset, NULL, NULL },

    /* WebDAV Current Principal (RFC 5397) properties */
    { "current-user-principal", NS_DAV, PROP_COLLECTION,
      propfind_curprin, NULL, NULL },

    /* CalDAV (RFC 4791) properties */
    { "calendar-home-set", NS_CALDAV, PROP_COLLECTION,
      propfind_calurl, NULL, NULL },

    /* CalDAV Scheduling (RFC 6638) properties */
    { "schedule-inbox-URL", NS_CALDAV, PROP_COLLECTION,
      propfind_calurl, NULL, SCHED_INBOX },
    { "schedule-outbox-URL", NS_CALDAV, PROP_COLLECTION,
      propfind_calurl, NULL, SCHED_OUTBOX },
    { "calendar-user-address-set", NS_CALDAV, PROP_COLLECTION,
      propfind_caluseraddr, NULL, NULL },
    { "calendar-user-type", NS_CALDAV, PROP_COLLECTION,
      propfind_calusertype, NULL, NULL },

    /* CardDAV (RFC 6352) properties */
    { "addressbook-home-set", NS_CARDDAV, PROP_COLLECTION,
      propfind_abookhome, NULL, NULL },

    /* WebDAV Notifications (draft-pot-webdav-notifications) properties */
    { "notification-URL", NS_DAV, PROP_COLLECTION,
      propfind_notifyurl, NULL, NULL },

    /* Backwards compatibility with Apple notifications clients */
    { "notification-URL", NS_CS, PROP_COLLECTION,
      propfind_notifyurl, NULL, NULL },

    { NULL, 0, 0, NULL, NULL, NULL }
};


static struct meth_params princ_params = {
    .parse_path = &principal_parse_path,
    .propfind = { 0, principal_props },
    .reports = principal_reports
};

/* Namespace for WebDAV principals */
struct namespace_t namespace_principal = {
    URL_NS_PRINCIPAL, 0, "/dav/principals", NULL,
    http_allow_noauth_get, /*authschemes*/0,
    /*mbtype */ 0,
    ALLOW_READ | ALLOW_DAV,
    &my_dav_init, &my_dav_auth, &my_dav_reset, &my_dav_shutdown, &dav_premethod,
    /*bearer*/NULL,
    {
        { NULL,                 NULL },                 /* ACL          */
        { NULL,                 NULL },                 /* BIND         */
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
        { NULL,                 NULL },                 /* PROPPATCH    */
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

    /* WebDAV (RFC 4918) preconditons */
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


/* Check ACL on userid's principal (Inbox): LOOKUP right gives access */
static int principal_acl_check(const char *userid, struct auth_state *authstate)
{
    int r = 0;

    if (!httpd_userisadmin) {
        char *inboxname = mboxname_user_mbox(userid, NULL);
        mbentry_t *mbentry = NULL;

        r = http_mlookup(inboxname, &mbentry, NULL);
        if (r) {
            syslog(LOG_ERR, "mlookup(%s) failed: %s",
                   inboxname, error_message(r));
            r = HTTP_NOT_FOUND;
        }
        else if (!(httpd_myrights(authstate, mbentry) & ACL_LOOKUP)) {
            r = HTTP_NOT_FOUND;
        }

        mboxlist_entry_free(&mbentry);
        free(inboxname);
    }

    return r;
}


/* Parse request-target path in DAV principals namespace */
static int principal_parse_path(const char *path, struct request_target_t *tgt,
                                const char **errstr)
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
        *errstr = "Namespace mismatch request target path";
        return HTTP_FORBIDDEN;
    }

    /* Skip namespace */
    p += len;
    if (!*p || !*++p) {
        /* Make sure collection is terminated with '/' */
        if (p[-1] != '/') *p++ = '/';
        return 0;
    }

    /* Check if we're in user space */
    len = strcspn(p, "/");
    if (!strncmp(p, USER_COLLECTION_PREFIX, len)) {
        p += len;
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

        p += len;
        if (!*p || !*++p) return 0;
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
//      *errstr = "Too many segments in request target path";
        return HTTP_NOT_FOUND;
    }

    return 0;
}


/* Parse request-target path in Cal/CardDAV namespace */
EXPORTED int calcarddav_parse_path(const char *path,
                                   struct request_target_t *tgt,
                                   const char *mboxprefix,
                                   const char **errstr)
{
    char *p, *owner = NULL, *collection = NULL, *freeme = NULL;
    size_t len;
    const char *mboxname;
    mbname_t *mbname = NULL;

    if (*tgt->path) return 0;  /* Already parsed */

    /* Make a working copy of target path */
    strlcpy(tgt->path, path, sizeof(tgt->path));
    tgt->tail = tgt->path + strlen(tgt->path);

    p = tgt->path;

    /* Sanity check namespace */
    len = strlen(tgt->namespace->prefix);
    if (strlen(p) < len ||
        strncmp(tgt->namespace->prefix, p, len) || (path[len] && path[len] != '/')) {
        *errstr = "Namespace mismatch request target path";
        return HTTP_FORBIDDEN;
    }

    tgt->mboxprefix = mboxprefix;

    /* Default to bare-bones Allow bits */
    tgt->allow &= ALLOW_READ_MASK;

    /* Skip namespace */
    p += len;
    if (!*p || !*++p) return 0;

    /* Check if we're in user space */
    len = strcspn(p, "/");
    /* zzzz is part of the FastMail sorting hack to make shared collections
     * always appear later */
    if (!strncmp(p, USER_COLLECTION_PREFIX, len) || !strncmp(p, "zzzz", len)) {
        p += len;
        if (!*p || !*++p) return 0;

        /* Get user id */
        len = strcspn(p, "/");
        tgt->userid = xstrndup(p, len);

        p += len;
        if (!*p || !*++p) {
            /* Make sure home-set is terminated with '/' */
            if (p[-1] != '/') *p++ = '/';
            goto done;
        }

        len = strcspn(p, "/");
    }

    /* Get collection */
    tgt->collection = p;
    tgt->collen = len;

    p += len;
    if (!*p || !*++p) {
        /* Make sure collection is terminated with '/' */
        if (p[-1] != '/') *p++ = '/';
        goto done;
    }

    /* Get resource */
    len = strcspn(p, "/");
    tgt->resource = p;
    tgt->reslen = len;

    p += len;

    if (*p) {
//      *errstr = "Too many segments in request target path";
        return HTTP_NOT_FOUND;
    }

  done:
    /* Create mailbox name from the parsed path */

    owner = tgt->userid;
    if (tgt->collen) {
        collection = freeme = xstrndup(tgt->collection, tgt->collen);

        /* Shared collection encoded as: <owner> "." <mboxname> */
        if (!tgt->mbentry &&  /* Not MKCOL or COPY/MOVE destination */
            (p = strrchr(collection, SHARED_COLLECTION_DELIM))) {
            owner = collection;
            *p++ = '\0';
            collection = p;

            tgt->flags = TGT_DAV_SHARED;
            tgt->allow |= ALLOW_DELETE;
        }
    }

    mbname = mbname_from_userid(owner);

    mbname_push_boxes(mbname, mboxprefix);
    if (collection) {
        mbname_push_boxes(mbname, collection);
        free(freeme);
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
        /* Just return the mboxname (MKCOL or COPY/MOVE destination) */
        tgt->mbentry->name = xstrdup(mboxname);

        if (!mboxlist_createmailboxcheck(mboxname, 0, NULL, httpd_userisadmin,
                                         httpd_userid, httpd_authstate,
                                         NULL, NULL, 0 /* force */)) {
            tgt->allow |= ALLOW_MKCOL;
        }
    }
    else if (*mboxname) {
        /* Locate the mailbox */
        int r = http_mlookup(mboxname, &tgt->mbentry, NULL);
        if (r) {
            syslog(LOG_ERR, "mlookup(%s) failed: %s",
                   mboxname, error_message(r));
            *errstr = error_message(r);
            mbname_free(&mbname);

            switch (r) {
            case IMAP_PERMISSION_DENIED: return HTTP_FORBIDDEN;
            case IMAP_MAILBOX_NONEXISTENT: return HTTP_NOT_FOUND;
            default: return HTTP_SERVER_ERROR;
            }
        }
    }

    /* Set generic Allow bits based on path components */
    tgt->allow |= ALLOW_ACL | ALLOW_PROPPATCH;

    if (tgt->collection) {
        tgt->allow |= ALLOW_WRITE | ALLOW_DELETE;

        if (!tgt->resource) tgt->allow |= ALLOW_POST;
    }
    else if (tgt->userid) tgt->allow |= ALLOW_MKCOL;

    mbname_free(&mbname);

    return 0;
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

                get_synctoken(mailbox, &buf, SYNC_TOKEN_URL_SCHEME);
                r = !strcmp(cond, buf_cstring(&buf));
                if (!r) {
                    get_synctoken(mailbox, &buf, XML_NS_MECOM "ctag/");
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
        if (!eval_if(hdr[0], params, mailbox, txn->req_tgt.resource,
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
            txn->resp_body.link = buf_cstring(&server_info_link);
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
    if (!(root = xmlNewNode(NULL, BAD_CAST resp))) return NULL;

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
            /* Last char of token signals href (1) or text (0) */
            if (data->lock_token[strlen(data->lock_token)-1] == '1') {
                node1 = xmlNewChild(active, NULL, BAD_CAST "owner", NULL);
                xml_add_href(node1, NULL, data->lock_owner);
            }
            else {
                xmlNewTextChild(active, NULL, BAD_CAST "owner",
                                BAD_CAST data->lock_owner);
            }
        }

        snprintf(tbuf, sizeof(tbuf), "Second-%lu", data->lock_expire - now);
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
int xml_add_response(struct propfind_ctx *fctx, long code, unsigned precond)
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
                    BAD_CAST http_statusline(code));

        if (precond) {
            xmlNodePtr error = xmlNewChild(resp, NULL, BAD_CAST "error", NULL);

            xmlNewChild(error, NULL, BAD_CAST preconds[precond].name, NULL);
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

            annotatemore_findall(fctx->mailbox->name, 0, "*", allprop_cb, &arock);
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
                            BAD_CAST http_statusline(stat->status));
                if (stat->precond) {
                    struct error_t error = { NULL, stat->precond, NULL, NULL, 0 };
                    xml_add_error(stat->root, &error, fctx->ns);
                }

                xmlAddChild(resp, stat->root);
            }
        }
    }

    fctx->record = NULL;

    return 0;
}


/* Helper function to prescreen/fetch resource data */
int propfind_getdata(const xmlChar *name, xmlNsPtr ns,
                     struct propfind_ctx *fctx,
                     xmlNodePtr prop, struct propstat propstat[],
                     struct mime_type_t *mime_types, int precond,
                     const char *data, unsigned long datalen)
{
    int ret = 0;
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

    if (!propstat) {
        /* Prescreen "property" request */
        if (!mime->content_type) {
            fctx->txn->error.precond = precond;
            ret = *fctx->ret = HTTP_FORBIDDEN;
        }
    }
    else {
        /* Add "property" */
        char *freeme = NULL;

        prop = xml_add_prop(HTTP_OK, fctx->ns[NS_DAV],
                            &propstat[PROPSTAT_OK], name, ns, NULL, 0);

        if (mime != mime_types) {
            /* Not the storage format - convert into requested MIME type */
            struct buf inbuf, *outbuf;

            if (!fctx->obj) {
                buf_init_ro(&inbuf, data, datalen);
                fctx->obj = mime_types->to_object(&inbuf);
                buf_free(&inbuf);
            }

            outbuf = mime->from_object(fctx->obj);
            datalen = buf_len(outbuf);
            data = freeme = buf_release(outbuf);
            buf_destroy(outbuf);
        }

        if (type) {
            xmlSetProp(prop, BAD_CAST "content-type", type);
            if (ver) xmlSetProp(prop, BAD_CAST "version", ver);
        }

        xmlAddChild(prop,
                    xmlNewCDataBlock(fctx->root->doc, BAD_CAST data, datalen));

        fctx->flags.fetcheddata = 1;

        if (freeme) free(freeme);
    }

    if (type) xmlFree(type);
    if (ver) xmlFree(ver);

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


/* Callback to fetch DAV:displayname */
static int propfind_displayname(const xmlChar *name, xmlNsPtr ns,
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
        /* add DQUOTEs */
        buf_printf(&fctx->buf, "\"%s\"",
                   message_guid_encode(&fctx->record->guid));
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
    if (!fctx->mailbox ||
        (fctx->req_tgt->resource && !fctx->record)) return HTTP_NOT_FOUND;

    buf_ensure(&fctx->buf, 30);
    httpdate_gen(fctx->buf.s, fctx->buf.alloc,
                 fctx->record ? fctx->record->internaldate :
                 fctx->mailbox->index_mtime);

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


/* Callback to fetch *DAV:supported-collection-set */
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
 * with description 'desc_str' to node 'root'.  For now, we alssume all
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
                if (rights & DACL_PROPRES) {
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
                if (rights & DACL_ADDRES) {
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
                if ((rights & DACL_RMRES) == DACL_RMRES) {
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

        quota_read(&fctx->quota, NULL, 0);
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
        !strcmp(fctx->req_tgt->collection, SCHED_OUTBOX)) {
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


static void get_synctoken(struct mailbox *mailbox,
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

    get_synctoken(fctx->mailbox, &fctx->buf, prefix);

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
    if (!r) r = annotate_state_writemask(astate, buf_cstring(&pctx->buf), httpd_userid, &value);
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

    if (fctx->mbentry && !fctx->record &&
        !(r = annotatemore_lookupmask(fctx->mbentry->name,
                                      buf_cstring(&fctx->buf),
                                      httpd_userid, &attrib))) {
        if (!buf_len(&attrib) &&
            !xmlStrcmp(name, BAD_CAST "displayname")) {
            /* Special case empty displayname -- use last segment of path */
            buf_setcstr(&attrib, strrchr(fctx->mbentry->name, '.') + 1);
        }
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

    if (freeme) xmlFree(freeme);

    return 0;
}


/* annotemore_findall callback for adding dead properties (allprop/propname) */
static int allprop_cb(const char *mailbox __attribute__((unused)),
                      uint32_t uid __attribute__((unused)),
                      const char *entry,
                      const char *userid, const struct buf *attrib,
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
    if (!ns) {
        char prefix[5];
        snprintf(prefix, sizeof(prefix), "X%u", arock->fctx->prefix_count++);
        ns = xmlNewNs(arock->fctx->root, BAD_CAST href, BAD_CAST prefix);
        hash_insert(href, ns, arock->fctx->ns_table);
    }

    /* XXX - can return the same property multiple times with annotate masks! */

    /* Add the dead property to the response */
    node = xml_add_prop(HTTP_OK, arock->fctx->ns[NS_DAV],
                        &arock->propstat[PROPSTAT_OK],
                        BAD_CAST name, ns, NULL, 0);

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
        allowed = !entry->get(prop->name, NULL, fctx,
                              prop, NULL, NULL, entry->rock);
    }

    return allowed;
}


/* Parse the requested properties and create a linked list of fetch callbacks.
 * The list gets reused for each href if Depth > 0
 */
static int preload_proplist(xmlNodePtr proplist, struct propfind_ctx *fctx)
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
            xmlNsPtr ns = prop->ns;
            const char *ns_href = (const char *) ns->href;
            unsigned i;

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
                /* No match, treat as a dead property.  Need to look for both collections
                 * resources */
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
                              strcmp((const char *) prop->ns->href,
                                     known_namespaces[entry->ns].href));
                         entry++);

                    if (entry->name) {
                        if (!entry->put) {
                            /* Protected property */
                            xml_add_prop(HTTP_FORBIDDEN, pctx->ns[NS_DAV],
                                         &propstat[PROPSTAT_FORBID],
                                         prop->name, prop->ns, NULL,
                                         DAV_PROT_PROP);
                            *pctx->ret = HTTP_FORBIDDEN;
                        }
                        else {
                            /* Write "live" property */
                            entry->put(prop, set, pctx, propstat, entry->rock);
                        }
                    }
                    else {
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
                        BAD_CAST http_statusline(stat->status));
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
    xmlParserCtxtPtr ctxt;
    xmlDocPtr doc = NULL;
    int r = 0;

    *root = NULL;

    /* Read body */
    txn->req_body.flags |= BODY_DECODE;
    r = http_read_body(httpd_in, httpd_out,
                       txn->req_hdrs, &txn->req_body, &txn->error.desc);
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
        txn->error.desc = "This method requires an XML body\r\n";
        return HTTP_BAD_MEDIATYPE;
    }

    /* Parse the XML request */
    ctxt = xmlNewParserCtxt();
    if (ctxt) {
        doc = xmlCtxtReadMemory(ctxt, buf_cstring(&txn->req_body.payload),
                                buf_len(&txn->req_body.payload), NULL, NULL,
                                XML_PARSE_NOERROR | XML_PARSE_NOWARNING);
        xmlFreeParserCtxt(ctxt);
    }
    if (!doc) {
        txn->error.desc = "Unable to parse XML body\r\n";
        return HTTP_BAD_REQUEST;
    }

    /* Get the root element of the XML request */
    if (!(*root = xmlDocGetRootElement(doc))) {
        txn->error.desc = "Missing root element in request\r\n";
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
    if ((r = aparams->parse_path(txn->req_uri->path,
                                 &txn->req_tgt, &txn->error.desc))) return r;

    /* Make sure method is allowed (only allowed on collections) */
    if (!(txn->req_tgt.allow & ALLOW_ACL)) {
        txn->error.desc = "ACLs can only be set on collections\r\n";
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
        txn->error.desc = "Missing request body\r\n";
        ret = HTTP_BAD_REQUEST;
    }
    if (ret) goto done;

    indoc = root->doc;

    /* Make sure its an DAV:acl element */
    if (xmlStrcmp(root->name, BAD_CAST "acl")) {
        txn->error.desc = "Missing acl element in ACL request\r\n";
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
                            txn->error.desc = "Multiple principals in ACE\r\n";
                            ret = HTTP_BAD_REQUEST;
                            goto done;
                        }

                        for (prin = child->children; prin &&
                             prin->type != XML_ELEMENT_NODE; prin = prin->next);
                    }
                    else if (!xmlStrcmp(child->name, BAD_CAST "grant")) {
                        if (privs) {
                            txn->error.desc = "Multiple grant|deny in ACE\r\n";
                            ret = HTTP_BAD_REQUEST;
                            goto done;
                        }

                        for (privs = child->children; privs &&
                             privs->type != XML_ELEMENT_NODE; privs = privs->next);
                    }
                    else if (!xmlStrcmp(child->name, BAD_CAST "deny")) {
                        if (privs) {
                            txn->error.desc = "Multiple grant|deny in ACE\r\n";
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
                        txn->error.desc = "Unknown element in ACE\r\n";
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
                            rights |= DACL_PROPRES;
                        else if (!xmlStrcmp(priv->name,
                                       BAD_CAST "make-collection"))
                            rights |= DACL_MKCOL;
                        else if (!xmlStrcmp(priv->name,
                                       BAD_CAST "remove-collection"))
                            rights |= DACL_RMCOL;
                        else if (!xmlStrcmp(priv->name,
                                       BAD_CAST "add-resource"))
                            rights |= DACL_ADDRES;
                        else if (!xmlStrcmp(priv->name,
                                       BAD_CAST "remove-resource"))
                            rights |= DACL_RMRES;
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

    mailbox_set_acl(mailbox, buf_cstring(&acl), 1);
    r = mboxlist_sync_setacls(txn->req_tgt.mbentry->name, buf_cstring(&acl));
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
        r = mboxlist_renamemailbox(mbentry->name, buf_cstring(&mrock->newname),
                                   NULL /* partition */, 0 /* uidvalidity */,
                                   1 /* admin */, httpd_userid, httpd_authstate,
                                   NULL, 0, 0, 1 /* ignorequota */);
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
                    BAD_CAST http_statusline(code));

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
                                           NULL, 1 /* checkacl */,
                                           0 /* localonly */, 0 /* force */);
    }
    else {
        r = mboxlist_deletemailbox(mbentry->name, 1, /* admin */
                                   httpd_userid, httpd_authstate,
                                   NULL, 1 /* checkacl */,
                                   0 /* localonly */, 0 /* force */);
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
                                               mboxevent, 1 /* checkacl */,
                                               0 /* localonly*/, 0 /* force */);
        }
        else {
            r = mboxlist_deletemailbox(newmailboxname,
                                       httpd_userisadmin,
                                       httpd_userid, httpd_authstate,
                                       mboxevent, 1 /* checkacl */,
                                       0 /* localonly*/, 0 /* force */);
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

    r = mboxlist_renamemailbox(oldmailboxname, newmailboxname,
                               NULL /* partition */, 0 /* uidvalidity */,
                               httpd_userisadmin, httpd_userid, httpd_authstate,
                               mboxevent, 0, 0, 1 /* ignorequota */);

    if (!r) mboxevent_notify(&mboxevent);
    mboxevent_free(&mboxevent);

    /* Attempt to rename all submailboxes */
    if (!r && recursive) {
        char ombn[MAX_MAILBOX_BUFFER];
        struct move_rock mrock =
            { ++omlen, ++nmlen, BUF_INITIALIZER, dest_tgt->namespace->prefix, NULL, {0} };

        strcpy(ombn, oldmailboxname);
        strcat(ombn, ".");

        /* Setup the rock */
        buf_setcstr(&mrock.newname, newmailboxname);
        buf_putc(&mrock.newname, '.');

        r = mboxlist_allmbox(ombn, move_collection, &mrock, 0);
        buf_free(&mrock.newname);

        if (mrock.root) {
            xml_response(HTTP_MULTI_STATUS, txn, mrock.root->doc);
            xmlFreeDoc(mrock.root->doc);
            return 0;
        }
    }

  done:
    switch (r) {
    case 0:
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
    struct buf msg_buf = BUF_INITIALIZER, body_buf;

    memset(&dest_tgt, 0, sizeof(struct request_target_t));

    /* Response should not be cached */
    txn->flags.cc |= CC_NOCACHE;

    /* Parse the source path */
    if ((r = cparams->parse_path(txn->req_uri->path,
                                 &txn->req_tgt, &txn->error.desc))) return r;

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
        ret = r;
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
        (meth_move && !(rights & DACL_RMRES))) {
        /* DAV:need-privileges */
        txn->error.precond = DAV_NEED_PRIVS;
        txn->error.resource = txn->req_tgt.path;
        txn->error.rights =
            (rights & DACL_READ) != DACL_READ ? DACL_READ : DACL_RMRES;
        ret = HTTP_NO_PRIVS;
        goto done;
    }

    /* Check ACL for current user on destination */
    rights = httpd_myrights(httpd_authstate, dest_tgt.mbentry);
    if (!(rights & DACL_ADDRES) || !(rights & DACL_WRITECONT)) {
        /* DAV:need-privileges */
        txn->error.precond = DAV_NEED_PRIVS;
        txn->error.resource = dest_tgt.path;
        txn->error.rights =
            !(rights & DACL_ADDRES) ? DACL_ADDRES : DACL_WRITECONT;
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

    if (ddata->imap_uid) {
        /* Mapped URL - Fetch index record for the resource */
        r = mailbox_find_index_record(src_mbox, ddata->imap_uid, &src_rec);
        if (r) {
            txn->error.desc = error_message(r);
            ret = HTTP_SERVER_ERROR;
            goto done;
        }

        etag = message_guid_encode(&src_rec.guid);
        lastmod = src_rec.internaldate;
    }
    else {
        /* Unmapped URL (empty resource) */
        src_rec.uid = 0;
        src_rec.recno = ddata->rowid;
        etag = NULL;
        lastmod = ddata->creationdate;
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
                src_rec.system_flags |= FLAG_EXPUNGED;
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

/* Perform a DELETE request */
int meth_delete(struct transaction_t *txn, void *params)
{
    struct meth_params *dparams = (struct meth_params *) params;
    int ret = HTTP_NO_CONTENT, r = 0, precond, rights, needrights;
    struct mboxevent *mboxevent = NULL;
    struct mailbox *mailbox = NULL;
    struct dav_data *ddata;
    struct index_record record;
    const char *etag = NULL;
    time_t lastmod = 0;
    void *davdb = NULL;

    /* Response should not be cached */
    txn->flags.cc |= CC_NOCACHE;

    /* Parse the path */
    r = dparams->parse_path(txn->req_uri->path,
                            &txn->req_tgt, &txn->error.desc);
    if (r) return r;

    /* Make sure method is allowed */
    if (!(txn->req_tgt.allow & ALLOW_DELETE)) return HTTP_NOT_ALLOWED;

    /* if FastMail sharing, we need to remove ACLs */
    if (config_getswitch(IMAPOPT_FASTMAILSHARING) &&!txn->req_tgt.resource &&
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
        return HTTP_OK;
    }

    /* Special case of deleting a shared collection */
    if (!txn->req_tgt.resource && (txn->req_tgt.flags == TGT_DAV_SHARED)) {
        char *inboxname = mboxname_user_mbox(txn->req_tgt.userid, NULL);
        mbentry_t *mbentry = NULL;

        r = http_mlookup(inboxname, &mbentry, NULL);
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

        return ret;
    }

    /* Check ACL for current user */
    rights = httpd_myrights(httpd_authstate, txn->req_tgt.mbentry);
    needrights = txn->req_tgt.resource ? DACL_RMRES : DACL_RMCOL;
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

    if (!txn->req_tgt.resource) {
        /* DELETE collection */

        if (dparams->delete) {
            /* Do special processing on all resources */
            struct delete_rock drock = { txn, NULL, dparams->delete };

            /* Open mailbox for reading */
            r = mailbox_open_irl(txn->req_tgt.mbentry->name, &mailbox);
            if (r) {
                syslog(LOG_ERR, "http_mailbox_open(%s) failed: %s",
                       txn->req_tgt.mbentry->name, error_message(r));
                txn->error.desc = error_message(r);
                return HTTP_SERVER_ERROR;
            }

            /* Open the DAV DB corresponding to the mailbox */
            davdb = dparams->davdb.open_db(mailbox);

            drock.mailbox = mailbox;
            r = dparams->davdb.foreach_resource(davdb, mailbox->name,
                                                  &delete_cb, &drock);
            /* we need the mailbox closed before we delete it */
            mailbox_close(&mailbox);
            if (r) {
                txn->error.desc = error_message(r);
                return HTTP_SERVER_ERROR;
            }
        }

        mboxevent = mboxevent_new(EVENT_MAILBOX_DELETE);

        if (mboxlist_delayed_delete_isenabled()) {
            r = mboxlist_delayed_deletemailbox(txn->req_tgt.mbentry->name,
                                       httpd_userisadmin || httpd_userisproxyadmin,
                                       httpd_userid, httpd_authstate, mboxevent,
                                       /*checkack*/1, /*localonly*/0, /*force*/0);
        }
        else {
            r = mboxlist_deletemailbox(txn->req_tgt.mbentry->name,
                                       httpd_userisadmin || httpd_userisproxyadmin,
                                       httpd_userid, httpd_authstate, mboxevent,
                                       /*checkack*/1, /*localonly*/0, /*force*/0);
        }
        if (r == IMAP_PERMISSION_DENIED) ret = HTTP_FORBIDDEN;
        else if (r == IMAP_MAILBOX_NONEXISTENT) ret = HTTP_NOT_FOUND;
        else if (r) ret = HTTP_SERVER_ERROR;

        goto done;
    }

    /* DELETE resource */

    /* Open mailbox for writing */
    r = mailbox_open_iwl(txn->req_tgt.mbentry->name, &mailbox);
    if (r) {
        syslog(LOG_ERR, "http_mailbox_open(%s) failed: %s",
               txn->req_tgt.mbentry->name, error_message(r));
        txn->error.desc = error_message(r);
        ret = HTTP_SERVER_ERROR;
        goto done;
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

    memset(&record, 0, sizeof(struct index_record));
    if (ddata->imap_uid) {
        /* Mapped URL - Fetch index record for the resource */
        r = mailbox_find_index_record(mailbox, ddata->imap_uid, &record);
        if (r) {
            txn->error.desc = error_message(r);
            ret = HTTP_SERVER_ERROR;
            goto done;
        }

        etag = message_guid_encode(&record.guid);
        lastmod = record.internaldate;
    }
    else {
        /* Unmapped URL (empty resource) */
        etag = NULL;
        lastmod = ddata->creationdate;
    }

    /* Check any preconditions */
    precond = dparams->check_precond(txn, params, mailbox,
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
        record.system_flags |= FLAG_EXPUNGED;

        mboxevent = mboxevent_new(EVENT_MESSAGE_EXPUNGE);

        r = mailbox_rewrite_index_record(mailbox, &record);

        if (r) {
            syslog(LOG_ERR, "expunging record (%s) failed: %s",
                   txn->req_tgt.mbentry->name, error_message(r));
            txn->error.desc = error_message(r);
            ret = HTTP_SERVER_ERROR;
            goto done;
        }

        mboxevent_extract_record(mboxevent, mailbox, &record);
        mboxevent_extract_mailbox(mboxevent, mailbox);
        mboxevent_set_numunseen(mboxevent, mailbox, -1);
        mboxevent_set_access(mboxevent, NULL, NULL, httpd_userid,
                             txn->req_tgt.mbentry->name, 0);
    }

  done:
    if (davdb) dparams->davdb.close_db(davdb);
    mailbox_close(&mailbox);

    if (!r)
        mboxevent_notify(&mboxevent);
    mboxevent_free(&mboxevent);

    return ret;
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
    ret = gparams->parse_path(txn->req_uri->path,
                              &txn->req_tgt, &txn->error.desc);
    if (ret) return ret;

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

    memset(&record, 0, sizeof(struct index_record));
    if (ddata->imap_uid) {
        /* Mapped URL - Fetch index record for the resource */
        r = mailbox_find_index_record(mailbox, ddata->imap_uid, &record);
        if (r) goto done;

        txn->flags.ranges = 1;
        etag = message_guid_encode(&record.guid);
        lastmod = record.internaldate;
    }
    else {
        /* Unmapped URL (empty resource) */
        txn->flags.ranges = 0;
        etag = NULL;
        lastmod = ddata->creationdate;
    }

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
                struct buf inbuf;

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
    xmlChar *owner = NULL;
    time_t now = time(NULL);
    void *davdb = NULL;

    /* XXX  We ignore Depth and Timeout header fields */

    /* Response should not be cached */
    txn->flags.cc |= CC_NOCACHE;

    /* Parse the path */
    if ((r = lparams->parse_path(txn->req_uri->path,
                                 &txn->req_tgt, &txn->error.desc))) return r;

    /* Make sure method is allowed (only allowed on resources) */
    if (!(txn->req_tgt.allow & ALLOW_WRITE)) return HTTP_NOT_ALLOWED;

    /* Check ACL for current user */
    rights = httpd_myrights(httpd_authstate, txn->req_tgt.mbentry);
    if (!(rights & DACL_WRITECONT) || !(rights & DACL_ADDRES)) {
        /* DAV:need-privileges */
        txn->error.precond = DAV_NEED_PRIVS;
        txn->error.resource = txn->req_tgt.path;
        txn->error.rights =
            !(rights & DACL_WRITECONT) ? DACL_WRITECONT : DACL_ADDRES;
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

    if (ddata->alive) {
        if (ddata->imap_uid) {
            /* Locking existing resource */

            /* Fetch index record for the resource */
            r = mailbox_find_index_record(mailbox, ddata->imap_uid, &oldrecord);
            if (r) {
                txn->error.desc = error_message(r);
                ret = HTTP_SERVER_ERROR;
                goto done;
            }

            etag = message_guid_encode(&oldrecord.guid);
            lastmod = oldrecord.internaldate;
        }
        else {
            /* Unmapped URL (empty resource) */
            etag = NULL;
            lastmod = ddata->creationdate;
        }
    }
    else {
        /* New resource */
        etag = NULL;
        lastmod = 0;

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
        unsigned owner_is_href = 0;

        /* Parse the required body */
        ret = parse_xml_body(txn, &root, NULL);
        if (!ret && !root) {
            txn->error.desc = "Missing request body";
            ret = HTTP_BAD_REQUEST;
        }
        if (ret) goto done;

        /* Check for correct root element */
        indoc = root->doc;
        if (xmlStrcmp(root->name, BAD_CAST "lockinfo")) {
            txn->error.desc = "Incorrect root element in XML request\r\n";
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
                for (sub = node->children;
                     sub && sub->type != XML_ELEMENT_NODE; sub = sub->next);
                if (!sub) {
                    owner = xmlNodeGetContent(node);
                }
                /* Make sure its a href element */
                else if (xmlStrcmp(sub->name, BAD_CAST "href")) {
                    ret = HTTP_BAD_REQUEST;
                    goto done;
                }
                else {
                    owner_is_href = 1;
                    owner = xmlNodeGetContent(sub);
                }
            }
        }

        ddata->lock_ownerid = httpd_userid;
        if (owner) ddata->lock_owner = (const char *) owner;

        /* Construct lock-token */
        assert(!buf_len(&txn->buf));
        buf_printf(&txn->buf, XML_NS_CYRUS "lock/%s-%x-%u",
                   mailbox->uniqueid, strhash(txn->req_tgt.resource),
                   owner_is_href);

        ddata->lock_token = buf_cstring(&txn->buf);
    }

    /* Update lock expiration */
    ddata->lock_expire = now + 300;  /* 5 min */

    /* Start construction of our prop response */
    if (!(root = init_xml_response("prop", NS_DAV, root, ns))) {
        ret = HTTP_SERVER_ERROR;
        txn->error.desc = "Unable to create XML response\r\n";
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
    if (owner) xmlFree(owner);

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
    if ((r = mparams->parse_path(txn->req_uri->path,
                                 &txn->req_tgt, &txn->error.desc))) {
        txn->error.precond = mparams->mkcol.location_precond;
        return HTTP_FORBIDDEN;
    }

    /* Make sure method is allowed (only allowed on home-set) */
    if (!(txn->req_tgt.allow & ALLOW_MKCOL)) {
        txn->error.precond = mparams->mkcol.location_precond;
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
        indoc = root->doc;

        buf_setcstr(&txn->buf, http_methods[txn->meth].name);
        r = xmlStrcmp(root->name, BAD_CAST buf_lcase(&txn->buf));
        if (r) {
            txn->error.desc = "Incorrect root element in XML request\r\n";
            ret = HTTP_BAD_MEDIATYPE;
            goto done;
        }

        instr = root->children;
    }

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
            txn->error.desc = "Unable to create XML response\r\n";
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
            mailbox_close(&mailbox);
            mboxlist_deletemailbox(txn->req_tgt.mbentry->name,
                                   /*isadmin*/1, NULL, NULL, NULL,
                                   /*checkacl*/0, /*localonly*/0, /*force*/1);

            if (!ret) {
                /* Output the XML response */
                xml_response(r, txn, outdoc);
            }

            goto done;
        }
    }

    if (!r) {
        assert(!buf_len(&txn->buf));
        get_synctoken(mailbox, &txn->buf, "");
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
        ret = xml_add_response(fctx, HTTP_NOT_FOUND, 0);
    }
    else if (!fctx->filter || fctx->filter(fctx, data)) {
        /* Add response for target */
        ret = xml_add_response(fctx, 0, 0);
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
            xml_add_response(fctx, HTTP_NOT_FOUND, 0);
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


static size_t make_collection_url(struct buf *buf, const char  *urlprefix,
                                  const char *mboxname, const char *userid,
                                  char **mbox_owner)
{
    mbname_t *mbname = NULL;
    const strarray_t *boxes;
    int n, size;
    size_t len;

    mbname = mbname_from_intname(mboxname);

    buf_reset(buf);
    buf_printf(buf, "%s/", urlprefix);

    if (userid) {
        if (!mbname_domain(mbname)) mbname_set_domain(mbname, httpd_extradomain);
        const char *owner = mbname_userid(mbname);
        if (!owner) owner = "";

        if (mbox_owner) *mbox_owner = xstrdup(owner);

        if (config_getswitch(IMAPOPT_FASTMAILSHARING)) {
            if (strcmp(owner, userid) && strstr(urlprefix, "addressbooks"))
                buf_printf(buf, "%s/%s/", "zzzz", owner);
            else
                buf_printf(buf, "%s/%s/", USER_COLLECTION_PREFIX, owner);
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

    mbname_free(&mbname);

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
    if (mboxname_isdeletedmailbox(mbentry->name, 0) || mbentry->mbtype == MBTYPE_DELETED)
        goto done;

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

    case URL_NS_CALENDAR:
        /*  Inbox and Outbox can't appear unless they are the target */
        if (!fctx->req_tgt->flags) {
            if (!strncmp(p, SCHED_INBOX, strlen(SCHED_INBOX) - 1)) goto done;
            if (!strncmp(p, SCHED_OUTBOX, strlen(SCHED_OUTBOX) - 1)) goto done;
        }
        /* fall through */

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
        fctx->txn->error.desc = error_message(r);
        *fctx->ret = HTTP_SERVER_ERROR;
        goto done;
    }

    fctx->mbentry = mbentry;
    fctx->mailbox = mailbox;
    fctx->record = NULL;

    if (!fctx->req_tgt->resource) {
        len = make_collection_url(&writebuf, fctx->req_tgt->namespace->prefix,
                                  mboxname, fctx->req_tgt->userid, NULL);

        /* copy it all back into place... in theory we should check against
         * 'last' and make sure it doesn't change from the original request.
         * yay for micro-optimised memory usage... */
        strlcpy(fctx->req_tgt->path, buf_cstring(&writebuf), MAX_MAILBOX_PATH);
        p = fctx->req_tgt->path + len;
        fctx->req_tgt->collection = p;
        fctx->req_tgt->collen = strlen(p);

        /* If not filtering by calendar resource, and not excluding root,
           add response for collection */
        if (!fctx->filter_crit && !(fctx->prefer & PREFER_NOROOT) &&
            (r = xml_add_response(fctx, 0, 0))) goto done;
    }

    if (fctx->depth > 1 && fctx->open_db) { // can't do davdb searches if no dav db
        /* Resource(s) */
        r = propfind_by_resources(fctx);
    }

  done:
    buf_free(&writebuf);
    if (mailbox) mailbox_close(&mailbox);

    return r;
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
    struct hash_table ns_table = HASH_TABLE_INITIALIZER;
    struct propfind_ctx fctx;
    struct propfind_entry_list *elist = NULL;

    memset(&fctx, 0, sizeof(struct propfind_ctx));

    /* Parse the path */
    if (fparams->parse_path) {
        r = fparams->parse_path(txn->req_uri->path,
                                &txn->req_tgt, &txn->error.desc);
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
        txn->error.desc = "Illegal Depth value\r\n";
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

        /* Make sure its a propfind element */
        if (xmlStrcmp(root->name, BAD_CAST "propfind")) {
            txn->error.desc = "Missing propfind element in PROPFIND request";
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
    fctx.prefer |= get_preferences(txn);
    fctx.userid = httpd_userid;
    fctx.userisadmin = httpd_userisadmin;
    fctx.authstate = httpd_authstate;
    fctx.mbentry = NULL;
    fctx.mailbox = NULL;
    fctx.record = NULL;
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
    preload_proplist(props, &fctx);

    /* Generate responses */
    if (txn->req_tgt.namespace->id == URL_NS_PRINCIPAL) {
        if (!depth || !(fctx.prefer & PREFER_NOROOT)) {
            /* Add response for target URL */
            xml_add_response(&fctx, 0, 0);
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
                xml_add_response(&fctx, 0, 0);
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

            if (!fctx.req_tgt->resource) xml_add_response(&fctx, 0, 0);

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
                mboxlist_usermboxtree(httpd_userid, propfind_by_collection, &fctx, MBOXTREE_PLUS_RACL);
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
                        r = xml_add_response(&fctx, 0, 0);
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

    /* Output the XML response */
    if (!ret) {
        /* iCalendar data in response should not be transformed */
        if (fctx.flags.fetcheddata) txn->flags.cc |= CC_NOTRANSFORM;

        xml_response(HTTP_MULTI_STATUS, txn, outdoc);
    }

  done:
    /* Free the entry list */
    elist = fctx.elist;
    while (elist) {
        struct propfind_entry_list *freeme = elist;
        elist = elist->next;
        xmlFree(freeme->name);
        free(freeme);
    }

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
    int ret = 0, r = 0, rights;
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
    if ((r = pparams->parse_path(txn->req_uri->path,
                                 &txn->req_tgt, &txn->error.desc))) return r;

    if (!txn->req_tgt.collection && !txn->req_tgt.userid) {
        txn->error.desc = "PROPPATCH requires a collection";
        return HTTP_NOT_ALLOWED;
    }

    /* Check ACL for current user */
    rights = httpd_myrights(httpd_authstate, txn->req_tgt.mbentry);
    if (!(rights & DACL_PROPCOL)) {
        /* DAV:need-privileges */
        txn->error.precond = DAV_NEED_PRIVS;
        txn->error.resource = txn->req_tgt.path;
        txn->error.rights = DACL_PROPCOL;
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

    r = mailbox_open_iwl(txn->req_tgt.mbentry->name, &mailbox);
    if (r) {
        syslog(LOG_ERR, "IOERROR: failed to open mailbox %s for proppatch",
               txn->req_tgt.mbentry->name);
        return HTTP_SERVER_ERROR;
    }

    /* Parse the PROPPATCH body */
    ret = parse_xml_body(txn, &root, NULL);
    if (!ret && !root) {
        txn->error.desc = "Missing request body\r\n";
        ret = HTTP_BAD_REQUEST;
    }
    if (ret) goto done;

    indoc = root->doc;

    /* Make sure its a propertyupdate element */
    if (xmlStrcmp(root->name, BAD_CAST "propertyupdate")) {
        txn->error.desc =
            "Missing propertyupdate element in PROPPATCH request\r\n";
        ret = HTTP_BAD_REQUEST;
        goto done;
    }
    instr = root->children;

    /* Start construction of our multistatus response */
    if (!(root = init_xml_response("multistatus", NS_DAV, root, ns))) {
        txn->error.desc = "Unable to create XML response\r\n";
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

    /* Output the XML response */
    if (!ret) {
        if (!r && (get_preferences(txn) & PREFER_MIN)) ret = HTTP_OK;
        else xml_response(HTTP_MULTI_STATUS, txn, outdoc);
    }

  done:
    if (davdb) pparams->davdb.close_db(davdb);
    mailbox_close(&mailbox);
    buf_free(&pctx.buf);

    if (outdoc) xmlFreeDoc(outdoc);
    if (indoc) xmlFreeDoc(indoc);

    return ret;
}


enum {
    SHARE_NONE = 0,
    SHARE_READONLY,
    SHARE_READWRITE
};

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


static int create_notify_collection(const char *userid,
                                    struct mailbox **mailbox);
static int notify_put(struct transaction_t *txn, void *obj,
                      struct mailbox *mailbox, const char *resource,
                      void *davdb, unsigned flags);

#define DAVSHARING_CONTENT_TYPE "application/davsharing+xml"

#define DAVNOTIFICATION_CONTENT_TYPE \
    "application/davnotification+xml; charset=utf-8"

#define SYSTEM_STATUS_NOTIFICATION  "systemstatus"
#define SHARE_INVITE_NOTIFICATION   "share-invite-notification"
#define SHARE_REPLY_NOTIFICATION    "share-reply-notification"

static int send_notification(struct transaction_t *top_txn, xmlDocPtr doc,
                             const char *userid, const char *resource)
{
    struct mailbox *mailbox = NULL;
    struct webdav_db *webdavdb = NULL;
    struct transaction_t txn;
    int r;

    /* XXX  Need to find location of user.
       If remote need to do a PUT or possibly email */

    /* Open notifications collection for writing */
    r = create_notify_collection(userid, &mailbox);
    if (r == IMAP_INVALID_USER) {
        syslog(LOG_NOTICE,
               "send_notification(%s) failed: %s", userid, error_message(r));
        return 0;
    }
    else if (r) {
        syslog(LOG_ERR,
               "send_notification: create_notify_collection(%s) failed: %s",
               userid, error_message(r));
        return r;
    }

    /* Open the WebDAV DB corresponding to collection */
    webdavdb = webdav_open_mailbox(mailbox);
    if (!webdavdb) {
        syslog(LOG_ERR, "send_notification: unable to open WebDAV DB (%s)",
               mailbox->name);
        r = HTTP_SERVER_ERROR;
        goto done;
    }

    /* Start with an empty (clean) transaction */
    memset(&txn, 0, sizeof(struct transaction_t));
    txn.req_tgt.namespace = top_txn->req_tgt.namespace;
    txn.req_tgt.mboxprefix = top_txn->req_tgt.mboxprefix;

    /* Create header cache */
    if (!(txn.req_hdrs = spool_new_hdrcache())) {
        syslog(LOG_ERR, "send_notification: unable to create header cache");
        r = HTTP_SERVER_ERROR;
        goto done;
    }

    spool_cache_header(xstrdup("Content-Type"),
                       xstrdup(DAVNOTIFICATION_CONTENT_TYPE), txn.req_hdrs);

    r = notify_put(&txn, doc, mailbox, resource, webdavdb, 0);
    if (r != HTTP_CREATED && r != HTTP_NO_CONTENT) {
        syslog(LOG_ERR,
               "send_notification: notify_put(%s, %s) failed: %s",
               mailbox->name, resource, error_message(r));
    }

  done:
    spool_free_hdrcache(txn.req_hdrs);
    buf_free(&txn.buf);
    webdav_close(webdavdb);
    mailbox_close(&mailbox);

    return r;
}


static int dav_post_share(struct transaction_t *txn,
                          struct meth_params *pparams)
{
    xmlNodePtr root = NULL, node, sharee, princ;
    int rights, ret, legacy = 0;
    struct buf resource = BUF_INITIALIZER;
    char dtstamp[RFC3339_DATETIME_MAX];
    xmlNodePtr notify = NULL, type, resp, share, comment;
    xmlNsPtr ns[NUM_NAMESPACE];
    const char *invite_principal_props[] = { "displayname", NULL };
    const char *invite_collection_props[] = { "displayname", "resourcetype",
                                              "supported-calendar-component-set",
                                              NULL };

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

    /* Local mailbox */

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

    /* Create share-invite-notification -
       response and share-access will be replaced for each sharee */
    notify = init_xml_response("notification", NS_DAV, NULL, ns);

    time_to_rfc3339(time(0), dtstamp, RFC3339_DATETIME_MAX);
    xmlNewChild(notify, NULL, BAD_CAST "dtstamp", BAD_CAST dtstamp);

    type = xmlNewChild(notify, NULL, BAD_CAST SHARE_INVITE_NOTIFICATION, NULL);

    princ = xmlNewChild(type, NULL, BAD_CAST "principal", NULL);
    buf_printf(&resource, "%s/%s/%s/", namespace_principal.prefix,
               USER_COLLECTION_PREFIX, txn->req_tgt.userid);
    xml_add_href(princ, NULL, buf_cstring(&resource));
    node = get_props(&txn->req_tgt, invite_principal_props,
                     notify, ns, princ_params.propfind.lprops);
    xmlAddChild(princ, node);

    resp = xmlNewChild(type, NULL, BAD_CAST "invite-noresponse", NULL);

    node = xmlNewChild(type, NULL, BAD_CAST "sharer-resource-uri", NULL);
    xml_add_href(node, NULL, txn->req_tgt.path);

    node = xmlNewChild(type, NULL, BAD_CAST "share-access", NULL);
    share = xmlNewChild(node, NULL, BAD_CAST "no-access", NULL);

    node = get_props(&txn->req_tgt, invite_collection_props,
                     notify, ns, pparams->propfind.lprops);
    xmlAddChild(type, node);

    comment = xmlNewChild(type, NULL, BAD_CAST "comment", NULL);


    /* Process each sharee */
    for (sharee = xmlFirstElementChild(root); sharee;
         sharee = xmlNextElementSibling(sharee)) {
        xmlChar *href = NULL, *content;
        int access = SHARE_READONLY;

        xmlNodeSetContent(comment, BAD_CAST "");

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
                    xmlNodeSetContent(comment, content);
                    xmlFree(content);
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
                xmlNodeSetContent(comment, content);
                xmlFree(content);
            }
        }

        if (href) {
            char *userid = NULL, *at;
            int r;

            if (!xmlStrncmp(href, BAD_CAST "mailto:", 7)) {
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
                    r = principal_parse_path((const char *) uri->path,
                                             &principal, &errstr);
                    if (!r && principal.userid) userid = principal.userid;
                    else if (principal.userid) free(principal.userid);

                    xmlFreeURI(uri);
                }
            }

            if (!userid) {
                /* XXX  set invite-invalid ? */
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
                    /* Notify sharee - patch in response and share-access */
                    const char *annot =
                        DAV_ANNOT_NS "<" XML_NS_DAV ">invite-status";
                    const char *response = "invite-noresponse";
                    struct buf value = BUF_INITIALIZER;
                    int r;

                    /* Lookup invite status */
                    r = annotatemore_lookupmask(txn->req_tgt.mbentry->name,
                                                annot, userid, &value);
                    if (!r && buf_len(&value)) response = buf_cstring(&value);
                    node = xmlNewNode(ns[NS_DAV], BAD_CAST response);
                    buf_free(&value);
                    xmlReplaceNode(resp, node);
                    xmlFreeNode(resp);
                    resp = node;

                    node = xmlNewNode(ns[NS_DAV], BAD_CAST access_types[access]);
                    xmlReplaceNode(share, node);
                    xmlFreeNode(share);
                    share = node;

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

                    r = send_notification(txn, notify->doc,
                                          userid, buf_cstring(&resource));
                }

                free(userid);
            }

            xmlFree(href);
        }

        ret = HTTP_NO_CONTENT;
    }

  done:
    if (root) xmlFreeDoc(root->doc);
    if (notify) xmlFreeDoc(notify->doc);
    buf_free(&resource);

    return ret;
}


static int dav_post_import(struct transaction_t *txn,
                          struct meth_params *pparams)
{
    int ret = 0, r, precond = HTTP_OK, rights;
    const char **hdr;
    struct mime_type_t *mime = NULL;
    struct mailbox *mailbox = NULL;
    quota_t qdiffs[QUOTA_NUMRESOURCES] = QUOTA_DIFFS_INITIALIZER;
    void *davdb = NULL, *obj = NULL;
    xmlDocPtr outdoc = NULL;
    xmlNodePtr root;
    xmlNsPtr ns[NUM_NAMESPACE];

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
    if (!(rights & DACL_WRITECONT) || !(rights & DACL_ADDRES)) {
        /* DAV:need-privileges */
        txn->error.precond = DAV_NEED_PRIVS;
        txn->error.resource = txn->req_tgt.path;
        txn->error.rights =
            !(rights & DACL_WRITECONT) ? DACL_WRITECONT : DACL_ADDRES;
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
    r = http_read_body(httpd_in, httpd_out,
                       txn->req_hdrs, &txn->req_body, &txn->error.desc);
    if (r) {
        txn->flags.conn = CONN_CLOSE;
        return r;
    }

    /* Check if we can append a new message to mailbox */
    qdiffs[QUOTA_STORAGE] = buf_len(&txn->req_body.payload);
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
    ret = pparams->post.import(txn, obj, NULL, NULL, NULL, NULL, 0);
    if (ret) goto done;

    /* Start construction of our multistatus response */
    root = init_xml_response("multistatus", NS_DAV, NULL, ns);
    if (!root) {
        ret = HTTP_SERVER_ERROR;
        txn->error.desc = "Unable to create XML response";
        goto done;
    }
    ensure_ns(ns, NS_CS, root, XML_NS_CS, "CS");

    outdoc = root->doc;

    /* Store the resources */
    ret = pparams->post.import(txn, obj, mailbox, davdb,
                               root, ns, get_preferences(txn));

    /* Validators */
    assert(!buf_len(&txn->buf));
    get_synctoken(mailbox, &txn->buf, "");
    txn->resp_body.ctag = buf_cstring(&txn->buf);
    txn->resp_body.etag = NULL;
    txn->resp_body.lastmod = 0;

    /* Output the XML response */
    if (!ret) xml_response(HTTP_MULTI_STATUS, txn, outdoc);

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
    static unsigned post_count = 0;
    struct strlist *action;
    int r, ret;
    size_t len;

    /* Response should not be cached */
    txn->flags.cc |= CC_NOCACHE;
    if (httpd_userid) txn->flags.cc |= CC_PRIVATE;

    /* Parse the path */
    if ((r = pparams->parse_path(txn->req_uri->path,
                                 &txn->req_tgt, &txn->error.desc))) return r;

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
            is_mediatype(hdr[0], DAVSHARING_CONTENT_TYPE)) {
            /* Sharing request */
            return dav_post_share(txn, pparams);
        }
        else if ((pparams->post.allowed & POST_BULK) && hdr) {
            if (is_mediatype(hdr[0], "application/xml")) {
                /* Bulk CRUD */
                return HTTP_FORBIDDEN;
            }
            else {
                /* Bulk import */
                return dav_post_import(txn, pparams);
            }
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
                 "%x-%d-%ld-%u.ics",
                 strhash(txn->req_tgt.path), getpid(), time(0), post_count++);

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
    if ((r = pparams->parse_path(txn->req_uri->path,
                                 &txn->req_tgt, &txn->error.desc))) {
        return HTTP_FORBIDDEN;
    }

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
    ret = http_read_body(httpd_in, httpd_out,
                         txn->req_hdrs, &txn->req_body, &txn->error.desc);
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

    /* Fetch index record for the resource */
    r = mailbox_find_index_record(mailbox, ddata->imap_uid, &oldrecord);
    if (r) {
        syslog(LOG_ERR, "mailbox_find_index_record(%s, %u) failed: %s",
               txn->req_tgt.mbentry->name, ddata->imap_uid, error_message(r));
        txn->error.desc = error_message(r);
        ret = HTTP_SERVER_ERROR;
        goto done;
    }

    etag = message_guid_encode(&oldrecord.guid);
    lastmod = oldrecord.internaldate;

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
        struct buf buf;

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
    int ret, r, precond, rights;
    const char **hdr, *etag;
    struct mime_type_t *mime = NULL;
    struct mailbox *mailbox = NULL;
    struct dav_data *ddata;
    struct index_record oldrecord;
    quota_t qdiffs[QUOTA_NUMRESOURCES] = QUOTA_DIFFS_INITIALIZER;
    time_t lastmod;
    unsigned flags = 0;
    void *davdb = NULL, *obj = NULL;
    struct buf msg_buf = BUF_INITIALIZER;

    if (txn->meth == METH_PUT) {
        /* Response should not be cached */
        txn->flags.cc |= CC_NOCACHE;

        /* Parse the path */
        if ((r = pparams->parse_path(txn->req_uri->path,
                                     &txn->req_tgt, &txn->error.desc))) {
            return HTTP_FORBIDDEN;
        }

        /* Make sure method is allowed (only allowed on resources) */
        if (!(txn->req_tgt.allow & ALLOW_WRITE)) return HTTP_NOT_ALLOWED;
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
    if (!(rights & DACL_WRITECONT) || !(rights & DACL_ADDRES)) {
        /* DAV:need-privileges */
        txn->error.precond = DAV_NEED_PRIVS;
        txn->error.resource = txn->req_tgt.path;
        txn->error.rights =
            !(rights & DACL_WRITECONT) ? DACL_WRITECONT : DACL_ADDRES;
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
    ret = http_read_body(httpd_in, httpd_out,
                         txn->req_hdrs, &txn->req_body, &txn->error.desc);
    if (ret) {
        txn->flags.conn = CONN_CLOSE;
        return ret;
    }

    /* Check if we can append a new message to mailbox */
    qdiffs[QUOTA_STORAGE] = buf_len(&txn->req_body.payload);
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

    /* Find message UID for the resource, if exists */
    pparams->davdb.lookup_resource(davdb, txn->req_tgt.mbentry->name,
                                   txn->req_tgt.resource, (void *) &ddata, 0);
    /* XXX  Check errors */

    if (ddata->imap_uid) {
        /* Overwriting existing resource */

        /* Fetch index record for the resource */
        r = mailbox_find_index_record(mailbox, ddata->imap_uid, &oldrecord);
        if (r) {
            syslog(LOG_ERR, "mailbox_find_index_record(%s, %u) failed: %s",
                   txn->req_tgt.mbentry->name, ddata->imap_uid, error_message(r));
            txn->error.desc = error_message(r);
            ret = HTTP_SERVER_ERROR;
            goto done;
        }

        etag = message_guid_encode(&oldrecord.guid);
        lastmod = oldrecord.internaldate;
    }
    else if (ddata->rowid) {
        /* Unmapped URL (empty resource) */
        etag = NULL;
        lastmod = ddata->creationdate;
    }
    else {
        /* New resource */
        etag = NULL;
        lastmod = 0;
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
        if (flags & PREFER_REP) {
            unsigned offset;
            struct buf buf;

            /* Load message containing the resource */
            mailbox_map_record(mailbox, &oldrecord, &msg_buf);

            /* Resource length doesn't include RFC 5322 header */
            offset = oldrecord.header_size;

            /* Parse existing resource */
            buf_init_ro(&buf, buf_base(&msg_buf) + offset,
                        buf_len(&msg_buf) - offset);
            obj = pparams->mime_types[0].to_object(&buf);
            buf_free(&buf);

            /* Fill in ETag and Last-Modified */
            txn->resp_body.etag = etag;
            txn->resp_body.lastmod = lastmod;
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
    if (obj) {
        if (pparams->mime_types[0].free) pparams->mime_types[0].free(obj);
        buf_free(&msg_buf);
    }
    if (davdb) pparams->davdb.close_db(davdb);
    mailbox_close(&mailbox);

    return ret;
}


/* Compare modseq in index maps -- used for sorting */
static int map_modseq_cmp(const struct index_map *m1,
                          const struct index_map *m2)
{
    if (m1->modseq < m2->modseq) return -1;
    if (m1->modseq > m2->modseq) return 1;
    return 0;
}


/* CALDAV:calendar-multiget/CARDDAV:addressbook-multiget REPORT */
int report_multiget(struct transaction_t *txn, struct meth_params *rparams,
                    xmlNodePtr inroot, struct propfind_ctx *fctx)
{
    int r, ret = 0;
    struct mailbox *mailbox = NULL;
    xmlNodePtr node;

    /* Get props for each href */
    for (node = inroot->children; node; node = node->next) {
        if ((node->type == XML_ELEMENT_NODE) &&
            !xmlStrcmp(node->name, BAD_CAST "href")) {
            xmlChar *href = xmlNodeListGetString(inroot->doc, node->children, 1);
            xmlURIPtr uri;
            struct request_target_t tgt;
            struct dav_data *ddata;

            /* Parse the URI */
            uri = parse_uri(METH_REPORT, (const char *) href,
                            1 /* path required */, &fctx->txn->error.desc);
            xmlFree(href);
            if (!uri) {
                ret = HTTP_FORBIDDEN;
                goto done;
            }

            /* Parse the path */
            memset(&tgt, 0, sizeof(struct request_target_t));
            tgt.namespace = txn->req_tgt.namespace;

            r = rparams->parse_path(uri->path, &tgt, &fctx->txn->error.desc);
            xmlFreeURI(uri);
            if (r) {
                ret = r;
                goto done;
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
                    txn->error.desc = error_message(r);
                    ret = HTTP_SERVER_ERROR;
                    goto done;
                }

                fctx->mailbox = mailbox;
            }

            if (!fctx->mailbox || !tgt.resource) {
                /* Add response for missing target */
                xml_add_response(fctx, HTTP_NOT_FOUND, 0);
                continue;
            }

            /* Open the DAV DB corresponding to the mailbox */
            fctx->davdb = rparams->davdb.open_db(fctx->mailbox);

            /* Find message UID for the resource */
            rparams->davdb.lookup_resource(fctx->davdb, tgt.mbentry->name,
                                           tgt.resource, (void **) &ddata, 0);
            ddata->resource = tgt.resource;
            /* XXX  Check errors */

            fctx->proc_by_resource(fctx, ddata);

            /* XXX - split this into a req_tgt cleanup */
            free(tgt.userid);
            mboxlist_entry_free(&tgt.mbentry);

            rparams->davdb.close_db(fctx->davdb);
        }
    }

  done:
    mailbox_close(&mailbox);

    return (ret ? ret : HTTP_MULTI_STATUS);
}


/* DAV:sync-collection REPORT */
int report_sync_col(struct transaction_t *txn,
                    struct meth_params *rparams __attribute__((unused)),
                    xmlNodePtr inroot, struct propfind_ctx *fctx)
{
    int ret = 0, r, i, unbind_flag = -1, unchanged_flag = -1;
    struct mailbox *mailbox = NULL;
    uint32_t uidvalidity = 0;
    modseq_t syncmodseq = 0;
    modseq_t basemodseq = 0;
    modseq_t highestmodseq = 0;
    modseq_t respmodseq = 0;
    uint32_t limit = -1;
    uint32_t msgno;
    uint32_t nresp = 0;
    xmlNodePtr node;
    struct index_state istate;
    char tokenuri[MAX_MAILBOX_PATH+1];

    /* XXX  Handle Depth (cal-home-set at toplevel) */

    memset(&istate, 0, sizeof(struct index_state));
    istate.map = NULL;

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
    mailbox_user_flag(mailbox, DFLAG_UNBIND, &unbind_flag, 1);
    mailbox_user_flag(mailbox, DFLAG_UNCHANGED, &unchanged_flag, 1);

    /* Parse children element of report */
    for (node = inroot->children; node; node = node->next) {
        xmlNodePtr node2;
        xmlChar *str = NULL;
        if (node->type == XML_ELEMENT_NODE) {
            if (!xmlStrcmp(node->name, BAD_CAST "sync-token") &&
                (str = xmlNodeListGetString(inroot->doc, node->children, 1))) {
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
                for (node2 = node->children; node2; node2 = node2->next) {
                    if ((node2->type == XML_ELEMENT_NODE) &&
                        !xmlStrcmp(node2->name, BAD_CAST "nresults") &&
                        (!(str = xmlNodeListGetString(inroot->doc,
                                                      node2->children, 1)) ||
                         (sscanf((char *) str, "%u", &limit) != 1))) {
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

    /* Construct array of records for sorting and/or fetching cached header */
    istate.mailbox = mailbox;
    istate.map = xzmalloc(mailbox->i.num_records *
                          sizeof(struct index_map));

    /* Find which resources we need to report */
    struct mailbox_iter *iter = mailbox_iter_init(mailbox, syncmodseq, 0);
    const message_t *msg;
    while ((msg = mailbox_iter_step(iter))) {
        const struct index_record *record = msg_record(msg);
        if ((unbind_flag >= 0) &&
            record->user_flags[unbind_flag / 32] & (1 << (unbind_flag & 31))) {
            /* Resource replaced by a PUT, COPY, or MOVE - ignore it */
            continue;
        }

        if ((record->modseq - syncmodseq == 1) &&
            (unchanged_flag >= 0) &&
            (record->user_flags[unchanged_flag / 32] &
             (1 << (unchanged_flag & 31)))) {
            /* Resource has just had VTIMEZONEs stripped - ignore it */
            continue;
        }

        if ((record->modseq <= basemodseq) &&
            (record->system_flags & FLAG_EXPUNGED)) {
            /* Initial sync - ignore unmapped resources */
            continue;
        }

        /* copy data into map (just like index.c - XXX helper fn? */
        istate.map[nresp].recno = record->recno;
        istate.map[nresp].uid = record->uid;
        istate.map[nresp].modseq = record->modseq;
        istate.map[nresp].system_flags = record->system_flags;
        for (i = 0; i < MAX_USER_FLAGS/32; i++)
            istate.map[nresp].user_flags[i] = record->user_flags[i];
        istate.map[nresp].cache_offset = record->cache_offset;

        nresp++;
    }
    mailbox_iter_done(&iter);

    if (limit < nresp) {
        /* Need to truncate the responses */
        struct index_map *map = istate.map;

        /* Sort the response records by modseq */
        qsort(map, nresp, sizeof(struct index_map),
              (int (*)(const void *, const void *)) &map_modseq_cmp);

        /* Our last response MUST be the last record with its modseq */
        for (nresp = limit;
             nresp && map[nresp-1].modseq == map[nresp].modseq;
             nresp--);

        if (!nresp) {
            /* DAV:number-of-matches-within-limits */
            fctx->txn->error.desc = "Unable to truncate results";
            txn->error.precond = DAV_OVER_LIMIT;
            ret = HTTP_NO_STORAGE;
            goto done;
        }

        /* respmodseq will be modseq of last record we return */
        respmodseq = map[nresp-1].modseq;

        /* Tell client we truncated the responses */
        xml_add_response(fctx, HTTP_NO_STORAGE, DAV_OVER_LIMIT);
    }
    else {
        /* Full response - respmodseq will be highestmodseq of mailbox */
        respmodseq = highestmodseq;
    }

    /* XXX - this is crappy - re-reading the messages again */
    /* Report the resources within the client requested limit (if any) */
    for (msgno = 1; msgno <= nresp; msgno++) {
        char *p, *resource = NULL;
        struct index_record thisrecord;

        if (index_reload_record(&istate, msgno, &thisrecord))
            continue;

        /* Get resource filename from Content-Disposition header */
        if ((p = index_getheader(&istate, msgno, "Content-Disposition")) &&
            (p = strstr(p, "filename="))) {
            resource = p + 9;
        }
        if (!resource) continue;  /* No filename */

        if (*resource == '\"') {
            resource++;
            if ((p = strchr(resource, '\"'))) *p = '\0';
        }
        else if ((p = strchr(resource, ';'))) *p = '\0';

        if (thisrecord.system_flags & FLAG_EXPUNGED) {
            /* report as NOT FOUND
               IMAP UID of 0 will cause index record to be ignored
               propfind_by_resource() will append our resource name */
            struct dav_data ddata;

            memset(&ddata, 0, sizeof(struct dav_data));
            ddata.resource = resource;
            fctx->proc_by_resource(fctx, &ddata);
        }
        else {
            struct dav_data *ddata;

            /* Open the DAV DB corresponding to the mailbox */
            if (!fctx->davdb)
                fctx->davdb = rparams->davdb.open_db(fctx->mailbox);

            rparams->davdb.lookup_resource(fctx->davdb, fctx->mailbox->name,
                                           resource, (void **) &ddata, 0);
            ddata->resource = resource;
            fctx->record = &thisrecord;
            fctx->proc_by_resource(fctx, ddata);
        }

        fctx->record = NULL;
    }

    if (fctx->davdb) rparams->davdb.close_db(fctx->davdb);

    /* Add sync-token element */
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
    xmlNewChild(fctx->root, NULL, BAD_CAST "sync-token", BAD_CAST tokenuri);

  done:
    if (istate.map) free(istate.map);
    mailbox_close(&mailbox);

    return (ret ? ret : HTTP_MULTI_STATUS);
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

        xml_add_response(fctx, 0, 0);

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
    while (fctx->elist) {
        struct propfind_entry_list *freeme = fctx->elist;
        fctx->elist = freeme->next;
        xmlFree(freeme->name);
        free(freeme);
    }

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
                         xmlNodePtr inroot, struct propfind_ctx *fctx)
{
    int ret = 0;
    struct request_target_t req_tgt;
    mbentry_t *mbentry = fctx->req_tgt->mbentry;
    char *userid, *nextid;
    xmlNodePtr cur;

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

    /* Parse children element of report */
    for (cur = inroot->children; cur; cur = cur->next) {
        if (cur->type == XML_ELEMENT_NODE &&
            !xmlStrcmp(cur->name, BAD_CAST "prop")) {

            if ((ret = preload_proplist(cur->children, fctx))) goto done;
            break;
        }
    }

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
            xml_add_response(fctx, 0, 0);

            free(req_tgt.userid);
        }
    }

  done:
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

    return xml_add_response(fctx, 0, 0);
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
    struct hash_table ns_table = HASH_TABLE_INITIALIZER;
    struct propfind_ctx fctx;
    struct propfind_entry_list *elist = NULL;

    memset(&fctx, 0, sizeof(struct propfind_ctx));

    /* Parse the path */
    if ((r = rparams->parse_path(txn->req_uri->path,
                                 &txn->req_tgt, &txn->error.desc))) return r;

    /* Make sure method is allowed */
    if (!(txn->req_tgt.allow & ALLOW_DAV)) return HTTP_NOT_ALLOWED;

    /* Check Depth */
    if ((hdr = spool_getheader(txn->req_hdrs, "Depth"))) {
        if (!strcmp(hdr[0], "infinity")) {
            depth = 2;
        }
        else if ((sscanf(hdr[0], "%u", &depth) != 1) || (depth > 1)) {
            txn->error.desc = "Illegal Depth value\r\n";
            return HTTP_BAD_REQUEST;
        }
    }

    /* Parse the REPORT body */
    ret = parse_xml_body(txn, &inroot, NULL);
    if (!ret && !inroot) {
        txn->error.desc = "Missing request body\r\n";
        return HTTP_BAD_REQUEST;
    }
    if (ret) goto done;

    /* Add report type to our header cache */
    spool_cache_header(xstrdup(":type"), xstrdup((const char *) inroot->name),
                       txn->req_hdrs);

    /* Check the report type against our supported list */
    for (report = rparams->reports; report && report->name; report++) {
        if (!xmlStrcmp(inroot->name, BAD_CAST report->name)) break;
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
            if (cur->type == XML_ELEMENT_NODE) {
                if (!xmlStrcmp(cur->name, BAD_CAST "allprop")) {
                    fctx.mode = PROPFIND_ALL;
                    prop = cur;
                    break;
                }
                else if (!xmlStrcmp(cur->name, BAD_CAST "propname")) {
                    fctx.mode = PROPFIND_NAME;
                    fctx.prefer = PREFER_MIN;  /* Don't want 404 (Not Found) */
                    prop = cur;
                    break;
                }
                else if (!xmlStrcmp(cur->name, BAD_CAST "prop")) {
                    fctx.mode = PROPFIND_PROP;
                    prop = cur;
                    props = cur->children;
                    break;
                }
            }
        }

        if (!prop && (report->flags & REPORT_NEED_PROPS)) {
            txn->error.desc = "Missing <prop> element in REPORT\r\n";
            ret = HTTP_BAD_REQUEST;
            goto done;
        }
    }

    /* Start construction of our multistatus response */
    if (report->resp_root &&
        !(outroot = init_xml_response(report->resp_root, NS_DAV, inroot, ns))) {
        txn->error.desc = "Unable to create XML response\r\n";
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
    fctx.reqd_privs = report->reqd_privs;
    if (rparams->mime_types) fctx.free_obj = rparams->mime_types[0].free;
    fctx.elist = NULL;
    fctx.lprops = rparams->propfind.lprops;
    fctx.root = outroot;
    fctx.ns = ns;
    fctx.ns_table = &ns_table;
    fctx.ret = &ret;

    /* Parse the list of properties and build a list of callbacks */
    if (fctx.mode) {
        fctx.proc_by_resource = &propfind_by_resource;
        ret = preload_proplist(props, &fctx);
    }

    /* Process the requested report */
    if (!ret) ret = (*report->proc)(txn, rparams, inroot, &fctx);

    /* Output the XML response */
    if (outroot) {
        switch (ret) {
        case HTTP_OK:
        case HTTP_MULTI_STATUS:
            /* iCalendar data in response should not be transformed */
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
    elist = fctx.elist;
    while (elist) {
        struct propfind_entry_list *freeme = elist;
        elist = elist->next;
        if (freeme->flags & PROP_CLEANUP) {
            freeme->get(freeme->name, NULL, &fctx,
                        NULL, NULL, NULL, freeme->rock);
        }
        xmlFree(freeme->name);
        free(freeme);
    }

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
    if ((r = lparams->parse_path(txn->req_uri->path,
                                 &txn->req_tgt, &txn->error.desc))) return r;

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

    if (ddata->imap_uid) {
        /* Mapped URL - Fetch index record for the resource */
        r = mailbox_find_index_record(mailbox, ddata->imap_uid, &record);
        if (r) {
            txn->error.desc = error_message(r);
            ret = HTTP_SERVER_ERROR;
            goto done;
        }

        etag = message_guid_encode(&record.guid);
        lastmod = record.internaldate;
    }
    else {
        /* Unmapped URL (empty resource) */
        etag = NULL;
        lastmod = ddata->creationdate;
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
                       strarray_t *imapflags)
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
        txn->error.desc = "append_newstage() failed\r\n";
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
        time_to_rfc822(now, datestr, sizeof(datestr));
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
        ret = HTTP_SERVER_ERROR;
        txn->error.desc = "append_setup() failed\r\n";
    }
    else {
        struct body *body = NULL;

        strarray_t *flaglist = NULL;
        struct entryattlist *annots = NULL;

        if (oldrecord) {
            flaglist = mailbox_extract_flags(mailbox, oldrecord, httpd_userid);
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
        if ((r = append_fromstage(&as, &body, stage, now, flaglist, 0, annots))) {
            syslog(LOG_ERR, "append_fromstage(%s) failed: %s",
                   mailbox->name, error_message(r));
            ret = HTTP_SERVER_ERROR;
            txn->error.desc = "append_fromstage() failed\r\n";
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
                txn->error.desc = "append_commit() failed\r\n";
            }
            else {
                /* Read index record for new message (always the last one) */
                struct index_record newrecord;
                memset(&newrecord, 0, sizeof(struct index_record));
                newrecord.recno = mailbox->i.num_records;
                newrecord.uid = mailbox->i.last_uid;

                mailbox_reload_index_record(mailbox, &newrecord);

                if (oldrecord) {
                    /* Now that we have the replacement message in place
                       expunge the old one. */
                    int userflag;

                    ret = HTTP_NO_CONTENT;

                    /* Perform the actual expunge */
                    r = mailbox_user_flag(mailbox, DFLAG_UNBIND, &userflag, 1);
                    if (!r) {
                        oldrecord->user_flags[userflag/32] |= 1 << (userflag & 31);
                        oldrecord->system_flags |= FLAG_EXPUNGED;
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
                    struct resp_body_t *resp_body = &txn->resp_body;
                    static char *newetag;

                    if (newetag) free(newetag);
                    newetag = xstrdupnull(message_guid_encode(&newrecord.guid));

                    /* Tell client about the new resource */
                    resp_body->lastmod = newrecord.internaldate;
                    resp_body->etag = newetag;
                }
            }
        }
    }

    append_removestage(stage);

    return ret;
}


static void my_dav_init(struct buf *serverinfo __attribute__((unused)))
{
    if (!namespace_principal.enabled) return;

    if (!config_getstring(IMAPOPT_DAVNOTIFICATIONSPREFIX)) {
        fatal("Required 'davnotificationsprefix' option is not set", EC_CONFIG);
    }

    namespace_notify.enabled = 1;

    webdav_init();
}


static int lookup_notify_collection(const char *userid, mbentry_t **mbentry)
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
    r = http_mlookup(notifyname, mbentry, NULL);
    if (r == IMAP_MAILBOX_NONEXISTENT) {
        /* Find location of INBOX */
        char *inboxname = mboxname_user_mbox(userid, NULL);

        int r1 = http_mlookup(inboxname, mbentry, NULL);
        free(inboxname);
        if (r1 == IMAP_MAILBOX_NONEXISTENT) {
            r = IMAP_INVALID_USER;
            goto done;
        }

        if (*mbentry) free((*mbentry)->name);
        else *mbentry = mboxlist_entry_create();
        (*mbentry)->name = xstrdup(notifyname);
    }

  done:
    mbname_free(&mbname);

    return r;
}


static int create_notify_collection(const char *userid, struct mailbox **mailbox)
{
    /* notifications collection */
    mbentry_t *mbentry = NULL;
    int r = lookup_notify_collection(userid, &mbentry);

    if (r == IMAP_INVALID_USER) {
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
                                   NULL, 1 /* admin */, userid, NULL,
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

static void my_dav_auth(const char *userid)
{
    if (httpd_userisadmin || httpd_userisanonymous ||
        global_authisa(httpd_authstate, IMAPOPT_PROXYSERVERS)) {
        /* admin, anonymous, or proxy from frontend - won't have DAV database */
        return;
    }
    else if (config_mupdate_server && !config_getstring(IMAPOPT_PROXYSERVERS)) {
        /* proxy-only server - won't have DAV databases */
    }
    else {
        /* Open WebDAV DB for 'userid' */
        my_dav_reset();
        auth_webdavdb = webdav_open_userid(userid);
        if (!auth_webdavdb) fatal("Unable to open WebDAV DB", EC_IOERR);
    }

    /* Auto-provision a notifications collection for 'userid' */
    create_notify_collection(userid, NULL);


    if (!server_info) {
        time_t compile_time = calc_compile_time(__TIME__, __DATE__);
        struct stat sbuf;
        struct message_guid guid;
        xmlNodePtr root, node, apps, app;
        xmlNsPtr ns[NUM_NAMESPACE];

        /* Generate token based on compile date/time of this source file,
           the number of available RSCALEs and the config file size/mtime */
        stat(config_filename, &sbuf);
        server_info_lastmod = MAX(compile_time, sbuf.st_mtime);

        buf_printf(&server_info_token, "%ld-%ld-%ld", (long) compile_time,
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
                            BAD_CAST "version", BAD_CAST cyrus_version());
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
    }
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

static int notify_parse_path(const char *path,
                             struct request_target_t *tgt, const char **errstr);

static int notify_get(struct transaction_t *txn, struct mailbox *mailbox,
                      struct index_record *record, void *data, void **obj);

static int propfind_notifytype(const xmlChar *name, xmlNsPtr ns,
                               struct propfind_ctx *fctx,
                               xmlNodePtr prop, xmlNodePtr resp,
                               struct propstat propstat[], void *rock);

static struct buf *from_xml(xmlDocPtr doc)
{
    struct buf *buf = buf_new();
    xmlChar *xml = NULL;
    int len;

    /* Dump XML response tree into a text buffer */
    xmlDocDumpFormatMemoryEnc(doc, &xml, &len, "utf-8",
                              config_httpprettytelemetry);
    if (xml) buf_initm(buf, (char *) xml, len);
    else buf_init(buf);

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
      DACL_ADMIN, REPORT_NEED_MBOX | REPORT_DEPTH_ZERO },

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
      PROP_ALLPROP | PROP_COLLECTION | PROP_RESOURCE,
      propfind_fromdb, proppatch_todb, NULL },
    { "getcontentlanguage", NS_DAV, PROP_ALLPROP | PROP_RESOURCE,
      propfind_fromhdr, NULL, "Content-Language" },
    { "getcontentlength", NS_DAV,
      PROP_ALLPROP | PROP_COLLECTION | PROP_RESOURCE,
      propfind_getlength, NULL, NULL },
    { "getcontenttype", NS_DAV, PROP_ALLPROP | PROP_RESOURCE,
      propfind_fromhdr, NULL, "Content-Type" },
    { "getetag", NS_DAV, PROP_ALLPROP | PROP_COLLECTION | PROP_RESOURCE,
      propfind_getetag, NULL, NULL },
    { "getlastmodified", NS_DAV,
      PROP_ALLPROP | PROP_COLLECTION | PROP_RESOURCE,
      propfind_getlastmod, NULL, NULL },
    { "resourcetype", NS_DAV,
      PROP_ALLPROP | PROP_COLLECTION | PROP_RESOURCE,
      propfind_restype, NULL, NULL },

    /* WebDAV Versioning (RFC 3253) properties */
    { "supported-report-set", NS_DAV, PROP_COLLECTION,
      propfind_reportset, NULL, (void *) notify_reports },

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

    /* WebDAV Current Principal (RFC 5397) properties */
    { "current-user-principal", NS_DAV,
      PROP_COLLECTION | PROP_RESOURCE,
      propfind_curprin, NULL, NULL },

    /* WebDAV Sync (RFC 6578) properties */
    { "sync-token", NS_DAV, PROP_COLLECTION,
      propfind_sync_token, NULL, SYNC_TOKEN_URL_SCHEME },

    /* WebDAV Notifications (draft-pot-webdav-notifications) properties */
    { "notificationtype", NS_DAV, PROP_RESOURCE,
      propfind_notifytype, NULL, NULL },

    /* Backwards compatibility with Apple notifications clients */
    { "notificationtype", NS_CS, PROP_RESOURCE,
      propfind_notifytype, NULL, "calendarserver-sharing" },

    /* Apple Calendar Server properties */
    { "getctag", NS_CS, PROP_ALLPROP | PROP_COLLECTION,
      propfind_sync_token, NULL, "" },

    { NULL, 0, 0, NULL, NULL, NULL }
};

struct meth_params notify_params = {
    notify_mime_types,
    &notify_parse_path,
    &dav_check_precond,
    { (db_open_proc_t) &webdav_open_mailbox,
      (db_close_proc_t) &webdav_close,
      (db_proc_t) &webdav_begin,
      (db_proc_t) &webdav_commit,
      (db_proc_t) &webdav_abort,
      (db_lookup_proc_t) &webdav_lookup_resource,
      (db_foreach_proc_t) &webdav_foreach,
      (db_write_proc_t) &webdav_write,
      (db_delete_proc_t) &webdav_delete },
    NULL,                                       /* No ACL extensions */
    { 0, &notify_put },
    NULL,                                       /* No special DELETE handling */
    &notify_get,
    { 0, 0 },                                   /* No MKCOL handling */
    NULL,                                       /* No PATCH handling */
    { 0, &notify_post, NULL },                  /* No generic POST handling */
    { 0, &notify_put },
    { DAV_FINITE_DEPTH, notify_props},
    notify_reports
};


/* Namespace for WebDAV notifcation collections */
struct namespace_t namespace_notify = {
    URL_NS_NOTIFY, 0, "/dav/notifications", NULL,
    http_allow_noauth_get, /*authschemes*/0,
    MBTYPE_COLLECTION,
    (ALLOW_READ | ALLOW_POST | ALLOW_DELETE |
     ALLOW_DAV | ALLOW_PROPPATCH | ALLOW_ACL),
    NULL, NULL, NULL, NULL,
    &dav_premethod, /*bearer*/NULL,
    {
        { &meth_acl,            &notify_params },      /* ACL          */
        { NULL,                 NULL },                /* BIND         */
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


/* Perform a GET/HEAD request on a WebDAV notification resource */
static int notify_get(struct transaction_t *txn, struct mailbox *mailbox,
                      struct index_record *record, void *data,
                      void **obj __attribute__((unused)))
{
    const char **hdr;
    struct webdav_data *wdata = (struct webdav_data *) data;
    struct dlist *dl = NULL, *al;
    const char *type_str;
    struct buf msg_buf = BUF_INITIALIZER;
    struct buf inbuf, *outbuf = NULL;
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


/* Perform a POST request on a WebDAV notification resource */
int notify_post(struct transaction_t *txn)
{
    xmlNodePtr root = NULL, node, resp = NULL;
    int rights, ret, r, legacy = 0, add = 0;
    struct mailbox *mailbox = NULL, *shared = NULL;
    struct webdav_db *webdavdb = NULL;
    struct webdav_data *wdata;
    struct dlist *dl = NULL, *data;
    const char *type_str, *mboxname, *url_prefix;
    char dtstamp[RFC3339_DATETIME_MAX], *owner = NULL, *resource = NULL;
    xmlNodePtr notify = NULL, type, sharee;
    xmlNsPtr ns[NUM_NAMESPACE];
    xmlChar *comment = NULL, *freeme = NULL;

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
        r = lookup_notify_collection(txn->req_tgt.userid, &txn->req_tgt.mbentry);
        if (r) {
            syslog(LOG_ERR, "lookup_notify_collection(%s) failed: %s",
                   txn->req_tgt.userid, error_message(r));
            txn->error.desc = error_message(r);
            ret = HTTP_SERVER_ERROR;
            goto done;
        }
    }

    /* Open notification mailbox for reading */
    r = mailbox_open_irl(txn->req_tgt.mbentry->name, &mailbox);
    if (r) {
        syslog(LOG_ERR, "mailbox_open_irl(%s) failed: %s",
               txn->req_tgt.mbentry->name, error_message(r));
        goto done;
    }

    /* Open the WebDAV DB corresponding to the mailbox */
    webdavdb = webdav_open_mailbox(mailbox);

    /* Find message UID for the resource */
    webdav_lookup_resource(webdavdb, txn->req_tgt.mbentry->name,
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
        syslog(LOG_ERR, "IOERROR: failed to open mailbox %s for share reply",
               mboxname);
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

            if (shared->mbtype == MBTYPE_CALENDAR) {
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
    make_collection_url(&txn->buf, url_prefix, mboxname, "", &owner);

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

    r = send_notification(txn, notify->doc, owner, buf_cstring(&txn->buf));

    if (add) {
        /* Accepted - create URL of sharee's new collection */
        make_collection_url(&txn->buf, url_prefix,
                            mboxname, txn->req_tgt.userid, NULL);

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
    mailbox_close(&mailbox);
    dlist_free(&dl);
    free(owner);

    return ret;
}


/* Perform a PUT request on a WebDAV notification resource */
static int notify_put(struct transaction_t *txn, void *obj,
                      struct mailbox *mailbox, const char *resource,
                      void *destdb, unsigned flags __attribute__((unused)))
{
    struct webdav_db *db = (struct webdav_db *)destdb;
    xmlDocPtr doc = (xmlDocPtr) obj;
    xmlNodePtr root, dtstamp, type = NULL, node;
    struct webdav_data *wdata;
    struct index_record *oldrecord = NULL, record;
    struct buf *xmlbuf;
    int r;

    /* Validate the data */
    if (!doc) return HTTP_FORBIDDEN;

    /* Find message UID for the resource */
    webdav_lookup_resource(db, mailbox->name, resource, &wdata, 0);

    if (wdata->dav.imap_uid) {
        /* Fetch index record for the resource */
        oldrecord = &record;
        mailbox_find_index_record(mailbox, wdata->dav.imap_uid, oldrecord);
    }

    /* Get type of notification */
    if ((root = xmlDocGetRootElement(doc)) &&
        (dtstamp = xmlFirstElementChild(root))) {
        type = xmlNextElementSibling(dtstamp);
    }

    /* Create and cache RFC 5322 header fields for resource */
    if (type) {
        struct buf buf = BUF_INITIALIZER;
        xmlChar *value;
        time_t t;
        struct dlist *dl, *al;
        xmlAttrPtr attr;

        spool_replace_header(xstrdup("Subject"),
                             xstrdup((char *) type->name), txn->req_hdrs);

        /* Create a dlist representing type, namespace, and attribute(s) */
        value = xmlNodeGetContent(dtstamp);
        time_from_iso8601((const char *) value, &t);
        xmlFree(value);

        dl = dlist_newkvlist(NULL, "N");
        dlist_setdate(dl, "S", t);
        dlist_setatom(dl, "NS", (char *) type->ns->href);
        dlist_setatom(dl, "T", (char *) type->name);

        /* Add any attributes */
        al = dlist_newkvlist(dl, "A");
        for (attr = type->properties; attr; attr = attr->next) {
            value = xmlNodeGetContent((xmlNodePtr) attr);
            dlist_setmap(al, (char *) attr->name,
                         (char *) value, xmlStrlen(value));
            xmlFree(value);
        }

        /* Add any additional data */
        al = dlist_newkvlist(dl, "D");
        if (!xmlStrcmp(type->name, BAD_CAST SHARE_INVITE_NOTIFICATION)) {
            for (node = xmlFirstElementChild(type); node;
                 node = xmlNextElementSibling(node)) {
                if (!xmlStrcmp(node->name, BAD_CAST "sharer-resource-uri")) {
                    struct request_target_t tgt;
                    const char *errstr;

                    memset(&tgt, 0, sizeof(struct request_target_t));
                    tgt.namespace = txn->req_tgt.namespace;
                    value = xmlNodeGetContent(xmlFirstElementChild(node));
                    calcarddav_parse_path((const char *) value, &tgt,
                                          txn->req_tgt.mboxprefix, &errstr);
                    xmlFree(value);
                    free(tgt.userid);

                    dlist_setatom(al, "M", tgt.mbentry->name);

                    mboxlist_entry_free(&tgt.mbentry);
                    break;
                }
            }
        }

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
                               mailbox, oldrecord, NULL);
    }

    buf_destroy(xmlbuf);

    return r;
}


/* Callback to fetch DAV:notification-URL and CS:notification-URL */
static int propfind_notifyurl(const xmlChar *name, xmlNsPtr ns,
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


void xml_add_shareaccess(struct propfind_ctx *fctx,
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
int propfind_shareaccess(const xmlChar *name, xmlNsPtr ns,
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
int propfind_invite(const xmlChar *name, xmlNsPtr ns,
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
int propfind_sharedurl(const xmlChar *name, xmlNsPtr ns,
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

    mbname = mbname_from_intname(fctx->mailbox->name);

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


/* Parse request-target path in DAV notifications namespace */
static int notify_parse_path(const char *path, struct request_target_t *tgt,
                             const char **errstr)
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
        *errstr = "Namespace mismatch request target path";
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
//      *errstr = "Too many segments in request target path";
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
        int r = http_mlookup(mboxname, &tgt->mbentry, NULL);
        if (r) {
            syslog(LOG_ERR, "mlookup(%s) failed: %s",
                   mboxname, error_message(r));
            *errstr = error_message(r);
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


static int propfind_csnotify_collection(struct propfind_ctx *fctx,
                                        xmlNodePtr props)
{
    struct propfind_ctx my_fctx;
    struct request_target_t tgt;
    struct propfind_entry_list *elist;
    const char *err = NULL;

    /* Populate our propfind context for notifcation collection */
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

    /* Parse the list of properties and build a list of callbacks */
    preload_proplist(props, &my_fctx);

    /* Add response for target collection */
    propfind_by_collection(tgt.mbentry, &my_fctx);

    free(tgt.userid);
    mboxlist_entry_free(&tgt.mbentry);

    /* Free the entry list */
    elist = my_fctx.elist;
    while (elist) {
        struct propfind_entry_list *freeme = elist;
        elist = elist->next;
        xmlFree(freeme->name);
        free(freeme);
    }

    buf_free(&my_fctx.buf);

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
