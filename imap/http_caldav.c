/* http_caldav.c -- Routines for handling CalDAV collections in httpd
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
 *   - Make proxying more robust.  Currently depends on calendar collections
 *     residing on same server as user's INBOX.  Doesn't handle global/shared
 *     calendars.
 *   - Support COPY/MOVE on collections
 *   - Add more required properties?
 *   - calendar-query REPORT (handle timezone, timezone-id)
 *   - free-busy-query REPORT (check ACL and transp on all calendars)
 *   - sync-collection REPORT - need to handle Depth infinity?
 */

#include <config.h>

#include <syslog.h>

#include <libical/ical.h>
#include <libxml/tree.h>
#include <libxml/uri.h>
#include <sys/types.h>

#include "acl.h"
#include "append.h"
#include "caldav_db.h"
#include "charset.h"
#include "exitcodes.h"
#include "global.h"
#include "hash.h"
#include "httpd.h"
#include "http_caldav.h"
#include "http_caldav_sched.h"
#include "http_dav.h"
#include "http_proxy.h"
#include "index.h"
#include "ical_support.h"
#include "jmap_ical.h"
#include "jcal.h"
#include "xcal.h"
#include "map.h"
#include "mailbox.h"
#include "mboxlist.h"
#include "message.h"
#include "message_guid.h"
#include "proxy.h"
#include "times.h"
#include "spool.h"
#include "strhash.h"
#include "stristr.h"
#include "tok.h"
#include "util.h"
#include "version.h"
#include "webdav_db.h"
#include "xmalloc.h"
#include "xml_support.h"
#include "xstrlcat.h"
#include "xstrlcpy.h"
#include "xstrnchr.h"
#include "zoneinfo_db.h"

/* generated headers are not necessarily in current directory */
#include "imap/http_err.h"
#include "imap/imap_err.h"

#define TZ_STRIP (1<<9)


#ifdef HAVE_RSCALE
#include <unicode/uversion.h>

static int rscale_cmp(const void *a, const void *b)
{
    /* Convert to uppercase since that's what we prefer to output */
    return strcmp(ucase(*((char **) a)), ucase(*((char **) b)));
}
#endif /* HAVE_RSCALE */


static struct caldav_db *auth_caldavdb = NULL;
static time_t compile_time;
static struct buf ical_prodid_buf = BUF_INITIALIZER;

unsigned config_allowsched = IMAP_ENUM_CALDAV_ALLOWSCHEDULING_OFF;
const char *ical_prodid = NULL;
icaltimezone *utc_zone = NULL;
struct strlist *cua_domains = NULL;
icalarray *rscale_calendars = NULL;

struct partial_comp_t {
    icalcomponent_kind kind;
    arrayu64_t props;
    struct partial_comp_t *sibling;
    struct partial_comp_t *child;
};

static struct partial_caldata_t {
    unsigned expand : 1;
    struct icalperiodtype range;
    struct partial_comp_t *comp;
} partial_caldata;

static int meth_options_cal(struct transaction_t *txn, void *params);
static int meth_get_head_cal(struct transaction_t *txn, void *params);
static int meth_get_head_fb(struct transaction_t *txn, void *params);

static void my_caldav_init(struct buf *serverinfo);
static void my_caldav_auth(const char *userid);
static void my_caldav_reset(void);
static void my_caldav_shutdown(void);

static int caldav_parse_path(const char *path,
                             struct request_target_t *tgt, const char **errstr);

static int caldav_check_precond(struct transaction_t *txn,
                                struct meth_params *params,
                                struct mailbox *mailbox, const void *data,
                                const char *etag, time_t lastmod);

static int caldav_acl(struct transaction_t *txn, xmlNodePtr priv, int *rights);
static int caldav_copy(struct transaction_t *txn, void *obj,
                       struct mailbox *dest_mbox, const char *dest_rsrc,
                       void *destdb, unsigned flags);
static int caldav_delete_cal(struct transaction_t *txn,
                             struct mailbox *mailbox,
                             struct index_record *record, void *data);
static int caldav_get(struct transaction_t *txn, struct mailbox *mailbox,
                      struct index_record *record, void *data, void **obj);
static int caldav_post(struct transaction_t *txn);
static int caldav_patch(struct transaction_t *txn, void *obj);
static int caldav_put(struct transaction_t *txn, void *obj,
                      struct mailbox *mailbox, const char *resource,
                      void *destdb, unsigned flags);
static int caldav_import(struct transaction_t *txn, void *obj,
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
static int propfind_scheduser(const xmlChar *name, xmlNsPtr ns,
                            struct propfind_ctx *fctx,
                            xmlNodePtr prop, xmlNodePtr resp,
                            struct propstat propstat[], void *rock);
static int propfind_caldata(const xmlChar *name, xmlNsPtr ns,
                            struct propfind_ctx *fctx,
                            xmlNodePtr prop, xmlNodePtr resp,
                            struct propstat propstat[], void *rock);
static int propfind_calcompset(const xmlChar *name, xmlNsPtr ns,
                               struct propfind_ctx *fctx,
                               xmlNodePtr prop, xmlNodePtr resp,
                               struct propstat propstat[], void *rock);
static int proppatch_calcompset(xmlNodePtr prop, unsigned set,
                                struct proppatch_ctx *pctx,
                                struct propstat propstat[], void *rock);
static int propfind_suppcaldata(const xmlChar *name, xmlNsPtr ns,
                                struct propfind_ctx *fctx,
                                xmlNodePtr prop, xmlNodePtr resp,
                                struct propstat propstat[], void *rock);
static int propfind_maxsize(const xmlChar *name, xmlNsPtr ns,
                            struct propfind_ctx *fctx,
                            xmlNodePtr prop, xmlNodePtr resp,
                            struct propstat propstat[], void *rock);
static int propfind_minmaxdate(const xmlChar *name, xmlNsPtr ns,
                               struct propfind_ctx *fctx,
                               xmlNodePtr prop, xmlNodePtr resp,
                               struct propstat propstat[], void *rock);
static int propfind_scheddefault(const xmlChar *name, xmlNsPtr ns,
                                 struct propfind_ctx *fctx,
                                 xmlNodePtr prop, xmlNodePtr resp,
                                 struct propstat propstat[], void *rock);
static int propfind_schedtag(const xmlChar *name, xmlNsPtr ns,
                             struct propfind_ctx *fctx,
                             xmlNodePtr prop, xmlNodePtr resp,
                             struct propstat propstat[], void *rock);
static int propfind_caltransp(const xmlChar *name, xmlNsPtr ns,
                              struct propfind_ctx *fctx,
                              xmlNodePtr prop, xmlNodePtr resp,
                              struct propstat propstat[], void *rock);
static int proppatch_caltransp(xmlNodePtr prop, unsigned set,
                               struct proppatch_ctx *pctx,
                               struct propstat propstat[], void *rock);
static int propfind_timezone(const xmlChar *name, xmlNsPtr ns,
                             struct propfind_ctx *fctx,
                             xmlNodePtr prop, xmlNodePtr resp,
                             struct propstat propstat[], void *rock);
static int proppatch_timezone(xmlNodePtr prop, unsigned set,
                              struct proppatch_ctx *pctx,
                              struct propstat propstat[], void *rock);
static int propfind_availability(const xmlChar *name, xmlNsPtr ns,
                                 struct propfind_ctx *fctx,
                                 xmlNodePtr prop, xmlNodePtr resp,
                                 struct propstat propstat[], void *rock);
static int proppatch_availability(xmlNodePtr prop, unsigned set,
                                  struct proppatch_ctx *pctx,
                                  struct propstat propstat[], void *rock);
static int propfind_tzservset(const xmlChar *name, xmlNsPtr ns,
                              struct propfind_ctx *fctx,
                              xmlNodePtr prop, xmlNodePtr resp,
                              struct propstat propstat[], void *rock);
static int propfind_tzid(const xmlChar *name, xmlNsPtr ns,
                         struct propfind_ctx *fctx,
                         xmlNodePtr prop, xmlNodePtr resp,
                         struct propstat propstat[], void *rock);
static int proppatch_tzid(xmlNodePtr prop, unsigned set,
                          struct proppatch_ctx *pctx,
                          struct propstat propstat[], void *rock);
static int propfind_rscaleset(const xmlChar *name, xmlNsPtr ns,
                              struct propfind_ctx *fctx,
                              xmlNodePtr prop, xmlNodePtr resp,
                              struct propstat propstat[], void *rock);
static int propfind_sharingmodes(const xmlChar *name, xmlNsPtr ns,
                                 struct propfind_ctx *fctx,
                                 xmlNodePtr prop, xmlNodePtr resp,
                                 struct propstat propstat[], void *rock);

static void strip_vtimezones(icalcomponent *ical);

static int report_cal_query(struct transaction_t *txn,
                            struct meth_params *rparams,
                            xmlNodePtr inroot, struct propfind_ctx *fctx);
static int report_fb_query(struct transaction_t *txn,
                           struct meth_params *rparams,
                           xmlNodePtr inroot, struct propfind_ctx *fctx);

static const char *begin_icalendar(struct buf *buf);
static void end_icalendar(struct buf *buf);

#define ICALENDAR_CONTENT_TYPE "text/calendar; charset=utf-8"

static struct mime_type_t caldav_mime_types[] = {
    /* First item MUST be the default type and storage format */
    { ICALENDAR_CONTENT_TYPE, "2.0", "ics",
      (struct buf* (*)(void *)) &my_icalcomponent_as_ical_string,
      (void * (*)(const struct buf*)) &ical_string_as_icalcomponent,
      (void (*)(void *)) &icalcomponent_free, &begin_icalendar, &end_icalendar
    },
    { "application/calendar+xml; charset=utf-8", NULL, "xcs",
      (struct buf* (*)(void *)) &icalcomponent_as_xcal_string,
      (void * (*)(const struct buf*)) &xcal_string_as_icalcomponent,
      NULL, &begin_xcal, &end_xcal
    },
    { "application/calendar+json; charset=utf-8", NULL, "jcs",
      (struct buf* (*)(void *)) &icalcomponent_as_jcal_string,
      (void * (*)(const struct buf*)) &jcal_string_as_icalcomponent,
      NULL, &begin_jcal, &end_jcal
    },
    { "application/event+json; charset=utf-8", NULL, "jevent",
      (struct buf* (*)(void *)) &icalcomponent_as_jevent_string,
      (void * (*)(const struct buf*)) &jevent_string_as_icalcomponent,
      NULL, NULL, NULL
    },
    { NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL }
};

static struct patch_doc_t caldav_patch_docs[] = {
#ifdef HAVE_VPATCH
    { ICALENDAR_CONTENT_TYPE "; component=VPATCH; optinfo=\"PATCH-VERSION:1\"",
      &caldav_patch },
#endif
    { NULL, &caldav_patch /* silence compiler when !HAVE_VPATCH */}
};

/* Array of supported REPORTs */
static const struct report_type_t caldav_reports[] = {

    /* WebDAV Versioning (RFC 3253) REPORTs */
    { "expand-property", NS_DAV, "multistatus", &report_expand_prop,
      DACL_READ, 0 },

    /* WebDAV ACL (RFC 3744) REPORTs */
    { "acl-principal-prop-set", NS_DAV, "multistatus", &report_acl_prin_prop,
      DACL_ADMIN, REPORT_NEED_MBOX | REPORT_DEPTH_ZERO },

    /* WebDAV Sync (RFC 6578) REPORTs */
    { "sync-collection", NS_DAV, "multistatus", &report_sync_col,
      DACL_READ, REPORT_NEED_MBOX | REPORT_NEED_PROPS },

    /* CalDAV (RFC 4791) REPORTs */
    { "calendar-query", NS_CALDAV, "multistatus", &report_cal_query,
      DACL_READ, REPORT_NEED_MBOX | REPORT_ALLOW_PROPS },
    { "calendar-multiget", NS_CALDAV, "multistatus", &report_multiget,
      DACL_READ, REPORT_NEED_MBOX | REPORT_ALLOW_PROPS },
    { "free-busy-query", NS_CALDAV, NULL, &report_fb_query,
      DACL_READFB, REPORT_NEED_MBOX },

    { NULL, 0, NULL, NULL, 0, 0 }
};

/* Array of known "live" properties */
static const struct prop_entry caldav_props[] = {

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
      propfind_restype, proppatch_restype, "calendar" },
    { "supportedlock", NS_DAV, PROP_ALLPROP | PROP_RESOURCE,
      propfind_suplock, NULL, NULL },

    /* WebDAV Versioning (RFC 3253) properties */
    { "supported-report-set", NS_DAV, PROP_COLLECTION,
      propfind_reportset, NULL, (void *) caldav_reports },

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
    { "current-user-principal", NS_DAV, PROP_COLLECTION | PROP_RESOURCE,
      propfind_curprin, NULL, NULL },

    /* WebDAV POST (RFC 5995) properties */
    { "add-member", NS_DAV, PROP_COLLECTION,
      propfind_addmember, NULL, NULL },

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

    /* Backwards compatibility with Apple calendar sharing clients */
    { "invite", NS_CS, PROP_COLLECTION,
      propfind_invite, NULL, "calendarserver-sharing" },
    { "allowed-sharing-modes", NS_CS, PROP_COLLECTION,
      propfind_sharingmodes, NULL, NULL },
    { "shared-url", NS_CS, PROP_COLLECTION,
      propfind_sharedurl, NULL, "calendarserver-sharing" },

    /* CalDAV (RFC 4791) properties */
    { "calendar-data", NS_CALDAV, PROP_RESOURCE | PROP_PRESCREEN | PROP_CLEANUP,
      propfind_caldata, NULL, &partial_caldata },
    { "schedule-user-address", NS_CYRUS, PROP_RESOURCE,
      propfind_scheduser, NULL, NULL },
    { "calendar-description", NS_CALDAV, PROP_COLLECTION,
      propfind_fromdb, proppatch_todb, NULL },
    { "calendar-timezone", NS_CALDAV, PROP_COLLECTION | PROP_PRESCREEN,
      propfind_timezone, proppatch_timezone, NULL },
    { "supported-calendar-component-set", NS_CALDAV, PROP_COLLECTION,
      propfind_calcompset, proppatch_calcompset, NULL },
    { "supported-calendar-data", NS_CALDAV, PROP_COLLECTION,
      propfind_suppcaldata, NULL, NULL },
    { "max-resource-size", NS_CALDAV, PROP_COLLECTION,
      propfind_maxsize, NULL, NULL },
    { "min-date-time", NS_CALDAV, PROP_COLLECTION,
      propfind_minmaxdate, NULL, &caldav_epoch },
    { "max-date-time", NS_CALDAV, PROP_COLLECTION,
      propfind_minmaxdate, NULL, &caldav_eternity },
    { "max-instances", NS_CALDAV, 0, NULL, NULL, NULL },
    { "max-attendees-per-instance", NS_CALDAV, 0, NULL, NULL, NULL },

    /* CalDAV Scheduling (RFC 6638) properties */
    { "schedule-tag", NS_CALDAV, PROP_RESOURCE,
      propfind_schedtag, NULL, NULL },
    { "schedule-default-calendar-URL", NS_CALDAV, PROP_COLLECTION,
      propfind_scheddefault, NULL, NULL },
    { "schedule-calendar-transp", NS_CALDAV, PROP_COLLECTION,
      propfind_caltransp, proppatch_caltransp, NULL },

    /* Calendar Availability (RFC 7953) properties */
    { "calendar-availability", NS_CALDAV, PROP_COLLECTION | PROP_PRESCREEN,
      propfind_availability, proppatch_availability, NULL },

    /* Backwards compatibility with Apple VAVAILABILITY clients */
    { "calendar-availability", NS_CS, PROP_COLLECTION | PROP_PRESCREEN,
      propfind_availability, proppatch_availability, NULL },

    /* Time Zones by Reference (RFC 7809) properties */
    { "timezone-service-set", NS_CALDAV, PROP_COLLECTION,
      propfind_tzservset, NULL, NULL },
    { "calendar-timezone-id", NS_CALDAV, PROP_COLLECTION,
      propfind_tzid, proppatch_tzid, NULL },

    /* RSCALE (RFC 7529) properties */
    { "supported-rscale-set", NS_CALDAV, PROP_COLLECTION,
      propfind_rscaleset, NULL, NULL },

    /* CalDAV Extensions (draft-daboo-caldav-extensions) properties */
    { "supported-calendar-component-sets", NS_CALDAV, PROP_COLLECTION,
      propfind_calcompset, NULL, NULL },

    /* Apple Calendar Server properties */
    { "getctag", NS_CS, PROP_ALLPROP | PROP_COLLECTION,
      propfind_sync_token, NULL, "" },

    /* Apple Mobile Me properties */
    { "bulk-requests", NS_MECOM, PROP_COLLECTION,
      propfind_bulkrequests, NULL, NULL },

    /* Apple Push Notifications Service properties */
    { "push-transports", NS_CS, PROP_COLLECTION,
      propfind_push_transports, NULL, (void *) MBTYPE_CALENDAR },
    { "pushkey", NS_CS, PROP_COLLECTION,
      propfind_pushkey, NULL, NULL },

    { NULL, 0, 0, NULL, NULL, NULL }
};


static struct meth_params caldav_params = {
    caldav_mime_types,
    &caldav_parse_path,
    &caldav_check_precond,
    { (db_open_proc_t) &caldav_open_mailbox,
      (db_close_proc_t) &caldav_close,
      (db_proc_t) &caldav_begin,
      (db_proc_t) &caldav_commit,
      (db_proc_t) &caldav_abort,
      (db_lookup_proc_t) &caldav_lookup_resource,
      (db_foreach_proc_t) &caldav_foreach,
      (db_write_proc_t) &caldav_write,
      (db_delete_proc_t) &caldav_delete },
    &caldav_acl,
    { CALDAV_UID_CONFLICT, &caldav_copy },
    &caldav_delete_cal,
    &caldav_get,
    { CALDAV_LOCATION_OK, MBTYPE_CALENDAR },
    caldav_patch_docs,
    { POST_ADDMEMBER | POST_SHARE | POST_BULK, &caldav_post, &caldav_import },
    { CALDAV_SUPP_DATA, &caldav_put },
    { 0, caldav_props },                        /* Allow infinite depth */
    caldav_reports
};


/* Namespace for CalDAV collections */
struct namespace_t namespace_calendar = {
    URL_NS_CALENDAR, 0, "/dav/calendars", "/.well-known/caldav", 1 /* auth */,
    MBTYPE_CALENDAR,
    (ALLOW_READ | ALLOW_POST | ALLOW_WRITE | ALLOW_DELETE |
#ifdef HAVE_VPATCH
     ALLOW_PATCH |
#endif
#ifdef HAVE_VAVAILABILITY
     ALLOW_CAL_AVAIL |
#endif
     ALLOW_DAV | ALLOW_PROPPATCH | ALLOW_MKCOL | ALLOW_ACL | ALLOW_CAL ),
    &my_caldav_init, &my_caldav_auth, my_caldav_reset, &my_caldav_shutdown,
    &dav_premethod,
    {
        { &meth_acl,            &caldav_params },       /* ACL          */
        { NULL,                 NULL },                 /* BIND         */
        { &meth_copy_move,      &caldav_params },       /* COPY         */
        { &meth_delete,         &caldav_params },       /* DELETE       */
        { &meth_get_head_cal,   NULL },                 /* GET          */
        { &meth_get_head_cal,   NULL },                 /* HEAD         */
        { &meth_lock,           &caldav_params },       /* LOCK         */
        { &meth_mkcol,          &caldav_params },       /* MKCALENDAR   */
        { &meth_mkcol,          &caldav_params },       /* MKCOL        */
        { &meth_copy_move,      &caldav_params },       /* MOVE         */
        { &meth_options_cal,    &caldav_parse_path },   /* OPTIONS      */
        { &meth_patch,          &caldav_params },       /* PATCH        */
        { &meth_post,           &caldav_params },       /* POST         */
        { &meth_propfind,       &caldav_params },       /* PROPFIND     */
        { &meth_proppatch,      &caldav_params },       /* PROPPATCH    */
        { &meth_put,            &caldav_params },       /* PUT          */
        { &meth_report,         &caldav_params },       /* REPORT       */
        { &meth_trace,          &caldav_parse_path },   /* TRACE        */
        { NULL,                 NULL },                 /* UNBIND       */
        { &meth_unlock,         &caldav_params }        /* UNLOCK       */
    }
};


/* Namespace for Freebusy Read URL */
struct namespace_t namespace_freebusy = {
    URL_NS_FREEBUSY, 0, "/freebusy", NULL, 1 /* auth */,
    MBTYPE_CALENDAR,
    ALLOW_READ,
    NULL, NULL, NULL, NULL, NULL,
    {
        { NULL,                 NULL },                 /* ACL          */
        { NULL,                 NULL },                 /* BIND         */
        { NULL,                 NULL },                 /* COPY         */
        { NULL,                 NULL },                 /* DELETE       */
        { &meth_get_head_fb,    NULL },                 /* GET          */
        { &meth_get_head_fb,    NULL },                 /* HEAD         */
        { NULL,                 NULL },                 /* LOCK         */
        { NULL,                 NULL },                 /* MKCALENDAR   */
        { NULL,                 NULL },                 /* MKCOL        */
        { NULL,                 NULL },                 /* MOVE         */
        { &meth_options,        &caldav_parse_path },   /* OPTIONS      */
        { NULL,                 NULL },                 /* PATCH        */
        { NULL,                 NULL },                 /* POST         */
        { NULL,                 NULL },                 /* PROPFIND     */
        { NULL,                 NULL },                 /* PROPPATCH    */
        { NULL,                 NULL },                 /* PUT          */
        { NULL,                 NULL },                 /* REPORT       */
        { &meth_trace,          &caldav_parse_path },   /* TRACE        */
        { NULL,                 NULL },                 /* UNBIND       */
        { NULL,                 NULL }                  /* UNLOCK       */
    }
};


static const struct cal_comp_t {
    const char *name;
    unsigned long type;
} cal_comps[] = {
    { "VEVENT",         CAL_COMP_VEVENT },
    { "VTODO",          CAL_COMP_VTODO },
    { "VJOURNAL",       CAL_COMP_VJOURNAL },
    { "VFREEBUSY",      CAL_COMP_VFREEBUSY },
#ifdef HAVE_VAVAILABILITY
    { "VAVAILABILITY",  CAL_COMP_VAVAILABILITY },
#endif
#ifdef HAVE_VPOLL
    { "VPOLL",          CAL_COMP_VPOLL },
#endif
//    { "VTIMEZONE",    CAL_COMP_VTIMEZONE },
//    { "VALARM",               CAL_COMP_VALARM },
    { NULL, 0 }
};


static void my_caldav_init(struct buf *serverinfo)
{
    const char *domains;
    char *domain;
    tok_t tok;

    buf_printf(serverinfo, " SQLite/%s", sqlite3_libversion());
    buf_printf(serverinfo, " LibiCal/%s", ICAL_VERSION);
#ifdef HAVE_RSCALE
    if ((rscale_calendars = icalrecurrencetype_rscale_supported_calendars())) {
        icalarray_sort(rscale_calendars, &rscale_cmp);

        buf_printf(serverinfo, " ICU4C/%s", U_ICU_VERSION);
    }
#endif
    buf_printf(serverinfo, " Jansson/%s", JANSSON_VERSION);

    namespace_calendar.enabled =
        config_httpmodules & IMAP_ENUM_HTTPMODULES_CALDAV;

    if (!namespace_calendar.enabled) return;

    if (!config_getstring(IMAPOPT_CALENDARPREFIX)) {
        fatal("Required 'calendarprefix' option is not set", EC_CONFIG);
    }

#ifdef HAVE_IANA_PARAMS
    config_allowsched = config_getenum(IMAPOPT_CALDAV_ALLOWSCHEDULING);
    if (config_allowsched) {
        namespace_calendar.allow |= ALLOW_CAL_SCHED;

#ifndef HAVE_SCHEDULING_PARAMS
        /* Need to set this to parse CalDAV Scheduling parameters */
        ical_set_unknown_token_handling_setting(ICAL_ASSUME_IANA_TOKEN);
#endif
    }

    if (config_getswitch(IMAPOPT_CALDAV_ALLOWATTACH))
        namespace_calendar.allow |= ALLOW_CAL_ATTACH;

#endif /* HAVE_IANA_PARAMS */

#ifdef HAVE_TZ_BY_REF
    if (namespace_tzdist.enabled) {
        /* Tell libical to use our builtin TZ */
        /* XXX  MUST be done before any use of libical, e.g caldav_init() */
        char zonedir[MAX_MAILBOX_PATH+1];

        snprintf(zonedir, MAX_MAILBOX_PATH, "%s%s",
                 config_dir, FNAME_ZONEINFODIR);
        set_zone_directory(zonedir);
        icaltimezone_set_tzid_prefix("");
        icaltimezone_set_builtin_tzdata(1);

        namespace_calendar.allow |= ALLOW_CAL_NOTZ;
    }
#endif

    caldav_init();
    webdav_init();

    namespace_principal.enabled = 1;
    /* Apple clients check principal resources for these DAV tokens */
    namespace_principal.allow |= namespace_calendar.allow &
        (ALLOW_CAL | ALLOW_CAL_AVAIL | ALLOW_CAL_SCHED | ALLOW_CAL_ATTACH);

    namespace_freebusy.enabled =
        config_httpmodules & IMAP_ENUM_HTTPMODULES_FREEBUSY;

    compile_time = calc_compile_time(__TIME__, __DATE__);

    buf_printf(&ical_prodid_buf,
               "-//CyrusIMAP.org/Cyrus %s//EN", cyrus_version());
    ical_prodid = buf_cstring(&ical_prodid_buf);

    /* Create an array of calendar-user-adddress-set domains */
    domains = config_getstring(IMAPOPT_CALENDAR_USER_ADDRESS_SET);
    if (!domains) domains = config_defdomain;
    if (!domains) domains = config_servername;

    tok_init(&tok, domains, " \t", TOK_TRIMLEFT|TOK_TRIMRIGHT);
    while ((domain = tok_next(&tok))) appendstrlist(&cua_domains, domain);
    tok_fini(&tok);

    utc_zone = icaltimezone_get_utc_timezone();
}

static int _create_mailbox(const char *userid, const char *mailboxname,
                           int type, int useracl, int anyoneacl,
                           const char *displayname)
{
    int r = 0;
    char rights[100];
    struct mailbox *mailbox = NULL;

    r = mboxlist_lookup(mailboxname, NULL, NULL);
    if (!r) return 0;
    if (r != IMAP_MAILBOX_NONEXISTENT) return r;

    /* Create locally */
    r = mboxlist_createmailbox(mailboxname, type,
                               NULL, 0,
                               userid, httpd_authstate,
                               0, 0, 0, 0, displayname ? &mailbox : NULL);
    if (!r && displayname) {
        annotate_state_t *astate = NULL;

        r = mailbox_get_annotate_state(mailbox, 0, &astate);
        if (!r) {
            const char *annot = DAV_ANNOT_NS "<" XML_NS_DAV ">displayname";
            struct buf value = BUF_INITIALIZER;

            buf_init_ro_cstr(&value, displayname);
            r = annotate_state_writemask(astate, annot, userid, &value);
        }

        mailbox_close(&mailbox);
    }
    if (!r && useracl) {
        cyrus_acl_masktostr(useracl, rights);
        r = mboxlist_setacl(&httpd_namespace, mailboxname, userid, rights,
                            1, httpd_userid, httpd_authstate);
    }
    if (!r && anyoneacl) {
        cyrus_acl_masktostr(anyoneacl, rights);
        r = mboxlist_setacl(&httpd_namespace, mailboxname, "anyone", rights,
                            1, httpd_userid, httpd_authstate);
    }

    if (r) syslog(LOG_ERR, "IOERROR: failed to create %s (%s)",
                  mailboxname, error_message(r));
    return r;
}

int caldav_create_defaultcalendars(const char *userid)
{
    int r;
    char *mailboxname;
    struct buf acl = BUF_INITIALIZER;

    /* calendar-home-set */
    mailboxname = caldav_mboxname(userid, NULL);
    r = mboxlist_lookup(mailboxname, NULL, NULL);
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
            free(mailboxname);
            return r;
        }
        mboxlist_entry_free(&mbentry);

        if (!r) r = _create_mailbox(userid, mailboxname, MBTYPE_CALENDAR,
                                    ACL_ALL | DACL_READFB, DACL_READFB, NULL);
    }

    free(mailboxname);
    if (r) goto done;

    if (config_getswitch(IMAPOPT_CALDAV_CREATE_DEFAULT)) {
        /* Default calendar */
        mailboxname = caldav_mboxname(userid, SCHED_DEFAULT);
        r = _create_mailbox(userid, mailboxname, MBTYPE_CALENDAR,
                            ACL_ALL | DACL_READFB, DACL_READFB, "personal");
        free(mailboxname);
        if (r) goto done;
    }

    if (config_getswitch(IMAPOPT_CALDAV_CREATE_SCHED) &&
        namespace_calendar.allow & ALLOW_CAL_SCHED) {
        /* Scheduling Inbox */
        mailboxname = caldav_mboxname(userid, SCHED_INBOX);
        r = _create_mailbox(userid, mailboxname, MBTYPE_CALENDAR,
                            ACL_ALL | DACL_SCHED, DACL_SCHED, NULL);
        free(mailboxname);
        if (r) goto done;

        /* Scheduling Outbox */
        mailboxname = caldav_mboxname(userid, SCHED_OUTBOX);
        r = _create_mailbox(userid, mailboxname, MBTYPE_CALENDAR,
                            ACL_ALL | DACL_SCHED, 0, NULL);
        free(mailboxname);
        if (r) goto done;
    }

    if (config_getswitch(IMAPOPT_CALDAV_CREATE_ATTACH) &&
        namespace_calendar.allow & ALLOW_CAL_ATTACH) {
        /* Managed Attachment Collection */
        mailboxname = caldav_mboxname(userid, MANAGED_ATTACH);
        r = _create_mailbox(userid, mailboxname, MBTYPE_COLLECTION,
                            ACL_ALL, ACL_READ, NULL);
        free(mailboxname);
        if (r) goto done;
    }

  done:
    buf_free(&acl);
    return r;
}

static void my_caldav_auth(const char *userid)
{
    int r;

    if (httpd_userisadmin ||
        global_authisa(httpd_authstate, IMAPOPT_PROXYSERVERS)) {
        /* admin or proxy from frontend - won't have DAV database */
        return;
    }
    if (config_mupdate_server && !config_getstring(IMAPOPT_PROXYSERVERS)) {
        /* proxy-only server - won't have DAV database */
        return;
    }
    else {
        /* Open CalDAV DB for 'userid' */
        my_caldav_reset();
        auth_caldavdb = caldav_open_userid(userid);
        if (!auth_caldavdb) fatal("Unable to open CalDAV DB", EC_IOERR);
    }

    /* Auto-provision calendars for 'userid' */
    r = caldav_create_defaultcalendars(userid);
    if (r) {
        syslog(LOG_ERR, "could not autoprovision calendars for userid %s: %s",
                userid, error_message(r));
    }
}

static void my_caldav_reset(void)
{
    if (auth_caldavdb) caldav_close(auth_caldavdb);
    auth_caldavdb = NULL;
}

static void my_caldav_shutdown(void)
{
    if (rscale_calendars) icalarray_free(rscale_calendars);
    rscale_calendars = NULL;

    buf_free(&ical_prodid_buf);

    freestrlist(cua_domains);
    cua_domains = NULL;

    my_caldav_reset();
    webdav_done();
    caldav_done();
}


/* Parse request-target path in CalDAV namespace */
static int caldav_parse_path(const char *path,
                             struct request_target_t *tgt, const char **errstr)
{
    int r;

    r = calcarddav_parse_path(path, tgt,
                              config_getstring(IMAPOPT_CALENDARPREFIX),
                              errstr);
    if (r) return r;

    /* Set proper Allow bits based on collection */
    if (tgt->namespace && tgt->namespace->id == URL_NS_FREEBUSY) {
        /* Read-only collections */
        tgt->allow = ALLOW_READ;
    }
    else if (!tgt->collection) {
        /* Allow POST to cal-home-set (share reply) */
        tgt->allow |= ALLOW_POST;
    }
    else if (!strncmp(tgt->collection, MANAGED_ATTACH, strlen(MANAGED_ATTACH))) {
        /* Read-only non-calendar collection */
        tgt->allow = ALLOW_READ;

        tgt->flags = TGT_MANAGED_ATTACH;
    }
    else if (!strncmp(tgt->collection, SCHED_INBOX, strlen(SCHED_INBOX))) {
        /* Can only read and DELETE resources from this collection */
        tgt->allow &= ALLOW_READ_MASK;

        if (tgt->resource) tgt->allow |= ALLOW_DELETE;

        tgt->flags = TGT_SCHED_INBOX;
    }
    else if (!strncmp(tgt->collection, SCHED_OUTBOX, strlen(SCHED_OUTBOX))){
        /* Can only POST to this collection (free/busy request) */
        tgt->allow &= ALLOW_READ_MASK;

        if (!tgt->resource) tgt->allow |= ALLOW_POST;

        tgt->flags = TGT_SCHED_OUTBOX;
    }
    else if (tgt->resource) {
        /* Resource in regular calendar collection (POST for managed attach) */
        tgt->allow |= (namespace_calendar.allow & ALLOW_PATCH) | ALLOW_POST;
    }

    return 0;
}


/* Check headers for any preconditions */
static int caldav_check_precond(struct transaction_t *txn,
                                struct meth_params *params,
                                struct mailbox *mailbox, const void *data,
                                const char *etag, time_t lastmod)
{
    const struct caldav_data *cdata = (const struct caldav_data *) data;
    const char *stag = cdata && cdata->organizer ? cdata->sched_tag : NULL;
    const char **hdr;
    int precond;

    /* Do normal WebDAV/HTTP checks (primarily for lock-token via If header) */
    precond = dav_check_precond(txn, params, mailbox, data, etag, lastmod);
    if (precond == HTTP_PRECOND_FAILED &&
        cdata->comp_flags.tzbyref && !cdata->organizer && cdata->sched_tag) {
        /* Resource has just had VTIMEZONEs stripped -
           check if conditional matches previous ETag */

        precond = check_precond(txn, cdata->sched_tag, lastmod);
    }
    if (!(precond == HTTP_OK || precond == HTTP_PARTIAL)) return precond;

    /* Per RFC 6638, check Schedule-Tag */
    if ((hdr = spool_getheader(txn->req_hdrs, "If-Schedule-Tag-Match"))) {
        /* Special case for Apple 'If-Schedule-Tag-Match:' with no value
         * and also no schedule tag on the record - let that match */
        if (cdata && !stag && !hdr[0][0]) return precond;
        if (etagcmp(hdr[0], stag)) return HTTP_PRECOND_FAILED;
    }

    if (txn->meth == METH_GET || txn->meth == METH_HEAD) {
        /* Fill in Schedule-Tag for successful GET/HEAD */
        txn->resp_body.stag = stag;
    }

    return precond;
}


static int caldav_acl(struct transaction_t *txn, xmlNodePtr priv, int *rights)
{
    if (!xmlStrcmp(priv->ns->href, BAD_CAST XML_NS_CALDAV)) {
        /* CalDAV privileges */
        switch (txn->req_tgt.flags) {
        case TGT_SCHED_INBOX:
            if (!xmlStrcmp(priv->name, BAD_CAST "schedule-deliver"))
                *rights |= DACL_SCHED;
            else if (!xmlStrcmp(priv->name, BAD_CAST "schedule-deliver-invite"))
                *rights |= DACL_INVITE;
            else if (!xmlStrcmp(priv->name, BAD_CAST "schedule-deliver-reply"))
                *rights |= DACL_REPLY;
            else if (!xmlStrcmp(priv->name, BAD_CAST "schedule-query-freebusy"))
                *rights |= DACL_SCHEDFB;
            else {
                /* DAV:not-supported-privilege */
                txn->error.precond = DAV_SUPP_PRIV;
            }
            break;
        case TGT_SCHED_OUTBOX:
            if (!xmlStrcmp(priv->name, BAD_CAST "schedule-send"))
                *rights |= DACL_SCHED;
            else if (!xmlStrcmp(priv->name, BAD_CAST "schedule-send-invite"))
                *rights |= DACL_INVITE;
            else if (!xmlStrcmp(priv->name, BAD_CAST "schedule-send-reply"))
                *rights |= DACL_REPLY;
            else if (!xmlStrcmp(priv->name, BAD_CAST "schedule-send-freebusy"))
                *rights |= DACL_SCHEDFB;
            else {
                /* DAV:not-supported-privilege */
                txn->error.precond = DAV_SUPP_PRIV;
            }
            break;
        default:
            if (!xmlStrcmp(priv->name, BAD_CAST "read-free-busy"))
                *rights |= DACL_READFB;
            else {
                /* DAV:not-supported-privilege */
                txn->error.precond = DAV_SUPP_PRIV;
            }
            break;
        }

        /* Done processing this priv */
        return 1;
    }
    else if (!xmlStrcmp(priv->ns->href, BAD_CAST XML_NS_DAV)) {
        /* WebDAV privileges */
        if (!xmlStrcmp(priv->name, BAD_CAST "all")) {
            switch (txn->req_tgt.flags) {
            case TGT_SCHED_INBOX:
                /* DAV:all aggregates CALDAV:schedule-deliver */
                *rights |= DACL_SCHED;
                break;
            case TGT_SCHED_OUTBOX:
                /* DAV:all aggregates CALDAV:schedule-send */
                *rights |= DACL_SCHED;
                break;
            default:
                /* DAV:all aggregates CALDAV:read-free-busy */
                *rights |= DACL_READFB;
                break;
            }
        }
        else if (!xmlStrcmp(priv->name, BAD_CAST "read")) {
            switch (txn->req_tgt.flags) {
            case TGT_SCHED_INBOX:
            case TGT_SCHED_OUTBOX:
                break;
            default:
                /* DAV:read aggregates CALDAV:read-free-busy */
                *rights |= DACL_READFB;
                break;
            }
        }
    }

    /* Process this priv in meth_acl() */
    return 0;
}

static int _scheduling_enabled(struct transaction_t *txn,
                               const struct mailbox *mailbox)
{
    if (!(namespace_calendar.allow & ALLOW_CAL_SCHED)) return 0;

    const char *entry = DAV_ANNOT_NS "<" XML_NS_CYRUS ">scheduling-enabled";
    struct buf buf = BUF_INITIALIZER;
    int is_enabled = 1;

    annotatemore_lookupmask(mailbox->name, entry, httpd_userid, &buf);
    /* legacy */
    if (!strcasecmp(buf_cstring(&buf), "no"))
        is_enabled = 0;
    if (!strcasecmp(buf_cstring(&buf), "F"))
        is_enabled = 0;

    const char **hdr = spool_getheader(txn->req_hdrs, "Scheduling-Enabled");
    if (hdr && !strcasecmp(hdr[0], "F"))
        is_enabled = 0;

    buf_free(&buf);
    return is_enabled;
}

/* Perform a COPY/MOVE request
 *
 * preconditions:
 *   CALDAV:supported-calendar-data
 *   CALDAV:valid-calendar-data
 *   CALDAV:valid-calendar-object-resource
 *   CALDAV:supported-calendar-component
 *   CALDAV:no-uid-conflict (DAV:href)
 *   CALDAV:calendar-collection-location-ok
 *   CALDAV:max-resource-size
 *   CALDAV:min-date-time
 *   CALDAV:max-date-time
 *   CALDAV:max-instances
 *   CALDAV:max-attendees-per-instance
 */
static int caldav_copy(struct transaction_t *txn, void *obj,
                       struct mailbox *dest_mbox, const char *dest_rsrc,
                       void *destdb, unsigned flags)
{
    int r;
    struct caldav_db *db = (struct caldav_db *)destdb;

    icalcomponent *comp, *ical = (icalcomponent *) obj;
    const char *organizer = NULL;
    icalproperty *prop;

    if (!ical) {
        txn->error.precond = CALDAV_VALID_DATA;
        return HTTP_FORBIDDEN;
    }

    if (_scheduling_enabled(txn, dest_mbox)) {
        comp = icalcomponent_get_first_real_component(ical);
        prop = icalcomponent_get_first_property(comp, ICAL_ORGANIZER_PROPERTY);
        if (prop) organizer = icalproperty_get_organizer(prop);
        if (organizer) flags |= NEW_STAG;
    }

    /* Store source resource at destination */
    /* XXX - set calendar-user-address based on original message? */
    r = caldav_store_resource(txn, ical, dest_mbox, dest_rsrc, db, flags, NULL);

    return r;
}


static void decrement_refcount(const char *managed_id,
                               struct mailbox *attachments,
                               struct webdav_db *webdavdb);
static struct webdav_data *increment_refcount(const char *managed_id,
                                              struct webdav_db *webdavdb);

enum {
    REFCNT_DEC  = -1,
    REFCNT_HOLD = 0,
    REFCNT_INC  = 1
};

static void update_refcount(const char *mid, short *op,
                            struct mailbox *attachments)
{
    switch (*op) {
    case REFCNT_DEC:
        decrement_refcount(mid, attachments, attachments->local_webdav);
        break;

    case REFCNT_INC:
        increment_refcount(mid, attachments->local_webdav);
        break;
    }
}

/* Check an iCal object to see if managed attachments are being manipulated */
static int manage_attachments(struct transaction_t *txn,
                              struct mailbox *mailbox,
                              icalcomponent *ical, struct caldav_data *cdata,
                              icalcomponent **oldical, char **schedule_address)
{
    /* Compare any managed attachments in new and existing resources */
    char *mailboxname = NULL;
    struct mailbox *attachments = NULL;
    struct webdav_db *webdavdb = NULL;
    struct hash_table mattach_table = HASH_TABLE_INITIALIZER;
    icalcomponent *comp = NULL;
    icalcomponent_kind kind;
    icalproperty *prop;
    icalparameter *param;
    const char *mid;
    short *op;
    int r, ret = 0;

    /* Open attachments collection for writing */
    mailboxname = caldav_mboxname(httpd_userid, MANAGED_ATTACH);
    r = mailbox_open_iwl(mailboxname, &attachments);
    if (r) {
        syslog(LOG_ERR, "mailbox_open_iwl(%s) failed: %s",
               mailboxname, error_message(r));
        ret = HTTP_SERVER_ERROR;
    }
    else {
        /* Open the WebDAV DB corresponding to the attachments collection */
        webdavdb = mailbox_open_webdav(attachments);
        if (!webdavdb) {
            syslog(LOG_ERR, "webdav_open_mailbox(%s) failed",
                   attachments->name);
            ret = HTTP_SERVER_ERROR;
        }
    }
    free(mailboxname);

    if (ret) return ret;

    /* Create hash table of managed attachments in new resource */
    construct_hash_table(&mattach_table, 10, 1);

    if (ical) {
        comp = icalcomponent_get_first_real_component(ical);
        kind = icalcomponent_isa(comp);
    }

    for (; comp;
         comp = icalcomponent_get_next_component(ical, kind)) {
            
        for (prop = icalcomponent_get_first_property(comp,
                                                     ICAL_ATTACH_PROPERTY);
             prop;
             prop = icalcomponent_get_next_property(comp,
                                                    ICAL_ATTACH_PROPERTY)) {

            icalattach *attach = icalproperty_get_attach(prop);

            if (icalattach_get_is_url(attach)) {
                struct webdav_data *wdata;

                param = icalproperty_get_managedid_parameter(prop);
                if (!param) continue;

                /* Find DAV record for the attachment with this managed-id */
                mid = icalparameter_get_managedid(param);
                webdav_lookup_uid(webdavdb, mid, &wdata);

                if (!wdata->dav.rowid) {
                    txn->error.precond = CALDAV_VALID_MANAGEDID;
                    ret = HTTP_FORBIDDEN;
                    goto done;
                }

                if (!hash_lookup(mid, &mattach_table)) {
                    /* Assume attachment is being added to ical */
                    op = xmalloc(sizeof(short));
                    *op = REFCNT_INC;
                    hash_insert(mid, op, &mattach_table);
                }
            }
            else {
                /* XXX  Do we want to strip and manage inline attachments? */
            }
        }
    }

    /* Compare existing managed attachments to those in new resource */
    if (cdata->comp_flags.mattach) {
        struct index_record record;

        syslog(LOG_NOTICE, "LOADING ICAL %u", cdata->dav.imap_uid);

        /* Load message containing the resource and parse iCal data */
        r = mailbox_find_index_record(mailbox, cdata->dav.imap_uid, &record);
        if (r) {
            txn->error.desc = "Failed to read record";
            ret = HTTP_SERVER_ERROR;
            goto done;
        }

        *oldical = record_to_ical(mailbox, &record, schedule_address);
        comp = icalcomponent_get_first_real_component(*oldical);
        kind = icalcomponent_isa(comp);

        for (; comp;
             comp = icalcomponent_get_next_component(*oldical, kind)) {
            for (prop = icalcomponent_get_first_property(comp,
                                                         ICAL_ATTACH_PROPERTY);
                 prop;
                 prop = icalcomponent_get_next_property(comp,
                                                        ICAL_ATTACH_PROPERTY)) {

                param = icalproperty_get_managedid_parameter(prop);
                if (!param) continue;

                mid = icalparameter_get_managedid(param);
                op = hash_lookup(mid, &mattach_table);
                if (!op) {
                    /* Attachment removed from ical */
                    op = xmalloc(sizeof(short));
                    *op = REFCNT_DEC;
                    hash_insert(mid, op, &mattach_table);
                }
                else if (*op != REFCNT_DEC) {
                    /* Attachment still in ical */
                    *op = REFCNT_HOLD;
                }
            }
        }
    }

    /* Update reference counts of attachments in hash table */
    hash_enumerate(&mattach_table,
                   (void(*)(const char*,void*,void*)) &update_refcount,
                   attachments);

  done:
    free_hash_table(&mattach_table, free);
    mailbox_close(&attachments);

    return ret;
}


static void get_schedule_addresses(struct transaction_t *txn,
                                   strarray_t *addresses)
{
    struct buf buf = BUF_INITIALIZER;

    /* allow override of schedule-address per-message (FM specific) */
    const char **hdr = spool_getheader(txn->req_hdrs, "Schedule-Address");

    if (hdr) strarray_append(addresses, hdr[0]);
    else {
        /* find schedule address based on the destination calendar's user */

        /* check calendar-user-address-set for target user */
        const char *annotname =
            DAV_ANNOT_NS "<" XML_NS_CALDAV ">calendar-user-address-set";
        char *mailboxname = caldav_mboxname(txn->req_tgt.userid, NULL);
        int r = annotatemore_lookupmask(mailboxname, annotname,
                                        txn->req_tgt.userid, &buf);
        free(mailboxname);
        if (!r && buf.len > 7 &&
            !strncasecmp(buf_cstring(&buf), "mailto:", 7)) {
            strarray_append(addresses, buf_cstring(&buf) + 7);
        }
        else if (strchr(txn->req_tgt.userid, '@')) {
            /* userid corresponding to target */
            strarray_append(addresses, txn->req_tgt.userid);
        }
        else {
            /* append fully qualified userids */
            struct strlist *domains;

            for (domains = cua_domains; domains; domains = domains->next) {
                buf_reset(&buf);
                buf_printf(&buf, "%s@%s", txn->req_tgt.userid, domains->s);

                strarray_appendm(addresses, buf_release(&buf));
            }
        }
    }

    buf_free(&buf);
}


/* Perform scheduling actions for a DELETE request */
static int caldav_delete_cal(struct transaction_t *txn,
                             struct mailbox *mailbox,
                             struct index_record *record, void *data)
{
    struct caldav_data *cdata = (struct caldav_data *) data;
    icalcomponent *ical = NULL;
    struct buf buf = BUF_INITIALIZER;
    char *schedule_address = NULL;
    int r = 0;

    /* Only process deletes on regular calendar collections */
    if (txn->req_tgt.flags) return 0;

    if ((namespace_calendar.allow & ALLOW_CAL_ATTACH) &&
        cdata->comp_flags.mattach) {
        r = manage_attachments(txn, mailbox, NULL,
                               cdata, &ical, &schedule_address);
        if (r) goto done;
    }

    if (cdata->organizer && _scheduling_enabled(txn, mailbox)) {
        /* Scheduling object resource */
        strarray_t schedule_addresses = STRARRAY_INITIALIZER;
        const char **hdr;

        /* XXX - check date range? - don't send in the past */

        /* Load message containing the resource and parse iCal data */
        if (!ical) ical = record_to_ical(mailbox, record, &schedule_address);

        if (!ical) {
            syslog(LOG_ERR,
                   "meth_delete: failed to parse iCalendar object %s:%u",
                   txn->req_tgt.mbentry->name, record->uid);
            return HTTP_SERVER_ERROR;
        }

        if (!schedule_address) {
            get_schedule_addresses(txn, &schedule_addresses);
        }
        else {
            strarray_appendm(&schedule_addresses, schedule_address);
            schedule_address = NULL;
        }

        /* XXX - after legacy records are gone, we can strip this and just not send a
         * cancellation if deleting a record which was never replied to... */

        char *userid = mboxname_to_userid(txn->req_tgt.mbentry->name);
        if (strarray_find_case(&schedule_addresses, cdata->organizer, 0) >= 0) {
            /* Organizer scheduling object resource */
            sched_request(userid, cdata->organizer, ical, NULL);
        }
        else if (!(hdr = spool_getheader(txn->req_hdrs, "Schedule-Reply")) ||
                 strcasecmp(hdr[0], "F")) {
            /* Attendee scheduling object resource */
            sched_reply(userid, strarray_nth(&schedule_addresses, 0), ical, NULL);
        }

        free(userid);
        strarray_fini(&schedule_addresses);
    }

  done:
    if (ical) icalcomponent_free(ical);
    free(schedule_address);
    buf_free(&buf);

    return r;
}

static const char *begin_icalendar(struct buf *buf)
{
    /* Begin iCalendar stream */
    buf_setcstr(buf, "BEGIN:VCALENDAR\r\n");
    buf_printf(buf, "PRODID:%s\r\n", ical_prodid);
    buf_appendcstr(buf, "VERSION:2.0\r\n");

    return "";
}

static void end_icalendar(struct buf *buf)
{
    /* End iCalendar stream */
    buf_setcstr(buf, "END:VCALENDAR\r\n");
}

static int export_calendar(struct transaction_t *txn)
{
    int ret = 0, r, precond;
    struct resp_body_t *resp_body = &txn->resp_body;
    struct buf *buf = &resp_body->payload;
    struct mailbox *mailbox = NULL;
    static char etag[33];
    struct hash_table tzid_table;
    static const char *displayname_annot =
        DAV_ANNOT_NS "<" XML_NS_DAV ">displayname";
    struct buf attrib = BUF_INITIALIZER;
    const char **hdr, *sep;
    struct mime_type_t *mime = NULL;

    /* Check requested MIME type:
       1st entry in caldav_mime_types array MUST be default MIME type */
    if ((hdr = spool_getheader(txn->req_hdrs, "Accept")))
        mime = get_accept_type(hdr, caldav_mime_types);
    else mime = caldav_mime_types;
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

        if (precond != HTTP_NOT_MODIFIED) break;

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
    r = annotatemore_lookupmask(mailbox->name, displayname_annot,
                                httpd_userid, &attrib);
    /* fall back to last part of mailbox name */
    if (r || !attrib.len) buf_setcstr(&attrib, strrchr(mailbox->name, '.') + 1);

    buf_reset(&txn->buf);
    buf_printf(&txn->buf, "%s.%s", buf_cstring(&attrib), mime->file_ext);
    txn->resp_body.fname = buf_cstring(&txn->buf);

    /* Short-circuit for HEAD request */
    if (txn->meth == METH_HEAD) {
        response_header(HTTP_OK, txn);
        return 0;
    }

    /* iCalendar data in response should not be transformed */
    txn->flags.cc |= CC_NOTRANSFORM;

    /* Create hash table for TZIDs */
    construct_hash_table(&tzid_table, 10, 1);

    /* Begin (converted) iCalendar stream */
    sep = mime->begin_stream(buf);
    write_body(HTTP_OK, txn, buf_cstring(buf), buf_len(buf));

    struct mailbox_iter *iter =
        mailbox_iter_init(mailbox, 0, ITER_SKIP_EXPUNGED|ITER_SKIP_DELETED);

    const message_t *msg;
    while ((msg = mailbox_iter_step(iter))) {
        const struct index_record *record = msg_record(msg);
        icalcomponent *ical;

        /* Map and parse existing iCalendar resource */
        ical = record_to_ical(mailbox, record, NULL);

        if (ical) {
            icalcomponent *comp;

            for (comp = icalcomponent_get_first_component(ical,
                                                          ICAL_ANY_COMPONENT);
                 comp;
                 comp = icalcomponent_get_next_component(ical,
                                                         ICAL_ANY_COMPONENT)) {
                struct buf *cal_str;
                icalcomponent_kind kind = icalcomponent_isa(comp);

                /* Don't duplicate any TZIDs in our iCalendar */
                if (kind == ICAL_VTIMEZONE_COMPONENT) {
                    icalproperty *prop =
                        icalcomponent_get_first_property(comp,
                                                         ICAL_TZID_PROPERTY);
                    const char *tzid = icalproperty_get_tzid(prop);

                    if (hash_lookup(tzid, &tzid_table)) continue;
                    else hash_insert(tzid, (void *)0xDEADBEEF, &tzid_table);
                }

                /* Include this component in our iCalendar */
                if (r++ && *sep) {
                    /* Add separator, if necessary */
                    buf_reset(buf);
                    buf_printf_markup(buf, 0, sep);
                    write_body(0, txn, buf_cstring(buf), buf_len(buf));
                }
                cal_str = mime->from_object(comp);
                write_body(0, txn, buf_base(cal_str), buf_len(cal_str));
                buf_destroy(cal_str);
            }

            icalcomponent_free(ical);
        }
    }

    mailbox_iter_done(&iter);

    free_hash_table(&tzid_table, NULL);

    /* End (converted) iCalendar stream */
    mime->end_stream(buf);
    write_body(0, txn, buf_cstring(buf), buf_len(buf));

    /* End of output */
    write_body(0, txn, NULL, 0);

  done:
    buf_free(&attrib);
    mailbox_close(&mailbox);

    return ret;
}


/*
 * mboxlist_findall() callback function to list calendars
 */

struct cal_info {
    char shortname[MAX_MAILBOX_NAME];
    char displayname[MAX_MAILBOX_NAME];
    unsigned flags;
    unsigned long types;
};

enum {
    CAL_IS_DEFAULT =    (1<<0),
    CAL_CAN_DELETE =    (1<<1),
    CAL_CAN_ADMIN =     (1<<2),
    CAL_IS_PUBLIC =     (1<<3),
    CAL_IS_TRANSP =     (1<<4)
};

struct list_cal_rock {
    struct cal_info *cal;
    unsigned len;
    unsigned alloc;
};

static int list_cal_cb(const mbentry_t *mbentry, void *rock)
{
    struct list_cal_rock *lrock = (struct list_cal_rock *) rock;
    struct cal_info *cal;
    static size_t inboxlen = 0;
    static size_t outboxlen = 0;
    static size_t defaultlen = 0;
    char *shortname;
    size_t len;
    int r, rights, any_rights = 0;
    static const char *displayname_annot =
        DAV_ANNOT_NS "<" XML_NS_DAV ">displayname";
    static const char *schedtransp_annot =
        DAV_ANNOT_NS "<" XML_NS_CALDAV ">schedule-calendar-transp";
    static const char *calcompset_annot =
        DAV_ANNOT_NS "<" XML_NS_CALDAV ">supported-calendar-component-set";
    struct buf displayname = BUF_INITIALIZER, schedtransp = BUF_INITIALIZER;
    struct buf calcompset = BUF_INITIALIZER;

    if (!inboxlen) inboxlen = strlen(SCHED_INBOX) - 1;
    if (!outboxlen) outboxlen = strlen(SCHED_OUTBOX) - 1;
    if (!defaultlen) defaultlen = strlen(SCHED_DEFAULT) - 1;

    /* Make sure its a calendar */
    if (mbentry->mbtype != MBTYPE_CALENDAR) goto done;

    /* Make sure its readable */
    rights = httpd_myrights(httpd_authstate, mbentry);
    if ((rights & DACL_READ) != DACL_READ) goto done;

    /* Don't list scheduling Inbox/Outbox */
    shortname = strrchr(mbentry->name, '.') + 1;
    len = strlen(shortname);

    if ((len == inboxlen && !strncmp(shortname, SCHED_INBOX, inboxlen)) ||
        (len == outboxlen && !strncmp(shortname, SCHED_OUTBOX, outboxlen)))
        goto done;

    /* Lookup DAV:displayname */
    r = annotatemore_lookupmask(mbentry->name, displayname_annot,
                                httpd_userid, &displayname);
    /* fall back to the last part of the mailbox name */
    if (r || !displayname.len) buf_setcstr(&displayname, shortname);

    /* Make sure we have room in our array */
    if (lrock->len == lrock->alloc) {
        lrock->alloc += 100;
        lrock->cal = xrealloc(lrock->cal,
                              lrock->alloc * sizeof(struct cal_info));
    }

    /* Add our calendar to the array */
    cal = &lrock->cal[lrock->len];
    strlcpy(cal->shortname, shortname, MAX_MAILBOX_NAME);
    strlcpy(cal->displayname, buf_cstring(&displayname), MAX_MAILBOX_NAME);
    cal->flags = 0;

    /* Is this the default calendar? */
    if (len == defaultlen && !strncmp(shortname, SCHED_DEFAULT, defaultlen)) {
        cal->flags |= CAL_IS_DEFAULT;
    }

    /* Can we delete this calendar? */
    else if (rights & DACL_RMCOL) {
        cal->flags |= CAL_CAN_DELETE;
    }

    /* Can we admin this calendar? */
    if (rights & DACL_ADMIN) {
        cal->flags |= CAL_CAN_ADMIN;
    }

    /* Is this calendar public? */
    if (mbentry->acl) {
        struct auth_state *auth_anyone = auth_newstate("anyone");

        any_rights = cyrus_acl_myrights(auth_anyone, mbentry->acl);
        auth_freestate(auth_anyone);
    }
    if ((any_rights & DACL_READ) == DACL_READ) {
        cal->flags |= CAL_IS_PUBLIC;
    }

    /* Is this calendar transparent? */
    r = annotatemore_lookupmask(mbentry->name, schedtransp_annot,
                                httpd_userid, &schedtransp);
    if (!r && !strcmp(buf_cstring(&schedtransp), "transparent")) {
        cal->flags |= CAL_IS_TRANSP;
    }
    buf_free(&schedtransp);

    /* Which component types are supported? */
    r = annotatemore_lookupmask(mbentry->name, calcompset_annot,
                                httpd_userid, &calcompset);
    if (!r && buf_len(&calcompset)) {
        cal->types = strtoul(buf_cstring(&calcompset), NULL, 10);
    }
    else {
        /* ALL component types */
        cal->types = -1;
    }
    buf_free(&calcompset);

    lrock->len++;

done:
    buf_free(&displayname);

    return 0;
}

static int cal_compare(const void *a, const void *b)
{
    struct cal_info *c1 = (struct cal_info *) a;
    struct cal_info *c2 = (struct cal_info *) b;

    return strcmp(c1->displayname, c2->displayname);
}


struct list_tzid_rock {
    struct buf *body;
    unsigned *level;
};

int list_tzid_cb(const char *tzid,
                 int tzidlen __attribute__((unused)),
                 struct zoneinfo *zi __attribute__((unused)),
                 void *rock)
{
    struct list_tzid_rock *tzrock = (struct list_tzid_rock *) rock;

    /* Skip Etc and other non-standard zones */
    if (strnchr(tzid, '/', tzidlen) && strncmp(tzid, "Etc/", 4)) {
        buf_printf_markup(tzrock->body, *tzrock->level,
                          "<option>%.*s</option>", tzidlen, tzid);
    }

    return 0;
}


/* Create a HTML document listing all calendars available to the user */
static int list_calendars(struct transaction_t *txn)
{
    int ret = 0, precond, rights;
    char mboxlist[MAX_MAILBOX_PATH+1];
    struct stat sbuf;
    time_t lastmod;
    const char *etag, *base_path = txn->req_tgt.path;
    unsigned level = 0, i;
    struct buf *body = &txn->resp_body.payload;
    struct list_cal_rock lrock;
    const char *proto = NULL;
    const char *host = NULL;
    const struct cal_comp_t *comp;
#include "imap/http_caldav_js.h"

    /* stat() mailboxes.db for Last-Modified and ETag */
    snprintf(mboxlist, MAX_MAILBOX_PATH, "%s%s", config_dir, FNAME_MBOXLIST);
    stat(mboxlist, &sbuf);
    lastmod = MAX(compile_time, sbuf.st_mtime);
    assert(!buf_len(&txn->buf));
    buf_printf(&txn->buf, "%ld-%ld-%ld",
               compile_time, sbuf.st_mtime, sbuf.st_size);

    /* stat() config file for Last-Modified and ETag */
    stat(config_filename, &sbuf);
    lastmod = MAX(lastmod, sbuf.st_mtime);
    buf_printf(&txn->buf, "-%ld-%ld", sbuf.st_mtime, sbuf.st_size);
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
    buf_printf_markup(body, level, "<title>%s</title>", "Available Calendars");
    buf_printf_markup(body, level++, "<script type=\"text/javascript\">");
    buf_appendcstr(body, "//<![CDATA[\n");
    buf_printf(body, (const char *) http_caldav_js,
               cyrus_version(), http_caldav_js_len);
    buf_appendcstr(body, "//]]>\n");
    buf_printf_markup(body, --level, "</script>");
    buf_printf_markup(body, level++, "<noscript>");
    buf_printf_markup(body, level, "<i>*** %s ***</i>",
                      "JavaScript required to create/modify/delete calendars");
    buf_printf_markup(body, --level, "</noscript>");
    buf_printf_markup(body, --level, "</head>");
    buf_printf_markup(body, level++, "<body>");

    write_body(HTTP_OK, txn, buf_cstring(body), buf_len(body));
    buf_reset(body);

    /* Check ACL for current user */
    rights = httpd_myrights(httpd_authstate, txn->req_tgt.mbentry);

    if (rights & DACL_MKCOL) {
        /* Add "create" form */
        struct list_tzid_rock tzrock = { body, &level };

        buf_printf_markup(body, level, "<h2>%s</h2>", "Create New Calendar");
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
        buf_printf_markup(body, level, "<td align=right>Components:</td>");
        buf_printf_markup(body, level++, "<td>");
        for (comp = cal_comps; comp->name; comp++) {
            buf_printf_markup(body, level,
                              "<input type=checkbox%s name=comp value=%s>%s",
                              !strcmp(comp->name, "VEVENT") ? " checked" : "",
                              comp->name, comp->name);
        }
        buf_printf_markup(body, --level, "</td>");
        buf_printf_markup(body, --level, "</tr>");

        if (namespace_calendar.allow & ALLOW_CAL_NOTZ) {
            buf_printf_markup(body, level++, "<tr>");
            buf_printf_markup(body, level, "<td align=right>Time Zone:</td>");
            buf_printf_markup(body, level++, "<td>");
            buf_printf_markup(body, level++, "<select name=tzid>");
            buf_printf_markup(body, level, "<option></option>");
            zoneinfo_find(NULL, 1, 0, &list_tzid_cb, &tzrock);
            buf_printf_markup(body, --level, "</select>");
            buf_printf_markup(body, --level, "</td>");
            buf_printf_markup(body, --level, "</tr>");
        }

        buf_printf_markup(body, level++, "<tr>");
        buf_printf_markup(body, level, "<td></td>");
        buf_printf_markup(body, level,
                          "<td><br><input type=button value='Create'"
                          " onclick=\"createCalendar('%s')\">"
                          " <input type=reset></td>",
                          base_path);
        buf_printf_markup(body, --level, "</tr>");

        buf_printf_markup(body, --level, "</table>");
        buf_printf_markup(body, --level, "</form>");

        buf_printf_markup(body, level, "<br><hr><br>");

        write_body(0, txn, buf_cstring(body), buf_len(body));
        buf_reset(body);
    }

    buf_printf_markup(body, level, "<h2>%s</h2>", "Available Calendars");
    buf_printf_markup(body, level++, "<table border cellpadding=5>");

    /* Create base URL for calendars */
    http_proto_host(txn->req_hdrs, &proto, &host);
    buf_reset(&txn->buf);
    buf_printf(&txn->buf, "%s://%s%s", proto, host, txn->req_tgt.path);

    memset(&lrock, 0, sizeof(struct list_cal_rock));
    mboxlist_mboxtree(txn->req_tgt.mbentry->name,
                      list_cal_cb, &lrock, MBOXTREE_SKIP_ROOT);

    /* Sort calendars by displayname */
    qsort(lrock.cal, lrock.len, sizeof(struct cal_info), &cal_compare);

    /* Add available calendars with action items */
    for (i = 0; i < lrock.len; i++) {
        struct cal_info *cal = &lrock.cal[i];

        /* Send a body chunk once in a while */
        if (buf_len(body) > PROT_BUFSIZE) {
            write_body(0, txn, buf_cstring(body), buf_len(body));
            buf_reset(body);
        }

        /* Calendar name */
        buf_printf_markup(body, level++, "<tr>");
        buf_printf_markup(body, level, "<td>%s%s%s",
                          (cal->flags & CAL_IS_DEFAULT) ? "<b>" : "",
                          cal->displayname,
                          (cal->flags & CAL_IS_DEFAULT) ? "</b>" : "");

        /* Supported components list */
        buf_printf_markup(body, level++, "<td>");
        buf_printf_markup(body, level++,
                          "<select multiple name=comp size=3"
                          " onChange=\"compsetCalendar('%s%s', '%s', this.options)\">",
                          base_path, cal->shortname, cal->displayname);
        for (comp = cal_comps; comp->name; comp++) {
            buf_printf_markup(body, level, "<option%s>%s</option>",
                              (cal->types & comp->type) ? " selected" : "",
                              comp->name);
        }
        buf_printf_markup(body, --level, "</select>");
        buf_printf_markup(body, --level, "</td>");

        /* Subscribe link */
        buf_printf_markup(body, level,
                          "<td><a href=\"webcal://%s%s%s\">Subscribe</a></td>",
                          host, base_path, cal->shortname);

        /* Download link */
        buf_printf_markup(body, level, "<td><a href=\"%s%s\">Download</a></td>",
                          base_path, cal->shortname);

        /* Delete button */
        buf_printf_markup(body, level,
                          "<td><input type=button%s value='Delete'"
                          " onclick=\"deleteCalendar('%s%s', '%s')\"></td>",
                          !(cal->flags & CAL_CAN_DELETE) ? " disabled" : "",
                          base_path, cal->shortname, cal->displayname);

        /* Public (shared) checkbox */
        buf_printf_markup(body, level,
                          "<td><input type=checkbox%s%s name=share"
                          " onclick=\"shareCalendar('%s%s', this.checked)\">"
                          "Public</td>",
                          !(cal->flags & CAL_CAN_ADMIN) ? " disabled" : "",
                          (cal->flags & CAL_IS_PUBLIC) ? " checked" : "",
                          base_path, cal->shortname);

        /* Transparent checkbox */
        buf_printf_markup(body, level,
                          "<td><input type=checkbox%s%s name=transp"
                          " onclick=\"transpCalendar('%s%s', this.checked)\">"
                          "Transparent</td>",
                          !(cal->flags & CAL_CAN_ADMIN) ? " disabled" : "",
                          (cal->flags & CAL_IS_TRANSP) ? " checked" : "",
                          base_path, cal->shortname);

        buf_printf_markup(body, --level, "</tr>");
    }

    free(lrock.cal);

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


/* Parse an RFC3339 date/time per
   http://www.calconnect.org/pubdocs/CD0903%20Freebusy%20Read%20URL.pdf */
static struct icaltimetype icaltime_from_rfc3339_string(const char *str)
{
    struct icaltimetype tt = icaltime_null_time();
    size_t size;

    size = strlen(str);

    if (size == 20) {
        /* UTC */
        if (sscanf(str, "%4u-%02u-%02uT%02u:%02u:%02uZ",
                   &tt.year, &tt.month, &tt.day,
                   &tt.hour, &tt.minute, &tt.second) < 6) {
            goto fail;
        }

        tt = icaltime_normalize(tt);
    }
    else if (size == 25) {
        /* TZ offset */
        int offset_hour, offset_minute;
        char offset_sign;

        if (sscanf(str, "%4u-%02u-%02uT%02u:%02u:%02u%c%02u:%02u",
                   &tt.year, &tt.month, &tt.day,
                   &tt.hour, &tt.minute, &tt.second,
                   &offset_sign, &offset_hour, &offset_minute) < 9) {
            goto fail;
        }

        if (offset_sign == '-') {
            /* negative offset */
            offset_hour *= -1;
            offset_minute *= -1;
        }
        else if (offset_sign != '+') {
            goto fail;
        }

        icaltime_adjust(&tt, 0, -offset_hour, -offset_minute, 0);
    }
    else {
        goto fail;
    }

    tt.is_utc = 1;
    return tt;

  fail:
    return icaltime_null_time();
}


struct timezone_rock {
    icalcomponent *old;
    icalcomponent *new;
};

static void add_timezone(icalparameter *param, void *data)
{
    struct timezone_rock *tzrock = (struct timezone_rock *) data;
    const char *tzid = icalparameter_get_tzid(param);

    /* Check if this tz is in our new object */
    if (!icalcomponent_get_timezone(tzrock->new, tzid)) {
        icalcomponent *vtz = NULL;

        if (tzrock->old) {
            /* Fetch tz from old object and add to new */
            icaltimezone *tz = icalcomponent_get_timezone(tzrock->old, tzid);
            if (tz) vtz = icalcomponent_new_clone(icaltimezone_get_component(tz));
        }
        else {
            /* Fetch tz from our tzdist repository */
            struct buf buf = BUF_INITIALIZER;
            const char *path;
            int fd;

            /* Open and mmap the timezone file */
            buf_printf(&buf, "%s%s/%s.ics", config_dir, FNAME_ZONEINFODIR, tzid);
            path = buf_cstring(&buf);

            if ((fd = open(path, O_RDONLY)) != -1) {
                struct buf data = BUF_INITIALIZER;
                icalcomponent *ical;

                buf_init_mmap(&data, 1, fd, path, MAP_UNKNOWN_LEN, NULL);
                ical = ical_string_as_icalcomponent(&data);
                vtz = icalcomponent_get_first_component(ical,
                                                        ICAL_VTIMEZONE_COMPONENT);
                icalcomponent_remove_component(ical, vtz);
                icalcomponent_free(ical);
                buf_free(&data);
                close(fd);
            }
            buf_free(&buf);
        }

        if (vtz) icalcomponent_add_component(tzrock->new, vtz);
    }
}


/* Perform a GET/HEAD request on a CalDAV resource */
static int caldav_get(struct transaction_t *txn, struct mailbox *mailbox,
                      struct index_record *record, void *data, void **obj)
{
    int r, rights;

    if (!(txn->req_tgt.collection || txn->req_tgt.userid))
        return HTTP_NO_CONTENT;

    /* Check ACL for current user */
    rights = httpd_myrights(httpd_authstate, txn->req_tgt.mbentry);
    if ((rights & DACL_READ) != DACL_READ) {
        /* DAV:need-privileges */
        txn->error.precond = DAV_NEED_PRIVS;
        txn->error.resource = txn->req_tgt.path;
        txn->error.rights = DACL_READ;
        return HTTP_NO_PRIVS;
    }

    if (record && record->uid) {
        /* GET on a resource */
        struct caldav_data *cdata = (struct caldav_data *) data;
        unsigned need_tz = 0;
        const char **hdr;
        icalcomponent *ical;
        int ret = HTTP_CONTINUE;

        /* Check for optional CalDAV-Timezones header */
        hdr = spool_getheader(txn->req_hdrs, "CalDAV-Timezones");
        if (hdr && !strcmp(hdr[0], "T")) need_tz = 1;

        if (cdata->comp_flags.tzbyref) {
            if (!cdata->organizer && cdata->sched_tag) {
                /* Resource has just had VTIMEZONEs stripped -
                   check if conditional matches previous ETag */

                if (check_precond(txn, cdata->sched_tag,
                                  record->internaldate) == HTTP_NOT_MODIFIED) {
                    /* Fill in previous ETag and don't return Last-Modified */
                    txn->resp_body.etag = cdata->sched_tag;
                    txn->resp_body.lastmod = 0;
                    ret = HTTP_NOT_MODIFIED;
                }
            }
            if (need_tz) {
                /* Add VTIMEZONE components for known TZIDs */
                struct timezone_rock tzrock = { NULL, NULL };
                icalcomponent *comp, *next;
                icalcomponent_kind kind;

                *obj = ical = record_to_ical(mailbox, record, NULL);
                tzrock.new = ical;

                comp = icalcomponent_get_first_real_component(ical);
                kind = icalcomponent_isa(comp);
                for (; comp; comp = next) {
                    next = icalcomponent_get_next_component(ical, kind);
                    icalcomponent_foreach_tzid(comp, &add_timezone, &tzrock);
                }
            }
        }
        else if (!need_tz && (namespace_calendar.allow & ALLOW_CAL_NOTZ)) {
            /* Strip known VTIMEZONEs */
            struct caldav_db *caldavdb = caldav_open_mailbox(mailbox);
            char *userid = NULL;

            mailbox_unlock_index(mailbox, NULL);
            r = mailbox_lock_index(mailbox, LOCK_EXCLUSIVE);
            if (r) {
                syslog(LOG_ERR, "relock index(%s) failed: %s",
                       mailbox->name, error_message(r));
                goto done;
            }

            *obj = ical = record_to_ical(mailbox, record, &userid);

            caldav_store_resource(txn, ical, mailbox,
                                  cdata->dav.resource, caldavdb,
                                  TZ_STRIP | (!cdata->sched_tag ? NEW_STAG : 0),
                                  userid);
            free(userid);

            /* Fetch the new DAV and index records */
            /* NOTE: previous contents of cdata was freed by store_resource */
            caldav_lookup_resource(caldavdb, mailbox->name,
                                   txn->req_tgt.resource, &cdata, /*tombstones*/0);

            mailbox_find_index_record(mailbox, cdata->dav.imap_uid, record);

            /* Fill in new ETag and Last-Modified */
            txn->resp_body.etag = message_guid_encode(&record->guid);
            txn->resp_body.lastmod = record->internaldate;

            caldav_close(caldavdb);
        }

        /* iCalendar data in response should not be transformed */
        txn->flags.cc |= CC_NOTRANSFORM;

      done:
        return ret;
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
        /* Download an entire calendar collection */
        return export_calendar(txn);
    }
    else if (txn->req_tgt.userid) {
        /* GET a list of calendars under calendar-home-set */
        return list_calendars(txn);
    }

    /* Unknown action */
    return HTTP_NO_CONTENT;
}


/* Perform a GET/HEAD request on a CalDAV/M-Attach resource */
static int meth_get_head_cal(struct transaction_t *txn,
                             void *gparams __attribute__((unused)))
{
    int r;

    /* Parse the path */
    if ((r = caldav_parse_path(txn->req_uri->path,
                               &txn->req_tgt, &txn->error.desc))) return r;

    return meth_get_head(txn, (txn->req_tgt.flags == TGT_MANAGED_ATTACH) ?
                         &webdav_params : &caldav_params);
}

/* Decrement reference count on a managed attachment resource */
static void decrement_refcount(const char *managed_id,
                               struct mailbox *attachments,
                               struct webdav_db *webdavdb)
{
    int r;
    struct webdav_data *wdata;

    /* Find DAV record for the attachment with this managed-id */
    webdav_lookup_uid(webdavdb, managed_id, &wdata);

    if (!wdata->dav.rowid) return;

    if (!--wdata->ref_count) {
        /* Delete attachment resource */
        struct index_record record;

        mailbox_find_index_record(attachments, wdata->dav.imap_uid, &record);
        record.system_flags |= FLAG_EXPUNGED;

        r = mailbox_rewrite_index_record(attachments, &record);

        if (r) {
            syslog(LOG_ERR, "expunging record (%s) failed: %s",
                   attachments->name, error_message(r));
        }
    }
    else {
        /* Update reference count on WebDAV record */
        r = webdav_write(webdavdb, wdata);

        if (r) {
            syslog(LOG_ERR, "updating ref count (%s) failed: %s",
                   wdata->dav.resource, error_message(r));
        }
    }
}

/* Increment reference count on a managed attachment resource */
static struct webdav_data *increment_refcount(const char *managed_id,
                                              struct webdav_db *webdavdb)
{
    int r;
    struct webdav_data *wdata;

    /* Find DAV record for the attachment with this managed-id */
    webdav_lookup_uid(webdavdb, managed_id, &wdata);

    if (wdata->dav.rowid) {
        /* Update reference count on WebDAV record */
        wdata->ref_count++;
        r = webdav_write(webdavdb, wdata);

        if (r) {
            syslog(LOG_ERR, "updating ref count (%s) failed: %s",
                   wdata->dav.resource, error_message(r));
        }
    }

    return wdata;
}

/* Manage attachment */
static int caldav_post_attach(struct transaction_t *txn, int rights)
{
    int ret = 0, r, precond;
    struct resp_body_t *resp_body = &txn->resp_body;
    struct strlist *action, *mid, *rid;
    struct mime_type_t *mime = NULL;
    struct mailbox *calendar = NULL, *attachments = NULL;
    struct caldav_db *caldavdb = NULL;
    struct caldav_data *cdata;
    struct webdav_db *webdavdb = NULL;
    struct webdav_data *wdata;
    struct index_record record;
    char *schedule_address = NULL;
    const char *etag = NULL, **hdr;
    char *mailboxname = NULL;
    time_t lastmod = 0;
    icalcomponent *ical = NULL, *comp, *nextc, *master = NULL;
    icalcomponent_kind kind;
    icalproperty *aprop = NULL, *prop;
    icalparameter *param;
    unsigned op, return_rep;
    strarray_t *rids = NULL;
    enum {
        ATTACH_ADD,
        ATTACH_UPDATE,
        ATTACH_REMOVE
    };

    if (!(namespace_calendar.allow & ALLOW_CAL_ATTACH)) return HTTP_NOT_ALLOWED;

    /* Check ACL for current user */
    if (!(rights & DACL_WRITECONT)) {
        /* DAV:need-privileges */
        txn->error.precond = DAV_NEED_PRIVS;
        txn->error.resource = txn->req_tgt.path;
        txn->error.rights = DACL_WRITECONT;
        return HTTP_NO_PRIVS;
    }

    if ((return_rep = (get_preferences(txn) & PREFER_REP))) {
        /* Check requested MIME type:
           1st entry in gparams->mime_types array MUST be default MIME type */
        if ((hdr = spool_getheader(txn->req_hdrs, "Accept")))
            mime = get_accept_type(hdr, caldav_mime_types);
        else mime = caldav_mime_types;
        if (!mime) return HTTP_NOT_ACCEPTABLE;
    }

    /* Fetch and sanity check parameters */
    action = hash_lookup("action", &txn->req_qparams);
    mid = hash_lookup("managed-id", &txn->req_qparams);
    rid = hash_lookup("rid", &txn->req_qparams);

    if (!action || action->next) return HTTP_BAD_REQUEST;
    else if (!strcmp(action->s, "attachment-add")) {
        op = ATTACH_ADD;
        if (mid) return HTTP_BAD_REQUEST;
    }
    else if (!strcmp(action->s, "attachment-update")) {
        op = ATTACH_UPDATE;
        if (rid || !mid || mid->next) return HTTP_BAD_REQUEST;
    }
    else if (!strcmp(action->s, "attachment-remove")) {
        op = ATTACH_REMOVE;
        if (!mid || mid->next) return HTTP_BAD_REQUEST;
    }
    else return HTTP_BAD_REQUEST;

    /* Open calendar for writing */
    r = mailbox_open_iwl(txn->req_tgt.mbentry->name, &calendar);
    if (r) {
        syslog(LOG_ERR, "mailbox_open_iwl(%s) failed: %s",
               txn->req_tgt.mbentry->name, error_message(r));
        txn->error.desc = error_message(r);
        ret = HTTP_SERVER_ERROR;
        goto done;
    }

    /* Open the CalDAV DB corresponding to the calendar */
    caldavdb = caldav_open_mailbox(calendar);

    /* Find message UID for the cal resource */
    caldav_lookup_resource(caldavdb, txn->req_tgt.mbentry->name,
                           txn->req_tgt.resource, &cdata, 0);
    if (!cdata->dav.rowid) ret = HTTP_NOT_FOUND;
    else if (!cdata->dav.imap_uid) ret = HTTP_CONFLICT;
    if (ret) goto done;

    /* Fetch index record for the cal resource */
    memset(&record, 0, sizeof(struct index_record));
    r = mailbox_find_index_record(calendar, cdata->dav.imap_uid, &record);
    if (r) {
        txn->error.desc = error_message(r);
        ret = HTTP_SERVER_ERROR;
        goto done;
    }

    etag = message_guid_encode(&record.guid);
    lastmod = record.internaldate;

    /* Load and parse message containing the resource */
    ical = record_to_ical(calendar, &record, &schedule_address);
    comp = icalcomponent_get_first_real_component(ical);
    kind = icalcomponent_isa(comp);

    /* Check any preconditions */
    precond = caldav_check_precond(txn, &caldav_params,
                                   calendar, cdata, etag, lastmod);

    switch (precond) {
    case HTTP_OK:
        break;

    case HTTP_LOCKED:
        txn->error.precond = DAV_NEED_LOCK_TOKEN;
        txn->error.resource = txn->req_tgt.path;

    default:
        /* We failed a precondition - don't perform the request */
        ret = precond;

        if ((precond == HTTP_PRECOND_FAILED) && return_rep) goto return_rep;
        else goto done;
    }

    /* Open attachments collection for writing */
    mailboxname = caldav_mboxname(httpd_userid, MANAGED_ATTACH);
    r = mailbox_open_iwl(mailboxname, &attachments);
    if (r) {
        syslog(LOG_ERR, "mailbox_open_iwl(%s) failed: %s",
               mailboxname, error_message(r));
        txn->error.desc = error_message(r);
        ret = HTTP_SERVER_ERROR;
        free(mailboxname);
        goto done;
    }
    free(mailboxname);

    /* Open the WebDAV DB corresponding to the attachments collection */
    webdavdb = webdav_open_mailbox(attachments);

    if (mid) {
        /* Locate first ATTACH property with this MANAGED-ID */
        do {
            for (aprop = icalcomponent_get_first_property(comp,
                                                          ICAL_ATTACH_PROPERTY);
                 aprop;
                 aprop = icalcomponent_get_next_property(comp,
                                                         ICAL_ATTACH_PROPERTY)) {
                param = icalproperty_get_managedid_parameter(aprop);
                if (param &&
                    !strcmp(mid->s, icalparameter_get_managedid(param))) break;
            }

            /* Check if this is master component */
            if (rid && !master &&
                !icalcomponent_get_first_property(comp,
                                                  ICAL_RECURRENCEID_PROPERTY)) {
                master = comp;
            }

        } while (!aprop &&
                 (comp = icalcomponent_get_next_component(ical, kind)));

        if (!aprop) {
            txn->error.precond = CALDAV_VALID_MANAGEDID;
            ret = HTTP_BAD_REQUEST;
            goto done;
        }

        /* Update reference count */
        decrement_refcount(mid->s, attachments, webdavdb);
    }

    if (op == ATTACH_REMOVE) aprop = NULL;
    else {
        /* SHA1 of content used as resource UID, resource name, & managed-id */
        static char uid[2*MESSAGE_GUID_SIZE+1];
        struct message_guid guid;

        /* Read body */
        txn->req_body.flags |= BODY_DECODE;
        r = http_read_body(httpd_in, httpd_out,
                           txn->req_hdrs, &txn->req_body, &txn->error.desc);
        if (r) {
            txn->flags.conn = CONN_CLOSE;
            return r;
        }

        /* Make sure we have a body */
        if (!buf_len(&txn->req_body.payload)) {
            txn->error.desc = "Missing request body";
            ret = HTTP_BAD_REQUEST;
            goto done;
        }

        /* Generate UID of body content */
        message_guid_generate(&guid, buf_base(&txn->req_body.payload),
                              buf_len(&txn->req_body.payload));
        strcpy(uid, message_guid_encode(&guid));

        /* Store the new/updated attachment using WebDAV callback */
        ret = webdav_params.put.proc(txn, &txn->req_body.payload,
                                     attachments, uid, webdavdb, 0);

        switch (ret) {
        case HTTP_CREATED:
        case HTTP_NO_CONTENT:
            resp_body->cmid = uid;
            resp_body->etag = NULL;
            break;

        default:
            goto done;
            break;
        }

        /* Update reference count */
        wdata = increment_refcount(uid, webdavdb);

        /* Create new ATTACH property */
        if (aprop) aprop = icalproperty_new_clone(aprop);
        else {
            const char *proto = NULL, *host = NULL;
            icalattach *attach;

            assert(!buf_len(&txn->buf));
            http_proto_host(txn->req_hdrs, &proto, &host);
            buf_printf(&txn->buf, "%s://%s%s/%s/%s/%s%s",
                       proto, host, namespace_calendar.prefix,
                       USER_COLLECTION_PREFIX,
                       txn->req_tgt.userid, MANAGED_ATTACH, uid);
            attach = icalattach_new_from_url(buf_cstring(&txn->buf));
            buf_reset(&txn->buf);

            aprop = icalproperty_new_attach(attach);
            icalattach_unref(attach);
        }

        /* Update ATTACH parameters - MANAGED-ID, FILENAME, SIZE, FMTTYPE */
        param = icalproperty_get_managedid_parameter(aprop);
        if (param) icalparameter_set_managedid(param, resp_body->cmid);
        else {
            param = icalparameter_new_managedid(resp_body->cmid);
            icalproperty_add_parameter(aprop, param);
        }

        if (wdata->filename) {
            param = icalproperty_get_filename_parameter(aprop);
            if (param) icalparameter_set_filename(param, wdata->filename);
            else {
                param = icalparameter_new_filename(wdata->filename);
                icalproperty_add_parameter(aprop, param);
            }
        }

        assert(!buf_len(&txn->buf));
        buf_printf(&txn->buf, "%tu", buf_len(&txn->req_body.payload));
        param = icalproperty_get_size_parameter(aprop);
        if (param) icalparameter_set_size(param, buf_cstring(&txn->buf));
        else {
            param = icalparameter_new_size(buf_cstring(&txn->buf));
            icalproperty_add_parameter(aprop, param);
        }
        buf_reset(&txn->buf);

        if ((hdr = spool_getheader(txn->req_hdrs, "Content-Type"))) {
            param = icalproperty_get_first_parameter(aprop,
                                                     ICAL_FMTTYPE_PARAMETER);
            if (param) icalparameter_set_fmttype(param, *hdr);
            else {
                param = icalparameter_new_fmttype(*hdr);
                icalproperty_add_parameter(aprop, param);
            }
        }
    }

    if (rid) {
        /* Split list of RECURRENCE-IDs */
        rids = strarray_split(rid->s, ",", STRARRAY_TRIM);
    }

    /* Process each component */
    for (; comp; comp = nextc) {
        int idx;

        nextc = icalcomponent_get_next_component(ical, kind);

        if (rid) {
            /* Check if RECURRENCE-ID is in our list */
            const char *recurid;

            prop = icalcomponent_get_first_property(comp,
                                                    ICAL_RECURRENCEID_PROPERTY);
            if (prop) recurid = icalproperty_get_value_as_string(prop);
            else {
                master = comp;
                recurid = "M";
            }

            idx = strarray_find_case(rids, recurid, 0);
            if (idx >= 0) {
                /* Remove found recurid from list -
                   we will create new overrides for unfound recurids */
                free(strarray_remove(rids, idx));
            }
            else if (!nextc && strarray_size(rids)) {
                /* Create new overrides */
                struct icaldatetimeperiodtype dtp;
                icalproperty *nextp;

                master = icalcomponent_new_clone(master);

                /* Get DTSTART and Remove unwanted recurrence properties */
                for (prop = icalcomponent_get_first_property(master,
                                                             ICAL_ANY_PROPERTY);
                     prop; prop = nextp) {
                    nextp = icalcomponent_get_next_property(master,
                                                            ICAL_ANY_PROPERTY);
                    switch (icalproperty_isa(prop)) {
                    case ICAL_RRULE_PROPERTY:
                    case ICAL_RDATE_PROPERTY:
                    case ICAL_EXDATE_PROPERTY:
                    case ICAL_EXRULE_PROPERTY:
                        icalcomponent_remove_property(master, prop);
                        icalproperty_free(prop);
                        break;

                    case ICAL_DTSTART_PROPERTY:
                        dtp = icalproperty_get_datetimeperiod(prop);
                        break;

                    default:
                        break;
                    }
                }

                /* Get TZID of DTSTART */
                struct icaltimetype dtstart = dtp.time;
                const icaltimezone *tz = icaltime_get_timezone(dtstart);
                const char *tzid = icaltimezone_get_tzid((icaltimezone *) tz);

                for (idx = 0; idx < strarray_size(rids); idx++) {
                    /* Create new component and set DTSTART and RECURRENCE-ID */
                    dtstart = icaltime_from_string(strarray_nth(rids, idx));
                    if (icaltime_is_null_time(dtstart)) continue;

                    icaltime_set_timezone(&dtstart, tz);

                    comp = icalcomponent_new_clone(master);
                    icalcomponent_add_component(ical, comp);
                    icalcomponent_set_dtstart(comp, dtstart);

                    prop = icalproperty_new_recurrenceid(dtstart);
                    icalcomponent_add_property(comp, prop);
                    if (tzid) {
                        icalproperty_add_parameter(prop,
                                                   icalparameter_new_tzid(tzid));
                    }
                }

                icalcomponent_free(master);
                nextc = icalcomponent_get_next_component(ical, kind);
                rid = NULL;
            }
            else {
                /* No matching RECURRENCE-ID - Skip this component */
                continue;
            }
        }

        if (mid) {
            /* Remove matching ATTACH property */
            for (prop = icalcomponent_get_first_property(comp,
                                                         ICAL_ATTACH_PROPERTY);
                 prop;
                 prop = icalcomponent_get_next_property(comp,
                                                        ICAL_ATTACH_PROPERTY)) {
                param = icalproperty_get_managedid_parameter(prop);
                if (param &&
                    !strcmp(mid->s, icalparameter_get_managedid(param))) {
                    icalcomponent_remove_property(comp, prop);
                    icalproperty_free(prop);
                    break;
                }
            }

            if (!prop) {
                /* No matching ATTACH - Skip this component */
                continue;
            }
        }

        if (aprop) {
            /* Add new/updated ATTACH property */
            icalcomponent_add_property(comp, icalproperty_new_clone(aprop));
        }
    }

    /* Finished with attachment collection */
    mailbox_unlock_index(attachments, NULL);

    /* Store updated calendar resource */
    ret = caldav_store_resource(txn, ical, calendar, txn->req_tgt.resource,
                                caldavdb, return_rep, schedule_address);

    if (ret == HTTP_NO_CONTENT && return_rep) {
        struct buf *data;

        ret = (op == ATTACH_ADD) ? HTTP_CREATED : HTTP_OK;

      return_rep:
        /* Convert into requested MIME type */
        data = mime->from_object(ical);

        /* Fill in Content-Type, Content-Length */
        resp_body->type = mime->content_type;
        resp_body->len = buf_len(data);

        /* Fill in Content-Location */
        resp_body->loc = txn->req_tgt.path;

        /* Fill in Expires and Cache-Control */
        resp_body->maxage = 3600;       /* 1 hr */
        txn->flags.cc = CC_MAXAGE
            | CC_REVALIDATE             /* don't use stale data */
            | CC_NOTRANSFORM;           /* don't alter iCal data */

        /* Output current representation */
        write_body(ret, txn, buf_base(data), buf_len(data));

        buf_destroy(data);
        ret = 0;
    }

  done:
    strarray_free(rids);
    free(schedule_address);
    if (aprop) icalproperty_free(aprop);
    if (ical) icalcomponent_free(ical);
    if (webdavdb) webdav_close(webdavdb);
    if (caldavdb) caldav_close(caldavdb);
    mailbox_close(&attachments);
    mailbox_close(&calendar);

    return ret;
}


/* Perform a busy time request */
static int caldav_post_outbox(struct transaction_t *txn, int rights)
{
    int ret = 0, r;
    const char **hdr;
    struct mime_type_t *mime = NULL;
    icalcomponent *ical = NULL, *comp;
    icalcomponent_kind kind = 0;
    icalproperty_method meth = 0;
    icalproperty *prop = NULL;
    const char *uid = NULL, *organizer = NULL;
    struct caldav_sched_param sparam;

    /* Check Content-Type */
    if ((hdr = spool_getheader(txn->req_hdrs, "Content-Type"))) {
        for (mime = caldav_mime_types; mime->content_type; mime++) {
            if (is_mediatype(mime->content_type, hdr[0])) break;
        }
    }
    if (!mime || !mime->content_type) {
        txn->error.precond = CALDAV_SUPP_DATA;
        return HTTP_BAD_REQUEST;
    }

    /* Read body */
    txn->req_body.flags |= BODY_DECODE;
    r = http_read_body(httpd_in, httpd_out,
                       txn->req_hdrs, &txn->req_body, &txn->error.desc);
    if (r) {
        txn->flags.conn = CONN_CLOSE;
        return r;
    }

    /* Make sure we have a body */
    if (!buf_len(&txn->req_body.payload)) {
        txn->error.desc = "Missing request body\r\n";
        return HTTP_BAD_REQUEST;
    }

    /* Parse the iCal data for important properties */
    ical = mime->to_object(&txn->req_body.payload);
    if (!ical || !icalrestriction_check(ical)) {
        txn->error.precond = CALDAV_VALID_DATA;
        ret = HTTP_BAD_REQUEST;
        goto done;
    }

    meth = icalcomponent_get_method(ical);
    comp = icalcomponent_get_first_real_component(ical);
    if (comp) {
        uid = icalcomponent_get_uid(comp);
        kind = icalcomponent_isa(comp);
        prop = icalcomponent_get_first_property(comp, ICAL_ORGANIZER_PROPERTY);
    }

    /* Check method preconditions */
    if (!meth || !uid || !prop) {
        txn->error.precond = CALDAV_VALID_SCHED;
        ret = HTTP_BAD_REQUEST;
        goto done;
    }

    /* Organizer MUST be local to use CalDAV Scheduling */
    organizer = icalproperty_get_organizer(prop);
    if (!organizer) {
        txn->error.precond = CALDAV_VALID_ORGANIZER;
        ret = HTTP_FORBIDDEN;
        goto done;
    }
    r = caladdress_lookup(organizer, &sparam, txn->req_tgt.userid);
    if (r) {
        txn->error.precond = CALDAV_VALID_ORGANIZER;
        ret = HTTP_FORBIDDEN;
        goto done;
    }
    if (!sparam.isyou) {
        sched_param_free(&sparam);
        txn->error.precond = CALDAV_VALID_ORGANIZER;
        ret = HTTP_FORBIDDEN;
        goto done;
    }
    sched_param_free(&sparam);

    switch (kind) {
    case ICAL_VFREEBUSY_COMPONENT:
        if (meth == ICAL_METHOD_REQUEST)
            if (!(rights & DACL_SCHEDFB)) {
                /* DAV:need-privileges */
                txn->error.precond = DAV_NEED_PRIVS;
                txn->error.resource = txn->req_tgt.path;
                txn->error.rights = DACL_SCHEDFB;
                ret = HTTP_NO_PRIVS;
            }
            else ret = sched_busytime_query(txn, mime, ical);
        else {
            txn->error.precond = CALDAV_VALID_SCHED;
            ret = HTTP_BAD_REQUEST;
        }
        break;

    default:
        txn->error.precond = CALDAV_VALID_SCHED;
        ret = HTTP_BAD_REQUEST;
    }

  done:
    if (ical) icalcomponent_free(ical);

    return ret;
}


/* Perform a bulk import */
static int caldav_import(struct transaction_t *txn, void *obj,
                         struct mailbox *mailbox, void *destdb,
                         xmlNodePtr root, xmlNsPtr *ns, unsigned flags)
{
    int ret = 0;
    icalcomponent *ical = obj, *comp, *next;
    icalcomponent_kind kind;
    icalproperty *prodid, *version, *calscale;
    const char *uid;
    struct caldav_db *caldavdb = destdb;
    xmlNodePtr resp, propstat, prop, error;
    unsigned post_count = 0;

    /* Validate the iCal data */
    if (!ical || (icalcomponent_isa(ical) != ICAL_VCALENDAR_COMPONENT)) {
        txn->error.precond = CALDAV_VALID_DATA;
        return HTTP_FORBIDDEN;
    }
    icalrestriction_check(ical);
    if ((txn->error.desc = get_icalcomponent_errstr(ical))) {
        buf_setcstr(&txn->buf, txn->error.desc);
        txn->error.desc = buf_cstring(&txn->buf);
        txn->error.precond = CALDAV_VALID_DATA;
        return HTTP_FORBIDDEN;
    }

    ensure_ns(ns, NS_CALDAV, root, XML_NS_CALDAV, "C");

    size_t len = strlen(txn->req_tgt.path);
    txn->req_tgt.resource = txn->req_tgt.path + len;

    prodid = icalcomponent_get_first_property(ical, ICAL_PRODID_PROPERTY);
    version = icalcomponent_get_first_property(ical, ICAL_VERSION_PROPERTY);
    calscale = icalcomponent_get_first_property(ical, ICAL_CALSCALE_PROPERTY);

    for (comp = icalcomponent_get_first_component(ical, ICAL_ANY_COMPONENT);
         comp; comp = next) {
        icalcomponent *newical;
        struct timezone_rock tzrock;

        next = icalcomponent_get_next_component(ical, ICAL_ANY_COMPONENT);
        kind = icalcomponent_isa(comp);
        if (kind == ICAL_VTIMEZONE_COMPONENT) continue;

        /* Create new object, making copies of PRODID, VERSION, CALSCALE */
        newical = icalcomponent_new(ICAL_VCALENDAR_COMPONENT);
        if (prodid)
            icalcomponent_add_property(newical, icalproperty_new_clone(prodid));
        if (version)
            icalcomponent_add_property(newical, icalproperty_new_clone(version));
        if (calscale)
            icalcomponent_add_property(newical, icalproperty_new_clone(calscale));

        /* Add our component */
        icalcomponent_remove_component(ical, comp);
        icalcomponent_add_component(newical, comp);

        /* Look for matching UIDs (recurrence set) */

        /* Add required timezone components */
        tzrock.old = ical;
        tzrock.new = newical;
        icalcomponent_foreach_tzid(comp, &add_timezone, &tzrock);

        /* Append a unique resource name to URL and perform a PUT */
        uid = icalcomponent_get_uid(comp);
        txn->req_tgt.reslen =
            snprintf(txn->req_tgt.resource, MAX_MAILBOX_PATH - len,
                     "%x-%d-%ld-%u.ics",
                     strhash(uid), getpid(), time(0), post_count++);

        ret = caldav_put(txn, newical, mailbox,
                         txn->req_tgt.resource, caldavdb, flags);

        resp = xmlNewChild(root, ns[NS_DAV], BAD_CAST "response", NULL);
        if (!resp) {
            txn->error.desc = "Unable to add response XML element";
            return HTTP_SERVER_ERROR;
        }

        switch (ret) {
        case HTTP_OK:
        case HTTP_CREATED:
        case HTTP_NO_CONTENT:
            xml_add_href(resp, NULL, txn->req_tgt.path);
            propstat = xmlNewChild(resp, ns[NS_DAV], BAD_CAST "propstat", NULL);
            prop = xmlNewChild(propstat, ns[NS_DAV], BAD_CAST "prop", NULL);

            if (txn->resp_body.etag) {
                xmlNewTextChild(prop, ns[NS_DAV], BAD_CAST "getetag",
                                BAD_CAST txn->resp_body.etag);
            }
            if (flags & PREFER_REP) {
                xmlNodePtr data = xmlNewChild(prop, ns[NS_CALDAV],
                                              BAD_CAST "calendar-data", NULL);
                const char *icalstr = icalcomponent_as_ical_string(newical);
                xmlAddChild(data, xmlNewCDataBlock(root->doc, BAD_CAST icalstr,
                                                   strlen(icalstr)));
            }
            else xmlNewTextChild(prop, ns[NS_CS], BAD_CAST "uid", BAD_CAST uid);

            xmlNewChild(propstat, ns[NS_DAV], BAD_CAST "status",
                        BAD_CAST http_statusline(HTTP_OK));
            break;

        default:
            xml_add_href(resp, NULL, NULL);
            xmlNewChild(resp, ns[NS_DAV], BAD_CAST "status",
                        BAD_CAST http_statusline(ret));
            error = xml_add_error(resp, &txn->error, ns);
            xmlNewTextChild(error, ns[NS_CS], BAD_CAST "uid", BAD_CAST uid);
            break;
        }

        icalcomponent_free(newical);
    }

    return 0;
}


static int caldav_post(struct transaction_t *txn)
{
    int ret, rights;

    /* Get rights for current user */
    rights = httpd_myrights(httpd_authstate, txn->req_tgt.mbentry);

    if (txn->req_tgt.resource) {
        if (txn->req_tgt.flags) {
            /* Don't allow POST on resources in special collections */
            ret = HTTP_NOT_ALLOWED;
        }
        else if (txn->req_tgt.mbentry->server) {
            /* Remote mailbox */
            struct backend *be;

            be = proxy_findserver(txn->req_tgt.mbentry->server,
                                  &http_protocol, httpd_userid,
                                  &backend_cached, NULL, NULL, httpd_in);
            if (!be) ret = HTTP_UNAVAILABLE;
            else ret = http_pipe_req_resp(be, txn);
        }
        else {
            /* Local Mailbox */
            ret = caldav_post_attach(txn, rights);
        }
    }
    else if (txn->req_tgt.flags == TGT_SCHED_OUTBOX) {
        /* POST to schedule-outbox */
        ret = caldav_post_outbox(txn, rights);
    }
    else if (txn->req_tgt.flags) {
        /* Don't allow POST to special collections */
        ret = HTTP_NOT_ALLOWED;
    }
    else if (!txn->req_tgt.collection) {
        /* POST to calendar-home-set */
        ret = notify_post(txn);
    }
    else {
        /* POST to regular calendar collection */
        ret = HTTP_CONTINUE;
    }

    return ret;
}


#ifdef HAVE_VPATCH
enum {
    ACTION_UPDATE = 1,
    ACTION_DELETE,
    ACTION_SETPARAM
};

enum {
    SEGMENT_COMP = 1,
    SEGMENT_PROP,
    SEGMENT_PARAM
};

union match_criteria_t {
    struct {
        char *uid;                /* component UID (optional) */
        icaltimetype rid;         /* component RECURRENCE-ID (optional) */
    } comp;
    struct {
        char *param;              /* parameter name (optional) */
        char *value;              /* prop/param value (optional) */
        unsigned not:1;           /* not equal? */
    } prop;
};

struct path_segment_t {
    unsigned type;                    /* Is it comp, prop, or param segment? */
    unsigned kind;                    /* libical kind of comp, prop, or param */
    union match_criteria_t match;     /* match criteria (depends on 'type') */
    unsigned action;                  /* patch action (create,update,setparam)*/
    void *data;                       /* patch data (depends on 'action') */

    struct path_segment_t *sibling;
    struct path_segment_t *child;
};

struct patch_data_t {
    icalcomponent *patch;             /* component containg patch data */
    struct path_segment_t *delete;    /* list of PATCH-DELETE actions */
    struct path_segment_t *setparam;  /* list of PATCH-PARAMETER items */
};

static int parse_target_path(char *path, struct path_segment_t **path_seg,
                             unsigned action, void *data,
                             struct error_t *err)
{
    char *p, sep;
    struct path_segment_t *tail = NULL, *new;

    for (sep = *path++; sep == '/';) {
        p = path + strcspn(path, "[/#");
        if ((sep = *p)) *p++ = '\0';

        new = xzmalloc(sizeof(struct path_segment_t));
        new->type = SEGMENT_COMP;
        new->kind = icalcomponent_string_to_kind(path);
        /* Initialize RID as invalid time rather than NULL time
           since NULL time is used for empty RID (master component) */
        new->match.comp.rid.year = -1;

        if (!*path_seg) *path_seg = new;
        else tail->child = new;
        tail = new;

        path = p;

        if (sep == '[') {
            /* Parse comp-match */
            const char *prefix = "UID=";
            size_t prefix_len = strlen(prefix);

            if (!(p = strchr(path, ']'))) {
                err->desc = "Badly formatted comp-match";
                return HTTP_BAD_REQUEST;
            }

            /* Parse uid-match */
            if (!strncmp(path, prefix, prefix_len)) {
                path += prefix_len;
                *p++ = '\0';
                new->match.comp.uid = xstrdup(path);
                sep = *p++;
                path = p;
            }

            /* Parse rid-match */
            if (sep == '[') {
                prefix = "RID=";
                prefix_len = strlen(prefix);

                if (strncmp(path, prefix, prefix_len) ||
                    !(p = strchr(path, ']'))) {
                    err->desc = "Badly formatted rid-match";
                    return HTTP_BAD_REQUEST;
                }

                path += prefix_len;
                *p++ = '\0';
                if (*path && strcmp(path, "M")) {
                    new->match.comp.rid = icaltime_from_string(path);
                    if (icaltime_is_null_time(new->match.comp.rid)) {
                        err->desc = "Invalid recurrence-id";
                        return HTTP_BAD_REQUEST;
                    }
                }
                else new->match.comp.rid = icaltime_null_time();

                sep = *p++;
                path = p;
            }
        }
    }

    if (sep == '#' && !*path_seg) {
        /* Parse prop-segment */
        p = path + strcspn(path, "[;=");
        if ((sep = *p)) *p++ = '\0';

        new = xzmalloc(sizeof(struct path_segment_t));
        new->type = SEGMENT_PROP;
        new->kind = icalproperty_string_to_kind(path);

        if (!*path_seg) *path_seg = new;
        else tail->child = new;
        tail = new;

        path = p;

        if (sep == '[') {
            /* Parse prop-match (MUST start with '=' or '!' or '@') */
            if (strspn(path, "=!@") != 1 || !(p = strchr(path, ']'))) {
                err->desc = "Badly formatted prop-match";
                return HTTP_BAD_REQUEST;
            }

            *p++ = '\0';
            if (*path == '@') {
                /* Parse param-match */
                size_t namelen = strcspn(++path, "!=");
                new->match.prop.param = xstrndup(path, namelen);
                path += namelen;
            }

            if (*path) {
                /* Parse prop/param [not]equal value */
                if (*path++ == '!') new->match.prop.not = 1;
                new->match.prop.value = xstrdup(path);
            }

            sep = *p++;
            path = p;
        }

        if (sep == ';') {
            /* Parse param-segment */
            p = path + strcspn(path, "=");
            if ((sep = *p)) *p++ = '\0';

            new = xzmalloc(sizeof(struct path_segment_t));
            new->type = SEGMENT_PARAM;
            new->kind = icalparameter_string_to_kind(path);

            tail->child = new;
            tail = new;

            path = p;
        }

        if (sep == '=' && action == ACTION_DELETE) {
            /* Parse value-segment */
            new->data = xstrdup(path);
        }
        else if (sep != '\0') {
            err->desc = "Invalid separator following prop-segment";
            return HTTP_BAD_REQUEST;
        }
    }
    else if (sep != '\0') {
        err->desc = "Invalid separator following comp-segment";
        return HTTP_BAD_REQUEST;
    }

    tail->action = action;
    if (!tail->data) tail->data = data;

    return 0;
}

static void apply_patch(struct path_segment_t *path_seg,
                        void *parent, int *num_changes);

static char *remove_single_value(const char *oldstr, const char *single)
{
    char *newstr = NULL;
    strarray_t *values = strarray_split(oldstr, ",", STRARRAY_TRIM);
    int idx = strarray_find(values, single, 0);

    if (idx >= 0) {
        /* Found the single value, remove it, and create new string */
        strarray_remove(values, idx);
        newstr = strarray_join(values, ",");
    }
    strarray_free(values);

    return newstr;
}

/* Apply a patch action to a parameter segment */
static void apply_patch_parameter(struct path_segment_t *path_seg,
                                  icalproperty *parent, int *num_changes)
{
    icalparameter *param =
        icalproperty_get_first_parameter(parent, path_seg->kind);
    if (!param) return;

    if (path_seg->action == ACTION_DELETE) {
        switch (path_seg->kind) {
        case ICAL_MEMBER_PARAMETER:
            /* Multi-valued parameter */
            if (path_seg->data) {
                /* Check if entire parameter value == single value */
                const char *single = (const char *) path_seg->data;
                const char *param_val = icalparameter_get_value_as_string(param);

                if (strcmp(param_val, single)) {
                    /* Not an exact match, try to remove single value */
                    char *newval = remove_single_value(param_val, single);
                    if (newval) {
                        *num_changes += 1;
                        icalparameter_set_member(param, newval);
                        free(newval);
                    }
                    break;
                }
            }

            /* Fall through and delete entire parameter */

        default:
            *num_changes += 1;
            icalproperty_remove_parameter_by_ref(parent, param);
            break;
        }
    }
}

static int apply_param_match(icalproperty *prop, union match_criteria_t *match)
{
    icalparameter_kind kind;
    icalparameter *param;
    int ret = 1;

    /* XXX  Need to handle X- parameters */

    kind = icalparameter_string_to_kind(match->prop.param);
    param = icalproperty_get_first_parameter(prop, kind);
    if (!param) {
        /* property doesn't have this parameter */
        ret = match->prop.not;
    }
    else if (match->prop.value) {
        const char *param_val = icalparameter_get_value_as_string(param);

        ret = !strcmp(match->prop.value, param_val);
        if (match->prop.not) ret = !ret;  /* invert */
    }

    return ret;
}

/* Apply a patch action to a property segment */
static void apply_patch_property(struct path_segment_t *path_seg,
                                 icalcomponent *parent, int *num_changes)
{
    icalproperty *prop, *nextprop;
    icalparameter *param;

    /* Iterate through each property */
    for (prop = icalcomponent_get_first_property(parent, path_seg->kind);
         prop; prop = nextprop) {
        nextprop = icalcomponent_get_next_property(parent, path_seg->kind);

        /* Check prop-match */
        int match = 1;
        if (path_seg->match.prop.param) {
            /* Check param-match */
            match = apply_param_match(prop, &path_seg->match);
        }
        else if (path_seg->match.prop.value) {
            /* Check prop-[not-]equal */
            const char *prop_val = icalproperty_get_value_as_string(prop);

            match = !strcmp(path_seg->match.prop.value, prop_val);
            if (path_seg->match.prop.not) match = !match;  /* invert */
        }
        if (!match) continue;

        if (path_seg->child) {
            /* Recurse into next segment */
            apply_patch(path_seg->child, prop, num_changes);
        }
        else if (path_seg->action == ACTION_DELETE) {
            /* Delete existing property */
            switch (path_seg->kind) {
            case ICAL_RDATE_PROPERTY:
            case ICAL_EXDATE_PROPERTY:
            case ICAL_FREEBUSY_PROPERTY:
            case ICAL_CATEGORIES_PROPERTY:
            case ICAL_RESOURCES_PROPERTY:
            case ICAL_ACCEPTRESPONSE_PROPERTY:
            case ICAL_POLLPROPERTIES_PROPERTY:
                /* Multi-valued property */
                if (path_seg->data) {
                    /* Check if entire property value == single value */
                    const char *single = (const char *) path_seg->data;
                    const char *propval = icalproperty_get_value_as_string(prop);

                    if (strcmp(propval, single)) {
                        /* Not an exact match, try to remove single value */
                        char *newval = remove_single_value(propval, single);
                        if (newval) {
                            *num_changes += 1;
                            icalproperty_set_value(prop,
                                                   icalvalue_new_string(newval));
                            free(newval);
                        }
                        break;
                    }
                }

                /* Fall through and delete entire property */

            default:
                *num_changes += 1;
                icalcomponent_remove_property(parent, prop);
                icalproperty_free(prop);
                break;
            }
        }
        else if (path_seg->action == ACTION_SETPARAM) {
            /* Set parameter(s) from those on PATCH-PARAMETER */
            icalproperty *pp_prop = (icalproperty *) path_seg->data;

            *num_changes += 1;
            for (param = icalproperty_get_first_parameter(pp_prop,
                                                          ICAL_ANY_PARAMETER);
                 param;
                 param = icalproperty_get_next_parameter(pp_prop,
                                                         ICAL_ANY_PARAMETER)) {
                icalproperty_set_parameter(prop, icalparameter_new_clone(param));
            }
        }
    }
}

static void create_override(icalcomponent *master, struct icaltime_span *span,
                            void *rock)
{
    icalcomponent *new;
    icalproperty *prop, *next;
    struct icaltimetype dtstart, dtend, now;
    const icaltimezone *tz = NULL;
    const char *tzid;
    int is_date;

    now = icaltime_current_time_with_zone(utc_zone);

    new = icalcomponent_new_clone(master);

    for (prop = icalcomponent_get_first_property(new, ICAL_ANY_PROPERTY);
         prop; prop = next) {
        next = icalcomponent_get_next_property(new, ICAL_ANY_PROPERTY);

        switch (icalproperty_isa(prop)) {
        case ICAL_DTSTART_PROPERTY:
            /* Set DTSTART for this recurrence */
            dtstart = icalproperty_get_dtstart(prop);
            is_date = icaltime_is_date(dtstart);
            tz = icaltime_get_timezone(dtstart);

            dtstart = icaltime_from_timet_with_zone(span->start, is_date, tz);
            icaltime_set_timezone(&dtstart, tz);
            icalproperty_set_dtstart(prop, dtstart);

            /* Add RECURRENCE-ID for this recurrence */
            prop = icalproperty_new_recurrenceid(dtstart);
            tzid = icaltimezone_get_tzid((icaltimezone *) tz);
            if (tzid) {
                icalproperty_add_parameter(prop, icalparameter_new_tzid(tzid));
            }
            icalcomponent_add_property(new, prop);
            break;

        case ICAL_DTEND_PROPERTY:
            /* Set DTEND for this recurrence */
            dtend = icalproperty_get_dtend(prop);
            is_date = icaltime_is_date(dtend);
            tz = icaltime_get_timezone(dtend);

            dtend = icaltime_from_timet_with_zone(span->end, is_date, tz);
            icaltime_set_timezone(&dtend, tz);
            icalproperty_set_dtend(prop, dtend);
            break;

        case ICAL_RRULE_PROPERTY:
        case ICAL_RDATE_PROPERTY:
        case ICAL_EXDATE_PROPERTY:
            /* Remove recurrence properties */
            icalcomponent_remove_property(new, prop);
            icalproperty_free(prop);
            break;

        case ICAL_DTSTAMP_PROPERTY:
            /* Update DTSTAMP */
            icalproperty_set_dtstamp(prop, now);
            break;

        case ICAL_CREATED_PROPERTY:
            /* Update CREATED */
            icalproperty_set_created(prop, now);
            break;

        case ICAL_LASTMODIFIED_PROPERTY:
            /* Update LASTMODIFIED */
            icalproperty_set_lastmodified(prop, now);
            break;

        default:
            break;
        }
    }

    *((icalcomponent **) rock) = new;
}

/* Apply property updates */
static void apply_property_updates(struct patch_data_t *patch,
                                   icalcomponent *parent, int *num_changes)
{
    icalproperty *prop = NULL, *nextprop, *newprop;

    for (newprop = icalcomponent_get_first_property(patch->patch,
                                                    ICAL_ANY_PROPERTY);
         newprop;
         newprop = icalcomponent_get_next_property(patch->patch,
                                                   ICAL_ANY_PROPERTY)) {
        icalproperty_kind kind = icalproperty_isa(newprop);
        icalparameter_patchaction action = ICAL_PATCHACTION_BYNAME;
        icalparameter *actionp;
        union match_criteria_t byparam;

        memset(&byparam, 0, sizeof(union match_criteria_t));
        newprop = icalproperty_new_clone(newprop);

        actionp = icalproperty_get_first_parameter(newprop,
                                                   ICAL_PATCHACTION_PARAMETER);
        if (actionp) {
            action = icalparameter_get_patchaction(actionp);
            if (action == ICAL_PATCHACTION_X) {
                /* libical treats DQUOTEd BYPARAM as X value */
                const char *byparam_prefix = "BYPARAM@";
                const char *x_val = icalparameter_get_xvalue(actionp);
                if (!strncmp(x_val, byparam_prefix, strlen(byparam_prefix))) {
                    /* Parse param-match */
                    const char *p = x_val + strlen(byparam_prefix);
                    size_t namelen = strcspn(p, "!=");
                    byparam.prop.param = xstrndup(p, namelen);
                    p += namelen;

                    if (*p) {
                        if (*p++ == '!') byparam.prop.not = 1;
                        byparam.prop.value = xstrdup(p);
                    }
                    action = ICAL_PATCHACTION_BYPARAM;
                }
            }

            icalproperty_remove_parameter_by_ref(newprop, actionp);
            icalparameter_free(actionp);
        }

        if (action != ICAL_PATCHACTION_CREATE) {
            /* Delete properties matching those being updated */
            const char *value = icalproperty_get_value_as_string(newprop);

            for (prop = icalcomponent_get_first_property(parent, kind);
                 prop; prop = nextprop) {
                int match = 1;

                nextprop = icalcomponent_get_next_property(parent, kind);

                if (action == ICAL_PATCHACTION_BYVALUE) {
                    match = !strcmp(value,
                                    icalproperty_get_value_as_string(prop));
                }
                else if (action == ICAL_PATCHACTION_BYPARAM) {
                    /* Check param-match */
                    match = apply_param_match(prop, &byparam);
                    free(byparam.prop.param);
                    free(byparam.prop.value);
                }
                if (!match) continue;

                icalcomponent_remove_property(parent, prop);
                icalproperty_free(prop);
            }
        }

        *num_changes += 1;
        icalcomponent_add_property(parent, newprop);
    }
}

/* Apply property updates */
static void apply_component_updates(struct patch_data_t *patch,
                                    icalcomponent *parent, int *num_changes)
{
    icalcomponent *comp, *nextcomp, *newcomp;

    for (newcomp = icalcomponent_get_first_component(patch->patch,
                                                     ICAL_ANY_COMPONENT);
         newcomp;
         newcomp = icalcomponent_get_next_component(patch->patch,
                                                    ICAL_ANY_COMPONENT)){
        icalcomponent_kind kind = icalcomponent_isa(newcomp);
        const char *uid = icalcomponent_get_uid(newcomp);
        icaltimetype rid = icalcomponent_get_recurrenceid(newcomp);

        newcomp = icalcomponent_new_clone(newcomp);

        /* Delete components matching those being updated */
        for (comp = icalcomponent_get_first_component(parent, kind);
             comp; comp = nextcomp) {

            nextcomp = icalcomponent_get_next_component(parent, kind);

            if (strcmp(uid, icalcomponent_get_uid(comp)) ||
                icaltime_compare(rid, icalcomponent_get_recurrenceid(comp))) {
                /* skip */
                continue;
            }

            icalcomponent_remove_component(parent, comp);
            icalcomponent_free(comp);
        }

        *num_changes += 1;
        icalcomponent_add_component(parent, newcomp);
    }
}

/* Apply a patch action to a component segment */
static void apply_patch_component(struct path_segment_t *path_seg,
                                 icalcomponent *parent, int *num_changes)
{
    icalcomponent *comp, *nextcomp, *master = NULL;

    /* Iterate through each component */
    if (path_seg->kind == ICAL_VCALENDAR_COMPONENT)
        comp = parent;
    else
        comp = icalcomponent_get_first_component(parent, path_seg->kind);

    for (; comp; comp = nextcomp) {
        nextcomp = icalcomponent_get_next_component(parent, path_seg->kind);

        /* Check comp-match */
        if (path_seg->match.comp.uid &&
            strcmp(path_seg->match.comp.uid, icalcomponent_get_uid(comp))) {
            continue;  /* UID doesn't match */
        }

        if (icaltime_is_valid_time(path_seg->match.comp.rid)) {
            icaltimetype recurid =
                icalcomponent_get_recurrenceid_with_zone(comp);

            if (icaltime_is_null_time(recurid)) master = comp;
            if (icaltime_compare(recurid, path_seg->match.comp.rid)) {
                if (!nextcomp && master) {
                    /* Possibly add an override recurrence.
                       Set start and end to coincide with recurrence */
                    icalcomponent *override = NULL;
                    struct icaltimetype start = path_seg->match.comp.rid;
                    struct icaltimetype end =
                        icaltime_add(start, icalcomponent_get_duration(master));
                    icalcomponent_foreach_recurrence(master, start, end,
                                                     &create_override,
                                                     &override);
                    if (!override) break;  /* Can't override - done */

                    /* Act on new overridden component */
                    icalcomponent_add_component(parent, override);
                    comp = override;
                }
                else continue;  /* RECURRENCE-ID doesn't match */
            }
        }

        if (path_seg->child) {
            /* Recurse into next segment */
            apply_patch(path_seg->child, comp, num_changes);
        }
        else if (path_seg->action == ACTION_DELETE) {
            /* Delete existing component */
            *num_changes += 1;
            icalcomponent_remove_component(parent, comp);
            icalcomponent_free(comp);
        }
        else if (path_seg->action == ACTION_UPDATE) {
            /* Patch existing component */
            struct patch_data_t *patch = (struct patch_data_t *) path_seg->data;

            /* Process all PATCH-DELETEs first */
            for (path_seg = patch->delete;
                 path_seg; path_seg = path_seg->child) {
                apply_patch(path_seg, comp, num_changes);
            }

            /* Process all PATCH-SETPARAMETERs second */
            for (path_seg = patch->setparam;
                 path_seg; path_seg = path_seg->child) {
                apply_patch(path_seg, comp, num_changes);
            }

            /* Process all components updates third */
            apply_component_updates(patch, comp, num_changes);

            /* Process all property updates last */
            apply_property_updates(patch, comp, num_changes);
        }
    }
}

/* Apply a patch action to a target segment */
static void apply_patch(struct path_segment_t *path_seg,
                        void *parent, int *num_changes)
{
    switch (path_seg->type) {
    case SEGMENT_COMP:
        apply_patch_component(path_seg, parent, num_changes);
        break;

    case SEGMENT_PROP:
        apply_patch_property(path_seg, parent, num_changes);
        break;

    case SEGMENT_PARAM:
        apply_patch_parameter(path_seg, parent, num_changes);
        break;
    }
}

static void path_segment_free(struct path_segment_t *path_seg)
{
    struct path_segment_t *next;

    for (; path_seg; path_seg = next) {
        next = path_seg->child;

        switch (path_seg->type) {
        case SEGMENT_COMP:
            free(path_seg->match.comp.uid);
            break;

        case SEGMENT_PROP:
            free(path_seg->match.prop.param);
            free(path_seg->match.prop.value);
            break;

        case SEGMENT_PARAM:
            break;
        }

        free(path_seg);
    }
}


/* Perform a PATCH request
 *
 * preconditions:
 */
static int caldav_patch(struct transaction_t *txn, void *obj)
{
    icalcomponent *ical = (icalcomponent *) obj;
    icalcomponent *pdoc, *vpatch, *patch;
    icalproperty *prop;
    int num_changes = 0;
    int ret = 0;

    /* Validate the iCal patch */
    pdoc = ical_string_as_icalcomponent(&txn->req_body.payload);
    if (!pdoc || (icalcomponent_isa(pdoc) != ICAL_VCALENDAR_COMPONENT)) {
        txn->error.desc = "Missing VCALENDAR";
        txn->error.precond = CALDAV_VALID_DATA;
        ret = HTTP_BAD_REQUEST;
    }
    else if (!icalrestriction_check(pdoc) || icalcomponent_count_errors(pdoc)) {
        if ((txn->error.desc = get_icalcomponent_errstr(pdoc)) ||
            (txn->error.desc =
             get_icalcomponent_errstr(icalcomponent_get_first_real_component(pdoc)))) {
            buf_setcstr(&txn->buf, txn->error.desc);
            txn->error.desc = buf_cstring(&txn->buf);
        }
        txn->error.precond = CALDAV_VALID_DATA;
        ret = HTTP_BAD_REQUEST;
    }
    else if (!(vpatch = icalcomponent_get_first_real_component(pdoc)) ||
             icalcomponent_isa(vpatch) != ICAL_VPATCH_COMPONENT) {
        txn->error.desc = "Missing VPATCH";
        txn->error.precond = CALDAV_VALID_DATA;
        ret = HTTP_BAD_REQUEST;
    }
    else if ((prop =
              icalcomponent_get_first_property(vpatch,
                                               ICAL_PATCHVERSION_PROPERTY)) &&
             strcmp(icalproperty_get_patchversion(prop), "1")) {
        txn->error.desc = "Unsupported PATCH-VERSION";
        txn->error.precond = CALDAV_SUPP_DATA;
        ret = HTTP_BAD_REQUEST;
    }

    if (ret) goto done;

    /* Process each patch sub-component */
    for (patch = icalcomponent_get_first_component(vpatch, ICAL_ANY_COMPONENT);
         patch;
         patch = icalcomponent_get_next_component(vpatch, ICAL_ANY_COMPONENT)) {

        if (icalcomponent_isa(patch) != ICAL_XPATCH_COMPONENT) {
            /* Unknown patch action */
            txn->error.precond = CALDAV_SUPP_COMP;
            ret = HTTP_BAD_REQUEST;
            goto done;
        }

        prop = icalcomponent_get_first_property(patch,
                                                ICAL_PATCHTARGET_PROPERTY);
        if (!prop) {
            txn->error.desc = "Missing TARGET";
            txn->error.precond = CALDAV_VALID_DATA;
            ret = HTTP_BAD_REQUEST;
            goto done;
        }

        /* Parse PATCH-TARGET */
        char *path = xstrdup(icalproperty_get_patchtarget(prop));
        struct path_segment_t *target = NULL, *next;
        struct patch_data_t patch_data = { patch, NULL, NULL };

        icalcomponent_remove_property(patch, prop);
        icalproperty_free(prop);

        ret = parse_target_path(path, &target,
                                ACTION_UPDATE, &patch_data, &txn->error);
        free(path);
        if (!ret) {
            if (!target || target->type != SEGMENT_COMP ||
                target->kind != ICAL_VCALENDAR_COMPONENT ||
                target->match.comp.uid) {
                txn->error.desc = "Initial segment of PATCH-TARGET"
                    " MUST be an unmatched VCALENDAR";
                ret = HTTP_BAD_REQUEST;
            }
        }

        if (!ret) {
            /* Parse and remove all PATCH-DELETEs and PATCH-PARAMETERs */
            icalproperty *nextprop;
            for (prop =
                     icalcomponent_get_first_property(patch, ICAL_ANY_PROPERTY);
                 !ret && prop; prop = nextprop) {

                icalproperty_kind kind = icalproperty_isa(prop);
                struct path_segment_t *ppath = NULL;

                nextprop =
                    icalcomponent_get_next_property(patch, ICAL_ANY_PROPERTY);

                if (kind == ICAL_PATCHDELETE_PROPERTY) {
                    path = xstrdup(icalproperty_get_patchdelete(prop));

                    icalcomponent_remove_property(patch, prop);
                    icalproperty_free(prop);

                    ret = parse_target_path(path, &ppath,
                                            ACTION_DELETE, NULL, &txn->error);
                    free(path);
                    if (!ret) {
                        if (!ppath ||
                            (ppath->type == SEGMENT_COMP &&
                             ppath->kind == ICAL_VCALENDAR_COMPONENT)) {
                            txn->error.desc = "Initial segment of PATCH-DELETE"
                                " MUST NOT be VCALENDAR";
                            ret = HTTP_BAD_REQUEST;
                        }
                        else {
                            /* Add this delete path to our list */
                            ppath->sibling = patch_data.delete;
                            patch_data.delete = ppath;
                        }
                    }
                }
                else if (kind == ICAL_PATCHPARAMETER_PROPERTY) {
                    path = xstrdup(icalproperty_get_patchparameter(prop));

                    icalcomponent_remove_property(patch, prop);

                    ret = parse_target_path(path, &ppath,
                                            ACTION_SETPARAM, prop, &txn->error);
                    free(path);
                    if (!ret) {
                        if (!ppath || ppath->type != SEGMENT_PROP) {
                            txn->error.desc =
                                "Initial segment of PATCH-PARAMETER"
                                " MUST be a property";
                            ret = HTTP_BAD_REQUEST;
                        }
                        else {
                            /* Add this setparam path to our list */
                            ppath->sibling = patch_data.setparam;
                            patch_data.setparam = ppath;
                        }
                    }
                }
            }
        }

        /* Apply this patch to the target component */
        if (!ret) apply_patch(target, ical, &num_changes);

        /* Cleanup target paths */
        path_segment_free(target);
        for (target = patch_data.delete; target; target = next) {
            next = target->sibling;
            if (target->data) free(target->data);
            path_segment_free(target);
        }
        for (target = patch_data.setparam; target; target = next) {
            next = target->sibling;
            if (target->data) icalproperty_free(target->data);
            path_segment_free(target);
        }

        if (ret) goto done;
    }

  done:
    icalcomponent_free(pdoc);

    if (ret) return ret;

    /* If no changes are made,
       return HTTP_NO_CONTENT to suppress storing of resource */
    return (!num_changes ? HTTP_NO_CONTENT : 0);
}
#else
static int caldav_patch(struct transaction_t *txn __attribute__((unused)),
                        void *obj __attribute__((unused)))

{
    fatal("caldav_patch() called, but no VPATCH", EC_SOFTWARE);
}
#endif /* HAVE_VPATCH */


/* Perform a PUT request
 *
 * preconditions:
 *   CALDAV:valid-calendar-data
 *   CALDAV:valid-calendar-object-resource
 *   CALDAV:supported-calendar-component
 *   CALDAV:no-uid-conflict (DAV:href)
 *   CALDAV:max-resource-size
 *   CALDAV:min-date-time
 *   CALDAV:max-date-time
 *   CALDAV:max-instances
 *   CALDAV:max-attendees-per-instance
 */
static int caldav_put(struct transaction_t *txn, void *obj,
                      struct mailbox *mailbox, const char *resource,
                      void *destdb, unsigned flags)
{
    int ret = 0;
    struct caldav_db *db = (struct caldav_db *)destdb;
    icalcomponent *ical = (icalcomponent *)obj;
    icalcomponent *oldical = NULL;
    icalcomponent *comp, *nextcomp;
    icalcomponent_kind kind;
    icalproperty *prop, *rrule = NULL;
    const char *uid, *organizer = NULL;
    char *schedule_address = NULL;
    struct buf buf = BUF_INITIALIZER;
    struct caldav_data *cdata;

    /* Validate the iCal data */
    if (!ical || (icalcomponent_isa(ical) != ICAL_VCALENDAR_COMPONENT)) {
        txn->error.precond = CALDAV_VALID_DATA;
        ret = HTTP_FORBIDDEN;
        goto done;
    }

    icalrestriction_check(ical);
    if ((txn->error.desc = get_icalcomponent_errstr(ical))) {
        buf_setcstr(&txn->buf, txn->error.desc);
        txn->error.desc = buf_cstring(&txn->buf);
        txn->error.precond = CALDAV_VALID_DATA;
        ret = HTTP_FORBIDDEN;
        goto done;
    }

    comp = icalcomponent_get_first_real_component(ical);
    if (rscale_calendars) {
        /* Grab RRULE to check RSCALE */
        rrule = icalcomponent_get_first_property(comp, ICAL_RRULE_PROPERTY);
    }

    /* Make sure iCal UIDs [and ORGANIZERs] in all components are the same */
    kind = icalcomponent_isa(comp);
    uid = icalcomponent_get_uid(comp);
    if (!uid) {
        txn->error.precond = CALDAV_VALID_OBJECT;
        ret = HTTP_FORBIDDEN;
        goto done;
    }
    prop = icalcomponent_get_first_property(comp, ICAL_ORGANIZER_PROPERTY);
    if (prop) organizer = icalproperty_get_organizer(prop);
    while ((nextcomp =
            icalcomponent_get_next_component(ical, kind))) {
        const char *nextuid = icalcomponent_get_uid(nextcomp);

        if (!nextuid || strcmp(uid, nextuid)) {
            txn->error.precond = CALDAV_VALID_OBJECT;
            ret = HTTP_FORBIDDEN;
            goto done;
        }

        const char *nextorg = NULL;

        prop = icalcomponent_get_first_property(nextcomp,
                                                ICAL_ORGANIZER_PROPERTY);
        if (prop) nextorg = icalproperty_get_organizer(prop);
        if ( (!organizer && nextorg)
             || (organizer && (!nextorg || strcmp(organizer, nextorg)))) {
            txn->error.precond = CALDAV_SAME_ORGANIZER;
            ret = HTTP_FORBIDDEN;
            goto done;
        }

        if (rscale_calendars && !rrule) {
            /* Grab RRULE to check RSCALE */
            rrule = icalcomponent_get_first_property(nextcomp,
                                                     ICAL_RRULE_PROPERTY);
        }
    }

#ifdef HAVE_RSCALE
    /* Make sure we support the provided RSCALE in an RRULE */
    if (rrule && rscale_calendars) {
        struct icalrecurrencetype rt = icalproperty_get_rrule(rrule);

        if (rt.rscale && *rt.rscale) {
            /* Perform binary search on sorted icalarray */
            unsigned found = 0, start = 0, end = rscale_calendars->num_elements;

            ucase((char *) rt.rscale);
            while (!found && start < end) {
                unsigned mid = start + (end - start) / 2;
                const char **rscale =
                    icalarray_element_at(rscale_calendars, mid);
                int r = strcmp(rt.rscale, *rscale);

                if (r == 0) found = 1;
                else if (r < 0) end = mid;
                else start = mid + 1;
            }

            if (!found) {
                txn->error.precond = CALDAV_SUPP_RSCALE;
                ret = HTTP_FORBIDDEN;
                goto done;
            }
        }
    }
#endif /* HAVE_RSCALE */

    /* Check for changed UID */
    caldav_lookup_resource(db, mailbox->name, resource, &cdata, 0);
    if (cdata->dav.imap_uid && strcmpsafe(cdata->ical_uid, uid)) {
        ret = HTTP_FORBIDDEN;
    }
    else {
        /* Check for duplicate iCalendar UID */
        caldav_lookup_uid(db, uid, &cdata);
        if (cdata->dav.imap_uid && (strcmp(cdata->dav.mailbox, mailbox->name) ||
                                    strcmp(cdata->dav.resource, resource))) {
            ret = HTTP_FORBIDDEN;
        }
    }
    if (ret) {
        /* CALDAV:no-uid-conflict */
        char *owner = mboxname_to_userid(cdata->dav.mailbox);

        txn->error.precond = CALDAV_UID_CONFLICT;
        buf_reset(&txn->buf);
        buf_printf(&txn->buf, "%s/%s/%s/%s/%s",
                   namespace_calendar.prefix, USER_COLLECTION_PREFIX, owner,
                   strrchr(cdata->dav.mailbox, '.')+1, cdata->dav.resource);
        txn->error.resource = buf_cstring(&txn->buf);
        free(owner);
        ret = HTTP_FORBIDDEN;
        goto done;
    }

    if (namespace_calendar.allow & ALLOW_CAL_ATTACH) {
        ret = manage_attachments(txn, mailbox, ical,
                                 cdata, &oldical, &schedule_address);
        if (ret) goto done;
    }

    switch (kind) {
    case ICAL_VEVENT_COMPONENT:
    case ICAL_VTODO_COMPONENT:
    case ICAL_VPOLL_COMPONENT:
        if (organizer && _scheduling_enabled(txn, mailbox) &&
            /* XXX  Hack for Outlook */
            icalcomponent_get_first_invitee(comp)) {
            /* Scheduling object resource */
            strarray_t schedule_addresses = STRARRAY_INITIALIZER;
            int r;

            syslog(LOG_DEBUG,
                   "caldav_put: organizer: %s", organizer);

            if (!strncasecmp(organizer, "mailto:", 7)) organizer += 7;

            if (cdata->organizer) {
                /* Don't allow ORGANIZER to be changed */
                if (strcmp(cdata->organizer, organizer)) {
                    txn->error.desc = "Can not change organizer address";
                    ret = HTTP_FORBIDDEN;
                }
            }

            /* existing record? */
            if (cdata->dav.imap_uid && !oldical) {
                /* Update existing object */
                struct index_record record;

                syslog(LOG_NOTICE, "LOADING ICAL %u", cdata->dav.imap_uid);

                /* Load message containing the resource and parse iCal data */
                r = mailbox_find_index_record(mailbox,
                                              cdata->dav.imap_uid, &record);
                if (r) {
                    txn->error.desc = "Failed to read record \r\n";
                    ret = HTTP_SERVER_ERROR;
                    goto done;
                }

                oldical = record_to_ical(mailbox, &record, &schedule_address);
            }

            if (!schedule_address) {
                get_schedule_addresses(txn, &schedule_addresses);
            }
            else {
                strarray_appendm(&schedule_addresses, schedule_address);
                schedule_address = NULL;
            }

            char *userid = mboxname_to_userid(txn->req_tgt.mbentry->name);
            if (strarray_find_case(&schedule_addresses, organizer, 0) >= 0) {
                /* Organizer scheduling object resource */
                if (ret) {
                    txn->error.precond = CALDAV_ALLOWED_ORG_CHANGE;
                }
                else sched_request(userid, organizer, oldical, ical);
            }
            else {
                /* Attendee scheduling object resource */
                if (ret) {
                    txn->error.precond = CALDAV_ALLOWED_ATT_CHANGE;
                }
#if 0
                else if (!oldical) {
                    /* Can't reply to a non-existent invitation */
                    /* XXX  But what about invites over iMIP? */
                    txn->error.desc = "Can not reply to non-existent resource";
                    ret = HTTP_FORBIDDEN;
                }
#endif
                else {
                    sched_reply(userid, strarray_nth(&schedule_addresses, 0),
                                oldical, ical);
                }
            }
            free(userid);
            strarray_fini(&schedule_addresses);

            if (ret) goto done;

            flags |= NEW_STAG;
        }
        break;

    case ICAL_VJOURNAL_COMPONENT:
    case ICAL_VFREEBUSY_COMPONENT:
    case ICAL_VAVAILABILITY_COMPONENT:
        /* Nothing else to do */
        break;

    default:
        txn->error.precond = CALDAV_SUPP_COMP;
        ret = HTTP_FORBIDDEN;
        goto done;
    }

    /* Store resource at target */
    if (!ret) {
        ret = caldav_store_resource(txn, ical, mailbox,
                                    resource, db, flags, schedule_address);
    }

  done:
    if (oldical) icalcomponent_free(oldical);
    free(schedule_address);
    buf_free(&buf);

    return ret;
}


struct comp_filter {
    xmlChar *name;              /* need this for X- components */
    unsigned depth;
    icalcomponent_kind kind;
    unsigned allof       : 1;
    unsigned not_defined : 1;
    struct icalperiodtype *range;
    struct prop_filter *prop;
    struct comp_filter *comp;
    struct comp_filter *next;
};

struct calquery_filter {
    unsigned flags;             /* mask of flags controlling filter */
    unsigned comp_types;        /* mask of "real" component types in filter */
    icaltimezone *tz;
    struct comp_filter *comp;
};

/* Bitmask of calquery flags */
enum {
    PARSE_ICAL = (1<<0)
};

static int is_valid_timerange(const struct icaltimetype start,
                              const struct icaltimetype end)
{
    return (icaltime_is_valid_time(start) && icaltime_is_valid_time(end) &&
            !icaltime_is_date(start) && !icaltime_is_date(end) &&
            (icaltime_is_utc(start) || start.zone) &&
            (icaltime_is_utc(end) || end.zone));
}

static void parse_timerange(xmlNodePtr node,
                            struct icalperiodtype **range, struct error_t *error)
{
    xmlChar *attr;

    *range = xzmalloc(sizeof(struct icalperiodtype));

    attr = xmlGetProp(node, BAD_CAST "start");
    if (attr) {
        (*range)->start = icaltime_from_string((char *) attr);
        xmlFree(attr);
    }
    else {
        (*range)->start =
            icaltime_from_timet_with_zone(caldav_epoch, 0, utc_zone);
    }

    attr = xmlGetProp(node, BAD_CAST "end");
    if (attr) {
        (*range)->end = icaltime_from_string((char *) attr);
        xmlFree(attr);
    }
    else {
        (*range)->end =
            icaltime_from_timet_with_zone(caldav_eternity, 0, utc_zone);
    }

    if (!is_valid_timerange((*range)->start, (*range)->end)) {
        error->precond = CALDAV_VALID_FILTER;
        error->desc = "Invalid time-range";
        error->node = xmlCopyNode(node->parent, 1);
    }
}

static void cal_parse_propfilter(xmlNodePtr node, struct prop_filter *prop,
                                 struct error_t *error)
{
    if (!xmlStrcmp(node->name, BAD_CAST "time-range")) {
        if (prop->other) {
            error->precond = CALDAV_SUPP_FILTER;
            error->desc = "Multiple time-range";
            error->node = xmlCopyNode(node->parent, 1);
        }
        else {
            struct icalperiodtype *range = NULL;
            icalvalue_kind kind =
                icalproperty_kind_to_value_kind(prop->kind);

            switch (kind) {
            case ICAL_DATE_VALUE:
            case ICAL_DATETIME_VALUE:
            case ICAL_DATETIMEPERIOD_VALUE:
            case ICAL_PERIOD_VALUE:
                parse_timerange(node, &range, error);
                prop->other = range;
                break;

            default:
                error->precond = CALDAV_SUPP_FILTER;
                error->desc = "Property does not support time-range";
                error->node = xmlCopyNode(node->parent, 1);
                break;
            }
        }
    }
    else {
        error->precond = CALDAV_SUPP_FILTER;
        error->desc = "Unsupported element in prop-filter";
        error->node = xmlCopyNode(node->parent, 1);
    }
}

/* This handles calendar-query-extended per draft-daboo-caldav-extensions */
static void parse_compfilter(xmlNodePtr root, unsigned depth,
                             struct comp_filter **comp, unsigned *flags,
                             unsigned *comp_types, struct error_t *error)
{
    xmlChar *attr;
    xmlNodePtr node;
    struct filter_profile_t profile =
        { 1 /* allof */, COLLATION_ASCII,
          CALDAV_SUPP_FILTER, CALDAV_SUPP_COLLATION,
          &icalproperty_string_to_kind, ICAL_NO_PROPERTY,
          &icalparameter_string_to_kind, ICAL_NO_PARAMETER,
          &cal_parse_propfilter };

    /* Parse elements of comp-filter */
    attr = xmlGetProp(root, BAD_CAST "name");
    if (!attr) {
        error->precond = CALDAV_SUPP_FILTER;
        error->desc = "Missing 'name' attribute";
        error->node = xmlCopyNode(root, 2);
    }
    else {
        icalcomponent_kind kind;

        if (!xmlStrcmp(attr, BAD_CAST "*")) kind = ICAL_ANY_COMPONENT;
        else kind = icalcomponent_string_to_kind((const char *) attr);

        *comp = xzmalloc(sizeof(struct comp_filter));
        (*comp)->name = attr;
        (*comp)->depth = depth;
        (*comp)->kind = kind;
        (*comp)->allof = 1;

        if (kind == ICAL_NO_COMPONENT) {
            error->precond = CALDAV_SUPP_FILTER;
            error->desc = "Unsupported component";
            error->node = xmlCopyNode(root, 2);
        }
        else {
            switch (depth) {
            case 0:
                /* VCALENDAR */
                if (kind != ICAL_VCALENDAR_COMPONENT) {
                    /* All other components MUST be a decendent of VCALENDAR */
                    error->precond = CALDAV_VALID_FILTER;
                    error->desc = "VCALENDAR must be toplevel component";
                }
                break;

            case 1:
                /* Child of VCALENDAR */
                switch (kind) {
                case ICAL_VCALENDAR_COMPONENT:
                    /* VCALENDAR MUST only appear at toplevel */
                    error->precond = CALDAV_VALID_FILTER;
                    error->desc = "VCALENDAR can only be toplevel component";
                    break;
                case ICAL_VEVENT_COMPONENT:
                    *comp_types |= CAL_COMP_VEVENT;
                    break;
                case ICAL_VTODO_COMPONENT:
                    *comp_types |= CAL_COMP_VTODO;
                    break;
                case ICAL_VJOURNAL_COMPONENT:
                    *comp_types |= CAL_COMP_VJOURNAL;
                    break;
                case ICAL_VFREEBUSY_COMPONENT:
                    *comp_types |= CAL_COMP_VFREEBUSY;
                    break;
                case ICAL_VAVAILABILITY_COMPONENT:
                    *comp_types |= CAL_COMP_VAVAILABILITY;
                    break;
                case ICAL_VPOLL_COMPONENT:
                    *comp_types |= CAL_COMP_VPOLL;
                    break;
                default:
                    *flags |= PARSE_ICAL;
                    break;
                }
                break;

            default:
                /* [Great*] grandchild of VCALENDAR */
                if (kind == ICAL_VCALENDAR_COMPONENT) {
                    /* VCALENDAR MUST only appear at toplevel */
                    error->precond = CALDAV_VALID_FILTER;
                    error->desc = "VCALENDAR can only be toplevel component";
                }
                else *flags |= PARSE_ICAL;
                break;
            }
        }

        if (!error->precond) {
            attr = xmlGetProp(root, BAD_CAST "test");
            if (attr) {
                if (!xmlStrcmp(attr, BAD_CAST "anyof")) (*comp)->allof = 0;
                else if (xmlStrcmp(attr, BAD_CAST "allof")) {
                    error->precond = CALDAV_SUPP_FILTER;
                    error->desc = "Unsupported test";
                    error->node = xmlCopyNode(root, 2);
                }
                xmlFree(attr);
            }
        }
    }

    for (node = xmlFirstElementChild(root); node && !error->precond;
         node = xmlNextElementSibling(node)) {

        if ((*comp)->not_defined) {
            error->precond = CALDAV_SUPP_FILTER;
            error->desc = DAV_FILTER_ISNOTDEF_ERR;
            error->node = xmlCopyNode(root, 1);
        }
        else if (!xmlStrcmp(node->name, BAD_CAST "is-not-defined")) {
            if ((*comp)->range || (*comp)->prop || (*comp)->comp) {
                error->precond = CALDAV_SUPP_FILTER;
                error->desc = DAV_FILTER_ISNOTDEF_ERR;
                error->node = xmlCopyNode(root, 1);
            }
            else (*comp)->not_defined = 1;
        }
        else if (!xmlStrcmp(node->name, BAD_CAST "time-range")) {
            if ((*comp)->range) {
                error->precond = CALDAV_SUPP_FILTER;
                error->desc = "Multiple time-range";
                error->node = xmlCopyNode(root, 1);
            }
            else {
                switch ((*comp)->kind) {
                case ICAL_ANY_COMPONENT:
                case ICAL_VEVENT_COMPONENT:
                case ICAL_VTODO_COMPONENT:
                case ICAL_VJOURNAL_COMPONENT:
                case ICAL_VFREEBUSY_COMPONENT:
                case ICAL_VAVAILABILITY_COMPONENT:
                case ICAL_VPOLL_COMPONENT:
                    parse_timerange(node, &(*comp)->range, error);
                    break;

                default:
                    error->precond = CALDAV_SUPP_FILTER;
                    error->desc = "time-range unsupported for this component";
                    error->node = xmlCopyNode(root, 1);
                    break;
                }
            }

            if (depth != 1) *flags |= PARSE_ICAL;
        }
        else if (!xmlStrcmp(node->name, BAD_CAST "prop-filter")) {
            struct prop_filter *prop = NULL;

            *flags |= PARSE_ICAL;

            dav_parse_propfilter(node, &prop, &profile, error);
            if (prop) {
                if ((*comp)->prop) prop->next = (*comp)->prop;
                (*comp)->prop = prop;
            }
            if (prop->match) {
                if (prop->other || prop->match->next) {
                    error->precond = CALDAV_SUPP_FILTER;
                    error->desc = prop->match->next ? "Multiple text-match" :
                        "time-range can NOT be combined with text-match";
                    error->node = xmlCopyNode(node, 1);
                }
            }
        }
        else if (!xmlStrcmp(node->name, BAD_CAST "comp-filter")) {
            struct comp_filter *subcomp = NULL;

            parse_compfilter(node, depth + 1, &subcomp,
                             flags, comp_types, error);
            if (subcomp) {
                if ((*comp)->comp) subcomp->next = (*comp)->comp;
                (*comp)->comp = subcomp;
            }
        }
        else {
            error->precond = CALDAV_SUPP_FILTER;
            error->desc = "Unsupported element in comp-filter";
            error->node = xmlCopyNode(root, 1);
        }
    }
}

static int parse_calfilter(xmlNodePtr root, struct calquery_filter *filter,
                           struct error_t *error)
{
    xmlNodePtr node;

    /* Parse elements of filter */
    node = xmlFirstElementChild(root);
    if (node && !xmlStrcmp(node->name, BAD_CAST "comp-filter")) {
        parse_compfilter(node, 0, &filter->comp,
                         &filter->flags, &filter->comp_types, error);
    }
    else {
        error->precond = CALDAV_VALID_FILTER;
        error->desc = "missing comp-filter element";
    }

    return error->precond ? HTTP_FORBIDDEN : 0;
}


static int apply_paramfilter(struct param_filter *paramfilter,
                             icalproperty *prop)
{
    int pass = 1;
    icalparameter *param =
        icalproperty_get_first_parameter(prop, paramfilter->kind);

    if (paramfilter->kind == ICAL_X_PARAMETER) {
        /* Find the first X- parameter with matching name */
        for (; param && strcmp((const char *) paramfilter->name,
                               icalparameter_get_xname(param));
             param = icalproperty_get_next_parameter(prop, paramfilter->kind));
    }

    if (!param) return paramfilter->not_defined;
    if (paramfilter->not_defined) return 0;
    if (!paramfilter->match) return 1;

    /* Test each instance of this parameter (logical OR) */
    do {
        const char *text;

        if (!pass && (paramfilter->kind == ICAL_X_PARAMETER) &&
            strcmp((const char *) paramfilter->name,
                   icalparameter_get_xname(param))) {
            /* Skip X- parameter if name doesn't match */
            continue;
        }

        text = icalparameter_get_iana_value(param);
        pass = dav_apply_textmatch(BAD_CAST text, paramfilter->match);

    } while (!pass &&
             (param = icalproperty_get_next_parameter(prop, paramfilter->kind)));

    return pass;
}

static int apply_prop_timerange(struct icalperiodtype *range, icalproperty *prop)
{
    icalvalue *value = icalproperty_get_value(prop);
    struct icalperiodtype period = icalperiodtype_null_period();
    icalparameter *param;

    switch (icalvalue_isa(value)) {
    case ICAL_DATE_VALUE:
        period.start = icalvalue_get_date(value);
        period.start.is_date = 0;  /* MUST be DATE-TIME */
        break;

    case ICAL_DATETIME_VALUE:
        period.start = icalvalue_get_datetime(value);
        break;

    case ICAL_PERIOD_VALUE:
        period = icalvalue_get_period(value);
        break;

    default:
        /* Should never get here */
        break;
    }

    /* Set the timezone, if any, on the start time */
    if ((param = icalproperty_get_first_parameter(prop, ICAL_TZID_PARAMETER))) {
        const char *tzid = icalparameter_get_tzid(param);
        icaltimezone *tz = NULL;
        icalcomponent *comp;

        for (comp = icalproperty_get_parent(prop); comp;
             comp = icalcomponent_get_parent(comp)) {
            tz = icalcomponent_get_timezone(comp, tzid);
            if (tz) break;
        }

        if (!tz) tz = icaltimezone_get_builtin_timezone_from_tzid(tzid);

        if (tz) period.start = icaltime_set_timezone(&period.start, tz);
    }

    if (!icaldurationtype_is_null_duration(period.duration)) {
        /* Calculate end time from duration */
        period.end = icaltime_add(period.start, period.duration);
    }
    else if (icaltime_is_null_time(period.end)) period.end = period.start;

    /* Convert to UTC for comparison with range */
    period.start = icaltime_convert_to_zone(period.start, utc_zone);
    period.end = icaltime_convert_to_zone(period.end, utc_zone);

    if (icaltime_compare(period.start, range->end) >= 0 ||
        icaltime_compare(period.end, range->start) <= 0) {
        /* Starts later or ends earlier than range */
        return 0;
    }

    return 1;
}

static int apply_propfilter(struct prop_filter *propfilter, icalcomponent *comp)
{
    int pass = 1;
    icalproperty *prop =
        icalcomponent_get_first_property(comp, propfilter->kind);

    if (propfilter->kind == ICAL_X_PROPERTY) {
        /* Find the first X- property with matching name */
        for (; prop && strcmp((const char *) propfilter->name,
                              icalproperty_get_property_name(prop));
             prop = icalcomponent_get_next_property(comp, propfilter->kind));
    }

    if (!prop) return propfilter->not_defined;
    if (propfilter->not_defined) return 0;
    if (!(propfilter->other || propfilter->match || propfilter->param)) return 1;

    /* Test each instance of this property (logical OR) */
    do {
        struct param_filter *paramfilter;

        if (!pass && (propfilter->kind == ICAL_X_PROPERTY) &&
            strcmp((const char *) propfilter->name,
                   icalproperty_get_property_name(prop))) {
            /* Skip X- property if name doesn't match */
            continue;
        }

        pass = propfilter->allof;

        if (propfilter->other) {
            pass = apply_prop_timerange(propfilter->other, prop);
        }
        else if (propfilter->match) {
            const char *text = icalproperty_get_value_as_string(prop);

            pass = dav_apply_textmatch(BAD_CAST text, propfilter->match);
        }

        /* Apply each param-filter, breaking if allof fails or anyof succeeds */
        for (paramfilter = propfilter->param;
             paramfilter && (pass == propfilter->allof);
             paramfilter = paramfilter->next) {

            pass = apply_paramfilter(paramfilter, prop);
        }

    } while (!pass &&
             (prop = icalcomponent_get_next_property(comp, propfilter->kind)));

    return pass;
}

static void in_range(icalcomponent *comp __attribute__((unused)),
                     struct icaltime_span *span __attribute__((unused)),
                     void *rock)
{
    int *pass = (int *) rock;

    *pass = 1;
}

static int apply_comp_timerange(struct comp_filter *compfilter,
                                icalcomponent *comp, struct caldav_data *cdata,
                                struct propfind_ctx *fctx)
{
    struct icalperiodtype *range = compfilter->range;
    struct icaltimetype dtstart;
    struct icaltimetype dtend;
    int pass = 0;

    if (compfilter->depth == 1) {
        /* Use period from cdata */
        dtstart = icaltime_from_string(cdata->dtstart);
        dtend = icaltime_from_string(cdata->dtend);

        if (icaltime_compare(dtstart, range->end) >= 0 ||
            icaltime_compare(dtend, range->start) <= 0) {
            /* All occurrences start later or end earlier than range */
            return 0;
        }
        if (compfilter->kind == ICAL_VAVAILABILITY_COMPONENT) {
            /* Don't try to expand VAVAILABILITY, just mark it as in range */
            return 1;
        }
        if (cdata->comp_flags.recurring) {
            if (!(compfilter->prop || compfilter->comp) &&
                (icaltime_compare(dtstart, range->start) >= 0 ||
                 icaltime_compare(dtend, range->end) <= 0)) {
                /* An occurrence (possibly override) starts or ends within range
                   and we don't need to do further filtering of the comp */
                return 1;
            }

            /* Load message containing the resource and parse iCal data */
            if (!comp) {
                if (!fctx->msg_buf.len) {
                    mailbox_map_record(fctx->mailbox,
                                       fctx->record, &fctx->msg_buf);
                }
                if (fctx->msg_buf.len && !fctx->obj) {
                    fctx->obj =
                        icalparser_parse_string(buf_cstring(&fctx->msg_buf) +
                                                fctx->record->header_size);
                }
                if (!fctx->obj) return 0;
                comp = icalcomponent_get_first_component(fctx->obj,
                                                         compfilter->kind);
            }
        }
        else {
            /* Non-recurring component overlaps range */
            return 1;
        }
    }

    /* Process component */
    if (!comp) return 0;

    icalcomponent_foreach_recurrence(comp, range->start, range->end,
                                     in_range, &pass);

    return pass;
}

/* See if the current resource matches the specified filter.
 * Returns 1 if match, 0 otherwise.
 */
static int apply_compfilter(struct comp_filter *compfilter, icalcomponent *ical,
                            struct caldav_data *cdata, struct propfind_ctx *fctx)
{
    int pass = 0;
    icalcomponent *comp = NULL;

    if (ical) {
        if (compfilter->kind == ICAL_VCALENDAR_COMPONENT) comp = ical;
        else comp = icalcomponent_get_first_component(ical, compfilter->kind);
    }

    /* XXX  Do we need to handle X- components?
       It doesn't appear that libical currently deals with them.
    */

    if (ical && !comp) return compfilter->not_defined;
    if (compfilter->not_defined) return 0;
    if (!(compfilter->range || compfilter->prop || compfilter->comp)) return 1;

    /* Test each instance of this component (logical OR) */
    do {
        struct prop_filter *propfilter;
        struct comp_filter *subfilter;

        pass = compfilter->allof;

        if (compfilter->range) {
            pass = apply_comp_timerange(compfilter, comp, cdata, fctx);
        }

        /* Apply each prop-filter, breaking if allof fails or anyof succeeds */
        for (propfilter = compfilter->prop;
             propfilter && (pass == compfilter->allof);
             propfilter = propfilter->next) {

            pass = apply_propfilter(propfilter, comp);
        }

        /* Apply each comp-filter, breaking if allof fails or anyof succeeds */
        for (subfilter = compfilter->comp;
             subfilter && (pass == compfilter->allof);
             subfilter = subfilter->next) {

            pass = apply_compfilter(subfilter, comp, cdata, fctx);
        }

    } while (!pass &&
             (comp = icalcomponent_get_next_component(ical, compfilter->kind)));

    return pass;
}

/* See if the current resource matches the specified filter.
 * Returns 1 if match, 0 otherwise.
 */
static int apply_calfilter(struct propfind_ctx *fctx, void *data)
{
    struct calquery_filter *calfilter =
        (struct calquery_filter *) fctx->filter_crit;
    struct caldav_data *cdata = (struct caldav_data *) data;
    icalcomponent *ical = fctx->obj;

    if (calfilter->comp_types) {
        /* Check comp-filter vs component type of resource */
        if (!(cdata->comp_type & calfilter->comp_types)) return 0;
    }

    if (calfilter->flags & PARSE_ICAL) {
        /* Load message containing the resource and parse iCal data */
        if (!ical) {
            if (!fctx->msg_buf.len)
                mailbox_map_record(fctx->mailbox, fctx->record, &fctx->msg_buf);
            if (!fctx->msg_buf.len) return 0;

            ical = fctx->obj =
                icalparser_parse_string(buf_cstring(&fctx->msg_buf) +
                                        fctx->record->header_size);
        }
        if (!ical) return 0;
    }

    return apply_compfilter(calfilter->comp, ical, cdata, fctx);
}


static void free_compfilter(struct comp_filter *comp)
{
    struct comp_filter *subcomp, *nextc;
    struct prop_filter *prop, *nextp;

    if (!comp) return;

    xmlFree(comp->name);
    if (comp->range) free(comp->range);

    for (prop = comp->prop; prop; prop = nextp) {
        nextp = prop->next;

        if (prop->other) free(prop->other);
        dav_free_propfilter(prop);
    }
    for (subcomp = comp->comp; subcomp; subcomp = nextc) {
        nextc = subcomp->next;

        free_compfilter(subcomp);
    }

    free(comp);
}


/* dav_foreach() callback to find props on a CalDAV resource
 *
 * This function will strip any known VTIMEZONEs from the existing resource
 * and store as a new resource before returning properties
 */
static int caldav_propfind_by_resource(void *rock, void *data)
{
    struct propfind_ctx *fctx = (struct propfind_ctx *) rock;
    struct caldav_data *cdata = (struct caldav_data *) data;

    if (sqlite3_libversion_number() < 3003008) {
        /* Can't write to a table while a SELECT is active */
        goto done;
    }

    if (cdata->dav.imap_uid && !cdata->comp_flags.tzbyref) {
        struct index_record record;
        int r;

        /* Relock index for writing */
        if (!mailbox_index_islocked(fctx->mailbox, 1)) {
            mailbox_unlock_index(fctx->mailbox, NULL);
            r = mailbox_lock_index(fctx->mailbox, LOCK_EXCLUSIVE);
            if (r) {
                syslog(LOG_ERR, "relock index(%s) failed: %s",
                       fctx->mailbox->name, error_message(r));
                goto done;
            }
        }

        if (!fctx->record) {
            /* Fetch index record for the resource */
            r = mailbox_find_index_record(fctx->mailbox,
                                          cdata->dav.imap_uid, &record);
            /* XXX  Check errors */

            fctx->record = r ? NULL : &record;
        }

        if (fctx->record) {
            char *schedule_address = NULL;
            icalcomponent *ical =
                record_to_ical(fctx->mailbox, fctx->record, &schedule_address);
            struct transaction_t txn;

            if (!ical) {
                syslog(LOG_NOTICE,
                       "Unable to parse iCal %s:%u prior to stripping TZ",
                       fctx->mailbox->name, fctx->record->uid);
                free(schedule_address);
                goto done;
            }

            memset(&txn, 0, sizeof(struct transaction_t));
            txn.req_hdrs = spool_new_hdrcache();

            caldav_store_resource(&txn, ical, fctx->mailbox,
                                  cdata->dav.resource, fctx->davdb,
                                  TZ_STRIP | (!cdata->sched_tag ? NEW_STAG : 0),
                                  schedule_address);
            spool_free_hdrcache(txn.req_hdrs);
            buf_free(&txn.buf);
            free(schedule_address);

            icalcomponent_free(ical);

            caldav_lookup_resource(fctx->davdb, fctx->mailbox->name,
                                   cdata->dav.resource, &cdata, 0);
            fctx->record = NULL;
        }
    }

  done:
    return propfind_by_resource(rock, data);
}


/* Callback to fetch DAV:getcontenttype */
static int propfind_getcontenttype(const xmlChar *name, xmlNsPtr ns,
                                   struct propfind_ctx *fctx,
                                   xmlNodePtr prop __attribute__((unused)),
                                   xmlNodePtr resp __attribute__((unused)),
                                   struct propstat propstat[],
                                   void *rock __attribute__((unused)))
{
    buf_setcstr(&fctx->buf, ICALENDAR_CONTENT_TYPE);

    if (fctx->data) {
        struct caldav_data *cdata = (struct caldav_data *) fctx->data;
        const char *comp = NULL;

        switch (cdata->comp_type) {
        case CAL_COMP_VEVENT: comp = "VEVENT"; break;
        case CAL_COMP_VTODO: comp = "VTODO"; break;
        case CAL_COMP_VJOURNAL: comp = "VJOURNAL"; break;
        case CAL_COMP_VFREEBUSY: comp = "VFREEBUSY"; break;
        case CAL_COMP_VAVAILABILITY: comp = "VAVAILABILITY"; break;
        case CAL_COMP_VPOLL: comp = "VPOLL"; break;
        }

        if (comp) buf_printf(&fctx->buf, "; component=%s", comp);
    }

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
                            void *rock)
{
    xmlNodePtr node = xml_add_prop(HTTP_OK, fctx->ns[NS_DAV],
                                   &propstat[PROPSTAT_OK], name, ns, NULL, 0);

    if (!fctx->record) {
        xmlNewChild(node, NULL, BAD_CAST "collection", NULL);

        if (fctx->req_tgt->collection &&
            fctx->mbentry->mbtype == MBTYPE_CALENDAR) {
            ensure_ns(fctx->ns, NS_CALDAV,
                      resp ? resp->parent : node->parent, XML_NS_CALDAV, "C");
            if (!strcmp(fctx->req_tgt->collection, SCHED_INBOX)) {
                xmlNewChild(node, fctx->ns[NS_CALDAV],
                            BAD_CAST "schedule-inbox", NULL);
            }
            else if (!strcmp(fctx->req_tgt->collection, SCHED_OUTBOX)) {
                xmlNewChild(node, fctx->ns[NS_CALDAV],
                            BAD_CAST "schedule-outbox", NULL);
            }
            else {
                xmlNewChild(node, fctx->ns[NS_CALDAV],
                            BAD_CAST "calendar", NULL);
                if (rock) {
                    /* Called from PROPFIND - include "shared[-owner]" type */
                    xml_add_shareaccess(fctx, resp, node, 1 /* legacy */);
                }
            }
        }
    }

    return 0;
}

#define PROP_NOVALUE (1<<31)

static struct partial_comp_t *parse_partial_comp(xmlNodePtr node)
{
    xmlChar *prop;
    struct partial_comp_t *pcomp;

    prop = xmlGetProp(node, BAD_CAST "name");
    if (!prop) return NULL;

    pcomp = xzmalloc(sizeof(struct partial_comp_t));
    pcomp->kind = icalcomponent_string_to_kind((char *) prop);
    xmlFree(prop);

    for (node = xmlFirstElementChild(node); node;
         node = xmlNextElementSibling(node)) {
        if (!xmlStrcmp(node->name, BAD_CAST "allprop")) {
            arrayu64_add(&pcomp->props, ICAL_ANY_PROPERTY);
        }
        else if (!xmlStrcmp(node->name, BAD_CAST "prop")) {
            uint64_t kind = ICAL_NO_PROPERTY;

            prop = xmlGetProp(node, BAD_CAST "name");
            if (prop) {
                kind = icalproperty_string_to_kind((char *) prop);
                xmlFree(prop);
 
                prop = xmlGetProp(node, BAD_CAST "novalue");
                if (prop) {
                    if (!xmlStrcmp(prop, BAD_CAST "yes")) {
                        /* Set highest order bit to encode "novalue" */
                        kind |= PROP_NOVALUE;
                    }
                    xmlFree(prop);
                }
            }
            arrayu64_add(&pcomp->props, kind);
        }
        else if (!xmlStrcmp(node->name, BAD_CAST "allcomp")) {
            pcomp->child = xzmalloc(sizeof(struct partial_comp_t));
            pcomp->child->kind = ICAL_ANY_COMPONENT;
            break;
        }
        else if (!xmlStrcmp(node->name, BAD_CAST "comp")) {
            struct partial_comp_t *child = parse_partial_comp(node);
            child->sibling = pcomp->child;
            pcomp->child = child;
        }
    }

    return pcomp;
}

static void prune_properties(icalcomponent *parent,
                             struct partial_comp_t *pcomp)
{
    icalcomponent *comp, *next;
    int n, size = arrayu64_size(&pcomp->props);

    if (!size || arrayu64_nth(&pcomp->props, 0) != ICAL_ANY_PROPERTY) {
        /* Strip unwanted properties from component */
        icalproperty *prop, *nextprop;

        for (prop = icalcomponent_get_first_property(parent, ICAL_ANY_PROPERTY);
             prop; prop = nextprop) {
            nextprop =
                icalcomponent_get_next_property(parent, ICAL_ANY_PROPERTY);

            uint64_t kind;

            for (n = 0; n < size; n++) {
                kind = arrayu64_nth(&pcomp->props, n);
                /* Highest order bit encodes "novalue" */
                if ((kind & ~PROP_NOVALUE) == icalproperty_isa(prop)) break;
            }

            if (n >= size) {
                /* Don't want this property, remove it */
                icalcomponent_remove_property(parent, prop);
                icalproperty_free(prop);
            }
            else if (kind & PROP_NOVALUE) {
                /* Don't want value for this property, remove it */
                /* XXX  This requires libical (<= 2.x) to be compiled with
                   ICAL_ALLOW_EMPTY_PROPERTIES=true
                   otherwise icalproperty_as_ical_string() will output
                   "ERROR: No Value" as the property value */
                icalproperty_set_value(prop, icalvalue_new(ICAL_NO_VALUE));
            }
        }
    }

    if (pcomp->child && pcomp->child->kind == ICAL_ANY_COMPONENT) return;

    /* Strip unwanted components from component */
    for (comp = icalcomponent_get_first_component(parent, ICAL_ANY_COMPONENT);
         comp; comp = next) {
        icalcomponent_kind kind = icalcomponent_isa(comp);
        struct partial_comp_t *child;

        next = icalcomponent_get_next_component(parent, ICAL_ANY_COMPONENT);

        for (child = pcomp->child; child; child = child->sibling) {
            if (child->kind == kind) break;
        }
        if (child) prune_properties(comp, child);
        else {
            icalcomponent_remove_component(parent, comp);
            icalcomponent_free(comp);
        }
    }
}

static int expand_cb(icalcomponent *comp,
                     icaltimetype start, icaltimetype end, void *rock)
{
    icalcomponent *ical = icalcomponent_get_parent(comp);
    icalcomponent *expanded_ical = (icalcomponent *) rock;
    icalproperty *prop, *nextprop, *recurid = NULL;
    struct icaldatetimeperiodtype dtp;
    icaltimetype dtstart;

    start = icaltime_convert_to_zone(start, utc_zone);
    end = icaltime_convert_to_zone(end, utc_zone);

    /* Fetch/set/remove interesting properties */
    for (prop = icalcomponent_get_first_property(comp, ICAL_ANY_PROPERTY);
         prop; prop = nextprop) {
        nextprop = icalcomponent_get_next_property(comp, ICAL_ANY_PROPERTY);

        switch (icalproperty_isa(prop)) {
        case ICAL_DTSTART_PROPERTY:
            /* Fetch exiting DTSTART (might be master) */
            dtp = icalproperty_get_datetimeperiod(prop);
            dtstart = icaltime_convert_to_zone(dtp.time, utc_zone);

            /* Set DTSTART to be for this occurrence (in UTC) */
            icalproperty_set_dtstart(prop, start);
            icalproperty_remove_parameter_by_kind(prop, ICAL_TZID_PARAMETER);
            break;

        case ICAL_DTEND_PROPERTY:
            /* Set DTEND to be for this occurrence (in UTC) */
            icalproperty_set_dtend(prop, end);
            icalproperty_remove_parameter_by_kind(prop, ICAL_TZID_PARAMETER);
            break;
            
        case ICAL_DURATION_PROPERTY:
            /* Set DURATION to be for this occurrence */
            icalproperty_set_duration(prop, icaltime_subtract(end, start));
            break;
            
        case ICAL_RECURRENCEID_PROPERTY:
            /* Reset RECURRENCE-ID of this override to UTC */
            dtp = icalproperty_get_datetimeperiod(prop);
            dtp.time = icaltime_convert_to_zone(dtp.time, utc_zone);
            icalproperty_set_recurrenceid(prop, dtp.time);
            icalproperty_remove_parameter_by_kind(prop, ICAL_TZID_PARAMETER);
            recurid = prop;

            /* Remove component from existing ical (we can use it as-is)  */
            icalcomponent_remove_component(ical, comp);
            break;

        case ICAL_RRULE_PROPERTY:
        case ICAL_RDATE_PROPERTY:
        case ICAL_EXRULE_PROPERTY:
        case ICAL_EXDATE_PROPERTY:
            /* We don't want any recurrence rule properties */
            icalcomponent_remove_property(comp, prop);
            icalproperty_free(prop);
            break;

        default:
            break;
        }
    }

    if (!recurid) {
        /* Master component */
        if (!icaltime_compare(start, dtstart)) {
            /* First instance -
               remove component from existing ical (we can use it as-is)  */
            icalcomponent_remove_component(ical, comp);
        }
        else {
            /* Clone the component and set RECURRENCE-ID */
            comp = icalcomponent_new_clone(comp);
            icalcomponent_set_recurrenceid(comp, start);
        }
    }

    /* Append the component to expanded ical */
    icalcomponent_add_component(expanded_ical, comp);

    return 1;
}

/* Expand recurrences of ical in range.
   NOTE: expand_cb() is destructive of ical as it builds expanded_ical */
static icalcomponent *expand_caldata(icalcomponent **ical,
                                     struct icalperiodtype range)
{
    icalcomponent *expanded_ical =
        icalcomponent_vanew(ICAL_VCALENDAR_COMPONENT,
                            icalproperty_new_version("2.0"),
                            icalproperty_new_prodid(ical_prodid),
                            0);

    /* Copy over any CALSCALE property */
    icalproperty *prop =
        icalcomponent_get_first_property(*ical, ICAL_CALSCALE_PROPERTY);
    if (prop)
        icalcomponent_add_property(expanded_ical, icalproperty_new_clone(prop));

    icalcomponent_myforeach(*ical, range, NULL, expand_cb, expanded_ical);
    icalcomponent_free(*ical);
    *ical = expanded_ical;
    
    return *ical;
}

static void limit_caldata(icalcomponent *ical, struct icalperiodtype *limit)
{
    icaltime_span limitspan;
    icaltimetype dtstart, dtend, recurid;
    struct icaldurationtype dtduration = icaldurationtype_null_duration();
    icalcomponent *comp, *nextcomp;
    icalcomponent_kind kind;

    limitspan.start = icaltime_as_timet_with_zone(limit->start, utc_zone);
    limitspan.end = icaltime_as_timet_with_zone(limit->end, utc_zone);

    comp = icalcomponent_get_first_real_component(ical);
    kind = icalcomponent_isa(comp);

    /* Find master component */
    for (; comp; comp = icalcomponent_get_next_component(ical, kind)) {

        recurid = icalcomponent_get_recurrenceid_with_zone(comp);

        if (icaltime_is_null_time(recurid)) {
            /* Calculate duration of master component */
            dtstart = icalcomponent_get_dtstart(comp);
            dtend = icalcomponent_get_dtend(comp);
            dtduration = icaltime_subtract(dtend, dtstart);
            break;
        }
    }

    /* Check spans of each override against our limit span */
    for (comp = icalcomponent_get_first_component(ical, kind);
         comp; comp = nextcomp) {

        icaltime_span recurspan;

        nextcomp = icalcomponent_get_next_component(ical, kind);
        recurid = icalcomponent_get_recurrenceid_with_zone(comp);

        /* Skip master component */
        if (icaltime_is_null_time(recurid)) continue;

        /* Check span of override */
        dtstart = icalcomponent_get_dtstart(comp);
        dtend = icalcomponent_get_dtend(comp);
        recurspan = icaltime_span_new(dtstart, dtend, 1);
        if (icaltime_span_overlaps(&recurspan, &limitspan)) continue;

        /* Check span of original occurrence */
        dtstart = recurid;
        dtend = icaltime_add(dtstart, dtduration);
        recurspan = icaltime_span_new(dtstart, dtend, 1);
        if (icaltime_span_overlaps(&recurspan, &limitspan)) continue;

        /* Remove this component (doesn't overlap limit range) */
        icalcomponent_remove_component(ical, comp);
        icalcomponent_free(comp);
    }
}

/* Callback to prescreen/fetch CALDAV:calendar-data */
static int propfind_scheduser(const xmlChar *name, xmlNsPtr ns,
                            struct propfind_ctx *fctx,
                            xmlNodePtr prop __attribute__((unused)),
                            xmlNodePtr resp __attribute__((unused)),
                            struct propstat propstat[],
                            void *rock __attribute__((unused)))
{
    struct buf buf = BUF_INITIALIZER;
    int rc = HTTP_NOT_FOUND;

    if (propstat && fctx->mailbox && fctx->record) {
        message_t *m = message_new_from_record(fctx->mailbox, fctx->record);

        message_get_field(m, "x-schedule-user-address",
                          MESSAGE_DECODED|MESSAGE_TRIM, &buf);

        message_unref(&m);
    }

    if (buf.len) {
        rc = 0;
        xmlNodePtr node = xml_add_prop(HTTP_OK, fctx->ns[NS_DAV], &propstat[PROPSTAT_OK],
                                       name, ns, NULL, 0);
        buf_reset(&fctx->buf);
        buf_printf(&fctx->buf, "mailto:%s", buf_cstring(&buf));
        xml_add_href(node, fctx->ns[NS_DAV], buf_cstring(&fctx->buf));
    }

    buf_free(&buf);

    return rc;
}

/* Callback to prescreen/fetch CALDAV:calendar-data */
static int propfind_caldata(const xmlChar *name, xmlNsPtr ns,
                            struct propfind_ctx *fctx,
                            xmlNodePtr prop,
                            xmlNodePtr resp __attribute__((unused)),
                            struct propstat propstat[],
                            void *rock)
{
    struct partial_caldata_t *partial = (struct partial_caldata_t *) rock;
    struct caldav_data *cdata = (struct caldav_data *) fctx->data;
    static unsigned need_tz = 0;
    const char *data = NULL;
    size_t datalen = 0;
    int r = 0;

    if (propstat) {
        icalcomponent *ical = NULL;

        if (!fctx->record) return HTTP_NOT_FOUND;

        if (!fctx->msg_buf.len)
            mailbox_map_record(fctx->mailbox, fctx->record, &fctx->msg_buf);
        if (!fctx->msg_buf.len) return HTTP_SERVER_ERROR;

        data = fctx->msg_buf.s + fctx->record->header_size;
        datalen = fctx->record->size - fctx->record->header_size;

        if (need_tz) {
            if (cdata->comp_flags.tzbyref) {
                /* Add VTIMEZONE components for known TZIDs */
                struct timezone_rock tzrock = { NULL, NULL };
                icalcomponent *comp, *next;
                icalcomponent_kind kind;

                if (!fctx->obj) fctx->obj = icalparser_parse_string(data);
                ical = fctx->obj;
                tzrock.new = ical;

                comp = icalcomponent_get_first_real_component(ical);
                kind = icalcomponent_isa(comp);
                for (; comp; comp = next) {
                    next = icalcomponent_get_next_component(ical, kind);
                    icalcomponent_foreach_tzid(comp, &add_timezone, &tzrock);
                }
            }
        }
        else if (!cdata->comp_flags.tzbyref &&
                 (namespace_calendar.allow & ALLOW_CAL_NOTZ)) {
            /* Strip all VTIMEZONE components for known TZIDs */
            if (!fctx->obj) fctx->obj = icalparser_parse_string(data);
            ical = fctx->obj;

            strip_vtimezones(ical);
        }

        if (!icaltime_is_null_time(partial->range.start)) {
            /* Expand/limit recurrence set */
            if (!fctx->obj) fctx->obj = icalparser_parse_string(data);
            ical = fctx->obj;

            if (partial->expand) {
                fctx->obj = expand_caldata(&ical, partial->range);
            }
            else limit_caldata(ical, &partial->range);
        }

        if (partial->comp) {
            /* Limit returned properties */
            if (!fctx->obj) fctx->obj = icalparser_parse_string(data);
            ical = fctx->obj;
            prune_properties(ical, partial->comp);
        }

        if (ical) {
            /* Create iCalendar data from new ical component */
            data = icalcomponent_as_ical_string(ical);
            datalen = strlen(data);
        }
    }
    else if (prop) {
        /* Prescreen "property" request - read partial/expand children */
        xmlNodePtr node;

        /* Check for optional CalDAV-Timezones header */
        const char **hdr =
            spool_getheader(fctx->txn->req_hdrs, "CalDAV-Timezones");
        if (hdr && !strcmp(hdr[0], "T")) need_tz = 1;
        else need_tz = 0;

        /* Initialize expand to be "empty" */
        partial->range.start = icaltime_null_time();
        partial->range.end = icaltime_null_time();
        partial->comp = NULL;

        /* Check for and parse child elements of CALDAV:calendar-data */
        for (node = xmlFirstElementChild(prop); node;
             node = xmlNextElementSibling(node)) {
            xmlChar *prop;

            if (!xmlStrcmp(node->name, BAD_CAST "expand") ||
                !xmlStrcmp(node->name, BAD_CAST "limit-recurrence-set")) {
                partial->expand = (node->name[0] == 'e');
                prop = xmlGetProp(node, BAD_CAST "start");
                if (!prop) return (*fctx->ret = HTTP_BAD_REQUEST);
                partial->range.start = icaltime_from_string((char *) prop);
                xmlFree(prop);

                prop = xmlGetProp(node, BAD_CAST "end");
                if (!prop) return (*fctx->ret = HTTP_BAD_REQUEST);
                partial->range.end = icaltime_from_string((char *) prop);
                xmlFree(prop);
            }
            else if (!xmlStrcmp(node->name, BAD_CAST "comp")) {
                partial->comp = parse_partial_comp(node);
                if (!partial->comp ||
                    partial->comp->kind != ICAL_VCALENDAR_COMPONENT) {
                    return (*fctx->ret = HTTP_BAD_REQUEST);
                }
            }
            else if (!xmlStrcmp(node->name, BAD_CAST "limit-freebusy-set")) {
                syslog(LOG_NOTICE,
                       "Client attempted to use CALDAV:limit-freebusy-set");
                return (*fctx->ret = HTTP_NOT_IMPLEMENTED);
            }
        }

        if (namespace_calendar.allow & ALLOW_CAL_NOTZ) {
            /* We want to strip known VTIMEZONEs */
            fctx->proc_by_resource = &caldav_propfind_by_resource;
        }
    }
    else {
        /* Cleanup "property" request - free partial component structure */
        struct partial_comp_t *pcomp, *child, *sibling;

        for (pcomp = partial->comp; pcomp; pcomp = child) {
            child = pcomp->child;

            do {
                sibling = pcomp->sibling;
                arrayu64_fini(&pcomp->props);
                free(pcomp);
            } while ((pcomp = sibling));
        }

        return 0;
    }

    r = propfind_getdata(name, ns, fctx, prop, propstat, caldav_mime_types,
                         CALDAV_SUPP_DATA, data, datalen);

    return r;
}


/* Callback to fetch CALDAV:calendar-home-set,
 * CALDAV:schedule-inbox-URL, CALDAV:schedule-outbox-URL,
 * and CALDAV:schedule-default-calendar-URL
 */
int propfind_calurl(const xmlChar *name, xmlNsPtr ns,
                    struct propfind_ctx *fctx,
                    xmlNodePtr prop,
                    xmlNodePtr resp __attribute__((unused)),
                    struct propstat propstat[], void *rock)
{
    const char *cal = (const char *) rock;
    xmlNodePtr node;
    /* NOTE: calbuf needs to stay in scope until 'cal' is finished with */
    struct buf calbuf = BUF_INITIALIZER;
    int ret = HTTP_NOT_FOUND; /* error condition if we bail early */

    if (!(namespace_calendar.enabled && httpd_userid))
        goto done;

    if (cal) {
        /* named calendars are only used for scheduling */
        if (!(namespace_calendar.allow & ALLOW_CAL_SCHED))
            goto done;

        /* check for renamed calendars - property on the homeset */
        const char *annotname = NULL;
        if (!strcmp(cal, SCHED_DEFAULT)) {
            annotname =
                DAV_ANNOT_NS "<" XML_NS_CALDAV ">schedule-default-calendar";
        }
        else if (!strcmp(cal, SCHED_INBOX))
            annotname = DAV_ANNOT_NS "<" XML_NS_CALDAV ">schedule-inbox";
        else if (!strcmp(cal, SCHED_OUTBOX))
            annotname = DAV_ANNOT_NS "<" XML_NS_CALDAV ">schedule-outbox";

        if (annotname) {
            char *mailboxname = caldav_mboxname(httpd_userid, NULL);
            int r = annotatemore_lookupmask(mailboxname, annotname,
                                            httpd_userid, &calbuf);
            free(mailboxname);
            if (!r && calbuf.len) {
                buf_putc(&calbuf, '/');
                cal = buf_cstring(&calbuf);
            }
        }
    }

    node = xml_add_prop(HTTP_OK, fctx->ns[NS_DAV], &propstat[PROPSTAT_OK],
                        name, ns, NULL, 0);

    buf_reset(&fctx->buf);
    if (strchr(httpd_userid, '@') || !httpd_extradomain) {
        buf_printf(&fctx->buf, "%s/%s/%s/", namespace_calendar.prefix,
                   USER_COLLECTION_PREFIX, httpd_userid);
    }
    else {
        buf_printf(&fctx->buf, "%s/%s/%s@%s/", namespace_calendar.prefix,
                   USER_COLLECTION_PREFIX, httpd_userid, httpd_extradomain);
    }
    if (cal) buf_appendcstr(&fctx->buf, cal);

    if ((fctx->mode == PROPFIND_EXPAND) && xmlFirstElementChild(prop)) {
        /* Return properties for this URL */
        expand_property(prop, fctx, &namespace_calendar, buf_cstring(&fctx->buf),
                        &caldav_parse_path, caldav_props, node, cal ? 1 : 0);
    }
    else {
        /* Return just the URL */
        xml_add_href(node, fctx->ns[NS_DAV], buf_cstring(&fctx->buf));
    }

    ret = 0;
done:
    buf_free(&calbuf);

    return ret;
}


/* Callback to fetch CALDAV:schedule-default-calendar-URL */
static int propfind_scheddefault(const xmlChar *name, xmlNsPtr ns,
                                 struct propfind_ctx *fctx,
                                 xmlNodePtr prop, xmlNodePtr resp,
                                 struct propstat propstat[],
                                 void *rock __attribute__((unused)))
{
    /* Only defined on CALDAV:schedule-inbox-URL */
    if (fctx->req_tgt->flags != TGT_SCHED_INBOX) return HTTP_NOT_FOUND;

    return propfind_calurl(name, ns, fctx,
                           prop, resp, propstat, SCHED_DEFAULT);
}


/* Callback to fetch CALDAV:supported-calendar-component-set[s] */
static int propfind_calcompset(const xmlChar *name, xmlNsPtr ns,
                               struct propfind_ctx *fctx,
                               xmlNodePtr prop __attribute__((unused)),
                               xmlNodePtr resp __attribute__((unused)),
                               struct propstat propstat[],
                               void *rock __attribute__((unused)))
{
    struct buf attrib = BUF_INITIALIZER;
    const char *prop_annot =
        DAV_ANNOT_NS "<" XML_NS_CALDAV ">supported-calendar-component-set";
    unsigned long types = 0;
    xmlNodePtr set, node;
    const struct cal_comp_t *comp;
    int r = 0;

    if (!fctx->req_tgt->collection) return HTTP_NOT_FOUND;

    r = annotatemore_lookupmask(fctx->mbentry->name, prop_annot,
                                httpd_userid, &attrib);
    if (r) return HTTP_SERVER_ERROR;

    if (attrib.len) {
        types = strtoul(buf_cstring(&attrib), NULL, 10);
    }
    else {
        types = -1;  /* ALL components types */

        /* Apple clients don't like VPOLL */
        types &= ~CAL_COMP_VPOLL;
    }

    buf_free(&attrib);

    if (!types) return HTTP_NOT_FOUND;

    set = xml_add_prop(HTTP_OK, fctx->ns[NS_DAV], &propstat[PROPSTAT_OK],
                       name, ns, NULL, 0);
    if (!resp) {
        ensure_ns(fctx->ns, NS_CALDAV, set->parent, XML_NS_CALDAV, "C");
        xmlSetNs(set, fctx->ns[NS_CALDAV]);
    }

    /* Create "comp" elements from the stored bitmask */
    for (comp = cal_comps; comp->name; comp++) {
        if (types & comp->type) {
            node = xmlNewChild(set, fctx->ns[NS_CALDAV],
                               BAD_CAST "comp", NULL);
            xmlNewProp(node, BAD_CAST "name", BAD_CAST comp->name);
        }
    }

    return 0;
}


/* Callback to write supported-calendar-component-set property */
static int proppatch_calcompset(xmlNodePtr prop, unsigned set,
                                struct proppatch_ctx *pctx,
                                struct propstat propstat[],
                                void *rock __attribute__((unused)))
{
    unsigned precond = 0, force = 0;
    xmlChar *attr = xmlGetProp(prop, BAD_CAST "force");

    /* Check if we want to force changing of a protected property.
       This is mainly for our list_calendars() JavaScript client. */
    if (attr) {
        if (!xmlStrcmp(attr, BAD_CAST "yes") &&
            mboxname_userownsmailbox(httpd_userid, pctx->mailbox->name)) {
            force = 1;
        }
        xmlFree(attr);
    }

    if (set && (force || (pctx->txn->meth != METH_PROPPATCH))) {
        /* "Writeable" for MKCOL/MKCALENDAR only */
        xmlNodePtr cur;
        unsigned long types = 0;

        /* Work through the given list of components */
        for (cur = prop->children; cur; cur = cur->next) {
            xmlChar *name;
            const struct cal_comp_t *comp;

            /* Make sure its a "comp" element with a "name" */
            if (cur->type != XML_ELEMENT_NODE) continue;
            if (xmlStrcmp(cur->name, BAD_CAST "comp") ||
                !(name = xmlGetProp(cur, BAD_CAST "name"))) break;

            /* Make sure we have a valid component type */
            for (comp = cal_comps;
                 comp->name && xmlStrcmp(name, BAD_CAST comp->name); comp++);
            xmlFree(name);

            if (comp->name) types |= comp->type;   /* found match in our list */
            else break;                            /* no match - invalid type */
        }

        if (!cur) {
            /* All component types are valid */
            char typestr[(sizeof(unsigned long) * 8) / 3 + 1];
            sprintf(typestr, "%lu", types);

            proppatch_todb(prop, set, pctx, propstat, (void *) typestr);

            return 0;
        }

        /* Invalid component type */
        precond = CALDAV_SUPP_COMP;
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

/* Callback to fetch CALDAV:supported-calendar-data */
static int propfind_suppcaldata(const xmlChar *name, xmlNsPtr ns,
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

    for (mime = caldav_mime_types; mime->content_type; mime++) {
        xmlNodePtr type = xmlNewChild(node, fctx->ns[NS_CALDAV],
                                      BAD_CAST "calendar-data", NULL);

        /* Trim any charset from content-type */
        buf_reset(&fctx->buf);
        buf_printf(&fctx->buf, "%.*s",
                   (int) strcspn(mime->content_type, ";"), mime->content_type);

        xmlNewProp(type, BAD_CAST "content-type",
                   BAD_CAST buf_cstring(&fctx->buf));

        if (mime->version)
            xmlNewProp(type, BAD_CAST "version", BAD_CAST mime->version);
    }

    return 0;
}


/* Callback to fetch CALDAV:max-resource-size */
static int propfind_maxsize(const xmlChar *name, xmlNsPtr ns,
                            struct propfind_ctx *fctx,
                            xmlNodePtr prop __attribute__((unused)),
                            xmlNodePtr resp __attribute__((unused)),
                            struct propstat propstat[],
                            void *rock __attribute__((unused)))
{
    static int maxsize = 0;

    if (!fctx->req_tgt->collection) return HTTP_NOT_FOUND;

    if (!maxsize) {
        maxsize = config_getint(IMAPOPT_MAXMESSAGESIZE);
        if (!maxsize) maxsize = INT_MAX;
    }

    buf_reset(&fctx->buf);
    buf_printf(&fctx->buf, "%d", maxsize);
    xml_add_prop(HTTP_OK, fctx->ns[NS_DAV], &propstat[PROPSTAT_OK],
                 name, ns, BAD_CAST buf_cstring(&fctx->buf), 0);

    return 0;
}


/* Callback to fetch CALDAV:min/max-date-time */
static int propfind_minmaxdate(const xmlChar *name, xmlNsPtr ns,
                               struct propfind_ctx *fctx,
                               xmlNodePtr prop __attribute__((unused)),
                               xmlNodePtr resp __attribute__((unused)),
                               struct propstat propstat[],
                               void *rock)
{
    struct icaltimetype date;

    if (!fctx->req_tgt->collection) return HTTP_NOT_FOUND;

    date = icaltime_from_timet_with_zone(*((time_t *) rock), 0, utc_zone);

    xml_add_prop(HTTP_OK, fctx->ns[NS_DAV], &propstat[PROPSTAT_OK],
                 name, ns, BAD_CAST icaltime_as_ical_string(date), 0);

    return 0;
}


/* Callback to fetch CALDAV:schedule-tag */
static int propfind_schedtag(const xmlChar *name, xmlNsPtr ns,
                             struct propfind_ctx *fctx,
                             xmlNodePtr prop __attribute__((unused)),
                             xmlNodePtr resp __attribute__((unused)),
                             struct propstat propstat[],
                             void *rock __attribute__((unused)))
{
    struct caldav_data *cdata = (struct caldav_data *) fctx->data;

    if (!cdata->organizer || !cdata->sched_tag) return HTTP_NOT_FOUND;

    /* add DQUOTEs */
    buf_reset(&fctx->buf);
    buf_printf(&fctx->buf, "\"%s\"", cdata->sched_tag);

    xml_add_prop(HTTP_OK, fctx->ns[NS_DAV], &propstat[PROPSTAT_OK],
                 name, ns, BAD_CAST buf_cstring(&fctx->buf), 0);

    return 0;
}


/* Callback to fetch CALDAV:calendar-user-address-set */
int propfind_caluseraddr(const xmlChar *name, xmlNsPtr ns,
                         struct propfind_ctx *fctx,
                         xmlNodePtr prop __attribute__((unused)),
                         xmlNodePtr resp __attribute__((unused)),
                         struct propstat propstat[],
                         void *rock __attribute__((unused)))
{
    xmlNodePtr node;
    struct strlist *domains;

    if (!(namespace_calendar.enabled && fctx->req_tgt->userid))
        return HTTP_NOT_FOUND;

    node = xml_add_prop(HTTP_OK, fctx->ns[NS_DAV], &propstat[PROPSTAT_OK],
                        name, ns, NULL, 0);

    const char *annotname =
        DAV_ANNOT_NS "<" XML_NS_CALDAV ">calendar-user-address-set";
    char *mailboxname = caldav_mboxname(fctx->req_tgt->userid, NULL);
    buf_reset(&fctx->buf);
    int r = annotatemore_lookupmask(mailboxname, annotname,
                                    fctx->req_tgt->userid, &fctx->buf);
    free(mailboxname);
    if (!r && fctx->buf.len) {
        xml_add_href(node, fctx->ns[NS_DAV], buf_cstring(&fctx->buf));
        return 0;
    }

    /* XXX  This needs to be done via an LDAP/DB lookup */
    if (strchr(fctx->req_tgt->userid, '@')) {
        buf_reset(&fctx->buf);
        buf_printf(&fctx->buf, "mailto:%s", fctx->req_tgt->userid);
        xml_add_href(node, fctx->ns[NS_DAV], buf_cstring(&fctx->buf));
        return 0;
    }

    if (httpd_extradomain) {
        buf_reset(&fctx->buf);
        buf_printf(&fctx->buf, "mailto:%s@%s",
                   fctx->req_tgt->userid, httpd_extradomain);
        xml_add_href(node, fctx->ns[NS_DAV], buf_cstring(&fctx->buf));
        return 0;
    }

    for (domains = cua_domains; domains; domains = domains->next) {
        buf_reset(&fctx->buf);
        buf_printf(&fctx->buf, "mailto:%s@%s",
                   fctx->req_tgt->userid, domains->s);

        xml_add_href(node, fctx->ns[NS_DAV], buf_cstring(&fctx->buf));
    }

    return 0;
}

/* Callback to fetch CALDAV:calendar-user-type */
int propfind_calusertype(const xmlChar *name, xmlNsPtr ns,
                         struct propfind_ctx *fctx,
                         xmlNodePtr prop __attribute__((unused)),
                         xmlNodePtr resp __attribute__((unused)),
                         struct propstat propstat[],
                         void *rock __attribute__((unused)))
{
    const char *type = fctx->req_tgt->userid ? "INDIVIDUAL" : NULL;

    if (!namespace_calendar.enabled || !type) return HTTP_NOT_FOUND;

    xml_add_prop(HTTP_OK, fctx->ns[NS_DAV], &propstat[PROPSTAT_OK],
                 name, ns, BAD_CAST type, 0);

    return 0;
}


/* Callback to fetch CALDAV:schedule-calendar-transp */
static int propfind_caltransp(const xmlChar *name, xmlNsPtr ns,
                              struct propfind_ctx *fctx,
                              xmlNodePtr prop __attribute__((unused)),
                              xmlNodePtr resp __attribute__((unused)),
                              struct propstat propstat[],
                              void *rock __attribute__((unused)))
{
    struct buf attrib = BUF_INITIALIZER;
    const char *prop_annot =
        DAV_ANNOT_NS "<" XML_NS_CALDAV ">schedule-calendar-transp";
    xmlNodePtr node;
    int r = 0;

    if (!fctx->req_tgt->collection) return HTTP_NOT_FOUND;

    r = annotatemore_lookupmask(fctx->mailbox->name, prop_annot,
                                httpd_userid, &attrib);

    if (r) return HTTP_SERVER_ERROR;
    if (!attrib.len) return HTTP_NOT_FOUND;

    node = xml_add_prop(HTTP_OK, fctx->ns[NS_DAV], &propstat[PROPSTAT_OK],
                        name, ns, NULL, 0);
    xmlNewChild(node, fctx->ns[NS_CALDAV], BAD_CAST buf_cstring(&attrib), NULL);

    buf_free(&attrib);

    return 0;
}


/* Callback to write schedule-calendar-transp property */
static int proppatch_caltransp(xmlNodePtr prop, unsigned set,
                               struct proppatch_ctx *pctx,
                               struct propstat propstat[],
                               void *rock __attribute__((unused)))
{
    if (pctx->txn->req_tgt.collection && !pctx->txn->req_tgt.resource) {
        const xmlChar *value = NULL;

        if (set) {
            xmlNodePtr cur;

            /* Find the value */
            for (cur = prop->children; cur; cur = cur->next) {

                /* Make sure its a value we understand */
                if (cur->type != XML_ELEMENT_NODE) continue;
                if (!xmlStrcmp(cur->name, BAD_CAST "opaque") ||
                    !xmlStrcmp(cur->name, BAD_CAST "transparent")) {
                    value = cur->name;
                    break;
                }
                else {
                    /* Unknown value */
                    xml_add_prop(HTTP_CONFLICT, pctx->ns[NS_DAV],
                                 &propstat[PROPSTAT_CONFLICT],
                                 prop->name, prop->ns, NULL, 0);

                    *pctx->ret = HTTP_FORBIDDEN;

                    return 0;
                }
            }
        }

        proppatch_todb(prop, set, pctx, propstat, (void *) value);
    }
    else {
        xml_add_prop(HTTP_FORBIDDEN, pctx->ns[NS_DAV],
                     &propstat[PROPSTAT_FORBID],
                     prop->name, prop->ns, NULL, 0);

        *pctx->ret = HTTP_FORBIDDEN;
    }

    return 0;
}


/* Callback to prescreen/fetch CALDAV:calendar-timezone */
static int propfind_timezone(const xmlChar *name, xmlNsPtr ns,
                             struct propfind_ctx *fctx,
                             xmlNodePtr prop,
                             xmlNodePtr resp __attribute__((unused)),
                             struct propstat propstat[],
                             void *rock __attribute__((unused)))
{
    struct buf attrib = BUF_INITIALIZER;
    const char *data = NULL, *msg_base = NULL;
    size_t datalen = 0;
    int r = 0;

    if (propstat) {
        const char *prop_annot =
            DAV_ANNOT_NS "<" XML_NS_CALDAV ">calendar-timezone";

        if (fctx->mailbox && !fctx->record) {
            r = annotatemore_lookupmask(fctx->mailbox->name, prop_annot,
                                        httpd_userid, &attrib);
        }

        if (r) r = HTTP_SERVER_ERROR;
        else if (attrib.len)  {
            data = buf_cstring(&attrib);
            datalen = attrib.len;
        }
        else if ((namespace_calendar.allow & ALLOW_CAL_NOTZ)) {
            /*  Check for CALDAV:calendar-timezone-id */
            prop_annot = DAV_ANNOT_NS "<" XML_NS_CALDAV ">calendar-timezone-id";

            buf_free(&attrib);
            r = annotatemore_lookupmask(fctx->mailbox->name, prop_annot,
                                        httpd_userid, &attrib);

            if (r) r = HTTP_SERVER_ERROR;
            else if (!attrib.len) r = HTTP_NOT_FOUND;
            else {
                const char *path;
                int fd;

                /* Open and mmap the timezone file */
                buf_reset(&fctx->buf);
                buf_printf(&fctx->buf, "%s%s/%s.ics",
                           config_dir, FNAME_ZONEINFODIR, buf_cstring(&attrib));

                path = buf_cstring(&fctx->buf);
                if ((fd = open(path, O_RDONLY)) == -1) return HTTP_SERVER_ERROR;

                map_refresh(fd, 1, &msg_base, &datalen,
                            MAP_UNKNOWN_LEN, path, NULL);
                close(fd);

                if (!msg_base) r = HTTP_SERVER_ERROR;

                data = msg_base;
            }
        }
        else r = HTTP_NOT_FOUND;
    }

    if (!r) r = propfind_getdata(name, ns, fctx, prop, propstat,
                                 caldav_mime_types, CALDAV_SUPP_DATA,
                                 data, datalen);

    if (msg_base) map_free(&msg_base, &datalen);
    buf_free(&attrib);

    return r;
}


/* Callback to write calendar-timezone property */
static int proppatch_timezone(xmlNodePtr prop, unsigned set,
                              struct proppatch_ctx *pctx,
                              struct propstat propstat[],
                              void *rock __attribute__((unused)))
{
    if (pctx->txn->req_tgt.collection && !pctx->txn->req_tgt.resource) {
        xmlChar *type, *ver = NULL, *freeme = NULL;
        const char *tz = NULL;
        struct mime_type_t *mime;
        unsigned valid = 1;

        type = xmlGetProp(prop, BAD_CAST "content-type");
        if (type) ver = xmlGetProp(prop, BAD_CAST "version");

        /* Check/find requested MIME type */
        for (mime = caldav_mime_types; type && mime->content_type; mime++) {
            if (is_mediatype(mime->content_type, (const char *) type)) {
                if (ver &&
                    (!mime->version || xmlStrcmp(ver, BAD_CAST mime->version))) {
                    continue;
                }
                break;
            }
        }

        if (!mime || !mime->content_type) {
            xml_add_prop(HTTP_FORBIDDEN, pctx->ns[NS_DAV],
                         &propstat[PROPSTAT_FORBID],
                         prop->name, prop->ns, NULL,
                         CALDAV_SUPP_DATA);
            *pctx->ret = HTTP_FORBIDDEN;
            valid = 0;
        }
        else if (set) {
            icalcomponent *ical = NULL;
            struct buf buf;

            freeme = xmlNodeGetContent(prop);
            tz = (const char *) freeme;

            /* Parse and validate the iCal data */
            buf_init_ro_cstr(&buf, tz);
            ical = mime->to_object(&buf);
            if (!ical || (icalcomponent_isa(ical) != ICAL_VCALENDAR_COMPONENT)) {
                xml_add_prop(HTTP_FORBIDDEN, pctx->ns[NS_DAV],
                             &propstat[PROPSTAT_FORBID],
                             prop->name, prop->ns, NULL,
                             CALDAV_VALID_DATA);
                *pctx->ret = HTTP_FORBIDDEN;
                valid = 0;
            }
            else if (!icalcomponent_get_first_component(ical,
                                                        ICAL_VTIMEZONE_COMPONENT)
                     || icalcomponent_get_first_real_component(ical)) {
                xml_add_prop(HTTP_FORBIDDEN, pctx->ns[NS_DAV],
                             &propstat[PROPSTAT_FORBID],
                             prop->name, prop->ns, NULL,
                             CALDAV_VALID_OBJECT);
                *pctx->ret = HTTP_FORBIDDEN;
                valid = 0;
            }
            else if (mime != caldav_mime_types) {
                tz = icalcomponent_as_ical_string(ical);
            }

            if (ical) icalcomponent_free(ical);
            buf_free(&buf);
        }

        if (valid) {
            /* Remove CALDAV:calendar-timezone-id */
            const char *prop_annot =
                DAV_ANNOT_NS "<" XML_NS_CALDAV ">calendar-timezone-id";
            annotate_state_t *astate = NULL;
            int r;

            buf_reset(&pctx->buf);
            r = mailbox_get_annotate_state(pctx->mailbox, 0, &astate);
            if (!r) r = annotate_state_writemask(astate, prop_annot,
                                                 httpd_userid, &pctx->buf);
            if (!r) {
                /* Set CALDAV:calendar-timezone */
                proppatch_todb(prop, set, pctx, propstat, (void *) tz);
            }
            else {
                xml_add_prop(HTTP_SERVER_ERROR, pctx->ns[NS_DAV],
                             &propstat[PROPSTAT_ERROR],
                             prop->name, prop->ns, NULL, 0);
                *pctx->ret = HTTP_SERVER_ERROR;
            }
        }

        if (freeme) xmlFree(freeme);
        if (type) xmlFree(type);
        if (ver) xmlFree(ver);
    }
    else {
        xml_add_prop(HTTP_FORBIDDEN, pctx->ns[NS_DAV],
                     &propstat[PROPSTAT_FORBID], prop->name, prop->ns, NULL, 0);

        *pctx->ret = HTTP_FORBIDDEN;
    }

    return 0;
}


/* Callback to prescreen/fetch CALDAV/CS:calendar-availability */
static int propfind_availability(const xmlChar *name, xmlNsPtr ns,
                                 struct propfind_ctx *fctx,
                                 xmlNodePtr prop,
                                 xmlNodePtr resp __attribute__((unused)),
                                 struct propstat propstat[],
                                 void *rock __attribute__((unused)))
{
    struct buf attrib = BUF_INITIALIZER;
    const char *data = NULL;
    unsigned long datalen = 0;
    int r = 0;

    if (propstat) {
        buf_reset(&fctx->buf);
        buf_printf(&fctx->buf, DAV_ANNOT_NS "<%s>%s",
                   (const char *) ns->href, name);

        if (fctx->mailbox && !fctx->record) {
            r = annotatemore_lookupmask(fctx->mailbox->name,
                                        buf_cstring(&fctx->buf),
                                        httpd_userid, &attrib);
        }

        if (!attrib.len && xmlStrcmp(ns->href, BAD_CAST XML_NS_CALDAV)) {
            /* Check for CALDAV:calendar-availability */
            buf_reset(&fctx->buf);
            buf_printf(&fctx->buf, DAV_ANNOT_NS "<%s>%s", XML_NS_CALDAV, name);

            if (fctx->mailbox && !fctx->record) {
                r = annotatemore_lookupmask(fctx->mailbox->name,
                                            buf_cstring(&fctx->buf),
                                            httpd_userid, &attrib);
            }
        }

        if (r) r = HTTP_SERVER_ERROR;
        else if (!attrib.len) r = HTTP_NOT_FOUND;
        else {
            data = buf_cstring(&attrib);
            datalen = attrib.len;
        }
    }

    if (!r) r = propfind_getdata(name, ns, fctx, prop, propstat,
                                 caldav_mime_types, CALDAV_SUPP_DATA,
                                 data, datalen);
    buf_free(&attrib);

    return r;
}



/* Callback to write calendar-availability property */
static int proppatch_availability(xmlNodePtr prop, unsigned set,
                                  struct proppatch_ctx *pctx,
                                  struct propstat propstat[],
                                  void *rock __attribute__((unused)))
{
    if (config_allowsched && pctx->txn->req_tgt.flags == TGT_SCHED_INBOX) {
        const char *avail = NULL;
        xmlChar *type, *ver = NULL, *freeme = NULL;
        struct mime_type_t *mime;
        unsigned valid = 1;

        type = xmlGetProp(prop, BAD_CAST "content-type");
        if (type) ver = xmlGetProp(prop, BAD_CAST "version");

        /* Check/find requested MIME type */
        for (mime = caldav_mime_types; type && mime->content_type; mime++) {
            if (is_mediatype(mime->content_type, (const char *) type)) {
                if (ver &&
                    (!mime->version || xmlStrcmp(ver, BAD_CAST mime->version))) {
                    continue;
                }
                break;
            }
        }

        if (!mime || !mime->content_type) {
            xml_add_prop(HTTP_FORBIDDEN, pctx->ns[NS_DAV],
                         &propstat[PROPSTAT_FORBID],
                         prop->name, prop->ns, NULL,
                         CALDAV_SUPP_DATA);
            *pctx->ret = HTTP_FORBIDDEN;
            valid = 0;
        }
        else if (set) {
            icalcomponent *ical = NULL;
            struct buf buf;

            freeme = xmlNodeGetContent(prop);
            avail = (const char *) freeme;

            /* Parse and validate the iCal data */
            buf_init_ro_cstr(&buf, avail);
            ical = mime->to_object(&buf);
            if (!ical || (icalcomponent_isa(ical) != ICAL_VCALENDAR_COMPONENT)) {
                xml_add_prop(HTTP_FORBIDDEN, pctx->ns[NS_DAV],
                             &propstat[PROPSTAT_FORBID],
                             prop->name, prop->ns, NULL,
                             CALDAV_VALID_DATA);
                *pctx->ret = HTTP_FORBIDDEN;
                valid = 0;
            }
            else if (!icalcomponent_get_first_component(ical,
                                                        ICAL_VAVAILABILITY_COMPONENT)) {
                xml_add_prop(HTTP_FORBIDDEN, pctx->ns[NS_DAV],
                             &propstat[PROPSTAT_FORBID],
                             prop->name, prop->ns, NULL,
                             CALDAV_VALID_OBJECT);
                *pctx->ret = HTTP_FORBIDDEN;
                valid = 0;
            }
            else if (mime != caldav_mime_types) {
                avail = icalcomponent_as_ical_string(ical);
            }

            if (ical) icalcomponent_free(ical);
        }

        if (valid) {
            proppatch_todb(prop, set, pctx, propstat, (void *) avail);
        }

        if (freeme) xmlFree(freeme);
        if (type) xmlFree(type);
        if (ver) xmlFree(ver);
    }
    else {
        xml_add_prop(HTTP_FORBIDDEN, pctx->ns[NS_DAV],
                     &propstat[PROPSTAT_FORBID], prop->name, prop->ns, NULL, 0);

        *pctx->ret = HTTP_FORBIDDEN;
    }

    return 0;
}


/* Callback to fetch CALDAV:timezone-service-set */
static int propfind_tzservset(const xmlChar *name, xmlNsPtr ns,
                              struct propfind_ctx *fctx,
                              xmlNodePtr prop __attribute__((unused)),
                              xmlNodePtr resp __attribute__((unused)),
                              struct propstat propstat[],
                              void *rock __attribute__((unused)))
{
    assert(name && ns && fctx && propstat);

#ifdef HAVE_TZ_BY_REF
    if (fctx->req_tgt->resource) return HTTP_NOT_FOUND;

    if (namespace_calendar.allow & ALLOW_CAL_NOTZ) {
        xmlNodePtr node;
        const char *proto = NULL, *host = NULL;

        node = xml_add_prop(HTTP_OK, fctx->ns[NS_DAV], &propstat[PROPSTAT_OK],
                            name, ns, NULL, 0);

        http_proto_host(fctx->txn->req_hdrs, &proto, &host);

        buf_reset(&fctx->buf);
        buf_printf(&fctx->buf, "%s://%s%s",
                   proto, host, namespace_tzdist.prefix);

        xml_add_href(node, fctx->ns[NS_DAV], buf_cstring(&fctx->buf));

        return 0;
    }
#endif /* HAVE_TZ_BY_REF */

    return HTTP_NOT_FOUND;
}


/* Callback to fetch CALDAV:calendar-timezone-id property */
static int propfind_tzid(const xmlChar *name, xmlNsPtr ns,
                         struct propfind_ctx *fctx,
                         xmlNodePtr prop __attribute__((unused)),
                         xmlNodePtr resp __attribute__((unused)),
                         struct propstat propstat[],
                         void *rock __attribute__((unused)))
{
    const char *prop_annot =
        DAV_ANNOT_NS "<" XML_NS_CALDAV ">calendar-timezone-id";
    struct buf attrib = BUF_INITIALIZER;
    const char *value = NULL;
    int r = 0;

    if (!(namespace_calendar.allow & ALLOW_CAL_NOTZ) ||
        !fctx->req_tgt->collection || fctx->req_tgt->resource)
        return HTTP_NOT_FOUND;

    r = annotatemore_lookupmask(fctx->mailbox->name, prop_annot,
                                httpd_userid, &attrib);

    if (r) r = HTTP_SERVER_ERROR;
    else if (attrib.len) {
        value = buf_cstring(&attrib);
    }
    else {
        /*  Check for CALDAV:calendar-timezone */
        prop_annot = DAV_ANNOT_NS "<" XML_NS_CALDAV ">calendar-timezone";

        if (fctx->mailbox && !fctx->record) {
            r = annotatemore_lookupmask(fctx->mailbox->name, prop_annot,
                                        httpd_userid, &attrib);
        }

        if (r) r = HTTP_SERVER_ERROR;
        else if (!attrib.len) r = HTTP_NOT_FOUND;
        else {
            icalcomponent *ical, *vtz;
            icalproperty *tzid;

            ical = icalparser_parse_string(buf_cstring(&attrib));
            vtz = icalcomponent_get_first_component(ical,
                                                    ICAL_VTIMEZONE_COMPONENT);
            tzid = icalcomponent_get_first_property(vtz, ICAL_TZID_PROPERTY);
            value = icalmemory_tmp_copy(icalproperty_get_tzid(tzid));
            icalcomponent_free(ical);
        }
    }

    if (!r) xml_add_prop(HTTP_OK, fctx->ns[NS_DAV], &propstat[PROPSTAT_OK],
                         name, ns, BAD_CAST value, 0);

    buf_free(&attrib);

    return r;
}


/* Callback to write CALDAV:calendar-timezone-id property */
static int proppatch_tzid(xmlNodePtr prop, unsigned set,
                          struct proppatch_ctx *pctx,
                          struct propstat propstat[],
                          void *rock __attribute__((unused)))
{
#ifdef HAVE_TZ_BY_REF
    if ((namespace_calendar.allow & ALLOW_CAL_NOTZ) &&
        pctx->txn->req_tgt.collection && !pctx->txn->req_tgt.resource) {
        xmlChar *freeme = NULL;
        const char *tzid = NULL;
        unsigned valid = 1;
        int r;

        if (set) {
            freeme = xmlNodeGetContent(prop);
            tzid = (const char *) freeme;

            /* Verify we have tzid record in the database */
            r = zoneinfo_lookup(tzid, NULL);
            if (r) {
                if (r == CYRUSDB_NOTFOUND) {
                    xml_add_prop(HTTP_FORBIDDEN, pctx->ns[NS_DAV],
                                 &propstat[PROPSTAT_FORBID],
                                 prop->name, prop->ns, NULL,
                                 CALDAV_VALID_TIMEZONE);
                }
                else {
                    xml_add_prop(HTTP_SERVER_ERROR, pctx->ns[NS_DAV],
                                 &propstat[PROPSTAT_ERROR],
                                 prop->name, prop->ns, NULL, 0);
                }
                *pctx->ret = HTTP_FORBIDDEN;
                valid = 0;
            }
        }

        if (valid) {
            /* Remove CALDAV:calendar-timezone */
            const char *prop_annot =
                DAV_ANNOT_NS "<" XML_NS_CALDAV ">calendar-timezone";
            annotate_state_t *astate = NULL;

            buf_reset(&pctx->buf);
            r = mailbox_get_annotate_state(pctx->mailbox, 0, &astate);
            if (!r) r = annotate_state_writemask(astate, prop_annot,
                                                 httpd_userid, &pctx->buf);

            if (r) {
                xml_add_prop(HTTP_SERVER_ERROR, pctx->ns[NS_DAV],
                             &propstat[PROPSTAT_ERROR],
                             prop->name, prop->ns, NULL, 0);
                *pctx->ret = HTTP_SERVER_ERROR;
            }
            else {
                /* Set CALDAV:calendar-timezone-id */
                proppatch_todb(prop, set, pctx, propstat, (void *) tzid);
            }
        }

        if (freeme) xmlFree(freeme);

        return 0;
    }
#else
    (void) set;  /* squash compiler warning */
#endif /* HAVE_TZ_BY_REF */

    xml_add_prop(HTTP_FORBIDDEN, pctx->ns[NS_DAV],
                 &propstat[PROPSTAT_FORBID], prop->name, prop->ns, NULL, 0);

    *pctx->ret = HTTP_FORBIDDEN;

    return 0;
}


/* Callback to fetch CALDAV:supported-rscale-set */
static int propfind_rscaleset(const xmlChar *name, xmlNsPtr ns,
                              struct propfind_ctx *fctx,
                              xmlNodePtr prop __attribute__((unused)),
                              xmlNodePtr resp __attribute__((unused)),
                              struct propstat propstat[],
                              void *rock __attribute__((unused)))
{
    assert(name && ns && fctx && propstat);

    if (fctx->req_tgt->resource) return HTTP_NOT_FOUND;

    if (rscale_calendars) {
        xmlNodePtr top;
        int i, n;

        top = xml_add_prop(HTTP_OK, fctx->ns[NS_DAV], &propstat[PROPSTAT_OK],
                           name, ns, NULL, 0);

        for (i = 0, n = rscale_calendars->num_elements; i < n; i++) {
            const char **rscale = icalarray_element_at(rscale_calendars, i);

            xmlNewChild(top, fctx->ns[NS_CALDAV],
                        BAD_CAST "supported-rscale", BAD_CAST *rscale);
        }

        return 0;
    }

    return HTTP_NOT_FOUND;
}


/* Callback to fetch CS:allowed-sharing-modes */
static int propfind_sharingmodes(const xmlChar *name, xmlNsPtr ns,
                                 struct propfind_ctx *fctx,
                                 xmlNodePtr prop __attribute__((unused)),
                                 xmlNodePtr resp __attribute__((unused)),
                                 struct propstat propstat[],
                                 void *rock __attribute__((unused)))
{
    xmlNodePtr node = xml_add_prop(HTTP_OK, fctx->ns[NS_DAV],
                                   &propstat[PROPSTAT_OK], name, ns, NULL, 0);

    fctx->flags.cs_sharing = 1;

    if (fctx->req_tgt->collection && !fctx->req_tgt->flags &&
        !fctx->req_tgt->resource &&
        mboxname_userownsmailbox(fctx->req_tgt->userid, fctx->mbentry->name)) {
        xmlNewChild(node, NULL, BAD_CAST "can-be-shared", NULL);
#if 0  /* XXX  this is probably iCloud specific */
        xmlNewChild(node, NULL, BAD_CAST "can-be-published", NULL);
#endif
    }

    return 0;
}


static int report_cal_query(struct transaction_t *txn,
                            struct meth_params *rparams __attribute__((unused)),
                            xmlNodePtr inroot, struct propfind_ctx *fctx)
{
    int ret = 0;
    xmlNodePtr node;
    struct calquery_filter calfilter;

    memset(&calfilter, 0, sizeof(struct calquery_filter));

    fctx->filter_crit = &calfilter;
    fctx->open_db = (db_open_proc_t) &caldav_open_mailbox;
    fctx->close_db = (db_close_proc_t) &caldav_close;
    fctx->lookup_resource = (db_lookup_proc_t) &caldav_lookup_resource;
    fctx->foreach_resource = (db_foreach_proc_t) &caldav_foreach;
    fctx->proc_by_resource = &propfind_by_resource;
    fctx->davdb = NULL;

    /* Parse children element of report */
    for (node = inroot->children; node; node = node->next) {
        if (node->type == XML_ELEMENT_NODE) {
            if (!xmlStrcmp(node->name, BAD_CAST "filter")) {
                ret = parse_calfilter(node, &calfilter, &txn->error);
                if (ret) goto done;
                else fctx->filter = apply_calfilter;
            }
            else if (!xmlStrcmp(node->name, BAD_CAST "timezone")) {
                xmlChar *tzdata = NULL;
                icalcomponent *ical = NULL, *tz = NULL;

                /* XXX  Need to pass this to query for floating time */
                syslog(LOG_WARNING, "REPORT calendar-query w/timezone");
                tzdata = xmlNodeGetContent(node);
                ical = icalparser_parse_string((const char *) tzdata);
                if (ical) {
                    tz = icalcomponent_get_first_component(ical,
                                                           ICAL_VTIMEZONE_COMPONENT);
                }
                if (!tz || icalcomponent_get_first_real_component(ical)) {
                    txn->error.precond = CALDAV_VALID_DATA;
                    ret = HTTP_FORBIDDEN;
                }
                else {
                    icalcomponent_remove_component(ical, tz);
                    calfilter.tz = icaltimezone_new();
                    icaltimezone_set_component(calfilter.tz, tz);
                }

                if (tzdata) xmlFree(tzdata);
                if (ical) icalcomponent_free(ical);
                if (ret) return ret;
            }
            else if (!xmlStrcmp(node->name, BAD_CAST "timezone-id")) {
                xmlChar *tzid = NULL;

                /* XXX  Need to pass this to query for floating time */
                syslog(LOG_WARNING, "REPORT calendar-query w/tzid");
                tzid = xmlNodeGetContent(node);

                /* XXX  Need to load timezone */

                if (tzid) xmlFree(tzid);
                if (ret) return ret;
            }
        }
    }

    if (fctx->depth++ > 0) {
        /* Calendar collection(s) */
        if (txn->req_tgt.collection) {
            /* Add response for target calendar collection */
            propfind_by_collection(txn->req_tgt.mbentry, fctx);
        }
        else {
            /* Add responses for all contained calendar collections */
            mboxlist_mboxtree(txn->req_tgt.mbentry->name,
                              propfind_by_collection, fctx,
                              MBOXTREE_SKIP_ROOT);

            /* Add responses for all shared calendar collections */
            mboxlist_usersubs(txn->req_tgt.userid,
                              propfind_by_collection, fctx,
                              MBOXTREE_SKIP_PERSONAL);
        }

        ret = *fctx->ret;
    }

  done:
    /* Free filter structure */
    if (calfilter.tz) icaltimezone_free(calfilter.tz, 1);
    free_compfilter(calfilter.comp);

    if (fctx->davdb) {
        caldav_close(fctx->davdb);
        fctx->davdb = NULL;
    }

    return (ret ? ret : HTTP_MULTI_STATUS);
}


static int is_busytime(icalcomponent *comp)
{
    /* Check TRANSP and STATUS per RFC 4791, section 7.10 */
    const icalproperty *prop;

    /* Skip transparent events */
    prop = icalcomponent_get_first_property(comp, ICAL_TRANSP_PROPERTY);
    if (prop && icalproperty_get_transp(prop) == ICAL_TRANSP_TRANSPARENT)
        return 0;

    /* Skip cancelled events */
    if (icalcomponent_get_status(comp) == ICAL_STATUS_CANCELLED) return 0;

    return 1;
}


/* Append a new busytime period to the busytime array */
static void add_freebusy(struct icaltimetype *recurid,
                         struct icaltimetype *start,
                         struct icaltimetype *end,
                         icalparameter_fbtype fbtype,
                         struct freebusy_filter *fbfilter)
{
    struct freebusy_array *freebusy = &fbfilter->freebusy;
    struct freebusy *newfb;

    /* Grow the array, if necessary */
    if (freebusy->len == freebusy->alloc) {
        freebusy->alloc += 100;  /* XXX  arbitrary */
        freebusy->fb = xrealloc(freebusy->fb,
                                freebusy->alloc * sizeof(struct freebusy));
    }

    /* Add new freebusy */
    newfb = &freebusy->fb[freebusy->len++];
    memset(newfb, 0, sizeof(struct freebusy));

    if (recurid) newfb->recurid = *recurid;

    if (icaltime_is_date(*start)) {
        newfb->per.duration = icaltime_subtract(*end, *start);
        newfb->per.end = icaltime_null_time();
        start->is_date = 0;  /* MUST be DATE-TIME */
        newfb->per.start = icaltime_convert_to_zone(*start, utc_zone);
    }
    else {
        newfb->per.duration = icaldurationtype_null_duration();
        if (icaltime_compare(fbfilter->end, *end) < 0) {
            newfb->per.end = fbfilter->end;
        }
        else newfb->per.end = *end;

        if (icaltime_compare(fbfilter->start, *start) > 0) {
            newfb->per.start = fbfilter->start;
        }
        else newfb->per.start = *start;
    }
    newfb->type = fbtype;
}


/* Append a new busytime period for recurring comp to the busytime array */
static int add_freebusy_comp(icalcomponent *comp,
                             icaltimetype start, icaltimetype end,
                             void *rock)
{
    struct freebusy_filter *fbfilter = (struct freebusy_filter *) rock;
    struct icaltimetype recurid;
    icalparameter_fbtype fbtype;

    if (!is_busytime(comp)) return 1;

    /* Set start and end times */
    start = icaltime_convert_to_zone(start, utc_zone);
    end = icaltime_convert_to_zone(end, utc_zone);

    /* Set recurid */
    recurid = icalcomponent_get_recurrenceid_with_zone(comp);
    if (icaltime_is_null_time(recurid)) recurid = start;
    else {
        recurid = icaltime_convert_to_zone(recurid, utc_zone);
        recurid.is_date = 0;  /* make DATE-TIME for comparison */
    }

    /* Set FBTYPE */
    switch (icalcomponent_isa(comp)) {
    case ICAL_VEVENT_COMPONENT:
        fbtype = icalcomponent_get_status(comp) == ICAL_STATUS_TENTATIVE ?
            ICAL_FBTYPE_BUSYTENTATIVE : ICAL_FBTYPE_BUSY;
        break;

    case ICAL_VFREEBUSY_COMPONENT:
        /* XXX  Need to do something better here */
        fbtype = ICAL_FBTYPE_BUSY;
        break;

#ifdef HAVE_VAVAILABILITY
    case ICAL_VAVAILABILITY_COMPONENT: {
        enum icalproperty_busytype busytype = ICAL_BUSYTYPE_BUSYUNAVAILABLE;
        icalproperty *prop =
            icalcomponent_get_first_property(comp, ICAL_BUSYTYPE_PROPERTY);

        if (prop) busytype = icalproperty_get_busytype(prop);

        switch (busytype) {
        case ICAL_BUSYTYPE_BUSYUNAVAILABLE:
            fbtype = ICAL_FBTYPE_BUSYUNAVAILABLE;
            break;
        case ICAL_BUSYTYPE_BUSYTENTATIVE:
            fbtype = ICAL_FBTYPE_BUSYTENTATIVE;
            break;
        default:
            fbtype = ICAL_FBTYPE_BUSY;
            break;
        }
        break;
    }

    case ICAL_XAVAILABLE_COMPONENT:
        fbtype = ICAL_FBTYPE_FREE;
        break;
#endif /* HAVE_VAVAILABILITY */

    default:
        fbtype = ICAL_FBTYPE_NONE;
        break;
    }

    add_freebusy(&recurid, &start, &end, fbtype, fbfilter);

    return 1;
}


static void expand_occurrences(icalcomponent *ical,
                               struct freebusy_filter *fbfilter)
{
    /* Create a span for the given time-range */
    struct icalperiodtype rangespan =
        { fbfilter->start, fbfilter->end, icaldurationtype_null_duration() };

    icalcomponent_myforeach(ical, rangespan, NULL, add_freebusy_comp, fbfilter);
}


/* Append a new vavailability period to the vavail array */
static void
add_vavailability(struct vavailability_array *vavail, icalcomponent *ical)
{
    struct vavailability *newav;
    icalcomponent *vav;
    icalproperty *prop;

    /* Grow the array, if necessary */
    if (vavail->len == vavail->alloc) {
        vavail->alloc += 10;  /* XXX  arbitrary */
        vavail->vav = xrealloc(vavail->vav,
                               vavail->alloc * sizeof(struct vavailability));
    }

    /* Add new vavailability */
    newav = &vavail->vav[vavail->len++];
    newav->ical = ical;

    vav = icalcomponent_get_first_real_component(ical);

    /* Set period */
    newav->per.start = icalcomponent_get_dtstart(vav);
    if (icaltime_is_null_time(newav->per.start)) {
        newav->per.start =
            icaltime_from_timet_with_zone(caldav_epoch, 0, utc_zone);
    }
    else {
        newav->per.start = icaltime_convert_to_zone(newav->per.start, utc_zone);
    }
    newav->per.end = icalcomponent_get_dtend(vav);
    if (icaltime_is_null_time(newav->per.end)) {
        newav->per.end =
            icaltime_from_timet_with_zone(caldav_eternity, 0, utc_zone);
    }
    else {
        newav->per.end = icaltime_convert_to_zone(newav->per.end, utc_zone);
    }
    newav->per.duration = icaldurationtype_null_duration();

    /* Set PRIORITY - 0 (or none) has lower priority than 9 */
    prop = icalcomponent_get_first_property(vav, ICAL_PRIORITY_PROPERTY);
    if (prop) newav->priority = icalproperty_get_priority(prop);
    if (!prop || !newav->priority) newav->priority = 10;
}


/* caldav_foreach() callback to find busytime of a resource */
static int busytime_by_resource(void *rock, void *data)
{
    struct propfind_ctx *fctx = (struct propfind_ctx *) rock;
    struct caldav_data *cdata = (struct caldav_data *) data;
    struct freebusy_filter *fbfilter =
        (struct freebusy_filter *) fctx->filter_crit;

    keepalive_response(fctx->txn);

    if (!cdata->dav.imap_uid) return 0;

    /* Perform component filtering */
    if (!(cdata->comp_type &
          (CAL_COMP_VEVENT | CAL_COMP_VFREEBUSY | CAL_COMP_VAVAILABILITY))) {
        return 0;
    }

    /* Perform time-range filtering */
    struct icaltimetype dtstart = icaltime_from_string(cdata->dtstart);
    struct icaltimetype dtend = icaltime_from_string(cdata->dtend);

    if (icaltime_compare(dtend, fbfilter->start) <= 0) {
        /* Component ends earlier than range */
        return 0;
    }
    if (icaltime_compare(dtstart, fbfilter->end) >= 0) {
        /* Component starts later than range */
        return 0;
    }

    if (cdata->comp_flags.recurring ||
        cdata->comp_type == CAL_COMP_VAVAILABILITY) {
        /* Need to mmap() and parse iCalendar object */
        struct index_record record;
        icalcomponent *ical = NULL;
        int r;

        /* Fetch index record for the resource */
        r = mailbox_find_index_record(fctx->mailbox,
                                      cdata->dav.imap_uid, &record);

        if (!r) ical = record_to_ical(fctx->mailbox, &record, NULL);
        if (!ical) return 0;

        if (cdata->comp_flags.recurring) {
            /* Component is recurring - process each recurrence */
            expand_occurrences(ical, fbfilter);

            icalcomponent_free(ical);
        }
        else {
            /* VAVAILABILITY - add to our array for later use */
            add_vavailability(&fbfilter->vavail, ical);
        }
    }
    else {
        /* Component is non-recurring */
        icalparameter_fbtype fbtype;

        if (cdata->comp_flags.transp) {
            /* Don't include transparent events in freebusy */
            return 0;
        }
        if (cdata->comp_flags.status == CAL_STATUS_CANCELED) {
            /* Don't include canceled events in freebusy */
            return 0;
        }

        switch (cdata->comp_flags.status) {
        case CAL_STATUS_UNAVAILABLE:
            fbtype = ICAL_FBTYPE_BUSYUNAVAILABLE; break;

        case CAL_STATUS_TENTATIVE:
            fbtype = ICAL_FBTYPE_BUSYTENTATIVE; break;

        default:
            fbtype = ICAL_FBTYPE_BUSY; break;
        }

        add_freebusy(&dtstart, &dtstart, &dtend, fbtype, fbfilter);
    }

    return 0;
}


/* mboxlist_findall() callback to find busytime of a collection */
static int busytime_by_collection(const mbentry_t *mbentry, void *rock)
{
    const char *mboxname = mbentry->name;
    struct propfind_ctx *fctx = (struct propfind_ctx *) rock;
    struct freebusy_filter *fbfilter =
        (struct freebusy_filter *) fctx->filter_crit;

    if (fbfilter->flags & CHECK_CAL_TRANSP) {
        /* Check if the collection is marked as transparent */
        struct buf attrib = BUF_INITIALIZER;
        const char *prop_annot =
            DAV_ANNOT_NS "<" XML_NS_CALDAV ">schedule-calendar-transp";

        if (!annotatemore_lookupmask(mboxname, prop_annot,
                                     httpd_userid, &attrib)) {
            if (!strcmp(buf_cstring(&attrib), "transparent")) {
                buf_free(&attrib);
                return 0;
            }
            buf_free(&attrib);
        }
    }

    return propfind_by_collection(mbentry, rock);
}


/* Compare start/end times of freebusy periods -- used for sorting */
static int compare_freebusy(const void *fb1, const void *fb2)
{
    struct freebusy *a = (struct freebusy *) fb1;
    struct freebusy *b = (struct freebusy *) fb2;

    int r = icaltime_compare(a->per.start, b->per.start);

    if (r == 0) r = icaltime_compare(a->per.end, b->per.end);

    return r;
}


/* Compare type and start/end times of freebusy periods -- used for sorting */
static int compare_freebusy_with_type(const void *fb1, const void *fb2)
{
    struct freebusy *a = (struct freebusy *) fb1;
    struct freebusy *b = (struct freebusy *) fb2;

    int r = a->type - b->type;

    if (r == 0) r = compare_freebusy(fb1, fb2);

    return r;
}


/* Compare priority, start/end times, and type of vavail periods for sorting */
static int compare_vavail(const void *v1, const void *v2)
{
    struct vavailability *a = (struct vavailability *) v1;
    struct vavailability *b = (struct vavailability *) v2;

    int r = a->priority - b->priority;

    if (r == 0) {
        r = icaltime_compare(a->per.start, b->per.start);

        if (r == 0) r = icaltime_compare(a->per.end, b->per.end);
    }

    return r;
}


static void combine_vavailability(struct freebusy_filter *fbfilter)
{
    struct vavailability_array *vavail = &fbfilter->vavail;
    struct freebusy_filter availfilter;
    struct query_range {
        struct icalperiodtype per;
        struct query_range *next;
    } *ranges, *range, *prev, *next;
    unsigned i, j;

    memset(&availfilter, 0, sizeof(struct freebusy_filter));

    /* Sort VAVAILBILITY periods by priority and start time */
    qsort(vavail->vav, vavail->len,
          sizeof(struct vavailability), compare_vavail);

    /* Maintain a linked list of remaining time ranges
     * to be filled in by lower priority VAV components
     * starting with the time range in the freebusy query.
     * Ranges are removed, clipped, or split as they get filled.
     * Quit when no ranges or VAVAILABILITY components remain.
     */
    ranges = xmalloc(sizeof(struct query_range));
    ranges->per.start = fbfilter->start;
    ranges->per.end = fbfilter->end;
    ranges->next = NULL;

    for (i = 0; i < vavail->len; i++) {
        struct vavailability *vav = &vavail->vav[i];
        icalcomponent *comp;

        comp = icalcomponent_get_first_component(vav->ical,
                                                 ICAL_VAVAILABILITY_COMPONENT);

        for (range = ranges, prev = NULL; range; prev = range, range = next) {
            struct icalperiodtype period;

            next = range->next;

            if (icaltime_compare(vav->per.end, range->per.start) <= 0 ||
                icaltime_compare(vav->per.start, range->per.end) >= 0) {
                /* Skip VAVAILABILITY outside our range */
                continue;
            }

            /* Set filter range (maximum start time and minimum end time)
               and adjust current range as necessary */
            if (icaltime_compare(vav->per.start, range->per.start) <= 0) {
                /* VAV starts before range - filter using range start */
                availfilter.start = range->per.start;

                if (icaltime_compare(vav->per.end, range->per.end) >= 0) {
                    /* VAV ends after range - filter using range end */
                    availfilter.end = range->per.end;

                    /* Filling entire range - remove it */
                    if (prev) prev->next = next;
                    else ranges = NULL;

                    free(range);
                    range = NULL;
                }
                else {
                    /* VAV ends before range - filter using VAV end */
                    availfilter.end = vav->per.end;

                    /* Filling front part - adjust start to back remainder */
                    range->per.start = vav->per.end;
                }
            }
            else {
                /* VAV starts after range - filter using VAV start */
                availfilter.start = vav->per.start;

                if (icaltime_compare(vav->per.end, range->per.end) >= 0) {
                    /* VAV ends after range - filter using range end */
                    availfilter.end = range->per.end;
                }
                else {
                    /* VAV ends before range - filter using VAV end */
                    availfilter.end = vav->per.end;

                    /* Splitting range - insert new range for back remainder */
                    struct query_range *newr =
                        xmalloc(sizeof(struct query_range));
                    newr->per.start = vav->per.end;
                    newr->per.end = range->per.end;
                    newr->next = next;
                    range->next = newr;
                }

                /* Adjust end to front remainder */
                range->per.end = vav->per.start;
            }

            /* Expand available time occurrences */
            expand_occurrences(comp, &availfilter);

            /* Calculate unavailable periods and add to busytime */
            period.start = availfilter.start;
            for (j = 0; j < availfilter.freebusy.len; j++) {
                struct freebusy *fb = &availfilter.freebusy.fb[j];

                /* Ignore overridden instances */
                if (fb->type == ICAL_FBTYPE_NONE) continue;

                period.end = fb->per.start;
                if (icaltime_compare(period.end, period.start) > 0) {
                    add_freebusy_comp(comp, period.start, period.end, fbfilter);
                }
                period.start = fb->per.end;
            }
            period.end = availfilter.end;
            if (icaltime_compare(period.end, period.start) > 0) {
                add_freebusy_comp(comp, period.start, period.end, fbfilter);
            }
        }

        /* Done with this ical component */
        icalcomponent_free(vav->ical);
    }

    /* Cleanup the vavailability array */
    free(vavail->vav);

    /* Cleanup the availability array */
    if (availfilter.freebusy.fb) free(availfilter.freebusy.fb);

    /* Remove any unfilled ranges */
    for (; ranges; ranges = next) {
        next = ranges->next;
        free(ranges);
    }
}


/* Create an iCalendar object containing busytime of all specified resources */
icalcomponent *busytime_query_local(struct transaction_t *txn,
                                    struct propfind_ctx *fctx,
                                    char mailboxname[],
                                    icalproperty_method method,
                                    const char *uid,
                                    const char *organizer,
                                    const char *attendee)
{
    struct freebusy_filter *fbfilter =
        (struct freebusy_filter *) fctx->filter_crit;
    struct freebusy_array *freebusy = &fbfilter->freebusy;
    struct vavailability_array *vavail = &fbfilter->vavail;
    icalcomponent *ical = NULL;
    icalcomponent *fbcomp;
    icalproperty *prop;
    unsigned n;

    fctx->open_db = (db_open_proc_t) &caldav_open_mailbox;
    fctx->close_db = (db_close_proc_t) &caldav_close;
    fctx->lookup_resource = (db_lookup_proc_t) &caldav_lookup_resource;
    fctx->foreach_resource = (db_foreach_proc_t) &caldav_foreach;
    fctx->proc_by_resource = &busytime_by_resource;

    /* Gather up all of the busytime and VAVAILABILITY periods */
    if (fctx->depth > 0) {
        /* Calendar collection(s) */

        if (txn->req_tgt.collection) {
            /* Get busytime for target calendar collection */
            busytime_by_collection(txn->req_tgt.mbentry, fctx);
        }
        else {
            /* Get busytime for all contained calendar collections */
            mboxlist_mboxtree(mailboxname, busytime_by_collection,
                              fctx, MBOXTREE_SKIP_ROOT);

            /* XXX  Get busytime for all shared calendar collections? */
        }

        if (fctx->davdb) caldav_close(fctx->davdb);
    }

    if (*fctx->ret) return NULL;

    if (fbfilter->flags & CHECK_USER_AVAIL) {
        /* Check for CALDAV:calendar-availability on user's Inbox */
        struct buf attrib = BUF_INITIALIZER;
        const char *prop_annot =
            DAV_ANNOT_NS "<" XML_NS_CALDAV ">calendar-availability";
        char *userid = mboxname_to_userid(mailboxname);
        const char *mboxname = caldav_mboxname(userid, SCHED_INBOX);
        if (!annotatemore_lookupmask(mboxname, prop_annot,
                                     httpd_userid, &attrib) && attrib.len) {
            add_vavailability(vavail,
                              icalparser_parse_string(buf_cstring(&attrib)));
        }
        free(userid);
    }

    /* Combine VAVAILABILITY components into busytime */
    if (vavail->len) combine_vavailability(fbfilter);

    /* Sort busytime periods by type and start/end times for coalescing */
    qsort(freebusy->fb, freebusy->len,
          sizeof(struct freebusy), compare_freebusy_with_type);

    /* Coalesce busytime periods of same type into one */
    for (n = 0; n + 1 < freebusy->len; n++) {
        struct freebusy *fb, *next_fb;
        icaltimetype end, next_end;
        int isdur, next_isdur;

        fb = &freebusy->fb[n];
        next_fb = &freebusy->fb[n+1];

        /* Ignore overridden instances */
        if (fb->type == ICAL_FBTYPE_NONE) continue;

        isdur = !icaldurationtype_is_null_duration(fb->per.duration);
        end = !isdur ? fb->per.end :
            icaltime_add(fb->per.start, fb->per.duration);

        /* Skip periods of different type or that don't overlap */
        if ((fb->type != next_fb->type) ||
            icaltime_compare(end, next_fb->per.start) < 0) continue;

        /* Coalesce into next busytime */
        next_isdur = !icaldurationtype_is_null_duration(next_fb->per.duration);
        next_end = !next_isdur ? next_fb->per.end :
            icaltime_add(next_fb->per.start, next_fb->per.duration);

        if (icaltime_compare(end, next_end) >= 0) {
            /* Current period subsumes next */
            next_fb->per.end = fb->per.end;
            next_fb->per.duration = fb->per.duration;
        }
        else if (isdur && next_isdur) {
            /* Both periods are durations */
            struct icaldurationtype overlap =
                icaltime_subtract(end, next_fb->per.start);

            next_fb->per.duration.days += fb->per.duration.days - overlap.days;
        }
        else {
            /* Need to use explicit period */
            next_fb->per.end = next_end;
            next_fb->per.duration = icaldurationtype_null_duration();
        }

        next_fb->per.start = fb->per.start;

        /* "Remove" the instance
           by setting fbtype to NONE (we ignore these later) */
        fb->type = ICAL_FBTYPE_NONE;
    }

    /* Sort busytime periods by start/end times for addition to VFREEBUSY */
    qsort(freebusy->fb, freebusy->len,
          sizeof(struct freebusy), compare_freebusy);

    /* Construct iCalendar object with VFREEBUSY component */
    ical = icalcomponent_vanew(ICAL_VCALENDAR_COMPONENT,
                               icalproperty_new_version("2.0"),
                               icalproperty_new_prodid(ical_prodid),
                               0);

    if (method) icalcomponent_set_method(ical, method);

    fbcomp = icalcomponent_vanew(ICAL_VFREEBUSY_COMPONENT,
                                 icalproperty_new_dtstamp(
                                     icaltime_from_timet_with_zone(
                                         time(0), 0, utc_zone)),
                                 icalproperty_new_dtstart(fbfilter->start),
                                 icalproperty_new_dtend(fbfilter->end),
                                 0);

    icalcomponent_add_component(ical, fbcomp);

    if (uid) icalcomponent_set_uid(fbcomp, uid);
    if (organizer) {
        prop = icalproperty_new_organizer(organizer);
        icalcomponent_add_property(fbcomp, prop);
    }
    if (attendee) {
        prop = icalproperty_new_attendee(attendee);
        icalcomponent_add_property(fbcomp, prop);
    }

    /* Add busytime periods to VFREEBUSY component */
    for (n = 0; n < freebusy->len; n++) {
        struct freebusy *fb = &freebusy->fb[n];
        icalproperty *busy;

        /* Ignore overridden instances */
        if (fb->type == ICAL_FBTYPE_NONE) continue;

        /* Create new FREEBUSY property with FBTYPE and add to component */
        busy = icalproperty_new_freebusy(fb->per);
        icalproperty_add_parameter(busy, icalparameter_new_fbtype(fb->type));
        icalcomponent_add_property(fbcomp, busy);
    }

    return ical;
}


static int report_fb_query(struct transaction_t *txn,
                           struct meth_params *rparams __attribute__((unused)),
                           xmlNodePtr inroot, struct propfind_ctx *fctx)
{
    int ret = 0;
    const char **hdr;
    struct mime_type_t *mime;
    struct freebusy_filter fbfilter;
    xmlNodePtr node;
    icalcomponent *cal;

    /* Can not be run against a resource */
    if (txn->req_tgt.resource) return HTTP_FORBIDDEN;

    /* Check requested MIME type:
       1st entry in caldav_mime_types array MUST be default MIME type */
    if ((hdr = spool_getheader(txn->req_hdrs, "Accept")))
        mime = get_accept_type(hdr, caldav_mime_types);
    else mime = caldav_mime_types;
    if (!mime) return HTTP_NOT_ACCEPTABLE;

    memset(&fbfilter, 0, sizeof(struct freebusy_filter));
    fbfilter.start = icaltime_from_timet_with_zone(caldav_epoch, 0, utc_zone);
    fbfilter.end = icaltime_from_timet_with_zone(caldav_eternity, 0, utc_zone);
    fctx->filter_crit = &fbfilter;

    /* Parse children element of report */
    for (node = inroot->children; node; node = node->next) {
        if (node->type == XML_ELEMENT_NODE) {
            if (!xmlStrcmp(node->name, BAD_CAST "time-range")) {
                xmlChar *start, *end;

                start = xmlGetProp(node, BAD_CAST "start");
                if (start) {
                    fbfilter.start = icaltime_from_string((char *) start);
                    xmlFree(start);
                }

                end = xmlGetProp(node, BAD_CAST "end");
                if (end) {
                    fbfilter.end = icaltime_from_string((char *) end);
                    xmlFree(end);
                }

                if (!is_valid_timerange(fbfilter.start, fbfilter.end)) {
                    return HTTP_BAD_REQUEST;
                }
            }
        }
    }

    cal = busytime_query_local(txn, fctx, txn->req_tgt.mbentry->name,
                               0, NULL, NULL, NULL);

    if (fbfilter.freebusy.fb) free(fbfilter.freebusy.fb);

    if (cal) {
        /* Output the iCalendar object as text/calendar */
        struct buf *cal_str = mime->from_object(cal);
        icalcomponent_free(cal);

        txn->resp_body.type = mime->content_type;

        /* iCalendar data in response should not be transformed */
        txn->flags.cc |= CC_NOTRANSFORM;

        write_body(HTTP_OK, txn, buf_base(cal_str), buf_len(cal_str));
        buf_destroy(cal_str);
    }
    else ret = HTTP_NOT_FOUND;

    return ret;
}


/* Replace TZID aliases with the actual TZIDs */
static void replace_tzid_aliases(icalcomponent *ical,
                                 struct hash_table *tzid_table)
{
    icalproperty *prop;
    for (prop = icalcomponent_get_first_property(ical, ICAL_ANY_PROPERTY);
         prop;
         prop = icalcomponent_get_next_property(ical, ICAL_ANY_PROPERTY)) {
        icalparameter *param =
            icalproperty_get_first_parameter(prop, ICAL_TZID_PARAMETER);
        if (!param) continue;

        const char *tzid =
            hash_lookup(icalparameter_get_tzid(param), tzid_table);
        if (tzid) icalparameter_set_tzid(param, tzid);
    }

    icalcomponent *comp;
    for (comp = icalcomponent_get_first_component(ical, ICAL_ANY_COMPONENT);
         comp;
         comp = icalcomponent_get_next_component(ical, ICAL_ANY_COMPONENT)) {
        replace_tzid_aliases(comp, tzid_table);
    }
}


/* Strip all VTIMEZONE components for known TZIDs */
static void strip_vtimezones(icalcomponent *ical)
{
    struct hash_table tzid_table;
    icalcomponent *vtz, *next;

    /* Create hash table for TZID aliases */
    construct_hash_table(&tzid_table, 10, 1);

    for (vtz = icalcomponent_get_first_component(ical, ICAL_VTIMEZONE_COMPONENT);
         vtz; vtz = next) {

        next = icalcomponent_get_next_component(ical, ICAL_VTIMEZONE_COMPONENT);

        icalproperty *prop =
            icalcomponent_get_first_property(vtz, ICAL_TZID_PROPERTY);
        const char *tzid = icalproperty_get_tzid(prop);
        struct zoneinfo zi;

        if (!zoneinfo_lookup(tzid, &zi)) {
            if (zi.type == ZI_LINK) {
                /* Add this alias to our table */
                hash_insert(tzid, xstrdup(zi.data->s), &tzid_table);
            }
            freestrlist(zi.data);

            icalcomponent_remove_component(ical, vtz);
            icalcomponent_free(vtz);
        }
    }

    if (hash_numrecords(&tzid_table)) {
        /* Replace all TZID aliases with actual TZIDs.
           Note: This NEEDS to be done, otherwise looking up the
           builtin timezone will fail on a TZID mismatch. */
        replace_tzid_aliases(ical, &tzid_table);
    }
    free_hash_table(&tzid_table, free);
}


/* Store the iCal data in the specified calendar/resource */
int caldav_store_resource(struct transaction_t *txn, icalcomponent *ical,
                          struct mailbox *mailbox, const char *resource,
                          struct caldav_db *caldavdb, unsigned flags,
                          const char *schedule_address)
{
    int ret;
    icalcomponent *comp;
    icalcomponent_kind kind;
    icalproperty_method meth;
    icalproperty *prop;
    unsigned mykind = 0, tzbyref = 0;
    const char *organizer = NULL;
    const char *prop_annot =
        DAV_ANNOT_NS "<" XML_NS_CALDAV ">supported-calendar-component-set";
    struct buf attrib = BUF_INITIALIZER;
    struct caldav_data *cdata;
    const char *uid;
    struct index_record *oldrecord = NULL, record;
    char datestr[80], *mimehdr;
    const char *sched_tag;
    strarray_t imapflags = STRARRAY_INITIALIZER;

    /* Check for supported component type */
    comp = icalcomponent_get_first_real_component(ical);
    uid = icalcomponent_get_uid(comp);
    kind = icalcomponent_isa(comp);
    switch (kind) {
    case ICAL_VEVENT_COMPONENT: mykind = CAL_COMP_VEVENT; break;
    case ICAL_VTODO_COMPONENT: mykind = CAL_COMP_VTODO; break;
    case ICAL_VJOURNAL_COMPONENT: mykind = CAL_COMP_VJOURNAL; break;
    case ICAL_VFREEBUSY_COMPONENT: mykind = CAL_COMP_VFREEBUSY; break;
    case ICAL_VAVAILABILITY_COMPONENT: mykind = CAL_COMP_VAVAILABILITY; break;
#ifdef HAVE_VPOLL
    case ICAL_VPOLL_COMPONENT: mykind = CAL_COMP_VPOLL; break;
#endif
    default:
        txn->error.precond = CALDAV_SUPP_COMP;
        return HTTP_FORBIDDEN;
    }

    if (!annotatemore_lookupmask(mailbox->name,
                                 prop_annot, httpd_userid, &attrib)
        && attrib.len) {
        unsigned long supp_comp = strtoul(buf_cstring(&attrib), NULL, 10);

        buf_free(&attrib);

        if (!(mykind & supp_comp)) {
            txn->error.precond = CALDAV_SUPP_COMP;
            return HTTP_FORBIDDEN;
        }
    }

    /* Find message UID for the resource, if exists */
    caldav_lookup_resource(caldavdb, mailbox->name, resource, &cdata, 0);

    /* does it already exist? */
    if (cdata->dav.imap_uid) {
        /* Check for change of iCalendar UID */
        if (strcmp(cdata->ical_uid, uid)) {
            /* CALDAV:no-uid-conflict */
            txn->error.precond = CALDAV_UID_CONFLICT;
            return HTTP_FORBIDDEN;
        }
        /* Fetch index record for the resource */
        oldrecord = &record;
        mailbox_find_index_record(mailbox, cdata->dav.imap_uid, oldrecord);
    }

    /* Remove all X-LIC-ERROR properties */
    icalcomponent_strip_errors(ical);

    /* Remove all VTIMEZONE components for known TZIDs */
    if (namespace_calendar.allow & ALLOW_CAL_NOTZ) {
        strip_vtimezones(ical);
        tzbyref = 1;
    }

    /* If we are just stripping VTIMEZONEs from resource, flag it */
    if (flags & TZ_STRIP) strarray_append(&imapflags, DFLAG_UNCHANGED);

    /* Create and cache RFC 5322 header fields for resource */
    prop = icalcomponent_get_first_property(comp, ICAL_ORGANIZER_PROPERTY);
    if (prop) {
        organizer = icalproperty_get_organizer(prop);
        if (organizer) {
            if (!strncasecmp(organizer, "mailto:", 7)) organizer += 7;
            assert(!buf_len(&txn->buf));
            buf_printf(&txn->buf, "<%s>", organizer);
            mimehdr = charset_encode_mimeheader(buf_cstring(&txn->buf),
                                                buf_len(&txn->buf));
            spool_replace_header(xstrdup("From"), mimehdr, txn->req_hdrs);
            buf_reset(&txn->buf);
        }
    }

    /* Set Schedule-Tag, if any */
    if (flags & NEW_STAG) {
        if (oldrecord) sched_tag = message_guid_encode(&oldrecord->guid);
        else sched_tag = NULL_ETAG;
    }
    else if (organizer) sched_tag = cdata->sched_tag;
    else sched_tag = cdata->sched_tag = NULL;

    prop = icalcomponent_get_first_property(comp, ICAL_SUMMARY_PROPERTY);
    if (prop) {
        mimehdr = charset_encode_mimeheader(icalproperty_get_summary(prop), 0);
        spool_replace_header(xstrdup("Subject"), mimehdr, txn->req_hdrs);
    }
    else spool_replace_header(xstrdup("Subject"),
                            xstrdup(icalcomponent_kind_to_string(kind)),
                            txn->req_hdrs);

    if (schedule_address) {
        mimehdr = charset_encode_mimeheader(schedule_address, 0);
        spool_replace_header(xstrdup("X-Schedule-User-Address"),
                             mimehdr, txn->req_hdrs);
    }

    time_to_rfc822(icaltime_as_timet_with_zone(icalcomponent_get_dtstamp(comp),
                                               utc_zone),
                   datestr, sizeof(datestr));
    spool_replace_header(xstrdup("Date"), xstrdup(datestr), txn->req_hdrs);

    buf_reset(&txn->buf);

    /* XXX - validate uid for mime safety? */
    if (strchr(uid, '@')) {
        buf_printf(&txn->buf, "<%s>", uid);
    }
    else {
        buf_printf(&txn->buf, "<%s@%s>", uid, config_servername);
    }
    spool_replace_header(xstrdup("Message-ID"),
                         buf_release(&txn->buf), txn->req_hdrs);

    buf_setcstr(&txn->buf, ICALENDAR_CONTENT_TYPE);
    if ((meth = icalcomponent_get_method(ical)) != ICAL_METHOD_NONE) {
        buf_printf(&txn->buf, "; method=%s",
                   icalproperty_method_to_string(meth));
    }
    buf_printf(&txn->buf, "; component=%s", icalcomponent_kind_to_string(kind));
    spool_replace_header(xstrdup("Content-Type"),
                         buf_release(&txn->buf), txn->req_hdrs);

    buf_printf(&txn->buf, "attachment;\r\n\tfilename=\"%s\"", resource);
    if (sched_tag) buf_printf(&txn->buf, ";\r\n\tschedule-tag=%s", sched_tag);
    if (tzbyref) buf_printf(&txn->buf, ";\r\n\ttz-by-ref=true");
    spool_replace_header(xstrdup("Content-Disposition"),
                         buf_release(&txn->buf), txn->req_hdrs);

    spool_remove_header(xstrdup("Content-Description"), txn->req_hdrs);

    /* Store the resource */
    ret = dav_store_resource(txn, icalcomponent_as_ical_string(ical), 0,
                             mailbox, oldrecord, &imapflags);
    strarray_fini(&imapflags);

    switch (ret) {
    case HTTP_CREATED:
    case HTTP_NO_CONTENT:
        if (cdata->organizer && (flags & NEW_STAG)) {
            txn->resp_body.stag = sched_tag;
        }

        if (!(flags & PREFER_REP)) {
            /* iCal data has been rewritten - don't return validators */
            txn->resp_body.lastmod = 0;
            txn->resp_body.etag = NULL;
        }
        break;
    }

    return ret;
}


static struct mime_type_t freebusy_mime_types[] = {
    /* First item MUST be the default type */
    { ICALENDAR_CONTENT_TYPE, "2.0", "ifb",
      (struct buf* (*)(void *)) &my_icalcomponent_as_ical_string,
      NULL, NULL, NULL, NULL
    },
    { "application/calendar+xml; charset=utf-8", NULL, "xfb",
      (struct buf* (*)(void *)) &icalcomponent_as_xcal_string,
      NULL, NULL, NULL, NULL
    },
    { "application/calendar+json; charset=utf-8", NULL, "jfb",
      (struct buf* (*)(void *)) &icalcomponent_as_jcal_string,
      NULL, NULL, NULL, NULL
    },
    { NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL }
};


/* Execute a free/busy query per
   http://www.calconnect.org/pubdocs/CD0903%20Freebusy%20Read%20URL.pdf */
static int meth_get_head_fb(struct transaction_t *txn,
                            void *params __attribute__((unused)))

{
    int ret = 0, r, rights;
    struct tm *tm;
    struct strlist *param;
    struct mime_type_t *mime = NULL;
    struct propfind_ctx fctx;
    struct freebusy_filter fbfilter;
    time_t start;
    struct icaldurationtype period = icaldurationtype_null_duration();
    icalcomponent *cal;

    /* Parse the path */
    if ((r = caldav_parse_path(txn->req_uri->path,
                               &txn->req_tgt, &txn->error.desc))) return r;

    if (txn->req_tgt.resource ||
        !(txn->req_tgt.userid)) {
        /* We don't handle GET on a resources or non-calendar collections */
        return HTTP_NO_CONTENT;
    }

    /* Check ACL for current user */
    rights = httpd_myrights(httpd_authstate, txn->req_tgt.mbentry);
    if (!(rights & DACL_READFB)) {
        /* DAV:need-privileges */
        txn->error.precond = DAV_NEED_PRIVS;
        txn->error.resource = txn->req_tgt.path;
        txn->error.rights = DACL_READFB;
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

    /* Check/find 'format' */
    param = hash_lookup("format", &txn->req_qparams);
    if (param) {
        if (param->next  /* once only */) return HTTP_BAD_REQUEST;

        for (mime = freebusy_mime_types; mime->content_type; mime++) {
            if (is_mediatype(param->s, mime->content_type)) break;
        }
    }
    else mime = freebusy_mime_types;

    if (!mime || !mime->content_type) return HTTP_NOT_ACCEPTABLE;

    memset(&fbfilter, 0, sizeof(struct freebusy_filter));
    fbfilter.flags = CHECK_CAL_TRANSP | CHECK_USER_AVAIL;

    /* Check for 'start' */
    param = hash_lookup("start", &txn->req_qparams);
    if (param) {
        if (param->next  /* once only */) return HTTP_BAD_REQUEST;

        fbfilter.start = icaltime_from_rfc3339_string(param->s);
        if (icaltime_is_null_time(fbfilter.start)) return HTTP_BAD_REQUEST;

        /* Default to end of given day */
        start = icaltime_as_timet_with_zone(fbfilter.start, utc_zone);
        tm = localtime(&start);

        period.seconds = 60 - tm->tm_sec;
        period.minutes = 59 - tm->tm_min;
        period.hours   = 23 - tm->tm_hour;
    }
    else {
        /* Default to start of current day */
        start = time(0);
        tm = localtime(&start);
        tm->tm_hour = tm->tm_min = tm->tm_sec = 0;
        fbfilter.start = icaltime_from_timet_with_zone(mktime(tm), 0, utc_zone);

        /* Default to 42 day period */
        period.days = 42;
    }

    /* Check for 'period' */
    param = hash_lookup("period", &txn->req_qparams);
    if (param) {
        if (param->next  /* once only */ ||
            hash_lookup("end", &txn->req_qparams)  /* can't use with 'end' */)
            return HTTP_BAD_REQUEST;

        period = icaldurationtype_from_string(param->s);
        if (icaldurationtype_is_bad_duration(period)) return HTTP_BAD_REQUEST;
    }

    /* Check for 'end' */
    param = hash_lookup("end", &txn->req_qparams);
    if (param) {
        if (param->next  /* once only */) return HTTP_BAD_REQUEST;

        fbfilter.end = icaltime_from_rfc3339_string(param->s);
        if (icaltime_is_null_time(fbfilter.end)) return HTTP_BAD_REQUEST;
    }
    else {
        /* Set end based on period */
        fbfilter.end = icaltime_add(fbfilter.start, period);
    }


    memset(&fctx, 0, sizeof(struct propfind_ctx));
    fctx.txn = txn;
    fctx.req_tgt = &txn->req_tgt;
    fctx.depth = 2;
    fctx.userid = httpd_userid;
    fctx.userisadmin = httpd_userisadmin;
    fctx.authstate = httpd_authstate;
    fctx.reqd_privs = 0;  /* handled by CALDAV:schedule-deliver on Inbox */
    fctx.filter_crit = &fbfilter;
    fctx.ret = &ret;

    cal = busytime_query_local(txn, &fctx, txn->req_tgt.mbentry->name,
                               0, NULL, NULL, NULL);

    if (fbfilter.freebusy.fb) free(fbfilter.freebusy.fb);

    if (cal) {
        const char *proto, *host;
        icalcomponent *fb;
        icalproperty *url;
        struct buf *cal_str;

        /* Construct URL */
        buf_reset(&txn->buf);
        http_proto_host(txn->req_hdrs, &proto, &host);
        buf_printf(&txn->buf, "%s://%s%s", proto, host, txn->req_uri->path);
        if (URI_QUERY(txn->req_uri))
            buf_printf(&txn->buf, "?%s", URI_QUERY(txn->req_uri));

        /* Set URL property */
        fb = icalcomponent_get_first_component(cal, ICAL_VFREEBUSY_COMPONENT);
        url = icalproperty_new_url(buf_cstring(&txn->buf));
        icalcomponent_add_property(fb, url);

        /* Set filename of resource */
        buf_reset(&txn->buf);
        buf_printf(&txn->buf, "%s.%s",
                   txn->req_tgt.userid,
                   mime->file_ext);
        txn->resp_body.fname = buf_cstring(&txn->buf);

        txn->resp_body.type = mime->content_type;

        /* iCalendar data in response should not be transformed */
        txn->flags.cc |= CC_NOTRANSFORM;

        /* Output the iCalendar object */
        cal_str = mime->from_object(cal);
        icalcomponent_free(cal);

        write_body(HTTP_OK, txn, buf_base(cal_str), buf_len(cal_str));
        buf_destroy(cal_str);
    }
    else ret = HTTP_NOT_FOUND;

    return ret;
}


static int meth_options_cal(struct transaction_t *txn, void *params)
{
    int r;

    /* Parse the path */
    if ((r = caldav_parse_path(txn->req_uri->path,
                               &txn->req_tgt, &txn->error.desc))) return r;

    if (txn->req_tgt.allow & ALLOW_PATCH) {
        /* Add Accept-Patch formats to response */
        txn->resp_body.patch = caldav_patch_docs;
    }

    return meth_options(txn, params);
}
