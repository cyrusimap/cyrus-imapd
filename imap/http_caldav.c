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
 *   - Add more required properties
 *   - GET/HEAD on collections (iCalendar stream of resources)
 *   - calendar-query REPORT (handle partial retrieval, prop-filter, timezone?)
 *   - free-busy-query REPORT (check ACL and transp on all calendars)
 *   - sync-collection REPORT - need to handle Depth infinity?
 */

#include <config.h>

#include <syslog.h>

#include <libical/ical.h>
#include <libxml/tree.h>
#include <libxml/uri.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "acl.h"
#include "append.h"
#include "caldav_db.h"
#include "global.h"
#include "hash.h"
#include "httpd.h"
#include "http_caldav_sched.h"
#include "http_dav.h"
#include "http_err.h"
#include "http_proxy.h"
#include "imap_err.h"
#include "index.h"
#include "jcal.h"
#include "xcal.h"
#include "mailbox.h"
#include "mboxlist.h"
#include "message.h"
#include "message_guid.h"
#include "proxy.h"
#include "rfc822date.h"
#include "smtpclient.h"
#include "spool.h"
#include "stristr.h"
#include "tok.h"
#include "util.h"
#include "version.h"
#include "xmalloc.h"
#include "xstrlcat.h"
#include "xstrlcpy.h"

#define NEW_STAG (1<<8)  /* Make sure we skip over PREFER bits */

struct busytime {
    struct icalperiodtype *busy;
    unsigned len;
    unsigned alloc;
};

struct calquery_filter {
    unsigned comp;
    struct icaltimetype start;
    struct icaltimetype end;
    unsigned check_transp;
    unsigned save_busytime;
    struct busytime busytime;    	/* array of found busytime periods */
};

static struct caldav_db *auth_caldavdb = NULL;
static time_t compile_time;

static void my_caldav_init(struct buf *serverinfo);
static void my_caldav_auth(const char *userid);
static void my_caldav_reset(void);
static void my_caldav_shutdown(void);

static int caldav_parse_path(const char *path,
			     struct request_target_t *tgt, const char **errstr);

static int caldav_check_precond(struct transaction_t *txn, const void *data,
				const char *etag, time_t lastmod);

static int caldav_acl(struct transaction_t *txn, xmlNodePtr priv, int *rights);
static int caldav_copy(struct transaction_t *txn,
		       struct mailbox *src_mbox, struct index_record *src_rec,
		       struct mailbox *dest_mbox, const char *dest_rsrc,
		       unsigned overwrite, unsigned flags);
static int caldav_delete_sched(struct transaction_t *txn,
			       struct mailbox *mailbox,
			       struct index_record *record, void *data);
static int meth_get(struct transaction_t *txn, void *params);
static int caldav_post(struct transaction_t *txn);
static int caldav_put(struct transaction_t *txn,
		      struct mime_type_t *mime,
		      struct mailbox *mailbox, unsigned flags);

static int propfind_getcontenttype(const xmlChar *name, xmlNsPtr ns,
				   struct propfind_ctx *fctx, xmlNodePtr resp,
				   struct propstat propstat[], void *rock);
static int propfind_restype(const xmlChar *name, xmlNsPtr ns,
			    struct propfind_ctx *fctx, xmlNodePtr resp,
			    struct propstat propstat[], void *rock);
static int propfind_reportset(const xmlChar *name, xmlNsPtr ns,
			      struct propfind_ctx *fctx, xmlNodePtr resp,
			      struct propstat propstat[], void *rock);
static int propfind_caldata(const xmlChar *name, xmlNsPtr ns,
			    struct propfind_ctx *fctx, xmlNodePtr resp,
			    struct propstat propstat[], void *rock);
static int propfind_calcompset(const xmlChar *name, xmlNsPtr ns,
			       struct propfind_ctx *fctx, xmlNodePtr resp,
			       struct propstat propstat[], void *rock);
static int proppatch_calcompset(xmlNodePtr prop, unsigned set,
				struct proppatch_ctx *pctx,
				struct propstat propstat[], void *rock);
static int propfind_suppcaldata(const xmlChar *name, xmlNsPtr ns,
				struct propfind_ctx *fctx, xmlNodePtr resp,
				struct propstat propstat[], void *rock);
static int propfind_schedtag(const xmlChar *name, xmlNsPtr ns,
			     struct propfind_ctx *fctx, xmlNodePtr resp,
			     struct propstat propstat[], void *rock);
static int propfind_caltransp(const xmlChar *name, xmlNsPtr ns,
			      struct propfind_ctx *fctx, xmlNodePtr resp,
			      struct propstat propstat[], void *rock);
static int proppatch_caltransp(xmlNodePtr prop, unsigned set,
			       struct proppatch_ctx *pctx,
			       struct propstat propstat[], void *rock);
static int propfind_timezone(const xmlChar *name, xmlNsPtr ns,
			    struct propfind_ctx *fctx, xmlNodePtr resp,
			    struct propstat propstat[], void *rock);
static int proppatch_timezone(xmlNodePtr prop, unsigned set,
			      struct proppatch_ctx *pctx,
			      struct propstat propstat[], void *rock);

static int report_cal_query(struct transaction_t *txn, xmlNodePtr inroot,
			    struct propfind_ctx *fctx);
static int report_cal_multiget(struct transaction_t *txn, xmlNodePtr inroot,
			       struct propfind_ctx *fctx);
static int report_fb_query(struct transaction_t *txn, xmlNodePtr inroot,
			   struct propfind_ctx *fctx);

static int store_resource(struct transaction_t *txn, icalcomponent *ical,
			  struct mailbox *mailbox, const char *resource,
			  struct caldav_db *caldavdb, int overwrite,
			  unsigned flags);

static void sched_request(const char *organizer, struct sched_param *sparam,
			  icalcomponent *oldical, icalcomponent *newical,
			  const char *att_update);
static void sched_reply(const char *userid,
			icalcomponent *oldical, icalcomponent *newical);

static const char *begin_icalendar(struct buf *buf);
static void end_icalendar(struct buf *buf);

static struct mime_type_t caldav_mime_types[] = {
    /* First item MUST be the default type and storage format */
    { "text/calendar; charset=utf-8", "2.0", "ics", "ifb",
      (char* (*)(void *)) &icalcomponent_as_ical_string_r,
      (void * (*)(const char*)) &icalparser_parse_string,
      (void (*)(void *)) &icalcomponent_free, &begin_icalendar, &end_icalendar
    },
    { "application/calendar+xml; charset=utf-8", NULL, "xcs", "xfb",
      (char* (*)(void *)) &icalcomponent_as_xcal_string,
      (void * (*)(const char*)) &xcal_string_as_icalcomponent,
      NULL, &begin_xcal, &end_xcal
    },
#ifdef WITH_JSON
    { "application/calendar+json; charset=utf-8", NULL, "jcs", "jfb",
      (char* (*)(void *)) &icalcomponent_as_jcal_string,
      (void * (*)(const char*)) &jcal_string_as_icalcomponent,
      NULL, &begin_jcal, &end_jcal
    },
#endif
    { NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL }
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
      propfind_reportset, NULL, NULL },

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
      propfind_sync_token, NULL, NULL },

    /* CalDAV (RFC 4791) properties */
    { "calendar-data", NS_CALDAV,
      PROP_RESOURCE | PROP_PRESCREEN | PROP_NEEDPROP,
      propfind_caldata, NULL, NULL },
    { "calendar-description", NS_CALDAV, PROP_COLLECTION,
      propfind_fromdb, proppatch_todb, NULL },
    { "calendar-timezone", NS_CALDAV,
      PROP_COLLECTION | PROP_PRESCREEN | PROP_NEEDPROP,
      propfind_timezone, proppatch_timezone, NULL },
    { "supported-calendar-component-set", NS_CALDAV, PROP_COLLECTION,
      propfind_calcompset, proppatch_calcompset, NULL },
    { "supported-calendar-data", NS_CALDAV, PROP_COLLECTION,
      propfind_suppcaldata, NULL, NULL },
    { "max-resource-size", NS_CALDAV, 0, NULL, NULL, NULL },
    { "min-date-time", NS_CALDAV, 0, NULL, NULL, NULL },
    { "max-date-time", NS_CALDAV, 0, NULL, NULL, NULL },
    { "max-instances", NS_CALDAV, 0, NULL, NULL, NULL },
    { "max-attendees-per-instance", NS_CALDAV, 0, NULL, NULL, NULL },

    /* CalDAV Scheduling (RFC 6638) properties */
    { "schedule-tag", NS_CALDAV, PROP_RESOURCE,
      propfind_schedtag, NULL, NULL },
    { "schedule-default-calendar-URL", NS_CALDAV, PROP_COLLECTION,
      propfind_calurl, NULL, SCHED_DEFAULT },
    { "schedule-calendar-transp", NS_CALDAV, PROP_COLLECTION,
      propfind_caltransp, proppatch_caltransp, NULL },

    /* Apple Calendar Server properties */
    { "getctag", NS_CS, PROP_ALLPROP | PROP_COLLECTION,
      propfind_sync_token, NULL, NULL },

    { NULL, 0, 0, NULL, NULL, NULL }
};


static struct meth_params caldav_params = {
    caldav_mime_types,
    &caldav_parse_path,
    &caldav_check_precond,
    { (void **) &auth_caldavdb,
      (db_lookup_proc_t) &caldav_lookup_resource,
      (db_foreach_proc_t) &caldav_foreach,
      (db_write_proc_t) &caldav_write,
      (db_delete_proc_t) &caldav_delete,
      (db_delmbox_proc_t) &caldav_delmbox },
    &caldav_acl,
    &caldav_copy,
    &caldav_delete_sched,
    { MBTYPE_CALENDAR, "mkcalendar", "mkcalendar-response", NS_CALDAV },
    &caldav_post,
    { CALDAV_SUPP_DATA, &caldav_put },
    caldav_props,
    { { "calendar-query", &report_cal_query, DACL_READ,
	REPORT_NEED_MBOX | REPORT_MULTISTATUS },
      { "calendar-multiget", &report_cal_multiget, DACL_READ,
	REPORT_NEED_MBOX | REPORT_MULTISTATUS },
      { "free-busy-query", &report_fb_query, DACL_READFB,
	REPORT_NEED_MBOX },
      { "sync-collection", &report_sync_col, DACL_READ,
	REPORT_NEED_MBOX | REPORT_MULTISTATUS | REPORT_NEED_PROPS },
      { NULL, NULL, 0, 0 } }
};


/* Namespace for CalDAV collections */
struct namespace_t namespace_calendar = {
    URL_NS_CALENDAR, 0, "/dav/calendars", "/.well-known/caldav", 1 /* auth */,
    (ALLOW_READ | ALLOW_POST | ALLOW_WRITE | ALLOW_DELETE |
     ALLOW_DAV | ALLOW_WRITECOL | ALLOW_CAL ),
    &my_caldav_init, &my_caldav_auth, my_caldav_reset, &my_caldav_shutdown,
    { 
	{ &meth_acl,		&caldav_params },	/* ACL		*/
	{ &meth_copy,		&caldav_params },	/* COPY		*/
	{ &meth_delete,		&caldav_params },	/* DELETE	*/
	{ &meth_get,		&caldav_params },	/* GET		*/
	{ &meth_get,		&caldav_params },	/* HEAD		*/
	{ &meth_lock,		&caldav_params },	/* LOCK		*/
	{ &meth_mkcol,		&caldav_params },	/* MKCALENDAR	*/
	{ &meth_mkcol,		&caldav_params },	/* MKCOL	*/
	{ &meth_copy,		&caldav_params },	/* MOVE		*/
	{ &meth_options,	&caldav_parse_path },	/* OPTIONS	*/
	{ &meth_post,		&caldav_params },	/* POST		*/
	{ &meth_propfind,	&caldav_params },	/* PROPFIND	*/
	{ &meth_proppatch,	&caldav_params },	/* PROPPATCH	*/
	{ &meth_put,		&caldav_params },	/* PUT		*/
	{ &meth_report,		&caldav_params },	/* REPORT	*/
	{ &meth_trace,		&caldav_parse_path },	/* TRACE	*/
	{ &meth_unlock,		&caldav_params } 	/* UNLOCK	*/
    }
};


static void my_caldav_init(struct buf *serverinfo)
{
    namespace_calendar.enabled =
	config_httpmodules & IMAP_ENUM_HTTPMODULES_CALDAV;

    if (!namespace_calendar.enabled) return;

    if (!config_getstring(IMAPOPT_CALENDARPREFIX)) {
	fatal("Required 'calendarprefix' option is not set", EC_CONFIG);
    }

    caldav_init();

    if (config_serverinfo == IMAP_ENUM_SERVERINFO_ON) {
	buf_printf(serverinfo, " libical/%s", ICAL_VERSION);
#ifdef WITH_JSON
	buf_printf(serverinfo, " Jansson/%s", JANSSON_VERSION);
#endif
    }

    if (config_getswitch(IMAPOPT_CALDAV_ALLOWSCHEDULING)) {
	namespace_calendar.allow |= ALLOW_CAL_SCHED;

	/* Need to set this to parse CalDAV Scheduling parameters */
	ical_set_unknown_token_handling_setting(ICAL_ASSUME_IANA_TOKEN);
    }

    compile_time = calc_compile_time(__TIME__, __DATE__);
}


static void my_caldav_auth(const char *userid)
{
    int r;
    struct mboxlist_entry mbentry;
    char mailboxname[MAX_MAILBOX_BUFFER], rights[100], *partition = NULL;
    char ident[MAX_MAILBOX_NAME];
    struct buf acl = BUF_INITIALIZER;

    if (httpd_userisadmin ||
	global_authisa(httpd_authstate, IMAPOPT_PROXYSERVERS)) {
	/* admin or proxy from frontend - won't have DAV database */
	return;
    }
    else if (config_mupdate_server && !config_getstring(IMAPOPT_PROXYSERVERS)) {
	/* proxy-only server - won't have DAV database */
    }
    else {
	/* Open CalDAV DB for 'userid' */
	my_caldav_reset();
	auth_caldavdb = caldav_open(userid, CALDAV_CREATE);
	if (!auth_caldavdb) fatal("Unable to open CalDAV DB", EC_IOERR);
    }

    /* Auto-provision calendars for 'userid' */

    strlcpy(ident, userid, sizeof(ident));
    mboxname_hiersep_toexternal(&httpd_namespace, ident, 0);

    /* calendar-home-set */
    caldav_mboxname(NULL, userid, mailboxname);
    r = mboxlist_lookup(mailboxname, &mbentry, NULL);
    if (r == IMAP_MAILBOX_NONEXISTENT) {
	if (config_mupdate_server) {
	    /* Find location of INBOX */
	    char inboxname[MAX_MAILBOX_BUFFER];

	    r = (*httpd_namespace.mboxname_tointernal)(&httpd_namespace,
						       "INBOX",
						       userid, inboxname);
	    if (!r) {
		char *server;

		r = http_mlookup(inboxname, &server, NULL, NULL);
		if (!r && server) {
		    proxy_findserver(server, &http_protocol, proxy_userid,
				     &backend_cached, NULL, NULL, httpd_in);

		    return;
		}
	    }
	}

	/* Create locally */
	if (!r) r = mboxlist_createmailboxcheck(mailboxname, 0, NULL, 0,
						userid, httpd_authstate, NULL,
						&partition, 0);
	if (!r) {
	    buf_reset(&acl);
	    cyrus_acl_masktostr(ACL_ALL | DACL_READFB, rights);
	    buf_printf(&acl, "%s\t%s\t", ident, rights);
	    cyrus_acl_masktostr(DACL_READFB, rights);
	    buf_printf(&acl, "%s\t%s\t", "anyone", rights);
	    r = mboxlist_createmailbox_full(mailboxname, MBTYPE_CALENDAR,
					    partition, 0,
					    userid, httpd_authstate,
					    OPT_POP3_NEW_UIDL, time(0),
					    buf_cstring(&acl), NULL,
					    0, 0, 0, NULL);
	}
	mbentry.partition = partition;
    }
    if (r) {
	if (partition) free(partition);
	buf_free(&acl);
	return;
    }

    /* Default calendar */
    caldav_mboxname(SCHED_DEFAULT, userid, mailboxname);
    r = mboxlist_lookup(mailboxname, NULL, NULL);
    if (r == IMAP_MAILBOX_NONEXISTENT) {
	buf_reset(&acl);
	cyrus_acl_masktostr(ACL_ALL | DACL_READFB, rights);
	buf_printf(&acl, "%s\t%s\t", ident, rights);
	cyrus_acl_masktostr(DACL_READFB, rights);
	buf_printf(&acl, "%s\t%s\t", "anyone", rights);
	r = mboxlist_createmailbox_full(mailboxname, MBTYPE_CALENDAR,
					mbentry.partition, 0,
					userid, httpd_authstate,
					OPT_POP3_NEW_UIDL, time(0),
					buf_cstring(&acl), NULL,
					0, 0, 0, NULL);
    }

    /* Scheduling Inbox */
    caldav_mboxname(SCHED_INBOX, userid, mailboxname);
    r = mboxlist_lookup(mailboxname, NULL, NULL);
    if (r == IMAP_MAILBOX_NONEXISTENT) {
	buf_reset(&acl);
	cyrus_acl_masktostr(ACL_ALL | DACL_SCHED, rights);
	buf_printf(&acl, "%s\t%s\t", ident, rights);
	cyrus_acl_masktostr(DACL_SCHED, rights);
	buf_printf(&acl, "%s\t%s\t", "anyone", rights);
	r = mboxlist_createmailbox_full(mailboxname, MBTYPE_CALENDAR,
					mbentry.partition, 0,
					userid, httpd_authstate,
					OPT_POP3_NEW_UIDL, time(0),
					buf_cstring(&acl), NULL,
					0, 0, 0, NULL);
    }

    /* Scheduling Outbox */
    caldav_mboxname(SCHED_OUTBOX, userid, mailboxname);
    r = mboxlist_lookup(mailboxname, NULL, NULL);
    if (r == IMAP_MAILBOX_NONEXISTENT) {
	buf_reset(&acl);
	cyrus_acl_masktostr(ACL_ALL | DACL_SCHED, rights);
	buf_printf(&acl, "%s\t%s\t", ident, rights);
	r = mboxlist_createmailbox_full(mailboxname, MBTYPE_CALENDAR,
					mbentry.partition, 0,
					userid, httpd_authstate,
					OPT_POP3_NEW_UIDL, time(0),
					buf_cstring(&acl), NULL,
					0, 0, 0, NULL);
    }

    if (partition) free(partition);
    buf_free(&acl);
}


static void my_caldav_reset(void)
{
    if (auth_caldavdb) caldav_close(auth_caldavdb);
    auth_caldavdb = NULL;
}


static void my_caldav_shutdown(void)
{
    caldav_done();
}


/* Parse request-target path in CalDAV namespace */
static int caldav_parse_path(const char *path,
			     struct request_target_t *tgt, const char **errstr)
{
    char *p;
    size_t len, siz;
    static const char *prefix = NULL;

    /* Make a working copy of target path */
    strlcpy(tgt->path, path, sizeof(tgt->path));
    tgt->tail = tgt->path + strlen(tgt->path);

    p = tgt->path;

    /* Sanity check namespace */
    len = strlen(namespace_calendar.prefix);
    if (strlen(p) < len ||
	strncmp(namespace_calendar.prefix, p, len) ||
	(path[len] && path[len] != '/')) {
	*errstr = "Namespace mismatch request target path";
	return HTTP_FORBIDDEN;
    }

    /* Default to bare-bones Allow bits for toplevel collections */
    tgt->allow &= ~(ALLOW_POST|ALLOW_WRITE|ALLOW_DELETE);

    /* Skip namespace */
    p += len;
    if (!*p || !*++p) return 0;

    /* Check if we're in user space */
    len = strcspn(p, "/");
    if (!strncmp(p, "user", len)) {
	p += len;
	if (!*p || !*++p) return 0;

	/* Get user id */
	len = strcspn(p, "/");
	tgt->user = p;
	tgt->userlen = len;

	p += len;
	if (!*p || !*++p) {
	    /* Make sure calendar-home-set is terminated with '/' */
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
//	*errstr = "Too many segments in request target path";
	return HTTP_NOT_FOUND;
    }

  done:
    /* Set proper Allow bits and flags based on path components */
    if (tgt->collection) {
	if (tgt->resource) {
	    tgt->allow &= ~ALLOW_WRITECOL;
	    tgt->allow |= (ALLOW_WRITE|ALLOW_DELETE);
	}
	else if (!strcmp(tgt->collection, SCHED_INBOX))
	    tgt->flags = TGT_SCHED_INBOX;
	else if (!strcmp(tgt->collection, SCHED_OUTBOX)) {
	    tgt->flags = TGT_SCHED_OUTBOX;
	    tgt->allow |= ALLOW_POST;
	}
	else if (!strcmp(tgt->collection, SCHED_DEFAULT))
	    tgt->allow |= ALLOW_POST;
	else
	    tgt->allow |= (ALLOW_POST|ALLOW_DELETE);
    }
    else if (tgt->user) tgt->allow |= ALLOW_DELETE;


    /* Create mailbox name from the parsed path */ 
    if (!prefix) prefix = config_getstring(IMAPOPT_CALENDARPREFIX);

    p = tgt->mboxname;
    siz = MAX_MAILBOX_BUFFER;
    if (tgt->user) {
	len = snprintf(p, siz, "user");
	p += len;
	siz -= len;

	if (tgt->userlen) {
	    len = snprintf(p, siz, ".%.*s", (int) tgt->userlen, tgt->user);
	    mboxname_hiersep_tointernal(&httpd_namespace, p+1, tgt->userlen);
	    p += len;
	    siz -= len;
	}
    }

    len = snprintf(p, siz, "%s%s", p != tgt->mboxname ? "." : "", prefix);
    p += len;
    siz -= len;

    if (tgt->collection) {
	snprintf(p, siz, ".%.*s", (int) tgt->collen, tgt->collection);
    }

    return 0;
}


/* Check headers for any preconditions */
static int caldav_check_precond(struct transaction_t *txn, const void *data,
				const char *etag, time_t lastmod)
{
    const struct caldav_data *cdata = (const struct caldav_data *) data;
    const char *stag = cdata ? cdata->sched_tag : NULL;
    const char **hdr;
    int precond;

    /* Do normal WebDAV/HTTP checks (primarily for lock-token via If header) */
    precond = check_precond(txn, data, etag, lastmod);
    if (!(precond == HTTP_OK || precond == HTTP_PARTIAL)) return precond;

    /* Per RFC 6638, check Schedule-Tag */
    if ((hdr = spool_getheader(txn->req_hdrs, "If-Schedule-Tag-Match"))) {
	if (!*hdr[0]) {
	    /* XXX  Workaround for bug in MacOS X 10.9.0 Calendar client */
	    const char *osx_sched_tag_bug_version =
		"Mac_OS_X/10.9 (13A603) CalendarAgent/174";
	    const char **ua = spool_getheader(txn->req_hdrs, "User-Agent");

	    if (ua && !strcmp(ua[0], osx_sched_tag_bug_version)) return precond;
	}
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
	    if (xmlStrcmp(priv->name, BAD_CAST "read-free-busy"))
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
static int caldav_copy(struct transaction_t *txn,
		       struct mailbox *src_mbox, struct index_record *src_rec,
		       struct mailbox *dest_mbox, const char *dest_rsrc,
		       unsigned overwrite, unsigned flags)
{
    int ret;

    const char *msg_base = NULL, *organizer = NULL;
    unsigned long msg_size = 0;
    icalcomponent *ical, *comp;
    icalproperty *prop;

    /* Load message containing the resource and parse iCal data */
    mailbox_map_message(src_mbox, src_rec->uid, &msg_base, &msg_size);
    ical = icalparser_parse_string(msg_base + src_rec->header_size);
    mailbox_unmap_message(src_mbox, src_rec->uid, &msg_base, &msg_size);

    if (!ical) {
	txn->error.precond = CALDAV_VALID_DATA;
	return HTTP_FORBIDDEN;
    }

    /* Finished our initial read of source mailbox */
    mailbox_unlock_index(src_mbox, NULL);

    if (namespace_calendar.allow & ALLOW_CAL_SCHED) {
	comp = icalcomponent_get_first_real_component(ical);
	prop = icalcomponent_get_first_property(comp, ICAL_ORGANIZER_PROPERTY);
	if (prop) organizer = icalproperty_get_organizer(prop);
	if (organizer) flags |= NEW_STAG;
    }

    /* Store source resource at destination */
    ret = store_resource(txn, ical, dest_mbox, dest_rsrc, auth_caldavdb,
			 overwrite, flags);

    icalcomponent_free(ical);

    return ret;
}


/* Perform scheduling actions for a DELETE request */
static int caldav_delete_sched(struct transaction_t *txn,
			       struct mailbox *mailbox,
			       struct index_record *record, void *data)
{
    struct caldav_data *cdata = (struct caldav_data *) data;
    int ret = 0;

    if (!(namespace_calendar.allow & ALLOW_CAL_SCHED)) return 0;

    if (!mailbox) {
	/* XXX  DELETE collection - check all resources for sched objects */
    }
    else if (cdata->sched_tag) {
	/* Scheduling object resource */
	const char *msg_base = NULL, *userid, *organizer, **hdr;
	unsigned long msg_size = 0;
	icalcomponent *ical, *comp;
	icalproperty *prop;
	struct sched_param sparam;

	/* Load message containing the resource and parse iCal data */
	mailbox_map_message(mailbox, record->uid, &msg_base, &msg_size);
	ical = icalparser_parse_string(msg_base + record->header_size);
	mailbox_unmap_message(mailbox, record->uid, &msg_base, &msg_size);

	if (!ical) {
	    syslog(LOG_ERR,
		   "meth_delete: failed to parse iCalendar object %s:%u",
		   txn->req_tgt.mboxname, record->uid);
	    return HTTP_SERVER_ERROR;
	}

	/* Construct userid corresponding to mailbox */
	userid = mboxname_to_userid(txn->req_tgt.mboxname);

	/* Grab the organizer */
	comp = icalcomponent_get_first_real_component(ical);
	prop = icalcomponent_get_first_property(comp, ICAL_ORGANIZER_PROPERTY);
	organizer = icalproperty_get_organizer(prop);

	if (caladdress_lookup(organizer, &sparam)) {
	    syslog(LOG_ERR,
		   "meth_delete: failed to process scheduling message in %s"
		   " (org=%s, att=%s)",
		   txn->req_tgt.mboxname, organizer, userid);
	    txn->error.desc = "Failed to lookup organizer address\r\n";
	    ret = HTTP_SERVER_ERROR;
	    goto done;
	}

	if (!strcmp(sparam.userid, userid)) {
	    /* Organizer scheduling object resource */
	    sched_request(organizer, &sparam, ical, NULL, 0);
	}
	else if (!(hdr = spool_getheader(txn->req_hdrs, "Schedule-Reply")) ||
		 strcmp(hdr[0], "F")) {
	    /* Attendee scheduling object resource */
	    sched_reply(userid, ical, NULL);
	}

      done:
	icalcomponent_free(ical);
    }

    return ret;
}

static const char *begin_icalendar(struct buf *buf)
{
    /* Begin iCalendar stream */
    buf_setcstr(buf, "BEGIN:VCALENDAR\r\n");
    buf_printf(buf, "PRODID:-//CyrusIMAP.org/Cyrus %s//EN\r\n",
	       cyrus_version());
    buf_appendcstr(buf, "VERSION:2.0\r\n");

    return "";
}

static void end_icalendar(struct buf *buf)
{
    /* End iCalendar stream */
    buf_setcstr(buf, "END:VCALENDAR\r\n");
}

static int dump_calendar(struct transaction_t *txn, struct meth_params *gparams)
{
    int ret = 0, r, precond;
    struct resp_body_t *resp_body = &txn->resp_body;
    struct buf *buf = &resp_body->payload;
    struct mailbox *mailbox = NULL;
    static char etag[33];
    uint32_t recno;
    struct index_record record;
    struct hash_table tzid_table;
    static const char *displayname_annot =
	ANNOT_NS "<" XML_NS_DAV ">displayname";
    struct annotation_data attrib;
    const char **hdr, *sep;
    struct mime_type_t *mime;

    /* Check requested MIME type:
       1st entry in caldav_mime_types array MUST be default MIME type */
    if ((hdr = spool_getheader(txn->req_hdrs, "Accept")))
	mime = get_accept_type(hdr, caldav_mime_types);
    else mime = caldav_mime_types;
    if (!mime) return HTTP_NOT_ACCEPTABLE;

    /* Open mailbox for reading */
    if ((r = http_mailbox_open(txn->req_tgt.mboxname, &mailbox, LOCK_SHARED))) {
	syslog(LOG_ERR, "http_mailbox_open(%s) failed: %s",
	       txn->req_tgt.mboxname, error_message(r));
	txn->error.desc = error_message(r);
	ret = HTTP_SERVER_ERROR;
	goto done;
    }

    /* Check any preconditions */
    sprintf(etag, "%u-%u-%u",
	    mailbox->i.uidvalidity, mailbox->i.last_uid, mailbox->i.exists);
    precond = gparams->check_precond(txn, NULL, etag, mailbox->index_mtime);

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
    memset(&attrib, 0, sizeof(struct annotation_data));
    r = annotatemore_lookup(mailbox->name, displayname_annot,
			    /* shared */ "", &attrib);
    if (r || !attrib.value) attrib.value = strrchr(mailbox->name, '.') + 1;

    buf_reset(&txn->buf);
    buf_printf(&txn->buf, "%s.%s", attrib.value, mime->file_ext);
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

    for (r = 0, recno = 1; recno <= mailbox->i.num_records; recno++) {
	const char *msg_base = NULL;
	unsigned long msg_size = 0;
	icalcomponent *ical;

	if (mailbox_read_index_record(mailbox, recno, &record)) continue;

	if (record.system_flags & (FLAG_EXPUNGED | FLAG_DELETED)) continue;

	/* Map and parse existing iCalendar resource */
	mailbox_map_message(mailbox, record.uid, &msg_base, &msg_size);
	ical = icalparser_parse_string(msg_base + record.header_size);
	mailbox_unmap_message(mailbox, record.uid, &msg_base, &msg_size);

	if (ical) {
	    icalcomponent *comp;

	    for (comp = icalcomponent_get_first_component(ical,
							  ICAL_ANY_COMPONENT);
		 comp;
		 comp = icalcomponent_get_next_component(ical,
							 ICAL_ANY_COMPONENT)) {
		char *cal_str;
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
		cal_str = mime->to_string(comp);
		write_body(0, txn, cal_str, strlen(cal_str));
		free(cal_str);
	    }

	    icalcomponent_free(ical);
	}
    }

    free_hash_table(&tzid_table, NULL);

    /* End (converted) iCalendar stream */
    mime->end_stream(buf);
    write_body(0, txn, buf_cstring(buf), buf_len(buf));

    /* End of output */
    write_body(0, txn, NULL, 0);

  done:
    if (mailbox) mailbox_unlock_index(mailbox, NULL);

    return ret;
}


/*
 * mboxlist_findall() callback function to list calendars
 */
static int list_cb(char *name,
		   int matchlen __attribute__((unused)),
		   int maycreate __attribute__((unused)),
		   void *rock)
{
    struct transaction_t *txn = (struct transaction_t *) rock;
    struct buf *body = &txn->resp_body.payload;
    struct buf *url = &txn->buf;
    static size_t inboxlen = 0;
    static size_t outboxlen = 0;
    char *acl, *shortname;
    size_t len;
    int r;
    static const char *displayname_annot =
	ANNOT_NS "<" XML_NS_DAV ">displayname";
    struct annotation_data displayname;

    if (!inboxlen) inboxlen = strlen(SCHED_INBOX) - 1;
    if (!outboxlen) outboxlen = strlen(SCHED_OUTBOX) - 1;

    shortname = strrchr(name, '.') + 1;
    len = strlen(shortname);

    /* Don't list scheduling Inbox/Outbox */
    if ((len == inboxlen && !strncmp(shortname, SCHED_INBOX, inboxlen)) ||
	(len == outboxlen && !strncmp(shortname, SCHED_OUTBOX, outboxlen)))
	return 0;

    /* Don't list deleted mailboxes */
    if (mboxname_isdeletedmailbox(name)) return 0;

    /* Lookup the mailbox and make sure its readable */
    http_mlookup(name, NULL, &acl, NULL);
    if (!acl || !(cyrus_acl_myrights(httpd_authstate, acl) & ACL_READ))
	return 0;

    /* Send a body chunk once in a while */
    if (buf_len(body) > PROT_BUFSIZE) {
	write_body(0, txn, buf_cstring(body), buf_len(body));
	buf_reset(body);
    }

    /* Lookup DAV:displayname */
    memset(&displayname, 0, sizeof(struct annotation_data));
    r = annotatemore_lookup(name, displayname_annot,
			    /* shared */ "", &displayname);
    if (r || !displayname.value) displayname.value = shortname;

    /* Add available calendar with link */
    len = buf_len(url);
    buf_printf_markup(body, 3, "<li><a href=\"%s%s\">%s</a></li>",
		      buf_cstring(url), shortname, displayname.value);
    buf_truncate(url, len);

    return 0;
}


/* Create a HTML document listing all calendars available to the user */
static int list_calendars(struct transaction_t *txn,
			  struct meth_params *gparams)
{
    int ret = 0, precond;
    time_t lastmod = compile_time;
    char mboxlist[MAX_MAILBOX_PATH+1];
    struct stat sbuf;
    static char etag[63];
    unsigned level = 0;
    struct buf *body = &txn->resp_body.payload;
    const char *host = NULL;

    /* stat() mailboxes.db for Last-Modified and ETag */
    snprintf(mboxlist, MAX_MAILBOX_PATH, "%s%s", config_dir, FNAME_MBOXLIST);
    stat(mboxlist, &sbuf);
    lastmod = MAX(compile_time, sbuf.st_mtime);
    sprintf(etag, "%ld-%ld-%ld", compile_time, sbuf.st_mtime, sbuf.st_size);

    /* Check any preconditions */
    precond = gparams->check_precond(txn, NULL, etag, lastmod);

    switch (precond) {
    case HTTP_OK:
    case HTTP_NOT_MODIFIED:
	/* Fill in ETag, Last-Modified, and Expires */
	txn->resp_body.etag = etag;
	txn->resp_body.lastmod = lastmod;
	txn->resp_body.maxage = 86400;  /* 24 hrs */
	txn->flags.cc |= CC_MAXAGE;

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
    buf_printf_markup(body, --level, "</head>");
    buf_printf_markup(body, level++, "<body>");
    buf_printf_markup(body, level, "<h2>%s</h2>", "Available Calendars");
    buf_printf_markup(body, level++, "<ul>");
    write_body(HTTP_OK, txn, buf_cstring(body), buf_len(body));
    buf_reset(body);

    /* Create base URL for calendars */
    http_proto_host(txn->req_hdrs, NULL, &host);
    assert(!buf_len(&txn->buf));
    buf_printf(&txn->buf, "webcal://%s%s", host, txn->req_tgt.path);

    /* Generate list of calendars */
    strlcat(txn->req_tgt.mboxname, ".%", sizeof(txn->req_tgt.mboxname));

    mboxlist_findall(NULL, txn->req_tgt.mboxname, 1, httpd_userid,
		     httpd_authstate, list_cb, txn);

    if (buf_len(body)) write_body(0, txn, buf_cstring(body), buf_len(body));

    /* Finish HTML */
    buf_reset(body);
    buf_printf_markup(body, --level, "</ul>");
    buf_printf_markup(body, --level, "</body>");
    buf_printf_markup(body, --level, "</html>");
    write_body(0, txn, buf_cstring(body), buf_len(body));

    /* End of output */
    write_body(0, txn, NULL, 0);

  done:
    return ret;
}


/* Perform a GET/HEAD request on a CalDAV resource */
static int meth_get(struct transaction_t *txn, void *params)
{
    struct meth_params *gparams = (struct meth_params *) params;
    int r, rights;
    char *server, *acl;

    /* Parse the path */
    if ((r = gparams->parse_path(txn->req_uri->path,
				 &txn->req_tgt, &txn->error.desc))) return r;

    /* GET an individual resource */
    if (txn->req_tgt.resource) return meth_get_dav(txn, gparams);

    /* Locate the mailbox */
    if ((r = http_mlookup(txn->req_tgt.mboxname, &server, &acl, NULL))) {
	syslog(LOG_ERR, "mlookup(%s) failed: %s",
	       txn->req_tgt.mboxname, error_message(r));
	txn->error.desc = error_message(r);

	switch (r) {
	case IMAP_PERMISSION_DENIED: return HTTP_FORBIDDEN;
	case IMAP_MAILBOX_NONEXISTENT: return HTTP_NOT_FOUND;
	default: return HTTP_SERVER_ERROR;
	}
    }

    /* Check ACL for current user */
    rights = acl ? cyrus_acl_myrights(httpd_authstate, acl) : 0;
    if ((rights & DACL_READ) != DACL_READ) {
	/* DAV:need-privileges */
	txn->error.precond = DAV_NEED_PRIVS;
	txn->error.resource = txn->req_tgt.path;
	txn->error.rights = DACL_READ;
	return HTTP_FORBIDDEN;
    }

    if (server) {
	/* Remote mailbox */
	struct backend *be;

	be = proxy_findserver(server, &http_protocol, proxy_userid,
			      &backend_cached, NULL, NULL, httpd_in);
	if (!be) return HTTP_UNAVAILABLE;

	return http_pipe_req_resp(be, txn);
    }

    /* Local Mailbox */

    /* Get an entire calendar collection */ 
    if (txn->req_tgt.collection) return dump_calendar(txn, gparams);

    /* GET a list of calendars under calendar-home-set */
    else return list_calendars(txn, gparams);
}


/* Perform a busy time request, if necessary */
static int caldav_post(struct transaction_t *txn)
{
    int ret = 0, r, rights;
    char *acl, orgid[MAX_MAILBOX_NAME+1] = "";
    const char **hdr;
    struct mime_type_t *mime = NULL;
    icalcomponent *ical = NULL, *comp;
    icalcomponent_kind kind = 0;
    icalproperty_method meth = 0;
    icalproperty *prop = NULL;
    const char *uid = NULL, *organizer = NULL;
    struct sched_param sparam;

    if (!(namespace_calendar.allow & ALLOW_CAL_SCHED) || !txn->req_tgt.flags) {
	/* POST to regular calendar collection */
	return HTTP_CONTINUE;
    }
    else if (txn->req_tgt.flags == TGT_SCHED_INBOX) {
	/* Don't allow POST to schedule-inbox */
	return HTTP_NOT_ALLOWED;
    }

    /* POST to schedule-outbox */

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

    /* Locate the mailbox */
    if ((r = http_mlookup(txn->req_tgt.mboxname, NULL, &acl, NULL))) {
	syslog(LOG_ERR, "mlookup(%s) failed: %s",
	       txn->req_tgt.mboxname, error_message(r));
	txn->error.desc = error_message(r);

	switch (r) {
	case IMAP_PERMISSION_DENIED: return HTTP_FORBIDDEN;
	case IMAP_MAILBOX_NONEXISTENT: return HTTP_NOT_FOUND;
	default: return HTTP_SERVER_ERROR;
	}
    }

    /* Get rights for current user */
    rights = acl ? cyrus_acl_myrights(httpd_authstate, acl) : 0;

    /* Read body */
    txn->req_body.flags |= BODY_DECODE;
    r = read_body(httpd_in, txn->req_hdrs, &txn->req_body, &txn->error.desc);
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
    ical = mime->from_string(buf_cstring(&txn->req_body.payload));
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
    if (organizer) {
	if (!caladdress_lookup(organizer, &sparam) &&
	    !(sparam.flags & SCHEDTYPE_REMOTE)) {
	    strlcpy(orgid, sparam.userid, sizeof(orgid));
	    mboxname_hiersep_toexternal(&httpd_namespace, orgid, 0);
	}
    }

    if (strncmp(orgid, txn->req_tgt.user, txn->req_tgt.userlen)) {
	txn->error.precond = CALDAV_VALID_ORGANIZER;
	ret = HTTP_FORBIDDEN;
	goto done;
    }

    switch (kind) {
    case ICAL_VFREEBUSY_COMPONENT:
	if (meth == ICAL_METHOD_REQUEST)
	    if (!(rights & DACL_SCHEDFB)) {
		/* DAV:need-privileges */
		txn->error.precond = DAV_NEED_PRIVS;
		txn->error.resource = txn->req_tgt.path;
		txn->error.rights = DACL_SCHEDFB;
		ret = HTTP_FORBIDDEN;
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


static const char *get_icalrestriction_errstr(icalcomponent *ical)
{
    icalcomponent *comp;

    for (comp = icalcomponent_get_first_component(ical, ICAL_ANY_COMPONENT);
	 comp;
	 comp = icalcomponent_get_next_component(ical, ICAL_ANY_COMPONENT)) {
	icalproperty *prop =
	    icalcomponent_get_first_property(comp, ICAL_XLICERROR_PROPERTY);
	if (prop) return icalproperty_get_xlicerror(prop);
    }

    return NULL;
}


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
static int caldav_put(struct transaction_t *txn,
		      struct mime_type_t *mime,
		      struct mailbox *mailbox, unsigned flags)
{
    int ret;
    icalcomponent *ical = NULL, *comp, *nextcomp;
    icalcomponent_kind kind;
    icalproperty *prop;
    const char *uid, *organizer = NULL;

    /* Parse and validate the iCal data */
    ical = mime->from_string(buf_cstring(&txn->req_body.payload));
    if (!ical || (icalcomponent_isa(ical) != ICAL_VCALENDAR_COMPONENT)) {
	txn->error.precond = CALDAV_VALID_DATA;
	ret = HTTP_FORBIDDEN;
	goto done;
    }
    else if (!icalrestriction_check(ical)) {
	txn->error.precond = CALDAV_VALID_OBJECT;
	if ((txn->error.desc = get_icalrestriction_errstr(ical))) {
	    assert(!buf_len(&txn->buf));
	    buf_setcstr(&txn->buf, txn->error.desc);
	    txn->error.desc = buf_cstring(&txn->buf);
	}
	ret = HTTP_FORBIDDEN;
	goto done;
    }

    /* Make sure iCal UIDs [and ORGANIZERs] in all components are the same */
    comp = icalcomponent_get_first_real_component(ical);
    kind = icalcomponent_isa(comp);
    uid = icalcomponent_get_uid(comp);
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

	if (organizer) {
	    const char *nextorg = NULL;

	    prop = icalcomponent_get_first_property(nextcomp,
						    ICAL_ORGANIZER_PROPERTY);
	    if (prop) nextorg = icalproperty_get_organizer(prop);
	    if (!nextorg || strcmp(organizer, nextorg)) {
		txn->error.precond = CALDAV_SAME_ORGANIZER;
		ret = HTTP_FORBIDDEN;
		goto done;
	    }
	}
    }

    if ((namespace_calendar.allow & ALLOW_CAL_SCHED) && organizer) {
	/* Scheduling object resource */
	const char *userid;
	struct caldav_data *cdata;
	struct sched_param sparam;
	icalcomponent *oldical = NULL;

	/* Construct userid corresponding to mailbox */
	userid = mboxname_to_userid(txn->req_tgt.mboxname);

	/* Make sure iCal UID is unique for this user */
	caldav_lookup_uid(auth_caldavdb, uid, 0, &cdata);
	/* XXX  Check errors */

	if (cdata->dav.mailbox &&
	    (strcmp(cdata->dav.mailbox, txn->req_tgt.mboxname) ||
	     strcmp(cdata->dav.resource, txn->req_tgt.resource))) {
	    /* CALDAV:unique-scheduling-object-resource */
	    char ext_userid[MAX_MAILBOX_NAME+1];

	    strlcpy(ext_userid, userid, sizeof(ext_userid));
	    mboxname_hiersep_toexternal(&httpd_namespace, ext_userid, 0);

	    txn->error.precond = CALDAV_UNIQUE_OBJECT;
	    assert(!buf_len(&txn->buf));
	    buf_printf(&txn->buf, "%s/user/%s/%s/%s",
		       namespace_calendar.prefix,
		       ext_userid, strrchr(cdata->dav.mailbox, '.')+1,
		       cdata->dav.resource);
	    txn->error.resource = buf_cstring(&txn->buf);
	    ret = HTTP_FORBIDDEN;
	    goto done;
	}

	/* Lookup the organizer */
	if (caladdress_lookup(organizer, &sparam)) {
	    syslog(LOG_ERR,
		   "meth_delete: failed to process scheduling message in %s"
		   " (org=%s, att=%s)",
		   txn->req_tgt.mboxname, organizer, userid);
	    txn->error.desc = "Failed to lookup organizer address\r\n";
	    ret = HTTP_SERVER_ERROR;
	    goto done;
	}

	if (cdata->dav.imap_uid) {
	    /* Update existing object */
	    struct index_record record;
	    const char *msg_base = NULL;
	    unsigned long msg_size = 0;

	    /* Load message containing the resource and parse iCal data */
	    mailbox_find_index_record(mailbox, cdata->dav.imap_uid, &record);
	    mailbox_map_message(mailbox, record.uid, &msg_base, &msg_size);
	    oldical = icalparser_parse_string(msg_base + record.header_size);
	    mailbox_unmap_message(mailbox, record.uid, &msg_base, &msg_size);
	}

	if (!strcmp(sparam.userid, userid)) {
	    /* Organizer scheduling object resource */
	    sched_request(organizer, &sparam, oldical, ical, 0);
	}
	else {
	    /* Attendee scheduling object resource */
	    sched_reply(userid, oldical, ical);
	}

	if (oldical) icalcomponent_free(oldical);

	flags |= NEW_STAG;
    }

    /* Store resource at target */
    ret = store_resource(txn, ical, mailbox, txn->req_tgt.resource,
			 auth_caldavdb, OVERWRITE_CHECK, flags);

    if (flags & PREFER_REP) {
	struct resp_body_t *resp_body = &txn->resp_body;
	const char **hdr;
	char *data;

	if ((hdr = spool_getheader(txn->req_hdrs, "Accept")))
	    mime = get_accept_type(hdr, caldav_mime_types);
	if (!mime) goto done;

	switch (ret) {
	case HTTP_NO_CONTENT:
	    ret = HTTP_OK;

	case HTTP_CREATED:
	    /* Convert into requested MIME type */
	    data = mime->to_string(ical);

	    /* Fill in Content-Type, Content-Length */
	    resp_body->type = mime->content_type;
	    resp_body->len = strlen(data);

	    /* Fill in Content-Location */
	    resp_body->loc = txn->req_tgt.path;

	    /* Fill in Expires and Cache-Control */
	    resp_body->maxage = 3600;	/* 1 hr */
	    txn->flags.cc = CC_MAXAGE
		| CC_REVALIDATE		/* don't use stale data */
		| CC_NOTRANSFORM;	/* don't alter iCal data */

	    /* Output current representation */
	    write_body(ret, txn, data, resp_body->len);

	    free(data);
	    ret = 0;
	    break;

	default:
	    /* failure - do nothing */
	    break;
	}
    }

  done:
    if (ical) icalcomponent_free(ical);

    return ret;
}


/* Append a new busytime period to the busytime array */
static void add_busytime(icalcomponent *comp, struct icaltime_span *span,
			 void *rock)
{
    struct busytime *busytime = (struct busytime *) rock;
    int is_date = icaltime_is_date(icalcomponent_get_dtstart(comp));
    icaltimezone *utc = icaltimezone_get_utc_timezone();
    struct icalperiodtype *newp;

    /* Grow the array, if necessary */
    if (busytime->len == busytime->alloc) {
	busytime->alloc += 100;  /* XXX  arbitrary */
	busytime->busy = xrealloc(busytime->busy,
				  busytime->alloc *
				  sizeof(struct icalperiodtype));
    }

    /* Add new busytime */
    newp = &busytime->busy[busytime->len++];
    newp->start = icaltime_from_timet_with_zone(span->start, is_date, utc);
    newp->end = icaltime_from_timet_with_zone(span->end, is_date, utc);
    newp->duration = icaldurationtype_null_duration();
}


/* See if the current resource matches the specified filter
 * (comp-type and/or time-range).  Returns 1 if match, 0 otherwise.
 */
static int apply_calfilter(struct propfind_ctx *fctx, void *data)
{
    struct calquery_filter *calfilter =
	(struct calquery_filter *) fctx->filter_crit;
    struct caldav_data *cdata = (struct caldav_data *) data;
    int match = 1;

    if (calfilter->comp) {
	/* Perform CALDAV:comp-filter filtering */
	if (!(cdata->comp_type & calfilter->comp)) return 0;
    }

    if (!icaltime_is_null_time(calfilter->start)) {
	/* Perform CALDAV:time-range filtering */
	struct icaltimetype dtstart = icaltime_from_string(cdata->dtstart);
	struct icaltimetype dtend = icaltime_from_string(cdata->dtend);

	if (icaltime_compare(dtend, calfilter->start) <= 0) {
	    /* Component is earlier than range */
	    return 0;
	}
	else if (icaltime_compare(dtstart, calfilter->end) >= 0) {
	    /* Component is later than range */
	    return 0;
	}
	else if (!cdata->recurring && !calfilter->save_busytime) {
	    /* Component is within range, non-recurring,
	       and we don't need to save busytime */
	    return 1;
	}
	else {
	    /* Component is within range and recurring.
	     * Need to mmap() and parse iCalendar object
	     * to perform complete check of each recurrence.
	     */
	    struct busytime *busytime = &calfilter->busytime;
	    icalcomponent *ical, *comp;
	    icalcomponent_kind kind;
	    icaltimezone *utc = icaltimezone_get_utc_timezone();
	    icaltime_span rangespan;
	    unsigned firstr, lastr;

	    mailbox_map_message(fctx->mailbox, fctx->record->uid,
				&fctx->msg_base, &fctx->msg_size);

	    ical = icalparser_parse_string(fctx->msg_base +
					   fctx->record->header_size);

	    comp = icalcomponent_get_first_real_component(ical);
	    kind = icalcomponent_isa(comp);

	    /* XXX  This code assumes that the first VEVENT will contain
	     * the recurrence rule and the subsequent VEVENTs will
	     * be the overrides.  Technically this doesn't have to be
	     * the case, but it appears to be true in practice.
	     */

	    /* Create a span for the given time-range */
	    rangespan.start =
		icaltime_as_timet_with_zone(calfilter->start, utc);
	    rangespan.end =
		icaltime_as_timet_with_zone(calfilter->end, utc);

	    /* Mark start of where recurrences will be added */
	    firstr = busytime->len;

	    /* Add all recurring busytime in specified time-range */
	    icalcomponent_foreach_recurrence(comp,
					     calfilter->start, calfilter->end,
					     add_busytime, busytime);

	    /* Mark end of where recurrences were added */
	    lastr = busytime->len;

	    /* XXX  Should we sort busytime array, so we can use bsearch()? */

	    /* Handle overridden recurrences */
	    while ((comp = icalcomponent_get_next_component(ical, kind))) {
		icalproperty *prop;
		struct icaltimetype recurid;
		icalparameter *param;
		icaltime_span recurspan;
		unsigned n;

		/* The *_get_recurrenceid() functions don't appear
		   to deal with timezones properly, so we do it ourselves */
		prop =
		    icalcomponent_get_first_property(comp,
						     ICAL_RECURRENCEID_PROPERTY);
		recurid = icalproperty_get_recurrenceid(prop);
		param =
		    icalproperty_get_first_parameter(prop, ICAL_TZID_PARAMETER);

		if (param) {
		    const char *tzid = icalparameter_get_tzid(param);
		    icaltimezone *tz = NULL;

		    tz = icalcomponent_get_timezone(ical, tzid);
		    if (!tz) {
			tz = icaltimezone_get_builtin_timezone_from_tzid(tzid);
		    }
		    if (tz) icaltime_set_timezone(&recurid, tz);
		}

		recurid =
		    icaltime_convert_to_zone(recurid,
					     icaltimezone_get_utc_timezone());

		/* Check if this overridden instance is in our array */
		/* XXX  Should we replace this linear search with bsearch() */
		for (n = firstr; n < lastr; n++) {
		    if (!icaltime_compare(recurid,
					  busytime->busy[n].start)) {
			/* Remove the instance
			   by sliding all future instances into its place */
			/* XXX  Doesn't handle the RANGE=THISANDFUTURE param */
			busytime->len--;
			memmove(&busytime->busy[n], &busytime->busy[n+1],
				sizeof(struct icalperiodtype) *
				(busytime->len - n));
			lastr--;

			break;
		    }
		}

		/* Check if the new instance is in our time-range */
		recurspan = icaltime_span_new(icalcomponent_get_dtstart(comp),
					      icalcomponent_get_dtend(comp), 1);

		if (icaltime_span_overlaps(&recurspan, &rangespan)) {
		    /* Add this instance to the array */
		    add_busytime(comp, &recurspan, busytime);
		}
	    }

	    if (lastr == firstr) match = 0;

	    if (!calfilter->save_busytime) busytime->len = 0;

	    icalcomponent_free(ical);
	}
    }

    return match;
}


static int is_valid_timerange(const struct icaltimetype start,
			      const struct icaltimetype end)
{
    return (icaltime_is_valid_time(start) && icaltime_is_valid_time(end) &&
	    !icaltime_is_date(start) && !icaltime_is_date(end) &&
	    (icaltime_is_utc(start) || start.zone) &&
	    (icaltime_is_utc(end) || end.zone));
}


static int parse_comp_filter(xmlNodePtr root, struct calquery_filter *filter,
			     struct error_t *error)
{
    int ret = 0;
    xmlNodePtr node;

    /* Parse elements of filter */
    for (node = root; node; node = node->next) {
	if (node->type == XML_ELEMENT_NODE) {
	    if (!xmlStrcmp(node->name, BAD_CAST "comp-filter")) {
		xmlChar *name = xmlGetProp(node, BAD_CAST "name");

		if (!filter->comp) {
		    if (!xmlStrcmp(name, BAD_CAST "VCALENDAR"))
			filter->comp = CAL_COMP_VCALENDAR;
		    else {
			error->precond = CALDAV_VALID_FILTER;
			ret = HTTP_FORBIDDEN;
		    }
		}
		else if (filter->comp == CAL_COMP_VCALENDAR) {
		    if (!xmlStrcmp(name, BAD_CAST "VCALENDAR") ||
			!xmlStrcmp(name, BAD_CAST "VALARM")) {
			error->precond = CALDAV_VALID_FILTER;
			ret = HTTP_FORBIDDEN;
		    }
		    else if (!xmlStrcmp(name, BAD_CAST "VEVENT"))
			filter->comp |= CAL_COMP_VEVENT;
		    else if (!xmlStrcmp(name, BAD_CAST "VTODO"))
			filter->comp |= CAL_COMP_VTODO;
		    else if (!xmlStrcmp(name, BAD_CAST "VJOURNAL"))
			filter->comp |= CAL_COMP_VJOURNAL;
		    else if (!xmlStrcmp(name, BAD_CAST "VFREEBUSY"))
			filter->comp |= CAL_COMP_VFREEBUSY;
		    else if (!xmlStrcmp(name, BAD_CAST "VTIMEZONE"))
			filter->comp |= CAL_COMP_VTIMEZONE;
		    else {
			error->precond = CALDAV_SUPP_FILTER;
			ret = HTTP_FORBIDDEN;
		    }
		}
		else if (filter->comp & (CAL_COMP_VEVENT | CAL_COMP_VTODO)) {
		    if (!xmlStrcmp(name, BAD_CAST "VALARM"))
			filter->comp |= CAL_COMP_VALARM;
		    else {
			error->precond = CALDAV_VALID_FILTER;
			ret = HTTP_FORBIDDEN;
		    }
		}
		else {
		    error->precond = CALDAV_SUPP_FILTER;
		    ret = HTTP_FORBIDDEN;
		}

		xmlFree(name);

		if (!ret)
		    ret = parse_comp_filter(node->children, filter, error);
		if (ret) return ret;
	    }
	    else if (!xmlStrcmp(node->name, BAD_CAST "time-range")) {
		icaltimezone *utc = icaltimezone_get_utc_timezone();
		xmlChar *start, *end;

		if (!(filter->comp & (CAL_COMP_VEVENT | CAL_COMP_VTODO))) {
		    error->precond = CALDAV_VALID_FILTER;
		    return HTTP_FORBIDDEN;
		}

		start = xmlGetProp(node, BAD_CAST "start");
		if (start) {
		    filter->start = icaltime_from_string((char *) start);
		    xmlFree(start);
		}
		else {
		    filter->start =
			icaltime_from_timet_with_zone(INT_MIN, 0, utc);
		}

		end = xmlGetProp(node, BAD_CAST "end");
		if (end) {
		    filter->end = icaltime_from_string((char *) end);
		    xmlFree(end);
		}
		else {
		    filter->end =
			icaltime_from_timet_with_zone(INT_MAX, 0, utc);
		}

		if (!is_valid_timerange(filter->start, filter->end)) {
		    error->precond = CALDAV_VALID_FILTER;
		    return HTTP_FORBIDDEN;
		}
	    }
	    else {
		error->precond = CALDAV_SUPP_FILTER;
		return HTTP_FORBIDDEN;
	    }
	}
    }

    return ret;
}


/* Callback to fetch DAV:getcontenttype */
static int propfind_getcontenttype(const xmlChar *name, xmlNsPtr ns,
				   struct propfind_ctx *fctx,
				   xmlNodePtr resp __attribute__((unused)),
				   struct propstat propstat[],
				   void *rock __attribute__((unused)))
{
    buf_setcstr(&fctx->buf, "text/calendar; charset=utf-8");

    if (fctx->data) {
	struct caldav_data *cdata = (struct caldav_data *) fctx->data;
	const char *comp = NULL;

	switch (cdata->comp_type) {
	case CAL_COMP_VEVENT: comp = "VEVENT"; break;
	case CAL_COMP_VTODO: comp = "VTODO"; break;
	case CAL_COMP_VJOURNAL: comp = "VJOURNAL"; break;
	case CAL_COMP_VFREEBUSY: comp = "VFREEBUSY"; break;
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
			    xmlNodePtr resp,
			    struct propstat propstat[],
			    void *rock __attribute__((unused)))
{
    xmlNodePtr node = xml_add_prop(HTTP_OK, fctx->ns[NS_DAV],
				   &propstat[PROPSTAT_OK], name, ns, NULL, 0);

    if (!fctx->record) {
	xmlNewChild(node, NULL, BAD_CAST "collection", NULL);

	if (fctx->req_tgt->collection) {
	    ensure_ns(fctx->ns, NS_CALDAV, resp->parent, XML_NS_CALDAV, "C");
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
	    }
	}
    }

    return 0;
}


/* Callback to fetch DAV:supported-report-set */
static int propfind_reportset(const xmlChar *name, xmlNsPtr ns,
			      struct propfind_ctx *fctx,
			      xmlNodePtr resp,
			      struct propstat propstat[],
			      void *rock __attribute__((unused)))
{
    xmlNodePtr s, r, top;

    top = xml_add_prop(HTTP_OK, fctx->ns[NS_DAV], &propstat[PROPSTAT_OK],
		       name, ns, NULL, 0);

    if (fctx->req_tgt->collection && !fctx->req_tgt->resource) {
	s = xmlNewChild(top, NULL, BAD_CAST "supported-report", NULL);
	r = xmlNewChild(s, NULL, BAD_CAST "report", NULL);
	xmlNewChild(r, fctx->ns[NS_DAV], BAD_CAST "sync-collection", NULL);
    }

    ensure_ns(fctx->ns, NS_CALDAV, resp->parent, XML_NS_CALDAV, "C");

    s = xmlNewChild(top, NULL, BAD_CAST "supported-report", NULL);
    r = xmlNewChild(s, NULL, BAD_CAST "report", NULL);
    xmlNewChild(r, fctx->ns[NS_CALDAV], BAD_CAST "calendar-query", NULL);

    s = xmlNewChild(top, NULL, BAD_CAST "supported-report", NULL);
    r = xmlNewChild(s, NULL, BAD_CAST "report", NULL);
    xmlNewChild(r, fctx->ns[NS_CALDAV], BAD_CAST "calendar-multiget", NULL);

    s = xmlNewChild(top, NULL, BAD_CAST "supported-report", NULL);
    r = xmlNewChild(s, NULL, BAD_CAST "report", NULL);
    xmlNewChild(r, fctx->ns[NS_CALDAV], BAD_CAST "free-busy-query", NULL);

    return 0;
}


/* Callback to prescreen/fetch CALDAV:calendar-data */
static int propfind_caldata(const xmlChar *name, xmlNsPtr ns,
			    struct propfind_ctx *fctx,
			    xmlNodePtr resp __attribute__((unused)),
			    struct propstat propstat[],
			    void *rock)
{
    xmlNodePtr prop = (xmlNodePtr) rock;
    const char *data = NULL;
    unsigned long datalen = 0;

    if (propstat) {
	if (!fctx->record) return HTTP_NOT_FOUND;

	if (!fctx->msg_base) {
	    mailbox_map_message(fctx->mailbox, fctx->record->uid,
				&fctx->msg_base, &fctx->msg_size);
	}
	if (!fctx->msg_base) return HTTP_SERVER_ERROR;

	data = fctx->msg_base + fctx->record->header_size;
	datalen = fctx->record->size - fctx->record->header_size;
    }

    return propfind_getdata(name, ns, fctx, propstat, prop, caldav_mime_types,
			    CALDAV_SUPP_DATA, data, datalen);
}


/* Callback to fetch CALDAV:calendar-home-set,
 * CALDAV:schedule-inbox-URL, CALDAV:schedule-outbox-URL,
 * and CALDAV:schedule-default-calendar-URL
 */
int propfind_calurl(const xmlChar *name, xmlNsPtr ns,
		    struct propfind_ctx *fctx,
		    xmlNodePtr resp __attribute__((unused)),
		    struct propstat propstat[],
		    void *rock)
{
    xmlNodePtr node;
    const char *cal = (const char *) rock;

    if (!fctx->userid) return HTTP_NOT_FOUND;

    /* sched-def-cal-URL only defined on sched-inbox-URL */
    if (!xmlStrcmp(name, BAD_CAST "schedule-default-calendar-URL") &&
	(!fctx->req_tgt->collection ||
	 strcmp(fctx->req_tgt->collection, SCHED_INBOX)))
	return HTTP_NOT_FOUND;

    node = xml_add_prop(HTTP_OK, fctx->ns[NS_DAV], &propstat[PROPSTAT_OK],
			name, ns, NULL, 0);

    buf_reset(&fctx->buf);
    buf_printf(&fctx->buf, "%s/user/%s/%s",
	       namespace_calendar.prefix, fctx->userid, cal ? cal : "");

    xml_add_href(node, fctx->ns[NS_DAV], buf_cstring(&fctx->buf));

    return 0;
}


/* Callback to fetch CALDAV:supported-calendar-component-set */
static const struct cal_comp_t {
    const char *name;
    unsigned long type;
} cal_comps[] = {
    { "VEVENT",    CAL_COMP_VEVENT },
    { "VTODO",     CAL_COMP_VTODO },
    { "VJOURNAL",  CAL_COMP_VJOURNAL },
    { "VFREEBUSY", CAL_COMP_VFREEBUSY },
//    { "VTIMEZONE", CAL_COMP_VTIMEZONE },
//    { "VALARM",	   CAL_COMP_VALARM },
    { NULL, 0 }
};

static int propfind_calcompset(const xmlChar *name, xmlNsPtr ns,
			       struct propfind_ctx *fctx,
			       xmlNodePtr resp __attribute__((unused)),
			       struct propstat propstat[],
			       void *rock __attribute__((unused)))
{
    const char *prop_annot = ANNOT_NS "CALDAV:supported-calendar-component-set";
    struct annotation_data attrib;
    unsigned long types = 0;
    xmlNodePtr set, node;
    const struct cal_comp_t *comp;
    int r = 0;

    if (!fctx->req_tgt->collection) return HTTP_NOT_FOUND;

    if (!(r = annotatemore_lookup(fctx->mailbox->name, prop_annot,
				  /* shared */ "", &attrib))) {
	if (attrib.value)
	    types = strtoul(attrib.value, NULL, 10);
	else
	    types = -1;  /* ALL components types */
    }

    if (r) return HTTP_SERVER_ERROR;
    if (!types) return HTTP_NOT_FOUND;

    set = xml_add_prop(HTTP_OK, fctx->ns[NS_DAV], &propstat[PROPSTAT_OK],
		       name, ns, NULL, 0);
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
    int r = 0;
    unsigned precond = 0;

    if (set && (pctx->meth == METH_MKCOL || pctx->meth == METH_MKCALENDAR)) {
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
	    else break;	    	     		   /* no match - invalid type */
	}

	if (!cur) {
	    /* All component types are valid */
	    const char *prop_annot =
		ANNOT_NS "CALDAV:supported-calendar-component-set";

	    buf_reset(&pctx->buf);
	    buf_printf(&pctx->buf, "%lu", types);
	    if (!(r = annotatemore_write_entry(pctx->mailboxname,
					       prop_annot, /* shared */ "",
					       buf_cstring(&pctx->buf), NULL,
					       buf_len(&pctx->buf), 0,
					       &pctx->tid))) {
		xml_add_prop(HTTP_OK, pctx->ns[NS_DAV], &propstat[PROPSTAT_OK],
			     prop->name, prop->ns, NULL, 0);
	    }
	    else {
		xml_add_prop(HTTP_SERVER_ERROR, pctx->ns[NS_DAV],
			     &propstat[PROPSTAT_ERROR],
			     prop->name, prop->ns, NULL, 0);
	    }

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
				xmlNodePtr resp __attribute__((unused)),
				struct propstat propstat[],
				void *rock __attribute__((unused)))
{
    xmlNodePtr node;
    struct mime_type_t *mime;

    if (!fctx->req_tgt->collection) return HTTP_NOT_FOUND;

    node = xml_add_prop(HTTP_OK, fctx->ns[NS_DAV], &propstat[PROPSTAT_OK],
			name, ns, NULL, 0);

    assert(!buf_len(&fctx->buf));

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

    buf_reset(&fctx->buf);

    return 0;
}


/* Callback to fetch CALDAV:schedule-tag */
static int propfind_schedtag(const xmlChar *name, xmlNsPtr ns,
			     struct propfind_ctx *fctx,
			     xmlNodePtr resp __attribute__((unused)),
			     struct propstat propstat[],
			     void *rock __attribute__((unused)))
{
    struct caldav_data *cdata = (struct caldav_data *) fctx->data;

    if (!cdata->sched_tag) return HTTP_NOT_FOUND;

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
			 xmlNodePtr resp __attribute__((unused)),
			 struct propstat propstat[],
			 void *rock __attribute__((unused)))
{
    xmlNodePtr node;

    if (!fctx->userid) return HTTP_NOT_FOUND;

    node = xml_add_prop(HTTP_OK, fctx->ns[NS_DAV], &propstat[PROPSTAT_OK],
			name, ns, NULL, 0);

    /* XXX  This needs to be done via an LDAP/DB lookup */
    buf_reset(&fctx->buf);
    buf_printf(&fctx->buf, "mailto:%s@%s", fctx->userid, config_servername);

    xmlNewChild(node, fctx->ns[NS_DAV], BAD_CAST "href",
		BAD_CAST buf_cstring(&fctx->buf));

    return 0;
}


/* Callback to fetch CALDAV:schedule-calendar-transp */
static int propfind_caltransp(const xmlChar *name, xmlNsPtr ns,
			      struct propfind_ctx *fctx,
			      xmlNodePtr resp __attribute__((unused)),
			      struct propstat propstat[],
			      void *rock __attribute__((unused)))
{
    const char *prop_annot = ANNOT_NS "CALDAV:schedule-calendar-transp";
    struct annotation_data attrib;
    const char *value = NULL;
    xmlNodePtr node;
    int r = 0;

    if (!fctx->req_tgt->collection) return HTTP_NOT_FOUND;

    if (!(r = annotatemore_lookup(fctx->mailbox->name, prop_annot,
				  /* shared */ "", &attrib)) && attrib.value) {
	value = attrib.value;
    }

    if (r) return HTTP_SERVER_ERROR;
    if (!value) return HTTP_NOT_FOUND;

    node = xml_add_prop(HTTP_OK, fctx->ns[NS_DAV], &propstat[PROPSTAT_OK],
			name, ns, NULL, 0);
    xmlNewChild(node, fctx->ns[NS_CALDAV], BAD_CAST value, NULL);

    return 0;
}


/* Callback to write schedule-calendar-transp property */
static int proppatch_caltransp(xmlNodePtr prop, unsigned set,
			       struct proppatch_ctx *pctx,
			       struct propstat propstat[],
			       void *rock __attribute__((unused)))
{
    if (pctx->req_tgt->collection && !pctx->req_tgt->resource) {
	const char *prop_annot =
	    ANNOT_NS "CALDAV:schedule-calendar-transp";
	const char *transp = "";

	if (set) {
	    xmlNodePtr cur;

	    /* Find the value */
	    for (cur = prop->children; cur; cur = cur->next) {

		/* Make sure its a value we understand */
		if (cur->type != XML_ELEMENT_NODE) continue;
		if (!xmlStrcmp(cur->name, BAD_CAST "opaque") ||
		    !xmlStrcmp(cur->name, BAD_CAST "transparent")) {
		    transp = (const char *) cur->name;
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

	if (!annotatemore_write_entry(pctx->mailboxname,
				      prop_annot, /* shared */ "",
				      transp, NULL,
				      strlen(transp), 0,
				      &pctx->tid)) {
	    xml_add_prop(HTTP_OK, pctx->ns[NS_DAV],
			 &propstat[PROPSTAT_OK], prop->name, prop->ns, NULL, 0);
	}
	else {
	    xml_add_prop(HTTP_SERVER_ERROR, pctx->ns[NS_DAV],
			 &propstat[PROPSTAT_ERROR],
			 prop->name, prop->ns, NULL, 0);
	}
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
			     xmlNodePtr resp __attribute__((unused)),
			     struct propstat propstat[],
			     void *rock)
{
    xmlNodePtr prop = (xmlNodePtr) rock;
    const char *data = NULL;
    unsigned long datalen = 0;

    if (propstat) {
	struct annotation_data attrib;
	int r = 0;

	buf_reset(&fctx->buf);
	buf_printf(&fctx->buf, ANNOT_NS "<%s>%s",
		   (const char *) ns->href, name);

	memset(&attrib, 0, sizeof(struct annotation_data));

	if (fctx->mailbox && !fctx->record) {
	    r = annotatemore_lookup(fctx->mailbox->name,
				    buf_cstring(&fctx->buf),
				    /* shared */ "", &attrib);
	}

	if (r) return HTTP_SERVER_ERROR;
	if (!attrib.value) return HTTP_NOT_FOUND;

	data = attrib.value;
	datalen = attrib.size;
    }

    return propfind_getdata(name, ns, fctx, propstat, prop, caldav_mime_types,
			    CALDAV_SUPP_DATA, data, datalen);
}


/* Callback to write calendar-timezone property */
static int proppatch_timezone(xmlNodePtr prop, unsigned set,
			      struct proppatch_ctx *pctx,
			      struct propstat propstat[],
			      void *rock __attribute__((unused)))
{
    if (pctx->req_tgt->collection && !pctx->req_tgt->resource) {
	xmlChar *type, *ver = NULL, *freeme = NULL;
	struct mime_type_t *mime;
	icalcomponent *ical = NULL;
	const char *value = NULL;
	size_t len = 0;
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

	if (!mime->content_type) {
	    xml_add_prop(HTTP_FORBIDDEN, pctx->ns[NS_DAV],
			 &propstat[PROPSTAT_FORBID],
			 prop->name, prop->ns, NULL,
			 CALDAV_SUPP_DATA);
	    *pctx->ret = HTTP_FORBIDDEN;
	    valid = 0;
	}
	else if (set) {
	    freeme = xmlNodeGetContent(prop);
	    value = (const char *) freeme;

	    /* Parse and validate the iCal data */
	    ical = mime->from_string(value);
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
		value = icalcomponent_as_ical_string(ical);
	    }

	    len = strlen(value);
	}

	if (valid) {
	    buf_reset(&pctx->buf);
	    buf_printf(&pctx->buf, ANNOT_NS "<%s>%s",
		       (const char *) prop->ns->href, prop->name);

	    if (!annotatemore_write_entry(pctx->mailboxname,
					  buf_cstring(&pctx->buf),
					  /* shared */ "", value, NULL,
					  len, 0, &pctx->tid)) {
		xml_add_prop(HTTP_OK, pctx->ns[NS_DAV], &propstat[PROPSTAT_OK],
			     prop->name, prop->ns, NULL, 0);
	    }
	    else {
		xml_add_prop(HTTP_SERVER_ERROR, pctx->ns[NS_DAV],
			     &propstat[PROPSTAT_ERROR],
			     prop->name, prop->ns, NULL, 0);
	    }
	}

	if (ical) icalcomponent_free(ical);
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


static int report_cal_query(struct transaction_t *txn,
			    xmlNodePtr inroot, struct propfind_ctx *fctx)
{
    int ret = 0;
    xmlNodePtr node;
    struct calquery_filter calfilter;

    memset(&calfilter, 0, sizeof(struct calquery_filter));
    calfilter.save_busytime = 0;

    fctx->davdb = auth_caldavdb;
    fctx->lookup_resource = (db_lookup_proc_t) &caldav_lookup_resource;
    fctx->foreach_resource = (db_foreach_proc_t) &caldav_foreach;
    fctx->proc_by_resource = &propfind_by_resource;

    /* Parse children element of report */
    for (node = inroot->children; node; node = node->next) {
	if (node->type == XML_ELEMENT_NODE) {
	    if (!xmlStrcmp(node->name, BAD_CAST "filter")) {
		ret = parse_comp_filter(node->children, &calfilter, &txn->error);
		if (ret) return ret;
		else {
		    fctx->filter = apply_calfilter;
		    fctx->filter_crit = &calfilter;
		}
	    }
	    else if (!xmlStrcmp(node->name, BAD_CAST "timezone")) {
		xmlChar *tz = NULL;
		icalcomponent *ical = NULL;

		syslog(LOG_WARNING, "REPORT calendar-query w/timezone");
		tz = xmlNodeGetContent(node);
		ical = icalparser_parse_string((const char *) tz);
		if (!ical ||
		    (icalcomponent_isa(ical) != ICAL_VCALENDAR_COMPONENT) ||
		    !icalcomponent_get_first_component(ical,
						       ICAL_VTIMEZONE_COMPONENT)
		    || icalcomponent_get_first_real_component(ical)) {
		    txn->error.precond = CALDAV_VALID_DATA;
		    ret = HTTP_FORBIDDEN;
		}

		if (tz) xmlFree(tz);
		if (ical) icalcomponent_free(ical);
		if (ret) return ret;
	    }
	}
    }

    if (fctx->depth > 0) {
	/* Calendar collection(s) */
	if (txn->req_tgt.collection) {
	    /* Add response for target calendar collection */
	    propfind_by_collection(txn->req_tgt.mboxname, 0, 0, fctx);
	}
	else {
	    /* Add responses for all contained calendar collections */
	    strlcat(txn->req_tgt.mboxname, ".%", sizeof(txn->req_tgt.mboxname));
	    mboxlist_findall(NULL,  /* internal namespace */
			     txn->req_tgt.mboxname, 1, httpd_userid, 
			     httpd_authstate, propfind_by_collection, fctx);
	}

	ret = *fctx->ret;
    }

    /* RRULEs still populate busytime array */
    if (calfilter.busytime.busy) free(calfilter.busytime.busy);

    return ret;
}


static int report_cal_multiget(struct transaction_t *txn,
			       xmlNodePtr inroot, struct propfind_ctx *fctx)
{
    int r, ret = 0;
    struct request_target_t tgt;
    struct mailbox *mailbox = NULL;
    xmlNodePtr node;
    struct buf uri = BUF_INITIALIZER;

    memset(&tgt, 0, sizeof(struct request_target_t));
    tgt.namespace = URL_NS_CALENDAR;

    /* Get props for each href */
    for (node = inroot->children; node; node = node->next) {
	if ((node->type == XML_ELEMENT_NODE) &&
	    !xmlStrcmp(node->name, BAD_CAST "href")) {
	    xmlChar *href = xmlNodeListGetString(inroot->doc, node->children, 1);
	    int len = xmlStrlen(href);
	    struct caldav_data *cdata;

	    buf_ensure(&uri, len);
	    xmlURIUnescapeString((const char *) href, len, uri.s);
	    xmlFree(href);

	    /* Parse the path */
	    if ((r = caldav_parse_path(uri.s, &tgt, &fctx->err->desc))) {
		ret = r;
		goto done;
	    }

	    fctx->req_tgt = &tgt;

	    /* Check if we already have this mailbox open */
	    if (!mailbox || strcmp(mailbox->name, tgt.mboxname)) {
		if (mailbox) mailbox_unlock_index(mailbox, NULL);

		/* Open mailbox for reading */
		if ((r = http_mailbox_open(tgt.mboxname, &mailbox, LOCK_SHARED))) {
		    syslog(LOG_ERR, "http_mailbox_open(%s) failed: %s",
			   tgt.mboxname, error_message(r));
		    txn->error.desc = error_message(r);
		    ret = HTTP_SERVER_ERROR;
		    goto done;
		}

		fctx->mailbox = mailbox;
	    }

	    /* Find message UID for the resource */
	    caldav_lookup_resource(auth_caldavdb,
				   tgt.mboxname, tgt.resource, 0, &cdata);
	    cdata->dav.resource = tgt.resource;
	    /* XXX  Check errors */

	    propfind_by_resource(fctx, cdata);
	}
    }

  done:
    if (mailbox) mailbox_unlock_index(mailbox, NULL);
    buf_free(&uri);

    return ret;
}



/* caldav_foreach() callback to find busytime of a resource */
static int busytime_by_resource(void *rock, void *data)
{
    struct propfind_ctx *fctx = (struct propfind_ctx *) rock;
    struct dav_data *ddata = (struct dav_data *) data;
    struct index_record record;
    int r;

    if (!ddata->imap_uid) return 0;

    /* Fetch index record for the resource */
    r = mailbox_find_index_record(fctx->mailbox, ddata->imap_uid, &record);
    if (r) return 0;

    fctx->record = &record;
    (void) apply_calfilter(fctx, data);

    if (fctx->msg_base) {
	mailbox_unmap_message(fctx->mailbox, fctx->record->uid,
			      &fctx->msg_base, &fctx->msg_size);
    }
    fctx->msg_base = NULL;
    fctx->msg_size = 0;
    fctx->record = NULL;

    return 0;
}


/* mboxlist_findall() callback to find busytime of a collection */
static int busytime_by_collection(char *mboxname, int matchlen,
				  int maycreate, void *rock)
{
    struct propfind_ctx *fctx = (struct propfind_ctx *) rock;
    struct calquery_filter *calfilter =
	(struct calquery_filter *) fctx->filter_crit;

    if (calfilter && calfilter->check_transp) {
	/* Check if the collection is marked as transparent */
	struct annotation_data attrib;
	const char *prop_annot =
	    ANNOT_NS "CALDAV:schedule-calendar-transp";

	if (!annotatemore_lookup(mboxname, prop_annot, /* shared */ "", &attrib)
	    && attrib.value && !strcmp(attrib.value, "transparent")) return 0;
    }

    return propfind_by_collection(mboxname, matchlen, maycreate, rock);
}


/* Compare start times of busytime period -- used for sorting */
static int compare_busytime(const void *b1, const void *b2)
{
    struct icalperiodtype *a = (struct icalperiodtype *) b1;
    struct icalperiodtype *b = (struct icalperiodtype *) b2;

    return icaltime_compare(a->start, b->start);
}


/* Create an iCalendar object containing busytime of all specified resources */
static icalcomponent *busytime_query_local(struct transaction_t *txn,
					   struct propfind_ctx *fctx,
					   char mailboxname[],
					   icalproperty_method method,
					   const char *uid,
					   const char *organizer,
					   const char *attendee)
{
    struct calquery_filter *calfilter =
	(struct calquery_filter *) fctx->filter_crit;
    struct busytime *busytime = &calfilter->busytime;
    icalcomponent *cal = NULL;

    fctx->lookup_resource = (db_lookup_proc_t) &caldav_lookup_resource;
    fctx->foreach_resource = (db_foreach_proc_t) &caldav_foreach;
    fctx->proc_by_resource = &busytime_by_resource;

    /* Gather up all of the busytime */
    if (fctx->depth > 0) {
	/* Calendar collection(s) */

	/* XXX  Check DACL_READFB on all calendars */

	if (txn->req_tgt.collection) {
	    /* Get busytime for target calendar collection */
	    busytime_by_collection(mailboxname, 0, 0, fctx);
	}
	else {
	    /* Get busytime for all contained calendar collections */
	    strlcat(mailboxname, ".%", sizeof(mailboxname));
	    mboxlist_findall(NULL,  /* internal namespace */
			     mailboxname, 1, httpd_userid, 
			     httpd_authstate, busytime_by_collection, fctx);
	}
    }

    if (!*fctx->ret) {
	struct buf prodid = BUF_INITIALIZER;
	icalcomponent *fb;
	icalproperty *prop;
	time_t now = time(0);
	unsigned n;

	/* Construct iCalendar object with VFREEBUSY component */
	buf_printf(&prodid, "-//CyrusIMAP.org/Cyrus %s//EN", cyrus_version());
	cal = icalcomponent_vanew(ICAL_VCALENDAR_COMPONENT,
				  icalproperty_new_version("2.0"),
				  icalproperty_new_prodid(buf_cstring(&prodid)),
				  0);
	buf_free(&prodid);

	if (method) icalcomponent_set_method(cal, method);

	fb = icalcomponent_vanew(ICAL_VFREEBUSY_COMPONENT,
				 icalproperty_new_dtstamp(
				     icaltime_from_timet_with_zone(
					 now,
					 0,
					 icaltimezone_get_utc_timezone())),
				 icalproperty_new_dtstart(calfilter->start),
				 icalproperty_new_dtend(calfilter->end),
				 0);

	if (uid) icalcomponent_set_uid(fb, uid);
	if (organizer) {
	    prop = icalproperty_new_organizer(organizer);
	    icalcomponent_add_property(fb, prop);
	}
	if (attendee) {
	    prop = icalproperty_new_attendee(attendee);
	    icalcomponent_add_property(fb, prop);
	}

	icalcomponent_add_component(cal, fb);

	/* Sort busytime periods by start time */
	qsort(busytime->busy, busytime->len, sizeof(struct icalperiodtype),
	      compare_busytime);

	/* Add busytime periods to VFREEBUSY component, coalescing as needed */
	for (n = 0; n < busytime->len; n++) {
	    if ((n+1 < busytime->len) &&
		icaltime_compare(busytime->busy[n].end,
				 busytime->busy[n+1].start) >= 0) {
		/* Periods overlap -- coalesce into next busytime */
		memcpy(&busytime->busy[n+1].start, &busytime->busy[n].start,
		       sizeof(struct icaltimetype));
		if (icaltime_compare(busytime->busy[n].end,
				     busytime->busy[n+1].end) > 0) {
		    memcpy(&busytime->busy[n+1].end, &busytime->busy[n].end,
			   sizeof(struct icaltimetype));
		}
	    }
	    else {
		icalproperty *busy =
		    icalproperty_new_freebusy(busytime->busy[n]);

		icalcomponent_add_property(fb, busy);
	    }
	}
    }

    return cal;
}


static int report_fb_query(struct transaction_t *txn,
			   xmlNodePtr inroot, struct propfind_ctx *fctx)
{
    int ret = 0;
    const char **hdr;
    struct mime_type_t *mime;
    struct calquery_filter calfilter;
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

    memset(&calfilter, 0, sizeof(struct calquery_filter));
    calfilter.comp = CAL_COMP_VEVENT | CAL_COMP_VFREEBUSY;
    calfilter.start = icaltime_from_timet_with_zone(INT_MIN, 0, NULL);
    calfilter.end = icaltime_from_timet_with_zone(INT_MAX, 0, NULL);
    calfilter.save_busytime = 1;
    fctx->filter = apply_calfilter;
    fctx->filter_crit = &calfilter;
    fctx->davdb = auth_caldavdb;

    /* Parse children element of report */
    for (node = inroot->children; node; node = node->next) {
	if (node->type == XML_ELEMENT_NODE) {
	    if (!xmlStrcmp(node->name, BAD_CAST "time-range")) {
		xmlChar *start, *end;

		start = xmlGetProp(node, BAD_CAST "start");
		if (start) {
		    calfilter.start = icaltime_from_string((char *) start);
		    xmlFree(start);
		}

		end = xmlGetProp(node, BAD_CAST "end");
		if (end) {
		    calfilter.end = icaltime_from_string((char *) end);
		    xmlFree(end);
		}

		if (!is_valid_timerange(calfilter.start, calfilter.end)) {
		    return HTTP_BAD_REQUEST;
		}
	    }
	}
    }

    cal = busytime_query_local(txn, fctx, txn->req_tgt.mboxname,
			       0, NULL, NULL, NULL);

    if (calfilter.busytime.busy) free(calfilter.busytime.busy);

    if (cal) {
	/* Output the iCalendar object as text/calendar */
	char *cal_str = mime->to_string(cal);
	icalcomponent_free(cal);

	txn->resp_body.type = mime->content_type;

	/* iCalendar data in response should not be transformed */
	txn->flags.cc |= CC_NOTRANSFORM;

	write_body(HTTP_OK, txn, cal_str, strlen(cal_str));
	free(cal_str);
    }
    else ret = HTTP_NOT_FOUND;

    return ret;
}


/* Store the iCal data in the specified calendar/resource */
static int store_resource(struct transaction_t *txn, icalcomponent *ical,
			  struct mailbox *mailbox, const char *resource,
			  struct caldav_db *caldavdb, int overwrite,
			  unsigned flags)
{
    int ret = HTTP_CREATED, r;
    icalcomponent *comp;
    icalcomponent_kind kind;
    icalproperty_method meth;
    icalproperty *prop;
    unsigned mykind = 0;
    const char *organizer = NULL;
    const char *prop_annot = ANNOT_NS "CALDAV:supported-calendar-component-set";
    struct annotation_data attrib;
    struct caldav_data *cdata;
    FILE *f = NULL;
    struct stagemsg *stage;
    const char *uid, *ics;
    uquota_t size;
    time_t now = time(NULL);
    char datestr[80];
    struct appendstate as;
    static char sched_tag[64];
    static unsigned store_count = 0;

    /* Check for supported component type */
    comp = icalcomponent_get_first_real_component(ical);
    kind = icalcomponent_isa(comp);
    switch (kind) {
    case ICAL_VEVENT_COMPONENT: mykind = CAL_COMP_VEVENT; break;
    case ICAL_VTODO_COMPONENT: mykind = CAL_COMP_VTODO; break;
    case ICAL_VJOURNAL_COMPONENT: mykind = CAL_COMP_VJOURNAL; break;
    case ICAL_VFREEBUSY_COMPONENT: mykind = CAL_COMP_VFREEBUSY; break;
    default:
	txn->error.precond = CALDAV_SUPP_COMP;
	return HTTP_FORBIDDEN;
    }

    if (!annotatemore_lookup(mailbox->name, prop_annot,
			     /* shared */ "", &attrib)
	&& attrib.value) {
	unsigned long supp_comp = strtoul(attrib.value, NULL, 10);

	if (!(mykind & supp_comp)) {
	    txn->error.precond = CALDAV_SUPP_COMP;
	    return HTTP_FORBIDDEN;
	}
    }

    /* Find iCalendar UID for the current resource, if exists */
    uid = icalcomponent_get_uid(comp);
    caldav_lookup_resource(caldavdb,
			   mailbox->name, resource, 0, &cdata);
    if (cdata->ical_uid && strcmp(cdata->ical_uid, uid)) {
	/* CALDAV:no-uid-conflict */
	txn->error.precond = CALDAV_UID_CONFLICT;
	return HTTP_FORBIDDEN;
    }

    /* Check for existing iCalendar UID */
    caldav_lookup_uid(caldavdb, uid, 0, &cdata);
    if (!(flags & NO_DUP_CHECK) &&
	cdata->dav.mailbox && !strcmp(cdata->dav.mailbox, mailbox->name) &&
	strcmp(cdata->dav.resource, resource)) {
	/* CALDAV:no-uid-conflict */
	char *owner = mboxname_to_userid(cdata->dav.mailbox);
	mboxname_hiersep_toexternal(&httpd_namespace, owner, 0);

	txn->error.precond = CALDAV_UID_CONFLICT;
	assert(!buf_len(&txn->buf));
	buf_printf(&txn->buf, "%s/user/%s/%s/%s",
		   namespace_calendar.prefix, owner,
		   strrchr(cdata->dav.mailbox, '.')+1, cdata->dav.resource);
	txn->error.resource = buf_cstring(&txn->buf);
	return HTTP_FORBIDDEN;
    }

    /* Prepare to stage the message */
    if (!(f = append_newstage(mailbox->name, now, 0, &stage))) {
	syslog(LOG_ERR, "append_newstage(%s) failed", mailbox->name);
	txn->error.desc = "append_newstage() failed\r\n";
	return HTTP_SERVER_ERROR;
    }

    /* Remove all X-LIC-ERROR properties*/
    icalcomponent_strip_errors(ical);

    ics = icalcomponent_as_ical_string(ical);

    /* Create iMIP header for resource */
    prop = icalcomponent_get_first_property(comp, ICAL_ORGANIZER_PROPERTY);
    if (prop) {
	organizer = icalproperty_get_organizer(prop)+7;
	fprintf(f, "From: %s\r\n", organizer);
    }
    else {
	/* XXX  This needs to be done via an LDAP/DB lookup */
	fprintf(f, "From: %s@%s\r\n", proxy_userid, config_servername);
    }

    fprintf(f, "Subject: %s\r\n", icalcomponent_get_summary(comp));

    rfc822date_gen(datestr, sizeof(datestr),
		   icaltime_as_timet_with_zone(icalcomponent_get_dtstamp(comp),
					       icaltimezone_get_utc_timezone()));
    fprintf(f, "Date: %s\r\n", datestr);

    fprintf(f, "Message-ID: <%s@%s>\r\n", uid, config_servername);

    fprintf(f, "Content-Type: text/calendar; charset=utf-8");
    if ((meth = icalcomponent_get_method(ical)) != ICAL_METHOD_NONE) {
	fprintf(f, "; method=%s", icalproperty_method_to_string(meth));
    }
    fprintf(f, "; component=%s\r\n", icalcomponent_kind_to_string(kind));

    fprintf(f, "Content-Length: %u\r\n", (unsigned) strlen(ics));
    fprintf(f, "Content-Disposition: inline; filename=\"%s\"", resource);
    if (organizer) {
	const char *stag;
	if (flags & NEW_STAG) {
	    sprintf(sched_tag, "%d-%ld-%u", getpid(), now, store_count++);
	    stag = sched_tag;
	}
	else stag = cdata->sched_tag;
	if (stag) fprintf(f, ";\r\n\tschedule-tag=%s", stag);
    }
    fprintf(f, "\r\n");

    /* XXX  Check domain of data and use appropriate CTE */

    fprintf(f, "MIME-Version: 1.0\r\n");
    fprintf(f, "\r\n");

    /* Write the iCal data to the file */
    fprintf(f, "%s", ics);
    size = ftell(f);

    fclose(f);


    /* Prepare to append the iMIP message to calendar mailbox */
    if ((r = append_setup(&as, mailbox->name, NULL, NULL, 0, size))) {
	syslog(LOG_ERR, "append_setup(%s) failed: %s",
	       mailbox->name, error_message(r));
	ret = HTTP_SERVER_ERROR;
	txn->error.desc = "append_setup() failed\r\n";
    }
    else {
	struct body *body = NULL;

	/* Append the iMIP file to the calendar mailbox */
	if ((r = append_fromstage(&as, &body, stage, now, NULL, 0, 0))) {
	    syslog(LOG_ERR, "append_fromstage() failed");
	    ret = HTTP_SERVER_ERROR;
	    txn->error.desc = "append_fromstage() failed\r\n";
	}
	if (body) {
	    message_free_body(body);
	    free(body);
	}

	if (r) append_abort(&as);
	else {
	    /* Commit the append to the calendar mailbox */
	    if ((r = append_commit(&as, size, NULL, NULL, NULL, &mailbox))) {
		syslog(LOG_ERR, "append_commit() failed");
		ret = HTTP_SERVER_ERROR;
		txn->error.desc = "append_commit() failed\r\n";
	    }
	    else {
		/* append_commit() returns a write-locked index */
		struct index_record newrecord, oldrecord, *expunge;

		/* Read index record for new message (always the last one) */
		mailbox_read_index_record(mailbox, mailbox->i.num_records,
					  &newrecord);

		/* Find message UID for the current resource, if exists */
		caldav_lookup_resource(caldavdb,
				       mailbox->name, resource, 1, &cdata);
		/* XXX  check for errors */

		if (cdata->dav.imap_uid) {
		    /* Now that we have the replacement message in place
		       and the mailbox locked, re-read the old record
		       and see if we should overwrite it.  Either way,
		       one of our records will have to be expunged.
		    */
		    int userflag;

		    ret = HTTP_NO_CONTENT;

		    /* Fetch index record for the resource */
		    r = mailbox_find_index_record(mailbox, cdata->dav.imap_uid,
						  &oldrecord);

		    if (overwrite == OVERWRITE_CHECK) {
			/* Check any preconditions */
			const char *etag = message_guid_encode(&oldrecord.guid);
			time_t lastmod = oldrecord.internaldate;
			int precond = caldav_check_precond(txn, cdata,
							   etag, lastmod);

			overwrite = (precond == HTTP_OK);
		    }

		    if (overwrite) {
			/* Keep new resource - expunge the old one */
			expunge = &oldrecord;
		    }
		    else {
			/* Keep old resource - expunge the new one */
			expunge = &newrecord;
			ret = HTTP_PRECOND_FAILED;
		    }

		    /* Perform the actual expunge */
		    r = mailbox_user_flag(mailbox, DFLAG_UNBIND,  &userflag);
		    if (!r) {
			expunge->user_flags[userflag/32] |= 1<<(userflag&31);
			expunge->system_flags |= FLAG_EXPUNGED | FLAG_UNLINKED;
			r = mailbox_rewrite_index_record(mailbox, expunge);
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

		    /* Create mapping entry from resource name to UID */
		    cdata->dav.mailbox = mailbox->name;
		    cdata->dav.resource = resource;
		    cdata->dav.imap_uid = newrecord.uid;
		    caldav_make_entry(ical, cdata);

		    if (!cdata->dav.creationdate) cdata->dav.creationdate = now;
		    if (!cdata->organizer) cdata->sched_tag = NULL;
		    else if (flags & NEW_STAG) {
			resp_body->stag = cdata->sched_tag = sched_tag;
		    }

		    caldav_write(caldavdb, cdata, 1);
		    /* XXX  check for errors, if this fails, backout changes */

		    if ((flags & PREFER_REP) || !(flags & NEW_STAG)) {
			/* Tell client about the new resource */
			resp_body->lastmod = newrecord.internaldate;
			resp_body->etag = message_guid_encode(&newrecord.guid);
		    }
		}

		/* need to close mailbox returned to us by append_commit */
		mailbox_close(&mailbox);
	    }
	}
    }

    append_removestage(stage);

    return ret;
}


int caladdress_lookup(const char *addr, struct sched_param *param)
{
    char *p;
    int islocal = 1, found = 1;
    static char userid[MAX_MAILBOX_BUFFER];

    memset(param, 0, sizeof(struct sched_param));

    if (!addr) return HTTP_NOT_FOUND;

    p = (char *) addr;
    if (!strncmp(addr, "mailto:", 7)) p += 7;

    /* XXX  Do LDAP/DB/socket lookup to see if user is local */
    /* XXX  Hack until real lookup stuff is written */
    strlcpy(userid, p, sizeof(userid));
    if ((p = strchr(userid, '@'))) *p++ = '\0';

    if (islocal) {
	/* User is in a local domain */
	int r;
	static const char *calendarprefix = NULL;
	char mailboxname[MAX_MAILBOX_BUFFER];

	if (!found) return HTTP_NOT_FOUND;
	else param->userid = userid;

	/* Lookup user's cal-home-set to see if its on this server */
	if (!calendarprefix) {
	    calendarprefix = config_getstring(IMAPOPT_CALENDARPREFIX);
	}

	mboxname_hiersep_tointernal(&httpd_namespace, userid, 0);
	snprintf(mailboxname, sizeof(mailboxname),
		 "user.%s.%s", param->userid, calendarprefix);

	if ((r = http_mlookup(mailboxname, &param->server, NULL, NULL))) {
	    syslog(LOG_ERR, "mlookup(%s) failed: %s",
		   mailboxname, error_message(r));

	    switch (r) {
	    case IMAP_PERMISSION_DENIED: return HTTP_FORBIDDEN;
	    case IMAP_MAILBOX_NONEXISTENT: return HTTP_NOT_FOUND;
	    default: return HTTP_SERVER_ERROR;
	    }
	}

	if (param->server) param->flags |= SCHEDTYPE_ISCHEDULE;
    }
    else {
	/* User is outside of our domain(s) -
	   Do remote scheduling (default = iMIP) */
	param->flags |= SCHEDTYPE_REMOTE;

#ifdef WITH_DKIM
	/* Do iSchedule DNS SRV lookup */

	/* XXX  If success, set server, port,
	   and flags |= SCHEDTYPE_ISCHEDULE [ | SCHEDTYPE_SSL ] */
#endif
    }

    return 0;
}


/* Send an iMIP request for attendees in 'ical' */
static int imip_send(icalcomponent *ical)
{
    icalcomponent *comp;
    icalproperty *prop;
    icalproperty_method meth;
    icalcomponent_kind kind;
    const char *argv[8], *organizer, *subject;
    FILE *sm;
    pid_t pid;
    int r;
    time_t t = time(NULL);
    char datestr[80];
    static unsigned send_count = 0;

    meth = icalcomponent_get_method(ical);
    comp = icalcomponent_get_first_real_component(ical);
    kind = icalcomponent_isa(comp);
    prop = icalcomponent_get_first_property(comp, ICAL_ORGANIZER_PROPERTY);
    organizer = icalproperty_get_organizer(prop) + 7;

    argv[0] = "sendmail";
    argv[1] = "-f";
    argv[2] = organizer;
    argv[3] = "-i";
    argv[4] = "-N";
    argv[5] = "failure,delay";
    argv[6] = "-t";
    argv[7] = NULL;
    pid = open_sendmail(argv, &sm);

    if (sm == NULL) return HTTP_UNAVAILABLE;

    /* Create iMIP message */
    fprintf(sm, "From: %s\r\n", organizer);

    for (prop = icalcomponent_get_first_property(comp, ICAL_ATTENDEE_PROPERTY);
	 prop;
	 prop = icalcomponent_get_next_property(comp, ICAL_ATTENDEE_PROPERTY)) {
	fprintf(sm, "To: %s\r\n", icalproperty_get_attendee(prop) + 7);
    }

    subject = icalcomponent_get_summary(comp);
    if (!subject) {
	fprintf(sm, "Subject: %s %s\r\n", icalcomponent_kind_to_string(kind),
		icalproperty_method_to_string(meth));
    }
    else fprintf(sm, "Subject: %s\r\n", subject);

    rfc822date_gen(datestr, sizeof(datestr), t);
    fprintf(sm, "Date: %s\r\n", datestr);

    fprintf(sm, "Message-ID: <cmu-httpd-%u-%ld-%u@%s>\r\n",
	    getpid(), t, send_count++, config_servername);

    fprintf(sm, "Content-Type: text/calendar; charset=utf-8");
    fprintf(sm, "; method=%s; component=%s \r\n",
	    icalproperty_method_to_string(meth),
	    icalcomponent_kind_to_string(kind));

    fputs("Content-Disposition: inline\r\n", sm);

    fputs("MIME-Version: 1.0\r\n", sm);
    fputs("\r\n", sm);

    fputs(icalcomponent_as_ical_string(ical), sm);

    fclose(sm);

    while (waitpid(pid, &r, 0) < 0);

    return r;
}


/* Add a <response> XML element for 'recipient' to 'root' */
xmlNodePtr xml_add_schedresponse(xmlNodePtr root, xmlNsPtr dav_ns,
				 xmlChar *recipient, xmlChar *status)
{
    xmlNodePtr resp, recip;

    resp = xmlNewChild(root, NULL, BAD_CAST "response", NULL);
    recip = xmlNewChild(resp, NULL, BAD_CAST "recipient", NULL);

    if (dav_ns) xmlNewChild(recip, dav_ns, BAD_CAST "href", recipient);
    else xmlNodeAddContent(recip, recipient);

    if (status)
	xmlNewChild(resp, NULL, BAD_CAST "request-status", status);

    return resp;
}


struct remote_rock {
    struct transaction_t *txn;
    icalcomponent *ical;
    xmlNodePtr root;
    xmlNsPtr *ns;
};

/* Send an iTIP busytime request to remote attendees via iMIP or iSchedule */
static void busytime_query_remote(const char *server __attribute__((unused)),
				  void *data, void *rock)
{
    struct sched_param *remote = (struct sched_param *) data;
    struct remote_rock *rrock = (struct remote_rock *) rock;
    icalcomponent *comp;
    struct proplist *list;
    xmlNodePtr resp;
    const char *status = NULL;
    int r;

    comp = icalcomponent_get_first_real_component(rrock->ical);

    /* Add the attendees to the iTIP request */
    for (list = remote->props; list; list = list->next) {
	icalcomponent_add_property(comp, list->prop);
    }

    if (remote->flags == SCHEDTYPE_REMOTE) {
	/* Use iMIP */

	r = imip_send(rrock->ical);

	if (!r) status = REQSTAT_SENT;
	else status = REQSTAT_TEMPFAIL;
    }
    else {
	/* Use iSchedule */
	xmlNodePtr xml;

	r = isched_send(remote, NULL, rrock->ical, &xml);
	if (r) status = REQSTAT_TEMPFAIL;
	else if (xmlStrcmp(xml->name, BAD_CAST "schedule-response")) {
	    if (r) status = REQSTAT_TEMPFAIL;
	}
	else {
	    xmlNodePtr cur;

	    /* Process each response element */
	    for (cur = xml->children; cur; cur = cur->next) {
		xmlNodePtr node;
		xmlChar *recip = NULL, *status = NULL, *content = NULL;

		if (cur->type != XML_ELEMENT_NODE) continue;

		for (node = cur->children; node; node = node->next) {
		    if (node->type != XML_ELEMENT_NODE) continue;

		    if (!xmlStrcmp(node->name, BAD_CAST "recipient"))
			recip = xmlNodeGetContent(node);
		    else if (!xmlStrcmp(node->name, BAD_CAST "request-status"))
			status = xmlNodeGetContent(node);
		    else if (!xmlStrcmp(node->name, BAD_CAST "calendar-data"))
			content = xmlNodeGetContent(node);
		}

		resp =
		    xml_add_schedresponse(rrock->root,
					  !(rrock->txn->req_tgt.allow & ALLOW_ISCHEDULE) ?
					  rrock->ns[NS_DAV] : NULL,
					  recip, status);

		xmlFree(status);
		xmlFree(recip);

		if (content) {
		    xmlNodePtr cdata =
			xmlNewTextChild(resp, NULL,
					BAD_CAST "calendar-data", NULL);
		    xmlAddChild(cdata,
				xmlNewCDataBlock(rrock->root->doc,
						 content,
						 xmlStrlen(content)));
		    xmlFree(content);

		    /* iCal data in resp SHOULD NOT be transformed */
		    rrock->txn->flags.cc |= CC_NOTRANSFORM;
		}
	    }

	    xmlFreeDoc(xml->doc);
	}
    }

    /* Report request-status (if necesary)
     * Remove the attendees from the iTIP request and hash bucket
     */
    for (list = remote->props; list; list = list->next) {
	if (status) {
	    const char *attendee = icalproperty_get_attendee(list->prop);
	    xml_add_schedresponse(rrock->root,
				  !(rrock->txn->req_tgt.allow & ALLOW_ISCHEDULE) ?
				  rrock->ns[NS_DAV] : NULL,
				  BAD_CAST attendee,
				  BAD_CAST status);
	}

	icalcomponent_remove_property(comp, list->prop);
	icalproperty_free(list->prop);
    }

    if (remote->server) free(remote->server);
}


static void free_sched_param(void *data)
{
    struct sched_param *sched_param = (struct sched_param *) data;

    if (sched_param) {
	struct proplist *prop, *next;

	for (prop = sched_param->props; prop; prop = next) {
	    next = prop->next;
	    free(prop);
	}
	free(sched_param);
    }
}


/* Perform a Busy Time query based on given VFREEBUSY component */
/* NOTE: This function is destructive of 'ical' */
int sched_busytime_query(struct transaction_t *txn,
			 struct mime_type_t *mime, icalcomponent *ical)
{
    int ret = 0;
    static const char *calendarprefix = NULL;
    icalcomponent *comp;
    char mailboxname[MAX_MAILBOX_BUFFER];
    icalproperty *prop = NULL, *next;
    const char *uid = NULL, *organizer = NULL;
    struct sched_param sparam;
    struct auth_state *org_authstate = NULL;
    xmlNodePtr root = NULL;
    xmlNsPtr ns[NUM_NAMESPACE];
    struct propfind_ctx fctx;
    struct calquery_filter calfilter;
    struct hash_table remote_table;
    struct sched_param *remote = NULL;

    if (!calendarprefix) {
	calendarprefix = config_getstring(IMAPOPT_CALENDARPREFIX);
    }

    comp = icalcomponent_get_first_real_component(ical);
    uid = icalcomponent_get_uid(comp);

    prop = icalcomponent_get_first_property(comp, ICAL_ORGANIZER_PROPERTY);
    organizer = icalproperty_get_organizer(prop);

    /* XXX  Do we need to do more checks here? */
    if (caladdress_lookup(organizer, &sparam) ||
	(sparam.flags & SCHEDTYPE_REMOTE))
	org_authstate = auth_newstate("anonymous");
    else
	org_authstate = auth_newstate(sparam.userid);

    /* Start construction of our schedule-response */
    if (!(root =
	  init_xml_response("schedule-response",
			    (txn->req_tgt.allow & ALLOW_ISCHEDULE) ? NS_ISCHED :
			    NS_CALDAV, NULL, ns))) {
	ret = HTTP_SERVER_ERROR;
	txn->error.desc = "Unable to create XML response\r\n";
	goto done;
    }

    /* Populate our filter and propfind context for local attendees */
    memset(&calfilter, 0, sizeof(struct calquery_filter));
    calfilter.comp = CAL_COMP_VEVENT | CAL_COMP_VFREEBUSY;
    calfilter.start = icalcomponent_get_dtstart(comp);
    calfilter.end = icalcomponent_get_dtend(comp);
    calfilter.check_transp = 1;
    calfilter.save_busytime = 1;

    memset(&fctx, 0, sizeof(struct propfind_ctx));
    fctx.req_tgt = &txn->req_tgt;
    fctx.depth = 2;
    fctx.userid = proxy_userid;
    fctx.int_userid = httpd_userid;
    fctx.userisadmin = httpd_userisadmin;
    fctx.authstate = org_authstate;
    fctx.reqd_privs = 0;  /* handled by CALDAV:schedule-deliver on Inbox */
    fctx.filter = apply_calfilter;
    fctx.filter_crit = &calfilter;
    fctx.err = &txn->error;
    fctx.ret = &ret;
    fctx.fetcheddata = 0;

    /* Create hash table for any remote attendee servers */
    construct_hash_table(&remote_table, 10, 1);

    assert(!buf_len(&txn->buf));

    /* Process each attendee */
    for (prop = icalcomponent_get_first_property(comp, ICAL_ATTENDEE_PROPERTY);
	 prop;
	 prop = next) {
	const char *attendee;
	int r;

	next = icalcomponent_get_next_property(comp, ICAL_ATTENDEE_PROPERTY);

	/* Remove each attendee so we can add in only those
	   that reside on a given remote server later */
	icalcomponent_remove_property(comp, prop);

	/* Is attendee remote or local? */
	attendee = icalproperty_get_attendee(prop);
	r = caladdress_lookup(attendee, &sparam);

	/* Don't allow scheduling of remote users via an iSchedule request */
	if ((sparam.flags & SCHEDTYPE_REMOTE) &&
	    (txn->req_tgt.allow & ALLOW_ISCHEDULE)) {
	    r = HTTP_FORBIDDEN;
	}

	if (r) {
	    xml_add_schedresponse(root,
				  !(txn->req_tgt.allow & ALLOW_ISCHEDULE) ?
				  ns[NS_DAV] : NULL,
				  BAD_CAST attendee, BAD_CAST REQSTAT_NOUSER);

	    icalproperty_free(prop);
	}
	else if (sparam.flags) {
	    /* Remote attendee */
	    struct proplist *newprop;
	    const char *key;

	    if (sparam.flags == SCHEDTYPE_REMOTE) {
		/* iMIP - collect attendees under empty key (no server) */
		key = "";
	    }
	    else {
		/* iSchedule - collect attendees by server */
		key = sparam.server;
	    }

	    remote = hash_lookup(key, &remote_table);
	    if (!remote) {
		/* New remote - add it to the hash table */
		remote = xzmalloc(sizeof(struct sched_param));
		if (sparam.server) remote->server = xstrdup(sparam.server);
		remote->port = sparam.port;
		remote->flags = sparam.flags;
		hash_insert(key, remote, &remote_table);
	    }
	    newprop = xmalloc(sizeof(struct proplist));
	    newprop->prop = prop;
	    newprop->next = remote->props;
	    remote->props = newprop;
	}
	else {
	    /* Local attendee on this server */
	    xmlNodePtr resp;
	    const char *userid = sparam.userid;
	    struct mboxlist_entry mbentry = { NULL, 0, NULL, NULL };
	    icalcomponent *busy = NULL;

	    resp =
		xml_add_schedresponse(root,
				      !(txn->req_tgt.allow & ALLOW_ISCHEDULE) ?
				      ns[NS_DAV] : NULL,
				      BAD_CAST attendee, NULL);
				 

	    /* Check ACL of ORGANIZER on attendee's Scheduling Inbox */
	    snprintf(mailboxname, sizeof(mailboxname),
		     "user.%s.%s.Inbox", userid, calendarprefix);

	    if ((r = mboxlist_lookup(mailboxname, &mbentry, NULL))) {
		syslog(LOG_INFO, "mboxlist_lookup(%s) failed: %s",
		       mailboxname, error_message(r));
		xmlNewChild(resp, NULL, BAD_CAST "request-status",
			    BAD_CAST REQSTAT_REJECTED);
	    }

	    else if (!mbentry.acl ||
		     !(cyrus_acl_myrights(org_authstate, mbentry.acl) &
		       DACL_SCHEDFB)) {
		xmlNewChild(resp, NULL, BAD_CAST "request-status",
			    BAD_CAST REQSTAT_NOPRIVS);
	    }

	    else {
		/* Start query at attendee's calendar-home-set */
		snprintf(mailboxname, sizeof(mailboxname),
			 "user.%s.%s", userid, calendarprefix);

		fctx.davdb = caldav_open(userid, CALDAV_CREATE);
		fctx.req_tgt->collection = NULL;
		calfilter.busytime.len = 0;
		busy = busytime_query_local(txn, &fctx, mailboxname,
					    ICAL_METHOD_REPLY, uid,
					    organizer, attendee);

		caldav_close(fctx.davdb);
	    }

	    if (busy) {
		xmlNodePtr cdata;
		char *fb_str = mime->to_string(busy);
		icalcomponent_free(busy);

		xmlNewChild(resp, NULL, BAD_CAST "request-status",
			    BAD_CAST REQSTAT_SUCCESS);

		cdata = xmlNewTextChild(resp, NULL,
					BAD_CAST "calendar-data", NULL);

		/* Trim any charset from content-type */
		buf_reset(&txn->buf);
		buf_printf(&txn->buf, "%.*s",
			   (int) strcspn(mime->content_type, ";"),
			   mime->content_type);

		xmlNewProp(cdata, BAD_CAST "content-type",
			   BAD_CAST buf_cstring(&txn->buf));

		if (mime->version)
		    xmlNewProp(cdata, BAD_CAST "version",
			       BAD_CAST mime->version);

		xmlAddChild(cdata,
			    xmlNewCDataBlock(root->doc, BAD_CAST fb_str,
					     strlen(fb_str)));
		free(fb_str);

		/* iCalendar data in response should not be transformed */
		txn->flags.cc |= CC_NOTRANSFORM;
	    }
	    else {
		xmlNewChild(resp, NULL, BAD_CAST "request-status",
			    BAD_CAST REQSTAT_NOUSER);
	    }

	    icalproperty_free(prop);
	}
    }

    buf_reset(&txn->buf);

    if (remote) {
	struct remote_rock rrock = { txn, ical, root, ns };
	hash_enumerate(&remote_table, busytime_query_remote, &rrock);
    }
    free_hash_table(&remote_table, free_sched_param);

    /* Output the XML response */
    if (!ret) xml_response(HTTP_OK, txn, root->doc);

  done:
    if (org_authstate) auth_freestate(org_authstate);
    if (calfilter.busytime.busy) free(calfilter.busytime.busy);
    if (root) xmlFreeDoc(root->doc);

    return ret;
}


static void free_sched_data(void *data)
{
    struct sched_data *sched_data = (struct sched_data *) data;

    if (sched_data) {
	if (sched_data->itip) icalcomponent_free(sched_data->itip);
	if (sched_data->force_send) free(sched_data->force_send);
	free(sched_data);
    }
}


#define SCHEDSTAT_PENDING	"1.0"
#define SCHEDSTAT_SENT		"1.1"
#define SCHEDSTAT_DELIVERED	"1.2"
#define SCHEDSTAT_SUCCESS	"2.0"
#define SCHEDSTAT_PARAM		"2.3"
#define SCHEDSTAT_NOUSER	"3.7"
#define SCHEDSTAT_NOPRIVS	"3.8"
#define SCHEDSTAT_TEMPFAIL	"5.1"
#define SCHEDSTAT_PERMFAIL	"5.2"
#define SCHEDSTAT_REJECTED	"5.3"

/* Deliver scheduling object to a remote recipient */
static void sched_deliver_remote(const char *recipient,
				 struct sched_param *sparam,
				 struct sched_data *sched_data)
{
    int r;

    if (sparam->flags == SCHEDTYPE_REMOTE) {
	/* Use iMIP */
	r = imip_send(sched_data->itip);
	if (!r) {
	    sched_data->status =
		sched_data->ischedule ? REQSTAT_SENT : SCHEDSTAT_SENT;
	}
	else {
	    sched_data->status = sched_data->ischedule ?
		REQSTAT_TEMPFAIL : SCHEDSTAT_TEMPFAIL;
	}
    }
    else {
	/* Use iSchedule */
	xmlNodePtr xml;

	r = isched_send(sparam, recipient, sched_data->itip, &xml);
	if (r) {
	    sched_data->status = sched_data->ischedule ?
		REQSTAT_TEMPFAIL : SCHEDSTAT_TEMPFAIL;
	}
	else if (xmlStrcmp(xml->name, BAD_CAST "schedule-response")) {
	    sched_data->status = sched_data->ischedule ?
		REQSTAT_TEMPFAIL : SCHEDSTAT_TEMPFAIL;
	}
	else {
	    xmlNodePtr cur;

	    /* Process each response element */
	    for (cur = xml->children; cur; cur = cur->next) {
		xmlNodePtr node;
		xmlChar *recip = NULL, *status = NULL;
		static char statbuf[1024];

		if (cur->type != XML_ELEMENT_NODE) continue;

		for (node = cur->children; node; node = node->next) {
		    if (node->type != XML_ELEMENT_NODE) continue;

		    if (!xmlStrcmp(node->name, BAD_CAST "recipient"))
			recip = xmlNodeGetContent(node);
		    else if (!xmlStrcmp(node->name,
					BAD_CAST "request-status"))
			status = xmlNodeGetContent(node);
		}

		if (!strncmp((const char *) status, "2.0", 3)) {
		    sched_data->status = sched_data->ischedule ?
			REQSTAT_DELIVERED : SCHEDSTAT_DELIVERED;
		}
		else {
		    if (sched_data->ischedule)
			strlcpy(statbuf, (const char *) status, sizeof(statbuf));
		    else
			strlcpy(statbuf, (const char *) status, 4);
		    
		    sched_data->status = statbuf;
		}

		xmlFree(status);
		xmlFree(recip);
	    }
	}
    }
}

/* Deliver scheduling object to local recipient */
static void sched_deliver_local(const char *recipient,
				struct sched_param *sparam,
				struct sched_data *sched_data,
				struct auth_state *authstate)
{
    int r = 0, rights, reqd_privs, deliver_inbox = 0;
    const char *userid = sparam->userid, *mboxname = NULL, *attendee = NULL;
    static struct buf resource = BUF_INITIALIZER;
    static unsigned sched_count = 0;
    char namebuf[MAX_MAILBOX_BUFFER];
    struct mboxlist_entry mbentry;
    struct mailbox *mailbox = NULL, *inbox = NULL;
    struct caldav_db *caldavdb = NULL;
    struct caldav_data *cdata;
    icalcomponent *ical = NULL;
    icalproperty *prop;
    struct transaction_t txn;

    /* Check ACL of sender on recipient's Scheduling Inbox */
    caldav_mboxname(SCHED_INBOX, userid, namebuf);
    if ((r = mboxlist_lookup(namebuf, &mbentry, NULL))) {
	syslog(LOG_INFO, "mboxlist_lookup(%s) failed: %s",
	       namebuf, error_message(r));
	sched_data->status =
	    sched_data->ischedule ? REQSTAT_REJECTED : SCHEDSTAT_REJECTED;
	goto done;
    }

    reqd_privs = sched_data->is_reply ? DACL_REPLY : DACL_INVITE;
    rights =
	mbentry.acl ? cyrus_acl_myrights(authstate, mbentry.acl) : 0;
    if (!(rights & reqd_privs)) {
	sched_data->status =
	    sched_data->ischedule ? REQSTAT_NOPRIVS : SCHEDSTAT_NOPRIVS;
	goto done;
    }

    /* Open recipient's Inbox for reading */
    if ((r = mailbox_open_irl(namebuf, &inbox))) {
	syslog(LOG_ERR, "mailbox_open_irl(%s) failed: %s",
	       namebuf, error_message(r));
	sched_data->status =
	    sched_data->ischedule ? REQSTAT_TEMPFAIL : SCHEDSTAT_TEMPFAIL;
	goto done;
    }

    /* Search for iCal UID in recipient's calendars */
    caldavdb = caldav_open(userid, CALDAV_CREATE);
    if (!caldavdb) {
	sched_data->status =
	    sched_data->ischedule ? REQSTAT_TEMPFAIL : SCHEDSTAT_TEMPFAIL;
	goto done;
    }

    caldav_lookup_uid(caldavdb,
		      icalcomponent_get_uid(sched_data->itip), 0, &cdata);

    if (cdata->dav.mailbox) {
	mboxname = cdata->dav.mailbox;
	buf_setcstr(&resource, cdata->dav.resource);
    }
    else if (sched_data->is_reply) {
	/* Can't find object belonging to organizer - ignore reply */
	sched_data->status =
	    sched_data->ischedule ? REQSTAT_PERMFAIL : SCHEDSTAT_PERMFAIL;
	goto done;
    }
    else {
	/* Can't find object belonging to attendee - use default calendar */
	caldav_mboxname(SCHED_DEFAULT, userid, namebuf);
	mboxname = namebuf;
	buf_reset(&resource);
	buf_printf(&resource, "%s.ics",
		   icalcomponent_get_uid(sched_data->itip));
    }

    /* Open recipient's calendar for reading */
    if ((r = mailbox_open_irl(mboxname, &mailbox))) {
	syslog(LOG_ERR, "mailbox_open_irl(%s) failed: %s",
	       mboxname, error_message(r));
	sched_data->status =
	    sched_data->ischedule ? REQSTAT_TEMPFAIL : SCHEDSTAT_TEMPFAIL;
	goto done;
    }

    if (!cdata->dav.imap_uid) {
	/* Create new object (copy of request w/o METHOD) */
	ical = icalcomponent_new_clone(sched_data->itip);

	prop = icalcomponent_get_first_property(ical, ICAL_METHOD_PROPERTY);
	icalcomponent_remove_property(ical, prop);
	icalproperty_free(prop);

	deliver_inbox = 1;
    }
    else {
	/* Update existing object */
	struct index_record record;
	const char *msg_base = NULL;
	unsigned long msg_size = 0;
	icalcomponent *comp;
	icalcomponent_kind kind;
	icalproperty_method method;

	/* Load message containing the resource and parse iCal data */
	mailbox_find_index_record(mailbox, cdata->dav.imap_uid, &record);
	mailbox_map_message(mailbox, record.uid, &msg_base, &msg_size);
	ical = icalparser_parse_string(msg_base + record.header_size);
	mailbox_unmap_message(mailbox, record.uid, &msg_base, &msg_size);

	/* Get component type */
	comp = icalcomponent_get_first_real_component(ical);
	kind = icalcomponent_isa(comp);

	/* Get METHOD of the iTIP message */
	method = icalcomponent_get_method(sched_data->itip);

	switch (method) {
	case ICAL_METHOD_CANCEL:
	    /* Set STATUS:CANCELLED on all components */
	    do {
		icalcomponent_set_status(comp, ICAL_STATUS_CANCELLED);
		icalcomponent_set_sequence(comp,
					   icalcomponent_get_sequence(comp)+1);
	    } while ((comp = icalcomponent_get_next_component(ical, kind)));

	    deliver_inbox = 1;

	    break;

	case ICAL_METHOD_REPLY: {
	    struct hash_table comp_table;
	    icalcomponent *itip;
	    icalproperty *att;
	    icalparameter *param;
	    icalparameter_partstat partstat;
	    icalparameter_rsvp rsvp = ICAL_RSVP_NONE;
	    const char *recurid, *req_stat = SCHEDSTAT_SUCCESS;

	    /* Add each component of old object to hash table for comparison */
	    construct_hash_table(&comp_table, 10, 1);
	    comp = icalcomponent_get_first_real_component(ical);
	    do {
		prop =
		    icalcomponent_get_first_property(comp,
						     ICAL_RECURRENCEID_PROPERTY);
		if (prop) recurid = icalproperty_get_value_as_string(prop);
		else recurid = "";

		hash_insert(recurid, comp, &comp_table);

	    } while ((comp = icalcomponent_get_next_component(ical, kind)));

	    /* Process each component in the iTIP reply */
	    itip = icalcomponent_get_first_component(sched_data->itip, kind);
	    do {
		/* Lookup this comp in the hash table */
		prop =
		    icalcomponent_get_first_property(itip,
						     ICAL_RECURRENCEID_PROPERTY);
		if (prop) recurid = icalproperty_get_value_as_string(prop);
		else recurid = "";

		comp = hash_lookup(recurid, &comp_table);
		if (!comp) {
		    /* New recurrence overridden by attendee.
		       Create a new recurrence from master component. */
		    comp =
			icalcomponent_new_clone(hash_lookup("", &comp_table));

		    /* Add RECURRENCE-ID */
		    icalcomponent_add_property(comp,
					       icalproperty_new_clone(prop));

		    /* Remove RRULE */
		    prop =
			icalcomponent_get_first_property(comp,
							 ICAL_RRULE_PROPERTY);
		    if (prop) {
			icalcomponent_remove_property(comp, prop);
			icalproperty_free(prop);
		    }

		    /* Replace DTSTART, DTEND, SEQUENCE */
		    prop =
			icalcomponent_get_first_property(comp,
							 ICAL_DTSTART_PROPERTY);
		    if (prop) {
			icalcomponent_remove_property(comp, prop);
			icalproperty_free(prop);
		    }
		    prop =
			icalcomponent_get_first_property(itip,
							 ICAL_DTSTART_PROPERTY);
		    if (prop)
			icalcomponent_add_property(comp,
						   icalproperty_new_clone(prop));

		    prop =
			icalcomponent_get_first_property(comp,
							 ICAL_DTEND_PROPERTY);
		    if (prop) {
			icalcomponent_remove_property(comp, prop);
			icalproperty_free(prop);
		    }
		    prop =
			icalcomponent_get_first_property(itip,
							 ICAL_DTEND_PROPERTY);
		    if (prop)
			icalcomponent_add_property(comp,
						   icalproperty_new_clone(prop));

		    prop =
			icalcomponent_get_first_property(comp,
							 ICAL_SEQUENCE_PROPERTY);
		    if (prop) {
			icalcomponent_remove_property(comp, prop);
			icalproperty_free(prop);
		    }
		    prop =
			icalcomponent_get_first_property(itip,
							 ICAL_SEQUENCE_PROPERTY);
		    if (prop)
			icalcomponent_add_property(comp,
						   icalproperty_new_clone(prop));

		    icalcomponent_add_component(ical, comp);
		}

		/* Get the sending attendee */
		att = icalcomponent_get_first_property(itip,
						       ICAL_ATTENDEE_PROPERTY);
		attendee = icalproperty_get_attendee(att);
		param =
		    icalproperty_get_first_parameter(att,
						     ICAL_PARTSTAT_PARAMETER);
		partstat = icalparameter_get_partstat(param);
		param =
		    icalproperty_get_first_parameter(att,
						     ICAL_RSVP_PARAMETER);
		if (param) rsvp = icalparameter_get_rsvp(param);

		prop =
		    icalcomponent_get_first_property(itip,
						     ICAL_REQUESTSTATUS_PROPERTY);
		if (prop) {
		    struct icalreqstattype rq =
			icalproperty_get_requeststatus(prop);
		    req_stat =
			icalenum_reqstat_code(rq.code);
		}

		/* Find matching attendee in existing object */
		for (prop =
			 icalcomponent_get_first_property(comp,
							  ICAL_ATTENDEE_PROPERTY);
		     prop && strcmp(attendee, icalproperty_get_attendee(prop));
		     prop =
			 icalcomponent_get_next_property(comp,
							 ICAL_ATTENDEE_PROPERTY));
		if (!prop) {
		    /* Attendee added themselves to this recurrence */
		    prop = icalproperty_new_clone(att);
		    icalcomponent_add_property(comp, prop);
		}

		/* Find and set PARTSTAT */
		param =
		    icalproperty_get_first_parameter(prop,
						     ICAL_PARTSTAT_PARAMETER);
		if (!param) {
		    param = icalparameter_new(ICAL_PARTSTAT_PARAMETER);
		    icalproperty_add_parameter(prop, param);
		}
		icalparameter_set_partstat(param, partstat);

		/* Find and set RSVP */
		param =
		    icalproperty_get_first_parameter(prop,
						     ICAL_RSVP_PARAMETER);
		if (param) icalproperty_remove_parameter_by_ref(prop, param);
		if (rsvp != ICAL_RSVP_NONE) {
		    param = icalparameter_new(ICAL_RSVP_PARAMETER);
		    icalproperty_add_parameter(prop, param);
		    icalparameter_set_rsvp(param, rsvp);
		}

		/* Find and set SCHEDULE-STATUS */
		for (param =
			 icalproperty_get_first_parameter(prop,
							  ICAL_IANA_PARAMETER);
		     param && strcmp(icalparameter_get_iana_name(param),
				     "SCHEDULE-STATUS");
		     param =
			 icalproperty_get_next_parameter(prop,
							 ICAL_IANA_PARAMETER));
		if (!param) {
		    param = icalparameter_new(ICAL_IANA_PARAMETER);
		    icalproperty_add_parameter(prop, param);
		    icalparameter_set_iana_name(param, "SCHEDULE-STATUS");
		}
		icalparameter_set_iana_value(param, req_stat);

	    } while ((itip = icalcomponent_get_next_component(sched_data->itip,
							      kind)));

	    free_hash_table(&comp_table, NULL);

	    deliver_inbox = 1;

	    break;
	}

	case ICAL_METHOD_REQUEST: {
	    struct hash_table comp_table;
	    icalcomponent *itip;
	    const char *tzid, *recurid;

	    /* Add each VTIMEZONE of old object to hash table for comparison */
	    construct_hash_table(&comp_table, 10, 1);
	    for (comp = icalcomponent_get_first_component(ical,
							  ICAL_VTIMEZONE_COMPONENT);
		 comp;
		 comp =
		     icalcomponent_get_next_component(ical,
						      ICAL_VTIMEZONE_COMPONENT)) {
		prop =
		    icalcomponent_get_first_property(comp, ICAL_TZID_PROPERTY);
		tzid = icalproperty_get_tzid(prop);

		hash_insert(tzid, comp, &comp_table);
	    }

	    /* Process each VTIMEZONE in the iTIP request */
	    for (itip =
		     icalcomponent_get_first_component(sched_data->itip,
						       ICAL_VTIMEZONE_COMPONENT);
		 itip;
		 itip =
		     icalcomponent_get_next_component(sched_data->itip,
						      ICAL_VTIMEZONE_COMPONENT)) {
		/* Lookup this TZID in the hash table */
		prop =
		    icalcomponent_get_first_property(itip,
						     ICAL_TZID_PROPERTY);
		tzid = icalproperty_get_tzid(prop);

		comp = hash_lookup(tzid, &comp_table);
		if (comp) {
		    /* Remove component from old object */
		    icalcomponent_remove_component(ical, comp);
		    icalcomponent_free(comp);
		}

		/* Add new/modified component from iTIP request*/
		icalcomponent_add_component(ical,
					    icalcomponent_new_clone(itip));
	    }

	    free_hash_table(&comp_table, NULL);

	    /* Add each component of old object to hash table for comparison */
	    construct_hash_table(&comp_table, 10, 1);
	    comp = icalcomponent_get_first_real_component(ical);
	    do {
		prop =
		    icalcomponent_get_first_property(comp,
						     ICAL_RECURRENCEID_PROPERTY);
		if (prop) recurid = icalproperty_get_value_as_string(prop);
		else recurid = "";

		hash_insert(recurid, comp, &comp_table);

	    } while ((comp = icalcomponent_get_next_component(ical, kind)));

	    /* Process each component in the iTIP request */
	    itip = icalcomponent_get_first_component(sched_data->itip, kind);
	    do {
		icalcomponent *new_comp = icalcomponent_new_clone(itip);

		/* Lookup this comp in the hash table */
		prop =
		    icalcomponent_get_first_property(itip,
						     ICAL_RECURRENCEID_PROPERTY);
		if (prop) recurid = icalproperty_get_value_as_string(prop);
		else recurid = "";

		comp = hash_lookup(recurid, &comp_table);
		if (comp) {
		    int old_seq, new_seq;
		    icalparameter *param;

		    /* Check if this is something more than an update */
		    /* XXX  Probably need to check PARTSTAT=NEEDS-ACTION
		            and RSVP=TRUE as well */
		    old_seq = icalcomponent_get_sequence(comp);
		    new_seq = icalcomponent_get_sequence(itip);
		    if (new_seq > old_seq) deliver_inbox = 1;

		    /* Copy over any COMPLETED, PERCENT-COMPLETE,
		       or TRANSP properties */
		    prop =
			icalcomponent_get_first_property(comp,
							 ICAL_COMPLETED_PROPERTY);
		    if (prop) {
			icalcomponent_add_property(new_comp,
						   icalproperty_new_clone(prop));
		    }
		    prop =
			icalcomponent_get_first_property(comp,
							 ICAL_PERCENTCOMPLETE_PROPERTY);
		    if (prop) {
			icalcomponent_add_property(new_comp,
						   icalproperty_new_clone(prop));
		    }
		    prop =
			icalcomponent_get_first_property(comp,
							 ICAL_TRANSP_PROPERTY);
		    if (prop) {
			icalcomponent_add_property(new_comp,
						   icalproperty_new_clone(prop));
		    }

		    /* Copy over any ORGANIZER;SCHEDULE-STATUS */
		    /* XXX  Do we only do this iff PARTSTAT!=NEEDS-ACTION */
		    prop =
			icalcomponent_get_first_property(comp,
							 ICAL_ORGANIZER_PROPERTY);
		    for (param =
			   icalproperty_get_first_parameter(prop,
							    ICAL_IANA_PARAMETER);
			 param;
			 param =
			   icalproperty_get_next_parameter(prop,
							   ICAL_IANA_PARAMETER)) {
			if (!strcmp(icalparameter_get_iana_name(param),
				    "SCHEDULE-STATUS")) {
			    const char *sched_stat =
				icalparameter_get_iana_value(param);

			    prop =
				icalcomponent_get_first_property(new_comp,
								 ICAL_ORGANIZER_PROPERTY);
			    param = icalparameter_new(ICAL_IANA_PARAMETER);
			    icalproperty_add_parameter(prop, param);
			    icalparameter_set_iana_name(param,
							"SCHEDULE-STATUS");
			    icalparameter_set_iana_value(param, sched_stat);
			}
		    }

		    /* Remove component from old object */
		    icalcomponent_remove_component(ical, comp);
		    icalcomponent_free(comp);
		}
		else deliver_inbox = 1;

		/* Add new/modified component from iTIP request*/
		icalcomponent_add_component(ical, new_comp);

	    } while ((itip = icalcomponent_get_next_component(sched_data->itip,
							      kind)));

	    free_hash_table(&comp_table, NULL);

	    break;
	}

	default:
	    /* Unknown METHOD -- ignore it */
	    syslog(LOG_ERR, "Unknown iTIP method: %s",
		   icalenum_method_to_string(method));
	    goto inbox;
	}
    }

    /* Store the (updated) object in the recipients's calendar */
    mailbox_unlock_index(mailbox, NULL);

    r = store_resource(&txn, ical, mailbox, buf_cstring(&resource),
		       caldavdb, OVERWRITE_YES, NEW_STAG);

    if (r == HTTP_CREATED || r == HTTP_NO_CONTENT) {
	sched_data->status =
	    sched_data->ischedule ? REQSTAT_SUCCESS : SCHEDSTAT_DELIVERED;
    }
    else {
	syslog(LOG_ERR, "store_resource(%s) failed: %s (%s)",
	       mailbox->name, error_message(r), txn.error.resource);
	sched_data->status =
	    sched_data->ischedule ? REQSTAT_TEMPFAIL : SCHEDSTAT_TEMPFAIL;
	goto done;
    }

  inbox:
    if (deliver_inbox) {
	/* Create a name for the new iTIP message resource */
	buf_reset(&resource);
	buf_printf(&resource, "%x-%d-%ld-%u.ics",
		   strhash(icalcomponent_get_uid(sched_data->itip)), getpid(),
		   time(0), sched_count++);

	/* Store the message in the recipient's Inbox */
	mailbox_unlock_index(inbox, NULL);

	r = store_resource(&txn, sched_data->itip, inbox,
			   buf_cstring(&resource), caldavdb, OVERWRITE_NO, 0);
	/* XXX  What do we do if storing to Inbox fails? */
    }

    /* XXX  Should this be a config option? - it might have perf implications */
    if (sched_data->is_reply) {
	/* Send updates to attendees */
	sched_request(recipient, sparam, NULL, ical, attendee);
    }

  done:
    if (ical) icalcomponent_free(ical);
    if (inbox) {
	mailbox_unlock_index(inbox, NULL);
	mailbox_close(&inbox);
    }
    if (mailbox) mailbox_close(&mailbox);
    if (caldavdb) caldav_close(caldavdb);
}


/* Deliver scheduling object to recipient's Inbox */
void sched_deliver(const char *recipient, void *data, void *rock)
{
    struct sched_data *sched_data = (struct sched_data *) data;
    struct auth_state *authstate = (struct auth_state *) rock;
    struct sched_param sparam;

    /* Check SCHEDULE-FORCE-SEND value */
    if (sched_data->force_send) {
	const char *force = sched_data->is_reply ? "REPLY" : "REQUEST";

	if (strcmp(sched_data->force_send, force)) {
	    sched_data->status = SCHEDSTAT_PARAM;
	    return;
	}
    }

    if (caladdress_lookup(recipient, &sparam)) {
	sched_data->status =
	    sched_data->ischedule ? REQSTAT_NOUSER : SCHEDSTAT_NOUSER;
	/* Unknown user */
	return;
    }

    if (sparam.flags) {
	/* Remote recipient */
	sched_deliver_remote(recipient, &sparam, sched_data);
    }
    else {
	/* Local recipient */
	sched_deliver_local(recipient, &sparam, sched_data, authstate);
    }
}


struct comp_data {
    icalcomponent *comp;
    icalparameter_partstat partstat;
    int sequence;
};

static void free_comp_data(void *data) {
    struct comp_data *comp_data = (struct comp_data *) data;

    if (comp_data) {
	if (comp_data->comp) icalcomponent_free(comp_data->comp);
	free(comp_data);
    }
}


/*
 * sched_request/reply() helper function
 *
 * Update DTSTAMP, remove VALARMs,
 * optionally remove scheduling params from ORGANIZER
 */
static void clean_component(icalcomponent *comp, int clean_org)
{
    icalcomponent *alarm, *next;
    icalproperty *prop;
    icaltimezone *utc = icaltimezone_get_utc_timezone();
    time_t now = time(NULL);

    /* Replace DTSTAMP on component */
    prop = icalcomponent_get_first_property(comp,
					    ICAL_DTSTAMP_PROPERTY);
    icalcomponent_remove_property(comp, prop);
    icalproperty_free(prop);
    prop =
	icalproperty_new_dtstamp(icaltime_from_timet_with_zone(now, 0, utc));
    icalcomponent_add_property(comp, prop);

    /* Remove any VALARM components */
    for (alarm = icalcomponent_get_first_component(comp, ICAL_VALARM_COMPONENT);
	 alarm; alarm = next) {
	next = icalcomponent_get_next_component(comp, ICAL_VALARM_COMPONENT);
	icalcomponent_remove_component(comp, alarm);
	icalcomponent_free(alarm);
    }

    if (clean_org) {
	icalparameter *param, *next;

	/* Grab the organizer */
	prop = icalcomponent_get_first_property(comp,
						ICAL_ORGANIZER_PROPERTY);

	/* Remove CalDAV Scheduling parameters from organizer */
	for (param =
		 icalproperty_get_first_parameter(prop, ICAL_IANA_PARAMETER);
	     param; param = next) {
	    next = icalproperty_get_next_parameter(prop, ICAL_IANA_PARAMETER);

	    if (!strcmp(icalparameter_get_iana_name(param),
			"SCHEDULE-AGENT")) {
		icalproperty_remove_parameter_by_ref(prop, param);
	    }
	    else if (!strcmp(icalparameter_get_iana_name(param),
			     "SCHEDULE-FORCE-SEND")) {
		icalproperty_remove_parameter_by_ref(prop, param);
	    }
	}
    }
}


/*
 * sched_request() helper function
 *
 * Add EXDATE to master component if attendee is excluded from recurrence
 */
struct exclude_rock {
    unsigned ncomp;
    icalcomponent *comp;
};

static void sched_exclude(const char *attendee __attribute__((unused)),
			  void *data, void *rock)
{
    struct sched_data *sched_data = (struct sched_data *) data;
    struct exclude_rock *erock = (struct exclude_rock *) rock;

    if (!(sched_data->comp_mask & (1<<erock->ncomp))) {
	icalproperty *recurid, *exdate;
	struct icaltimetype exdt;
	icalparameter *param;

	/* Fetch the RECURRENCE-ID and use it to create a new EXDATE */
	recurid = icalcomponent_get_first_property(erock->comp,
						   ICAL_RECURRENCEID_PROPERTY);
	exdt = icalproperty_get_recurrenceid(recurid);

	exdate = icalproperty_new_exdate(exdt);

	/* Copy any parameters from RECURRENCE-ID to EXDATE */
	param = icalproperty_get_first_parameter(recurid, ICAL_TZID_PARAMETER);
	if (param) {
	    icalproperty_add_parameter(exdate, icalparameter_new_clone(param));
	}
	param = icalproperty_get_first_parameter(recurid, ICAL_VALUE_PARAMETER);
	if (param) {
	    icalproperty_add_parameter(exdate, icalparameter_new_clone(param));
	}
	/* XXX  Need to handle RANGE parameter */

	/* Add the EXDATE to the master component for this attendee */
	icalcomponent_add_property(sched_data->master, exdate);
    }
}


/*
 * sched_request() helper function
 *
 * Process all attendees in the given component and add a 
 * properly modified component to the attendee's iTIP request if necessary
 */
static void process_attendees(icalcomponent *comp, unsigned ncomp,
			      const char *organizer, const char *att_update,
			      struct hash_table *att_table,
			      icalcomponent *itip, unsigned needs_action)
{
    icalcomponent *copy;
    icalproperty *prop;
    icalparameter *param, *next;

    /* Strip SCHEDULE-STATUS from each attendee
       and optionally set PROPSTAT=NEEDS-ACTION */
    for (prop = icalcomponent_get_first_property(comp, ICAL_ATTENDEE_PROPERTY);
	 prop;
	 prop = icalcomponent_get_next_property(comp, ICAL_ATTENDEE_PROPERTY)) {
	const char *attendee = icalproperty_get_attendee(prop);

	/* Don't modify attendee == organizer */
	if (!strcmp(attendee, organizer)) continue;

	for (param =
		 icalproperty_get_first_parameter(prop, ICAL_IANA_PARAMETER);
	     param; param = next) {
	    next = icalproperty_get_next_parameter(prop, ICAL_IANA_PARAMETER);

	    if (!strcmp(icalparameter_get_iana_name(param),
			     "SCHEDULE-STATUS")) {
		icalproperty_remove_parameter_by_ref(prop, param);
	    }
	}

	if (needs_action) {
	    param =
		icalproperty_get_first_parameter(prop, ICAL_PARTSTAT_PARAMETER);
	    if (!param) {
		param = icalparameter_new(ICAL_PARTSTAT_PARAMETER);
		icalproperty_add_parameter(prop, param);
	    }
	    icalparameter_set_partstat(param, ICAL_PARTSTAT_NEEDSACTION);
	}
    }

    /* Clone a working copy of the component */
    copy = icalcomponent_new_clone(comp);

    clean_component(copy, 0);

    /* Process each attendee */
    for (prop = icalcomponent_get_first_property(copy, ICAL_ATTENDEE_PROPERTY);
	 prop;
	 prop = icalcomponent_get_next_property(copy, ICAL_ATTENDEE_PROPERTY)) {
	const char *attendee = icalproperty_get_attendee(prop);
	unsigned do_sched = 1;
	icalparameter *force_send = NULL;

	/* Don't schedule attendee == organizer */
	if (!strcmp(attendee, organizer)) continue;

	/* Don't send an update to the attendee that just sent a reply */
	if (att_update && !strcmp(attendee, att_update)) continue;

	/* Check CalDAV Scheduling parameters */
	for (param =
		 icalproperty_get_first_parameter(prop, ICAL_IANA_PARAMETER);
	     param; param = next) {
	    next = icalproperty_get_next_parameter(prop, ICAL_IANA_PARAMETER);

	    if (!strcmp(icalparameter_get_iana_name(param),
			"SCHEDULE-AGENT")) {
		do_sched =
		    !strcmp(icalparameter_get_iana_value(param), "SERVER");
		icalproperty_remove_parameter_by_ref(prop, param);
	    }
	    else if (!strcmp(icalparameter_get_iana_name(param),
			     "SCHEDULE-FORCE-SEND")) {
		force_send = param;
	    }
	}

	/* Create/update iTIP request for this attendee */
	if (do_sched) {
	    struct sched_data *sched_data;
	    icalcomponent *new_comp;

	    sched_data = hash_lookup(attendee, att_table);
	    if (!sched_data) {
		/* New attendee - add it to the hash table */
		sched_data = xzmalloc(sizeof(struct sched_data));
		sched_data->itip = icalcomponent_new_clone(itip);
		if (force_send) {
		    sched_data->force_send =
			xstrdup(icalparameter_get_iana_value(force_send));
		}
		hash_insert(attendee, sched_data, att_table);
	    }
	    new_comp = icalcomponent_new_clone(copy);
	    icalcomponent_add_component(sched_data->itip, new_comp);
	    sched_data->comp_mask |= (1 << ncomp);

	    /* XXX  We assume that the master component is always first */
	    if (!ncomp) sched_data->master = new_comp;
	}

	if (force_send) icalproperty_remove_parameter_by_ref(prop, force_send);
    }

    /* XXX  We assume that the master component is always first */
    if (ncomp) {
	/* Handle attendees that are excluded from this recurrence */
	struct exclude_rock erock = { ncomp, copy };

	hash_enumerate(att_table, sched_exclude, &erock);
    }

    icalcomponent_free(copy);
}


/*
 * sched_request() helper function
 *
 * Organizer removed this component, mark it as cancelled for all attendees
 */
struct cancel_rock {
    const char *organizer;
    struct hash_table *att_table;
    icalcomponent *itip;
};

static void sched_cancel(const char *recurid __attribute__((unused)),
			 void *data, void *rock)
{
    struct comp_data *old_data = (struct comp_data *) data;
    struct cancel_rock *crock = (struct cancel_rock *) rock;

    /* Deleting the object -- set STATUS to CANCELLED for component */
    icalcomponent_set_status(old_data->comp, ICAL_STATUS_CANCELLED);
//    icalcomponent_set_sequence(old_data->comp, old_data->sequence+1);

    process_attendees(old_data->comp, 0, crock->organizer, NULL,
		      crock->att_table, crock->itip, 0);
}


static unsigned propcmp(icalcomponent *oldical, icalcomponent *newical,
			icalproperty_kind kind)
{
    icalproperty *oldprop, *newprop;

    oldprop = icalcomponent_get_first_property(oldical, kind);
    newprop = icalcomponent_get_first_property(newical, kind);

    if (!oldprop) {
	if (newprop) return 1;
    }
    else if (!newprop) return 1;
    else {
	/* XXX  Do something smarter based on property type */
	const char *oldstr = icalproperty_get_value_as_string(oldprop);
	const char *newstr = icalproperty_get_value_as_string(newprop);

	if (strcmp(oldstr, newstr)) return 1;
    }

    return 0;
}


/* Create and deliver an organizer scheduling request */
static void sched_request(const char *organizer, struct sched_param *sparam,
			  icalcomponent *oldical, icalcomponent *newical,
			  const char *att_update)
{
    int r, rights;
    struct mboxlist_entry mbentry;
    char outboxname[MAX_MAILBOX_BUFFER];
    icalproperty_method method;
    static struct buf prodid = BUF_INITIALIZER;
    struct auth_state *authstate;
    icalcomponent *ical, *req, *comp;
    icalproperty *prop;
    icalcomponent_kind kind;
    struct hash_table att_table, comp_table;
    const char *sched_stat = NULL, *recurid;
    struct comp_data *old_data;

    /* Check what kind of action we are dealing with */
    if (!newical) {
	/* Remove */
	ical = oldical;
	method = ICAL_METHOD_CANCEL;
    }
    else {
	/* Create / Modify */
	ical = newical;
	method = ICAL_METHOD_REQUEST;
    }

    if (!att_update) {
	/* Check ACL of auth'd user on userid's Scheduling Outbox */
	caldav_mboxname(SCHED_OUTBOX, sparam->userid, outboxname);

	if ((r = mboxlist_lookup(outboxname, &mbentry, NULL))) {
	    syslog(LOG_INFO, "mboxlist_lookup(%s) failed: %s",
		   outboxname, error_message(r));
	    mbentry.acl = NULL;
	}

	rights =
	    mbentry.acl ? cyrus_acl_myrights(httpd_authstate, mbentry.acl) : 0;
	if (!(rights & DACL_INVITE)) {
	    /* DAV:need-privileges */
	    sched_stat = SCHEDSTAT_NOPRIVS;

	    goto done;
	}
    }

    /* Create a shell for our iTIP request objects */
    if (!buf_len(&prodid)) {
	buf_printf(&prodid, "-//CyrusIMAP.org/Cyrus %s//EN", cyrus_version());
    }

    req = icalcomponent_vanew(ICAL_VCALENDAR_COMPONENT,
			      icalproperty_new_version("2.0"),
			      icalproperty_new_prodid(buf_cstring(&prodid)),
			      icalproperty_new_method(method),
			      0);

    /* XXX  Make sure SEQUENCE is incremented */

    /* Copy over any CALSCALE property */
    prop = icalcomponent_get_first_property(ical, ICAL_CALSCALE_PROPERTY);
    if (prop) {
	icalcomponent_add_property(req,
				   icalproperty_new_clone(prop));
    }

    /* Copy over any VTIMEZONE components */
    for (comp = icalcomponent_get_first_component(ical,
						  ICAL_VTIMEZONE_COMPONENT);
	 comp;
	 comp = icalcomponent_get_next_component(ical,
						 ICAL_VTIMEZONE_COMPONENT)) {
	 icalcomponent_add_component(req,
				     icalcomponent_new_clone(comp));
    }

    comp = icalcomponent_get_first_real_component(ical);
    kind = icalcomponent_isa(comp);

    /* Add each component of old object to hash table for comparison */
    construct_hash_table(&comp_table, 10, 1);

    if (oldical) {
	comp = icalcomponent_get_first_real_component(oldical);
	do {
	    old_data = xzmalloc(sizeof(struct comp_data));
	    old_data->comp = comp;
	    old_data->sequence = icalcomponent_get_sequence(comp);

	    prop = icalcomponent_get_first_property(comp,
						    ICAL_RECURRENCEID_PROPERTY);
	    if (prop) recurid = icalproperty_get_value_as_string(prop);
	    else recurid = "";

	    hash_insert(recurid, old_data, &comp_table);

	} while ((comp = icalcomponent_get_next_component(oldical, kind)));
    }

    /* Create hash table of attendees */
    construct_hash_table(&att_table, 10, 1);

    /* Process each component of new object */
    if (newical) {
	unsigned ncomp = 0;

	comp = icalcomponent_get_first_real_component(newical);
	do {
	    unsigned changed = 1, needs_action = 0;

	    prop = icalcomponent_get_first_property(comp,
						    ICAL_RECURRENCEID_PROPERTY);
	    if (prop) recurid = icalproperty_get_value_as_string(prop);
	    else recurid = "";

	    old_data = hash_del(recurid, &comp_table);

	    if (old_data) {
		/* Per RFC 6638, Section 3.2.8: We need to compare
		   DTSTART, DTEND, DURATION, DUE, RRULE, RDATE, EXDATE */
		needs_action += propcmp(old_data->comp, comp,
					ICAL_DTSTART_PROPERTY);
		needs_action += propcmp(old_data->comp, comp,
					ICAL_DTEND_PROPERTY);
		needs_action += propcmp(old_data->comp, comp,
					ICAL_DURATION_PROPERTY);
		needs_action += propcmp(old_data->comp, comp,
					ICAL_DUE_PROPERTY);
		needs_action += propcmp(old_data->comp, comp,
					ICAL_RRULE_PROPERTY);
		needs_action += propcmp(old_data->comp, comp,
					ICAL_RDATE_PROPERTY);
		needs_action += propcmp(old_data->comp, comp,
					ICAL_EXDATE_PROPERTY);

		if (old_data->sequence >= icalcomponent_get_sequence(comp)) {
		    /* Make sure SEQUENCE is set properly */
		    if (!needs_action) changed = 0;

		    icalcomponent_set_sequence(comp,
					       old_data->sequence + changed);
		}

		free(old_data);
	    }

	    if (changed) {
		/* Process all attendees in created/modified components */
		process_attendees(comp, ncomp++, organizer, att_update,
				  &att_table, req, needs_action);
	    }

	} while ((comp = icalcomponent_get_next_component(newical, kind)));
    }

    if (oldical) {
	/* Cancel any components that have been left behind in the old obj */
	struct cancel_rock crock = { organizer, &att_table, req };

	hash_enumerate(&comp_table, sched_cancel, &crock);
    }
    free_hash_table(&comp_table, free);

    icalcomponent_free(req);

    /* Attempt to deliver requests to attendees */
    /* XXX  Do we need to do more checks here? */
    if (sparam->flags & SCHEDTYPE_REMOTE)
	authstate = auth_newstate("anonymous");
    else
	authstate = auth_newstate(sparam->userid);

    hash_enumerate(&att_table, sched_deliver, authstate);
    auth_freestate(authstate);

  done:
    if (newical) {
	unsigned ncomp = 0;

	/* Set SCHEDULE-STATUS for each attendee in organizer object */
	comp = icalcomponent_get_first_real_component(newical);
	kind = icalcomponent_isa(comp);

	do {
	    for (prop =
		     icalcomponent_get_first_property(comp, ICAL_ATTENDEE_PROPERTY);
		 prop;
		 prop =
		     icalcomponent_get_next_property(comp, ICAL_ATTENDEE_PROPERTY)) {
		const char *attendee = icalproperty_get_attendee(prop);
		const char *stat = NULL;

		/* Don't set status if attendee == organizer */
		if (!strcmp(attendee, organizer)) continue;

		if (sched_stat) stat = sched_stat;
		else {
		    struct sched_data *sched_data;

		    sched_data = hash_lookup(attendee, &att_table);
		    if (sched_data && (sched_data->comp_mask & (1 << ncomp)))
			stat = sched_data->status;
		}

		if (stat) {
		    icalparameter *param;
		    for (param =
			     icalproperty_get_first_parameter(prop,
							      ICAL_IANA_PARAMETER);
			 param && strcmp(icalparameter_get_iana_name(param),
					 "SCHEDULE-STATUS");
			 param =
			     icalproperty_get_next_parameter(prop,
							     ICAL_IANA_PARAMETER));
		    if (!param) {
			param = icalparameter_new(ICAL_IANA_PARAMETER);
			icalproperty_add_parameter(prop, param);
			icalparameter_set_iana_name(param, "SCHEDULE-STATUS");
		    }
		    icalparameter_set_iana_value(param, stat);
		}
	    }

	    ncomp++;
	} while ((comp = icalcomponent_get_next_component(newical, kind)));
    }

    /* Cleanup */
    if (!sched_stat) free_hash_table(&att_table, free_sched_data);
}


/*
 * sched_reply() helper function
 *
 * Remove all attendees from 'comp' other than the one corresponding to 'userid'
 *
 * Returns the new trimmed component (must be freed by caller)
 * Optionally returns the 'attendee' property, his/her 'propstat',
 * and the 'recurid' of the component
 */
static icalcomponent *trim_attendees(icalcomponent *comp, const char *userid,
				     icalproperty **attendee,
				     icalparameter_partstat *partstat,
				     const char **recurid)
{
    icalcomponent *copy;
    icalproperty *prop, *nextprop, *myattendee = NULL;

    if (partstat) *partstat = ICAL_PARTSTAT_NONE;

    /* Clone a working copy of the component */
    copy = icalcomponent_new_clone(comp);

    /* Locate userid in the attendee list (stripping others) */
    for (prop = icalcomponent_get_first_property(copy,
						 ICAL_ATTENDEE_PROPERTY);
	 prop;
	 prop = nextprop) {
	const char *att = icalproperty_get_attendee(prop);
	struct sched_param sparam;

	nextprop = icalcomponent_get_next_property(copy,
						   ICAL_ATTENDEE_PROPERTY);

	if (!myattendee &&
	    !caladdress_lookup(att, &sparam) &&
	    !(sparam.flags & SCHEDTYPE_REMOTE) &&
	    !strcmp(sparam.userid, userid)) {
	    /* Found it */
	    myattendee = prop;

	    if (partstat) {
		/* Get the PARTSTAT */
		icalparameter *param = 
		    icalproperty_get_first_parameter(myattendee,
						     ICAL_PARTSTAT_PARAMETER);
		if (param) *partstat = icalparameter_get_partstat(param);
	    }
	}
	else {
	    /* Some other attendee, remove it */
	    icalcomponent_remove_property(copy, prop);
	    icalproperty_free(prop);
	}
    }

    if (attendee) *attendee = myattendee;

    if (recurid) {
	prop = icalcomponent_get_first_property(copy,
						ICAL_RECURRENCEID_PROPERTY);
	if (prop) *recurid = icalproperty_get_value_as_string(prop);
	else *recurid = "";
    }

    return copy;
}


/*
 * sched_reply() helper function
 *
 * Attendee removed this component, mark it as declined for the organizer.
 */
static void sched_decline(const char *recurid __attribute__((unused)),
			  void *data, void *rock)
{
    struct comp_data *old_data = (struct comp_data *) data;
    icalcomponent *itip = (icalcomponent *) rock;
    icalproperty *myattendee;
    icalparameter *param;

    /* Don't send a decline for cancelled components */
    if (icalcomponent_get_status(old_data->comp) == ICAL_STATUS_CANCELLED)
	return;

    myattendee = icalcomponent_get_first_property(old_data->comp,
						  ICAL_ATTENDEE_PROPERTY);

    param =
	icalproperty_get_first_parameter(myattendee,
					 ICAL_PARTSTAT_PARAMETER);
    if (!param) {
	param = icalparameter_new(ICAL_PARTSTAT_PARAMETER);
	icalproperty_add_parameter(myattendee, param);
    }
    icalparameter_set_partstat(param, ICAL_PARTSTAT_DECLINED);

    clean_component(old_data->comp, 1);

    icalcomponent_add_component(itip, old_data->comp);
}


/* Create and deliver an attendee scheduling reply */
static void sched_reply(const char *userid,
			icalcomponent *oldical, icalcomponent *newical)
{
    int r, rights;
    struct mboxlist_entry mbentry;
    char outboxname[MAX_MAILBOX_BUFFER];
    icalcomponent *ical;
    static struct buf prodid = BUF_INITIALIZER;
    struct sched_data *sched_data;
    struct auth_state *authstate;
    icalcomponent *comp;
    icalproperty *prop;
    icalparameter *param, *force_send = NULL;
    icalcomponent_kind kind;
    const char *organizer, *recurid;
    struct hash_table comp_table;
    struct comp_data *old_data;

    /* Check what kind of action we are dealing with */
    if (!newical) {
	/* Remove */
	ical = oldical;
    }
    else {
	/* Create / Modify */
	ical = newical;
    }

    /* Check CalDAV Scheduling parameters on the organizer */
    comp = icalcomponent_get_first_real_component(ical);
    kind = icalcomponent_isa(comp);
    prop = icalcomponent_get_first_property(comp, ICAL_ORGANIZER_PROPERTY);
    organizer = icalproperty_get_organizer(prop);

    for (param = icalproperty_get_first_parameter(prop,
						  ICAL_IANA_PARAMETER);
	 param;
	 param = icalproperty_get_next_parameter(prop,
						 ICAL_IANA_PARAMETER)) {
	if (!strcmp(icalparameter_get_iana_name(param),
		    "SCHEDULE-AGENT")) {
	    if (strcmp(icalparameter_get_iana_value(param), "SERVER")) {
		/* We are not supposed to send replies to the organizer */
		return;
	    }
	}
	else if (!strcmp(icalparameter_get_iana_name(param),
			 "SCHEDULE-FORCE-SEND")) {
	    force_send = param;
	}
    }

    sched_data = xzmalloc(sizeof(struct sched_data));
    sched_data->is_reply = 1;
    if (force_send) {
	sched_data->force_send =
	    xstrdup(icalparameter_get_iana_value(force_send));
    }

    /* Check ACL of auth'd user on userid's Scheduling Outbox */
    caldav_mboxname(SCHED_OUTBOX, userid, outboxname);

    if ((r = mboxlist_lookup(outboxname, &mbentry, NULL))) {
	syslog(LOG_INFO, "mboxlist_lookup(%s) failed: %s",
	       outboxname, error_message(r));
	mbentry.acl = NULL;
    }

    rights =
	mbentry.acl ? cyrus_acl_myrights(httpd_authstate, mbentry.acl) : 0;
    if (!(rights & DACL_REPLY)) {
	/* DAV:need-privileges */
	if (newical) sched_data->status = SCHEDSTAT_NOPRIVS;

	goto done;
    }

    /* Create our reply iCal object */
    if (!buf_len(&prodid)) {
	buf_printf(&prodid, "-//CyrusIMAP.org/Cyrus %s//EN", cyrus_version());
    }

    sched_data->itip =
	icalcomponent_vanew(ICAL_VCALENDAR_COMPONENT,
			    icalproperty_new_version("2.0"),
			    icalproperty_new_prodid(buf_cstring(&prodid)),
			    icalproperty_new_method(ICAL_METHOD_REPLY),
			    0);

    /* XXX  Make sure SEQUENCE is incremented */

    /* Copy over any CALSCALE property */
    prop = icalcomponent_get_first_property(ical, ICAL_CALSCALE_PROPERTY);
    if (prop) {
	icalcomponent_add_property(sched_data->itip,
				   icalproperty_new_clone(prop));
    }

    /* Copy over any VTIMEZONE components */
    for (comp = icalcomponent_get_first_component(ical,
						  ICAL_VTIMEZONE_COMPONENT);
	 comp;
	 comp = icalcomponent_get_next_component(ical,
						 ICAL_VTIMEZONE_COMPONENT)) {
	 icalcomponent_add_component(sched_data->itip,
				     icalcomponent_new_clone(comp));
    }

    /* Add each component of old object to hash table for comparison */
    construct_hash_table(&comp_table, 10, 1);

    if (oldical) {
	comp = icalcomponent_get_first_real_component(oldical);
	do {
	    old_data = xzmalloc(sizeof(struct comp_data));

	    old_data->comp = trim_attendees(comp, userid, NULL,
					    &old_data->partstat, &recurid);

	    hash_insert(recurid, old_data, &comp_table);

	} while ((comp = icalcomponent_get_next_component(oldical, kind)));
    }

    /* Process each component of new object */
    if (newical) {
	unsigned ncomp = 0;

	comp = icalcomponent_get_first_real_component(newical);
	do {
	    icalcomponent *copy;
	    icalproperty *myattendee;
	    icalparameter_partstat partstat;
	    int changed = 1;

	    copy = trim_attendees(comp, userid,
				  &myattendee, &partstat, &recurid);
	    if (myattendee) {
		/* Found our userid */
		old_data = hash_del(recurid, &comp_table);

		if (old_data) {
		    /* XXX  Need to check EXDATE */

		    /* Compare PARTSTAT in the two components */
		    if (old_data->partstat == partstat) {
			changed = 0;
		    }

		    free_comp_data(old_data);
		}
	    }
	    else {
		/* Our user isn't in this component */
		/* XXX  Can this actually happen? */
		changed = 0;
	    }

	    if (changed) {
		clean_component(copy, 1);

		icalcomponent_add_component(sched_data->itip, copy);
		sched_data->comp_mask |= (1 << ncomp);
	    }
	    else icalcomponent_free(copy);

	    ncomp++;
	} while ((comp = icalcomponent_get_next_component(newical, kind)));
    }

    /* Decline any components that have been left behind in the old obj */
    hash_enumerate(&comp_table, sched_decline, sched_data->itip);
    free_hash_table(&comp_table, free_comp_data);

  done:
    if (sched_data->itip &&
	icalcomponent_get_first_real_component(sched_data->itip)) {
	/* We built a reply object */

	if (!sched_data->status) {
	    /* Attempt to deliver reply to organizer */
	    authstate = auth_newstate(userid);
	    sched_deliver(organizer, sched_data, authstate);
	    auth_freestate(authstate);
	}

	if (newical) {
	    unsigned ncomp = 0;

	    /* Set SCHEDULE-STATUS for organizer in attendee object */
	    comp = icalcomponent_get_first_real_component(newical);
	    do {
		if (sched_data->comp_mask & (1 << ncomp)) {
		    prop =
			icalcomponent_get_first_property(comp,
							 ICAL_ORGANIZER_PROPERTY);
		    param = icalparameter_new(ICAL_IANA_PARAMETER);
		    icalparameter_set_iana_name(param, "SCHEDULE-STATUS");
		    icalparameter_set_iana_value(param, sched_data->status);
		    icalproperty_add_parameter(prop, param);
		}

		ncomp++;
	    } while ((comp = icalcomponent_get_next_component(newical, kind)));
	}
    }

    /* Cleanup */
    free_sched_data(sched_data);
}
