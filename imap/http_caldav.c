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
 *   - Use XML precondition error codes
 *   - Add WebDAV LOCKing?  Does anybody use it?
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
#include "http_dav.h"
#include "http_err.h"
#include "http_proxy.h"
#include "imap_err.h"
#include "index.h"
#include "mailbox.h"
#include "mboxlist.h"
#include "message.h"
#include "message_guid.h"
#include "proxy.h"
#include "rfc822date.h"
#include "smtpclient.h"
#include "spool.h"
#include "stristr.h"
#include "util.h"
#include "version.h"
#include "xmalloc.h"
#include "xstrlcat.h"
#include "xstrlcpy.h"

#define NEW_STAG (1<<8)  /* Make sure we skip over PREFER bits */

enum {
    OVERWRITE_CHECK = -1,
    OVERWRITE_NO,
    OVERWRITE_YES
};

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

static void my_caldav_init(struct buf *serverinfo);
static void my_caldav_auth(const char *userid);
static void my_caldav_reset(void);
static void my_caldav_shutdown(void);

static int caldav_parse_path(struct request_target_t *tgt, const char **errstr);

static int caldav_acl(struct transaction_t *txn, xmlNodePtr priv, int *rights);

static int caldav_check_precond(struct transaction_t *txn, const void *data,
				const char *etag, time_t lastmod);

static int report_cal_query(struct transaction_t *txn, xmlNodePtr inroot,
			    struct propfind_ctx *fctx);
static int report_cal_multiget(struct transaction_t *txn, xmlNodePtr inroot,
			       struct propfind_ctx *fctx);
static int report_fb_query(struct transaction_t *txn, xmlNodePtr inroot,
			   struct propfind_ctx *fctx);

static int meth_copy(struct transaction_t *txn, void *params);
static int meth_delete(struct transaction_t *txn, void *params);
static int meth_post(struct transaction_t *txn, void *params);
static int meth_put(struct transaction_t *txn, void *params);
static int store_resource(struct transaction_t *txn, icalcomponent *ical,
			  struct mailbox *mailbox, const char *resource,
			  struct caldav_db *caldavdb, int overwrite,
			  unsigned flags);
static icalcomponent *busytime_query_local(struct transaction_t *txn,
					   struct propfind_ctx *fctx,
					   char mailboxname[],
					   icalproperty_method method,
					   const char *uid,
					   const char *organizer,
					   const char *attendee);
#ifdef WITH_CALDAV_SCHED
static int caladdress_lookup(const char *addr, struct sched_param *param);
static int sched_busytime(struct transaction_t *txn);
static void sched_request(const char *organizer, struct sched_param *sparam,
			  icalcomponent *oldical, icalcomponent *newical);
static void sched_reply(const char *userid,
			icalcomponent *oldical, icalcomponent *newical);
#endif /* WITH_CALDAV_SCHED */

static struct acl_params acl_params = {
    &caldav_parse_path, &caldav_acl
};

static struct get_params get_params = {
    &caldav_parse_path,
    (void **) &auth_caldavdb,
    (lookup_proc_t) &caldav_lookup_resource,
    &caldav_check_precond,
    "text/calendar; charset=utf-8"
};

static struct mkcol_params mkcalendar_params = {
    &caldav_parse_path,
    MBTYPE_CALENDAR, "mkcalendar", "mkcalendar-response", NS_CALDAV
};

static struct mkcol_params mkcol_params = {
    &caldav_parse_path,
    MBTYPE_CALENDAR, "mkcol", "mkcol-response", NS_DAV
};

static struct propfind_params propfind_params = {
    &caldav_parse_path,
    (void **) &auth_caldavdb,
    (lookup_proc_t) &caldav_lookup_resource,
    (foreach_proc_t) &caldav_foreach
};

static struct proppatch_params proppatch_params = {
    &caldav_parse_path
};

static struct report_params report_params = {
    &caldav_parse_path,
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
const struct namespace_t namespace_calendar = {
    URL_NS_CALENDAR, "/calendars", "/.well-known/caldav", 1 /* auth */,
    (ALLOW_READ | ALLOW_POST | ALLOW_WRITE | ALLOW_DAV | ALLOW_CAL),
    &my_caldav_init, &my_caldav_auth, my_caldav_reset, &my_caldav_shutdown,
    { 
	{ &meth_acl,		&acl_params },		/* ACL		*/
	{ &meth_copy,		NULL },			/* COPY		*/
	{ &meth_delete,		NULL },			/* DELETE	*/
	{ &meth_get_dav,	&get_params },		/* GET		*/
	{ &meth_get_dav,	&get_params },		/* HEAD		*/
	{ &meth_mkcol,		&mkcalendar_params },	/* MKCALENDAR	*/
	{ &meth_mkcol,		&mkcol_params },	/* MKCOL	*/
	{ &meth_copy,		NULL },			/* MOVE		*/
	{ &meth_options,	NULL },			/* OPTIONS	*/
	{ &meth_post,		NULL },			/* POST		*/
	{ &meth_propfind,	&propfind_params },	/* PROPFIND	*/
	{ &meth_proppatch,	&proppatch_params },	/* PROPPATCH	*/
	{ &meth_put,		NULL },			/* PUT		*/
	{ &meth_report,		&report_params }	/* REPORT	*/
    }
};


static void my_caldav_init(struct buf *serverinfo)
{
    if (!config_getstring(IMAPOPT_CALENDARPREFIX)) {
	fatal("Required 'calendarprefix' option is not set", EC_CONFIG);
    }

    caldav_init();

    if (config_serverinfo == IMAP_ENUM_SERVERINFO_ON) {
	buf_printf(serverinfo, " libical/%s", ICAL_VERSION);
	buf_printf(serverinfo, " SQLite/%s", sqlite3_libversion());
    }

    /* Need to set this to parse CalDAV Scheduling parameters */
    ical_set_unknown_token_handling_setting(ICAL_ASSUME_IANA_TOKEN);
}


static void my_caldav_auth(const char *userid)
{
    if (config_mupdate_server && !config_getstring(IMAPOPT_PROXYSERVERS)) {
	/* proxy-only server - won't have DAV databases */
	return;
    }
    else if (httpd_userisadmin ||
	     global_authisa(httpd_authstate, IMAPOPT_PROXYSERVERS)) {
	/* admin or proxy from frontend - won't have DAV database */
	return;
    }

    auth_caldavdb = caldav_open(userid, CALDAV_CREATE);
    if (!auth_caldavdb) fatal("Unable to open CalDAV DB", EC_IOERR);
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


/* Parse request-target path in /calendars namespace */
static int caldav_parse_path(struct request_target_t *tgt, const char **errstr)
{
    char *p = tgt->path;
    size_t len, siz;
    static const char *prefix = NULL;

    if (!*p || !*++p) return 0;

    /* Sanity check namespace */
    len = strcspn(p, "/");
    if (len != strlen(namespace_calendar.prefix)-1 ||
	strncmp(namespace_calendar.prefix+1, p, len)) {
	*errstr = "Namespace mismatch request target path";
	return HTTP_FORBIDDEN;
    }

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
	if (!*p || !*++p) goto done;

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
	*errstr = "Too many segments in request target path";
	return HTTP_FORBIDDEN;
    }

  done:
    /* Determine if this is a scheduling Inbox/Outbox */
    if (tgt->collection) {
	if (!strcmp(tgt->collection, SCHED_INBOX))
	    tgt->flags = TGT_SCHED_INBOX;
	else if (!strcmp(tgt->collection, SCHED_OUTBOX))
	    tgt->flags = TGT_SCHED_OUTBOX;
    }

    /* Create mailbox name from the parsed path */ 
    if (!prefix) prefix = config_getstring(IMAPOPT_CALENDARPREFIX);

    p = tgt->mboxname;
    siz = MAX_MAILBOX_BUFFER;
    if (tgt->user) {
	len = snprintf(p, siz, "user");
	p += len;
	siz -= len;

	if (tgt->userlen) {
	    len = snprintf(p, siz, ".%.*s", tgt->userlen, tgt->user);
	    p += len;
	    siz -= len;
	}
    }

    len = snprintf(p, siz, "%s%s", p != tgt->mboxname ? "." : "", prefix);
    p += len;
    siz -= len;

    if (tgt->collection) {
	snprintf(p, siz, ".%.*s", tgt->collen, tgt->collection);
    }

    return 0;
}


/* Check headers for any preconditions */
static int caldav_check_precond(struct transaction_t *txn, const void *data,
				const char *etag, time_t lastmod)
{
    const struct caldav_data *cdata = (const struct caldav_data *) data;
    const char **hdr;
    int ret;

    /* Per RFC 6638,
       If-Schedule-Tag-Match supercedes any ETag-based precondition tests */
    if ((hdr = spool_getheader(txn->req_hdrs, "If-Schedule-Tag-Match"))) {
	if (cdata && etagcmp(hdr[0], cdata->sched_tag))
	    return HTTP_PRECOND_FAILED;

	ret = HTTP_OK;  /* Ignore remaining conditionals */
    }
    else {
	/* Do normal WebDAV and/or HTTP checks */
	ret = check_precond(txn, NULL, etag, lastmod);
    }

    switch (txn->meth) {
    case METH_GET:
    case METH_HEAD:
	if (ret == HTTP_OK) {
	    /* Fill in Schedule-Tag */
	    txn->resp_body.stag = cdata->sched_tag;
	}
    }

    return ret;
}


static int caldav_acl(struct transaction_t *txn, xmlNodePtr priv, int *rights)
{
    if (!xmlStrcmp(priv->ns->href, BAD_CAST XML_NS_CALDAV)) {
	/* CalDAV privileges */
	if (!xmlStrcmp(priv->name, BAD_CAST "read-free-busy"))
	    *rights |= DACL_READFB;
	else if (txn->req_tgt.flags == TGT_SCHED_INBOX &&
		 !xmlStrcmp(priv->name, BAD_CAST "schedule-deliver"))
	    *rights |= DACL_SCHED;
	else if (txn->req_tgt.flags == TGT_SCHED_OUTBOX &&
		 !xmlStrcmp(priv->name, BAD_CAST "schedule-send"))
	    *rights |= DACL_SCHED;
	else if (!xmlStrcmp(priv->name, BAD_CAST "schedule-deliver-invite")
		 || !xmlStrcmp(priv->name, BAD_CAST "schedule-deliver-reply")
		 || !xmlStrcmp(priv->name, BAD_CAST "schedule-query-freebusy")
		 || !xmlStrcmp(priv->name, BAD_CAST "schedule-send-invite")
		 || !xmlStrcmp(priv->name, BAD_CAST "schedule-send-reply")
		 || !xmlStrcmp(priv->name, BAD_CAST "schedule-send-freebusy")) {
	    /* DAV:no-abstract */
	    txn->error.precond = DAV_NO_ABSTRACT;
	}
	else {
	    /* DAV:not-supported-privilege */
	    txn->error.precond = DAV_SUPP_PRIV;
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
	    /* DAV:read aggregates CALDAV:read-free-busy */
	    *rights |= DACL_READFB;
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
static int meth_copy(struct transaction_t *txn,
		     void *params __attribute__((unused)))
{
    int ret = HTTP_CREATED, r, precond, rights, overwrite = OVERWRITE_YES;
    const char **hdr;
    struct request_target_t dest;  /* Parsed destination URL */
    char *server, *acl;
    struct backend *src_be = NULL, *dest_be = NULL;
    struct mailbox *src_mbox = NULL, *dest_mbox = NULL;
    struct caldav_data *cdata;
    struct index_record src_rec;
    const char *etag = NULL;
    time_t lastmod = 0;
    const char *msg_base = NULL;
    unsigned long msg_size = 0;
    icalcomponent *ical = NULL;

    /* Response should not be cached */
    txn->flags.cc |= CC_NOCACHE;

    /* Make sure source is a DAV resource */
    if (!(txn->req_tgt.allow & ALLOW_DAV)) return HTTP_NOT_ALLOWED;

    /* Parse the source path */
    if ((r = caldav_parse_path(&txn->req_tgt, &txn->error.desc))) return r;

    /* We don't yet handle COPY/MOVE on collections */
    if (!txn->req_tgt.resource) return HTTP_NOT_ALLOWED;

    /* Check for mandatory Destination header */
    if (!(hdr = spool_getheader(txn->req_hdrs, "Destination"))) {
	txn->error.desc = "Missing Destination header\r\n";
	return HTTP_BAD_REQUEST;
    }

    /* Parse destination URI */
    if ((r = parse_uri(METH_UNKNOWN, hdr[0], &dest, &txn->error.desc))) return r;

    /* Make sure source and dest resources are NOT the same */
    if (!strcmp(txn->req_tgt.path, dest.path)) {
	txn->error.desc = "Source and destination resources are the same\r\n";
	return HTTP_FORBIDDEN;
    }

    /* Parse the destination path */
    if ((r = caldav_parse_path(&dest, &txn->error.desc))) return r;
    dest.namespace = txn->req_tgt.namespace;

    /* We don't yet handle COPY/MOVE on collections */
    if (!dest.resource) return HTTP_NOT_ALLOWED;

    /* Locate the source mailbox */
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

    /* Check ACL for current user on source mailbox */
    rights = acl ? cyrus_acl_myrights(httpd_authstate, acl) : 0;
    if (((rights & DACL_READ) != DACL_READ) ||
	((txn->meth == METH_MOVE) && !(rights & DACL_RMRSRC))) {
	/* DAV:need-privileges */
	txn->error.precond = DAV_NEED_PRIVS;
	txn->error.resource = txn->req_tgt.path;
	txn->error.rights =
	    (rights & DACL_READ) != DACL_READ ? DACL_READ : DACL_RMRSRC;
	return HTTP_FORBIDDEN;
    }

    if (server) {
	/* Remote source mailbox */
	src_be = proxy_findserver(server, &http_protocol, httpd_userid,
				  &backend_cached, NULL, NULL, httpd_in);
	if (!src_be) return HTTP_UNAVAILABLE;
    }

    /* Locate the destination mailbox */
    if ((r = http_mlookup(dest.mboxname, &server, &acl, NULL))) {
	syslog(LOG_ERR, "mlookup(%s) failed: %s",
	       dest.mboxname, error_message(r));
	txn->error.desc = error_message(r);

	switch (r) {
	case IMAP_PERMISSION_DENIED: return HTTP_FORBIDDEN;
	case IMAP_MAILBOX_NONEXISTENT: return HTTP_NOT_FOUND;
	default: return HTTP_SERVER_ERROR;
	}
    }

    /* Check ACL for current user on destination */
    rights = acl ? cyrus_acl_myrights(httpd_authstate, acl) : 0;
    if (!(rights & DACL_ADDRSRC) || !(rights & DACL_WRITECONT)) {
	/* DAV:need-privileges */
	txn->error.precond = DAV_NEED_PRIVS;
	txn->error.resource = dest.path;
	txn->error.rights =
	    !(rights & DACL_ADDRSRC) ? DACL_ADDRSRC : DACL_WRITECONT;
	return HTTP_FORBIDDEN;
    }

    if (server) {
	/* Remote destination mailbox */
	dest_be = proxy_findserver(server, &http_protocol, httpd_userid,
				   &backend_cached, NULL, NULL, httpd_in);
	if (!dest_be) return HTTP_UNAVAILABLE;
    }

    if (src_be) {
	/* Remote source mailbox */
	/* XXX  Currently only supports standard Murder */

	if (!dest_be) return HTTP_NOT_ALLOWED;

	/* Replace cached Destination header with just the absolute path */
	hdr = spool_getheader(txn->req_hdrs, "Destination");
	strcpy((char *) hdr[0], dest.path);

	if (src_be == dest_be) {
	    /* Simply send the COPY to the backend */
	    return http_pipe_req_resp(src_be, txn);
	}

	/* This is the harder case: GET from source and PUT on destination */
	return http_proxy_copy(src_be, dest_be, txn);
    }

    /* Local Mailbox */

    /* Open dest mailbox for reading */
    if ((r = mailbox_open_irl(dest.mboxname, &dest_mbox))) {
	syslog(LOG_ERR, "mailbox_open_irl(%s) failed: %s",
	       dest.mboxname, error_message(r));
	txn->error.desc = error_message(r);
	ret = HTTP_SERVER_ERROR;
	goto done;
    }

    /* Find message UID for the dest resource, if exists */
    caldav_lookup_resource(auth_caldavdb,
			   dest.mboxname, dest.resource, 0, &cdata);
    /* XXX  Check errors */

    /* Finished our initial read of dest mailbox */
    mailbox_unlock_index(dest_mbox, NULL);

    /* Check any preconditions on destination */
    if ((hdr = spool_getheader(txn->req_hdrs, "Overwrite")) &&
	!strcmp(hdr[0], "F")) {

	if (cdata->dav.imap_uid) {
	    /* Don't overwrite the destination resource */
	    ret = HTTP_PRECOND_FAILED;
	    goto done;
	}
	overwrite = OVERWRITE_NO;
    }

    /* Open source mailbox for reading */
    if ((r = http_mailbox_open(txn->req_tgt.mboxname, &src_mbox, LOCK_SHARED))) {
	syslog(LOG_ERR, "http_mailbox_open(%s) failed: %s",
	       txn->req_tgt.mboxname, error_message(r));
	txn->error.desc = error_message(r);
	ret = HTTP_SERVER_ERROR;
	goto done;
    }

    /* Find message UID for the source resource */
    caldav_lookup_resource(auth_caldavdb,
			   txn->req_tgt.mboxname, txn->req_tgt.resource, 0, &cdata);
    /* XXX  Check errors */

    /* Fetch index record for the source resource */
    if (!cdata->dav.imap_uid ||
	mailbox_find_index_record(src_mbox, cdata->dav.imap_uid, &src_rec)) {
	ret = HTTP_NOT_FOUND;
	goto done;
    }

    /* Check any preconditions on source */
    etag = message_guid_encode(&src_rec.guid);
    lastmod = src_rec.internaldate;
    precond = caldav_check_precond(txn, cdata, etag, lastmod);

    if (precond != HTTP_OK) {
	/* We failed a precondition - don't perform the request */
	ret = precond;
	goto done;
    }

    /* Load message containing the resource and parse iCal data */
    mailbox_map_message(src_mbox, src_rec.uid, &msg_base, &msg_size);
    ical = icalparser_parse_string(msg_base + src_rec.header_size);
    mailbox_unmap_message(src_mbox, src_rec.uid, &msg_base, &msg_size);

    /* Finished our initial read of source mailbox */
    mailbox_unlock_index(src_mbox, NULL);

    /* Store source resource at destination */
    ret = store_resource(txn, ical, dest_mbox, dest.resource, auth_caldavdb,
			 overwrite, NEW_STAG);

    /* For MOVE, we need to delete the source resource */
    if ((txn->meth == METH_MOVE) &&
	(ret == HTTP_CREATED || ret == HTTP_NO_CONTENT)) {
	/* Lock source mailbox */
	mailbox_lock_index(src_mbox, LOCK_EXCLUSIVE);

	/* Find message UID for the source resource */
	caldav_lookup_resource(auth_caldavdb,
			       txn->req_tgt.mboxname, txn->req_tgt.resource, 1, &cdata);
	/* XXX  Check errors */

	/* Fetch index record for the source resource */
	if (cdata->dav.imap_uid &&
	    !mailbox_find_index_record(src_mbox, cdata->dav.imap_uid,
				       &src_rec)) {

	    /* Expunge the source message */
	    src_rec.system_flags |= FLAG_EXPUNGED;
	    if ((r = mailbox_rewrite_index_record(src_mbox, &src_rec))) {
		syslog(LOG_ERR, "expunging src record (%s) failed: %s",
		       txn->req_tgt.mboxname, error_message(r));
		txn->error.desc = error_message(r);
		ret = HTTP_SERVER_ERROR;
		goto done;
	    }
	}

	/* Delete mapping entry for source resource name */
	caldav_delete(auth_caldavdb, cdata->dav.rowid);
	caldav_commit(auth_caldavdb);
    }

  done:
    if (ret == HTTP_CREATED) {
	/* Tell client where to find the new resource */
	hdr = spool_getheader(txn->req_hdrs, "Destination");
	txn->location = hdr[0];
    }
    else {
	/* Don't confuse client by providing ETag of Destination resource */
	txn->resp_body.etag = NULL;
    }

    if (ical) icalcomponent_free(ical);
    if (dest_mbox) mailbox_close(&dest_mbox);
    if (src_mbox) mailbox_unlock_index(src_mbox, NULL);

    return ret;
}


/* Perform a DELETE request */
static int meth_delete(struct transaction_t *txn,
		       void *params __attribute__((unused)))
{
    int ret = HTTP_NO_CONTENT, r, precond, rights;
    char *server, *acl;
    struct mailbox *mailbox = NULL;
    struct caldav_data *cdata;
    struct index_record record;
    const char *etag = NULL, *userid;
    time_t lastmod = 0;
    unsigned rowid;

    /* Response should not be cached */
    txn->flags.cc |= CC_NOCACHE;

    /* Make sure its a DAV resource */
    if (!(txn->req_tgt.allow & ALLOW_WRITE)) return HTTP_NOT_ALLOWED; 

    /* Parse the path */
    if ((r = caldav_parse_path(&txn->req_tgt, &txn->error.desc))) return r;

    /* Construct userid corresponding to mailbox */
    userid = mboxname_to_userid(txn->req_tgt.mboxname);

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
    if ((txn->req_tgt.resource && !(rights & DACL_RMRSRC)) ||
	!(rights & DACL_RMCOL)) {
	/* DAV:need-privileges */
	txn->error.precond = DAV_NEED_PRIVS;
	txn->error.resource = txn->req_tgt.path;
	txn->error.rights = txn->req_tgt.resource ? DACL_RMRSRC : DACL_RMCOL;
	return HTTP_FORBIDDEN;
    }

    if (server) {
	/* Remote mailbox */
	struct backend *be;

	be = proxy_findserver(server, &http_protocol, httpd_userid,
			      &backend_cached, NULL, NULL, httpd_in);
	if (!be) return HTTP_UNAVAILABLE;

	return http_pipe_req_resp(be, txn);
    }

    /* Local Mailbox */

    if (!txn->req_tgt.resource) {
	/* DELETE collection */
	/* XXX  Need to process any scheduling objects */

	r = mboxlist_deletemailbox(txn->req_tgt.mboxname,
				   httpd_userisadmin || httpd_userisproxyadmin,
				   httpd_userid, httpd_authstate,
				   1, 0, 0);

	if (!r) caldav_delmbox(auth_caldavdb, txn->req_tgt.mboxname);
	else if (r == IMAP_PERMISSION_DENIED) ret = HTTP_FORBIDDEN;
	else if (r == IMAP_MAILBOX_NONEXISTENT) ret = HTTP_NOT_FOUND;
	else if (r) ret = HTTP_SERVER_ERROR;

	return ret;
    }


    /* DELETE resource */

    /* Open mailbox for writing */
    if ((r = http_mailbox_open(txn->req_tgt.mboxname, &mailbox, LOCK_EXCLUSIVE))) {
	syslog(LOG_ERR, "http_mailbox_open(%s) failed: %s",
	       txn->req_tgt.mboxname, error_message(r));
	txn->error.desc = error_message(r);
	ret = HTTP_SERVER_ERROR;
	goto done;
    }

    /* Find message UID for the resource */
    caldav_lookup_resource(auth_caldavdb, txn->req_tgt.mboxname,
			   txn->req_tgt.resource, 1, &cdata);
    /* XXX  Check errors */

    /* Fetch index record for the resource */
    if (!cdata->dav.imap_uid ||
	mailbox_find_index_record(mailbox, cdata->dav.imap_uid, &record)) {
	ret = HTTP_NOT_FOUND;
	goto done;
    }

    etag = message_guid_encode(&record.guid);
    lastmod = record.internaldate;

    /* Check any preconditions */
    precond = caldav_check_precond(txn, cdata, etag, lastmod);

    /* We failed a precondition - don't perform the request */
    if (precond != HTTP_OK) {
	ret = precond;
	goto done;
    }

    /* Save rowid because cdata will be overwritten by scheduling ops */
    rowid = cdata->dav.rowid;

#ifdef WITH_CALDAV_SCHED
    if (cdata->sched_tag) {
	/* Scheduling object resource */
	struct mboxlist_entry mbentry;
	char outboxname[MAX_MAILBOX_BUFFER];
	const char *msg_base = NULL, *organizer, **hdr;
	unsigned long msg_size = 0;
	icalcomponent *ical, *comp;
	icalproperty *prop;
	struct sched_param sparam;

	/* Check ACL of auth'd user on userid's Scheduling Outbox */
	caldav_mboxname(SCHED_OUTBOX, userid, outboxname);

	if ((r = mboxlist_lookup(outboxname, &mbentry, NULL))) {
	    syslog(LOG_INFO, "mboxlist_lookup(%s) failed: %s",
		   outboxname, error_message(r));
	    mbentry.acl = NULL;
	}

	rights =
	    mbentry.acl ? cyrus_acl_myrights(httpd_authstate, mbentry.acl) : 0;
	if (!(rights & DACL_SCHED)) {
	    /* DAV:need-privileges */
	    txn->error.precond = DAV_NEED_PRIVS;
	    txn->error.rights = DACL_SCHED;

	    assert(!buf_len(&txn->buf));
	    buf_printf(&txn->buf, "/calendars/user/%s/%s", userid, SCHED_OUTBOX);
	    txn->error.resource = buf_cstring(&txn->buf);
	    ret = HTTP_FORBIDDEN;
	    goto done;
	}

	/* Load message containing the resource and parse iCal data */
	mailbox_map_message(mailbox, record.uid, &msg_base, &msg_size);
	ical = icalparser_parse_string(msg_base + record.header_size);
	mailbox_unmap_message(mailbox, record.uid, &msg_base, &msg_size);

	if (!ical) {
	    syslog(LOG_ERR,
		   "meth_delete: failed to parse iCalendar object %s:%u",
		   txn->req_tgt.mboxname, record.uid);
	    ret = HTTP_SERVER_ERROR;
	    goto done;
	}

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
	    sched_request(organizer, &sparam, ical, NULL);
	}
	else if (!(hdr = spool_getheader(txn->req_hdrs, "Schedule-Reply")) ||
		 strcmp(hdr[0], "F")) {
	    /* Attendee scheduling object resource */
	    sched_reply(userid, ical, NULL);
	}

	icalcomponent_free(ical);
    }
#endif /* WITH_CALDAV_SCHED */

    /* Expunge the resource */
    record.system_flags |= FLAG_EXPUNGED;

    if ((r = mailbox_rewrite_index_record(mailbox, &record))) {
	syslog(LOG_ERR, "expunging record (%s) failed: %s",
	       txn->req_tgt.mboxname, error_message(r));
	txn->error.desc = error_message(r);
	ret = HTTP_SERVER_ERROR;
	goto done;
    }

    /* Delete mapping entry for resource name */
    caldav_delete(auth_caldavdb, rowid);
    caldav_commit(auth_caldavdb);

  done:
    if (mailbox) mailbox_unlock_index(mailbox, NULL);

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


/* Perform a POST request */
static int meth_post(struct transaction_t *txn,
		     void *params __attribute__((unused)))
{
    static unsigned post_count = 0;
    int r, ret;
    size_t len;
    char *p;

    /* Response should not be cached */
    txn->flags.cc |= CC_NOCACHE;

    /* Make sure its a DAV resource */
    if (!(txn->req_tgt.allow & ALLOW_WRITE)) return HTTP_NOT_ALLOWED; 

    /* Parse the path */
    if ((r = caldav_parse_path(&txn->req_tgt, &txn->error.desc))) return r;

    /* We only handle POST on calendar collections */
    if (!txn->req_tgt.collection ||
	txn->req_tgt.resource) return HTTP_NOT_ALLOWED;

#ifdef WITH_CALDAV_SCHED
    if (!strcmp(txn->req_tgt.collection, SCHED_OUTBOX)) {
	/* POST to schedule-outbox (busy time request) */

	return sched_busytime(txn);
    }
#endif

    /* POST to regular calendar collection */

    /* Append a unique resource name to URL path and perform a PUT */
    len = strlen(txn->req_tgt.path);
    p = txn->req_tgt.path + len;

    snprintf(p, MAX_MAILBOX_PATH - len, "%x-%d-%ld-%u.ics",
	     strhash(txn->req_tgt.path), getpid(), time(0), post_count++);

    /* Tell client where to find the new resource */
    txn->location = txn->req_tgt.path;

    ret = meth_put(txn, NULL);

    if (ret != HTTP_CREATED) txn->location = NULL;

    return ret;
}


/* Perform a PUT request
 *
 * preconditions:
 *   CALDAV:supported-calendar-data
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
static int meth_put(struct transaction_t *txn,
		    void *params __attribute__((unused)))
{
    int ret, r, precond, rights;
    char *server, *acl;
    struct mailbox *mailbox = NULL;
    struct caldav_data *cdata;
    struct index_record oldrecord;
    const char *etag, *organizer = NULL, *userid;
    time_t lastmod;
    const char **hdr, *uid;
    uquota_t size = 0;
    icalcomponent *ical = NULL, *comp, *nextcomp;
    icalcomponent_kind kind;
    icalproperty *prop;
    unsigned flags = 0;

    /* Response should not be cached */
    txn->flags.cc |= CC_NOCACHE;

    /* Make sure Content-Range isn't specified */
    if (spool_getheader(txn->req_hdrs, "Content-Range"))
	return HTTP_BAD_REQUEST;

    /* Make sure its a DAV resource */
    if (!(txn->req_tgt.allow & ALLOW_WRITE)) return HTTP_NOT_ALLOWED; 

    /* Parse the path */
    if ((r = caldav_parse_path(&txn->req_tgt, &txn->error.desc))) return r;

    /* We only handle PUT on resources */
    if (!txn->req_tgt.resource) return HTTP_NOT_ALLOWED;

    /* Check Content-Type */
    if (!(hdr = spool_getheader(txn->req_hdrs, "Content-Type")) ||
	!is_mediatype(hdr[0], "text/calendar")) {
	txn->error.precond = CALDAV_SUPP_DATA;
	return HTTP_FORBIDDEN;
    }

    /* Construct userid corresponding to mailbox */
    userid = mboxname_to_userid(txn->req_tgt.mboxname);

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
    if (!(rights & DACL_WRITECONT) || !(rights & DACL_ADDRSRC)) {
	/* DAV:need-privileges */
	txn->error.precond = DAV_NEED_PRIVS;
	txn->error.resource = txn->req_tgt.path;
	txn->error.rights =
	    !(rights & DACL_WRITECONT) ? DACL_WRITECONT : DACL_ADDRSRC;
	return HTTP_FORBIDDEN;
    }

    if (server) {
	/* Remote mailbox */
	struct backend *be;

	be = proxy_findserver(server, &http_protocol, httpd_userid,
			      &backend_cached, NULL, NULL, httpd_in);
	if (!be) return HTTP_UNAVAILABLE;

	return http_pipe_req_resp(be, txn);
    }

    /* Local Mailbox */

    /* Open mailbox for reading */
    if ((r = http_mailbox_open(txn->req_tgt.mboxname, &mailbox, LOCK_SHARED))) {
	syslog(LOG_ERR, "http_mailbox_open(%s) failed: %s",
	       txn->req_tgt.mboxname, error_message(r));
	txn->error.desc = error_message(r);
	ret = HTTP_SERVER_ERROR;
	goto done;
    }

    /* Find message UID for the resource, if exists */
    caldav_lookup_resource(auth_caldavdb, txn->req_tgt.mboxname,
			   txn->req_tgt.resource, 0, &cdata);
    /* XXX  Check errors */

    if (cdata->dav.imap_uid) {
	/* Overwriting existing resource */

	/* Fetch index record for the resource */
	r = mailbox_find_index_record(mailbox, cdata->dav.imap_uid, &oldrecord);
	/* XXX  check for errors */

	etag = message_guid_encode(&oldrecord.guid);
	lastmod = oldrecord.internaldate;
    }
    else {
	/* New resource */
	etag = NULL;
	lastmod = 0;
    }

    /* Finished our initial read */
    mailbox_unlock_index(mailbox, NULL);

    /* Check any preconditions */
    precond = caldav_check_precond(txn, cdata, etag, lastmod);

    if (precond != HTTP_OK) {
	/* We failed a precondition - don't perform the request */
	ret = precond;
	goto done;
    }

    /* Read body */
    if (!txn->flags.havebody) {
	txn->flags.havebody = 1;
	ret = read_body(httpd_in, txn->req_hdrs, &txn->req_body, 1,
			&txn->error.desc);
	if (ret) {
	    txn->flags.close = 1;
	    goto done;
	}
    }

    /* Make sure we have a body */
    size = buf_len(&txn->req_body);
    if (!size) {
	txn->error.desc = "Missing request body\r\n";
	ret = HTTP_BAD_REQUEST;
	goto done;
    }

    /* Check if we can append a new iMIP message to calendar mailbox */
    if ((r = append_check(txn->req_tgt.mboxname, httpd_authstate, ACL_INSERT, size))) {
	txn->error.desc = error_message(r);
	ret = HTTP_SERVER_ERROR;
	goto done;
    }

    /* Parse and validate the iCal data */
    ical = icalparser_parse_string(buf_cstring(&txn->req_body));
    if (!ical || (icalcomponent_isa(ical) != ICAL_VCALENDAR_COMPONENT)) {
	txn->error.precond = CALDAV_VALID_DATA;
	ret = HTTP_FORBIDDEN;
	goto done;
    }
    else if (!icalrestriction_check(ical)) {
	txn->error.precond = CALDAV_VALID_OBJECT;
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

#ifdef WITH_CALDAV_SCHED
    if (organizer) {
	/* Scheduling object resource */
	struct sched_param sparam;

	/* Make sure iCal UID is unique for this user */
	caldav_lookup_uid(auth_caldavdb, uid, 0, &cdata);
	/* XXX  Check errors */

	if (cdata->dav.mailbox &&
	    (strcmp(cdata->dav.mailbox, txn->req_tgt.mboxname) ||
	     strcmp(cdata->dav.resource, txn->req_tgt.resource))) {
	    /* CALDAV:unique-scheduling-object-resource */

	    txn->error.precond = CALDAV_UNIQUE_OBJECT;
	    assert(!buf_len(&txn->buf));
	    buf_printf(&txn->buf, "/calendars/user/%s/%s/%s",
		       userid, strrchr(cdata->dav.mailbox, '.')+1,
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

	if (!strcmp(sparam.userid, userid)) {
	    /* Organizer scheduling object resource */
	    sched_request(organizer, &sparam, NULL, ical);
	}
	else {
	    /* Attendee scheduling object resource */
	    sched_reply(userid, NULL, ical);
	}
    }

    flags |= NEW_STAG;
#endif /* WITH_CALDAV_SCHED */

    if (get_preferences(txn) & PREFER_REP) flags |= PREFER_REP;

    /* Store resource at target */
    ret = store_resource(txn, ical, mailbox, txn->req_tgt.resource,
			 auth_caldavdb, OVERWRITE_CHECK, flags);

  done:
    if (ical) icalcomponent_free(ical);
    if (mailbox) mailbox_unlock_index(mailbox, NULL);

    return ret;
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

		if (filter->comp) {
		    error->precond = CALDAV_VALID_FILTER;
		    return HTTP_FORBIDDEN;
		}

		if (!xmlStrcmp(name, BAD_CAST "VCALENDAR"))
		    filter->comp = CAL_COMP_VCALENDAR;
		else if (!xmlStrcmp(name, BAD_CAST "VEVENT"))
		    filter->comp = CAL_COMP_VEVENT;
		else if (!xmlStrcmp(name, BAD_CAST "VTODO"))
		    filter->comp = CAL_COMP_VTODO;
		else if (!xmlStrcmp(name, BAD_CAST "VJOURNAL"))
		    filter->comp = CAL_COMP_VJOURNAL;
		else if (!xmlStrcmp(name, BAD_CAST "VFREEBUSY"))
		    filter->comp = CAL_COMP_VFREEBUSY;
		else {
		    error->precond = CALDAV_SUPP_FILTER;
		    return HTTP_FORBIDDEN;
		}

		ret = parse_comp_filter(node->children, filter, error);
		if (ret) return ret;
	    }
	    else if (!xmlStrcmp(node->name, BAD_CAST "time-range")) {
		const char *start, *end;

		start = (const char *) xmlGetProp(node, BAD_CAST "start");
		filter->start = start ? icaltime_from_string(start) :
		    icaltime_from_timet_with_zone(INT_MIN, 0, NULL);

		end = (const char *) xmlGetProp(node, BAD_CAST "end");
		filter->end = end ? icaltime_from_string(end) :
		    icaltime_from_timet_with_zone(INT_MAX, 0, NULL);
	    }
	    else {
		error->precond = CALDAV_SUPP_FILTER;
		return HTTP_FORBIDDEN;
	    }
	}
    }

    return ret;
}


static int report_cal_query(struct transaction_t *txn,
			    xmlNodePtr inroot, struct propfind_ctx *fctx)
{
    int ret = 0;
    xmlNodePtr node;
    struct calquery_filter calfilter;

    fctx->davdb = auth_caldavdb;
    fctx->lookup_resource = (lookup_proc_t) &caldav_lookup_resource;
    fctx->foreach_resource = (foreach_proc_t) &caldav_foreach;
    fctx->proc_by_resource = &propfind_by_resource;

    /* Parse children element of report */
    for (node = inroot->children; node; node = node->next) {
	if (node->type == XML_ELEMENT_NODE) {
	    if (!xmlStrcmp(node->name, BAD_CAST "filter")) {
		memset(&calfilter, 0, sizeof(struct calquery_filter));
		ret = parse_comp_filter(node->children, &calfilter, &txn->error);
		if (!ret) {
		    fctx->filter = apply_calfilter;
		    fctx->filter_crit = &calfilter;
		}
	    }
	    else if (!xmlStrcmp(node->name, BAD_CAST "timezone")) {
		syslog(LOG_WARNING, "REPORT calendar-query w/timezone");
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

	    /* Parse the path */
	    strlcpy(tgt.path, uri.s, sizeof(tgt.path));
	    if ((r = caldav_parse_path(&tgt, fctx->errstr))) {
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

    fctx->lookup_resource = (lookup_proc_t) &caldav_lookup_resource;
    fctx->foreach_resource = (foreach_proc_t) &caldav_foreach;
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
    struct calquery_filter calfilter;
    xmlNodePtr node;
    icalcomponent *cal;

    /* Can not be run against a resource */
    if (txn->req_tgt.resource) return HTTP_FORBIDDEN;

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
		const char *start, *end;

		start = (const char *) xmlGetProp(node, BAD_CAST "start");
		if (start) calfilter.start = icaltime_from_string(start);

		end = (const char *) xmlGetProp(node, BAD_CAST "end");
		if (end) calfilter.end = icaltime_from_string(end);
	    }
	}
    }

    cal = busytime_query_local(txn, fctx, txn->req_tgt.mboxname,
			       0, NULL, NULL, NULL);

    if (calfilter.busytime.busy) free(calfilter.busytime.busy);

    if (cal) {
	/* Output the iCalendar object as text/calendar */
	const char *cal_str = icalcomponent_as_ical_string(cal);
	icalcomponent_free(cal);

	txn->resp_body.type = "text/calendar; charset=utf-8";

	/* iCalendar data in response should not be transformed */
	txn->flags.cc |= CC_NOTRANSFORM;

	write_body(HTTP_OK, txn, cal_str, strlen(cal_str));
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

    /* Check for existing iCalendar UID */
    uid = icalcomponent_get_uid(comp);
    caldav_lookup_uid(caldavdb, uid, 0, &cdata);
    if (cdata->dav.mailbox && !strcmp(cdata->dav.mailbox, mailbox->name) &&
	strcmp(cdata->dav.resource, resource)) {
	/* CALDAV:no-uid-conflict */
	txn->error.precond = CALDAV_UID_CONFLICT;
	assert(!buf_len(&txn->buf));
	buf_printf(&txn->buf, "/calendars/user/%s/%s/%s",
		   mboxname_to_userid(cdata->dav.mailbox),
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

    ics = icalcomponent_as_ical_string(ical);

    /* Create iMIP header for resource */
    prop = icalcomponent_get_first_property(comp, ICAL_ORGANIZER_PROPERTY);
    if (prop) {
	fprintf(f, "From: %s\r\n", icalproperty_get_organizer(prop)+7);
    }
    else {
	/* XXX  This needs to be done via an LDAP/DB lookup */
	fprintf(f, "From: %s@%s\r\n", httpd_userid, config_servername);
    }

    fprintf(f, "Subject: %s\r\n", icalcomponent_get_summary(comp));

    rfc822date_gen(datestr, sizeof(datestr),
		   icaltime_as_timet_with_zone(icalcomponent_get_dtstamp(comp),
					       icaltimezone_get_utc_timezone()));
    fprintf(f, "Date: %s\r\n", datestr);

    fprintf(f, "Message-ID: <%s@%s>\r\n", uid, config_servername);

    fprintf(f, "Content-Type: text/calendar; charset=UTF-8");
    if ((meth = icalcomponent_get_method(ical)) != ICAL_METHOD_NONE) {
	fprintf(f, "; method=%s", icalproperty_method_to_string(meth));
    }
    fprintf(f, "; component=%s\r\n", icalcomponent_kind_to_string(kind));

    fprintf(f, "Content-Length: %u\r\n", strlen(ics));
    fprintf(f, "Content-Disposition: inline; filename=\"%s\"\r\n", resource);

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
	if (body) message_free_body(body);

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

		    ret = (flags & PREFER_REP) ? HTTP_OK : HTTP_NO_CONTENT;

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
		    /* Create mapping entry from resource name to UID */
		    cdata->dav.mailbox = mailbox->name;
		    cdata->dav.resource = resource;
		    cdata->dav.imap_uid = newrecord.uid;
		    caldav_make_entry(ical, cdata);

		    if (!cdata->organizer) cdata->sched_tag = NULL;
		    else if (flags & NEW_STAG) {
			sprintf(sched_tag, "%d-%ld-%u",
				getpid(), now, store_count++);
			cdata->sched_tag = sched_tag;
		    }

		    caldav_write(caldavdb, cdata);
		    caldav_commit(caldavdb);
		    /* XXX  check for errors, if this fails, backout changes */

		    /* Tell client about the new resource */
		    txn->resp_body.etag = message_guid_encode(&newrecord.guid);
		    if (cdata->sched_tag) txn->resp_body.stag = cdata->sched_tag;

		    if (flags & PREFER_REP) {
			struct resp_body_t *resp_body = &txn->resp_body;

			resp_body->loc = txn->req_tgt.path;
			resp_body->type = "text/calendar; charset=utf-8";
			resp_body->len = strlen(ics);

			/* iCalendar data in response should not be transformed */
			txn->flags.cc |= CC_NOTRANSFORM;

			write_body(ret, txn, ics, strlen(ics));
			ret = 0;
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


#ifdef WITH_CALDAV_SCHED
static int caladdress_lookup(const char *addr, struct sched_param *param)
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
static xmlNodePtr xml_add_schedresponse(xmlNodePtr root, xmlNsPtr dav_ns,
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


#define REQSTAT_PENDING		"1.0;Pending"
#define REQSTAT_SENT		"1.1;Sent"
#define REQSTAT_DELIVERED	"1.2;Delivered"
#define REQSTAT_SUCCESS		"2.0;Success"
#define REQSTAT_NOUSER		"3.7;Invalid calendar user"
#define REQSTAT_NOPRIVS		"3.8;Noauthority"
#define REQSTAT_TEMPFAIL	"5.1;Service unavailable"
#define REQSTAT_PERMFAIL	"5.2;Invalid calendar service"
#define REQSTAT_REJECTED	"5.3;No scheduling support for user"

struct remote_rock {
    struct transaction_t *txn;
    icalcomponent *ical;
    xmlNodePtr root;
    xmlNsPtr *ns;
};

/* Send an iTIP busytime request to remote attendees via iMIP or iSchedule */
static void busytime_query_remote(char *server __attribute__((unused)),
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

	r = isched_send(remote, rrock->ical, &xml);
	if (r) status = REQSTAT_TEMPFAIL;
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


/* Perform a Busy Time query based on given VFREEBUSY component */
/* NOTE: This function is destructive of 'ical' */
int busytime_query(struct transaction_t *txn, icalcomponent *ical)
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
    fctx.userid = httpd_userid;
    fctx.userisadmin = httpd_userisadmin;
    fctx.authstate = org_authstate;
    fctx.reqd_privs = 0;  /* handled by CALDAV:schedule-deliver on Inbox */
    fctx.filter = apply_calfilter;
    fctx.filter_crit = &calfilter;
    fctx.errstr = &txn->error.desc;
    fctx.ret = &ret;
    fctx.fetcheddata = 0;

    /* Create hash table for any remote attendee servers */
    construct_hash_table(&remote_table, 10, 1);

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
	    struct mboxlist_entry mbentry;
	    int rights;
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
		continue;
	    }

	    rights =
		mbentry.acl ? cyrus_acl_myrights(org_authstate, mbentry.acl) : 0;
	    if (!(rights & DACL_SCHED)) {
		xmlNewChild(resp, NULL, BAD_CAST "request-status",
			    BAD_CAST REQSTAT_NOPRIVS);
		continue;
	    }

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

	    if (busy) {
		xmlNodePtr cdata;
		const char *fb_str = icalcomponent_as_ical_string(busy);
		icalcomponent_free(busy);

		xmlNewChild(resp, NULL, BAD_CAST "request-status",
			    BAD_CAST REQSTAT_SUCCESS);

		cdata = xmlNewTextChild(resp, NULL,
					BAD_CAST "calendar-data", NULL);

		xmlAddChild(cdata,
			    xmlNewCDataBlock(root->doc, BAD_CAST fb_str,
					     strlen(fb_str)));

		/* iCalendar data in response should not be transformed */
		txn->flags.cc |= CC_NOTRANSFORM;
	    }
	    else {
		xmlNewChild(resp, NULL, BAD_CAST "request-status",
			    BAD_CAST REQSTAT_NOUSER);
	    }
	}
    }

    if (remote) {
	struct remote_rock rrock = { txn, ical, root, ns };
	hash_enumerate(&remote_table, busytime_query_remote, &rrock);
    }
    free_hash_table(&remote_table, free);

    /* Output the XML response */
    if (!ret) xml_response(HTTP_OK, txn, root->doc);

  done:
    if (org_authstate) auth_freestate(org_authstate);
    if (calfilter.busytime.busy) free(calfilter.busytime.busy);
    if (root) xmlFree(root->doc);

    return ret;
}


/* Perform a CalDAV Scheduling Busy Time request */
static int sched_busytime(struct transaction_t *txn)
{
    int ret = 0, r, rights;
    char *acl;
    const char **hdr;
    icalcomponent *ical = NULL, *comp;
    icalcomponent_kind kind = 0;
    icalproperty_method meth = 0;
    icalproperty *prop = NULL;
    const char *uid = NULL, *organizer = NULL, *orgid = NULL;
    struct sched_param sparam;

    /* Check Content-Type */
    if (!(hdr = spool_getheader(txn->req_hdrs, "Content-Type")) ||
	!is_mediatype(hdr[0], "text/calendar")) {
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

    /* Check ACL for current user */
    rights = acl ? cyrus_acl_myrights(httpd_authstate, acl) : 0;
    if (!(rights & DACL_SCHED)) {
	/* DAV:need-privileges */
	txn->error.precond = DAV_NEED_PRIVS;
	txn->error.resource = txn->req_tgt.path;
	txn->error.rights = DACL_SCHED;
	return HTTP_FORBIDDEN;
    }

    /* Read body */
    if (!txn->flags.havebody) {
	txn->flags.havebody = 1;
	r = read_body(httpd_in, txn->req_hdrs, &txn->req_body, 1,
		      &txn->error.desc);
	if (r) {
	    txn->flags.close = 1;
	    return r;
	}
    }

    /* Make sure we have a body */
    if (!buf_len(&txn->req_body)) {
	txn->error.desc = "Missing request body\r\n";
	return HTTP_BAD_REQUEST;
    }

    /* Parse the iCal data for important properties */
    ical = icalparser_parse_string(buf_cstring(&txn->req_body));
    if (!ical || !icalrestriction_check(ical)) {
	txn->error.precond = CALDAV_VALID_DATA;
	return HTTP_BAD_REQUEST;
    }

    meth = icalcomponent_get_method(ical);
    comp = icalcomponent_get_first_real_component(ical);
    if (comp) {
	uid = icalcomponent_get_uid(comp);
	kind = icalcomponent_isa(comp);
	prop = icalcomponent_get_first_property(comp, ICAL_ORGANIZER_PROPERTY);
    }

    /* Check method preconditions */
    if (!meth || meth != ICAL_METHOD_REQUEST || !uid ||
	kind != ICAL_VFREEBUSY_COMPONENT || !prop) {
	txn->error.precond = CALDAV_VALID_SCHED;
	ret = HTTP_BAD_REQUEST;
	goto done;
    }

    /* Organizer MUST be local to use CalDAV Scheduling */
    organizer = icalproperty_get_organizer(prop);
    if (organizer) {
	if (!caladdress_lookup(organizer, &sparam) &&
	    !(sparam.flags & SCHEDTYPE_REMOTE))
	    orgid = sparam.userid;
    }

    if (!orgid || strncmp(orgid, txn->req_tgt.user, txn->req_tgt.userlen)) {
	txn->error.precond = CALDAV_VALID_ORGANIZER;
	ret = HTTP_FORBIDDEN;
	goto done;
    }

    ret = busytime_query(txn, ical);

  done:
    if (ical) icalcomponent_free(ical);

    return ret;
}


struct sched_data {
    unsigned is_reply;
    icalcomponent *ical;
    icalcomponent *master;
    unsigned comp_mask;
    char *force_send;
    const char *status;
};

struct exclude_rock {
    unsigned ncomp;
    icalcomponent *comp;
};

/* Add EXDATE to master component if attendee is excluded from recurrence */
static void sched_exclude(char *attendee __attribute__((unused)),
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

/* Deliver scheduling object to recipient's Inbox */
static void sched_deliver(char *recipient, void *data, void *rock)
{
    struct sched_data *sched_data = (struct sched_data *) data;
    struct auth_state *authstate = (struct auth_state *) rock;
    int r = 0, rights;
    struct sched_param sparam;
    const char *userid, *mboxname = NULL;
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

    if (caladdress_lookup(recipient, &sparam)) {
	sched_data->status = SCHEDSTAT_NOUSER;
	goto done;
    }
    else userid = sparam.userid;
    /* XXX  Check sparam.flags for remote recipients */

    /* Check SCHEDULE-FORCE-SEND value */
    if (sched_data->force_send) {
	const char *force = sched_data->is_reply ? "REPLY" : "REQUEST";

	if (strcmp(sched_data->force_send, force)) {
	    sched_data->status = SCHEDSTAT_PARAM;
	    goto done;
	}
    }

    /* Check ACL of sender on recipient's Scheduling Inbox */
    caldav_mboxname(SCHED_INBOX, userid, namebuf);
    if ((r = mboxlist_lookup(namebuf, &mbentry, NULL))) {
	syslog(LOG_INFO, "mboxlist_lookup(%s) failed: %s",
	       namebuf, error_message(r));
	sched_data->status = SCHEDSTAT_REJECTED;
	goto done;
    }

    rights =
	mbentry.acl ? cyrus_acl_myrights(authstate, mbentry.acl) : 0;
    if (!(rights & DACL_SCHED)) {
	sched_data->status = SCHEDSTAT_NOPRIVS;
	goto done;
    }

    /* Open recipient's Inbox for reading */
    if ((r = mailbox_open_irl(namebuf, &inbox))) {
	syslog(LOG_ERR, "mailbox_open_irl(%s) failed: %s",
	       namebuf, error_message(r));
	sched_data->status = SCHEDSTAT_TEMPFAIL;
	goto done;
    }

    /* Search for iCal UID in recipient's calendars */
    caldavdb = caldav_open(userid, CALDAV_CREATE);
    if (!caldavdb) {
	sched_data->status = SCHEDSTAT_TEMPFAIL;
	goto done;
    }

    caldav_lookup_uid(caldavdb,
		      icalcomponent_get_uid(sched_data->ical), 0, &cdata);

    if (cdata->dav.mailbox) {
	mboxname = cdata->dav.mailbox;
	buf_setcstr(&resource, cdata->dav.resource);
    }
    else if (sched_data->is_reply) {
	/* Can't find object belonging to organizer - ignore reply */
	sched_data->status = SCHEDSTAT_PERMFAIL;
	goto done;
    }
    else {
	/* Can't find object belonging to attendee - use default calendar */
	caldav_mboxname(SCHED_DEFAULT, userid, namebuf);
	mboxname = namebuf;
	buf_reset(&resource);
	buf_printf(&resource, "%s.ics",
		   icalcomponent_get_uid(sched_data->ical));
    }

    /* Open recipient's calendar for reading */
    if ((r = mailbox_open_irl(mboxname, &mailbox))) {
	syslog(LOG_ERR, "mailbox_open_irl(%s) failed: %s",
	       mboxname, error_message(r));
	sched_data->status = SCHEDSTAT_TEMPFAIL;
	goto done;
    }

    if (!cdata->dav.imap_uid) {
	/* Create new object (copy of request w/o METHOD) */
	ical = icalcomponent_new_clone(sched_data->ical);

	prop = icalcomponent_get_first_property(ical, ICAL_METHOD_PROPERTY);
	icalcomponent_remove_property(ical, prop);
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
	method = icalcomponent_get_method(sched_data->ical);

	switch (method) {
	case ICAL_METHOD_CANCEL:
	    /* Set STATUS:CANCELLED on all components */
	    do {
		icalcomponent_set_status(comp, ICAL_STATUS_CANCELLED);
		icalcomponent_set_sequence(comp,
					   icalcomponent_get_sequence(comp)+1);
	    } while ((comp = icalcomponent_get_next_component(ical, kind)));

	    break;

	case ICAL_METHOD_REPLY: {
	    icalcomponent *itip;
	    icalparameter *param;
	    icalparameter_partstat partstat;
	    const char *attendee, *req_stat = SCHEDSTAT_SUCCESS;

	    itip = icalcomponent_get_first_component(sched_data->ical, kind);

	    prop = icalcomponent_get_first_property(itip,
						    ICAL_ATTENDEE_PROPERTY);
	    attendee = icalproperty_get_attendee(prop);
	    param = icalproperty_get_first_parameter(prop,
						     ICAL_PARTSTAT_PARAMETER);
	    partstat = icalparameter_get_partstat(param);

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
	    if (!prop) break;

	    /* Find and set PARTSTAT */
	    param =
		icalproperty_get_first_parameter(prop,
						 ICAL_PARTSTAT_PARAMETER);
	    if (!param) {
		param = icalparameter_new(ICAL_PARTSTAT_PARAMETER);
		icalproperty_add_parameter(prop, param);
	    }
	    icalparameter_set_partstat(param, partstat);

	    /* Find and set SCHEDULE-STATUS */
	    for (param = icalproperty_get_first_parameter(prop,
							  ICAL_IANA_PARAMETER);
		 param && strcmp(icalparameter_get_iana_name(param),
				 "SCHEDULE-STATUS");
		 param = icalproperty_get_next_parameter(prop,
							 ICAL_IANA_PARAMETER));
	    if (!param) {
		param = icalparameter_new(ICAL_IANA_PARAMETER);
		icalproperty_add_parameter(prop, param);
		icalparameter_set_iana_name(param, "SCHEDULE-STATUS");
	    }
	    icalparameter_set_iana_value(param, SCHEDSTAT_SUCCESS);

	    break;
	}

	case ICAL_METHOD_REQUEST:
	    /* XXX  Do merge logic */
	    syslog(LOG_INFO, "merge with existing sched object");
	    sched_data->status = SCHEDSTAT_TEMPFAIL;
	    goto inbox;
	    break;

	default:
	    /* Unknown METHOD -- ignore it */
	    syslog(LOG_ERR, "Unknown iTIP method: %s",
		   icalenum_method_to_string(method));
	    goto done;
	}
    }

    /* Store the (updated) object in the recipients's calendar */
    mailbox_unlock_index(mailbox, NULL);

    r = store_resource(&txn, ical, mailbox, buf_cstring(&resource),
		       caldavdb, OVERWRITE_YES, NEW_STAG);

    if (r == HTTP_CREATED || r == HTTP_NO_CONTENT) {
	sched_data->status = SCHEDSTAT_DELIVERED;
    }
    else {
	syslog(LOG_ERR, "store_resource(%s) failed: %s (%s)",
	       mailbox->name, error_message(r), txn.error.resource);
	sched_data->status = SCHEDSTAT_TEMPFAIL;
	goto done;
    }

  inbox:
    /* Create a name for the new iTIP message resource */
    buf_reset(&resource);
    buf_printf(&resource, "%x-%d-%ld-%u.ics",
	       strhash(icalcomponent_get_uid(sched_data->ical)), getpid(),
	       time(0), sched_count++);

    /* Store the message in the recipient's Inbox */
    mailbox_unlock_index(inbox, NULL);

    r = store_resource(&txn, sched_data->ical, inbox, buf_cstring(&resource),
		       caldavdb, OVERWRITE_NO, 0);
    /* XXX  What do we do if storing to Inbox fails? */

  done:
    if (ical) icalcomponent_free(ical);
    if (inbox) mailbox_close(&inbox);
    if (mailbox) mailbox_close(&mailbox);
    if (caldavdb) caldav_close(caldavdb);
}

static void free_sched_data(void *data) {
    struct sched_data *sched_data = (struct sched_data *) data;

    if (sched_data) {
	if (sched_data->ical) icalcomponent_free(sched_data->ical);
	if (sched_data->force_send) free(sched_data->force_send);
	free(sched_data);
    }
}

static void sched_request(const char *organizer, struct sched_param *sparam,
			  icalcomponent *oldical, icalcomponent *newical)
{
    int r, rights;
    struct mboxlist_entry mbentry;
    char outboxname[MAX_MAILBOX_BUFFER];
    icalcomponent *ical;
    icalproperty_method method;
//    icaltimezone *utc = icaltimezone_get_utc_timezone();
    static struct buf prodid = BUF_INITIALIZER;
    struct auth_state *authstate;
    icalcomponent *req, *copy, *comp;
    icalproperty *prop;
    icalcomponent_kind kind;
    struct hash_table att_table;
    unsigned ncomp;

    /* Check ACL of auth'd user on userid's Scheduling Outbox */
    caldav_mboxname(SCHED_OUTBOX, sparam->userid, outboxname);

    if ((r = mboxlist_lookup(outboxname, &mbentry, NULL))) {
	syslog(LOG_INFO, "mboxlist_lookup(%s) failed: %s",
	       outboxname, error_message(r));
	mbentry.acl = NULL;
    }

    rights =
	mbentry.acl ? cyrus_acl_myrights(httpd_authstate, mbentry.acl) : 0;
    if (!(rights & DACL_SCHED)) {
	/* DAV:need-privileges */
	if (newical) {
	    if (newical) {
		/* Set SCHEDULE-STATUS for each attendee in organizer object */
		comp = icalcomponent_get_first_real_component(newical);

		for (prop =
			 icalcomponent_get_first_property(comp,
							  ICAL_ATTENDEE_PROPERTY);
		     prop;
		     prop =
			 icalcomponent_get_next_property(comp,
							 ICAL_ATTENDEE_PROPERTY)) {
		    icalparameter *param = icalparameter_new(ICAL_IANA_PARAMETER);
		    icalparameter_set_iana_name(param, "SCHEDULE-STATUS");
		    icalparameter_set_iana_value(param, SCHEDSTAT_NOPRIVS);
		    icalproperty_add_parameter(prop, param);
		}
	    }
	}

	return;
    }

    construct_hash_table(&att_table, 10, 1);

    /* Check what kind of METHOD we are dealing with */
    if (!newical) {
	method = ICAL_METHOD_CANCEL;
	ical = oldical;
    }
    else {
	/* XXX  Need to handle modify */
	method = ICAL_METHOD_REQUEST;
	ical = newical;
    }

    /* Clone a working copy of the iCal object */
    copy = icalcomponent_new_clone(ical);

    /* Create a shell for our request iCal Objects */
    if (!buf_len(&prodid)) {
	buf_printf(&prodid, "-//CyrusIMAP.org/Cyrus %s//EN", cyrus_version());
    }

    req = icalcomponent_vanew(ICAL_VCALENDAR_COMPONENT,
			      icalproperty_new_version("2.0"),
			      icalproperty_new_prodid(buf_cstring(&prodid)),
			      icalproperty_new_method(method),
			      0);

    /* Copy over any CALSCALE property */
    prop = icalcomponent_get_first_property(copy, ICAL_CALSCALE_PROPERTY);
    if (prop) {
	icalcomponent_add_property(req,
				   icalproperty_new_clone(prop));
    }

    /* Copy over any VTIMEZONE components */
    for (comp = icalcomponent_get_first_component(copy,
						  ICAL_VTIMEZONE_COMPONENT);
	 comp;
	 comp = icalcomponent_get_next_component(copy,
						 ICAL_VTIMEZONE_COMPONENT)) {
	 icalcomponent_add_component(req,
				     icalcomponent_new_clone(comp));
    }

    /* XXX  Do we need to do more checks here? */
    if (sparam->flags & SCHEDTYPE_REMOTE)
	authstate = auth_newstate("anonymous");
    else
	authstate = auth_newstate(sparam->userid);

    /* Process each component */
    ncomp = 0;
    comp = icalcomponent_get_first_real_component(copy);
    kind = icalcomponent_isa(comp);
    do {
	icalcomponent *alarm, *next;

	/* Remove any VALARM components */
	for (alarm = icalcomponent_get_first_component(comp,
						       ICAL_VALARM_COMPONENT);
	     alarm; alarm = next) {
	    next = icalcomponent_get_next_component(comp,
						    ICAL_VALARM_COMPONENT);
	    icalcomponent_remove_component(comp, alarm);
	}
#if 0
	/* Replace DTSTAMP on component */
	prop = icalcomponent_get_first_property(comp, ICAL_DTSTAMP_PROPERTY);
	icalcomponent_remove_property(comp, prop);
	prop =
	    icalproperty_new_dtstamp(icaltime_from_timet_with_zone(now, 0, utc));
	icalcomponent_add_property(comp, prop);
#endif
	if (method == ICAL_METHOD_CANCEL) {
	    /* Deleting the object -- set STATUS to CANCELLED for component */
	    icalcomponent_set_status(comp, ICAL_STATUS_CANCELLED);
	    icalcomponent_set_sequence(comp,
				       icalcomponent_get_sequence(comp) + 1);
	}

	/* Process each attendee */
	for (prop = icalcomponent_get_first_property(comp,
						     ICAL_ATTENDEE_PROPERTY);
	     prop;
	     prop = icalcomponent_get_next_property(comp,
						    ICAL_ATTENDEE_PROPERTY)) {
	    const char *attendee = icalproperty_get_attendee(prop);
	    unsigned do_sched = 1;
	    icalparameter *param, *force_send = NULL;

	    /* Don't schedule attendee == organizer */
	    if (!strcmp(attendee, organizer)) continue;

	    /* Check CalDAV Scheduling parameters */
	    for (param = icalproperty_get_first_parameter(prop,
							  ICAL_IANA_PARAMETER);
		 param;
		 param = icalproperty_get_next_parameter(prop,
							 ICAL_IANA_PARAMETER)) {
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

	    /* Check if we are supposed to schedule for this attendee */
	    if (do_sched) {
		struct sched_data *sched_data;
		icalcomponent *new_comp;

		sched_data = hash_lookup(attendee, &att_table);
		if (!sched_data) {
		    /* New attendee - add it to the hash table */
		    sched_data = xzmalloc(sizeof(struct sched_data));
		    sched_data->ical = icalcomponent_new_clone(req);
		    if (force_send) {
			sched_data->force_send =
			    xstrdup(icalparameter_get_iana_value(force_send));
		    }
		    hash_insert(attendee, sched_data, &att_table);
		}
		new_comp = icalcomponent_new_clone(comp);
		icalcomponent_add_component(sched_data->ical, new_comp);
		sched_data->comp_mask |= (1 << ncomp);
		if (!ncomp) sched_data->master = new_comp;
	    }

	    if (force_send)
		icalproperty_remove_parameter_by_ref(prop, force_send);
	}

	if (ncomp) {
	    /* Handle any attendees that are excluded from this recurrence */
	    struct exclude_rock erock = { ncomp, comp };

	    hash_enumerate(&att_table, sched_exclude, &erock);
	}

	ncomp++;

    } while ((comp = icalcomponent_get_next_component(copy, kind)));

    /* Attempt to deliver requests to attendees */
    hash_enumerate(&att_table, sched_deliver, authstate);

    if (newical) {
	/* Set SCHEDULE-STATUS for each attendee in organizer object */
	comp = icalcomponent_get_first_real_component(newical);

	for (prop =
		 icalcomponent_get_first_property(comp, ICAL_ATTENDEE_PROPERTY);
	     prop;
	     prop =
		 icalcomponent_get_next_property(comp, ICAL_ATTENDEE_PROPERTY)) {
	    const char *attendee = icalproperty_get_attendee(prop);
	    struct sched_data *sched_data;

	    sched_data = hash_lookup(attendee, &att_table);
	    if (sched_data) {
		icalparameter *param = icalparameter_new(ICAL_IANA_PARAMETER);
		icalparameter_set_iana_name(param, "SCHEDULE-STATUS");
		icalparameter_set_iana_value(param, sched_data->status);
		icalproperty_add_parameter(prop, param);
	    }
	}
    }

    /* Cleanup */
    auth_freestate(authstate);
    icalcomponent_free(copy);
    icalcomponent_free(req);

    free_hash_table(&att_table, free_sched_data);
}

static void sched_reply(const char *userid,
			icalcomponent *oldical, icalcomponent *newical)
{
    int r, rights;
    struct mboxlist_entry mbentry;
    char outboxname[MAX_MAILBOX_BUFFER];
    icalcomponent *ical;
    icalproperty_method method;
    static struct buf prodid = BUF_INITIALIZER;
    struct sched_data *sched_data;
    struct auth_state *authstate;
    icalcomponent *copy, *comp;
    icalproperty *prop;
    icalparameter *param;
    icalcomponent_kind kind;
    const char *organizer;

    /* Check ACL of auth'd user on userid's Scheduling Outbox */
    caldav_mboxname(SCHED_OUTBOX, userid, outboxname);

    if ((r = mboxlist_lookup(outboxname, &mbentry, NULL))) {
	syslog(LOG_INFO, "mboxlist_lookup(%s) failed: %s",
	       outboxname, error_message(r));
	mbentry.acl = NULL;
    }

    rights =
	mbentry.acl ? cyrus_acl_myrights(httpd_authstate, mbentry.acl) : 0;
    if (!(rights & DACL_SCHED)) {
	/* DAV:need-privileges */
	if (newical) {
	    /* Set SCHEDULE-STATUS for organizer in attendee object */
	    comp = icalcomponent_get_first_real_component(newical);
	    prop = icalcomponent_get_first_property(comp, ICAL_ORGANIZER_PROPERTY);
	    param = icalparameter_new(ICAL_IANA_PARAMETER);
	    icalparameter_set_iana_name(param, "SCHEDULE-STATUS");
	    icalparameter_set_iana_value(param, SCHEDSTAT_NOPRIVS);
	    icalproperty_add_parameter(prop, param);
	}

	return;
    }

    sched_data = xzmalloc(sizeof(struct sched_data));
    sched_data->is_reply = 1;

    method = ICAL_METHOD_REPLY;

    /* Check what kind of reply we are dealing with */
    if (!newical) {
	ical = oldical;
    }
    else {
	/* XXX  Need to handle modify */
	ical = newical;
    }

    /* Create our reply iCal object */
    if (!buf_len(&prodid)) {
	buf_printf(&prodid, "-//CyrusIMAP.org/Cyrus %s//EN", cyrus_version());
    }

    sched_data->ical =
	icalcomponent_vanew(ICAL_VCALENDAR_COMPONENT,
			    icalproperty_new_version("2.0"),
			    icalproperty_new_prodid(buf_cstring(&prodid)),
			    icalproperty_new_method(method),
			    0);

    /* Clone a working copy of the iCal object */
    copy = icalcomponent_new_clone(ical);

    /* Copy over any CALSCALE property */
    prop = icalcomponent_get_first_property(copy, ICAL_CALSCALE_PROPERTY);
    if (prop) {
	icalcomponent_add_property(sched_data->ical,
				   icalproperty_new_clone(prop));
    }

    /* Copy over any VTIMEZONE components */
    for (comp = icalcomponent_get_first_component(copy,
						  ICAL_VTIMEZONE_COMPONENT);
	 comp;
	 comp = icalcomponent_get_next_component(copy,
						 ICAL_VTIMEZONE_COMPONENT)) {
	 icalcomponent_add_component(sched_data->ical,
				     icalcomponent_new_clone(comp));
    }

    authstate = auth_newstate(userid);

    /* Process each component */
    comp = icalcomponent_get_first_real_component(copy);
    kind = icalcomponent_isa(comp);
    prop = icalcomponent_get_first_property(comp, ICAL_ORGANIZER_PROPERTY);
    organizer = icalproperty_get_organizer(prop);
    do {
	icalcomponent *alarm, *nextcomp;
	icalproperty *nextprop, *myattendee = NULL;

	/* Remove any VALARM components */
	for (alarm = icalcomponent_get_first_component(comp,
						       ICAL_VALARM_COMPONENT);
	     alarm; alarm = nextcomp) {
	    nextcomp = icalcomponent_get_next_component(comp,
						    ICAL_VALARM_COMPONENT);
	    icalcomponent_remove_component(comp, alarm);
	}

	/* See if userid is in attendee list (stripping others) */
	for (prop = icalcomponent_get_first_property(comp,
						     ICAL_ATTENDEE_PROPERTY);
	     prop;
	     prop = nextprop) {
	    const char *attendee = icalproperty_get_attendee(prop);
	    struct sched_param sparam;

	    nextprop = icalcomponent_get_next_property(comp,
						   ICAL_ATTENDEE_PROPERTY);

	    if (!caladdress_lookup(attendee, &sparam) &&
		!(sparam.flags & SCHEDTYPE_REMOTE) &&
		!strcmp(sparam.userid, userid)) {
		/* Found it */
		myattendee = prop;
	    }
	    else {
		/* Some other attendee, remove it */
		icalcomponent_remove_property(comp, prop);
	    }
	}

	if (myattendee) {
	    /* Found our userid */
	    unsigned do_sched = 1;
	    icalparameter *force_send = NULL;

	    /* Grab the organizer */
	    prop = icalcomponent_get_first_property(comp,
						    ICAL_ORGANIZER_PROPERTY);

	    /* Check CalDAV Scheduling parameters */
	    for (param = icalproperty_get_first_parameter(prop,
							  ICAL_IANA_PARAMETER);
		 param;
		 param = icalproperty_get_next_parameter(prop,
							 ICAL_IANA_PARAMETER)) {
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

	    /* Check if we are supposed to schedule for the organizer */
	    if (do_sched) {
		icalcomponent *new_comp;

		if (force_send) {
		    if (!sched_data->force_send) {
			sched_data->force_send =
			    xstrdup(icalparameter_get_iana_value(force_send));
		    }

		    icalproperty_remove_parameter_by_ref(prop, force_send);
		}

		if (!newical) {
		    /* Attendee is deleting the object, set PARTSTAT:DECLINED */
		    param =
			icalproperty_get_first_parameter(myattendee,
							 ICAL_PARTSTAT_PARAMETER);
		    if (param) {
			icalproperty_remove_parameter_by_ref(myattendee, param);
		    }
		    param = icalparameter_new(ICAL_PARTSTAT_PARAMETER);
		    icalproperty_add_parameter(myattendee, param);
		    icalparameter_set_partstat(param, ICAL_PARTSTAT_DECLINED);
		}

		new_comp = icalcomponent_new_clone(comp);
		icalcomponent_add_component(sched_data->ical, new_comp);
	    }
	}

    } while ((comp = icalcomponent_get_next_component(copy, kind)));

    /* Attempt to deliver reply to organizer */
    sched_deliver((char *) organizer, sched_data, authstate);

    if (newical) {
	/* Set SCHEDULE-STATUS for organizer in attendee object */
	comp = icalcomponent_get_first_real_component(newical);
	prop = icalcomponent_get_first_property(comp, ICAL_ORGANIZER_PROPERTY);
	param = icalparameter_new(ICAL_IANA_PARAMETER);
	icalparameter_set_iana_name(param, "SCHEDULE-STATUS");
	icalparameter_set_iana_value(param, sched_data->status);
	icalproperty_add_parameter(prop, param);
    }

    /* Cleanup */
    auth_freestate(authstate);
    icalcomponent_free(copy);
    free_sched_data(sched_data);
}
#endif /* WITH_CALDAV_SCHED */
