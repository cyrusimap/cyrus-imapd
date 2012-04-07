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
 *   - Rewrite COPY/MOVE to use guts of PUT.  Current code doesn't rewrite
 *     Content-Disposition to have new filename.
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

#include "acl.h"
#include "append.h"
#include "caldav_db.h"
#include "dav_prop.h"
#include "global.h"
#include "httpd.h"
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
#include "spool.h"
#include "stristr.h"
#include "util.h"
#include "version.h"
#include "xmalloc.h"
#include "xstrlcat.h"
#include "xstrlcpy.h"

#define DFLAG_UNBIND "DAV:unbind"

static int meth_acl(struct transaction_t *txn);
static int meth_copy(struct transaction_t *txn);
static int meth_delete(struct transaction_t *txn);
static int meth_get(struct transaction_t *txn);
static int meth_mkcol(struct transaction_t *txn);
static int meth_proppatch(struct transaction_t *txn);
static int meth_post(struct transaction_t *txn);
static int meth_put(struct transaction_t *txn);
static int meth_report(struct transaction_t *txn);
static int parse_path(struct request_target_t *tgt, const char **errstr);
static int is_mediatype(const char *hdr, const char *type);
static int parse_xml_body(struct transaction_t *txn, xmlNodePtr *root);
static icalcomponent *do_fb_query(struct transaction_t *txn,
				  struct propfind_ctx *fctx,
				  char mailboxname[],
				  icalproperty_method method,
				  const char *uid,
				  const char *organizer,
				  const char *attendee);
static int sched_busytime(struct transaction_t *txn);
int target_to_mboxname(struct request_target_t *req_tgt, char *mboxname);

/* Namespace for CalDAV collections */
const struct namespace_t namespace_calendar = {
    URL_NS_CALENDAR, "/calendars", 1 /* auth */,
    (ALLOW_READ | ALLOW_WRITE | ALLOW_DAV | ALLOW_CAL),
    { 
	&meth_acl,		/* ACL		*/
	&meth_copy,		/* COPY		*/
	&meth_delete,		/* DELETE	*/
	&meth_get,		/* GET		*/
	&meth_get,		/* HEAD		*/
	NULL,			/* LOCK		*/
	&meth_mkcol,		/* MKCALENDAR	*/
	&meth_mkcol,		/* MKCOL	*/
	&meth_copy,		/* MOVE		*/
	&meth_options,		/* OPTIONS	*/
	&meth_post,		/* POST		*/
	&meth_propfind,		/* PROPFIND	*/
	&meth_proppatch,	/* PROPPATCH	*/
	&meth_put,		/* PUT		*/
	&meth_report,		/* REPORT	*/
	NULL			/* UNLOCK	*/
    }
};

/* Namespace for WebDAV principals */
const struct namespace_t namespace_principal = {
    URL_NS_PRINCIPAL, "/principals", 1 /* auth */,
    (ALLOW_DAV | ALLOW_CAL | ALLOW_CARD),
    {
	NULL,			/* ACL		*/
	NULL,			/* COPY		*/
	NULL,			/* DELETE	*/
	NULL,			/* GET		*/
	NULL,			/* HEAD		*/
	NULL,			/* LOCK		*/
	NULL,			/* MKCALENDAR	*/
	NULL,			/* MKCOL	*/
	NULL,			/* MOVE		*/
	&meth_options,		/* OPTIONS	*/
	NULL,			/* POST		*/
	&meth_propfind,		/* PROPFIND	*/
	NULL,			/* PROPPATCH	*/
	NULL,			/* PUT		*/
	&meth_report,		/* REPORT	*/
	NULL			/* UNLOCK	*/
    }
};


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
 */
static int meth_acl(struct transaction_t *txn)
{
    int ret = 0, r, rights, is_inbox = 0, is_outbox = 0;
    xmlDocPtr indoc = NULL;
    xmlNodePtr root, ace;
    char *server, *aclstr, mailboxname[MAX_MAILBOX_BUFFER];
    struct mailbox *mailbox = NULL;
    struct buf acl = BUF_INITIALIZER;

    /* Make sure its a DAV resource */
    if (!(txn->req_tgt.allow & ALLOW_WRITE)) return HTTP_NOT_ALLOWED;

    /* Parse the path */
    if ((r = parse_path(&txn->req_tgt, &txn->error.desc))) return r;

    /* Make sure its a calendar collection */
    if (!txn->req_tgt.collection || txn->req_tgt.resource) {
	txn->error.desc = "ACLs can only be set on calendar collections";
	syslog(LOG_DEBUG, "Tried to set ACL on non-calendar collection");
	return HTTP_NOT_ALLOWED;
    }

    /* Construct mailbox name corresponding to request target URI */
    (void) target_to_mboxname(&txn->req_tgt, mailboxname);

    /* Locate the mailbox */
    if ((r = http_mlookup(mailboxname, &server, &aclstr, NULL))) {
	syslog(LOG_ERR, "mlookup(%s) failed: %s",
	       mailboxname, error_message(r));
	txn->error.desc = error_message(r);

	switch (r) {
	case IMAP_PERMISSION_DENIED: return HTTP_FORBIDDEN;
	case IMAP_MAILBOX_NONEXISTENT: return HTTP_NOT_FOUND;
	default: return HTTP_SERVER_ERROR;
	}
    }

    /* Check ACL for current user */
    rights =  aclstr ? cyrus_acl_myrights(httpd_authstate, aclstr) : 0;
    if (!(rights & DACL_ADMIN)) {
	/* DAV:need-privileges */
	txn->error.precond = &preconds[DAV_NEED_PRIVS];
	txn->error.resource = txn->req_tgt.path;
	txn->error.rights = DACL_ADMIN;
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

    /* Response should not be cached */
    txn->flags |= HTTP_NOCACHE;

    /* Open mailbox for writing */
    if ((r = http_mailbox_open(mailboxname, &mailbox, LOCK_EXCLUSIVE))) {
	syslog(LOG_ERR, "http_mailbox_open(%s) failed: %s",
	       mailboxname, error_message(r));
	txn->error.desc = error_message(r);
	ret = HTTP_SERVER_ERROR;
	goto done;
    }

    /* Parse the ACL body */
    ret = parse_xml_body(txn, &root);
    if (!root) {
	txn->error.desc = "Missing request body";
	ret = HTTP_BAD_REQUEST;
    }
    if (ret) goto done;

    indoc = root->doc;

    /* Make sure its an DAV:acl element */
    if (xmlStrcmp(root->name, BAD_CAST "acl")) {
	txn->error.desc = "Missing acl element in ACL request";
	ret = HTTP_BAD_REQUEST;
	goto done;
    }

    /* See if its a scheduling collection */
    if (!strcmp(txn->req_tgt.collection, SCHED_INBOX)) is_inbox++;
    else if (!strcmp(txn->req_tgt.collection, SCHED_INBOX)) is_outbox++;

    /* Parse the DAV:ace elements */
    for (ace = root->children; ace; ace = ace->next) {
	if (ace->type == XML_ELEMENT_NODE) {
	    xmlNodePtr child = NULL, prin = NULL, privs = NULL;
	    const char *userid = NULL;
	    int deny = 0, rights = 0;
	    char rightstr[100];

	    for (child = ace->children; child; child = child->next) {
		if (child->type == XML_ELEMENT_NODE) {
		    if (!xmlStrcmp(child->name, BAD_CAST "principal")) {
			if (prin) {
			    txn->error.desc = "Multiple principals in ACE";
			    ret = HTTP_BAD_REQUEST;
			    goto done;
			}

			for (prin = child->children;
			     prin->type != XML_ELEMENT_NODE; prin = prin->next);
		    }
		    else if (!xmlStrcmp(child->name, BAD_CAST "grant")) {
			if (privs) {
			    txn->error.desc = "Multiple grant|deny in ACE";
			    ret = HTTP_BAD_REQUEST;
			    goto done;
			}

			for (privs = child->children;
			     privs->type != XML_ELEMENT_NODE; privs = privs->next);
		    }
		    else if (!xmlStrcmp(child->name, BAD_CAST "deny")) {
			if (privs) {
			    txn->error.desc = "Multiple grant|deny in ACE";
			    ret = HTTP_BAD_REQUEST;
			    goto done;
			}

			for (privs = child->children;
			     privs->type != XML_ELEMENT_NODE; privs = privs->next);
			deny = 1;
		    }
		    else if (!xmlStrcmp(child->name, BAD_CAST "invert")) {
			/* DAV:no-invert */
			txn->error.precond = &preconds[DAV_NO_INVERT];
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
#if 0  /* XXX  Do we need to support this? */
	    else if (!xmlStrcmp(prin->name, BAD_CAST "owner")) {
		/* XXX construct userid from mailbox name */
	    }
#endif
	    else if (!xmlStrcmp(prin->name, BAD_CAST "authenticated")) {
		userid = "anyone";
	    }
	    else if (!xmlStrcmp(prin->name, BAD_CAST "href")) {
		xmlChar *href = xmlNodeGetContent(prin);
		struct request_target_t uri;
		const char *errstr = NULL;

		r = parse_uri(NULL, (const char *) href, &uri, &errstr);
		if (!r &&
		    !strncmp("/principals/", uri.path, strlen("/principals/"))) {
		    uri.namespace = URL_NS_PRINCIPAL;
		    r = parse_path(&uri, &errstr);
		    if (!r && uri.user) userid = uri.user;
		}
		xmlFree(href);
	    }

	    if (!userid) {
		/* DAV:recognized-principal */
		txn->error.precond = &preconds[DAV_RECOG_PRINC];
		ret = HTTP_FORBIDDEN;
		goto done;
	    }

	    for (; privs; privs = privs->next) {
		if (privs->type == XML_ELEMENT_NODE) {
		    xmlNodePtr priv = privs->children;
		    for (; priv->type != XML_ELEMENT_NODE; priv = priv->next);

		    if (!xmlStrcmp(priv->ns->href,
				   BAD_CAST XML_NS_DAV)) {
			/* WebDAV privileges */
			if (!xmlStrcmp(priv->name,
				       BAD_CAST "all")) {
			    rights |= DACL_ALL | DACL_READFB;
			    if (is_inbox || is_outbox) rights |= DACL_SCHED;
			}
			else if (!xmlStrcmp(priv->name,
					    BAD_CAST "read"))
			    rights |= DACL_READ | DACL_READFB;
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
					       BAD_CAST "unlock")) {
			    /* DAV:no-abstract */
			    txn->error.precond = &preconds[DAV_NO_ABSTRACT];
			    ret = HTTP_FORBIDDEN;
			    goto done;
			}
			else {
			    /* DAV:not-supported-privilege */
			    txn->error.precond = &preconds[DAV_SUPP_PRIV];
			    ret = HTTP_FORBIDDEN;
			    goto done;
			}
		    }

		    else if (!xmlStrcmp(priv->ns->href,
					BAD_CAST XML_NS_CALDAV)) {
			/* CalDAV privileges */
			if (!xmlStrcmp(priv->name,
				       BAD_CAST "read-free-busy"))
			    rights |= DACL_READFB;
			else if (is_inbox &&
				 !xmlStrcmp(priv->name,
					    BAD_CAST "schedule-deliver"))
			    rights |= DACL_SCHED;
			else if (is_outbox &&
				 !xmlStrcmp(priv->name,
					    BAD_CAST "schedule-send"))
			    rights |= DACL_SCHED;
			else if (!xmlStrcmp(priv->name,
					    BAD_CAST "schedule-deliver-invite")
				 || !xmlStrcmp(priv->name,
					       BAD_CAST "schedule-deliver-reply")
				 || !xmlStrcmp(priv->name,
					       BAD_CAST "schedule-query-freebusy")
				 || !xmlStrcmp(priv->name,
					       BAD_CAST "schedule-send-invite")
				 || !xmlStrcmp(priv->name,
					       BAD_CAST "schedule-send-reply")
				 || !xmlStrcmp(priv->name,
					       BAD_CAST "schedule-send-freebusy")) {
			    /* DAV:no-abstract */
			    txn->error.precond = &preconds[DAV_NO_ABSTRACT];
			    ret = HTTP_FORBIDDEN;
			    goto done;
			}
			else {
			    /* DAV:not-supported-privilege */
			    txn->error.precond = &preconds[DAV_SUPP_PRIV];
			    ret = HTTP_FORBIDDEN;
			    goto done;
			}
		    }

		    else if (!xmlStrcmp(priv->ns->href,
				   BAD_CAST XML_NS_CYRUS)) {
			/* Cyrus-specific privileges */
			if (!xmlStrcmp(priv->name,
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
			    txn->error.precond = &preconds[DAV_SUPP_PRIV];
			    ret = HTTP_FORBIDDEN;
			    goto done;
			}
		    }
		    else {
			/* DAV:not-supported-privilege */
			txn->error.precond = &preconds[DAV_SUPP_PRIV];
			ret = HTTP_FORBIDDEN;
			goto done;
		    }
		}
	    }

	    cyrus_acl_masktostr(rights, rightstr);
	    buf_printf(&acl, "%s%s\t%s\t",
		       deny ? "-" : "", userid, rightstr);
	}
    }

    if ((r = mboxlist_sync_setacls(mailboxname, buf_cstring(&acl)))) {
	syslog(LOG_ERR, "mboxlist_sync_setacls(%s) failed: %s",
	       mailboxname, error_message(r));
	txn->error.desc = error_message(r);
	ret = HTTP_SERVER_ERROR;
	goto done;
    }
    mailbox_set_acl(mailbox, buf_cstring(&acl), 0);

    response_header(HTTP_OK, txn);

  done:
    buf_free(&acl);
    if (indoc) xmlFreeDoc(indoc);
    if (mailbox) mailbox_unlock_index(mailbox, NULL);

    return ret;
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
static int meth_copy(struct transaction_t *txn)
{
    int ret = HTTP_CREATED, r, precond, rights;
    const char **hdr;
    struct request_target_t dest;  /* Parsed destination URL */
    char src_mboxname[MAX_MAILBOX_BUFFER], dest_mboxname[MAX_MAILBOX_BUFFER];
    char *server, *acl;
    struct backend *src_be = NULL, *dest_be = NULL;
    struct mailbox *src_mbox = NULL, *dest_mbox = NULL;
    struct caldav_db *src_caldb = NULL, *dest_caldb = NULL;
    uint32_t src_uid = 0, olduid = 0;
    struct index_record src_rec;
    const char *etag = NULL;
    time_t lastmod = 0;
    struct appendstate appendstate;

    /* Response should not be cached */
    txn->flags |= HTTP_NOCACHE;

    /* Make sure source is a DAV resource */
    if (!(txn->req_tgt.allow & ALLOW_DAV)) return HTTP_NOT_ALLOWED;

    /* Parse the path */
    if ((r = parse_path(&txn->req_tgt, &txn->error.desc))) return r;

    /* We don't yet handle COPY/MOVE on collections */
    if (!txn->req_tgt.resource) return HTTP_NOT_ALLOWED;

    /* Check for mandatory Destination header */
    if (!(hdr = spool_getheader(txn->req_hdrs, "Destination"))) {
	txn->error.desc = "Missing Destination header";
	return HTTP_BAD_REQUEST;
    }

    /* Parse destination URI */
    if ((r = parse_uri(NULL, hdr[0], &dest, &txn->error.desc))) return r;

    /* Check namespace */
    if (strncmp("/calendars/", dest.path, strlen("/calendars/")))
	return HTTP_FORBIDDEN;

    dest.namespace = URL_NS_CALENDAR;
    if ((r = parse_path(&dest, &txn->error.desc))) return r;

    /* Make sure dest resource is in same namespace as source */
    if (txn->req_tgt.namespace != dest.namespace) return HTTP_FORBIDDEN;

    /* Make sure source and dest resources are NOT the same */
    if (!strcmp(txn->req_tgt.path, dest.path)) {
	txn->error.desc = "Source and destination resources are the same";
	return HTTP_FORBIDDEN;
    }

    /* Construct source mailbox name corresponding to request target URI */
    (void) target_to_mboxname(&txn->req_tgt, src_mboxname);

    /* Locate the source mailbox */
    if ((r = http_mlookup(src_mboxname, &server, &acl, NULL))) {
	syslog(LOG_ERR, "mlookup(%s) failed: %s",
	       src_mboxname, error_message(r));
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
	((txn->meth[0] == 'M') && !(rights & DACL_RMRSRC))) {
	/* DAV:need-privileges */
	txn->error.precond = &preconds[DAV_NEED_PRIVS];
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

    /* Construct dest mailbox name corresponding to destination URI */
    (void) target_to_mboxname(&dest, dest_mboxname);

    /* Locate the destination mailbox */
    if ((r = http_mlookup(dest_mboxname, &server, &acl, NULL))) {
	syslog(LOG_ERR, "mlookup(%s) failed: %s",
	       dest_mboxname, error_message(r));
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
	txn->error.precond = &preconds[DAV_NEED_PRIVS];
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

    /* Open source mailbox for reading */
    if ((r = http_mailbox_open(src_mboxname, &src_mbox, LOCK_SHARED))) {
	syslog(LOG_ERR, "http_mailbox_open(%s) failed: %s",
	       src_mboxname, error_message(r));
	txn->error.desc = error_message(r);
	ret = HTTP_SERVER_ERROR;
	goto done;
    }

    /* Open the associated CalDAV database */
    if ((r = caldav_open(src_mbox, 0, &src_caldb))) {
	syslog(LOG_ERR, "caldav_open(%s) failed: %s",
	       src_mboxname, error_message(r));
	txn->error.desc = error_message(r);
	ret = HTTP_SERVER_ERROR;
	goto done;
    }

    /* Find message UID for the source resource */
    caldav_read(src_caldb, txn->req_tgt.resource, &src_uid);

    /* Fetch index record for the source resource */
    if (!src_uid || mailbox_find_index_record(src_mbox, src_uid, &src_rec)) {
	ret = HTTP_NOT_FOUND;
	goto done;
    }

    /* Check any preconditions on source */
    etag = message_guid_encode(&src_rec.guid);
    lastmod = src_rec.internaldate;
    precond = check_precond(txn->meth, etag, lastmod, txn->req_hdrs);

    if (precond != HTTP_OK) {
	/* We failed a precondition - don't perform the request */
	ret = precond;
	goto done;
    }

    /* Local Mailbox */

    /* Fetch cache record for the source resource (so we can copy it) */
    if ((r = mailbox_cacherecord(src_mbox, &src_rec))) {
	syslog(LOG_ERR, "mailbox_cacherecord(%s) failed: %s",
	       src_mboxname, error_message(r));
	txn->error.desc = error_message(r);
	ret = HTTP_SERVER_ERROR;
	goto done;
    }

    /* Finished our initial read of source mailbox */
    mailbox_unlock_index(src_mbox, NULL);

    /* Open dest mailbox for reading */
    if ((r = mailbox_open_irl(dest_mboxname, &dest_mbox))) {
	syslog(LOG_ERR, "mailbox_open_irl(%s) failed: %s",
	       dest_mboxname, error_message(r));
	txn->error.desc = error_message(r);
	ret = HTTP_SERVER_ERROR;
	goto done;
    }

    /* Open the associated CalDAV database */
    if ((r = caldav_open(dest_mbox, CALDAV_CREATE, &dest_caldb))) {
	syslog(LOG_ERR, "caldav_open(%s) failed: %s",
	       dest_mboxname, error_message(r));
	txn->error.desc = error_message(r);
	ret = HTTP_SERVER_ERROR;
	goto done;
    }

    /* Find message UID for the dest resource, if exists */
    caldav_read(dest_caldb, dest.resource, &olduid);
    /* XXX  Check errors */

    /* Finished our initial read of dest mailbox */
    mailbox_unlock_index(dest_mbox, NULL);

    /* Check any preconditions on destination */
    if (olduid && (hdr = spool_getheader(txn->req_hdrs, "Overwrite")) &&
	!strcmp(hdr[0], "F")) {
	/* Don't overwrite the destination resource */
	ret = HTTP_PRECOND_FAILED;
	goto done;
    }

    /* Prepare to append source resource to destination mailbox */
    if ((r = append_setup(&appendstate, dest_mboxname, 
			  httpd_userid, httpd_authstate, ACL_INSERT,
			  (txn->meth[0]) == 'C' ? (long) src_rec.size : -1))) {
	syslog(LOG_ERR, "append_setup(%s) failed: %s",
	       dest_mboxname, error_message(r));
	ret = HTTP_SERVER_ERROR;
	txn->error.desc = "append_setup() failed";
    }
    else {
	struct copymsg copymsg;
	int flag = 0, userflag;
	bit32 flagmask = 0;

	/* Copy the resource */
	copymsg.uid = src_rec.uid;
	copymsg.internaldate = src_rec.internaldate;
	copymsg.sentdate = src_rec.sentdate;
	copymsg.gmtime = src_rec.gmtime;
	copymsg.size = src_rec.size;
	copymsg.header_size = src_rec.header_size;
	copymsg.content_lines = src_rec.content_lines;
	copymsg.cache_version = src_rec.cache_version;
	copymsg.cache_crc = src_rec.cache_crc;
	copymsg.crec = src_rec.crec;
	message_guid_copy(&copymsg.guid, &src_rec.guid);
	copymsg.system_flags = src_rec.system_flags;

	for (userflag = 0; userflag < MAX_USER_FLAGS; userflag++) {
	    if ((userflag & 31) == 0) {
		flagmask = src_rec.user_flags[userflag/32];
	    }
	    if (src_mbox->flagname[userflag] && (flagmask & (1<<(userflag&31)))) {
		copymsg.flag[flag++] = src_mbox->flagname[userflag];
	    }
	}
	copymsg.flag[flag] = 0;
	copymsg.seen = 0;  /* XXX */

	if ((r = append_copy(src_mbox, &appendstate, 1, &copymsg, 0))) {
	    syslog(LOG_ERR, "append_copy(%s->%s) failed: %s",
		   src_mboxname, dest_mboxname, error_message(r));
	    ret = HTTP_SERVER_ERROR;
	    txn->error.desc = "append_copy() failed";
	}

	if (r) append_abort(&appendstate);
	else {
	    struct mailbox *lock_mbox = NULL;

	    /* Commit the append to the destination mailbox */
	    if ((r = append_commit(&appendstate, -1,
				   NULL, NULL, NULL, &lock_mbox))) {
		syslog(LOG_ERR, "append_commit(%s) failed: %s",
		       dest_mboxname, error_message(r));
		ret = HTTP_SERVER_ERROR;
		txn->error.desc = "append_commit() failed";
	    }
	    else {
		/* append_commit() returns a write-locked index */
		struct index_record newrecord, oldrecord;

		/* Read index record for new message (always the last one) */
		mailbox_read_index_record(lock_mbox, lock_mbox->i.num_records,
					  &newrecord);

		/* Find message UID for the dest resource, if exists */
		caldav_lockread(dest_caldb, dest.resource, &olduid);
		/* XXX  check for errors */

		if (olduid) {
		    /* Now that we have the replacement message in place
		       and the mailbox locked, re-read the old record
		       and expunge it.
		    */
		    ret = HTTP_NO_CONTENT;

		    /* Fetch index record for the old message */
		    r = mailbox_find_index_record(lock_mbox, olduid, &oldrecord);

		    /* Expunge the old message */
		    if (!r) r = mailbox_user_flag(lock_mbox, DFLAG_UNBIND,
						  &userflag);
		    if (!r) {
			oldrecord.user_flags[userflag/32] |= 1<<(userflag&31);
			oldrecord.system_flags |= FLAG_EXPUNGED | FLAG_UNLINKED;
			r = mailbox_rewrite_index_record(lock_mbox, &oldrecord);
		    }
		    if (r) {
			syslog(LOG_ERR,
			       "expunging old dest record (%s) failed: %s",
			       dest_mboxname, error_message(r));
			txn->error.desc = error_message(r);
			ret = HTTP_SERVER_ERROR;
			goto done;
		    }
		}

		/* Create mapping entry from dest resource name to UID */
		caldav_write(dest_caldb, dest.resource, newrecord.uid);
		/* XXX  check for errors, if this fails, backout changes */
		caldav_unlock(dest_caldb);

		/* append_setup() opened mailbox again,
		   we need to close it to decrement reference count */
		mailbox_close(&lock_mbox);

		/* Tell client about the new resource */
		txn->resp_body.etag = message_guid_encode(&newrecord.guid);
	    }
	}
    }

    /* For MOVE, we need to delete the source resource */
    if (!r && (txn->meth[0] == 'M')) {
	/* Lock source mailbox */
	mailbox_lock_index(src_mbox, LOCK_EXCLUSIVE);

	/* Find message UID for the source resource */
	caldav_lockread(src_caldb, txn->req_tgt.resource, &src_uid);
	/* XXX  Check errors */

	/* Fetch index record for the source resource */
	if (src_uid &&
	    !mailbox_find_index_record(src_mbox, src_uid, &src_rec)) {

	    /* Expunge the source message */
	    src_rec.system_flags |= FLAG_EXPUNGED;
	    if ((r = mailbox_rewrite_index_record(src_mbox, &src_rec))) {
		syslog(LOG_ERR, "expunging src record (%s) failed: %s",
		       src_mboxname, error_message(r));
		txn->error.desc = error_message(r);
		ret = HTTP_SERVER_ERROR;
		goto done;
	    }
	}

	/* Delete mapping entry for source resource name */
	caldav_delete(src_caldb, txn->req_tgt.resource);
    }

  done:
    if (dest_caldb) caldav_close(dest_caldb);
    if (dest_mbox) mailbox_close(&dest_mbox);
    if (src_caldb) caldav_close(src_caldb);
    if (src_mbox) mailbox_unlock_index(src_mbox, NULL);

    return ret;
}


/* Perform a DELETE request */
static int meth_delete(struct transaction_t *txn)
{
    int ret = HTTP_NO_CONTENT, r, precond, rights;
    char *server, *acl, mailboxname[MAX_MAILBOX_BUFFER];
    struct mailbox *mailbox = NULL;
    struct caldav_db *caldavdb = NULL;
    uint32_t uid = 0;
    struct index_record record;
    const char *etag = NULL;
    time_t lastmod = 0;

    /* Make sure its a DAV resource */
    if (!(txn->req_tgt.allow & ALLOW_WRITE)) return HTTP_NOT_ALLOWED; 

    /* Parse the path */
    if ((r = parse_path(&txn->req_tgt, &txn->error.desc))) return r;

    /* Construct mailbox name corresponding to request target URI */
    (void) target_to_mboxname(&txn->req_tgt, mailboxname);

    /* Locate the mailbox */
    if ((r = http_mlookup(mailboxname, &server, &acl, NULL))) {
	syslog(LOG_ERR, "mlookup(%s) failed: %s",
	       mailboxname, error_message(r));
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
	txn->error.precond = &preconds[DAV_NEED_PRIVS];
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
	r = mboxlist_deletemailbox(mailboxname,
				   httpd_userisadmin || httpd_userisproxyadmin,
				   httpd_userid, httpd_authstate,
				   1, 0, 0);

	if (r == IMAP_PERMISSION_DENIED) ret = HTTP_FORBIDDEN;
	else if (r == IMAP_MAILBOX_NONEXISTENT) ret = HTTP_NOT_FOUND;
	else if (r) ret = HTTP_SERVER_ERROR;

	return ret;
    }


    /* DELETE resource */

    /* Open mailbox for writing */
    if ((r = http_mailbox_open(mailboxname, &mailbox, LOCK_EXCLUSIVE))) {
	syslog(LOG_ERR, "http_mailbox_open(%s) failed: %s",
	       mailboxname, error_message(r));
	txn->error.desc = error_message(r);
	ret = HTTP_SERVER_ERROR;
	goto done;
    }

    /* Open the associated CalDAV database */
    if ((r = caldav_open(mailbox, CALDAV_CREATE, &caldavdb))) {
	txn->error.desc = error_message(r);
	ret = HTTP_SERVER_ERROR;
	goto done;
    }

    /* Find message UID for the resource */
    caldav_lockread(caldavdb, txn->req_tgt.resource, &uid);

    /* Fetch index record for the resource */
    if (!uid || mailbox_find_index_record(mailbox, uid, &record)) {
	ret = HTTP_NOT_FOUND;
	goto done;
    }

    etag = message_guid_encode(&record.guid);
    lastmod = record.internaldate;

    /* Check any preconditions */
    precond = check_precond(txn->meth, etag, lastmod, txn->req_hdrs);

    /* We failed a precondition - don't perform the request */
    if (precond != HTTP_OK) {
	ret = precond;
	goto done;
    }

    /* Expunge the resource */
    record.system_flags |= FLAG_EXPUNGED;

    if ((r = mailbox_rewrite_index_record(mailbox, &record))) {
	syslog(LOG_ERR, "expunging record (%s) failed: %s",
	       mailboxname, error_message(r));
	txn->error.desc = error_message(r);
	ret = HTTP_SERVER_ERROR;
	goto done;
    }

    /* Delete mapping entry for resource name */
    caldav_delete(caldavdb, txn->req_tgt.resource);

  done:
    if (caldavdb) caldav_close(caldavdb);
    if (mailbox) mailbox_unlock_index(mailbox, NULL);

    return ret;
}


/* Perform a GET/HEAD request */
static int meth_get(struct transaction_t *txn)
{
    int ret = 0, r, precond, rights;
    const char *msg_base = NULL;
    unsigned long msg_size = 0;
    struct resp_body_t *resp_body = &txn->resp_body;
    char *server, *acl, mailboxname[MAX_MAILBOX_BUFFER];
    struct mailbox *mailbox = NULL;
    struct caldav_db *caldavdb = NULL;
    uint32_t uid = 0;
    struct index_record record;
    time_t lastmod = 0;

    /* Parse the path */
    if ((r = parse_path(&txn->req_tgt, &txn->error.desc))) return r;

    /* We don't handle GET on a calendar collection (yet) */
    if (!txn->req_tgt.resource) return HTTP_NO_CONTENT;

    /* Construct mailbox name corresponding to request target URI */
    (void) target_to_mboxname(&txn->req_tgt, mailboxname);

    /* Locate the mailbox */
    if ((r = http_mlookup(mailboxname, &server, &acl, NULL))) {
	syslog(LOG_ERR, "mlookup(%s) failed: %s",
	       mailboxname, error_message(r));
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
	txn->error.precond = &preconds[DAV_NEED_PRIVS];
	txn->error.resource = txn->req_tgt.path;
	txn->error.rights = DACL_READ;
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
    if ((r = http_mailbox_open(mailboxname, &mailbox, LOCK_SHARED))) {
	syslog(LOG_ERR, "http_mailbox_open(%s) failed: %s",
	       mailboxname, error_message(r));
	txn->error.desc = error_message(r);
	ret = HTTP_SERVER_ERROR;
	goto done;
    }

    /* Open the associated CalDAV database */
    if ((r = caldav_open(mailbox, CALDAV_CREATE, &caldavdb))) {
	txn->error.desc = error_message(r);
	ret = HTTP_SERVER_ERROR;
	goto done;
    }

    /* Find message UID for the resource */
    caldav_read(caldavdb, txn->req_tgt.resource, &uid);

    /* Fetch index record for the resource */
    if (!uid || mailbox_find_index_record(mailbox, uid, &record)) {
	ret = HTTP_NOT_FOUND;
	goto done;
    }

    /* Check any preconditions */
    resp_body->etag = message_guid_encode(&record.guid);
    lastmod = record.internaldate;
    precond = check_precond(txn->meth, resp_body->etag, lastmod, txn->req_hdrs);

    if (precond != HTTP_OK) {
	/* We failed a precondition - don't perform the request */
	ret = precond;
	goto done;
    }

    /* Fill in Last-Modified, and Content-Length */
    resp_body->lastmod = lastmod;
    resp_body->type = "text/calendar; charset=utf-8";

    if (txn->meth[0] == 'G') {
	/* Load message containing the resource */
	mailbox_map_message(mailbox, record.uid, &msg_base, &msg_size);
    }

    write_body(HTTP_OK, txn,
	       /* skip message header */
	       msg_base + record.header_size, record.size - record.header_size);

    if (msg_base)
	mailbox_unmap_message(mailbox, record.uid, &msg_base, &msg_size);

  done:
    if (caldavdb) caldav_close(caldavdb);
    if (mailbox) mailbox_unlock_index(mailbox, NULL);

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
static int meth_mkcol(struct transaction_t *txn)
{
    int ret = 0, r = 0;
    xmlDocPtr indoc = NULL, outdoc = NULL;
    xmlNodePtr root = NULL, instr = NULL;
    xmlNsPtr ns[NUM_NAMESPACE];
    char *server, mailboxname[MAX_MAILBOX_BUFFER], *partition = NULL;
    struct proppatch_ctx pctx;

    memset(&pctx, 0, sizeof(struct proppatch_ctx));

    /* Make sure its a DAV resource */
    if (!(txn->req_tgt.allow & ALLOW_WRITE)) return HTTP_NOT_ALLOWED; 

    /* Parse the path */
    if ((r = parse_path(&txn->req_tgt, &txn->error.desc))) return r;

    /* Make sure its a home-set collection */
    if (!txn->req_tgt.collection || txn->req_tgt.resource) {
	txn->error.precond = &preconds[CALDAV_LOCATION_OK];
	return HTTP_FORBIDDEN;
    }

    /* Construct mailbox name corresponding to calendar-home-set */
    r = (*httpd_namespace.mboxname_tointernal)(&httpd_namespace, "INBOX",
					       httpd_userid, mailboxname);

    /* Locate the mailbox */
    if ((r = http_mlookup(mailboxname, &server, NULL, NULL))) {
	syslog(LOG_ERR, "mlookup(%s) failed: %s",
	       mailboxname, error_message(r));
	txn->error.desc = error_message(r);

	switch (r) {
	case IMAP_PERMISSION_DENIED: return HTTP_FORBIDDEN;
	case IMAP_MAILBOX_NONEXISTENT: return HTTP_NOT_FOUND;
	default: return HTTP_SERVER_ERROR;
	}
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

    /* Response should not be cached */
    txn->flags |= HTTP_NOCACHE;

    /* Construct mailbox name corresponding to request target URI */
    (void) target_to_mboxname(&txn->req_tgt, mailboxname);

    /* Check if we are allowed to create the mailbox */
    r = mboxlist_createmailboxcheck(mailboxname, 0, NULL,
				    httpd_userisadmin || httpd_userisproxyadmin,
				    httpd_userid, httpd_authstate,
				    NULL, &partition, 0);

    if (r == IMAP_PERMISSION_DENIED) return HTTP_FORBIDDEN;
    else if (r == IMAP_MAILBOX_EXISTS) return HTTP_FORBIDDEN;
    else if (r) return HTTP_SERVER_ERROR;

    /* Parse the MKCOL/MKCALENDAR body, if exists */
    ret = parse_xml_body(txn, &root);
    if (ret) goto done;

    if (root) {
	indoc = root->doc;

	if ((txn->meth[3] == 'O') &&
	    /* Make sure its a mkcol element */
	    xmlStrcmp(root->name, BAD_CAST "mkcol")) {
	    txn->error.desc = "Missing mkcol element in MKCOL request";
	    return HTTP_BAD_MEDIATYPE;
	}
	else if ((txn->meth[3] == 'A') &&
		 /* Make sure its a mkcalendar element */
		 xmlStrcmp(root->name, BAD_CAST "mkcalendar")) {
	    txn->error.desc = "Missing mkcalendar element in MKCALENDAR request";
	    return HTTP_BAD_MEDIATYPE;
	}

	instr = root->children;
    }

    if (instr) {
	/* Start construction of our mkcol/mkcalendar response */
	if (!(root = init_xml_response(txn->meth[3] == 'A' ?
				       "mkcalendar-response" :
				       "mkcol-response",
				       root->nsDef, ns))) {
	    ret = HTTP_SERVER_ERROR;
	    txn->error.desc = "Unable to create XML response";
	    goto done;
	}

	outdoc = root->doc;

	/* Populate our proppatch context */
	pctx.req_tgt = &txn->req_tgt;
	pctx.meth = txn->meth;
	pctx.mailboxname = mailboxname;
	pctx.root = root;
	pctx.ns = ns;
	pctx.tid = NULL;
	pctx.errstr = &txn->error.desc;
	pctx.ret = &r;

	/* Execute the property patch instructions */
	ret = do_proppatch(&pctx, instr);

	if (ret || r) {
	    /* Something failed.  Abort the txn and change the OK status */
	    annotatemore_abort(pctx.tid);

	    if (!ret) {
		/* Output the XML response */
		xml_response(HTTP_MULTI_STATUS, txn, outdoc);
		ret = 0;
	    }

	    goto done;
	}
    }

    /* Create the mailbox */
    r = mboxlist_createmailbox(mailboxname, MBTYPE_CALENDAR, partition, 
			       httpd_userisadmin || httpd_userisproxyadmin,
			       httpd_userid, httpd_authstate,
			       0, 0, 0);

    if (!r) ret = HTTP_CREATED;
    else if (r == IMAP_PERMISSION_DENIED) ret = HTTP_FORBIDDEN;
    else if (r == IMAP_MAILBOX_EXISTS) ret = HTTP_FORBIDDEN;
    else if (r) {
	txn->error.desc = error_message(r);
	ret = HTTP_SERVER_ERROR;
    }

    if (instr) {
	if (r) {
	    /* Failure.  Abort the txn */
	    annotatemore_abort(pctx.tid);
	}
	else {
	    /* Success.  Commit the txn */
	    annotatemore_commit(pctx.tid);
	}
    }

  done:
    buf_free(&pctx.buf);

    if (outdoc) xmlFreeDoc(outdoc);
    if (indoc) xmlFreeDoc(indoc);

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
static int apply_calfilter(struct propfind_ctx *fctx)
{
    int match = 1;
    icalcomponent *ical, *comp;

    /* mmap() and parse iCalendar object to perform filtering */
    mailbox_map_message(fctx->mailbox, fctx->record->uid,
			&fctx->msg_base, &fctx->msg_size);

    ical = icalparser_parse_string(fctx->msg_base + fctx->record->header_size);

    comp = icalcomponent_get_first_real_component(ical);

    if (fctx->calfilter->comp) {
	icalcomponent_kind kind = icalcomponent_isa(comp);
	unsigned mykind = 0;

	/* Perform CALDAV:comp-filter filtering */
	/* XXX  This should be checked with a caldav_db entry */
	switch (kind) {
	case ICAL_VEVENT_COMPONENT: mykind = COMP_VEVENT; break;
	case ICAL_VTODO_COMPONENT: mykind = COMP_VTODO; break;
	case ICAL_VJOURNAL_COMPONENT: mykind = COMP_VJOURNAL; break;
	case ICAL_VFREEBUSY_COMPONENT: mykind = COMP_VFREEBUSY; break;
	default: break;
	}

	if (!(mykind & fctx->calfilter->comp)) match = 0;
    }

    if (match && !icaltime_is_null_time(fctx->calfilter->start)) {
	/* XXX  This code assumes that the first VEVENT will contain
	 * the recurrence rule and the subsequent VEVENTs will
	 * be the overrides.  Technically this doesn't have to be
	 * the case, but it appears to be true in practice.
	 */
	unsigned firstr, lastr;
	icaltimezone *utc = icaltimezone_get_utc_timezone();
	icaltime_span rangespan;

	/* Create a span for the given time-range */
	rangespan.start =
	    icaltime_as_timet_with_zone(fctx->calfilter->start, utc);
	rangespan.end =
	    icaltime_as_timet_with_zone(fctx->calfilter->end, utc);

	/* Mark start of where recurrences will be added */
	firstr = fctx->busytime.len;

	/* Add all recurring busytime in specified time-range */
	icalcomponent_foreach_recurrence(comp,
					 fctx->calfilter->start,
					 fctx->calfilter->end,
					 add_busytime,
					 &fctx->busytime);

	/* Mark end of where recurrences were added */
	lastr = fctx->busytime.len;

	/* XXX  Should we sort the busytime array, so we can use bsearch()? */

	/* Handle overridden recurrences */
	while ((comp =
		icalcomponent_get_next_component(ical,
						 ICAL_VEVENT_COMPONENT))) {
	    unsigned n;
	    icalproperty *prop;
	    struct icaltimetype recurid;
	    icalparameter *param;
	    icaltime_span recurspan;

	    /* The *_get_recurrenceid() functions don't appear
	       to deal with timezones properly, so we do it ourselves */
	    prop = icalcomponent_get_first_property(comp,
						    ICAL_RECURRENCEID_PROPERTY);
	    recurid = icalproperty_get_recurrenceid(prop);
	    param = icalproperty_get_first_parameter(prop, ICAL_TZID_PARAMETER);

	    if (param) {
		const char *tzid = icalparameter_get_tzid(param);
		icaltimezone *tz = NULL;

		tz = icalcomponent_get_timezone(ical, tzid);
		if (!tz) tz = icaltimezone_get_builtin_timezone_from_tzid(tzid);
		if (tz) icaltime_set_timezone(&recurid, tz);
	    }

	    recurid = icaltime_convert_to_zone(recurid,
					       icaltimezone_get_utc_timezone());

	    /* Check if this overridden instance is in our array */
	    /* XXX  Should we replace this linear search with bsearch() */
	    for (n = firstr; n < lastr; n++) {
		if (!icaltime_compare(recurid,
				      fctx->busytime.busy[n].start)) {
		    /* Remove the instance
		       by sliding all future instances into its place */
		    /* XXX  Doesn't handle the RANGE=THISANDFUTURE param */
		    fctx->busytime.len--;
		    memmove(&fctx->busytime.busy[n],
			    &fctx->busytime.busy[n+1],
			    sizeof(struct icalperiodtype) *
			    (fctx->busytime.len - n));
		    lastr--;

		    break;
		}
	    }

	    /* Check if the new instance is in our time-range */
	    recurspan = icaltime_span_new(icalcomponent_get_dtstart(comp),
					  icalcomponent_get_dtend(comp), 1);

	    if (icaltime_span_overlaps(&recurspan, &rangespan)) {
		/* Add this instance to the array */
		add_busytime(comp, &recurspan, &fctx->busytime);
	    }
	}

	if (!fctx->busytime.len) match = 0;
    }

    icalcomponent_free(ical);

    return match;
}


/* caldav_foreach() callback to find props on a resource */
static int propfind_by_resource(void *rock, const char *resource, uint32_t uid)
{
    struct propfind_ctx *fctx = (struct propfind_ctx *) rock;
    struct index_record record;
    char *p;
    size_t len;
    int r, ret = 0;

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
    strlcpy(p, resource, MAX_MAILBOX_PATH - len);
    fctx->req_tgt->resource = p;
    fctx->req_tgt->reslen = strlen(p);

    if (uid && !fctx->record) {
	/* Fetch index record for the resource */
	r = mailbox_find_index_record(fctx->mailbox, uid, &record);
	/* XXX  Check errors */

	fctx->record = r ? NULL : &record;
    }

    if (!uid || !fctx->record) {
	/* Add response for missing target */
	ret = xml_add_response(fctx, HTTP_NOT_FOUND);
    }
    else {
	int add_it = 1;

	fctx->busytime.len = 0;
	if (fctx->calfilter) add_it = apply_calfilter(fctx);

	if (add_it) {
	    /* Add response for target */
	    ret = xml_add_response(fctx, 0);
	}
    }

    if (fctx->msg_base) {
	mailbox_unmap_message(fctx->mailbox, uid,
			      &fctx->msg_base, &fctx->msg_size);
    }
    fctx->msg_base = NULL;
    fctx->msg_size = 0;
    fctx->record = NULL;

    return ret;
}

/* mboxlist_findall() callback to find props on a collection */
static int propfind_by_collection(char *mboxname,
				  int matchlen __attribute__((unused)),
				  int maycreate __attribute__((unused)),
				  void *rock)
{
    struct propfind_ctx *fctx = (struct propfind_ctx *) rock;
    struct mboxlist_entry mbentry;
    struct mailbox *mailbox = NULL;
    struct caldav_db *caldavdb = NULL;
    char *p;
    size_t len;
    int r = 0, rights;

    if (fctx->calfilter && fctx->calfilter->check_transp) {
	/* Check if the collection is marked as transparent */
	struct annotation_data attrib;
	const char *prop_annot =
	    ANNOT_NS "CALDAV:schedule-calendar-transp";

	if (!annotatemore_lookup(mboxname, prop_annot, /* shared */ "", &attrib)
	    && attrib.value && !strcmp(attrib.value, "transparent")) return 0;
    }

    /* Check ACL on mailbox for current user */
    if ((r = mboxlist_lookup(mboxname, &mbentry, NULL))) {
	syslog(LOG_INFO, "mboxlist_lookup(%s) failed: %s",
	       mboxname, error_message(r));
	*fctx->errstr = error_message(r);
	*fctx->ret = HTTP_SERVER_ERROR;
	goto done;
    }

    rights = mbentry.acl ? cyrus_acl_myrights(httpd_authstate, mbentry.acl) : 0;
    if ((rights & fctx->reqd_privs) != fctx->reqd_privs) goto done;

    /* Open mailbox for reading */
    if ((r = mailbox_open_irl(mboxname, &mailbox))) {
	syslog(LOG_INFO, "mailbox_open_irl(%s) failed: %s",
	       mboxname, error_message(r));
	*fctx->errstr = error_message(r);
	*fctx->ret = HTTP_SERVER_ERROR;
	goto done;
    }

    /* Open the associated CalDAV database */
    if ((r = caldav_open(mailbox, CALDAV_CREATE, &caldavdb))) {
	*fctx->errstr = error_message(r);
	*fctx->ret = HTTP_SERVER_ERROR;
	goto done;
    }

    fctx->mailbox = mailbox;
    fctx->record = NULL;

    if (!fctx->req_tgt->resource) {
	/* Append collection name to URL path */
	if (!fctx->req_tgt->collection) {
	    len = strlen(fctx->req_tgt->path);
	    p = fctx->req_tgt->path + len;
	}
	else {
	    p = fctx->req_tgt->collection;
	    len = p - fctx->req_tgt->path;
	}

	if (p[-1] != '/') {
	    *p++ = '/';
	    len++;
	}
	strlcpy(p, strrchr(mboxname, '.') + 1, MAX_MAILBOX_PATH - len);
	strlcat(p, "/", MAX_MAILBOX_PATH - len - 1);
	fctx->req_tgt->collection = p;
	fctx->req_tgt->collen = strlen(p);

	/* If not filtering by calendar resource, add response for collection */
	if (!fctx->calfilter && (r = xml_add_response(fctx, 0))) goto done;
    }

    if (fctx->depth > 1) {
	/* Resource(s) */

	if (fctx->req_tgt->resource) {
	    /* Add response for target resource */
	    uint32_t uid;

	    /* Find message UID for the resource */
	    caldav_read(caldavdb, fctx->req_tgt->resource, &uid);
	    /* XXX  Check errors */

	    r = fctx->proc_by_resource(rock, fctx->req_tgt->resource, uid);
	}
	else {
	    /* Add responses for all contained resources */
	    caldav_foreach(caldavdb, fctx->proc_by_resource, rock);

	    /* Started with NULL resource, end with NULL resource */
	    fctx->req_tgt->resource = NULL;
	    fctx->req_tgt->reslen = 0;
	}
    }

  done:
    if (caldavdb) caldav_close(caldavdb);
    if (mailbox) mailbox_close(&mailbox);

    return r;
}


/* Perform a PROPFIND request */
int meth_propfind(struct transaction_t *txn)
{
    int ret = 0, r;
    const char **hdr;
    unsigned depth;
    xmlDocPtr indoc = NULL, outdoc = NULL;
    xmlNodePtr root, cur = NULL;
    xmlNsPtr ns[NUM_NAMESPACE];
    char mailboxname[MAX_MAILBOX_BUFFER];
    struct propfind_ctx fctx;
    struct propfind_entry_list *elist = NULL;

    memset(&fctx, 0, sizeof(struct propfind_ctx));

    /* Make sure its a DAV resource */
    if (!(txn->req_tgt.allow & ALLOW_DAV) && 
	strcmp(txn->req_tgt.path, "/")) {  /* Apple iCal checks "/" */
	return HTTP_NOT_ALLOWED;
    }

    /* In case namespace didn't enforce auth - Needed for Evolution */
    if (!httpd_userid) return HTTP_UNAUTHORIZED;

    /* Parse the path */
    if ((r = parse_path(&txn->req_tgt, &txn->error.desc))) return r;

    /* Check Depth */
    hdr = spool_getheader(txn->req_hdrs, "Depth");
    if (!hdr || !strcmp(hdr[0], "infinity")) {
	depth = 2;
    }
    else if (hdr && ((sscanf(hdr[0], "%u", &depth) != 1) || (depth > 1))) {
	txn->error.desc = "Illegal Depth value";
	return HTTP_BAD_REQUEST;
    }

    if ((txn->req_tgt.namespace == URL_NS_CALENDAR) && txn->req_tgt.user) {
	char *server, *acl;
	int rights;

	/* Construct mailbox name corresponding to request target URI */
	(void) target_to_mboxname(&txn->req_tgt, mailboxname);

	/* Locate the mailbox */
	if ((r = http_mlookup(mailboxname, &server, &acl, NULL))) {
	    syslog(LOG_ERR, "mlookup(%s) failed: %s",
		   mailboxname, error_message(r));
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
	    txn->error.precond = &preconds[DAV_NEED_PRIVS];
	    txn->error.resource = txn->req_tgt.path;
	    txn->error.rights = DACL_READ;
	    ret = HTTP_FORBIDDEN;
	    goto done;
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
    }

    /* Principal or Local Mailbox */

    /* Normalize depth so that:
     * 0 = home-set collection, 1+ = calendar collection, 2+ = calendar resource
     */
    if (txn->req_tgt.collection) depth++;
    if (txn->req_tgt.resource) depth++;

    /* Parse the PROPFIND body, if exists */
    ret = parse_xml_body(txn, &root);
    if (ret) goto done;

    if (!root) {
	/* XXX allprop request */
    }
    else {
	indoc = root->doc;

	/* XXX  Need to support propname request too! */

	/* Make sure its a propfind element */
	if (xmlStrcmp(root->name, BAD_CAST "propfind")) {
	    txn->error.desc = "Missing propfind element in PROFIND request";
	    ret = HTTP_BAD_REQUEST;
	    goto done;
	}

	/* Find child element of propfind */
	for (cur = root->children;
	     cur && cur->type != XML_ELEMENT_NODE; cur = cur->next);

	/* Make sure its a prop element */
	/* XXX  TODO: Check for allprop and propname too */
	if (!cur || xmlStrcmp(cur->name, BAD_CAST "prop")) {
	    ret = HTTP_BAD_REQUEST;
	    goto done;
	}
    }

    /* Start construction of our multistatus response */
    if (!(root = init_xml_response("multistatus", root->nsDef, ns))) {
	ret = HTTP_SERVER_ERROR;
	txn->error.desc = "Unable to create XML response";
	goto done;
    }

    outdoc = root->doc;

    /* Populate our propfind context */
    fctx.req_tgt = &txn->req_tgt;
    fctx.depth = depth;
    fctx.userid = httpd_userid;
    fctx.userisadmin = httpd_userisadmin;
    fctx.authstate = httpd_authstate;
    fctx.mailbox = NULL;
    fctx.record = NULL;
    fctx.reqd_privs = DACL_READ;
    fctx.calfilter = NULL;
    fctx.proc_by_resource = &propfind_by_resource;
    fctx.elist = NULL;
    fctx.root = root;
    fctx.ns = ns;
    fctx.errstr = &txn->error.desc;
    fctx.ret = &ret;

    /* Check for Brief header */
    if ((hdr = spool_getheader(txn->req_hdrs, "Brief")) &&
	!strcasecmp(hdr[0], "t")) {
	fctx.brief = 1;
    }

    /* Parse the list of properties and build a list of callbacks */
    preload_proplist(cur->children, &fctx);

    if (!txn->req_tgt.collection) {
	/* Add response for home-set collection */
	if (xml_add_response(&fctx, 0)) goto done;
    }

    if (depth > 0) {
	/* Calendar collection(s) */

	/* Construct mailbox name corresponding to request target URI */
	(void) target_to_mboxname(&txn->req_tgt, mailboxname);

	if (txn->req_tgt.collection) {
	    /* Add response for target calendar collection */
	    propfind_by_collection(mailboxname, 0, 0, &fctx);
	}
	else {
	    /* Add responses for all contained calendar collections */
	    strlcat(mailboxname, ".%", sizeof(mailboxname));
	    r = mboxlist_findall(NULL,  /* internal namespace */
				 mailboxname, 1, httpd_userid, 
				 httpd_authstate, propfind_by_collection, &fctx);
	}

	ret = *fctx.ret;
    }

    /* Output the XML response */
    if (!ret) xml_response(HTTP_MULTI_STATUS, txn, outdoc);

  done:
    /* Free the entry list */
    elist = fctx.elist;
    while (elist) {
	struct propfind_entry_list *freeme = elist;
	elist = elist->next;
	free(freeme);
    }

    if (fctx.busytime.busy) free(fctx.busytime.busy);
    buf_free(&fctx.buf);

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
static int meth_proppatch(struct transaction_t *txn)
{
    int ret = 0, r = 0, rights;
    xmlDocPtr indoc = NULL, outdoc = NULL;
    xmlNodePtr root, instr, resp;
    xmlNsPtr ns[NUM_NAMESPACE];
    char *server, *acl, mailboxname[MAX_MAILBOX_BUFFER];
    struct proppatch_ctx pctx;

    memset(&pctx, 0, sizeof(struct proppatch_ctx));

    /* Make sure its a DAV resource */
    if (!(txn->req_tgt.allow & ALLOW_WRITE)) return HTTP_NOT_ALLOWED;

    /* Parse the path */
    if ((r = parse_path(&txn->req_tgt, &txn->error.desc))) return r;

    /* Make sure its a calendar collection */
    if (!txn->req_tgt.collection || txn->req_tgt.resource) {
	txn->error.desc =
	    "Properties can only be updated on calendar collections";
	return HTTP_FORBIDDEN;
    }

    /* Construct mailbox name corresponding to request target URI */
    (void) target_to_mboxname(&txn->req_tgt, mailboxname);

    /* Locate the mailbox */
    if ((r = http_mlookup(mailboxname, &server, &acl, NULL))) {
	syslog(LOG_ERR, "mlookup(%s) failed: %s",
	       mailboxname, error_message(r));
	txn->error.desc = error_message(r);

	switch (r) {
	case IMAP_PERMISSION_DENIED: return HTTP_FORBIDDEN;
	case IMAP_MAILBOX_NONEXISTENT: return HTTP_NOT_FOUND;
	default: return HTTP_SERVER_ERROR;
	}
    }

    /* Check ACL for current user */
    rights = acl ? cyrus_acl_myrights(httpd_authstate, acl) : 0;
    if (!(rights & DACL_WRITEPROPS)) {
	/* DAV:need-privileges */
	txn->error.precond = &preconds[DAV_NEED_PRIVS];
	txn->error.resource = txn->req_tgt.path;
	txn->error.rights = DACL_WRITEPROPS;
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

    /* Response should not be cached */
    txn->flags |= HTTP_NOCACHE;

    /* Parse the PROPPATCH body */
    ret = parse_xml_body(txn, &root);
    if (!root) {
	txn->error.desc = "Missing request body";
	return HTTP_BAD_REQUEST;
    }
    if (ret) goto done;

    indoc = root->doc;

    /* Make sure its a propertyupdate element */
    if (xmlStrcmp(root->name, BAD_CAST "propertyupdate")) {
	txn->error.desc = "Missing propertyupdate element in PROPPATCH request";
	return HTTP_BAD_REQUEST;
    }
    instr = root->children;

    /* Start construction of our multistatus response */
    if (!(root = init_xml_response("multistatus", root->nsDef, ns))) {
	ret = HTTP_SERVER_ERROR;
	txn->error.desc = "Unable to create XML response";
	goto done;
    }

    outdoc = root->doc;

    /* Add a response tree to 'root' for the specified href */
    resp = xmlNewChild(root, NULL, BAD_CAST "response", NULL);
    if (!resp) syslog(LOG_ERR, "new child response failed");
    xmlNewChild(resp, NULL, BAD_CAST "href", BAD_CAST txn->req_tgt.path);

    /* Populate our proppatch context */
    pctx.req_tgt = &txn->req_tgt;
    pctx.meth = txn->meth;
    pctx.mailboxname = mailboxname;
    pctx.root = resp;
    pctx.ns = ns;
    pctx.tid = NULL;
    pctx.errstr = &txn->error.desc;
    pctx.ret = &r;

    /* Execute the property patch instructions */
    ret = do_proppatch(&pctx, instr);

    if (ret || r) {
	/* Something failed.  Abort the txn and change the OK status */
	annotatemore_abort(pctx.tid);

	if (ret) goto done;
    }
    else {
	/* Success.  Commit the txn */
	annotatemore_commit(pctx.tid);
    }

    /* Output the XML response */
    if (!ret) xml_response(HTTP_MULTI_STATUS, txn, outdoc);

  done:
    buf_free(&pctx.buf);

    if (outdoc) xmlFreeDoc(outdoc);
    if (indoc) xmlFreeDoc(indoc);

    return ret;
}


/* Perform a POST request */
static int meth_post(struct transaction_t *txn)
{
    static unsigned post_count = 0;
    int r;
    size_t len;
    char *p;

    /* Make sure its a DAV resource */
    if (!(txn->req_tgt.allow & ALLOW_WRITE)) return HTTP_NOT_ALLOWED; 

    /* Parse the path */
    if ((r = parse_path(&txn->req_tgt, &txn->error.desc))) return r;

    /* We only handle POST on calendar collections */
    if (!txn->req_tgt.collection ||
	txn->req_tgt.resource) return HTTP_NOT_ALLOWED;

    if (!strcmp(txn->req_tgt.collection, SCHED_OUTBOX)) {
	/* POST to schedule-outbox (busy time request) */

	return sched_busytime(txn);
    }

    /* POST to regular calendar collection */

    /* Append a unique resource name to URL path and perform a PUT */
    len = strlen(txn->req_tgt.path);
    p = txn->req_tgt.path + len;

    snprintf(p, MAX_MAILBOX_PATH - len, "%d-%ld-%u.ics",
	     getpid(), time(0), post_count++);

    return meth_put(txn);
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
static int meth_put(struct transaction_t *txn)
{
    static unsigned put_count = 0;
    int ret = HTTP_CREATED, r, precond, rights;
    char *server, *acl, mailboxname[MAX_MAILBOX_BUFFER];
    struct mailbox *mailbox = NULL;
    struct caldav_db *caldavdb = NULL;
    uint32_t olduid = 0;
    struct index_record oldrecord;
    const char *etag;
    time_t lastmod;
    FILE *f = NULL;
    struct stagemsg *stage = NULL;
    const char **hdr, *uid;
    uquota_t size = 0;
    time_t now = time(NULL);
    pid_t pid = getpid();
    char datestr[80];
    struct appendstate appendstate;
    icalcomponent *ical, *comp;
    icalcomponent_kind kind;
    icalproperty_method meth;

    /* Make sure its a DAV resource */
    if (!(txn->req_tgt.allow & ALLOW_WRITE)) return HTTP_NOT_ALLOWED; 

    /* Parse the path */
    if ((r = parse_path(&txn->req_tgt, &txn->error.desc))) return r;

    /* We only handle PUT on resources */
    if (!txn->req_tgt.resource) return HTTP_NOT_ALLOWED;

    /* Check Content-Type */
    if (!(hdr = spool_getheader(txn->req_hdrs, "Content-Type")) ||
	!is_mediatype(hdr[0], "text/calendar")) {
	txn->error.precond = &preconds[CALDAV_SUPP_DATA];
	return HTTP_FORBIDDEN;
    }

    /* Construct mailbox name corresponding to request target URI */
    (void) target_to_mboxname(&txn->req_tgt, mailboxname);

    /* Locate the mailbox */
    if ((r = http_mlookup(mailboxname, &server, &acl, NULL))) {
	syslog(LOG_ERR, "mlookup(%s) failed: %s",
	       mailboxname, error_message(r));
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
	txn->error.precond = &preconds[DAV_NEED_PRIVS];
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
    if ((r = http_mailbox_open(mailboxname, &mailbox, LOCK_SHARED))) {
	syslog(LOG_ERR, "http_mailbox_open(%s) failed: %s",
	       mailboxname, error_message(r));
	txn->error.desc = error_message(r);
	ret = HTTP_SERVER_ERROR;
	goto done;
    }

    /* Open the associated CalDAV database */
    if ((r = caldav_open(mailbox, CALDAV_CREATE, &caldavdb))) {
	txn->error.desc = error_message(r);
	ret = HTTP_SERVER_ERROR;
	goto done;
    }

    /* Find message UID for the resource, if exists */
    caldav_read(caldavdb, txn->req_tgt.resource, &olduid);

    if (olduid) {
	/* Overwriting existing resource */

	/* Fetch index record for the resource */
	r = mailbox_find_index_record(mailbox, olduid, &oldrecord);
	/* XXX  check for errors */

	etag = message_guid_encode(&oldrecord.guid);
	lastmod = oldrecord.internaldate;
    }
    else {
	/* New resource */
	etag = NULL;
	lastmod = 0;
    }

    /* Check any preconditions */
    precond = check_precond(txn->meth, etag, lastmod, txn->req_hdrs);

    if (precond != HTTP_OK) {
	/* We failed a precondition - don't perform the request */
	ret = precond;
	goto done;
    }

    /* Finished our initial read */
    mailbox_unlock_index(mailbox, NULL);

    /* Check if we can append a new iMIP message to calendar mailbox */
    if ((r = append_check(mailboxname, httpd_authstate, ACL_INSERT, size))) {
	txn->error.desc = error_message(r);
	ret = HTTP_SERVER_ERROR;
	goto done;
    }

    /* Read body */
    if (!(txn->flags & HTTP_READBODY)) {
	txn->flags |= HTTP_READBODY;
	r = read_body(httpd_in, txn->req_hdrs, &txn->req_body, &txn->error.desc);
	if (r) {
	    txn->flags |= HTTP_CLOSE;
	    ret = r;
	    goto done;
	}
    }

    /* Make sure we have a body */
    if (!buf_len(&txn->req_body)) {
	txn->error.desc = "Missing request body";
	ret = HTTP_BAD_REQUEST;
	goto done;
    }

    /* Parse the iCal data for important properties */
    ical = icalparser_parse_string(buf_cstring(&txn->req_body));
    if (!ical || !icalrestriction_check(ical)) {
	txn->error.precond = &preconds[CALDAV_VALID_DATA];
	ret = HTTP_FORBIDDEN;
	goto done;
    }

    /* Prepare to stage the message */
    if (!(f = append_newstage(mailboxname, now, 0, &stage))) {
	txn->error.desc = error_message(r);
	ret = HTTP_SERVER_ERROR;
	goto done;
    }

    meth = icalcomponent_get_method(ical);
    comp = icalcomponent_get_first_real_component(ical);
    kind = icalcomponent_isa(comp);

    /* Create iMIP header for resource */
    fprintf(f, "From: <%s>\r\n", httpd_userid ? httpd_userid : "");

    fprintf(f, "Subject: %s\r\n", icalcomponent_get_summary(comp));

    rfc822date_gen(datestr, sizeof(datestr), now);
    fprintf(f, "Date: %s\r\n", datestr);

    fprintf(f, "Message-ID: ");
    if ((uid = icalcomponent_get_uid(comp)) && *uid) fprintf(f, "<%s", uid);
    else fprintf(f, "<cmu-http-%d-%ld-%u", pid, now, put_count++);
    fprintf(f, "@%s>\r\n", config_servername);

    hdr = spool_getheader(txn->req_hdrs, "Content-Type");
    fprintf(f, "Content-Type: %s", hdr[0]);
    if (meth != ICAL_METHOD_NONE) {
	fprintf(f, "; method=%s", icalproperty_method_to_string(meth));
    }
    fprintf(f, "; component=%s\r\n", icalcomponent_kind_to_string(kind));

    fprintf(f, "Content-Length: %u\r\n", buf_len(&txn->req_body));
    fprintf(f, "Content-Disposition: inline; filename=%s\r\n",
	    txn->req_tgt.resource);

    /* XXX  Check domain of data and use appropriate CTE */

    fprintf(f, "MIME-Version: 1.0\r\n");
    fprintf(f, "\r\n");
    size += ftell(f);

    /* Write the iCal data to the file */
    fprintf(f, "%s", buf_cstring(&txn->req_body));
    size += buf_len(&txn->req_body);

    fclose(f);


    /* Prepare to append the iMIP message to calendar mailbox */
    if ((r = append_setup(&appendstate, mailboxname, 
			  httpd_userid, httpd_authstate, ACL_INSERT, size))) {
	ret = HTTP_SERVER_ERROR;
	txn->error.desc = "append_setup() failed";
    }
    else {
	struct body *body = NULL;

	/* Append the iMIP file to the calendar mailbox */
	if ((r = append_fromstage(&appendstate, &body, stage, now, NULL, 0, 0))) {
	    ret = HTTP_SERVER_ERROR;
	    txn->error.desc = "append_fromstage() failed";
	}
	if (body) message_free_body(body);

	if (r) append_abort(&appendstate);
	else {
	    struct mailbox *lock_mbox = NULL;

	    /* Commit the append to the calendar mailbox */
	    if ((r = append_commit(&appendstate, size,
				   NULL, NULL, NULL, &lock_mbox))) {
		ret = HTTP_SERVER_ERROR;
		txn->error.desc = "append_commit() failed";
	    }
	    else {
		/* append_commit() returns a write-locked index */
		struct index_record newrecord, *expunge;

		/* Read index record for new message (always the last one) */
		mailbox_read_index_record(lock_mbox, lock_mbox->i.num_records,
					  &newrecord);

		/* Find message UID for the resource, if exists */
		caldav_lockread(caldavdb, txn->req_tgt.resource, &olduid);
		/* XXX  check for errors */

		if (olduid) {
		    /* Now that we have the replacement message in place
		       and the mailbox locked, re-read the old record
		       and re-test any preconditions. Either way,
		       one of our records will have to be expunged.
		    */
		    int userflag;

		    ret = HTTP_NO_CONTENT;

		    /* Fetch index record for the resource */
		    r = mailbox_find_index_record(lock_mbox, olduid, &oldrecord);

		    etag = message_guid_encode(&oldrecord.guid);
		    lastmod = oldrecord.internaldate;

		    /* Check any preconditions */
		    precond = check_precond(txn->meth, etag, lastmod,
					    txn->req_hdrs);

		    if (precond != HTTP_OK) {
			/* We failed a precondition */
			ret = precond;

			/* Keep old resource - expunge the new one */
			expunge = &newrecord;
		    }
		    else {
			/* Keep new resource - expunge the old one */
			expunge = &oldrecord;
		    }

		    /* Perform the actual expunge */
		    r = mailbox_user_flag(lock_mbox, DFLAG_UNBIND,  &userflag);
		    if (!r) {
			expunge->user_flags[userflag/32] |= 1<<(userflag&31);
			expunge->system_flags |= FLAG_EXPUNGED | FLAG_UNLINKED;
			r = mailbox_rewrite_index_record(lock_mbox, expunge);
		    }
		    if (r) {
			syslog(LOG_ERR, "expunging record (%s) failed: %s",
			       mailboxname, error_message(r));
			txn->error.desc = error_message(r);
			ret = HTTP_SERVER_ERROR;
		    }
		}

		if (!r) {
		    /* Create mapping entry from resource name and UID */
		    caldav_write(caldavdb, txn->req_tgt.resource, newrecord.uid);
		    /* XXX  check for errors, if this fails, backout changes */

		    /* append_setup() opened mailbox again,
		       we need to close it to decrement reference count */
		    mailbox_close(&lock_mbox);

		    /* Tell client about the new resource */
		    txn->resp_body.etag = message_guid_encode(&newrecord.guid);
		    if (txn->meth[1] == 'O') txn->loc = txn->req_tgt.path;
		}
	    }
	}
    }

  done:
    if (stage) append_removestage(stage);
    if (caldavdb) caldav_close(caldavdb);
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
		    error->precond = &preconds[CALDAV_VALID_FILTER];
		    return HTTP_FORBIDDEN;
		}

		if (!xmlStrcmp(name, BAD_CAST "VCALENDAR"))
		    filter->comp = COMP_VCALENDAR;
		else if (!xmlStrcmp(name, BAD_CAST "VEVENT"))
		    filter->comp = COMP_VEVENT;
		else if (!xmlStrcmp(name, BAD_CAST "VTODO"))
		    filter->comp = COMP_VTODO;
		else if (!xmlStrcmp(name, BAD_CAST "VJOURNAL"))
		    filter->comp = COMP_VJOURNAL;
		else if (!xmlStrcmp(name, BAD_CAST "VFREEBUSY"))
		    filter->comp = COMP_VFREEBUSY;
		else {
		    error->precond = &preconds[CALDAV_SUPP_FILTER];
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
		error->precond = &preconds[CALDAV_SUPP_FILTER];
		return HTTP_FORBIDDEN;
	    }
	}
    }

    return ret;
}


static int report_cal_query(struct transaction_t *txn,
			    xmlNodePtr inroot, struct propfind_ctx *fctx,
			    char mailboxname[])
{
    int ret = 0;
    xmlNodePtr node;
    struct calquery_filter filter;

    fctx->proc_by_resource = &propfind_by_resource;

    /* Parse children element of report */
    for (node = inroot->children; node; node = node->next) {
	if (node->type == XML_ELEMENT_NODE) {
	    if (!xmlStrcmp(node->name, BAD_CAST "filter")) {
		memset(&filter, 0, sizeof(struct calquery_filter));
		ret = parse_comp_filter(node->children, &filter, &txn->error);
		if (!ret) fctx->calfilter = &filter;
	    }
	    else if (!xmlStrcmp(node->name, BAD_CAST "timezone")) {
		syslog(LOG_WARNING, "REPORT calendar-query w/timezone");
	    }
	}
    }

    if (fctx->depth > 0) {
	/* Calendar collection(s) */
	int r;

	if (txn->req_tgt.collection) {
	    /* Add response for target calendar collection */
	    propfind_by_collection(mailboxname, 0, 0, fctx);
	}
	else {
	    /* Add responses for all contained calendar collections */
	    strlcat(mailboxname, ".%", sizeof(mailboxname));
	    r = mboxlist_findall(NULL,  /* internal namespace */
				 mailboxname, 1, httpd_userid, 
				 httpd_authstate, propfind_by_collection, fctx);
	}

	ret = *fctx->ret;
    }

    return ret;
}


static int report_cal_multiget(struct transaction_t *txn __attribute__((unused)),
			       xmlNodePtr inroot, struct propfind_ctx *fctx,
			       char mailboxname[])
{
    int r, ret = 0;
    struct mailbox *mailbox = NULL;
    struct caldav_db *caldavdb = NULL;
    xmlNodePtr node;
    struct buf uri = BUF_INITIALIZER;

    /* Open mailbox for reading */
    if ((r = http_mailbox_open(mailboxname, &mailbox, LOCK_SHARED))) {
	syslog(LOG_ERR, "http_mailbox_open(%s) failed: %s",
	       mailboxname, error_message(r));
	txn->error.desc = error_message(r);
	ret = HTTP_SERVER_ERROR;
	goto done;
    }

    /* Open the associated CalDAV database */
    if ((r = caldav_open(mailbox, CALDAV_CREATE, &caldavdb))) {
	txn->error.desc = error_message(r);
	ret = HTTP_SERVER_ERROR;
	goto done;
    }

    fctx->mailbox = mailbox;

    /* Get props for each href */
    for (node = inroot->children; node; node = node->next) {
	if ((node->type == XML_ELEMENT_NODE) &&
	    !xmlStrcmp(node->name, BAD_CAST "href")) {
	    xmlChar *href = xmlNodeListGetString(inroot->doc, node->children, 1);
	    int len = xmlStrlen(href);
	    const char *resource;
	    uint32_t uid = 0;

	    buf_ensure(&uri, len);
	    xmlURIUnescapeString((const char *) href, len, uri.s);
	    resource = strrchr(uri.s, '/') + 1;

	    /* Find message UID for the resource */
	    caldav_read(caldavdb, resource, &uid);
	    /* XXX  Check errors */

	    propfind_by_resource(fctx, resource, uid);
	}
    }

  done:
    if (caldavdb) caldav_close(caldavdb);
    if (mailbox) mailbox_unlock_index(mailbox, NULL);
    buf_free(&uri);

    return ret;
}



static int busytime_by_resource(void *rock,
				const char *resource __attribute__((unused)),
				uint32_t uid)
{
    struct propfind_ctx *fctx = (struct propfind_ctx *) rock;
    struct index_record record;
    int r;

    if (!uid) return 0;

    /* Fetch index record for the resource */
    r = mailbox_find_index_record(fctx->mailbox, uid, &record);
    if (r) return 0;

    fctx->record = &record;
    (void) apply_calfilter(fctx);

    if (fctx->msg_base) {
	mailbox_unmap_message(fctx->mailbox, fctx->record->uid,
			      &fctx->msg_base, &fctx->msg_size);
    }
    fctx->msg_base = NULL;
    fctx->msg_size = 0;
    fctx->record = NULL;

    return 0;
}


static int compare_busytime(const void *b1, const void *b2)
{
    struct icalperiodtype *a = (struct icalperiodtype *) b1;
    struct icalperiodtype *b = (struct icalperiodtype *) b2;

    return icaltime_compare(a->start, b->start);
}


static icalcomponent *do_fb_query(struct transaction_t *txn,
				  struct propfind_ctx *fctx,
				  char mailboxname[],
				  icalproperty_method method,
				  const char *uid,
				  const char *organizer,
				  const char *attendee)
{
    struct busytime *busytime = &fctx->busytime;
    icalcomponent *cal = NULL;

    fctx->proc_by_resource = &busytime_by_resource;

    /* Gather up all of the busytime */
    if (fctx->depth > 0) {
	/* Calendar collection(s) */
	int r;

	/* XXX  Check DACL_READFB on all calendars */

	if (txn->req_tgt.collection) {
	    /* Get busytime for target calendar collection */
	    propfind_by_collection(mailboxname, 0, 0, fctx);
	}
	else {
	    /* Get busytime for all contained calendar collections */
	    strlcat(mailboxname, ".%", sizeof(mailboxname));
	    r = mboxlist_findall(NULL,  /* internal namespace */
				 mailboxname, 1, httpd_userid, 
				 httpd_authstate, propfind_by_collection, fctx);
	}
    }

    if (!*fctx->ret) {
	struct buf prodid = BUF_INITIALIZER;
	icalcomponent *fb;
	icalproperty *prop;
	time_t now = time(0);
	unsigned n;

	/* Construct iCalendar object with VFREEBUSY component */
	buf_printf(&prodid, "-//cyrusimap.org/Cyrus %s//EN", cyrus_version());
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
				 icalproperty_new_dtstart(fctx->calfilter->start),
				 icalproperty_new_dtend(fctx->calfilter->end),
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
			   xmlNodePtr inroot, struct propfind_ctx *fctx,
			   char mailboxname[])
{
    int ret = 0;
    struct calquery_filter filter;
    xmlNodePtr node;
    icalcomponent *cal;

    /* Can not be run against a collection */
    if (txn->req_tgt.resource) return HTTP_FORBIDDEN;

    memset(&filter, 0, sizeof(struct calquery_filter));
    filter.comp = COMP_VEVENT | COMP_VFREEBUSY;
    filter.start = icaltime_from_timet_with_zone(INT_MIN, 0, NULL);
    filter.end = icaltime_from_timet_with_zone(INT_MAX, 0, NULL);
    fctx->calfilter = &filter;

    /* Parse children element of report */
    for (node = inroot->children; node; node = node->next) {
	if (node->type == XML_ELEMENT_NODE) {
	    if (!xmlStrcmp(node->name, BAD_CAST "time-range")) {
		const char *start, *end;

		start = (const char *) xmlGetProp(node, BAD_CAST "start");
		if (start) filter.start = icaltime_from_string(start);

		end = (const char *) xmlGetProp(node, BAD_CAST "end");
		if (end) filter.end = icaltime_from_string(end);
	    }
	}
    }

    cal = do_fb_query(txn, fctx, mailboxname, 0, NULL, NULL, NULL);

    if (cal) {
	/* Output the iCalendar object as text/calendar */
	const char *cal_str = icalcomponent_as_ical_string(cal);
	icalcomponent_free(cal);

	txn->resp_body.type = "text/calendar; charset=utf-8";

	write_body(HTTP_OK, txn, cal_str, strlen(cal_str));
    }
    else ret = HTTP_NOT_FOUND;

    return ret;
}


static int map_modseq_cmp(const struct index_map *m1,
			  const struct index_map *m2)
{
    if (m1->record.modseq < m2->record.modseq) return -1;
    if (m1->record.modseq > m2->record.modseq) return 1;
    return 0;
}


static int report_sync_col(struct transaction_t *txn __attribute__((unused)),
			   xmlNodePtr inroot, struct propfind_ctx *fctx,
			   char mailboxname[])
{
    int ret = 0, r, userflag;
    struct mailbox *mailbox = NULL;
    uint32_t uidvalidity = 0;
    modseq_t syncmodseq = 0, highestmodseq;
    uint32_t limit = -1, recno, nresp;
    xmlNodePtr node;
    struct index_state istate;
    struct index_record *record;
    char tokenuri[MAX_MAILBOX_PATH+1];

    /* XXX  Handle Depth (cal-home-set at toplevel) */

    istate.map = NULL;

    /* Open mailbox for reading */
    if ((r = http_mailbox_open(mailboxname, &mailbox, LOCK_SHARED))) {
	syslog(LOG_ERR, "http_mailbox_open(%s) failed: %s",
	       mailboxname, error_message(r));
	txn->error.desc = error_message(r);
	ret = HTTP_SERVER_ERROR;
	goto done;
    }

    fctx->mailbox = mailbox;

    highestmodseq = mailbox->i.highestmodseq;
    r = mailbox_user_flag(mailbox, DFLAG_UNBIND, &userflag);

    /* Parse children element of report */
    for (node = inroot->children; node; node = node->next) {
	xmlNodePtr node2;
	xmlChar *str;
	if (node->type == XML_ELEMENT_NODE) {
	    if (!xmlStrcmp(node->name, BAD_CAST "sync-token") &&
		(str = xmlNodeListGetString(inroot->doc, node->children, 1))) {
		if (xmlStrncmp(str, BAD_CAST XML_NS_CYRUS "sync/",
			       strlen(XML_NS_CYRUS "sync/")) ||
		    (sscanf(strrchr((char *) str, '/') + 1,
			    "%u-" MODSEQ_FMT,
			    &uidvalidity, &syncmodseq) != 2) ||
		    !syncmodseq ||
		    (uidvalidity != mailbox->i.uidvalidity) ||
		    (syncmodseq < mailbox->i.deletedmodseq) ||
		    (syncmodseq > highestmodseq)) {
		    /* DAV:valid-sync-token */
		    *fctx->errstr = "Invalid sync-token";
		    ret = HTTP_FORBIDDEN;
		    goto done;
		}
	    }
	    if (!xmlStrcmp(node->name, BAD_CAST "sync-level") &&
		(str = xmlNodeListGetString(inroot->doc, node->children, 1))) {
		if (!strcmp((char *) str, "infinity")) {
		    *fctx->errstr =
			"This server DOES NOT support infinite depth requests";
		    ret = HTTP_SERVER_ERROR;
		    goto done;
		}
		else if ((sscanf((char *) str, "%u", &fctx->depth) != 1) ||
			 (fctx->depth != 1)) {
		    *fctx->errstr = "Illegal sync-level";
		    ret = HTTP_BAD_REQUEST;
		    goto done;
		}
	    }
	    if (!xmlStrcmp(node->name, BAD_CAST "limit")) {
		for (node2 = node->children; node2; node2 = node2->next) {
		    if ((node2->type == XML_ELEMENT_NODE) &&
			!xmlStrcmp(node2->name, BAD_CAST "nresults") &&
			(!(str = xmlNodeListGetString(inroot->doc,
						      node2->children, 1)) ||
			 (sscanf((char *) str, "%u", &limit) != 1))) {
			*fctx->errstr = "Invalid limit";
			ret = HTTP_FORBIDDEN;
			goto done;
		    }
		}
	    }
	}
    }

    /* Check Depth */
    if (!fctx->depth) {
	*fctx->errstr = "Illegal sync-level";
	ret = HTTP_BAD_REQUEST;
	goto done;
    }


    /* Construct array of records for sorting and/or fetching cached header */
    istate.mailbox = mailbox;
    istate.map = xzmalloc(mailbox->i.num_records *
			  sizeof(struct index_map));

    /* Find which resources we need to report */
    for (nresp = 0, recno = 1; recno <= mailbox->i.num_records; recno++) {

	record = &istate.map[nresp].record;
	if (mailbox_read_index_record(mailbox, recno, record)) {
	    /* XXX  Corrupted record?  Should we bail? */
	    continue;
	}

	if (record->modseq <= syncmodseq) {
	    /* Resource not added/removed since last sync */
	    continue;
	}

	if (record->user_flags[userflag / 32] & (1 << (userflag & 31))) {
	    /* Resource replaced by a PUT, COPY, or MOVE - ignore it */
	    continue;
	}

	if (!syncmodseq && (record->system_flags & FLAG_EXPUNGED)) {
	    /* Initial sync - ignore unmapped resources */
	    continue;
	}

	nresp++;
    }

    if (limit < nresp) {
	/* Need to truncate the responses */
	struct index_map *map = istate.map;

	/* Sort the response records by modseq */
	qsort(map, nresp, sizeof(struct index_map),
	      (int (*)(const void *, const void *)) &map_modseq_cmp);

	/* Our last response MUST be the last record with its modseq */
	for (nresp = limit;
	     nresp && map[nresp-1].record.modseq == map[nresp].record.modseq;
	     nresp--);

	if (!nresp) {
	    /* DAV:number-of-matches-within-limits */
	    *fctx->errstr = "Unable to truncate results";
	    ret = HTTP_FORBIDDEN;  /* HTTP_NO_STORAGE ? */
	    goto done;
	}

	/* highestmodseq will be modseq of last record we return */
	highestmodseq = map[nresp-1].record.modseq;

	/* Tell client we truncated the responses */
	xml_add_response(fctx, HTTP_NO_STORAGE);
    }

    /* Report the resources within the client requested limit (if any) */
    for (recno = 1; recno <= nresp; recno++) {
	char *p, *resource = NULL;

	record = &istate.map[recno-1].record;

	/* Get resource filename from Content-Disposition header */
	if ((p = index_getheader(&istate, recno, "Content-Disposition"))) {
	    resource = strstr(p, "filename=") + 9;
	}
	if (!resource) continue;  /* No filename */
	if ((p = strchr(resource, ';'))) *p = '\0';

	if (record->system_flags & FLAG_EXPUNGED) {
	    /* report as NOT FOUND
	       propfind_by_resource() will append our resource name */
	    propfind_by_resource(fctx, resource, 0 /* ignore record */);
	}
	else {
	    fctx->record = record;
	    propfind_by_resource(fctx, resource, record->uid);
	}
    }

    /* Add sync-token element */
    snprintf(tokenuri, MAX_MAILBOX_PATH,
	     XML_NS_CYRUS "sync/%u-" MODSEQ_FMT,
	     mailbox->i.uidvalidity, highestmodseq);
    xmlNewChild(fctx->root, NULL, BAD_CAST "sync-token", BAD_CAST tokenuri);

  done:
    if (istate.map) free(istate.map);
    if (mailbox) mailbox_unlock_index(mailbox, NULL);

    return ret;
}


/* Report types and flags */
enum {
    REPORT_NEED_MBOX	= (1<<0),
    REPORT_NEED_PROPS 	= (1<<1),
    REPORT_MULTISTATUS	= (1<<2)
};

typedef int (*report_proc_t)(struct transaction_t *txn, xmlNodePtr inroot,
			     struct propfind_ctx *fctx,
			     char mailboxname[]);

static const struct report_type_t {
    const char *name;
    report_proc_t proc;
    unsigned long reqd_privs;
    unsigned flags;
} report_types[] = {
    { "calendar-query", &report_cal_query, DACL_READ,
      REPORT_NEED_MBOX | REPORT_MULTISTATUS },
    { "calendar-multiget", &report_cal_multiget, DACL_READ,
      REPORT_NEED_MBOX | REPORT_MULTISTATUS },
    { "free-busy-query", &report_fb_query, DACL_READFB,
      REPORT_NEED_MBOX },
    { "sync-collection", &report_sync_col, DACL_READ,
      REPORT_NEED_MBOX | REPORT_MULTISTATUS | REPORT_NEED_PROPS },
    { NULL, NULL, 0, 0 }
};


/* Perform a REPORT request */
static int meth_report(struct transaction_t *txn)
{
    int ret = 0, r;
    const char **hdr;
    unsigned depth = 0;
    xmlNodePtr inroot = NULL, outroot = NULL, cur, prop = NULL;
    const struct report_type_t *report = NULL;
    xmlNsPtr ns[NUM_NAMESPACE];
    char mailboxname[MAX_MAILBOX_BUFFER];
    struct propfind_ctx fctx;
    struct propfind_entry_list *elist = NULL;

    memset(&fctx, 0, sizeof(struct propfind_ctx));

    /* Make sure its a DAV resource */
    if (!(txn->req_tgt.allow & ALLOW_DAV)) return HTTP_NOT_ALLOWED; 

    /* Parse the path */
    if ((r = parse_path(&txn->req_tgt, &txn->error.desc))) return r;

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

    /* Normalize depth so that:
     * 0 = home-set collection, 1+ = calendar collection, 2+ = calendar resource
     */
    if (txn->req_tgt.collection) depth++;
    if (txn->req_tgt.resource) depth++;

    /* Parse the REPORT body */
    ret = parse_xml_body(txn, &inroot);
    if (!inroot) {
	txn->error.desc = "Missing request body";
	return HTTP_BAD_REQUEST;
    }
    if (ret) goto done;

    /* Check the report type against our supported list */
    for (report = report_types; report && report->name; report++) {
	if (!xmlStrcmp(inroot->name, BAD_CAST report->name)) break;
    }
    if (!report || !report->name) {
	syslog(LOG_WARNING, "REPORT %s", inroot->name);
	/* DAV:supported-report */
	txn->error.precond = &preconds[DAV_SUPP_REPORT];
	ret = HTTP_FORBIDDEN;
	goto done;
    }

    if (report->flags & REPORT_NEED_MBOX) {
	char *server, *acl;
	int rights;

	/* Construct mailbox name corresponding to request target URI */
	(void) target_to_mboxname(&txn->req_tgt, mailboxname);

	/* Locate the mailbox */
	if ((r = http_mlookup(mailboxname, &server, &acl, NULL))) {
	    syslog(LOG_ERR, "mlookup(%s) failed: %s",
		   mailboxname, error_message(r));
	    txn->error.desc = error_message(r);

	    switch (r) {
	    case IMAP_PERMISSION_DENIED: ret = HTTP_FORBIDDEN;
	    case IMAP_MAILBOX_NONEXISTENT: ret = HTTP_NOT_FOUND;
	    default: ret = HTTP_SERVER_ERROR;
	    }
	    goto done;
	}

	/* Check ACL for current user */
	rights = acl ? cyrus_acl_myrights(httpd_authstate, acl) : 0;
	if ((rights & report->reqd_privs) != report->reqd_privs) {
	    if (report->reqd_privs == DACL_READFB) ret = HTTP_NOT_FOUND;
	    else {
		/* DAV:need-privileges */
		txn->error.precond = &preconds[DAV_NEED_PRIVS];
		txn->error.resource = txn->req_tgt.path;
		txn->error.rights = report->reqd_privs;
		ret = HTTP_FORBIDDEN;
	    }
	    goto done;
	}

	if (server) {
	    /* Remote mailbox */
	    struct backend *be;

	    be = proxy_findserver(server, &http_protocol, httpd_userid,
				  &backend_cached, NULL, NULL, httpd_in);
	    if (!be) ret = HTTP_UNAVAILABLE;
	    else ret = http_pipe_req_resp(be, txn);
	    goto done;
	}

	/* Local Mailbox */
    }

    /* Principal or Local Mailbox */

    /* Parse children element of report */
    for (cur = inroot->children; cur; cur = cur->next) {
	if (cur->type == XML_ELEMENT_NODE) {
	    if (!xmlStrcmp(cur->name, BAD_CAST "allprop")) {
		syslog(LOG_WARNING, "REPORT %s w/allprop", report->name);
		txn->error.desc = "Unsupported REPORT option <allprop>";
		ret = HTTP_NOT_IMPLEMENTED;
		goto done;
	    }
	    else if (!xmlStrcmp(cur->name, BAD_CAST "propname")) {
		syslog(LOG_WARNING, "REPORT %s w/propname", report->name);
		txn->error.desc = "Unsupported REPORT option <propname>";
		ret = HTTP_NOT_IMPLEMENTED;
		goto done;
	    }
	    else if (!xmlStrcmp(cur->name, BAD_CAST "prop")) {
		prop = cur;
		break;
	    }
	}
    }

    if (!prop && (report->flags & REPORT_NEED_PROPS)) {
	txn->error.desc = "Missing <prop> element in REPORT";
	ret = HTTP_BAD_REQUEST;
	goto done;
    }

    /* Start construction of our multistatus response */
    if ((report->flags & REPORT_MULTISTATUS) &&
	!(outroot = init_xml_response("multistatus", inroot->nsDef, ns))) {
	txn->error.desc = "Unable to create XML response";
	ret = HTTP_SERVER_ERROR;
	goto done;
    }

    /* Populate our propfind context */
    fctx.req_tgt = &txn->req_tgt;
    fctx.depth = depth;
    fctx.userid = httpd_userid;
    fctx.userisadmin = httpd_userisadmin;
    fctx.authstate = httpd_authstate;
    fctx.mailbox = NULL;
    fctx.record = NULL;
    fctx.reqd_privs = report->reqd_privs;
    fctx.elist = NULL;
    fctx.root = outroot;
    fctx.ns = ns;
    fctx.errstr = &txn->error.desc;
    fctx.ret = &ret;

    /* Check for Brief header */
    if ((hdr = spool_getheader(txn->req_hdrs, "Brief")) &&
	!strcasecmp(hdr[0], "t")) {
	fctx.brief = 1;
    }

    /* Parse the list of properties and build a list of callbacks */
    if (prop) preload_proplist(prop->children, &fctx);

    /* Process the requested report */
    ret = (*report->proc)(txn, inroot, &fctx, mailboxname);

    /* Output the XML response */
    if (!ret && outroot) xml_response(HTTP_MULTI_STATUS, txn, outroot->doc);

  done:
    /* Free the entry list */
    elist = fctx.elist;
    while (elist) {
	struct propfind_entry_list *freeme = elist;
	elist = elist->next;
	free(freeme);
    }

    if (fctx.busytime.busy) free(fctx.busytime.busy);
    buf_free(&fctx.buf);

    if (inroot) xmlFreeDoc(inroot->doc);
    if (outroot) xmlFreeDoc(outroot->doc);

    return ret;
}


/* Parse request-target path */
/* XXX  THIS NEEDS TO BE COMPLETELY REWRITTEN
   AND MAYBE COMBINED WITH target_to_mboxname() */
static int parse_path(struct request_target_t *tgt, const char **errstr)
{
    char *p = tgt->path;
    size_t len;

    if (!*p || !*++p) return 0;

    /* Skip namespace */
    len = strcspn(p, "/");
    p += len;
    if (!*p || !*++p) return 0;

    /* Check if we're in user space */
    len = strcspn(p, "/");
    if (!strncmp(p, "user", len)) {
	p += len;
	if (!*p || !*++p) return HTTP_FORBIDDEN;  /* need to specify a userid */

	/* Get user id */
	len = strcspn(p, "/");
	tgt->user = p;
	tgt->userlen = len;

	p += len;
	if (!*p || !*++p) return 0;

	if (tgt->namespace == URL_NS_PRINCIPAL) goto done;

	len = strcspn(p, "/");
    }
    else if (tgt->namespace == URL_NS_PRINCIPAL) {
	return HTTP_FORBIDDEN;  /* need to specify a userid */
    }

    /* Get collection */
    tgt->collection = p;
    tgt->collen = len;

    p += len;
    if (!*p || !*++p) {
	/* Make sure collection is terminated with '/' */
	if (p[-1] != '/') *p++ = '/';
	return 0;
    }

    /* Get resource */
    len = strcspn(p, "/");
    tgt->resource = p;
    tgt->reslen = len;

    p += len;

  done:
    if (*p) {
	*errstr = "Too many segments in request target path";
	return HTTP_FORBIDDEN;
    }

    return 0;
}


static int is_mediatype(const char *hdr, const char *type)
{
    size_t len = strlen(type);

    return (!strncasecmp(hdr, type, len) && strchr("; \t\r\n\0", hdr[len]));
}


/* Parse an XML body into a tree */
static int parse_xml_body(struct transaction_t *txn, xmlNodePtr *root)
{
    const char **hdr;
    xmlParserCtxtPtr ctxt;
    xmlDocPtr doc = NULL;
    int r = 0;

    *root = NULL;

    /* Read body */
    if (!(txn->flags & HTTP_READBODY)) {
	txn->flags |= HTTP_READBODY;
	r = read_body(httpd_in, txn->req_hdrs, &txn->req_body, &txn->error.desc);
	if (r) {
	    txn->flags |= HTTP_CLOSE;
	    return r;
	}
    }

    if (!buf_len(&txn->req_body)) return 0;

    /* Check Content-Type */
    if (!(hdr = spool_getheader(txn->req_hdrs, "Content-Type")) ||
	(!is_mediatype(hdr[0], "text/xml") &&
	 !is_mediatype(hdr[0], "application/xml"))) {
	txn->error.desc = "This method requires an XML body";
	return HTTP_BAD_MEDIATYPE;
    }

    /* Parse the XML request */
    ctxt = xmlNewParserCtxt();
    if (ctxt) {
	doc = xmlCtxtReadMemory(ctxt, buf_cstring(&txn->req_body),
				buf_len(&txn->req_body), NULL, NULL,
				XML_PARSE_NOWARNING);
	xmlFreeParserCtxt(ctxt);
    }
    if (!doc) {
	txn->error.desc = "Unable to parse XML body";
	return HTTP_BAD_REQUEST;
    }

    /* Get the root element of the XML request */
    if (!(*root = xmlDocGetRootElement(doc))) {
	txn->error.desc = "Missing root element in request";
	return HTTP_BAD_REQUEST;
    }

    return 0;
}


/* Create a mailbox name from the request URL */ 
int target_to_mboxname(struct request_target_t *req_tgt, char *mboxname)
{
    static const char *calendarprefix = NULL;
    char *p;
    size_t siz, len;

    if (!calendarprefix) {
	calendarprefix = config_getstring(IMAPOPT_CALENDARPREFIX);
    }

    p = mboxname;
    siz = MAX_MAILBOX_BUFFER - 1;
    if (req_tgt->user) {
	len = snprintf(p, siz, "user");
	p += len;
	siz -= len;

	if (req_tgt->userlen) {
	    len = snprintf(p, siz, ".%.*s",
			   req_tgt->userlen, req_tgt->user);
	    p += len;
	    siz -= len;
	}
    }
    len = snprintf(p, siz, "%s%s", p != mboxname ? "." : "",
		   req_tgt->namespace == URL_NS_CALENDAR ? calendarprefix :
		   "#addressbooks");
    p += len;
    siz -= len;
    if (req_tgt->collection) {
	snprintf(p, siz, ".%.*s",
		 req_tgt->collen, req_tgt->collection);
    }

    return 0;
}


/* XXX  This needs to be done via an LDAP/DB lookup */
static char *caladdress_to_userid(const char *addr)
{
    static char userid[MAX_MAILBOX_BUFFER];
    char *p;

    if (!addr) return NULL;

    p = (char *) addr;
    if (!strncmp(addr, "mailto:", 7)) p += 7;
    strlcpy(userid, p, sizeof(userid));
    if ((p = strchr(userid, '@'))) *p = '\0';

    return userid;
}


/* Perform a Scheduling Busy Time request */
static int sched_busytime(struct transaction_t *txn)
{
    int ret = 0, r, rights;
    char *server, *acl, mailboxname[MAX_MAILBOX_BUFFER];
    const char **hdr;
    icalcomponent *ical, *comp;
    icalcomponent_kind kind = 0;
    icalproperty_method meth = 0;
    icalproperty *prop = NULL;
    const char *uid = NULL, *organizer = NULL, *orgid = NULL;
    struct auth_state *org_authstate = NULL;
    xmlDocPtr doc = NULL;
    xmlNodePtr root = NULL;
    xmlNsPtr calns = NULL, davns = NULL;
    struct propfind_ctx fctx;
    struct calquery_filter filter;

    /* Check Content-Type */
    if (!(hdr = spool_getheader(txn->req_hdrs, "Content-Type")) ||
	!is_mediatype(hdr[0], "text/calendar")) {
	txn->error.precond = &preconds[CALDAV_SUPP_DATA];
	return HTTP_BAD_REQUEST;
    }

    /* Construct mailbox name corresponding to request target URI */
    (void) target_to_mboxname(&txn->req_tgt, mailboxname);

    /* Locate the mailbox */
    if ((r = http_mlookup(mailboxname, &server, &acl, NULL))) {
	syslog(LOG_ERR, "mlookup(%s) failed: %s",
	       mailboxname, error_message(r));
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
	txn->error.precond = &preconds[DAV_NEED_PRIVS];
	txn->error.resource = txn->req_tgt.path;
	txn->error.rights = DACL_SCHED;
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

    /* Read body */
    if (!(txn->flags & HTTP_READBODY)) {
	txn->flags |= HTTP_READBODY;
	r = read_body(httpd_in, txn->req_hdrs, &txn->req_body, &txn->error.desc);
	if (r) {
	    txn->flags |= HTTP_CLOSE;
	    return r;
	}
    }

    /* Make sure we have a body */
    if (!buf_len(&txn->req_body)) {
	txn->error.desc = "Missing request body";
	return HTTP_BAD_REQUEST;
    }

    /* Parse the iCal data for important properties */
    ical = icalparser_parse_string(buf_cstring(&txn->req_body));
    if (!ical || !icalrestriction_check(ical)) {
	txn->error.precond = &preconds[CALDAV_VALID_DATA];
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
	txn->error.precond = &preconds[CALDAV_VALID_SCHED];
	return HTTP_BAD_REQUEST;
    }

    organizer = icalproperty_get_organizer(prop);
    if (organizer) orgid = caladdress_to_userid(organizer);

    if (!orgid || strncmp(orgid, txn->req_tgt.user, txn->req_tgt.userlen)) {
	txn->error.precond = &preconds[CALDAV_VALID_ORGANIZER];
	return HTTP_FORBIDDEN;
    }

    org_authstate = auth_newstate(orgid);

    /* Start construction of our schedule-response */
    if (!(doc = xmlNewDoc(BAD_CAST "1.0")) ||
	!(root = xmlNewNode(NULL, BAD_CAST "schedule-response")) ||
	!(calns = xmlNewNs(root, BAD_CAST XML_NS_CALDAV, BAD_CAST "C")) ||
	!(davns = xmlNewNs(root, BAD_CAST XML_NS_DAV, BAD_CAST "D"))) {
	ret = HTTP_SERVER_ERROR;
	txn->error.desc = "Unable to create XML response";
	goto done;
    }

    xmlDocSetRootElement(doc, root);
    xmlSetNs(root, calns);

    memset(&filter, 0, sizeof(struct calquery_filter));
    filter.comp = COMP_VEVENT | COMP_VFREEBUSY;
    filter.start = icalcomponent_get_dtstart(comp);
    filter.end = icalcomponent_get_dtend(comp);
    filter.check_transp = 1;

    /* Populate our propfind context */
    memset(&fctx, 0, sizeof(struct propfind_ctx));
    fctx.req_tgt = &txn->req_tgt;
    fctx.depth = 2;
    fctx.userid = httpd_userid;
    fctx.userisadmin = httpd_userisadmin;
    fctx.authstate = httpd_authstate;
    fctx.reqd_privs = 0;  /* handled by CALDAV:schedule-deliver on Inbox */
    fctx.calfilter = &filter;
    fctx.errstr = &txn->error.desc;
    fctx.ret = &ret;

    for (prop = icalcomponent_get_first_property(comp, ICAL_ATTENDEE_PROPERTY);
	 prop;
	 prop = icalcomponent_get_next_property(comp, ICAL_ATTENDEE_PROPERTY)) {
	const char *attendee, *userid;
	xmlNodePtr resp, recip, cdata;
	struct mboxlist_entry mbentry;
	icalcomponent *fb;
	int r;

	attendee = icalproperty_get_attendee(prop);

	resp = xmlNewChild(root, NULL, BAD_CAST "response", NULL);
	recip = xmlNewChild(resp, NULL, BAD_CAST "recipient", NULL);
	xmlNewChild(recip, davns, BAD_CAST "href", BAD_CAST attendee);

	userid = caladdress_to_userid(attendee);

	/* Check ACL of ORGANIZER on attendee's Scheduling Inbox */
	snprintf(mailboxname, sizeof(mailboxname),
		 "user.%s.#calendars.Inbox", userid);

	if ((r = mboxlist_lookup(mailboxname, &mbentry, NULL))) {
	    syslog(LOG_INFO, "mboxlist_lookup(%s) failed: %s",
		   mailboxname, error_message(r));
	    xmlNewChild(resp, NULL, BAD_CAST "request-status",
			BAD_CAST "3.7;Invalid calendar user");
	    continue;
	}

	rights =
	    mbentry.acl ? cyrus_acl_myrights(org_authstate, mbentry.acl) : 0;
	if (!(rights & DACL_SCHED)) {
	    xmlNewChild(resp, NULL, BAD_CAST "request-status",
			BAD_CAST "3.8;No authority");
	    continue;
	}

	/* Start query at attendee's calendar-home-set */
	snprintf(mailboxname, sizeof(mailboxname),
		 "user.%s.#calendars", userid);

	fctx.req_tgt->collection = NULL;
	fctx.busytime.len = 0;
	fb = do_fb_query(txn, &fctx, mailboxname,
			 ICAL_METHOD_REPLY, uid, organizer, attendee);

	if (fb) {
	    const char *fb_str = icalcomponent_as_ical_string(fb);
	    icalcomponent_free(fb);

	    xmlNewChild(resp, NULL, BAD_CAST "request-status",
			BAD_CAST "2.0;Success");
	    cdata = xmlNewTextChild(resp, NULL, BAD_CAST "calendar-data", NULL);

	    xmlAddChild(cdata,
			xmlNewCDataBlock(doc, BAD_CAST fb_str, strlen(fb_str)));
 	}
	else {
	    xmlNewChild(resp, NULL, BAD_CAST "request-status",
			BAD_CAST "3.7;Invalid calendar user");
	}
    }

    /* Output the XML response */
    if (!ret) xml_response(HTTP_OK, txn, doc);

  done:
    if (org_authstate) auth_freestate(org_authstate);
    if (fctx.busytime.busy) free(fctx.busytime.busy);
    if (doc) xmlFree(doc);
    icalcomponent_free(ical);

    return ret;
}
