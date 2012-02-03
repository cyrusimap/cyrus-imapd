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
 *   - calendar-query REPORT filtering (optimize for time range, component type)
 *   - free-busy-query REPORT?
 *   - sync-collection REPORT - need to handle Depth infinity?
 *   - Use XML precondition error codes
 *   - Add WebDAV LOCKing?  Does anybody use it?
 */

#include <config.h>

#include <syslog.h>

#include <libical/ical.h>
#include <libxml/tree.h>

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
#include "xmalloc.h"
#include "xstrlcat.h"

#define DFLAG_UNBIND "DAV:unbind"

static int meth_acl(struct transaction_t *txn);
static int meth_copy(struct transaction_t *txn);
static int meth_delete(struct transaction_t *txn);
static int meth_get(struct transaction_t *txn);
static int meth_mkcol(struct transaction_t *txn);
static int meth_proppatch(struct transaction_t *txn);
static int meth_put(struct transaction_t *txn);
static int meth_report(struct transaction_t *txn);
static int parse_path(struct request_target_t *tgt, const char **errstr);
static int is_mediatype(const char *hdr, const char *type);
static int parse_xml_body(struct transaction_t *txn, xmlNodePtr *root);

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
	&meth_put,		/* POST		*/
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
    int ret = 0, r, rights;
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
				       BAD_CAST "all"))
			    rights |= DACL_ALL | DACL_READFB;
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
				   BAD_CAST XML_NS_CAL)
			     /* CalDAV privileges */
			     && !xmlStrcmp(priv->name,
				   BAD_CAST "read-free-busy")) {
			rights |= DACL_READFB;
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
	txn->error.rights = (rights & DACL_READ) != DACL_READ ? DACL_READ : DACL_RMRSRC;
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
	    /* Commit the append to the destination mailbox */
	    if ((r = append_commit(&appendstate, -1,
				   NULL, NULL, NULL, &dest_mbox))) {
		syslog(LOG_ERR, "append_commit(%s) failed: %s",
		       dest_mboxname, error_message(r));
		ret = HTTP_SERVER_ERROR;
		txn->error.desc = "append_commit() failed";
	    }
	    else {
		/* append_commit() returns a write-locked index */
		struct index_record newrecord, oldrecord;

		/* Read index record for new message (always the last one) */
		mailbox_read_index_record(dest_mbox, dest_mbox->i.num_records,
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
		    r = mailbox_find_index_record(dest_mbox, olduid, &oldrecord);

		    /* Expunge the old message */
		    if (!r) r = mailbox_user_flag(dest_mbox, DFLAG_UNBIND,
						  &userflag);
		    if (!r) {
			oldrecord.user_flags[userflag/32] |= 1<<(userflag&31);
			oldrecord.system_flags |= FLAG_EXPUNGED | FLAG_UNLINKED;
			r = mailbox_rewrite_index_record(dest_mbox, &oldrecord);
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

		/* Tell client about the new resource */
		txn->etag = message_guid_encode(&newrecord.guid);
		txn->loc = dest.path;

		mailbox_unlock_index(dest_mbox, NULL);
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
    const char *etag = NULL;
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
    etag = message_guid_encode(&record.guid);
    lastmod = record.internaldate;
    precond = check_precond(txn->meth, etag, lastmod, txn->req_hdrs);

    if (precond != HTTP_OK) {
	/* We failed a precondition - don't perform the request */
	ret = precond;
	goto done;
    }

    /* Fill in Etag, Last-Modified, and Content-Length */
    txn->etag = etag;
    resp_body->lastmod = lastmod;
    resp_body->type = "text/calendar; charset=utf-8";

    if (txn->meth[0] == 'G') {
	/* Load message containing the resource */
	mailbox_map_message(mailbox, record.uid, &msg_base, &msg_size);
    }

    write_body(HTTP_OK, txn,
	       /* skip message header */
	       msg_base + record.header_size, record.size - record.header_size);

    if (msg_base) mailbox_unmap_message(mailbox, record.uid, &msg_base, &msg_size);

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
    else if (r) ret = HTTP_SERVER_ERROR;

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
	char *server;

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
    memset(&fctx, 0, sizeof(struct propfind_ctx));
    fctx.req_tgt = &txn->req_tgt;
    fctx.depth = depth;
    fctx.userid = httpd_userid;
    fctx.userisadmin = httpd_userisadmin;
    fctx.authstate = httpd_authstate;
    fctx.mailbox = NULL;
    fctx.record = NULL;
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
	    find_collection_props(mailboxname, 0, 0, &fctx);
	}
	else {
	    /* Add responses for all contained calendar collections */
	    strlcat(mailboxname, ".%", sizeof(mailboxname));
	    r = mboxlist_findall(NULL,  /* internal namespace */
				 mailboxname, 0, httpd_userid, 
				 httpd_authstate, find_collection_props, &fctx);
	}

	ret = *fctx.ret;
    }

    /* Output the XML response */
    xml_response(HTTP_MULTI_STATUS, txn, outdoc);

  done:
    /* Free the entry list */
    elist = fctx.elist;
    while (elist) {
	struct propfind_entry_list *freeme = elist;
	elist = elist->next;
	free(freeme);
    }

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

    /* Make sure its a DAV resource */
    if (!(txn->req_tgt.allow & ALLOW_WRITE)) return HTTP_NOT_ALLOWED;

    /* Parse the path */
    if ((r = parse_path(&txn->req_tgt, &txn->error.desc))) return r;

    /* Make sure its a calendar collection */
    if (!txn->req_tgt.collection || txn->req_tgt.resource) {
	txn->error.desc = "Properties can only be updated on calendar collections";
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
    xml_response(HTTP_MULTI_STATUS, txn, outdoc);

  done:
    buf_free(&pctx.buf);

    if (outdoc) xmlFreeDoc(outdoc);
    if (indoc) xmlFreeDoc(indoc);

    return ret;
}


/* Perform a PUT/POST request
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
static int global_put_count = 0;

static int meth_put(struct transaction_t *txn)
{
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
    const char **hdr, *uid, *meth;
    uquota_t size = 0;
    time_t now = time(NULL);
    pid_t pid = getpid();
    char datestr[80];
    struct appendstate appendstate;
    icalcomponent *ical, *comp;

    /* Make sure its a DAV resource */
    if (!(txn->req_tgt.allow & ALLOW_WRITE)) return HTTP_NOT_ALLOWED; 

    /* Parse the path */
    if ((r = parse_path(&txn->req_tgt, &txn->error.desc))) return r;

    /* We don't handle POST/PUT on non-calendar collections */
    if (!txn->req_tgt.collection) return HTTP_NOT_ALLOWED;

    /* We don't handle PUT on calendar collections */
    if (!txn->req_tgt.resource && (txn->meth[1] != 'O')) return HTTP_NOT_ALLOWED;

    /* Check Content-Type */
    if (!(hdr = spool_getheader(txn->req_hdrs, "Content-Type")) ||
	!is_mediatype(hdr[0], "text/calendar")) {
	txn->error.desc = "This collection only supports text/calendar data";
	return HTTP_BAD_MEDIATYPE;
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

    if (txn->meth[1] == 'O') {
	/* POST - Create a unique resource name and append to URL path */
	size_t len = strlen(txn->req_tgt.path);
	char *p = txn->req_tgt.path + len;

	if (p[-1] != '/') {
	    *p++ = '/';
	    len++;
	}
	snprintf(p, MAX_MAILBOX_PATH - len, "%d-%d-%s-%u.ics",
		 pid, (int) now, mailbox->uniqueid, mailbox->i.last_uid+1);
	txn->req_tgt.resource = p;
	txn->req_tgt.reslen = strlen(p);
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
    txn->flags |= HTTP_READBODY;
    r = read_body(httpd_in, txn->req_hdrs, &txn->req_body, &txn->error.desc);
    if (r) {
	txn->flags |= HTTP_CLOSE;
	ret = r;
	goto done;
    }

    /* Make sure we have a body */
    if (!buf_len(&txn->req_body)) {
	txn->error.desc = "Missing request body";
	ret = HTTP_BAD_REQUEST;
	goto done;
    }

    /* Parse the iCal data for important properties */
    ical = icalparser_parse_string(buf_cstring(&txn->req_body));
    if (!ical) {
	txn->error.desc = "Invalid calendar data";
	ret = HTTP_BAD_MEDIATYPE;
	goto done;
    }
    comp = icalcomponent_get_first_real_component(ical);

    /* Prepare to stage the message */
    if (!(f = append_newstage(mailboxname, now, 0, &stage))) {
	txn->error.desc = error_message(r);
	ret = HTTP_SERVER_ERROR;
	goto done;
    }


    /* Create iMIP header for resource */
    fprintf(f, "From: <%s>\r\n", httpd_userid ? httpd_userid : "");

    fprintf(f, "Subject: %s\r\n", icalcomponent_get_summary(comp));

    rfc822date_gen(datestr, sizeof(datestr), now);
    fprintf(f, "Date: %s\r\n", datestr);

    fprintf(f, "Message-ID: ");
    if ((uid = icalcomponent_get_uid(comp)) && *uid) fprintf(f, "<%s", uid);
    else fprintf(f, "<cmu-http-%d-%d-%d", pid, (int) now, global_put_count++);
    fprintf(f, "@%s>\r\n", config_servername);

    hdr = spool_getheader(txn->req_hdrs, "Content-Type");
    fprintf(f, "Content-Type: %s", hdr[0]);
    if ((meth = icalproperty_method_to_string(icalcomponent_get_method(comp)))
	&& *meth) {
	fprintf(f, "; method=%s", meth);
    }
    fprintf(f, "\r\n");

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

	if (!r) {
	    /* Commit the append to the calendar mailbox */
	    if ((r = append_commit(&appendstate, size,
				   NULL, NULL, NULL, &mailbox))) {
		ret = HTTP_SERVER_ERROR;
		txn->error.desc = "append_commit() failed";
	    }
	    else {
		struct index_record newrecord, *expunge;

		/* Read index record for new message (always the last one) */
		mailbox_read_index_record(mailbox, mailbox->i.num_records,
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
		    r = mailbox_find_index_record(mailbox, olduid, &oldrecord);

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
		    r = mailbox_user_flag(mailbox, DFLAG_UNBIND,  &userflag);
		    if (!r) {
			expunge->user_flags[userflag/32] |= 1<<(userflag&31);
			expunge->system_flags |= FLAG_EXPUNGED | FLAG_UNLINKED;
			r = mailbox_rewrite_index_record(mailbox, expunge);
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

		    /* Tell client about the new resource */
		    txn->etag = message_guid_encode(&newrecord.guid);
		    txn->loc = txn->req_tgt.path;
		}
	    }
	}
	else {
	    append_abort(&appendstate);
	}

	/* append_setup() opened mailbox again,
	   we need to close it to decrement reference count */
	if (mailbox) mailbox_close(&mailbox);
    }

  done:
    if (stage) append_removestage(stage);
    if (caldavdb) caldav_close(caldavdb);
    if (mailbox) mailbox_unlock_index(mailbox, NULL);

    return ret;
}


static int report_cal_query(xmlNodePtr inroot, struct propfind_ctx *fctx,
			    struct caldav_db *caldavdb)
{
    int ret = 0;
    xmlNodePtr node;

    /* Parse children element of report */
    for (node = inroot->children; node; node = node->next) {
	if (node->type == XML_ELEMENT_NODE) {
	    if (!xmlStrcmp(node->name, BAD_CAST "filter")) {
		syslog(LOG_WARNING, "REPORT calendar-query w/filter");
	    }
	}
    }

    caldav_foreach(caldavdb, find_resource_props, fctx);

    return ret;
}


static int report_cal_multiget(xmlNodePtr inroot, struct propfind_ctx *fctx,
			       struct caldav_db *caldavdb)
{
    int ret = 0;
    xmlNodePtr node;

    /* Get props for each href */
    for (node = inroot->children; node; node = node->next) {
	if ((node->type == XML_ELEMENT_NODE) &&
	    !xmlStrcmp(node->name, BAD_CAST "href")) {
	    xmlChar *href = xmlNodeListGetString(inroot->doc, node->children, 1);
	    const char *resource = strrchr((char *) href, '/') + 1;
	    uint32_t uid = 0;

	    /* Find message UID for the resource */
	    caldav_read(caldavdb, resource, &uid);
	    /* XXX  Check errors */

	    find_resource_props(fctx, resource, uid);
	}
    }

    return ret;
}

static int map_modseq_cmp(const struct index_map *m1,
			  const struct index_map *m2)
{
    if (m1->record.modseq < m2->record.modseq) return -1;
    if (m1->record.modseq > m2->record.modseq) return 1;
    return 0;
}

static int report_sync_col(xmlNodePtr inroot, struct propfind_ctx *fctx,
			   struct caldav_db *caldavdb __attribute__((unused)))
{
    int ret = 0, r, userflag;
    struct mailbox *mailbox = fctx->mailbox;
    uint32_t uidvalidity = 0;
    modseq_t syncmodseq = 0, highestmodseq = mailbox->i.highestmodseq;
    uint32_t limit = -1, recno, nresp;
    xmlNodePtr node;
    struct index_state istate;
    struct index_record *record;
    char tokenuri[MAX_MAILBOX_PATH+1];

    /* XXX  Handle Depth (cal-home-set at toplevel) */

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
		    return HTTP_FORBIDDEN;
		}
	    }
	    if (!xmlStrcmp(node->name, BAD_CAST "sync-level") &&
		(str = xmlNodeListGetString(inroot->doc, node->children, 1))) {
		if (!strcmp((char *) str, "infinity")) {
		    *fctx->errstr = "This server DOES NOT support infinite depth requests";
		    return HTTP_SERVER_ERROR;
		}
		else if ((sscanf((char *) str, "%u", &fctx->depth) != 1) ||
			 (fctx->depth != 1)) {
		    *fctx->errstr = "Illegal sync-level";
		    return HTTP_BAD_REQUEST;
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
			return HTTP_FORBIDDEN;
		    }
		}
	    }
	}
    }

    /* Check Depth */
    if (!fctx->depth) {
	*fctx->errstr = "Illegal sync-level";
	return HTTP_BAD_REQUEST;
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
	    return HTTP_FORBIDDEN;  /* HTTP_NO_STORAGE ? */
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
	       find_resource_props() will append our resource name */
	    find_resource_props(fctx, resource, 0 /* ignore record */);
	}
	else {
	    fctx->record = record;
	    find_resource_props(fctx, resource, record->uid);
	}
    }

    /* Add sync-token element */
    snprintf(tokenuri, MAX_MAILBOX_PATH,
	     XML_NS_CYRUS "sync/%u-" MODSEQ_FMT,
	     fctx->mailbox->i.uidvalidity, highestmodseq);
    xmlNewChild(fctx->root, NULL, BAD_CAST "sync-token", BAD_CAST tokenuri);

    free(istate.map);

    return ret;
}


/* Report types and flags */
enum {
    REPORT_NEED_MBOX  = (1<<0),
    REPORT_NEED_DAVDB = (1<<1),
    REPORT_NEED_PROPS = (1<<2),
    REPORT_USE_BRIEF  = (1<<3)
};

typedef int (*report_proc_t)(xmlNodePtr inroot, struct propfind_ctx *fctx,
			     struct caldav_db *caldavdb);

static const struct report_type_t {
    const char *name;
    report_proc_t proc;
    unsigned flags;
} report_types[] = {
    { "calendar-query", &report_cal_query,
      REPORT_NEED_MBOX |REPORT_NEED_DAVDB | REPORT_USE_BRIEF },
    { "calendar-multiget", &report_cal_multiget,
      REPORT_NEED_MBOX | REPORT_NEED_DAVDB | REPORT_USE_BRIEF },
    { "sync-collection", &report_sync_col,
      REPORT_NEED_MBOX | REPORT_NEED_PROPS },
    { NULL, NULL, 0 }
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
    struct mailbox *mailbox = NULL;
    struct caldav_db *caldavdb = NULL;
    struct propfind_ctx fctx;
    struct propfind_entry_list *elist = NULL;

    /* Make sure its a DAV resource */
    if (!(txn->req_tgt.allow & ALLOW_DAV)) return HTTP_NOT_ALLOWED; 

    /* Parse the path */
    if ((r = parse_path(&txn->req_tgt, &txn->error.desc))) return r;

    /* Check Depth */
    if ((hdr = spool_getheader(txn->req_hdrs, "Depth"))) {
	if (!strcmp(hdr[0], "infinity")) {
	    txn->error.desc = "This server DOES NOT support infinite depth requests";
	    return HTTP_SERVER_ERROR;
	}
	else if ((sscanf(hdr[0], "%u", &depth) != 1) || (depth > 1)) {
	    txn->error.desc = "Illegal Depth value";
	    return HTTP_BAD_REQUEST;
	}
    }

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
    if (!(outroot = init_xml_response("multistatus", inroot->nsDef, ns))) {
	txn->error.desc = "Unable to create XML response";
	ret = HTTP_SERVER_ERROR;
	goto done;
    }

    /* Populate our propfind context */
    memset(&fctx, 0, sizeof(struct propfind_ctx));
    fctx.req_tgt = &txn->req_tgt;
    fctx.depth = depth;
    fctx.userid = httpd_userid;
    fctx.userisadmin = httpd_userisadmin;
    fctx.authstate = httpd_authstate;
    fctx.mailbox = NULL;
    fctx.record = NULL;
    fctx.elist = NULL;
    fctx.root = outroot;
    fctx.ns = ns;
    fctx.errstr = &txn->error.desc;
    fctx.ret = &ret;

    /* Check for Brief header */
    if ((report->flags & REPORT_USE_BRIEF) &&
	(hdr = spool_getheader(txn->req_hdrs, "Brief")) &&
	!strcasecmp(hdr[0], "t")) {
	fctx.brief = 1;
    }

    /* Parse the list of properties and build a list of callbacks */
    if (prop) preload_proplist(prop->children, &fctx);

    if (report->flags & REPORT_NEED_MBOX) {
	char *server, *acl, mailboxname[MAX_MAILBOX_BUFFER];
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
	    if (!be) ret = HTTP_UNAVAILABLE;
	    else ret = http_pipe_req_resp(be, txn);
	    goto done;
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

	if (report->flags & REPORT_NEED_DAVDB) {
	    /* Open the associated CalDAV database */
	    if ((r = caldav_open(mailbox, CALDAV_CREATE, &caldavdb))) {
		txn->error.desc = error_message(r);
		ret = HTTP_SERVER_ERROR;
		goto done;
	    }
	}

	fctx.mailbox = mailbox;
    }

    /* Process the requested report */
    ret = (*report->proc)(inroot, &fctx, caldavdb);

    /* Output the XML response */
    if (!ret) xml_response(HTTP_MULTI_STATUS, txn, outroot->doc);

  done:
    if (caldavdb) caldav_close(caldavdb);
    if (mailbox) mailbox_unlock_index(mailbox, NULL);

    /* Free the entry list */
    elist = fctx.elist;
    while (elist) {
	struct propfind_entry_list *freeme = elist;
	elist = elist->next;
	free(freeme);
    }

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
    if (!*p || !*++p) return 0;

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

    /* Check Content-Type */
    if (!(hdr = spool_getheader(txn->req_hdrs, "Content-Type")) ||
	(!is_mediatype(hdr[0], "text/xml") &&
	 !is_mediatype(hdr[0], "application/xml"))) {
	txn->error.desc = "This method requires an XML body";
	return HTTP_BAD_MEDIATYPE;
    }

    /* Read body */
    txn->flags |= HTTP_READBODY;
    if ((r = read_body(httpd_in, txn->req_hdrs, &txn->req_body, &txn->error.desc))) {
	txn->flags |= HTTP_CLOSE;
	return r;
    }

    if (!buf_len(&txn->req_body)) return 0;

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
