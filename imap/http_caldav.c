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
 *     calendars.  COPY/MOVE doesn't handle remote destination.
 *   - Check meth_acl() to make sure we have logic correct
 *     (iCal seems to blow up existing ACLs).
 *   - Fix PROPFIND depth logic?  (need to confirm that its broken)
 *   - Support COPY/MOVE on collections
 *   - Add more required properties
 *   - GET/HEAD on collections (iCalendar stream of resources)
 *   - calendar-query REPORT filtering (optimize for time range, component type)
 *   - free-busy-query REPORT
 *   - sync-collection REPORT (can probably use MODSEQs -- as CTag too)
 *   - Use XML precondition error codes
 *   - Add WebDAV LOCKing?  Does anybody use it?
 *   - Should we have a linked-list/hash of open mailboxes,
 *     rather than open/close for every method?
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
#include "util.h"
#include "xstrlcat.h"

static int meth_acl(struct transaction_t *txn);
static int meth_copy(struct transaction_t *txn);
static int meth_delete(struct transaction_t *txn);
static int meth_get(struct transaction_t *txn);
static int meth_mkcol(struct transaction_t *txn);
static int meth_proppatch(struct transaction_t *txn);
static int meth_put(struct transaction_t *txn);
static int meth_report(struct transaction_t *txn);
static int parse_path(struct request_target_t *tgt, const char **errstr);
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
    int ret = 0, r;
    xmlDocPtr indoc = NULL;
    xmlNodePtr root, ace;
    char *server, mailboxname[MAX_MAILBOX_BUFFER];
    struct mailbox *mailbox = NULL;
    struct buf acl = BUF_INITIALIZER;

    /* Response should not be cached */
    txn->flags |= HTTP_NOCACHE;

    /* Make sure its a DAV resource */
    if (!(txn->req_tgt.allow & ALLOW_WRITE)) return HTTP_NOT_ALLOWED;

    /* Parse the path */
    if ((r = parse_path(&txn->req_tgt, &txn->errstr))) return r;

    /* Make sure its a calendar collection */
    if (!txn->req_tgt.collection || txn->req_tgt.resource) {
	txn->errstr = "ACLs can only be set on calendar collections";
	syslog(LOG_DEBUG, "Tried to set ACL on non-calendar collection");
	return HTTP_NOT_ALLOWED;
    }

    /* Construct mailbox name corresponding to request target URI */
    (void) target_to_mboxname(&txn->req_tgt, mailboxname);

    /* Locate the mailbox */
    if ((r = http_mlookup(mailboxname, &server, NULL, NULL))) {
	syslog(LOG_ERR, "mlookup(%s) failed: %s",
	       mailboxname, error_message(r));
	txn->errstr = error_message(r);

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

    /* Open mailbox for writing */
    if ((r = mailbox_open_iwl(mailboxname, &mailbox))) {
	syslog(LOG_ERR, "mailbox_open_iwl(%s) failed: %s",
	       mailboxname, error_message(r));
	txn->errstr = error_message(r);
	ret = HTTP_SERVER_ERROR;
	goto done;
    }

    /* Check ACL for current user */
    if (!(cyrus_acl_myrights(httpd_authstate, mailbox->acl) & DACL_ADMIN)) {
	/* DAV:need-privilege */
	ret = HTTP_FORBIDDEN;
	goto done;
    }

    /* Parse the ACL body */
    ret = parse_xml_body(txn, &root);
    if (!root) {
	txn->errstr = "Missing request body";
	ret = HTTP_BAD_REQUEST;
    }
    if (ret) goto done;

    indoc = root->doc;

    /* Make sure its an DAV:acl element */
    if (xmlStrcmp(root->name, BAD_CAST "acl")) {
	txn->errstr = "Missing acl element in ACL request";
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
			    txn->errstr = "Multiple principals in ACE";
			    ret = HTTP_BAD_REQUEST;
			    goto done;
			}

			prin = child->children;
		    }
		    else if (!xmlStrcmp(child->name, BAD_CAST "grant")) {
			if (privs) {
			    txn->errstr = "Multiple grant|deny in ACE";
			    ret = HTTP_BAD_REQUEST;
			    goto done;
			}

			privs = child->children;
		    }
		    else if (!xmlStrcmp(child->name, BAD_CAST "deny")) {
			if (privs) {
			    txn->errstr = "Multiple grant|deny in ACE";
			    ret = HTTP_BAD_REQUEST;
			    goto done;
			}

			privs = child->children;
			deny = 1;
		    }
		    else if (!xmlStrcmp(child->name, BAD_CAST "invert")) {
			/* DAV:no-invert */
			ret = HTTP_FORBIDDEN;
			goto done;
		    }
		    else {
			txn->errstr = "Unknown element in ACE";
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
		ret = HTTP_FORBIDDEN;
		goto done;
	    }

	    for (; privs; privs = privs->next) {
		if (privs->type == XML_ELEMENT_NODE) {
		    if (!xmlStrcmp(privs->children->ns->href,
				   BAD_CAST XML_NS_DAV)) {
			/* WebDAV privileges */
			if (!xmlStrcmp(privs->children->name,
				       BAD_CAST "all"))
			    rights |= DACL_ALL | DACL_READFB;
			else if (!xmlStrcmp(privs->children->name,
				       BAD_CAST "read"))
			    rights |= DACL_READ | DACL_READFB;
			else if (!xmlStrcmp(privs->children->name,
				       BAD_CAST "write"))
			    rights |= DACL_WRITE;
			else if (!xmlStrcmp(privs->children->name,
				       BAD_CAST "write-content"))
			    rights |= DACL_WRITECONT;
			else if (!xmlStrcmp(privs->children->name,
				       BAD_CAST "write-properties"))
			    rights |= DACL_WRITEPROPS;
			else if (!xmlStrcmp(privs->children->name,
				       BAD_CAST "bind"))
			    rights |= DACL_BIND;
			else if (!xmlStrcmp(privs->children->name,
				       BAD_CAST "unbind"))
			    rights |= DACL_UNBIND;
			else if (!xmlStrcmp(privs->children->name,
					    BAD_CAST "read-current-user-privilege-set")
				 || !xmlStrcmp(privs->children->name,
					       BAD_CAST "read-acl")
				 || !xmlStrcmp(privs->children->name,
					       BAD_CAST "write-acl")
				 || !xmlStrcmp(privs->children->name,
					       BAD_CAST "unlock")) {
			    /* DAV:no-abstract */
			    ret = HTTP_FORBIDDEN;
			    goto done;
			}
			else {
			    /* DAV:not-supported-privilege */
			    ret = HTTP_FORBIDDEN;
			    goto done;
			}
		    }

		    else if (!xmlStrcmp(privs->children->ns->href,
				   BAD_CAST XML_NS_CAL)
			     /* CalDAV privileges */
			     && !xmlStrcmp(privs->children->name,
				   BAD_CAST "read-free-busy")) {
			rights |= DACL_READFB;
		    }

		    else if (!xmlStrcmp(privs->children->ns->href,
				   BAD_CAST XML_NS_CYRUS)) {
			/* Cyrus-specific privileges */
			if (!xmlStrcmp(privs->children->name,
				       BAD_CAST "make-collection"))
			    rights |= DACL_MKCOL;
			else if (!xmlStrcmp(privs->children->name,
				       BAD_CAST "remove-collection"))
			    rights |= DACL_RMCOL;
			else if (!xmlStrcmp(privs->children->name,
				       BAD_CAST "add-resource"))
			    rights |= DACL_ADDRSRC;
			else if (!xmlStrcmp(privs->children->name,
				       BAD_CAST "remove-resource"))
			    rights |= DACL_RMRSRC;
			else if (!xmlStrcmp(privs->children->name,
				       BAD_CAST "admin"))
			    rights |= DACL_ADMIN;
			else {
			    /* DAV:not-supported-privilege */
			    ret = HTTP_FORBIDDEN;
			    goto done;
			}
		    }
		    else {
			/* DAV:not-supported-privilege */
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
	txn->errstr = error_message(r);
	ret = HTTP_SERVER_ERROR;
	goto done;
    }
    mailbox_set_acl(mailbox, buf_cstring(&acl), 0);

    response_header(HTTP_OK, txn);

  done:
    buf_free(&acl);
    if (indoc) xmlFreeDoc(indoc);
    if (mailbox) mailbox_close(&mailbox);

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
    int ret = HTTP_CREATED, r, precond;
    const char **hdr;
    struct request_target_t dest;  /* Parsed destination URL */
    char src_mboxname[MAX_MAILBOX_BUFFER], dest_mboxname[MAX_MAILBOX_BUFFER];
    char *server;
    struct mailbox *src_mbox = NULL, *dest_mbox = NULL;
    struct caldav_db *src_caldb = NULL, *dest_caldb = NULL;
    uint32_t src_uid = 0, olduid = 0;
    struct index_record src_rec;
    const char *etag = NULL;
    time_t lastmod = 0;
    struct appendstate appendstate;

    /* Response should not be cached */
    txn->flags |= HTTP_NOCACHE;

    /* We don't accept a body for this method */
    if (buf_len(&txn->req_body)) return HTTP_BAD_MEDIATYPE;

    /* Make sure source is a DAV resource */
    if (!(txn->req_tgt.allow & ALLOW_DAV)) return HTTP_NOT_ALLOWED;

    /* Parse the path */
    if ((r = parse_path(&txn->req_tgt, &txn->errstr))) return r;

    /* We don't yet handle COPY/MOVE on collections */
    if (!txn->req_tgt.resource) return HTTP_NOT_ALLOWED;

    /* Check for mandatory Destination header */
    if (!(hdr = spool_getheader(txn->req_hdrs, "Destination"))) {
	txn->errstr = "Missing Destination header";
	return HTTP_BAD_REQUEST;
    }

    /* Parse destination URI */
    if ((r = parse_uri(NULL, hdr[0], &dest, &txn->errstr))) return r;

    /* Check namespace */
    if (strncmp("/calendars/", dest.path, strlen("/calendars/")))
	return HTTP_FORBIDDEN;

    dest.namespace = URL_NS_CALENDAR;
    if ((r = parse_path(&dest, &txn->errstr))) return r;

    /* Make sure dest resource is in same namespace as source */
    if (txn->req_tgt.namespace != dest.namespace) return HTTP_FORBIDDEN;

    /* Make sure source and dest resources are NOT the same */
    if (!strcmp(txn->req_tgt.path, dest.path)) {
	txn->errstr = "Source and destination resources are the same";
	return HTTP_FORBIDDEN;
    }

    /* Construct source mailbox name corresponding to request target URI */
    (void) target_to_mboxname(&txn->req_tgt, src_mboxname);

    /* Locate the mailbox */
    if ((r = http_mlookup(src_mboxname, &server, NULL, NULL))) {
	syslog(LOG_ERR, "mlookup(%s) failed: %s",
	       src_mboxname, error_message(r));
	txn->errstr = error_message(r);

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

    /* Open source mailbox for reading */
    if ((r = mailbox_open_irl(src_mboxname, &src_mbox))) {
	syslog(LOG_ERR, "mailbox_open_irl(%s) failed: %s",
	       src_mboxname, error_message(r));
	txn->errstr = error_message(r);
	ret = HTTP_SERVER_ERROR;
	goto done;
    }

    /* Open the associated CalDAV database */
    if ((r = caldav_open(src_mbox, 0, &src_caldb))) {
	syslog(LOG_ERR, "caldav_open(%s) failed: %s",
	       src_mboxname, error_message(r));
	txn->errstr = error_message(r);
	ret = HTTP_SERVER_ERROR;
	goto done;
    }

    /* Find message UID for the source resource */
    caldav_read(src_caldb, txn->req_tgt.resource, &src_uid);
    /* XXX  Check errors */

    /* Fetch index record for the source resource */
    if (!src_uid || mailbox_find_index_record(src_mbox, src_uid, &src_rec)) {
	ret = HTTP_NOT_FOUND;
	goto done;
    }

    /* Fetch cache record for the source resource (so we can copy it) */
    if ((r = mailbox_cacherecord(src_mbox, &src_rec))) {
	syslog(LOG_ERR, "mailbox_cacherecord(%s) failed: %s",
	       src_mboxname, error_message(r));
	txn->errstr = error_message(r);
	ret = HTTP_SERVER_ERROR;
	goto done;
    }

    /* Finished our initial read of source mailbox */
    mailbox_unlock_index(src_mbox, NULL);

    /* Construct dest mailbox name corresponding to destination URI */
    (void) target_to_mboxname(&dest, dest_mboxname);

    /* XXX  Need to check for remote dest mailbox and use PUT */

    /* Open dest mailbox for reading */
    if ((r = mailbox_open_irl(dest_mboxname, &dest_mbox))) {
	syslog(LOG_ERR, "mailbox_open_irl(%s) failed: %s",
	       dest_mboxname, error_message(r));
	txn->errstr = error_message(r);
	ret = HTTP_SERVER_ERROR;
	goto done;
    }

    /* Open the associated CalDAV database */
    if ((r = caldav_open(dest_mbox, CALDAV_CREATE, &dest_caldb))) {
	syslog(LOG_ERR, "caldav_open(%s) failed: %s",
	       dest_mboxname, error_message(r));
	txn->errstr = error_message(r);
	ret = HTTP_SERVER_ERROR;
	goto done;
    }

    /* Find message UID for the dest resource, if exists */
    caldav_read(dest_caldb, dest.resource, &olduid);
    /* XXX  Check errors */

    /* Finished our initial read of dest mailbox */
    mailbox_unlock_index(dest_mbox, NULL);

    /* Check any preconditions */
    etag = message_guid_encode(&src_rec.guid);
    lastmod = src_rec.internaldate;
    precond = check_precond(txn->meth, etag, lastmod, olduid, txn->req_hdrs);

    if (precond != HTTP_OK) {
	/* We failed a precondition - don't perform the request */
	ret = precond;
	goto done;
    }

    /* Prepare to append source resource to destination mailbox */
    if ((r = append_setup(&appendstate, dest_mboxname, 
			  httpd_userid, httpd_authstate, ACL_INSERT,
			  (txn->meth[0]) == 'C' ? (long) src_rec.size : -1))) {
	syslog(LOG_ERR, "append_setup(%s) failed: %s",
	       dest_mboxname, error_message(r));
	ret = HTTP_SERVER_ERROR;
	txn->errstr = "append_setup() failed";
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
	    txn->errstr = "append_copy() failed";
	}

	if (!r) {
	    /* Commit the append to the destination mailbox */
	    if ((r = append_commit(&appendstate, -1,
				   NULL, NULL, NULL, &dest_mbox))) {
		syslog(LOG_ERR, "append_commit(%s) failed: %s",
		       dest_mboxname, error_message(r));
		ret = HTTP_SERVER_ERROR;
		txn->errstr = "append_commit() failed";
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
		    oldrecord.system_flags |= FLAG_EXPUNGED;
		    if ((r = mailbox_rewrite_index_record(dest_mbox, &oldrecord))) {
			syslog(LOG_ERR, "rewrite_index_rec(%s) failed: %s",
			       dest_mboxname, error_message(r));
			txn->errstr = error_message(r);
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


		/* For MOVE, we need to delete the source resource */
		if (txn->meth[0] == 'M') {
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
			    syslog(LOG_ERR, "rewrite_index_rec(%s) failed: %s",
				   src_mboxname, error_message(r));
			    txn->errstr = error_message(r);
			    ret = HTTP_SERVER_ERROR;
			    goto done;
			}
		    }

		    /* Delete mapping entry for source resource name */
		    caldav_delete(src_caldb, txn->req_tgt.resource);
		}
	    }
	}
	else {
	    append_abort(&appendstate);
	}
    }

  done:
    if (dest_caldb) caldav_close(dest_caldb);
    if (dest_mbox) mailbox_close(&dest_mbox);
    if (src_caldb) caldav_close(src_caldb);
    if (src_mbox) mailbox_close(&src_mbox);

    return ret;
}


/* Perform a DELETE request */
static int meth_delete(struct transaction_t *txn)
{
    int ret = HTTP_NO_CONTENT, r, precond;
    char *server, mailboxname[MAX_MAILBOX_BUFFER];
    struct mailbox *mailbox = NULL;
    struct caldav_db *caldavdb = NULL;
    uint32_t uid = 0;
    struct index_record record;
    const char *etag = NULL;
    time_t lastmod = 0;

    /* Make sure its a DAV resource */
    if (!(txn->req_tgt.allow & ALLOW_WRITE)) return HTTP_NOT_ALLOWED; 

    /* Parse the path */
    if ((r = parse_path(&txn->req_tgt, &txn->errstr))) return r;

    /* Construct mailbox name corresponding to request target URI */
    (void) target_to_mboxname(&txn->req_tgt, mailboxname);

    /* Locate the mailbox */
    if ((r = http_mlookup(mailboxname, &server, NULL, NULL))) {
	syslog(LOG_ERR, "mlookup(%s) failed: %s",
	       mailboxname, error_message(r));
	txn->errstr = error_message(r);

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
    if ((r = mailbox_open_iwl(mailboxname, &mailbox))) {
	syslog(LOG_ERR, "mailbox_open_iwl(%s) failed: %s",
	       mailboxname, error_message(r));
	txn->errstr = error_message(r);
	ret = HTTP_SERVER_ERROR;
	goto done;
    }

    /* Open the associated CalDAV database */
    if ((r = caldav_open(mailbox, CALDAV_CREATE, &caldavdb))) {
	txn->errstr = error_message(r);
	ret = HTTP_SERVER_ERROR;
	goto done;
    }

    /* Find message UID for the resource */
    caldav_lockread(caldavdb, txn->req_tgt.resource, &uid);
    /* XXX  Check errors */

    /* Fetch index record for the resource */
    if (!uid || mailbox_find_index_record(mailbox, uid, &record)) {
	ret = HTTP_NOT_FOUND;
	goto done;
    }

    etag = message_guid_encode(&record.guid);
    lastmod = record.internaldate;

    /* Check any preconditions */
    precond = check_precond(txn->meth, etag, lastmod, 0, txn->req_hdrs);

    /* We failed a precondition - don't perform the request */
    if (precond != HTTP_OK) {
	ret = precond;
	goto done;
    }

    /* Expunge the resource */
    record.system_flags |= FLAG_EXPUNGED;

    if ((r = mailbox_rewrite_index_record(mailbox, &record))) {
	syslog(LOG_ERR, "rewrite_index_rec(%s) failed: %s",
	       mailboxname, error_message(r));
	txn->errstr = error_message(r);
	ret = HTTP_SERVER_ERROR;
	goto done;
    }

    /* Delete mapping entry for resource name */
    caldav_delete(caldavdb, txn->req_tgt.resource);

  done:
    if (caldavdb) caldav_close(caldavdb);
    if (mailbox) mailbox_close(&mailbox);

    return ret;
}


/* Perform a GET/HEAD request */
static int meth_get(struct transaction_t *txn)
{
    int ret = 0, r, precond;
    const char *msg_base = NULL;
    unsigned long msg_size = 0;
    struct resp_body_t *resp_body = &txn->resp_body;
    char *server, mailboxname[MAX_MAILBOX_BUFFER];
    struct mailbox *mailbox = NULL;
    struct caldav_db *caldavdb = NULL;
    uint32_t uid = 0;
    struct index_record record;
    const char *etag = NULL;
    time_t lastmod = 0;

    /* We don't accept a body for this method */
    if (buf_len(&txn->req_body)) return HTTP_BAD_MEDIATYPE;

    /* Parse the path */
    if ((r = parse_path(&txn->req_tgt, &txn->errstr))) return r;

    /* We don't handle GET on a calendar collection (yet) */
    if (!txn->req_tgt.resource) return HTTP_NO_CONTENT;

    /* Construct mailbox name corresponding to request target URI */
    (void) target_to_mboxname(&txn->req_tgt, mailboxname);

    /* Locate the mailbox */
    if ((r = http_mlookup(mailboxname, &server, NULL, NULL))) {
	syslog(LOG_ERR, "mlookup(%s) failed: %s",
	       mailboxname, error_message(r));
	txn->errstr = error_message(r);

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

    /* Open mailbox for reading */
    if ((r = mailbox_open_irl(mailboxname, &mailbox))) {
	syslog(LOG_ERR, "mailbox_open_irl(%s) failed: %s",
	       mailboxname, error_message(r));
	txn->errstr = error_message(r);
	ret = HTTP_SERVER_ERROR;
	goto done;
    }

    /* Open the associated CalDAV database */
    if ((r = caldav_open(mailbox, CALDAV_CREATE, &caldavdb))) {
	txn->errstr = error_message(r);
	ret = HTTP_SERVER_ERROR;
	goto done;
    }

    /* Find message UID for the resource */
    caldav_read(caldavdb, txn->req_tgt.resource, &uid);
    /* XXX  Check errors */

    /* Fetch index record for the resource */
    r = mailbox_find_index_record(mailbox, uid, &record);
    /* XXX  check for errors */

    etag = message_guid_encode(&record.guid);
    lastmod = record.internaldate;

    /* Check any preconditions */
    precond = check_precond(txn->meth, etag, lastmod, 0, txn->req_hdrs);

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
    if (mailbox) mailbox_close(&mailbox);

    return ret;
}


/* Perform a MKCOL/MKCALENDAR request */
/*
 * preconditions:
 *   DAV:resource-must-be-null
 *   DAV:need-privilege
 *   DAV:valid-resourcetype
 *   CALDAV:calendar-collection-location-ok
 *   CALDAV:valid-calendar-data (CALDAV:calendar-timezone)
 */
static int meth_mkcol(struct transaction_t *txn)
{
    int ret = 0, r = 0;
    xmlDocPtr indoc = NULL, outdoc = NULL;
    xmlNodePtr root = NULL, instr = NULL;
    xmlNodePtr propstat[NUM_PROPSTAT];
    xmlNsPtr ns[NUM_NAMESPACE];
    char *server, mailboxname[MAX_MAILBOX_BUFFER], *partition = NULL;
    struct proppatch_ctx pctx;

    /* Response should not be cached */
    txn->flags |= HTTP_NOCACHE;

    /* Make sure its a DAV resource */
    if (!(txn->req_tgt.allow & ALLOW_WRITE)) return HTTP_NOT_ALLOWED; 

    /* Parse the path */
    if ((r = parse_path(&txn->req_tgt, &txn->errstr))) return r;

    /* Make sure its a home-set collection */
    if (!txn->req_tgt.collection || txn->req_tgt.resource) {
	txn->errstr = "Calendars can only be created under a home-set collection";
	return HTTP_FORBIDDEN;
    }

    /* Parse the MKCOL/MKCALENDAR body, if exists */
    ret = parse_xml_body(txn, &root);
    if (ret) goto done;

    if (root) {
	indoc = root->doc;

	if ((txn->meth[3] == 'O') &&
	    /* Make sure its a mkcol element */
	    xmlStrcmp(root->name, BAD_CAST "mkcol")) {
	    txn->errstr = "Missing mkcol element in MKCOL request";
	    return HTTP_BAD_MEDIATYPE;
	}
	else if ((txn->meth[3] == 'A') &&
		 /* Make sure its a mkcalendar element */
		 xmlStrcmp(root->name, BAD_CAST "mkcalendar")) {
	    txn->errstr = "Missing mkcalendar element in MKCALENDAR request";
	    return HTTP_BAD_MEDIATYPE;
	}

	instr = root->children;
    }

    /* Construct mailbox name corresponding to calendar-home-set */
    r = (*httpd_namespace.mboxname_tointernal)(&httpd_namespace, "INBOX",
					       httpd_userid, mailboxname);

    /* Locate the mailbox */
    if ((r = http_mlookup(mailboxname, &server, NULL, NULL))) {
	syslog(LOG_ERR, "mlookup(%s) failed: %s",
	       mailboxname, error_message(r));
	txn->errstr = error_message(r);

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

    /* Construct mailbox name corresponding to request target URI */
    (void) target_to_mboxname(&txn->req_tgt, mailboxname);

    /* Check if we are allowed to create the mailbox */
    r = mboxlist_createmailboxcheck(mailboxname, 0, NULL,
				    httpd_userisadmin || httpd_userisproxyadmin,
				    httpd_userid, httpd_authstate,
				    NULL, &partition, 0);

    if (r == IMAP_PERMISSION_DENIED) ret = HTTP_FORBIDDEN;
    else if (r == IMAP_MAILBOX_EXISTS) ret = HTTP_FORBIDDEN;
    else if (r) ret = HTTP_SERVER_ERROR;

    if (ret) goto done;

    if (instr) {
	/* Start construction of our mkcol/mkcalendar response */
	if (!(root = init_prop_response(txn->meth[3] == 'A' ?
					"mkcalendar-response" :
					"mkcol-response",
					root->nsDef, ns))) {
	    ret = HTTP_SERVER_ERROR;
	    txn->errstr = "Unable to create XML response";
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
	pctx.errstr = &txn->errstr;
	pctx.ret = &r;

	/* Execute the property patch instructions */
	ret = do_proppatch(&pctx, instr, propstat);

	if (ret || r) {
	    /* Something failed.  Abort the txn and change the OK status */
	    annotatemore_abort(pctx.tid);

	    if (!ret) {
		if (propstat[PROPSTAT_OK]) {
		    xmlNodeSetContent(propstat[PROPSTAT_OK]->parent->children,
				      BAD_CAST http_statusline(HTTP_FAILED_DEP));
		}

		/* Output the XML response */
		xml_response(HTTP_MULTI_STATUS, txn, outdoc);
		ret = 0;
	    }

	    goto done;
	}
    }

    /* Create the mailbox */
    r = mboxlist_createmailbox(mailboxname, 0, partition, 
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

    /* Parse the path */
    if ((r = parse_path(&txn->req_tgt, &txn->errstr))) return r;

    /* Check Depth */
    hdr = spool_getheader(txn->req_hdrs, "Depth");
    if (!hdr || !strcmp(hdr[0], "infinity")) {
	depth = 2;
    }
    if (hdr && ((sscanf(hdr[0], "%u", &depth) != 1) || (depth > 1))) {
	txn->errstr = "Illegal Depth value";
	return HTTP_BAD_REQUEST;
    }

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
	    txn->errstr = "Missing propfind element in PROFIND request";
	    return HTTP_BAD_REQUEST;
	}

	/* Find child element of propfind */
	for (cur = root->children;
	     cur && cur->type != XML_ELEMENT_NODE; cur = cur->next);

	/* Make sure its a prop element */
	/* XXX  TODO: Check for allprop and propname too */
	if (!cur || xmlStrcmp(cur->name, BAD_CAST "prop")) {
	    return HTTP_BAD_REQUEST;
	}
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
	    txn->errstr = error_message(r);

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

    /* Start construction of our multistatus response */
    if (!(root = init_prop_response("multistatus", root->nsDef, ns))) {
	ret = HTTP_SERVER_ERROR;
	txn->errstr = "Unable to create XML response";
	goto done;
    }

    outdoc = root->doc;

    /* Parse the list of properties and build a list of callbacks */
    preload_proplist(cur->children, &elist);

    /* Populate our propfind context */
    memset(&fctx, 0, sizeof(struct propfind_ctx));
    fctx.req_tgt = &txn->req_tgt;
    fctx.depth = depth;
    fctx.userid = httpd_userid;
    fctx.userisadmin = httpd_userisadmin;
    fctx.authstate = httpd_authstate;
    fctx.mailbox = NULL;
    fctx.record = NULL;
    fctx.elist = elist;
    fctx.root = root;
    fctx.ns = ns;
    fctx.errstr = &txn->errstr;
    fctx.ret = &ret;

    if (!txn->req_tgt.collection) {
	/* Add response for home-set collection */
	add_prop_response(&fctx);
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
    while (elist) {
	struct propfind_entry_list *freeme = elist;
	elist = elist->next;
	free(freeme);
    }

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
    int ret = 0, r = 0;
    xmlDocPtr indoc = NULL, outdoc = NULL;
    xmlNodePtr root, instr;
    xmlNodePtr resp, propstat[NUM_PROPSTAT];
    xmlNsPtr ns[NUM_NAMESPACE];
    char *server, mailboxname[MAX_MAILBOX_BUFFER];
    struct proppatch_ctx pctx;

    /* Response should not be cached */
    txn->flags |= HTTP_NOCACHE;

    /* Make sure its a DAV resource */
    if (!(txn->req_tgt.allow & ALLOW_WRITE)) return HTTP_NOT_ALLOWED;

    /* Parse the path */
    if ((r = parse_path(&txn->req_tgt, &txn->errstr))) return r;

    /* Make sure its a calendar collection */
    if (!txn->req_tgt.collection || txn->req_tgt.resource) {
	txn->errstr = "Properties can only be updated on calendar collections";
	return HTTP_FORBIDDEN;
    }

    /* Parse the PROPPATCH body */
    ret = parse_xml_body(txn, &root);
    if (!root) {
	txn->errstr = "Missing request body";
	return HTTP_BAD_REQUEST;
    }
    if (ret) goto done;

    indoc = root->doc;

    /* Make sure its a propertyupdate element */
    if (xmlStrcmp(root->name, BAD_CAST "propertyupdate")) {
	txn->errstr = "Missing propertyupdate element in PROPPATCH request";
	return HTTP_BAD_REQUEST;
    }
    instr = root->children;

    /* Construct mailbox name corresponding to request target URI */
    (void) target_to_mboxname(&txn->req_tgt, mailboxname);

    /* Locate the mailbox */
    if ((r = http_mlookup(mailboxname, &server, NULL, NULL))) {
	syslog(LOG_ERR, "mlookup(%s) failed: %s",
	       mailboxname, error_message(r));
	txn->errstr = error_message(r);

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

    /* Start construction of our multistatus response */
    if (!(root = init_prop_response("multistatus", root->nsDef, ns))) {
	ret = HTTP_SERVER_ERROR;
	txn->errstr = "Unable to create XML response";
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
    pctx.errstr = &txn->errstr;
    pctx.ret = &r;

    /* Execute the property patch instructions */
    ret = do_proppatch(&pctx, instr, propstat);

    if (ret || r) {
	/* Something failed.  Abort the txn and change the OK status */
	annotatemore_abort(pctx.tid);

	if (ret) goto done;

	if (propstat[PROPSTAT_OK]) {
	    xmlNodeSetContent(propstat[PROPSTAT_OK]->parent->children,
			      BAD_CAST http_statusline(HTTP_FAILED_DEP));
	}
    }
    else {
	/* Success.  Commit the txn */
	annotatemore_commit(pctx.tid);
    }

    /* Output the XML response */
    xml_response(HTTP_MULTI_STATUS, txn, outdoc);

  done:
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
    int ret = HTTP_CREATED, r, precond;
    char *server, mailboxname[MAX_MAILBOX_BUFFER];
    struct mailbox *mailbox = NULL;
    struct caldav_db *caldavdb = NULL;
    uint32_t olduid = 0;
    struct index_record oldrecord;
    const char *etag;
    time_t lastmod;
    FILE *f = NULL;
    struct stagemsg *stage = NULL;
    const char **hdr;
    uquota_t size = 0;
    time_t now = time(NULL);
    pid_t p;
    char datestr[80], msgid[8192];
    struct appendstate appendstate;
    icalcomponent *ical, *comp;

    /* Make sure its a DAV resource */
    if (!(txn->req_tgt.allow & ALLOW_WRITE)) return HTTP_NOT_ALLOWED; 

    /* Parse the path */
    if ((r = parse_path(&txn->req_tgt, &txn->errstr))) return r;

   /* We don't handle POST/PUT on non-calendar collections */
    if (!txn->req_tgt.collection) return HTTP_NOT_ALLOWED;

    /* We don't handle PUT on calendar collections */
    if (!txn->req_tgt.resource && (txn->meth[1] != 'O')) return HTTP_NOT_ALLOWED;

    /* Make sure we have a body */
    if (!buf_len(&txn->req_body)) {
	txn->errstr = "Missing request body";
	return HTTP_BAD_REQUEST;
    }

    /* Check Content-Type */
    if ((hdr = spool_getheader(txn->req_hdrs, "Content-Type")) &&
	strncmp(hdr[0], "text/calendar", 13)) {
	txn->errstr = "This collection only supports text/calendar data";
	return HTTP_BAD_MEDIATYPE;
    }

    /* Parse the iCal data for important properties */
    ical = icalparser_parse_string(buf_cstring(&txn->req_body));
    if (!ical) {
	txn->errstr = "Invalid calendar data";
	return HTTP_BAD_MEDIATYPE;
    }
    comp = icalcomponent_get_first_real_component(ical);

    /* Construct mailbox name corresponding to request target URI */
    (void) target_to_mboxname(&txn->req_tgt, mailboxname);

    /* Locate the mailbox */
    if ((r = http_mlookup(mailboxname, &server, NULL, NULL))) {
	syslog(LOG_ERR, "mlookup(%s) failed: %s",
	       mailboxname, error_message(r));
	txn->errstr = error_message(r);

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

    /* Open mailbox for reading */
    if ((r = mailbox_open_irl(mailboxname, &mailbox))) {
	syslog(LOG_ERR, "mailbox_open_irl(%s) failed: %s",
	       mailboxname, error_message(r));
	txn->errstr = error_message(r);
	ret = HTTP_SERVER_ERROR;
	goto done;
    }

    /* Open the associated CalDAV database */
    if ((r = caldav_open(mailbox, CALDAV_CREATE, &caldavdb))) {
	txn->errstr = error_message(r);
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
	snprintf(p, MAX_MAILBOX_PATH - len, "%08X-%s.ics",
		 strhash(mailboxname), icalcomponent_get_uid(comp));
	txn->req_tgt.resource = p;
	txn->req_tgt.reslen = strlen(p);
    }

    /* Find message UID for the resource, if exists */
    caldav_read(caldavdb, txn->req_tgt.resource, &olduid);
    /* XXX  Check errors */

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
    precond = check_precond(txn->meth, etag, lastmod, 0, txn->req_hdrs);

    if (precond != HTTP_OK) {
	/* We failed a precondition - don't perform the request */
	ret = precond;
	goto done;
    }

    /* Finished our initial read */
    mailbox_unlock_index(mailbox, NULL);

    /* Check if we can append a new iMIP message to calendar mailbox */
    if ((r = append_check(mailboxname, httpd_authstate, ACL_INSERT, size))) {
	txn->errstr = error_message(r);
	ret = HTTP_SERVER_ERROR;
	goto done;
    }

    /* Prepare to stage the message */
    if (!(f = append_newstage(mailboxname, now, 0, &stage))) {
	txn->errstr = error_message(r);
	ret = HTTP_SERVER_ERROR;
	goto done;
    }


    /* Create iMIP header for resource */
    fprintf(f, "From: <%s>\r\n", httpd_userid ? httpd_userid : "");

    fprintf(f, "Subject: %s\r\n", icalcomponent_get_summary(comp));

    rfc822date_gen(datestr, sizeof(datestr), now);
    fprintf(f, "Date: %s\r\n", datestr);

    p = getpid();
    snprintf(msgid, sizeof(msgid), "<cmu-http-%d-%d-%d@%s>", 
	     (int) p, (int) now, global_put_count++, config_servername);
    fprintf(f, "Message-ID: %s\r\n", msgid);

    hdr = spool_getheader(txn->req_hdrs, "Content-Type");
    fprintf(f, "Content-Type: %s\r\n", hdr[0]);

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
	txn->errstr = "append_setup() failed";
    }
    else {
	struct body *body = NULL;

	/* Append the iMIP file to the calendar mailbox */
	if ((r = append_fromstage(&appendstate, &body, stage, now, NULL, 0, 0))) {
	    ret = HTTP_SERVER_ERROR;
	    txn->errstr = "append_fromstage() failed";
	}
	if (body) message_free_body(body);

	if (!r) {
	    /* Commit the append to the calendar mailbox */
	    if ((r = append_commit(&appendstate, size,
				   NULL, NULL, NULL, &mailbox))) {
		ret = HTTP_SERVER_ERROR;
		txn->errstr = "append_commit() failed";
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
		    ret = HTTP_NO_CONTENT;

		    /* Fetch index record for the resource */
		    r = mailbox_find_index_record(mailbox, olduid, &oldrecord);

		    etag = message_guid_encode(&oldrecord.guid);
		    lastmod = oldrecord.internaldate;

		    /* Check any preconditions */
		    precond = check_precond(txn->meth, etag, lastmod, 0,
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
		    expunge->system_flags |= FLAG_EXPUNGED;
		    if ((r = mailbox_rewrite_index_record(mailbox, expunge))) {
			syslog(LOG_ERR, "rewrite_index_rec(%s) failed: %s",
			       mailboxname, error_message(r));
			txn->errstr = error_message(r);
			ret = HTTP_SERVER_ERROR;
			goto done;
		    }
		}

		/* Create mapping entry from resource name and UID */
		caldav_write(caldavdb, txn->req_tgt.resource, newrecord.uid);
		/* XXX  check for errors, if this fails, backout changes */

		/* Tell client about the new resource */
		txn->etag = message_guid_encode(&newrecord.guid);
		txn->loc = txn->req_tgt.path;
	    }
	}
	else {
	    append_abort(&appendstate);
	}
    }

  done:
    if (stage) append_removestage(stage);
    if (caldavdb) caldav_close(caldavdb);
    if (mailbox) mailbox_close(&mailbox);

    return ret;
}


/* Report types */
enum {
    REPORT_CAL_QUERY = 0,
    REPORT_CAL_MULTIGET,
    REPORT_FB_QUERY,
    REPORT_EXPAND_PROP,
    REPORT_PRIN_PROP_SET,
    REPORT_PRIN_MATCH,
    REPORT_PRIN_PROP_SRCH
};

/* Perform a REPORT request */
static int meth_report(struct transaction_t *txn)
{
    int ret = 0, r;
    const char **hdr;
    unsigned depth = 0, type;
    xmlDocPtr indoc = NULL, outdoc = NULL;
    xmlNodePtr root, cur;
    xmlNsPtr ns[NUM_NAMESPACE];
    char *server, mailboxname[MAX_MAILBOX_BUFFER];
    struct mailbox *mailbox = NULL;
    struct caldav_db *caldavdb = NULL;
    struct propfind_ctx fctx;
    struct propfind_entry_list *elist = NULL;

    /* Make sure its a DAV resource */
    if (!(txn->req_tgt.allow & ALLOW_DAV)) return HTTP_NOT_ALLOWED; 

    /* Parse the path */
    if ((r = parse_path(&txn->req_tgt, &txn->errstr))) return r;

    /* Check Depth */
    if ((hdr = spool_getheader(txn->req_hdrs, "Depth"))) {
	if (!strcmp(hdr[0], "infinity")) {
	    txn->errstr = "This server DOES NOT support infinite depth requests";
	    return HTTP_SERVER_ERROR;
	}
	else if ((sscanf(hdr[0], "%u", &depth) != 1) || (depth > 1)) {
	    txn->errstr = "Illegal Depth value";
	    return HTTP_BAD_REQUEST;
	}
    }

    /* Parse the REPORT body */
    ret = parse_xml_body(txn, &root);
    if (!root) {
	txn->errstr = "Missing request body";
	return HTTP_BAD_REQUEST;
    }
    if (ret) goto done;

    indoc = root->doc;

    /* Make sure its a calendar element */
    if (!xmlStrcmp(root->name, BAD_CAST "calendar-query")) {
	type = REPORT_CAL_QUERY;
    }
    else if (!xmlStrcmp(root->name, BAD_CAST "calendar-multiget")) {
	type = REPORT_CAL_MULTIGET;
    }
    else {
	txn->errstr = "Unsupported REPORT type";
	return HTTP_NOT_IMPLEMENTED;
    }

    /* Find child element of report */
    for (cur = root->children;
	 cur && cur->type != XML_ELEMENT_NODE; cur = cur->next);

    /* Make sure its a prop element */
    if (!cur || xmlStrcmp(cur->name, BAD_CAST "prop")) {
	txn->errstr = "MIssing prop element";
	return HTTP_BAD_REQUEST;
    }

    /* Construct mailbox name corresponding to request target URI */
    (void) target_to_mboxname(&txn->req_tgt, mailboxname);

    /* Locate the mailbox */
    if ((r = http_mlookup(mailboxname, &server, NULL, NULL))) {
	syslog(LOG_ERR, "mlookup(%s) failed: %s",
	       mailboxname, error_message(r));
	txn->errstr = error_message(r);

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

    /* Start construction of our multistatus response */
    if (!(root = init_prop_response("multistatus", root->nsDef, ns))) {
	ret = HTTP_SERVER_ERROR;
	txn->errstr = "Unable to create XML response";
	goto done;
    }

    outdoc = root->doc;

    /* Parse the list of properties and build a list of callbacks */
    preload_proplist(cur->children, &elist);

    /* Open mailbox for reading */
    if ((r = mailbox_open_irl(mailboxname, &mailbox))) {
	syslog(LOG_ERR, "mailbox_open_irl(%s) failed: %s",
	       mailboxname, error_message(r));
	txn->errstr = error_message(r);
	ret = HTTP_SERVER_ERROR;
	goto done;
    }

    /* Open the associated CalDAV database */
    if ((r = caldav_open(mailbox, CALDAV_CREATE, &caldavdb))) {
	txn->errstr = error_message(r);
	ret = HTTP_SERVER_ERROR;
	goto done;
    }

    /* Populate our propfind context */
    fctx.req_tgt = &txn->req_tgt;
    fctx.depth = depth;
    fctx.userid = httpd_userid;
    fctx.userisadmin = httpd_userisadmin;
    fctx.authstate = httpd_authstate;
    fctx.mailbox = mailbox;
    fctx.record = NULL;
    fctx.elist = elist;
    fctx.root = root;
    fctx.ns = ns;
    fctx.errstr = &txn->errstr;
    fctx.ret = &ret;

    switch (type) {
    case REPORT_CAL_QUERY: {

	/* XXX  TODO: Need to handle the filter */
	caldav_foreach(caldavdb, find_resource_props, &fctx);
    }
	break;
    case REPORT_CAL_MULTIGET:
	/* Get props for each href */
	for (; cur; cur = cur->next) {
	    if ((cur->type == XML_ELEMENT_NODE) &&
		!xmlStrcmp(cur->name, BAD_CAST "href")) {
		xmlChar *href = xmlNodeListGetString(indoc, cur->children, 1);
		const char *resource = strrchr((char *) href, '/') + 1;
		uint32_t uid = 0;

		/* Find message UID for the resource */
		caldav_read(caldavdb, resource, &uid);
		/* XXX  Check errors */

		find_resource_props(&fctx, resource, uid);
	    }
	}
	break;
    }

    /* Output the XML response */
    xml_response(HTTP_MULTI_STATUS, txn, outdoc);

  done:
    if (caldavdb) caldav_close(caldavdb);
    if (mailbox) mailbox_close(&mailbox);

    /* Free the entry list */
    while (elist) {
	struct propfind_entry_list *freeme = elist;
	elist = elist->next;
	free(freeme);
    }

    if (outdoc) xmlFreeDoc(outdoc);
    if (indoc) xmlFreeDoc(indoc);

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
    xmlDocPtr doc;

    *root = NULL;

    if (!buf_len(&txn->req_body)) return 0;

    /* Check Content-Type */
    if (!(hdr = spool_getheader(txn->req_hdrs, "Content-Type")) ||
	(!is_mediatype(hdr[0], "text/xml") &&
	 !is_mediatype(hdr[0], "application/xml"))) {
	txn->errstr = "This method requires an XML body";
	return HTTP_BAD_MEDIATYPE;
    }

    /* Parse the XML request */
    doc = xmlParseMemory(buf_cstring(&txn->req_body), buf_len(&txn->req_body));
    xmlCleanupParser();
    if (!doc) {
	txn->errstr = "Unable to parse XML body";
	return HTTP_BAD_REQUEST;
    }

    /* Get the root element of the XML request */
    if (!(*root = xmlDocGetRootElement(doc))) {
	txn->errstr = "Missing root element in request";
	return HTTP_BAD_REQUEST;
    }

    return 0;
}
