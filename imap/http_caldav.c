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

#include "acl.h"
#include "append.h"
#include "caldav_db.h"
#include "dav_prop.h"
#include "global.h"
#include "hash.h"
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
#include "tok.h"
#include "util.h"
#include "version.h"
#include "xmalloc.h"
#include "xstrlcat.h"
#include "xstrlcpy.h"

#define DFLAG_UNBIND "DAV:unbind"

#define NEW_STAG (1<<8)  /* Make sure we skip over PREFER bits */

enum {
    OVERWRITE_CHECK = -1,
    OVERWRITE_NO,
    OVERWRITE_YES
};

static struct caldav_db *auth_caldavdb = NULL;

static void my_caldav_init(struct buf *serverinfo);
static void my_caldav_auth(const char *userid);
static void my_caldav_reset(void);
static void my_caldav_shutdown(void);

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
static unsigned get_preferences(hdrcache_t hdrcache);
static int store_resource(struct transaction_t *txn, icalcomponent *ical,
			  struct mailbox *mailbox, const char *resource,
			  struct caldav_db *caldavdb, int overwrite,
			  unsigned flags);
static icalcomponent *busytime(struct transaction_t *txn,
			       struct propfind_ctx *fctx,
			       char mailboxname[],
			       icalproperty_method method,
			       const char *uid,
			       const char *organizer,
			       const char *attendee);
#ifdef WITH_CALDAV_SCHED
static int caladdress_lookup(const char *addr, struct sched_param *param);
static int sched_busytime(struct transaction_t *txn);
static int sched_request(const char *organizer,
			 icalcomponent *oldical, icalcomponent *newical);
static int sched_reply(icalcomponent *oldical, icalcomponent *newical,
		       const char *userid);
#endif /* WITH_CALDAV_SCHED */

int target_to_mboxname(struct request_target_t *req_tgt, char *mboxname);

/* Namespace for CalDAV collections */
const struct namespace_t namespace_calendar = {
    URL_NS_CALENDAR, "/calendars", "/.well-known/caldav", 1 /* auth */,
    (ALLOW_READ | ALLOW_POST | ALLOW_WRITE | ALLOW_DAV | ALLOW_CAL),
    &my_caldav_init, &my_caldav_auth, my_caldav_reset, &my_caldav_shutdown,
    { 
	{ &meth_acl,		0		},	/* ACL		*/
	{ &meth_copy,		METH_NOBODY	},	/* COPY		*/
	{ &meth_delete,		METH_NOBODY	},	/* DELETE	*/
	{ &meth_get,		METH_NOBODY	},	/* GET		*/
	{ &meth_get,		METH_NOBODY	},	/* HEAD		*/
	{ &meth_mkcol,		0		},	/* MKCALENDAR	*/
	{ &meth_mkcol,		0		},	/* MKCOL	*/
	{ &meth_copy,		METH_NOBODY	},	/* MOVE		*/
	{ &meth_options,	METH_NOBODY	},	/* OPTIONS	*/
	{ &meth_post,		0		},	/* POST		*/
	{ &meth_propfind,	0		},	/* PROPFIND	*/
	{ &meth_proppatch,	0		},	/* PROPPATCH	*/
	{ &meth_put,		0		},	/* PUT		*/
	{ &meth_report,		0		}	/* REPORT	*/
    }
};

/* Namespace for WebDAV principals */
const struct namespace_t namespace_principal = {
    URL_NS_PRINCIPAL, "/principals", NULL, 1 /* auth */,
    (ALLOW_DAV | ALLOW_CAL | ALLOW_CARD),
    NULL, NULL, NULL, NULL,
    {
	{ NULL,			0		},	/* ACL		*/
	{ NULL,			0		},	/* COPY		*/
	{ NULL,			0		},	/* DELETE	*/
	{ &meth_get,		METH_NOBODY	},	/* GET		*/
	{ &meth_get,		METH_NOBODY	},	/* HEAD		*/
	{ NULL,			0		},	/* MKCALENDAR	*/
	{ NULL,			0		},	/* MKCOL	*/
	{ NULL,			0		},	/* MOVE		*/
	{ &meth_options,	METH_NOBODY	},	/* OPTIONS	*/
	{ NULL,			0		},	/* POST		*/
	{ &meth_propfind,	0		},	/* PROPFIND	*/
	{ NULL,			0		},	/* PROPPATCH	*/
	{ NULL,			0		},	/* PUT		*/
	{ &meth_report,		0		}	/* REPORT	*/
    }
};


static void my_caldav_init(struct buf *serverinfo)
{
    if (!config_getstring(IMAPOPT_CALENDARPREFIX)) {
	fatal("Required 'calendarprefix' option is not set", EC_CONFIG);
    }

    caldav_init();

    buf_printf(serverinfo, " libical/%s", ICAL_VERSION);
    buf_printf(serverinfo, " SQLite/%s", sqlite3_libversion());

    /* Need to set this to parse CalDAV Scheduling parameters */
    ical_set_unknown_token_handling_setting(ICAL_ASSUME_IANA_TOKEN);
}


static void my_caldav_auth(const char *userid)
{
    if (config_mupdate_server && !config_getstring(IMAPOPT_PROXYSERVERS)) {
	/* proxy-only server */
	return;
    }
    else if (httpd_userisadmin) return;

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
	txn->error.desc = "ACLs can only be set on calendar collections\r\n";
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
	txn->error.precond = DAV_NEED_PRIVS;
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
			    txn->error.desc = "Multiple principals in ACE\r\n";
			    ret = HTTP_BAD_REQUEST;
			    goto done;
			}

			for (prin = child->children;
			     prin->type != XML_ELEMENT_NODE; prin = prin->next);
		    }
		    else if (!xmlStrcmp(child->name, BAD_CAST "grant")) {
			if (privs) {
			    txn->error.desc = "Multiple grant|deny in ACE\r\n";
			    ret = HTTP_BAD_REQUEST;
			    goto done;
			}

			for (privs = child->children;
			     privs->type != XML_ELEMENT_NODE; privs = privs->next);
		    }
		    else if (!xmlStrcmp(child->name, BAD_CAST "deny")) {
			if (privs) {
			    txn->error.desc = "Multiple grant|deny in ACE\r\n";
			    ret = HTTP_BAD_REQUEST;
			    goto done;
			}

			for (privs = child->children;
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

		r = parse_uri(METH_UNKNOWN, (const char *) href, &uri, &errstr);
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
		txn->error.precond = DAV_RECOG_PRINC;
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
			    txn->error.precond = DAV_NO_ABSTRACT;
			    ret = HTTP_FORBIDDEN;
			    goto done;
			}
			else {
			    /* DAV:not-supported-privilege */
			    txn->error.precond = DAV_SUPP_PRIV;
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
			    txn->error.precond = DAV_NO_ABSTRACT;
			    ret = HTTP_FORBIDDEN;
			    goto done;
			}
			else {
			    /* DAV:not-supported-privilege */
			    txn->error.precond = DAV_SUPP_PRIV;
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
			    txn->error.precond = DAV_SUPP_PRIV;
			    ret = HTTP_FORBIDDEN;
			    goto done;
			}
		    }
		    else {
			/* DAV:not-supported-privilege */
			txn->error.precond = DAV_SUPP_PRIV;
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
    int ret = HTTP_CREATED, r, precond, rights, overwrite = OVERWRITE_YES;
    size_t plen;
    const char **hdr;
    struct request_target_t dest;  /* Parsed destination URL */
    char src_mboxname[MAX_MAILBOX_BUFFER], dest_mboxname[MAX_MAILBOX_BUFFER];
    char *server, *acl;
    struct backend *src_be = NULL, *dest_be = NULL;
    struct mailbox *src_mbox = NULL, *dest_mbox = NULL;
    struct caldav_data cdata;
    struct index_record src_rec;
    const char *etag = NULL;
    time_t lastmod = 0;
    const char *msg_base = NULL;
    unsigned long msg_size = 0;
    icalcomponent *ical = NULL;

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
	txn->error.desc = "Missing Destination header\r\n";
	return HTTP_BAD_REQUEST;
    }

    /* Parse destination URI */
    if ((r = parse_uri(METH_UNKNOWN, hdr[0], &dest, &txn->error.desc))) return r;

    /* Check namespace of destination */
    plen = strlen(namespace_calendar.prefix);
    if (strncmp(namespace_calendar.prefix, dest.path, plen) ||
	dest.path[plen] != '/') {
	return HTTP_FORBIDDEN;
    }

    dest.namespace = URL_NS_CALENDAR;
    if ((r = parse_path(&dest, &txn->error.desc))) return r;

    /* Make sure dest resource is in same namespace as source */
    if (txn->req_tgt.namespace != dest.namespace) return HTTP_FORBIDDEN;

    /* Make sure source and dest resources are NOT the same */
    if (!strcmp(txn->req_tgt.path, dest.path)) {
	txn->error.desc = "Source and destination resources are the same\r\n";
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
    if ((r = mailbox_open_irl(dest_mboxname, &dest_mbox))) {
	syslog(LOG_ERR, "mailbox_open_irl(%s) failed: %s",
	       dest_mboxname, error_message(r));
	txn->error.desc = error_message(r);
	ret = HTTP_SERVER_ERROR;
	goto done;
    }

    /* Find message UID for the dest resource, if exists */
    memset(&cdata, 0, sizeof(struct caldav_data));
    cdata.mailbox = dest_mboxname;
    cdata.resource = dest.resource;
    caldav_read(auth_caldavdb, &cdata);
    /* XXX  Check errors */

    /* Finished our initial read of dest mailbox */
    mailbox_unlock_index(dest_mbox, NULL);

    /* Check any preconditions on destination */
    if ((hdr = spool_getheader(txn->req_hdrs, "Overwrite")) &&
	!strcmp(hdr[0], "F")) {

	if (cdata.imap_uid) {
	    /* Don't overwrite the destination resource */
	    ret = HTTP_PRECOND_FAILED;
	    goto done;
	}
	overwrite = OVERWRITE_NO;
    }

    /* Open source mailbox for reading */
    if ((r = http_mailbox_open(src_mboxname, &src_mbox, LOCK_SHARED))) {
	syslog(LOG_ERR, "http_mailbox_open(%s) failed: %s",
	       src_mboxname, error_message(r));
	txn->error.desc = error_message(r);
	ret = HTTP_SERVER_ERROR;
	goto done;
    }

    /* Find message UID for the source resource */
    memset(&cdata, 0, sizeof(struct caldav_data));
    cdata.mailbox = src_mboxname;
    cdata.resource = txn->req_tgt.resource;
    caldav_read(auth_caldavdb, &cdata);
    /* XXX  Check errors */

    /* Fetch index record for the source resource */
    if (!cdata.imap_uid ||
	mailbox_find_index_record(src_mbox, cdata.imap_uid, &src_rec)) {
	ret = HTTP_NOT_FOUND;
	goto done;
    }

    /* Check any preconditions on source */
    etag = message_guid_encode(&src_rec.guid);
    lastmod = src_rec.internaldate;
    precond = check_precond(txn->meth, cdata.sched_tag,
			    etag, lastmod, txn->req_hdrs);

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
	memset(&cdata, 0, sizeof(struct caldav_data));
	cdata.mailbox = src_mboxname;
	cdata.resource = txn->req_tgt.resource;
	caldav_lockread(auth_caldavdb, &cdata);
	/* XXX  Check errors */

	/* Fetch index record for the source resource */
	if (cdata.imap_uid &&
	    !mailbox_find_index_record(src_mbox, cdata.imap_uid, &src_rec)) {

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
	caldav_delete(auth_caldavdb, &cdata);
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
static int meth_delete(struct transaction_t *txn)
{
    int ret = HTTP_NO_CONTENT, r, precond, rights;
    char *server, *acl, mailboxname[MAX_MAILBOX_BUFFER];
    struct mailbox *mailbox = NULL;
    struct caldav_data cdata;
    struct index_record record;
    const char *etag = NULL, *userid;
    time_t lastmod = 0;

    /* Make sure its a DAV resource */
    if (!(txn->req_tgt.allow & ALLOW_WRITE)) return HTTP_NOT_ALLOWED; 

    /* Parse the path */
    if ((r = parse_path(&txn->req_tgt, &txn->error.desc))) return r;

    /* Construct mailbox name corresponding to request target URI */
    (void) target_to_mboxname(&txn->req_tgt, mailboxname);
    userid = mboxname_to_userid(mailboxname);

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
	r = mboxlist_deletemailbox(mailboxname,
				   httpd_userisadmin || httpd_userisproxyadmin,
				   httpd_userid, httpd_authstate,
				   1, 0, 0);

	if (!r) caldav_delmbox(auth_caldavdb, mailboxname);
	else if (r == IMAP_PERMISSION_DENIED) ret = HTTP_FORBIDDEN;
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

    /* Find message UID for the resource */
    memset(&cdata, 0, sizeof(struct caldav_data));
    cdata.mailbox = mailboxname;
    cdata.resource = txn->req_tgt.resource;
    caldav_lockread(auth_caldavdb, &cdata);
    /* XXX  Check errors */

    /* Fetch index record for the resource */
    if (!cdata.imap_uid ||
	mailbox_find_index_record(mailbox, cdata.imap_uid, &record)) {
	ret = HTTP_NOT_FOUND;
	goto done;
    }

    etag = message_guid_encode(&record.guid);
    lastmod = record.internaldate;

    /* Check any preconditions */
    precond = check_precond(txn->meth, cdata.sched_tag,
			    etag, lastmod, txn->req_hdrs);

    /* We failed a precondition - don't perform the request */
    if (precond != HTTP_OK) {
	ret = precond;
	goto done;
    }

#ifdef WITH_CALDAV_SCHED
    if (cdata.sched_tag) {
	/* Scheduling object resource */
	struct mboxlist_entry mbentry;
	char outboxname[MAX_MAILBOX_BUFFER];
	const char *msg_base = NULL, *organizer;
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
		   mailboxname, record.uid);
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
		   mailboxname, organizer, userid);
	    txn->error.desc = "Failed to lookup organizer address\r\n";
	    ret = HTTP_SERVER_ERROR;
	    goto done;
	}

	if (!strcmp(sparam.userid, userid)) {
	    /* Organizer scheduling object resource */
	    r = sched_request(organizer, ical, NULL);
	}
	else {
	    /* Attendee scheduling object resource */
	    r = sched_reply(ical, NULL, userid);
	}

	icalcomponent_free(ical);

	if (r) {
	    syslog(LOG_ERR,
		   "meth_delete: failed to process scheduling message in %s"
		   " (org=%s, att=%s)",
		   mailboxname, organizer, userid);
	    txn->error.desc = "Failed to process scheduling message\r\n";
	    ret = HTTP_SERVER_ERROR;
	    goto done;
	}
    }
#endif /* WITH_CALDAV_SCHED */

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
    caldav_delete(auth_caldavdb, &cdata);
    caldav_commit(auth_caldavdb);

  done:
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
    struct caldav_data cdata;
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
	txn->error.precond = DAV_NEED_PRIVS;
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

    /* Find message UID for the resource */
    memset(&cdata, 0, sizeof(struct caldav_data));
    cdata.mailbox = mailboxname;
    cdata.resource = txn->req_tgt.resource;
    caldav_read(auth_caldavdb, &cdata);
    /* XXX  Check errors */

    /* Fetch index record for the resource */
    if (!cdata.imap_uid ||
	mailbox_find_index_record(mailbox, cdata.imap_uid, &record)) {
	ret = HTTP_NOT_FOUND;
	goto done;
    }

    /* Check any preconditions */
    resp_body->etag = message_guid_encode(&record.guid);
    lastmod = record.internaldate;
    precond = check_precond(txn->meth, cdata.sched_tag,
			    resp_body->etag, lastmod, txn->req_hdrs);

    if (precond != HTTP_OK) {
	/* We failed a precondition - don't perform the request */
	ret = precond;
	goto done;
    }

    /* Fill in Last-Modified, and Content-Length */
    resp_body->lastmod = lastmod;
    resp_body->type = "text/calendar; charset=utf-8";

    if (txn->meth == METH_GET) {
	/* Load message containing the resource */
	mailbox_map_message(mailbox, record.uid, &msg_base, &msg_size);

	/* iCalendar data in response should not be transformed */
	txn->flags |= HTTP_NOTRANSFORM;
    }

    write_body(HTTP_OK, txn,
	       /* skip message header */
	       msg_base + record.header_size, record.size - record.header_size);

    if (msg_base)
	mailbox_unmap_message(mailbox, record.uid, &msg_base, &msg_size);

  done:
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
    if ((r = parse_path(&txn->req_tgt, &txn->error.desc))) {
	txn->error.precond = CALDAV_LOCATION_OK;
	return HTTP_FORBIDDEN;
    }

    /* Make sure its a home-set collection */
    if (!txn->req_tgt.collection || txn->req_tgt.resource) {
	txn->error.precond = CALDAV_LOCATION_OK;
	return HTTP_FORBIDDEN;
    }

    /* Construct mailbox name corresponding to calendar-home-set */
    r = caldav_mboxname("", httpd_userid, mailboxname);

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
    else if (r == IMAP_MAILBOX_EXISTS) {
	txn->error.precond = DAV_RSRC_EXISTS;
	return HTTP_FORBIDDEN;
    }
    else if (r) return HTTP_SERVER_ERROR;

    /* Parse the MKCOL/MKCALENDAR body, if exists */
    ret = parse_xml_body(txn, &root);
    if (ret) goto done;

    if (root) {
	indoc = root->doc;

	if ((txn->meth == METH_MKCOL) &&
	    /* Make sure its a mkcol element */
	    xmlStrcmp(root->name, BAD_CAST "mkcol")) {
	    txn->error.desc = "Missing mkcol element in MKCOL request\r\n";
	    return HTTP_BAD_MEDIATYPE;
	}
	else if ((txn->meth == METH_MKCALENDAR) &&
		 /* Make sure its a mkcalendar element */
		 xmlStrcmp(root->name, BAD_CAST "mkcalendar")) {
	    txn->error.desc =
		"Missing mkcalendar element in MKCALENDAR request\r\n";
	    return HTTP_BAD_MEDIATYPE;
	}

	instr = root->children;
    }

    if (instr) {
	/* Start construction of our mkcol/mkcalendar response */
	if (txn->meth == METH_MKCALENDAR)
	    root = init_xml_response("mkcalendar-response", NS_CALDAV,
				     root, ns);
	else
	    root = init_xml_response("mkcol-response", NS_DAV,
				     root, ns);
	if (!root) {
	    ret = HTTP_SERVER_ERROR;
	    txn->error.desc = "Unable to create XML response\r\n";
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
		xml_response(HTTP_FORBIDDEN, txn, outdoc);
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
    else if (r == IMAP_MAILBOX_EXISTS) {
	txn->error.precond = DAV_RSRC_EXISTS;
	ret = HTTP_FORBIDDEN;
    }
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
static int apply_calfilter(struct propfind_ctx *fctx, struct caldav_data *cdata)
{
    int match = 1;

    if (fctx->calfilter->comp) {
	/* Perform CALDAV:comp-filter filtering */
	if (!(cdata->comp_type & fctx->calfilter->comp)) return 0;
    }

    if (!icaltime_is_null_time(fctx->calfilter->start)) {
	/* Perform CALDAV:time-range filtering */
	struct icaltimetype dtstart = icaltime_from_string(cdata->dtstart);
	struct icaltimetype dtend = icaltime_from_string(cdata->dtend);

	if (icaltime_compare(dtend, fctx->calfilter->start) <= 0) {
	    /* Component is earlier than range */
	    return 0;
	}
	else if (icaltime_compare(dtstart, fctx->calfilter->end) >= 0) {
	    /* Component is later than range */
	    return 0;
	}
	else if (!cdata->recurring) {
	    /* Component is within range and non-recurring */
	    return 1;
	}
	else {
	    /* Component is within range and recurring.
	     * Need to mmap() and parse iCalendar object
	     * to perform complete check of each recurrence.
	     */
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

	    icalcomponent_free(ical);
	}
    }

    return match;
}


/* caldav_foreach() callback to find props on a resource */
static int propfind_by_resource(void *rock, struct caldav_data *cdata)
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
    strlcpy(p, cdata->resource, MAX_MAILBOX_PATH - len);
    fctx->req_tgt->resource = p;
    fctx->req_tgt->reslen = strlen(p);

    fctx->cdata = cdata;
    if (cdata->imap_uid && !fctx->record) {
	/* Fetch index record for the resource */
	r = mailbox_find_index_record(fctx->mailbox, cdata->imap_uid, &record);
	/* XXX  Check errors */

	fctx->record = r ? NULL : &record;
    }

    if (!cdata->imap_uid || !fctx->record) {
	/* Add response for missing target */
	ret = xml_add_response(fctx, HTTP_NOT_FOUND);
    }
    else {
	int add_it = 1;

	fctx->busytime.len = 0;
	if (fctx->calfilter) add_it = apply_calfilter(fctx, cdata);

	if (add_it) {
	    /* Add response for target */
	    ret = xml_add_response(fctx, 0);
	}
    }

    if (fctx->msg_base) {
	mailbox_unmap_message(fctx->mailbox, cdata->imap_uid,
			      &fctx->msg_base, &fctx->msg_size);
    }
    fctx->msg_base = NULL;
    fctx->msg_size = 0;
    fctx->record = NULL;
    fctx->cdata = NULL;

    return ret;
}

/* mboxlist_findall() callback to find props on a collection */
static int propfind_by_collection(char *mboxname, int matchlen,
				  int maycreate __attribute__((unused)),
				  void *rock)
{
    struct propfind_ctx *fctx = (struct propfind_ctx *) rock;
    struct mboxlist_entry mbentry;
    struct mailbox *mailbox = NULL;
    char *p;
    size_t len;
    int r = 0, rights, root;

    /* If this function is called outside of mboxlist_findall()
       with matchlen == 0, this is the root resource of the PROPFIND */
    root = !matchlen;

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

	/* If not filtering by calendar resource, and not excluding root,
	   add response for collection */
	if (!fctx->calfilter &&
	    (!root || (fctx->depth == 1) || !(fctx->prefer & PREFER_NOROOT)) &&
	    (r = xml_add_response(fctx, 0))) goto done;
    }

    if (fctx->depth > 1) {
	/* Resource(s) */

	if (fctx->req_tgt->resource) {
	    /* Add response for target resource */
	    struct caldav_data cdata;

	    /* Find message UID for the resource */
	    memset(&cdata, 0, sizeof(struct caldav_data));
	    cdata.mailbox = mboxname;
	    cdata.resource = fctx->req_tgt->resource;
	    caldav_read(fctx->caldavdb, &cdata);
	    /* XXX  Check errors */

	    r = fctx->proc_by_resource(rock, &cdata);
	}
	else {
	    /* Add responses for all contained resources */
	    caldav_foreach(fctx->caldavdb, mboxname, fctx->proc_by_resource, rock);

	    /* Started with NULL resource, end with NULL resource */
	    fctx->req_tgt->resource = NULL;
	    fctx->req_tgt->reslen = 0;
	}
    }

  done:
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
    char mailboxname[MAX_MAILBOX_BUFFER] = "";
    struct propfind_ctx fctx;
    struct propfind_entry_list *elist = NULL;

    memset(&fctx, 0, sizeof(struct propfind_ctx));

    /* Make sure its a DAV resource */
    if (!(txn->req_tgt.allow & ALLOW_DAV)) return HTTP_NOT_ALLOWED;

    /* Parse the path */
    if ((r = parse_path(&txn->req_tgt, &txn->error.desc))) return r;

    /* Check Depth */
    hdr = spool_getheader(txn->req_hdrs, "Depth");
    if (!hdr || !strcmp(hdr[0], "infinity")) {
	depth = 2;
    }
    else if (hdr && ((sscanf(hdr[0], "%u", &depth) != 1) || (depth > 1))) {
	txn->error.desc = "Illegal Depth value\r\n";
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
	    txn->error.precond = DAV_NEED_PRIVS;
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
	    txn->error.desc = "Missing propfind element in PROFIND request\r\n";
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
    if (!(root = init_xml_response("multistatus", NS_DAV, root, ns))) {
	ret = HTTP_SERVER_ERROR;
	txn->error.desc = "Unable to create XML response\r\n";
	goto done;
    }

    outdoc = root->doc;

    /* Populate our propfind context */
    fctx.req_tgt = &txn->req_tgt;
    fctx.depth = depth;
    fctx.prefer = get_preferences(txn->req_hdrs);
    fctx.userid = httpd_userid;
    fctx.userisadmin = httpd_userisadmin;
    fctx.authstate = httpd_authstate;
    fctx.caldavdb = auth_caldavdb;
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
    fctx.fetcheddata = 0;

    /* Parse the list of properties and build a list of callbacks */
    preload_proplist(cur->children, &fctx);

    if (!txn->req_tgt.collection &&
	(!depth || !(fctx.prefer & PREFER_NOROOT))) {
	/* Add response for principal or home-set collection */
	struct mailbox *mailbox = NULL;

	if (*mailboxname) {
	    /* Open mailbox for reading */
	    if ((r = mailbox_open_irl(mailboxname, &mailbox))) {
		syslog(LOG_INFO, "mailbox_open_irl(%s) failed: %s",
		       mailboxname, error_message(r));
		txn->error.desc = error_message(r);
		ret = HTTP_SERVER_ERROR;
		goto done;
	    }
	    fctx.mailbox = mailbox;
	}

	xml_add_response(&fctx, 0);

	mailbox_close(&mailbox);
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
    if (!ret) {
	/* iCalendar data in response should not be transformed */
	if (fctx.fetcheddata) txn->flags |= HTTP_NOTRANSFORM;

	xml_response(HTTP_MULTI_STATUS, txn, outdoc);
    }

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

    /* Make sure its a collection */
    if ((txn->req_tgt.namespace != URL_NS_CALENDAR) || txn->req_tgt.resource) {
	txn->error.desc =
	    "Properties can only be updated on collections\r\n";
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
	txn->error.precond = DAV_NEED_PRIVS;
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
	txn->error.desc = "Missing request body\r\n";
	return HTTP_BAD_REQUEST;
    }
    if (ret) goto done;

    indoc = root->doc;

    /* Make sure its a propertyupdate element */
    if (xmlStrcmp(root->name, BAD_CAST "propertyupdate")) {
	txn->error.desc =
	    "Missing propertyupdate element in PROPPATCH request\r\n";
	return HTTP_BAD_REQUEST;
    }
    instr = root->children;

    /* Start construction of our multistatus response */
    if (!(root = init_xml_response("multistatus", NS_DAV, root, ns))) {
	ret = HTTP_SERVER_ERROR;
	txn->error.desc = "Unable to create XML response\r\n";
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
    if (!ret) {
	if (get_preferences(txn->req_hdrs) & PREFER_MIN) ret = HTTP_OK;
	else xml_response(HTTP_MULTI_STATUS, txn, outdoc);
    }

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
    int r, ret;
    size_t len;
    char *p;

    /* Response should not be cached */
    txn->flags |= HTTP_NOCACHE;

    /* Make sure its a DAV resource */
    if (!(txn->req_tgt.allow & ALLOW_WRITE)) return HTTP_NOT_ALLOWED; 

    /* Parse the path */
    if ((r = parse_path(&txn->req_tgt, &txn->error.desc))) return r;

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

    ret = meth_put(txn);

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
static int meth_put(struct transaction_t *txn)
{
    int ret, r, precond, rights;
    char *server, *acl, mailboxname[MAX_MAILBOX_BUFFER];
    struct mailbox *mailbox = NULL;
    struct caldav_data cdata;
    struct index_record oldrecord;
    const char *etag, *organizer = NULL, *userid;
    time_t lastmod;
    const char **hdr, *uid;
    uquota_t size = 0;
    icalcomponent *ical = NULL, *comp, *nextcomp;
    icalcomponent_kind kind;
    icalproperty *prop;
    unsigned flags;

    /* Make sure its a DAV resource */
    if (!(txn->req_tgt.allow & ALLOW_WRITE)) return HTTP_NOT_ALLOWED; 

    /* Parse the path */
    if ((r = parse_path(&txn->req_tgt, &txn->error.desc))) return r;

    /* We only handle PUT on resources */
    if (!txn->req_tgt.resource) return HTTP_NOT_ALLOWED;

    /* Check Content-Type */
    if (!(hdr = spool_getheader(txn->req_hdrs, "Content-Type")) ||
	!is_mediatype(hdr[0], "text/calendar")) {
	txn->error.precond = CALDAV_SUPP_DATA;
	return HTTP_FORBIDDEN;
    }

    /* Construct mailbox name corresponding to request target URI */
    (void) target_to_mboxname(&txn->req_tgt, mailboxname);
    userid = mboxname_to_userid(mailboxname);

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
    if ((r = http_mailbox_open(mailboxname, &mailbox, LOCK_SHARED))) {
	syslog(LOG_ERR, "http_mailbox_open(%s) failed: %s",
	       mailboxname, error_message(r));
	txn->error.desc = error_message(r);
	ret = HTTP_SERVER_ERROR;
	goto done;
    }

    /* Find message UID for the resource, if exists */
    memset(&cdata, 0, sizeof(struct caldav_data));
    cdata.mailbox = mailboxname;
    cdata.resource = txn->req_tgt.resource;
    caldav_read(auth_caldavdb, &cdata);
    /* XXX  Check errors */

    if (cdata.imap_uid) {
	/* Overwriting existing resource */

	/* Fetch index record for the resource */
	r = mailbox_find_index_record(mailbox, cdata.imap_uid, &oldrecord);
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
    precond = check_precond(txn->meth, cdata.sched_tag,
			    etag, lastmod, txn->req_hdrs);

    if (precond != HTTP_OK) {
	/* We failed a precondition - don't perform the request */
	ret = precond;
	goto done;
    }

    /* Read body */
    if (!(txn->flags & HTTP_READBODY)) {
	txn->flags |= HTTP_READBODY;
	ret = read_body(httpd_in, txn->req_hdrs,
			&txn->req_body, &txn->error.desc);
	if (ret) {
	    txn->flags |= HTTP_CLOSE;
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
    if ((r = append_check(mailboxname, httpd_authstate, ACL_INSERT, size))) {
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
	struct mboxlist_entry mbentry;
	char outboxname[MAX_MAILBOX_BUFFER];
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

	    buf_printf(&txn->buf, "/calendars/user/%s/%s", userid, SCHED_OUTBOX);
	    txn->error.resource = buf_cstring(&txn->buf);
	    ret = HTTP_FORBIDDEN;
	    goto done;
	}

	/* Make sure iCal UID is unique for this user */
	memset(&cdata, 0, sizeof(struct caldav_data));
	cdata.ical_uid = uid;
	caldav_read(auth_caldavdb, &cdata);
	/* XXX  Check errors */

	if (cdata.mailbox && (strcmp(cdata.mailbox, mailboxname) ||
			      strcmp(cdata.resource, txn->req_tgt.resource))) {
	    /* CALDAV:unique-scheduling-object-resource */

	    txn->error.precond = CALDAV_UNIQUE_OBJECT;
	    buf_printf(&txn->buf, "/calendars/user/%s/%s/%s",
		       userid, strrchr(cdata.mailbox, '.')+1, cdata.resource);
	    txn->error.resource = buf_cstring(&txn->buf);
	    ret = HTTP_FORBIDDEN;
	    goto done;
	}

	if (caladdress_lookup(organizer, &sparam)) {
	    syslog(LOG_ERR,
		   "meth_delete: failed to process scheduling message in %s"
		   " (org=%s, att=%s)",
		   mailboxname, organizer, userid);
	    txn->error.desc = "Failed to lookup organizer address\r\n";
	    ret = HTTP_SERVER_ERROR;
	    goto done;
	}

	if (!strcmp(sparam.userid, userid)) {
	    /* Organizer scheduling object resource */
	    r = sched_request(organizer, NULL, ical);
	}
	else {
	    /* Attendee scheduling object resource */
	    r = sched_reply(NULL, ical, userid);
	}

	if (r) {
	    syslog(LOG_ERR,
		   "meth_put: failed to process scheduling message in %s"
		   " (org=%s, att=%s)",
		   mailboxname, organizer, userid);
	    txn->error.desc = "Failed to process scheduling message\r\n";
	    ret = HTTP_SERVER_ERROR;
	    goto done;
	}
    }
#endif /* WITH_CALDAV_SCHED */

    flags = NEW_STAG;
    if (get_preferences(txn->req_hdrs) & PREFER_REP) flags |= PREFER_REP;

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
	if (txn->req_tgt.collection) {
	    /* Add response for target calendar collection */
	    propfind_by_collection(mailboxname, 0, 0, fctx);
	}
	else {
	    /* Add responses for all contained calendar collections */
	    strlcat(mailboxname, ".%", sizeof(mailboxname));
	    mboxlist_findall(NULL,  /* internal namespace */
			     mailboxname, 1, httpd_userid, 
			     httpd_authstate, propfind_by_collection, fctx);
	}

	ret = *fctx->ret;
    }

    return ret;
}


static int report_cal_multiget(struct transaction_t *txn,
			       xmlNodePtr inroot, struct propfind_ctx *fctx,
			       char mailboxname[])
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
	    struct caldav_data cdata;

	    buf_ensure(&uri, len);
	    xmlURIUnescapeString((const char *) href, len, uri.s);

	    /* Parse the path */
	    strlcpy(tgt.path, uri.s, sizeof(tgt.path));
	    if ((r = parse_path(&tgt, fctx->errstr))) {
		ret = r;
		goto done;
	    }

	    fctx->req_tgt = &tgt;

	    target_to_mboxname(&tgt, mailboxname);

	    /* Check if we already have this mailbox open */
	    if (!mailbox || strcmp(mailbox->name, mailboxname)) {
		if (mailbox) mailbox_unlock_index(mailbox, NULL);

		/* Open mailbox for reading */
		if ((r = http_mailbox_open(mailboxname, &mailbox, LOCK_SHARED))) {
		    syslog(LOG_ERR, "http_mailbox_open(%s) failed: %s",
			   mailboxname, error_message(r));
		    txn->error.desc = error_message(r);
		    ret = HTTP_SERVER_ERROR;
		    goto done;
		}

		fctx->mailbox = mailbox;
	    }

	    /* Find message UID for the resource */
	    memset(&cdata, 0, sizeof(struct caldav_data));
	    cdata.mailbox = mailboxname;
	    cdata.resource = tgt.resource;
	    caldav_read(auth_caldavdb, &cdata);
	    /* XXX  Check errors */

	    propfind_by_resource(fctx, &cdata);
	}
    }

  done:
    if (mailbox) mailbox_unlock_index(mailbox, NULL);
    buf_free(&uri);

    return ret;
}



/* caldav_foreach() callback to find busytime of a resource */
static int busytime_by_resource(void *rock,
				struct caldav_data *cdata)
{
    struct propfind_ctx *fctx = (struct propfind_ctx *) rock;
    struct index_record record;
    int r;

    if (!cdata->imap_uid) return 0;

    /* Fetch index record for the resource */
    r = mailbox_find_index_record(fctx->mailbox, cdata->imap_uid, &record);
    if (r) return 0;

    fctx->record = &record;
    (void) apply_calfilter(fctx, cdata);

    if (fctx->msg_base) {
	mailbox_unmap_message(fctx->mailbox, fctx->record->uid,
			      &fctx->msg_base, &fctx->msg_size);
    }
    fctx->msg_base = NULL;
    fctx->msg_size = 0;
    fctx->record = NULL;

    return 0;
}


/* Compare start times of busytime period -- used for sorting */
static int compare_busytime(const void *b1, const void *b2)
{
    struct icalperiodtype *a = (struct icalperiodtype *) b1;
    struct icalperiodtype *b = (struct icalperiodtype *) b2;

    return icaltime_compare(a->start, b->start);
}


/* Create an iCalendar object containing busytime of all specified resources */
static icalcomponent *busytime(struct transaction_t *txn,
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

	/* XXX  Check DACL_READFB on all calendars */

	if (txn->req_tgt.collection) {
	    /* Get busytime for target calendar collection */
	    propfind_by_collection(mailboxname, 0, 0, fctx);
	}
	else {
	    /* Get busytime for all contained calendar collections */
	    strlcat(mailboxname, ".%", sizeof(mailboxname));
	    mboxlist_findall(NULL,  /* internal namespace */
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
    filter.comp = CAL_COMP_VEVENT | CAL_COMP_VFREEBUSY;
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

    cal = busytime(txn, fctx, mailboxname, 0, NULL, NULL, NULL);

    if (cal) {
	/* Output the iCalendar object as text/calendar */
	const char *cal_str = icalcomponent_as_ical_string(cal);
	icalcomponent_free(cal);

	txn->resp_body.type = "text/calendar; charset=utf-8";

	/* iCalendar data in response should not be transformed */
	txn->flags |= HTTP_NOTRANSFORM;

	write_body(HTTP_OK, txn, cal_str, strlen(cal_str));
    }
    else ret = HTTP_NOT_FOUND;

    return ret;
}


/* Compare modseq in index maps -- used for sorting */
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
    if (mailbox_user_flag(mailbox, DFLAG_UNBIND, &userflag)) userflag = -1;

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

	if ((userflag >= 0) &&
	    record->user_flags[userflag / 32] & (1 << (userflag & 31))) {
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
	struct caldav_data cdata;

	record = &istate.map[recno-1].record;

	/* Get resource filename from Content-Disposition header */
	if ((p = index_getheader(&istate, recno, "Content-Disposition"))) {
	    resource = strstr(p, "filename=") + 9;
	}
	if (!resource) continue;  /* No filename */

	if (*resource == '\"') {
	    resource++;
	    if ((p = strchr(resource, '\"'))) *p = '\0';
	}
	else if ((p = strchr(resource, ';'))) *p = '\0';

	memset(&cdata, 0, sizeof(struct caldav_data));
	cdata.resource = resource;

	if (record->system_flags & FLAG_EXPUNGED) {
	    /* report as NOT FOUND
	       IMAP UID of 0 will cause index record to be ignored
	       propfind_by_resource() will append our resource name */
	    propfind_by_resource(fctx, &cdata);
	}
	else {
	    fctx->record = record;
	    cdata.imap_uid = record->uid;
	    propfind_by_resource(fctx, &cdata);
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
	    txn->error.desc = "Illegal Depth value\r\n";
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
	txn->error.desc = "Missing request body\r\n";
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
	txn->error.precond = DAV_SUPP_REPORT;
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
		txn->error.precond = DAV_NEED_PRIVS;
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
		txn->error.desc = "Unsupported REPORT option <allprop>\r\n";
		ret = HTTP_NOT_IMPLEMENTED;
		goto done;
	    }
	    else if (!xmlStrcmp(cur->name, BAD_CAST "propname")) {
		syslog(LOG_WARNING, "REPORT %s w/propname", report->name);
		txn->error.desc = "Unsupported REPORT option <propname>\r\n";
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
	txn->error.desc = "Missing <prop> element in REPORT\r\n";
	ret = HTTP_BAD_REQUEST;
	goto done;
    }

    /* Start construction of our multistatus response */
    if ((report->flags & REPORT_MULTISTATUS) &&
	!(outroot = init_xml_response("multistatus", NS_DAV, inroot, ns))) {
	txn->error.desc = "Unable to create XML response\r\n";
	ret = HTTP_SERVER_ERROR;
	goto done;
    }

    /* Populate our propfind context */
    fctx.req_tgt = &txn->req_tgt;
    fctx.depth = depth;
    fctx.prefer = get_preferences(txn->req_hdrs);
    fctx.userid = httpd_userid;
    fctx.userisadmin = httpd_userisadmin;
    fctx.authstate = httpd_authstate;
    fctx.caldavdb = auth_caldavdb;
    fctx.mailbox = NULL;
    fctx.record = NULL;
    fctx.reqd_privs = report->reqd_privs;
    fctx.elist = NULL;
    fctx.root = outroot;
    fctx.ns = ns;
    fctx.errstr = &txn->error.desc;
    fctx.ret = &ret;
    fctx.fetcheddata = 0;

    /* Parse the list of properties and build a list of callbacks */
    if (prop) preload_proplist(prop->children, &fctx);

    /* Process the requested report */
    ret = (*report->proc)(txn, inroot, &fctx, mailboxname);

    /* Output the XML response */
    if (!ret && outroot) {
	/* iCalendar data in response should not be transformed */
	if (fctx.fetcheddata) txn->flags |= HTTP_NOTRANSFORM;

	xml_response(HTTP_MULTI_STATUS, txn, outroot->doc);
    }

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
	if (!*p || !*++p) return 0;

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
	return HTTP_NOT_FOUND;  /* need to specify a userid */
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


/* Parse an XML body into a tree */
int parse_xml_body(struct transaction_t *txn, xmlNodePtr *root)
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
	txn->error.desc = "This method requires an XML body\r\n";
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
    struct caldav_data cdata;
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
    memset(&cdata, 0, sizeof(struct caldav_data));
    cdata.ical_uid = uid = icalcomponent_get_uid(comp);
    caldav_read(caldavdb, &cdata);
    if (cdata.mailbox && !strcmp(cdata.mailbox, mailbox->name) &&
	strcmp(cdata.resource, resource)) {
	/* CALDAV:no-uid-conflict */
	txn->error.precond = CALDAV_UID_CONFLICT;
	buf_printf(&txn->buf, "/calendars/user/%s/%s/%s",
		   mboxname_to_userid(cdata.mailbox),
		   strrchr(cdata.mailbox, '.')+1, cdata.resource);
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
		memset(&cdata, 0, sizeof(struct caldav_data));
		cdata.mailbox = mailbox->name;
		cdata.resource = resource;
		caldav_lockread(caldavdb, &cdata);
		/* XXX  check for errors */

		if (cdata.imap_uid) {
		    /* Now that we have the replacement message in place
		       and the mailbox locked, re-read the old record
		       and see if we should overwrite it.  Either way,
		       one of our records will have to be expunged.
		    */
		    int userflag;

		    ret = (flags & PREFER_REP) ? HTTP_OK : HTTP_NO_CONTENT;

		    /* Fetch index record for the resource */
		    r = mailbox_find_index_record(mailbox,
						  cdata.imap_uid, &oldrecord);

		    if (overwrite == OVERWRITE_CHECK) {
			/* Check any preconditions */
			const char *etag = message_guid_encode(&oldrecord.guid);
			time_t lastmod = oldrecord.internaldate;
			int precond = check_precond(txn->meth, cdata.sched_tag,
						    etag, lastmod,
						    txn->req_hdrs);

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
		    cdata.mailbox = mailbox->name;
		    cdata.resource = resource;
		    cdata.imap_uid = newrecord.uid;
		    caldav_make_entry(ical, &cdata);

		    if (!cdata.organizer) cdata.sched_tag = NULL;
		    else if (flags & NEW_STAG) {
			sprintf(sched_tag, "%d-%ld-%u",
				getpid(), now, store_count++);
			cdata.sched_tag = sched_tag;
		    }

		    caldav_write(caldavdb, &cdata);
		    caldav_commit(caldavdb);
		    /* XXX  check for errors, if this fails, backout changes */

		    /* Tell client about the new resource */
		    txn->resp_body.etag = message_guid_encode(&newrecord.guid);
		    if (cdata.sched_tag) txn->resp_body.stag = cdata.sched_tag;

		    if (flags & PREFER_REP) {
			struct resp_body_t *resp_body = &txn->resp_body;

			resp_body->loc = txn->req_tgt.path;
			resp_body->type = "text/calendar; charset=utf-8";
			resp_body->len = strlen(ics);

			/* iCalendar data in response should not be transformed */
			txn->flags |= HTTP_NOTRANSFORM;

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

static unsigned get_preferences(hdrcache_t hdrcache)
{
    unsigned prefs = 0;
    const char **hdr;

    /* Check for Brief header */
    if ((hdr = spool_getheader(hdrcache, "Brief")) &&
	!strcasecmp(hdr[0], "t")) {
	prefs |= PREFER_MIN;
    }

    /* Check for Prefer header(s) */
    if ((hdr = spool_getheader(hdrcache, "Prefer"))) {
	int i;
	for (i = 0; hdr[i]; i++) {
	    tok_t tok;
	    char *token;

	    tok_init(&tok, hdr[i], ",\r\n", TOK_TRIMLEFT|TOK_TRIMRIGHT);
	    while ((token = tok_next(&tok))) {
		if (!strcmp(token, "return-minimal"))
		    prefs |= PREFER_MIN;
		else if (!strcmp(token, "return-representation"))
		    prefs |= PREFER_REP;
		else if (!strcmp(token, "depth-noroot"))
		    prefs |= PREFER_NOROOT;
	    }
	    tok_fini(&tok);
	}
    }

    return prefs;
}

#ifdef WITH_CALDAV_SCHED
static int caladdress_lookup(const char *addr, struct sched_param *param)
{
    char *p;
    int islocal = 1, found = 1;

    memset(param, 0, sizeof(struct sched_param));

    if (!addr) return HTTP_NOT_FOUND;

    p = (char *) addr;
    if (!strncmp(addr, "mailto:", 7)) p += 7;

    /* XXX  Do LDAP/DB/socket lookup to see if user is local */

    if (islocal) {
	/* User is in a local domain */
	int r;
	static const char *calendarprefix = NULL;
	char mailboxname[MAX_MAILBOX_BUFFER];

	if (!found) return HTTP_NOT_FOUND;
	else {
	    /* XXX  Hack until real lookup stuff is written */
	    static char userid[MAX_MAILBOX_BUFFER];

	    strlcpy(userid, p, sizeof(userid));
	    if ((p = strchr(userid, '@'))) *p = '\0';

	    param->userid = userid;
	}

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


/* Perform a Busy Time query based on given VFREEBUSY component */
int busytime_query(struct transaction_t *txn, icalcomponent *ical)
{
    int ret = 0;
    static const char *calendarprefix = NULL;
    icalcomponent *comp;
    char mailboxname[MAX_MAILBOX_BUFFER];
    icalproperty *prop = NULL;
    const char *uid = NULL, *organizer = NULL;
    struct sched_param sparam;
    struct auth_state *org_authstate = NULL;
    xmlNodePtr root = NULL;
    xmlNsPtr ns[NUM_NAMESPACE];
    struct propfind_ctx fctx;
    struct calquery_filter filter;

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

    memset(&filter, 0, sizeof(struct calquery_filter));
    filter.comp = CAL_COMP_VEVENT | CAL_COMP_VFREEBUSY;
    filter.start = icalcomponent_get_dtstart(comp);
    filter.end = icalcomponent_get_dtend(comp);
    filter.check_transp = 1;

    /* Populate our propfind context */
    memset(&fctx, 0, sizeof(struct propfind_ctx));
    fctx.req_tgt = &txn->req_tgt;
    fctx.depth = 2;
    fctx.userid = httpd_userid;
    fctx.userisadmin = httpd_userisadmin;
    fctx.authstate = org_authstate;
    fctx.reqd_privs = 0;  /* handled by CALDAV:schedule-deliver on Inbox */
    fctx.calfilter = &filter;
    fctx.errstr = &txn->error.desc;
    fctx.ret = &ret;
    fctx.fetcheddata = 0;

    for (prop = icalcomponent_get_first_property(comp, ICAL_ATTENDEE_PROPERTY);
	 prop;
	 prop = icalcomponent_get_next_property(comp, ICAL_ATTENDEE_PROPERTY)) {
	const char *attendee;
	xmlNodePtr resp, recip;

	attendee = icalproperty_get_attendee(prop);

	resp = xmlNewChild(root, NULL, BAD_CAST "response", NULL);
	recip = xmlNewChild(resp, NULL, BAD_CAST "recipient", NULL);
	if (txn->req_tgt.allow & ALLOW_ISCHEDULE) {
	    xmlNodeAddContent(recip, BAD_CAST attendee);
	}
	else {
	    xmlNewChild(recip, ns[NS_DAV], BAD_CAST "href", BAD_CAST attendee);
	}

	if (caladdress_lookup(attendee, &sparam)) {
	    xmlNewChild(resp, NULL, BAD_CAST "request-status",
			BAD_CAST "3.7;Invalid calendar user");
	    continue;
	}

	/* Is user remote or local? */
	if (!sparam.flags) {
	    /* Local attendee on this server */
	    const char *userid = sparam.userid;
	    struct mboxlist_entry mbentry;
	    int r, rights;
	    icalcomponent *busy = NULL;

	    /* Check ACL of ORGANIZER on attendee's Scheduling Inbox */
	    snprintf(mailboxname, sizeof(mailboxname),
		     "user.%s.%s.Inbox", userid, calendarprefix);

	    if ((r = mboxlist_lookup(mailboxname, &mbentry, NULL))) {
		syslog(LOG_INFO, "mboxlist_lookup(%s) failed: %s",
		       mailboxname, error_message(r));
		xmlNewChild(resp, NULL, BAD_CAST "request-status",
			    BAD_CAST "5.3;No scheduling support for user");
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
		     "user.%s.%s", userid, calendarprefix);

	    fctx.caldavdb = caldav_open(userid, CALDAV_CREATE);
	    fctx.req_tgt->collection = NULL;
	    fctx.busytime.len = 0;
	    busy = busytime(txn, &fctx, mailboxname,
			    ICAL_METHOD_REPLY, uid, organizer, attendee);

	    caldav_close(fctx.caldavdb);

	    if (busy) {
		xmlNodePtr cdata;
		const char *fb_str = icalcomponent_as_ical_string(busy);
		icalcomponent_free(busy);

		xmlNewChild(resp, NULL, BAD_CAST "request-status",
			    BAD_CAST "2.0;Success");
		cdata = xmlNewTextChild(resp, NULL,
					BAD_CAST "calendar-data", NULL);

		xmlAddChild(cdata,
			    xmlNewCDataBlock(root->doc,
					     BAD_CAST fb_str, strlen(fb_str)));

		/* iCalendar data in response should not be transformed */
		txn->flags |= HTTP_NOTRANSFORM;
	    }
	    else {
		xmlNewChild(resp, NULL, BAD_CAST "request-status",
			    BAD_CAST "3.7;Invalid calendar user");
	    }
	}
	else {
	    /* Remote attendee - send request elsewhere */
	    if (sparam.flags == SCHEDTYPE_REMOTE) {
		/* Use iMIP */
		syslog(LOG_INFO, "Use iMIP");
	    }
	    else {
		/* Use iSchedule */
		int r;
		icalcomponent *copy;
		xmlNodePtr xml;

		/* Clone a working copy of the iCal object */
		copy = icalcomponent_new_clone(ical);

		r = isched_send(&sparam, copy, &xml);
		if (!r) {
		    xmlNodePtr cur, node;
		    xmlChar *content;

		    /* Process each response element */
		    for (cur = xmlFirstElementChild(xml); cur;
			 cur = xmlNextElementSibling(cur)) {
			int match;

			node = xmlFirstElementChild(cur);   /* recipient */
			content = xmlNodeGetContent(node);
			match = !xmlStrcmp(content, BAD_CAST attendee);
			xmlFree(content);
			if (!match) continue;

			node = xmlNextElementSibling(node); /* request-status */
			content = xmlNodeGetContent(node);
			xmlNewChild(resp, NULL, BAD_CAST "request-status",
				    content);
			xmlFree(content);

			node = xmlNextElementSibling(node); /* calendar-data? */
			if (node &&
			    !xmlStrcmp(node->name, BAD_CAST "calendar-data")) {
			    xmlNodePtr cdata =
				xmlNewTextChild(resp, NULL,
						BAD_CAST "calendar-data", NULL);
			    content = xmlNodeGetContent(node);
			    xmlAddChild(cdata,
					xmlNewCDataBlock(root->doc,
							 content,
							 xmlStrlen(content)));
			    xmlFree(content);

			    /* iCal data in resp SHOULD NOT be transformed */
			    txn->flags |= HTTP_NOTRANSFORM;
			}
		    }

		    xmlFreeDoc(xml->doc);
		}
		else if (r == HTTP_UNAVAILABLE) {
		    xmlNewChild(resp, NULL, BAD_CAST "request-status",
				BAD_CAST "5.1;Service unavailable");
		}

		icalcomponent_free(copy);
	    }
	}
    }

    /* Output the XML response */
    if (!ret) xml_response(HTTP_OK, txn, root->doc);

  done:
    if (org_authstate) auth_freestate(org_authstate);
    if (fctx.busytime.busy) free(fctx.busytime.busy);
    if (root) xmlFree(root->doc);

    return ret;
}


/* Perform a CalDAV Scheduling Busy Time request */
static int sched_busytime(struct transaction_t *txn)
{
    int ret = 0, r, rights;
    char *acl, mailboxname[MAX_MAILBOX_BUFFER];
    const char **hdr;
    icalcomponent *ical, *comp;
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

    /* Construct mailbox name corresponding to request target URI */
    (void) target_to_mboxname(&txn->req_tgt, mailboxname);

    /* Locate the mailbox */
    if ((r = http_mlookup(mailboxname, NULL, &acl, NULL))) {
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
	txn->error.precond = DAV_NEED_PRIVS;
	txn->error.resource = txn->req_tgt.path;
	txn->error.rights = DACL_SCHED;
	return HTTP_FORBIDDEN;
    }

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
	return HTTP_BAD_REQUEST;
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
	return HTTP_FORBIDDEN;
    }

    ret = busytime_query(txn, ical);

    icalcomponent_free(ical);

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
    struct caldav_data cdata;
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

    memset(&cdata, 0, sizeof(struct caldav_data));
    cdata.ical_uid = icalcomponent_get_uid(sched_data->ical);
    caldav_read(caldavdb, &cdata);

    if (cdata.mailbox) {
	mboxname = cdata.mailbox;
	buf_setcstr(&resource, cdata.resource);
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

    if (!cdata.imap_uid) {
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
	mailbox_find_index_record(mailbox, cdata.imap_uid, &record);
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

static int sched_request(const char *organizer,
			 icalcomponent *oldical, icalcomponent *newical)
{
    int ret = 0;
    icalcomponent *ical;
    icalproperty_method method;
//    icaltimezone *utc = icaltimezone_get_utc_timezone();
    static struct buf prodid = BUF_INITIALIZER;
    struct sched_param sparam;
    struct auth_state *authstate;
    icalcomponent *req, *copy, *comp;
    icalproperty *prop;
    icalcomponent_kind kind;
    struct hash_table att_table;
    unsigned ncomp;

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

    /* Grab the organizer */
    comp = icalcomponent_get_first_real_component(copy);
    kind = icalcomponent_isa(comp);

    /* XXX  Do we need to do more checks here? */
    if (caladdress_lookup(organizer, &sparam) ||
	(sparam.flags & SCHEDTYPE_REMOTE))
	authstate = auth_newstate("anonymous");
    else
	authstate = auth_newstate(sparam.userid);

    /* Process each component */
    ncomp = 0;
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
	    if (do_sched && strcmp(attendee, organizer)) {
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

    return ret;
}

static int sched_reply(icalcomponent *oldical, icalcomponent *newical,
		       const char *userid)
{
    int ret = 0;
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

    sched_data = xzmalloc(sizeof(struct sched_data));
    sched_data->is_reply = 1;

    /* Check what kind of METHOD we are dealing with */
    if (!newical) {
	method = ICAL_METHOD_CANCEL;
	ical = oldical;
    }
    else {
	/* XXX  Need to handle modify */
	method = ICAL_METHOD_REPLY;
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

	    /* Check CalDAV Scheduling parameters */
	    for (param = icalproperty_get_first_parameter(myattendee,
							  ICAL_IANA_PARAMETER);
		 param;
		 param = icalproperty_get_next_parameter(myattendee,
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
		icalcomponent *new_comp;

		if (force_send) {
		    if (!sched_data->force_send) {
			sched_data->force_send =
			    xstrdup(icalparameter_get_iana_value(force_send));
		    }

		    icalproperty_remove_parameter_by_ref(prop, force_send);
		}

		new_comp = icalcomponent_new_clone(comp);
		icalcomponent_add_component(sched_data->ical, new_comp);
	    }
	}

    } while ((comp = icalcomponent_get_next_component(copy, kind)));

    /* Grab the organizer */
    comp = icalcomponent_get_first_real_component(ical);
    prop = icalcomponent_get_first_property(comp, ICAL_ORGANIZER_PROPERTY);
    organizer = icalproperty_get_organizer(prop);

    /* Attempt to deliver reply to organizer */
    sched_deliver((char *) organizer, sched_data, authstate);

    if (newical) {
	/* Set SCHEDULE-STATUS for organizer in attendee object */
	param = icalparameter_new(ICAL_IANA_PARAMETER);
	icalparameter_set_iana_name(param, "SCHEDULE-STATUS");
	icalparameter_set_iana_value(param, sched_data->status);
	icalproperty_add_parameter(prop, param);
    }

    /* Cleanup */
    auth_freestate(authstate);
    icalcomponent_free(copy);
    free_sched_data(sched_data);

    return ret;
}
#endif /* WITH_CALDAV_SCHED */
