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
#include "global.h"
#include "http_err.h"
#include "http_proxy.h"
#include "imap_err.h"
#include "index.h"
#include "proxy.h"
#include "rfc822date.h"
#include "tok.h"
#include "xmalloc.h"
#include "xstrlcat.h"
#include "xstrlcpy.h"

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
    { XML_NS_CYRUS, "CY" },
};

/* PROPFIND modes */
enum {
    PROPFIND_NONE = 0,			/* only used with REPORT */
    PROPFIND_ALL,
    PROPFIND_NAME,
    PROPFIND_PROP
};

static void my_dav_init(struct buf *serverinfo);

static int prin_parse_path(const char *path,
			   struct request_target_t *tgt, const char **errstr);
static int propfind_restype(const xmlChar *name, xmlNsPtr ns,
			    struct propfind_ctx *fctx, xmlNodePtr resp,
			    struct propstat propstat[], void *rock);
static int propfind_reportset(const xmlChar *name, xmlNsPtr ns,
			      struct propfind_ctx *fctx, xmlNodePtr resp,
			      struct propstat propstat[], void *rock);
static int propfind_principalurl(const xmlChar *name, xmlNsPtr ns,
				 struct propfind_ctx *fctx, xmlNodePtr resp,
				 struct propstat propstat[], void *rock);

static int allprop_cb(const char *mailbox __attribute__((unused)),
		      const char *entry,
		      const char *userid, struct annotation_data *attrib,
		      void *rock);

/* Array of known "live" properties */
static const struct prop_entry dav_props[] = {

    /* WebDAV (RFC 4918) properties */
    { "creationdate", NS_DAV, PROP_ALLPROP, NULL, NULL, NULL },
    { "displayname", NS_DAV, PROP_ALLPROP, NULL, NULL, NULL },
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
      propfind_reportset, NULL, NULL },

    /* WebDAV ACL (RFC 3744) properties */
    { "alternate-URI-set", NS_DAV, 0, NULL, NULL, NULL },
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
    { "calendar-user-type", NS_CALDAV, 0, NULL, NULL, NULL },

    /* CardDAV (RFC 6352) properties */
    { "addressbook-home-set", NS_CARDDAV, PROP_COLLECTION,
      propfind_abookurl, NULL, NULL },

    /* Apple Calendar Server properties */
    { "getctag", NS_CS, PROP_ALLPROP, NULL, NULL, NULL },

    { NULL, 0, 0, NULL, NULL, NULL }
};


static struct meth_params princ_params = {
    .parse_path = &prin_parse_path,
    .lprops = dav_props
};

/* Namespace for WebDAV principals */
struct namespace_t namespace_principal = {
    URL_NS_PRINCIPAL, 0, "/dav/principals", NULL, 1 /* auth */,
    ALLOW_READ | ALLOW_DAV,
    &my_dav_init, NULL, NULL, NULL,
    {
	{ NULL,			NULL },			/* ACL		*/
	{ NULL,			NULL },			/* COPY		*/
	{ NULL,			NULL },			/* DELETE	*/
	{ &meth_get_dav,	&princ_params },	/* GET		*/
	{ &meth_get_dav,	&princ_params },	/* HEAD		*/
	{ NULL,			NULL },			/* LOCK		*/
	{ NULL,			NULL },			/* MKCALENDAR	*/
	{ NULL,			NULL },			/* MKCOL	*/
	{ NULL,			NULL },			/* MOVE		*/
	{ &meth_options,	NULL },			/* OPTIONS	*/
	{ NULL,			NULL },			/* POST		*/
	{ &meth_propfind,	&princ_params },	/* PROPFIND	*/
	{ NULL,			NULL },			/* PROPPATCH	*/
	{ NULL,			NULL },			/* PUT		*/
	{ &meth_report,		NULL },			/* REPORT	*/
	{ &meth_trace,		NULL },			/* TRACE	*/
	{ NULL,			NULL }			/* UNLOCK	*/
    }
};


static void my_dav_init(struct buf *serverinfo)
{
    if (config_httpmodules & IMAP_ENUM_HTTPMODULES_CALDAV) {
	namespace_principal.enabled = 1;
	namespace_principal.allow |= ALLOW_CAL;
	if (config_getswitch(IMAPOPT_CALDAV_ALLOWSCHEDULING))
	    namespace_principal.allow |= ALLOW_CAL_SCHED;
    }
    if (config_httpmodules & IMAP_ENUM_HTTPMODULES_CARDDAV) {
	namespace_principal.enabled = 1;
	namespace_principal.allow |= ALLOW_CARD;
    }

    if (!namespace_principal.enabled) return;

    if (config_serverinfo == IMAP_ENUM_SERVERINFO_ON) {
	buf_printf(serverinfo, " SQLite/%s", sqlite3_libversion());
    }
}


/* Linked-list of properties for fetching */
struct propfind_entry_list {
    const xmlChar *name;		/* Property name */
    xmlNsPtr ns;			/* Property namespace */
    unsigned char flags;		/* Flags for how/where prop apply */
    int (*get)(const xmlChar *name,	/* Callback to fetch property */
	       xmlNsPtr ns, struct propfind_ctx *fctx, xmlNodePtr resp,
	       struct propstat propstat[], void *rock);
    void *rock;				/* Add'l data to pass to callback */
    struct propfind_entry_list *next;
};


/* Bitmask of privilege flags */
enum {
    PRIV_IMPLICIT =		(1<<0),
    PRIV_INBOX =		(1<<1),
    PRIV_OUTBOX =		(1<<2)
};


/* Array of precondition/postcondition errors */
static const struct precond_t {
    const char *name;			/* Property name */
    unsigned ns;			/* Index into known namespace array */
} preconds[] = {
    /* Placeholder for zero (no) precondition code */
    { NULL, 0 },

    /* WebDAV (RFC 4918) preconditons */
    { "cannot-modify-protected-property", NS_DAV },
    { "lock-token-matches-request-uri", NS_DAV },
    { "lock-token-submitted", NS_DAV },
    { "no-conflicting-lock", NS_DAV },

    /* WebDAV Versioning (RFC 3253) preconditions */
    { "supported-report", NS_DAV },
    { "resource-must-be-null", NS_DAV },

    /* WebDAV ACL (RFC 3744) preconditions */
    { "need-privileges", NS_DAV },
    { "no-invert", NS_DAV },
    { "no-abstract", NS_DAV },
    { "not-supported-privilege", NS_DAV },
    { "recognized-principal", NS_DAV },

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
    { "supported-filter", NS_CARDDAV }
};


/* Parse request-target path in DAV principals namespace */
static int prin_parse_path(const char *path,
			   struct request_target_t *tgt, const char **errstr)
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
    }
    else return HTTP_NOT_FOUND;  /* need to specify a userid */

    if (*p) {
//	*errstr = "Too many segments in request target path";
	return HTTP_NOT_FOUND;
    }

    return 0;
}


unsigned get_preferences(struct transaction_t *txn)
{
    unsigned mask = 0, prefs = 0;
    const char **hdr;

    /* Create a mask for preferences honored by method */
    switch (txn->meth) {
    case METH_COPY:
    case METH_MOVE:
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


static int add_privs(int rights, unsigned flags,
		     xmlNodePtr parent, xmlNodePtr root, xmlNsPtr *ns);


/* Ensure that we have a given namespace.  If it doesn't exist in what we
 * parsed in the request, create it and attach to 'node'.
 */
int ensure_ns(xmlNsPtr *respNs, int ns, xmlNodePtr node,
	      const char *url, const char *prefix)
{
    if (!respNs[ns])
	respNs[ns] = xmlNewNs(node, BAD_CAST url, BAD_CAST prefix);

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
    ensure_ns(respNs, ns, root,
	      known_namespaces[ns].href, known_namespaces[ns].prefix);
    xmlSetNs(root, respNs[ns]);

    return root;
}

xmlNodePtr xml_add_href(xmlNodePtr parent, xmlNsPtr ns, const char *href)
{
    xmlChar *uri = xmlURIEscapeStr(BAD_CAST href, BAD_CAST ":/");
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
	if (err->resource) xml_add_href(node, avail_ns[NS_DAV], err->resource);
	break;
    }

    if (err->desc) {
	xmlNewTextChild(error, NULL, BAD_CAST resp_desc, BAD_CAST err->desc);
    }

    return root;
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
static int xml_add_response(struct propfind_ctx *fctx, long code)
{
    xmlNodePtr resp;

    resp = xmlNewChild(fctx->root, NULL, BAD_CAST "response", NULL);
    if (!resp) {
	fctx->err->desc = "Unable to add response XML element";
	*fctx->ret = HTTP_SERVER_ERROR;
	return HTTP_SERVER_ERROR;
    }
    xml_add_href(resp, NULL, fctx->req_tgt->path);

    if (code) {
	xmlNewChild(resp, NULL, BAD_CAST "status",
		    BAD_CAST http_statusline(code));
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
			r = e->get(e->name, e->ns,
				   fctx, resp, propstat, e->rock);
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

	    annotatemore_findall(fctx->mailbox->name, ANNOT_NS "*",
				 allprop_cb, &arock, NULL);
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
		    struct error_t error = { NULL, stat->precond, NULL, 0 };
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
		     struct propstat propstat[], xmlNodePtr prop,
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
	    fctx->err->precond = precond;
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
	    void *obj = mime_types->from_string(data);
	    
	    data = freeme = mime->to_string(obj);
	    datalen = strlen(data);
	    mime_types->free(obj);
	}

	if (type) {
	    xmlSetProp(prop, BAD_CAST "content-type", type);
	    if (ver) xmlSetProp(prop, BAD_CAST "version", ver);
	}

	xmlAddChild(prop,
		    xmlNewCDataBlock(fctx->root->doc, BAD_CAST data, datalen));

	fctx->fetcheddata = 1;

	if (freeme) free(freeme);
    }

    if (type) xmlFree(type);
    if (ver) xmlFree(ver);

    return ret;
}


/* Callback to fetch DAV:creationdate */
int propfind_creationdate(const xmlChar *name, xmlNsPtr ns,
			  struct propfind_ctx *fctx,
			  xmlNodePtr resp __attribute__((unused)),
			  struct propstat propstat[],
			  void *rock __attribute__((unused)))
{
    time_t t = 0;
    char datestr[21];

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

    rfc3339date_gen(datestr, sizeof(datestr), t);

    xml_add_prop(HTTP_OK, fctx->ns[NS_DAV], &propstat[PROPSTAT_OK],
		 name, ns, BAD_CAST datestr, 0);

    return 0;
}


/* Callback to fetch DAV:getcontentlength */
int propfind_getlength(const xmlChar *name, xmlNsPtr ns,
		       struct propfind_ctx *fctx,
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
		      xmlNodePtr resp __attribute__((unused)),
		      struct propstat propstat[],
		      void *rock __attribute__((unused)))
{
    xmlNodePtr node = xml_add_prop(HTTP_OK, fctx->ns[NS_DAV],
				   &propstat[PROPSTAT_OK], name, ns, NULL, 0);

    if (fctx->mailbox && fctx->record) {
	struct dav_data *ddata = (struct dav_data *) fctx->data;

	xml_add_lockdisc(node, fctx->req_tgt->path, ddata);
    }

    return 0;
}


/* Callback to fetch DAV:resourcetype */
static int propfind_restype(const xmlChar *name, xmlNsPtr ns,
			    struct propfind_ctx *fctx,
			    xmlNodePtr resp __attribute__((unused)),
			    struct propstat propstat[],
			    void *rock __attribute__((unused)))
{
    xmlNodePtr node = xml_add_prop(HTTP_OK, fctx->ns[NS_DAV],
				   &propstat[PROPSTAT_OK], name, ns, NULL, 0);

    xmlNewChild(node, NULL, BAD_CAST "collection", NULL);

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

    if (set && (pctx->meth == METH_MKCOL || pctx->meth == METH_MKCALENDAR)) {
	/* "Writeable" for MKCOL/MKCALENDAR only */
	xmlNodePtr cur;

	for (cur = prop->children; cur; cur = cur->next) {
	    if (cur->type != XML_ELEMENT_NODE) continue;
	    /* Make sure we have valid resourcetypes for the collection */
	    if (xmlStrcmp(cur->name, BAD_CAST "collection") &&
		xmlStrcmp(cur->name, BAD_CAST coltype)) break;
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
static int propfind_reportset(const xmlChar *name, xmlNsPtr ns,
			      struct propfind_ctx *fctx,
			      xmlNodePtr resp __attribute__((unused)),
			      struct propstat propstat[],
			      void *rock __attribute__((unused)))
{
    xml_add_prop(HTTP_OK, fctx->ns[NS_DAV], &propstat[PROPSTAT_OK],
		 name, ns, NULL, 0);

    return 0;
}


/* Callback to fetch DAV:principalurl */
static int propfind_principalurl(const xmlChar *name, xmlNsPtr ns,
				 struct propfind_ctx *fctx,
				 xmlNodePtr resp __attribute__((unused)),
				 struct propstat propstat[],
				 void *rock __attribute__((unused)))
{
    xmlNodePtr node = xml_add_prop(HTTP_OK, fctx->ns[NS_DAV],
				   &propstat[PROPSTAT_OK], name, ns, NULL, 0);

    buf_reset(&fctx->buf);
    if (fctx->req_tgt->user) {
	buf_printf(&fctx->buf, "%s/user/%.*s/",
		   namespace_principal.prefix,
		   (int) fctx->req_tgt->userlen, fctx->req_tgt->user);
    }

    xml_add_href(node, NULL, buf_cstring(&fctx->buf));

    return 0;
}


/* Callback to fetch DAV:owner */
int propfind_owner(const xmlChar *name, xmlNsPtr ns,
		   struct propfind_ctx *fctx,
		   xmlNodePtr resp __attribute__((unused)),
		   struct propstat propstat[],
		   void *rock __attribute__((unused)))
{
    xmlNodePtr node = xml_add_prop(HTTP_OK, fctx->ns[NS_DAV],
				   &propstat[PROPSTAT_OK], name, ns, NULL, 0);

    if (fctx->req_tgt->user) {
	buf_reset(&fctx->buf);
	buf_printf(&fctx->buf, "%s/user/%.*s/",
		   namespace_principal.prefix,
		   (int) fctx->req_tgt->userlen, fctx->req_tgt->user);

	xml_add_href(node, NULL, buf_cstring(&fctx->buf));
    }

    return 0;
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

    if (fctx->req_tgt->namespace == URL_NS_CALENDAR) {
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
    add_suppriv(write, "write-properties", NULL, 0, "Write properties");

    agg = add_suppriv(write, "bind", NULL, 0, "Add new member to collection");
    ensure_ns(fctx->ns, NS_CYRUS, resp->parent, XML_NS_CYRUS, "CY");
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


static int add_privs(int rights, unsigned flags,
		     xmlNodePtr parent, xmlNodePtr root, xmlNsPtr *ns)
{
    xmlNodePtr priv;

    if ((rights & DACL_ALL) == DACL_ALL &&
	/* DAV:all on CALDAV:schedule-in/outbox MUST include CALDAV:schedule */
	(!(flags & (PRIV_INBOX|PRIV_OUTBOX)) ||
	 (rights & DACL_SCHED) == DACL_SCHED)) {
	priv = xmlNewChild(parent, NULL, BAD_CAST "privilege", NULL);
	xmlNewChild(priv, NULL, BAD_CAST "all", NULL);
    }
    if ((rights & DACL_READ) == DACL_READ) {
	priv = xmlNewChild(parent, NULL, BAD_CAST "privilege", NULL);
	xmlNewChild(priv, NULL, BAD_CAST "read", NULL);
	if (flags & PRIV_IMPLICIT) rights |= DACL_READFB;
    }
    if ((rights & DACL_READFB) &&
	/* CALDAV:read-free-busy does not apply to CALDAV:schedule-in/outbox */
	!(flags & (PRIV_INBOX|PRIV_OUTBOX))) {
	priv = xmlNewChild(parent, NULL, BAD_CAST "privilege", NULL);
	ensure_ns(ns, NS_CALDAV, root, XML_NS_CALDAV, "C");
	xmlNewChild(priv, ns[NS_CALDAV], BAD_CAST  "read-free-busy", NULL);
    }
    if ((rights & DACL_WRITE) == DACL_WRITE) {
	priv = xmlNewChild(parent, NULL, BAD_CAST "privilege", NULL);
	xmlNewChild(priv, NULL, BAD_CAST "write", NULL);
    }
    if (rights & DACL_WRITECONT) {
	priv = xmlNewChild(parent, NULL, BAD_CAST "privilege", NULL);
	xmlNewChild(priv, NULL, BAD_CAST "write-content", NULL);
    }
    if (rights & DACL_WRITEPROPS) {
	priv = xmlNewChild(parent, NULL, BAD_CAST "privilege", NULL);
	xmlNewChild(priv, NULL, BAD_CAST "write-properties", NULL);
    }

    if (rights & (DACL_BIND|DACL_UNBIND|DACL_ADMIN)) {
	ensure_ns(ns, NS_CYRUS, root, XML_NS_CYRUS, "CY");
    }

    if ((rights & DACL_BIND) == DACL_BIND) {
	priv = xmlNewChild(parent, NULL, BAD_CAST "privilege", NULL);
	xmlNewChild(priv, NULL, BAD_CAST "bind", NULL);
    }
    if (rights & DACL_MKCOL) {
	priv = xmlNewChild(parent, NULL, BAD_CAST "privilege", NULL);
	xmlNewChild(priv, ns[NS_CYRUS], BAD_CAST "make-collection", NULL);
    }
    if (rights & DACL_ADDRSRC) {
	priv = xmlNewChild(parent, NULL, BAD_CAST "privilege", NULL);
	xmlNewChild(priv, ns[NS_CYRUS], BAD_CAST "add-resource", NULL);
    }
    if ((rights & DACL_UNBIND) == DACL_UNBIND) {
	priv = xmlNewChild(parent, NULL, BAD_CAST "privilege", NULL);
	xmlNewChild(priv, NULL, BAD_CAST "unbind", NULL);
    }
    if (rights & DACL_RMCOL) {
	priv = xmlNewChild(parent, NULL, BAD_CAST "privilege", NULL);
	xmlNewChild(priv, ns[NS_CYRUS], BAD_CAST "remove-collection", NULL);
    }
    if (rights & DACL_RMRSRC) {
	priv = xmlNewChild(parent, NULL, BAD_CAST "privilege", NULL);
	xmlNewChild(priv, ns[NS_CYRUS], BAD_CAST "remove-resource", NULL);
    }
    if (rights & DACL_ADMIN) {
	priv = xmlNewChild(parent, NULL, BAD_CAST "privilege", NULL);
	xmlNewChild(priv, ns[NS_CYRUS], BAD_CAST  "admin", NULL);
    }

    if (rights & DACL_SCHED) {
	ensure_ns(ns, NS_CALDAV, root, XML_NS_CALDAV, "C");
    }
    if ((rights & DACL_SCHED) == DACL_SCHED) {
	priv = xmlNewChild(parent, NULL, BAD_CAST "privilege", NULL);
	if (flags & PRIV_INBOX)
	    xmlNewChild(priv, ns[NS_CALDAV], BAD_CAST "schedule-deliver", NULL);
	else if (flags & PRIV_OUTBOX)
	    xmlNewChild(priv, ns[NS_CALDAV], BAD_CAST "schedule-send", NULL);
    }
    if (rights & DACL_INVITE) {
	priv = xmlNewChild(parent, NULL, BAD_CAST "privilege", NULL);
	if (flags & PRIV_INBOX)
	    xmlNewChild(priv, ns[NS_CALDAV],
			BAD_CAST "schedule-deliver-invite", NULL);
	else if (flags & PRIV_OUTBOX)
	    xmlNewChild(priv, ns[NS_CALDAV],
			BAD_CAST "schedule-send-invite", NULL);
    }
    if (rights & DACL_REPLY) {
	priv = xmlNewChild(parent, NULL, BAD_CAST "privilege", NULL);
	if (flags & PRIV_INBOX)
	    xmlNewChild(priv, ns[NS_CALDAV],
			BAD_CAST "schedule-deliver-reply", NULL);
	else if (flags & PRIV_OUTBOX)
	    xmlNewChild(priv, ns[NS_CALDAV],
			BAD_CAST "schedule-send-reply", NULL);
    }
    if (rights & DACL_SCHEDFB) {
	priv = xmlNewChild(parent, NULL, BAD_CAST "privilege", NULL);
	if (flags & PRIV_INBOX)
	    xmlNewChild(priv, ns[NS_CALDAV],
			BAD_CAST "schedule-query-freebusy", NULL);
	else if (flags & PRIV_OUTBOX)
	    xmlNewChild(priv, ns[NS_CALDAV],
			BAD_CAST "schedule-send-freebusy", NULL);
    }

    return 0;
}


/* Callback to fetch DAV:current-user-privilege-set */
int propfind_curprivset(const xmlChar *name, xmlNsPtr ns,
			struct propfind_ctx *fctx,
			xmlNodePtr resp,
			struct propstat propstat[],
			void *rock __attribute__((unused)))
{
    int rights;
    unsigned flags = 0;
    xmlNodePtr set;

    if (!fctx->mailbox) return HTTP_NOT_FOUND;
    if (((rights = cyrus_acl_myrights(fctx->authstate, fctx->mailbox->acl))
	 & DACL_READ) != DACL_READ) {
	return HTTP_UNAUTHORIZED;
    }

    /* Add in implicit rights */
    if (fctx->userisadmin) {
	rights |= DACL_ADMIN;
    }
    else if (mboxname_userownsmailbox(fctx->int_userid, fctx->mailbox->name)) {
	rights |= config_implicitrights;
    }

    /* Build the rest of the XML response */
    set = xml_add_prop(HTTP_OK, fctx->ns[NS_DAV], &propstat[PROPSTAT_OK],
		       name, ns, NULL, 0);

    if (fctx->req_tgt->collection) {
	if (fctx->req_tgt->namespace == URL_NS_CALENDAR) {
	    flags = PRIV_IMPLICIT;

	    if (!strcmp(fctx->req_tgt->collection, SCHED_INBOX))
		flags = PRIV_INBOX;
	    else if (!strcmp(fctx->req_tgt->collection, SCHED_OUTBOX))
		flags = PRIV_OUTBOX;
	}

	add_privs(rights, flags, set, resp->parent, fctx->ns);
    }

    return 0;
}


/* Callback to fetch DAV:acl */
int propfind_acl(const xmlChar *name, xmlNsPtr ns,
		 struct propfind_ctx *fctx,
		 xmlNodePtr resp,
		 struct propstat propstat[],
		 void *rock __attribute__((unused)))
{
    int rights;
    xmlNodePtr acl;
    char *aclstr, *userid;
    unsigned flags = 0;

    if (!fctx->mailbox) return HTTP_NOT_FOUND;
    if (!((rights = cyrus_acl_myrights(fctx->authstate, fctx->mailbox->acl))
	  & DACL_ADMIN)) {
	return HTTP_UNAUTHORIZED;
    }

    if (fctx->req_tgt->namespace == URL_NS_CALENDAR) {
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
	/* XXX  Does this correspond to DAV:deny? */
	if (*userid == '-') {
	    deny = 1;
	    userid++;
	}

	rights = cyrus_acl_strtomask(rightstr);

	/* Add ace XML element for this userid/right pair */
	ace = xmlNewChild(acl, NULL, BAD_CAST "ace", NULL);

	/* XXX  Need to check for groups.
	 * Is there any IMAP equivalent to "unauthenticated"?
	 * Is there any DAV equivalent to "anonymous"?
	 */

	node = xmlNewChild(ace, NULL, BAD_CAST "principal", NULL);
	if (!strcmp(userid, fctx->userid))
	    xmlNewChild(node, NULL, BAD_CAST "self", NULL);
	else if ((strlen(userid) == fctx->req_tgt->userlen) &&
		 !strncmp(userid, fctx->req_tgt->user, fctx->req_tgt->userlen))
	    xmlNewChild(node, NULL, BAD_CAST "owner", NULL);
	else if (!strcmp(userid, "anyone"))
	    xmlNewChild(node, NULL, BAD_CAST "authenticated", NULL);
	else {
	    buf_reset(&fctx->buf);
	    buf_printf(&fctx->buf, "%s/user/%s/",
		       namespace_principal.prefix, userid);
	    xml_add_href(node, NULL, buf_cstring(&fctx->buf));
	}

	node = xmlNewChild(ace, NULL,
			   BAD_CAST (deny ? "deny" : "grant"), NULL);
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
int propfind_princolset(const xmlChar *name, xmlNsPtr ns,
			struct propfind_ctx *fctx,
			xmlNodePtr resp __attribute__((unused)),
			struct propstat propstat[],
			void *rock __attribute__((unused)))
{
    xmlNodePtr node = xml_add_prop(HTTP_OK, fctx->ns[NS_DAV],
				   &propstat[PROPSTAT_OK], name, ns, NULL, 0);

    buf_reset(&fctx->buf);
    buf_printf(&fctx->buf, "%s/", namespace_principal.prefix);
    xmlNewChild(node, NULL, BAD_CAST "href", BAD_CAST buf_cstring(&fctx->buf));

    return 0;
}


/* Callback to fetch DAV:quota-available-bytes and DAV:quota-used-bytes */
int propfind_quota(const xmlChar *name, xmlNsPtr ns,
		   struct propfind_ctx *fctx,
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
    else {
	/* Find the quotaroot governing this hierarchy */
	if (quota_findroot(foundroot, sizeof(foundroot), fctx->req_tgt->mboxname)) {
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
	uquota_t limit = fctx->quota.limit * QUOTA_UNITS;

	buf_printf(&fctx->buf, UQUOTA_T_FMT, limit - fctx->quota.used);
    }
    else if (fctx->record) {
	/* Bytes used by resource */
	buf_printf(&fctx->buf, "%u", fctx->record->size);
    }
    else if (fctx->mailbox) {
	/* Bytes used by calendar collection */
	buf_printf(&fctx->buf, UQUOTA_T_FMT,
		   fctx->mailbox->i.quota_mailbox_used);
    }
    else {
	/* Bytes used by entire hierarchy */
	buf_printf(&fctx->buf, UQUOTA_T_FMT, fctx->quota.used);
    }

    xml_add_prop(HTTP_OK, fctx->ns[NS_DAV], &propstat[PROPSTAT_OK],
		 name, ns, BAD_CAST buf_cstring(&fctx->buf), 0);

    return 0;
}


/* Callback to fetch DAV:current-user-principal */
int propfind_curprin(const xmlChar *name, xmlNsPtr ns,
		     struct propfind_ctx *fctx,
		     xmlNodePtr resp __attribute__((unused)),
		     struct propstat propstat[],
		     void *rock __attribute__((unused)))
{
    xmlNodePtr node = xml_add_prop(HTTP_OK, fctx->ns[NS_DAV],
				   &propstat[PROPSTAT_OK], name, ns, NULL, 0);

    if (fctx->userid) {
	buf_reset(&fctx->buf);
	buf_printf(&fctx->buf, "%s/user/%s/",
		   namespace_principal.prefix, fctx->userid);
	xml_add_href(node, NULL, buf_cstring(&fctx->buf));
    }
    else {
	xmlNewChild(node, NULL, BAD_CAST "unauthenticated", NULL);
    }

    return 0;
}


/* Callback to fetch DAV:add-member */
int propfind_addmember(const xmlChar *name, xmlNsPtr ns,
		       struct propfind_ctx *fctx,
		       xmlNodePtr resp __attribute__((unused)),
		       struct propstat propstat[],
		       void *rock __attribute__((unused)))
{
    xmlNodePtr node;
    int len;

    if (!fctx->req_tgt->collection) return HTTP_NOT_FOUND;

    node = xml_add_prop(HTTP_OK, fctx->ns[NS_DAV], &propstat[PROPSTAT_OK],
			name, ns, NULL, 0);

    len = fctx->req_tgt->resource ?
	(size_t) (fctx->req_tgt->resource - fctx->req_tgt->path) :
	strlen(fctx->req_tgt->path);
    buf_reset(&fctx->buf);
    buf_printf(&fctx->buf, "%.*s", len, fctx->req_tgt->path);

    xml_add_href(node, NULL, buf_cstring(&fctx->buf));

    return 0;
}


/* Callback to fetch DAV:sync-token and CS:getctag */
int propfind_sync_token(const xmlChar *name, xmlNsPtr ns,
			struct propfind_ctx *fctx,
			xmlNodePtr resp __attribute__((unused)),
			struct propstat propstat[],
			void *rock __attribute__((unused)))
{
    if (!fctx->mailbox || fctx->record) return HTTP_NOT_FOUND;

    buf_reset(&fctx->buf);
    buf_printf(&fctx->buf, XML_NS_CYRUS "sync/%u-" MODSEQ_FMT,
	       fctx->mailbox->i.uidvalidity,
	       fctx->mailbox->i.highestmodseq);

    xml_add_prop(HTTP_OK, fctx->ns[NS_DAV], &propstat[PROPSTAT_OK],
		 name, ns, BAD_CAST buf_cstring(&fctx->buf), 0);

    return 0;
}


/* Callback to fetch properties from resource header */
int propfind_fromhdr(const xmlChar *name, xmlNsPtr ns,
		     struct propfind_ctx *fctx,
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


/* Callback to read a property from annotation DB */
int propfind_fromdb(const xmlChar *name, xmlNsPtr ns,
		    struct propfind_ctx *fctx,
		    xmlNodePtr resp __attribute__((unused)),
		    struct propstat propstat[],
		    void *rock __attribute__((unused)))
{
    struct annotation_data attrib;
    xmlNodePtr node;
    int r = 0;

    buf_reset(&fctx->buf);
    buf_printf(&fctx->buf, ANNOT_NS "<%s>%s",
	       (const char *) ns->href, name);

    memset(&attrib, 0, sizeof(struct annotation_data));

    if (fctx->mailbox && !fctx->record &&
	!(r = annotatemore_lookup(fctx->mailbox->name, buf_cstring(&fctx->buf),
				  /* shared */ "", &attrib))) {
	if (!attrib.value && 
	    !xmlStrcmp(name, BAD_CAST "displayname")) {
	    /* Special case empty displayname -- use last segment of path */
	    attrib.value = strrchr(fctx->mailbox->name, '.') + 1;
	    attrib.size = strlen(attrib.value);
	}
    }

    if (r) return HTTP_SERVER_ERROR;
    if (!attrib.value) return HTTP_NOT_FOUND;

    node = xml_add_prop(HTTP_OK, fctx->ns[NS_DAV], &propstat[PROPSTAT_OK],
			name, ns, NULL, 0);
    xmlAddChild(node, xmlNewCDataBlock(fctx->root->doc,
				       BAD_CAST attrib.value, attrib.size));

    return 0;
}


/* Callback to write a property to annotation DB */
int proppatch_todb(xmlNodePtr prop, unsigned set,
		   struct proppatch_ctx *pctx,
		   struct propstat propstat[],
		   void *rock __attribute__((unused)))
{
    xmlChar *freeme = NULL;
    const char *value = NULL;
    size_t len = 0;
    int r;

    buf_reset(&pctx->buf);
    buf_printf(&pctx->buf, ANNOT_NS "<%s>%s",
	       (const char *) prop->ns->href, prop->name);

    if (set) {
	freeme = xmlNodeGetContent(prop);
	value = (const char *) freeme;
	len = strlen(value);
    }

    if (!(r = annotatemore_write_entry(pctx->mailboxname,
				       buf_cstring(&pctx->buf), /* shared */ "",
				       value, NULL, len, 0,
				       &pctx->tid))) {
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
		      const char *entry,
		      const char *userid, struct annotation_data *attrib,
		      void *rock)
{
    struct allprop_rock *arock = (struct allprop_rock *) rock;
    const struct prop_entry *pentry;
    char *href, *name;
    xmlNsPtr ns;
    xmlNodePtr node;

    /* Make sure its a shared entry or the user's private one */
    if (*userid && strcmp(userid, arock->fctx->userid)) return 0;

    /* Split entry into namespace href and name ( <href>name ) */
    buf_setcstr(&arock->fctx->buf, entry + strlen(ANNOT_NS) + 1);
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

    /* Add the dead property to the response */
    node = xml_add_prop(HTTP_OK, arock->fctx->ns[NS_DAV],
			&arock->propstat[PROPSTAT_OK],
			BAD_CAST name, ns, NULL, 0);

    if (arock->fctx->mode == PROPFIND_ALL) {
	xmlAddChild(node, xmlNewCDataBlock(arock->fctx->root->doc,
					   BAD_CAST attrib->value,
					   attrib->size));
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
	void *rock = (entry->flags & PROP_NEEDPROP) ? prop : entry->rock;

	allowed = !entry->get(prop->name, NULL, fctx, NULL, NULL, rock);
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

    if (fctx->mode == PROPFIND_ALL || fctx->mode == PROPFIND_NAME) {
	xmlNsPtr nsDef;

	/* Add live properties for allprop/propname */
	for (entry = fctx->lprops; entry->name; entry++) {
	    if (entry->flags & PROP_ALLPROP) {
		/* Pre-screen request based on prop flags */
		int allowed = prescreen_prop(entry, NULL, fctx);

		if (allowed || fctx->mode == PROP_ALLPROP) {
		    struct propfind_entry_list *nentry =
			xzmalloc(sizeof(struct propfind_entry_list));

		    ensure_ns(fctx->ns, entry->ns, fctx->root,
			      known_namespaces[entry->ns].href,
			      known_namespaces[entry->ns].prefix);

		    nentry->name = BAD_CAST entry->name;
		    nentry->ns = fctx->ns[entry->ns];
		    if (allowed) {
			nentry->flags = entry->flags;
			nentry->get = entry->get;
			nentry->rock = entry->rock;
		    }
		    nentry->next = fctx->elist;
		    fctx->elist = nentry;
		}
	    }
	}

	/* Add all namespaces attached to the response to our hash table */
	construct_hash_table(fctx->ns_table, 10, 1);

	for (nsDef = fctx->root->nsDef; nsDef; nsDef = nsDef->next) {
	    hash_insert((const char *) nsDef->href, nsDef, fctx->ns_table);
	}
    }

    /* Iterate through requested properties */
    for (prop = proplist; !*fctx->ret && prop; prop = prop->next) {
	if (prop->type == XML_ELEMENT_NODE) {
	    struct propfind_entry_list *nentry;

	    /* Look for a match against our known properties */
	    for (entry = fctx->lprops;
		 entry->name && 
		     (strcmp((const char *) prop->name, entry->name) ||
		      strcmp((const char *) prop->ns->href,
			     known_namespaces[entry->ns].href));
		 entry++);

	    /* Skip properties already included by allprop */
	    if (fctx->mode == PROPFIND_ALL && (entry->flags & PROP_ALLPROP))
		continue;		

	    nentry = xzmalloc(sizeof(struct propfind_entry_list));
	    nentry->name = prop->name;
	    nentry->ns = prop->ns;
	    if (entry->name) {
		/* Found a match - Pre-screen request based on prop flags */
		if (prescreen_prop(entry, prop, fctx)) {
		    nentry->flags = entry->flags;
		    nentry->get = entry->get;
		    if (entry->flags & PROP_NEEDPROP)
			nentry->rock = prop;
		    else
			nentry->rock = entry->rock;
		}
		ret = *fctx->ret;
	    }
	    else {
		/* No match, treat as a dead property */
		nentry->flags = PROP_COLLECTION;
		nentry->get = propfind_fromdb;
		nentry->rock = NULL;
	    }
	    nentry->next = fctx->elist;
	    fctx->elist = nentry;
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
	    else if ((pctx->meth == METH_PROPPATCH) &&
		     !xmlStrcmp(instr->name, BAD_CAST "remove")) set = 0;
	    else {
		syslog(LOG_INFO, "Unknown PROPPATCH instruction");
		pctx->err->desc = "Unknown PROPPATCH instruction";
		return HTTP_BAD_REQUEST;
	    }

	    /* Find child element */
	    for (prop = instr->children;
		 prop && prop->type != XML_ELEMENT_NODE; prop = prop->next);
	    if (!prop || xmlStrcmp(prop->name, BAD_CAST "prop")) {
		pctx->err->desc = "Missing prop element";
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
		struct error_t error = { NULL, stat->precond, NULL, 0 };
		xml_add_error(stat->root, &error, pctx->ns);
	    }

	    xmlAddChild(pctx->root, stat->root);
	}
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
    txn->req_body.flags |= BODY_DECODE;
    r = read_body(httpd_in, txn->req_hdrs, &txn->req_body, &txn->error.desc);
    if (r) {
	txn->flags.conn = CONN_CLOSE;
	return r;
    }

    if (!buf_len(&txn->req_body.payload)) return 0;

    /* Check Content-Type */
    if (!(hdr = spool_getheader(txn->req_hdrs, "Content-Type")) ||
	(!is_mediatype("text/xml", hdr[0]) &&
	 !is_mediatype("application/xml", hdr[0]))) {
	txn->error.desc = "This method requires an XML body\r\n";
	return HTTP_BAD_MEDIATYPE;
    }

    /* Parse the XML request */
    ctxt = xmlNewParserCtxt();
    if (ctxt) {
	doc = xmlCtxtReadMemory(ctxt, buf_cstring(&txn->req_body.payload),
				buf_len(&txn->req_body.payload), NULL, NULL,
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
int meth_acl(struct transaction_t *txn, void *params)
{
    struct meth_params *aparams = (struct meth_params *) params;
    int ret = 0, r, rights;
    xmlDocPtr indoc = NULL;
    xmlNodePtr root, ace;
    char *server, *aclstr;
    struct mailbox *mailbox = NULL;
    struct buf acl = BUF_INITIALIZER;

    /* Response should not be cached */
    txn->flags.cc |= CC_NOCACHE;

    /* Parse the path */
    if ((r = aparams->parse_path(txn->req_uri->path,
				 &txn->req_tgt, &txn->error.desc))) return r;

    /* Make sure method is allowed (only allowed on collections) */
    if (!(txn->req_tgt.allow & ALLOW_WRITECOL)) {
	txn->error.desc = "ACLs can only be set on collections\r\n";
	syslog(LOG_DEBUG, "Tried to set ACL on non-collection");
	return HTTP_NOT_ALLOWED;
    }

    /* Locate the mailbox */
    if ((r = http_mlookup(txn->req_tgt.mboxname, &server, &aclstr, NULL))) {
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

	be = proxy_findserver(server, &http_protocol, proxy_userid,
			      &backend_cached, NULL, NULL, httpd_in);
	if (!be) return HTTP_UNAVAILABLE;

	return http_pipe_req_resp(be, txn);
    }

    /* Local Mailbox */

    /* Open mailbox for writing */
    if ((r = http_mailbox_open(txn->req_tgt.mboxname, &mailbox, LOCK_EXCLUSIVE))) {
	syslog(LOG_ERR, "http_mailbox_open(%s) failed: %s",
	       txn->req_tgt.mboxname, error_message(r));
	txn->error.desc = error_message(r);
	ret = HTTP_SERVER_ERROR;
	goto done;
    }

    /* Parse the ACL body */
    ret = parse_xml_body(txn, &root);
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

    /* Parse the DAV:ace elements */
    for (ace = root->children; ace; ace = ace->next) {
	if (ace->type == XML_ELEMENT_NODE) {
	    xmlNodePtr child = NULL, prin = NULL, privs = NULL;
	    const char *userid = NULL;
	    int deny = 0, rights = 0;
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
		userid = proxy_userid;
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
		xmlURIPtr uri;
		const char *errstr = NULL;
		size_t plen = strlen(namespace_principal.prefix);

		uri = parse_uri(METH_UNKNOWN, (const char *) href, 1, &errstr);
		if (uri &&
		    !strncmp(namespace_principal.prefix, uri->path, plen) &&
		    uri->path[plen] == '/') {
		    memset(&tgt, 0, sizeof(struct request_target_t));
		    tgt.namespace = URL_NS_PRINCIPAL;
		    r = prin_parse_path(uri->path, &tgt, &errstr);
		    if (!r && tgt.user) userid = tgt.user;
		}
		if (uri) xmlFreeURI(uri);
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

		    if (aparams->acl_ext &&
			aparams->acl_ext(txn, priv, &rights)) {
			/* Extension (CalDAV) privileges */
			if (txn->error.precond) {
			    ret = HTTP_FORBIDDEN;
			    goto done;
			}
		    }
		    else if (!xmlStrcmp(priv->ns->href,
					BAD_CAST XML_NS_DAV)) {
			/* WebDAV privileges */
			if (!xmlStrcmp(priv->name,
				       BAD_CAST "all"))
			    rights |= DACL_ALL;
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

    if ((r = mboxlist_sync_setacls(txn->req_tgt.mboxname, buf_cstring(&acl)))) {
	syslog(LOG_ERR, "mboxlist_sync_setacls(%s) failed: %s",
	       txn->req_tgt.mboxname, error_message(r));
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
 *   *DAV:need-privileges
 */
int meth_copy(struct transaction_t *txn, void *params)
{
    struct meth_params *cparams = (struct meth_params *) params;
    int ret = HTTP_CREATED, r, precond, rights, overwrite = OVERWRITE_YES;
    const char **hdr;
    xmlURIPtr dest_uri;
    struct request_target_t dest_tgt;  /* Parsed destination URL */
    char *server, *acl;
    struct backend *src_be = NULL, *dest_be = NULL;
    struct mailbox *src_mbox = NULL, *dest_mbox = NULL;
    struct dav_data *ddata;
    struct index_record src_rec;
    const char *etag = NULL;
    time_t lastmod = 0;
    unsigned flags = 0;

    /* Response should not be cached */
    txn->flags.cc |= CC_NOCACHE;

    /* Parse the source path */
    if ((r = cparams->parse_path(txn->req_uri->path,
				 &txn->req_tgt, &txn->error.desc))) return r;

    /* Make sure method is allowed (not allowed on collections yet) */
    if (!(txn->req_tgt.allow & ALLOW_WRITE)) return HTTP_NOT_ALLOWED;

    /* Check for mandatory Destination header */
    if (!(hdr = spool_getheader(txn->req_hdrs, "Destination"))) {
	txn->error.desc = "Missing Destination header\r\n";
	return HTTP_BAD_REQUEST;
    }

    /* Parse destination URI */
    if (!(dest_uri = parse_uri(METH_UNKNOWN, hdr[0], 1, &txn->error.desc))) {
	txn->error.desc = "Illegal Destination target URI";
	return HTTP_BAD_REQUEST;
    }

    /* Make sure source and dest resources are NOT the same */
    if (!strcmp(txn->req_uri->path, dest_uri->path)) {
	txn->error.desc = "Source and destination resources are the same\r\n";
	r = HTTP_FORBIDDEN;
    }

    /* Parse the destination path */
    if (!r) {
	r = cparams->parse_path(dest_uri->path, &dest_tgt, &txn->error.desc);
    }
    xmlFreeURI(dest_uri);

    if (r) return HTTP_FORBIDDEN;

    /* We don't yet handle COPY/MOVE on collections */
    if (!dest_tgt.resource) return HTTP_NOT_ALLOWED;

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
	src_be = proxy_findserver(server, &http_protocol, proxy_userid,
				  &backend_cached, NULL, NULL, httpd_in);
	if (!src_be) return HTTP_UNAVAILABLE;
    }

    /* Locate the destination mailbox */
    if ((r = http_mlookup(dest_tgt.mboxname, &server, &acl, NULL))) {
	syslog(LOG_ERR, "mlookup(%s) failed: %s",
	       dest_tgt.mboxname, error_message(r));
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
	txn->error.resource = dest_tgt.path;
	txn->error.rights =
	    !(rights & DACL_ADDRSRC) ? DACL_ADDRSRC : DACL_WRITECONT;
	return HTTP_FORBIDDEN;
    }

    if (server) {
	/* Remote destination mailbox */
	dest_be = proxy_findserver(server, &http_protocol, proxy_userid,
				   &backend_cached, NULL, NULL, httpd_in);
	if (!dest_be) return HTTP_UNAVAILABLE;
    }

    if (src_be) {
	/* Remote source mailbox */
	/* XXX  Currently only supports standard Murder */

	if (!dest_be) return HTTP_NOT_ALLOWED;

	/* Replace cached Destination header with just the absolute path */
	hdr = spool_getheader(txn->req_hdrs, "Destination");
	strcpy((char *) hdr[0], dest_tgt.path);

	if (src_be == dest_be) {
	    /* Simply send the COPY to the backend */
	    return http_pipe_req_resp(src_be, txn);
	}

	/* This is the harder case: GET from source and PUT on destination */
	return http_proxy_copy(src_be, dest_be, txn);
    }

    /* Local Mailbox */

    if (!*cparams->davdb.db) {
	syslog(LOG_ERR, "DAV database for user '%s' is not opened.  "
	       "Check 'configdirectory' permissions or "
	       "'proxyservers' option on backend server.", proxy_userid);
	txn->error.desc = "DAV database is not opened";
	return HTTP_SERVER_ERROR;
    }

    /* Open dest mailbox for reading */
    if ((r = mailbox_open_irl(dest_tgt.mboxname, &dest_mbox))) {
	syslog(LOG_ERR, "mailbox_open_irl(%s) failed: %s",
	       dest_tgt.mboxname, error_message(r));
	txn->error.desc = error_message(r);
	ret = HTTP_SERVER_ERROR;
	goto done;
    }

    /* Find message UID for the dest resource, if exists */
    cparams->davdb.lookup_resource(*cparams->davdb.db, dest_tgt.mboxname,
				   dest_tgt.resource, 0, (void **) &ddata);
    /* XXX  Check errors */

    /* Finished our initial read of dest mailbox */
    mailbox_unlock_index(dest_mbox, NULL);

    /* Check any preconditions on destination */
    if ((hdr = spool_getheader(txn->req_hdrs, "Overwrite")) &&
	!strcmp(hdr[0], "F")) {

	if (ddata->rowid) {
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
    cparams->davdb.lookup_resource(*cparams->davdb.db, txn->req_tgt.mboxname,
				   txn->req_tgt.resource, 0, (void **) &ddata);
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
	etag = NULL_ETAG;
	lastmod = ddata->creationdate;
    }

    /* Check any preconditions on source */
    precond = check_precond(txn, (void **) ddata, etag, lastmod);

    switch (precond) {
    case HTTP_OK:
	break;

    case HTTP_LOCKED:
	txn->error.precond = DAV_NEED_LOCK_TOKEN;
	txn->error.resource = txn->req_tgt.path;

    default:
	/* We failed a precondition - don't perform the request */
	ret = precond;
	goto done;
    }

    if (get_preferences(txn) & PREFER_REP) flags |= PREFER_REP;
    if ((txn->meth == METH_MOVE) && (dest_mbox == src_mbox))
	flags |= NO_DUP_CHECK;

    /* Parse, validate, and store the resource */
    ret = cparams->copy(txn, src_mbox, &src_rec, dest_mbox, dest_tgt.resource,
			overwrite, flags);

    /* For MOVE, we need to delete the source resource */
    if ((txn->meth == METH_MOVE) &&
	(ret == HTTP_CREATED || ret == HTTP_NO_CONTENT)) {
	/* Lock source mailbox */
	mailbox_lock_index(src_mbox, LOCK_EXCLUSIVE);

	/* Find message UID for the source resource */
	cparams->davdb.lookup_resource(*cparams->davdb.db, txn->req_tgt.mboxname,
				       txn->req_tgt.resource, 1, (void **) &ddata);
	/* XXX  Check errors */

	/* Fetch index record for the source resource */
	if (ddata->imap_uid &&
	    !mailbox_find_index_record(src_mbox, ddata->imap_uid, &src_rec)) {

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
	cparams->davdb.delete_resource(*cparams->davdb.db, ddata->rowid, 1);
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

    if (dest_mbox) mailbox_close(&dest_mbox);
    if (src_mbox) mailbox_unlock_index(src_mbox, NULL);

    return ret;
}


/* Perform a DELETE request */
int meth_delete(struct transaction_t *txn, void *params)
{
    struct meth_params *dparams = (struct meth_params *) params;
    int ret = HTTP_NO_CONTENT, r, precond, rights;
    char *server, *acl;
    struct mailbox *mailbox = NULL;
    struct dav_data *ddata;
    struct index_record record;
    const char *etag = NULL;
    time_t lastmod = 0;

    /* Response should not be cached */
    txn->flags.cc |= CC_NOCACHE;

    /* Parse the path */
    if ((r = dparams->parse_path(txn->req_uri->path,
				 &txn->req_tgt, &txn->error.desc))) return r;

    /* Make sure method is allowed */
    if (!(txn->req_tgt.allow & ALLOW_DELETE)) return HTTP_NOT_ALLOWED; 

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

	be = proxy_findserver(server, &http_protocol, proxy_userid,
			      &backend_cached, NULL, NULL, httpd_in);
	if (!be) return HTTP_UNAVAILABLE;

	return http_pipe_req_resp(be, txn);
    }

    /* Local Mailbox */

    if (!*dparams->davdb.db) {
	syslog(LOG_ERR, "DAV database for user '%s' is not opened.  "
	       "Check 'configdirectory' permissions or "
	       "'proxyservers' option on backend server.", proxy_userid);
	txn->error.desc = "DAV database is not opened";
	return HTTP_SERVER_ERROR;
    }

    if (!txn->req_tgt.resource) {
	/* DELETE collection */

	/* Do any special processing */
	if (dparams->delete) dparams->delete(txn, NULL, NULL, NULL);

	r = mboxlist_deletemailbox(txn->req_tgt.mboxname,
				   httpd_userisadmin || httpd_userisproxyadmin,
				   httpd_userid, httpd_authstate,
				   1, 0, 0);

	if (!r) dparams->davdb.delete_mbox(*dparams->davdb.db, txn->req_tgt.mboxname, 0);
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

    /* Find message UID for the resource, if exists */
    dparams->davdb.lookup_resource(*dparams->davdb.db, txn->req_tgt.mboxname,
				   txn->req_tgt.resource, 1, (void **) &ddata);
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
	etag = NULL_ETAG;
	lastmod = ddata->creationdate;
    }

    /* Check any preconditions */
    precond = dparams->check_precond(txn, (void *) ddata, etag, lastmod);

    switch (precond) {
    case HTTP_OK:
	break;

    case HTTP_LOCKED:
	txn->error.precond = DAV_NEED_LOCK_TOKEN;
	txn->error.resource = txn->req_tgt.path;

    default:
	/* We failed a precondition - don't perform the request */
	ret = precond;
	goto done;
    }

    if (record.uid) {
	/* Expunge the resource */
	record.system_flags |= FLAG_EXPUNGED;

	if ((r = mailbox_rewrite_index_record(mailbox, &record))) {
	    syslog(LOG_ERR, "expunging record (%s) failed: %s",
		   txn->req_tgt.mboxname, error_message(r));
	    txn->error.desc = error_message(r);
	    ret = HTTP_SERVER_ERROR;
	    goto done;
	}
    }

    /* Delete mapping entry for resource name */
    dparams->davdb.delete_resource(*dparams->davdb.db, ddata->rowid, 1);

    /* Do any special processing */
    if (dparams->delete) dparams->delete(txn, mailbox, &record, ddata);

  done:
    if (mailbox) mailbox_unlock_index(mailbox, NULL);

    return ret;
}


/* Perform a GET/HEAD request on a DAV resource */
int meth_get_dav(struct transaction_t *txn, void *params)
{
    struct meth_params *gparams = (struct meth_params *) params;
    const char **hdr;
    struct mime_type_t *mime;
    int ret = 0, r, precond, rights;
    const char *msg_base = NULL, *data = NULL;
    unsigned long msg_size = 0, datalen, offset;
    struct resp_body_t *resp_body = &txn->resp_body;
    char *server, *acl, *freeme = NULL;
    struct mailbox *mailbox = NULL;
    struct dav_data *ddata;
    struct index_record record;
    const char *etag = NULL;
    time_t lastmod = 0;

    /* Parse the path */
    if ((r = gparams->parse_path(txn->req_uri->path,
				 &txn->req_tgt, &txn->error.desc))) return r;

    /* We don't handle GET on a collection (yet) */
    if (!txn->req_tgt.resource) return HTTP_NO_CONTENT;

    /* Check requested MIME type:
       1st entry in gparams->mime_types array MUST be default MIME type */
    if ((hdr = spool_getheader(txn->req_hdrs, "Accept")))
	mime = get_accept_type(hdr, gparams->mime_types);
    else mime = gparams->mime_types;
    if (!mime) return HTTP_NOT_ACCEPTABLE;

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

    if (!*gparams->davdb.db) {
	syslog(LOG_ERR, "DAV database for user '%s' is not opened.  "
	       "Check 'configdirectory' permissions or "
	       "'proxyservers' option on backend server.", proxy_userid);
	txn->error.desc = "DAV database is not opened";
	return HTTP_SERVER_ERROR;
    }

    /* Open mailbox for reading */
    if ((r = http_mailbox_open(txn->req_tgt.mboxname, &mailbox, LOCK_SHARED))) {
	syslog(LOG_ERR, "http_mailbox_open(%s) failed: %s",
	       txn->req_tgt.mboxname, error_message(r));
	txn->error.desc = error_message(r);
	ret = HTTP_SERVER_ERROR;
	goto done;
    }

    /* Find message UID for the resource */
    gparams->davdb.lookup_resource(*gparams->davdb.db, txn->req_tgt.mboxname,
				   txn->req_tgt.resource, 0, (void **) &ddata);
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

	/* Resource length doesn't include RFC 5322 header */
	offset = record.header_size;
	datalen = record.size - offset;

	txn->flags.ranges = 1;
	etag = message_guid_encode(&record.guid);
	lastmod = record.internaldate;
    }
    else {
	/* Unmapped URL (empty resource) */
	offset = datalen = 0;
	txn->flags.ranges = 0;
	etag = NULL_ETAG;
	lastmod = ddata->creationdate;
    }

    /* Check any preconditions, including range request */
    precond = gparams->check_precond(txn, (void *) ddata, etag, lastmod);

    switch (precond) {
    case HTTP_OK:
    case HTTP_PARTIAL:
    case HTTP_NOT_MODIFIED:
	/* Fill in ETag, Last-Modified, Expires, and Cache-Control */
	resp_body->etag = etag;
	resp_body->lastmod = lastmod;
	resp_body->maxage = 3600;	/* 1 hr */
	txn->flags.cc |= CC_MAXAGE | CC_REVALIDATE;  /* don't use stale data */

	if (precond != HTTP_NOT_MODIFIED) break;

    default:
	/* We failed a precondition - don't perform the request */
	ret = precond;
	goto done;
    }

    if (record.uid) {
	txn->flags.vary |= VARY_ACCEPT;
	resp_body->type = mime->content_type;

	if (txn->meth == METH_GET) {
	    /* Load message containing the resource */
	    mailbox_map_message(mailbox, record.uid, &msg_base, &msg_size);

	    /* iCalendar data in response should not be transformed */
	    txn->flags.cc |= CC_NOTRANSFORM;

	    data = msg_base + offset;

	    if (mime != gparams->mime_types) {
		/* Not the storage format - convert into requested MIME type */
		void *obj = gparams->mime_types[0].from_string(data);

		data = freeme = mime->to_string(obj);
		datalen = strlen(data);
		gparams->mime_types[0].free(obj);
	    }
	}
    }

    write_body(precond, txn, data, datalen);

    if (msg_base)
	mailbox_unmap_message(mailbox, record.uid, &msg_base, &msg_size);
    if (freeme) free(freeme);

  done:
    if (mailbox) mailbox_unlock_index(mailbox, NULL);

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
    char *server, *acl;
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

    /* XXX  We ignore Depth and Timeout header fields */

    /* Response should not be cached */
    txn->flags.cc |= CC_NOCACHE;

    /* Parse the path */
    if ((r = lparams->parse_path(txn->req_uri->path,
				 &txn->req_tgt, &txn->error.desc))) return r;

    /* Make sure method is allowed (only allowed on resources) */
    if (!(txn->req_tgt.allow & ALLOW_WRITE)) return HTTP_NOT_ALLOWED; 

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

	be = proxy_findserver(server, &http_protocol, proxy_userid,
			      &backend_cached, NULL, NULL, httpd_in);
	if (!be) return HTTP_UNAVAILABLE;

	return http_pipe_req_resp(be, txn);
    }

    /* Local Mailbox */

    if (!*lparams->davdb.db) {
	syslog(LOG_ERR, "DAV database for user '%s' is not opened.  "
	       "Check 'configdirectory' permissions or "
	       "'proxyservers' option on backend server.", proxy_userid);
	txn->error.desc = "DAV database is not opened";
	return HTTP_SERVER_ERROR;
    }

    /* Open mailbox for reading */
    if ((r = http_mailbox_open(txn->req_tgt.mboxname, &mailbox, LOCK_SHARED))) {
	syslog(LOG_ERR, "http_mailbox_open(%s) failed: %s",
	       txn->req_tgt.mboxname, error_message(r));
	txn->error.desc = error_message(r);
	ret = HTTP_SERVER_ERROR;
	goto done;
    }

    /* Find message UID for the resource, if exists */
    lparams->davdb.lookup_resource(*lparams->davdb.db, txn->req_tgt.mboxname,
				   txn->req_tgt.resource, 1, (void *) &ddata);

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
    else if (ddata->rowid) {
	/* Unmapped URL (empty resource) */
	etag = NULL_ETAG;
	lastmod = ddata->creationdate;
    }
    else {
	/* New resource */
	etag = NULL;
	lastmod = 0;

	ddata->creationdate = now;
	ddata->mailbox = mailbox->name;
	ddata->resource = txn->req_tgt.resource;
    }

    /* Check any preconditions */
    precond = lparams->check_precond(txn, ddata, etag, lastmod);

    switch (precond) {
    case HTTP_OK:
	break;

    case HTTP_LOCKED:
	if (strcmp(ddata->lock_ownerid, httpd_userid))
	    txn->error.precond = DAV_LOCKED;
	else
	    txn->error.precond = DAV_NEED_LOCK_TOKEN;
	txn->error.resource = txn->req_tgt.path;

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
	ret = parse_xml_body(txn, &root);
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

    lparams->davdb.write_resource(*lparams->davdb.db, ddata, 1);

    txn->resp_body.lock = ddata->lock_token;

    if (!ddata->rowid) {
	ret = HTTP_CREATED;

	/* Tell client about the new resource */
	txn->resp_body.etag = NULL_ETAG;

	/* Tell client where to find the new resource */
	txn->location = txn->req_tgt.path;
    }
    else ret = HTTP_OK;

    xml_response(ret, txn, outdoc);
    ret = 0;

  done:
    if (mailbox) mailbox_unlock_index(mailbox, NULL);
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

    memset(&pctx, 0, sizeof(struct proppatch_ctx));

    /* Response should not be cached */
    txn->flags.cc |= CC_NOCACHE;

    /* Parse the path */
    if ((r = mparams->parse_path(txn->req_uri->path,
				 &txn->req_tgt, &txn->error.desc))) {
	txn->error.precond = CALDAV_LOCATION_OK;
	return HTTP_FORBIDDEN;
    }

    /* Make sure method is allowed (only allowed on home-set) */
    if (!(txn->req_tgt.allow & ALLOW_WRITECOL)) {
	txn->error.precond = CALDAV_LOCATION_OK;
	return HTTP_FORBIDDEN;
    }

    /* Check if we are allowed to create the mailbox */
    r = mboxlist_createmailboxcheck(txn->req_tgt.mboxname, 0, NULL,
				    httpd_userisadmin || httpd_userisproxyadmin,
				    httpd_userid, httpd_authstate,
				    NULL, &partition, 0);

    if (r == IMAP_PERMISSION_DENIED) return HTTP_FORBIDDEN;
    else if (r == IMAP_MAILBOX_EXISTS) {
	txn->error.precond = DAV_RSRC_EXISTS;
	return HTTP_FORBIDDEN;
    }
    else if (r) return HTTP_SERVER_ERROR;

    if (!config_partitiondir(partition)) {
	/* Invalid partition, assume its a server (remote mailbox) */
	char *server = partition, *p;
	struct backend *be;

	/* Trim remote partition */
	p = strchr(server, '!');
	if (p) *p++ = '\0';

	be = proxy_findserver(server, &http_protocol, proxy_userid,
			      &backend_cached, NULL, NULL, httpd_in);
	if (!be) return HTTP_UNAVAILABLE;

	return http_pipe_req_resp(be, txn);
    }

    /* Local Mailbox */

    /* Parse the MKCOL/MKCALENDAR body, if exists */
    ret = parse_xml_body(txn, &root);
    if (ret) goto done;

    if (root) {
	/* Check for correct root element */
	indoc = root->doc;

	if (txn->meth == METH_MKCOL)
	    r = xmlStrcmp(root->name, BAD_CAST "mkcol");
	else
	    r = xmlStrcmp(root->name, BAD_CAST mparams->mkcol.xml_req);
	if (r) {
	    txn->error.desc = "Incorrect root element in XML request\r\n";
	    return HTTP_BAD_MEDIATYPE;
	}

	instr = root->children;
    }

    if (instr) {
	/* Start construction of our mkcol/mkcalendar response */
	if (txn->meth == METH_MKCOL)
	    root = init_xml_response("mkcol-response", NS_DAV, root, ns);
	else
	    root = init_xml_response(mparams->mkcol.xml_resp,
				     mparams->mkcol.xml_ns, root, ns);
	if (!root) {
	    ret = HTTP_SERVER_ERROR;
	    txn->error.desc = "Unable to create XML response\r\n";
	    goto done;
	}

	outdoc = root->doc;

	/* Populate our proppatch context */
	pctx.req_tgt = &txn->req_tgt;
	pctx.meth = txn->meth;
	pctx.mailboxname = txn->req_tgt.mboxname;
	pctx.lprops = mparams->lprops;
	pctx.root = root;
	pctx.ns = ns;
	pctx.tid = NULL;
	pctx.err = &txn->error;
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
    r = mboxlist_createmailbox(txn->req_tgt.mboxname, mparams->mkcol.mbtype,
			       partition, 
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


/* dav_foreach() callback to find props on a resource */
int propfind_by_resource(void *rock, void *data)
{
    struct propfind_ctx *fctx = (struct propfind_ctx *) rock;
    struct dav_data *ddata = (struct dav_data *) data;
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
    strlcpy(p, ddata->resource, MAX_MAILBOX_PATH - len);
    fctx->req_tgt->resource = p;
    fctx->req_tgt->reslen = strlen(p);

    fctx->data = data;
    if (ddata->imap_uid && !fctx->record) {
	/* Fetch index record for the resource */
	r = mailbox_find_index_record(fctx->mailbox, ddata->imap_uid,
				      &record);
	/* XXX  Check errors */

	fctx->record = r ? NULL : &record;
    }

    if (!ddata->imap_uid || !fctx->record) {
	/* Add response for missing target */
	ret = xml_add_response(fctx, HTTP_NOT_FOUND);
    }
    else {
	int add_it = 1;

	if (fctx->filter) add_it = fctx->filter(fctx, data);

	if (add_it) {
	    /* Add response for target */
	    ret = xml_add_response(fctx, 0);
	}
    }

    if (fctx->msg_base) {
	mailbox_unmap_message(fctx->mailbox, ddata->imap_uid,
			      &fctx->msg_base, &fctx->msg_size);
    }
    fctx->msg_base = NULL;
    fctx->msg_size = 0;
    fctx->record = NULL;
    fctx->data = NULL;

    return ret;
}


/* mboxlist_findall() callback to find props on a collection */
int propfind_by_collection(char *mboxname, int matchlen,
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

    /* Check ACL on mailbox for current user */
    if ((r = mboxlist_lookup(mboxname, &mbentry, NULL))) {
	syslog(LOG_INFO, "mboxlist_lookup(%s) failed: %s",
	       mboxname, error_message(r));
	fctx->err->desc = error_message(r);
	*fctx->ret = HTTP_SERVER_ERROR;
	goto done;
    }

    rights = mbentry.acl ? cyrus_acl_myrights(httpd_authstate, mbentry.acl) : 0;
    if ((rights & fctx->reqd_privs) != fctx->reqd_privs) goto done;

    /* Open mailbox for reading */
    if ((r = mailbox_open_irl(mboxname, &mailbox))) {
	syslog(LOG_INFO, "mailbox_open_irl(%s) failed: %s",
	       mboxname, error_message(r));
	fctx->err->desc = error_message(r);
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
	if (!fctx->filter &&
	    (!root || (fctx->depth == 1) || !(fctx->prefer & PREFER_NOROOT)) &&
	    (r = xml_add_response(fctx, 0))) goto done;
    }

    if (fctx->depth > 1) {
	/* Resource(s) */

	if (fctx->req_tgt->resource) {
	    /* Add response for target resource */
	    void *data;

	    /* Find message UID for the resource */
	    fctx->lookup_resource(fctx->davdb,
				  mboxname, fctx->req_tgt->resource, 0, &data);
	    /* XXX  Check errors */

	    r = fctx->proc_by_resource(rock, data);
	}
	else {
	    /* Add responses for all contained resources */
	    fctx->foreach_resource(fctx->davdb, mboxname,
				   fctx->proc_by_resource, rock);

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
int meth_propfind(struct transaction_t *txn, void *params)
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
    struct propfind_entry_list *elist = NULL;

    memset(&fctx, 0, sizeof(struct propfind_ctx));

    /* Parse the path */
    if (fparams->parse_path &&
	(r = fparams->parse_path(txn->req_uri->path,
				 &txn->req_tgt, &txn->error.desc))) return r;

    /* Make sure method is allowed */
    if (!(txn->req_tgt.allow & ALLOW_DAV)) return HTTP_NOT_ALLOWED;

    /* Check Depth */
    hdr = spool_getheader(txn->req_hdrs, "Depth");
    if (!hdr || !strcmp(hdr[0], "infinity")) {
	depth = 2;
    }
    else if (hdr && ((sscanf(hdr[0], "%u", &depth) != 1) || (depth > 1))) {
	txn->error.desc = "Illegal Depth value\r\n";
	return HTTP_BAD_REQUEST;
    }

    if ((txn->req_tgt.namespace != URL_NS_PRINCIPAL) && txn->req_tgt.user) {
	char *server, *acl;
	int rights;

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
	    ret = HTTP_FORBIDDEN;
	    goto done;
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
	if (!*fparams->davdb.db) {
	    syslog(LOG_ERR, "DAV database for user '%s' is not opened.  "
		   "Check 'configdirectory' permissions or "
		   "'proxyservers' option on backend server.", proxy_userid);
	    txn->error.desc = "DAV database is not opened";
	    return HTTP_SERVER_ERROR;
	}
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
	/* Empty request */
	fctx.mode = PROPFIND_ALL;
    }
    else {
	indoc = root->doc;

	/* Make sure its a propfind element */
	if (xmlStrcmp(root->name, BAD_CAST "propfind")) {
	    txn->error.desc = "Missing propfind element in PROFIND request\r\n";
	    ret = HTTP_BAD_REQUEST;
	    goto done;
	}

	/* Find child element of propfind */
	for (cur = root->children;
	     cur && cur->type != XML_ELEMENT_NODE; cur = cur->next);

	/* Add propfind type to our header cache */
	spool_cache_header(xstrdup(":type"), xstrdup((const char *) cur->name),
			   txn->req_hdrs);

	/* Make sure its a known element */
	if (!cur) {
	    ret = HTTP_BAD_REQUEST;
	    goto done;
	}
	else if (!xmlStrcmp(cur->name, BAD_CAST "allprop")) {
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
    if (!(root = init_xml_response("multistatus", NS_DAV, root, ns))) {
	ret = HTTP_SERVER_ERROR;
	txn->error.desc = "Unable to create XML response\r\n";
	goto done;
    }

    outdoc = root->doc;

    /* Populate our propfind context */
    fctx.req_tgt = &txn->req_tgt;
    fctx.depth = depth;
    fctx.prefer |= get_preferences(txn);
    fctx.userid = proxy_userid;
    fctx.int_userid = httpd_userid;
    fctx.userisadmin = httpd_userisadmin;
    fctx.authstate = httpd_authstate;
    fctx.mailbox = NULL;
    fctx.record = NULL;
    fctx.reqd_privs = DACL_READ;
    fctx.filter = NULL;
    fctx.filter_crit = NULL;
    if (fparams->davdb.db) {
	fctx.davdb = *fparams->davdb.db;
	fctx.lookup_resource = fparams->davdb.lookup_resource;
	fctx.foreach_resource = fparams->davdb.foreach_resource;
    }
    fctx.proc_by_resource = &propfind_by_resource;
    fctx.elist = NULL;
    fctx.lprops = fparams->lprops;
    fctx.root = root;
    fctx.ns = ns;
    fctx.ns_table = &ns_table;
    fctx.err = &txn->error;
    fctx.ret = &ret;
    fctx.fetcheddata = 0;

    /* Parse the list of properties and build a list of callbacks */
    preload_proplist(props, &fctx);

    if (!txn->req_tgt.collection &&
	(!depth || !(fctx.prefer & PREFER_NOROOT))) {
	/* Add response for principal or home-set collection */
	struct mailbox *mailbox = NULL;

	if (*txn->req_tgt.mboxname) {
	    /* Open mailbox for reading */
	    if ((r = mailbox_open_irl(txn->req_tgt.mboxname, &mailbox))) {
		syslog(LOG_INFO, "mailbox_open_irl(%s) failed: %s",
		       txn->req_tgt.mboxname, error_message(r));
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

	if (txn->req_tgt.collection) {
	    /* Add response for target calendar collection */
	    propfind_by_collection(txn->req_tgt.mboxname, 0, 0, &fctx);
	}
	else {
	    /* Add responses for all contained calendar collections */
	    strlcat(txn->req_tgt.mboxname, ".%", sizeof(txn->req_tgt.mboxname));
	    r = mboxlist_findall(NULL,  /* internal namespace */
				 txn->req_tgt.mboxname, 1, httpd_userid, 
				 httpd_authstate, propfind_by_collection, &fctx);
	}

	ret = *fctx.ret;
    }

    /* Output the XML response */
    if (!ret) {
	/* iCalendar data in response should not be transformed */
	if (fctx.fetcheddata) txn->flags.cc |= CC_NOTRANSFORM;

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
int meth_proppatch(struct transaction_t *txn,  void *params)
{
    struct meth_params *pparams = (struct meth_params *) params;
    int ret = 0, r = 0, rights;
    xmlDocPtr indoc = NULL, outdoc = NULL;
    xmlNodePtr root, instr, resp;
    xmlNsPtr ns[NUM_NAMESPACE];
    char *server, *acl;
    struct proppatch_ctx pctx;

    memset(&pctx, 0, sizeof(struct proppatch_ctx));

    /* Response should not be cached */
    txn->flags.cc |= CC_NOCACHE;

    /* Parse the path */
    if ((r = pparams->parse_path(txn->req_uri->path,
				 &txn->req_tgt, &txn->error.desc))) return r;

    /* Make sure method is allowed (only allowed on collections) */
    if (!(txn->req_tgt.allow & ALLOW_WRITECOL))  {
	txn->error.desc =
	    "Properties can only be updated on collections\r\n";
	return HTTP_NOT_ALLOWED;
    }

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

	be = proxy_findserver(server, &http_protocol, proxy_userid,
			      &backend_cached, NULL, NULL, httpd_in);
	if (!be) return HTTP_UNAVAILABLE;

	return http_pipe_req_resp(be, txn);
    }

    /* Local Mailbox */

    /* Parse the PROPPATCH body */
    ret = parse_xml_body(txn, &root);
    if (!ret && !root) {
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
    pctx.mailboxname = txn->req_tgt.mboxname;
    pctx.lprops = pparams->lprops;
    pctx.root = resp;
    pctx.ns = ns;
    pctx.tid = NULL;
    pctx.err = &txn->error;
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
	if (get_preferences(txn) & PREFER_MIN) ret = HTTP_OK;
	else xml_response(HTTP_MULTI_STATUS, txn, outdoc);
    }

  done:
    buf_free(&pctx.buf);

    if (outdoc) xmlFreeDoc(outdoc);
    if (indoc) xmlFreeDoc(indoc);

    return ret;
}


/* Perform a POST request */
int meth_post(struct transaction_t *txn, void *params)
{
    struct meth_params *pparams = (struct meth_params *) params;
    static unsigned post_count = 0;
    int r, ret;
    size_t len;

    /* Response should not be cached */
    txn->flags.cc |= CC_NOCACHE;

    /* Parse the path */
    if ((r = pparams->parse_path(txn->req_uri->path,
				 &txn->req_tgt, &txn->error.desc))) return r;

    /* Make sure method is allowed (only allowed on certain collections) */
    if (!(txn->req_tgt.allow & ALLOW_POST)) return HTTP_NOT_ALLOWED; 

    /* Do any special processing */
    if (pparams->post) {
	ret = pparams->post(txn);
	if (ret != HTTP_CONTINUE) return ret;
    }

    /* POST to regular collection */

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
    char *server, *acl;
    struct mailbox *mailbox = NULL;
    struct dav_data *ddata;
    struct index_record oldrecord;
    time_t lastmod;
    uquota_t size = 0;
    unsigned flags = 0;

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

    /* Make sure Content-Range isn't specified */
    if (spool_getheader(txn->req_hdrs, "Content-Range"))
	return HTTP_BAD_REQUEST;

    /* Check Content-Type */
    if ((hdr = spool_getheader(txn->req_hdrs, "Content-Type"))) {
	for (mime = pparams->mime_types; mime->content_type; mime++) {
	    if (is_mediatype(mime->content_type, hdr[0])) break;
	}
    }
    if (!mime || !mime->content_type) {
	txn->error.precond = pparams->put.supp_data_precond;
	return HTTP_FORBIDDEN;
    }

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

	be = proxy_findserver(server, &http_protocol, proxy_userid,
			      &backend_cached, NULL, NULL, httpd_in);
	if (!be) return HTTP_UNAVAILABLE;

	return http_pipe_req_resp(be, txn);
    }

    /* Local Mailbox */

    if (!*pparams->davdb.db) {
	syslog(LOG_ERR, "DAV database for user '%s' is not opened.  "
	       "Check 'configdirectory' permissions or "
	       "'proxyservers' option on backend server.", proxy_userid);
	txn->error.desc = "DAV database is not opened";
	return HTTP_SERVER_ERROR;
    }

    /* Open mailbox for reading */
    if ((r = http_mailbox_open(txn->req_tgt.mboxname, &mailbox, LOCK_SHARED))) {
	syslog(LOG_ERR, "http_mailbox_open(%s) failed: %s",
	       txn->req_tgt.mboxname, error_message(r));
	txn->error.desc = error_message(r);
	ret = HTTP_SERVER_ERROR;
	goto done;
    }

    /* Find message UID for the resource, if exists */
    pparams->davdb.lookup_resource(*pparams->davdb.db, txn->req_tgt.mboxname,
				   txn->req_tgt.resource, 0, (void *) &ddata);
    /* XXX  Check errors */

    if (ddata->imap_uid) {
	/* Overwriting existing resource */

	/* Fetch index record for the resource */
	r = mailbox_find_index_record(mailbox, ddata->imap_uid, &oldrecord);
	if (r) {
	    syslog(LOG_ERR, "mailbox_find_index_record(%s, %u) failed: %s",
		   txn->req_tgt.mboxname, ddata->imap_uid, error_message(r));
	    txn->error.desc = error_message(r);
	    ret = HTTP_SERVER_ERROR;
	    goto done;
	}

	etag = message_guid_encode(&oldrecord.guid);
	lastmod = oldrecord.internaldate;
    }
    else if (ddata->rowid) {
	/* Unmapped URL (empty resource) */
	etag = NULL_ETAG;
	lastmod = ddata->creationdate;
    }
    else {
	/* New resource */
	etag = NULL;
	lastmod = 0;
    }

    /* Finished our initial read */
    mailbox_unlock_index(mailbox, NULL);

    /* Check any preconditions */
    precond = pparams->check_precond(txn, ddata, etag, lastmod);

    switch (precond) {
    case HTTP_OK:
	break;

    case HTTP_LOCKED:
	txn->error.precond = DAV_NEED_LOCK_TOKEN;
	txn->error.resource = txn->req_tgt.path;

    default:
	/* We failed a precondition - don't perform the request */
	ret = precond;
	goto done;
    }

    /* Read body */
    txn->req_body.flags |= BODY_DECODE;
    ret = read_body(httpd_in, txn->req_hdrs, &txn->req_body, &txn->error.desc);
    if (ret) {
	txn->flags.conn = CONN_CLOSE;
	goto done;
    }

    /* Make sure we have a body */
    size = buf_len(&txn->req_body.payload);
    if (!size) {
	txn->error.desc = "Missing request body\r\n";
	ret = HTTP_BAD_REQUEST;
	goto done;
    }

    /* Check if we can append a new message to mailbox */
    if ((r = append_check(txn->req_tgt.mboxname,
			  httpd_authstate, ACL_INSERT, size))) {
	syslog(LOG_ERR, "append_check(%s) failed: %s",
	       txn->req_tgt.mboxname, error_message(r));
	txn->error.desc = error_message(r);
	ret = HTTP_SERVER_ERROR;
	goto done;
    }

    if (get_preferences(txn) & PREFER_REP) flags |= PREFER_REP;

    /* Parse, validate, and store the resource */
    ret = pparams->put.proc(txn, mime, mailbox, flags);

  done:
    if (mailbox) mailbox_unlock_index(mailbox, NULL);

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


int report_sync_col(struct transaction_t *txn,
		    xmlNodePtr inroot, struct propfind_ctx *fctx)
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
    if ((r = http_mailbox_open(txn->req_tgt.mboxname, &mailbox, LOCK_SHARED))) {
	syslog(LOG_ERR, "http_mailbox_open(%s) failed: %s",
	       txn->req_tgt.mboxname, error_message(r));
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
	xmlChar *str = NULL;
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
		    txn->error.precond = DAV_SYNC_TOKEN;
		    ret = HTTP_FORBIDDEN;
		}
	    }
	    else if (!xmlStrcmp(node->name, BAD_CAST "sync-level") &&
		(str = xmlNodeListGetString(inroot->doc, node->children, 1))) {
		if (!strcmp((char *) str, "infinity")) {
		    fctx->err->desc =
			"This server DOES NOT support infinite depth requests";
		    ret = HTTP_SERVER_ERROR;
		}
		else if ((sscanf((char *) str, "%u", &fctx->depth) != 1) ||
			 (fctx->depth != 1)) {
		    fctx->err->desc = "Illegal sync-level";
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
	fctx->err->desc = "Illegal sync-level";
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
	    fctx->err->desc = "Unable to truncate results";
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
	struct dav_data ddata;

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

	memset(&ddata, 0, sizeof(struct dav_data));
	ddata.resource = resource;

	if (record->system_flags & FLAG_EXPUNGED) {
	    /* report as NOT FOUND
	       IMAP UID of 0 will cause index record to be ignored
	       propfind_by_resource() will append our resource name */
	    propfind_by_resource(fctx, &ddata);
	}
	else {
	    fctx->record = record;
	    ddata.imap_uid = record->uid;
	    propfind_by_resource(fctx, &ddata);
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

    /* Normalize depth so that:
     * 0 = home-set collection, 1+ = calendar collection, 2+ = calendar resource
     */
    if (txn->req_tgt.collection) depth++;
    if (txn->req_tgt.resource) depth++;

    /* Parse the REPORT body */
    ret = parse_xml_body(txn, &inroot);
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

    if (report->flags & REPORT_NEED_MBOX) {
	char *server, *acl;
	int rights;

	/* Locate the mailbox */
	if ((r = http_mlookup(txn->req_tgt.mboxname, &server, &acl, NULL))) {
	    syslog(LOG_ERR, "mlookup(%s) failed: %s",
		   txn->req_tgt.mboxname, error_message(r));
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

	    be = proxy_findserver(server, &http_protocol, proxy_userid,
				  &backend_cached, NULL, NULL, httpd_in);
	    if (!be) ret = HTTP_UNAVAILABLE;
	    else ret = http_pipe_req_resp(be, txn);
	    goto done;
	}

	/* Local Mailbox */
	if (!*rparams->davdb.db) {
	    syslog(LOG_ERR, "DAV database for user '%s' is not opened.  "
		   "Check 'configdirectory' permissions or "
		   "'proxyservers' option on backend server.", proxy_userid);
	    txn->error.desc = "DAV database is not opened";
	    return HTTP_SERVER_ERROR;
	}
    }

    /* Principal or Local Mailbox */

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
    fctx.prefer |= get_preferences(txn);
    fctx.userid = proxy_userid;
    fctx.int_userid = httpd_userid;
    fctx.userisadmin = httpd_userisadmin;
    fctx.authstate = httpd_authstate;
    fctx.mailbox = NULL;
    fctx.record = NULL;
    fctx.reqd_privs = report->reqd_privs;
    fctx.elist = NULL;
    fctx.lprops = rparams->lprops;
    fctx.root = outroot;
    fctx.ns = ns;
    fctx.ns_table = &ns_table;
    fctx.err = &txn->error;
    fctx.ret = &ret;
    fctx.fetcheddata = 0;

    /* Parse the list of properties and build a list of callbacks */
    if (fctx.mode) ret = preload_proplist(props, &fctx);

    /* Process the requested report */
    if (!ret) ret = (*report->proc)(txn, inroot, &fctx);

    /* Output the XML response */
    if (!ret && outroot) {
	/* iCalendar data in response should not be transformed */
	if (fctx.fetcheddata) txn->flags.cc |= CC_NOTRANSFORM;

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
    int ret = HTTP_NO_CONTENT, r, precond, rights;
    const char **hdr, *token;
    char *server, *acl;
    struct mailbox *mailbox = NULL;
    struct dav_data *ddata;
    struct index_record record;
    const char *etag;
    time_t lastmod;
    size_t len;

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

    if (server) {
	/* Remote mailbox */
	struct backend *be;

	be = proxy_findserver(server, &http_protocol, proxy_userid,
			      &backend_cached, NULL, NULL, httpd_in);
	if (!be) return HTTP_UNAVAILABLE;

	return http_pipe_req_resp(be, txn);
    }

    /* Local Mailbox */

    if (!*lparams->davdb.db) {
	syslog(LOG_ERR, "DAV database for user '%s' is not opened.  "
	       "Check 'configdirectory' permissions or "
	       "'proxyservers' option on backend server.", proxy_userid);
	txn->error.desc = "DAV database is not opened";
	return HTTP_SERVER_ERROR;
    }

    /* Open mailbox for reading */
    if ((r = http_mailbox_open(txn->req_tgt.mboxname, &mailbox, LOCK_SHARED))) {
	syslog(LOG_ERR, "http_mailbox_open(%s) failed: %s",
	       txn->req_tgt.mboxname, error_message(r));
	txn->error.desc = error_message(r);
	ret = HTTP_SERVER_ERROR;
	goto done;
    }

    /* Find message UID for the resource, if exists */
    lparams->davdb.lookup_resource(*lparams->davdb.db, txn->req_tgt.mboxname,
				   txn->req_tgt.resource, 1, (void **) &ddata);
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
	rights =  acl ? cyrus_acl_myrights(httpd_authstate, acl) : 0;
	if (!(rights & DACL_ADMIN)) {
	    /* DAV:need-privileges */
	    txn->error.precond = DAV_NEED_PRIVS;
	    txn->error.resource = txn->req_tgt.path;
	    txn->error.rights = DACL_ADMIN;
	    ret = HTTP_FORBIDDEN;
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
	etag = NULL_ETAG;
	lastmod = ddata->creationdate;
    }

    /* Check any preconditions */
    precond = lparams->check_precond(txn, ddata, etag, lastmod);

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

	lparams->davdb.write_resource(*lparams->davdb.db, ddata, 1);
    }
    else {
	/* Unmapped URL - Treat as lock-null and delete mapping entry */
	lparams->davdb.delete_resource(lparams->davdb.db, ddata->rowid, 1);
    }

  done:
    if (mailbox) mailbox_unlock_index(mailbox, NULL);

    return ret;
}
