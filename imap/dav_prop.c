/* dav_prop.c -- Routines for dealing with DAV properties in httpd
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

#include "dav_prop.h"
#include "annotate.h"
#include "acl.h"
#include "caldav_db.h"
#include "global.h"
#include "http_err.h"
#include "xmalloc.h"
#include "xstrlcpy.h"
#include "xstrlcat.h"

#define SCHED_INBOX	"Inbox/"
#define SCHED_OUTBOX	"Outbox/"


/* Ensure that we have a given namespace.  If it doesn't exist in what we
 * parsed in the request, create it and attach to 'node'.
 */
static int ensure_ns(xmlNsPtr *respNs, int ns, xmlNodePtr node,
		     const char *url, const char *prefix)
{
    if (!respNs[ns])
	respNs[ns] = xmlNewNs(node, BAD_CAST url, BAD_CAST prefix);

    /* XXX  check for errors */
    return 0;
}


/* Initialize an XML tree for a property response */
xmlNodePtr init_xml_response(const char *resp,
			     xmlNsPtr reqNs, xmlNsPtr *respNs)
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
    for (; reqNs; reqNs = reqNs->next) {
	if (!xmlStrcmp(reqNs->href, BAD_CAST XML_NS_DAV))
	    respNs[NS_DAV] = xmlNewNs(root, reqNs->href, reqNs->prefix);
	else if (!xmlStrcmp(reqNs->href, BAD_CAST XML_NS_CAL))
	    respNs[NS_CAL] = xmlNewNs(root, reqNs->href, reqNs->prefix);
	else if (!xmlStrcmp(reqNs->href, BAD_CAST XML_NS_CS))
	    respNs[NS_CS] = xmlNewNs(root, reqNs->href, reqNs->prefix);
	else if (!xmlStrcmp(reqNs->href, BAD_CAST XML_NS_APPLE))
	    respNs[NS_APPLE] = xmlNewNs(root, reqNs->href, reqNs->prefix);
	else if (!xmlStrcmp(reqNs->href, BAD_CAST XML_NS_CYRUS))
	    respNs[NS_CYRUS] = xmlNewNs(root, reqNs->href, reqNs->prefix);
	else
	    xmlNewNs(root, reqNs->href, reqNs->prefix);
    }

    /* Set namespace of root node */
    ensure_ns(respNs, NS_DAV, root, XML_NS_DAV, "D");
    xmlSetNs(root, respNs[NS_DAV]);

    return root;
}

xmlNodePtr xml_add_error(xmlNodePtr root, const struct precond *precond,
			 xmlNsPtr *avail_ns)
{
    xmlNsPtr ns[NUM_NAMESPACE];
    xmlNodePtr error;

    if (!root) {
	error = root = init_xml_response("error", NULL, ns);
	avail_ns = ns;
    }
    else error = xmlNewChild(root, NULL, BAD_CAST "error", NULL);

    xmlNewChild(error, avail_ns[precond->ns], BAD_CAST precond->name, NULL);

    return root;
}


/* Add a property 'name', of namespace 'ns', with content 'content',
 * and status code/string 'status' to propstat element 'stat'.
 * 'stat' will be created as necessary.
 */
static xmlNodePtr xml_add_prop(long status, xmlNodePtr resp,
			       struct propstat propstat[],
			       xmlNsPtr prop_ns, const xmlChar *prop_name,
			       xmlChar *content,
			       const struct precond *precond)
{
    xmlNodePtr prop;

    if (!propstat->prop) {
	xmlNodePtr stat = xmlNewChild(resp, NULL, BAD_CAST "propstat", NULL);
	propstat->prop = xmlNewChild(stat, NULL, BAD_CAST "prop", NULL);
    }

    prop = xmlNewTextChild(propstat->prop, prop_ns, prop_name, content);
    propstat->status = status;
    propstat->precond = precond;

    return prop;
}


/* Add a response tree to 'root' for the specified href and 
   either error code or property list */
int xml_add_response(struct propfind_ctx *fctx, long code)
{
    xmlNodePtr resp;
    struct propstat propstat[NUM_PROPSTAT];
    struct propfind_entry_list *e;
    int i;

    memset(propstat, 0, NUM_PROPSTAT * sizeof(struct propstat));

    resp = xmlNewChild(fctx->root, NULL, BAD_CAST "response", NULL);
    if (!resp) {
	*fctx->errstr = "Unable to add response XML element";
	*fctx->ret = HTTP_SERVER_ERROR;
	return HTTP_SERVER_ERROR;
    }
    xmlNewChild(resp, NULL, BAD_CAST "href", BAD_CAST fctx->req_tgt->path);

    if (code) {
	xmlNewChild(resp, NULL, BAD_CAST "status",
		    BAD_CAST http_statusline(code));
    }
    else {
	/* Process each property in the linked list */
	for (e = fctx->elist; e; e = e->next) {
	    if (e->get) {
		e->get(e->name, e->ns, fctx, resp, propstat, e->rock);
	    }
	    else {
		xml_add_prop(HTTP_NOT_FOUND, resp, &propstat[PROPSTAT_NOTFOUND],
			     e->ns, e->name, NULL, NULL);
	    }
	}
    }

    /* Add status and optional error to the propstat elements */
    for (i = 0; i < NUM_PROPSTAT; i++) {
	struct propstat *stat = &propstat[i];

	if (stat->prop) {
	    xmlNewChild(stat->prop->parent, NULL, BAD_CAST "status",
			BAD_CAST http_statusline(stat->status));
	    if (stat->precond) {
		xml_add_error(stat->prop->parent, stat->precond, fctx->ns);
	    }
	}
    }

    fctx->record = NULL;

    return 0;
}


/* caldav_foreach() callback to find props on a resource */
int find_resource_props(void *rock, const char *resource, uint32_t uid)
{
    struct propfind_ctx *fctx = (struct propfind_ctx *) rock;
    struct index_record record;
    char *p;
    size_t len;
    int r;

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

    /* Add response for target */
    return xml_add_response(fctx, (!uid || !fctx->record) ? HTTP_NOT_FOUND : 0);
}

/* mboxlist_findall() callback to find props on a collection */
int find_collection_props(char *mboxname,
			  int matchlen __attribute__((unused)),
			  int maycreate __attribute__((unused)),
			  void *rock)
{
    struct propfind_ctx *fctx = (struct propfind_ctx *) rock;
    struct mailbox *mailbox = NULL;
    struct caldav_db *caldavdb = NULL;
    char *p;
    size_t len;
    int r = 0;

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
    fctx->req_tgt->resource = NULL;
    fctx->req_tgt->reslen = 0;

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

    /* Add response for target collection */
    fctx->mailbox = mailbox;
    fctx->record = NULL;
    if ((r = xml_add_response(fctx, 0))) goto done;

    if (fctx->depth > 1) {
	/* Resource(s) */

	if (fctx->req_tgt->resource) {
	    /* Add response for target resource */
	    uint32_t uid;

	    /* Find message UID for the resource */
	    caldav_read(caldavdb, fctx->req_tgt->resource, &uid);
	    /* XXX  Check errors */

	    r = find_resource_props(rock, fctx->req_tgt->resource, uid);
	}
	else {
	    /* Add responses for all contained resources */
	    caldav_foreach(caldavdb, find_resource_props, rock);
	}
    }

  done:
    if (caldavdb) caldav_close(caldavdb);
    if (mailbox) mailbox_close(&mailbox);

    return r;
}


/* Callback to fetch DAV:add-member */
static int propfind_addmember(const xmlChar *propname, xmlNsPtr ns,
			      struct propfind_ctx *fctx, xmlNodePtr resp,
			      struct propstat propstat[],
			      void *rock __attribute__((unused)))
{
    if (fctx->req_tgt->collection) {
	xmlNodePtr node;
	size_t len;
	char uri[MAX_MAILBOX_PATH+1];

	node = xml_add_prop(HTTP_OK, resp, &propstat[PROPSTAT_OK],
			    ns, BAD_CAST propname, NULL, NULL);

	len = fctx->req_tgt->resource ?
	    (size_t) (fctx->req_tgt->resource - fctx->req_tgt->path) :
	    strlen(fctx->req_tgt->path);
	snprintf(uri, sizeof(uri), "%.*s", len, fctx->req_tgt->path);
	xmlNewChild(node, NULL, BAD_CAST "href", BAD_CAST uri);
    }
    else {
	xml_add_prop(HTTP_NOT_FOUND, resp, &propstat[PROPSTAT_NOTFOUND],
		     ns, BAD_CAST propname, NULL, NULL);
    }

    return 0;
}


/* Callback to fetch DAV:getetag */
static int propfind_getetag(const xmlChar *propname, xmlNsPtr ns,
			    struct propfind_ctx *fctx, xmlNodePtr resp,
			    struct propstat propstat[],
			    void *rock __attribute__((unused)))
{
    if (fctx->record) {
	char etag[2*MESSAGE_GUID_SIZE+3];

	/* add DQUOTEs */
	sprintf(etag, "\"%s\"", message_guid_encode(&fctx->record->guid));

	xml_add_prop(HTTP_OK, resp, &propstat[PROPSTAT_OK],
		     ns, BAD_CAST propname, BAD_CAST etag, NULL);
    }
    else {
	xml_add_prop(HTTP_NOT_FOUND, resp, &propstat[PROPSTAT_NOTFOUND],
		     ns, BAD_CAST propname, NULL, NULL);
    }

    return 0;
}


/* Callback to fetch DAV:resourcetype */
static int propfind_restype(const xmlChar *propname, xmlNsPtr ns,
			    struct propfind_ctx *fctx, xmlNodePtr resp,
			    struct propstat propstat[],
			    void *rock __attribute__((unused)))
{
    xmlNodePtr node = xml_add_prop(HTTP_OK, resp, &propstat[PROPSTAT_OK],
				   ns, BAD_CAST propname, NULL, NULL);

    if ((fctx->req_tgt->namespace != URL_NS_DEFAULT) && !fctx->record) {
	xmlNewChild(node, NULL, BAD_CAST "collection", NULL);

	switch (fctx->req_tgt->namespace) {
	case URL_NS_PRINCIPAL:
	    if (fctx->req_tgt->user)
		xmlNewChild(node, NULL, BAD_CAST "principal", NULL);
	    break;

	case URL_NS_CALENDAR:
	    if (fctx->mailbox) {
		ensure_ns(fctx->ns, NS_CAL, resp->parent, XML_NS_CAL, "C");
		xmlNewChild(node, fctx->ns[NS_CAL], BAD_CAST "calendar", NULL);
		if (!strcmp(fctx->req_tgt->collection, SCHED_INBOX)) {
		    xmlNewChild(node, fctx->ns[NS_CAL],
				BAD_CAST "schedule-inbox", NULL);
		}
		else if (!strcmp(fctx->req_tgt->collection, SCHED_OUTBOX)) {
		    xmlNewChild(node, fctx->ns[NS_CAL],
				BAD_CAST "schedule-outbox", NULL);
		}
	    }
	    break;

	case URL_NS_ADDRESSBOOK:
	    if (fctx->mailbox) {
		ensure_ns(fctx->ns, NS_CAL, resp->parent, XML_NS_CAL, "C");
		xmlNewChild(node, fctx->ns[NS_CAL], BAD_CAST "addressbook", NULL);
	    }
	    break;
	}
    }

    return 0;
}


/* Callback to "write" resourcetype property */
static int proppatch_restype(xmlNodePtr prop, unsigned set,
			     xmlNsPtr ns, struct proppatch_ctx *pctx,
			     struct propstat propstat[],
			     void *rock __attribute__((unused)))
{
    if (set && pctx->meth[0] == 'M') {
	/* "Writeable" for MKCOL/MKCALENDAR only */
	xmlNodePtr cur;

	for (cur = prop->children; cur; cur = cur->next) {
	    if (cur->type != XML_ELEMENT_NODE) continue;
	    /* Make sure we have valid resourcetypes for the collection */
	    if (xmlStrcmp(cur->name, BAD_CAST "collection") &&
		(xmlStrcmp(cur->name, BAD_CAST "calendar") ||
		 (pctx->req_tgt->namespace != URL_NS_CALENDAR))) break;
	}

	if (!cur) {
	    /* All resourcetypes are valid */
	    xml_add_prop(HTTP_OK, pctx->root, &propstat[PROPSTAT_OK],
			 ns, prop->name, NULL, NULL);

	    return 0;
	}
    }

    /* Protected property / Invalid resourcetype */
    xml_add_prop(HTTP_FORBIDDEN, pctx->root, &propstat[PROPSTAT_FORBID],
		 ns, prop->name, NULL,
		 (set && pctx->meth[0] == 'M') ? &preconds[DAV_VALID_RESTYPE] :
		 &preconds[DAV_PROT_PROP]);
	     
    *pctx->ret = HTTP_FORBIDDEN;

    return 0;
}


/* Callback to fetch DAV:sync-token and CS:getctag */
static int propfind_sync_token(const xmlChar *propname, xmlNsPtr ns,
			       struct propfind_ctx *fctx, xmlNodePtr resp,
			       struct propstat propstat[],
			       void *rock __attribute__((unused)))
{
    if (fctx->mailbox && !fctx->record) {
	char sync[MAX_MAILBOX_PATH+1];

	snprintf(sync, MAX_MAILBOX_PATH, XML_NS_CYRUS "sync/" MODSEQ_FMT,
		 fctx->mailbox->i.highestmodseq);

	xml_add_prop(HTTP_OK, resp, &propstat[PROPSTAT_OK],
		     ns, BAD_CAST propname, BAD_CAST sync, NULL);
    }
    else {
	xml_add_prop(HTTP_NOT_FOUND, resp, &propstat[PROPSTAT_NOTFOUND],
		     ns, BAD_CAST propname, NULL, NULL);
    }

    return 0;
}


/* Callback to fetch DAV:supported-report-set */
static int propfind_reportset(const xmlChar *propname, xmlNsPtr ns,
			      struct propfind_ctx *fctx, xmlNodePtr resp,
			      struct propstat propstat[],
			      void *rock __attribute__((unused)))
{
    xmlNodePtr s, r, top = xml_add_prop(HTTP_OK, resp, &propstat[PROPSTAT_OK],
					ns, BAD_CAST propname, NULL, NULL);

    if ((fctx->req_tgt->namespace == URL_NS_CALENDAR ||
	 fctx->req_tgt->namespace == URL_NS_ADDRESSBOOK) &&
	!fctx->req_tgt->resource) {
	s = xmlNewChild(top, NULL, BAD_CAST "supported-report", NULL);
	r = xmlNewChild(s, NULL, BAD_CAST "report", NULL);
	ensure_ns(fctx->ns, NS_DAV, resp->parent, XML_NS_DAV, "D");
	xmlNewChild(r, fctx->ns[NS_DAV], BAD_CAST "sync-collection", NULL);
    }

    if (fctx->req_tgt->namespace == URL_NS_CALENDAR) {
	s = xmlNewChild(top, NULL, BAD_CAST "supported-report", NULL);
	r = xmlNewChild(s, NULL, BAD_CAST "report", NULL);
	ensure_ns(fctx->ns, NS_CAL, resp->parent, XML_NS_CAL, "C");
	xmlNewChild(r, fctx->ns[NS_CAL], BAD_CAST "calendar-query", NULL);

	s = xmlNewChild(top, NULL, BAD_CAST "supported-report", NULL);
	r = xmlNewChild(s, NULL, BAD_CAST "report", NULL);
	ensure_ns(fctx->ns, NS_CAL, resp->parent, XML_NS_CAL, "C");
	xmlNewChild(r, fctx->ns[NS_CAL], BAD_CAST "calendar-multiget", NULL);
    }

    return 0;
}


/* Callback to fetch DAV:principalurl */
static int propfind_principalurl(const xmlChar *propname, xmlNsPtr ns,
				 struct propfind_ctx *fctx, xmlNodePtr resp,
				 struct propstat propstat[],
				 void *rock __attribute__((unused)))
{
    xmlNodePtr node;
    char uri[MAX_MAILBOX_PATH+1] = "";

    if (fctx->req_tgt->namespace != URL_NS_PRINCIPAL) {
	xml_add_prop(HTTP_NOT_FOUND, resp, &propstat[PROPSTAT_NOTFOUND],
		     ns, BAD_CAST propname, NULL, NULL);
    }
    else {
	node = xml_add_prop(HTTP_OK, resp, &propstat[PROPSTAT_OK],
			    ns, BAD_CAST propname, NULL, NULL);

	if (fctx->req_tgt->user) {
	    snprintf(uri, sizeof(uri), "/principals/user/%.*s/",
		     fctx->req_tgt->userlen, fctx->req_tgt->user);
	}

	xmlNewChild(node, NULL, BAD_CAST "href", BAD_CAST uri);
    }

    return 0;
}


/* Callback to fetch DAV:owner */
static int propfind_owner(const xmlChar *propname, xmlNsPtr ns,
			  struct propfind_ctx *fctx, xmlNodePtr resp,
			  struct propstat propstat[],
			  void *rock __attribute__((unused)))
{
    xmlNodePtr node;
    char uri[MAX_MAILBOX_PATH+1] = "";

    node = xml_add_prop(HTTP_OK, resp, &propstat[PROPSTAT_OK],
			ns, BAD_CAST propname, NULL, NULL);

    if ((fctx->req_tgt->namespace == URL_NS_CALENDAR) &&
	fctx->req_tgt->user) {
	    snprintf(uri, sizeof(uri), "/principals/user/%.*s/",
		     fctx->req_tgt->userlen, fctx->req_tgt->user);

	    xmlNewChild(node, NULL, BAD_CAST "href", BAD_CAST uri);
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
static int propfind_supprivset(const xmlChar *propname, xmlNsPtr ns,
			       struct propfind_ctx *fctx, xmlNodePtr resp,
			       struct propstat propstat[],
			       void *rock __attribute__((unused)))
{
    xmlNodePtr set, all, agg, write;

    set = xml_add_prop(HTTP_OK, resp, &propstat[PROPSTAT_OK],
		       ns, BAD_CAST propname, NULL, NULL);

    all = add_suppriv(set, "all", NULL, 0, "Any operation");

    agg = add_suppriv(all, "read", NULL, 0, "Read any object");
    add_suppriv(agg, "read-current-user-privilege-set", NULL, 1,
		"Read current user privilege set");

    ensure_ns(fctx->ns, NS_CAL, resp->parent, XML_NS_CAL, "C");
    add_suppriv(agg, "read-free-busy", fctx->ns[NS_CAL], 0,
		"Read free/busy time");

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

    return 0;
}


/* Callback to fetch DAV:current-user-principal */
static int propfind_curprin(const xmlChar *propname, xmlNsPtr ns,
			    struct propfind_ctx *fctx,
			    xmlNodePtr resp,
			    struct propstat propstat[],
			    void *rock __attribute__((unused)))
{
    xmlNodePtr node;
    char uri[MAX_MAILBOX_PATH+1];

    node = xml_add_prop(HTTP_OK, resp, &propstat[PROPSTAT_OK],
			ns, BAD_CAST propname, NULL, NULL);

    if (fctx->userid) {
	snprintf(uri, sizeof(uri), "/principals/user/%s/", fctx->userid);
	xmlNewChild(node, NULL, BAD_CAST "href", BAD_CAST uri);
    }
    else {
	xmlNewChild(node, NULL, BAD_CAST "unauthenticated", NULL);
    }

    return 0;
}


static int add_privs(int rights,
		     xmlNodePtr parent, xmlNodePtr root, xmlNsPtr *ns)
{
    xmlNodePtr priv;

    if ((rights & DACL_ALL) == DACL_ALL) {
	priv = xmlNewChild(parent, NULL, BAD_CAST "privilege", NULL);
	xmlNewChild(priv, NULL, BAD_CAST "all", NULL);
    }
    if (rights & DACL_READ) {
	priv = xmlNewChild(parent, NULL, BAD_CAST "privilege", NULL);
	xmlNewChild(priv, NULL, BAD_CAST "read", NULL);
    }
    if (rights & (DACL_READ|DACL_READFB)) {
	priv = xmlNewChild(parent, NULL, BAD_CAST "privilege", NULL);
	ensure_ns(ns, NS_CAL, root, XML_NS_CAL, "C");
	xmlNewChild(priv, ns[NS_CAL], BAD_CAST  "read-free-busy", NULL);
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

    return 0;
}


/* Callback to fetch DAV:current-user-privilege-set */
static int propfind_curprivset(const xmlChar *propname, xmlNsPtr ns,
			       struct propfind_ctx *fctx,
			       xmlNodePtr resp,
			       struct propstat propstat[],
			       void *rock __attribute__((unused)))
{
    int rights;

    if (!fctx->mailbox) {
	xml_add_prop(HTTP_NOT_FOUND, resp, &propstat[PROPSTAT_NOTFOUND],
		     ns, BAD_CAST propname, NULL, NULL);
    }
    else if (!((rights =
		cyrus_acl_myrights(fctx->authstate, fctx->mailbox->acl))
	       & DACL_READ)) {
	xml_add_prop(HTTP_UNAUTHORIZED, resp, &propstat[PROPSTAT_UNAUTH],
		     ns, BAD_CAST propname, NULL, NULL);
    }
    else {
	xmlNodePtr set;

	/* Add in implicit rights */
	if (fctx->userisadmin) {
	    rights |= DACL_ADMIN;
	}
	else if (mboxname_userownsmailbox(fctx->userid, fctx->mailbox->name)) {
	    rights |= config_implicitrights;
	}

	/* Build the rest of the XML response */
	set = xml_add_prop(HTTP_OK, resp, &propstat[PROPSTAT_OK],
			   ns, BAD_CAST propname, NULL, NULL);

	add_privs(rights, set, resp->parent, fctx->ns);
    }

    return 0;
}


/* Callback to fetch DAV:acl */
static int propfind_acl(const xmlChar *propname, xmlNsPtr ns,
			struct propfind_ctx *fctx,
			xmlNodePtr resp,
			struct propstat propstat[],
			void *rock __attribute__((unused)))
{
    int rights;

    if (!fctx->mailbox) {
	xml_add_prop(HTTP_NOT_FOUND, resp, &propstat[PROPSTAT_NOTFOUND],
		     ns, BAD_CAST propname, NULL, NULL);
    }
    else if (!((rights =
		cyrus_acl_myrights(fctx->authstate, fctx->mailbox->acl))
	       & DACL_ADMIN)) {
	xml_add_prop(HTTP_UNAUTHORIZED, resp, &propstat[PROPSTAT_UNAUTH],
		     ns, BAD_CAST propname, NULL, NULL);
    }
    else {
	xmlNodePtr acl;
	char *aclstr, *userid;

	/* Start the acl XML response */
	acl = xml_add_prop(HTTP_OK, resp, &propstat[PROPSTAT_OK],
			   ns, BAD_CAST propname, NULL, NULL);

	/* Parse the ACL string (userid/rights pairs) */
	userid = aclstr = xstrdup(fctx->mailbox->acl);

	while (userid) {
	    char *rightstr, *nextid;
	    xmlNodePtr ace, node;
	    char uri[MAX_MAILBOX_PATH+1];
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
		snprintf(uri, sizeof(uri), "/principals/user/%s/", userid);
		xmlNewChild(node, NULL, BAD_CAST "href", BAD_CAST uri);
	    }

	    node = xmlNewChild(ace, NULL,
			       BAD_CAST (deny ? "deny" : "grant"), NULL);
	    add_privs(rights, node, resp->parent, fctx->ns);

	    if (fctx->req_tgt->resource) {
		node = xmlNewChild(ace, NULL, BAD_CAST "inherited", NULL);
		snprintf(uri, sizeof(uri), "%.*s",
			 fctx->req_tgt->resource - fctx->req_tgt->path,
		    fctx->req_tgt->path);
		xmlNewChild(node, NULL, BAD_CAST "href", BAD_CAST uri);
	    }

	    userid = nextid;
	}

	if (aclstr) free(aclstr);
    }

    return 0;
}


/* Callback to fetch DAV:acl-restrictions */
static int propfind_aclrestrict(const xmlChar *propname, xmlNsPtr ns,
				struct propfind_ctx *fctx  __attribute__((unused)),
				xmlNodePtr resp,
				struct propstat propstat[],
				void *rock __attribute__((unused)))
{
    xmlNodePtr node;

    node = xml_add_prop(HTTP_OK, resp, &propstat[PROPSTAT_OK],
			ns, BAD_CAST propname, NULL, NULL);

    xmlNewChild(node, NULL, BAD_CAST "no-invert", NULL);

    return 0;
}


/* Callback to fetch DAV:principal-collection-set */
static int propfind_princolset(const xmlChar *propname, xmlNsPtr ns,
			       struct propfind_ctx *fctx  __attribute__((unused)),
			       xmlNodePtr resp,
			       struct propstat propstat[],
			       void *rock __attribute__((unused)))
{
    xmlNodePtr node;
    char uri[MAX_MAILBOX_PATH+1];

    node = xml_add_prop(HTTP_OK, resp, &propstat[PROPSTAT_OK],
			ns, BAD_CAST propname, NULL, NULL);

    snprintf(uri, sizeof(uri), "/principals/");
    xmlNewChild(node, NULL, BAD_CAST "href", BAD_CAST uri);

    return 0;
}


/* Callback to fetch DAV:quota-available-bytes and DAV:quota-used-bytes */
static int propfind_quota(const xmlChar *propname, xmlNsPtr ns,
			  struct propfind_ctx *fctx, xmlNodePtr resp,
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
	char mboxname[MAX_MAILBOX_BUFFER];
	
	(void) target_to_mboxname(fctx->req_tgt, mboxname);
	if (quota_findroot(foundroot, sizeof(foundroot), mboxname)) {
	    qr = foundroot;
	}
    }

    if (qr) {
	char bytes[21]; /* ULLONG_MAX is 20 digits */

	if (!fctx->quota.root ||
	    strcmp(fctx->quota.root, qr)) {
	    /* Different quotaroot - read it */

	    syslog(LOG_DEBUG, "reading quota for '%s'", qr);

	    fctx->quota.root = strcpy(prevroot, qr);

	    quota_read(&fctx->quota, NULL, 0);
	}

	if (!xmlStrcmp(propname, BAD_CAST "quota-available-bytes")) {
	    /* Calculate limit in bytes and subtract usage */
	    uquota_t limit = fctx->quota.limit * QUOTA_UNITS;

	    snprintf(bytes, sizeof(bytes),
		     UQUOTA_T_FMT, limit - fctx->quota.used);
	}
	else if (fctx->record) {
	    /* Bytes used by resource */
	    snprintf(bytes, sizeof(bytes), "%u", fctx->record->size);
	}
	else if (fctx->mailbox) {
	    /* Bytes used by calendar collection */
	    snprintf(bytes, sizeof(bytes), UQUOTA_T_FMT,
		     fctx->mailbox->i.quota_mailbox_used);
	}
	else {
	    /* Bytes used by entire hierarchy */
	    snprintf(bytes, sizeof(bytes), UQUOTA_T_FMT, fctx->quota.used);
	}

	xml_add_prop(HTTP_OK, resp, &propstat[PROPSTAT_OK],
		     ns, BAD_CAST propname, BAD_CAST bytes, NULL);
    }
    else {
	xml_add_prop(HTTP_NOT_FOUND, resp, &propstat[PROPSTAT_NOTFOUND],
		     ns, BAD_CAST propname, NULL, NULL);
    }

    return 0;
}


/* Callback to fetch CALDAV:calendar-data */
static int propfind_caldata(const xmlChar *propname, xmlNsPtr ns,
			    struct propfind_ctx *fctx, xmlNodePtr resp,
			    struct propstat propstat[],
			    void *rock __attribute__((unused)))
{
    if (fctx->record) {
	const char *msg_base = NULL;
	unsigned long msg_size = 0;
	xmlNodePtr data;

	mailbox_map_message(fctx->mailbox, fctx->record->uid,
			    &msg_base, &msg_size);

	data = xml_add_prop(HTTP_OK, resp, &propstat[PROPSTAT_OK],
			    ns, BAD_CAST propname, NULL, NULL);
	xmlAddChild(data,
		    xmlNewCDataBlock(fctx->root->doc,
				     BAD_CAST msg_base + fctx->record->header_size,
				     msg_size - fctx->record->header_size));

	mailbox_unmap_message(fctx->mailbox, fctx->record->uid,
			      &msg_base, &msg_size);
    }
    else {
	xml_add_prop(HTTP_NOT_FOUND, resp, &propstat[PROPSTAT_NOTFOUND],
		     ns, BAD_CAST propname, NULL, NULL);
    }

    return 0;
}


/* Callback to fetch CALDAV:calendar-home-set,
 * CALDAV:schedule-inbox-URL, and CALDAV:schedule-outbox-URL
 */
static int propfind_calurl(const xmlChar *propname, xmlNsPtr ns,
				struct propfind_ctx *fctx,
				xmlNodePtr resp,
				struct propstat propstat[],
				void *rock)
{
    xmlNodePtr node;
    char uri[MAX_MAILBOX_PATH+1];
    const char *cal = (const char *) rock;

    if (fctx->userid) {
	node = xml_add_prop(HTTP_OK, resp, &propstat[PROPSTAT_OK],
			    ns, BAD_CAST propname, NULL, NULL);

	snprintf(uri, sizeof(uri), "/calendars/user/%s/%s", fctx->userid,
		 cal ? cal : "");

	xmlNewChild(node, fctx->ns[NS_DAV], BAD_CAST "href", BAD_CAST uri);
    }
    else {
	xml_add_prop(HTTP_NOT_FOUND, resp, &propstat[PROPSTAT_NOTFOUND],
		     ns, BAD_CAST propname, NULL, NULL);
    }

    return 0;
}


/* Callback to fetch properties from resource header */
static int propfind_fromhdr(const xmlChar *propname, xmlNsPtr ns,
			    struct propfind_ctx *fctx, xmlNodePtr resp,
			    struct propstat propstat[], void *hdrname)
{
    if (fctx->record) {
	if (mailbox_cached_header((const char *) hdrname) != BIT32_MAX &&
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
		xml_add_prop(HTTP_OK, resp, &propstat[PROPSTAT_OK],
			     ns, BAD_CAST propname, BAD_CAST hdr[0], NULL);
	    }

	    spool_free_hdrcache(hdrs);

	    if (hdr) return 0;
	}
    }

    xml_add_prop(HTTP_NOT_FOUND, resp, &propstat[PROPSTAT_NOTFOUND],
		 ns, BAD_CAST propname, NULL, NULL);

    return 0;
}


/* Callback to read a property from annotation DB */
static int propfind_fromdb(const xmlChar *propname, xmlNsPtr ns,
			   struct propfind_ctx *fctx, xmlNodePtr resp,
			   struct propstat propstat[], void *ns_prefix)
{
    char prop_annot[MAX_MAILBOX_PATH+1];
    struct annotation_data attrib;
    xmlNodePtr node;
    const char *value = NULL;

    if (ns_prefix) {
	snprintf(prop_annot, sizeof(prop_annot),
		 "/vendor/cmu/cyrus-imapd/%s:%s",
		(const char *) ns_prefix, BAD_CAST propname);
    }
    else {
	/* "dead" property - use hash of the namespace href as prefix */
	snprintf(prop_annot, sizeof(prop_annot),
		 "/vendor/cmu/cyrus-imapd/%08X:%s",
		 strhash((const char *) ns->href), BAD_CAST propname);
    }

    if (fctx->mailbox && !fctx->record) {
	if (!annotatemore_lookup(fctx->mailbox->name, prop_annot,
				 /* shared */ "", &attrib)
	    && attrib.value) {
	    value = attrib.value;
	}
	else if (!xmlStrcmp(propname, BAD_CAST "displayname")) {
	    /* Special case empty displayname -- use last segment of path */
	    value = strrchr(fctx->mailbox->name, '.') + 1;
	}
    }

    if (value) {
	node = xml_add_prop(HTTP_OK, resp, &propstat[PROPSTAT_OK],
			    ns, BAD_CAST propname, BAD_CAST value, NULL);
    }
    else {
	node = xml_add_prop(HTTP_NOT_FOUND, resp, &propstat[PROPSTAT_NOTFOUND],
			    ns, BAD_CAST propname, NULL, NULL);
    }

    return 0;
}


/* Callback to write a property to annotation DB */
static int proppatch_todb(xmlNodePtr prop, unsigned set,
			  xmlNsPtr ns, struct proppatch_ctx *pctx,
			  struct propstat propstat[], void *ns_prefix)
{
    char prop_annot[MAX_MAILBOX_PATH+1];
    xmlChar *freeme = NULL;
    const char *value;
    xmlNodePtr node;
    int r;

    if (ns_prefix) {
	snprintf(prop_annot, sizeof(prop_annot),
		 "/vendor/cmu/cyrus-imapd/%s:%s",
		 (const char *) ns_prefix, BAD_CAST prop->name);
    }
    else {
	/* "dead" property - use hash of the namespace href as prefix */
	snprintf(prop_annot, sizeof(prop_annot),
		 "/vendor/cmu/cyrus-imapd/%08X:%s",
		 strhash((const char *) ns->href), BAD_CAST prop->name);
    }

    if (set) freeme = xmlNodeGetContent(prop);
    value = freeme ? (const char *) freeme : "";

    if (!(r = annotatemore_write_entry(pctx->mailboxname,
				       prop_annot, /* shared */ "",
				       value, NULL, strlen(value), 0,
				       &pctx->tid))) {
	node = xml_add_prop(HTTP_OK, pctx->root, &propstat[PROPSTAT_OK],
			    ns, prop->name, NULL, NULL);
    }
    else {
	/* XXX  Is this the correct code for a write failure? */
	node = xml_add_prop(HTTP_FORBIDDEN, pctx->root, &propstat[PROPSTAT_FORBID],
			    ns, prop->name, NULL, NULL);
	*pctx->ret = r;
    }

    if (freeme) xmlFree(freeme);

    return 0;
}


static const struct prop_entry prop_entries[] = 
{
    /* WebDAV (RFC 4918) properties */
    { "add-member", NS_DAV, 0, propfind_addmember, NULL, NULL },
    { "creationdate", NS_DAV, 1, NULL, NULL, NULL },
    { "displayname", NS_DAV, 1, propfind_fromdb, proppatch_todb, "DAV" },
    { "getcontentlanguage", NS_DAV, 1, propfind_fromhdr, NULL, "Content-Language" },
    { "getcontentlength", NS_DAV, 1, NULL, NULL, NULL },
    { "getcontenttype", NS_DAV, 1, propfind_fromhdr, NULL, "Content-Type" },
    { "getetag", NS_DAV, 1, propfind_getetag, NULL, NULL },
    { "getlastmodified", NS_DAV, 1, NULL, NULL, NULL },
    { "lockdiscovery", NS_DAV, 1, NULL, NULL, NULL },
    { "resourcetype", NS_DAV, 1, propfind_restype, proppatch_restype, NULL },
    { "supportedlock", NS_DAV, 1, NULL, NULL, NULL },
    { "sync-token", NS_DAV, 1, propfind_sync_token, NULL, NULL },

    /* WebDAV Versioning (RFC 3253) properties */
    { "supported-report-set", NS_DAV, 0, propfind_reportset, NULL, NULL },

    /* WebDAV ACL (RFC 3744) properties */
    { "alternate-URI-set", NS_DAV, 0, NULL, NULL, NULL },
    { "principal-URL", NS_DAV, 0, propfind_principalurl, NULL, NULL },
    { "group-member-set", NS_DAV, 0, NULL, NULL, NULL },
    { "group-membership", NS_DAV, 0, NULL, NULL, NULL },
    { "owner", NS_DAV, 0, propfind_owner, NULL, NULL },
    { "group", NS_DAV, 0, NULL, NULL, NULL },
    { "supported-privilege-set", NS_DAV, 0, propfind_supprivset, NULL, NULL },
    { "current-user-principal", NS_DAV, 0, propfind_curprin, NULL, NULL },
    { "current-user-privilege-set", NS_DAV, 0, propfind_curprivset, NULL, NULL },
    { "acl", NS_DAV, 0, propfind_acl, NULL, NULL },
    { "acl-restrictions", NS_DAV, 0, propfind_aclrestrict, NULL, NULL },
    { "inherited-acl-set", NS_DAV, 0, NULL, NULL, NULL },
    { "principal-collection-set", NS_DAV, 0, propfind_princolset, NULL, NULL },

    /* WebDAV Quota (RFC 4331) properties */
    { "quota-available-bytes", NS_DAV, 0, propfind_quota, NULL, NULL },
    { "quota-used-bytes", NS_DAV, 0, propfind_quota, NULL, NULL },

    /* CalDAV (RFC 4791) properties */
    { "calendar-data", NS_CAL, 0, propfind_caldata, NULL, NULL },
    { "calendar-description", NS_CAL, 0, propfind_fromdb, proppatch_todb, "CALDAV" },
    { "calendar-home-set", NS_CAL, 0, propfind_calurl, NULL, NULL },
    { "calendar-timezone", NS_CAL, 0, propfind_fromdb, proppatch_todb, "CALDAV" },
    { "supported-calendar-component-set", NS_CAL, 0, NULL, NULL, NULL },
    { "supported-calendar-data", NS_CAL, 0, NULL, NULL, NULL },
    { "max-resource-size", NS_CAL, 0, NULL, NULL, NULL },
    { "min-date-time", NS_CAL, 0, NULL, NULL, NULL },
    { "max-date-time", NS_CAL, 0, NULL, NULL, NULL },
    { "max-instances", NS_CAL, 0, NULL, NULL, NULL },
    { "max-attendees-per-instance", NS_CAL, 0, NULL, NULL, NULL },

    /* CalDAV Scheduling properties */
    { "schedule-inbox-URL", NS_CAL, 0, propfind_calurl, NULL, SCHED_INBOX },
    { "schedule-outbox-URL", NS_CAL, 0, propfind_calurl, NULL, SCHED_OUTBOX },
    { "calendar-user-address-set", NS_CAL, 0, NULL, NULL, NULL },
    { "calendar-user-type", NS_CAL, 0, NULL, NULL, NULL },

    /* Calendar Server properties */
    { "getctag", NS_CS, 1, propfind_sync_token, NULL, NULL },

    /* Apple properties */
    { "calendar-color", NS_APPLE, 0, propfind_fromdb, proppatch_todb, "APPLE" },
    { "calendar-order", NS_APPLE, 0, propfind_fromdb, proppatch_todb, "APPLE" },

    { NULL, NS_UNKNOWN, 0, NULL, NULL, NULL }
};

const struct precond preconds[] =
{
    /* WebDAV (RFC 4918) preconditons */
    { "cannot-modify-protected-property", NS_DAV },

    /* WebDAV Versioning (RFC 3253) preconditions */
    { "supported-report", NS_DAV },

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

    /* WebDAV Sync (draft-daboo-webdav-sync) preconditions */
    { "valid-sync-token", NS_DAV },
    { "number-of-matches-within-limits", NS_DAV },

    /* CalDAV (RFC 4791) preconditions */
    { "supported-calendar-data", NS_CAL },
    { "valid-calendar-data", NS_CAL }
};


/* Parse the requested properties and create a linked list of fetch callbacks.
 * The list gets reused for each href if Depth > 0
 */
int preload_proplist(xmlNodePtr proplist, struct propfind_entry_list **list)
{
    xmlNodePtr prop;
    const struct prop_entry *entry;

    /* Iterate through requested properties */
    for (prop = proplist; prop; prop = prop->next) {
	if (prop->type == XML_ELEMENT_NODE) {
	    struct propfind_entry_list *nentry =
		xzmalloc(sizeof(struct propfind_entry_list));

	    /* Look for a match against our known properties */
	    for (entry = prop_entries;
		 entry->name && strcmp((const char *) prop->name, entry->name);
		 entry++);

	    nentry->name = prop->name;
	    nentry->ns = prop->ns;
	    if (entry->name) {
		/* Found a match */
		nentry->get = entry->get;
		nentry->rock = entry->rock;
	    }
	    else {
		/* No match, treat as a dead property */
		nentry->get = propfind_fromdb;
		nentry->rock = NULL;
	    }
	    nentry->next = *list;
	    *list = nentry;
	}
    }

    return 0;
}


/* Execute the given property patch instructions */
int do_proppatch(struct proppatch_ctx *pctx, xmlNodePtr instr)
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
	    else if ((pctx->meth[0] == 'P') &&
		     !xmlStrcmp(instr->name, BAD_CAST "remove")) set = 0;
	    else {
		syslog(LOG_INFO, "Unknown PROPPATCH instruction");
		*pctx->errstr = "Unknown PROPPATCH instruction";
		return HTTP_BAD_REQUEST;
	    }

	    /* Find child element */
	    for (prop = instr->children;
		 prop && prop->type != XML_ELEMENT_NODE; prop = prop->next);
	    if (!prop || xmlStrcmp(prop->name, BAD_CAST "prop")) {
		*pctx->errstr = "Missing prop element";
		return HTTP_BAD_REQUEST;
	    }

	    /* Iterate through requested properties */
	    for (prop = prop->children; prop; prop = prop->next) {
		if (prop->type == XML_ELEMENT_NODE) {
		    const struct prop_entry *entry;

		    /* Look for a match against our known properties */
		    for (entry = prop_entries;
			 entry->name &&
			     strcmp((const char *) prop->name, entry->name);
			 entry++);

		    if (entry->name) {
			if (!entry->put) {
			    /* Protected property */
			    xml_add_prop(HTTP_FORBIDDEN, pctx->root,
					 &propstat[PROPSTAT_FORBID],
					 prop->ns,
					 prop->name, NULL,
					 &preconds[DAV_PROT_PROP]);
			    *pctx->ret = HTTP_FORBIDDEN;
			}
			else {
			    /* Write "live" property */
			    entry->put(prop, set,
				       prop->ns,
				       pctx, propstat,
				       entry->rock);
			}
		    }
		    else {
			/* Write "dead" property */
			proppatch_todb(prop, set,
				       prop->ns, pctx, propstat,
				       NULL);
		    }
		}
	    }
	}
    }

    /* One or more of the properties failed */
    if (*pctx->ret && propstat[PROPSTAT_OK].prop) {
	/* 200 status must become 424 */
	propstat[PROPSTAT_OK].status = HTTP_FAILED_DEP;
    }

    /* Add status and optional error to the propstat elements */
    for (i = 0; i < NUM_PROPSTAT; i++) {
	struct propstat *stat = &propstat[i];

	if (stat->prop) {
	    xmlNewChild(stat->prop->parent, NULL, BAD_CAST "status",
			BAD_CAST http_statusline(stat->status));
	    if (stat->precond) {
		xml_add_error(stat->prop->parent, stat->precond, pctx->ns);
	    }
	}
    }

    return 0;
}
