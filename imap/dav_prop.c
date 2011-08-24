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
#include "caldav_db.h"
#include "http_err.h"
#include "xmalloc.h"
#include "xstrlcpy.h"
#include "xstrlcat.h"


/* Initialize an XML tree for a property response */
xmlDocPtr init_prop_response(const char *resp, xmlNodePtr *root,
			     xmlNsPtr reqNs, xmlNsPtr *respNs)
{
    /* Start construction of our XML response tree */
    xmlDocPtr outdoc = xmlNewDoc(BAD_CAST "1.0");

    *root = xmlNewNode(NULL, BAD_CAST resp);
    xmlDocSetRootElement(outdoc, *root);

    /* Add namespaces from request to our response,
     * creating array of known namespaces that we can reference later.
     */
    memset(respNs, 0, NUM_NAMESPACE * sizeof(xmlNsPtr));
    for (; reqNs; reqNs = reqNs->next) {
	if (!xmlStrcmp(reqNs->href, BAD_CAST NS_URL_DAV))
	    respNs[NS_DAV] = xmlNewNs(*root, reqNs->href, reqNs->prefix);
	else if (!xmlStrcmp(reqNs->href, BAD_CAST NS_URL_CAL))
	    respNs[NS_CAL] = xmlNewNs(*root, reqNs->href, reqNs->prefix);
	else if (!xmlStrcmp(reqNs->href, BAD_CAST NS_URL_CS))
	    respNs[NS_CS] = xmlNewNs(*root, reqNs->href, reqNs->prefix);
	else if (!xmlStrcmp(reqNs->href, BAD_CAST NS_URL_APPLE))
	    respNs[NS_APPLE] = xmlNewNs(*root, reqNs->href, reqNs->prefix);
	else
	    xmlNewNs(*root, reqNs->href, reqNs->prefix);
    }

    /* Set namespace of root node */
    xmlSetNs(*root, respNs[NS_DAV]);

    return outdoc;
}


/* Add a property 'name', of namespace 'ns', with content 'content',
 * and status code/string 'status' to propstat element 'stat'.
 * 'stat' will be created as necessary.
 */
static xmlNodePtr add_prop(long status, xmlNodePtr resp, xmlNodePtr *stat,
			   xmlNsPtr ns, const xmlChar *name, xmlChar *content,
			   const xmlChar *precond __attribute__((unused)))
{
    xmlNodePtr node;

    if (!*stat) {
	*stat = xmlNewChild(resp, NULL, BAD_CAST "propstat", NULL);
	xmlNewChild(*stat, NULL, BAD_CAST "status",
		    BAD_CAST http_statusline(status));
	*stat = xmlNewChild(*stat, NULL, BAD_CAST "prop", NULL);
    }

    node = xmlNewChild(*stat, ns, name, content);

    return node;
}


/* Add a response tree to 'root' for the specified href and property list */
void add_prop_response(struct propfind_ctx *fctx)
{
    xmlNodePtr resp, propstat[NUM_PROPSTAT] = { NULL, NULL, NULL };
    struct propfind_entry_list *e;

    resp = xmlNewChild(fctx->root, NULL, BAD_CAST "response", NULL);
    if (!resp) syslog(LOG_INFO, "new child response failed");
    xmlNewChild(resp, NULL, BAD_CAST "href", BAD_CAST fctx->req_tgt->path);

    /* Process each property in the linked list */
    for (e = fctx->elist; e; e = e->next) {
	if (e->get) {
	    e->get(e->name, e->ns, fctx, resp, propstat, e->rock);
	}
	else {
	    add_prop(HTTP_NOT_FOUND, resp, &propstat[PROPSTAT_NOTFOUND], e->ns,
		     e->name, NULL, NULL);
	}
    }

    return;
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

    /* Fetch index record for the resource */
    r = mailbox_find_index_record(fctx->mailbox, uid, &record);
    /* XXX  Check errors */

    fctx->record = r ? NULL : &record;

    /* Add response for target */
    add_prop_response(fctx);

    return 0;
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
    add_prop_response(fctx);

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
			      xmlNodePtr *propstat,
			      void *rock __attribute__((unused)))
{
    if (fctx->req_tgt->collection) {
	xmlNodePtr node;
	size_t len;
	char uri[MAX_MAILBOX_PATH+1];

	node = add_prop(HTTP_OK, resp, &propstat[PROPSTAT_OK], ns,
			BAD_CAST propname, NULL, NULL);

	len = fctx->req_tgt->resource ?
	    (size_t) (fctx->req_tgt->resource - fctx->req_tgt->path) :
	    strlen(fctx->req_tgt->path);
	snprintf(uri, sizeof(uri), "%.*s", len, fctx->req_tgt->path);
	xmlNewChild(node, fctx->ns[NS_DAV], BAD_CAST "href", BAD_CAST uri);
    }
    else {
	add_prop(HTTP_NOT_FOUND, resp, &propstat[PROPSTAT_NOTFOUND], ns,
		 BAD_CAST propname, NULL, NULL);
    }

    return 0;
}


/* Callback to fetch DAV:getetag */
static int propfind_getetag(const xmlChar *propname, xmlNsPtr ns,
			    struct propfind_ctx *fctx, xmlNodePtr resp,
			    xmlNodePtr *propstat,
			    void *rock __attribute__((unused)))
{
    if (fctx->record) {
	char etag[2*MESSAGE_GUID_SIZE+3];

	/* add DQUOTEs */
	sprintf(etag, "\"%s\"", message_guid_encode(&fctx->record->guid));

	add_prop(HTTP_OK, resp, &propstat[PROPSTAT_OK], ns,
		 BAD_CAST propname, BAD_CAST etag, NULL);
    }
    else {
	add_prop(HTTP_NOT_FOUND, resp, &propstat[PROPSTAT_NOTFOUND], ns,
		 BAD_CAST propname, NULL, NULL);
    }

    return 0;
}


/* Callback to fetch DAV:resourcetype */
static int propfind_restype(const xmlChar *propname, xmlNsPtr ns,
			    struct propfind_ctx *fctx, xmlNodePtr resp,
			    xmlNodePtr *propstat,
			    void *rock __attribute__((unused)))
{
    xmlNodePtr node = add_prop(HTTP_OK, resp, &propstat[PROPSTAT_OK], ns,
			       BAD_CAST propname, NULL, NULL);

    if ((fctx->req_tgt->namespace != URL_NS_DEFAULT) && !fctx->record) {
	xmlNewChild(node, fctx->ns[NS_DAV], BAD_CAST "collection", NULL);

	switch (fctx->req_tgt->namespace) {
	case URL_NS_PRINCIPAL:
	    if (fctx->req_tgt->user)
		xmlNewChild(node, fctx->ns[NS_DAV], BAD_CAST "principal", NULL);
	    break;

	case URL_NS_CALENDAR:
	    if (fctx->mailbox)
		xmlNewChild(node, fctx->ns[NS_CAL], BAD_CAST "calendar", NULL);
	    break;

	case URL_NS_ADDRESSBOOK:
	    if (fctx->mailbox)
		xmlNewChild(node, fctx->ns[NS_CAL], BAD_CAST "addressbook", NULL);
	    break;
	}
    }

    return 0;
}


/* Callback to "write" resourcetype property */
static int proppatch_restype(xmlNodePtr prop, unsigned set,
			     xmlNsPtr ns, struct proppatch_ctx *pctx,
			     xmlNodePtr *propstat,
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
	    add_prop(HTTP_OK, pctx->root, &propstat[PROPSTAT_OK],
		     ns, prop->name, NULL, NULL);

	    return 0;
	}
    }

    /* Protected property / Invalid resourcetype */
    add_prop(HTTP_FORBIDDEN, pctx->root, &propstat[PROPSTAT_FORBID],
	     ns, prop->name, NULL,
	     (set && pctx->meth[0] == 'M') ? BAD_CAST "valid-resourcetype":
	     BAD_CAST "cannot-modify-protected-property");
	     
    *pctx->ret = HTTP_FORBIDDEN;

    return 0;
}


/* Callback to fetch DAV:supported-report-set */
static int propfind_reportset(const xmlChar *propname, xmlNsPtr ns,
			      struct propfind_ctx *fctx, xmlNodePtr resp,
			      xmlNodePtr *propstat,
			      void *rock __attribute__((unused)))
{
    xmlNodePtr s, r, top = add_prop(HTTP_OK, resp, &propstat[PROPSTAT_OK], ns,
				    BAD_CAST propname, NULL, NULL);

    if (fctx->req_tgt->namespace == URL_NS_CALENDAR) {
	s = xmlNewChild(top, fctx->ns[NS_DAV], BAD_CAST "supported-report", NULL);
	r = xmlNewChild(s, fctx->ns[NS_DAV], BAD_CAST "report", NULL);
	xmlNewChild(r, fctx->ns[NS_CAL], BAD_CAST "calendar-query", NULL);

	s = xmlNewChild(top, fctx->ns[NS_DAV], BAD_CAST "supported-report", NULL);
	r = xmlNewChild(s, fctx->ns[NS_DAV], BAD_CAST "report", NULL);
	xmlNewChild(r, fctx->ns[NS_CAL], BAD_CAST "calendar-multiget", NULL);
    }

    return 0;
}


/* Callback to fetch DAV:owner */
static int propfind_owner(const xmlChar *propname, xmlNsPtr ns,
			  struct propfind_ctx *fctx, xmlNodePtr resp,
			  xmlNodePtr *propstat,
			  void *rock __attribute__((unused)))
{
    xmlNodePtr node;
    char uri[MAX_MAILBOX_PATH+1] = "";

    if (((propname[0] == 'o') &&
	 (fctx->req_tgt->namespace == URL_NS_PRINCIPAL)) ||
	((propname[0] == 'p') &&
	 (fctx->req_tgt->namespace != URL_NS_PRINCIPAL))) {
	node = add_prop(HTTP_NOT_FOUND, resp, &propstat[PROPSTAT_NOTFOUND], ns,
			BAD_CAST propname, NULL, NULL);
    }
    else {
	node = add_prop(HTTP_OK, resp, &propstat[PROPSTAT_OK], ns,
			BAD_CAST propname, NULL, NULL);

	if (fctx->req_tgt->user) {
	    snprintf(uri, sizeof(uri), "/principals/user/%.*s/",
		     fctx->req_tgt->userlen, fctx->req_tgt->user);
	}

	xmlNewChild(node, fctx->ns[NS_DAV], BAD_CAST "href", BAD_CAST uri);
    }

    return 0;
}


/* Callback to fetch DAV:supported-privilege-set */
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

    return priv;
}

static int propfind_supprivset(const xmlChar *propname, xmlNsPtr ns,
			       struct propfind_ctx *fctx, xmlNodePtr resp,
			       xmlNodePtr *propstat,
			       void *rock __attribute__((unused)))
{
    xmlNodePtr set, all, read, write;

    set = add_prop(HTTP_OK, resp, &propstat[PROPSTAT_OK], ns,
		    BAD_CAST propname, NULL, NULL);

    all = add_suppriv(set, "all", NULL, 1, "Any operation");

    read = add_suppriv(all, "read", NULL, 0, "Read any object");
    add_suppriv(read, "read-current-user-privilege-set", NULL, 1,
		"Read current user privilege set property");
    add_suppriv(read, "read-free-busy", fctx->ns[NS_CAL], 0,
		"Read free/busy time");

    write = add_suppriv(all, "write", NULL, 0, "Write any object");
    add_suppriv(write, "bind", NULL, 0, "Add new member to collection");
    add_suppriv(write, "unbind", NULL, 0, "Remove member from collection");
    add_suppriv(write, "write-properties", NULL, 0, "Write properties");
    add_suppriv(write, "write-content", NULL, 0, "Write resource content");

    add_suppriv(all, "read-acl", NULL, 0, "Read ACL");
    add_suppriv(all, "write-acl", NULL, 0, "Write ACL");
    add_suppriv(all, "unlock", NULL, 0, "Unlock resource");

    return 0;
}


/* Callback to fetch DAV:current-user-principal */
static int propfind_curprin(const xmlChar *propname, xmlNsPtr ns,
			     struct propfind_ctx *fctx,
			     xmlNodePtr resp,
			     xmlNodePtr *propstat,
			     void *rock __attribute__((unused)))
{
    xmlNodePtr node;
    char uri[MAX_MAILBOX_PATH+1];

    node = add_prop(HTTP_OK, resp, &propstat[PROPSTAT_OK], ns,
		    BAD_CAST propname, NULL, NULL);

    if (fctx->userid) {
	snprintf(uri, sizeof(uri), "/principals/user/%s/", fctx->userid);
	xmlNewChild(node, fctx->ns[NS_DAV], BAD_CAST "href", BAD_CAST uri);
    }
    else {
	xmlNewChild(node, fctx->ns[NS_DAV], BAD_CAST "unauthenticated", NULL);
    }

    return 0;
}


/* Callback to fetch DAV:principal-collection-set */
static int propfind_princolset(const xmlChar *propname, xmlNsPtr ns,
			     struct propfind_ctx *fctx,
			     xmlNodePtr resp,
			     xmlNodePtr *propstat,
			     void *rock __attribute__((unused)))
{
    xmlNodePtr node;
    char uri[MAX_MAILBOX_PATH+1];

    node = add_prop(HTTP_OK, resp, &propstat[PROPSTAT_OK], ns,
		    BAD_CAST propname, NULL, NULL);

    snprintf(uri, sizeof(uri), "/principals/");
    xmlNewChild(node, fctx->ns[NS_DAV], BAD_CAST "href", BAD_CAST uri);

    return 0;
}


/* Callback to fetch DAV:quota-available-bytes and DAV:quota-used-bytes */
static int propfind_quota(const xmlChar *propname, xmlNsPtr ns,
			  struct propfind_ctx *fctx, xmlNodePtr resp,
			  xmlNodePtr *propstat,
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

	add_prop(HTTP_OK, resp, &propstat[PROPSTAT_OK], ns,
		 BAD_CAST propname, BAD_CAST bytes, NULL);
    }
    else {
	add_prop(HTTP_NOT_FOUND, resp, &propstat[PROPSTAT_NOTFOUND], ns,
		 BAD_CAST propname, NULL, NULL);
    }

    return 0;
}


/* Callback to fetch CALDAV:calendar-data */
static int propfind_caldata(const xmlChar *propname, xmlNsPtr ns,
			    struct propfind_ctx *fctx, xmlNodePtr resp,
			    xmlNodePtr *propstat,
			    void *rock __attribute__((unused)))
{
    if (fctx->record) {
	const char *msg_base = NULL;
	unsigned long msg_size = 0;

	mailbox_map_message(fctx->mailbox, fctx->record->uid,
			    &msg_base, &msg_size);

	add_prop(HTTP_OK, resp, &propstat[PROPSTAT_OK], ns, BAD_CAST propname,
		 BAD_CAST msg_base + fctx->record->header_size, NULL);

	mailbox_unmap_message(fctx->mailbox, fctx->record->uid,
			      &msg_base, &msg_size);
    }
    else {
	add_prop(HTTP_NOT_FOUND, resp, &propstat[PROPSTAT_NOTFOUND], ns,
		 BAD_CAST propname, NULL, NULL);
    }

    return 0;
}


/* Callback to fetch CALDAV:calendar-home-set */
static int propfind_calhomeset(const xmlChar *propname, xmlNsPtr ns,
			       struct propfind_ctx *fctx,
			       xmlNodePtr resp,
			       xmlNodePtr *propstat,
			       void *rock __attribute__((unused)))
{
    xmlNodePtr node;
    char uri[MAX_MAILBOX_PATH+1];

    node = add_prop(HTTP_OK, resp, &propstat[PROPSTAT_OK], ns,
		    BAD_CAST propname, NULL, NULL);

    snprintf(uri, sizeof(uri), "/calendars/user/%s/", fctx->userid);

    xmlNewChild(node, fctx->ns[NS_DAV], BAD_CAST "href", BAD_CAST uri);

    return 0;
}


/* Callback to fetch CS:getctag */
static int propfind_getctag(const xmlChar *propname, xmlNsPtr ns,
			    struct propfind_ctx *fctx, xmlNodePtr resp,
			    xmlNodePtr *propstat,
			    void *rock __attribute__((unused)))
{
    if (fctx->mailbox && !fctx->record) {
	char ctag[33]; /* UIDVALIDITY-EXISTS-LAST_UID */

	sprintf(ctag, "%u-%u-%u", fctx->mailbox->i.uidvalidity,
		fctx->mailbox->i.exists, fctx->mailbox->i.last_uid);

	add_prop(HTTP_OK, resp, &propstat[PROPSTAT_OK], ns,
		 BAD_CAST propname, BAD_CAST ctag, NULL);
    }
    else {
	add_prop(HTTP_NOT_FOUND, resp, &propstat[PROPSTAT_NOTFOUND], ns,
		 BAD_CAST propname, NULL, NULL);
    }

    return 0;
}


/* Callback to fetch properties from resource header */
static int propfind_fromhdr(const xmlChar *propname, xmlNsPtr ns,
			    struct propfind_ctx *fctx, xmlNodePtr resp,
			    xmlNodePtr *propstat, void *hdrname)
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

	    if ((hdr = spool_getheader(hdrs, "Content-Type"))) {
		add_prop(HTTP_OK, resp, &propstat[PROPSTAT_OK], NULL,
 			 BAD_CAST propname, BAD_CAST hdr[0], NULL);
	    }

	    spool_free_hdrcache(hdrs);

	    if (hdr) return 0;
	}
    }

    add_prop(HTTP_NOT_FOUND, resp, &propstat[PROPSTAT_NOTFOUND], ns,
	     BAD_CAST propname, NULL, NULL);

    return 0;
}


/* Callback to read a property from annotation DB */
static int propfind_fromdb(const xmlChar *propname, xmlNsPtr ns,
			   struct propfind_ctx *fctx, xmlNodePtr resp,
			   xmlNodePtr *propstat, void *ns_prefix)
{
    char prop_annot[MAX_MAILBOX_PATH+1];
    struct annotation_data attrib;
    xmlNodePtr node;
    const char *value = NULL;

    if (ns_prefix) {
	sprintf(prop_annot, "/vendor/cmu/cyrus-imapd/%s:%s",
		(const char *) ns_prefix, BAD_CAST propname);
    }
    else {
	/* "dead" property - use hash of the namespace href as prefix */
	sprintf(prop_annot, "/vendor/cmu/cyrus-imapd/%08X:%s",
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
	node = add_prop(HTTP_OK, resp, &propstat[PROPSTAT_OK], ns,
			BAD_CAST propname, BAD_CAST value, NULL);
    }
    else {
	node = add_prop(HTTP_NOT_FOUND, resp, &propstat[PROPSTAT_NOTFOUND], ns,
			BAD_CAST propname, NULL, NULL);
    }

    return 0;
}


/* Callback to write a property to annotation DB */
static int proppatch_todb(xmlNodePtr prop, unsigned set,
			  xmlNsPtr ns, struct proppatch_ctx *pctx,
			  xmlNodePtr *propstat, void *ns_prefix)
{
    char prop_annot[MAX_MAILBOX_PATH+1];
    xmlChar *freeme = NULL;
    const char *value;
    xmlNodePtr node;
    int r;

    if (ns_prefix) {
	sprintf(prop_annot, "/vendor/cmu/cyrus-imapd/%s:%s",
		(const char *) ns_prefix, BAD_CAST prop->name);
    }
    else {
	/* "dead" property - use hash of the namespace href as prefix */
	sprintf(prop_annot, "/vendor/cmu/cyrus-imapd/%08X:%s",
		strhash((const char *) ns->href), BAD_CAST prop->name);
    }

    if (set) freeme = xmlNodeGetContent(prop);
    value = freeme ? (const char *) freeme : "";

    if (!(r = annotatemore_write_entry(pctx->mailboxname,
				       prop_annot, /* shared */ "",
				       value, NULL, strlen(value), 0,
				       &pctx->tid))) {
	node = add_prop(HTTP_OK, pctx->root, &propstat[PROPSTAT_OK],
			ns, prop->name, NULL, NULL);
    }
    else {
	/* XXX  Is this the correct code for a write failure? */
	node = add_prop(HTTP_FORBIDDEN, pctx->root, &propstat[PROPSTAT_FORBID],
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

    /* WebDAV Versioning (RFC 3253) properties */
    { "supported-report-set", NS_DAV, 0, propfind_reportset, NULL, NULL },

    /* WebDAV ACL (RFC 3744) properties */
    { "alternate-URI-set", NS_DAV, 0, NULL, NULL, NULL },
    { "principal-URL", NS_DAV, 0, propfind_owner, NULL, NULL },
    { "group-member-set", NS_DAV, 0, NULL, NULL, NULL },
    { "group-membership", NS_DAV, 0, NULL, NULL, NULL },
    { "owner", NS_DAV, 0, NULL/*propfind_owner*/, NULL, NULL },
    { "group", NS_DAV, 0, NULL, NULL, NULL },
    { "supported-privilege-set", NS_DAV, 0, propfind_supprivset, NULL, NULL },
    { "current-user-principal", NS_DAV, 0, propfind_curprin, NULL, NULL },
    { "current-user-privilege-set", NS_DAV, 0, NULL, NULL, NULL },
    { "acl", NS_DAV, 0, NULL, NULL, NULL },
    { "acl-restrictions", NS_DAV, 0, NULL, NULL, NULL },
    { "inherited-acl-set", NS_DAV, 0, NULL, NULL, NULL },
    { "principal-collection-set", NS_DAV, 0, propfind_princolset, NULL, NULL },

    /* WebDAV Quota (RFC 4331) properties */
    { "quota-available-bytes", NS_DAV, 0, propfind_quota, NULL, NULL },
    { "quota-used-bytes", NS_DAV, 0, propfind_quota, NULL, NULL },

    /* CalDAV (RFC 4791) properties */
    { "calendar-data", NS_CAL, 0, propfind_caldata, NULL, NULL },
    { "calendar-description", NS_CAL, 0, propfind_fromdb, proppatch_todb, "CALDAV" },
    { "calendar-home-set", NS_CAL, 0, propfind_calhomeset, NULL, NULL },
    { "calendar-timezone", NS_CAL, 0, propfind_fromdb, proppatch_todb, "CALDAV" },
    { "supported-calendar-component-set", NS_CAL, 0, NULL, NULL, NULL },
    { "supported-calendar-data", NS_CAL, 0, NULL, NULL, NULL },
    { "max-resource-size", NS_CAL, 0, NULL, NULL, NULL },
    { "min-date-time", NS_CAL, 0, NULL, NULL, NULL },
    { "max-date-time", NS_CAL, 0, NULL, NULL, NULL },
    { "max-instances", NS_CAL, 0, NULL, NULL, NULL },
    { "max-attendees-per-instance", NS_CAL, 0, NULL, NULL, NULL },

    /* CalDAV Scheduling properties */
    { "schedule-inbox-URL", NS_CAL, 0, NULL, NULL, NULL },
    { "schedule-outbox-URL", NS_CAL, 0, NULL, NULL, NULL },
    { "calendar-user-address-set", NS_CAL, 0, NULL, NULL, NULL },
    { "calendar-user-type", NS_CAL, 0, NULL, NULL, NULL },

    /* Calendar Server properties */
    { "getctag", NS_CS, 1, propfind_getctag, NULL, NULL },

    /* Apple properties */
    { "calendar-color", NS_APPLE, 0, propfind_fromdb, proppatch_todb, "APPLE" },
    { "calendar-order", NS_APPLE, 0, propfind_fromdb, proppatch_todb, "APPLE" },

    { NULL, NS_UNKNOWN, 0, NULL, NULL, NULL }
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
int do_proppatch(struct proppatch_ctx *pctx, xmlNodePtr instr,
		 xmlNodePtr *propstat)
{
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
			    add_prop(HTTP_FORBIDDEN, pctx->root,
				     &propstat[PROPSTAT_FORBID],
				     prop->ns,
				     prop->name, NULL,
				     BAD_CAST "cannot-modify-protected-property");
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

    return 0;
}
