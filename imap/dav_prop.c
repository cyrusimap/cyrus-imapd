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


#include "dav_prop.h"
#include "annotate.h"
#include "acl.h"
#include "caldav_db.h"
#include "global.h"
#include "http_err.h"
#include "xmalloc.h"
#include "rfc822date.h"

#include <libxml/uri.h>


static const struct cal_comp_t {
    const char *name;
    unsigned long type;
} cal_comps[] = {
    { "VEVENT",    CAL_COMP_VEVENT },
    { "VTODO",     CAL_COMP_VTODO },
    { "VJOURNAL",  CAL_COMP_VJOURNAL },
    { "VFREEBUSY", CAL_COMP_VFREEBUSY },
    { "VTIMEZONE", CAL_COMP_VTIMEZONE },
    { "VALARM",	   CAL_COMP_VALARM },
    { NULL, 0 }
};

/* Bitmask of privilege flags */
enum {
    PRIV_IMPLICIT =		(1<<0),
    PRIV_INBOX =		(1<<1),
    PRIV_OUTBOX =		(1<<2)
};

extern int target_to_mboxname(struct request_target_t *req_tgt, char *mboxname);
static int add_privs(int rights, unsigned flags,
		     xmlNodePtr parent, xmlNodePtr root, xmlNsPtr *ns);


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
		else if (!xmlStrcmp(nsDef->href, BAD_CAST XML_NS_CS))
		    ensure_ns(respNs, NS_CS, root,
			      (const char *) nsDef->href,
			      (const char *) nsDef->prefix);
		else if (!xmlStrcmp(nsDef->href, BAD_CAST XML_NS_CYRUS))
		    ensure_ns(respNs, NS_CYRUS, root,
			      (const char *) nsDef->href,
			      (const char *) nsDef->prefix);
		else if (!xmlStrcmp(nsDef->href, BAD_CAST XML_NS_ICAL))
		    ensure_ns(respNs, NS_ICAL, root,
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
    if (ns == NS_CALDAV) ensure_ns(respNs, NS_CALDAV, root, XML_NS_CALDAV, "C");
    ensure_ns(respNs, NS_DAV, root, XML_NS_DAV, "D");
    xmlSetNs(root, respNs[ns]);

    return root;
}

static xmlNodePtr xml_add_href(xmlNodePtr parent, xmlNsPtr ns,
			       const char *href)
{
    xmlChar *uri = xmlURIEscapeStr(BAD_CAST href, BAD_CAST "/");
    xmlNodePtr node = xmlNewChild(parent, ns, BAD_CAST "href", uri);

    free(uri);
    return node;
}

/* Array of precondition/postcondition errors */
static const struct precond_t {
    const char *name;			/* Property name */
    unsigned ns;			/* Index into known namespace array */
} preconds[] = {
    /* Placeholder for zero (no) precondition code */
    { NULL, 0 },

    /* WebDAV (RFC 4918) preconditons */
    { "cannot-modify-protected-property", NS_DAV },

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

    /* CalDAV Scheduling (draft-desruisseaux-caldav-sched) preconditions */
    { "valid-scheduling-message", NS_CALDAV },
    { "valid-organizer", NS_CALDAV },
    { "unique-scheduling-object-resource", NS_CALDAV },
    { "same-organizer-in-all-components", NS_CALDAV },
    { "allowed-organizer-scheduling-object-change", NS_CALDAV },
    { "allowed-attendee-scheduling-object-change", NS_CALDAV }
};

xmlNodePtr xml_add_error(xmlNodePtr root, struct error_t *err,
			 xmlNsPtr *avail_ns)
{
    xmlNsPtr ns[NUM_NAMESPACE];
    xmlNodePtr error, node;
    const struct precond_t *precond = &preconds[err->precond];

    if (!root) {
	error = root = init_xml_response("error", NS_DAV, NULL, ns);
	avail_ns = ns;
    }
    else error = xmlNewChild(root, NULL, BAD_CAST "error", NULL);

    if (precond->ns == NS_CALDAV) {
	ensure_ns(avail_ns, NS_CALDAV, root, XML_NS_CALDAV, "C");
    }
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
		flags |= PRIV_INBOX;
	    else if (rlen > 7 && !strcmp(p-7, SCHED_OUTBOX))
		flags |= PRIV_OUTBOX;

	    add_privs(err->rights, flags, node, root, avail_ns);
	}
	break;

    case CALDAV_UNIQUE_OBJECT:
    case CALDAV_UID_CONFLICT:
	if (err->resource) xml_add_href(node, avail_ns[NS_DAV], err->resource);
	break;
    }

    return root;
}


/* Add a property 'name', of namespace 'ns', with content 'content',
 * and status code/string 'status' to propstat element 'stat'.
 * 'stat' will be created as necessary.
 */
static xmlNodePtr xml_add_prop(long status, xmlNsPtr davns,
			       struct propstat *propstat,
			       xmlNodePtr prop, xmlChar *content,
			       unsigned precond)
{
    xmlNodePtr newprop;

    if (!propstat->root) {
	propstat->root = xmlNewNode(davns, BAD_CAST "propstat");
	xmlNewChild(propstat->root, NULL, BAD_CAST "prop", NULL);
    }

    newprop = xmlNewTextChild(propstat->root->children,
			      prop->ns, prop->name, content);
    propstat->status = status;
    propstat->precond = precond;

    return newprop;
}


/* Add a response tree to 'root' for the specified href and 
   either error code or property list */
int xml_add_response(struct propfind_ctx *fctx, long code)
{
    xmlNodePtr resp;

    resp = xmlNewChild(fctx->root, NULL, BAD_CAST "response", NULL);
    if (!resp) {
	*fctx->errstr = "Unable to add response XML element";
	*fctx->ret = HTTP_SERVER_ERROR;
	return HTTP_SERVER_ERROR;
    }
    xml_add_href(resp, NULL, fctx->req_tgt->path);

    if (!code) {
	struct propstat propstat[NUM_PROPSTAT];
	struct propfind_entry_list *e;
	int i, have_propstat = 0;

	memset(propstat, 0, NUM_PROPSTAT * sizeof(struct propstat));

	/* Process each property in the linked list */
	for (e = fctx->elist; e; e = e->next) {
	    if (e->get) {
		e->get(e->prop, fctx, resp, propstat, e->rock);
	    }
	    else {
		xml_add_prop(HTTP_NOT_FOUND, fctx->ns[NS_DAV],
			     &propstat[PROPSTAT_NOTFOUND], e->prop, NULL, 0);
	    }
	}

	/* Add status and optional error to the propstat elements
	   and then add them to response element */
	for (i = 0; i < NUM_PROPSTAT; i++) {
	    struct propstat *stat = &propstat[i];

	    if (stat->root) {
		if ((stat->status == HTTP_NOT_FOUND) &&
		    (fctx->prefer & PREFER_MIN)) {
		    xmlFreeNode(stat->root);
		}
		else {
		    have_propstat = 1;

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

	if (!have_propstat) {
	    /* Didn't include any propstat elements, so add a status element */
	    code = HTTP_OK;
	}
    }

    if (code) {
	xmlNewChild(resp, NULL, BAD_CAST "status",
		    BAD_CAST http_statusline(code));
    }

    fctx->record = NULL;

    return 0;
}


/* Callback to fetch DAV:add-member */
static int propfind_addmember(xmlNodePtr prop,
			      struct propfind_ctx *fctx,
			      xmlNodePtr resp __attribute__((unused)),
			      struct propstat propstat[],
			      void *rock __attribute__((unused)))
{
    if (fctx->req_tgt->collection) {
	xmlNodePtr node;
	size_t len;

	node = xml_add_prop(HTTP_OK, fctx->ns[NS_DAV], &propstat[PROPSTAT_OK],
			    prop, NULL, 0);

	len = fctx->req_tgt->resource ?
	    (size_t) (fctx->req_tgt->resource - fctx->req_tgt->path) :
	    strlen(fctx->req_tgt->path);
	buf_reset(&fctx->buf);
	buf_printf(&fctx->buf, "%.*s", len, fctx->req_tgt->path);

	xml_add_href(node, NULL, buf_cstring(&fctx->buf));
    }
    else {
	xml_add_prop(HTTP_NOT_FOUND, fctx->ns[NS_DAV],
		     &propstat[PROPSTAT_NOTFOUND], prop, NULL, 0);
    }

    return 0;
}


/* Callback to fetch DAV:getcontentlength */
static int propfind_getlength(xmlNodePtr prop,
			      struct propfind_ctx *fctx,
			      xmlNodePtr resp __attribute__((unused)),
			      struct propstat propstat[],
			      void *rock __attribute__((unused)))
{
    uint32_t len = 0;

    if (fctx->record) len = fctx->record->size - fctx->record->header_size;

    buf_reset(&fctx->buf);
    buf_printf(&fctx->buf, "%u", len);
    xml_add_prop(HTTP_OK, fctx->ns[NS_DAV], &propstat[PROPSTAT_OK],
		 prop, BAD_CAST buf_cstring(&fctx->buf), 0);

    return 0;
}


/* Callback to fetch DAV:getetag */
static int propfind_getetag(xmlNodePtr prop,
			    struct propfind_ctx *fctx,
			    xmlNodePtr resp __attribute__((unused)),
			    struct propstat propstat[],
			    void *rock __attribute__((unused)))
{
    if (fctx->record) {
	/* add DQUOTEs */
	buf_reset(&fctx->buf);
	buf_printf(&fctx->buf, "\"%s\"",
		   message_guid_encode(&fctx->record->guid));

	xml_add_prop(HTTP_OK, fctx->ns[NS_DAV], &propstat[PROPSTAT_OK],
		     prop, BAD_CAST buf_cstring(&fctx->buf), 0);
    }
    else {
	xml_add_prop(HTTP_NOT_FOUND, fctx->ns[NS_DAV],
		     &propstat[PROPSTAT_NOTFOUND], prop, NULL, 0);
    }

    return 0;
}


/* Callback to fetch DAV:getlastmodified */
static int propfind_getlastmod(xmlNodePtr prop,
			       struct propfind_ctx *fctx,
			       xmlNodePtr resp __attribute__((unused)),
			       struct propstat propstat[],
			       void *rock __attribute__((unused)))
{
    if (fctx->record) {
	buf_ensure(&fctx->buf, 80);
	rfc822date_gen(fctx->buf.s, fctx->buf.alloc,
		       fctx->record->internaldate);

	xml_add_prop(HTTP_OK, fctx->ns[NS_DAV], &propstat[PROPSTAT_OK],
		     prop, BAD_CAST fctx->buf.s, 0);
    }
    else {
	xml_add_prop(HTTP_NOT_FOUND, fctx->ns[NS_DAV],
		     &propstat[PROPSTAT_NOTFOUND], prop, NULL, 0);
    }

    return 0;
}


/* Callback to fetch DAV:resourcetype */
static int propfind_restype(xmlNodePtr prop,
			    struct propfind_ctx *fctx,
			    xmlNodePtr resp,
			    struct propstat propstat[],
			    void *rock __attribute__((unused)))
{
    xmlNodePtr node = xml_add_prop(HTTP_OK, fctx->ns[NS_DAV],
				   &propstat[PROPSTAT_OK], prop, NULL, 0);

    if ((fctx->req_tgt->namespace != URL_NS_DEFAULT) && !fctx->record) {
	xmlNewChild(node, NULL, BAD_CAST "collection", NULL);

	switch (fctx->req_tgt->namespace) {
	case URL_NS_PRINCIPAL:
	    if (fctx->req_tgt->user)
		xmlNewChild(node, NULL, BAD_CAST "principal", NULL);
	    break;

	case URL_NS_CALENDAR:
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
	    break;
#if 0
	case URL_NS_ADDRESSBOOK:
	    if (fctx->req_tgt->collection) {
		ensure_ns(fctx->ns, NS_CARDDAV, resp->parent,
			  XML_NS_CARDDAV, "C");
		xmlNewChild(node, fctx->ns[NS_CARDDAV],
			    BAD_CAST "addressbook", NULL);
	    }
	    break;
#endif
	}
    }

    return 0;
}


/* Callback to "write" resourcetype property */
static int proppatch_restype(xmlNodePtr prop, unsigned set,
			     struct proppatch_ctx *pctx,
			     struct propstat propstat[],
			     void *rock __attribute__((unused)))
{
    unsigned precond = 0;

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
	    xml_add_prop(HTTP_OK, pctx->ns[NS_DAV], &propstat[PROPSTAT_OK],
			 prop, NULL, 0);

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
		 prop, NULL, precond);
	     
    *pctx->ret = HTTP_FORBIDDEN;

    return 0;
}


/* Callback to fetch DAV:sync-token and CS:getctag */
static int propfind_sync_token(xmlNodePtr prop,
			       struct propfind_ctx *fctx,
			       xmlNodePtr resp __attribute__((unused)),
			       struct propstat propstat[],
			       void *rock __attribute__((unused)))
{
    if (fctx->mailbox && !fctx->record) {
	buf_reset(&fctx->buf);
	buf_printf(&fctx->buf, XML_NS_CYRUS "sync/%u-" MODSEQ_FMT,
		   fctx->mailbox->i.uidvalidity,
		   fctx->mailbox->i.highestmodseq);

	xml_add_prop(HTTP_OK, fctx->ns[NS_DAV], &propstat[PROPSTAT_OK],
		     prop, BAD_CAST buf_cstring(&fctx->buf), 0);
    }
    else {
	xml_add_prop(HTTP_NOT_FOUND, fctx->ns[NS_DAV],
		     &propstat[PROPSTAT_NOTFOUND], prop, NULL, 0);
    }

    return 0;
}


/* Callback to fetch DAV:supported-report-set */
static int propfind_reportset(xmlNodePtr prop,
			      struct propfind_ctx *fctx,
			      xmlNodePtr resp,
			      struct propstat propstat[],
			      void *rock __attribute__((unused)))
{
    xmlNodePtr s, r, top;

    top = xml_add_prop(HTTP_OK, fctx->ns[NS_DAV], &propstat[PROPSTAT_OK],
		       prop, NULL, 0);

    if ((fctx->req_tgt->namespace == URL_NS_CALENDAR ||
	 fctx->req_tgt->namespace == URL_NS_ADDRESSBOOK) &&
	fctx->req_tgt->collection && !fctx->req_tgt->resource) {
	s = xmlNewChild(top, NULL, BAD_CAST "supported-report", NULL);
	r = xmlNewChild(s, NULL, BAD_CAST "report", NULL);
	ensure_ns(fctx->ns, NS_DAV, resp->parent, XML_NS_DAV, "D");
	xmlNewChild(r, fctx->ns[NS_DAV], BAD_CAST "sync-collection", NULL);
    }

    if (fctx->req_tgt->namespace == URL_NS_CALENDAR) {
	s = xmlNewChild(top, NULL, BAD_CAST "supported-report", NULL);
	r = xmlNewChild(s, NULL, BAD_CAST "report", NULL);
	ensure_ns(fctx->ns, NS_CALDAV, resp->parent, XML_NS_CALDAV, "C");
	xmlNewChild(r, fctx->ns[NS_CALDAV], BAD_CAST "calendar-query", NULL);

	s = xmlNewChild(top, NULL, BAD_CAST "supported-report", NULL);
	r = xmlNewChild(s, NULL, BAD_CAST "report", NULL);
	ensure_ns(fctx->ns, NS_CALDAV, resp->parent, XML_NS_CALDAV, "C");
	xmlNewChild(r, fctx->ns[NS_CALDAV], BAD_CAST "calendar-multiget", NULL);

	s = xmlNewChild(top, NULL, BAD_CAST "supported-report", NULL);
	r = xmlNewChild(s, NULL, BAD_CAST "report", NULL);
	ensure_ns(fctx->ns, NS_CALDAV, resp->parent, XML_NS_CALDAV, "C");
	xmlNewChild(r, fctx->ns[NS_CALDAV], BAD_CAST "free-busy-query", NULL);
    }

    return 0;
}


/* Callback to fetch DAV:principalurl */
static int propfind_principalurl(xmlNodePtr prop,
				 struct propfind_ctx *fctx,
				 xmlNodePtr resp __attribute__((unused)),
				 struct propstat propstat[],
				 void *rock __attribute__((unused)))
{
    xmlNodePtr node;

    if (fctx->req_tgt->namespace != URL_NS_PRINCIPAL) {
	xml_add_prop(HTTP_NOT_FOUND, fctx->ns[NS_DAV],
		     &propstat[PROPSTAT_NOTFOUND], prop, NULL, 0);
    }
    else {
	node = xml_add_prop(HTTP_OK, fctx->ns[NS_DAV], &propstat[PROPSTAT_OK],
			    prop, NULL, 0);

	buf_reset(&fctx->buf);
	if (fctx->req_tgt->user) {
	    buf_printf(&fctx->buf, "/principals/user/%.*s/",
		       fctx->req_tgt->userlen, fctx->req_tgt->user);
	}

	xml_add_href(node, NULL, buf_cstring(&fctx->buf));
    }

    return 0;
}


/* Callback to fetch DAV:owner */
static int propfind_owner(xmlNodePtr prop,
			  struct propfind_ctx *fctx,
			  xmlNodePtr resp __attribute__((unused)),
			  struct propstat propstat[],
			  void *rock __attribute__((unused)))
{
    xmlNodePtr node;

    node = xml_add_prop(HTTP_OK, fctx->ns[NS_DAV], &propstat[PROPSTAT_OK],
			prop, NULL, 0);

    if ((fctx->req_tgt->namespace == URL_NS_CALENDAR) && fctx->req_tgt->user) {
	buf_reset(&fctx->buf);
	buf_printf(&fctx->buf, "/principals/user/%.*s/",
		   fctx->req_tgt->userlen, fctx->req_tgt->user);

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
static int propfind_supprivset(xmlNodePtr prop,
			       struct propfind_ctx *fctx,
			       xmlNodePtr resp,
			       struct propstat propstat[],
			       void *rock __attribute__((unused)))
{
    xmlNodePtr set, all, agg, write;

    set = xml_add_prop(HTTP_OK, fctx->ns[NS_DAV], &propstat[PROPSTAT_OK],
		       prop, NULL, 0);

    all = add_suppriv(set, "all", NULL, 0, "Any operation");

    agg = add_suppriv(all, "read", NULL, 0, "Read any object");
    add_suppriv(agg, "read-current-user-privilege-set", NULL, 1,
		"Read current user privilege set");

    ensure_ns(fctx->ns, NS_CALDAV, resp->parent, XML_NS_CALDAV, "C");
    add_suppriv(agg, "read-free-busy", fctx->ns[NS_CALDAV], 0,
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

    if (!strcmp(fctx->req_tgt->collection, SCHED_INBOX)) {
	ensure_ns(fctx->ns, NS_CALDAV, resp->parent, XML_NS_CALDAV, "C");
	agg = add_suppriv(all, "schedule-deliver", fctx->ns[NS_CALDAV], 0,
			  "Deliver scheduling messages");
	add_suppriv(agg, "schedule-deliver-invite", fctx->ns[NS_CALDAV], 1,
			  "Deliver scheduling messages from Organizers");
	add_suppriv(agg, "schedule-deliver-reply", fctx->ns[NS_CALDAV], 1,
			  "Deliver scheduling messages from Attendees");
	add_suppriv(agg, "schedule-query-freebusy", fctx->ns[NS_CALDAV], 1,
			  "Accept freebusy requests");
    }
    else if (!strcmp(fctx->req_tgt->collection, SCHED_OUTBOX)) {
	ensure_ns(fctx->ns, NS_CALDAV, resp->parent, XML_NS_CALDAV, "C");
	agg = add_suppriv(all, "schedule-send", fctx->ns[NS_CALDAV], 0,
			  "Send scheduling messages");
	add_suppriv(agg, "schedule-send-invite", fctx->ns[NS_CALDAV], 1,
			  "Send scheduling messages by Organizers");
	add_suppriv(agg, "schedule-send-reply", fctx->ns[NS_CALDAV], 1,
			  "Send scheduling messages by Attendees");
	add_suppriv(agg, "schedule-send-freebusy", fctx->ns[NS_CALDAV], 1,
			  "Submit freebusy requests");
    }

    return 0;
}


/* Callback to fetch DAV:current-user-principal */
static int propfind_curprin(xmlNodePtr prop,
			    struct propfind_ctx *fctx,
			    xmlNodePtr resp __attribute__((unused)),
			    struct propstat propstat[],
			    void *rock __attribute__((unused)))
{
    xmlNodePtr node;

    node = xml_add_prop(HTTP_OK, fctx->ns[NS_DAV], &propstat[PROPSTAT_OK],
			prop, NULL, 0);

    if (fctx->userid) {
	buf_reset(&fctx->buf);
	buf_printf(&fctx->buf, "/principals/user/%s/", fctx->userid);
	xml_add_href(node, NULL, buf_cstring(&fctx->buf));
    }
    else {
	xmlNewChild(node, NULL, BAD_CAST "unauthenticated", NULL);
    }

    return 0;
}


static int add_privs(int rights, unsigned flags,
		     xmlNodePtr parent, xmlNodePtr root, xmlNsPtr *ns)
{
    xmlNodePtr priv;

    if ((rights & DACL_ALL) == DACL_ALL) {
	priv = xmlNewChild(parent, NULL, BAD_CAST "privilege", NULL);
	xmlNewChild(priv, NULL, BAD_CAST "all", NULL);
    }
    if ((rights & DACL_READ) == DACL_READ) {
	priv = xmlNewChild(parent, NULL, BAD_CAST "privilege", NULL);
	xmlNewChild(priv, NULL, BAD_CAST "read", NULL);
	if (flags & PRIV_IMPLICIT) rights |= DACL_READFB;
    }
    if (rights & DACL_READFB) {
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
	priv = xmlNewChild(parent, NULL, BAD_CAST "privilege", NULL);
	ensure_ns(ns, NS_CALDAV, root, XML_NS_CALDAV, "C");
	if (flags & PRIV_INBOX)
	    xmlNewChild(priv, ns[NS_CALDAV], BAD_CAST "schedule-deliver", NULL);
	else if (flags & PRIV_OUTBOX)
	    xmlNewChild(priv, ns[NS_CALDAV], BAD_CAST "schedule-send", NULL);
    }

    return 0;
}


/* Callback to fetch DAV:current-user-privilege-set */
static int propfind_curprivset(xmlNodePtr prop,
			       struct propfind_ctx *fctx,
			       xmlNodePtr resp,
			       struct propstat propstat[],
			       void *rock __attribute__((unused)))
{
    int rights;
    unsigned flags = PRIV_IMPLICIT;

    if (!fctx->mailbox) {
	xml_add_prop(HTTP_NOT_FOUND, fctx->ns[NS_DAV],
		     &propstat[PROPSTAT_NOTFOUND], prop, NULL, 0);
    }
    else if (((rights =
	       cyrus_acl_myrights(fctx->authstate, fctx->mailbox->acl))
	      & DACL_READ) != DACL_READ) {
	xml_add_prop(HTTP_UNAUTHORIZED, fctx->ns[NS_DAV],
		     &propstat[PROPSTAT_UNAUTH], prop, NULL, 0);
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
	set = xml_add_prop(HTTP_OK, fctx->ns[NS_DAV], &propstat[PROPSTAT_OK],
			   prop, NULL, 0);

	if (!strcmp(fctx->req_tgt->collection, SCHED_INBOX))
	    flags |= PRIV_INBOX;
	else if (!strcmp(fctx->req_tgt->collection, SCHED_OUTBOX))
	    flags |= PRIV_OUTBOX;

	add_privs(rights, flags, set, resp->parent, fctx->ns);
    }

    return 0;
}


/* Callback to fetch DAV:acl */
static int propfind_acl(xmlNodePtr prop,
			struct propfind_ctx *fctx,
			xmlNodePtr resp,
			struct propstat propstat[],
			void *rock __attribute__((unused)))
{
    int rights;

    if (!fctx->mailbox) {
	xml_add_prop(HTTP_NOT_FOUND, fctx->ns[NS_DAV],
		     &propstat[PROPSTAT_NOTFOUND], prop, NULL, 0);
    }
    else if (!((rights =
		cyrus_acl_myrights(fctx->authstate, fctx->mailbox->acl))
	       & DACL_ADMIN)) {
	xml_add_prop(HTTP_UNAUTHORIZED, fctx->ns[NS_DAV],
		     &propstat[PROPSTAT_UNAUTH], prop, NULL, 0);
    }
    else {
	xmlNodePtr acl;
	char *aclstr, *userid;
	unsigned flags = PRIV_IMPLICIT;

	if (fctx->req_tgt->collection) {
	    if (!strcmp(fctx->req_tgt->collection, SCHED_INBOX))
		flags |= PRIV_INBOX;
	    else if (!strcmp(fctx->req_tgt->collection, SCHED_OUTBOX))
		flags |= PRIV_OUTBOX;
	}

	/* Start the acl XML response */
	acl = xml_add_prop(HTTP_OK, fctx->ns[NS_DAV], &propstat[PROPSTAT_OK],
			   prop, NULL, 0);

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
		buf_printf(&fctx->buf, "/principals/user/%s/", userid);
		xml_add_href(node, NULL, buf_cstring(&fctx->buf));
	    }

	    node = xmlNewChild(ace, NULL,
			       BAD_CAST (deny ? "deny" : "grant"), NULL);
	    add_privs(rights, flags, node, resp->parent, fctx->ns);

	    if (fctx->req_tgt->resource) {
		node = xmlNewChild(ace, NULL, BAD_CAST "inherited", NULL);
		buf_reset(&fctx->buf);
		buf_printf(&fctx->buf, "%.*s",
			   fctx->req_tgt->resource - fctx->req_tgt->path,
			   fctx->req_tgt->path);
		xml_add_href(node, NULL, buf_cstring(&fctx->buf));
	    }

	    userid = nextid;
	}

	if (aclstr) free(aclstr);
    }

    return 0;
}


/* Callback to fetch DAV:acl-restrictions */
static int propfind_aclrestrict(xmlNodePtr prop,
				struct propfind_ctx *fctx,
				xmlNodePtr resp __attribute__((unused)),
				struct propstat propstat[],
				void *rock __attribute__((unused)))
{
    xmlNodePtr node;

    node = xml_add_prop(HTTP_OK, fctx->ns[NS_DAV], &propstat[PROPSTAT_OK],
			prop, NULL, 0);

    xmlNewChild(node, NULL, BAD_CAST "no-invert", NULL);

    return 0;
}


/* Callback to fetch DAV:principal-collection-set */
static int propfind_princolset(xmlNodePtr prop,
			       struct propfind_ctx *fctx,
			       xmlNodePtr resp __attribute__((unused)),
			       struct propstat propstat[],
			       void *rock __attribute__((unused)))
{
    xmlNodePtr node;

    node = xml_add_prop(HTTP_OK, fctx->ns[NS_DAV], &propstat[PROPSTAT_OK],
			prop, NULL, 0);

    xmlNewChild(node, NULL, BAD_CAST "href", BAD_CAST "/principals/");

    return 0;
}


/* Callback to fetch DAV:quota-available-bytes and DAV:quota-used-bytes */
static int propfind_quota(xmlNodePtr prop,
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
	char mboxname[MAX_MAILBOX_BUFFER];
	
	(void) target_to_mboxname(fctx->req_tgt, mboxname);
	if (quota_findroot(foundroot, sizeof(foundroot), mboxname)) {
	    qr = foundroot;
	}
    }

    if (qr) {
	if (!fctx->quota.root ||
	    strcmp(fctx->quota.root, qr)) {
	    /* Different quotaroot - read it */

	    syslog(LOG_DEBUG, "reading quota for '%s'", qr);

	    fctx->quota.root = strcpy(prevroot, qr);

	    quota_read(&fctx->quota, NULL, 0);
	}

	buf_reset(&fctx->buf);
	if (!xmlStrcmp(prop->name, BAD_CAST "quota-available-bytes")) {
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
		     prop, BAD_CAST buf_cstring(&fctx->buf), 0);
    }
    else {
	xml_add_prop(HTTP_NOT_FOUND, fctx->ns[NS_DAV],
		     &propstat[PROPSTAT_NOTFOUND], prop, NULL, 0);
    }

    return 0;
}


/* Callback to fetch CALDAV:calendar-data */
static int propfind_caldata(xmlNodePtr prop,
			    struct propfind_ctx *fctx,
			    xmlNodePtr resp,
			    struct propstat propstat[],
			    void *rock __attribute__((unused)))
{
    ensure_ns(fctx->ns, NS_CALDAV, resp->parent, XML_NS_CALDAV, "C");
    if (fctx->record) {
	xmlNodePtr data;

	if (!fctx->msg_base) {
	    mailbox_map_message(fctx->mailbox, fctx->record->uid,
				&fctx->msg_base, &fctx->msg_size);
	}

	data = xml_add_prop(HTTP_OK, fctx->ns[NS_DAV], &propstat[PROPSTAT_OK],
			    prop, NULL, 0);
	xmlAddChild(data,
		    xmlNewCDataBlock(fctx->root->doc,
				     BAD_CAST fctx->msg_base +
				     fctx->record->header_size,
				     fctx->record->size -
				     fctx->record->header_size));
    }
    else {
	xml_add_prop(HTTP_NOT_FOUND, fctx->ns[NS_DAV],
		     &propstat[PROPSTAT_NOTFOUND], prop, NULL, 0);
    }

    return 0;
}


/* Callback to fetch CALDAV:calendar-home-set,
 * CALDAV:schedule-inbox-URL, CALDAV:schedule-outbox-URL,
 * and CALDAV:schedule-default-calendar-URL
 */
static int propfind_calurl(xmlNodePtr prop,
			   struct propfind_ctx *fctx,
			   xmlNodePtr resp,
			   struct propstat propstat[],
			   void *rock)
{
    xmlNodePtr node;
    const char *cal = (const char *) rock;

    ensure_ns(fctx->ns, NS_CALDAV, resp->parent, XML_NS_CALDAV, "C");
    if (fctx->userid &&
	/* sched-def-cal-URL only defined on sched-inbox-URL */
	((fctx->req_tgt->namespace == URL_NS_CALENDAR &&
	  fctx->req_tgt->collection && cal &&
	  !strcmp(fctx->req_tgt->collection, SCHED_INBOX) &&
	  !strcmp(cal, SCHED_DEFAULT))
	 /* others only defined on principals */
	 || (fctx->req_tgt->namespace == URL_NS_PRINCIPAL))) {
	node = xml_add_prop(HTTP_OK, fctx->ns[NS_DAV], &propstat[PROPSTAT_OK],
			    prop, NULL, 0);

	buf_reset(&fctx->buf);
	buf_printf(&fctx->buf, "/calendars/user/%s/%s", fctx->userid,
		   cal ? cal : "");

	xml_add_href(node, fctx->ns[NS_DAV], buf_cstring(&fctx->buf));
    }
    else {
	xml_add_prop(HTTP_NOT_FOUND, fctx->ns[NS_DAV],
		     &propstat[PROPSTAT_NOTFOUND], prop, NULL, 0);
    }

    return 0;
}


/* Callback to fetch CALDAV:supported-calendar-component-set */
static int propfind_calcompset(xmlNodePtr prop,
			       struct propfind_ctx *fctx,
			       xmlNodePtr resp __attribute__((unused)),
			       struct propstat propstat[],
			       void *rock __attribute__((unused)))
{
    struct annotation_data attrib;
    const char *value = NULL;
    unsigned long types;
    int r = 0;

    if ((fctx->req_tgt->namespace == URL_NS_CALENDAR) &&
	fctx->req_tgt->collection && !fctx->req_tgt->resource) {
	const char *prop_annot =
	    ANNOT_NS "CALDAV:supported-calendar-component-set";

	if (!(r = annotatemore_lookup(fctx->mailbox->name, prop_annot,
				      /* shared */ "", &attrib))
	    && attrib.value) {
	    value = attrib.value;
	}
    }

    if (r) {
	xml_add_prop(HTTP_SERVER_ERROR, fctx->ns[NS_DAV],
		     &propstat[PROPSTAT_ERROR], prop, NULL, 0);
    }
    else if (value && (types = strtoul(value, NULL, 10))) {
	xmlNodePtr set, node;
	const struct cal_comp_t *comp;

	set = xml_add_prop(HTTP_OK, fctx->ns[NS_DAV], &propstat[PROPSTAT_OK],
			   prop, NULL, 0);
	/* Create "comp" elements from the stored bitmask */
	for (comp = cal_comps; comp->name; comp++) {
	    if (types & comp->type) {
		node = xmlNewChild(set, fctx->ns[NS_CALDAV],
				   BAD_CAST "comp", NULL);
		xmlNewProp(node, BAD_CAST "name", BAD_CAST comp->name);
	    }
	}
    }
    else {
	xml_add_prop(HTTP_NOT_FOUND, fctx->ns[NS_DAV],
		     &propstat[PROPSTAT_NOTFOUND], prop, NULL, 0);
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

    if ((pctx->req_tgt->namespace == URL_NS_CALENDAR) &&
	set && pctx->meth[0] == 'M') {
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
		xml_add_prop(HTTP_OK, pctx->ns[NS_DAV],
			     &propstat[PROPSTAT_OK], prop, NULL, 0);
	    }
	    else {
		xml_add_prop(HTTP_SERVER_ERROR, pctx->ns[NS_DAV],
			     &propstat[PROPSTAT_ERROR], prop, NULL, 0);
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
		 prop, NULL, precond);
	     
    *pctx->ret = HTTP_FORBIDDEN;

    return 0;
}

#ifdef WITH_CALDAV_SCHED
/* Callback to fetch CALDAV:schedule-tag */
static int propfind_schedtag(xmlNodePtr prop,
			     struct propfind_ctx *fctx,
			     xmlNodePtr resp,
			     struct propstat propstat[],
			     void *rock __attribute__((unused)))
{
    ensure_ns(fctx->ns, NS_CALDAV, resp->parent, XML_NS_CALDAV, "C");
    if (fctx->cdata->sched_tag) {
	/* add DQUOTEs */
	buf_reset(&fctx->buf);
	buf_printf(&fctx->buf, "\"%s\"", fctx->cdata->sched_tag);

	xml_add_prop(HTTP_OK, fctx->ns[NS_DAV], &propstat[PROPSTAT_OK],
		     prop, BAD_CAST buf_cstring(&fctx->buf), 0);
    }
    else {
	xml_add_prop(HTTP_NOT_FOUND, fctx->ns[NS_DAV],
		     &propstat[PROPSTAT_NOTFOUND], prop, NULL, 0);
    }

    return 0;
}


/* Callback to fetch CALDAV:calendar-user-address-set */
static int propfind_caluseraddr(xmlNodePtr prop,
				struct propfind_ctx *fctx,
				xmlNodePtr resp,
				struct propstat propstat[],
				void *rock __attribute__((unused)))
{
    xmlNodePtr node;

    ensure_ns(fctx->ns, NS_CALDAV, resp->parent, XML_NS_CALDAV, "C");
    if (fctx->userid) {
	node = xml_add_prop(HTTP_OK, fctx->ns[NS_DAV], &propstat[PROPSTAT_OK],
			    prop, NULL, 0);

	/* XXX  This needs to be done via an LDAP/DB lookup */
	buf_reset(&fctx->buf);
	buf_printf(&fctx->buf, "mailto:%s@%s", fctx->userid, config_servername);

	xmlNewChild(node, fctx->ns[NS_DAV], BAD_CAST "href",
		    BAD_CAST buf_cstring(&fctx->buf));
    }
    else {
	xml_add_prop(HTTP_NOT_FOUND, fctx->ns[NS_DAV],
		     &propstat[PROPSTAT_NOTFOUND], prop, NULL, 0);
    }

    return 0;
}


/* Callback to fetch CALDAV:schedule-calendar-transp */
static int propfind_caltransp(xmlNodePtr prop,
			      struct propfind_ctx *fctx,
			      xmlNodePtr resp,
			      struct propstat propstat[],
			      void *rock __attribute__((unused)))
{
    struct annotation_data attrib;
    const char *value = NULL;
    int r = 0;

    if ((fctx->req_tgt->namespace == URL_NS_CALENDAR) &&
	fctx->req_tgt->collection && !fctx->req_tgt->resource) {
	const char *prop_annot =
	    ANNOT_NS "CALDAV:schedule-calendar-transp";

	if (!(r = annotatemore_lookup(fctx->mailbox->name, prop_annot,
				      /* shared */ "", &attrib))
	    && attrib.value) {
	    value = attrib.value;
	}
    }

    ensure_ns(fctx->ns, NS_CALDAV, resp->parent, XML_NS_CALDAV, "C");
    if (r) {
	xml_add_prop(HTTP_SERVER_ERROR, fctx->ns[NS_DAV],
		     &propstat[PROPSTAT_ERROR], prop, NULL, 0);
    }
    else if (value) {
	xmlNodePtr node;

	node = xml_add_prop(HTTP_OK, fctx->ns[NS_DAV], &propstat[PROPSTAT_OK],
			    prop, NULL, 0);
	xmlNewChild(node, fctx->ns[NS_CALDAV], BAD_CAST value, NULL);
    }
    else {
	xml_add_prop(HTTP_NOT_FOUND, fctx->ns[NS_DAV],
		     &propstat[PROPSTAT_NOTFOUND], prop, NULL, 0);
    }

    return 0;
}


/* Callback to write schedule-calendar-transp property */
static int proppatch_caltransp(xmlNodePtr prop, unsigned set,
			       struct proppatch_ctx *pctx,
			       struct propstat propstat[],
			       void *rock __attribute__((unused)))
{
    if ((pctx->req_tgt->namespace == URL_NS_CALENDAR) &&
	pctx->req_tgt->collection && !pctx->req_tgt->resource) {
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
				 &propstat[PROPSTAT_CONFLICT], prop, NULL, 0);

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
			 &propstat[PROPSTAT_OK], prop, NULL, 0);
	}
	else {
	    xml_add_prop(HTTP_SERVER_ERROR, pctx->ns[NS_DAV],
			 &propstat[PROPSTAT_ERROR], prop, NULL, 0);
	}
    }
    else {
	xml_add_prop(HTTP_FORBIDDEN, pctx->ns[NS_DAV],
		     &propstat[PROPSTAT_FORBID], prop, NULL, 0);

	*pctx->ret = HTTP_FORBIDDEN;
    }

    return 0;
}
#endif /* WITH_CALDAV_SCHED */

/* Callback to fetch properties from resource header */
static int propfind_fromhdr(xmlNodePtr prop,
			    struct propfind_ctx *fctx,
			    xmlNodePtr resp __attribute__((unused)),
			    struct propstat propstat[],
			    void *hdrname)
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
		xml_add_prop(HTTP_OK, fctx->ns[NS_DAV], &propstat[PROPSTAT_OK],
			     prop, BAD_CAST hdr[0], 0);
	    }

	    spool_free_hdrcache(hdrs);

	    if (hdr) return 0;
	}
    }

    xml_add_prop(HTTP_NOT_FOUND, fctx->ns[NS_DAV], &propstat[PROPSTAT_NOTFOUND],
		 prop, NULL, 0);

    return 0;
}


/* Callback to read a property from annotation DB */
static int propfind_fromdb(xmlNodePtr prop,
			   struct propfind_ctx *fctx,
			   xmlNodePtr resp __attribute__((unused)),
			   struct propstat propstat[],
			   void *ns_prefix)
{
    struct annotation_data attrib;
    xmlNodePtr node;
    int r = 0;

    buf_reset(&fctx->buf);
    if (ns_prefix) {
	buf_printf(&fctx->buf, ANNOT_NS "%s:%s",
		   (const char *) ns_prefix, prop->name);
    }
    else {
	/* "dead" property - use hash of the namespace href as prefix */
	buf_printf(&fctx->buf, ANNOT_NS "%08X:%s",
		   strhash((const char *) prop->ns->href), prop->name);
    }

    memset(&attrib, 0, sizeof(struct annotation_data));

    if (fctx->mailbox && !fctx->record &&
	!(r = annotatemore_lookup(fctx->mailbox->name, buf_cstring(&fctx->buf),
				  /* shared */ "", &attrib))) {
	if (!attrib.value && 
	    !xmlStrcmp(prop->name, BAD_CAST "displayname")) {
	    /* Special case empty displayname -- use last segment of path */
	    attrib.value = strrchr(fctx->mailbox->name, '.') + 1;
	    attrib.size = strlen(attrib.value);
	}
    }

    if (r) {
	node = xml_add_prop(HTTP_SERVER_ERROR, fctx->ns[NS_DAV],
			    &propstat[PROPSTAT_ERROR], prop, NULL, 0);
    }
    else if (attrib.value) {
	node = xml_add_prop(HTTP_OK, fctx->ns[NS_DAV], &propstat[PROPSTAT_OK],
			    prop, NULL, 0);
	xmlAddChild(node, xmlNewCDataBlock(fctx->root->doc,
					   BAD_CAST attrib.value, attrib.size));
    }
    else {
	node = xml_add_prop(HTTP_NOT_FOUND, fctx->ns[NS_DAV],
			    &propstat[PROPSTAT_NOTFOUND], prop, NULL, 0);
    }

    return 0;
}


/* Callback to write a property to annotation DB */
static int proppatch_todb(xmlNodePtr prop, unsigned set,
			  struct proppatch_ctx *pctx,
			  struct propstat propstat[], void *ns_prefix)
{
    xmlChar *freeme = NULL;
    const char *value = NULL;
    size_t len = 0;
    xmlNodePtr node;
    int r;

    buf_reset(&pctx->buf);
    if (ns_prefix) {
	buf_printf(&pctx->buf, ANNOT_NS "%s:%s",
		   (const char *) ns_prefix, BAD_CAST prop->name);
    }
    else {
	/* "dead" property - use hash of the namespace href as prefix */
	buf_printf(&pctx->buf, ANNOT_NS "%08X:%s",
		   strhash((const char *) prop->ns->href), BAD_CAST prop->name);
    }

    if (set) {
	freeme = xmlNodeGetContent(prop);
	value = (const char *) freeme;
	len = strlen(value);
    }

    if (!(r = annotatemore_write_entry(pctx->mailboxname,
				       buf_cstring(&pctx->buf), /* shared */ "",
				       value, NULL, len, 0,
				       &pctx->tid))) {
	node = xml_add_prop(HTTP_OK, pctx->ns[NS_DAV], &propstat[PROPSTAT_OK],
			    prop, NULL, 0);
    }
    else {
	node = xml_add_prop(HTTP_SERVER_ERROR, pctx->ns[NS_DAV],
			    &propstat[PROPSTAT_ERROR], prop, NULL, 0);
    }

    if (freeme) xmlFree(freeme);

    return 0;
}


/* Array of known "live" properties */
static const struct prop_entry {
    const char *name;			/* Property name */
    const char *ns;			/* Property namespace */
    unsigned allprop;			/* Should we fetch for allprop? */
    int (*get)(xmlNodePtr node,		/* Callback to fetch property */
	       struct propfind_ctx *fctx, xmlNodePtr resp,
	       struct propstat propstat[], void *rock);
    int (*put)(xmlNodePtr prop,		/* Callback to write property */
	       unsigned set, struct proppatch_ctx *pctx,
	       struct propstat propstat[], void *rock);
    void *rock;				/* Add'l data to pass to callback */
} prop_entries[] = {

    /* WebDAV (RFC 4918) properties */
    { "add-member", XML_NS_DAV, 0, propfind_addmember, NULL, NULL },
    { "creationdate", XML_NS_DAV, 1, NULL, NULL, NULL },
    { "displayname", XML_NS_DAV, 1, propfind_fromdb, proppatch_todb, "DAV" },
    { "getcontentlanguage", XML_NS_DAV, 1,
      propfind_fromhdr, NULL, "Content-Language" },
    { "getcontentlength", XML_NS_DAV, 1, propfind_getlength, NULL, NULL },
    { "getcontenttype", XML_NS_DAV, 1, propfind_fromhdr, NULL, "Content-Type" },
    { "getetag", XML_NS_DAV, 1, propfind_getetag, NULL, NULL },
    { "getlastmodified", XML_NS_DAV, 1, propfind_getlastmod, NULL, NULL },
    { "lockdiscovery", XML_NS_DAV, 1, NULL, NULL, NULL },
    { "resourcetype", XML_NS_DAV, 1,
      propfind_restype, proppatch_restype, NULL },
    { "supportedlock", XML_NS_DAV, 1, NULL, NULL, NULL },
    { "sync-token", XML_NS_DAV, 1, propfind_sync_token, NULL, NULL },

    /* WebDAV Versioning (RFC 3253) properties */
    { "supported-report-set", XML_NS_DAV, 0, propfind_reportset, NULL, NULL },

    /* WebDAV ACL (RFC 3744) properties */
    { "alternate-URI-set", XML_NS_DAV, 0, NULL, NULL, NULL },
    { "principal-URL", XML_NS_DAV, 0, propfind_principalurl, NULL, NULL },
    { "group-member-set", XML_NS_DAV, 0, NULL, NULL, NULL },
    { "group-membership", XML_NS_DAV, 0, NULL, NULL, NULL },
    { "owner", XML_NS_DAV, 0, propfind_owner, NULL, NULL },
    { "group", XML_NS_DAV, 0, NULL, NULL, NULL },
    { "supported-privilege-set", XML_NS_DAV, 0,
      propfind_supprivset, NULL, NULL },
    { "current-user-principal", XML_NS_DAV, 0,
      propfind_curprin, NULL, NULL },
    { "current-user-privilege-set", XML_NS_DAV, 0,
      propfind_curprivset, NULL, NULL },
    { "acl", XML_NS_DAV, 0, propfind_acl, NULL, NULL },
    { "acl-restrictions", XML_NS_DAV, 0, propfind_aclrestrict, NULL, NULL },
    { "inherited-acl-set", XML_NS_DAV, 0, NULL, NULL, NULL },
    { "principal-collection-set", XML_NS_DAV, 0,
      propfind_princolset, NULL, NULL },

    /* WebDAV Quota (RFC 4331) properties */
    { "quota-available-bytes", XML_NS_DAV, 0, propfind_quota, NULL, NULL },
    { "quota-used-bytes", XML_NS_DAV, 0, propfind_quota, NULL, NULL },

    /* CalDAV (RFC 4791) properties */
    { "calendar-data", XML_NS_CALDAV, 0, propfind_caldata, NULL, NULL },
    { "calendar-description", XML_NS_CALDAV, 0,
      propfind_fromdb, proppatch_todb, "CALDAV" },
    { "calendar-home-set", XML_NS_CALDAV, 0, propfind_calurl, NULL, NULL },
    { "calendar-timezone", XML_NS_CALDAV, 0,
      propfind_fromdb, proppatch_todb, "CALDAV" },
    { "supported-calendar-component-set", XML_NS_CALDAV, 0,
      propfind_calcompset, proppatch_calcompset, NULL },
    { "supported-calendar-data", XML_NS_CALDAV, 0, NULL, NULL, NULL },
    { "max-resource-size", XML_NS_CALDAV, 0, NULL, NULL, NULL },
    { "min-date-time", XML_NS_CALDAV, 0, NULL, NULL, NULL },
    { "max-date-time", XML_NS_CALDAV, 0, NULL, NULL, NULL },
    { "max-instances", XML_NS_CALDAV, 0, NULL, NULL, NULL },
    { "max-attendees-per-instance", XML_NS_CALDAV, 0, NULL, NULL, NULL },

#ifdef WITH_CALDAV_SCHED
    /* CalDAV Scheduling properties */
    { "schedule-tag", XML_NS_CALDAV, 0, propfind_schedtag, NULL, NULL },
    { "schedule-inbox-URL", XML_NS_CALDAV, 0,
      propfind_calurl, NULL, SCHED_INBOX },
    { "schedule-outbox-URL", XML_NS_CALDAV, 0,
      propfind_calurl, NULL, SCHED_OUTBOX },
    { "schedule-default-calendar-URL", XML_NS_CALDAV, 0,
      propfind_calurl, NULL, SCHED_DEFAULT },
    { "schedule-calendar-transp", XML_NS_CALDAV, 0,
      propfind_caltransp, proppatch_caltransp, NULL },
    { "calendar-user-address-set", XML_NS_CALDAV, 0,
      propfind_caluseraddr, NULL, NULL },
    { "calendar-user-type", XML_NS_CALDAV, 0, NULL, NULL, NULL },
#endif /* WITH_CALDAV_SCHED */

    /* Calendar Server properties */
    { "getctag", XML_NS_CS, 1, propfind_sync_token, NULL, NULL },

    /* Apple iCal properties */
    { "calendar-color", XML_NS_ICAL, 0,
      propfind_fromdb, proppatch_todb, "iCAL" },
    { "calendar-order", XML_NS_ICAL, 0,
      propfind_fromdb, proppatch_todb, "iCAL" },

    { NULL, NULL, 0, NULL, NULL, NULL }
};


/* Parse the requested properties and create a linked list of fetch callbacks.
 * The list gets reused for each href if Depth > 0
 */
int preload_proplist(xmlNodePtr proplist, struct propfind_ctx *fctx)
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
		 entry->name && 
		     (strcmp((const char *) prop->name, entry->name) ||
		      strcmp((const char *) prop->ns->href, entry->ns));
		 entry++);

	    nentry->prop = prop;
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
	    nentry->next = fctx->elist;
	    fctx->elist = nentry;
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
			     (strcmp((const char *) prop->name, entry->name) ||
			      strcmp((const char *) prop->ns->href, entry->ns));
			 entry++);

		    if (entry->name) {
			if (!entry->put) {
			    /* Protected property */
			    xml_add_prop(HTTP_FORBIDDEN, pctx->ns[NS_DAV],
					 &propstat[PROPSTAT_FORBID],
					 prop, NULL,
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
