/* http_ischedule.c -- Routines for handling iSchedule in httpd
 *
 * Copyright (c) 1994-2012 Carnegie Mellon University.  All rights reserved.
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

#include <config.h>

#include <syslog.h>

#include <libical/ical.h>

#include "dav_prop.h"
#include "global.h"
#include "httpd.h"
#include "http_err.h"
#include "http_proxy.h"
#include "util.h"

extern int busytime_query(struct transaction_t *txn, icalcomponent *comp);
static int meth_get(struct transaction_t *txn);
static int meth_post(struct transaction_t *txn);

const struct namespace_t namespace_ischedule = {
  URL_NS_ISCHEDULE, "/ischedule", "/.well-known/ischedule", 1 /* auth */,
    (ALLOW_READ | ALLOW_POST), HTTP_ISCHEDULE,
    NULL, NULL, NULL, NULL,
    {
	NULL,			/* ACL		*/
	NULL,			/* COPY		*/
	NULL,			/* DELETE	*/
	&meth_get,		/* GET		*/
	&meth_get,		/* HEAD		*/
	NULL,			/* LOCK		*/
	NULL,			/* MKCALENDAR	*/
	NULL,			/* MKCOL	*/
	NULL,			/* MOVE		*/
	&meth_options,		/* OPTIONS	*/
	&meth_post,		/* POST		*/
	NULL,			/* PROPFIND	*/
	NULL,			/* PROPPATCH	*/
	NULL,			/* PUT		*/
	NULL,			/* REPORT	*/
	NULL			/* UNLOCK	*/
    }
};


static int meth_get(struct transaction_t *txn)
{
    int ret = 0, r;
    xmlDocPtr doc;
    xmlNodePtr root, capa, node, comp, meth;
    xmlNsPtr ns;

    /* We don't handle GET on a anything other than ?query=capabilities */
    if (strcmp(txn->req_tgt.query, "query=capabilities"))
	return HTTP_NOT_FOUND;

    /* Start construction of our query-result */
    if (!(doc = xmlNewDoc(BAD_CAST "1.0")) ||
	!(root = xmlNewNode(NULL, BAD_CAST "query-result")) ||
	!(ns = xmlNewNs(root, BAD_CAST XML_NS_ISCHED, NULL))) {
	ret = HTTP_SERVER_ERROR;
	txn->error.desc = "Unable to create XML response";
	goto done;
    }

    xmlDocSetRootElement(doc, root);
    xmlSetNs(root, ns);

    capa = xmlNewChild(root, NULL, BAD_CAST "capability-set", NULL);

    node = xmlNewChild(capa, NULL, BAD_CAST "supported-version-set", NULL);
    node = xmlNewChild(node, NULL, BAD_CAST "version", BAD_CAST "1.0");

    node = xmlNewChild(capa, NULL,
		       BAD_CAST "supported-scheduling-message-set", NULL);
    comp = xmlNewChild(node, NULL, BAD_CAST "comp", NULL);
    xmlNewProp(comp, BAD_CAST "name", BAD_CAST "VEVENT");
    meth = xmlNewChild(comp, NULL, BAD_CAST "method", NULL);
    xmlNewProp(meth, BAD_CAST "name", BAD_CAST "REQUEST");
    meth = xmlNewChild(comp, NULL, BAD_CAST "method", NULL);
    xmlNewProp(meth, BAD_CAST "name", BAD_CAST "REPLY");
    meth = xmlNewChild(comp, NULL, BAD_CAST "method", NULL);
    xmlNewProp(meth, BAD_CAST "name", BAD_CAST "CANCEL");

    comp = xmlNewChild(node, NULL, BAD_CAST "comp", NULL);
    xmlNewProp(comp, BAD_CAST "name", BAD_CAST "VTODO");
    comp = xmlNewChild(node, NULL, BAD_CAST "comp", NULL);
    xmlNewProp(comp, BAD_CAST "name", BAD_CAST "VFREEBUSY");

    node = xmlNewChild(capa, NULL,
		       BAD_CAST "supported-calendar-data-type", NULL);
    node = xmlNewChild(node, NULL, BAD_CAST "calendar-data-type", NULL);
    xmlNewProp(node, BAD_CAST "content-type", BAD_CAST "text/calendar");
    xmlNewProp(node, BAD_CAST "version", BAD_CAST "2.0");

    node = xmlNewChild(capa, NULL,
		       BAD_CAST "supported-attachment-values", NULL);
    node = xmlNewChild(node, NULL, BAD_CAST "inline-attachment", NULL);

    node = xmlNewChild(capa, NULL,
		       BAD_CAST "supported-recipient-uri-scheme-set", NULL);
    node = xmlNewChild(node, NULL, BAD_CAST "scheme", BAD_CAST "mailto");

    /* Output the XML response */
    if (!ret) xml_response(HTTP_OK, txn, doc);

  done:
    if (doc) xmlFree(doc);

    return ret;
}


static int meth_post(struct transaction_t *txn)
{
    int ret = 0, r;
    const char **hdr;
    icalcomponent *ical, *comp;
    icalcomponent_kind kind = 0;
    icalproperty_method meth = 0;
    icalproperty *prop = NULL;
    const char *uid = NULL;

    /* Check Content-Type */
    if (!(hdr = spool_getheader(txn->req_hdrs, "Content-Type")) ||
	!is_mediatype(hdr[0], "text/calendar")) {
	txn->error.precond = CALDAV_SUPP_DATA;
	return HTTP_BAD_REQUEST;
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
	txn->error.desc = "Missing request body";
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

    ret = busytime_query(txn, comp);

    icalcomponent_free(ical);

    return ret;
}
