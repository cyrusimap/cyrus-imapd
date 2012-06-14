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
#include "map.h"
#include "util.h"
#include "xmalloc.h"

#ifdef WITH_DKIM
#include <dkim.h>

#define TEST

static DKIM_LIB *dkim_lib = NULL;
static struct buf privkey = BUF_INITIALIZER;
static struct buf hdrfield = BUF_INITIALIZER;

static void isched_init(struct buf *serverinfo);
static void isched_shutdown(void);
static void dkim_cachehdr(const char *name, const char *contents, void *rock);
#endif /* WITH_DKIM */

extern int busytime_query(struct transaction_t *txn, icalcomponent *comp);
static int meth_get(struct transaction_t *txn);
static int meth_post(struct transaction_t *txn);

const struct namespace_t namespace_ischedule = {
  URL_NS_ISCHEDULE, "/ischedule", "/.well-known/ischedule", 0 /* auth */,
    (ALLOW_READ | ALLOW_POST), HTTP_ISCHEDULE,
#ifdef WITH_DKIM
    isched_init, NULL, NULL, isched_shutdown,
#else
    NULL, NULL, NULL, NULL,
#endif
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
    int ret = 0;
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
    int ret = 0, r, authd = 0;
    const char **hdr;
    icalcomponent *ical = NULL, *comp;
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

    /* Check authorization */
    if (httpd_userid) authd = httpd_userisadmin;
    else if (spool_getheader(txn->req_hdrs, "DKIM-Signature")) {
#ifdef WITH_DKIM
	DKIM *dkim = NULL;
	DKIM_STAT stat;

	if (dkim_lib &&
	    (dkim = dkim_verify(dkim_lib, NULL /* id */, NULL, &stat))) {
#ifdef TEST
	    /* XXX  Hack for local testing */
	    dkim_query_t qtype = DKIM_QUERY_FILE;
	    struct buf keyfile = BUF_INITIALIZER;

	    stat = dkim_options(dkim_lib, DKIM_OP_SETOPT, DKIM_OPTS_QUERYMETHOD,
				&qtype, sizeof(qtype));

	    buf_printf(&keyfile, "%s/dkim.public", config_dir);
	    stat = dkim_options(dkim_lib, DKIM_OP_SETOPT, DKIM_OPTS_QUERYINFO,
				(void *) buf_cstring(&keyfile),
				buf_len(&keyfile));
#endif
	    spool_enum_hdrcache(txn->req_hdrs, &dkim_cachehdr, dkim);
	    stat = dkim_eoh(dkim);
	    if (stat == DKIM_STAT_OK) {
		stat = dkim_body(dkim, (u_char *) buf_cstring(&txn->req_body),
				 buf_len(&txn->req_body));
		stat = dkim_eom(dkim, NULL);
		if (stat == DKIM_STAT_OK) authd = 1;
	    }

	    dkim_free(dkim);
	}
#else
	syslog(LOG_WARNING, "DKIM-Signature provided, but DKIM isn't supported");
#endif /* WITH_DKIM */
    }

    if (!authd) {
	ret = HTTP_FORBIDDEN;
	goto done;
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
    if (!meth || meth != ICAL_METHOD_REQUEST || !uid || !prop) {
	txn->error.precond = CALDAV_VALID_SCHED;
	ret = HTTP_BAD_REQUEST;
	goto done;
    }

    switch (meth) {
    case ICAL_METHOD_REQUEST:
	switch (kind) {
	case ICAL_VFREEBUSY_COMPONENT:
	    ret = busytime_query(txn, comp);
	    break;

	default:
	    txn->error.precond = CALDAV_VALID_SCHED;
	    ret = HTTP_BAD_REQUEST;
	}
	break;

    default:
	txn->error.precond = CALDAV_VALID_SCHED;
	ret = HTTP_BAD_REQUEST;
    }

  done:
    if (ical) icalcomponent_free(ical);

    return ret;
}


#ifdef WITH_DKIM
static void isched_init(struct buf *serverinfo)
{
    int fd;
    struct buf keypath = BUF_INITIALIZER;
    const char *requiredhdrs[] = { "Content-Type", "Host",
				   "Originator", "Recipient", NULL };
    const char *skiphdrs[] = { "Connection", "Keep-Alive",
			       "Proxy-Authenticate", "Proxy-Authorization",
			       "TE", "Trailer", "Transfer-Encoding",
			       "Upgrade", NULL };
    const char *senderhdrs[] = { "Originator", NULL };
    const char *oversignhdrs[] = { "Recipient", NULL };
    uint32_t ver = dkim_libversion();

    /* Add OpenDKIM version to serverinfo string */
    buf_printf(serverinfo, " OpenDKIM/%u.%u.%u",
	       (ver >> 24) & 0xff, (ver >> 16) & 0xff, (ver >> 8) & 0xff);
    if (ver & 0xff) buf_printf(serverinfo, ".%u", ver & 0xff);

    /* Initialize DKIM library */
    if (!(dkim_lib = dkim_init(NULL, NULL))) {
	syslog(LOG_ERR, "unable to initialize libopendkim");
	return;
    }

    /* Setup iSchedule DKIM options */
    dkim_options(dkim_lib, DKIM_OP_SETOPT, DKIM_OPTS_REQUIREDHDRS,
		 requiredhdrs, sizeof(const char **));
    dkim_options(dkim_lib, DKIM_OP_SETOPT, DKIM_OPTS_SIGNHDRS,
		 requiredhdrs, sizeof(const char **));
    dkim_options(dkim_lib, DKIM_OP_SETOPT, DKIM_OPTS_SKIPHDRS,
		 skiphdrs, sizeof(const char **));
    dkim_options(dkim_lib, DKIM_OP_SETOPT, DKIM_OPTS_SENDERHDRS,
		 senderhdrs, sizeof(const char **));
    if (dkim_libfeature(dkim_lib, DKIM_FEATURE_OVERSIGN))
	dkim_options(dkim_lib, DKIM_OP_SETOPT, DKIM_OPTS_OVERSIGNHDRS,
		     oversignhdrs, sizeof(const char **));
    else syslog(LOG_WARNING, "no oversign support in libopendkim");

    /* Fetch DKIM private key for signing */
    buf_printf(&keypath, "%s/dkim.private", config_dir);
    if ((fd = open(buf_cstring(&keypath), O_RDONLY)) != -1) {
	const char *base = NULL;
	unsigned long len = 0;

	map_refresh(fd, 1, &base, &len,
		    MAP_UNKNOWN_LEN, buf_cstring(&keypath), NULL);
	buf_setmap(&privkey, base, len);
	map_free(&base, &len);
	close(fd);
    }
    else {
	syslog(LOG_ERR, "unable to open private key file %s",
	       buf_cstring(&keypath));
    }
    buf_free(&keypath);
}


static void isched_shutdown(void)
{
    buf_free(&privkey);
    buf_free(&hdrfield);
    if (dkim_lib) dkim_close(dkim_lib);
}


static void dkim_cachehdr(const char *name, const char *contents, void *rock)
{
    buf_reset(&hdrfield);
    buf_printf(&hdrfield, "%s:%s", name, contents);

    dkim_header((DKIM *) rock,
		(u_char *) buf_cstring(&hdrfield), buf_len(&hdrfield));
}
#endif /* WITH_DKIM */
