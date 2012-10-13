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

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <errno.h>
#include <syslog.h>

#include <libical/ical.h>

#include "dav_prop.h"
#include "global.h"
#include "httpd.h"
#include "http_err.h"
#include "http_proxy.h"
#include "map.h"
#include "proxy.h"
#include "tok.h"
#include "util.h"
#include "xmalloc.h"
#include "xstrlcpy.h"
#include <sasl/saslutil.h>

#define ISCHED_WELLKNOWN_URI "/.well-known/ischedule"

#ifdef WITH_DKIM
#include <dkim.h>

//#define TEST

#define BASE64_LEN(inlen) ((((inlen) + 2) / 3) * 4)

static DKIM_LIB *dkim_lib = NULL;
static struct buf privkey = BUF_INITIALIZER;
static struct buf tmpbuf = BUF_INITIALIZER;
static struct buf b64req = BUF_INITIALIZER;

static void isched_init(struct buf *serverinfo);
static void isched_shutdown(void);
static void isched_cachehdr(const char *name, const char *contents, void *rock);
#endif /* WITH_DKIM */

extern int busytime_query(struct transaction_t *txn, icalcomponent *comp);
static int isched_capa(struct transaction_t *txn);
static int isched_recv(struct transaction_t *txn);
static int meth_getkey(struct transaction_t *txn);
static void calc_compile_time(struct buf *serverinfo);
static time_t compile_time;

const struct namespace_t namespace_ischedule = {
    URL_NS_ISCHEDULE, "/ischedule", ISCHED_WELLKNOWN_URI, 0 /* auth */,
    (ALLOW_READ | ALLOW_POST | ALLOW_ISCHEDULE),
#ifdef WITH_DKIM
    isched_init, NULL, NULL, isched_shutdown,
#else
    calc_compile_time, NULL, NULL, NULL,
#endif
    {
	{ NULL,			0		},	/* ACL		*/
	{ NULL,			0		},	/* COPY		*/
	{ NULL,			0		},	/* DELETE	*/
	{ &isched_capa,		METH_NOBODY	},	/* GET		*/
	{ &isched_capa,		METH_NOBODY	},	/* HEAD		*/
	{ NULL,			0		},	/* MKCALENDAR	*/
	{ NULL,			0		},	/* MKCOL	*/
	{ NULL,			0		},	/* MOVE		*/
	{ &meth_options,	METH_NOBODY	},	/* OPTIONS	*/
	{ &isched_recv,		0		},	/* POST		*/
	{ NULL,			0		},	/* PROPFIND	*/
	{ NULL,			0		},	/* PROPPATCH	*/
	{ NULL,			0		},	/* PUT		*/
	{ NULL,			0		}	/* REPORT	*/
    }
};

const struct namespace_t namespace_domainkey = {
    URL_NS_DOMAINKEY, "/domainkeys", "/.well-known/domainkey", 0 /* auth */,
    ALLOW_READ, NULL, NULL, NULL, NULL,
    {
	{ NULL,			0		},	/* ACL		*/
	{ NULL,			0		},	/* COPY		*/
	{ NULL,			0		},	/* DELETE	*/
	{ &meth_getkey,		METH_NOBODY	},	/* GET		*/
	{ &meth_getkey,		METH_NOBODY	},	/* HEAD		*/
	{ NULL,			0		},	/* MKCALENDAR	*/
	{ NULL,			0		},	/* MKCOL	*/
	{ NULL,			0		},	/* MOVE		*/
	{ &meth_options,	METH_NOBODY	},	/* OPTIONS	*/
	{ NULL,			0		},	/* POST		*/
	{ NULL,			0		},	/* PROPFIND	*/
	{ NULL,			0		},	/* PROPPATCH	*/
	{ NULL,			0		},	/* PUT		*/
	{ NULL,			0		}	/* REPORT	*/
    }
};


/* Calculate compile time of this file for use as Etag for capabilities */
static void calc_compile_time(struct buf *serverinfo __attribute__((unused)))
{
    struct tm tm;
    char month[4];
    const char *monthname[] = {
	"Jan", "Feb", "Mar", "Apr", "May", "Jun",
	"Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
    };

    memset(&tm, 0, sizeof(struct tm));
    tm.tm_isdst = -1;
    sscanf(__TIME__, "%02d:%02d:%02d", &tm.tm_hour, &tm.tm_min, &tm.tm_sec);
    sscanf(__DATE__, "%s %2d %4d", month, &tm.tm_mday, &tm.tm_year);
    tm.tm_year -= 1900;
    for (tm.tm_mon = 0; tm.tm_mon < 12; tm.tm_mon++) {
	if (!strcmp(month, monthname[tm.tm_mon])) break;
    }

    compile_time = mktime(&tm);
}


/* iSchedule Receiver Capabilities */
static int isched_capa(struct transaction_t *txn)
{
    int precond;
    struct message_guid guid;
    const char *etag;
    xmlNodePtr root, capa, node, comp, meth;
    xmlNsPtr ns[NUM_NAMESPACE];

    /* We don't handle GET on a anything other than ?action=capabilities */
    if (strcmp(txn->req_tgt.query, "action=capabilities"))
	return HTTP_NOT_FOUND;

    /* Generate ETag based on compile date/time of this source file.
     * Extend this to include config file size/mtime if we add run-time options.
     */
    assert(!buf_len(&txn->buf));
    buf_printf(&txn->buf, "%ld", (long) compile_time);
    message_guid_generate(&guid, buf_cstring(&txn->buf), buf_len(&txn->buf));
    etag = message_guid_encode(&guid);

    /* Check any preconditions */
    precond = check_precond(txn->meth, NULL, etag, compile_time, txn->req_hdrs);

    /* We failed a precondition - don't perform the request */
    if (precond != HTTP_OK) return precond;

    /* Fill in Etag and Last-Modified */
    txn->resp_body.etag = etag;
    txn->resp_body.lastmod = compile_time;

    /* Start construction of our query-result */
    if (!(root = init_xml_response("query-result", NS_ISCHED, NULL, ns))) {
	txn->error.desc = "Unable to create XML response\r\n";
	return HTTP_SERVER_ERROR;
    }

    capa = xmlNewChild(root, NULL, BAD_CAST "capabilities", NULL);

    node = xmlNewChild(capa, NULL, BAD_CAST "versions", NULL);
    node = xmlNewChild(node, NULL, BAD_CAST "version", BAD_CAST "1.0");

    node = xmlNewChild(capa, NULL,
		       BAD_CAST "scheduling-messages", NULL);
#if 0
    comp = xmlNewChild(node, NULL, BAD_CAST "component", NULL);
    xmlNewProp(comp, BAD_CAST "name", BAD_CAST "VEVENT");
    meth = xmlNewChild(comp, NULL, BAD_CAST "method", NULL);
    xmlNewProp(meth, BAD_CAST "name", BAD_CAST "REQUEST");
    meth = xmlNewChild(comp, NULL, BAD_CAST "method", NULL);
    xmlNewProp(meth, BAD_CAST "name", BAD_CAST "REPLY");
    meth = xmlNewChild(comp, NULL, BAD_CAST "method", NULL);
    xmlNewProp(meth, BAD_CAST "name", BAD_CAST "CANCEL");

    comp = xmlNewChild(node, NULL, BAD_CAST "component", NULL);
    xmlNewProp(comp, BAD_CAST "name", BAD_CAST "VTODO");
#endif
    comp = xmlNewChild(node, NULL, BAD_CAST "component", NULL);
    xmlNewProp(comp, BAD_CAST "name", BAD_CAST "VFREEBUSY");

    node = xmlNewChild(capa, NULL,
		       BAD_CAST "calendar-data-types", NULL);
    node = xmlNewChild(node, NULL, BAD_CAST "calendar-data-type", NULL);
    xmlNewProp(node, BAD_CAST "content-type", BAD_CAST "text/calendar");
    xmlNewProp(node, BAD_CAST "version", BAD_CAST "2.0");

    node = xmlNewChild(capa, NULL, BAD_CAST "attachments", NULL);
    node = xmlNewChild(node, NULL, BAD_CAST "inline", NULL);

    /* Output the XML response */
    xml_response(HTTP_OK, txn, root->doc);

    xmlFree(root->doc);

    return 0;
}


/* iSchedule Receiver */
static int isched_recv(struct transaction_t *txn)
{
    int ret = 0, r, authd = 0;
    const char **hdr;
    icalcomponent *ical = NULL, *comp;
    icalcomponent_kind kind = 0;
    icalproperty_method meth = 0;
    icalproperty *prop = NULL;
    const char *uid = NULL;

    /* Response should not be cached */
    txn->flags.cc |= CC_NOCACHE;

    /* Check Content-Type */
    if (!(hdr = spool_getheader(txn->req_hdrs, "Content-Type")) ||
	!is_mediatype(hdr[0], "text/calendar")) {
	txn->error.precond = CALDAV_SUPP_DATA;
	return HTTP_BAD_REQUEST;
    }

    /* Read body */
    if (!txn->flags.havebody) {
	txn->flags.havebody = 1;
	r = read_body(httpd_in, txn->req_hdrs, &txn->req_body, 1,
		      &txn->error.desc);
	if (r) {
	    txn->flags.close = 1;
	    return r;
	}
    }

    /* Make sure we have a body */
    if (!buf_len(&txn->req_body)) {
	txn->error.desc = "Missing request body\r\n";
	return HTTP_BAD_REQUEST;
    }

    /* Check authorization */
    if (httpd_userid) {
	/* Allow admins or proxyservers to auth and use iSchedule */
	authd = httpd_userisadmin ||
	    global_authisa(httpd_authstate, IMAPOPT_PROXYSERVERS);
    }
    else if (!spool_getheader(txn->req_hdrs, "DKIM-Signature")) {
	txn->error.desc = "No signature";
    }
    else {
#ifdef WITH_DKIM
	DKIM *dkim = NULL;
	DKIM_STAT stat;
	struct buf *reqline = &tmpbuf;

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
	    /* Process the cached headers and body */
	    spool_enum_hdrcache(txn->req_hdrs, &isched_cachehdr, dkim);
	    stat = dkim_eoh(dkim);
	    if (stat == DKIM_STAT_OK) {
		stat = dkim_body(dkim, (u_char *) buf_cstring(&txn->req_body),
				 buf_len(&txn->req_body));
		stat = dkim_eom(dkim, NULL);
	    }
	    if (stat == DKIM_STAT_OK) authd = 1;
	    else if (stat == DKIM_STAT_CBREJECT) {
		txn->error.desc =
		    "Unable to verify: HTTP request-line mismatch";
	    }
	    else {
		DKIM_SIGINFO *sig = dkim_getsignature(dkim);

		if (sig) {
		    const char *sigerr;

		    if (dkim_sig_getbh(sig) == DKIM_SIGBH_MISMATCH)
			sigerr = "body hash mismatch";
		    else {
			DKIM_SIGERROR err = dkim_sig_geterror(sig);

			sigerr = dkim_sig_geterrorstr(err);
		    }

		    assert(!buf_len(&txn->buf));
		    buf_printf(&txn->buf, "%s: %s",
			       dkim_getresultstr(stat), sigerr);
		    txn->error.desc = buf_cstring(&txn->buf);
		}
		else txn->error.desc = dkim_getresultstr(stat);
	    }

	    dkim_free(dkim);
	}
#else
	syslog(LOG_WARNING, "DKIM-Signature provided, but DKIM isn't supported");
#endif /* WITH_DKIM */
    }

    if (!authd) {
	ret = HTTP_FORBIDDEN;
	txn->error.precond = ISCHED_VERIFICATION_FAILED;
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
	    ret = busytime_query(txn, ical);
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


int isched_send(struct sched_param *sparam, icalcomponent *ical,
		xmlNodePtr *xml)
{
    int r = 0;
    struct backend *be;
    static unsigned send_count = 0;
    static struct buf hdrs = BUF_INITIALIZER;
    const char *body, *uri;
    size_t bodylen;
    icalcomponent *comp;
    icalcomponent_kind kind;
    icalproperty *prop;
    unsigned code;
    struct transaction_t txn;

    *xml = NULL;
    memset(&txn, 0, sizeof(struct transaction_t));

    if (sparam->flags & SCHEDTYPE_REMOTE) uri = ISCHED_WELLKNOWN_URI;
    else uri = namespace_ischedule.prefix;

    /* Open connection to iSchedule receiver */
    be = proxy_findserver(sparam->server, &http_protocol, NULL,
			  &backend_cached, NULL, NULL, httpd_in);
    if (!be) return HTTP_UNAVAILABLE;

    /* Create iSchedule request body */
    body = icalcomponent_as_ical_string(ical);
    bodylen = strlen(body);

    /* Create iSchedule request header */
    buf_reset(&hdrs);
    buf_printf(&hdrs, "Host: %s\r\n", sparam->server);
    buf_printf(&hdrs, "Cache-Control: no-cache, no-transform\r\n");
    if (config_serverinfo == IMAP_ENUM_SERVERINFO_ON) {
	buf_printf(&hdrs, "User-Agent: %s\r\n", buf_cstring(&serverinfo));
    }
    buf_printf(&hdrs, "iSchedule-Version: 1.0\r\n");
    buf_printf(&hdrs, "iSchedule-Message-ID: <cmu-ischedule-%u-%ld-%u@%s>\r\n",
	       getpid(), time(NULL), send_count++, config_servername);
    buf_printf(&hdrs, "Content-Type: text/calendar; charset=utf-8");

    comp = icalcomponent_get_first_real_component(ical);
    kind = icalcomponent_isa(comp);
    buf_printf(&hdrs, "; method=REQUEST; component=%s \r\n",
	       icalcomponent_kind_to_string(kind));

    buf_printf(&hdrs, "Content-Length: %u\r\n", bodylen);

    prop = icalcomponent_get_first_property(comp, ICAL_ORGANIZER_PROPERTY);
    buf_printf(&hdrs, "Originator: %s\r\n", icalproperty_get_organizer(prop));

    for (prop = icalcomponent_get_first_property(comp, ICAL_ATTENDEE_PROPERTY);
	 prop;
	 prop = icalcomponent_get_next_property(comp, ICAL_ATTENDEE_PROPERTY)) {
	buf_printf(&hdrs, "Recipient: %s\r\n", icalproperty_get_attendee(prop));
    }

    buf_printf(&hdrs, "\r\n");

  redirect:
    /* Send request line */
    prot_printf(be->out, "POST %s %s\r\n", uri, HTTP_VERSION);

    if (sparam->flags & SCHEDTYPE_REMOTE) {
#ifdef WITH_DKIM
	DKIM *dkim = NULL;
	DKIM_STAT stat;
	struct buf *reqline = &tmpbuf;
	unsigned char *sig = NULL;
	size_t siglen;

	/* Create iSchedule/DKIM signature */
	if (dkim_lib &&
	    (dkim = dkim_sign(dkim_lib, NULL /* id */, NULL,
			      (dkim_sigkey_t) buf_cstring(&privkey),
			      (const u_char *) config_getstring(IMAPOPT_DKIM_SELECTOR),
			      (const u_char *) config_getstring(IMAPOPT_DKIM_DOMAIN),
			      DKIM_CANON_RELAXED, DKIM_CANON_SIMPLE,
			      DKIM_SIGN_RSASHA256, -1 /* entire body */,
			      &stat))) {

	    /* Add our query method list */
	    stat = dkim_add_querymethod(dkim, "private-exchange", NULL);
	    stat = dkim_add_querymethod(dkim, "http", "well-known");
	    stat = dkim_add_querymethod(dkim, "dns", "txt");

	    /* Process the headers and body */
	    stat = dkim_chunk(dkim,
			      (u_char *) buf_cstring(&hdrs), buf_len(&hdrs));
	    stat = dkim_chunk(dkim, (u_char *) body, bodylen);
	    stat = dkim_chunk(dkim, NULL, 0);
	    stat = dkim_eom(dkim, NULL);

	    /* Generate the signature */
	    stat = dkim_getsighdr_d(dkim, strlen(DKIM_SIGNHEADER) + 2,
				    &sig, &siglen);

	    /* Prepend a DKIM-Signature header */
	    prot_printf(be->out, "%s: %s\r\n", DKIM_SIGNHEADER, sig);

	    dkim_free(dkim);
	}
#else
	syslog(LOG_WARNING, "DKIM-Signature required, but DKIM isn't supported");
#endif /* WITH_DKIM */
    }

    /* Send request headers and body */
    prot_putbuf(be->out, &hdrs);
    prot_write(be->out, body, bodylen);

    /* Read response (req_hdr and req_body are actually the response) */
    r = http_read_response(be, METH_POST, &code, NULL,
			   &txn.req_hdrs, &txn.req_body, 1, &txn.error.desc);
    if (!r) {
	switch (code) {
	case 200:  /* Successful */
	    txn.flags.havebody = 1;
	    r = parse_xml_body(&txn, xml);
	    break;

	case 301:
	case 302:
	case 307:
	case 308:  /* Redirection */
	    uri = spool_getheader(txn.req_hdrs, "Location")[0];
	    goto redirect;

	default:
	    r = HTTP_UNAVAILABLE;
	}
    }

    if (txn.req_hdrs) spool_free_hdrcache(txn.req_hdrs);
    buf_free(&txn.req_body);

    return r;
}


#ifdef WITH_DKIM
static DKIM_CBSTAT isched_get_key(DKIM *dkim, DKIM_SIGINFO *sig,
				  u_char *buf, size_t buflen)
{
    DKIM_CBSTAT stat = DKIM_CBSTAT_NOTFOUND;
    const char *domain, *selector, *query;
    tok_t tok;
    char *type, *opts;

    assert(dkim != NULL);
    assert(sig != NULL);

    domain = (const char *) dkim_sig_getdomain(sig);
    selector = (const char *) dkim_sig_getselector(sig);
    if (!domain || !selector) return DKIM_CBSTAT_ERROR;

    query = (const char *) dkim_sig_gettagvalue(sig, 0, (u_char *) "q");
    if (!query) query = "dns/txt";  /* implicit default */

    /* Parse the q= tag */
    tok_init(&tok, query, ":", 0);
    while ((type = tok_next(&tok))) {
	/* Split type/options */
	if ((opts = strchr(type, '/'))) *opts++ = '\0';

	if (!strcmp(type, "private-exchange")) {
	    const char *prefix = config_getstring(IMAPOPT_HTTPDOCROOT);
	    struct buf path = BUF_INITIALIZER;
	    FILE *f;

	    if (!prefix) continue;

	    buf_setcstr(&path, prefix);
	    buf_printf(&path, "%s/%s/%s",
		       namespace_domainkey.prefix, domain, selector);

	    if (!(f = fopen(buf_cstring(&path), "r"))) {
		syslog(LOG_NOTICE, "%s: fopen(): %s",
		       buf_cstring(&path), strerror(errno));
	    }
	    buf_free(&path);
	    if (!f) continue;

	    memset(buf, '\0', buflen);
	    fgets((char *) buf, buflen, f);
	    fclose(f);

	    if (buf[0] != '\0') {
		stat = DKIM_CBSTAT_CONTINUE;
		break;
	    }
	}
	else if (!strcmp(type, "http") && !strcmp(opts, "well-known")) {
	}
	else if (!strcmp(type, "dns") && !strcmp(opts, "txt")) {
	    stat = DKIM_CBSTAT_DEFAULT;
	    break;
	}
    }

    tok_fini(&tok);

    return stat;
}


static void isched_init(struct buf *serverinfo)
{
    int fd;
    struct buf keypath = BUF_INITIALIZER;
    unsigned flags = ( DKIM_LIBFLAGS_BADSIGHANDLES | DKIM_LIBFLAGS_CACHE |
		       DKIM_LIBFLAGS_VERIFYONE );
    uint64_t ttl = 3600;  /* 1 hour */
    const char *requiredhdrs[] = { "Content-Type", "iSchedule-Version",
				   "Originator", "Recipient", NULL };
    const char *signhdrs[] = { "iSchedule-Message-ID", "User-Agent", NULL };
    const char *skiphdrs[] = { "Connection", "Content-Length", "Keep-Alive",
			       "Proxy-Authenticate", "Proxy-Authorization",
			       "TE", "Trailer", "Transfer-Encoding",
			       "Upgrade", "Via", NULL };
    const char *senderhdrs[] = { "Originator", NULL };
    const char *oversignhdrs[] = { "Recipient", NULL };
    uint32_t ver = dkim_libversion();

    calc_compile_time(serverinfo);

    /* Add OpenDKIM version to serverinfo string */
    buf_printf(serverinfo, " OpenDKIM/%u.%u.%u",
	       (ver >> 24) & 0xff, (ver >> 16) & 0xff, (ver >> 8) & 0xff);
    if (ver & 0xff) buf_printf(serverinfo, ".%u", ver & 0xff);

    /* Initialize DKIM library */
    if (!(dkim_lib = dkim_init(NULL, NULL))) {
	syslog(LOG_ERR, "unable to initialize libopendkim");
	return;
    }

    /* Install our callback for doing key lookups */
    dkim_set_key_lookup(dkim_lib, isched_get_key);

    /* Setup iSchedule DKIM options */
#ifdef TEST
    flags |= ( DKIM_LIBFLAGS_SIGNLEN | DKIM_LIBFLAGS_ZTAGS );
#endif
    dkim_options(dkim_lib, DKIM_OP_SETOPT, DKIM_OPTS_FLAGS,
		 &flags, sizeof(flags));
    dkim_options(dkim_lib, DKIM_OP_SETOPT, DKIM_OPTS_SIGNATURETTL,
		 &ttl, sizeof(ttl));
    dkim_options(dkim_lib, DKIM_OP_SETOPT, DKIM_OPTS_REQUIREDHDRS,
		 requiredhdrs, sizeof(const char **));
    dkim_options(dkim_lib, DKIM_OP_SETOPT, DKIM_OPTS_MUSTBESIGNED,
		 requiredhdrs, sizeof(const char **));
    dkim_options(dkim_lib, DKIM_OP_SETOPT, DKIM_OPTS_SIGNHDRS,
		 signhdrs, sizeof(const char **));
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
    buf_free(&tmpbuf);
    buf_free(&b64req);
    if (dkim_lib) dkim_close(dkim_lib);
}


static void isched_cachehdr(const char *name, const char *contents, void *rock)
{
    struct buf *hdrfield = &tmpbuf;

    buf_reset(hdrfield);
    buf_printf(hdrfield, "%s:%s", name, contents);

    dkim_header((DKIM *) rock,
		(u_char *) buf_cstring(hdrfield), buf_len(hdrfield));
}
#endif /* WITH_DKIM */


/* Perform a GET/HEAD request for a domainkey */
static int meth_getkey(struct transaction_t *txn)
{
    txn->resp_body.type = "text/plain";

    return get_doc(txn, NULL);
}
