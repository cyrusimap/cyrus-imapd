/* http_timezone.c -- Routines for handling timezone serice requests in httpd
 *
 * Copyright (c) 1994-2013 Carnegie Mellon University.  All rights reserved.
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
#include <ctype.h>
#include <string.h>
#include <syslog.h>
#include <assert.h>

#include "acl.h"
#include "annotate.h"
#include "charset.h"
#include "global.h"
#include "httpd.h"
#include "http_err.h"
#include "http_proxy.h"
#include "imap_err.h"
#include "jcal.h"
#include "mailbox.h"
#include "map.h"
#include "mboxlist.h"
#include "message.h"
#include "parseaddr.h"
#include "proxy.h"
#include "rfc822date.h"
#include "seen.h"
#include "tok.h"
#include "util.h"
#include "version.h"
#include "wildmat.h"
#include "xmalloc.h"
#include "xstrlcpy.h"


#define TIMEZONE_WELLKNOWN_URI "/.well-known/timezone"

static time_t compile_time;
static void timezone_init(struct buf *serverinfo);
static int meth_get(struct transaction_t *txn, void *params);


/* Namespace for TIMEZONE feeds of mailboxes */
struct namespace_t namespace_timezone = {
    URL_NS_TIMEZONE, 0, "/timezone", TIMEZONE_WELLKNOWN_URI, 0 /* auth */, ALLOW_READ,
    timezone_init, NULL, NULL, NULL,
    {
	{ NULL,			NULL },			/* ACL		*/
	{ NULL,			NULL },			/* COPY		*/
	{ NULL,			NULL },			/* DELETE	*/
	{ &meth_get,		NULL },			/* GET		*/
	{ &meth_get,		NULL },			/* HEAD		*/
	{ NULL,			NULL },			/* LOCK		*/
	{ NULL,			NULL },			/* MKCALENDAR	*/
	{ NULL,			NULL },			/* MKCOL	*/
	{ NULL,			NULL },			/* MOVE		*/
	{ &meth_options,	NULL },			/* OPTIONS	*/
	{ NULL,			NULL },			/* POST		*/
	{ NULL,			NULL },			/* PROPFIND	*/
	{ NULL,			NULL },			/* PROPPATCH	*/
	{ NULL,			NULL },			/* PUT		*/
	{ NULL,			NULL },			/* REPORT	*/
	{ &meth_trace,		NULL },			/* TRACE	*/
	{ NULL,			NULL }			/* UNLOCK	*/
    }
};


static void timezone_init(struct buf *serverinfo __attribute__((unused)))
{
    namespace_timezone.enabled =
	config_httpmodules & IMAP_ENUM_HTTPMODULES_TIMEZONE;

    if (!namespace_timezone.enabled) return;

    if (config_serverinfo == IMAP_ENUM_SERVERINFO_ON &&
	!strstr(buf_cstring(serverinfo), " Jansson/")) {
	buf_printf(serverinfo, " Jansson/%s", JANSSON_VERSION);
    }

    compile_time = calc_compile_time(__TIME__, __DATE__);
}

/* Perform a GET/HEAD request */
static int meth_get(struct transaction_t *txn,
		    void *params __attribute__((unused)))
{
    int precond;
    struct message_guid guid;
    const char *etag;
    static time_t lastmod = 0;
    static char *buf = NULL;

    /* We don't handle GET on a anything other than ?action=capabilities */
    if (!URI_QUERY(txn->req_uri) ||
	strcmp(URI_QUERY(txn->req_uri), "action=capabilities")) {
	return HTTP_NOT_FOUND;
    }

    /* Generate ETag based on compile date/time of this source file.
     * Extend this to include config file size/mtime if we add run-time options.
     */
    assert(!buf_len(&txn->buf));
    buf_printf(&txn->buf, "%ld", (long) compile_time);
    message_guid_generate(&guid, buf_cstring(&txn->buf), buf_len(&txn->buf));
    etag = message_guid_encode(&guid);

    /* Check any preconditions, including range request */
    txn->flags.ranges = 1;
    precond = check_precond(txn, NULL, etag, compile_time);

    switch (precond) {
    case HTTP_OK:
    case HTTP_PARTIAL:
    case HTTP_NOT_MODIFIED:
	/* Fill in Etag,  Last-Modified, Expires, and iSchedule-Capabilities */
	txn->resp_body.etag = etag;
	txn->resp_body.lastmod = compile_time;
	txn->resp_body.maxage = 86400;  /* 24 hrs */
	txn->flags.cc |= CC_MAXAGE;

	if (precond != HTTP_NOT_MODIFIED) break;

    default:
	/* We failed a precondition - don't perform the request */
	return precond;
    }

    if (txn->resp_body.lastmod > lastmod) {
	size_t flags = JSON_PRESERVE_ORDER;
	json_t *root;

	/* Construct our response */
	root = json_pack("{s:i"				/* version */
			 "  s:{s:s s:s}"		/* info */
			 "  s:["			/* actions */
			 "    {s:s s:[]}"		/* capabilities */
			 "    {s:s s:["			/* list */
			 "      {s:s s:b s:b}"
			 "      {s:s s:b s:b}"
			 "      {s:s s:b s:b}]}"
			 "    {s:s s:["			/* get */
			 "      {s:s s:b s:b}"
			 "      {s:s s:b s:b}"
			 "      {s:s s:b s:b s:[s s s]}"
			 "      {s:s s:b s:b s:[b b]}]}"
			 "    {s:s s:["			/* expand */
			 "      {s:s s:b s:b}"
			 "      {s:s s:b s:b}"
			 "      {s:s s:b s:b}"
			 "      {s:s s:b s:b}"
			 "      {s:s s:b s:b}]}"
			 "    {s:s s:["			/* find */
			 "      {s:s s:b s:b}"
			 "      {s:s s:b s:b}]}"
			 "  ]}",
			 "version", 1,
			 "info", "primary-source", "foo", "contact", "bar",
			 "actions",
			 "name", "capabilities", "parameters",

			 "name", "list", "parameters",
			 "name", "lang", "required", 0, "multi", 1,
			 "name", "tzid", "required", 0, "multi", 1,
			 "name", "changedsince", "required", 0, "multi", 0,

			 "name", "get", "parameters",
			 "name", "lang", "required", 0, "multi", 1,
			 "name", "tzid", "required", 1, "multi", 0,
			 "name", "format", "required", 0, "multi", 0,
			 "values", "text/calendar", "application/calendar+xml",
			 "application/calendar+json",
			 "name", "substitute-alias", "required", 0, "multi", 0,
			 "values", 1, 0,

			 "name", "expand", "parameters",
			 "name", "lang", "required", 0, "multi", 1,
			 "name", "tzid", "required", 1, "multi", 0,
			 "name", "changedsince", "required", 0, "multi", 0,
			 "name", "start", "required", 0, "multi", 0,
			 "name", "end", "required", 0, "multi", 0,

			 "name", "find", "parameters",
			 "name", "lang", "required", 0, "multi", 1,
			 "name", "name", "required", 1, "multi", 0);
	if (!root) {
	    txn->error.desc = "Unable to create JSON response";
	    return HTTP_SERVER_ERROR;
	}

	/* Dump JSON object into a text buffer */
	if (buf) free(buf);
	flags |= (config_httpprettytelemetry ? JSON_INDENT(2) : JSON_COMPACT);
	buf = json_dumps(root, flags);
	json_decref(root);

	if (!buf) {
	    txn->error.desc = "Error dumping JSON object";
	    return HTTP_SERVER_ERROR;
	}

	lastmod = txn->resp_body.lastmod;
    }

    /* Output the JSON object */
    txn->resp_body.type = "application/json; charset=utf-8";
    write_body(precond, txn, buf, strlen(buf));

    return 0;
}
