/* http_timezone.c -- Routines for handling timezone service requests in httpd
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

/*
 * TODO:
 * - Implement action=expand
 * - Implement action=get&tzid=*
 * - Implement action=get&substitute-alias=true
 * - Implement error (JSON) response bodies
 * - Implement localized names and "lang" parameter
 * - Implement multiple tzid parameters
 * - Implement action=find with sub-string match anywhere (not just prefix)?
 */

#include <config.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <ctype.h>
#include <string.h>
#include <syslog.h>
#include <assert.h>

#include "global.h"
#include "hash.h"
#include "httpd.h"
#include "http_dav.h"
#include "http_err.h"
#include "jcal.h"
#include "map.h"
#include "tok.h"
#include "util.h"
#include "xcal.h"
#include "xstrlcpy.h"
#include "zoneinfo_db.h"


#define TIMEZONE_WELLKNOWN_URI "/.well-known/timezone"

static time_t compile_time;
static void timezone_init(struct buf *serverinfo);
static void timezone_shutdown(void);
static int meth_get(struct transaction_t *txn, void *params);
static int action_capa(struct transaction_t *txn, struct hash_table *params);
static int action_list(struct transaction_t *txn, struct hash_table *params);
static int action_get(struct transaction_t *txn, struct hash_table *params);

static const struct action_t {
    const char *name;
    int (*proc)(struct transaction_t *txn, struct hash_table *params);
} actions[] = {
    { "capabilities",	&action_capa },
    { "list",		&action_list },
    { "get",		&action_get },
    { "find",		&action_list },
    { NULL,		NULL}
};


static struct mime_type_t tz_mime_types[] = {
    /* First item MUST be the default type and storage format */
    { "text/calendar; charset=utf-8", "2.0", "ics", "ifb",
      (char* (*)(void *)) &icalcomponent_as_ical_string_r,
      NULL, NULL, NULL, NULL
    },
    { "application/calendar+xml; charset=utf-8", NULL, "xcs", "xfb",
      (char* (*)(void *)) &icalcomponent_as_xcal_string,
      NULL, NULL, NULL, NULL
    },
    { "application/calendar+json; charset=utf-8", NULL, "jcs", "jfb",
      (char* (*)(void *)) &icalcomponent_as_jcal_string,
      NULL, NULL, NULL, NULL
    },
    { NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL }
};


/* Namespace for TIMEZONE feeds of mailboxes */
struct namespace_t namespace_timezone = {
    URL_NS_TIMEZONE, 0, "/timezone", TIMEZONE_WELLKNOWN_URI, 0 /* auth */, ALLOW_READ,
    timezone_init, NULL, NULL, timezone_shutdown,
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


static void timezone_init(struct buf *serverinfo)
{
    namespace_timezone.enabled =
	config_httpmodules & IMAP_ENUM_HTTPMODULES_TIMEZONE;

    if (!namespace_timezone.enabled) return;

    /* Open zoneinfo db */
    if (zoneinfo_open(NULL)) {
	namespace_timezone.enabled = 0;
	return;
    }

    if (config_serverinfo == IMAP_ENUM_SERVERINFO_ON &&
	!strstr(buf_cstring(serverinfo), " Jansson/")) {
	buf_printf(serverinfo, " Jansson/%s", JANSSON_VERSION);
    }

    compile_time = calc_compile_time(__TIME__, __DATE__);
}


static void timezone_shutdown(void)
{
    zoneinfo_close(NULL);
}


/* Perform a GET/HEAD request */
static int meth_get(struct transaction_t *txn,
		    void *params __attribute__((unused)))
{
    int ret;
    tok_t tok;
    char *param, *action;
    struct hash_table query_params;
    const struct action_t *ap;

    if (!URI_QUERY(txn->req_uri)) return HTTP_BAD_REQUEST;

    /* Parse the query string and add param/value pairs to hash table */
    construct_hash_table(&query_params, 10, 1);
    tok_initm(&tok, URI_QUERY(txn->req_uri), "&=", TOK_TRIMLEFT|TOK_TRIMRIGHT);
    while ((param = tok_next(&tok))) {
	char *value = tok_next(&tok);
	if (!value) break;

	hash_insert(param, value, &query_params);
    }
    tok_fini(&tok);

    action = hash_lookup("action", &query_params);
    for (ap = actions; action && ap->name && strcmp(action, ap->name); ap++);
    if (!action || !ap->name) ret = HTTP_BAD_REQUEST;
    else ret = ap->proc(txn, &query_params);

    free_hash_table(&query_params, NULL);

    return ret;
}


/* Perform a capabilities action */
static int action_capa(struct transaction_t *txn,
		       struct hash_table *params __attribute__((unused)))
{
    int precond;
    struct message_guid guid;
    const char *etag;
    static time_t lastmod = 0;
    static char *buf = NULL;

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
	/* Fill in Etag,  Last-Modified, Expires */
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
	struct zoneinfo info;
	int r;

	/* Get info record from the database */
	if ((r = zoneinfo_lookup_info(&info))) return HTTP_SERVER_ERROR;

	/* Construct our response */
	root = json_pack("{s:i"				/* version */
			 "  s:{s:s s:[]}"		/* info */
			 "  s:["			/* actions */
			 "    {s:s s:[]}"		/* capabilities */
			 "    {s:s s:["			/* list */
//			 "      {s:s s:b s:b}"
			 "      {s:s s:b s:b}"
			 "      {s:s s:b s:b}"
			 "    ]}"
			 "    {s:s s:["			/* get */
//			 "      {s:s s:b s:b}"
			 "      {s:s s:b s:b}"
			 "      {s:s s:b s:b s:[s s s]}"
//			 "      {s:s s:b s:b s:[b b]}"
			 "    ]}"
//			 "    {s:s s:["			/* expand */
//			 "      {s:s s:b s:b}"
//			 "      {s:s s:b s:b}"
//			 "      {s:s s:b s:b}"
//			 "      {s:s s:b s:b}"
//			 "      {s:s s:b s:b}"
//			 "    ]}"
			 "    {s:s s:["			/* find */
//			 "      {s:s s:b s:b}"
			 "      {s:s s:b s:b}"
			 "    ]}"
			 "  ]}",
			 "version", 1,
			 "info", "primary-source", info.data->s, "contacts",
			 "actions",
			 "name", "capabilities", "parameters",

			 "name", "list", "parameters",
//			 "name", "lang", "required", 0, "multi", 1,
			 "name", "tzid", "required", 0, "multi", 0, // 1
			 "name", "changedsince", "required", 0, "multi", 0,

			 "name", "get", "parameters",
//			 "name", "lang", "required", 0, "multi", 1,
			 "name", "tzid", "required", 1, "multi", 0,
			 "name", "format", "required", 0, "multi", 0,
			 "values", "text/calendar", "application/calendar+xml",
			 "application/calendar+json",
//			 "name", "substitute-alias", "required", 0, "multi", 0,
//			 "values", 1, 0,

//			 "name", "expand", "parameters",
//			 "name", "lang", "required", 0, "multi", 1,
//			 "name", "tzid", "required", 1, "multi", 0,
//			 "name", "changedsince", "required", 0, "multi", 0,
//			 "name", "start", "required", 0, "multi", 0,
//			 "name", "end", "required", 0, "multi", 0,

			 "name", "find", "parameters",
//			 "name", "lang", "required", 0, "multi", 1,
			 "name", "name", "required", 1, "multi", 0);
	freestrlist(info.data);

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


static int list_cb(const char *tzid, int tzidlen,
		   struct zoneinfo *zi, void *rock)
{
    json_t *tzarray = (json_t *) rock, *tz;
    char tzidbuf[200], lastmod[21];

    strlcpy(tzidbuf, tzid, tzidlen+1);
    rfc3339date_gen(lastmod, sizeof(lastmod), zi->dtstamp);

    tz = json_pack("{s:s s:s}", "tzid", tzidbuf, "last-modified", lastmod);
    json_array_append_new(tzarray, tz);

    if (zi->data) {
	struct strlist *sl;
	json_t *aliases = json_array();

	json_object_set_new(tz, "aliases", aliases);

	for (sl = zi->data; sl; sl = sl->next)
	    json_array_append_new(aliases, json_string(sl->s));
    }

    return 0;
}


/* Perform a list action */
static int action_list(struct transaction_t *txn, struct hash_table *params)
{
    int ret = 0, r, precond = HTTP_OK;
    struct resp_body_t *resp_body = &txn->resp_body;
    char *buf = NULL;
    unsigned long buflen = 0;
    struct zoneinfo info;
    time_t lastmod, changedsince = 0;
    const char *name = NULL;

    /* Sanity check the parameters */
    if (!strcmp("find", hash_lookup("action", params))) {
	name = hash_lookup("name", params);
	if (!name) return HTTP_BAD_REQUEST;
    }
    else {
	const char *cs = hash_lookup("changedsince", params);

	name = hash_lookup("tzid", params);
	if (name && !strcmp(name, "*")) name = NULL;

	if (cs) {
	    if (name) return HTTP_BAD_REQUEST;

	    changedsince = icaltime_as_timet(icaltime_from_string(cs));
	    if (!changedsince) return HTTP_BAD_REQUEST;
	}
    }

    /* Get info record from the database */
    if ((r = zoneinfo_lookup_info(&info))) return HTTP_SERVER_ERROR;

    /* Generate ETag & Last-Modified from info record */
    assert(!buf_len(&txn->buf));
    buf_printf(&txn->buf, "%ld-%u",
	       info.dtstamp, strhash(info.data->s));
    lastmod = info.dtstamp;
    freestrlist(info.data);

    /* Check any preconditions, including range request */
    txn->flags.ranges = 1;
    precond = check_precond(txn, NULL, buf_cstring(&txn->buf), lastmod);

    switch (precond) {
    case HTTP_OK:
    case HTTP_PARTIAL:
    case HTTP_NOT_MODIFIED:
	/* Fill in ETag, Last-Modified, and Expires */
	resp_body->etag = buf_cstring(&txn->buf);
	resp_body->lastmod = lastmod;
	resp_body->maxage = 86400;  /* 24 hrs */
	txn->flags.cc |= CC_MAXAGE | CC_REVALIDATE;
	if (httpd_userid) txn->flags.cc |= CC_PUBLIC;

	if (precond != HTTP_NOT_MODIFIED) break;

    default:
	/* We failed a precondition - don't perform the request */
	resp_body->type = NULL;
	return precond;
    }


    if (txn->meth == METH_GET) {
	size_t flags = JSON_PRESERVE_ORDER;
	json_t *root;
	char dtstamp[21];

	/* Start constructing our response */
	rfc3339date_gen(dtstamp, sizeof(dtstamp), lastmod);
	root = json_pack("{s:s s:[]}", "dtstamp", dtstamp, "timezones");
	if (!root) {
	    txn->error.desc = "Unable to create JSON response";
	    return HTTP_SERVER_ERROR;
	}

	/* Add timezones to array */
	zoneinfo_find((char *) name, changedsince, &list_cb,
		      json_object_get(root, "timezones"));

	/* Dump JSON object into a text buffer */
	flags |= (config_httpprettytelemetry ? JSON_INDENT(2) : JSON_COMPACT);
	buf = json_dumps(root, flags);
	json_decref(root);

	if (buf) buflen = strlen(buf);
	else {
	    txn->error.desc = "Error dumping JSON object";
	    return HTTP_SERVER_ERROR;
	}
    }

    /* Output the JSON object */
    resp_body->type = "application/json; charset=utf-8";
    write_body(precond, txn, buf, buflen);

    if (buf) free(buf);

    return ret;
}


/* Perform a get action */
static int action_get(struct transaction_t *txn, struct hash_table *params)
{
    static struct buf pathbuf = BUF_INITIALIZER;
    int ret = 0, r, fd = -1, precond;
    struct stat sbuf;
    char *freeme = NULL;
    const char *tzid, *format, *path, *msg_base, *data = NULL;
    unsigned long msg_size, datalen = 0;
    struct resp_body_t *resp_body = &txn->resp_body;
    struct mime_type_t *mime;

    tzid = hash_lookup("tzid", params);
    if (!tzid || strchr(tzid, '.')) return HTTP_BAD_REQUEST;

    /* Check/find requested MIME type */
    format = hash_lookup("format", params);
    for (mime = tz_mime_types; format && mime->content_type; mime++) {
	if (is_mediatype(format, mime->content_type)) break;
    }
    if (!mime->content_type) return HTTP_BAD_REQUEST;

    /* See if file exists and get Content-Length & Last-Modified time */
    buf_reset(&pathbuf);
    buf_printf(&pathbuf, "%s/zoneinfo/%s.ics", config_dir, tzid);
    path = buf_cstring(&pathbuf);
    r = stat(path, &sbuf);
    if (r || !S_ISREG(sbuf.st_mode)) return HTTP_NOT_FOUND;

    /* Generate ETag */
    assert(!buf_len(&txn->buf));
    buf_printf(&txn->buf, "%ld-%ld", (long) sbuf.st_mtime, (long) sbuf.st_size);

    /* Check any preconditions, including range request */
    txn->flags.ranges = 1;
    precond = check_precond(txn, NULL, buf_cstring(&txn->buf), sbuf.st_mtime);

    switch (precond) {
    case HTTP_OK:
    case HTTP_PARTIAL:
    case HTTP_NOT_MODIFIED:
	/* Fill in Content-Type, ETag, Last-Modified, and Expires */
	resp_body->type = mime->content_type;
	resp_body->etag = buf_cstring(&txn->buf);
	resp_body->lastmod = sbuf.st_mtime;
	resp_body->maxage = 86400;  /* 24 hrs */
	txn->flags.cc |= CC_MAXAGE | CC_REVALIDATE;
	if (httpd_userid) txn->flags.cc |= CC_PUBLIC;

	if (precond != HTTP_NOT_MODIFIED) break;

    default:
	/* We failed a precondition - don't perform the request */
	resp_body->type = NULL;
	return precond;
    }


    if (txn->meth == METH_GET) {
	/* Open and mmap the file */
	if ((fd = open(path, O_RDONLY)) == -1) return HTTP_SERVER_ERROR;
	map_refresh(fd, 1, &msg_base, &msg_size, sbuf.st_size, path, NULL);
	data = msg_base;
	datalen = msg_size;

	buf_reset(&pathbuf);
	buf_printf(&pathbuf, "%s.%s", tzid, mime->file_ext);
	resp_body->fname = buf_cstring(&pathbuf);

	if (mime != tz_mime_types) {
	    /* Not the storage format - convert into requested MIME type */
	    icalcomponent *ical = icalparser_parse_string(data);
	    
	    data = freeme = mime->to_string(ical);
	    datalen = strlen(data);
	    icalcomponent_free(ical);
	}

    }

    write_body(precond, txn, data, datalen);

    if (freeme) free(freeme);
    if (fd != -1) {
	map_free(&msg_base, &msg_size);
	close(fd);
    }

    return ret;
}
