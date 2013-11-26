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
#include "http_proxy.h"
#include "jcal.h"
#include "map.h"
#include "tok.h"
#include "util.h"
#include "version.h"
#include "xcal.h"
#include "xstrlcpy.h"
#include "zoneinfo_db.h"


#define TIMEZONE_WELLKNOWN_URI "/.well-known/timezone"

#define FNAME_ZONEINFODIR "/zoneinfo/"

static time_t compile_time;
static void timezone_init(struct buf *serverinfo);
static void timezone_shutdown(void);
static int meth_get(struct transaction_t *txn, void *params);
static int action_capa(struct transaction_t *txn, struct hash_table *params);
static int action_list(struct transaction_t *txn, struct hash_table *params);
static int action_get(struct transaction_t *txn, struct hash_table *params);
static int action_get_all(struct transaction_t *txn, struct mime_type_t *mime);
static int action_expand(struct transaction_t *txn, struct hash_table *params);
static int json_response(int code, struct transaction_t *txn, json_t *root,
			 char **resp);
static int json_error_response(struct transaction_t *txn, const char *err);
static const char *begin_ical(struct buf *buf);
static void end_ical(struct buf *buf);

static const struct action_t {
    const char *name;
    int (*proc)(struct transaction_t *txn, struct hash_table *params);
} actions[] = {
    { "capabilities",	&action_capa },
    { "list",		&action_list },
    { "get",		&action_get },
    { "expand",		&action_expand },
    { "find",		&action_list },
    { NULL,		NULL}
};


static struct mime_type_t tz_mime_types[] = {
    /* First item MUST be the default type and storage format */
    { "text/calendar; charset=utf-8", "2.0", "ics", "ifb",
      (char* (*)(void *)) &icalcomponent_as_ical_string_r,
      NULL, NULL, &begin_ical, &end_ical
    },
    { "application/calendar+xml; charset=utf-8", NULL, "xcs", "xfb",
      (char* (*)(void *)) &icalcomponent_as_xcal_string,
      NULL, NULL, &begin_xcal, &end_xcal
    },
    { "application/calendar+json; charset=utf-8", NULL, "jcs", "jfb",
      (char* (*)(void *)) &icalcomponent_as_jcal_string,
      NULL, NULL, &begin_jcal, &end_jcal
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

    if (!action || !ap->name) ret = json_error_response(txn, "invalid-action");
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
    static char *resp = NULL;
    json_t *root = NULL;

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
			 "      {s:s s:b s:b s:[b b]}"
			 "    ]}"
			 "    {s:s s:["			/* expand */
//			 "      {s:s s:b s:b}"
			 "      {s:s s:b s:b}"
			 "      {s:s s:b s:b}"
			 "      {s:s s:b s:b}"
			 "      {s:s s:b s:b}"
			 "    ]}"
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
			 "name", "substitute-alias", "required", 0, "multi", 0,
			 "values", 1, 0,

			 "name", "expand", "parameters",
//			 "name", "lang", "required", 0, "multi", 1,
			 "name", "tzid", "required", 1, "multi", 0,
			 "name", "changedsince", "required", 0, "multi", 0,
			 "name", "start", "required", 0, "multi", 0,
			 "name", "end", "required", 0, "multi", 0,

			 "name", "find", "parameters",
//			 "name", "lang", "required", 0, "multi", 1,
			 "name", "name", "required", 1, "multi", 0);
	freestrlist(info.data);

	if (!root) {
	    txn->error.desc = "Unable to create JSON response";
	    return HTTP_SERVER_ERROR;
	}

	/* Update lastmod */
	lastmod = txn->resp_body.lastmod;
    }

    /* Output the JSON object */
    return json_response(precond, txn, root, &resp);
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
    int r, precond = HTTP_OK;
    struct resp_body_t *resp_body = &txn->resp_body;
    struct zoneinfo info;
    time_t lastmod, changedsince = 0;
    const char *name = NULL;
    json_t *root = NULL;

    /* Sanity check the parameters */
    if (!strcmp("find", hash_lookup("action", params))) {
	name = hash_lookup("name", params);
	if (!name) return json_error_response(txn, "invalid-name");
    }
    else {
	const char *cs = hash_lookup("changedsince", params);

	name = hash_lookup("tzid", params);
	if (name && !strcmp(name, "*")) name = NULL;

	if (cs) {
	    if (name) return json_error_response(txn, "invalid-tzid");

	    changedsince = icaltime_as_timet(icaltime_from_string(cs));
	    if (!changedsince)
		return json_error_response(txn, "invalid-changedsince");
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
    }

    /* Output the JSON object */
    return json_response(precond, txn, root, NULL);
}


/* Perform a get action */
static int action_get(struct transaction_t *txn, struct hash_table *params)
{
    int r, precond, substitute = 0;
    const char *tzid, *param;
    struct zoneinfo zi;
    time_t lastmod;
    char *data = NULL;
    unsigned long datalen = 0;
    struct resp_body_t *resp_body = &txn->resp_body;
    struct mime_type_t *mime;

    /* Sanity check the parameters */
    tzid = hash_lookup("tzid", params);
    if (!tzid || strchr(tzid, '.'))
	return json_error_response(txn, "invalid-tzid");

    /* Check/find requested MIME type */
    param = hash_lookup("format", params);
    for (mime = tz_mime_types; param && mime->content_type; mime++) {
	if (is_mediatype(param, mime->content_type)) break;
    }
    if (!mime->content_type) return json_error_response(txn, "invalid-format");

    /* Handle tzid=* separately */
    if (!strcmp(tzid, "*")) return action_get_all(txn, mime);

    /* Get info record from the database */
    if ((r = zoneinfo_lookup(tzid, &zi)))
	return (r == CYRUSDB_NOTFOUND ? HTTP_NOT_FOUND : HTTP_SERVER_ERROR);

    if (zi.type == ZI_LINK) {
	/* Check for substitute-alias */
	param = hash_lookup("substitute-alias", params);
	if (param && !strcmp(param, "true")) substitute = 1;
    }

    /* Generate ETag & Last-Modified from info record */
    assert(!buf_len(&txn->buf));
    buf_printf(&txn->buf, "%u-%ld", strhash(tzid), zi.dtstamp);
    lastmod = zi.dtstamp;
    freestrlist(zi.data);

    /* Check any preconditions, including range request */
    txn->flags.ranges = 1;
    precond = check_precond(txn, NULL, buf_cstring(&txn->buf), lastmod);

    switch (precond) {
    case HTTP_OK:
    case HTTP_PARTIAL:
    case HTTP_NOT_MODIFIED:
	/* Fill in Content-Type, ETag, Last-Modified, and Expires */
	resp_body->type = mime->content_type;
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
	static struct buf pathbuf = BUF_INITIALIZER;
	const char *path, *proto, *host, *msg_base = NULL;
	unsigned long msg_size = 0;
	icalcomponent *ical, *comp;
	icalproperty *prop;
	int fd;

	/* Open, mmap, and parse the file */
	buf_reset(&pathbuf);
	buf_printf(&pathbuf, "%s%s%s.ics", config_dir, FNAME_ZONEINFODIR, tzid);
	path = buf_cstring(&pathbuf);
	if ((fd = open(path, O_RDONLY)) == -1) return HTTP_SERVER_ERROR;

	map_refresh(fd, 1, &msg_base, &msg_size, MAP_UNKNOWN_LEN, path, NULL);
	if (!msg_base) return HTTP_SERVER_ERROR;

	ical = icalparser_parse_string(msg_base);
	map_free(&msg_base, &msg_size);
	close(fd);

	/* Set TZURL property */
	buf_reset(&pathbuf);
	http_proto_host(txn->req_hdrs, &proto, &host);
	buf_printf(&pathbuf, "%s://%s%s?action=get&tzid=%s",
		   proto, host, namespace_timezone.prefix, tzid);
	if (mime != tz_mime_types) {
	    buf_printf(&pathbuf, "&format=%.*s",
		       (int) strcspn(mime->content_type, ";"),
		       mime->content_type);
	}
	path = buf_cstring(&pathbuf);
	comp =
	    icalcomponent_get_first_component(ical, ICAL_VTIMEZONE_COMPONENT);
	prop = icalproperty_new_tzurl(path);
	icalcomponent_add_property(comp, prop);

	if (substitute) {
	    /* Substitute TZID alias */
	    prop = icalcomponent_get_first_property(comp, ICAL_TZID_PROPERTY);
	    icalproperty_set_tzid(prop, tzid);
	}

	/* Convert to requested MIME type */
	data = mime->to_string(ical);
	datalen = strlen(data);
	icalcomponent_free(ical);

	/* Set Content-Disposition filename */
	buf_reset(&pathbuf);
	buf_printf(&pathbuf, "%s.%s", tzid, mime->file_ext);
	resp_body->fname = buf_cstring(&pathbuf);
    }

    write_body(precond, txn, data, datalen);

    if (data) free(data);

    return 0;
}


static const char *begin_ical(struct buf *buf)
{
    /* Begin iCalendar stream */
    buf_setcstr(buf, "BEGIN:VCALENDAR\r\n");
    buf_printf(buf, "PRODID:-//CyrusIMAP.org/Cyrus %s//EN\r\n",
	       cyrus_version());
    buf_appendcstr(buf, "VERSION:2.0\r\n");

    return "";
}

static void end_ical(struct buf *buf)
{
    /* End iCalendar stream */
    buf_setcstr(buf, "END:VCALENDAR\r\n");
}

struct get_rock {
    struct transaction_t *txn;
    struct mime_type_t *mime;
    const char *sep;
    unsigned count;
};

static int get_cb(const char *tzid, int tzidlen,
		  struct zoneinfo *zi __attribute__((unused)),
		  void *rock)
{
    struct get_rock *grock = (struct get_rock *) rock;
    struct buf *pathbuf = &grock->txn->buf;
    const char *path, *msg_base = NULL;
    unsigned long msg_size = 0;
    icalcomponent *ical, *comp;
    int fd = -1;
    char *tz_str;

    buf_reset(pathbuf);
    buf_printf(pathbuf, "%s%s%.*s.ics",
	       config_dir, FNAME_ZONEINFODIR, tzidlen, tzid);
    path = buf_cstring(pathbuf);

    /* Open, mmap, and parse the file */
    if ((fd = open(path, O_RDONLY)) == -1) return HTTP_SERVER_ERROR;
    map_refresh(fd, 1, &msg_base, &msg_size, MAP_UNKNOWN_LEN, path, NULL);
    if (!msg_base) return HTTP_SERVER_ERROR;
    ical = icalparser_parse_string(msg_base);
    map_free(&msg_base, &msg_size);
    close(fd);
	    
    if (grock->count++ && *grock->sep) {
	/* Add separator, if necessary */
	struct buf *buf = &grock->txn->resp_body.payload;

	buf_reset(buf);
	buf_printf_markup(buf, 0, grock->sep);
	write_body(0, grock->txn, buf_cstring(buf), buf_len(buf));
    }

    /* Output the (converted) VTIMEZONE component */
    comp = icalcomponent_get_first_component(ical, ICAL_VTIMEZONE_COMPONENT);
    tz_str = grock->mime->to_string(comp);
    write_body(0, grock->txn, tz_str, strlen(tz_str));
    free(tz_str);

    icalcomponent_free(ical);

    return 0;
}


static int action_get_all(struct transaction_t *txn, struct mime_type_t *mime)
{
    int r, precond;
    struct resp_body_t *resp_body = &txn->resp_body;
    struct zoneinfo info;
    time_t lastmod;
    struct buf *buf = &resp_body->payload;
    struct get_rock grock = { txn, mime, NULL, 0 };

    /* Get info record from the database */
    if ((r = zoneinfo_lookup_info(&info))) return HTTP_SERVER_ERROR;

    /* Generate ETag & Last-Modified from info record */
    assert(!buf_len(&txn->buf));
    buf_printf(&txn->buf, "%ld-%u", info.dtstamp, strhash(info.data->s));
    lastmod = info.dtstamp;
    freestrlist(info.data);

    /* Check any preconditions */
    precond = check_precond(txn, NULL, buf_cstring(&txn->buf), lastmod);

    switch (precond) {
    case HTTP_OK:
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

    /* Setup for chunked response */
    txn->flags.te |= TE_CHUNKED;
    txn->flags.vary |= VARY_ACCEPT;
    txn->resp_body.type = mime->content_type;

    /* Short-circuit for HEAD request */
    if (txn->meth == METH_HEAD) {
	response_header(HTTP_OK, txn);
	return 0;
    }

    /* iCalendar data in response should not be transformed */
    txn->flags.cc |= CC_NOTRANSFORM;

    /* Begin (converted) iCalendar stream */
    grock.sep = mime->begin_stream(buf);
    write_body(HTTP_OK, txn, buf_cstring(buf), buf_len(buf));

    zoneinfo_find(NULL, 0, &get_cb, &grock);

    /* End (converted) iCalendar stream */
    mime->end_stream(buf);
    write_body(0, txn, buf_cstring(buf), buf_len(buf));

    /* End of output */
    write_body(0, txn, NULL, 0);

    return 0;
}


struct observance {
    const char *name;
    icaltimetype onset;
    int offset_from;
    int offset_to;
};

static int observance_compare(const void *obs1, const void *obs2)
{
    return icaltime_compare(((struct observance *) obs1)->onset,
			    ((struct observance *) obs2)->onset);
}

/* Perform an expand action */
static int action_expand(struct transaction_t *txn, struct hash_table *params)
{
    int r, precond;
    const char *tzid, *param;
    struct zoneinfo zi;
    time_t lastmod, changedsince = 0;
    icaltimetype start, end;
    struct resp_body_t *resp_body = &txn->resp_body;
    json_t *root = NULL;

    /* Sanity check the parameters */
    tzid = hash_lookup("tzid", params);
    if (!tzid || strchr(tzid, '.'))
	return json_error_response(txn, "invalid-tzid");

    param = hash_lookup("changedsince", params);
    if (param) {
	if (!(changedsince = icaltime_as_timet(icaltime_from_string(param))))
	    return json_error_response(txn, "invalid-changedsince");
    }

    param = hash_lookup("start", params);
    if (param) {
	start = icaltime_from_string(param);
	if (icaltime_is_null_time(start))
	    return json_error_response(txn, "invalid-start");
    }
    else {
	/* Default to current year */
	time_t now = time(0);
	struct tm *tm = gmtime(&now);

	start = icaltime_from_day_of_year(1, tm->tm_year + 1900);
    }

    param = hash_lookup("end", params);
    if (param) {
	end = icaltime_from_string(param);
	if (icaltime_compare(end, start) <= 0)
	    return json_error_response(txn, "invalid-end");
    }
    else {
	/* Default to start year + 10 */
	memcpy(&end, &start, sizeof(icaltimetype));
	end.year += 10;
    }

    /* Get info record from the database */
    if ((r = zoneinfo_lookup(tzid, &zi)))
	return (r == CYRUSDB_NOTFOUND ? HTTP_NOT_FOUND : HTTP_SERVER_ERROR);

    /* Generate ETag & Last-Modified from info record */
    assert(!buf_len(&txn->buf));
    buf_printf(&txn->buf, "%u-%ld", strhash(tzid), zi.dtstamp);
    lastmod = zi.dtstamp;
    freestrlist(zi.data);

    /* Check any preconditions, including range request */
    txn->flags.ranges = 1;
    if (lastmod <= changedsince) precond = HTTP_NOT_MODIFIED;
    else precond = check_precond(txn, NULL, buf_cstring(&txn->buf), lastmod);

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
	static struct buf pathbuf = BUF_INITIALIZER;
	const char *path, *msg_base = NULL;
	unsigned long msg_size = 0;
	icalcomponent *ical, *vtz, *comp;
	char dtstamp[21];
	icalarray *obsarray;
	json_t *jobsarray;
	unsigned n;
	int fd;

	/* Open, mmap, and parse the file */
	buf_reset(&pathbuf);
	buf_printf(&pathbuf, "%s%s%s.ics", config_dir, FNAME_ZONEINFODIR, tzid);
	path = buf_cstring(&pathbuf);
	if ((fd = open(path, O_RDONLY)) == -1) return HTTP_SERVER_ERROR;

	map_refresh(fd, 1, &msg_base, &msg_size, MAP_UNKNOWN_LEN, path, NULL);
	if (!msg_base) return HTTP_SERVER_ERROR;

	ical = icalparser_parse_string(msg_base);
	map_free(&msg_base, &msg_size);
	close(fd);

	/* Start constructing our response */
	rfc3339date_gen(dtstamp, sizeof(dtstamp), lastmod);
	root = json_pack("{s:s s:[]}", "dtstamp", dtstamp, "observances");
	if (!root) {
	    txn->error.desc = "Unable to create JSON response";
	    return HTTP_SERVER_ERROR;
	}

	/* Create an array of observances */
	obsarray = icalarray_new(sizeof(struct observance), 20);

	/* Process each VTMEZONE STANDARD/DAYLIGHT subcomponent */
	vtz = icalcomponent_get_first_component(ical, ICAL_VTIMEZONE_COMPONENT);
	for (comp = icalcomponent_get_first_component(vtz, ICAL_ANY_COMPONENT);
	     comp;
	     comp = icalcomponent_get_next_component(vtz, ICAL_ANY_COMPONENT)) {

	    icaltimetype dtstart = icaltime_null_time();
	    struct observance obs;
	    icalproperty *prop, *rrule_prop = NULL;

	    /* Grab the properties that we require to expand recurrences */
	    memset(&obs, 0, sizeof(struct observance));
	    for (prop = icalcomponent_get_first_property(comp,
							 ICAL_ANY_PROPERTY);
		 prop;
		 prop = icalcomponent_get_next_property(comp,
							ICAL_ANY_PROPERTY)) {

		switch (icalproperty_isa(prop)) {
		case ICAL_TZNAME_PROPERTY:
		    obs.name = icalproperty_get_tzname(prop);
		    break;

		case ICAL_DTSTART_PROPERTY:
		    dtstart = icalproperty_get_dtstart(prop);
		    break;

		case ICAL_TZOFFSETFROM_PROPERTY:
		    obs.offset_from = icalproperty_get_tzoffsetfrom(prop);
		    break;

		case ICAL_TZOFFSETTO_PROPERTY:
		    obs.offset_to = icalproperty_get_tzoffsetto(prop);
		    break;

		case ICAL_RRULE_PROPERTY:
		    rrule_prop = prop;
		    break;

		default:
		    /* ignore all other properties */
		    break;
		}
	    }

	    /* We MUST have TZNAME, DTSTART, TZOFFSETFROM and TZOFFSETTO */
	    if (!obs.name || !obs.offset_from || !obs.offset_to ||
		icaltime_is_null_time(dtstart)) continue;

	    /* Adjust DTSTART to UTC */
	    memcpy(&obs.onset, &dtstart, sizeof(icaltimetype));
	    icaltime_adjust(&obs.onset, 0, 0, 0, -obs.offset_from);
	    obs.onset.is_utc = 1;

	    if (icaltime_compare(obs.onset, end) > 0) {
		/* Skip observance(s) after our window */
	    }
	    else if (rrule_prop) {
		/* Add any RRULE observances within our window */
		struct icalrecurrencetype rrule;
		icalrecur_iterator *ritr;
		icaltimetype recur;

		rrule = icalproperty_get_rrule(rrule_prop);

		if (!icaltime_is_null_time(rrule.until) && rrule.until.is_utc) {
		    /* Adjust UNTIL to local time */
		    icaltime_adjust(&rrule.until, 0, 0, 0, obs.offset_from);
		    rrule.until.is_utc = 0;
		}

		if (icaltime_compare(start, obs.onset) > 0) {
		    /* Set iterator dtstart to be 1 day prior to our window */
		    obs.onset.year = start.year;
		    obs.onset.month = start.month;
		    obs.onset.day = start.day - 1;
		}

		/* Adjust iterator dtstart to local time */
		icaltime_adjust(&obs.onset, 0, 0, 0, obs.offset_from);
		obs.onset.is_utc = 0;

		ritr = icalrecur_iterator_new(rrule, obs.onset);
		while (!icaltime_is_null_time(recur =
					      icalrecur_iterator_next(ritr))) {
		    /* Adjust observance to UTC */
		    memcpy(&obs.onset, &recur, sizeof(icaltimetype));
		    icaltime_adjust(&obs.onset, 0, 0, 0, -obs.offset_from);
		    obs.onset.is_utc = 1;

		    if (icaltime_compare(obs.onset, end) > 0) {
			/* Quit if we've gone past our window */
			break;
		    }
		    else if (icaltime_compare(obs.onset, start) < 0) {
			/* Skip observances prior to our window */
		    }
		    else {
			/* Add the observance to our array */
			icalarray_append(obsarray, &obs);
		    }
		}
		icalrecur_iterator_free(ritr);
	    }
	    else if (icaltime_compare(obs.onset, start) < 0) {
		/* Skip observances prior to our window */
	    }
	    else {
		/* Add the DTSTART observance to our array */
		icalarray_append(obsarray, &obs);
	    }

	    /* Add any RDATE observances within our window */
	    for (prop = icalcomponent_get_first_property(comp,
							 ICAL_RDATE_PROPERTY);
		 prop;
		 prop = icalcomponent_get_next_property(comp,
							ICAL_RDATE_PROPERTY)) {
		struct icaldatetimeperiodtype rdate =
		    icalproperty_get_rdate(prop);

		/* Adjust RDATE to UTC */
		memcpy(&obs.onset, &rdate.time, sizeof(icaltimetype));
		icaltime_adjust(&obs.onset, 0, 0, 0, -obs.offset_from);
		obs.onset.is_utc = 1;

		if (icaltime_compare(obs.onset, start) < 0) {
		    /* Skip observances prior to our window */
		}
		else if (icaltime_compare(obs.onset, end) > 0) {
		    /* Skip observances after our window */
		}
		else if (icaltime_compare(obs.onset, dtstart) == 0) {
		    /* Skip duplicates of DTSTART observance */
		}
		else {
		    /* Add the RDATE observance to our array */
		    icalarray_append(obsarray, &obs);
		}
	    }
	}

	/* Sort the observances by onset */
	icalarray_sort(obsarray, &observance_compare);

	/* Add observances to JSON array */
	jobsarray = json_object_get(root, "observances");
	for (n = 0; n < obsarray->num_elements; n++) {
	    struct observance *obs = icalarray_element_at(obsarray, n);

	    json_array_append_new(jobsarray,
				  json_pack("{s:s s:s s:i s:i}",
					    "name", obs->name,
					    "onset",
					    icaltime_as_ical_string(obs->onset),
					    "utc-offset-from", obs->offset_from,
					    "utc-offset-to", obs->offset_to));
	}
	icalarray_free(obsarray);

	icalcomponent_free(ical);
    }

    /* Output the JSON object */
    return json_response(precond, txn, root, NULL);
}


static int json_response(int code, struct transaction_t *txn, json_t *root,
			 char **resp)
{
    size_t flags = JSON_PRESERVE_ORDER;
    char *buf = NULL;

    if (root) {
	/* Dump JSON object into a text buffer */
	flags |= (config_httpprettytelemetry ? JSON_INDENT(2) : JSON_COMPACT);
	buf = json_dumps(root, flags);
	json_decref(root);

	if (!buf) {
	    txn->error.desc = "Error dumping JSON object";
	    return HTTP_SERVER_ERROR;
	}
	else if (resp) {
	    if (*resp) free(*resp);
	    *resp = buf;
	}
    }
    else if (resp) buf = *resp;

    /* Output the JSON object */
    txn->resp_body.type = "application/json; charset=utf-8";
    write_body(code, txn, buf, buf ? strlen(buf) : 0);

    if (!resp && buf) free(buf);

    return 0;
}


static int json_error_response(struct transaction_t *txn, const char *err)
{
    json_t *root;

    root = json_pack("{s:s}", "error", err);
    if (!root) {
	txn->error.desc = "Unable to create JSON response";
	return HTTP_SERVER_ERROR;
    }

    return json_response(HTTP_BAD_REQUEST, txn, root, NULL);
}
