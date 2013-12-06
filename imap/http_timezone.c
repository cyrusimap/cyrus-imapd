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

static time_t compile_time;
static void timezone_init(struct buf *serverinfo);
static void timezone_shutdown(void);
static int meth_get(struct transaction_t *txn, void *params);
static int action_capa(struct transaction_t *txn, struct hash_table *params);
static int action_list(struct transaction_t *txn, struct hash_table *params);
static int action_get(struct transaction_t *txn, struct hash_table *params);
static int action_get_all(struct transaction_t *txn,
			  struct mime_type_t *mime, icaltimetype *truncate);
static int action_expand(struct transaction_t *txn, struct hash_table *params);
static int json_response(int code, struct transaction_t *txn, json_t *root,
			 char **resp);
static int json_error_response(struct transaction_t *txn, const char *err);
static const char *begin_ical(struct buf *buf);
static void end_ical(struct buf *buf);

struct observance {
    const char *name;
    icaltimetype onset;
    int offset_from;
    int offset_to;
    int is_daylight;
};

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
    char *param;
    struct strlist *action;
    struct hash_table query_params;
    const struct action_t *ap = NULL;

    /* Parse the query string and add param/value pairs to hash table */
    construct_hash_table(&query_params, 10, 1);
    tok_initm(&tok, URI_QUERY(txn->req_uri), "&=", TOK_TRIMLEFT|TOK_TRIMRIGHT);
    while ((param = tok_next(&tok))) {
	struct strlist *vals;
	char *value = tok_next(&tok);
	if (!value) break;

	vals = hash_lookup(param, &query_params);
	appendstrlist(&vals, value);
	hash_insert(param, vals, &query_params);
    }
    tok_fini(&tok);

    action = hash_lookup("action", &query_params);
    if (action && !action->next  /* mandatory, once only */) {
	for (ap = actions; ap->name && strcmp(action->s, ap->name); ap++);
    }

    if (!ap || !ap->name) ret = json_error_response(txn, "invalid-action");
    else ret = ap->proc(txn, &query_params);

    free_hash_table(&query_params, (void (*)(void *)) &freestrlist);

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
			 "  s:{s:s s:{s:b s:b} s:[]}"	/* info */
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
			 "      {s:s s:b s:b}"
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
			 "info", "primary-source", info.data->s,
			 "truncated", "any", 1, "untruncated", 1, "contacts",
			 "actions",
			 "name", "capabilities", "parameters",

			 "name", "list", "parameters",
//			 "name", "lang", "required", 0, "multi", 1,
			 "name", "tzid", "required", 0, "multi", 1,
			 "name", "changedsince", "required", 0, "multi", 0,

			 "name", "get", "parameters",
//			 "name", "lang", "required", 0, "multi", 1,
			 "name", "tzid", "required", 1, "multi", 0,
			 "name", "format", "required", 0, "multi", 0,
			 "values", "text/calendar", "application/calendar+xml",
			 "application/calendar+json",
			 "name", "truncate", "required", 0, "multi", 0,
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
    int r, precond, tzid_only = 1;
    struct strlist *param, *name = NULL;
    struct resp_body_t *resp_body = &txn->resp_body;
    struct zoneinfo info;
    time_t lastmod, changedsince = 0;
    json_t *root = NULL;

    /* Sanity check the parameters */
    param = hash_lookup("action", params);
    if (!strcmp("find", param->s)) {
	name = hash_lookup("name", params);
	if (!name || name->next  /* mandatory, once only */) {
	    return json_error_response(txn, "invalid-name");
	}
	tzid_only = 0;
    }
    else {
	param = hash_lookup("changedsince", params);
	if (param) {
	    changedsince = icaltime_as_timet(icaltime_from_string(param->s));
	    if (!changedsince || param->next  /* once only */)
		return json_error_response(txn, "invalid-changedsince");
	}

	name = hash_lookup("tzid", params);
	if (name) {
	    if (changedsince) return json_error_response(txn, "invalid-tzid");
	    else {
		/* Check for tzid=*, and revert to empty list */
		struct strlist *sl;

		for (sl = name; sl && strcmp(sl->s, "*"); sl = sl->next);
		if (sl) name = NULL;
	    }
	}
    }

    /* Get info record from the database */
    if ((r = zoneinfo_lookup_info(&info))) return HTTP_SERVER_ERROR;

    /* Generate ETag & Last-Modified from info record */
    assert(!buf_len(&txn->buf));
    buf_printf(&txn->buf, "%u-%ld", strhash(info.data->s), info.dtstamp);
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
	do {
	    zoneinfo_find(name ? name->s : NULL, tzid_only, changedsince,
			  &list_cb, json_object_get(root, "timezones"));
	} while (name && (name = name->next));
    }

    /* Output the JSON object */
    return json_response(precond, txn, root, NULL);
}


static void check_tombstone(struct observance *tombstone,
			    struct observance *obs, icaltimetype *recur)
{
    icaltimetype *onset = recur ? recur : &obs->onset;

    if (icaltime_compare(*onset, tombstone->onset) > 0) {
	/* onset is closer to cutoff than existing tombstone */
	tombstone->name = icalmemory_tmp_copy(obs->name);
	tombstone->offset_from = tombstone->offset_to = obs->offset_to;
	tombstone->is_daylight = obs->is_daylight;
	memcpy(&tombstone->onset, onset, sizeof(icaltimetype));
    }
}

struct rdate {
    icalproperty *prop;
    struct icaldatetimeperiodtype date;
};

static int rdate_compare(const void *rdate1, const void *rdate2)
{
    return icaltime_compare(((struct rdate *) rdate1)->date.time,
			    ((struct rdate *) rdate2)->date.time);
}

static void truncate_vtimezone(icalcomponent *vtz, icaltimetype *truncate)
{
    icalcomponent *comp, *nextc;
    struct observance tombstone;

    memset(&tombstone, 0, sizeof(struct observance));

    /* Process each VTMEZONE STANDARD/DAYLIGHT subcomponent */
    for (comp = icalcomponent_get_first_component(vtz, ICAL_ANY_COMPONENT);
	 comp; comp = nextc) {
	icalproperty *prop, *dtstart_prop = NULL, *rrule_prop = NULL;
	icalarray *rdate_array = icalarray_new(sizeof(struct rdate), 20);
	struct observance obs;
	unsigned n;
	int r;

	nextc = icalcomponent_get_next_component(vtz, ICAL_ANY_COMPONENT);

	memset(&obs, 0, sizeof(struct observance));
	obs.is_daylight = (icalcomponent_isa(comp) == ICAL_XDAYLIGHT_COMPONENT);

	/* Grab the properties that we require to expand recurrences */
	for (prop = icalcomponent_get_first_property(comp, ICAL_ANY_PROPERTY);
	     prop;
	     prop = icalcomponent_get_next_property(comp, ICAL_ANY_PROPERTY)) {

	    switch (icalproperty_isa(prop)) {
	    case ICAL_TZNAME_PROPERTY:
		obs.name = icalproperty_get_tzname(prop);
		break;

	    case ICAL_DTSTART_PROPERTY:
		dtstart_prop = prop;
		obs.onset = icalproperty_get_dtstart(prop);
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

	    case ICAL_RDATE_PROPERTY: {
		struct rdate rdate = { prop, icalproperty_get_rdate(prop) };

		icalarray_append(rdate_array, &rdate);
		break;
	    }

	    default:
		/* ignore all other properties */
		break;
	    }
	}

	/* We MUST have DTSTART, TZNAME, TZOFFSETFROM, and TZOFFSETTO */
	if (!dtstart_prop || !obs.name || !obs.offset_from || !obs.offset_to)
	    continue;

	r = icaltime_compare(obs.onset, *truncate);
	if (r <= 0) {
	    /* Check DTSTART vs tombstone */
	    check_tombstone(&tombstone, &obs, NULL);
	}

	if (r >= 0) {
	    /* All observances occur on or after our cutoff, nothing to do */
	    icalarray_free(rdate_array);
	    continue;
	}

	/* Check RRULE */
	if (rrule_prop) {
	    struct icalrecurrencetype rrule;

	    rrule = icalproperty_get_rrule(rrule_prop);

	    /* Check RRULE duration */
	    if (!icaltime_is_null_time(rrule.until)) {
		if (rrule.until.is_utc) {
		    /* Adjust UNTIL to local time */
		    icaltime_adjust(&rrule.until, 0, 0, 0, obs.offset_from);
		    rrule.until.is_utc = 0;
		}

		if (icaltime_compare(rrule.until, *truncate) < 0) {
		    /* RRULE ends prior to our cutoff - remove it */
		    icalcomponent_remove_property(comp, rrule_prop);
		    icalproperty_free(rrule_prop);
		    rrule_prop = NULL;

		    /* Check UNTIL vs tombstone */
		    check_tombstone(&tombstone, &obs, &rrule.until);
		}
	    }

	    if (rrule_prop) {
		icalrecur_iterator *ritr;

		/* Set iterator to start 1 year prior to our cutoff */
		obs.onset.year = truncate->year - 1;
		obs.onset.month = truncate->month;
		obs.onset.day = truncate->day;

		ritr = icalrecur_iterator_new(rrule, obs.onset);

		/* Check last recurrence prior to our cutoff vs tombstone */
		obs.onset = icalrecur_iterator_next(ritr);
		check_tombstone(&tombstone, &obs, NULL);

		/* Use first recurrence after our cutoff as new DTSTART */
		obs.onset = icalrecur_iterator_next(ritr);
		icalproperty_set_dtstart(dtstart_prop, obs.onset);
		dtstart_prop = NULL;

		icalrecur_iterator_free(ritr);
	    }
	}

	/* Sort the RDATEs by onset */
	icalarray_sort(rdate_array, &rdate_compare);

	/* Check RDATEs */
	for (n = 0; n < rdate_array->num_elements; n++) {
	    struct rdate *rdate = icalarray_element_at(rdate_array, n);

	    r = icaltime_compare(rdate->date.time, *truncate);
	    if (r <= 0) {
		/* Check RDATE vs tombstone */
		check_tombstone(&tombstone, &obs, &rdate->date.time);
	    }

	    if (r < 0) {
		/* RDATE occurs prior to our cutoff - remove it */
		icalcomponent_remove_property(comp, rdate->prop);
		icalproperty_free(rdate->prop);
	    }
	    else {
		if (dtstart_prop) {
		    /* Make this RDATE the new DTSTART */
		    icalproperty_set_dtstart(dtstart_prop, rdate->date.time);
		    dtstart_prop = NULL;

		    icalcomponent_remove_property(comp, rdate->prop);
		    icalproperty_free(rdate->prop);
		}
		break;
	    }
	}
	icalarray_free(rdate_array);

	/* Final check */
	if (dtstart_prop) {
	    /* All observances occur prior to our cutoff, remove comp */
	    icalcomponent_remove_component(vtz, comp);
	    icalcomponent_free(comp);
	}
    }

    if (icaltime_compare(tombstone.onset, *truncate) < 0) {
	/* Need to add a tombstone component starting at our cutoff */
	comp = icalcomponent_vanew(
	    tombstone.is_daylight ?
	    ICAL_XDAYLIGHT_COMPONENT : ICAL_XSTANDARD_COMPONENT,
	    icalproperty_new_tzoffsetfrom(tombstone.offset_from),
	    icalproperty_new_tzoffsetto(tombstone.offset_to),
	    icalproperty_new_tzname(tombstone.name),
	    icalproperty_new_dtstart(*truncate),
	    0);
	icalcomponent_add_component(vtz, comp);
    }
}

/* Perform a get action */
static int action_get(struct transaction_t *txn, struct hash_table *params)
{
    int r, precond, substitute = 0;
    struct strlist *param;
    const char *tzid;
    struct zoneinfo zi;
    time_t lastmod;
    icaltimetype truncate = icaltime_null_time();
    char *data = NULL;
    unsigned long datalen = 0;
    struct resp_body_t *resp_body = &txn->resp_body;
    struct mime_type_t *mime = NULL;

    /* Sanity check the parameters */
    param = hash_lookup("tzid", params);
    if (!param || param->next  /* mandatory, once only */
	|| strchr(param->s, '.')  /* paranoia */) {
	return json_error_response(txn, "invalid-tzid");
    }
    tzid = param->s;

    /* Check/find requested MIME type */
    param = hash_lookup("format", params);
    if (param && !param->next  /* optional, once only */) {
	for (mime = tz_mime_types; mime->content_type; mime++) {
	    if (is_mediatype(param->s, mime->content_type)) break;
	}
    }
    else mime = tz_mime_types;

    if (!mime || !mime->content_type) {
	return json_error_response(txn, "invalid-format");
    }

    /* Check for any truncation */
    param = hash_lookup("truncate", params);
    if (param) {
	truncate = icaltime_from_day_of_year(1, atoi(param->s));
	truncate.is_date = truncate.hour = truncate.minute = truncate.second = 0;
	if (icaltime_is_null_time(truncate) || param->next  /* once only */)
	    return json_error_response(txn, "invalid-truncate");
    }

    /* Handle tzid=* separately */
    if (!strcmp(tzid, "*")) return action_get_all(txn, mime, &truncate);

    /* Get info record from the database */
    if ((r = zoneinfo_lookup(tzid, &zi)))
	return (r == CYRUSDB_NOTFOUND ? HTTP_NOT_FOUND : HTTP_SERVER_ERROR);

    if (zi.type == ZI_LINK) {
	/* Check for substitute-alias */
	param = hash_lookup("substitute-alias", params);
	if (param && !strcmp(param->s, "true")) substitute = 1;
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
	icalcomponent *ical, *vtz;
	icalproperty *prop;
	int fd;

	/* Open, mmap, and parse the file */
	buf_reset(&pathbuf);
	buf_printf(&pathbuf, "%s%s/%s.ics",
		   config_dir, FNAME_ZONEINFODIR, tzid);
	path = buf_cstring(&pathbuf);
	if ((fd = open(path, O_RDONLY)) == -1) return HTTP_SERVER_ERROR;

	map_refresh(fd, 1, &msg_base, &msg_size, MAP_UNKNOWN_LEN, path, NULL);
	if (!msg_base) return HTTP_SERVER_ERROR;

	ical = icalparser_parse_string(msg_base);
	map_free(&msg_base, &msg_size);
	close(fd);

	vtz = icalcomponent_get_first_component(ical, ICAL_VTIMEZONE_COMPONENT);
	prop = icalcomponent_get_first_property(vtz, ICAL_TZID_PROPERTY);

	if (substitute) {
	    /* Substitute TZID alias */
	    icalproperty_set_tzid(prop, tzid);
	}
	else tzid = icalproperty_get_tzid(prop);

	/* Start constructing TZURL */
	buf_reset(&pathbuf);
	http_proto_host(txn->req_hdrs, &proto, &host);
	buf_printf(&pathbuf, "%s://%s%s?action=get&tzid=%s",
		   proto, host, namespace_timezone.prefix, tzid);
	if (mime != tz_mime_types) {
	    buf_printf(&pathbuf, "&format=%.*s",
		       (int) strcspn(mime->content_type, ";"),
		       mime->content_type);
	}

	if (!icaltime_is_null_time(truncate)) {
	    /* Truncate the VTIMEZONE */
	    truncate_vtimezone(vtz, &truncate);

	    buf_printf(&pathbuf, "&truncate=%d", truncate.year);
	}

	/* Set TZURL property */
	prop = icalproperty_new_tzurl(buf_cstring(&pathbuf));
	icalcomponent_add_property(vtz, prop);

	/* Convert to requested MIME type */
	data = mime->to_string(ical);
	datalen = strlen(data);

	/* Set Content-Disposition filename */
	buf_reset(&pathbuf);
	buf_printf(&pathbuf, "%s.%s", tzid, mime->file_ext);
	resp_body->fname = buf_cstring(&pathbuf);

	icalcomponent_free(ical);
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
    icaltimetype *truncate;
    const char *sep;
    unsigned count;
};

static int get_cb(const char *tzid, int tzidlen,
		  struct zoneinfo *zi __attribute__((unused)),
		  void *rock)
{
    struct get_rock *grock = (struct get_rock *) rock;
    struct buf *pathbuf = &grock->txn->buf;
    struct mime_type_t *mime = grock->mime;
    const char *path, *proto, *host, *msg_base = NULL;
    unsigned long msg_size = 0;
    icalcomponent *ical, *vtz;
    icalproperty *prop;
    int fd = -1;
    char *tz_str;

    buf_reset(pathbuf);
    buf_printf(pathbuf, "%s%s/%.*s.ics",
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

    vtz = icalcomponent_get_first_component(ical, ICAL_VTIMEZONE_COMPONENT);
    prop = icalcomponent_get_first_property(vtz, ICAL_TZID_PROPERTY);

    /* Start constructing TZURL */
    buf_reset(pathbuf);
    http_proto_host(grock->txn->req_hdrs, &proto, &host);
    buf_printf(pathbuf, "%s://%s%s?action=get&tzid=%.*s",
	       proto, host, namespace_timezone.prefix, tzidlen, tzid);
    if (mime != tz_mime_types) {
	buf_printf(pathbuf, "&format=%.*s",
		   (int) strcspn(mime->content_type, ";"),
		   mime->content_type);
    }

    if (!icaltime_is_null_time(*grock->truncate)) {
	/* Truncate the VTIMEZONE */
	truncate_vtimezone(vtz, grock->truncate);

	buf_printf(pathbuf, "&truncate=%d", grock->truncate->year);
    }

    /* Set TZURL property */
    prop = icalproperty_new_tzurl(buf_cstring(pathbuf));
    icalcomponent_add_property(vtz, prop);

    /* Output the (converted) VTIMEZONE component */
    tz_str = mime->to_string(vtz);
    write_body(0, grock->txn, tz_str, strlen(tz_str));
    free(tz_str);

    icalcomponent_free(ical);

    return 0;
}


static int action_get_all(struct transaction_t *txn,
			  struct mime_type_t *mime, icaltimetype *truncate)
{
    int r, precond;
    struct resp_body_t *resp_body = &txn->resp_body;
    struct zoneinfo info;
    time_t lastmod;
    struct buf *buf = &resp_body->payload;
    struct get_rock grock = { txn, mime, truncate, NULL, 0 };

    /* Get info record from the database */
    if ((r = zoneinfo_lookup_info(&info))) return HTTP_SERVER_ERROR;

    /* Generate ETag & Last-Modified from info record */
    assert(!buf_len(&txn->buf));
    buf_printf(&txn->buf, "%u-%ld", strhash(info.data->s), info.dtstamp);
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

    zoneinfo_find(NULL, 1 /* tzid_only */, 0, &get_cb, &grock);

    /* End (converted) iCalendar stream */
    mime->end_stream(buf);
    write_body(0, txn, buf_cstring(buf), buf_len(buf));

    /* End of output */
    write_body(0, txn, NULL, 0);

    return 0;
}


static int observance_compare(const void *obs1, const void *obs2)
{
    return icaltime_compare(((struct observance *) obs1)->onset,
			    ((struct observance *) obs2)->onset);
}

/* Perform an expand action */
static int action_expand(struct transaction_t *txn, struct hash_table *params)
{
    int r, precond;
    struct strlist *param;
    const char *tzid;
    struct zoneinfo zi;
    time_t lastmod, changedsince = 0;
    icaltimetype start, end;
    struct resp_body_t *resp_body = &txn->resp_body;
    json_t *root = NULL;

    /* Sanity check the parameters */
    param = hash_lookup("tzid", params);
    if (!param || param->next  /* mandatory, once only */
	|| strchr(param->s, '.')  /* paranoia */) {
	return json_error_response(txn, "invalid-tzid");
    }
    tzid = param->s;

    param = hash_lookup("changedsince", params);
    if (param) {
	changedsince = icaltime_as_timet(icaltime_from_string(param->s));
	if (!changedsince || param->next  /* once only */)
	    return json_error_response(txn, "invalid-changedsince");
    }

    param = hash_lookup("start", params);
    if (param) {
	start = icaltime_from_string(param->s);
	if (icaltime_is_null_time(start) || param->next  /* once only */)
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
	end = icaltime_from_string(param->s);
	if (icaltime_compare(end, start) <= 0  /* end MUST be > start */
	    || param->next  /* once only */)
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
	buf_printf(&pathbuf, "%s%s/%s.ics",
		   config_dir, FNAME_ZONEINFODIR, tzid);
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
