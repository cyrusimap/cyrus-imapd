/* http_timezone.c -- Routines for handling timezone service requests in httpd
 *
 * Copyright (c) 1994-2014 Carnegie Mellon University.  All rights reserved.
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
#include "tz_err.h"
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
static int action_capa(struct transaction_t *txn);
static int action_list(struct transaction_t *txn);
static int action_get(struct transaction_t *txn);
static int action_expand(struct transaction_t *txn);
static int json_response(int code, struct transaction_t *txn, json_t *root,
			 char **resp);
static int json_error_response(struct transaction_t *txn, long tz_code,
			       struct strlist *param, icaltimetype *time);

struct observance {
    const char *name;
    icaltimetype onset;
    int offset_from;
    int offset_to;
    int is_daylight;
};

static const struct action_t {
    const char *name;
    int (*proc)(struct transaction_t *txn);
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
	{ &meth_get,		NULL },			/* POST	*/
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

    /* Open zoneinfo db */
    if (zoneinfo_open(NULL)) {
	namespace_timezone.enabled = 0;
	return;
    }

    compile_time = calc_compile_time(__TIME__, __DATE__);

    initialize_tz_error_table();
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
    struct strlist *action;
    const struct action_t *ap = NULL;

    action = hash_lookup("action", &txn->req_qparams);
    if (action && !action->next  /* mandatory, once only */) {
	for (ap = actions; ap->name && strcmp(action->s, ap->name); ap++);
    }

    if (!ap || !ap->name)
	ret = json_error_response(txn, TZ_INVALID_ACTION, action, NULL);
    else
	ret = ap->proc(txn);

    return ret;
}


/* Perform a capabilities action */
static int action_capa(struct transaction_t *txn)
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
			 "  s:{"			/* info */
			 "      s:s"			/*   primary-source */
			 "      s:{s:b s:b}"		/*   truncated */
			 "      s:s"   			/*   provider-details */
			 "      s:[]"  			/*   contacts */
			 "    }"
			 "  s:["			/* actions */
			 "    {s:s s:[]}"		/*   capabilities */
			 "    {s:s s:["			/*   list */
//			 "      {s:s s:b s:b}"		/*     lang */
			 "      {s:s s:b s:b}"		/*     tzid */
			 "      {s:s s:b s:b}"		/*     changedsince */
			 "    ]}"
			 "    {s:s s:["			/*   get */
//			 "      {s:s s:b s:b}"		/*     lang */
			 "      {s:s s:b s:b}"		/*     tzid */
			 "      {s:s s:b s:b s:[s s s]}"/*     format */
			 "      {s:s s:b s:b}"		/*     truncate */
			 "    ]}"
			 "    {s:s s:["			/*   expand */
//			 "      {s:s s:b s:b}"		/*     lang */
			 "      {s:s s:b s:b}"		/*     tzid */
			 "      {s:s s:b s:b}"		/*     changedsince */
			 "      {s:s s:b s:b}"		/*     start */
			 "      {s:s s:b s:b}"		/*     end */
			 "    ]}"
			 "    {s:s s:["			/*   find */
//			 "      {s:s s:b s:b}"		/*     lang */
			 "      {s:s s:b s:b}"		/*     pattern */
			 "    ]}"
			 "  ]}",
			 "version", 1,
			 "info", "primary-source", info.data->s,
			 "truncated", "any", 1, "untruncated", 1,
			 "provider-details", "", "contacts",
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

			 "name", "expand", "parameters",
//			 "name", "lang", "required", 0, "multi", 1,
			 "name", "tzid", "required", 1, "multi", 0,
			 "name", "changedsince", "required", 0, "multi", 0,
			 "name", "start", "required", 1, "multi", 0,
			 "name", "end", "required", 0, "multi", 0,

			 "name", "find", "parameters",
//			 "name", "lang", "required", 0, "multi", 1,
			 "name", "pattern", "required", 1, "multi", 0);
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

struct list_rock {
    json_t *tzarray;
    struct hash_table *tztable;
};

static int list_cb(const char *tzid, int tzidlen,
		   struct zoneinfo *zi, void *rock)
{
    struct list_rock *lrock = (struct list_rock *) rock;
    char tzidbuf[200], lastmod[21];
    json_t *tz;

    if (lrock->tztable) {
	if (hash_lookup(tzid, lrock->tztable)) return 0;
	hash_insert(tzid, (void *) 0xDEADBEEF, lrock->tztable);
    }

    strlcpy(tzidbuf, tzid, tzidlen+1);
    rfc3339date_gen(lastmod, sizeof(lastmod), zi->dtstamp);

    tz = json_pack("{s:s s:s}", "tzid", tzidbuf, "last-modified", lastmod);
    json_array_append_new(lrock->tzarray, tz);

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
static int action_list(struct transaction_t *txn)
{
    int r, precond, tzid_only = 1;
    struct strlist *param, *name = NULL;
    icaltimetype changedsince = icaltime_null_time();
    struct resp_body_t *resp_body = &txn->resp_body;
    struct zoneinfo info;
    time_t lastmod;
    json_t *root = NULL;

    /* Sanity check the parameters */
    param = hash_lookup("action", &txn->req_qparams);
    if (!strcmp("find", param->s)) {
	name = hash_lookup("pattern", &txn->req_qparams);
	if (!name || name->next) {  /* mandatory, once only */
	    return json_error_response(txn, TZ_INVALID_PATTERN, name, NULL);
	}
	tzid_only = 0;
    }
    else {
	param = hash_lookup("changedsince", &txn->req_qparams);
	if (param) {
	    changedsince = icaltime_from_string(param->s);
	    if (param->next || !changedsince.is_utc) {  /* once only, UTC */
		return json_error_response(txn, TZ_INVALID_CHANGEDSINCE,
					   param, &changedsince);
	    }
	}

	name = hash_lookup("tzid", &txn->req_qparams);
	if (name) {
	    if (changedsince.is_utc) {
		return json_error_response(txn, TZ_INVALID_TZID,
					   param, &changedsince);
	    }
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


    if (txn->meth != METH_HEAD) {
	struct list_rock lrock = { NULL, NULL };
	struct hash_table tzids;
	char dtstamp[21];

	/* Start constructing our response */
	rfc3339date_gen(dtstamp, sizeof(dtstamp), lastmod);
	root = json_pack("{s:s s:[]}", "dtstamp", dtstamp, "timezones");
	if (!root) {
	    txn->error.desc = "Unable to create JSON response";
	    return HTTP_SERVER_ERROR;
	}

	lrock.tzarray = json_object_get(root, "timezones");
	if (!tzid_only) {
	    construct_hash_table(&tzids, 500, 1);
	    lrock.tztable = &tzids;
	}

	/* Add timezones to array */
	do {
	    zoneinfo_find(name ? name->s : NULL, tzid_only,
			  icaltime_as_timet(changedsince), &list_cb, &lrock);
	} while (name && (name = name->next));

	if (!tzid_only) free_hash_table(&tzids, NULL);
    }

    /* Output the JSON object */
    return json_response(precond, txn, root, NULL);
}


static void check_tombstone(struct observance *tombstone,
			    struct observance *obs)
{
    if (icaltime_compare(obs->onset, tombstone->onset) > 0) {
	/* onset is closer to cutoff than existing tombstone */
	tombstone->name = icalmemory_tmp_copy(obs->name);
	tombstone->offset_from = tombstone->offset_to = obs->offset_to;
	tombstone->is_daylight = obs->is_daylight;
	tombstone->onset = obs->onset;
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

static void expand_vtimezone(icalcomponent *vtz, icalarray *obsarray,
			     icaltimetype start, icaltimetype end)
{
    int truncate = !obsarray;
    icalcomponent *comp, *nextc, *tomb_std = NULL, *tomb_day = NULL;
    struct observance tombstone;

    memset(&tombstone, 0, sizeof(struct observance));

    /* Process each VTMEZONE STANDARD/DAYLIGHT subcomponent */
    for (comp = icalcomponent_get_first_component(vtz, ICAL_ANY_COMPONENT);
	 comp; comp = nextc) {
	icalproperty *prop, *dtstart_prop = NULL, *rrule_prop = NULL;
	icalarray *rdate_array = icalarray_new(sizeof(struct rdate), 10);
	icaltimetype dtstart;
	struct observance obs;
	unsigned n, trunc_dtstart = 0;
	int r;

	nextc = icalcomponent_get_next_component(vtz, ICAL_ANY_COMPONENT);

	memset(&obs, 0, sizeof(struct observance));
	obs.offset_from = obs.offset_to = INT_MAX;
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
		obs.onset = dtstart = icalproperty_get_dtstart(prop);
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
	if (!dtstart_prop || !obs.name ||
	    obs.offset_from == INT_MAX || obs.offset_to == INT_MAX) {
	    icalarray_free(rdate_array);
	    continue;
	}

	/* Adjust DTSTART observance to UTC */
	icaltime_adjust(&obs.onset, 0, 0, 0, -obs.offset_from);
	obs.onset.is_utc = 1;

	/* Check DTSTART vs window close */
	if (icaltime_compare(obs.onset, end) >= 0) {
	    /* All observances occur on/after window close, nothing to do */
	    icalarray_free(rdate_array);
	    continue;
	}

	/* Check DTSTART vs window open */
	r = icaltime_compare(obs.onset, start);
	if (r <= 0) {
	    /* DTSTART is on/prior to our window open - check it vs tombstone */
	    check_tombstone(&tombstone, &obs);
	}

	if (r >= 0) {
	    /* DTSTART is on/after our window open */
	    if (truncate) {
		/* All observances occur on/after window open - nothing to do */
		icalarray_free(rdate_array);
		continue;
	    }
	    else if (!rrule_prop) {
		/* Add the DTSTART observance to our array */
		icalarray_append(obsarray, &obs);
	    }
	}
	else {
	    /* DTSTART is prior to our window open - need to adjust it */
	    trunc_dtstart = 1;
	}

	if (rrule_prop) {
	    struct icalrecurrencetype rrule =
		icalproperty_get_rrule(rrule_prop);
	    icalrecur_iterator *ritr = NULL;

	    /* Check RRULE duration */
	    if (icaltime_is_null_time(rrule.until) ||
		icaltime_compare(rrule.until, start) >= 0) {
		/* RRULE ends on/after our window open */

		if (rrule.until.is_utc) {
		    /* Adjust UNTIL to local time */
		    icaltime_adjust(&rrule.until, 0, 0, 0, obs.offset_from);
		    rrule.until.is_utc = 0;
		}

		if (trunc_dtstart) {
		    /* Bump RRULE start to 1 year prior to our window open */
		    dtstart.year = start.year - 1;
		}

		ritr = icalrecur_iterator_new(rrule, dtstart);
	    }
	    else {
		/* RRULE ends prior to our window open -
		   check UNTIL vs tombstone */
		obs.onset = rrule.until;
		check_tombstone(&tombstone, &obs);

		if (truncate) {
		    /* Remove RRULE */
		    icalcomponent_remove_property(comp, rrule_prop);
		    icalproperty_free(rrule_prop);
		}
	    }

	    /* Add any RRULE observances within our window */
	    if (ritr) {
		icaltimetype recur;

		while (!icaltime_is_null_time(obs.onset = recur =
					      icalrecur_iterator_next(ritr))) {

		    /* Adjust observance to UTC */
		    icaltime_adjust(&obs.onset, 0, 0, 0, -obs.offset_from);
		    obs.onset.is_utc = 1;

		    if (icaltime_compare(obs.onset, end) >= 0) {
			/* Observance is on/after window close - we're done */
			break;
		    }

		    /* Check observance vs our window open */
		    r = icaltime_compare(obs.onset, start);
		    if (r <= 0) {
			/* Observance is on/prior to our window open -
			   check it vs tombstone */
			check_tombstone(&tombstone, &obs);
		    }

		    if (r >= 0) {
			/* Observance is on/after our window open */
			if (truncate && trunc_dtstart) {
			    unsigned ydiff;

			    /* Make this observance the new DTSTART */
			    icalproperty_set_dtstart(dtstart_prop, recur);
			    trunc_dtstart = 0;

			    /* Check if new DSTART is within 1 year of UNTIL */
			    ydiff = rrule.until.year - recur.year;
			    if (ydiff <= 1) {
				/* Remove RRULE */
				icalcomponent_remove_property(comp, rrule_prop);
				icalproperty_free(rrule_prop);

				if (ydiff) {
				    /* Add UNTIL as RDATE */
				    struct icaldatetimeperiodtype rdate = {
					rrule.until,
					icalperiodtype_null_period()
				    };
				    prop = icalproperty_new_rdate(rdate);
				    icalcomponent_add_property(comp, prop);
				}
			    }
			    break;
			}
			else {
			    /* Add the observance to our array */
			    icalarray_append(obsarray, &obs);
			}
		    }
		}
		icalrecur_iterator_free(ritr);
	    }
	}

	/* Sort the RDATEs by onset */
	icalarray_sort(rdate_array, &rdate_compare);

	/* Check RDATEs */
	for (n = 0; n < rdate_array->num_elements; n++) {
	    struct rdate *rdate = icalarray_element_at(rdate_array, n);

	    obs.onset = rdate->date.time;

	    /* Adjust observance to UTC */
	    icaltime_adjust(&obs.onset, 0, 0, 0, -obs.offset_from);
	    obs.onset.is_utc = 1;

	    if (icaltime_compare(obs.onset, end) >= 0) {
		/* RDATE is after our window close - we're done */
		break;
	    }

	    r = icaltime_compare(obs.onset, start);
	    if (r <= 0) {
		/* RDATE is on/prior to window open - check it vs tombstone */
		check_tombstone(&tombstone, &obs);
	    }

	    if (r >= 0) {
		/* RDATE is on/after our window open */
		if (truncate) {
		    if (trunc_dtstart) {
			/* Make this RDATE the new DTSTART */
			icalproperty_set_dtstart(dtstart_prop,
						 rdate->date.time);
			trunc_dtstart = 0;

			icalcomponent_remove_property(comp, rdate->prop);
			icalproperty_free(rdate->prop);
		    }
		    break;
		}
		else if (icaltime_compare(rdate->date.time, dtstart) != 0) {
		    /* RDATE != DTSTART - add observance to our array */
		    icalarray_append(obsarray, &obs);
		}
	    }
	    else if (truncate) {
		/* RDATE is prior to our window open - remove it */
		icalcomponent_remove_property(comp, rdate->prop);
		icalproperty_free(rdate->prop);
	    }
	}
	icalarray_free(rdate_array);

	/* Final check */
	if (truncate && trunc_dtstart) {
	    /* All observances in comp occur prior to window open, remove it
	       unless we haven't saved a tombstone comp of this type yet */
	    if (icalcomponent_isa(comp) == ICAL_XDAYLIGHT_COMPONENT) {
		if (!tomb_day) {
		    tomb_day = comp;
		    comp = NULL;
		}
	    }
	    else if (!tomb_std) {
		tomb_std = comp;
		comp = NULL;
	    }

	    if (comp) {
		icalcomponent_remove_component(vtz, comp);
		icalcomponent_free(comp);
	    }
	}
    }

    if (tombstone.name && icaltime_compare(tombstone.onset, start) < 0) {
	/* Need to add tombstone component/observance starting at window open
	   as long as its not prior to start of TZ data */
	if (truncate) {
	    /* Determine which tombstone component we need */
	    icalcomponent *tomb;
	    icalproperty *prop, *nextp;

	    if (tombstone.is_daylight) {
		tomb = tomb_day;
		tomb_day = NULL;
	    }
	    else {
		tomb = tomb_std;
		tomb_std = NULL;
	    }

	    /* Adjust property values on our tombstone */
	    for (prop =
		     icalcomponent_get_first_property(tomb, ICAL_ANY_PROPERTY);
		 prop; prop = nextp) {

		nextp =
		    icalcomponent_get_next_property(tomb, ICAL_ANY_PROPERTY);

		switch (icalproperty_isa(prop)) {
		case ICAL_TZNAME_PROPERTY:
		    icalproperty_set_tzname(prop, tombstone.name);
		    break;
		case ICAL_TZOFFSETFROM_PROPERTY:
		    icalproperty_set_tzoffsetfrom(prop, tombstone.offset_from);
		    break;
		case ICAL_TZOFFSETTO_PROPERTY:
		    icalproperty_set_tzoffsetto(prop, tombstone.offset_to);
		    break;
		case ICAL_DTSTART_PROPERTY:
		    /* Adjust DTSTART to local time */
		    icaltime_adjust(&start, 0, 0, 0, tombstone.offset_from);
		    start.is_utc = 0;

		    icalproperty_set_dtstart(prop, start);
		    break;
		default:
		    icalcomponent_remove_property(tomb, prop);
		    icalproperty_free(prop);
		    break;
		}
	    }
	}
	else {
	    tombstone.onset = start;
	    icalarray_append(obsarray, &tombstone);
	}
    }

    /* Remove any unused tombstone components */
    if (tomb_std) {
	icalcomponent_remove_component(vtz, tomb_std);
	icalcomponent_free(tomb_std);
    }
    if (tomb_day) {
	icalcomponent_remove_component(vtz, tomb_day);
	icalcomponent_free(tomb_day);
    }
}

static void truncate_vtimezone(icalcomponent *vtz, icaltimetype start)
{
    /* We don't have an end date for truncation, so use "end of time" */
    time_t now = INT_MAX;
    struct tm *tm = gmtime(&now);
    icaltimetype end = icaltime_from_day_of_year(1, tm->tm_year + 1900);

    expand_vtimezone(vtz, NULL, start, end);
}

/* Perform a get action */
static int action_get(struct transaction_t *txn)
{
    int r, precond;
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
    param = hash_lookup("tzid", &txn->req_qparams);
    if (!param || param->next) { /* mandatory, once only */
	return json_error_response(txn, TZ_INVALID_TZID, param, NULL);
    }
    if (strchr(param->s, '.')) {  /* paranoia */
	return json_error_response(txn, TZ_NOT_FOUND, NULL, NULL);
    }
    tzid = param->s;

    /* Check/find requested MIME type */
    param = hash_lookup("format", &txn->req_qparams);
    if (param && !param->next  /* optional, once only */) {
	for (mime = tz_mime_types; mime->content_type; mime++) {
	    if (is_mediatype(param->s, mime->content_type)) break;
	}
    }
    else mime = tz_mime_types;

    if (!mime || !mime->content_type) {
	return json_error_response(txn, TZ_INVALID_FORMAT, param, NULL);
    }

    /* Check for any truncation */
    param = hash_lookup("truncate", &txn->req_qparams);
    if (param) {
	truncate = icaltime_from_string(param->s);
	if (param->next || !truncate.is_utc) {  /* once only, UTC */
	    return json_error_response(txn, TZ_INVALID_TRUNCATE,
				       param, &truncate);
	}
    }

    /* Get info record from the database */
    if ((r = zoneinfo_lookup(tzid, &zi))) {
	return (r == CYRUSDB_NOTFOUND ?
		json_error_response(txn, TZ_NOT_FOUND, NULL, NULL)
		: HTTP_SERVER_ERROR);
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


    if (txn->meth != METH_HEAD) {
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

	if (zi.type == ZI_LINK) {
	    /* Add EQUIVALENT-TZID */
	    const char *equiv = icalproperty_get_tzid(prop);
	    icalproperty *eprop = icalproperty_new_x(equiv);

	    icalproperty_set_x_name(eprop, "EQUIVALENT-TZID");	
	    icalcomponent_add_property(vtz, eprop);

	    /* Substitute TZID alias */
	    icalproperty_set_tzid(prop, tzid);
	}

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
	if (truncate.is_utc) {
	    buf_printf(&pathbuf, "&truncate=%s",
		       icaltime_as_ical_string(truncate));

	    /* Truncate the VTIMEZONE */
	    truncate_vtimezone(vtz, truncate);
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


static int observance_compare(const void *obs1, const void *obs2)
{
    return icaltime_compare(((struct observance *) obs1)->onset,
			    ((struct observance *) obs2)->onset);
}


static const char *dow[] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
static const char *mon[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun",
			     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

#define CTIME_FMT "%s %s %2d %02d:%02d:%02d %4d"
#define CTIME_ARGS(tt) \
    dow[icaltime_day_of_week(tt)-1], mon[tt.month-1], \
    tt.day, tt.hour, tt.minute, tt.second, tt.year


/* Perform an expand action */
static int action_expand(struct transaction_t *txn)
{
    int r, precond, zdump = 0;
    struct strlist *param;
    const char *tzid;
    struct zoneinfo zi;
    time_t lastmod;
    icaltimetype start, end, changedsince = icaltime_null_time();
    struct resp_body_t *resp_body = &txn->resp_body;
    json_t *root = NULL;

    /* Sanity check the parameters */
    param = hash_lookup("tzid", &txn->req_qparams);
    if (!param || param->next) {  /* mandatory, once only */
	return json_error_response(txn, TZ_INVALID_TZID, param, NULL);
    }
    if (strchr(param->s, '.')) {  /* paranoia */
	return json_error_response(txn, TZ_NOT_FOUND, NULL, NULL);
    }
    tzid = param->s;

    param = hash_lookup("changedsince", &txn->req_qparams);
    if (param) {
	changedsince = icaltime_from_string(param->s);
	if (param->next || !changedsince.is_utc) {  /* once only, UTC */
	    return json_error_response(txn, TZ_INVALID_CHANGEDSINCE,
				       param, &changedsince);
	}
    }

    param = hash_lookup("start", &txn->req_qparams);
    if (!param || param->next)  /* mandatory, once only */
	return json_error_response(txn, TZ_INVALID_START, param, NULL);

    start = icaltime_from_string(param->s);
    if (!start.is_utc)  /* MUST be UTC */
	return json_error_response(txn, TZ_INVALID_START, param, &start);

    param = hash_lookup("end", &txn->req_qparams);
    if (param) {
	end = icaltime_from_string(param->s);
	if (param->next || !end.is_utc  /* once only, UTC */
	    || icaltime_compare(end, start) <= 0) {  /* end MUST be > start */
	    return json_error_response(txn, TZ_INVALID_END, param, &end);
	}
    }
    else {
	/* Default to start + 10 years */
	end = start;
	end.year += 10;
    }

    /* Check requested format (debugging only) */
    param = hash_lookup("format", &txn->req_qparams);
    if (param) {
	if (param->next || strcmp(param->s, "zdump"))  /* optional, once only */
	    return json_error_response(txn, TZ_INVALID_FORMAT, param, NULL);

	/* Mimic zdump(8) output for comparision:
	   For each zonename on the command line, print  the  time  at  the
	   lowest  possible  time  value, the time one day after the lowest
	   possible time value,  the  times  both  one  second  before  and
	   exactly at each detected time discontinuity, the time at one day
	   less than the highest possible time value, and the time  at  the
	   highest  possible time value, Each line ends with isdst=1 if the
	   given time is Daylight Saving Time or isdst=0 otherwise.
	*/
	zdump = 1;
    }

    /* Get info record from the database */
    if ((r = zoneinfo_lookup(tzid, &zi))) {
	return (r == CYRUSDB_NOTFOUND ?
		json_error_response(txn, TZ_NOT_FOUND, NULL, NULL)
		: HTTP_SERVER_ERROR);
    }

    /* Generate ETag & Last-Modified from info record */
    assert(!buf_len(&txn->buf));
    buf_printf(&txn->buf, "%u-%ld", strhash(tzid), zi.dtstamp);
    lastmod = zi.dtstamp;
    freestrlist(zi.data);

    /* Check any preconditions, including range request */
    txn->flags.ranges = 1;
    if (lastmod <= icaltime_as_timet(changedsince)) precond = HTTP_NOT_MODIFIED;
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


    if (txn->meth != METH_HEAD) {
	static struct buf pathbuf = BUF_INITIALIZER;
	const char *path, *msg_base = NULL;
	unsigned long msg_size = 0;
	icalcomponent *ical, *vtz;
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
	if (zdump) {
	    struct buf *body = &txn->resp_body.payload;
	    const time_t min_time =
		((time_t) -1 < 0
		 ? (time_t) -1 << (CHAR_BIT * sizeof (time_t) - 1)
		 : 0);

	    txn->resp_body.type = "text/plain; charset=us-ascii";

	    /* Lowest possible time value and day after lowest time value */
	    buf_printf(body, "%s  %ld = NULL\n", tzid, min_time);
	    buf_printf(body, "%s  %ld = NULL\n", tzid, min_time + 86400);
	}
	else {
	    rfc3339date_gen(dtstamp, sizeof(dtstamp), lastmod);
	    root = json_pack("{s:s s:s s:[]}",
			     "dtstamp", dtstamp, "tzid", tzid, "observances");
	    if (!root) {
		txn->error.desc = "Unable to create JSON response";
		return HTTP_SERVER_ERROR;
	    }
	}
	

	/* Create an array of observances */
	obsarray = icalarray_new(sizeof(struct observance), 20);
	vtz = icalcomponent_get_first_component(ical, ICAL_VTIMEZONE_COMPONENT);
	expand_vtimezone(vtz, obsarray, start, end);

	/* Sort the observances by onset */
	icalarray_sort(obsarray, &observance_compare);

	if (zdump) {
	    struct buf *body = &txn->resp_body.payload;
	    struct icaldurationtype off = icaldurationtype_null_duration();
	    const char *prev_name = "LMT";
	    int prev_isdst = 0;

	    for (n = 0; n < obsarray->num_elements; n++) {
		struct observance *obs = icalarray_element_at(obsarray, n);
		struct icaltimetype local, ut;

		/* Skip any no-ops as zdump doesn't output them */
		if (obs->offset_from == obs->offset_to
		    && prev_isdst == obs->is_daylight
		    && !strcmp(prev_name, obs->name)) continue;

		/* UT and local time 1 second before onset */
		off.seconds = -1;
		ut = icaltime_add(obs->onset, off);

		off.seconds = obs->offset_from;
		local = icaltime_add(ut, off);

		buf_printf(body,
			   "%s  " CTIME_FMT " UT = " CTIME_FMT " %s"
			   " isdst=%d gmtoff=%d\n",
			   tzid, CTIME_ARGS(ut), CTIME_ARGS(local),
			   prev_name, prev_isdst, obs->offset_from);

		/* UT and local time at onset */
		icaltime_adjust(&ut, 0, 0, 0, 1);

		off.seconds = obs->offset_to;
		local = icaltime_add(ut, off);

		buf_printf(body,
			   "%s  " CTIME_FMT " UT = " CTIME_FMT " %s"
			   " isdst=%d gmtoff=%d\n",
			   tzid, CTIME_ARGS(ut), CTIME_ARGS(local),
			   obs->name, obs->is_daylight, obs->offset_to);

		prev_name = obs->name;
		prev_isdst = obs->is_daylight;
	    }
	}
	else {
	    /* Add observances to JSON array */
	    jobsarray = json_object_get(root, "observances");
	    for (n = 0; n < obsarray->num_elements; n++) {
		struct observance *obs = icalarray_element_at(obsarray, n);

		json_array_append_new(jobsarray,
				      json_pack(
					  "{s:s s:s s:i s:i}",
					  "name", obs->name,
					  "onset",
					  icaltime_as_iso_string(obs->onset),
					  "utc-offset-from", obs->offset_from,
					  "utc-offset-to", obs->offset_to));
	    }
	}
	icalarray_free(obsarray);

	icalcomponent_free(ical);
    }

    if (zdump) {
	struct buf *body = &txn->resp_body.payload;
	const time_t max_time =
	    ((time_t) -1 < 0
	     ? - (~ 0 < 0) - ((time_t) -1 << (CHAR_BIT * sizeof (time_t) - 1))
	     : -1);

	/* Day before highest possible time value and highest time value */
	buf_printf(body, "%s  %ld = NULL\n", tzid, max_time - 86400);
	buf_printf(body, "%s  %ld = NULL\n", tzid, max_time);
	write_body(precond, txn, buf_cstring(body), buf_len(body));

	return 0;
    }
    else {
	/* Output the JSON object */
	return json_response(precond, txn, root, NULL);
    }
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


/* Array of parameter names - MUST be kept in sync with tz_err.et */
static const char *param_names[] = {
    "action",
    "tzid",
    "pattern",
    "format",
    "start",
    "end",
    "changedsince",
    "truncate",
    "tzid"
};

static int json_error_response(struct transaction_t *txn, long tz_code,
			       struct strlist *param, icaltimetype *time)
{
    long http_code = HTTP_BAD_REQUEST;
    const char *param_name, *fmt = NULL;
    char desc[100];
    json_t *root;

    param_name = param_names[tz_code - tz_err_base];

    if (!param) fmt = "missing %s parameter";
    else if (param->next) fmt = "multiple %s parameters";
    else if (!time) fmt = "unknown %s value";
    else if (!time->is_utc) fmt = "invalid %s UTC value";

    switch (tz_code) {
    case TZ_INVALID_TZID:
	if (!fmt) fmt = "tzid used with changedsince";
	break;

    case TZ_INVALID_END:
	if (!fmt) fmt = "end <= start";
	break;

    case TZ_NOT_FOUND:
	http_code = HTTP_NOT_FOUND;
	fmt = "time zone not found";
	break;
    }

    snprintf(desc, sizeof(desc), fmt ? fmt : "unknown error", param_name);

    root = json_pack("{s:s s:s}", "error", error_message(tz_code),
		     "description", desc);
    if (!root) {
	txn->error.desc = "Unable to create JSON response";
	return HTTP_SERVER_ERROR;
    }

    return json_response(http_code, txn, root, NULL);
}
