/* http_tzdist.c -- Routines for handling tzdist service requests in httpd
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
 * - Implement localized names / handle Accept-Language header field?
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


#define TZDIST_WELLKNOWN_URI "/.well-known/timezone"

static time_t compile_time;
static void tzdist_init(struct buf *serverinfo);
static void tzdist_shutdown(void);
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
    const char *path;
    int need_tzid;
    int (*proc)(struct transaction_t *txn);
} actions[] = {
    { "capabilities",	0,	&action_capa },
    { "zones",		0,	&action_list },
    { "zones",		1,	&action_get },
    { "observances",	1,	&action_expand },
    { NULL,		0,	NULL}
};


static struct mime_type_t tz_mime_types[] = {
    /* First item MUST be the default type and storage format */
    { "text/calendar; charset=utf-8", "2.0", "ics",
      (char* (*)(void *)) &icalcomponent_as_ical_string_r,
      NULL, NULL, NULL, NULL
    },
    { "application/calendar+xml; charset=utf-8", NULL, "xcs",
      (char* (*)(void *)) &icalcomponent_as_xcal_string,
      NULL, NULL, NULL, NULL
    },
    { "application/calendar+json; charset=utf-8", NULL, "jcs",
      (char* (*)(void *)) &icalcomponent_as_jcal_string,
      NULL, NULL, NULL, NULL
    },
    { NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL }
};


/* Namespace for tzdist service */
struct namespace_t namespace_tzdist = {
    URL_NS_TZDIST, 0, "/tzdist", TZDIST_WELLKNOWN_URI, 0 /* auth */, ALLOW_READ,
    tzdist_init, NULL, NULL, tzdist_shutdown,
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
	{ NULL,			NULL },			/* POST	*/
	{ NULL,			NULL },			/* PROPFIND	*/
	{ NULL,			NULL },			/* PROPPATCH	*/
	{ NULL,			NULL },			/* PUT		*/
	{ NULL,			NULL },			/* REPORT	*/
	{ &meth_trace,		NULL },			/* TRACE	*/
	{ NULL,			NULL }			/* UNLOCK	*/
    }
};


static void tzdist_init(struct buf *serverinfo __attribute__((unused)))
{
    namespace_tzdist.enabled =
	config_httpmodules & IMAP_ENUM_HTTPMODULES_TZDIST;

    if (!namespace_tzdist.enabled) return;

    /* Open zoneinfo db */
    if (zoneinfo_open(NULL)) {
	namespace_tzdist.enabled = 0;
	return;
    }

    compile_time = calc_compile_time(__TIME__, __DATE__);

    initialize_tz_error_table();
}


static void tzdist_shutdown(void)
{
    zoneinfo_close(NULL);
}


/* Perform a GET/HEAD request */
static int meth_get(struct transaction_t *txn,
		    void *params __attribute__((unused)))
{
    struct request_target_t *tgt = &txn->req_tgt;
    const struct action_t *ap = NULL;
    char *p;

    /* Make a working copy of target path */
    strlcpy(tgt->path, txn->req_uri->path, sizeof(tgt->path));
    p = tgt->path;

    /* Skip namespace */
    p += strlen(namespace_tzdist.prefix);
    if (*p == '/') *p++ = '\0';

    /* Check for path after prefix */
    if (*p) {
	/* Get collection (action) */
	tgt->collection = p;
	p += strcspn(p, "/");
	if (*p == '/') *p++ = '\0';

	if (*p) {
	    /* Get resource (tzid) */
	    tgt->resource = p;
	    p += strlen(p);
	    if (p[-1] == '/') *--p = '\0';
	}

	/* Search known actions for matching path */
	for (ap = actions; ap->path; ap++) {

	    if (!strcmp(tgt->collection, ap->path)) {
		if (ap->need_tzid) {
		    if (tgt->resource) break;
		}
		else if (!tgt->resource) break;
	    }
	}
    }

    if (!ap || !ap->path)
	return json_error_response(txn, TZ_INVALID_ACTION, NULL, NULL);

    if (tgt->resource && strchr(tgt->resource, '.'))  /* paranoia */
	return json_error_response(txn, TZ_NOT_FOUND, NULL, NULL);

    return ap->proc(txn);
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
	struct mime_type_t *mime;
	json_t *formats;
	int r;

	/* Get info record from the database */
	if ((r = zoneinfo_lookup_info(&info))) return HTTP_SERVER_ERROR;

	/* Construct our response */
	root = json_pack("{ s:i"			/* version */
			 "  s:{"			/* info */
			 "      s:s"			/*   primary-source */
			 "      s:[]"			/*   formats */
			 "      s:{s:b s:b}"		/*   truncated */
//			 "      s:s"   			/*   provider-details */
//			 "      s:[]"  			/*   contacts */
			 "    }"
			 "  s:["			/* actions */
			 "    {s:s s:["			/*   capabilities */
			 "    ]}"
			 "    {s:s s:["			/*   list */
			 "      {s:s}"			/*     changedsince */
			 "    ]}"
			 "    {s:s s:["			/*   get */
			 "      {s:s}"			/*     start */
			 "      {s:s}"			/*     end */
			 "    ]}"
			 "    {s:s s:["			/*   expand */
			 "      {s:s s:b}"		/*     start */
			 "      {s:s s:b}"		/*     end */
			 "      {s:s}"			/*     changedsince */
			 "    ]}"
			 "    {s:s s:["			/*   find */
			 "      {s:s s:b}"		/*     pattern */
			 "    ]}"
			 "  ]}",

			 "version", 1,

			 "info", "primary-source", info.data->s, "formats",
			 "truncated", "any", 1, "untruncated", 1,
//			 "provider-details", "", "contacts",

			 "actions",
			 "name", "capabilities", "parameters",

			 "name", "list", "parameters",
			 "name", "changedsince",

			 "name", "get", "parameters",
			 "name", "start",
			 "name", "end",

			 "name", "expand", "parameters",
			 "name", "start", "required", 1,
			 "name", "end", "required", 1,
			 "name", "changedsince",

			 "name", "find", "parameters",
			 "name", "pattern", "required", 1);
	freestrlist(info.data);

	if (!root) {
	    txn->error.desc = "Unable to create JSON response";
	    return HTTP_SERVER_ERROR;
	}

	/* Add supported formats */
	formats = json_object_get(json_object_get(root, "info"), "formats");
	for (mime = tz_mime_types; mime->content_type; mime++) {
	    buf_setcstr(&txn->buf, mime->content_type);
	    buf_truncate(&txn->buf, strcspn(mime->content_type, ";"));
	    json_array_append_new(formats, json_string(buf_cstring(&txn->buf)));
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
    int r, precond;
    struct strlist *param;
    const char *pattern = NULL;
    icaltimetype changedsince = icaltime_null_time();
    struct resp_body_t *resp_body = &txn->resp_body;
    struct zoneinfo info;
    time_t lastmod;
    json_t *root = NULL;

    /* Sanity check the parameters */
    if ((param = hash_lookup("pattern", &txn->req_qparams))) {
	if (param->next			  /* once only */
	    || !param->s || !*param->s	  /* not empty */
	    || strspn(param->s, "*") == strlen(param->s)) {  /* not (*)+ */
	    return json_error_response(txn, TZ_INVALID_PATTERN, param, NULL);
	}
	pattern = param->s;
    }
    else if ((param = hash_lookup("changedsince", &txn->req_qparams))) {
	changedsince = icaltime_from_string(param->s);
	if (param->next || !changedsince.is_utc) {  /* once only, UTC */
	    return json_error_response(txn, TZ_INVALID_CHANGEDSINCE,
				       param, &changedsince);
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
	if (pattern) {
	    construct_hash_table(&tzids, 500, 1);
	    lrock.tztable = &tzids;
	}

	/* Add timezones to array */
	zoneinfo_find(pattern, !pattern,
		      icaltime_as_timet(changedsince), &list_cb, &lrock);

	if (pattern) free_hash_table(&tzids, NULL);
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

static const struct observance *truncate_vtimezone(icalcomponent *vtz,
						   icaltimetype start,
						   icaltimetype end,
						   icalarray *obsarray)
{
    icalcomponent *comp, *nextc, *tomb_std = NULL, *tomb_day = NULL;
    icalproperty *prop, *proleptic_prop = NULL;
    static struct observance tombstone;
    unsigned need_tomb = !icaltime_is_null_time(start);

    /* See if we have a proleptic tzname in VTIMEZONE */
    for (prop = icalcomponent_get_first_property(vtz, ICAL_X_PROPERTY);
	 prop;
	 prop = icalcomponent_get_next_property(vtz, ICAL_X_PROPERTY)) {
	if (!strcmp("X-PROLEPTIC-TZNAME", icalproperty_get_x_name(prop))) {
	    proleptic_prop = prop;
	    break;
	}
    }

    memset(&tombstone, 0, sizeof(struct observance));
    tombstone.name = icalmemory_tmp_copy(proleptic_prop ?
					 icalproperty_get_x(proleptic_prop) :
					 "LMT");

    /* Process each VTMEZONE STANDARD/DAYLIGHT subcomponent */
    for (comp = icalcomponent_get_first_component(vtz, ICAL_ANY_COMPONENT);
	 comp; comp = nextc) {
	icalproperty *dtstart_prop = NULL, *rrule_prop = NULL;
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
	if (!icaltime_is_null_time(end) &&
	    icaltime_compare(obs.onset, end) >= 0) {
	    /* All observances occur on/after window close - remove component */
	    icalcomponent_remove_component(vtz, comp);
	    icalcomponent_free(comp);

	    /* Nothing else to do */
	    icalarray_free(rdate_array);
	    continue;
	}

	/* Check DTSTART vs window open */
	r = icaltime_compare(obs.onset, start);
	if (r < 0) {
	    /* DTSTART is prior to our window open - check it vs tombstone */
	    if (need_tomb) check_tombstone(&tombstone, &obs);

	    /* Adjust it */
	    trunc_dtstart = 1;
	}
	else {
	    /* DTSTART is on/after our window open */
	    if (r == 0) need_tomb = 0;

	    if (obsarray && !rrule_prop) {
		/* Add the DTSTART observance to our array */
		icalarray_append(obsarray, &obs);
	    }
	}

	if (rrule_prop) {
	    struct icalrecurrencetype rrule =
		icalproperty_get_rrule(rrule_prop);
	    icalrecur_iterator *ritr = NULL;
	    unsigned infinite = icaltime_is_null_time(rrule.until);
	    unsigned trunc_until = 0;

	    /* Check RRULE duration */
	    if (!infinite && icaltime_compare(rrule.until, start) < 0) {
		/* RRULE ends prior to our window open -
		   check UNTIL vs tombstone */
		obs.onset = rrule.until;
		if (need_tomb) check_tombstone(&tombstone, &obs);

		/* Remove RRULE */
		icalcomponent_remove_property(comp, rrule_prop);
		icalproperty_free(rrule_prop);
	    }
	    else {
		/* RRULE ends on/after our window open */
		if (!icaltime_is_null_time(end) &&
		    (infinite || icaltime_compare(rrule.until, end) > 0)) {
		    /* RRULE ends after our window close - need to adjust it */
		    trunc_until = 1;
		}

		if (!infinite) {
		    /* Adjust UNTIL to local time (for iterator) */
		    icaltime_adjust(&rrule.until, 0, 0, 0, obs.offset_from);
		    rrule.until.is_utc = 0;
		}

		if (trunc_dtstart) {
		    /* Bump RRULE start to 1 year prior to our window open */
		    dtstart.year = start.year - 1;
		}

		ritr = icalrecur_iterator_new(rrule, dtstart);
	    }

	    /* Process any RRULE observances within our window */
	    if (ritr) {
		icaltimetype recur, prev_onset;

		/* Mark original DTSTART (UTC) */
		dtstart = obs.onset;

		while (!icaltime_is_null_time(obs.onset = recur =
					      icalrecur_iterator_next(ritr))) {
		    unsigned ydiff;

		    /* Adjust observance to UTC */
		    icaltime_adjust(&obs.onset, 0, 0, 0, -obs.offset_from);
		    obs.onset.is_utc = 1;

		    if (trunc_until && icaltime_compare(obs.onset, end) > 0) {
			/* Observance is on/after window close */

			/* Check if DSTART is within 1yr of prev onset */
			ydiff = prev_onset.year - dtstart.year;
			if (ydiff <= 1) {
			    /* Remove RRULE */
			    icalcomponent_remove_property(comp, rrule_prop);
			    icalproperty_free(rrule_prop);

			    if (ydiff) {
				/* Add previous onset as RDATE */
				struct icaldatetimeperiodtype rdate = {
				    prev_onset,
				    icalperiodtype_null_period()
				};
				prop = icalproperty_new_rdate(rdate);
				icalcomponent_add_property(comp, prop);
			    }
			}
			else {
			    /* Set UNTIL to previous onset */
			    rrule.until = prev_onset;
			    icalproperty_set_rrule(rrule_prop, rrule);
			}

			/* We're done */
			break;
		    }

		    /* Check observance vs our window open */
		    r = icaltime_compare(obs.onset, start);
		    if (r < 0) {
			/* Observance is prior to our window open -
			   check it vs tombstone */
			if (need_tomb) check_tombstone(&tombstone, &obs);
		    }
		    else {
			/* Observance is on/after our window open */
			if (r == 0) need_tomb = 0;

			if (trunc_dtstart) {
			    /* Make this observance the new DTSTART */
			    icalproperty_set_dtstart(dtstart_prop, recur);
			    dtstart = obs.onset;
			    trunc_dtstart = 0;

			    /* Check if new DSTART is within 1yr of UNTIL */
			    ydiff = rrule.until.year - recur.year;
			    if (!trunc_until && ydiff <= 1) {
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
			}

			if (obsarray) {
			    /* Add the observance to our array */
			    icalarray_append(obsarray, &obs);
			}
			else if (!trunc_until) {
			    /* We're done */
			    break;
			}
		    }
		    prev_onset = obs.onset;
		}
		icalrecur_iterator_free(ritr);
	    }
	}

	/* Sort the RDATEs by onset */
	icalarray_sort(rdate_array, &rdate_compare);

	/* Check RDATEs */
	for (n = 0; n < rdate_array->num_elements; n++) {
	    struct rdate *rdate = icalarray_element_at(rdate_array, n);

	    if (n == 0 && icaltime_compare(rdate->date.time, dtstart) == 0) {
		/* RDATE is same as DTSTART - remove it */
		icalcomponent_remove_property(comp, rdate->prop);
		icalproperty_free(rdate->prop);
		continue;
	    }

	    obs.onset = rdate->date.time;

	    /* Adjust observance to UTC */
	    icaltime_adjust(&obs.onset, 0, 0, 0, -obs.offset_from);
	    obs.onset.is_utc = 1;

	    if (!icaltime_is_null_time(end) &&
		icaltime_compare(obs.onset, end) >= 0) {
		/* RDATE is after our window close - remove it */
		icalcomponent_remove_property(comp, rdate->prop);
		icalproperty_free(rdate->prop);
		continue;
	    }

	    r = icaltime_compare(obs.onset, start);
	    if (r < 0) {
		/* RDATE is prior to window open - check it vs tombstone */
		if (need_tomb) check_tombstone(&tombstone, &obs);

		/* Remove it */
		icalcomponent_remove_property(comp, rdate->prop);
		icalproperty_free(rdate->prop);
	    }
	    else {
		/* RDATE is on/after our window open */
		if (r == 0) need_tomb = 0;

		if (trunc_dtstart) {
		    /* Make this RDATE the new DTSTART */
		    icalproperty_set_dtstart(dtstart_prop,
					     rdate->date.time);
		    trunc_dtstart = 0;

		    icalcomponent_remove_property(comp, rdate->prop);
		    icalproperty_free(rdate->prop);
		}

		if (obsarray) {
		    /* Add the observance to our array */
		    icalarray_append(obsarray, &obs);
		}
	    }
	}
	icalarray_free(rdate_array);

	/* Final check */
	if (trunc_dtstart) {
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

    if (need_tomb && !icaltime_is_null_time(tombstone.onset)) {
	/* Need to add tombstone component/observance starting at window open
	   as long as its not prior to start of TZ data */
	icalcomponent *tomb;
	icalproperty *prop, *nextp;

	if (obsarray) {
	    /* Add the tombstone to our array */
	    tombstone.onset = start;
	    icalarray_append(obsarray, &tombstone);
	}

	/* Determine which tombstone component we need */
	if (tombstone.is_daylight) {
	    tomb = tomb_day;
	    tomb_day = NULL;
	}
	else {
	    tomb = tomb_std;
	    tomb_std = NULL;
	}

	/* Set property values on our tombstone */
	for (prop = icalcomponent_get_first_property(tomb, ICAL_ANY_PROPERTY);
	     prop; prop = nextp) {

	    nextp = icalcomponent_get_next_property(tomb, ICAL_ANY_PROPERTY);

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
		/* Adjust window open to local time */
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

	/* Remove X-PROLEPTIC-TZNAME as it no longer applies */
	if (proleptic_prop) {
	    icalcomponent_remove_property(vtz, proleptic_prop);
	    icalproperty_free(proleptic_prop);
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

    return &tombstone;
}

#ifndef HAVE_TZDIST_PROPS
static icalproperty *icalproperty_new_tzidaliasof(const char *v)
{
    icalproperty *prop = icalproperty_new_x(v);
    icalproperty_set_x_name(prop, "TZID-ALIAS-OF");
    return prop;
}

static icalproperty *icalproperty_new_tzuntil(struct icaltimetype v)
{
    icalproperty *prop = icalproperty_new_x(icaltime_as_ical_string(v));
    icalproperty_set_x_name(prop, "TZUNTIL");
    return prop;
}
#endif /* HAVE_TZDIST_PROPS */

/* Perform a get action */
static int action_get(struct transaction_t *txn)
{
    int r, precond;
    struct strlist *param;
    const char *tzid = txn->req_tgt.resource;
    struct zoneinfo zi;
    time_t lastmod;
    icaltimetype start = icaltime_null_time(), end = icaltime_null_time();
    char *data = NULL;
    unsigned long datalen = 0;
    struct resp_body_t *resp_body = &txn->resp_body;
    struct mime_type_t *mime = NULL;
    const char **hdr;

    /* Check/find requested MIME type:
       1st entry in gparams->mime_types array MUST be default MIME type */
    if ((hdr = spool_getheader(txn->req_hdrs, "Accept")))
	mime = get_accept_type(hdr, tz_mime_types);
    else mime = tz_mime_types;

    if (!mime) return json_error_response(txn, TZ_INVALID_FORMAT, NULL, NULL);

    /* Sanity check the parameters */
    if ((param = hash_lookup("start", &txn->req_qparams))) {
	start = icaltime_from_string(param->s);
	if (param->next || !start.is_utc) {  /* once only, UTC */
	    return json_error_response(txn, TZ_INVALID_START, param, &start);
	}
    }

    if ((param = hash_lookup("end", &txn->req_qparams))) {
	end = icaltime_from_string(param->s);
	if (param->next || !end.is_utc  /* once only, UTC */
	    || icaltime_compare(end, start) <= 0) {  /* end MUST be > start */
	    return json_error_response(txn, TZ_INVALID_END, param, &end);
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
	    /* Add TZID-ALIAS-OF */
	    const char *aliasof = icalproperty_get_tzid(prop);
	    icalproperty *atzid = icalproperty_new_tzidaliasof(aliasof);

	    icalcomponent_add_property(vtz, atzid);

	    /* Substitute TZID alias */
	    icalproperty_set_tzid(prop, tzid);
	}

	/* Start constructing TZURL */
	buf_reset(&pathbuf);
	http_proto_host(txn->req_hdrs, &proto, &host);
	buf_printf(&pathbuf, "%s://%s%s", proto, host, txn->req_uri->path);

	if (!icaltime_is_null_time(start) || !icaltime_is_null_time(end)) {

	    if (!icaltime_is_null_time(end)) {
		/* Add TZUNTIL to VTIMEZONE */
		icalproperty *tzuntil = icalproperty_new_tzuntil(end);
		icalcomponent_add_property(vtz, tzuntil);
	    }

	    /* Add truncation parameter(s) to TZURL */
	    buf_printf(&pathbuf, "?%s", URI_QUERY(txn->req_uri));

	    /* Truncate the VTIMEZONE */
	    truncate_vtimezone(vtz, start, end, NULL);
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

	txn->flags.vary |= VARY_ACCEPT;

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
    const char *tzid = txn->req_tgt.resource;
    struct zoneinfo zi;
    time_t lastmod;
    icaltimetype start, end, changedsince = icaltime_null_time();
    struct resp_body_t *resp_body = &txn->resp_body;
    json_t *root = NULL;

    /* Sanity check the parameters */
    if ((param = hash_lookup("changedsince", &txn->req_qparams))) {
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
    if (!param || param->next)  /* mandatory, once only */
	return json_error_response(txn, TZ_INVALID_END, param, NULL);

    end = icaltime_from_string(param->s);
    if (!end.is_utc  /* MUST be UTC */
	|| icaltime_compare(end, start) <= 0) {  /* end MUST be > start */
	return json_error_response(txn, TZ_INVALID_END, param, &end);
    }

    /* Check requested format (debugging only) */
    if ((param = hash_lookup("zdump", &txn->req_qparams))) {
	/* Mimic zdump(8) -V output for comparision:

	   For each zonename, print the times both one  second  before  and
	   exactly at each detected time discontinuity, the time at one day
	   less than the highest possible time value, and the time  at  the
	   highest  possible  time value.  Each line is followed by isdst=D
	   where D is positive, zero, or negative depending on whether  the
	   given time is daylight saving time, standard time, or an unknown
	   time type, respectively.  Each line is also followed by gmtoff=N
	   if  the given local time is known to be N seconds east of Green‐
	   wich.
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
	const struct observance *proleptic;
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
	    txn->resp_body.type = "text/plain; charset=us-ascii";
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
	proleptic = truncate_vtimezone(vtz, start, end, obsarray);

	/* Sort the observances by onset */
	icalarray_sort(obsarray, &observance_compare);

	if (zdump) {
	    struct buf *body = &txn->resp_body.payload;
	    struct icaldurationtype off = icaldurationtype_null_duration();
	    const char *prev_name = proleptic->name;
	    int prev_isdst = proleptic->is_daylight;

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
    if (code == HTTP_OK)
	txn->resp_body.type = "application/json; charset=utf-8";
    else
	txn->resp_body.type = "application/problem+json; charset=utf-8";
    write_body(code, txn, buf, buf ? strlen(buf) : 0);

    if (!resp && buf) free(buf);

    return 0;
}


/* Array of parameter names - MUST be kept in sync with tz_err.et */
static const char *param_names[] = {
    "action",
    "pattern",
    "format",
    "start",
    "end",
    "changedsince",
    "tzid"
};

static int json_error_response(struct transaction_t *txn, long tz_code,
			       struct strlist *param, icaltimetype *time)
{
    long http_code = HTTP_BAD_REQUEST;
    const char *param_name, *fmt = NULL;
    json_t *root;

    param_name = param_names[tz_code - tz_err_base];

    if (!param) {
	switch (tz_code) {
	case TZ_INVALID_ACTION:
	    fmt = "Request URI doesn't map to a known action";
	    break;

	case TZ_INVALID_FORMAT:
	    http_code = HTTP_NOT_ACCEPTABLE;
	    fmt = "Unsupported media type";
	    break;

	case TZ_NOT_FOUND:
	    http_code = HTTP_NOT_FOUND;
	    fmt = "Time zone identifier not found";
	    break;

	default:
	    fmt = "Missing %s parameter";
	    break;
	}
    }
    else if (param->next) fmt = "Multiple %s parameters";
    else if (!param->s || !param->s[0]) fmt = "Missing %s value";
    else if (!time) fmt = "Invalid %s value";
    else if (!time->is_utc) fmt = "Invalid %s UTC value";
    else fmt = "End date-time <= start date-time";

    assert(!buf_len(&txn->buf));
    buf_printf(&txn->buf, fmt, param_name);

    root = json_pack("{s:s s:s s:i}", "title", buf_cstring(&txn->buf),
		     "error-code", error_message(tz_code),
		     "status", atoi(error_message(http_code)));;
    if (!root) {
	txn->error.desc = "Unable to create JSON response";
	return HTTP_SERVER_ERROR;
    }

    return json_response(http_code, txn, root, NULL);
}
