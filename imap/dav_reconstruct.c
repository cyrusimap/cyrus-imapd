/* dav_reconstruct.c - (re)build DAV DB for a user
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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <libical/ical.h>

#include "annotate.h"
#include "caldav_db.h"
#include "dav_prop.h"
#include "global.h"
#include "imap_err.h"
#include "mailbox.h"
#include "message.h"
#include "message_guid.h"
#include "mboxname.h"
#include "mboxlist.h"
#include "xmalloc.h"

extern int optind;
extern char *optarg;

/* current namespace */
static struct namespace recon_namespace;

/* config.c stuff */
const int config_need_data = 0;

/* forward declarations */
int do_reconstruct(char *name, int matchlen, int maycreate, void *rock);
void usage(void);
void shut_down(int code);

static int code = 0;
static struct caldav_db *caldavdb = NULL;


int main(int argc, char **argv)
{
    int opt, r;
    char buf[MAX_MAILBOX_PATH+1];
    char *alt_config = NULL, *userid;

    if ((geteuid()) == 0 && (become_cyrus() != 0)) {
	fatal("must run as the Cyrus user", EC_USAGE);
    }

    /* Ensure we're up-to-date on the index file format */
    assert(INDEX_HEADER_SIZE == (OFFSET_HEADER_CRC+4));
    assert(INDEX_RECORD_SIZE == (OFFSET_RECORD_CRC+4));

    while ((opt = getopt(argc, argv, "C:")) != EOF) {
	switch (opt) {
	case 'C': /* alt config file */
	    alt_config = optarg;
	    break;

	default:
	    usage();
	}
    }

    cyrus_init(alt_config, "dav_reconstruct", 0);

    /* Set namespace -- force standard (internal) */
    if ((r = mboxname_init_namespace(&recon_namespace, 1)) != 0) {
	syslog(LOG_ERR, "%s", error_message(r));
	fatal(error_message(r), EC_CONFIG);
    }

    mboxlist_init(0);
    mboxlist_open(NULL);

    /* open annotations.db, we'll need it for collection properties */
    annotatemore_init(0, NULL, NULL);
    annotatemore_open(NULL);

    signals_set_shutdown(&shut_down);
    signals_add_handlers(0);

    if (optind == argc) usage();

    userid = argv[optind];

    printf("Reconstructing DAV DB for %s...\n", userid);
    caldav_init();
    caldavdb = caldav_open(userid, CALDAV_CREATE | CALDAV_TRUNC);

    snprintf(buf, sizeof(buf), "user.%s.#calendars.*", userid);
    (*recon_namespace.mboxlist_findall)(&recon_namespace, buf, 1, 0, 0,
					do_reconstruct, NULL);

    caldav_close(caldavdb);
    caldav_done();

    annotatemore_close();
    annotatemore_done();

    mboxlist_close();
    mboxlist_done();

    exit(code);
}


void usage(void)
{
    fprintf(stderr,
	    "usage: dav_reconstruct [-C <alt_config>] userid\n");
    exit(EC_USAGE);
}


/* icalcomponent_foreach_recurrence() callback to find ealiest/latest time */
static void get_times(icalcomponent *comp, struct icaltime_span *span,
		      void *rock)
{
    struct icalperiodtype *period = (struct icalperiodtype *) rock;
    int is_date = icaltime_is_date(icalcomponent_get_dtstart(comp));
    icaltimezone *utc = icaltimezone_get_utc_timezone();
    struct icaltimetype start =
	icaltime_from_timet_with_zone(span->start, is_date, utc);
    struct icaltimetype end =
	icaltime_from_timet_with_zone(span->end, is_date, utc);

    if (icaltime_compare(start, period->start) < 0)
	memcpy(&period->start, &start, sizeof(struct icaltimetype));

    if (icaltime_compare(end, period->end) > 0)
	memcpy(&period->end, &end, sizeof(struct icaltimetype));
}


/*
 * mboxlist_findall() callback function to create DAV DB entries for a mailbox
 */
int do_reconstruct(char *mboxname,
		   int matchlen __attribute__((unused)),
		   int maycreate __attribute__((unused)),
		   void *rock __attribute__((unused)))
{
    int r = 0;
    unsigned recno;
    char ext_name_buf[MAX_MAILBOX_PATH+1];
    struct mailbox *mailbox = NULL;
    struct index_record record;
    icaltimezone *utc = icaltimezone_get_utc_timezone();
    struct caldav_data cdata;
    
    signals_poll();

    /* Convert internal name to external */
    (*recon_namespace.mboxname_toexternal)(&recon_namespace, mboxname,
					   "cyrus", ext_name_buf);
    printf("Inserting DAV DB entries for %s...\n", ext_name_buf);

    /* Open/lock header */
    r = mailbox_open_irl(mboxname, &mailbox);
    if (r) return r;

    if (chdir(mailbox_datapath(mailbox)) == -1) {
	r = IMAP_IOERROR;
	goto done;
    }

    printf(" Mailbox Header Info:\n");
    printf("  Path to mailbox: %s\n", mailbox_datapath(mailbox));

    printf("\n Index Header Info:\n");
    printf("  Number of Messages: %u  Mailbox Size: " UQUOTA_T_FMT " bytes\n",
	   mailbox->i.exists, mailbox->i.quota_mailbox_used);

    printf("\n Message Info:\n");

    /* Begin new transaction for each mailbox */
    memset(&cdata, 0, sizeof(struct caldav_data));
    caldav_lockread(caldavdb, &cdata);

    for (recno = 1; recno <= mailbox->i.num_records; recno++) {
	struct body *body;
	struct param *param;
	const char *msg_base = NULL, *resource = NULL;
	unsigned long msg_size = 0;
	icalcomponent *ical = NULL, *comp;
	icalcomponent_kind kind;
	icalproperty *prop;
	unsigned mykind = 0, recurring = 0, transp = 0;
	struct icalperiodtype period;

	if (mailbox_read_index_record(mailbox, recno, &record)) continue;

	if (record.system_flags & FLAG_EXPUNGED) continue;

	if (mailbox_cacherecord(mailbox, &record)) continue;

	/* Load message containing the resource and parse iCal data */
	mailbox_map_message(mailbox, record.uid, &msg_base, &msg_size);
	ical = icalparser_parse_string(msg_base + record.header_size);
	mailbox_unmap_message(mailbox, record.uid, &msg_base, &msg_size);
	if (!ical) continue;

	memset(&cdata, 0, sizeof(struct caldav_data));
	cdata.mailbox = mboxname;
	cdata.imap_uid = record.uid;

	/* Get resource URL from filename param in Content-Disposition header */
	message_read_bodystructure(&record, &body);
	for (param = body->disposition_params; param; param = param->next) {
	    if (!strcmp(param->attribute, "FILENAME")) {
		resource = param->value;
		break;
	    }
	}
	cdata.resource = resource;

	/* Get icalendar UID */
	comp = icalcomponent_get_first_real_component(ical);
	cdata.ical_uid = icalcomponent_get_uid(comp);

	/* Get component type */
	kind = icalcomponent_isa(comp);
	switch (kind) {
	case ICAL_VEVENT_COMPONENT: mykind = CAL_COMP_VEVENT; break;
	case ICAL_VTODO_COMPONENT: mykind = CAL_COMP_VTODO; break;
	case ICAL_VJOURNAL_COMPONENT: mykind = CAL_COMP_VJOURNAL; break;
	case ICAL_VFREEBUSY_COMPONENT: mykind = CAL_COMP_VFREEBUSY; break;
	default: break;
	}
	cdata.comp_type = mykind;

	/* Get organizer */
	prop = icalcomponent_get_first_property(comp, ICAL_ORGANIZER_PROPERTY);
	if (prop) {
	    /* Scheduling message - set initial stag = etag */
	    cdata.organizer = icalproperty_get_organizer(prop)+7;
	    cdata.sched_tag = message_guid_encode(&record.guid);
	}

	/* Get transparency */
	prop = icalcomponent_get_first_property(comp, ICAL_TRANSP_PROPERTY);
	if (prop) {
	    icalvalue *transp_val = icalproperty_get_value(prop);

	    switch (icalvalue_get_transp(transp_val)) {
	    case ICAL_TRANSP_TRANSPARENT:
	    case ICAL_TRANSP_TRANSPARENTNOCONFLICT:
		transp = 1;
		break;

	    default:
		transp = 0;
		break;
	    }
	}
	cdata.transp = transp;

	/* Get dtstart and dtend */
	period.start =
	    icaltime_convert_to_zone(icalcomponent_get_dtstart(comp), utc);
	period.end =
	    icaltime_convert_to_zone(icalcomponent_get_dtend(comp), utc);

	/* See if its a recurring event */
	if (icalcomponent_get_first_property(comp,ICAL_RRULE_PROPERTY) ||
	    icalcomponent_get_first_property(comp,ICAL_RDATE_PROPERTY) ||
	    icalcomponent_get_first_property(comp,ICAL_EXDATE_PROPERTY)) {
	    /* Recurring - find widest time range that includes events */
	    recurring = 1;

	    icalcomponent_foreach_recurrence(
		comp,
		icaltime_from_timet_with_zone(INT_MIN, 0, NULL),
		icaltime_from_timet_with_zone(INT_MAX, 0, NULL),
		get_times,
		&period);

	    /* Handle overridden recurrences */
	    while ((comp =
		    icalcomponent_get_next_component(ical, kind))) {
		struct icaltimetype start =
		    icaltime_convert_to_zone(icalcomponent_get_dtstart(comp), utc);
		struct icaltimetype end =
		    icaltime_convert_to_zone(icalcomponent_get_dtend(comp), utc);

		if (icaltime_compare(start, period.start) < 0)
		    memcpy(&period.start, &start, sizeof(struct icaltimetype));

		if (icaltime_compare(end, period.end) > 0)
		    memcpy(&period.end, &end, sizeof(struct icaltimetype));
	    }
	}

	cdata.dtstart = icaltime_as_ical_string(period.start);
	cdata.dtend = icaltime_as_ical_string(period.end);
	cdata.recurring = recurring;

	caldav_write(caldavdb, &cdata);

	message_free_body(body); free(body);
	icalcomponent_free(ical);
    }

    caldav_commit(caldavdb);

 done:
    mailbox_close(&mailbox);

    return r;
}

/*
 * Cleanly shut down and exit
 */
void shut_down(int code) __attribute__((noreturn));
void shut_down(int code)
{
    in_shutdown = 1;

    mboxlist_close();
    mboxlist_done();
    caldav_done();
    exit(code);
}
