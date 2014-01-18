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
#include <time.h>

#include <libical/ical.h>

#include "annotate.h"
#include "caldav_db.h"
#include "global.h"
#include "http_dav.h"
#include "imap_err.h"
#include "mailbox.h"
#include "message.h"
#include "message_guid.h"
#include "mboxname.h"
#include "mboxlist.h"
#include "xmalloc.h"
#include "xstrlcat.h"

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
    struct mailbox mailbox;

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

    /* Generate mailboxname of calendar-home-set */
    caldav_mboxname(NULL, userid, buf);

    /* Open DAV DB corresponding to userid */
    mailbox.name = buf;
    caldavdb = caldav_open(&mailbox, CALDAV_CREATE | CALDAV_TRUNC);

    strlcat(buf, ".*", sizeof(buf));
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
    caldav_begin(caldavdb);

    for (recno = 1; recno <= mailbox->i.num_records; recno++) {
	struct body *body;
	struct param *param;
	const char *msg_base = NULL;
	unsigned long msg_size = 0;
	icalcomponent *ical = NULL;

	if (mailbox_read_index_record(mailbox, recno, &record)) continue;

	if (record.system_flags & FLAG_EXPUNGED) continue;

	if (mailbox_cacherecord(mailbox, &record)) continue;

	/* Load message containing the resource and parse iCal data */
	mailbox_map_message(mailbox, record.uid, &msg_base, &msg_size);
	ical = icalparser_parse_string(msg_base + record.header_size);
	mailbox_unmap_message(mailbox, record.uid, &msg_base, &msg_size);
	if (!ical) continue;

	memset(&cdata, 0, sizeof(struct caldav_data));
	cdata.dav.creationdate = time(NULL);
	cdata.dav.mailbox = mboxname;
	cdata.dav.imap_uid = record.uid;

	/* Get resource URL from filename param in Content-Disposition header */
	message_read_bodystructure(&record, &body);
	for (param = body->disposition_params; param; param = param->next) {
	    if (!strcmp(param->attribute, "FILENAME")) {
		cdata.dav.resource = param->value;
	    }
	    else if (!strcmp(param->attribute, "SCHEDULE-TAG")) {
		cdata.sched_tag = param->value;
	    }
	}

	caldav_make_entry(ical, &cdata);

	caldav_write(caldavdb, &cdata, 0);

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
