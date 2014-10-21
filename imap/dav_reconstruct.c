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
#include <syslog.h>
#include <time.h>

#include <libical/ical.h>

#include "annotate.h"
#include "caldav_db.h"
#include "carddav_db.h"
#include "exitcodes.h"
#include "global.h"
#include "http_dav.h"
#include "imap_err.h"
#include "mailbox.h"
#include "message.h"
#include "message_guid.h"
#include "mboxname.h"
#include "mboxlist.h"
#include "util.h"
#include "xmalloc.h"
#include "xstrlcat.h"

extern int optind;
extern char *optarg;

/* current namespace */
static struct namespace recon_namespace;

/* config.c stuff */
const int config_need_data = 0;

/* forward declarations */
static int do_reconstruct(void *rock,
			  const char *key,
			  size_t keylen,
			  const char *data,
			  size_t datalen);
void usage(void);
void shut_down(int code);

static int code = 0;
static struct caldav_db *caldavdb = NULL;


int main(int argc, char **argv)
{
    int opt, r;
    char *alt_config = NULL, *userid;
    struct buf fnamebuf = BUF_INITIALIZER;

    if ((geteuid()) == 0 && (become_cyrus(/*is_master*/0) != 0)) {
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

    cyrus_init(alt_config, "dav_reconstruct", 0, 0);

    /* Set namespace -- force standard (internal) */
    if ((r = mboxname_init_namespace(&recon_namespace, 1)) != 0) {
	syslog(LOG_ERR, "%s", error_message(r));
	fatal(error_message(r), EC_CONFIG);
    }

    mboxlist_init(0);
    mboxlist_open(NULL);

    signals_set_shutdown(&shut_down);
    signals_add_handlers(0);

    if (optind == argc) usage();

    userid = argv[optind];

    printf("Reconstructing DAV DB for %s...\n", userid);
    caldav_init();
    carddav_init();

    /* remove existing database entirely */
    /* XXX - build a new file and rename into place? */
    dav_getpath_byuserid(&fnamebuf, userid);
    if (buf_len(&fnamebuf))
	unlink(buf_cstring(&fnamebuf));

    mboxlist_allusermbox(userid, do_reconstruct, NULL, 0);

    caldav_close(caldavdb);
    caldav_done();

    mboxlist_close();
    mboxlist_done();

    buf_free(&fnamebuf);

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
static int do_reconstruct(void *rock __attribute__((unused)),
			  const char *key,
			  size_t keylen,
			  const char *data __attribute__((unused)),
			  size_t datalen __attribute__((unused)))
{
    int r = 0;
    char ext_name_buf[MAX_MAILBOX_PATH+1];
    mbentry_t *mbentry = NULL;
    struct mailbox *mailbox = NULL;
    char *name = xstrndup(key, keylen);

    signals_poll();

    r = mboxlist_lookup(name, &mbentry, NULL);
    if (r) goto done;

    /* Convert internal name to external */
    (*recon_namespace.mboxname_toexternal)(&recon_namespace, mbentry->name,
					   "cyrus", ext_name_buf);

    if (mbentry->mbtype & (MBTYPE_CALENDAR|MBTYPE_ADDRESSBOOK)) {
	printf("Inserting DAV DB entries for %s...\n", ext_name_buf);

	/* Open/lock header */
	r = mailbox_open_irl(mbentry->name, &mailbox);
	if (!r) r = mailbox_add_dav(mailbox);
	mailbox_close(&mailbox);
    }

done:
    mboxlist_entry_free(&mbentry);
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
