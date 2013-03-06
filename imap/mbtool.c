/* mbtool.c - tool to fiddle mailboxes
 *
 * Copyright (c) 1994-2008 Carnegie Mellon University.  All rights reserved.
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
 * $Id: mbexamine.c,v 1.25 2010/01/06 17:01:36 murch Exp $
 */

#include <config.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <ctype.h>
#include <syslog.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <stdlib.h>

#if HAVE_DIRENT_H
# include <dirent.h>
# define NAMLEN(dirent) strlen((dirent)->d_name)
#else
# define dirent direct
# define NAMLEN(dirent) (dirent)->d_namlen
# if HAVE_SYS_NDIR_H
#  include <sys/ndir.h>
# endif
# if HAVE_SYS_DIR_H
#  include <sys/dir.h>
# endif
# if HAVE_NDIR_H
#  include <ndir.h>
# endif
#endif

#include "acl.h"
#include "assert.h"
#include "exitcodes.h"
#include "index.h"
#include "global.h"
#include "imap/imap_err.h"
#include "imparse.h"
#include "mailbox.h"
#include "message.h"
#include "message_guid.h"
#include "mboxname.h"
#include "mboxlist.h"
#include "seen.h"
#include "times.h"
#include "retry.h"
#include "util.h"
#include "xmalloc.h"
#include "xstrlcpy.h"
#include "xstrlcat.h"

extern int optind;
extern char *optarg;

/* current namespace */
static struct namespace recon_namespace;

/* forward declarations */
static int do_cmd(char *name, int matchlen, int maycreate, void *rock);

static void usage(void);
void shut_down(int code);

enum {
    CMD_TIME = 1,
};

int main(int argc, char **argv)
{
    int opt, i, r;
    int cmd = 0;
    char buf[MAX_MAILBOX_PATH+1];
    char *alt_config = NULL;

    if ((geteuid()) == 0 && (become_cyrus(/*is_master*/0) != 0)) {
	fatal("must run as the Cyrus user", EC_USAGE);
    }

    /* Ensure we're up-to-date on the index file format */
    assert(INDEX_HEADER_SIZE == (OFFSET_HEADER_CRC+4));
    assert(INDEX_RECORD_SIZE == (OFFSET_RECORD_CRC+4));

    while ((opt = getopt(argc, argv, "C:t")) != EOF) {
	switch (opt) {
	case 'C': /* alt config file */
	    alt_config = optarg;
	    break;

	case 't':
	    cmd = CMD_TIME;
	    break;

	default:
	    usage();
	}
    }

    cyrus_init(alt_config, "mbtool", 0, 0);

    /* Set namespace -- force standard (internal) */
    if ((r = mboxname_init_namespace(&recon_namespace, 1)) != 0) {
	syslog(LOG_ERR, "%s", error_message(r));
	fatal(error_message(r), EC_CONFIG);
    }

    mboxlist_init(0);
    mboxlist_open(NULL);

    signals_set_shutdown(&shut_down);
    signals_add_handlers(0);

    if (optind == argc) {
	usage();
    }

    for (i = optind; i < argc; i++) {
	/* Handle virtdomains and separators in mailboxname */
	(*recon_namespace.mboxname_tointernal)(&recon_namespace, argv[i],
					       NULL, buf);
	(*recon_namespace.mboxlist_findall)(&recon_namespace, buf, 1, 0, 0,
					    do_cmd, &cmd);
    }

    mboxlist_close();
    mboxlist_done();

    exit(0);
}

static void usage(void)
{
    fprintf(stderr,
	    "usage: mbtool [-C <alt_config>] mailbox...\n");
    exit(EC_USAGE);
}

/*
 * mboxlist_findall() callback function to examine a mailbox
 */
static int do_timestamp(char *name)
{
    unsigned recno;
    int r = 0;
    char ext_name_buf[MAX_MAILBOX_PATH+1];
    struct mailbox *mailbox = NULL;
    struct index_record record;
    char olddate[RFC822_DATETIME_MAX+1];
    char newdate[RFC822_DATETIME_MAX+1];

    signals_poll();

    /* Convert internal name to external */
    (*recon_namespace.mboxname_toexternal)(&recon_namespace, name,
					   "cyrus", ext_name_buf);
    printf("Working on %s...\n", ext_name_buf);

    /* Open/lock header */
    r = mailbox_open_iwl(name, &mailbox);
    if (r) return r;

    for (recno = 1; recno <= mailbox->i.num_records; recno++) {
	r = mailbox_read_index_record(mailbox, recno, &record);
	if (r) goto done;

	if (record.system_flags & FLAG_EXPUNGED)
	    continue;

	/* 1 day is close enough */
	if (abs(record.internaldate - record.gmtime) < 86400)
	    continue;

	time_to_rfc822(record.internaldate, olddate, sizeof(olddate));
	time_to_rfc822(record.gmtime, newdate, sizeof(newdate));
	printf("  %u: %s => %s\n", record.uid, olddate, newdate);

	/* switch internaldate */
	record.internaldate = record.gmtime;

	r = mailbox_rewrite_index_record(mailbox, &record);
	if (r) goto done;
    }

 done:
    mailbox_close(&mailbox);

    return r;
}

int do_cmd(char *name,
	   int matchlen __attribute__((unused)),
	   int maycreate __attribute__((unused)),
	   void *rock)
{
    int *valp = (int *)rock;

    if (*valp == CMD_TIME)
	return do_timestamp(name);

    return 0;
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
    exit(code);
}
