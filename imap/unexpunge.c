/* unexpunge.c -- Program to unexpunge messages
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
 * $Id: unexpunge.c,v 1.15 2010/01/06 17:01:42 murch Exp $
 */

#include <config.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <syslog.h>
#include <errno.h>
#include <signal.h>

#include "annotate.h"
#include "cyrusdb.h"
#include "duplicate.h"
#include "exitcodes.h"
#include "global.h"
#include "hash.h"
#include "imap_err.h"
#include "index.h"
#include "libcyr_cfg.h"
#include "cyr_lock.h"
#include "map.h"
#include "mailbox.h"
#include "mboxlist.h"
#include "util.h"
#include "xmalloc.h"
#include "xstrlcpy.h"
#include "xstrlcat.h"
#include "sync_log.h"

/* global state */
const int config_need_data = 0;

/* current namespace */
static struct namespace unex_namespace;

int verbose = 0;
int unsetdeleted = 0;

void usage(void)
{
    fprintf(stderr,
	    "unexpunge [-C <altconfig>] -l <mailbox>\n"
            "unexpunge [-C <altconfig>] -t time-interval [ -d ] [ -v ] mailbox\n"
	    "unexpunge [-C <altconfig>] -a [-d] [-v] <mailbox>\n"
	    "unexpunge [-C <altconfig>] -u [-d] [-v] <mailbox> <uid>...\n");
    exit(-1);
}

int compare_uid(const void *a, const void *b)
{
    return *((unsigned long *) a) - *((unsigned long *) b);
}

enum {
    MODE_UNKNOWN = -1,
    MODE_LIST,
    MODE_ALL,
    MODE_TIME,
    MODE_UID
};

void list_expunged(const char *mboxname)
{
    struct mailbox *mailbox = NULL;
    struct index_record *records = NULL;
    struct index_record *record;
    uint32_t recno;
    int alloc = 0;
    int num = 0;
    int i;
    int r;

    r = mailbox_open_irl(mboxname, &mailbox);
    if (r) {
	printf("Failed to open mailbox %s: %s",
	       mboxname, error_message(r));
	return;
    }

    /* first pass - read the records.  Don't print until we release the
     * lock */
    for (recno = 1; recno <= mailbox->i.num_records; recno++) {
	/* pre-allocate more space */
	if (alloc <= num) {
	    alloc += 64;
	    records = xrealloc(records, sizeof(struct index_record) * alloc);
	}
	record = &records[num];

	if (mailbox_read_index_record(mailbox, recno, record))
	    continue;

	/* still active */
	if (!(record->system_flags & FLAG_EXPUNGED))
	    continue;
	/* no file, unrescuable */
	if (record->system_flags & FLAG_UNLINKED)
	    continue;

	num++;
    }

    mailbox_unlock_index(mailbox, NULL);

    for (i = 0; i < num; i++) {
	record = &records[i];
	printf("UID: %u\n", record->uid);
	printf("\tSize: %u\n", record->size);
	printf("\tSent: %s", ctime(&record->sentdate));
	printf("\tRecv: %s", ctime(&record->internaldate));
	printf("\tExpg: %s", ctime(&record->last_updated));

	if (mailbox_cacherecord(mailbox, record)) {
	    printf("\tERROR: cache record missing or corrupt, "
		   "not printing cache details\n\n");
	    continue;
	}

	printf("\tFrom: %.*s\n", cacheitem_size(record, CACHE_FROM),
		cacheitem_base(record, CACHE_FROM));
	printf("\tTo  : %.*s\n", cacheitem_size(record, CACHE_TO),
		cacheitem_base(record, CACHE_TO));
	printf("\tCc  : %.*s\n", cacheitem_size(record, CACHE_CC),
		cacheitem_base(record, CACHE_CC));
	printf("\tBcc : %.*s\n", cacheitem_size(record, CACHE_BCC),
		cacheitem_base(record, CACHE_BCC));
	printf("\tSubj: %.*s\n\n", cacheitem_size(record, CACHE_SUBJECT),
		cacheitem_base(record, CACHE_SUBJECT));
    }

    free(records);
    mailbox_close(&mailbox);
}

int restore_expunged(struct mailbox *mailbox, int mode, unsigned long *uids,
		     unsigned nuids, time_t time_since, unsigned *numrestored)
{
    uint32_t recno;
    uint32_t olduid;
    struct index_record record;
    unsigned uidnum = 0;
    char oldfname[MAX_MAILBOX_PATH];
    const char *fname;
    int r = 0;

    *numrestored = 0;

    for (recno = 1; recno <= mailbox->i.num_records; recno++) {
	r = mailbox_read_index_record(mailbox, recno, &record);
	if (r) return r;

	/* still active */
	if (!(record.system_flags & FLAG_EXPUNGED))
	    continue;
	/* no file, unrescuable */
	if (record.system_flags & FLAG_UNLINKED)
	    continue;

	if (mode == MODE_UID) {
	    while (uidnum < nuids && record.uid > uids[uidnum])
		uidnum++;
	    if (uidnum >= nuids)
		continue;
	    if (record.uid != uids[uidnum])
		continue;
	    /* otherwise we want this one */
	}
	else if (mode == MODE_TIME) {
	    if (record.last_updated < time_since)
		continue;
	    /* otherwise we want this one */
	}

	/* mark the old one unlinked so we don't see it again */
	olduid = record.uid;
	record.system_flags |= FLAG_UNLINKED;
	r = mailbox_rewrite_index_record(mailbox, &record);
	if (r) return r;

	/* duplicate the old filename */
	fname = mailbox_message_fname(mailbox, olduid);
	strncpy(oldfname, fname, MAX_MAILBOX_PATH);

	/* bump the UID, strip the flags */
	record.uid = mailbox->i.last_uid + 1;
	record.system_flags &= ~(FLAG_UNLINKED|FLAG_EXPUNGED);
	if (unsetdeleted)
	    record.system_flags &= ~FLAG_DELETED;

	/* copy the message file */
	fname = mailbox_message_fname(mailbox, record.uid);
	r = mailbox_copyfile(oldfname, fname, 0);
	if (r) return r;

	/* and append the new record */
	mailbox_append_index_record(mailbox, &record);

	if (verbose)
	    printf("Unexpunged %s: %u => %u\n",
		   mailbox->name, olduid, record.uid);

	(*numrestored)++;
    }

    return 0;
}

int main(int argc, char *argv[])
{
    extern char *optarg;
    int opt, r = 0;
    char *alt_config = NULL;
    char buf[MAX_MAILBOX_PATH+1];
    struct mailbox *mailbox = NULL;
    int mode = MODE_UNKNOWN;
    unsigned numrestored = 0;
    time_t time_since = time(NULL);
    int len, secs = 0;
    unsigned long *uids = NULL;
    unsigned nuids = 0;

    if ((geteuid()) == 0 && (become_cyrus() != 0)) {
	fatal("must run as the Cyrus user", EC_USAGE);
    }

    while ((opt = getopt(argc, argv, "C:laudt:v")) != EOF) {
	switch (opt) {
	case 'C': /* alt config file */
	    alt_config = optarg;
	    break;

	case 'l':
	    if (mode != MODE_UNKNOWN) usage();
	    mode = MODE_LIST;
	    break;

	case 'a':
	    if (mode != MODE_UNKNOWN) usage();
	    mode = MODE_ALL;
	    break;

	case 't':
	    if (mode != MODE_UNKNOWN) usage();

	    mode = MODE_TIME;
            secs = atoi(optarg);
            len  = strlen(optarg);

            if ((secs > 0) && (len > 1)) {
                switch (optarg[len-1]) {
                case 'm':
                    secs *= 60;
                    break;
                case 'h':
                    secs *= (60*60);
                    break;
                case 'd':
                    secs *= (24*60*60);
                    break;
                case 'w':
                    secs *= (7*24*60*60);
                    break;
                }
            }
            time_since = time(NULL) - secs;
	    break;

	case 'u':
	    if (mode != MODE_UNKNOWN) usage();
	    mode = MODE_UID;
	    break;

	case 'd':
	    unsetdeleted = 1;
	    break;

	case 'v':
	    verbose = 1;
	    break;

	default:
	    usage();
	    break;
	}
    }

    /* sanity check */
    if (mode == MODE_UNKNOWN ||
	(optind + (mode == MODE_UID ? 1 : 0)) >= argc) usage();

    cyrus_init(alt_config, "unexpunge", 0);

    mboxlist_init(0);
    mboxlist_open(NULL);

    quotadb_init(0);
    quotadb_open(NULL);

    sync_log_init();

    /* Set namespace -- force standard (internal) */
    if ((r = mboxname_init_namespace(&unex_namespace, 1)) != 0) {
	syslog(LOG_ERR, "%s", error_message(r));
	fatal(error_message(r), EC_CONFIG);
    }

    /* Translate mailboxname */
    (*unex_namespace.mboxname_tointernal)(&unex_namespace, argv[optind],
					  NULL, buf);

    if (mode == MODE_LIST) {
	list_expunged(buf);
	goto done;
    }

    /* Open/lock header */
    r = mailbox_open_iwl(buf, &mailbox);
    if (r) {
	printf("Failed to open mailbox '%s'\n", buf);
	goto done;
    }

    if (mode == MODE_UID) {
	unsigned i;

	nuids = argc - ++optind;
	uids = (unsigned long *) xmalloc(nuids * sizeof(unsigned long));

	for (i = 0; i < nuids; i++)
	    uids[i] = strtoul(argv[optind+i], NULL, 10);

	/* Sort the UIDs so we can binary search */
	qsort(uids, nuids, sizeof(unsigned long), compare_uid);
    }

    printf("restoring %sexpunged messages in mailbox '%s'\n",
	    mode == MODE_ALL ? "all " : "", mailbox->name);

    r = restore_expunged(mailbox, mode, uids, nuids, time_since, &numrestored);

    if (!r) {
	printf("restored %u expunged messages\n",
		numrestored);
	syslog(LOG_NOTICE,
	       "restored %u expunged messages in mailbox '%s'",
	       numrestored, mailbox->name);
    }

    mailbox_close(&mailbox);

done:
    sync_log_done();

    quotadb_close();
    quotadb_done();

    mboxlist_close();
    mboxlist_done();

    cyrus_done();

    exit(r);
}
