/* cyr_expire.c -- Program to expire deliver.db entries and messages
 *
 * Copyright (c) 1998-2003 Carnegie Mellon University.  All rights reserved.
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
 *    prior written permission. For permission or any other legal
 *    details, please contact  
 *      Office of Technology Transfer
 *      Carnegie Mellon University
 *      5000 Forbes Avenue
 *      Pittsburgh, PA  15213-3890
 *      (412) 268-4387, fax: (412) 268-7395
 *      tech-transfer@andrew.cmu.edu
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
 * $Id: cyr_expire.c,v 1.2.2.9 2004/06/15 15:59:45 ken3 Exp $
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
#include "libcyr_cfg.h"
#include "mboxlist.h"
#include "util.h"
#include "xmalloc.h"

/* global state */
const int config_need_data = 0;

void usage(void)
{
    fprintf(stderr,
	    "cyr_expire [-C <altconfig>] -E <days> [-v]\n");
    exit(-1);
}

struct expire_rock {
    struct hash_table *table;
    enum enum_value expunge_mode;
    time_t expire_mark;
    time_t expunge_mark;
    unsigned long mailboxes;
    unsigned long messages;
    unsigned long deleted;
    int verbose;
};

/*
 * mailbox_expunge() callback to expunge expired articles.
 */
static int expire_cb(struct mailbox *mailbox __attribute__((unused)),
		      void *rock, char *index, int expunge_flags)
{
    struct expire_rock *erock = (struct expire_rock *) rock;
    bit32 tstamp;

    erock->messages++;

    /* if we're cleaning up expunge, delete by expunge time */
    if (expunge_flags & EXPUNGE_CLEANUP) {
	tstamp = ntohl(*((bit32 *)(index+OFFSET_LAST_UPDATED)));
	if (tstamp < erock->expunge_mark) {
	    erock->deleted++;
	    return 1;
	}
    } else {
	/* otherwise, we're expiring messages by sent date */
	tstamp = ntohl(*((bit32 *)(index+OFFSET_SENTDATE)));
	if (tstamp < erock->expire_mark) {
	    erock->deleted++;
	    return 1;
	}
    }

    return 0;
}


/*
 * mboxlist_findall() callback function to:
 * - expire messages from mailboxes,
 * - build a hash table of mailboxes in which we expired messages,
 * - and perform a cleanup of expunged messages
 */
int expire(char *name, int matchlen, int maycreate __attribute__((unused)),
	   void *rock)
{
    struct expire_rock *erock = (struct expire_rock *) rock;
    char buf[MAX_MAILBOX_NAME+1] = "", *p;
    struct annotation_data attrib;
    int r, domainlen = 0;

    if (config_virtdomains && (p = strchr(name, '!')))
	domainlen = p - name + 1;

    strncpy(buf, name, matchlen);
    buf[matchlen] = '\0';

    /* see if we need to expire messages.
     * since mailboxes inherit /vendor/cmu/cyrus-imapd/expire,
     * we need to iterate all the way up to "" (server entry)
     */
    while (1) {
	r = annotatemore_lookup(buf, "/vendor/cmu/cyrus-imapd/expire", "",
				&attrib);

	if (r ||				/* error */
	    attrib.value ||			/* found an entry */
	    !buf[0] ||				/* done recursing */
	    !strcmp(buf+domainlen, "user")) {	/* server entry doesn't apply
						   to personal mailboxes */
	    break;
	}

	p = strrchr(buf, '.');			/* find parent mailbox */

	if (p && (p - buf > domainlen))		/* don't split subdomain */
	    *p = '\0';
	else if (!buf[domainlen])		/* server entry */
	    buf[0] = '\0';
	else					/* domain entry */
	    buf[domainlen] = '\0';
    }

    if (!r && (attrib.value ||
	       erock->expunge_mode != IMAP_ENUM_EXPUNGE_MODE_IMMEDIATE)) {
	struct mailbox mailbox;
	int doclose = 0;
	int expunge_flags = 0;

	/* Open/lock header */
	r = mailbox_open_header(name, 0, &mailbox);
	if (!r && mailbox.header_fd != -1) {
	    doclose = 1;
	    (void) mailbox_lock_header(&mailbox);
	    mailbox.header_lock_count = 1;
	}

	/* Attempt to open/lock index */
	if (!r) r = mailbox_open_index(&mailbox);
	if (!r) {
	    (void) mailbox_lock_index(&mailbox);
	    mailbox.index_lock_count = 1;
	}

	if (r) {
	    /* mailbox corrupt/nonexistent -- skip it */
	    syslog(LOG_WARNING, "unable to open/lock mailbox %s", name);
	    if (doclose) mailbox_close(&mailbox);
	    return 0;
	}

	erock->mailboxes++;
	erock->expire_mark = 0;

	if (attrib.value) {
	    /* add mailbox to table */
	    unsigned long expire_days = strtoul(attrib.value, NULL, 10);
	    time_t *expire_mark = (time_t *) xmalloc(sizeof(time_t));

	    *expire_mark = expire_days ?
		time(0) - (expire_days * 60 * 60 * 24) : 0 /* never */ ;
	    hash_insert(name, (void *) expire_mark, erock->table);

	    if (erock->verbose) {
		fprintf(stderr,
			"expiring messages in %s older than %ld days\n",
			name, expire_days);
	    }

	    erock->expire_mark = *expire_mark;

	    expunge_flags |= EXPUNGE_FORCE;
	}

	if (erock->expunge_mode != IMAP_ENUM_EXPUNGE_MODE_IMMEDIATE) {
	    /* cleanup mailbox of expunged messages */
	    expunge_flags |= EXPUNGE_CLEANUP;
	}

	r = mailbox_expunge(&mailbox, expire_cb, erock, expunge_flags);
	mailbox_close(&mailbox);
    }

    return r;
}

int main(int argc, char *argv[])
{
    extern char *optarg;
    int opt, r = 0, expire_days = 0, expunge_days = 0;
    char *alt_config = NULL;
    char buf[100];
    struct hash_table expire_table;
    struct expire_rock erock;

    if (geteuid() == 0) fatal("must run as the Cyrus user", EC_USAGE);

    /* zero the expire_rock */
    memset(&erock, 0, sizeof(erock));

    while ((opt = getopt(argc, argv, "C:E:X:v")) != EOF) {
	switch (opt) {
	case 'C': /* alt config file */
	    alt_config = optarg;
	    break;

	case 'E':
	    if (expire_days) usage();
	    expire_days = atoi(optarg);
	    break;

	case 'X':
	    if (expunge_days) usage();
	    expunge_days = atoi(optarg);
	    break;

	case 'v':
	    erock.verbose++;
	    break;
	
	default:
	    usage();
	    break;
	}
    }

    if (!expire_days) usage();

    cyrus_init(alt_config, "cyr_expire", 0);

    annotatemore_init(0, NULL, NULL);
    annotatemore_open(NULL);

    mboxlist_init(0);
    mboxlist_open(NULL);

    /* open the quota db, we'll need it for expunge */
    quotadb_init(0);
    quotadb_open(NULL);

    if (duplicate_init(NULL, 0) != 0) {
	fprintf(stderr, 
		"cyr_expire: unable to init duplicate delivery database\n");
	exit(1);
    }

    /* xxx better way to determine a size for this table? */
    construct_hash_table(&expire_table, 10000, 1);

    /* expire messages from mailboxes,
     * build a hash table of mailboxes in which we expired messages,
     * and perform a cleanup of expunged messages
     */
    erock.table = &expire_table;
    erock.expunge_mode = config_getenum(IMAPOPT_EXPUNGE_MODE);
    erock.expunge_mark = time(0) - (expunge_days * 60 * 60 * 24);

    if (erock.verbose && 
	erock.expunge_mode != IMAP_ENUM_EXPUNGE_MODE_IMMEDIATE) {
	fprintf(stderr,
		"expunging deleted messages in mailboxes older than %ld days\n",
		expunge_days);
    }

    strlcpy(buf, "*", sizeof(buf));
    mboxlist_findall(NULL, buf, 1, 0, 0, &expire, &erock);

    syslog(LOG_NOTICE, "expunged %lu out of %lu messages from %lu mailboxes",
	   erock.deleted, erock.messages, erock.mailboxes);
    if (erock.verbose) {
	fprintf(stderr, "\nexpunged %lu out of %lu messages from %lu mailboxes\n",
		erock.deleted, erock.messages, erock.mailboxes);
    }

    /* purge deliver.db entries of expired messages */
    r = duplicate_prune(expire_days, &expire_table);

    free_hash_table(&expire_table, free);

    quotadb_close();
    quotadb_done();
    mboxlist_close();
    mboxlist_done();
    annotatemore_close();
    annotatemore_done();
    duplicate_done();
    cyrus_done();

    exit(r);
}
