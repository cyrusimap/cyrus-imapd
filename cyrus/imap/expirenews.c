/* 
 * expirenews.c -- program to expire news articles
 *                 (prune netnews db and remove message files)
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
 */

/* $Id: expirenews.c,v 1.1.2.7 2003/02/28 21:56:12 ken3 Exp $ */

#include <config.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "exitcodes.h"
#include "global.h"
#include "mailbox.h"
#include "mboxlist.h"
#include "netnews.h"
#include "xmalloc.h"

/* global state */
const int config_need_data = 0;

struct purge_rock {
    struct wildmat *wild;
    time_t expire;
    unsigned long deleted;
    unsigned long messages;
    unsigned long mailboxes;
};

void usage(void)
{
    fprintf(stderr, "expirenews [-C <altconfig>] -E <days> [<wildmat>]\n");
    exit(-1);
}

/*
 * netnews_findall() callback to purge expired entries.
 */
int prune_cb(char *msgid, char *mailbox, unsigned long uid,
	     unsigned long lines, time_t tstamp, void *rock)
{
    unsigned long *deletions = (unsigned long *) rock;

    (*deletions)++;

    netnews_delete(msgid);

    return 0;
}

/*
 * mailbox_expunge() callback to expunge expired articles.
 */
static int expunge_cb(struct mailbox *mailbox, void *rock, char *index)
{
    struct purge_rock *prock = (struct purge_rock *) rock;
    bit32 senttime = ntohl(*((bit32 *)(index+OFFSET_SENTDATE)));

    prock->messages++;

    if (senttime < prock->expire) {
	prock->deleted++;
	return 1;
    }

    return 0;
}

/*
 * mboxlist_findall() callback function to expire articles from mailboxes
 * which match the wildmat.
 */
int purge_cb(char *name, int matchlen, int maycreate __attribute__((unused)),
	     void *rock)
{
    static char lastname[MAX_MAILBOX_NAME+1] = "";
    struct purge_rock *prock = (struct purge_rock *) rock;
    struct wildmat *wild = prock->wild;
    struct mailbox mailbox;
    int r;

    /* skip personal mailboxes */
    if ((!strncasecmp(name, "INBOX", 5) && (!name[5] || name[5] == '.')) ||
	!strncmp(name, "user.", 5))
	return 0;

    /* don't repeat */
    if (matchlen == strlen(lastname) &&
	!strncmp(name, lastname, matchlen)) return 0;

    strncpy(lastname, name, matchlen);
    lastname[matchlen] = '\0';

    /* see if the mailbox matches one of our wildmats */
    while (wild->pat && wildmat(name, wild->pat) != 1) wild++;

    /* if we don't have a match, or its a negative match, skip it */
    if (!wild->pat || wild->not) return 0;

    prock->mailboxes++;

    /* Open/lock header */
    r = mailbox_open_header(name, 0, &mailbox);
    if (!r && mailbox.header_fd != -1) {
	(void) mailbox_lock_header(&mailbox);
	mailbox.header_lock_count = 1;
    }

    if (!r) r = chdir(mailbox.path);

    /* Attempt to open/lock index */
    if (!r) r = mailbox_open_index(&mailbox);
    if (!r) {
	(void) mailbox_lock_index(&mailbox);
	mailbox.index_lock_count = 1;
    }

    if (!r) mailbox_expunge(&mailbox, 1, expunge_cb, prock);
    mailbox_close(&mailbox);

    return 0;
}

int main(int argc, char *argv[])
{
    extern char *optarg;
    extern int optind;
    int opt;
    char *alt_config = NULL;
    unsigned long days = 0, count = 0, deleted = 0;
    time_t expmark;
    const char *prefix;
    char pattern[MAX_MAILBOX_NAME+1] = "", *p;
    struct wildmat *wild;
    struct purge_rock prock;

    if (geteuid() == 0) fatal("must run as the Cyrus user", EC_USAGE);

    while ((opt = getopt(argc, argv, "C:E:")) != EOF) {
	switch (opt) {
	case 'C': /* alt config file */
	    alt_config = optarg;
	    break;

	case 'E':
	    days = atol(optarg);
	    if (days < 0)
		fatal("must specify positive number of days", EC_USAGE);
	    break;
	
	default:
	    usage();
	    /* NOTREACHED */
	}
    }

    cyrus_init(alt_config, "expirenews");

    /* initialize and open mailbox database */
    mboxlist_init(0);
    mboxlist_open(NULL);

    /* initialize news database */
    if (netnews_init(NULL, 0) != 0) {
	fprintf(stderr, "expirenews: unable to init news database\n");
	syslog(LOG_ERR, "expirenews: unable to init news database\n");
	cyrus_done();
	exit(-1);
    }

    syslog(LOG_NOTICE, "pruning back %lu days", days);

    expmark = time(NULL) - (days * 60 * 60 * 24);

    if (optind == argc) /* do all newsgroups */
	p = "*";
    else
	p = argv[optind];

    wild = split_wildmats(p);

    count = netnews_findall(wild, expmark, 0, prune_cb, &deleted);

    syslog(LOG_NOTICE, "purged %lu out of %lu entries from database",
	   deleted, count);

    if ((prefix = config_getstring(IMAPOPT_NEWSPREFIX)))
	snprintf(pattern, sizeof(pattern), "%s.", prefix);
    strcat(pattern, "*");
    prock.wild = wild;
    prock.expire = expmark;
    prock.deleted = prock.messages = prock.mailboxes = 0;
    mboxlist_findall(NULL, pattern, 1, 0, 0, purge_cb, &prock);

    syslog(LOG_NOTICE, "expunged %lu out of %lu message%s from %lu mailbox%s",
	   prock.deleted, prock.messages, prock.messages == 1 ? "" : "s",
	   prock.mailboxes, prock.mailboxes == 1 ? "" : "es");

    free_wildmats(wild);

    netnews_done();
    mboxlist_close();
    mboxlist_done();
    cyrus_done();

    return 0;
}
