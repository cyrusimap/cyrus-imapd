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

/* $Id: expirenews.c,v 1.1.2.6 2003/02/13 20:32:55 rjs3 Exp $ */

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
#include "netnews.h"
#include "xmalloc.h"

/* global state */
const int config_need_data = 0;

void usage(void)
{
    fprintf(stderr, "expirenews [-C <altconfig>] -E <days> [<wildmat>]\n");
    exit(-1);
}

int prune_cb(char *msgid, char *mailbox, unsigned long uid,
	     unsigned long lines, time_t tstamp, void *rock)
{
    int *deletions = (int *) rock;

    (*deletions)++;

    netnews_delete(msgid);

    return 0;
}

int main(int argc, char *argv[])
{
    extern char *optarg;
    extern int optind;
    int opt;
    char *alt_config = NULL;
    int days = 0, count = 0, deleted = 0;
    time_t expmark;
    char *p;
    struct wildmat *wild;

    if (geteuid() == 0) fatal("must run as the Cyrus user", EC_USAGE);

    while ((opt = getopt(argc, argv, "C:E:")) != EOF) {
	switch (opt) {
	case 'C': /* alt config file */
	    alt_config = optarg;
	    break;

	case 'E':
	    days = atoi(optarg);
	    if (days < 0)
		fatal("must specify positive number of days", EC_USAGE);
	    break;
	
	default:
	    usage();
	    /* NOTREACHED */
	}
    }

    cyrus_init(alt_config, "expirenews");

    /* initialize news database */
    if (netnews_init(NULL, 0) != 0) {
	fprintf(stderr, "expirenews: unable to init news database\n");
	syslog(LOG_ERR, "expirenews: unable to init news database\n");
	cyrus_done();
	exit(-1);
    }

    syslog(LOG_NOTICE, "expirenews: pruning back %d days", days);

    expmark = time(NULL) - (days * 60 * 60 * 24);

    if (optind == argc) /* do all newsgroups */
	p = "*";
    else
	p = argv[optind];

    wild = split_wildmats(p);

    count = netnews_findall(wild, expmark, 0, prune_cb, &deleted);

    syslog(LOG_NOTICE, "expirenews: purged %d out of %d entries",
	   deleted, count);

    free_wildmats(wild);

    netnews_done();
    cyrus_done();

    return 0;
}
