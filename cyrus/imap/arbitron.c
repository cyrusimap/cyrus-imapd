/* arbitron.c -- program to report readership statistics
 *
 * Copyright (c) 1998, 2000 Carnegie Mellon University.  All rights reserved.
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

/* $Id: arbitron.c,v 1.24 2002/11/06 20:43:20 rjs3 Exp $ */

#include <config.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <syslog.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <com_err.h>
#include <time.h>

#include "assert.h"
#include "imapconf.h"
#include "exitcodes.h"
#include "imap_err.h"
#include "mailbox.h"
#include "xmalloc.h"
#include "mboxlist.h"
#include "convert_code.h"
#include "seen.h"

extern int optind;
extern char *optarg;

int code = 0;

time_t report_time, prune_time = 0;

/* current namespace */
static struct namespace arb_namespace;

/* forward declarations */
void usage(void);
int do_mailbox();
int arbitron(char *name);

struct arbitronargs {
    char *name;
    unsigned read_count;
};

int main(int argc,char **argv)
{
    int opt, r;
    int report_days = 30;
    int prune_months = 0;
    char pattern[MAX_MAILBOX_NAME+1];
    char *alt_config = NULL;

    strcpy(pattern, "*");

    if (geteuid() == 0) fatal("must run as the Cyrus user", EC_USAGE);

    while ((opt = getopt(argc, argv, "C:d:p:")) != EOF) {
	switch (opt) {
	case 'C': /* alt config file */
	    alt_config = optarg;
	    break;

	case 'd':
	    report_days = atoi(optarg);
	    if (report_days <= 0) usage();
	    break;

	case 'p':
	    prune_months = atoi(optarg);
	    if (prune_months <= 0) usage();
	    break;

	default:
	    usage();
	}
    }

    config_init(alt_config, "arbitron");

    /* Set namespace -- force standard (internal) */
    if ((r = mboxname_init_namespace(&arb_namespace, 1)) != 0) {
	syslog(LOG_ERR, error_message(r));
	fatal(error_message(r), EC_CONFIG);
    }

    if (optind != argc) strncpy(pattern, argv[optind], MAX_MAILBOX_NAME);

    report_time = time(0) - (report_days*60*60*24);
    if (prune_months) {
	prune_time = time(0) - (prune_months*60*60*24*31);
    }

    /* Translate any separators in mailboxname */
    mboxname_hiersep_tointernal(&arb_namespace, pattern);

    (*arb_namespace.mboxlist_findall)(&arb_namespace, pattern, 1, 0, 0,
				      do_mailbox, NULL);

    exit(code);

    return -1; /* never reaches */
}

void usage(void)
{
    fprintf(stderr,
	    "usage: arbitron [-C <alt_config] [-d days]"
	    " [-p months] [mboxpattern]\n");
    exit(EC_USAGE);
}    

int
do_mailbox(name, matchlen, maycreate)
char *name;
int matchlen;
int maycreate;
{
    int r;

    r = arbitron(name);
    if (r) {
	com_err(name, r, (r == IMAP_IOERROR) ? error_message(errno) : NULL);
	code = convert_code(r);
    }

    return 0;
}

int
reportproc(rock, line)
void *rock;
const char *line;
{
    struct arbitronargs *arbitronargs = (struct arbitronargs *)rock;
    const char *tab = strchr(line, '\t');
    int useridlen = tab - line;

    /* Don't report users reading their own private mailboxes */
    if (!strncasecmp(arbitronargs->name, "user.", 5) &&
	!memchr(line, '.', useridlen) &&
	!strncasecmp(arbitronargs->name+5, line, useridlen) &&
	(arbitronargs->name[5+useridlen] == '.' ||
	 arbitronargs->name[5+useridlen] == '\0')) {
	return 0;
    }

    arbitronargs->read_count++;
    return 0;
}

int arbitron(char *name)
{
    int r;
    struct mailbox mailbox;
    struct arbitronargs arbitronargs;
    char buf[MAX_MAILBOX_PATH];

    /* Open/lock header */
    r = mailbox_open_header(name, 0, &mailbox);
    if (r) {
	return r;
    }

    r = mailbox_open_index(&mailbox);
    if (r) {
	mailbox_close(&mailbox);
	return r;
    }

    arbitronargs.name = name;
    arbitronargs.read_count = 0;

    r = seen_reconstruct(&mailbox, report_time, prune_time,
			 reportproc, (void *)&arbitronargs);
    mailbox_close(&mailbox);

    if (!r) {
	if (arbitronargs.read_count ||
	    strncasecmp(name, "user.", 5) != 0) {
	    /* Convert internal name to external */
	    (*arb_namespace.mboxname_toexternal)(&arb_namespace, name,
						 "cyrus", buf);
	    printf("%u %s\n", arbitronargs.read_count, buf);
	}
    }

    return r;
}

void fatal(const char* s, int code)
{
    fprintf(stderr, "arbitron: %s\n", s);
    exit(code);
}

