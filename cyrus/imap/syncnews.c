/* syncnews.c -- program to synchronize active file with mailbox list
 *
 * 
 * Copyright (c) 1998-2000 Carnegie Mellon University.  All rights reserved.
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
 */

/*
 * $Id: syncnews.c,v 1.19.14.3 2003/02/06 22:40:57 rjs3 Exp $
 */
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

#include "assert.h"
#include "global.h"
#include "xmalloc.h"
#include "exitcodes.h"
#include "imap_err.h"
#include "mailbox.h"
#include "mboxlist.h"
#include "convert_code.h"

extern int optind;
extern char *optarg;

int code = 0;

void do_syncnews(void);

char **group = 0;
int *group_seen;
int group_num = 0;
int group_alloc = 0;

/* Forward declarations */
void readactive(char *active);

void usage(void)
{
    fprintf(stderr, "usage: syncnews [-C <alt_config>] active\n");
    exit(EC_USAGE);
}    

int main(int argc, char **argv)
{
    int opt;
    char *alt_config = NULL;

    if (geteuid() == 0) fatal("must run as the Cyrus user", EC_USAGE);

    while ((opt = getopt(argc, argv, "C:")) != EOF) {
	switch (opt) {
	case 'C': /* alt config file */
	    alt_config = optarg;
	    break;
	default:
	    usage();
	}
    }

    cyrus_init(alt_config, "syncnews");

    if (!argv[optind] || argv[optind+1]) usage();

    readactive(argv[optind]);
    do_syncnews();

    cyrus_done();

    return code;
}

#define GROUPGROW 300

/*
 * comparison function for qsort() of the group list
 */
int compare_group(char **a,char **b)
{
    return strcmp(*a, *b);
}

/*
 * Read a news active file, building the group list
 */
void readactive(char *active)
{
    FILE *active_file;
    char buf[1024];
    char *p;
    const char *newsprefix;
    int newsprefixlen = 0;
    int lineno = 0;

    newsprefix = config_getstring("newsprefix", 0);
    if (newsprefix) {
	newsprefixlen = strlen(newsprefix);
	if (newsprefix[newsprefixlen-1] == '.') {
	    newsprefixlen--;
	}
    }

    active_file = fopen(active, "r");
    if (!active_file) {
	perror(active);
	syslog(LOG_ERR, "cannot read active file %s: %m", active);
	cyrus_done();
	exit(EC_NOINPUT);
    }

    while (fgets(buf, sizeof(buf), active_file)) {
	lineno++;
	p = strchr(buf, ' ');	/* end of group */
	if (!p) goto badactive;
	*p++ = '\0';
	p = strchr(p, ' ');	/* start of min */
	if (!p) goto badactive;
	p = strchr(p+1, ' ');
	if (!p) goto badactive;
	p++;
	if (*p == 'y' || *p == 'm' || *p == 'n') {
	    /* Add group to list */
	    if (group_num == group_alloc) {
		/* Grow arrary */
		group_alloc += GROUPGROW;
		group = (char **) xrealloc((char *)group,
					   group_alloc * sizeof(char *));
		group_seen = (int *) xrealloc((char *)group_seen,
					     group_alloc * sizeof(int));
	    }

	    if (newsprefixlen) {
		group[group_num] = xmalloc(strlen(buf)+newsprefixlen+2);
		strcpy(group[group_num], newsprefix);
		group[group_num][newsprefixlen] = '.';
		strcpy(group[group_num]+newsprefixlen+1, buf);
	    }
	    else {
		group[group_num] = xstrdup(buf);
	    }
	    group_seen[group_num] = 0;
	    group_num++;
	}
    }

    if (ferror(active_file)) {
	fprintf(stderr, "syncnews: error reading active file\n");
	syslog(LOG_ERR, "error reading active file");
	cyrus_done();
	exit(EC_DATAERR);
    }
    fclose(active_file);

    if (group_num == 0) {
	fprintf(stderr, "syncnews: no groups in active file\n");
	syslog(LOG_ERR, "no groups in active file");
	cyrus_done();
	exit(EC_DATAERR);
    }

    qsort(group, group_num, sizeof(char *), (int (*)(const void *, const void *)) compare_group);
    return;

  badactive:
    fprintf(stderr, "syncnews: bad line %d in active file\n", lineno);
    syslog(LOG_ERR, "bad line %d in active file", lineno);
    cyrus_done();
    exit(EC_DATAERR);
    
}

/*
 * Do the real work.
 */
void do_syncnews(void)
{
    int r;
    int i;

    /*
     * call mboxlist_syncnews() to check our group list against
     * the mailboxes file.  mboxlist_syncnews() will remove any
     * mailboxes that aren't in the group list.
     */
    r = mboxlist_syncnews(group_num, group, group_seen);
    if (r) {
	com_err("syncnews: resynchronizing", r,
		(r == IMAP_IOERROR) ? error_message(errno) : NULL);
	code = convert_code(r);
	return;
    }

    /*
     * Go through the group list creating mailboxes for
     * those groups which were not found in the mailboxes file.
     */
    for (i = 0; i < group_num; i++) {
	if (!group_seen[i]) {
	    r = mboxlist_createmailbox(group[i],
				       MBTYPE_NETNEWS, "news",
				       1, "anonymous", 0);

	    if (r == IMAP_MAILBOX_BADNAME) {
		printf("ignored %s\n", group[i]);
	    }
	    else if (r) {
		fprintf(stderr, "syncnews: cannot creat %s: %s\n",
			group[i], error_message(r));
		syslog(LOG_ERR, "cannot create %s: %s",
		       group[i], error_message(r));
	    }
	    else {
		printf("created %s\n", group[i]);
	    }
	}
    }
    return;
}

void fatal(const char* s, int code)
{
    fprintf(stderr, "syncnews: %s\n", s);
    cyrus_done();
    exit(code);
}

