/* syncnews.c -- program to synchronize active file with mailbox list
 *
 * Copyright 1998 Carnegie Mellon University
 * 
 * No warranties, either expressed or implied, are made regarding the
 * operation, use, or results of the software.
 *
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted for non-commercial purposes only
 * provided that this copyright notice appears in all copies and in
 * supporting documentation.
 *
 * Permission is also granted to Internet Service Providers and others
 * entities to use the software for internal purposes.
 *
 * The distribution, modification or sale of a product which uses or is
 * based on the software, in whole or in part, for commercial purposes or
 * benefits requires specific, additional permission from:
 *
 *  Office of Technology Transfer
 *  Carnegie Mellon University
 *  5000 Forbes Avenue
 *  Pittsburgh, PA  15213-3890
 *  (412) 268-4387, fax: (412) 268-7395
 *  tech-transfer@andrew.cmu.edu
 *
 */

/*
 * $Id: syncnews.c,v 1.14 2000/01/28 22:09:52 leg Exp $
 */

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <syslog.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <com_err.h>

#include "assert.h"
#include "config.h"
#include "xmalloc.h"
#include "exitcodes.h"
#include "imap_err.h"
#include "mailbox.h"
#include "mboxlist.h"

extern int errno;
extern int optind;
extern char *optarg;

int code = 0;

int do_syncnews();

char **group = 0;
int *group_seen;
int group_num = 0;
int group_alloc = 0;

int main(int argc, char **argv)
{
    int opt;

    config_init("syncnews");

    if (geteuid() == 0) fatal("must run as the Cyrus user", EC_USAGE);

    while ((opt = getopt(argc, argv, "")) != EOF) {
	switch (opt) {
	default:
	    usage();
	}
    }

    if (!argv[optind] || argv[optind+1]) usage();

    readactive(argv[optind]);
    do_syncnews();

    exit(code);
}

usage()
{
    fprintf(stderr, "usage: syncnews active\n");
    exit(EC_USAGE);
}    

#define GROUPGROW 300

/*
 * comparison function for qsort() of the group list
 */
compare_group(a, b)
char **a, **b;
{
    return strcmp(*a, *b);
}

/*
 * Read a news active file, building the group list
 */
readactive(active)
char *active;
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
	exit(EC_DATAERR);
    }
    fclose(active_file);

    if (group_num == 0) {
	fprintf(stderr, "syncnews: no groups in active file\n");
	syslog(LOG_ERR, "no groups in active file");
	exit(EC_DATAERR);
    }

    qsort(group, group_num, sizeof(char *), compare_group);
    return;

  badactive:
    fprintf(stderr, "syncnews: bad line %d in active file\n", lineno);
    syslog(LOG_ERR, "bad line %d in active file", lineno);
    exit(EC_DATAERR);
    
}

/*
 * Do the real work.
 */
do_syncnews()
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
    exit(code);
}

