/* syncnews.c -- program to synchronize active file with mailbox list
 *
 *	(C) Copyright 1994 by Carnegie Mellon University
 *
 *                      All Rights Reserved
 *
 * Permission to use, copy, modify, distribute, and sell this software
 * and its documentation for any purpose is hereby granted without
 * fee, provided that the above copyright notice appear in all copies
 * and that both that copyright notice and this permission notice
 * appear in supporting documentation, and that the name of Carnegie
 * Mellon University not be used in advertising or publicity
 * pertaining to distribution of the software without specific,
 * written prior permission.  Carnegie Mellon University makes no
 * representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied
 * warranty.
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 *
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
#include "sysexits.h"
#include "imap_err.h"
#include "mailbox.h"

extern int errno;
extern int optind;
extern char *optarg;

int code = 0;

int do_syncnews();

char **group = 0;
int *group_seen;
int group_num = 0;
int group_alloc = 0;

main(argc, argv)
int argc;
char **argv;
{
    int opt;

    config_init("syncnews");

    if (geteuid() == 0) fatal("must run as the Cyrus user", EX_USAGE);

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
    exit(EX_USAGE);
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
	exit(EX_NOINPUT);
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
	exit(EX_DATAERR);
    }
    fclose(active_file);

    if (group_num == 0) {
	fprintf(stderr, "syncnews: no groups in active file\n");
	syslog(LOG_ERR, "no groups in active file");
	exit(EX_DATAERR);
    }

    qsort(group, group_num, sizeof(char *), compare_group);
    return;

  badactive:
    fprintf(stderr, "syncnews: bad line %d in active file\n", lineno);
    syslog(LOG_ERR, "bad line %d in active file", lineno);
    exit(EX_DATAERR);
    
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
				       MAILBOX_FORMAT_NETNEWS, "news",
				       1, "anonymous");
	    if (r) {
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

int convert_code(r)
int r;
{
    switch (r) {
    case 0:
	return 0;
	
    case IMAP_IOERROR:
	return EX_IOERR;

    case IMAP_PERMISSION_DENIED:
	return EX_NOPERM;

    case IMAP_QUOTA_EXCEEDED:
	return EX_TEMPFAIL;

    case IMAP_MAILBOX_NOTSUPPORTED:
	return EX_DATAERR;

    case IMAP_MAILBOX_NONEXISTENT:
	return EX_UNAVAILABLE;
    }
	
    /* Some error we're not expecting. */
    return EX_SOFTWARE;
}	

fatal(s, code)
char *s;
int code;
{
    fprintf(stderr, "syncnews: %s\n", s);
    exit(code);
}

