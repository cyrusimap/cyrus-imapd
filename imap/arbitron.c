/* arbitron.c -- program to report readership statistics
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
#include "sysexits.h"
#include "imap_err.h"
#include "mailbox.h"
#include "xmalloc.h"

extern int errno;
extern int optind;
extern char *optarg;

int code = 0;

time_t report_time, prune_time = 0;

int do_mailbox();

struct arbitronargs {
    char *name;
    unsigned read_count;
};

main(argc, argv)
int argc;
char **argv;
{
    int opt, i;
    int report_days = 30;
    int prune_months = 0;
    char pattern[30];

    config_init("arbitron");

    if (geteuid() == 0) fatal("must run as the Cyrus user", EX_USAGE);

    while ((opt = getopt(argc, argv, "d:p:")) != EOF) {
	switch (opt) {
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

    if (optind != argc) usage();

    report_time = time(0) - (report_days*60*60*24);
    if (prune_months) {
	prune_time = time(0) - (prune_months*60*60*24*31);
    }

    strcpy(pattern, "*");
    mboxlist_findall(pattern, 1, 0, 0, do_mailbox);

    exit(code);
}

usage()
{
    fprintf(stderr, "usage: arbitron [-d days] [-p months]\n");
    exit(EX_USAGE);
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

int 
arbitron(name)
char *name;
{
    int r;
    struct mailbox mailbox;
    struct arbitronargs arbitronargs;

    /* Open/lock header */
    r = mailbox_open_header(name, 0, &mailbox);
    if (r) {
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
	    printf("%u %s\n", arbitronargs.read_count, name);
	}
    }

    return r;
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
    fprintf(stderr, "arbitron: %s\n", s);
    exit(code);
}

