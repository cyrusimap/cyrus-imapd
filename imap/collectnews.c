/* collectnews.c -- program to add news articles to relevant header files
 *
 *	(C) Copyright 1994 by Carnegie Mellon University
 *
 *                      All Rights Reserved
 *
 * Permission to use, copy, modify, and distribute this software and its 
 * documentation for any purpose and without fee is hereby granted, 
 * provided that the above copyright notice appear in all copies and that
 * both that copyright notice and this permission notice appear in 
 * supporting documentation, and that the name of CMU not be
 * used in advertising or publicity pertaining to distribution of the
 * software without specific, written prior permission.  
 * 
 * CMU DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
 * ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL
 * CMU BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR
 * ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
 * WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
 * ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 *
 */

#include <stdio.h>
#include <string.h>
#include <sysexits.h>
#include <syslog.h>
#include <com_err.h>

#include "config.h"
#include "imap_err.h"
#include "mailbox.h"
#include "xmalloc.h"

/* Many systems don't define EX_CONFIG */
#ifndef EX_CONFIG
#define EX_CONFIG 78
#endif

extern int errno;

struct newsgroup {
    unsigned long last_uid;
    char groupname[1];
};

struct newsgroup **newsgroup = 0;
int num_newsgroup = 0;
int size_newsgroup = 0;
struct newsgroup *getnewsgroup();

char *newsprefix;
int newsprefixlen;


main(argc, argv)
int argc;
char **argv;
{
    char buf[4096], *group, *nextgroup, *uid, *p;
    int c;

    config_init("collectnews");

    newsprefix = config_getstring("newsprefix", 0);
    if (newsprefix) newsprefixlen = strlen(newsprefix);
    
    if (!config_getstring("partition-news", 0)) {
	fatal("partition-news option not specified in configuration file",
	      EX_CONFIG);
    }

    while (fgets(buf, sizeof(buf), stdin)) {
	p = buf + strlen(buf) - 1;
	if (*p == '\n') {
	    *p = '\0';
	}
	else {
	    /* Line too long.  Eat up rest of line. */
	    do {
		c = getc(stdin);
	    } while (c != EOF && c != '\n');

	    if (!strchr(buf, '\t')) {
		/* No overview junk to throw away */
		if (p = strrchr(buf, ' ')) {
		    /* Throw away last (partial) filename */
		    *p = '\0';
		}
		else {
		    /* Ignore entire line */
		    continue;
		}
	    }
	}

	/* Nuke out overview junk */
	if (p = strchr(buf, '\t')) {
	    *p = '\0';
	}

	group = buf;
	do {
	    nextgroup = strchr(group, ' ');
	    if (nextgroup) *nextgroup++ = '\0';

	    uid = strrchr(group, '/');
	    if (!uid) continue;
	    *uid++ = '\0';

	    for (p = group; *p; p++) {
		if (*p == '/') *p = '.';
	    }

	    collect(group, atol(uid));
	} while ((group = nextgroup) != 0);
    }
    exit(0);
}

collect(group, feeduid)
char *group;
unsigned long feeduid;
{
    
    int r;
    struct mailbox mailbox;
    char namebuf[MAX_MAILBOX_PATH];
    struct newsgroup *ng;
    
    /* Some sort of parsing screwup */
    if (!feeduid) return;

    ng = getnewsgroup(group);

    /* Check to see if we already processed this one */
    if (feeduid <= ng->last_uid) return;

    if (newsprefix) {
	strcpy(namebuf, newsprefix);
	if (namebuf[newsprefixlen-1] != '.') {
	    namebuf[newsprefixlen] = '.';
	    strcpy(namebuf+newsprefixlen+1, group);
	}
	else {
	    strcpy(namebuf+newsprefixlen, group);
	}
    }

    r = append_setup(&mailbox, newsprefix ? namebuf : group,
		     MAILBOX_FORMAT_NETNEWS, 0, 0);

    if (r == IMAP_MAILBOX_NONEXISTENT) {
	r = mboxlist_createmailbox(newsprefix ? namebuf : group,
				   MAILBOX_FORMAT_NETNEWS, "news",
				   1, "anonymous");
	if (r) {
	    syslog(LOG_CRIT, "cannot create %s: %s",
		   newsprefix ? namebuf : group,
		   error_message(r));
	    fatal("cannot create mailbox for new newsgroup", convert_code(r));
	}

	r = append_setup(&mailbox, newsprefix ? namebuf : group,
			 MAILBOX_FORMAT_NETNEWS, 0, 0);
    }

    if (r) {
	syslog(LOG_CRIT, "cannot open %s: %s",
	       newsprefix ? namebuf : group,
	       error_message(r));
	fatal("cannot open mailbox for newsgroup", convert_code(r));
    }

    r = append_collectnews(&mailbox, feeduid);

    if (r) {
	syslog(LOG_CRIT, "cannot append to %s: %s",
	       newsprefix ? namebuf : group,
	       error_message(r));
	fatal("cannot append to mailbox for newsgroup", convert_code(r));
    }

    ng->last_uid = mailbox.last_uid; 
    mailbox_close(&mailbox);
}

#define GROW 10 /* 1000 */
struct newsgroup *
getnewsgroup(group)
char *group;
{
    int low=0, high=num_newsgroup-1;
    int mid, cmp;

    while (low <= high) {
	mid = (high - low)/2 + low;
	cmp = strcmp(group, newsgroup[mid]->groupname);
	if (!cmp) {
	    return newsgroup[mid];
	}
	else if (cmp < 0) {
	    high = mid - 1;
	}
	else {
	    low = mid + 1;
	}
    }
    if (num_newsgroup == size_newsgroup) {
	size_newsgroup += GROW;
	newsgroup = (struct newsgroup **)
	  xrealloc((char *)newsgroup,
		   size_newsgroup * sizeof(struct newsgroup *));
    }
    
    for (high = num_newsgroup; high > low; high--) {
	newsgroup[high] = newsgroup[high-1];
    }
    num_newsgroup++;
    newsgroup[low] = (struct newsgroup *)
      xmalloc(sizeof(struct newsgroup)+strlen(group));
    newsgroup[low]->last_uid = 0;
    strcpy(newsgroup[low]->groupname, group);
    return newsgroup[low];
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
	/* XXX Might have been moved to other server */
	return EX_UNAVAILABLE;
    }
	
    /* Some error we're not expecting. */
    return EX_SOFTWARE;
}	

fatal(s, code)
char *s;
int code;
{
    fprintf(stderr, "collectnews: %s\n", s);
    exit(code);
}

