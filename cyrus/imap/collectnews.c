/* collectnews.c -- program to add news articles to relevant header files
 $Id: collectnews.c,v 1.26.14.1 2002/11/07 15:11:15 ken3 Exp $
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
 */

#include <config.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <com_err.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <errno.h>

#include "imapconf.h"
#include "exitcodes.h"
#include "imap_err.h"
#include "mailbox.h"
#include "xmalloc.h"
#include "mboxlist.h"
#include "append.h"
#include "convert_code.h"

extern int optind;
extern char *optarg;

struct newsgroup {
    unsigned long last_uid;
    char groupname[1];
};

void collect(char *group, unsigned long feeduid);

struct newsgroup **newsgroup = 0;
int num_newsgroup = 0;
int size_newsgroup = 0;
struct newsgroup *getnewsgroup();

const char *newsprefix;
int newsprefixlen;


int main(int argc, char **argv)
{
    char buf[4096], *group, *nextgroup, *uid, *p;
    int c;
    int opt;
    char *alt_config = NULL;

    while ((opt = getopt(argc, argv, "C:")) != EOF) {
	switch (opt) {
	case 'C': /* alt config file */
	    alt_config = optarg;
	    break;
	default:
	    break;
	}
    }

    config_init(alt_config, "collectnews");

    if (geteuid() == 0) fatal("must run as the Cyrus user", EC_USAGE);

    newsprefix = config_getstring("newsprefix", 0);
    if (newsprefix) newsprefixlen = strlen(newsprefix);
    
    if (!config_getstring("partition-news", 0)) {
	fatal("partition-news option not specified in configuration file",
	      EC_CONFIG);
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
		if ((p = strrchr(buf, ' '))!=NULL) {
		    /* Throw away last (partial) filename */
		    *p = '\0';
		}
		else {
		    /* Ignore entire line */
		    continue;
		}
	    }
	}

#ifdef OLD_INN_FORMAT
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
#else
	/* this is the new INN format that uses the replication data */

	/* we see "group.foo.A/#,group.bar.B/#,group.baz.C/#" */
	group = buf;
	while (group) {
	    nextgroup = strchr(group, ',');
	    if (nextgroup) *nextgroup++ = '\0';

	    uid = strrchr(group, '/');
	    if (!uid) continue;
	    *uid++ = '\0';
	    
	    collect(group, atol(uid));
	    
	    group = nextgroup;
	}
    }
#endif
    exit(0);
}

void collect(char *group, unsigned long feeduid)
{
    int r;
    struct appendstate as;
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

    r = append_setup(&as, newsprefix ? namebuf : group,
		     MAILBOX_FORMAT_NETNEWS, 0, 0, 0, 0);

    if (r == IMAP_MAILBOX_NONEXISTENT) {
	r = mboxlist_createmailbox(newsprefix ? namebuf : group,
				   MBTYPE_NETNEWS, "news",
				   1, "anonymous", 0);

	/* Ignore bad mailbox names */
	if (r == IMAP_MAILBOX_BADNAME) return;

	if (r) {
	    syslog(LOG_CRIT, "cannot create %s: %s",
		   newsprefix ? namebuf : group,
		   error_message(r));
	    fatal("cannot create mailbox for new newsgroup", convert_code(r));
	}

	r = append_setup(&as, newsprefix ? namebuf : group,
			 MAILBOX_FORMAT_NETNEWS, 0, 0, 0, 0);
    }

    if (r) {
	syslog(LOG_CRIT, "cannot open %s: %s",
	       newsprefix ? namebuf : group,
	       error_message(r));
	fatal("cannot open mailbox for newsgroup", convert_code(r));
    }

    /*
     * Avoid O(n**2) behavior when we're indexing articles
     * that have already expired.
     */
    if (as.m.last_uid < ng->last_uid) as.m.last_uid = ng->last_uid;

    r = append_collectnews(&as, group, feeduid);

    if (r) {
	append_abort(&as);
	syslog(LOG_CRIT, "cannot append to %s: %s",
	       newsprefix ? namebuf : group,
	       error_message(r));
	fatal("cannot append to mailbox for newsgroup", convert_code(r));
    }

    append_commit(&as, NULL, NULL, NULL);
    ng->last_uid = as.m.last_uid; 
    if (ng->last_uid < feeduid) ng->last_uid = feeduid;

    /* now expunge old messages */
    {
	struct mailbox mailbox;

	mailbox_open_header(newsprefix ? namebuf : group, NULL,
			    &mailbox);
	mailbox_expungenews(&mailbox);
	mailbox_close(&mailbox);
    }
}

#define GROW 1000
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
	return EC_IOERR;

    case IMAP_PERMISSION_DENIED:
	return EC_NOPERM;

    case IMAP_QUOTA_EXCEEDED:
	return EC_TEMPFAIL;

    case IMAP_MAILBOX_NOTSUPPORTED:
	return EC_DATAERR;

    case IMAP_MAILBOX_NONEXISTENT:
	return EC_UNAVAILABLE;
    }
	
    /* Some error we're not expecting. */
    return EC_SOFTWARE;
}	

void fatal(const char* s, int code)
{
    syslog(LOG_CRIT, "collectnews: %s\n", s);
    exit(code);
}

