/* rmnews.c -- program to expunge/remove news articles
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
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <com_err.h>

#include "config.h"
#include "imap_err.h"
#include "mailbox.h"
#include "sysexits.h"
#include "xmalloc.h"

extern int errno;

char *newsprefix;
int newsprefixlen;
char *newspartition;

struct uidlist {
    unsigned int *list;
    int first, last, size;
};
#define UIDGROW 500

int expungeuidlist();
int compuint();

main(argc, argv)
int argc;
char **argv;
{
    int ruid, rgid;
    char lastgroup[4096];
    char buf[4096], *group, *nextgroup, *uid, *p;
    static struct uidlist uidlist;
    int c;

    config_init("rmnews");

    if (geteuid() == 0) fatal("must run as the Cyrus user", EX_USAGE);

    newsprefix = config_getstring("newsprefix", 0);
    if (newsprefix) newsprefixlen = strlen(newsprefix);
    
    newspartition = config_getstring("partition-news", 0);
    if (!newspartition) {
	fatal("partition-news option not specified in configuration file",
	      EX_CONFIG);
    }

    /* only allow setuid/setgid from news user */
    ruid = getuid();
    rgid = getgid();
    if (ruid && ruid != geteuid()) {
	struct stat sbuf;
	if (stat(newspartition, &sbuf) || sbuf.st_uid != ruid) {
	    fprintf(stderr, "rmnews: renouncing set-uid/set-gid\n");
	    syslog(LOG_ERR,
		   "RENOUNCE: renouncing setuid/setgid since run by %d/%d",
		   ruid, rgid);
	    setuid(ruid);
	    setgid(rgid);
	}
    }

    lastgroup[0] = '\0';

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
	    continue;
	}

	group = buf;
	do {
	    nextgroup = strchr(group, ' ');
	    if (nextgroup) *nextgroup++ = '\0';

	    uid = strrchr(group, '/');
	    if (!uid) continue;
	    *uid++ = '\0';

	    if (strcmp(group,lastgroup) != 0) {
		if (lastgroup[0]) removearticles(lastgroup, &uidlist);
		strcpy(lastgroup, group);
		uidlist.first = uidlist.last = 0;
	    }
	    if (uidlist.last == uidlist.size) {
		uidlist.size += UIDGROW;
		uidlist.list = (unsigned int *)
		  xrealloc((char *)uidlist.list,
			   uidlist.size * sizeof(unsigned int));
	    }
	    uidlist.list[uidlist.last++] = atol(uid);
	} while ((group = nextgroup) != 0);
    }
    if (lastgroup[0]) removearticles(lastgroup, &uidlist);
    exit(0);
}

/*
 * EXPUNGE or remove the articles listed in uidlist from the directory
 * 'dir'
 */
removearticles(dir, uidlist)
char *dir;
struct uidlist *uidlist;
{
    
    unsigned i;
    int r;
    struct mailbox mailbox;
    char namebuf[MAX_MAILBOX_PATH];
    char *p, buf[4096];
    
    /* Sort uidlist if necessary */
    for (i=1; i<uidlist->last; i++) {
	if (uidlist->list[i] < uidlist->list[i-1]) break;
    }
    if (i < uidlist->last) {
	qsort((char *)uidlist->list, uidlist->last, sizeof(unsigned int),
	      compuint);
    }

    /* Get corresponding mailbox name */
    if (newsprefix) {
	strcpy(namebuf, newsprefix);
	if (namebuf[newsprefixlen-1] != '.') {
	    namebuf[newsprefixlen] = '.';
	    strcpy(namebuf+newsprefixlen+1, dir);
	}
	else {
	    strcpy(namebuf+newsprefixlen, dir);
	}
    }
    else {
	strcpy(namebuf, dir);
	for (p = namebuf; *p; p++) {
	    if (*p == '/') *p = '.';
	}
    }

    r = mailbox_open_header(namebuf, &mailbox);
    if (!r) r = mailbox_open_index(&mailbox);

    if (r == IMAP_MAILBOX_NONEXISTENT) {
	/* Just cd to the directory and unlink the files */
	strcpy(buf, newspartition);
	if (newsprefix) {
	    strcat(buf, "/");
	    strcat(buf, newsprefix);
	    for (p = buf + strlen(newspartition); *p; p++) {
		if (*p == '.') *p = '/';
	    }
	}
	strcat(buf, "/");
	strcat(buf, dir);
	if (chdir(buf)) {
	    syslog(LOG_ERR, "IOERROR: changing dir to %s: %m", dir);
	    fatal("cannot change dir to newsgroup", EX_IOERR);
	}
	for (i = uidlist->first; i < uidlist->last; i++) {
	    sprintf(buf, "%u", i);
	    unlink(buf);
	}
	return;
    }
    else if (r) {
	syslog(LOG_CRIT, "cannot open %s: %s", namebuf, error_message(r));
	fatal("cannot open mailbox for newsgroup", convert_code(r));
    }

    if (chdir(mailbox.path)) {
	syslog(LOG_ERR, "IOERROR: changing dir to %s: %m", mailbox.path);
	fatal("cannot change dir to mailbox for newsgroup", EX_IOERR);
    }

    r = mailbox_expunge(&mailbox, 1, expungeuidlist, (char *)uidlist);

    if (r) {
	syslog(LOG_CRIT, "cannot expunge %s: %s", namebuf, error_message(r));
	fatal("cannot expunge newsgroup", convert_code(r));
    }
    mailbox_close(&mailbox);

    /* Remove any remaining files that weren't in the index file */
    for (i = uidlist->first; i < uidlist->last; i++) {
	sprintf(buf, "%u", uidlist->list[i]);
	unlink(buf);
    }
}

/*
 * Expunge decision procedure to get rid of articles
 * listed in uidlist.
 */
int expungeuidlist(rock, index)
char *rock;
char *index;
{
    struct uidlist *uidlist = (struct uidlist *)rock;
    unsigned uid = ntohl(*((bit32 *)(index+OFFSET_UID)));
    char buf[80];

    while (uidlist->first < uidlist->last &&
	   uidlist->list[uidlist->first] <= uid) {
	if (uidlist->list[uidlist->first++] == uid) {
	    return 1;
	}
	/* Article not in index file, just remove the file */
	sprintf(buf, "%u", uid);
	unlink(buf);
    }
    return 0;
}

/*
 * qsort comparison function to sort unsigned ints.
 */
int compuint(a, b)
char *a;
char *b;
{
    return (*(unsigned int *)a) - (*(unsigned int *)b);
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
    fprintf(stderr, "rmnews: %s\n", s);
    exit(code);
}

