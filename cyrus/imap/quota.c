/* quota.c -- program to report/reconstruct quotas
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
#include <ctype.h>
#include <sysexits.h>
#include <dirent.h>
#include <syslog.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <com_err.h>

#include "assert.h"
#include "config.h"
#include "imap_err.h"
#include "mailbox.h"
#include "xmalloc.h"

/* Many systems don't define EX_CONFIG */
#ifndef EX_CONFIG
#define EX_CONFIG 78
#endif

extern int errno;
extern int optind;
extern char *optarg;

extern char *mailbox_findquota();

struct quotaentry {
    struct quota quota;
    int refcount;
    unsigned long newused;
};

#define QUOTAGROW 10 /* XXX 300 */

struct quotaentry zeroquotaentry;
struct quotaentry *quota;
int quota_num = 0, quota_alloc = 0;

main(argc, argv)
int argc;
char **argv;
{
    int opt;
    int rflag = 0;
    int i, r, code = 0;

    config_init("quota");

    while ((opt = getopt(argc, argv, "r")) != EOF) {
	switch (opt) {
	case 'r':
	    rflag = 1;
	    break;

	default:
	    usage();
	}
    }

    r = buildquotalist(argv+optind, argc-optind);

    if (!r && rflag) r = fsckquota();

    if (!r) reportquota(rflag);

    if (r) {
	com_err("quota", r, (r == EX_IOERR) ? error_message(errno) : NULL);
	code = convert_code(r);
    }

    exit(code);
}

usage()
{
    fprintf(stderr, "usage: quota [-r] [prefix]...\n");
    exit(EX_USAGE);
}    

int compare_quota(a, b)
char *a, *b;
{
    return strcasecmp(((struct quotaentry *)a)->quota.root,
		      ((struct quotaentry *)b)->quota.root);
}

#define QUOTA_GROW 10 /* XXX 300 */

int 
buildquotalist(roots, nroots)
char **roots;
int nroots;
{
    int r;
    char quota_path[MAX_MAILBOX_PATH];
    int i, flag;
    char *p;
    FILE *newindex, *newcache;
    DIR *dirp;
    struct dirent *dirent;
    int msg, old_msg = 0, new_exists = 0;
    unsigned long new_quota = 0;
    struct stat sbuf;
    int n;

    sprintf(quota_path, "%s%s", config_dir, FNAME_QUOTADIR);
    if (chdir(quota_path)) {
	return IMAP_IOERROR;
    }

    dirp = opendir(".");
    if (!dirp) {
	return IMAP_IOERROR;
    }
    while (dirent = readdir(dirp)) {
	if (dirent->d_name[0] == '.') continue;
	
	/* If restricting our list, see if this quota file matches */
	if (nroots) {
	    for (i = 0; i < nroots; i++) {
		if (!strcasecmp(dirent->d_name, roots[i]) ||
		    (!strncasecmp(dirent->d_name, roots[i], strlen(roots[i])) &&
		     dirent->d_name[strlen(roots[i])] == '.')) break;
	    }
	    if (i == nroots) continue;
	}

	/* Ignore .NEW files */
	i = strlen(dirent->d_name);
	if (i > 4 && !strcmp(dirent->d_name+i-4, ".NEW")) continue;

	if (quota_num == quota_alloc) {
	    quota_alloc += QUOTA_GROW;
	    quota = (struct quotaentry *)
	      xrealloc((char *)quota, quota_alloc * sizeof(struct quotaentry));
	}
	quota[quota_num] = zeroquotaentry;
	quota[quota_num].quota.root = strsave(dirent->d_name);
	
	r = mailbox_read_quota(&quota[quota_num].quota);
	if (quota[quota_num].quota.file) {
	    fclose(quota[quota_num].quota.file);
	    quota[quota_num].quota.file = 0;
	}
	if (r) {
	    com_err(dirent->d_name, r,
		    (r == EX_IOERR) ? error_message(errno) : NULL);
	    quota[quota_num].quota.used = 0;
	    quota[quota_num].quota.limit = -1;
	}

	quota_num++;
    }
    closedir(dirp);
    qsort((char *)quota, quota_num, sizeof(*quota), compare_quota);

    return 0;
}

int fsckquota()
{
    /* XXX */ abort();
}

int reportquota(rflag)
int rflag;
{
    int i;

    printf(
	 "Root                                 %s    Used   Quota  %% Used\n",
	   rflag ? "Mailboxes" : "         ");

    for (i = 0; i < quota_num; i++) {
	printf("%-37s", quota[i].quota.root);
	if (rflag) {
	    printf("%9d", quota[i].refcount);
	}
	else {
	    printf("         ");
	}
	printf(" %7d", quota[i].quota.used / QUOTA_UNITS);
	if (quota[i].quota.limit > 0) {
	    printf(" %7d %7d", quota[i].quota.limit,
		   ((quota[i].quota.used / QUOTA_UNITS) * 100) / quota[i].quota.limit);
	}
	else if (quota[i].quota.limit == 0) {
	    printf("       0");
	}
	printf("\n");
    }
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
    fprintf(stderr, "reconstruct: %s\n", s);
    exit(code);
}

