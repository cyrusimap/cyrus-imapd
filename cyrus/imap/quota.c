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
    int deleted;
    unsigned long newused;
};

#define QUOTAGROW 10 /* XXX 300 */

struct quotaentry zeroquotaentry;
struct quotaentry *quota;
int quota_num = 0, quota_alloc = 0;

int firstquota;
int redofix;

main(argc, argv)
int argc;
char **argv;
{
    int opt;
    int fflag = 0;
    int r, code = 0;

    config_init("quota");

    while ((opt = getopt(argc, argv, "f")) != EOF) {
	switch (opt) {
	case 'f':
	    fflag = 1;
	    break;

	default:
	    usage();
	}
    }

    r = buildquotalist(argv+optind, argc-optind);

    if (!r && fflag) r = fixquota();

    if (!r) reportquota();

    if (r) {
	com_err("quota", r, (r == IMAP_IOERROR) ? error_message(errno) : NULL);
	code = convert_code(r);
    }

    exit(code);
}

usage()
{
    fprintf(stderr, "usage: quota [-f] [prefix]...\n");
    exit(EX_USAGE);
}    

/*
 * Comparison function for sorting quota roots
 */
int compare_quota(a, b)
char *a, *b;
{
    return strcasecmp(((struct quotaentry *)a)->quota.root,
		      ((struct quotaentry *)b)->quota.root);
}

#define QUOTA_GROW 10 /* XXX 300 */

/*
 * Build the list of quota roots in 'quota'
 */
int 
buildquotalist(roots, nroots)
char **roots;
int nroots;
{
    int r;
    char quota_path[MAX_MAILBOX_PATH];
    int i;
    DIR *dirp;
    struct dirent *dirent;

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

/*
 * Account for mailbox 'name' when fixing the quota roots
 */
int
fixquota_mailbox(name, matchlen, maycreate)
char *name;
int matchlen;
int maycreate;
{
    int r;
    struct mailbox mailbox;
    int i, len, thisquota, thisquotalen;

    while (firstquota < quota_num &&
	   strncasecmp(name, quota[firstquota].quota.root,
		       strlen(quota[firstquota].quota.root)) > 0) {
	r = fixquota_finish(firstquota++);
	if (r) return r;
    }

    thisquota = -1;
    thisquotalen = 0;
    for (i = firstquota;
	 i < quota_num && strcasecmp(name, quota[i].quota.root) >= 0; i++) {
	len = strlen(quota[i].quota.root);
	if (!strncasecmp(name, quota[i].quota.root, len) &&
	    (!name[len] || name[len] == '.')) {
	    quota[i].refcount++;
	    if (len > thisquotalen) {
		thisquota = i;
		thisquotalen = len;
	    }
	}
    }

    r = mailbox_open_header(name, &mailbox);
    if (r) return r;

    if (thisquota == -1) {
	if (mailbox.quota.root) {
	    r = fixquota_fixroot(&mailbox, (char *)0);
	    if (r) {
		mailbox_close(&mailbox);
		return r;
	    }
	}
	return 0;
    }

    if (!mailbox.quota.root ||
	strcmp(mailbox.quota.root, quota[thisquota].quota.root) != 0) {
	r = fixquota_fixroot(&mailbox, quota[thisquota].quota.root);
	if (r) {
	    mailbox_close(&mailbox);
	    return r;
	}
    }
    
    if (!quota[thisquota].quota.file) {
	r = mailbox_lock_quota(&quota[thisquota].quota);
	if (r) {
	    mailbox_close(&mailbox);
	    return r;
	}
    }

    r = mailbox_open_index(&mailbox);
    if (r) {
	mailbox_close(&mailbox);
	return r;
    }

    quota[thisquota].newused += mailbox.quota_mailbox_used;
    mailbox_close(&mailbox);

    return 0;
}
	
int
fixquota_fixroot(mailbox, root)
struct mailbox *mailbox;
char *root;
{
    int i, r;

    /*
     * Locking order is to lock header before quota.  We therefore
     * unlock all the quota roots we have locked in order to avoid a
     * deadlock.  As releasing these locks can cause the quota use
     * recalculation to screw up, we set the global variable 'redofix'
     * to cause the quota use recalculation to be redone.
     *
     * We could optimize this by trying to get a nonblocking lock on
     * the header and unlocking all the quota roots only when that fails.
     */
    for (i = firstquota; i < quota_num; i++) {
	if (quota[i].quota.file) {
	    fclose(quota[i].quota.file);
	    quota[i].quota.file = 0;
	}
    }
    redofix = 1;

    r = mailbox_lock_header(mailbox);
    if (r) return r;

    printf("%s: quota root %s --> %s\n", mailbox->name,
	   mailbox->quota.root ? mailbox->quota.root : "(none)",
	   root ? root : "(none)");

    if (mailbox->quota.root) free(mailbox->quota.root);
    if (root) {
	mailbox->quota.root = strsave(root);
    }
    else {
	mailbox->quota.root = 0;
    }

    r = mailbox_write_header(mailbox);
    (void) mailbox_unlock_header(mailbox);
    return r;
}

/*
 * Finish fixing up a quota root
 */
int
fixquota_finish(thisquota)
int thisquota;
{
    int r;

    if (!quota[thisquota].refcount) {
	if (!quota[thisquota].deleted++) {
	    printf("%s: removed\n", quota[thisquota].quota.root);
	    unlink(quota[thisquota].quota.root);
	}
	return 0;
    }

    if (!quota[thisquota].quota.file) {
	r = mailbox_lock_quota(&quota[thisquota].quota);
	if (r) {
	    if (quota[thisquota].quota.file) {
		fclose(quota[thisquota].quota.file);
		quota[thisquota].quota.file = 0;
	    }
	    return r;
	}
    }
    
    if (quota[thisquota].quota.used != quota[thisquota].newused) {
	printf("%s: usage was %d, now %d\n", quota[thisquota].quota.root,
	       quota[thisquota].quota.used, quota[thisquota].newused);
	quota[thisquota].quota.used = quota[thisquota].newused;
	r = mailbox_write_quota(&quota[thisquota].quota);
	if (r) return r;
    }

    fclose(quota[thisquota].quota.file);
    quota[thisquota].quota.file = 0;
    return 0;
}


/*
 * Fix all the quota roots
 */
int
fixquota()
{
    FILE *listfile;
    int r;
    char pattern[] = "*";

    /*
     * Lock mailbox list to prevent mailbox creation/deletion
     * during the fix
     */
    r = mboxlist_openlock(&listfile, (unsigned *)0);
    if (r) return r;

    redofix = 1;
    while (redofix) {
	redofix = 0;
	firstquota = 0;

	r = mboxlist_findall(pattern, 1, 0, fixquota_mailbox);
	if (r) {
	    fclose(listfile);
	    return r;
	}

	while (firstquota < quota_num) {
	    r = fixquota_finish(firstquota++);
	    if (r) {
		fclose(listfile);
		return r;
	    }
	}
    }
    
    fclose(listfile);
    return 0;
}
    
/*
 * Print out the quota report
 */
int
reportquota()
{
    int i;

    printf("   Quota  %% Used    Used Root\n");

    for (i = 0; i < quota_num; i++) {
	if (quota[i].deleted) continue;
	if (quota[i].quota.limit > 0) {
	    printf(" %7d %7d", quota[i].quota.limit,
		   ((quota[i].quota.used / QUOTA_UNITS) * 100) / quota[i].quota.limit);
	}
	else if (quota[i].quota.limit == 0) {
	    printf("       0        ");
	}
	else {
	    printf("                ");
	}
	printf(" %7d %s\n", quota[i].quota.used / QUOTA_UNITS,
	       quota[i].quota.root);
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

