/* quota.c -- program to report/reconstruct quotas
 *
 * Copyright (c) 1998-2003 Carnegie Mellon University.  All rights reserved.
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
/* $Id: quota.c,v 1.41.4.8 2003/02/13 20:33:01 rjs3 Exp $ */


#include <config.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <syslog.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <com_err.h>

#if HAVE_DIRENT_H
# include <dirent.h>
# define NAMLEN(dirent) strlen((dirent)->d_name)
#else
# define dirent direct
# define NAMLEN(dirent) (dirent)->d_namlen
# if HAVE_SYS_NDIR_H
#  include <sys/ndir.h>
# endif
# if HAVE_SYS_DIR_H
#  include <sys/dir.h>
# endif
# if HAVE_NDIR_H
#  include <ndir.h>
# endif
#endif

#include "assert.h"
#include "global.h"
#include "exitcodes.h"
#include "imap_err.h"
#include "mailbox.h"
#include "xmalloc.h"
#include "mboxlist.h"
#include "mboxname.h"
#include "convert_code.h"

extern int optind;
extern char *optarg;

/* current namespace */
static struct namespace quota_namespace;

/* config.c stuff */
const int config_need_data = CONFIG_NEED_PARTITION_DATA;

/* forward declarations */
void usage(void);
void reportquota(void);
int buildquotalist(char **roots, int nroots);
int fixquota_mailbox(char *name,
		     int matchlen,
		     int maycreate,
		     void* rock);
int fixquota(int ispartial);
int fixquota_fixroot(struct mailbox *mailbox,
		     char *root);
int fixquota_finish(int thisquota);

struct quotaentry {
    struct quota quota;
    int refcount;
    int deleted;
    unsigned long newused;
};

#define QUOTAGROW 300

struct quotaentry zeroquotaentry;
struct quotaentry *quota;
int quota_num = 0, quota_alloc = 0;

int firstquota;
int redofix;
int partial;

int main(int argc,char **argv)
{
    int opt;
    int fflag = 0;
    int r, code = 0;
    char *alt_config = NULL;

    if (geteuid() == 0) fatal("must run as the Cyrus user", EC_USAGE);

    while ((opt = getopt(argc, argv, "C:f")) != EOF) {
	switch (opt) {
	case 'C': /* alt config file */
	    alt_config = optarg;
	    break;

	case 'f':
	    fflag = 1;
	    break;

	default:
	    usage();
	}
    }

    cyrus_init(alt_config, "quota");

    /* Set namespace -- force standard (internal) */
    if ((r = mboxname_init_namespace(&quota_namespace, 1)) != 0) {
	syslog(LOG_ERR, error_message(r));
	fatal(error_message(r), EC_CONFIG);
    }

    r = buildquotalist(argv+optind, argc-optind);

    if (!r && fflag) {
	mboxlist_init(0);
	r = fixquota(argc-optind);
	mboxlist_done();
    }

    if (!r) reportquota();

    if (r) {
	com_err("quota", r, (r == IMAP_IOERROR) ? error_message(errno) : NULL);
	code = convert_code(r);
    }

    cyrus_done();

    return code;
}

void usage(void)
{
    fprintf(stderr, "usage: quota [-C <alt_config>] [-f] [prefix]...\n");
    exit(EC_USAGE);
}    

/*
 * Comparison function for sorting quota roots
 */
int compare_quota(const void *a, const void *b)
{
    return strcmp(((struct quotaentry *)a)->quota.root,
		      ((struct quotaentry *)b)->quota.root);
}

/*
 * Build the list of quota roots in 'quota'
 */
int buildquotalist(char **roots, int nroots)
{
    int r;
    char quota_path[MAX_MAILBOX_PATH];
    int i;
    DIR *dirp;
    DIR *topp;
    struct dirent *dirent;

    /* Translate separator in mailboxnames.
     *
     * We do this directly instead of using the mboxname_tointernal()
     * function pointer because we know that we are using the internal
     * namespace and so we don't have to allocate a buffer for the
     * translated name.
     */
    for (i = 0; i < nroots; i++) {
	mboxname_hiersep_tointernal(&quota_namespace, roots[i], 0);
    }

    snprintf(quota_path, sizeof(quota_path),
	     "%s%s", config_dir, FNAME_QUOTADIR);
    if (chdir(quota_path)) {
	return IMAP_IOERROR;
    }
    
    topp = opendir(".");
    if (!topp) {
	return IMAP_IOERROR;
    }
    while ((dirent = readdir(topp))!=NULL) {
	if (dirent->d_name[0] == '.') continue;
	
	dirp = opendir(dirent->d_name);
	if (!dirp) continue;

	while ((dirent = readdir(dirp))!=NULL) {
	    if (dirent->d_name[0] == '.') continue;

	    /* If restricting our list, see if this quota file matches */
	    if (nroots) {
		for (i = 0; i < nroots; i++) {
		    if (!strcmp(dirent->d_name, roots[i]) ||
			(!strncmp(dirent->d_name, roots[i], strlen(roots[i])) &&
			 dirent->d_name[strlen(roots[i])] == '.')) break;
		}
		if (i == nroots) continue;
	    }
	    
	    /* Ignore .NEW files */
	    i = strlen(dirent->d_name);
	    if (i > 4 && !strcmp(dirent->d_name+i-4, ".NEW")) continue;
	    
	    if (quota_num == quota_alloc) {
		quota_alloc += QUOTAGROW;
		quota = (struct quotaentry *)
		    xrealloc((char *)quota, quota_alloc * sizeof(struct quotaentry));
	    }
	    quota[quota_num] = zeroquotaentry;
	    quota[quota_num].quota.fd = -1;
	    quota[quota_num].quota.root = xstrdup(dirent->d_name);
	    
	    r = mailbox_read_quota(&quota[quota_num].quota);
	    if (quota[quota_num].quota.fd != -1) {
		close(quota[quota_num].quota.fd);
		quota[quota_num].quota.fd = -1;
	    }
	    if (r) {
		com_err(dirent->d_name, r,
			(r == EC_IOERR) ? error_message(errno) : NULL);
		quota[quota_num].quota.used = 0;
		quota[quota_num].quota.limit = -1;
	    }
	    
	    quota_num++;
	}
	
	/* close this subdirectory */
	closedir(dirp);
    }
    closedir(topp);
    qsort((char *)quota, quota_num, sizeof(*quota), compare_quota);

    return 0;
}

/*
 * Account for mailbox 'name' when fixing the quota roots
 */
int fixquota_mailbox(char *name,
		     int matchlen,
		     int maycreate,
		     void* rock)
{
    int r;
    struct mailbox mailbox;
    int i, len, thisquota, thisquotalen;

    while (firstquota < quota_num &&
	   strncmp(name, quota[firstquota].quota.root,
		       strlen(quota[firstquota].quota.root)) > 0) {
	r = fixquota_finish(firstquota++);
	if (r) return r;
    }

    thisquota = -1;
    thisquotalen = 0;
    for (i = firstquota;
	 i < quota_num && strcmp(name, quota[i].quota.root) >= 0; i++) {
	len = strlen(quota[i].quota.root);
	if (!strncmp(name, quota[i].quota.root, len) &&
	    (!name[len] || name[len] == '.')) {
	    quota[i].refcount++;
	    if (len > thisquotalen) {
		thisquota = i;
		thisquotalen = len;
	    }
	}
    }

    if (partial && thisquota == -1) return 0;

    r = mailbox_open_header(name, 0, &mailbox);
    if (r) return r;

    if (thisquota == -1) {
	if (mailbox.quota.root) {
	    r = fixquota_fixroot(&mailbox, (char *)0);
	    if (r) {
		mailbox_close(&mailbox);
		return r;
	    }
	}
	mailbox_close(&mailbox);
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
    
    if (quota[thisquota].quota.fd == -1) {
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
	
int fixquota_fixroot(struct mailbox *mailbox,
		     char *root)
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
	if (quota[i].quota.fd != -1) {
	    close(quota[i].quota.fd);
	    quota[i].quota.fd = -1;
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
	mailbox->quota.root = xstrdup(root);
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
int fixquota_finish(int thisquota)
{
    int r;

    if (!quota[thisquota].refcount) {
	if (!quota[thisquota].deleted++) {
	    char buf[MAX_MAILBOX_PATH+1];
	    
	    printf("%s: removed\n", quota[thisquota].quota.root);
	    mailbox_hash_quota(buf, sizeof(buf), quota[thisquota].quota.root);

	    unlink(buf);
	}
	return 0;
    }

    if (quota[thisquota].quota.fd == -1) {
	r = mailbox_lock_quota(&quota[thisquota].quota);
	if (r) {
	    if (quota[thisquota].quota.fd != -1) {
		close(quota[thisquota].quota.fd);
		quota[thisquota].quota.fd = -1;
	    }
	    return r;
	}
    }
    
    if (quota[thisquota].quota.used != quota[thisquota].newused) {
	printf("%s: usage was %lu, now %lu\n", quota[thisquota].quota.root,
	       quota[thisquota].quota.used, quota[thisquota].newused);
	quota[thisquota].quota.used = quota[thisquota].newused;
	r = mailbox_write_quota(&quota[thisquota].quota);
	if (r) return r;
    }

    close(quota[thisquota].quota.fd);
    quota[thisquota].quota.fd = -1;
    return 0;
}


/*
 * Fix all the quota roots
 */
int fixquota(int ispartial)
{
    int r = 0;
    static char pattern[2] = "*";

    /*
     * Lock mailbox list to prevent mailbox creation/deletion
     * during the fix
     */
    mboxlist_open(NULL);

    redofix = 1;
    while (redofix) {
	redofix = 0;
	firstquota = 0;
	partial = ispartial;

	r = (*quota_namespace.mboxlist_findall)(&quota_namespace, pattern, 1,
						0, 0, fixquota_mailbox, NULL);
	if (r) {
	    mboxlist_close();
	    return r;
	}

	while (firstquota < quota_num) {
	    r = fixquota_finish(firstquota++);
	    if (r) {
		mboxlist_close();
		return r;
	    }
	}
    }
    
    mboxlist_close();
    return 0;
}
    
/*
 * Print out the quota report
 */
void
reportquota(void)
{
    int i;
    char buf[MAX_MAILBOX_PATH];

    printf("   Quota  %% Used    Used Root\n");

    for (i = 0; i < quota_num; i++) {
	if (quota[i].deleted) continue;
	if (quota[i].quota.limit > 0) {
	    printf(" %7d %7ld", quota[i].quota.limit,
		   ((quota[i].quota.used / QUOTA_UNITS) * 100) / quota[i].quota.limit);
	}
	else if (quota[i].quota.limit == 0) {
	    printf("       0        ");
	}
	else {
	    printf("                ");
	}
	/* Convert internal name to external */
	(*quota_namespace.mboxname_toexternal)(&quota_namespace,
					       quota[i].quota.root,
					       "cyrus", buf);
	printf(" %7ld %s\n", quota[i].quota.used / QUOTA_UNITS, buf);
    }
}
