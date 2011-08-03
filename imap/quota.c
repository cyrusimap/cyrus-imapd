/* quota.c -- program to report/reconstruct quotas
 *
 * Copyright (c) 1994-2008 Carnegie Mellon University.  All rights reserved.
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
 *    prior written permission. For permission or any legal
 *    details, please contact
 *      Carnegie Mellon University
 *      Center for Technology Transfer and Enterprise Creation
 *      4615 Forbes Avenue
 *      Suite 302
 *      Pittsburgh, PA  15213
 *      (412) 268-7393, fax: (412) 268-7395
 *      innovation@andrew.cmu.edu
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
 * $Id: quota.c,v 1.72 2010/01/06 17:01:39 murch Exp $
 */

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
#include "bsearch.h"
#include "cyrusdb.h"
#include "global.h"
#include "exitcodes.h"
#include "imap_err.h"
#include "mailbox.h"
#include "xmalloc.h"
#include "xstrlcpy.h"
#include "xstrlcat.h"
#include "mboxlist.h"
#include "mboxname.h"
#include "quota.h"
#include "convert_code.h"
#include "util.h"

extern int optind;
extern char *optarg;

/* current namespace */
static struct namespace quota_namespace;

/* config.c stuff */
const int config_need_data = CONFIG_NEED_PARTITION_DATA;

struct quotaentry {
    struct quota quota;
    char *allocname;
    int refcount;
    int deleted;
    uquota_t newused;
};

/* forward declarations */
void usage(void);
void reportquota(void);
static int buildquotalist(char *domain, char **roots, int nroots);
static int fixquotas(char *domain, char **roots, int nroots);
static int fixquota_mailbox(void *rock, const char *name, int namelen,
			    const char *val, int vallen);
static int fixquota_fixroot(struct mailbox *mailbox, const char *root);
static int fixquota_finish(int thisquota);
static int (*compar)(const char *s1, const char *s2);

#define QUOTAGROW 300

struct quotaentry *quota;
int quota_num = 0, quota_alloc = 0;

int firstquota = 0;
int redofix = 0;

int main(int argc,char **argv)
{
    int opt;
    int i;
    int fflag = 0;
    int r, code = 0;
    int do_report = 1;
    char *alt_config = NULL, *domain = NULL;

    if ((geteuid()) == 0 && (become_cyrus() != 0)) {
	fatal("must run as the Cyrus user", EC_USAGE);
    }

    while ((opt = getopt(argc, argv, "C:d:fq")) != EOF) {
	switch (opt) {
	case 'C': /* alt config file */
	    alt_config = optarg;
	    break;

	case 'q':
	    do_report = 0;
	    break;

	case 'd':
	    domain = optarg;
	    break;

	case 'f':
	    fflag = 1;
	    break;

	default:
	    usage();
	}
    }

    /* always report if not fixing, otherwise we do nothing */
    if (!fflag)
	do_report = 1;

    cyrus_init(alt_config, "quota", 0);

    /* Set namespace -- force standard (internal) */
    if ((r = mboxname_init_namespace(&quota_namespace, 1)) != 0) {
	syslog(LOG_ERR, "%s", error_message(r));
	fatal(error_message(r), EC_CONFIG);
    }

    if (config_getswitch(IMAPOPT_IMPROVED_MBOXLIST_SORT))
	compar = bsearch_compare;
    else
	compar = strcmp;

    /*
     * Lock mailbox list to prevent mailbox creation/deletion
     * during work
     */
    mboxlist_init(0);
    mboxlist_open(NULL);

    quotadb_init(0);
    quotadb_open(NULL);

    r = buildquotalist(domain, argv+optind, argc-optind);

    if (!r && fflag)
	r = fixquotas(domain, argv+optind, argc-optind);

    quotadb_close();
    quotadb_done();

    mboxlist_close();
    mboxlist_done();

    if (r) code = convert_code(r);
    else if (do_report) reportquota();

    /* just for neatness */
    for (i = 0; i < quota_num; i++)
	free(quota[i].allocname);
    free(quota);

    cyrus_done();

    return code;
}

void usage(void)
{
    fprintf(stderr,
	    "usage: quota [-C <alt_config>] [-d <domain>] [-f] [-q] [prefix]...\n");
    exit(EC_USAGE);
}

void errmsg(const char *fmt, const char *arg, int err)
{
    char buf[1024];
    size_t len;

    len = snprintf(buf, sizeof(buf), fmt, arg);
    if (len < sizeof(buf))
	len += snprintf(buf+len, sizeof(buf)-len, ": %s", error_message(err));
    if ((err == IMAP_IOERROR) && (len < sizeof(buf)))
	len += snprintf(buf+len, sizeof(buf)-len, ": %s", strerror(errno));

    syslog(LOG_ERR, "%s", buf);
    fprintf(stderr, "%s\n", buf);
}

/*
 * A quotaroot was found, add it to our list
 */
static int fixquota_addroot(struct quota *q,
			    void *rock __attribute__((unused)))
{
    if (quota_num == quota_alloc) {
	/* Create new qr list entry */
	quota_alloc += QUOTAGROW;
	quota = (struct quotaentry *)
	    xrealloc((char *)quota, quota_alloc * sizeof(struct quotaentry));
	memset(&quota[quota_num], 0, QUOTAGROW * sizeof(struct quotaentry));
    }

    /* copy this quota */
    quota[quota_num].allocname   = xstrdup(q->root);
    quota[quota_num].quota.root  = quota[quota_num].allocname;
    quota[quota_num].quota.limit = q->limit;
    quota[quota_num].quota.used  = q->used;
    quota_num++;

    return 0;
}

/*
 * Build the list of quota roots in 'quota'
 */
int buildquotalist(char *domain, char **roots, int nroots)
{
    int i, r;
    char buf[MAX_MAILBOX_BUFFER], *tail;
    size_t domainlen = 0;

    buf[0] = '\0';
    tail = buf;
    if (domain) {
	domainlen = snprintf(buf, sizeof(buf), "%s!", domain);
	tail += domainlen;
    }

    /* basic case - everything (potentially limited by domain still) */
    if (!nroots) {
	r = quota_foreach(buf, fixquota_addroot, NULL);
	if (r) {
	    errmsg("failed building quota list for '%s'", buf, IMAP_IOERROR);
	}
    }

    /*
     * Walk through all given pattern(s) and add all the quota roots
     * with the matching prefixes.
     */
    for (i = 0; i < nroots; i++) {
	strlcpy(tail, roots[i], sizeof(buf) - domainlen);
	/* change the separator to internal namespace */
	mboxname_hiersep_tointernal(&quota_namespace, tail, 0);

	r = quota_foreach(buf, fixquota_addroot, NULL);
	if (r) {
	    errmsg("failed building quota list for '%s'", buf, IMAP_IOERROR);
	    break;
	}
    }

    return r;
}

static int findroot(const char *name, int *thisquota)
{
    int i;

    *thisquota = -1;

    for (i = firstquota; i < quota_num; i++) {
	const char *root = quota[i].quota.root;

	/* have we already passed the name, then there can
	 * be no further matches */
	if (compar(root, name) > 0)
	    return 0;

	/* is the mailbox within this root? */
	if (mboxname_is_prefix(name, root)) {
	    /* fantastic, but don't return yet, we may find
	     * a more exact match */
	    quota[i].refcount++;
	    *thisquota = i;
	}
	else {
	    /* not a match, so we can finish everything up to here */
	    while (firstquota < i) {
		int r = fixquota_finish(firstquota);
		if (r) return r;
		firstquota++;
	    }
	}
    }

    return 0;
}

/*
 * Account for mailbox 'name' when fixing the quota roots
 */
static int fixquota_mailbox(void *rock __attribute__((unused)),
			    const char *name, int namelen,
			    const char *val __attribute__((unused)),
			    int vallen __attribute__((unused)))
{
    int r = 0;
    struct mailbox *mailbox = NULL;
    int thisquota = -1;
    char *mboxname = xstrndup(name, namelen);

    r = findroot(mboxname, &thisquota);
    if (r) {
	errmsg("failed finding quotaroot for mailbox '%s'", name, r);
	goto done;
    }

    r = mailbox_open_iwl(mboxname, &mailbox);
    if (r) {
	errmsg("failed opening header for mailbox '%s'", name, r);
	goto done;
    }

    if (thisquota == -1) {
	/* no matching quotaroot exists, remove from
	 * mailbox if present */
	if (mailbox->quotaroot) {
	    r = fixquota_fixroot(mailbox, (char *)0);
	}
    }
    else {
	/* matching quotaroot exists, ensure mailbox has the
	 * correct root */
	if (!mailbox->quotaroot ||
	    strcmp(mailbox->quotaroot, quota[thisquota].quota.root) != 0) {
	    r = fixquota_fixroot(mailbox, quota[thisquota].quota.root);
	}

	/* and track the total usage inside this root */
	if (!r)
	    quota[thisquota].newused += mailbox->i.quota_mailbox_used;
    }

done:
    mailbox_close(&mailbox);
    free(mboxname);

    return r;
}

int fixquota_fixroot(struct mailbox *mailbox,
		     const char *root)
{
    int r;

    printf("%s: quota root %s --> %s\n", mailbox->name,
	   mailbox->quotaroot ? mailbox->quotaroot : "(none)",
	   root ? root : "(none)");

    r = mailbox_set_quotaroot(mailbox, root);
    if (r) errmsg("failed writing header for mailbox '%s'", mailbox->name, r);

    return r;
}

/*
 * Finish fixing up a quota root
 */
int fixquota_finish(int thisquota)
{
    int r = 0;
    struct txn *tid = NULL;

    if (!quota[thisquota].refcount) {
	printf("%s: removed\n", quota[thisquota].quota.root);
	r = quota_deleteroot(quota[thisquota].quota.root);
	if (r) {
	    errmsg("failed deleting quotaroot '%s'",
		   quota[thisquota].quota.root, r);
	}
	return r;
    }

    /* nothing changed, all good */
    if (quota[thisquota].quota.used == quota[thisquota].newused)
	return 0;

    /* re-read the quota with the record locked */
    r = quota_read(&quota[thisquota].quota, &tid, 1);
    if (r) {
	errmsg("failed reading quotaroot '%s'",
	       quota[thisquota].quota.root, r);
	return r;
    }

    /* is it still different? */
    if (quota[thisquota].quota.used != quota[thisquota].newused) {
	printf("%s: usage was " UQUOTA_T_FMT ", now " UQUOTA_T_FMT "\n",
	       quota[thisquota].quota.root,
	       quota[thisquota].quota.used, quota[thisquota].newused);
	quota[thisquota].quota.used = quota[thisquota].newused;
	r = quota_write(&quota[thisquota].quota, &tid);
	if (r) {
	    errmsg("failed writing quotaroot '%s'",
		   quota[thisquota].quota.root, r);
	    quota_abort(&tid);
	    return r;
	}
    }

    quota_commit(&tid);

    return 0;
}

/*
 * Fix all the quota roots
 */
int fixquotas(char *domain, char **roots, int nroots)
{
    int i, r;
    char buf[MAX_MAILBOX_BUFFER], *tail;
    size_t domainlen = 0;

    buf[0] = '\0';
    tail = buf;
    if (domain) {
	domainlen = snprintf(buf, sizeof(buf), "%s!", domain);
	tail += domainlen;
    }

    /* basic case - everything (potentially limited by domain still) */
    if (!nroots) {
	r = mboxlist_allmbox(buf, fixquota_mailbox, NULL);
	if (r) {
	    errmsg("processing mbox list for '%s'", buf, IMAP_IOERROR);
	}
    }

    /*
     * Walk through all given pattern(s) and add all the quota roots
     * with the matching prefixes.
     */
    for (i = 0; i < nroots; i++) {
	strlcpy(tail, roots[i], sizeof(buf) - domainlen);
	/* change the separator to internal namespace */
	mboxname_hiersep_tointernal(&quota_namespace, tail, 0);

	r = mboxlist_allmbox(buf, fixquota_mailbox, NULL);
	if (r) {
	    errmsg("processing mbox list for '%s'", buf, IMAP_IOERROR);
	    break;
	}
    }

    while (!r && firstquota < quota_num) {
	r = fixquota_finish(firstquota);
	firstquota++;
    }

    return r;
}

/*
 * Print out the quota report
 */
void reportquota(void)
{
    int i;
    char buf[MAX_MAILBOX_PATH+1];

    printf("   Quota   %% Used     Used Root\n");

    for (i = 0; i < quota_num; i++) {
	if (quota[i].deleted) continue;
	if (quota[i].quota.limit > 0) {
	    printf(" %7d " QUOTA_REPORT_FMT , quota[i].quota.limit,
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
	printf(" " QUOTA_REPORT_FMT " %s\n",
	       quota[i].quota.used / QUOTA_UNITS, buf);
    }
}
