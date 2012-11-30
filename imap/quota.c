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
#include <sys/poll.h>

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
#include "imap/imap_err.h"
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

struct quotaentry {
    char *name;
    int refcount;
    int deleted;
};

/* forward declarations */
static void usage(void);
static void reportquota(void);
static int buildquotalist(char *domain, char **roots, int nroots);
static int fixquotas(char *domain, char **roots, int nroots);
static int fixquota_dopass(char *domain, char **roots, int nroots,
			   foreach_cb *pass);
static int fixquota_dombox(void *rock, const char *name, size_t namelen,
			  const char *val, size_t vallen);
static int fixquota_fixroot(struct mailbox *mailbox, const char *root);
static int fixquota_finish(int thisquota);
static int (*compar)(const char *s1, const char *s2);

#define QUOTAGROW 300

static struct quotaentry *quotaroots;
static int quota_num = 0, quota_alloc = 0;
static int quota_todo = 0;

static int test_sync_mode = 0;

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

    while ((opt = getopt(argc, argv, "C:d:fqZ")) != EOF) {
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

	/* deliberately undocumented option for testing */
	case 'Z':
	    test_sync_mode = 1;
	    break;

	default:
	    usage();
	}
    }

    /* always report if not fixing, otherwise we do nothing */
    if (!fflag)
	do_report = 1;

    cyrus_init(alt_config, "quota", 0, CONFIG_NEED_PARTITION_DATA);

    /* Set namespace -- force standard (internal) */
    if ((r = mboxname_init_namespace(&quota_namespace, 1)) != 0) {
	syslog(LOG_ERR, "%s", error_message(r));
	fatal(error_message(r), EC_CONFIG);
    }

    if (config_getswitch(IMAPOPT_IMPROVED_MBOXLIST_SORT))
	compar = bsearch_compare_mbox;
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

    quota_changelock();

    if (!r)
	r = buildquotalist(domain, argv+optind, argc-optind);

    if (!r && fflag)
	r = fixquotas(domain, argv+optind, argc-optind);

    quota_changelockrelease();

    if (r) code = convert_code(r);
    else if (do_report) reportquota();

    quotadb_close();
    quotadb_done();

    mboxlist_close();
    mboxlist_done();

    /* just for neatness */
    for (i = 0; i < quota_num; i++)
	free(quotaroots[i].name);
    free(quotaroots);

    cyrus_done();

    return code;
}

static void usage(void)
{
    fprintf(stderr,
	    "usage: quota [-C <alt_config>] [-d <domain>] [-f] [-q] [prefix]...\n");
    exit(EC_USAGE);
}

static void errmsg(const char *fmt, const char *arg, int err)
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

static void test_sync_wait(const char *mboxname)
{
    char *filename;
    struct stat sb;
    clock_t start;
    int status = 0;
    int r;
#define TIMEOUT	    (30 * CLOCKS_PER_SEC)

    if (!test_sync_mode)
	return;
    /* aha, we're in test synchronisation mode */

    syslog(LOG_ERR, "quota -Z waiting for signal to do %s", mboxname);

    filename = strconcat(config_dir, "/quota-sync/", mboxname, (char *)NULL);
    start = sclock();

    while ((r = stat(filename, &sb)) < 0 && errno == ENOENT) {
	if (sclock() - start > TIMEOUT) {
	    status = 2;
	    break;
	}
	status = 1;
	poll(NULL, 0, 20);  /* try again in 20 millisec */
    }

    switch (status)
    {
    case 0:
	syslog(LOG_ERR, "quota -Z did not wait");
	break;
    case 1:
	syslog(LOG_ERR, "quota -Z waited %2.3f sec",
			 (sclock() - start) / (double) CLOCKS_PER_SEC);
	break;
    case 2:
	syslog(LOG_ERR, "quota -Z timed out");
	break;
    }

    free(filename);
#undef TIMEOUT
}

static void test_sync_done(const char *mboxname)
{
    char *filename;

    if (!test_sync_mode)
	return;
    /* aha, we're in test synchronisation mode */

    syslog(LOG_ERR, "quota -Z done with %s", mboxname);

    filename = strconcat(config_dir, "/quota-sync/", mboxname, (char *)NULL);
    unlink(filename);
    free(filename);
}


/*
 * A quotaroot was found, add it to our list
 */
static int fixquota_addroot(struct quota *q,
			    void *rock)
{
    const char *prefix = (const char *)rock;
    int prefixlen = (prefix ? strlen(prefix) : 0);
    struct quota localq;
    struct txn *tid = NULL;
    int r;

    assert(prefixlen <= (int)strlen(q->root));
    if (prefixlen && q->root[prefixlen] && q->root[prefixlen] != '.')
	return 0;

    if (quota_num == quota_alloc) {
	/* Create new qr list entry */
	quota_alloc += QUOTAGROW;
	quotaroots = (struct quotaentry *)
	    xrealloc((char *)quotaroots, quota_alloc * sizeof(struct quotaentry));
	memset(&quotaroots[quota_num], 0, QUOTAGROW * sizeof(struct quotaentry));
    }

    quotaroots[quota_num].name = xstrdup(q->root);

    /* get a locked read */
    quota_init(&localq, quotaroots[quota_num].name);
    r = quota_read(&localq, &tid, 1);
    if (r) {
	errmsg("failed reading quota record for '%s'",
	       q->root, r);
	goto done;
    }

    /* clean the scanused data if present */
    if (localq.scanmbox) {
	free(localq.scanmbox);
	localq.scanmbox = NULL;

	r = quota_write(&localq, &tid);
	if (r) {
	    errmsg("failed writing quota record for '%s'",
		   q->root, r);
	    goto done;
	}
    }

done:
    quota_free(&localq);
    if (r) {
	quota_abort(&tid);
	free(quotaroots[quota_num].name);
	quotaroots[quota_num].name = NULL;
    }
    else {
	quota_commit(&tid);
	quota_num++;
    }

    return r;
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
	r = quota_foreach(buf, fixquota_addroot, buf, NULL);
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

	r = quota_foreach(buf, fixquota_addroot, buf, NULL);
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

    for (i = quota_todo; i < quota_num; i++) {
	const char *root = quotaroots[i].name;

	/* have we already passed the name, then there can
	 * be no further matches */
	if (compar(root, name) > 0)
	    break;

	/* is the mailbox within this root? */
	if (mboxname_is_prefix(name, root)) {
	    /* fantastic, but don't return yet, we may find
	     * a more exact match */
	    *thisquota = i;
	}
    }

    if (*thisquota >= 0)
	quotaroots[*thisquota].refcount++;

    return 0;
}

/*
 * Pass 2: account for mailbox 'name' when fixing the quota roots
 */
static int fixquota_dombox(void *rock,
			   const char *name, size_t namelen,
			   const char *val __attribute__((unused)),
			   size_t vallen __attribute__((unused)))
{
    int r = 0;
    const char *prefix = (const char *)rock;
    size_t prefixlen = (prefix ? strlen(prefix) : 0);
    struct mailbox *mailbox = NULL;
    int thisquota = -1;
    char *mboxname = xstrndup(name, namelen);
    struct txn *txn = NULL;

    assert(prefixlen <= namelen);
    if (prefixlen && mboxname[prefixlen] && mboxname[prefixlen] != '.') goto done;

    while (quota_todo < quota_num) {
	const char *root = quotaroots[quota_todo].name;

	/* in the future, definitely don't close yet */
	if (compar(mboxname, root) < 0)
	    break;

	/* inside the first root, don't close yet */
	if (mboxname_is_prefix(mboxname, root))
	    break;

	/* finished, close out now */
	r = fixquota_finish(quota_todo);
	quota_todo++;
	if (r) goto done;
    }

    test_sync_wait(mboxname);

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
	    r = fixquota_fixroot(mailbox, NULL);
	    if (r) goto done;
	}
    }
    else {
	const char *root = quotaroots[thisquota].name;
	quota_t useds[QUOTA_NUMRESOURCES];
	struct quota localq;
	int res;

	/* matching quotaroot exists, ensure mailbox has the
	 * correct root */
	if (!mailbox->quotaroot ||
	    strcmp(mailbox->quotaroot, root) != 0) {
	    r = fixquota_fixroot(mailbox, root);
	    if (r) goto done;
	}

	/* read the current data */
	quota_init(&localq, root);
	r = quota_read(&localq, &txn, 1);
	if (r) goto done;

	/* add the usage for this mailbox */
	mailbox_get_usage(mailbox, useds);
	for (res = 0; res < QUOTA_NUMRESOURCES; res++)
	    localq.scanuseds[res] += useds[res];

	/* and mention that this mailbox has been scanned */
	free(localq.scanmbox);
	localq.scanmbox = xstrdup(mboxname);

	r = quota_write(&localq, &txn);
	quota_free(&localq);

	if (r) {
	    quota_abort(&txn);
	    goto done;
	}

	quota_commit(&txn);
    }

done:
    mailbox_close(&mailbox);
    test_sync_done(mboxname);
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
 * Pass 3: finish fixing up a quota root
 */
int fixquota_finish(int thisquota)
{
    int res;
    int r = 0;
    struct txn *tid = NULL;
    const char *root = quotaroots[thisquota].name;
    struct quota localq;

    if (!quotaroots[thisquota].refcount) {
	quotaroots[thisquota].deleted = 1;
	printf("%s: removed\n", root);
	r = quota_deleteroot(root);
	if (r) {
	    errmsg("failed deleting quotaroot '%s'", root, r);
	}
	return r;
    }

    /* re-read the quota with the record locked */
    quota_init(&localq, root);
    r = quota_read(&localq, &tid, 1);
    if (r) {
	errmsg("failed reading quotaroot '%s'", root, r);
	goto done;
    }

    /* is it different? */
    for (res = 0; res < QUOTA_NUMRESOURCES; res++) {
	if (localq.scanuseds[res] != localq.useds[res]) {
	    printf("%s: %s usage was " QUOTA_T_FMT ", now " QUOTA_T_FMT "\n",
		root,
		quota_names[res],
		localq.useds[res],
		localq.scanuseds[res]);
	    localq.useds[res] = localq.scanuseds[res];
	}
    }

    /* remove the scanned data, we're now up-to-date */
    free(localq.scanmbox);
    localq.scanmbox = NULL;

    r = quota_write(&localq, &tid);
    if (r) {
	errmsg("failed writing quotaroot: '%s'", root, r);
	goto done;
    }

done:
    quota_free(&localq);

    if (r) quota_abort(&tid);
    else quota_commit(&tid);

    return r;
}

/*
 * Run a pass over all the quota roots
 */
int fixquota_dopass(char *domain, char **roots, int nroots,
		    foreach_cb *cb)
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
	r = mboxlist_allmbox(buf, cb, buf);
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

	r = mboxlist_allmbox(buf, cb, buf);
	if (r) {
	    errmsg("processing mbox list for '%s'", buf, IMAP_IOERROR);
	    break;
	}
    }

    return r;
}

/*
 * Fix all the quota roots
 */
int fixquotas(char *domain, char **roots, int nroots)
{
    int r;

    r = fixquota_dopass(domain, roots, nroots, fixquota_dombox);

    while (!r && quota_todo < quota_num) {
	r = fixquota_finish(quota_todo);
	quota_todo++;
    }

    return r;
}

static void reportquota_resource(struct quota * quota, const char *root, int res)
{
    if (quota->limits[res] > 0) {
	printf(" %7" PRIdMAX " %8" PRIdMAX, (intmax_t)quota->limits[res],
	    (intmax_t)((((intmax_t)quota->useds[res] / quota_units[res])
	    * 100) / quota->limits[res]));
    }
    else if (quota->limits[res] == 0) {
	printf("       0         ");
    }
    else {
	printf("                 ");
    }
    printf(" %8" PRIdMAX " %20s %s\n",
	(intmax_t)((intmax_t)quota->useds[res] / quota_units[res]),
	quota_names[res], root);
}

/*
 * Print out the quota report
 */
static void reportquota(void)
{
    int i;
    int res;

    printf("   Quota   %% Used     Used             Resource Root\n");

    for (i = 0; i < quota_num; i++) {
	struct quota localq;
	int r;

	if (quotaroots[i].deleted) continue;

	/* XXX - cache these from either the parse or the commit again */
	quota_init(&localq, quotaroots[i].name);
	r = quota_read(&localq, NULL, 0);
	if (r) {
	    quota_free(&localq);
	    return;
	}

	for (res = 0; res < QUOTA_NUMRESOURCES; res++) {
	    reportquota_resource(&localq, quotaroots[i].name, res);
	}

	quota_free(&localq);
    }
}
