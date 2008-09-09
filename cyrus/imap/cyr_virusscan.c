/* cyr_virusscan.c - scan mailboxes for infected messages and remove them
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
 * $Id: cyr_virusscan.c,v 1.1 2008/09/09 15:28:25 murch Exp $
 */

#include <config.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <syslog.h>
#include <string.h>
#include <netinet/in.h>

/* cyrus includes */
#include "global.h"
#include "sysexits.h"
#include "exitcodes.h"
#include "imap_err.h"
#include "mailbox.h"
#include "xmalloc.h"
#include "mboxlist.h"
#include "util.h"
#include "sync_log.h"

#define HAVE_CLAMAV

#ifdef HAVE_CLAMAV
#include <clamav.h>
#endif

/* config.c stuff */
const int config_need_data = CONFIG_NEED_PARTITION_DATA;

/* globals for getopt routines */
extern char *optarg;
extern int  optind;
extern int  opterr;
extern int  optopt;

/* globals for callback functions */
int disinfect = 0;

#ifdef HAVE_CLAMAV
struct cl_engine *av_engine = NULL;
struct cl_limits av_limits;
void init_clamav();
void destroy_clamav();
#endif

/* for statistical purposes */
typedef struct mbox_stats_s {

    int total;         /* total including those deleted */
    int total_bytes;
    int deleted;       
    int deleted_bytes;

} mbox_stats_t;

/* current namespace */
static struct namespace scan_namespace;

int verbose = 1;

int scan_me(char *, int, int);
unsigned virus_check(struct mailbox *, void *, unsigned char *, int);
int usage(char *name);
void print_stats(mbox_stats_t *stats);

int main (int argc, char *argv[]) {
    int option;		/* getopt() returns an int */
    char buf[MAX_MAILBOX_PATH+1];
    char *alt_config = NULL;
    int r;

    if ((geteuid()) == 0 && (become_cyrus() != 0)) {
	fatal("must run as the Cyrus user", EC_USAGE);
    }

    while ((option = getopt(argc, argv, "C:r")) != EOF) {
	switch (option) {
	case 'C': /* alt config file */
	    alt_config = optarg;
	    break;

	case 'r':
	    disinfect = 1;
	    break;

	case 'h':
	default: usage(argv[0]);
	}
    }

    cyrus_init(alt_config, "cyr_virusscan", 0);

#ifdef HAVE_CLAMAV
    init_clamav();
#endif

    /* Set namespace -- force standard (internal) */
    if ((r = mboxname_init_namespace(&scan_namespace, 1)) != 0) {
	syslog(LOG_ERR, error_message(r));
	fatal(error_message(r), EC_CONFIG);
    }

    mboxlist_init(0);
    mboxlist_open(NULL);

    /* open the quota db, we'll need it for expunge */
    quotadb_init(0);
    quotadb_open(NULL);

    sync_log_init();

    if (optind == argc) { /* do the whole partition */
	strcpy(buf, "*");
	(*scan_namespace.mboxlist_findall)(&scan_namespace, buf, 1, 0, 0,
					   scan_me, NULL);
    } else {
	for (; optind < argc; optind++) {
	    strncpy(buf, argv[optind], MAX_MAILBOX_NAME);
	    /* Translate any separators in mailboxname */
	    mboxname_hiersep_tointernal(&scan_namespace, buf,
					config_virtdomains ?
					strcspn(buf, "@") : 0);
	    (*scan_namespace.mboxlist_findall)(&scan_namespace, buf, 1, 0, 0,
					       scan_me, NULL);
	}
    }
    quotadb_close();
    quotadb_done();

    mboxlist_close();
    mboxlist_done();

#ifdef HAVE_CLAMAV
    destroy_clamav();
#endif

    cyrus_done();

    return 0;
}

int usage(char *name)
{
    printf("usage: %s [-C <alt_config>] [-r]\n\t[mboxpattern1 ... [mboxpatternN]]\n", name);
    printf("\tif no mboxpattern is given %s works on all mailboxes\n", name);
    printf("\t -r remove infected messages\n");
    exit(0);
}

#ifdef HAVE_CLAMAV
void init_clamav()
{
    unsigned int sigs = 0;
    int r;

    /* load all available databases from default directory */
    if ((r = cl_load(cl_retdbdir(), &av_engine, &sigs, CL_DB_STDOPT))) {
	syslog(LOG_ERR, "cl_load: %s", cl_strerror(r));
	fatal(cl_strerror(r), EC_SOFTWARE);
    }

    printf("Loaded %d virus signatures.\n", sigs);

    /* build av_engine */
    if((r = cl_build(av_engine))) {
	syslog(LOG_ERR,
	       "Database initialization error: %s", cl_strerror(r));
	cl_free(av_engine);
	fatal(cl_strerror(r), EC_SOFTWARE);
    }

    /* set up archive av_limits */
    memset(&av_limits, 0, sizeof(struct cl_limits));
    av_limits.maxfiles = 10000; /* max files */
    av_limits.maxscansize = 100 * 1048576; /* during the scanning of archives
					    * this size (100 MB) will never be
					    * exceeded
					    */
    av_limits.maxfilesize = 10 * 1048576; /* compressed files will only be
					   * decompressed and scanned up to this
					   * size (10 MB)
					   */
    av_limits.maxreclevel = 16; /* maximum recursion level for archives */
}

void destroy_clamav()
{
    if (av_engine) {
	/* free memory */
	cl_free(av_engine);
    }
}
#endif /* HAVE_CLAMAV */

/* we don't check what comes in on matchlen and maycreate, should we? */
int scan_me(char *name, int matchlen __attribute__((unused)),
	    int maycreate __attribute__((unused))) {
    struct mailbox the_box;
    int            error;
    mbox_stats_t   stats;

    memset(&stats, '\0', sizeof(mbox_stats_t));

    if (verbose) {
	char mboxname[MAX_MAILBOX_NAME+1];

	/* Convert internal name to external */
	(*scan_namespace.mboxname_toexternal)(&scan_namespace, name,
					     "cyrus", mboxname);
	printf("Working on %s...\n", mboxname);
    }

    error = mailbox_open_header(name, 0, &the_box);
    if (error != 0) { /* did we find it? */
	syslog(LOG_ERR, "Couldn't find %s, check spelling", name);
	return 0;
    }
    if (the_box.header_fd != -1) {
	(void) mailbox_lock_header(&the_box);
    }
    the_box.header_lock_count = 1;

    error = mailbox_open_index(&the_box);
    if (error != 0) {
	mailbox_close(&the_box);
	syslog(LOG_ERR, "Couldn't open mailbox index for %s", name);
	return 0;
    }
    (void) mailbox_lock_index(&the_box);
    the_box.index_lock_count = 1;

    mailbox_expunge(&the_box, virus_check, &stats, EXPUNGE_FORCE);

    sync_log_mailbox(the_box.name);
    mailbox_close(&the_box);

    if (disinfect) print_stats(&stats);

    return 0;
}

void deleteit(bit32 msgsize, mbox_stats_t *stats)
{
    stats->deleted++;
    stats->deleted_bytes += msgsize;
}

/* thumbs up routine, checks for virus and returns yes or no for deletion */
/* 0 = no, 1 = yes */
unsigned virus_check(struct mailbox *mailbox __attribute__((unused)),
		     void *deciderock,
		     unsigned char *buf,
		     int expunge_flags __attribute__((unused)))
{
    mbox_stats_t *stats = (mbox_stats_t *) deciderock;
    bit32 senttime;
    bit32 msgsize;
    bit32 flagged;

    senttime = ntohl(*((bit32 *)(buf + OFFSET_SENTDATE)));
    msgsize = ntohl(*((bit32 *)(buf + OFFSET_SIZE)));
    flagged = ntohl(*((bit32 *)(buf + OFFSET_SYSTEM_FLAGS))) & FLAG_FLAGGED;

    stats->total++;
    stats->total_bytes += msgsize;

#ifdef HAVE_CLAMAV
    if (av_engine) {
	int r;
	char fname[4096];
	const char *virname;
	unsigned long uid = ntohl(*((bit32 *)(buf+OFFSET_UID)));

	snprintf(fname, sizeof(fname), "%s/%lu.", mailbox->path, uid);

	/* scan file */
	r = cl_scanfile(fname, &virname, NULL, av_engine, &av_limits,
			CL_SCAN_STDOPT);

	switch (r) {
	case CL_CLEAN:
	    /* do nothing */
	    break;
	case CL_VIRUS:
	    if (verbose) {
		printf("Virus detected in message %lu: %s\n", uid, virname);
	    }
	    if (disinfect) {
		deleteit(msgsize, stats);
		return 1;
	    }
	    break;

	default:
	    printf("cl_scanfile error: %s\n", cl_strerror(r));
	    syslog(LOG_ERR, "cl_scanfile error: %s\n", cl_strerror(r));
	    break;
	}
    }
#endif

    return 0;
}

void print_stats(mbox_stats_t *stats)
{
    printf("total messages    \t\t %d\n",stats->total);
    printf("total bytes       \t\t %d\n",stats->total_bytes);
    printf("Deleted messages  \t\t %d\n",stats->deleted);
    printf("Deleted bytes     \t\t %d\n",stats->deleted_bytes);
    printf("Remaining messages\t\t %d\n",stats->total - stats->deleted);
    printf("Remaining bytes   \t\t %d\n",
	   stats->total_bytes - stats->deleted_bytes);
}
