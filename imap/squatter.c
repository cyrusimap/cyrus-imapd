/* squatter.c -- SQUAT-based message indexing tool
 *
 * Copyright (c) 1994-2012 Carnegie Mellon University.  All rights reserved.
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
 */

/*
  This is the tool that creates/updates search indexes for Cyrus mailboxes.

  Despite the name, it handles whichever search engine in configured
  by the 'search_engine' option in imapd.conf.
*/

#include <config.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <syslog.h>
#include <string.h>

#include "annotate.h"
#include "assert.h"
#include "mboxlist.h"
#include "global.h"
#include "exitcodes.h"
#include "imap/imap_err.h"
#include "search_engines.h"
#include "mailbox.h"
#include "xmalloc.h"
#include "xstrlcpy.h"
#include "xstrlcat.h"
#include "seen.h"
#include "mboxname.h"
#include "index.h"
#include "message.h"
#include "util.h"

extern char *optarg;
extern int optind;

/* current namespace */
static struct namespace squat_namespace;

const int SKIP_FUZZ = 60;

static int verbose = 0;
static int skip_unmodified = 0;
static int incremental_mode = 0;
static int recursive_flag = 0;
static int annotation_flag = 0;
static search_text_receiver_t *rx = NULL;

static int usage(const char *name)
{
    fprintf(stderr,
	    "usage: %s [-C <alt_config>] [-r] [-s] [-a] [-v] [mailbox...]\n",
	    name);
 
    exit(EC_USAGE);
}

/* ====================================================================== */

/* Squat a single open mailbox */
static int squat_single(struct index_state *state, int incremental)
{
    uint32_t msgno;
    message_t *msg;
    int r = 0;			/* Using IMAP_* not SQUAT_* return codes here */

    r = rx->begin_mailbox(rx, state->mailbox, incremental);
    if (r) goto out;

    for (msgno = 1; msgno <= state->exists; msgno++) {
	uint32_t uid = index_getuid(state, msgno);

	if (rx->is_indexed(rx, uid))
	    continue;

	/* This UID didn't appear in the old index file */
	msg = index_get_message(state, msgno);
	index_getsearchtext(msg, rx);
	message_unref(&msg);
    }

    r = rx->end_mailbox(rx, state->mailbox);
out:
    return (r);
}

/* This is called once for each mailbox we're told to index. */
static int index_one(const char *name)
{
    mbentry_t *mbentry = NULL;
    struct index_state *state = NULL;
    int r;
    const char *fname;
    struct stat sbuf;
    char extname[MAX_MAILBOX_BUFFER];

    /* Convert internal name to external */
    (*squat_namespace.mboxname_toexternal)(&squat_namespace, name,
					   NULL, extname);

    /* Skip remote mailboxes */
    r = mboxlist_lookup(name, &mbentry, NULL);
    if (r) {
        if (verbose) {
            printf("error opening looking up %s: %s\n",
		   extname, error_message(r));
        }
        syslog(LOG_INFO, "error opening looking up %s: %s\n",
               extname, error_message(r));

        return 1;
    }
    if (mbentry->mbtype & MBTYPE_REMOTE) {
	mboxlist_entry_free(&mbentry);
	return 0;
    }

    mboxlist_entry_free(&mbentry);

    /* make sure the mailbox (or an ancestor) has
       /vendor/cmu/cyrus-imapd/squat set to "true" */
    if (annotation_flag) {
	char buf[MAX_MAILBOX_BUFFER] = "", *p;
	struct buf attrib = BUF_INITIALIZER;
	int domainlen = 0;

	if (config_virtdomains && (p = strchr(name, '!')))
	    domainlen = p - name + 1;

	strlcpy(buf, name, sizeof(buf));

	/* since mailboxes inherit /vendor/cmu/cyrus-imapd/squat,
	   we need to iterate all the way up to "" (server entry) */
	while (1) {
	    r = annotatemore_lookup(buf, "/vendor/cmu/cyrus-imapd/squat", "",
				    &attrib);

	    if (r ||				/* error */
		attrib.s ||			/* found an entry */
		!buf[0]) {			/* done recursing */
		break;
	    }

	    p = strrchr(buf, '.');		/* find parent mailbox */

	    if (p && (p - buf > domainlen))	/* don't split subdomain */
		*p = '\0';
	    else if (!buf[domainlen])		/* server entry */
		buf[0] = '\0';
	    else				/* domain entry */
		buf[domainlen] = '\0';
	}

	if (r || !attrib.s || strcasecmp(attrib.s, "true")) {
	    buf_free(&attrib);
	    return 0;
	}
	buf_free(&attrib);
    }

    r = index_open(name, NULL, &state);
    if (r) {
        if (verbose) {
            printf("error opening %s: %s\n", extname, error_message(r));
        }
        syslog(LOG_INFO, "error opening %s: %s\n", extname, error_message(r));

        return 1;
    }

    fname = mailbox_meta_fname(state->mailbox, META_SQUAT);

    /* process only changed mailboxes if skip option delected. */
    if (skip_unmodified && !stat(fname, &sbuf)) {
        if (SKIP_FUZZ + state->mailbox->index_mtime < sbuf.st_mtime) {
            syslog(LOG_DEBUG, "skipping mailbox %s", extname);
            if (verbose > 0) {
                printf("Skipping mailbox %s\n", extname);
            }
            index_close(&state);
            return 0;
        }
    }

    syslog(LOG_INFO, "indexing mailbox %s... ", extname);
    if (verbose > 0) {
      printf("Indexing mailbox %s... ", extname);
    }

    squat_single(state, incremental_mode);

    index_close(&state);

    return 0;
}

static int addmbox(char *name,
		   int matchlen __attribute__((unused)),
		   int maycreate __attribute__((unused)),
		   void *rock)
{
    strarray_t *sa = (strarray_t *) rock;
    strarray_append(sa, name);
    return 0;
}

static void do_indexer(int nmboxnames, const char **mboxnames)
{
    int i;
    strarray_t sa = STRARRAY_INITIALIZER;
    char buf[MAX_MAILBOX_PATH + 1];

    rx = search_begin_update(verbose);
    if (rx == NULL)
	return;	/* no indexer defined */

    if (!nmboxnames) {
	assert(!recursive_flag);
	strlcpy(buf, "*", sizeof(buf));
	(*squat_namespace.mboxlist_findall) (&squat_namespace, buf, 1,
					     0, 0, addmbox, &sa);
    }

    for (i = 0; i < nmboxnames; i++) {
	/* Translate any separators in mailboxname */
	(*squat_namespace.mboxname_tointernal) (&squat_namespace,
						mboxnames[i], NULL, buf);
	strarray_append(&sa, buf);
	if (recursive_flag) {
	    strlcat(buf, ".*", sizeof(buf));
	    (*squat_namespace.mboxlist_findall) (&squat_namespace, buf, 1,
						 0, 0, addmbox, &sa);
	}
    }

    for (i = 0 ; i < sa.count ; i++) {
	index_one(sa.data[i]);
	/* Ignore errors: most will be mailboxes moving around */
    }

    search_end_update(rx);

    strarray_fini(&sa);
}


int main(int argc, char **argv)
{
    int opt;
    char *alt_config = NULL;
    int r;

    if ((geteuid()) == 0 && (become_cyrus(/*is_master*/0) != 0)) {
	fatal("must run as the Cyrus user", EC_USAGE);
    }

    setbuf(stdout, NULL);

    while ((opt = getopt(argc, argv, "C:rsiav")) != EOF) {
	switch (opt) {
	case 'C':		/* alt config file */
	    alt_config = optarg;
	    break;

	case 'v':		/* verbose */
	    verbose++;
	    break;

	case 'r':		/* recurse */
	    recursive_flag = 1;
	    break;

	case 's':		/* skip unmodifed */
	    skip_unmodified = 1;
	    break;

	case 'i':		/* incremental mode */
	    incremental_mode = 1;
	    break;

	case 'a':		/* use /squat annotation */
	    annotation_flag = 1;
	    break;

	default:
	    usage("squatter");
	}
    }

    cyrus_init(alt_config, "squatter", 0, CONFIG_NEED_PARTITION_DATA);

    syslog(LOG_NOTICE, "indexing mailboxes");

    /* Set namespace -- force standard (internal) */
    if ((r = mboxname_init_namespace(&squat_namespace, 1)) != 0) {
	fatal(error_message(r), EC_CONFIG);
    }

    annotate_init(NULL, NULL);
    annotatemore_open();

    mboxlist_init(0);
    mboxlist_open(NULL);

    /* -r requires at least one mailbox */
    if (recursive_flag && optind == argc) usage(argv[0]);
    do_indexer(argc-optind, (const char **)argv+optind);
    syslog(LOG_NOTICE, "done indexing mailboxes");

    seen_done();
    mboxlist_close();
    mboxlist_done();
    annotatemore_close();
    annotate_done();

    cyrus_done();

    return 0;
}
