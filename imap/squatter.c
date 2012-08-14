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
#include "tok.h"
#include "acl.h"
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
	    "usage: %s [-C <alt_config>] [-v] [-s] [-a] [mailbox...]\n",
	    name);
    fprintf(stderr,
	    "       %s [-C <alt_config>] [-v] [-s] [-a] -r mailbox [...]\n",
	    name);
    fprintf(stderr,
	    "       %s [-C <alt_config>] [-v] [-r] -e query mailbox [...]\n",
	    name);
    fprintf(stderr,
	    "       %s [-C <alt_config>] [-v] -c (start|stop) mailbox\n",
	    name);

    exit(EC_USAGE);
}

/* ====================================================================== */

/* Squat a single open mailbox */
static int squat_single(struct mailbox *mailbox, int incremental)
{
    uint32_t uid;
    message_t *msg;
    int r = 0;			/* Using IMAP_* not SQUAT_* return codes here */
    int first = 1;
    struct index_record record;

    r = rx->begin_mailbox(rx, mailbox, incremental);
    if (r) return r;

    for (uid = rx->first_unindexed_uid(rx) ;
	 uid <= mailbox->i.last_uid ;
	 uid++) {

	if (rx->is_indexed(rx, uid))
	    continue;

	/* This UID didn't appear in the old index file */
	r = mailbox_find_index_record(mailbox, uid, &record,
				      (first ? NULL : &record));
	if (r == IMAP_NOTFOUND) continue;
	if (r) break;
	first = 0;
	if (record.system_flags & (FLAG_EXPUNGED|FLAG_UNLINKED))
	    continue;

	msg = message_new_from_record(mailbox, &record);
	index_getsearchtext(msg, rx);
	message_unref(&msg);
    }

    r = rx->end_mailbox(rx, mailbox);
    return (r);
}

/* This is called once for each mailbox we're told to index. */
static int index_one(const char *name)
{
    mbentry_t *mbentry = NULL;
    struct mailbox *mailbox = NULL;
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

    r = mailbox_open_iwl(name, &mailbox);
    if (r) {
        if (verbose) {
            printf("error opening %s: %s\n", extname, error_message(r));
        }
        syslog(LOG_INFO, "error opening %s: %s\n", extname, error_message(r));

        return 1;
    }

    fname = mailbox_meta_fname(mailbox, META_SQUAT);

    /* process only changed mailboxes if skip option delected. */
    if (skip_unmodified && !stat(fname, &sbuf)) {
	if (SKIP_FUZZ + mailbox->index_mtime < sbuf.st_mtime) {
            syslog(LOG_DEBUG, "skipping mailbox %s", extname);
            if (verbose > 0) {
                printf("Skipping mailbox %s\n", extname);
            }
	    mailbox_close(&mailbox);
            return 0;
        }
    }

    syslog(LOG_INFO, "indexing mailbox %s... ", extname);
    if (verbose > 0) {
      printf("Indexing mailbox %s... ", extname);
    }

    squat_single(mailbox, incremental_mode);

    mailbox_close(&mailbox);

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

static void expand_mboxnames(strarray_t *sa, int nmboxnames,
			     const char **mboxnames)
{
    int i;
    char buf[MAX_MAILBOX_PATH + 1];

    if (!nmboxnames) {
	assert(!recursive_flag);
	strlcpy(buf, "*", sizeof(buf));
	(*squat_namespace.mboxlist_findall) (&squat_namespace, buf, 1,
					     0, 0, addmbox, sa);
    }

    for (i = 0; i < nmboxnames; i++) {
	/* Translate any separators in mailboxname */
	(*squat_namespace.mboxname_tointernal) (&squat_namespace,
						mboxnames[i], NULL, buf);
	strarray_append(sa, buf);
	if (recursive_flag) {
	    strlcat(buf, ".*", sizeof(buf));
	    (*squat_namespace.mboxlist_findall) (&squat_namespace, buf, 1,
						 0, 0, addmbox, sa);
	}
    }
}

static void do_indexer(const strarray_t *sa)
{
    int i;

    rx = search_begin_update(verbose);
    if (rx == NULL)
	return;	/* no indexer defined */

    for (i = 0 ; i < sa->count ; i++) {
	index_one(sa->data[i]);
	/* Ignore errors: most will be mailboxes moving around */
    }

    search_end_update(rx);
}

static int squatter_build_query(search_builder_t *bx, const char *query)
{
    tok_t tok = TOK_INITIALIZER(query, NULL, 0);
    char *p;
    char *q;
    int r = 0;
    int part;

    while ((p = tok_next(&tok))) {
	if (!strncasecmp(p, "__begin:", 8)) {
	    q = p + 8;
	    if (!strcasecmp(q, "and"))
		bx->begin_boolean(bx, SEARCH_OP_AND);
	    else if (!strcasecmp(q, "or"))
		bx->begin_boolean(bx, SEARCH_OP_OR);
	    else if (!strcasecmp(q, "not"))
		bx->begin_boolean(bx, SEARCH_OP_NOT);
	    else
		goto error;
	    continue;
	}
	if (!strncasecmp(p, "__end:", 6)) {
	    q = p + 6;
	    if (!strcasecmp(q, "and"))
		bx->end_boolean(bx, SEARCH_OP_AND);
	    else if (!strcasecmp(q, "or"))
		bx->end_boolean(bx, SEARCH_OP_OR);
	    else if (!strcasecmp(q, "not"))
		bx->end_boolean(bx, SEARCH_OP_NOT);
	    else
		goto error;
	    continue;
	}

	/* everything else is a ->match() of some kind */
	q = strchr(p, ':');
	if (q) q++;
	if (!q) {
	    part = SEARCH_PART_ANY;
	    q = p;
	}
	else if (!strncasecmp(p, "to:", 3))
	    part = SEARCH_PART_TO;
	else if (!strncasecmp(p, "from:", 5))
	    part = SEARCH_PART_FROM;
	else if (!strncasecmp(p, "cc:", 3))
	    part = SEARCH_PART_CC;
	else if (!strncasecmp(p, "bcc:", 4))
	    part = SEARCH_PART_BCC;
	else if (!strncasecmp(p, "subject:", 8))
	    part = SEARCH_PART_SUBJECT;
	else if (!strncasecmp(p, "header:", 7))
	    part = SEARCH_PART_HEADERS;
	else if (!strncasecmp(p, "body:", 5))
	    part = SEARCH_PART_BODY;
	else
	    goto error;

	q = charset_convert(q, /*US-ASCII*/0, charset_flags);
	bx->match(bx, part, q);
	free(q);
    }
    r = 0;

out:
    tok_fini(&tok);
    return r;

error:
    syslog(LOG_ERR, "bad query expression at \"%s\"", p);
    r = IMAP_PROTOCOL_ERROR;
    goto out;
}

static void do_search(const char *query, const strarray_t *mboxnames)
{
    struct index_state *state = NULL;
    int i;
    int r;
    int j;
    search_builder_t *bx;
    int count;
    unsigned int *msgno_list;

    /* At the moment we only have a single-mailbox API for searching
     * so we have to handle multiple mailbox searches with a loop */

    for (i = 0 ; i < mboxnames->count ; i++) {
	const char *mboxname = mboxnames->data[i];

	r = index_open(mboxname, NULL, &state);
	if (r) {
	    fprintf(stderr, "Cannot open mailbox %s: %s\n",
		    mboxname, error_message(r));
	    continue;
	}
	printf("mailbox %s\n", mboxname);
	msgno_list = xmalloc(sizeof(unsigned int) * state->exists);

	bx = search_begin_search1(state, msgno_list, verbose);
	if (!bx) goto next;

	r = squatter_build_query(bx, query);

	count = search_end_search1(bx);
	if (r < 0 || count < 0) goto next;

	for (j = 0 ; j < count ; j++)
	    printf("uid %u\n", state->map[msgno_list[j]-1].record.uid);
next:
	free(msgno_list);
	index_close(&state);
    }
}

int main(int argc, char **argv)
{
    int opt;
    char *alt_config = NULL;
    int r;
    strarray_t mboxnames = STRARRAY_INITIALIZER;
    const char *query = NULL;
    enum { UNKNOWN, INDEXER, SEARCH, START_DAEMON, STOP_DAEMON } mode = UNKNOWN;

    if ((geteuid()) == 0 && (become_cyrus(/*is_master*/0) != 0)) {
	fatal("must run as the Cyrus user", EC_USAGE);
    }

    setbuf(stdout, NULL);

    while ((opt = getopt(argc, argv, "C:c:e:rsiav")) != EOF) {
	switch (opt) {
	case 'C':		/* alt config file */
	    alt_config = optarg;
	    break;

	case 'c':		/* daemon control mode */
	    if (mode != UNKNOWN) usage(argv[0]);
	    if (!strcmp(optarg, "start"))
		mode = START_DAEMON;
	    else if (!strcmp(optarg, "stop"))
		mode = STOP_DAEMON;
	    else
		usage(argv[0]);
	    break;

	case 'e':		/* add a search term */
	    if (mode != UNKNOWN && mode != SEARCH) usage(argv[0]);
	    query = optarg;
	    mode = SEARCH;
	    break;

	case 'v':		/* verbose */
	    verbose++;
	    break;

	case 'r':		/* recurse */
	    if (mode != UNKNOWN && mode != INDEXER) usage(argv[0]);
	    recursive_flag = 1;
	    mode = INDEXER;
	    break;

	case 's':		/* skip unmodifed */
	    if (mode != UNKNOWN && mode != INDEXER) usage(argv[0]);
	    skip_unmodified = 1;
	    mode = INDEXER;
	    break;

	case 'i':		/* incremental mode */
	    if (mode != UNKNOWN && mode != INDEXER) usage(argv[0]);
	    incremental_mode = 1;
	    mode = INDEXER;
	    break;

	case 'a':		/* use /squat annotation */
	    if (mode != UNKNOWN && mode != INDEXER) usage(argv[0]);
	    annotation_flag = 1;
	    mode = INDEXER;
	    break;

	default:
	    usage("squatter");
	}
    }

    if (mode == UNKNOWN)
	mode = INDEXER;

    cyrus_init(alt_config, "squatter",
	       (isatty(2) ? CYRUSINIT_PERROR : 0),
	       CONFIG_NEED_PARTITION_DATA);

    /* Set namespace -- force standard (internal) */
    if ((r = mboxname_init_namespace(&squat_namespace, 1)) != 0) {
	fatal(error_message(r), EC_CONFIG);
    }

    annotate_init(NULL, NULL);
    annotatemore_open();

    mboxlist_init(0);
    mboxlist_open(NULL);

    switch (mode) {
    case UNKNOWN:
	break;
    case INDEXER:
	/* -r requires at least one mailbox */
	if (recursive_flag && optind == argc) usage(argv[0]);
	expand_mboxnames(&mboxnames, argc-optind, (const char **)argv+optind);
	syslog(LOG_NOTICE, "indexing mailboxes");
	do_indexer(&mboxnames);
	syslog(LOG_NOTICE, "done indexing mailboxes");
	break;
    case SEARCH:
	if (recursive_flag && optind == argc) usage(argv[0]);
	expand_mboxnames(&mboxnames, argc-optind, (const char **)argv+optind);
	do_search(query, &mboxnames);
	break;
    case START_DAEMON:
	/* daemon control requires exactly one mailbox */
	if (optind != argc-1) usage("squatter");
	expand_mboxnames(&mboxnames, argc-optind, (const char **)argv+optind);
	if (search_start_daemon(verbose, mboxnames.data[0]))
	    exit(EC_TEMPFAIL);
	break;
    case STOP_DAEMON:
	/* daemon control requires exactly one mailbox */
	if (optind != argc-1) usage("squatter");
	expand_mboxnames(&mboxnames, argc-optind, (const char **)argv+optind);
	if (search_stop_daemon(verbose, mboxnames.data[0]))
	    exit(EC_TEMPFAIL);
	break;
    }

    strarray_fini(&mboxnames);
    seen_done();
    mboxlist_close();
    mboxlist_done();
    annotatemore_close();
    annotate_done();

    cyrus_done();

    return 0;
}
