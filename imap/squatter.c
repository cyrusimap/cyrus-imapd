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
#include <sys/poll.h>
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
#include "sync_log.h"
#include "mailbox.h"
#include "xmalloc.h"
#include "xstrlcpy.h"
#include "xstrlcat.h"
#include "ptrarray.h"
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
static int running_daemon = 0;
static search_text_receiver_t *rx = NULL;

static void shut_down(int code) __attribute__((noreturn));

static int usage(const char *name)
{
    fprintf(stderr,
	    "usage: %s [-C <alt_config>] [-v] [-s] [-a] [mailbox...]\n",
	    name);
    fprintf(stderr,
	    "       %s [-C <alt_config>] [-v] [-s] [-a] -r mailbox [...]\n",
	    name);
    fprintf(stderr,
	    "       %s [-C <alt_config>] [-v] [-s] [-d] [-n channel] -R\n",
	    name);
    fprintf(stderr,
	    "       %s [-C <alt_config>] [-v] [-s] -f synclogfile\n",
	    name);

    exit(EC_USAGE);
}

/* ====================================================================== */

static void become_daemon(void)
{
    pid_t pid;
    int nfds = getdtablesize();
    int nullfd;
    int fd;

    nullfd = open("/dev/null", O_RDWR, 0);
    if (nullfd < 0) {
	perror("/dev/null");
	exit(1);
    }
    dup2(nullfd, 0);
    dup2(nullfd, 1);
    dup2(nullfd, 2);
    for (fd = 3 ; fd < nfds ; fd++)
	close(fd);	    /* this will close nullfd too */

    pid = fork();
    if (pid == -1) {
	perror("fork");
	exit(1);
    }

    if (pid)
	exit(0); /* parent */
}

/* ====================================================================== */

/* This is called once for each mailbox we're told to index. */
static int index_one(const char *name, int blocking)
{
    mbentry_t *mbentry = NULL;
    struct mailbox *mailbox = NULL;
    int r;
    char extname[MAX_MAILBOX_BUFFER];

    /* Convert internal name to external */
    (*squat_namespace.mboxname_toexternal)(&squat_namespace, name,
					   NULL, extname);

    /* Skip remote mailboxes */
    r = mboxlist_lookup(name, &mbentry, NULL);
    if (r) {
	if (verbose) {
	    printf("error looking up %s: %s\n",
		   extname, error_message(r));
	}
	syslog(LOG_INFO, "error looking up %s: %s\n",
	       extname, error_message(r));

	return r;
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

    if (blocking)
	r = mailbox_open_irl(name, &mailbox);
    else
	r = mailbox_open_irlnb(name, &mailbox);

    if (r == IMAP_MAILBOX_LOCKED) {
	if (verbose) syslog(LOG_INFO, "mailbox %s locked, retrying", extname);
	return r;
    }
    if (r) {
	if (verbose) {
	    printf("error opening %s: %s\n", extname, error_message(r));
	}
	syslog(LOG_INFO, "error opening %s: %s\n", extname, error_message(r));

	return r;
    }

    /* process only changed mailboxes if skip option detected. */
    if (skip_unmodified) {
	char *fname = mailbox_meta_fname(mailbox, META_SQUAT);
	struct stat sbuf;
	if (!stat(fname, &sbuf) &&
	    SKIP_FUZZ + mailbox->index_mtime < sbuf.st_mtime) {
	    syslog(LOG_DEBUG, "skipping mailbox %s", extname);
	    if (verbose > 0) {
		printf("Skipping mailbox %s\n", extname);
	    }
	    mailbox_close(&mailbox);
	    return IMAP_AGAIN;
	}
    }

    syslog(LOG_INFO, "indexing mailbox %s... ", extname);
    if (verbose > 0) {
	printf("Indexing mailbox %s... ", extname);
    }

    r = search_update_mailbox(rx, mailbox, incremental_mode);

    mailbox_close(&mailbox);

    return r;
}

static int addmbox(char *name,
		   int matchlen __attribute__((unused)),
		   int maycreate __attribute__((unused)),
		   void *rock)
{
    strarray_t *sa = (strarray_t *) rock;
    if (!mboxname_isdeletedmailbox(name, NULL))
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
	index_one(sa->data[i], /*blocking*/1);
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
    int utf8 = charset_lookupname("utf-8");

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
	else if (!strncasecmp(p, "listid:", 7))
	    part = SEARCH_PART_LISTID;
	else if (!strncasecmp(p, "contenttype:", 12))
	    part = SEARCH_PART_TYPE;
	else if (!strncasecmp(p, "header:", 7))
	    part = SEARCH_PART_HEADERS;
	else if (!strncasecmp(p, "body:", 5))
	    part = SEARCH_PART_BODY;
	else
	    goto error;

	q = charset_convert(q, utf8, charset_flags);
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

static int print_search_hit(const char *mboxname, uint32_t uidvalidity,
			    uint32_t uid, void *rock)
{
    int single = *(int *)rock;

    if (single)
	printf("uid %u\n", uid);
    else
	printf("mailbox %s\nuidvalidity %u\nuid %u\n", mboxname, uidvalidity, uid);
    return 0;
}

static void do_search(const char *query, int single, const strarray_t *mboxnames)
{
    struct mailbox *mailbox = NULL;
    int i;
    int r;
    search_builder_t *bx;
    int opts = SEARCH_VERBOSE(verbose);

    if (!single)
	opts |= SEARCH_MULTIPLE;

    for (i = 0 ; i < mboxnames->count ; i++) {
	const char *mboxname = mboxnames->data[i];

	r = mailbox_open_iwl(mboxname, &mailbox);
	if (r) {
	    fprintf(stderr, "Cannot open mailbox %s: %s\n",
		    mboxname, error_message(r));
	    continue;
	}
	if (single)
	    printf("mailbox %s\n", mboxname);

	bx = search_begin_search(mailbox, opts);
	if (bx) {
	    r = squatter_build_query(bx, query);
	    if (!r)
		r = bx->run(bx, print_search_hit, &single);
	    search_end_search(bx);
	}

	mailbox_close(&mailbox);
    }
}

typedef struct qitem qitem_t;
struct qitem
{
    qitem_t *next;
    int delta_ms;	/* time after previous item */
    int delay_ms;	/* how much to delay */
    int elapsed_ms;	/* total elapsed delays */
    int retries;	/* number of times we have failed to index */
    char *mboxname;
};
/* Initial delay is very short to make retries fast when
 * racing against lmtpd.  */
#define INIT_DELAY_MS    (32)		    /* 32 millisec */
#define MAX_DELAY_MS     (1000)		    /* 1 sec */
#define MAX_ELAPSED_MS	 (10 * 60 * 1000)   /* 10 min */

static qitem_t *queue;
static int n_unretried = 0;

static qitem_t *qitem_new(const char *mboxname)
{
    qitem_t *item = xzmalloc(sizeof(qitem_t));
    item->mboxname = xstrdup(mboxname);
    return item;
}

static void qitem_delete(qitem_t *item)
{
    free(item->mboxname);
    free(item);
}

static int qitem_compare(const void *v1, const void *v2)
{
    const qitem_t *item1 = *(const qitem_t **)v1;
    const qitem_t *item2 = *(const qitem_t **)v2;
    return strcmp(item1->mboxname, item2->mboxname);
}

static void debug_dump(void)
{
    qitem_t *item;

    syslog(LOG_INFO, "queue {");
    for (item = queue ; item ; item = item->next) {
	syslog(LOG_INFO, "    delta_ms=%d delay_ms=%d mboxname=%s retries=%d",
		item->delta_ms, item->delay_ms, item->mboxname, item->retries);
    }
    syslog(LOG_INFO, "} queue");
    syslog(LOG_INFO, "n_unretried=%d", n_unretried);
}

static qitem_t *_queue_detach(qitem_t **prevp);

static qitem_t *queue_remove_by_name(qitem_t **headp, const char *mboxname)
{
    qitem_t **prevp;

    for (prevp = headp ; *prevp ; prevp = &((*prevp)->next)) {
	if (!strcmp((*prevp)->mboxname, mboxname))
	    return _queue_detach(prevp);
    }
    return NULL;
}

static qitem_t *_queue_detach(qitem_t **prevp)
{
    qitem_t *item = *prevp;
    if (item) {
	*prevp = item->next;
	item->next = NULL;
	if (!item->retries) n_unretried--;
    }
    return item;
}

static void _queue_insert(qitem_t **prevp, qitem_t *item)
{
    item->next = *prevp;
    *prevp = item;
    if (!item->retries) n_unretried++;
}

static qitem_t *queue_remove_due(qitem_t **headp)
{
    qitem_t *item = *headp;
    if (item && item->delta_ms <= 0)
	return _queue_detach(headp);
    return NULL;
}

static void queue_delay(qitem_t **headp, qitem_t *item)
{
    qitem_t **prevp;
    int delta_ms;

    delta_ms = item->delay_ms;

    item->elapsed_ms += delta_ms;
    if (item->elapsed_ms > MAX_ELAPSED_MS) {
	syslog(LOG_ERR, "IOERROR: Unable to open mailbox %s for indexing "
			"after %d.%03d second of delays, giving up",
			item->mboxname,
			item->elapsed_ms / 1000, item->elapsed_ms % 1000);
	qitem_delete(item);
	return;
    }

    if (!item->delay_ms)
	item->delay_ms = INIT_DELAY_MS;
    else
	item->delay_ms = MIN(item->delay_ms * 2, MAX_DELAY_MS);

    if (verbose > 1)
	syslog(LOG_INFO, "queue_delay(%s, %d ms)", item->mboxname, delta_ms);

    for (prevp = headp ;
	 *prevp && delta_ms >= (*prevp)->delta_ms ;
	 prevp = &((*prevp)->next))
	delta_ms -= (*prevp)->delta_ms;

    item->delta_ms = delta_ms;
    _queue_insert(prevp, item);
}

static int queue_next_due(qitem_t **headp)
{
    return (*headp ? (*headp)->delta_ms : INT_MAX);
}

static void queue_slept(qitem_t **headp, int delay_ms)
{
    if (*headp)
	(*headp)->delta_ms -= delay_ms;
}

static void read_sync_log_items(sync_log_reader_t *slr)
{
    const char *args[3];
    qitem_t *item = NULL;
    int i;
    ptrarray_t items = PTRARRAY_INITIALIZER;

    while (sync_log_reader_getitem(slr, args) == 0) {
	if (!strcmp(args[0], "APPEND")) {
	    item = queue_remove_by_name(&queue, args[1]);
	    if (!item)
		item = qitem_new(args[1]);
	    ptrarray_append(&items, item);
	}
    }

    /* sort the mailboxes to get locality of reference
     * for searchd startups */
    qsort(items.data, items.count, sizeof(qitem_t*), qitem_compare);

    for (i = 0 ; i < items.count ; i++) {
	item = ptrarray_nth(&items, i);
	item->delay_ms = 0;
	item->retries = 0;
	item->elapsed_ms = 0;
	queue_delay(&queue, item);
    }

    ptrarray_fini(&items);

    /* TODO: save the queue to a file at this point */
}

static void do_synclogfile(const char *synclogfile)
{
    sync_log_reader_t *slr;
    qitem_t *item;
    int delay_ms;
    int r;

    slr = sync_log_reader_create_with_filename(synclogfile);
    r = sync_log_reader_begin(slr);
    if (r) goto out;
    read_sync_log_items(slr);
    sync_log_reader_end(slr);

    while (queue) {
	signals_poll();

	if (queue_next_due(&queue) <= 0) {
	    /* have some due items in the queue, try to index them */
	    rx = search_begin_update(verbose);
	    while ((item = queue_remove_due(&queue))) {
		if (verbose > 1)
		    syslog(LOG_INFO, "do_synclogfile: indexing %s", item->mboxname);
		r = index_one(item->mboxname, /*blocking*/0);
		if (r == IMAP_AGAIN || r == IMAP_MAILBOX_LOCKED) {
		    item->retries++;
		    queue_delay(&queue, item);
		}
		else
		    qitem_delete(item);
	    }
	    search_end_update(rx);
	    rx = NULL;
	}

	delay_ms = queue_next_due(&queue);
	if (delay_ms && delay_ms != INT_MAX) {
	    poll(NULL, 0, delay_ms);
	    queue_slept(&queue, delay_ms);
	}
    }

out:
    sync_log_reader_free(slr);
}

static void do_rolling(const char *channel)
{
    sync_log_reader_t *slr;
    qitem_t *item;
    int poll_period_ms = 1000;
    int delay_ms;
    int r;

    slr = sync_log_reader_create_with_channel(channel);

    for (;;) {
	r = signals_poll();
	if (r == SIGHUP) {
	    debug_dump();
	    signals_clear(SIGHUP);
	    continue;
	}
	if (shutdown_file(NULL, 0))
	    shut_down(EC_TEMPFAIL);

	if (!n_unretried) {
	    /* Have successfully drained the queue of items which are on
	     * their first pass around, go see if there's some more to
	     * be had in the sync log */
	    r = sync_log_reader_begin(slr);
	    if (r && r != IMAP_AGAIN)
		break;
	    if (!r) {
		read_sync_log_items(slr);
	    }
	}

	if (queue_next_due(&queue) <= 0) {
	    /* have some due items in the queue, try to index them */
	    rx = search_begin_update(verbose);
	    while ((item = queue_remove_due(&queue))) {
		if (verbose > 1)
		    syslog(LOG_INFO, "do_rolling: indexing %s", item->mboxname);
		r = index_one(item->mboxname, /*blocking*/0);
		if (r == IMAP_AGAIN || r == IMAP_MAILBOX_LOCKED) {
		    item->retries++;
		    queue_delay(&queue, item);
		}
		else
		    qitem_delete(item);
	    }
	    search_end_update(rx);
	    rx = NULL;
	}

	delay_ms = MIN(poll_period_ms, queue_next_due(&queue));
	if (delay_ms) {
	    poll(NULL, 0, delay_ms);
	    queue_slept(&queue, delay_ms);
	}
    }
    sync_log_reader_free(slr);
}

/*
 * Run a search daemon in such a way that the natural shutdown
 * mechanism for Cyrus (sending a SIGTERM to the master process)
 * will cleanly shut down the search daemon too.  For Sphinx
 * this currently means running a loop in a forked process whose
 * job it is to live in the master process' process group and thus
 * receive the SIGTERM that master re-sends.
 */
static void do_run_daemon(void)
{
    int r;

    /* We start the daemon before forking.  This eliminates a
     * race condition during slot startup by ensuring that
     * Sphinx is fully running before the rolling squatter
     * tries to use it. */
    r = search_start_daemon(verbose);
    if (r) exit(EC_TEMPFAIL);

    /* tell shut_down() to shut down the searchd too */
    running_daemon = 1;

    become_daemon();
    signals_set_shutdown(&shut_down);
    signals_add_handlers(0);

    for (;;) {
	signals_poll();		/* will call shut_down() after SIGTERM */
	poll(NULL, 0, -1);	/* sleeps until signalled */
    }
}

static void shut_down(int code)
{
    if (running_daemon)
	search_stop_daemon(verbose);
    seen_done();
    mboxlist_close();
    mboxlist_done();
    annotatemore_close();
    annotate_done();

    cyrus_done();

    exit(code);
}

int main(int argc, char **argv)
{
    int opt;
    char *alt_config = NULL;
    int r;
    strarray_t mboxnames = STRARRAY_INITIALIZER;
    const char *query = NULL;
    int background = 1;
    const char *channel = "squatter";
    const char *synclogfile = NULL;
    int init_flags = CYRUSINIT_PERROR;
    int multi_folder = 0;
    enum { UNKNOWN, INDEXER, SEARCH, ROLLING, SYNCLOG,
	   START_DAEMON, STOP_DAEMON, RUN_DAEMON } mode = UNKNOWN;

    if ((geteuid()) == 0 && (become_cyrus(/*is_master*/0) != 0)) {
	fatal("must run as the Cyrus user", EC_USAGE);
    }

    setbuf(stdout, NULL);

    while ((opt = getopt(argc, argv, "C:Rc:de:f:mn:rsiav")) != EOF) {
	switch (opt) {
	case 'C':		/* alt config file */
	    alt_config = optarg;
	    break;

	case 'R':		/* rolling indexer */
	    if (mode != UNKNOWN) usage(argv[0]);
	    mode = ROLLING;
	    break;

	/* This option is deliberately undocumented, for testing only */
	case 'c':		/* daemon control mode */
	    if (mode != UNKNOWN) usage(argv[0]);
	    if (!strcmp(optarg, "start"))
		mode = START_DAEMON;
	    else if (!strcmp(optarg, "stop"))
		mode = STOP_DAEMON;
	    else if (!strcmp(optarg, "run"))
		mode = RUN_DAEMON;
	    else
		usage(argv[0]);
	    break;

	case 'd':		/* foreground (with -R) */
	    background = 0;
	    break;

	/* This option is deliberately undocumented, for testing only */
	case 'e':		/* add a search term */
	    if (mode != UNKNOWN && mode != SEARCH) usage(argv[0]);
	    query = optarg;
	    mode = SEARCH;
	    break;

	case 'f': /* alternate synclogfile used in SYNCLOG mode */
	    synclogfile = optarg;
	    mode = SYNCLOG;
	    break;

	/* This option is deliberately undocumented, for testing only */
	case 'm':		/* multi-folder in SEARCH mode */
	    if (mode != UNKNOWN && mode != SEARCH) usage(argv[0]);
	    multi_folder = 1;
	    mode = SEARCH;
	    break;

	case 'n':		/* sync channel name (with -R) */
	    channel = optarg;
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

    /* fork and close fds if required */
    if (mode == ROLLING && background) {
	become_daemon();
	init_flags &= ~CYRUSINIT_PERROR;
    }

    cyrus_init(alt_config, "squatter", init_flags, CONFIG_NEED_PARTITION_DATA);

    /* Set namespace -- force standard (internal) */
    if ((r = mboxname_init_namespace(&squat_namespace, 1)) != 0) {
	fatal(error_message(r), EC_CONFIG);
    }

    annotate_init(NULL, NULL);
    annotatemore_open();

    mboxlist_init(0);
    mboxlist_open(NULL);

    if (mode == ROLLING || mode == SYNCLOG) {
	signals_set_shutdown(&shut_down);
	signals_add_handlers(0);
    }

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
	do_search(query, !multi_folder, &mboxnames);
	break;
    case ROLLING:
	do_rolling(channel);
	break;
    case SYNCLOG:
	do_synclogfile(synclogfile);
	break;
    case START_DAEMON:
	if (optind != argc) usage("squatter");
	if (search_start_daemon(verbose))
	    exit(EC_TEMPFAIL);
	break;
    case STOP_DAEMON:
	if (optind != argc) usage("squatter");
	if (search_stop_daemon(verbose))
	    exit(EC_TEMPFAIL);
	break;
    case RUN_DAEMON:
	if (optind != argc) usage("squatter");
	do_run_daemon();
	break;
    }

    strarray_fini(&mboxnames);
    shut_down(0);
}
