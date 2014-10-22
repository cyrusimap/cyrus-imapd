/* cyr_expire.c -- Program to expire deliver.db entries and messages
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
 */

#include <config.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <syslog.h>
#include <signal.h>

#include <sasl/sasl.h>

#include "annotate.h"
#include "duplicate.h"
#include "exitcodes.h"
#include "imap/imap_err.h"
#include "global.h"
#include "hash.h"
#include "libcyr_cfg.h"
#include "mboxevent.h"
#include "mboxlist.h"
#include "util.h"
#include "xmalloc.h"
#include "strarray.h"

/* global state */
static volatile sig_atomic_t sigquit = 0;
static int verbose = 0;

/* current namespace */
static struct namespace expire_namespace;

static void usage(void)
{
    fprintf(stderr,
	    "cyr_expire [-C <altconfig>] [-E <expire-duration>] [-D <delete-duration] [-X <expunge-duration>] [-p prefix] [-a] [-v] [-x]\n");
    exit(-1);
}

struct expire_rock {
    struct hash_table table;
    time_t expire_mark;
    time_t expunge_mark;
    unsigned long mailboxes_seen;
    unsigned long messages_seen;
    unsigned long messages_expired;
    unsigned long messages_expunged;
    int skip_annotate;
    bit32 userflags[MAX_USER_FLAGS/32];
    int do_userflags;
    unsigned long userflags_expunged;
};

struct delete_rock {
    time_t delete_mark;
    strarray_t to_delete;
};

/*
 * Parse a non-negative duration string as seconds.
 *
 * Convert "23.5m" to fractional days.  Accepts the suffixes "d" (day),
 * (day), "h" (hour), "m" (minute) and "s" (second).  If no suffix, assume
 * days.
 * Returns 1 if successful and *secondsp is filled in, or 0 if the suffix
 * is unknown or on error.
 */
static int parse_duration(const char *s, int *secondsp)
{
    char *end = NULL;
    double val;
    int multiplier = 86400; /* default is days */

    /* no negative or empty numbers please */
    if (!*s || *s == '-')
	return 0;

    val = strtod(s, &end);
    /* Allow 'd', 'h', 'm' and 's' as end, else return error. */
    if (*end) {
	if (end[1]) return 0; /* trailing extra junk */

	switch (*end) {
	case 'd':
	    /* already the default */
	    break;
	case 'h':
	    multiplier = 3600;
	    break;
	case 'm':
	    multiplier = 60;
	    break;
	case 's':
	    multiplier = 1;
	    break;
	default:
	    return 0;
	}
    }

    *secondsp = multiplier * val;

    return 1;
}

static int expunge_userflags(struct mailbox *mailbox, struct expire_rock *erock)
{
    unsigned int i;
    int r;

    for (i = 0; i < MAX_USER_FLAGS; i++) {
	if (erock->userflags[i/32] & 1<<(i&31))
	    continue;
	if (verbose)
	    fprintf(stderr, "Expunging userflag %u (%s) from %s\n",
		    i, mailbox->flagname[i], mailbox->name);
	r = mailbox_remove_user_flag(mailbox, i);
	if (r) return r;
	erock->userflags_expunged++;
    }

    return 0;
}

/*
 * mailbox_expunge() callback to expunge expired articles.
 */
static unsigned expire_cb(struct mailbox *mailbox __attribute__((unused)),
			  struct index_record *record,
			  void *rock)
{
    struct expire_rock *erock = (struct expire_rock *) rock;
    unsigned int i;

    /* otherwise, we're expiring messages by sent date */
    if (record->gmtime < erock->expire_mark) {
	erock->messages_expired++;
	return 1;
    }

    /* record which user flags are set */
    for (i = 0; i < (MAX_USER_FLAGS/32); i++)
	erock->userflags[i] |= record->user_flags[i];

    return 0;
}

/*
 * mailbox_expunge() callback to *only* count userflags.
 */
static unsigned userflag_cb(struct mailbox *mailbox __attribute__((unused)),
			    struct index_record *record,
			    void *rock)
{
    struct expire_rock *erock = (struct expire_rock *) rock;
    unsigned int i;

    /* record which user flags are set */
    for (i = 0; i < (MAX_USER_FLAGS/32); i++)
	erock->userflags[i] |= record->user_flags[i];

    return 0;	/* always keep the message */
}


/*
 * mboxlist_findall() callback function to:
 * - expire messages from mailboxes,
 * - build a hash table of mailboxes in which we expired messages,
 * - and perform a cleanup of expunged messages
 */
static int expire(void *rock, const char *key, size_t keylen,
			      const char *data, size_t datalen)
{
    mbentry_t *mbentry = NULL;
    struct expire_rock *erock = (struct expire_rock *) rock;
    char *buf;
    struct buf attrib = BUF_INITIALIZER;
    int r;
    struct mailbox *mailbox = NULL;
    unsigned numexpunged = 0;
    int expire_seconds = 0;
    int did_expunge = 0;

    if (sigquit) {
	/* don't care if we leak some memory, we are shutting down */
	return 1;
    }
    if (mboxlist_parse_entry(&mbentry, key, keylen, data, datalen))
	goto done; /* xxx - syslog? */

    /* Skip remote mailboxes */
    if (mbentry->mbtype & MBTYPE_REMOTE)
	goto done;

    /* clean up deleted entries after 7 days */
    if (mbentry->mbtype & MBTYPE_DELETED) {
	if (time(0) - mbentry->mtime > 86400*7) {
	    syslog(LOG_NOTICE, "Removing stale tombstone for %s", mbentry->name);
	    cyrusdb_delete(mbdb, key, keylen, NULL, /*force*/1);
	}

	goto done;
    }

    buf = xstrdup(mbentry->name);

    /* see if we need to expire messages.
     * since mailboxes inherit /vendor/cmu/cyrus-imapd/expire,
     * we need to iterate all the way up to "" (server entry)
     */
    if (!erock->skip_annotate) {
	do {
	    buf_free(&attrib);
	    r = annotatemore_lookup(buf, "/vendor/cmu/cyrus-imapd/expire", "",
				    &attrib);

	    if (r ||				/* error */
		attrib.s)			/* found an entry */
		break;

	} while (mboxname_make_parent(buf));
    }
    free(buf);

    memset(erock->userflags, 0, sizeof(erock->userflags));

    r = mailbox_open_iwl(mbentry->name, &mailbox);
    if (r) {
	/* mailbox corrupt/nonexistent -- skip it */
	syslog(LOG_WARNING, "unable to open mailbox %s: %s",
	       mbentry->name, error_message(r));
	goto done;
    }

    if (attrib.s && parse_duration(attrib.s, &expire_seconds)) {
	/* add mailbox to table */
	erock->expire_mark = expire_seconds ?
			     time(0) - expire_seconds : 0 /* never */ ;
	hash_insert(mbentry->name,
		    xmemdup(&erock->expire_mark, sizeof(erock->expire_mark)),
		    &erock->table);

	if (expire_seconds) {
	    if (verbose) {
		fprintf(stderr,
			"expiring messages in %s older than %0.2f days\n",
			mbentry->name, ((double)expire_seconds/86400));
	    }

	    r = mailbox_expunge(mailbox, expire_cb, erock, NULL,
				EVENT_MESSAGE_EXPIRE);
	    if (r)
		syslog(LOG_ERR, "failed to expire old messages: %s", mbentry->name);
	    did_expunge = 1;
	}
    }
    buf_free(&attrib);

    if (!did_expunge && erock->do_userflags) {
	r = mailbox_expunge(mailbox, userflag_cb, erock, NULL,
			    EVENT_MESSAGE_EXPIRE);
	if (r)
	    syslog(LOG_ERR, "failed to scan user flags for %s: %s",
		   mbentry->name, error_message(r));
    }

    erock->messages_seen += mailbox->i.num_records;

    if (erock->do_userflags)
	expunge_userflags(mailbox, erock);

    r = mailbox_expunge_cleanup(mailbox, erock->expunge_mark, &numexpunged);

    erock->messages_expunged += numexpunged;
    erock->mailboxes_seen++;

    if (r) {
	syslog(LOG_WARNING, "failure expiring %s: %s", mbentry->name, error_message(r));
	annotate_state_abort(&mailbox->annot_state);
    }

done:
    mboxlist_entry_free(&mbentry);
    mailbox_close(&mailbox);
    /* Even if we had a problem with one mailbox, continue with the others */
    return 0;
}

static int delete(char *name,
		  int matchlen __attribute__((unused)),
		  int maycreate __attribute__((unused)),
		  void *rock)
{
    mbentry_t *mbentry = NULL;
    struct delete_rock *drock = (struct delete_rock *) rock;
    int r;
    time_t timestamp;

    if (sigquit) {
	return 1;
    }

    /* check if this is a mailbox we want to examine */
    if (!mboxname_isdeletedmailbox(name, &timestamp))
	return 0;

    /* Skip remote mailboxes */
    r = mboxlist_lookup(name, &mbentry, NULL);
    if (r) {
	if (verbose) {
	    printf("error looking up %s: %s\n", name, error_message(r));
	}
	return 1;
    }

    if (mbentry->mbtype & MBTYPE_REMOTE) {
	mboxlist_entry_free(&mbentry);
	return 0;
    }
    mboxlist_entry_free(&mbentry);

    if ((timestamp == 0) || (timestamp > drock->delete_mark))
	return 0;

    /* Add this mailbox to list of mailboxes to delete */
    strarray_append(&drock->to_delete, name);

    return(0);
}

static void sighandler (int sig __attribute((unused)))
{
    sigquit = 1;
    return;
}

int main(int argc, char *argv[])
{
    extern char *optarg;
    int opt, r = 0;
    int do_expunge = 1;	/* gnb:TODO bool */
    int expunge_seconds = -1;
    int delete_seconds = -1;
    int expire_seconds = 0;
    char *alt_config = NULL;
    const char *find_prefix = "*";
    struct expire_rock erock;
    struct delete_rock drock;
    struct sigaction action;

    if ((geteuid()) == 0 && (become_cyrus(/*is_master*/0) != 0)) {
	fatal("must run as the Cyrus user", EC_USAGE);
    }

    /* zero the expire_rock & delete_rock */
    memset(&erock, 0, sizeof(erock));
    construct_hash_table(&erock.table, 10000, 1);
    memset(&drock, 0, sizeof(drock));
    strarray_init(&drock.to_delete);

    while ((opt = getopt(argc, argv, "C:D:E:X:p:vaxt")) != EOF) {
	switch (opt) {
	case 'C': /* alt config file */
	    alt_config = optarg;
	    break;

	case 'D':
	    if (delete_seconds >= 0) usage();
	    if (!parse_duration(optarg, &delete_seconds)) usage();
	    break;

	case 'E':
	    if (expire_seconds > 0) usage();
	    if (!parse_duration(optarg, &expire_seconds)) usage();
	    break;

	case 'X':
	    if (expunge_seconds >= 0) usage();
	    if (!parse_duration(optarg, &expunge_seconds)) usage();
	    break;

	case 'p':
	    find_prefix = optarg;
	    break;

	case 'v':
	    verbose++;
	    break;

	case 'a':
	    erock.skip_annotate = 1;
	    break;

	case 'x':
	    if (!do_expunge) usage();
	    do_expunge = 0;
	    break;

	case 't':
	    erock.do_userflags = 1;
	    break;

	default:
	    usage();
	    break;
	}
    }

    if (!expire_seconds &&
	delete_seconds == -1 &&
	expunge_seconds == -1 &&
	!erock.do_userflags)
	usage();

    sigemptyset(&action.sa_mask);
    action.sa_flags = 0;
    action.sa_handler = sighandler;
    if (sigaction(SIGQUIT, &action, NULL) < 0)
	fatal("unable to install signal handler for SIGQUIT", EC_TEMPFAIL);
    if (sigaction(SIGINT, &action, NULL) < 0)
	fatal("unable to install signal handler for SIGINT", EC_TEMPFAIL);
    if (sigaction(SIGTERM, &action, NULL) < 0)
	fatal("unable to install signal handler for SIGTERM", EC_TEMPFAIL);

    cyrus_init(alt_config, "cyr_expire", 0, 0);
    global_sasl_init(1, 0, NULL);

    annotate_init(NULL, NULL);
    annotatemore_open();

    mboxlist_init(0);
    mboxlist_open(NULL);

    /* open the quota db, we'll need it for expunge */
    quotadb_init(0);
    quotadb_open(NULL);

    /* setup for mailbox event notifications */
    mboxevent_init();

    /* Set namespace -- force standard (internal) */
    if ((r = mboxname_init_namespace(&expire_namespace, 1)) != 0) {
	syslog(LOG_ERR, "%s", error_message(r));
	fatal(error_message(r), EC_CONFIG);
    }

    mboxevent_setnamespace(&expire_namespace);

    if (duplicate_init(NULL) != 0) {
	fprintf(stderr,
		"cyr_expire: unable to init duplicate delivery database\n");
	exit(1);
    }

    if (do_expunge && (expunge_seconds >= 0 || expire_seconds || erock.do_userflags)) {
	/* xxx better way to determine a size for this table? */

	/* expire messages from mailboxes,
	 * build a hash table of mailboxes in which we expired messages,
	 * and perform a cleanup of expunged messages
	 */
	if (expunge_seconds < 0) {
	    erock.expunge_mark = 0;
	} else {
	    erock.expunge_mark = time(0) - expunge_seconds;

	    if (verbose) {
		fprintf(stderr,
			"Expunging deleted messages in mailboxes older than %0.2f days\n",
			((double)expunge_seconds/86400));
	    }
	}

	mboxlist_findall(NULL, find_prefix, 1, 0, 0, expire, &erock);

	syslog(LOG_NOTICE, "Expired %lu and expunged %lu out of %lu "
			    "messages from %lu mailboxes",
			   erock.messages_expired,
			   erock.messages_expunged,
			   erock.messages_seen,
			   erock.mailboxes_seen);
	if (erock.do_userflags)
	    syslog(LOG_NOTICE, "Expunged %lu user flags",
			   erock.userflags_expunged);
	if (verbose) {
	    fprintf(stderr, "\nExpired %lu and expunged %lu out of %lu "
			    "messages from %lu mailboxes\n",
			   erock.messages_expired,
			   erock.messages_expunged,
			   erock.messages_seen,
			   erock.mailboxes_seen);
	    if (erock.do_userflags)
		fprintf(stderr, "Expunged %lu user flags\n",
			       erock.userflags_expunged);
	}
    }
    if (sigquit) {
	goto finish;
    }

    if ((delete_seconds >= 0) && mboxlist_delayed_delete_isenabled() &&
	config_getstring(IMAPOPT_DELETEDPREFIX)) {
	int count = 0;
	int i;

	if (verbose) {
	    fprintf(stderr,
		    "Removing deleted mailboxes older than %0.2f days\n",
		    ((double)delete_seconds/86400));
	}

	drock.delete_mark = time(0) - delete_seconds;

	mboxlist_findall(NULL, find_prefix, 1, 0, 0, delete, &drock);

	for (i = 0 ; i < drock.to_delete.count ; i++) {
	    char *name = drock.to_delete.data[i];

	    if (sigquit) {
		goto finish;
	    }
	    if (verbose) {
		fprintf(stderr, "Removing: %s\n", name);
	    }
	    r = mboxlist_deletemailbox(name, 1, NULL, NULL, NULL, 0, 0, 0);
	    count++;
	}

	if (verbose) {
	    if (count != 1) {
		fprintf(stderr, "Removed %d deleted mailboxes\n", count);
	    } else {
		fprintf(stderr, "Removed 1 deleted mailbox\n");
	    }
	}
	syslog(LOG_NOTICE, "Removed %d deleted mailboxes", count);
    }
    if (sigquit) {
	goto finish;
    }

    /* purge deliver.db entries of expired messages */
    if (expire_seconds > 0)
	r = duplicate_prune(expire_seconds, &erock.table);

finish:
    free_hash_table(&erock.table, free);
    strarray_fini(&drock.to_delete);

    quotadb_close();
    quotadb_done();
    mboxlist_close();
    mboxlist_done();
    annotatemore_close();
    annotate_done();
    duplicate_done();
    sasl_done();
    cyrus_done();

    exit(r);
}
