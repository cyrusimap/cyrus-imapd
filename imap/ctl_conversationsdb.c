/*
 * Copyright (c) 1994-2011 Carnegie Mellon University.  All rights reserved.
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
#include <syslog.h>
#include <string.h>
#include <sys/stat.h>

/* cyrus includes */
#include "assert.h"
#include "bsearch.h"
#include "exitcodes.h"
#include "global.h"
#include "index.h"
#include "conversations.h"
#include "mailbox.h"
#include "mboxlist.h"
#include "message.h"
#include "sync_log.h"
#include "sysexits.h"
#include "util.h"
#include "xmalloc.h"

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"

/* config.c stuff */
const int config_need_data = CONFIG_NEED_PARTITION_DATA;
static struct namespace conv_namespace;

enum { UNKNOWN, DUMP, UNDUMP, ZERO, BUILD, RECALC, AUDIT, CHECKFOLDERS };

int verbose = 0;

char *prev_userid;
int mode = UNKNOWN;
static const char *audit_temp_directory;

static int do_dump(const char *fname)
{
    struct conversations_state *state = NULL;
    struct stat sb;
    int r;

    /* What we really want here is read-only database access without
     * the create-if-nonexistant semantics.  However, the cyrusdb
     * interface makes it difficult to do that properly.  In the
     * meantime, we can just check if the file exists here. */
    r = stat(fname, &sb);
    if (r < 0) {
	perror(fname);
	return -1;
    }

    r = conversations_open_path(fname, &state);
    if (r) {
	fprintf(stderr, "Failed to open conversations database %s: %s\n",
		fname, error_message(r));
	return -1;
    }

    conversations_dump(state, stdout);

    conversations_commit(&state);
    return 0;
}

static int do_undump(const char *fname)
{
    struct conversations_state *state;
    int r;

    r = conversations_open_path(fname, &state);
    if (r) {
	fprintf(stderr, "Failed to open conversations database %s: %s\n",
		fname, error_message(r));
	return -1;
    }

    r = conversations_truncate(state);
    if (r) {
	fprintf(stderr, "Failed to truncate conversations database %s: %s\n",
		fname, error_message(r));
	goto out;
    }

    r = conversations_undump(state, stdin);
    if (r) {
	fprintf(stderr, "Failed to undump to conversations database %s: %s\n",
		fname, error_message(r));
	goto out;
    }

    r = conversations_commit(&state);
    if (r)
	fprintf(stderr, "Failed to commit conversations database %s: %s\n",
		fname, error_message(r));

out:
    conversations_abort(&state);
    return r;
}

static int zero_cid_cb(const char *mboxname,
		       int matchlen __attribute__((unused)),
		       int maycreate __attribute__((unused)),
		       void *rock __attribute__((unused)))
{
    struct mailbox *mailbox = NULL;
    const struct index_record *record;
    int r;

    r = mailbox_open_iwl(mboxname, &mailbox);
    if (r) return r;

    struct mailbox_iter *iter = mailbox_iter_init(mailbox, 0, ITER_SKIP_UNLINKED);
    while ((record = mailbox_iter_step(iter))) {
	/* already zero, fine */
	if (record->cid == NULLCONVERSATION)
	    continue;

	struct index_record oldrecord = *record;
	oldrecord.cid = NULLCONVERSATION;
	r = mailbox_rewrite_index_record(mailbox, &oldrecord);
	if (r) goto done;
    }
    mailbox_iter_done(&iter);

 done:
    mailbox_close(&mailbox);
    return r;
}

static int do_zero(const char *inboxname)
{
    char buf[MAX_MAILBOX_NAME];
    int r;
    struct conversations_state *state = NULL;

    r = conversations_open_mbox(inboxname, &state);

    r = zero_cid_cb(inboxname, 0, 0, NULL);
    if (r) return r;

    snprintf(buf, sizeof(buf), "%s.*", inboxname);
    r = mboxlist_findall(NULL, buf, 1, NULL,
			 NULL, zero_cid_cb, NULL);

    conversations_commit(&state);

    return r;
}

static int build_cid_cb(const char *mboxname,
		        int matchlen __attribute__((unused)),
		        int maycreate __attribute__((unused)),
		        void *rock __attribute__((unused)))
{
    struct mailbox *mailbox = NULL;
    const struct index_record *record;
    int r;
    struct conversations_state *cstate = conversations_get_mbox(mboxname);

    if (!cstate) return IMAP_CONVERSATIONS_NOT_OPEN;

    r = mailbox_open_iwl(mboxname, &mailbox);
    if (r) return r;

    struct mailbox_iter *iter = mailbox_iter_init(mailbox, 0, ITER_SKIP_UNLINKED);
    while ((record = mailbox_iter_step(iter))) {
	/* already assigned, fine */
	if (record->cid != NULLCONVERSATION)
	    continue;

	struct index_record oldrecord = *record;
	r = mailbox_cacherecord(mailbox, &oldrecord);
	if (r) goto done;

	r = message_update_conversations(cstate, &oldrecord, NULL);
	if (r) goto done;

	r = mailbox_rewrite_index_record(mailbox, &oldrecord);
	if (r) goto done;
    }

    mailbox_iter_done(&iter);

 done:
    mailbox_close(&mailbox);
    return r;
}

static int do_build(const char *inboxname)
{
    char buf[MAX_MAILBOX_NAME];
    int r;
    struct conversations_state *state = NULL;

    r = conversations_open_mbox(inboxname, &state);

    r = build_cid_cb(inboxname, 0, 0, NULL);
    if (r) return r;

    snprintf(buf, sizeof(buf), "%s.*", inboxname);
    r = mboxlist_findall(NULL, buf, 1, NULL,
			 NULL, build_cid_cb, NULL);

    conversations_commit(&state);
    return r;
}

static int recalc_counts_cb(const char *mboxname,
			    int matchlen __attribute__((unused)),
			    int maycreate __attribute__((unused)),
			    void *rock __attribute__((unused)))
{
    struct mailbox *mailbox = NULL;
    int r;

    r = mailbox_open_irl(mboxname, &mailbox);
    if (r) return r;

    if (verbose)
	printf("%s\n", mboxname);

    r = mailbox_add_conversations(mailbox);

    mailbox_close(&mailbox);
    return r;
}

static int audit_counts_cb(const char *mboxname,
			   int matchlen __attribute__((unused)),
			   int maycreate __attribute__((unused)),
			   void *rock __attribute__((unused)))
{
    struct mailbox *mailbox = NULL;
    int r;

    r = mailbox_open_irl(mboxname, &mailbox);
    if (r) return r;

    if (verbose)
	printf("%s\n", mboxname);

    r = mailbox_add_conversations(mailbox);

    mailbox_close(&mailbox);
    return r;
}

static int do_recalc(const char *inboxname)
{
    char buf[MAX_MAILBOX_NAME];
    int r;
    struct conversations_state *state = NULL;

    r = conversations_open_mbox(inboxname, &state);
    if (r) return r;

    r = conversations_zero_counts(state);
    if (r) goto err;

    r = recalc_counts_cb(inboxname, 0, 0, NULL);
    if (r) goto err;

    snprintf(buf, sizeof(buf), "%s.*", inboxname);
    r = mboxlist_findall(NULL, buf, 1, NULL,
			 NULL, recalc_counts_cb, NULL);
    if (r) goto err;

    r = conversations_cleanup_zero(state);
    if (r) goto err;

    conversations_commit(&state);
    return 0;

err:
    conversations_abort(&state);
    return r;
}

struct cursor
{
    struct db *db;
    struct txn **txnp;
    const char *key; size_t keylen;
    const char *data; size_t datalen;
    int err;
};

static void cursor_init(struct cursor *c,
			struct db *db, struct txn **txnp)
{
    memset(c, 0, sizeof(*c));
    c->db = db;
    c->txnp = txnp;
}

static int cursor_next(struct cursor *c)
{
    if (!c->err)
	c->err = cyrusdb_fetchnext(c->db,
				   c->key, c->keylen,
				   &c->key, &c->keylen,
				   &c->data, &c->datalen,
				   c->txnp);
    return c->err;
}

static int blob_compare(const char *a, size_t alen,
			const char *b, size_t blen)
{
    int d = memcmp(a, b, MIN(alen, blen));
    if (!d)
	d = alen - blen;
    return d;
}

static int next_diffable_record(struct cursor *c)
{
    for (;;)
    {
	int r = cursor_next(c);
	if (r) return r;

	/* skip < records, they won't be in the
	 * temp database and we don't care so much */
	if (c->key[0] == '<')
	    continue;

	/* Subject, not re-calculated */
	if (c->key[0] == 'S')
	    continue;

	return 0;
    }
}

static unsigned int diff_records(struct conversations_state *a,
				 struct conversations_state *b)
{
    unsigned int ndiffs = 0;
    int ra, rb;
    struct cursor ca, cb;
    int keydelta;
    int delta;

    cursor_init(&ca, a->db, &a->txn);
    ra = cursor_next(&ca);

    cursor_init(&cb, b->db, &b->txn);
    rb = cursor_next(&cb);

    while (!ra || !rb) {
	keydelta = blob_compare(ca.key, ca.keylen, cb.key, cb.keylen);
	if (rb || keydelta < 0) {
	    if (ra) break;
	    ndiffs++;
	    if (verbose)
		printf("REALONLY: \"%.*s\" data \"%.*s\"\n",
		       (int)ca.keylen, ca.key, (int)ca.datalen, ca.data);
	    ra = next_diffable_record(&ca);
	    continue;
	}
	if (ra || keydelta > 0) {
	    if (rb) break;
	    ndiffs++;
	    if (verbose)
		printf("TEMPONLY: \"%.*s\" data \"%.*s\"\n",
		       (int)cb.keylen, cb.key, (int)cb.datalen, cb.data);
	    rb = next_diffable_record(&cb);
	    continue;
	}

	/* both exist an are the same key */
	delta = blob_compare(ca.data, ca.datalen, cb.data, cb.datalen);
	if (delta) {
	    ndiffs++;
	    if (verbose)
		printf("REAL: \"%.*s\" data \"%.*s\"\n"
		       "TEMP: \"%.*s\" data \"%.*s\"\n",
		       (int)ca.keylen, ca.key, (int)ca.datalen, ca.data,
		       (int)cb.keylen, cb.key, (int)cb.datalen, cb.data);
	}

	ra = next_diffable_record(&ca);
	rb = next_diffable_record(&cb);
    }

    return ndiffs;
}

static int fix_modseqs(struct conversations_state *a,
		       struct conversations_state *b)
{
    int ra, rb;
    struct cursor ca, cb;
    int keydelta;
    int r;

    cursor_init(&ca, a->db, &a->txn);
    ra = cursor_next(&ca);

    cursor_init(&cb, b->db, &b->txn);
    rb = cursor_next(&cb);

    while (!ra || !rb) {
	keydelta = blob_compare(ca.key, ca.keylen, cb.key, cb.keylen);
	if (rb || keydelta < 0) {
	    if (ra) break;
	    if (ca.key[0] == 'F') {
		conv_status_t status = CONV_STATUS_INIT;
		/* need to add record if it's zero */
		r = conversation_parsestatus(ca.data, ca.datalen, &status);
		if (r) return r;
		if (status.exists == 0) {
		    r = conversation_storestatus(b, ca.key, ca.keylen, &status);
		    if (r) {
			fprintf(stderr, "Failed to store conversations "
					"record \"%.*s\" to %s: %s, giving up\n",
					(int)ca.keylen, ca.key,
					b->path, error_message(r));
			return r;
		    }
		}
		/* otherwise it's a bug, so leave it in for reporting */
	    }
	    ra = cursor_next(&ca);
	    continue;
	}
	if (ra || keydelta > 0) {
	    if (rb) break;
	    rb = cursor_next(&cb);
	    continue;
	}

	/* folders?  Just modseq check */
	if (ca.key[0] == 'F') {
	    /* check if modseq is higher for real */
	    conv_status_t statusa = CONV_STATUS_INIT;
	    conv_status_t statusb = CONV_STATUS_INIT;
	    /* need to add record if it's zero */
	    r = conversation_parsestatus(ca.data, ca.datalen, &statusa);
	    if (r) {
		fprintf(stderr, "Failed to parse conversations "
				"record \"%.*s\" in %s: %s\n",
				(int)ca.keylen, ca.key,
				a->path, error_message(r));
		/* There's no need to report failure to the caller - the
		 * record diffing passing that occurs after this will
		 * also pick up the same problem */
		goto next;
	    }
	    r = conversation_parsestatus(cb.data, cb.datalen, &statusb);
	    if (r) {
		fprintf(stderr, "Failed to parse conversations "
				"record \"%.*s\" in %s: %s\n",
				(int)cb.keylen, cb.key,
				b->path, error_message(r));
		goto next;
	    }
	    if (statusa.modseq > statusb.modseq) {
		statusb.modseq = statusa.modseq;
		r = conversation_storestatus(b, cb.key, cb.keylen, &statusb);
		if (r) {
		    fprintf(stderr, "Failed to store conversations "
				    "record \"%.*s\" to %s: %s, giving up\n",
				    (int)cb.keylen, cb.key,
				    b->path, error_message(r));
		    /* If we cannot write to the temp DB, something is
		     * drastically wrong and we need to report a failure */
		    return r;
		}
	    }
	}
	if (ca.key[0] == 'B') {
	    /* B keys - check all the modseqs, both top level and per folder */
	    conversation_t *conva = NULL;
	    conversation_t *convb = NULL;
	    conv_folder_t *foldera;
	    conv_folder_t *folderb;
	    conv_sender_t *sendera;

	    r = conversation_parse(a, ca.data, ca.datalen, &conva);
	    if (r) {
		fprintf(stderr, "Failed to parse conversations "
				"record \"%.*s\" in %s: %s\n",
				(int)ca.keylen, ca.key,
				a->path, error_message(r));
		goto next;
	    }
	    r = conversation_parse(b, cb.data, cb.datalen, &convb);
	    if (r) {
		fprintf(stderr, "Failed to parse conversations "
				"record \"%.*s\" in %s: %s\n",
				(int)cb.keylen, cb.key,
				b->path, error_message(r));
		conversation_free(conva);
		goto next;
	    }

	    /* because expunged messages could have had higher modseqs,
	     * we need to re-copy any higher modseqs in */
	    if (conva->modseq > convb->modseq)
		convb->modseq = conva->modseq;

	    for (foldera = conva->folders; foldera; foldera = foldera->next) {
		folderb = conversation_get_folder(convb, foldera->number, 1);
		if (folderb->modseq < foldera->modseq)
		    folderb->modseq = foldera->modseq;
	    }

	    /* senders are timestamped, and the timestamp might be for a
	     * deleted message! */
	    for (sendera = conva->senders; sendera; sendera = sendera->next) {
		/* always update!  The delta logic will ensure we don't add
		 * the record if it's not already at least present in the
		 * other conversation */
		conversation_update_sender(convb, sendera->name, sendera->route,
					   sendera->mailbox, sendera->domain,
					   sendera->lastseen, /*delta_count*/0);
	    }

	    /* be nice to know if this is needed, but at least twoskip
	     * will dedup for us */
	    r = conversation_store(b, cb.key, cb.keylen, convb);

	    /* free first before checking for errors */
	    conversation_free(conva);
	    conversation_free(convb);

	    if (r) {
		fprintf(stderr, "Failed to store conversations "
				"record \"%.*s\" to %s: %s, giving up\n",
				(int)cb.keylen, cb.key,
				b->path, error_message(r));
		return r;
	    }
	}

next:
	ra = cursor_next(&ca);
	rb = cursor_next(&cb);
    }

    return 0;
}

int do_checkfolders(const char *inboxname)
{
    int r;
    struct conversations_state *state = NULL;
    strarray_t *copy1, *copy2;

    /* open the DB */
    r = conversations_open_mbox(inboxname, &state);
    if (r) {
	fprintf(stderr, "Cannot open conversations db %s: %s\n",
		inboxname, error_message(r));
	goto out;
    }

    /* don't mess with the original */
    copy1 = strarray_dup(state->folder_names);
    /* remove empty folders first, they will duplicate for sure */
    strarray_remove_all(copy1, "-");
    copy2 = strarray_dup(copy1);
    strarray_sort(copy2, cmpstringp_raw);
    strarray_uniq(copy2);
    if (copy1->count != copy2->count) {
	printf("DUPLICATE %s\n", inboxname);
    }
    else {
	printf("OK %s\n", inboxname);
    }
    strarray_free(copy1);
    strarray_free(copy2);

out:
    conversations_abort(&state);
    return r;
}

static int do_audit(const char *inboxname)
{
    char buf[MAX_MAILBOX_NAME];
    int r;
    char temp_suffix[64];
    char *filename_temp = NULL;
    char *filename_real = NULL;
    struct conversations_state *state_temp = NULL;
    struct conversations_state *state_real = NULL;
    unsigned int ndiffs = 0;

    if (verbose)
	printf("Inbox %s\n", inboxname);

    if (verbose)
	printf("Pass 1: recalculate counts into temporary db\n");

    /* Generate a unique suffix for the temp db */
    snprintf(temp_suffix, sizeof(temp_suffix),
	     "conversations.audit.%d", (int)getpid());

    /* Get the filenames */
    filename_real = conversations_getmboxpath(inboxname);
    conversations_set_suffix(temp_suffix);
    conversations_set_directory(audit_temp_directory);
    filename_temp = conversations_getmboxpath(inboxname);
    conversations_set_suffix(NULL);
    conversations_set_directory(NULL);
    assert(strcmp(filename_temp, filename_real));

    /* Initialise the temp copy of the database */
    unlink(filename_temp);
    r = cyrusdb_copyfile(filename_real, filename_temp);
    if (r) {
	fprintf(stderr, "Cannot make temp copy of conversations db %s: %s\n",
		filename_real, error_message(r));
	goto out;
    }

    /* Begin recalculating in the temp db */
    r = conversations_open_path(filename_temp, &state_temp);
    if (r) {
	fprintf(stderr, "Cannot open conversations db %s: %s\n",
		filename_temp, error_message(r));
	goto out;
    }

    r = conversations_zero_counts(state_temp);
    if (r) {
	fprintf(stderr, "Failed to zero counts in %s: %s\n",
		filename_temp, error_message(r));
	goto out;
    }

    /*
     * Set the conversations db suffix during the recalc pass, so that
     * calls to conversations_open_mbox() from the mailbox code get
     * redirected to the temporary db.
     */
    conversations_set_suffix(temp_suffix);
    conversations_set_directory(audit_temp_directory);

    r = audit_counts_cb(inboxname, 0, 0, NULL);
    if (r) {
	fprintf(stderr, "Failed to recalculate counts in %s: %s\n",
		filename_temp, error_message(r));
	goto out;
    }

    snprintf(buf, sizeof(buf), "%s.*", inboxname);
    r = mboxlist_findall(NULL, buf, 1, NULL,
			 NULL, audit_counts_cb, NULL);
    if (r) {
	fprintf(stderr, "Failed to recalculate counts in %s: %s\n",
		filename_temp, error_message(r));
	goto out;
    }

    r = conversations_cleanup_zero(state_temp);
    if (r) {
	fprintf(stderr, "Failed to cleanup zero counts in %s: %s\n",
		filename_temp, error_message(r));
	goto out;
    }

    conversations_set_suffix(NULL);
    conversations_set_directory(NULL);

    r = conversations_commit(&state_temp);
    if (r) {
	fprintf(stderr, "Cannot commit conversations db %s: %s\n",
		filename_temp, error_message(r));
	goto out;
    }

    if (verbose)
	printf("Pass 2: find differences from recalculated to live dbs\n");

    r = conversations_open_path(filename_temp, &state_temp);
    if (r) {
	fprintf(stderr, "Cannot open conversations db %s: %s\n",
		filename_temp, error_message(r));
	goto out;
    }

    r = conversations_open_path(filename_real, &state_real);
    if (r) {
	fprintf(stderr, "Cannot open conversations db %s: %s\n",
		filename_real, error_message(r));
	goto out;
    }

    r = fix_modseqs(state_real, state_temp);
    if (r) {
	/* Error reported in fix_modseqs() */
	goto out;
    }

    ndiffs += diff_records(state_real, state_temp);
    if (ndiffs)
	printf("%s is BROKEN (%u differences)\n", inboxname, ndiffs);
    else if (verbose)
	printf("%s is OK\n", inboxname);

out:
    if (state_temp)
	conversations_abort(&state_temp);
    if (state_real)
	conversations_abort(&state_real);
    conversations_set_suffix(NULL);
    conversations_set_directory(NULL);
    if (filename_temp)
	unlink(filename_temp);
    free(filename_temp);
    free(filename_real);
    return r;
}

static int usage(const char *name)
    __attribute__((noreturn));

static int do_user(const char *userid)
{
    char *inboxname;
    char *fname;
    int r = 0;

    fname = conversations_getuserpath(userid);
    if (fname == NULL) {
	fprintf(stderr, "Unable to get conversations database "
			"filename for userid \"%s\"\n",
			userid);
	return EC_USAGE;
    }

    inboxname = mboxname_user_mbox(userid, NULL);
    if (inboxname == NULL) {
	free(fname);
	fprintf(stderr, "Invalid userid %s", userid);
	return EC_USAGE;
    }

    switch (mode)
    {
    case DUMP:
	if (do_dump(fname))
	    r = EC_NOINPUT;
	break;

    case UNDUMP:
	if (do_undump(fname))
	    r = EC_NOINPUT;
	break;

    case ZERO:
	if (do_zero(inboxname))
	    r = EC_NOINPUT;
	break;

    case BUILD:
	if (do_build(inboxname))
	    r = EC_NOINPUT;
	break;

    case RECALC:
	if (do_recalc(inboxname))
	    r = EC_NOINPUT;
	break;

    case AUDIT:
	if (do_audit(inboxname))
	    r = EC_NOINPUT;
	break;

    case CHECKFOLDERS:
	if (do_checkfolders(inboxname))
	    r = EC_NOINPUT;
	break;

    case UNKNOWN:
	fatal("UNKNOWN MODE", EC_SOFTWARE);
    }

    free(fname);
    free(inboxname);

    return r;
}

static int do_mailbox(char *name,
		      int namelen,
		      int maycreate __attribute__((unused)),
		      void *rock __attribute__((unused)))
{
    char *mboxname = xstrndup(name, namelen);
    const char *userid = mboxname_to_userid(mboxname);

    if (mboxname_isdeletedmailbox(mboxname, NULL))
	goto done;

    if (userid && strcmp(userid, prev_userid)) {
	printf("%s\n", userid);
	do_user(userid);
	free(prev_userid);
	prev_userid = xstrdup(userid);
    }

done:
    free(mboxname);

    return 0;
}

int main(int argc, char **argv)
{
    int c;
    const char *alt_config = NULL;
    const char *userid = NULL;
    int r = 0;
    int recursive = 0;

    if ((geteuid()) == 0 && (become_cyrus(/*ismaster*/0) != 0)) {
	fatal("must run as the Cyrus user", EC_USAGE);
    }

    while ((c = getopt(argc, argv, "durzAbvRFC:T:")) != EOF) {
	switch (c) {
	case 'd':
	    if (mode != UNKNOWN)
		usage(argv[0]);
	    mode = DUMP;
	    break;

	case 'r':
	    recursive = 1;
	    break;

	case 'u':
	    if (mode != UNKNOWN)
		usage(argv[0]);
	    mode = UNDUMP;
	    break;

	case 'z':
	    if (mode != UNKNOWN)
		usage(argv[0]);
	    mode = ZERO;
	    break;

	case 'b':
	    if (mode != UNKNOWN)
		usage(argv[0]);
	    mode = BUILD;
	    break;

	case 'R':
	    if (mode != UNKNOWN)
		usage(argv[0]);
	    mode = RECALC;
	    break;

	case 'A':
	    if (mode != UNKNOWN)
		usage(argv[0]);
	    mode = AUDIT;
	    break;

	case 'F':
	    if (mode != UNKNOWN)
		usage(argv[0]);
	    mode = CHECKFOLDERS;
	    break;

	case 'v':
	    verbose++;
	    break;

	case 'C': /* alt config file */
	    alt_config = optarg;
	    break;

	case 'T': /* tmpfs directory for audit */
	    audit_temp_directory = optarg;
	    break;

	default:
	    usage(argv[0]);
	    break;
	}
    }

    if (mode == UNKNOWN)
	usage(argv[0]);

    if (optind == argc-1)
	userid = argv[optind];
    else if (recursive)
	userid = "";
    else
	usage(argv[0]);

    cyrus_init(alt_config, "ctl_conversationsdb", 0, 0);

    mboxlist_init(0);
    mboxlist_open(NULL);

    sync_log_init();

    if (recursive) {
	char *buf = xmalloc(strlen(userid) + 2);
	prev_userid = xstrdup("");
	strcpy(buf, userid);
	strcat(buf, "*");

	if ((r = mboxname_init_namespace(&conv_namespace, 1)) != 0) {
	    syslog(LOG_ERR, "%s", error_message(r));
	    fatal(error_message(r), EC_CONFIG);
	}

	(*conv_namespace.mboxlist_findall)(&conv_namespace, buf, 1, 0, 0,
					   do_mailbox, NULL);

	free(prev_userid);
	free(buf);
    }
    else
	do_user(userid);

    sync_log_done();

    mboxlist_close();
    mboxlist_done();

    cyrus_done();

    return r;
}

static int usage(const char *name)
{
    fprintf(stderr, "usage: %s [options] [-u|-d|-z|-f] [-r] username\n", name);
    fprintf(stderr, "\n");
    fprintf(stderr, "options are:\n");
    fprintf(stderr, "    -v             be more verbose\n");
    fprintf(stderr, "    -C altconfig   use altconfig instead of imapd.conf\n");
    fprintf(stderr, "    -u             undump the conversations database from stdin\n");
    fprintf(stderr, "    -d             dump the conversations database to stdout\n");
    fprintf(stderr, "    -z             zero the conversations DB (make all NULLs)\n");
    fprintf(stderr, "    -b             build conversations entries for any NULL records\n");
    fprintf(stderr, "    -R             recalculate all counts\n");
    fprintf(stderr, "    -A             audit conversations DB counts\n");
    fprintf(stderr, "    -F             check folder names\n");
    fprintf(stderr, "    -T dir         store temporary data for audit in dir\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "    -r             recursive mode: username is a prefix\n");

    exit(EC_USAGE);
}

void fatal(const char* s, int code)
{
    fprintf(stderr, "ctl_conversationsdb: %s\n", s);
    cyrus_done();
    exit(code);
}

