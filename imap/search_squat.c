/* search_squat.c -- glue code for searching via SQUAT
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

#include <config.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <syslog.h>
#include <string.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "index.h"
#include "global.h"
#include "xmalloc.h"
#include "xstrlcpy.h"
#include "xstrlcat.h"
#include "bitvector.h"

#include "imap_err.h"
#include "search_engines.h"
#include "squat.h"

typedef struct {
    bitvector_t		*vector;
    struct index_state	*state;
    const char		*part_types;
    int			found_validity;
} SquatSearchResult;

/* The document name is of the form

   pnnn.vvv

   Where p is a part_type character (denoting which segment of the message
   is represented by the document), nnn is the UID of the message, and vvv
   is the UID validity value.

   This function parses the document name and returns the message
   UID only if the name has the right part type and it corresponds
   to a real message UID.
*/
static int parse_doc_name(SquatSearchResult *r, const char *doc_name)
{
    int ch = doc_name[0];
    const char *t = r->part_types;
    int doc_UID, index;

    if (ch == 'v' && strncmp(doc_name, "validity.", 9) == 0) {
	if ((unsigned) atoi(doc_name + 9) == r->state->mailbox->i.uidvalidity) {
	    r->found_validity = 1;
	}
	return -1;
    }

    /* make sure that the document part type is one of the ones we're
     accepting */
    while (*t != 0 && *t != ch) {
	t++;
    }
    if (*t == 0) {
	return -1;
    }

    doc_UID = atoi(++doc_name);
    while ((*doc_name >= '0' && *doc_name <= '9') || *doc_name == '-') {
	++doc_name;
    }
    if (*doc_name != 0) {
	return -1;
    }

    index = index_finduid(r->state, doc_UID);
    if (index >= 0 && index_getuid(r->state, index) != (unsigned)doc_UID)
	index = -1;

    return index;
}

static int drop_indexed_docs(void* closure, const SquatListDoc *doc)
{
    SquatSearchResult* r = (SquatSearchResult*)closure;
    int doc_uid = parse_doc_name(r, doc->doc_name);

    if (doc_uid >= 0)
	bv_clear(r->vector, doc_uid);
    return SQUAT_CALLBACK_CONTINUE;
}

static int fill_with_hits(void* closure, char const* doc)
{
    SquatSearchResult* r = (SquatSearchResult*)closure;
    int doc_uid = parse_doc_name(r, doc);

    if (doc_uid >= 0)
	bv_set(r->vector, doc_uid);
    return SQUAT_CALLBACK_CONTINUE;
}

static int search_strlist(SquatSearchIndex* index, struct index_state *state,
			  bitvector_t *output, bitvector_t *tmp,
			  struct strlist* strs, char const* part_types)
{
    SquatSearchResult r;

    r.part_types = part_types;
    r.vector = tmp;
    r.state = state;
    while (strs != NULL) {
	char const* s = strs->s;

	bv_clearall(tmp);
	if (squat_search_execute(index, s, strlen(s), fill_with_hits, &r)
	    != SQUAT_OK) {
	    if (squat_get_last_error() == SQUAT_ERR_SEARCH_STRING_TOO_SHORT)
		return 1; /* The rest of the search is still viable */
	    syslog(LOG_DEBUG, "SQUAT string list search failed on string %s "
			      "with part types %s", s, part_types);
	    return 0;
	}
	bv_andeq(output, tmp);

	strs = strs->next;
    }
    return 1;
}

static int search_squat_do_query(SquatSearchIndex* index,
				 struct index_state *state,
				 const struct searchargs* args,
				 bitvector_t *vect)
{
    bitvector_t t_vect = BV_INITIALIZER;
    bitvector_t sub1_vect = BV_INITIALIZER;
    bitvector_t sub2_vect = BV_INITIALIZER;
    struct searchsub* sub;
    int found_something = 1;

    bv_setsize(vect, state->exists);
    bv_setall(vect);
    bv_setsize(&t_vect, state->exists);

    if (!(search_strlist(index, state, vect, &t_vect, args->to, "t")
	&& search_strlist(index, state, vect, &t_vect, args->from, "f")
	&& search_strlist(index, state, vect, &t_vect, args->cc, "c")
	&& search_strlist(index, state, vect, &t_vect, args->bcc, "b")
	&& search_strlist(index, state, vect, &t_vect, args->subject, "s")
	&& search_strlist(index, state, vect, &t_vect, args->header_name, "h")
	&& search_strlist(index, state, vect, &t_vect, args->header, "h")
	&& search_strlist(index, state, vect, &t_vect, args->body, "m")
	&& search_strlist(index, state, vect, &t_vect, args->text, "mh"))) {
	found_something = 0;
	goto cleanup;
    }

    sub = args->sublist;
    while (sub != NULL) {
	if (args->sublist->sub2 == NULL) {
	    /* do nothing; because our search is conservative (may include false
	       positives) we can't compute the NOT (since the result might include
	       false negatives, which we do not allow) */
	    /* Note that it's OK to do nothing. We'll just be returning more
	       false positives. */
	} else {
	    if (!search_squat_do_query(index, state,
				       args->sublist->sub1, &sub1_vect)) {
		found_something = 0;
		goto cleanup;
	    }

	    if (!search_squat_do_query(index, state,
				       args->sublist->sub2, &sub2_vect)) {
		found_something = 0;
		goto cleanup;
	    }

	    bv_oreq(&sub1_vect, &sub2_vect);
	    bv_oreq(vect, &sub1_vect);
	}

	sub = sub->next;
    }

cleanup:
    bv_free(&t_vect);
    bv_free(&sub1_vect);
    bv_free(&sub2_vect);
    return found_something;
}

static int search_squat(unsigned* msg_list, struct index_state *state,
			const struct searchargs *searchargs)
{
    char *fname;
    int fd;
    SquatSearchIndex* index;
    bitvector_t msg_vector = BV_INITIALIZER;
    int result;

    fname = mailbox_meta_fname(state->mailbox, META_SQUAT);
    if ((fd = open(fname, O_RDONLY)) < 0) {
	syslog(LOG_DEBUG, "SQUAT failed to open index file");
	return -1;   /* probably not found. Just bail */
    }
    if ((index = squat_search_open(fd)) == NULL) {
	syslog(LOG_DEBUG, "SQUAT failed to open index");
	close(fd);
	return -1;
    }
    if (!search_squat_do_query(index, state, searchargs, &msg_vector)) {
	result = -1;
    } else {
	unsigned i;
	bitvector_t unindexed_vector = BV_INITIALIZER;
	SquatSearchResult r;

	bv_setsize(&unindexed_vector, state->exists);
	bv_setall(&unindexed_vector);
	r.vector = &unindexed_vector;
	r.state = state;
	r.part_types = "tfcbsmh";
	r.found_validity = 0;
	if (squat_search_list_docs(index, drop_indexed_docs, &r) != SQUAT_OK) {
	    syslog(LOG_DEBUG, "SQUAT failed to get list of indexed documents");
	    result = -1;
	} else if (!r.found_validity) {
	    syslog(LOG_DEBUG, "SQUAT didn't find validity record");
	    result = -1;
	} else {
	    /* Add in any unindexed messages. They must be searched manually. */
	    bv_oreq(&msg_vector, &unindexed_vector);

	    result = 0;
	    for (i = 1; i <= state->exists; i++) {
		if (bv_isset(&msg_vector, i)) {
		    msg_list[result] = i;
		    result++;
		}
	    }
	}
	bv_free(&unindexed_vector);
    }
    bv_free(&msg_vector);
    squat_search_close(index);
    close(fd);
    return result;
}


/*
  SQUAT index files are organised as follows:

  There is (at most) one index file for each Cyrus mailbox, named
  "cyrus.squat", stored in the mailbox directory.

  Source documents are named 'xUID' where UID is the numeric UID of a
  message and x is a character denoting a part of the message: 'f' ==
  FROM, 't' == TO, 'b' == BCC, 'c' == CC, 's' == SUBJECT, 'h' == other
  headers, 'm' == the body. So, a message with UID 331 could give rise
  to several source documents named "f331", "t331", "b331", "c331",
  "s331", "h331"  and "m331".

  There is also a special source document named "validity.N" where N
  is the uidvalidity nonce for the mailbox. We use this to detect when
  the UIDs have been renumbered since we created the index (in which
  case the index is useless and is ignored).

  Updating creates new indexes for one or more mailboxes. (We do not
  support true incremental updates to an index yet.) The index is created
  in "cyrus.squat.tmp" and then, if creation was successful, it is
  atomically renamed to "cyrus.squat". This guarantees that we don't
  interfere with anyone who has the old index open.
*/

/* These stats are gathered 1) per mailbox and 2) for the whole operation. */
typedef struct {
  unsigned long indexed_bytes;    /* How many bytes of processed message text
			   have we indexed? */
  unsigned long indexed_messages; /* How many messages have we indexed? */
  unsigned long index_size;       /* How many bytes is the index using? */
  time_t start_time;    /* When did this operation start? */
  time_t end_time;      /* When did it end? */
} SquatStats;

typedef struct {
    search_text_receiver_t super;
    int verbose;
    SquatStats mailbox_stats;
    SquatStats total_stats;
    SquatIndex *index;
    int fd;
    SquatSearchIndex *old_index;
    int old_fd;
    struct mailbox *mailbox;
    int valid;
    uint32_t uidvalidity;
    unsigned int mailbox_count;
    /* Tracks which UIDs were indexed in the old
     * index (or all 0 if a full update) */
    bitvector_t indexed;
    uint32_t uid;
    int doc_is_open;
    char doc_name[100];
    struct buf pending_text;
} SquatReceiverData;

static void start_stats(SquatStats *stats)
{
    stats->index_size = 0;
    stats->indexed_bytes = 0;
    stats->indexed_messages = 0;
    stats->start_time = time(NULL);
}

static void stop_stats(SquatStats *stats)
{
    stats->end_time = time(NULL);
}

static void print_stats(const char *which, const SquatStats *stats)
{
    syslog(LOG_NOTICE, "squat: %s indexed %lu messages (%lu bytes) "
	    "into %lu index bytes in %d seconds\n",
	    which,
	    stats->indexed_messages,
	    stats->indexed_bytes,
	    stats->index_size,
	    (int)(stats->end_time - stats->start_time));
}

static const char *squat_strerror(int err)
{
    static char buf[64];

    switch (err) {
    case SQUAT_ERR_SYSERR:
	return strerror(errno);
    default:
	/* There are other error codes, but they only apply for searching,
	   not index construction */
	snprintf(buf, sizeof(buf), "unknown squat error %d", err);
	return buf;
    }
}

/* Cyrus passes the text to index in here, after it has canonicalized
   the text. We figure out what source document the text belongs to,
   and update the index. */
static void begin_message(search_text_receiver_t *rx, uint32_t uid)
{
    SquatReceiverData *d = (SquatReceiverData *) rx;

    d->uid = uid;
    d->doc_is_open = 0;
    d->doc_name[0] = '\0';
    buf_init(&d->pending_text);

    d->mailbox_stats.indexed_messages++;
    d->total_stats.indexed_messages++;
}

static void begin_part(search_text_receiver_t *rx, int part)
{
    SquatReceiverData *d = (SquatReceiverData *) rx;
    char part_char = 0;

    /* Figure out what the name of the source document is going to be. */
    switch (part) {
    case SEARCH_PART_FROM: part_char = 'f'; break;
    case SEARCH_PART_TO: part_char = 't'; break;
    case SEARCH_PART_CC: part_char = 'c'; break;
    case SEARCH_PART_BCC: part_char = 'b'; break;
    case SEARCH_PART_SUBJECT: part_char = 's'; break;
    case SEARCH_PART_HEADERS: part_char = 'h'; break;
    case SEARCH_PART_BODY:
	part_char = 'm';
	break;
    default:
	return;
    }

    snprintf(d->doc_name, sizeof(d->doc_name), "%c%d", part_char, d->uid);
    d->doc_is_open = 0;
    buf_reset(&d->pending_text);

    /* The document will be opened lazily later, once we have
     * accumulated more than the minimum amount of text */
}

static int do_append(SquatReceiverData *d, const struct buf *text)
{
    int s;	    /* SQUAT error */

    if (d->verbose > 3)
	syslog(LOG_ERR, "squat: writing %d bytes into message %d\n",
	       text->len, d->uid);

    s = squat_index_append_document(d->index, text->s, text->len);
    if (s != SQUAT_OK) {
	syslog(LOG_ERR, "squat: error writing index data "
			"for mailbox %s uid %u: %s",
			d->mailbox->name, d->uid,
			squat_strerror(s));
	return IMAP_IOERROR;
    }
    d->mailbox_stats.indexed_bytes += text->len;
    d->total_stats.indexed_bytes += text->len;
    return 0;
}

static void append_text(search_text_receiver_t *rx,
			const struct buf *text)
{
    SquatReceiverData *d = (SquatReceiverData *) rx;
    int r = 0;	    /* IMAP error */
    int s = 0;	    /* SQUAT error */

    if (!d->doc_is_open) {
	if (text->len + d->pending_text.len < SQUAT_WORD_SIZE) {
	    /* not enough text yet */
	    buf_append(&d->pending_text, text);
	    return;
	}

	/* just went over the threshold */
	if (d->verbose > 2)
	    syslog(LOG_NOTICE, "squat: opening document part '%s'\n",
		    d->doc_name);

	s = squat_index_open_document(d->index, d->doc_name);
	if (s != SQUAT_OK) {
	    syslog(LOG_ERR, "squat: error opening document %s "
			    "for mailbox %s: %s",
			    d->doc_name, d->mailbox->name,
			    squat_strerror(s));
	    return;
	}
	d->doc_is_open = 1;

	/* flush any pending text */
	if (d->pending_text.len)
	    r = do_append(d, &d->pending_text);
	buf_reset(&d->pending_text);
    }

    if (!r)
	r = do_append(d, text);

    /* TODO: propagate an error to the caller */
}

static void end_part(search_text_receiver_t *rx,
		     int part __attribute__((unused)))
{
    SquatReceiverData *d = (SquatReceiverData *) rx;
    int s = 0;	    /* SQUAT error */

    if (d->doc_is_open) {
	s = squat_index_close_document(d->index);
	if (s != SQUAT_OK) {
	    syslog(LOG_ERR, "squat: error closing document %s "
			    "for mailbox %s uid %u: %s",
			    d->doc_name, d->mailbox->name,
			    d->uid, squat_strerror(s));
	    return;
	}
    }
    d->doc_is_open = 0;
    buf_reset(&d->pending_text);
}

static void end_message(search_text_receiver_t *rx,
			uint32_t uid __attribute__((unused)))
{
    SquatReceiverData *d = (SquatReceiverData *) rx;

    d->uid = 0;
}

/* Let SQUAT tell us what's going on in the expensive
   squat_index_finish function. */
static void stats_callback(void *closure,
			   SquatStatsEvent *params)
{
    SquatReceiverData *d = (SquatReceiverData *)closure;

    switch (params->generic.type) {
    case SQUAT_STATS_COMPLETED_INITIAL_CHAR:
	if (d->verbose > 1) {
	    if (params->completed_initial_char.num_words > 0) {
		printf("Processing index character %d, %d total words, "
		       "temp file size is %d\n",
		       params->completed_initial_char.completed_char,
		       params->completed_initial_char.num_words,
		       params->completed_initial_char.temp_file_size);
	    }
	}
	break;

    default:
	;			/* do nothing */
    }
}

/* Populate d->indexed map using document names from SquatSearchIndex backend */
static int doc_check(void *closure, const SquatListDoc *doc)
{
    SquatReceiverData *d = (SquatReceiverData *)closure;
    unsigned long uid;

    /* validity will be replaced with new value in same slot */
    if (!strncmp(doc->doc_name, "validity.", 9)) {
	d->uidvalidity = strtoul(doc->doc_name + 9, NULL, 10);
	return (1);
    }

    if (!strchr("tfcbsmh", doc->doc_name[0])) {
	syslog(LOG_ERR, "squat: invalid document name: %s", doc->doc_name);
	d->valid = 0;
	/* TODO: is this right?? */
	return (1);
    }

    uid = strtoul(doc->doc_name + 1, NULL, 10);
    if (uid > 0) {
	bv_set(&d->indexed, uid);
	return (1);
    }

    /* Remove this UID from the index */
    return (0);
}

static int begin_mailbox(search_text_receiver_t *rx,
			 struct mailbox *mailbox,
			 int incremental)
{
    SquatReceiverData *d = (SquatReceiverData *)rx;
    SquatOptions options;
    const char *filename;
    const char *old_filename;
    int fd = -1;
    int old_fd = -1;
    SquatIndex *index = NULL;
    SquatSearchIndex *old_index = NULL;
    int r = 0;	    /* IMAP error code */
    int s = 0;	    /* SQUAT error code */

    bv_clearall(&d->indexed);

    filename = mailbox_meta_newfname(mailbox, META_SQUAT);
    if ((fd = open(filename, O_CREAT | O_TRUNC | O_WRONLY, 0666)) < 0) {
	syslog(LOG_ERR, "squat: unable to create temporary index file %s: %m",
	       filename);
	r = IMAP_IOERROR;
	goto out;
    }

    options.option_mask = SQUAT_OPTION_TMP_PATH | SQUAT_OPTION_STATISTICS;
    options.tmp_path = mailbox_datapath(mailbox);
    options.stats_callback = stats_callback;
    options.stats_callback_closure = (void *)d;
    index = squat_index_init(fd, &options);
    if (index == NULL) {
	syslog(LOG_ERR, "squat: unable to initialise index %s: %s",
	       filename, squat_strerror(squat_get_last_error()));
	r = IMAP_IOERROR;
	goto out;
    }

    /* Open existing index if it exists */
    old_filename = mailbox_meta_fname(mailbox, META_SQUAT);
    if (incremental) {
	old_fd = open(old_filename, O_RDONLY);
	/* Silently ignore errors opening the old fd or index
	 * and fall back to a full update.  Probably should
	 * NOT be silent if the error is anything other than
	 * a missing index. */
	if (old_fd >= 0)
	    old_index = squat_search_open(old_fd);
	if (old_index == NULL)
	    incremental = 0;
    }

    if (incremental) {
	/* Copy existing document names verbatim. They end up with the same
	 * doc_IDs as in the old index, which makes trie copying much simpler.
	 */
	d->valid = 1;
	d->uidvalidity = 0L;
	squat_index_add_existing(index, old_index, doc_check, d);

	if (!d->valid) {
	    syslog(LOG_ERR, "squat: corrupt old index for mailbox %s, "
			    "forcing full update",
			    mailbox->name);
	    incremental = 0;
	}

	if (incremental &&
	    d->uidvalidity != mailbox->i.uidvalidity) {
	    /* Squat file refers to old mailbox: force full rebuild */
	    syslog(LOG_ERR, "squat: mailbox %s uidvalidity changed "
			    "from %u to %u, forcing full update",
			    mailbox->name,
			    mailbox->i.uidvalidity,
			    d->uidvalidity);
	    incremental = 0;
	}
    }

    if (!incremental) {
	bv_clearall(&d->indexed);

	/* write an empty document at the beginning to record the validity
	   nonce */
	snprintf(d->doc_name, sizeof(d->doc_name),
		 "validity.%u", mailbox->i.uidvalidity);
	s = squat_index_open_document(index, d->doc_name);
	if (s != SQUAT_OK) {
	    syslog(LOG_ERR, "squat: cannot write uidvalidity nonce: %s",
		   squat_strerror(s));
	    r = IMAP_IOERROR;
	    goto out;
	}
	s = squat_index_close_document(index);
	if (s != SQUAT_OK) {
	    syslog(LOG_ERR, "squat: cannot close document for "
			    "uidvalidity nonce: %s",
			    squat_strerror(s));
	    r = IMAP_IOERROR;
	    goto out;
	}
    }

out:
    /* it isn't obvious, but we need to keep old_index and old_fd
     * around until after new_index has been finished. */
    if (r) {
	if (index != NULL) squat_index_destroy(index);
	d->index = NULL;
	if (fd >= 0) close(fd);
	d->fd = -1;

	if (old_index != NULL) squat_search_close(old_index);
	d->old_index = NULL;
	if (old_fd >= 0) close(old_fd);
	d->old_fd = -1;

	d->mailbox = NULL;
    }
    else {
	d->index = index;
	d->fd = fd;

	d->old_index = old_index;
	d->old_fd = old_fd;

	d->mailbox = mailbox;
	start_stats(&d->mailbox_stats);
    }
    return r;
}

static int is_indexed(search_text_receiver_t *rx, uint32_t uid)
{
    SquatReceiverData *d = (SquatReceiverData *)rx;

    return bv_isset(&d->indexed, uid);
}

static int end_mailbox(search_text_receiver_t *rx,
		       struct mailbox *mailbox
			    __attribute__((unused)))
{
    SquatReceiverData *d = (SquatReceiverData *)rx;
    struct stat sb;
    int r = 0;	    /* IMAP error code or syscall return */
    int s = 0;	    /* SQUAT error code */

    if (!d->index)
	return 0;

    s = squat_index_finish(d->index);
    if (s != SQUAT_OK) {
	syslog(LOG_ERR,
	       "squat: failed to close index for mailbox %s (error %d)",
	       d->mailbox->name, s);
	r = IMAP_IOERROR;
	goto out;
    }

    /* Check how big the resulting file is */
    if (fstat(d->fd, &sb) < 0) {
	syslog(LOG_ERR, "squat: unable to stat temporary index file: %m");
	r = IMAP_IOERROR;
	goto out;
    }
    d->mailbox_stats.index_size = sb.st_size;
    d->total_stats.index_size += sb.st_size;

    r = close(d->fd);
    d->fd = -1;
    if (r < 0) {
	/* This isn't going to happen unless we're on NFS */
	syslog(LOG_ERR, "squat: unable to complete writing "
			"temporary index file: %m");
	r = IMAP_IOERROR;
	goto out;
    }

    /* OK, we successfully created the index under the temporary file name.
       Let's rename it to make it the real index. */
    r = mailbox_meta_rename(d->mailbox, META_SQUAT);
    if (r) goto out;

    if (d->verbose) {
	stop_stats(&d->mailbox_stats);
	print_stats(d->mailbox->name, &d->mailbox_stats);
    }
    d->mailbox_count++;
    r = 0;

out:
    if (d->old_index) squat_search_close(d->old_index);
    d->old_index = NULL;
    if (d->old_fd >= 0) close(d->old_fd);
    d->old_fd = -1;

    d->index = NULL;
    if (d->fd >= 0) close(d->fd);
    d->fd = -1;

    d->mailbox = NULL;
    return r;
}

static search_text_receiver_t *begin_update(int verbose)
{
    SquatReceiverData *d;

    d = xzmalloc(sizeof(SquatReceiverData));
    d->super.begin_mailbox = begin_mailbox;
    d->super.is_indexed = is_indexed;
    d->super.begin_message = begin_message;
    d->super.begin_part = begin_part;
    d->super.append_text = append_text;
    d->super.end_part = end_part;
    d->super.end_message = end_message;
    d->super.end_mailbox = end_mailbox;

    d->fd = -1;
    d->verbose = verbose;

    start_stats(&d->total_stats);

    return &d->super;
}

static int end_update(search_text_receiver_t *rx)
{
    SquatReceiverData *d = (SquatReceiverData *)rx;

    if (d->verbose && d->mailbox_count > 1) {
	stop_stats(&d->total_stats);
	print_stats("Total", &d->total_stats);
    }

    bv_free(&d->indexed);
    free(d);
    return 0;
}

const struct search_engine squat_search_engine = {
    "SQUAT",
    0,
    search_squat,
    begin_update,
    end_update,
    /* start_daemon */NULL,
    /* stop_daemon */NULL
};

