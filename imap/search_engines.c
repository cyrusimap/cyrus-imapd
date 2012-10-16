/* search_engines.c -- Prefiltering routines for SEARCH
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

#include <sys/types.h>
#include <stdlib.h>
#include <syslog.h>
#include <string.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "imap_err.h"
#include "index.h"
#include "message.h"
#include "global.h"
#include "search_engines.h"

#ifdef USE_SQUAT
extern const struct search_engine squat_search_engine;
#endif
#ifdef USE_SPHINX
extern const struct search_engine sphinx_search_engine;
#endif

static const struct search_engine default_search_engine = {
    "default",
    0,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
};

static const struct search_engine *engine(void)
{
    switch (config_getenum(IMAPOPT_SEARCH_ENGINE)) {
#ifdef USE_SPHINX
    case IMAP_ENUM_SEARCH_ENGINE_SPHINX:
	return &sphinx_search_engine;
#endif
#ifdef USE_SQUAT
    case IMAP_ENUM_SEARCH_ENGINE_SQUAT:
	return &squat_search_engine;
#endif
    default:
	return &default_search_engine;
    }
}

EXPORTED const char *search_part_as_string(int part)
{
    static const char *names[SEARCH_NUM_PARTS] = {
	/* ANY */NULL, "FROM", "TO", "CC",
	"BCC", "SUBJECT", "HEADERS", "BODY"
    };

    return (part < 0 || part >= SEARCH_NUM_PARTS ? NULL : names[part]);
}


EXPORTED search_builder_t *search_begin_search(struct mailbox *mailbox, int opts)
{
    const struct search_engine *se = engine();
    return (se->begin_search ?
	    se->begin_search(mailbox, opts) : NULL);
}

EXPORTED void search_end_search(search_builder_t *bx)
{
    const struct search_engine *se = engine();
    if (se->end_search) se->end_search(bx);
}

EXPORTED search_text_receiver_t *search_begin_update(int verbose)
{
    const struct search_engine *se = engine();
    /* We don't fallback to the default search engine here
     * because the default behaviour is not to index anything */
    return (se->begin_update ? se->begin_update(verbose) : NULL);
}

static int search_batch_size(void)
{
    const struct search_engine *se = engine();
    return (se->flags & SEARCH_FLAG_CAN_BATCH ?
	    config_getint(IMAPOPT_SEARCH_BATCHSIZE) : INT_MAX);
}

EXPORTED int search_update_mailbox(search_text_receiver_t *rx,
				   struct mailbox *mailbox,
				   int incremental)
{
    uint32_t uid;
    message_t *msg;
    int r = 0;			/* Using IMAP_* not SQUAT_* return codes here */
    int first = 1;
    int batch_size = search_batch_size();
    int nbatch = 0;
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
	index_getsearchtext(msg, rx, 0);
	message_unref(&msg);

	if (++nbatch >= batch_size) {
	    syslog(LOG_INFO, "search_update_mailbox batching %s after %d messages",
		   mailbox->name, nbatch);
	    /* give someone else a chance */
	    r = mailbox_yield_index(mailbox);
	    if (r) break;
	    nbatch = 0;
	}
    }

    r = rx->end_mailbox(rx, mailbox);
    if (r) return r;

    return r;
}

EXPORTED int search_end_update(search_text_receiver_t *rx)
{
    const struct search_engine *se = engine();
    /* We don't fallback to the default search engine here
     * because the default behaviour is not to index anything */
    return (se->end_update ? se->end_update(rx) : 0);
}

EXPORTED search_text_receiver_t *search_begin_snippets(void *internalised,
						       int verbose,
						       search_snippet_cb_t proc,
						       void *rock)
{
    const struct search_engine *se = engine();
    return (se->begin_snippets ? se->begin_snippets(internalised,
				    verbose, proc, rock) : NULL);
}

EXPORTED int search_end_snippets(search_text_receiver_t *rx)
{
    const struct search_engine *se = engine();
    return (se->end_snippets ? se->end_snippets(rx) : 0);
}

EXPORTED char *search_describe_internalised(void *internalised)
{
    const struct search_engine *se = engine();
    return (se->describe_internalised ?
	    se->describe_internalised(internalised) : 0);
}

EXPORTED void search_free_internalised(void *internalised)
{
    const struct search_engine *se = engine();
    if (se->free_internalised) se->free_internalised(internalised);
}

EXPORTED int search_start_daemon(int verbose, const char *mboxname)
{
    const struct search_engine *se = engine();
    return (se->start_daemon ? se->start_daemon(verbose, mboxname) : 0);
}

EXPORTED int search_stop_daemon(int verbose, const char *mboxname)
{
    const struct search_engine *se = engine();
    return (se->stop_daemon ? se->stop_daemon(verbose, mboxname) : 0);
}

const char *search_op_as_string(int op)
{
    static char buf[33];

    switch (op) {
    case SEARCH_OP_AND: return "AND";
    case SEARCH_OP_OR: return "OR";
    case SEARCH_OP_NOT: return "NOT";
    default:
	snprintf(buf, sizeof(buf), "(%d)", op);
	return buf;
    }
}
