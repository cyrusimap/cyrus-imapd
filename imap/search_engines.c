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

#include "index.h"
#include "message.h"
#include "global.h"
#include "search_engines.h"
#include "ptrarray.h"

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"

#ifdef USE_SQUAT
extern const struct search_engine squat_search_engine;
#endif
#ifdef USE_SPHINX
extern const struct search_engine sphinx_search_engine;
#endif
#ifdef USE_XAPIAN
extern const struct search_engine xapian_search_engine;
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
    NULL,
    NULL,
    NULL,
    NULL
};

static const struct search_engine *engine(void)
{
    switch (config_getenum(IMAPOPT_SEARCH_ENGINE)) {
#ifdef USE_XAPIAN
    case IMAP_ENUM_SEARCH_ENGINE_XAPIAN:
        return &xapian_search_engine;
#endif
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
        "BCC", "SUBJECT", "LISTID", "TYPE",
        "HEADERS", "BODY"
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

/*
 * Flush a batch of messages to the search engine's indexer code.  We
 * drop the index lock during the presumably CPU and IO heavy parts of
 * the procedure and re-acquire it afterward, to avoid delaying other
 * processes like imapds.  The reacquisition may of course fail.
 * Returns an IMAP error code or 0 on success.
 */
static int flush_batch(search_text_receiver_t *rx,
                       struct mailbox *mailbox,
                       ptrarray_t *batch)
{
    int i;
    int r = 0;

    /* give someone else a chance */
    mailbox_unlock_index(mailbox, NULL);

    /* prefetch files */
    for (i = 0 ; i < batch->count ; i++) {
        message_t *msg = ptrarray_nth(batch, i);

        const char *fname;
        r = message_get_fname(msg, &fname);
        if (r) return r;
        r = warmup_file(fname, 0, 0);
        if (r) return r; /* means we failed to open a file,
                            so we'll fail later anyway */
    }

    for (i = 0 ; i < batch->count ; i++) {
        message_t *msg = ptrarray_nth(batch, i);
        if (!r) r = index_getsearchtext(msg, rx, 0);
        message_unref(&msg);
    }
    ptrarray_truncate(batch, 0);

    if (r) return r;

    if (rx->flush) {
        r = rx->flush(rx);
        if (r) return r;
    }

    return r;
}

EXPORTED int search_update_mailbox(search_text_receiver_t *rx,
                                   struct mailbox *mailbox,
                                   int flags)
{
    int r = 0;                  /* Using IMAP_* not SQUAT_* return codes here */
    int r2;
    int was_partial = 0;
    int batch_size = search_batch_size();
    ptrarray_t batch = PTRARRAY_INITIALIZER;
    const struct index_record *record;
    int incremental = (flags & SEARCH_UPDATE_INCREMENTAL);

    r = rx->begin_mailbox(rx, mailbox, flags);
    if (r) goto done;

    struct mailbox_iter *iter = mailbox_iter_init(mailbox, 0, ITER_SKIP_EXPUNGED);
    mailbox_iter_startuid(iter, rx->first_unindexed_uid(rx));

    while ((record = mailbox_iter_step(iter))) {
        if (incremental && batch.count >= batch_size) {
            syslog(LOG_INFO, "search_update_mailbox batching %u messages to %s",
                   batch.count, mailbox->name);
            was_partial = 1;
            break;
        }

        message_t *msg = message_new_from_record(mailbox, record);

        if (!rx->is_indexed(rx, msg))
            ptrarray_append(&batch, msg);
    }
    mailbox_iter_done(&iter);

    if (batch.count)
        r = flush_batch(rx, mailbox, &batch);

 done:
    ptrarray_fini(&batch);
    r2 = rx->end_mailbox(rx, mailbox);
    if (r) return r;
    if (r2) return r2;
    if (was_partial) return IMAP_AGAIN;
    return 0;
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

EXPORTED int search_start_daemon(int verbose)
{
    const struct search_engine *se = engine();
    return (se->start_daemon ? se->start_daemon(verbose) : 0);
}

EXPORTED int search_stop_daemon(int verbose)
{
    const struct search_engine *se = engine();
    return (se->stop_daemon ? se->stop_daemon(verbose) : 0);
}

EXPORTED int search_list_files(const char *userid,
                               strarray_t *files)
{
    const struct search_engine *se = engine();
    return (se->list_files ? se->list_files(userid, files) : 0);
}

EXPORTED int search_compact(const char *userid,
                            const char *tempdir,
                            const strarray_t *srctiers,
                            const char *desttier,
                            int flags)
{
    const struct search_engine *se = engine();
    return (se->compact ? se->compact(userid, tempdir, srctiers, desttier, flags) : 0);
}

EXPORTED int search_deluser(const char *userid)
{
    const struct search_engine *se = engine();
    return (se->deluser ? se->deluser(userid) : 0);
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
