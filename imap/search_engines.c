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

#include "dynarray.h"
#include "index.h"
#include "map.h"
#include "message.h"
#include "global.h"
#include "ptrarray.h"
#include "search_engines.h"
#include "attachextract.h"

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"

#ifdef USE_SQUAT
extern const struct search_engine squat_search_engine;
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
    NULL,
    NULL,
    NULL
};

EXPORTED const struct search_engine *search_engine(void)
{
    switch (config_getenum(IMAPOPT_SEARCH_ENGINE)) {
#ifdef USE_XAPIAN
    case IMAP_ENUM_SEARCH_ENGINE_XAPIAN:
        return &xapian_search_engine;
#endif
#ifdef USE_SQUAT
    case IMAP_ENUM_SEARCH_ENGINE_SQUAT:
        return &squat_search_engine;
#endif
    default:
        return &default_search_engine;
    }
}

EXPORTED search_snippet_markup_t default_snippet_markup = {
    "<b>", "</b>", "..."
};

EXPORTED const char *search_part_as_string(int part)
{
    static const char *names[SEARCH_NUM_PARTS] = {
        /* ANY */NULL, "FROM", "TO", "CC",
        "BCC", "SUBJECT", "LISTID", "TYPE",
        "HEADERS", "BODY", "LOCATION", "ATTACHMENTNAME",
        "ATTACHMENTBODY", "DELIVEREDTO", "LANGUAGE"
    };

    return (part < 0 || part >= SEARCH_NUM_PARTS ? NULL : names[part]);
}

EXPORTED int search_part_is_body(int part)
{
    return part == SEARCH_PART_BODY ||
           part == SEARCH_PART_LOCATION ||
           part == SEARCH_PART_ATTACHMENTBODY;
}


EXPORTED search_builder_t *search_begin_search(struct mailbox *mailbox, int opts)
{
    if (!mailbox) return NULL;

    const struct search_engine *se = search_engine();
    return (se->begin_search ?
            se->begin_search(mailbox, opts) : NULL);
}

EXPORTED void search_end_search(search_builder_t *bx)
{
    const struct search_engine *se = search_engine();
    if (se->end_search) se->end_search(bx);
}

EXPORTED search_text_receiver_t *search_begin_update(int verbose)
{
    const struct search_engine *se = search_engine();
    /* We don't fallback to the default search engine here
     * because the default behaviour is not to index anything */
    return (se->begin_update ? se->begin_update(verbose) : NULL);
}

static int search_batch_size(void)
{
    const struct search_engine *se = search_engine();
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
                       int flags,
                       ptrarray_t *batch)
{
    int i;
    int r = 0;
    int indexflags = 0;

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

    if (flags & SEARCH_UPDATE_ALLOW_PARTIALS)
        indexflags |= INDEX_GETSEARCHTEXT_PARTIALS;

    for (i = 0 ; i < batch->count ; i++) {
        message_t *msg = ptrarray_nth(batch, i);
        if (!r) r = index_getsearchtext(msg, NULL, rx, indexflags);
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

struct withattach_record {
    char *fname;
    uint32_t imap_uid;
    char *imap_partid;
    size_t content_offset;
    size_t content_size;
    int encoding;
    char *charset;
    struct attachextract_record axrec;
    strarray_t freeme;
};

static int create_withattach(struct mailbox *mailbox,
                             message_t *msg,
                             dynarray_t *withattach)
{
    int created = 0;
    ptrarray_t queue = PTRARRAY_INITIALIZER;

    uint32_t imap_uid = 0;
    int r = message_get_uid(msg, &imap_uid);
    if (r) {
        xsyslog(LOG_ERR, "can not get message uid",
                "mboxname=<%s> err=<%s>",
                mailbox_name(mailbox), error_message(r));
        goto done;
    }

    const struct body *body = NULL;
    r = message_get_cachebody(msg, &body);
    if (r) {
        xsyslog(LOG_ERR, "can not load cachebody",
                "mboxname=<%s> uid=<%d> err=<%s>",
                mailbox_name(mailbox), imap_uid, error_message(r));
        goto done;
    }

    const char *fname = NULL;
    r = message_get_fname(msg, &fname);
    if (r) {
        xsyslog(LOG_ERR, "can not get file name",
                "mboxname=<%s> uid=<%d> err=<%s>",
                mailbox_name(mailbox), imap_uid, error_message(r));
        goto done;
    }

    ptrarray_append(&queue, (void*)body);

    while ((body = ptrarray_pop(&queue))) {
        if (index_want_attachextract(body->type, body->subtype)) {
            strarray_t freeme = STRARRAY_INITIALIZER;
            struct withattach_record wa = {
                .fname = xstrdup(fname),
                .imap_uid = imap_uid,
                .imap_partid = xstrdupnull(body->part_id),
                .content_offset = body->content_offset,
                .content_size = body->content_size,
                .encoding = encoding_lookupname(body->encoding),
                .axrec.type = strarray_appendv(&freeme, body->type),
                .axrec.subtype = strarray_appendv(&freeme, body->subtype),
                .axrec.guid = message_guid_clone(&body->content_guid),
            };

            const struct param *param = body->params;
            while (param && param->attribute) {
                if (!strcmp(param->attribute, "charset") && param->value) {
                    wa.charset = xstrdupnull(param->value);
                    break;
                }
                param = param->next;
            }

            wa.freeme = freeme;
            dynarray_append(withattach, &wa);
            created = 1;
        }

        for (int i = 0; i < body->numparts; i++) {
            ptrarray_append(&queue, body->subpart + i);
        }
    }

done:
    ptrarray_fini(&queue);
    return created;
}

static void free_withattach(dynarray_t *withattach)
{
    for (int i = 0; i < dynarray_size(withattach); i++) {
        struct withattach_record *wa = dynarray_nth(withattach, i);
        free(wa->fname);
        free(wa->imap_partid);
        free(wa->charset);
        strarray_fini(&wa->freeme);
    }
    dynarray_fini(withattach);
}

static void warmup_attachextract_cache(dynarray_t *withattach)
{
    const char *mapped = NULL;
    size_t mapped_len = 0;
    const char *fname = NULL;
    struct buf buf = BUF_INITIALIZER;
    int fd = -1;

    for (int i = 0; i < dynarray_size(withattach); i++) {
        struct withattach_record *wa = dynarray_nth(withattach, i);

        if (strcmpsafe(wa->fname, fname)) {
            if (mapped)
                map_free(&mapped, &mapped_len);

            if (fd != -1)
                close(fd);

            fd = open(wa->fname, O_RDONLY);
            if (fd == -1) {
                xsyslog(LOG_WARNING, "could not open message file - ignoring",
                        "file=<%s>", wa->fname);
                fname = NULL;
                continue;
            }

            map_refresh(fd, 1, &mapped, &mapped_len,
                    MAP_UNKNOWN_LEN, wa->fname, NULL);
            fname = wa->fname;
        }

        if (wa->content_offset + wa->content_size > mapped_len) {
            xsyslog(LOG_ERR, "file size has changed - ignoring",
                    "file=<%s> expect_size=<%zu> have_size=<%zu>",
                    wa->fname, wa->content_offset + wa->content_size,
                    mapped_len);
            continue;
        }

        struct buf data = BUF_INITIALIZER;
        buf_init_ro(&data, mapped + wa->content_offset, wa->content_size);

        int r = attachextract_extract(&wa->axrec, &data,
                wa->encoding, wa->charset, &buf);
        if (!r) {
            xsyslog(LOG_DEBUG, "warmed up attachextract cache for body part",
                    "file=<%s> imap_partid=<%s>", wa->fname, wa->imap_partid);
        }
        else {
            xsyslog(LOG_ERR, "failed to warmup attachextract cache for body part",
                    "file=<%s> imap_partid=<%s> err=<%s>",
                    wa->fname, wa->imap_partid, error_message(r));
        }

        buf_reset(&buf);
        buf_free(&data);
    }

    if (mapped)
        map_free(&mapped, &mapped_len);

    if (fd != -1)
        close(fd);

    buf_free(&buf);
}

static int flush_withattach(search_text_receiver_t *rx,
                            struct mailbox *mailbox,
                            int flags,
                            dynarray_t *withattach)
{
    ptrarray_t batch = PTRARRAY_INITIALIZER;
    int r = 0;

    for (int i = 0; i < dynarray_size(withattach); i++) {
        struct withattach_record *wa = dynarray_nth(withattach, i);

        struct index_record record = {0};
        r = mailbox_find_index_record(mailbox, wa->imap_uid, &record);
        if (r) {
            xsyslog(LOG_WARNING, "could not find index record - ignoring",
                    "mboxname=<%s> imap_uid=<%d> err=<%s>",
                    mailbox_name(mailbox), wa->imap_uid,
                    error_message(r));
            continue;
        }

        message_t *msg = message_new_from_record(mailbox, &record);
        ptrarray_append(&batch, msg);
    }

    if (batch.count) {
        // we warmed up the cache - now do not incur network io again
        r = flush_batch(rx, flags, &batch);
    }

    ptrarray_fini(&batch);
    return r;
}

static void build_batch(search_text_receiver_t *rx,
                        struct mailbox *mailbox,
                        int min_indexlevel,
                        int flags,
                        ptrarray_t *batch,
                        int *is_incomplete)
{
    int reindex_partials = flags & SEARCH_UPDATE_REINDEX_PARTIALS;
    int batch_size = search_batch_size();
    const message_t *msg;

    /* we want to index EXPUNGED messages too, because otherwise when we check the
     * ranges matching the GUID in conversations DB later, we might think we've
     * indexed it when we actually haven't */
    struct mailbox_iter *iter = mailbox_iter_init(mailbox, 0, ITER_SKIP_UNLINKED);
    if ((flags & SEARCH_UPDATE_INCREMENTAL) && !reindex_partials)
        mailbox_iter_startuid(iter, rx->first_unindexed_uid(rx));

    while ((msg = mailbox_iter_step(iter))) {
        const struct index_record *record = msg_record(msg);
        if ((flags & SEARCH_UPDATE_BATCH) && batch->count >= batch_size) {
            syslog(LOG_INFO, "search_update_mailbox batching %u messages to %s",
                    batch->count, mailbox_name(mailbox));
            *is_incomplete = 1;
        }

        message_t *msg = message_new_from_record(mailbox, record);

        uint8_t indexlevel = rx->is_indexed(rx, msg);
        if ((reindex_partials && (indexlevel & SEARCH_INDEXLEVEL_PARTIAL)) ||
            (min_indexlevel && indexlevel < min_indexlevel)) {
            /* Reindex that message */
            indexlevel = 0;
        }

        if (!indexlevel)
            ptrarray_append(batch, msg);
        else
            message_unref(&msg);
    }

    mailbox_iter_done(&iter);
}

EXPORTED int search_update_mailbox(search_text_receiver_t *rx,
                                   struct mailbox **mailboxptr,
                                   int min_indexlevel,
                                   int flags)
{
    int r = 0;                  /* Using IMAP_* not SQUAT_* return codes here */
    int is_incomplete = 0;
    ptrarray_t batch = PTRARRAY_INITIALIZER;
    dynarray_t withattach = DYNARRAY_INITIALIZER(sizeof(struct withattach_record));
    char *mycachedir = NULL;
    struct mailbox *mailbox = *mailboxptr;
    char *mboxname = xstrdup(mailbox_name(mailbox));

    r = rx->begin_mailbox(rx, mailbox, flags);
    if (r) goto done;

    // Build message batch

    build_batch(rx, mailbox, min_indexlevel, flags, &batch, &is_incomplete);
    if (!batch.count) goto done;

    // Split messages with attachments from batch
    int newlen = 0;
    for (int i = 0; i < ptrarray_size(&batch); i++) {
        message_t *msg = ptrarray_nth(&batch, i);
        if (create_withattach(mailbox, msg, &withattach)) {
            message_unref(&msg);
        }
        else ptrarray_set(&batch, newlen++, msg);
    }

    if (newlen < ptrarray_size(&batch))
        ptrarray_truncate(&batch, newlen);

    // Index text-only messages
    if (batch.count) {
        r = flush_batch(rx, flags, &batch);
        if (r) goto done;
    }

    if (!dynarray_size(&withattach))
        goto done;

    // Release mailbox lock
    r = rx->end_mailbox(rx, mailbox);
    if (r) goto done;
    mailbox_close(&mailbox);

    // Log timestamp
    if (flags & SEARCH_UPDATE_VERBOSE) {
        xsyslog(LOG_DEBUG, "released mailbox lock",
                "mboxname=<%s> unixepoch=<" TIME_T_FMT ">",
                mboxname, time(NULL));
    }

    // Extract attachment text and cache results
    if (!attachextract_get_cachedir()) {
        mycachedir =
            create_tempdir(config_getstring(IMAPOPT_TEMP_PATH), "attachextract");
        attachextract_set_cachedir(mycachedir);
    }

    warmup_attachextract_cache(&withattach);

    // Retake mailbox lock
    r = mailbox_open_irl(mboxname, &mailbox);
    if (r) goto done;

    r = rx->begin_mailbox(rx, mailbox, flags);
    if (r) goto done;

    // Log timestamp
    if (flags & SEARCH_UPDATE_VERBOSE) {
        xsyslog(LOG_DEBUG, "reacquired mailbox lock",
                "mboxname=<%s> unixepoch=<" TIME_T_FMT ">",
                mboxname, time(NULL));
    }

    // Index cached attachment text
    int txcacheonly = attachextract_get_cacheonly();
    if (!txcacheonly) {
        attachextract_set_cacheonly(1);
    }

    r = flush_withattach(rx, mailbox, flags, &withattach);

    if (!txcacheonly) {
        attachextract_set_cacheonly(0);
    }

    if (mycachedir) {
        attachextract_set_cachedir(NULL);
        removedir(mycachedir);
    }

 done:
    *mailboxptr = mailbox;
    ptrarray_fini(&batch);
    free_withattach(&withattach);
    free(mycachedir);
    free(mboxname);
    {
        int r2 = rx->end_mailbox(rx, mailbox);
        if (r) return r;
        if (r2) return r2;
    }
    return is_incomplete ? IMAP_AGAIN : 0;
}

EXPORTED int search_end_update(search_text_receiver_t *rx)
{
    const struct search_engine *se = search_engine();
    /* We don't fallback to the default search engine here
     * because the default behaviour is not to index anything */
    return (se->end_update ? se->end_update(rx) : 0);
}

EXPORTED search_text_receiver_t *search_begin_snippets(void *internalised,
                                                       int verbose,
                                                       search_snippet_markup_t *markup,
                                                       search_snippet_cb_t proc,
                                                       void *rock)
{
    const struct search_engine *se = search_engine();
    return (se->begin_snippets ? se->begin_snippets(internalised,
                                    verbose, markup, proc, rock) : NULL);
}

EXPORTED int search_end_snippets(search_text_receiver_t *rx)
{
    const struct search_engine *se = search_engine();
    return (se->end_snippets ? se->end_snippets(rx) : 0);
}

EXPORTED char *search_describe_internalised(void *internalised)
{
    const struct search_engine *se = search_engine();
    return (se->describe_internalised ?
            se->describe_internalised(internalised) : 0);
}

EXPORTED void search_free_internalised(void *internalised)
{
    const struct search_engine *se = search_engine();
    if (se->free_internalised) se->free_internalised(internalised);
}

EXPORTED int search_list_files(const char *userid,
                               strarray_t *files)
{
    const struct search_engine *se = search_engine();
    return (se->list_files ? se->list_files(userid, files) : 0);
}

EXPORTED int search_compact(const char *userid,
                            const strarray_t *reindextiers,
                            const strarray_t *srctiers,
                            const char *desttier,
                            int flags)
{
    const struct search_engine *se = search_engine();
    return (se->compact ? se->compact(userid, reindextiers, srctiers, desttier, flags) : 0);
}

EXPORTED int search_deluser(const mbentry_t *mbentry)
{
    const struct search_engine *se = search_engine();
    return (se->deluser ? se->deluser(mbentry) : 0);
}

EXPORTED int search_check_config(char **errstr)
{
    const struct search_engine *se = search_engine();
    return (se->check_config ? se->check_config(errstr) : 0);
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

EXPORTED int search_can_match(enum search_op matchop, int partnum)
{
    const struct search_engine *se = search_engine();
    return (se->can_match ? se->can_match(matchop, partnum) : 0);
}

EXPORTED int search_upgrade(const char *userid)
{
    const struct search_engine *se = search_engine();
    return se->upgrade ? se->upgrade(userid) : 0;
}
