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
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <syslog.h>
#include <string.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "assert.h"
#include "index.h"
#include "global.h"
#include "xmalloc.h"
#include "xstrlcpy.h"
#include "xstrlcat.h"
#include "bitvector.h"

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"

#include "search_engines.h"
#include "squat.h"

#define DEBUG 0

struct opstack {
    int op;         /* boolean operator to apply */
    int valid;      /* whether msg_vector is valid yet */
    bitvector_t msg_vector;
                    /* merged search results, indexed by uid (so
                     * that bit 0 is not meaningful) */
};

typedef struct {
    search_builder_t super;
    struct mailbox *mailbox;
    int verbose;
    SquatSearchIndex *index;
    int fd;
    const char *part_types;
    int found_validity;
    int depth;
    int alloc;
    struct opstack *stack;
} SquatBuilderData;

static const char *squat_strerror(int err);

static const char * const doctypes_by_part[SEARCH_NUM_PARTS] = {
    "msh", // SEARCH_PART_ANY
    "f",   // SEARCH_PART_FROM
    "t",   // SEARCH_PART_TO
    "c",   // SEARCH_PART_CC
    "b",   // SEARCH_PART_BCC
    "s",   // SEARCH_PART_SUBJECT
    NULL,  // SEARCH_PART_LISTID
    NULL,  // SEARCH_PART_TYPE
    "h",   // SEARCH_PART_HEADERS
    "m",   // SEARCH_PART_BODY
    "o",   // SEARCH_PART_LOCATION
    "a",   // SEARCH_PART_ATTACHMENTNAME
    NULL,  // SEARCH_PART_ATTACHMENTBODY
    NULL,  // SEARCH_PART_DELIVEREDTO
    NULL,  // SEARCH_PART_LANGUAGE
    NULL   // SEARCH_PART_PRIORITY
};

/* The document name is of the form

   pnnn.vvv

   Where p is a part_type character (denoting which segment of the message
   is represented by the document), nnn is the UID of the message, and vvv
   is the UID validity value.

   This function parses the document name and returns the UID
   only if the name has the right part type and it corresponds
   to a real message UID.
   Returns a UID (>=1) or zero on error.
*/
static unsigned int parse_doc_name(SquatBuilderData *bb, const char *doc_name)
{
    int ch = doc_name[0];
    const char *t = bb->part_types;
    int doc_UID;

    if (ch == 'v' && strncmp(doc_name, "validity.", 9) == 0) {
        if ((unsigned) atoi(doc_name + 9) == bb->mailbox->i.uidvalidity) {
            bb->found_validity = 1;
        }
        return 0;
    }

    /* make sure that the document part type is one of the ones we're
     accepting */
    while (*t != 0 && *t != ch) {
        t++;
    }
    if (*t == 0) {
        return 0;
    }

    doc_UID = atoi(++doc_name);
    while ((*doc_name >= '0' && *doc_name <= '9') || *doc_name == '-') {
        ++doc_name;
    }
    if (*doc_name != 0) {
        return 0;
    }

    return doc_UID;
}

#if DEBUG
static void opstack_dump(SquatBuilderData *bb, const char *where)
{
    int i;
    char *desc;
    struct buf line = BUF_INITIALIZER;

    syslog(LOG_NOTICE, "Squat opstack %s {", where);
    for (i = 0 ; i < bb->depth ; i++) {
        struct opstack *o = bb->stack+i;

        buf_reset(&line);
        buf_printf(&line, "op=%s", search_op_as_string(o->op));

        buf_printf(&line, " valid=%d", o->valid);

        desc = bv_cstring(&o->msg_vector);
        buf_printf(&line, " msg_vector=%s", desc);
        free(desc);

        syslog(LOG_NOTICE, "Squat    %s", buf_cstring(&line));
    }
    syslog(LOG_NOTICE, "Squat }");
    buf_free(&line);
}
#endif

static struct opstack *opstack_top(SquatBuilderData *bb)
{
    return (bb->depth ? &bb->stack[bb->depth-1] : NULL);
}

static struct opstack *opstack_push(SquatBuilderData *bb, int op)
{
    struct opstack *top;

#if DEBUG
    if (bb->verbose > 1)
        syslog(LOG_NOTICE, "Squat opstack_push(op=%s)", search_op_as_string(op));
#endif

    /* push a new op on the stack */
    if (bb->depth+1 > bb->alloc) {
        bb->alloc += 16;
        bb->stack = xrealloc(bb->stack, bb->alloc * sizeof(struct opstack));
    }

    top = &bb->stack[bb->depth++];
    top->op = op;
    top->valid = 0;
    bv_init(&top->msg_vector);
    bv_setsize(&top->msg_vector, bb->mailbox->i.last_uid+1);

#if DEBUG
    if (bb->verbose > 1)
        opstack_dump(bb, "after push");
#endif

    return top;
}

static void opstack_pop(SquatBuilderData *bb)
{
    struct opstack *child;
    struct opstack *parent;

#if DEBUG
    if (bb->verbose > 1)
        syslog(LOG_NOTICE, "Squat opstack_pop()");
#endif

    /* pop the last operator off the stack */
    assert(bb->depth);
    child = opstack_top(bb);
    bb->depth--;
    parent = opstack_top(bb);

    if (parent && child->valid) {
        /* merge the result with the parent node */
        if (!parent->valid)
            bv_copy(&parent->msg_vector, &child->msg_vector);
        else if (parent->op == SEARCH_OP_OR)
            bv_oreq(&parent->msg_vector, &child->msg_vector);
        else if (parent->op == SEARCH_OP_AND)
            bv_andeq(&parent->msg_vector, &child->msg_vector);
        parent->valid = 1;
    }

    bv_fini(&child->msg_vector);

#if DEBUG
    if (bb->verbose > 1)
        opstack_dump(bb, "after pop");
#endif
}

static int drop_indexed_docs(void* closure, const SquatListDoc *doc)
{
    SquatBuilderData* bb = (SquatBuilderData*)closure;
    unsigned int uid = parse_doc_name(bb, doc->doc_name);

    if (uid)
        bv_clear(&opstack_top(bb)->msg_vector, uid);
    return SQUAT_CALLBACK_CONTINUE;
}

static int fill_with_hits(void* closure, char const* doc)
{
    SquatBuilderData* bb = (SquatBuilderData*)closure;
    unsigned int uid = parse_doc_name(bb, doc);

    if (uid)
        bv_set(&opstack_top(bb)->msg_vector, uid);
    return SQUAT_CALLBACK_CONTINUE;
}

static void begin_boolean(search_builder_t *bx, int op)
{
    SquatBuilderData *bb = (SquatBuilderData *)bx;

#if DEBUG
    if (bb->verbose > 1)
        syslog(LOG_NOTICE, "Squat begin_boolean(op=%s)", search_op_as_string(op));
#endif

    opstack_push(bb, op);
}

static void end_boolean(search_builder_t *bx, int op __attribute__((unused)))
{
    SquatBuilderData *bb = (SquatBuilderData *)bx;

#if DEBUG
    if (bb->verbose > 1)
        syslog(LOG_NOTICE, "Squat end_boolean()");
#endif
    opstack_pop(bb);
}

static void match(search_builder_t *bx, int part, const char *str)
{
    SquatBuilderData *bb = (SquatBuilderData *)bx;
    struct opstack *parent = opstack_top(bb);
    struct opstack *top;
    int r;

#if DEBUG
    if (bb->verbose > 1)
        syslog(LOG_NOTICE, "Squat match(part=%d str=\"%s\")", part, str);
#endif

    if (!doctypes_by_part[part])
        return;
    if (parent && parent->op == SEARCH_OP_NOT)
        return;

    top = opstack_push(bb, /*doesn't matter*/0);
    bb->part_types = doctypes_by_part[part];

    charset_t utf8 = charset_lookupname("utf-8");
    char *mystr = charset_convert(str, utf8, charset_flags);
    r = squat_search_execute(bb->index, mystr, strlen(mystr),
                             fill_with_hits, bb);
    free(mystr);
    charset_free(&utf8);
    if (r != SQUAT_OK) {
        if (squat_get_last_error() == SQUAT_ERR_SEARCH_STRING_TOO_SHORT)
            goto out; /* The rest of the search is still viable */
        syslog(LOG_ERR, "SQUAT string list search failed on string %s "
                          "with part types %s: %s",
                          str, bb->part_types, squat_strerror(r));
        goto out;
    }
    top->valid = 1;

#if DEBUG
    if (bb->verbose > 1)
        opstack_dump(bb, "after match");
#endif

out:
    opstack_pop(bb);
}

static void *get_internalised(search_builder_t *bx
                                __attribute__((unused)))
{
    return NULL;
}

static int run(search_builder_t *bx, search_hit_cb_t proc, void *rock);

static search_builder_t *begin_search(struct mailbox *mailbox, int opts)
{
    SquatBuilderData *bb;
    SquatSearchIndex* index;
    const char *fname;
    int fd;

    if ((opts & SEARCH_MULTIPLE)) {
        syslog(LOG_ERR, "Squat does not support multiple-folder searches, sorry");
        /* although it could with some extra work, but why bother */
        return NULL;
    }

    fname = mailbox_meta_fname(mailbox, META_SQUAT);
    if ((fd = open(fname, O_RDONLY)) < 0) {
        if (errno != ENOENT)
            syslog(LOG_ERR, "SQUAT failed to open index file %s: %s",
                   fname, squat_strerror(squat_get_last_error()));
        return NULL;   /* probably not found. Just bail */
    }
    if ((index = squat_search_open(fd)) == NULL) {
        syslog(LOG_ERR, "SQUAT failed to open index %s: %s",
               fname, squat_strerror(squat_get_last_error()));
        close(fd);
        return NULL;
    }

    bb = xzmalloc(sizeof(SquatBuilderData));
    bb->super.begin_boolean = begin_boolean;
    bb->super.end_boolean = end_boolean;
    bb->super.match = match;
    bb->super.get_internalised = get_internalised;
    bb->super.run = run;

    bb->mailbox = mailbox;
    bb->verbose = (opts & _SEARCH_VERBOSE_MASK);
    bb->index = index;
    bb->fd = fd;

    /* Push a boolean node on the stack -- this will be used
     * at the end of the search to OR in any unindexed messages */
    opstack_push(bb, SEARCH_OP_OR);

    return &bb->super;
}

static int add_unindexed(SquatBuilderData *bb)
{
    struct opstack *top = opstack_top(bb);
    int r = 0;

    top = opstack_push(bb, /*doesn't matter*/0);
    bv_setall(&top->msg_vector);
    bv_clear(&top->msg_vector, 0);  /* UID 0 is not valid */
    bb->part_types = "tfcbsmh";
    bb->found_validity = 0;

    r = squat_search_list_docs(bb->index, drop_indexed_docs, bb);
    if (r != SQUAT_OK) {
        syslog(LOG_ERR, "SQUAT failed to get list of indexed documents: %s",
               squat_strerror(r));
        r = IMAP_IOERROR;
        goto out;
    }
    if (!bb->found_validity) {
        syslog(LOG_ERR, "SQUAT didn't find validity record");
        r = IMAP_IOERROR;
        goto out;
    }
    top->valid = 1;
    r = 0;

#if DEBUG
    if (bb->verbose > 1)
        opstack_dump(bb, "after adding unindexed");
#endif

out:
    opstack_pop(bb);
    return r;
}

static int run(search_builder_t *bx, search_hit_cb_t proc, void *rock)
{
    SquatBuilderData *bb = (SquatBuilderData *)bx;
    unsigned int uid;
    int r = 0;

    syslog(bb->verbose > 1 ? LOG_NOTICE : LOG_DEBUG, "Squat run()");

    /* check we had balanced ->begin_boolean and ->end_boolean calls */
    if (bb->depth != 1)
        goto out;

    r = add_unindexed(bb);
    if (r) goto out;

    /* Flatten out the final bit vector into a sequence */
    for (uid = 1 ; uid <= bb->mailbox->i.last_uid; uid++) {
        if (bv_isset(&bb->stack[0].msg_vector, uid)) {
            r = proc(bb->mailbox->name,
                     bb->mailbox->i.uidvalidity,
                     uid, NULL, rock);
            if (r) goto out;
        }
    }

out:
    return r;
}

static void end_search(search_builder_t *bx)
{
    SquatBuilderData *bb = (SquatBuilderData *)bx;

    while (bb->depth) opstack_pop(bb);
    free(bb->stack);
    if (bb->index) squat_search_close(bb->index);
    if (bb->fd >= 0) close(bb->fd);
    free(bx);
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
            "into %lu index bytes in %d seconds",
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
static int begin_message(search_text_receiver_t *rx,
                          message_t *msg)
{
    SquatReceiverData *d = (SquatReceiverData *) rx;

    message_get_uid(msg, &d->uid);
    d->doc_is_open = 0;
    d->doc_name[0] = '\0';

    d->mailbox_stats.indexed_messages++;
    d->total_stats.indexed_messages++;

    return 0;
}

static int begin_bodypart(search_text_receiver_t *rx __attribute__((unused)),
                          const char *partid __attribute__((unused)),
                          const struct message_guid *content_guid __attribute__((unused)),
                          const char *type __attribute__((unused)),
                          const char *subtype __attribute__((unused)))
{
    return 0;
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
    int s;          /* SQUAT error */

    if (d->verbose > 3)
        syslog(LOG_ERR, "squat: writing %llu bytes into message %u",
               (unsigned long long)text->len, d->uid);

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

static int append_text(search_text_receiver_t *rx,
                        const struct buf *text)
{
    SquatReceiverData *d = (SquatReceiverData *) rx;
    int r = 0;      /* IMAP error */
    int s = 0;      /* SQUAT error */

    if (!d->doc_is_open) {
        if (text->len + d->pending_text.len < SQUAT_WORD_SIZE) {
            /* not enough text yet */
            buf_append(&d->pending_text, text);
            return 0;
        }

        /* just went over the threshold */
        if (d->verbose > 2)
            syslog(LOG_NOTICE, "squat: opening document part '%s'",
                    d->doc_name);

        s = squat_index_open_document(d->index, d->doc_name);
        if (s != SQUAT_OK) {
            syslog(LOG_ERR, "squat: error opening document %s "
                            "for mailbox %s: %s",
                            d->doc_name, d->mailbox->name,
                            squat_strerror(s));
            return IMAP_IOERROR;
        }
        d->doc_is_open = 1;

        /* flush any pending text */
        if (d->pending_text.len)
            r = do_append(d, &d->pending_text);
        buf_reset(&d->pending_text);
    }

    if (!r)
        r = do_append(d, text);

    return r;
}

static void end_part(search_text_receiver_t *rx,
                     int part __attribute__((unused)))
{
    SquatReceiverData *d = (SquatReceiverData *) rx;
    int s = 0;      /* SQUAT error */

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

static void end_bodypart(search_text_receiver_t *rx __attribute__((unused)))
{
}


static int end_message(search_text_receiver_t *rx,
                       uint8_t indexlevel __attribute__((unused)))
{
    SquatReceiverData *d = (SquatReceiverData *) rx;

    d->uid = 0;
    return 0;
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
        ;                       /* do nothing */
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
    int r = 0;      /* IMAP error code */
    int s = 0;      /* SQUAT error code */

    bv_clearall(&d->indexed);

    filename = mailbox_meta_newfname(mailbox, META_SQUAT);
    if ((fd = open(filename, O_CREAT | O_TRUNC | O_WRONLY, 0666)) < 0) {
        syslog(LOG_ERR, "squat: unable to create temporary index file %s: %m",
               filename);
        r = IMAP_IOERROR;
        goto out;
    }

    options.option_mask = SQUAT_OPTION_TMP_PATH | SQUAT_OPTION_STATISTICS;
    options.tmp_path = mailbox_datapath(mailbox, 0);
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

static uint32_t first_unindexed_uid(search_text_receiver_t *rx
                                    __attribute__((unused)))
{
    return 1;
}

static uint8_t is_indexed(search_text_receiver_t *rx, message_t *msg)
{
    SquatReceiverData *d = (SquatReceiverData *)rx;
    uint32_t uid = 0;
    message_get_uid(msg, &uid);

    return bv_isset(&d->indexed, uid);
}

static int end_mailbox(search_text_receiver_t *rx,
                       struct mailbox *mailbox
                            __attribute__((unused)))
{
    SquatReceiverData *d = (SquatReceiverData *)rx;
    struct stat sb;
    int r = 0;      /* IMAP error code or syscall return */
    int s = 0;      /* SQUAT error code */

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

static int squat_charset_flags(int flags)
{
    return flags & ~CHARSET_KEEPCASE;
}

static search_text_receiver_t *begin_update(int verbose)
{
    SquatReceiverData *d;

    d = xzmalloc(sizeof(SquatReceiverData));
    d->super.begin_mailbox = begin_mailbox;
    d->super.first_unindexed_uid = first_unindexed_uid;
    d->super.is_indexed = is_indexed;
    d->super.begin_message = begin_message;
    d->super.begin_bodypart = begin_bodypart;
    d->super.begin_part = begin_part;
    d->super.append_text = append_text;
    d->super.end_part = end_part;
    d->super.end_bodypart = end_bodypart;
    d->super.end_message = end_message;
    d->super.end_mailbox = end_mailbox;
    d->super.index_charset_flags = squat_charset_flags;

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

    bv_fini(&d->indexed);
    free(d);
    return 0;
}

static int can_match(enum search_op matchop, int partnum)
{
    return (matchop == SEOP_MATCH || matchop == SEOP_FUZZYMATCH) &&
        doctypes_by_part[partnum];
}

const struct search_engine squat_search_engine = {
    "SQUAT",
    0,
    begin_search,
    end_search,
    begin_update,
    end_update,
    /* begin_snippets */NULL,
    /* end_snippets */NULL,
    /* describe_internalised */NULL,
    /* free_internalised */NULL,
    /* list_files */NULL,
    /* compact */NULL,
    /* deluser */NULL,
    /* check_config */NULL,
    /* langstats */NULL,
    can_match
};

