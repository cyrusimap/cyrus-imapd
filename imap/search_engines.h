/* search_engines.h --  Prefiltering routines for SEARCH
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

#ifndef INCLUDED_SEARCH_ENGINES_H
#define INCLUDED_SEARCH_ENGINES_H

#include "mailbox.h"
#include "message_guid.h"
#include "util.h"
#include "strarray.h"

#include "search_part.h"

typedef int (*search_hit_cb_t)(const char *mboxname, uint32_t uidvalidity,
                               uint32_t uid, void *rock);
typedef int (*search_snippet_cb_t)(struct mailbox *, uint32_t uid,
                                   /* SEARCH_PART_* constants */int part,
                                   const char *snippet, void *rock);

typedef struct search_builder search_builder_t;
struct search_builder {
/* These values are carefully chosen a) not to clash with the
 * SEARCH_PART_* constants, and b) to reflect operator precedence */
#define SEARCH_OP_AND       101
#define SEARCH_OP_OR        102
#define SEARCH_OP_NOT       103
    void (*begin_boolean)(search_builder_t *, int op);
    void (*end_boolean)(search_builder_t *, int op);
    void (*match)(search_builder_t *, int part, const char *str);
    void *(*get_internalised)(search_builder_t *);
    int (*run)(search_builder_t *, search_hit_cb_t proc, void *rock);
};

typedef struct search_snippet_markup {
    const char *hi_start;
    const char *hi_end;
    const char *omit;
} search_snippet_markup_t;

extern search_snippet_markup_t default_snippet_markup;

/* The functions in search_text_receiver_t get called at least once for each part of every message.
   The invocations form a sequence:
       begin_message(message_t)
       receiver->begin_part(<part1>)
       receiver->append_text(<text>)     (1 or more times)
       receiver->end_part(<part1>)
       ...
       receiver->begin_part(<partN>)
       receiver->append_text(<text>)     (1 or more times)
       receiver->end_part(<partN>)
       receiver->end_message()

   The parts need not arrive in any particular order, but each part
   can only participate in one begin_part ... append_text ... end_part
   sequence, and the sequences for different parts cannot be interleaved.
*/
typedef struct search_text_receiver search_text_receiver_t;
struct search_text_receiver {
    int (*begin_mailbox)(search_text_receiver_t *,
                         struct mailbox *, int incremental);
    uint32_t (*first_unindexed_uid)(search_text_receiver_t *);
    int (*is_indexed)(search_text_receiver_t *, message_t *msg);
    int (*begin_message)(search_text_receiver_t *, message_t *msg);
    void (*begin_part)(search_text_receiver_t *, int part);
    void (*append_text)(search_text_receiver_t *, const struct buf *);
    void (*end_part)(search_text_receiver_t *, int part);
    int (*end_message)(search_text_receiver_t *);
    int (*end_mailbox)(search_text_receiver_t *,
                       struct mailbox *);
    int (*flush)(search_text_receiver_t *);
};

#define SEARCH_FLAG_CAN_BATCH   (1<<0)
struct search_engine {
    const char *name;
    unsigned int flags;
#define _SEARCH_VERBOSE_MASK    (0x7)
#define SEARCH_VERBOSE(v)       ((v)&_SEARCH_VERBOSE_MASK)
#define SEARCH_MULTIPLE         (1<<3)  /* return results from
                                         * multiple folders */
#define SEARCH_UNINDEXED        (1<<4)  /* return unindexed messages
                                         * as hits (doesn't work
                                         * with MULTIPLE) */
#define SEARCH_COMPACT_COPYONE  (1<<5)  /* if only one source, just copy */
#define SEARCH_COMPACT_FILTER   (1<<6)  /* filter resulting DB for
                                         * expunged records */
#define SEARCH_COMPACT_REINDEX  (1<<7)  /* re-index all matching messages */
    search_builder_t *(*begin_search)(struct mailbox *, int opts);
    void (*end_search)(search_builder_t *);
    search_text_receiver_t *(*begin_update)(int verbose);
    int (*end_update)(search_text_receiver_t *);
    search_text_receiver_t *(*begin_snippets)(void *internalised,
                                              int verbose,
                                              search_snippet_markup_t *markup,
                                              search_snippet_cb_t,
                                              void *rock);
    int (*end_snippets)(search_text_receiver_t *);
    char *(*describe_internalised)(void *);
    void (*free_internalised)(void *);
    int (*start_daemon)(int verbose);
    int (*stop_daemon)(int verbose);
    int (*list_files)(const char *userid, strarray_t *);
    int (*compact)(const char *userid, const char *tempdir,
                   const strarray_t *srctiers, const char *desttier,
                   int flags);
    int (*deluser)(const char *userid);
};

/*
 * Search for messages which could match the query built with the
 * search_builder_t.  Calls 'proc' once for each hit found.  If 'single'
 * is true, only hits in 'mailbox' are reported; otherwise hits in any
 * folder in the same conversation scope (i.e. the same user) as
 * reported.
 */
extern search_builder_t *search_begin_search(struct mailbox *, int opts);
extern void search_end_search(search_builder_t *);

#define SEARCH_UPDATE_INCREMENTAL (1<<0)
#define SEARCH_UPDATE_NONBLOCKING (1<<1)
#define SEARCH_UPDATE_BATCH (1<<2)
search_text_receiver_t *search_begin_update(int verbose);
int search_update_mailbox(search_text_receiver_t *rx,
                          struct mailbox *mailbox,
                          int flags);
int search_end_update(search_text_receiver_t *rx);
search_text_receiver_t *search_begin_snippets(void *internalised,
                                              int verbose,
                                              search_snippet_markup_t *markup,
                                              search_snippet_cb_t proc,
                                              void *rock);
int search_end_snippets(search_text_receiver_t *rx);
/* Returns a new string which describes the internalised query, and must
 * be free()d by the caller.  Only useful for whitebox testing.  */
char *search_describe_internalised(void *internalised);
void search_free_internalised(void *internalised);
int search_start_daemon(int verbose);
int search_stop_daemon(int verbose);
int search_list_files(const char *userid, strarray_t *);
int search_compact(const char *userid, const char *tempdir,
                   const strarray_t *srctiers, const char *desttier, int verbose);
int search_deluser(const char *userid);


/* for debugging */
extern const char *search_op_as_string(int op);

#endif
