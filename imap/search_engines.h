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
#include "bitvector.h"

#include "search_expr.h"
#include "search_part.h"
#include "search_sort.h"

typedef int (*search_hit_cb_t)(const char *mboxname, uint32_t uidvalidity,
                               uint32_t uid, const strarray_t *partids,
                               void *rock);

typedef int (*search_hitguid_cb_t)(const conv_guidrec_t *rec, size_t nguids,
                                   void *rock);

typedef int (*search_snippet_cb_t)(struct mailbox *, uint32_t uid,
                                   /* SEARCH_PART_* constants */int part,
                                   const char *bodypartid,
                                   const char *snippet, void *rock);

typedef struct search_builder search_builder_t;
struct search_builder {
/* These values are carefully chosen a) not to clash with the
 * SEARCH_PART_* constants, and b) to reflect operator precedence */
/* Values > 1024 are reserved for search engine implementations */
#define SEARCH_OP_AND       101
#define SEARCH_OP_OR        102
#define SEARCH_OP_NOT       103
#define SEARCH_OP_TRUE      104
#define SEARCH_OP_FALSE     105
    void (*begin_boolean)(search_builder_t *, int op);
    void (*end_boolean)(search_builder_t *, int op);
    void (*match)(search_builder_t *, int part, const char *str);
    void (*matchlist)(search_builder_t *, int part, const strarray_t *items);
    void *(*get_internalised)(search_builder_t *);
    int (*run)(search_builder_t *, search_hit_cb_t proc, void *rock);
    /* XXX - guidsearch is a hack for speeding up JMAP email queries */
    int (*run_guidsearch)(search_builder_t *, search_hitguid_cb_t proc, void *rock);
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

       (1 or more times)
       receiver->begin_bodypart(<bodypart1>, <contentid>)
       receiver->begin_part(<part1>)
       receiver->append_text(<text>)     (1 or more times)
       receiver->end_part(<part1>)
       receiver->end_bodypart(<bodypart1>)
       ...
       receiver->begin_part(<partN>)
       receiver->append_text(<text>)     (1 or more times)
       receiver->end_part(<partN>)
       receiver->begin_bodypart(<bodypart1>)

       receiver->end_message()

   The parts need not arrive in any particular order, but each part
   can only participate in one begin_part ... append_text ... end_part
   sequence, and the sequences for different parts cannot be interleaved.
   Multiple parts can share the same <contentid>.
*/
typedef struct search_text_receiver search_text_receiver_t;
struct search_text_receiver {
    int (*begin_mailbox)(search_text_receiver_t *,
                         struct mailbox *, int incremental);
    uint32_t (*first_unindexed_uid)(search_text_receiver_t *);
    /* returns the highest index level of msg. ties between equal index levels
     * are broken by choosing the index level without the partial bit set */
    uint8_t (*is_indexed)(search_text_receiver_t *, message_t *msg);
    int (*begin_message)(search_text_receiver_t *, message_t *msg);
    int (*begin_bodypart)(search_text_receiver_t *, const char *partid,
                          const struct message_guid *content_guid,
                          const char *type, const char *subtype);
    void (*begin_part)(search_text_receiver_t *, int part);
    /* Returns IMAP_MESSAGE_TOO_LARGE if no more bytes are accepted */
    int  (*append_text)(search_text_receiver_t *, const struct buf *);
    void (*end_part)(search_text_receiver_t *, int part);
    void (*end_bodypart)(search_text_receiver_t *);
#define SEARCH_INDEXLEVEL_BASIC 1
#define SEARCH_INDEXLEVEL_ATTACH 3
#define SEARCH_INDEXLEVEL_PARTIAL 0x80 /*  high bit indicates a partial */
#define SEARCH_INDEXLEVEL_BEST SEARCH_INDEXLEVEL_ATTACH
#define SEARCH_INDEXLEVEL_MAX (SEARCH_INDEXLEVEL_PARTIAL - 1)
    int (*end_message)(search_text_receiver_t *, uint8_t indexlevel);
    int (*end_mailbox)(search_text_receiver_t *, struct mailbox *);
    int (*flush)(search_text_receiver_t *);
    int (*audit_mailbox)(search_text_receiver_t *, bitvector_t *unindexed);
    int (*index_charset_flags)(int base_flags);
    int (*index_message_format)(int format, int is_snippet);
};

struct search_langstat {
    char *iso_lang;
    size_t count;
};

#define SEARCH_FLAG_CAN_BATCH      (1<<0)
#define SEARCH_FLAG_CAN_GUIDSEARCH (1<<1)
struct search_engine {
    const char *name;
    unsigned int flags;
#define _SEARCH_VERBOSE_MASK    (0x7)
#define SEARCH_VERBOSE(v)       ((v)&_SEARCH_VERBOSE_MASK)
#define SEARCH_MULTIPLE         (1<<3)  /* return results from
                                         * multiple folders */
// DEPRECATED: #define SEARCH_UNINDEXED   (1<<4)
#define SEARCH_COMPACT_COPYONE  (1<<5)  /* if only one source, just copy */
#define SEARCH_COMPACT_FILTER   (1<<6)  /* filter resulting DB for
                                         * expunged records */
#define SEARCH_COMPACT_REINDEX  (1<<7)  /* re-index all matching messages */
#define SEARCH_COMPACT_ONLYUPGRADE (1<<8) /* only compact if reindexing */
#define SEARCH_COMPACT_XAPINDEXED (1<<9) /* use XAPIAN index */
#define SEARCH_ATTACHMENTS_IN_ANY (1<<10) /* search attachments in ANY part */
#define SEARCH_COMPACT_ALLOW_PARTIALS (1<<11) /* allow partially indexed messages */
#define SEARCH_COMPACT_NONBLOCKING (1<<12) /* skip if locked */
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
    int (*list_files)(const char *userid, strarray_t *);
    int (*compact)(const char *userid, const strarray_t *reindextiers,
                   const strarray_t *srctiers, const char *desttier,
                   int flags);
    int (*deluser)(const char *userid);
    int (*check_config)(char **errstr);
    int (*langstats)(const char *userid, ptrarray_t *lstats, size_t *total_docs);
    int (*can_match)(enum search_op matchop, int partnum);
};

/* Returns the configured search engine */
extern const struct search_engine *search_engine();

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
#define SEARCH_UPDATE_XAPINDEXED (1<<3)
#define SEARCH_UPDATE_AUDIT (1<<4)
#define SEARCH_UPDATE_ALLOW_PARTIALS (1<<5)
#define SEARCH_UPDATE_REINDEX_PARTIALS (1<<6)
#define SEARCH_UPDATE_ALLOW_DUPPARTS (1<<7)
search_text_receiver_t *search_begin_update(int verbose);
int search_update_mailbox(search_text_receiver_t *rx,
                          struct mailbox *mailbox,
                          int min_indexlevel, int flags);
int search_end_update(search_text_receiver_t *rx);

/* Create a search text receiver for snippets. For each non-empty
 * snippet generated from a message search part, callback proc is called.
 *
 * The callback is called in ascending order of SEARCH_PART definitions,
 * where higher valued search parts are more costly to generate snippets.
 * The callback may return 0 to continue snippet generation for the
 * message, or return IMAP_OK_COMPLETED to indicate that it does not
 * require more snippets for this message. It still must be prepared
 * to receive more snippets for this message. */
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
int search_list_files(const char *userid, strarray_t *);
int search_compact(const char *userid, const strarray_t *reindextiers,
                   const strarray_t *srctiers, const char *desttier, int verbose);
int search_deluser(const char *userid);
int search_check_config(char **errstr);

int search_can_match(enum search_op matchop, int partnum);

/* for debugging */
extern const char *search_op_as_string(int op);

/* for mbpath */
extern int xapian_basedir(const char *tier, const char *mboxname, const char *part,
                          const char *root, char **basedir);



#endif
