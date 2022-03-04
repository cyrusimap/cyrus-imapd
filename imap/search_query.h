/* search_query.h -- search query routines
 *
 * Copyright (c) 1994-2018 Carnegie Mellon University.  All rights reserved.
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

#ifndef __CYRUS_SEARCH_RESULT_H__
#define __CYRUS_SEARCH_RESULT_H__

#include "mailbox.h"
#include "message.h"
#include "conversations.h"
#include "util.h"
#include "bitvector.h"
#include "ptrarray.h"
#include "dynarray.h"
#include "search_engines.h"

struct sortcrit;            /* imapd.h */
struct searchargs;          /* imapd.h */
typedef struct search_subquery search_subquery_t;
typedef struct search_query search_query_t;
typedef struct search_folder search_folder_t;

struct search_folder_partnum {
    uint32_t uid;
    uint32_t partnum;
};

struct search_folder {
    char *mboxname;
    uint32_t uidvalidity;
    uint64_t highest_modseq; /* of returned messages, not the folder */
    uint64_t first_modseq; /* of returned messages, not the folder */
    uint64_t last_modseq; /* of returned messages, not the folder */
    int id;
    bitvector_t uids;
    bitvector_t found_uids;
    int found_dirty;
    dynarray_t partnums; /* list of struct search_folder_partnum */
};

struct search_subquery {
    char *mboxname;             /* may be NULL */
    search_expr_t *indexed;     /* may be NULL */
    search_expr_t *expr;
};

struct search_saved_msgdata {
    /* Used to remember MsgData** arrays returned by
     * index_msgdata_load() for later freeing. */
    struct msgdata **msgdata;
    int n;
};

struct search_query {

    /*
     * A query may report results from multiple folders, but we need
     * this one specific folder to tell us the username to limit the
     * search engine scope.  Also, for most IMAP search commands we
     * start with a selected folder anyway so we need to avoid
     * double-opening it.
     */
    struct index_state *state;

    int (*checkfolder)(const char *mboxname, void *rock);
    void *checkfolderrock;
    /*
     * Input parameters of the query.  Set these after
     * search_query_new() and before search_query_run().
     */
    struct searchargs *searchargs;
    const struct sortcrit *sortcrit;
    int multiple;
    int need_ids;
    int need_expunge;
    int want_expunged;
    uint32_t want_mbtype;
    int verbose;
    int ignore_timer;
    int attachments_in_any;
    int want_partids;

    /*
     * A query comprises multiple sub-queries logically ORed together.
     * The sub-queries are organised by the first of three criteria
     * which might apply:
     *
     *  - subs_by_indexed: one or more indexed match nodes (need to scan
     *  all messages reported by a given search engine lookup)
     *
     *  - subs_by_folder: a single positive folder match node (need to
     *  scan all messages in a given folder)
     *
     *  - global_sub: neither indexed nor folder (need to scan all
     *  messages in many folders)
     */
    hash_table subs_by_indexed;
    unsigned int indexed_count;
    hash_table subs_by_folder;
    unsigned int folder_count;
    search_subquery_t global_sub;

    /* Used as a temporary holder for errors, e.g. to pass an error from
     * a hashtable enumeration callback back up to the caller */
    int error;
    /*
     * Resulting messages from a search engine query or a folder scan
     * need to be organised per-folder both for the secondary scan
     * (which needs to proceed per-folder to minimise the number of
     * index_open() calls) and for reporting back to the IMAP client.
     */
    hash_table folders_by_name;
    /*
     * Some callers need a unique and contiguous 0-based set of integer
     * ids for folders which have any results.  Note that the
     * folders_by_name hash table may contain folders with no results in
     * them, e.g. when the search engine returns hits for a folder which
     * all subsequently prove to be deleted.
     */
    ptrarray_t folders_by_id;
    /*
     * Array of search_saved_msgdata objects for later freeing
     */
    ptrarray_t saved_msgdata;
    /*
     * When sorting in requested, this array contains the final merged
     * sort results as an array of MsgData*.  The MsgData objects might
     * be "fake" ones if the results were retrieved from the cache DB,
     * but the following fields are guaranteed to be usable: uid, cid,
     * folder, guid.
     */
    ptrarray_t merged_msgdata;

    /* A map from string message part ids to a unique numeric
     * identifier. This allows to save good chunk of string mallocs */
    hashu64_table partid_by_num;
    hash_table partnum_by_id;
    uint32_t partnum_seq;

};

extern search_query_t *search_query_new(struct index_state *state,
                                        struct searchargs *);
extern int search_query_run(search_query_t *query);
extern void search_query_free(search_query_t *query);

extern search_folder_t *search_query_find_folder(search_query_t *query,
                                                 const char *mboxname);
extern void search_folder_use_msn(search_folder_t *, struct index_state *);
extern seqset_t *search_folder_get_seqset(const search_folder_t *);
extern int search_folder_get_array(const search_folder_t *, unsigned int **);
extern uint32_t search_folder_get_min(const search_folder_t *);
extern uint32_t search_folder_get_max(const search_folder_t *);
extern unsigned int search_folder_get_count(const search_folder_t *);
#define search_folder_foreach(folder, u) \
    for ((u) = bv_next_set(&(folder)->uids, 0) ; \
         (u) != -1 ; \
         (u) = bv_next_set(&(folder)->uids, (u)+1))
extern uint64_t search_folder_get_highest_modseq(const search_folder_t *);
extern uint64_t search_folder_get_first_modseq(const search_folder_t *);
extern uint64_t search_folder_get_last_modseq(const search_folder_t *);

extern void search_build_query(search_builder_t *bx, search_expr_t *e);

extern int search_is_mutable(struct sortcrit *sortcrit, search_expr_t *e);


#endif /* __CYRUS_SEARCH_RESULT_H__ */
