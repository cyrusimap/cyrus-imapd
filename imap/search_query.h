/* search_result.h -- search result data structure
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

#ifndef __CYRUS_SEARCH_RESULT_H__
#define __CYRUS_SEARCH_RESULT_H__

#include "mailbox.h"
#include "message.h"
#include "conversations.h"
#include "util.h"
#include "bitvector.h"
#include "ptrarray.h"

struct sortcrit;	    /* imapd.h */
struct searchargs;	    /* imapd.h */
typedef struct search_subquery search_subquery_t;
typedef struct search_query search_query_t;
typedef struct search_folder search_folder_t;

struct search_folder {
    char *mboxname;
    uint32_t uidvalidity;
    uint64_t highest_modseq; /* of returned messages, not the folder */
    int id;
    bitvector_t uids;
    struct msgdata *msgdata;
};

struct search_subquery {
    char *mboxname;		/* may be NULL */
    search_expr_t *indexed;	/* may be NULL */
    search_expr_t *expr;
    hash_table folders_by_name;
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
    /*
     * Input parameters of the query.  Set these after
     * search_query_new() and before search_query_run().
     */
    struct searchargs *searchargs;
    int multiple;
    int verbose;

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

    /*
     * Resulting messages from a search engine query or a folder scan
     * need to be organised per-folder both for the secondary scan
     * (which needs to proceed per-folder to minimise the number of
     * index_open() calls) and for reporting back to the IMAP client.
     */
    ptrarray_t merged_msgdata;
    int error;
    hash_table folders_by_name;
    ptrarray_t folders_by_id;
    search_subquery_t *current_sub;
};

extern search_query_t *search_query_new(struct index_state *state,
					struct searchargs *);
extern int search_query_run(search_query_t *query);
extern void search_query_free(search_query_t *query);

extern search_folder_t *search_query_find_folder(search_query_t *query,
						 const char *mboxname);
extern void search_folder_use_msn(search_folder_t *, struct index_state *);
extern struct seqset *search_folder_get_seqset(const search_folder_t *);
extern uint32_t search_folder_get_min(const search_folder_t *);
extern uint32_t search_folder_get_max(const search_folder_t *);
extern unsigned int search_folder_get_count(const search_folder_t *);
#define search_folder_foreach(folder, u) \
    for ((u) = bv_next_set(&(folder)->uids, 0) ; \
	 (u) != -1 ; \
	 (u) = bv_next_set(&(folder)->uids, (u)+1))
extern uint64_t search_folder_get_highest_modseq(const search_folder_t *);


#endif /* __CYRUS_SEARCH_RESULT_H__ */
