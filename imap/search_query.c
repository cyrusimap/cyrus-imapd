/* search_result.c -- search result data structure
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
#include <stdlib.h>
#include <syslog.h>
#include <string.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "imap_err.h"
#include "search_expr.h"
#include "search_query.h"
#include "imapd.h"
#include "message.h"
#include "annotate.h"
#include "global.h"
#include "xstrlcpy.h"
#include "xmalloc.h"

/* ====================================================================== */

EXPORTED search_query_t *search_query_new(struct index_state *state,
					  int multiple)
{
    search_query_t *query;

    query = xzmalloc(sizeof(*query));
    query->state = state;
    query->multiple = multiple;
    construct_hash_table(&query->subs_by_folder, 128, 0);
    construct_hash_table(&query->subs_by_indexed, 128, 0);
    ptrarray_init(&query->merged_msgdata);
    construct_hash_table(&query->folders_by_name, 128, 0);
    ptrarray_init(&query->folders_by_id);

    return query;
}

static void folder_free(void *data)
{
    search_folder_t *folder = data;

    free(folder->mboxname);
//     _index_msgdata_free(folder->msgdata);
    bv_free(&folder->uids);
    free(folder);
}

static void subquery_free(void *data)
{
    search_subquery_t *sub = data;

    free(sub->mboxname);
    search_expr_free(sub->indexed);
    search_expr_free(sub->expr);
    free_hash_table(&sub->folders_by_name, folder_free);
    free(sub);
}

EXPORTED void search_query_free(search_query_t *query)
{
    if (!query) return;
    free_hash_table(&query->subs_by_folder, subquery_free);
    free_hash_table(&query->subs_by_indexed, subquery_free);
    ptrarray_fini(&query->folders_by_id);
    free_hash_table(&query->folders_by_name, folder_free);
    ptrarray_fini(&query->merged_msgdata);
    free(query);
}

/* ====================================================================== */


/*
 * Find the named folder folder.  Returns NULL if there are no
 * search results for that folder.
 */
EXPORTED search_folder_t *search_query_find_folder(search_query_t *query,
						   const char *mboxname)
{
    return (search_folder_t *)hash_lookup(mboxname, &query->folders_by_name);
}

/*
 * Switch the folder over to reporting MSNs rather than UIDs.
 */
EXPORTED void search_folder_use_msn(search_folder_t *folder, struct index_state *state)
{
    int uid;
    unsigned msgno;
    bitvector_t msns = BV_INITIALIZER;

    search_folder_foreach(folder, uid) {
	msgno = index_finduid(state, uid);
	if (index_getuid(state, msgno) == uid)
	    bv_set(&msns, msgno);
    }
    bv_free(&folder->uids);
    folder->uids = msns;
}

/*
 * Return the results for the given folder as a sequence of UIDs (or
 * MSNs if search_folder_use_msn() has been called).  The caller is
 * responsible for freeing the result using seqset_free()
 */
EXPORTED struct seqset *search_folder_get_seqset(const search_folder_t *folder)
{
    struct seqset *seq = seqset_init(0, SEQ_SPARSE);
    int uid;

    for (uid = bv_next_set(&folder->uids, 0) ;
	 uid != -1 ;
	 uid = bv_next_set(&folder->uids, uid+1))
	seqset_add(seq, uid, 1);

    return seq;
}

/*
 * Return the minimum UID (or MSN if search_folder_use_msn() has been
 * called).
 */
EXPORTED uint32_t search_folder_get_min(const search_folder_t *folder)
{
    return bv_first_set(&folder->uids);
}

/*
 * Return the maximum UID (or MSN if search_folder_use_msn() has been
 * called).
 */
EXPORTED uint32_t search_folder_get_max(const search_folder_t *folder)
{
    return bv_last_set(&folder->uids);
}

/*
 * Returns the count of UIDs or MSNs.
 */
EXPORTED unsigned int search_folder_get_count(const search_folder_t *folder)
{
    return bv_count(&folder->uids);
}

EXPORTED uint64_t search_folder_get_highest_modseq(const search_folder_t *folder)
{
    return folder->highest_modseq;
}

/* ====================================================================== */

static search_folder_t *query_get_folder(search_query_t *query, const char *mboxname)
{
    hash_table *table;
    search_folder_t *folder;

    if (query->current_sub)
	table = &query->current_sub->folders_by_name;
    else
	table = &query->folders_by_name;

    folder = (search_folder_t *)hash_lookup(mboxname, table);
    if (!folder) {
	folder = xzmalloc(sizeof(*folder));
	folder->mboxname = xstrdup(mboxname);
	folder->id = -1;
	hash_insert(folder->mboxname, folder, table);
    }
    return folder;
}

static search_folder_t *query_get_valid_folder(search_query_t *query,
					       const char *mboxname,
					       uint32_t uidvalidity)
{
    search_folder_t *folder;

    folder = query_get_folder(query, mboxname);

    if (uidvalidity < folder->uidvalidity) {
	/* these are uids are too old, forget them */
	return NULL;
    }
    if (uidvalidity > folder->uidvalidity) {
	/* these uids are newer than what we have,
	 * forget the old ones; or none at all and
	 * remember the uidvalidity for later */
	bv_clearall(&folder->uids);
	folder->uidvalidity = uidvalidity;
    }

    if (folder->id < 0) {
	folder->id = query->folders_by_id.count;
	ptrarray_append(&query->folders_by_id, folder);
    }

    return folder;
}

static void folder_add_uid(search_folder_t *folder, uint32_t uid)
{
    bv_set(&folder->uids, uid);
}

static void folder_remove_uid(search_folder_t *folder, uint32_t uid)
{
    bv_clear(&folder->uids, uid);
}

static void folder_add_modseq(search_folder_t *folder, uint64_t modseq)
{
    if (modseq > folder->highest_modseq)
	folder->highest_modseq = modseq;
}

static int query_begin_index(search_query_t *query,
			     const char *mboxname,
			     struct index_state **statep)
{
    int r = 0;

    /* open an index_state */
    if (!strcmp(query->state->mailbox->name, mboxname)) {
	*statep = query->state;
    }
    else {
	struct index_init init;

	memset(&init, 0, sizeof(struct index_init));
	init.userid = query->searchargs->userid;
	init.authstate = query->searchargs->authstate;
	init.out = query->state->out;

	r = index_open(mboxname, &init, statep);
	if (r) goto out;

	index_checkflags(*statep, 0, 0);
    }

    /* make sure \Deleted messages are expunged.  Will also lock the
     * mailbox state and read any new information */
    r = index_expunge(*statep, NULL, 1);
    if (r) goto out;

out:
    return r;
}

static void query_end_index(search_query_t *query,
			    struct index_state **statep)
{
    if (*statep != query->state)
	index_close(statep);
    else
	*statep = NULL;
}

/* ====================================================================== */

static void merge_one_folder(const char *key, void *data, void *rock)
{
    const char *mboxname = key;
    search_folder_t *from_folder = data;
    search_folder_t *to_folder;
    search_query_t *query = rock;

    to_folder = query_get_valid_folder(query, mboxname, from_folder->uidvalidity);
    if (to_folder)
	bv_oreq(&to_folder->uids, &from_folder->uids);
}

static void query_merge_folders(search_query_t *query, search_subquery_t *sub)
{
    hash_enumerate(&sub->folders_by_name, merge_one_folder, query);
}

static void subquery_post_indexed(const char *key, void *data, void *rock)
{
    const char *mboxname = key;
    search_folder_t *folder = data;
    search_query_t *query = rock;
    search_subquery_t *sub = query->current_sub;
    struct index_state *state = NULL;
    unsigned msgno;
    int r = 0;

    if (query->error) return;

    r = query_begin_index(query, mboxname, &state);
    if (r) goto out;

    if (!state->exists) goto out;

    search_expr_internalise(state->mailbox, sub->expr);

    /* One pass through the folder's message list */
    for (msgno = 1 ; msgno <= state->exists ; msgno++) {
	struct index_record *record = &state->map[msgno-1].record;

	if (!bv_isset(&folder->uids, record->uid))
	    continue;

	/* can happen if we didn't "tellchanges" yet */
	if (record->system_flags & FLAG_EXPUNGED)
	    continue;

	/* run the search program */
	if (!index_search_evaluate(state, sub->expr, msgno))
	    folder_remove_uid(folder, record->uid);
    }

    r = 0;

out:
    query_end_index(query, &state);
    if (r) query->error = r;
}

void build_query(search_builder_t *bx, search_expr_t *e)
{
    search_expr_t *child;
    int bop = -1;

    switch (e->op) {

    case SEOP_NOT:
	bop = SEARCH_OP_NOT;
	break;

    case SEOP_AND:
	bop = SEARCH_OP_AND;
	break;

    case SEOP_OR:
	bop = SEARCH_OP_OR;
	break;

    case SEOP_FUZZYMATCH:
	if (e->attr && e->attr->part >= 0) {
	    bx->match(bx, e->attr->part, e->value.s);
	}
	return;

    default:
	return;
    }

    if (e->children) {
	assert(bop != -1);
	bx->begin_boolean(bx, bop);
	for (child = e->children ; child ; child = child->next)
	    build_query(bx, child);
	bx->end_boolean(bx, bop);
    }
}

static int add_hit(const char *mboxname, uint32_t uidvalidity,
		   uint32_t uid, void *rock)
{
    search_query_t *query = rock;
    search_folder_t *folder = query_get_valid_folder(query, mboxname, uidvalidity);
    if (folder)
	folder_add_uid(folder, uid);
    return 0;
}

static void subquery_run_indexed(const char *key __attribute__((unused)),
				 void *data, void *rock)
{
//     const char *mboxname = key;
    search_subquery_t *sub = data;
    search_query_t *query = rock;
    search_builder_t *bx;
    int r;

    if (query->error) return;

    if (query->verbose) {
	char *s = search_expr_serialise(sub->indexed);
	syslog(LOG_INFO, "Running indexed subquery: %s", s);
	free(s);
    }

    query->current_sub = sub;

    bx = search_begin_search(query->state->mailbox,
			     (query->multiple ? SEARCH_MULTIPLE : 0)|
			     SEARCH_VERBOSE(query->verbose));
    if (!bx) {
	r = IMAP_INTERNAL;
	goto out;
    }
    build_query(bx, sub->indexed);
    r = bx->run(bx, add_hit, query);
    search_end_search(bx);
    if (r) goto out;

    if (sub->expr && sub->expr->op != SEOP_TRUE) {

	if (query->verbose) {
	    char *s = search_expr_serialise(sub->expr);
	    syslog(LOG_INFO, "Applying scan expression: %s", s);
	    free(s);
	}

	hash_enumerate(&sub->folders_by_name, subquery_post_indexed, query);
    }

    query->current_sub = NULL;

    query_merge_folders(query, sub);

out:
    if (r) query->error = r;
}

static int subquery_run_one_folder(search_query_t *query,
				   const char *mboxname,
				   search_expr_t *e)
{
    struct index_state *state = NULL;
    unsigned msgno;
    search_folder_t *folder = NULL;
    int r = 0;

    if (query->verbose) {
	char *s = search_expr_serialise(e);
	syslog(LOG_INFO, "Running folder scan subquery for %s: %s", mboxname, s);
	free(s);
    }

    r = query_begin_index(query, mboxname, &state);
    if (r) goto out;

    if (!state->exists) goto out;

    search_expr_internalise(state->mailbox, e);

    /* One pass through the folder's message list */
    for (msgno = 1 ; msgno <= state->exists ; msgno++) {
	struct index_record *record = &state->map[msgno-1].record;

	/* can happen if we didn't "tellchanges" yet */
	if (record->system_flags & FLAG_EXPUNGED)
	    continue;

	/* run the search program */
	if (!index_search_evaluate(state, e, msgno))
	    continue;

	if (!folder) {
	    folder = query_get_valid_folder(query, mboxname,
					    state->mailbox->i.uidvalidity);
	    if (!folder) {
		r = IMAP_INTERNAL;
		goto out;   /* can't happen */
	    }
	}

	folder_add_uid(folder, record->uid);
	folder_add_modseq(folder, record->modseq);
    }

    r = 0;

out:
    query_end_index(query, &state);
    return r;
}

static void subquery_run_folder(const char *key, void *data, void *rock)
{
    const char *mboxname = key;
    search_subquery_t *sub = data;
    search_query_t *query = rock;
    int r;

    if (query->error) return;
    r = subquery_run_one_folder(query, mboxname, sub->expr);
    if (r) query->error = r;
}

static int subquery_run_global(void *rock,
			       const char *key, size_t keylen,
			       const char *val __attribute((unused)),
			       size_t vallen __attribute((unused)))
{
    search_query_t *query = rock;
    char *mboxname = xstrndup(key, keylen);
    search_subquery_t *sub;
    int r;

    sub = (search_subquery_t *)hash_lookup(mboxname, &query->subs_by_folder);
    if (sub) {
	/* this folder also has a per-folder scan expression, OR it in */
	search_expr_t *e = search_expr_new(NULL, SEOP_OR);
	search_expr_append(e, sub->expr);
	sub->expr = NULL;
	search_expr_append(e, search_expr_duplicate(query->global_sub.expr));

	r = subquery_run_one_folder(query, mboxname, e);
	search_expr_free(e);
    }
    else {
	r = subquery_run_one_folder(query, mboxname, query->global_sub.expr);
    }

    free(mboxname);
    return r;
}

static search_subquery_t *subquery_new(void)
{
    search_subquery_t *sub = xzmalloc(sizeof(*sub));
    construct_hash_table(&sub->folders_by_name, 128, 0);
    return sub;
}

static void query_add_subquery(const char *mboxname,
			       search_expr_t *indexed,
			       search_expr_t *e,
			       void *rock)
{
    search_query_t *query = rock;
    search_subquery_t *sub;

    if (indexed) {
	char *key = search_expr_serialise(indexed);
	sub = (search_subquery_t *)hash_lookup(key, &query->subs_by_indexed);
	if (!sub) {
	    sub = subquery_new();
	    sub->indexed = indexed;
	    hash_insert(key, sub, &query->subs_by_indexed);
	    query->indexed_count++;
	}
	free(key);
    }
    else if (mboxname) {
	sub = (search_subquery_t *)hash_lookup(mboxname, &query->subs_by_folder);
	if (!sub) {
	    sub = subquery_new();
	    sub->mboxname = xstrdup(mboxname);
	    hash_insert(sub->mboxname, sub, &query->subs_by_folder);
	    query->folder_count++;
	}
    }
    else {
	sub = &query->global_sub;
    }

    if (sub->expr == NULL) {
	/* adding the first expression: just store it */
	sub->expr = e;
    }
    else if (sub->expr->op != SEOP_OR) {
	/* adding the second: make a new OR node */
	search_expr_t *or = search_expr_new(NULL, SEOP_OR);
	search_expr_append(or, sub->expr);
	search_expr_append(or, e);
	sub->expr = or;
    }
    else {
	/* append to the existing OR node */
	search_expr_append(sub->expr, e);
    }
}

EXPORTED int search_query_run(search_query_t *query,
			      struct searchargs *searchargs)
{
    int r = 0;

    query->searchargs = searchargs;

    search_expr_normalise(&searchargs->root);
    search_expr_split_by_folder_and_index(searchargs->root, query_add_subquery, query);
    searchargs->root = NULL;

    if (query->indexed_count) {
	/*
	 * Indexed searches proceed in two phases.  The first runs
	 * all the search engine queries, and builds a set of matched
	 * uids per folder.  The second runs per folder and applies
	 * any scan expression.
	 */
	hash_enumerate(&query->subs_by_indexed, subquery_run_indexed, query);
	r = query->error;
	if (r) goto out;
    }

    if (query->global_sub.expr) {
	/* We have a scan expression which applies to all folders.
	 * Walk over every folder, applying the scan expression. */
	r = mboxlist_allusermbox(mboxname_to_userid(query->state->mailbox->name),
				 subquery_run_global, query, /*+deleted*/0);
	if (r) goto out;
    }
    else if (query->folder_count) {
	/* We only have scan expressions limited to specific folders,
	 * let's iterate those folders */
	hash_enumerate(&query->subs_by_folder, subquery_run_folder, query);
	r = query->error;
	if (r) goto out;
    }
    else {
    }

out:
    return r;
}

/* ====================================================================== */
