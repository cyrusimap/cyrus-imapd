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

#include "assert.h"
#include "search_expr.h"
#include "search_query.h"
#include "imapd.h"
#include "message.h"
#include "annotate.h"
#include "global.h"
#include "bsearch.h"
#include "xstrlcpy.h"
#include "xmalloc.h"

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"

/* ====================================================================== */

EXPORTED search_query_t *search_query_new(struct index_state *state,
                                          struct searchargs *searchargs)
{
    search_query_t *query;

    query = xzmalloc(sizeof(*query));
    query->state = state;
    query->searchargs = searchargs;
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
    bv_free(&folder->uids);
    bv_free(&folder->unchecked_uids);
    free(folder);
}

static void subquery_free(void *data)
{
    search_subquery_t *sub = data;

    free(sub->mboxname);
    search_expr_free(sub->indexed);
    search_expr_free(sub->expr);
    free(sub);
}

EXPORTED void search_query_free(search_query_t *query)
{
    int i;

    if (!query) return;
    free_hash_table(&query->subs_by_folder, subquery_free);
    free_hash_table(&query->subs_by_indexed, subquery_free);
    search_expr_free(query->global_sub.expr);
    ptrarray_fini(&query->folders_by_id);
    free_hash_table(&query->folders_by_name, folder_free);
    ptrarray_fini(&query->merged_msgdata);

    /* free pending MsgData arrays */
    for (i = 0 ; i < query->saved_msgdata.count ; i++) {
        struct search_saved_msgdata *saved = ptrarray_nth(&query->saved_msgdata, i);
        index_msgdata_free(saved->msgdata, saved->n);
        free(saved);
    }
    ptrarray_fini(&query->saved_msgdata);

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
        if (index_getuid(state, msgno) == (unsigned)uid)
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
 * Return the results for a given folder as an array of UIDs (or MSNs if
 * search_folder_use_msn() has been called).  Returns the number of
 * results or zero, and the newly allocated array in *'arrayp'.  The
 * caller is responsible for freeing the result using free().
 */
EXPORTED int search_folder_get_array(const search_folder_t *folder, unsigned int **arrayp)
{
    int n = search_folder_get_count(folder);
    unsigned int *p;
    int uid;

    if (n) {

        p = *arrayp = xzmalloc(sizeof(unsigned int) * n);
        for (uid = bv_next_set(&folder->uids, 0) ;
             uid != -1 ;
             uid = bv_next_set(&folder->uids, uid+1))
            *p++ = (unsigned)uid;
    }

    return n;
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

EXPORTED uint64_t search_folder_get_first_modseq(const search_folder_t *folder)
{
    return folder->first_modseq;
}

EXPORTED uint64_t search_folder_get_last_modseq(const search_folder_t *folder)
{
    return folder->last_modseq;
}

/* ====================================================================== */

static search_folder_t *query_get_folder(search_query_t *query, const char *mboxname)
{
    search_folder_t *folder;

    folder = (search_folder_t *)hash_lookup(mboxname, &query->folders_by_name);
    if (!folder) {
        folder = xzmalloc(sizeof(*folder));
        folder->mboxname = xstrdup(mboxname);
        folder->id = -1;
        hash_insert(folder->mboxname, folder, &query->folders_by_name);
    }
    return folder;
}

static search_folder_t *query_get_valid_folder(search_query_t *query,
                                               const char *mboxname,
                                               uint32_t uidvalidity)
{
    search_folder_t *folder;

    if (mboxname_isdeletedmailbox(mboxname, 0) &&
        !(query->want_mbtype & MBTYPE_DELETED)) {
        return NULL;
    }

    if (mboxname_iscalendarmailbox(mboxname, 0) &&
       !(query->want_mbtype & MBTYPE_CALENDAR)) {
        return NULL;
    }

    if (mboxname_isaddressbookmailbox(mboxname, 0) &&
       !(query->want_mbtype & MBTYPE_ADDRESSBOOK)) {
        return NULL;
    }

    folder = query_get_folder(query, mboxname);
    if (uidvalidity) {
        if (uidvalidity < folder->uidvalidity) {
            /* these are uids are too old, forget them */
            return NULL;
        }
        if (uidvalidity > folder->uidvalidity) {
            /* these uids are newer than what we have,
            * forget the old ones; or none at all and
            * remember the uidvalidity for later */
            if (folder->uidvalidity) {
                bv_clearall(&folder->uids);
                bv_clearall(&folder->unchecked_uids);
            }
            folder->uidvalidity = uidvalidity;
        }
    }

    return folder;
}

static void folder_add_uid(search_folder_t *folder, uint32_t uid)
{
    bv_set(&folder->uids, uid);
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
    int needs_refresh = 0;

    /* open an index_state */
    if (!strcmp(index_mboxname(query->state), mboxname)) {
        *statep = query->state;
        needs_refresh = 1;
    }
    else {
        struct index_init init;

        memset(&init, 0, sizeof(struct index_init));
        init.userid = query->searchargs->userid;
        init.authstate = query->searchargs->authstate;
        init.out = query->state->out;
        init.want_expunged = query->want_expunged;
        init.want_mbtype = query->want_mbtype;

        r = index_open(mboxname, &init, statep);
        if (r == IMAP_PERMISSION_DENIED) r = IMAP_MAILBOX_NONEXISTENT;
        if (r == IMAP_MAILBOX_BADTYPE) r = IMAP_MAILBOX_NONEXISTENT;
        if (r) goto out;

        index_checkflags(*statep, 0, 0);
    }

    if (query->need_expunge) {
        /* make sure \Deleted messages are expunged.  Will also lock the
         * mailbox state and read any new information */
        r = index_expunge(*statep, NULL, 1);
        if (r) goto out;
    }
    else if (needs_refresh) {
        /* Expunge considered unhelpful - just refresh */
        r = index_refresh(*statep);
        if (r) goto out;
    }

    r = cmd_cancelled();

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

static void add_folder(const char *key __attribute__((unused)),
                       void *data, void *rock)
{
    search_folder_t *folder = data;
    ptrarray_t *array = rock;

    ptrarray_append(array, folder);
}

static int compare_folders(const void **v1, const void **v2)
{
    const search_folder_t *f1 = (const search_folder_t *)*v1;
    const search_folder_t *f2 = (const search_folder_t *)*v2;

    return bsearch_compare_mbox(f1->mboxname, f2->mboxname);
}

/*
 * Assign a contiguous 0-based sequence of folder ids to the folders
 * that have any remaining uids in the search results, in folder name
 * order.  The order isn't necessary but helps make the results
 * consistent which makes testing easier.
 */
static void query_assign_folder_ids(search_query_t *query)
{
    ptrarray_t folders = PTRARRAY_INITIALIZER;
    int i;

    /* TODO: need a hash_values() function */
    hash_enumerate(&query->folders_by_name, add_folder, &folders);

    ptrarray_sort(&folders, compare_folders);

    for (i = 0 ; i < folders.count ; i++) {
        search_folder_t *folder = ptrarray_nth(&folders, i);

        if (search_folder_get_count(folder) && folder->id < 0) {
            folder->id = query->folders_by_id.count;
            ptrarray_append(&query->folders_by_id, folder);
        }
    }

    ptrarray_fini(&folders);
}

/* ====================================================================== */

static void query_load_msgdata(search_query_t *query,
                               search_folder_t *folder,
                               struct index_state *state,
                               unsigned *msgno_list, unsigned nmsgs)
{
    unsigned i;
    MsgData **msgdata;
    struct search_saved_msgdata *saved;

    msgdata = index_msgdata_load(state, msgno_list, nmsgs, query->sortcrit, 0, NULL);

    /* add the new messages to the global list */
    for (i = 0 ; i < nmsgs ; i++) {
        ptrarray_append(&query->merged_msgdata, msgdata[i]);
        msgdata[i]->folder = folder;
    }

    /* save the MsgData array for later deletion */
    saved = xzmalloc(sizeof(*saved));
    saved->msgdata = msgdata;
    saved->n = nmsgs;
    ptrarray_append(&query->saved_msgdata, saved);
}

struct subquery_rock {
    search_query_t *query;
    search_subquery_t *sub;
};

/*
 * After an indexed subquery is run, we have accumulated a number of
 * unchecked UID hits in folders.  Here we check those UIDs for a) not
 * being deleted since indexing and b) matching any unindexed scan
 * expression.  We also take advantage of having an open index_state to
 * load some MsgData objects and save them to query->merged_msgdata.
 */
static void subquery_post_indexed(const char *key, void *data, void *rock)
{
    const char *mboxname = key;
    search_folder_t *folder = data;
    struct subquery_rock *qr = rock;
    search_query_t *query = qr->query;
    search_subquery_t *sub = qr->sub;
    struct index_state *state = NULL;
    unsigned msgno;
    unsigned nmsgs = 0;
    unsigned *msgno_list = NULL;
    int r = 0;

    if (query->error) return;
    if (!folder->unchecked_dirty) return;

    if (sub->expr && query->verbose) {
        char *s = search_expr_serialise(sub->expr);
        syslog(LOG_INFO, "Folder %s: applying scan expression: %s",
                folder->mboxname, s);
        free(s);
    }
    if (query->sortcrit && query->verbose) {
        char *s = sortcrit_as_string(query->sortcrit);
        syslog(LOG_INFO, "Folder %s: loading MsgData for sort criteria %s",
                folder->mboxname, s);
        free(s);
    }

    r = query_begin_index(query, mboxname, &state);
    if (r == IMAP_MAILBOX_NONEXISTENT) {
        /* Silently swallow mailboxes which have been deleted, renamed,
         * or had their ACL changed to prevent us reading them, after
         * the index was constructed [IRIS-2469].  */
        r = 0;
        goto out;
    }
    if (r) goto out;

    if (!state->exists) goto out;

    search_expr_internalise(state, sub->expr);

    if (query->sortcrit)
        msgno_list = (unsigned *) xmalloc(state->exists * sizeof(unsigned));

    /* One pass through the folder's message list */
    for (msgno = 1 ; msgno <= state->exists ; msgno++) {
        struct index_map *im = &state->map[msgno-1];

        r = cmd_cancelled();
        if (r) goto out;

        /* we only want to look at unchecked UIDs */
        if (!bv_isset(&folder->unchecked_uids, im->uid))
            continue;

        /* moot if already in the uids set */
        if (bv_isset(&folder->uids, im->uid))
            continue;

        /* can happen if we didn't "tellchanges" yet */
        if ((im->internal_flags & FLAG_INTERNAL_EXPUNGED) && !query->want_expunged)
            continue;

        /* run the search program */
        if (!index_search_evaluate(state, sub->expr, msgno))
            continue;

        /* we have a new UID that needs to be merged in */

        folder_add_uid(folder, im->uid);
        folder_add_modseq(folder, im->modseq);
        if (query->sortcrit)
            msgno_list[nmsgs++] = msgno;
        /* track first and last for MIN/MAX queries */
        if (!folder->first_modseq) folder->first_modseq = im->modseq;
        folder->last_modseq = im->modseq;
    }

    /* msgno_list contains only the MSNs for newly
     * checked messages */
    if (query->sortcrit && nmsgs)
        query_load_msgdata(query, folder, state, msgno_list, nmsgs);

    folder->unchecked_dirty = 0;
    r = 0;

out:
    query_end_index(query, &state);
    free(msgno_list);
    if (r) query->error = r;
}

EXPORTED void search_build_query(search_builder_t *bx, search_expr_t *e)
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
            search_build_query(bx, child);
        bx->end_boolean(bx, bop);
    }
}

static int add_unchecked_uid(const char *mboxname, uint32_t uidvalidity,
                             uint32_t uid, void *rock)
{
    search_query_t *query = rock;
    search_folder_t *folder = query_get_valid_folder(query, mboxname, uidvalidity);
    if (folder) {
        bv_set(&folder->unchecked_uids, uid);
        folder->unchecked_dirty = 1;
    }
    return 0;
}

static void subquery_run_indexed(const char *key __attribute__((unused)),
                                 void *data, void *rock)
{
//     const char *mboxname = key;
    search_subquery_t *sub = data;
    search_query_t *query = rock;
    search_builder_t *bx;
    struct subquery_rock qr;
    int r;

    if (query->error) return;

    if (query->verbose) {
        char *s = search_expr_serialise(sub->indexed);
        syslog(LOG_INFO, "Running indexed subquery: %s", s);
        free(s);
    }

    bx = search_begin_search(query->state->mailbox,
                             (query->multiple ? SEARCH_MULTIPLE : 0)|
                             SEARCH_VERBOSE(query->verbose));
    if (!bx) {
        r = IMAP_INTERNAL;
        goto out;
    }
    search_build_query(bx, sub->indexed);
    r = bx->run(bx, add_unchecked_uid, query);
    search_end_search(bx);
    if (r) goto out;

    qr.query = query;
    qr.sub = sub;
    hash_enumerate(&query->folders_by_name, subquery_post_indexed, &qr);

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
    unsigned nmsgs = 0;
    unsigned *msgno_list = NULL;
    int r = 0;

    if (query->verbose) {
        char *s = search_expr_serialise(e);
        syslog(LOG_INFO, "Folder %s: running folder scan subquery: %s",
                mboxname, s);
        free(s);
    }
    if (query->sortcrit && query->verbose) {
        char *s = sortcrit_as_string(query->sortcrit);
        syslog(LOG_INFO, "Folder %s: loading MsgData for sort criteria %s",
                mboxname, s);
        free(s);
    }

    r = query_begin_index(query, mboxname, &state);
    if (r == IMAP_MAILBOX_NONEXISTENT) {
        /* Silently swallow mailboxes which have been deleted, renamed,
         * or had their ACL changed to prevent us reading them, after
         * the index was constructed [IRIS-2469].  */
        r = 0;
        goto out;
    }
    if (r) goto out;

    if (!state->exists) goto out;

    search_expr_internalise(state, e);

    if (query->sortcrit)
        msgno_list = (unsigned *) xmalloc(state->exists * sizeof(unsigned));

    /* One pass through the folder's message list */
    for (msgno = 1 ; msgno <= state->exists ; msgno++) {
        struct index_map *im = &state->map[msgno-1];

        r = cmd_cancelled();
        if (r) goto out;

        /* can happen if we didn't "tellchanges" yet */
        if ((im->internal_flags & FLAG_INTERNAL_EXPUNGED) && !query->want_expunged)
            continue;

        /* run the search program */
        if (!index_search_evaluate(state, e, msgno))
            continue;

        if (!folder) {
            folder = query_get_valid_folder(query, mboxname, state->uidvalidity);
            if (!folder) {
                r = IMAP_INTERNAL;
                goto out;   /* can't happen */
            }
        }

        /* moot if already in the uids set */
        if (bv_isset(&folder->uids, im->uid))
            continue;

        folder_add_uid(folder, im->uid);
        folder_add_modseq(folder, im->modseq);

        if (query->sortcrit)
            msgno_list[nmsgs++] = msgno;

        /* track first and last for MIN/MAX queries */
        if (!folder->first_modseq) folder->first_modseq = im->modseq;
        folder->last_modseq = im->modseq;
    }

    if (query->sortcrit && nmsgs)
        query_load_msgdata(query, folder, state, msgno_list, nmsgs);

    r = 0;

out:
    query_end_index(query, &state);
    free(msgno_list);
    return r;
}

static void subquery_run_folder(const char *key, void *data, void *rock)
{
    const char *mboxname = key;
    search_subquery_t *sub = data;
    search_query_t *query = rock;
    int r;

    if (query->error) return;
    if (!query->multiple && strcmp(mboxname, index_mboxname(query->state)))
        return;
    r = subquery_run_one_folder(query, mboxname, sub->expr);
    if (r) query->error = r;
}

static int subquery_run_global(search_query_t *query, const char *mboxname)
{
    search_subquery_t *sub;
    search_expr_t *e, *exprs[2];
    int nexprs = 0;
    int r;

    sub = (search_subquery_t *)hash_lookup(mboxname, &query->subs_by_folder);
    if (sub) {
        /* this folder also has a per-folder scan expression, OR it in */
        exprs[nexprs++] = search_expr_duplicate(sub->expr);
    }

    if (query->global_sub.expr)
        exprs[nexprs++] = search_expr_duplicate(query->global_sub.expr);

    switch (nexprs) {
    case 0:
        e = search_expr_new(NULL, SEOP_TRUE);
        break;
    case 1:
        e = exprs[0];
        break;
    case 2:
        e = search_expr_new(NULL, SEOP_OR);
        search_expr_append(e, exprs[0]);
        search_expr_append(e, exprs[1]);
        break;
    }

    r = subquery_run_one_folder(query, mboxname, e);
    search_expr_free(e);
    return r;
}

static int subquery_run_global_cb(const mbentry_t *mbentry, void *rock)
{
    search_query_t *query = rock;
    return subquery_run_global(query, mbentry->name);
}

static search_subquery_t *subquery_new(void)
{
    search_subquery_t *sub = xzmalloc(sizeof(*sub));
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

EXPORTED int search_query_run(search_query_t *query)
{
    int r = 0;

    search_expr_split_by_folder_and_index(query->searchargs->root, query_add_subquery, query);
    query->searchargs->root = NULL;

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
        if (query->multiple) {
            char *userid = mboxname_to_userid(index_mboxname(query->state));
            r = mboxlist_usermboxtree(userid, subquery_run_global_cb, query, /*flags*/0);
            free(userid);
        }
        else {
            r = subquery_run_global(query, index_mboxname(query->state));
        }
        if (r) goto out;
    }
    else if (query->folder_count) {
        /* We only have scan expressions limited to specific folders,
         * let's iterate those folders */
        hash_enumerate(&query->subs_by_folder, subquery_run_folder, query);
        r = query->error;
        if (r) goto out;
    }

    if (query->need_ids)
        query_assign_folder_ids(query);

    if (query->sortcrit) {
        /*
         * Do a post-search sorting phase.
         *
         * Sorts MsgData objects.  These really really need to be replaced with
         * either message_t objects or some new smaller object which only stores
         * exactly the data we need to sort with, according to sortcrit, plus a
         * few things we always need like folder, uid, cid etc.  But in the
         * interests of getting this code working before Christmas we're going
         * to use MsgData for now, and in the way that means the least amount of
         * code changes.
         */
        index_msgdata_sort((MsgData **)query->merged_msgdata.data,
                           query->merged_msgdata.count,
                           query->sortcrit);
    }

out:
    return r;
}

/* ====================================================================== */

static int is_mutable_sort(struct sortcrit *sortcrit)
{
    int i;

    if (!sortcrit) return 0;

    for (i = 0; sortcrit[i].key; i++) {
        switch (sortcrit[i].key) {
            /* these are the mutable fields */
            case SORT_ANNOTATION:
            case SORT_MODSEQ:
            case SORT_HASFLAG:
            case SORT_CONVMODSEQ:
            case SORT_CONVEXISTS:
            case SORT_CONVSIZE:
            case SORT_HASCONVFLAG:
                return 1;
            default:
                break;
        }
    }

    return 0;
}

/* This function will return a TRUE value if anything in the
 * sort or search criteria returns a MUTABLE ordering, i.e.
 * the user can take actions which will change the order in
 * which the results are returned.  For example, the base
 * case of UID sort and all messages is NOT mutable */
EXPORTED int search_is_mutable(struct sortcrit *sortcrit,
                               struct searchargs *searchargs)
{
    if (is_mutable_sort(sortcrit))
        return 1;
    if (search_expr_is_mutable(searchargs->root))
        return 1;
    return 0;
}

