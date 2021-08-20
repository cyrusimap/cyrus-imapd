/* search_expr.c -- query tree handling for SEARCH
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
#include "index.h"
#include "message.h"
#include "charset.h"
#include "annotate.h"
#include "global.h"
#include "lsort.h"
#include "seen.h"
#include "xstrlcpy.h"
#include "xmalloc.h"

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"

#define DEBUG 0

#if DEBUG
static search_expr_t **the_rootp;
static search_expr_t *the_focus;
#endif

static void split(search_expr_t *e,
                  void (*cb)(const char *, search_expr_t *, search_expr_t *, void *),
                  void *rock);

/*-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-*/

static search_expr_t *append(search_expr_t *parent, search_expr_t *child)
{
    search_expr_t **tailp;

    for (tailp = &parent->children ; *tailp ; tailp = &(*tailp)->next)
        ;
    *tailp = child;
    child->next = NULL;
    child->parent = parent;

    return child;
}

static search_expr_t *detachp(search_expr_t **prevp)
{
    search_expr_t *child = *prevp;

    if (child) {
        *prevp = child->next;
        child->next = NULL;
        child->parent = NULL;
    }

    return child;
}

EXPORTED void search_expr_detach(search_expr_t *parent, search_expr_t *child)
{
    search_expr_t **prevp;

    for (prevp = &parent->children ; *prevp && *prevp != child; prevp = &(*prevp)->next)
        ;
    detachp(prevp);
}

/*
 * Create a new node in a search expression tree, with the given
 * operation.  If 'parent' is not NULL, the new node is attached as the
 * last child of 'parent'.  If 'nnodes' is not NULL then it is incremented by one.
 * Returns a new node, never returns NULL.
 */
static search_expr_t *search_expr_new_nnodes(search_expr_t *parent, enum search_op op, unsigned *nnodes)
{
    search_expr_t *e = xzmalloc(sizeof(search_expr_t));
    e->op = op;
    if (parent) append(parent, e);
    if (nnodes && *nnodes < UINT_MAX) *nnodes += 1;
    return e;
}

/*
 * Detach the node '*prevp' from the tree, and reparent its children to
 * '*prevp' parent, preserving '*prevp's location and its children's
 * order.
 *
 * Apparently this operation is called "splat" but I think that's
 * a damn silly name.
 */
static search_expr_t *elide(search_expr_t **prevp)
{
    search_expr_t *e = *prevp;
    search_expr_t *child;

    *prevp = e->children;

    for (child = e->children ; child ; child = child->next) {
        child->parent = e->parent;
        prevp = &child->next;
    }
    *prevp = e->next;

    e->next = NULL;
    e->children = NULL;
    e->parent = NULL;

    return e;
}

static search_expr_t *interpolate(search_expr_t **prevp, enum search_op op, unsigned *nnodes)
{
    search_expr_t *e = search_expr_new_nnodes(NULL, op, nnodes);

    e->parent = (*prevp)->parent;
    e->children = (*prevp);
    e->next = (*prevp)->next;
    (*prevp)->next = NULL;
    (*prevp)->parent = e;
    *prevp = e;

    return e;
}

/*
 * Create a new node in a search expression tree, with the given
 * operation.  If 'parent' is not NULL, the new node is attached as the
 * last child of 'parent'.  Returns a new node, never returns NULL.
 */
EXPORTED search_expr_t *search_expr_new(search_expr_t *parent, enum search_op op)
{
    return search_expr_new_nnodes(parent, op, NULL);
}

static int complexity_check(int r, unsigned *nnodes)
{
    unsigned max = (unsigned)config_getint(IMAPOPT_SEARCH_NORMALISATION_MAX);
    if (max && nnodes && *nnodes >= max) {
        xsyslog(LOG_WARNING, "nnodes exceeds normalisation_max",
                "nnodes=%d normalisation_max=%d", *nnodes, max);
        return -1;
    }
    return r;
}

/*
 * Append the given search expression tree 'e' to the end of the
 * node 'parent'.  'e' must not already have a parent.
 */
EXPORTED void search_expr_append(search_expr_t *parent, search_expr_t *e)
{
    assert(e->parent == NULL);
    append(parent, e);
}

/*
 * Recursively free a search expression tree including the given node
 * and all descendent nodes.
 */
EXPORTED void search_expr_free(search_expr_t *e)
{
    if (!e) return;
    while (e->children) {
        search_expr_t *child = e->children;
        search_expr_detach(e, child);
        search_expr_free(child);
    }
    if (e->attr) {
        if (e->attr->internalise) e->attr->internalise(NULL, NULL, &e->internalised);
        if (e->attr->free) e->attr->free(&e->value);
    }
    free(e);
}

/*
 * Create and return a new search expression tree which is an
 * exact duplicate of the given tree.
 */
static search_expr_t *search_expr_duplicate_nnodes(const search_expr_t *e, unsigned *nnodes)
{
    search_expr_t *newe;
    search_expr_t *child;

    newe = search_expr_new_nnodes(NULL, e->op, nnodes);
    newe->attr = e->attr;
    if (newe->attr && newe->attr->duplicate)
        newe->attr->duplicate(&newe->value, &e->value);
    else
        newe->value = e->value;

    for (child = e->children ; child ; child = child->next)
        append(newe, search_expr_duplicate_nnodes(child, nnodes));

    return newe;
}

/*
 * Create and return a new search expression tree which is an
 * exact duplicate of the given tree.
 */
EXPORTED search_expr_t *search_expr_duplicate(const search_expr_t *e)
{
    return search_expr_duplicate_nnodes(e, NULL);
}

/*
 * Apply the given callback to every node in the search expression tree,
 * in pre-order (i.e. parent before children), as long as the callback
 * returns zero.  Returns the first non-zero return from the callback
 * (which is typically an error code).
 */
EXPORTED int search_expr_apply(search_expr_t *e,
                               int (*cb)(search_expr_t *, void *),
                               void *rock)
{
    search_expr_t *child;
    int r;

    r = cb(e, rock);
    if (r) return r;

    for (child = e->children ; child ; child = child->next) {
        r = search_expr_apply(child, cb, rock);
        if (r) break;
    }

    return r;
}

/*-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-*/

static const char *op_strings[] = {
    "unknown", "true", "false",
    "lt", "le", "gt", "ge", "match",
    "fuzzymatch", "and", "or", "not"
};

static const char *op_as_string(unsigned int op)
{
    return (op < VECTOR_SIZE(op_strings) ? op_strings[op] : "WTF?");
}

static void serialise(const search_expr_t *e, struct buf *buf)
{
    const search_expr_t *child;

#if DEBUG
    if (e == the_focus) buf_putc(buf, '<');
#endif
    buf_putc(buf, '(');
    buf_appendcstr(buf, op_as_string(e->op));
    if (e->attr) {
        buf_putc(buf, ' ');
        buf_appendcstr(buf, e->attr->name);
        buf_putc(buf, ' ');
        if (e->attr->serialise) e->attr->serialise(buf, &e->value);
    }
    for (child = e->children ; child ; child = child->next) {
        buf_putc(buf, ' ');
        serialise(child, buf);
    }
    buf_putc(buf, ')');
#if DEBUG
    if (e == the_focus) buf_putc(buf, '>');
#endif
}

/*
 * Given an expression tree, return a string which uniquely describes
 * the tree.  The string is designed to be used as a cache key and for
 * unit tests, not for human readability.
 *
 * Returns a new string which must be free()d by the caller.
 */
EXPORTED char *search_expr_serialise(const search_expr_t *e)
{
    struct buf buf = BUF_INITIALIZER;
    serialise(e, &buf);
    return buf_release(&buf);
}

/*-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-*/

static int getseword(struct protstream *prot, char *buf, int maxlen)
{
    int c = EOF;
    int quoted = 0;

    c = prot_getc(prot);
    if (c == '"')
        quoted = 1;
    else
        prot_ungetc(c, prot);

    while (maxlen > 1 &&
           (c = prot_getc(prot)) != EOF &&
           (quoted ?
               (c != '"') :
               (c != ' ' && c != ')'))) {
        *buf++ = c;
        maxlen--;
    }
    *buf = '\0';
    if (quoted && c != EOF)
        c = prot_getc(prot);
    return c;
}

static search_expr_t *unserialise(search_expr_t *parent,
                                  struct protstream *prot)
{
    int c;
    search_expr_t *e = NULL;
    unsigned int op;
    char tmp[128];

    c = prot_getc(prot);
    if (c != '(')
        goto bad;

    c = getseword(prot, tmp, sizeof(tmp));
    if (c != ' ' && c != ')')
        goto bad;

    for (op = 0 ; op < VECTOR_SIZE(op_strings) ; op++) {
        if (!strcmp(tmp, op_strings[op]))
            break;
    }
    if (op == VECTOR_SIZE(op_strings))
        goto bad;

    e = search_expr_new(parent, op);
    if (c == ')')
        return e;    /* SEOP_TRUE, SEOP_FALSE */

    switch (op) {
    case SEOP_AND:
    case SEOP_OR:
    case SEOP_NOT:
        /* parse children */
        for (;;) {
            if (unserialise(e, prot) == NULL)
                goto bad;
            c = prot_getc(prot);
            if (c == ')')
                break;
            if (c != ' ')
                goto bad;
        }
        break;
    case SEOP_LT:
    case SEOP_LE:
    case SEOP_GT:
    case SEOP_GE:
    case SEOP_MATCH:
    case SEOP_FUZZYMATCH:
        /* parse attribute */
        c = getseword(prot, tmp, sizeof(tmp));
        if (c != ' ')
            goto bad;
        e->attr = search_attr_find(tmp);
        if (e->attr == NULL)
            goto bad;
        /* parse value */
        if (e->attr->unserialise)
            c = e->attr->unserialise(prot, &e->value);
        if (c != ')')
            goto bad;
        break;
    default:
        c = prot_getc(prot);
        if (c != ')')
            goto bad;
        break;
    }

    return e;

bad:
    if (e) {
        e->op = SEOP_UNKNOWN;
        if (parent == NULL)
            search_expr_free(e);
    }
    return NULL;
}

/*
 * Given a string generated by search_expr_serialise(),
 * parse it and return a new expression tree, or NULL if
 * there were any errors.  Used mainly for unit tests.
 */
EXPORTED search_expr_t *search_expr_unserialise(const char *s)
{
    struct protstream *prot;
    search_expr_t *root = NULL;

    if (!s || !*s) return NULL;
    prot = prot_readmap(s, strlen(s));
    root = unserialise(NULL, prot);

#if DEBUG
    if (!root) {
#define MAX_CONTEXT 48
        int off = ((const char *)prot->ptr - s);
        int len = strlen(s);
        int context_begin = off - MIN(off, MAX_CONTEXT);
        int context_end = off + MIN((len-off), MAX_CONTEXT);
        int i;
        fputc('\n', stderr);
        fprintf(stderr, "ERROR: failed to unserialise string at or near:\n");
        if (context_begin) fputs("...", stderr);
        fwrite(s+context_begin, 1, context_end-context_begin, stderr);
        fputc('\n', stderr);
        if (context_begin) fputs("---", stderr);
        for (i = off - context_begin - 1 ; i > 0 ; i--)
            fputc('-', stderr);
        fputc('^', stderr);
        fputc('\n', stderr);
    }
#endif

    prot_free(prot);
    return root;
}

/*-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-*/

enum {
    DNF_OR, DNF_AND, DNF_NOT, DNF_CMP
};

/* expected depth, in a full tree.  0 is rootmost, 3 is leafmost */
static int dnf_depth(const search_expr_t *e)
{
    switch (e->op) {
    case SEOP_TRUE:
    case SEOP_FALSE:
    case SEOP_LT:
    case SEOP_LE:
    case SEOP_GT:
    case SEOP_GE:
    case SEOP_MATCH:
    case SEOP_FUZZYMATCH:
        return DNF_CMP;
    case SEOP_AND:
        return DNF_AND;
    case SEOP_OR:
        return DNF_OR;
    case SEOP_NOT:
        return DNF_NOT;
    default: assert(0); return -1;
    }
    return -1;
}

static int has_enough_children(const search_expr_t *e)
{
    const search_expr_t *child;
    int min;
    int n = 0;

    switch (e->op) {
    case SEOP_OR:
    case SEOP_AND:
        min = 2;
        break;
    case SEOP_NOT:
        min = 1;
        break;
    default:
        return 1;
    }

    for (child = e->children ; child ; child = child->next)
        if (++n >= min) return 1;
    return 0;
}

static int apply_demorgan(search_expr_t **ep, search_expr_t **prevp, unsigned *nnodes)
{
    search_expr_t *child = *prevp;
    search_expr_t **grandp;

    /* NOT nodes have exactly one child */
    assert(*prevp != NULL);
    assert((*prevp)->next == NULL);

    child->op = (child->op == SEOP_AND ? SEOP_OR : SEOP_AND);
    for (grandp = &child->children ; *grandp ; grandp = &(*grandp)->next)
        interpolate(grandp, SEOP_NOT, nnodes);
    search_expr_free(elide(ep));

    return complexity_check(1, nnodes);
}

static int apply_distribution(search_expr_t **ep, search_expr_t **prevp, unsigned *nnodes)
{
    search_expr_t *newor;
    search_expr_t *or;
    search_expr_t *and;
    search_expr_t *orchild;
    search_expr_t *newand;
    int r = 1;

    newor = interpolate(ep, SEOP_OR, nnodes);
    and = detachp(&newor->children);
    or = detachp(prevp);

    while (complexity_check(r, nnodes) >= 0) {
        orchild = detachp(&or->children);
        if (orchild == NULL) break;
        newand = search_expr_duplicate_nnodes(and, nnodes);
        append(newand, orchild);
        append(newor, newand);
    }

    search_expr_free(and);
    search_expr_free(or);

    return complexity_check(r, nnodes);
}

static int invert(search_expr_t **ep, search_expr_t **prevp, unsigned *nnodes)
{
    if ((*ep)->op == SEOP_NOT)
        return apply_demorgan(ep, prevp, nnodes);
    else
        return apply_distribution(ep, prevp, nnodes);
}

/* combine compatible boolean parent and child nodes */
static void combine(search_expr_t **ep, search_expr_t **prevp)
{
    switch ((*ep)->op) {
    case SEOP_NOT:
        search_expr_free(elide(prevp));
        search_expr_free(elide(ep));
        break;
    case SEOP_AND:
    case SEOP_OR:
        search_expr_free(elide(prevp));
        break;
    default:
        break;
    }
}

/*
 * Top-level normalisation step.  Returns 1 if it changed the subtree, 0
 * if it didn't, and -1 on error (such as exceeding a complexity limit).
 */
static int normalise(search_expr_t **ep, unsigned *nnodes)
{
    search_expr_t **prevp;
    int depth;
    int changed = -1;
    int r;

restart:
    changed++;

#if DEBUG
    the_focus = *ep;
    {
        char *s = search_expr_serialise(*the_rootp);
        fprintf(stderr, "normalise: tree=%s\n", s);
        free(s);
    }
#endif

    if (!has_enough_children(*ep)) {
        /* eliminate trivial nodes: AND and ORs with
         * a single child, NOTs with none */
        search_expr_free(elide(ep));
        goto restart;
    }

    depth = dnf_depth(*ep);
    for (prevp = &(*ep)->children ; *prevp ; prevp = &(*prevp)->next)
    {
        int child_depth = dnf_depth(*prevp);
        if (child_depth == depth) {
            combine(ep, prevp);
            goto restart;
        }
        if (child_depth < depth) {
            r = invert(ep, prevp, nnodes);
            if (r < 0) return -1;
            goto restart;
        }
        r = normalise(prevp, nnodes);
        if (r < 0) return -1;
        if (r > 0) goto restart;
    }

    return complexity_check(changed, nnodes);
}

static void *getnext(void *p)
{
    return ((search_expr_t *)p)->next;
}

static void setnext(void *p, void *next)
{
    ((search_expr_t *)p)->next = next;
}

static int maxcost(const search_expr_t *e, hashu64_table *costcache)
{
    if (!e) return 0;

    if (costcache) {
        intptr_t cost = (intptr_t) hashu64_lookup((uint64_t) e, costcache);
        assert(cost > INT_MIN && cost < INT_MAX);
        if (cost) return cost > 0 ? cost : 0;
    }

    int cost = e->attr ? e->attr->cost : 0;
    search_expr_t *child;
    for (child = e->children ; child ; child = child->next) {
        int childcost = maxcost(child, costcache);
        if (childcost > cost) cost = childcost;
    }

    if (costcache) {
        hashu64_insert((uint64_t) e, (void*)((intptr_t)(cost ? cost : -1)), costcache);
    }
    return cost;
}

static int compare(void *p1, void *p2, void *calldata)
{
    const search_expr_t *e1 = p1;
    const search_expr_t *e2 = p2;
    int r = 0;

    if (!r)
        r = maxcost(e1, calldata) - maxcost(e2, calldata);

    if (!r)
        r = dnf_depth(e2) - dnf_depth(e1);

    if (!r)
        r = strcasecmp(e1->attr ? e1->attr->name : "zzz",
                       e2->attr ? e2->attr->name : "zzz");

    if (!r)
        r = (int)e1->op - (int)e2->op;

    if (!r) {
        struct buf b1 = BUF_INITIALIZER;
        struct buf b2 = BUF_INITIALIZER;
        if (e1->attr && e1->attr->serialise)
            e1->attr->serialise(&b1, &e1->value);
        if (e2->attr && e2->attr->serialise)
            e2->attr->serialise(&b2, &e2->value);
        r = strcmp(buf_cstring(&b1), buf_cstring(&b2));
        buf_free(&b1);
        buf_free(&b2);
    }

    if (!r) {
        if (e1->children || e2->children)
            r = compare((void *)(e1->children ? e1->children : e1),
                        (void *)(e2->children ? e2->children : e2),
                        calldata);
    }

    return r;
}

static void sort_children_internal(search_expr_t *e, hashu64_table *costcache)
{
    search_expr_t *child;

    for (child = e->children ; child ; child = child->next)
        sort_children_internal(child, costcache);

    e->children = lsort(e->children, getnext, setnext, compare, costcache);
}

static void sort_children(search_expr_t *e)
{
    search_expr_t *child;
    hashu64_table maxcostcache = HASHU64_TABLE_INITIALIZER;
    construct_hashu64_table(&maxcostcache, 512, 0);
    hashu64_table *costcache = &maxcostcache;

    if (sizeof(uint64_t) < sizeof(search_expr_t*)) {
        costcache = NULL; // woot?
    }

    for (child = e->children ; child ; child = child->next)
        sort_children_internal(child, costcache);

    e->children = lsort(e->children, getnext, setnext, compare, costcache);

    free_hashu64_table(&maxcostcache, NULL);
}

/*
 * Reorganise a search expression tree into Disjunctive Normal Form.
 * This form is useful for picking out cacheable and runnable sub-queries.
 *
 * An expression in DNF has a number of constraints:
 *
 * - it contains at most one OR node
 * - if present the OR node is the root
 * - NOT nodes if present have only comparisons as children
 * - it contains at most 4 levels of nodes
 * - nodes have a strict order of types, down from the root
 *   they are: OR, AND, NOT, comparisons.
 *
 * DNF is useful for running queries.  Each of the children of the
 * root OR node can be run as a separate sub-query, and cached
 * independently because their results are just accumulated together
 * without any further processing.  Each of those children is a single
 * conjuctive clause which can implemented using an index lookup (or a
 * scan of all messages) followed by a filtering step.  Finally, each of
 * those conjunctive clauses can be analysed to discover which folders
 * will need to be opened: no folders, a single specific folder,
 * all folders, or all folders except some specific folders.
 *
 * We also enforce a fixed order on child nodes of any node, so
 * that all logically equivalent trees are the same shape.  This
 * helps when constructing a cache key from a tree.  The sorting
 * criteria are:
 *
 * - NOT nodes after un-negated comparison nodes, then
 * - comparison nodes sorted lexically on attribute, then
 * - comparison nodes sorted lexically on stringified value
 *
 * Note that IMAP search syntax, when translated most directly into an
 * expression tree, defines trees whose outermost node is always an AND.
 * Those trees are not in any kind of normal form but more closely
 * resemble Conjunctive Normal Form than DNF.  Any IMAP search program
 * containing an OR criterion will require significant juggling to
 * achieve DNF.
 *
 * Takes the root of the tree in *'ep' and returns a possibly reshaped
 * tree whose root is stored in *'ep'.
 *
 * Returns 1 if the subtree was changed, 0 if it wasn't, and -1 on error
 * (such as exceeding a complexity limit).
 */
static int search_expr_normalise_nnodes(search_expr_t **ep, unsigned *nnodes)
{
    int r;

#if DEBUG
    the_rootp = ep;
#endif
    r = normalise(ep, nnodes);
    sort_children(*ep);
#if DEBUG
    the_rootp = NULL;
    the_focus = NULL;
#endif
    return r;
}

EXPORTED int search_expr_normalise(search_expr_t **ep)
{
    unsigned nnodes = 0;
    return search_expr_normalise_nnodes(ep, &nnodes);
}

/*-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-*/

static int internalise(search_expr_t *e, void *rock)
{
    struct index_state *state = rock;
    if (e->attr && e->attr->internalise)
        e->attr->internalise(state, &e->value, &e->internalised);
    return 0;
}

/*
 * Prepare the given expression for use with the given mailbox.
 */
EXPORTED void search_expr_internalise(struct index_state *state, search_expr_t *e)
{
    search_expr_apply(e, internalise, state);
}

/* result:
 * -1 definitely false (regardless of message)
 *  0 depends on message
 * +1 definitely true (regardless of message)
 */
EXPORTED int search_expr_always_same(const search_expr_t *e)
{
    search_expr_t *child;

    switch (e->op) {
    case SEOP_UNKNOWN:
         assert(0); // fatally bad
         return 0;
    case SEOP_TRUE:
         return 1;
    case SEOP_FALSE:
         return -1;
    case SEOP_LT:
    case SEOP_LE:
    case SEOP_GT:
    case SEOP_GE:
    case SEOP_FUZZYMATCH:
    case SEOP_MATCH:
        return 0;
    case SEOP_AND:
        {
            int res = 1;
            for (child = e->children ; child ; child = child->next) {
                int cres = search_expr_always_same(child);
                if (cres == -1) return -1;
                if (cres == 0) res = 0; // could still be a definite no
            }
            return res;
        }
    case SEOP_OR:
        {
            int res = -1;
            for (child = e->children ; child ; child = child->next) {
                int cres = search_expr_always_same(child);
                if (cres == 1) return 1;
                if (cres == 0) res = 0; // could still be a definite yes
            }
            return res;
        }
    case SEOP_NOT:
        {
            assert(e->children);
            // reverse the result only
            return 0 - search_expr_always_same(e->children);
        }
    }
    return 0;
}

/*
 * Evaluate the given search expression for the given message,
 * Returns nonzero if the expression is true, 0 otherwise.
 */
EXPORTED int search_expr_evaluate(message_t *m, const search_expr_t *e)
{
    search_expr_t *child;

    switch (e->op) {
    case SEOP_UNKNOWN: assert(0); return 1;
    case SEOP_TRUE: return 1;
    case SEOP_FALSE: return 0;
    case SEOP_LT:
        assert(e->attr);
        assert(e->attr->cmp);
        return (e->attr->cmp(m, &e->value, e->internalised, e->attr->data1) < 0);
    case SEOP_LE:
        assert(e->attr);
        assert(e->attr->cmp);
        return (e->attr->cmp(m, &e->value, e->internalised, e->attr->data1) <= 0);
    case SEOP_GT:
        assert(e->attr);
        assert(e->attr->cmp);
        return (e->attr->cmp(m, &e->value, e->internalised, e->attr->data1) > 0);
    case SEOP_GE:
        assert(e->attr);
        assert(e->attr->cmp);
        return (e->attr->cmp(m, &e->value, e->internalised, e->attr->data1) >= 0);
    case SEOP_FUZZYMATCH:
        /* FUZZYMATCH should never be evaluated, as such nodes are
         * picked out of the expression during query optimisation and
         * used to drive search engine lookups.  But the nearest
         * approximation would be MATCH. */
    case SEOP_MATCH:
        assert(e->attr);
        assert(e->attr->match);
        return e->attr->match(m, &e->value, e->internalised, e->attr->data1);
    case SEOP_AND:
        for (child = e->children ; child ; child = child->next)
            if (!search_expr_evaluate(m, child))
                return 0;
        return 1;
    case SEOP_OR:
        for (child = e->children ; child ; child = child->next)
            if (search_expr_evaluate(m, child))
                return 1;
        return 0;
    case SEOP_NOT:
        assert(e->children);
        return !search_expr_evaluate(m, e->children);
    }
    return 0;
}

/* ====================================================================== */

static int uses_attr(search_expr_t *e, void *rock)
{
    const search_attr_t *attr = rock;
    return (e->attr == attr);
}

/*
 * Returns non-zero if any comparison node in the given search
 * expression tree uses the attribute with the given name.
 */
EXPORTED int search_expr_uses_attr(const search_expr_t *e, const char *name)
{
    const search_attr_t *attr = search_attr_find(name);

    if (!attr) return 0;
    return search_expr_apply((search_expr_t *)e, uses_attr, (void *)attr);
}

/* ====================================================================== */

    /* NOTE: older than 'N' days will be a mutable search of course,
     * but that fact isn't available down here - we only know the
     * date range itself, and that isn't mutable.  So if you need
     * immutable results, you'll need to maintain a fixed date range
     * up in the higher level */

static int is_mutable(search_expr_t *e, void *rock __attribute__((unused)))
{
    return (e->attr && (e->attr->flags & SEA_MUTABLE));
}

/*
 * Return non-zero if the search expression is mutable, i.e. it might
 * return a different set of messages if run again, assuming that
 *
 * a) no folders covered by the search have received new messages, and
 * b) uidvalidities of folders covered by the search have not changed.
 *
 * Basically, mutable searches are on attributes of a message which are
 * not derived solely from the message text itself and can be changed after
 * the message is inserted.  For example: system flags are mutable, the
 * From: header field is not.
 */
EXPORTED int search_expr_is_mutable(const search_expr_t *e)
{
    return search_expr_apply((search_expr_t *)e, is_mutable, NULL);
}

/* ====================================================================== */

static int get_countability(search_expr_t *e, void *rock)
{
    unsigned int *maskp = rock;

    if (e->op == SEOP_TRUE)
        *maskp |= SEC_EXISTS;
    else if (e->op == SEOP_FALSE)
        *maskp |= SEC_EXISTS|SEC_NOT;
    else if (e->op == SEOP_NOT)
        *maskp |= SEC_NOT;
    else if (e->attr) {
        if (e->attr->get_countability)
            *maskp |= e->attr->get_countability(&e->value);
        else
            *maskp |= SEC_UNCOUNTED;
    }

    return 0;
}

/*
 * Analyse the search expression to discover how countable the results are
 * going to be.  By "countable" we mean "predictable from stored state,
 * without searching every message".  Currently that means
 *
 * in message mode:
 *    - total number of messages
 *    - number unseen messages
 *    - number seen messages (by inference)
 *    - number recent messages
 *    - number unrecent messages (by inference)
 * in conversation mode:
 *    - total number of conversations
 *    - number of conversations with unseen messages
 *    - number of conversations with no unseen messages (by inference)
 *
 * Returns a mask of SEC_* constants (e.g. SEC_SEEN) describing which
 * countable attributes are specified by the expression. The special value
 * SEC_UNCOUNTED means that at least one uncounted attribute was found.
 * Mask values with more than one bit set are effectively uncountable.
 *
 * Note: the heuristics used here are intended for normalised search
 * expressions, and may not work correctly otherwise.  In particular,
 * SEC_NOT doesn't do quite what you expect.
 */

EXPORTED unsigned int search_expr_get_countability(const search_expr_t *e)
{
    unsigned int mask = 0;

    if (!e)
        return 0;

    search_expr_apply((search_expr_t *)e, get_countability, &mask);
    return mask;
}

/* ====================================================================== */

/*
 * Neutralise a node: make it always return success.  Useful for
 * changing the logic of an expression without reshaping it.
 */
EXPORTED void search_expr_neutralise(search_expr_t *e)
{
    /* Leave the children and attribute in place.  This might be
     * wrong, but we are only called for MATCH nodes at the moment
     * and they seem to be able to tolerate such weirdness. */
    e->op = SEOP_TRUE;
}

/* ====================================================================== */

static int is_folder_node(const search_expr_t *e)
{
    return (e->op == SEOP_MATCH &&
            e->attr &&
            !strcasecmp(e->attr->name, "folder"));
}

static int is_indexed_node(const search_expr_t *e)
{
    if (e->op == SEOP_NOT)
        return is_indexed_node(e->children);

    return e->attr &&
        ((e->op == SEOP_FUZZYMATCH && e->attr->part != SEARCH_PART_NONE) ||
         (e->op == SEOP_MATCH && search_can_match(e->op, e->attr->part)));
}

static int is_folder_or_indexed(search_expr_t *e, void *rock __attribute__((unused)))
{
    return (is_folder_node(e) || is_indexed_node(e));
}

/* given an expression tree, return the name of the first mailbox that
 * is mentioned in it (if any).  This is depth-first, but normally that
 * won't matter.  It does explicitly skip "not in this mailbox" type
 * queries because we won't want to open those mailboxes! */
EXPORTED char *search_expr_firstmailbox(const search_expr_t *e)
{
    // don't descend into "NOT" because we won't want to open those mailboxes
    if (e->op == SEOP_NOT) return NULL;

    if (is_folder_node(e)) {
        char *res = xstrdupnull(e->value.s);
        if (res) return res;
    }

    const search_expr_t *child;
    for (child = e->children; child; child = child->next) {
        char *res = search_expr_firstmailbox(child);
        if (res) return res;
    }

    return NULL;
}

/*
 * Split a search expression into one or more parts, each of which
 * satisfies the earliest of these conditions:
 *
 *  - contains at least one indexed match node
 *      (the callback's 'indexed' is non-NULL), or
 *
 *  - is limited to exactly one folder by a positive folder match node
 *      (the callback's 'mboxname' is non-NULL), or
 *
 *  - applies to all folders and is not indexed
 *      (both the callback's 'mboxname' and 'indexed' are NULL)
 *
 * Destroys the original expression as a side effect.
 *
 * The callback function 'cb' is called one or more times with up to two
 * expression trees which have just been detached from the original expression
 * tree.  Both of these trees will be in DNF and will be at most a
 * conjuctive node, i.e. no disjunctions.
 *
 * The 'indexed' tree, if not NULL, contains all the indexed search terms.
 * The 'scan' tree will never be NULL, although it may be a trivial tree
 * comprising a single (true) node.  It contains an expression that must be
 * matched by every message reported by the index or the folder scan.
 *
 * The callback is responsible for freeing the expression using
 * search_expr_free().  The callback may be called multiple times with
 * the same folder/index combination, in which case the expressions should
 * be considered logically ORed together.
 *
 * Does not require the input expression to be normalised, and may
 * normalise it during processing.  Expressions passed to the callback
 * are always normalised.
 */
EXPORTED void search_expr_split_by_folder_and_index(search_expr_t *e,
                  void (*cb)(const char *, search_expr_t *, search_expr_t *, void *),
                  void *rock)
{
    search_expr_t *copy = NULL;

    if (!search_expr_apply(e, is_folder_or_indexed, NULL)) {
        /* The expression contains neither a folder match node nor an
         * indexable node, which means we can short circuit the whole
         * normalisation and splitting process.  This optimisation helps
         * us cope with the FM web frontends generating queries with
         *
         * or or or or to "word" cc "word" bcc "word" from "word" subject "word"
         *
         * for every "word" the user types into the Search box, by
         * avoiding the complexity explosion due to normalising all
         * those OR nodes.
         *
         * But - we still sort it.  */
        sort_children(e);
        cb(NULL, NULL, e, rock);
        return;
    }

    copy = search_expr_duplicate(e);
    if (search_expr_normalise(&copy) < 0)
    {
        /* We blew the complexity limit because the expression has too
         * many ORs.  Rats.  Give up and scan folders with the original
         * expression */
        search_expr_free(copy);
        cb(NULL, NULL, e, rock);
        return;
    }

    search_expr_free(e);
    split(copy, cb, rock);
}

static void split(search_expr_t *e,
                  void (*cb)(const char *, search_expr_t *, search_expr_t *, void *),
                  void *rock)
{
    search_expr_t *child;

    if (e->op == SEOP_OR) {
        /* top level node */
        while ((child = detachp(&e->children)) != NULL)
            split(child, cb, rock);
        search_expr_free(e);
    }
    else if (e->op == SEOP_AND) {
        search_expr_t **prevp;
        search_expr_t **folder_prevp = NULL;
        int nfolders = 0;
        int nindexes = 0;

        for (prevp = &e->children ; *prevp ; prevp = &(*prevp)->next) {
            if (is_indexed_node(*prevp)) {
                nindexes++;
            }
            if (is_folder_node(*prevp)) {
                nfolders++;
                folder_prevp = prevp;
            }
        }
        if (nindexes) {
            /*
             * The presence of indexable fields overrides all other
             * considerations; we assume it's easier to consult the
             * index and then filter out folders later.  Note that this
             * assumption is broken for SQUAT which is per-folder.
             *
             * We remove the indexed matches from the conjunction and
             * build a new conjunction containing only those matches.
             * Note that this assumes the search engine does not give
             * false positives, which is also broken for SQUAT.
             */
            search_expr_t *indexed = search_expr_new(NULL, SEOP_AND);

            for (prevp = &e->children ; *prevp ; ) {
                if (is_indexed_node(*prevp))
                    append(indexed, detachp(prevp));
                else
                    prevp = &(*prevp)->next;
            }
            search_expr_normalise(&indexed);    /* in case of a trivial AND */
            if (!e->children) {
                search_expr_free(e);
                e = search_expr_new(NULL, SEOP_TRUE);
            }
            else
                search_expr_normalise(&e);
            cb(NULL, indexed, e, rock);
        }
        else if (!nfolders) {
            /* No positive folder match: whole expression applies
             * to all folders */
            cb(NULL, NULL, e, rock);
        }
        else {
            /* One or more folder matches; Extract the first folder
             * to split the expression. Any remaining folder matches
             * will be evaluated in the subtree. */
            child = detachp(folder_prevp);
            /* normalise the remaining subtree */
            search_expr_normalise(&e);
            cb(child->value.s, NULL, e, rock);
            search_expr_free(child);
        }
    }
    else if (is_folder_node(e)) {
        cb(e->value.s, NULL, search_expr_new(NULL, SEOP_TRUE), rock);
        search_expr_free(e);
    }
    else if (is_indexed_node(e)) {
        cb(NULL, e, search_expr_new(NULL, SEOP_TRUE), rock);
    }
    else {
        cb(NULL, NULL, e, rock);
    }
}

/* ====================================================================== */

static int search_list_match(message_t *m,
                             const union search_value *v __attribute__((unused)),
                             void *internalised,
                             void *data1)
{
    int r;
    struct buf buf = BUF_INITIALIZER;
    int (*getter)(message_t *, struct buf *) = (int(*)(message_t *, struct buf *))data1;
    strarray_t *internal = internalised;

    // XXX - this should never happen

    r = getter(m, &buf);
    if (!r && buf.len) {
        const char *val = buf_cstring(&buf);
        r = (strarray_find(internal, val, 0) >= 0) ? 1 : 0;
    }
    else
        r = 0;
    buf_free(&buf);

    return r;
}

static void search_list_serialise(struct buf *b, const union search_value *v)
{
    buf_putc(b, '(');
    int i;
    for (i = 0; i < strarray_size(v->list); i++) {
        if (i) buf_putc(b, ' ');
        buf_putc(b, '"');
        buf_appendcstr(b, strarray_nth(v->list, i));
        buf_putc(b, '"');
    }
    buf_putc(b, ')');
}

static int search_list_unserialise(struct protstream *prot, union search_value *v)
{
    int c;
    char tmp[1024];

    c = prot_getc(prot);
    if (c != '(') return EOF;

    v->list = strarray_new();
    do {
        c = getseword(prot, tmp, sizeof(tmp));
        strarray_append(v->list, tmp);
    } while (c == ' ');

    if (c != ')') return EOF;

    return prot_getc(prot);
}

static void search_list_internalise(struct index_state *state __attribute__((unused)),
                                      const union search_value *v, void **internalisedp)
{
    if (*internalisedp) *internalisedp = NULL;
    if (v) *internalisedp = v->list;
}

static void search_list_duplicate(union search_value *new,
                                  const union search_value *old)
{
    new->list = strarray_dup(old->list);
}

static void search_list_free(union search_value *v)
{
    strarray_free(v->list);
    v->list = NULL;
}

/* ====================================================================== */

struct search_string_internal {
    comp_pat *pat;
    char *s;
};

static int search_string_match(message_t *m,
                                const union search_value *v __attribute__((unused)),
                                void *internalised,
                                void *data1)
{
    int r;
    struct buf buf = BUF_INITIALIZER;
    int (*getter)(message_t *, struct buf *) = (int(*)(message_t *, struct buf *))data1;
    struct search_string_internal *internal = internalised;

    r = getter(m, &buf);
    if (!r && buf.len)
        r = charset_searchstring(internal->s, internal->pat, buf.s, buf.len, charset_flags);
    else
        r = 0;
    buf_free(&buf);

    return r;
}

static void search_string_serialise(struct buf *b, const union search_value *v)
{
    buf_printf(b, "\"%s\"", v->s);
}

static int search_string_unserialise(struct protstream *prot, union search_value *v)
{
    int c;
    char tmp[1024];

    c = getseword(prot, tmp, sizeof(tmp));
    v->s = xstrdup(tmp);
    return c;
}

static void search_string_internalise(struct index_state *state __attribute__((unused)),
                                      const union search_value *v, void **internalisedp)
{
    if (*internalisedp) {
        struct search_string_internal *internal = *internalisedp;
        charset_freepat(internal->pat);
        free(internal->s);
        free(internal);
        *internalisedp = NULL;
    }
    if (v) {
        struct search_string_internal *internal = xzmalloc(sizeof(struct search_string_internal));
        charset_t utf8 = charset_lookupname("utf8");
        internal->s = charset_convert(v->s, utf8, charset_flags);
        internal->pat = charset_compilepat(internal->s);
        charset_free(&utf8);
        *internalisedp = internal;
    }
}

static void search_string_duplicate(union search_value *new,
                                    const union search_value *old)
{
    new->s = xstrdup(old->s);
}

static void search_string_free(union search_value *v)
{
    free(v->s);
    v->s = NULL;
}

/* ====================================================================== */

static int search_listid_match(message_t *m, const union search_value *v,
                               void *internalised,
                               void *data1 __attribute__((unused)))
{
    int r;
    struct buf buf = BUF_INITIALIZER;
    comp_pat *pat = (comp_pat *)internalised;

    r = message_get_listid(m, &buf);
    if (!r) {
        r = charset_searchstring(v->s, pat, buf.s, buf.len, charset_flags);
        if (r) goto out;    // success
    }

    r = message_get_mailinglist(m, &buf);
    if (!r) {
        r = charset_searchstring(v->s, pat, buf.s, buf.len, charset_flags);
        if (r) goto out;    // success
    }

    r = 0;  // failure

out:
    buf_free(&buf);
    return r;
}

/* ====================================================================== */

static int search_contenttype_match(message_t *m,
                                    const union search_value *v __attribute__((unused)),
                                    void *internalised,
                                    void *data1 __attribute__((unused)))
{
    int r;
    struct search_string_internal *internal = internalised;
    comp_pat *pat = internal->pat;
    const char *s = internal->s;
    strarray_t types = STRARRAY_INITIALIZER;
    int i;
    char combined[128];

    if (!message_get_types(m, &types)) {
        for (i = 0 ; i < types.count ; i+= 2) {
            const char *type = types.data[i];
            const char *subtype = types.data[i+1];

            /* match against type */
            r = charset_searchstring(s, pat, type, strlen(type), charset_flags);
            if (r) goto out;    // success

            /* match against subtype */
            r = charset_searchstring(s, pat, subtype, strlen(subtype), charset_flags);
            if (r) goto out;    // success

            /* match against combined type_subtype */
            snprintf(combined, sizeof(combined), "%s/%s", type, subtype);
            r = charset_searchstring(s, pat, combined, strlen(combined), charset_flags);
            if (r) goto out;    // success
        }
    }

    r = 0;  // failure

out:
    strarray_fini(&types);
    return r;
}

/* ====================================================================== */

static int search_header_match(message_t *m, const union search_value *v,
                               void *internalised,
                               void *data1)
{
    int r;
    struct buf buf = BUF_INITIALIZER;
    const char *field = (const char *)data1;
    struct search_string_internal *internal = internalised;

    /* XXX MESSAGE_MULTIPLE is not actually implemented, but we still
     * XXX search all the values because it always returns all the values!
     */
    r = message_get_field(m, field,
                          MESSAGE_DECODED|MESSAGE_APPEND|MESSAGE_MULTIPLE,
                          &buf);
    if (!r) {
        if (*v->s) {
            r = charset_searchstring(internal->s, internal->pat, buf.s, buf.len, charset_flags);
        }
        else {
            /* RFC 3501: If the string to search is zero-length, this matches
             * all messages that have a header line with the specified
             * field-name regardless of the contents. */
            r = buf.len ? 1 : 0;
        }
    }
    else
        r = 0;
    buf_free(&buf);

    return r;
}

/* ====================================================================== */

static void internalise_sequence(const union search_value *v,
                                 void **internalisedp, unsigned maxval)
{
    seqset_free((seqset_t **)internalisedp);
    if (v) {
        *internalisedp = seqset_parse(v->s, NULL, maxval);
    }
}

static void search_msgno_internalise(struct index_state *state,
                                     const union search_value *v, void **internalisedp)
{
    internalise_sequence(v, internalisedp, (state ? state->exists : 0));
}

static void search_uid_internalise(struct index_state *state,
                                   const union search_value *v, void **internalisedp)
{
    internalise_sequence(v, internalisedp, (state ? state->last_uid : 0));
}

static int search_seq_match(message_t *m,
                            const union search_value *v __attribute__((unused)),
                            void *internalised,
                            void *data1)
{
    seqset_t *seq = internalised;
    int r;
    uint32_t u;
    int (*getter)(message_t *, uint32_t *) = (int(*)(message_t *, uint32_t *))data1;

    r = getter(m, &u);
    if (!r)
        r = seqset_ismember(seq, u);
    else
        r = 0;

    return r;
}

static void search_seq_serialise(struct buf *b, const union search_value *v)
{
    buf_appendcstr(b, v->s);
}

/* ====================================================================== */

static int search_flags_match(message_t *m, const union search_value *v,
                              void *internalised __attribute__((unused)),
                              void *data1)
{
    int r;
    uint32_t u;
    int (*getter)(message_t *, uint32_t *) = (int(*)(message_t *, uint32_t *))data1;

    r = getter(m, &u);
    if (!r)
        r = !!(v->u & u);
    else
        r = 0;

    return r;
}

static void search_systemflags_serialise(struct buf *b, const union search_value *v)
{
    if ((v->u & FLAG_ANSWERED))
        buf_appendcstr(b, "\\Answered");
    if ((v->u & FLAG_FLAGGED))
        buf_appendcstr(b, "\\Flagged");
    if ((v->u & FLAG_DELETED))
        buf_appendcstr(b, "\\Deleted");
    if ((v->u & FLAG_DRAFT))
        buf_appendcstr(b, "\\Draft");
    if ((v->u & FLAG_SEEN))
        buf_appendcstr(b, "\\Seen");
}

static int search_systemflags_unserialise(struct protstream *prot, union search_value *v)
{
    int c;
    char tmp[64];

    c = getseword(prot, tmp, sizeof(tmp));

    if (!strcasecmp(tmp, "\\Answered"))
        v->u = FLAG_ANSWERED;
    else if (!strcasecmp(tmp, "\\Flagged"))
        v->u = FLAG_FLAGGED;
    else if (!strcasecmp(tmp, "\\Deleted"))
        v->u = FLAG_DELETED;
    else if (!strcasecmp(tmp, "\\Draft"))
        v->u = FLAG_DRAFT;
    else if (!strcasecmp(tmp, "\\Seen"))
        v->u = FLAG_SEEN;
    else
        return EOF;
    return c;
}

static void search_indexflags_serialise(struct buf *b, const union search_value *v)
{
    if ((v->u & MESSAGE_SEEN))
        buf_appendcstr(b, "\\Seen");
    if ((v->u & MESSAGE_RECENT))
        buf_appendcstr(b, "\\Recent");
}

static int search_indexflags_unserialise(struct protstream *prot, union search_value *v)
{
    int c;
    char tmp[64];

    c = getseword(prot, tmp, sizeof(tmp));

    if (!strcasecmp(tmp, "\\Seen"))
        v->u = MESSAGE_SEEN;
    else if (!strcasecmp(tmp, "\\Recent"))
        v->u = MESSAGE_RECENT;
    else
        return EOF;
    return c;
}

unsigned int search_indexflags_get_countability(const union search_value *v)
{
    switch (v->u) {
    case MESSAGE_SEEN: return SEC_SEEN;
    case MESSAGE_RECENT: return SEC_RECENT;
    default: return SEC_UNCOUNTED;
    }
}

/* ====================================================================== */

static void search_keyword_internalise(struct index_state *state,
                                       const union search_value *v,
                                       void **internalisedp)
{
    int r;
    int num = 0;

    if (state) {
        r = mailbox_user_flag(state->mailbox, v->s, &num, /*create*/0);
        if (!r)
            num++;
        else
            num = 0;
    }
    *internalisedp = (void*)(unsigned long)num;
}

static int search_keyword_match(message_t *m,
                                const union search_value *v __attribute__((unused)),
                                void *internalised,
                                void *data1 __attribute__((unused)))
{
    int r;
    int num = (int)(unsigned long)internalised;
    uint32_t flags[MAX_USER_FLAGS/32];

    if (!num)
        return 0;   /* not a valid flag for this mailbox */
    num--;

    r = message_get_userflags(m, flags);
    if (!r)
        r = !!(flags[num/32] & (1<<(num % 32)));
    else
        r = 0;

    return r;
}

/* ====================================================================== */

static int search_time_t_cmp(message_t *m, const union search_value *v,
                             void *internalised __attribute__((unused)),
                             void *data1)
{
    int r;
    time_t t;
    int (*getter)(message_t *, time_t *) = (int(*)(message_t *, time_t *))data1;

    r = getter(m, &t);
    if (!r) {
        if (t < v->t)
            r = -1;
        else if (t == v->t)
            r = 0;
        else
            r = 1;
    }
    else
        r = 0;
    return r;
}

static int search_time_t_match(message_t *m, const union search_value *v,
                               void *internalised __attribute__((unused)),
                               void *data1)
{
    int r;
    time_t t;
    int (*getter)(message_t *, time_t *) = (int(*)(message_t *, time_t *))data1;

    r = getter(m, &t);
    if (!r)
        r = (v->t == t);
    else
        r = 0;

    return r;
}

static void search_time_t_serialise(struct buf *b, const union search_value *v)
{
    buf_printf(b, "%lld", (long long)v->t);
}

static int search_time_t_unserialise(struct protstream *prot, union search_value *v)
{
    int c;
    char tmp[32];

    c = getseword(prot, tmp, sizeof(tmp));
    v->t = strtoll(tmp, NULL, 10);
    return c;
}

/* ====================================================================== */

static int search_uint64_cmp(message_t *m, const union search_value *v,
                             void *internalised __attribute__((unused)),
                             void *data1)
{
    int r;
    uint64_t u;
    int (*getter)(message_t *, uint64_t *) = (int(*)(message_t *, uint64_t *))data1;

    r = getter(m, &u);
    if (!r) {
        if (u < v->u)
            r = -1;
        else if (u == v->u)
            r = 0;
        else
            r = 1;
    }
    else
        r = 0;
    return r;
}

static int search_uint64_match(message_t *m, const union search_value *v,
                               void *internalised __attribute__((unused)),
                               void *data1)
{
    int r;
    uint64_t u;
    int (*getter)(message_t *, uint64_t *) = (int(*)(message_t *, uint64_t *))data1;

    r = getter(m, &u);
    if (!r)
        r = (v->u == u);
    else
        r = 0;

    return r;
}

static void search_uint64_serialise(struct buf *b, const union search_value *v)
{
    buf_printf(b, "%llu", (unsigned long long)v->u);
}

static int search_uint64_unserialise(struct protstream *prot, union search_value *v)
{
    int c;
    char tmp[32];

    c = getseword(prot, tmp, sizeof(tmp));
    v->u = strtoull(tmp, NULL, 10);
    return c;
}

/* ====================================================================== */

static void search_cid_serialise(struct buf *b, const union search_value *v)
{
    buf_appendcstr(b, conversation_id_encode(v->u));
}

static int search_cid_unserialise(struct protstream *prot, union search_value *v)
{
    int c;
    conversation_id_t cid;
    char tmp[32];

    c = getseword(prot, tmp, sizeof(tmp));
    if (!conversation_id_decode(&cid, tmp))
        return EOF;
    v->u = cid;
    return c;
}

/* ====================================================================== */

static void search_folder_internalise(struct index_state *state,
                                      const union search_value *v,
                                      void **internalisedp)
{
    if (state)
        *internalisedp = (void *)(unsigned long)(!strcmp(mailbox_name(state->mailbox), v->s));
}

static int search_folder_match(message_t *m __attribute__((unused)),
                               const union search_value *v __attribute__((unused)),
                               void *internalised,
                               void *data1 __attribute__((unused)))
{
    return (int)(unsigned long)internalised;
}

unsigned int search_folder_get_countability(const union search_value *v
                                            __attribute__((unused)))
{
    return 0;
}

/* ====================================================================== */

static void search_annotation_internalise(struct index_state *state,
                                          const union search_value *v __attribute__((unused)),
                                          void **internalisedp)
{
    if (state)
        *internalisedp = state->mailbox;
}

struct search_annot_rock {
    int result;
    const struct buf *match;
};

static int _search_annot_match(const struct buf *match,
                               const struct buf *value)
{
    /* These cases are not explicitly defined in RFC 5257 */

    /* NIL matches NIL and nothing else */
    if (match->s == NULL)
        return (value->s == NULL);
    if (value->s == NULL)
        return 0;

    /* empty matches empty and nothing else */
    if (match->len == 0)
        return (value->len == 0);
    if (value->len == 0)
        return 0;

    /* RFC 5257 seems to define a simple CONTAINS style search */
    return !!memmem(value->s, value->len,
                    match->s, match->len);
}

static void _search_annot_callback(const char *mboxname __attribute__((unused)),
                                   uint32_t uid __attribute__((unused)),
                                   const char *entry __attribute__((unused)),
                                   struct attvaluelist *attvalues, void *rock)
{
    struct search_annot_rock *sarock = rock;
    struct attvaluelist *l;

    for (l = attvalues ; l ; l = l->next) {
        if (_search_annot_match(sarock->match, &l->value))
            sarock->result = 1;
    }
}

static int search_emailid_match(message_t *m, const union search_value *v,
                              void *internalised __attribute__((unused)),
                              void *data1 __attribute__((unused)))
{
    const struct message_guid *guid = NULL;
    char emailid[26];

    int r = message_get_guid(m, &guid);
    if (r) return 0;

    emailid[0] = 'M';
    memcpy(emailid+1, message_guid_encode(guid), 24);
    emailid[25] = '\0';

    return !strcmp(v->s, emailid);
}

static int search_threadid_match(message_t *m, const union search_value *v,
                                 void *internalised __attribute__((unused)),
                                 void *data1 __attribute__((unused)))
{
    conversation_id_t cid = 0;
    char threadid[18];

    int r = message_get_cid(m, &cid);
    if (r) return 0;

    threadid[0] = 'T';
    memcpy(threadid+1, conversation_id_encode(cid), 16);
    threadid[17] = '\0';

    return !strcmp(v->s, threadid);
}

static int search_annotation_match(message_t *m, const union search_value *v,
                                   void *internalised,
                                   void *data1 __attribute__((unused)))
{
    struct mailbox *mailbox = (struct mailbox *)internalised;
    struct searchannot *sa = v->annot;
    strarray_t entries = STRARRAY_INITIALIZER;
    strarray_t attribs = STRARRAY_INITIALIZER;
    annotate_state_t *astate = NULL;
    struct search_annot_rock rock;
    uint32_t uid;
    int r;

    strarray_append(&entries, sa->entry);
    strarray_append(&attribs, sa->attrib);

    message_get_uid(m, &uid);

    r = mailbox_get_annotate_state(mailbox, uid, &astate);
    if (r) goto out;
    annotate_state_set_auth(astate, sa->isadmin,
                            sa->userid, sa->auth_state);

    memset(&rock, 0, sizeof(rock));
    rock.match = &sa->value;

    r = annotate_state_fetch(astate,
                             &entries, &attribs,
                             _search_annot_callback, &rock);
    if (r >= 0)
        r = rock.result;

out:
    strarray_fini(&entries);
    strarray_fini(&attribs);
    return r;
}

static void search_annotation_serialise(struct buf *b, const union search_value *v)
{
    buf_printf(b, "(entry \"%s\" attrib \"%s\" value \"%s\")",
                v->annot->entry, v->annot->attrib, buf_cstring(&v->annot->value));
}

/* Note: this won't be usable for execution as it lacks
 * namespace etc pointers.  Nor can it handle binary values. */
static int search_annotation_unserialise(struct protstream *prot, union search_value *v)
{
    int c;
    char tmp[64];
    char entry[1024];
    char attrib[1024];
    char value[1024];

    c = prot_getc(prot);
    if (c != '(') return EOF;

    c = getseword(prot, tmp, sizeof(tmp));
    if (c != ' ') return EOF;
    if (strcmp(tmp, "entry")) return EOF;
    c = getseword(prot, entry, sizeof(entry));
    if (c != ' ') return EOF;

    c = getseword(prot, tmp, sizeof(tmp));
    if (c != ' ') return EOF;
    if (strcmp(tmp, "attrib")) return EOF;
    c = getseword(prot, attrib, sizeof(attrib));
    if (c != ' ') return EOF;

    c = getseword(prot, tmp, sizeof(tmp));
    if (c != ' ') return EOF;
    if (strcmp(tmp, "value")) return EOF;
    c = getseword(prot, value, sizeof(value));
    if (c != ')') return EOF;

    v->annot = (struct searchannot *)xzmalloc(sizeof(struct searchannot));
    v->annot->entry = xstrdup(entry);
    v->annot->attrib = xstrdup(attrib);
    buf_appendcstr(&v->annot->value, value);
    buf_cstring(&v->annot->value);

    c = prot_getc(prot);
    return c;
}

static void search_annotation_duplicate(union search_value *new,
                                        const union search_value *old)
{
    new->annot = (struct searchannot *)xmemdup(old->annot, sizeof(*old->annot));
    new->annot->entry = xstrdup(new->annot->entry);
    new->annot->attrib = xstrdup(new->annot->attrib);
    memset(&new->annot->value, 0, sizeof(struct buf));
    buf_append(&new->annot->value, &old->annot->value);
}

static void search_annotation_free(union search_value *v)
{
    if (v->annot) {
        free(v->annot->entry);
        free(v->annot->attrib);
        buf_free(&v->annot->value);
        free(v->annot);
        v->annot = NULL;
    }
}

/* ====================================================================== */

struct conv_rock {
    struct conversations_state *cstate;
    int cstate_is_ours;
    int num;        /* -1=invalid, 0=\Seen, 1+=index into cstate->counted_flags+1 */
};

static void conv_rock_new(struct mailbox *mailbox,
                          struct conv_rock **rockp);
static void conv_rock_free(struct conv_rock **rockp);

static void search_convflags_internalise(struct index_state *state,
                                         const union search_value *v,
                                         void **internalisedp)
{
    struct conv_rock **rockp = (struct conv_rock **)internalisedp;
    struct conv_rock *rock;

    conv_rock_free(rockp);

    if (state) {
        conv_rock_new(state->mailbox, rockp);
        rock = *rockp;
        if (rock->cstate) {
            if (!strcasecmp(v->s, "\\Seen")) {
                rock->num = 0;
            }
            else if (!rock->cstate->counted_flags) {
                rock->num = -1;
            }
            else {
                rock->num = strarray_find_case(rock->cstate->counted_flags, v->s, 0);
                /* rock->num might be -1 invalid */
                if (rock->num >= 0)
                    rock->num++;
            }
        }
    }
}

static int search_convflags_match(message_t *m,
                                  const union search_value *v __attribute__((unused)),
                                  void *internalised,
                                  void *data1 __attribute__((unused)))
{
    struct conv_rock *rock = (struct conv_rock *)internalised;
    conversation_id_t cid = NULLCONVERSATION;
    conversation_t conv = CONVERSATION_INIT;
    int r = 0; /* invalid flag name */

    if (!rock->cstate) return 0;

    message_get_cid(m, &cid);
    if (conversation_load_advanced(rock->cstate, cid, &conv, /*flags*/0)) return 0;
    if (!conv.exists) return 0;

    if (rock->num == 0)
        r = (conv.unseen != conv.exists);
    else if (rock->num > 0)
        r = !!conv.counts[rock->num-1];

    conversation_fini(&conv);
    return r;
}

static int search_allconvflags_match(message_t *m,
                                     const union search_value *v __attribute__((unused)),
                                     void *internalised,
                                     void *data1 __attribute__((unused)))
{
    struct conv_rock *rock = (struct conv_rock *)internalised;
    conversation_id_t cid = NULLCONVERSATION;
    conversation_t conv = CONVERSATION_INIT;
    int r = 0; /* invalid flag name */

    if (!rock->cstate) return 0;

    message_get_cid(m, &cid);
    if (conversation_load_advanced(rock->cstate, cid, &conv, /*flags*/0)) return 0;
    if (!conv.exists) return 0;

    if (rock->num == 0)
        r = !conv.unseen;
    else if (rock->num > 0)
        r = (conv.counts[rock->num-1] == conv.exists);

    conversation_fini(&conv);
    return r;
}

unsigned int search_convflags_get_countability(const union search_value *v)
{
    if (!strcasecmp(v->s, "\\Seen"))
        return SEC_CONVSEEN;
    return SEC_UNCOUNTED;
}

static void search_convmodseq_internalise(struct index_state *state,
                                          const union search_value *v __attribute__((unused)),
                                          void **internalisedp)
{
    struct conv_rock **rockp = (struct conv_rock **)internalisedp;

    conv_rock_free(rockp);

    if (state) {
        conv_rock_new(state->mailbox, rockp);
    }
}

static int search_convmodseq_match(message_t *m, const union search_value *v,
                                   void *internalised,
                                   void *data1 __attribute__((unused)))
{
    struct conv_rock *rock = (struct conv_rock *)internalised;
    conversation_id_t cid = NULLCONVERSATION;
    conversation_t conv = CONVERSATION_INIT;
    int r;

    if (!rock->cstate) return 0;

    message_get_cid(m, &cid);
    if (conversation_load_advanced(rock->cstate, cid, &conv, /*flags*/0)) return 0;
    if (!conv.exists) return 0;

    r = (v->u == conv.modseq);

    conversation_fini(&conv);
    return r;
}

static void conv_rock_new(struct mailbox *mailbox,
                          struct conv_rock **rockp)
{
    struct conv_rock *rock = xzmalloc(sizeof(*rock));

    rock->cstate = conversations_get_mbox(mailbox_name(mailbox));
    if (!rock->cstate) {
        if (conversations_open_mbox(mailbox_name(mailbox), 1/*shared*/, &rock->cstate))
            rock->num = -1;         /* invalid */
        else
            rock->cstate_is_ours = 1;
    }

    *rockp = rock;
}

static void conv_rock_free(struct conv_rock **rockp)
{
    struct conv_rock *rock = *rockp;
    if (rock) {
        if (rock->cstate_is_ours)
            conversations_abort(&rock->cstate);
        free(rock);
        *rockp = NULL;
    }
}


/* ====================================================================== */

static int search_uint32_cmp(message_t *m, const union search_value *v,
                             void *internalised __attribute__((unused)),
                             void *data1)
{
    int r;
    uint32_t u;
    int (*getter)(message_t *, uint32_t *) = (int(*)(message_t *, uint32_t *))data1;

    r = getter(m, &u);
    if (!r) {
        if (u < v->u)
            r = -1;
        else if (u == v->u)
            r = 0;
        else
            r = 1;
    }
    else
        r = 0;
    return r;
}

static int search_uint32_match(message_t *m, const union search_value *v,
                               void *internalised __attribute__((unused)),
                               void *data1)
{
    int r;
    uint32_t u;
    int (*getter)(message_t *, uint32_t *) = (int(*)(message_t *, uint32_t *))data1;

    r = getter(m, &u);
    if (!r)
        r = (v->u == u);
    else
        r = 0;
    return r;
}

static void search_uint32_serialise(struct buf *b, const union search_value *v)
{
    buf_printf(b, "%u", (uint32_t)v->u);
}

static int search_uint32_unserialise(struct protstream *prot, union search_value *v)
{
    int c;
    char tmp[32];

    c = getseword(prot, tmp, sizeof(tmp));
    v->u = strtoul(tmp, NULL, 10);
    return c;
}

static void search_percent_serialise(struct buf *b, const union search_value *v)
{
    buf_printf(b, "%0.2f", ((float)v->u / 100));
}

static int search_percent_unserialise(struct protstream *prot, union search_value *v)
{
    int c;
    char tmp[32];

    c = getseword(prot, tmp, sizeof(tmp));
    v->u = (int)((atof(tmp) * 100) + 0.5);
    return c;
}

/* ====================================================================== */

/*
 * Search part of a message for a substring.
 */

struct searchmsg_rock
{
    const char *substr;
    comp_pat *pat;
    int skipheader;
    int result;
};

static int searchmsg_cb(int isbody, charset_t charset, int encoding,
                        const char *type __attribute__((unused)),
                        const char *subtype __attribute__((unused)),
                        const struct param *type_params __attribute__((unused)),
                        const char *disposition __attribute__((unused)),
                        const struct param *disposition_params __attribute__((unused)),
                        const struct message_guid *content_guid __attribute__((unused)),
                        const char *part __attribute__((unused)),
                        struct buf *data, void *rock)
{
    struct searchmsg_rock *sr = (struct searchmsg_rock *)rock;

    if (!isbody) {
        /* header-like */
        if (sr->skipheader) {
            sr->skipheader = 0; /* Only skip top-level message header */
            return 0;
        }
        sr->result = charset_search_mimeheader(sr->substr, sr->pat,
                                               buf_cstring(data), charset_flags);
    }
    else {
        /* body-like */
        if (charset == CHARSET_UNKNOWN_CHARSET) return 0;
        sr->result = charset_searchfile(sr->substr, sr->pat,
                                        data->s, data->len,
                                        charset, encoding, charset_flags);
    }
    if (sr->result) return 1; /* found it, exit early */
    return 0;
}

static int search_text_match(message_t *m,
                             const union search_value *v __attribute__((unused)),
                             void *internalised,
                             void *data1)
{
    struct searchmsg_rock sr;
    struct search_string_internal *internal = internalised;

    sr.substr = internal->s;
    sr.pat = internal->pat;
    sr.skipheader = (int)(unsigned long)data1;
    sr.result = 0;
    message_foreach_section(m, searchmsg_cb, &sr);
    return sr.result;
}

static int search_language_match(message_t *m __attribute__((unused)),
                                 const union search_value *v __attribute__((unused)),
                                 void *internalised __attribute__((unused)),
                                 void *data1 __attribute__((unused)))
{
    /* language matching must be done in the backend */
    syslog(LOG_DEBUG, "%s: ignoring language search attribute", __func__);
    return 1;
}

/* ====================================================================== */

static void search_seen_internalise(struct index_state *state,
                                    const union search_value *v,
                                    void **internalisedp)
{
    seqset_free((seqset_t **)internalisedp);
    if (v) {
        if (!mailbox_internal_seen(state->mailbox, v->s)) {
            // read sequence of seen uids from seendb,
            // fall back to owner systemflags on error
            seqset_t *seen = NULL;
            struct seen *seendb = NULL;
            int r = seen_open(v->s, SEEN_SILENT, &seendb);
            if (!r) {
                struct seendata sd = SEENDATA_INITIALIZER;
                r = seen_read(seendb, mailbox_uniqueid(state->mailbox), &sd);
                if (!r) {
                    seen = seqset_parse(sd.seenuids, NULL, sd.lastuid);
                    seen_freedata(&sd);
                    *internalisedp = seen;
                }
                else {
                    xsyslog(LOG_WARNING, "can not read seen data",
                            "userid=<%s> mboxid=<%s> err=<%s>",
                            v->s, mailbox_uniqueid(state->mailbox), error_message(r));
                }
            }
            else {
                xsyslog(LOG_WARNING, "can not open seendb",
                        "userid=<%s> err=<%s>", v->s, error_message(r));
            }
            seen_close(&seendb);
        }
    }
}

static int search_seen_match(message_t *m,
                             const union search_value *v __attribute__((unused)),
                             void *internalised,
                             void *data1 __attribute__((unused)))
{
    if (internalised) {
        seqset_t *seen = internalised;
        uint32_t uid;
        if (!message_get_uid(m, &uid)) {
            return seqset_ismember(seen, uid);
        }
        else return 0;
    }
    else {
        uint32_t flags;
        if (!message_get_systemflags(m, &flags)) {
            return flags & FLAG_SEEN;
        }
        else return 0;
    }
}

/* ====================================================================== */

static hash_table attrs_by_name = HASH_TABLE_INITIALIZER;

static int search_attr_initialized = 0;

static void done_cb(void *rock __attribute__((unused))) {
    hash_iter *iter = hash_table_iter(&attrs_by_name);
    while (hash_iter_next(iter)) {
        struct search_attr *attr = hash_iter_val(iter);
        if (attr->freeattr) attr->freeattr(attr);
    }
    hash_iter_free(&iter);
    free_hash_table(&attrs_by_name, NULL);
}

static void init_internal() {
    if (!search_attr_initialized) {
        search_attr_init();
        cyrus_modules_add(done_cb, NULL);
    }
}

/*
 * Call search_attr_init() before doing any work with search
 * expressions.
 */
EXPORTED void search_attr_init(void)
{
    unsigned int i;

    static const search_attr_t attrs[] = {
        {
            "bcclist",
            SEA_FUZZABLE|SEA_ISLIST,
            SEARCH_PART_BCC,
            SEARCH_COST_CACHE,
            search_list_internalise,
            /*cmp*/NULL,
            search_list_match,
            search_list_serialise,
            search_list_unserialise,
            /*get_countability*/NULL,
            search_list_duplicate,
            search_list_free,
            /*freeattr*/NULL,
            (void *)message_get_bcc
        },{
            "cclist",
            SEA_FUZZABLE|SEA_ISLIST,
            SEARCH_PART_CC,
            SEARCH_COST_CACHE,
            search_list_internalise,
            /*cmp*/NULL,
            search_list_match,
            search_list_serialise,
            search_list_unserialise,
            /*get_countability*/NULL,
            search_list_duplicate,
            search_list_free,
            /*freeattr*/NULL,
            (void *)message_get_cc
        },{
            "fromlist",
            SEA_FUZZABLE|SEA_ISLIST,
            SEARCH_PART_FROM,
            SEARCH_COST_CACHE,
            search_list_internalise,
            /*cmp*/NULL,
            search_list_match,
            search_list_serialise,
            search_list_unserialise,
            /*get_countability*/NULL,
            search_list_duplicate,
            search_list_free,
            /*freeattr*/NULL,
            (void *)message_get_from
        },{
            "tolist",
            SEA_FUZZABLE|SEA_ISLIST,
            SEARCH_PART_TO,
            SEARCH_COST_CACHE,
            search_list_internalise,
            /*cmp*/NULL,
            search_list_match,
            search_list_serialise,
            search_list_unserialise,
            /*get_countability*/NULL,
            search_list_duplicate,
            search_list_free,
            /*freeattr*/NULL,
            (void *)message_get_to
        },{
            "bcc",
            SEA_FUZZABLE,
            SEARCH_PART_BCC,
            SEARCH_COST_CACHE,
            search_string_internalise,
            /*cmp*/NULL,
            search_string_match,
            search_string_serialise,
            search_string_unserialise,
            /*get_countability*/NULL,
            search_string_duplicate,
            search_string_free,
            /*freeattr*/NULL,
            (void *)message_get_bcc
        },{
            "deliveredto",
            SEA_FUZZABLE,
            SEARCH_PART_DELIVEREDTO,
            SEARCH_COST_BODY,
            search_string_internalise,
            /*cmp*/NULL,
            search_string_match,
            search_string_serialise,
            search_string_unserialise,
            /*get_countability*/NULL,
            search_string_duplicate,
            search_string_free,
            /*freeattr*/NULL,
            (void *)message_get_deliveredto
        },{
            "cc",
            SEA_FUZZABLE,
            SEARCH_PART_CC,
            SEARCH_COST_CACHE,
            search_string_internalise,
            /*cmp*/NULL,
            search_string_match,
            search_string_serialise,
            search_string_unserialise,
            /*get_countability*/NULL,
            search_string_duplicate,
            search_string_free,
            /*freeattr*/NULL,
            (void *)message_get_cc
        },{
            "from",
            SEA_FUZZABLE,
            SEARCH_PART_FROM,
            SEARCH_COST_CACHE,
            search_string_internalise,
            /*cmp*/NULL,
            search_string_match,
            search_string_serialise,
            search_string_unserialise,
            /*get_countability*/NULL,
            search_string_duplicate,
            search_string_free,
            /*freeattr*/NULL,
            (void *)message_get_from
        },{
            "message-id",
            /*flags*/0,
            SEARCH_PART_NONE,
            SEARCH_COST_CACHE,
            search_string_internalise,
            /*cmp*/NULL,
            search_string_match,
            search_string_serialise,
            search_string_unserialise,
            /*get_countability*/NULL,
            search_string_duplicate,
            search_string_free,
            /*freeattr*/NULL,
            (void *)message_get_messageid
        },{
            "listid",
            SEA_FUZZABLE,
            SEARCH_PART_LISTID,
            SEARCH_COST_CACHE,
            search_string_internalise,
            /*cmp*/NULL,
            search_listid_match,
            search_string_serialise,
            search_string_unserialise,
            /*get_countability*/NULL,
            search_string_duplicate,
            search_string_free,
            /*freeattr*/NULL,
            NULL
        },{
            "contenttype",
            SEA_FUZZABLE,
            SEARCH_PART_TYPE,
            SEARCH_COST_CACHE,
            search_string_internalise,
            /*cmp*/NULL,
            search_contenttype_match,
            search_string_serialise,
            search_string_unserialise,
            /*get_countability*/NULL,
            search_string_duplicate,
            search_string_free,
            /*freeattr*/NULL,
            NULL
        },{
            "subject",
            SEA_FUZZABLE,
            SEARCH_PART_SUBJECT,
            SEARCH_COST_CACHE,
            search_string_internalise,
            /*cmp*/NULL,
            search_string_match,
            search_string_serialise,
            search_string_unserialise,
            /*get_countability*/NULL,
            search_string_duplicate,
            search_string_free,
            /*freeattr*/NULL,
            (void *)message_get_subject
        },{
            "to",
            SEA_FUZZABLE,
            SEARCH_PART_TO,
            SEARCH_COST_CACHE,
            search_string_internalise,
            /*cmp*/NULL,
            search_string_match,
            search_string_serialise,
            search_string_unserialise,
            /*get_countability*/NULL,
            search_string_duplicate,
            search_string_free,
            /*freeattr*/NULL,
            (void *)message_get_to
        },{
            "msgno",
            SEA_MUTABLE,
            SEARCH_PART_NONE,
            SEARCH_COST_INDEX,
            search_msgno_internalise,
            /*cmp*/NULL,
            search_seq_match,
            search_seq_serialise,
            search_string_unserialise,
            /*get_countability*/NULL,
            search_string_duplicate,
            search_string_free,
            /*freeattr*/NULL,
            (void *)message_get_msgno
        },{
            "uid",
            /*flags*/0,
            SEARCH_PART_NONE,
            SEARCH_COST_INDEX,
            search_uid_internalise,
            /*cmp*/NULL,
            search_seq_match,
            search_seq_serialise,
            search_string_unserialise,
            /*get_countability*/NULL,
            search_string_duplicate,
            search_string_free,
            /*freeattr*/NULL,
            (void *)message_get_uid
        },{
            "systemflags",
            SEA_MUTABLE,
            SEARCH_PART_NONE,
            SEARCH_COST_INDEX,
            /*internalise*/NULL,
            /*cmp*/NULL,
            search_flags_match,
            search_systemflags_serialise,
            search_systemflags_unserialise,
            /*get_countability*/NULL,
            /*duplicate*/NULL,
            /*free*/NULL,
            /*freeattr*/NULL,
            (void *)message_get_systemflags
        },{
            "indexflags",
            SEA_MUTABLE,
            SEARCH_PART_NONE,
            SEARCH_COST_INDEX,
            /*internalise*/NULL,
            /*cmp*/NULL,
            search_flags_match,
            search_indexflags_serialise,
            search_indexflags_unserialise,
            search_indexflags_get_countability,
            /*duplicate*/NULL,
            /*free*/NULL,
            /*freeattr*/NULL,
            (void *)message_get_indexflags
        },{
            "keyword",
            SEA_MUTABLE,
            SEARCH_PART_NONE,
            SEARCH_COST_INDEX,
            search_keyword_internalise,
            /*cmp*/NULL,
            search_keyword_match,
            search_string_serialise,
            search_string_unserialise,
            /*get_countability*/NULL,
            search_string_duplicate,
            search_string_free,
            /*freeattr*/NULL,
            NULL
        },{
            "convflags",
            SEA_MUTABLE,
            SEARCH_PART_NONE,
            SEARCH_COST_CONV,
            search_convflags_internalise,
            /*cmp*/NULL,
            search_convflags_match,
            search_string_serialise,
            search_string_unserialise,
            search_convflags_get_countability,
            search_string_duplicate,
            search_string_free,
            /*freeattr*/NULL,
            NULL
        },{
            "allconvflags",
            SEA_MUTABLE,
            SEARCH_PART_NONE,
            SEARCH_COST_CONV,
            search_convflags_internalise,
            /*cmp*/NULL,
            search_allconvflags_match,
            search_string_serialise,
            search_string_unserialise,
            search_convflags_get_countability,
            search_string_duplicate,
            search_string_free,
            /*freeattr*/NULL,
            NULL
        },{
            "convmodseq",
            SEA_MUTABLE,
            SEARCH_PART_NONE,
            SEARCH_COST_CONV,
            search_convmodseq_internalise,
            /*cmp*/NULL,
            search_convmodseq_match,
            search_uint64_serialise,
            search_uint64_unserialise,
            /*get_countability*/NULL,
            /*duplicate*/NULL,
            /*free*/NULL,
            /*freeattr*/NULL,
            NULL
        },{
            "modseq",
            SEA_MUTABLE,
            SEARCH_PART_NONE,
            SEARCH_COST_INDEX,
            /*internalise*/NULL,
            search_uint64_cmp,
            search_uint64_match,
            search_uint64_serialise,
            search_uint64_unserialise,
            /*get_countability*/NULL,
            /*duplicate*/NULL,
            /*free*/NULL,
            /*freeattr*/NULL,
            (void *)message_get_modseq
        },{
            "cid",
            SEA_MUTABLE,
            SEARCH_PART_NONE,
            SEARCH_COST_INDEX,
            /*internalise*/NULL,
            search_uint64_cmp,
            search_uint64_match,
            search_cid_serialise,
            search_cid_unserialise,
            /*get_countability*/NULL,
            /*duplicate*/NULL,
            /*free*/NULL,
            /*freeattr*/NULL,
            (void *)message_get_cid
        },{
            "emailid",
            /* flags */0,
            SEARCH_PART_NONE,
            SEARCH_COST_INDEX,
            /*internalise*/NULL,
            /*cmp*/ NULL,
            search_emailid_match,
            search_string_serialise,
            search_string_unserialise,
            /*get_countability*/NULL,
            search_string_duplicate,
            search_string_free,
            /*freeattr*/NULL,
            (void *)NULL
        },{
            "threadid",
            /* flags */0,
            SEARCH_PART_NONE,
            SEARCH_COST_INDEX,
            /*internalise*/NULL,
            /*cmp*/ NULL,
            search_threadid_match,
            search_string_serialise,
            search_string_unserialise,
            /*get_countability*/NULL,
            search_string_duplicate,
            search_string_free,
            /*freeattr*/NULL,
            (void *)NULL
        },{
            "folder",
            /*flags*/0,
            SEARCH_PART_NONE,
            SEARCH_COST_NONE,
            search_folder_internalise,
            /*cmp*/NULL,
            search_folder_match,
            search_string_serialise,
            search_string_unserialise,
            search_folder_get_countability,
            search_string_duplicate,
            search_string_free,
            /*freeattr*/NULL,
            (void *)NULL
        },{
            "annotation",
            SEA_MUTABLE,
            SEARCH_PART_NONE,
            SEARCH_COST_ANNOT,
            search_annotation_internalise,
            /*cmp*/NULL,
            search_annotation_match,
            search_annotation_serialise,
            search_annotation_unserialise,
            /*get_countability*/NULL,
            search_annotation_duplicate,
            search_annotation_free,
            /*freeattr*/NULL,
            (void *)NULL
        },{
            "size",
            /*flags*/0,
            SEARCH_PART_NONE,
            SEARCH_COST_INDEX,
            /*internalise*/NULL,
            search_uint32_cmp,
            search_uint32_match,
            search_uint32_serialise,
            search_uint32_unserialise,
            /*get_countability*/NULL,
            /*duplicate*/NULL,
            /*free*/NULL,
            /*freeattr*/NULL,
            (void *)message_get_size
        },{
            "internaldate",
            /*flags*/0,
            SEARCH_PART_NONE,
            SEARCH_COST_INDEX,
            /*internalise*/NULL,
            search_time_t_cmp,
            search_time_t_match,
            search_time_t_serialise,
            search_time_t_unserialise,
            /*get_countability*/NULL,
            /*duplicate*/NULL,
            /*free*/NULL,
            /*freeattr*/NULL,
            (void *)message_get_internaldate
        },{
            "savedate",
            /*flags*/0,
            SEARCH_PART_NONE,
            SEARCH_COST_INDEX,
            /*internalise*/NULL,
            search_time_t_cmp,
            search_time_t_match,
            search_time_t_serialise,
            search_time_t_unserialise,
            /*get_countability*/NULL,
            /*duplicate*/NULL,
            /*free*/NULL,
            /*freeattr*/NULL,
            (void *)message_get_savedate
        },{
            "indexversion",
            /*flags*/0,
            SEARCH_PART_NONE,
            SEARCH_COST_NONE,
            /*internalise*/NULL,
            search_uint32_cmp,
            search_uint32_match,
            search_uint32_serialise,
            search_uint32_unserialise,
            /*get_countability*/NULL,
            /*duplicate*/NULL,
            /*free*/NULL,
            /*freeattr*/NULL,
            (void *)message_get_indexversion
        },{
            "sentdate",
            /*flags*/0,
            SEARCH_PART_NONE,
            SEARCH_COST_INDEX,
            /*internalise*/NULL,
            search_time_t_cmp,
            search_time_t_match,
            search_time_t_serialise,
            search_time_t_unserialise,
            /*get_countability*/NULL,
            /*duplicate*/NULL,
            /*free*/NULL,
            /*freeattr*/NULL,
            (void *)message_get_sentdate
        },{
            "spamscore",
            /*flags*/0,
            SEARCH_PART_NONE,
            SEARCH_COST_INDEX,
            /*internalise*/NULL,
            search_uint32_cmp,
            search_uint32_match,
            search_percent_serialise,
            search_percent_unserialise,
            /*get_countability*/NULL,
            /*duplicate*/NULL,
            /*free*/NULL,
            /*freeattr*/NULL,
            (void *)message_get_spamscore
        },{
            "body",
            SEA_FUZZABLE,
            SEARCH_PART_BODY,
            SEARCH_COST_BODY,
            search_string_internalise,
            /*cmp*/NULL,
            search_text_match,
            search_string_serialise,
            search_string_unserialise,
            /*get_countability*/NULL,
            search_string_duplicate,
            search_string_free,
            /*freeattr*/NULL,
            (void *)1       /* skipheader flag */
        },{
            "text",
            SEA_FUZZABLE,
            SEARCH_PART_ANY,
            SEARCH_COST_BODY,
            search_string_internalise,
            /*cmp*/NULL,
            search_text_match,
            search_string_serialise,
            search_string_unserialise,
            /*get_countability*/NULL,
            search_string_duplicate,
            search_string_free,
            /*freeattr*/NULL,
            (void *)0       /* skipheader flag */
        },{
            "date",
            /*flags*/0,
            SEARCH_PART_NONE,
            SEARCH_COST_INDEX,
            /*internalise*/NULL,
            search_time_t_cmp,
            search_time_t_match,
            search_time_t_serialise,
            search_time_t_unserialise,
            /*get_countability*/NULL,
            /*duplicate*/NULL,
            /*free*/NULL,
            /*freeattr*/NULL,
            (void *)message_get_gmtime
        },{
            "location",     /* for iCalendar */
            SEA_FUZZABLE,
            SEARCH_PART_LOCATION,
            SEARCH_COST_BODY,
            search_string_internalise,
            /*cmp*/NULL,
            search_string_match,
            search_string_serialise,
            search_string_unserialise,
            /*get_countability*/NULL,
            search_string_duplicate,
            search_string_free,
            /*freeattr*/NULL,
            (void *)0
        },{
            "attachmentname",
            SEA_FUZZABLE,
            SEARCH_PART_ATTACHMENTNAME,
            SEARCH_COST_BODY,
            search_string_internalise,
            /*cmp*/NULL,
            search_string_match,
            search_string_serialise,
            search_string_unserialise,
            /*get_countability*/NULL,
            search_string_duplicate,
            search_string_free,
            /*freeattr*/NULL,
            (void *)0
        },{
            "attachmentbody",
            SEA_FUZZABLE,
            SEARCH_PART_ATTACHMENTBODY,
            SEARCH_COST_BODY,
            search_string_internalise,
            /*cmp*/NULL,
            search_text_match,
            search_string_serialise,
            search_string_unserialise,
            /*get_countability*/NULL,
            search_string_duplicate,
            search_string_free,
            /*freeattr*/NULL,
            (void *)0       /* skipheader flag */
        },{
            "language",
            SEA_FUZZABLE,
            SEARCH_PART_LANGUAGE,
            SEARCH_COST_BODY,
            search_string_internalise,
            /*cmp*/NULL,
            search_language_match,
            search_string_serialise,
            search_string_unserialise,
            /*get_countability*/NULL,
            search_string_duplicate,
            search_string_free,
            /*freeattr*/NULL,
            (void *)0
        }, {
            "priority",
            SEA_FUZZABLE,
            SEARCH_PART_PRIORITY,
            SEARCH_COST_BODY,
            search_string_internalise,
            /*cmp*/NULL,
            search_string_match,
            search_string_serialise,
            search_string_unserialise,
            /*get_countability*/NULL,
            search_string_duplicate,
            search_string_free,
            /*freeattr*/NULL,
            (void *)message_get_priority
        },{
            "seen",
            SEA_MUTABLE,
            SEARCH_PART_NONE,
            SEARCH_COST_INDEX,
            search_seen_internalise,
            /*cmp*/NULL,
            search_seen_match,
            search_string_serialise,
            search_string_unserialise,
            /*get_countability*/NULL,
            search_string_duplicate,
            search_string_free,
            /*freeattr*/NULL,
            (void *)0
        }
    };

    construct_hash_table(&attrs_by_name, VECTOR_SIZE(attrs), 0);
    for (i = 0 ; i < VECTOR_SIZE(attrs) ; i++)
        hash_insert(attrs[i].name, (void *)&attrs[i], &attrs_by_name);

    search_attr_initialized = 1;
}

/*
 * Find and return a search attribute by name.  Used when building
 * comparison nodes in a search expression tree.  Name comparison is
 * case insensitive.  Returns a pointer to static data or NULL if there
 * is no attribute of the given name.
 */
EXPORTED const search_attr_t *search_attr_find(const char *name)
{
    char tmp[128];

    init_internal();

    strlcpy(tmp, name, sizeof(tmp));
    lcase(tmp);
    return hash_lookup(tmp, &attrs_by_name);
}

static void field_attr_free(search_attr_t *attr)
{
    free((char*)attr->name);
    free(attr);
}

/*
 * Find and return a search attribute for the named header field.  Used
 * when building comparison nodes for the HEADER search criterion in a
 * search expression tree.  Field name comparison is case insensitive.
 * Returns a pointer to internally managed data or NULL if there is no
 * attribute of the given name.
 */
EXPORTED const search_attr_t *search_attr_find_field(const char *field)
{
    search_attr_t *attr;
    char *key = NULL;
    static const search_attr_t proto = {
        "name",
        SEA_FUZZABLE,
        SEARCH_PART_NONE,
        SEARCH_COST_NONE,
        search_string_internalise,
        /*cmp*/NULL,
        search_header_match,
        search_string_serialise,
        search_string_unserialise,
        /*get_countability*/NULL,
        search_string_duplicate,
        search_string_free,
        field_attr_free,
        NULL
    };

    init_internal();

    /* some header fields can be reduced to search terms */
    if (!strcasecmp(field, "bcc") ||
        !strcasecmp(field, "cc") ||
        !strcasecmp(field, "to") ||
        !strcasecmp(field, "from") ||
        !strcasecmp(field, "subject") ||
        !strcasecmp(field, "message-id"))
        return search_attr_find(field);

    key = lcase(strconcat("header:", field, (char *)NULL));
    attr = (search_attr_t *)hash_lookup(key, &attrs_by_name);

    if (!attr) {
        attr = (search_attr_t *)xzmalloc(sizeof(search_attr_t));
        *attr = proto;
        attr->name = key;
        attr->cost = (mailbox_cached_header(field) != BIT32_MAX)
                   ? SEARCH_COST_CACHE : SEARCH_COST_BODY;
        attr->part = (config_getswitch(IMAPOPT_SEARCH_INDEX_HEADERS)
                        ? SEARCH_PART_HEADERS : -1);
        attr->freeattr = field_attr_free;
        attr->data1 = strchr(key, ':')+1;
        hash_insert(attr->name, (void *)attr, &attrs_by_name);
        key = NULL;     /* attr takes this over */
    }

    free(key);
    return attr;
}

/*
 * Return non-zero if the given attribute may be used with a
 * SEOP_FUZZYMATCH operation.
 */
EXPORTED int search_attr_is_fuzzable(const search_attr_t *attr)
{
    return (attr->part != SEARCH_PART_NONE &&
            (attr->flags & SEA_FUZZABLE));
}

EXPORTED enum search_cost search_attr_cost(const search_attr_t *attr)
{
    return attr->cost;
}

