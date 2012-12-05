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

#include "imap_err.h"
#include "search_expr.h"
#include "message.h"
#include "charset.h"
#include "annotate.h"
#include "global.h"
#include "xstrlcpy.h"
#include "xmalloc.h"

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

static search_expr_t *detach(search_expr_t *parent, search_expr_t *child)
{
    search_expr_t **prevp;

    for (prevp = &parent->children ; *prevp && *prevp != child; prevp = &(*prevp)->next)
	;
    *prevp = child->next;
    child->next = NULL;
    child->parent = NULL;

    return child;
}

/* Replace the node 'child' with it's children, i.e. reparent them.
 * Apparently this operation is called "splat" but I think that's
 * a damn silly name */
static search_expr_t *elide(search_expr_t *parent, search_expr_t *child)
{
    search_expr_t **prevp;
    search_expr_t *grand;

    for (prevp = &parent->children ; *prevp && *prevp != child; prevp = &(*prevp)->next)
	;
    *prevp = child->children;

    for (grand = child->children ; grand ; grand = grand->next) {
	grand->parent = parent;
	prevp = &grand->next;
    }
    *prevp = child->next;

    child->next = NULL;
    child->children = NULL;
    child->parent = NULL;

    return child;
}

EXPORTED search_expr_t *search_expr_new(search_expr_t *parent, enum search_op op)
{
    search_expr_t *e = xzmalloc(sizeof(search_expr_t));
    e->op = op;
    if (parent) append(parent, e);
    return e;
}

EXPORTED void search_expr_free(search_expr_t *e)
{
    while (e->children)
	search_expr_free(detach(e, e->children));
    if (e->attr) {
	if (e->attr->internalise) e->attr->internalise(NULL, NULL, &e->internalised);
	if (e->attr->free) e->attr->free(&e->value);
    }
    free(e);
}

static const char *op_as_string(enum search_op op)
{
    switch (op) {
    case SEOP_UNKNOWN: return "UNKNOWN";
    case SEOP_TRUE: return "TRUE";
    case SEOP_FALSE: return "FALSE";
    case SEOP_LT: return "LT";
    case SEOP_LE: return "LE";
    case SEOP_GT: return "GT";
    case SEOP_GE: return "GE";
    case SEOP_MATCH: return "MATCH";
    case SEOP_AND: return "AND";
    case SEOP_OR: return "OR";
    case SEOP_NOT: return "NOT";
    }
    return "WTF??";
}

static void dump2(const search_expr_t *e, int indent)
{
    int i;
    const search_expr_t *child;
    static struct buf buf = BUF_INITIALIZER;

    buf_reset(&buf);
    for (i = 0 ; i < indent ; i++)
	buf_appendcstr(&buf, "  ");
    buf_printf(&buf, "%s", op_as_string(e->op));
    if (e->attr) {
	buf_printf(&buf, " %s ", e->attr->name);
	if (e->attr->describe) e->attr->describe(&buf, &e->value);
    }
    syslog(LOG_INFO, "EXPR %s", buf_cstring(&buf));
    for (child = e->children ; child ; child = child->next)
	dump2(child, indent+1);
}

EXPORTED void search_expr_dump(const search_expr_t *e)
{
    syslog(LOG_INFO, "EXPR {");
    dump2(e, 0);
    syslog(LOG_INFO, "EXPR }");
}

EXPORTED void search_expr_internalise(struct mailbox *mailbox, search_expr_t *e)
{
    search_expr_t *child;

    if (e->attr && e->attr->internalise)
	e->attr->internalise(mailbox, &e->value, &e->internalised);

    for (child = e->children ; child ; child = child->next)
	search_expr_internalise(mailbox, child);
}

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

static int search_string_match(message_t *m, const union search_value *v,
				void *internalised, void *data1)
{
    int r;
    struct buf buf = BUF_INITIALIZER;
    int (*getter)(message_t *, struct buf *) = (int(*)(message_t *, struct buf *))data1;
    comp_pat *pat = (comp_pat *)internalised;

    r = getter(m, &buf);
    if (!r)
	r = charset_searchstring(v->s, pat, buf.s, buf.len, charset_flags);
    else
	r = 0;
    buf_free(&buf);

    return r;
}

static void search_string_describe(struct buf *b, const union search_value *v)
{
    buf_printf(b, "\"%s\"", v->s);
}

static void search_string_internalise(struct mailbox *mailbox __attribute__((unused)),
				      const union search_value *v, void **internalisedp)
{
    if (*internalisedp) {
	charset_freepat(*internalisedp);
	*internalisedp = NULL;
    }
    if (v) {
	*internalisedp = charset_compilepat(v->s);
    }
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

static int search_contenttype_match(message_t *m, const union search_value *v,
				    void *internalised,
				    void *data1 __attribute__((unused)))
{
    int r;
    comp_pat *pat = (comp_pat *)internalised;
    strarray_t types = STRARRAY_INITIALIZER;
    int i;
    char combined[128];

    if (!message_get_leaf_types(m, &types)) {
	for (i = 0 ; i < types.count ; i+= 2) {
	    const char *type = types.data[i];
	    const char *subtype = types.data[i+1];

	    /* match against type */
	    r = charset_searchstring(v->s, pat, type, strlen(type), charset_flags);
	    if (r) goto out;	// success

	    /* match against subtype */
	    r = charset_searchstring(v->s, pat, subtype, strlen(subtype), charset_flags);
	    if (r) goto out;	// success

	    /* match against combined type_subtype */
	    snprintf(combined, sizeof(combined), "%s_%s", type, subtype);
	    r = charset_searchstring(v->s, pat, combined, strlen(combined), charset_flags);
	    if (r) goto out;	// success
	}
    }

    r = 0;  // failure

out:
    strarray_fini(&types);
    return r;
}

/* ====================================================================== */

static int search_seq_match(message_t *m, const union search_value *v,
			    void *internalised __attribute__((unused)),
			    void *data1)
{
    int r;
    uint32_t u;
    int (*getter)(message_t *, uint32_t *) = (int(*)(message_t *, uint32_t *))data1;

    r = getter(m, &u);
    if (!r)
	r = seqset_ismember(v->seq, u);
    else
	r = 0;

    return r;
}

static void search_seq_describe(struct buf *b, const union search_value *v)
{
    char *ss = seqset_cstring(v->seq);
    buf_appendcstr(b, ss);
    free(ss);
}

static void search_seq_free(union search_value *v)
{
    seqset_free(v->seq);
    v->seq = NULL;
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

static void search_systemflags_describe(struct buf *b, const union search_value *v)
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

static void search_indexflags_describe(struct buf *b, const union search_value *v)
{
    if ((v->u & MESSAGE_SEEN))
	buf_appendcstr(b, "\\Seen");
    if ((v->u & MESSAGE_RECENT))
	buf_appendcstr(b, "\\Recent");
}

/* ====================================================================== */

static void search_keyword_internalise(struct mailbox *mailbox,
				       const union search_value *v,
				       void **internalisedp)
{
    int r;
    int num = 0;

    if (mailbox) {
	r = mailbox_user_flag(mailbox, v->s, &num, /*create*/0);
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

static void search_uint64_describe(struct buf *b, const union search_value *v)
{
    buf_printf(b, "%llu", (unsigned long long)v->u);
}

/* ====================================================================== */

static void search_cid_describe(struct buf *b, const union search_value *v)
{
    buf_appendcstr(b, conversation_id_encode(v->u));
}

/* ====================================================================== */

static void search_folder_internalise(struct mailbox *mailbox,
				      const union search_value *v,
				      void **internalisedp)
{
    if (mailbox)
	*internalisedp = (void *)(unsigned long)(!strcmp(mailbox->name, v->s));
}

static int search_folder_match(message_t *m __attribute__((unused)),
			       const union search_value *v __attribute__((unused)),
			       void *internalised, void *data1 __attribute__((unused)))
{
    return (int)(unsigned long)internalised;
}

/* ====================================================================== */

static void search_annotation_internalise(struct mailbox *mailbox,
					  const union search_value *v __attribute__((unused)),
					  void **internalisedp)
{
    *internalisedp = mailbox;
}

struct search_annot_rock {
    int result;
    const struct buf *match;
};

static int _search_annot_match(const struct buf *match,
			       const struct buf *value)
{
    /* These cases are not explicitly defined in RFC5257 */

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

    /* RFC5257 seems to define a simple CONTAINS style search */
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

static int search_annotation_match(message_t *m, const union search_value *v,
				   void *internalised, void *data1 __attribute__((unused)))
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
			     _search_annot_callback, &rock,
			     0);
    if (r >= 0)
	r = rock.result;

out:
    strarray_fini(&entries);
    strarray_fini(&attribs);
    return r;
}

static void search_annotation_describe(struct buf *b, const union search_value *v)
{
    buf_printf(b, " entry \"%s\" attrib \"%s\" value \"%s\"",
		v->annot->entry, v->annot->attrib, buf_cstring(&v->annot->value));
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

struct convflags_rock {
    struct conversations_state *cstate;
    int cstate_is_ours;
    int num;	    /* -1=invalid, 0=\Seen, 1+=index into cstate->counted_flags+1 */
};

static void search_convflags_internalise(struct mailbox *mailbox,
					 const union search_value *v,
					 void **internalisedp)
{
    struct convflags_rock *rock;
    int r;

    if (*internalisedp) {
	rock = (struct convflags_rock *)(*internalisedp);
	if (rock->cstate_is_ours)
	    conversations_abort(&rock->cstate);
	free(rock);
    }

    if (mailbox) {
	rock = xzmalloc(sizeof(struct convflags_rock));

	rock->cstate = conversations_get_mbox(mailbox->name);
	if (!rock->cstate) {
	    r = conversations_open_mbox(mailbox->name, &rock->cstate);
	    if (r)
		rock->num = -1;	    /* invalid */
	    else
		rock->cstate_is_ours = 1;
	}

	if (rock->cstate) {
	    if (!strcasecmp(v->s, "\\Seen"))
		rock->num = 0;
	    else {
		rock->num = strarray_find_case(rock->cstate->counted_flags, v->s, 0);
		/* rock->num might be -1 invalid */
		if (rock->num >= 0)
		    rock->num++;
	    }
	}

	*internalisedp = rock;
    }
}

static int search_convflags_match(message_t *m, const union search_value *v,
				  void *internalised, void *data1 __attribute__((unused)))
{
    struct convflags_rock *rock = (struct convflags_rock *)internalised;
    conversation_id_t cid = NULLCONVERSATION;
    conversation_t *conv = NULL;
    int r;

    if (!rock->cstate) return 0;

    message_get_cid(m, &cid);
    if (conversation_load(rock->cstate, cid, &conv)) return 0;
    if (!conv) return 0;

    if (rock->num < 0)
	r = 0;	    /* invalid flag name */
    else if (rock->num == 0)
	r = !conv->unseen;
    else if (rock->num > 0)
	r = !!conv->counts[rock->num-1];

    conversation_free(conv);
    return r;
}

/* ====================================================================== */

/* TODO: share this code with the convflags above */
struct convmodseq_rock {
    struct conversations_state *cstate;
    int cstate_is_ours;
};

static void search_convmodseq_internalise(struct mailbox *mailbox,
					  const union search_value *v,
					  void **internalisedp)
{
    struct convmodseq_rock *rock;
    int r;

    if (*internalisedp) {
	rock = (struct convmodseq_rock *)(*internalisedp);
	if (rock->cstate_is_ours)
	    conversations_abort(&rock->cstate);
	free(rock);
    }

    if (mailbox) {
	rock = xzmalloc(sizeof(struct convmodseq_rock));

	rock->cstate = conversations_get_mbox(mailbox->name);
	if (!rock->cstate) {
	    r = conversations_open_mbox(mailbox->name, &rock->cstate);
	    if (r)
		rock->cstate = NULL;
	    else
		rock->cstate_is_ours = 1;
	}

	*internalisedp = rock;
    }
}

static int search_convmodseq_match(message_t *m, const union search_value *v,
				   void *internalised, void *data1 __attribute__((unused)))
{
    struct convmodseq_rock *rock = (struct convmodseq_rock *)internalised;
    conversation_id_t cid = NULLCONVERSATION;
    conversation_t *conv = NULL;
    int r;

    if (!rock->cstate) return 0;

    message_get_cid(m, &cid);
    if (conversation_load(rock->cstate, cid, &conv)) return 0;
    if (!conv) return 0;

    r = (v->u == conv->modseq);

    conversation_free(conv);
    return r;
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

static void search_uint32_describe(struct buf *b, const union search_value *v)
{
    buf_printf(b, " %u", (uint32_t)v->u);
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
};

static int searchmsg_cb(int partno, int charset, int encoding,
			const char *subtype __attribute((unused)),
			struct buf *data, void *rock)
{
    struct searchmsg_rock *sr = (struct searchmsg_rock *)rock;

    if (!partno) {
	/* header-like */
	if (sr->skipheader) {
	    sr->skipheader = 0; /* Only skip top-level message header */
	    return 0;
	}
	return charset_search_mimeheader(sr->substr, sr->pat,
					 buf_cstring(data), charset_flags);
    }
    else {
	/* body-like */
	if (charset < 0 || charset == 0xffff)
		return 0;
	return charset_searchfile(sr->substr, sr->pat,
				  data->s, data->len,
				  charset, encoding, charset_flags);
    }
}

static int search_text_match(message_t *m, const union search_value *v,
			     void *internalised, void *data1)
{
    int r;
    struct searchmsg_rock sr;

    sr.substr = v->s;
    sr.pat = (comp_pat *)internalised;
    sr.skipheader = (int)(unsigned long)data1;
    return message_foreach_text_section(m, searchmsg_cb, &sr);
}

/* ====================================================================== */

static hash_table attrs_by_name = HASH_TABLE_INITIALIZER;

EXPORTED void search_attr_init(void)
{
    unsigned int i;

    static const search_attr_t attrs[] = {
	{
	    "bcc",
	    search_string_internalise,
	    /*cmp*/NULL,
	    search_string_match,
	    search_string_describe,
	    search_string_free,
	    (void *)message_get_bcc
	},{
	    "cc",
	    search_string_internalise,
	    /*cmp*/NULL,
	    search_string_match,
	    search_string_describe,
	    search_string_free,
	    (void *)message_get_cc
	},{
	    "from",
	    search_string_internalise,
	    /*cmp*/NULL,
	    search_string_match,
	    search_string_describe,
	    search_string_free,
	    (void *)message_get_from
	},{
	    "message-id",
	    search_string_internalise,
	    /*cmp*/NULL,
	    search_string_match,
	    search_string_describe,
	    search_string_free,
	    (void *)message_get_messageid
	},{
	    "listid",
	    search_string_internalise,
	    /*cmp*/NULL,
	    search_listid_match,
	    search_string_describe,
	    search_string_free,
	    NULL
	},{
	    "contenttype",
	    search_string_internalise,
	    /*cmp*/NULL,
	    search_contenttype_match,
	    search_string_describe,
	    search_string_free,
	    NULL
	},{
	    "subject",
	    search_string_internalise,
	    /*cmp*/NULL,
	    search_string_match,
	    search_string_describe,
	    search_string_free,
	    (void *)message_get_subject
	},{
	    "to",
	    search_string_internalise,
	    /*cmp*/NULL,
	    search_string_match,
	    search_string_describe,
	    search_string_free,
	    (void *)message_get_to
	},{
	    "msgno",
	    /*internalise*/NULL,
	    /*cmp*/NULL,
	    search_seq_match,
	    search_seq_describe,
	    search_seq_free,
	    (void *)message_get_msgno
	},{
	    "uid",
	    /*internalise*/NULL,
	    /*cmp*/NULL,
	    search_seq_match,
	    search_seq_describe,
	    search_seq_free,
	    (void *)message_get_uid
	},{
	    "systemflags",
	    /*internalise*/NULL,
	    /*cmp*/NULL,
	    search_flags_match,
	    search_systemflags_describe,
	    /*free*/NULL,
	    (void *)message_get_systemflags
	},{
	    "indexflags",
	    /*internalise*/NULL,
	    /*cmp*/NULL,
	    search_flags_match,
	    search_indexflags_describe,
	    /*free*/NULL,
	    (void *)message_get_indexflags
	},{
	    "keyword",
	    search_keyword_internalise,
	    /*cmp*/NULL,
	    search_keyword_match,
	    search_string_describe,
	    search_string_free,
	    NULL
	},{
	    "convflags",
	    search_convflags_internalise,
	    /*cmp*/NULL,
	    search_convflags_match,
	    search_string_describe,
	    search_string_free,
	    NULL
	},{
	    "convmodseq",
	    search_convmodseq_internalise,
	    /*cmp*/NULL,
	    search_convmodseq_match,
	    search_uint64_describe,
	    /*free*/NULL,
	    NULL
	},{
	    "modseq",
	    /*internalise*/NULL,
	    /*cmp*/NULL,
	    search_uint64_match,
	    search_uint64_describe,
	    /*free*/NULL,
	    (void *)message_get_modseq
	},{
	    "cid",
	    /*internalise*/NULL,
	    /*cmp*/NULL,
	    search_uint64_match,
	    search_cid_describe,
	    /*free*/NULL,
	    (void *)message_get_cid
	},{
	    "folder",
	    search_folder_internalise,
	    /*cmp*/NULL,
	    search_folder_match,
	    search_string_describe,
	    search_string_free,
	    (void *)NULL
	},{
	    "annotation",
	    search_annotation_internalise,
	    /*cmp*/NULL,
	    search_annotation_match,
	    search_annotation_describe,
	    search_annotation_free,
	    (void *)NULL
	},{
	    "size",
	    /*internalise*/NULL,
	    search_uint32_cmp,
	    search_uint32_match,
	    search_uint32_describe,
	    /*free*/NULL,
	    (void *)message_get_size
	},{
	    "internaldate",
	    /*internalise*/NULL,
	    search_uint32_cmp,
	    search_uint32_match,
	    search_uint32_describe,
	    /*free*/NULL,
	    (void *)message_get_internaldate
	},{
	    "sentdate",
	    /*internalise*/NULL,
	    search_uint32_cmp,
	    search_uint32_match,
	    search_uint32_describe,
	    /*free*/NULL,
	    (void *)message_get_sentdate
	},{
	    "body",
	    search_string_internalise,
	    /*cmp*/NULL,
	    search_text_match,
	    search_string_describe,
	    search_string_free,
	    (void *)1	    /* skipheader flag */
	},{
	    "text",
	    search_string_internalise,
	    /*cmp*/NULL,
	    search_text_match,
	    search_string_describe,
	    search_string_free,
	    (void *)0	    /* skipheader flag */
	}
    };

    construct_hash_table(&attrs_by_name, VECTOR_SIZE(attrs), 0);
    for (i = 0 ; i < VECTOR_SIZE(attrs) ; i++)
	hash_insert(attrs[i].name, (void *)&attrs[i], &attrs_by_name);
}

EXPORTED const search_attr_t *search_attr_find(const char *name)
{
    char tmp[128];

    strlcpy(tmp, name, sizeof(tmp));
    lcase(tmp);
    return hash_lookup(tmp, &attrs_by_name);
}
