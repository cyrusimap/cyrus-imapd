/* tree.c -- abstract syntax tree handling
 * Larry Greenfield
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
 *
 * $Id: tree.c,v 1.15 2009/03/25 23:58:54 brong Exp $
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include "xmalloc.h"

#include "tree.h"
#include "sieve.h"

stringlist_t *new_sl(char *s, stringlist_t *n)
{
    stringlist_t *p = (stringlist_t *) xmalloc(sizeof(stringlist_t));
    p->s = s;
    p->next = n;
    return p;
}

stringlist_t *sl_reverse(stringlist_t *l)
{
    stringlist_t *prev = NULL;
    stringlist_t *next;
    stringlist_t *cur = l;
    while (cur) {
	next = cur->next;
	cur->next = prev;
	prev = cur;
	cur = next;
    }
    return prev;
}

tag_t *new_tag(int type, char *s)
{
    tag_t *p = (tag_t *) xmalloc(sizeof(tag_t));
    p->type = type;
    p->arg = s;
    return p;
}

taglist_t *new_taglist(tag_t *t, taglist_t *n)
{
    taglist_t *p = (taglist_t *) xmalloc(sizeof(taglist_t));
    p->t = t;
    p->next = n;
    return p;
}

test_t *new_test(int type) 
{
    test_t *p = (test_t *) xmalloc(sizeof(test_t));
    p->type = type;
    return p;
}

testlist_t *new_testlist(test_t *t, testlist_t *n)
{
    testlist_t *p = (testlist_t *) xmalloc(sizeof(testlist_t));
    p->t = t;
    p->next = n;
    return p;
}

commandlist_t *new_command(int type)
{
    commandlist_t *p = (commandlist_t *) xmalloc(sizeof(commandlist_t));
    p->type = type;
    p->next = NULL;
    return p;
}

commandlist_t *new_if(test_t *t, commandlist_t *y, commandlist_t *n)
{
    commandlist_t *p = (commandlist_t *) xmalloc(sizeof(commandlist_t));
    p->type = IF;
    p->u.i.t = t;
    p->u.i.do_then = y;
    p->u.i.do_else = n;
    p->next = NULL;
    return p;
}

void free_sl(stringlist_t *sl) 
{
    stringlist_t *sl2;
    
    while (sl != NULL) {
	sl2 = sl->next;

	if (sl->s) free(sl->s);

	free(sl);
	sl = sl2;
    }
}


void free_test(test_t *t);

static void free_tl(testlist_t *tl)
{
    testlist_t *tl2;

    while (tl) {
	tl2 = tl->next;

	if (tl->t) free_test(tl->t);

	free(tl);
	tl = tl2;
    }
}

void free_test(test_t *t)
{
    if (t == NULL) return;

    switch (t->type) {
    case ANYOF:
    case ALLOF:
	free_tl(t->u.tl);
	break;

    case EXISTS:
	free_sl(t->u.sl);
	break;

    case SIZE:
    case SFALSE:
    case STRUE:
	break;

    case HEADER:
	free_sl(t->u.h.sl);
	free_sl(t->u.h.pl);
	
	break;

    case ADDRESS:
	free_sl(t->u.ae.sl);
	free_sl(t->u.ae.pl);
	break;

    case BODY:
	free_sl(t->u.b.content_types);
	free_sl(t->u.b.pl);
	break;

    case NOT:
	free_test(t->u.t);
	break;
    }

    free(t);
}

void free_tree(commandlist_t *cl)
{
    commandlist_t *cl2;

    while (cl != NULL) {
	cl2 = cl->next;
	switch (cl->type) {
	case IF:
	    free_test(cl->u.i.t);
	    free_tree(cl->u.i.do_then);
	    free_tree(cl->u.i.do_else);
	    break;

	case INCLUDE:
	    if (cl->u.inc.script) free(cl->u.inc.script);
	    break;

	case FILEINTO:
	    if (cl->u.f.folder) free(cl->u.f.folder);
	    break;

	case REDIRECT:
	    if (cl->u.r.address) free(cl->u.r.address);
	    break;

	case REJCT:
	    if (cl->u.str) free(cl->u.str);
	    break;

	case VACATION:
	    if (cl->u.v.subject) free(cl->u.v.subject);
	    if (cl->u.v.addresses) free_sl(cl->u.v.addresses);
	    if (cl->u.v.message) free(cl->u.v.message);
	    break;
	    
	case SETFLAG:
	case ADDFLAG:
	case REMOVEFLAG:
	    free_sl(cl->u.sl);
	    break;

	case KEEP:
	case STOP:
	case DISCARD:
	case RETURN:
	    break;

	case NOTIFY:
	    if (cl->u.n.method) free(cl->u.n.method);
	    if (cl->u.n.id) free(cl->u.n.id);
	    if (cl->u.n.options) free_sl(cl->u.n.options);
	    if (cl->u.n.message) free(cl->u.n.message);
	    break;

	case DENOTIFY:
	    if (cl->u.d.pattern) {
#ifdef ENABLE_REGEX
		if (cl->u.d.comptag == REGEX) {
		    regfree((regex_t *) cl->u.d.pattern);
		}
#endif
		free(cl->u.d.pattern);
	    }
	    break;
	}

	free(cl);
	cl = cl2;
    }
}
