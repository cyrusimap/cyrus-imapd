/* tree.c -- abstract syntax tree handling
 * Larry Greenfield
 * $Id: tree.c,v 1.9 2002/02/19 18:09:47 ken3 Exp $
 */
/***********************************************************
        Copyright 1999 by Carnegie Mellon University

                      All Rights Reserved

Permission to use, copy, modify, and distribute this software and its
documentation for any purpose and without fee is hereby granted,
provided that the above copyright notice appear in all copies and that
both that copyright notice and this permission notice appear in
supporting documentation, and that the name of Carnegie Mellon
University not be used in advertising or publicity pertaining to
distribution of the software without specific, written prior
permission.

CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE FOR
ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
******************************************************************/

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

patternlist_t *new_pl(void *pat, patternlist_t *n)
{
    patternlist_t *p = (patternlist_t *) xmalloc(sizeof(patternlist_t));
    p->p = pat;
    p->next = n;
    return p;
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

void free_pl(patternlist_t *pl, int comptag) 
{
    patternlist_t *pl2;

    while (pl != NULL) {
	pl2 = pl->next;

	if (pl->p) {
#ifdef ENABLE_REGEX
	    if (comptag == REGEX) {
		regfree((regex_t *) pl->p);
	    }
#endif
	    free(pl->p);
	}

	free(pl);
	pl = pl2;
    }
}

void free_test(test_t *t);

void free_tl(testlist_t *tl)
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
	free_pl(t->u.h.pl, t->u.h.comptag);
	break;

    case ADDRESS:
	free_sl(t->u.ae.sl);
	free_pl(t->u.ae.pl, t->u.ae.comptag);
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

	case FILEINTO:
	case REDIRECT:
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
