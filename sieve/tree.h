/* tree.h -- abstract syntax tree
 * Larry Greenfield
 * $Id: tree.h,v 1.6.4.1 2003/02/27 18:13:55 rjs3 Exp $
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

#ifndef TREE_H
#define TREE_H

#include "comparator.h"

/* abstract syntax tree for sieve */
typedef struct Stringlist stringlist_t;
typedef struct Commandlist commandlist_t;
typedef struct Test test_t;
typedef struct Testlist testlist_t;
typedef struct Tag tag_t;
typedef struct Taglist taglist_t;

struct Stringlist {
    char *s;
    stringlist_t *next;
};

 
struct Tag {
    int type;
    char *arg;
};

struct Taglist {
    tag_t *t;
    taglist_t *next;
};

struct Test {
    int type;
    union {
	testlist_t *tl; /* anyof, allof */
	stringlist_t *sl; /* exists */
	struct { /* it's a header test */
	    int comptag;
	    char * comparator;
	    int relation;
	    void *comprock;
	    stringlist_t *sl;
	    stringlist_t *pl;
	} h;
	struct { /* it's an address or envelope test */
	    int comptag;
	    int relation; 
	    char * comparator;
	    void *comprock;
	    stringlist_t *sl;
	    stringlist_t *pl;
            int addrpart;
	} ae; 
	test_t *t; /* not */
	struct { /* size */
	    int t; /* tag */
	    int n; /* param */
	} sz;
    } u;
};

struct Testlist {
    test_t *t;
    testlist_t *next;
};

struct Commandlist {
    int type;
    union {
        char *str;
	stringlist_t *sl; /* the parameters */
	struct { /* it's an if statement */
	    test_t *t;
	    commandlist_t *do_then;
	    commandlist_t *do_else;
	} i;
	struct { /* it's a vacation action */
	    char *subject;
	    int days;
	    stringlist_t *addresses;
	    char *message;
	    int mime;
	} v;
	struct { /* it's a notify action */
	    char *method;
	    char *id;
	    stringlist_t *options;
	    int priority;
	    char *message;
	} n;
	struct { /* it's a denotify action */
	    int comptag;
	    int relation;
	    void *comprock;
	    void *pattern;
	    int priority;
	} d;
    } u;
    struct Commandlist *next;
};

stringlist_t *new_sl(char *s, stringlist_t *n);
tag_t *new_tag(int type, char *s);
taglist_t *new_taglist(tag_t *t, taglist_t *n);
test_t *new_test(int type);
testlist_t *new_testlist(test_t *t, testlist_t *n);
commandlist_t *new_command(int type);
commandlist_t *new_if(test_t *t, commandlist_t *y, commandlist_t *n);

void free_sl(stringlist_t *sl);
void free_test(test_t *t);
void free_tree(commandlist_t *cl);

#endif
