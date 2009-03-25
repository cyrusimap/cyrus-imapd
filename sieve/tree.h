/* tree.h -- abstract syntax tree
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
 * $Id: tree.h,v 1.12 2009/03/25 23:58:54 brong Exp $
 */

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
	    char * comparator;
	    int relation; 
	    void *comprock;
	    stringlist_t *sl;
	    stringlist_t *pl;
            int addrpart;
	} ae; 
	struct { /* it's a body test */
	    int comptag;
	    int relation; 
	    char * comparator;
	    void *comprock;
	    int transform;
	    int offset;
	    stringlist_t *content_types;
	    stringlist_t *pl;
	} b; 
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
	struct { /* it's an include action */
	    int location;
	    char *script;
	} inc;
	struct { /* it's a fileinto action */
	    char *folder;
	    int copy;
	    /* add stringlist_t for imap4flags */
	} f;
	struct { /* it's a redirect action */
	    char *address;
	    int copy;
	} r;
	struct { /* it's a vacation action */
	    char *subject;
	    int days;
	    stringlist_t *addresses;
	    char *message;
	    char *from;
	    char *handle;
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
stringlist_t *sl_reverse(stringlist_t *l);
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
