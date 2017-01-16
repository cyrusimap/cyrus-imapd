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
 */

#ifndef TREE_H
#define TREE_H

#include "comparator.h"
#include "strarray.h"

/* abstract syntax tree for sieve */
typedef struct Commandlist commandlist_t;
typedef struct Test test_t;
typedef struct Testlist testlist_t;
typedef struct Tag tag_t;
typedef struct Taglist taglist_t;

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
        strarray_t *sl; /* exists */
        struct { /* it's a header or hasflag or string test */
            int index;
            int comptag;
            char * comparator;
            int relation;
            void *comprock;
            strarray_t *sl;
            strarray_t *pl;
        } h;
        struct { /* it's an address or envelope test */
            int index;
            int comptag;
            char * comparator;
            int relation;
            void *comprock;
            strarray_t *sl;
            strarray_t *pl;
            int addrpart;
        } ae;
        struct { /* it's a body test */
            int comptag;
            int relation;
            char * comparator;
            void *comprock;
            int transform;
            int offset;
            strarray_t *content_types;
            strarray_t *pl;
        } b;
        test_t *t; /* not */
        struct { /* size */
            int t; /* tag */
            int n; /* param */
        } sz;
        struct { /* it's a date test */
            int index;
            int zonetag;
            char *zone;
            int comptag;
            int relation;
            char *comparator;
            int date_part;
            char *header_name;
            strarray_t *kl;
        } dt;
        struct { /* it's one of the mailbox type tests */
            char *extname;
            char *keyname;
            strarray_t *keylist;
            int comptag;
            int relation;
            char *comparator;
        } mbx;
    } u;
};

struct Testlist {
    test_t *t;
    testlist_t *next;
};

struct Commandlist {
    int type;
    union {
        char *reject; /* its a reject action */
        struct { /* it's an if statement */
            test_t *t;
            commandlist_t *do_then;
            commandlist_t *do_else;
        } i;
        struct { /* it's an include action */
            int location;
            int once;
            int optional;
            char *script;
        } inc;
        struct { /* it's a set action */
            int mod40; /* :lower or :upper */
            int mod30; /* :lowerfirst or :upperfirst */
            int mod20; /* :quotewildcard */
            int mod10; /* :length */
            char *variable;
            char *value;
        } s;
        struct { /* it's a keep action */
            int copy;
            strarray_t *flags;
        } k;
        struct { /* it's a fileinto action */
            char *folder;
            int copy;
            int create;
            strarray_t *flags;
        } f;
        struct { /* it's a flag action */
            char *variable;
            strarray_t *flags;
        } fl;
        struct { /* it's a redirect action */
            char *address;
            int copy;
        } r;
        struct { /* it's a vacation action */
            char *subject;
            int seconds;
            strarray_t *addresses;
            char *message;
            char *from;
            char *handle;
            int mime;
        } v;
        struct { /* it's a notify action */
            char *method;
            char *id;
            strarray_t *options;
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
        struct { /* it's an addheader action */
            int index;
            char *name;
            char *value;
        } ah;
        struct { /* it's a deleteheader action */
            int index;
            int comptag;
            int relation;
            char *comparator;
            char *name;
            strarray_t *values;
        } dh;
    } u;
    struct Commandlist *next;
};

tag_t *new_tag(int type, char *s);
taglist_t *new_taglist(tag_t *t, taglist_t *n);
test_t *new_test(int type);
testlist_t *new_testlist(test_t *t, testlist_t *n);
commandlist_t *new_command(int type);
commandlist_t *new_if(test_t *t, commandlist_t *y, commandlist_t *n);

void free_test(test_t *t);
void free_tree(commandlist_t *cl);

#endif
