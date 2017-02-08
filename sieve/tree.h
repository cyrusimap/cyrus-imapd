/* tree.h -- abstract syntax tree
 * Larry Greenfield
 *
 * Copyright (c) 1994-2017 Carnegie Mellon University.  All rights reserved.
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
typedef struct Comp comp_t;

struct Comp {
    int match;
    int relation;
    int collation;  /* only used where :comparator can be defined */
    int index;      /* only used where index extension is defined */
};

struct Test {
    int type;
    union {
        test_t *t; /* not */
        testlist_t *tl; /* anyof, allof */
        strarray_t *sl; /* exists, valid_ext_list */
        struct { /* it's a header or hasflag or string test */
            comp_t comp;
            strarray_t *sl;
            strarray_t *pl;
        } hhs;
        struct { /* it's an address or envelope test */
            comp_t comp;
            strarray_t *sl;
            strarray_t *pl;
            int addrpart;
        } ae;
        struct { /* it's a body test */
            comp_t comp;
            int transform;
            int offset;
            strarray_t *content_types;
            strarray_t *pl;
        } b;
        struct { /* size */
            int t; /* tag */
            int n; /* param */
        } sz;
        struct { /* it's a date test */
            comp_t comp;
            int zonetag;
            int zone;  /* time-zone offset in minutes */
            int date_part;
            char *header_name;
            strarray_t *kl;
        } dt;
        struct { /* it's one of the mailbox or metadata type tests */
            comp_t comp;
            char *extname;
            char *keyname;
            strarray_t *keylist;
        } mm;
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
            int mod15; /* :encodeurl */
            int mod10; /* :length */
            char *variable;
            char *value;
        } s;
        struct { /* it's a keep action */
            strarray_t *flags;
            int copy;
        } k;
        struct { /* it's a fileinto action */
            strarray_t *flags;
            char *folder;
            int copy;
            int create;
        } f;
        struct { /* it's a flag action */
            char *variable;
            strarray_t *flags;
        } fl;
        struct { /* it's a redirect action */
            char *address;
            int copy;
            int list;
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
        struct { /* it's an (e)notify action */
            char *method;
            char *id;
            char *from;
            strarray_t *options;
            int priority;
            char *message;
        } n;
        struct { /* it's a denotify action */
            comp_t comp;
            void *pattern;
            int priority;
        } d;
        struct { /* it's an addheader action */
            int index;
            char *name;
            char *value;
        } ah;
        struct { /* it's a deleteheader action */
            comp_t comp;
            char *name;
            strarray_t *values;
        } dh;
    } u;
    struct Commandlist *next;
};

comp_t *canon_comptags(comp_t *c);

test_t *new_test(int type, sieve_script_t *parse_script);
testlist_t *new_testlist(test_t *t, testlist_t *n);
commandlist_t *new_command(int type, sieve_script_t *parse_script);
commandlist_t *new_if(test_t *t, commandlist_t *y, commandlist_t *n);

void free_test(test_t *t);
void free_tree(commandlist_t *cl);

#endif
