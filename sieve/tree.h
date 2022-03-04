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

#include <jansson.h>

#include "comparator.h"
#include "strarray.h"
#include "arrayu64.h"

#define MAX_CMD_ARGS 12  /* bump if required (currently vacation needs 11) */

/* abstract syntax tree for sieve */
typedef struct Commandlist commandlist_t;
typedef struct Test test_t;
typedef struct Testlist testlist_t;
typedef struct Comp comp_t;
typedef struct Zone zone_t;
typedef struct CmdArg cmdarg_t;

struct CmdArg {
    unsigned char type;  /* argument data type */
    union {
        int i;
        const char *s;
        const strarray_t *sa;
        const arrayu64_t *ua;
        const comp_t *c;
        const test_t *t;
        const testlist_t *tl;
    } u;
};

enum argument_data_type {
    AT_INT      = 'i',
    AT_STR      = 's',
    AT_STRARRAY = 'S',
    AT_ARRAYU64 = 'U',
    AT_TEST     = 't',
    AT_TESTLIST = 'T'
};

struct Comp {
    int match;
    int relation;
    int collation;  /* only used where :comparator can be defined */
    int index;      /* only used where index extension is defined */
};

struct Zone {
    int tag;
    char *offset;   /* time-zone offset string (+/-hhmm) */
};

struct Test {
    unsigned type;
    int ignore_err;
    union {
        test_t *t; /* not */
        strarray_t *sl; /* exists, ihave, valid_ext_list */
        testlist_t *tl; /* anyof, allof (bytecode generation only) */
        struct { /* anyof, allof (bytecode parsing/eval only) */
            int ntests;   /* number of tests */
            int endtests; /* offset to end of tests */
        } aa;
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
            zone_t zone;
            int date_part;
            char *header_name;
            strarray_t *kl;
        } dt;
        struct { /* it's a mailbox or metadata or environment test */
            comp_t comp;
            char *extname;
            char *keyname;
            strarray_t *keylist;
        } mm;
        struct { /* it's a duplicate test */
            int idtype;
            char *idval;
            char *handle;
            int seconds;
            int last;
        } dup;
        char *jquery; /* jmapquery */
    } u;

    unsigned nargs;
    cmdarg_t args[MAX_CMD_ARGS]; /* only used for precompilation */
};

struct Testlist {
    test_t *t;
    testlist_t *next;
};

struct Fileinto {
    strarray_t *flags;
    char *folder;
    char *specialuse;
    int copy;
    int create;
    char *mailboxid;
};

struct Commandlist {
    unsigned type;
    union {
        int jump; /* bytecode parsing/eval only */
        char *str; /* it's a reject or error action */
        struct { /* it's an if statement */
            test_t *t;
            int testend; /* offset to end of test (bytecode parsing/eval only) */
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
            unsigned modifiers;
            char *variable;
            char *value;
        } s;
        struct { /* it's a keep action */
            strarray_t *flags;
        } k;
        struct Fileinto f; /* it's a fileinto action */
        struct { /* it's a flag action */
            char *variable;
            strarray_t *flags;
        } fl;
        struct { /* it's a redirect action */
            char *address;
            int copy;
            int list;
            char *bytime;
            char *bymode;
            int bytrace;
            char *dsn_notify;
            char *dsn_ret;
        } r;
        struct { /* it's a vacation action */
            char *subject;
            int seconds;
            strarray_t *addresses;
            char *message;
            char *from;
            char *handle;
            int mime;
            struct Fileinto fcc;
        } v;
        struct { /* it's an (e)notify action */
            char *method;
            char *id;
            char *from;
            strarray_t *options;
            int priority;
            char *message;
            struct Fileinto fcc;
        } n;
        struct { /* it's a denotify action */
            comp_t comp;
            char *pattern;
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
        struct { /* it's a log action */
            char *text;
        } l;
        struct { /* it's a snooze action */
            struct Fileinto f;
            int is_mboxid;  /* only used for parsing pre- 0x1D scripts */
            strarray_t *addflags;
            strarray_t *removeflags;
            unsigned char days;
            arrayu64_t *times;
            char *tzid;
        } sn;
        struct {
            int invites_only;
            int updates_only;
            int delete_canceled;
            char *calendarid;
            char *outcome_var;
            char *errstr_var;
        } imip;
    } u;
    struct Commandlist *next;

    unsigned nargs;
    cmdarg_t args[MAX_CMD_ARGS]; /* only used for compilation */
};

comp_t *canon_comptags(comp_t *c, sieve_script_t *parse_script);

test_t *new_test(int type, sieve_script_t *parse_script);
testlist_t *new_testlist(test_t *t, testlist_t *n);
commandlist_t *new_command(int type, sieve_script_t *parse_script);
commandlist_t *new_if(test_t *t, commandlist_t *y, commandlist_t *n);

void free_testlist(testlist_t *tl);
void free_test(test_t *t);
void free_tree(commandlist_t *cl);

#endif
