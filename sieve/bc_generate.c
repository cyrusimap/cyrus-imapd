/* bc_generate.c -- sieve bytecode- almost flattened bytecode
 * Rob Siemborski
 * Ken Murchison
 *
 * Copyright (c) 1994-2018 Carnegie Mellon University.  All rights reserved.
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "xmalloc.h"
#include "sieve_interface.h"

#include "script.h"
#include "tree.h"
#include "sieve/sieve.h"

#include "bytecode.h"

#include "assert.h"
#include <string.h>


static int bc_test_generate(int codep, bytecode_info_t *retval, test_t *t);

/* returns false if the request can't be satisfied, true if it can. */

static int atleast(bytecode_info_t *arr, size_t len)
{
    // This evil line of code exists because people aren't doing good
    // accounting everywhere.  The "atleast" mechanism is disgusting
    // and bad and wrong, but it's what we have.  So this means we don't
    // overrun the end ever.  1024 is also super way more than needed,
    // but memory is pretty cheap during the sieve script generation,
    // so I just don't care.
    len += 1024;

    if (arr->reallen < len) {
        /* too small; double if that's big enough, otherwise increase to the
           requested size. */
        arr->reallen = (len > arr->reallen * 2 ? len : arr->reallen * 2);
        arr->data = xrealloc(arr->data, arr->reallen * sizeof(bytecode_t));
        if (!arr->data) {
            /* out of memory? */
            return 0;
        }
    }

    return 1;
}

/*
 * functions of the form bc_XXX_generate have the following properties:
 * on success they return an int that corresponds to the next empty location
 * for code, and on failure they return -1.
 *
 *  they will take a  bytecode_info_t as a parameter and modify it by
 *  making it larger and adding more bytecommands in the pass 1 form
 */

/* given a location and a string list, compile it into almost-flat form.
 * <list len> <string len><string ptr><string len><string ptr> etc... */
static int bc_stringlist_generate(int codep, bytecode_info_t *retval,
                                  strarray_t *sa)
{
    int strcount = sa ? sa->count : 0;
    int i;

    /* Bounds check the string list length */
    if (!atleast(retval, codep+1)) return -1;

    retval->data[codep].type = BT_STRLISTLEN;
    retval->data[codep++].u.listlen = strcount;

    for (i = 0 ; i < strcount ; i++) {
        char *s = sa->data[i];

        assert(s != NULL);

        /* Bounds check for each string before we allocate it */
        if (!atleast(retval, codep+1)) return -1;

        retval->data[codep].type = BT_STR;
        retval->data[codep++].u.str = s;
    }

    return codep;
}


/* given a location and a value list, compile it into almost-flat form.
 * <list len> <value><value> etc... */
static int bc_vallist_generate(int codep, bytecode_info_t *retval,
                               arrayu64_t *va)
{
    int count = va ? va->count : 0;
    int i;

    /* Bounds check the string list length */
    if (!atleast(retval, codep+1)) return -1;

    retval->data[codep].type = BT_VALLISTLEN;
    retval->data[codep++].u.listlen = count;

    for (i = 0 ; i < count ; i++) {
        /* Bounds check for each string before we allocate it */
        if (!atleast(retval, codep+1)) return -1;

        retval->data[codep].type = BT_VALUE;
        retval->data[codep++].u.value = arrayu64_nth(va, i);;
    }

    return codep;
}


/* write a list of tests into almost-flat form, starting at codep.
 * returns the next code location, -1 on error. */

/* <list len> <next test ptr> <test ...> <next test ptr> <test ...> ... */
static int bc_testlist_generate(int codep, bytecode_info_t *retval,
                                testlist_t *tl)
{
    int len_codep = codep;
    int testcount = 0;
    testlist_t *cur;

    codep++;

    /* Bounds check the test list length */
    if (!atleast(retval,codep+1)) return -1;

    for (cur=tl; cur; cur = cur->next) {
        int oldcodep = codep;

        /* Make room for tail marker */
        if (!atleast(retval, codep+1)) return -1;

        testcount++;
        codep = bc_test_generate(codep+1, retval, cur->t);

        retval->data[oldcodep].type = BT_JUMP;
        retval->data[oldcodep].u.jump = codep;
    }

    retval->data[len_codep].type = BT_STRLISTLEN;
    retval->data[len_codep].u.listlen = testcount;

    return codep;
}

/* writes a single comparator into almost-flat form starting at codep.
 * will always write out 3 words
 * returns the next code location or -1 on error. */
static int bc_comparator_generate(int codep, bytecode_info_t *retval,
                                  int comptag, int relat, int collation)
{
    assert(retval != NULL);

    /* comptag */
    if (!atleast(retval, codep + 1)) return -1;
    retval->data[codep].type = BT_VALUE;
    retval->data[codep++].u.value = comptag;

    /* relation */
    if (!atleast(retval, codep + 1)) return -1;
    retval->data[codep].type = BT_VALUE;
    retval->data[codep++].u.value = relat;

    if (!collation) return codep;

    /* collation (value specified with :comparator) */
    if (!atleast(retval, codep + 1)) return -1;
    retval->data[codep].type = BT_VALUE;
    retval->data[codep++].u.value = collation;

    return codep;
}

static int bc_zone_generate(int codep, bytecode_info_t *retval,
                            int zonetag, int zone)
{
    assert(retval != NULL);

    /* zonetag */
    if (!atleast(retval, codep + 1)) return -1;

    retval->data[codep].type = BT_VALUE;
    retval->data[codep++].u.value = zonetag;
    switch (zonetag) {
    case B_TIMEZONE:
        /* time-zone offset in minutes */
        if (!atleast(retval, codep + 1)) return -1;
        retval->data[codep].type = BT_VALUE;
        retval->data[codep++].u.value = zone;
        break;
    case B_ORIGINALZONE:
        break;
    default:
        return -1;
    }

    return codep;
}




/* writes a single test into almost-flat form starting at codep.
 * returns the next code location or -1 on error. */
static int bc_test_generate(int codep, bytecode_info_t *retval, test_t *t)
{
    if (!retval) return -1;

    if (!atleast(retval, codep+1)) return -1;

    retval->data[codep].type = BT_OPCODE;
    retval->data[codep++].u.op = t->type;

    switch(t->type) {
    case BC_TRUE: /* BC_TRUE */
        break;
    case BC_FALSE:/* BC_FALSE */
        break;
    case BC_NOT: /* BC_NOT {subtest : test} */
        codep = bc_test_generate(codep, retval, t->u.t);
        if (codep == -1) return -1;
        break;
    case BC_SIZE: /* BC_SIZE (B_OVER | B_UNDER) {size : int} */
        if(!atleast(retval,codep+2)) return -1;
        retval->data[codep].type = BT_VALUE;
        retval->data[codep++].u.value = t->u.sz.t;
        retval->data[codep].type = BT_VALUE;
        retval->data[codep++].u.value = t->u.sz.n;
        break;
    case BC_EXISTS:    /* BC_EXISTS       { headers    : string list } */
    case BC_IHAVE:     /* BC_IHAVE        { extensions : string list } */
    case BC_VALIDEXTLIST: /* BC_VALIDEXTLIST { listnames  : string list } */
    case BC_VALIDNOTIFYMETHOD: /* BC_VALIDNOTIFYMETHOD { uris  : string list } */
        codep = bc_stringlist_generate(codep, retval, t->u.sl);
        break;
    case BC_ANYOF:/* BC_ANYOF { tests : test list } */
        codep=bc_testlist_generate(codep, retval, t->u.tl);
        if (codep == -1) return -1;
        break;
    case BC_ALLOF: /* BC_ALLOF { tests : test list } */
        codep= bc_testlist_generate(codep, retval, t->u.tl);
        if (codep == -1) return -1;
        break;
    case BC_HEADER:
    case BC_HASFLAG:
    case BC_STRING:
        /* BC_HEADER { i: index } { c: comparator }
         * { haystacks : string list } { patterns : string list }
         *
         * (BC_HASFLAG | BC_STRING) { c: comparator }
         * { haystacks : string list } { patterns : string list }
         */

        if (t->type == BC_HEADER) {
            /* index */
            if (!atleast(retval, codep + 1)) return -1;
            retval->data[codep].type = BT_VALUE;
            retval->data[codep++].u.value = t->u.hhs.comp.index;
        }

        /* comparator */
        codep = bc_comparator_generate(codep, retval,
                                       t->u.hhs.comp.match,
                                       t->u.hhs.comp.relation,
                                       t->u.hhs.comp.collation);
        if (codep == -1) return -1;

        /* haystacks */
        codep = bc_stringlist_generate(codep, retval, t->u.hhs.sl);
        if (codep == -1) return -1;

        /* pattern */
        codep = bc_stringlist_generate(codep, retval, t->u.hhs.pl);
        if (codep == -1) return -1;
        break;
    case BC_ADDRESS:
    case BC_ENVELOPE:
        /* BC_ADDRESS {i : index } {c : comparator}
           (B_ALL | B_LOCALPART | ...) { header : string list }
           { pattern : string list }

           BC_ENVELOPE {c : comparator}
           (B_ALL | B_LOCALPART | ...) { header : string list }
           { pattern : string list } */

        /* index */
        if (t->type == BC_ADDRESS) {
            if (!atleast(retval, codep+1)) return -1;
            retval->data[codep].type = BT_VALUE;
            retval->data[codep++].u.value = t->u.ae.comp.index;
        }

        codep = bc_comparator_generate(codep, retval,t->u.ae.comp.match,
                                       t->u.ae.comp.relation,
                                       t->u.ae.comp.collation);
        if (codep == -1) return -1;

        if (!atleast(retval, codep+1)) return -1;

        /*address part*/
        retval->data[codep].type = BT_VALUE;
        retval->data[codep++].u.value = t->u.ae.addrpart;

        /* headers */
        codep = bc_stringlist_generate(codep, retval, t->u.ae.sl);
        if (codep == -1) return -1;

        /* patterns */
        codep = bc_stringlist_generate(codep, retval, t->u.ae.pl);
        if (codep == -1) return -1;

        break;
    case BC_BODY:
        /* BC_BODY {c : comparator} (B_RAW | B_TEXT | ...)
           { offset : int }
           { content-types : stringlist }
           { pattern : string list } */

        codep = bc_comparator_generate(codep, retval,t->u.b.comp.match,
                                       t->u.b.comp.relation,
                                       t->u.b.comp.collation);
        if (codep == -1) return -1;

        if (!atleast(retval, codep+2)) return -1;

        /* transform */
        retval->data[codep].type = BT_VALUE;
        retval->data[codep++].u.value = t->u.b.transform;

        /* offset */
        retval->data[codep].type = BT_VALUE;
        retval->data[codep++].u.value = t->u.b.offset;

        /* content-types */
        codep = bc_stringlist_generate(codep, retval, t->u.b.content_types);
        if (codep == -1) return -1;

        /* patterns */
        codep = bc_stringlist_generate(codep, retval, t->u.b.pl);
        if (codep == -1) return -1;

        break;
    case BC_DATE:
    case BC_CURRENTDATE:
        /* BC_DATE { i: index } { time-zone: string} { c: comparator }
         *         { date-part: string } { header-name : string }
         *         { key-list : string list }
         *
         * BC_CURRENTDATE { time-zone: string} { c: comparator }
         *         { date-part: string } { key-list : string list }
        */

        /* index */
        if (BC_DATE == t->type) {
            if(!atleast(retval,codep + 1)) return -1;
            retval->data[codep].type = BT_VALUE;
            retval->data[codep++].u.value = t->u.dt.comp.index;
        }

        /* zone */
        codep = bc_zone_generate(codep, retval,
                                 t->u.dt.zonetag,
                                 t->u.dt.tzoffset);
        if (codep == -1) return -1;

        /* comparator */
        codep = bc_comparator_generate(codep, retval,
                                       t->u.dt.comp.match,
                                       t->u.dt.comp.relation,
                                       t->u.dt.comp.collation);
        if (codep == -1) return -1;

        /* date-part */
        if (!atleast(retval, codep + 1)) return -1;
        retval->data[codep].type = BT_VALUE;
        retval->data[codep++].u.value = t->u.dt.date_part;

        if (BC_DATE == t->type) {
            /* header-name */
            if (!atleast(retval, codep + 1)) return -1;
            retval->data[codep].type = BT_STR;
            retval->data[codep++].u.str = t->u.dt.header_name;
        }

        /* keywords */
        codep = bc_stringlist_generate(codep, retval, t->u.dt.kl);
        if (codep == -1) return -1;

        break;

    case BC_MAILBOXEXISTS:
        /* XXX ops ? */
        codep = bc_stringlist_generate(codep,retval,t->u.mm.keylist);
        if (codep == -1) return -1;

        break;

    case BC_METADATA:
    case BC_NOTIFYMETHODCAPABILITY:
        /* comparator */
        codep = bc_comparator_generate(codep, retval,
                                       t->u.mm.comp.match,
                                       t->u.mm.comp.relation,
                                       t->u.mm.comp.collation);
        if (codep == -1) return -1;

        if (!atleast(retval, codep+2)) return -1;
        retval->data[codep].type = BT_STR;
        retval->data[codep++].u.str = t->u.mm.extname;
        retval->data[codep].type = BT_STR;
        retval->data[codep++].u.str = t->u.mm.keyname;

        codep = bc_stringlist_generate(codep,retval,t->u.mm.keylist);
        if (codep == -1) return -1;

        break;

    case BC_METADATAEXISTS:
    case BC_SPECIALUSEEXISTS:
        if (!atleast(retval, codep+1)) return -1;
        retval->data[codep].type = BT_STR;
        retval->data[codep++].u.str = t->u.mm.extname;
        codep = bc_stringlist_generate(codep,retval,t->u.mm.keylist);
        if (codep == -1) return -1;

        break;

    case BC_SERVERMETADATA:
    case BC_ENVIRONMENT:
        /* comparator */
        codep = bc_comparator_generate(codep, retval,
                                       t->u.mm.comp.match,
                                       t->u.mm.comp.relation,
                                       t->u.mm.comp.collation);
        if (codep == -1) return -1;

        if (!atleast(retval, codep+1)) return -1;
        retval->data[codep].type = BT_STR;
        retval->data[codep++].u.str = t->u.mm.keyname;

        codep = bc_stringlist_generate(codep,retval,t->u.mm.keylist);
        if (codep == -1) return -1;

        break;

    case BC_SERVERMETADATAEXISTS:
        codep = bc_stringlist_generate(codep,retval,t->u.mm.keylist);
        if (codep == -1) return -1;

        break;

    case BC_DUPLICATE:
        /* BC_DUPLICATE { idtype: HEADER | UNIQUEID }
         *              { hdrname/uniqueid : string }
         *              { handle: string} { seconds: int } { last: int }
         */
        if (!atleast(retval, codep+1)) return -1;
        retval->data[codep].type = BT_VALUE;
        retval->data[codep++].u.value = t->u.dup.idtype;

        if (!atleast(retval, codep+1)) return -1;
        retval->data[codep].type = BT_STR;
        retval->data[codep++].u.str = t->u.dup.idval;

        if (!atleast(retval, codep+1)) return -1;
        retval->data[codep].type = BT_STR;
        retval->data[codep++].u.str = t->u.dup.handle;

        if (!atleast(retval, codep+2)) return -1;
        retval->data[codep].type = BT_VALUE;
        retval->data[codep++].u.value = t->u.dup.seconds;
        retval->data[codep].type = BT_VALUE;
        retval->data[codep++].u.value = t->u.dup.last;

        if (codep == -1) return -1;

        break;

    case BC_MAILBOXIDEXISTS:
        /* XXX ops ? */
        codep = bc_stringlist_generate(codep,retval,t->u.mm.keylist);
        if (codep == -1) return -1;

        break;

    case BC_JMAPQUERY:
        if (!atleast(retval, codep+1)) return -1;
        retval->data[codep].type = BT_STR;
        retval->data[codep++].u.str = t->u.jquery;

        break;

    default:
        return -1;

    }
    return codep;
}


/* generate a not-quite-flattened bytecode */
/* returns address of next instruction or -1 on error*/
/* needs current instruction, buffer for the code, and a current parse tree */
/* sieve is cool because everything is immediate! */
static int bc_action_generate(int codep, bytecode_info_t *retval,
                              commandlist_t *c)
{
    int jumploc;

    if (!retval) return -1;

    if (c == NULL) {
        if (!atleast(retval, codep+1)) return -1;
        retval->data[codep].type = BT_OPCODE;
        retval->data[codep++].u.op = B_NULL;
    }
    else {
        do {
            if (!atleast(retval, codep+1)) return -1;
            retval->data[codep].type = BT_OPCODE;
            retval->data[codep++].u.op = c->type;

            switch(c->type) {
            case B_STOP:
                /* STOP (no arguments) */
                break;

            case B_DISCARD:
                /* DISCARD (no arguments) */
                break;

            case B_KEEP:
                /* KEEP
                   STRINGLIST flags
                */
                codep = bc_stringlist_generate(codep,retval,c->u.k.flags);
                if (codep == -1) return -1;
                break;

            case B_MARK:
                /* MARK (no arguments) */
                break;

            case B_UNMARK:
                /* UNMARK (no arguments) */
                break;

            case B_RETURN:
                /* RETURN (no arguments) */
                break;

            case B_DENOTIFY:
                /* DENOTIFY  */
                if (!atleast(retval, codep+1)) return -1;
                retval->data[codep].type = BT_VALUE;
                retval->data[codep++].u.value = c->u.d.priority;

                /* comparator */
                codep = bc_comparator_generate(codep, retval,
                                               c->u.d.comp.match,
                                               c->u.d.comp.relation,
                                               0);
                if (codep == -1) return -1;

                if (!atleast(retval, codep+1)) return -1;
                retval->data[codep].type = BT_STR;
                retval->data[codep++].u.str = c->u.d.pattern;

                break;

            case B_REJECT:
            case B_EREJECT:
            case B_ERROR:
                /* (REJECT | EREJECT | ERROR) (STRING: len + dataptr) */
                if (!atleast(retval, codep+1)) return -1;
                retval->data[codep].type = BT_STR;
                retval->data[codep++].u.str = c->u.str;
                break;

            case B_FILEINTO:
                /* FILEINTO
                   STRING mailboxid
                   STRING specialuse
                   VALUE create
                   STRINGLIST flags
                   VALUE copy
                   STRING folder
                */
                if (!atleast(retval, codep+2)) return -1;
                retval->data[codep].type = BT_STR;
                retval->data[codep++].u.str = c->u.f.mailboxid;
                retval->data[codep].type = BT_STR;
                retval->data[codep++].u.str = c->u.f.specialuse;
                if (!atleast(retval, codep+1)) return -1;
                retval->data[codep].type = BT_VALUE;
                retval->data[codep++].u.value = c->u.f.create;
                codep = bc_stringlist_generate(codep, retval, c->u.f.flags);
                if (codep == -1) return -1;
                if (!atleast(retval, codep+1)) return -1;
                retval->data[codep].type = BT_VALUE;
                retval->data[codep++].u.value = c->u.f.copy;
                retval->data[codep].type = BT_STR;
                retval->data[codep++].u.str = c->u.f.folder;
                break;

            case B_REDIRECT:
                /* REDIRECT
                   STRING bytime
                   STRING bymode
                   VALUE bytrace
                   STRING dsn_notify
                   STRING dsn_ret
                   VALUE list
                   VALUE copy
                   STRING address
                */
                if (!atleast(retval, codep+8)) return -1;
                retval->data[codep].type = BT_STR;
                retval->data[codep++].u.str = c->u.r.bytime;
                retval->data[codep].type = BT_STR;
                retval->data[codep++].u.str = c->u.r.bymode;
                retval->data[codep].type = BT_VALUE;
                retval->data[codep++].u.value = c->u.r.bytrace;
                retval->data[codep].type = BT_STR;
                retval->data[codep++].u.str = c->u.r.dsn_notify;
                retval->data[codep].type = BT_STR;
                retval->data[codep++].u.str = c->u.r.dsn_ret;
                retval->data[codep].type = BT_VALUE;
                retval->data[codep++].u.value = c->u.r.list;
                retval->data[codep].type = BT_VALUE;
                retval->data[codep++].u.value = c->u.r.copy;
                retval->data[codep].type = BT_STR;
                retval->data[codep++].u.str = c->u.r.address;
                break;

            case B_ADDFLAG:
            case B_SETFLAG:
            case B_REMOVEFLAG:
                /* (ADDFLAG | SETFLAG | REMOVEFLAG) string stringlist */
                if (!atleast(retval, codep+1)) return -1;
                retval->data[codep].type = BT_STR;
                retval->data[codep++].u.str = c->u.fl.variable;
                codep = bc_stringlist_generate(codep,retval,c->u.fl.flags);
                if (codep == -1) return -1;
                break;

            case B_NOTIFY:
            case B_ENOTIFY:
            {
                /* (E)NOTIFY
                   (STRING: len + dataptr)
                   (STRING: len + dataptr)
                   stringlist
                   (VALUE)
                   (STRING: len + dataptr)
                   method/(from|id) /options list/priority/message
                */
                char *str;

                if (c->type == ENOTIFY) {
                    str = c->u.n.from;
                }
                else {
                    str = c->u.n.id;
                }

                if (!atleast(retval, codep+2)) return -1;
                retval->data[codep].type = BT_STR;
                retval->data[codep++].u.str = c->u.n.method;

                retval->data[codep].type = BT_STR;
                retval->data[codep++].u.str = str;

                codep = bc_stringlist_generate(codep,retval,c->u.n.options);
                if (codep == -1) return -1;

                if (!atleast(retval, codep+2)) return -1;

                retval->data[codep].type = BT_VALUE;
                retval->data[codep++].u.value = c->u.n.priority;

                retval->data[codep].type = BT_STR;
                retval->data[codep++].u.str = c->u.n.message;
            }
            break;

            case B_VACATION:
                /* VACATION
                   STRINGLIST addresses
                   STRING subject (if len is -1, then subject was NULL)
                   STRING message (again, len == -1 means message was NULL)
                   VALUE seconds
                   VALUE mime
                   STRING from (if len is -1, then from was NULL)
                   STRING handle (again, len == -1 means handle was NULL)
                   STRING fcc (again, len == -1 means fcc was NULL)
                      VALUE create (if and only if fcc != NULL)
                      STRINGLIST flags (if and only if fcc != NULL)
                      STRING specialuse (if and only if fcc != NULL)
                */

                codep = bc_stringlist_generate(codep,retval,c->u.v.addresses);
                if (codep == -1) return -1;

                if (!atleast(retval, codep+1)) return -1;
                retval->data[codep].type = BT_STR;
                retval->data[codep++].u.str = c->u.v.subject;

                if (!atleast(retval, codep+1)) return -1;
                retval->data[codep].type = BT_STR;
                retval->data[codep++].u.str = c->u.v.message;

                if (!atleast(retval, codep+2)) return -1;
                retval->data[codep].type = BT_VALUE;
                retval->data[codep++].u.value = c->u.v.seconds;
                retval->data[codep].type = BT_VALUE;
                retval->data[codep++].u.value = c->u.v.mime;

                if (!atleast(retval, codep+1)) return -1;
                retval->data[codep].type = BT_STR;
                retval->data[codep++].u.str = c->u.v.from;

                if (!atleast(retval, codep+1)) return -1;
                retval->data[codep].type = BT_STR;
                retval->data[codep++].u.str = c->u.v.handle;

                if (!atleast(retval, codep+1)) return -1;
                retval->data[codep].type = BT_STR;
                retval->data[codep++].u.str = c->u.v.fcc.folder;
                if (c->u.v.fcc.folder) {
                    if (!atleast(retval, codep+1)) return -1;
                    retval->data[codep].type = BT_VALUE;
                    retval->data[codep++].u.value = c->u.v.fcc.create;

                    codep = bc_stringlist_generate(codep, retval,
                                                   c->u.v.fcc.flags);
                    if (codep == -1) return -1;

                    if (!atleast(retval, codep+1)) return -1;
                    retval->data[codep].type = BT_STR;
                    retval->data[codep++].u.str = c->u.v.fcc.specialuse;
                }

                if (codep == -1) return -1;
                break;

            case B_INCLUDE:
                /* INCLUDE
                   VALUE location + (once << 6) + (optional << 7)
                   STRING filename */

                if (!atleast(retval, codep+3)) return -1;
                retval->data[codep].type = BT_VALUE;
                retval->data[codep].u.value = c->u.inc.location;

                retval->data[codep].type = BT_VALUE;
                retval->data[codep++].u.value |=
                    (c->u.inc.once << 6) | (c->u.inc.optional << 7);
                retval->data[codep].type = BT_STR;
                retval->data[codep++].u.str = c->u.inc.script;
                break;

            case B_SET:
                /* SET
                   BITFIELD modifiers
                   STRING variable
                   STRING value
                */
                if (!atleast(retval, codep+3)) return -1;
                retval->data[codep].type = BT_VALUE;
                retval->data[codep++].u.value = c->u.s.modifiers;
                retval->data[codep].type = BT_STR;
                retval->data[codep++].u.str = c->u.s.variable;
                retval->data[codep].type = BT_STR;
                retval->data[codep++].u.str = c->u.s.value;
                break;

            case B_ADDHEADER:
                /* ADDHEADER
                   NUMBER index
                   STRING name
                   STRING value
                */
                if (!atleast(retval, codep+3)) return -1;
                retval->data[codep].type = BT_VALUE;
                retval->data[codep++].u.value = c->u.ah.index;
                retval->data[codep].type = BT_STR;
                retval->data[codep++].u.str = c->u.ah.name;
                retval->data[codep].type = BT_STR;
                retval->data[codep++].u.str = c->u.ah.value;
                break;

            case B_DELETEHEADER:
                /* DELETEHEADER
                   NUMBER index
                   COMPARATOR
                   STRING name
                   STRINGLIST value-patterns
                */
                if (!atleast(retval, codep+1)) return -1;
                retval->data[codep].type = BT_VALUE;
                retval->data[codep++].u.value = c->u.dh.comp.index;

                codep = bc_comparator_generate(codep, retval,
                                               c->u.dh.comp.match,
                                               c->u.dh.comp.relation,
                                               c->u.dh.comp.collation);
                if (codep == -1) return -1;

                if (!atleast(retval, codep+1)) return -1;
                retval->data[codep].type = BT_STR;
                retval->data[codep++].u.str = c->u.dh.name;

                codep = bc_stringlist_generate(codep, retval, c->u.dh.values);
                if (codep == -1) return -1;
                break;

            case B_LOG:
                /* LOG
                   STRING text
                */
                if (!atleast(retval, codep+1)) return -1;
                retval->data[codep].type = BT_STR;
                retval->data[codep++].u.str = c->u.l.text;
                break;

            case B_SNOOZE:
                /* SNOOZE
                   STRING mailbox / mailboxid
                   STRINGLIST addflags
                   STRINGLIST removeflags
                   VALUE weekdays + (is_mboxid << 7)
                   VALUELIST times
                */
                if (!atleast(retval, codep+1)) return -1;
                retval->data[codep].type = BT_STR;
                retval->data[codep++].u.str = c->u.sn.mailbox;
                codep = bc_stringlist_generate(codep, retval, c->u.sn.addflags);
                if (codep == -1) return -1;
                codep = bc_stringlist_generate(codep, retval, c->u.sn.removeflags);
                if (codep == -1) return -1;
                retval->data[codep].type = BT_VALUE;
                if (c->u.sn.is_mboxid) {
                    retval->data[codep++].u.value =
                        c->u.sn.days | SNOOZE_IS_ID_MASK;
                }
                else {
                    retval->data[codep++].u.value =
                        c->u.sn.days & ~SNOOZE_IS_ID_MASK;
                }
                codep = bc_vallist_generate(codep, retval, c->u.sn.times);
                if (codep == -1) return -1;
                break;

            case B_IF:
            {
                int jumpVal;
                /* IF
                   (int: begin then block)
                   (int: end then block/begin else block)
                   (int: end else block) (-1 if no else block)
                   (test)
                   (then block)
                   (else block)(optional)
                */

                /* Allocate jump table offsets */
                if (!atleast(retval, codep+3)) return -1;
                jumploc = codep+3;

                /* beginning of then  code */
                jumpVal = bc_test_generate(jumploc,retval,c->u.i.t);
                if (jumpVal == -1)
                    return -1;
                else {
                    retval->data[codep].type = BT_JUMP;
                    retval->data[codep].u.jump = jumpVal;
                    codep++;
                }

                /* find then code and offset to else code,
                 * we want to write this code starting at the offset we
                 * just found */

                jumpVal = bc_action_generate(jumpVal,retval, c->u.i.do_then);
                if (jumpVal == -1)
                    return -1;
                else {
                    retval->data[codep].type = BT_JUMP;
                    retval->data[codep].u.jump = jumpVal;
                }

                codep++;
                /* write else code if its there*/
                if (c->u.i.do_else) {
                    jumpVal = bc_action_generate(jumpVal,retval, c->u.i.do_else);
                    if (jumpVal == -1) return -1;
                    else {
                        retval->data[codep].type = BT_JUMP;
                        retval->data[codep].u.jump = jumpVal;
                    }

                    /* Update code pointer to end of else code */
                    codep = retval->data[codep].u.jump;
                } else {
                    /*there is no else block, so its -1*/
                    retval->data[codep].u.jump = -1;
                    /* Update code pointer to end of then code */
                    codep = retval->data[codep-1].u.jump;
                }

            }
            break;

            default:
                /* no such action known */
                return -1;
            }

            /* generate from next command */
            c = c->next;
        } while(c);
    }

    /* scriptend may be updated before the end, but it will be
     * updated at the end, which is what matters. */
    retval->scriptend = codep;

    return codep;
}



/* Entry point to the bytecode emitter module */
EXPORTED int sieve_generate_bytecode(bytecode_info_t **retval, sieve_script_t *s)
{
    commandlist_t *c;
    int requires = 0;
    int codep = 0;

    if (!retval) return -1;
    if (!s) return -1;
    c = s->cmds;
    /* if c is NULL, it is handled in bc_action_generate and a script
       with only BC_NULL is returned
    */

    /* populate requires field */
    if (s->support & SIEVE_CAPA_VARIABLES) {
	requires |= BFE_VARIABLES;
    }
    
    *retval = xmalloc(sizeof(bytecode_info_t));
    if (!(*retval)) return -1;

    memset(*retval, 0, sizeof(bytecode_info_t));

    if (!atleast(*retval, codep+1)) return -1;
    (*retval)->data[codep].type = BT_VALUE;
    (*retval)->data[codep++].u.value = requires;

    return bc_action_generate(codep, *retval, c);
}


EXPORTED void sieve_free_bytecode(bytecode_info_t **p)
{
    if (!p || !*p) return;
    if ((*p)->data) free((*p)->data);
    free(*p);
    *p = NULL;
}
