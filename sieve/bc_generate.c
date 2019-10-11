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

    retval->data[codep].type = BT_LISTLEN;
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

    retval->data[len_codep].type = BT_LISTLEN;
    retval->data[len_codep].u.listlen = testcount;

    return codep;
}

/* output a relation into almost-flat form at codep.
 * returns new codep on success, -1 on failure. */
static int bc_relation_generate(int codep, bytecode_info_t *retval, int relat)
{
    if (!atleast(retval, codep + 1)) return -1;

    retval->data[codep].type = BT_VALUE;
    switch (relat) {
    case GT:
        retval->data[codep++].u.value = B_GT;
        break;
    case GE:
        retval->data[codep++].u.value = B_GE;
        break;
    case LT:
        retval->data[codep++].u.value = B_LT;
        break;
    case LE:
        retval->data[codep++].u.value = B_LE;
        break;
    case EQ:
        retval->data[codep++].u.value = B_EQ;
        break;
    case NE:
        retval->data[codep++].u.value = B_NE;
        break;
    default:
        /* comparator has no relational field */
        retval->data[codep++].u.value = -1;
        break;
    }
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
    switch (comptag) {
    case IS:
        retval->data[codep++].u.value = B_IS;
        break;
    case CONTAINS:
        retval->data[codep++].u.value = B_CONTAINS;
        break;
    case MATCHES:
        retval->data[codep++].u.value = B_MATCHES;
        break;
#ifdef ENABLE_REGEX
    case REGEX:
        retval->data[codep++].u.value = B_REGEX;
        break;
#endif
    case LIST:
        retval->data[codep++].u.value = B_LIST;
        break;
    case COUNT:
        retval->data[codep++].u.value = B_COUNT;
        break;
    case VALUE:
        retval->data[codep++].u.value = B_VALUE;
        break;

    default:
        return -1;
    }

    /* relation */
    codep = bc_relation_generate(codep, retval, relat);

    if (!collation) return codep;

    /* collation (value specified with :comparator) */
    if (!atleast(retval, codep + 1)) return -1;

    retval->data[codep].type = BT_VALUE;
    switch (collation) {
    case OCTET:
        retval->data[codep++].u.value = B_OCTET;
        break;
    case ASCIICASEMAP:
        retval->data[codep++].u.value = B_ASCIICASEMAP;
        break;
    case ASCIINUMERIC:
        retval->data[codep++].u.value = B_ASCIINUMERIC;
        break;

    default:
        return -1;
    }

    return codep;
}

static int bc_zone_generate(int codep, bytecode_info_t *retval,
                            int zonetag, int zone)
{
    assert(retval != NULL);

    /* zonetag */
    if (!atleast(retval, codep + 1)) return -1;

    retval->data[codep].type = BT_VALUE;
    switch (zonetag) {
    case ZONE:
        /* time-zone offset in minutes */
        retval->data[codep++].u.value = B_TIMEZONE;
        if (!atleast(retval, codep + 1)) return -1;
        retval->data[codep].type = BT_VALUE;
        retval->data[codep++].u.value = zone;
        break;
    case ORIGINALZONE:
        retval->data[codep++].u.value = B_ORIGINALZONE;
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
    switch(t->type) {
    case STRUE: /* BC_TRUE */
        retval->data[codep++].u.op = BC_TRUE;
        break;
    case SFALSE:/* BC_FALSE */
        retval->data[codep++].u.op = BC_FALSE;
        break;
    case NOT: /* BC_NOT {subtest : test} */
        retval->data[codep++].u.op = BC_NOT;
        codep = bc_test_generate(codep, retval, t->u.t);
        if (codep == -1) return -1;
        break;
    case SIZE: /* BC_SIZE (B_OVER | B_UNDER) {size : int} */
        retval->data[codep++].u.op = BC_SIZE;
        if(!atleast(retval,codep+2)) return -1;
        retval->data[codep].type = BT_VALUE;
        retval->data[codep++].u.value =
            (t->u.sz.t == OVER ? B_OVER : B_UNDER);
        retval->data[codep].type = BT_VALUE;
        retval->data[codep++].u.value = t->u.sz.n;
        break;
    case EXISTS:       /* BC_EXISTS       { headers    : string list } */
    case IHAVE:        /* BC_IHAVE        { extensions : string list } */
    case VALIDEXTLIST: /* BC_VALIDEXTLIST { listnames  : string list } */
    case VALIDNOTIFYMETHOD: /* BC_VALIDNOTIFYMETHOD { uris  : string list } */
        switch (t->type) {
        case EXISTS:       retval->data[codep++].u.op = BC_EXISTS; break;
        case IHAVE:        retval->data[codep++].u.op = BC_IHAVE; break;
        case VALIDEXTLIST: retval->data[codep++].u.op = BC_VALIDEXTLIST; break;
        case VALIDNOTIFYMETHOD:
            retval->data[codep++].u.op = BC_VALIDNOTIFYMETHOD; break;
        }
        codep = bc_stringlist_generate(codep, retval, t->u.sl);
        break;
    case ANYOF:/* BC_ANYOF { tests : test list } */
        retval->data[codep++].u.op = BC_ANYOF;
        codep=bc_testlist_generate(codep, retval, t->u.tl);
        if (codep == -1) return -1;
        break;
    case ALLOF: /* BC_ALLOF { tests : test list } */
        retval->data[codep++].u.op = BC_ALLOF;
        codep= bc_testlist_generate(codep, retval, t->u.tl);
        if (codep == -1) return -1;
        break;
    case HEADERT:
    case HASFLAG:
    case STRINGT:
        /* BC_HEADER { i: index } { c: comparator }
         * { haystacks : string list } { patterns : string list }
         *
         * (BC_HASFLAG | BC_STRING) { c: comparator }
         * { haystacks : string list } { patterns : string list }
         */

        switch (t->type) {
        case HEADERT:
            retval->data[codep++].u.op = BC_HEADER;
            break;
        case HASFLAG:
            retval->data[codep++].u.op = BC_HASFLAG;
            break;
        case STRINGT:
            retval->data[codep++].u.op = BC_STRING;
            break;
        }

        if (t->type == HEADERT) {
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
    case ADDRESS:
    case ENVELOPE:
        /* BC_ADDRESS {i : index } {c : comparator}
           (B_ALL | B_LOCALPART | ...) { header : string list }
           { pattern : string list }

           BC_ENVELOPE {c : comparator}
           (B_ALL | B_LOCALPART | ...) { header : string list }
           { pattern : string list } */

        retval->data[codep++].u.op =
            (t->type == ADDRESS) ? BC_ADDRESS : BC_ENVELOPE;

        /* index */
        if (t->type == ADDRESS) {
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
        switch(t->u.ae.addrpart) {
        case ALL:
            retval->data[codep++].u.value = B_ALL;
            break;
        case LOCALPART:
            retval->data[codep++].u.value = B_LOCALPART;
            break;
        case DOMAIN:
            retval->data[codep++].u.value = B_DOMAIN;
            break;
        case USER:
            retval->data[codep++].u.value = B_USER;
            break;
        case DETAIL:
            retval->data[codep++].u.value = B_DETAIL;
            break;
        default:
            return -1;
        }

        /* headers */
        codep = bc_stringlist_generate(codep, retval, t->u.ae.sl);
        if (codep == -1) return -1;

        /* patterns */
        codep = bc_stringlist_generate(codep, retval, t->u.ae.pl);
        if (codep == -1) return -1;

        break;
    case BODY:
        /* BC_BODY {c : comparator} (B_RAW | B_TEXT | ...)
           { offset : int }
           { content-types : stringlist }
           { pattern : string list } */

        retval->data[codep++].u.op = BC_BODY;

        codep = bc_comparator_generate(codep, retval,t->u.b.comp.match,
                                       t->u.b.comp.relation,
                                       t->u.b.comp.collation);
        if (codep == -1) return -1;

        if (!atleast(retval, codep+2)) return -1;

        /* transform */
        retval->data[codep].type = BT_VALUE;
        switch(t->u.b.transform) {
        case RAW:
            retval->data[codep++].u.value = B_RAW;
            break;
        case TEXT:
            retval->data[codep++].u.value = B_TEXT;
            break;
        case CONTENT:
            retval->data[codep++].u.value = B_CONTENT;
            break;
        default:
            return -1;
        }

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
    case DATE:
    case CURRENTDATE:
        /* BC_DATE { i: index } { time-zone: string} { c: comparator }
         *         { date-part: string } { header-name : string }
         *         { key-list : string list }
         *
         * BC_CURRENTDATE { time-zone: string} { c: comparator }
         *         { date-part: string } { key-list : string list }
        */

        retval->data[codep++].u.op =
            (DATE == t->type) ? BC_DATE : BC_CURRENTDATE;

        /* index */
        if (DATE == t->type) {
            if(!atleast(retval,codep + 1)) return -1;
            retval->data[codep].type = BT_VALUE;
            retval->data[codep++].u.value = t->u.dt.comp.index;
        }

        /* zone */
        codep = bc_zone_generate(codep, retval,
                                 t->u.dt.zonetag,
                                 t->u.dt.zone);
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
        switch (t->u.dt.date_part) {
        case YEARP:
                retval->data[codep++].u.value = B_YEAR;
                break;
        case MONTHP:
                retval->data[codep++].u.value = B_MONTH;
                break;
        case DAYP:
                retval->data[codep++].u.value = B_DAY;
                break;
        case DATEP:
                retval->data[codep++].u.value = B_DATE;
                break;
        case JULIAN:
                retval->data[codep++].u.value = B_JULIAN;
                break;
        case HOURP:
                retval->data[codep++].u.value = B_HOUR;
                break;
        case MINUTEP:
                retval->data[codep++].u.value = B_MINUTE;
                break;
        case SECONDP:
                retval->data[codep++].u.value = B_SECOND;
                break;
        case TIMEP:
                retval->data[codep++].u.value = B_TIME;
                break;
        case ISO8601:
                retval->data[codep++].u.value = B_ISO8601;
                break;
        case STD11:
                retval->data[codep++].u.value = B_STD11;
                break;
        case ZONEP:
                retval->data[codep++].u.value = B_ZONE;
                break;
        case WEEKDAYP:
                retval->data[codep++].u.value = B_WEEKDAY;
                break;
        }

        if (DATE == t->type) {
            /* header-name */
            if (!atleast(retval, codep + 1)) return -1;
            retval->data[codep].type = BT_STR;
            retval->data[codep++].u.str = t->u.dt.header_name;
        }

        /* keywords */
        codep = bc_stringlist_generate(codep, retval, t->u.dt.kl);
        if (codep == -1) return -1;

        break;

    case MAILBOXEXISTS:
        retval->data[codep++].u.op = BC_MAILBOXEXISTS;
        /* XXX ops ? */
        codep = bc_stringlist_generate(codep,retval,t->u.mm.keylist);
        if (codep == -1) return -1;

        break;

    case METADATA:
    case NOTIFYMETHODCAPABILITY:
        retval->data[codep++].u.op =
            t->type == METADATA ? BC_METADATA : BC_NOTIFYMETHODCAPABILITY;

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

    case METADATAEXISTS:
    case SPECIALUSEEXISTS:
        retval->data[codep++].u.op =
            t->type == METADATAEXISTS ? BC_METADATAEXISTS : BC_SPECIALUSEEXISTS;
        if (!atleast(retval, codep+1)) return -1;
        retval->data[codep].type = BT_STR;
        retval->data[codep++].u.str = t->u.mm.extname;
        codep = bc_stringlist_generate(codep,retval,t->u.mm.keylist);
        if (codep == -1) return -1;

        break;

    case SERVERMETADATA:
    case ENVIRONMENT:
        retval->data[codep++].u.op =
            t->type == ENVIRONMENT ? BC_ENVIRONMENT : BC_SERVERMETADATA;

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

    case SERVERMETADATAEXISTS:
        retval->data[codep++].u.op = BC_SERVERMETADATAEXISTS;
        codep = bc_stringlist_generate(codep,retval,t->u.mm.keylist);
        if (codep == -1) return -1;

        break;

    case DUPLICATE:
        /* BC_DUPLICATE { idtype: HEADER | UNIQUEID }
         *              { hdrname/uniqueid : string }
         *              { handle: string} { seconds: int } { last: int }
         */
        retval->data[codep++].u.op = BC_DUPLICATE;

        if (!atleast(retval, codep+1)) return -1;
        retval->data[codep].type = BT_VALUE;
        retval->data[codep++].u.value =
            (t->u.dup.idtype == UNIQUEID) ? B_UNIQUEID : B_HEADER;

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

    case MAILBOXIDEXISTS:
        retval->data[codep++].u.op = BC_MAILBOXIDEXISTS;
        /* XXX ops ? */
        codep = bc_stringlist_generate(codep,retval,t->u.mm.keylist);
        if (codep == -1) return -1;

        break;

    case JMAPQUERY:
        retval->data[codep++].u.op = BC_JMAPQUERY;
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

            switch(c->type) {
            case STOP:
                /* STOP (no arguments) */
                retval->data[codep++].u.op = B_STOP;
                break;

            case DISCARD:
                /* DISCARD (no arguments) */
                retval->data[codep++].u.op = B_DISCARD;
                break;

            case KEEP:
                /* KEEP
                   STRINGLIST flags
                */
                retval->data[codep++].u.op = B_KEEP;
                codep = bc_stringlist_generate(codep,retval,c->u.k.flags);
                if (codep == -1) return -1;
                break;

            case MARK:
                /* MARK (no arguments) */
                retval->data[codep++].u.op = B_MARK;
                break;

            case UNMARK:
                /* UNMARK (no arguments) */
                retval->data[codep++].u.op = B_UNMARK;
                break;

            case RETURN:
                /* RETURN (no arguments) */
                retval->data[codep++].u.op = B_RETURN;
                break;

            case DENOTIFY:
                /* DENOTIFY  */
                retval->data[codep++].u.op = B_DENOTIFY;
                if (!atleast(retval, codep+1)) return -1;
                retval->data[codep].type = BT_VALUE;
                switch(c->u.d.priority) {
                case LOW:
                    retval->data[codep++].u.value = B_LOW;
                    break;
                case NORMAL:
                    retval->data[codep++].u.value = B_NORMAL;
                    break;
                case HIGH:
                    retval->data[codep++].u.value = B_HIGH;
                    break;
                case ANY:
                    retval->data[codep++].u.value = B_ANY;
                    break;
                default:
                    return -1;
                }

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

            case REJCT:
            case EREJECT:
            case ERROR:
                /* (REJECT | EREJECT | ERROR) (STRING: len + dataptr) */
                switch (c->type) {
                case REJCT:   retval->data[codep++].u.op = B_REJECT; break;
                case EREJECT: retval->data[codep++].u.op = B_EREJECT; break;
                case ERROR:   retval->data[codep++].u.op = B_ERROR; break;
                }
                if (!atleast(retval, codep+1)) return -1;
                retval->data[codep].type = BT_STR;
                retval->data[codep++].u.str = c->u.str;
                break;

            case FILEINTO:
                /* FILEINTO
                   STRING mailboxid
                   STRING specialuse
                   VALUE create
                   STRINGLIST flags
                   VALUE copy
                   STRING folder
                */
                retval->data[codep++].u.op = B_FILEINTO;
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

            case REDIRECT:
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
                retval->data[codep++].u.op = B_REDIRECT;
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

            case ADDFLAG:
            case SETFLAG:
            case REMOVEFLAG:
                /* (ADDFLAG | SETFLAG | REMOVEFLAG) string stringlist */
                switch(c->type) {
                case ADDFLAG:
                    retval->data[codep++].u.op = B_ADDFLAG;
                    break;
                case SETFLAG:
                    retval->data[codep++].u.op = B_SETFLAG;
                    break;
                case REMOVEFLAG:
                    retval->data[codep++].u.op = B_REMOVEFLAG;
                    break;
                }
                if (!atleast(retval, codep+1)) return -1;
                retval->data[codep].type = BT_STR;
                retval->data[codep++].u.str = c->u.fl.variable;
                codep = bc_stringlist_generate(codep,retval,c->u.fl.flags);
                if (codep == -1) return -1;
                break;

            case NOTIFY:
            case ENOTIFY:
            {
                /* (E)NOTIFY
                   (STRING: len + dataptr)
                   (STRING: len + dataptr)
                   stringlist
                   (VALUE)
                   (STRING: len + dataptr)
                   method/(from|id) /options list/priority/message
                */
                int op;
                char *str;

                if (c->type == ENOTIFY) {
                    op = B_ENOTIFY;
                    str = c->u.n.from;
                }
                else {
                    op = B_NOTIFY;
                    str = c->u.n.id;
                }

                retval->data[codep++].u.op = op;

                if (!atleast(retval, codep+2)) return -1;
                retval->data[codep].type = BT_STR;
                retval->data[codep++].u.str = c->u.n.method;

                retval->data[codep].type = BT_STR;
                retval->data[codep++].u.str = str;

                codep = bc_stringlist_generate(codep,retval,c->u.n.options);
                if (codep == -1) return -1;

                if (!atleast(retval, codep+2)) return -1;

                retval->data[codep].type = BT_VALUE;
                switch(c->u.n.priority) {
                case LOW:
                    retval->data[codep++].u.value = B_LOW;
                    break;
                case NORMAL:
                    retval->data[codep++].u.value = B_NORMAL;
                    break;
                case HIGH:
                    retval->data[codep++].u.value = B_HIGH;
                    break;
                case ANY:
                    retval->data[codep++].u.value = B_ANY;
                    break;
                default:
                    return -1;
                }

                retval->data[codep].type = BT_STR;
                retval->data[codep++].u.str = c->u.n.message;
            }
            break;

            case VACATION:
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

                retval->data[codep++].u.op = B_VACATION;

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

            case INCLUDE:
                /* INCLUDE
                   VALUE location + (once << 6) + (optional << 7)
                   STRING filename */
                retval->data[codep++].u.op = B_INCLUDE;

                if (!atleast(retval, codep+3)) return -1;
                retval->data[codep].type = BT_VALUE;
                switch(c->u.inc.location) {
                case PERSONAL:
                    retval->data[codep].u.value = B_PERSONAL;
                    break;
                case GLOBAL:
                    retval->data[codep].u.value = B_GLOBAL;
                    break;
                default:
                    return -1;
                }

                retval->data[codep].type = BT_VALUE;
                retval->data[codep++].u.value |=
                    (c->u.inc.once << 6) | (c->u.inc.optional << 7);
                retval->data[codep].type = BT_STR;
                retval->data[codep++].u.str = c->u.inc.script;
                break;

            case SET:
                /* SET
                   BITFIELD modifiers
                   STRING variable
                   STRING value
                */
                retval->data[codep++].u.op = B_SET;
                if (!atleast(retval, codep+3)) return -1;
                retval->data[codep].type = BT_VALUE;
                retval->data[codep].u.value = 0;
                switch(c->u.s.mod40) {
                case LOWER:
                    retval->data[codep].u.value |= BFV_LOWER;
                    break;
                case UPPER:
                    retval->data[codep].u.value |= BFV_UPPER;
                    break;
                }
                switch(c->u.s.mod30) {
                case LOWERFIRST:
                    retval->data[codep].u.value |= BFV_LOWERFIRST;
                    break;
                case UPPERFIRST:
                    retval->data[codep].u.value |= BFV_UPPERFIRST;
                    break;
                }
                switch(c->u.s.mod20) {
                case QUOTEWILDCARD:
                    retval->data[codep].u.value |= BFV_QUOTEWILDCARD;
                    break;
                case QUOTEREGEX:
                    retval->data[codep].u.value |= BFV_QUOTEREGEX;
                    break;
                }
                switch(c->u.s.mod15) {
                case ENCODEURL:
                    retval->data[codep].u.value |= BFV_ENCODEURL;
                    break;
                }
                switch(c->u.s.mod10) {
                case LENGTH:
                    retval->data[codep].u.value |= BFV_LENGTH;
                    break;
                }
                codep++;
                retval->data[codep].type = BT_STR;
                retval->data[codep++].u.str = c->u.s.variable;
                retval->data[codep].type = BT_STR;
                retval->data[codep++].u.str = c->u.s.value;
                break;

            case ADDHEADER:
                /* ADDHEADER
                   NUMBER index
                   STRING name
                   STRING value
                */
                retval->data[codep++].u.op = B_ADDHEADER;
                if (!atleast(retval, codep+3)) return -1;
                retval->data[codep].type = BT_VALUE;
                retval->data[codep++].u.value = c->u.ah.index;
                retval->data[codep].type = BT_STR;
                retval->data[codep++].u.str = c->u.ah.name;
                retval->data[codep].type = BT_STR;
                retval->data[codep++].u.str = c->u.ah.value;
                break;

            case DELETEHEADER:
                /* DELETEHEADER
                   NUMBER index
                   COMPARATOR
                   STRING name
                   STRINGLIST value-patterns
                */
                retval->data[codep++].u.op = B_DELETEHEADER;
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

            case LOG:
                /* LOG
                   STRING text
                */
                retval->data[codep++].u.op = B_LOG;
                if (!atleast(retval, codep+1)) return -1;
                retval->data[codep].type = BT_STR;
                retval->data[codep++].u.str = c->u.l.text;
                break;

            case SNOOZE:
                /* SNOOZE
                   STRING mailbox
                   STRINGLIST addflags
                   STRINGLIST removeflags
                   STRINGLIST daysofweek
                   STRINGLIST times
                */
                retval->data[codep++].u.op = B_SNOOZE;
                if (!atleast(retval, codep+1)) return -1;
                retval->data[codep].type = BT_STR;
                retval->data[codep++].u.str = c->u.sn.mailbox;

                codep = bc_stringlist_generate(codep, retval, c->u.sn.addflags);
                if (codep == -1) return -1;
                codep = bc_stringlist_generate(codep, retval, c->u.sn.removeflags);
                if (codep == -1) return -1;
                retval->data[codep].type = BT_VALUE;
                retval->data[codep++].u.value = c->u.sn.days;
                codep = bc_stringlist_generate(codep, retval, c->u.sn.times);
                if (codep == -1) return -1;
                break;

            case IF:
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

                retval->data[codep++].u.op = B_IF;

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
