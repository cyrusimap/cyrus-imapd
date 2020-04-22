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

#include "bytecode.h"

#include "assert.h"
#include <string.h>


static int bc_test_generate(int codep, bytecode_info_t *retval, const test_t *t);

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
                                  const strarray_t *sa)
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
                               const arrayu64_t *va)
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
                                const testlist_t *tl)
{
    int len_codep = codep;
    int testcount = 0;
    const testlist_t *cur;

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
 * will write out 2 or 3 words
 * returns the next code location or -1 on error. */
static int bc_comparator_generate(int codep, bytecode_info_t *retval,
                                  const comp_t *comp)
{
    assert(retval != NULL);

    /* comptag */
    if (!atleast(retval, codep + 1)) return -1;
    retval->data[codep].type = BT_VALUE;
    retval->data[codep++].u.value = comp->match;

    /* relation */
    if (!atleast(retval, codep + 1)) return -1;
    retval->data[codep].type = BT_VALUE;
    retval->data[codep++].u.value = comp->relation;

    if (comp->collation == -1) return codep;

    /* collation (value specified with :comparator) */
    if (!atleast(retval, codep + 1)) return -1;
    retval->data[codep].type = BT_VALUE;
    retval->data[codep++].u.value = comp->collation;

    return codep;
}

/* writes out a series of command arguments.
 * returns the next code location or -1 on error. */
static int bc_args_generate(int codep, bytecode_info_t *retval,
                            unsigned nargs, const cmdarg_t args[])
{
    unsigned i;
                
    for (i = 0; i < nargs; i++) {
        switch (args[i].type) {
        case AT_INT:
            if (!atleast(retval, codep+1)) return -1;
            retval->data[codep].type = BT_VALUE;
            retval->data[codep++].u.value = args[i].u.i;
            break;

        case AT_STR:
            if (!atleast(retval, codep+1)) return -1;
            retval->data[codep].type = BT_STR;
            retval->data[codep++].u.str = args[i].u.s;
            break;

        case AT_STRARRAY:
            codep = bc_stringlist_generate(codep, retval, args[i].u.sa);
            if (codep == -1) return -1;
            break;

        case AT_ARRAYU64:
            codep = bc_vallist_generate(codep, retval, args[i].u.ua);
            if (codep == -1) return -1;
            break;

        case AT_COMP:
            codep = bc_comparator_generate(codep, retval, args[i].u.c);
            if (codep == -1) return -1;
            break;

        case AT_TEST:
            codep = bc_test_generate(codep, retval, args[i].u.t);
            if (codep == -1) return -1;
            break;

        case AT_TESTLIST:
            codep = bc_testlist_generate(codep, retval, args[i].u.tl);
            if (codep == -1) return -1;
            break;

        default:
            return -1;
        }
    }

    return codep;
}

/* writes a single test into almost-flat form starting at codep.
 * returns the next code location or -1 on error. */
static int bc_test_generate(int codep, bytecode_info_t *retval, const test_t *t)
{
    if (!retval) return -1;

    if (t->type >= BC_ILLEGAL_VALUE) {
        /* no such test known */
        return -1;
    }

    if (!atleast(retval, codep+1)) return -1;

    retval->data[codep].type = BT_OPCODE;
    retval->data[codep++].u.op = t->type;

    return bc_args_generate(codep, retval, t->nargs, t->args);
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
            if (c->type >= B_ILLEGAL_VALUE) {
                /* no such action known */
                return -1;
            }

            if (!atleast(retval, codep+1)) return -1;
            retval->data[codep].type = BT_OPCODE;
            retval->data[codep++].u.op = c->type;

            if (c->type == B_IF) {
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
            else {
                codep = bc_args_generate(codep, retval, c->nargs, c->args);
                if (codep == -1) return -1;
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
