/* bc_generate.c -- sieve bytecode- almost flattened bytecode */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

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

static inline int bc_simple_generate(int codep, bytecode_info_t *retval,
                                     int type, ...)
{
    va_list ap;

    if (!atleast(retval, codep+1)) return -1;

    retval->data[codep].type = type;

    va_start(ap, type);
    if (type == BT_STR) {
        retval->data[codep++].u.str = va_arg(ap, const char *);
    }
    else {
        /* XXX  can use any of: op, value, jump, listlen */
        retval->data[codep++].u.value = va_arg(ap, int);
    }
    va_end(ap);

    return codep;
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

    /* Bounds check the string list length (count + 1) */
    if (!atleast(retval, codep + strcount + 1)) return -1;

    codep = bc_simple_generate(codep, retval, BT_STRLISTLEN, strcount);

    for (i = 0 ; i < strcount ; i++) {
        char *s = sa->data[i];

        assert(s != NULL);

        codep = bc_simple_generate(codep, retval, BT_STR, s);
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

    /* Bounds check the value list length (count + 1) */
    if (!atleast(retval, codep + count + 1)) return -1;

    codep = bc_simple_generate(codep, retval, BT_VALLISTLEN, count);

    for (i = 0 ; i < count ; i++) {
        codep = bc_simple_generate(codep, retval, BT_VALUE, arrayu64_nth(va, i));
    }

    return codep;
}


/* write a list of tests into almost-flat form, starting at codep.
 * returns the next code location, -1 on error. */

/* <list len> <next test ptr> <test ...> <next test ptr> <test ...> ... */
static int bc_testlist_generate(int codep, bytecode_info_t *retval,
                                const testlist_t *tl)
{
    int lenloc = codep++;
    int testcount = 0;
    const testlist_t *cur;

    /* Allocate list len */
    if (!atleast(retval, lenloc+1)) return -1;

    for (cur = tl; cur; cur = cur->next, testcount++) {
        int jumploc = codep;

        /* Allocate jump location */
        if (!atleast(retval, jumploc+1)) return -1;

        codep = bc_test_generate(jumploc+1, retval, cur->t);
        if (codep == -1) return -1;

        /* update jump location */
        bc_simple_generate(jumploc, retval, BT_JUMP, codep);
    }

    /* update list length */
    bc_simple_generate(lenloc, retval, BT_STRLISTLEN, testcount);

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
            codep = bc_simple_generate(codep, retval, BT_VALUE, args[i].u.i);
            break;

        case AT_STR:
            codep = bc_simple_generate(codep, retval, BT_STR, args[i].u.s);
            break;

        case AT_STRARRAY:
            codep = bc_stringlist_generate(codep, retval, args[i].u.sa);
            break;

        case AT_ARRAYU64:
            codep = bc_vallist_generate(codep, retval, args[i].u.ua);
            break;

        case AT_TEST:
            codep = bc_test_generate(codep, retval, args[i].u.t);
            break;

        case AT_TESTLIST:
            codep = bc_testlist_generate(codep, retval, args[i].u.tl);
            break;

        default:
            return -1;
        }

        if (codep == -1) return -1;
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

    codep = bc_simple_generate(codep, retval, BT_OPCODE, t->type);
    if (codep == -1) return -1;

    return bc_args_generate(codep, retval, t->nargs, t->args);
}


/* generate a not-quite-flattened bytecode */
/* returns address of next instruction or -1 on error*/
/* needs current instruction, buffer for the code, and a current parse tree */
/* sieve is cool because everything is immediate! */
static int bc_action_generate(int codep, bytecode_info_t *retval,
                              commandlist_t *c)
{
    if (!retval) return -1;

    if (c == NULL) {
        codep = bc_simple_generate(codep, retval, BT_OPCODE, B_NULL);
        if (codep == -1) return -1;
    }
    else {
        do {
            if (c->type >= B_ILLEGAL_VALUE) {
                /* no such action known */
                return -1;
            }

            codep = bc_simple_generate(codep, retval, BT_OPCODE, c->type);
            if (codep == -1) return -1;

            if (c->type == B_IF) {
                /* IF
                   (int: begin then block)
                   (int: end then block/begin else block)
                   (int: end else block) (-1 if no else block)
                   (test)
                   (then block)
                   (else block)(optional)
                */
                int jumploc = codep;

                /* Allocate jump table offsets */
                if (!atleast(retval, jumploc+3)) return -1;

                /* write test */
                codep = bc_test_generate(jumploc+3, retval, c->u.i.t);
                if (codep == -1) return -1;

                /* update jump table with beginning of then block */
                bc_simple_generate(jumploc, retval, BT_JUMP, codep);

                /* write then block */
                codep = bc_action_generate(codep, retval, c->u.i.do_then);
                if (codep == -1) return -1;

                /* update jump table with end of then block */
                bc_simple_generate(jumploc+1, retval, BT_JUMP, codep);

                /* write else block */
                if (c->u.i.do_else) {
                    codep = bc_action_generate(codep, retval, c->u.i.do_else);
                    if (codep == -1) return -1;

                    /* update jump table with end of else block */
                    bc_simple_generate(jumploc+2, retval, BT_JUMP, codep);
                }
                else {
                    /* no else block */
                    bc_simple_generate(jumploc+2, retval, BT_JUMP, -1);
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

    codep = bc_simple_generate(codep, *retval, BT_VALUE, requires);
    if (codep == -1) return -1;

    return bc_action_generate(codep, *retval, c);
}


EXPORTED void sieve_free_bytecode(bytecode_info_t **p)
{
    if (!p || !*p) return;
    if ((*p)->data) free((*p)->data);
    free(*p);
    *p = NULL;
}
