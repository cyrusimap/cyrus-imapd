/* bc_generate.c -- sieve bytecode- almost flattened bytecode
 * Rob Siemborski
 * $Id: bc_generate.c,v 1.1.4.1 2003/02/27 18:13:52 rjs3 Exp $
 */
/***********************************************************
        Copyright 2001 by Carnegie Mellon University

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

#include "xmalloc.h"
#include "sieve_interface.h"

#include "script.h"
#include "tree.h"
#include "sieve.h"

#include "bytecode.h"

#include <assert.h>
#include <string.h>



struct bytecode_info 
{
    bytecode_t *data;/* pointer to almost-flat bytecode */
    size_t scriptend; /* used by emit code to know final length of bytecode */
    size_t reallen; /* allocated length of 'data' */
};

static int bc_test_generate(int codep, bytecode_info_t *retval, test_t *t);

/* returns false if the request can't be satisfied, true if it can. */

static int atleast(bytecode_info_t *arr, size_t len) 
{
    if(arr->reallen < len) {
	/* too small; double if that's big enough, otherwise increase to the
	   requested size. */
	arr->reallen = (len > arr->reallen * 2 ? len : arr->reallen * 2);
	arr->data = xrealloc(arr->data, arr->reallen*sizeof(bytecode_t));
	if(!arr->data) 
	{ /* out of memory? */
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
				  stringlist_t *sl) 
{
    int len_codep = codep;
    int strcount = 0;
    stringlist_t *cur;
    
    codep++;

    /* Bounds check the string list length */
    if(!atleast(retval,codep+1)) 
	return -1;

    for(cur=sl; cur; cur=cur->next) 
    {
	strcount++;
	assert((cur->s)!=NULL);
	
	/* Bounds check for each string before we allocate it */
	if(!atleast(retval,codep+2)) 
	    return -1;

	retval->data[codep++].len = strlen(cur->s);
	retval->data[codep++].str = cur->s;
    }
    
    retval->data[len_codep].listlen = strcount;
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
    if(!atleast(retval,codep+1)) 
	return -1;
       
    for(cur=tl; cur; cur=cur->next) {
	int oldcodep = codep;

	/* Make room for tail marker */
	if(!atleast(retval,codep+1)) 
	    return -1;

	testcount++;
	codep = bc_test_generate(codep+1, retval, cur->t);

	retval->data[oldcodep].jump = codep;
    }

    retval->data[len_codep].listlen = testcount;
        
    return codep;
}
/* output a relation into almost-flat form at codep.
 * returns new codep on success, -1 on failure. */
static int bc_relation_generate(int codep, bytecode_info_t *retval, int relat)
{
    if (!atleast(retval, codep + 1)) return -1;
    switch (relat)
    {
    case GT:
	retval->data[codep++].value= B_GT;
	break;
    case GE:
	retval->data[codep++].value= B_GE;
	break; 
    case LT:
	retval->data[codep++].value= B_LT;
	break;
    case LE:
	retval->data[codep++].value= B_LE;
	break;
    case EQ:
	retval->data[codep++].value= B_EQ;
	break;
    case NE:
	retval->data[codep++].value= B_NE;
	break;
    default:
	/* comparator has no relational field */
	retval->data[codep++].value=  -1;
	break;
    }
    return codep;
}
/* writes a single comparator into almost-flat form starting at codep.
 * will always write out 3 words
 * returns the next code location or -1 on error. */
static int bc_comparator_generate(int codep, bytecode_info_t *retval,
                                  int comptag, int relat,
                                  const char *comparator)
{
    assert(retval != NULL);

    /* comptag */
    if (!atleast(retval, codep + 1)) return -1;

    switch (comptag) {
    case IS:
        retval->data[codep++].value = B_IS;
        break;
    case CONTAINS:
        retval->data[codep++].value = B_CONTAINS;
        break;
    case MATCHES:
        retval->data[codep++].value = B_MATCHES;
        break;
#ifdef ENABLE_REGEX
    case REGEX:
        retval->data[codep++].value = B_REGEX;
        break;
#endif
    case COUNT:
        retval->data[codep++].value = B_COUNT;
        break;
    case VALUE:
        retval->data[codep++].value = B_VALUE;
        break;

    default:
        return -1;
    }
  
    /*relation*/
    codep = bc_relation_generate(codep, retval, relat);
  
    /* comparator (value specified with :comparator) */
    if (!atleast(retval, codep + 1)) return -1;
  
    /* xxx perhaps extend comparator.h to have
       lookup_comp return an index, and then
       lookup_by_index return the actual comparator?
       
       we can then eliminate the comptag above, too. */
    
    if (!strcmp (comparator, "i;octet"))
        retval->data[codep++].value = B_OCTET;
    else if (!strcmp (comparator, "i;ascii-casemap"))
        retval->data[codep++].value = B_ASCIICASEMAP;
    else if (!strcmp (comparator, "i;ascii-numeric"))
        retval->data[codep++].value = B_ASCIINUMERIC;

    return codep;
}



/* writes a single test into almost-flat form starting at codep.
 * returns the next code location or -1 on error. */
static int bc_test_generate(int codep, bytecode_info_t *retval, test_t *t)
{
    if(!retval) return -1;
    switch(t->type) {
    case STRUE: /* BC_TRUE */
	if(!atleast(retval,codep+1)) return -1;
	retval->data[codep++].op = BC_TRUE;
	break;
    case SFALSE:/* BC_FALSE */
	if(!atleast(retval,codep+1)) return -1;
	retval->data[codep++].op = BC_FALSE;
	break;
    case NOT: /* BC_NOT {subtest : test} */
	if(!atleast(retval,codep+1)) return -1;
	retval->data[codep++].op = BC_NOT;
	codep = bc_test_generate(codep, retval, t->u.t);
	if (codep == -1) return -1;
	break;
    case SIZE: /* BC_SIZE (B_OVER | B_UNDER) {size : int} */
	if(!atleast(retval,codep+3)) return -1;
	retval->data[codep++].op = BC_SIZE;
	retval->data[codep++].value = (t->u.sz.t == OVER
				       ? B_OVER : B_UNDER);
	retval->data[codep++].value = t->u.sz.n;
	break;
    case EXISTS:/* BC_EXISTS { headers : string list } */
	if(!atleast(retval,codep+1)) return -1;
	retval->data[codep++].op = BC_EXISTS;
	codep= bc_stringlist_generate(codep, retval, t->u.sl);
	break;
    case ANYOF:/* BC_ANYOF { tests : test list } */
	if(!atleast(retval,codep+1)) return -1;
	retval->data[codep++].op = BC_ANYOF;
	codep=bc_testlist_generate(codep, retval, t->u.tl);
	if (codep == -1) return -1;
	break;
    case ALLOF: /* BC_ALLOF { tests : test list } */
	if(!atleast(retval,codep+1)) return -1;
	retval->data[codep++].op = BC_ALLOF;
	codep= bc_testlist_generate(codep, retval, t->u.tl);
	if (codep == -1) return -1;
	break;
    case HEADER:
	/* BC_HEADER { c: comparator } { headers : string list }
	   { patterns : string list } 
	*/
      
	if(!atleast(retval,codep + 1)) return -1;
	retval->data[codep++].op = BC_HEADER;
      
	/* comparator */
	codep = bc_comparator_generate(codep, retval,
				       t->u.h.comptag,
				       t->u.h.relation,
				       t->u.h.comparator);
	if (codep == -1) return -1;
      
	/* headers */
	codep = bc_stringlist_generate(codep, retval, t->u.h.sl);
	if (codep == -1) return -1;
      
	/* pattern */
	codep = bc_stringlist_generate(codep, retval, t->u.h.pl);
	if (codep == -1) return -1;
	break;
    case ADDRESS:
    case ENVELOPE:
	/* (BC_ADDRESS | BC_ENVELOPE) {c : comparator} 
	   (B_ALL | B_LOCALPART | ...) { header : string list }
	   { pattern : string list } */
      
	if(!atleast(retval,codep+1)) return -1;
      
	retval->data[codep++].op = (t->type == ADDRESS)
	    ? BC_ADDRESS : BC_ENVELOPE;
            
	codep = bc_comparator_generate(codep, retval,t->u.ae.comptag,
				       t->u.ae.relation, 
				       t->u.ae.comparator);
	if (codep == -1) return -1;
	/*address part*/
	switch(t->u.ae.addrpart) {
	case ALL:
	    retval->data[codep++].value = B_ALL;
	    break;
	case LOCALPART:
	    retval->data[codep++].value = B_LOCALPART;
	    break;
	case DOMAIN:
	    retval->data[codep++].value = B_DOMAIN;
	    break;
	case USER:
	    retval->data[codep++].value = B_USER;
	    break;
	case DETAIL:
	    retval->data[codep++].value = B_DETAIL;
	    break;
	default:
	    return -1;
	}
	/*headers*/
	codep = bc_stringlist_generate(codep, retval, t->u.h.sl);
	if (codep == -1) return -1;

	/*patterns*/
	codep = bc_stringlist_generate(codep, retval, t->u.h.pl);
	if (codep == -1) return -1;
     
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
    int jumploc,baseloc;

    if(!retval) return -1;
    if (c==NULL)
    {
	if(!atleast(retval,codep+1)) return -1;
	retval->data[codep++].op = B_NULL;
    }
    else
    {
	do {
	    switch(c->type) {
	    case STOP:
		/* STOP (no arguments) */
		if(!atleast(retval,codep+1)) return -1;
		retval->data[codep++].op = B_STOP;
		break;
	    case DISCARD:
		/* DISCARD (no arguments) */
		if(!atleast(retval,codep+1)) return -1;
		retval->data[codep++].op = B_DISCARD;
		break;
	    case KEEP:
		/* KEEP (no arguments) */
		if(!atleast(retval,codep+1)) return -1;
		retval->data[codep++].op = B_KEEP;
		break;
	    case MARK:
		/* MARK (no arguments) */
		if(!atleast(retval,codep+1)) return -1;
		retval->data[codep++].op = B_MARK;
		break;
	    case UNMARK:
		/* UNMARK (no arguments) */
		if(!atleast(retval,codep+1)) return -1;
		retval->data[codep++].op = B_UNMARK;
		break;
	    case DENOTIFY:
		/* DENOTIFY  */
		if(!atleast(retval,codep+6)) return -1;
		retval->data[codep++].op = B_DENOTIFY;
		switch(c->u.d.priority) {
		case LOW:
		    retval->data[codep++].value = B_LOW;
		    break;
		case NORMAL:
		    retval->data[codep++].value = B_NORMAL;
		    break;
		case HIGH:
		    retval->data[codep++].value = B_HIGH;
		    break;
		case ANY:
		    retval->data[codep++].value = B_ANY;
		    break;
		default:
		    return -1;
		}
		switch(c->u.d.comptag) {
		case IS:
		    retval->data[codep++].value = B_IS;
		    break;
		case CONTAINS:
		    retval->data[codep++].value = B_CONTAINS;
		    break;
		case MATCHES:
		    retval->data[codep++].value = B_MATCHES;
		    break;
#ifdef ENABLE_REGEX
		case REGEX:
		    retval->data[codep++].value = B_REGEX;
		    break;
#endif
		case ANY:
		    retval->data[codep++].value = B_ANY;
		    break; 
		default:
		    return -1;
		}
		codep = bc_relation_generate(codep, retval, c->u.d.relation);
	
		if(c->u.d.pattern)
		{
		    retval->data[codep++].len = strlen(c->u.d.pattern);
		    retval->data[codep++].str = c->u.d.pattern;
		} else {
		    retval->data[codep++].len = -1;
		    retval->data[codep++].str = NULL;
		}

		break;
	    case REJCT:
		/* REJECT (STRING: len + dataptr) */
		if(!atleast(retval,codep+3)) return -1;
		retval->data[codep++].op = B_REJECT;
		retval->data[codep++].len = strlen(c->u.str);
		retval->data[codep++].str = c->u.str;
		break;
	    case FILEINTO:
		/* FILEINTO (STRING: len + dataptr) */
		if(!atleast(retval,codep+3)) return -1;
		retval->data[codep++].op = B_FILEINTO;
		retval->data[codep++].len = strlen(c->u.str);
		retval->data[codep++].str = c->u.str;
		break;
	    case REDIRECT:
		/* REDIRECT (STRING: len + dataptr) */
		if(!atleast(retval,codep+3)) return -1;
		retval->data[codep++].op = B_REDIRECT;
		retval->data[codep++].len = strlen(c->u.str);
		retval->data[codep++].str = c->u.str;
		break;
	    case ADDFLAG:
		/* ADDFLAG stringlist */
		if(!atleast(retval,codep+1)) return -1;
		retval->data[codep++].op = B_ADDFLAG;
		codep = bc_stringlist_generate(codep,retval,c->u.sl);

		if(codep == -1) return -1;
		break;
	    case SETFLAG:
		/* SETFLAG stringlist */
		if(!atleast(retval,codep+1)) return -1;
		retval->data[codep++].op = B_SETFLAG;
		codep = bc_stringlist_generate(codep,retval,c->u.sl);

		if(codep == -1) return -1;
		break;
	    case REMOVEFLAG:
		/* REMOVEFLAG stringlist */
		if(!atleast(retval,codep+1)) return -1;
		retval->data[codep++].op = B_REMOVEFLAG;
		codep = bc_stringlist_generate(codep,retval,c->u.sl);

		if(codep == -1) return -1;
		break;
	    case NOTIFY:
		/* NOTIFY 
		   (STRING: len + dataptr)
		   (STRING: len + dataptr)
		   stringlist
		   (STRING: len + dataptr)
		   (STRING: len + dataptr)
		   method/id /options list/priority/message 
		*/
			
		if(!atleast(retval,codep+5)) return -1;
		retval->data[codep++].op = B_NOTIFY;
		
		retval->data[codep++].len = strlen(c->u.n.method);
		retval->data[codep++].str = c->u.n.method;
				
		if (c->u.n.id)
		{
		    retval->data[codep++].len = strlen(c->u.n.id);
		    retval->data[codep++].str = c->u.n.id;
		}
		else
		{
		    retval->data[codep++].len = -1;
		    retval->data[codep++].str = NULL;
		}
		
		codep = bc_stringlist_generate(codep,retval,c->u.n.options);
		if(codep == -1) return -1;

		if(!atleast(retval,codep+3)) return -1;

		switch(c->u.n.priority) {
		case LOW:
		    retval->data[codep++].value = B_LOW;
		    break;
		case NORMAL:
		    retval->data[codep++].value = B_NORMAL;
		    break;
		case HIGH:
		    retval->data[codep++].value = B_HIGH;
		    break;
		case ANY:
		    retval->data[codep++].value = B_ANY;
		    break;
		default:
		    return -1;
		}
		
		retval->data[codep++].len = strlen(c->u.n.message);
		retval->data[codep++].str = c->u.n.message;
		break;
	    case VACATION:
		/* VACATION
		   STRINGLIST addresses
		   STRING subject (if len is -1, then subject was NULL)
		   STRING message (again, len == -1 means subject was NULL)
		   VALUE days
		   VALUE mime
		*/

		if(!atleast(retval,codep+1)) return -1;
		retval->data[codep++].op = B_VACATION;
	    
		codep = bc_stringlist_generate(codep,retval,c->u.v.addresses);
		if (codep == -1) return -1;

		if (!atleast(retval,codep+2)) return -1;
		if(c->u.v.subject) {
		    retval->data[codep++].len = strlen(c->u.v.subject);
		    retval->data[codep++].str = c->u.v.subject;
		} else {
		    retval->data[codep++].len = -1;
		    retval->data[codep++].str = NULL;
		}

		if (!atleast(retval,codep+2)) return -1;
		if(c->u.v.message) {
		    retval->data[codep++].len = strlen(c->u.v.message);
		    retval->data[codep++].str = c->u.v.message;
		} else {
		    retval->data[codep++].len = -1;
		    retval->data[codep++].str = NULL;
		}

		if (!atleast(retval,codep+2)) return -1;
		retval->data[codep++].value = c->u.v.days;
		retval->data[codep++].value = c->u.v.mime;
	    

		if(codep == -1) return -1;
		break;
	    case IF:
	    {
		int jumpVal; 	    
		/* IF
		   (int: begin then block)
		   (int: end then block/begin else block)
		   (int:end else block) (-1 if no else block)
		   (test)
		   (then block)
		   (else block)(optional)
		*/
		baseloc = codep;
	    
		/* Allocate operator + jump table offsets */
		if(!atleast(retval,codep+4)) return -1;
		
		jumploc = codep+4;
		retval->data[codep++].op = B_IF;
		    
		/* begining of then  code */
		jumpVal= bc_test_generate(jumploc,retval,c->u.i.t);
		if(jumpVal == -1) 
		    return -1;
		else {
		    retval->data[codep].jump = jumpVal;
		    codep++;
		}
	    
		/* find then code and offset to else code,
		 * we want to write this code starting at the offset we
		 * just found */
	
		jumpVal= bc_action_generate(jumpVal,retval, c->u.i.do_then);
		if(jumpVal == -1) 
		    return -1;
		else 
		    retval->data[codep].jump = jumpVal;
		
		codep++;
		/* write else code if its there*/
		if(c->u.i.do_else) {
	
		    jumpVal= bc_action_generate(jumpVal,retval, c->u.i.do_else);
		    if(jumpVal == -1) 
		    {
			return -1;
		    } else 
		    {
			retval->data[codep].jump = jumpVal;
		    }
		    
		    /* Update code pointer to end of else code */
		    codep = retval->data[codep].jump;
		} else {
		    /*there is no else block, so its -1*/
		    retval->data[codep].jump = -1;
		    /* Update code pointer to end of then code */
		    codep = retval->data[codep-1].jump;
		}
	    
		break;
	    }
	    default:
		/* no such action known */
		return -1;
	    }
	  
	    /* generate from next command */
	    c = c->next;
	} while(c);
    }
    /*scriptend may be updated before the end, but it will be updated at the end, which is what matters.*/
    retval->scriptend=codep;
    return codep;
   
}



/* Entry point to the bytecode emitter module */	
int sieve_generate_bytecode(bytecode_info_t **retval, sieve_script_t *s) 
{
    commandlist_t *c;

    if(!retval) return -1;
    if(!s) return -1;
    c = s->cmds;
    if(!c) return -1;
    
    *retval = xmalloc(sizeof(bytecode_info_t));
    if(!(*retval)) return -1;

    memset(*retval, 0, sizeof(bytecode_info_t));

    return bc_action_generate(0, *retval, c);
}
