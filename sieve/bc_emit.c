/* bc_emit.c -- sieve bytecode - pass 2 of the compiler
 * Rob Siemborski
 * Jen Smith
 * $Id: bc_emit.c,v 1.1.4.2 2003/03/31 16:55:25 rjs3 Exp $
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

 
#include "bytecode.h"

#include <syslog.h>
#include <sys/types.h>
#include <unistd.h>


#if DUMPCODE
void dump(bytecode_info_t *d);
#endif


struct bytecode_info 
{
    bytecode_t *data;/* pointer to almost-flat bytecode */
    size_t scriptend; /* used by emit code to know final length of bytecode  */
    size_t reallen; /* allocated length of 'data' */
};

/* Pad null bytes onto the end of the string we just wrote */
/* returns -1 on failure or number of bytes written on success */
static int align_string(int fd, int string_len) 
{
    /* Keep in mind that we always want to pad a string with *at least*
     * one zero, that's why sometimes we have to pad with 4 */
    int needed = sizeof(int) - (string_len % sizeof(int));
    if (needed>= 0 && needed <=4)
    {
    	if(write(fd, "\0\0\0\0", needed) == -1) return -1;
    }
    return needed;
}

/*all functions keep codep up to date as they use it.
  the amount that has been written to the file is maintained by the
  filelen variable in bc_action_emit
  the other bc_xxx_emit funtions keep track of how much they (and any functions they call) have written and return this value
*/


/* Write out a stringlist to a given file descriptor.
 * return # of bytes written on success and -1 on error */

/* stringlist: <# listitems>
               <pos of listend (bytes)>
               <string:(size)(aligned string)>
*/
static int bc_stringlist_emit(int fd, int *codep, bytecode_info_t *bc) 
{
    int len = bc->data[(*codep)++].len;
    int i;
    int ret;
    int wrote = 2*sizeof(int);
    int begin,end;
    /* Write out number of items in the list */
    ret = write(fd, &len, sizeof(int));
    if(ret == -1) return 0;
    
    begin=lseek(fd,0,SEEK_CUR);
    lseek(fd,sizeof(int),SEEK_CUR);/*skip one spot endoflist position*/
    
    /* Loop through all the items of the list, writing out length and string
     * in sequence */
    for(i=0; i < len; i++)
    {
	int datalen = bc->data[(*codep)++].len;
	
	if(write(fd, &datalen, sizeof(int)) == -1) return 0;
	wrote += sizeof(int);
	
	if(write(fd, bc->data[(*codep)++].str, datalen) == -1) return 0;
	wrote += datalen;
	
	ret = align_string(fd,datalen);
	if(ret == -1) return -1;
	
	wrote+=ret;
    }
    end=lseek(fd,0,SEEK_CUR);
 
    /*go back and write end of list position*/
    lseek(fd,begin,SEEK_SET);
    if(write(fd, &end, sizeof(int)) == -1) return 0;

    /*return to the end */
    lseek(fd,end,SEEK_SET);
    return wrote;
}

static int bc_test_emit(int fd, int *codep, bytecode_info_t *bc);

/* Write out a testlist to a given file descriptor.
 * return # of bytes written on success and -1 on error */
static int bc_testlist_emit(int fd, int *codep, bytecode_info_t *bc) 
{
    int len = bc->data[(*codep)++].len;
    int i;
    int ret;
    int wrote = sizeof(int);
    
    
    /* Write out number of items in the list */
    ret = write(fd, &len, sizeof(int));
    if(ret == -1) return -1;
    
  
    /* Loop through all the items of the list, writing out each
     * test as we reach it in sequence. */
    for(i=0; i < len; i++) {
	int nextcodep = bc->data[(*codep)++].jump;
	
	ret = bc_test_emit(fd, codep, bc);
	if(ret == -1) return -1;
	
	wrote+=ret;
	*codep = nextcodep;
    }
    
    return wrote;
}

/* emit the bytecode for a test.  returns -1 on failure or size of
 * emitted bytecode on success */
static int bc_test_emit(int fd, int *codep, bytecode_info_t *bc) 
{
    int wrote=0;/* Relative offset to account for interleaved strings */
    
    
    int ret; /* Temporary Return Value Variable */
    
    /* Output this opcode */
    if(write(fd, &bc->data[(*codep)].op, sizeof(bc->data[(*codep)].op)) == -1)
	return -1;
    wrote += sizeof(int);
    
    switch(bc->data[(*codep)++].op) {
    case BC_TRUE:
    case BC_FALSE:
	/* No parameter opcodes */
	break;
	
    case BC_NOT:
    {
	/* Single parameter: another test */
	ret = bc_test_emit(fd, codep, bc);
	if(ret != -1)
	    wrote+=ret;
	else
	    return ret;
	break;
    }
    
    case BC_ALLOF:
    case BC_ANYOF:
	/*where we jump to?*/
	/* Just drop a testlist */
	ret = bc_testlist_emit(fd, codep, bc);
	if(ret != -1)
	    wrote+=ret;
	else
	    return ret;
	break;
	
    case BC_SIZE:
	/* Drop tag and number */
	if(write(fd, &bc->data[(*codep)].value,
		 sizeof(bc->data[(*codep)].value)) == -1)
	    return -1;
	if(write(fd, &bc->data[(*codep)+1].value,
		 sizeof(bc->data[(*codep)+1].value)) == -1)
	    return -1;
	
	wrote += 2 * sizeof(int);
	(*codep) += 2;
	break;
	
    case BC_EXISTS:
    {
	int ret;
	ret = bc_stringlist_emit(fd, codep, bc);
	if(ret < 0) return -1;
	wrote += ret;
	break;
    }
    
    case BC_HEADER:
    {
	int ret;
	    /* Drop match type and comparator */
	if(write(fd, &bc->data[(*codep)].value,
		 sizeof(bc->data[(*codep)].value)) == -1)
	    return -1;
	if(write(fd, &bc->data[(*codep)+1].value,
		 sizeof(bc->data[(*codep)+1].value)) == -1)
	    return -1;
	wrote += 2*sizeof(int);
	(*codep) += 2;    
	/*now drop relation*/
	if(write(fd, &bc->data[(*codep)].value,
		 sizeof(bc->data[(*codep)].value)) == -1)
	    return -1;
	wrote += sizeof(int);
	(*codep)++;
	/* Now drop headers */
	ret = bc_stringlist_emit(fd, codep, bc);
	if(ret < 0) return -1;
	wrote+=ret;
	/* Now drop data */
	ret = bc_stringlist_emit(fd, codep, bc);
	if(ret < 0) return -1;
	wrote+=ret;
	break;
    }
    
    case BC_ADDRESS:
    case BC_ENVELOPE:
    {
	int ret;
	/* Drop match type and Comparator  */
	if(write(fd, &bc->data[(*codep)].value,
		 sizeof(bc->data[(*codep)].value)) == -1)
	    return -1;
	if(write(fd, &bc->data[(*codep)+1].value,
		 sizeof(bc->data[(*codep)+1].value)) == -1)
	    return -1;
	wrote += 2*sizeof(int);
	(*codep) += 2;    
	/*now drop relation*/
	if(write(fd, &bc->data[(*codep)].value,
		 sizeof(bc->data[(*codep)].value)) == -1)
	    return -1;
	wrote += sizeof(int);
	(*codep)++;
	/*now drop address part*/
	if(write(fd, &bc->data[(*codep)].value,
		 sizeof(bc->data[(*codep)].value)) == -1)
	    return -1;
	wrote += sizeof(int);
	(*codep)++;
	/* Now drop headers */
	ret = bc_stringlist_emit(fd, codep, bc);
	if(ret < 0) return -1;
	wrote+=ret;
	/* Now drop data */
	ret = bc_stringlist_emit(fd, codep, bc);
	if(ret < 0) return -1;
	wrote+=ret;
	break;
    }
    
    default:
	/* Unknown testcode? */
	return -1;
    }
    return wrote;
}

/* emit the bytecode to a file descriptor given a flattened parse tree
 * returns -1 on failure, size of emitted bytecode on success.
 *
 * this takes care of everything except the comparisons */
static int bc_action_emit(int fd, int codep, int stopcodep,
			  bytecode_info_t *bc, int filelen) 
{
    int len; /* Temporary Length Variable */
    int ret; /* Temporary Return Value Variable */
    int start_filelen = filelen;
    int i;
    
    /*debugging variable to check filelen*/
    /*int location;*/
    
    syslog(LOG_DEBUG, "entered bc_action_emit with filelen: %d", filelen);
    
    /* All non-string data MUST be sizeof(int)
       byte alligned so the end of each string may require a pad */
    /*
     * Note that for purposes of jumps you must multiply codep by sizeof(int)
     */
    while(codep < stopcodep) {
	/* Output this opcode */
	if(write(fd, &bc->data[codep].op, sizeof(bc->data[codep].op)) == -1)
	    return -1;
	
	filelen+=sizeof(int);
	
	switch(bc->data[codep++].op) {

	case B_IF:
	{
	    /* IF
	     *  test
	     *  jump (false condition)
	     *  then
	     * (if there is an else) jump(finish) 
	     * (if there is an else) else
	     */

	    int testEndLoc=-1;
	    int testdist, thendist, elsedist;
	    int c;
	    
	    int jumpFalseLoc=-1;/*this is the location that is being reserved
				  for the first jump command
				  we jump to the false condition of the test*/
	    
	    int jumpEndLoc=-1; /* this is the location that is being reserved
				  for the optional jump command
				  it jumps over the else statement to the end*/
	    int jumpto=-1;
	    int jumpop= B_JUMP;

	    /*leave space to store the location of end of the test*/
	    ret = lseek(fd, sizeof(int), SEEK_CUR);
	    if(ret == -1) return ret;
	    
	    testEndLoc=filelen;
	    filelen+=sizeof(int);
	    
	    /* spew the test */

	    c=codep+3;
	    testdist = bc_test_emit(fd, &c, bc);
	    if(testdist == -1)return -1;
	   
	   	    
	    filelen +=testdist;
	    
            /*store the location for hte end of the test
	     *this is important for short circuiting of allof/anyof*/
	    jumpto=filelen/4;
	    if(lseek(fd, testEndLoc, SEEK_SET) == -1)
		return -1;
	    if(write(fd,&jumpto,sizeof(jumpto)) == -1)
		return -1;
	    if(lseek(fd,filelen,SEEK_SET) == -1)
		return -1;

	    /* leave space for jump */
	    if(write(fd, &jumpop, sizeof(int)) == -1)
		return -1;
	    ret = lseek(fd, sizeof(int), SEEK_CUR);
	    if(ret == -1)
		return ret;
	    jumpFalseLoc=filelen+sizeof(int);
	    
	    filelen +=2*sizeof(int);
	    
	    /* spew the then code */ 
	    thendist = bc_action_emit(fd, bc->data[codep].value,
				      bc->data[codep+1].value, bc,
				      filelen);
	 
	    filelen+=thendist;
	  	    
	    /* there is an else case */
	    if(bc->data[codep+2].value != -1)
	    {
		/* leave space for jump */
		if(write(fd, &jumpop, sizeof(int)) == -1)
		    return -1;
		ret = lseek(fd, sizeof(int), SEEK_CUR);
		if(ret == -1)
		    return ret;

		jumpEndLoc=filelen+sizeof(int);
		filelen+=2*sizeof(int);
	    }
	  
	    /*put previous jump to the end of the then code,
	     *or the end of the jump if there is an else case */
	    jumpto=filelen/4;
	    if(lseek(fd, jumpFalseLoc, SEEK_SET) == -1)
		return -1;
	    if(write(fd,&jumpto,sizeof(jumpto)) == -1)
		return -1;
	    if(lseek(fd,filelen,SEEK_SET) == -1)
		return -1;
	    
	    /* there is an else case */
	    if(bc->data[codep+2].value != -1) {
		/* spew the else code */
		elsedist = bc_action_emit(fd, bc->data[codep+1].value,
					 bc->data[codep+2].value, bc,
					 filelen);
	
		filelen+=elsedist;
		
		/*put jump to the end of the else code*/
	        jumpto=filelen/4;
		if(lseek(fd, jumpEndLoc, SEEK_SET) == -1)
		    return -1;
		if(write(fd,&jumpto,sizeof(jumpto)) == -1)
		    return -1;
		if(lseek(fd,filelen,SEEK_SET) == -1)
		    return -1;
		
		codep = bc->data[codep+2].value;
	    } else {
		codep = bc->data[codep+1].value;
	    }
	    
	    break;
	}
	
	case B_REJECT:
	case B_FILEINTO:
	case B_REDIRECT:
	    /*just a string*/
	    len = bc->data[codep++].len;
	    if(write(fd,&len,sizeof(len)) == -1)
		return -1;

	    filelen+=sizeof(int);
	    
	    if(write(fd,bc->data[codep++].str,len) == -1)
		return -1;
	    
	    ret = align_string(fd, len);
	    if(ret == -1)
		return -1;

	    filelen += len + ret;
	    
	    break; 

	case B_SETFLAG:
	case B_ADDFLAG:
	case B_REMOVEFLAG:
	    /* Dump just a stringlist */
	    ret = bc_stringlist_emit(fd, &codep, bc);
	    if(ret < 0)
		return -1;
	    filelen += ret;
	    break;
	    
	case B_NOTIFY:
	    /* method string, id string, options string list,
	       priotity, Message String */
	    /*method and id*/
	    for(i=0; i<2; i++) {
		len = bc->data[codep++].len;
		if(write(fd,&len,sizeof(len)) == -1)
		    return -1;
		filelen += sizeof(int);
		if(len == -1)
		{
                    /* this will probably only happen for the id */
		    /* this is a nil string */
		    /* skip the null pointer and make up for it 
		     * by adjusting the offset */
		    codep++;
		}
		else
		{	
		    if(write(fd,bc->data[codep++].str,len) == -1)
			return -1;
		    
		    ret = align_string(fd, len);
		    if(ret == -1)
			return -1;
		    
		    filelen += len + ret;
		}
		
	    }
	    /*options */
	    ret = bc_stringlist_emit(fd, &codep, bc);
	    if(ret < 0)
		return -1;
	    filelen+=ret;
	    
	    /*priority*/
	    if(write(fd, &bc->data[codep].value,
		     sizeof(bc->data[codep].value)) == -1)
		return -1;
	    codep++;
	    filelen += sizeof(int);
	    
	    len = bc->data[codep++].len;
	    if(write(fd,&len,sizeof(len)) == -1)
		return -1;
	    filelen += sizeof(int);
	    
	    if(write(fd,bc->data[codep++].str,len) == -1)
		return -1;
	    
	    ret = align_string(fd, len);
	    if(ret == -1) return -1;
	    
 	    filelen += len + ret;
	    break;

		
	case B_DENOTIFY:
	    /* priority num,comptype  num,relat num, comp string*/ 

	    /* priority and comptype and relational*/
	    for(i=0; i<3; i++) 
	    {
		if(write(fd, &bc->data[codep].value,
			 sizeof(bc->data[codep].value)) == -1)
		    return -1;
		filelen += sizeof(int);
		codep++;
	    }
	    
	    /*comp string*/
	    
	    len = bc->data[codep++].len;
	    if(write(fd,&len,sizeof(len)) == -1)
		return -1;
	    filelen += sizeof(int);
	    
	    if(len == -1)
	    {
		/* this is a nil string */
		/* skip the null pointer and make up for it 
		 * by adjusting the offset */
		codep++;
	    }
	    else
	    {
		if(write(fd,bc->data[codep++].str,len) == -1)
		    return -1;
		
		ret = align_string(fd, len);
		if(ret == -1) return -1;
		
		filelen += len + ret;
	    }
	    	    break;
	case B_VACATION:
	    /* Address list, Subject String, Message String,
	       Days (word), Mime (word) */
	   
	        /*new code-this might be broken*/
	    ret = bc_stringlist_emit(fd, &codep, bc);
	    if(ret < 0) return -1;
	    filelen += ret;
	    /*end of new code*/

	    for(i=0; i<2; i++) {/*writing strings*/

		/*write length of string*/
		len = bc->data[codep++].len;
		if(write(fd,&len,sizeof(len)) == -1)
		    return -1;
		filelen += sizeof(int);
		    
		if(len == -1)
		{
		    /* this is a nil string */
		    /* skip the null pointer and make up for it 
		     * by adjusting the offset */
		    codep++;
		}
		else
		{
		    /*write string*/
		    if(write(fd,bc->data[codep++].str,len) == -1)
			return -1;
		    
		    ret = align_string(fd, len);
		    if(ret == -1) return -1;
		    
		    filelen += len + ret;
		}
		
	    }
	    if(write(fd,&bc->data[codep].value,
		     sizeof(bc->data[codep].value)) == -1)
		return -1;
	    codep++;
	    filelen += sizeof(int);

	    if(write(fd,&bc->data[codep].value,
		     sizeof(bc->data[codep].value)) == -1)
		return -1;
	    codep++;
	    filelen += sizeof(int);

	    break;
	case B_NULL:
	case B_STOP:
	case B_DISCARD:
	case B_KEEP:
	case B_MARK:
	case B_UNMARK:
	    /* No Parameters! */
	    break;

	default:
	    /* Unknown opcode? */
	    return -1;
	}
    }
    return filelen - start_filelen;
}

/* spew the bytecode to disk */
int sieve_emit_bytecode(int fd, bytecode_info_t *bc)  
{
    /* First output version number (4 bytes) */
    int data = BYTECODE_VERSION;
    
    if(write(fd, BYTECODE_MAGIC, BYTECODE_MAGIC_LEN) == -1)
	return -1;

    if(write(fd, &data, sizeof(data)) == -1)
	return -1;

#if DUMPCODE
    dump(bc);
#endif

    /*the 4 is to account for the version # at the begining*/
    return bc_action_emit(fd, 0, bc->scriptend, bc, 4 + BYTECODE_MAGIC_LEN);
}

void sieve_free_bytecode(bytecode_info_t **p) 
{
    if(!p || !*p) return;
    if((*p)->data) free((*p)->data);
    free(*p);
    *p = NULL;
}
 
