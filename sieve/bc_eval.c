/* bc_eval.c - evaluate the bytecode
 * $Id: bc_eval.c,v 1.6 2004/07/12 15:52:18 ken3 Exp $
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

#include "sieve_interface.h"
#include "interp.h"
#include "message.h"

#include "bytecode.h"

#include "xmalloc.h"

#include <string.h>
#include <ctype.h>

/**************************************************************************/
/**************************************************************************/
/**************************************************************************/
/**************************EXECUTING BYTECODE******************************/
/**************************************************************************/
/**************************************************************************/
/**************************************************************************/
/**************************************************************************/

/* Given a bytecode_input_t at the beginning of a string (the len block),
 * return the string, the length, and the bytecode index of the NEXT
 * item */
int unwrap_string(bytecode_input_t *bc, int pos, const char **str, int *len) 
{
    int local_len = ntohl(bc[pos].value);

    pos++;
    
    if(local_len == -1) {
	/* -1 length indicates NULL */
	*str = NULL;
    } else {
	/* This cast is ugly, but necessary */
	*str = (const char *)&bc[pos].str;
	
	/* Compute the next index */
	pos += ((ROUNDUP(local_len+1))/sizeof(bytecode_input_t));
    }
    
    if(len) *len = local_len;
    
    return pos;
}


/* this is used by notify to pass the options list to do_notify
 * do_notify needs null-terminated (char *)[],
 *  we have a stringlist, the beginning of which is pointed at by pos */
const char ** bc_makeArray(bytecode_input_t *bc, int *pos) 
{ 
    int i;
    const char** array;
    int len = ntohl(bc[*pos].value);

    (*pos)+=2; /* Skip # Values and Total Byte Length */
  
    array=(const char **)xmalloc((len+1) * sizeof(char *));

    for (i=0; i<len; i++) {
	*pos = unwrap_string(bc, *pos, &(array[i]), NULL);
    }

    array[i] = NULL;
  
    return array;
}

/* Compile a regular expression for use during parsing */
regex_t * bc_compile_regex(const char *s, int ctag,
			   char *errmsg, size_t errsiz)
{
    int ret;
    regex_t *reg = (regex_t *) xmalloc(sizeof(regex_t));
    
    if ( (ret=regcomp(reg, s, ctag)) != 0)
    {
	(void) regerror(ret, reg, errmsg, errsiz);
	free(reg);
	return NULL;
    }
    return reg;
}

/* Determine if addr is a system address */
static int sysaddr(const char *addr)
{
    if (!strncasecmp(addr, "MAILER-DAEMON", 13))
	return 1;

    if (!strncasecmp(addr, "LISTSERV", 8))
	return 1;

    if (!strncasecmp(addr, "majordomo", 9))
	return 1;

    if (strstr(addr, "-request"))
	return 1;

    if (!strncmp(addr, "owner-", 6))
	return 1;

    return 0;
}

/* look for myaddr and myaddrs in the body of a header - return the match */
static char* look_for_me(char *myaddr, int numaddresses,
			       bytecode_input_t *bc, int i, const char **body)
{
    char *found = NULL;
    int l;
    int curra,x ;

    /* loop through each TO header */
    for (l = 0; body[l] != NULL && !found; l++) {
	void *data = NULL, *marker = NULL;
	char *addr;
	
	parse_address(body[l], &data, &marker);

	/* loop through each address in the header */
	while (!found &&
	       ((addr = get_address(ADDRESS_ALL,&data, &marker, 1))!= NULL)) {

	    if (!strcasecmp(addr, myaddr)) {
		found = xstrdup(myaddr);
		break;
	    }

	    curra=i;

	    for(x=0; x<numaddresses; x++)
	    {
		void *altdata = NULL, *altmarker = NULL;
		char *altaddr;
		const char *str;

		curra = unwrap_string(bc, curra, &str, NULL);
		
		/* is this address one of my addresses? */
      		parse_address(str, &altdata, &altmarker);

		altaddr = get_address(ADDRESS_ALL, &altdata, &altmarker, 1);

		if (!strcasecmp(addr,altaddr)) {
		    found=xstrdup(str);
		    break;
		}

		free_address(&altdata, &altmarker);
	    }

	}
	free_address(&data, &marker);
    }

    return found;
}
 
/* Determine if we should respond to a vacation message */
int shouldRespond(void * m, sieve_interp_t *interp,
		  int numaddresses, bytecode_input_t* bc,
		  int i, char **from, char **to)
{
    const char **body;
    char buf[128];
    char *myaddr = NULL;
    int l = SIEVE_OK;
    void *data = NULL, *marker = NULL;
    char *tmp;
    int curra, x;
    char *found=NULL;
    char *reply_to=NULL;
  
    /* is there an Auto-Submitted keyword other than "no"? */
    strcpy(buf, "auto-submitted");
    if (interp->getheader(m, buf, &body) == SIEVE_OK) {
	/* we don't deal with comments, etc. here */
	/* skip leading white-space */
	while (*body[0] && isspace((int) *body[0])) body[0]++;
	if (strcasecmp(body[0], "no")) l = SIEVE_DONE;
    }

    /* is there a Precedence keyword of "junk | bulk | list"? */
    strcpy(buf, "precedence");
    if (interp->getheader(m, buf, &body) == SIEVE_OK) {
	/* we don't deal with comments, etc. here */
	/* skip leading white-space */
	while (*body[0] && isspace((int) *body[0])) body[0]++;
	if (!strcasecmp(body[0], "junk") ||
	    !strcasecmp(body[0], "bulk") ||
	    !strcasecmp(body[0], "list"))
	    l = SIEVE_DONE;
    }

    /* Note: the domain-part of all addresses are canonicalized */
    /* grab my address from the envelope */
    if (l == SIEVE_OK) {
	strcpy(buf, "to");
	l = interp->getenvelope(m, buf, &body);
	
	if (body[0]) {  
	    parse_address(body[0], &data, &marker);
	    tmp = get_address(ADDRESS_ALL, &data, &marker, 1);
	    myaddr = (tmp != NULL) ? xstrdup(tmp) : NULL;
	    free_address(&data, &marker);
	}  
    }  
  
    if (l == SIEVE_OK) {
	strcpy(buf, "from");
	l = interp->getenvelope(m, buf, &body);
    }
    if (l == SIEVE_OK && body[0]) {
	/* we have to parse this address & decide whether we
	   want to respond to it */
	parse_address(body[0], &data, &marker);
	tmp = get_address(ADDRESS_ALL, &data, &marker, 1);
	reply_to = (tmp != NULL) ? xstrdup(tmp) : NULL;
	free_address(&data, &marker);

	/* first, is there a reply-to address? */
	if (reply_to == NULL) {
	    l = SIEVE_DONE;
	}
    
	/* first, is it from me? */
	if (l == SIEVE_OK && !strcmp(myaddr, reply_to)) {
	    l = SIEVE_DONE;
	}
   
	/* ok, is it any of the other addresses i've
	   specified? */
	if (l == SIEVE_OK)
	{
	    curra=i;
	    for(x=0; x<numaddresses; x++) {
		const char *address;

		curra = unwrap_string(bc, curra, &address, NULL);
		
		if (!strcmp(address, reply_to))
		    l=SIEVE_DONE;
	    }
	}
   
	/* ok, is it a system address? */
	if (l == SIEVE_OK && sysaddr(reply_to)) {
	    l = SIEVE_DONE;
	}
    }
    if (l == SIEVE_OK) {
	/* ok, we're willing to respond to the sender.
	   but is this message to me?  that is, is my address
	   in the TO, CC or BCC fields? */
	if (strcpy(buf, "to"), 
	    interp->getheader(m, buf, &body) == SIEVE_OK)
	    found = look_for_me(myaddr, numaddresses ,bc, i, body);
	if (!found && (strcpy(buf, "cc"),
		       (interp->getheader(m, buf, &body) == SIEVE_OK)))
	    found = look_for_me(myaddr, numaddresses, bc, i, body);
	if (!found && (strcpy(buf, "bcc"),
		       (interp->getheader(m, buf, &body) == SIEVE_OK)))
	    found = look_for_me(myaddr, numaddresses, bc, i, body);
	if (!found)
	    l = SIEVE_DONE;
    }
    /* ok, ok, if we got here maybe we should reply */
    if (myaddr) free(myaddr);
    *from=found;
    *to=reply_to;
    return l;
}

/* Evaluate a bytecode test */
int eval_bc_test(sieve_interp_t *interp, void* m,
		 bytecode_input_t * bc, int * ip)
{
    int res=0; 
    int i=*ip;
    int x,y,z;/* loop variable */
    int list_len; /* for allof/anyof/exists */
    int list_end; /* for allof/anyof/exists */
    int address=0;/*to differentiate between address and envelope*/
    comparator_t * comp=NULL;
    void * comprock=NULL;
    int op= ntohl(bc[i].op);
    
    switch(op)
    {
    case BC_FALSE:
	res=0; i++; break;

    case BC_TRUE:
	res=1; i++; break;

    case BC_NOT:/*2*/
	i+=1;
	res = eval_bc_test(interp,m, bc, &i);
	if(res >= 0) res = !res; /* Only invert in non-error case */
	break;

    case BC_EXISTS:/*3*/
    {
	int headersi=i+1;
	const char** val;
	int currh;

	res=1;

	list_len=ntohl(bc[headersi].len);
	list_end=ntohl(bc[headersi+1].value)/4;

	currh=headersi+2;

	for(x=0; x<list_len && res; x++)
	{
	    const char *str;

	    currh = unwrap_string(bc, currh, &str, NULL);
	    
	    if(interp->getheader(m,str, &val) != SIEVE_OK)
		res = 0;
	}

	i=list_end; /* adjust for short-circuit */
	break;
    }
    case BC_SIZE:/*4*/
    {
	int s;
	int sizevar=ntohl(bc[i+1].value);
	int x=ntohl(bc[i+2].value);
	
	if (interp->getsize(m, &s) != SIEVE_OK)
	    break;
	
	if (sizevar ==B_OVER) {
	    /* over */
	    res= s > x;
	} else {
            /* under */
	    res= s < x;
	}
	i+=3;
	break;
    }
    case BC_ANYOF:/*5*/
	res = 0;
	list_len=ntohl(bc[i+1].len);
	list_end=ntohl(bc[i+2].len)/4;
	i+=3;

	/* need to process all of them, to ensure our instruction pointer stays
	 * in the right place */
	for (x=0; x<list_len && !res; x++) { 
	    int tmp;
	    tmp = eval_bc_test(interp,m,bc,&i);
	    if(tmp < 0) {
		res = tmp;
		break;
	    }
	    res = res || tmp;
	}

	i = list_end; /* handle short-circuting */

	break; 
    case BC_ALLOF:/*6*/ 
        res = 1;     
	list_len=ntohl(bc[i+1].len);
	list_end=ntohl(bc[i+2].len)/4;
	i+=3;

	/* return 1 unless you find one that isn't true, then return 0 */
	for (x=0; x<list_len && res; x++) {
	    int tmp;
	    tmp = eval_bc_test(interp,m,bc,&i);
	    if(tmp < 0) {
		res = tmp;
		break;
	    }
	    res = res && tmp; 
	}

	i = list_end; /* handle short-circuiting */
	
	break;
    case BC_ADDRESS:/*7*/
	address=1;
	/* fall through */
    case BC_ENVELOPE:/*8*/
    {
	const char ** val;
	void * data=NULL;
	void * marker=NULL;
	char * addr;
	int addrpart=ADDRESS_ALL;/* XXX correct default behavior?*/

 	int headersi=i+5;/* the i value for the begining of the headers */
	int datai=(ntohl(bc[headersi+1].value)/4);

	int numheaders=ntohl(bc[headersi].len);
	int numdata=ntohl(bc[datai].len);

	int currh, currd; /* current header, current data */

	int match=ntohl(bc[i+1].value);
	int relation=ntohl(bc[i+2].value);
	int comparator=ntohl(bc[i+3].value);
	int apart=ntohl(bc[i+4].value);
	int count=0;
	char scount[3];
	int isReg = (match==B_REGEX);
	int ctag = 0;
	regex_t *reg;
	char errbuf[100]; /* Basically unused, as regexps are tested at compile */

	/* set up variables needed for compiling regex */
	if (isReg)
	{
	    if (comparator== B_ASCIICASEMAP)
	    {
		ctag = REG_EXTENDED | REG_NOSUB | REG_ICASE;
	    }
	    else
	    {
		ctag = REG_EXTENDED | REG_NOSUB;
	    }
	}

	/*find the correct comparator fcn*/
	comp = lookup_comp(comparator, match, relation, &comprock);

	if(!comp) {
	    res = SIEVE_RUN_ERROR;
	    break;
	}
	
	/*find the part of the address that we want*/
	switch(apart)
	{
	case B_ALL:
	    addrpart = ADDRESS_ALL; break;
	case B_LOCALPART:
	    addrpart = ADDRESS_LOCALPART; break;
	case B_DOMAIN:
	    addrpart = ADDRESS_DOMAIN; break;
	case B_USER:
	    addrpart = ADDRESS_USER; break;
	case B_DETAIL:
	    addrpart = ADDRESS_DETAIL; break;
	default:
	    /* this shouldn't happen with correcct bytecode */
	    res = SIEVE_RUN_ERROR;
	}

	if(res == SIEVE_RUN_ERROR) break;

	/*loop through all the headers*/
	currh=headersi+2;
#if VERBOSE
	printf("about to process %d headers\n", numheaders);
#endif
	for (x=0; x<numheaders && !res; x++)
	{
	    const char *this_header;

	    currh = unwrap_string(bc, currh, &this_header, NULL);
	    
	    /* Try the next string if we don't have this one */
	    if(address) {
		/* Header */
		if(interp->getheader(m, this_header, &val) != SIEVE_OK)
		    continue;
#if VERBOSE
                printf(" [%d] header %s is %s\n", x, this_header, val[0]);
#endif
	    } else {
		/* Envelope */
		if(interp->getenvelope(m, this_header, &val) != SIEVE_OK)
		    continue;
	    }
	
	    /*header exists, now to test it*/
	    /*search through all the headers that match*/
	    
	    for (y=0; val[y]!=NULL && !res; y++) {
		
#if VERBOSE
		printf("about to parse %s\n", val[y]);
#endif
		    
		if (parse_address(val[y], &data, &marker)!=SIEVE_OK) 
		    return 0;
		    
		while (!res &&
		       (addr = get_address(addrpart, &data, &marker, 0))) {
#if VERBOSE
		    printf("working addr %s\n", (addr ? addr : "[nil]"));
#endif
			
		    if (match == B_COUNT) {
			count++;
		    } else {
			/*search through all the data*/ 
			currd=datai+2;
			for (z=0; z<numdata && !res; z++)
			{
			    const char *data_val;
			    
			    currd = unwrap_string(bc, currd, &data_val, NULL);

			    if (isReg) {
				reg = bc_compile_regex(data_val, ctag,
						       errbuf, sizeof(errbuf));
				if (!reg) {
				    /* Oops */
				    res=-1;
				    goto alldone;
				}

				res |= comp(val[y], (const char *)reg,
					    comprock);
				free(reg);
			    } else {
#if VERBOSE
				printf("%s compared to %s(from script)\n",
				       addr, data_val);
#endif 
				res |= comp(addr, data_val, comprock);
			    }
			} /* For each data */
		    }
		} /* For each address */

		free_address(&data, &marker);
	    }/* For each message header */
	    
#if VERBOSE
	    printf("end of loop, res is %d, x is %d (%d)\n", res, x, numheaders);
#endif	    
	} /* For each script header */
     
	if  (match == B_COUNT)
	{
	    sprintf(scount, "%u", count);
	    /* search through all the data */ 
	    currd=datai+2;
	    for (z=0; z<numdata && !res; z++)
	    {
		const char *data_val;
		
		currd = unwrap_string(bc, currd, &data_val, NULL);

		res |= comp(scount, data_val, comprock);
	    }
	}

	/* Update IP */
	i=(ntohl(bc[datai+1].value)/4);
	
	break;
    }
    case BC_HEADER:/*9*/
    {
	const char** val;

	int headersi=i+4;/*the i value for the begining of hte headers*/
	int datai=(ntohl(bc[headersi+1].value)/4);

	int numheaders=ntohl(bc[headersi].len);
	int numdata=ntohl(bc[datai].len);

	int currh, currd; /*current header, current data*/

	int match=ntohl(bc[i+1].value);
	int relation=ntohl(bc[i+2].value);
	int comparator=ntohl(bc[i+3].value);
	int count=0;	
	char scount[3];
	int isReg = (match==B_REGEX);
	int ctag = 0;
	regex_t *reg;
	char errbuf[100]; /* Basically unused, regexps tested at compile */ 

	/* set up variables needed for compiling regex */
	if (isReg)
	{
	    if (comparator== B_ASCIICASEMAP)
	    {
		ctag= REG_EXTENDED | REG_NOSUB | REG_ICASE;
	    }
	    else
	    {
		ctag= REG_EXTENDED | REG_NOSUB;
	    }
     
	}
	
	/*find the correct comparator fcn*/
	comp=lookup_comp(comparator, match, relation, &comprock);

	if(!comp) {
	    res = SIEVE_RUN_ERROR;
	    break;
	}

	/*search through all the flags for the header*/
	currh=headersi+2;
	for(x=0; x<numheaders && !res; x++)
	{
	    const char *this_header;
	    
	    currh = unwrap_string(bc, currh, &this_header, NULL);
	   
	    if(interp->getheader(m, this_header, &val) != SIEVE_OK) {
		continue; /*this header does not exist, search the next*/ 
	    }
#if VERBOSE
	    printf ("val %s %s %s\n", val[0], val[1], val[2]);
#endif
	    
	    /* search through all the headers that match */
	    
	    for (y=0; val[y]!=NULL && !res; y++)
	    {
		if  (match == B_COUNT) {
		    count++;
		} else {
		    /*search through all the data*/ 
		    currd=datai+2;
		    for (z=0; z<numdata && !res; z++)
		    {
			const char *data_val;
			
			currd = unwrap_string(bc, currd, &data_val, NULL);
			
			if (isReg) {
			    reg= bc_compile_regex(data_val, ctag, errbuf,
						  sizeof(errbuf));
			    if (!reg)
			    {
				/* Oops */
				res=-1;
				goto alldone;
			    }
			    
			    res |= comp(val[y], (const char *)reg,
					comprock);
			    free(reg);
			} else {
			    res |= comp(val[y], data_val, comprock);
			}
		    }
		}
	    }
	}
	
	if  (match == B_COUNT )
	{
	    sprintf(scount, "%u", count);
	    /*search through all the data*/ 
	    currd=datai+2;
	    for (z=0; z<numdata && !res; z++)
	    { 	
		const char *data_val;
			
		currd = unwrap_string(bc, currd, &data_val, NULL);
#if VERBOSE
		printf("%d, %s \n", count, data_val);
#endif
		res |= comp(scount, data_val, comprock);
	    }
	      
	}

	/* Update IP */
	i=(ntohl(bc[datai+1].value)/4);
	
	break;
    }
    default:
#if VERBOSE
	printf("WERT, can't evaluate if statement. %d is not a valid command",
	       op);
#endif     
	return SIEVE_RUN_ERROR;
    }
    
  
 alldone:
    
    *ip=i;
    return res;
}

/* The entrypoint for bytecode evaluation */
int sieve_eval_bc(sieve_interp_t *i, const void *bc_in, unsigned int bc_len,
		  void *m, sieve_imapflags_t * imapflags,
		  action_list_t *actions,
		  notify_list_t *notify_list,
		  const char **errmsg) 
{
    const char *data;
    unsigned int ip = 0, ip_max = (bc_len/sizeof(bytecode_input_t));
    int res=0;
    int op;
    int version;
    
    bytecode_input_t *bc = (bytecode_input_t *)bc_in;
    
    /* Check that we
     * a) have bytecode
     * b) it is atleast long enough for the magic number, the version
     *    and one opcode */
    if(!bc) return SIEVE_FAIL;
    if(bc_len < (BYTECODE_MAGIC_LEN + 2*sizeof(bytecode_input_t)))
       return SIEVE_FAIL;

    if(memcmp(bc, BYTECODE_MAGIC, BYTECODE_MAGIC_LEN)) {
	*errmsg = "Not a bytecode file";
	return SIEVE_FAIL;
    }

    ip = BYTECODE_MAGIC_LEN / sizeof(bytecode_input_t);

    version= ntohl(bc[ip].op);

    /* this is because there was a time where integers were not network byte
       order.  all the scripts written then would have version 0x01 written
       in host byte order.*/

     if(version == ntohl(1)) {
	if(errmsg) {
	    *errmsg =
		"Incorrect Bytecode Version, please recompile (use sievec)";
	    
	}
	return SIEVE_FAIL;
    }
    
    if( version != BYTECODE_VERSION) {
	if(errmsg) {
	    *errmsg =
		"Incorrect Bytecode Version, please recompile (use sievec)";
	}
	return SIEVE_FAIL;
    }

#if VERBOSE
    printf("version number %d\n",version); 
#endif

    for(ip++; ip<ip_max; ) { 
	op=ntohl(bc[ip].op);
	switch(op) {
	case B_STOP:/*0*/
	    res=1;
	    break;

	case B_KEEP:/*1*/
	    res = do_keep(actions, imapflags);
	    if (res == SIEVE_RUN_ERROR)
		*errmsg = "Keep can not be used with Reject";
	    ip++;
	    break;

	case B_DISCARD:/*2*/
	    res=do_discard(actions);
	    ip++;
	    break;

	case B_REJECT:/*3*/
	    ip = unwrap_string(bc, ip+1, &data, NULL);
	    
	    res = do_reject(actions, data);
	
	    if (res == SIEVE_RUN_ERROR)
		*errmsg = "Reject can not be used with any other action";  

	    break;

	case B_FILEINTO:/*4*/
	{
	    ip = unwrap_string(bc, ip+1, &data, NULL);

	    res = do_fileinto(actions, data, imapflags);

	    if (res == SIEVE_RUN_ERROR)
		*errmsg = "Fileinto can not be used with Reject";

	    break;
	}

	case B_REDIRECT:/*5*/
	{
	    ip = unwrap_string(bc, ip+1, &data, NULL);

	    res = do_redirect(actions, data);

	    if (res == SIEVE_RUN_ERROR)
		*errmsg = "Redirect can not be used with Reject";

	    break;
	}

	case B_IF:/*6*/
	{
	    int testend=ntohl(bc[ip+1].value);
	    int result;
	   
	    ip+=2;
	    result=eval_bc_test(i, m, bc, &ip);
	    
	    if (result<0) {
		*errmsg = "Invalid test";
		return SIEVE_FAIL;
	    } else if (result) {
	    	/*skip over jump instruction*/
		testend+=2;
	    }
	    ip=testend;
	    
	    break;
	}

	case B_MARK:/*8*/
	    res = do_mark(actions);
	    ip++;
	    break;

	case B_UNMARK:/*9*/
	    res = do_unmark(actions);
	    ip++;
	    break;

	case B_ADDFLAG:/*10*/ 
	{
	    int x;
	    int list_len=ntohl(bc[ip+1].len);

	    ip+=3; /* skip opcode, list_len, and list data len */

	    for (x=0; x<list_len; x++) {
		ip = unwrap_string(bc, ip, &data, NULL);
		
		res = do_addflag(actions, data);

		if (res == SIEVE_RUN_ERROR)
		    *errmsg = "addflag can not be used with Reject";
	    } 
	    break;
	}

	case B_SETFLAG:
	{
	    int x;
	    int list_len=ntohl(bc[ip+1].len);

	    ip+=3; /* skip opcode, list_len, and list data len */

	    ip = unwrap_string(bc, ip, &data, NULL);

	    res = do_setflag(actions, data);

	    if (res == SIEVE_RUN_ERROR) {
		*errmsg = "setflag can not be used with Reject";
	    } else {
		for (x=1; x<list_len; x++) {
		    ip = unwrap_string(bc, ip, &data, NULL);

		    res = do_addflag(actions, data);

		    if (res == SIEVE_RUN_ERROR)
			*errmsg = "setflag can not be used with Reject";
		} 
	    }
	    
	    break;
	}

	case B_REMOVEFLAG:
	{
	    int x;
	    int list_len=ntohl(bc[ip+1].len);

	    ip+=3; /* skip opcode, list_len, and list data len */

	    for (x=0; x<list_len; x++) {
		ip = unwrap_string(bc, ip, &data, NULL);

		res = do_removeflag(actions, data);

		if (res == SIEVE_RUN_ERROR)
		    *errmsg = "removeflag can not be used with Reject";
	    } 
	    break;
	}

	case B_NOTIFY:
	{
	    const char * id;
	    const char * method;
	    const char **options = NULL;
	    const char *priority = NULL;
	    const char * message;
	    int pri;
	    
	    ip++;

	    /* method */
	    ip = unwrap_string(bc, ip, &method, NULL);

	    /* id */
	    ip = unwrap_string(bc, ip, &id, NULL);

	    /*options*/
	    options=bc_makeArray(bc, &ip); 

	    /* priority */
	    pri=ntohl(bc[ip].value);
	    ip++;
	    
	    switch (pri)
	    {
	    case B_LOW:
		priority="low";
	    case B_NORMAL:
		priority="normal";
		break;
	    case B_HIGH: 
		priority="high";
		break; 
	    case B_ANY:
		priority="any";
		break;
	    default:
		res=SIEVE_RUN_ERROR;
	    }

	    /* message */
	    ip = unwrap_string(bc, ip, &message, NULL);
	  
	    res = do_notify(notify_list, id, method, options,
			    priority, message);

	    free(options);
	 	  
	    break;
	}
	case B_DENOTIFY:
	{
         /*
	  * i really have no idea what the count matchtype should do here.
	  * the sanest thing would be to use 1.
	  * however that would require passing on the match type to do_notify.
	  *  -jsmith2
	  */

	    comparator_t *comp = NULL;
	    
	    const char *pattern;
	    regex_t *reg;
	    
	    const char *priority = NULL;
	    void *comprock = NULL;
	    
	    int comparator;
	    int pri;
	    
	    ip++;
	    pri=ntohl(bc[ip].value);
	    ip++;
	    
	    switch (pri)
	    {
	    case B_LOW:
		priority="low";		
	    case B_NORMAL:
		priority="normal";
		break;
	    case B_HIGH: 
		priority="high";
		break; 
	    case B_ANY:
		priority="any";
		break;
	    default:
		res=SIEVE_RUN_ERROR;
	    }

	    if(res == SIEVE_RUN_ERROR)
		break;
	   
	    comparator =ntohl( bc[ip].value);
	    ip++;
	    
	    if (comparator == B_ANY)
	    { 
		ip++;/* skip placeholder this has no comparator function */
		comp=NULL;
	    } else {
		int x= ntohl(bc[ip].value);
		ip++;
		
		comp=lookup_comp(B_ASCIICASEMAP,comparator,
				 x, &comprock);
	    }
	    
	    ip = unwrap_string(bc, ip, &pattern, NULL);
	  
	    if (comparator == B_REGEX)
	    {	
		char errmsg[1024]; /* Basically unused */
		
		reg=bc_compile_regex(pattern,
				     REG_EXTENDED | REG_NOSUB | REG_ICASE,
				     errmsg, sizeof(errmsg));
		if (!reg) {
		    res = SIEVE_RUN_ERROR;
		} else {
		    res = do_denotify(notify_list, comp, reg,
				      comprock, priority);
		    free(reg);
		}
	    } else {
		res = do_denotify(notify_list, comp, pattern,
				  comprock, priority);
	    }
	    
	    break;
	}
	case B_VACATION:
	{
	    int respond;
	    char *fromaddr = NULL; /* relative to message we send */
	    char *toaddr = NULL; /* relative to message we send */
	    const char *message = NULL;
	    char buf[128];
	    char subject[1024];
	    int x;
	    
	    ip++;

	    x=ntohl( bc[ip].len);
	    
	    respond=shouldRespond(m, i, x, bc, ip+2,
				  &fromaddr, &toaddr);
	    
	    ip=(ntohl(bc[ip+1].value)/4);	
	    if (respond==SIEVE_OK)
	    {	 
		ip = unwrap_string(bc, ip, &data, NULL);
		
		if (!data) 
		{
		    /* we have to generate a subject */
		    const char **s;	    
		    strlcpy(buf, "subject", sizeof(buf));
		    if (i->getheader(m, buf, &s) != SIEVE_OK ||
			s[0] == NULL) {
			strlcpy(subject, "Automated reply", sizeof(subject));
		    } else {
			/* s[0] contains the original subject */
			const char *origsubj = s[0];

			while (!strncasecmp(origsubj, "Re: ", 4)) 
			    origsubj += 4;

			snprintf(subject, sizeof(subject), "Re: %s", origsubj);
		    }
		} else {
		    /* user specified subject */
		    strlcpy(subject, data, sizeof(subject));
		}
		
		ip = unwrap_string(bc, ip, &message, NULL);

		res = do_vacation(actions, toaddr, fromaddr,
				  xstrdup(subject), message,
				  ntohl(bc[ip].value), ntohl(bc[ip+1].value));

		ip+=2;		

		if (res == SIEVE_RUN_ERROR)
		    *errmsg = "Vacation can not be used with Reject or Vacation";
	    } else if (respond == SIEVE_DONE) {
                /* skip subject and message */

		ip = unwrap_string(bc, ip, &data, NULL);
		ip = unwrap_string(bc, ip, &data, NULL);

		ip+=2;/*skip days and mime flag*/
	    } else {
		res = SIEVE_RUN_ERROR; /* something is bad */ 
	    }

	    break;
	}
	case B_NULL:/*15*/
	    ip++;
	    break;

	case B_JUMP:/*16*/
	    ip= ntohl(bc[ip+1].jump);
	    break;
	    
	default:
	    if(errmsg) *errmsg = "Invalid sieve bytecode";
	    return SIEVE_FAIL;
	}
      
	if (res) /* we've either encountered an error or a stop */
	    break;
    }
    return res;      
}
