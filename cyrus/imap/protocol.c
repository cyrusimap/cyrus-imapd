/* protocol.c -- client-side protocol abstraction
 *
 * Copyright (c) 1998-2003 Carnegie Mellon University.  All rights reserved.
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
 *    prior written permission. For permission or any other legal
 *    details, please contact  
 *      Office of Technology Transfer
 *      Carnegie Mellon University
 *      5000 Forbes Avenue
 *      Pittsburgh, PA  15213-3890
 *      (412) 268-4387, fax: (412) 268-7395
 *      tech-transfer@andrew.cmu.edu
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

/* $Id: protocol.c,v 1.1.2.3 2003/02/13 20:33:00 rjs3 Exp $ */

#include <string.h>

#include "protocol.h"
#include "xmalloc.h"

static char *imap_parsemechlist(char *str)
{
    char *tmp;
    int num=0;
    char *ret=xmalloc(strlen(str)+1);
    
    ret[0] = '\0';
    
    while ((tmp=strstr(str,"AUTH="))!=NULL)
    {
	char *end=tmp+5;
	tmp+=5;
	
	while(((*end)!=' ') && ((*end)!='\0'))
	    end++;
	
	(*end)='\0';
	
	/* add entry to list */
	if (num>0)
	    strcat(ret," ");
	strcat(ret, tmp);
	num++;
	
	/* reset the string */
	str=end+1;
    }
    
    return ret;
}

static char *nntp_parsesuccess(char *str, const char **status)
{
    char *success = NULL;

    if (!strncmp(str, "251 ", 4)) {
	success = str+4;
    }

    if (status) *status = NULL;
    return success;
}

struct protocol_t protocol[] = {
    { "imap", "imap",
      { "C01 CAPABILITY", "C01 ", "STARTTLS", "AUTH=", &imap_parsemechlist },
      { "S01 STARTTLS", "S01 OK", "S01 NO" },
      { "A01 AUTHENTICATE", 0, NULL, "A01 OK", "A01 NO", "+ ", "*", NULL },
      { "Q01 LOGOUT", "Q01 " } },
    { "pop3", "pop",
      { "CAPA", ".", "STLS", "SASL ", NULL },
      { "STLS", "+OK", "-ERR" },
      { "AUTH", 0, "", "+OK", "-ERR", "+ ", "*", NULL },
      { "QUIT", "+OK" } },
    { "nntp", "nntp",
      { "LIST EXTENSIONS", ".", "STARTTLS", "SASL ", NULL },
      { "STARTTLS", "382", "580" },
      { "AUTHINFO SASL", 0, "", "25", "452", "351 ", "*", &nntp_parsesuccess },
      { "QUIT", "205" } },
    { "lmtp", "lmtp",
      { "LHLO murder", "250 ", "STARTTLS", "AUTH ", NULL },
      { "STARTTLS", "220", "454" },
      { "AUTH", 0, "=", "235", "5", "334 ", "*", NULL },
      { "QUIT", "221" } },
    { "mupdate", "mupdate",
      { NULL, "* OK", NULL, "* AUTH ", NULL },
      { NULL },
      { "A01 AUTHENTICATE", 1, "", "A01 OK", "A01 NO", "", "*", NULL },
      { "Q01 LOGOUT", "Q01 " } }
};
