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

/* $Id: protocol.c,v 1.12 2004/08/04 13:03:16 ken3 Exp $ */

#include <config.h>

#include <ctype.h>
#include <string.h>
#include <limits.h>

#include "protocol.h"
#include "xmalloc.h"

static char *imap_parsemechlist(const char *str, struct protocol_t *prot)
{
    char *ret = xzmalloc(strlen(str)+1);
    char *tmp;
    int num = 0;
    
    if (strstr(str, "SASL-IR")) {
	/* server supports initial response in AUTHENTICATE command */
	prot->sasl_cmd.maxlen = INT_MAX;
    }
    
    while ((tmp = strstr(str, "AUTH="))) {
	char *end = (tmp += 5);
	
	while((*end != ' ') && (*end != '\0')) end++;
	
	/* add entry to list */
	if (num++ > 0) strcat(ret, " ");
	strlcat(ret, tmp, strlen(ret) + (end - tmp) + 1);
	
	/* reset the string */
	str = end + 1;
    }
    
    return ret;
}

static char *nntp_parsemechlist(const char *str,
				struct protocol_t *prot __attribute__((unused)))
{
    char *ret;
    char *tmp;
    int num = 0;
    
    tmp = strstr(str, " SASL:") + 6;
    if (isspace((int) *tmp)) return NULL;

    ret = xzmalloc(strlen(tmp)+1);
    do {
	char *end = tmp;
	
	while ((*end != ',') && (*end != ' ') && (*end != '\0')) end++;
	
	/* add entry to list */
	if (num++ > 0) strcat(ret, " ");
	strlcat(ret, tmp, strlen(ret) + (end - tmp) + 1);

	/* reset the string */
	tmp = end;

    } while (*tmp++ != '\0');
    
    return ret;
}

static char *nntp_parsesuccess(char *str, const char **status)
{
    char *success = NULL;

    if (!strncmp(str, "283 ", 4)) {
	success = str+4;
    }

    if (status) *status = NULL;
    return success;
}

struct protocol_t protocol[] = {
    { "imap", "imap",
      { "C01 CAPABILITY", "C01 ", &imap_parsemechlist,
	{ { " AUTH=", CAPA_AUTH },
	  { " STARTTLS", CAPA_STARTTLS },
	  { " IDLE", CAPA_IDLE },
	  { " MUPDATE", CAPA_MUPDATE },
	  { " MULTIAPPEND", CAPA_MULTIAPPEND },
	  { NULL, 0 } } },
      { "S01 STARTTLS", "S01 OK", "S01 NO" },
      { "A01 AUTHENTICATE", 0, 0, "A01 OK", "A01 NO", "+ ", "*", NULL },
      { "N01 NOOP", "N01 OK" },
      { "Q01 LOGOUT", "Q01 " } },
    { "pop3", "pop",
      { "CAPA", ".", NULL,
	{ { "SASL ", CAPA_AUTH },
	  { "STLS", CAPA_STARTTLS },
	  { NULL, 0 } } },
      { "STLS", "+OK", "-ERR" },
      { "AUTH", 255, 0, "+OK", "-ERR", "+ ", "*", NULL },
      { "NOOP", "+OK" },
      { "QUIT", "+OK" } },
    { "nntp", "nntp",
      { "LIST EXTENSIONS", ".", &nntp_parsemechlist,
	{ { " SASL:", CAPA_AUTH },
	  { "STARTTLS", CAPA_STARTTLS },
	  { NULL, 0 } } },
      { "STARTTLS", "382", "580" },
      { "AUTHINFO SASL", 512, 0, "28", "5", "383 ", "*", &nntp_parsesuccess },
      { "DATE", "111" },
      { "QUIT", "205" } },
    { "lmtp", "lmtp",
      { "LHLO murder", "250 ", NULL,
	{ { "AUTH ", CAPA_AUTH },
	  { "STARTTLS", CAPA_STARTTLS },
	  { "PIPELINING", CAPA_PIPELINING },
	  { "IGNOREQUOTA", CAPA_IGNOREQUOTA },
	  { NULL, 0 } } },
      { "STARTTLS", "220", "454" },
      { "AUTH", 512, 0, "235", "5", "334 ", "*", NULL },
      { "NOOP", "250" },
      { "QUIT", "221" } },
    { "mupdate", "mupdate",
      { NULL, "* OK", NULL,
	{ { "* AUTH ", CAPA_AUTH },
	  { NULL, 0 } } },
      { "S01 STARTTLS", "S01 OK", "S01 NO" },
      { "A01 AUTHENTICATE", INT_MAX, 1, "A01 OK", "A01 NO", "", "*", NULL },
      { "N01 NOOP", "N01 OK" },
      { "Q01 LOGOUT", "Q01 " } }
};
