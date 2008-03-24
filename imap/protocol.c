/* protocol.c -- client-side protocol abstraction
 *
 * Copyright (c) 1994-2008 Carnegie Mellon University.  All rights reserved.
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
 *
 * $Id: protocol.c,v 1.17 2008/03/24 17:09:18 murch Exp $
 */

#include <config.h>

#include <ctype.h>
#include <string.h>
#include <limits.h>

#include "protocol.h"
#include "xmalloc.h"
#include "xstrlcat.h"

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

static char *nntp_parsesuccess(char *str, const char **status)
{
    char *success = NULL;

    if (!strncmp(str, "283 ", 4)) {
	success = str+4;
    }

    if (status) *status = NULL;
    return success;
}

static char *sieve_parsesuccess(char *str, const char **status)
{
    char *success = NULL, *tmp;

    if (!strncmp(str, "OK (", 4) &&
	(tmp = strstr(str+4, "SASL \"")) != NULL) {
	success = tmp+6; /* skip SASL " */
	tmp = strstr(success, "\"");
	*tmp = '\0'; /* clip " */
    }

    if (status) *status = NULL;
    return success;
}

struct protocol_t protocol[] = {
    { "imap", "imap",
      { 0, "* OK" },
      { "C01 CAPABILITY", "C01 ", &imap_parsemechlist,
	{ { " AUTH=", CAPA_AUTH },
	  { " STARTTLS", CAPA_STARTTLS },
	  { " IDLE", CAPA_IDLE },
	  { " MUPDATE", CAPA_MUPDATE },
	  { " MULTIAPPEND", CAPA_MULTIAPPEND },
	  { " LIST-SUBSCRIBED", CAPA_LISTSUBSCRIBED },
	  { " RIGHTS=kxte", CAPA_ACLRIGHTS },
	  { NULL, 0 } } },
      { "S01 STARTTLS", "S01 OK", "S01 NO" },
      { "A01 AUTHENTICATE", 0, 0, "A01 OK", "A01 NO", "+ ", "*", NULL },
      { "N01 NOOP", "* ", "N01 OK" },
      { "Q01 LOGOUT", "* ", "Q01 " } },
    { "pop3", "pop",
      { 0, "+OK " },
      { "CAPA", ".", NULL,
	{ { "SASL ", CAPA_AUTH },
	  { "STLS", CAPA_STARTTLS },
	  { NULL, 0 } } },
      { "STLS", "+OK", "-ERR" },
      { "AUTH", 255, 0, "+OK", "-ERR", "+ ", "*", NULL },
      { "NOOP", NULL, "+OK" },
      { "QUIT", NULL, "+OK" } },
    { "nntp", "nntp",
      { 0, "20" },
      { "CAPABILITIES", ".", NULL,
	{ { "SASL ", CAPA_AUTH },
	  { "STARTTLS", CAPA_STARTTLS },
	  { NULL, 0 } } },
      { "STARTTLS", "382", "580" },
      { "AUTHINFO SASL", 512, 0, "28", "48", "383 ", "*", &nntp_parsesuccess },
      { "DATE", NULL, "111" },
      { "QUIT", NULL, "205" } },
    { "lmtp", "lmtp",
      { 0, "220 " },
      { "LHLO murder", "250 ", NULL,
	{ { "AUTH ", CAPA_AUTH },
	  { "STARTTLS", CAPA_STARTTLS },
	  { "PIPELINING", CAPA_PIPELINING },
	  { "IGNOREQUOTA", CAPA_IGNOREQUOTA },
	  { NULL, 0 } } },
      { "STARTTLS", "220", "454" },
      { "AUTH", 512, 0, "235", "5", "334 ", "*", NULL },
      { "NOOP", NULL, "250" },
      { "QUIT", NULL, "221" } },
    { "mupdate", "mupdate",
      { 1, "* OK" },
      { NULL, "* OK", NULL,
	{ { "* AUTH ", CAPA_AUTH },
	  { "* STARTTLS", CAPA_STARTTLS },
	  { NULL, 0 } } },
      { "S01 STARTTLS", "S01 OK", "S01 NO" },
      { "A01 AUTHENTICATE", INT_MAX, 1, "A01 OK", "A01 NO", "", "*", NULL },
      { "N01 NOOP", NULL, "N01 OK" },
      { "Q01 LOGOUT", NULL, "Q01 " } },
    { "sieve", SIEVE_SERVICE_NAME,
      { 1, "OK" },
      { "CAPABILITY", "OK", NULL,
	{ { "\"SASL\" ", CAPA_AUTH },
	  { "\"STARTTLS\"", CAPA_STARTTLS },
	  { NULL, 0 } } },
      { "STARTTLS", "OK", "NO" },
      { "AUTHENTICATE", INT_MAX, 1, "OK", "NO", NULL, "*", &sieve_parsesuccess },
      { NULL, NULL, NULL },
      { "LOGOUT", NULL, "OK" } },
    { "csync", "csync",
      { 1, "* OK" },
      { NULL, "* OK", NULL,
	{ { "* SASL ", CAPA_AUTH },
	  { "* STARTTLS", CAPA_STARTTLS },
	  { NULL, 0 } } },
      { "STARTTLS", "OK", "NO" },
      { "AUTHENTICATE", INT_MAX, 0, "OK", "NO", "+ ", "*", NULL },
      { "NOOP", NULL, "OK" },
      { "EXIT", NULL, "OK" } }
};
