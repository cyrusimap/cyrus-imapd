%{
/*
 * addr.y -- RFC 822 address parser
 * Ken Murchison
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
 * $Id: addr.y,v 1.14 2008/03/24 20:08:46 murch Exp $
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <string.h>

#include "addr.h"
#include "script.h"
#include "xmalloc.h"
#include "xstrlcpy.h"
    
int yyerror(char *msg);
extern int yylex(void);

#define YYERROR_VERBOSE /* i want better error messages! */
%}

%token ATOM QTEXT DTEXT

%%
sieve_address: addrspec			/* simple address */
	| phrase '<' addrspec '>'	/* name & addr-spec */
	;

addrspec: localpart '@' domain		/* global-address */
	;

localpart: word				/* uninterpreted, case-preserved */
	| word '.' localpart
	;

domain: subdomain
	| subdomain '.' domain
	;

subdomain: domainref
	| domainlit
	;

domainref: ATOM				/* symbolic reference */
	;

domainlit: '[' DTEXT ']'
	;

phrase: word
	| word phrase
	;

word: ATOM
	| qstring
	;

qstring: '"' QTEXT '"'
	;

%%

/* copy address error message into buffer provided by sieve parser */
int yyerror(char *s)
{
    extern char addrerr[ADDRERR_SIZE];
    
    strlcpy(addrerr, s, sizeof(addrerr));
    return 0;
}
