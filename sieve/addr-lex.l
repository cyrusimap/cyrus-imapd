%{
/*
 * addr-lex.l -- RFC 822 address lexer
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
 * $Id: addr-lex.l,v 1.11 2008/03/24 20:08:46 murch Exp $
 */

#include "addr.h"
#include <stdlib.h>
#include <string.h>

#undef YY_INPUT
#define YY_INPUT(b, r, ms) (r = addrinput(b, ms))

int addrinput(char *buf, size_t max_size);
void addrerror(const char *);

static int ncom;	/* number of open comments */
%}

%option noyywrap
%option nounput
%option prefix="addr"

%x QSTRING DOMAINLIT COMMENT

%%

\"				{ BEGIN QSTRING; return yytext[0]; }
\[				{ BEGIN DOMAINLIT; return yytext[0]; }
\(				{ ncom = 1; BEGIN COMMENT; }
\)				{ addrerror("address parse error, "
					  "unexpected `')'' "
					  "(unbalanced comment)");
				  yyterminate(); }

[^\(\)<>@,;:\\".\[\] \n\r]+	return ATOM;

[\t \n\r]+			/* ignore whitespace */
.				return yytext[0];

<QSTRING>([^\n\r"\\]|\\.)*	return QTEXT;
<QSTRING>\"			{ BEGIN INITIAL; return yytext[0]; }

<DOMAINLIT>([^\[\]\n\r\\]|\\.)*	return DTEXT;
<DOMAINLIT>\]			{ BEGIN INITIAL; return yytext[0]; }

<COMMENT>([^\(\)\n\0\\]|\\.)*	/* ignore comments */
<COMMENT>\(			ncom++;
<COMMENT>\)			{ ncom--; if (ncom == 0) BEGIN INITIAL; }
<COMMENT><<EOF>>		{ addrerror("address parse error, "
					  "expecting `')'' "
					  "(unterminated comment)");
				  yyterminate(); }

%%

/* take input from address string provided by sieve parser */
int addrinput(char *buf, size_t max_size)
{
    extern char *addrptr;	/* current position in address string */
    size_t n;			/* number of characters to read from string */

    n = strlen(addrptr) < max_size ? strlen(addrptr) : max_size;
    if (n > 0) {
	memcpy(buf, addrptr, n);
	addrptr += n;
    }
    return n;
}
