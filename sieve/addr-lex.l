%{
/*
 * addr-lex.l -- RFC 822 address lexer
 * Ken Murchison
 * $Id: addr-lex.l,v 1.8 2002/02/19 18:09:46 ken3 Exp $
 */
/***********************************************************
        Copyright 1999 by Carnegie Mellon University

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

#include "addr.h"
#include <string.h>

#undef YY_INPUT
#define YY_INPUT(b, r, ms) (r = addrinput(b, ms))

int addrinput(char *buf, int max_size);
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
int addrinput(char *buf, int max_size)
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
