%{
/*
 * addr-lex.y -- RFC 822 address parser
 */

#include "addr.h"
#include <string.h>

#undef YY_INPUT
#define YY_INPUT(b, r, ms) (r = addrinput(b, ms))

static int ncom;	/* number of open comments */
%}

%option noyywrap
%x QSTRING DOMAINLIT COMMENT

%%

\"				{ BEGIN QSTRING; return yytext[0]; }
\[				{ BEGIN DOMAINLIT; return yytext[0]; }
\(				{ ncom = 1; BEGIN COMMENT; }
\)				{ yyerror("address parse error, "
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
<COMMENT><<EOF>>		{ yyerror("address parse error, "
					  
					  "expecting `')'' "
					  "(unterminated comment)");
				  yyterminate(); }

%%

extern char *addrptr;	/* current position in address string */

int addrinput(char *buf, int max_size)
{
    int n = strlen(addrptr) < max_size ? strlen(addrptr) : max_size;

    if (n > 0) {
	memcpy(buf, addrptr, n);
	addrptr += n;
    }
    return n;
}
