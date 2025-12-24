%{
/* addr-lex.l -- RFC 822 address lexer */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include "sieve/sieve_interface.h"
#include "sieve/addr.h"

void addrerror(void*, const char *);

static int ncom;        /* number of open comments */
#define YY_DECL int addrlex(YYSTYPE* addrlval __attribute__((unused)), void* parse_script)
%}

%option noyywrap
%option nounput
%option noinput
%option prefix="addr" outfile="lex.yy.c"

%x QSTRING DOMAINLIT COMMENT

%%

\"                              { BEGIN QSTRING; return yytext[0]; }
\[                              { BEGIN DOMAINLIT; return yytext[0]; }
\(                              { ncom = 1; BEGIN COMMENT; }
\)                              { addrerror(parse_script, "address parse error, "
                                          "unexpected `')'' "
                                          "(unbalanced comment)");
                                  yyterminate(); }

[^\(\)<>@,;:\\".\[\] \n\r]+     return ATOM;

[\t \n\r]+                      /* ignore whitespace */
.                               return yytext[0];

<QSTRING>([^\n\r"\\]|\\.)*      return QTEXT;
<QSTRING>\"                     { BEGIN INITIAL; return yytext[0]; }
<QSTRING><<EOF>>                { BEGIN INITIAL;
                                  addrerror(parse_script, "address parse error, expecting `'\"'' (unterminated string)");
                                  yyterminate(); }

<DOMAINLIT>([^\[\]\n\r\\]|\\.)* return DTEXT;
<DOMAINLIT>\]                   { BEGIN INITIAL; return yytext[0]; }
<DOMAINLIT><<EOF>>              { BEGIN INITIAL;
                                  addrerror(parse_script, "address parse error, expecting `']'' (unterminated domain literal)");
                                  yyterminate(); }



<COMMENT>([^\(\)\n\0\\]|\\.)*   /* ignore comments */
<COMMENT>\(                     ncom++;
<COMMENT>\)                     { ncom--; if (ncom == 0) BEGIN INITIAL; }
<COMMENT><<EOF>>                { BEGIN INITIAL;
                                  addrerror(parse_script, "address parse error, "
                                          "expecting `')'' "
                                          "(unterminated comment)");
                                  yyterminate(); }

%%
