%{
/* sieve.l -- sieve lexer
 * Larry Greenfield
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

#include <string.h> /* for strdup */
#include "tree.h"
#include "sieve.tab.h"

static int tonum(char *c);
static char *fixstr(char *);
static char *mlbuf;
static int mlbufsz, mlcur;
%}

%option yylineno

ws		[ \t]+
ident		[a-zA-Z_][a-zA-Z_0-9]*
CRLF		(\r\n|\r|\n)

%state MULTILINE

%%
<MULTILINE>^\.{CRLF}	{ BEGIN INITIAL; yylval.sval = mlbuf; return STRING; }
<MULTILINE>^\.\.  { /* dot stuffing! we want one . */ yyless(1); }
<MULTILINE>(.|\n) { if (mlcur == mlbufsz) 
			mlbuf = realloc(mlbuf, mlbufsz+=1024);
		    mlbuf[mlcur++] = yytext[0]; }
text:{ws}?(#.*)?{CRLF}	{ BEGIN MULTILINE;
			  mlcur = 0; mlbufsz = 0; mlbuf = NULL; }
[0-9]+[KMG]?	{ yylval.nval = tonum(yytext); return NUMBER; }
if		return IF;
elsif		return ELSIF;
else		return ELSE;
anyof		return ANYOF;
allof		return ALLOF;
exists		return EXISTS;
false		return FALSE;
true		return TRUE;
address		return ADDRESS;
envelope        return ENVELOPE;
header		return HEADER;
not		return NOT;
size		return SIZE;
reject		return REJCT;
fileinto	return FILEINTO;
redirect	return FORWARD;
keep		return KEEP;
require         return REQUIRE;
stop		return STOP;
discard		return DISCARD;
vacation	return VACATION;
:days		return DAYS;
:addresses	return ADDRESSES;
:subject	return SUBJECT;
:mime		return MIME;
:comparator	return COMPARATOR;
:is		return IS;
:contains	return CONTAINS;
:matches	return MATCHES;
:over		return OVER;
:under		return UNDER;
:all		return ALL;
:localpart	return LOCALPART;
:domain		return DOMAIN;
\"([^"]|\\.)*\"	{ yylval.sval = fixstr(yytext); return STRING; }
[ \t\n\r] ;	/* ignore whitespace */
#.* ;		/* ignore comments */
.		return yytext[0];

%%
static int tonum(char *c)
{
  int val = atoi(c);
  switch (c[strlen(c)-1]) {
  case 'K': val *= (2 << 10); break;
  case 'M': val *= (2 << 20); break;
  case 'G': val *= (2 << 30); break;
  default: break;
  }
  return val;
}

static char *fixstr(char *str)
{
    char *r, *s = (char *) malloc(sizeof(char) * strlen(str));

    r = s;
    str++; /* skip open " */
    while (*str != '"') {
	if (*str == '\\')
	    str++;
	*s++ = *str++;
    }
    *s = '\0';
    return r;
}

/* i don't want to have to link in the library */
int yywrap() 
{
   return 1;
}

