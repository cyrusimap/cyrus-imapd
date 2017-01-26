%{
/* sieve.l -- sieve lexer
 * Larry Greenfield
 *
 * Copyright (c) 1994-2016 Carnegie Mellon University.  All rights reserved.
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
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "xmalloc.h"

#include "sieve/tree.h"
#include "sieve/sieve_interface.h"
#include "sieve/sieve.h"

#define YY_NO_INPUT
#define YY_DECL int yylex(YYSTYPE *yylval, sieve_script_t *parse_script)

static int tonum(char *c);
static char *chkstr(char *);
static char *mlbuf;
static int mlbufsz, mlcur;
extern void sieveerror(sieve_script_t *, char *);
%}

%option yylineno
%option noyywrap
%option nounput
%option prefix="sieve" outfile="lex.yy.c"

ws              [ \t]+
ident           [a-zA-Z_][a-zA-Z_0-9]*
CRLF            (\r\n|\r|\n)

%state MULTILINE
%state QSTRING

%%
<MULTILINE>^\.{CRLF}    { BEGIN INITIAL;
                          if (mlbuf) mlbuf[mlcur] = '\0';
                          yylval->sval = chkstr(mlbuf); return STRING; }
<MULTILINE>^\.\.  { /* dot stuffing! we want one . */ yyless(1); }
<MULTILINE>(.|\n) { if (mlcur == mlbufsz)
                        mlbuf = xrealloc(mlbuf, 1 + (mlbufsz+=1024));
                    mlbuf[mlcur++] = yytext[0]; }
<MULTILINE><<EOF>> { BEGIN INITIAL;
                     sieveerror(parse_script, "unexpected end of file in string");
                     if (mlbuf) free(mlbuf);
                     yyterminate(); }
<QSTRING>\"        { BEGIN INITIAL;
                     if (mlbuf) mlbuf[mlcur] = '\0';
                     yylval->sval = chkstr(mlbuf); return STRING; }
<QSTRING>\\.      { if (mlcur == mlbufsz)
                        mlbuf = xrealloc(mlbuf, 1 + (mlbufsz+=1024));
                    mlbuf[mlcur++] = yytext[1]; }
<QSTRING>(.|\n)   { if (mlcur == mlbufsz)
                        mlbuf = xrealloc(mlbuf, 1 + (mlbufsz+=1024));
                    mlbuf[mlcur++] = yytext[0]; }
<QSTRING><<EOF>>  { sieveerror(parse_script, "unexpected end of file in string");
                    if (mlbuf) free(mlbuf);
                    BEGIN INITIAL;
                    yyterminate(); }
<INITIAL>text:{ws}?(#.*)?{CRLF} { BEGIN MULTILINE;
                          mlcur = 0; mlbufsz = 0; mlbuf = NULL; }
<INITIAL>\"        { BEGIN QSTRING;
                    mlcur = 0; mlbufsz = 0; mlbuf = NULL; }
<INITIAL>[0-9]+[KMGkmg]?        { yylval->nval = tonum(yytext); return NUMBER; }
<INITIAL>if             return IF;
<INITIAL>elsif          return ELSIF;
<INITIAL>else           return ELSE;
<INITIAL>anyof          return ANYOF;
<INITIAL>allof          return ALLOF;
<INITIAL>exists         return EXISTS;
<INITIAL>false          return SFALSE;
<INITIAL>true           return STRUE;
<INITIAL>address        return ADDRESS;
<INITIAL>envelope       return ENVELOPE;
<INITIAL>header         return HEADER;
<INITIAL>body           return BODY;
<INITIAL>not            return NOT;
<INITIAL>size           return SIZE;
<INITIAL>hasflag        return yylval->nval = HASFLAG;
<INITIAL>string         return yylval->nval = STRINGT;
<INITIAL>reject         return REJCT;
<INITIAL>ereject        return EREJECT;
<INITIAL>fileinto       return FILEINTO;
<INITIAL>redirect       return REDIRECT;
<INITIAL>keep           return KEEP;
<INITIAL>require        return REQUIRE;
<INITIAL>stop           return STOP;
<INITIAL>discard        return DISCARD;
<INITIAL>setflag        return yylval->nval = SETFLAG;
<INITIAL>addflag        return yylval->nval = ADDFLAG;
<INITIAL>removeflag     return yylval->nval = REMOVEFLAG;
<INITIAL>mark           return MARK;
<INITIAL>unmark         return UNMARK;
<INITIAL>notify         return NOTIFY;
<INITIAL>denotify       return DENOTIFY;
<INITIAL>:id            return ID;
<INITIAL>:method        return METHOD;
<INITIAL>:options       return OPTIONS;
<INITIAL>:low           return LOW;
<INITIAL>:normal        return NORMAL;
<INITIAL>:high          return HIGH;
<INITIAL>:message       return MESSAGE;
<INITIAL>vacation       return VACATION;
<INITIAL>:days          return DAYS;
<INITIAL>:seconds       return SECONDS;
<INITIAL>:addresses     return ADDRESSES;
<INITIAL>:subject       return SUBJECT;
<INITIAL>:from          return FROM;
<INITIAL>:handle        return HANDLE;
<INITIAL>:mime          return MIME;
<INITIAL>:comparator    return COMPARATOR;
<INITIAL>:is            return IS;
<INITIAL>:contains      return CONTAINS;
<INITIAL>:matches       return MATCHES;
<INITIAL>:regex         return REGEX;
<INITIAL>:list          return LIST;
<INITIAL>:count         return COUNT;
<INITIAL>:value         return VALUE;
<INITIAL>:over          return OVER;
<INITIAL>:under         return UNDER;
<INITIAL>:all           return ALL;
<INITIAL>:localpart     return LOCALPART;
<INITIAL>:domain        return DOMAIN;
<INITIAL>:user          return USER;
<INITIAL>:detail        return DETAIL;
<INITIAL>:raw           return RAW;
<INITIAL>:text          return TEXT;
<INITIAL>:content       return CONTENT;
<INITIAL>include        return INCLUDE;
<INITIAL>:personal      return PERSONAL;
<INITIAL>:global        return GLOBAL;
<INITIAL>:optional      return OPTIONAL;
<INITIAL>:once          return ONCE;
<INITIAL>return         return RETURN;
<INITIAL>:copy          return COPY;
<INITIAL>date           return DATE;
<INITIAL>currentdate    return CURRENTDATE;
<INITIAL>:index         return INDEX;
<INITIAL>:last          return LAST;
<INITIAL>:zone          return ZONE;
<INITIAL>:originalzone  return ORIGINALZONE;
<INITIAL>:flags         return FLAGS;
<INITIAL>mailboxexists  return MAILBOXEXISTS; /* RFC 5490 */
<INITIAL>:create        return CREATE;
<INITIAL>metadata       return METADATA;
<INITIAL>metadataexists return METADATAEXISTS;
<INITIAL>servermetadata       return SERVERMETADATA;
<INITIAL>servermetadataexists return SERVERMETADATAEXISTS;
<INITIAL>set            return yylval->nval = SET;
<INITIAL>:lower         return yylval->nval = LOWER;
<INITIAL>:upper	        return yylval->nval = UPPER;
<INITIAL>:lowerfirst    return yylval->nval = LOWERFIRST;
<INITIAL>:upperfirst    return yylval->nval = UPPERFIRST;
<INITIAL>:quotewildcard return yylval->nval = QUOTEWILDCARD;
<INITIAL>:length        return yylval->nval = LENGTH;
<INITIAL>addheader      return ADDHEADER;
<INITIAL>deleteheader   return DELETEHEADER;
<INITIAL>[ \t\n\r] ;    /* ignore whitespace */
<INITIAL>#.* ;          /* ignore hash comments */
<INITIAL>"/*"([^\*]|\*[^\/])*\*?"*/" ;  /* ignore bracket comments */
.                       return yytext[0];

%%
/*  */
static int tonum(char *c)
{
  int val = atoi(c);
  switch (c[strlen(c)-1]) {
  case 'K': case 'k': val *= (1 << 10); break;
  case 'M': case 'm': val *= (1 << 20); break;
  case 'G': case 'g': val *= (1 << 30); break;
  default: break;
  }
  return val;
}

/* convert NULL strings to "" */
static char *chkstr(char *str)
{
    if (!str) return xstrdup("");
    else return str;
}
