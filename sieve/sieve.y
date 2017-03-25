%{
/* sieve.y -- sieve parser
 * Larry Greenfield
 *
 * Copyright (c) 1994-2017 Carnegie Mellon University.  All rights reserved.
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

/*
 * Yacc definitions
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include "xmalloc.h"
#include "sieve/comparator.h"
#include "sieve/interp.h"
#include "sieve/script.h"
#include "sieve/tree.h"
#include "sieve/flags.h"
#include "sieve/grammar.h"
#include "sieve/sieve_err.h"

#include "imapurl.h"
#include "lib/gmtoff.h"
#include "util.h"
#include "imparse.h"
#include "libconfig.h"
#include "times.h"

#define ERR_BUF_SIZE 1024

int getdatepart = 0;   /* used to send start state feedback to lexer */
static comp_t *ctags;  /* used for accessing comp_t* in a test/command union */

extern int addrparse(sieve_script_t*);
typedef struct yy_buffer_state *YY_BUFFER_STATE;
extern YY_BUFFER_STATE addr_scan_string(const char*);
extern void addr_delete_buffer(YY_BUFFER_STATE);

extern int sievelineno;

void sieveerror_c(sieve_script_t *parse_script, int code, ...);

static int check_reqs(sieve_script_t *script, strarray_t *sl);

static commandlist_t *build_fileinto(sieve_script_t*,
                                     commandlist_t *c, char *folder);
static commandlist_t *build_redirect(sieve_script_t*,
                                     commandlist_t *c, char *addr);
static commandlist_t *build_reject(sieve_script_t*, int t, char *message);
static commandlist_t *build_vacation(sieve_script_t*, commandlist_t *t, char *s);
static commandlist_t *build_flag(sieve_script_t* ,
                                 commandlist_t *c, strarray_t *flags);
static commandlist_t *build_notify(sieve_script_t *parse_script,
                                   commandlist_t *c, int t, char *method);
static commandlist_t *build_denotify(commandlist_t *c);
static commandlist_t *build_include(sieve_script_t*, commandlist_t *c, char*);
static commandlist_t *build_set(sieve_script_t*, commandlist_t *c,
                                char *variable, char *value);
static commandlist_t *build_addheader(sieve_script_t*, commandlist_t *c,
                                      char *name, char *value);
static commandlist_t *build_deleteheader(sieve_script_t*, commandlist_t *c,
                                         char *name, strarray_t *values);
static test_t *build_address(sieve_script_t*, test_t *t,
                             strarray_t *sl, strarray_t *pl);
static test_t *build_envelope(sieve_script_t*, test_t *t,
                              strarray_t *sl, strarray_t *pl);
static test_t *build_header(sieve_script_t*, test_t *t,
                            strarray_t *sl, strarray_t *pl);
static test_t *build_body(sieve_script_t*, test_t *t, strarray_t *pl);
static test_t *build_stringt(sieve_script_t*, test_t *t,
                             strarray_t *sl, strarray_t *pl);
static test_t *build_hasflag(sieve_script_t*, test_t *t,
                             strarray_t *sl, strarray_t *pl);
static test_t *build_date(sieve_script_t*, test_t *t,
                          char *hn, int part, strarray_t *kl);
static test_t *build_mbox_meta(sieve_script_t*,
                               test_t *t, const char *extname,
                               const char *keyname, strarray_t *keylist);

static int verify_stringlist(sieve_script_t*, strarray_t *sl,
                             int (*verify)(sieve_script_t*, char *));
static int verify_patternlist(sieve_script_t*, strarray_t *sl, comp_t *c,
                              int (*verify)(sieve_script_t*, char *));
static int verify_address(sieve_script_t*, char *s);
static int verify_utf8(sieve_script_t*, char *s);

void yyerror(sieve_script_t*, const char *msg);
extern int yylex(void*, sieve_script_t*);
extern void sieverestart(FILE *f);

#define YYERROR_VERBOSE /* I want better error messages! */

/* byacc default is 500, bison default is 10000 - go with the
   larger to support big sieve scripts (see Bug #3461) */
#define YYSTACKSIZE 10000
%}


%name-prefix "sieve"
%defines
%destructor  { free_tree($$); } commands command action elsif block

%parse-param { sieve_script_t *parse_script }
%lex-param   { sieve_script_t *parse_script }
%pure-parser

%union {
    int nval;
    char *sval;
    strarray_t *sl;
    comp_t *ctag;
    test_t *test;
    testlist_t *testl;
    commandlist_t *cl;
}

%token <nval> NUMBER
%token <sval> STRING
%type <sl> optstringlist stringlist strings
%type <cl> commands command action
%type <testl> testlist tests
%type <test> test

/* standard control commands - RFC 5228 */
%token IF ELSIF ELSE REQUIRE STOP
%type <cl> elsif block

/* standard action commands - RFC 5228 */
%token DISCARD KEEP FILEINTO REDIRECT
%type <cl> ktags ftags rtags

/* standard tests - RFC 5228 */
%token ANYOF ALLOF EXISTS NOT SFALSE STRUE SIZE
%token HEADER ADDRESS ENVELOPE COMPARATOR
%token <nval> OVER UNDER
%token <nval> ALL LOCALPART DOMAIN
%token <nval> IS CONTAINS MATCHES
%token <nval> OCTET ASCIICASEMAP ASCIINUMERIC
%type <test> htags atags etags
%type <nval> matchtag collation sizetag addrparttag

/* regex - draft-murchison-sieve-regex */
%token <nval> REGEX

/* copy - RFC 3894 */
%token COPY

/* body - RFC 5173 */
%token BODY
%token <nval> RAW TEXT CONTENT
%type <test> btags
%type <nval> transform

/* variables - RFC 5229 */
%token STRINGT SET
%token <nval> LOWER UPPER LOWERFIRST UPPERFIRST QUOTEWILDCARD LENGTH
%type <test> strtags
%type <cl> stags
%type <nval> mod40 mod30 mod20 mod10

/* vacation - RFC 5230 */
%token VACATION DAYS SUBJECT FROM ADDRESSES MIME HANDLE
%type <cl> vtags

/* vacation-seconds - RFC 6131 */
%token SECONDS

 /* relational - RFC 5231 */
%token <nval> COUNT VALUE GT GE LT LE EQ NE
%type <nval> relmatch relation

/* imap[4]flags - RFC 5232 */
%token FLAGS HASFLAG
%token <nval> SETFLAG ADDFLAG REMOVEFLAG
%type <test> hftags
%type <cl> flagtags
%type <nval> flagaction

/* imapflags - draft-melnikov-sieve-imapflags */
%token <nval> MARK UNMARK
%type <nval> flagmark

/* subaddress - RFC 5233 */
%token <nval> USER DETAIL
%type <nval> subaddress

/* date - RFC 5260 */
%token DATE CURRENTDATE ORIGINALZONE ZONE
%token <nval> TIMEZONE
%token <nval> YEARP MONTHP DAYP DATEP JULIAN
%token <nval> HOURP MINUTEP SECONDP TIMEP ISO8601 STD11 ZONEP WEEKDAYP
%type <test> dttags cdtags
%type <nval> datepart

/* index - RFC 5260 */
%token INDEX LAST

/* editheader - RFC 5293 */
%token ADDHEADER DELETEHEADER
%type <cl> ahtags dhtags

/* [e]reject - RFC 5429 */
%token <nval> REJCT EREJECT
%type <nval> reject

/* enotify - RFC 5435 */
%token METHOD OPTIONS MESSAGE IMPORTANCE
%token <nval> NOTIFY ENOTIFY ENCODEURL
%type <cl> ntags
%type <nval> mod15

/* notify - draft-martin-sieve-notify */
%token DENOTIFY ID ANY
%token <nval> LOW NORMAL HIGH
%type <cl> dtags
%type <nval> priority

/* mailbox - RFC 5490 */
%token MAILBOXEXISTS CREATE
%type <test> mtags

/* mboxmetadata - RFC 5490 */
%token <nval> METADATA
%token METADATAEXISTS

/* servermetadata - RFC 5490 */
%token <nval> SERVERMETADATA
%token SERVERMETADATAEXISTS

/* extlists - RFC 6134 */
%token VALIDEXTLIST
%token <nval> LIST
%type <nval> listtag

/* include - RFC 6609 */
%token INCLUDE OPTIONAL ONCE RETURN
%token <nval> PERSONAL GLOBAL
%type <cl> itags
%type <nval> location


%%

/*
 * Yacc rules
 *
 * NOTE: In several place we use the inherited attribute $0,
 * which gives us access to the symbol to the left of the current rule.
 * This allows us to pass values "forward" by reference.
 */

start: reqs                      { parse_script->cmds = NULL; }
        | reqs commands          { parse_script->cmds = $2; }
        ;


reqs: /* empty */
        | require reqs
        ;


/*
 * Control commands
 */
require: REQUIRE stringlist ';'  {
                                     if (!check_reqs(parse_script, $2)) {
                                         YYERROR; /* cr should call yyerror() */
                                     }
                                 }
        ;

commands: command                { $$ = $1; }
        | command commands       { $1->next = $2; $$ = $1; }
        ;


command:  action ';'             { $$ = $1; }
        | IF test block elsif    { $$ = new_if($2, $3, $4); }
        | error ';'              { $$ = new_command(STOP, parse_script); }
        ;


elsif: /* empty */               { $$ = NULL; }
        | ELSIF test block elsif { $$ = new_if($2, $3, $4); }
        | ELSE block             { $$ = $2; }
        ;


block: '{' commands '}'          { $$ = $2; }
        | '{' '}'                { $$ = NULL; }
        ;


optstringlist: /* empty */       { $$ = strarray_new(); }
        | stringlist             { $$ = $1; }
;


stringlist: '[' strings ']'      { $$ = $2; }
        | STRING                 {
                                    $$ = strarray_new();
                                    strarray_appendm($$, $1);
                                 }
        ;


strings: STRING                  {
                                    $$ = strarray_new();
                                    strarray_appendm($$, $1);
                                 }
        | strings ',' STRING     {
                                    $$ = $1;
                                    strarray_appendm($$, $3);
                                 }
        ;


/*
 * Action commands
 */
action:   STOP                   { $$ = new_command(STOP, parse_script);    }
        | DISCARD                { $$ = new_command(DISCARD, parse_script); }
        | KEEP ktags             { $$ = $2; }
        | FILEINTO ftags STRING  {
                                     $$ = build_fileinto(parse_script, $2, $3);
                                     if ($$ == NULL) {
                                         YYERROR; /* bf should call yyerror() */
                                     }
                                 }
        | REDIRECT rtags STRING  {
                                     $$ = build_redirect(parse_script, $2, $3);
                                     if ($$ == NULL) {
                                         YYERROR; /* br should call yyerror() */
                                     }
                                 }
        | SET stags STRING STRING
                                 {
                                     $$ = build_set(parse_script, $2, $3, $4);
                                     if ($$ == NULL) {
                                         YYERROR; /* bs should call yyerror() */
                                     }
                                 }

        | VACATION vtags STRING  {
                                     $$ = build_vacation(parse_script, $2, $3);
                                     if ($$ == NULL) {
                                         YYERROR; /* bv should call yyerror() */
                                     }
                                 }
        /* SET/ADD/REMOVEFLAG */
        | flagaction flagtags stringlist
                                 {
                                     $$ = build_flag(parse_script, $2, $3);
                                     if ($$ == NULL) {
                                         YYERROR; /* bf should call yyerror() */
                                     }
                                 }
        /* MARK/UNMARK */
        | flagmark
                                 {
                                     $$ = new_command($1, parse_script);
                                     if ($$ == NULL) {
                                         YYERROR; /* nc should call yyerror() */
                                     }
                                 }

        | ADDHEADER ahtags STRING STRING
                                 {
                                     $$ = build_addheader(parse_script,
                                                          $2, $3, $4);
                                     if ($$ == NULL) {
                                         YYERROR; /* bah should call yyerror() */
                                     }
                                 }

        | DELETEHEADER dhtags STRING optstringlist
                                 {
                                     $$ = build_deleteheader(parse_script,
                                                             $2, $3, $4);
                                     if ($$ == NULL) {
                                         YYERROR; /* bdh should call yyerror() */
                                     }
                                 }

        | reject STRING          {
                                     $$ = build_reject(parse_script, $1, $2);
                                     if ($$ == NULL) {
                                         YYERROR; /* br should call yyerror() */
                                     }
                                 }
        | NOTIFY ntags STRING
                                 {
                                     $$ = build_notify(parse_script,
                                                       $2, ENOTIFY, $3);
                                     if ($$ == NULL) {
                                         YYERROR; /* bn should call yyerror() */
                                     }
                                 }
        | NOTIFY ntags           {
                                     $$ = build_notify(parse_script,
                                                       $2, NOTIFY, NULL);
                                     if ($$ == NULL) {
                                         YYERROR; /* bn should call yyerror() */
                                     }
                                 }
        | DENOTIFY dtags         { $$ = build_denotify($2); }
        | INCLUDE itags STRING   {
                                     $$ = build_include(parse_script, $2, $3);
                                     if ($$ == NULL) {
                                         YYERROR; /* bi should call yyerror() */
                                     }
                                 }
        | RETURN                 {
                                     $$ = new_command(RETURN, parse_script);
                                     if ($$ == NULL) {
                                         YYERROR; /* nc should call yyerror() */
                                     }
                                 }
        ;


/* KEEP tagged arguments */
ktags: /* empty */               { $$ = new_command(KEEP, parse_script); }
        | ktags flags
        ;


/* :flags */
flags: FLAGS stringlist          {
                                     if (!parse_script->support.imap4flags) {
                                         sieveerror_c(parse_script,
                                                      SIEVE_MISSING_REQUIRE,
                                                      "imap4flags");
                                         YYERROR;
                                     }

                                     /* $0 refers to ktags or ftags */
                                     commandlist_t *c = $<cl>0;
                                     strarray_t **flags = (c->type == KEEP) ?
                                         &c->u.k.flags : &c->u.f.flags;

                                     if (*flags != NULL) {
                                         sieveerror_c(parse_script,
                                                      SIEVE_DUPLICATE_TAG,
                                                      ":flags");
                                         YYERROR;
                                     }

                                     if (!parse_script->support.variables) {
                                         verify_flaglist($2);
                                     }

                                     if (!strarray_size($2)) {
                                         strarray_add($2, "");
                                     }
                                     *flags = $2;
                                 }
        ;


/* FILEINTO tagged arguments */
ftags: /* empty */               {
                                     $$ = new_command(FILEINTO, parse_script);
                                     if ($$ == NULL) {
                                         YYERROR; /* nc should call yyerror() */
                                     }
                                 }
        | ftags CREATE           {
                                     if (!parse_script->support.mailbox) {
                                         sieveerror_c(parse_script,
                                                      SIEVE_MISSING_REQUIRE,
                                                      "mailbox");
                                         YYERROR;
                                     }
                                     if ($$->u.f.create) {
                                         sieveerror_c(parse_script,
                                                      SIEVE_DUPLICATE_TAG,
                                                      ":create");
                                         YYERROR;
                                     }

                                     $$->u.f.create = 1;
                                 }
        | ftags copy
        | ftags flags
        ;


/* :copy */
copy: COPY                       {
                                     if (!parse_script->support.copy) {
                                         sieveerror_c(parse_script,
                                                      SIEVE_MISSING_REQUIRE,
                                                      "copy");
                                         YYERROR;
                                     }

                                     /* $0 refers to ftags or rtags */
                                     commandlist_t *c = $<cl>0;
                                     int *copy = (c->type == FILEINTO) ?
                                         &c->u.f.copy : &c->u.r.copy;

                                     if (*copy) {
                                         sieveerror_c(parse_script,
                                                      SIEVE_DUPLICATE_TAG,
                                                      ":copy");
                                         YYERROR;
                                     }

                                     *copy = 1;
                                 }
        ;


/* REDIRECT tagged arguments */
rtags: /* empty */               { $$ = new_command(REDIRECT, parse_script); }
        | rtags listtag          {
                                     if ($$->u.r.list) {
                                         sieveerror_c(parse_script,
                                                      SIEVE_DUPLICATE_TAG,
                                                      ":list");
                                         YYERROR;
                                     }

                                     $$->u.r.list = 1;
                                 }
        | rtags copy
        ;


/* SET tagged arguments */
stags: /* empty */               {
                                     $$ = new_command(SET, parse_script);
                                     if ($$ == NULL) {
                                         YYERROR; /* nc should call yyerror() */
                                     }
                                 }
        | stags mod40            {
                                     if ($$->u.s.mod40) {
                                         sieveerror_c(parse_script,
                                                      SIEVE_DUPLICATE_TAG,
                                                      "precedence 40 modifier");
                                         YYERROR;
                                     }

                                     $$->u.s.mod40 = $2;
                                 }
        | stags mod30            {
                                     if ($$->u.s.mod30) {
                                         sieveerror_c(parse_script,
                                                      SIEVE_DUPLICATE_TAG,
                                                      "precedence 30 modifier");
                                         YYERROR;
                                     }

                                     $$->u.s.mod30 = $2;
                                 }
        | stags mod20            {
                                     if ($$->u.s.mod20) {
                                         sieveerror_c(parse_script,
                                                      SIEVE_DUPLICATE_TAG,
                                                      "precedence 20 modifier");
                                         YYERROR;
                                     }

                                     $$->u.s.mod20 = $2;
                                 }
        | stags mod15            {
                                     if ($$->u.s.mod15) {
                                         sieveerror_c(parse_script,
                                                      SIEVE_DUPLICATE_TAG,
                                                      "precedence 15 modifier");
                                         YYERROR;
                                     }

                                     $$->u.s.mod15 = $2;
                                 }
        | stags mod10            {
                                     if ($$->u.s.mod10) {
                                         sieveerror_c(parse_script,
                                                      SIEVE_DUPLICATE_TAG,
                                                      "precedence 10 modifier");
                                         YYERROR;
                                     }

                                     $$->u.s.mod10 = $2;
                                 }
        ;


/* SET modifiers */
mod40:    LOWER
        | UPPER
        ;

mod30:    LOWERFIRST
        | UPPERFIRST
        ;

mod20:    QUOTEWILDCARD
        ;

mod15:    ENCODEURL              { 
                                     if (!parse_script->support.enotify) {
                                         sieveerror_c(parse_script,
                                                      SIEVE_MISSING_REQUIRE,
                                                      "enotify");
                                         YYERROR;
                                     }
                                 }
        ;

mod10:    LENGTH
        ;


/* VACATION tagged arguments */
vtags: /* empty */               {
                                     $$ = new_command(VACATION, parse_script);
                                     if ($$ == NULL) {
                                         YYERROR; /* nc should call yyerror() */
                                     }
                                 }
        | vtags DAYS NUMBER      {
                                     if ($$->u.v.seconds != -1) {
                                         sieveerror_c(parse_script,
                                                      SIEVE_DUPLICATE_TAG,
                                                      "period");
                                         YYERROR;
                                     }

                                     $$->u.v.seconds = $3 * DAY2SEC;
                                 }
        | vtags SECONDS NUMBER   {
                                     if (!parse_script->support.vacation_seconds) {
                                         sieveerror_c(parse_script,
                                                      SIEVE_MISSING_REQUIRE,
                                                      "vacation-seconds");
                                         YYERROR;
                                     }
                                     if ($$->u.v.seconds != -1) {
                                         sieveerror_c(parse_script,
                                                      SIEVE_DUPLICATE_TAG,
                                                      "period");
                                         YYERROR;
                                     }

                                     $$->u.v.seconds = $3;
                                 }
        | vtags SUBJECT STRING   {
                                     if ($$->u.v.subject != NULL) {
                                         sieveerror_c(parse_script,
                                                      SIEVE_DUPLICATE_TAG,
                                                      ":subject");
                                         YYERROR;
                                     }
                                     if (!verify_utf8(parse_script, $3)) {
                                         YYERROR; /* vu should call yyerror() */
                                     }

                                     $$->u.v.subject = $3;
                                 }
        | vtags FROM STRING      {
                                     if ($$->u.v.from != NULL) {
                                         sieveerror_c(parse_script,
                                                      SIEVE_DUPLICATE_TAG,
                                                      ":from");
                                         YYERROR;
                                     }
                                     if (!verify_address(parse_script, $3)) {
                                         YYERROR; /* va should call yyerror() */
                                     }

                                     $$->u.v.from = $3;
                                 }
        | vtags ADDRESSES stringlist
                                 {
                                     if ($$->u.v.addresses != NULL) {
                                         sieveerror_c(parse_script,
                                                      SIEVE_DUPLICATE_TAG,
                                                      ":addresses");
                                         YYERROR;
                                     }
                                     if (!verify_stringlist(parse_script, $3,
                                                            verify_address)) {
                                         YYERROR; /* va should call yyerror() */
                                     }

                                     $$->u.v.addresses = $3;
                                 }
        | vtags MIME             {
                                     if ($$->u.v.mime != -1) {
                                         sieveerror_c(parse_script,
                                                      SIEVE_DUPLICATE_TAG,
                                                      ":mime");
                                         YYERROR;
                                     }

                                     $$->u.v.mime = 1;
                                 }
        | vtags HANDLE STRING    {
                                     if ($$->u.v.handle != NULL) {
                                         sieveerror_c(parse_script,
                                                      SIEVE_DUPLICATE_TAG,
                                                      ":handle");
                                         YYERROR;
                                     }
                                     if (!verify_utf8(parse_script, $3)) {
                                         YYERROR; /* vu should call yyerror() */
                                     }

                                     $$->u.v.handle = $3;
                                 }
        ;


/* SET/ADD/REMOVEFLAG */
flagaction: SETFLAG
        | ADDFLAG
        | REMOVEFLAG
        ;


/* SET/ADD/REMOVEFLAG tagged arguments */
flagtags: /* empty */            {
                                     /* $0 refers to flagaction */
                                     $$ = new_command($<nval>0, parse_script);
                                     if ($$ == NULL) {
                                         YYERROR; /* nc should call yyerror() */
                                     }
                                 }
        | flagtags STRING        {
                                     if (!(parse_script->support.imap4flags)) {
                                         sieveerror_c(parse_script,
                                                      SIEVE_MISSING_REQUIRE,
                                                      "imap4flags");
                                         YYERROR;
                                     }
                                     if ($$->u.fl.variable) {
                                         sieveerror_c(parse_script,
                                                      SIEVE_DUPLICATE_ARG,
                                                      "variablename");
                                         YYERROR;
                                     }
                                     if (!is_identifier($2)) {
                                         sieveerror_c(parse_script,
                                                      SIEVE_INVALID_VALUE,
                                                      "variablename");
                                         YYERROR;
                                     }

                                     $$->u.fl.variable = $2;
                                 }
        ;


/* MARK/UNMARK */
flagmark: MARK
        | UNMARK
        ;


/* ADDHEADER tagged arguments */
ahtags: /* empty */              {
                                     $$ = new_command(ADDHEADER, parse_script);
                                     if ($$ == NULL) {
                                         YYERROR; /* nc should call yyerror() */
                                     }
                                 }
        | ahtags LAST            {
                                     if ($$->u.ah.index < 0) {
                                         sieveerror_c(parse_script,
                                                      SIEVE_DUPLICATE_TAG,
                                                      ":last");
                                         YYERROR;
                                     }

                                     $$->u.ah.index = -1;
                                 }
        ;


/* DELETEHEADER tagged arguments */
dhtags: /* empty */              {
                                     $$ = new_command(DELETEHEADER,
                                                      parse_script);
                                     if ($$ == NULL) {
                                         YYERROR; /* nc should call yyerror() */
                                     }
                                 }

        | dhtags { ctags = &($1->u.dh.comp); } matchtype
        | dhtags { ctags = &($1->u.dh.comp); } listmatch
        | dhtags { ctags = &($1->u.dh.comp); } comparator
        | dhtags { ctags = &($1->u.dh.comp); } idxtags
        ;


/* REJECT/EREJECT */
reject:   REJCT
        | EREJECT
        ;


/* NOTIFY tagged arguments
 *
 * Haven't been able to find a way to split the allowed tags for enotify
 * and legacy notify without creating a shift/reduce conflict, so we
 * try to police it during parsing.  Note that this allows :importance
 * and :low/:normal/:high to be used with the incorrect notify flavor.
 */
ntags: /* empty */               {
                                     $$ = new_command(NOTIFY, parse_script);
                                     if ($$ == NULL) {
                                         YYERROR; /* nc should call yyerror() */
                                     }
                                 }

        /* enotify-only tagged arguments */
        | ntags FROM STRING      {
                                     if ($$->type == NOTIFY) {
                                         sieveerror_c(parse_script,
                                                      SIEVE_UNEXPECTED_TAG,
                                                      ":from");
                                         YYERROR;
                                     }
                                     if ($$->u.n.from != NULL) {
                                         sieveerror_c(parse_script,
                                                      SIEVE_DUPLICATE_TAG,
                                                      ":from");
                                         YYERROR;
                                     }

                                     $$->type = ENOTIFY;
                                     $$->u.n.from = $3;
                                 }

        | ntags IMPORTANCE priority
                                 {
                                     if ($$->type == NOTIFY) {
                                         sieveerror_c(parse_script,
                                                      SIEVE_UNEXPECTED_TAG,
                                                      ":importance");
                                         YYERROR;
                                     }
                                     if ($$->u.n.priority != -1) {
                                         sieveerror_c(parse_script,
                                                      SIEVE_DUPLICATE_TAG,
                                                      ":importance");
                                         YYERROR;
                                     }

                                     $$->type = ENOTIFY;
                                     $$->u.n.priority = $3;
                                 }

        /* legacy-only tagged arguments */
        | ntags ID STRING        {
                                     if ($$->type == ENOTIFY) {
                                         sieveerror_c(parse_script,
                                                      SIEVE_UNEXPECTED_TAG,
                                                      ":id");
                                         YYERROR;
                                     }
                                     if ($$->u.n.id != NULL) {
                                         sieveerror_c(parse_script,
                                                      SIEVE_DUPLICATE_TAG,
                                                      ":id");
                                         YYERROR;
                                     }

                                     $$->type = NOTIFY;
                                     $$->u.n.id = $3;
                                 }
        | ntags METHOD STRING    {
                                     if ($$->type == ENOTIFY) {
                                         sieveerror_c(parse_script,
                                                      SIEVE_UNEXPECTED_TAG,
                                                      ":method");
                                         YYERROR;
                                     }
                                     if ($$->u.n.method != NULL) {
                                         sieveerror_c(parse_script,
                                                      SIEVE_DUPLICATE_TAG,
                                                      ":method");
                                         YYERROR;
                                     }

                                     $$->type = NOTIFY;
                                     $$->u.n.method = $3;
                                 }
        | ntags priority         {
                                     if ($$->type == ENOTIFY) {
                                         sieveerror_c(parse_script,
                                                      SIEVE_UNEXPECTED_TAG,
                                                      "priority");
                                         YYERROR;
                                     }
                                     if ($$->u.n.priority != -1) {
                                         sieveerror_c(parse_script,
                                                      SIEVE_DUPLICATE_TAG,
                                                      "priority");
                                         YYERROR;
                                     }

                                     $$->type = NOTIFY;
                                     $$->u.n.priority = $2;
                                 }

        /* common tagged arguments */
        | ntags MESSAGE STRING   {
                                     if ($$->u.n.message != NULL) {
                                         sieveerror_c(parse_script,
                                                      SIEVE_DUPLICATE_TAG,
                                                      ":message");
                                         YYERROR;
                                     }

                                     $$->u.n.message = $3;
                                 }

        | ntags OPTIONS stringlist
                                 {
                                     if ($$->u.n.options != NULL) {
                                         sieveerror_c(parse_script,
                                                      SIEVE_DUPLICATE_TAG,
                                                      ":options");
                                         YYERROR;
                                     }

                                     $$->u.n.options = $3;
                                 }
        ;


/* priority tag or :importance value */
priority: LOW
        | NORMAL
        | HIGH
        ;


/* DENOTIFY tagged arguments */
dtags: /* empty */               {
                                     $$ = new_command(DENOTIFY, parse_script);
                                     if ($$ == NULL) {
                                         YYERROR; /* nc should call yyerror() */
                                     }
                                 }
        | dtags priority         {
                                     if ($$->u.d.priority != -1) {
                                         sieveerror_c(parse_script,
                                                      SIEVE_DUPLICATE_TAG,
                                                      "priority");
                                         YYERROR;
                                     }

                                     $$->u.d.priority = $2;
                                 }

        | dtags { ctags = &($1->u.d.comp); } matchtype STRING {
                                     strarray_t sa = STRARRAY_INITIALIZER;
                                     strarray_appendm(&sa, $4);
                                     if (!verify_patternlist(parse_script, &sa,
                                                             &($$->u.d.comp),
                                                             NULL)) {
                                         YYERROR;
                                     }
                                     strarray_fini(&sa);

                                     $$->u.d.pattern = $4;
                                 }
        ;


/* INCLUDE tagged arguments */
itags: /* empty */               {
                                     $$ = new_command(INCLUDE, parse_script);
                                     if ($$ == NULL) {
                                         YYERROR; /* nc should call yyerror() */
                                     }
                                 }
        | itags location         {
                                     if ($$->u.inc.location != -1) {
                                         sieveerror_c(parse_script,
                                                      SIEVE_DUPLICATE_TAG,
                                                      "location");
                                         YYERROR;
                                     }

                                     $$->u.inc.location = $2;
                                 }
        | itags ONCE             {
                                     if ($$->u.inc.once != -1) {
                                         sieveerror_c(parse_script,
                                                      SIEVE_DUPLICATE_TAG,
                                                      ":once");
                                         YYERROR;
                                     }

                                     $$->u.inc.once = 1;
                                 }
        | itags OPTIONAL         {
                                     if ($$->u.inc.optional != -1) {
                                         sieveerror_c(parse_script,
                                                      SIEVE_DUPLICATE_TAG,
                                                      ":optional");
                                         YYERROR;
                                     }

                                     $$->u.inc.optional = 1;
                                 }
        ;


/* location tags */
location: PERSONAL
        | GLOBAL
        ;


/*
 * Test commands
 */
testlist: '(' tests ')'          { $$ = $2; }
        ;

tests: test                      { $$ = new_testlist($1, NULL); }
        | test ',' tests         { $$ = new_testlist($1, $3); }
        ;

test:     ANYOF testlist         {
                                     $$ = new_test(ANYOF, parse_script);
                                     $$->u.tl = $2;
                                 }
        | ALLOF testlist         {
                                     $$ = new_test(ALLOF, parse_script);
                                     $$->u.tl = $2;
                                 }
        | EXISTS stringlist      {
                                     $$ = new_test(EXISTS, parse_script);
                                     $$->u.sl = $2;
                                 }
        | NOT test               {
                                     $$ = new_test(NOT, parse_script);
                                     $$->u.t  = $2;
                                 }
        | SFALSE                 { $$ = new_test(SFALSE, parse_script); }
        | STRUE                  { $$ = new_test(STRUE, parse_script);  }

        | SIZE sizetag NUMBER    {
                                     $$ = new_test(SIZE, parse_script);
                                     $$->u.sz.t = $2;
                                     $$->u.sz.n = $3;
                                 }

        | HEADER htags stringlist stringlist
                                 {
                                     $$ = build_header(parse_script, $2, $3, $4);
                                     if ($$ == NULL) {
                                         YYERROR; /* bh should call yyerror() */
                                     }
                                 }

        | ADDRESS atags stringlist stringlist
                                 {
                                     $$ = build_address(parse_script,
                                                         $2, $3, $4);
                                     if ($$ == NULL) {
                                         YYERROR; /* ba should call yyerror() */
                                     }
                                 }

        | ENVELOPE etags stringlist stringlist
                                 {
                                     $$ = build_envelope(parse_script,
                                                         $2, $3, $4);
                                     if ($$ == NULL) {
                                         YYERROR; /* ba should call yyerror() */
                                     }
                                 }
        | BODY btags stringlist  {
                                     $$ = build_body(parse_script, $2, $3);
                                     if ($$ == NULL) {
                                         YYERROR; /* bb should call yyerror() */
                                     }
                                 }

        | STRINGT strtags stringlist stringlist
                                 {
                                     $$ = build_stringt(parse_script,
                                                        $2, $3, $4);
                                     if ($$ == NULL) {
                                         YYERROR; /* bh should call yyerror() */
                                     }
                                 }

        /* Per RFC 5232, the variables list (penultimate argument) is optional,
         * but defining the grammar this way results in a shift/reduce conflict.
         * Therefore, we have to flatten the grammar into two rules.
        */
        | HASFLAG hftags stringlist stringlist
                                 {
                                     $$ = build_hasflag(parse_script,
                                                        $2, $3, $4);
                                     if ($$ == NULL) {
                                         YYERROR; /* bh should call yyerror() */
                                     }
                                 }

        | HASFLAG hftags stringlist
                                 {
                                     $$ = build_hasflag(parse_script,
                                                        $2, NULL, $3);
                                     if ($$ == NULL) {
                                         YYERROR; /* bh should call yyerror() */
                                     }
                                 }

        /* getdatepart variable is used to change the start state of the lexer */
        | DATE dttags STRING { getdatepart = 1; } datepart stringlist
                                 {
                                     $$ = build_date(parse_script,
                                                     $2, $3, $5, $6);
                                     if ($$ == NULL) {
                                         YYERROR; /* bd should call yyerror() */
                                     }
                                 }

        | CURRENTDATE cdtags datepart stringlist
                                 {
                                     $$ = build_date(parse_script,
                                                     $2, NULL, $3, $4);
                                     if ($$ == NULL) {
                                         YYERROR; /* bd should call yyerror() */
                                     }
                                 }

        | MAILBOXEXISTS stringlist
                                 {
                                     $$ = new_test(MAILBOXEXISTS, parse_script);
                                     if ($$ == NULL) {
                                         YYERROR; /* nt should call yyerror() */
                                     }

                                     $$ = build_mbox_meta(parse_script,
                                                          $$, NULL, NULL, $2);
                                 }

        | METADATA mtags STRING STRING stringlist
                                 {
                                     $$ = build_mbox_meta(parse_script,
                                                          $2, $3, $4, $5);
                                 }

        | METADATAEXISTS STRING stringlist
                                 {
                                     $$ = new_test(METADATAEXISTS, parse_script);
                                     if ($$ == NULL) {
                                         YYERROR; /* nt should call yyerror() */
                                     }

                                     $$ = build_mbox_meta(parse_script,
                                                          $$, $2, NULL, $3);
                                 }

        | SERVERMETADATA mtags STRING stringlist
                                 {
                                     $$ = build_mbox_meta(parse_script,
                                                          $2, NULL, $3, $4);
                                 }

        | SERVERMETADATAEXISTS stringlist
                                 {
                                     $$ = new_test(SERVERMETADATAEXISTS,
                                                   parse_script);
                                     if ($$ == NULL) {
                                         YYERROR; /* nt should call yyerror() */
                                     }

                                     $$ = build_mbox_meta(parse_script,
                                                          $$, NULL, NULL, $2);
                                 }

        | VALIDEXTLIST stringlist
                                 {
                                     $$ = new_test(VALIDEXTLIST, parse_script);
                                     if ($$ == NULL) {
                                         YYERROR; /* nt should call yyerror() */
                                     }

                                     $$->u.sl = $2;
                                 }

        | error                  { $$ = NULL; }
        ;


/* SIZE tagged arguments */
sizetag:  OVER
        | UNDER
        ;


/* HEADER tagged arguments */
htags: /* empty */               { $$ = new_test(HEADER, parse_script); }
        | htags { ctags = &($1->u.hhs.comp); } matchtype
        | htags { ctags = &($1->u.hhs.comp); } listmatch
        | htags { ctags = &($1->u.hhs.comp); } comparator
        | htags { ctags = &($1->u.hhs.comp); } idxtags
        ;


/* All match-types except for :list */
matchtype: matchtag              {
                                     if (ctags->match != -1) {
                                         sieveerror_c(parse_script,
                                                      SIEVE_DUPLICATE_TAG,
                                                      "match-type");
                                         YYERROR;
                                     }

                                     ctags->match = $1;
                                 }
        | relmatch relation
                                 {
                                     if (!parse_script->support.relational) {
                                         sieveerror_c(parse_script,
                                                      SIEVE_MISSING_REQUIRE,
                                                      "relational");
                                         YYERROR;
                                     }

                                     if (ctags->match != -1) {
                                         sieveerror_c(parse_script,
                                                      SIEVE_DUPLICATE_TAG,
                                                      "match-type");
                                         YYERROR;
                                     }

                                     ctags->match = $1;
                                     ctags->relation = $2;
                                 }
        ;


/* match-type tags */
matchtag: IS
        | CONTAINS
        | MATCHES
        | REGEX                  {
                                     if (!parse_script->support.regex) {
                                         sieveerror_c(parse_script,
                                                      SIEVE_MISSING_REQUIRE,
                                                      "regex");
                                         YYERROR;
                                     }
                                 }
        ;


/* Relational match-type tags */
relmatch: COUNT
        | VALUE
        ;


/* relational-match */
relation: EQ
        | NE
        | GT
        | GE
        | LT
        | LE
        ;


/* :list match-type */
listmatch: listtag               {
                                     if (ctags->match != -1) {
                                         sieveerror_c(parse_script,
                                                      SIEVE_DUPLICATE_TAG,
                                                      "match-type");
                                         YYERROR;
                                     }

                                     ctags->match = LIST;
                                 }
        ;


/* :list */
listtag: LIST                    {
                                     if (!parse_script->support.extlists) {
                                         sieveerror_c(parse_script,
                                                      SIEVE_MISSING_REQUIRE,
                                                      "extlists");
                                         YYERROR;
                                     }
                                 }
        ;


/* :comparator */
comparator: COMPARATOR collation
                                 {
                                     if (ctags->collation != -1) {
                                         sieveerror_c(parse_script,
                                                      SIEVE_DUPLICATE_TAG,
                                                      ":comparator");
                                         YYERROR;
                                     }

                                     
                                     ctags->collation = $2;
                                 }
        ;


/* comparator-types */
collation: OCTET
        | ASCIICASEMAP
        | ASCIINUMERIC           {
                                     if (!parse_script->support.i_ascii_numeric) {
                                         sieveerror_c(parse_script,
                                                      SIEVE_MISSING_REQUIRE,
                                                      "comparator-i;ascii-numeric");
                                         YYERROR;
                                     }
                                 }
        ;


/* Index tags */
idxtags: INDEX NUMBER
                                 {
                                     if (!parse_script->support.index) {
                                         sieveerror_c(parse_script,
                                                      SIEVE_MISSING_REQUIRE,
                                                      "index");
                                         YYERROR;
                                     }

                                     if (ctags->index != 0) {
                                         sieveerror_c(parse_script,
                                                      SIEVE_DUPLICATE_TAG,
                                                      ":index");
                                         YYERROR;
                                     }

                                     ctags->index = $2;
                                 }
        | LAST
                                 {
                                     if (!parse_script->support.index) {
                                         sieveerror_c(parse_script,
                                                      SIEVE_MISSING_REQUIRE,
                                                      "index");
                                         YYERROR;
                                     }

                                     if (ctags->index == 0) {
                                         sieveerror_c(parse_script,
                                                      SIEVE_MISSING_TAG,
                                                      ":index");
                                         YYERROR;
                                     }
                                     if (ctags->index < 0) {
                                         sieveerror_c(parse_script,
                                                      SIEVE_DUPLICATE_TAG,
                                                      ":last");
                                         YYERROR;
                                     }

                                     ctags->index *= -1;
                                 }
        ;


/* ADDRESS tagged arguments */
atags: /* empty */               { $$ = new_test(ADDRESS, parse_script); }
        | atags addrpart
        | atags { ctags = &($1->u.ae.comp); } matchtype
        | atags { ctags = &($1->u.ae.comp); } listmatch
        | atags { ctags = &($1->u.ae.comp); } comparator
        | atags { ctags = &($1->u.ae.comp); } idxtags
        ;


/* address-part */
addrpart: addrparttag           {
                                     /* $0 refers to a test_t* (ADDR/ENV)*/
                                     test_t *test = $<test>0;

                                     if (test->u.ae.addrpart != -1) {
                                         sieveerror_c(parse_script,
                                                      SIEVE_DUPLICATE_TAG,
                                                      "address-part");
                                         YYERROR;
                                     }

                                     test->u.ae.addrpart = $1;
                                 }


/* address-part tags */
addrparttag: ALL
        | LOCALPART
        | DOMAIN
        | subaddress             {
                                     if (!parse_script->support.subaddress) {
                                         sieveerror_c(parse_script,
                                                      SIEVE_MISSING_REQUIRE,
                                                      "subaddress");
                                         YYERROR;
                                     }
                                 }
        ;


/* subaddress-part tags */
subaddress: USER
        | DETAIL
        ;


/* ENVELOPE tagged arguments */
etags: /* empty */               {
                                     $$ = new_test(ENVELOPE, parse_script);
                                     if ($$ == NULL) {
                                         YYERROR; /* nt should call yyerror() */
                                     }
                                 }
        | etags addrpart
        | etags { ctags = &($1->u.ae.comp); } matchtype
        | etags { ctags = &($1->u.ae.comp); } listmatch
        | etags { ctags = &($1->u.ae.comp); } comparator
        ;


/* BODY tagged arguments */
btags: /* empty */               {
                                     $$ = new_test(BODY, parse_script);
                                     if ($$ == NULL) {
                                         YYERROR; /* nt should call yyerror() */
                                     }
                                 }
        | btags transform        {
                                     if ($$->u.b.transform != -1) {
                                         sieveerror_c(parse_script,
                                                      SIEVE_DUPLICATE_TAG,
                                                      "transform");
                                         YYERROR;
                                     }

                                     $$->u.b.transform = $2;
                                 }

        | btags CONTENT stringlist
                                 {
                                     if ($$->u.b.transform != -1) {
                                         sieveerror_c(parse_script,
                                                      SIEVE_DUPLICATE_TAG,
                                                      "transform");
                                         YYERROR;
                                     }

                                     $$->u.b.transform = $2;
                                     $$->u.b.content_types = $3;
                                 }

        | btags { ctags = &($1->u.b.comp); } matchtype
        | btags { ctags = &($1->u.b.comp); } comparator
        ;


/* body-transform tags */
transform: RAW
        | TEXT
        ;


/* STRING tagged arguments */
strtags: /* empty */             {
                                     $$ = new_test(STRINGT, parse_script);
                                     if ($$ == NULL) {
                                         YYERROR; /* nt should call yyerror() */
                                     }
                                 }

        | strtags { ctags = &($1->u.hhs.comp); } matchtype
        | strtags { ctags = &($1->u.hhs.comp); } listmatch
        | strtags { ctags = &($1->u.hhs.comp); } comparator
        ;


/* HASFLAG tagged arguments */
hftags: /* empty */              {
                                     $$ = new_test(HASFLAG, parse_script);
                                     if ($$ == NULL) {
                                         YYERROR; /* nt should call yyerror() */
                                     }
                                 }
        | hftags { ctags = &($1->u.hhs.comp); } matchtype
        | hftags { ctags = &($1->u.hhs.comp); } comparator
        ;


/* DATE tagged arguments */
dttags: /* empty */              {
                                     $$ = new_test(DATE, parse_script);
                                     if ($$ == NULL) {
                                         YYERROR; /* nt should call yyerror() */
                                     }
                                 }
        | dttags ORIGINALZONE    {
                                     if ($$->u.dt.zonetag != -1) {
                                         sieveerror_c(parse_script,
                                                      SIEVE_DUPLICATE_TAG,
                                                      ":originalzone");
                                         YYERROR;
                                     }

                                     $$->u.dt.zonetag = ORIGINALZONE;
                                 }
        | dttags zone
        | dttags { ctags = &($1->u.dt.comp); } matchtype
        | dttags { ctags = &($1->u.dt.comp); } comparator
        | dttags { ctags = &($1->u.dt.comp); } idxtags
        ;


/* :zone */
zone: ZONE TIMEZONE              {
                                     /* $0 refers to a test_t* ([CURRENT]DATE)*/
                                     test_t *test = $<test>0;

                                     if (test->u.dt.zonetag != -1) {
                                         sieveerror_c(parse_script,
                                                      SIEVE_DUPLICATE_TAG,
                                                      ":zone");
                                         YYERROR;
                                     }

                                     test->u.dt.zonetag = ZONE;
                                     test->u.dt.zone = $2;
                                 }
        ;


/* CURRENTDATE tagged arguments */
cdtags: /* empty */              {
                                     $$ = new_test(CURRENTDATE, parse_script);
                                     if ($$ == NULL) {
                                         YYERROR; /* nt should call yyerror() */
                                     }
                                 }
        | cdtags zone
        | cdtags { ctags = &($1->u.dt.comp); } matchtype
        | cdtags { ctags = &($1->u.dt.comp); } comparator
        ;


/* date-parts */
datepart: YEARP
        | MONTHP
        | DAYP
        | DATEP
        | JULIAN
        | HOURP
        | MINUTEP
        | SECONDP
        | TIMEP
        | ISO8601
        | STD11
        | ZONEP
        | WEEKDAYP
        ;


/* METADATA/SERVERMETADATA tagged arguments */
mtags: /* empty */               {
                                     /* $0 refers to [SERVER]METADATA */
                                     $$ = new_test($<nval>0, parse_script);
                                     if ($$ == NULL) {
                                         YYERROR; /* nt should call yyerror() */
                                     }
                                 }

        | mtags { ctags = &($1->u.mm.comp); } matchtype
        | mtags { ctags = &($1->u.mm.comp); } comparator
        ;
%%


/*
 * Yacc actions
 */

void yyerror(sieve_script_t *parse_script, const char *msg)
{
    parse_script->err++;
    if (parse_script->interp.err) {
        parse_script->interp.err(sievelineno, msg,
                                 parse_script->interp.interp_context,
                                 parse_script->script_context);
    }
}


static void vsieveerror_f(sieve_script_t *parse_script,
                          const char *fmt, va_list args)
{
    buf_reset(&parse_script->sieveerr);
    buf_vprintf(&parse_script->sieveerr, fmt, args);
    yyerror(parse_script, buf_cstring(&parse_script->sieveerr));
}

void sieveerror_f(sieve_script_t *parse_script, const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    vsieveerror_f(parse_script, fmt, args);
    va_end(args);
}

void sieveerror_c(sieve_script_t *parse_script, int code, ...)
{
    va_list args;

    va_start(args, code);
    vsieveerror_f(parse_script, error_message(code), args);
    va_end(args);
}

static int verify_stringlist(sieve_script_t *parse_script, strarray_t *sa,
                             int (*verify)(sieve_script_t*, char *))
{
    int i;

    for (i = 0 ; i < strarray_size(sa) ; i++) {
        if (!verify(parse_script, (char *) strarray_nth(sa, i))) return 0;
    }
    return 1;
}

#ifdef ENABLE_REGEX
static int verify_regexlist(sieve_script_t *parse_script,
                            const strarray_t *sa, int collation)
{
    int i, ret = 0;
    regex_t *reg = (regex_t *) xmalloc(sizeof(regex_t));
    int cflags = REG_EXTENDED | REG_NOSUB;

#ifdef HAVE_PCREPOSIX_H
    /* support UTF8 comparisons */
    cflags |= REG_UTF8;
#endif

    if (collation == ASCIICASEMAP) {
        cflags |= REG_ICASE;
    }

    for (i = 0 ; i < strarray_size(sa) ; i++) {
        if ((ret = regcomp(reg, strarray_nth(sa, i), cflags)) != 0) {
            size_t errbuf_size = regerror(ret, reg, NULL, 0);

            buf_reset(&parse_script->sieveerr);
            buf_ensure(&parse_script->sieveerr, errbuf_size);
            (void) regerror(ret, reg,
                            (char *) buf_base(&parse_script->sieveerr),
                            errbuf_size);
            yyerror(parse_script, buf_cstring(&parse_script->sieveerr));
            break;
        }
    }

    free(reg);

    return (ret == 0);
}
#else

static int verify_regexlist(sieve_script_t *parse_script __attribute__((unused)),
                            const strarray_t *sa __attribute__((unused)),
                            char *comp __attribute__((unused)))
{
    return 0;
}
#endif /* ENABLE_REGEX */

static int verify_patternlist(sieve_script_t *parse_script,
                              strarray_t *sa, comp_t *c,
                              int (*verify)(sieve_script_t*, char *))
{
    if (verify && !verify_stringlist(parse_script, sa, verify)) return 0;

    canon_comptags(c);

    return (c->match == REGEX) ?
        verify_regexlist(parse_script, sa, c->collation) : 1;
}

static int verify_address(sieve_script_t *parse_script, char *s)
{
    parse_script->addrerr[0] = '\0';    /* paranoia */
    YY_BUFFER_STATE buffer = addr_scan_string(s);
    if (addrparse(parse_script)) {
        sieveerror_f(parse_script, "address '%s': %s", s, parse_script->addrerr);
        addr_delete_buffer(buffer);
        return 0;
    }
    addr_delete_buffer(buffer);
    return 1;
}

static int verify_mailbox(sieve_script_t *parse_script, char *s)
{
    if (!verify_utf8(parse_script, s)) return 0;

    /* xxx if not a mailbox, call yyerror */
    return 1;
}

static int verify_header(sieve_script_t *parse_script, char *hdr)
{
    char *h = hdr;

    while (*h) {
        /* field-name      =       1*ftext
           ftext           =       %d33-57 / %d59-126
           ; Any character except
           ;  controls, SP, and
           ;  ":". */
        if (!((*h >= 33 && *h <= 57) || (*h >= 59 && *h <= 126))) {
            sieveerror_f(parse_script, "header '%s': not a valid header", hdr);
            return 0;
        }
        h++;
    }
    return 1;
}

static int verify_addrheader(sieve_script_t *parse_script, char *hdr)
{
    const char **h, *hdrs[] = {
        "from", "sender", "reply-to",   /* RFC2822 originator fields */
        "to", "cc", "bcc",              /* RFC2822 destination fields */
        "resent-from", "resent-sender", /* RFC2822 resent fields */
        "resent-to", "resent-cc", "resent-bcc",
        "return-path",                  /* RFC2822 trace fields */
        "disposition-notification-to",  /* RFC2298 MDN request fields */
        "delivered-to",                 /* non-standard (loop detection) */
        "approved",                     /* RFC1036 moderator/control fields */
        NULL
    };

    if (!config_getswitch(IMAPOPT_RFC3028_STRICT))
        return verify_header(parse_script, hdr);

    for (lcase(hdr), h = hdrs; *h; h++) {
        if (!strcmp(*h, hdr)) return 1;
    }

    sieveerror_f(parse_script,
                 "header '%s': not a valid header for an address test", hdr);
    return 0;
}

static int verify_envelope(sieve_script_t *parse_script, char *env)
{
    lcase(env);
    if (!config_getswitch(IMAPOPT_RFC3028_STRICT) ||
        !strcmp(env, "from") || !strcmp(env, "to") || !strcmp(env, "auth")) {
        return 1;
    }

    sieveerror_f(parse_script,
                 "env-part '%s': not a valid part for an envelope test", env);
    return 0;
}

/*
 * Valid UTF-8 check (from RFC 2640 Annex B.1)
 *
 * The following routine checks if a byte sequence is valid UTF-8. This
 * is done by checking for the proper tagging of the first and following
 * bytes to make sure they conform to the UTF-8 format. It then checks
 * to assure that the data part of the UTF-8 sequence conforms to the
 * proper range allowed by the encoding. Note: This routine will not
 * detect characters that have not been assigned and therefore do not
 * exist.
 */
static int verify_utf8(sieve_script_t *parse_script, char *s)
{
    const char *buf = s;
    const char *endbuf = s + strlen(s);
    unsigned char byte2mask = 0x00, c;
    int trailing = 0;  /* trailing (continuation) bytes to follow */

    while (buf != endbuf) {
        c = *buf++;
        if (trailing) {
            if ((c & 0xC0) == 0x80) {           /* Does trailing byte
                                                   follow UTF-8 format? */
                if (byte2mask) {                /* Need to check 2nd byte
                                                   for proper range? */
                    if (c & byte2mask)          /* Are appropriate bits set? */
                        byte2mask = 0x00;
                    else
                        break;
                }
                trailing--;
            }
            else
                break;
        }
        else {
            if ((c & 0x80) == 0x00)             /* valid 1 byte UTF-8 */
                continue;
            else if ((c & 0xE0) == 0xC0)        /* valid 2 byte UTF-8 */
                if (c & 0x1E) {                 /* Is UTF-8 byte
                                                   in proper range? */
                    trailing = 1;
                }
                else
                    break;
            else if ((c & 0xF0) == 0xE0) {      /* valid 3 byte UTF-8 */
                if (!(c & 0x0F)) {              /* Is UTF-8 byte
                                                   in proper range? */
                    byte2mask = 0x20;           /* If not, set mask
                                                   to check next byte */
                }
                trailing = 2;
            }
            else if ((c & 0xF8) == 0xF0) {      /* valid 4 byte UTF-8 */
                if (!(c & 0x07)) {              /* Is UTF-8 byte
                                                   in proper range? */
                    byte2mask = 0x30;           /* If not, set mask
                                                   to check next byte */
                }
                trailing = 3;
            }
            else if ((c & 0xFC) == 0xF8) {      /* valid 5 byte UTF-8 */
                if (!(c & 0x03)) {              /* Is UTF-8 byte
                                                   in proper range? */
                    byte2mask = 0x38;           /* If not, set mask
                                                   to check next byte */
                }
                trailing = 4;
            }
            else if ((c & 0xFE) == 0xFC) {      /* valid 6 byte UTF-8 */
                if (!(c & 0x01)) {              /* Is UTF-8 byte
                                                   in proper range? */
                    byte2mask = 0x3C;           /* If not, set mask
                                                   to check next byte */
                }
                trailing = 5;
            }
            else
                break;
        }
    }

    if ((buf != endbuf) || trailing) {
        sieveerror_f(parse_script, "string '%s': not valid utf8", s);
        return 0;
    }

    return 1;
}

static int verify_list(sieve_script_t *parse_script, char *s)
{
    if (parse_script->interp.isvalidlist &&
        parse_script->interp.isvalidlist(parse_script->interp.interp_context, s)
        != SIEVE_OK) {
        sieveerror_f(parse_script, "list '%s': is not valid/supported", s);
        return 0;
    }

    return 1;
}

static int check_reqs(sieve_script_t *parse_script, strarray_t *sa)
{
    char *s;
    struct buf *errs = &parse_script->sieveerr;
    int ret = 1, sep = ':';

    buf_setcstr(errs, "Unsupported feature(s) in \"require\"");
    while ((s = strarray_shift(sa))) {
        if (!script_require(parse_script, s)) {
            buf_printf(errs, "%c \"%s\"", sep, s);
            ret = 0;
            sep = ',';
        }
        free(s);
    }
    strarray_free(sa);

    if (ret == 0) yyerror(parse_script, buf_cstring(&parse_script->sieveerr));

    return ret;
}

static commandlist_t *build_fileinto(sieve_script_t *parse_script,
                                     commandlist_t *c, char *folder)
{
    assert(c && c->type == FILEINTO);

    if (!verify_mailbox(parse_script, folder)) return NULL;

    if (config_getswitch(IMAPOPT_SIEVE_UTF8FILEINTO)) {
        c->u.f.folder = xmalloc(5 * strlen(folder) + 1);
        UTF8_to_mUTF7(c->u.f.folder, folder);
    }
    else c->u.f.folder = xstrdup(folder);

    return c;
}

static commandlist_t *build_redirect(sieve_script_t *parse_script,
                                     commandlist_t *c, char *address)
{
    assert(c && c->type == REDIRECT);

    if (c->u.r.list) {
        if (!verify_list(parse_script, address)) return NULL;
    }
    else if (!verify_address(parse_script, address)) return NULL;

    c->u.r.address = xstrdup(address);

    return c;
}

static int verify_identifier(sieve_script_t *parse_script, char *s)
{
    /* identifier         = (ALPHA / "_") *(ALPHA / DIGIT / "_") */

    if (!is_identifier(s)) {
        sieveerror_f(parse_script,
                     "string '%s': not a valid sieve identifier", s);
        return 0;
    }
    return 1;
}

static commandlist_t *build_set(sieve_script_t *parse_script,
                                commandlist_t *c, char *variable, char *value)
{
    assert(c && c->type == SET);

    if (!verify_identifier(parse_script, variable)) return NULL;
    if (!verify_utf8(parse_script, value)) return NULL;

    c->u.s.variable = xstrdup(variable);
    c->u.s.value = xstrdup(value);

    return c;
}

static commandlist_t *build_vacation(sieve_script_t *parse_script,
                                     commandlist_t *c, char *message)
{
    int min = parse_script->interp.vacation->min_response;
    int max = parse_script->interp.vacation->max_response;

    assert(c && c->type == VACATION);

    if ((c->u.v.mime == -1) && !verify_utf8(parse_script, message)) return NULL;

    c->u.v.from = xstrdupnull(c->u.v.from);
    c->u.v.handle = xstrdupnull(c->u.v.handle);
    c->u.v.subject = xstrdupnull(c->u.v.subject);
    c->u.v.message = xstrdup(message);

    if (c->u.v.seconds == -1) c->u.v.seconds = 7 * DAY2SEC;
    if (c->u.v.seconds < min) c->u.v.seconds = min;
    if (c->u.v.seconds > max) c->u.v.seconds = max;
    if (c->u.v.mime == -1) c->u.v.mime = 0;

    return c;
}

static commandlist_t *build_flag(sieve_script_t *parse_script,
                                 commandlist_t *c, strarray_t *flags)
{
    assert(c &&
           (c->type == SETFLAG || c->type == ADDFLAG || c->type == REMOVEFLAG));

    if (!parse_script->support.variables && !verify_flaglist(flags)) return NULL;

    if (!strarray_size(flags)) strarray_add(flags, "");
    c->u.fl.flags = flags;
    c->u.fl.variable = xstrdupsafe(c->u.fl.variable);

    return c;
}

static commandlist_t *build_addheader(sieve_script_t *parse_script,
                                      commandlist_t *c, char *name, char *value)
{
    assert(c && c->type == ADDHEADER);

    if (!verify_header(parse_script, name)) return NULL;
    if (!verify_utf8(parse_script, value)) return NULL;

    if (c->u.ah.index == 0) c->u.ah.index = 1;
    c->u.ah.name = xstrdup(name);
    c->u.ah.value = xstrdup(value);

    return c;
}

static commandlist_t *build_deleteheader(sieve_script_t *parse_script,
                                         commandlist_t *c,
                                         char *name, strarray_t *values)
{
    assert(c && c->type == DELETEHEADER);

    if (!strcasecmp("Received", name) || !strcasecmp("Auto-Submitted", name)) {
        sieveerror_f(parse_script,
                     "MUST NOT delete Received or Auto-Submitted headers");
        return NULL;
    }
    if (!verify_header(parse_script, name)) {
        return NULL;
    }
    if (!verify_patternlist(parse_script, values, &c->u.dh.comp, verify_utf8)) {
        return NULL;
    }

    c->u.dh.name = xstrdup(name);
    c->u.dh.values = values;

    return c;
}

static commandlist_t *build_reject(sieve_script_t *parse_script,
                                   int t, char *message)
{
    commandlist_t *c;

    assert(t == REJCT || t == EREJECT);

    if (!verify_utf8(parse_script, message)) return NULL;

    if ((c = new_command(t, parse_script))) c->u.reject = xstrdup(message);

    return c;
}

static commandlist_t *build_notify(sieve_script_t *parse_script,
                                   commandlist_t *c, int t, char *method)
{
    assert(c && (t == NOTIFY || t == ENOTIFY));

    if (t == ENOTIFY) {
        if (!parse_script->support.enotify) {
            sieveerror_c(parse_script, SIEVE_MISSING_REQUIRE, "enotify");
            return NULL;
        }
        if (c->u.n.id != NULL) {
            sieveerror_c(parse_script, SIEVE_UNEXPECTED_TAG, ":id");
            return NULL;
        }
        if (c->u.n.method != NULL) {
            sieveerror_c(parse_script, SIEVE_UNEXPECTED_TAG, ":method");
            return NULL;
        }

        c->u.n.method = xstrdup(method);
    }
    else {
        if (!parse_script->support.notify) {
            sieveerror_c(parse_script, SIEVE_MISSING_REQUIRE, "notify");
            return NULL;
        }
        if (c->u.n.from != NULL) {
            sieveerror_c(parse_script, SIEVE_UNEXPECTED_TAG, ":from");
            return NULL;
        }

        c->u.n.method = xstrdup(c->u.n.method ? c->u.n.method : "default");
    }

    c->type = t;
    if (c->u.n.priority == -1) c->u.n.priority = NORMAL;
    c->u.n.id = xstrdupnull(c->u.n.id);
    c->u.n.from = xstrdupnull(c->u.n.from);
    c->u.n.message =
        xstrdup(c->u.n.message ? c->u.n.message : "$from$: $subject$");

    return c;
}

static commandlist_t *build_denotify(commandlist_t *t)
{
    assert(t && t->type == DENOTIFY);

    canon_comptags(&t->u.d.comp);
    if (t->u.d.priority == -1) t->u.d.priority = ANY;
    t->u.d.pattern = xstrdup(t->u.d.pattern);

    return t;
}

static commandlist_t *build_include(sieve_script_t *parse_script,
                                    commandlist_t *c, char* script)
{
    assert(c && c->type == INCLUDE);

    if (strchr(script, '/')) {
        sieveerror_c(parse_script, SIEVE_INVALID_VALUE, "script-name");
        return NULL;
    }

    c->u.inc.script = xstrdup(script);
    if (c->u.inc.once == -1) c->u.inc.once = 0;
    if (c->u.inc.location == -1) c->u.inc.location = PERSONAL;
    if (c->u.inc.optional == -1) c->u.inc.optional = 0;

    return c;
}

static test_t *build_hhs(sieve_script_t *parse_script, test_t *t,
                         strarray_t *sl, strarray_t *pl)
{
    assert(t);

    if (!verify_patternlist(parse_script, pl, &t->u.hhs.comp, verify_utf8))
        return NULL;

    t->u.hhs.sl = sl;
    t->u.hhs.pl = pl;

    return t;
}

static test_t *build_header(sieve_script_t *parse_script, test_t *t,
                            strarray_t *sl, strarray_t *pl)
{
    assert(t && t->type == HEADER);

    if (!verify_stringlist(parse_script, sl, verify_header)) return NULL;

    return build_hhs(parse_script, t, sl, pl);
}

static test_t *build_stringt(sieve_script_t *parse_script, test_t *t,
                             strarray_t *sl, strarray_t *pl)
{
    assert(t && t->type == STRINGT);

    if (!verify_stringlist(parse_script, sl, verify_utf8)) return NULL;

    return build_hhs(parse_script, t, sl, pl);
}

static test_t *build_hasflag(sieve_script_t *parse_script, test_t *t,
                             strarray_t *sl, strarray_t *pl)
{
    assert(t && t->type == HASFLAG);

    if (sl) {
        if (!parse_script->support.variables) {
            sieveerror_c(parse_script, SIEVE_MISSING_REQUIRE, "variables");
            return NULL;
        }

        if (!verify_stringlist(parse_script, sl, verify_identifier)) return NULL;
    }

    return build_hhs(parse_script, t, sl, pl);
}

static test_t *build_ae(sieve_script_t *parse_script, test_t *t,
                        strarray_t *sl, strarray_t *pl)
{
    assert(t);

    if (!verify_patternlist(parse_script, pl, &t->u.ae.comp, NULL)) return NULL;

    if (t->u.ae.addrpart == -1) t->u.ae.addrpart = ALL;
    t->u.ae.sl = sl;
    t->u.ae.pl = pl;

    return t;
}

static test_t *build_address(sieve_script_t *parse_script, test_t *t,
                             strarray_t *sl, strarray_t *pl)
{
    assert(t && t->type == ADDRESS);

    if (!verify_stringlist(parse_script, sl, verify_addrheader)) return NULL;

    return build_ae(parse_script, t, sl, pl);
}

static test_t *build_envelope(sieve_script_t *parse_script, test_t *t,
                              strarray_t *sl, strarray_t *pl)
{
    assert(t && t->type == ENVELOPE);

    if (!verify_stringlist(parse_script, sl, verify_envelope)) return NULL;

    return build_ae(parse_script, t, sl, pl);
}

static test_t *build_body(sieve_script_t *parse_script,
                          test_t *t, strarray_t *pl)
{
    assert(t && (t->type == BODY));

    if (!verify_patternlist(parse_script, pl, &t->u.b.comp, verify_utf8))
        return NULL;

    if (t->u.b.offset == -1) t->u.b.offset = 0;
    if (t->u.b.transform == -1) t->u.b.transform = TEXT;
    if (t->u.b.content_types == NULL) {
        t->u.b.content_types = strarray_new();
        strarray_append(t->u.b.content_types,
                        (t->u.b.transform == RAW) ? "" : "text");
    }
    t->u.b.pl = pl;

    return t;
}

static test_t *build_date(sieve_script_t *parse_script,
                          test_t *t, char *hn, int part, strarray_t *kl)
{
    assert(t && (t->type == DATE || t->type == CURRENTDATE));

    if (hn && !verify_header(parse_script, hn)) return NULL;
    if (!verify_patternlist(parse_script, kl, &t->u.dt.comp, NULL)) return NULL;

    if (t->u.dt.comp.index == 0) t->u.dt.comp.index = 1;
    if (t->u.dt.zonetag == -1) {
        struct tm tm;
        time_t now = time(NULL);

        localtime_r(&now, &tm);
        t->u.dt.zone = gmtoff_of(&tm, now) / 60;
        t->u.dt.zonetag = ZONE;
    }

    t->u.dt.date_part = part;
    t->u.dt.header_name = xstrdupnull(hn);
    t->u.dt.kl = kl;

    return t;
}

static test_t *build_mbox_meta(sieve_script_t *s __attribute__((unused)),
                               test_t *t, const char *extname,
                               const char *keyname, strarray_t *keylist)
{
    assert(t && (t->type == MAILBOXEXISTS ||
                 t->type == METADATA || t->type == METADATAEXISTS ||
                 t->type == SERVERMETADATA || t->type == SERVERMETADATAEXISTS));

    canon_comptags(&t->u.mm.comp);
    t->u.mm.extname = xstrdupnull(extname);
    t->u.mm.keyname = xstrdupnull(keyname);
    t->u.mm.keylist = keylist;

    return t;
}

