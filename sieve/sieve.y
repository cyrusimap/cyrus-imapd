%{
/* sieve.y -- sieve parser
 * Larry Greenfield
 * Ken Murchison
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
#include "tok.h"

#define ERR_BUF_SIZE 1024

int encoded_char = 0;  /* used to send encoded-character feedback to lexer */
int getdatepart = 0;   /* used to send start state feedback to lexer */
static comp_t *ctags;  /* used for accessing comp_t* in a test/command union */

extern int addrparse(sieve_script_t*);
typedef struct yy_buffer_state *YY_BUFFER_STATE;
extern YY_BUFFER_STATE addr_scan_string(const char*);
extern void addr_delete_buffer(YY_BUFFER_STATE);

extern int sievelineno;

void sieveerror_c(sieve_script_t*, int code, ...);

static int check_reqs(sieve_script_t*, strarray_t *sl);
static int chk_match_vars(sieve_script_t*, char *s);

/* construct/canonicalize action commands */
static commandlist_t *build_keep(sieve_script_t*, commandlist_t *c);
static commandlist_t *build_fileinto(sieve_script_t*,
                                     commandlist_t *c, char *folder);
static commandlist_t *build_redirect(sieve_script_t*,
                                     commandlist_t *c, char *addr);
static commandlist_t *build_rej_err(sieve_script_t*, int t, char *message);
static commandlist_t *build_vacation(sieve_script_t*, commandlist_t *t, char *s);
static commandlist_t *build_flag(sieve_script_t*,
                                 commandlist_t *c, strarray_t *flags);
static commandlist_t *build_notify(sieve_script_t*, int t,
                                   commandlist_t *c, char *method);
static commandlist_t *build_denotify(sieve_script_t*, commandlist_t *c);
static commandlist_t *build_include(sieve_script_t*, commandlist_t *c, char*);
static commandlist_t *build_set(sieve_script_t*, commandlist_t *c,
                                char *variable, char *value);
static commandlist_t *build_addheader(sieve_script_t*, commandlist_t *c,
                                      char *name, char *value);
static commandlist_t *build_deleteheader(sieve_script_t*, commandlist_t *c,
                                         char *name, strarray_t *values);
static commandlist_t *build_log(sieve_script_t*, char *text);

/* construct/canonicalize test commands */
static test_t *build_anyof(sieve_script_t*, testlist_t *tl);
static test_t *build_allof(sieve_script_t*, testlist_t *tl);
static test_t *build_not(sieve_script_t*, test_t *t);
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
static test_t *build_ihave(sieve_script_t*, strarray_t *sa);
static test_t *build_mbox_meta(sieve_script_t*, test_t *t, char *extname,
                               char *keyname, strarray_t *keylist);
static test_t *build_duplicate(sieve_script_t*, test_t *t);
static test_t *build_jmapquery(sieve_script_t*, const char *json);

void yyerror(sieve_script_t*, const char *msg);
extern int yylex(void*, sieve_script_t*);
extern void sieverestart(FILE *f);

#define supported(capa) (sscript->support & capa)

#define _verify_flaglist(flags) \
  (supported(SIEVE_CAPA_VARIABLES) || verify_flaglist(flags))

#define YYERROR_VERBOSE /* I want better error messages! */

/* byacc default is 500, bison default is 10000 - go with the
   larger to support big sieve scripts (see Bug #3461) */
#define YYSTACKSIZE 10000
%}


%name-prefix "sieve"
%defines
%destructor  { free_tree($$);     } commands command action control thenelse elsif block
%destructor  { free_testlist($$); } testlist tests
%destructor  { free_test($$);     } test
%destructor  { strarray_free($$); } optstringlist stringlist strings string1
%destructor  { free($$);          } STRING string

%param   { sieve_script_t *sscript }
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
%type <sval> string
%type <sl> optstringlist stringlist strings string1
%type <cl> commands command action control
%type <testl> testlist tests
%type <test> test

/* standard control commands - RFC 5228 */
%token IF ELSIF ELSE REQUIRE STOP
%type <cl> thenelse elsif block

/* standard action commands - RFC 5228 */
%token DISCARD KEEP FILEINTO REDIRECT
%type <cl> ktags ftags rtags

/* standard tests - RFC 5228 */
%token ANYOF ALLOF EXISTS NOT SFALSE STRUE SIZE
%token HEADERT ADDRESS ENVELOPE COMPARATOR
%token <nval> OVER UNDER
%token <nval> ALL LOCALPART DOMAIN
%token <nval> IS CONTAINS MATCHES
%token <nval> OCTET ASCIICASEMAP ASCIINUMERIC
%type <test> htags atags etags
%type <nval> matchtag collation sizetag addrparttag

/* regex - draft-ietf-sieve-regex */
%token <nval> REGEX QUOTEREGEX

/* copy - RFC 3894 */
%token COPY

/* body - RFC 5173 */
%token BODY
%token <nval> RAW TEXT CONTENT
%type <test> btags
%type <nval> transform

/* environment - RFC 5183 */
%token ENVIRONMENT
%type <test> envtags

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

/* imapflags - draft-melnikov-sieve-imapflags-04 */
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
%token METHOD OPTIONS MESSAGE IMPORTANCE VALIDNOTIFYMETHOD NOTIFYMETHODCAPABILITY
%token <nval> NOTIFY ENOTIFY ENCODEURL
%type <cl> ntags
%type <nval> mod15
%type <test> methtags

/* notify - draft-martin-sieve-notify-01 */
%token DENOTIFY ID ANY
%token <nval> LOW NORMAL HIGH
%type <cl> dtags
%type <nval> priority

/* ihave - RFC 5463 */
%token IHAVE ERROR

/* mailbox - RFC 5490 */
%token MAILBOXEXISTS CREATE
%type <test> mtags

/* mboxmetadata - RFC 5490 */
%token <nval> METADATA
%token METADATAEXISTS

/* servermetadata - RFC 5490 */
%token <nval> SERVERMETADATA
%token SERVERMETADATAEXISTS

/* redirect-deliveryby - RFC 6009 */
%token BYTIMEREL BYTIMEABS BYMODE BYTRACE

/* redirect-dsn - RFC 6009 */
%token DSNNOTIFY DSNRET

/* extlists - RFC 6134 */
%token VALIDEXTLIST
%token <nval> LIST

/* include - RFC 6609 */
%token INCLUDE OPTIONAL ONCE RETURN
%token <nval> PERSONAL GLOBAL
%type <cl> itags
%type <nval> location

/* duplicate - RFC 7352 */
%token DUPLICATE
%token <nval> HEADER UNIQUEID
%type <test> duptags
%type <nval> idtype

/* special-use - RFC 8579 */
%token SPECIALUSEEXISTS SPECIALUSE

/* fcc - RFC 8580 */
%token FCC

/* draft-gondwana-sieve-mailboxid */
%token MAILBOXID MAILBOXIDEXISTS

/* x-cyrus-log */
%token LOG

/* x-cyrus-jmapquery */
%token JMAPQUERY


%%

/*
 * Yacc rules
 *
 * NOTE: In several place we use the inherited attribute $0,
 * which gives us access to the symbol to the left of the current rule.
 * This allows us to pass values "forward" by reference.
 */

/* Per RFC5228, Section 3.2, ALL require commands MUST appear first */
start:    reqs                   { sscript->cmds = NULL; }
        | reqs commands          { sscript->cmds = $2; }
        ;


reqs: /* empty */
        | require reqs
        ;


/* Can NOT be empty otherwise we get a shift/reduce conflict */
commands: command
        | command commands       { $$ = $1; $$->next = $2; }
        ;


command:  control
        | action ';'
        | error ';'              {
                                     struct buf buf = BUF_INITIALIZER;
                                     buf_printf(&buf, "%s: line %d",
                                                error_message(SIEVE_UNSUPP_EXT),
                                                sievelineno);
                                     sscript->support |= SIEVE_CAPA_IHAVE;
                                     $$ = build_rej_err(sscript, ERROR,
                                                        buf_release(&buf));
                                 }
        ;


optstringlist: /* empty */       { $$ = strarray_new(); }
        | stringlist
        ;


stringlist: string1
        | '[' strings ']'        { $$ = $2; }
        ;


strings:  string1
        | strings ',' string     { $$ = $1; strarray_appendm($$, $3); }
        ;


string1: string                  {
                                     $$ = strarray_new();
                                     strarray_appendm($$, $1);
                                 }
        ;


string: STRING                   { $$ = $1; chk_match_vars(sscript, $$); }
        ;


/*
 * Control commands
 */
require: REQUIRE stringlist ';'  { check_reqs(sscript, $2); }
        ;


control:  IF thenelse            { $$ = $2; }
        | STOP ';'               { $$ = new_command(STOP, sscript); }
        | ERROR string ';'       { $$ = build_rej_err(sscript, ERROR, $2); }
        ;


thenelse: test block elsif       { 
                                     if ($1->ignore_err) {
                                         /* end of block - decrement counter */
                                         sscript->ignore_err--;
                                     }

                                     $$ = new_if($1, $2, $3);
                                 }
        ;


elsif: /* empty */               { $$ = NULL; }
        | ELSIF thenelse         { $$ = $2; }
        | ELSE block             { $$ = $2; }
        ;


block: '{' commands '}'          { $$ = $2; }
        | '{' '}'                { $$ = NULL; }
        ;


/*
 * Action commands
 */
action:   KEEP ktags             { $$ = build_keep(sscript, $2); }
        | FILEINTO ftags string  { $$ = build_fileinto(sscript, $2, $3); }
        | REDIRECT rtags string  { $$ = build_redirect(sscript, $2, $3); }
        | DISCARD                { $$ = new_command(DISCARD, sscript); }
        | SET stags string string
                                 { $$ = build_set(sscript, $2, $3, $4); }
        | VACATION vtags string  { $$ = build_vacation(sscript, $2, $3); }

        /* SET/ADD/REMOVEFLAG */ 
        | flagaction flagtags stringlist
                                 { $$ = build_flag(sscript, $2, $3); }

        /* MARK/UNMARK */ 
        | flagmark               { $$ = new_command($1, sscript); }

        | ADDHEADER ahtags string string
                                 { $$ = build_addheader(sscript,
                                                        $2, $3, $4); }
        | DELETEHEADER dhtags string optstringlist
                                 { $$ = build_deleteheader(sscript,
                                                           $2, $3, $4); }

        | reject string          { $$ = build_rej_err(sscript, $1, $2); }
        | NOTIFY ntags string    { $$ = build_notify(sscript,
                                                     ENOTIFY, $2, $3); }

        | NOTIFY ntags           { $$ = build_notify(sscript,
                                                     NOTIFY, $2, NULL); }

        | DENOTIFY dtags         { $$ = build_denotify(sscript, $2); }
        | INCLUDE itags string   { $$ = build_include(sscript, $2, $3); }
        | LOG string             { $$ = build_log(sscript, $2); }
        | RETURN                 { $$ = new_command(RETURN, sscript); }
        ;


/* KEEP tagged arguments */
ktags: /* empty */               { $$ = new_command(KEEP, sscript); }
        | ktags flags
        ;


/* :flags */
flags: FLAGS stringlist          {
                                     /* $0 refers to ktags, ftags, or vtags */
                                     commandlist_t *c = $<cl>0;
                                     strarray_t **flags = NULL;

                                     switch (c->type) {
                                     case KEEP:
                                         flags = &c->u.k.flags; break;
                                     case FILEINTO:
                                         flags = &c->u.f.flags; break;
                                     case VACATION:
                                         flags = &c->u.v.fcc.flags; break;
                                     case ENOTIFY:
                                         flags = &c->u.n.fcc.flags; break;
                                     }

                                     if (*flags != NULL) {
                                         sieveerror_c(sscript,
                                                      SIEVE_DUPLICATE_TAG,
                                                      ":flags");
                                         strarray_free(*flags);
                                     }
                                     else if (!supported(SIEVE_CAPA_IMAP4FLAGS)) {
                                         sieveerror_c(sscript,
                                                      SIEVE_MISSING_REQUIRE,
                                                      "imap4flags");
                                     }

                                     *flags = $2;
                                 }
        ;


/* FILEINTO tagged arguments */
ftags: /* empty */               { $$ = new_command(FILEINTO, sscript); }
        | ftags copy
        | ftags flags
        | ftags create
        | ftags specialuse
        | ftags mailboxid
        ;


/* :copy */
copy: COPY                       {
                                     /* $0 refers to ftags or rtags */
                                     commandlist_t *c = $<cl>0;
                                     int *copy = (c->type == FILEINTO) ?
                                         &c->u.f.copy : &c->u.r.copy;

                                     if ((*copy)++) {
                                         sieveerror_c(sscript,
                                                      SIEVE_DUPLICATE_TAG,
                                                      ":copy");
                                     }
                                     else if (!supported(SIEVE_CAPA_COPY)) {
                                         sieveerror_c(sscript,
                                                      SIEVE_MISSING_REQUIRE,
                                                      "copy");
                                     }
                                 }
        ;


/* :create */
create: CREATE                  {
                                     /* $0 refers to ftags or vtags */
                                     commandlist_t *c = $<cl>0;
                                     int *create = NULL;

                                     switch (c->type) {
                                     case FILEINTO:
                                         create = &c->u.f.create; break;
                                     case VACATION:
                                         create = &c->u.v.fcc.create; break;
                                     case ENOTIFY:
                                         create = &c->u.n.fcc.create; break;
                                     }

                                     if ((*create)++) {
                                         sieveerror_c(sscript,
                                                      SIEVE_DUPLICATE_TAG,
                                                      ":create");
                                     }
                                     else if (!supported(SIEVE_CAPA_MAILBOX)) {
                                         sieveerror_c(sscript,
                                                      SIEVE_MISSING_REQUIRE,
                                                      "mailbox");
                                     }
                                 }
        ;


/* :specialuse */
specialuse: SPECIALUSE string    {
                                     /* $0 refers to ftags or vtags */
                                     commandlist_t *c = $<cl>0;
                                     char **specialuse = NULL;

                                     switch (c->type) {
                                     case FILEINTO:
                                         specialuse = &c->u.f.specialuse;
                                         break;
                                     case VACATION:
                                         specialuse = &c->u.v.fcc.specialuse;
                                         break;
                                     case ENOTIFY:
                                         specialuse = &c->u.n.fcc.specialuse;
                                         break;
                                     }

                                     if (*specialuse != NULL) {
                                         sieveerror_c(sscript,
                                                      SIEVE_DUPLICATE_TAG,
                                                      ":specialuse");
                                         free(*specialuse);
                                     }
                                     else if (!supported(SIEVE_CAPA_SPECIAL_USE)) {
                                         sieveerror_c(sscript,
                                                      SIEVE_MISSING_REQUIRE,
                                                      "special-use");
                                     }

                                     *specialuse = $2;
                                 }
        ;

mailboxid: MAILBOXID string      {
                                     /* $0 refers to ftags or vtags */
                                     commandlist_t *c = $<cl>0;
                                     char **mailboxid = NULL;

                                     switch (c->type) {
                                     case FILEINTO:
                                         mailboxid = &c->u.f.mailboxid;
                                         break;
                                     case VACATION:
                                         mailboxid = &c->u.v.fcc.mailboxid;
                                         break;
                                     case ENOTIFY:
                                         mailboxid = &c->u.n.fcc.mailboxid;
                                         break;
                                     }

                                     if (*mailboxid != NULL) {
                                         sieveerror_c(sscript,
                                                      SIEVE_DUPLICATE_TAG,
                                                      ":mailboxid");
                                         free(*mailboxid);
                                     }
                                     else if (!supported(SIEVE_CAPA_MAILBOXID)) {
                                         sieveerror_c(sscript,
                                                      SIEVE_MISSING_REQUIRE,
                                                      "mailboxid");
                                     }

                                     *mailboxid = $2;
                                 }
        ;


/* REDIRECT tagged arguments */
rtags: /* empty */               { $$ = new_command(REDIRECT, sscript); }
        | rtags copy
        | rtags LIST             {
                                     if ($$->u.r.list++) {
                                         sieveerror_c(sscript,
                                                      SIEVE_DUPLICATE_TAG,
                                                      ":list");
                                     }
                                     else if (!supported(SIEVE_CAPA_EXTLISTS)) {
                                         sieveerror_c(sscript,
                                                      SIEVE_MISSING_REQUIRE,
                                                      "extlists");
                                     }
                                 }
        | rtags delbytags        {
                                     if (!supported(SIEVE_CAPA_REDIR_DELBY)) {
                                         sieveerror_c(sscript,
                                                      SIEVE_MISSING_REQUIRE,
                                                      "redirect-deliverby");
                                     }
                                 }
        | rtags dsntags          {
                                     if (!supported(SIEVE_CAPA_REDIR_DSN)) {
                                         sieveerror_c(sscript,
                                                      SIEVE_MISSING_REQUIRE,
                                                      "redirect-dsn");
                                     }
                                 }
        ;

/* REDIRECT-DELIVERBY tagged arguments */
delbytags: BYTIMEREL NUMBER      {
                                     /* $0 refers to rtags */
                                     commandlist_t *c = $<cl>0;

                                     if (c->u.r.bytime != NULL) {
                                         sieveerror_c(sscript,
                                                      SIEVE_DUPLICATE_TAG,
                                                      ":bytime*");
                                     }                                         

                                     struct buf buf = BUF_INITIALIZER;
                                     buf_printf(&buf, "+%d", $2);
                                     c->u.r.bytime = buf_release(&buf);
                                 }
        | BYTIMEABS string       {
                                     /* $0 refers to rtags */
                                     commandlist_t *c = $<cl>0;

                                     if (c->u.r.bytime != NULL) {
                                         sieveerror_c(sscript,
                                                      SIEVE_DUPLICATE_TAG,
                                                      ":bytimerelative"
                                                      " OR :bytimeabsolute");
                                     }

                                     c->u.r.bytime = $2;
                                 }
        | BYMODE string          {
                                     /* $0 refers to rtags */
                                     commandlist_t *c = $<cl>0;

                                     if (c->u.r.bymode != NULL) {
                                         sieveerror_c(sscript,
                                                      SIEVE_DUPLICATE_TAG,
                                                      ":bymode");
                                     }

                                     c->u.r.bymode = $2;
                                 }
        | BYTRACE                {
                                     /* $0 refers to rtags */
                                     commandlist_t *c = $<cl>0;

                                     if (c->u.r.bytrace != 0) {
                                         sieveerror_c(sscript,
                                                      SIEVE_DUPLICATE_TAG,
                                                      ":bytrace");
                                     }

                                     c->u.r.bytrace = 1;
                                 }
        ;


/* REDIRECT-DSN tagged arguments */
dsntags:  DSNNOTIFY string       {
                                     /* $0 refers to rtags */
                                     commandlist_t *c = $<cl>0;

                                     if (c->u.r.dsn_notify != NULL) {
                                         sieveerror_c(sscript,
                                                      SIEVE_DUPLICATE_TAG,
                                                      ":notify");
                                     }                                         

                                     c->u.r.dsn_notify = $2;
                                 }
        | DSNRET string          {
                                     /* $0 refers to rtags */
                                     commandlist_t *c = $<cl>0;

                                     if (c->u.r.dsn_ret != NULL) {
                                         sieveerror_c(sscript,
                                                      SIEVE_DUPLICATE_TAG,
                                                      ":ret");
                                     }

                                     c->u.r.dsn_ret = $2;
                                 }
        ;


/* SET tagged arguments */
stags: /* empty */               { $$ = new_command(SET, sscript); }
        | stags mod40            {
                                     if ($$->u.s.mod40) {
                                         sieveerror_c(sscript,
                                                      SIEVE_DUPLICATE_TAG,
                                                      "precedence 40 modifier");
                                     }

                                     $$->u.s.mod40 = $2;
                                 }
        | stags mod30            {
                                     if ($$->u.s.mod30) {
                                         sieveerror_c(sscript,
                                                      SIEVE_DUPLICATE_TAG,
                                                      "precedence 30 modifier");
                                     }

                                     $$->u.s.mod30 = $2;
                                 }
        | stags mod20            {
                                     if ($$->u.s.mod20) {
                                         sieveerror_c(sscript,
                                                      SIEVE_DUPLICATE_TAG,
                                                      "precedence 20 modifier");
                                     }

                                     $$->u.s.mod20 = $2;
                                 }
        | stags mod15            {
                                     if ($$->u.s.mod15) {
                                         sieveerror_c(sscript,
                                                      SIEVE_DUPLICATE_TAG,
                                                      "precedence 15 modifier");
                                     }

                                     $$->u.s.mod15 = $2;
                                 }
        | stags mod10            {
                                     if ($$->u.s.mod10) {
                                         sieveerror_c(sscript,
                                                      SIEVE_DUPLICATE_TAG,
                                                      "precedence 10 modifier");
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
        | QUOTEREGEX            { 
                                     if (!supported(SIEVE_CAPA_REGEX)) {
                                         sieveerror_c(sscript,
                                                      SIEVE_MISSING_REQUIRE,
                                                      "regex");
                                     }
                                 }

        ;

mod15:    ENCODEURL              { 
                                     if (!supported(SIEVE_CAPA_ENOTIFY)) {
                                         sieveerror_c(sscript,
                                                      SIEVE_MISSING_REQUIRE,
                                                      "enotify");
                                     }
                                 }
        ;

mod10:    LENGTH
        ;


/* VACATION tagged arguments */
vtags: /* empty */               { $$ = new_command(VACATION, sscript); }
        | vtags DAYS NUMBER      {
                                     if ($$->u.v.seconds != -1) {
                                         sieveerror_c(sscript,
                                                      SIEVE_DUPLICATE_TAG,
                                                      ":days");
                                     }

                                     $$->u.v.seconds = $3 * DAY2SEC;
                                 }
        | vtags SECONDS NUMBER   {
                                     if (!supported(SIEVE_CAPA_VACATION_SEC)) {
                                         sieveerror_c(sscript,
                                                      SIEVE_MISSING_REQUIRE,
                                                      "vacation-seconds");
                                     }
                                     if ($$->u.v.seconds != -1) {
                                         sieveerror_c(sscript,
                                                      SIEVE_DUPLICATE_TAG,
                                                      ":seconds");
                                     }

                                     $$->u.v.seconds = $3;
                                 }
        | vtags SUBJECT string   {
                                     if ($$->u.v.subject != NULL) {
                                         sieveerror_c(sscript,
                                                      SIEVE_DUPLICATE_TAG,
                                                      ":subject");
                                         free($$->u.v.subject);
                                     }

                                     $$->u.v.subject = $3;
                                 }
        | vtags FROM string      {
                                     if ($$->u.v.from != NULL) {
                                         sieveerror_c(sscript,
                                                      SIEVE_DUPLICATE_TAG,
                                                      ":from");
                                         free($$->u.v.from);
                                     }

                                     $$->u.v.from = $3;
                                 }

        | vtags ADDRESSES stringlist
                                 {
                                     if ($$->u.v.addresses != NULL) {
                                         sieveerror_c(sscript,
                                                      SIEVE_DUPLICATE_TAG,
                                                      ":addresses");
                                         strarray_free($$->u.v.addresses);
                                     }

                                     $$->u.v.addresses = $3;
                                 }
        | vtags MIME             {
                                     if ($$->u.v.mime != -1) {
                                         sieveerror_c(sscript,
                                                      SIEVE_DUPLICATE_TAG,
                                                      ":mime");
                                     }

                                     $$->u.v.mime = 1;
                                 }
        | vtags HANDLE string    {
                                     if ($$->u.v.handle != NULL) {
                                         sieveerror_c(sscript,
                                                      SIEVE_DUPLICATE_TAG,
                                                      ":handle");
                                         free($$->u.v.handle);
                                     }

                                     $$->u.v.handle = $3;
                                 }
        | vtags fcctags
        ;


fcctags: FCC string              {
                                     /* $0 refers to vtags or ntags */
                                     commandlist_t *c = $<cl>0;
                                     char **folder = NULL;

                                     switch (c->type) {
                                     case VACATION:
                                         folder = &c->u.v.fcc.folder; break;
                                     case ENOTIFY:
                                         folder = &c->u.n.fcc.folder; break;
                                     }

                                     if (*folder != NULL) {
                                         sieveerror_c(sscript,
                                                      SIEVE_DUPLICATE_TAG,
                                                      ":fcc");
                                         free(*folder);
                                     }
                                     else if (!supported(SIEVE_CAPA_FCC)) {
                                         sieveerror_c(sscript,
                                                      SIEVE_MISSING_REQUIRE,
                                                      "fcc");
                                     }

                                     *folder = $2;
                                 }
        | create
        | flags
        | specialuse
        ;


/* SET/ADD/REMOVEFLAG */
flagaction: SETFLAG
        | ADDFLAG
        | REMOVEFLAG
        ;


/* SET/ADD/REMOVEFLAG tagged arguments - $0 refers to flagaction */
flagtags: /* empty */            { $$ = new_command($<nval>0, sscript); }
        | flagtags string        {
                                     if ($$->u.fl.variable != NULL) {
                                         sieveerror_c(sscript,
                                                      SIEVE_DUPLICATE_ARG,
                                                      "variablename");
                                         free($$->u.fl.variable);
                                     }
                                     else if (!supported(SIEVE_CAPA_IMAP4FLAGS)) {
                                         sieveerror_c(sscript,
                                                      SIEVE_MISSING_REQUIRE,
                                                      "imap4flags");
                                     }

                                     $$->u.fl.variable = $2;
                                 }
        ;


/* MARK/UNMARK */
flagmark: MARK
        | UNMARK
        ;


/* ADDHEADER tagged arguments */
ahtags: /* empty */              { $$ = new_command(ADDHEADER, sscript); }
        | ahtags LAST            {
                                     if ($$->u.ah.index < 0) {
                                         sieveerror_c(sscript,
                                                      SIEVE_DUPLICATE_TAG,
                                                      ":last");
                                     }

                                     $$->u.ah.index = -1;
                                 }
        ;


/* DELETEHEADER tagged arguments */
dhtags: /* empty */              { $$ = new_command(DELETEHEADER, sscript);}
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
ntags: /* empty */               { $$ = new_command(ENOTIFY, sscript); }

        /* enotify-only tagged arguments */
        | ntags FROM string      {
                                     if ($$->u.n.from != NULL) {
                                         sieveerror_c(sscript,
                                                      SIEVE_DUPLICATE_TAG,
                                                      ":from");
                                         free($$->u.n.from);
                                     }

                                     $$->u.n.from = $3;
                                 }

        | ntags IMPORTANCE priority
                                 {
                                     if ($$->u.n.priority != -1) {
                                         sieveerror_c(sscript,
                                                      SIEVE_DUPLICATE_TAG,
                                                      ":importance");
                                     }

                                     $$->u.n.priority = $3;
                                 }
        | ntags fcctags

        /* legacy-only tagged arguments */
        | ntags ID string        {
                                     if ($$->u.n.id != NULL) {
                                         sieveerror_c(sscript,
                                                      SIEVE_DUPLICATE_TAG,
                                                      ":id");
                                         free($$->u.n.id);
                                     }

                                     $$->u.n.id = $3;
                                 }
        | ntags METHOD string    {
                                     if ($$->u.n.method != NULL) {
                                         sieveerror_c(sscript,
                                                      SIEVE_DUPLICATE_TAG,
                                                      ":method");
                                         free($$->u.n.method);
                                     }

                                     $$->u.n.method = $3;
                                 }
        | ntags priority         {
                                     if ($$->u.n.priority != -1) {
                                         sieveerror_c(sscript,
                                                      SIEVE_DUPLICATE_TAG,
                                                      "priority");
                                     }

                                     $$->u.n.priority = $2;
                                 }

        /* common tagged arguments */
        | ntags MESSAGE string   {
                                     if ($$->u.n.message != NULL) {
                                         sieveerror_c(sscript,
                                                      SIEVE_DUPLICATE_TAG,
                                                      ":message");
                                         free($$->u.n.message);
                                     }

                                     $$->u.n.message = $3;
                                 }

        | ntags OPTIONS stringlist
                                 {
                                     if ($$->u.n.options != NULL) {
                                         sieveerror_c(sscript,
                                                      SIEVE_DUPLICATE_TAG,
                                                      ":options");
                                         strarray_free($$->u.n.options);
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
dtags: /* empty */               { $$ = new_command(DENOTIFY, sscript); }
        | dtags priority         {
                                     if ($$->u.d.priority != -1) {
                                         sieveerror_c(sscript,
                                                      SIEVE_DUPLICATE_TAG,
                                                      "priority");
                                     }

                                     $$->u.d.priority = $2;
                                 }

        | dtags { ctags = &($1->u.d.comp); } matchtype string
                                 {
                                     if ($$->u.d.pattern) free($$->u.d.pattern);
                                     $$->u.d.pattern = $4;
                                 }
        ;


/* INCLUDE tagged arguments */
itags: /* empty */               { $$ = new_command(INCLUDE, sscript); }
        | itags location         {
                                     if ($$->u.inc.location != -1) {
                                         sieveerror_c(sscript,
                                                      SIEVE_DUPLICATE_TAG,
                                                      "location");
                                     }

                                     $$->u.inc.location = $2;
                                 }
        | itags ONCE             {
                                     if ($$->u.inc.once != -1) {
                                         sieveerror_c(sscript,
                                                      SIEVE_DUPLICATE_TAG,
                                                      ":once");
                                     }

                                     $$->u.inc.once = 1;
                                 }
        | itags OPTIONAL         {
                                     if ($$->u.inc.optional != -1) {
                                         sieveerror_c(sscript,
                                                      SIEVE_DUPLICATE_TAG,
                                                      ":optional");
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


test:     ANYOF testlist         { $$ = build_anyof(sscript, $2); }
        | ALLOF testlist         { $$ = build_allof(sscript, $2); }
        | NOT test               { $$ = build_not(sscript, $2);   }
        | SFALSE                 { $$ = new_test(SFALSE, sscript); }
        | STRUE                  { $$ = new_test(STRUE, sscript);  }
        | EXISTS stringlist      {
                                     $$ = new_test(EXISTS, sscript);
                                     $$->u.sl = $2;
                                 }
        | SIZE sizetag NUMBER    {
                                     $$ = new_test(SIZE, sscript);
                                     $$->u.sz.t = $2;
                                     $$->u.sz.n = $3;
                                 }

        | HEADERT htags stringlist stringlist
                                 { $$ = build_header(sscript, $2, $3, $4); }

        | ADDRESS atags stringlist stringlist
                                 { $$ = build_address(sscript, $2, $3, $4); }
        | ENVELOPE etags stringlist stringlist
                                 { $$ = build_envelope(sscript, $2, $3, $4); }

        | BODY btags stringlist  { $$ = build_body(sscript, $2, $3); }

        | ENVIRONMENT envtags string stringlist
                                 { $$ = build_mbox_meta(sscript,
                                                        $2, NULL, $3, $4); }

        | STRINGT strtags stringlist stringlist
                                 { $$ = build_stringt(sscript, $2, $3, $4); }

        /* Per RFC 5232, the variables list (penultimate argument) is optional,
         * but defining the grammar this way results in a shift/reduce conflict.
         * Therefore, we have to flatten the grammar into two rules.
        */
        | HASFLAG hftags stringlist stringlist
                                 { $$ = build_hasflag(sscript, $2, $3, $4); }
        | HASFLAG hftags stringlist
                                 { $$ = build_hasflag(sscript, $2, NULL, $3); }

        /* getdatepart variable is used to change the start state of the lexer */
        | DATE dttags string { getdatepart = 1; } datepart stringlist
                                 { $$ = build_date(sscript, $2, $3, $5, $6); }

        | CURRENTDATE cdtags datepart stringlist
                                 { $$ = build_date(sscript, $2, NULL, $3, $4); }
        | VALIDNOTIFYMETHOD stringlist
                                 {
                                     $$ = new_test(VALIDNOTIFYMETHOD, sscript);
                                     $$->u.sl = $2;
                                 }
        | NOTIFYMETHODCAPABILITY methtags string string stringlist
                                 { $$ = build_mbox_meta(sscript,
                                                        $2, $3, $4, $5); }

        | IHAVE stringlist       { $$ = build_ihave(sscript, $2); }

        | MAILBOXEXISTS stringlist
                                 {
                                     $$ = new_test(MAILBOXEXISTS, sscript);
                                     $$ = build_mbox_meta(sscript,
                                                          $$, NULL, NULL, $2);
                                 }

        | METADATA mtags string string stringlist
                                 { $$ = build_mbox_meta(sscript,
                                                        $2, $3, $4, $5); }

        | METADATAEXISTS string stringlist
                                 {
                                     $$ = new_test(METADATAEXISTS, sscript);
                                     $$ = build_mbox_meta(sscript,
                                                          $$, $2, NULL, $3);
                                 }

        | SERVERMETADATA mtags string stringlist
                                 { $$ = build_mbox_meta(sscript,
                                                        $2, NULL, $3, $4); }

        | SERVERMETADATAEXISTS stringlist
                                 {
                                     $$ = new_test(SERVERMETADATAEXISTS,
                                                   sscript);
                                     $$ = build_mbox_meta(sscript,
                                                          $$, NULL, NULL, $2);
                                 }

        | VALIDEXTLIST stringlist
                                 {
                                     $$ = new_test(VALIDEXTLIST, sscript);
                                     $$->u.sl = $2;
                                 }
        | DUPLICATE duptags      { $$ = build_duplicate(sscript, $2); }

        | SPECIALUSEEXISTS stringlist
                                 { 
                                     $$ = new_test(SPECIALUSEEXISTS, sscript);
                                     $$ = build_mbox_meta(sscript,
                                                          $$, NULL, NULL, $2);
                                 }

        | SPECIALUSEEXISTS string stringlist
                                 {
                                     $$ = new_test(SPECIALUSEEXISTS, sscript);
                                     $$ = build_mbox_meta(sscript,
                                                          $$, $2, NULL, $3);
                                 }

        | MAILBOXIDEXISTS stringlist
                                 {
                                     $$ = new_test(MAILBOXIDEXISTS, sscript);
                                     $$ = build_mbox_meta(sscript,
                                                          $$, NULL, NULL, $2);
                                 }

        | JMAPQUERY string       { $$ = build_jmapquery(sscript, $2); }

        | error                  { $$ = new_test(SFALSE, sscript); }
        ;


/* SIZE tagged arguments */
sizetag:  OVER
        | UNDER
        ;


/* HEADER tagged arguments */
htags: /* empty */               { $$ = new_test(HEADERT, sscript); }
        | htags { ctags = &($1->u.hhs.comp); } matchtype
        | htags { ctags = &($1->u.hhs.comp); } listmatch
        | htags { ctags = &($1->u.hhs.comp); } comparator
        | htags { ctags = &($1->u.hhs.comp); } idxtags
        ;


/* All match-types except for :list */
matchtype: matchtag              {
                                     if (ctags->match != -1) {
                                         sieveerror_c(sscript,
                                                      SIEVE_DUPLICATE_TAG,
                                                      "match-type");
                                     }

                                     ctags->match = $1;
                                 }
        | relmatch relation
                                 {
                                     if (ctags->match != COUNT &&
                                         ctags->match != VALUE &&
                                         !supported(SIEVE_CAPA_RELATIONAL)) {
                                         sieveerror_c(sscript,
                                                      SIEVE_MISSING_REQUIRE,
                                                      "relational");
                                     }
                                     if (ctags->match != -1) {
                                         sieveerror_c(sscript,
                                                      SIEVE_DUPLICATE_TAG,
                                                      "match-type");
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
                                     if (!supported(SIEVE_CAPA_REGEX)) {
                                         sieveerror_c(sscript,
                                                      SIEVE_MISSING_REQUIRE,
                                                      "regex");
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
listmatch: LIST                  {
                                     if (ctags->match != LIST &&
                                         !supported(SIEVE_CAPA_EXTLISTS)) {
                                         sieveerror_c(sscript,
                                                      SIEVE_MISSING_REQUIRE,
                                                      "extlists");
                                     }
                                     if (ctags->match != -1) {
                                         sieveerror_c(sscript,
                                                      SIEVE_DUPLICATE_TAG,
                                                      "match-type");
                                     }

                                     ctags->match = LIST;
                                 }
        ;


/* :comparator */
comparator: COMPARATOR collation
                                 {
                                     if (ctags->collation != -1) {
                                         sieveerror_c(sscript,
                                                      SIEVE_DUPLICATE_TAG,
                                                      ":comparator");
                                     }

                                     ctags->collation = $2;
                                 }
        ;


/* comparator-types */
collation: OCTET
        | ASCIICASEMAP
        | ASCIINUMERIC           {
                                     if (!supported(SIEVE_CAPA_COMP_NUMERIC)) {
                                         sieveerror_c(sscript,
                                                      SIEVE_MISSING_REQUIRE,
                                                      "comparator-"
                                                      "i;ascii-numeric");
                                     }
                                 }
        ;


/* Index tags */
idxtags: INDEX NUMBER            {
                                     if (ctags->index == INT_MIN) {
                                         /* :last before :index */
                                         ctags->index = -$2;
                                     }
                                     else if (ctags->index != 0) {
                                         sieveerror_c(sscript,
                                                      SIEVE_DUPLICATE_TAG,
                                                      ":index");
                                     }
                                     else {
                                       if (!supported(SIEVE_CAPA_INDEX)) {
                                             sieveerror_c(sscript,
                                                          SIEVE_MISSING_REQUIRE,
                                                          "index");
                                         }

                                         ctags->index = $2;
                                     }
                                 }
        | LAST                   {
                                     if (ctags->index > 0) {
                                         ctags->index *= -1;
                                     }
                                     else if (ctags->index < 0) {
                                         sieveerror_c(sscript,
                                                      SIEVE_DUPLICATE_TAG,
                                                      ":last");
                                     }
                                     else if (ctags->index == 0) {
                                       if (!supported(SIEVE_CAPA_INDEX)) {
                                             sieveerror_c(sscript,
                                                          SIEVE_MISSING_REQUIRE,
                                                          "index");
                                         }

                                         /* :last before :index */
                                         ctags->index = INT_MIN;
                                     }
                                 }
        ;


/* ADDRESS tagged arguments */
atags: /* empty */               { $$ = new_test(ADDRESS, sscript); }
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
                                         sieveerror_c(sscript,
                                                      SIEVE_DUPLICATE_TAG,
                                                      "address-part");
                                     }

                                     test->u.ae.addrpart = $1;
                                 }


/* address-part tags */
addrparttag: ALL
        | LOCALPART
        | DOMAIN
        | subaddress             {
                                     if (!supported(SIEVE_CAPA_SUBADDRESS)) {
                                         sieveerror_c(sscript,
                                                      SIEVE_MISSING_REQUIRE,
                                                      "subaddress");
                                     }
                                 }
        ;


/* subaddress-part tags */
subaddress: USER
        | DETAIL
        ;


/* ENVELOPE tagged arguments */
etags: /* empty */               { $$ = new_test(ENVELOPE, sscript); }
        | etags addrpart
        | etags { ctags = &($1->u.ae.comp); } matchtype
        | etags { ctags = &($1->u.ae.comp); } listmatch
        | etags { ctags = &($1->u.ae.comp); } comparator
        ;


/* ENVIRONMENT tagged arguments */
envtags: /* empty */               { $$ = new_test(ENVIRONMENT, sscript); }
        | envtags { ctags = &($1->u.mm.comp); } matchtype
        | envtags { ctags = &($1->u.mm.comp); } comparator
        ;


/* BODY tagged arguments */
btags: /* empty */               { $$ = new_test(BODY, sscript); }
        | btags transform        {
                                     if ($$->u.b.transform != -1) {
                                         sieveerror_c(sscript,
                                                      SIEVE_DUPLICATE_TAG,
                                                      "transform");
                                     }

                                     $$->u.b.transform = $2;
                                 }

        | btags CONTENT stringlist
                                 {
                                     if ($$->u.b.transform != -1) {
                                         sieveerror_c(sscript,
                                                      SIEVE_DUPLICATE_TAG,
                                                      "transform");
                                         strarray_free($$->u.b.content_types);
                                     }

                                     $$->u.b.transform = CONTENT;
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
strtags: /* empty */             { $$ = new_test(STRINGT, sscript); }
        | strtags { ctags = &($1->u.hhs.comp); } matchtype
        | strtags { ctags = &($1->u.hhs.comp); } listmatch
        | strtags { ctags = &($1->u.hhs.comp); } comparator
        ;


/* HASFLAG tagged arguments */
hftags: /* empty */              { $$ = new_test(HASFLAG, sscript); }
        | hftags { ctags = &($1->u.hhs.comp); } matchtype
        | hftags { ctags = &($1->u.hhs.comp); } comparator
        ;


/* DATE tagged arguments */
dttags: /* empty */              { $$ = new_test(DATE, sscript); }
        | dttags zone
        | dttags ORIGINALZONE    {
                                     if ($$->u.dt.zonetag != -1) {
                                         sieveerror_c(sscript,
                                                      SIEVE_DUPLICATE_TAG,
                                                      ":originalzone");
                                     }

                                     $$->u.dt.zonetag = ORIGINALZONE;
                                 }
        | dttags { ctags = &($1->u.dt.comp); } matchtype
        | dttags { ctags = &($1->u.dt.comp); } comparator
        | dttags { ctags = &($1->u.dt.comp); } idxtags
        ;


/* :zone */
zone: ZONE TIMEZONE              {
                                     /* $0 refers to a test_t* ([CURRENT]DATE)*/
                                     test_t *test = $<test>0;

                                     if (test->u.dt.zonetag != -1) {
                                         sieveerror_c(sscript,
                                                      SIEVE_DUPLICATE_TAG,
                                                      ":zone");
                                     }

                                     test->u.dt.zonetag = ZONE;
                                     test->u.dt.zone = $2;
                                 }
        ;


/* CURRENTDATE tagged arguments */
cdtags: /* empty */              { $$ = new_test(CURRENTDATE, sscript); }
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


/* NOTIFYMETHODCAPABILITY tagged arguments */
methtags: /* empty */            { $$ = new_test(NOTIFYMETHODCAPABILITY, sscript); }
        | methtags { ctags = &($1->u.mm.comp); } matchtype
        | methtags { ctags = &($1->u.mm.comp); } comparator
        ;


/* [SERVER]METADATA tagged arguments - $0 refers to [SERVER]METADATA */
mtags: /* empty */               { $$ = new_test($<nval>0, sscript); }
        | mtags { ctags = &($1->u.mm.comp); } matchtype
        | mtags { ctags = &($1->u.mm.comp); } comparator
        ;


/* DUPLICATE tagged arguments */
duptags: /* empty */             { $$ = new_test(DUPLICATE, sscript); }
        | duptags idtype string  {
                                     if ($$->u.dup.idtype != -1) {
                                         sieveerror_c(sscript,
                                                      SIEVE_DUPLICATE_TAG,
                                                      $2 == HEADER ?
                                                      ":header" : ":uniqueid");
                                         free($$->u.dup.idval);
                                     }

                                     $$->u.dup.idtype = $2;
                                     $$->u.dup.idval = $3;
                                 }
        | duptags HANDLE string  {
                                     if ($$->u.dup.handle != NULL) {
                                         sieveerror_c(sscript,
                                                      SIEVE_DUPLICATE_TAG,
                                                      ":handle");
                                         free($$->u.dup.handle);
                                     }

                                     $$->u.dup.handle = $3;
                                 }
        | duptags SECONDS NUMBER {
                                     if ($$->u.dup.seconds != -1) {
                                         sieveerror_c(sscript,
                                                      SIEVE_DUPLICATE_TAG,
                                                      ":seconds");
                                     }

                                     $$->u.dup.seconds = $3;
                                 }
        | duptags LAST           {
                                     if ($$->u.dup.last != 0) {
                                         sieveerror_c(sscript,
                                                      SIEVE_DUPLICATE_TAG,
                                                      ":last");
                                     }

                                     $$->u.dup.last = 1;
                                 }
        ;


/* DUPLICATE idtypes */
idtype:   HEADER
        | UNIQUEID
        ;


%%


/*
 * Yacc actions
 */

void yyerror(sieve_script_t *sscript, const char *msg)
{
    if (sscript->ignore_err) return;

    sscript->err++;
    if (sscript->interp.err) {
        sscript->interp.err(sievelineno, msg, sscript->interp.interp_context,
                            sscript->script_context);
    }
}


static void vsieveerror_f(sieve_script_t *sscript,
                          const char *fmt, va_list args)
{
    buf_reset(&sscript->sieveerr);
    buf_vprintf(&sscript->sieveerr, fmt, args);
    yyerror(sscript, buf_cstring(&sscript->sieveerr));
}

void sieveerror_f(sieve_script_t *sscript, const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    vsieveerror_f(sscript, fmt, args);
    va_end(args);
}

void sieveerror_c(sieve_script_t *sscript, int code, ...)
{
    va_list args;

    va_start(args, code);
    vsieveerror_f(sscript, error_message(code), args);
    va_end(args);
}

/*
 * variable-ref        =  "${" [namespace] variable-name "}"
 * namespace           =  identifier "." *sub-namespace
 * sub-namespace       =  variable-name "."
 * variable-name       =  num-variable / identifier
 * num-variable        =  1*DIGIT
 * identifier          =  (ALPHA / "_") *(ALPHA / DIGIT / "_")
 */
static int find_variables(sieve_script_t *sscript, char *s, int find_one)
{
    char *p = s;

    if (!supported(SIEVE_CAPA_VARIABLES)) return !find_one;

    while ((p = strstr(p, "${"))) {
        long num = 0, is_id = 0;

        p += 2;  /* skip over beginning of variable-ref */

        do {
            if (isdigit(*p)) {
                /* possible num-variable - get value and skip over digits */
                num = strtol(p, &p, 10);
            }
            else if (!find_one) {
                /* validating match variables - ignoroe identifiers */
                break;
            }
            else if (isalpha(*p) || *p == '_') {
                /* possible identifier - skip over identifier chars */
                for (++p; isalnum(*p) || *p == '_'; p++);
                is_id = 1;
            }
            else {
                /* not a valid variable-name */
                break;
            }

            if (*p == '}') {
                /* end of variable-ref */
                if (find_one) return 1;

                /* validating match variables */
                if (!is_id && num > MAX_MATCH_VARS) {
                    sieveerror_f(sscript, "string '%s':"
                                 " match variable index > %u unsupported",
                                 s, MAX_MATCH_VARS);
                    return 0;
                }
            }

        } while (is_id && *p == '.' && *(++p));  /* (sub-)namespace */
    }

    return !find_one;
}

static int chk_match_vars(sieve_script_t *sscript, char *s)
{
    return find_variables(sscript, s, 0 /* find_one */);
}

static int contains_variable(sieve_script_t *sscript, char *s)
{
    return find_variables(sscript, s, 1 /* find_one */);
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
static int verify_utf8(sieve_script_t *sscript, char *s)
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
        sieveerror_f(sscript, "string '%s': not valid utf8", s);
        return 0;
    }

    return 1;
}

static int verify_stringlist(sieve_script_t *sscript, strarray_t *sa,
                             int (*verify)(sieve_script_t*, char *))
{
    int i;

    for (i = 0 ; i < strarray_size(sa) ; i++) {
        if (!verify(sscript, (char *) strarray_nth(sa, i))) return 0;
    }
    return 1;
}

#ifdef ENABLE_REGEX
static int verify_regexlist(sieve_script_t *sscript,
                            const strarray_t *sa, int collation)
{
    int i, ret = 0;
    regex_t reg;
    int cflags = REG_EXTENDED | REG_NOSUB;

#ifdef HAVE_PCREPOSIX_H
    /* support UTF8 comparisons */
    cflags |= REG_UTF8;
#endif

    if (collation == ASCIICASEMAP) {
        cflags |= REG_ICASE;
    }

    for (i = 0 ; !ret && i < strarray_size(sa) ; i++) {
        if ((ret = regcomp(&reg, strarray_nth(sa, i), cflags)) != 0) {
            size_t errbuf_size = regerror(ret, &reg, NULL, 0);

            buf_reset(&sscript->sieveerr);
            buf_ensure(&sscript->sieveerr, errbuf_size);
            (void) regerror(ret, &reg,
                            (char *) buf_base(&sscript->sieveerr),
                            errbuf_size);
            buf_truncate(&sscript->sieveerr, errbuf_size);
            yyerror(sscript, buf_cstring(&sscript->sieveerr));
        }

        regfree(&reg);
    }

    return (ret == 0);
}
#else

static int verify_regexlist(sieve_script_t *sscript __attribute__((unused)),
                            const strarray_t *sa __attribute__((unused)),
                            char *comp __attribute__((unused)))
{
    return 0;
}
#endif /* ENABLE_REGEX */

static int verify_patternlist(sieve_script_t *sscript,
                              strarray_t *sa, comp_t *c,
                              int (*verify)(sieve_script_t*, char *))
{
    if (verify && !verify_stringlist(sscript, sa, verify)) return 0;

    canon_comptags(c, sscript);

    return (c->match == REGEX) ?
        verify_regexlist(sscript, sa, c->collation) : 1;
}

static int verify_address(sieve_script_t *sscript, char *s)
{
    if (contains_variable(sscript, s)) return 1;

    YY_BUFFER_STATE buffer = addr_scan_string(s);
    int r = 1;

    sscript->addrerr[0] = '\0';    /* paranoia */
    if (addrparse(sscript)) {
        sieveerror_f(sscript, "address '%s': %s", s, sscript->addrerr);
        r = 0;
    }
    addr_delete_buffer(buffer);

    return r;
}

static int verify_mailbox(sieve_script_t *sscript, char *s)
{
    if (!verify_utf8(sscript, s)) {
        sieveerror_f(sscript, "mailbox '%s': not a valid mailbox", s);
        return 0;
    }

    return 1;
}

static int verify_header(sieve_script_t *sscript, char *hdr)
{
    char *h = hdr;

    while (*h) {
        /* field-name      =       1*ftext
           ftext           =       %d33-57 / %d59-126
           ; Any character except
           ;  controls, SP, and
           ;  ":". */
        if (!((*h >= 33 && *h <= 57) || (*h >= 59 && *h <= 126))) {
            sieveerror_f(sscript, "header '%s': not a valid header", hdr);
            return 0;
        }
        h++;
    }
    return 1;
}

static int verify_addrheader(sieve_script_t *sscript, char *hdr)
{
    const char **h, *hdrs[] = {
        "from", "sender", "reply-to",   /* RFC5322 originator fields */
        "to", "cc", "bcc",              /* RFC5322 destination fields */
        "message-id", "in-reply-to",    /* RFC5322 identification fields */
        "references"
        "resent-from", "resent-sender", /* RFC5322 resent fields */
        "resent-to", "resent-cc", "resent-bcc",
        "return-path",                  /* RFC5322 trace fields */
        "disposition-notification-to",  /* RFC8098 MDN request fields */
        "approved",                     /* RFC5536 moderator/control fields */
        "delivered-to",                 /* non-standard (loop detection) */
        NULL
    };

    if (contains_variable(sscript, hdr)) return 1;

    if (!config_getswitch(IMAPOPT_RFC3028_STRICT))
        return verify_header(sscript, hdr);

    for (lcase(hdr), h = hdrs; *h; h++) {
        if (!strcmp(*h, hdr)) return 1;
    }

    sieveerror_f(sscript,
                 "header '%s': not a valid header for an address test", hdr);
    return 0;
}

static int verify_envelope(sieve_script_t *sscript, char *env)
{
    if (contains_variable(sscript, env)) return 1;

    lcase(env);
    if (!config_getswitch(IMAPOPT_RFC3028_STRICT) ||
        !strcmp(env, "from") || !strcmp(env, "to") || !strcmp(env, "auth")) {
        return 1;
    }

    sieveerror_f(sscript,
                 "env-part '%s': not a valid part for an envelope test", env);
    return 0;
}

static int verify_list(sieve_script_t *sscript, char *s)
{
    if (sscript->interp.isvalidlist &&
        sscript->interp.isvalidlist(sscript->interp.interp_context, s)
        != SIEVE_OK) {
        sieveerror_f(sscript, "list '%s': is not valid/supported", s);
        return 0;
    }

    return 1;
}

static int check_reqs(sieve_script_t *sscript, strarray_t *sa)
{
    char *s;
    struct buf *errs = &sscript->sieveerr;
    int ret = 1, sep = ':';

    buf_setcstr(errs, "Unsupported feature(s) in \"require\"");
    while ((s = strarray_shift(sa))) {
        if (!script_require(sscript, s)) {
            buf_printf(errs, "%c \"%s\"", sep, s);
            ret = 0;
            sep = ',';
        }
        free(s);
    }
    strarray_free(sa);

    if (ret == 0) yyerror(sscript, buf_cstring(&sscript->sieveerr));
    else if (supported(SIEVE_CAPA_IHAVE)) {
        /* mark all allowed extensions as supported */
        sscript->support |= (SIEVE_CAPA_ALL & ~SIEVE_CAPA_IHAVE_INCOMPAT);
    }

    encoded_char = supported(SIEVE_CAPA_ENCODED_CHAR);

    return ret;
}

static commandlist_t *build_keep(sieve_script_t *sscript, commandlist_t *c)
{
    assert(c && c->type == KEEP);

    if (c->u.k.flags && !_verify_flaglist(c->u.k.flags)) {
        strarray_add(c->u.k.flags, "");
    }

    return c;
}

static commandlist_t *build_fileinto(sieve_script_t *sscript,
                                     commandlist_t *c, char *folder)
{
    assert(c && c->type == FILEINTO);

    if (c->u.f.flags && !_verify_flaglist(c->u.f.flags)) {
        strarray_add(c->u.f.flags, "");
    }
    if (verify_mailbox(sscript, folder) &&
        config_getswitch(IMAPOPT_SIEVE_UTF8FILEINTO)) {
        c->u.f.folder = xmalloc(5 * strlen(folder) + 1);
        UTF8_to_mUTF7(c->u.f.folder, folder);
        free(folder);
    }
    else c->u.f.folder = folder;

    return c;
}

static commandlist_t *build_redirect(sieve_script_t *sscript,
                                     commandlist_t *c, char *address)
{
    assert(c && c->type == REDIRECT);

    if (c->u.r.list) verify_list(sscript, address);
    else verify_address(sscript, address);

    /* Verify DELIVERBY values */
    if (c->u.r.bytime) {
        if (!supported(SIEVE_CAPA_VARIABLES)) {
            time_t t;

            if (c->u.r.bytime[0] != '+' &&
                time_from_iso8601(c->u.r.bytime, &t) == -1) {
                sieveerror_f(sscript,
                             "string '%s': not a valid DELIVERBY time value",
                             c->u.r.bytime);
            }
            if (c->u.r.bymode &&
                strcasecmp(c->u.r.bymode, "NOTIFY") &&
                strcasecmp(c->u.r.bymode, "RETURN")) {
                sieveerror_f(sscript,
                             "string '%s': not a valid DELIVERBY mode value",
                             c->u.r.bymode);
            }
        }
    }
    else if (c->u.r.bymode || c->u.r.bytrace) {
        sieveerror_c(sscript, SIEVE_MISSING_TAG,
                     ":bytimerelative OR :bytimeabsolute");
    }

    /* Verify DSN NOTIFY value(s) */
    if (c->u.r.dsn_notify && !supported(SIEVE_CAPA_VARIABLES)) {
        tok_t tok =
            TOK_INITIALIZER(c->u.r.dsn_notify, ",", TOK_TRIMLEFT|TOK_TRIMRIGHT);
        char *token;
        int never = 0;

        while ((token = tok_next(&tok))) {
            if (!strcasecmp(token, "NEVER")) never = 1;
            else if (never) {
                sieveerror_f(sscript,
                             "DSN NOTIFY value 'NEVER' MUST be used by itself",
                             token);
                break;
            }
            else if (strcasecmp(token, "SUCCESS") &&
                     strcasecmp(token, "FAILURE") &&
                     strcasecmp(token, "DELAY")) {
                sieveerror_f(sscript,
                             "string '%s': not a valid DSN NOTIFY value",
                             token);
                break;
            }
        }
        tok_fini(&tok);
    }

    /* Verify DSN RET value */
    if (c->u.r.dsn_ret && !supported(SIEVE_CAPA_VARIABLES) &&
        strcasecmp(c->u.r.dsn_ret, "FULL") &&
        strcasecmp(c->u.r.dsn_ret, "HDRS")) {
        sieveerror_f(sscript, "string '%s': not a valid DSN RET value",
                     c->u.r.dsn_ret);
    }

    c->u.r.address = address;

    return c;
}

static int verify_identifier(sieve_script_t *sscript, char *s)
{
    /* identifier         = (ALPHA / "_") *(ALPHA / DIGIT / "_") */

    if (!is_identifier(s)) {
        sieveerror_f(sscript,
                     "string '%s': not a valid sieve identifier", s);
        return 0;
    }
    return 1;
}

static commandlist_t *build_set(sieve_script_t *sscript,
                                commandlist_t *c, char *variable, char *value)
{
    assert(c && c->type == SET);

    verify_identifier(sscript, variable);
    verify_utf8(sscript, value);

    c->u.s.variable = variable;
    c->u.s.value = value;

    return c;
}

static commandlist_t *build_vacation(sieve_script_t *sscript,
                                     commandlist_t *c, char *message)
{
    int min = sscript->interp.vacation->min_response;
    int max = sscript->interp.vacation->max_response;

    assert(c && c->type == VACATION);

    if (c->u.v.handle) verify_utf8(sscript, c->u.v.handle);
    if (c->u.v.subject) verify_utf8(sscript, c->u.v.subject);
    if (c->u.v.from) verify_address(sscript, c->u.v.from);
    if (c->u.v.addresses)
        verify_stringlist(sscript, c->u.v.addresses, verify_address);
    if (c->u.v.mime == -1) {
        verify_utf8(sscript, message);
        c->u.v.mime = 0;
    }
    if (c->u.v.fcc.folder) {
        verify_mailbox(sscript, c->u.v.fcc.folder);
        if (c->u.v.fcc.flags && !_verify_flaglist(c->u.v.fcc.flags)) {
            strarray_add(c->u.v.fcc.flags, "");
        }
    }
    else if (c->u.v.fcc.create || c->u.v.fcc.flags || c->u.v.fcc.specialuse) {
        sieveerror_c(sscript, SIEVE_MISSING_TAG, ":fcc");
    }

    c->u.v.message = message;

    if (c->u.v.seconds == -1) c->u.v.seconds = 7 * DAY2SEC;
    if (c->u.v.seconds < min) c->u.v.seconds = min;
    if (c->u.v.seconds > max) c->u.v.seconds = max;

    return c;
}

static commandlist_t *build_flag(sieve_script_t *sscript,
                                 commandlist_t *c, strarray_t *flags)
{
    assert(c &&
           (c->type == SETFLAG || c->type == ADDFLAG || c->type == REMOVEFLAG));

    if (!_verify_flaglist(flags)) {
        strarray_add(flags, "");
    }
    c->u.fl.flags = flags;

    if (!c->u.fl.variable) c->u.fl.variable = xstrdup("");
    else if (!is_identifier(c->u.fl.variable)) {
        sieveerror_c(sscript, SIEVE_INVALID_VALUE, "variablename");
    }

    return c;
}

static commandlist_t *build_addheader(sieve_script_t *sscript,
                                      commandlist_t *c, char *name, char *value)
{
    assert(c && c->type == ADDHEADER);

    verify_header(sscript, name);
    verify_utf8(sscript, value);

    if (c->u.ah.index == 0) c->u.ah.index = 1;
    c->u.ah.name = name;
    c->u.ah.value = value;

    return c;
}

static commandlist_t *build_deleteheader(sieve_script_t *sscript,
                                         commandlist_t *c,
                                         char *name, strarray_t *values)
{
    assert(c && c->type == DELETEHEADER);

    if (!strcasecmp("Received", name) || !strcasecmp("Auto-Submitted", name)) {
        sieveerror_f(sscript,
                     "MUST NOT delete Received or Auto-Submitted headers");
    }

    verify_header(sscript, name);
    verify_patternlist(sscript, values, &c->u.dh.comp, verify_utf8);

    c->u.dh.name = name;
    c->u.dh.values = values;

    return c;
}

static commandlist_t *build_rej_err(sieve_script_t *sscript,
                                    int t, char *message)
{
    commandlist_t *c;

    assert(t == REJCT || t == EREJECT || t == ERROR);

    verify_utf8(sscript, message);

    c = new_command(t, sscript);
    c->u.str = message;

    return c;
}

static commandlist_t *build_notify(sieve_script_t *sscript, int t,
                                   commandlist_t *c, char *method)
{
    assert(c && (t == NOTIFY || t == ENOTIFY));

    if (t == ENOTIFY) {
        if (!supported(SIEVE_CAPA_ENOTIFY)) {
            sieveerror_c(sscript, SIEVE_MISSING_REQUIRE, "enotify");
        }
        if (c->u.n.id != NULL) {
            sieveerror_c(sscript, SIEVE_UNEXPECTED_TAG, ":id");
        }
        if (c->u.n.method != NULL) {
            sieveerror_c(sscript, SIEVE_UNEXPECTED_TAG, ":method");
        }
        if (c->u.n.fcc.folder) {
            verify_mailbox(sscript, c->u.n.fcc.folder);
            if (c->u.n.fcc.flags && !_verify_flaglist(c->u.n.fcc.flags)) {
                strarray_add(c->u.n.fcc.flags, "");
            }
        }
        else if (c->u.n.fcc.create || c->u.n.fcc.flags || c->u.n.fcc.specialuse) {
            sieveerror_c(sscript, SIEVE_MISSING_TAG, ":fcc");
        }

        c->u.n.method = method;
    }
    else {
        if (!supported(SIEVE_CAPA_NOTIFY)) {
            sieveerror_c(sscript, SIEVE_MISSING_REQUIRE, "notify");
        }
        if (c->u.n.from != NULL) {
            sieveerror_c(sscript, SIEVE_UNEXPECTED_TAG, ":from");
        }
        if (c->u.n.fcc.folder != NULL) {
            sieveerror_c(sscript, SIEVE_UNEXPECTED_TAG, ":fcc");
        }
        if (c->u.n.fcc.create != 0) {
            sieveerror_c(sscript, SIEVE_UNEXPECTED_TAG, ":create");
        }
        if (c->u.n.fcc.flags != NULL) {
            sieveerror_c(sscript, SIEVE_UNEXPECTED_TAG, ":flags");
        }
        if (c->u.n.fcc.specialuse != NULL) {
            sieveerror_c(sscript, SIEVE_UNEXPECTED_TAG, ":specialuse");
        }

        if (!c->u.n.method) c->u.n.method = xstrdup("default");
    }

    c->type = t;
    if (c->u.n.priority == -1) c->u.n.priority = NORMAL;
    if (!c->u.n.message) c->u.n.message = xstrdup("$from$: $subject$");

    return c;
}

static commandlist_t *build_denotify(sieve_script_t *sscript,
                                     commandlist_t *t)
{
    assert(t && t->type == DENOTIFY);

    canon_comptags(&t->u.d.comp, sscript);
    if (t->u.d.priority == -1) t->u.d.priority = ANY;
    if (t->u.d.pattern) {
        strarray_t sa = STRARRAY_INITIALIZER;

        strarray_pushm(&sa, t->u.d.pattern);
        verify_patternlist(sscript, &sa, &t->u.d.comp, NULL);
        strarray_pop(&sa);
        strarray_fini(&sa);
    }

    return t;
}

static commandlist_t *build_include(sieve_script_t *sscript,
                                    commandlist_t *c, char *script)
{
    assert(c && c->type == INCLUDE);

    if (strchr(script, '/')) {
        sieveerror_c(sscript, SIEVE_INVALID_VALUE, "script-name");
    }

    c->u.inc.script = script;
    if (c->u.inc.once == -1) c->u.inc.once = 0;
    if (c->u.inc.location == -1) c->u.inc.location = PERSONAL;
    if (c->u.inc.optional == -1) c->u.inc.optional = 0;

    return c;
}

static commandlist_t *build_log(sieve_script_t *sscript, char *text)
{
    commandlist_t *c;

    if (!supported(SIEVE_CAPA_LOG)) {
          sieveerror_c(sscript, SIEVE_MISSING_REQUIRE, "x-cyrus-log");
    }

    verify_utf8(sscript, text);

    c = new_command(LOG, sscript);
    c->u.l.text = text;

    return c;
}

static test_t *build_anyof(sieve_script_t *sscript, testlist_t *tl)
{
    test_t *t;

    assert(tl);

    if (tl->next == NULL) {
        /* collapse single item list into a simple test */
        t = tl->t;
        free(tl);
    }
    else {
        test_t *fail = NULL, *maybe = NULL;

        /* create ANYOF test */
        t = new_test(ANYOF, sscript);
        t->u.tl = tl;

        /* find first test that did/didn't set ignore_err */
        for ( ; tl && !fail && !maybe; tl = tl->next) {
            if (tl->t->ignore_err) {
                if (!fail) fail = tl->t;
            }
            else if (!maybe) maybe = tl->t;
        }

        if (fail) {
            if (maybe) {
                /* test may succeed - backout ignore_err */
                sscript->ignore_err = --fail->ignore_err;
            }
            else {
                /* test will fail - revert ignore_err to first value */
                sscript->ignore_err = t->ignore_err = fail->ignore_err;
            }
        }
    }

    return t;
}

static test_t *build_allof(sieve_script_t *sscript, testlist_t *tl)
{
    test_t *t;

    assert(tl);

    if (tl->next == NULL) {
        /* collapse single item list into a simple test */
        t = tl->t;
        free(tl);
    }
    else {
        /* create ALLOF test */
        t = new_test(ALLOF, sscript);
        t->u.tl = tl;

        /* find first test that set ignore_err and revert to that value */
        for ( ; tl; tl = tl->next) {
            if (tl->t->ignore_err) {
                sscript->ignore_err = t->ignore_err = tl->t->ignore_err;
                break;
            }
        }
    }

    return t;
}

static test_t *build_not(sieve_script_t *sscript, test_t *t)
{
    test_t *n;

    assert(t);

    if (t->ignore_err) {
        /* test will succeed - backout ignore_err */
        sscript->ignore_err = --t->ignore_err;
    }

    n = new_test(NOT, sscript);
    n->u.t = t;

    return n;
}

static test_t *build_hhs(sieve_script_t *sscript, test_t *t,
                         strarray_t *sl, strarray_t *pl)
{
    assert(t);

    verify_patternlist(sscript, pl, &t->u.hhs.comp, verify_utf8);

    t->u.hhs.sl = sl;
    t->u.hhs.pl = pl;

    return t;
}

static test_t *build_header(sieve_script_t *sscript, test_t *t,
                            strarray_t *sl, strarray_t *pl)
{
    assert(t && t->type == HEADERT);

    verify_stringlist(sscript, sl, verify_header);

    return build_hhs(sscript, t, sl, pl);
}

static test_t *build_stringt(sieve_script_t *sscript, test_t *t,
                             strarray_t *sl, strarray_t *pl)
{
    assert(t && t->type == STRINGT);

    verify_stringlist(sscript, sl, verify_utf8);

    return build_hhs(sscript, t, sl, pl);
}

static test_t *build_hasflag(sieve_script_t *sscript, test_t *t,
                             strarray_t *sl, strarray_t *pl)
{
    assert(t && t->type == HASFLAG);

    if (sl) {
        if (!supported(SIEVE_CAPA_VARIABLES)) {
            sieveerror_c(sscript, SIEVE_MISSING_REQUIRE, "variables");
        }

        verify_stringlist(sscript, sl, verify_identifier);
    }

    return build_hhs(sscript, t, sl, pl);
}

static test_t *build_ae(sieve_script_t *sscript, test_t *t,
                        strarray_t *sl, strarray_t *pl)
{
    assert(t);

    verify_patternlist(sscript, pl, &t->u.ae.comp, NULL);

    if (t->u.ae.addrpart == -1) t->u.ae.addrpart = ALL;
    t->u.ae.sl = sl;
    t->u.ae.pl = pl;

    return t;
}

static test_t *build_address(sieve_script_t *sscript, test_t *t,
                             strarray_t *sl, strarray_t *pl)
{
    assert(t && t->type == ADDRESS);

    verify_stringlist(sscript, sl, verify_addrheader);

    return build_ae(sscript, t, sl, pl);
}

static test_t *build_envelope(sieve_script_t *sscript, test_t *t,
                              strarray_t *sl, strarray_t *pl)
{
    assert(t && t->type == ENVELOPE);

    verify_stringlist(sscript, sl, verify_envelope);

    return build_ae(sscript, t, sl, pl);
}

static test_t *build_body(sieve_script_t *sscript,
                          test_t *t, strarray_t *pl)
{
    assert(t && (t->type == BODY));

    verify_patternlist(sscript, pl, &t->u.b.comp, verify_utf8);

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

static test_t *build_date(sieve_script_t *sscript,
                          test_t *t, char *hn, int part, strarray_t *kl)
{
    assert(t && (t->type == DATE || t->type == CURRENTDATE));

    if (hn) verify_header(sscript, hn);
    verify_patternlist(sscript, kl, &t->u.dt.comp, NULL);

    if (t->u.dt.comp.index == 0) t->u.dt.comp.index = 1;
    if (t->u.dt.zonetag == -1) {
        struct tm tm;
        time_t now = time(NULL);

        localtime_r(&now, &tm);
        t->u.dt.zone = gmtoff_of(&tm, now) / 60;
        t->u.dt.zonetag = ZONE;
    }

    t->u.dt.date_part = part;
    t->u.dt.header_name = hn;
    t->u.dt.kl = kl;

    return t;
}

static test_t *build_ihave(sieve_script_t *sscript, strarray_t *sa)
{
    test_t *t;
    int i;

    t = new_test(IHAVE, sscript);
    t->u.sl = sa;

    /* check if we support all listed extensions */
    for (i = 0; i < strarray_size(sa); i++) {
        unsigned long long capa = lookup_capability(strarray_nth(sa, i));

        if (!capa) {
            /* need to start ignoring errors immediately in case this ihave
               is part of a testlist with an unknown test later in the list */
            if (!t->ignore_err) t->ignore_err = ++sscript->ignore_err;
        }
        else if (capa & SIEVE_CAPA_IHAVE_INCOMPAT) {
            /* incompatible extension used in ihave - parse error */
            sscript->ignore_err = 0;
            sieveerror_c(sscript, SIEVE_IHAVE_INCOMPAT, strarray_nth(sa, i));
            break;
        }
    }

    return t;
}

static test_t *build_mbox_meta(sieve_script_t *sscript,
                               test_t *t, char *extname,
                               char *keyname, strarray_t *keylist)
{
    assert(t && (t->type == MAILBOXEXISTS || t->type == MAILBOXIDEXISTS ||
                 t->type == METADATA || t->type == METADATAEXISTS ||
                 t->type == SERVERMETADATA || t->type == SERVERMETADATAEXISTS ||
                 t->type == ENVIRONMENT || t->type == SPECIALUSEEXISTS ||
                 t->type == NOTIFYMETHODCAPABILITY));

    canon_comptags(&t->u.mm.comp, sscript);
    t->u.mm.extname = extname;
    t->u.mm.keyname = keyname;
    t->u.mm.keylist = keylist;

    return t;
}

static test_t *build_duplicate(sieve_script_t *sscript, test_t *t)
{
    assert(t && t->type == DUPLICATE);

    switch (t->u.dup.idtype) {
    case HEADER:
        verify_header(sscript, t->u.dup.idval);
        break;

    case UNIQUEID:
        verify_utf8(sscript, t->u.dup.idval);
        break;

    default:
        t->u.dup.idtype = HEADER;
        t->u.dup.idval = xstrdup("Message-ID");
        break;
    }

    if (!t->u.dup.handle) t->u.dup.handle = xstrdup("");
    else verify_utf8(sscript, t->u.dup.handle);

    if (t->u.dup.seconds == -1) t->u.dup.seconds = 7 * 86400; /* 7 days */

    return t;
}

static test_t *build_jmapquery(sieve_script_t *sscript, const char *json)
{
    test_t *t = new_test(JMAPQUERY, sscript);
    json_error_t jerr;

    if (!supported(SIEVE_CAPA_JMAPQUERY)) {
        sieveerror_c(sscript, SIEVE_MISSING_REQUIRE, "x-cyrus-jmapquery");
    }

    t->u.jquery = json_loads(json, 0, &jerr);
    if (!t->u.jquery) {
        sieveerror_f(sscript, "string '%s': not valid json", json);
    }

    return t;
}
