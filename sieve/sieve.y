%{
/* sieve.y -- sieve parser
 * Larry Greenfield
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

#include "imapurl.h"
#include "lib/gmtoff.h"
#include "util.h"
#include "imparse.h"
#include "libconfig.h"
#include "times.h"

#define ERR_BUF_SIZE 1024

/*
 * Definitions
 */

extern int addrparse(sieve_script_t*);
typedef struct yy_buffer_state *YY_BUFFER_STATE;
extern YY_BUFFER_STATE addr_scan_string(const char*);
extern void addr_delete_buffer(YY_BUFFER_STATE);

extern int sievelineno;

struct vtags {
    int seconds;
    strarray_t *addresses;
    char *subject;
    char *from;
    char *handle;
    int mime;
};

struct comptags {
    int match;
    int relation;
    char *comparator;  /* only used where comparator can be defined */
    int index;         /* only used were index extension is defined */
};

struct aetags {
    struct comptags comptags;  /* MUST be first so we can typecast */
    int addrtag;
};

struct btags {
    struct comptags comptags;  /* MUST be first so we can typecast */
    int transform;
    int offset;
    strarray_t *content_types;
};

struct ntags {
    char *method;
    char *id;
    strarray_t *options;
    int priority;
    char *message;
};

struct dtags {
    struct comptags comptags;  /* MUST be first so we can typecast */
    void *pattern;
    int priority;
};

struct itags {
    int location;
    int once;
    int optional;
};

struct dttags {
    struct comptags comptags;  /* MUST be first so we can typecast */
    int zonetag;
    char *zone;
    int date_part;
};

struct ftags {
    int copy;
    int create;
    strarray_t *flags;
};

struct stags {
    int mod40; /* :lower or :upper */
    int mod30; /* :lowerfirst or :upperfirst */
    int mod20; /* :quotewildcard */
    int mod10; /* :length */
};

static char *check_reqs(sieve_script_t *script, strarray_t *sl);

static test_t *build_address(int t, struct aetags *ae,
                             strarray_t *sl, strarray_t *pl);
static test_t *build_header(int t, struct comptags *c,
                            strarray_t *sl, strarray_t *pl);
static test_t *build_body(int t, struct btags *b, strarray_t *pl);
static test_t *build_date(int t, struct dttags *dt, char *hn, strarray_t *kl);
static test_t *build_mailboxtest(int t, struct comptags *c, const char *extname,
                                 const char *keyname, strarray_t *keylist);

static commandlist_t *build_vacation(int t, struct vtags *h, char *s);
static commandlist_t *build_notify(int t, struct ntags *n);
static commandlist_t *build_denotify(int t, struct dtags *n);
static commandlist_t *build_keep(int t, struct ftags *f);
static commandlist_t *build_fileinto(int t, struct ftags *f, char *folder);
static commandlist_t *build_redirect(int t, int c, char *a);
static commandlist_t *build_include(int, struct itags *, char*);
static commandlist_t *build_set(int t, struct stags *s,
                                char *variable, char *value);
static commandlist_t *build_flag(int t, char *variable, strarray_t *flags);

static struct aetags *new_aetags(void);
static struct aetags *canon_aetags(struct aetags *ae);
static void free_aetags(struct aetags *ae);

static struct comptags *new_comptags(void);
static struct comptags *init_comptags(struct comptags *c);
static struct comptags *canon_comptags(struct comptags *c);
static void free_comptags(struct comptags *c, int destroy);

static struct btags *new_btags(void);
static struct btags *canon_btags(struct btags *b);
static void free_btags(struct btags *b);

static struct vtags *new_vtags(void);
static struct vtags *canon_vtags(sieve_script_t *script, struct vtags *v);
static void free_vtags(struct vtags *v);

static struct ntags *new_ntags(void);
static struct ntags *canon_ntags(struct ntags *n);
static void free_ntags(struct ntags *n);

static struct dtags *new_dtags(void);
static struct dtags *canon_dtags(struct dtags *d);
static void free_dtags(struct dtags *d);

static struct itags *new_itags(void);

static struct dttags *new_dttags(void);
static struct dttags *canon_dttags(struct dttags *dt);
static void free_dttags(struct dttags *b);

static struct ftags *new_ftags(void);
static struct ftags *canon_ftags(struct ftags *f);
static void free_ftags(struct ftags *f);

static struct stags *new_stags(void);
static struct stags *canon_stags(struct stags *s);
static void free_stags(struct stags *s);

static int verify_stringlist(sieve_script_t*, strarray_t *sl,
                             int (*verify)(sieve_script_t*, char *));
static int verify_patternlist(sieve_script_t*,
                              strarray_t *sl, struct comptags *c);
static int verify_mailbox(sieve_script_t*, char *s);
static int verify_address(sieve_script_t*, char *s);
static int verify_header(sieve_script_t*, char *s);
static int verify_addrheader(sieve_script_t*, char *s);
static int verify_envelope(sieve_script_t*, char *s);
static int verify_relat(sieve_script_t*, char *s);
static int verify_zone(sieve_script_t*, char *s);
static int verify_date_part(sieve_script_t *parse_script, char *dp);
static int verify_utf8(sieve_script_t*, char *s);
static int verify_identifier(sieve_script_t*, char *s);

void yyerror(sieve_script_t*, const char *msg);
extern int yylex(void*, sieve_script_t*);
extern void sieverestart(FILE *f);

#define YYERROR_VERBOSE /* i want better error messages! */

/* byacc default is 500, bison default is 10000 - go with the
   larger to support big sieve scripts (see Bug #3461) */
#define YYSTACKSIZE 10000
%}

%union {
    int nval;
    char *sval;
    strarray_t *sl;
    test_t *test;
    testlist_t *testl;
    commandlist_t *cl;
    struct vtags *vtag;
    struct aetags *aetag;
    struct comptags *ctag;
    struct btags *btag;
    struct ntags *ntag;
    struct dtags *dtag;
    struct itags *itag;
    struct dttags *dttag;
    struct ftags *ftag;
    struct stags *stag;
}

%token <nval> NUMBER
%token <sval> STRING
%token IF ELSIF ELSE
%token REJCT FILEINTO REDIRECT KEEP STOP DISCARD VACATION REQUIRE
%token MARK UNMARK FLAGS
%token NOTIFY DENOTIFY
%token ANYOF ALLOF EXISTS SFALSE STRUE HEADER NOT SIZE ADDRESS ENVELOPE BODY
%token COMPARATOR IS CONTAINS MATCHES REGEX COUNT VALUE OVER UNDER
%token GT GE LT LE EQ NE
%token ALL LOCALPART DOMAIN USER DETAIL
%token RAW TEXT CONTENT
%token DAYS ADDRESSES SUBJECT FROM HANDLE MIME SECONDS
%token METHOD ID OPTIONS LOW NORMAL HIGH ANY MESSAGE
%token INCLUDE PERSONAL GLOBAL RETURN OPTIONAL ONCE
%token COPY
%token DATE CURRENTDATE INDEX LAST ZONE ORIGINALZONE
%token MAILBOXEXISTS CREATE
%token METADATA METADATAEXISTS
%token SERVERMETADATA SERVERMETADATAEXISTS
%token YEAR MONTH DAY JULIAN HOUR MINUTE SECOND TIME ISO8601 STD11 WEEKDAY
%token <nval> STRINGT SET LOWER UPPER LOWERFIRST UPPERFIRST QUOTEWILDCARD LENGTH
%token <nval> SETFLAG ADDFLAG REMOVEFLAG HASFLAG

%type <cl> commands command action elsif block
%type <sl> utf8list stringlist strings
%type <test> test
%type <nval> match relmatch sizetag addrparttag copy rtags creat
%type <testl> testlist tests
%type <ctag> htags strtags hftags mtags
%type <aetag> atags etags
%type <btag> btags
%type <vtag> vtags
%type <ntag> ntags
%type <dtag> dtags
%type <itag> itags
%type <dttag> dttags cdtags
%type <nval> priority
%type <ftag> ftags
%type <stag> stags
%type <nval> mod40 mod30 mod20 mod10
%type <sval> flagtags
%type <nval> flagaction

%name-prefix "sieve"
%defines
%destructor { free_tree($$); } commands command action elsif block

%parse-param { sieve_script_t *parse_script }
%lex-param { sieve_script_t *parse_script }
%pure-parser


/*
 * Rules
 */

%%

start: reqs                     { parse_script->cmds = NULL; }
        | reqs commands         { parse_script->cmds = $2; }
        ;

reqs: /* empty */
        | require reqs
        ;

require: REQUIRE stringlist ';'
                                {
                                    char *err = check_reqs(parse_script, $2);
                                    if (err) {
                                        yyerror(parse_script, err);
                                        free(err);
                                        YYERROR;
                                    }
                                }
        ;

commands: command               { $$ = $1; }
        | command commands      { $1->next = $2; $$ = $1; }
        ;

command: action ';'             { $$ = $1; }
        | IF test block elsif   { $$ = new_if($2, $3, $4); }
        | error ';'             { $$ = new_command(STOP); }
        ;

elsif: /* empty */               { $$ = NULL; }
        | ELSIF test block elsif { $$ = new_if($2, $3, $4); }
        | ELSE block             { $$ = $2; }
        ;

action: REJCT STRING
                                 {
                                     if (!parse_script->support.reject) {
                                         yyerror(parse_script,
                                                 "reject MUST be enabled with \"require\"");
                                         YYERROR; 
                                     }
                                     if (!verify_utf8(parse_script, $2)) {
                                         YYERROR; /* vu should call yyerror() */
                                     }
                                     $$ = new_command(REJCT);
                                     $$->u.reject = $2;
                                 }

        | FILEINTO ftags STRING
                                 {
                                     if (!parse_script->support.fileinto) {
                                         yyerror(parse_script,
                                                 "fileinto MUST be enabled with \"require\"");
                                         YYERROR;
                                     }
                                     if (!verify_mailbox(parse_script, $3)) {
                                         YYERROR; /* vm should call yyerror() */
                                     }
                                     $$ = build_fileinto(FILEINTO,
                                                         canon_ftags($2), $3);
                                 }

        | REDIRECT rtags STRING
                                 {
                                     if (!verify_address(parse_script, $3)) {
                                         YYERROR; /* va should call yyerror() */
                                     }
                                     $$ = build_redirect(REDIRECT, $2, $3);
                                 }

        | KEEP ftags             { $$ = build_keep(KEEP,canon_ftags($2)); }
        | STOP                   { $$ = new_command(STOP); }
        | DISCARD                { $$ = new_command(DISCARD); }

        | VACATION vtags STRING
                                 {
                                     if (!parse_script->support.vacation) {
                                         yyerror(parse_script,
                                                 "vacation MUST be enabled with \"require\"");
                                         YYERROR;
                                     }
                                     if (($2->mime == -1) &&
                                         !verify_utf8(parse_script, $3)) {
                                         YYERROR; /* vu should call yyerror() */
                                     }
                                     $$ = build_vacation(VACATION,
                                                         canon_vtags(parse_script, $2),
                                                         $3);
                                 }

        | flagaction flagtags stringlist
                                 {
                                     if (!(parse_script->support.imapflags ||
                                           parse_script->support.imap4flags)) {
                                         yyerror(parse_script,
                                                 "imap4flags MUST be enabled with \"require\"");
                                         YYERROR;
                                     }
                                     if (!parse_script->support.variables) {
                                         verify_flaglist($3);
                                     }
                                     if (!$3->count) strarray_add($3, "");
                                     $$ = build_flag($1, $2, $3);
                                 }

         | MARK
                                 {
                                     if (!parse_script->support.imapflags) {
                                         yyerror(parse_script,
                                                 "imapflags MUST be enabled with \"require\"");
                                         YYERROR;
                                     }
                                     $$ = new_command(MARK);
                                 }

         | UNMARK
                                 {
                                     if (!parse_script->support.imapflags) {
                                         yyerror(parse_script,
                                                 "imapflags MUST be enabled with \"require\"");
                                         YYERROR;
                                     }
                                     $$ = new_command(UNMARK);
                                 }

         | NOTIFY ntags
                                 {
                                     if (!parse_script->support.notify) {
                                         yyerror(parse_script,
                                                 "notify MUST be enabled with \"require\"");
                                         $$ = new_command(NOTIFY);
                                         YYERROR;
                                     }
                                     $$ = build_notify(NOTIFY, canon_ntags($2));
                                 }

         | DENOTIFY dtags
                                 {
                                     if (!parse_script->support.notify) {
                                         yyerror(parse_script,
                                                 "notify MUST be enabled with \"require\"");
                                         $$ = new_command(DENOTIFY);
                                         YYERROR;
                                     }
                                     $$ = build_denotify(DENOTIFY, canon_dtags($2));
                                     if ($$ == NULL) {
                                         yyerror(parse_script,
                                                 "unable to build denotify action");
                                         YYERROR;
                                     }
                                 }

         | INCLUDE itags STRING
                                 {
                                     if (!parse_script->support.include) {
                                         yyerror(parse_script,
                                                 "include MUST be enabled with \"require\"");
                                         YYERROR;
                                     }
                                     int i;
                                     for (i = 0; $3[i] != '\0'; i++) {
                                         if ($3[i] == '/') {
                                             yyerror(parse_script,
                                                     "included script name must not contain slash");
                                             YYERROR;
                                             break;
                                         }
                                     }
                                     $$ = build_include(INCLUDE, $2, $3);
                                 }

         | RETURN
                                 {
                                     if (!parse_script->support.include) {
                                         yyerror(parse_script,
                                                 "include MUST be enabled with \"require\"");
                                         YYERROR;
                                     }
                                     $$ = new_command(RETURN);
                                 }

         | SET stags STRING STRING
                                 {
                                     if (!parse_script->support.variables) {
                                         yyerror(parse_script,
                                                 "variables MUST be enabled with \"require\"");
                                         YYERROR;
                                     }
                                     if (!verify_identifier(parse_script, $3)) {
                                         YYERROR; /* vi should call yyerror() */
                                     }
                                     if (!verify_utf8(parse_script, $4)) {
                                         YYERROR; /* vu should call yyerror() */
                                     }
                                     $$ = build_set(SET, canon_stags($2), $3, $4);
                                 }
        ;

flagaction: ADDFLAG
        | SETFLAG
        | REMOVEFLAG
        ;

flagtags: /* empty */            { $$ = NULL; }
        | flagtags STRING
                                 {
                                     if (!(parse_script->support.imap4flags)) {
                                         yyerror(parse_script,
                                                 "imap4flags MUST be enabled with \"require\"");
                                         YYERROR;
                                     }
                                     if ($1) {
                                         yyerror(parse_script,
                                                 "duplicate variablename");
                                         YYERROR;
                                     }
                                     if (!is_identifier($2)) {
                                         yyerror(parse_script,
                                                 "variablename must be a valid identifier");
                                         YYERROR;
                                     }
                                     $$ = $2;
                                 }
        ;

stags: /* empty */               { $$ = new_stags(); }
        | stags mod40
                                 {
                                     if ($$->mod40) {
                                         yyerror(parse_script,
                                                 "duplicate mod40 (:lower or :upper)");
                                         YYERROR;
                                     }
                                     else $$->mod40 = $2;
                                 }
        | stags mod30
                                 {
                                     if ($$->mod30) {
                                         yyerror(parse_script,
                                                 "duplicate mod30 (:lowerfirst or :upperfirst)");
                                         YYERROR;
                                     }
                                     else $$->mod30 = $2;
                                 }
        | stags mod20
                                 {
                                     if ($$->mod20) {
                                         yyerror(parse_script,
                                                 "duplicate :quotewildcard");
                                         YYERROR;
                                     }
                                     else $$->mod20 = $2;
                                 }
/* TODO: :encodeurl
   Requires "enotify" extension, which has not been implemented yet.

   RFC 5435 (Sieve Extension: Notifications)
   6.  Modifier encodeurl to the 'set' Action

   Usage:  ":encodeurl"

   When the Sieve script specifies both "variables" [Variables] and
   "enotify" capabilities in the "require", a new "set" action modifier
   (see [Variables]) ":encodeurl" becomes available to Sieve scripts.
   This modifier performs percent-encoding of any octet in the string
   that doesn't belong to the "unreserved" set (see [URI]).  The
   percent-encoding procedure is described in [URI].

   The ":encodeurl" modifier has precedence 15.

   Example 6:
   require ["enotify", "variables"];

   set :encodeurl "body_param" "Safe body&evil=evilbody";

   notify "mailto:tim@example.com?body=${body_param}";

*/
        | stags mod10
                                 {
                                     if ($$->mod10) {
                                         yyerror(parse_script,
                                                 "duplicate :length");
                                         YYERROR;
                                     }
                                     else $$->mod10 = $2;
                                 }
;

mod40:  LOWER
        | UPPER
        ;
mod30:  LOWERFIRST
        | UPPERFIRST
        ;
mod20:  QUOTEWILDCARD
        ;
mod10:  LENGTH
        ;

itags: /* empty */               { $$ = new_itags(); }
        | itags PERSONAL
                                 {
                                     if ($$->location != -1) {
                                         yyerror(parse_script,
                                                 "duplicate location (:personal or :global)");
                                         YYERROR;
                                     }
                                     else $$->location = PERSONAL;
                                 }
        | itags GLOBAL
                                 {
                                     if ($$->location != -1) {
                                         yyerror(parse_script,
                                                 "duplicate location (:personal or :global)");
                                         YYERROR;
                                     }
                                     else $$->location = GLOBAL;
                                 }
        | itags ONCE
                                 {
                                     if ($$->once != -1) {
                                         yyerror(parse_script, "duplicate :once");
                                         YYERROR;
                                     }
                                     else $$->once = 1;
                                 }
        | itags OPTIONAL
                                 { if ($$->optional != -1) {
                                         yyerror(parse_script,
                                                 "duplicate :optional");
                                         YYERROR;
                                     }
                                     else $$->optional = 1;
                                 }
        ;

ntags: /* empty */               { $$ = new_ntags(); }
        | ntags ID STRING
                                 {
                                     if ($$->id != NULL) {
                                         yyerror(parse_script,
                                                 "duplicate :method");
                                         YYERROR;
                                     }
                                     else $$->id = $3;
                                 }
        | ntags METHOD STRING
                                 {
                                     if ($$->method != NULL) {
                                         yyerror(parse_script,
                                                 "duplicate :method");
                                         YYERROR;
                                     }
                                     else $$->method = $3;
                                 }
        | ntags OPTIONS stringlist
                                 {
                                     if ($$->options != NULL) {
                                         yyerror(parse_script,
                                                 "duplicate :options");
                                         YYERROR;
                                     }
                                     else $$->options = $3;
                                 }
        | ntags priority
                                 {
                                     if ($$->priority != -1) {
                                         yyerror(parse_script,
                                                 "duplicate :priority");
                                         YYERROR;
                                     }
                                     else $$->priority = $2;
                                 }
        | ntags MESSAGE STRING
                                 {
                                     if ($$->message != NULL) {
                                         yyerror(parse_script,
                                                 "duplicate :message");
                                         YYERROR;
                                     }
                                     else $$->message = $3;
                                 }
        ;

dtags: /* empty */               { $$ = new_dtags(); }
        | dtags priority
                                 {
                                     if ($$->priority != -1) {
                                         yyerror(parse_script,
                                                 "duplicate priority level");
                                         YYERROR;
                                     }
                                     else $$->priority = $2;
                                 }
        | dtags match STRING
                                 {
                                     if ($$->comptags.match != -1) {
                                         yyerror(parse_script,
                                                 "duplicate match type tag");
                                         YYERROR;
                                     }
                                     $$->comptags.match = $2;
                                     $$->pattern = $3;

                                     strarray_t sa = STRARRAY_INITIALIZER;
                                     strarray_appendm(&sa, $3);
                                     if (!verify_patternlist(parse_script, &sa,
                                                             &($$->comptags))) {
                                         YYERROR; /* vp should call yyerror() */
                                     }
                                     strarray_fini(&sa);
                                 }
        | dtags relmatch STRING
                                 {
                                     $$ = $1;
                                     if ($$->comptags.match != -1) {
                                         yyerror(parse_script,
                                                 "duplicate comparator type tag");
                                         YYERROR;
                                     }
                                     else {
                                         $$->comptags.match = $2;
                                         $$->comptags.relation =
                                             verify_relat(parse_script, $3);
                                         if ($$->comptags.relation == -1) {
                                             YYERROR; /*vr called yyerror()*/
                                         }
                                     }
                                 }
        ;

priority: LOW                   { $$ = LOW; }
        | NORMAL                { $$ = NORMAL; }
        | HIGH                  { $$ = HIGH; }
        ;

vtags: /* empty */               { $$ = new_vtags(); }
        | vtags DAYS NUMBER
                                 {
                                     if ($$->seconds != -1) {
                                         yyerror(parse_script,
                                                 "duplicate :days or :seconds");
                                         YYERROR;
                                     }
                                     else $$->seconds = $3 * DAY2SEC;
                                 }
        | vtags SECONDS NUMBER
                                 {
                                     if (!parse_script->support.vacation_seconds) {
                                         yyerror(parse_script,
                                                 "vacation-seconds not required");
                                         YYERROR;
                                     }
                                     if ($$->seconds != -1) {
                                         yyerror(parse_script,
                                                 "duplicate :days or :seconds");
                                         YYERROR;
                                     }
                                     $$->seconds = $3;
                                 }
        | vtags ADDRESSES stringlist
                                 {
                                     if ($$->addresses != NULL) {
                                         yyerror(parse_script,
                                                 "duplicate :addresses");
                                         YYERROR;
                                     }
                                     if (!verify_stringlist(parse_script, $3,
                                                            verify_address)) {
                                         YYERROR;
                                     }
                                     $$->addresses = $3;
                                 }
        | vtags SUBJECT STRING
                                 {
                                     if ($$->subject != NULL) {
                                         yyerror(parse_script,
                                                 "duplicate :subject");
                                         YYERROR;
                                     }
                                     if (!verify_utf8(parse_script, $3)) {
                                         YYERROR; /* vu should call yyerror() */
                                     }
                                     $$->subject = $3;
                                 }
        | vtags FROM STRING
                                 {
                                     if ($$->from != NULL) {
                                         yyerror(parse_script,
                                                 "duplicate :from");
                                         YYERROR;
                                     }
                                     if (!verify_address(parse_script, $3)) {
                                         YYERROR; /* va should call yyerror() */
                                     }
                                     $$->from = $3;
                                 }
        | vtags HANDLE STRING
                                 {
                                     if ($$->handle != NULL) {
                                         yyerror(parse_script,
                                                 "duplicate :handle");
                                         YYERROR;
                                     }
                                     if (!verify_utf8(parse_script, $3)) {
                                         YYERROR; /* vu should call yyerror() */
                                     }
                                     $$->handle = $3;
                                 }
        | vtags MIME
                                 {
                                     if ($$->mime != -1) {
                                         yyerror(parse_script,
                                                 "duplicate :mime");
                                         YYERROR;
                                     }
                                     $$->mime = MIME;
                                 }
        ;

utf8list: stringlist
                                 {
                                     if (!verify_stringlist(parse_script,
                                                            $1, verify_utf8)) {
                                         YYERROR; /* vu should call yyerror() */
                                     }
                                 }
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

block: '{' commands '}'          { $$ = $2; }
        | '{' '}'                { $$ = NULL; }
        ;

test:     ANYOF testlist         { $$ = new_test(ANYOF); $$->u.tl = $2; }
        | ALLOF testlist         { $$ = new_test(ALLOF); $$->u.tl = $2; }
        | EXISTS stringlist      { $$ = new_test(EXISTS); $$->u.sl = $2; }
        | SFALSE                 { $$ = new_test(SFALSE); }
        | STRUE                  { $$ = new_test(STRUE); }

        | HEADER htags stringlist utf8list
                                 {
                                     if (!verify_stringlist(parse_script,
                                                            $3, verify_header)) {
                                         YYERROR; /* vh should call yyerror() */
                                     }
                                     $2 = canon_comptags($2);

                                     if (!verify_patternlist(parse_script,
                                                             $4, $2)) {
                                         YYERROR; /* vp should call yyerror() */
                                     }

                                     $$ = build_header(HEADER, $2, $3, $4);
                                     if ($$ == NULL) {
                                         yyerror(parse_script,
                                                 "unable to build header test");
                                         YYERROR;
                                     }
                                 }

        | STRINGT strtags utf8list utf8list
                                 {
                                     if (!parse_script->support.variables) {
                                         yyerror(parse_script,
                                                 "variables MUST be enabled with \"require\"");
                                         YYERROR;
                                     }
                                     $2 = canon_comptags($2);

                                     if (!verify_patternlist(parse_script,
                                                             $4, $2)) {
                                         YYERROR; /* vp should call yyerror() */
                                     }

                                     $$ = build_header(STRINGT, $2, $3, $4);
                                     if ($$ == NULL) {
                                         yyerror(parse_script,
                                                 "unable to build string test");
                                         YYERROR;
                                     }
                                 }

/* Per RFC 5232, the variables list (penultimate argument) is optional,
   but defining the grammar this way results in a shift/reduce conflict.
   Therefore, we have to flatten the grammar into two rules.
*/
        | HASFLAG hftags stringlist utf8list
                                 {
                                     if (!parse_script->support.imap4flags) {
                                         yyerror(parse_script,
                                                 "imap4flags MUST be enabled with \"require\"");
                                         YYERROR;
                                     }
                                     if (!parse_script->support.variables) {
                                         yyerror(parse_script,
                                                 "variables MUST be enabled with \"require\"");
                                         YYERROR;
                                     }
                                     if (!verify_stringlist(parse_script, $3,
                                                            verify_identifier)) {
                                         YYERROR; /* vi should call yyerror() */
                                     }
                                     $2 = canon_comptags($2);

                                     if (!verify_patternlist(parse_script,
                                                             $4, $2)) {
                                         YYERROR; /* vp should call yyerror() */
                                     }

                                     $$ = build_header(HASFLAG, $2, $3, $4);
                                     if ($$ == NULL) {
                                         yyerror(parse_script,
                                                 "unable to build hasflag test");
                                         YYERROR;
                                     }
                                 }

        | HASFLAG hftags utf8list 
                                 {
                                     if (!parse_script->support.imap4flags) {
                                         yyerror(parse_script,
                                                 "imap4flags MUST be enabled with \"require\"");
                                         YYERROR;
                                     }
                                     $2 = canon_comptags($2);

                                     if (!verify_patternlist(parse_script,
                                                             $3, $2)) {
                                         YYERROR; /* vp should call yyerror() */
                                     }

                                     $$ = build_header(HASFLAG, $2, NULL, $3);
                                     if ($$ == NULL) {
                                         yyerror(parse_script,
                                                 "unable to build hasflag test");
                                         YYERROR;
                                     }
                                 }

        | ADDRESS atags stringlist stringlist
                                 {
                                     if (!verify_stringlist(parse_script, $3,
                                                            verify_addrheader)) {
                                         YYERROR; /* vah should call yyerror() */
                                     }
                                     $2 = canon_aetags($2);

                                     if (!verify_patternlist(parse_script, $4,
                                                             &($2->comptags))) {
                                         YYERROR; /* vp should call yyerror() */
                                     }

                                     $$ = build_address(ADDRESS, $2, $3, $4);
                                     if ($$ == NULL) {
                                         yyerror(parse_script,
                                                 "unable to build address test");
                                         YYERROR;
                                     }
                                 }

        | ENVELOPE etags stringlist stringlist
                                 {
                                     if (!parse_script->support.envelope) {
                                         yyerror(parse_script,
                                                 "envelope MUST be enabled with \"require\"");
                                         YYERROR;
                                     }
                                     if (!verify_stringlist(parse_script, $3,
                                                            verify_envelope)) {
                                         YYERROR;
                                     }
                                     $2 = canon_aetags($2);

                                     if (!verify_patternlist(parse_script, $4,
                                                             &($2->comptags))) {
                                         YYERROR; /* vp should call yyerror() */
                                     }

                                     $$ = build_address(ENVELOPE, $2, $3, $4);
                                     if ($$ == NULL) {
                                         yyerror(parse_script,
                                                 "unable to build envelope test");
                                         YYERROR;
                                     }
                                 }

        | BODY btags utf8list
                                 {
                                     if (!parse_script->support.body) {
                                         yyerror(parse_script,
                                                 "body MUST be enabled with \"require\"");
                                         YYERROR;
                                     }
                                     $2 = canon_btags($2);

                                     if (!verify_patternlist(parse_script, $3,
                                                             &($2->comptags))) {
                                         YYERROR; /* vp should call yyerror() */
                                     }

                                     $$ = build_body(BODY, $2, $3);
                                     if ($$ == NULL) {
                                         yyerror(parse_script,
                                                 "unable to build body test");
                                         YYERROR;
                                     }
                                 }

        | NOT test               { $$ = new_test(NOT); $$->u.t = $2; }
        | SIZE sizetag NUMBER    { $$ = new_test(SIZE); $$->u.sz.t = $2;
                                   $$->u.sz.n = $3; }

        | DATE dttags STRING STRING stringlist
                                 {
                                     if (!parse_script->support.date) {
                                         yyerror(parse_script,
                                                 "date MUST be enabled with \"require\"");
                                         YYERROR;
                                     }

                                     $2->date_part =
                                         verify_date_part(parse_script, $4);
                                     if ($2->date_part == -1) {
                                         YYERROR; /* vdp called yyerror() */
                                     }

                                     $$ = build_date(DATE,
                                                     canon_dttags($2), $3, $5);
                                     if ($$ == NULL) {
                                         yyerror(parse_script,
                                                 "unable to build date test");
                                         YYERROR;
                                     }
                                 }

        | CURRENTDATE cdtags STRING stringlist
                                 {
                                     if (!parse_script->support.date) {
                                         yyerror(parse_script,
                                                 "date MUST be enabled with \"require\"");
                                         YYERROR;
                                     }

                                     $2->date_part =
                                         verify_date_part(parse_script, $3);
                                     if ($2->date_part == -1) {
                                         YYERROR; /* vdp called yyerror() */
                                     }

                                     $$ = build_date(CURRENTDATE,
                                                     canon_dttags($2), NULL, $4);
                                     if ($$ == NULL) {
                                         yyerror(parse_script,
                                                 "unable to build currentdate test");
                                         YYERROR;
                                     }
                                 }

        | MAILBOXEXISTS stringlist
                                 {
                                     if (!parse_script->support.mailbox) {
                                         yyerror(parse_script,
                                                 "mailbox MUST be enabled with \"require\"");
                                         YYERROR;
                                     }

                                     $$ = build_mailboxtest(MAILBOXEXISTS, NULL,
                                                            NULL, NULL, $2);
                                     if ($$ == NULL) {
                                         yyerror(parse_script,
                                                 "unable to build mailbox test");
                                         YYERROR;
                                     }
                                 }

        | METADATA mtags STRING STRING stringlist
                                 {
                                     if (!parse_script->support.mboxmetadata) {
                                         yyerror(parse_script,
                                                 "mboxmetadata MUST be enabled with \"require\"");
                                         YYERROR;
                                     }

                                     $$ = build_mailboxtest(METADATA,
                                                            $2, $3, $4, $5);
                                     if ($$ == NULL) {
                                         yyerror(parse_script,
                                                 "unable to build metadata test");
                                         YYERROR;
                                     }
                                 }

        | METADATAEXISTS STRING stringlist
                                 {
                                     if (!parse_script->support.mboxmetadata) {
                                         yyerror(parse_script,
                                                 "mboxmetadata MUST be enabled with \"require\"");
                                         YYERROR;
                                     }

                                     $$ = build_mailboxtest(METADATAEXISTS,
                                                            NULL, $2, NULL, $3);
                                     if ($$ == NULL) {
                                         yyerror(parse_script,
                                                 "unable to build metadataexists test");
                                         YYERROR;
                                     }
                                 }

        | SERVERMETADATA mtags STRING stringlist
                                 {
                                     if (!parse_script->support.servermetadata) {
                                         yyerror(parse_script,
                                                 "servermetadata MUST be enabled with \"require\"");
                                         YYERROR;
                                     }

                                     $$ = build_mailboxtest(SERVERMETADATA,
                                                            $2, NULL, $3, $4);
                                     if ($$ == NULL) {
                                         yyerror(parse_script,
                                                 "unable to build servermetadata test");
                                         YYERROR;
                                     }
                                 }

        | SERVERMETADATAEXISTS stringlist
                                 {
                                     if (!parse_script->support.servermetadata) {
                                         yyerror(parse_script,
                                                 "servermetadata MUST be enabled with \"require\"");
                                         YYERROR;
                                     }

                                     $$ = build_mailboxtest(SERVERMETADATAEXISTS,
                                                            NULL, NULL, NULL, $2);
                                     if ($$ == NULL) {
                                         yyerror(parse_script,
                                                 "unable to build servermetadataexists test");
                                         YYERROR;
                                     }
                                 }

        | error                  { $$ = NULL; }
        ;

atags: /* empty */               { $$ = new_aetags(); }
        | atags addrparttag
                                 {
                                     $$ = $1;
                                     if ($$->addrtag != -1) {
                                         yyerror(parse_script,
                                                 "duplicate or conflicting address part tag");
                                         YYERROR;
                                     }
                                     else $$->addrtag = $2;
                                 }
        | atags comptags
        | atags idxtags
        ;

etags: /* empty */               { $$ = new_aetags(); }
        | etags addrparttag
                                 {
                                     $$ = $1;
                                     if ($$->addrtag != -1) {
                                         yyerror(parse_script,
                                                 "duplicate or conflicting address part tag");
                                         YYERROR;
                                     }
                                     else $$->addrtag = $2;
                                 }
        | etags comptags
        ;

/* $0 is the symbol which precedes comptags (e.g. aetags).
   We typecast this pointer into struct comptags *
*/
comptags: match
                                 {
                                     struct comptags *ctags = $<ctag>0;
                                     if (ctags->match != -1) {
                                         yyerror(parse_script,
                                                 "duplicate match-type tag");
                                         YYERROR;
                                     }
                                     else ctags->match = $1;
                                 }
        | relmatch STRING
                                 {
                                     struct comptags *ctags = $<ctag>0;
                                     if (ctags->match != -1) {
                                         yyerror(parse_script,
                                                 "duplicate match-type tag");
                                         YYERROR;
                                     }
                                     else {
                                         ctags->match = $1;
                                         ctags->relation =
                                             verify_relat(parse_script, $2);
                                         if (ctags->relation == -1) {
                                             YYERROR; /*vr called yyerror()*/
                                         }
                                     }
                                 }
        | COMPARATOR STRING
                                 {
                                     struct comptags *ctags = $<ctag>0;
                                     if (ctags->comparator != NULL) {
                                         yyerror(parse_script,
                                                 "duplicate comparator tag");
                                         YYERROR;
                                     }
                                     else if (!strcmp($2, "i;ascii-numeric") &&
                                              !parse_script->support.i_ascii_numeric) {
                                         yyerror(parse_script,
                                                 "comparator-i;ascii-numeric MUST be enabled with \"require\"");
                                         YYERROR;
                                     }
                                     else ctags->comparator = $2;
                                 }
        ;

/* $0 is the symbol which precedes idxtags (e.g. aetags).
   We typecast this pointer into struct comptags *
*/
idxtags: INDEX NUMBER
                                 {
                                     struct comptags *ctags = $<ctag>0;
                                     if (!parse_script->support.index) {
                                         yyerror(parse_script,
                                                 "index MUST be enabled with \"require\"");
                                         YYERROR;
                                     }
                                     if (ctags->index != 0) {
                                         yyerror(parse_script,
                                                 "duplicate index argument");
                                         YYERROR;
                                     }
                                     if ($2 <= 0) {
                                         yyerror(parse_script,
                                                 "invalid index value");
                                         YYERROR;
                                     }
                                     else ctags->index = $2;
                                 }
        | LAST
                                 { struct comptags *ctags = $<ctag>0;
                                     if (!parse_script->support.index) {
                                         yyerror(parse_script,
                                                 "index MUST be enabled with \"require\"");
                                         YYERROR;
                                     }
                                     if (ctags->index == 0) {
                                         yyerror(parse_script,
                                                 "index argument is required");
                                         YYERROR;
                                     }
                                     else if (ctags->index < 0) {
                                         yyerror(parse_script,
                                                 "duplicate last argument");
                                         YYERROR;
                                     }
                                     else ctags->index *= -1;
                                 }
        ;

htags: /* empty */               { $$ = new_comptags(); }
        | htags comptags
        | htags idxtags
        ;

strtags:/* empty */              { $$ = new_comptags(); }
        | strtags comptags
        ;

hftags:/* empty */               { $$ = new_comptags(); }
        | hftags comptags
        ;

mtags: /* empty */               { $$ = new_comptags(); }
        | mtags comptags
        ;

btags: /* empty */               { $$ = new_btags(); }
        | btags RAW
                                 {
                                     $$ = $1;
                                     if ($$->transform != -1) {
                                         yyerror(parse_script,
                                                 "duplicate or conflicting transform tag");
                                         YYERROR;
                                     }
                                     else $$->transform = RAW;
                                 }
        | btags TEXT
                                 {
                                     $$ = $1;
                                     if ($$->transform != -1) {
                                         yyerror(parse_script,
                                                 "duplicate or conflicting transform tag");
                                         YYERROR;
                                     }
                                     else $$->transform = TEXT;
                                 }
        | btags CONTENT stringlist
                                 {
                                     $$ = $1;
                                     if ($$->transform != -1) {
                                         yyerror(parse_script,
                                                 "duplicate or conflicting transform tag");
                                         YYERROR;
                                     }
                                     else {
                                         $$->transform = CONTENT;
                                         $$->content_types = $3;
                                     }
                                 }
        | btags comptags
        ;

dttags: /* empty */              { $$ = new_dttags(); }
        | dttags ORIGINALZONE
                                 {
                                     $$ = $1;
                                     if ($$->zonetag != -1) {
                                         yyerror(parse_script,
                                                 "duplicate zone tag"); YYERROR; }
                                     else $$->zonetag = ORIGINALZONE;
                                 }
        | dttags zone
        | dttags comptags
        | dttags idxtags
        ;

cdtags: /* empty */              { $$ = new_dttags(); }
        | cdtags zone
        | cdtags comptags
        ;

/* $0 is the symbol which precedes zone (e.g. dttags).
   We typecast this pointer into struct comptags *
*/
zone: ZONE STRING
                                 {
                                     struct dttags *dttags = $<dttag>0;
                                     if (dttags->zonetag != -1) {
                                         yyerror(parse_script,
                                                 "duplicate zone tag");
                                         YYERROR;
                                     }
                                     else if (verify_zone(parse_script, $2) == -1) {
                                         YYERROR; /*vr called yyerror()*/
                                     }
                                     else {
                                         dttags->zone = $2;
                                         dttags->zonetag = ZONE;
                                     }
                                 }
        ;

addrparttag: ALL                 { $$ = ALL; }
        | LOCALPART              { $$ = LOCALPART; }
        | DOMAIN                 { $$ = DOMAIN; }
        | USER
                                 {
                                     if (!parse_script->support.subaddress) {
                                         yyerror(parse_script,
                                                 "subaddress MUST be enabled with \"require\"");
                                         YYERROR;
                                     }
                                     $$ = USER;
                                 }
        | DETAIL
                                 {
                                     if (!parse_script->support.subaddress) {
                                         yyerror(parse_script,
                                                 "subaddress MUST be enabled with \"require\"");
                                         YYERROR;
                                     }
                                     $$ = DETAIL;
                                 }
        ;
match: IS                        { $$ = IS; }
        | CONTAINS               { $$ = CONTAINS; }
        | MATCHES                { $$ = MATCHES; }
        | REGEX
                                 {
                                     if (!parse_script->support.regex) {
                                         yyerror(parse_script,
                                                 "regex MUST be enabled with \"require\"");
                                         YYERROR;
                                     }
                                     $$ = REGEX;
                                 }
        ;

relmatch: COUNT
                                 {
                                     if (!parse_script->support.relational) {
                                         yyerror(parse_script,
                                                 "relational MUST be enabled with \"require\"");
                                         YYERROR;
                                     }
                                     $$ = COUNT;
                                 }
        | VALUE
                                 {
                                     if (!parse_script->support.relational) {
                                         yyerror(parse_script,
                                                 "relational MUST be enabled with \"require\"");
                                         YYERROR;
                                     }
                                     $$ = VALUE;
                                 }
        ;


sizetag: OVER                    { $$ = OVER; }
        | UNDER                  { $$ = UNDER; }
        ;

copy: COPY
                                 {
                                     if (!parse_script->support.copy) {
                                         yyerror(parse_script,
                                                 "copy MUST be enabled with \"require\"");
                                         YYERROR;
                                     }
                                     $$ = 1;
                                 }
        ;

creat:  CREATE
                                 {
                                     if (!parse_script->support.mailbox) {
                                         yyerror(parse_script,
                                                 "mailbox MUST be enabled with \"require\"");
                                         YYERROR;
                                     }
                                     $$ = 1;
                                 }
        ;

ftags: /* empty */               { $$ = new_ftags(); }
        | ftags copy
                                 {
                                     $$ = $1;
                                     if ($$->copy) {
                                         yyerror(parse_script,
                                                 "duplicate copy tag");
                                         YYERROR;
                                     }
                                     else $$->copy = $2;
                                 }
        | ftags creat
                                 {
                                     $$ = $1;
                                     if ($$->create) {
                                         yyerror(parse_script,
                                                 "duplicate create tag");
                                         YYERROR;
                                     }
                                     else $$->create = $2;
                                 }
        | ftags FLAGS stringlist
                                 {
                                     $$ = $1;
                                     if (!parse_script->support.imap4flags) {
                                         yyerror(parse_script,
                                                 "imap4flags MUST be enabled with \"require\"");
                                         YYERROR;
                                     }
                                     if ($$->flags != NULL) {
                                         yyerror(parse_script,
                                                 "duplicate flags tag");
                                         YYERROR;
                                     }
                                     else {
                                         if (!parse_script->support.variables) {
                                             verify_flaglist($3);
                                         }
                                         if (!$3->count) strarray_add($3, "");
                                         $$->flags = $3;
                                     }
                                 }
        ;

rtags: /* empty */               { $$ = 0; }
        | rtags copy
                                 {
                                     $$ = $1;
                                     if ($$) {
                                         yyerror(parse_script,
                                                 "duplicate copy tag");
                                         YYERROR;
                                     }
                                     else $$ = $2;
                                 }
        ;

testlist: '(' tests ')'          { $$ = $2; }
        ;

tests: test                      { $$ = new_testlist($1, NULL); }
        | test ',' tests         { $$ = new_testlist($1, $3); }
        ;

%%


/*
 * Actions
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

static char *check_reqs(sieve_script_t *parse_script, strarray_t *sa)
{
    char *s;
    struct buf errs = BUF_INITIALIZER;
    char *res;

    while ((s = strarray_shift(sa))) {
        if (!script_require(parse_script, s)) {
            if (!errs.len)
                buf_printf(&errs,
                           "Unsupported feature(s) in \"require\": \"%s\"", s);
            else buf_printf(&errs, ", \"%s\"", s);
        }
        free(s);
    }
    strarray_free(sa);

    res = buf_release(&errs);
    if (!res[0]) {
        free(res);
        return NULL;
    }

    return res;
}

static test_t *build_address(int t, struct aetags *ae,
                             strarray_t *sl, strarray_t *pl)
{
    test_t *ret = new_test(t);  /* can be either ADDRESS or ENVELOPE */

    assert((t == ADDRESS) || (t == ENVELOPE));

    if (ret) {
        ret->u.ae.comptag = ae->comptags.match;
        ret->u.ae.relation=ae->comptags.relation;
        ret->u.ae.comparator=xstrdup(ae->comptags.comparator);
        ret->u.ae.index = ae->comptags.index;
        ret->u.ae.sl = sl;
        ret->u.ae.pl = pl;
        ret->u.ae.addrpart = ae->addrtag;
        free_aetags(ae);

    }
    return ret;
}

static test_t *build_header(int t, struct comptags *c,
                            strarray_t *sl, strarray_t *pl)
{
    test_t *ret = new_test(t);  /* can be HEADER or HASFLAG or STRINGT */

    assert((t == HEADER) || (t == HASFLAG) || (t == STRINGT));

    if (ret) {
        ret->u.h.comptag = c->match;
        ret->u.h.relation = c->relation;
        ret->u.h.comparator = xstrdup(c->comparator);
        ret->u.h.index = c->index;
        ret->u.h.sl = sl;
        ret->u.h.pl = pl;
        free_comptags(c, 1);
    }
    return ret;
}

static test_t *build_body(int t, struct btags *b, strarray_t *pl)
{
    test_t *ret = new_test(t);  /* can be BODY */

    assert(t == BODY);

    if (ret) {
        ret->u.b.comptag = b->comptags.match;
        ret->u.b.relation = b->comptags.relation;
        ret->u.b.comparator = xstrdup(b->comptags.comparator);
        ret->u.b.transform = b->transform;
        ret->u.b.offset = b->offset;
        ret->u.b.content_types = b->content_types; b->content_types = NULL;
        ret->u.b.pl = pl;
        free_btags(b);
    }
    return ret;
}

static test_t *build_mailboxtest(int t, struct comptags *c,
                                 const char *extname, const char *keyname,
                                 strarray_t *keylist)
{
    test_t *ret = new_test(t);

    if (ret) {
        ret->u.mbx.extname = xstrdupnull(extname);
        ret->u.mbx.keyname = xstrdupnull(keyname);
        ret->u.mbx.keylist = keylist;
        if (c) {
            canon_comptags(c);
            ret->u.mbx.comptag = c->match;
            ret->u.mbx.relation = c->relation;
            ret->u.mbx.comparator = xstrdup(c->comparator);
            free_comptags(c, 1);
        }
    }

    return ret;
}

static commandlist_t *build_vacation(int t, struct vtags *v, char *reason)
{
    commandlist_t *ret = new_command(t);

    assert(t == VACATION);

    if (ret) {
        ret->u.v.subject = v->subject; v->subject = NULL;
        ret->u.v.from = v->from; v->from = NULL;
        ret->u.v.handle = v->handle; v->handle = NULL;
        ret->u.v.seconds = v->seconds;
        ret->u.v.mime = v->mime;
        ret->u.v.addresses = v->addresses; v->addresses = NULL;
        free_vtags(v);
        ret->u.v.message = reason;
    }
    return ret;
}

static commandlist_t *build_notify(int t, struct ntags *n)
{
    commandlist_t *ret = new_command(t);

    assert(t == NOTIFY);
       if (ret) {
        ret->u.n.method = n->method; n->method = NULL;
        ret->u.n.id = n->id; n->id = NULL;
        ret->u.n.options = n->options; n->options = NULL;
        ret->u.n.priority = n->priority;
        ret->u.n.message = n->message; n->message = NULL;
        free_ntags(n);
    }
    return ret;
}

static commandlist_t *build_denotify(int t, struct dtags *d)
{
    commandlist_t *ret = new_command(t);

    assert(t == DENOTIFY);

    if (ret) {
        ret->u.d.comptag = d->comptags.match;
        ret->u.d.relation = d->comptags.relation;
        ret->u.d.pattern = d->pattern; d->pattern = NULL;
        ret->u.d.priority = d->priority;
        free_dtags(d);
    }
    return ret;
}

static commandlist_t *build_keep(int t, struct ftags *f)
{
    commandlist_t *ret = new_command(t);

    assert(t == KEEP);

    if (ret) {
        ret->u.k.copy = f->copy;
        ret->u.k.flags = f->flags; f->flags = NULL;
        free_ftags(f);
    }
    return ret;
}

static commandlist_t *build_fileinto(int t, struct ftags *f, char *folder)
{
    commandlist_t *ret = new_command(t);

    assert(t == FILEINTO);

    if (ret) {
        ret->u.f.copy = f->copy;
        ret->u.f.create = f->create;
        ret->u.f.flags = f->flags; f->flags = NULL;
        if (config_getswitch(IMAPOPT_SIEVE_UTF8FILEINTO)) {
            ret->u.f.folder = xmalloc(5 * strlen(folder) + 1);
            UTF8_to_mUTF7(ret->u.f.folder, folder);
        }
        else {
            ret->u.f.folder = xstrdup(folder);
        }
        free_ftags(f);
    }
    return ret;
}

static commandlist_t *build_redirect(int t, int copy, char *address)
{
    commandlist_t *ret = new_command(t);

    assert(t == REDIRECT);

    if (ret) {
        ret->u.r.copy = copy;
        ret->u.r.address = address;
    }
    return ret;
}

static commandlist_t *build_include(int t, struct itags *i, char* script)
{
    commandlist_t *ret = new_command(t);

    assert(t == INCLUDE);

    if (i->location == -1) i->location = PERSONAL;
    if (i->once == -1) i->once = 0;
    if (i->optional == -1) i->optional = 0;

    if (ret) {
        ret->u.inc.location = i->location;
        ret->u.inc.once = i->once;
        ret->u.inc.optional = i->optional;
        ret->u.inc.script = script;
        free(i);
    }
    return ret;
}

static test_t *build_date(int t, struct dttags *dt,
                          char *hn, strarray_t *kl)
{
    test_t *ret = new_test(t);
    assert(t == DATE || t == CURRENTDATE);

    if (ret) {
        ret->u.dt.comptag = dt->comptags.match;
        ret->u.dt.relation = dt->comptags.relation;
        ret->u.dt.comparator = xstrdup(dt->comptags.comparator);
        ret->u.dt.index = dt->comptags.index;
        ret->u.dt.zone = (dt->zone ? xstrdup(dt->zone) : NULL);
        ret->u.dt.zonetag = dt->zonetag;
        ret->u.dt.date_part = dt->date_part;
        ret->u.dt.header_name = (hn ? xstrdup(hn) : NULL);
        ret->u.dt.kl = kl;
        free_dttags(dt);
    }
    return ret;
}

static commandlist_t *build_set(int t, struct stags *s,
                                char *variable, char *value)
{
    commandlist_t *ret = new_command(t);

    assert(t == SET);

    if (ret) {
        ret->u.s.mod40 = s->mod40;
        ret->u.s.mod30 = s->mod30;
        ret->u.s.mod20 = s->mod20;
        ret->u.s.mod10 = s->mod10;
        ret->u.s.variable = xstrdup(variable);
        ret->u.s.value = xstrdup(value);

        free_stags(s);
    }

    return ret;
}

static commandlist_t *build_flag(int t, char *variable, strarray_t *flags)
{
    commandlist_t *ret = new_command(t);

    assert(t == SETFLAG || t == ADDFLAG || t == REMOVEFLAG);

    if (ret) {
        ret->u.fl.variable = xstrdup(variable ? variable : "");
        ret->u.fl.flags = flags;
    }

    return ret;
}

static struct aetags *new_aetags(void)
{
    struct aetags *r = (struct aetags *) xmalloc(sizeof(struct aetags));

    init_comptags(&r->comptags);
    r->addrtag = -1;

    return r;
}

static struct aetags *canon_aetags(struct aetags *ae)
{
    canon_comptags(&ae->comptags);
    if (ae->addrtag == -1) { ae->addrtag = ALL; }
    return ae;
}

static void free_aetags(struct aetags *ae)
{
    free_comptags(&ae->comptags, 0);
    free(ae);
}

static struct comptags *new_comptags(void)
{
    struct comptags *c = (struct comptags *) xmalloc(sizeof(struct comptags));

    return init_comptags(c);
}

static struct comptags *init_comptags(struct comptags *c)
{
    c->match = c->relation = -1;
    c->comparator = NULL;
    c->index = 0;

    return c;
}

static struct comptags *canon_comptags(struct comptags *c)
{
    if (c->match == -1) c->match = IS;
    if (c->comparator == NULL) c->comparator = xstrdup("i;ascii-casemap");
    return c;
}

static void free_comptags(struct comptags *c, int destroy)
{
    free(c->comparator);
    if (destroy) free(c);
}

static struct btags *new_btags(void)
{
    struct btags *r = (struct btags *) xmalloc(sizeof(struct btags));

    init_comptags(&r->comptags);
    r->transform = r->offset = -1;
    r->content_types = NULL;

    return r;
}

static struct btags *canon_btags(struct btags *b)
{
    canon_comptags(&b->comptags);
    if (b->transform == -1) b->transform = TEXT;
    if (b->content_types == NULL) {
        b->content_types = strarray_new();
        if (b->transform == RAW) strarray_append(b->content_types, "");
        else strarray_append(b->content_types, "text");
    }
    if (b->offset == -1) b->offset = 0;
    return b;
}

static void free_btags(struct btags *b)
{
    free_comptags(&b->comptags, 0);
    if (b->content_types) strarray_free(b->content_types);
    free(b);
}

static struct vtags *new_vtags(void)
{
    struct vtags *r = (struct vtags *) xmalloc(sizeof(struct vtags));

    r->seconds = -1;
    r->addresses = NULL;
    r->subject = NULL;
    r->from = NULL;
    r->handle = NULL;
    r->mime = -1;

    return r;
}

static struct vtags *canon_vtags(sieve_script_t *parse_script, struct vtags *v)
{
    assert(parse_script->interp.vacation != NULL);

    if (v->seconds == -1) v->seconds = 7 * DAY2SEC;
    if (v->seconds < parse_script->interp.vacation->min_response)
        v->seconds = parse_script->interp.vacation->min_response;
    if (v->seconds > parse_script->interp.vacation->max_response)
        v->seconds = parse_script->interp.vacation->max_response;
    if (v->mime == -1) v->mime = 0;

    return v;
}

static void free_vtags(struct vtags *v)
{
    strarray_free(v->addresses);
    free(v->subject);
    free(v->from);
    free(v->handle);
    free(v);
}

static struct itags *new_itags()
{
    struct itags *r = (struct itags *) xmalloc(sizeof(struct itags));

    r->once = -1;
    r->location = -1;
    r->optional = -1;

    return r;
}

static struct dttags *new_dttags(void)
{
    struct dttags *dt = (struct dttags *) xmalloc(sizeof(struct dttags));

    init_comptags(&dt->comptags);
    dt->zonetag = -1;
    dt->zone = NULL;
    dt->date_part = -1;
    return dt;
}

static struct dttags *canon_dttags(struct dttags *dt)
{
    char zone[6];
    int gmoffset;
    int hours;
    int minutes;
    struct tm tm;
    time_t t;

    canon_comptags(&dt->comptags);
    if (dt->comptags.index == 0) dt->comptags.index = 1;
    if (dt->zonetag == -1) {
        t = time(NULL);
        localtime_r(&t, &tm);
        gmoffset = gmtoff_of(&tm, t) / 60;
        hours = abs(gmoffset) / 60;
        minutes = abs(gmoffset) % 60;
        snprintf(zone, 6, "%c%02d%02d",
                 (gmoffset >= 0 ? '+' : '-'), hours, minutes);
        dt->zone = xstrdup(zone);
        dt->zonetag = ZONE;
    }
    return dt;
}

static void free_dttags(struct dttags *dt)
{
    free_comptags(&dt->comptags, 0);
    free(dt->zone);
    free(dt);
}


static struct ntags *new_ntags(void)
{
    struct ntags *r = (struct ntags *) xmalloc(sizeof(struct ntags));

    r->method = NULL;
    r->id = NULL;
    r->options = NULL;
    r->priority = -1;
    r->message = NULL;

    return r;
}

static struct ntags *canon_ntags(struct ntags *n)
{
    if (n->priority == -1) n->priority = NORMAL;
    if (n->message == NULL) n->message = xstrdup("$from$: $subject$");
    if (n->method == NULL) n->method = xstrdup("default");
    return n;
}
static struct dtags *canon_dtags(struct dtags *d)
{
    canon_comptags(&d->comptags);
    if (d->priority == -1) d->priority = ANY;
    return d;
}

static void free_ntags(struct ntags *n)
{
    free(n->method);
    free(n->id);
    strarray_free(n->options);
    free(n->message);
    free(n);
}

static struct dtags *new_dtags(void)
{
    struct dtags *r = (struct dtags *) xzmalloc(sizeof(struct dtags));

    init_comptags(&r->comptags);
    r->comptags.comparator = xstrdup("i;ascii-casemap");
    r->priority = -1;

    return r;
}

static void free_dtags(struct dtags *d)
{
    if (!d) return;
    free_comptags(&d->comptags, 0);
    free(d->pattern);
    free(d);
}

static struct ftags *new_ftags(void)
{
    struct ftags *f = (struct ftags *) xzmalloc(sizeof(struct ftags));
    return f;
}

static struct ftags *canon_ftags(struct ftags *f)
{
    return f;
}

static struct stags *new_stags(void)
{
    struct stags *s = (struct stags *) xmalloc(sizeof(struct stags));

    s->mod40 = 0;
    s->mod30 = 0;
    s->mod20 = 0;
    s->mod10 = 0;

    return s;
}

static struct stags *canon_stags(struct stags *s)
{
    return s;
}

static void free_stags(struct stags *s)
{
    free(s);
}

static void free_ftags(struct ftags *f)
{
    if (!f) return;
    strarray_free(f->flags);
    free(f);
}

static int verify_identifier(sieve_script_t *parse_script, char *s)
{
    /* identifier         = (ALPHA / "_") *(ALPHA / DIGIT / "_") */

    if (!is_identifier(s)) {
        snprintf(parse_script->sieveerr, ERR_BUF_SIZE,
                 "string '%s': not a valid sieve identifier", s);
        yyerror(parse_script, parse_script->sieveerr);
        return 0;
    }
    return 1;
}

static int verify_stringlist(sieve_script_t *parse_script, strarray_t *sa,
                             int (*verify)(sieve_script_t*, char *))
{
    int i;

    for (i = 0 ; i < sa->count ; i++) {
        if (!verify(parse_script, sa->data[i])) return 0;
    }
    return 1;
}

static int verify_address(sieve_script_t *parse_script, char *s)
{
    parse_script->addrerr[0] = '\0';    /* paranoia */
    YY_BUFFER_STATE buffer = addr_scan_string(s);
    if (addrparse(parse_script)) {
        snprintf(parse_script->sieveerr, ERR_BUF_SIZE,
                 "address '%s': %s", s, parse_script->addrerr);
        yyerror(parse_script, parse_script->sieveerr);
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
            snprintf(parse_script->sieveerr, ERR_BUF_SIZE,
                     "header '%s': not a valid header", hdr);
            yyerror(parse_script, parse_script->sieveerr);
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

    snprintf(parse_script->sieveerr, ERR_BUF_SIZE,
             "header '%s': not a valid header for an address test", hdr);
    yyerror(parse_script, parse_script->sieveerr);
    return 0;
}

static int verify_envelope(sieve_script_t *parse_script, char *env)
{
    lcase(env);
    if (!config_getswitch(IMAPOPT_RFC3028_STRICT) ||
        !strcmp(env, "from") || !strcmp(env, "to") || !strcmp(env, "auth")) {
        return 1;
    }

    snprintf(parse_script->sieveerr, ERR_BUF_SIZE,
             "env-part '%s': not a valid part for an envelope test", env);
    yyerror(parse_script, parse_script->sieveerr);
    return 0;
}

static int verify_relat(sieve_script_t *parse_script, char *r)
{
    /* this really should have been a token to begin with.*/
    lcase(r);
    if (!strcmp(r, "gt")) return GT;
    else if (!strcmp(r, "ge")) return GE;
    else if (!strcmp(r, "lt")) return LT;
    else if (!strcmp(r, "le")) return LE;
    else if (!strcmp(r, "ne")) return NE;
    else if (!strcmp(r, "eq")) return EQ;
    else {
        snprintf(parse_script->sieveerr, ERR_BUF_SIZE,
                 "flag '%s': not a valid relational operation", r);
        yyerror(parse_script, parse_script->sieveerr);
        return -1;
    }
}

static int verify_zone(sieve_script_t *parse_script, char *tz)
{
    int valid = 0;
    unsigned hours;
    unsigned minutes;
    char sign;

    if (sscanf(tz, "%c%02u%02u", &sign, &hours, &minutes) != 3) {
        valid |= -1;
    }

    // test sign
    switch (sign) {
    case '+':
    case '-':
        break;

    default:
        valid |= -1;
        break;
    }

    // test minutes
    if (minutes > 59) {
            valid |= -1;
    }

    if (valid != 0) {
        snprintf(parse_script->sieveerr, ERR_BUF_SIZE,
                 "flag '%s': not a valid timezone offset", tz);
        yyerror(parse_script, parse_script->sieveerr);
    }

    return valid;
}

static int verify_date_part(sieve_script_t *parse_script, char *dp)
{
    lcase(dp);
    if (!strcmp(dp, "year")) return YEAR;
    else if (!strcmp(dp, "month")) return MONTH;
    else if (!strcmp(dp, "day")) return DAY;
    else if (!strcmp(dp, "date")) return DATE;
    else if (!strcmp(dp, "julian")) return JULIAN;
    else if (!strcmp(dp, "hour")) return HOUR;
    else if (!strcmp(dp, "minute")) return MINUTE;
    else if (!strcmp(dp, "second")) return SECOND;
    else if (!strcmp(dp, "time")) return TIME;
    else if (!strcmp(dp, "iso8601")) return ISO8601;
    else if (!strcmp(dp, "std11")) return STD11;
    else if (!strcmp(dp, "zone")) return ZONE;
    else if (!strcmp(dp, "weekday")) return WEEKDAY;
    else {
        snprintf(parse_script->sieveerr, ERR_BUF_SIZE,
                 "'%s': not a valid date-part", dp);
        yyerror(parse_script, parse_script->sieveerr);
    }

    return -1;
}

#ifdef ENABLE_REGEX
static int verify_regex(sieve_script_t *parse_script, char *s, int cflags)
{
    int ret;
    regex_t *reg = (regex_t *) xmalloc(sizeof(regex_t));

    if ((ret = regcomp(reg, s, cflags)) != 0) {
        (void) regerror(ret, reg, parse_script->sieveerr, ERR_BUF_SIZE);
        yyerror(parse_script, parse_script->sieveerr);
        free(reg);
        return 0;
    }
    free(reg);
    return 1;
}

static int verify_regexs(sieve_script_t *parse_script,
                         const strarray_t *sa, char *comp)
{
    int i;
    int cflags = REG_EXTENDED | REG_NOSUB;

#ifdef HAVE_PCREPOSIX_H
    /* support UTF8 comparisons */
    cflags |= REG_UTF8;
#endif

    if (!strcmp(comp, "i;ascii-casemap")) {
        cflags |= REG_ICASE;
    }

    for (i = 0 ; i < sa->count ; i++) {
        if ((verify_regex(parse_script, sa->data[i], cflags)) == 0)
            return 0;
    }
    return 1;
}
#else

static int verify_regexs(sieve_script_t *parse_script __attribute__((unused)),
                         const strarray_t *sa __attribute__((unused)),
                         char *comp __attribute__((unused)))
{
    return 0;
}
#endif /* ENABLE_REGEX */

static int verify_patternlist(sieve_script_t *parse_script, strarray_t *sl,
                              struct comptags *c)
{
    return (c->match == REGEX) ?
        verify_regexs(parse_script, sl, c->comparator) : 1;
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
        snprintf(parse_script->sieveerr, ERR_BUF_SIZE,
                 "string '%s': not valid utf8", s);
        yyerror(parse_script, parse_script->sieveerr);
        return 0;
    }

    return 1;
}
