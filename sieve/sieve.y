%{
/* sieve.y -- sieve parser
 * Larry Greenfield
 * $Id: sieve.y,v 1.1.1.1 1999/07/02 18:55:35 leg Exp $
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

#include <assert.h>
#include <string.h>
#include "comparator.h"
#include "interp.h"
#include "script.h"
#include "tree.h"

struct vtags {
    int days;
    stringlist_t *addresses;
    char *subject;
    int mime;
};

struct htags {
    char *comparator;
    int comptag;
};

struct aetags {
    int addrtag;
    char *comparator;
    int comptag;
};

static commandlist_t *ret;
static sieve_script_t *parse_script;
static int check_reqs(stringlist_t *sl);
static test_t *build_address(int t, struct aetags *ae,
			     stringlist_t *s1, stringlist_t *s2);
static test_t *build_header(int t, struct htags *h,
			    stringlist_t *s1, stringlist_t *s2);
static commandlist_t *build_vacation(int t, struct vtags *h, char *s);
static struct aetags *new_aetags(void);
static struct aetags *canon_aetags(struct aetags *ae);
static void free_aetags(struct aetags *ae);
static struct htags *new_htags(void);
static struct htags *canon_htags(struct htags *h);
static void free_htags(struct htags *h);
static struct vtags *new_vtags(void);
static struct vtags *canon_vtags(struct vtags *v);
static void free_vtags(struct vtags *v);

#define YYERROR_VERBOSE /* i want better error messages! */
%}

%union {
    int nval;
    char *sval;
    stringlist_t *sl;
    test_t *test;
    testlist_t *testl;
    commandlist_t *cl;
    struct vtags *vtag;
    struct aetags *aetag;
    struct htags *htag;
}

%token <nval> NUMBER
%token <sval> STRING
%token IF ELSIF ELSE
%token REJCT FILEINTO FORWARD KEEP STOP DISCARD VACATION REQUIRE
%token ANYOF ALLOF EXISTS FALSE TRUE HEADER NOT SIZE ADDRESS ENVELOPE
%token COMPARATOR IS CONTAINS MATCHES OVER UNDER ALL LOCALPART DOMAIN
%token DAYS ADDRESSES SUBJECT MIME

%type <cl> commands command action elsif block
%type <sl> stringlist strings
%type <test> test
%type <nval> comptag sizetag addrparttag addrorenv
%type <testl> testlist tests
%type <htag> htags
%type <aetag> aetags
%type <vtag> vtags

%%

start: /* empty */		{ ret = NULL; }
	| reqs commands		{ ret = $2; }
	;

reqs: /* empty */
	| require reqs
	;

require: REQUIRE stringlist ';'	{ if (!check_reqs($2)) {
                                    yyerror("unsupported feature");
				    YYERROR; 
                                  } }
	;

commands: command		{ $$ = $1; }
	| command commands	{ $1->next = $2; $$ = $1; }
	;

command: action ';'		{ $$ = $1; }
	| IF test block elsif   { $$ = new_if($2, $3, $4); }
	;

elsif: /* empty */               { $$ = NULL; }
	| ELSIF test block elsif { $$ = new_if($2, $3, $4); }
	| ELSE block             { $$ = $2; }
	;

action: REJCT STRING             { if (!parse_script->support.reject) {
				     yyerror("reject not required");
				     YYERROR;
				   }
				   $$ = new_command(REJCT); $$->u.str = $2; }
	| FILEINTO stringlist	 { if (!parse_script->support.fileinto) {
				     yyerror("fileinto not required");
	                             YYERROR;
                                   }
	                           $$ = new_command(FILEINTO);
				   $$->u.sl = $2; }
	| FORWARD stringlist     { $$ = new_command(FORWARD);
				   $$->u.sl = $2; }
	| KEEP			 { $$ = new_command(KEEP); }
	| STOP			 { $$ = new_command(STOP); }
	| DISCARD		 { $$ = new_command(DISCARD); }
	| VACATION vtags STRING  { if (!parse_script->support.vacation) {
				     yyerror("vacation not required");
				     $$ = new_command(VACATION);
				     YYERROR;
				   } else {
  				     $$ = build_vacation(VACATION,
					    canon_vtags($2), $3);
				     if ($$ == NULL) { YYERROR; } } }
	;

vtags: /* empty */		 { $$ = new_vtags(); }
	| vtags DAYS NUMBER	 { if ($$->days != -1) { YYERROR; }
				   else { $$->days = $3; } }
	| vtags ADDRESSES stringlist { if ($$->addresses != NULL) { YYERROR; }
				       else { $$->addresses = $3; } }
	| vtags SUBJECT STRING	 { if ($$->subject != NULL) { YYERROR; }
				   else { $$->subject = $3; } }
	| vtags MIME		 { if ($$->mime != -1) { YYERROR; }
				   else { $$->mime = MIME; } }
	;

stringlist: '[' strings ']'      { $$ = $2; }
	| STRING		 { $$ = new_sl($1, NULL); }
	;

strings: STRING			 { $$ = new_sl($1, NULL); }
	| STRING ',' strings	 { $$ = new_sl($1, $3); }
	;

block: '{' commands '}'		 { $$ = $2; }
	| '{' '}'		 { $$ = NULL; }
	;

test: ANYOF testlist		 { $$ = new_test(ANYOF); $$->u.tl = $2; }
	| ALLOF testlist	 { $$ = new_test(ALLOF); $$->u.tl = $2; }
	| EXISTS stringlist      { $$ = new_test(EXISTS); $$->u.sl = $2; }
	| FALSE			 { $$ = new_test(FALSE); }
	| TRUE			 { $$ = new_test(TRUE); }
	| HEADER htags stringlist stringlist
				 { $$ = build_header(HEADER, canon_htags($2), 
						     $3, $4);
				   if ($$ == NULL) { YYERROR; } }
	| addrorenv aetags stringlist stringlist
				 { $$ = build_address($1, canon_aetags($2), 
						      $3, $4); 
				   if ($$ == NULL) { YYERROR; } }
	| NOT test		 { $$ = new_test(NOT); $$->u.t = $2; }
	| SIZE sizetag NUMBER    { $$ = new_test(SIZE); $$->u.sz.t = $2;
		                   $$->u.sz.n = $3; }
	;

addrorenv: ADDRESS		 { $$ = ADDRESS; }
	| ENVELOPE		 { $$ = ENVELOPE; }
	;

aetags: /* empty */              { $$ = new_aetags(); }
        | aetags addrparttag	 { $$ = $1;
				   if ($$->addrtag != -1) { YYERROR; }
				   else { $$->addrtag = $2; } }
	| aetags comptag         { $$ = $1;
				   if ($$->comptag != -1) { YYERROR; }
				   else { $$->comptag = $2; } }
	| aetags COMPARATOR STRING { $$ = $1;
				   if ($$->comparator != NULL) { YYERROR; }
				   else { $$->comparator = $3; } }
	;

htags: /* empty */		 { $$ = new_htags(); }
	| htags comptag		 { $$ = $1;
				   if ($$->comptag != -1) { YYERROR; }
				   else { $$->comptag = $2; } }
	| htags COMPARATOR STRING { $$ = $1;
				   if ($$->comparator != NULL) { YYERROR; }
				   else { $$->comparator = $3; } }
	;

addrparttag: ALL                 { $$ = ALL; }
	| LOCALPART		 { $$ = LOCALPART; }
	| DOMAIN                 { $$ = DOMAIN; }
	;

comptag: IS			 { $$ = IS; }
	| CONTAINS		 { $$ = CONTAINS; }
	| MATCHES		 { $$ = MATCHES; }
	;

sizetag: OVER			 { $$ = OVER; }
	| UNDER			 { $$ = UNDER; }

testlist: '(' tests ')'		 { $$ = $2; }
	;

tests: test                      { $$ = new_testlist($1, NULL); }
	| test ',' tests         { $$ = new_testlist($1, $3); }
	;

%%
commandlist_t *sieve_parse(sieve_script_t *script, FILE *f)
{
    commandlist_t *t;
    extern FILE *yyin;

    yyin = f;
    parse_script = script;
    if (yyparse()) {
	t = NULL;
    } else {
	t = ret;
    }
    ret = NULL;
    return t;
}

int yyerror(char *msg)
{
#if 0
    extern int yylineno;
    extern char *yytext;
    fprintf(stderr, "%d: %s at '%s'\n", yylineno, msg, yytext);
#endif
    return 0;
}

static int check_reqs(stringlist_t *sl)
{
    int i = 1;
    stringlist_t *s;
    
    while (sl != NULL) {
	s = sl;
	sl = sl->next;

	i &= script_require(parse_script, s->s);

	if (s->s) free(s->s);
	free(s);
    }
    return i;
}

static test_t *build_address(int t, struct aetags *ae,
			     stringlist_t *s1, stringlist_t *s2)
{
    test_t *ret = new_test(t);	/* can be either ADDRESS or ENVELOPE */

    assert((t == ADDRESS) || (t == ENVELOPE));

    if (ret) {
	ret->u.ae.comp = lookup_comp(ae->comparator, ae->comptag);
	ret->u.ae.s1 = s1;
	ret->u.ae.s2 = s2;
	ret->u.ae.addrpart = ae->addrtag;
	free_aetags(ae);
	if (ret->u.ae.comp == NULL) {
	    free_test(ret);
	    ret = NULL;
	}
    }
    return ret;
}

static test_t *build_header(int t, struct htags *h,
			    stringlist_t *s1, stringlist_t *s2)
{
    test_t *ret = new_test(t);	/* can be HEADER */

    assert(t == HEADER);

    if (ret) {
	ret->u.h.comp = lookup_comp(h->comparator, h->comptag);
	ret->u.h.s1 = s1;
	ret->u.h.s2 = s2;
	free_htags(h);
	if (ret->u.ae.comp == NULL) {
	    free_test(ret);
	    ret = NULL;
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
	ret->u.v.days = v->days;
	ret->u.v.mime = v->mime;
	ret->u.v.addresses = v->addresses; v->addresses = NULL;
	free_vtags(v);
	ret->u.v.message = reason;
    }
    return ret;
}

static struct aetags *new_aetags(void)
{
    struct aetags *r = (struct aetags *) malloc(sizeof(struct aetags));

    r->addrtag = r->comptag = -1;
    r->comparator = NULL;

    return r;
}

static struct aetags *canon_aetags(struct aetags *ae)
{
    if (ae->addrtag == -1) { ae->addrtag = ALL; }
    if (ae->comparator == NULL) { ae->comparator = strdup("i;ascii-casemap"); }
    if (ae->comptag == -1) { ae->comptag = IS; }
    return ae;
}

static void free_aetags(struct aetags *ae)
{
    free(ae->comparator);
    free(ae);
}

static struct htags *new_htags(void)
{
    struct htags *r = (struct htags *) malloc(sizeof(struct htags));

    r->comptag = -1;
    r->comparator = NULL;

    return r;
}

static struct htags *canon_htags(struct htags *h)
{
    if (h->comparator == NULL) { h->comparator = strdup("i;ascii-casemap"); }
    if (h->comptag == -1) { h->comptag = IS; }
    return h;
}

static void free_htags(struct htags *h)
{
    free(h->comparator);
    free(h);
}

static struct vtags *new_vtags(void)
{
    struct vtags *r = (struct vtags *) malloc(sizeof(struct vtags));

    r->days = -1;
    r->addresses = NULL;
    r->subject = NULL;
    r->mime = -1;

    return r;
}

static struct vtags *canon_vtags(struct vtags *v)
{
    assert(parse_script->interp.vacation != NULL);

    if (v->days == -1) { v->days = 7; }
    if (v->days < parse_script->interp.vacation->min_response) 
       { v->days = parse_script->interp.vacation->min_response; }
    if (v->days > parse_script->interp.vacation->max_response)
       { v->days = parse_script->interp.vacation->max_response; }
    if (v->mime == -1) { v->mime = 0; }

    return v;
}

static void free_vtags(struct vtags *v)
{
    if (v->addresses) { free_sl(v->addresses); }
    if (v->subject) { free(v->subject); }
    free(v);
}
