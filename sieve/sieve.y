%{
/* sieve.y -- sieve parser
 * Larry Greenfield
 * $Id: sieve.y,v 1.19.4.6 2003/03/24 19:01:42 ken3 Exp $
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <ctype.h>
#include "xmalloc.h"
#include "comparator.h"
#include "interp.h"
#include "script.h"
#include "tree.h"

#include "../lib/util.h"
#include "../lib/imparse.h"

    /* definitions */
    extern int addrparse(void);

struct vtags {
    int days;
    stringlist_t *addresses;
    char *subject;
    int mime;
};

struct htags {
    char *comparator;
    int comptag;
    int relation;
};

struct aetags {
    int addrtag;
    char *comparator;
    int comptag;
    int relation;
};

struct ntags {
    char *method;
    char *id;
    stringlist_t *options;
    int priority;
    char *message;
};

struct dtags {
    int comptag;
    int relation;
    void *pattern;
    int priority;
};

static commandlist_t *ret;
static sieve_script_t *parse_script;
static int check_reqs(stringlist_t *sl);
static test_t *build_address(int t, struct aetags *ae,
			     stringlist_t *sl, stringlist_t *pl);
static test_t *build_header(int t, struct htags *h,
			    stringlist_t *sl, stringlist_t *pl);
static commandlist_t *build_vacation(int t, struct vtags *h, char *s);
static commandlist_t *build_notify(int t, struct ntags *n);
static commandlist_t *build_denotify(int t, struct dtags *n);
static struct aetags *new_aetags(void);
static struct aetags *canon_aetags(struct aetags *ae);
static void free_aetags(struct aetags *ae);
static struct htags *new_htags(void);
static struct htags *canon_htags(struct htags *h);
static void free_htags(struct htags *h);
static struct vtags *new_vtags(void);
static struct vtags *canon_vtags(struct vtags *v);
static void free_vtags(struct vtags *v);
static struct ntags *new_ntags(void);
static struct ntags *canon_ntags(struct ntags *n);
static void free_ntags(struct ntags *n);
static struct dtags *new_dtags(void);
static struct dtags *canon_dtags(struct dtags *d);
static void free_dtags(struct dtags *d);

static int verify_stringlist(stringlist_t *sl, int (*verify)(char *));
static int verify_mailbox(char *s);
static int verify_address(char *s);
static int verify_header(char *s);
static int verify_flag(char *s);
static int verify_relat(char *s);
#ifdef ENABLE_REGEX
static int verify_regex(char *s, int cflags);
static int verify_regexs(stringlist_t *sl, char *comp);
#endif
static int ok_header(char *s);

int yyerror(char *msg);
extern int yylex(void);

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
    struct ntags *ntag;
    struct dtags *dtag;
}

%token <nval> NUMBER
%token <sval> STRING
%token IF ELSIF ELSE
%token REJCT FILEINTO REDIRECT KEEP STOP DISCARD VACATION REQUIRE
%token SETFLAG ADDFLAG REMOVEFLAG MARK UNMARK
%token NOTIFY DENOTIFY
%token ANYOF ALLOF EXISTS SFALSE STRUE HEADER NOT SIZE ADDRESS ENVELOPE
%token COMPARATOR IS CONTAINS MATCHES REGEX COUNT VALUE OVER UNDER
%token GT GE LT LE EQ NE
%token ALL LOCALPART DOMAIN USER DETAIL
%token DAYS ADDRESSES SUBJECT MIME
%token METHOD ID OPTIONS LOW NORMAL HIGH ANY MESSAGE

%type <cl> commands command action elsif block
%type <sl> stringlist strings
%type <test> test
%type <nval> comptag relcomp sizetag addrparttag addrorenv
%type <testl> testlist tests
%type <htag> htags
%type <aetag> aetags
%type <vtag> vtags
%type <ntag> ntags
%type <dtag> dtags
%type <nval> priority

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
	| error ';'		{ $$ = new_command(STOP); }
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
	| FILEINTO STRING	 { if (!parse_script->support.fileinto) {
				     yyerror("fileinto not required");
	                             YYERROR;
                                   }
				   if (!verify_mailbox($2)) {
				     YYERROR; /* vm should call yyerror() */
				   }
	                           $$ = new_command(FILEINTO);
				   $$->u.str = $2; }
	| REDIRECT STRING         { $$ = new_command(REDIRECT);
				   if (!verify_address($2)) {
				     YYERROR; /* va should call yyerror() */
				   }
				   $$->u.str = $2; }
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
				   } }
        | SETFLAG stringlist     { if (!parse_script->support.imapflags) {
                                    yyerror("imapflags not required");
                                    YYERROR;
                                   }
                                  if (!verify_stringlist($2, verify_flag)) {
                                    YYERROR; /* vf should call yyerror() */
                                  }
                                  $$ = new_command(SETFLAG);
                                  $$->u.sl = $2; }
         | ADDFLAG stringlist     { if (!parse_script->support.imapflags) {
                                    yyerror("imapflags not required");
                                    YYERROR;
                                    }
                                  if (!verify_stringlist($2, verify_flag)) {
                                    YYERROR; /* vf should call yyerror() */
                                  }
                                  $$ = new_command(ADDFLAG);
                                  $$->u.sl = $2; }
         | REMOVEFLAG stringlist  { if (!parse_script->support.imapflags) {
                                    yyerror("imapflags not required");
                                    YYERROR;
                                    }
                                  if (!verify_stringlist($2, verify_flag)) {
                                    YYERROR; /* vf should call yyerror() */
                                  }
                                  $$ = new_command(REMOVEFLAG);
                                  $$->u.sl = $2; }
         | MARK                   { if (!parse_script->support.imapflags) {
                                    yyerror("imapflags not required");
                                    YYERROR;
                                    }
                                  $$ = new_command(MARK); }
         | UNMARK                 { if (!parse_script->support.imapflags) {
                                    yyerror("imapflags not required");
                                    YYERROR;
                                    }
                                  $$ = new_command(UNMARK); }

         | NOTIFY ntags           { if (!parse_script->support.notify) {
				       yyerror("notify not required");
				       $$ = new_command(NOTIFY); 
				       YYERROR;
	 			    } else {
				      $$ = build_notify(NOTIFY,
				             canon_ntags($2));
				    } }
         | DENOTIFY dtags         { if (!parse_script->support.notify) {
                                       yyerror("notify not required");
				       $$ = new_command(DENOTIFY);
				       YYERROR;
				    } else {
					$$ = build_denotify(DENOTIFY, canon_dtags($2));
					if ($$ == NULL) { 
			yyerror("unable to find a compatible comparator");
			YYERROR; } } }
	;

ntags: /* empty */		 { $$ = new_ntags(); }
	| ntags ID STRING	 { if ($$->id != NULL) { 
					yyerror("duplicate :method"); YYERROR; }
				   else { $$->id = $3; } }
	| ntags METHOD STRING	 { if ($$->method != NULL) { 
					yyerror("duplicate :method"); YYERROR; }
				   else { $$->method = $3; } }
	| ntags OPTIONS stringlist { if ($$->options != NULL) { 
					yyerror("duplicate :options"); YYERROR; }
				     else { $$->options = $3; } }
        | ntags priority	 { if ($$->priority != -1) { 
                                 yyerror("duplicate :priority"); YYERROR; }
                                   else { $$->priority = $2; } }
	| ntags MESSAGE STRING	 { if ($$->message != NULL) { 
					yyerror("duplicate :message"); YYERROR; }
				   else { $$->message = $3; } }
	;

dtags: /* empty */		 { $$ = new_dtags(); }
	| dtags priority	 { if ($$->priority != -1) { 
				yyerror("duplicate priority level"); YYERROR; }
				   else { $$->priority = $2; } }
	| dtags comptag STRING 	 { if ($$->comptag != -1)
	                             { 
					 yyerror("duplicate comparator type tag"); YYERROR;
				     }
	                           $$->comptag = $2;
#ifdef ENABLE_REGEX
				   if ($$->comptag == REGEX)
				   {
				       int cflags = REG_EXTENDED |
					   REG_NOSUB | REG_ICASE;
				       if (!verify_regex($3, cflags)) { YYERROR; }
				   }
#endif
				   $$->pattern = $3;
	                          }
	| dtags relcomp STRING  { $$ = $1;
				   if ($$->comptag != -1) { 
			yyerror("duplicate comparator type tag"); YYERROR; }
				   else { $$->comptag = $2;
				   $$->relation = verify_relat($3);
				   if ($$->relation==-1) 
				     {YYERROR; /*vr called yyerror()*/ }
				   } }
	;

priority: LOW                   { $$ = LOW; }
        | NORMAL                { $$ = NORMAL; }
        | HIGH                  { $$ = HIGH; }
        ;

vtags: /* empty */		 { $$ = new_vtags(); }
	| vtags DAYS NUMBER	 { if ($$->days != -1) { 
					yyerror("duplicate :days"); YYERROR; }
				   else { $$->days = $3; } }
	| vtags ADDRESSES stringlist { if ($$->addresses != NULL) { 
					yyerror("duplicate :addresses"); 
					YYERROR;
				       } else if (!verify_stringlist($3,
							verify_address)) {
					  YYERROR;
				       } else {
					 $$->addresses = $3; } }
	| vtags SUBJECT STRING	 { if ($$->subject != NULL) { 
					yyerror("duplicate :subject"); 
					YYERROR;
				   } else if (!ok_header($3)) {
					YYERROR;
				   } else { $$->subject = $3; } }
	| vtags MIME		 { if ($$->mime != -1) { 
					yyerror("duplicate :mime"); 
					YYERROR; }
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

test:     ANYOF testlist	 { $$ = new_test(ANYOF); $$->u.tl = $2; }
        | ALLOF testlist	 { $$ = new_test(ALLOF); $$->u.tl = $2; }
        | EXISTS stringlist      { $$ = new_test(EXISTS); $$->u.sl = $2; }
        | SFALSE		 { $$ = new_test(SFALSE); }
	| STRUE			 { $$ = new_test(STRUE); }
	| HEADER htags stringlist stringlist
				 {
				     if (!verify_stringlist($3, verify_header)) {
					 YYERROR; /* vh should call yyerror() */
				     }
				     
				     $2 = canon_htags($2);
#ifdef ENABLE_REGEX
				     if ($2->comptag == REGEX)
				     {
					 if (!(verify_regexs($4, $2->comparator)))
					 { YYERROR; }
				     }
#endif
				     $$ = build_header(HEADER, $2, $3, $4);
				     if ($$ == NULL) { 
					 yyerror("unable to find a compatible comparator");
					 YYERROR; } 
				 }


        | addrorenv aetags stringlist stringlist
				 { 
				     if (!verify_stringlist($3, verify_header))
				     {
					 YYERROR; /* vh should call yyerror() */
				     }
				     
				     $2 = canon_aetags($2);
#ifdef ENABLE_REGEX
				     if ($2->comptag == REGEX)
				     {
					 if (!( verify_regexs($4, $2->comparator)))
					 { YYERROR; }
				     }
#endif
				     $$ = build_address($1, $2, $3, $4);
				     if ($$ == NULL) { 
					 yyerror("unable to find a compatible comparator");
					 YYERROR; } 
				 }

	| NOT test		 { $$ = new_test(NOT); $$->u.t = $2; }
	| SIZE sizetag NUMBER    { $$ = new_test(SIZE); $$->u.sz.t = $2;
		                   $$->u.sz.n = $3; }
	| error			 { $$ = NULL; }
	;

addrorenv: ADDRESS		 { $$ = ADDRESS; }
	| ENVELOPE		 {if (!parse_script->support.envelope)
	                              {yyerror("envelope not required"); YYERROR;}
	                          else{$$ = ENVELOPE; }
	                         }

	;

aetags: /* empty */              { $$ = new_aetags(); }
        | aetags addrparttag	 { $$ = $1;
				   if ($$->addrtag != -1) { 
			yyerror("duplicate or conflicting address part tag");
			YYERROR; }
				   else { $$->addrtag = $2; } }
	| aetags comptag         { $$ = $1;
				   if ($$->comptag != -1) { 
			yyerror("duplicate comparator type tag"); YYERROR; }
				   else { $$->comptag = $2; } }
	| aetags relcomp STRING{ $$ = $1;
				   if ($$->comptag != -1) { 
			yyerror("duplicate comparator type tag"); YYERROR; }
				   else { $$->comptag = $2;
				   $$->relation = verify_relat($3);
				   if ($$->relation==-1) 
				     {YYERROR; /*vr called yyerror()*/ }
				   } }
        | aetags COMPARATOR STRING { $$ = $1;
	if ($$->comparator != NULL) { 
			yyerror("duplicate comparator tag"); YYERROR; }
				   else if (!strcmp($3, "i;ascii-numeric") &&
					    !parse_script->support.i_ascii_numeric) {
			yyerror("comparator-i;ascii-numeric not required");
			YYERROR; }
				   else { $$->comparator = $3; } }
	;

htags: /* empty */		 { $$ = new_htags(); }
	| htags comptag		 { $$ = $1;
				   if ($$->comptag != -1) { 
			yyerror("duplicate comparator type tag"); YYERROR; }
				   else { $$->comptag = $2; } }
	| htags relcomp STRING { $$ = $1;
				   if ($$->comptag != -1) { 
			yyerror("duplicate comparator type tag"); YYERROR; }
				   else { $$->comptag = $2;
				   $$->relation = verify_relat($3);
				   if ($$->relation==-1) 
				     {YYERROR; /*vr called yyerror()*/ }
				   } }
	| htags COMPARATOR STRING { $$ = $1;
				   if ($$->comparator != NULL) { 
			 yyerror("duplicate comparator tag"); YYERROR; }
				   else if (!strcmp($3, "i;ascii-numeric") &&
					    !parse_script->support.i_ascii_numeric) { 
			 yyerror("comparator-i;ascii-numeric not required");  YYERROR; }
				   else { 
				     $$->comparator = $3; } }
        ;


addrparttag: ALL                 { $$ = ALL; }
	| LOCALPART		 { $$ = LOCALPART; }
	| DOMAIN                 { $$ = DOMAIN; }
	| USER                   { if (!parse_script->support.subaddress) {
				     yyerror("subaddress not required");
				     YYERROR;
				   }
				   $$ = USER; }  
	| DETAIL                { if (!parse_script->support.subaddress) {
				     yyerror("subaddress not required");
				     YYERROR;
				   }
				   $$ = DETAIL; }
	;
comptag: IS			 { $$ = IS; }
	| CONTAINS		 { $$ = CONTAINS; }
	| MATCHES		 { $$ = MATCHES; }
	| REGEX			 { if (!parse_script->support.regex) {
				     yyerror("regex not required");
				     YYERROR;
				   }
				   $$ = REGEX; }
	;

relcomp: COUNT			 { if (!parse_script->support.relational) {
				     yyerror("relational not required");
				     YYERROR;
				   }
				   $$ = COUNT; }
	| VALUE			 { if (!parse_script->support.relational) {
				     yyerror("relational not required");
				     YYERROR;
				   }
				   $$ = VALUE; }
	;


sizetag: OVER			 { $$ = OVER; }
	| UNDER			 { $$ = UNDER; }
	;

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
    extern int yylineno;
    int ret;

    parse_script->err++;
    if (parse_script->interp.err) {
	ret = parse_script->interp.err(yylineno, msg, 
				       parse_script->interp.interp_context,
				       parse_script->script_context);
    }

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
			     stringlist_t *sl, stringlist_t *pl)
{
    test_t *ret = new_test(t);	/* can be either ADDRESS or ENVELOPE */

    assert((t == ADDRESS) || (t == ENVELOPE));

    if (ret) {
	ret->u.ae.comptag = ae->comptag;
	ret->u.ae.relation=ae->relation;
	ret->u.ae.comparator=strdup(ae->comparator);
	ret->u.ae.sl = sl;
	ret->u.ae.pl = pl;
	ret->u.ae.addrpart = ae->addrtag;
	free_aetags(ae);

    }
    return ret;
}

static test_t *build_header(int t, struct htags *h,
			    stringlist_t *sl, stringlist_t *pl)
{
    test_t *ret = new_test(t);	/* can be HEADER */

    assert(t == HEADER);

    if (ret) {
	ret->u.h.comptag = h->comptag;
	ret->u.h.relation=h->relation;
	ret->u.h.comparator=strdup(h->comparator);
	ret->u.h.sl = sl;
	ret->u.h.pl = pl;
	free_htags(h);
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
	ret->u.d.comptag = d->comptag;
	ret->u.d.relation=d->relation;
	ret->u.d.pattern = d->pattern; d->pattern = NULL;
	ret->u.d.priority = d->priority;
	free_dtags(d);
    }
    return ret;
}

static struct aetags *new_aetags(void)
{
    struct aetags *r = (struct aetags *) xmalloc(sizeof(struct aetags));

    r->addrtag = r->comptag = r->relation=-1;
    r->comparator=NULL;

    return r;
}

static struct aetags *canon_aetags(struct aetags *ae)
{
    if (ae->addrtag == -1) { ae->addrtag = ALL; }
    if (ae->comparator == NULL) {
        ae->comparator = xstrdup("i;ascii-casemap");
    }
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
    struct htags *r = (struct htags *) xmalloc(sizeof(struct htags));

    r->comptag = r->relation= -1;
    
    r->comparator = NULL;

    return r;
}

static struct htags *canon_htags(struct htags *h)
{
    if (h->comparator == NULL) {
	h->comparator = xstrdup("i;ascii-casemap");
    }
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
    struct vtags *r = (struct vtags *) xmalloc(sizeof(struct vtags));

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
    if (n->priority == -1) { n->priority = NORMAL; }
    if (n->message == NULL) { n->message = strdup("$from$: $subject$"); }
    if (n->method == NULL) { n->method = strdup("default"); }
    return n;
}
static struct dtags *canon_dtags(struct dtags *d)
{
    if (d->priority == -1) { d->priority = ANY; }
    if (d->comptag == -1) { d->comptag = ANY; }
       return d;
}

static void free_ntags(struct ntags *n)
{
    if (n->method) { free(n->method); }
    if (n->id) { free(n->id); }
    if (n->options) { free_sl(n->options); }
    if (n->message) { free(n->message); }
    free(n);
}

static struct dtags *new_dtags(void)
{
    struct dtags *r = (struct dtags *) xmalloc(sizeof(struct dtags));

    r->comptag = r->priority= r->relation = -1;
    r->pattern  = NULL;

    return r;
}

static void free_dtags(struct dtags *d)
{
    if (d->pattern) free(d->pattern);
    free(d);
}

static int verify_stringlist(stringlist_t *sl, int (*verify)(char *))
{
    for (; sl != NULL && verify(sl->s); sl = sl->next) ;
    return (sl == NULL);
}

char *addrptr;		/* pointer to address string for address lexer */
char addrerr[500];	/* buffer for address parser error messages */

static int verify_address(char *s)
{
    char errbuf[500];

    addrptr = s;
    addrerr[0] = '\0';	/* paranoia */
    if (addrparse()) {
	snprintf(errbuf, sizeof(errbuf), "address '%s': %s", s, addrerr);
	yyerror(errbuf);
	return 0;
    }
    return 1;
}

static int verify_mailbox(char *s __attribute__((unused)))
{
    /* xxx if not a mailbox, call yyerror */
    return 1;
}

static int verify_header(char *hdr)
{
    char *h = hdr;
    char errbuf[100];

    while (*h) {
	/* field-name      =       1*ftext
	   ftext           =       %d33-57 / %d59-126         
	   ; Any character except
	   ;  controls, SP, and
	   ;  ":". */
	if (!((*h >= 33 && *h <= 57) || (*h >= 59 && *h <= 126))) {
	    snprintf(errbuf, sizeof(errbuf),
		     "header '%s': not a valid header", hdr);
	    yyerror(errbuf);
	    return 0;
	}
	h++;
    }
    return 1;
}
 
static int verify_relat(char *r)
{/* this really should have been a token to begin with.*/
    char errbuf[100];
	lcase(r);
	if (strcmp(r, "gt")) {return GT;}
	else if (strcmp(r, "ge")) {return GE;}
	else if (strcmp(r, "lt")) {return LT;}
	else if (strcmp(r, "le")) {return LE;}
	else if (strcmp(r, "ne")) {return NE;}
	else if (strcmp(r, "eq")) {return EQ;}
	else{
	  sprintf(errbuf, "flag '%s': not a valid relational operation", r);
	  yyerror(errbuf);
	  return -1;
	}
	
}




static int verify_flag(char *f)
{
    char errbuf[100];
 
    if (f[0] == '\\') {
	lcase(f);
	if (strcmp(f, "\\seen") && strcmp(f, "\\answered") &&
	    strcmp(f, "\\flagged") && strcmp(f, "\\draft") &&
	    strcmp(f, "\\deleted")) {
	    snprintf(errbuf, sizeof(errbuf),
		     "flag '%s': not a system flag", f);
	    yyerror(errbuf);
	    return 0;
	}
	return 1;
    }
    if (!imparse_isatom(f)) {
	snprintf(errbuf, sizeof(errbuf), "flag '%s': not a valid keyword", f);
	yyerror(errbuf);
	return 0;
    }
    return 1;
}
 
#ifdef ENABLE_REGEX
static int verify_regex(char *s, int cflags)
{
    int ret;
    char errbuf[100];
    regex_t *reg = (regex_t *) xmalloc(sizeof(regex_t));

     if ((ret = regcomp(reg, s, cflags)) != 0) {
	(void) regerror(ret, reg, errbuf, sizeof(errbuf));
	yyerror(errbuf);
	free(reg);
	return 0;
	}
    free(reg);
    return 1;
}

static int verify_regexs(stringlist_t *sl, char *comp)
{
    stringlist_t *sl2;
    int cflags = REG_EXTENDED | REG_NOSUB;
 

    if (!strcmp(comp, "i;ascii-casemap")) {
	cflags |= REG_ICASE;
    }

    for (sl2 = sl; sl2 != NULL; sl2 = sl2->next) {
	if ((verify_regex(sl2->s, cflags)) == 0) {
	    break;
	}
    }
    if (sl2 == NULL) {
	return 1;
    }
    return 0;
}
#endif

/* xxx is it ok to put this in an RFC822 header body? */
static int ok_header(char *s __attribute__((unused)))
{
    return 1;
}
