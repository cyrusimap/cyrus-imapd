%{
/* sieve.y -- sieve parser
 * Larry Greenfield
 * $Id: sieve.y,v 1.13 2002/02/13 20:44:04 rjs3 Exp $
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
			     stringlist_t *sl, patternlist_t *pl);
static test_t *build_header(int t, struct htags *h,
			    stringlist_t *sl, patternlist_t *pl);
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

static int verify_mailboxes(stringlist_t *sl);
static int verify_addresses(stringlist_t *sl);
static int verify_flags(stringlist_t *sl);
#ifdef ENABLE_REGEX
static patternlist_t *verify_regexs(stringlist_t *sl, char *comp);
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
}

%token <nval> NUMBER
%token <sval> STRING
%token IF ELSIF ELSE
%token REJCT FILEINTO FORWARD KEEP STOP DISCARD VACATION REQUIRE
%token SETFLAG ADDFLAG REMOVEFLAG MARK UNMARK
%token NOTIFY DENOTIFY
%token ANYOF ALLOF EXISTS SFALSE STRUE HEADER NOT SIZE ADDRESS ENVELOPE
%token COMPARATOR IS CONTAINS MATCHES REGEX OVER UNDER
%token ALL LOCALPART DOMAIN USER DETAIL
%token DAYS ADDRESSES SUBJECT MIME
%token LOW MEDIUM HIGH

%type <cl> commands command action elsif block
%type <sl> stringlist strings
%type <test> test
%type <nval> comptag sizetag addrparttag addrorenv
%type <testl> testlist tests
%type <htag> htags
%type <aetag> aetags
%type <vtag> vtags
%type <sl> optional_headers
%type <sval> priority

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
	| FILEINTO stringlist	 { if (!parse_script->support.fileinto) {
				     yyerror("fileinto not required");
	                             YYERROR;
                                   }
				   if (!verify_mailboxes($2)) {
				     YYERROR; /* vm should call yyerror() */
				   }
	                           $$ = new_command(FILEINTO);
				   $$->u.sl = $2; }
	| FORWARD stringlist     { $$ = new_command(FORWARD);
				   if (!verify_addresses($2)) {
				     YYERROR; /* va should call yyerror() */
				   }
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
				   } }
        | SETFLAG stringlist     { if (!parse_script->support.imapflags) {
                                    yyerror("imapflags not required");
                                    YYERROR;
                                   }
                                  if (!verify_flags($2)) {
                                    YYERROR; /* vf should call yyerror() */
                                  }
                                  $$ = new_command(SETFLAG);
                                  $$->u.sl = $2; }
         | ADDFLAG stringlist     { if (!parse_script->support.imapflags) {
                                    yyerror("imapflags not required");
                                    YYERROR;
                                    }
                                  if (!verify_flags($2)) {
                                    YYERROR; /* vf should call yyerror() */
                                  }
                                  $$ = new_command(ADDFLAG);
                                  $$->u.sl = $2; }
         | REMOVEFLAG stringlist  { if (!parse_script->support.imapflags) {
                                    yyerror("imapflags not required");
                                    YYERROR;
                                    }
                                  if (!verify_flags($2)) {
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

         | NOTIFY priority STRING optional_headers
                                    {
					if (!parse_script->support.notify) {
					    yyerror("notify not required");
					    YYERROR;
					}

					$$ = new_command(NOTIFY); 
					$$->u.n.priority = $2;
					$$->u.n.message = $3;
					$$->u.n.headers_list = $4;
				    }
         | DENOTIFY               { if (!parse_script->support.notify) {
                                    yyerror("notify not required");
                                    YYERROR;
                                    }
	                            $$ = new_command(DENOTIFY); }

	;

priority: /* nothing */ { $$ = "medium"; }
	| LOW    { $$ = "low"; }
        | MEDIUM { $$ = "medium"; }
        | HIGH { $$ = "high"; }
        ;

optional_headers: /* empty */ { 	                        
				$$ = NULL;
	                      }
                 | stringlist { $$ = $1; }
                 ;

vtags: /* empty */		 { $$ = new_vtags(); }
	| vtags DAYS NUMBER	 { if ($$->days != -1) { 
					yyerror("duplicate :days"); YYERROR; }
				   else { $$->days = $3; } }
	| vtags ADDRESSES stringlist { if ($$->addresses != NULL) { 
					yyerror("duplicate :addresses"); 
					YYERROR;
				       } else if (!verify_addresses($3)) {
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

test: ANYOF testlist		 { $$ = new_test(ANYOF); $$->u.tl = $2; }
	| ALLOF testlist	 { $$ = new_test(ALLOF); $$->u.tl = $2; }
	| EXISTS stringlist      { $$ = new_test(EXISTS); $$->u.sl = $2; }
	| SFALSE		 { $$ = new_test(SFALSE); }
	| STRUE			 { $$ = new_test(STRUE); }
	| HEADER htags stringlist stringlist
				 { patternlist_t *pl;
				   $2 = canon_htags($2);
#ifdef ENABLE_REGEX
				   if ($2->comptag == REGEX) {
				     pl = verify_regexs($4, $2->comparator);
				     if (!pl) { YYERROR; }
				   }
				   else
#endif
				     pl = (patternlist_t *) $4;
				       
				   $$ = build_header(HEADER, $2, $3, pl);
				   if ($$ == NULL) { YYERROR; } }
	| addrorenv aetags stringlist stringlist
				 { patternlist_t *pl;
				   $2 = canon_aetags($2);
#ifdef ENABLE_REGEX
				   if ($2->comptag == REGEX) {
				     pl = verify_regexs($4, $2->comparator);
				     if (!pl) { YYERROR; }
				   }
				   else
#endif
				     pl = (patternlist_t *) $4;
				       
				   $$ = build_address($1, $2, $3, pl);
				   if ($$ == NULL) { YYERROR; } }
	| NOT test		 { $$ = new_test(NOT); $$->u.t = $2; }
	| SIZE sizetag NUMBER    { $$ = new_test(SIZE); $$->u.sz.t = $2;
		                   $$->u.sz.n = $3; }
	| error			 { $$ = NULL; }
	;

addrorenv: ADDRESS		 { $$ = ADDRESS; }
	| ENVELOPE		 { $$ = ENVELOPE; }
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
	| aetags COMPARATOR STRING { $$ = $1;
				   if ($$->comparator != NULL) { 
			yyerror("duplicate comparator tag"); YYERROR; }
				   else { $$->comparator = $3; } }
	;

htags: /* empty */		 { $$ = new_htags(); }
	| htags comptag		 { $$ = $1;
				   if ($$->comptag != -1) { 
			yyerror("duplicate comparator type tag"); YYERROR; }
				   else { $$->comptag = $2; } }
	| htags COMPARATOR STRING { $$ = $1;
				   if ($$->comparator != NULL) { 
			yyerror("duplicate comparator tag");
					YYERROR; }
				   else { $$->comparator = $3; } }
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
			     stringlist_t *sl, patternlist_t *pl)
{
    test_t *ret = new_test(t);	/* can be either ADDRESS or ENVELOPE */

    assert((t == ADDRESS) || (t == ENVELOPE));

    if (ret) {
	ret->u.ae.comptag = ae->comptag;
	ret->u.ae.comp = lookup_comp(ae->comparator, ae->comptag);
	ret->u.ae.sl = sl;
	ret->u.ae.pl = pl;
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
			    stringlist_t *sl, patternlist_t *pl)
{
    test_t *ret = new_test(t);	/* can be HEADER */

    assert(t == HEADER);

    if (ret) {
	ret->u.h.comptag = h->comptag;
	ret->u.h.comp = lookup_comp(h->comparator, h->comptag);
	ret->u.h.sl = sl;
	ret->u.h.pl = pl;
	free_htags(h);
	if (ret->u.h.comp == NULL) {
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
    struct aetags *r = (struct aetags *) xmalloc(sizeof(struct aetags));

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
    struct htags *r = (struct htags *) xmalloc(sizeof(struct htags));

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

char *addrptr;		/* pointer to address string for address lexer */
char addrerr[500];	/* buffer for address parser error messages */

static int verify_address(char *s)
{
    char errbuf[500];

    addrptr = s;
    addrerr[0] = '\0';	/* paranoia */
    if (addrparse()) {
	sprintf(errbuf, "address '%s': %s", s, addrerr);
	yyerror(errbuf);
	return 0;
    }
    return 1;
}

static int verify_addresses(stringlist_t *sl)
{
    for (; sl != NULL && verify_address(sl->s); sl = sl->next) ;
    return (sl == NULL);
}

static int verify_mailbox(char *s __attribute__((unused)))
{
    /* xxx if not a mailbox, call yyerror */
    return 1;
}

static int verify_mailboxes(stringlist_t *sl)
{
    for (; sl != NULL && verify_mailbox(sl->s); sl = sl->next) ;
    return (sl == NULL);
}

static int verify_flag(char *f)
{
    char errbuf[100];
 
    if (f[0] == '\\') {
	lcase(f);
	if (strcmp(f, "\\seen") && strcmp(f, "\\answered") &&
	    strcmp(f, "\\flagged") && strcmp(f, "\\draft") &&
	    strcmp(f, "\\deleted")) {
	    sprintf(errbuf, "flag '%s': not a system flag", f);
	    yyerror(errbuf);
	    return 0;
	}
	return 1;
    }
    if (!imparse_isatom(f)) {
	sprintf(errbuf, "flag '%s': not a valid keyword", f);
	yyerror(errbuf);
	return 0;
    }
    return 1;
}
 
static int verify_flags(stringlist_t *sl)
{
    for (; sl != NULL && verify_flag(sl->s); sl = sl->next) ;
    return (sl == NULL);
}


#ifdef ENABLE_REGEX
static regex_t *verify_regex(char *s, int cflags)
{
    int ret;
    char errbuf[100];
    regex_t *reg = (regex_t *) xmalloc(sizeof(regex_t));

    if ((ret = regcomp(reg, s, cflags)) != 0) {
	(void) regerror(ret, reg, errbuf, sizeof(errbuf));
	yyerror(errbuf);
	free(reg);
	return NULL;
    }
    return reg;
}

static patternlist_t *verify_regexs(stringlist_t *sl, char *comp)
{
    stringlist_t *sl2;
    patternlist_t *pl = NULL;
    int cflags = REG_EXTENDED | REG_NOSUB;
    regex_t *reg;

    if (!strcmp(comp, "i;ascii-casemap")) {
	cflags |= REG_ICASE;
    }

    for (sl2 = sl; sl2 != NULL; sl2 = sl2->next) {
	if ((reg = verify_regex(sl2->s, cflags)) == NULL) {
	    free_pl(pl, REGEX);
	    break;
	}
	pl = (patternlist_t *) new_pl(reg, pl);
    }
    if (sl2 == NULL) {
	free_sl(sl);
	return pl;
    }
    return NULL;
}
#endif

/* xxx is it ok to put this in an RFC822 header body? */
static int ok_header(char *s __attribute__((unused)))
{
    return 1;
}
