%{
/* addr.y -- RFC 822 address parser */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <string.h>

#include "sieve/script.h"
#include "sieve/addr.h"
#include "xstrlcpy.h"

#define ADDRERR_SIZE 500

void yyerror(sieve_script_t*, const char *);
extern int addrlex(YYSTYPE*, sieve_script_t*);

#define YYERROR_VERBOSE /* i want better error messages! */

/* byacc default is 500, bison default is 10000 - go with the
   larger to support big sieve scripts (see Bug #3461) */
#define YYSTACKSIZE 10000
%}

%token ATOM QTEXT DTEXT
%name-prefix "addr"
%defines
%param {sieve_script_t *parse_script}
%pure-parser
%%
sieve_address: addrspec                 /* simple address */
        | phrase '<' addrspec '>'       /* name & addr-spec */
        ;

addrspec: localpart '@' domain          /* global-address */
        ;

localpart: word                         /* uninterpreted, case-preserved */
        | word '.' localpart
        ;

domain: subdomain
        | subdomain '.' domain
        ;

subdomain: domainref
        | domainlit
        ;

domainref: ATOM                         /* symbolic reference */
        ;

domainlit: '[' DTEXT ']'
        ;

phrase: word
        | word phrase
        ;

word: ATOM
        | qstring
        ;

qstring: '"' QTEXT '"'
        ;

%%

/* copy address error message into buffer provided by sieve parser */
void yyerror(sieve_script_t *parse_script, const char *s)
{
    strlcpy(parse_script->addrerr, s, ADDRERR_SIZE);
}
