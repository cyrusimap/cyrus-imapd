%{
/*
 * addr.y -- RFC 822 address parser
 */

#include <stdlib.h>
#include <string.h>

#include "addr.h"

#include "script.h"
    
int yyerror(char *msg);
extern int yylex(void);

#define yyparse addrparse
#define yyerror addrerror

#define YYERROR_VERBOSE /* i want better error messages! */
%}

%token ATOM QTEXT DTEXT

%start sieve_address

%%
address: mailbox			/* one addressee */
	| group				/* named list */
	;

group: phrase ':' ';'
	| phrase ':' mailboxes ';'
	;

mailboxes: mailbox
	| mailbox ',' mailboxes
	;

mailbox: addrspec			/* simple address */
	| phrase routeaddr		/* name & addr-spec */
	;

routeaddr: '<' addrspec '>'
	| '<' route ':' addrspec '>'
	;

route: '@' domain			/* path-relative */
	| '@' domain ',' route
	;

sieve_address: addrspec			/* simple address */
	| phrase '<' addrspec '>'	/* name & addr-spec */
	;

addrspec: localpart '@' domain		/* global-address */
	;

localpart: word				/* uninterpreted, case-preserved */
	| word '.' localpart
	;

domain: subdomain
	| subdomain '.' domain
	;

subdomain: domainref
	| domainlit
	;

domainref: ATOM				/* symbolic reference */
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
int yyerror(char *s)
{
    strlcpy(addrerr, s, sizeof(addrerr));
    return 0;
}
