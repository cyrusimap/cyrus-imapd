%{

/* parse.y -- parser used by timsieved
 * Tim Martin
 * 9/21/99
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



#include <stdlib.h>
#include <stdio.h>

#include <string.h>
#include <sasl.h>


#define YYPARSE_PARAM _client
#define YYLEX_PARAM _client
#define YYERROR_VERBOSE

#define yylex timlex
#define yyparse timparse

  /*#undef __GNUC__*/

#include "prot.h"

#include "mystring.h"

  /* because bison is stupid */
#undef __GNUC__


extern sasl_conn_t *sieved_saslconn; /* the sasl connection context */

int authenticated=0;


%}

%pure_parser
%token_table

%union {
  string_t *str;
  unsigned long number;
  
  int boolean;

}

%{
extern int yylex(YYSTYPE *lvalp, void *client);
static void yyerror(char *s);

static void
  report_error(struct protstream *conn, const char *msg);

static void
  report_error_code(struct protstream *conn, int code);

#define CONN ((struct protstream *)(_client))

#define yyerror(s) report_error(CONN,s)

extern struct protstream *sieved_out;

%}





%token EOL
%token STRING


%token AUTHENTICATE
%token NOOP
%token LOGOUT
%token GETSCRIPT
%token PUTSCRIPT
%token SETACTIVE
%token LISTSCRIPTS
%token DELETESCRIPT

%type <str> STRING

%type <str> authenticate_optional_string

%type <str> sievename
%type <str> sievedata

%%

top: /*{ CLIENT->recovering = FALSE; CLIENT->isbad = FALSE; }*/ line
{
  return TRUE;
}

line: command
{

}
    | error EOL
{
  return FALSE;
}

/* commands we support */
command: authenticate
      |  noop
      |  logout
      |  getscript
      |  putscript
      |  setactive
      |  deletescript
      |  listscripts

/* AUTHENTICATION RULES */

authenticate: notauthed AUTHENTICATE ' ' STRING authenticate_optional_string EOL
{
  int sasl_result;

  char *mech = string_DATAPTR($4);

  string_t *clientinstr=NULL;
  char *clientin=NULL;
  int clientinlen = 0;

  char *serverout=NULL;
  unsigned int serveroutlen;
  const char *errstr;
  char *username;

  clientinstr = $5;
  if (clientinstr!=NULL)
  {

      clientin=(char *) malloc(clientinstr->len*2);

      sasl_result=sasl_decode64(string_DATAPTR(clientinstr), clientinstr->len,
				clientin, &clientinlen);

      if (sasl_result!=SASL_OK)
      {
	report_error(CONN, "error base63 decoding string");
	return FALSE;
      }
  }

  sasl_result = sasl_server_start(sieved_saslconn, mech,
				  clientin, clientinlen,
				  &serverout, &serveroutlen,
				  &errstr);

  while (sasl_result==SASL_CONTINUE)
  {
    YYSTYPE state;
    int token1;
    int token2;
    int token3;
    char *strout=NULL;
    int stroutlen;
    string_t *str;
    char *inbase64;
    int inbase64len;

    /* convert to base64 */
    inbase64 = malloc( serveroutlen*2+1);
    sasl_encode64(serverout, serveroutlen,
		  inbase64, serveroutlen*2+1, &inbase64len);

    /* send out the string always as a literal */
    prot_printf(sieved_out, "{%d+}\r\n",inbase64len);
    prot_write(sieved_out,inbase64,inbase64len);
    prot_printf(sieved_out,"\r\n");
    prot_flush(sieved_out);

    token1 = timlex(&state, CONN);
    str = state.str;

    if (token1==STRING)
    {
      clientin=(char *) malloc(str->len*2);

      sasl_result=sasl_decode64(string_DATAPTR(str), str->len,
		    clientin, &clientinlen);

      if (sasl_result!=SASL_OK)
      {
	report_error(CONN, "error base64 decoding string");
	return FALSE;
      }      
      
    } else {
      prot_printf(sieved_out, "notstring %d\n",token1);
      prot_flush(sieved_out);
    }

    token2 = timlex(&state, CONN);

    /* we want to see a STRING followed by EOL */
    if ((token1==STRING) && (token2==EOL))
    {
      
      sasl_result = sasl_server_step(sieved_saslconn,
				     clientin,
				     clientinlen,
				     &serverout, &serveroutlen,
				     &errstr);


    } else {
      report_error(CONN, "expected a STRING followed by an EOL");
      return FALSE;
    }


  }

  if (sasl_result!=SASL_OK)
  {
    report_error(CONN, sasl_errstring(sasl_result,NULL,NULL) );
    return FALSE;
  }

  /* get the userid from SASL */
  sasl_result=sasl_getprop(sieved_saslconn, SASL_USERNAME,(void **) &username);
  if (sasl_result!=SASL_OK)
  {
    report_error(CONN, "Internal SASL error");
    return FALSE;
  }
  
  if (actions_setuser(username)!=TIMSIEVE_OK)
  {
    report_error(CONN, "Internal error");
    return FALSE;
  }

  /* Yay! authenticated */
  prot_printf(sieved_out, "OK \"Authenticated!\"\r\n");
  prot_flush(sieved_out);  

  authenticated=1;

  /* free memory */
}

authenticate_optional_string: /* nothing */
{ 
  $$=NULL; 
} 
                            | ' ' STRING 
{ 
  $$ = $2; 
} 

/* END AUTHENTICATION RULES */

logout: LOGOUT EOL
{
  /* xxx make atomic */
  prot_printf(sieved_out, "Ok \"Logout Complete\"\r\n");
  prot_flush(sieved_out);

  prot_free(sieved_out);

  exit(0);

  return TRUE;			/* *do* close the connection */
}

noop: NOOP EOL
{
  prot_printf(sieved_out, "OK \"Noop Complete\"\r\n");
  prot_flush(sieved_out);

}

getscript: authed GETSCRIPT ' ' sievename EOL
{
  getscript(sieved_out, $4);
  prot_flush(sieved_out);

  free($4);
}

putscript: authed PUTSCRIPT ' ' sievename ' ' sievedata EOL
{
  putscript(sieved_out, $4, $6);
  prot_flush(sieved_out);

  free($4);
  free($6);
}

setactive: authed SETACTIVE ' ' sievename EOL
{
  setactive(sieved_out, $4);
  prot_flush(sieved_out);

  free($4);
}

deletescript: authed DELETESCRIPT ' ' sievename EOL
{
  deletescript(sieved_out, $4);
  prot_flush(sieved_out);

  free($4);
}

listscripts: authed LISTSCRIPTS EOL
{
  listscripts(sieved_out);
  prot_flush(sieved_out);
}

sievename: STRING
{
  if (verifyscriptname($1)!=TIMSIEVE_OK)
    return -1;
  $$=$1;
}

sievedata: STRING
{
  $$=$1;
}

authed: /* nothing */
{
  if (authenticated!=1)
  {
    report_error(CONN, "Authenticate first");
    return -1;
  }
}

notauthed: /* nothing */
{
  if (authenticated==1)
  {
    report_error(CONN, "You are already authenticated");
    return -1;
  }
}

%%

static void
report_error(struct protstream *conn, const char *msg)
{
  int result;
  YYSTYPE foo;

  prot_printf(sieved_out, "NO \"%s\"\r\n",msg);
  result=prot_flush(sieved_out);

  lex_reset();

  /* wait until we get a newline */
  while (timlex(&foo, conn)!=EOL)
    {

    }

  if (result!=0)
  {
    exit(0);
  }
 
}

static void
report_error_code(struct protstream *conn, int code)
{
  
  /* XXX  report_error(conn, error_message(code));*/
  report_error(conn, "some error");
}

