/* parser.c -- parser used by timsieved
 * Tim Martin
 * 9/21/99
 * $Id: parser.c,v 1.9 2001/01/29 21:15:06 leg Exp $
 */
/*
 * Copyright (c) 1999-2000 Carnegie Mellon University.  All rights reserved.
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
 *    prior written permission. For permission or any other legal
 *    details, please contact  
 *      Office of Technology Transfer
 *      Carnegie Mellon University
 *      5000 Forbes Avenue
 *      Pittsburgh, PA  15213-3890
 *      (412) 268-4387, fax: (412) 268-7395
 *      tech-transfer@andrew.cmu.edu
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
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <syslog.h>

#include <string.h>
#include <sasl.h>
#include <saslutil.h>

#include "prot.h"
#include "lex.h"
#include "actions.h"

extern sasl_conn_t *sieved_saslconn; /* the sasl connection context */
extern char sieved_clienthost[250];
int authenticated = 0;


/* forward declarations */
static int cmd_logout(struct protstream *sieved_out, struct protstream *sieved_in);
static int cmd_authenticate(struct protstream *sieved_out, struct protstream *sieved_in,
			    mystring_t *mechanism_name, mystring_t *initial_challenge, const char **errmsg);



int parser(struct protstream *sieved_out, struct protstream *sieved_in)
{
  int token;
  const char *error_msg = "Generic Error";

  mystring_t *mechanism_name = NULL;
  mystring_t *initial_challenge = NULL;
  mystring_t *sieve_name = NULL;
  mystring_t *sieve_data = NULL;
  unsigned long num;

  /* get one token from the lexer */
  token = timlex(NULL, NULL, sieved_in);

  if ((authenticated == 0) && (token > 255) && (token!=AUTHENTICATE) && (token!=LOGOUT))
  {
    error_msg = "Authenticate first";
    if (token!=EOL)
      lex_setrecovering();

    goto error;
  }

  switch (token)
  {
  case AUTHENTICATE:
    if (timlex(NULL, NULL, sieved_in)!=SPACE)
    {
      error_msg = "SPACE must occur after AUTHENTICATE";
      goto error;
    }

    if (timlex(&mechanism_name, NULL, sieved_in)!=STRING)
    {
      error_msg = "Did not specify mechanism name";
      goto error;
    }

    token = timlex(NULL, NULL, sieved_in);

    if (token != EOL)
    {
      /* optional client first challenge */
      if (token!=SPACE)
      {
	error_msg = "Expected SPACE";
	goto error;
      }

      if (timlex(&initial_challenge, NULL, sieved_in)!=STRING)
      {
	error_msg = "Expected string";
	goto error;
      }

      token = timlex(NULL, NULL, sieved_in);      
    }

    if (token != EOL)
    {
      error_msg = "Expected EOL";
      goto error;
    }

    if (cmd_authenticate(sieved_out, sieved_in, mechanism_name, initial_challenge, &error_msg)==FALSE)
    {
	/* free memory */
	free(mechanism_name);
	free(initial_challenge);
	
	prot_printf(sieved_out, "NO (\"SASL\" \"%s\") \"Authentication error\"\r\n",error_msg);
	prot_flush(sieved_out);

	return -1;
    }
    
    break;

  case CAPABILITY:
      capabilities(sieved_out, sieved_saslconn);
      break;

  case HAVESPACE:
      if (timlex(NULL, NULL, sieved_in)!=SPACE)
      {
	  error_msg = "SPACE must occur after PUTSCRIPT";
	  goto error;
      }
      
      if (timlex(&sieve_name, NULL, sieved_in)!=STRING)
      {
	  error_msg = "Did not specify script name";
	  goto error;
      }
      
      if (timlex(NULL, NULL, sieved_in)!=SPACE)
      {
	  error_msg = "Expected SPACE";
	  goto error;
      }
      
      if (timlex(NULL, &num, sieved_in)!=NUMBER)
      {
	  error_msg = "Expected Number";
	  goto error;
      }

      if (timlex(NULL, NULL, sieved_in)!=EOL)
      {
	  error_msg = "Expected EOL";
	  goto error;
      }

      cmd_havespace(sieved_out, sieve_name, num);

      break;

  case LOGOUT:
    if (timlex(NULL, NULL, sieved_in)!=EOL)
    {
      error_msg = "Garbage after logout command";
      goto error;
    }

    cmd_logout(sieved_out, sieved_in);

    return TRUE;			/* *do* close the connection */   
    break;

  case GETSCRIPT:
    if (timlex(NULL, NULL, sieved_in)!=SPACE)
    {
      error_msg = "SPACE must occur after GETSCRIPT";
      goto error;
    }

    if (timlex(&sieve_name, NULL, sieved_in)!=STRING)
    {
      error_msg = "Did not specify script name";
      goto error;
    }

    if (timlex(NULL, NULL, sieved_in)!=EOL)
    {
      error_msg = "Expected EOL";
      goto error;
    }

    getscript(sieved_out, sieve_name);
    
    break;


  case PUTSCRIPT:
    if (timlex(NULL, NULL, sieved_in)!=SPACE)
    {
      error_msg = "SPACE must occur after PUTSCRIPT";
      goto error;
    }

    if (timlex(&sieve_name, NULL, sieved_in)!=STRING)
    {
      error_msg = "Did not specify script name";
      goto error;
    }

    if (timlex(NULL, NULL, sieved_in)!=SPACE)
    {
      error_msg = "Expected SPACE";
      goto error;
    }

    if (timlex(&sieve_data, NULL, sieved_in)!=STRING)
    {
      error_msg = "Did not specify script data";
      goto error;
    }

    if (timlex(NULL, NULL, sieved_in)!=EOL)
    {
      error_msg = "Expected EOL";
      goto error;
    }

    putscript(sieved_out, sieve_name, sieve_data);
    
    break;

  case SETACTIVE:
    if (timlex(NULL, NULL, sieved_in)!=SPACE)
    {
      error_msg = "SPACE must occur after SETACTIVE";
      goto error;
    }

    if (timlex(&sieve_name, NULL, sieved_in)!=STRING)
    {
      error_msg = "Did not specify script name";
      goto error;
    }

    if (timlex(NULL, NULL, sieved_in)!=EOL)
    {
      error_msg = "Expected EOL";
      goto error;
    }

    setactive(sieved_out, sieve_name);
    
    break;

  case DELETESCRIPT:
    if (timlex(NULL, NULL, sieved_in)!=SPACE)
    {
      error_msg = "SPACE must occur after DELETESCRIPT";
      goto error;
    }

    if (timlex(&sieve_name, NULL, sieved_in)!=STRING)
    {
      error_msg = "Did not specify script name";
      goto error;
    }

    if (timlex(NULL, NULL, sieved_in)!=EOL)
    {
      error_msg = "Expected EOL";
      goto error;
    }

    deletescript(sieved_out, sieve_name);
    
    break;

  case LISTSCRIPTS:

    if (timlex(NULL, NULL, sieved_in)!=EOL)
    {
      error_msg = "Expected EOL";
      goto error;
    }

    listscripts(sieved_out);
    
    break;

  default:
    error_msg="Expected a command. Got something else";
    goto error;
    break;

  }
 
  /* free memory */
  free(mechanism_name);
  free(initial_challenge);
  free(sieve_name);
  free(sieve_data);
 
  prot_flush(sieved_out);

  return 0;

 error:

  /* free memory */
  free(mechanism_name);
  free(initial_challenge);
  free(sieve_name);
  free(sieve_data);


  prot_printf(sieved_out, "NO \"%s\"\r\n",error_msg);
  prot_flush(sieved_out);

  return -1;
}


static int cmd_logout(struct protstream *sieved_out, struct protstream *sieved_in)
{
    prot_printf(sieved_out, "Ok \"Logout Complete\"\r\n");
    prot_flush(sieved_out);
    
    prot_free(sieved_out);
    
    exit(0);    
}

static int cmd_authenticate(struct protstream *sieved_out, struct protstream *sieved_in,
			    mystring_t *mechanism_name, mystring_t *initial_challenge, 
			    const char **errmsg)
{

  int sasl_result;

  char *mech = string_DATAPTR(mechanism_name);

  mystring_t *clientinstr=NULL;
  char *clientin = NULL;
  unsigned int clientinlen = 0;

  char *serverout=NULL;
  unsigned int serveroutlen;
  const char *errstr=NULL;
  char *username;

  clientinstr = initial_challenge;
  if (clientinstr!=NULL)
  {

      clientin=(char *) malloc(clientinstr->len*2);
      
      if (clientinstr->len) {
	  sasl_result=sasl_decode64(string_DATAPTR(clientinstr), 
				    clientinstr->len,
				    clientin, &clientinlen);
      } else {
	  clientinlen = 0;
	  sasl_result = SASL_OK;
      }

      if (sasl_result!=SASL_OK)
      {
	*errmsg="error base64 decoding string";
	syslog(LOG_NOTICE, "badlogin: %s %s %s",
	       sieved_clienthost, mech, "error base64 decoding string");
	return FALSE;
      }
  }

  sasl_result = sasl_server_start(sieved_saslconn, mech,
				  clientin, clientinlen,
				  &serverout, &serveroutlen,
				  &errstr);

  while (sasl_result==SASL_CONTINUE)
  {
    int token1;
    int token2;
    mystring_t *str, *blahstr;
    char *inbase64;
    unsigned int inbase64len;

    /* convert to base64 */
    inbase64 = malloc( serveroutlen*2+1);
    sasl_encode64(serverout, serveroutlen,
		  inbase64, serveroutlen*2+1, &inbase64len);

    /* send out the string always as a literal */
    prot_printf(sieved_out, "{%d}\r\n",inbase64len);
    prot_write(sieved_out,inbase64,inbase64len);
    prot_printf(sieved_out,"\r\n");

    token1 = timlex(&str, NULL, sieved_in);

    if (token1==STRING)
    {
      clientin=(char *) malloc(str->len*2);

      sasl_result=sasl_decode64(string_DATAPTR(str), str->len,
		    clientin, &clientinlen);

      if (sasl_result!=SASL_OK)
      {
	*errmsg="error base64 decoding string";
	syslog(LOG_NOTICE, "badlogin: %s %s %s",
	       sieved_clienthost, mech, "error base64 decoding string");
	return FALSE;
      }      
      
    } else {
      *errmsg="Expected STRING-xxx1";
      return FALSE;
    }

    token2 = timlex(&blahstr, NULL, sieved_in);

    /* we want to see a STRING followed by EOL */
    if ((token1==STRING) && (token2==EOL))
    {
      
      sasl_result = sasl_server_step(sieved_saslconn,
				     clientin,
				     clientinlen,
				     &serverout, &serveroutlen,
				     &errstr);


    } else {
      *errmsg = "expected a STRING followed by an EOL";
      syslog(LOG_NOTICE, "badlogin: %s %s %s",
	     sieved_clienthost, mech, "expected string");
      return FALSE;
    }

  }

  if (sasl_result!=SASL_OK)
  {
      /* convert to user error code */
      sasl_result = sasl_usererr(sasl_result);
      *errmsg = (const char *) sasl_errstring(sasl_result,NULL,NULL);
      if (errstr!=NULL) {
	  syslog(LOG_NOTICE, "badlogin: %s %s %d %s",
		 sieved_clienthost, mech, sasl_result, errstr);
      } else { 
	  syslog(LOG_NOTICE, "badlogin: %s %s %s",
		 sieved_clienthost, mech, 
		 sasl_errstring(sasl_result, NULL, NULL));
      }
      return FALSE;
  }

  /* get the userid from SASL */
  sasl_result=sasl_getprop(sieved_saslconn, SASL_USERNAME,(void **) &username);
  if (sasl_result!=SASL_OK)
  {
    *errmsg = "Internal SASL error";
    syslog(LOG_ERR, "SASL: sasl_getprop SASL_USERNAME: %s",
	   sasl_errstring(sasl_result, NULL, NULL));
    return FALSE;
  }

  if (actions_setuser(username) != TIMSIEVE_OK)
  {
    *errmsg = "internal error";
    syslog(LOG_ERR, "error in actions_setuser()");
    return FALSE;
  }

  /* Yay! authenticated */
  prot_printf(sieved_out, "OK\r\n");
  syslog(LOG_NOTICE, "login: %s %s %s %s", sieved_clienthost, username,
	 mech, "User logged in");

  authenticated = 1;

  /* free memory */

  return TRUE;
}
