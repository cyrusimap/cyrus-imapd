/* parser.c -- parser used by timsieved
 * Tim Martin
 * 9/21/99
 * $Id: parser.c,v 1.20.4.8 2003/02/05 21:01:11 ken3 Exp $
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
#include <sasl/sasl.h>
#include <sasl/saslutil.h>

#include "imapconf.h"
#include "com_err.h"
#include "auth.h"
#include "mboxname.h"
#include "mboxlist.h"
#include "xmalloc.h"
#include "prot.h"
#include "tls.h"
#include "lex.h"
#include "actions.h"
#include "exitcodes.h"
#include "telemetry.h"

extern char sieved_clienthost[250];
extern int sieved_domainfromip;

/* xxx these are both leaked, but we only handle one connection at a
 * time... */
extern sasl_conn_t *sieved_saslconn; /* the sasl connection context */
const char *referral_host = NULL;

int authenticated = 0;
int verify_only = 0;
int starttls_done = 0;
#ifdef HAVE_SSL
/* our tls connection, if any */
static SSL *tls_conn = NULL;
#endif /* HAVE_SSL */

/* from elsewhere */
void fatal(const char *s, int code);
extern int sieved_logfd;

/* forward declarations */
static void cmd_logout(struct protstream *sieved_out,
		       struct protstream *sieved_in);
static int cmd_authenticate(struct protstream *sieved_out, struct protstream *sieved_in,
			    mystring_t *mechanism_name, mystring_t *initial_challenge, const char **errmsg);
static int cmd_starttls(struct protstream *sieved_out, struct protstream *sieved_in);

/* Returns TRUE if we are done */
int parser(struct protstream *sieved_out, struct protstream *sieved_in)
{
  int token = EOL;
  const char *error_msg = "Generic Error";

  mystring_t *mechanism_name = NULL;
  mystring_t *initial_challenge = NULL;
  mystring_t *sieve_name = NULL;
  mystring_t *sieve_data = NULL;
  unsigned long num;
  int ret = FALSE;

  /* get one token from the lexer */
  while(token == EOL) 
      token = timlex(NULL, NULL, sieved_in);

  if (!authenticated && (token > 255) && (token!=AUTHENTICATE) &&
      (token!=LOGOUT) && (token!=CAPABILITY) &&
      (!tls_enabled() || (token!=STARTTLS)))
  {
    error_msg = "Authenticate first";
    if (token!=EOL)
      lex_setrecovering();

    goto error;
  }

  if (verify_only && (token > 255) && (token!=PUTSCRIPT) && (token!=LOGOUT))
  {
    error_msg = "Script verification only";
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

    if (authenticated)
	prot_printf(sieved_out, "NO \"Already authenticated\"\r\n");
    else if (cmd_authenticate(sieved_out, sieved_in, mechanism_name,
			      initial_challenge, &error_msg)==FALSE)
    {
	error_msg = "Authentication Error";
	goto error;
    }

#if 0 /* XXX - not implemented in sieveshell*/
    /* referral_host is non-null only once we are authenticated */
    if(referral_host)
	goto do_referral;
#endif
    break;

  case CAPABILITY:
      if (timlex(NULL, NULL, sieved_in)!=EOL)
      {
	  error_msg = "Expected EOL";
	  goto error;
      }

      if(referral_host)
	  goto do_referral;

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

      if(referral_host)
	  goto do_referral;

      cmd_havespace(sieved_out, sieve_name, num);

      break;

  case LOGOUT:
      token = timlex(NULL, NULL, sieved_in);
      
      /* timlex() will return LOGOUT when the remote disconnects badly */
      if (token!=EOL && token!=EOF && token!=LOGOUT)
      {
	  error_msg = "Garbage after logout command";
	  goto error;
      }

      /* no referral for logout */

      cmd_logout(sieved_out, sieved_in);
      
      ret = TRUE;
      goto done;
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

    if(referral_host)
	goto do_referral;

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

    if(referral_host)
	goto do_referral;

    putscript(sieved_out, sieve_name, sieve_data, verify_only);
    
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

    if(referral_host)
	goto do_referral;

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

    if(referral_host)
	goto do_referral;

    deletescript(sieved_out, sieve_name);
    
    break;

  case LISTSCRIPTS:

    if (timlex(NULL, NULL, sieved_in)!=EOL)
    {
      error_msg = "Expected EOL";
      goto error;
    }

    if(referral_host)
	goto do_referral;
    
    listscripts(sieved_out);
    
    break;

  case STARTTLS:

    if (timlex(NULL, NULL, sieved_in)!=EOL)
    {
      error_msg = "Expected EOL";
      goto error;
    }

    if(referral_host)
	goto do_referral;

    cmd_starttls(sieved_out, sieved_in);
    
    break;

  default:
    error_msg="Expected a command. Got something else.";
    goto error;
    break;

  }

 done: 
  /* free memory */
  free(mechanism_name);
  free(initial_challenge);
  free(sieve_name);
  free(sieve_data);
 
  prot_flush(sieved_out);

  return ret;

 error:

  /* free memory */
  free(mechanism_name);
  free(initial_challenge);
  free(sieve_name);
  free(sieve_data);

  prot_printf(sieved_out, "NO \"%s\"\r\n",error_msg);
  prot_flush(sieved_out);

  return FALSE;

 do_referral:
  {
      char buf[4096];
      char *c;

      /* Truncate the hostname if necessary */
      strcpy(buf, referral_host);
      c = strchr(buf, '!');
      if(c) *c = '\0';
      
      prot_printf(sieved_out, "BYE (REFERRAL \"%s\") \"Try Remote.\"\r\n",
		  buf);
      ret = TRUE;
      goto done;
  }

}


void cmd_logout(struct protstream *sieved_out,
		struct protstream *sieved_in __attribute__((unused)))
{
    prot_printf(sieved_out, "OK \"Logout Complete\"\r\n");
    prot_flush(sieved_out);
}

static sasl_ssf_t ssf = 0;
static char *authid = NULL;

extern int reset_saslconn(sasl_conn_t **conn, sasl_ssf_t ssf, char *authid);

static int cmd_authenticate(struct protstream *sieved_out,
			    struct protstream *sieved_in,
			    mystring_t *mechanism_name,
			    mystring_t *initial_challenge, 
			    const char **errmsg)
{

  int sasl_result;

  char *mech = string_DATAPTR(mechanism_name);

  mystring_t *clientinstr=NULL;
  char *clientin = NULL;
  unsigned int clientinlen = 0;

  const char *serverout=NULL;
  unsigned int serveroutlen;
  const char *errstr=NULL;
  const char *canon_user;
  char *username;
  int ret = TRUE;

  clientinstr = initial_challenge;
  if (clientinstr!=NULL)
  {
      clientin=(char *) malloc(clientinstr->len*2);
      
      if (clientinstr->len) {
	  sasl_result=sasl_decode64(string_DATAPTR(clientinstr), 
				    clientinstr->len,
				    clientin, clientinstr->len*2,
				    &clientinlen);
      } else {
	  clientinlen = 0;
	  sasl_result = SASL_OK;
      }

      if (sasl_result!=SASL_OK)
      {
	*errmsg="error base64 decoding string";
	syslog(LOG_NOTICE, "badlogin: %s %s %s",
	       sieved_clienthost, mech, "error base64 decoding string");

      if(reset_saslconn(&sieved_saslconn, ssf, authid) != SASL_OK)
	  fatal("could not reset the sasl_conn_t after failure",
		EC_TEMPFAIL);

	return FALSE;
      }
  }

  sasl_result = sasl_server_start(sieved_saslconn, mech,
				  clientin, clientinlen,
				  &serverout, &serveroutlen);

  while (sasl_result==SASL_CONTINUE)
  {
    int token1;
    int token2;
    mystring_t *str, *blahstr;
    char *inbase64;
    unsigned int inbase64len;

    /* convert to base64 */
    inbase64 = xmalloc(serveroutlen*2+1);
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
				clientin, str->len*2, &clientinlen);

      if (sasl_result!=SASL_OK)
      {
	*errmsg="error base64 decoding string";
	syslog(LOG_NOTICE, "badlogin: %s %s %s",
	       sieved_clienthost, mech, "error base64 decoding string");

      if(reset_saslconn(&sieved_saslconn, ssf, authid) != SASL_OK)
	  fatal("could not reset the sasl_conn_t after failure",
		EC_TEMPFAIL);

	return FALSE;
      }      
      
    } else {
      *errmsg="Expected STRING-xxx1";

      if(reset_saslconn(&sieved_saslconn, ssf, authid) != SASL_OK)
	  fatal("could not reset the sasl_conn_t after failure",
		EC_TEMPFAIL);

      return FALSE;
    }

    token2 = timlex(&blahstr, NULL, sieved_in);

    /* we want to see a STRING followed by EOL */
    if ((token1==STRING) && (token2==EOL))
    {
      sasl_result = sasl_server_step(sieved_saslconn,
				     clientin,
				     clientinlen,
				     &serverout, &serveroutlen);
    } else {
      *errmsg = "expected a STRING followed by an EOL";
      syslog(LOG_NOTICE, "badlogin: %s %s %s",
	     sieved_clienthost, mech, "expected string");

      if(reset_saslconn(&sieved_saslconn, ssf, authid) != SASL_OK)
	  fatal("could not reset the sasl_conn_t after failure",
		EC_TEMPFAIL);

      return FALSE;
    }

  }

  if (sasl_result!=SASL_OK)
  {
      /* convert to user error code */
      if(sasl_result == SASL_NOUSER)
	  sasl_result = SASL_BADAUTH;
      *errmsg = (const char *) sasl_errstring(sasl_result,NULL,NULL);
      if (errstr!=NULL) {
	  syslog(LOG_NOTICE, "badlogin: %s %s %d %s",
		 sieved_clienthost, mech, sasl_result, errstr);
      } else { 
	  syslog(LOG_NOTICE, "badlogin: %s %s %s",
		 sieved_clienthost, mech, 
		 sasl_errstring(sasl_result, NULL, NULL));
      }

      if(reset_saslconn(&sieved_saslconn, ssf, authid) != SASL_OK)
	  fatal("could not reset the sasl_conn_t after failure",
		EC_TEMPFAIL);

      return FALSE;
  }

  /* get the userid from SASL */
  sasl_result=sasl_getprop(sieved_saslconn, SASL_USERNAME,
			   (const void **) &canon_user);
  if (sasl_result!=SASL_OK)
  {
    *errmsg = "Internal SASL error";
    syslog(LOG_ERR, "SASL: sasl_getprop SASL_USERNAME: %s",
	   sasl_errstring(sasl_result, NULL, NULL));

    if(reset_saslconn(&sieved_saslconn, ssf, authid) != SASL_OK)
	fatal("could not reset the sasl_conn_t after failure",
	      EC_TEMPFAIL);

    return FALSE;
  }
  username = xstrdup(canon_user);

  verify_only = !strcmp(username, "anonymous");

  if (!verify_only) {
      /* Check for a remote mailbox (should we setup a redirect?) */
      struct namespace sieved_namespace;
      char inboxname[MAX_MAILBOX_NAME];
      char *server;
      int type, r;
      
      /* Set namespace */
      if ((r = mboxname_init_namespace(&sieved_namespace, 0)) != 0) {
	  syslog(LOG_ERR, error_message(r));
	  fatal(error_message(r), EC_CONFIG);
      }

      /* Translate any separators in userid */
      mboxname_hiersep_tointernal(&sieved_namespace, username,
				  config_virtdomains ?
				  strcspn(username, "@") : 0);

      (*sieved_namespace.mboxname_tointernal)(&sieved_namespace, "INBOX",
					     username, inboxname);

      r = mboxlist_detail(inboxname, &type, &server, NULL, NULL, NULL);
      
      if(r) {
	  /* mboxlist_detail error */
	  *errmsg = "mailbox unknown";
	  return FALSE;
      }

      if(type & MBTYPE_REMOTE) {
	  /* It's a remote mailbox, we want to set up a referral */
	  if (sieved_domainfromip) {
	      char *authname, *p;

	      /* get a new copy of the userid */
	      free(username);
	      username = xstrdup(canon_user);

	      /* get the authid from SASL */
	      sasl_result=sasl_getprop(sieved_saslconn, SASL_AUTHUSER,
				       (const void **) &canon_user);
	      if (sasl_result!=SASL_OK)
		  {
		      *errmsg = "Internal SASL error";
		      syslog(LOG_ERR, "SASL: sasl_getprop SASL_AUTHUSER: %s",
			     sasl_errstring(sasl_result, NULL, NULL));

		      if(reset_saslconn(&sieved_saslconn, ssf, authid) != SASL_OK)
			  fatal("could not reset the sasl_conn_t after failure",
				EC_TEMPFAIL);

		      ret = FALSE;
		      goto cleanup;
		  }
	      authname = xstrdup(canon_user);

	      if ((p = strchr(authname, '@'))) *p = '%';
	      if ((p = strchr(username, '@'))) *p = '%';

	      referral_host =
		  (char*) xmalloc(strlen(authname)+1+strlen(username)+1+
				  strlen(server)+1);
	      sprintf((char*) referral_host, "%s;%s@%s",
		      authname, username, server);

	      free(authname);
	  }
	  else
	      referral_host = xstrdup(server);
      } else if (actions_setuser(username) != TIMSIEVE_OK) {
	  *errmsg = "internal error";
	  syslog(LOG_ERR, "error in actions_setuser()");

	  if(reset_saslconn(&sieved_saslconn, ssf, authid) != SASL_OK)
	      fatal("could not reset the sasl_conn_t after failure",
		    EC_TEMPFAIL);

	  ret = FALSE;
	  goto cleanup;
      }
  }

  /* Yay! authenticated */
  if(serverout) {
      char *inbase64;
      unsigned int inbase64len;

      /* convert to base64 */
      inbase64 = xmalloc(serveroutlen*2+1);
      sasl_encode64(serverout, serveroutlen,
		    inbase64, serveroutlen*2+1, &inbase64len);

      prot_printf(sieved_out, "OK (SASL \"%s\")\r\n", inbase64);
      free(inbase64);
  } else {
      prot_printf(sieved_out, "OK\r\n");
  }
  
  syslog(LOG_NOTICE, "login: %s %s %s%s %s", sieved_clienthost, username,
	 mech, starttls_done ? "+TLS" : "", "User logged in");

  authenticated = 1;

  prot_setsasl(sieved_in, sieved_saslconn);
  prot_setsasl(sieved_out, sieved_saslconn);

  /* Create telemetry log */
  sieved_logfd = telemetry_log(username, sieved_in, sieved_out);
  
  cleanup:
  /* free memory */
  free(username);

  return ret;
}

#ifdef HAVE_SSL
static int cmd_starttls(struct protstream *sieved_out, struct protstream *sieved_in)
{
    int result;
    int *layerp;

    /* SASL and openssl have different ideas about whether ssf is signed */
    layerp = (int *) &ssf;

    if (starttls_done == 1)
    {
	prot_printf(sieved_out, "NO \"TLS already active\"\r\n");
	return TIMSIEVE_FAIL;
    }

    result=tls_init_serverengine("sieve",
				 5,        /* depth to verify */
				 1,        /* can client auth? */
				 1);       /* TLS only? */

    if (result == -1) {

	syslog(LOG_ERR, "error initializing TLS");

	prot_printf(sieved_out, "NO \"Error initializing TLS\"\r\n");

	return TIMSIEVE_FAIL;
    }

    prot_printf(sieved_out, "OK \"Begin TLS negotiation now\"\r\n");
    /* must flush our buffers before starting tls */
    prot_flush(sieved_out);

    result=tls_start_servertls(0, /* read */
			       1, /* write */
			       layerp,
			       &authid,
			       &tls_conn);

    /* if error */
    if (result==-1) {
	prot_printf(sieved_out, "NO \"Starttls failed\"\r\n");
	syslog(LOG_NOTICE, "STARTTLS failed: %s", sieved_clienthost);
	return TIMSIEVE_FAIL;
    }

    /* tell SASL about the negotiated layer */
    result = sasl_setprop(sieved_saslconn, SASL_SSF_EXTERNAL, &ssf);

    if (result != SASL_OK) {
        fatal("sasl_setprop() failed: cmd_starttls()", EC_TEMPFAIL);
    }
            
    result = sasl_setprop(sieved_saslconn, SASL_AUTH_EXTERNAL, authid);

    if (result != SASL_OK) {
	fatal("sasl_setprop() failed: cmd_starttls()", EC_TEMPFAIL);
    }

    /* tell the prot layer about our new layers */
    prot_settls(sieved_in, tls_conn);
    prot_settls(sieved_out, tls_conn);

    starttls_done = 1;

    return result;
}
#else
static int cmd_starttls(struct protstream *sieved_out, struct protstream *sieved_in)
{
    fatal("cmd_starttls() called, but no OpenSSL", EC_SOFTWARE);
}
#endif /* HAVE_SSL */
