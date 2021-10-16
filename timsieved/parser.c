/* parser.c -- parser used by timsieved
 * Tim Martin
 * 9/21/99
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
#include <stdio.h>
#include <sysexits.h>
#include <syslog.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <string.h>
#include <sasl/sasl.h>
#include <sasl/saslutil.h>

#include "assert.h"
#include "libconfig.h"
#include "xmalloc.h"
#include "xstrlcpy.h"

#include "imap/backend.h"
#include "imap/global.h"
#include "imap/mboxlist.h"
#include "imap/mboxname.h"
#include "imap/telemetry.h"
#include "imap/tls.h"

#include "timsieved/actions.h"
#include "timsieved/codes.h"
#include "timsieved/lex.h"
#include "timsieved/parser.h"

extern const char *sieved_clienthost;
extern int sieved_domainfromip;
extern int sieved_userisadmin;

/* xxx these are both leaked, but we only handle one connection at a
 * time... */
extern sasl_conn_t *sieved_saslconn; /* the sasl connection context */
static const char *referral_host = NULL;

int authenticated = 0;
int verify_only = 0;
int starttls_done = 0;
sasl_ssf_t sasl_ssf = 0;
#ifdef HAVE_SSL
/* our tls connection, if any */
static SSL *tls_conn = NULL;
#endif /* HAVE_SSL */
extern int sieved_timeout;

/* from elsewhere */
void fatal(const char *s, int code) __attribute__((noreturn));
extern int sieved_logfd;
extern struct backend *backend;

/* forward declarations */
static void cmd_logout(struct protstream *sieved_out,
                       struct protstream *sieved_in);
static int cmd_authenticate(struct protstream *sieved_out, struct protstream *sieved_in,
                            const char *mech, const struct buf *initial_challenge, const char **errmsg);
static void cmd_unauthenticate(struct protstream *sieved_out,
                               struct protstream *sieved_in);
static int cmd_starttls(struct protstream *sieved_out,
                        struct protstream *sieved_in,
                        struct saslprops_t *saslprops);

static char *sieve_parsesuccess(char *str, const char **status)
{
    char *success = NULL, *tmp;

    if (!strncmp(str, "OK (", 4) &&
        (tmp = strstr(str+4, "SASL \"")) != NULL) {
        success = tmp+6; /* skip SASL " */
        tmp = strstr(success, "\"");
        if (tmp) *tmp = '\0'; /* clip " */
    }

    if (status) *status = NULL;
    return success;
}

static struct protocol_t sieve_protocol =
{ "sieve", SIEVE_SERVICE_NAME, TYPE_STD,
  { { { 1, "OK" },
      { "CAPABILITY", NULL, "OK", NULL,
        CAPAF_ONE_PER_LINE|CAPAF_QUOTE_WORDS,
        { { "SASL", CAPA_AUTH },
          { "STARTTLS", CAPA_STARTTLS },
          { NULL, 0 } } },
      { "STARTTLS", "OK", "NO", 1 },
      { "AUTHENTICATE", USHRT_MAX, 1, "OK", "NO", NULL, "*",
        &sieve_parsesuccess, AUTO_CAPA_AUTH_SSF },
      { NULL, NULL, NULL },
      { NULL, NULL, NULL },
      { "LOGOUT", NULL, "OK" } } }
};

/* Returns TRUE if we are done */
int parser(struct protstream *sieved_out, struct protstream *sieved_in,
           struct saslprops_t *saslprops)
{
  int token = EOL;
  const char *error_msg = "Generic Error";

  struct buf mechanism_name = BUF_INITIALIZER;
  struct buf initial_challenge = BUF_INITIALIZER;
  struct buf sieve_name = BUF_INITIALIZER;
  struct buf sieve_data = BUF_INITIALIZER;
  unsigned long num;
  int ret = FALSE;

  /* get one token from the lexer */
  while(token == EOL)
      token = timlex(NULL, NULL, sieved_in);

  if (!authenticated && (token > 255) && (token!=AUTHENTICATE) &&
      (token!=LOGOUT) && (token!=CAPABILITY) &&
      (token!=NOOP) && (token!=CHECKSCRIPT) &&
      (!tls_enabled() || (token!=STARTTLS)))
  {
    error_msg = "Authenticate first";
    if (token!=EOL)
      lex_setrecovering();

    goto error;
  }

  if (verify_only && (token > 255) && (token!=CHECKSCRIPT)
    && (token!=PUTSCRIPT) && (token!=LOGOUT))
  {
    error_msg = "Script verification only";
    if (token!=EOL)
      lex_setrecovering();

    goto error;
  }

  switch (token)
  {
  case EOF:
      /* timlex() will return EOF when the remote disconnects badly */
      syslog(LOG_WARNING, "Lost connection to client -- exiting");
      prot_printf(sieved_out, "BYE \"Shutdown TCP timeout\"\r\n");
      ret = TRUE;
      goto done;
      break;

  case AUTHENTICATE:
    if (sieved_tls_required) {
      error_msg = "AUTHENTICATE only available under a layer";
      goto error;
    }
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
    else if (cmd_authenticate(sieved_out, sieved_in, mechanism_name.s,
                              &initial_challenge, &error_msg)==FALSE)
    {
        error_msg = "Authentication Error";
        goto error;
    }

    break;

  case CAPABILITY:
      if (timlex(NULL, NULL, sieved_in)!=EOL)
      {
          error_msg = "Expected EOL";
          goto error;
      }

      if(referral_host)
          goto do_referral;

      capabilities(sieved_out, sieved_saslconn, starttls_done, authenticated,
                   sasl_ssf);
      break;

  case CHECKSCRIPT:
      if (timlex(NULL, NULL, sieved_in)!=SPACE)
      {
          error_msg = "SPACE must occur after CHECKSCRIPT";
          goto error;
      }

      if (timlex(&sieve_data, NULL, sieved_in)!=STRING)
      {
          error_msg = "Expected script content as second parameter";
          goto error;
      }

      if (timlex(NULL, NULL, sieved_in)!=EOL)
      {
        error_msg = "Expected EOL";
        goto error;
      }

      /* f stands for "f"aked name, it could be any valid script name */
      buf_reset(&sieve_name);
      buf_appendcstr(&sieve_name, "f");
      putscript(sieved_out, &sieve_name, &sieve_data, /* verify_only */ 1);
      break;

  case HAVESPACE:
      if (timlex(NULL, NULL, sieved_in)!=SPACE)
      {
          error_msg = "SPACE must occur after HAVESPACE";
          goto error;
      }

      if (timlex(&sieve_name, NULL, sieved_in)!=STRING)
      {
          error_msg = "Did not specify script name";
          goto error;
      }

      if (timlex(NULL, NULL, sieved_in)!=SPACE)
      {
          error_msg = "Expected SPACE after SCRIPTNAME";
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

      cmd_havespace(sieved_out, &sieve_name, num);

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

    getscript(sieved_out, &sieve_name);

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
      error_msg = "Did not specify legal script data length";
      goto error;
    }

    if (timlex(NULL, NULL, sieved_in)!=EOL)
    {
      error_msg = "Expected EOL";
      goto error;
    }

    if(referral_host)
        goto do_referral;

    putscript(sieved_out, &sieve_name, &sieve_data, verify_only);

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

    setactive(sieved_out, &sieve_name);

    break;

  case RENAMESCRIPT:
    if (timlex(NULL, NULL, sieved_in)!=SPACE)
    {
      error_msg = "SPACE must occur after RENAMESCRIPT";
      goto error;
    }

    if (timlex(&sieve_name, NULL, sieved_in)!=STRING)
    {
      error_msg = "Did not specify old script name";
      goto error;
    }

    if (timlex(NULL, NULL, sieved_in)!=SPACE)
    {
      error_msg = "Expected SPACE";
      goto error;
    }

    if (timlex(&sieve_data, NULL, sieved_in)!=STRING)
    {
      error_msg = "Did not specify new script name";
      goto error;
    }

    if (timlex(NULL, NULL, sieved_in)!=EOL)
    {
      error_msg = "Expected EOL";
      goto error;
    }

    if(referral_host)
        goto do_referral;

    renamescript(sieved_out, &sieve_name, &sieve_data);

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

    deletescript(sieved_out, &sieve_name);

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

    /* XXX  discard any input pipelined after STARTTLS */
    prot_flush(sieved_in);

    if(referral_host)
        goto do_referral;

    cmd_starttls(sieved_out, sieved_in, saslprops);

    break;

  case NOOP:

    token = timlex(NULL, NULL, sieved_in);
    if (token != EOL)
    {
      /* optional string parameter */
      if (token!=SPACE)
      {
        error_msg = "Expected SPACE";
        goto error;
      }

      if (timlex(&sieve_name, NULL, sieved_in)!=STRING)
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

    if (sieve_name.len) {
      prot_printf(sieved_out, "OK (TAG ");
      prot_printliteral(sieved_out, sieve_name.s, sieve_name.len);
      prot_printf(sieved_out, ") \"Done\"\r\n");
    } else
      prot_printf(sieved_out, "OK \"Done\"\r\n");
    break;

  case UNAUTHENTICATE:
      if (timlex(NULL, NULL, sieved_in)!=EOL)
      {
          error_msg = "Expected EOL";
          goto error;
      }
      cmd_unauthenticate(sieved_out, sieved_in);
      break;

  default:
    error_msg="Expected a command. Got something else.";
    goto error;
    break;

  }

 done:
  /* free memory */
  buf_free(&mechanism_name);
  buf_free(&initial_challenge);
  buf_free(&sieve_name);
  buf_free(&sieve_data);

  prot_flush(sieved_out);

  return ret;

 error:

  /* free memory */
  buf_free(&mechanism_name);
  buf_free(&initial_challenge);
  buf_free(&sieve_name);
  buf_free(&sieve_data);

  prot_printf(sieved_out, "NO \"%s\"\r\n",error_msg);
  prot_flush(sieved_out);

  return FALSE;

 do_referral:
  {
      char buf[4096];
      char *c;

      /* Truncate the hostname if necessary */
      strlcpy(buf, referral_host, sizeof(buf));
      c = strchr(buf, '!');
      if(c) *c = '\0';

      prot_printf(sieved_out, "BYE (REFERRAL \"sieve://%s\") \"Try Remote.\"\r\n",
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

extern int reset_saslconn(sasl_conn_t **conn);

static void cmd_unauthenticate(struct protstream *sieved_out,
                              struct protstream *sieved_in)
{
    prot_printf(sieved_out, "OK\r\n");
    prot_flush(sieved_out);

    if (chdir("/tmp/"))
        syslog(LOG_ERR, "Failed to chdir to /tmp/");
    reset_saslconn(&sieved_saslconn);
    prot_unsetsasl(sieved_out);
    prot_unsetsasl(sieved_in);
    authenticated = 0;
}

static int cmd_authenticate(struct protstream *sieved_out,
                            struct protstream *sieved_in,
                            const char *mech,
                            const struct buf *initial_challenge,
                            const char **errmsg)
{

  int sasl_result;
  char *clientin = NULL;
  unsigned int clientinlen = 0;

  const char *serverout=NULL;
  unsigned int serveroutlen;
  const void *canon_user, *val;
  char *username = NULL;
  int ret = TRUE;
  mbentry_t *mbentry = NULL;

  assert(initial_challenge);
  if (initial_challenge->s)
  {
      /* a value was provided on the wire, possibly of zero length */
      clientin = xmalloc(initial_challenge->len*2);

      if (initial_challenge->len) {
          sasl_result=sasl_decode64(initial_challenge->s,
                                    initial_challenge->len,
                                    clientin, initial_challenge->len*2,
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
        goto reset;
      }
  }

  sasl_result = sasl_server_start(sieved_saslconn, mech,
                                  clientin, clientinlen,
                                  &serverout, &serveroutlen);

  while (sasl_result==SASL_CONTINUE)
  {
    int token1;
    int token2;
    struct buf str = BUF_INITIALIZER, blahstr = BUF_INITIALIZER;
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
    free(inbase64);

    token1 = timlex(&str, NULL, sieved_in);

    if (token1==STRING)
    {
      free(clientin);
      clientin = xmalloc(str.len*2);

      if (str.len) {
          sasl_result=sasl_decode64(str.s, str.len,
                                    clientin, str.len*2, &clientinlen);
      } else {
          clientinlen = 0;
          sasl_result = SASL_OK;
      }
      buf_free(&str);

      if (sasl_result!=SASL_OK)
      {
        *errmsg="error base64 decoding string";
        syslog(LOG_NOTICE, "badlogin: %s %s %s",
               sieved_clienthost, mech, "error base64 decoding string");
        goto reset;
      }

    } else {
      *errmsg="Expected STRING-xxx1";
      goto reset;
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
      goto reset;
    }

  }

  if (sasl_result!=SASL_OK)
  {
      /* convert to user error code */
      if(sasl_result == SASL_NOUSER)
          sasl_result = SASL_BADAUTH;
      *errmsg = (const char *) sasl_errstring(sasl_result,NULL,NULL);
      syslog(LOG_NOTICE, "badlogin: %s %s %s",
             sieved_clienthost, mech, *errmsg);
      goto reset;
  }

  /* get the userid from SASL */
  sasl_result=sasl_getprop(sieved_saslconn, SASL_USERNAME, &canon_user);
  if (sasl_result!=SASL_OK)
  {
    *errmsg = "Internal SASL error";
    syslog(LOG_ERR, "SASL: sasl_getprop SASL_USERNAME: %s",
           sasl_errstring(sasl_result, NULL, NULL));
    goto reset;
  }
  username = xstrdup((const char *) canon_user);

  verify_only = !strcmp(username, "anonymous");

  if (!verify_only) {
      /* Check for a remote mailbox (should we setup a redirect?) */
      int r;

      char *inbox = mboxname_user_mbox(username, NULL);
      r = mboxlist_lookup(inbox, &mbentry, NULL);
      free(inbox);

      if(r && !sieved_userisadmin) {
          /* lookup error */
          syslog(LOG_ERR, "%s", error_message(r));
          goto reset;
      }

      if (mbentry && mbentry->mbtype & MBTYPE_REMOTE) {
          /* It's a remote mailbox */
          if (config_getswitch(IMAPOPT_SIEVE_ALLOWREFERRALS)) {
              /* We want to set up a referral */
              if (sieved_domainfromip) {
                  char *authname, *p;

                  /* get a new copy of the userid */
                  free(username);
                  username = xstrdup((const char *) canon_user);

                  /* get the authid from SASL */
                  sasl_result=sasl_getprop(sieved_saslconn, SASL_AUTHUSER,
                                           &canon_user);
                  if (sasl_result!=SASL_OK) {
                      *errmsg = "Internal SASL error";
                      syslog(LOG_ERR, "SASL: sasl_getprop SASL_AUTHUSER: %s",
                             sasl_errstring(sasl_result, NULL, NULL));
                      goto reset;
                  }
                  authname = xstrdup((const char *) canon_user);

                  if ((p = strchr(authname, '@'))) *p = '%';
                  if ((p = strchr(username, '@'))) *p = '%';

                  referral_host =
                      (char*) xmalloc(strlen(authname)+1+strlen(username)+1+
                                      strlen(mbentry->server)+1);
                  sprintf((char*) referral_host, "%s;%s@%s",
                          authname, username, mbentry->server);

                  free(authname);
              }
              else
                  referral_host = xstrdup(mbentry->server);
          }
          else {
              /* We want to set up a connection to the backend for proxying */
              const char *statusline = NULL;

              /* get a new copy of the userid */
              free(username);
              username = xstrdup((const char *) canon_user);

              backend = backend_connect(NULL, mbentry->server, &sieve_protocol,
                                        username, NULL, &statusline, -1);

              if (!backend) {
                  syslog(LOG_ERR, "couldn't authenticate to backend server");
                  prot_printf(sieved_out, "NO \"%s\"\r\n",
                              statusline ? statusline :
                              "Authentication to backend server failed");
                  prot_flush(sieved_out);

                  goto cleanup;
              }
          }
      } else if (actions_setuser(username) != TIMSIEVE_OK) {
          *errmsg = "internal error";
          syslog(LOG_ERR, "error in actions_setuser()");
          goto reset;
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

  sasl_getprop(sieved_saslconn, SASL_SSF, &val);
  sasl_ssf = *((sasl_ssf_t *) val);

  if (sasl_ssf &&
      config_getswitch(IMAPOPT_SIEVE_SASL_SEND_UNSOLICITED_CAPABILITY)) {
      capabilities(sieved_out, sieved_saslconn, starttls_done, authenticated,
                   sasl_ssf);
      prot_flush(sieved_out);
  }

  /* Create telemetry log */
  sieved_logfd = telemetry_log(username, sieved_in, sieved_out, 0);

cleanup:
  /* free memory */
  mboxlist_entry_free(&mbentry);
  free(username);
  free(clientin);

  return ret;

reset:
  if(reset_saslconn(&sieved_saslconn) != SASL_OK)
      fatal("could not reset the sasl_conn_t after failure",
            EX_TEMPFAIL);
  ret = FALSE;
  goto cleanup;
}

#ifdef HAVE_SSL
static int cmd_starttls(struct protstream *sieved_out,
                        struct protstream *sieved_in,
                        struct saslprops_t *saslprops)
{
    int result;

    if (starttls_done == 1)
    {
        prot_printf(sieved_out, "NO \"TLS already active\"\r\n");
        return TIMSIEVE_FAIL;
    }

    result=tls_init_serverengine("sieve",
                                 5,        /* depth to verify */
                                 1,        /* can client auth? */
                                 NULL);

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
                               sieved_timeout,
                               saslprops,
                               &tls_conn);

    /* if error */
    if (result==-1) {
        prot_printf(sieved_out, "NO \"Starttls failed\"\r\n");
        syslog(LOG_NOTICE, "STARTTLS failed: %s", sieved_clienthost);
        return TIMSIEVE_FAIL;
    }

    /* tell SASL about the negotiated layer */
    result = saslprops_set_tls(saslprops, sieved_saslconn);

    if (result != SASL_OK) {
        fatal("saslprops_set_tls() failed: cmd_starttls()", EX_TEMPFAIL);
    }

    /* tell the prot layer about our new layers */
    prot_settls(sieved_in, tls_conn);
    prot_settls(sieved_out, tls_conn);

    starttls_done = 1;
    sieved_tls_required = 0;

    return capabilities(sieved_out, sieved_saslconn, starttls_done,
                        authenticated, sasl_ssf);
}
#else
static int cmd_starttls(struct protstream *sieved_out __attribute__((unused)),
                        struct protstream *sieved_in __attribute__((unused)),
                        struct saslprops_t *saslprops __attribute__((unused)))
{
    fatal("cmd_starttls() called, but no OpenSSL", EX_SOFTWARE);
}
#endif /* HAVE_SSL */
