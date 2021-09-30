/* request.c -- request to execute functions on the timsieved server
 * Tim Martin
 * 9/21/99
 */
/*
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

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "xmalloc.h"
#include "perl/sieve/lib/request.h"
#include "perl/sieve/lib/lex.h"

#define BLOCKSIZE 1024

void parseerror(const char *str)
{
  printf("Bad protocol from MANAGESIEVE server: %s\n", str);

  exit(2);
}

int handle_response(int res,int version,struct protstream *pin,
                    char **refer_to, char **errstr)
{
  lexstate_t state;
  int r = 0;

  *refer_to = NULL;

  if (res == -1)
      parseerror("lost connection");

  if ((res!=TOKEN_OK) && (res!=TOKEN_NO) && (res!=TOKEN_BYE))
      parseerror("ATOM");

  if(res == TOKEN_BYE) {
      if (yylex(&state, pin)!=' ')
          parseerror("expected space");

      res = yylex(&state, pin);

      /* additional error response */
      if (res == '(') {
          /* '(' string [SP string] ')' */

          /* we only support the REFERRAL response with BYE */
          if (yylex(&state, pin)==TOKEN_REFERRAL) {
              if (yylex(&state, pin)!=' ')
                  parseerror("expected space");
              if (yylex(&state, pin)!=STRING)
                  parseerror("expected string");

              *refer_to = state.str;

              if (yylex(&state, pin)!=')')
                  parseerror("expected RPAREN");
          } else {
              res = 0;
              while(res != ')' && res != -1) {
                  res = yylex(&state, pin);
              }
              if(res != ')') {
                  parseerror("expected RPAREN");
              }
          }

          res = yylex(&state, pin);
          if (res == ' ') res = yylex(&state, pin);
      }

      if (res != STRING && res != EOL)
          parseerror("expected string2");

      if (errstr)
          *errstr = state.str;

      r = -2;
  } else if (res==TOKEN_NO) {
      if (yylex(&state, pin)!=' ')
          parseerror("expected space");

      res = yylex(&state, pin);

      /* additional error response */
      if (res == '(') {
          /* '(' string [SP string] ')' */

          res = 0;
          while(res != ')' && res != -1) {
              res = yylex(&state, pin);
          }
          if(res != ')') {
              parseerror("expected RPAREN");
          }

          res = yylex(&state, pin);
          if (res == ' ') res = yylex(&state, pin);
      }

      if (res != STRING)
          parseerror("expected string");


      if (errstr)
          *errstr = state.str;

      r = -1;
  } else {
      /* ok */
      int lres;

      /* SASL response */
      lres = yylex(&state, pin);
      if(res == ' ') {
          if (yylex(&state, pin) != '(')
              parseerror("expected LPAREN");

          if (yylex(&state, pin)==TOKEN_SASL) {
              if (yylex(&state, pin)!=' ')
                  parseerror("expected space");
              if (yylex(&state, pin)!=STRING)
                  parseerror("expected string");

              *refer_to = xstrdup(state.str);

              if (yylex(&state, pin)!=')')
                  parseerror("expected RPAREN");
          } else {
              parseerror("unexpected response code with OK response");
          }
      } else if (version != OLD_VERSION && lres == EOL) {
          return r;
      }

      /* old version of protocol had strings with ok responses too */
      if (version == OLD_VERSION) {
          if (lres !=' ')
              parseerror("expected sp");

          if (yylex(&state, pin)!=STRING)
              parseerror("expected string");
      }
  }

  if (yylex(&state, pin)!=EOL)
      parseerror("expected EOL");

  return r;
}

int deleteascript(int version, struct protstream *pout,
                  struct protstream *pin, const char *name,
                  char **refer_to, char **errstrp)
{
  lexstate_t state;
  int res;
  int ret;
  char *errstr = NULL;

  prot_printf(pout,"DELETESCRIPT \"%s\"\r\n",name);
  prot_flush(pout);

  res=yylex(&state, pin);

  ret = handle_response(res,version,pin,refer_to,&errstr);

  if(ret == -2 && *refer_to) {
      return -2;
  } else if (ret!=0) {
      *errstrp = strconcat("Deleting script: ",
                           errstr,
                           (char *)NULL);
      return -1;
  }

  return 0;
}

int installdata(int version,struct protstream *pout, struct protstream *pin,
                char *scriptname, char *data, int len,
                char **refer_to, char **errstrp)
{
  int res;
  int ret;
  char *errstr=NULL;
  lexstate_t state;

  prot_printf(pout, "PUTSCRIPT \"%s\" ",scriptname);

  prot_printf(pout, "{%d+}\r\n",len);

  prot_write(pout, data, len);

  prot_printf(pout,"\r\n");
  prot_flush(pout);

  /* now let's see what the server said */
  res=yylex(&state,pin);

  ret = handle_response(res,version,pin,refer_to,&errstr);

  /* if command failed */
  if(ret == -2 && *refer_to) {
      return -2;
  } else if (ret!=0) {
      *errstrp = strconcat("Putting script: ",
                           errstr,
                           (char *)NULL);
      return -1;
  }

  return 0;
}

static char *getsievename(char *filename)
{
  char *ret, *ptr;

  ret=(char *) xmalloc( strlen(filename) + 2);

  /* just take the basename of the file */
  ptr = strrchr(filename, '/');
  if (ptr == NULL) {
      ptr = filename;
  } else {
      ptr++;
  }

  strcpy(ret, ptr);

  return ret;
}


int installafile(int version,struct protstream *pout, struct protstream *pin,
                 char *filename, char *destname,
                 char **refer_to, char **errstrp)
{
  FILE *stream;
  struct stat filestats;  /* returned by stat */
  int size;     /* size of the file */
  int result;
  int cnt;
  int res;
  int ret;
  char *errstr=NULL;
  lexstate_t state;
  char *sievename;

  if(!destname) destname = filename;

  result=stat(filename,&filestats);

  if (result!=0) {
      *errstrp = xstrdup(strerror(errno));
      return -1;
  }

  size=filestats.st_size;

  stream=fopen(filename, "r");

  if (stream==NULL)
  {
      *errstrp = xstrdup(
        "put script: internal error: couldn't open temporary file");
      return -1;
  }

  sievename=getsievename(destname);

  prot_printf(pout, "PUTSCRIPT \"%s\" ",sievename);

  prot_printf(pout, "{%d+}\r\n",size);

  cnt=0;

  while (cnt < size)
  {
    char buf[BLOCKSIZE];
    int amount=BLOCKSIZE;
    int n;

    if (size-cnt < BLOCKSIZE)
      amount=size-cnt;

    n = fread(buf, 1, BLOCKSIZE, stream);
    if (!n) {
      *errstrp = xstrdup("put script: failed to finish reading");
      fclose(stream);
      free(sievename);
      return -1;
    }

    prot_write(pout, buf, n);

    cnt+=amount;
  }

  prot_printf(pout,"\r\n");
  prot_flush(pout);

  fclose(stream);
  free(sievename);

  /* now let's see what the server said */
  res=yylex(&state,pin);

  ret = handle_response(res,version,pin,refer_to,&errstr);

  /* if command failed */
  if(ret == -2 && *refer_to) {
      return -2;
  } else if (ret!=0) {
      *errstrp = strconcat("put script: ",
                           errstr,
                           (char *)NULL);
      return -1;
  }

  return 0;
}

int list_wcb(int version, struct protstream *pout,
             struct protstream *pin,isieve_listcb_t *cb ,void *rock,
             char **refer_to)
{
  lexstate_t state;
  int end=0;
  int res;
  int ret = 0;

  prot_printf(pout, "LISTSCRIPTS\r\n");
  prot_flush(pout);

  do {

    if ((res=yylex(&state, pin))==STRING)
    {
      char *str=state.str;

      if (yylex(&state, pin)==' ')
      {
          if (yylex(&state, pin)!=TOKEN_ACTIVE)
              printf("Expected ACTIVE\n");
          if (yylex(&state, pin)!=EOL)
              printf("Expected EOL\n");

          cb(str, 1, rock);
      } else {

          /* in old version we had that '*' means active script thing */
          if (version == OLD_VERSION) {

              if (str[strlen(str)-1]=='*') {
                  str[strlen(str)-1]='\0';
                  cb(str, 1, rock);
              } else {
                  cb(str, 0, rock);
              }

          } else { /* NEW_VERSION */
              /* assume it's a EOL */
              cb(str, 0, rock);
          }
      }

    } else {
        ret = handle_response(res,version,pin,refer_to,NULL);

        end=1;
    }
  } while (end==0);

  return ret;
}

int setscriptactive(int version, struct protstream *pout,
                    struct protstream *pin,char *name,
                    char **refer_to, char **errstrp)
{
  lexstate_t state;
  int res;
  int ret;
  char *errstr=NULL;

  /* tell server we want "name" to be the active script */
  prot_printf(pout, "SETACTIVE \"%s\"\r\n",name);
  prot_flush(pout);

  /* now let's see what the server said */
  res=yylex(&state, pin);

  ret = handle_response(res, version, pin, refer_to, &errstr);

  /* if command failed */
  if(ret == -2 && *refer_to) {
      return -2;
  } else if (ret != 0) {
      *errstrp = strconcat("Setting script active: ",
                           errstr,
                           (char *)NULL);
      return -1;
  }
  return 0;
}

int getscriptvalue(int version, struct protstream *pout,
                   struct protstream *pin, char *name, char **data,
                   char **refer_to, char **errstrp)
{
  int res;
  int ret;
  char *errstr=NULL;
  lexstate_t state;

  prot_printf(pout,"GETSCRIPT \"%s\"\r\n",name);
  prot_flush(pout);

  res=yylex(&state,pin);

  if (res==STRING)
  {
    *data=state.str;

    if (yylex(&state, pin)!=EOL)
      parseerror("EOL");

    res=yylex(&state,pin);
  }

  ret = handle_response(res,version,pin, refer_to, &errstr);

  /* if command failed */
  if(ret == -2 && *refer_to) {
      return -2;
  } else if (ret!=0) {
      *errstrp = errstr;
      return -1;
  }

  return 0;

}
