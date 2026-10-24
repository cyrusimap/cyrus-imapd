/* request.c - request to execute functions on the timsieved server */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

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

int parseerror(struct protstream *pin, const char *str, char **errstr)
{
    /* the rest of the response would be misread as the next one */
    pin->cnt = 0;
    pin->eof = 1;
    yylex_reset();

    if (errstr) {
        *errstr = strconcat("Bad protocol from MANAGESIEVE server: ",
                            str, (char *) NULL);
    }
    return -1;
}

#define BAD(s) do { bad = (s); goto fail; } while (0)

int handle_response(int res, int version __attribute__((unused)),
                    struct protstream *pin,
                    char **refer_to, char **errstr)
{
  lexstate_t state;
  const char *bad = NULL;
  char *text = NULL;
  int r = 0;

  *refer_to = NULL;

  if (res == -1)
      BAD("lost connection");

  if ((res!=TOKEN_OK) && (res!=TOKEN_NO) && (res!=TOKEN_BYE))
      BAD("ATOM");

  if(res == TOKEN_BYE) {
      r = -2;
      res = yylex(&state, pin);
      if (res == EOL)
          goto done;
      if (res != ' ')
          BAD("expected space");

      res = yylex(&state, pin);

      /* additional error response */
      if (res == '(') {
          /* '(' string [SP string] ')' */

          /* we only support the REFERRAL response with BYE */
          if (yylex(&state, pin)==TOKEN_REFERRAL) {
              if (yylex(&state, pin)!=' ')
                  BAD("expected space");
              if (yylex(&state, pin)!=STRING)
                  BAD("expected string");

              *refer_to = state.str;

              if (yylex(&state, pin)!=')')
                  BAD("expected RPAREN");
          } else {
              res = 0;
              while(res != ')' && res != -1) {
                  res = yylex(&state, pin);
                  if (res == STRING) free(state.str);
              }
              if(res != ')') {
                  BAD("expected RPAREN");
              }
          }

          res = yylex(&state, pin);
          if (res == ' ') res = yylex(&state, pin);
      }

      if (res == EOL)
          goto done;
      if (res != STRING)
          BAD("expected string2");
      text = state.str;
  } else if (res==TOKEN_NO) {
      r = -1;
      res = yylex(&state, pin);
      if (res == EOL)
          goto done;
      if (res != ' ')
          BAD("expected space");

      res = yylex(&state, pin);

      /* additional error response */
      if (res == '(') {
          /* '(' string [SP string] ')' */

          res = 0;
          while(res != ')' && res != -1) {
              res = yylex(&state, pin);
              if (res == STRING) free(state.str);
          }
          if(res != ')') {
              BAD("expected RPAREN");
          }

          res = yylex(&state, pin);
          if (res == ' ') res = yylex(&state, pin);
      }

      if (res == EOL)
          goto done;
      if (res != STRING)
          BAD("expected string");
      text = state.str;
  } else {
      /* "OK" [SP "(" resp-code ")"] [SP string] */
      res = yylex(&state, pin);
      if (res == ' ') {
          res = yylex(&state, pin);
          if (res == '(') {
              if (yylex(&state, pin) != TOKEN_SASL)
                  BAD("unexpected response code with OK response");
              if (yylex(&state, pin)!=' ')
                  BAD("expected space");
              if (yylex(&state, pin)!=STRING)
                  BAD("expected string");

              *refer_to = state.str;

              if (yylex(&state, pin)!=')')
                  BAD("expected RPAREN");

              res = yylex(&state, pin);
              if (res == ' ') res = yylex(&state, pin);
          }
          if (res == STRING) {
              free(state.str);
              res = yylex(&state, pin);
          }
      }

      if (res != EOL)
          BAD("expected EOL");

      goto done;
  }

  if (yylex(&state, pin)!=EOL)
      BAD("expected EOL");

done:
  if (errstr)
      *errstr = text;
  else
      free(text);
  return r;

fail:
  free(text);
  free(*refer_to);
  *refer_to = NULL;
  return parseerror(pin, bad, errstr);
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
      free(errstr);
      return -2;
  } else if (ret!=0) {
      *errstrp = strconcat("Deleting script: ",
                           errstr,
                           (char *)NULL);
      free(errstr);
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
      free(errstr);
      return -2;
  } else if (ret!=0) {
      *errstrp = strconcat("Putting script: ",
                           errstr,
                           (char *)NULL);
      free(errstr);
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
      free(errstr);
      return -2;
  } else if (ret!=0) {
      *errstrp = strconcat("put script: ",
                           errstr,
                           (char *)NULL);
      free(errstr);
      return -1;
  }

  return 0;
}

int list_wcb(int version, struct protstream *pout,
             struct protstream *pin,isieve_listcb_t *cb ,void *rock,
             char **refer_to, char **errstr)
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
              /* assume it's an EOL */
              cb(str, 0, rock);
          }
      }

    } else {
        ret = handle_response(res,version,pin,refer_to,errstr);

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
      free(errstr);
      return -2;
  } else if (ret != 0) {
      *errstrp = strconcat("Setting script active: ",
                           errstr,
                           (char *)NULL);
      free(errstr);
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

    if (yylex(&state, pin)!=EOL) {
      free(*data);
      *data = NULL;
      return parseerror(pin, "EOL", errstrp);
    }

    res=yylex(&state,pin);
  }

  ret = handle_response(res,version,pin, refer_to, &errstr);

  /* if command failed */
  if(ret == -2 && *refer_to) {
      free(errstr);
      return -2;
  } else if (ret!=0) {
      *errstrp = errstr;
      return -1;
  }

  return 0;

}
