/* request.c -- request to execute functions on the timsieved server
 * Tim Martin
 * 9/21/99
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
 */

/* $Id: request.c,v 1.18 2002/05/25 19:57:47 leg Exp $ */

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <sys/file.h>

#include "request.h"

#include "prot.h"
#include "lex.h"
#include "xmalloc.h"

#define BLOCKSIZE 1024

void parseerror(char *str)
{
  printf("Parse error:\n");

  printf("client expected %s\n",str);
  printf("exiting\n");

  exit(2);
}

int handle_response(int res,int version,struct protstream *pin, mystring_t **errstr)
{    
  lexstate_t state;

  if ((res!=TOKEN_OK) && (res!=TOKEN_NO))
    parseerror("ATOM");

  if (res==TOKEN_NO) {

      if (yylex(&state, pin)!=' ')
	  parseerror("expected space\n");

      res = yylex(&state, pin);

      /* additional error response */
      if (res == '(') {
	  /* '(' string [SP string] ')' */
	  
	  if (yylex(&state, pin)!=STRING)
	      parseerror("expected string\n");

	  if (strcmp(string_DATAPTR(state.str),"SASL")==0) {
	      if (yylex(&state, pin)!=' ')
		  parseerror("expected space\n");
	      if (yylex(&state, pin)!=STRING)
		  parseerror("expected string\n");
	  }

	  if (yylex(&state, pin)!=')')
	      parseerror("expected RPAREN\n");

	  res = yylex(&state, pin);
      }

      if (res !=' ')
	  parseerror("expected sp\n");
      
      if (yylex(&state, pin)!=STRING)
	  parseerror("expected string\n");
      

      if (errstr)
	  *errstr = state.str;

      return -1;
  }
  
  /* old version of protocol had strings with ok responses too */
  if (version == OLD_VERSION) {
      if (yylex(&state, pin)!=' ')
	  parseerror("expected sp\n");
      
      if (yylex(&state, pin)!=STRING)
	  parseerror("expected string\n");
  }
  
  if (yylex(&state, pin)!=EOL)
      parseerror("expected string\n");
  
  return 0;
}

int deleteascript(int version, struct protstream *pout, struct protstream *pin,char *name)
{
  lexstate_t state;
  int res;
  int ret;
  mystring_t *errstr;

  prot_printf(pout,"DELETESCRIPT \"%s\"\r\n",name);
  prot_flush(pout);  

  res=yylex(&state, pin);

  ret = handle_response(res,version,pin,&errstr);

  if (ret!=0)
  {
    printf("Deletescript error: %s\n",string_DATAPTR(errstr));
    return -1;
  }

  printf("Script %s deleted successfully\n",name);
  return 0;
}

int installdata(int version,struct protstream *pout, struct protstream *pin,
		char *scriptname, char *data, int len)
{
  int res;
  int ret;
  mystring_t *errstr=NULL;
  lexstate_t state;

  prot_printf(pout, "PUTSCRIPT \"%s\" ",scriptname);

  prot_printf(pout, "{%d+}\r\n",len);

  prot_write(pout, data, len);

  prot_printf(pout,"\r\n");
  prot_flush(pout);

  /* now let's see what the server said */
  res=yylex(&state,pin);

  ret = handle_response(res,version,pin,&errstr);

  /* if command failed */
  if (ret!=0)
  {
    printf("Putting script failed with message: %s\n",string_DATAPTR(errstr));
    
    return -1;
  }

  return setscriptactive(version,pout,pin,scriptname);
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

  if ( strcmp( ret + strlen(ret) - 7,".script")==0)
  {
    ret[ strlen(ret) - 7] = '\0';
  }

  return ret;
}


int installafile(int version,struct protstream *pout, struct protstream *pin,char *filename)
{
  FILE *stream;
  struct stat filestats;  /* returned by stat */
  int size;     /* size of the file */
  int result;
  int cnt;
  int res;
  int ret;
  mystring_t *errstr=NULL;
  lexstate_t state;
  char *sievename;

  sievename=getsievename(filename);

  result=stat(filename,&filestats);

  if (result!=0)
  {
    perror("stat");
    return -1;
  }

  size=filestats.st_size;

  stream=fopen(filename, "r");

  if (stream==NULL)
  {
    printf("Couldn't open file\n");
    return -1;
  }

  prot_printf(pout, "PUTSCRIPT \"%s\" ",sievename);

  prot_printf(pout, "{%d+}\r\n",size);

  cnt=0;

  while (cnt < size)
  {
    char buf[BLOCKSIZE];
    int amount=BLOCKSIZE;

    if (size-cnt < BLOCKSIZE)
      amount=size-cnt;

    fread(buf, 1, BLOCKSIZE, stream);
    
    prot_write(pout, buf, amount);

    cnt+=amount;
  }

  prot_printf(pout,"\r\n");
  prot_flush(pout);

  /* now let's see what the server said */
  res=yylex(&state,pin);

  ret = handle_response(res,version,pin,&errstr);

  /* if command failed */
  if (ret!=0)
  {
    printf("Putting script failed with message: %s\n",string_DATAPTR(errstr));    
    return -1;
  }

  return setscriptactive(version,pout,pin,sievename);
}



int showlist(int version, struct protstream *pout, struct protstream *pin)
{
  lexstate_t state;
  int end=0;
  int res;
  int ret = 0;

  printf("You have the following scripts on the server:\n");

  prot_printf(pout, "LISTSCRIPTS\r\n");
  prot_flush(pout);

  do {

    if ((res=yylex(&state, pin))==STRING)
    {
      char *str=string_DATAPTR(state.str);

      if (yylex(&state, pin)==' ')
      {
	  if (yylex(&state, pin)!=TOKEN_ACTIVE)
	      printf("Expected ACTIVE\n");
	  if (yylex(&state, pin)!=EOL)
	      printf("Expected EOL\n");

	  printf("  %s  <- Active Sieve Script\n",str);	  
      } else {

	  /* in old version we had that '*' means active script thing */
	  if (version == OLD_VERSION) {

	      if (str[strlen(str)-1]=='*') {
		  str[strlen(str)-1]='\0';
		  printf("  %s  <- Active Sieve Script\n",str);	  
	      } else {
		  printf("  %s\n",str);	  	  
	      }

	  } else { /* NEW_VERSION */
	      /* assume it's a EOL */
	      printf("  %s\n",str);	  	  
	  }
      }

    } else {

	ret = handle_response(res,version,pin,NULL);
	
	end=1;
    }


    
  } while (end==0);

  return ret;
}

int list_wcb(int version, struct protstream *pout, struct protstream *pin,isieve_listcb_t *cb ,void *rock)
{
  lexstate_t state;
  int end=0;
  int res;
  int ret = 0;

  printf("You have the following scripts on the server:\n");

  prot_printf(pout, "LISTSCRIPTS\r\n");
  prot_flush(pout);

  do {

    if ((res=yylex(&state, pin))==STRING)
    {
      char *str=string_DATAPTR(state.str);

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

	ret = handle_response(res,version,pin,NULL);
	
	end=1;
    }


    
  } while (end==0);

  return ret;
}

int setscriptactive(int version, struct protstream *pout, struct protstream *pin,char *name)
{
  lexstate_t state;
  int res;
  int ret;
  mystring_t *errstr=NULL;

  /* tell server we want "name" to be the active script */
  prot_printf(pout, "SETACTIVE \"%s\"\r\n",name);
  prot_flush(pout);


  /* now let's see what the server said */
  res=yylex(&state, pin);

  ret = handle_response(res,version,pin, &errstr);

  /* if command failed */
  if (ret!=0)
  {
    if (!strlen(name))
      printf("Disabling active script failed with message: %s\n", string_DATAPTR(errstr));
    else
      printf("Setting script %s active failed with message: %s\n",name, string_DATAPTR(errstr));
    return -1;
  }

  return 0;
}

static int viewafile(mystring_t *data, char *name)
{
  printf("%s\r\n", string_DATAPTR(data));

  return 0;
}

static int writefile(mystring_t *data, char *name)
{
  FILE *stream;

  char *scrname;

  scrname=malloc(strlen(name)+10);
  strcpy(scrname, name);
  strcat(scrname, ".script");

  stream=fopen(scrname,"w");

  if (stream==NULL)
  {
    printf("Unable to open %s for writing\n",name);
    return -1;
  }

  fwrite(string_DATAPTR(data), 1, data->len, stream);

  fclose(stream);

  return 0;
}

int getscript(int version, struct protstream *pout, 
	      struct protstream *pin,char *name, int save)
{
  int res;
  mystring_t *str=NULL;
  mystring_t *errstr=NULL;
  lexstate_t state;
  int ret = 0;

  prot_printf(pout,"GETSCRIPT \"%s\"\r\n",name);
  prot_flush(pout);

  res=yylex(&state,pin);

  if (res==STRING)
  {

    if (save==1)
      writefile(state.str, name);
    else
      viewafile(state.str, name);

    if (yylex(&state, pin)!=EOL)
      parseerror("EOL");

    res=yylex(&state,pin);
  }

  ret = handle_response(res,version,pin, &errstr);

  /* if command failed */
  if (ret!=0)
  {
    printf("Getting script %s active failed with message: %s\n",name, string_DATAPTR(str));
  }

  return ret;

}


int getscriptvalue(int version, struct protstream *pout, 
		   struct protstream *pin,char *name, mystring_t **data)
{
  int res;
  int ret;
  mystring_t *errstr=NULL;
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

  ret = handle_response(res,version,pin, &errstr);

  /* if command failed */
  if (ret!=0)
  {
    printf("Getting script %s active failed with message: %s\n",name, string_DATAPTR(errstr));
    return -1;
  }

  return 0;

}
