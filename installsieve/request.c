/* request.c -- request to execute functions on the timsieved server
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


#define BLOCKSIZE 1024

extern struct protstream *pout, *pin;


void parseerror(char *str)
{
  printf("Parse error:\n");

  printf("client expected %s\n",str);
  printf("exiting\n");

  exit(2);
}

int deleteascript(char *name)
{
  lexstate_t state;
  int res;

  prot_printf(pout,"DELETESCRIPT \"%s\"\r\n",name);
  prot_flush(pout);  

  res=yylex(&state, pin);

  if ((res!=TOKEN_OK) && (res!=TOKEN_NO)) {
    parseerror("OK | NO");
  }


  if (yylex(&state, pin)!=' ')
    parseerror("SPACE");

  if (yylex(&state, pin)!=STRING)
    parseerror("STRING");

  if (res==TOKEN_NO)
  {
    printf("Deletescript error: %s\n",string_DATAPTR(state.str));

    if (yylex(&state, pin)!=EOL)
      parseerror("EOL");

    return -1;
  }

  if (yylex(&state, pin)!=EOL)
      parseerror("EOL");

  printf("Script %s deleted successfully\n",name);

  return 0;
}

int installafile(char *filename)
{
  FILE *stream;
  struct stat filestats;  /* returned by stat */
  int size;     /* size of the file */
  int result;
  int cnt;
  int res;
  string_t *str;
  lexstate_t state;

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

  prot_printf(pout, "PUTSCRIPT \"%s\" ",filename);


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

  if ((res!=TOKEN_OK) && (res!=TOKEN_NO))    
    parseerror("STRING");

  if (yylex(&state,pin)!=' ')
    parseerror("SPACE");

  if (yylex(&state,pin)!=STRING)
    parseerror("STRING");

  str=state.str;

  if (yylex(&state,pin)!=EOL)
    parseerror("EOL");

  /* if command failed */
  if (res==TOKEN_NO)
  {
    printf("Putting script failed with message: %s\n",string_DATAPTR(str));
    
    return -1;
  }

  return setscriptactive(filename);
}



int showlist(void)
{
  lexstate_t state;
  int end=0;

  printf("You have the following scripts on the server:\n");

  prot_printf(pout, "LISTSCRIPTS\r\n");
  prot_flush(pout);

  do {

    if (yylex(&state, pin)==STRING)
    {
      char *str=string_DATAPTR(state.str);

      /* see if it has a '*' as the last character (i.e. is active script ) */
      if (str[state.str->len -1]=='*')
      {
	str[(state.str->len)-1]='\0';
	printf("  %s  <- Active Sieve Script\n",string_DATAPTR(state.str));
      } else {
	printf("  %s\n",string_DATAPTR(state.str));
      }

    } else {

      if (yylex(&state, pin)!=' ')
	printf("expected sp\n");

      if (yylex(&state, pin)!=STRING)
	printf("expected string\n");

      end=1;
    }

    if (yylex(&state, pin)!=EOL)
      printf("expected eol\n");
    
  } while (end==0);


  return 0;
}



int setscriptactive(char *name)
{
  lexstate_t state;
  int res;
  string_t *str;

  /* tell server we want "name" to be the active script */
  prot_printf(pout, "SETACTIVE \"%s\"\r\n",name);
  prot_flush(pout);


  /* now let's see what the server said */
  res=yylex(&state, pin);

  if ((res!=TOKEN_OK) && (res!=TOKEN_NO))
    parseerror("TOKEN");
  
  if (yylex(&state, pin)!=' ')
    parseerror("SPACE");

  if (yylex(&state, pin)!=STRING)
    parseerror("STRING");

  str=state.str;

  if (yylex(&state, pin)!=EOL)
    parseerror("EOL");

  /* if command failed */
  if (res==TOKEN_NO)
  {
    printf("Setting script %s active failed with message: %s\n",name, string_DATAPTR(str));
    return -1;
  }

  return 0;
}

static int viewafile(string_t *data, char *name)
{
  printf("-----------script (%s)-----\n",name);
  printf("%s\r\n",string_DATAPTR(data));
  printf("----------------------------------\n");
  
  return 0;
}

static int writefile(string_t *data, char *name)
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

int getscript(char *name, int save)
{
  int res;
  string_t *str;
  lexstate_t state;

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

  if ((res!=TOKEN_OK) && (res!=TOKEN_NO))
    parseerror("TOKEN");
  
  if (yylex(&state, pin)!=' ')
    parseerror("SPACE");

  if (yylex(&state, pin)!=STRING)
    parseerror("STRING");

  str=state.str;

  if (yylex(&state, pin)!=EOL)
    parseerror("EOL");

  /* if command failed */
  if (res==TOKEN_NO)
  {
    printf("Getting script %s active failed with message: %s\n",name, string_DATAPTR(str));
    return -1;
  }

  return 0;

}
