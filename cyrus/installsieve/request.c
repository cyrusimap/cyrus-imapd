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

int deleteascript(char *name)
{
  lexstate_t state;

  prot_printf(pout,"DELETESCRIPT \"%s\"\r\n",name);
  prot_flush(pout);  

  if (yylex(&state, pin)!=' ')
    printf("expected xxxxxxx\n");
  
  if (yylex(&state, pin)!=' ')
    printf("expected space\n");

  if (yylex(&state, pin)!=STRING)
    printf("expected string\n");

  if (yylex(&state, pin)!=EOL)
    printf("expected eol\n");

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
  if (yylex(&state,pin)!=STRING)
    printf("expected xxxxxx\n");  

  if (yylex(&state,pin)!=' ')
    printf("expected sp\n");

  if (yylex(&state,pin)!=STRING)
    printf("expected string\n");  

  printf("got status: %s\n",string_DATAPTR(state.str));

  if (yylex(&state,pin)!=EOL)
    printf("expected eol\n");  

  setscriptactive(filename);

  return 0;
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

int viewafile(char *name)
{
  lexstate_t state;

  prot_printf(pout,"GETSCRIPT \"%s\"\r\n",name);
  prot_flush(pout);

  if (yylex(&state,pin)!=STRING)
    printf("expected string\n");

  printf("-----------script (%s)-----\n",name);
  printf("%s\r\n",string_DATAPTR(state.str));
  printf("----------------------------------\n");
  
  return 0;
}

int setscriptactive(char *name)
{
  lexstate_t state;

  /* tell server we want "name" to be the active script */
  prot_printf(pout, "SETACTIVE \"%s\"\r\n",name);
  prot_flush(pout);


  /* now let's see what the server said */
  if (yylex(&state, pin)!=TOKEN_OK)
    printf("expected xxxxxxx\n");
  
  if (yylex(&state, pin)!=' ')
    printf("expected space\n");

  if (yylex(&state, pin)!=STRING)
    printf("expected string\n");

  printf("result= %s\n",string_DATAPTR(state.str));

  if (yylex(&state, pin)!=EOL)
    printf("expected eol\n");

  printf("Set script active \n");

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

int getscript(char *name)
{
  int type;
  lexstate_t state;

  prot_printf(pout,"GETSCRIPT \"%s\"\r\n",name);
  prot_flush(pout);

  type=yylex(&state,pin);

  if (type!=STRING)
  {
    printf("type: %i\n",type);

    yylex(&state,pin); /* space */
    yylex(&state,pin); /* string */

    printf("Error: %s\n",string_DATAPTR(state.str));

    yylex(&state,pin);

    return -1;
  }
 
  writefile(state.str, name);
  
  return 0;
}
