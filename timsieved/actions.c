/* actions.c -- executes the commands (creating, deleting scripts etc..) for timsieved
 * Tim Martin
 * 
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
#include <sys/stat.h>
#include <errno.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <limits.h>
#include <sys/param.h>

#include <dirent.h>
#include "codes.h"

#include "actions.h"

#include "prot.h"

#include "scripttest.h"

#include "config.h"

#include "xmalloc.h"

char *sieve_dir = NULL;

int actions_init(void)
{
  int sieve_usehomedir = 0;

  sieve_usehomedir = config_getswitch("sieveusehomedir", 0);
  
  if (!sieve_usehomedir) {
    sieve_dir = (char *) config_getstring("sievedir", "/usr/sieve");
    

  } else {
    /* can't use home directories with timsieved */
    return TIMSIEVE_FAIL;
  }
  
  return TIMSIEVE_OK;
}


int actions_setuser(char *userid)
{
  char *buf;
  char hash;
  char *foo=sieve_dir;
  struct stat filestats;  /* returned by stat */
  int result;  


  sieve_dir=(char *) xmalloc(1024);
  
  hash = (char) tolower((int) *userid);
  if (!islower(hash)) { hash = 'q'; }
    
  snprintf(sieve_dir, 1023, "%s/%c/", foo, hash);

  /* see if we need to create the /%c/ directory */
  result=stat(sieve_dir,&filestats);

  if (result!=0)
  {
    result=mkdir(sieve_dir, 0755);
    if (result!=0)
      return TIMSIEVE_FAIL;
  }

  snprintf(sieve_dir, 1023, "%s/%c/%s/", foo, hash,userid);

  /* see if we need to create the /%c/<user>/ directory */
  result=stat(sieve_dir,&filestats);

  if (result!=0)
  {
    result=mkdir(sieve_dir, 0755);
    if (result!=0)
      return TIMSIEVE_FAIL;
  }

  return TIMSIEVE_OK;
}


static char *getsievepath(void)
{
  return sieve_dir;
}

static char *getpath(char *name)
{
  char *buf;
  char hash;

  buf=(char *) xmalloc(1024);
     
  snprintf(buf, 1023, "%s/%s.script", sieve_dir, name);
  
  return buf;
}

static char *getactivepath(void)
{
  char *buf;
  char hash;

  buf=(char *) xmalloc(1024);
     
  snprintf(buf, 1023, "%s/default", sieve_dir);
  
  return buf;
}

static int validchar(char ch)
{
  if (isalpha(ch)!=0) return TIMSIEVE_OK;

  if (isalnum(ch)!=0) return TIMSIEVE_OK;

  if ((ch=='_') || (ch=='-') || (ch==' '))
    return TIMSIEVE_OK;


  return TIMSIEVE_FAIL;
}

int verifyscriptname(string_t *name)
{
  int lup;
  char *ptr;

  /* must be at least one character long */
  if (name->len<1) return TIMSIEVE_FAIL;

  ptr=string_DATAPTR(name);

  for (lup=0;lup<name->len;lup++)
  {
    if ( validchar(ptr[lup])!=TIMSIEVE_OK) return TIMSIEVE_FAIL;
  }
  
  return TIMSIEVE_OK;
}

int getscript(struct protstream *conn, string_t *name)
{
  FILE *stream;
  struct stat filestats;  /* returned by stat */
  int size;     /* size of the file */
  int result;
  int cnt;

  char *path;

  path=getpath(string_DATAPTR(name));

  result=stat(path,&filestats);

  if (result!=0)
  {
    prot_printf(conn,"NO \"Unable to stat script\"\r\n");
    return TIMSIEVE_NOEXIST;
  }

  size=filestats.st_size;

  stream=fopen(path, "r");

  if (stream==NULL)
  {
    prot_printf(conn,"NO \"Unable to open script\"\r\n");
    return TIMSIEVE_NOEXIST;
  }

  prot_printf(conn, "{%d+}\r\n", size);

  cnt=0;

  while (cnt < size)
  {
    char buf[BLOCKSIZE];
    int amount=BLOCKSIZE;

    if (size-cnt < BLOCKSIZE)
      amount=size-cnt;

    /* xxx what to do on failure? */
    fread(buf, 1, BLOCKSIZE, stream);
    
    prot_write(conn, buf, amount);

    cnt+=amount;
  }

  prot_printf(conn,"\r\n");
  
  prot_printf(conn, "OK \"Success\"\r\n");

  return TIMSIEVE_OK;
}

/* counts the number of scripts user has. used for enforcing quotas */
static int countscripts(char *name)
{
  DIR *dp;
  struct dirent *dir;
  int length;
  int number=0;

  char *path = getsievepath();

  if ((dp=opendir(path)) !=NULL) /* ignore errors */    
    while ((dir=readdir(dp)) != NULL)
    {
      length=strlen(dir->d_name);
      if (length >= strlen(".script"))
      {
	if (strcmp(dir->d_name + (length - 7), ".script")==0)
	{
	  char *tmp=(char *) malloc(strlen(name)+10);

	  strcpy(tmp,name);
	  strcat(tmp,".script");

	  if (strcmp(tmp, dir->d_name)!=0)
	      number++;

	  free(tmp);
	}
      }

    }

  return number;
}



/* save name as a sieve script */
int putscript(struct protstream *conn, string_t *name, string_t *data)
{
  FILE *stream;
  char *dataptr;
  int lup;
  int result;
  char *path;
  int maxscripts;

  /* first let's make sure this is a valid script
     (no parse errors)
  */
  result=is_script_parsable(data);

  if (result!=TIMSIEVE_OK)
  {
    prot_printf(conn,"NO \"Script is not a valid sieve script\"\r\n");
    return result;
  }

  /* see if this would put the user over quota */
  maxscripts=config_getint("maxscripts",5);

  if (countscripts(string_DATAPTR(name))+1 > maxscripts)
  {
    prot_printf(conn,"NO \"You are only allowed %d scripts on this server\"\r\n",maxscripts);
    return TIMSIEVE_FAIL;
  }

  path=getpath(string_DATAPTR(name));

  stream=fopen(path,"w+");

  if (stream==NULL)
  {
    prot_printf(conn,"NO \"Unable to open script for writing (%s)\"\r\n",path);
    return TIMSIEVE_NOEXIST;
  }

  dataptr=string_DATAPTR(data);

  for (lup=0;lup<= data->len / BLOCKSIZE; lup++)
  {
    int amount=BLOCKSIZE;

    if (lup*BLOCKSIZE+BLOCKSIZE > data->len)
      amount=data->len % BLOCKSIZE;

    fwrite(dataptr, 1, amount, stream);

    dataptr+=amount;
  }

  fclose(stream);

  prot_printf(conn, "OK \"Success\"\r\n");

  return TIMSIEVE_OK;
}

/* delete the active script */

static int deleteactive(struct protstream *conn)
{
  struct stat filestats;  /* returned by stat */
  int result;  
  char *active;

  active=getactivepath();

  /* first see if it exists; if it doesn't we're fine */
  result=stat(active,&filestats);
  if (result!=0) return TIMSIEVE_OK;

  result=unlink(active);

  if (result==-1)
  {
    prot_printf(conn,"NO \"Unable to unlink active script\"\r\n");
    return TIMSIEVE_FAIL;
  }

  return TIMSIEVE_OK;
}


/* is this the active script? */
static int isactive(char *name)
{
  char *filename=getpath(name);
  struct stat filestats;  /* returned by stat */
  int result;  

  result=stat(filename,&filestats);

  if (result!=0) return FALSE;

  if (filestats.st_nlink>1)
    return TRUE;

  return FALSE;
}

/* delete a sieve script */
int deletescript(struct protstream *conn, string_t *name)
{
  int result;

  char *path;

  path=getpath(string_DATAPTR(name));

  if (isactive(string_DATAPTR(name))==TRUE)
    if (deleteactive(conn)!=TIMSIEVE_OK)
    {
      return TIMSIEVE_FAIL;
    }

  result=unlink(path);

  if (result==-1)
  {
    prot_printf(conn,"NO \"Error deleting script\"\r\n");
    return TIMSIEVE_FAIL;
  }

  prot_printf(conn,"OK \"Success\"\r\n");

  return TIMSIEVE_OK;
}

/* list the scripts user has available */
int listscripts(struct protstream *conn)
{
  DIR *dp;
  struct dirent *dir;
  int length;

  char *path = getsievepath();

  /* open the directory */
  dp=opendir(path);
  
  if (dp==NULL)
  {
    prot_printf(conn,"NO \"Error opening directory\"\r\n");
    return TIMSIEVE_FAIL;
  }

  while ((dir=readdir(dp)) != NULL) /* while there are files here */
  {
    length=strlen(dir->d_name);
    if (length >= strlen(".script")) /* if ends in .script */
    {
      if (strcmp(dir->d_name + (length - 7), ".script")==0)
      {
	char *namewo=(char *) xmalloc(length-6);
	  
	memcpy(namewo, dir->d_name, length-7);
	namewo[length-7]='\0';
	
	if (isactive(namewo)==TRUE)
	  prot_printf(conn,"\"%s*\"\r\n", namewo);
	else
	  prot_printf(conn,"\"%s\"\r\n", namewo);


	free(namewo);
      }
    }    
  }

  prot_printf(conn,"OK \"Success\"\r\n");
  
  return TIMSIEVE_OK;
}

/* does the script 'str' exist
   return TRUE | FALSE */
static int exists(char *str)
{
  char *filename=getpath(str);
  struct stat filestats;  /* returned by stat */
  int result;

  result=stat(filename,&filestats);  

  if (result!=0)
    return FALSE;

  return TRUE;
}

/* set the sieve script 'name' to be the active script */

int setactive(struct protstream *conn, string_t *name)
{
  int result;
  char *filename;
  char *active;
  char *activebak;

  if (exists(string_DATAPTR(name))==FALSE)
  {
    prot_printf(conn,"NO \"Script does not exist\"\r\n");
    return TIMSIEVE_NOEXIST;
  }

  if (deleteactive(conn)!=TIMSIEVE_OK)
    return TIMSIEVE_FAIL;

  /* get the name of the active sieve script */
  filename=getpath(string_DATAPTR(name));
  active=getactivepath();

  /* make a name with .bak so we can do this atomically */
  activebak=(char *) xmalloc(strlen(active)+30);
  strcpy(activebak, active);
  strcat(activebak,".bak");

  /* ok we want to do this atomically so let's
     - make <activesieve>.bak as a hard link
     - rename it to <activesieve>
  */

  result=link(  filename, activebak);

  if (result!=0)
  {
    prot_printf(conn,"NO \"Can't make link\"\r\n");    
    return TIMSIEVE_FAIL;
  }

  result=rename(activebak, active);

  free(activebak);

  if (result!=0)
  {
    prot_printf(conn,"NO \"Error renaming\"\r\n");
    return TIMSIEVE_FAIL;
  }

  prot_printf(conn,"OK \"Worked\"\r\n");

  

  return TIMSIEVE_OK;
}
