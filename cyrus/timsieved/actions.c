/* actions.c -- executes the commands for timsieved
 * Tim Martin
 * $Id: actions.c,v 1.9.2.2 2000/10/17 04:53:57 ken3 Exp $
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
#include <stdlib.h>
#include <limits.h>
#include <sys/param.h>
#include <syslog.h>
#include <dirent.h>
#include <ctype.h>
#include <unistd.h>
#include <string.h>

#include "prot.h"
#include "config.h"
#include "xmalloc.h"

#include "codes.h"
#include "actions.h"
#include "scripttest.h"



/* after a user has authentication, our current directory is their Sieve 
   directory! */

char *sieve_dir = NULL;

int actions_init(void)
{
  int sieve_usehomedir = 0;

  sieve_usehomedir = config_getswitch("sieveusehomedir", 0);
  
  if (!sieve_usehomedir) {
      sieve_dir = (char *) config_getstring("sievedir", "/usr/sieve");
  } else {
      /* can't use home directories with timsieved */
      syslog(LOG_ERR, "can't use home directories");

      return TIMSIEVE_FAIL;
  }
  
  return TIMSIEVE_OK;
}


int actions_setuser(char *userid)
{
  char hash;
  char *foo=sieve_dir;
  int result;  

  sieve_dir=(char *) xmalloc(1024);
  
  hash = (char) tolower((int) *userid);
  if (!islower((int) hash)) { hash = 'q'; }
    
  snprintf(sieve_dir, 1023, "%s/%c/%s", foo, hash,userid);

  printf("sievedir=%s\n",sieve_dir);

  result = chdir(sieve_dir);
  if (result != 0) {
      result = mkdir(sieve_dir, 0755);
      if (!result) result = chdir(sieve_dir);
      if (result) {
	  syslog(LOG_ERR, "mkdir %s: %m", sieve_dir);
	  return TIMSIEVE_FAIL;
      }
  }

  return TIMSIEVE_OK;
}

static int validchar(char ch)
{
    if (isalnum((int) ch) || (ch == '_') || (ch == '-') || (ch == ' ')) {
	return TIMSIEVE_OK;
    }

    return TIMSIEVE_FAIL;
}

int verifyscriptname(mystring_t *name)
{
  int lup;
  char *ptr;

  /* must be at least one character long */
  if (name->len < 1) return TIMSIEVE_FAIL;

  ptr=string_DATAPTR(name);

  for (lup=0;lup<name->len;lup++) {
      if ( validchar(ptr[lup])!=TIMSIEVE_OK) return TIMSIEVE_FAIL;
  }
  
  return TIMSIEVE_OK;
}

int getscript(struct protstream *conn, mystring_t *name)
{
  FILE *stream;
  struct stat filestats;	/* returned by stat */
  int size;			/* size of the file */
  int result;
  int cnt;

  char path[1024];

  snprintf(path, 1023, "%s.script", string_DATAPTR(name));

  result = stat(path, &filestats);
  if (result != 0) {
    prot_printf(conn,"NO \"Script doesn't exist\"\r\n");
    return TIMSIEVE_NOEXIST;
  }
  size = filestats.st_size;

  stream = fopen(path, "r");

  if (stream == NULL) {
      prot_printf(conn,"NO \"fopen failed\"\r\n");
      return TIMSIEVE_NOEXIST;
  }

  prot_printf(conn, "{%d}\r\n", size);

  cnt = 0;
  while (cnt < size) {
      char buf[BLOCKSIZE];
      int amount=BLOCKSIZE;

      if (size-cnt < BLOCKSIZE)
	  amount=size-cnt;

      if (fread(buf, 1, BLOCKSIZE, stream) == 0) {
	  if (ferror(stream)) {
	      fatal("fatal error (fread)", 0);
	  }
      }
    
      prot_write(conn, buf, amount);
      
      cnt += amount;
  }

  prot_printf(conn,"\r\n");
  
  prot_printf(conn, "OK \"Success\"\r\n");

  return TIMSIEVE_OK;
}

/* counts the number of scripts user has that are DIFFERENT from name. 
   used for enforcing quotas */
static int countscripts(char *name)
{
    DIR *dp;
    struct dirent *dir;
    int length;
    int number=0;
    char myname[1024];
    
    snprintf(myname, 1023, "%s.script", name);
    
    if ((dp = opendir(".")) == NULL) {
	return -1;
    }
    
    while ((dir=readdir(dp)) != NULL) {
	length=strlen(dir->d_name);
	if (length >= strlen(".script") && 
	    (strcmp(dir->d_name + (length - 7), ".script") == 0)) {
	    /* this is a sieve script */
	    if (strcmp(myname, dir->d_name) != 0) {
		/* and it's different from me */
		number++;
	    }
	}
    }
    
    return number;
}

/* save name as a sieve script */
int putscript(struct protstream *conn, mystring_t *name, mystring_t *data)
{
  FILE *stream;
  char *dataptr;
  char *errstr;
  int lup;
  int result;
  char path[1024], p2[1024];
  int maxscripts;

  /* see if this would put the user over quota */
  maxscripts = config_getint("sieve_maxscripts",5);

  if (countscripts(string_DATAPTR(name))+1 > maxscripts)
  {
    prot_printf(conn,
		"NO \"You are only allowed %d scripts on this server\"\r\n",
		maxscripts);
    return TIMSIEVE_FAIL;
  }

  snprintf(path, 1023, "%s.script.NEW", string_DATAPTR(name));

  stream = fopen(path, "w+");
  if (stream == NULL) {
      prot_printf(conn, "NO \"Unable to open script for writing (%s)\"\r\n",
		  path);
      return TIMSIEVE_NOEXIST;
  }

  dataptr = string_DATAPTR(data);

  for (lup=0;lup<= data->len / BLOCKSIZE; lup++) {
      int amount = BLOCKSIZE;

      if (lup*BLOCKSIZE+BLOCKSIZE > data->len)
	  amount=data->len % BLOCKSIZE;

      fwrite(dataptr, 1, amount, stream);
      
      dataptr += amount;
  }

  /* let's make sure this is a valid script
     (no parse errors)
  */
  result = is_script_parsable(stream, &errstr);

  if (result != TIMSIEVE_OK) {
      if (errstr && *errstr) { 
	  prot_printf(conn, "NO {%d}\r\n%s\r\n", strlen(errstr), errstr);
	  free(errstr);
      } else {
	  if (errstr) free(errstr);
	  prot_printf(conn, "NO \"parse failed\"\r\n");
      }
      fclose(stream);
      unlink(path);
      return result;
  }

  fflush(stream);
  fclose(stream);
  
  snprintf(p2, 1023, "%s.script", string_DATAPTR(name));
  rename(path, p2);

  prot_printf(conn, "OK \"Success\"\r\n");

  return TIMSIEVE_OK;
}

/* delete the active script */

static int deleteactive(struct protstream *conn)
{

  if (unlink("default") != 0) {
      prot_printf(conn,"NO \"Unable to unlink active script\"\r\n");
      return TIMSIEVE_FAIL;
  }

  return TIMSIEVE_OK;
}


/* is this the active script? */
static int isactive(char *name)
{
  char filename[1024];
  struct stat filestats;  /* returned by stat */
  int result;  

  snprintf(filename, 1023, "%s.script", name);

  result=stat(filename,&filestats);
  if (result != 0) {
      return FALSE;
  }

  if (filestats.st_nlink>1) {
    return TRUE;
  }

  return FALSE;
}

/* delete a sieve script */
int deletescript(struct protstream *conn, mystring_t *name)
{
  int result;
  char path[1024];

  snprintf(path, 1023, "%s.script", string_DATAPTR(name));

  if (isactive(string_DATAPTR(name)) && (deleteactive(conn)!=TIMSIEVE_OK)) {
      return TIMSIEVE_FAIL;
  }

  result = unlink(path);

  if (result != 0) {
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

  /* open the directory */
  dp=opendir(".");
  
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
  char filename[1024];
  struct stat filestats;  /* returned by stat */
  int result;

  snprintf(filename, 1023, "%s.script", str);

  result = stat(filename,&filestats);  

  if (result != 0) {
    return FALSE;
  }

  return TRUE;
}

/* set the sieve script 'name' to be the active script */

int setactive(struct protstream *conn, mystring_t *name)
{
  int result;
  char filename[1024];

  /* if string name is empty, disable active script */
  if (!strlen(string_DATAPTR(name))) {
    if (deleteactive(conn) != TIMSIEVE_OK)
      return TIMSIEVE_FAIL;

    prot_printf(conn,"OK \"Worked\"\r\n");
    return TIMSIEVE_OK;
  }

  if (exists(string_DATAPTR(name))==FALSE)
  {
    prot_printf(conn,"NO \"Script does not exist\"\r\n");
    return TIMSIEVE_NOEXIST;
  }

  /* get the name of the active sieve script */
  snprintf(filename, 1023, "%s.script", string_DATAPTR(name));

  /* ok we want to do this atomically so let's
     - make <activesieve>.NEW as a hard link
     - rename it to <activesieve>
  */

  result = link(filename, "default.NEW");

  if (result!=0) {
    prot_printf(conn, "NO \"Can't make link\"\r\n");    
    return TIMSIEVE_FAIL;
  }

  result=rename("default.NEW", "default");

  if (result!=0) {
      prot_printf(conn,"NO \"Error renaming\"\r\n");
      return TIMSIEVE_FAIL;
  }

  prot_printf(conn,"OK \"Worked\"\r\n");
  return TIMSIEVE_OK;
}
