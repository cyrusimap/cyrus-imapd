/* actions.c -- executes the commands for timsieved
 * Tim Martin
 * $Id: actions.c,v 1.30.4.6 2003/02/27 18:14:15 rjs3 Exp $
 */
/*
 * Copyright (c) 1998-2003 Carnegie Mellon University.  All rights reserved.
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
#include <sys/stat.h>
#include <errno.h>
#include <stdlib.h>
#include <limits.h>
#include <sys/param.h>
#include <sys/types.h>
#include <fcntl.h>
#include <syslog.h>
#include <dirent.h>
#include <ctype.h>
#include <unistd.h>
#include <string.h>

#include "prot.h"
#include "tls.h"
#include "util.h"
#include "global.h"
#include "libconfig.h"
#include "xmalloc.h"
#include "sieve_interface.h"

#include "codes.h"
#include "actions.h"
#include "scripttest.h"

/* after a user has authentication, our current directory is their Sieve 
   directory! */

char *sieve_dir = NULL;

int actions_init(void)
{
  int sieve_usehomedir = 0;

  sieve_usehomedir = config_getswitch(IMAPOPT_SIEVEUSEHOMEDIR);
  
  if (!sieve_usehomedir) {
      sieve_dir = (char *) config_getstring(IMAPOPT_SIEVEDIR);
  } else {
      /* can't use home directories with timsieved */
      syslog(LOG_ERR, "can't use home directories");

      return TIMSIEVE_FAIL;
  }
  
  return TIMSIEVE_OK;
}

int actions_setuser(const char *userid)
{
  char hash, *domain;
  char *foo=sieve_dir;
  int result;  

  sieve_dir=(char *) xmalloc(1024);
  
  if (config_virtdomains && (domain = strchr(userid, '@'))) {
      char d = (char) dir_hash_c(domain+1);
      *domain = '\0';  /* split user@domain */
      hash = (char) dir_hash_c(userid);
      snprintf(sieve_dir, 1023, "%s%s%c/%s/%c/%s",
	       foo, FNAME_DOMAINDIR, d, domain+1,
	       hash, userid);
      *domain = '@';  /* reassemble user@domain */
  }
  else {
      hash = (char) dir_hash_c(userid);
    
      snprintf(sieve_dir, 1023, "%s/%c/%s", foo, hash,userid);
  }

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

/*
 *
 * Everything but '/' and '\0' are valid.
 *
 */

int scriptname_valid(mystring_t *name)
{
  int lup;
  char *ptr;

  /* must be at least one character long */
  if (name->len < 1) return TIMSIEVE_FAIL;

  ptr=string_DATAPTR(name);

  for (lup=0;lup<name->len;lup++)
  {
      if ((ptr[lup]=='/') || (ptr[lup]=='\0'))
	  return TIMSIEVE_FAIL;
  }
  
  return TIMSIEVE_OK;
}

int capabilities(struct protstream *conn, sasl_conn_t *saslconn)
{
    const char *sasllist;
    unsigned mechcount;

    /* implementation */
    prot_printf(conn, "\"IMPLEMENTATION\" \"Cyrus timsieved %s\"\r\n",
		CYRUS_VERSION);
    
    /* SASL */
    if (sasl_listmech(saslconn, NULL, 
		    "\"SASL\" \"", " ", "\"\r\n",
		    &sasllist,
		    NULL, &mechcount) == SASL_OK && mechcount > 0)
    {
      prot_printf(conn,"%s",sasllist);
    }
    
    /* Sieve capabilities */
    prot_printf(conn,"\"SIEVE\" \"%s\"\r\n",sieve_listextensions());

    if (tls_enabled()) {
	prot_printf(conn, "\"STARTTLS\"\r\n");
    }

    prot_printf(conn,"OK\r\n");

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

  result = scriptname_valid(name);
  if (result!=TIMSIEVE_OK)
  {
      prot_printf(conn,"NO \"Invalid script name\"\r\n");
      return result;
  }


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
  
  prot_printf(conn, "OK\r\n");

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
int putscript(struct protstream *conn, mystring_t *name, mystring_t *data,
	      int verify_only)
{
  FILE *stream;
  char *dataptr;
  char *errstr;
  int lup;
  int result;
  char path[1024], p2[1024];
  char bc_path[1024], bc_p2[1024];
  int maxscripts;
  sieve_script_t *s;

  result = scriptname_valid(name);
  if (result!=TIMSIEVE_OK)
  {
      prot_printf(conn,"NO \"Invalid script name\"\r\n");
      return result;
  }

  if (verify_only)
      stream = tmpfile();

  else {
      /* see if this would put the user over quota */
      maxscripts = config_getint(IMAPOPT_SIEVE_MAXSCRIPTS);

      if (countscripts(string_DATAPTR(name))+1 > maxscripts)
      {
	  prot_printf(conn,
		      "NO (\"QUOTA\") \"You are only allowed %d scripts on this server\"\r\n",
		      maxscripts);
	  return TIMSIEVE_FAIL;
      }

      snprintf(path, 1023, "%s.script.NEW", string_DATAPTR(name));

      stream = fopen(path, "w+");
  }


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
  result = is_script_parsable(stream, &errstr, &s);

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
  
  if (!verify_only) {
      int fd;
      bytecode_info_t *bc;
      
      /* Now, generate the bytecode */
      if(sieve_generate_bytecode(&bc, s) == -1) {
	  unlink(path);
	  sieve_script_free(&s);
	  prot_printf(conn, "NO \"bytecode generate failed\"\r\n");
	  return TIMSIEVE_FAIL;
      }

      /* Now, open the new file */
      snprintf(bc_path, 1023, "%s.bc.NEW", string_DATAPTR(name));
      fd = open(bc_path, O_CREAT | O_TRUNC | O_WRONLY, 0600);
      if(fd < 0) {
	  unlink(path);
	  sieve_free_bytecode(&bc);
	  sieve_script_free(&s);
	  prot_printf(conn, "NO \"couldn't open bytecode file\"\r\n");
	  return TIMSIEVE_FAIL;
      }
	  
      /* Now, emit the bytecode */
      if(sieve_emit_bytecode(fd, bc) == -1) {
	  close(fd);
	  unlink(path);
	  unlink(bc_path);
	  sieve_free_bytecode(&bc);
	  sieve_script_free(&s);
	  prot_printf(conn, "NO \"bytecode emit failed\"\r\n");
	  return TIMSIEVE_FAIL;
      }

      sieve_free_bytecode(&bc);
      sieve_script_free(&s);

      close(fd);

      /* Now, rename! */
      snprintf(p2, 1023, "%s.script", string_DATAPTR(name));
      snprintf(bc_p2, 1023, "%s.bc", string_DATAPTR(name));
      rename(path, p2);
      rename(bc_path, bc_p2);

  }

  prot_printf(conn, "OK\r\n");

  return TIMSIEVE_OK;
}

/* delete the active script */

static int deleteactive(struct protstream *conn)
{
    if (unlink("default.bc") != 0) {
	prot_printf(conn,"NO \"Unable to unlink active script\"\r\n");
	return TIMSIEVE_FAIL;
    }

    return TIMSIEVE_OK;
}


/* is this the active script? */
static int isactive(char *name)
{
    char filename[1024];
    char activelink[1024];

    snprintf(filename, 1023, "%s.bc", name);
    memset(activelink, 0, sizeof(activelink));
    if ((readlink("default.bc", activelink, sizeof(activelink)-1) < 0) && 
	(errno != ENOENT)) 
    {
	syslog(LOG_ERR, "readlink(default.bc): %m");
	return FALSE;
    }

    if (!strcmp(filename, activelink)) {
	return TRUE;
    } else {
	return FALSE;
    }
}

/* delete a sieve script */
int deletescript(struct protstream *conn, mystring_t *name)
{
  int result;
  char path[1024];

  result = scriptname_valid(name);
  if (result!=TIMSIEVE_OK)
  {
      prot_printf(conn,"NO \"Invalid script name\"\r\n");
      return result;
  }

  snprintf(path, 1023, "%s.script", string_DATAPTR(name));

  if (isactive(string_DATAPTR(name)) && (deleteactive(conn)!=TIMSIEVE_OK)) {
      return TIMSIEVE_FAIL;
  }

  result = unlink(path);

  if (result != 0) {
      prot_printf(conn,"NO \"Error deleting script\"\r\n");
      return TIMSIEVE_FAIL;
  }

  snprintf(path, 1023, "%s.bc", string_DATAPTR(name));

  result = unlink(path);

  if (result != 0) {
      prot_printf(conn,"NO \"Error deleting bytecode\"\r\n");
      return TIMSIEVE_FAIL;
  }

  prot_printf(conn,"OK\r\n");
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
		    prot_printf(conn,"\"%s\" ACTIVE\r\n", namewo);
		else
		    prot_printf(conn,"\"%s\"\r\n", namewo);

		free(namewo);
	    }
	}    
    }

    prot_printf(conn,"OK\r\n");
  
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

	prot_printf(conn,"OK\r\n");
	return TIMSIEVE_OK;
    }

    result = scriptname_valid(name);
    if (result!=TIMSIEVE_OK)
    {
	prot_printf(conn,"NO \"Invalid script name\"\r\n");
	return result;
    }

    if (exists(string_DATAPTR(name))==FALSE)
    {
	prot_printf(conn,"NO \"Script does not exist\"\r\n");
	return TIMSIEVE_NOEXIST;
    }

    /* if script already is the active one just say ok */
    if (isactive(string_DATAPTR(name))==TRUE) {
	prot_printf(conn,"OK\r\n");
	return TIMSIEVE_OK;  
    }

    /* get the name of the active sieve script */
    snprintf(filename, sizeof(filename), "%s.bc", string_DATAPTR(name));

    /* ok we want to do this atomically so let's
       - make <activesieve>.NEW as a hard link
       - rename it to <activesieve>
    */
    result = symlink(filename, "default.bc.NEW");
    if (result) {
	syslog(LOG_ERR, "symlink(%s, default.bc.NEW): %m", filename);
	prot_printf(conn, "NO \"Can't make link\"\r\n");    
	return TIMSIEVE_FAIL;
    }

    result = rename("default.bc.NEW", "default.bc");
    if (result) {
	unlink("default.bc.NEW");
	syslog(LOG_ERR, "rename(default.bc.NEW, default.bc): %m");
	prot_printf(conn,"NO \"Error renaming\"\r\n");
	return TIMSIEVE_FAIL;
    }

    prot_printf(conn,"OK\r\n");
    return TIMSIEVE_OK;
}

int cmd_havespace(struct protstream *conn, mystring_t *sieve_name, unsigned long num)
{
    int result;
    int maxscripts;
    unsigned long maxscriptsize;

    result = scriptname_valid(sieve_name);
    if (result!=TIMSIEVE_OK)
    {
	prot_printf(conn,"NO \"Invalid script name\"\r\n");
	return result;
    }

    /* see if the size of the script is too big */
    maxscriptsize = config_getint(IMAPOPT_SIEVE_MAXSCRIPTSIZE);
    maxscriptsize *= 1024;

    if (num > maxscriptsize)
    {
	prot_printf(conn,
		    "NO (\"QUOTA\") \"Script size is too large. "
		    "Max script size is %ld bytes\"\r\n",
		    maxscriptsize);
	return TIMSIEVE_FAIL;
    }

    /* see if this would put the user over quota */
    maxscripts = config_getint(IMAPOPT_SIEVE_MAXSCRIPTS);

    if (countscripts(string_DATAPTR(sieve_name))+1 > maxscripts)
    {
	prot_printf(conn,
		    "NO (\"QUOTA\") \"You are only allowed %d scripts on this server\"\r\n",
		    maxscripts);
	return TIMSIEVE_FAIL;
    }


    prot_printf(conn,"OK\r\n");
    return TIMSIEVE_OK;
}
