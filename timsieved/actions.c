/* actions.c -- executes the commands for timsieved
 * Tim Martin
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

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>

#include "libconfig.h"
#include "xmalloc.h"
#include "xstrlcat.h"
#include "xstrlcpy.h"
#include "imap/global.h"
#include "imap/sync_log.h"
#include "imap/tls.h"
#include "imap/version.h"
#include "sievedir.h"
#include "sieve/sieve_interface.h"
#include "timsieved/actions.h"
#include "timsieved/codes.h"

/* after a user has authentication, our current directory is their Sieve
   directory! */

extern int sieved_userisadmin;
extern sieve_interp_t *interp;

static char *sieve_dir_config = NULL;
static char *sieved_userid = NULL;

static char *sieve_dir = NULL;

int actions_init(void)
{
  int sieve_usehomedir = 0;

  sieve_usehomedir = config_getswitch(IMAPOPT_SIEVEUSEHOMEDIR);

  if (!sieve_usehomedir) {
      sieve_dir_config = (char *) config_getstring(IMAPOPT_SIEVEDIR);
  } else {
      /* can't use home directories with timsieved */
      syslog(LOG_ERR, "can't use home directories");

      return TIMSIEVE_FAIL;
  }

  return TIMSIEVE_OK;
}

int actions_setuser(const char *userid)
{
  char *domain = NULL;
  struct buf buf = BUF_INITIALIZER;
  int result, ret = TIMSIEVE_OK;

  free(sieved_userid);
  sieved_userid = xstrdup(userid);
  if (config_virtdomains) {
      /* split the user and domain */
      if ((domain = strrchr(sieved_userid, '@'))) *domain++ = '\0';
  }

  buf_setcstr(&buf, sieve_dir_config);

  if (domain) {
      char dhash = (char) dir_hash_c(domain, config_fulldirhash);
      buf_printf(&buf, "%s%c/%s", FNAME_DOMAINDIR, dhash, domain);
  }

  if (sieved_userisadmin) {
      buf_appendcstr(&buf, "/global");
  }
  else {
      char hash = (char) dir_hash_c(sieved_userid, config_fulldirhash);
      buf_printf(&buf, "/%c/%s", hash, sieved_userid);
  }

  /* rejoin user and domain */
  if (domain) domain[-1] = '@';

  if (sieve_dir) free(sieve_dir);
  sieve_dir = buf_release(&buf);

  result = chdir(sieve_dir);
  if (result != 0) {
      result = cyrus_mkdir(sieve_dir, 0755);
      if (!result) result = mkdir(sieve_dir, 0755);
      if (!result) result = chdir(sieve_dir);
      if (result) {
          syslog(LOG_ERR, "mkdir %s: %m", sieve_dir);
          ret = TIMSIEVE_FAIL;
      }
  }

  buf_free(&buf);
  return ret;
}

/*
 *
 * Everything but '/' and '\0' are valid.
 *
 */

static int scriptname_valid(const struct buf *name)
{
  unsigned int lup;
  char *ptr;

  /* must be at least one character long */
  if (name->len < 1) return TIMSIEVE_FAIL;

  ptr = name->s;

  for (lup=0;lup<name->len;lup++)
  {
      if ((ptr[lup]=='/') || (ptr[lup]=='\0'))
          return TIMSIEVE_FAIL;
  }

  return lup < 1013 ? TIMSIEVE_OK : TIMSIEVE_FAIL;
}

int capabilities(struct protstream *conn, sasl_conn_t *saslconn,
                 int starttls_done, int authenticated, sasl_ssf_t sasl_ssf)
{
    const char *sasllist;
    int mechcount, i;

    /* implementation */
    if (config_serverinfo == IMAP_ENUM_SERVERINFO_ON) {
        prot_printf(conn,
                    "\"IMPLEMENTATION\" \"Cyrus timsieved%s %s\"\r\n",
                    config_mupdate_server ? " (Murder)" : "", CYRUS_VERSION);
    } else if (config_serverinfo == IMAP_ENUM_SERVERINFO_MIN) {
        prot_printf(conn,
                    "\"IMPLEMENTATION\" \"Cyrus timsieved%s\"\r\n",
                    config_mupdate_server ? " (Murder)" : "");
    } else {
        /* IMAP_ENUM_SERVERINFO_OFF */
        prot_puts(conn, "\"IMPLEMENTATION\" \"ManageSieve\"\r\n");
    }
    prot_puts(conn, "\"VERSION\" \"1.0\"\r\n");

    /* SASL */
    if (!sieved_tls_required && (!authenticated || sasl_ssf) &&
        sasl_listmech(saslconn, NULL,
                      "\"SASL\" \"", " ", "\"\r\n",
                      &sasllist,
                      NULL, &mechcount) == SASL_OK/* && mechcount > 0*/)
    {
        prot_printf(conn,"%s",sasllist);
    }

    /* Sieve capabilities */
    const strarray_t *extensions = sieve_listextensions(interp);
    for (i = 0; i < strarray_size(extensions); i += 2) {
        /* capability/value pairs */
        prot_printf(conn,"\"%s\" \"%s\"\r\n",
                    strarray_nth(extensions, i), strarray_nth(extensions, i+1));
    }

    if (tls_enabled() && !starttls_done && !authenticated) {
        prot_puts(conn, "\"STARTTLS\"\r\n");
    }

    if (authenticated) prot_printf(conn, "\"OWNER\" \"%s\"\r\n", sieved_userid);
    prot_puts(conn, "\"UNAUTHENTICATE\"\r\n");

    prot_puts(conn,"OK\r\n");

    return TIMSIEVE_OK;
}

int getscript(struct protstream *conn, const struct buf *name)
{
    int size;                     /* size of the file */
    int result;
    char path[1024];
    struct buf *buf;

    result = scriptname_valid(name);
    if (result != TIMSIEVE_OK) {
        prot_printf(conn,"NO \"Invalid script name\"\r\n");
        return result;
    }

    snprintf(path, 1023, "%s.script", name->s);

    buf = sieve_get_script(sieve_dir, path);

    if (!buf) {
        prot_printf(conn,"NO (NONEXISTENT) \"Script doesn't exist\"\r\n");
        return TIMSIEVE_NOEXIST;
    }

    size = buf_len(buf);
    prot_printf(conn, "{%d}\r\n", size);
    prot_write(conn, buf_base(buf), size);
    buf_destroy(buf);

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
    size_t length;
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

    closedir(dp);

    return number;
}


/* save name as a sieve script */
int putscript(struct protstream *conn, const struct buf *name,
              const struct buf *data, int verify_only)
{
  FILE *stream;
  const char *dataptr;
  struct buf errors = BUF_INITIALIZER;
  unsigned int i;
  int last_was_r = 0;
  int result;
  char path[1024], p2[1024];
  char bc_path[1024], bc_p2[1024];
  int maxscripts;
  sieve_script_t *s = NULL;

  result = scriptname_valid(name);
  if (result!=TIMSIEVE_OK)
  {
      prot_printf(conn,"NO \"Invalid script name\"\r\n");
      return result;
  }

  if (verify_only) {
      char *err = NULL;
      result = sieve_script_parse_string(interp, buf_cstring(data), &err, &s);
      if (err) buf_initm(&errors, err, strlen(err));
  }
  else {
      /* see if this would put the user over quota */
      maxscripts = config_getint(IMAPOPT_SIEVE_MAXSCRIPTS);

      if (countscripts(name->s)+1 > maxscripts)
      {
          prot_printf(conn,
                      "NO (QUOTA/MAXSCRIPTS) \"You are only allowed %d scripts on this server\"\r\n",
                      maxscripts);
          return TIMSIEVE_FAIL;
      }

      snprintf(path, 1023, "%s.script.NEW", name->s);

      stream = fopen(path, "w+");

      if (stream == NULL) {
          prot_printf(conn, "NO \"Unable to open script for writing (%s)\"\r\n",
                      path);
          return TIMSIEVE_NOEXIST;
      }

      dataptr = data->s;

      /* copy data to file - replacing any lone \r or \n with the
       * \r\n pair so notify messages are SMTP compatible */
      for (i = 0; i < data->len; i++) {
          if (last_was_r) {
              if (dataptr[i] != '\n')
                  putc('\n', stream);
          }
          else {
              if (dataptr[i] == '\n')
                  putc('\r', stream);
          }
          putc(dataptr[i], stream);
          last_was_r = (dataptr[i] == '\r');
      }
      if (last_was_r)
          putc('\n', stream);

      rewind(stream);

      /* let's make sure this is a valid script
         (no parse errors)
      */
      result = sieve_script_parse(interp, stream, &errors, &s);

      fflush(stream);
      fclose(stream);
  }

  if (result != SIEVE_OK) {
      if (buf_len(&errors)) {
          prot_printf(conn, "NO ");
          prot_printstring(conn, buf_cstring(&errors));
          prot_printf(conn, "\r\n");
      } else {
          prot_printf(conn, "NO \"parse failed\"\r\n");
      }
      sieve_script_free(&s);
      buf_free(&errors);
      unlink(path);
      return TIMSIEVE_FAIL;
  }

  buf_free(&errors);

  if (!verify_only) {
      int fd;
      bytecode_info_t *bc = NULL;

      /* Now, generate the bytecode */
      if(sieve_generate_bytecode(&bc, s) == -1) {
          unlink(path);
          sieve_script_free(&s);
          prot_printf(conn, "NO \"bytecode generate failed\"\r\n");
          return TIMSIEVE_FAIL;
      }

      /* Now, open the new file */
      snprintf(bc_path, 1023, "%s.bc.NEW", name->s);
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

      close(fd);

      /* Now, rename! */
      snprintf(p2, 1023, "%s.script", name->s);
      snprintf(bc_p2, 1023, "%s.bc", name->s);
      rename(path, p2);
      rename(bc_path, bc_p2);

  }

  sieve_script_free(&s);

  prot_printf(conn, "OK\r\n");
  sync_log_sieve(sieved_userid);

  return TIMSIEVE_OK;
}

/* delete the active script */

static int deleteactive(struct protstream *conn)
{
    int result = sieve_deactivate_script(sieve_dir);
    if (result != SIEVEDIR_OK) {
        prot_printf(conn,"NO \"Unable to deactivate script\"\r\n");
        return TIMSIEVE_FAIL;
    }
    sync_log_sieve(sieved_userid);

    return TIMSIEVE_OK;
}

/* delete a sieve script */
int deletescript(struct protstream *conn, const struct buf *name)
{
  int result;

  result = scriptname_valid(name);
  if (result!=TIMSIEVE_OK)
  {
      prot_printf(conn,"NO \"Invalid script name\"\r\n");
      return result;
  }

  if (sieve_script_isactive(sieve_dir, name->s)) {
    prot_printf(conn, "NO (ACTIVE) \"Active script cannot be deleted\"\r\n");
    return TIMSIEVE_FAIL;
  }

  result = sieve_delete_script(sieve_dir, name->s);
  if (result != SIEVEDIR_OK) {
      if (result == SIEVEDIR_NOTFOUND)
          prot_printf(conn, "NO (NONEXISTENT) \"Script %s does not exist.\"\r\n", name->s);
      else
          prot_printf(conn,"NO \"Error deleting script\"\r\n");
      return TIMSIEVE_FAIL;
  }

  sync_log_sieve(sieved_userid);

  prot_printf(conn,"OK\r\n");
  return TIMSIEVE_OK;
}

/* list the scripts user has available */
int listscripts(struct protstream *conn)
{
    DIR *dp;
    struct dirent *dir;
    size_t length;

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
                char *namewo = xstrndup(dir->d_name, length-7);

                if (sieve_script_isactive(sieve_dir, namewo))
                    prot_printf(conn,"\"%s\" ACTIVE\r\n", namewo);
                else
                    prot_printf(conn,"\"%s\"\r\n", namewo);

                free(namewo);
            }
        }
    }

    closedir(dp);

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

int setactive(struct protstream *conn, const struct buf *name)
{
    int result;

    /* if string name is empty, disable active script */
    if (!name->len) {
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

    if (exists(name->s)==FALSE)
    {
        prot_printf(conn,"NO (NONEXISTENT) \"Script does not exist\"\r\n");
        return TIMSIEVE_NOEXIST;
    }

    /* if script already is the active one just say ok */
    if (sieve_script_isactive(sieve_dir, name->s)==TRUE) {
        prot_printf(conn,"OK\r\n");
        return TIMSIEVE_OK;
    }

    result = sieve_activate_script(sieve_dir, name->s);
    if (result != SIEVEDIR_OK) {
        prot_printf(conn,"NO \"Error activating script\"\r\n");
        return TIMSIEVE_FAIL;
    }

    sync_log_sieve(sieved_userid);

    prot_printf(conn,"OK\r\n");
    return TIMSIEVE_OK;
}

/* rename a sieve script */
int renamescript(struct protstream *conn,
                 const struct buf *oldname, const struct buf *newname)
{
  int result;
  char oldpath[1024], newpath[1024];

  result = scriptname_valid(oldname);
  if (result!=TIMSIEVE_OK)
  {
      prot_printf(conn,"NO \"Invalid old script name\"\r\n");
      return result;
  }
  result = scriptname_valid(newname);
  if (result!=TIMSIEVE_OK)
  {
      prot_printf(conn,"NO \"Invalid new script name\"\r\n");
      return result;
  }

  if (exists(newname->s)==TRUE) {
    prot_printf(conn, "NO (ALREADYEXISTS) \"Script %s already exists.\"\r\n",
                newname->s);
    return TIMSIEVE_EXISTS;
  }

  snprintf(oldpath, 1023, "%s.script", oldname->s);
  snprintf(newpath, 1023, "%s.script", newname->s);

  result = rename(oldpath, newpath);

  if (result != 0) {
      if (errno== ENOENT)
          prot_printf(conn, "NO (NONEXISTENT) \"Script %s does not exist.\"\r\n",
                      oldname->s);
      else
          prot_printf(conn,"NO \"Error renaming script\"\r\n");
      return TIMSIEVE_FAIL;
  }

  snprintf(oldpath, 1023, "%s.bc", oldname->s);
  snprintf(newpath, 1023, "%s.bc", newname->s);

  result = rename(oldpath, newpath);

  if (result != 0) {
      prot_printf(conn,"NO \"Error renaming bytecode\"\r\n");
      return TIMSIEVE_FAIL;
  }

  if (sieve_script_isactive(sieve_dir, oldname->s)) {
    result = setactive(conn, newname);
  }
  else {
    prot_printf(conn,"OK\r\n");
    result = TIMSIEVE_OK;
  }

  if (result == TIMSIEVE_OK) sync_log_sieve(sieved_userid);
  return result;
}

int cmd_havespace(struct protstream *conn, const struct buf *sieve_name, unsigned long num)
{
    int result;
    int maxscripts;
    extern unsigned long maxscriptsize;

    result = scriptname_valid(sieve_name);
    if (result!=TIMSIEVE_OK)
    {
        prot_printf(conn,"NO \"Invalid script name\"\r\n");
        return result;
    }

    /* see if the size of the script is too big */
    if (num > maxscriptsize)
    {
        prot_printf(conn,
                    "NO (QUOTA/MAXSIZE) \"Script size is too large. "
                    "Max script size is %ld bytes\"\r\n",
                    maxscriptsize);
        return TIMSIEVE_FAIL;
    }

    /* see if this would put the user over quota */
    maxscripts = config_getint(IMAPOPT_SIEVE_MAXSCRIPTS);

    if (countscripts(sieve_name->s)+1 > maxscripts)
    {
        prot_printf(conn,
                    "NO (QUOTA/MAXSCRIPTS) \"You are only allowed %d scripts on this server\"\r\n",
                    maxscripts);
        return TIMSIEVE_FAIL;
    }


    prot_printf(conn,"OK\r\n");
    return TIMSIEVE_OK;
}
