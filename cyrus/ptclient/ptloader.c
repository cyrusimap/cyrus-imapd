/* ptloader.c -- AFS group loader daemon
 */
/*
 * Copyright (c) 1996-2000 Carnegie Mellon University.  All rights reserved.
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

static char rcsid[] __attribute__((unused)) = 
      "$Id: ptloader.c,v 1.29 2003/01/10 17:44:56 rjs3 Exp $";

#include <config.h>

#include <string.h>
#include "auth_krb_pts.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/param.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <krb.h>
#include <rx/rxkad.h>
#include <afs/auth.h>
#include <com_err.h>

#include <db.h>

#include "xmalloc.h"
#include "lock.h"
#include "retry.h"
#include "hash.h"

/* blame transarc i've been told */
#ifndef AFSCONF_CLIENTNAME
#include <afs/dirpath.h>
#define AFSCONF_CLIENTNAME AFSDIR_CLIENT_ETC_DIRPATH
#endif

static char ptclient_debug = 0;

static void newclient();
static int reauth();

int
key_to_key(user,instance,realm,passwd,key)
    char *user, *instance, *realm, *passwd;
    C_Block key;
{
  memcpy(key, passwd, sizeof(des_cblock));
  return (0);
}

#define AUTH_USER "postman"
#define AUTH_INTERVAL (60*60*10) /* every 10 hours*/

int
main(argc, argv)
     int argc;
     char *argv[];
{
    int s, c, r, len; 
    int opt;
    struct sockaddr_un srvaddr;
    struct sockaddr_un clientaddr;
    char fnamebuf[1024];
    mode_t oldumask;
    int listen_queue = 5;
    extern char *optarg;
    char *user;
    char *pw_file = NULL;
    time_t next_auth_time = 0;
    unsigned int auth_interval;
    int do_reauth = 1, use_srvtab = 0;
    int use_newpag = 0;

    auth_interval = AUTH_INTERVAL;
    user = AUTH_USER;

    /* normally LOCAL6, but do this while we're logging keys */
    openlog("ptloader", LOG_PID, LOG_LOCAL7);
    syslog(LOG_NOTICE, "starting: $Id: ptloader.c,v 1.29 2003/01/10 17:44:56 rjs3 Exp $");

    while ((opt = getopt(argc, argv, "Uspd:l:f:u:t:")) != EOF) {
	switch (opt) {
	case 'U':
	    do_reauth = 0;
	    break;
	case 's':
	    use_srvtab = 1;
	    break;
	case 'p':
	    use_newpag = 1;
	    break;
	case 'd':
	    ptclient_debug = atoi(optarg);
	    if (ptclient_debug < 1) {
		ptclient_debug = 1;
	    }
	    break;
	case 'l':
	    listen_queue = atoi(optarg);
	    break;
	case 'f':
	    pw_file = optarg;
	    break;
	case 'u':
	    user = optarg;
	    break;
	case 't':
	    auth_interval = atoi(optarg);
	    break;
	case '?':
	    fprintf(stderr,"usage: -Udlfut"
		    "\n\t-d <n>\tdebug level"
		    "\n\t-l <n>\tlisten(2) queue backlog"
		    "\n\t-U\tDo not reauthenticate"
		    "\n\t-s\tAssume file is srvtab"
		    "\n\t-u <userid>\tuser to authenticate as"
		    "\n\t-f <file>\tfile for the users password"
		    "\n\t-t <seconds>\tinterval between authentications"
		    "\n\t-p\tset a new pag"
		    "\n");
	    syslog(LOG_ERR, "Invalid command line option specified");
	    exit(-1);
	    break;
	default:
	    break;
	    /* just pass through */
	}
    }

    if (listen_queue < 5) {
	if (ptclient_debug) {
	    syslog(LOG_ERR, "Invalid listen_queue specified (%d), resetting to 5",
		   listen_queue);
	    listen_queue = 5;
	}
    }

    s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s == -1) {
	syslog(LOG_ERR, "socket: %m");
	exit(1);
    }

    strcpy(fnamebuf, STATEDIR);
    strcat(fnamebuf, PTS_DBSOCKET);

    (void) unlink(fnamebuf);
    memset((char *)&srvaddr, 0, sizeof(srvaddr));
    srvaddr.sun_family = AF_UNIX;
    strcpy(srvaddr.sun_path, fnamebuf);
    /* Most Unixen make sockets 777 by default
       Not Linux, not DUX. */
    oldumask = umask((mode_t) 0); /* for Linux */
    r = bind(s, (struct sockaddr *)&srvaddr, sizeof(srvaddr));
    umask(oldumask); /* for Linux */
    chmod(fnamebuf, 0777); /* for DUX */
    if (r == -1) {
	syslog(LOG_ERR, "bind: %s: %m", fnamebuf);
	exit(1);
    }
    r = listen(s, listen_queue);
    if (r == -1) {
	syslog(LOG_ERR, "listen: %m");
	exit(1);
    }

    if (do_reauth) {
	if (pw_file == NULL) {
	    syslog(LOG_ERR, "Invalid password file specified. Exiting...");
	    exit(-1);
	}
	if (reauth(user, pw_file, use_newpag, use_srvtab) < 0) {
	    syslog(LOG_ERR, "initialization failed. exiting...");
	    exit(-1);
	}
      
	next_auth_time = time(0) + auth_interval;

	if (ptclient_debug > 10) {
	    syslog(LOG_DEBUG, "Authenticated as %s; next reauth at %d", 
		   user, next_auth_time);
	}
    } else {
	r = pr_Initialize (1L, AFSCONF_CLIENTNAME, 0);
        if (r) {
            syslog(LOG_DEBUG, "pr_Initialize failed: %d", r);
	}
    }

    len = sizeof(clientaddr);
    for (;;) {
	c = accept(s, (struct sockaddr *)&clientaddr, &len);
	if (c == -1) {
	    syslog(LOG_WARNING, "WARNING: accept: %m");
	    continue;
	}

	if (do_reauth && (time(0) > next_auth_time)) {
	    if (ptclient_debug > 10) {
		syslog(LOG_DEBUG, "Reauthenticating at %d", time(0));
	    }
	    if (reauth(user, pw_file, use_newpag, use_srvtab) < 0) {
		syslog(LOG_ERR, "error reauthenticating. continuing...");
	    } else {
		next_auth_time = time(0) + auth_interval;
		if (ptclient_debug) {
		    syslog(LOG_DEBUG, "Successfully re-authenticated.");
		}
	    }
	}

	newclient(c);
    }
    /* NOTREACHED */
}

static void
newclient(c)
int c;
{
    char fnamebuf[1024];
    char keyinhex[512];
    const char *reply;
    DB *ptdb;
    DBT key, data;
    char indata[PTS_DB_KEYSIZE];
    char user[PR_MAXNAMELEN];
    char user_tmp[PR_MAXNAMELEN];
    namelist groups;
    int i,fd,rc;
    size_t size;
    struct auth_state *newstate;

    memset(&key, 0, sizeof(key));
    memset(&data, 0, sizeof(data));

    (void)memset(&size, 0, sizeof(size));
    if (read(c, &size, sizeof(size_t)) < 0) {
        syslog(LOG_ERR, "socket (size): %m");
        reply = "Error reading request (size)";
        goto sendreply;
    }

    if (size > PTS_DB_KEYSIZE)  {
	syslog(LOG_ERR, "size sent %d is greater than buffer size %d", 
	       size, PTS_DB_KEYSIZE);
	reply = "Error: invalid request size";
	goto sendreply;
    }

    memset(&indata, 0, PTS_DB_KEYSIZE);
    if (read(c, &indata, size) < 0) {
        syslog(LOG_ERR,"socket (indata; size = %d): %m", size);
        reply = "Error reading request (key)";
        goto sendreply;
    }

    /* convert request to hex */
    for (i=0; i<size; i++) {
	sprintf(keyinhex+(2*i), "%.2x", indata[i]);
    }

    memset(&user, 0, sizeof(user));
    if (read(c, &user, PR_MAXNAMELEN) < 0) {
        syslog(LOG_ERR, "socket(user; size = %d; key = %s): %m", 
	       size, keyinhex);
        reply = "Error reading request (user)";
        goto sendreply;
    }      

    if (ptclient_debug) {
	syslog(LOG_DEBUG, "user %s, cacheid %s", user, keyinhex);
    }

    memset(&groups, 0, sizeof(groups));
    groups.namelist_len = 0;
    groups.namelist_val = NULL;

    /* afs is going to overwrite our nice canonicalized user if we don't
     * give it something else to chew on */
    strlcpy(user_tmp, user, sizeof(user_tmp));
    if ((rc = pr_ListMembers(user_tmp, &groups))) {
        syslog(LOG_ERR, "pr_ListMembers %s: %s", user, error_message(rc));
        reply = error_message(rc);
        goto sendreply;
    }

    key.data = indata;
    key.size = size;

    /* fill in our new state structure */
    data.size = sizeof(struct auth_state) + 
	(groups.namelist_len * sizeof(struct auth_ident));
    newstate = (struct auth_state *) xmalloc(data.size);
    data.data = newstate;
    strcpy(newstate->userid.id, user);
    newstate->userid.hash = hash(user);
    kname_parse(newstate->aname, newstate->inst, newstate->realm, user);
    newstate->mark = time(0);
    newstate->ngroups = groups.namelist_len;
    /* store group list in contiguous array for easy storage in the database */
    memset(newstate->groups, 0, newstate->ngroups * sizeof(struct auth_ident));
    for (i = 0; i < newstate->ngroups; i++) {
        strcpy(newstate->groups[i].id, groups.namelist_val[i]);
	newstate->groups[i].hash = hash(groups.namelist_val[i]);
	/* don't free groups.namelist_val[i]. Something else currently
	 * takes care of that data. 
	 */
    }
    if (groups.namelist_val != NULL) {
	free(groups.namelist_val);
    }

    /* lock database */
    strcpy(fnamebuf, STATEDIR);
    strcat(fnamebuf, PTS_DBLOCK);
    fd=open(fnamebuf, O_CREAT|O_TRUNC|O_RDWR, 0664);
    if (fd == -1) {
        syslog(LOG_ERR, "IOERROR: creating lock file %s: %m", fnamebuf);
        reply="Couldn't create lock file";
	free(newstate);
        goto sendreply;
    }
    if (lock_blocking(fd) < 0) {
        syslog(LOG_ERR, "IOERROR: locking lock file %s: %m", fnamebuf);
        reply ="Couldn't lock database";
	free(newstate);
        goto sendreply;
    }

    /* store to database */
    strcpy(fnamebuf, STATEDIR);
    strcat(fnamebuf, PTS_DBFIL);
    rc = db_create(&ptdb, NULL, 0);
    if (!rc) {
#if DB_VERSION_MAJOR == 4 && DB_VERSION_MINOR >= 1
	rc = ptdb->open(ptdb, NULL, fnamebuf, NULL, DB_HASH, DB_AUTO_COMMIT, 0664);
#else
	rc = ptdb->open(ptdb, fnamebuf, NULL, DB_HASH, 0, 0664);
#endif
    }
    if (rc == ENOENT) {
	rc = db_create(&ptdb, NULL, 0);
	if (!rc) {
#if DB_VERSION_MAJOR == 4 && DB_VERSION_MINOR >= 1
	    rc = ptdb->open(ptdb, NULL, fnamebuf, NULL, DB_HASH, DB_CREATE | DB_AUTO_COMMIT, 0664);
#else
	    rc = ptdb->open(ptdb, fnamebuf, NULL, DB_HASH, DB_CREATE, 0664);
#endif
	}
    }
    if (rc != 0) {
        syslog(LOG_ERR, "IOERROR: opening database %s: %s", fnamebuf,
	       db_strerror(rc));
        close(fd);
        reply="Couldn't open database";
	free(newstate);
        goto sendreply;
    }

    rc = ptdb->put(ptdb, NULL, &key, &data, 0);
    free(newstate);
    ptdb->close(ptdb, 0);
    close(fd);
    if (rc != 0) {
        syslog(LOG_ERR, "IOERROR: writing header into database %s: %s", 
	       fnamebuf, db_strerror(rc));
        reply = "Couldn't write database";
        goto sendreply;
    }

    /* and we're done */
    reply = "OK";
    
 sendreply:
    if (retry_write(c, reply, strlen(reply)) <0) {
	syslog(LOG_WARNING, "retry_write: %m");
    }
    close(c);
}

static int
reauth(name, file, newpag, is_srvtab) 
     char *name;
     char *file;
     int newpag;
     int is_srvtab;
{
  int rc;
  char *reason;
  char password[256];
  char *c;
  FILE *fp;
  static char pr_init = 0;

  if (pr_init) {
#ifdef HAVE_PR_END
    /* this doesn't really do anything other than attempt to
     * clean up the ubik connection. Calling pr_Initialize
     * later in the code will most likely leak memory until 
     * the AFS libraries get cleaned up.
     */
    pr_End();
#else
    /* this destroys existing ubik connections... */
    pr_Initialize(1L,"/", 0);
    if (!pr_Initialize (1L, AFSCONF_CLIENTNAME, 0))
#endif
  }

  if (is_srvtab) {
    /* Not done yet */
    char lrealm[REALM_SZ];
    int bkvno = 0, kerrno;
    C_Block use_as_key;
    CREDENTIALS c;
    struct ktc_principal aserver;
    struct ktc_principal aclient;
    struct ktc_token atoken;


    if (newpag)
      setpag();
    
    if ((kerrno = krb_get_lrealm(lrealm, 1)) != 0) {
      syslog(LOG_ERR, "krb_get_lrealm: %d", kerrno);
      return(-1);
    }

    (void)memset(password, 0, sizeof(password));
    kerrno = read_service_key(name, "", lrealm, bkvno, file, (char *)password);
    if (kerrno != 0) {
      syslog(LOG_ERR, "read_service_key: %d", kerrno);
      return(-1);
    }
    (void)memcpy(use_as_key, password, 8);
    kerrno = krb_get_in_tkt(name, "", lrealm, "krbtgt", lrealm, 
			    DEFAULT_TKT_LIFE, key_to_key, NULL, use_as_key);
    (void)memset(use_as_key, 0, sizeof(use_as_key));
    if (kerrno != 0) {
      syslog(LOG_ERR, "get_in_tkt: %d", kerrno);
      return(-1);
    }
    if ((kerrno = krb_get_cred("afs", "", lrealm, &c)) != 0) {
      if ((kerrno = get_ad_tkt("afs", "", lrealm, 255)) != 0) {
	syslog(LOG_ERR,"get_ad_tkt: %d", kerrno);
        return(-1);
      } else {
        if ((kerrno = krb_get_cred("afs", "", lrealm, &c)) != 0) {
	  syslog(LOG_ERR,"get_cred: %d", kerrno);
          return(-1);
        }
      }
    }
    strncpy(aserver.name, "afs", MAXKTCNAMELEN - 1);
    strncpy(aserver.instance, "", MAXKTCNAMELEN - 1);
    strncpy(aserver.cell, lrealm, MAXKTCREALMLEN - 1);
    {
      char *t = aserver.cell;
      char *s = aserver.cell;
      int c;
      while ((c = *t++)) {
        if (isupper((unsigned char) c)) c = tolower(c);
        *s++ = c;
      }
      *s++ = 0;
    }
    
    atoken.kvno = c.kvno;
    atoken.startTime = c.issue_date;
#ifdef HAVE_KRB_LIFE_TO_TIME
    atoken.endTime = krb_life_to_time(c.issue_date, c.lifetime);
#else
    atoken.endTime = c.issue_date + ((unsigned char)c.lifetime * 5 * 60);
#endif
    memcpy(&atoken.sessionKey, c.session, 8);
    atoken.ticketLen = c.ticket_st.length;
    memcpy(atoken.ticket, c.ticket_st.dat, atoken.ticketLen);
    
    if ((kerrno = ktc_SetToken(&aserver, &atoken, &aclient)) != 0) {
      syslog(LOG_ERR, "ktc_SetToken: %d", kerrno);
      return(-1);
    }
  } else { /* not using srvtab but using a regular file */
    if ((fp = fopen(file, "r")) == NULL) {
      syslog(LOG_ERR, "fopen: password file: %m");
      return(-1);
    }
    if (fgets(password, sizeof(password), fp) == NULL) {
      syslog(LOG_ERR, "fgets: unable to read password: %m");
      return(-1);
    }
    if (feof(fp) != 0) {
      syslog(LOG_ERR, "internal error: password longer than max length(%d)\n", 
	     sizeof(password));
      return(-1);
    }
    fclose(fp);
    
    /* if the file has an ending \n, nuke it. */
    if ((c = strrchr(password, '\n')) != NULL) {
      *c='\0';
    }
    /* so we probably should allow instances but it isn't worth
     * the overhead right now 
     */
    if (ka_UserAuthenticate(name, /*inst*/ "", /*realm*/0, password, 
			    newpag, &reason)) 
      {
	syslog(LOG_ERR, "Unable to authenticate to AFS: %s", reason);
	return (-1);
      }
    (void)memset(&password, 0, sizeof(password));
  }

  if ((rc = pr_Initialize(1L, AFSCONF_CLIENTNAME, 0))) {
    syslog(LOG_ERR, "pr_Initialize: %s", error_message(rc));
    return (-1);
  }
  pr_init = 1;

  return 0;
}


/* we need to have this function here 'cause libcyrus.a 
 * makes calls to this function. 
 */
void fatal(const char *msg, int exitcode)
{
    syslog(LOG_ERR, "%s", msg);
    exit(-1);
}
/* $Header: /mnt/data/cyrus/cvsroot/src/cyrus/ptclient/ptloader.c,v 1.29 2003/01/10 17:44:56 rjs3 Exp $ */
