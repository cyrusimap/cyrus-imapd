/* ptloader.c -- AFS group loader daemon
 *
 * Copyright 1996, Carnegie Mellon University.  All Rights Reserved.
 * 
 * This software is made available for academic and research
 * purposes only.  No commercial license is hereby granted.
 * Copying and other reproduction is authorized only for research,
 * education, and other non-commercial purposes.  No warranties,
 * either expressed or implied, are made regarding the operation,
 * use, or results of the software.  Such a release does not permit
 * use of the code for commercial purposes or benefits by anyone
 * without specific, additional permission by the owner of the code.
 *
 */

static char rcsid[] = "$Id: ptloader.c,v 1.8 1998/03/06 16:45:26 wcw Exp $";
#include <string.h>
#include "auth_krb_pts.h"
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <com_err.h>


static char ptclient_debug = 0;

static void newclient();
static int reauth();
int fatal();

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
    extern int optind;
    char *user, *pw_file;
    time_t next_auth_time;
    unsigned int auth_interval;
    int do_reauth = 1;

    auth_interval = AUTH_INTERVAL;
    user = AUTH_USER;

    /* normally LOCAL6, but do this while we're logging keys */
    openlog(PTCLIENT, LOG_PID, LOG_LOCAL7);
    syslog(LOG_DEBUG, "starting: $Id: ptloader.c,v 1.8 1998/03/06 16:45:26 wcw Exp $");

    while ((opt = getopt(argc, argv, "Ud:l:f:u:t:")) != EOF) {
      switch (opt) {
      case 'U':
	do_reauth = 0;
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
	fprintf(stderr,"usage: -dlfut"
		"\n\t-d <n>\tdebug level"
		"\n\t-l <n>\tlisten(2) queue backlog"
		"\n\t-U\tDo not reauthenticate"
		"\n\t-u <userid>\tuser to authenticate as"
		"\n\t-f <file>\tfile for the users password"
		"\n\t-t <seconds>\tinterval between authentications"
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
      if (reauth(user, pw_file, 1) < 0) {
	syslog(LOG_ERR, "initialization failed. exiting...");
	exit(-1);
      }
      
      next_auth_time = time(0) + auth_interval;

      if (ptclient_debug > 10) {
	syslog(LOG_DEBUG, "Authenticated as %s; next reauth at %d", 
	       user, next_auth_time);
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
	if (reauth(user, pw_file, 0) < 0) {
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
    /*NOTREACHED*/
}

static void
newclient(c)
int c;
{
    char fnamebuf[1024];
    char keyinhex[512];
    const char *reply;
    HASHINFO info;
    DB *ptdb;
    char indata[PR_MAXNAMELEN+4];
    char user[PR_MAXNAMELEN];
    namelist groups;
    int i,fd,rc;
    DBT key,dataheader,datalist;
    ptluser us;
    char (*list)[][PR_MAXNAMELEN];
    size_t size;

    (void)memset(&size, 0, sizeof(size));
    if (read(c, &size, sizeof(size_t)) < 0) {
        syslog(LOG_ERR, "socket (size): %m");
        reply = "Error reading request (size)";
        goto sendreply;
    }

    (void)memset(&indata,0,sizeof(indata));
    if (read(c, &indata, size) < 0) {
        syslog(LOG_ERR,"socket (indata; size = %d): %m", size);
        reply = "Error reading request (key)";
        goto sendreply;
    }

    for (i=0; i<size; i++) 
      sprintf(keyinhex+(2*i), "%.2x", indata[i]);

    (void)memset(&user, 0, sizeof(user));
    if (read(c, &user, PR_MAXNAMELEN) < 0) {
        syslog(LOG_ERR, "socket(user; size = %d; key = %s): %m", size, keyinhex);
        reply = "Error reading request (user)";
        goto sendreply;
    }      

    if (ptclient_debug) {
      syslog(LOG_DEBUG, "user %s, cacheid %s", user, keyinhex);
    }

    (void)memset(&info, 0, sizeof(info));
    info.hash = hashfn;
    info.lorder = 0;
    info.bsize = 2048;
    info.cachesize = 20480;
    info.ffactor = 8;

    (void)memset(&groups, 0, sizeof(groups));
    groups.namelist_len = 0;
    groups.namelist_val = NULL;
    
    if ((rc = pr_ListMembers(user, &groups))) {
        syslog(LOG_ERR, "pr_ListMembers %s: %s", user, error_message(rc));
        reply = error_message(rc);
        goto sendreply;
    }

    (void)memset(&key, 0, sizeof(key));
    key.data = indata;
    key.size = size;

    us.ngroups = groups.namelist_len;
    us.cached = time(0);
    /* store group list in contiguous array for easy storage in the database */
    list = (char (*)[][PR_MAXNAMELEN])xmalloc(us.ngroups*PR_MAXNAMELEN);
    memset(list, 0, us.ngroups * PR_MAXNAMELEN);
    for (i=0; i<us.ngroups; i++){
        strcpy((*list)[i], groups.namelist_val[i]);
	free(groups.namelist_val[i]);
    }
    if (groups.namelist_val != NULL) {
      free(groups.namelist_val);
    }

    /* build and store a header record for this user */
    strcpy(us.user, user);
    
    (void)memset(&dataheader, 0, sizeof(dataheader));
    dataheader.data = &us;
    dataheader.size = sizeof(ptluser);
    datalist.data = list;
    datalist.size = us.ngroups*PR_MAXNAMELEN;
    indata[key.size-4] = 'H';

    strcpy(fnamebuf, STATEDIR);
    strcat(fnamebuf, PTS_DBLOCK);
    fd=open(fnamebuf, O_CREAT|O_TRUNC|O_RDWR, 0664);
    if (fd == -1) {
        syslog(LOG_ERR, "IOERROR: creating lock file %s: %m", fnamebuf);
        reply="Couldn't create lock file";
	free(list);
        goto sendreply;
    }
    if (lock_blocking(fd) < 0) {
        syslog(LOG_ERR, "IOERROR: locking lock file %s: %m", fnamebuf);
        reply="Couldn't lock database";
	free(list);
        goto sendreply;
    }
    strcpy(fnamebuf, STATEDIR);
    strcat(fnamebuf, PTS_DBFIL);
    ptdb=dbopen(fnamebuf, O_RDWR, 0, DB_HASH, &info);
    if (ptdb == NULL) {
        syslog(LOG_ERR, "IOERROR: opening database %s: %m", fnamebuf);
        close(fd);
        reply="Couldn't open database";
	free(list);
        goto sendreply;
    }
    if (ptclient_debug > 10) {
      for (i=0; i<size; i++) 
	sprintf(keyinhex+(2*i), "%.2x", indata[i]);
      syslog(LOG_DEBUG, "user %s: header key: %s", user, keyinhex);
    }

    rc=PUT(ptdb, &key, &dataheader, 0);
    if (rc < 0) {
        syslog(LOG_ERR, "IOERROR: writing header into database %s: %m", fnamebuf);
        CLOSE(ptdb);
        close(fd);
        reply="Couldn't write database";
	free(list);
        goto sendreply;
    }

    /* store the grouplist */
    indata[key.size-4] = 'D';
    if (ptclient_debug > 10) {
      for (i=0; i<size; i++) 
	sprintf(keyinhex+(2*i), "%.2x", indata[i]);
      syslog(LOG_DEBUG, "user %s: grouplist key: %s", user, keyinhex);
    }

    rc=PUT(ptdb, &key, &datalist, 0);
    if (rc < 0) {
        syslog(LOG_ERR, "IOERROR: writing data into database %s: %m", fnamebuf);
	/* We don't do any cleanup as this is the last function in line. 
	 * if we actually exit here, don't forget to clean up. */
    }
    CLOSE(ptdb);
    close(fd);

    /* and we're done */
    free(list);
    reply="OK";
    
sendreply:
    if (retry_write(c, reply, strlen(reply)) <0) {
      syslog(LOG_WARNING, "retry_write: %m");
    }
    close(c);
}

static int
reauth(name, file, newpag) 
     char *name;
     char *file;
     int newpag;
{
  int rc;
  char *reason;
  char password[256];
  char *c;
  FILE *fp;
  static char pr_init = 0;

  if (pr_init) {
    /* this doesn't really do anything other than attempt to
     * clean up the ubik connection. Calling pr_Initialize
     * later in the code will most likely leak memory until 
     * the AFS libraries get cleaned up.
     */
    pr_End();
  }

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
			  newpag, &reason)) {
    syslog(LOG_ERR, "Unable to authenticate to AFS: %s", reason);
    return (-1);
  }
  (void)memset(&password, 0, sizeof(password));

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
int
fatal(msg, exitcode)
char *msg;
int exitcode;
{
  syslog(LOG_ERR, "%s", msg);
  exit(-1);
}
/* $Header: /mnt/data/cyrus/cvsroot/src/cyrus/ptclient/ptloader.c,v 1.8 1998/03/06 16:45:26 wcw Exp $ */
