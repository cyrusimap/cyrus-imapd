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

#include "auth_krb_pts.h"
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <com_err.h>

int
main()
{
    int s;
    int c;
    struct sockaddr_un srvaddr;
    struct sockaddr_un clientaddr;
    int r;
    int len;
    char fnamebuf[1024];
    mode_t oldumask;

    openlog(PTCLIENT, LOG_PID, LOG_LOCAL6);
    
    s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s == -1) {
	perror("socket");
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
	printf("bind: %s ", fnamebuf);
        perror("");
        exit(1);
    }
    r = listen(s, 5);
    if (r == -1) {
	perror("listen");
	exit(1);
    }
    for (;;) {
	len = sizeof(clientaddr);
	c = accept(s, (struct sockaddr *)&clientaddr, &len);
	if (c == -1) {
	    perror("accept");
	    continue;
	}

	newclient(c);
    }
}

newclient(c)
int c;
{
    char fnamebuf[1024];
    const char *reply;
    HASHINFO info;
    DB * ptdb;
    char indata[PR_MAXNAMELEN+4];
    char user[PR_MAXNAMELEN];
    namelist groups;
    int i,fd,rc;
    DBT key,dataheader,datalist;
    ptluser us;
    char (*list)[][PR_MAXNAMELEN];
    size_t size;
    memset(indata,0,PR_MAXNAMELEN+4);
    
    if (read(c, &size, sizeof(size_t)) < 0) {
        syslog(LOG_ERR, "read from socket: %m");
        reply = "Error reading request (size)";
        goto sendreply;
    }
    if (read(c, indata, size) < 0) {
        syslog(LOG_ERR,"read from socket: %m");
        reply = "Error reading request (key)";
        goto sendreply;
    }
    key.data = indata;
    key.size = size;
    if (read(c, user, PR_MAXNAMELEN) < 0) {
        syslog(LOG_ERR, "read from socket: %m");
        reply = "Error reading request (user)";
        goto sendreply;
    }      
#ifdef DEBUG
    printf("Ptclient got user %s\ncache val: ", user);
    for (i=0; i<size; i++) {
	if (isprint(indata[i])) {
	    printf("%c",indata[i]);
	}
	else {
	    printf("\\%.3o", indata[i]);
	}
    }
    printf("\n");
#endif
    info.hash = hashfn;
    info.lorder = 0;
    info.bsize = 2048;
    info.cachesize = 20480;
    info.ffactor = 8;
    /* Get group list from PTS */
    if ((rc = pr_Initialize(1L, AFSCONF_CLIENTNAME, 0))) {
        syslog(LOG_ERR, "pr_Initialize: %s", error_message(rc));
        reply = error_message(rc);
        goto sendreply;
    }
    groups.namelist_len = 0;
    groups.namelist_val = NULL;
    
    if ((rc = pr_ListMembers(user, &groups))) {
        syslog(LOG_ERR, "pr_ListMembers %s: %s", user, error_message(rc));
        reply = error_message(rc);
        goto sendreply;
    }
    us.ngroups = groups.namelist_len;
    us.cached = time(0);
    /* store group list in contiguous array for easy storage in the database */
    list = (char (*)[][PR_MAXNAMELEN])xmalloc(us.ngroups*PR_MAXNAMELEN);
    memset(list, 0, us.ngroups * PR_MAXNAMELEN);
    for (i=0; i<us.ngroups; i++){
        strcpy((*list)[i], groups.namelist_val[i]);
    }
    pr_End();
    /* build and store a header record for this user */
    strcpy(us.user, user);
    dataheader.data = &us;
    dataheader.size = sizeof(ptluser);
    datalist.data = list;
    datalist.size = us.ngroups*PR_MAXNAMELEN;
    indata[key.size-4] = 'H';
  
    strcpy(fnamebuf, STATEDIR);
    strcat(fnamebuf, PTS_DBLOCK);
    fd=open(fnamebuf, O_CREAT|O_TRUNC|O_RDWR, 0644);
    if (fd == -1) {
        syslog(LOG_ERR, "IOERROR: creating lock file %s: %m", fnamebuf);
        reply="Couldn't lock database";
        goto sendreply;
    }
    if (lock_blocking(fd) < 0) {
        syslog(LOG_ERR, "IOERROR: locking lock file %s: %m", fnamebuf);
        reply="Couldn't lock database";
        goto sendreply;
    }
    strcpy(fnamebuf, STATEDIR);
    strcat(fnamebuf, PTS_DBFIL);
    ptdb=dbopen(fnamebuf, O_RDWR, 0, DB_HASH, &info);
    if (!ptdb) {
        syslog(LOG_ERR, "IOERROR: opening database %s: %m", fnamebuf);
        close(fd);
        reply="Couldn't open database";
        goto sendreply;
    }
    rc=PUT(ptdb, &key, &dataheader, 0);
    if (rc < 0) {
        syslog(LOG_ERR, "IOERROR: writing database %s: %m", fnamebuf);
        CLOSE(ptdb);
        close(fd);
        reply="Couldn't write database";
        goto sendreply;
    }
    /* store the grouplist */
    indata[key.size-4] = 'D';
    rc=PUT(ptdb, &key, &datalist, 0);
    if (rc < 0) {
        syslog(LOG_ERR, "IOERROR: writing database %s: %m", fnamebuf);
        CLOSE(ptdb);
        close(fd);
    }
    CLOSE(ptdb);
    close(fd);
    /* and we're done */
    free(list);
    reply="OK";
    
#ifdef DEBUG
    printf("Ptclient suceeded\n");
#endif
sendreply:
    retry_write(c, reply, strlen(reply));
    close(c);
}

int fatal(msg, exitcode)
char *msg;
int exitcode;
{
    syslog(LOG_ERR, "%s", msg);
    exit(-1);
}

    
