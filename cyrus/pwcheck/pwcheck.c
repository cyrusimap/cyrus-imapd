/* pwcheck.c -- Unix pwcheck daemon
 # Copyright 1998 Carnegie Mellon University
 # 
 # No warranties, either expressed or implied, are made regarding the
 # operation, use, or results of the software.
 #
 # Permission to use, copy, modify and distribute this software and its
 # documentation is hereby granted for non-commercial purposes only
 # provided that this copyright notice appears in all copies and in
 # supporting documentation.
 #
 # Permission is also granted to Internet Service Providers and others
 # entities to use the software for internal purposes.
 #
 # The distribution, modification or sale of a product which uses or is
 # based on the software, in whole or in part, for commercial purposes or
 # benefits requires specific, additional permission from:
 #
 #  Office of Technology Transfer
 #  Carnegie Mellon University
 #  5000 Forbes Avenue
 #  Pittsburgh, PA  15213-3890
 #  (412) 268-4387, fax: (412) 268-7395
 #  tech-transfer@andrew.cmu.edu
 *
 */
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <sys/stat.h>

extern int errno;

/*
 * Unix pwcheck daemon-authenticated login (shadow password)
 */

int
main()
{
    char fnamebuf[1024];
    int s;
    int c;
    struct sockaddr_un srvaddr;
    struct sockaddr_un clientaddr;
    int r;
    int len;
    mode_t oldumask;

    s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s == -1) {
	perror("socket");
	exit(1);
    }

    strcpy(fnamebuf, STATEDIR);
    strcat(fnamebuf, "/pwcheck/pwcheck");

    (void) unlink(fnamebuf);

    memset((char *)&srvaddr, 0, sizeof(srvaddr));
    srvaddr.sun_family = AF_UNIX;
    strcpy(srvaddr.sun_path, fnamebuf);
    /* Most systems make sockets 0777 no matter what you ask for.
       Known exceptions are Linux and DUX. */
    oldumask = umask((mode_t) 0); /* for Linux, which observes the umask when
			    setting up the socket */
    r = bind(s, (struct sockaddr *)&srvaddr, sizeof(srvaddr));
    if (r == -1) {
	perror(fnamebuf);
	exit(1);
    }
    umask(oldumask); /* for Linux */
    chmod(fnamebuf, (mode_t) 0777); /* for DUX, where this isn't the default.
				    (harmlessly fails on some systems) */	
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
    char request[1024];
    int start, n;
    char *reply;
    extern char *pwcheck();
    
    start = 0;
    while (start < sizeof(request) - 1) {
	n = read(c, request+start, sizeof(request) - 1 - start);
	if (n < 1) {
	    reply = "Error reading request";
	    goto sendreply;
	}
		
	start += n;

	if (request[start-1] == '\0' && strlen(request) < start) {
	    break;
	}
    }

    if (start >= sizeof(request) - 1) {
	reply = "Request too big";
    }
    else {
	reply = pwcheck(request, request + strlen(request) + 1);
    }

sendreply:

    retry_write(c, reply, strlen(reply));
    close(c);
}
  
