/* pwcheck.c -- Unix pwcheck daemon
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
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>

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
    r = bind(s, (struct sockaddr *)&srvaddr, sizeof(srvaddr));
    if (r == -1) {
	perror(fnamebuf);
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
  
