/* service.c -- skeleton for Cyrus service; calls the real main
 *
 * Copyright 2000 Carnegie Mellon University
 * 
 * No warranties, either expressed or implied, are made regarding the
 * operation, use, or results of the software.
 *
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted for non-commercial purposes only
 * provided that this copyright notice appears in all copies and in
 * supporting documentation.
 *
 * Permission is also granted to Internet Service Providers and others
 * entities to use the software for internal purposes.
 *
 * The distribution, modification or sale of a product which uses or is
 * based on the software, in whole or in part, for commercial purposes or
 * benefits requires specific, additional permission from:
 *
 *  Office of Technology Transfer
 *  Carnegie Mellon University
 *  5000 Forbes Avenue
 *  Pittsburgh, PA  15213-3890
 *  (412) 268-4387, fax: (412) 268-7395
 *  tech-transfer@andrew.cmu.edu
 */

/* $Id: service.c,v 1.1 2000/02/15 22:21:53 leg Exp $ */
#include <config.h>

#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <syslog.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include "config.h"

#include "service.h"

/* number of times this service has been used */
static int use_count = 0;

void notify_master(int fd, int msg)
{
    if (write(fd, &msg, sizeof(msg)) != sizeof(msg)) {
	syslog(LOG_ERR, "unable to tell master %x: %m", msg);
    }
}

int main(int argc, char **argv, char **envp)
{
    char name[64];
    int fdflags;
    int fd;

    snprintf(name, sizeof(name) - 1, "service-%s", argv[0]);
    config_init(name);

    syslog(LOG_DEBUG, "executed");
    
    /* set close on exec */
    fdflags = fcntl(LISTEN_FD, F_GETFD, 0);
    if (fdflags != -1) fdflags = fcntl(LISTEN_FD, F_SETFD, 
				       fdflags | FD_CLOEXEC);
    if (fdflags == -1) {
	syslog(LOG_ERR, "unable to set close on exec: %m");
	notify_master(STATUS_FD, SERVICE_UNAVAILABLE);
	return 1;
    }
    fdflags = fcntl(STATUS_FD, F_GETFD, 0);
    if (fdflags != -1) fdflags = fcntl(STATUS_FD, F_SETFD, 
				       fdflags | FD_CLOEXEC);
    if (fdflags == -1) {
	syslog(LOG_ERR, "unable to set close on exec: %m");
	notify_master(STATUS_FD, SERVICE_UNAVAILABLE);
	return 1;
    }

    if (service_init(argc, argv, envp) != 0) {
	notify_master(STATUS_FD, SERVICE_UNAVAILABLE);
	return 1;
    }

    for (;;) {
	/* ok, listen to this socket until someone talks to us */
	fd = -1;
	while (fd < 0) { /* loop until we succeed */
	    fd = accept(LISTEN_FD, NULL, NULL);
	    if (fd < 0) {
		switch (errno) {
		case ENETDOWN:
		case EPROTO:
		case ENOPROTOOPT:
		case EHOSTDOWN:
		case ENONET:
		case EHOSTUNREACH:
		case EOPNOTSUPP:
		case ENETUNREACH:
		case EAGAIN:
		    break;
		default:
		    syslog(LOG_ERR, "accept failed: %m");
		    notify_master(STATUS_FD, SERVICE_UNAVAILABLE);
		    return 1;
		}
	    }
	}
	
	syslog(LOG_DEBUG, "accepted connection");
	notify_master(STATUS_FD, SERVICE_UNAVAILABLE);

	if (dup2(fd, 0) < 0) {
	    syslog(LOG_ERR, "can't duplicate accepted socket: %m");
	    exit(1);
	}
	if (dup2(fd, 1) < 0) {
	    syslog(LOG_ERR, "can't duplicate accepted socket: %m");
	    exit(1);
	}
	if (dup2(fd, 2) < 0) {
	    syslog(LOG_ERR, "can't duplicate accepted socket: %m");
	    exit(1);
	}

	close(fd);
	
	use_count++;
	service_main(argc, argv, envp);
	/* if we returned, we can service another client with this process */
	if (use_count >= MAX_USE) break;

	notify_master(STATUS_FD, SERVICE_AVAILABLE);
    }

    return 0;
}
