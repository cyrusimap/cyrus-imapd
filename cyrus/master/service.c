/* service.c -- skeleton for Cyrus service; calls the real main
 *
 * Copyright (c) 2000 Carnegie Mellon University.  All rights reserved.
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
 */

/* $Id: service.c,v 1.20 2001/03/14 18:22:15 ken3 Exp $ */
#include <config.h>

#include <stdio.h>
#include <sys/time.h>
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
#include <stdlib.h>
#include <sysexits.h>

#include "service.h"

extern int optind;
extern char *optarg;

/* number of times this service has been used */
static int use_count = 0;
static int verbose = 0;

void notify_master(int fd, int msg)
{
    if (verbose) syslog(LOG_DEBUG, "telling master %d", msg);
    if (write(fd, &msg, sizeof(msg)) != sizeof(msg)) {
	syslog(LOG_ERR, "unable to tell master %x: %m", msg);
    }
}

#ifdef HAVE_LIBWRAP
#include <tcpd.h>

int allow_severity = LOG_DEBUG;
int deny_severity = LOG_ERR;

static void libwrap_init(struct request_info *r, char *service)
{
    request_init(r, RQ_DAEMON, service, 0);
}

static int libwrap_ask(struct request_info *r, int fd)
{
    int a;
    struct sockaddr_in sin;
    socklen_t len = sizeof(sin);
    
    /* is this a connection from the local host? */
    if (getpeername(fd, (struct sockaddr *) &sin, &len) == 0) {
	if (sin.sin_family == AF_UNIX) {
	    return 1;
	}
    }
    
    /* i hope using the sock_* functions are legal; it certainly makes
       this code very easy! */
    request_set(r, RQ_FILE, fd, 0);
    sock_host(r);

    a = hosts_access(r);
    if (!a) {
	syslog(deny_severity, "refused connection from %s", eval_client(r));
    }

    return a;
}

#else
struct request_info { int x; };

static void libwrap_init(struct request_info *r, char *service)
{

}

static int libwrap_ask(struct request_info *r, int fd)
{
    return 1;
}

#endif

extern void config_init(const char *, const char *);

int main(int argc, char **argv, char **envp)
{
    char name[64];
    int fdflags;
    int fd;
    char *p = NULL;
    struct request_info request;
    int opt;
    char *alt_config = NULL;

    while ((opt = getopt(argc, argv, "C:")) != EOF) {
	switch (opt) {
	case 'C': /* alt config file */
	    alt_config = optarg;
	    break;
	default:
	    break;
	}
    }
    optind = 1;

    p = getenv("CYRUS_VERBOSE");
    if (p) verbose = atoi(p) + 1;

    if (verbose > 30) {
	syslog(LOG_DEBUG, "waiting 15 seconds for debugger");
	sleep(15);
    }

    snprintf(name, sizeof(name) - 1, "service-%s", getenv("CYRUS_SERVICE"));
    config_init(alt_config, name);

    syslog(LOG_DEBUG, "executed");

    /* set close on exec */
    fdflags = fcntl(LISTEN_FD, F_GETFD, 0);
    if (fdflags != -1) fdflags = fcntl(LISTEN_FD, F_SETFD, 
				       fdflags | FD_CLOEXEC);
    if (fdflags == -1) {
	syslog(LOG_ERR, "unable to set close on exec: %m");
	notify_master(STATUS_FD, MASTER_SERVICE_UNAVAILABLE);
	return 1;
    }
    fdflags = fcntl(STATUS_FD, F_GETFD, 0);
    if (fdflags != -1) fdflags = fcntl(STATUS_FD, F_SETFD, 
				       fdflags | FD_CLOEXEC);
    if (fdflags == -1) {
	syslog(LOG_ERR, "unable to set close on exec: %m");
	notify_master(STATUS_FD, MASTER_SERVICE_UNAVAILABLE);
	return 1;
    }

    if (service_init(argc, argv, envp) != 0) {
	notify_master(STATUS_FD, MASTER_SERVICE_UNAVAILABLE);
	return 1;
    }

    for (;;) {
	/* ok, listen to this socket until someone talks to us */
	fd = -1;
	while (fd < 0) { /* loop until we succeed */
	    /* we should probably do a select() here and time out */
	    if (use_count > 0) {
		fd_set rfds;
		struct timeval tv;
		int r;

		FD_ZERO(&rfds);
		FD_SET(LISTEN_FD, &rfds);
		tv.tv_sec = REUSE_TIMEOUT;
		tv.tv_usec = 0;
		r = select(LISTEN_FD + 1, &rfds, NULL, NULL, &tv);
		if (!FD_ISSET(LISTEN_FD, &rfds)) {
		    notify_master(STATUS_FD, MASTER_SERVICE_UNAVAILABLE);
		    service_abort();
		    exit(0);
		}
	    }

	    fd = accept(LISTEN_FD, NULL, NULL);
	    if (fd < 0) {
		switch (errno) {
		case ENETDOWN:
#ifdef EPROTO
		case EPROTO:
#endif
		case ENOPROTOOPT:
		case EHOSTDOWN:
#ifdef ENONET
		case ENONET:
#endif
		case EHOSTUNREACH:
		case EOPNOTSUPP:
		case ENETUNREACH:
		case EAGAIN:
		    break;
		default:
		    syslog(LOG_ERR, "accept failed: %m");
		    notify_master(STATUS_FD, MASTER_SERVICE_UNAVAILABLE);
		    service_abort();
		    exit(EX_OSERR);
		}
	    }
	}
	
	libwrap_init(&request, getenv("CYRUS_SERVICE"));

	if (!libwrap_ask(&request, fd)) {
	    /* connection denied! */
	    close(fd);
	    continue;
	}
	
	syslog(LOG_DEBUG, "accepted connection");
	notify_master(STATUS_FD, MASTER_SERVICE_UNAVAILABLE);

	if (fd != 0 && dup2(fd, 0) < 0) {
	    syslog(LOG_ERR, "can't duplicate accepted socket: %m");
	    service_abort();
	    exit(EX_OSERR);
	}
	if (fd != 1 && dup2(fd, 1) < 0) {
	    syslog(LOG_ERR, "can't duplicate accepted socket: %m");
	    service_abort();
	    exit(EX_OSERR);
	}
	if (fd != 2 && dup2(fd, 2) < 0) {
	    syslog(LOG_ERR, "can't duplicate accepted socket: %m");
	    service_abort();
	    exit(EX_OSERR);
	}

	if (fd > 2) close(fd);
	
	use_count++;
	service_main(argc, argv, envp);
	/* if we returned, we can service another client with this process */
	if (use_count >= MAX_USE) break;

	notify_master(STATUS_FD, MASTER_SERVICE_AVAILABLE);
    }

    return 0;
}
