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

/* $Id: service.c,v 1.33 2002/06/03 18:22:34 rjs3 Exp $ */

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
#include <sys/time.h>
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
#include <string.h>

#include "service.h"

extern int optind;
extern char *optarg;

/* number of times this service has been used */
static int use_count = 0;
static int verbose = 0;
static int gotalrm = 0;
static int lockfd = -1;

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
extern const char *config_dir;

static int getlockfd(char *service)
{
    char lockfile[1024];
    int fd;

    snprintf(lockfile, sizeof(lockfile), "%s/socket/%s.lock", 
	     config_dir, service);
    fd = open(lockfile, O_CREAT | O_RDWR, 0600);
    if (fd < 0) {
	syslog(LOG_ERR, 
	       "locking disabled: couldn't open socket lockfile %s: %m",
	       lockfile);
	lockfd = -1;
	return -1;
    }

    lockfd = fd;
    return 0;
}

static int lockaccept(void)
{
    struct flock alockinfo;
    int rc;

    /* setup the alockinfo structure */
    alockinfo.l_start = 0;
    alockinfo.l_len = 0;
    alockinfo.l_whence = SEEK_SET;

    if (lockfd != -1) {
	alockinfo.l_type = F_WRLCK;
	while ((rc = fcntl(lockfd, F_SETLKW, &alockinfo)) < 0 && 
	       errno == EINTR &&
	       !gotalrm)
	    /* noop */;
	
	if (rc < 0 && gotalrm) {
	    notify_master(STATUS_FD, MASTER_SERVICE_UNAVAILABLE);
	    service_abort(0);
	    return -1;
	}

	if (rc < 0) {
	    syslog(LOG_ERR, "fcntl: F_SETLKW: error getting accept lock: %m");
	    notify_master(STATUS_FD, MASTER_SERVICE_UNAVAILABLE);
	    service_abort(EX_OSERR);
	    return -1;
	}
    }

    return 0;
}

static int unlockaccept(void)
{
    struct flock alockinfo;
    int rc;

    /* setup the alockinfo structure */
    alockinfo.l_start = 0;
    alockinfo.l_len = 0;
    alockinfo.l_whence = SEEK_SET;

    if (lockfd != -1) {
	alockinfo.l_type = F_UNLCK;
	while ((rc = fcntl(lockfd, F_SETLKW, &alockinfo)) < 0 && 
	       errno == EINTR)
	    /* noop */;

	if (rc < 0) {
	    syslog(LOG_ERR, 
		   "fcntl: F_SETLKW: error releasing accept lock: %m");
	    notify_master(STATUS_FD, MASTER_SERVICE_UNAVAILABLE);
	    service_abort(EX_OSERR);
	    return -1;
	}
    }

    return 0;
}

static void sigalrm(int sig)
{
    /* syslog(LOG_DEBUG, "got signal %d", sig); */
    if (sig == SIGALRM) {
	gotalrm = 1;
    }
}

int setsigalrm(void)
{
    struct sigaction action;
    
    sigemptyset(&action.sa_mask);

    action.sa_flags = 0;
#ifdef SA_RESETHAND
    action.sa_flags |= SA_RESETHAND;
#endif
    action.sa_handler = sigalrm;
    if (sigaction(SIGALRM, &action, NULL) < 0) {
	syslog(LOG_ERR, "installing SIGALRM handler: sigaction: %m");
	return -1;
    }

    return 0;
}

int main(int argc, char **argv, char **envp)
{
    int fdflags;
    int fd;
    char *p = NULL, *service;
    struct request_info request;
    int opt;
    char *alt_config = NULL;
    int call_debugger = 0;
    int soctype;
    int typelen = sizeof(soctype);

    while ((opt = getopt(argc, argv, "C:D")) != EOF) {
	switch (opt) {
	case 'C': /* alt config file */
	    alt_config = optarg;
	    break;
	case 'D':
	    call_debugger = 1;
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

    p = getenv("CYRUS_SERVICE");
    if (p == NULL) {
	syslog(LOG_ERR, "could not getenv(CYRUS_SERVICE); exiting");
	exit(EX_SOFTWARE);
    }
    service = strdup(p);
    if (service == NULL) {
	syslog(LOG_ERR, "couldn't strdup() service: %m");
	exit(EX_OSERR);
    }
    config_init(alt_config, service);

    if (call_debugger) {
	char debugbuf[1024];
	int ret;
	const char *debugger = config_getstring("debug_command", NULL);
	if (debugger) {
	    snprintf(debugbuf, sizeof(debugbuf), debugger, 
		     argv[0], getpid(), service);
	    syslog(LOG_DEBUG, "running external debugger: %s", debugbuf);
	    ret = system(debugbuf); /* run debugger */
	    syslog(LOG_DEBUG, "debugger returned exit status: %d", ret);
	}
    }
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

    /* figure out what sort of socket this is */
    if (getsockopt(LISTEN_FD, SOL_SOCKET, SO_TYPE,
		   (char *) &soctype, &typelen) < 0) {
	syslog(LOG_ERR, "getsockopt: SOL_SOCKET: failed to get type: %m");
	notify_master(STATUS_FD, MASTER_SERVICE_UNAVAILABLE);
	return 1;
    }

    if (service_init(argc, argv, envp) != 0) {
	notify_master(STATUS_FD, MASTER_SERVICE_UNAVAILABLE);
	return 1;
    }

    getlockfd(service);
    for (;;) {
	/* ok, listen to this socket until someone talks to us */

	if (use_count > 0) {
	    /* we want to time out after 60 seconds, set an alarm */
	    if (setsigalrm() < 0) {
		notify_master(STATUS_FD, MASTER_SERVICE_UNAVAILABLE);
		service_abort(EX_OSERR);
	    }
	    gotalrm = 0;
	    alarm(REUSE_TIMEOUT);
	}

	/* lock */
	lockaccept();

	fd = -1;
	while (fd < 0 && !gotalrm) { /* loop until we succeed */
	    if (soctype == SOCK_STREAM) {
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
		    case EINTR:
			break;
			
		    default:
			syslog(LOG_ERR, "accept failed: %m");
			notify_master(STATUS_FD, MASTER_SERVICE_UNAVAILABLE);
			service_abort(EX_OSERR);
		    }
		}
	    } else {
		/* udp */
		struct sockaddr_in from;
		socklen_t fromlen;
		char ch;
		int r;
 
		fromlen = sizeof(from);
		r = recvfrom(LISTEN_FD, (void *) &ch, 1, MSG_PEEK,
			     (struct sockaddr *) &from, &fromlen);
		if (r == -1) {
		    syslog(LOG_ERR, "recvfrom failed: %m");
		    notify_master(STATUS_FD, MASTER_SERVICE_UNAVAILABLE);
		    service_abort(EX_OSERR);
		}
		fd = LISTEN_FD;
	    }
	}

	/* unlock */
	unlockaccept();

	if (fd < 0 && gotalrm) {
	    /* timed out */
	    notify_master(STATUS_FD, MASTER_SERVICE_UNAVAILABLE);
	    service_abort(0);
	}
	if (fd < 0) {
	    /* how did this happen? */
	    syslog(LOG_ERR, "accept() failed but we didn't catch it?");
	    notify_master(STATUS_FD, MASTER_SERVICE_UNAVAILABLE);
	    service_abort(EX_SOFTWARE);
	}

	/* cancel the alarm */
	alarm(0);
	gotalrm = 0;

	/* tcp only */
	if(soctype == SOCK_STREAM) {
	    libwrap_init(&request, service);

	    if (!libwrap_ask(&request, fd)) {
		/* connection denied! */
		close(fd);
		continue;
	    }
	}
	
	notify_master(STATUS_FD, MASTER_SERVICE_UNAVAILABLE);
	syslog(LOG_DEBUG, "accepted connection");

	if (fd != 0 && dup2(fd, 0) < 0) {
	    syslog(LOG_ERR, "can't duplicate accepted socket: %m");
	    service_abort(EX_OSERR);
	}
	if (fd != 1 && dup2(fd, 1) < 0) {
	    syslog(LOG_ERR, "can't duplicate accepted socket: %m");
	    service_abort(EX_OSERR);
	}
	if (fd != 2 && dup2(fd, 2) < 0) {
	    syslog(LOG_ERR, "can't duplicate accepted socket: %m");
	    service_abort(EX_OSERR);
	}

	/* tcp only */
	if(soctype == SOCK_STREAM) {
	    if (fd > 2) close(fd);
	}
	
	notify_master(STATUS_FD, MASTER_SERVICE_CONNECTION);
	use_count++;
	service_main(argc, argv, envp);
	/* if we returned, we can service another client with this process */

	if (use_count >= MAX_USE) {
	    break;
	}

	notify_master(STATUS_FD, MASTER_SERVICE_AVAILABLE);
    }

    return 0;
}
