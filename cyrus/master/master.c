/* master.c -- IMAP master process to handle recovery, checkpointing, spawning
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

/* $Id: master.c,v 1.1 2000/02/15 22:21:53 leg Exp $ */

#include <config.h>

#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <fcntl.h>
#include <signal.h>
#include <pwd.h>
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

#define MAXSERVICE 5
#define CHKPOINT_INTERVAL (30 * 60)
#define SERVICE_PATH (CYRUS_PATH "/bin")

static const int become_cyrus_early = 1;

struct service {
    char *name;
    char *proto;
    char *const *exec;

    int socket;
    struct sockaddr *saddr;

    int ready_workers;
    int desired_workers;
    int stat[2];
};

char *const imapd_exec[] = { "imapd", NULL };
char *const pop3d_exec[] = { "pop3d", NULL };
char *const deliver_exec[] = { "lmtpd", NULL };
char *const timsieved_exec[] = { "timsieved", NULL };

static struct service Services[] =
{
    { "imap", "tcp", imapd_exec, 0, 0, 0, 0, {0,0} },
    { "pop3", "tcp", pop3d_exec, 0, 0, 0, 0, {0,0} },
    { "lmtp", "tcp", deliver_exec, 0, 0, 0, 0, {0,0} },
/*    { "sieve", "tcp", timsieved_exec, 0, 0, 0, 0, {0,0} }*/
};

static int nservices = 3;

char *const recovery_exec[] = { "ctl_mboxlist", "-r", NULL };
char *const checkpoint_exec[] = { "ctl_mboxlist", "-c", NULL };

void fatal(char *msg, int code)
{
    syslog(LOG_CRIT, msg);
    syslog(LOG_NOTICE, "exiting");
    exit(code);
}

int become_cyrus(void)
{
    struct passwd *p;
    static int uid = 0;

    if (uid) return setuid(uid);

    p = getpwnam(CYRUS_USER);
    if (p == NULL) {
	syslog(LOG_ERR, "no entry in /etc/passwd for %s", CYRUS_USER);
	return -1;
    }
    uid = p->pw_uid;

    return setuid(uid);
}

void get_statsock(int filedes[2])
{
    int r, fdflags;

    r = pipe(filedes);
    if (r != 0) {
	fatal("couldn't create status socket: %m", 1);
    }

    /* we don't want the master blocking on reads */
    fdflags = fcntl(filedes[0], F_GETFL, 0);
    if (fdflags != -1) fdflags = fcntl(filedes[0], F_SETFL, 
				       fdflags | O_NONBLOCK);
    if (fdflags == -1) {
	fatal("unable to set non-blocking: %m", 1);
    }
    /* we don't want the services to be able to read from it */
    fdflags = fcntl(filedes[0], F_GETFD, 0);
    if (fdflags != -1) fdflags = fcntl(filedes[0], F_SETFD, 
				       fdflags | FD_CLOEXEC);
    if (fdflags == -1) {
	fatal("unable to set close-on-exec: %m", 1);
    }
}

void service_create(struct service *s)
{
    struct sockaddr_in sin;
    struct servent *serv;
    int on = 1;
    char buffer[128];

    /* let people disable this service */
    sprintf(buffer, "%s-service", s->name);
    if (!config_getswitch(buffer, 1)) return;

    memset(&sin, 0, sizeof(sin));

    serv = getservbyname(s->name, s->proto);
    if (serv == NULL) {
	syslog(LOG_INFO, "no service '%s' in /etc/services, disabling it", 
	       s->name);
	s->exec = NULL;
	return;
    }

    s->socket = socket(AF_INET, SOCK_STREAM, 0);
    
    sin.sin_family = AF_INET;
    sin.sin_port = serv->s_port;

    if (s->socket < 0) {
	syslog(LOG_ERR, "unable to create %s listener socket: %m", s->name);
	s->exec = NULL;
	return;
    }

    /* allow reuse of address */
    setsockopt(s->socket, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

    if (bind(s->socket, &sin, sizeof(sin)) < 0) {
	syslog(LOG_ERR, "unable to bind %s socket: %m", s->name);
	close(s->socket);
	s->socket = 0;
	s->exec = NULL;
	return;
    }

    if (listen(s->socket, 10) < 0) {
	syslog(LOG_ERR, "unable to listen to %s socket: %m", s->name);
	close(s->socket);
	s->socket = 0;
	s->exec = NULL;
	return;
    }

    s->ready_workers = 0;
    sprintf(buffer, "%s-workers", s->name);
    s->desired_workers = config_getint(buffer, 1);

    get_statsock(s->stat);
}

void run_recovery(void)
{
    pid_t p;
    int res;
    char path[1024];

    switch (p = fork()) {
    case -1:
	syslog(LOG_CRIT, "can't fork process to run recovery");
	fatal("can't run recovery", 1);
	break;

    case 0:
	become_cyrus();
	sprintf(path, "%s/%s", SERVICE_PATH, recovery_exec[0]);
	execv(path, recovery_exec);
	syslog(LOG_ERR, "can't exec %s for recovery: %m", path);
	exit(1);

    default:
	waitpid(p, &res, 0);
	if (res != 0) {
	    syslog(LOG_CRIT, "recovery process exited with code '%d'", res);
	}
	break;
    }
}

void spawn_checkpoint(void)
{
    pid_t p;
    char path[1024];

    switch (p = fork()) {
    case -1:
	syslog(LOG_CRIT, "can't fork process to run checkpoint");
	break;

    case 0:
	become_cyrus();
	sprintf(path, "%s/%s", SERVICE_PATH, checkpoint_exec[0]);
	execv(path, checkpoint_exec);
	syslog(LOG_ERR, "can't exec %s for checkpointing: %m", path);
	exit(1);
	break;

    default:
	/* we don't wait for it to complete */
	break;
    }
}

void spawn_service(struct service *s)
{
    pid_t p;
    int i;
    char path[1024];
    int fdflags;

    switch (p = fork()) {
    case -1:
	syslog(LOG_ERR, "can't fork process to run checkpoint");
	break;

    case 0:
	/* child */
	if (become_cyrus() != 0) {
	    syslog(LOG_ERR, "can't change to the cyrus user");
	    exit(1);
	}

	sprintf(path, "%s/%s", SERVICE_PATH, s->exec[0]);
	if (dup2(s->stat[1], STATUS_FD) < 0) {
	    syslog(LOG_ERR, "can't duplicate status fd: %m");
	    exit(1);
	}
	if (dup2(s->socket, LISTEN_FD) < 0) {
	    syslog(LOG_ERR, "can't duplicate listener fd: %m");
	    exit(1);
	}

	fdflags = fcntl(LISTEN_FD, F_GETFD, 0);
	if (fdflags != -1) fdflags = fcntl(LISTEN_FD, F_SETFD, 
					   fdflags & ~FD_CLOEXEC);
	if (fdflags == -1) {
	    syslog(LOG_ERR, "unable to unset close on exec: %m");
	}
	fdflags = fcntl(STATUS_FD, F_GETFD, 0);
	if (fdflags != -1) fdflags = fcntl(STATUS_FD, F_SETFD, 
					   fdflags & ~FD_CLOEXEC);
	if (fdflags == -1) {
	    syslog(LOG_ERR, "unable to unset close on exec: %m");
	}

	/* close all listeners */
	for (i = 0; i < nservices; i++) {
	    if (Services[i].socket > 0) close(Services[i].socket);
	    if (Services[i].stat[0] > 0) close(Services[i].stat[0]);
	    if (Services[i].stat[1] > 0) close(Services[i].stat[1]);
	}
	execv(path, s->exec);
	syslog(LOG_ERR, "couldn't exec %s: %m", path);

    default: 
	/* parent */
	s->ready_workers++;
	break;
    }

}

void reap_child(void)
{
    int status;
    pid_t pid;

    while ((pid = waitpid((pid_t) -1, &status, WNOHANG)) > 0) {
	syslog(LOG_DEBUG, "process %d exited, status %d\n", pid, 
	       WEXITSTATUS(status));

	/* do we want to do child accounting at some point? probably */
    }
}

static int gotsigchld = 0;

void sigchld_handler(int sig)
{
    gotsigchld = 1;
}

static int gotsighup = 0;

void sighup_handler(int sig)
{
    gotsighup = 1;
}

static int do_chkpoint = 0;

void sigalrm_handler(int sig)
{
    do_chkpoint = 1;
}

void sighandler_setup(void)
{
    struct sigaction action;
    
    sigemptyset(&action.sa_mask);
    action.sa_flags = 0;

    action.sa_handler = sighup_handler;
#ifdef SA_RESTART
    action.sa_flags |= SA_RESTART;
#endif
    if (sigaction(SIGHUP, &action, NULL) < 0) {
	fatal("unable to install signal handler for SIGHUP: %m", 1);
    }

    action.sa_handler = sigalrm_handler;
    if (sigaction(SIGALRM, &action, NULL) < 0) {
	fatal("unable to install signal handler for SIGALRM: %m", 1);
    }

    action.sa_flags |= SA_NOCLDSTOP;
    action.sa_handler = sigchld_handler;
    if (sigaction(SIGCHLD, &action, NULL) < 0) {
	fatal("unable to install signal handler for SIGCHLD: %m", 1);
    }
}

void process_msg(struct service *s, int msg)
{
    switch (msg) {
    case SERVICE_AVAILABLE:
	s->ready_workers++;
	break;

    case SERVICE_UNAVAILABLE:
	s->ready_workers--;
	break;
	
    default:
	syslog(LOG_ERR, "unrecognized message for service '%s': %x", 
	       s->name, msg);
	break;
    }
}

int main(int argc, char **argv, char **envp)
{
    int i;
    int fd;
    fd_set rfds;

    config_init("master");
    syslog(LOG_NOTICE, "process started");

    /* close stdin/out/err */
    for (fd = 0; fd < 3; fd++) {
	close(fd);
	if (open("/dev/null", O_RDWR, 0) != fd)
	    fatal("couldn't open /dev/null: %m", 2);
    }

    /* we reserve fds 3 and 4 for children to communicate with us, so they
       better be available. */
    for (fd = 3; fd < 5; fd++) {
	close(fd);
	if (dup(0) != fd) fatal("couldn't dup fd 0: %m", 2);
    }

    /* kill all previous clients */

    /* run recovery on database environments */
    run_recovery();

    /* checkpoint the database environments */
    spawn_checkpoint();

    /* set signal handlers */
    sighandler_setup();

    /* initialize services */
    for (i = 0; i < nservices; i++) {
	service_create(&Services[i]);
    }

    if (become_cyrus_early) become_cyrus();

    /* remind ourselves to checkpoint */
    alarm(CHKPOINT_INTERVAL);

    /* ok, we're going to start spawning like mad now */
    syslog(LOG_NOTICE, "ready for work");

    for (;;) {
	int r, i, msg, maxfd;

	/* do we have any services undermanned? */
	for (i = 0; i < nservices; i++) {
	    if (Services[i].exec /* enabled */ &&
		(Services[i].ready_workers < Services[i].desired_workers)) {
		spawn_service(&Services[i]);
	    }
	}

	if (do_chkpoint) {
	    do_chkpoint = 0;
	    spawn_checkpoint();
	    alarm(CHKPOINT_INTERVAL);
	}

	if (gotsigchld) {
	    /* order matters here */
	    gotsigchld = 0;
	    reap_child();
	}

	if (gotsighup) {
	    syslog(LOG_NOTICE, "got SIGHUP");
	    gotsighup = 0;
	}

	FD_ZERO(&rfds);
	maxfd = 0;
	for (i = 0; i < nservices; i++) {
	    int x = Services[i].stat[0];
	    if (x > 0) FD_SET(x, &rfds);
	    if (x > maxfd) maxfd = x;
	}
	errno = 0;
	r = select(maxfd + 1, &rfds, NULL, NULL, NULL);
	if (r == -1 && errno == EAGAIN) continue;
	if (r == -1 && errno == EINTR) continue;
	if (r == -1) {
	    /* uh oh */
	    fatal("select failed: %m", 1);
	}

	for (i = 0; i < nservices; i++) {
	    int x = Services[i].stat[0];

	    if (FD_ISSET(x, &rfds)) {
		r = read(x, &msg, sizeof(int));
		if (r != sizeof(int)) {
		    syslog(LOG_ERR, "got weird response from child: %x", i);
		    continue;
		}
		
		process_msg(&Services[i], msg);
	    }
	}
    }
}
