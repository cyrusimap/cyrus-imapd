/* master.c -- IMAP master process to handle recovery, checkpointing, spawning
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

/* $Id: master.c,v 1.15 2000/09/05 04:07:52 leg Exp $ */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <fcntl.h>
#include <signal.h>
#include <pwd.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <syslog.h>
#include <netdb.h>
#include <ctype.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <sysexits.h>
#include <errno.h>

#include "masterconf.h"

#include "service.h"

#define CHKPOINT_INTERVAL (30 * 60)
#define SERVICE_PATH (CYRUS_PATH "/bin")

static const int become_cyrus_early = 1;

static int verbose = 0;
static int listen_queue_backlog = 10;

struct service {
    char *name;
    char *listen;
    char *proto;
    char *const *exec;

    int socket;
    struct sockaddr *saddr;

    int ready_workers;
    int desired_workers;
    int stat[2];
};

static struct service *Services = NULL;
static int allocservices = 0;
static int nservices = 0;

struct recover {
    char *name;
    char *const *exec;
};

struct event {
    char *name;
    time_t mark;
    time_t period;
    char *const *exec;
    struct event *next;
};

static struct event *schedule = NULL;

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

void get_prog(char *path, char *const *cmd)
{
    if (cmd[0][0] == '/') strcpy(path, cmd[0]);
    else sprintf(path, "%s/%s", SERVICE_PATH, cmd[0]);
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
    struct sockaddr_un sunsock;
    struct sockaddr *sa;
    struct servent *serv;
    mode_t oldumask;
    int on = 1, salen;
    int r;

    memset(&sin, 0, sizeof(sin));

    if (s->listen[0] == '/') { /* unix socket */
	sunsock.sun_family = AF_UNIX;
	strcpy(sunsock.sun_path, s->listen);
	unlink(s->listen);
	sa = (struct sockaddr *) &sunsock;
	salen = sizeof(sunsock.sun_family) + strlen(sunsock.sun_path) + 1;

	s->socket = socket(AF_UNIX, SOCK_STREAM, 0);
    } else { /* inet socket */
	sin.sin_family = AF_INET;

	serv = getservbyname(s->listen, s->proto);
	if (serv) {
	    sin.sin_port = serv->s_port;
	} else {
	    sin.sin_port = htons(atoi(s->listen));
	    if (sin.sin_port == 0) {
		syslog(LOG_INFO, "no service '%s' in /etc/services, "
		       "disabling %s", s->listen, s->name);
		s->exec = NULL;
		return;
	    }
	}
	sa = (struct sockaddr *) &sin;
	salen = sizeof(sin);

	s->socket = socket(AF_INET, SOCK_STREAM, 0);
    }

    if (s->socket < 0) {
	syslog(LOG_ERR, "unable to create %s listener socket: %m", s->name);
	s->exec = NULL;
	return;
    }

    /* allow reuse of address */
    setsockopt(s->socket, SOL_SOCKET, SO_REUSEADDR, (void *) &on, sizeof(on));

    oldumask = umask((mode_t) 0); /* for linux */
    r = bind(s->socket, sa, salen);
    umask(oldumask);
    if (r < 0) {
	syslog(LOG_ERR, "unable to bind %s socket: %m", s->name);
	close(s->socket);
	s->socket = 0;
	s->exec = NULL;
	return;
    }

    if (s->listen[0] == '/') { /* unix socket */
	/* for DUX, where this isn't the default.
	   (harmlessly fails on some systems) */
	chmod(s->listen, (mode_t) 0777);
    }

    if (listen(s->socket, listen_queue_backlog) < 0) {
	syslog(LOG_ERR, "unable to listen to %s socket: %m", s->name);
	close(s->socket);
	s->socket = 0;
	s->exec = NULL;
	return;
    }

    s->ready_workers = 0;

    get_statsock(s->stat);
}

void run_startup(char **cmd)
{
    pid_t pid;
    int status;
    char path[1024];

    switch (pid = fork()) {
    case -1:
	syslog(LOG_CRIT, "can't fork process to run startup");
	fatal("can't run startup", 1);
	break;
	
    case 0:
	if (become_cyrus() != 0) {
	    syslog(LOG_ERR, "can't change to the cyrus user");
	    exit(1);
	}

	get_prog(path, cmd);
	syslog(LOG_DEBUG, "about to exec %s", path);
	execv(path, cmd);
	syslog(LOG_ERR, "can't exec %s for startup: %m", path);
	exit(1);
	
    default:
	if (waitpid(pid, &status, 0) < 0) {
	    syslog(LOG_ERR, "waitpid(): %m");
	} else if (status != 0) {
	    if (WIFEXITED(status)) {
		syslog(LOG_ERR, "process %d exited, status %d\n", pid, 
		       WEXITSTATUS(status));
	    }
	    if (WIFSIGNALED(status)) {
		syslog(LOG_ERR, 
		       "process %d exited, signaled to death by %d\n",
		       pid, WTERMSIG(status));
	    }
	}
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

	get_prog(path, s->exec);
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
	syslog(LOG_DEBUG, "about to exec %s", path);
	execv(path, s->exec);
	syslog(LOG_ERR, "couldn't exec %s: %m", path);

    default: 
	/* parent */
	s->ready_workers++;
	break;
    }

}

void schedule_event(struct event *a)
{
    struct event *ptr;

    if (!schedule || a->mark < schedule->mark) {
	a->next = schedule;
	schedule = a;
	
	return;
    }
    for (ptr = schedule; ptr->next && ptr->next->mark <= a->mark; 
	 ptr = ptr->next) ;

    /* insert a */
    a->next = ptr->next;
    ptr->next = a;
}

void spawn_schedule(time_t now)
{
    struct event *a, *b;
    char path[1024];
    pid_t p;

    a = NULL;
    /* update schedule accordingly */
    while (schedule && schedule->mark <= now) {
	/* delete from schedule, insert into a */
	struct event *ptr = schedule;

	/* delete */
	schedule = schedule->next;

	/* insert */
	ptr->next = a;
	a = ptr;
    }

    /* run all events */
    while (a && a != schedule) {
	switch (p = fork()) {
	case -1:
	    syslog(LOG_CRIT, "can't fork process to run event %s");
	    break;

	case 0:
	    if (become_cyrus() != 0) {
		syslog(LOG_ERR, "can't change to the cyrus user");
		exit(1);
	    }
	    get_prog(path, a->exec);
	    syslog(LOG_DEBUG, "about to exec %s", path);
	    execv(path, a->exec);
	    syslog(LOG_ERR, "can't exec %s on schedule: %m", path);
	    exit(1);
	    break;
	    
	default:
	    /* we don't wait for it to complete */
	    break;
	}

	b = a->next;
	if (a->period) {
	    a->mark = now + a->period;
	    /* reschedule a */
	    schedule_event(a);
	} else {
	    free(a);
	}
	/* examine next event */
	a = b;
    }
}

void reap_child(void)
{
    int status;
    pid_t pid;

    while ((pid = waitpid((pid_t) -1, &status, WNOHANG)) > 0) {
	if (WIFEXITED(status)) {
	    syslog(LOG_DEBUG, "process %d exited, status %d\n", pid, 
		   WEXITSTATUS(status));
	}

	if (WIFSIGNALED(status)) {
	    syslog(LOG_DEBUG, "process %d exited, signaled to death by %d\n",
		   pid, WTERMSIG(status));
	}

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

void sigterm_handler(int sig)
{
    struct sigaction action;

    /* send all the other processes SIGTERM, then exit */
    sigemptyset(&action.sa_mask);
    action.sa_flags = 0;
    action.sa_handler = SIG_IGN;
    if (sigaction(SIGTERM, &action, (struct sigaction *) 0) < 0) {
	syslog(LOG_ERR, "sigaction: %m");
	exit(1);
    }
    /* kill my process group */
    if (kill(0, SIGTERM) < 0) {
	syslog(LOG_ERR, "kill(0, SIGTERM): %m");
    }

    syslog(LOG_INFO, "exiting on SIGTERM");
    exit(0);
}

void sigalrm_handler(int sig)
{
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

    action.sa_handler = sigterm_handler;
    if (sigaction(SIGTERM, &action, NULL) < 0) {
	fatal("unable to install signal handler for SIGTERM: %m", 1);
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

    if (verbose)
	syslog(LOG_DEBUG, "service %s now has %d workers\n", 
	       s->name, s->ready_workers);
}

static char **tokenize(char *p)
{
    char **tokens = NULL; /* allocated in increments of 10 */
    int i = 0;

    if (!p || !*p) return NULL; /* sanity check */
    while (*p) {
	while (*p && isspace((int) *p)) p++; /* skip whitespace */

	if (!(i % 10)) tokens = realloc(tokens, (i+10) * sizeof(char *));
	if (!tokens) return NULL;

	/* got a token */
	tokens[i++] = p;
	while (*p && !isspace((int) *p)) p++;

	/* p is whitespace or end of cmd */
	if (*p) *p++ = '\0';
    }
    /* add a NULL on the end */
    if (!(i % 10)) tokens = realloc(tokens, (i+1) * sizeof(char *));
    if (!tokens) return NULL;
    tokens[i] = NULL;

    return tokens;
}

void add_start(const char *name, struct entry *e, void *rock)
{
    char *cmd = strdup(masterconf_getstring(e, "cmd", NULL));
    char buf[256];
    char **tok;

    if (!cmd) {
	snprintf(buf, sizeof(buf), "unable to find command for %s", name);
	fatal(buf, EX_CONFIG);
    }

    tok = tokenize(cmd);
    if (!tok) fatal("out of memory", EX_UNAVAILABLE);
    run_startup(tok);
    free(tok);
    free(cmd);
}

void add_service(const char *name, struct entry *e, void *rock)
{
    char *cmd = strdup(masterconf_getstring(e, "cmd", NULL));
    int prefork = masterconf_getint(e, "prefork", 0);
    char *listen = strdup(masterconf_getstring(e, "listen", NULL));
    char *proto = strdup(masterconf_getstring(e, "proto", "tcp"));

    if (!cmd || !listen) {
	char buf[256];
	snprintf(buf, sizeof(buf), "unable to find command or port for %s", 
		 name);
	fatal(buf, EX_CONFIG);
    }
    if (!(allocservices % 5)) {
	Services = realloc(Services, 
			   (allocservices+=5) * sizeof(struct service));
	if (!Services) fatal("out of memory", EX_UNAVAILABLE);
    }

    Services[nservices].name = strdup(name);
    Services[nservices].listen = listen;
    Services[nservices].proto = proto;
    Services[nservices].exec = tokenize(cmd);
    if (!Services[nservices].exec) fatal("out of memory", EX_UNAVAILABLE);

    Services[nservices].socket = 0;
    Services[nservices].saddr = NULL;

    Services[nservices].ready_workers = 0;
    Services[nservices].desired_workers = prefork;
    memset(Services[nservices].stat, 0, sizeof(Services[nservices].stat));

    nservices++;
}

void add_event(const char *name, struct entry *e, void *rock)
{
    char *cmd = strdup(masterconf_getstring(e, "cmd", NULL));
    int period = 60 * masterconf_getint(e, "period", 0);
    struct event *evt;

    if (!cmd) {
	char buf[256];
	snprintf(buf, sizeof(buf), "unable to find command or port for %s", 
		 name);
	fatal(buf, EX_CONFIG);
    }
    
    evt = (struct event *) malloc(sizeof(struct event));
    if (!evt) fatal("out of memory", EX_UNAVAILABLE);
    evt->name = strdup(name);
    evt->mark = 0;
    evt->period = period;
    evt->exec = tokenize(cmd);
    if (!evt->exec) fatal("out of memory", EX_UNAVAILABLE);
    evt->next = schedule;
    schedule = evt;
}

int main(int argc, char **argv, char **envp)
{
    int i, opt;
    extern int optind;
    extern char *optarg;
    int fd;
    fd_set rfds;
    char *p = NULL;

    p = getenv("CYRUS_VERBOSE");
    if (p) verbose = atoi(p) + 1;
    while ((opt = getopt(argc, argv, "l:")) != EOF) {
	switch (opt) {
	case 'l': /* user defined listen queue backlog */
	    listen_queue_backlog = atoi(optarg);
	    break;
	default:
	    break;
	}
    }
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

    masterconf_init("master");
    syslog(LOG_NOTICE, "process started");

    masterconf_getsection("START", &add_start, NULL);
    masterconf_getsection("SERVICES", &add_service, NULL);
    masterconf_getsection("EVENTS", &add_event, NULL);

    /* set signal handlers */
    sighandler_setup();

    /* initialize services */
    for (i = 0; i < nservices; i++) {
	service_create(&Services[i]);
	if (verbose > 2)
	    syslog(LOG_DEBUG, "init: service %s socket %d pipe %d %d",
		   Services[i].name, Services[i].socket,
		   Services[i].stat[0], Services[i].stat[1]);
    }

    if (become_cyrus_early) become_cyrus();

    /* ok, we're going to start spawning like mad now */
    syslog(LOG_NOTICE, "ready for work");

    for (;;) {
	int r, i, msg, maxfd;
	struct timeval tv, *tvptr;
	time_t now = time(NULL);

	/* run any scheduled processes */
	spawn_schedule(now);

	tvptr = NULL;
	if (schedule) {
	    if (now < schedule->mark) tv.tv_sec = schedule->mark - now;
	    else tv.tv_sec = 0;
	    tv.tv_usec = 0;
	    tvptr = &tv;
	}
	
	/* do we have any services undermanned? */
	for (i = 0; i < nservices; i++) {
	    if (Services[i].exec /* enabled */ &&
		(Services[i].ready_workers < Services[i].desired_workers)) {
		spawn_service(&Services[i]);
	    }
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
	    int y = Services[i].socket;

	    /* messages */
	    if (x > 0) {
		if (verbose > 2)
		    syslog(LOG_DEBUG, "listening for messages from %s",
			   Services[i].name);
		FD_SET(x, &rfds);
	    }
	    if (x > maxfd) maxfd = x;

	    /* connections */
	    if (y > 0 && Services[i].ready_workers == 0) {
		if (verbose > 2)
		    syslog(LOG_DEBUG, "listening for connections for %s", 
			   Services[i].name);
		FD_SET(y, &rfds);
		if (y > maxfd) maxfd = y;
	    }

	    /* paranoia */
	    if (Services[i].ready_workers < 0) {
		syslog(LOG_ERR, "%s has %d workers?!?", Services[i].name,
		       Services[i].ready_workers);
	    }
	}
	errno = 0;
	r = select(maxfd + 1, &rfds, NULL, NULL, tvptr);
	if (r == -1 && errno == EAGAIN) continue;
	if (r == -1 && errno == EINTR) continue;
	if (r == -1) {
	    /* uh oh */
	    fatal("select failed: %m", 1);
	}

	for (i = 0; i < nservices; i++) {
	    int x = Services[i].stat[0];
	    int y = Services[i].socket;

	    if (FD_ISSET(x, &rfds)) {
		r = read(x, &msg, sizeof(int));
		if (r != sizeof(int)) {
		    syslog(LOG_ERR, "got weird response from child: %x", i);
		    continue;
		}
		
		process_msg(&Services[i], msg);
	    }

	    if (Services[i].ready_workers == 0 && 
		FD_ISSET(y, &rfds)) {
		/* huh, someone wants to talk to us */
		spawn_service(&Services[i]);
	    }
	}
    }
}
