/* master.c -- IMAP master process to handle recovery, checkpointing, spawning
 *
 * Copyright (c) 1998-2003 Carnegie Mellon University.  All rights reserved.
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

/* $Id: master.c,v 1.90 2004/01/21 17:03:25 rjs3 Exp $ */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <grp.h>
#include <sys/types.h>
#include <sys/wait.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
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
#include <limits.h>

#ifndef INADDR_NONE
#define INADDR_NONE 0xffffffff
#endif

#ifndef INADDR_ANY
#define INADDR_ANY 0x00000000
#endif

#if !defined(IPV6_V6ONLY) && defined(IPV6_BINDV6ONLY)
#define	IPV6_V6ONLY	IPV6_BINDV6ONLY
#endif

#ifdef HAVE_UCDSNMP
#include <ucd-snmp/ucd-snmp-config.h>
#include <ucd-snmp/ucd-snmp-includes.h>
#include <ucd-snmp/ucd-snmp-agent-includes.h>

#include "cyrusMasterMIB.h"

int allow_severity = LOG_DEBUG;
int deny_severity = LOG_ERR;

#endif

#include "masterconf.h"

#include "master.h"
#include "service.h"

#include "lock.h"

#include "xmalloc.h"

enum {
    become_cyrus_early = 1,
    child_table_size = 10000,
    child_table_inc = 100
};

static int verbose = 0;
static int listen_queue_backlog = 32;
static int pidfd = -1;

const char *MASTER_CONFIG_FILENAME = DEFAULT_MASTER_CONFIG_FILENAME;

struct service *Services = NULL;
int allocservices = 0;
int nservices = 0;

/* make libcyrus_min happy */
int config_need_data = 0;

struct event {
    char *name;
    time_t mark;
    time_t period;
    int periodic;
    char *const *exec;
    struct event *next;
};
static struct event *schedule = NULL;

enum sstate {
    SERVICE_STATE_UNKNOWN = 0,  /* duh */
    SERVICE_STATE_INIT    = 1,  /* Service forked - UNUSED */
    SERVICE_STATE_READY   = 2,  /* Service told us it is ready */
    				/* or it just forked and has not
				 * talked to us yet */
    SERVICE_STATE_BUSY    = 3,  /* Service told us it is not ready */
    SERVICE_STATE_DEAD    = 4   /* We received a sigchld from this service */
};

struct centry {
    pid_t pid;
    enum sstate service_state;	/* SERVICE_STATE_* */
    time_t janitor_deadline;	/* cleanup deadline */
    struct service *s;
    struct centry *next;
};
static struct centry *ctable[child_table_size];
static struct centry *cfreelist;

static int janitor_frequency = 1;	/* Janitor sweeps per second */
static int janitor_position;		/* Entry to begin at in next sweep */
static struct timeval janitor_mark;	/* Last time janitor did a sweep */

void limit_fds(rlim_t);
void schedule_event(struct event *a);

void fatal(const char *msg, int code)
{
    syslog(LOG_CRIT, "%s", msg);
    syslog(LOG_NOTICE, "exiting");
    exit(code);
}

void event_free(struct event *a) 
{
    if(a->exec) free((char**)a->exec);
    if(a->name) free((char*)a->name);
    free(a);
}

int become_cyrus(void)
{
    struct passwd *p;
    int newuid, newgid;
    int result;
    static int uid = 0;

    if (uid) return setuid(uid);

    p = getpwnam(CYRUS_USER);
    if (p == NULL) {
	syslog(LOG_ERR, "no entry in /etc/passwd for user %s", CYRUS_USER);
	return -1;
    }

    /* Save these in case initgroups does a getpw*() */
    newuid = p->pw_uid;
    newgid = p->pw_gid;

    if (initgroups(CYRUS_USER, newgid)) {
        syslog(LOG_ERR, "unable to initialize groups for user %s: %s",
	       CYRUS_USER, strerror(errno));
        return -1;
    }

    if (setgid(newgid)) {
        syslog(LOG_ERR, "unable to set group id to %d for user %s: %s",
              newgid, CYRUS_USER, strerror(errno));
        return -1;
    }

    result = setuid(newuid);

    /* Only set static uid if successful, else future calls won't reset gid */
    if (result == 0)
        uid = newuid;
    return result;
}

void get_prog(char *path, unsigned size, char *const *cmd)
{
    if (cmd[0][0] == '/') {
	/* master lacks strlcpy, due to no libcyrus */
	snprintf(path, size, "%s", cmd[0]);
    }
    else snprintf(path, size, "%s/%s", SERVICE_PATH, cmd[0]);
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

/* return a new 'centry', either from the freelist or by malloc'ing it */
static struct centry *get_centry(void)
{
    struct centry *t;

    if (!cfreelist) {
	/* create child_table_inc more and add them to the freelist */
	struct centry *n;
	int i;

	n = xmalloc(child_table_inc * sizeof(struct centry));
	cfreelist = n;
	for (i = 0; i < child_table_inc - 1; i++) {
	    n[i].next = n + (i + 1);
	}
	/* i == child_table_inc - 1, last item in block */
	n[i].next = NULL;
    }

    t = cfreelist;
    cfreelist = cfreelist->next;

    t->janitor_deadline = 0;

    return t;
}

/* see if 'listen' parameter has both hostname and port, or just port */
char *parse_listen(char *listen)
{
    char *cp;
    char *port = NULL;

    if ((cp = strrchr(listen,']')) != NULL) {
        /* ":port" after closing bracket for IP address? */
        if (*cp++ != '\0' && *cp == ':') {
            *cp++ = '\0';
            if (*cp != '\0') {
                port = cp;
            } 
        }
    } else if ((cp = strrchr(listen,':')) != NULL) {
        /* ":port" after hostname? */
        *cp++ = '\0';
        if (*cp != '\0') {
            port = cp;
        }
    }
    return port;
}

char *parse_host(char *listen)
{
    char *cp;

    /* do we have a hostname, or IP number? */
    /* XXX are brackets necessary  */
    if (*listen == '[') {
        listen++;  /* skip first bracket */
        if ((cp = strrchr(listen,']')) != NULL) {
            *cp = '\0';
        }
    }
    return listen;
}

int verify_service_file(char *const *filename)
{
    char path[PATH_MAX];
    struct stat statbuf;
    
    get_prog(path, sizeof(path), filename);
    if (stat(path, &statbuf)) return 0;
    if (! S_ISREG(statbuf.st_mode)) return 0;
    return statbuf.st_mode & S_IXUSR;
}

void service_create(struct service *s)
{
    struct service service0, service;
    struct addrinfo hints, *res0, *res;
    int error, nsocket = 0;
    struct sockaddr_un sunsock;
    mode_t oldumask;
    int on = 1;
    int r;

    if (s->associate > 0)
	return;			/* service is already activated */
    
    if (s->listen[0] == '/') { /* unix socket */
	res0 = (struct addrinfo *)malloc(sizeof(struct addrinfo));
	if (!res0)
	    fatal("out of memory", EX_UNAVAILABLE);
	memset(res0, 0, sizeof(struct addrinfo));
	res0->ai_flags = AI_PASSIVE;
	res0->ai_family = PF_UNIX;
	if(!strcmp(s->proto, "tcp")) {
	    res0->ai_socktype = SOCK_STREAM;
	} else {
	    /* udp */
	    res0->ai_socktype = SOCK_DGRAM;
	}
 	res0->ai_addr = (struct sockaddr *)&sunsock;
 	res0->ai_addrlen = sizeof(sunsock.sun_family) + strlen(s->listen) + 1;
#ifdef SIN6_LEN
 	res0->ai_addrlen += sizeof(sunsock.sun_len);
 	sunsock.sun_len = res0->ai_addrlen;
#endif
	sunsock.sun_family = AF_UNIX;
	strcpy(sunsock.sun_path, s->listen);
	unlink(s->listen);
    } else { /* inet socket */
	char *listen, *port;
	char *listen_addr;
	
 	memset(&hints, 0, sizeof(hints));
 	hints.ai_flags = AI_PASSIVE;
 	if (!strcmp(s->proto, "tcp")) {
 	    hints.ai_family = PF_UNSPEC;
 	    hints.ai_socktype = SOCK_STREAM;
 	} else if (!strcmp(s->proto, "tcp4")) {
 	    hints.ai_family = PF_INET;
 	    hints.ai_socktype = SOCK_STREAM;
 	} else if (!strcmp(s->proto, "tcp6")) {
 	    hints.ai_family = PF_INET6;
 	    hints.ai_socktype = SOCK_STREAM;
 	} else if (!strcmp(s->proto, "udp")) {
 	    hints.ai_family = PF_UNSPEC;
 	    hints.ai_socktype = SOCK_DGRAM;
 	} else if (!strcmp(s->proto, "udp4")) {
 	    hints.ai_family = PF_INET;
 	    hints.ai_socktype = SOCK_DGRAM;
 	} else if (!strcmp(s->proto, "udp6")) {
 	    hints.ai_family = PF_INET6;
 	    hints.ai_socktype = SOCK_DGRAM;
 	} else {
  	    syslog(LOG_INFO, "invalid proto '%s', disabling %s",
		   s->proto, s->name);
 	    s->exec = NULL;
 	    return;
 	}

	/* parse_listen() and resolve_host() are destructive,
	 * so make a work copy of s->listen
	 */
	listen = xstrdup(s->listen);

        if ((port = parse_listen(listen)) == NULL) {
            /* listen IS the port */
	    port = listen;
	    listen_addr = NULL;
        } else {
            /* s->listen is now just the address */
	    listen_addr = parse_host(listen);
	    if (*listen_addr == '\0')
		listen_addr = NULL;	    
        }

	error = getaddrinfo(listen_addr, port, &hints, &res0);

	free(listen);

	if (error) {
	    syslog(LOG_INFO, "%s, disabling %s", gai_strerror(error), s->name);
	    s->exec = NULL;
	    return;
	}
    }

    memcpy(&service0, s, sizeof(struct service));

    for (res = res0; res; res = res->ai_next) {
	if (s->socket > 0) {
	    memcpy(&service, &service0, sizeof(struct service));
	    s = &service;
	}

	s->socket = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (s->socket < 0) {
	    s->socket = 0;
	    if (verbose > 2)
		syslog(LOG_ERR, "unable to open %s socket: %m", s->name);
	    continue;
	}

	/* allow reuse of address */
	r = setsockopt(s->socket, SOL_SOCKET, SO_REUSEADDR, 
		       (void *) &on, sizeof(on));
	if (r < 0) {
	    syslog(LOG_ERR, "unable to setsocketopt(SO_REUSEADDR): %m");
	}
#if defined(IPV6_V6ONLY) && !(defined(__FreeBSD__) && __FreeBSD__ < 3)
	if (res->ai_family == AF_INET6) {
	    r = setsockopt(s->socket, IPPROTO_IPV6, IPV6_V6ONLY,
			   (void *) &on, sizeof(on));
	    if (r < 0) {
		syslog(LOG_ERR, "unable to setsocketopt(IPV6_V6ONLY): %m");
	    }
	}
#endif

	oldumask = umask((mode_t) 0); /* for linux */
	r = bind(s->socket, res->ai_addr, res->ai_addrlen);
	umask(oldumask);
	if (r < 0) {
	    close(s->socket);
	    s->socket = 0;
	    if (verbose > 2)
		syslog(LOG_ERR, "unable to bind to %s socket: %m", s->name);
	    continue;
	}
	
	if (s->listen[0] == '/') { /* unix socket */
	    /* for DUX, where this isn't the default.
	       (harmlessly fails on some systems) */
	    chmod(s->listen, (mode_t) 0777);
	}
	
	if ((!strcmp(s->proto, "tcp") || !strcmp(s->proto, "tcp4")
	     || !strcmp(s->proto, "tcp6"))
	    && listen(s->socket, listen_queue_backlog) < 0) {
	    syslog(LOG_ERR, "unable to listen to %s socket: %m", s->name);
	    close(s->socket);
	    s->socket = 0;
	    continue;
	}
	
	s->ready_workers = 0;
	s->associate = nsocket;
	
	get_statsock(s->stat);
	
	if (s == &service) {
	    if (nservices == allocservices) {
		Services = xrealloc(Services, 
				    (allocservices+=5) * sizeof(struct service));
		if (!Services) fatal("out of memory", EX_UNAVAILABLE);
	    }
	    memcpy(&Services[nservices++], s, sizeof(struct service));
	}
	nsocket++;
    }
    if (res0)
	freeaddrinfo(res0);
    if (nsocket <= 0) {
	syslog(LOG_ERR, "unable to create %s listener socket: %m", s->name);
	s->exec = NULL;
	return;
    }
}

void run_startup(char **cmd)
{
    pid_t pid;
    int status;
    char path[PATH_MAX];

    switch (pid = fork()) {
    case -1:
	syslog(LOG_CRIT, "can't fork process to run startup: %m");
	fatal("can't run startup", 1);
	break;
	
    case 0:
	/* Child - Release our pidfile lock. */
	if(pidfd != -1) close(pidfd);

	if (become_cyrus() != 0) {
	    syslog(LOG_ERR, "can't change to the cyrus user: %m");
	    exit(1);
	}

	limit_fds(256);

	get_prog(path, sizeof(path), cmd);
	syslog(LOG_DEBUG, "about to exec %s", path);
	execv(path, cmd);
	syslog(LOG_ERR, "can't exec %s for startup: %m", path);
	exit(EX_OSERR);
	
    default: /* parent */
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

void fcntl_unset(int fd, int flag)
{
    int fdflags = fcntl(fd, F_GETFD, 0);
    if (fdflags != -1) fdflags = fcntl(STATUS_FD, F_SETFD, 
				       fdflags & ~flag);
    if (fdflags == -1) {
	syslog(LOG_ERR, "fcntl(): unable to unset %d: %m", flag);
    }
}

void spawn_service(struct service *s)
{
    /* Note that there is logic that depends on this being 2 */
    const int FORKRATE_INTERVAL = 2;

    pid_t p;
    int i;
    char path[PATH_MAX];
    static char name_env[100], name_env2[100];
    struct centry *c;
    time_t now = time(NULL);
    
    /* update our fork rate */
    if(now - s->last_interval_start >= FORKRATE_INTERVAL) {
	int interval;
	
	s->forkrate = (s->interval_forks/2) + (s->forkrate/2);
	s->interval_forks = 0;
	s->last_interval_start += FORKRATE_INTERVAL;

	/* if there is an even wider window, however, we need
	 * to account for a good deal of zeros, we can do this at once */
	interval = now - s->last_interval_start;

	if(interval > 2) {
	    int skipped_intervals = interval / FORKRATE_INTERVAL;
	    /* avoid a > 30 bit right shift) */
	    if(skipped_intervals > 30) s->forkrate = 0;
	    else {
		/* divide by 2^(skipped_intervals).
		 * this is the logic mentioned in the comment above */
		s->forkrate >>= skipped_intervals;
		s->last_interval_start = now;
	    }
	}
    }

    /* If we've been busy lately, we will refuse to fork! */
    /* (We schedule a wakeup call for sometime soon though to be
     * sure that we don't wait to do the fork that is required forever! */
    if(s->maxforkrate && s->forkrate >= s->maxforkrate) {
	struct event *evt = (struct event *) xmalloc(sizeof(struct event));

	memset(evt, 0, sizeof(struct event));

	evt->name = xstrdup("forkrate wakeup call");
	evt->mark = time(NULL) + FORKRATE_INTERVAL;
	schedule_event(evt);

	return;
    }

    switch (p = fork()) {
    case -1:
	syslog(LOG_ERR, "can't fork process to run service %s: %m", s->name);
	break;

    case 0:
	/* Child - Release our pidfile lock. */
	if(pidfd != -1) close(pidfd);

	if (become_cyrus() != 0) {
	    syslog(LOG_ERR, "can't change to the cyrus user");
	    exit(1);
	}

	get_prog(path, sizeof(path), s->exec);
	if (dup2(s->stat[1], STATUS_FD) < 0) {
	    syslog(LOG_ERR, "can't duplicate status fd: %m");
	    exit(1);
	}
	if (dup2(s->socket, LISTEN_FD) < 0) {
	    syslog(LOG_ERR, "can't duplicate listener fd: %m");
	    exit(1);
	}

	fcntl_unset(STATUS_FD, FD_CLOEXEC);
	fcntl_unset(LISTEN_FD, FD_CLOEXEC);

	/* close all listeners */
	for (i = 0; i < nservices; i++) {
	    if (Services[i].socket > 0) close(Services[i].socket);
	    if (Services[i].stat[0] > 0) close(Services[i].stat[0]);
	    if (Services[i].stat[1] > 0) close(Services[i].stat[1]);
	}
	limit_fds(s->maxfds);

	syslog(LOG_DEBUG, "about to exec %s", path);

	/* add service name to environment */
	snprintf(name_env, sizeof(name_env), "CYRUS_SERVICE=%s", s->name);
	putenv(name_env);
	snprintf(name_env2, sizeof(name_env2), "CYRUS_ID=%d", s->associate);
	putenv(name_env2);

	execv(path, s->exec);
	syslog(LOG_ERR, "couldn't exec %s: %m", path);
	exit(EX_OSERR);

    default:			/* parent */
	s->ready_workers++;
	s->interval_forks++;
	s->nforks++;
	s->nactive++;

	/* add to child table */
	c = get_centry();
	c->pid = p;
	c->service_state = SERVICE_STATE_READY;
	c->s = s;
	c->next = ctable[p % child_table_size];
	ctable[p % child_table_size] = c;
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
    int i;
    char path[PATH_MAX];
    pid_t p;
    struct centry *c;

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
	/* if a->exec is NULL, we just used the event to wake up,
	 * so we actually don't need to exec anything at the moment */
	if(a->exec) {
	    switch (p = fork()) {
	    case -1:
		syslog(LOG_CRIT,
		       "can't fork process to run event %s", a->name);
		break;

	    case 0:
		/* Child - Release our pidfile lock. */
		if(pidfd != -1) close(pidfd);

		if (become_cyrus() != 0) {
		    syslog(LOG_ERR, "can't change to the cyrus user");
		    exit(1);
		}
		
		/* close all listeners */
		for (i = 0; i < nservices; i++) {
		    if (Services[i].socket > 0) close(Services[i].socket);
		    if (Services[i].stat[0] > 0) close(Services[i].stat[0]);
		    if (Services[i].stat[1] > 0) close(Services[i].stat[1]);
		}
		limit_fds(256);
		
		get_prog(path, sizeof(path), a->exec);
		syslog(LOG_DEBUG, "about to exec %s", path);
		execv(path, a->exec);
		syslog(LOG_ERR, "can't exec %s on schedule: %m", path);
		exit(EX_OSERR);
		break;
		
	    default:
		/* we don't wait for it to complete */
		
		/* add to child table */
		c = get_centry();
		c->pid = p;
		c->service_state = SERVICE_STATE_READY;
		c->s = NULL;
		c->next = ctable[p % child_table_size];
		ctable[p % child_table_size] = c;
		
		break;
	    }
	} /* a->exec */
	
	/* reschedule as needed */
	b = a->next;
	if (a->period) {
	    if(a->periodic) {
		a->mark = now + a->period;
	    } else {
		/* Daily Event */
		while(a->mark < now) {
			a->mark += a->period;
		}
	    }
	    /* reschedule a */
	    schedule_event(a);
	} else {
	    event_free(a);
	}
	/* examine next event */
	a = b;
    }
}

void reap_child(void)
{
    int status;
    pid_t pid;
    struct centry *c;

    while ((pid = waitpid((pid_t) -1, &status, WNOHANG)) > 0) {
	if (WIFEXITED(status)) {
	    syslog(LOG_DEBUG, "process %d exited, status %d", pid, 
		   WEXITSTATUS(status));
	}

	if (WIFSIGNALED(status)) {
	    syslog(LOG_ERR, "process %d exited, signaled to death by %d",
		   pid, WTERMSIG(status));
	}

	/* account for the child */
	c = ctable[pid % child_table_size];
	while(c && c->pid != pid) c = c->next;
	
	if (c && c->pid == pid) {
	    /* paranoia */
	    switch (c->service_state) {
	    case SERVICE_STATE_READY:
	    case SERVICE_STATE_BUSY:
	    case SERVICE_STATE_UNKNOWN:
	    case SERVICE_STATE_DEAD:
		break;
	    default:
		syslog(LOG_CRIT, 
		       "service %s pid %d in ILLEGAL STATE: exited. Serious software bug or memory corruption detected!",
		       ((c->s) ? c->s->name : "unknown"), pid);
		syslog(LOG_DEBUG,
		       "service %s pid %d in ILLEGAL state: forced to valid UNKNOWN state",
		       ((c->s) ? c->s->name : "unknown"), pid);
		c->service_state = SERVICE_STATE_UNKNOWN;
	    }
	    if (c->s) {
	        /* update counters for known services */
		switch (c->service_state) {
		case SERVICE_STATE_READY:
		    c->s->nactive--;
		    c->s->ready_workers--;
		    if (WIFSIGNALED(status) ||
			(WIFEXITED(status) && WEXITSTATUS(status))) {
			syslog(LOG_WARNING, 
			       "service %s pid %d in READY state: terminated abnormally",
			       c->s->name, pid);
		    }
		    break;
		    
		case SERVICE_STATE_DEAD:
		    /* uh? either we got duplicate signals, or we are now MT */
		    syslog(LOG_WARNING, 
			   "service %s pid %d in DEAD state: receiving duplicate signals", 
			   c->s->name, pid);
		    break;
		    
		case SERVICE_STATE_BUSY:
		    c->s->nactive--;
		    if (WIFSIGNALED(status) ||
			(WIFEXITED(status) && WEXITSTATUS(status))) {
			syslog(LOG_DEBUG,
			       "service %s pid %d in BUSY state: terminated abnormally",
			       c->s->name, pid);
		    }
		    break;
		    
		case SERVICE_STATE_UNKNOWN:
		    c->s->nactive--;
		    syslog(LOG_WARNING,
			   "service %s pid %d in UNKNOWN state: exited",
			   c->s->name, pid);
		    break;

		default:
		    /* Prevent Warning */
		    break;
		} 
	    } else {
	    	/* children from spawn_schedule (events) or children that messaged us before being registered */
		if (c->service_state != SERVICE_STATE_READY) {
		    syslog(LOG_ERR,
			   "unknown service pid %d in state %d: exited (maybe using a service as an event?)",
			   pid, c->service_state);
		}
	    }
	    c->service_state = SERVICE_STATE_DEAD;
	    c->janitor_deadline = time(NULL) + 2;
	} else {
	    /* weird. Are we multithreaded now? we don't know this child */
	    syslog(LOG_WARNING,
		   "receiving signals from unregistered child %d. Handling it anyway",
		   pid);
	    c = get_centry();
	    c->pid = pid;
	    c->service_state = SERVICE_STATE_DEAD;
	    c->janitor_deadline = time(NULL) + 2;
	    c->s = NULL;
	    c->next = ctable[pid % child_table_size];
	    ctable[pid % child_table_size] = c;
	}
    if (verbose && c && c->s)
	syslog(LOG_DEBUG, "service %s now has %d ready workers\n", 
	       c->s->name, c->s->ready_workers);
    }
}

void init_janitor(void)
{
    struct event *evt = (struct event *) malloc(sizeof(struct event));
    
    if (!evt) fatal("out of memory", EX_UNAVAILABLE);
    memset(evt, 0, sizeof(struct event));
    
    gettimeofday(&janitor_mark, NULL);
    janitor_position = 0;
    
    evt->name = xstrdup("janitor periodic wakeup call");
    evt->period = 10;
    evt->mark = time(NULL) + 2;
    schedule_event(evt);
}

void child_janitor(void)
{
    int i;
    struct centry **p;
    struct centry *c;
    struct timeval rightnow;
    time_t now;
    
    now = time(NULL);
    
    /* Estimate the number of entries to clean up in this sweep */
    gettimeofday(&rightnow, NULL);
    if (rightnow.tv_sec > janitor_mark.tv_sec + 1) {
	/* overflow protection */
	i = child_table_size;
    } else {
	double n;
	
	n = child_table_size * janitor_frequency * 
	    (double) ((rightnow.tv_sec - janitor_mark.tv_sec) * 1000000 +
	              rightnow.tv_usec - janitor_mark.tv_usec ) / 1000000;
	if (n < child_table_size) {
	    i = n;
	} else {
	    i = child_table_size;
	}
    }
    
    while (i-- > 0) {
	p = &ctable[janitor_position++];
	janitor_position = janitor_position % child_table_size;
	while (*p) {
	    c = *p;
	    if (c->service_state == SERVICE_STATE_DEAD) {
		if (c->janitor_deadline < now) {
		    *p = c->next;
		    c->next = cfreelist;
		    cfreelist = c;
		} else {
		    p = &((*p)->next);
		}
	    } else {
		p = &((*p)->next);
	    }
	}
    }
}

static volatile int gotsigchld = 0;

void sigchld_handler(int sig __attribute__((unused)))
{
    gotsigchld = 1;
}

static volatile int gotsighup = 0;

void sighup_handler(int sig __attribute__((unused)))
{
    gotsighup = 1;
}

void sigterm_handler(int sig __attribute__((unused)))
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
	syslog(LOG_ERR, "sigterm_handler: kill(0, SIGTERM): %m");
    }

#ifdef HAVE_UCDSNMP
    /* tell master agent we're exiting */
    snmp_shutdown("cyrusMaster");
#endif

    syslog(LOG_INFO, "exiting on SIGTERM/SIGINT");
    exit(0);
}

void sigalrm_handler(int sig __attribute__((unused)))
{
    return;
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

    /* Handle SIGTERM and SIGINT the same way -- kill
     * off our children! */
    action.sa_handler = sigterm_handler;
    if (sigaction(SIGTERM, &action, NULL) < 0) {
	fatal("unable to install signal handler for SIGTERM: %m", 1);
    }
    if (sigaction(SIGINT, &action, NULL) < 0) {
	fatal("unable to install signal handler for SIGINT: %m", 1);
    }

    action.sa_flags |= SA_NOCLDSTOP;
    action.sa_handler = sigchld_handler;
    if (sigaction(SIGCHLD, &action, NULL) < 0) {
	fatal("unable to install signal handler for SIGCHLD: %m", 1);
    }
}

void process_msg(struct service *s, struct notify_message *msg) 
{
    struct centry * c;
    
    /* s must NOT be null
     * but we don't assert(s) since the current code 
     * makes NULL s an impossibility anyway 
     */

    /* Search hash table with linked list for pid */
    c = ctable[msg->service_pid % child_table_size];
    while (c && c->pid != msg->service_pid) c = c->next;
    
    /* Did we find it? */
    if (!c || c->pid != msg->service_pid) {
	syslog(LOG_WARNING, "service %s pid %d: while trying to process message 0x%x: not registered yet", 
	       s->name, msg->service_pid, msg->message);
	/* resilience paranoia. Causes small performance loss when used */
	c = get_centry();
	c->s = s;
	c->pid = msg->service_pid;
	c->service_state = SERVICE_STATE_UNKNOWN;
	c->next = ctable[c->pid % child_table_size];
	ctable[c->pid % child_table_size] = c;
    }
    
    /* paranoia */
    if (s != c->s) {
	syslog(LOG_ERR, 
	       "service %s pid %d: changing from service %s due to received message",
	       s->name, c->pid, ( (c->s) ? c->s->name : "unknown" ));
	c->s = s;
    }
    switch (c->service_state) {
    case SERVICE_STATE_UNKNOWN:
	syslog(LOG_WARNING, 
	       "service %s pid %d in UNKNOWN state: processing message 0x%x",
	       s->name, c->pid, msg->message);
	break;
    case SERVICE_STATE_READY:
    case SERVICE_STATE_BUSY:
    case SERVICE_STATE_DEAD:
	break;
    default:
	syslog(LOG_CRIT,
	       "service %s pid %d in ILLEGAL state: detected. Serious software bug or memory corruption uncloaked while processing message 0x%x from child!",
	       s->name, c->pid, msg->message);
	syslog(LOG_DEBUG,
	       "service %s pid %d in ILLEGAL state: forced to valid UNKNOWN state",
	       s->name, c->pid);
	c->service_state = SERVICE_STATE_UNKNOWN;
	break;
    }
    
    /* process message, according to state machine */
    switch (msg->message) {
    case MASTER_SERVICE_AVAILABLE:
	switch (c->service_state) {
	case SERVICE_STATE_READY:
	    /* duplicate message? */
	    syslog(LOG_WARNING,
		   "service %s pid %d in READY state: sent available message but it is already ready",
		   s->name, c->pid);
	    break;
	    
	case SERVICE_STATE_UNKNOWN:
	    /* since state is unknwon, error in non-DoS way, i.e.
	     * we don't increment ready_workers */
	    syslog(LOG_DEBUG,
		   "service %s pid %d in UNKNOWN state: now available and in READY state",
		   s->name, c->pid);
	    c->service_state = SERVICE_STATE_READY;
	    break;
	    
	case SERVICE_STATE_BUSY:
	    if (verbose) 
		syslog(LOG_DEBUG,
		       "service %s pid %d in BUSY state: now available and in READY state",
		       s->name, c->pid);
	    c->service_state = SERVICE_STATE_READY;
	    s->ready_workers++;
	    break;

	default:
	    /* Prevent Warning */
	    break;
	}
	break;

    case MASTER_SERVICE_UNAVAILABLE:
	switch (c->service_state) {
	case SERVICE_STATE_BUSY:
	    /* duplicate message? */
	    syslog(LOG_WARNING,
		   "service %s pid %d in BUSY state: sent unavailable message but it is already busy",
		   s->name, c->pid);
	    break;
	    
	case SERVICE_STATE_UNKNOWN:
	    syslog(LOG_DEBUG,
		   "service %s pid %d in UNKNOWN state: now unavailable and in BUSY state",
		   s->name, c->pid);
	    c->service_state = SERVICE_STATE_BUSY;
	    break;
	    
	case SERVICE_STATE_READY:
	    if (verbose)
		syslog(LOG_DEBUG,
		       "service %s pid %d in READY state: now unavailable and in BUSY state",
		       s->name, c->pid);
	    c->service_state = SERVICE_STATE_BUSY;
	    s->ready_workers--;
	    break;

	default:
	    /* Prevent Warning */
	    break;
	}
	break;

    case MASTER_SERVICE_CONNECTION:
	switch (c->service_state) {
	case SERVICE_STATE_BUSY:
	    s->nconnections++;
	    if (verbose)
		syslog(LOG_DEBUG,
		       "service %s pid %d in BUSY state: now serving connection",
		       s->name, c->pid);
	    break;
	    
	case SERVICE_STATE_UNKNOWN:
	    s->nconnections++;
	    c->service_state = SERVICE_STATE_BUSY;
	    syslog(LOG_DEBUG,
		   "service %s pid %d in UNKNOWN state: now in BUSY state and serving connection",
		   s->name, c->pid);
	    break;
	    
	case SERVICE_STATE_READY:
	    syslog(LOG_ERR, 
		   "service %s pid %d in READY state: reported new connection, forced to BUSY state",
		   s->name, c->pid);
	    /* be resilient on face of a bogon source, so lets err to the side
	     * of non-denial-of-service */
	    c->service_state = SERVICE_STATE_BUSY;
	    s->nconnections++;
	    s->ready_workers--;

	default:
	    /* Prevent Warning */
	    break;
	}
	break;
	
    case MASTER_SERVICE_CONNECTION_MULTI:
	switch (c->service_state) {
	case SERVICE_STATE_READY:
	    s->nconnections++;
	    if (verbose)
		syslog(LOG_DEBUG, 
		       "service %s pid %d in READY state: serving one more multi-threaded connection",
		       s->name, c->pid);
	    break;
	    
	case SERVICE_STATE_BUSY:
	    syslog(LOG_ERR, 
		   "service %s pid %d in BUSY state: serving one more multi-threaded connection, forced to READY state",
		   s->name, c->pid);
	    /* be resilient on face of a bogon source, so lets err to the side
	     * of non-denial-of-service */
	    c->service_state = SERVICE_STATE_READY;
	    s->nconnections++;
	    s->ready_workers++;
	    break;
	    
	case SERVICE_STATE_UNKNOWN:
	    s->nconnections++;
	    c->service_state = SERVICE_STATE_READY;
	    syslog(LOG_ERR,
		   "service %s pid %d in UNKNOWN state: serving one more multi-threaded connection, forced to READY state",
		   s->name, c->pid);
	    break;

	default:
	    /* Prevent Warning */
	    break;
	}
	break;
	
    default:
	syslog(LOG_CRIT, "service %s pid %d: Software bug: unrecognized message 0x%x", 
	       s->name, c->pid, msg->message);
	break;
    }

    if (verbose)
	syslog(LOG_DEBUG, "service %s now has %d ready workers\n", 
	       s->name, s->ready_workers);
}

static char **tokenize(char *p)
{
    char **tokens = NULL; /* allocated in increments of 10 */
    int i = 0;

    if (!p || !*p) return NULL; /* sanity check */
    while (*p) {
	while (*p && isspace((int) *p)) p++; /* skip whitespace */

	if (!(i % 10)) tokens = xrealloc(tokens, (i+10) * sizeof(char *));

	/* got a token */
	tokens[i++] = p;
	while (*p && !isspace((int) *p)) p++;

	/* p is whitespace or end of cmd */
	if (*p) *p++ = '\0';
    }
    /* add a NULL on the end */
    if (!(i % 10)) tokens = xrealloc(tokens, (i+1) * sizeof(char *));
    if (!tokens) return NULL;
    tokens[i] = NULL;

    return tokens;
}

void add_start(const char *name, struct entry *e,
	       void *rock __attribute__((unused)))
{
    char *cmd = xstrdup(masterconf_getstring(e, "cmd", NULL));
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
    int ignore_err = (int) rock;
    char *cmd = xstrdup(masterconf_getstring(e, "cmd", NULL));
    int prefork = masterconf_getint(e, "prefork", 0);
    int babysit = masterconf_getswitch(e, "babysit", 0);
    int maxforkrate = masterconf_getint(e, "maxforkrate", 0);
    char *listen = xstrdup(masterconf_getstring(e, "listen", NULL));
    char *proto = xstrdup(masterconf_getstring(e, "proto", "tcp"));
    char *max = xstrdup(masterconf_getstring(e, "maxchild", "-1"));
    rlim_t maxfds = (rlim_t) masterconf_getint(e, "maxfds", 256);
    int i, j;

    if(babysit && prefork == 0) prefork = 1;
    if(babysit && maxforkrate == 0) maxforkrate = 10; /* reasonable safety */

    if (!cmd || !listen) {
	char buf[256];
	snprintf(buf, sizeof(buf),
		 "unable to find command or port for service '%s'", name);

	if (ignore_err) {
	    syslog(LOG_WARNING, "WARNING: %s -- ignored", buf);
	    return;
	}

	fatal(buf, EX_CONFIG);
    }

    /* see if we have an existing entry for this service */
    for (i = 0; i < nservices; i++) {
	if (Services[i].associate > 0)
	    continue;
	if (Services[i].name && !strcmp(Services[i].name, name)) break;
    }

    /* we have duplicate service names in the config file */
    if ((i < nservices) && Services[i].exec) {
	char buf[256];
	snprintf(buf, sizeof(buf), "multiple entries for service '%s'", name);

	if (ignore_err) {
	    syslog(LOG_WARNING, "WARNING: %s -- ignored", buf);
	    return;
	}

	fatal(buf, EX_CONFIG);
    }

    if ((i < nservices) &&
	!strcmp(Services[i].listen, listen) &&
	!strcmp(Services[i].proto, proto)) {

	/* we found an existing entry and the port paramters are the same */
	Services[i].exec = tokenize(cmd);
	if (!Services[i].exec) fatal("out of memory", EX_UNAVAILABLE);

	/* is this service actually there? */
	if (!verify_service_file(Services[i].exec)) {
	    char buf[1024];
	    snprintf(buf, sizeof(buf),
		     "cannot find executable for service '%s'", name);

	    /* if it is not, we're misconfigured, die. */
	    fatal(buf, EX_CONFIG);
	}

	Services[i].maxforkrate = maxforkrate;

 	Services[nservices].maxfds = maxfds;

	if (!strcmp(Services[i].proto, "tcp") ||
	    !strcmp(Services[i].proto, "tcp4") ||
	    !strcmp(Services[i].proto, "tcp6")) {
	    Services[i].desired_workers = prefork;
	    Services[i].babysit = babysit;
	    Services[i].max_workers = atoi(max);
	    if (Services[i].max_workers == -1) {
		Services[i].max_workers = INT_MAX;
	    }
	} else {
	    /* udp */
	    if (prefork > 1) prefork = 1;
	    Services[i].desired_workers = prefork;
	    Services[i].max_workers = 1;
	}
 
	for (j = 0; j < nservices; j++) {
	    if (Services[j].associate > 0 &&
		Services[j].name && !strcmp(Services[j].name, name)) {
		Services[j].maxforkrate = Services[i].maxforkrate;
		Services[j].exec = Services[i].exec;
		Services[j].desired_workers = Services[i].desired_workers;
		Services[j].babysit = Services[i].babysit;
		Services[j].max_workers = Services[i].max_workers;
	    }
	}

	if (verbose > 2)
	    syslog(LOG_DEBUG, "reconfig: service '%s' (%s, %s:%s, %d, %d)",
		   Services[i].name, cmd,
		   Services[i].proto, Services[i].listen,
		   Services[i].desired_workers,
		   Services[i].max_workers);
    }
    else {
	/* either we don't have an existing entry or we are changing
	 * the port parameters, so create a new service
	 */
	if (nservices == allocservices) {
	    Services = xrealloc(Services, 
			       (allocservices+=5) * sizeof(struct service));
	}

	Services[nservices].name = xstrdup(name);
	Services[nservices].listen = listen;
	Services[nservices].proto = proto;
	Services[nservices].exec = tokenize(cmd);
	if (!Services[nservices].exec) fatal("out of memory", EX_UNAVAILABLE);

	/* is this service actually there? */
	if (!verify_service_file(Services[i].exec)) {
	    char buf[1024];
	    snprintf(buf, sizeof(buf),
		     "cannot find executable for service '%s'", name);

	    /* if it is not, we're misconfigured, die. */
	    fatal(buf, EX_CONFIG);
	}

	Services[nservices].socket = 0;
	Services[nservices].saddr = NULL;

	Services[nservices].ready_workers = 0;

 	Services[nservices].maxfds = maxfds;
	Services[nservices].maxforkrate = maxforkrate;

	if(!strcmp(Services[nservices].proto, "tcp") ||
	   !strcmp(Services[nservices].proto, "tcp4") ||
	   !strcmp(Services[nservices].proto, "tcp6")) {
	    Services[nservices].desired_workers = prefork;
	    Services[nservices].babysit = babysit;
	    Services[nservices].max_workers = atoi(max);
	    if (Services[nservices].max_workers == -1) {
		Services[nservices].max_workers = INT_MAX;
	    }
	} else {
	    if (prefork > 1) prefork = 1;
	    Services[nservices].desired_workers = prefork;
	    Services[nservices].max_workers = 1;
	}
	
	memset(Services[nservices].stat, 0, sizeof(Services[nservices].stat));

	Services[nservices].last_interval_start = time(NULL);
	Services[nservices].interval_forks = 0;
	Services[nservices].forkrate = 0;
	
	Services[nservices].nforks = 0;
	Services[nservices].nactive = 0;
	Services[nservices].nconnections = 0;
	Services[nservices].associate = 0;
	
	if (verbose > 2)
	    syslog(LOG_DEBUG, "add: service '%s' (%s, %s:%s, %d, %d, %d)",
		   Services[nservices].name, cmd,
		   Services[nservices].proto, Services[nservices].listen,
		   Services[nservices].desired_workers,
		   Services[nservices].max_workers,
		   (int) Services[nservices].maxfds);

	nservices++;
    }

    free(max);
}

void add_event(const char *name, struct entry *e, void *rock)
{
    int ignore_err = (int) rock;
    char *cmd = xstrdup(masterconf_getstring(e, "cmd", NULL));
    int period = 60 * masterconf_getint(e, "period", 0);
    int at = masterconf_getint(e, "at", -1), hour, min;
    time_t now = time(NULL);
    struct event *evt;

    if (!cmd) {
	char buf[256];
	snprintf(buf, sizeof(buf),
		 "unable to find command or port for event '%s'", name);

	if (ignore_err) {
	    syslog(LOG_WARNING, "WARNING: %s -- ignored", buf);
	    return;
	}

	fatal(buf, EX_CONFIG);
    }
    
    evt = (struct event *) xmalloc(sizeof(struct event));
    evt->name = xstrdup(name);

    if (at >= 0 && ((hour = at / 100) <= 23) && ((min = at % 100) <= 59)) {
	struct tm *tm = localtime(&now);

	period = 86400; /* 24 hours */
	evt->periodic = 1;
	tm->tm_hour = hour;
	tm->tm_min = min;
	tm->tm_sec = 0;
	if ((evt->mark = mktime(tm)) < now) {
	    /* already missed it, so schedule for next day */
	    evt->mark += period;
	}
    }
    else {
	evt->periodic = 0;
	evt->mark = now;
    }
    evt->period = period;

    evt->exec = tokenize(cmd);
    if (!evt->exec) fatal("out of memory", EX_UNAVAILABLE);

    schedule_event(evt);
}

#ifdef HAVE_SETRLIMIT

#ifdef RLIMIT_NOFILE
# define RLIMIT_NUMFDS RLIMIT_NOFILE
#else
# ifdef RLIMIT_OFILE
#  define RLIMIT_NUMFDS RLIMIT_OFILE
# endif
#endif
void limit_fds(rlim_t x)
{
    struct rlimit rl;
    int r;

    rl.rlim_cur = x;
    rl.rlim_max = x;
    if (setrlimit(RLIMIT_NUMFDS, &rl) < 0) {
	syslog(LOG_ERR, "setrlimit: Unable to set file descriptors limit to %ld: %m", x);

#ifdef HAVE_GETRLIMIT

	if (!getrlimit(RLIMIT_NUMFDS, &rl)) {
	    syslog(LOG_ERR, "retrying with %ld (current max)", rl.rlim_max);
	    rl.rlim_cur = rl.rlim_max;
	    if (setrlimit(RLIMIT_NUMFDS, &rl) < 0) {
		syslog(LOG_ERR, "setrlimit: Unable to set file descriptors limit to %ld: %m", x);
	    }
	}
    }


    if (verbose > 1) {
	r = getrlimit(RLIMIT_NUMFDS, &rl);
	syslog(LOG_DEBUG, "set maximum file descriptors to %ld/%ld", rl.rlim_cur,
	       rl.rlim_max);
    }
#else
    }
#endif /* HAVE_GETRLIMIT */
}
#else
void limit_fds(rlim_t x)
{
}
#endif /* HAVE_SETRLIMIT */

void reread_conf(void)
{
    int i;
    struct event *ptr;

    /* disable all services -
       they will be re-enabled if they appear in config file */
    for (i = 0; i < nservices; i++) Services[i].exec = NULL;

    /* read services */
    masterconf_getsection("SERVICES", &add_service, (void*) 1);

    for (i = 0; i < nservices; i++) {
	if (!Services[i].exec && Services[i].socket) {
	    /* cleanup newly disabled services */

	    if (verbose > 2)
		syslog(LOG_DEBUG, "disable: service %s socket %d pipe %d %d",
		       Services[i].name, Services[i].socket,
		       Services[i].stat[0], Services[i].stat[1]);

	    /* Only free the service info once */
	    if(Services[i].associate == 0) {
		free(Services[i].name);
		free(Services[i].listen);
		free(Services[i].proto);
	    }
	    Services[i].name = NULL;
	    Services[i].desired_workers = 0;
	    Services[i].nforks = 0;
	    Services[i].nactive = 0;
	    Services[i].nconnections = 0;

	    /* close all listeners */
	    if (Services[i].socket > 0) {
		shutdown(Services[i].socket, SHUT_RDWR);
		close(Services[i].socket);
	    }
	    Services[i].socket = 0;
	    Services[i].saddr = NULL;

	    if (Services[i].stat[0] > 0) close(Services[i].stat[0]);
	    if (Services[i].stat[1] > 0) close(Services[i].stat[1]);
	    memset(Services[i].stat, 0, sizeof(Services[i].stat));
	}
	else if (Services[i].exec && !Services[i].socket) {
	    /* initialize new services */

	    service_create(&Services[i]);
	    if (verbose > 2)
		syslog(LOG_DEBUG, "init: service %s socket %d pipe %d %d",
		       Services[i].name, Services[i].socket,
		       Services[i].stat[0], Services[i].stat[1]);
	}
    }


    /* remove existing events */
    while (schedule) {
	ptr = schedule;
	schedule = schedule->next;
	event_free(ptr);
    }
    schedule = NULL;

    /* read events */
    masterconf_getsection("EVENTS", &add_event, (void*) 1);

    /* reinit child janitor */
    init_janitor();
}

int main(int argc, char **argv)
{
    const char *default_pidfile = MASTER_PIDFILE;
    const char *lock_suffix = ".lock";

    const char *pidfile = default_pidfile;
    char *pidfile_lock = NULL;

    int startup_pipe[2] = { -1, -1 };
    int pidlock_fd = -1;

    int i, opt, close_std = 1, daemon_mode = 0;
    extern int optind;
    extern char *optarg;

    char *alt_config = NULL;
    
    int fd;
    fd_set rfds;
    char *p = NULL;

    p = getenv("CYRUS_VERBOSE");
    if (p) verbose = atoi(p) + 1;
    while ((opt = getopt(argc, argv, "C:M:p:l:Ddj:")) != EOF) {
	switch (opt) {
	case 'C': /* alt imapd.conf file */
	    alt_config = optarg;
	    break;
	case 'M': /* alt cyrus.conf file */
	    MASTER_CONFIG_FILENAME = optarg;
	    break;
	case 'l':
            /* user defined listen queue backlog */
	    listen_queue_backlog = atoi(optarg);
	    break;
	case 'p':
	    /* Set the pidfile name */
	    pidfile = optarg;
	    break;
	case 'd':
	    /* Daemon Mode */
	    if(!close_std)
		fatal("Unable to both be debug and daemon mode", EX_CONFIG);
	    daemon_mode = 1;
	    break;
	case 'D':
	    /* Debug Mode */
	    if(daemon_mode)
		fatal("Unable to be both debug and daemon mode", EX_CONFIG);
	    close_std = 0;
	    break;
	case 'j':
	    /* Janitor frequency */
	    janitor_frequency = atoi(optarg);
	    if(janitor_frequency < 1)
		fatal("The janitor period must be at least 1 second", EX_CONFIG);
	    break;   
	default:
	    break;
	}
    }

    masterconf_init("master", alt_config);

    /* zero out the children table */
    memset(&ctable, 0, sizeof(struct centry *) * child_table_size);

    if (close_std) {
      /* close stdin/out/err */
      for (fd = 0; fd < 3; fd++) {
	close(fd);
	if (open("/dev/null", O_RDWR, 0) != fd)
	  fatal("couldn't open /dev/null: %m", 2);
      }
    }

    /* we reserve fds 3 and 4 for children to communicate with us, so they
       better be available. */
    for (fd = 3; fd < 5; fd++) {
	close(fd);
	if (dup(0) != fd) fatal("couldn't dup fd 0: %m", 2);
    }

    /* Pidfile Algorithm in Daemon Mode.  This is a little subtle because
     * we want to ensure that we can report an error to our parent if the
     * child fails to lock the pidfile.
     *
     * [A] Create/lock pidfile.lock.  If locked, exit(failure).
     * [A] Create a pipe
     * [A] Fork [B]
     * [A] Block on reading exit code from pipe
     * [B] Create/lock pidfile.  If locked, write failure code to pipe and
     *     exit(failure)
     * [B] write pid to pidfile
     * [B] write success code to pipe & finish starting up
     * [A] unlink pidfile.lock and exit(code read from pipe)
     *
     */
    if(daemon_mode) {
	/* Daemonize */
	pid_t pid = -1;

	pidfile_lock = xmalloc(strlen(pidfile) + strlen(lock_suffix) + 1);

	strcpy(pidfile_lock, pidfile);
	strcat(pidfile_lock, lock_suffix);
	
	pidlock_fd = open(pidfile_lock, O_CREAT|O_TRUNC|O_RDWR, 0644);
	if(pidlock_fd == -1) {
	    syslog(LOG_ERR, "can't open pidfile lock: %s (%m)", pidfile_lock);
	    exit(EX_OSERR);
	} else {
	    if(lock_nonblocking(pidlock_fd)) {
		syslog(LOG_ERR, "can't get exclusive lock on %s",
		       pidfile_lock);
		exit(EX_TEMPFAIL);
	    }
	}
	
	if(pipe(startup_pipe) == -1) {
	    syslog(LOG_ERR, "can't create startup pipe (%m)");
	    exit(EX_OSERR);
	}

	do {
	    pid = fork();
	    	    
	    if ((pid == -1) && (errno == EAGAIN)) {
		syslog(LOG_WARNING, "master fork failed (sleeping): %m");
		sleep(5);
	    }
	} while ((pid == -1) && (errno == EAGAIN));

	if (pid == -1) {
	    fatal("fork error", EX_OSERR);
	} else if (pid != 0) {
	    int exit_code;

	    /* Parent, wait for child */
	    if(read(startup_pipe[0], &exit_code, sizeof(exit_code)) == -1) {
		syslog(LOG_ERR, "could not read from startup_pipe (%m)");
		unlink(pidfile_lock);
		exit(EX_OSERR);
	    } else {
		unlink(pidfile_lock);
		exit(exit_code);
	    }
	}

	/* Child! */
	close(startup_pipe[0]);

	free(pidfile_lock);

	/*
	 * We're now running in the child. Lose our controlling terminal
	 * and obtain a new process group.
	 */
	if (setsid() == -1) {
	    int exit_result = EX_OSERR;
	    
	    /* Tell our parent that we failed. */
	    write(startup_pipe[1], &exit_result, sizeof(exit_result));
	
	    fatal("setsid failure", EX_OSERR);
	}
    }

    limit_fds(RLIM_INFINITY);

    /* Write out the pidfile */
    pidfd = open(pidfile, O_CREAT|O_RDWR, 0644);
    if(pidfd == -1) {
	int exit_result = EX_OSERR;

	/* Tell our parent that we failed. */
	write(startup_pipe[1], &exit_result, sizeof(exit_result));

	syslog(LOG_ERR, "can't open pidfile: %m");
	exit(EX_OSERR);
    } else {
	char buf[100];

	if(lock_nonblocking(pidfd)) {
	    int exit_result = EX_OSERR;

	    /* Tell our parent that we failed. */
	    write(startup_pipe[1], &exit_result, sizeof(exit_result));
	    
	    fatal("cannot get exclusive lock on pidfile (is another master still running?)", EX_OSERR);
	} else {
	    int pidfd_flags = fcntl(pidfd, F_GETFD, 0);
	    if (pidfd_flags != -1)
		pidfd_flags = fcntl(pidfd, F_SETFD, 
				    pidfd_flags | FD_CLOEXEC);
	    if (pidfd_flags == -1) {
		int exit_result = EX_OSERR;
		
		/* Tell our parent that we failed. */
		write(startup_pipe[1], &exit_result, sizeof(exit_result));

		fatal("unable to set close-on-exec for pidfile: %m", EX_OSERR);
	    }
	    
	    /* Write PID */
	    snprintf(buf, sizeof(buf), "%lu\n", (unsigned long int)getpid());
	    if(lseek(pidfd, 0, SEEK_SET) == -1 ||
	       ftruncate(pidfd, 0) == -1 ||
	       write(pidfd, buf, strlen(buf)) == -1) {
		int exit_result = EX_OSERR;

		/* Tell our parent that we failed. */
		write(startup_pipe[1], &exit_result, sizeof(exit_result));

		fatal("unable to write to pidfile: %m", EX_OSERR);
	    }
	    fsync(pidfd);
	}
    }

    if(daemon_mode) {
	int exit_result = 0;

	/* success! */
	if(write(startup_pipe[1], &exit_result, sizeof(exit_result)) == -1) {
	    syslog(LOG_ERR,
		   "could not write success result to startup pipe (%m)");
	    exit(EX_OSERR);
	}

	close(startup_pipe[1]);
	if(pidlock_fd != -1) close(pidlock_fd);
    }

    syslog(LOG_NOTICE, "process started");

#ifdef HAVE_UCDSNMP
    /* initialize SNMP agent */
    
    /* make us a agentx client. */
    ds_set_boolean(DS_APPLICATION_ID, DS_AGENT_ROLE, 1);

    /* initialize the agent library */
    init_agent("cyrusMaster");

    init_cyrusMasterMIB();

    init_snmp("cyrusMaster"); 
#endif

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

    if (become_cyrus_early) {
	if (become_cyrus() != 0) {
	    syslog(LOG_ERR, "can't change to the cyrus user: %m");
	    exit(1);
	}
    }
    
    /* init ctable janitor */
    init_janitor();
    
    /* ok, we're going to start spawning like mad now */
    syslog(LOG_NOTICE, "ready for work");

    for (;;) {
	int r, i, maxfd;
	struct timeval tv, *tvptr;
	time_t now = time(NULL);
	struct notify_message msg;
#if HAVE_UCDSNMP
	int blockp = 0;
#endif

	/* run any scheduled processes */
	spawn_schedule(now);

	/* reap first, that way if we need to babysit we will */
	if (gotsigchld) {
	    /* order matters here */
	    gotsigchld = 0;
	    reap_child();
	}
	
	/* do we have any services undermanned? */
	for (i = 0; i < nservices; i++) {
	    if (Services[i].exec /* enabled */ &&
		(Services[i].nactive < Services[i].max_workers) &&
		(Services[i].ready_workers < Services[i].desired_workers)) {
		spawn_service(&Services[i]);
	    } else if (Services[i].exec
		       && Services[i].babysit
		       && Services[i].nactive == 0) {
		syslog(LOG_ERR,
		       "lost all children for service: %s.  " \
		       "Applying babysitter.",
		       Services[i].name);
		spawn_service(&Services[i]);
	    }
	}

	if (gotsighup) {
	    syslog(LOG_NOTICE, "got SIGHUP");
	    gotsighup = 0;
	    reread_conf();
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
	    if (y > 0 && Services[i].ready_workers == 0 &&
		Services[i].nactive < Services[i].max_workers) {
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
	maxfd++;		/* need 1 greater than maxfd */

	/* how long to wait? - do now so that any scheduled wakeup
	 * calls get accounted for*/
	tvptr = NULL;
	if (schedule) {
	    if (now < schedule->mark) tv.tv_sec = schedule->mark - now;
	    else tv.tv_sec = 0;
	    tv.tv_usec = 0;
	    tvptr = &tv;
	}

#ifdef HAVE_UCDSNMP
	if (tvptr == NULL) blockp = 1;
	snmp_select_info(&maxfd, &rfds, tvptr, &blockp);
#endif
	errno = 0;
	r = select(maxfd, &rfds, NULL, NULL, tvptr);
	if (r == -1 && errno == EAGAIN) continue;
	if (r == -1 && errno == EINTR) continue;
	if (r == -1) {
	    /* uh oh */
	    fatal("select failed: %m", 1);
	}

#ifdef HAVE_UCDSNMP
	/* check for SNMP queries */
	snmp_read(&rfds);
	snmp_timeout();
#endif
	for (i = 0; i < nservices; i++) {
	    int x = Services[i].stat[0];
	    int y = Services[i].socket;
	    int j;

	    if (FD_ISSET(x, &rfds)) {
		r = read(x, &msg, sizeof(msg));
		if (r != sizeof(msg)) {
		    syslog(LOG_ERR, "got incorrectly sized response from child: %x", i);
		    continue;
		}
		
		process_msg(&Services[i], &msg);
	    }

	    if (Services[i].exec &&
		Services[i].nactive < Services[i].max_workers) {
		/* bring us up to desired_workers */
		for (j = Services[i].ready_workers;
		     j < Services[i].desired_workers; 
		     j++)
		{
		    spawn_service(&Services[i]);
		}

		if (Services[i].ready_workers == 0 && 
		    FD_ISSET(y, &rfds)) {
		    /* huh, someone wants to talk to us */
		    spawn_service(&Services[i]);
		}
	    }
	}
	child_janitor();
    }
}
